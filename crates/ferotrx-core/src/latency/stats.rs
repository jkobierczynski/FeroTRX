//! Counters of received latency streams: loss, order and latency per flow.

use std::collections::BTreeMap;
use std::time::Duration;

use super::Signature;
use crate::RunStats;

/// Latency of the packets of one flow: minimum, mean, maximum, jitter and a
/// histogram for percentiles.
///
/// Latency is the receive time minus the send time in the packet's
/// [`Signature`]. When the sender and the receiver are different machines
/// their clocks must agree (NTP gets them within a millisecond or so, PTP far
/// better); packets that seem to arrive before they left are counted in
/// `negative` and taken as zero.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LatencyStats {
    count: u64,
    sum_ns: u128,
    min_ns: u64,
    max_ns: u64,
    /// RFC 3550 interarrival jitter, in nanoseconds.
    jitter_ns: f64,
    last_ns: Option<u64>,
    /// Log-linear histogram, see [`bucket`].
    hist: Vec<u64>,
    /// Packets whose receive time was before their send time.
    pub negative: u64,
}

/// Sub-buckets per power of two: values are kept to within 1/8 (12.5%).
const SUB_BITS: u32 = 3;
const SUB: u64 = 1 << SUB_BITS;

/// Histogram bucket of a value: exact below 8, then 8 buckets per power of two.
fn bucket(v: u64) -> usize {
    if v < SUB {
        return v as usize;
    }
    let k = 63 - v.leading_zeros(); // v is in [2^k, 2^(k+1))
    let sub = (v >> (k - SUB_BITS)) & (SUB - 1);
    (SUB + u64::from(k - SUB_BITS) * SUB + sub) as usize
}

/// The smallest value and the width of a bucket.
fn bucket_range(i: usize) -> (u64, u64) {
    let i = i as u64;
    if i < SUB {
        return (i, 1);
    }
    let k = (i - SUB) / SUB + u64::from(SUB_BITS);
    let sub = (i - SUB) % SUB;
    let width = 1u64 << (k - u64::from(SUB_BITS));
    ((SUB + sub) * width, width)
}

impl LatencyStats {
    /// Adds one packet's latency; `None` for a packet that arrived before it was sent.
    pub fn record(&mut self, latency: Option<Duration>) {
        let ns = match latency {
            Some(d) => u64::try_from(d.as_nanos()).unwrap_or(u64::MAX),
            None => {
                self.negative += 1;
                0
            }
        };
        if self.count == 0 || ns < self.min_ns {
            self.min_ns = ns;
        }
        self.max_ns = self.max_ns.max(ns);
        self.count += 1;
        self.sum_ns += u128::from(ns);
        if let Some(last) = self.last_ns {
            let d = (ns as f64 - last as f64).abs();
            self.jitter_ns += (d - self.jitter_ns) / 16.0;
        }
        self.last_ns = Some(ns);
        let b = bucket(ns);
        if self.hist.len() <= b {
            self.hist.resize(b + 1, 0);
        }
        self.hist[b] += 1;
    }

    /// Packets measured.
    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn min(&self) -> Option<Duration> {
        (self.count > 0).then(|| Duration::from_nanos(self.min_ns))
    }

    pub fn max(&self) -> Option<Duration> {
        (self.count > 0).then(|| Duration::from_nanos(self.max_ns))
    }

    pub fn mean(&self) -> Option<Duration> {
        (self.count > 0).then(|| {
            Duration::from_nanos(u64::try_from(self.sum_ns / u128::from(self.count)).unwrap_or(0))
        })
    }

    /// Smoothed variation of latency from one packet to the next, as RTP
    /// measures it (RFC 3550, section 6.4.1).
    pub fn jitter(&self) -> Option<Duration> {
        (self.count > 1).then(|| Duration::from_nanos(self.jitter_ns as u64))
    }

    /// The latency that a fraction `p` (0.0 to 1.0) of the packets did not
    /// exceed, to within 12.5%, e.g. `percentile(0.99)`.
    pub fn percentile(&self, p: f64) -> Option<Duration> {
        if self.count == 0 {
            return None;
        }
        let rank = ((p.clamp(0.0, 1.0) * self.count as f64).ceil() as u64).max(1);
        let mut seen = 0;
        for (i, &n) in self.hist.iter().enumerate() {
            seen += n;
            if seen >= rank {
                let (low, width) = bucket_range(i);
                let mid = low + width / 2;
                return Some(Duration::from_nanos(mid.clamp(self.min_ns, self.max_ns)));
            }
        }
        self.max()
    }

    /// Adds the packets of `other`, e.g. to sum up repeated trials. Jitter
    /// becomes the larger of the two, as it is a running estimate.
    pub fn merge(&mut self, other: &LatencyStats) {
        if other.count == 0 {
            return;
        }
        if self.count == 0 || other.min_ns < self.min_ns {
            self.min_ns = other.min_ns;
        }
        self.max_ns = self.max_ns.max(other.max_ns);
        self.count += other.count;
        self.sum_ns += other.sum_ns;
        self.jitter_ns = self.jitter_ns.max(other.jitter_ns);
        self.last_ns = None;
        self.negative += other.negative;
        if self.hist.len() < other.hist.len() {
            self.hist.resize(other.hist.len(), 0);
        }
        for (a, b) in self.hist.iter_mut().zip(&other.hist) {
            *a += b;
        }
    }

    /// The histogram: `(from, to, packets)` for every non-empty bucket, `to` exclusive.
    pub fn histogram(&self) -> impl Iterator<Item = (Duration, Duration, u64)> + '_ {
        self.hist
            .iter()
            .enumerate()
            .filter(|(_, &n)| n > 0)
            .map(|(i, &n)| {
                let (low, width) = bucket_range(i);
                (
                    Duration::from_nanos(low),
                    Duration::from_nanos(low + width),
                    n,
                )
            })
    }
}

/// Packets of a window behind the highest sequence number seen are remembered,
/// to tell late packets from duplicates.
const WINDOW: u64 = 4096;

/// Counters of one received flow.
#[derive(Clone, Debug, PartialEq)]
pub struct FlowStats {
    pub flow: u32,
    /// Packets received, duplicates included.
    pub packets: u64,
    pub bytes: u64,
    /// Packets whose sequence number was seen before.
    pub duplicates: u64,
    /// Packets that came after one with a higher sequence number.
    pub out_of_order: u64,
    /// Lowest sequence number seen first: where counting starts.
    pub first_seq: u64,
    /// One more than the highest sequence number seen.
    pub next_seq: u64,
    pub latency: LatencyStats,
    /// Per interval of send time, when [`RxStats::interval`] is set: the
    /// packets sent in each interval that arrived, keyed by the send time
    /// divided by the interval.
    pub intervals: BTreeMap<u64, IntervalStats>,
    window: Vec<u64>,
}

/// Packets of a flow sent in one interval that arrived (once), and their
/// latency.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct IntervalStats {
    pub packets: u64,
    pub bytes: u64,
    /// Packets with a latency: not those that seemed to arrive before they left.
    pub timed: u64,
    pub latency_sum_ns: u128,
    pub latency_min_ns: u64,
    pub latency_max_ns: u64,
}

impl IntervalStats {
    fn record(&mut self, len: usize, latency: Option<Duration>) {
        self.packets += 1;
        self.bytes += len as u64;
        if let Some(l) = latency {
            let ns = u64::try_from(l.as_nanos()).unwrap_or(u64::MAX);
            if self.timed == 0 || ns < self.latency_min_ns {
                self.latency_min_ns = ns;
            }
            self.latency_max_ns = self.latency_max_ns.max(ns);
            self.timed += 1;
            self.latency_sum_ns += u128::from(ns);
        }
    }

    pub fn min(&self) -> Option<Duration> {
        (self.timed > 0).then(|| Duration::from_nanos(self.latency_min_ns))
    }

    pub fn max(&self) -> Option<Duration> {
        (self.timed > 0).then(|| Duration::from_nanos(self.latency_max_ns))
    }

    pub fn mean(&self) -> Option<Duration> {
        (self.timed > 0)
            .then(|| Duration::from_nanos((self.latency_sum_ns / u128::from(self.timed)) as u64))
    }
}

impl FlowStats {
    fn new(flow: u32, seq: u64) -> Self {
        Self {
            flow,
            packets: 0,
            bytes: 0,
            duplicates: 0,
            out_of_order: 0,
            first_seq: seq,
            next_seq: seq,
            latency: LatencyStats::default(),
            intervals: BTreeMap::new(),
            window: vec![0; (WINDOW / 64) as usize],
        }
    }

    /// Packets received once, not counting duplicates.
    pub fn unique(&self) -> u64 {
        self.packets - self.duplicates
    }

    /// Packets missing from the sequence numbers seen so far: the gaps between
    /// the first and the highest one. Packets lost after the highest one are
    /// not seen here; compare with the sender's count for those
    /// (see [`FlowReport`]).
    pub fn seq_lost(&self) -> u64 {
        (self.next_seq - self.first_seq).saturating_sub(self.unique())
    }

    fn bit(&mut self, seq: u64) -> (&mut u64, u64) {
        let i = seq % WINDOW;
        (&mut self.window[(i / 64) as usize], 1u64 << (i % 64))
    }

    fn record(&mut self, sig: &Signature, len: usize, rx_time: Duration, interval: Option<u128>) {
        self.packets += 1;
        self.bytes += len as u64;
        let seq = sig.seq;
        if seq >= self.next_seq {
            // New ground: forget what falls out of the window.
            let fresh = (seq - self.next_seq).min(WINDOW);
            for s in self.next_seq..self.next_seq + fresh {
                let (word, bit) = self.bit(s);
                *word &= !bit;
            }
            let (word, bit) = self.bit(seq);
            *word |= bit;
            self.next_seq = seq + 1;
        } else if seq < self.first_seq {
            // From before the first packet seen: counting starts earlier.
            self.out_of_order += 1;
            self.first_seq = seq;
            if self.next_seq - seq <= WINDOW {
                let (word, bit) = self.bit(seq);
                *word |= bit;
            }
        } else if self.next_seq - seq > WINDOW {
            // Too old to tell: count it as late.
            self.out_of_order += 1;
        } else {
            let (word, bit) = self.bit(seq);
            if *word & bit != 0 {
                self.duplicates += 1;
                return;
            }
            *word |= bit;
            self.out_of_order += 1;
        }
        let latency = rx_time.checked_sub(sig.tx_time);
        self.latency.record(latency);
        if let Some(ns) = interval {
            let key = u64::try_from(sig.tx_time.as_nanos() / ns).unwrap_or(u64::MAX);
            self.intervals.entry(key).or_default().record(len, latency);
        }
    }
}

/// Counters of a receiver: every frame it saw, and per flow the ones that
/// carried a [`Signature`].
///
/// ```
/// use ferotrx_core::{RxStats, Signature};
/// use std::time::Duration;
///
/// let mut rx = RxStats::default();
/// let t0 = Duration::from_secs(1_700_000_000);
/// for seq in [0, 1, 3, 2, 2] {
///     let mut frame = vec![0u8; 14];
///     frame.extend_from_slice(&Signature { flow: 1, seq, tx_time: t0 }.encode());
///     rx.record(&frame, t0 + Duration::from_micros(250));
/// }
/// let f = rx.flow(1).unwrap();
/// assert_eq!((f.unique(), f.duplicates, f.out_of_order, f.seq_lost()), (4, 1, 1, 0));
/// assert_eq!(f.latency.mean(), Some(Duration::from_micros(250)));
/// ```
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RxStats {
    /// Frames received, with a signature or not.
    pub packets: u64,
    pub bytes: u64,
    /// Frames without a signature.
    pub untagged: u64,
    /// How long the receiver has been running.
    pub elapsed: Duration,
    pub flows: BTreeMap<u32, FlowStats>,
    /// When set, every flow also counts what arrived per interval of send
    /// time ([`FlowStats::intervals`]), e.g. per second for availability.
    pub interval: Option<Duration>,
}

impl RxStats {
    /// Counts one received frame; `rx_time` is when it arrived, since the Unix epoch.
    /// Returns its signature, if it has one.
    pub fn record(&mut self, frame: &[u8], rx_time: Duration) -> Option<Signature> {
        self.packets += 1;
        self.bytes += frame.len() as u64;
        let Some(sig) = Signature::find(frame) else {
            self.untagged += 1;
            return None;
        };
        let interval = self.interval.map(|d| d.as_nanos()).filter(|&ns| ns > 0);
        self.flows
            .entry(sig.flow)
            .or_insert_with(|| FlowStats::new(sig.flow, sig.seq))
            .record(&sig, frame.len(), rx_time, interval);
        Some(sig)
    }

    pub fn flow(&self, flow: u32) -> Option<&FlowStats> {
        self.flows.get(&flow)
    }

    /// Counts every packet of a capture, e.g. one taken with tcpdump on the
    /// receiving machine; its timestamps are the receive times.
    pub fn from_capture(capture: &crate::Capture) -> RxStats {
        let mut rx = RxStats::default();
        for p in &capture.packets {
            rx.record(&p.data, p.timestamp);
        }
        if let (Some(a), Some(b)) = (capture.packets.first(), capture.packets.last()) {
            rx.elapsed = b.timestamp.saturating_sub(a.timestamp);
        }
        rx
    }
}

/// Loss and latency of one sent stream: what was sent against what came back.
#[derive(Clone, Debug, PartialEq)]
pub struct FlowReport {
    /// The stream's name.
    pub stream: String,
    pub flow: u32,
    /// Packets sent with a signature.
    pub tx: u64,
    /// Packets received once (duplicates not counted).
    pub rx: u64,
    /// Bytes received, duplicates included.
    pub rx_bytes: u64,
    /// `tx - rx`. While a run is going, packets on their way count here too.
    pub lost: u64,
    pub duplicates: u64,
    pub out_of_order: u64,
    pub latency: LatencyStats,
}

impl FlowReport {
    /// Lost packets as a fraction of those sent (0.0 to 1.0).
    pub fn loss(&self) -> f64 {
        if self.tx == 0 {
            0.0
        } else {
            self.lost as f64 / self.tx as f64
        }
    }

    /// Reports for the streams of a run that carry signatures. `flows` is the
    /// flow id of each stream (see [`Job::flows`](crate::Job::flows)), in the
    /// order of `names` and `tx.streams`.
    pub fn for_run(
        names: &[String],
        flows: &[Option<u32>],
        tx: &RunStats,
        rx: &RxStats,
    ) -> Vec<FlowReport> {
        names
            .iter()
            .zip(flows)
            .zip(&tx.streams)
            .filter_map(|((name, flow), st)| {
                let flow = (*flow)?;
                let got = rx.flow(flow);
                let rx_n = got.map_or(0, FlowStats::unique);
                Some(FlowReport {
                    stream: name.clone(),
                    flow,
                    tx: st.tagged,
                    rx: rx_n,
                    rx_bytes: got.map_or(0, |f| f.bytes),
                    lost: st.tagged.saturating_sub(rx_n),
                    duplicates: got.map_or(0, |f| f.duplicates),
                    out_of_order: got.map_or(0, |f| f.out_of_order),
                    latency: got.map(|f| f.latency.clone()).unwrap_or_default(),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_cover_every_value() {
        let mut last = None;
        for v in (0..5000u64).chain([1 << 20, (1 << 40) + 12345, u64::MAX]) {
            let b = bucket(v);
            let (low, width) = bucket_range(b);
            assert!(
                low <= v && v - low < width,
                "{v} in bucket {b} = {low}+{width}"
            );
            if let Some(l) = last {
                assert!(b >= l);
            }
            last = Some(b);
        }
    }

    #[test]
    fn latency_numbers() {
        let mut l = LatencyStats::default();
        for us in 1..=100u64 {
            l.record(Some(Duration::from_micros(us * 10)));
        }
        l.record(None);
        assert_eq!(l.count(), 101);
        assert_eq!(l.negative, 1);
        assert_eq!(l.min(), Some(Duration::ZERO));
        assert_eq!(l.max(), Some(Duration::from_micros(1000)));
        let p50 = l.percentile(0.5).unwrap().as_micros() as f64;
        assert!((p50 - 500.0).abs() / 500.0 < 0.13, "{p50}");
        let p99 = l.percentile(0.99).unwrap().as_micros() as f64;
        assert!((p99 - 990.0).abs() / 990.0 < 0.13, "{p99}");
        assert!(l.jitter().unwrap() > Duration::ZERO);
        assert_eq!(l.histogram().map(|h| h.2).sum::<u64>(), 101);
        let mut m = LatencyStats::default();
        m.merge(&l);
        let mut more = LatencyStats::default();
        more.record(Some(Duration::from_millis(5)));
        m.merge(&more);
        assert_eq!(m.count(), 102);
        assert_eq!(m.min(), Some(Duration::ZERO));
        assert_eq!(m.max(), Some(Duration::from_millis(5)));
        assert_eq!(m.negative, 1);
        assert_eq!(m.histogram().map(|h| h.2).sum::<u64>(), 102);
    }

    fn sig(seq: u64) -> Signature {
        Signature {
            flow: 4,
            seq,
            tx_time: Duration::from_secs(10),
        }
    }

    #[test]
    fn sequence_tracking() {
        let mut f = FlowStats::new(4, 5);
        let at = Duration::from_secs(11);
        for s in [5, 6, 8, 9, 7, 9, 20, 3] {
            f.record(&sig(s), 60, at, None);
        }
        // 3..=20 is 18 numbers; seen 3,5,6,7,8,9,20 once each.
        assert_eq!(f.packets, 8);
        assert_eq!(f.duplicates, 1);
        assert_eq!(f.out_of_order, 2);
        assert_eq!((f.first_seq, f.next_seq), (3, 21));
        assert_eq!(f.seq_lost(), 18 - 7);
        // Far ahead, then something too old to tell.
        f.record(&sig(100_000), 60, at, None);
        f.record(&sig(50), 60, at, None);
        assert_eq!(f.out_of_order, 3);
        assert_eq!(f.duplicates, 1);
    }

    #[test]
    fn report_against_the_sender() {
        let mut rx = RxStats::default();
        let t = Duration::from_secs(10);
        for s in 0..90 {
            let mut frame = vec![0u8; 14];
            frame.extend_from_slice(&sig(s).encode());
            rx.record(&frame, t + Duration::from_millis(2));
        }
        rx.record(&[0u8; 60], t);
        assert_eq!((rx.packets, rx.untagged), (91, 1));
        let mut tx = RunStats {
            streams: vec![Default::default(), Default::default()],
            ..Default::default()
        };
        tx.streams[0].tagged = 100;
        tx.streams[1].packets = 7;
        let names = ["a".to_string(), "b".to_string()];
        let r = FlowReport::for_run(&names, &[Some(4), None], &tx, &rx);
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].tx, r[0].rx, r[0].lost), (100, 90, 10));
        assert!((r[0].loss() - 0.1).abs() < 1e-9);
        assert_eq!(r[0].latency.mean(), Some(Duration::from_millis(2)));
    }
}
