use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::latency::{reserve, reserve_inside, stamp, wall_clock};
use crate::{
    Error, ImpairSpec, ImpairStats, Impairer, MergeStats, Pacer, Packet, PacketSink, PacketSource,
    Rate, ReplayStats, Result, SinkError, TrafficModel, Transform,
};

/// One flow of traffic: a source, the transforms applied to it, and its own rate.
///
/// Several streams can run together into one sink with [`run`].
pub struct Stream<'a> {
    pub name: String,
    pub rate: Rate,
    /// Stop this stream after this many packets (sent or failed).
    pub limit: Option<u64>,
    /// Wait this long after the run starts before the first packet.
    pub delay: Duration,
    /// Flow id of the latency [`Signature`](crate::Signature) every packet
    /// carries, or `None` for a stream without one.
    pub latency: Option<u32>,
    /// Put the latency signature over the last bytes of each packet's payload
    /// instead of after them, so packets keep the size they were given (see
    /// [`keep_size`](Stream::keep_size)).
    pub keep_size: bool,
    /// How packets spread around the rate: Poisson arrivals, bursts, ramps.
    /// Anything but the default needs a pps or Mbit/s rate.
    pub model: TrafficModel,
    /// What a bad link would do to this stream's packets on their way to the
    /// sink: delay, jitter, loss and the rest (see [`ImpairSpec`]). Packets
    /// are counted as sent when they go into the impairment; the impairment's
    /// own counters are in [`ReplayStats::impair`]. A run waits at its end
    /// until the held packets are out, unless it is stopped.
    pub impair: Option<ImpairSpec>,
    /// This stream's part of a stream split over several workers:
    /// (index, count); see [`shard`](Stream::shard).
    shard: (u64, u64),
    source: Box<dyn PacketSource + 'a>,
    transforms: Vec<Box<dyn Transform + 'a>>,
}

impl<'a> Stream<'a> {
    /// A stream at the default rate (original timing), with no transforms.
    pub fn new(name: impl Into<String>, source: impl PacketSource + 'a) -> Self {
        Self {
            name: name.into(),
            rate: Rate::default(),
            limit: None,
            delay: Duration::ZERO,
            latency: None,
            keep_size: false,
            model: TrafficModel::default(),
            impair: None,
            shard: (0, 1),
            source: Box::new(source),
            transforms: Vec::new(),
        }
    }

    pub fn with_rate(mut self, rate: Rate) -> Self {
        self.rate = rate;
        self
    }

    pub fn with_limit(mut self, limit: Option<u64>) -> Self {
        self.limit = limit;
        self
    }

    /// Spreads the packets around the rate by `model`.
    pub fn with_model(mut self, model: TrafficModel) -> Self {
        self.model = model;
        self
    }

    /// Impairs the stream's packets by `spec` (see [`impair`](Self::impair)).
    pub fn with_impair(mut self, spec: ImpairSpec) -> Self {
        self.impair = (!spec.is_none()).then_some(spec);
        self
    }

    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Measures loss and latency of this stream: every packet carries a
    /// [`Signature`](crate::Signature) with flow id `flow`, a sequence number
    /// and its send time, at the end of its IP payload (28 more bytes; frames
    /// that are not IP get it at their end, IP fragments get none). A
    /// [`PacketReceiver`](crate::PacketReceiver) on the far side counts what arrives.
    pub fn with_latency(mut self, flow: u32) -> Self {
        self.latency = Some(flow);
        self
    }

    /// With a latency signature: write it over the last 28 bytes of each
    /// packet's IP payload instead of adding 28 bytes, so packets keep the
    /// size their source and transforms gave them, as benchmarks with set
    /// frame sizes need. Packets whose payload is shorter than the signature
    /// still grow, to the headers plus 28 bytes.
    pub fn keep_size(mut self, keep: bool) -> Self {
        self.keep_size = keep;
        self
    }

    /// Appends a transform; transforms run in the order they were added.
    pub fn with_transform(mut self, transform: impl Transform + 'a) -> Self {
        self.push_transform(transform);
        self
    }

    pub fn push_transform(&mut self, transform: impl Transform + 'a) {
        self.transforms.push(Box::new(transform));
    }

    pub fn linktype(&self) -> u32 {
        self.source.linktype()
    }

    /// Makes this stream worker `index`'s part of the stream split over
    /// `count` workers, each with its own copy of the stream and its own sink.
    /// Packet `i` of the whole stream is sent by worker `i % count`, so
    /// together the workers send exactly what one stream would: the same
    /// packets, transform values, latency sequence numbers and limit. Each
    /// worker skips the others' packets without building them (see
    /// [`PacketSource::skip`] and [`Transform::skip`]).
    ///
    /// The rate is shared too: a packet or bit rate is divided by `count`, and
    /// each worker of an evenly spaced pps stream starts `index / pps` later,
    /// so the packets interleave as one stream's would. Original timing and
    /// top speed stay as they are. A traffic model's seed is offset per worker.
    ///
    /// Call it after the rate, limit and model are set.
    ///
    /// ```
    /// use ferotrx_core::*;
    /// use std::sync::Arc;
    /// use std::time::Duration;
    ///
    /// let cap = Arc::new(Capture::from_specs(&["eth/ipv4/udp/raw(len=8)"], Duration::ZERO).unwrap());
    /// let make = |k| Stream::new("s", CaptureSource::new(cap.clone()).loops(10))
    ///     .with_rate(Rate::TopSpeed)
    ///     .with_transform(FieldEngine::parse(["ip_id=0..65535"]).unwrap())
    ///     .shard(k, 3);
    /// let mut ids = Vec::new();
    /// for k in 0..3 {
    ///     let mut sink = VecSink::default();
    ///     run(&mut [make(k)], &mut sink, &RunConfig::default()).unwrap();
    ///     ids.extend(sink.packets.iter().map(|p| u16::from_be_bytes([p[18], p[19]])));
    /// }
    /// ids.sort();
    /// assert_eq!(ids, (0..10).collect::<Vec<u16>>());
    /// ```
    pub fn shard(mut self, index: usize, count: usize) -> Self {
        assert!(count > 0 && index < count, "shard {index} of {count}");
        let (k, n) = (index as u64, count as u64);
        self.shard = (k, n);
        if n == 1 {
            return self;
        }
        self.limit = self.limit.map(|l| crate::share(l, index, count));
        match self.rate {
            Rate::Pps(pps) => {
                self.rate = Rate::Pps(pps / n as f64);
                if self.model.is_steady() {
                    self.delay += Duration::from_secs_f64(k as f64 / pps);
                }
            }
            Rate::Mbps(mbps) => self.rate = Rate::Mbps(mbps / n as f64),
            Rate::Original { .. } | Rate::TopSpeed => {}
        }
        if let Some(seed) = self.model.seed {
            self.model.seed = Some(crate::worker_seed(seed, index));
        }
        if let Some(spec) = &mut self.impair {
            // Each worker's share of the link.
            *spec = spec.for_lane(index);
            spec.rate = spec.rate.map(|r| r / n as f64);
        }
        self
    }

    /// Which part of a split stream this is: (index, count); (0, 1) for a
    /// whole stream.
    pub fn shard_of(&self) -> (usize, usize) {
        (self.shard.0 as usize, self.shard.1 as usize)
    }
}

impl std::fmt::Debug for Stream<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream")
            .field("name", &self.name)
            .field("rate", &self.rate)
            .field("limit", &self.limit)
            .field("delay", &self.delay)
            .field("latency", &self.latency)
            .field("keep_size", &self.keep_size)
            .field("model", &self.model)
            .field("impair", &self.impair.as_ref().map(ToString::to_string))
            .field("impair", &self.impair.as_ref().map(ToString::to_string))
            .field("shard", &self.shard)
            .field("transforms", &self.transforms.len())
            .finish_non_exhaustive()
    }
}

/// Settings shared by all streams of a [`run`].
#[derive(Clone, Debug, Default)]
pub struct RunConfig {
    /// Stop after this many packets in total (sent or failed).
    pub limit: Option<u64>,
    /// Stop after this much time.
    pub duration: Option<Duration>,
    /// Count failed sends and carry on, instead of stopping at the first failure.
    pub ignore_send_errors: bool,
    /// Set to true from another thread (for example a Ctrl-C handler) to stop early.
    pub stop: Option<Arc<AtomicBool>>,
}

/// Counters of a run: the total, and one entry per stream in the order given.
///
/// `total.loops_completed` is the sum over the streams.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RunStats {
    pub total: ReplayStats,
    pub streams: Vec<ReplayStats>,
}

/// Runs `streams` together into `sink`, each at its own rate, and returns the counters.
pub fn run(
    streams: &mut [Stream<'_>],
    sink: &mut dyn PacketSink,
    config: &RunConfig,
) -> Result<RunStats> {
    run_with_progress(streams, sink, config, Duration::MAX, |_| {})
}

struct Lane {
    pacer: Pacer,
    packet: Packet,
    pending: bool,
    done: bool,
    /// Offset from the start of the run when the pending packet should leave.
    deadline: Duration,
    /// The source's pass count after the pending packet was read.
    passes: u64,
    /// Where the pending packet's latency signature is.
    signature: Option<usize>,
    /// Sequence number of the next signature.
    seq: u64,
    /// No packet read yet (a shard skips the packets before its first).
    first: bool,
}

/// Like [`run`], and calls `progress` with the running counters about every `interval`.
///
/// The scheduler is a single thread that always sends the packet with the
/// earliest deadline across all streams. Top speed streams take whatever time
/// the paced streams leave free.
pub fn run_with_progress<F>(
    streams: &mut [Stream<'_>],
    sink: &mut dyn PacketSink,
    config: &RunConfig,
    interval: Duration,
    mut progress: F,
) -> Result<RunStats>
where
    F: FnMut(&RunStats),
{
    for s in streams.iter() {
        s.rate.validate()?;
        Pacer::check_model(s.rate, &s.model)
            .map_err(|e| Error::InvalidSpec(format!("stream '{}': {e}", s.name)))?;
    }
    if let Some(first) = streams.first() {
        let lt = first.linktype();
        if let Some(other) = streams.iter().map(Stream::linktype).find(|&l| l != lt) {
            return Err(Error::MixedLinkTypes(lt, other));
        }
    }

    let mut stats = RunStats {
        total: ReplayStats::default(),
        streams: vec![ReplayStats::default(); streams.len()],
    };
    let mut lanes: Vec<Lane> = streams
        .iter()
        .map(|s| Lane {
            pacer: Pacer::with_model(s.rate, &s.model).expect("checked above"),
            packet: Packet::new(Duration::ZERO, Vec::new()),
            pending: false,
            done: false,
            deadline: Duration::ZERO,
            passes: 0,
            signature: None,
            seq: s.shard.0,
            first: true,
        })
        .collect();

    let mut impairers: Vec<Option<Impairer>> = streams
        .iter()
        .map(|s| s.impair.clone().map(Impairer::new))
        .collect();
    let impaired = impairers.iter().any(Option::is_some);

    let stop_requested = || {
        config
            .stop
            .as_ref()
            .is_some_and(|s| s.load(Ordering::Relaxed))
    };
    let start = Instant::now();
    let mut next_report = start.checked_add(interval);

    loop {
        if config
            .limit
            .is_some_and(|l| stats.total.packets + stats.total.send_errors >= l)
        {
            break;
        }

        for ((stream, lane), st) in streams.iter_mut().zip(&mut lanes).zip(&stats.streams) {
            if !lane.pending && !lane.done {
                fill(stream, lane, st, start)?;
            }
        }
        let Some(i) = (0..lanes.len())
            .filter(|&i| lanes[i].pending)
            .min_by_key(|&i| lanes[i].deadline)
        else {
            break;
        };
        let lane = &mut lanes[i];

        if let Some(limit) = config.duration {
            if lane.deadline > limit || start.elapsed() > limit {
                break;
            }
        }
        let send_at = start + lane.deadline;
        if impaired {
            // Let held packets out as they fall due while we wait for this one.
            let mut waited = true;
            loop {
                if let Err(source) = release(&mut impairers, start.elapsed(), sink) {
                    if !config.ignore_send_errors {
                        let index = stats.total.packets + stats.total.send_errors;
                        let _ = sink.flush();
                        return Err(Error::Sink { index, source });
                    }
                }
                match next_due(&impairers) {
                    Some(due) if start + due < send_at => {
                        let _ = sink.idle();
                        if !wait_until(start + due, &stop_requested) {
                            waited = false;
                            break;
                        }
                    }
                    _ => break,
                }
            }
            if !waited {
                stats.total.stopped = true;
                break;
            }
        }
        if send_at > Instant::now() {
            // Let batching sinks hand over what they hold before we wait.
            if let Err(source) = sink.idle() {
                if !config.ignore_send_errors {
                    let index = stats.total.packets + stats.total.send_errors;
                    let _ = sink.flush();
                    return Err(Error::Sink { index, source });
                }
            }
        }
        if !wait_until(send_at, &stop_requested) {
            stats.total.stopped = true;
            break;
        }

        let flow = streams[i].latency;
        if let (Some(at), Some(flow)) = (lane.signature, flow) {
            stamp(&mut lane.packet.data, at, flow, lane.seq, wall_clock());
        }
        let len = lane.packet.data.len() as u64;
        let st = &mut stats.streams[i];
        let sent = match &mut impairers[i] {
            Some(link) => {
                link.push(&lane.packet.data, start.elapsed());
                Ok(())
            }
            None => sink.send(&lane.packet.data),
        };
        match sent {
            Ok(()) => {
                if lane.signature.is_some() {
                    // Numbers only advance on packets that left, so failed
                    // sends do not show up as loss.
                    lane.seq += streams[i].shard.1;
                    st.tagged += 1;
                    stats.total.tagged += 1;
                }
                st.packets += 1;
                st.bytes += len;
                stats.total.packets += 1;
                stats.total.bytes += len;
            }
            Err(_) if config.ignore_send_errors => {
                st.send_errors += 1;
                stats.total.send_errors += 1;
            }
            Err(source) => {
                let index = stats.total.packets + stats.total.send_errors;
                let _ = sink.flush();
                return Err(Error::Sink { index, source });
            }
        }
        stats.total.loops_completed += lane.passes - st.loops_completed;
        st.loops_completed = lane.passes;
        lane.pending = false;

        if let Some(at) = next_report {
            let now = Instant::now();
            if now >= at {
                set_elapsed(&mut stats, now - start);
                if impaired {
                    set_impair(&mut stats, &impairers);
                }
                progress(&stats);
                next_report = now.checked_add(interval);
            }
        }
    }

    if impaired && !stats.total.stopped {
        // The packets still on the link arrive before the run ends.
        loop {
            release(&mut impairers, start.elapsed(), sink).map_err(|source| Error::Sink {
                index: stats.total.packets,
                source,
            })?;
            let Some(due) = next_due(&impairers) else {
                break;
            };
            let _ = sink.idle();
            if !wait_until(start + due, &stop_requested) {
                stats.total.stopped = true;
                break;
            }
        }
    }
    sink.flush().map_err(|source| Error::Sink {
        index: stats.total.packets,
        source,
    })?;
    set_elapsed(&mut stats, start.elapsed());
    if impaired {
        set_impair(&mut stats, &impairers);
    }
    for st in &mut stats.streams {
        st.stopped = stats.total.stopped;
    }
    Ok(stats)
}

/// Reads and transforms the next packet of `stream`, and works out when it leaves.
fn fill(stream: &mut Stream<'_>, lane: &mut Lane, st: &ReplayStats, start: Instant) -> Result<()> {
    if stream
        .limit
        .is_some_and(|l| st.packets + st.send_errors >= l)
    {
        lane.done = true;
        return Ok(());
    }
    let (k, n) = stream.shard;
    if n > 1 {
        // The packets before this worker's next one belong to the others.
        let skip = if lane.first { k } else { n - 1 };
        if skip > 0 {
            if !stream.source.skip(skip)? {
                lane.done = true;
                return Ok(());
            }
            for t in &mut stream.transforms {
                t.skip(skip);
            }
        }
    }
    lane.first = false;
    if !stream.source.next_into(&mut lane.packet)? {
        lane.done = true;
        return Ok(());
    }
    for t in &mut stream.transforms {
        t.apply(&mut lane.packet);
    }
    lane.signature = stream.latency.and_then(|flow| {
        if stream.keep_size {
            reserve_inside(&mut lane.packet.data, flow)
        } else {
            reserve(&mut lane.packet.data, flow)
        }
    });
    lane.deadline = match lane
        .pacer
        .next_deadline(lane.packet.timestamp, lane.packet.data.len())
    {
        Some(d) => stream.delay + d,
        // The model's shape has ended: so has the stream.
        None if lane.pacer.ended() => {
            lane.done = true;
            return Ok(());
        }
        None => start.elapsed().max(stream.delay),
    };
    lane.passes = stream.source.passes();
    lane.pending = true;
    Ok(())
}

/// Sends what the impairers hold that is due by `now`.
fn release(
    impairers: &mut [Option<Impairer>],
    now: Duration,
    sink: &mut dyn PacketSink,
) -> std::result::Result<(), SinkError> {
    for link in impairers.iter_mut().flatten() {
        while let Some(frame) = link.pop_due(now) {
            sink.send(&frame)?;
        }
    }
    Ok(())
}

fn next_due(impairers: &[Option<Impairer>]) -> Option<Duration> {
    impairers
        .iter()
        .flatten()
        .filter_map(Impairer::next_due)
        .min()
}

fn set_impair(stats: &mut RunStats, impairers: &[Option<Impairer>]) {
    let mut total = ImpairStats::default();
    for (st, link) in stats.streams.iter_mut().zip(impairers) {
        st.impair = link.as_ref().map(|l| l.stats().clone());
        if let Some(s) = &st.impair {
            total.merge(s);
        }
    }
    stats.total.impair = Some(total);
}

fn set_elapsed(stats: &mut RunStats, elapsed: Duration) {
    stats.total.elapsed = elapsed;
    for st in &mut stats.streams {
        st.elapsed = elapsed;
    }
}

/// Waits until `target`, sleeping while far away and spinning for the last stretch,
/// because OS sleeps are too coarse for sub-millisecond gaps.
/// Returns false if a stop was requested while waiting.
fn wait_until(target: Instant, stop_requested: &impl Fn() -> bool) -> bool {
    const SPIN: Duration = Duration::from_micros(200);
    const MAX_SLEEP: Duration = Duration::from_millis(50);
    loop {
        if stop_requested() {
            return false;
        }
        let now = Instant::now();
        if now >= target {
            return true;
        }
        let remaining = target - now;
        if remaining > SPIN {
            std::thread::sleep((remaining - SPIN).min(MAX_SLEEP));
        } else {
            std::hint::spin_loop();
        }
    }
}
