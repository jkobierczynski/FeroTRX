use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::{Error, Pacer, Packet, PacketSink, PacketSource, Rate, ReplayStats, Result, Transform};

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

    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
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
}

impl std::fmt::Debug for Stream<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream")
            .field("name", &self.name)
            .field("rate", &self.rate)
            .field("limit", &self.limit)
            .field("delay", &self.delay)
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
            pacer: Pacer::new(s.rate),
            packet: Packet::new(Duration::ZERO, Vec::new()),
            pending: false,
            done: false,
            deadline: Duration::ZERO,
            passes: 0,
        })
        .collect();

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
        if !wait_until(start + lane.deadline, &stop_requested) {
            stats.total.stopped = true;
            break;
        }

        let len = lane.packet.data.len() as u64;
        let st = &mut stats.streams[i];
        match sink.send(&lane.packet.data) {
            Ok(()) => {
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
                progress(&stats);
                next_report = now.checked_add(interval);
            }
        }
    }

    sink.flush().map_err(|source| Error::Sink {
        index: stats.total.packets,
        source,
    })?;
    set_elapsed(&mut stats, start.elapsed());
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
        || !stream.source.next_into(&mut lane.packet)?
    {
        lane.done = true;
        return Ok(());
    }
    for t in &mut stream.transforms {
        t.apply(&mut lane.packet);
    }
    lane.deadline = match lane
        .pacer
        .next_deadline(lane.packet.timestamp, lane.packet.data.len())
    {
        Some(d) => stream.delay + d,
        None => start.elapsed().max(stream.delay),
    };
    lane.passes = stream.source.passes();
    lane.pending = true;
    Ok(())
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
