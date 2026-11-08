use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::control::LaneClock;
use crate::latency::{reserve, reserve_inside, stamp, wall_clock};
use crate::{
    Error, ImpairSpec, ImpairStats, Impairer, MergeStats, Pacer, Packet, PacketSink, PacketSource,
    Rate, ReplayStats, Result, RunControl, SinkError, TrafficModel, Transform,
};

/// Packets in bursts with a pause between them (TRex's multi-burst,
/// Ostinato's bursts mode): `count` bursts (`None`: until the stream ends
/// otherwise) of `packets` each, sent at the stream's rate, with `gap` added
/// to the schedule before every burst after the first. So the time from the
/// last packet of a burst to the first of the next is `gap` plus one packet
/// interval (none at top speed).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MultiBurst {
    pub packets: u64,
    pub count: Option<u64>,
    pub gap: Duration,
}

impl MultiBurst {
    pub fn validate(&self) -> Result<()> {
        if self.packets == 0 || self.count == Some(0) {
            return Err(Error::InvalidSpec(
                "bursts need at least one packet and at least one burst".into(),
            ));
        }
        Ok(())
    }
}

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
    /// How far behind its schedule the stream may fall before it skips
    /// packets instead of sending them late. `None` (the default) catches up:
    /// after a stall (a busy CPU, a paused VM) the packets that are due go out
    /// back to back, which a policer downstream sees as a burst. With a
    /// limit, packets more than this late are left out, so the stream sends
    /// fewer packets but never bursts more than this much of its rate.
    pub max_lag: Option<Duration>,
    /// Bytes counted per packet on top of its length by a bit rate:
    /// [`WIRE_OVERHEAD`](crate::WIRE_OVERHEAD) for a rate on the wire (see
    /// [`RateSpec`](crate::RateSpec)).
    pub overhead: u32,
    /// Packets in bursts with gaps between them.
    pub bursts: Option<MultiBurst>,
    /// The stream (by index in the run) that starts when this one ends:
    /// the end of its source, its limit, its bursts or its model's shape.
    /// A stream that an earlier stream names here waits for that, unless
    /// [`self_start`](Self::self_start) says otherwise; a later stream
    /// naming an earlier one makes a loop.
    pub next: Option<usize>,
    /// How many times this stream starts its `next` (`None`: every time it
    /// ends). Pointing `next` back at an earlier stream makes a loop that
    /// runs this many more times.
    pub next_count: Option<u64>,
    /// Whether the stream starts with the run. `None` (the default): yes,
    /// unless an earlier stream names it as its [`next`](Self::next).
    pub self_start: Option<bool>,
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
            max_lag: None,
            overhead: 0,
            bursts: None,
            next: None,
            next_count: None,
            self_start: None,
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

    /// Skips packets that fall more than `lag` behind the schedule (see
    /// [`max_lag`](Self::max_lag)).
    pub fn with_max_lag(mut self, lag: Duration) -> Self {
        self.max_lag = Some(lag);
        self
    }

    /// Sends the packets in bursts (see [`MultiBurst`]).
    pub fn with_bursts(mut self, bursts: MultiBurst) -> Self {
        self.bursts = Some(bursts);
        self
    }

    /// Starts stream `index` of the run when this one ends, `count` times
    /// (`None`: every time).
    pub fn with_next(mut self, index: usize, count: Option<u64>) -> Self {
        self.next = Some(index);
        self.next_count = count;
        self
    }

    /// Whether the stream starts with the run (see [`self_start`](Self::self_start)).
    pub fn with_self_start(mut self, yes: bool) -> Self {
        self.self_start = Some(yes);
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

    /// Puts a transform before all the others.
    pub fn prepend_transform(&mut self, transform: impl Transform + 'a) {
        self.transforms.insert(0, Box::new(transform));
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
            .field("overhead", &self.overhead)
            .field("bursts", &self.bursts)
            .field("next", &self.next)
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
    /// A [`Job`](crate::Job) waits for this wall-clock time before it sends,
    /// so that runs on several machines start together (see [`wait_until`](crate::wait_until)).
    pub start_at: Option<std::time::SystemTime>,
    /// Pause, resume and change the rate while the run goes. A
    /// [`Job`](crate::Job) makes one when this is `None` (see
    /// [`Job::control`](crate::Job::control)).
    pub control: Option<Arc<RunControl>>,
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
    /// Sending now: started with the run or by another stream's end, and
    /// not ended yet. A lane that waits to be started is done but not active.
    active: bool,
    /// Ran before: a new start rewinds the source.
    used: bool,
    /// Offset on the stream's own schedule when the pending packet should leave.
    deadline: Duration,
    /// The source's pass count after the pending packet was read.
    passes: u64,
    /// Passes of earlier starts.
    pass_base: u64,
    /// Where the pending packet's latency signature is.
    signature: Option<usize>,
    /// Sequence number of the next signature.
    seq: u64,
    /// No packet read yet (a shard skips the packets before its first).
    first: bool,
    /// The stream's sent and failed packets when it last started, for its limit.
    base: u64,
    /// Packets this worker read since the stream last started.
    count: u64,
    /// The burst of the last packet read.
    burst: u64,
    /// Top speed in bursts: no packet before this point of the schedule.
    floor: Duration,
    /// Times `next` may still be started (`None`: always).
    nexts_left: Option<u64>,
    /// The stream's schedule against the run's clock.
    clock: LaneClock,
}

impl Lane {
    /// Where the stream's schedule is now.
    fn sched_now(&self, start: Instant) -> Duration {
        Duration::from_secs_f64(self.clock.sched(start.elapsed().as_secs_f64()))
    }

    /// When the pending packet leaves, as time since the run started;
    /// `None` while the stream is paused.
    fn real_deadline(&self) -> Option<Duration> {
        let t = self.clock.real(self.deadline.as_secs_f64());
        t.is_finite().then(|| Duration::from_secs_f64(t))
    }
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
        if let Some(b) = &s.bursts {
            b.validate()
                .map_err(|e| Error::InvalidSpec(format!("stream '{}': {e}", s.name)))?;
        }
        if let Some(n) = s.next {
            if n >= streams.len() {
                return Err(Error::InvalidSpec(format!(
                    "stream '{}': next stream {n} is not in the run",
                    s.name
                )));
            }
        }
    }
    if let Some(first) = streams.first() {
        let lt = first.linktype();
        if let Some(other) = streams.iter().map(Stream::linktype).find(|&l| l != lt) {
            return Err(Error::MixedLinkTypes(lt, other));
        }
    }
    // Streams an earlier stream starts wait for it, unless told otherwise.
    let waits: Vec<bool> = (0..streams.len())
        .map(|i| match streams[i].self_start {
            Some(yes) => !yes,
            None => streams[..i].iter().any(|s| s.next == Some(i)),
        })
        .collect();

    let mut stats = RunStats {
        total: ReplayStats::default(),
        streams: vec![ReplayStats::default(); streams.len()],
    };
    let mut lanes: Vec<Lane> = streams
        .iter()
        .zip(&waits)
        .map(|(s, &waits)| Lane {
            pacer: Pacer::with_model(s.rate, &s.model)
                .expect("checked above")
                .with_overhead(s.overhead),
            packet: Packet::new(Duration::ZERO, Vec::new()),
            pending: false,
            done: waits,
            active: !waits,
            used: !waits,
            deadline: Duration::ZERO,
            passes: 0,
            pass_base: 0,
            signature: None,
            seq: s.shard.0,
            first: true,
            base: 0,
            count: 0,
            burst: 0,
            floor: Duration::ZERO,
            nexts_left: s.next_count,
            clock: LaneClock::default(),
        })
        .collect();

    let mut impairers: Vec<Option<Impairer>> = streams
        .iter()
        .map(|s| s.impair.clone().map(Impairer::new))
        .collect();
    let impaired = impairers.iter().any(Option::is_some);

    let control = config.control.as_deref();
    let mut seen = None;
    let stop_requested = || {
        config
            .stop
            .as_ref()
            .is_some_and(|s| s.load(Ordering::Relaxed))
    };
    let changed = |seen: Option<u64>| control.is_some_and(|c| Some(c.generation()) != seen);
    let start = Instant::now();
    let mut next_report = start.checked_add(interval);

    loop {
        if config
            .limit
            .is_some_and(|l| stats.total.packets + stats.total.send_errors >= l)
        {
            break;
        }
        if let Some(c) = control {
            let g = c.generation();
            if seen != Some(g) {
                seen = Some(g);
                let state = c.state();
                let now = start.elapsed().as_secs_f64();
                for (i, lane) in lanes.iter_mut().enumerate() {
                    lane.clock.set_speed(now, state.speed(i));
                }
            }
        }

        // Fill the lanes; a stream that ends may start another one.
        loop {
            let mut started = false;
            for i in 0..lanes.len() {
                if lanes[i].pending || lanes[i].done {
                    continue;
                }
                fill(&mut streams[i], &mut lanes[i], &stats.streams[i], start)?;
                if lanes[i].done && lanes[i].active {
                    lanes[i].active = false;
                    if let Some(j) = next_to_start(&streams[i], &mut lanes[i]) {
                        begin(&mut streams[j], &mut lanes, j, &stats.streams[j], start)?;
                        started = true;
                    }
                }
            }
            if !started {
                break;
            }
        }
        let Some(i) = (0..lanes.len())
            .filter(|&i| lanes[i].pending)
            .min_by(|&a, &b| {
                let key = |i: usize| lanes[i].real_deadline().unwrap_or(Duration::MAX);
                key(a).cmp(&key(b))
            })
        else {
            break;
        };
        let Some(real) = lanes[i].real_deadline() else {
            // Every stream with a packet to send is paused: wait for a change.
            if let Some(limit) = config.duration {
                if start.elapsed() > limit {
                    break;
                }
            }
            let wake = Instant::now() + PAUSED_POLL;
            let wake = match next_due(&impairers) {
                Some(due) if start + due < wake => start + due,
                _ => wake,
            };
            if let Err(source) = release(&mut impairers, start.elapsed(), sink) {
                if !config.ignore_send_errors {
                    let index = stats.total.packets + stats.total.send_errors;
                    let _ = sink.flush();
                    return Err(Error::Sink { index, source });
                }
            }
            let _ = sink.idle();
            match wait_until(wake, &stop_requested, &|| changed(seen)) {
                Wait::Stopped => {
                    stats.total.stopped = true;
                    break;
                }
                Wait::Due | Wait::Changed => {}
            }
            report(
                &mut next_report,
                interval,
                start,
                &mut stats,
                impaired,
                &impairers,
                &mut progress,
            );
            continue;
        };
        let lane = &mut lanes[i];

        if let Some(limit) = config.duration {
            if real > limit || start.elapsed() > limit {
                break;
            }
        }
        let send_at = start + real;
        if impaired {
            // Let held packets out as they fall due while we wait for this one.
            let mut outcome = Wait::Due;
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
                        outcome = wait_until(start + due, &stop_requested, &|| changed(seen));
                        if outcome != Wait::Due {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            match outcome {
                Wait::Stopped => {
                    stats.total.stopped = true;
                    break;
                }
                Wait::Changed => continue,
                Wait::Due => {}
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
        match wait_until(send_at, &stop_requested, &|| changed(seen)) {
            Wait::Stopped => {
                stats.total.stopped = true;
                break;
            }
            // The schedule changed: the packet keeps its place and gets a new time.
            Wait::Changed => continue,
            Wait::Due => {}
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
        let passes = lane.pass_base + lane.passes;
        stats.total.loops_completed += passes - st.loops_completed;
        st.loops_completed = passes;
        lane.pending = false;

        report(
            &mut next_report,
            interval,
            start,
            &mut stats,
            impaired,
            &impairers,
            &mut progress,
        );
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
            if wait_until(start + due, &stop_requested, &|| false) == Wait::Stopped {
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

/// How often a run whose streams are all paused looks for a change.
const PAUSED_POLL: Duration = Duration::from_millis(20);

/// Calls `progress` when a report is due.
#[allow(clippy::too_many_arguments)]
fn report<F: FnMut(&RunStats)>(
    next_report: &mut Option<Instant>,
    interval: Duration,
    start: Instant,
    stats: &mut RunStats,
    impaired: bool,
    impairers: &[Option<Impairer>],
    progress: &mut F,
) {
    if let Some(at) = *next_report {
        let now = Instant::now();
        if now >= at {
            set_elapsed(stats, now - start);
            if impaired {
                set_impair(stats, impairers);
            }
            progress(stats);
            *next_report = now.checked_add(interval);
        }
    }
}

/// The stream an ended stream starts, if any is left to start.
fn next_to_start(stream: &Stream<'_>, lane: &mut Lane) -> Option<usize> {
    let next = stream.next?;
    match &mut lane.nexts_left {
        Some(0) => None,
        Some(n) => {
            *n -= 1;
            Some(next)
        }
        None => Some(next),
    }
}

/// Starts stream `j` (again): its schedule, limit and bursts from the top,
/// its source from the first packet. Field engines and signature numbers go on.
fn begin(
    stream: &mut Stream<'_>,
    lanes: &mut [Lane],
    j: usize,
    st: &ReplayStats,
    start: Instant,
) -> Result<()> {
    let lane = &mut lanes[j];
    if lane.active {
        // Still going: nothing to start.
        return Ok(());
    }
    if lane.used && !stream.source.rewind() {
        return Err(Error::InvalidSpec(format!(
            "stream '{}' can't start again: its source can't start over",
            stream.name
        )));
    }
    lane.pass_base += lane.passes;
    lane.passes = 0;
    lane.pacer = Pacer::with_model(stream.rate, &stream.model)?.with_overhead(stream.overhead);
    lane.pending = false;
    lane.done = false;
    lane.active = true;
    lane.used = true;
    lane.first = true;
    lane.base = st.packets + st.send_errors;
    lane.count = 0;
    lane.burst = 0;
    lane.floor = Duration::ZERO;
    lane.clock.restart(start.elapsed().as_secs_f64());
    Ok(())
}

/// Reads and transforms the next packet of `stream`, and works out when it
/// leaves. With a [`max_lag`](Stream::max_lag), packets due longer ago than
/// that are skipped.
fn fill(stream: &mut Stream<'_>, lane: &mut Lane, st: &ReplayStats, start: Instant) -> Result<()> {
    loop {
        fill_one(stream, lane, st, start)?;
        let late = match stream.max_lag {
            Some(lag) if lane.pending && !lane.clock.paused() => {
                lane.sched_now(start) > lane.deadline + lag
            }
            _ => false,
        };
        if !late {
            return Ok(());
        }
        lane.pending = false;
    }
}

fn fill_one(
    stream: &mut Stream<'_>,
    lane: &mut Lane,
    st: &ReplayStats,
    start: Instant,
) -> Result<()> {
    if stream
        .limit
        .is_some_and(|l| st.packets + st.send_errors - lane.base >= l)
    {
        lane.done = true;
        return Ok(());
    }
    let (k, n) = stream.shard;
    // The burst of the packet about to be read: packet `count` of this
    // worker is packet `k + count * n` of the whole stream.
    let burst = stream.bursts.map(|b| (k + lane.count * n) / b.packets);
    if let (Some(b), Some(burst)) = (&stream.bursts, burst) {
        if b.count.is_some_and(|c| burst >= c) {
            lane.done = true;
            return Ok(());
        }
    }
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
    // Every burst after the first starts `gap` later on the schedule.
    let gaps = match (&stream.bursts, burst) {
        (Some(b), Some(burst)) => {
            if burst != lane.burst && lane.count > 0 {
                lane.floor = lane.sched_now(start) + b.gap;
            }
            lane.burst = burst;
            b.gap
                .saturating_mul(u32::try_from(burst).unwrap_or(u32::MAX))
        }
        _ => Duration::ZERO,
    };
    lane.count += 1;
    lane.deadline = match lane
        .pacer
        .next_deadline(lane.packet.timestamp, lane.packet.data.len())
    {
        Some(d) => stream.delay + gaps + d,
        // The model's shape has ended: so has the stream.
        None if lane.pacer.ended() => {
            lane.done = true;
            return Ok(());
        }
        // Top speed: now, after the start delay and a burst's gap.
        None => lane.sched_now(start).max(stream.delay).max(lane.floor),
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

/// How a [`wait_until`] ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wait {
    Due,
    Stopped,
    /// The run control changed: the schedule needs another look.
    Changed,
}

/// Waits until `target`, sleeping while far away and spinning for the last stretch,
/// because OS sleeps are too coarse for sub-millisecond gaps. Ends early when
/// a stop is requested or `changed` says the schedule changed.
fn wait_until(
    target: Instant,
    stop_requested: &impl Fn() -> bool,
    changed: &impl Fn() -> bool,
) -> Wait {
    const SPIN: Duration = Duration::from_micros(200);
    const MAX_SLEEP: Duration = Duration::from_millis(50);
    loop {
        if stop_requested() {
            return Wait::Stopped;
        }
        if changed() {
            return Wait::Changed;
        }
        let now = Instant::now();
        if now >= target {
            return Wait::Due;
        }
        let remaining = target - now;
        if remaining > SPIN {
            std::thread::sleep((remaining - SPIN).min(MAX_SLEEP));
        } else {
            std::hint::spin_loop();
        }
    }
}
