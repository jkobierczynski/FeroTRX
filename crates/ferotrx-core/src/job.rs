use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use crate::{
    merge_all, run_with_progress, share, Error, FlowReport, PacketReceiver, PacketSink, Rate,
    Result, RunConfig, RunControl, RunStats, RxConfig, RxJob, RxStats, Stream,
};

/// How often a running [`Job`] publishes its counters.
pub const JOB_STATS_INTERVAL: Duration = Duration::from_millis(100);

/// What a [`Job`] is doing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobState {
    Running,
    /// The run ended: all streams finished, a limit was reached, or it was stopped.
    Finished,
    /// The run ended with an error, such as a failed send.
    Failed(String),
}

/// A receiver that runs alongside a [`Job`]'s streams, to measure the loss and
/// latency of the streams made with [`Stream::with_latency`].
pub struct RxSettings {
    pub receiver: Box<dyn PacketReceiver>,
    /// How long to keep receiving after the last packet is sent, for packets
    /// still on their way.
    pub wait: Duration,
}

impl RxSettings {
    /// Time a receiver keeps going after the last packet, unless told otherwise.
    pub const DEFAULT_WAIT: Duration = Duration::from_millis(500);

    pub fn new(receiver: Box<dyn PacketReceiver>) -> Self {
        Self {
            receiver,
            wait: Self::DEFAULT_WAIT,
        }
    }
}

/// A [`run`](crate::run) on its own thread, which can be watched and stopped
/// from other threads.
///
/// This is how the `ferotrx` command line tool and the `ferotrx-ctl` control
/// server both run traffic, so they share one code path.
///
/// ```
/// use ferotrx_core::*;
/// use std::time::Duration;
///
/// let capture = Capture::new(1, vec![Packet::new(Duration::ZERO, vec![0u8; 60])]);
/// let streams = vec![
///     Stream::new("a", CaptureSource::new(std::sync::Arc::new(capture)).loops(0))
///         .with_rate(Rate::Pps(1000.0)),
/// ];
/// let job = Job::spawn(streams, Box::new(NullSink), RunConfig::default()).unwrap();
/// std::thread::sleep(Duration::from_millis(300));
/// assert!(job.stats().total.packets > 0);
/// job.stop();
/// let stats = job.join().unwrap();
/// assert!(stats.total.stopped);
/// ```
pub struct Job {
    names: Vec<String>,
    rates: Vec<Rate>,
    flows: Vec<Option<u32>>,
    workers: usize,
    rx: Option<Arc<RxJob>>,
    stop: Arc<AtomicBool>,
    control: Arc<RunControl>,
    ended: Arc<AtomicBool>,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<Result<RunStats>>>,
}

struct Shared {
    live: Mutex<Live>,
    changed: Condvar,
}

struct Live {
    /// All workers together.
    stats: RunStats,
    /// Each worker's latest counters.
    parts: Vec<RunStats>,
    state: JobState,
    start: Instant,
    /// When the streams started, by the wall clock (after `start_at`).
    started_at: Option<SystemTime>,
}

impl Job {
    /// Starts running `streams` into `sink` on a new thread.
    ///
    /// The job stops when `config.stop` is set, or when [`stop`](Job::stop) is called;
    /// if `config.stop` is `None` the job makes its own flag.
    pub fn spawn(
        streams: Vec<Stream<'static>>,
        sink: Box<dyn PacketSink + Send>,
        config: RunConfig,
    ) -> Result<Job> {
        Self::spawn_with_rx(streams, sink, config, None)
    }

    /// Like [`spawn`](Job::spawn), with a receiver counting what arrives while
    /// the streams run, and for `rx.wait` after. The job ends when the
    /// receiver does. See [`rx_stats`](Job::rx_stats) and [`flow_reports`](Job::flow_reports).
    ///
    /// ```
    /// use ferotrx_core::*;
    /// use std::time::Duration;
    ///
    /// let (tx, rx) = memory_ports();
    /// let cap = std::sync::Arc::new(Capture::from_specs(
    ///     &["eth/ipv4(dst=10.0.0.2)/udp(dport=7)/raw(len=32)"], Duration::ZERO).unwrap());
    /// let streams = vec![Stream::new("probe", CaptureSource::new(cap).loops(100))
    ///     .with_rate(Rate::Pps(5000.0))
    ///     .with_latency(1)];
    /// let rx = RxSettings { receiver: Box::new(PortReceiver(rx)), wait: Duration::from_millis(50) };
    /// let job = Job::spawn_with_rx(streams, Box::new(tx), RunConfig::default(), Some(rx)).unwrap();
    /// job.wait(None);
    /// let report = &job.flow_reports()[0];
    /// assert_eq!((report.tx, report.rx, report.lost), (100, 100, 0));
    /// assert!(report.latency.max().unwrap() < Duration::from_secs(1));
    /// ```
    pub fn spawn_with_rx(
        streams: Vec<Stream<'static>>,
        sink: Box<dyn PacketSink + Send>,
        config: RunConfig,
        rx: Option<RxSettings>,
    ) -> Result<Job> {
        Self::spawn_workers(vec![(streams, sink)], config, rx)
    }

    /// Like [`spawn_with_rx`](Job::spawn_with_rx), on several threads: one per
    /// worker, each with its own streams and sink. Every worker's streams are
    /// the same streams, made with [`Stream::shard`] for that worker, so
    /// together they send what one thread would; the counters are the
    /// workers' added up. A total `config.limit` is shared out among them.
    ///
    /// ```
    /// use ferotrx_core::*;
    /// use std::sync::Arc;
    /// use std::time::Duration;
    ///
    /// let cap = Arc::new(Capture::new(1, vec![Packet::new(Duration::ZERO, vec![0u8; 60])]));
    /// let workers = (0..4)
    ///     .map(|k| {
    ///         let stream = Stream::new("a", CaptureSource::new(cap.clone()).loops(1000))
    ///             .with_rate(Rate::TopSpeed)
    ///             .shard(k, 4);
    ///         (vec![stream], Box::new(NullSink) as Box<dyn PacketSink + Send>)
    ///     })
    ///     .collect();
    /// let job = Job::spawn_workers(workers, RunConfig::default(), None).unwrap();
    /// assert_eq!(job.workers(), 4);
    /// let stats = job.join().unwrap();
    /// assert_eq!(stats.total.packets, 1000);
    /// assert_eq!(stats.streams[0].loops_completed, 1000);
    /// ```
    pub fn spawn_workers(
        workers: Vec<(Vec<Stream<'static>>, Box<dyn PacketSink + Send>)>,
        mut config: RunConfig,
        rx: Option<RxSettings>,
    ) -> Result<Job> {
        let Some((first, _)) = workers.first() else {
            return Err(Error::InvalidSpec("a run needs at least one worker".into()));
        };
        let count = workers.len();
        for (streams, _) in &workers {
            for s in streams {
                s.rate.validate()?;
            }
            if let Some(first) = streams.first() {
                let lt = first.linktype();
                if let Some(other) = streams.iter().map(Stream::linktype).find(|&l| l != lt) {
                    return Err(Error::MixedLinkTypes(lt, other));
                }
            }
            if streams.len() != first.len() {
                return Err(Error::InvalidSpec(
                    "every worker needs the same streams".into(),
                ));
            }
        }
        let stop = config
            .stop
            .get_or_insert_with(|| Arc::new(AtomicBool::new(false)))
            .clone();
        let control = config
            .control
            .get_or_insert_with(|| Arc::new(RunControl::new()))
            .clone();
        let names: Vec<String> = first.iter().map(|s| s.name.clone()).collect();
        let flows: Vec<Option<u32>> = first.iter().map(|s| s.latency).collect();
        // The rate asked for: the workers' parts added up.
        let rates: Vec<Rate> = (0..first.len())
            .map(|i| {
                workers
                    .iter()
                    .map(|(streams, _)| streams[i].rate)
                    .reduce(|a, b| match (a, b) {
                        (Rate::Pps(a), Rate::Pps(b)) => Rate::Pps(a + b),
                        (Rate::Mbps(a), Rate::Mbps(b)) => Rate::Mbps(a + b),
                        (a, _) => a,
                    })
                    .expect("at least one worker")
            })
            .collect();
        let (rx, rx_wait) = match rx {
            Some(r) => (
                Some(Arc::new(RxJob::spawn(r.receiver, RxConfig::default())?)),
                r.wait,
            ),
            None => (None, Duration::ZERO),
        };
        let empty = RunStats {
            total: Default::default(),
            streams: vec![Default::default(); first.len()],
        };
        let shared = Arc::new(Shared {
            live: Mutex::new(Live {
                stats: empty.clone(),
                parts: vec![empty; count],
                state: JobState::Running,
                start: Instant::now(),
                started_at: None,
            }),
            changed: Condvar::new(),
        });
        let ended = Arc::new(AtomicBool::new(false));
        let thread = {
            let shared = shared.clone();
            let rx = rx.clone();
            let stop = stop.clone();
            let ended = ended.clone();
            std::thread::Builder::new()
                .name("ferotrx-job".into())
                .spawn(move || {
                    let started = crate::wait_until(config.start_at, &stop);
                    {
                        let mut live = shared.lock();
                        live.start = Instant::now();
                        live.started_at = Some(started);
                    }
                    let mut result = run_workers(workers, &config, &shared, &stop);
                    if let Some(rx) = rx {
                        // Packets still on their way get `rx_wait` to arrive.
                        rx.wait(Some(rx_wait));
                        rx.stop();
                        if let Err(e) = rx.join_ref() {
                            if result.is_ok() {
                                result = Err(e);
                            }
                        }
                    }
                    let mut live = shared.lock();
                    match &result {
                        Ok(stats) => {
                            live.stats = stats.clone();
                            live.state = JobState::Finished;
                        }
                        Err(e) => {
                            let elapsed = live.start.elapsed();
                            live.stats.total.elapsed = elapsed;
                            for st in &mut live.stats.streams {
                                st.elapsed = elapsed;
                            }
                            live.state = JobState::Failed(e.to_string());
                        }
                    }
                    drop(live);
                    ended.store(true, Ordering::Release);
                    shared.changed.notify_all();
                    result
                })?
        };
        Ok(Job {
            names,
            rates,
            flows,
            workers: count,
            rx,
            stop,
            control,
            ended,
            shared,
            thread: Some(thread),
        })
    }

    /// When the streams started, by the wall clock; `None` while the job
    /// waits for its [`RunConfig::start_at`].
    pub fn started_at(&self) -> Option<SystemTime> {
        self.shared.lock().started_at
    }

    /// Pauses, resumes and changes the rate of the running streams (all
    /// workers together); stream numbers are as in [`stream_names`](Job::stream_names).
    pub fn control(&self) -> &Arc<RunControl> {
        &self.control
    }

    /// A flag that turns true when the job has ended, for helpers that live
    /// as long as the run (such as a port answering ARP for it).
    pub fn ended_flag(&self) -> Arc<AtomicBool> {
        self.ended.clone()
    }

    /// The number of threads the streams run on (see [`spawn_workers`](Job::spawn_workers)).
    pub fn workers(&self) -> usize {
        self.workers
    }

    /// Names of the streams, in the order of [`RunStats::streams`].
    pub fn stream_names(&self) -> &[String] {
        &self.names
    }

    /// The rate each stream was asked to send at, in the order of [`RunStats::streams`].
    pub fn rates(&self) -> &[Rate] {
        &self.rates
    }

    /// The latency flow id of each stream (see [`Stream::with_latency`]), in
    /// the order of [`RunStats::streams`].
    pub fn flows(&self) -> &[Option<u32>] {
        &self.flows
    }

    /// The receiver's latest counters, if the job has one
    /// ([`spawn_with_rx`](Job::spawn_with_rx)); final once the job has ended.
    pub fn rx_stats(&self) -> Option<RxStats> {
        self.rx.as_ref().map(|r| r.stats())
    }

    /// Sent against received, for each stream with a latency signature, when
    /// the job has a receiver. While the job runs, packets on their way count
    /// as lost.
    pub fn flow_reports(&self) -> Vec<FlowReport> {
        match self.rx_stats() {
            Some(rx) => FlowReport::for_run(&self.names, &self.flows, &self.stats(), &rx),
            None => Vec::new(),
        }
    }

    /// The latest counters. While the job runs they are at most
    /// [`JOB_STATS_INTERVAL`] old, except for `elapsed`, which is current.
    pub fn stats(&self) -> RunStats {
        let live = self.shared.lock();
        let mut stats = live.stats.clone();
        if live.state == JobState::Running {
            let elapsed = live.start.elapsed();
            stats.total.elapsed = elapsed;
            for st in &mut stats.streams {
                st.elapsed = elapsed;
            }
        }
        stats
    }

    pub fn state(&self) -> JobState {
        self.shared.lock().state.clone()
    }

    pub fn is_running(&self) -> bool {
        self.state() == JobState::Running
    }

    /// Asks the job to stop. It stops within a few milliseconds; use
    /// [`wait`](Job::wait) or [`join`](Job::join) to wait for it.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Waits until the job ends or `timeout` passes (`None` waits for ever).
    /// Returns true if the job has ended.
    pub fn wait(&self, timeout: Option<Duration>) -> bool {
        let deadline = timeout.and_then(|t| Instant::now().checked_add(t));
        let mut live = self.shared.lock();
        while live.state == JobState::Running {
            match deadline {
                None => {
                    live = self
                        .shared
                        .changed
                        .wait(live)
                        .unwrap_or_else(|e| e.into_inner())
                }
                Some(d) => {
                    let now = Instant::now();
                    if now >= d {
                        return false;
                    }
                    live = self
                        .shared
                        .changed
                        .wait_timeout(live, d - now)
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
            }
        }
        true
    }

    /// Waits for the job to end and returns its final counters or its error.
    pub fn join(mut self) -> Result<RunStats> {
        let thread = self.thread.take().expect("job thread is joined once");
        match thread.join() {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Live> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Worker `k`'s latest counters, and the total again.
    fn update(&self, k: usize, stats: &RunStats) {
        let mut live = self.lock();
        live.parts[k] = stats.clone();
        live.stats = merge_all(&live.parts);
    }
}

/// Runs each worker's streams on a thread of its own and adds up the counters.
/// A worker that fails stops the others.
fn run_workers(
    workers: Vec<(Vec<Stream<'static>>, Box<dyn PacketSink + Send>)>,
    config: &RunConfig,
    shared: &Shared,
    stop: &AtomicBool,
) -> Result<RunStats> {
    let count = workers.len();
    if count == 1 {
        let (mut streams, mut sink) = workers.into_iter().next().expect("one worker");
        return run_with_progress(&mut streams, &mut *sink, config, JOB_STATS_INTERVAL, |s| {
            shared.update(0, s)
        });
    }
    let results: Vec<Result<RunStats>> = std::thread::scope(|scope| {
        let handles: Vec<_> = workers
            .into_iter()
            .enumerate()
            .map(|(k, (mut streams, mut sink))| {
                let mut config = config.clone();
                config.limit = config.limit.map(|l| share(l, k, count));
                std::thread::Builder::new()
                    .name(format!("ferotrx-worker-{k}"))
                    .spawn_scoped(scope, move || {
                        let result = run_with_progress(
                            &mut streams,
                            &mut *sink,
                            &config,
                            JOB_STATS_INTERVAL,
                            |s| shared.update(k, s),
                        );
                        match &result {
                            Ok(s) => shared.update(k, s),
                            Err(_) => stop.store(true, Ordering::Relaxed),
                        }
                        result
                    })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| match h {
                Ok(h) => h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)),
                Err(e) => {
                    stop.store(true, Ordering::Relaxed);
                    Err(e.into())
                }
            })
            .collect()
    });
    let mut parts = Vec::with_capacity(count);
    for r in results {
        parts.push(r?);
    }
    Ok(merge_all(&parts))
}

/// Dropping a job stops it, so traffic never outlives its handle.
impl Drop for Job {
    fn drop(&mut self) {
        self.stop();
        if let Some(rx) = &self.rx {
            rx.stop();
        }
    }
}

impl std::fmt::Debug for Job {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Job")
            .field("streams", &self.names)
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Capture, CaptureSource, NullSink, Packet, Rate, SinkError, VecSink};

    fn streams(loops: u64, rate: Rate) -> Vec<Stream<'static>> {
        let cap = Arc::new(Capture::new(
            1,
            vec![Packet::new(Duration::ZERO, vec![0u8; 60])],
        ));
        vec![
            Stream::new("a", CaptureSource::new(cap.clone()).loops(loops)).with_rate(rate),
            Stream::new("b", CaptureSource::new(cap).loops(loops)).with_rate(rate),
        ]
    }

    #[test]
    fn runs_to_the_end() {
        let job = Job::spawn(
            streams(10, Rate::TopSpeed),
            Box::new(VecSink::default()),
            RunConfig::default(),
        )
        .unwrap();
        assert_eq!(job.stream_names(), ["a", "b"]);
        assert!(job.wait(Some(Duration::from_secs(10))));
        assert_eq!(job.state(), JobState::Finished);
        assert_eq!(job.stats().total.packets, 20);
        let stats = job.join().unwrap();
        assert_eq!(stats.streams[1].packets, 10);
        assert!(!stats.total.stopped);
    }

    #[test]
    fn stops_on_request_and_reports_live_counters() {
        let job = Job::spawn(
            streams(0, Rate::Pps(2000.0)),
            Box::new(NullSink),
            RunConfig::default(),
        )
        .unwrap();
        assert!(!job.wait(Some(Duration::from_millis(300))));
        assert!(job.is_running());
        let live = job.stats();
        assert!(live.total.packets > 0, "{live:?}");
        assert!(live.total.elapsed >= Duration::from_millis(200));
        job.stop();
        assert!(job.wait(Some(Duration::from_secs(5))));
        let stats = job.join().unwrap();
        assert!(stats.total.stopped);
        assert!(stats.total.packets >= live.total.packets);
    }

    struct Failing;
    impl PacketSink for Failing {
        fn send(&mut self, _: &[u8]) -> std::result::Result<(), SinkError> {
            Err("link down".into())
        }
    }

    #[test]
    fn reports_failures() {
        let job = Job::spawn(
            streams(1, Rate::TopSpeed),
            Box::new(Failing),
            RunConfig::default(),
        )
        .unwrap();
        job.wait(None);
        match job.state() {
            JobState::Failed(msg) => assert!(msg.contains("link down"), "{msg}"),
            other => panic!("{other:?}"),
        }
        assert!(job.join().is_err());
    }

    #[test]
    fn rejects_bad_rates_up_front() {
        let err = Job::spawn(
            streams(1, Rate::Pps(0.0)),
            Box::new(NullSink),
            RunConfig::default(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidRate(_)));
    }
}
