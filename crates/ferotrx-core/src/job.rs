use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::{run_with_progress, Error, PacketSink, Result, RunConfig, RunStats, Stream};

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
    stop: Arc<AtomicBool>,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<Result<RunStats>>>,
}

struct Shared {
    live: Mutex<Live>,
    changed: Condvar,
}

struct Live {
    stats: RunStats,
    state: JobState,
    start: Instant,
}

impl Job {
    /// Starts running `streams` into `sink` on a new thread.
    ///
    /// The job stops when `config.stop` is set, or when [`stop`](Job::stop) is called;
    /// if `config.stop` is `None` the job makes its own flag.
    pub fn spawn(
        streams: Vec<Stream<'static>>,
        sink: Box<dyn PacketSink + Send>,
        mut config: RunConfig,
    ) -> Result<Job> {
        for s in &streams {
            s.rate.validate()?;
        }
        if let Some(first) = streams.first() {
            let lt = first.linktype();
            if let Some(other) = streams.iter().map(Stream::linktype).find(|&l| l != lt) {
                return Err(Error::MixedLinkTypes(lt, other));
            }
        }
        let stop = config
            .stop
            .get_or_insert_with(|| Arc::new(AtomicBool::new(false)))
            .clone();
        let names: Vec<String> = streams.iter().map(|s| s.name.clone()).collect();
        let shared = Arc::new(Shared {
            live: Mutex::new(Live {
                stats: RunStats {
                    total: Default::default(),
                    streams: vec![Default::default(); streams.len()],
                },
                state: JobState::Running,
                start: Instant::now(),
            }),
            changed: Condvar::new(),
        });
        let thread = {
            let shared = shared.clone();
            std::thread::Builder::new()
                .name("ferotrx-job".into())
                .spawn(move || {
                    let mut streams = streams;
                    let mut sink = sink;
                    shared.lock().start = Instant::now();
                    let result = run_with_progress(
                        &mut streams,
                        &mut *sink,
                        &config,
                        JOB_STATS_INTERVAL,
                        |s| shared.lock().stats = s.clone(),
                    );
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
                    shared.changed.notify_all();
                    result
                })?
        };
        Ok(Job {
            names,
            stop,
            shared,
            thread: Some(thread),
        })
    }

    /// Names of the streams, in the order of [`RunStats::streams`].
    pub fn stream_names(&self) -> &[String] {
        &self.names
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
}

/// Dropping a job stops it, so traffic never outlives its handle.
impl Drop for Job {
    fn drop(&mut self) {
        self.stop();
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
