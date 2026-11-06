//! Receiving: the [`PacketReceiver`] trait and [`RxJob`], a receiver on its own thread.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::{wall_clock, RxStats};
use crate::{JobState, PacketPort, Result, SinkError};

/// Something frames arrive on, for measuring loss and latency.
///
/// `ferotrx-io` has one for libpcap/Npcap interfaces, which reports the
/// kernel's receive time of each frame; [`PortReceiver`] makes one of any
/// [`PacketPort`].
pub trait PacketReceiver: Send {
    /// Puts the next frame into `buf` and returns when it arrived, as time
    /// since the Unix epoch, or returns `None` if nothing came for a little
    /// while. Must not block for more than about 50 ms, so a receiver can be
    /// stopped quickly.
    fn recv(&mut self, buf: &mut Vec<u8>) -> std::result::Result<Option<Duration>, SinkError>;
}

impl<R: PacketReceiver + ?Sized> PacketReceiver for Box<R> {
    fn recv(&mut self, buf: &mut Vec<u8>) -> std::result::Result<Option<Duration>, SinkError> {
        (**self).recv(buf)
    }
}

/// A [`PacketReceiver`] on a [`PacketPort`]: frames are stamped when they are
/// read, with the system clock.
#[derive(Debug)]
pub struct PortReceiver<P>(pub P);

impl<P: PacketPort> PacketReceiver for PortReceiver<P> {
    fn recv(&mut self, buf: &mut Vec<u8>) -> std::result::Result<Option<Duration>, SinkError> {
        if self.0.recv(buf)? {
            Ok(Some(wall_clock()))
        } else {
            // Ports return at once when nothing is waiting; do not spin.
            std::thread::sleep(Duration::from_micros(200));
            Ok(None)
        }
    }
}

/// Settings of an [`RxJob`].
#[derive(Clone, Debug, Default)]
pub struct RxConfig {
    /// Stop after this long.
    pub duration: Option<Duration>,
    /// Set to true from another thread to stop.
    pub stop: Option<Arc<AtomicBool>>,
    /// Count per interval of send time too (see [`RxStats::interval`]).
    pub interval: Option<Duration>,
}

/// How often a running [`RxJob`] publishes its counters.
const RX_STATS_INTERVAL: Duration = Duration::from_millis(100);

/// A receiver on its own thread, counting what arrives into [`RxStats`],
/// until it is stopped or its duration ends.
///
/// ```
/// use ferotrx_core::*;
/// use std::time::Duration;
///
/// let (mut tx, rx) = memory_ports();
/// let job = RxJob::spawn(Box::new(PortReceiver(rx)), RxConfig::default()).unwrap();
/// let capture = Capture::from_specs(&["eth/ipv4(dst=10.0.0.2)/udp(dport=7)"], Duration::ZERO).unwrap();
/// let mut streams = [Stream::new("a", CaptureSource::new(&capture).loops(20))
///     .with_rate(Rate::Pps(2000.0))
///     .with_latency(1)];
/// run(&mut streams, &mut tx, &RunConfig::default()).unwrap();
/// std::thread::sleep(Duration::from_millis(50));
/// job.stop();
/// let stats = job.join().unwrap();
/// assert_eq!(stats.flow(1).unwrap().unique(), 20);
/// ```
pub struct RxJob {
    stop: Arc<AtomicBool>,
    shared: Arc<Shared>,
    thread: Mutex<Option<JoinHandle<Result<RxStats>>>>,
}

struct Shared {
    live: Mutex<Live>,
    changed: Condvar,
}

struct Live {
    stats: RxStats,
    state: JobState,
    start: Instant,
}

impl RxJob {
    /// Starts counting what `receiver` gets, on a new thread.
    pub fn spawn(receiver: Box<dyn PacketReceiver>, mut config: RxConfig) -> Result<RxJob> {
        let stop = config
            .stop
            .get_or_insert_with(|| Arc::new(AtomicBool::new(false)))
            .clone();
        let shared = Arc::new(Shared {
            live: Mutex::new(Live {
                stats: RxStats::default(),
                state: JobState::Running,
                start: Instant::now(),
            }),
            changed: Condvar::new(),
        });
        let thread = {
            let shared = shared.clone();
            let stop = stop.clone();
            std::thread::Builder::new()
                .name("ferotrx-rx".into())
                .spawn(move || {
                    let result = receive(receiver, &config, &stop, &shared);
                    let mut live = shared.lock();
                    match &result {
                        Ok(stats) => {
                            live.stats = stats.clone();
                            live.state = JobState::Finished;
                        }
                        Err(e) => {
                            live.stats.elapsed = live.start.elapsed();
                            live.state = JobState::Failed(e.to_string());
                        }
                    }
                    drop(live);
                    shared.changed.notify_all();
                    result
                })?
        };
        Ok(RxJob {
            stop,
            shared,
            thread: Mutex::new(Some(thread)),
        })
    }

    /// The latest counters, at most 100 ms old while the job runs.
    pub fn stats(&self) -> RxStats {
        let live = self.shared.lock();
        let mut stats = live.stats.clone();
        if live.state == JobState::Running {
            stats.elapsed = live.start.elapsed();
        }
        stats
    }

    pub fn state(&self) -> JobState {
        self.shared.lock().state.clone()
    }

    pub fn is_running(&self) -> bool {
        self.state() == JobState::Running
    }

    /// Asks the receiver to stop; it does within about 50 ms.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Waits until the job ends or `timeout` passes (`None` waits for ever).
    /// Returns true if it has ended.
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
    pub fn join(self) -> Result<RxStats> {
        self.join_ref()
    }

    /// Like [`join`](RxJob::join) through a shared reference; a second call
    /// returns the counters as they were at the end.
    pub(crate) fn join_ref(&self) -> Result<RxStats> {
        let thread = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take();
        match thread {
            Some(t) => match t.join() {
                Ok(result) => result,
                Err(panic) => std::panic::resume_unwind(panic),
            },
            None => {
                self.wait(None);
                Ok(self.stats())
            }
        }
    }
}

impl Drop for RxJob {
    fn drop(&mut self) {
        self.stop();
    }
}

impl std::fmt::Debug for RxJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RxJob")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Live> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn receive(
    mut receiver: Box<dyn PacketReceiver>,
    config: &RxConfig,
    stop: &AtomicBool,
    shared: &Shared,
) -> Result<RxStats> {
    let start = Instant::now();
    shared.lock().start = start;
    let mut stats = RxStats {
        interval: config.interval,
        ..Default::default()
    };
    let mut buf = Vec::with_capacity(2048);
    let mut next_report = start + RX_STATS_INTERVAL;
    loop {
        if stop.load(Ordering::Relaxed) || config.duration.is_some_and(|d| start.elapsed() >= d) {
            break;
        }
        match receiver.recv(&mut buf) {
            Ok(Some(at)) => {
                stats.record(&buf, at);
            }
            Ok(None) => {}
            Err(e) => {
                shared.lock().stats = stats;
                return Err(crate::Error::Io(std::io::Error::other(format!(
                    "receiving failed: {e}"
                ))));
            }
        }
        let now = Instant::now();
        if now >= next_report {
            stats.elapsed = now - start;
            shared.lock().stats = stats.clone();
            next_report = now + RX_STATS_INTERVAL;
        }
    }
    stats.elapsed = start.elapsed();
    Ok(stats)
}
