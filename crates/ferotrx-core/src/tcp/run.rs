//! Running a [`TcpEngine`] on real ports, on this thread or on its own.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::engine::{TcpEngine, TcpStats};
use crate::{Error, PacketSink, Result, SinkError};

/// A network port that can send and receive frames, for stateful traffic.
///
/// `ferotrx-io` has one for libpcap/Npcap interfaces; [`memory_ports`] makes
/// a pair joined back to back.
pub trait PacketPort: Send {
    /// Sends one frame, starting at the Ethernet header.
    fn send(&mut self, frame: &[u8]) -> std::result::Result<(), SinkError>;

    /// Puts the next received frame into `buf` and returns true, or returns
    /// false at once if none is waiting. Must not block for long.
    fn recv(&mut self, buf: &mut Vec<u8>) -> std::result::Result<bool, SinkError>;

    /// Hands over frames queued by `send`, if the port batches them.
    fn flush(&mut self) -> std::result::Result<(), SinkError> {
        Ok(())
    }
}

impl<P: PacketPort + ?Sized> PacketPort for Box<P> {
    fn send(&mut self, frame: &[u8]) -> std::result::Result<(), SinkError> {
        (**self).send(frame)
    }
    fn recv(&mut self, buf: &mut Vec<u8>) -> std::result::Result<bool, SinkError> {
        (**self).recv(buf)
    }
    fn flush(&mut self) -> std::result::Result<(), SinkError> {
        (**self).flush()
    }
}

type Queue = Arc<Mutex<VecDeque<Vec<u8>>>>;

/// One end of a pair of ports joined by a virtual cable; see [`memory_ports`].
#[derive(Clone, Debug)]
pub struct MemoryPort {
    rx: Queue,
    tx: Queue,
}

/// Two ports joined back to back: what one sends, the other receives.
pub fn memory_ports() -> (MemoryPort, MemoryPort) {
    let a: Queue = Default::default();
    let b: Queue = Default::default();
    (
        MemoryPort {
            rx: a.clone(),
            tx: b.clone(),
        },
        MemoryPort { rx: b, tx: a },
    )
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// What a memory port sends as a [`PacketSink`], the other end receives.
impl PacketSink for MemoryPort {
    fn send(&mut self, data: &[u8]) -> std::result::Result<(), SinkError> {
        PacketPort::send(self, data)
    }
}

impl PacketPort for MemoryPort {
    fn send(&mut self, frame: &[u8]) -> std::result::Result<(), SinkError> {
        lock(&self.tx).push_back(frame.to_vec());
        Ok(())
    }

    fn recv(&mut self, buf: &mut Vec<u8>) -> std::result::Result<bool, SinkError> {
        match lock(&self.rx).pop_front() {
            Some(f) => {
                *buf = f;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

/// When a TCP run ends early.
#[derive(Clone, Debug, Default)]
pub struct TcpRunConfig {
    /// Stop after this long.
    pub duration: Option<Duration>,
    /// Set to stop the run from another thread (Ctrl-C).
    pub stop: Option<Arc<AtomicBool>>,
}

/// Frames read from one port before the others get a turn.
const RX_BURST: usize = 256;
/// Sleep when nothing happened, so an idle run does not spin a core.
const IDLE_SLEEP: Duration = Duration::from_micros(200);

/// Runs `engine` on `ports` until the client is done, the run is stopped, or
/// its duration passes. `progress` gets the counters every `interval`.
///
/// Port numbers in the engine's endpoints index `ports`.
pub fn run_tcp<F>(
    engine: &mut TcpEngine,
    ports: &mut [Box<dyn PacketPort>],
    config: &TcpRunConfig,
    interval: Duration,
    mut progress: F,
) -> Result<TcpStats>
where
    F: FnMut(&TcpStats),
{
    let start = Instant::now();
    let mut next_progress = interval;
    let mut buf = Vec::with_capacity(2048);
    loop {
        let now = start.elapsed();
        let mut busy = false;
        for (p, port) in ports.iter_mut().enumerate() {
            for _ in 0..RX_BURST {
                match port.recv(&mut buf) {
                    Ok(true) => {
                        engine.handle_frame(p, &buf, now);
                        busy = true;
                    }
                    Ok(false) => break,
                    Err(e) => return Err(Error::Tcp(format!("receiving on port {p}: {e}"))),
                }
            }
        }
        engine.poll(now);
        if let Some(e) = engine.error() {
            return Err(Error::Tcp(e.to_string()));
        }
        let out = engine.take_output();
        busy |= !out.is_empty();
        for (index, (p, frame)) in out.iter().enumerate() {
            let port = ports
                .get_mut(*p)
                .ok_or_else(|| Error::Tcp(format!("no port {p}")))?;
            port.send(frame).map_err(|source| Error::Sink {
                index: index as u64,
                source,
            })?;
        }
        for port in ports.iter_mut() {
            port.flush()
                .map_err(|source| Error::Sink { index: 0, source })?;
        }

        let stopped = config
            .stop
            .as_ref()
            .is_some_and(|s| s.load(Ordering::Relaxed))
            || config.duration.is_some_and(|d| now >= d);
        if stopped || engine.is_done() {
            engine.set_elapsed(start.elapsed(), stopped && !engine.is_done());
            let stats = engine.stats().clone();
            progress(&stats);
            return Ok(stats);
        }
        if now >= next_progress {
            next_progress = now + interval;
            engine.set_elapsed(now, false);
            progress(engine.stats());
        }
        if !busy {
            std::thread::sleep(IDLE_SLEEP);
        }
    }
}

/// A TCP run on its own thread, which can be watched and stopped.
///
/// ```
/// use ferotrx_core::*;
/// use std::sync::Arc;
///
/// // A client and a server joined by a virtual cable, on one subnet.
/// let (a, b) = memory_ports();
/// let program = TcpProgram::new(80, vec![
///     TcpMessage::new(TcpRole::Client, "ping"),
///     TcpMessage::new(TcpRole::Server, "pong"),
/// ]);
/// let server_ep = TcpEndpoint::new(1, "02:00:00:00:00:02".parse().unwrap(), "10.0.0.2".parse().unwrap());
/// let mut client = TcpClientConfig::new(
///     TcpEndpoint::new(0, "02:00:00:00:00:01".parse().unwrap(), "10.0.0.1".parse().unwrap()),
///     "10.0.0.2:80".parse().unwrap(),
/// );
/// client.connections = 5;
/// client.cps = 1000.0;
/// let engine = TcpEngine::new(TcpConfig {
///     program: Arc::new(program),
///     client: Some(client),
///     server: Some(TcpServerConfig { endpoint: server_ep, port: 80 }),
///     options: TcpOptions::default(),
/// }).unwrap();
/// let job = TcpJob::spawn(engine, vec![Box::new(a), Box::new(b)], TcpRunConfig::default()).unwrap();
/// let stats = job.join().unwrap();
/// assert_eq!(stats.client.completed, 5);
/// assert_eq!(stats.server.completed, 5);
/// assert_eq!(stats.client.mismatched, 0);
/// ```
pub struct TcpJob {
    stop: Arc<AtomicBool>,
    shared: Arc<JobShared>,
    thread: Option<JoinHandle<Result<TcpStats>>>,
}

struct JobShared {
    live: Mutex<Live>,
    changed: Condvar,
}

struct Live {
    stats: TcpStats,
    error: Option<String>,
    running: bool,
}

impl TcpJob {
    /// Starts running `engine` on `ports` on a new thread.
    pub fn spawn(
        mut engine: TcpEngine,
        mut ports: Vec<Box<dyn PacketPort>>,
        mut config: TcpRunConfig,
    ) -> Result<TcpJob> {
        let stop = config
            .stop
            .get_or_insert_with(|| Arc::new(AtomicBool::new(false)))
            .clone();
        let shared = Arc::new(JobShared {
            live: Mutex::new(Live {
                stats: TcpStats::default(),
                error: None,
                running: true,
            }),
            changed: Condvar::new(),
        });
        let thread = {
            let shared = shared.clone();
            std::thread::Builder::new()
                .name("ferotrx-tcp".into())
                .spawn(move || {
                    let result = run_tcp(
                        &mut engine,
                        &mut ports,
                        &config,
                        crate::JOB_STATS_INTERVAL,
                        |s| lock(&shared.live).stats = s.clone(),
                    );
                    let mut live = lock(&shared.live);
                    live.running = false;
                    match &result {
                        Ok(s) => live.stats = s.clone(),
                        Err(e) => {
                            live.stats = engine.stats().clone();
                            live.error = Some(e.to_string());
                        }
                    }
                    drop(live);
                    shared.changed.notify_all();
                    result
                })?
        };
        Ok(TcpJob {
            stop,
            shared,
            thread: Some(thread),
        })
    }

    /// The latest counters, at most [`JOB_STATS_INTERVAL`](crate::JOB_STATS_INTERVAL) old.
    pub fn stats(&self) -> TcpStats {
        lock(&self.shared.live).stats.clone()
    }

    pub fn is_running(&self) -> bool {
        lock(&self.shared.live).running
    }

    /// The error the run ended with, if it failed.
    pub fn error(&self) -> Option<String> {
        lock(&self.shared.live).error.clone()
    }

    /// Asks the run to stop.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Waits until the run ends or `timeout` passes (`None` waits for ever).
    /// Returns true if it has ended.
    pub fn wait(&self, timeout: Option<Duration>) -> bool {
        let deadline = timeout.and_then(|t| Instant::now().checked_add(t));
        let mut live = lock(&self.shared.live);
        while live.running {
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

    /// Waits for the run to end and returns its counters or its error.
    pub fn join(mut self) -> Result<TcpStats> {
        let thread = self.thread.take().expect("joined once");
        match thread.join() {
            Ok(r) => r,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}

/// Dropping a job stops it.
impl Drop for TcpJob {
    fn drop(&mut self) {
        self.stop();
    }
}

impl std::fmt::Debug for TcpJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpJob")
            .field("running", &self.is_running())
            .finish_non_exhaustive()
    }
}
