//! Running a [`TcpEngine`] (or a UDP engine) on real ports, on this thread
//! or on its own.

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

    /// One line on how the port sends and receives, for example
    /// `af_xdp on eth0: 4 queue(s), XDP driver mode, zero-copy`.
    fn describe(&self) -> Option<String> {
        None
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
    fn describe(&self) -> Option<String> {
        (**self).describe()
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

/// An engine that plays stateful traffic on [`PacketPort`]s: the TCP engine
/// and the UDP engine. It does no I/O and reads no clock; [`run_engine`] and
/// [`PortJob`] feed it frames and the time.
pub trait PortEngine: Send {
    /// The engine's counters.
    type Stats: Clone + Default + Send + 'static;
    /// Handles one frame received on `port`.
    fn handle_frame(&mut self, port: usize, frame: &[u8], now: Duration);
    /// Runs timers and starts what is due.
    fn poll(&mut self, now: Duration);
    /// Frames to send, as (port, frame). Empties the queue.
    fn take_output(&mut self) -> Vec<(usize, Vec<u8>)>;
    /// The error that stopped the engine.
    fn error(&self) -> Option<&str>;
    /// True when the engine has nothing more to do.
    fn is_done(&self) -> bool;
    /// Sets the elapsed time and stop flag in the counters.
    fn set_elapsed(&mut self, elapsed: Duration, stopped: bool);
    fn stats(&self) -> &Self::Stats;
    /// Wraps an error message in the engine's kind of [`Error`].
    fn wrap_error(message: String) -> Error;
}

impl PortEngine for TcpEngine {
    type Stats = TcpStats;
    fn handle_frame(&mut self, port: usize, frame: &[u8], now: Duration) {
        TcpEngine::handle_frame(self, port, frame, now)
    }
    fn poll(&mut self, now: Duration) {
        TcpEngine::poll(self, now)
    }
    fn take_output(&mut self) -> Vec<(usize, Vec<u8>)> {
        TcpEngine::take_output(self)
    }
    fn error(&self) -> Option<&str> {
        TcpEngine::error(self)
    }
    fn is_done(&self) -> bool {
        TcpEngine::is_done(self)
    }
    fn set_elapsed(&mut self, elapsed: Duration, stopped: bool) {
        TcpEngine::set_elapsed(self, elapsed, stopped)
    }
    fn stats(&self) -> &TcpStats {
        TcpEngine::stats(self)
    }
    fn wrap_error(message: String) -> Error {
        Error::Tcp(message)
    }
}

/// When a TCP or UDP run ends early.
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
    progress: F,
) -> Result<TcpStats>
where
    F: FnMut(&TcpStats),
{
    run_engine(engine, ports, config, interval, progress)
}

/// Runs any [`PortEngine`] on `ports` until it is done, the run is stopped,
/// or its duration passes; see [`run_tcp`].
pub fn run_engine<E, F>(
    engine: &mut E,
    ports: &mut [Box<dyn PacketPort>],
    config: &TcpRunConfig,
    interval: Duration,
    mut progress: F,
) -> Result<E::Stats>
where
    E: PortEngine,
    F: FnMut(&E::Stats),
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
                    Err(e) => return Err(E::wrap_error(format!("receiving on port {p}: {e}"))),
                }
            }
        }
        engine.poll(now);
        if let Some(e) = engine.error() {
            return Err(E::wrap_error(e.to_string()));
        }
        let out = engine.take_output();
        busy |= !out.is_empty();
        for (index, (p, frame)) in out.iter().enumerate() {
            let port = ports
                .get_mut(*p)
                .ok_or_else(|| E::wrap_error(format!("no port {p}")))?;
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

/// A TCP run on its own thread; see [`PortJob`].
pub type TcpJob = PortJob<TcpStats>;

/// A run of a [`PortEngine`] (TCP or UDP) on its own thread, which can be
/// watched and stopped.
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
/// );
/// client.connections = 5;
/// client.cps = 1000.0;
/// let engine = TcpEngine::new(TcpConfig {
///     templates: vec![TcpTemplate::new(Arc::new(program), "10.0.0.2:80".parse().unwrap())],
///     client: Some(client),
///     server: Some(TcpServerConfig::new(server_ep)),
///     options: TcpOptions::default(),
/// }).unwrap();
/// let job = TcpJob::spawn(engine, vec![Box::new(a), Box::new(b)], TcpRunConfig::default()).unwrap();
/// let stats = job.join().unwrap();
/// assert_eq!(stats.client.completed, 5);
/// assert_eq!(stats.server.completed, 5);
/// assert_eq!(stats.client.mismatched, 0);
/// ```
pub struct PortJob<S> {
    stop: Arc<AtomicBool>,
    shared: Arc<JobShared<S>>,
    thread: Option<JoinHandle<Result<S>>>,
}

struct JobShared<S> {
    live: Mutex<Live<S>>,
    changed: Condvar,
}

struct Live<S> {
    stats: S,
    error: Option<String>,
    running: bool,
}

impl<S: Clone + Default + Send + 'static> PortJob<S> {
    /// Starts running `engine` on `ports` on a new thread.
    pub fn spawn<E>(
        mut engine: E,
        mut ports: Vec<Box<dyn PacketPort>>,
        mut config: TcpRunConfig,
    ) -> Result<PortJob<S>>
    where
        E: PortEngine<Stats = S> + 'static,
    {
        let stop = config
            .stop
            .get_or_insert_with(|| Arc::new(AtomicBool::new(false)))
            .clone();
        let shared = Arc::new(JobShared {
            live: Mutex::new(Live {
                stats: S::default(),
                error: None,
                running: true,
            }),
            changed: Condvar::new(),
        });
        let thread = {
            let shared = shared.clone();
            std::thread::Builder::new()
                .name("ferotrx-engine".into())
                .spawn(move || {
                    let result = run_engine(
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
        Ok(PortJob {
            stop,
            shared,
            thread: Some(thread),
        })
    }

    /// The latest counters, at most [`JOB_STATS_INTERVAL`](crate::JOB_STATS_INTERVAL) old.
    pub fn stats(&self) -> S {
        lock(&self.shared.live).stats.clone()
    }
}

impl<S> PortJob<S> {
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
    pub fn join(mut self) -> Result<S> {
        let thread = self.thread.take().expect("joined once");
        match thread.join() {
            Ok(r) => r,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}

/// Dropping a job stops it.
impl<S> Drop for PortJob<S> {
    fn drop(&mut self) {
        self.stop();
    }
}

impl<S> std::fmt::Debug for PortJob<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortJob")
            .field("running", &lock(&self.shared.live).running)
            .finish_non_exhaustive()
    }
}
