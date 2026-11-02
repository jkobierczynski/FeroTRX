//! Stateful TCP runs: [`start_tcp`] and the `tcp.*` methods.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ferotrx_core::{PacketPort, SinkError, TcpEngine, TcpJob, TcpProfile, TcpRunConfig};

use crate::controller::StartError;
use crate::protocol::{RunState, TcpRunInfo};

/// Opens an interface by name as a port that sends and receives.
pub type PortOpener = dyn Fn(&str) -> Result<Box<dyn PacketPort>, SinkError> + Send + Sync;

/// A TCP run started by [`start_tcp`].
pub struct TcpStarted {
    pub job: TcpJob,
    /// The session played.
    pub program: String,
    /// The interfaces, in port order.
    pub interfaces: Vec<String>,
}

/// Loads a TCP profile's program, opens its interfaces and starts a [`TcpJob`].
///
/// `ferotrx tcp` calls it, and so does `tcp.start` on the control server.
/// `iface` is the interface of hosts whose table names none.
pub fn start_tcp(
    profile: &TcpProfile,
    iface: Option<&str>,
    config: TcpRunConfig,
) -> Result<TcpStarted, StartError> {
    start_tcp_with(profile, iface, config, &ferotrx_io::open_port)
}

/// Like [`start_tcp`], opening ports with `open` (for tests and embedding).
pub fn start_tcp_with(
    profile: &TcpProfile,
    iface: Option<&str>,
    mut config: TcpRunConfig,
    open: &PortOpener,
) -> Result<TcpStarted, StartError> {
    let program = Arc::new(profile.program()?);
    let interfaces = profile.interfaces(iface)?;
    let engine = TcpEngine::new(profile.config(program.clone(), &interfaces, iface)?)?;
    let mut ports = Vec::with_capacity(interfaces.len());
    for name in &interfaces {
        ports.push(open(name)?);
    }
    if config.duration.is_none() {
        config.duration = profile.duration;
    }
    Ok(TcpStarted {
        job: TcpJob::spawn(engine, ports, config)?,
        program: program.to_string(),
        interfaces,
    })
}

pub(crate) struct TcpRun {
    pub id: u64,
    pub program: String,
    pub interfaces: Vec<String>,
    pub job: TcpJob,
    pub stopped_by_request: AtomicBool,
}

impl TcpRun {
    pub fn info(&self) -> TcpRunInfo {
        let stats = self.job.stats();
        let state = if self.job.is_running() {
            RunState::Running
        } else if self.job.error().is_some() {
            RunState::Failed
        } else if stats.stopped && self.stopped_by_request.load(Ordering::Relaxed) {
            RunState::Stopped
        } else {
            RunState::Finished
        };
        let mut info = TcpRunInfo {
            id: self.id,
            program: self.program.clone(),
            interfaces: self.interfaces.clone(),
            state,
            error: self.job.error(),
            client: Default::default(),
            server: Default::default(),
            tx_packets: 0,
            tx_bytes: 0,
            rx_packets: 0,
            rx_bytes: 0,
            elapsed_s: 0.0,
            cps: 0.0,
        };
        info.fill(&stats);
        info
    }

    pub fn stop(&self, wait: Option<Duration>) {
        if self.job.is_running() {
            self.stopped_by_request.store(true, Ordering::Relaxed);
        }
        self.job.stop();
        if wait.is_some() {
            self.job.wait(wait);
        }
    }
}
