//! Runs of emulated hosts on the control server: the `host.*` methods, as
//! `ferotrx host` runs them on the command line.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ferotrx_core::{HostEngine, HostProfile, HostStats, PortJob, TcpRunConfig};
use ferotrx_io::PortSettings;

use crate::controller::StartError;
use crate::protocol::{HostInfo, HostRunInfo, PortImpairCounters, RunState};
use crate::tcp::PortOpener;

/// Opens a host profile's interfaces with `open` and starts its hosts.
pub(crate) fn start_hosts_with(
    profile: &HostProfile,
    iface: Option<&str>,
    until_ready: bool,
    config: TcpRunConfig,
    open: &PortOpener,
) -> Result<(PortJob<HostStats>, Vec<String>), StartError> {
    if profile.output.workers() > 1 {
        return Err(ferotrx_core::Error::Profile(
            "host runs use one worker: leave out workers".into(),
        )
        .into());
    }
    let interfaces = profile.interfaces(iface)?;
    let configs = profile.configs(&interfaces, iface)?;
    let mut engine = HostEngine::new(configs, profile.options.clone())?;
    engine.set_until_settled(until_ready);
    let mut ports = Vec::with_capacity(interfaces.len());
    for (i, name) in interfaces.iter().enumerate() {
        let settings = PortSettings {
            send: profile.output.clone(),
            macs: engine.port_macs(i),
        };
        ports.push(profile.impair.wrap(open(name, &settings)?, i));
    }
    let job = PortJob::spawn(engine, ports, config)?;
    Ok((job, interfaces))
}

pub(crate) struct HostRun {
    pub id: u64,
    pub interfaces: Vec<String>,
    pub job: PortJob<HostStats>,
    pub stopped_by_request: AtomicBool,
}

impl HostRun {
    pub fn info(&self) -> HostRunInfo {
        // Running first: once it is false, the final counters are stored.
        let running = self.job.is_running();
        let stats = self.job.stats();
        let state = if running {
            RunState::Running
        } else if self.job.error().is_some() {
            RunState::Failed
        } else if stats.stopped && self.stopped_by_request.load(Ordering::Relaxed) {
            RunState::Stopped
        } else {
            RunState::Finished
        };
        HostRunInfo {
            id: self.id,
            interfaces: self.interfaces.clone(),
            state,
            error: self.job.error(),
            elapsed_s: stats.elapsed.as_secs_f64(),
            started_at: self.job.started_at().map(ferotrx_core::unix_seconds),
            ready: stats.ready(),
            failed: stats.failed(),
            tx_packets: stats.tx_packets,
            rx_packets: stats.rx_packets,
            hosts: stats.hosts.iter().map(HostInfo::from).collect(),
            impair: PortImpairCounters::of(&stats.impair),
        }
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
