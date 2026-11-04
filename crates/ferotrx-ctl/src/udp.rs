//! Stateful UDP runs: [`start_udp`] and the `udp.*` methods.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ferotrx_core::{wall_clock, TcpRunConfig, UdpEngine, UdpJob, UdpProfile};

use crate::controller::StartError;
use crate::protocol::{RunState, UdpRunInfo};
use crate::tcp::PortOpener;
use ferotrx_io::PortSettings;

/// A UDP run started by [`start_udp`].
pub struct UdpStarted {
    pub job: UdpJob,
    /// What the transactions carry; with several templates, each one's name,
    /// weight or rate, and content.
    pub program: String,
    /// The interfaces, in port order.
    pub interfaces: Vec<String>,
    /// How each port sends and receives, where it says (AF_XDP, DPDK).
    pub port_details: Vec<String>,
}

/// Loads a UDP profile, opens its interfaces and starts a [`UdpJob`].
///
/// `ferotrx udp` calls it, and so does `udp.start` on the control server.
/// `iface` is the interface of hosts whose table names none. NTP timestamps
/// follow the system clock.
pub fn start_udp(
    profile: &UdpProfile,
    iface: Option<&str>,
    config: TcpRunConfig,
) -> Result<UdpStarted, StartError> {
    start_udp_with(profile, iface, config, &ferotrx_io::open_port_with)
}

/// Like [`start_udp`], opening ports with `open` (for tests and embedding).
pub fn start_udp_with(
    profile: &UdpProfile,
    iface: Option<&str>,
    mut config: TcpRunConfig,
    open: &PortOpener,
) -> Result<UdpStarted, StartError> {
    let apps = profile.apps()?;
    let interfaces = profile.interfaces(iface)?;
    let mut engine_config = profile.config(&apps, &interfaces, iface)?;
    engine_config.options.clock = wall_clock();
    // With DHCP, SLAAC or DHCPv6 the hosts get their addresses first, and
    // the engine is built with them; checked now with example addresses.
    let (engine, hosted) = match profile.endpoint_hosts(&engine_config)? {
        Some(plan) => {
            let (checked, hosted) =
                plan.hosted(engine_config, profile.host_options.clone(), UdpEngine::new)?;
            (checked, Some(hosted))
        }
        None => (UdpEngine::new(engine_config)?, None),
    };
    let program = match engine.templates() {
        [one] => one.app.to_string(),
        many => many
            .iter()
            .map(|t| match t.rate {
                Some(r) => format!("{} ({r}/s): {}", t.name, t.app),
                None => format!("{} (weight {}): {}", t.name, t.weight, t.app),
            })
            .collect::<Vec<_>>()
            .join("; "),
    };
    let mut ports = Vec::with_capacity(interfaces.len());
    let mut port_details = Vec::new();
    for (i, name) in interfaces.iter().enumerate() {
        let settings = PortSettings {
            send: profile.output.clone(),
            macs: engine.port_macs(i),
        };
        let port = open(name, &settings)?;
        port_details.extend(port.describe());
        ports.push(port);
    }
    if config.duration.is_none() {
        config.duration = profile.duration;
    }
    let job = match hosted {
        Some(h) => UdpJob::spawn(h, ports, config)?,
        None => UdpJob::spawn(engine, ports, config)?,
    };
    Ok(UdpStarted {
        job,
        program,
        interfaces,
        port_details,
    })
}

pub(crate) struct UdpRun {
    pub id: u64,
    pub program: String,
    pub interfaces: Vec<String>,
    pub ports: Vec<String>,
    pub job: UdpJob,
    pub stopped_by_request: AtomicBool,
}

impl UdpRun {
    pub fn info(&self) -> UdpRunInfo {
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
        let mut info = UdpRunInfo {
            id: self.id,
            program: self.program.clone(),
            interfaces: self.interfaces.clone(),
            ports: self.ports.clone(),
            state,
            error: self.job.error(),
            client: Default::default(),
            server: Default::default(),
            templates: Vec::new(),
            tx_packets: 0,
            tx_bytes: 0,
            rx_packets: 0,
            rx_bytes: 0,
            elapsed_s: 0.0,
            tps: 0.0,
            hosts: Vec::new(),
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
