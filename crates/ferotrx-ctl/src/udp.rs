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
    let workers = profile.output.workers();
    if config.pinning.is_none() {
        config.pinning = crate::controller::pinning(profile.output.cpus.as_ref());
    }
    let plan = profile.endpoint_hosts(&engine_config)?;
    if workers > 1 && plan.is_some() {
        return Err(ferotrx_core::Error::Udp(
            "hosts that get their addresses by DHCP, SLAAC or DHCPv6, announce them or join \
             groups cannot be split over several workers yet; use workers = 1"
                .into(),
        )
        .into());
    }
    // Each worker gets its share of the client and the same servers.
    let split = if workers > 1 {
        let (configs, router) = engine_config.split(workers)?;
        let engines = configs
            .into_iter()
            .map(UdpEngine::new)
            .collect::<ferotrx_core::Result<Vec<_>>>()?;
        Some((engines, router))
    } else {
        None
    };
    let (engine, hosted) = match plan {
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
    let mut gtpu = profile.gtpu_ends(&interfaces, iface)?;
    let mut ports = Vec::with_capacity(interfaces.len());
    let mut port_details = Vec::new();
    for (i, name) in interfaces.iter().enumerate() {
        let settings = PortSettings {
            send: profile.output.clone(),
            // A tunnel's frames come to its outer MAC.
            macs: engine
                .port_macs(i)
                .into_iter()
                .chain(gtpu[i].iter().map(|e| e.spec.mac()))
                .collect(),
        };
        // The impairments act on the wire, so on the tunnel's outer frames.
        let port = profile.impair.wrap(open(name, &settings)?, i);
        let port = ferotrx_core::gtpu_port(port, std::mem::take(&mut gtpu[i]));
        port_details.extend(port.describe());
        ports.push(port);
    }
    if config.duration.is_none() {
        config.duration = profile.duration;
    }
    let job = match (hosted, split) {
        (Some(h), _) => UdpJob::spawn(h, ports, config)?,
        (None, Some((engines, router))) => {
            let lanes = ferotrx_core::split_ports(ports, workers);
            port_details.clear();
            for lane in lanes.iter().flatten() {
                if let Some(d) = lane.describe() {
                    if !port_details.contains(&d) {
                        port_details.push(d);
                    }
                }
            }
            UdpJob::spawn_workers(engines, lanes, router, config)?
        }
        (None, None) => UdpJob::spawn(engine, ports, config)?,
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
            workers: self.job.workers(),
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
            impair: None,
            started_at: self.job.started_at().map(ferotrx_core::unix_seconds),
            drops: Default::default(),
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
