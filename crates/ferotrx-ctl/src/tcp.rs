//! Stateful TCP runs: [`start_tcp`] and the `tcp.*` methods.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ferotrx_core::{
    PacketPort, SinkError, TcpEngine, TcpJob, TcpProfile, TcpProgram, TcpRunConfig,
};

use ferotrx_io::PortSettings;

use crate::controller::StartError;
use crate::protocol::{RunState, TcpRunInfo};

/// Opens an interface by name as a port that sends and receives, with the
/// backend and emulated hosts' MACs given ([`ferotrx_io::open_port_with`]).
pub type PortOpener =
    dyn Fn(&str, &PortSettings) -> Result<Box<dyn PacketPort>, SinkError> + Send + Sync;

/// A TCP run started by [`start_tcp`].
pub struct TcpStarted {
    pub job: TcpJob,
    /// The session played; with several templates, each one's name, weight
    /// and session.
    pub program: String,
    /// The interfaces, in port order.
    pub interfaces: Vec<String>,
    /// How each port sends and receives, where it says (AF_XDP, DPDK).
    pub port_details: Vec<String>,
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
    start_tcp_with(profile, iface, config, &ferotrx_io::open_port_with)
}

/// Like [`start_tcp`], opening ports with `open` (for tests and embedding).
pub fn start_tcp_with(
    profile: &TcpProfile,
    iface: Option<&str>,
    mut config: TcpRunConfig,
    open: &PortOpener,
) -> Result<TcpStarted, StartError> {
    let programs: Vec<Arc<TcpProgram>> = profile.programs()?.into_iter().map(Arc::new).collect();
    let interfaces = profile.interfaces(iface)?;
    let engine_config = profile.config(&programs, &interfaces, iface)?;
    // With DHCP, SLAAC or DHCPv6 the hosts get their addresses first, and
    // the engine is built with them; checked now with example addresses.
    let workers = profile.output.workers();
    if config.pinning.is_none() {
        config.pinning = crate::controller::pinning(profile.output.cpus.as_ref());
    }
    let plan = profile.endpoint_hosts(&engine_config)?;
    if workers > 1 && plan.is_some() {
        return Err(ferotrx_core::Error::Tcp(
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
            .map(TcpEngine::new)
            .collect::<ferotrx_core::Result<Vec<_>>>()?;
        Some((engines, router))
    } else {
        None
    };
    let (engine, hosted) = match plan {
        Some(plan) => {
            let (checked, hosted) =
                plan.hosted(engine_config, profile.host_options.clone(), TcpEngine::new)?;
            (checked, Some(hosted))
        }
        None => (TcpEngine::new(engine_config)?, None),
    };
    let program = match engine.templates() {
        [one] => one.describe(),
        many => many
            .iter()
            .map(|t| match t.cps {
                Some(cps) => format!("{} ({cps} cps): {}", t.name, t.describe()),
                None => format!("{} (weight {}): {}", t.name, t.weight, t.describe()),
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
        (Some(h), _) => TcpJob::spawn(h, ports, config)?,
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
            TcpJob::spawn_workers(engines, lanes, router, config)?
        }
        (None, None) => TcpJob::spawn(engine, ports, config)?,
    };
    Ok(TcpStarted {
        job,
        program,
        interfaces,
        port_details,
    })
}

pub(crate) struct TcpRun {
    pub id: u64,
    pub program: String,
    pub interfaces: Vec<String>,
    pub ports: Vec<String>,
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
            cps: 0.0,
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
