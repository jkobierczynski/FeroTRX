//! Running scenario checks on real interfaces: [`LabRunner`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ferotrx_core::scenario::{
    tcp_metrics, tcp_summary, traffic_metrics, traffic_summary, udp_metrics, udp_summary, Check,
    CheckRun, CheckRunner, Workload,
};
use ferotrx_core::{
    Job, PacketPort, PacketReceiver, PacketSink, Profile, RunConfig, RxSettings, SendSettings,
    SinkError, TcpProfile, TcpRunConfig, UdpProfile, LINKTYPE_ETHERNET,
};

use crate::controller::ReceiverOpener;
use crate::tcp::{start_tcp_with, PortOpener};
use crate::udp::start_udp_with;

/// Opens an interface to send stateless traffic on: its name, the profile's
/// `[output]` settings and the link type.
pub type SinkOpener =
    dyn Fn(&str, &SendSettings, u32) -> Result<Box<dyn PacketSink + Send>, SinkError> + Send + Sync;

/// What [`LabRunner::with_progress`] calls: the check, and a line on its counters.
type ProgressFn = dyn FnMut(&Check, &str) + Send;

/// Runs the checks of a scenario the way `ferotrx tcp`, `ferotrx udp` and
/// `ferotrx run --rx` would: TCP and UDP checks through [`start_tcp_with`]
/// and [`start_udp_with`], traffic checks as a [`Job`] with a receiver.
///
/// Interfaces are opened with libpcap/Npcap (or the profile's `[output]`
/// backend) unless other openers are set, e.g. in-memory ports for tests.
pub struct LabRunner {
    open_port: Box<PortOpener>,
    open_receiver: Box<ReceiverOpener>,
    open_sink: Box<SinkOpener>,
    progress: Option<Box<ProgressFn>>,
}

impl Default for LabRunner {
    fn default() -> Self {
        Self::new()
    }
}

fn open_interface(
    name: &str,
    send: &SendSettings,
    linktype: u32,
) -> Result<Box<dyn PacketSink + Send>, SinkError> {
    ferotrx_io::Output::Interface {
        name: name.to_string(),
        send: SendSettings::default(),
    }
    .with_defaults(send)
    .open(linktype)
}

/// How often a running check reports its progress.
const PROGRESS_EVERY: Duration = Duration::from_secs(1);
/// How often the scenario's stop flag is looked at while a check runs.
const POLL: Duration = Duration::from_millis(100);

impl LabRunner {
    pub fn new() -> Self {
        Self {
            open_port: Box::new(ferotrx_io::open_port),
            open_receiver: Box::new(ferotrx_io::open_receiver),
            open_sink: Box::new(open_interface),
            progress: None,
        }
    }

    /// Opens the ports of TCP and UDP checks with `open`.
    pub fn with_port_opener(
        mut self,
        open: impl Fn(&str) -> Result<Box<dyn PacketPort>, SinkError> + Send + Sync + 'static,
    ) -> Self {
        self.open_port = Box::new(open);
        self
    }

    /// Opens the receiving interface of traffic checks with `open`.
    pub fn with_receiver_opener(
        mut self,
        open: impl Fn(&str) -> Result<Box<dyn PacketReceiver>, SinkError> + Send + Sync + 'static,
    ) -> Self {
        self.open_receiver = Box::new(open);
        self
    }

    /// Opens the sending interface of traffic checks with `open`.
    pub fn with_sink_opener(
        mut self,
        open: impl Fn(&str, &SendSettings, u32) -> Result<Box<dyn PacketSink + Send>, SinkError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.open_sink = Box::new(open);
        self
    }

    /// Calls `f` about once a second while a check runs, with a line on its
    /// live counters.
    pub fn with_progress(mut self, f: impl FnMut(&Check, &str) + Send + 'static) -> Self {
        self.progress = Some(Box::new(f));
        self
    }

    /// Waits for a run to end, passing on a scenario stop and reporting progress.
    fn watch(
        &mut self,
        check: &Check,
        stop: &AtomicBool,
        wait: impl Fn(Duration) -> bool,
        halt: impl Fn(),
        line: impl Fn() -> String,
    ) {
        let mut since = Duration::ZERO;
        while !wait(POLL) {
            if stop.load(Ordering::Relaxed) {
                halt();
            }
            since += POLL;
            if since >= PROGRESS_EVERY {
                since = Duration::ZERO;
                if let Some(p) = self.progress.as_mut() {
                    p(check, &line());
                }
            }
        }
    }

    fn tcp(
        &mut self,
        check: &Check,
        p: &TcpProfile,
        stop: &AtomicBool,
    ) -> Result<CheckRun, String> {
        // Each run has its own flag: a job sets it when it ends.
        let config = TcpRunConfig {
            duration: check.duration.or(p.duration),
            stop: Some(Arc::new(AtomicBool::new(false))),
        };
        let started = start_tcp_with(p, check.iface.as_deref(), config, &*self.open_port)
            .map_err(|e| e.to_string())?;
        let job = started.job;
        self.watch(
            check,
            stop,
            |t| job.wait(Some(t)),
            || job.stop(),
            || tcp_summary(&job.stats()),
        );
        let stats = job.join().map_err(|e| e.to_string())?;
        Ok(CheckRun {
            metrics: tcp_metrics(&stats),
            summary: tcp_summary(&stats),
        })
    }

    fn udp(
        &mut self,
        check: &Check,
        p: &UdpProfile,
        stop: &AtomicBool,
    ) -> Result<CheckRun, String> {
        let config = TcpRunConfig {
            duration: check.duration.or(p.duration),
            stop: Some(Arc::new(AtomicBool::new(false))),
        };
        let started = start_udp_with(p, check.iface.as_deref(), config, &*self.open_port)
            .map_err(|e| e.to_string())?;
        let job = started.job;
        self.watch(
            check,
            stop,
            |t| job.wait(Some(t)),
            || job.stop(),
            || udp_summary(&job.stats()),
        );
        let stats = job.join().map_err(|e| e.to_string())?;
        Ok(CheckRun {
            metrics: udp_metrics(&stats),
            summary: udp_summary(&stats),
        })
    }

    fn traffic(
        &mut self,
        check: &Check,
        p: &Profile,
        stop: &AtomicBool,
    ) -> Result<CheckRun, String> {
        let (Some(iface), Some(rx)) = (&check.iface, &check.rx) else {
            return Err("a traffic check needs `iface` and `rx`".into());
        };
        if check.duration.is_none() {
            if let Some(s) = p.streams.iter().find(|s| s.loops == 0 && s.limit.is_none()) {
                return Err(format!(
                    "stream {} loops for ever: give the check a `duration`",
                    s.name
                ));
            }
        }
        let mut profile = p.clone();
        if !profile.has_latency() {
            profile.enable_latency();
        }
        let streams = profile.load().map_err(|e| e.to_string())?;
        let linktype = streams
            .first()
            .map_or(LINKTYPE_ETHERNET, ferotrx_core::Stream::linktype);
        // The receiver first, so it sees the first packet.
        let receiver =
            (self.open_receiver)(rx).map_err(|e| format!("cannot receive on {rx}: {e}"))?;
        let sink = (self.open_sink)(iface, &profile.output, linktype)
            .map_err(|e| format!("cannot send on {iface}: {e}"))?;
        let job = Job::spawn_with_rx(
            streams,
            sink,
            RunConfig {
                limit: None,
                duration: check.duration,
                ignore_send_errors: false,
                stop: Some(Arc::new(AtomicBool::new(false))),
            },
            Some(RxSettings {
                receiver,
                wait: check.rx_wait,
            }),
        )
        .map_err(|e| e.to_string())?;
        self.watch(
            check,
            stop,
            |t| job.wait(Some(t)),
            || job.stop(),
            || {
                let s = job.stats();
                let rx: u64 = job.flow_reports().iter().map(|f| f.rx).sum();
                format!("{} packets sent, {rx} received", s.total.packets)
            },
        );
        let rx_stats = job.rx_stats();
        let flows = job.flow_reports();
        let stats = job.join().map_err(|e| e.to_string())?;
        let metrics = traffic_metrics(&stats, rx_stats.as_ref(), &flows);
        let summary = traffic_summary(&metrics);
        Ok(CheckRun { metrics, summary })
    }
}

impl CheckRunner for LabRunner {
    fn run(&mut self, check: &Check, stop: &Arc<AtomicBool>) -> Result<CheckRun, String> {
        match &check.workload {
            Workload::Tcp(p) => self.tcp(check, p, stop),
            Workload::Udp(p) => self.udp(check, p, stop),
            Workload::Traffic(p) => self.traffic(check, p, stop),
        }
    }
}
