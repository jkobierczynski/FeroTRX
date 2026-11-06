use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use ferotrx_core::{
    parse_duration, FlowReport, Job, JobState, PacketReceiver, Profile, Rate, RunConfig, RxConfig,
    RxJob, RxSettings, SendSettings, SinkError, StreamSource, TcpProfile, TcpRunConfig, UdpProfile,
    UdpSource, LINKTYPE_ETHERNET,
};
use ferotrx_io::Output;

use crate::bench::{open_bench_sinks, BenchJob, BenchRun, BenchSinkOpener};
use crate::files::FilePolicy;
use crate::protocol::*;
use crate::scenario::{scenario_info, LabRunner, RunLists, ScenarioRun};
use crate::tcp::{start_tcp_with, PortOpener, TcpRun};
use crate::udp::{start_udp_with, UdpRun};
use crate::y1564::{Y1564Job, Y1564Run};
use ferotrx_core::scenario::{Scenario, Workload};

/// Error from [`start_run`].
pub type StartError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A run started by [`start_run_detailed`].
pub struct Started {
    pub job: Job,
    /// How the output sends, e.g. `af_xdp on enp0s3 queue 0, copy mode`.
    pub detail: String,
}

/// Loads a profile's streams, opens the output and starts a [`Job`].
///
/// This is the one way traffic profiles are started: `ferotrx run` calls it,
/// and so does `run.start` on the control server. `rate`, when given,
/// replaces the rate of every stream. Send settings the output leaves unset
/// come from the profile's `[output]` table.
pub fn start_run(
    profile: &Profile,
    output: &Output,
    rate: Option<Rate>,
    config: RunConfig,
) -> Result<Job, StartError> {
    Ok(start_run_detailed(profile, output, rate, config)?.job)
}

/// Like [`start_run`], and says how the output sends.
pub fn start_run_detailed(
    profile: &Profile,
    output: &Output,
    rate: Option<Rate>,
    config: RunConfig,
) -> Result<Started, StartError> {
    start_run_with_rx(profile, output, rate, config, None)
}

/// Like [`start_run_detailed`], with a receiver that measures loss and
/// latency while the run goes (see [`Job::spawn_with_rx`]). With a receiver,
/// a profile that marks no stream with `latency` has a signature put in
/// every stream's packets.
pub fn start_run_with_rx(
    profile: &Profile,
    output: &Output,
    rate: Option<Rate>,
    config: RunConfig,
    rx: Option<RxSettings>,
) -> Result<Started, StartError> {
    let profile = if rx.is_some() && !profile.has_latency() {
        let mut p = profile.clone();
        p.enable_latency();
        std::borrow::Cow::Owned(p)
    } else {
        std::borrow::Cow::Borrowed(profile)
    };
    let output = output.clone().with_defaults(&profile.output);
    // Interface outputs carry the profile's [output] settings now; files and
    // the null output take the worker count from the profile.
    let workers = match &output {
        Output::Interface { send, .. } => send.workers(),
        _ => profile.output.workers(),
    };
    if let Some(rate) = rate {
        rate.validate()?;
    }
    let mut sets = Vec::with_capacity(workers);
    for k in 0..workers {
        let mut streams = profile.load()?;
        for s in &mut streams {
            if let Some(rate) = rate {
                s.rate = rate;
            }
        }
        if workers > 1 {
            streams = streams.into_iter().map(|s| s.shard(k, workers)).collect();
        }
        sets.push(streams);
    }
    let linktype = sets[0]
        .first()
        .map_or(LINKTYPE_ETHERNET, ferotrx_core::Stream::linktype);
    let opened = output.open_workers(linktype, workers)?;
    let mut details: Vec<String> = Vec::new();
    let mut work = Vec::with_capacity(workers);
    for (streams, o) in sets.into_iter().zip(opened) {
        if !details.contains(&o.detail) {
            details.push(o.detail);
        }
        work.push((streams, o.sink));
    }
    Ok(Started {
        job: Job::spawn_workers(work, config, rx)?,
        detail: details.join("; "),
    })
}

/// Opens an interface by name to receive on, for loss and latency.
pub type ReceiverOpener = dyn Fn(&str) -> Result<Box<dyn PacketReceiver>, SinkError> + Send + Sync;

/// How long `run.stop` waits for a run to end before answering anyway.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// The state behind the control API: loaded profiles and runs.
///
/// It does not know about connections, so it can sit behind any transport;
/// [`Server`](crate::Server) puts it behind JSON-RPC over TCP. All methods
/// take `&self` and can be called from several threads at once.
pub struct Controller {
    profiles: Mutex<BTreeMap<String, Profile>>,
    runs: Arc<Mutex<BTreeMap<u64, Arc<Run>>>>,
    tcp_runs: Arc<Mutex<BTreeMap<u64, Arc<TcpRun>>>>,
    udp_runs: Arc<Mutex<BTreeMap<u64, Arc<UdpRun>>>>,
    rx_runs: Mutex<BTreeMap<u64, Arc<RxRun>>>,
    next_run: Arc<AtomicU64>,
    auth_required: bool,
    files: FilePolicy,
    scenario_runs: Mutex<BTreeMap<u64, Arc<ScenarioRun>>>,
    bench_runs: Mutex<BTreeMap<u64, Arc<BenchRun>>>,
    y1564_runs: Mutex<BTreeMap<u64, Arc<Y1564Run>>>,
    open_bench_sinks: Arc<BenchSinkOpener>,
    open_port: Arc<PortOpener>,
    open_receiver: Arc<ReceiverOpener>,
    /// Whether `lab.start` may build a lab, and the one running.
    lab_allowed: bool,
    lab: Mutex<Option<ferotrx_io::Lab>>,
}

struct RxRun {
    id: u64,
    iface: String,
    job: RxJob,
    stopped_by_request: std::sync::atomic::AtomicBool,
}

pub(crate) struct Run {
    pub id: u64,
    pub profile: String,
    /// How the output sends, as `start_run_detailed` described it.
    pub output: String,
    /// The interface the run receives on, if it measures loss and latency.
    pub rx_iface: Option<String>,
    pub job: Job,
    pub stopped_by_request: std::sync::atomic::AtomicBool,
}

impl Default for Controller {
    fn default() -> Self {
        Self::new()
    }
}

impl Controller {
    pub fn new() -> Self {
        Self {
            profiles: Mutex::default(),
            runs: Arc::default(),
            tcp_runs: Arc::default(),
            udp_runs: Arc::default(),
            rx_runs: Mutex::default(),
            next_run: Arc::new(AtomicU64::new(1)),
            auth_required: false,
            files: FilePolicy::unrestricted(),
            scenario_runs: Mutex::default(),
            bench_runs: Mutex::default(),
            y1564_runs: Mutex::default(),
            open_bench_sinks: Arc::new(open_bench_sinks),
            open_port: Arc::new(ferotrx_io::open_port_with),
            open_receiver: Arc::new(ferotrx_io::open_receiver),
            lab_allowed: false,
            lab: Mutex::default(),
        }
    }

    /// Lets clients with the operator role build a lab router on this
    /// machine (`lab.start`, see [`ferotrx_io::Lab`]). Off unless asked
    /// for: a lab changes the machine's network (a namespace and a link).
    pub fn with_lab(mut self, allowed: bool) -> Self {
        self.lab_allowed = allowed;
        self
    }

    /// Why `lab.start` is refused, or `None`.
    fn lab_unavailable(&self) -> Option<String> {
        if !self.lab_allowed {
            return Some("labs are off on this server: start it with ferotrx serve --lab".into());
        }
        ferotrx_io::lab_unavailable()
    }

    pub fn lab_info(&self) -> LabInfo {
        let lab = lock(&self.lab);
        let unavailable = self.lab_unavailable();
        match lab.as_ref() {
            Some(l) => lab_info(l, unavailable),
            None => LabInfo {
                unavailable,
                interface: ferotrx_io::LAB_INTERFACE.into(),
                namespace: ferotrx_io::LAB_NAMESPACE.into(),
                ..Default::default()
            },
        }
    }

    /// Builds the lab, replacing a running one.
    pub fn lab_start(&self, p: LabStartParams) -> Result<LabInfo, RpcError> {
        if let Some(why) = self.lab_unavailable() {
            return Err(RpcError::failed(why));
        }
        let config = lab_config(&p);
        let mut lab = lock(&self.lab);
        if let Some(old) = lab.take() {
            old.down();
        }
        let l = ferotrx_io::Lab::up(config).map_err(|e| RpcError::failed(format!("lab: {e}")))?;
        let info = lab_info(&l, None);
        *lab = Some(l);
        Ok(info)
    }

    /// Builds the lab a scenario names, unless one built the same way runs.
    fn scenario_lab(&self, spec: &ferotrx_core::scenario::LabSpec) -> Result<(), RpcError> {
        if !self.lab_allowed {
            return Err(RpcError::failed(
                "the scenario needs the lab router ([lab]), and labs are off on this server: \
                 start it with ferotrx serve --lab, or run with \"lab\": false on what is there",
            ));
        }
        let p = LabStartParams::from(spec);
        let same = lock(&self.lab)
            .as_ref()
            .is_some_and(|l| *l.config() == lab_config(&p));
        if !same {
            self.lab_start(p)?;
        }
        Ok(())
    }

    pub fn lab_stop(&self) -> LabInfo {
        if let Some(l) = lock(&self.lab).take() {
            l.down();
        }
        self.lab_info()
    }

    /// Opens the interfaces runs receive on with `open` instead of
    /// libpcap/Npcap, for example to receive from in-memory ports in tests.
    pub fn with_receiver_opener(
        mut self,
        open: impl Fn(&str) -> Result<Box<dyn PacketReceiver>, SinkError> + Send + Sync + 'static,
    ) -> Self {
        self.open_receiver = Arc::new(open);
        self
    }

    /// Opens the sending interface of benchmarks with `open` instead of
    /// libpcap/Npcap (or the backend asked for), e.g. in-memory ports in tests.
    pub fn with_bench_sink_opener(
        mut self,
        open: impl Fn(
                &str,
                &SendSettings,
                u32,
                usize,
            )
                -> Result<(Vec<Box<dyn ferotrx_core::PacketSink + Send>>, String), SinkError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.open_bench_sinks = Arc::new(open);
        self
    }

    /// Opens the interfaces of TCP runs with `open` instead of libpcap/Npcap,
    /// for example to run on in-memory ports in tests.
    pub fn with_port_opener(
        mut self,
        open: impl Fn(
                &str,
                &ferotrx_io::PortSettings,
            ) -> Result<Box<dyn ferotrx_core::PacketPort>, ferotrx_core::SinkError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.open_port = Arc::new(open);
        self
    }

    /// Restricts the files clients may name (see [`FilePolicy`]). Profiles
    /// added with [`add_profile`](Controller::add_profile) are not checked.
    pub fn with_file_policy(mut self, files: FilePolicy) -> Self {
        self.files = files;
        self
    }

    pub fn file_policy(&self) -> &FilePolicy {
        &self.files
    }

    pub(crate) fn set_auth_required(&mut self, yes: bool) {
        self.auth_required = yes;
    }

    /// Handles one method call. `params` is the JSON `params` member (or null).
    ///
    /// Connection-scoped methods (`auth`, `stats.subscribe`, `stats.unsubscribe`)
    /// are handled by the server, not here.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        match method {
            "server.info" => to_value(self.info()),
            "interfaces.list" => to_value(self.interfaces()?),
            "profile.load" => to_value(self.load_profile(parse(params)?)?),
            "profile.get" => {
                let p: ProfileName = parse(params)?;
                to_value(self.profile(&p.name)?)
            }
            "profile.list" => to_value(self.profiles()),
            "profile.unload" => {
                let p: ProfileName = parse(params)?;
                self.unload_profile(&p.name)?;
                Ok(Value::Bool(true))
            }
            "run.start" => to_value(self.start(parse(params)?)?),
            "run.stop" => {
                let p: StopParams = parse(params)?;
                to_value(self.stop(p.id, p.wait)?)
            }
            "run.stats" => {
                let p: RunId = parse(params)?;
                to_value(self.run(p.id)?)
            }
            "run.list" => to_value(self.runs()),
            "run.remove" => {
                let p: RunId = parse(params)?;
                to_value(self.remove(p.id)?)
            }
            "tcp.start" => to_value(self.tcp_start(parse(params)?)?),
            "tcp.stop" => {
                let p: StopParams = parse(params)?;
                to_value(self.tcp_stop(p.id, p.wait)?)
            }
            "tcp.stats" => {
                let p: RunId = parse(params)?;
                to_value(self.tcp_run(p.id)?.info())
            }
            "tcp.list" => to_value(self.tcp_runs()),
            "tcp.remove" => {
                let p: RunId = parse(params)?;
                let info = self.tcp_stop(p.id, true)?;
                lock(&self.tcp_runs).remove(&p.id);
                to_value(info)
            }
            "udp.start" => to_value(self.udp_start(parse(params)?)?),
            "udp.stop" => {
                let p: StopParams = parse(params)?;
                to_value(self.udp_stop(p.id, p.wait)?)
            }
            "udp.stats" => {
                let p: RunId = parse(params)?;
                to_value(self.udp_run(p.id)?.info())
            }
            "udp.list" => to_value(self.udp_runs()),
            "udp.remove" => {
                let p: RunId = parse(params)?;
                let info = self.udp_stop(p.id, true)?;
                lock(&self.udp_runs).remove(&p.id);
                to_value(info)
            }
            "rx.start" => to_value(self.rx_start(parse(params)?)?),
            "rx.stop" => {
                let p: StopParams = parse(params)?;
                to_value(self.rx_stop(p.id, p.wait)?)
            }
            "rx.stats" => {
                let p: RunId = parse(params)?;
                to_value(self.rx_run(p.id)?.info())
            }
            "rx.list" => to_value(self.rx_runs()),
            "rx.remove" => {
                let p: RunId = parse(params)?;
                let info = self.rx_stop(p.id, true)?;
                lock(&self.rx_runs).remove(&p.id);
                to_value(info)
            }
            "scenario.check" => to_value(self.scenario_check(parse(params)?)?),
            "scenario.start" => to_value(self.scenario_start(parse(params)?)?),
            "scenario.get" => {
                let p: RunId = parse(params)?;
                to_value(self.scenario_run(p.id)?.info())
            }
            "scenario.list" => to_value(self.scenario_runs()),
            "scenario.stop" => {
                let p: StopParams = parse(params)?;
                to_value(self.scenario_stop(p.id, p.wait)?)
            }
            "scenario.remove" => {
                let p: RunId = parse(params)?;
                to_value(self.scenario_remove(p.id)?)
            }
            "bench.start" => to_value(self.bench_start(parse(params)?)?),
            "bench.get" => {
                let p: RunId = parse(params)?;
                to_value(self.bench_run(p.id)?.info())
            }
            "bench.list" => to_value(self.bench_runs()),
            "bench.stop" => {
                let p: StopParams = parse(params)?;
                to_value(self.bench_stop(p.id, p.wait)?)
            }
            "bench.remove" => {
                let p: RunId = parse(params)?;
                to_value(self.bench_remove(p.id)?)
            }
            "y1564.start" => to_value(self.y1564_start(parse(params)?)?),
            "y1564.get" => {
                let p: RunId = parse(params)?;
                to_value(self.y1564_run(p.id)?.info())
            }
            "y1564.list" => to_value(self.y1564_runs()),
            "y1564.stop" => {
                let p: StopParams = parse(params)?;
                to_value(self.y1564_stop(p.id, p.wait)?)
            }
            "y1564.remove" => {
                let p: RunId = parse(params)?;
                to_value(self.y1564_remove(p.id)?)
            }
            "lab.get" => to_value(self.lab_info()),
            "lab.start" => to_value(self.lab_start(parse(params)?)?),
            "lab.stop" => to_value(self.lab_stop()),
            _ => Err(RpcError::new(
                RpcError::METHOD_NOT_FOUND,
                format!("unknown method '{method}'"),
            )),
        }
    }

    pub fn info(&self) -> ServerInfo {
        ServerInfo {
            name: "ferotrx".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            protocol: PROTOCOL_VERSION,
            interfaces: !ferotrx_io::backends().is_empty(),
            backends: ferotrx_io::backends()
                .into_iter()
                .map(|b| b.name().to_string())
                .collect(),
            auth_required: self.auth_required,
            tls: false,
            role: None,
            user: None,
            lab: self.lab_unavailable().is_none(),
        }
    }

    pub fn interfaces(&self) -> Result<Vec<InterfaceEntry>, RpcError> {
        #[cfg(feature = "pcap")]
        {
            Ok(ferotrx_io::list_interfaces()
                .map_err(RpcError::failed)?
                .into_iter()
                .map(|i| InterfaceEntry {
                    name: i.name,
                    description: i.description,
                })
                .collect())
        }
        #[cfg(not(feature = "pcap"))]
        {
            Err(RpcError::failed(
                "this server was built without interface support",
            ))
        }
    }

    /// Loads (or replaces) a profile from a file on the server or from TOML text.
    pub fn load_profile(&self, p: LoadProfileParams) -> Result<ProfileInfo, RpcError> {
        let (name, profile) = match (p.path, p.toml) {
            (Some(path), None) => {
                if p.base_dir.is_some() {
                    return Err(RpcError::invalid_params(
                        "base_dir goes with toml; a profile file uses its own folder",
                    ));
                }
                let name = match p.name {
                    Some(n) => n,
                    None => path
                        .file_stem()
                        .map(|s| s.to_string_lossy().into_owned())
                        .ok_or_else(|| RpcError::invalid_params("path has no file name"))?,
                };
                let file = self.files.readable(&path)?;
                let profile = Profile::from_path(&file).map_err(|e| {
                    RpcError::failed(format!("cannot load {}: {e}", path.display()))
                })?;
                (name, profile)
            }
            (None, Some(text)) => {
                let name = p.name.ok_or_else(|| {
                    RpcError::invalid_params("a profile given as toml needs a name")
                })?;
                self.files.upload(&text)?;
                let base = self.files.base_dir(p.base_dir.as_deref())?;
                let profile = Profile::from_toml(&text, &base).map_err(RpcError::failed)?;
                (name, profile)
            }
            _ => return Err(RpcError::invalid_params("give either path or toml")),
        };
        if name.trim().is_empty() {
            return Err(RpcError::invalid_params("profile name is empty"));
        }
        self.check_stream_files(&profile)?;
        let info = profile_info(&name, &profile);
        lock(&self.profiles).insert(name, profile);
        Ok(info)
    }

    /// Adds an already parsed profile, e.g. one named on the server's command line.
    pub fn add_profile(&self, name: impl Into<String>, profile: Profile) -> ProfileInfo {
        let name = name.into();
        let info = profile_info(&name, &profile);
        lock(&self.profiles).insert(name, profile);
        info
    }

    pub fn profile(&self, name: &str) -> Result<ProfileInfo, RpcError> {
        lock(&self.profiles)
            .get(name)
            .map(|p| profile_info(name, p))
            .ok_or_else(|| no_profile(name))
    }

    pub fn profiles(&self) -> Vec<ProfileInfo> {
        lock(&self.profiles)
            .iter()
            .map(|(n, p)| profile_info(n, p))
            .collect()
    }

    /// Forgets a profile. Runs already started from it carry on.
    pub fn unload_profile(&self, name: &str) -> Result<(), RpcError> {
        lock(&self.profiles)
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| no_profile(name))
    }

    /// Starts a run of a loaded profile and returns it.
    pub fn start(&self, p: StartParams) -> Result<RunInfo, RpcError> {
        let mut profile = lock(&self.profiles)
            .get(&p.profile)
            .cloned()
            .ok_or_else(|| no_profile(&p.profile))?;
        let send = p.output.send_settings()?;
        // Files and the null output take only a worker count.
        let workers_only = send
            == SendSettings {
                workers: send.workers,
                ..Default::default()
            };
        if workers_only && p.output.iface.is_none() && send.workers.is_some() {
            profile.output.workers = send.workers;
        }
        let output = match (p.output.iface, p.output.file, p.output.null) {
            (Some(name), None, false) => Output::Interface { name, send },
            (None, Some(f), false) if workers_only => Output::File(self.files.writable(&f)?),
            (None, None, true) if workers_only => Output::Null,
            (None, Some(_), false) | (None, None, true) => {
                return Err(RpcError::invalid_params(
                    "backend, queue, xdp_mode, batch and dpdk_args need iface",
                ))
            }
            _ => {
                return Err(RpcError::invalid_params(
                    "output needs exactly one of iface, file or null",
                ))
            }
        };
        let rate = p
            .rate
            .as_deref()
            .map(str::parse::<Rate>)
            .transpose()
            .map_err(|e| RpcError::invalid_params(e.to_string()))?;
        let duration = p
            .duration
            .as_deref()
            .map(parse_duration)
            .transpose()
            .map_err(|e| RpcError::invalid_params(e.to_string()))?;
        let config = RunConfig {
            limit: p.limit,
            duration,
            ignore_send_errors: p.ignore_errors,
            stop: None,
        };
        if p.latency {
            profile.enable_latency();
        }
        if let Some(text) = &p.impair {
            let spec = parse_impair(text)?;
            for s in &mut profile.streams {
                s.impair = spec.clone();
            }
        }
        let rx = match &p.rx {
            Some(spec) => {
                let wait = spec
                    .wait
                    .as_deref()
                    .map(parse_duration)
                    .transpose()
                    .map_err(|e| RpcError::invalid_params(e.to_string()))?
                    .unwrap_or(RxSettings::DEFAULT_WAIT);
                let receiver = (self.open_receiver)(&spec.iface).map_err(|e| {
                    RpcError::failed(format!("cannot receive on {}: {e}", spec.iface))
                })?;
                Some(RxSettings { receiver, wait })
            }
            None => None,
        };
        let started =
            start_run_with_rx(&profile, &output, rate, config, rx).map_err(RpcError::failed)?;
        let id = self.next_run.fetch_add(1, Ordering::Relaxed);
        let run = Arc::new(Run {
            id,
            profile: p.profile,
            rx_iface: p.rx.map(|r| r.iface),
            output: started.detail,
            job: started.job,
            stopped_by_request: Default::default(),
        });
        let info = run.info();
        lock(&self.runs).insert(id, run);
        Ok(info)
    }

    /// Stops a run. With `wait`, answers once it has ended (or after 10 s).
    pub fn stop(&self, id: u64, wait: bool) -> Result<RunInfo, RpcError> {
        let run = self.get_run(id)?;
        if run.job.is_running() {
            run.stopped_by_request.store(true, Ordering::Relaxed);
        }
        run.job.stop();
        if wait {
            run.job.wait(Some(STOP_TIMEOUT));
        }
        Ok(run.info())
    }

    pub fn run(&self, id: u64) -> Result<RunInfo, RpcError> {
        Ok(self.get_run(id)?.info())
    }

    pub fn runs(&self) -> Vec<RunInfo> {
        let runs: Vec<Arc<Run>> = lock(&self.runs).values().cloned().collect();
        runs.iter().map(|r| r.info()).collect()
    }

    /// Ids of the runs that are running now.
    pub fn running(&self) -> Vec<u64> {
        lock(&self.runs)
            .values()
            .filter(|r| r.job.is_running())
            .map(|r| r.id)
            .collect()
    }

    /// Forgets a run, stopping it first if it is still running. Returns its last state.
    pub fn remove(&self, id: u64) -> Result<RunInfo, RpcError> {
        let info = self.stop(id, true)?;
        lock(&self.runs).remove(&id);
        Ok(info)
    }

    /// Stops every run and waits for them, e.g. when the server shuts down.
    pub fn stop_all(&self) {
        let benches: Vec<Arc<BenchRun>> = lock(&self.bench_runs).values().cloned().collect();
        for r in &benches {
            r.stop();
        }
        let y1564: Vec<Arc<Y1564Run>> = lock(&self.y1564_runs).values().cloned().collect();
        for r in &y1564 {
            r.stop();
        }
        let scenarios: Vec<Arc<ScenarioRun>> =
            lock(&self.scenario_runs).values().cloned().collect();
        for r in &scenarios {
            r.stop();
        }
        let runs: Vec<Arc<Run>> = lock(&self.runs).values().cloned().collect();
        let tcp: Vec<Arc<TcpRun>> = lock(&self.tcp_runs).values().cloned().collect();
        let udp: Vec<Arc<UdpRun>> = lock(&self.udp_runs).values().cloned().collect();
        let rx: Vec<Arc<RxRun>> = lock(&self.rx_runs).values().cloned().collect();
        for r in &rx {
            r.job.stop();
        }
        for r in &runs {
            r.job.stop();
        }
        for r in &tcp {
            r.job.stop();
        }
        for r in &udp {
            r.job.stop();
        }
        for r in &runs {
            r.job.wait(Some(STOP_TIMEOUT));
        }
        for r in &tcp {
            r.job.wait(Some(STOP_TIMEOUT));
        }
        for r in &udp {
            r.job.wait(Some(STOP_TIMEOUT));
        }
    }

    /// The pcaps the streams of a profile replay must be readable.
    fn check_stream_files(&self, profile: &Profile) -> Result<(), RpcError> {
        for s in &profile.streams {
            if let StreamSource::Pcap(path) = &s.source {
                self.files.readable(path)?;
            }
        }
        Ok(())
    }

    fn check_tcp_files(&self, profile: &TcpProfile) -> Result<(), RpcError> {
        for t in &profile.templates {
            if let ferotrx_core::TcpSource::Pcap { path, .. } = &t.source {
                self.files.readable(path)?;
            }
        }
        Ok(())
    }

    fn check_udp_files(&self, profile: &UdpProfile) -> Result<(), RpcError> {
        for t in &profile.templates {
            match &t.source {
                UdpSource::Pcap { path, .. }
                | UdpSource::Dns {
                    pcap: Some(path), ..
                } => {
                    self.files.readable(path)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Reads the scenario of `scenario.check` and `scenario.start`, with
    /// every file it names checked against the file policy.
    fn read_scenario(&self, p: &ScenarioStartParams) -> Result<Scenario, RpcError> {
        let overrides: Vec<(String, String)> =
            p.set.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let allow = |path: &Path| self.files.readable(path).map_err(|e| e.message);
        let failed = |what: &str, e: ferotrx_core::Error| RpcError::failed(format!("{what}: {e}"));
        let mut scenario = match (&p.path, &p.toml) {
            (Some(path), None) => {
                if p.base_dir.is_some() {
                    return Err(RpcError::invalid_params(
                        "base_dir goes with toml; a scenario file uses its own folder",
                    ));
                }
                let file = self.files.readable(path)?;
                let text = std::fs::read_to_string(&file).map_err(|e| {
                    RpcError::failed(format!("cannot read {}: {e}", path.display()))
                })?;
                let base = file.parent().unwrap_or(Path::new("."));
                let what = path.display().to_string();
                let mut s = Scenario::from_toml_with(&text, base, &overrides, &allow)
                    .map_err(|e| failed(&what, e))?;
                s.path = Some(path.clone());
                if s.name.is_empty() {
                    s.name = path
                        .file_stem()
                        .map_or("scenario".into(), |n| n.to_string_lossy().into_owned());
                }
                s
            }
            (None, Some(text)) => {
                self.files.upload(text)?;
                let base = self.files.base_dir(p.base_dir.as_deref())?;
                Scenario::from_toml_with(text, &base, &overrides, &allow)
                    .map_err(|e| failed("scenario", e))?
            }
            _ => return Err(RpcError::invalid_params("give either path or toml")),
        };
        if scenario.name.is_empty() {
            scenario.name = "scenario".into();
        }
        if let Some(i) = &p.iface {
            scenario.set_default_iface(i);
        }
        for c in &scenario.checks {
            match &c.workload {
                Workload::Tcp(t) => self.check_tcp_files(t)?,
                Workload::Udp(u) => self.check_udp_files(u)?,
                Workload::Traffic(t) => self.check_stream_files(t)?,
                Workload::Y1564(_) => {}
            }
        }
        for name in &p.only {
            if !scenario.checks.iter().any(|c| c.name == *name) {
                let names: Vec<&str> = scenario.checks.iter().map(|c| c.name.as_str()).collect();
                return Err(RpcError::invalid_params(format!(
                    "no check called '{name}'; there are: {}",
                    names.join(", ")
                )));
            }
        }
        Ok(scenario)
    }

    /// Reads a scenario and lists its checks; nothing runs.
    pub fn scenario_check(&self, p: ScenarioStartParams) -> Result<ScenarioInfo, RpcError> {
        Ok(scenario_info(&self.read_scenario(&p)?))
    }

    /// Starts running a scenario's checks, one after the other, on a thread
    /// of its own; `scenario.get` follows it.
    pub fn scenario_start(&self, p: ScenarioStartParams) -> Result<ScenarioRunInfo, RpcError> {
        let scenario = self.read_scenario(&p)?;
        if let (Some(spec), true) = (&scenario.lab, p.lab.unwrap_or(true)) {
            self.scenario_lab(spec)?;
        }
        let open_port = self.open_port.clone();
        let open_receiver = self.open_receiver.clone();
        let runner = LabRunner::new()
            .with_port_opener(move |name, settings| open_port(name, settings))
            .with_receiver_opener(move |name| open_receiver(name))
            .with_runs(RunLists {
                runs: self.runs.clone(),
                tcp: self.tcp_runs.clone(),
                udp: self.udp_runs.clone(),
                next: self.next_run.clone(),
            });
        let id = self.next_run.fetch_add(1, Ordering::Relaxed);
        let run = ScenarioRun::spawn(id, scenario, p.only, runner)
            .map_err(|e| RpcError::failed(format!("cannot start the scenario: {e}")))?;
        let info = run.info();
        lock(&self.scenario_runs).insert(id, run);
        Ok(info)
    }

    fn scenario_run(&self, id: u64) -> Result<Arc<ScenarioRun>, RpcError> {
        lock(&self.scenario_runs)
            .get(&id)
            .cloned()
            .ok_or_else(|| RpcError::not_found(format!("no scenario run {id}")))
    }

    pub fn scenario_runs(&self) -> Vec<ScenarioRunInfo> {
        let runs: Vec<Arc<ScenarioRun>> = lock(&self.scenario_runs).values().cloned().collect();
        runs.iter().map(|r| r.info()).collect()
    }

    /// Stops a scenario run: the running check ends, the rest are skipped.
    /// With `wait`, answers once it has ended (or after 10 s).
    pub fn scenario_stop(&self, id: u64, wait: bool) -> Result<ScenarioRunInfo, RpcError> {
        let run = self.scenario_run(id)?;
        run.stop();
        if wait {
            run.wait(STOP_TIMEOUT);
        }
        Ok(run.info())
    }

    /// Forgets a scenario run that has ended.
    pub fn scenario_remove(&self, id: u64) -> Result<ScenarioRunInfo, RpcError> {
        let run = self.scenario_run(id)?;
        if run.is_running() {
            return Err(RpcError::failed(format!(
                "scenario run {id} is still running; stop it first"
            )));
        }
        lock(&self.scenario_runs).remove(&id);
        Ok(run.info())
    }

    /// Starts a benchmark (RFC 2544 tests, as `ferotrx bench`) on a thread
    /// of its own; `bench.get` follows its trials.
    pub fn bench_start(&self, p: BenchStartParams) -> Result<BenchRunInfo, RpcError> {
        let bad = |e: String| RpcError::invalid_params(e);
        let (text, name) = match (&p.path, &p.toml) {
            (Some(path), None) => {
                let file = self.files.readable(path)?;
                let text = std::fs::read_to_string(&file).map_err(|e| {
                    RpcError::failed(format!("cannot read {}: {e}", path.display()))
                })?;
                (text, path.display().to_string())
            }
            (None, Some(text)) => {
                self.files.upload(text)?;
                (text.clone(), "upload".to_string())
            }
            _ => return Err(RpcError::invalid_params("give either path or toml")),
        };
        let mut profile = ferotrx_core::BenchProfile::from_toml(&text)
            .map_err(|e| RpcError::failed(format!("{name}: {e}")))?;
        let c = &mut profile.config;
        if !p.tests.is_empty() {
            c.tests = p
                .tests
                .iter()
                .map(|t| t.parse().map_err(|e: ferotrx_core::Error| e.to_string()))
                .collect::<Result<_, _>>()
                .map_err(bad)?;
        }
        if !p.sizes.is_empty() {
            c.sizes = Vec::new();
            for s in &p.sizes {
                if s.trim().eq_ignore_ascii_case("rfc2544") {
                    c.sizes.extend(
                        ferotrx_core::RFC2544_SIZES
                            .iter()
                            .filter_map(|&n| ferotrx_core::SizeMix::fixed(n).ok()),
                    );
                } else {
                    c.sizes.push(
                        s.parse()
                            .map_err(|e: ferotrx_core::Error| bad(e.to_string()))?,
                    );
                }
            }
        }
        if let Some(r) = &p.line_rate {
            c.line_rate_mbps = match r.parse::<Rate>().map_err(|e| bad(e.to_string()))? {
                Rate::Mbps(m) => m,
                _ => return Err(bad("line_rate is a bit rate such as 1gbps".into())),
            };
        }
        if let Some(d) = &p.trial_duration {
            c.trial_duration = parse_duration(d).map_err(|e| bad(e.to_string()))?;
        }
        if let Some(n) = p.repetitions {
            c.repetitions = n;
        }
        c.validate().map_err(|e| bad(e.to_string()))?;
        let send = OutputSpec {
            backend: p.backend,
            queue: p.queue,
            xdp_mode: p.xdp_mode,
            workers: p.workers,
            ..Default::default()
        }
        .send_settings()?
        .or(&profile.output);
        let id = self.next_run.fetch_add(1, Ordering::Relaxed);
        let job = BenchJob {
            profile,
            profile_name: name,
            profile_text: text,
            iface: p.iface,
            rx: p.rx,
            send,
        };
        let run = BenchRun::spawn(id, job, &*self.open_bench_sinks, &*self.open_receiver)
            .map_err(RpcError::failed)?;
        let info = run.info();
        lock(&self.bench_runs).insert(id, run);
        Ok(info)
    }

    fn bench_run(&self, id: u64) -> Result<Arc<BenchRun>, RpcError> {
        lock(&self.bench_runs)
            .get(&id)
            .cloned()
            .ok_or_else(|| RpcError::not_found(format!("no benchmark run {id}")))
    }

    pub fn bench_runs(&self) -> Vec<BenchRunInfo> {
        let runs: Vec<Arc<BenchRun>> = lock(&self.bench_runs).values().cloned().collect();
        runs.iter().map(|r| r.info()).collect()
    }

    /// Stops a benchmark after the trial under way; its report is partial.
    /// With `wait`, answers once it has ended (or after 10 s).
    pub fn bench_stop(&self, id: u64, wait: bool) -> Result<BenchRunInfo, RpcError> {
        let run = self.bench_run(id)?;
        run.stop();
        if wait {
            run.wait(STOP_TIMEOUT);
        }
        Ok(run.info())
    }

    /// Forgets a benchmark run that has ended.
    pub fn bench_remove(&self, id: u64) -> Result<BenchRunInfo, RpcError> {
        let run = self.bench_run(id)?;
        if run.is_running() {
            return Err(RpcError::failed(format!(
                "benchmark run {id} is still running; stop it first"
            )));
        }
        lock(&self.bench_runs).remove(&id);
        Ok(run.info())
    }

    /// Starts a Y.1564 service activation test (as `ferotrx y1564`) on a
    /// thread of its own; `y1564.get` follows its steps.
    pub fn y1564_start(&self, p: Y1564StartParams) -> Result<Y1564RunInfo, RpcError> {
        let bad = |e: String| RpcError::invalid_params(e);
        let (text, name) = match (&p.path, &p.toml) {
            (Some(path), None) => {
                let file = self.files.readable(path)?;
                let text = std::fs::read_to_string(&file).map_err(|e| {
                    RpcError::failed(format!("cannot read {}: {e}", path.display()))
                })?;
                (text, path.display().to_string())
            }
            (None, Some(text)) => {
                self.files.upload(text)?;
                (text.clone(), "upload".to_string())
            }
            _ => return Err(RpcError::invalid_params("give either path or toml")),
        };
        let mut profile = ferotrx_core::Y1564Profile::from_toml(&text)
            .map_err(|e| RpcError::failed(format!("{name}: {e}")))?;
        let c = &mut profile.config;
        if !p.tests.is_empty() {
            c.tests = p
                .tests
                .iter()
                .map(|t| t.parse().map_err(|e: ferotrx_core::Error| e.to_string()))
                .collect::<Result<_, _>>()
                .map_err(bad)?;
        }
        if !p.services.is_empty() {
            profile
                .keep_services(&p.services)
                .map_err(|e| bad(e.to_string()))?;
        }
        let c = &mut profile.config;
        if let Some(r) = &p.line_rate {
            c.line_rate_mbps = match r.parse::<Rate>().map_err(|e| bad(e.to_string()))? {
                Rate::Mbps(m) => m,
                _ => return Err(bad("line_rate is a bit rate such as 1gbps".into())),
            };
        }
        if let Some(d) = &p.step_duration {
            c.step_duration = parse_duration(d).map_err(|e| bad(e.to_string()))?;
        }
        if let Some(d) = &p.performance_duration {
            c.performance_duration = parse_duration(d).map_err(|e| bad(e.to_string()))?;
        }
        c.validate().map_err(|e| bad(e.to_string()))?;
        let send = OutputSpec {
            backend: p.backend,
            queue: p.queue,
            xdp_mode: p.xdp_mode,
            workers: p.workers,
            ..Default::default()
        }
        .send_settings()?
        .or(&profile.output);
        let id = self.next_run.fetch_add(1, Ordering::Relaxed);
        let job = Y1564Job {
            profile,
            profile_name: name,
            profile_text: text,
            iface: p.iface,
            rx: p.rx,
            send,
        };
        let run = Y1564Run::spawn(id, job, &*self.open_bench_sinks, &*self.open_receiver)
            .map_err(RpcError::failed)?;
        let info = run.info();
        lock(&self.y1564_runs).insert(id, run);
        Ok(info)
    }

    fn y1564_run(&self, id: u64) -> Result<Arc<Y1564Run>, RpcError> {
        lock(&self.y1564_runs)
            .get(&id)
            .cloned()
            .ok_or_else(|| RpcError::not_found(format!("no Y.1564 run {id}")))
    }

    pub fn y1564_runs(&self) -> Vec<Y1564RunInfo> {
        let runs: Vec<Arc<Y1564Run>> = lock(&self.y1564_runs).values().cloned().collect();
        runs.iter().map(|r| r.info()).collect()
    }

    /// Stops a Y.1564 test; the step under way ends early and the report is
    /// partial. With `wait`, answers once it has ended (or after 10 s).
    pub fn y1564_stop(&self, id: u64, wait: bool) -> Result<Y1564RunInfo, RpcError> {
        let run = self.y1564_run(id)?;
        run.stop();
        if wait {
            run.wait(STOP_TIMEOUT);
        }
        Ok(run.info())
    }

    /// Forgets a Y.1564 run that has ended.
    pub fn y1564_remove(&self, id: u64) -> Result<Y1564RunInfo, RpcError> {
        let run = self.y1564_run(id)?;
        if run.is_running() {
            return Err(RpcError::failed(format!(
                "Y.1564 run {id} is still running; stop it first"
            )));
        }
        lock(&self.y1564_runs).remove(&id);
        Ok(run.info())
    }

    /// Starts a stateful TCP run from a TCP profile.
    pub fn tcp_start(&self, p: TcpStartParams) -> Result<TcpRunInfo, RpcError> {
        let failed = |e: ferotrx_core::Error| RpcError::failed(e);
        let mut profile = match (p.path, p.toml) {
            (Some(path), None) => TcpProfile::from_path(self.files.readable(&path)?)
                .map_err(|e| RpcError::failed(format!("{}: {e}", path.display())))?,
            (None, Some(text)) => {
                self.files.upload(&text)?;
                let base = self.files.base_dir(p.base_dir.as_deref())?;
                TcpProfile::from_toml(&text, &base).map_err(failed)?
            }
            _ => return Err(RpcError::invalid_params("give either path or toml")),
        };
        self.check_tcp_files(&profile)?;
        if let Some(v) = p.cps {
            profile.cps = v;
        }
        if let Some(v) = p.connections {
            profile.connections = v;
        }
        if let Some(v) = p.concurrency {
            profile.concurrency = v;
        }
        let duration = p
            .duration
            .as_deref()
            .map(parse_duration)
            .transpose()
            .map_err(|e| RpcError::invalid_params(e.to_string()))?;
        let config = TcpRunConfig {
            duration,
            stop: None,
        };
        let output = OutputSpec {
            backend: p.backend,
            queue: p.queue,
            xdp_mode: p.xdp_mode,
            batch: p.batch,
            dpdk_args: p.dpdk_args,
            workers: p.workers,
            ..Default::default()
        }
        .send_settings()?;
        profile.output = output.or(&profile.output);
        if let Some(c) = &p.congestion {
            profile.options.congestion = c.parse().map_err(RpcError::invalid_params)?;
        }
        if let Some(e) = p.ecn {
            profile.options.ecn = e;
        }
        apply_impair(&mut profile.impair, &p.impair, &p.impair_rx)?;
        let started = start_tcp_with(&profile, p.iface.as_deref(), config, &*self.open_port)
            .map_err(RpcError::failed)?;
        let id = self.next_run.fetch_add(1, Ordering::Relaxed);
        let run = Arc::new(TcpRun {
            id,
            program: started.program,
            interfaces: started.interfaces,
            ports: started.port_details,
            job: started.job,
            stopped_by_request: Default::default(),
        });
        let info = run.info();
        lock(&self.tcp_runs).insert(id, run);
        Ok(info)
    }

    /// Stops a TCP run. With `wait`, answers once it has ended (or after 10 s).
    pub fn tcp_stop(&self, id: u64, wait: bool) -> Result<TcpRunInfo, RpcError> {
        let run = self.tcp_run(id)?;
        run.stop(wait.then_some(STOP_TIMEOUT));
        Ok(run.info())
    }

    pub fn tcp_runs(&self) -> Vec<TcpRunInfo> {
        let runs: Vec<Arc<TcpRun>> = lock(&self.tcp_runs).values().cloned().collect();
        runs.iter().map(|r| r.info()).collect()
    }

    fn tcp_run(&self, id: u64) -> Result<Arc<TcpRun>, RpcError> {
        lock(&self.tcp_runs)
            .get(&id)
            .cloned()
            .ok_or_else(|| RpcError::not_found(format!("no TCP run {id}")))
    }

    /// Starts a stateful UDP run from a UDP profile.
    pub fn udp_start(&self, p: UdpStartParams) -> Result<UdpRunInfo, RpcError> {
        let failed = |e: ferotrx_core::Error| RpcError::failed(e);
        let mut profile = match (p.path, p.toml) {
            (Some(path), None) => UdpProfile::from_path(self.files.readable(&path)?)
                .map_err(|e| RpcError::failed(format!("{}: {e}", path.display())))?,
            (None, Some(text)) => {
                self.files.upload(&text)?;
                let base = self.files.base_dir(p.base_dir.as_deref())?;
                UdpProfile::from_toml(&text, &base).map_err(failed)?
            }
            _ => return Err(RpcError::invalid_params("give either path or toml")),
        };
        self.check_udp_files(&profile)?;
        if let Some(v) = p.rate {
            profile.rate = v;
        }
        if let Some(v) = p.transactions {
            profile.transactions = v;
        }
        if let Some(v) = p.concurrency {
            profile.concurrency = v;
        }
        let duration = p
            .duration
            .as_deref()
            .map(parse_duration)
            .transpose()
            .map_err(|e| RpcError::invalid_params(e.to_string()))?;
        let config = TcpRunConfig {
            duration,
            stop: None,
        };
        let output = OutputSpec {
            backend: p.backend,
            queue: p.queue,
            xdp_mode: p.xdp_mode,
            batch: p.batch,
            dpdk_args: p.dpdk_args,
            workers: p.workers,
            ..Default::default()
        }
        .send_settings()?;
        profile.output = output.or(&profile.output);
        apply_impair(&mut profile.impair, &p.impair, &p.impair_rx)?;
        let started = start_udp_with(&profile, p.iface.as_deref(), config, &*self.open_port)
            .map_err(RpcError::failed)?;
        let id = self.next_run.fetch_add(1, Ordering::Relaxed);
        let run = Arc::new(UdpRun {
            id,
            program: started.program,
            interfaces: started.interfaces,
            ports: started.port_details,
            job: started.job,
            stopped_by_request: Default::default(),
        });
        let info = run.info();
        lock(&self.udp_runs).insert(id, run);
        Ok(info)
    }

    /// Stops a UDP run. With `wait`, answers once it has ended (or after 10 s).
    pub fn udp_stop(&self, id: u64, wait: bool) -> Result<UdpRunInfo, RpcError> {
        let run = self.udp_run(id)?;
        run.stop(wait.then_some(STOP_TIMEOUT));
        Ok(run.info())
    }

    pub fn udp_runs(&self) -> Vec<UdpRunInfo> {
        let runs: Vec<Arc<UdpRun>> = lock(&self.udp_runs).values().cloned().collect();
        runs.iter().map(|r| r.info()).collect()
    }

    fn udp_run(&self, id: u64) -> Result<Arc<UdpRun>, RpcError> {
        lock(&self.udp_runs)
            .get(&id)
            .cloned()
            .ok_or_else(|| RpcError::not_found(format!("no UDP run {id}")))
    }

    /// Starts a receiver that counts the latency flows arriving on an interface.
    pub fn rx_start(&self, p: RxStartParams) -> Result<RxRunInfo, RpcError> {
        let duration = p
            .duration
            .as_deref()
            .map(parse_duration)
            .transpose()
            .map_err(|e| RpcError::invalid_params(e.to_string()))?;
        let receiver = (self.open_receiver)(&p.iface)
            .map_err(|e| RpcError::failed(format!("cannot receive on {}: {e}", p.iface)))?;
        let job = RxJob::spawn(
            receiver,
            RxConfig {
                duration,
                stop: None,
                interval: None,
            },
        )
        .map_err(RpcError::failed)?;
        let id = self.next_run.fetch_add(1, Ordering::Relaxed);
        let run = Arc::new(RxRun {
            id,
            iface: p.iface,
            job,
            stopped_by_request: Default::default(),
        });
        let info = run.info();
        lock(&self.rx_runs).insert(id, run);
        Ok(info)
    }

    /// Stops a receiver. With `wait`, answers once it has ended (or after 10 s).
    pub fn rx_stop(&self, id: u64, wait: bool) -> Result<RxRunInfo, RpcError> {
        let run = self.rx_run(id)?;
        if run.job.is_running() {
            run.stopped_by_request.store(true, Ordering::Relaxed);
        }
        run.job.stop();
        if wait {
            run.job.wait(Some(STOP_TIMEOUT));
        }
        Ok(run.info())
    }

    pub fn rx_runs(&self) -> Vec<RxRunInfo> {
        let runs: Vec<Arc<RxRun>> = lock(&self.rx_runs).values().cloned().collect();
        runs.iter().map(|r| r.info()).collect()
    }

    fn rx_run(&self, id: u64) -> Result<Arc<RxRun>, RpcError> {
        lock(&self.rx_runs)
            .get(&id)
            .cloned()
            .ok_or_else(|| RpcError::not_found(format!("no receiver {id}")))
    }

    fn get_run(&self, id: u64) -> Result<Arc<Run>, RpcError> {
        lock(&self.runs)
            .get(&id)
            .cloned()
            .ok_or_else(|| RpcError::not_found(format!("no run {id}")))
    }
}

impl Run {
    fn info(&self) -> RunInfo {
        let stats = self.job.stats();
        let (state, error) = match self.job.state() {
            JobState::Running => (RunState::Running, None),
            JobState::Finished
                if stats.total.stopped && self.stopped_by_request.load(Ordering::Relaxed) =>
            {
                (RunState::Stopped, None)
            }
            JobState::Finished => (RunState::Finished, None),
            JobState::Failed(e) => (RunState::Failed, Some(e)),
        };
        let (total, mut streams) = RunInfo::counters(&stats, self.job.stream_names());
        let rx = match (&self.rx_iface, self.job.rx_stats()) {
            (Some(iface), Some(rx)) => {
                let reports =
                    FlowReport::for_run(self.job.stream_names(), self.job.flows(), &stats, &rx);
                for r in &reports {
                    if let Some(s) = streams.iter_mut().find(|s| s.name == r.stream) {
                        s.latency = Some(r.into());
                    }
                }
                Some(RxCounters::new(iface, &rx))
            }
            _ => None,
        };
        RunInfo {
            id: self.id,
            profile: self.profile.clone(),
            output: self.output.clone(),
            workers: self.job.workers(),
            state,
            error,
            impair: stats.total.impair.as_ref().map(Into::into),
            total,
            streams,
            rx,
        }
    }
}

impl RxRun {
    fn info(&self) -> RxRunInfo {
        let stats = self.job.stats();
        let (state, error) = match self.job.state() {
            JobState::Running => (RunState::Running, None),
            JobState::Finished if self.stopped_by_request.load(Ordering::Relaxed) => {
                (RunState::Stopped, None)
            }
            JobState::Finished => (RunState::Finished, None),
            JobState::Failed(e) => (RunState::Failed, Some(e)),
        };
        RxRunInfo {
            id: self.id,
            state,
            error,
            counters: RxCounters::new(&self.iface, &stats),
            flows: stats.flows.values().map(Into::into).collect(),
        }
    }
}

fn profile_info(name: &str, p: &Profile) -> ProfileInfo {
    ProfileInfo {
        name: name.to_string(),
        streams: p
            .streams
            .iter()
            .map(|s| StreamInfo {
                name: s.name.clone(),
                source: match &s.source {
                    StreamSource::Pcap(path) => display_path(path),
                    other => other.to_string(),
                },
                rate: s.rate.to_string(),
                loops: s.loops,
                limit: s.limit,
                delay_s: s.delay.as_secs_f64(),
                rewrite: s.rewrite.iter().map(ToString::to_string).collect(),
                vary: s.vary.iter().map(ToString::to_string).collect(),
                latency: s.latency,
                sizes: s.sizes.as_ref().map(ToString::to_string),
                model: (!s.model.is_steady()).then(|| s.model.to_string()),
                impair: s.impair.as_ref().map(ToString::to_string),
            })
            .collect(),
    }
}

fn display_path(p: &Path) -> String {
    p.display().to_string()
}

fn no_profile(name: &str) -> RpcError {
    RpcError::not_found(format!("no profile '{name}' (load it with profile.load)"))
}

impl OutputSpec {
    /// The send settings of an `iface` output, checked.
    pub fn send_settings(&self) -> Result<SendSettings, RpcError> {
        let bad = |e: ferotrx_core::Error| RpcError::invalid_params(e.to_string());
        let s = SendSettings {
            backend: self
                .backend
                .as_deref()
                .map(str::parse)
                .transpose()
                .map_err(bad)?,
            queue: self.queue,
            xdp_mode: self
                .xdp_mode
                .as_deref()
                .map(str::parse)
                .transpose()
                .map_err(bad)?,
            batch: self.batch,
            dpdk_args: self.dpdk_args.clone(),
            workers: self.workers,
        };
        s.validate().map_err(bad)?;
        Ok(s)
    }
}

pub(crate) fn parse<T: DeserializeOwned>(params: Value) -> Result<T, RpcError> {
    // Methods without required parameters accept a missing `params`.
    let params = if params.is_null() {
        Value::Object(Default::default())
    } else {
        params
    };
    serde_json::from_value(params).map_err(|e| RpcError::invalid_params(e.to_string()))
}

pub(crate) fn to_value<T: Serialize>(v: T) -> Result<Value, RpcError> {
    serde_json::to_value(v).map_err(|e| RpcError::new(RpcError::INTERNAL_ERROR, e.to_string()))
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The lab router `lab.start` builds from its parameters.
fn lab_config(p: &LabStartParams) -> ferotrx_io::LabConfig {
    let d = ferotrx_io::LabConfig::default();
    ferotrx_io::LabConfig {
        ipv6: p.ipv6.unwrap_or(d.ipv6),
        nat: p.nat.unwrap_or(d.nat),
        loss: p.loss.unwrap_or(0.0),
        delay: p.delay.clone().unwrap_or_default(),
        block_tcp: p.block_tcp.clone(),
        block_udp: p.block_udp.clone(),
        dhcp: p.dhcp,
        queues: p.queues.unwrap_or(1).clamp(1, 64),
    }
}

fn lab_info(l: &ferotrx_io::Lab, unavailable: Option<String>) -> LabInfo {
    let c = l.config();
    let mut summary = vec![
        format!(
            "send on {}: clients on VLAN 10, 192.168.10.0/24, gateway 192.168.10.1",
            l.interface()
        ),
        "servers on VLAN 20, 192.168.20.0/24, gateway 192.168.20.1".to_string(),
        format!(
            "router MAC {} on both VLANs (mac_dst for replayed streams)",
            ferotrx_io::LAB_ROUTER_MAC
        ),
        format!(
            "stream receiver {} (always reachable, received on {})",
            ferotrx_io::LAB_RECEIVER_IP,
            l.interface()
        ),
    ];
    if c.ipv6 {
        summary
            .push("IPv6: fd00:10::/64 (gateway fd00:10::1) and fd00:20::/64 (fd00:20::1)".into());
    }
    let mut opts = Vec::new();
    if c.nat {
        opts.push("NAT towards the servers".to_string());
    }
    if c.loss > 0.0 {
        opts.push(format!("drops {:.1}%", c.loss * 100.0));
    }
    if !c.delay.is_empty() {
        opts.push(format!("delay {}", c.delay));
    }
    if !c.block_tcp.is_empty() {
        opts.push(format!("resets TCP to {:?}", c.block_tcp));
    }
    if !c.block_udp.is_empty() {
        opts.push(format!("drops UDP to {:?}", c.block_udp));
    }
    if c.dhcp {
        opts.push("DHCP on VLAN 10 (.200-.250)".into());
    }
    if c.queues > 1 {
        opts.push(format!("{} queues on the link", c.queues));
    }
    if !opts.is_empty() {
        summary.push(format!("router: {}", opts.join(", ")));
    }
    LabInfo {
        running: true,
        interface: l.interface().into(),
        namespace: ferotrx_io::LAB_NAMESPACE.into(),
        summary,
        notes: l.notes().to_vec(),
        config: LabStartParams {
            ipv6: Some(c.ipv6),
            nat: Some(c.nat),
            loss: (c.loss > 0.0).then_some(c.loss),
            delay: (!c.delay.is_empty()).then(|| c.delay.clone()),
            block_tcp: c.block_tcp.clone(),
            block_udp: c.block_udp.clone(),
            dhcp: c.dhcp,
            queues: Some(c.queues),
        },
        unavailable,
    }
}

/// An impairment spec from a request; `None` for one that does nothing.
fn parse_impair(text: &str) -> Result<Option<ferotrx_core::ImpairSpec>, RpcError> {
    let spec: ferotrx_core::ImpairSpec = text
        .parse()
        .map_err(|e: ferotrx_core::Error| RpcError::invalid_params(e.to_string()))?;
    Ok((!spec.is_none()).then_some(spec))
}

/// A request's `impair` and `impair_rx` over a profile's.
fn apply_impair(
    profile: &mut ferotrx_core::PortImpair,
    tx: &Option<String>,
    rx: &Option<String>,
) -> Result<(), RpcError> {
    if let Some(t) = tx {
        profile.tx = parse_impair(t)?;
    }
    if let Some(t) = rx {
        profile.rx = parse_impair(t)?;
    }
    Ok(())
}

#[cfg(test)]
mod lab_tests {
    use super::*;

    #[test]
    fn labs_are_off_unless_asked_for() {
        let c = Controller::new();
        assert!(!c.info().lab);
        let e = c.call("lab.start", serde_json::json!({})).unwrap_err();
        assert!(e.message.contains("--lab"), "{}", e.message);
        let info: LabInfo =
            serde_json::from_value(c.call("lab.get", Value::Null).unwrap()).unwrap();
        assert!(!info.running);
        assert_eq!(info.interface, "ftrx-lab");
        assert!(info.unavailable.is_some());
        let bad = c.call("lab.start", serde_json::json!({"colour": "red"}));
        assert!(bad.is_err());
        assert_eq!(Role::required_for("lab.get"), Some(Role::Read));
        assert_eq!(Role::required_for("lab.start"), Some(Role::Operator));
    }
}
