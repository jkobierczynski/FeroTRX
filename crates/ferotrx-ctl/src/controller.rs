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

use crate::files::FilePolicy;
use crate::protocol::*;
use crate::tcp::{start_tcp_with, PortOpener, TcpRun};
use crate::udp::{start_udp_with, UdpRun};

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
    let mut streams = if rx.is_some() && !profile.has_latency() {
        let mut p = profile.clone();
        p.enable_latency();
        p.load()?
    } else {
        profile.load()?
    };
    if let Some(rate) = rate {
        rate.validate()?;
        for s in &mut streams {
            s.rate = rate;
        }
    }
    let linktype = streams
        .first()
        .map_or(LINKTYPE_ETHERNET, ferotrx_core::Stream::linktype);
    let opened = output
        .clone()
        .with_defaults(&profile.output)
        .open_detailed(linktype)?;
    Ok(Started {
        job: Job::spawn_with_rx(streams, opened.sink, config, rx)?,
        detail: opened.detail,
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
    runs: Mutex<BTreeMap<u64, Arc<Run>>>,
    tcp_runs: Mutex<BTreeMap<u64, Arc<TcpRun>>>,
    udp_runs: Mutex<BTreeMap<u64, Arc<UdpRun>>>,
    rx_runs: Mutex<BTreeMap<u64, Arc<RxRun>>>,
    next_run: AtomicU64,
    auth_required: bool,
    files: FilePolicy,
    open_port: Box<PortOpener>,
    open_receiver: Box<ReceiverOpener>,
}

struct RxRun {
    id: u64,
    iface: String,
    job: RxJob,
    stopped_by_request: std::sync::atomic::AtomicBool,
}

struct Run {
    id: u64,
    profile: String,
    /// How the output sends, as `start_run_detailed` described it.
    output: String,
    /// The interface the run receives on, if it measures loss and latency.
    rx_iface: Option<String>,
    job: Job,
    stopped_by_request: std::sync::atomic::AtomicBool,
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
            runs: Mutex::default(),
            tcp_runs: Mutex::default(),
            udp_runs: Mutex::default(),
            rx_runs: Mutex::default(),
            next_run: AtomicU64::new(1),
            auth_required: false,
            files: FilePolicy::unrestricted(),
            open_port: Box::new(ferotrx_io::open_port),
            open_receiver: Box::new(ferotrx_io::open_receiver),
        }
    }

    /// Opens the interfaces runs receive on with `open` instead of
    /// libpcap/Npcap, for example to receive from in-memory ports in tests.
    pub fn with_receiver_opener(
        mut self,
        open: impl Fn(&str) -> Result<Box<dyn PacketReceiver>, SinkError> + Send + Sync + 'static,
    ) -> Self {
        self.open_receiver = Box::new(open);
        self
    }

    /// Opens the interfaces of TCP runs with `open` instead of libpcap/Npcap,
    /// for example to run on in-memory ports in tests.
    pub fn with_port_opener(
        mut self,
        open: impl Fn(&str) -> Result<Box<dyn ferotrx_core::PacketPort>, ferotrx_core::SinkError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.open_port = Box::new(open);
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
        for s in &profile.streams {
            if let StreamSource::Pcap(path) = &s.source {
                self.files.readable(path)?;
            }
        }
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
        let profile = lock(&self.profiles)
            .get(&p.profile)
            .cloned()
            .ok_or_else(|| no_profile(&p.profile))?;
        let send = p.output.send_settings()?;
        let output = match (p.output.iface, p.output.file, p.output.null) {
            (Some(name), None, false) => Output::Interface { name, send },
            (None, Some(f), false) if send.is_empty() => Output::File(self.files.writable(&f)?),
            (None, None, true) if send.is_empty() => Output::Null,
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
        let mut profile = profile;
        if p.latency {
            profile.enable_latency();
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
        for t in &profile.templates {
            if let ferotrx_core::TcpSource::Pcap { path, .. } = &t.source {
                self.files.readable(path)?;
            }
        }
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
        let started = start_tcp_with(&profile, p.iface.as_deref(), config, &*self.open_port)
            .map_err(RpcError::failed)?;
        let id = self.next_run.fetch_add(1, Ordering::Relaxed);
        let run = Arc::new(TcpRun {
            id,
            program: started.program,
            interfaces: started.interfaces,
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
        let started = start_udp_with(&profile, p.iface.as_deref(), config, &*self.open_port)
            .map_err(RpcError::failed)?;
        let id = self.next_run.fetch_add(1, Ordering::Relaxed);
        let run = Arc::new(UdpRun {
            id,
            program: started.program,
            interfaces: started.interfaces,
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
            state,
            error,
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
