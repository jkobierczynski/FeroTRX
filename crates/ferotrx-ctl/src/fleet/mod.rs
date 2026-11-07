//! A controller for several agents: deploys a [`FleetPlan`]'s profiles to
//! the control servers it names, starts every run at one instant, reads
//! their counters as they go and adds them up.
//!
//! The runs start together by the wall clock: each start call carries a
//! `start_at`, the shared start in the agent's own clock. The controller
//! measures how far each agent's clock is from its own (the way NTP does,
//! from the round trip of `server.info`), so the agents need not have their
//! clocks in step for this; one-way latency between two agents does.

mod metrics;
mod report;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use ferotrx_core::fleet::{AgentSpec, FleetPlan, FleetRun};
use ferotrx_core::scenario::{CheckKind, ConditionResult, Metrics};
use ferotrx_core::{unix_seconds, Error, Result};

use crate::protocol::*;
use crate::{Client, ClientTls};

pub use metrics::{merge_latency, tcp_metrics, traffic_metrics, udp_metrics, TrafficPart};
pub use report::{
    AgentRecord, CaptureRecord, DeployRecord, FleetReport, FleetSample, InstanceRecord, RunRecord,
    FLEET_REPORT_FORMAT,
};

/// Longest a call to an agent may take.
const CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// After the last run should have ended, how long the controller waits
/// for it before stopping it.
const GRACE: Duration = Duration::from_secs(10);

/// How a fleet run goes besides the plan.
#[derive(Clone, Debug, Default)]
pub struct FleetOptions {
    /// Set to stop every run (Ctrl-C); the report is partial.
    pub stop: Option<Arc<AtomicBool>>,
    /// Every run goes this long instead of the plan's durations.
    pub duration: Option<Duration>,
    /// Leave the runs on the agents when they end, to look at them there.
    pub keep: bool,
    /// Deploy only, and start nothing.
    pub deploy_only: bool,
    /// Fetch the plan's captures from the agents into this folder after the
    /// run, as `CAPTURE.pcap` (`AGENT-IFACE.pcap`).
    pub collect: Option<std::path::PathBuf>,
    /// Merge the fetched captures into this pcapng, one interface per
    /// capture, with times put on the controller's clock.
    pub merge: Option<std::path::PathBuf>,
}

/// What a fleet run tells its watcher as it goes.
#[derive(Debug)]
pub enum FleetEvent<'a> {
    /// An agent answered.
    Agent(&'a AgentRecord),
    /// A run's profile and files are on an agent.
    Deployed(&'a DeployRecord),
    /// Every run was told to start at this time (Unix seconds, the
    /// controller's clock).
    Starting { at: f64 },
    /// Counters, every `interval`.
    Sample(&'a FleetSample),
}

/// An agent the controller talks to.
pub struct Agent {
    pub spec: AgentSpec,
    pub client: Client,
    pub info: ServerInfo,
    /// The agent's clock minus the controller's, in seconds.
    pub offset: f64,
    /// The round trip of the best clock reading, in seconds.
    pub rtt: f64,
}

impl Agent {
    /// Connects, logs in and reads the agent's clock.
    pub fn connect(spec: &AgentSpec) -> std::result::Result<Agent, String> {
        let at = &spec.address;
        let mut client = match &spec.tls {
            None => Client::connect(at).map_err(|e| format!("cannot connect to {at}: {e}"))?,
            Some(t) => {
                let ca = t.ca.as_ref().ok_or_else(|| {
                    "TLS needs ca: the authority that signed the agent's certificate".to_string()
                })?;
                let mut tls = ClientTls::from_ca_file(ca).map_err(|e| e.to_string())?;
                if let (Some(cert), Some(key)) = (&t.cert, &t.key) {
                    tls = tls
                        .with_client_cert_files(cert, key)
                        .map_err(|e| e.to_string())?;
                }
                if let Some(n) = &t.server_name {
                    tls = tls.with_server_name(n.clone());
                }
                Client::connect_tls(at, &tls).map_err(|e| format!("cannot connect to {at}: {e}"))?
            }
        };
        client
            .set_timeout(Some(CALL_TIMEOUT))
            .map_err(|e| e.to_string())?;
        let token = match (&spec.token, &spec.token_env) {
            (Some(t), _) => Some(t.clone()),
            (None, Some(var)) => Some(
                std::env::var(var)
                    .map_err(|_| format!("the token is in ${var}, which is not set here"))?,
            ),
            (None, None) => None,
        };
        if let Some(t) = token {
            client.auth(&t).map_err(|e| format!("cannot log in: {e}"))?;
        }
        // The clock: the reading with the shortest round trip.
        let (mut best, mut info) = (None::<(f64, f64)>, None);
        for _ in 0..5 {
            let t0 = unix_seconds(SystemTime::now());
            let i = client.info().map_err(|e| e.to_string())?;
            let t1 = unix_seconds(SystemTime::now());
            let Some(at) = i.time else {
                return Err(format!(
                    "the agent runs FeroTRX {}, which cannot start runs at a given time; \
                     a fleet needs 0.31.0 or later",
                    i.version
                ));
            };
            let rtt = t1 - t0;
            if best.is_none_or(|(r, _)| rtt < r) {
                best = Some((rtt, at - (t0 + t1) / 2.0));
            }
            info = Some(i);
        }
        let (rtt, offset) = best.expect("five readings");
        let info = info.expect("five readings");
        if info.auth_required && info.role.is_none() {
            return Err(
                "the agent wants a login: give token, token_env or a client certificate".into(),
            );
        }
        if info.role == Some(Role::Read) {
            return Err("logged in read-only; a fleet needs the operator role".into());
        }
        Ok(Agent {
            spec: spec.clone(),
            client,
            info,
            offset,
            rtt,
        })
    }

    fn record(&self) -> AgentRecord {
        AgentRecord {
            name: self.spec.name.clone(),
            address: self.spec.address.clone(),
            version: self.info.version.clone(),
            tls: self.info.tls,
            user: self.info.user.clone(),
            backends: self.info.backends.clone(),
            rtt_ms: self.rtt * 1000.0,
            offset_ms: self.offset * 1000.0,
        }
    }
}

/// One run on one agent, once started.
struct Started {
    run: usize,
    agent: usize,
    kind: CheckKind,
    id: u64,
    /// The receiver on another agent: (agent, rx id).
    rx: Option<(usize, u64)>,
    /// When it should start, by the controller's clock.
    planned: f64,
    last: Option<Last>,
    rx_last: Option<RxRunInfo>,
    error: Option<String>,
}

/// The latest counters of a run.
#[derive(Clone, Debug)]
enum Last {
    Traffic(Box<RunInfo>),
    Tcp(Box<TcpRunInfo>),
    Udp(Box<UdpRunInfo>),
}

impl Last {
    fn running(&self) -> bool {
        match self {
            Last::Traffic(i) => i.state.is_running(),
            Last::Tcp(i) => i.state.is_running(),
            Last::Udp(i) => i.state.is_running(),
        }
    }

    fn state(&self) -> RunState {
        match self {
            Last::Traffic(i) => i.state,
            Last::Tcp(i) => i.state,
            Last::Udp(i) => i.state,
        }
    }

    fn error(&self) -> Option<String> {
        match self {
            Last::Traffic(i) => i.error.clone(),
            Last::Tcp(i) => i.error.clone(),
            Last::Udp(i) => i.error.clone(),
        }
    }

    fn started_at(&self) -> Option<f64> {
        match self {
            Last::Traffic(i) => i.started_at,
            Last::Tcp(i) => i.started_at,
            Last::Udp(i) => i.started_at,
        }
    }

    fn json(&self) -> serde_json::Value {
        match self {
            Last::Traffic(i) => serde_json::to_value(i),
            Last::Tcp(i) => serde_json::to_value(i),
            Last::Udp(i) => serde_json::to_value(i),
        }
        .unwrap_or_default()
    }
}

fn failed(what: String) -> Error {
    Error::Profile(what)
}

/// Connects to every agent of the plan.
pub fn connect_all(plan: &FleetPlan, progress: &mut dyn FnMut(&FleetEvent)) -> Result<Vec<Agent>> {
    let mut agents = Vec::new();
    for spec in &plan.agents {
        let a = Agent::connect(spec).map_err(|e| failed(format!("agent '{}': {e}", spec.name)))?;
        progress(&FleetEvent::Agent(&a.record()));
        agents.push(a);
    }
    Ok(agents)
}

/// Sends every run's profile and files to its agents; files an agent has
/// already (by SHA-256) are not sent again.
pub fn deploy(
    plan: &FleetPlan,
    agents: &mut [Agent],
    progress: &mut dyn FnMut(&FleetEvent),
) -> Result<Vec<DeployRecord>> {
    let mut out = Vec::new();
    for run in &plan.runs {
        let dir = plan.deploy_dir.join(run.slug());
        for inst in &run.instances {
            let a = agent_index(agents, &inst.agent);
            let dep = inst.deployment(&dir);
            let mut rec = DeployRecord {
                run: run.name.clone(),
                agent: inst.agent.clone(),
                profile: dep.profile.display().to_string(),
                files_sent: 0,
                files_kept: 0,
                bytes_sent: 0,
            };
            let client = &mut agents[a].client;
            let ctx =
                |e: String| failed(format!("deploying '{}' to '{}': {e}", run.name, inst.agent));
            for (local, remote) in &dep.files {
                let data = std::fs::read(local)
                    .map_err(|e| ctx(format!("cannot read {}: {e}", local.display())))?;
                if client
                    .upload(remote, &data)
                    .map_err(|e| ctx(e.to_string()))?
                {
                    rec.files_sent += 1;
                    rec.bytes_sent += data.len() as u64;
                } else {
                    rec.files_kept += 1;
                }
            }
            client
                .upload(&dep.profile, inst.text.as_bytes())
                .map_err(|e| ctx(e.to_string()))?;
            progress(&FleetEvent::Deployed(&rec));
            out.push(rec);
        }
    }
    Ok(out)
}

fn agent_index(agents: &[Agent], name: &str) -> usize {
    agents
        .iter()
        .position(|a| a.spec.name == name)
        .expect("the plan checked its agents")
}

fn ms(d: Duration) -> String {
    format!("{}ms", d.as_millis())
}

/// The name a traffic run's profile is loaded under on its agent.
fn profile_name(plan: &FleetPlan, run: &FleetRun) -> String {
    format!("fleet-{}-{}", slug_of(&plan.name), run.slug())
}

fn slug_of(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    s.trim_matches('-').to_string()
}

/// Deploys the plan, starts every run together, follows them to the end
/// and adds up their counters.
pub fn run_fleet(
    plan: &FleetPlan,
    options: &FleetOptions,
    progress: &mut dyn FnMut(&FleetEvent),
) -> Result<FleetReport> {
    let stop = options.stop.clone().unwrap_or_default();
    let began = Instant::now();
    let mut agents = connect_all(plan, progress)?;
    let deployed = deploy(plan, &mut agents, progress)?;
    let mut report = FleetReport::new(plan, &agents, deployed);
    if options.deploy_only {
        report.elapsed_s = began.elapsed().as_secs_f64();
        return Ok(report);
    }

    let mut captures = start_captures(plan, &mut agents)?;
    let start = SystemTime::now() + plan.start_delay;
    let start_s = unix_seconds(start);
    progress(&FleetEvent::Starting { at: start_s });
    report.started_at = start_s;
    let mut started: Vec<Started> = Vec::new();
    if let Err(e) = start_all(plan, options, &mut agents, start_s, &mut started) {
        // Nothing may run half: stop what started.
        stop_all(&mut agents, &mut started);
        remove_all(plan, &mut agents, &started);
        stop_captures(&mut agents, &mut captures, true);
        return Err(e);
    }
    let late = unix_seconds(SystemTime::now()) - start_s;
    if late > 0.0 {
        report.notes.push(format!(
            "the start calls took {:.0} ms longer than start_delay: the runs started as they were told, late",
            late * 1000.0
        ));
    }

    // The longest a run should take, by the controller's clock.
    let longest = plan
        .runs
        .iter()
        .map(|r| {
            options
                .duration
                .or(r.settings.duration)
                .map(|d| r.delay + d)
        })
        .collect::<Option<Vec<_>>>()
        .and_then(|v| v.into_iter().max());
    let deadline = longest.map(|d| start + d + GRACE);
    let mut stopped = false;
    loop {
        let next = Instant::now() + plan.interval;
        poll(&mut agents, &mut started);
        let sample = sample(plan, &started, start_s);
        progress(&FleetEvent::Sample(&sample));
        report.samples.push(sample);
        let waiting = SystemTime::now() < start;
        if !waiting
            && started
                .iter()
                .all(|s| !s.last.as_ref().is_some_and(Last::running))
        {
            break;
        }
        if stop.load(Ordering::Relaxed) {
            stopped = true;
            break;
        }
        if deadline.is_some_and(|d| SystemTime::now() > d) {
            report
                .notes
                .push("a run went on after its duration: the controller stopped it".into());
            break;
        }
        while Instant::now() < next && !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    stop_all(&mut agents, &mut started);
    finish_rx(plan, &mut agents, &mut started);
    report.finish(plan, &agents, &started, stopped);
    if !options.keep {
        remove_all(plan, &mut agents, &started);
    }
    stop_captures(&mut agents, &mut captures, !options.keep);
    if let Some(dir) = &options.collect {
        collect_captures(&mut agents, &mut captures, dir);
        if let Some(out) = &options.merge {
            match merge_captures(&agents, &captures, out) {
                Ok(n) => {
                    report.merged = Some(out.display().to_string());
                    report
                        .notes
                        .push(format!("{n} frames merged into {}", out.display()));
                }
                Err(e) => report.notes.push(format!("cannot merge the captures: {e}")),
            }
        }
    }
    report.captures = captures.into_iter().map(|c| c.record).collect();
    report.elapsed_s = began.elapsed().as_secs_f64();
    Ok(report)
}

/// A capture of the plan, on its agent.
struct Capturing {
    agent: usize,
    id: Option<u64>,
    record: CaptureRecord,
}

/// Starts the plan's captures, before the runs so they see the start. Each
/// writes `deploy_dir/captures/NAME.pcap` on its agent.
fn start_captures(plan: &FleetPlan, agents: &mut [Agent]) -> Result<Vec<Capturing>> {
    let mut out: Vec<Capturing> = Vec::new();
    for c in &plan.captures {
        let a = agent_index(agents, &c.agent);
        let file = plan
            .deploy_dir
            .join("captures")
            .join(format!("{}.pcap", c.name));
        let got = agents[a].client.capture_start(&CaptureStartParams {
            iface: c.iface.clone(),
            filter: c.filter.clone(),
            snaplen: c.snaplen,
            file: Some(file.clone()),
            stream: Some(false),
            ..Default::default()
        });
        match got {
            Ok(info) => out.push(Capturing {
                agent: a,
                id: Some(info.id),
                record: CaptureRecord {
                    agent: c.agent.clone(),
                    iface: c.iface.clone(),
                    filter: c.filter.clone(),
                    file: file.display().to_string(),
                    ..Default::default()
                },
            }),
            Err(e) => {
                stop_captures(agents, &mut out, true);
                return Err(failed(format!(
                    "capture on {} of '{}': {e}",
                    c.iface, c.agent
                )));
            }
        }
    }
    Ok(out)
}

/// Stops the captures and reads their counters; with `remove`, forgets
/// them on the agents (their files stay).
fn stop_captures(agents: &mut [Agent], captures: &mut [Capturing], remove: bool) {
    for c in captures.iter_mut() {
        let Some(id) = c.id else { continue };
        let client = &mut agents[c.agent].client;
        match client.capture_stop(id) {
            Ok(i) => {
                c.record.frames = i.frames;
                c.record.bytes = i.bytes;
                c.record.dropped = i.dropped;
                c.record.if_dropped = i.if_dropped;
                if let Some(e) = i.error {
                    c.record.error.get_or_insert(e);
                }
            }
            Err(e) => {
                c.record.error.get_or_insert(e.to_string());
            }
        }
        if remove {
            let _ = client.capture_remove(id);
        }
    }
}

/// Fetches each capture's pcap into `dir` as `AGENT-IFACE.pcap`.
fn collect_captures(agents: &mut [Agent], captures: &mut [Capturing], dir: &std::path::Path) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        for c in captures.iter_mut() {
            c.record
                .error
                .get_or_insert(format!("cannot make {}: {e}", dir.display()));
        }
        return;
    }
    for c in captures.iter_mut() {
        if c.record.error.is_some() {
            continue;
        }
        let name = std::path::Path::new(&c.record.file)
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        let local = dir.join(name);
        let got = agents[c.agent]
            .client
            .download(&c.record.file)
            .map_err(|e| e.to_string())
            .and_then(|data| {
                std::fs::write(&local, data)
                    .map_err(|e| format!("cannot write {}: {e}", local.display()))
            });
        match got {
            Ok(()) => c.record.collected = Some(local.display().to_string()),
            Err(e) => c.record.error = Some(e),
        }
    }
}

/// Merges the collected captures into one pcapng: one interface per
/// capture (named `AGENT:IFACE`), every frame's time moved from its agent's
/// clock to the controller's, in time order. Returns the frames written.
fn merge_captures(
    agents: &[Agent],
    captures: &[Capturing],
    out: &std::path::Path,
) -> std::result::Result<u64, String> {
    use ferotrx_core::{Capture, PcapngWriter};
    let mut inputs = Vec::new();
    for c in captures {
        let Some(path) = &c.record.collected else {
            continue;
        };
        let cap = Capture::from_path(path).map_err(|e| format!("{path}: {e}"))?;
        inputs.push((c, cap));
    }
    if inputs.is_empty() {
        return Err("no capture was fetched".into());
    }
    let file = std::fs::File::create(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let mut w = PcapngWriter::new(std::io::BufWriter::new(file), "FeroTRX fleet")
        .map_err(|e| e.to_string())?;
    // (time on the controller's clock in ns, input, packet)
    let mut all: Vec<(i128, usize, usize)> = Vec::new();
    for (i, (c, cap)) in inputs.iter().enumerate() {
        let name = format!("{}:{}", c.record.agent, c.record.iface);
        w.add_interface(cap.linktype, ferotrx_core::live::DEFAULT_SNAPLEN, &name)
            .map_err(|e| e.to_string())?;
        let offset_ns = (agents[c.agent].offset * 1e9) as i128;
        for (p, pkt) in cap.packets.iter().enumerate() {
            all.push((pkt.timestamp.as_nanos() as i128 - offset_ns, i, p));
        }
    }
    all.sort();
    for (t, i, p) in &all {
        let pkt = &inputs[*i].1.packets[*p];
        let frame = ferotrx_core::Frame {
            ts: Duration::from_nanos((*t).max(0) as u64),
            len: pkt.data.len() as u32,
            data: pkt.data.clone(),
        };
        w.write(*i as u32, &frame).map_err(|e| e.to_string())?;
    }
    w.flush().map_err(|e| e.to_string())?;
    Ok(all.len() as u64)
}

fn start_all(
    plan: &FleetPlan,
    options: &FleetOptions,
    agents: &mut [Agent],
    start_s: f64,
    started: &mut Vec<Started>,
) -> Result<()> {
    for (ri, run) in plan.runs.iter().enumerate() {
        let st = &run.settings;
        let duration = options.duration.or(st.duration).map(ms);
        let planned = start_s + run.delay.as_secs_f64();
        let dir = plan.deploy_dir.join(run.slug());
        for inst in &run.instances {
            let a = agent_index(agents, &inst.agent);
            let at = Some(planned + agents[a].offset);
            let dep = inst.deployment(&dir);
            let ctx =
                |e: String| failed(format!("starting '{}' on '{}': {e}", run.name, inst.agent));
            // A receiver on another agent goes first, at once.
            let rx = match (&st.rx_agent, &st.rx) {
                (Some(rx_agent), Some(iface)) if *rx_agent != inst.agent => {
                    let b = agent_index(agents, rx_agent);
                    let r = agents[b]
                        .client
                        .rx_start(&RxStartParams {
                            iface: iface.clone(),
                            duration: None,
                        })
                        .map_err(|e| ctx(format!("receiver on '{rx_agent}': {e}")))?;
                    Some((b, r.id))
                }
                _ => None,
            };
            let c = &mut agents[a].client;
            let id = match run.kind {
                CheckKind::Tcp => {
                    c.tcp_start(&TcpStartParams {
                        path: Some(dep.profile.clone()),
                        iface: inst.iface.clone(),
                        cps: st.cps,
                        connections: st.connections,
                        concurrency: st.concurrency,
                        duration: duration.clone(),
                        backend: st.backend.clone(),
                        queue: st.queue,
                        xdp_mode: st.xdp_mode.clone(),
                        workers: st.workers,
                        impair: st.impair.clone(),
                        impair_rx: st.impair_rx.clone(),
                        start_at: at,
                        ..Default::default()
                    })
                    .map_err(|e| ctx(e.to_string()))?
                    .id
                }
                CheckKind::Udp => {
                    let rate = st
                        .rate
                        .as_deref()
                        .map(str::parse::<f64>)
                        .transpose()
                        .map_err(|e| ctx(format!("rate: {e}")))?;
                    c.udp_start(&UdpStartParams {
                        path: Some(dep.profile.clone()),
                        iface: inst.iface.clone(),
                        rate,
                        transactions: st.transactions,
                        concurrency: st.concurrency,
                        duration: duration.clone(),
                        backend: st.backend.clone(),
                        queue: st.queue,
                        xdp_mode: st.xdp_mode.clone(),
                        workers: st.workers,
                        impair: st.impair.clone(),
                        impair_rx: st.impair_rx.clone(),
                        start_at: at,
                        ..Default::default()
                    })
                    .map_err(|e| ctx(e.to_string()))?
                    .id
                }
                _ => {
                    let name = profile_name(plan, run);
                    c.load_profile(&LoadProfileParams {
                        name: Some(name.clone()),
                        path: Some(dep.profile.clone()),
                        ..Default::default()
                    })
                    .map_err(|e| ctx(e.to_string()))?;
                    let own_rx = rx.is_none() && st.rx.is_some();
                    c.start(&StartParams {
                        profile: name,
                        output: OutputSpec {
                            iface: inst.iface.clone(),
                            backend: st.backend.clone(),
                            queue: st.queue,
                            xdp_mode: st.xdp_mode.clone(),
                            workers: st.workers,
                            ..Default::default()
                        },
                        rate: st.rate.clone(),
                        limit: st.limit,
                        duration: duration.clone(),
                        // Another agent can count only signed packets.
                        latency: st.latency || rx.is_some(),
                        rx: st.rx.clone().filter(|_| own_rx).map(|iface| RxSpec {
                            iface,
                            wait: st.rx_wait.clone(),
                        }),
                        impair: st.impair.clone(),
                        start_at: at,
                        ..Default::default()
                    })
                    .map_err(|e| ctx(e.to_string()))?
                    .id
                }
            };
            started.push(Started {
                run: ri,
                agent: a,
                kind: run.kind,
                id,
                rx,
                planned,
                last: None,
                rx_last: None,
                error: None,
            });
        }
    }
    Ok(())
}

/// Reads every run's counters (and its receiver's, on another agent).
fn poll(agents: &mut [Agent], started: &mut [Started]) {
    for s in started.iter_mut() {
        let c = &mut agents[s.agent].client;
        let got = match s.kind {
            CheckKind::Tcp => c.tcp_stats(s.id).map(|i| Last::Tcp(Box::new(i))),
            CheckKind::Udp => c.udp_stats(s.id).map(|i| Last::Udp(Box::new(i))),
            _ => c.stats(s.id).map(|i| Last::Traffic(Box::new(i))),
        };
        match got {
            Ok(l) => s.last = Some(l),
            Err(e) => s.error = Some(e.to_string()),
        }
        if let Some((b, id)) = s.rx {
            if let Ok(r) = agents[b].client.rx_stats(id) {
                s.rx_last = Some(r);
            }
        }
    }
}

fn stop_all(agents: &mut [Agent], started: &mut [Started]) {
    for s in started.iter_mut() {
        let c = &mut agents[s.agent].client;
        let got = match s.kind {
            CheckKind::Tcp => c.tcp_stop(s.id).map(|i| Last::Tcp(Box::new(i))),
            CheckKind::Udp => c.udp_stop(s.id).map(|i| Last::Udp(Box::new(i))),
            _ => c.stop(s.id).map(|i| Last::Traffic(Box::new(i))),
        };
        match got {
            Ok(l) => s.last = Some(l),
            Err(e) => {
                s.error.get_or_insert(e.to_string());
            }
        }
    }
}

/// Receivers on other agents get the run's `rx_wait` for frames on their
/// way, then stop.
fn finish_rx(plan: &FleetPlan, agents: &mut [Agent], started: &mut [Started]) {
    let wait = started
        .iter()
        .filter(|s| s.rx.is_some())
        .map(|s| {
            plan.runs[s.run]
                .settings
                .rx_wait
                .as_deref()
                .and_then(|w| ferotrx_core::parse_duration(w).ok())
                .unwrap_or(Duration::from_millis(500))
        })
        .max();
    let Some(wait) = wait else {
        return;
    };
    std::thread::sleep(wait);
    for s in started.iter_mut() {
        if let Some((b, id)) = s.rx {
            match agents[b].client.rx_stop(id) {
                Ok(r) => s.rx_last = Some(r),
                Err(e) => {
                    s.error.get_or_insert(format!("receiver: {e}"));
                }
            }
        }
    }
}

/// Forgets the runs on the agents, and unloads the traffic profiles.
fn remove_all(plan: &FleetPlan, agents: &mut [Agent], started: &[Started]) {
    for s in started {
        let c = &mut agents[s.agent].client;
        let _ = match s.kind {
            CheckKind::Tcp => c.tcp_remove(s.id).map(drop),
            CheckKind::Udp => c.udp_remove(s.id).map(drop),
            _ => c
                .remove(s.id)
                .map(drop)
                .and_then(|_| c.unload_profile(&profile_name(plan, &plan.runs[s.run]))),
        };
        if let Some((b, id)) = s.rx {
            let _ = agents[b].client.rx_remove(id);
        }
    }
}

/// The metrics of the runs in `which`, added up, by kind.
fn metrics_of<'a>(started: impl Iterator<Item = &'a Started>, kind: CheckKind) -> Option<Metrics> {
    let list: Vec<&Started> = started.filter(|s| s.kind == kind).collect();
    if list.is_empty() {
        return None;
    }
    Some(match kind {
        CheckKind::Tcp => {
            let infos: Vec<&TcpRunInfo> = list
                .iter()
                .filter_map(|s| match &s.last {
                    Some(Last::Tcp(i)) => Some(&**i),
                    _ => None,
                })
                .collect();
            tcp_metrics(&infos)
        }
        CheckKind::Udp => {
            let infos: Vec<&UdpRunInfo> = list
                .iter()
                .filter_map(|s| match &s.last {
                    Some(Last::Udp(i)) => Some(&**i),
                    _ => None,
                })
                .collect();
            udp_metrics(&infos)
        }
        _ => {
            let parts: Vec<TrafficPart> = list
                .iter()
                .filter_map(|s| match &s.last {
                    Some(Last::Traffic(i)) => Some(TrafficPart {
                        run: i,
                        rx: s.rx_last.as_ref().filter(|_| s.rx.is_some()),
                    }),
                    _ => None,
                })
                .collect();
            traffic_metrics(&parts)
        }
    })
}

const KINDS: [CheckKind; 3] = [CheckKind::Tcp, CheckKind::Udp, CheckKind::Traffic];

fn sample(plan: &FleetPlan, started: &[Started], start_s: f64) -> FleetSample {
    let now = unix_seconds(SystemTime::now());
    let mut totals = BTreeMap::new();
    for kind in KINDS {
        if let Some(m) = metrics_of(started.iter(), kind) {
            totals.insert(kind.as_str().to_string(), m);
        }
    }
    let _ = plan;
    FleetSample {
        t_s: now - start_s,
        running: started
            .iter()
            .filter(|s| s.last.as_ref().is_some_and(Last::running))
            .count(),
        runs: started.len(),
        totals,
    }
}

fn judge(conditions: &[ferotrx_core::scenario::Condition], m: &Metrics) -> Vec<ConditionResult> {
    conditions
        .iter()
        .map(|c| {
            let (actual, pass) = c.eval(m);
            ConditionResult {
                condition: c.text.clone(),
                metric: c.metric.clone(),
                actual,
                pass,
            }
        })
        .collect()
}

impl FleetReport {
    fn new(plan: &FleetPlan, agents: &[Agent], deployed: Vec<DeployRecord>) -> Self {
        FleetReport {
            format: FLEET_REPORT_FORMAT.into(),
            name: plan.name.clone(),
            description: plan.description.clone(),
            started_at: 0.0,
            elapsed_s: 0.0,
            passed: true,
            stopped: false,
            start_spread_ms: None,
            agents: agents.iter().map(Agent::record).collect(),
            deployed,
            runs: Vec::new(),
            totals: BTreeMap::new(),
            conditions: Vec::new(),
            samples: Vec::new(),
            notes: Vec::new(),
            captures: Vec::new(),
            merged: None,
        }
    }

    fn finish(&mut self, plan: &FleetPlan, agents: &[Agent], started: &[Started], stopped: bool) {
        self.stopped = stopped;
        let mut starts = Vec::new();
        for (ri, run) in plan.runs.iter().enumerate() {
            let mine: Vec<&Started> = started.iter().filter(|s| s.run == ri).collect();
            let instances: Vec<InstanceRecord> = mine
                .iter()
                .map(|s| {
                    let one = std::iter::once(*s);
                    let late = s
                        .last
                        .as_ref()
                        .and_then(Last::started_at)
                        .map(|t| (t - agents[s.agent].offset - s.planned) * 1000.0);
                    if let Some(l) = late {
                        starts.push(l);
                    }
                    let metrics = metrics_of(one, run.kind).unwrap_or_default();
                    InstanceRecord {
                        conditions: judge(&run.require_each, &metrics),
                        agent: agents[s.agent].spec.name.clone(),
                        id: s.id,
                        state: s.last.as_ref().map(Last::state),
                        error: s
                            .error
                            .clone()
                            .or_else(|| s.last.as_ref().and_then(Last::error)),
                        start_late_ms: late,
                        rx_agent: s.rx.map(|(b, _)| agents[b].spec.name.clone()),
                        metrics,
                        info: s.last.as_ref().map(Last::json),
                        rx: s
                            .rx_last
                            .as_ref()
                            .map(|r| serde_json::to_value(r).unwrap_or_default()),
                    }
                })
                .collect();
            let metrics = metrics_of(mine.iter().copied(), run.kind).unwrap_or_default();
            let conditions = judge(&run.require, &metrics);
            let ok = instances.iter().all(|i| {
                i.error.is_none()
                    && i.state != Some(RunState::Failed)
                    && i.conditions.iter().all(|c| c.pass)
            }) && conditions.iter().all(|c| c.pass);
            self.runs.push(RunRecord {
                name: run.name.clone(),
                kind: run.kind.as_str().into(),
                source: run.source.clone(),
                instances,
                metrics,
                conditions,
                passed: ok,
            });
        }
        for kind in KINDS {
            if let Some(m) = metrics_of(started.iter(), kind) {
                let conds: Vec<_> = plan
                    .require
                    .iter()
                    .filter(|(k, _)| *k == kind)
                    .map(|(_, c)| c.clone())
                    .collect();
                for mut r in judge(&conds, &m) {
                    r.condition = format!("{kind}: {}", r.condition);
                    self.conditions.push(r);
                }
                self.totals.insert(kind.as_str().into(), m);
            }
        }
        // Totals asked for a kind no run has fail.
        for (kind, c) in &plan.require {
            if !self.totals.contains_key(kind.as_str()) {
                self.conditions.push(ConditionResult {
                    condition: format!("{kind}: {}", c.text),
                    metric: c.metric.clone(),
                    actual: None,
                    pass: false,
                });
            }
        }
        if starts.len() > 1 {
            let lo = starts.iter().cloned().fold(f64::INFINITY, f64::min);
            let hi = starts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            self.start_spread_ms = Some(hi - lo);
        }
        self.passed = !stopped
            && self.runs.iter().all(|r| r.passed)
            && self.conditions.iter().all(|c| c.pass);
    }
}
