//! A controller for several agents: deploys a [`FleetPlan`]'s profiles to
//! the control servers it names, starts every run at one instant, reads
//! their counters as they go and adds them up.
//!
//! The runs start together by the wall clock: each start call carries a
//! `start_at`, the shared start in the agent's own clock. The controller
//! measures how far each agent's clock is from its own (the way NTP does,
//! from the round trip of `server.info`), so the agents need not have their
//! clocks in step for this; one-way latency between two agents does.
//!
//! The controller talks to the agents in parallel, one thread each. Before
//! anything is deployed it checks that the plan fits every agent (kinds of
//! runs, backends, interfaces, CPUs, limits). Once per interval it reads
//! every agent's health (CPU, memory, clock) with its runs' counters. When
//! an agent's control connection breaks, the controller connects again
//! (its runs go on there meanwhile); an agent that does not come back
//! within the plan's `reconnect` is lost, and the report says which runs it
//! had and how old their counters are.

mod capture;
mod metrics;
mod report;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use ferotrx_core::fleet::{AgentSpec, FleetKind, FleetPlan, FleetRun, OnAgentLoss};
use ferotrx_core::scenario::{ConditionResult, Metrics};
use ferotrx_core::{unix_seconds, DropCounters, Error, Result};

use crate::protocol::*;
use crate::{Client, ClientError, ClientTls};

use capture::{collect_captures, merge_captures, start_captures, stop_captures};

pub use metrics::{
    bench_metrics, hosts_metrics, merge_latency, scenario_metrics, tcp_metrics, traffic_metrics,
    udp_metrics, y1564_metrics, TrafficPart,
};
pub use report::{
    AgentFailure, AgentRecord, AgentSample, AgentTelemetry, CaptureRecord, DeployRecord,
    FleetReport, FleetSample, InstanceRecord, RunRecord, FLEET_REPORT_FORMAT,
};

/// Longest a call to an agent may take while deploying and starting.
const CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// Longest a call may take while the runs go: a slower agent counts as
/// unreachable, and the controller connects again.
const FOLLOW_TIMEOUT: Duration = Duration::from_secs(5);

/// Longest the controller waits for an agent to accept a connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// After the last run should have ended, how long the controller waits
/// for it before stopping it.
const GRACE: Duration = Duration::from_secs(10);

/// An agent whose CPUs are busier than this before the start gets a note:
/// its results may suffer from whatever else runs there.
const BUSY_PCT: f64 = 80.0;

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
    /// An agent's control connection broke; the controller tries again.
    AgentDown { agent: &'a str, error: &'a str },
    /// The controller reached the agent again, after this many seconds.
    AgentBack { agent: &'a str, after_s: f64 },
    /// The agent did not come back in time.
    AgentLost(&'a AgentFailure),
    /// Something worth knowing that does not stop the run.
    Note(&'a str),
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
    /// What it can run (`None`: an agent older than 0.51.0).
    pub caps: Option<Capabilities>,
    /// Its health when the controller connected (`None`: older agent).
    pub health: Option<Health>,
}

impl Agent {
    /// Connects, logs in, reads the agent's clock, capabilities and health.
    pub fn connect(spec: &AgentSpec) -> std::result::Result<Agent, String> {
        let at = &spec.address;
        let mut client = match &spec.tls {
            None => Client::connect_timeout(at, CONNECT_TIMEOUT)
                .map_err(|e| format!("cannot connect to {at}: {e}"))?,
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
                Client::connect_tls_within(at, &tls, Some(CONNECT_TIMEOUT))
                    .map_err(|e| format!("cannot connect to {at}: {e}"))?
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
        // Agents before 0.51.0 know neither call: they answer "no such method".
        let caps = optional(client.capabilities())?;
        let health = optional(client.health())?;
        Ok(Agent {
            spec: spec.clone(),
            client,
            info,
            offset,
            rtt,
            caps,
            health,
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
            capabilities: self.caps.clone(),
            status: "ok".into(),
            reconnects: 0,
            telemetry: None,
            failure: None,
        }
    }
}

/// The answer of a call older agents may not know: `None` for an RPC
/// error, an error for a broken connection.
fn optional<T>(r: std::result::Result<T, ClientError>) -> std::result::Result<Option<T>, String> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(ClientError::Rpc(_)) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// True when an error means the control connection is gone (or too slow
/// to trust), rather than an answer from the agent.
fn broken(e: &ClientError) -> bool {
    !matches!(e, ClientError::Rpc(_))
}

/// Runs `f` for every item at once, one thread each, and returns the
/// results in order.
fn each<A: Send, T: Send>(items: &mut [A], f: impl Fn(usize, &mut A) -> T + Sync) -> Vec<T> {
    if items.len() <= 1 {
        return items.iter_mut().enumerate().map(|(i, a)| f(i, a)).collect();
    }
    std::thread::scope(|scope| {
        let f = &f;
        let handles: Vec<_> = items
            .iter_mut()
            .enumerate()
            .map(|(i, a)| scope.spawn(move || f(i, a)))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)))
            .collect()
    })
}

/// One run on one agent, once started.
struct Started {
    run: usize,
    agent: usize,
    kind: FleetKind,
    id: u64,
    /// The receiver on another agent: (agent, rx id).
    rx: Option<(usize, u64)>,
    /// When it should start, by the controller's clock.
    planned: f64,
    last: Option<Last>,
    rx_last: Option<RxRunInfo>,
    error: Option<String>,
}

impl Started {
    fn running(&self) -> bool {
        self.last.as_ref().is_some_and(Last::running)
    }
}

/// The latest counters of a run.
#[derive(Clone, Debug)]
enum Last {
    Traffic(Box<RunInfo>),
    Tcp(Box<TcpRunInfo>),
    Udp(Box<UdpRunInfo>),
    Hosts(Box<HostRunInfo>),
    Scenario(Box<ScenarioRunInfo>),
    Bench(Box<BenchRunInfo>),
    Y1564(Box<Y1564RunInfo>),
}

impl Last {
    fn state(&self) -> RunState {
        match self {
            Last::Traffic(i) => i.state,
            Last::Tcp(i) => i.state,
            Last::Udp(i) => i.state,
            Last::Hosts(i) => i.state,
            Last::Scenario(i) => i.state,
            Last::Bench(i) => i.state,
            Last::Y1564(i) => i.state,
        }
    }

    fn running(&self) -> bool {
        self.state().is_running()
    }

    fn error(&self) -> Option<String> {
        match self {
            Last::Traffic(i) => i.error.clone(),
            Last::Tcp(i) => i.error.clone(),
            Last::Udp(i) => i.error.clone(),
            Last::Hosts(i) => i.error.clone(),
            Last::Scenario(i) => i.error.clone(),
            Last::Bench(i) => i.error.clone(),
            Last::Y1564(i) => i.error.clone(),
        }
    }

    fn started_at(&self) -> Option<f64> {
        match self {
            Last::Traffic(i) => i.started_at,
            Last::Tcp(i) => i.started_at,
            Last::Udp(i) => i.started_at,
            Last::Hosts(i) => i.started_at,
            Last::Scenario(i) => i.started_at,
            Last::Bench(i) => i.started_at,
            Last::Y1564(i) => i.started_at,
        }
    }

    /// Frames dropped before they were read or sent, by layer.
    fn drops(&self) -> DropCounters {
        match self {
            Last::Traffic(i) => i.drops,
            Last::Tcp(i) => i.drops,
            Last::Udp(i) => i.drops,
            _ => DropCounters::default(),
        }
    }

    fn json(&self) -> serde_json::Value {
        match self {
            Last::Traffic(i) => serde_json::to_value(i),
            Last::Tcp(i) => serde_json::to_value(i),
            Last::Udp(i) => serde_json::to_value(i),
            Last::Hosts(i) => serde_json::to_value(i),
            Last::Scenario(i) => serde_json::to_value(i),
            Last::Bench(i) => serde_json::to_value(i),
            Last::Y1564(i) => serde_json::to_value(i),
        }
        .unwrap_or_default()
    }
}

fn failed(what: String) -> Error {
    Error::Profile(what)
}

/// Connects to every agent of the plan, all at once.
pub fn connect_all(plan: &FleetPlan, progress: &mut dyn FnMut(&FleetEvent)) -> Result<Vec<Agent>> {
    let mut specs: Vec<AgentSpec> = plan.agents.clone();
    let got = each(&mut specs, |_, spec| Agent::connect(spec));
    let mut agents = Vec::new();
    let mut errors = Vec::new();
    for (spec, r) in plan.agents.iter().zip(got) {
        match r {
            Ok(a) => {
                progress(&FleetEvent::Agent(&a.record()));
                agents.push(a);
            }
            Err(e) => errors.push(format!("agent '{}': {e}", spec.name)),
        }
    }
    if !errors.is_empty() {
        return Err(failed(errors.join("; ")));
    }
    Ok(agents)
}

/// Sends every run's profile and files to its agents, every agent at once;
/// files an agent has already (by SHA-256) are not sent again.
pub fn deploy(
    plan: &FleetPlan,
    agents: &mut [Agent],
    progress: &mut dyn FnMut(&FleetEvent),
) -> Result<Vec<DeployRecord>> {
    let got = each(agents, |_, agent| deploy_to(plan, agent));
    let mut out = Vec::new();
    let mut errors = Vec::new();
    for r in got {
        match r {
            Ok(recs) => out.extend(recs),
            Err(e) => errors.push(e),
        }
    }
    if !errors.is_empty() {
        return Err(failed(errors.join("; ")));
    }
    // In the plan's order, whichever agent finished first.
    let order = |d: &DeployRecord| {
        let r = plan.runs.iter().position(|r| r.name == d.run);
        let a = plan.agents.iter().position(|a| a.name == d.agent);
        (r, a)
    };
    out.sort_by_key(order);
    for rec in &out {
        progress(&FleetEvent::Deployed(rec));
    }
    Ok(out)
}

/// One agent's part of [`deploy`].
fn deploy_to(
    plan: &FleetPlan,
    agent: &mut Agent,
) -> std::result::Result<Vec<DeployRecord>, String> {
    let mut out = Vec::new();
    for run in &plan.runs {
        let dir = plan.deploy_dir.join(run.slug());
        for inst in run.instances.iter().filter(|i| i.agent == agent.spec.name) {
            let dep = inst.deployment(&dir);
            let mut rec = DeployRecord {
                run: run.name.clone(),
                agent: inst.agent.clone(),
                profile: dep.profile.display().to_string(),
                files_sent: 0,
                files_kept: 0,
                bytes_sent: 0,
            };
            let ctx = |e: String| format!("deploying '{}' to '{}': {e}", run.name, inst.agent);
            for (local, remote) in &dep.files {
                let data = std::fs::read(local)
                    .map_err(|e| ctx(format!("cannot read {}: {e}", local.display())))?;
                if agent
                    .client
                    .upload(remote, &data)
                    .map_err(|e| ctx(e.to_string()))?
                {
                    rec.files_sent += 1;
                    rec.bytes_sent += data.len() as u64;
                } else {
                    rec.files_kept += 1;
                }
            }
            agent
                .client
                .upload(&dep.profile, inst.text.as_bytes())
                .map_err(|e| ctx(e.to_string()))?;
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

/// Whether the controller can reach an agent.
#[derive(Clone, Debug)]
enum Link {
    Up,
    /// The connection broke at `since` (seconds from the shared start).
    Down {
        since: Instant,
        since_s: f64,
        error: String,
    },
    Lost,
}

/// An agent during a run, with what the controller learned about it.
struct Slot {
    agent: Agent,
    link: Link,
    reconnects: u32,
    /// The agent answers `server.health`.
    health: bool,
    /// Seconds from the shared start of its last answer.
    last_seen_s: Option<f64>,
    tele: AgentTelemetry,
    cpu_sum: f64,
    cpu_n: u32,
    failure: Option<AgentFailure>,
    /// Its latest reading, for the samples.
    reading: Option<AgentSample>,
}

impl Slot {
    fn new(agent: Agent) -> Self {
        Slot {
            health: agent.health.is_some(),
            agent,
            link: Link::Up,
            reconnects: 0,
            last_seen_s: None,
            tele: AgentTelemetry::default(),
            cpu_sum: 0.0,
            cpu_n: 0,
            failure: None,
            reading: None,
        }
    }

    fn up(&self) -> bool {
        matches!(self.link, Link::Up)
    }

    fn lost(&self) -> bool {
        matches!(self.link, Link::Lost)
    }

    fn name(&self) -> &str {
        &self.agent.spec.name
    }

    /// Notes a reading of `server.health` taken over a round trip `rtt`.
    fn read_health(&mut self, h: &Health, t0: f64, t1: f64) {
        let offset_ms = (h.time - (t0 + t1) / 2.0) * 1000.0;
        let rtt_ms = (t1 - t0) * 1000.0;
        let t = &mut self.tele;
        t.samples += 1;
        let lo = |a: Option<f64>, b: f64| Some(a.map_or(b, |a: f64| a.min(b)));
        let hi = |a: Option<f64>, b: f64| Some(a.map_or(b, |a: f64| a.max(b)));
        if let Some(c) = h.cpu_pct {
            t.cpu_max_pct = hi(t.cpu_max_pct, c);
            self.cpu_sum += c;
            self.cpu_n += 1;
            t.cpu_avg_pct = Some(self.cpu_sum / self.cpu_n as f64);
        }
        if let Some(c) = h.process_cpu_pct {
            t.process_cpu_max_pct = hi(t.process_cpu_max_pct, c);
        }
        if let Some(m) = h.memory_available_mb {
            t.memory_min_mb = Some(t.memory_min_mb.map_or(m, |x| x.min(m)));
        }
        t.offset_min_ms = lo(t.offset_min_ms, offset_ms);
        t.offset_max_ms = hi(t.offset_max_ms, offset_ms);
        t.rtt_max_ms = hi(t.rtt_max_ms, rtt_ms);
        self.reading = Some(AgentSample {
            agent: self.agent.spec.name.clone(),
            status: "up".into(),
            cpu_pct: h.cpu_pct,
            process_cpu_pct: h.process_cpu_pct,
            memory_available_mb: h.memory_available_mb,
            offset_ms: Some(offset_ms),
            rtt_ms: Some(rtt_ms),
            running: Some(h.running),
            drops: DropCounters::default(),
        });
    }
}

/// What the controller asks one agent each interval.
#[derive(Clone, Copy)]
enum Task {
    /// A run's counters: (index in `started`, kind, id).
    Run(usize, FleetKind, u64),
    /// A receiver's counters for the run at that index.
    Rx(usize, u64),
}

/// What one agent answered in an interval.
#[derive(Default)]
struct Answers {
    runs: Vec<(usize, std::result::Result<Last, String>)>,
    rx: Vec<(usize, RxRunInfo)>,
    /// The connection broke now: why.
    broke: Option<String>,
    /// The agent came back after this many seconds.
    back: Option<f64>,
    /// It is now lost.
    lost: bool,
}

/// Reads one run's counters.
fn stats(c: &mut Client, kind: FleetKind, id: u64) -> std::result::Result<Last, ClientError> {
    Ok(match kind {
        FleetKind::Tcp => Last::Tcp(Box::new(c.tcp_stats(id)?)),
        FleetKind::Udp => Last::Udp(Box::new(c.udp_stats(id)?)),
        FleetKind::Traffic => Last::Traffic(Box::new(c.stats(id)?)),
        FleetKind::Hosts => Last::Hosts(Box::new(c.host_stats(id)?)),
        FleetKind::Scenario => Last::Scenario(Box::new(c.scenario_get(id)?)),
        FleetKind::Bench => Last::Bench(Box::new(c.bench_get(id)?)),
        FleetKind::Y1564 => Last::Y1564(Box::new(c.y1564_get(id)?)),
    })
}

/// Stops one run and waits for it to end.
fn stop_one(c: &mut Client, kind: FleetKind, id: u64) -> std::result::Result<Last, ClientError> {
    Ok(match kind {
        FleetKind::Tcp => Last::Tcp(Box::new(c.tcp_stop(id)?)),
        FleetKind::Udp => Last::Udp(Box::new(c.udp_stop(id)?)),
        FleetKind::Traffic => Last::Traffic(Box::new(c.stop(id)?)),
        FleetKind::Hosts => Last::Hosts(Box::new(c.host_stop(id)?)),
        FleetKind::Scenario => Last::Scenario(Box::new(c.scenario_stop(id)?)),
        FleetKind::Bench => Last::Bench(Box::new(c.bench_stop(id)?)),
        FleetKind::Y1564 => Last::Y1564(Box::new(c.y1564_stop(id)?)),
    })
}

/// One interval with one agent: reconnects when it is down, reads its
/// health and its runs' counters when it is up.
fn follow(slot: &mut Slot, tasks: &[Task], plan: &FleetPlan, start_s: f64) -> Answers {
    let mut out = Answers::default();
    let now_s = || unix_seconds(SystemTime::now()) - start_s;
    match slot.link.clone() {
        Link::Lost => return out,
        Link::Down {
            since,
            since_s,
            error,
        } => match Agent::connect(&slot.agent.spec) {
            Ok(a) => {
                slot.agent = a;
                slot.link = Link::Up;
                slot.reconnects += 1;
                out.back = Some(now_s() - since_s);
            }
            Err(e) => {
                if since.elapsed() >= plan.reconnect {
                    slot.link = Link::Lost;
                    out.lost = true;
                    slot.failure = Some(AgentFailure {
                        agent: slot.name().to_string(),
                        at_s: since_s,
                        lost_at_s: now_s(),
                        error: format!("{error}; then: {e}"),
                        last_seen_s: slot.last_seen_s,
                        runs: Vec::new(),
                    });
                }
                return out;
            }
        },
        Link::Up => {}
    }
    let _ = slot.agent.client.set_timeout(Some(FOLLOW_TIMEOUT));
    let broke = |slot: &mut Slot, e: &ClientError| {
        slot.link = Link::Down {
            since: Instant::now(),
            since_s: now_s(),
            error: e.to_string(),
        };
        slot.reading = None;
        Some(e.to_string())
    };
    if plan.telemetry && slot.health {
        let t0 = unix_seconds(SystemTime::now());
        match slot.agent.client.health() {
            Ok(h) => {
                let t1 = unix_seconds(SystemTime::now());
                slot.read_health(&h, t0, t1);
            }
            Err(ClientError::Rpc(_)) => slot.health = false,
            Err(e) => {
                out.broke = broke(slot, &e);
                return out;
            }
        }
    }
    for t in tasks {
        let c = &mut slot.agent.client;
        match *t {
            Task::Run(si, kind, id) => match stats(c, kind, id) {
                Ok(l) => out.runs.push((si, Ok(l))),
                Err(e) if broken(&e) => {
                    out.broke = broke(slot, &e);
                    return out;
                }
                Err(e) => out.runs.push((si, Err(e.to_string()))),
            },
            Task::Rx(si, id) => match c.rx_stats(id) {
                Ok(r) => out.rx.push((si, r)),
                Err(e) if broken(&e) => {
                    out.broke = broke(slot, &e);
                    return out;
                }
                Err(_) => {}
            },
        }
    }
    slot.last_seen_s = Some(now_s());
    out
}

/// What the controller found about whether a plan fits its agents.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Fit {
    /// What an agent cannot do: the plan does not start.
    pub problems: Vec<String>,
    /// What may go wrong, or make results less sure.
    pub warnings: Vec<String>,
    /// Interfaces the plan names that an agent does not list. A run may
    /// still open them (a name the system takes but does not list), so
    /// `run_fleet` only warns; `ferotrx fleet check` fails on them.
    pub missing_interfaces: Vec<String>,
}

/// Checks the plan against what each agent says it can run
/// (`server.capabilities`): the kinds of runs, the backends, the
/// interfaces, the CPUs the workers need, and the agent's limits
/// ([`check_limits`]). Agents before 0.51.0 say nothing, so only their
/// version and backends are checked.
pub fn check_fit(plan: &FleetPlan, options: &FleetOptions, agents: &[Agent]) -> Fit {
    let mut fit = Fit::default();
    if let Err(e) = check_limits(plan, options, agents) {
        fit.problems.push(e.to_string());
    }
    for a in agents {
        let name = &a.spec.name;
        let caps = a.caps.as_ref();
        let mut workers = 0usize;
        let mut ifaces: Vec<(&str, &str)> = Vec::new();
        for run in &plan.runs {
            let st = &run.settings;
            if st.rx_agent.as_deref() == Some(name.as_str()) {
                if let Some(rx) = &st.rx {
                    ifaces.push((rx, &run.name));
                }
            }
            for inst in run.instances.iter().filter(|i| i.agent == *name) {
                match caps {
                    Some(c) if !c.kinds.iter().any(|k| k == run.kind.as_str()) => {
                        fit.problems.push(format!(
                            "'{}' on '{name}': the agent cannot run {} runs",
                            run.name, run.kind
                        ))
                    }
                    None if run.kind.since() != "0.31.0" => fit.problems.push(format!(
                        "'{}' on '{name}': {} runs in a fleet need an agent from {}; it runs {}",
                        run.name,
                        run.kind,
                        run.kind.since(),
                        a.info.version
                    )),
                    _ => {}
                }
                if let Some(b) = &st.backend {
                    if !a.info.backends.iter().any(|x| x == b) {
                        fit.problems.push(format!(
                            "'{}' on '{name}': backend {b}, and the agent has {}",
                            run.name,
                            if a.info.backends.is_empty() {
                                "none".to_string()
                            } else {
                                a.info.backends.join(", ")
                            }
                        ));
                    }
                }
                if let Some(i) = &inst.iface {
                    ifaces.push((i, &run.name));
                }
                if st.rx_agent.is_none() {
                    if let Some(rx) = &st.rx {
                        ifaces.push((rx, &run.name));
                    }
                }
                workers += st.workers.unwrap_or(1).max(1) as usize;
            }
        }
        let Some(c) = caps else { continue };
        if !c.interfaces.is_empty() {
            for (i, run) in ifaces {
                if !c.interfaces.iter().any(|x| x == i) {
                    fit.missing_interfaces.push(format!(
                        "'{run}' on '{name}': the agent has no interface {i}"
                    ));
                }
            }
        }
        if workers > c.cpus {
            fit.warnings.push(format!(
                "'{name}' runs {workers} worker(s) at once on {} CPU(s): they share cores, \
                 and rates may suffer",
                c.cpus
            ));
        }
        if let Some(cpu) = a.health.as_ref().and_then(|h| h.cpu_pct) {
            if cpu > BUSY_PCT {
                fit.warnings.push(format!(
                    "'{name}' is busy before the start ({cpu:.0}% CPU): results may suffer"
                ));
            }
        }
        if let Some(h) = &a.health {
            if h.running > 0 {
                fit.warnings
                    .push(format!("'{name}' already has {} run(s) going", h.running));
            }
        }
    }
    fit.problems.dedup();
    fit
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
    let fit = check_fit(plan, options, &agents);
    if !fit.problems.is_empty() {
        return Err(failed(format!(
            "the plan does not fit its agents: {}",
            fit.problems.join("; ")
        )));
    }
    for w in fit.warnings.iter().chain(&fit.missing_interfaces) {
        progress(&FleetEvent::Note(w));
    }
    let deployed = deploy(plan, &mut agents, progress)?;
    let mut report = FleetReport::new(plan, &agents, deployed);
    report.notes.extend(fit.warnings.iter().cloned());
    report.notes.extend(fit.missing_interfaces.iter().cloned());
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
        let mut slots: Vec<Slot> = agents.into_iter().map(Slot::new).collect();
        stop_all(&mut slots, &mut started);
        remove_all(plan, &mut slots, &started);
        stop_captures(&mut slots, &mut captures, true);
        return Err(e);
    }
    let late = unix_seconds(SystemTime::now()) - start_s;
    if late > 0.0 {
        report.notes.push(format!(
            "the start calls took {:.0} ms longer than start_delay: the runs started as they were told, late",
            late * 1000.0
        ));
    }
    let mut slots: Vec<Slot> = agents.into_iter().map(Slot::new).collect();

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
        poll(
            plan,
            &mut slots,
            &mut started,
            start_s,
            &mut report,
            progress,
        );
        let sample = sample(&slots, &started, start_s);
        progress(&FleetEvent::Sample(&sample));
        report.samples.push(sample);
        let waiting = SystemTime::now() < start;
        // A lost agent's runs no longer count; a down one's may still go.
        let going = started.iter().any(|s| {
            let here = !slots[s.agent].lost();
            here && (s.running() || (s.last.is_none() && !slots[s.agent].up()))
        });
        if !waiting && !going {
            break;
        }
        if stop.load(Ordering::Relaxed) {
            stopped = true;
            break;
        }
        if plan.on_agent_loss == OnAgentLoss::Stop && slots.iter().any(Slot::lost) {
            report
                .notes
                .push("an agent was lost: every run was stopped (on_agent_loss = \"stop\")".into());
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
    for s in &mut slots {
        let _ = s.agent.client.set_timeout(Some(CALL_TIMEOUT));
    }
    stop_all(&mut slots, &mut started);
    finish_rx(plan, &mut slots, &mut started);
    report.finish(plan, &slots, &started, stopped);
    if !options.keep {
        remove_all(plan, &mut slots, &started);
    }
    stop_captures(&mut slots, &mut captures, !options.keep);
    if let Some(dir) = &options.collect {
        collect_captures(&mut slots, &mut captures, dir);
        if let Some(out) = &options.merge {
            match merge_captures(&slots, &captures, out) {
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

/// Checks what the plan starts on each agent against the limits the agent
/// reports (`server.info`, servers from 0.42.0), so that a plan an agent
/// would refuse fails before anything is deployed or started. The agents
/// check again at each start, also what is in the profiles.
pub fn check_limits(plan: &FleetPlan, options: &FleetOptions, agents: &[Agent]) -> Result<()> {
    for a in agents {
        let Some(l) = a.info.limits.as_ref().map(|l| &l.limits) else {
            continue;
        };
        let name = &a.spec.name;
        let mut runs = 0usize;
        for run in &plan.runs {
            let st = &run.settings;
            let ctx = |e: RpcError| {
                failed(format!(
                    "'{}' on '{name}': {} (a limit of that agent)",
                    run.name, e.message
                ))
            };
            // A receiver this agent runs for a run elsewhere.
            if st.rx_agent.as_deref() == Some(name.as_str()) {
                if let Some(rx) = &st.rx {
                    l.check_iface(rx).map_err(ctx)?;
                }
            }
            for inst in run.instances.iter().filter(|i| i.agent == *name) {
                runs += 1;
                if let Some(i) = &inst.iface {
                    l.check_iface(i).map_err(ctx)?;
                }
                if let (Some(rx), None) = (&st.rx, &st.rx_agent) {
                    l.check_iface(rx).map_err(ctx)?;
                }
                if !run.kind.runs_to_the_end() {
                    l.check_duration(options.duration.or(st.duration))
                        .map_err(ctx)?;
                }
                match run.kind {
                    FleetKind::Tcp => {
                        if st.cps.is_some() || st.concurrency.is_some() {
                            l.check_flows(
                                st.cps.unwrap_or(0.0),
                                st.concurrency.unwrap_or(0),
                                "the run (connections)",
                            )
                            .map_err(ctx)?;
                        }
                    }
                    FleetKind::Udp => {
                        let rate = st.rate.as_deref().and_then(|r| r.parse::<f64>().ok());
                        if rate.is_some() || st.concurrency.is_some() {
                            l.check_flows(
                                rate.unwrap_or(0.0),
                                st.concurrency.unwrap_or(0),
                                "the run (transactions)",
                            )
                            .map_err(ctx)?;
                        }
                    }
                    FleetKind::Traffic => {
                        if let Some(rate) = st.rate.as_deref().and_then(|r| r.parse().ok()) {
                            let mut d = crate::Demand::default();
                            d.add(rate);
                            l.check_demand(d, "the run").map_err(ctx)?;
                        }
                    }
                    _ => {}
                }
            }
        }
        if let Some(max) = l.max_runs.filter(|&m| runs > m) {
            return Err(failed(format!(
                "the plan starts {runs} runs on '{name}' at once, and that agent runs at most \
                 {max} (--max-runs)"
            )));
        }
    }
    Ok(())
}

/// One run's part to start on one agent.
struct Part<'a> {
    run: usize,
    spec: &'a FleetRun,
    inst: &'a ferotrx_core::fleet::FleetInstance,
    rx: Option<(usize, u64)>,
    planned: f64,
}

fn start_all(
    plan: &FleetPlan,
    options: &FleetOptions,
    agents: &mut [Agent],
    start_s: f64,
    started: &mut Vec<Started>,
) -> Result<()> {
    // Receivers on other agents go first, at once: (agent, run, instance).
    let mut wants_rx: Vec<Vec<(usize, usize, String)>> = vec![Vec::new(); agents.len()];
    for (ri, run) in plan.runs.iter().enumerate() {
        let st = &run.settings;
        if let (Some(rx_agent), Some(iface)) = (&st.rx_agent, &st.rx) {
            let b = agent_index(agents, rx_agent);
            for (ii, inst) in run.instances.iter().enumerate() {
                if inst.agent != *rx_agent {
                    wants_rx[b].push((ri, ii, iface.clone()));
                }
            }
        }
    }
    let got = each(agents, |b, agent| {
        let mut out = Vec::new();
        for (ri, ii, iface) in &wants_rx[b] {
            let r = agent
                .client
                .rx_start(&RxStartParams {
                    iface: iface.clone(),
                    duration: None,
                })
                .map(|r| r.id)
                .map_err(|e| {
                    format!(
                        "starting '{}': receiver on '{}': {e}",
                        plan.runs[*ri].name, agent.spec.name
                    )
                });
            out.push(((*ri, *ii), r));
        }
        out
    });
    let mut receivers: BTreeMap<(usize, usize), (usize, u64)> = BTreeMap::new();
    let mut errors = Vec::new();
    for (b, list) in got.into_iter().enumerate() {
        for (key, r) in list {
            match r {
                Ok(id) => {
                    receivers.insert(key, (b, id));
                }
                Err(e) => errors.push(e),
            }
        }
    }
    if !errors.is_empty() {
        // No run started: only the receivers to remove.
        remove_receivers(agents, &receivers);
        return Err(failed(errors.join("; ")));
    }

    // Then every agent starts its parts, all agents at once.
    let mut parts: Vec<Vec<Part>> = (0..agents.len()).map(|_| Vec::new()).collect();
    for (ri, run) in plan.runs.iter().enumerate() {
        for (ii, inst) in run.instances.iter().enumerate() {
            let a = agent_index(agents, &inst.agent);
            parts[a].push(Part {
                run: ri,
                spec: run,
                inst,
                rx: receivers.get(&(ri, ii)).copied(),
                planned: start_s + run.delay.as_secs_f64(),
            });
        }
    }
    let got = each(agents, |a, agent| {
        parts[a]
            .iter()
            .map(|p| {
                start_one(plan, options, agent, p).map(|id| Started {
                    run: p.run,
                    agent: a,
                    kind: p.spec.kind,
                    id,
                    rx: p.rx,
                    planned: p.planned,
                    last: None,
                    rx_last: None,
                    error: None,
                })
            })
            .collect::<Vec<_>>()
    });
    let mut errors = Vec::new();
    for list in got {
        for r in list {
            match r {
                Ok(s) => started.push(s),
                Err(e) => errors.push(e),
            }
        }
    }
    // Receivers whose sender did not start.
    let orphans: BTreeMap<(usize, usize), (usize, u64)> = receivers
        .iter()
        .filter(|(_, rx)| !started.iter().any(|s| s.rx == Some(**rx)))
        .map(|(k, v)| (*k, *v))
        .collect();
    remove_receivers(agents, &orphans);
    started.sort_by_key(|s| (s.run, s.agent));
    if errors.is_empty() {
        Ok(())
    } else {
        Err(failed(errors.join("; ")))
    }
}

fn remove_receivers(agents: &mut [Agent], receivers: &BTreeMap<(usize, usize), (usize, u64)>) {
    for &(b, id) in receivers.values() {
        let c = &mut agents[b].client;
        let _ = c.rx_stop(id);
        let _ = c.rx_remove(id);
    }
}

/// Starts one run's part on its agent; returns its id there.
fn start_one(
    plan: &FleetPlan,
    options: &FleetOptions,
    agent: &mut Agent,
    p: &Part,
) -> std::result::Result<u64, String> {
    let run = p.spec;
    let inst = p.inst;
    let st = &run.settings;
    let duration = options
        .duration
        .filter(|_| !run.kind.runs_to_the_end())
        .or(st.duration)
        .map(ms);
    let at = Some(p.planned + agent.offset);
    let dep = inst.deployment(&plan.deploy_dir.join(run.slug()));
    let ctx = |e: String| format!("starting '{}' on '{}': {e}", run.name, inst.agent);
    let c = &mut agent.client;
    let id = match run.kind {
        FleetKind::Tcp => {
            c.tcp_start(&TcpStartParams {
                path: Some(dep.profile.clone()),
                iface: inst.iface.clone(),
                cps: st.cps,
                connections: st.connections,
                concurrency: st.concurrency,
                duration,
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
        FleetKind::Udp => {
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
                duration,
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
        FleetKind::Traffic => {
            let name = profile_name(plan, run);
            c.load_profile(&LoadProfileParams {
                name: Some(name.clone()),
                path: Some(dep.profile.clone()),
                ..Default::default()
            })
            .map_err(|e| ctx(e.to_string()))?;
            let own_rx = p.rx.is_none() && st.rx.is_some();
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
                duration,
                // Another agent can count only signed packets.
                latency: st.latency || p.rx.is_some(),
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
        FleetKind::Hosts => {
            c.host_start(&HostStartParams {
                path: Some(dep.profile.clone()),
                iface: inst.iface.clone(),
                duration,
                backend: st.backend.clone(),
                queue: st.queue,
                xdp_mode: st.xdp_mode.clone(),
                impair: st.impair.clone(),
                impair_rx: st.impair_rx.clone(),
                until_ready: st.until_ready,
                start_at: at,
                ..Default::default()
            })
            .map_err(|e| ctx(e.to_string()))?
            .id
        }
        FleetKind::Scenario => {
            c.scenario_start(&ScenarioStartParams {
                path: Some(dep.profile.clone()),
                iface: inst.iface.clone(),
                only: st.only.clone(),
                lab: st.lab,
                start_at: at,
                ..Default::default()
            })
            .map_err(|e| ctx(e.to_string()))?
            .id
        }
        FleetKind::Bench => {
            let iface = inst.iface.clone().unwrap_or_default();
            c.bench_start(&BenchStartParams {
                path: Some(dep.profile.clone()),
                rx: st.rx.clone().unwrap_or_else(|| iface.clone()),
                iface,
                backend: st.backend.clone(),
                queue: st.queue,
                xdp_mode: st.xdp_mode.clone(),
                workers: st.workers,
                tests: st.tests.clone(),
                sizes: st.sizes.clone(),
                line_rate: st.line_rate.clone(),
                start_at: at,
                ..Default::default()
            })
            .map_err(|e| ctx(e.to_string()))?
            .id
        }
        FleetKind::Y1564 => {
            let iface = inst.iface.clone().unwrap_or_default();
            c.y1564_start(&Y1564StartParams {
                path: Some(dep.profile.clone()),
                rx: st.rx.clone().unwrap_or_else(|| iface.clone()),
                iface,
                backend: st.backend.clone(),
                queue: st.queue,
                xdp_mode: st.xdp_mode.clone(),
                workers: st.workers,
                tests: st.tests.clone(),
                services: st.services.clone(),
                line_rate: st.line_rate.clone(),
                start_at: at,
                ..Default::default()
            })
            .map_err(|e| ctx(e.to_string()))?
            .id
        }
    };
    Ok(id)
}

/// Reads every agent's health and runs' counters, all agents at once;
/// reconnects to agents whose connection broke, and gives up on those
/// that do not come back.
fn poll(
    plan: &FleetPlan,
    slots: &mut [Slot],
    started: &mut [Started],
    start_s: f64,
    report: &mut FleetReport,
    progress: &mut dyn FnMut(&FleetEvent),
) {
    let mut tasks: Vec<Vec<Task>> = vec![Vec::new(); slots.len()];
    for (si, s) in started.iter().enumerate() {
        // A run that ended keeps its last counters.
        if s.last.as_ref().is_none_or(Last::running) {
            tasks[s.agent].push(Task::Run(si, s.kind, s.id));
        }
        if let Some((b, id)) = s.rx {
            tasks[b].push(Task::Rx(si, id));
        }
    }
    let answers = each(slots, |a, slot| follow(slot, &tasks[a], plan, start_s));
    for (a, ans) in answers.into_iter().enumerate() {
        for (si, r) in ans.runs {
            match r {
                Ok(l) => started[si].last = Some(l),
                Err(e) => started[si].error = Some(e),
            }
        }
        for (si, r) in ans.rx {
            started[si].rx_last = Some(r);
        }
        let name = slots[a].name().to_string();
        if let Some(e) = &ans.broke {
            progress(&FleetEvent::AgentDown {
                agent: &name,
                error: e,
            });
        }
        if let Some(after) = ans.back {
            let note = format!(
                "agent '{name}' was out of reach for {after:.1} s; the controller connected again"
            );
            progress(&FleetEvent::AgentBack {
                agent: &name,
                after_s: after,
            });
            report.notes.push(note);
        }
        if ans.lost {
            // What it had: its runs, and receivers for runs elsewhere.
            let mut runs: Vec<String> = Vec::new();
            for s in started.iter_mut() {
                let rname = &plan.runs[s.run].name;
                if s.agent == a && s.id != 0 {
                    if !runs.contains(rname) {
                        runs.push(rname.clone());
                    }
                    s.error.get_or_insert_with(|| {
                        format!("agent '{name}' lost; its counters may be incomplete")
                    });
                }
                if s.rx.is_some_and(|(b, _)| b == a) {
                    let r = format!("{rname} (receiver)");
                    if !runs.contains(&r) {
                        runs.push(r);
                    }
                    s.error
                        .get_or_insert_with(|| format!("its receiver on agent '{name}' was lost"));
                }
            }
            let slot = &mut slots[a];
            if let Some(f) = &mut slot.failure {
                f.runs = runs;
                progress(&FleetEvent::AgentLost(f));
            }
        }
    }
}

fn stop_all(slots: &mut [Slot], started: &mut [Started]) {
    let mine: Vec<Vec<(usize, FleetKind, u64)>> = (0..slots.len())
        .map(|a| {
            started
                .iter()
                .enumerate()
                .filter(|(_, s)| s.agent == a && s.id != 0)
                .map(|(si, s)| (si, s.kind, s.id))
                .collect()
        })
        .collect();
    let got = each(slots, |a, slot| {
        if !slot.up() {
            return Vec::new();
        }
        mine[a]
            .iter()
            .map(|&(si, kind, id)| (si, stop_one(&mut slot.agent.client, kind, id)))
            .collect::<Vec<_>>()
    });
    for list in got {
        for (si, r) in list {
            match r {
                Ok(l) => started[si].last = Some(l),
                Err(e) => {
                    started[si].error.get_or_insert(e.to_string());
                }
            }
        }
    }
}

/// Receivers on other agents get the run's `rx_wait` for frames on their
/// way, then stop.
fn finish_rx(plan: &FleetPlan, slots: &mut [Slot], started: &mut [Started]) {
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
            if !slots[b].up() {
                continue;
            }
            match slots[b].agent.client.rx_stop(id) {
                Ok(r) => s.rx_last = Some(r),
                Err(e) => {
                    s.error.get_or_insert(format!("receiver: {e}"));
                }
            }
        }
    }
}

/// Forgets the runs on the agents, and unloads the traffic profiles.
fn remove_all(plan: &FleetPlan, slots: &mut [Slot], started: &[Started]) {
    let names: Vec<String> = plan.runs.iter().map(|r| profile_name(plan, r)).collect();
    let mine: Vec<Vec<&Started>> = (0..slots.len())
        .map(|a| started.iter().filter(|s| s.agent == a).collect())
        .collect();
    let rx_here: Vec<Vec<u64>> = (0..slots.len())
        .map(|b| {
            started
                .iter()
                .filter_map(|s| s.rx.filter(|(x, _)| *x == b).map(|(_, id)| id))
                .collect()
        })
        .collect();
    each(slots, |a, slot| {
        if !slot.up() {
            return;
        }
        let c = &mut slot.agent.client;
        for s in &mine[a] {
            if s.id == 0 {
                continue;
            }
            let _ = match s.kind {
                FleetKind::Tcp => c.tcp_remove(s.id).map(drop),
                FleetKind::Udp => c.udp_remove(s.id).map(drop),
                FleetKind::Hosts => c.host_remove(s.id).map(drop),
                FleetKind::Scenario => c.scenario_remove(s.id).map(drop),
                FleetKind::Bench => c.bench_remove(s.id).map(drop),
                FleetKind::Y1564 => c.y1564_remove(s.id).map(drop),
                FleetKind::Traffic => c
                    .remove(s.id)
                    .map(drop)
                    .and_then(|_| c.unload_profile(&names[s.run])),
            };
        }
        for id in &rx_here[a] {
            let _ = c.rx_remove(*id);
        }
    });
}

/// The metrics of the runs in `list`, added up, for a kind.
fn metrics_of<'a>(list: impl Iterator<Item = &'a Started>, kind: FleetKind) -> Option<Metrics> {
    let list: Vec<&Started> = list.filter(|s| s.kind == kind && s.id != 0).collect();
    if list.is_empty() {
        return None;
    }
    macro_rules! infos {
        ($variant:ident) => {
            list.iter()
                .filter_map(|s| match &s.last {
                    Some(Last::$variant(i)) => Some(&**i),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
    }
    Some(match kind {
        FleetKind::Tcp => tcp_metrics(&infos!(Tcp)),
        FleetKind::Udp => udp_metrics(&infos!(Udp)),
        FleetKind::Hosts => hosts_metrics(&infos!(Hosts)),
        FleetKind::Scenario => scenario_metrics(&infos!(Scenario)),
        FleetKind::Bench => bench_metrics(&infos!(Bench)),
        FleetKind::Y1564 => y1564_metrics(&infos!(Y1564)),
        FleetKind::Traffic => {
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

/// The frames dropped over an agent's runs (and receivers), by layer.
fn agent_drops(started: &[Started], a: usize) -> DropCounters {
    let mut d = DropCounters::default();
    for s in started {
        if s.agent == a {
            if let Some(l) = &s.last {
                d.add(&l.drops());
            }
        }
        if s.rx.is_some_and(|(b, _)| b == a) {
            if let Some(r) = &s.rx_last {
                d.add(&r.counters.drops);
            }
        }
    }
    d
}

fn sample(slots: &[Slot], started: &[Started], start_s: f64) -> FleetSample {
    let now = unix_seconds(SystemTime::now());
    let mut totals = BTreeMap::new();
    for kind in FleetKind::ALL {
        if let Some(m) = metrics_of(started.iter(), kind) {
            totals.insert(kind.as_str().to_string(), m);
        }
    }
    let agents = slots
        .iter()
        .enumerate()
        .map(|(a, s)| {
            let mut r = match (&s.link, &s.reading) {
                (Link::Up, Some(r)) => r.clone(),
                (link, _) => AgentSample {
                    agent: s.name().to_string(),
                    status: match link {
                        Link::Up => "up",
                        Link::Down { .. } => "down",
                        Link::Lost => "lost",
                    }
                    .into(),
                    ..Default::default()
                },
            };
            r.drops = agent_drops(started, a);
            r
        })
        .collect();
    FleetSample {
        t_s: now - start_s,
        running: started
            .iter()
            .filter(|s| s.id != 0 && s.running() && !slots[s.agent].lost())
            .count(),
        runs: started.iter().filter(|s| s.id != 0).count(),
        totals,
        agents,
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
            failures: Vec::new(),
        }
    }

    fn finish(&mut self, plan: &FleetPlan, slots: &[Slot], started: &[Started], stopped: bool) {
        self.stopped = stopped;
        // The agents as they ended up.
        for (a, (rec, s)) in self.agents.iter_mut().zip(slots).enumerate() {
            rec.reconnects = s.reconnects;
            rec.status = match (&s.link, s.reconnects) {
                (Link::Lost, _) => "lost",
                (Link::Down { .. }, _) => "down",
                (Link::Up, 0) => "ok",
                (Link::Up, _) => "reconnected",
            }
            .into();
            if s.tele.samples > 0 || !started.is_empty() {
                let mut t = s.tele.clone();
                t.drops = agent_drops(started, a);
                rec.telemetry = Some(t);
            }
            rec.failure = s.failure.clone();
            if let Some(f) = &s.failure {
                self.failures.push(f.clone());
            }
        }
        let mut starts = Vec::new();
        for (ri, run) in plan.runs.iter().enumerate() {
            let mine: Vec<&Started> = started
                .iter()
                .filter(|s| s.run == ri && s.id != 0)
                .collect();
            let instances: Vec<InstanceRecord> = mine
                .iter()
                .map(|s| {
                    let one = std::iter::once(*s);
                    let late = s
                        .last
                        .as_ref()
                        .and_then(Last::started_at)
                        .map(|t| (t - slots[s.agent].agent.offset - s.planned) * 1000.0);
                    if let Some(l) = late {
                        starts.push(l);
                    }
                    let metrics = metrics_of(one, run.kind).unwrap_or_default();
                    InstanceRecord {
                        conditions: judge(&run.require_each, &metrics),
                        agent: slots[s.agent].name().to_string(),
                        id: s.id,
                        state: s.last.as_ref().map(Last::state),
                        error: s
                            .error
                            .clone()
                            .or_else(|| s.last.as_ref().and_then(Last::error)),
                        start_late_ms: late,
                        rx_agent: s.rx.map(|(b, _)| slots[b].name().to_string()),
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
            let ok = instances.len() == run.instances.len()
                && instances.iter().all(|i| {
                    i.error.is_none()
                        && i.state != Some(RunState::Failed)
                        && i.conditions.iter().all(|c| c.pass)
                })
                && conditions.iter().all(|c| c.pass)
                && run_passed(run.kind, &metrics);
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
        for kind in FleetKind::ALL {
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
            && self.failures.is_empty()
            && self.runs.iter().all(|r| r.passed)
            && self.conditions.iter().all(|c| c.pass);
    }
}

/// Kinds with a verdict of their own (a scenario's checks, a benchmark
/// that ran to its end, a Y.1564 test) pass only with it.
fn run_passed(kind: FleetKind, m: &Metrics) -> bool {
    match kind {
        FleetKind::Scenario | FleetKind::Bench | FleetKind::Y1564 => m.get("passed") == Some(&1.0),
        FleetKind::Hosts => m.get("failed").is_none_or(|f| *f == 0.0),
        _ => true,
    }
}
