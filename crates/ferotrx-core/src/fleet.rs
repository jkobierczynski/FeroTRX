//! Fleet plans: runs on several FeroTRX agents at once.
//!
//! An agent is a control server (`ferotrx serve`) on a machine of the lab.
//! A plan names the agents and what each runs: TCP, UDP and traffic
//! profiles, with the settings of the start calls. A controller
//! (`ferotrx fleet run`, `ferotrx_ctl::fleet`) deploys the profiles and the
//! files they name to the agents, starts every run at one instant, and adds
//! up their counters. This module reads plans and works out what goes
//! where; it does no networking.
//!
//! ```toml
//! format = 1
//! name = "two-sites"
//! start_delay = "3s"          # from the start calls to the shared start
//! duration = "30s"            # every run, unless it says otherwise
//!
//! [vars]                      # ${NAME} here and in the profiles
//! server = "10.9.2.80"
//!
//! [[agent]]
//! name = "east"
//! address = "10.0.0.11:4510"
//! token_env = "FEROTRX_TOKEN" # or token = "...", or a client certificate
//! iface = "enp0s8"            # default interface of its runs
//! vars = { client_ip = "10.9.1.100" }   # ${client_ip} in its profiles
//!
//! [[run]]
//! name = "web clients"
//! agents = ["east", "west"]   # or agent = "east"
//! tcp = "clients.toml"        # or udp, traffic; a file or a table
//! cps = 50
//! require = ["cps > 90"]            # the agents' counters added up
//! require_each = ["completed_pct == 100", "connections == 500"]  # every agent's
//!
//! [require]                   # on the sums over every run of a kind
//! tcp = ["cps > 90"]
//!
//! [[capture]]                 # pcaps on the agents while the runs go
//! agents = ["east", "west"]   # or agent = "east"; default: every agent
//! iface = "enp0s8"            # default: the agent's iface
//! filter = "tcp port 80"      # BPF
//! snaplen = 256
//! ```

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::scenario::{
    read_vars, substitute, var_value, Better, CheckKind, Condition, MetricDef, Unit,
};
use crate::{parse_duration, Error, Profile, Result, TcpProfile, UdpProfile};

/// Time from the start calls to the shared start, unless the plan says.
pub const DEFAULT_START_DELAY: Duration = Duration::from_secs(3);

/// How long the controller tries to reach an agent again after its control
/// connection broke, unless the plan says.
pub const DEFAULT_RECONNECT: Duration = Duration::from_secs(10);

/// What a run of a fleet plan runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FleetKind {
    /// Stateful TCP (`tcp.start`).
    Tcp,
    /// Stateful UDP (`udp.start`).
    Udp,
    /// Stateless streams (`run.start`).
    Traffic,
    /// Emulated hosts (`host.start`).
    Hosts,
    /// A scenario's checks, one after the other (`scenario.start`).
    Scenario,
    /// An RFC 2544 benchmark (`bench.start`).
    Bench,
    /// A Y.1564 service activation test (`y1564.start`).
    Y1564,
}

impl FleetKind {
    pub const ALL: [FleetKind; 7] = [
        FleetKind::Tcp,
        FleetKind::Udp,
        FleetKind::Traffic,
        FleetKind::Hosts,
        FleetKind::Scenario,
        FleetKind::Bench,
        FleetKind::Y1564,
    ];

    /// The name in plans and reports; also what `server.capabilities` lists.
    pub fn as_str(self) -> &'static str {
        match self {
            FleetKind::Tcp => "tcp",
            FleetKind::Udp => "udp",
            FleetKind::Traffic => "traffic",
            FleetKind::Hosts => "hosts",
            FleetKind::Scenario => "scenario",
            FleetKind::Bench => "bench",
            FleetKind::Y1564 => "y1564",
        }
    }

    pub fn from_name(name: &str) -> Option<FleetKind> {
        Self::ALL.into_iter().find(|k| k.as_str() == name)
    }

    /// The metrics its conditions may test.
    pub fn metrics(self) -> &'static [MetricDef] {
        match self {
            FleetKind::Tcp => CheckKind::Tcp.metrics(),
            FleetKind::Udp => CheckKind::Udp.metrics(),
            FleetKind::Traffic => CheckKind::Traffic.metrics(),
            FleetKind::Y1564 => CheckKind::Y1564.metrics(),
            FleetKind::Hosts => HOSTS_METRICS,
            FleetKind::Scenario => SCENARIO_METRICS,
            FleetKind::Bench => BENCH_METRICS,
        }
    }

    /// The scenario check kind with the same metrics, for the kinds that have one.
    pub fn check_kind(self) -> Option<CheckKind> {
        match self {
            FleetKind::Tcp => Some(CheckKind::Tcp),
            FleetKind::Udp => Some(CheckKind::Udp),
            FleetKind::Traffic => Some(CheckKind::Traffic),
            FleetKind::Y1564 => Some(CheckKind::Y1564),
            _ => None,
        }
    }

    /// Runs that end by themselves when their work is done, without a
    /// duration: scenarios, benchmarks and Y.1564 tests.
    pub fn runs_to_the_end(self) -> bool {
        matches!(
            self,
            FleetKind::Scenario | FleetKind::Bench | FleetKind::Y1564
        )
    }

    /// The first agent version that runs it in a fleet.
    pub fn since(self) -> &'static str {
        match self {
            FleetKind::Tcp | FleetKind::Udp | FleetKind::Traffic => "0.31.0",
            _ => "0.51.0",
        }
    }

    /// Parses a condition on this kind's metrics.
    pub fn condition(self, text: &str) -> Result<Condition> {
        Condition::parse_in(text, self.as_str(), self.metrics())
    }
}

impl std::fmt::Display for FleetKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

const fn metric(name: &'static str, unit: Unit, better: Better, help: &'static str) -> MetricDef {
    MetricDef {
        name,
        unit,
        better,
        help,
    }
}

/// Metrics of a run of emulated hosts.
pub const HOSTS_METRICS: &[MetricDef] = &[
    metric("hosts", Unit::Count, Better::Neither, "emulated hosts"),
    metric(
        "ready",
        Unit::Count,
        Better::Higher,
        "hosts that got their addresses",
    ),
    metric(
        "ready_pct",
        Unit::Percent,
        Better::Higher,
        "ready, of the hosts",
    ),
    metric("failed", Unit::Count, Better::Lower, "hosts that failed"),
    metric(
        "ready_avg",
        Unit::Millis,
        Better::Lower,
        "average time a host took to get its addresses",
    ),
    metric(
        "ready_max",
        Unit::Millis,
        Better::Lower,
        "longest time a host took to get its addresses",
    ),
    metric(
        "tx_packets",
        Unit::Count,
        Better::Neither,
        "frames the hosts sent",
    ),
    metric(
        "rx_packets",
        Unit::Count,
        Better::Neither,
        "frames the hosts took",
    ),
];

/// Metrics of a scenario run.
pub const SCENARIO_METRICS: &[MetricDef] = &[
    metric(
        "passed",
        Unit::Count,
        Better::Higher,
        "1 when every check that ran passed, 0 otherwise",
    ),
    metric("checks", Unit::Count, Better::Neither, "checks run"),
    metric(
        "checks_passed",
        Unit::Count,
        Better::Higher,
        "checks that passed",
    ),
    metric(
        "checks_failed",
        Unit::Count,
        Better::Lower,
        "checks that failed or broke",
    ),
    metric(
        "checks_passed_pct",
        Unit::Percent,
        Better::Higher,
        "passed, of the checks run",
    ),
];

/// Metrics of a benchmark run.
pub const BENCH_METRICS: &[MetricDef] = &[
    metric(
        "passed",
        Unit::Count,
        Better::Higher,
        "1 when the benchmark ran to its end, 0 when it failed or was stopped",
    ),
    metric("trials", Unit::Count, Better::Neither, "trials run"),
    metric(
        "throughput_pct",
        Unit::Percent,
        Better::Higher,
        "throughput in percent of the line rate, the lowest over the sizes",
    ),
    metric(
        "throughput_mbps",
        Unit::Mbps,
        Better::Higher,
        "throughput of the size with the lowest one, in Mbit/s",
    ),
    metric(
        "throughput_pps",
        Unit::PerSecond,
        Better::Higher,
        "throughput of the size with the lowest one, in frames per second",
    ),
    metric(
        "latency_avg",
        Unit::Millis,
        Better::Lower,
        "average latency, the highest over the sizes",
    ),
    metric(
        "latency_max",
        Unit::Millis,
        Better::Lower,
        "largest latency over the sizes",
    ),
    metric(
        "frame_loss_pct",
        Unit::Percent,
        Better::Lower,
        "frame loss at the highest load measured, the worst size",
    ),
    metric(
        "sender_limited",
        Unit::Count,
        Better::Lower,
        "sizes whose result may be the sender's limit",
    ),
];

/// What the controller does when it loses an agent during a run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OnAgentLoss {
    /// The other agents go on; the fleet fails.
    #[default]
    Continue,
    /// Every run is stopped.
    Stop,
}

/// A fleet plan: agents, and the runs they do together.
#[derive(Clone, Debug)]
pub struct FleetPlan {
    pub name: String,
    pub description: Option<String>,
    /// The file it was read from.
    pub path: Option<PathBuf>,
    pub vars: BTreeMap<String, String>,
    /// How long before the shared start the start calls go out: time for
    /// every agent to open its interfaces and answer.
    pub start_delay: Duration,
    /// How long every run goes, unless it has its own.
    pub duration: Option<Duration>,
    /// How often the controller reads the agents' counters.
    pub interval: Duration,
    /// Where the profiles go on the agents, relative to their data
    /// directory: `fleet/NAME` unless the plan says.
    pub deploy_dir: PathBuf,
    pub agents: Vec<AgentSpec>,
    pub runs: Vec<FleetRun>,
    /// Conditions on the sums over every run of a kind.
    pub require: Vec<(FleetKind, Condition)>,
    /// Captures on the agents while the runs go, one per agent and interface.
    pub captures: Vec<FleetCapture>,
    /// How long the controller tries to reach an agent again after its
    /// control connection broke; after that the agent is lost.
    pub reconnect: Duration,
    /// What happens to the other runs when an agent is lost.
    pub on_agent_loss: OnAgentLoss,
    /// Read every agent's health (CPU, memory, clock) once per interval.
    pub telemetry: bool,
}

/// A capture on one agent's interface for the length of a fleet run
/// (`[[capture]]`); the controller can fetch the pcaps afterwards and merge
/// them.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FleetCapture {
    pub agent: String,
    pub iface: String,
    pub filter: Option<String>,
    pub snaplen: Option<u32>,
    /// `AGENT-IFACE`, unique in the plan: the pcap's name on the agent and
    /// after collection.
    pub name: String,
}

/// An agent: a `ferotrx serve` the controller reaches.
#[derive(Clone, Debug, Default)]
pub struct AgentSpec {
    pub name: String,
    /// `host:port`.
    pub address: String,
    pub token: Option<String>,
    /// An environment variable of the controller that holds the token.
    pub token_env: Option<String>,
    /// TLS settings; `None` for a plain connection.
    pub tls: Option<AgentTls>,
    /// The interface of its runs when a run names none.
    pub iface: Option<String>,
    /// `${NAME}` in the profiles it runs.
    pub vars: BTreeMap<String, String>,
}

/// How to reach an agent over TLS.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AgentTls {
    /// The CA the agent's certificate must come from; `None`: the system's.
    pub ca: Option<PathBuf>,
    /// A client certificate and key, to log in with.
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    /// The name in the agent's certificate, when it is not the address's host.
    pub server_name: Option<String>,
}

/// One `[[run]]`: a profile, on one or more agents.
#[derive(Clone, Debug)]
pub struct FleetRun {
    pub name: String,
    pub kind: FleetKind,
    /// The profile file as the plan names it, or `inline`.
    pub source: String,
    /// One per agent.
    pub instances: Vec<FleetInstance>,
    pub settings: RunSettings,
    /// How long after the shared start this run starts.
    pub delay: Duration,
    /// Conditions on this run's counters, added up over its agents.
    pub require: Vec<Condition>,
    /// Conditions each agent's part must meet on its own.
    pub require_each: Vec<Condition>,
}

/// A run's profile as one agent gets it.
#[derive(Clone, Debug)]
pub struct FleetInstance {
    pub agent: String,
    /// The profile, with the variables filled in.
    pub text: String,
    /// The folder its relative paths start from, here.
    pub dir: PathBuf,
    /// The name it is written under on the agent.
    pub file_name: String,
    /// The files it names by relative paths, here (canonical): sent along.
    pub files: Vec<PathBuf>,
    /// The interface: the run's, or the agent's.
    pub iface: Option<String>,
}

/// What the start calls carry besides the profile. Rates and durations stay
/// text, as the control protocol takes them.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RunSettings {
    /// Traffic: receive on this interface, for loss and latency.
    pub rx: Option<String>,
    /// Traffic: the agent that receives (default: the one that sends).
    pub rx_agent: Option<String>,
    pub rx_wait: Option<String>,
    pub backend: Option<String>,
    pub xdp_mode: Option<String>,
    pub queue: Option<u16>,
    pub workers: Option<u16>,
    /// TCP.
    pub cps: Option<f64>,
    pub connections: Option<u64>,
    pub concurrency: Option<usize>,
    /// Traffic: a rate for every stream (`10kpps`, `100mbps`); UDP:
    /// transactions per second.
    pub rate: Option<String>,
    /// UDP.
    pub transactions: Option<u64>,
    /// Traffic: packets in all.
    pub limit: Option<u64>,
    /// Traffic: a signature in every stream.
    pub latency: bool,
    pub duration: Option<Duration>,
    pub impair: Option<String>,
    pub impair_rx: Option<String>,
    /// Benchmark and Y.1564: the tests; benchmark: the frame sizes;
    /// Y.1564: the services; both: the line rate.
    pub tests: Vec<String>,
    pub sizes: Vec<String>,
    pub services: Vec<String>,
    pub line_rate: Option<String>,
    /// Scenario: only these checks, and whether to build its `[lab]`.
    pub only: Vec<String>,
    pub lab: Option<bool>,
    /// Hosts: end once every host has its addresses.
    pub until_ready: bool,
}

/// Where an instance's files go on its agent.
#[derive(Clone, Debug, PartialEq)]
pub struct Deployment {
    /// The profile, relative to the agent's data directory.
    pub profile: PathBuf,
    /// The folder relative paths in the profile start from.
    pub base_dir: PathBuf,
    /// Each local file and where it goes.
    pub files: Vec<(PathBuf, PathBuf)>,
}

impl FleetInstance {
    /// Where this instance's profile and files go under `dir` (the plan's
    /// `deploy_dir` and the run's own folder): the files keep their places
    /// relative to the profile, so its paths hold there too.
    pub fn deployment(&self, dir: &Path) -> Deployment {
        let here = self.dir.canonicalize().unwrap_or_else(|_| self.dir.clone());
        let mut root = here.clone();
        for f in &self.files {
            let parent = f.parent().unwrap_or(f);
            while !parent.starts_with(&root) {
                if !root.pop() {
                    break;
                }
            }
        }
        let rel = |p: &Path| -> PathBuf {
            p.strip_prefix(&root)
                .map(Path::to_path_buf)
                .unwrap_or_else(|_| PathBuf::from(p.file_name().unwrap_or_default()))
        };
        let base_dir = dir.join(rel(&here));
        Deployment {
            profile: base_dir.join(&self.file_name),
            base_dir,
            files: self
                .files
                .iter()
                .map(|f| (f.clone(), dir.join(rel(f))))
                .collect(),
        }
    }
}

impl FleetRun {
    /// The run's folder name on the agents: its name in lower case, with
    /// `-` for anything but letters and digits.
    pub fn slug(&self) -> String {
        slug(&self.name)
    }
}

fn slug(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    let s = s.trim_matches('-').to_string();
    if s.is_empty() {
        "run".into()
    } else {
        s
    }
}

impl FleetPlan {
    /// The agent called `name`.
    pub fn agent(&self, name: &str) -> Option<&AgentSpec> {
        self.agents.iter().find(|a| a.name == name)
    }

    /// Reads a plan file; profiles are relative to its folder. `overrides`
    /// replace or add `[vars]`.
    pub fn from_path(path: impl AsRef<Path>, overrides: &[(String, String)]) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Profile(format!("cannot read {}: {e}", path.display())))?;
        let stem = path
            .file_stem()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "fleet".into());
        let mut plan = Self::parse(
            &text,
            path.parent().unwrap_or(Path::new(".")),
            overrides,
            &stem,
        )?;
        plan.path = Some(path.to_path_buf());
        Ok(plan)
    }

    /// Parses a plan; profile files and the files they name are relative
    /// to `base_dir`.
    pub fn from_toml(text: &str, base_dir: &Path, overrides: &[(String, String)]) -> Result<Self> {
        Self::parse(text, base_dir, overrides, "fleet")
    }

    fn parse(
        text: &str,
        base_dir: &Path,
        overrides: &[(String, String)],
        default_name: &str,
    ) -> Result<Self> {
        let vars = read_vars(text, overrides, "fleet")?;
        // Agents' own variables are filled in later, in their profiles.
        let text = substitute_known(text, &vars);
        let raw: RawPlan =
            toml::from_str(&text).map_err(|e| Error::Profile(format!("fleet: {e}")))?;
        crate::check_format(raw.format)?;
        let name = raw.name.unwrap_or_else(|| default_name.to_string());
        let dur = |s: Option<String>, what: &str| -> Result<Option<Duration>> {
            s.map(|s| parse_duration(&s).map_err(|e| Error::Profile(format!("{what}: {e}"))))
                .transpose()
        };
        let start_delay = dur(raw.start_delay, "start_delay")?.unwrap_or(DEFAULT_START_DELAY);
        let interval = dur(raw.interval, "interval")?.unwrap_or(Duration::from_secs(1));
        if interval < Duration::from_millis(100) {
            return Err(Error::Profile("interval: at least 100ms".into()));
        }
        let duration = dur(raw.duration, "duration")?;
        let reconnect = dur(raw.reconnect, "reconnect")?.unwrap_or(DEFAULT_RECONNECT);
        let on_agent_loss = match raw.on_agent_loss.as_deref().map(str::trim) {
            None | Some("continue") => OnAgentLoss::Continue,
            Some("stop") => OnAgentLoss::Stop,
            Some(o) => {
                return Err(Error::Profile(format!(
                    "on_agent_loss = \"{o}\": give \"continue\" or \"stop\""
                )))
            }
        };
        let deploy_dir = match raw.deploy_dir {
            Some(d) => PathBuf::from(d),
            None => Path::new("fleet").join(slug(&name)),
        };
        let plain = deploy_dir
            .components()
            .all(|c| matches!(c, Component::Normal(_)));
        if !plain || deploy_dir.as_os_str().is_empty() {
            return Err(Error::Profile(format!(
                "deploy_dir {}: give a relative path without '..' (in the agents' data directory)",
                deploy_dir.display()
            )));
        }

        if raw.agent.is_empty() {
            return Err(Error::Profile(
                "a fleet needs at least one [[agent]]".into(),
            ));
        }
        let mut agents: Vec<AgentSpec> = Vec::new();
        for (i, a) in raw.agent.into_iter().enumerate() {
            let agent = a.into_spec(i, base_dir)?;
            if agents.iter().any(|o| o.name == agent.name) {
                return Err(Error::Profile(format!(
                    "two agents are called '{}'",
                    agent.name
                )));
            }
            agents.push(agent);
        }

        if raw.run.is_empty() {
            return Err(Error::Profile("a fleet needs at least one [[run]]".into()));
        }
        let mut runs: Vec<FleetRun> = Vec::new();
        for (i, r) in raw.run.into_iter().enumerate() {
            let name = r.name.clone().unwrap_or_else(|| format!("run {}", i + 1));
            let run = r
                .into_run(name.clone(), base_dir, &vars, &agents, duration)
                .map_err(|e| match e {
                    Error::Profile(m) => Error::Profile(format!("run '{name}': {m}")),
                    e => Error::Profile(format!("run '{name}': {e}")),
                })?;
            if runs.iter().any(|o| o.name == run.name) {
                return Err(Error::Profile(format!(
                    "two runs are called '{}'; reports go by name",
                    run.name
                )));
            }
            if runs.iter().any(|o| o.slug() == run.slug()) {
                return Err(Error::Profile(format!(
                    "runs '{}' and another one would share a folder on the agents ({}); rename one",
                    run.name,
                    run.slug()
                )));
            }
            runs.push(run);
        }

        let mut captures: Vec<FleetCapture> = Vec::new();
        for (i, c) in raw.capture.into_iter().enumerate() {
            let names: Vec<String> = match (c.agent, c.agents) {
                (Some(a), None) => vec![a],
                (None, Some(list)) if !list.is_empty() => list,
                (None, None) | (None, Some(_)) => agents.iter().map(|a| a.name.clone()).collect(),
                (Some(_), Some(_)) => {
                    return Err(Error::Profile(format!(
                        "capture {}: give agent or agents, not both",
                        i + 1
                    )))
                }
            };
            for n in names {
                let Some(agent) = agents.iter().find(|a| a.name == n) else {
                    return Err(Error::Profile(format!(
                        "capture {}: no agent called '{n}'",
                        i + 1
                    )));
                };
                let Some(iface) = c.iface.clone().or_else(|| agent.iface.clone()) else {
                    return Err(Error::Profile(format!(
                        "capture {}: agent '{n}' has no iface; give the capture one",
                        i + 1
                    )));
                };
                let name = slug(&format!("{n}-{iface}"));
                if captures.iter().any(|o| o.name == name) {
                    return Err(Error::Profile(format!(
                        "two captures on {iface} of agent '{n}'"
                    )));
                }
                captures.push(FleetCapture {
                    agent: n,
                    iface,
                    filter: c.filter.clone().filter(|f| !f.trim().is_empty()),
                    snaplen: c.snaplen,
                    name,
                });
            }
        }

        let mut require = Vec::new();
        for (name, list) in raw.require {
            let kind = FleetKind::from_name(&name).ok_or_else(|| {
                let all: Vec<&str> = FleetKind::ALL.iter().map(|k| k.as_str()).collect();
                Error::Profile(format!(
                    "[require] {name}: no such kind of run; there are {}",
                    all.join(", ")
                ))
            })?;
            for c in list {
                require.push((kind, kind.condition(&c)?));
            }
        }
        Ok(FleetPlan {
            name,
            description: raw.description,
            path: None,
            vars,
            start_delay,
            duration,
            interval,
            deploy_dir,
            agents,
            runs,
            require,
            captures,
            reconnect,
            on_agent_loss,
            telemetry: raw.telemetry.unwrap_or(true),
        })
    }

    /// Lines on the plan: agents, then runs.
    pub fn summary(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "fleet '{}': {} agent(s), {} run(s), start {:.1}s after the start calls{}",
            self.name,
            self.agents.len(),
            self.runs.len(),
            self.start_delay.as_secs_f64(),
            self.duration
                .map(|d| format!(", {:.1}s each", d.as_secs_f64()))
                .unwrap_or_default()
        )];
        for a in &self.agents {
            let mut how = Vec::new();
            if a.tls.is_some() {
                how.push("tls".to_string());
            }
            if a.token.is_some() || a.token_env.is_some() {
                how.push("token".into());
            }
            if let Some(i) = &a.iface {
                how.push(format!("iface {i}"));
            }
            lines.push(format!(
                "  agent {} at {}{}",
                a.name,
                a.address,
                if how.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", how.join(", "))
                }
            ));
        }
        for c in &self.captures {
            lines.push(format!(
                "  capture on {} of {}{}",
                c.iface,
                c.agent,
                c.filter
                    .as_deref()
                    .map(|f| format!(", filter '{f}'"))
                    .unwrap_or_default()
            ));
        }
        for r in &self.runs {
            let agents: Vec<&str> = r.instances.iter().map(|i| i.agent.as_str()).collect();
            let files: usize = r.instances.first().map_or(0, |i| i.files.len());
            lines.push(format!(
                "  run {}: {} {} on {}{}{}",
                r.name,
                r.kind,
                r.source,
                agents.join(", "),
                if files > 0 {
                    format!(", {files} file(s) sent along")
                } else {
                    String::new()
                },
                if r.delay.is_zero() {
                    String::new()
                } else {
                    format!(", {:.1}s after the start", r.delay.as_secs_f64())
                }
            ));
        }
        lines
    }
}

/// `${NAME}` replaced where NAME is known; the rest left for later.
fn substitute_known(text: &str, vars: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("${") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        let Some(end) = after.find('}') else {
            out.push_str(&rest[i..]);
            return out;
        };
        match vars.get(after[..end].trim()) {
            Some(v) => out.push_str(v),
            None => out.push_str(&rest[i..i + 2 + end + 1]),
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPlan {
    format: Option<u32>,
    name: Option<String>,
    description: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    vars: toml::Table,
    start_delay: Option<String>,
    duration: Option<String>,
    interval: Option<String>,
    deploy_dir: Option<String>,
    reconnect: Option<String>,
    on_agent_loss: Option<String>,
    telemetry: Option<bool>,
    #[serde(default)]
    agent: Vec<RawAgent>,
    #[serde(default)]
    run: Vec<RawRun>,
    #[serde(default)]
    require: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    capture: Vec<RawCapture>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCapture {
    agent: Option<String>,
    agents: Option<Vec<String>>,
    iface: Option<String>,
    filter: Option<String>,
    snaplen: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgent {
    name: Option<String>,
    address: String,
    token: Option<String>,
    token_env: Option<String>,
    tls: Option<bool>,
    ca: Option<String>,
    cert: Option<String>,
    key: Option<String>,
    server_name: Option<String>,
    iface: Option<String>,
    #[serde(default)]
    vars: toml::Table,
}

impl RawAgent {
    fn into_spec(self, i: usize, base_dir: &Path) -> Result<AgentSpec> {
        let name = self.name.unwrap_or_else(|| format!("agent{}", i + 1));
        let ctx = |m: String| Error::Profile(format!("agent '{name}': {m}"));
        if !self.address.contains(':') {
            return Err(ctx(format!(
                "address '{}': give host:port (ferotrx serve listens on 4510)",
                self.address
            )));
        }
        if self.token.is_some() && self.token_env.is_some() {
            return Err(ctx("give token or token_env, not both".into()));
        }
        if self.cert.is_some() != self.key.is_some() {
            return Err(ctx("a client certificate needs both cert and key".into()));
        }
        let wants_tls = self.ca.is_some()
            || self.cert.is_some()
            || self.server_name.is_some()
            || self.tls == Some(true);
        if self.tls == Some(false) && wants_tls {
            return Err(ctx("tls = false with TLS settings".into()));
        }
        let file = |p: Option<String>| p.map(|p| base_dir.join(p));
        let tls = wants_tls.then(|| AgentTls {
            ca: file(self.ca),
            cert: file(self.cert),
            key: file(self.key),
            server_name: self.server_name,
        });
        let mut vars = BTreeMap::new();
        for (k, v) in &self.vars {
            vars.insert(k.clone(), var_value(k, v).map_err(|e| ctx(e.to_string()))?);
        }
        Ok(AgentSpec {
            name,
            address: self.address,
            token: self.token,
            token_env: self.token_env,
            tls,
            iface: self.iface,
            vars,
        })
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawWorkload {
    Path(String),
    Inline(toml::Table),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRun {
    name: Option<String>,
    agent: Option<String>,
    agents: Option<Vec<String>>,
    tcp: Option<RawWorkload>,
    udp: Option<RawWorkload>,
    traffic: Option<RawWorkload>,
    hosts: Option<RawWorkload>,
    scenario: Option<RawWorkload>,
    bench: Option<RawWorkload>,
    y1564: Option<RawWorkload>,
    iface: Option<String>,
    rx: Option<String>,
    rx_agent: Option<String>,
    rx_wait: Option<String>,
    backend: Option<String>,
    xdp_mode: Option<String>,
    queue: Option<u16>,
    workers: Option<u16>,
    cps: Option<f64>,
    connections: Option<u64>,
    concurrency: Option<usize>,
    rate: Option<toml::Value>,
    transactions: Option<u64>,
    limit: Option<u64>,
    #[serde(default)]
    latency: bool,
    duration: Option<String>,
    delay: Option<String>,
    impair: Option<String>,
    impair_rx: Option<String>,
    #[serde(default)]
    tests: Vec<String>,
    #[serde(default)]
    sizes: Vec<String>,
    #[serde(default)]
    services: Vec<String>,
    line_rate: Option<String>,
    #[serde(default)]
    only: Vec<String>,
    lab: Option<bool>,
    #[serde(default)]
    until_ready: bool,
    #[serde(default)]
    require: Vec<String>,
    #[serde(default)]
    require_each: Vec<String>,
}

impl RawRun {
    fn into_run(
        self,
        name: String,
        base_dir: &Path,
        vars: &BTreeMap<String, String>,
        agents: &[AgentSpec],
        default_duration: Option<Duration>,
    ) -> Result<FleetRun> {
        let mut given: Vec<(FleetKind, RawWorkload)> = [
            (FleetKind::Tcp, self.tcp),
            (FleetKind::Udp, self.udp),
            (FleetKind::Traffic, self.traffic),
            (FleetKind::Hosts, self.hosts),
            (FleetKind::Scenario, self.scenario),
            (FleetKind::Bench, self.bench),
            (FleetKind::Y1564, self.y1564),
        ]
        .into_iter()
        .filter_map(|(k, w)| w.map(|w| (k, w)))
        .collect();
        let (kind, raw) = match given.len() {
            1 => given.remove(0),
            0 => {
                return Err(Error::Profile(
                    "give what runs: tcp, udp, traffic, hosts, scenario, bench or y1564 \
                     (a profile file or a table)"
                        .into(),
                ))
            }
            _ => {
                let kinds: Vec<&str> = given.iter().map(|(k, _)| k.as_str()).collect();
                return Err(Error::Profile(format!(
                    "give one of {}; make another run for the other",
                    kinds.join(", ")
                )));
            }
        };
        let names: Vec<String> = match (self.agent, self.agents) {
            (Some(a), None) => vec![a],
            (None, Some(list)) if !list.is_empty() => list,
            (None, None) | (None, Some(_)) => {
                return Err(Error::Profile("say where it runs: agent or agents".into()))
            }
            (Some(_), Some(_)) => {
                return Err(Error::Profile("give agent or agents, not both".into()))
            }
        };
        let known = |n: &str| -> Result<&AgentSpec> {
            agents.iter().find(|a| a.name == n).ok_or_else(|| {
                let all: Vec<&str> = agents.iter().map(|a| a.name.as_str()).collect();
                Error::Profile(format!(
                    "no agent called '{n}'; there are: {}",
                    all.join(", ")
                ))
            })
        };
        for (i, n) in names.iter().enumerate() {
            known(n)?;
            if names[..i].contains(n) {
                return Err(Error::Profile(format!("agent '{n}' is named twice")));
            }
        }
        if let Some(rx_agent) = &self.rx_agent {
            known(rx_agent)?;
            if self.rx.is_none() {
                return Err(Error::Profile(
                    "rx_agent needs rx: the interface it receives on".into(),
                ));
            }
        }
        use FleetKind as K;
        // Which settings go with which kinds.
        let only_for = |set: bool, what: &str, kinds: &[FleetKind]| -> Result<()> {
            if set && !kinds.contains(&kind) {
                let names: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
                return Err(Error::Profile(format!(
                    "{what} is for {} runs, not {kind}",
                    names.join(" and ")
                )));
            }
            Ok(())
        };
        only_for(self.rx.is_some(), "rx", &[K::Traffic, K::Bench, K::Y1564])?;
        only_for(self.rx_agent.is_some(), "rx_agent", &[K::Traffic])?;
        only_for(self.rx_wait.is_some(), "rx_wait", &[K::Traffic])?;
        only_for(self.limit.is_some(), "limit", &[K::Traffic])?;
        only_for(self.latency, "latency", &[K::Traffic])?;
        only_for(self.cps.is_some(), "cps", &[K::Tcp])?;
        only_for(self.connections.is_some(), "connections", &[K::Tcp])?;
        only_for(self.concurrency.is_some(), "concurrency", &[K::Tcp, K::Udp])?;
        only_for(self.transactions.is_some(), "transactions", &[K::Udp])?;
        only_for(self.rate.is_some(), "rate", &[K::Traffic, K::Udp])?;
        only_for(
            self.impair.is_some(),
            "impair",
            &[K::Tcp, K::Udp, K::Traffic, K::Hosts],
        )?;
        only_for(
            self.impair_rx.is_some(),
            "impair_rx",
            &[K::Tcp, K::Udp, K::Hosts],
        )?;
        only_for(!self.tests.is_empty(), "tests", &[K::Bench, K::Y1564])?;
        only_for(!self.sizes.is_empty(), "sizes", &[K::Bench])?;
        only_for(!self.services.is_empty(), "services", &[K::Y1564])?;
        only_for(self.line_rate.is_some(), "line_rate", &[K::Bench, K::Y1564])?;
        only_for(!self.only.is_empty(), "only", &[K::Scenario])?;
        only_for(self.lab.is_some(), "lab", &[K::Scenario])?;
        only_for(self.until_ready, "until_ready", &[K::Hosts])?;
        only_for(
            self.backend.is_some() || self.xdp_mode.is_some() || self.queue.is_some(),
            "backend, xdp_mode and queue",
            &[K::Tcp, K::Udp, K::Traffic, K::Hosts, K::Bench, K::Y1564],
        )?;
        only_for(
            self.workers.is_some(),
            "workers",
            &[K::Tcp, K::Udp, K::Traffic, K::Bench, K::Y1564],
        )?;
        if kind.runs_to_the_end() && self.duration.is_some() {
            return Err(Error::Profile(format!(
                "a {kind} run ends when its work is done: leave out duration"
            )));
        }
        let rate = match self.rate {
            None => None,
            Some(toml::Value::String(s)) if kind == K::Traffic => {
                s.parse::<crate::Rate>()
                    .map_err(|e| Error::Profile(format!("rate: {e}")))?;
                Some(s)
            }
            Some(toml::Value::Integer(n)) if kind == K::Udp => Some(n.to_string()),
            Some(toml::Value::Float(n)) if kind == K::Udp => Some(n.to_string()),
            Some(_) if kind == K::Udp => {
                return Err(Error::Profile(
                    "rate: transactions per second, as a number".into(),
                ))
            }
            Some(_) => {
                return Err(Error::Profile(
                    "rate: a rate for every stream, e.g. \"10kpps\" or \"100mbps\"".into(),
                ))
            }
        };
        if let Some(r) = &self.line_rate {
            match r.parse::<crate::Rate>() {
                Ok(crate::Rate::Mbps(_)) => {}
                _ => {
                    return Err(Error::Profile(format!(
                        "line_rate = \"{r}\": a bit rate such as \"1gbps\""
                    )))
                }
            }
        }
        let dur = |s: Option<String>, what: &str| -> Result<Option<Duration>> {
            s.map(|s| parse_duration(&s).map_err(|e| Error::Profile(format!("{what}: {e}"))))
                .transpose()
        };
        if let Some(w) = &self.rx_wait {
            parse_duration(w).map_err(|e| Error::Profile(format!("rx_wait: {e}")))?;
        }
        let duration = if kind.runs_to_the_end() {
            None
        } else {
            dur(self.duration, "duration")?.or(default_duration)
        };
        let delay = dur(self.delay, "delay")?.unwrap_or_default();

        let (template, dir, source, file_name) = match raw {
            RawWorkload::Path(p) => {
                let path = base_dir.join(&p);
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| Error::Profile(format!("cannot read {}: {e}", path.display())))?;
                let file_name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "profile.toml".into());
                let dir = path.parent().unwrap_or(base_dir).to_path_buf();
                (text, dir, p, file_name)
            }
            RawWorkload::Inline(t) => (
                toml::to_string(&t).map_err(|e| Error::Profile(e.to_string()))?,
                base_dir.to_path_buf(),
                "inline".to_string(),
                format!("{}.toml", slug(&name)),
            ),
        };
        let mut instances = Vec::new();
        for n in &names {
            let agent = known(n)?;
            let mut all = vars.clone();
            all.extend(agent.vars.iter().map(|(k, v)| (k.clone(), v.clone())));
            all.entry("agent".into())
                .or_insert_with(|| agent.name.clone());
            let what = format!("{source} on agent '{n}'");
            // A scenario has variables of its own: those stay for it.
            let text = if kind == K::Scenario {
                substitute_known(&template, &all)
            } else {
                substitute(&template, &all, &what)?
            };
            let ctx = |e: Error| Error::Profile(format!("{what}: {e}"));
            // Read here first: a mistake shows before anything starts.
            match kind {
                K::Tcp => drop(TcpProfile::from_toml(&text, &dir).map_err(ctx)?),
                K::Udp => drop(UdpProfile::from_toml(&text, &dir).map_err(ctx)?),
                K::Traffic => drop(Profile::from_toml(&text, &dir).map_err(ctx)?),
                K::Hosts => {
                    let p = crate::HostProfile::from_toml(&text).map_err(ctx)?;
                    if p.output.workers() > 1 {
                        return Err(Error::Profile(format!("{what}: host runs use one worker")));
                    }
                }
                K::Scenario => {
                    let sc = crate::scenario::Scenario::from_toml(&text, &dir, &[]).map_err(ctx)?;
                    for o in &self.only {
                        if !sc.checks.iter().any(|c| c.name == *o) {
                            return Err(Error::Profile(format!(
                                "{what}: only names '{o}', which is no check of the scenario"
                            )));
                        }
                    }
                }
                K::Bench => {
                    drop(crate::BenchProfile::from_toml(&text).map_err(ctx)?);
                    // The overrides as the agent reads them.
                    for t in &self.tests {
                        t.parse::<crate::bench::BenchTest>().map_err(ctx)?;
                    }
                    for z in &self.sizes {
                        if !z.trim().eq_ignore_ascii_case("rfc2544") {
                            z.parse::<crate::SizeMix>().map_err(ctx)?;
                        }
                    }
                }
                K::Y1564 => {
                    let mut p = crate::Y1564Profile::from_toml(&text).map_err(ctx)?;
                    for t in &self.tests {
                        t.parse::<crate::y1564::Y1564Test>().map_err(ctx)?;
                    }
                    if !self.services.is_empty() {
                        p.keep_services(&self.services).map_err(ctx)?;
                    }
                }
            }
            // A scenario's own [vars] name its profiles: fill them in before
            // looking for the files to send along.
            let deps_text = match kind {
                K::Scenario => crate::scenario::read_vars(&text, &[], "scenario")
                    .and_then(|v| crate::scenario::substitute(&text, &v, "scenario"))
                    .unwrap_or_else(|_| text.clone()),
                _ => text.clone(),
            };
            let table: toml::Table = toml::from_str(&crate::check::blank(&deps_text))
                .map_err(|e| Error::Profile(format!("{source}: {e}")))?;
            let iface = self.iface.clone().or_else(|| agent.iface.clone());
            if matches!(kind, K::Traffic | K::Bench | K::Y1564) && iface.is_none() {
                return Err(Error::Profile(format!(
                    "a {kind} run needs iface, here or on agent '{n}'"
                )));
            }
            instances.push(FleetInstance {
                agent: n.clone(),
                text,
                files: crate::bundle::files_named_in(&table, &dir),
                dir: dir.clone(),
                file_name: file_name.clone(),
                iface,
            });
        }
        let parse = |list: &[String]| {
            list.iter()
                .map(|c| kind.condition(c))
                .collect::<Result<Vec<_>>>()
        };
        let require = parse(&self.require)?;
        let require_each = parse(&self.require_each)?;
        Ok(FleetRun {
            name,
            kind,
            source,
            instances,
            settings: RunSettings {
                rx: self.rx,
                rx_agent: self.rx_agent,
                rx_wait: self.rx_wait,
                backend: self.backend,
                xdp_mode: self.xdp_mode,
                queue: self.queue,
                workers: self.workers,
                cps: self.cps,
                connections: self.connections,
                concurrency: self.concurrency,
                rate,
                transactions: self.transactions,
                limit: self.limit,
                latency: self.latency,
                duration,
                impair: self.impair,
                impair_rx: self.impair_rx,
                tests: self.tests,
                sizes: self.sizes,
                services: self.services,
                line_rate: self.line_rate,
                only: self.only,
                lab: self.lab,
                until_ready: self.until_ready,
            },
            delay,
            require,
            require_each,
        })
    }
}

#[cfg(test)]
mod tests;
