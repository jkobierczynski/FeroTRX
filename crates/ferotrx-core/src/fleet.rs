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
//! ```

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::scenario::{read_vars, substitute, var_value, CheckKind, Condition};
use crate::{parse_duration, Error, Profile, Result, TcpProfile, UdpProfile};

/// Time from the start calls to the shared start, unless the plan says.
pub const DEFAULT_START_DELAY: Duration = Duration::from_secs(3);

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
    pub require: Vec<(CheckKind, Condition)>,
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
    /// TCP, UDP or traffic.
    pub kind: CheckKind,
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

        let mut require = Vec::new();
        for (kind, list) in [
            (CheckKind::Tcp, raw.require.tcp),
            (CheckKind::Udp, raw.require.udp),
            (CheckKind::Traffic, raw.require.traffic),
        ] {
            for c in list {
                require.push((kind, Condition::parse(&c, kind)?));
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

/// The files a profile names by relative paths that exist here: every
/// string value that is the path of a file in `dir`.
fn files_named(table: &toml::Table, dir: &Path) -> Vec<PathBuf> {
    fn walk(v: &toml::Value, dir: &Path, out: &mut Vec<PathBuf>) {
        match v {
            toml::Value::String(s) => {
                let p = Path::new(s);
                if s.is_empty() || s.len() > 1024 || s.contains('\n') || p.is_absolute() {
                    return;
                }
                let full = dir.join(p);
                if full.is_file() {
                    if let Ok(c) = full.canonicalize() {
                        if !out.contains(&c) {
                            out.push(c);
                        }
                    }
                }
            }
            toml::Value::Array(a) => a.iter().for_each(|v| walk(v, dir, out)),
            toml::Value::Table(t) => t.values().for_each(|v| walk(v, dir, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    for v in table.values() {
        walk(v, dir, &mut out);
    }
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
    #[serde(default)]
    agent: Vec<RawAgent>,
    #[serde(default)]
    run: Vec<RawRun>,
    #[serde(default)]
    require: RawRequire,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawRequire {
    #[serde(default)]
    tcp: Vec<String>,
    #[serde(default)]
    udp: Vec<String>,
    #[serde(default)]
    traffic: Vec<String>,
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
        let (kind, raw) = match (self.tcp, self.udp, self.traffic) {
            (Some(w), None, None) => (CheckKind::Tcp, w),
            (None, Some(w), None) => (CheckKind::Udp, w),
            (None, None, Some(w)) => (CheckKind::Traffic, w),
            (None, None, None) => {
                return Err(Error::Profile(
                    "give what runs: tcp, udp or traffic (a profile file or a table)".into(),
                ))
            }
            _ => {
                return Err(Error::Profile(
                    "give one of tcp, udp and traffic; make another run for the other".into(),
                ))
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
        if kind != CheckKind::Traffic {
            for (set, what) in [
                (self.rx.is_some(), "rx"),
                (self.rx_agent.is_some(), "rx_agent"),
                (self.rx_wait.is_some(), "rx_wait"),
                (self.limit.is_some(), "limit"),
                (self.latency, "latency"),
            ] {
                if set {
                    return Err(Error::Profile(format!("{what} is for traffic runs")));
                }
            }
        }
        if kind != CheckKind::Tcp {
            for (set, what) in [
                (self.cps.is_some(), "cps"),
                (self.connections.is_some(), "connections"),
            ] {
                if set {
                    return Err(Error::Profile(format!("{what} is for TCP runs")));
                }
            }
        }
        if kind == CheckKind::Traffic && self.concurrency.is_some() {
            return Err(Error::Profile("concurrency is for TCP and UDP runs".into()));
        }
        if kind != CheckKind::Udp && self.transactions.is_some() {
            return Err(Error::Profile("transactions is for UDP runs".into()));
        }
        if kind == CheckKind::Traffic && self.impair_rx.is_some() {
            return Err(Error::Profile("impair_rx is for TCP and UDP runs".into()));
        }
        let rate = match self.rate {
            None => None,
            Some(toml::Value::String(s)) if kind == CheckKind::Traffic => {
                s.parse::<crate::Rate>()
                    .map_err(|e| Error::Profile(format!("rate: {e}")))?;
                Some(s)
            }
            Some(toml::Value::Integer(n)) if kind == CheckKind::Udp => Some(n.to_string()),
            Some(toml::Value::Float(n)) if kind == CheckKind::Udp => Some(n.to_string()),
            Some(_) if kind == CheckKind::Udp => {
                return Err(Error::Profile(
                    "rate: transactions per second, as a number".into(),
                ))
            }
            Some(_) if kind == CheckKind::Traffic => {
                return Err(Error::Profile(
                    "rate: a rate for every stream, e.g. \"10kpps\" or \"100mbps\"".into(),
                ))
            }
            Some(_) => return Err(Error::Profile("rate is for traffic and UDP runs".into())),
        };
        let dur = |s: Option<String>, what: &str| -> Result<Option<Duration>> {
            s.map(|s| parse_duration(&s).map_err(|e| Error::Profile(format!("{what}: {e}"))))
                .transpose()
        };
        if let Some(w) = &self.rx_wait {
            parse_duration(w).map_err(|e| Error::Profile(format!("rx_wait: {e}")))?;
        }
        let duration = dur(self.duration, "duration")?.or(default_duration);
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
            let text = substitute(&template, &all, &format!("{source} on agent '{n}'"))?;
            let ctx = |e: Error| Error::Profile(format!("{source} on agent '{n}': {e}"));
            // Read here first: a mistake shows before anything starts.
            match kind {
                CheckKind::Tcp => drop(TcpProfile::from_toml(&text, &dir).map_err(ctx)?),
                CheckKind::Udp => drop(UdpProfile::from_toml(&text, &dir).map_err(ctx)?),
                _ => drop(Profile::from_toml(&text, &dir).map_err(ctx)?),
            }
            let table: toml::Table =
                toml::from_str(&text).map_err(|e| Error::Profile(format!("{source}: {e}")))?;
            let iface = self.iface.clone().or_else(|| agent.iface.clone());
            if kind == CheckKind::Traffic && iface.is_none() {
                return Err(Error::Profile(format!(
                    "a traffic run needs iface, here or on agent '{n}'"
                )));
            }
            instances.push(FleetInstance {
                agent: n.clone(),
                text,
                files: files_named(&table, &dir),
                dir: dir.clone(),
                file_name: file_name.clone(),
                iface,
            });
        }
        let parse = |list: &[String]| {
            list.iter()
                .map(|c| Condition::parse(c, kind))
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
            },
            delay,
            require,
            require_each,
        })
    }
}

#[cfg(test)]
mod tests;
