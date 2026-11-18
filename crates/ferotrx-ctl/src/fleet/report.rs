//! The report of a fleet run: JSON (`ferotrx-fleet-1`) and text.

use std::collections::BTreeMap;

use ferotrx_core::scenario::{CheckKind, ConditionResult, Metrics};
use serde::{Deserialize, Serialize};

use ferotrx_core::DropCounters;

use crate::protocol::{Capabilities, RunState};

/// `format` of the JSON report.
pub const FLEET_REPORT_FORMAT: &str = "ferotrx-fleet-1";

/// An agent, as the controller found it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentRecord {
    pub name: String,
    pub address: String,
    pub version: String,
    pub tls: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default)]
    pub backends: Vec<String>,
    /// Round trip of a call.
    pub rtt_ms: f64,
    /// The agent's clock minus the controller's.
    pub offset_ms: f64,
    /// What the agent can run (agents from 0.51.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capabilities>,
    /// `ok`, `reconnected` (its control connection broke and came back) or
    /// `lost` (it did not come back; see `failure`).
    #[serde(default = "ok")]
    pub status: String,
    /// Times the controller connected again after losing it.
    #[serde(default)]
    pub reconnects: u32,
    /// What the agent's health readings said over the run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<AgentTelemetry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<AgentFailure>,
}

fn ok() -> String {
    "ok".into()
}

/// An agent's health over a fleet run (`server.health` once per interval).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentTelemetry {
    /// Readings taken.
    pub samples: u32,
    /// The machine's CPU load, in percent of all its CPUs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_avg_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_max_pct: Option<f64>,
    /// The agent process's share, at most.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_cpu_max_pct: Option<f64>,
    /// Memory available, at least.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_min_mb: Option<u64>,
    /// Its clock offset, as measured along the way: the lowest and highest.
    /// Their difference is how far the clocks drifted (or how uncertain the
    /// readings were).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset_min_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset_max_ms: Option<f64>,
    /// The slowest round trip of a reading.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_max_ms: Option<f64>,
    /// Frames dropped before they were read or sent, by layer, over the
    /// agent's runs ([`DropCounters`]).
    pub drops: DropCounters,
}

/// An agent the controller lost during the run.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentFailure {
    pub agent: String,
    /// When its control connection broke, in seconds from the shared start.
    pub at_s: f64,
    /// When the controller gave up on it.
    pub lost_at_s: f64,
    pub error: String,
    /// Its last answer, in seconds from the shared start: its counters in
    /// the report are from then.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_s: Option<f64>,
    /// The runs it had (`RUN` or `RUN (receiver)`): their parts on it are
    /// incomplete, and may still be going there.
    pub runs: Vec<String>,
}

impl AgentFailure {
    /// One line on it.
    pub fn line(&self) -> String {
        format!(
            "agent '{}' lost at {:.1} s ({}); it had {}; {}",
            self.agent,
            self.at_s,
            self.error,
            if self.runs.is_empty() {
                "no runs".to_string()
            } else {
                self.runs.join(", ")
            },
            match self.last_seen_s {
                Some(t) => format!("its counters are from {t:.1} s"),
                None => "no counters came from it".into(),
            }
        )
    }
}

/// One agent at one moment of the run.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentSample {
    pub agent: String,
    /// `up`, `down` (the controller is trying to reach it again) or `lost`.
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_cpu_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_available_mb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    /// The agent's runs going now, all kinds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub running: Option<usize>,
    /// Frames dropped so far over the plan's runs on it, by layer.
    pub drops: DropCounters,
}

/// A run's profile and files, sent to one agent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeployRecord {
    pub run: String,
    pub agent: String,
    /// The profile on the agent, relative to its data directory.
    pub profile: String,
    /// Files sent, and files the agent had already.
    pub files_sent: usize,
    pub files_kept: usize,
    pub bytes_sent: u64,
}

/// A capture on one agent during the fleet run (`[[capture]]`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CaptureRecord {
    pub agent: String,
    pub iface: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    /// The pcap on the agent, relative to its data directory.
    pub file: String,
    pub frames: u64,
    pub bytes: u64,
    /// Frames the agent's kernel or interface dropped.
    pub dropped: u64,
    pub if_dropped: u64,
    /// Where the controller saved it (`--collect`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collected: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One run on one agent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InstanceRecord {
    pub agent: String,
    /// The run's id on the agent.
    pub id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<RunState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// How much later than planned it started, by the controller's clock
    /// (the agent's clock offset taken off).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_late_ms: Option<f64>,
    /// The agent that received its traffic, when another one did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_agent: Option<String>,
    pub metrics: Metrics,
    /// The run's `require_each`, on this agent's counters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<ConditionResult>,
    /// The run as the agent reported it last (`run.stats`, `tcp.stats`, `udp.stats`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<serde_json::Value>,
    /// The receiver on the other agent (`rx.stats`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx: Option<serde_json::Value>,
}

/// A `[[run]]` of the plan: its agents, and their counters added up.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RunRecord {
    pub name: String,
    /// `tcp`, `udp`, `traffic`, `hosts`, `scenario`, `bench` or `y1564`.
    pub kind: String,
    pub source: String,
    pub instances: Vec<InstanceRecord>,
    pub metrics: Metrics,
    pub conditions: Vec<ConditionResult>,
    pub passed: bool,
}

/// The sums over every run, at one moment.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FleetSample {
    /// Seconds since the shared start (negative before it).
    pub t_s: f64,
    pub running: usize,
    pub runs: usize,
    /// By kind: `tcp`, `udp`, `traffic`, `hosts`, `scenario`, `bench`, `y1564`.
    pub totals: BTreeMap<String, Metrics>,
    /// Every agent's health and drops.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<AgentSample>,
}

/// What a fleet run did.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FleetReport {
    pub format: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The shared start, in Unix seconds by the controller's clock.
    pub started_at: f64,
    pub elapsed_s: f64,
    /// Every run without errors and every condition holding.
    pub passed: bool,
    /// Stopped before the runs ended (Ctrl-C).
    pub stopped: bool,
    /// The latest start minus the earliest, over every run on every agent,
    /// after the planned delays.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_spread_ms: Option<f64>,
    pub agents: Vec<AgentRecord>,
    pub deployed: Vec<DeployRecord>,
    pub runs: Vec<RunRecord>,
    /// Sums over every run of a kind.
    pub totals: BTreeMap<String, Metrics>,
    /// The plan's `[require]` on the sums.
    pub conditions: Vec<ConditionResult>,
    pub samples: Vec<FleetSample>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// The captures on the agents.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub captures: Vec<CaptureRecord>,
    /// The captures merged into one pcapng (`--merge`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merged: Option<String>,
    /// Agents lost during the run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<AgentFailure>,
}

/// The few metrics a line shows for a kind.
fn headline(kind: &str, m: &Metrics) -> String {
    let get = |k: &str| m.get(k).copied();
    let mut parts = Vec::new();
    let mut add = |label: &str, v: Option<f64>, f: &dyn Fn(f64) -> String| {
        if let Some(v) = v {
            parts.push(format!("{label} {}", f(v)));
        }
    };
    let int = |v: f64| format!("{v:.0}");
    let one = |v: f64| format!("{v:.1}");
    let pc = |v: f64| format!("{v:.2}%");
    let msf = |v: f64| format!("{v:.2}ms");
    match kind {
        "tcp" if get("connections") == Some(0.0) && get("server_connections") > Some(0.0) => {
            add("server: connections", get("server_connections"), &int);
            add("completed", get("server_completed"), &int);
            add("failed", get("server_failed"), &int);
        }
        "tcp" => {
            add("connections", get("connections"), &int);
            add("completed", get("completed"), &int);
            add("failed", get("failed"), &int);
            add("retransmits", get("retransmits"), &int);
            add("cps", get("cps"), &one);
        }
        "udp" => {
            add("transactions", get("transactions"), &int);
            add("answered", get("answered"), &int);
            add("timed out", get("timed_out"), &int);
            add("tps", get("tps"), &one);
        }
        "hosts" => {
            add("hosts", get("hosts"), &int);
            add("ready", get("ready"), &int);
            add("failed", get("failed"), &int);
            add("ready avg", get("ready_avg"), &msf);
        }
        "scenario" => {
            add("checks", get("checks"), &int);
            add("passed", get("checks_passed"), &int);
            add("failed", get("checks_failed"), &int);
        }
        "bench" => {
            add("trials", get("trials"), &int);
            add("throughput", get("throughput_pct"), &|v| format!("{v:.1}%"));
            add("Mbit/s", get("throughput_mbps"), &one);
            add("latency avg", get("latency_avg"), &msf);
        }
        "y1564" => {
            add("steps", get("steps"), &int);
            add("failed", get("steps_failed"), &int);
            add("FLR", get("flr_pct"), &pc);
            add("FTD", get("ftd"), &msf);
        }
        _ => {
            add("sent", get("tx_packets"), &int);
            add("Mbit/s", get("tx_mbps"), &|v| format!("{v:.3}"));
            add("received", get("rx_packets"), &int);
            add("loss", get("loss_pct"), &pc);
            add("latency avg", get("latency_avg"), &msf);
            add("p99", get("latency_p99"), &msf);
        }
    }
    parts.join(", ")
}

impl FleetSample {
    /// One line: the time and every kind's headline.
    pub fn line(&self) -> String {
        let mut s = format!("{:>6.1}s  {}/{} running", self.t_s, self.running, self.runs);
        for (kind, m) in &self.totals {
            s.push_str(&format!("  {kind}: {}", headline(kind, m)));
        }
        if !self.agents.is_empty() {
            let parts: Vec<String> = self
                .agents
                .iter()
                .map(|a| match (a.status.as_str(), a.cpu_pct) {
                    ("up", Some(c)) => format!("{} {c:.0}%", a.agent),
                    ("up", None) => a.agent.clone(),
                    (st, _) => format!("{} {}", a.agent, st.to_uppercase()),
                })
                .collect();
            s.push_str(&format!("  cpu: {}", parts.join(" ")));
        }
        s
    }
}

impl FleetReport {
    /// The report as text.
    pub fn text(&self) -> String {
        let mut out = String::new();
        let mut line = |s: String| {
            out.push_str(&s);
            out.push('\n');
        };
        line(format!("Fleet '{}'", self.name));
        if let Some(d) = &self.description {
            line(format!("  {d}"));
        }
        line(String::new());
        line("Agents:".into());
        line(format!(
            "  {:<12} {:<22} {:<8} {:>9} {:>11} {:>6} {:>8}  status",
            "agent", "address", "version", "rtt", "clock", "cpus", "cpu max"
        ));
        for a in &self.agents {
            let t = a.telemetry.as_ref();
            line(format!(
                "  {:<12} {:<22} {:<8} {:>7.2}ms {:>+9.1}ms {:>6} {:>8}  {}{}{}",
                a.name,
                a.address,
                a.version,
                a.rtt_ms,
                a.offset_ms,
                a.capabilities
                    .as_ref()
                    .map_or("?".to_string(), |c| c.cpus.to_string()),
                t.and_then(|t| t.cpu_max_pct)
                    .map_or("-".to_string(), |c| format!("{c:.0}%")),
                a.status,
                if a.reconnects > 0 {
                    format!(" ({}x)", a.reconnects)
                } else {
                    String::new()
                },
                if a.tls { ", tls" } else { "" }
            ));
            if let Some(t) = t {
                let mut extra = Vec::new();
                if let (Some(lo), Some(hi)) = (t.offset_min_ms, t.offset_max_ms) {
                    extra.push(format!("clock {lo:+.1}..{hi:+.1} ms"));
                }
                if let Some(m) = t.memory_min_mb {
                    extra.push(format!("memory free >= {m} MiB"));
                }
                let (rx, tx) = (t.drops.rx_total(), t.drops.tx_total());
                if rx + tx > 0 {
                    extra.push(format!(
                        "dropped {rx} received, {tx} sent ({})",
                        drops_text(&t.drops)
                    ));
                }
                if !extra.is_empty() {
                    line(format!("  {:<12} {}", "", extra.join("; ")));
                }
            }
        }
        for f in &self.failures {
            line(format!("LOST: {}", f.line()));
        }
        if !self.deployed.is_empty() {
            let sent: usize = self.deployed.iter().map(|d| d.files_sent).sum();
            let kept: usize = self.deployed.iter().map(|d| d.files_kept).sum();
            let bytes: u64 = self.deployed.iter().map(|d| d.bytes_sent).sum();
            line(format!(
                "Deployed {} profile(s); {sent} file(s) sent ({bytes} bytes), {kept} the agents had",
                self.deployed.len()
            ));
        }
        if let Some(s) = self.start_spread_ms {
            line(format!("Started within {s:.1} ms of each other"));
        }
        for n in &self.notes {
            line(format!("Note: {n}"));
        }
        line(String::new());
        for r in &self.runs {
            line(format!(
                "Run '{}' ({} {}): {}",
                r.name,
                r.kind,
                r.source,
                if r.passed { "PASS" } else { "FAIL" }
            ));
            for i in &r.instances {
                let state = i
                    .state
                    .map(|s| format!("{s:?}").to_lowercase())
                    .unwrap_or_else(|| "?".into());
                let mut l = format!(
                    "  {:<12} {:<9} {}",
                    i.agent,
                    state,
                    headline(&r.kind, &i.metrics)
                );
                if let Some(rx) = &i.rx_agent {
                    l.push_str(&format!(" (received on {rx})"));
                }
                if let Some(late) = i.start_late_ms {
                    l.push_str(&format!("; started {late:+.1} ms"));
                }
                if let Some(e) = &i.error {
                    l.push_str(&format!("; error: {e}"));
                }
                line(l);
                for c in &i.conditions {
                    line(condition_line(c));
                }
            }
            if r.instances.len() > 1 {
                line(format!(
                    "  {:<12} {:<9} {}",
                    "all",
                    "",
                    headline(&r.kind, &r.metrics)
                ));
            }
            for c in &r.conditions {
                line(condition_line(c));
            }
        }
        if !self.totals.is_empty() {
            line(String::new());
            line("Totals:".into());
            for (kind, m) in &self.totals {
                line(format!("  {kind}: {}", headline(kind, m)));
            }
            for c in &self.conditions {
                line(condition_line(c));
            }
        }
        if !self.captures.is_empty() {
            line(String::new());
            line("Captures:".into());
            for c in &self.captures {
                let mut l = format!(
                    "  {:<12} {:<10} {:>8} frames {:>12} bytes, {} dropped",
                    c.agent,
                    c.iface,
                    c.frames,
                    c.bytes,
                    c.dropped + c.if_dropped
                );
                match (&c.collected, &c.error) {
                    (_, Some(e)) => l.push_str(&format!("  error: {e}")),
                    (Some(f), None) => l.push_str(&format!("  -> {f}")),
                    (None, None) => l.push_str(&format!("  on the agent: {}", c.file)),
                }
                line(l);
            }
            if let Some(m) = &self.merged {
                line(format!("  merged into {m}"));
            }
        }
        line(String::new());
        line(format!(
            "Fleet: {}{}",
            if self.passed { "PASS" } else { "FAIL" },
            if self.stopped { " (stopped)" } else { "" }
        ));
        out
    }

    /// Runs that failed, by name.
    pub fn failed_runs(&self) -> Vec<&str> {
        self.runs
            .iter()
            .filter(|r| !r.passed)
            .map(|r| r.name.as_str())
            .collect()
    }

    /// The sums of one kind.
    pub fn total(&self, kind: CheckKind) -> Option<&Metrics> {
        self.totals.get(kind.as_str())
    }

    /// The sums of one kind of run.
    pub fn total_of(&self, kind: ferotrx_core::fleet::FleetKind) -> Option<&Metrics> {
        self.totals.get(kind.as_str())
    }
}

/// The layers that dropped frames, e.g. `capture 12, nic_rx_missed 3`.
fn drops_text(d: &DropCounters) -> String {
    [
        ("nic_rx_missed", d.nic_rx_missed),
        ("nic_rx_errors", d.nic_rx_errors),
        ("ring_rx_dropped", d.ring_rx_dropped),
        ("capture", d.capture_dropped),
        ("nic_tx_errors", d.nic_tx_errors),
        ("ring_tx_invalid", d.ring_tx_invalid),
    ]
    .into_iter()
    .filter(|(_, n)| *n > 0)
    .map(|(k, n)| format!("{k} {n}"))
    .collect::<Vec<_>>()
    .join(", ")
}

fn condition_line(c: &ConditionResult) -> String {
    format!(
        "    {} {}{}",
        if c.pass { "ok  " } else { "FAIL" },
        c.condition,
        match c.actual {
            Some(v) => format!(" (got {v:.3})"),
            None => " (not measured)".into(),
        }
    )
}
