//! The report of a fleet run: JSON (`ferotrx-fleet-1`) and text.

use std::collections::BTreeMap;

use ferotrx_core::scenario::{CheckKind, ConditionResult, Metrics};
use serde::{Deserialize, Serialize};

use crate::protocol::RunState;

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
    /// `tcp`, `udp` or `traffic`.
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
    /// By kind: `tcp`, `udp`, `traffic`.
    pub totals: BTreeMap<String, Metrics>,
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
            "  {:<12} {:<22} {:<8} {:>9} {:>11}",
            "agent", "address", "version", "rtt", "clock"
        ));
        for a in &self.agents {
            line(format!(
                "  {:<12} {:<22} {:<8} {:>7.2}ms {:>+9.1}ms{}",
                a.name,
                a.address,
                a.version,
                a.rtt_ms,
                a.offset_ms,
                if a.tls { "  tls" } else { "" }
            ));
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
