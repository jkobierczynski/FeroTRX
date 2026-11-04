//! Scenarios: a list of checks with expected outcomes, for regression tests.
//!
//! A scenario answers "did this change to the network break anything?". Each
//! check is a run (stateful TCP, stateful UDP or stateless streams with a
//! receiver) and what should come of it: the sessions complete, or are
//! blocked, and conditions on what was measured (`loss_pct < 1%`,
//! `latency_p99 < 20ms`, `rx_mbps > 50Mbit/s`). [`run_scenario`] runs the
//! checks one after the other through a [`CheckRunner`] (the `ferotrx-ctl`
//! crate has the one that opens interfaces) and returns a [`ScenarioReport`]
//! with a verdict per check, which is saved as JSON and JUnit XML, and which
//! [`compare`] holds against an earlier run.
//!
//! ```toml
//! name = "branch-router"
//! iface = "enp0s3"          # default interface of the checks
//! attempts = 2              # run a failing check again once (a jittery VM)
//!
//! [vars]                    # ${NAME} anywhere below; `--set NAME=...` overrides
//! server = "192.168.20.80"
//!
//! [[check]]
//! name = "web through NAT"
//! tcp = "lab-tcp.toml"      # a TCP profile file, or a [check.tcp] table
//! require = ["completed_pct >= 99%", "cps > 10"]
//!
//! [[check]]
//! name = "telnet is blocked"
//! expect = "blocked"
//! duration = "3s"
//! [check.tcp]
//! port = 23
//! connections = 3
//! [[check.tcp.message]]
//! from = "client"
//! text = "hello"
//! [check.tcp.client]
//! ip = "192.168.10.100/24"
//! gateway = "192.168.10.1"
//! [check.tcp.server]
//! ip = "${server}/24"
//! ```

mod collect;
mod metric;
mod report;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::{parse_duration, Error, Profile, Result, TcpProfile, UdpProfile};

pub use collect::{
    tcp_metrics, tcp_summary, traffic_metrics, traffic_summary, udp_metrics, udp_summary,
};
pub use metric::{
    Better, CheckKind, Condition, MetricDef, Metrics, Op, Unit, TCP_METRICS, TRAFFIC_METRICS,
    UDP_METRICS,
};
pub use report::{
    check_line, compare, format_utc, run_scenario, Change, CheckChange, CheckReport, CheckRun,
    CheckRunner, Comparison, ConditionResult, MetricChange, Progress, RunOptions, ScenarioReport,
    Summary, Verdict, REPORT_FORMAT,
};

/// What a check expects of its run, besides its own conditions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Expect {
    /// Every session completes as captured (TCP: every connection
    /// completed; UDP: every transaction answered; traffic: packets arrive).
    #[default]
    Complete,
    /// Nothing gets through: no TCP handshake, no UDP answer, no packet
    /// received. The client must have tried.
    Blocked,
    /// Only the check's own conditions.
    Any,
}

impl Expect {
    pub fn as_str(self) -> &'static str {
        match self {
            Expect::Complete => "complete",
            Expect::Blocked => "blocked",
            Expect::Any => "any",
        }
    }

    fn parse(s: &str) -> Result<Expect> {
        match s {
            "complete" | "completes" | "pass" | "passes" => Ok(Expect::Complete),
            "blocked" | "block" | "fail" | "fails" => Ok(Expect::Blocked),
            "any" | "none" => Ok(Expect::Any),
            other => Err(Error::Profile(format!(
                "expect = '{other}': give complete, blocked or any"
            ))),
        }
    }

    /// The conditions this expectation stands for, for a check of `kind`.
    pub fn conditions(self, kind: CheckKind) -> Vec<Condition> {
        use Op::*;
        let c = Condition::built_in;
        match (kind, self) {
            (_, Expect::Any) => Vec::new(),
            (CheckKind::Tcp, Expect::Complete) => vec![
                c("connections", Gt, 0.0),
                c("completed_pct", Eq, 100.0),
                c("mismatched", Eq, 0.0),
            ],
            (CheckKind::Tcp, Expect::Blocked) => {
                vec![c("connections", Gt, 0.0), c("established", Eq, 0.0)]
            }
            (CheckKind::Udp, Expect::Complete) => vec![
                c("transactions", Gt, 0.0),
                c("answered_pct", Eq, 100.0),
                c("mismatched", Eq, 0.0),
            ],
            (CheckKind::Udp, Expect::Blocked) => {
                vec![c("transactions", Gt, 0.0), c("answered", Eq, 0.0)]
            }
            (CheckKind::Traffic, Expect::Complete) => {
                vec![c("tx_packets", Gt, 0.0), c("rx_packets", Gt, 0.0)]
            }
            (CheckKind::Traffic, Expect::Blocked) => {
                vec![c("tx_packets", Gt, 0.0), c("rx_packets", Eq, 0.0)]
            }
        }
    }
}

/// The run of a check.
#[derive(Clone, Debug)]
pub enum Workload {
    Tcp(TcpProfile),
    Udp(UdpProfile),
    /// Stateless streams; every stream carries a latency signature unless
    /// the profile marks some.
    Traffic(Profile),
}

impl Workload {
    pub fn kind(&self) -> CheckKind {
        match self {
            Workload::Tcp(_) => CheckKind::Tcp,
            Workload::Udp(_) => CheckKind::Udp,
            Workload::Traffic(_) => CheckKind::Traffic,
        }
    }
}

/// How long a traffic check keeps receiving after the last packet, unless set.
pub const DEFAULT_RX_WAIT: Duration = Duration::from_millis(500);

/// One check of a [`Scenario`].
#[derive(Clone, Debug)]
pub struct Check {
    pub name: String,
    pub description: Option<String>,
    pub workload: Workload,
    /// Where the profile came from: a file, or `inline`.
    pub source: String,
    /// Interface for hosts (TCP, UDP) whose table names none; for traffic,
    /// the interface sent on.
    pub iface: Option<String>,
    /// Traffic: the interface received on.
    pub rx: Option<String>,
    /// Traffic: how long to keep receiving after the last packet.
    pub rx_wait: Duration,
    /// Stop the run after this long (the profile's own `duration` otherwise).
    pub duration: Option<Duration>,
    pub expect: Expect,
    /// The check's own conditions (`require`).
    pub require: Vec<Condition>,
    /// Runs before the check is failed: a failing check is run again, up to
    /// this many times in all.
    pub attempts: u32,
}

impl Check {
    pub fn kind(&self) -> CheckKind {
        self.workload.kind()
    }

    /// Every condition the check is judged by: the expectation's, then its own.
    pub fn conditions(&self) -> Vec<Condition> {
        let mut all = self.expect.conditions(self.kind());
        all.extend(self.require.iter().cloned());
        all
    }
}

/// A scenario file: named checks with expected outcomes.
#[derive(Clone, Debug)]
pub struct Scenario {
    pub name: String,
    pub description: Option<String>,
    /// The file it was read from.
    pub path: Option<PathBuf>,
    /// The variables, after `--set` overrides.
    pub vars: BTreeMap<String, String>,
    pub checks: Vec<Check>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScenario {
    format: Option<u32>,
    name: Option<String>,
    description: Option<String>,
    /// Read in a first pass, before the variables are filled in.
    #[serde(default)]
    #[allow(dead_code)]
    vars: toml::Table,
    iface: Option<String>,
    rx: Option<String>,
    rx_wait: Option<String>,
    duration: Option<String>,
    attempts: Option<u32>,
    #[serde(default)]
    check: Vec<RawCheck>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCheck {
    name: Option<String>,
    description: Option<String>,
    tcp: Option<RawWorkload>,
    udp: Option<RawWorkload>,
    traffic: Option<RawWorkload>,
    iface: Option<String>,
    rx: Option<String>,
    rx_wait: Option<String>,
    duration: Option<String>,
    expect: Option<String>,
    #[serde(default)]
    require: Vec<String>,
    attempts: Option<u32>,
}

/// A profile file, or the profile's tables right in the scenario.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawWorkload {
    Path(String),
    Inline(toml::Table),
}

fn duration(s: Option<String>, what: &str) -> Result<Option<Duration>> {
    s.map(|s| parse_duration(&s).map_err(|e| Error::Profile(format!("{what}: {e}"))))
        .transpose()
}

/// Replaces `${NAME}` with the variable's value.
fn substitute(text: &str, vars: &BTreeMap<String, String>, what: &str) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("${") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| Error::Profile(format!("{what}: '${{' without a closing '}}'")))?;
        let name = after[..end].trim();
        let value = vars.get(name).ok_or_else(|| {
            Error::Profile(format!(
                "{what}: ${{{name}}} is not set; add it to [vars] or give --set {name}=VALUE"
            ))
        })?;
        out.push_str(value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// `${...}` replaced by `0`, which is valid TOML both as a value and inside
/// a string, so the `[vars]` table can be read before the variables are known.
fn blank_vars(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("${") {
        out.push_str(&rest[..i]);
        match rest[i..].find('}') {
            Some(end) => {
                out.push('0');
                rest = &rest[i + end + 1..];
            }
            None => {
                rest = &rest[i..];
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

fn var_value(name: &str, v: &toml::Value) -> Result<String> {
    match v {
        toml::Value::String(s) => Ok(s.clone()),
        toml::Value::Integer(i) => Ok(i.to_string()),
        toml::Value::Float(f) => Ok(f.to_string()),
        toml::Value::Boolean(b) => Ok(b.to_string()),
        _ => Err(Error::Profile(format!(
            "[vars] {name}: give a string, number or boolean"
        ))),
    }
}

impl Scenario {
    /// Reads a scenario file. `overrides` replace or add `[vars]`.
    pub fn from_path(path: impl AsRef<Path>, overrides: &[(String, String)]) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Profile(format!("cannot read {}: {e}", path.display())))?;
        let mut s = Self::from_toml(&text, path.parent().unwrap_or(Path::new(".")), overrides)?;
        s.path = Some(path.to_path_buf());
        if s.name.is_empty() {
            s.name = path
                .file_stem()
                .map_or("scenario".into(), |n| n.to_string_lossy().into_owned());
        }
        Ok(s)
    }

    /// Parses a scenario; profile files and their pcaps are relative to `base_dir`.
    pub fn from_toml(text: &str, base_dir: &Path, overrides: &[(String, String)]) -> Result<Self> {
        Self::from_toml_with(text, base_dir, overrides, &|p: &Path| Ok(p.to_path_buf()))
    }

    /// [`from_toml`](Scenario::from_toml), asking `allow` before a profile
    /// file is read: it returns the path to read, or why the file may not
    /// be read (a server that only reads files in its data directories).
    pub fn from_toml_with(
        text: &str,
        base_dir: &Path,
        overrides: &[(String, String)],
        allow: &dyn Fn(&Path) -> std::result::Result<PathBuf, String>,
    ) -> Result<Self> {
        // The variables first, then the text with them filled in.
        let blank: toml::Table = toml::from_str(&blank_vars(text))
            .map_err(|e| Error::Profile(format!("scenario: {e}")))?;
        let mut vars = BTreeMap::new();
        if let Some(t) = blank.get("vars") {
            let toml::Value::Table(t) = t else {
                return Err(Error::Profile("`vars` must be a table".into()));
            };
            // Read from the real text: a value may hold "${" only if it is not a variable.
            let raw: toml::Table = toml::from_str(text).unwrap_or_default();
            let real = raw.get("vars").and_then(|v| v.as_table()).unwrap_or(t);
            for (k, v) in real {
                vars.insert(k.clone(), var_value(k, v)?);
            }
        }
        for (k, v) in overrides {
            vars.insert(k.clone(), v.clone());
        }
        let text = substitute(text, &vars, "scenario")?;
        let raw: RawScenario =
            toml::from_str(&text).map_err(|e| Error::Profile(format!("scenario: {e}")))?;
        crate::check_format(raw.format)?;
        let defaults_wait = duration(raw.rx_wait, "rx_wait")?;
        let defaults_duration = duration(raw.duration, "duration")?;
        if raw.check.is_empty() {
            return Err(Error::Profile(
                "a scenario needs at least one [[check]]".into(),
            ));
        }
        let mut checks = Vec::with_capacity(raw.check.len());
        for (i, c) in raw.check.into_iter().enumerate() {
            let name = c.name.clone().unwrap_or_else(|| format!("check {}", i + 1));
            let ctx = |e: Error| match e {
                Error::Profile(m) => Error::Profile(format!("check '{name}': {m}")),
                e => Error::Profile(format!("check '{name}': {e}")),
            };
            let check = Self::check(
                c,
                name.clone(),
                base_dir,
                allow,
                &vars,
                (
                    &raw.iface,
                    &raw.rx,
                    defaults_wait,
                    defaults_duration,
                    raw.attempts,
                ),
            )
            .map_err(ctx)?;
            if checks.iter().any(|o: &Check| o.name == check.name) {
                return Err(Error::Profile(format!(
                    "two checks are called '{}'; reports and comparisons go by name",
                    check.name
                )));
            }
            checks.push(check);
        }
        Ok(Scenario {
            name: raw.name.unwrap_or_default(),
            description: raw.description,
            path: None,
            vars,
            checks,
        })
    }

    #[allow(clippy::type_complexity)]
    fn check(
        c: RawCheck,
        name: String,
        base_dir: &Path,
        allow: &dyn Fn(&Path) -> std::result::Result<PathBuf, String>,
        vars: &BTreeMap<String, String>,
        defaults: (
            &Option<String>,
            &Option<String>,
            Option<Duration>,
            Option<Duration>,
            Option<u32>,
        ),
    ) -> Result<Check> {
        let (iface, rx, rx_wait, dur, attempts) = defaults;
        let (kind, raw) = match (c.tcp, c.udp, c.traffic) {
            (Some(w), None, None) => (CheckKind::Tcp, w),
            (None, Some(w), None) => (CheckKind::Udp, w),
            (None, None, Some(w)) => (CheckKind::Traffic, w),
            (None, None, None) => {
                return Err(Error::Profile(
                    "give the run: tcp, udp or traffic (a profile file or a table)".into(),
                ))
            }
            _ => {
                return Err(Error::Profile(
                    "give one of tcp, udp and traffic; make another check for the other".into(),
                ))
            }
        };
        let (text, dir, source) = match raw {
            RawWorkload::Path(p) => {
                let path = allow(&base_dir.join(&p)).map_err(Error::Profile)?;
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| Error::Profile(format!("cannot read {}: {e}", path.display())))?;
                let text = substitute(&text, vars, &p)?;
                let dir = path.parent().unwrap_or(base_dir).to_path_buf();
                (text, dir, p)
            }
            RawWorkload::Inline(t) => (
                toml::to_string(&t).map_err(|e| Error::Profile(e.to_string()))?,
                base_dir.to_path_buf(),
                "inline".to_string(),
            ),
        };
        let workload = match kind {
            CheckKind::Tcp => Workload::Tcp(TcpProfile::from_toml(&text, &dir)?),
            CheckKind::Udp => Workload::Udp(UdpProfile::from_toml(&text, &dir)?),
            CheckKind::Traffic => Workload::Traffic(Profile::from_toml(&text, &dir)?),
        };
        let expect = c
            .expect
            .as_deref()
            .map(Expect::parse)
            .transpose()?
            .unwrap_or_default();
        let require = c
            .require
            .iter()
            .map(|r| Condition::parse(r, kind))
            .collect::<Result<Vec<_>>>()?;
        let attempts = c.attempts.or(attempts).unwrap_or(1);
        if attempts == 0 {
            return Err(Error::Profile("attempts must be at least 1".into()));
        }
        let check = Check {
            name,
            description: c.description,
            workload,
            source,
            iface: c.iface.or_else(|| iface.clone()),
            rx: c.rx.or_else(|| rx.clone()),
            rx_wait: duration(c.rx_wait, "rx_wait")?
                .or(rx_wait)
                .unwrap_or(DEFAULT_RX_WAIT),
            duration: duration(c.duration, "duration")?.or(dur),
            expect,
            require,
            attempts,
        };
        if kind == CheckKind::Traffic {
            if check.rx.is_none() {
                return Err(Error::Profile(
                    "a traffic check needs `rx`, the interface to receive on".into(),
                ));
            }
            if check.iface.is_none() {
                return Err(Error::Profile(
                    "a traffic check needs `iface`, the interface to send on".into(),
                ));
            }
        }
        if check.conditions().is_empty() {
            return Err(Error::Profile(
                "expect = \"any\" needs conditions in `require`".into(),
            ));
        }
        Ok(check)
    }

    /// Sets the interface of every check that has none (`--iface`).
    pub fn set_default_iface(&mut self, iface: &str) {
        for c in &mut self.checks {
            if c.iface.is_none() {
                c.iface = Some(iface.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCENARIO: &str = r#"
name = "lab"
description = "the lab router"
iface = "eth1"
attempts = 2

[vars]
server = "10.9.0.2"
port = 80

[[check]]
name = "web"
require = ["cps > 5", "retransmits <= 10"]
[check.tcp]
port = ${port}
connections = 4
[[check.tcp.message]]
from = "client"
text = "GET /"
[[check.tcp.message]]
from = "server"
text = "200 OK"
[check.tcp.client]
ip = "10.9.0.1"
[check.tcp.server]
ip = "${server}"

[[check]]
name = "dns blocked"
expect = "blocked"
duration = "2s"
attempts = 1
[check.udp]
queries = ["www.lab.local A"]
records = ["www.lab.local A 10.9.0.80"]
[check.udp.client]
ip = "10.9.0.1"
[check.udp.server]
ip = "${server}"

[[check]]
name = "stream"
rx = "eth2"
rx_wait = "1s"
require = ["loss_pct < 1%", "latency_p99 < 20ms"]
[check.traffic]
[[check.traffic.stream]]
name = "s"
packet = "eth/ipv4(dst=${server})/udp/raw(len=100)"
"#;

    #[test]
    fn scenario_parses_with_vars_and_defaults() {
        let s = Scenario::from_toml(SCENARIO, Path::new("."), &[]).unwrap();
        assert_eq!(s.name, "lab");
        assert_eq!(s.checks.len(), 3);
        assert_eq!(s.vars["port"], "80");
        let web = &s.checks[0];
        assert_eq!(web.kind(), CheckKind::Tcp);
        assert_eq!(web.iface.as_deref(), Some("eth1"));
        assert_eq!(web.attempts, 2);
        assert_eq!(web.expect, Expect::Complete);
        let names: Vec<_> = web.conditions().iter().map(|c| c.metric.clone()).collect();
        assert_eq!(
            names,
            [
                "connections",
                "completed_pct",
                "mismatched",
                "cps",
                "retransmits"
            ]
        );
        let Workload::Tcp(p) = &web.workload else {
            panic!()
        };
        assert_eq!(p.connections, 4);
        assert_eq!(p.server.as_ref().unwrap().ip.to_string(), "10.9.0.2");
        assert_eq!(web.source, "inline");

        let dns = &s.checks[1];
        assert_eq!((dns.kind(), dns.expect), (CheckKind::Udp, Expect::Blocked));
        assert_eq!(dns.duration, Some(Duration::from_secs(2)));
        assert_eq!(dns.attempts, 1);

        let stream = &s.checks[2];
        assert_eq!(stream.kind(), CheckKind::Traffic);
        assert_eq!(stream.rx.as_deref(), Some("eth2"));
        assert_eq!(stream.rx_wait, Duration::from_secs(1));
    }

    #[test]
    fn overrides_replace_vars() {
        let set = [("server".to_string(), "10.9.0.3".to_string())];
        let s = Scenario::from_toml(SCENARIO, Path::new("."), &set).unwrap();
        let Workload::Tcp(p) = &s.checks[0].workload else {
            panic!()
        };
        assert_eq!(p.server.as_ref().unwrap().ip.to_string(), "10.9.0.3");
        assert_eq!(s.vars["server"], "10.9.0.3");
    }

    #[test]
    fn mistakes_are_explained() {
        let err = |text: &str| {
            Scenario::from_toml(text, Path::new("."), &[])
                .unwrap_err()
                .to_string()
        };
        let e = err("name = \"x\"\n");
        assert!(e.contains("at least one [[check]]"), "{e}");
        let e = err("[[check]]\nname = \"a\"\n");
        assert!(e.contains("tcp, udp or traffic"), "{e}");
        let e = err("[[check]]\nname = \"a\"\ntcp = \"x.toml\"\nudp = \"y.toml\"\n");
        assert!(e.contains("one of tcp, udp and traffic"), "{e}");
        let e = err("[[check]]\nname = \"a\"\ntcp = \"${nope}.toml\"\n");
        assert!(e.contains("${nope} is not set"), "{e}");
        let e = err("[[check]]\nname = \"a\"\ntcp = \"/no/such/file.toml\"\n");
        assert!(
            e.contains("check 'a': cannot read /no/such/file.toml"),
            "{e}"
        );
        let tcp = "[check.tcp]\nport = 80\n[[check.tcp.message]]\nfrom = \"client\"\ntext = \"x\"\n[check.tcp.client]\nip = \"10.0.0.1\"\n";
        let e = err(&format!(
            "[[check]]\nname = \"a\"\nrequire = [\"loss_pct < 1%\"]\n{tcp}"
        ));
        assert!(e.contains("check 'a': condition 'loss_pct < 1%'"), "{e}");
        let e = err(&format!(
            "[[check]]\nname = \"a\"\nexpect = \"maybe\"\n{tcp}"
        ));
        assert!(e.contains("complete, blocked or any"), "{e}");
        let e = err(&format!("[[check]]\nname = \"a\"\nexpect = \"any\"\n{tcp}"));
        assert!(e.contains("needs conditions"), "{e}");
        let e = err(&format!(
            "[[check]]\nname = \"a\"\n{tcp}[[check]]\nname = \"a\"\n{tcp}"
        ));
        assert!(e.contains("two checks are called 'a'"), "{e}");
        let e = err("[[check]]\nname = \"a\"\n[check.traffic]\n[[check.traffic.stream]]\npacket = \"eth/ipv4/udp\"\n");
        assert!(e.contains("needs `rx`"), "{e}");
        let e = err("[[check]]\nname = \"a\"\ncolor = \"red\"\n");
        assert!(e.contains("unknown field `color`"), "{e}");
    }

    #[test]
    fn profile_files_get_vars_too() {
        let dir = std::env::temp_dir().join(format!("ferotrx-scenario-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("web.toml"),
            "port = ${port}\nconnections = ${n}\n[[message]]\nfrom = \"client\"\ntext = \"x\"\n[client]\nip = \"10.0.0.1\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("s.toml"),
            "[vars]\nport = 8080\nn = 3\n[[check]]\nname = \"web\"\ntcp = \"web.toml\"\n",
        )
        .unwrap();
        let s = Scenario::from_path(dir.join("s.toml"), &[("n".into(), "7".into())]).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(s.name, "s");
        let Workload::Tcp(p) = &s.checks[0].workload else {
            panic!()
        };
        assert_eq!(p.connections, 7);
        assert_eq!(s.checks[0].source, "web.toml");
    }

    #[test]
    fn substitution() {
        let vars: BTreeMap<String, String> = [("a".to_string(), "1".to_string())].into();
        assert_eq!(substitute("x${a}y${ a }", &vars, "t").unwrap(), "x1y1");
        assert!(substitute("x${a", &vars, "t").is_err());
        assert_eq!(
            blank_vars("p = ${p}\nq = \"${q}/24\""),
            "p = 0\nq = \"0/24\""
        );
    }
}
