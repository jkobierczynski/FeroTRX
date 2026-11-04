//! What a check measures, and the conditions on it: `loss_pct < 1%`.

use std::collections::BTreeMap;
use std::fmt;

use crate::{Error, Result};

/// A check's measurements, by metric name. Percentages are 0 to 100, times
/// in milliseconds, throughput in Mbit/s (10^6 bits), rates per second.
pub type Metrics = BTreeMap<String, f64>;

/// What kind of run a check is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CheckKind {
    /// Stateful TCP connections ([`TcpProfile`](crate::TcpProfile)).
    Tcp,
    /// Stateful UDP transactions ([`UdpProfile`](crate::UdpProfile)).
    Udp,
    /// Stateless streams ([`Profile`](crate::Profile)) with a receiver for
    /// loss, latency and throughput.
    Traffic,
}

impl CheckKind {
    pub const ALL: [CheckKind; 3] = [CheckKind::Tcp, CheckKind::Udp, CheckKind::Traffic];

    pub fn as_str(self) -> &'static str {
        match self {
            CheckKind::Tcp => "tcp",
            CheckKind::Udp => "udp",
            CheckKind::Traffic => "traffic",
        }
    }

    /// The kind called `name`, as in reports.
    pub fn from_name(name: &str) -> Option<CheckKind> {
        CheckKind::ALL.into_iter().find(|k| k.as_str() == name)
    }

    /// The metrics a check of this kind reports.
    pub fn metrics(self) -> &'static [MetricDef] {
        match self {
            CheckKind::Tcp => TCP_METRICS,
            CheckKind::Udp => UDP_METRICS,
            CheckKind::Traffic => TRAFFIC_METRICS,
        }
    }

    /// The metric called `name`.
    pub fn metric(self, name: &str) -> Option<&'static MetricDef> {
        self.metrics().iter().find(|m| m.name == name)
    }
}

impl fmt::Display for CheckKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The unit of a metric, and what a condition's value may be written in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    /// A plain number of things.
    Count,
    /// 0 to 100; `1%` or `1`.
    Percent,
    /// Milliseconds; `5ms`, `500us`, `1s` or a plain number of milliseconds.
    Millis,
    /// Mbit/s; `20Mbit/s`, `500kbit/s`, `1Gbit/s` or a plain number of Mbit/s.
    Mbps,
    /// Per second; `100/s`, `100pps`, `100cps`, `100tps` or a plain number.
    PerSecond,
}

impl Unit {
    /// `value` in this unit, for reports: `95.2%`, `5.12ms`.
    pub fn format(self, value: f64) -> String {
        let num = |v: f64| {
            if v == v.trunc() && v.abs() < 1e15 {
                format!("{v:.0}")
            } else if v.abs() >= 100.0 {
                format!("{v:.1}")
            } else {
                format!("{v:.3}")
                    .trim_end_matches('0')
                    .trim_end_matches('.')
                    .to_string()
            }
        };
        match self {
            Unit::Count => num(value),
            Unit::Percent => format!("{}%", num(value)),
            Unit::Millis => format!("{}ms", num(value)),
            Unit::Mbps => format!("{} Mbit/s", num(value)),
            Unit::PerSecond => format!("{}/s", num(value)),
        }
    }

    /// Parses a value written in this unit, giving it in the metric's unit.
    fn parse(self, text: &str) -> std::result::Result<f64, String> {
        let text = text.trim();
        let split = text
            .find(|c: char| !(c.is_ascii_digit() || matches!(c, '.' | '-' | '+' | 'e' | 'E')))
            .unwrap_or(text.len());
        // An exponent needs digits before it: "5e" is not a number.
        let (num, suffix) = text.split_at(split);
        let value: f64 = num
            .parse()
            .map_err(|_| format!("'{text}' does not start with a number"))?;
        if !value.is_finite() {
            return Err(format!("'{text}' is not a finite number"));
        }
        let suffix = suffix.trim();
        let factor = match (self, suffix.to_ascii_lowercase().as_str()) {
            (_, "") => 1.0,
            (Unit::Percent, "%") => 1.0,
            (Unit::Millis, "ms") => 1.0,
            (Unit::Millis, "us" | "µs") => 1e-3,
            (Unit::Millis, "ns") => 1e-6,
            (Unit::Millis, "s") => 1e3,
            (Unit::Mbps, "mbit/s" | "mbps" | "mb/s") => 1.0,
            (Unit::Mbps, "kbit/s" | "kbps" | "kb/s") => 1e-3,
            (Unit::Mbps, "gbit/s" | "gbps" | "gb/s") => 1e3,
            (Unit::Mbps, "bit/s" | "bps") => 1e-6,
            (Unit::PerSecond, "/s" | "pps" | "cps" | "tps") => 1.0,
            (unit, s) => {
                let want = match unit {
                    Unit::Count => "a plain number",
                    Unit::Percent => "a percentage, e.g. 1%",
                    Unit::Millis => "a time, e.g. 5ms, 500us or 1s",
                    Unit::Mbps => "a rate in bit/s, e.g. 20Mbit/s or 500kbit/s",
                    Unit::PerSecond => "a rate per second, e.g. 100/s",
                };
                return Err(format!("unit '{s}' does not fit: give {want}"));
            }
        };
        Ok(value * factor)
    }
}

/// Which way a metric should move: used when comparing two runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Better {
    Lower,
    Higher,
    /// Neither is better, e.g. the number of connections asked for.
    Neither,
}

/// A metric a check can report and conditions can test.
#[derive(Clone, Copy, Debug)]
pub struct MetricDef {
    pub name: &'static str,
    pub unit: Unit,
    pub better: Better,
    pub help: &'static str,
}

const fn m(name: &'static str, unit: Unit, better: Better, help: &'static str) -> MetricDef {
    MetricDef {
        name,
        unit,
        better,
        help,
    }
}

use Better::{Higher, Lower, Neither};
use Unit::{Count, Mbps, Millis, PerSecond, Percent};

/// Metrics of a TCP check: the client side, and the server's with `server_`.
pub const TCP_METRICS: &[MetricDef] = &[
    m(
        "connections",
        Count,
        Neither,
        "connections the client opened",
    ),
    m(
        "established",
        Count,
        Higher,
        "connections that finished the handshake",
    ),
    m(
        "established_pct",
        Percent,
        Higher,
        "established, of the connections opened",
    ),
    m(
        "completed",
        Count,
        Higher,
        "connections that played the whole session and closed",
    ),
    m(
        "completed_pct",
        Percent,
        Higher,
        "completed, of the connections opened",
    ),
    m("failed", Count, Lower, "connections reset or timed out"),
    m(
        "failed_pct",
        Percent,
        Lower,
        "failed, of the connections opened",
    ),
    m("reset", Count, Lower, "connections ended by a reset"),
    m(
        "timed_out",
        Count,
        Lower,
        "connections given up after retransmissions or idle time",
    ),
    m(
        "mismatched",
        Count,
        Lower,
        "connections that received other bytes than the capture",
    ),
    m(
        "open",
        Count,
        Lower,
        "connections still open when the run ended",
    ),
    m("retransmits", Count, Lower, "segments sent again"),
    m("timeouts", Count, Lower, "retransmission timeouts"),
    m("cps", PerSecond, Higher, "completed connections per second"),
    m(
        "server_connections",
        Count,
        Neither,
        "connections the server accepted",
    ),
    m(
        "server_completed",
        Count,
        Higher,
        "connections the server completed",
    ),
    m(
        "server_failed",
        Count,
        Lower,
        "server connections reset or timed out",
    ),
    m(
        "server_mismatched",
        Count,
        Lower,
        "server connections that received other bytes",
    ),
    m(
        "app_transactions",
        Count,
        Higher,
        "application transactions the client finished (HTTP requests answered, DNS queries)",
    ),
    m(
        "app_failed",
        Count,
        Lower,
        "application transactions that did not go as expected (status, response code)",
    ),
    m(
        "app_failed_pct",
        Percent,
        Lower,
        "failed, of the application transactions",
    ),
    m(
        "app_errors",
        Count,
        Neither,
        "answers with an error status or code (HTTP 4xx/5xx, DNS NXDOMAIN...)",
    ),
    m(
        "protocol_errors",
        Count,
        Lower,
        "things the server sent that the application protocol could not take",
    ),
    m("response_min", Millis, Lower, "fastest application answer"),
    m(
        "response_avg",
        Millis,
        Lower,
        "average time from a request to its whole answer",
    ),
    m(
        "response_p99",
        Millis,
        Lower,
        "99th percentile of the time to an answer",
    ),
    m("response_max", Millis, Lower, "slowest application answer"),
];

/// Metrics of a UDP check: the client side, and the server's with `server_`.
pub const UDP_METRICS: &[MetricDef] = &[
    m("transactions", Count, Neither, "transactions the client started"),
    m("answered", Count, Higher, "transactions answered as expected"),
    m("answered_pct", Percent, Higher, "answered, of the transactions started"),
    m("timed_out", Count, Lower, "transactions without an answer after all retries"),
    m("timed_out_pct", Percent, Lower, "timed out, of the transactions started"),
    m("mismatched", Count, Lower, "transactions answered with something else than expected"),
    m("unmatched", Count, Lower, "datagrams that matched no open transaction"),
    m("errors", Count, Neither, "answers with an error code (DNS NXDOMAIN, SERVFAIL...; NTP kiss-o'-death), also counted in answered"),
    m("retries", Count, Lower, "requests sent again"),
    m("response_min", Millis, Lower, "fastest answer"),
    m("response_avg", Millis, Lower, "average time to an answer"),
    m("response_p99", Millis, Lower, "99th percentile of the time to an answer"),
    m("response_max", Millis, Lower, "slowest answer"),
    m("tps", PerSecond, Higher, "answered transactions per second"),
    m("server_answered", Count, Higher, "requests the server answered"),
];

/// Metrics of a traffic check. Latency figures are of the worst stream.
pub const TRAFFIC_METRICS: &[MetricDef] = &[
    m("tx_packets", Count, Neither, "packets sent, all streams"),
    m("tx_mbps", Mbps, Higher, "send rate achieved"),
    m("tx_pps", PerSecond, Higher, "packets sent per second"),
    m("send_errors", Count, Lower, "packets the interface refused"),
    m(
        "rx_packets",
        Count,
        Higher,
        "packets with a signature received (duplicates not counted)",
    ),
    m(
        "rx_mbps",
        Mbps,
        Higher,
        "frames received, in Mbit/s over the sending time",
    ),
    m(
        "lost",
        Count,
        Lower,
        "packets with a signature sent and not received",
    ),
    m(
        "loss_pct",
        Percent,
        Lower,
        "lost, of the packets sent with a signature",
    ),
    m(
        "duplicates",
        Count,
        Lower,
        "packets received more than once",
    ),
    m(
        "out_of_order",
        Count,
        Lower,
        "packets that arrived after a later one",
    ),
    m(
        "out_of_order_pct",
        Percent,
        Lower,
        "out of order, of the packets received",
    ),
    m("latency_min", Millis, Lower, "lowest one-way latency"),
    m(
        "latency_avg",
        Millis,
        Lower,
        "average latency (over all streams)",
    ),
    m(
        "latency_p50",
        Millis,
        Lower,
        "median latency of the worst stream",
    ),
    m(
        "latency_p99",
        Millis,
        Lower,
        "99th percentile latency of the worst stream",
    ),
    m("latency_max", Millis, Lower, "highest latency"),
    m(
        "jitter",
        Millis,
        Lower,
        "RFC 3550 jitter of the worst stream",
    ),
];

/// A comparison in a condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Lt => "<",
            Op::Le => "<=",
            Op::Gt => ">",
            Op::Ge => ">=",
            Op::Eq => "==",
            Op::Ne => "!=",
        }
    }

    pub fn holds(self, actual: f64, value: f64) -> bool {
        // Counts and percentages computed from them are exact enough, but a
        // percentage like 100 * 3 / 3 should equal 100.
        let eq = (actual - value).abs() <= 1e-9 * value.abs().max(1.0);
        match self {
            Op::Lt => actual < value && !eq,
            Op::Le => actual <= value || eq,
            Op::Gt => actual > value && !eq,
            Op::Ge => actual >= value || eq,
            Op::Eq => eq,
            Op::Ne => !eq,
        }
    }
}

/// A condition on one metric, such as `loss_pct < 1%` or `latency_p99 <= 20ms`.
#[derive(Clone, Debug, PartialEq)]
pub struct Condition {
    /// As written.
    pub text: String,
    pub metric: String,
    pub op: Op,
    /// In the metric's unit.
    pub value: f64,
}

impl Condition {
    /// Parses `METRIC OP VALUE` for a check of `kind`.
    pub fn parse(text: &str, kind: CheckKind) -> Result<Condition> {
        let bad = |why: String| Error::Profile(format!("condition '{text}': {why}"));
        let t = text.trim();
        let end = t
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(t.len());
        let (metric, rest) = t.split_at(end);
        if metric.is_empty() {
            return Err(bad("start with a metric name, e.g. loss_pct < 1%".into()));
        }
        let def = kind.metric(metric).ok_or_else(|| {
            let names: Vec<&str> = kind.metrics().iter().map(|m| m.name).collect();
            bad(format!(
                "a {kind} check has no metric '{metric}'; it has {}",
                names.join(", ")
            ))
        })?;
        let rest = rest.trim_start();
        let (op, value) = [
            ("<=", Op::Le),
            (">=", Op::Ge),
            ("==", Op::Eq),
            ("!=", Op::Ne),
            ("<", Op::Lt),
            (">", Op::Gt),
            ("=", Op::Eq),
        ]
        .into_iter()
        .find_map(|(s, op)| rest.strip_prefix(s).map(|v| (op, v)))
        .ok_or_else(|| bad("compare with <, <=, >, >=, == or !=".into()))?;
        let value = def.unit.parse(value).map_err(bad)?;
        Ok(Condition {
            text: t.to_string(),
            metric: metric.to_string(),
            op,
            value,
        })
    }

    /// A condition made by the program (an expectation's built-in ones).
    pub(crate) fn built_in(metric: &str, op: Op, value: f64) -> Condition {
        Condition {
            text: format!("{metric} {} {value}", op.as_str()),
            metric: metric.to_string(),
            op,
            value,
        }
    }

    /// Whether the condition holds for these metrics; a metric that was not
    /// measured fails it.
    pub fn eval(&self, metrics: &Metrics) -> (Option<f64>, bool) {
        match metrics.get(&self.metric) {
            Some(&v) => (Some(v), self.op.holds(v, self.value)),
            None => (None, false),
        }
    }
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// `part` as a percentage of `whole`; 0 when there is no whole.
pub(crate) fn pct(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 * 100.0 / whole as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditions_parse_with_units() {
        let c = Condition::parse("loss_pct < 1%", CheckKind::Traffic).unwrap();
        assert_eq!(
            (c.metric.as_str(), c.op, c.value),
            ("loss_pct", Op::Lt, 1.0)
        );
        let c = Condition::parse("latency_p99<=500us", CheckKind::Traffic).unwrap();
        assert_eq!((c.op, c.value), (Op::Le, 0.5));
        let c = Condition::parse("latency_max < 1s", CheckKind::Traffic).unwrap();
        assert_eq!(c.value, 1000.0);
        let c = Condition::parse("rx_mbps >= 500 kbit/s", CheckKind::Traffic).unwrap();
        assert_eq!(c.value, 0.5);
        let c = Condition::parse("rx_mbps > 1Gbit/s", CheckKind::Traffic).unwrap();
        assert_eq!(c.value, 1000.0);
        let c = Condition::parse("completed = 10", CheckKind::Tcp).unwrap();
        assert_eq!((c.op, c.value), (Op::Eq, 10.0));
        let c = Condition::parse("cps > 50cps", CheckKind::Tcp).unwrap();
        assert_eq!(c.value, 50.0);
        let c = Condition::parse("response_p99 < 0.2s", CheckKind::Udp).unwrap();
        assert_eq!(c.value, 200.0);
    }

    #[test]
    fn bad_conditions_say_why() {
        let e = Condition::parse("loss < 1%", CheckKind::Traffic).unwrap_err();
        assert!(e.to_string().contains("no metric 'loss'"), "{e}");
        assert!(e.to_string().contains("loss_pct"), "{e}");
        let e = Condition::parse("loss_pct ~ 1", CheckKind::Traffic).unwrap_err();
        assert!(e.to_string().contains("compare with"), "{e}");
        let e = Condition::parse("loss_pct < 1ms", CheckKind::Traffic).unwrap_err();
        assert!(e.to_string().contains("percentage"), "{e}");
        let e = Condition::parse("completed > lots", CheckKind::Tcp).unwrap_err();
        assert!(e.to_string().contains("number"), "{e}");
        assert!(Condition::parse("latency_avg < 5ms", CheckKind::Tcp).is_err());
    }

    #[test]
    fn conditions_evaluate() {
        let mut metrics = Metrics::new();
        metrics.insert("completed_pct".into(), 100.0 * 3.0 / 3.0);
        metrics.insert("failed".into(), 0.0);
        let c = Condition::parse("completed_pct == 100", CheckKind::Tcp).unwrap();
        assert_eq!(c.eval(&metrics), (Some(100.0), true));
        let c = Condition::parse("failed > 0", CheckKind::Tcp).unwrap();
        assert_eq!(c.eval(&metrics), (Some(0.0), false));
        let c = Condition::parse("failed <= 0", CheckKind::Tcp).unwrap();
        assert!(c.eval(&metrics).1);
        // Not measured: fails.
        let c = Condition::parse("cps > 1", CheckKind::Tcp).unwrap();
        assert_eq!(c.eval(&metrics), (None, false));
    }

    #[test]
    fn units_format() {
        assert_eq!(Unit::Percent.format(100.0), "100%");
        assert_eq!(Unit::Percent.format(99.5), "99.5%");
        assert_eq!(Unit::Millis.format(5.125), "5.125ms");
        assert_eq!(Unit::Mbps.format(19.87654), "19.877 Mbit/s");
        assert_eq!(Unit::PerSecond.format(1234.5), "1234.5/s");
        assert_eq!(Unit::Count.format(7.0), "7");
    }

    #[test]
    fn every_kind_names_its_metrics_once() {
        for k in CheckKind::ALL {
            let mut names: Vec<_> = k.metrics().iter().map(|m| m.name).collect();
            let n = names.len();
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), n, "{k}");
            assert_eq!(CheckKind::from_name(k.as_str()), Some(k));
        }
    }
}
