//! Metrics and one-line summaries from the counters of a run.

use std::time::Duration;

use super::metric::{pct, Metrics};
use crate::{FlowReport, LatencyStats, RunStats, RxStats, TcpStats, UdpStats};

fn ms(d: Duration) -> f64 {
    d.as_nanos() as f64 / 1e6
}

fn put(m: &mut Metrics, name: &str, v: f64) {
    m.insert(name.to_string(), v);
}

/// The metrics of a TCP run ([`TCP_METRICS`](super::TCP_METRICS)).
pub fn tcp_metrics(s: &TcpStats) -> Metrics {
    let c = &s.client;
    let mut m = Metrics::new();
    put(&mut m, "connections", c.started as f64);
    put(&mut m, "established", c.established as f64);
    put(&mut m, "established_pct", pct(c.established, c.started));
    put(&mut m, "completed", c.completed as f64);
    put(&mut m, "completed_pct", pct(c.completed, c.started));
    put(&mut m, "failed", c.failed() as f64);
    put(&mut m, "failed_pct", pct(c.failed(), c.started));
    put(&mut m, "reset", c.reset as f64);
    put(&mut m, "timed_out", c.timed_out as f64);
    put(&mut m, "mismatched", c.mismatched as f64);
    put(&mut m, "open", c.active as f64);
    put(&mut m, "retransmits", c.retransmits as f64);
    put(&mut m, "timeouts", c.timeouts as f64);
    put(&mut m, "cps", s.cps());
    let sv = &s.server;
    put(&mut m, "server_connections", sv.started as f64);
    put(&mut m, "server_completed", sv.completed as f64);
    put(&mut m, "server_failed", sv.failed() as f64);
    put(&mut m, "server_mismatched", sv.mismatched as f64);
    let a = &c.app;
    put(&mut m, "app_transactions", a.transactions as f64);
    put(&mut m, "app_failed", a.failed as f64);
    put(&mut m, "app_failed_pct", pct(a.failed, a.transactions));
    put(&mut m, "app_errors", a.errors as f64);
    put(&mut m, "protocol_errors", a.protocol_errors as f64);
    latency_metrics(&mut m, "response", &a.response_time);
    m
}

/// One line on a TCP run, e.g. `20 connections: 20 established, 20 completed; 15.2 cps`.
pub fn tcp_summary(s: &TcpStats) -> String {
    let c = &s.client;
    let mut line = format!(
        "{} connections: {} established, {} completed",
        c.started, c.established, c.completed
    );
    for (n, what) in [
        (c.reset, "reset"),
        (c.timed_out, "timed out"),
        (c.mismatched, "mismatched"),
        (c.active, "still open"),
    ] {
        if n > 0 {
            line.push_str(&format!(", {n} {what}"));
        }
    }
    line.push_str(&format!(
        "; {} retransmits; {:.1} cps",
        c.retransmits,
        s.cps()
    ));
    line
}

fn latency_metrics(m: &mut Metrics, prefix: &str, l: &LatencyStats) {
    if l.count() == 0 {
        return;
    }
    if let Some(v) = l.min() {
        put(m, &format!("{prefix}_min"), ms(v));
    }
    if let Some(v) = l.mean() {
        put(m, &format!("{prefix}_avg"), ms(v));
    }
    if let Some(v) = l.percentile(0.99) {
        put(m, &format!("{prefix}_p99"), ms(v));
    }
    if let Some(v) = l.max() {
        put(m, &format!("{prefix}_max"), ms(v));
    }
}

/// The metrics of a UDP run ([`UDP_METRICS`](super::UDP_METRICS)).
pub fn udp_metrics(s: &UdpStats) -> Metrics {
    let c = &s.client;
    let mut m = Metrics::new();
    put(&mut m, "transactions", c.sent as f64);
    put(&mut m, "answered", c.answered as f64);
    put(&mut m, "answered_pct", pct(c.answered, c.sent));
    put(&mut m, "timed_out", c.timed_out as f64);
    put(&mut m, "timed_out_pct", pct(c.timed_out, c.sent));
    put(&mut m, "mismatched", c.mismatched as f64);
    put(&mut m, "unmatched", c.unmatched as f64);
    put(&mut m, "errors", c.errors as f64);
    put(&mut m, "retries", c.retries as f64);
    latency_metrics(&mut m, "response", &c.response_time);
    put(&mut m, "tps", s.tps());
    put(&mut m, "server_answered", s.server.answered as f64);
    m
}

/// One line on a UDP run.
pub fn udp_summary(s: &UdpStats) -> String {
    let c = &s.client;
    let mut line = format!("{} transactions: {} answered", c.sent, c.answered);
    for (n, what) in [
        (c.timed_out, "timed out"),
        (c.mismatched, "mismatched"),
        (c.errors, "with error codes"),
        (c.retries, "retries"),
    ] {
        if n > 0 {
            line.push_str(&format!(", {n} {what}"));
        }
    }
    if let Some(avg) = c.response_time.mean() {
        line.push_str(&format!("; answers in {:.2}ms on average", ms(avg)));
    }
    line.push_str(&format!("; {:.1} per second", s.tps()));
    line
}

/// The metrics of a traffic run with a receiver
/// ([`TRAFFIC_METRICS`](super::TRAFFIC_METRICS)): what was sent, what the
/// receiver saw, and the streams' loss and latency.
pub fn traffic_metrics(run: &RunStats, rx: Option<&RxStats>, flows: &[FlowReport]) -> Metrics {
    let t = &run.total;
    let mut m = Metrics::new();
    put(&mut m, "tx_packets", t.packets as f64);
    put(&mut m, "tx_mbps", t.mbps());
    put(&mut m, "tx_pps", t.pps());
    put(&mut m, "send_errors", t.send_errors as f64);
    let tx: u64 = flows.iter().map(|f| f.tx).sum();
    let got: u64 = flows.iter().map(|f| f.rx).sum();
    let lost: u64 = flows.iter().map(|f| f.lost).sum();
    put(&mut m, "rx_packets", got as f64);
    put(&mut m, "lost", lost as f64);
    put(&mut m, "loss_pct", pct(lost, tx));
    put(
        &mut m,
        "duplicates",
        flows.iter().map(|f| f.duplicates).sum::<u64>() as f64,
    );
    let ooo: u64 = flows.iter().map(|f| f.out_of_order).sum();
    put(&mut m, "out_of_order", ooo as f64);
    put(&mut m, "out_of_order_pct", pct(ooo, got));
    if let Some(rx) = rx {
        let secs = t.elapsed.as_secs_f64();
        let mbps = if secs > 0.0 {
            rx.bytes as f64 * 8.0 / 1e6 / secs
        } else {
            0.0
        };
        put(&mut m, "rx_mbps", mbps);
    }
    let measured: Vec<&LatencyStats> = flows
        .iter()
        .map(|f| &f.latency)
        .filter(|l| l.count() > 0)
        .collect();
    if !measured.is_empty() {
        let worst = |f: &dyn Fn(&LatencyStats) -> Option<Duration>| {
            measured.iter().filter_map(|l| f(l)).max().map(ms)
        };
        if let Some(v) = measured.iter().filter_map(|l| l.min()).min() {
            put(&mut m, "latency_min", ms(v));
        }
        let n: u64 = measured.iter().map(|l| l.count()).sum();
        let sum: f64 = measured
            .iter()
            .filter_map(|l| l.mean().map(|d| ms(d) * l.count() as f64))
            .sum();
        put(&mut m, "latency_avg", sum / n as f64);
        for (name, q) in [("latency_p50", 0.5), ("latency_p99", 0.99)] {
            if let Some(v) = worst(&|l| l.percentile(q)) {
                put(&mut m, name, v);
            }
        }
        if let Some(v) = worst(&|l| l.max()) {
            put(&mut m, "latency_max", v);
        }
        if let Some(v) = worst(&|l| l.jitter()) {
            put(&mut m, "jitter", v);
        }
    }
    m
}

/// One line on a traffic run.
pub fn traffic_summary(metrics: &Metrics) -> String {
    let g = |k: &str| metrics.get(k).copied().unwrap_or(0.0);
    let mut line = format!(
        "{:.0} packets sent at {:.3} Mbit/s, {:.0} received, {:.0} lost ({:.2}%)",
        g("tx_packets"),
        g("tx_mbps"),
        g("rx_packets"),
        g("lost"),
        g("loss_pct")
    );
    if let (Some(avg), Some(p99)) = (metrics.get("latency_avg"), metrics.get("latency_p99")) {
        line.push_str(&format!("; latency avg {avg:.2}ms, p99 {p99:.2}ms"));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReplayStats, TcpSideStats};

    #[test]
    fn tcp_percentages() {
        let s = TcpStats {
            client: TcpSideStats {
                started: 4,
                established: 4,
                completed: 3,
                reset: 1,
                ..Default::default()
            },
            elapsed: Duration::from_secs(2),
            ..Default::default()
        };
        let m = tcp_metrics(&s);
        assert_eq!(m["completed_pct"], 75.0);
        assert_eq!(m["failed"], 1.0);
        assert_eq!(m["cps"], 1.5);
        let line = tcp_summary(&s);
        assert!(
            line.starts_with("4 connections: 4 established, 3 completed, 1 reset"),
            "{line}"
        );
    }

    #[test]
    fn traffic_without_flows_has_no_latency() {
        let run = RunStats {
            total: ReplayStats {
                packets: 10,
                ..Default::default()
            },
            streams: Vec::new(),
        };
        let m = traffic_metrics(&run, None, &[]);
        assert_eq!(m["tx_packets"], 10.0);
        assert_eq!(m["rx_packets"], 0.0);
        assert_eq!(m["loss_pct"], 0.0);
        assert!(!m.contains_key("latency_avg"));
        assert!(!m.contains_key("rx_mbps"));
        assert!(traffic_summary(&m).starts_with("10 packets sent"));
    }
}
