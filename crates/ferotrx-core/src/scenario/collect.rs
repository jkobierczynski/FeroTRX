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
    put(&mut m, "ecn_connections", c.ecn_connections as f64);
    put(&mut m, "ce_marks", (c.ce_marks + s.server.ce_marks) as f64);
    put(
        &mut m,
        "ecn_reductions",
        (c.ecn_reductions + s.server.ecn_reductions) as f64,
    );
    put(&mut m, "cps", s.cps());
    put(
        &mut m,
        "impair_dropped",
        (s.impair.tx.dropped() + s.impair.rx.dropped()) as f64,
    );
    let sv = &s.server;
    put(&mut m, "server_connections", sv.started as f64);
    put(&mut m, "server_completed", sv.completed as f64);
    put(&mut m, "server_failed", sv.failed() as f64);
    put(&mut m, "server_mismatched", sv.mismatched as f64);
    let a = &c.app;
    put(&mut m, "app_transactions", a.transactions as f64);
    put(&mut m, "app_failed", a.failed as f64);
    put(&mut m, "app_failed_pct", pct(a.failed, a.transactions));
    put(&mut m, "app_passed", a.passed() as f64);
    put(&mut m, "app_passed_pct", pct(a.passed(), a.transactions));
    put(&mut m, "app_errors", a.errors as f64);
    put(&mut m, "protocol_errors", a.protocol_errors as f64);
    latency_metrics(&mut m, "response", &a.response_time);
    latency_metrics(&mut m, "connect", &c.connect_time);
    latency_metrics(&mut m, "first_byte", &c.first_byte);
    let n = &c.session_requests;
    if n.count() > 0 {
        let v = |x: Option<u64>| x.unwrap_or(0) as f64;
        put(&mut m, "session_requests_avg", n.mean().unwrap_or(0.0));
        put(&mut m, "session_requests_p50", v(n.percentile(0.5)));
        put(&mut m, "session_requests_p99", v(n.percentile(0.99)));
        put(&mut m, "session_requests_max", v(n.max()));
    }
    latency_metrics(&mut m, "session_time", &c.session_time);
    user_metrics(&mut m, &s.users);
    if a.handshakes > 0 {
        put(&mut m, "tls_handshakes", a.handshakes as f64);
        put(&mut m, "tls_failed", a.handshake_failures as f64);
        put(&mut m, "tls_unexpected", a.handshakes_unexpected as f64);
        put(&mut m, "tls_resumed", a.resumed as f64);
        put(&mut m, "tls_full", a.full_handshakes() as f64);
        if let Some(r) = a.handshake_rate() {
            put(&mut m, "tls_rate", r);
        }
        latency_metrics(&mut m, "handshake", &a.handshake_time);
        latency_metrics(&mut m, "handshake_full", &a.full_time);
        latency_metrics(&mut m, "handshake_resumed", &a.resumed_time);
    }
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

/// The users of a run, all groups together.
fn user_metrics(m: &mut Metrics, users: &[crate::UserStats]) {
    let Some(all) = users.last() else { return };
    put(m, "users_online", all.online as f64);
    put(m, "users_arrived", all.arrived as f64);
    put(m, "users_departed", all.departed as f64);
    put(m, "user_sessions", all.sessions as f64);
    if let Some(v) = all.think.mean() {
        put(m, "user_think_avg", ms(v));
    }
    if let Some(v) = all.lifetime.mean() {
        put(m, "user_lifetime_avg", ms(v));
    }
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
    put(
        &mut m,
        "impair_dropped",
        (s.impair.tx.dropped() + s.impair.rx.dropped()) as f64,
    );
    latency_metrics(&mut m, "response", &c.response_time);
    put(&mut m, "tps", s.tps());
    user_metrics(&mut m, &s.users);
    put(&mut m, "server_answered", s.server.answered as f64);
    let a = &c.app;
    if !a.is_empty() {
        put(&mut m, "app_transactions", a.transactions as f64);
        put(&mut m, "app_failed", a.failed as f64);
        put(&mut m, "protocol_errors", a.protocol_errors as f64);
    }
    // Media is counted on both ends; the worst way counts.
    let (cm, sm) = (&c.app.media, &s.server.app.media);
    if cm.streams > 0 || sm.streams > 0 {
        put(&mut m, "media_streams", cm.streams.max(sm.streams) as f64);
        put(&mut m, "media_received", cm.packets_received as f64);
        put(&mut m, "media_lost", cm.lost.max(sm.lost) as f64);
        put(&mut m, "media_loss_pct", cm.loss().max(sm.loss()) * 100.0);
        let mut jitter = cm.jitter.clone();
        jitter.merge(&sm.jitter);
        latency_metrics(&mut m, "jitter", &jitter);
        put(&mut m, "media_late", cm.late.max(sm.late) as f64);
        put(
            &mut m,
            "media_playout_loss_pct",
            cm.playout_loss().max(sm.playout_loss()) * 100.0,
        );
        put(&mut m, "max_burst", cm.max_burst.max(sm.max_burst) as f64);
        let mut rtt = cm.rtt.clone();
        rtt.merge(&sm.rtt);
        if let Some(v) = rtt.mean() {
            put(&mut m, "rtt_avg", ms(v));
        }
        if let Some(v) = rtt.max() {
            put(&mut m, "rtt_max", ms(v));
        }
        let worse = |a: Option<f64>, b: Option<f64>| match (a, b) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if let Some(v) = worse(cm.mos_avg(), sm.mos_avg()) {
            put(&mut m, "mos", v);
        }
        if let Some(v) = worse(cm.mos_min, sm.mos_min) {
            put(&mut m, "mos_min", v);
        }
        if let Some(v) = worse(cm.r_avg(), sm.r_avg()) {
            put(&mut m, "r_factor", v);
        }
        if let Some(v) = worse(cm.r_min, sm.r_min) {
            put(&mut m, "r_factor_min", v);
        }
    }
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
/// receiver saw, the streams' loss and latency, and where the frames were
/// lost (`loss`, see [`Job::loss`](crate::Job::loss)).
pub fn traffic_metrics(
    run: &RunStats,
    rx: Option<&RxStats>,
    flows: &[FlowReport],
    loss: Option<&crate::LossReport>,
) -> Metrics {
    let t = &run.total;
    let mut m = Metrics::new();
    put(&mut m, "tx_packets", t.packets as f64);
    put(&mut m, "tx_mbps", t.mbps());
    put(&mut m, "tx_pps", t.pps());
    put(&mut m, "send_errors", t.send_errors as f64);
    put(
        &mut m,
        "impair_dropped",
        t.impair.as_ref().map_or(0, |i| i.dropped()) as f64,
    );
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
    if let Some(l) = loss {
        loss_metrics(&mut m, l);
    }
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

/// `generator_loss`, `network_loss`, `receiver_loss` and their `_pct`.
pub fn loss_metrics(m: &mut Metrics, l: &crate::LossReport) {
    for (name, v) in [
        ("generator_loss", l.generator),
        ("network_loss", l.network),
        ("receiver_loss", l.receiver),
    ] {
        put(m, name, v as f64);
        put(m, &format!("{name}_pct"), l.pct(v));
    }
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

/// The metrics of a Y.1564 check.
pub fn y1564_metrics(r: &crate::Y1564Report) -> Metrics {
    let mut m = Metrics::new();
    put(&mut m, "passed", if r.passed { 1.0 } else { 0.0 });
    let steps = r.configuration.len() + usize::from(r.performance.is_some());
    put(&mut m, "steps", steps as f64);
    put(&mut m, "steps_failed", r.failed_steps() as f64);
    put(
        &mut m,
        "services_failed",
        r.services.iter().filter(|s| !s.passed).count() as f64,
    );
    if steps > 0 {
        put(
            &mut m,
            "flr_pct",
            r.worst(|s| Some(s.flr_pct)).unwrap_or(0.0),
        );
    }
    if let Some(v) = r.worst(|s| s.ftd_ms) {
        put(&mut m, "ftd", v);
    }
    if let Some(v) = r.worst(|s| s.fdv_ms) {
        put(&mut m, "fdv", v);
    }
    if let Some(v) = r.worst(|s| s.yellow_flr_pct) {
        put(&mut m, "yellow_loss_pct", v);
    }
    if let Some(v) = r.min_availability() {
        put(&mut m, "availability_pct", v);
    }
    if let Some(p) = &r.performance {
        put(
            &mut m,
            "ses",
            p.services.iter().filter_map(|s| s.ses).sum::<u64>() as f64,
        );
        put(
            &mut m,
            "ir_mbps",
            p.services.iter().map(|s| s.ir_mbps).sum(),
        );
    }
    m
}

/// One line on a Y.1564 check.
pub fn y1564_summary(r: &crate::Y1564Report) -> String {
    let steps = r.configuration.len() + usize::from(r.performance.is_some());
    let mut line = format!(
        "{}: {} step(s), {} failed",
        if r.passed { "passed" } else { "failed" },
        steps,
        r.failed_steps()
    );
    if let Some(flr) = r.worst(|s| Some(s.flr_pct)) {
        line.push_str(&format!("; worst green FLR {flr:.3}%"));
    }
    if let Some(a) = r.min_availability() {
        line.push_str(&format!(", availability {a:.3}%"));
    }
    let failed: Vec<&str> = r
        .services
        .iter()
        .filter(|s| !s.passed)
        .map(|s| s.service.as_str())
        .collect();
    if !failed.is_empty() {
        line.push_str(&format!("; failed: {}", failed.join(", ")));
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
            drops: Default::default(),
        };
        let m = traffic_metrics(&run, None, &[], None);
        assert_eq!(m["tx_packets"], 10.0);
        assert_eq!(m["rx_packets"], 0.0);
        assert_eq!(m["loss_pct"], 0.0);
        assert!(!m.contains_key("latency_avg"));
        assert!(!m.contains_key("rx_mbps"));
        assert!(traffic_summary(&m).starts_with("10 packets sent"));
    }
}
