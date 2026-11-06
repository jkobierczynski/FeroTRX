//! Metrics of runs on several agents, added up: the names of the scenario
//! metrics (`ferotrx_core::scenario::TCP_METRICS` and the others), from
//! the counters the agents report.

use ferotrx_core::scenario::Metrics;

use crate::protocol::{
    FlowCounters, LatencyCounters, RunInfo, RxRunInfo, TcpCounters, TcpRunInfo, UdpCounters,
    UdpRunInfo,
};

fn put(m: &mut Metrics, name: &str, v: f64) {
    m.insert(name.to_string(), v);
}

fn pct(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 * 100.0 / whole as f64
    }
}

/// Latency figures of several agents together: the lowest minimum, the
/// mean weighted by `weight`, and the worst percentiles and maximum (a
/// percentile of the whole cannot be had from the parts' figures).
pub fn merge_latency<'a>(
    parts: impl IntoIterator<Item = (&'a LatencyCounters, u64)>,
) -> Option<LatencyCounters> {
    let mut out: Option<LatencyCounters> = None;
    let (mut sum, mut n) = (0.0, 0u64);
    for (l, w) in parts {
        let o = out.get_or_insert_with(Default::default);
        let min = |a: Option<f64>, b: Option<f64>| match (a, b) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let max = |a: Option<f64>, b: Option<f64>| match (a, b) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        o.min_us = min(o.min_us, l.min_us);
        o.max_us = max(o.max_us, l.max_us);
        o.p50_us = max(o.p50_us, l.p50_us);
        o.p99_us = max(o.p99_us, l.p99_us);
        o.jitter_us = max(o.jitter_us, l.jitter_us);
        if let Some(a) = l.avg_us {
            let w = w.max(1);
            sum += a * w as f64;
            n += w;
        }
    }
    if let Some(o) = &mut out {
        o.avg_us = (n > 0).then(|| sum / n as f64);
    }
    out
}

/// `prefix_min`, `_avg`, `_p99` and `_max` in milliseconds.
fn latency(m: &mut Metrics, prefix: &str, l: Option<LatencyCounters>) {
    let Some(l) = l else {
        return;
    };
    for (what, v) in [
        ("min", l.min_us),
        ("avg", l.avg_us),
        ("p99", l.p99_us),
        ("max", l.max_us),
    ] {
        if let Some(v) = v {
            put(m, &format!("{prefix}_{what}"), v / 1000.0);
        }
    }
}

fn sum<T>(list: &[&T], f: impl Fn(&T) -> u64) -> u64 {
    list.iter().map(|x| f(x)).sum()
}

/// The metrics of TCP runs on several agents, added up.
pub fn tcp_metrics(runs: &[&TcpRunInfo]) -> Metrics {
    let c: Vec<&TcpCounters> = runs.iter().map(|r| &r.client).collect();
    let s: Vec<&TcpCounters> = runs.iter().map(|r| &r.server).collect();
    let mut m = Metrics::new();
    let started = sum(&c, |x| x.started);
    let established = sum(&c, |x| x.established);
    let completed = sum(&c, |x| x.completed);
    let failed = sum(&c, |x| x.reset + x.timed_out);
    put(&mut m, "connections", started as f64);
    put(&mut m, "established", established as f64);
    put(&mut m, "established_pct", pct(established, started));
    put(&mut m, "completed", completed as f64);
    put(&mut m, "completed_pct", pct(completed, started));
    put(&mut m, "failed", failed as f64);
    put(&mut m, "failed_pct", pct(failed, started));
    put(&mut m, "reset", sum(&c, |x| x.reset) as f64);
    put(&mut m, "timed_out", sum(&c, |x| x.timed_out) as f64);
    put(&mut m, "mismatched", sum(&c, |x| x.mismatched) as f64);
    put(&mut m, "open", sum(&c, |x| x.active) as f64);
    put(&mut m, "retransmits", sum(&c, |x| x.retransmits) as f64);
    put(&mut m, "timeouts", sum(&c, |x| x.timeouts) as f64);
    put(
        &mut m,
        "ecn_connections",
        sum(&c, |x| x.ecn_connections) as f64,
    );
    put(
        &mut m,
        "ce_marks",
        (sum(&c, |x| x.ce_marks) + sum(&s, |x| x.ce_marks)) as f64,
    );
    put(
        &mut m,
        "ecn_reductions",
        (sum(&c, |x| x.ecn_reductions) + sum(&s, |x| x.ecn_reductions)) as f64,
    );
    put(&mut m, "cps", runs.iter().map(|r| r.cps).sum());
    put(&mut m, "server_connections", sum(&s, |x| x.started) as f64);
    put(&mut m, "server_completed", sum(&s, |x| x.completed) as f64);
    put(
        &mut m,
        "server_failed",
        sum(&s, |x| x.reset + x.timed_out) as f64,
    );
    put(
        &mut m,
        "server_mismatched",
        sum(&s, |x| x.mismatched) as f64,
    );
    let impair: u64 = runs
        .iter()
        .filter_map(|r| r.impair.as_ref())
        .map(|i| i.dropped())
        .sum();
    put(&mut m, "impair_dropped", impair as f64);
    latency(
        &mut m,
        "connect",
        merge_latency(
            c.iter()
                .filter_map(|x| x.connect_time.as_ref().map(|l| (l, x.established))),
        ),
    );
    latency(
        &mut m,
        "first_byte",
        merge_latency(
            c.iter()
                .filter_map(|x| x.first_byte.as_ref().map(|l| (l, x.established))),
        ),
    );
    let apps: Vec<_> = c.iter().filter_map(|x| x.app.as_ref()).collect();
    if !apps.is_empty() {
        let tx = sum(&apps, |a| a.transactions);
        let failed = sum(&apps, |a| a.failed);
        put(&mut m, "app_transactions", tx as f64);
        put(&mut m, "app_failed", failed as f64);
        put(&mut m, "app_failed_pct", pct(failed, tx));
        put(&mut m, "app_errors", sum(&apps, |a| a.errors) as f64);
        put(
            &mut m,
            "protocol_errors",
            sum(&apps, |a| a.protocol_errors) as f64,
        );
        latency(
            &mut m,
            "response",
            merge_latency(
                apps.iter()
                    .filter_map(|a| a.response_time.as_ref().map(|l| (l, a.transactions))),
            ),
        );
        let tls: Vec<_> = apps.iter().filter_map(|a| a.tls.as_ref()).collect();
        if !tls.is_empty() {
            put(&mut m, "tls_handshakes", sum(&tls, |t| t.handshakes) as f64);
            put(&mut m, "tls_failed", sum(&tls, |t| t.failed) as f64);
            put(&mut m, "tls_unexpected", sum(&tls, |t| t.unexpected) as f64);
            put(&mut m, "tls_resumed", sum(&tls, |t| t.resumed) as f64);
            put(&mut m, "tls_full", sum(&tls, |t| t.full) as f64);
            let rates: Vec<f64> = tls.iter().filter_map(|t| t.rate).collect();
            if !rates.is_empty() {
                // Agents run at the same time: their rates add up.
                put(&mut m, "tls_rate", rates.iter().sum());
            }
            latency(
                &mut m,
                "handshake",
                merge_latency(
                    tls.iter()
                        .filter_map(|t| t.time.as_ref().map(|l| (l, t.handshakes))),
                ),
            );
            latency(
                &mut m,
                "handshake_full",
                merge_latency(
                    tls.iter()
                        .filter_map(|t| t.full_time.as_ref().map(|l| (l, t.full))),
                ),
            );
            latency(
                &mut m,
                "handshake_resumed",
                merge_latency(
                    tls.iter()
                        .filter_map(|t| t.resumed_time.as_ref().map(|l| (l, t.resumed))),
                ),
            );
        }
    }
    m
}

/// The metrics of UDP runs on several agents, added up.
pub fn udp_metrics(runs: &[&UdpRunInfo]) -> Metrics {
    let c: Vec<&UdpCounters> = runs.iter().map(|r| &r.client).collect();
    let mut m = Metrics::new();
    let sent = sum(&c, |x| x.sent);
    let answered = sum(&c, |x| x.answered);
    let timed_out = sum(&c, |x| x.timed_out);
    put(&mut m, "transactions", sent as f64);
    put(&mut m, "answered", answered as f64);
    put(&mut m, "answered_pct", pct(answered, sent));
    put(&mut m, "timed_out", timed_out as f64);
    put(&mut m, "timed_out_pct", pct(timed_out, sent));
    put(&mut m, "mismatched", sum(&c, |x| x.mismatched) as f64);
    put(&mut m, "unmatched", sum(&c, |x| x.unmatched) as f64);
    put(&mut m, "errors", sum(&c, |x| x.errors) as f64);
    put(&mut m, "retries", sum(&c, |x| x.retries) as f64);
    put(&mut m, "tps", runs.iter().map(|r| r.tps).sum());
    put(
        &mut m,
        "server_answered",
        runs.iter().map(|r| r.server.answered).sum::<u64>() as f64,
    );
    let impair: u64 = runs
        .iter()
        .filter_map(|r| r.impair.as_ref())
        .map(|i| i.dropped())
        .sum();
    put(&mut m, "impair_dropped", impair as f64);
    latency(
        &mut m,
        "response",
        merge_latency(
            c.iter()
                .filter_map(|x| x.response_time.as_ref().map(|l| (l, x.answered))),
        ),
    );
    let apps: Vec<_> = c.iter().filter_map(|x| x.app.as_ref()).collect();
    if !apps.is_empty() {
        put(
            &mut m,
            "app_transactions",
            sum(&apps, |a| a.transactions) as f64,
        );
        put(&mut m, "app_failed", sum(&apps, |a| a.failed) as f64);
        put(
            &mut m,
            "protocol_errors",
            sum(&apps, |a| a.protocol_errors) as f64,
        );
    }
    m
}

/// A traffic run on one agent, and what was received of it: on the same
/// agent (in `run.streams`), or on another one (`rx`).
pub struct TrafficPart<'a> {
    pub run: &'a RunInfo,
    pub rx: Option<&'a RxRunInfo>,
}

/// The metrics of traffic runs on several agents, added up.
pub fn traffic_metrics(parts: &[TrafficPart<'_>]) -> Metrics {
    let mut m = Metrics::new();
    let runs: Vec<&RunInfo> = parts.iter().map(|p| p.run).collect();
    put(&mut m, "tx_packets", sum(&runs, |r| r.total.packets) as f64);
    put(&mut m, "tx_mbps", runs.iter().map(|r| r.total.mbps).sum());
    put(&mut m, "tx_pps", runs.iter().map(|r| r.total.pps).sum());
    put(
        &mut m,
        "send_errors",
        sum(&runs, |r| r.total.send_errors) as f64,
    );
    put(
        &mut m,
        "impair_dropped",
        runs.iter()
            .filter_map(|r| r.impair.as_ref())
            .map(|i| i.dropped())
            .sum::<u64>() as f64,
    );
    // (sent with a signature, received, lost, flows) of each part.
    let (mut tx, mut got, mut lost, mut dup, mut ooo) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut flows: Vec<&FlowCounters> = Vec::new();
    let mut any = false;
    let mut rx_mbps = 0.0;
    for p in parts {
        match p.rx {
            Some(rx) => {
                // Another agent received: what it got, against what was sent.
                any = true;
                let sent = p.run.total.tagged;
                let r: u64 = rx.flows.iter().map(|f| f.rx).sum();
                tx += sent;
                got += r;
                lost += sent.saturating_sub(r);
                dup += rx.flows.iter().map(|f| f.duplicates).sum::<u64>();
                ooo += rx.flows.iter().map(|f| f.out_of_order).sum::<u64>();
                flows.extend(&rx.flows);
                if rx.counters.elapsed_s > 0.0 {
                    rx_mbps += rx.counters.bytes as f64 * 8.0 / 1e6 / rx.counters.elapsed_s;
                }
            }
            None => {
                let own: Vec<&FlowCounters> = p
                    .run
                    .streams
                    .iter()
                    .filter_map(|s| s.latency.as_ref())
                    .collect();
                if p.run.rx.is_some() {
                    any = true;
                }
                for f in own {
                    tx += f.tx.unwrap_or(0);
                    got += f.rx;
                    lost += f.lost;
                    dup += f.duplicates;
                    ooo += f.out_of_order;
                    flows.push(f);
                }
                if let Some(rx) = &p.run.rx {
                    if p.run.total.elapsed_s > 0.0 {
                        rx_mbps += rx.bytes as f64 * 8.0 / 1e6 / p.run.total.elapsed_s;
                    }
                }
            }
        }
    }
    if !any {
        return m;
    }
    put(&mut m, "rx_packets", got as f64);
    put(&mut m, "lost", lost as f64);
    put(&mut m, "loss_pct", pct(lost, tx));
    put(&mut m, "duplicates", dup as f64);
    put(&mut m, "out_of_order", ooo as f64);
    put(&mut m, "out_of_order_pct", pct(ooo, got));
    put(&mut m, "rx_mbps", rx_mbps);
    if let Some(l) = merge_latency(flows.iter().map(|f| (&f.latency, f.rx))) {
        for (name, v) in [
            ("latency_min", l.min_us),
            ("latency_avg", l.avg_us),
            ("latency_p50", l.p50_us),
            ("latency_p99", l.p99_us),
            ("latency_max", l.max_us),
            ("jitter", l.jitter_us),
        ] {
            if let Some(v) = v {
                put(&mut m, name, v / 1000.0);
            }
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lat(min: f64, avg: f64, max: f64) -> LatencyCounters {
        LatencyCounters {
            min_us: Some(min),
            avg_us: Some(avg),
            max_us: Some(max),
            p99_us: Some(max),
            ..Default::default()
        }
    }

    #[test]
    fn latency_merges() {
        let (a, b) = (lat(10.0, 20.0, 30.0), lat(5.0, 50.0, 100.0));
        let m = merge_latency([(&a, 3), (&b, 1)]).unwrap();
        assert_eq!(m.min_us, Some(5.0));
        assert_eq!(m.max_us, Some(100.0));
        assert_eq!(m.p99_us, Some(100.0));
        assert_eq!(m.avg_us, Some((20.0 * 3.0 + 50.0) / 4.0));
        assert!(merge_latency([]).is_none());
    }

    #[test]
    fn tcp_adds_up() {
        let run = |started, completed, cps| TcpRunInfo {
            client: TcpCounters {
                started,
                established: started,
                completed,
                reset: started - completed,
                ..Default::default()
            },
            server: TcpCounters {
                completed,
                ..Default::default()
            },
            cps,
            ..Default::default()
        };
        let (a, b) = (run(100, 100, 10.0), run(50, 40, 4.0));
        let m = tcp_metrics(&[&a, &b]);
        assert_eq!(m["connections"], 150.0);
        assert_eq!(m["completed"], 140.0);
        assert_eq!(m["failed"], 10.0);
        assert!((m["completed_pct"] - 93.333).abs() < 0.01);
        assert_eq!(m["cps"], 14.0);
        assert_eq!(m["server_completed"], 140.0);
        assert!(!m.contains_key("connect_avg"));
    }

    #[test]
    fn traffic_from_another_agent() {
        let mut run = RunInfo {
            total: Default::default(),
            ..serde_json::from_value(serde_json::json!({
                "id": 1, "profile": "p", "output": "o", "state": "running",
                "total": {"packets": 1000, "bytes": 64000, "send_errors": 0,
                          "loops_completed": 0, "elapsed_s": 1.0, "pps": 1000.0, "mbps": 0.5},
                "streams": []
            }))
            .unwrap()
        };
        run.total.packets = 1000;
        run.total.tagged = 1000;
        run.total.mbps = 0.5;
        let rx: RxRunInfo = serde_json::from_value(serde_json::json!({
            "id": 2, "state": "finished", "iface": "s0", "packets": 990, "bytes": 63360,
            "untagged": 0, "elapsed_s": 1.0,
            "flows": [{"flow": 1, "rx": 990, "lost": 10, "loss_pct": 1.0, "duplicates": 0,
                       "out_of_order": 0, "latency": {"min_us": 100.0, "avg_us": 150.0,
                       "max_us": 900.0, "p99_us": 400.0}}]
        }))
        .unwrap();
        let m = traffic_metrics(&[TrafficPart {
            run: &run,
            rx: Some(&rx),
        }]);
        assert_eq!(m["tx_packets"], 1000.0);
        assert_eq!(m["rx_packets"], 990.0);
        assert_eq!(m["lost"], 10.0);
        assert!((m["loss_pct"] - 1.0).abs() < 1e-9);
        assert_eq!(m["latency_p99"], 0.4);
        // Without a receiver, nothing about loss.
        let m = traffic_metrics(&[TrafficPart {
            run: &run,
            rx: None,
        }]);
        assert!(!m.contains_key("loss_pct"));
    }
}
