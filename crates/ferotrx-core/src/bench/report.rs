//! The human-readable form of a [`BenchReport`].

use std::fmt::Write;

use super::{BenchReport, BenchTest, LatencySummary, RunInfo, SizeReport, Spread};

/// Microseconds as `850.0us`, `5.12ms` or `1.30s`; `-` for none.
pub(crate) fn fmt_us(us: Option<f64>) -> String {
    match us {
        None => "-".into(),
        Some(v) if v < 1000.0 => format!("{v:.1}us"),
        Some(v) if v < 1e6 => format!("{:.2}ms", v / 1e3),
        Some(v) => format!("{:.2}s", v / 1e6),
    }
}

fn fmt_len(s: &SizeReport) -> String {
    if s.frame_len.fract() == 0.0 {
        format!("{}", s.frame_len)
    } else {
        format!("{:.1}", s.frame_len)
    }
}

fn lat_cols(l: &LatencySummary) -> String {
    format!(
        "{:>9} {:>9} {:>9} {:>9} {:>9} {:>9}",
        fmt_us(l.min_us),
        fmt_us(l.avg_us),
        fmt_us(l.p99_us),
        fmt_us(l.p999_us),
        fmt_us(l.max_us),
        fmt_us(l.jitter_us)
    )
}

impl BenchReport {
    /// The report as text tables: one per test, a row per size, then every
    /// trial. Run metadata is not included; put [`RunInfo::lines`](super::RunInfo::lines) above it.
    pub fn text(&self) -> String {
        let mut o = String::new();
        let c = &self.config;
        let tests: Vec<&str> = c.tests.iter().map(|t| t.name()).collect();
        let _ = writeln!(
            o,
            "RFC 2544 benchmark: {}; line rate {} Mbit/s; trials of {}s{}{}, {} repetition(s)",
            tests.join(", "),
            c.line_rate_mbps,
            c.trial_duration_s,
            c.trial_packets
                .map_or(String::new(), |p| format!(" or {p} frames")),
            if c.warmup_s > 0.0 {
                format!(", warm-up {}s at {}%", c.warmup_s, c.warmup_load)
            } else {
                String::new()
            },
            c.repetitions
        );
        let _ = writeln!(
            o,
            "Frame sizes are without the 4-byte FCS; loads are percent of the line rate, counting 24 bytes of FCS, preamble and gap per frame."
        );
        if self.stopped {
            let _ = writeln!(o, "STOPPED before the end: the results are partial.");
        }
        let w = self
            .sizes
            .iter()
            .map(|s| s.size.len())
            .max()
            .unwrap_or(4)
            .max(4);

        if self.sizes.iter().any(|s| s.throughput.is_some()) {
            let _ = writeln!(
                o,
                "\nThroughput (highest load losing at most {}%, searched to {}%):",
                c.loss_threshold, c.resolution
            );
            let _ = writeln!(
                o,
                "  {:<w$} {:>7} {:>8} {:>12} {:>10} {:>10}  note",
                "size", "frame", "load %", "frames/s", "Mbit/s", "L1 Mbit/s"
            );
            for s in &self.sizes {
                let Some(t) = &s.throughput else { continue };
                let mut note = Vec::new();
                if t.load_pct == 0.0 {
                    note.push("no load passed".to_string());
                }
                if t.repetitions.len() > 1 {
                    let r: Vec<String> = t.repetitions.iter().map(|l| format!("{l:.2}")).collect();
                    note.push(format!("runs {}", r.join("/")));
                }
                if t.sender_limited {
                    note.push("sender below the offered rate".into());
                }
                let _ = writeln!(
                    o,
                    "  {:<w$} {:>7} {:>8.2} {:>12.0} {:>10.2} {:>10.2}  {}",
                    s.size,
                    fmt_len(s),
                    t.load_pct,
                    t.pps,
                    t.mbps,
                    t.l1_mbps,
                    note.join("; ")
                );
            }
        }

        if self.sizes.iter().any(|s| s.latency.is_some()) {
            let _ = writeln!(o, "\nLatency:");
            let _ = writeln!(
                o,
                "  {:<w$} {:>8} {:>7} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9}",
                "size", "load %", "loss %", "min", "avg", "p99", "p99.9", "max", "jitter"
            );
            for s in &self.sizes {
                let Some(l) = &s.latency else { continue };
                let _ = writeln!(
                    o,
                    "  {:<w$} {:>8.2} {:>7.3} {}",
                    s.size,
                    l.load_pct,
                    l.loss_pct,
                    lat_cols(&l.latency)
                );
                if l.latency.negative > 0 {
                    let _ = writeln!(
                        o,
                        "  {:<w$} warning: {} frames arrived before they were sent; the clocks disagree",
                        "", l.latency.negative
                    );
                }
            }
        }

        if self.sizes.iter().any(|s| !s.frame_loss.is_empty()) {
            let _ = writeln!(o, "\nFrame loss:");
            let _ = writeln!(
                o,
                "  {:<w$} {:>8} {:>12} {:>12} {:>12} {:>8}",
                "size", "load %", "offered/s", "sent", "received", "loss %"
            );
            for s in &self.sizes {
                for p in &s.frame_loss {
                    let _ = writeln!(
                        o,
                        "  {:<w$} {:>8.2} {:>12.0} {:>12} {:>12} {:>8.3}",
                        s.size, p.load_pct, p.offered_pps, p.tx, p.rx, p.loss_pct
                    );
                }
            }
        }

        if self.sizes.iter().any(|s| s.back_to_back.is_some()) {
            let _ = writeln!(o, "\nBack-to-back (longest burst without loss):");
            let _ = writeln!(
                o,
                "  {:<w$} {:>8} {:>10} {:>10}  note",
                "size", "load %", "frames", "burst"
            );
            for s in &self.sizes {
                let Some(b) = &s.back_to_back else { continue };
                let mut note = Vec::new();
                if b.repetitions.len() > 1 {
                    let r: Vec<String> = b.repetitions.iter().map(u64::to_string).collect();
                    note.push(format!("runs {}", r.join("/")));
                }
                if b.at_limit {
                    note.push(format!("reached burst_max ({})", c.burst_max));
                }
                let _ = writeln!(
                    o,
                    "  {:<w$} {:>8.2} {:>10.0} {:>10}  {}",
                    s.size,
                    b.load_pct,
                    b.frames,
                    fmt_us(Some(b.duration_us)),
                    note.join("; ")
                );
            }
        }

        if self.sizes.iter().any(|s| s.sweep.is_some()) {
            let _ = writeln!(
                o,
                "\nSweep ({} trial(s) per size after a warm-up; median, and min-max over the trials):",
                c.repetitions
            );
            let _ = writeln!(
                o,
                "  {:<w$} {:>7} {:>8} {:>12} {:>25} {:>8} {:>10} {:>10} {:>12} {:>8} {:>9} {:>9}  note",
                "size", "frame", "load %", "sent/s", "min-max", "spread%", "Mbit/s", "L1 Mbit/s", "received/s", "loss %", "p50", "p99"
            );
            for s in &self.sizes {
                let Some(r) = &s.sweep else { continue };
                let note = if r.sender_limited > 0 {
                    format!(
                        "sender below the offered rate in {} of {}",
                        r.sender_limited, r.trials
                    )
                } else {
                    String::new()
                };
                let _ = writeln!(
                    o,
                    "  {:<w$} {:>7} {:>8.2} {:>12.0} {:>25} {:>8.2} {:>10.2} {:>10.2} {:>12.0} {:>8.3} {:>9} {:>9}  {}",
                    s.size,
                    fmt_len(s),
                    r.load_pct,
                    r.tx_pps.median,
                    format!("{:.0}-{:.0}", r.tx_pps.min, r.tx_pps.max),
                    r.tx_pps.spread_pct,
                    r.tx_mbps.median,
                    r.tx_l1_mbps.median,
                    r.rx_pps.median,
                    r.loss_pct.median,
                    fmt_us(r.latency_p50_us.as_ref().map(|l| l.median)),
                    fmt_us(r.latency_p99_us.as_ref().map(|l| l.median)),
                    note
                );
            }
        }

        let grown: Vec<String> = self
            .sizes
            .iter()
            .filter(|s| s.grown)
            .map(|s| format!("{} (sent {})", s.size, fmt_len(s)))
            .collect();
        if !grown.is_empty() {
            let _ = writeln!(
                o,
                "\nNote: frames of {} were sent longer than asked, to hold their headers and the 28-byte signature.",
                grown.join(", ")
            );
        }

        let _ = writeln!(o, "\nTrials:");
        let _ = writeln!(
            o,
            "  {:<w$} {:<12} {:>3} {:>8} {:>8} {:>11} {:>11} {:>10} {:>10} {:>8} {:>9} {:>9}  ",
            "size",
            "test",
            "run",
            "load %",
            "burst",
            "offered/s",
            "achieved/s",
            "sent",
            "received",
            "loss %",
            "avg",
            "max"
        );
        for s in &self.sizes {
            for t in &s.trials {
                let verdict = match t.passed {
                    Some(true) => "pass",
                    Some(false) => "fail",
                    None => "",
                };
                let _ = writeln!(
                    o,
                    "  {:<w$} {:<12} {:>3} {:>8.2} {:>8} {:>11.0} {:>11.0} {:>10} {:>10} {:>8.3} {:>9} {:>9}  {}{}",
                    s.size,
                    t.test.name(),
                    t.repetition,
                    t.load_pct,
                    t.burst.map_or("-".to_string(), |b| b.to_string()),
                    t.offered_pps,
                    t.achieved_pps,
                    t.tx,
                    t.rx,
                    t.loss_pct,
                    fmt_us(t.latency.avg_us),
                    fmt_us(t.latency.max_us),
                    verdict,
                    if t.sender_limited() { " (sender slow)" } else { "" }
                );
            }
        }
        let _ = writeln!(o, "\nTook {:.1}s.", self.elapsed_s);
        o
    }

    /// The report as Markdown: the test conditions (`info`: NIC and driver,
    /// link speed, CPU, kernel, backend and queues, workers and their CPUs),
    /// the method, and a table per test, then the full text report.
    pub fn markdown(&self, info: &RunInfo) -> String {
        let mut o = String::new();
        let c = &self.config;
        let _ = writeln!(o, "# FeroTRX benchmark report\n");
        let _ = writeln!(o, "## Test conditions\n");
        let _ = writeln!(o, "| | |\n|---|---|");
        let mut row = |k: &str, v: Option<String>| {
            if let Some(v) = v.filter(|v| !v.is_empty()) {
                let _ = writeln!(o, "| {k} | {} |", v.replace('|', "\\|"));
            }
        };
        row("FeroTRX", Some(info.ferotrx_version.clone()));
        row("Started (UTC)", Some(info.started.clone()));
        row("Command", info.command.clone().map(|c| format!("`{c}`")));
        row("Host", info.hostname.clone());
        row(
            "OS",
            Some(match &info.kernel {
                Some(k) => format!("{} {k} ({})", info.os, info.arch),
                None => format!("{} ({})", info.os, info.arch),
            }),
        );
        row(
            "CPU",
            Some(match &info.cpu {
                Some(m) => format!("{m}, {} threads", info.cpus),
                None => format!("{} threads", info.cpus),
            }),
        );
        row("CPU affinity", info.cpu_affinity.clone());
        row(
            "Workers",
            info.workers.map(|w| match &info.pinned_cpus {
                Some(p) => format!("{w}, pinned to CPUs {p}"),
                None => format!("{w}, not pinned"),
            }),
        );
        row("Sender (backend, queues)", info.backend.clone());
        let iface =
            |d: &Option<super::InterfaceDetails>| d.as_ref().map(super::InterfaceDetails::describe);
        row("Sending interface", iface(&info.tx_interface));
        row("Receiving interface", iface(&info.rx_interface));
        row("Timestamps", info.timestamps.clone());
        row(
            "Profile",
            info.profile.clone().map(|p| match &info.profile_sha256 {
                Some(h) => format!("{p} (sha256 {})", &h[..h.len().min(16)]),
                None => p,
            }),
        );
        let tests: Vec<&str> = c.tests.iter().map(|t| t.name()).collect();
        let _ = writeln!(o, "\n## Method\n");
        let _ = writeln!(
            o,
            "Tests {} for frame sizes {} (without the 4-byte FCS), on a {} Mbit/s line \
             (24 bytes of FCS, preamble and gap counted per frame). Trials of {} s{}, \
             {} repetition(s){}.{}",
            tests.join(", "),
            c.sizes.join(", "),
            c.line_rate_mbps,
            c.trial_duration_s,
            c.trial_packets
                .map_or(String::new(), |p| format!(" or {p} frames")),
            c.repetitions,
            if c.warmup_s > 0.0 {
                format!(
                    ", a warm-up of {} s at {}% before each size",
                    c.warmup_s, c.warmup_load
                )
            } else {
                String::new()
            },
            if c.tests.contains(&BenchTest::Sweep) {
                format!(
                    " The sweep sends a warm-up trial at {}% for each size first and throws it \
                     away, then the trials; it reports the median of the trials, their minimum \
                     and maximum, and the spread (max - min in percent of the median).",
                    c.max_load
                )
            } else {
                String::new()
            }
        );
        if self.stopped {
            let _ = writeln!(o, "\n**Stopped before the end: the results are partial.**");
        }
        if self.sizes.iter().any(|s| s.sweep.is_some()) {
            let _ = writeln!(o, "\n## Sweep\n");
            let _ = writeln!(
                o,
                "| Size | Frame | Load % | Sent frames/s (median) | min | max | spread % | Mbit/s | L1 Mbit/s | Received/s | Loss % (median, max) | Latency p50 | Latency p99 |"
            );
            let _ = writeln!(
                o,
                "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
            );
            for s in &self.sizes {
                let Some(r) = &s.sweep else { continue };
                let lat = |l: &Option<Spread>| fmt_us(l.as_ref().map(|l| l.median));
                let _ = writeln!(
                    o,
                    "| {} | {} | {:.2} | {:.0} | {:.0} | {:.0} | {:.2} | {:.2} | {:.2} | {:.0} | {:.3}, {:.3} | {} | {} |",
                    s.size,
                    fmt_len(s),
                    r.load_pct,
                    r.tx_pps.median,
                    r.tx_pps.min,
                    r.tx_pps.max,
                    r.tx_pps.spread_pct,
                    r.tx_mbps.median,
                    r.tx_l1_mbps.median,
                    r.rx_pps.median,
                    r.loss_pct.median,
                    r.loss_pct.max,
                    lat(&r.latency_p50_us),
                    lat(&r.latency_p99_us)
                );
            }
            let limited: Vec<String> = self
                .sizes
                .iter()
                .filter_map(|s| {
                    s.sweep
                        .as_ref()
                        .filter(|r| r.sender_limited > 0)
                        .map(|r| format!("{} ({} of {})", s.size, r.sender_limited, r.trials))
                })
                .collect();
            if !limited.is_empty() {
                let _ = writeln!(
                    o,
                    "\nThe sender stayed below 97% of the offered rate in trials of {}: there the figures are the sender's limit on this machine.",
                    limited.join(", ")
                );
            }
        }
        if self.sizes.iter().any(|s| s.throughput.is_some()) {
            let _ = writeln!(o, "\n## Throughput\n");
            let _ = writeln!(o, "| Size | Frame | Load % | Frames/s | Mbit/s | L1 Mbit/s |\n|---|---:|---:|---:|---:|---:|");
            for s in &self.sizes {
                let Some(t) = &s.throughput else { continue };
                let _ = writeln!(
                    o,
                    "| {} | {} | {:.2} | {:.0} | {:.2} | {:.2} |",
                    s.size,
                    fmt_len(s),
                    t.load_pct,
                    t.pps,
                    t.mbps,
                    t.l1_mbps
                );
            }
        }
        if self.sizes.iter().any(|s| s.latency.is_some()) {
            let _ = writeln!(o, "\n## Latency\n");
            let _ = writeln!(o, "| Size | Load % | Loss % | min | avg | p99 | p99.9 | max | jitter |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|");
            for s in &self.sizes {
                let Some(l) = &s.latency else { continue };
                let x = &l.latency;
                let _ = writeln!(
                    o,
                    "| {} | {:.2} | {:.3} | {} | {} | {} | {} | {} | {} |",
                    s.size,
                    l.load_pct,
                    l.loss_pct,
                    fmt_us(x.min_us),
                    fmt_us(x.avg_us),
                    fmt_us(x.p99_us),
                    fmt_us(x.p999_us),
                    fmt_us(x.max_us),
                    fmt_us(x.jitter_us)
                );
            }
        }
        let _ = writeln!(o, "\n## Full report\n\n```text\n{}```", self.text());
        o
    }

    /// True when a test was asked for and gave no result for some size.
    pub fn is_complete(&self) -> bool {
        !self.stopped
            && self.sizes.len() == self.config.sizes.len()
            && self.sizes.iter().all(|s| {
                self.config.tests.iter().all(|t| match t {
                    BenchTest::Throughput => s.throughput.is_some(),
                    // No latency without a throughput that passed.
                    BenchTest::Latency => {
                        s.latency.is_some()
                            || s.throughput.as_ref().is_some_and(|t| t.load_pct == 0.0)
                    }
                    BenchTest::FrameLoss => !s.frame_loss.is_empty(),
                    BenchTest::BackToBack => s.back_to_back.is_some(),
                    BenchTest::Sweep => s.sweep.is_some(),
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use std::time::Duration;

    struct Perfect;
    impl TrialRunner for Perfect {
        fn run(&mut self, t: &Trial) -> crate::Result<TrialResult> {
            let d = t.duration.unwrap();
            let tx = t.packets.unwrap_or((t.pps * d.as_secs_f64()) as u64);
            let mut latency = LatencyStats::default();
            latency.record(Some(Duration::from_micros(80)));
            Ok(TrialResult {
                tx,
                rx: tx,
                elapsed: Duration::from_secs_f64(tx as f64 / t.pps),
                latency,
                ..Default::default()
            })
        }
        fn sent_len(&self, size: usize) -> usize {
            size.max(70)
        }
    }

    #[test]
    fn text_has_every_table() {
        let config = BenchConfig {
            tests: BenchTest::ALL.to_vec(),
            sizes: vec!["60".parse().unwrap(), "imix".parse().unwrap()],
            trial_duration: Duration::from_millis(10),
            burst_max: 50,
            ..Default::default()
        };
        let r = run_benchmark(&config, &mut Perfect, |_, _| {}).unwrap();
        assert!(r.is_complete());
        let text = r.text();
        for want in [
            "Throughput",
            "Latency:",
            "Frame loss:",
            "Back-to-back",
            "reached burst_max (50)",
            "imix",
            "frames of 60 (sent 70), imix (sent 363.7) were sent longer",
            "80.0us",
            "Sweep (1 trial(s) per size",
        ] {
            assert!(text.contains(want), "{want} missing in:\n{text}");
        }
        let mut info = RunInfo::new();
        info.workers = Some(2);
        info.pinned_cpus = Some("2-3".into());
        info.backend = Some("af_xdp on eth0 queue 0".into());
        let md = r.markdown(&info);
        for want in [
            "## Test conditions",
            "| Workers | 2, pinned to CPUs 2-3 |",
            "| Sender (backend, queues) | af_xdp on eth0 queue 0 |",
            "## Sweep",
            "| imix | 363.7 |",
            "## Full report",
        ] {
            assert!(md.contains(want), "{want} missing in:\n{md}");
        }
    }
}
