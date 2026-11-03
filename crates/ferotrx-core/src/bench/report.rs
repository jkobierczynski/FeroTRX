//! The human-readable form of a [`BenchReport`].

use std::fmt::Write;

use super::{BenchReport, BenchTest, LatencySummary, SizeReport};

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
        ] {
            assert!(text.contains(want), "{want} missing in:\n{text}");
        }
    }
}
