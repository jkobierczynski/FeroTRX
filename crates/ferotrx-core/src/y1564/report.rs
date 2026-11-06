//! The human-readable form of a [`Y1564Report`].

use std::fmt::Write;

use super::{Color, ServiceResult, StepRecord, Y1564Report};

fn fmt_ms(v: Option<f64>) -> String {
    match v {
        None => "-".into(),
        Some(v) if v < 1.0 => format!("{:.1}us", v * 1000.0),
        Some(v) if v < 1000.0 => format!("{v:.2}ms"),
        Some(v) => format!("{:.2}s", v / 1000.0),
    }
}

fn fmt_flr(v: f64) -> String {
    if v == 0.0 || v >= 0.1 {
        format!("{v:.2}%")
    } else {
        format!("{v:.4}%")
    }
}

fn verdict(passed: bool) -> &'static str {
    if passed {
        "PASS"
    } else {
        "FAIL"
    }
}

impl ServiceResult {
    /// What failed, or `-`.
    fn why(&self) -> String {
        let mut all = self.failures.clone();
        all.extend(self.notes.iter().map(|n| format!("note: {n}")));
        if all.is_empty() {
            String::new()
        } else {
            format!("  {}", all.join("; "))
        }
    }
}

impl StepRecord {
    /// One line per service of the step, e.g. for progress.
    pub fn lines(&self) -> Vec<String> {
        self.services
            .iter()
            .map(|s| {
                let offered: f64 = self
                    .flows
                    .iter()
                    .filter(|f| f.service == s.service)
                    .map(|f| f.offered_mbps)
                    .sum();
                let what = if self.step == super::StepKind::Performance {
                    "performance".to_string()
                } else {
                    format!("{} {}", self.test, self.name)
                };
                let mut line = format!(
                    "{what}: {} offered {:.3} Mbit/s, IR {:.3} Mbit/s, FLR {}, FTD {}, FDV {}",
                    s.service,
                    offered,
                    s.ir_mbps,
                    fmt_flr(s.flr_pct),
                    fmt_ms(s.ftd_ms),
                    fmt_ms(s.fdv_ms)
                );
                if let Some(y) = s.yellow_flr_pct {
                    let _ = write!(line, ", yellow lost {}", fmt_flr(y));
                }
                if let Some(a) = s.availability_pct {
                    let _ = write!(line, ", availability {a:.3}%");
                }
                let _ = write!(line, ": {}{}", verdict(s.passed), s.why());
                line
            })
            .collect()
    }
}

impl Y1564Report {
    /// The report as text: the services, a table per service for the
    /// configuration test, one for the performance test, and the verdicts.
    /// Run metadata is not included; put [`RunInfo::lines`](crate::RunInfo::lines) above it.
    pub fn text(&self) -> String {
        let mut o = String::new();
        let c = &self.config;
        let tests: Vec<&str> = c.tests.iter().map(|t| t.name()).collect();
        let _ = writeln!(
            o,
            "Y.1564 service activation: {}; line rate {} Mbit/s; rates count {}",
            tests.join(", "),
            c.line_rate_mbps,
            if c.layer1 {
                "frames with FCS, preamble and gap (layer 1)"
            } else {
                "frames with FCS (layer 2)"
            }
        );
        if self.stopped {
            let _ = writeln!(o, "STOPPED before the end: the results are partial.");
        }
        let sw = c
            .services
            .iter()
            .map(|s| s.size.len())
            .max()
            .unwrap_or(5)
            .max(5);
        let nw = c
            .services
            .iter()
            .map(|s| s.name.len())
            .max()
            .unwrap_or(7)
            .max(7);
        let _ = writeln!(o, "\nServices:");
        let _ = writeln!(
            o,
            "  {:<nw$} {:>10} {:>10} {:>8} {:>8} {:<sw$} {:>8} {:>9} {:>9} {:>8}",
            "service", "CIR Mb/s", "EIR Mb/s", "CBS", "EBS", "sizes", "FLR", "FTD", "FDV", "avail"
        );
        for s in &c.services {
            let _ = writeln!(
                o,
                "  {:<nw$} {:>10} {:>10} {:>8} {:>8} {:<sw$} {:>8} {:>9} {:>9} {:>8}",
                s.name,
                s.cir_mbps,
                s.eir_mbps,
                s.cbs,
                s.ebs,
                s.size,
                format!("{}%", s.flr_pct),
                fmt_ms(s.ftd_ms),
                fmt_ms(s.fdv_ms),
                s.availability_pct.map_or("-".into(), |a| format!("{a}%"))
            );
        }
        if !self.configuration.is_empty() {
            let _ = writeln!(
                o,
                "\nService configuration test ({}s per step):",
                c.step_duration_s
            );
            for svc in &c.services {
                let steps: Vec<(&StepRecord, &ServiceResult)> = self
                    .configuration
                    .iter()
                    .filter_map(|st| {
                        st.services
                            .iter()
                            .find(|r| r.service == svc.name)
                            .map(|r| (st, r))
                    })
                    .collect();
                if steps.is_empty() {
                    continue;
                }
                let _ = writeln!(o, "  {}:", svc.name);
                let _ = writeln!(
                    o,
                    "    {:<10} {:>11} {:>11} {:>9} {:>9} {:>9} {:>11}  result",
                    "step", "green Mb/s", "yellow Mb/s", "IR Mb/s", "FLR", "FTD", "FDV"
                );
                for (st, r) in steps {
                    let offered = |color: Color| {
                        st.flows
                            .iter()
                            .filter(|f| f.service == svc.name && f.color == color)
                            .map(|f| {
                                let mut t = format!("{:.3}", f.offered_mbps);
                                if f.burst.is_some() {
                                    t.push('*');
                                }
                                t
                            })
                            .next()
                            .unwrap_or_else(|| "-".into())
                    };
                    let _ = writeln!(
                        o,
                        "    {:<10} {:>11} {:>11} {:>9.3} {:>9} {:>9} {:>11}  {}{}",
                        st.name,
                        offered(Color::Green),
                        offered(Color::Yellow),
                        r.ir_mbps,
                        fmt_flr(r.flr_pct),
                        fmt_ms(r.ftd_ms),
                        fmt_ms(r.fdv_ms),
                        verdict(r.passed),
                        r.why()
                    );
                }
            }
            if self
                .configuration
                .iter()
                .flat_map(|s| &s.flows)
                .any(|f| f.burst.is_some())
            {
                let _ = writeln!(o, "  * sent in bursts of CBS or EBS bytes at line rate");
            }
            let _ = writeln!(
                o,
                "  FLR, FTD (mean) and FDV (p99 - min) are of the green frames; IR is all that arrived."
            );
        }
        if let Some(p) = &self.performance {
            let _ = writeln!(
                o,
                "\nService performance test ({:.0}s, intervals of {}s):",
                p.duration_s, c.interval_s
            );
            let _ = writeln!(
                o,
                "  {:<12} {:>9} {:>9} {:>9} {:>11} {:>11} {:>7}  result",
                "service", "IR Mb/s", "FLR", "FTD", "FDV", "available", "SES"
            );
            for r in &p.services {
                let _ = writeln!(
                    o,
                    "  {:<12} {:>9.3} {:>9} {:>9} {:>11} {:>11} {:>7}  {}{}",
                    r.service,
                    r.ir_mbps,
                    fmt_flr(r.flr_pct),
                    fmt_ms(r.ftd_ms),
                    fmt_ms(r.fdv_ms),
                    r.availability_pct
                        .map_or("-".into(), |a| format!("{a:.3}%")),
                    r.ses.map_or("-".into(), |s| s.to_string()),
                    verdict(r.passed),
                    r.why()
                );
            }
        }
        let _ = writeln!(o, "\nVerdict:");
        let opt = |v: Option<bool>| v.map_or("-", verdict);
        for v in &self.services {
            let _ = writeln!(
                o,
                "  {:<12} configuration {:<4}  performance {:<4}  {}",
                v.service,
                opt(v.configuration),
                opt(v.performance),
                verdict(v.passed)
            );
        }
        let _ = writeln!(
            o,
            "Y.1564: {}{}",
            verdict(self.passed),
            if self.stopped { " (stopped)" } else { "" }
        );
        o
    }
}
