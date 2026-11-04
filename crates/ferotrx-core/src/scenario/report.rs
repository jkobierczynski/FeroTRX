//! Running a scenario, its report (JSON, JUnit XML, text) and comparing two runs.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::metric::{Better, CheckKind, Metrics, Unit};
use super::{Check, Scenario};
use crate::wall_clock;

/// The `format` of a [`ScenarioReport`] in JSON.
pub const REPORT_FORMAT: &str = "ferotrx-scenario-1";

/// What one run of a check measured.
#[derive(Clone, Debug, Default)]
pub struct CheckRun {
    pub metrics: Metrics,
    /// One line on what happened, for people.
    pub summary: String,
}

/// Runs the workload of a check: opens its interfaces, sends, waits for the
/// end and collects the metrics. `stop` is set when the whole scenario is
/// being stopped (Ctrl-C); the run should end soon after.
pub trait CheckRunner {
    fn run(&mut self, check: &Check, stop: &Arc<AtomicBool>) -> Result<CheckRun, String>;
}

/// The verdict on a check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Every condition held.
    Pass,
    /// The run went, and a condition did not hold.
    Fail,
    /// The run could not be made: an interface missing, a pcap unreadable.
    Error,
    /// Not run: left out with `--check`, or the scenario was stopped.
    Skipped,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
            Verdict::Error => "error",
            Verdict::Skipped => "skipped",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS ",
            Verdict::Fail => "FAIL ",
            Verdict::Error => "ERROR",
            Verdict::Skipped => "SKIP ",
        }
    }

    fn is_bad(self) -> bool {
        matches!(self, Verdict::Fail | Verdict::Error)
    }
}

/// How one condition came out.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConditionResult {
    /// The condition, as written.
    pub condition: String,
    pub metric: String,
    /// What was measured; absent when the run did not measure it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual: Option<f64>,
    pub pass: bool,
}

/// The outcome of one check.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CheckReport {
    pub name: String,
    /// `tcp`, `udp` or `traffic`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub verdict: Verdict,
    /// `complete`, `blocked` or `any`.
    pub expect: String,
    /// Runs made; more than one when a failing check was run again.
    pub attempts: u32,
    pub elapsed_s: f64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The last run's conditions.
    #[serde(default)]
    pub conditions: Vec<ConditionResult>,
    /// The last run's metrics.
    #[serde(default)]
    pub metrics: Metrics,
}

impl CheckReport {
    fn kind(&self) -> Option<CheckKind> {
        CheckKind::from_name(&self.kind)
    }

    /// The conditions that did not hold, e.g. `loss_pct < 1% (was 2.5%)`.
    pub fn failures(&self) -> Vec<String> {
        self.conditions
            .iter()
            .filter(|c| !c.pass)
            .map(|c| {
                let was = match c.actual {
                    Some(v) => self.format_metric(&c.metric, v),
                    None => "not measured".into(),
                };
                format!("{} (was {was})", c.condition)
            })
            .collect()
    }

    /// A metric's value with its unit.
    pub fn format_metric(&self, metric: &str, value: f64) -> String {
        match self.kind().and_then(|k| k.metric(metric)) {
            Some(def) => def.unit.format(value),
            None => Unit::Count.format(value),
        }
    }
}

/// How many checks ended which way.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub checks: usize,
    pub passed: usize,
    pub failed: usize,
    pub errors: usize,
    pub skipped: usize,
}

/// A run of a scenario: what `ferotrx scenario run` writes with `--report`
/// and keeps in the history.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScenarioReport {
    /// [`REPORT_FORMAT`].
    pub format: String,
    pub scenario: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// The FeroTRX version that ran it.
    pub version: String,
    /// When it started, UTC, RFC 3339.
    pub started: String,
    pub started_unix: f64,
    pub elapsed_s: f64,
    /// The variables it ran with.
    #[serde(default)]
    pub vars: BTreeMap<String, String>,
    /// True when it was stopped before every check ran.
    #[serde(default)]
    pub stopped: bool,
    pub summary: Summary,
    pub checks: Vec<CheckReport>,
}

/// What [`run_scenario`] tells its caller as it goes.
pub enum Progress<'a> {
    /// A check is about to run (`attempt` from 1).
    Starting { check: &'a Check, attempt: u32 },
    /// A check has its verdict.
    Finished(&'a CheckReport),
}

/// Settings of [`run_scenario`].
pub struct RunOptions<'a> {
    /// Only the checks with these names; all when empty.
    pub only: Vec<String>,
    /// Set from another thread (Ctrl-C) to stop: the running check ends and
    /// the rest are skipped.
    pub stop: Arc<AtomicBool>,
    /// Recorded in the report.
    pub version: String,
    /// Called as checks start and end.
    pub progress: Option<&'a mut dyn FnMut(Progress<'_>)>,
}

impl Default for RunOptions<'_> {
    fn default() -> Self {
        Self {
            only: Vec::new(),
            stop: Arc::new(AtomicBool::new(false)),
            version: String::new(),
            progress: None,
        }
    }
}

/// Runs the checks of a scenario one after the other and judges each.
///
/// A check whose conditions do not hold is run again while it has
/// attempts left; an error (the run could not be made) is not retried.
pub fn run_scenario(
    scenario: &Scenario,
    runner: &mut dyn CheckRunner,
    mut options: RunOptions<'_>,
) -> ScenarioReport {
    let started_unix = wall_clock();
    let t0 = Instant::now();
    let mut checks = Vec::with_capacity(scenario.checks.len());
    let mut stopped = false;
    for check in &scenario.checks {
        let base = CheckReport {
            name: check.name.clone(),
            kind: check.kind().as_str().into(),
            description: check.description.clone(),
            verdict: Verdict::Skipped,
            expect: check.expect.as_str().into(),
            attempts: 0,
            elapsed_s: 0.0,
            summary: String::new(),
            error: None,
            conditions: Vec::new(),
            metrics: Metrics::new(),
        };
        let wanted = options.only.is_empty() || options.only.contains(&check.name);
        if !wanted || options.stop.load(Ordering::Relaxed) {
            stopped |= wanted;
            if let Some(p) = options.progress.as_mut() {
                p(Progress::Finished(&base));
            }
            checks.push(base);
            continue;
        }
        let report = run_check(check, runner, &mut options, base);
        if let Some(p) = options.progress.as_mut() {
            p(Progress::Finished(&report));
        }
        checks.push(report);
    }
    let count = |v: Verdict| checks.iter().filter(|c| c.verdict == v).count();
    let summary = Summary {
        checks: checks.len(),
        passed: count(Verdict::Pass),
        failed: count(Verdict::Fail),
        errors: count(Verdict::Error),
        skipped: count(Verdict::Skipped),
    };
    ScenarioReport {
        format: REPORT_FORMAT.into(),
        scenario: scenario.name.clone(),
        description: scenario.description.clone(),
        file: scenario.path.as_ref().map(|p| p.display().to_string()),
        version: options.version,
        started: format_utc(started_unix),
        started_unix: started_unix.as_secs_f64(),
        elapsed_s: t0.elapsed().as_secs_f64(),
        vars: scenario.vars.clone(),
        stopped,
        summary,
        checks,
    }
}

fn run_check(
    check: &Check,
    runner: &mut dyn CheckRunner,
    options: &mut RunOptions<'_>,
    mut report: CheckReport,
) -> CheckReport {
    let conditions = check.conditions();
    let t0 = Instant::now();
    for attempt in 1..=check.attempts {
        if attempt > 1 && options.stop.load(Ordering::Relaxed) {
            break;
        }
        if let Some(p) = options.progress.as_mut() {
            p(Progress::Starting { check, attempt });
        }
        report.attempts = attempt;
        match runner.run(check, &options.stop) {
            Err(e) => {
                report.verdict = Verdict::Error;
                report.error = Some(e);
                report.conditions.clear();
                break;
            }
            Ok(run) => {
                report.conditions = conditions
                    .iter()
                    .map(|c| {
                        let (actual, pass) = c.eval(&run.metrics);
                        ConditionResult {
                            condition: c.text.clone(),
                            metric: c.metric.clone(),
                            actual,
                            pass,
                        }
                    })
                    .collect();
                report.metrics = run.metrics;
                report.summary = run.summary;
                report.error = None;
                if report.conditions.iter().all(|c| c.pass) {
                    report.verdict = Verdict::Pass;
                    break;
                }
                report.verdict = Verdict::Fail;
            }
        }
    }
    report.elapsed_s = t0.elapsed().as_secs_f64();
    report
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // Characters XML 1.0 does not allow.
            c if (c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r') => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

impl ScenarioReport {
    /// True when no check failed or had an error, and at least one ran.
    pub fn passed(&self) -> bool {
        self.summary.failed == 0 && self.summary.errors == 0 && self.summary.passed > 0
    }

    /// The report as JUnit XML, which CI systems (GitHub Actions, GitLab,
    /// Jenkins) show as test results: one test suite, one test case per check.
    pub fn junit(&self) -> String {
        let s = &self.summary;
        let mut x = String::new();
        x.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        let _ = writeln!(
            x,
            "<testsuites name=\"ferotrx\" tests=\"{}\" failures=\"{}\" errors=\"{}\" skipped=\"{}\" time=\"{:.3}\">",
            s.checks, s.failed, s.errors, s.skipped, self.elapsed_s
        );
        let _ = writeln!(
            x,
            "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"{}\" skipped=\"{}\" time=\"{:.3}\" timestamp=\"{}\">",
            xml_escape(&self.scenario),
            s.checks,
            s.failed,
            s.errors,
            s.skipped,
            self.elapsed_s,
            xml_escape(self.started.trim_end_matches('Z'))
        );
        x.push_str("    <properties>\n");
        let mut props = vec![("ferotrx.version".to_string(), self.version.clone())];
        if let Some(f) = &self.file {
            props.push(("scenario.file".into(), f.clone()));
        }
        for (k, v) in &self.vars {
            props.push((format!("var.{k}"), v.clone()));
        }
        for (k, v) in props {
            let _ = writeln!(
                x,
                "      <property name=\"{}\" value=\"{}\"/>",
                xml_escape(&k),
                xml_escape(&v)
            );
        }
        x.push_str("    </properties>\n");
        for c in &self.checks {
            let _ = writeln!(
                x,
                "    <testcase classname=\"{}.{}\" name=\"{}\" time=\"{:.3}\">",
                xml_escape(&self.scenario),
                xml_escape(&c.kind),
                xml_escape(&c.name),
                c.elapsed_s
            );
            match c.verdict {
                Verdict::Pass => {}
                Verdict::Fail => {
                    let failures = c.failures();
                    let _ = writeln!(
                        x,
                        "      <failure type=\"fail\" message=\"{}\">{}</failure>",
                        xml_escape(&failures.join("; ")),
                        xml_escape(&format!(
                            "expected {}; failed after {} attempt(s):\n{}",
                            c.expect,
                            c.attempts,
                            failures.join("\n")
                        ))
                    );
                }
                Verdict::Error => {
                    let _ = writeln!(
                        x,
                        "      <error type=\"error\" message=\"{}\"/>",
                        xml_escape(c.error.as_deref().unwrap_or("error"))
                    );
                }
                Verdict::Skipped => x.push_str("      <skipped/>\n"),
            }
            if !c.metrics.is_empty() || !c.summary.is_empty() {
                let mut out = String::new();
                if !c.summary.is_empty() {
                    out.push_str(&c.summary);
                    out.push('\n');
                }
                for (k, v) in &c.metrics {
                    let _ = writeln!(out, "{k} = {}", c.format_metric(k, *v));
                }
                let _ = writeln!(x, "      <system-out>{}</system-out>", xml_escape(&out));
            }
            x.push_str("    </testcase>\n");
        }
        x.push_str("  </testsuite>\n</testsuites>\n");
        x
    }

    /// The report for people: a line per check, what failed, and a total.
    pub fn text(&self) -> String {
        let mut t = String::new();
        let _ = writeln!(t, "scenario {} ({})", self.scenario, self.started);
        for c in &self.checks {
            let _ = writeln!(t, "{}", check_line(c));
            for f in c.failures() {
                let _ = writeln!(t, "        not met: {f}");
            }
            if let Some(e) = &c.error {
                let _ = writeln!(t, "        error: {e}");
            }
        }
        let _ = write!(t, "{}", self.total_line());
        t
    }

    /// `3 passed, 1 failed, 0 errors, 0 skipped in 12.3 s`.
    pub fn total_line(&self) -> String {
        let s = &self.summary;
        format!(
            "{}: {} passed, {} failed, {} errors, {} skipped in {:.1} s{}",
            if self.passed() { "PASSED" } else { "FAILED" },
            s.passed,
            s.failed,
            s.errors,
            s.skipped,
            self.elapsed_s,
            if self.stopped { " (stopped)" } else { "" }
        )
    }
}

/// A check's verdict line: `PASS  web (tcp, 1.2 s): 20 connections ...`.
pub fn check_line(c: &CheckReport) -> String {
    let mut line = format!("{}  {} ({}", c.verdict.label(), c.name, c.kind);
    if c.verdict != Verdict::Skipped {
        let _ = write!(line, ", {:.1} s", c.elapsed_s);
    }
    if c.attempts > 1 {
        let _ = write!(line, ", {} attempts", c.attempts);
    }
    line.push(')');
    if c.expect == "blocked" {
        line.push_str(" expect blocked");
    }
    if !c.summary.is_empty() {
        let _ = write!(line, ": {}", c.summary);
    }
    line
}

/// How a check changed from one run to another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Change {
    /// The same verdict (or skipped in one of them).
    Same,
    /// Passed before, fails or has an error now.
    Regressed,
    /// Failed before, passes now.
    Fixed,
    /// Only in the second run.
    Added,
    /// Only in the first run.
    Removed,
    /// Same verdict, and a metric moved the wrong way by more than the
    /// tolerance (only counted with `strict`).
    Worse,
}

/// A metric that moved more than the tolerance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetricChange {
    pub metric: String,
    pub before: f64,
    pub after: f64,
    /// `after` against `before`, e.g. 0.5 for 50% more; absent when `before` was 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relative: Option<f64>,
    /// True when the move is for the worse, false for the better; absent
    /// when neither direction is better.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worse: Option<bool>,
}

/// One check in a [`Comparison`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CheckChange {
    pub name: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Verdict>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Verdict>,
    pub change: Change,
    pub metrics: Vec<MetricChange>,
}

/// Two runs side by side, check by check (by name): verdicts that changed
/// and metrics that moved by more than the tolerance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Comparison {
    pub before: String,
    pub after: String,
    pub tolerance: f64,
    pub checks: Vec<CheckChange>,
}

/// Compares two runs, e.g. before and after a firewall change, of two
/// devices, or IPv4 against IPv6: checks are matched by name, so the two
/// may be different scenario files. Metrics count as moved when they differ
/// by more than `tolerance` (0.2 = 20%) of the earlier value; with `strict`,
/// a move for the worse is a [`Change::Worse`].
pub fn compare(
    before: &ScenarioReport,
    after: &ScenarioReport,
    tolerance: f64,
    strict: bool,
) -> Comparison {
    let label = |r: &ScenarioReport| format!("{} {}", r.scenario, r.started);
    let mut checks = Vec::new();
    for a in &after.checks {
        let b = before.checks.iter().find(|b| b.name == a.name);
        let metrics = b.map(|b| moved(b, a, tolerance)).unwrap_or_default();
        let change = match b.map(|b| b.verdict) {
            None => Change::Added,
            Some(bv) if bv == Verdict::Pass && a.verdict.is_bad() => Change::Regressed,
            Some(bv) if bv.is_bad() && a.verdict == Verdict::Pass => Change::Fixed,
            Some(bv)
                if strict
                    && bv == a.verdict
                    && a.verdict == Verdict::Pass
                    && metrics.iter().any(|m| m.worse == Some(true)) =>
            {
                Change::Worse
            }
            Some(_) => Change::Same,
        };
        checks.push(CheckChange {
            name: a.name.clone(),
            kind: a.kind.clone(),
            before: b.map(|b| b.verdict),
            after: Some(a.verdict),
            change,
            metrics,
        });
    }
    for b in &before.checks {
        if !after.checks.iter().any(|a| a.name == b.name) {
            checks.push(CheckChange {
                name: b.name.clone(),
                kind: b.kind.clone(),
                before: Some(b.verdict),
                after: None,
                change: Change::Removed,
                metrics: Vec::new(),
            });
        }
    }
    Comparison {
        before: label(before),
        after: label(after),
        tolerance,
        checks,
    }
}

fn moved(before: &CheckReport, after: &CheckReport, tolerance: f64) -> Vec<MetricChange> {
    let kind = after.kind();
    let mut out = Vec::new();
    for (name, &a) in &after.metrics {
        let Some(&b) = before.metrics.get(name) else {
            continue;
        };
        let diff = (a - b).abs();
        if diff == 0.0 || diff <= tolerance * b.abs() {
            continue;
        }
        // Tiny absolute moves of small numbers (0 -> 1 retransmit, 0.1% loss,
        // 0.3 ms more latency on a busy machine) are noise, not news.
        let def = kind.and_then(|k| k.metric(name));
        let floor = match def.map(|d| d.unit) {
            Some(Unit::Percent) => 0.5,
            Some(Unit::Millis) => 1.0,
            Some(Unit::Count) => 1.0,
            _ => 0.0,
        };
        if diff <= floor {
            continue;
        }
        let worse = match def.map(|d| d.better) {
            Some(Better::Lower) => Some(a > b),
            Some(Better::Higher) => Some(a < b),
            _ => None,
        };
        out.push(MetricChange {
            metric: name.clone(),
            before: b,
            after: a,
            relative: (b != 0.0).then(|| (a - b) / b.abs()),
            worse,
        });
    }
    out
}

impl Comparison {
    /// Checks that passed before and fail now (and, with `strict`, those
    /// with a metric moved for the worse).
    pub fn regressions(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| matches!(c.change, Change::Regressed | Change::Worse))
            .count()
    }

    /// The comparison for people.
    pub fn text(&self, before: &ScenarioReport, after: &ScenarioReport) -> String {
        let mut t = String::new();
        let _ = writeln!(t, "before: {}", self.before);
        let _ = writeln!(t, "after:  {}", self.after);
        let v = |v: Option<Verdict>| v.map_or("-", Verdict::as_str);
        for c in &self.checks {
            let what = match c.change {
                Change::Same => "same     ",
                Change::Regressed => "REGRESSED",
                Change::Fixed => "fixed    ",
                Change::Added => "added    ",
                Change::Removed => "removed  ",
                Change::Worse => "WORSE    ",
            };
            let _ = writeln!(
                t,
                "{what}  {} ({}): {} -> {}",
                c.name,
                c.kind,
                v(c.before),
                v(c.after)
            );
            if c.change == Change::Regressed {
                if let Some(a) = after.checks.iter().find(|a| a.name == c.name) {
                    for f in a.failures() {
                        let _ = writeln!(t, "             not met: {f}");
                    }
                    if let Some(e) = &a.error {
                        let _ = writeln!(t, "             error: {e}");
                    }
                }
            }
            let fmt = |m: &str, x: f64| {
                after
                    .checks
                    .iter()
                    .chain(&before.checks)
                    .find(|r| r.name == c.name)
                    .map_or_else(|| x.to_string(), |r| r.format_metric(m, x))
            };
            // A changed verdict says it already; its metrics moved with it.
            let metrics = match c.change {
                Change::Regressed | Change::Fixed => &[][..],
                _ => &c.metrics[..],
            };
            for m in metrics {
                let rel = m
                    .relative
                    .map_or(String::new(), |r| format!(" ({:+.0}%)", r * 100.0));
                let dir = match m.worse {
                    Some(true) => ", worse",
                    Some(false) => ", better",
                    None => "",
                };
                let _ = writeln!(
                    t,
                    "             {}: {} -> {}{rel}{dir}",
                    m.metric,
                    fmt(&m.metric, m.before),
                    fmt(&m.metric, m.after)
                );
            }
        }
        let n = |ch: Change| self.checks.iter().filter(|c| c.change == ch).count();
        let _ = write!(
            t,
            "{} regressed, {} fixed, {} worse, {} added, {} removed, {} the same (metrics moved by more than {:.0}% shown)",
            n(Change::Regressed),
            n(Change::Fixed),
            n(Change::Worse),
            n(Change::Added),
            n(Change::Removed),
            n(Change::Same),
            self.tolerance * 100.0
        );
        t
    }
}

/// A time since the Unix epoch as `2026-11-03T21:04:05Z`.
pub fn format_utc(t: Duration) -> String {
    let secs = t.as_secs();
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's days-to-civil.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::Scenario;
    use std::path::Path;

    const TCP: &str = "port = 80\nconnections = 2\n[[message]]\nfrom = \"client\"\ntext = \"x\"\n[client]\nip = \"10.0.0.1\"\n";

    fn scenario() -> Scenario {
        let tcp = TCP
            .replace("\n[[message]]", "\n[[check.tcp.message]]")
            .replace("[client]", "[check.tcp.client]");
        let text = format!(
            "name = \"t\"\n[[check]]\nname = \"web\"\nattempts = 3\nrequire = [\"cps > 1\"]\n[check.tcp]\n{tcp}\
             [[check]]\nname = \"blocked\"\nexpect = \"blocked\"\n[check.tcp]\n{tcp}\
             [[check]]\nname = \"broken\"\n[check.tcp]\n{tcp}"
        );
        Scenario::from_toml(&text, Path::new("."), &[]).unwrap()
    }

    /// Answers from a script: per check name, the metrics of each attempt.
    struct Scripted {
        runs: Vec<String>,
        web_cps: Vec<f64>,
    }

    impl CheckRunner for Scripted {
        fn run(&mut self, check: &Check, _stop: &Arc<AtomicBool>) -> Result<CheckRun, String> {
            self.runs.push(check.name.clone());
            let mut m = Metrics::new();
            m.insert("connections".into(), 2.0);
            match check.name.as_str() {
                "web" => {
                    m.insert("completed_pct".into(), 100.0);
                    m.insert("mismatched".into(), 0.0);
                    m.insert("cps".into(), self.web_cps.remove(0));
                    m.insert("retransmits".into(), 3.0);
                }
                "blocked" => {
                    m.insert("established".into(), 0.0);
                }
                _ => return Err("no interface eth9".into()),
            }
            Ok(CheckRun {
                metrics: m,
                summary: "2 connections".into(),
            })
        }
    }

    fn run(cps: Vec<f64>, only: Vec<String>) -> (ScenarioReport, Vec<String>) {
        let mut runner = Scripted {
            runs: Vec::new(),
            web_cps: cps,
        };
        let mut seen = Vec::new();
        let mut progress = |p: Progress<'_>| {
            if let Progress::Finished(r) = p {
                seen.push(r.name.clone());
            }
        };
        let report = run_scenario(
            &scenario(),
            &mut runner,
            RunOptions {
                only,
                version: "9.9.9".into(),
                progress: Some(&mut progress),
                ..Default::default()
            },
        );
        assert_eq!(seen, ["web", "blocked", "broken"]);
        (report, runner.runs)
    }

    #[test]
    fn verdicts_retries_and_errors() {
        let (r, runs) = run(vec![0.5, 0.5, 2.0], Vec::new());
        // web failed twice (cps 0.5), passed on the third attempt; the
        // error is not retried.
        assert_eq!(runs, ["web", "web", "web", "blocked", "broken"]);
        let v: Vec<_> = r.checks.iter().map(|c| (c.verdict, c.attempts)).collect();
        assert_eq!(
            v,
            [(Verdict::Pass, 3), (Verdict::Pass, 1), (Verdict::Error, 1)]
        );
        assert_eq!(r.summary.errors, 1);
        assert!(!r.passed());
        assert_eq!(r.format, REPORT_FORMAT);
        assert_eq!(r.version, "9.9.9");
        assert!(r.text().contains("ERROR  broken (tcp"), "{}", r.text());
        assert!(
            r.text().contains("error: no interface eth9"),
            "{}",
            r.text()
        );

        let (r, _) = run(vec![0.5, 0.5, 0.5], vec!["web".into()]);
        assert_eq!(r.checks[0].verdict, Verdict::Fail);
        assert_eq!(r.checks[1].verdict, Verdict::Skipped);
        assert_eq!(r.checks[0].failures(), ["cps > 1 (was 0.5/s)"]);
        assert!(!r.passed());
        assert!(!r.stopped);

        // JSON round trip. serde_json reads some floats back one bit off
        // (it does not round-trip exactly without its float_roundtrip
        // feature), so use start and run times that survive exactly.
        let mut r = r;
        r.started_unix = 1_793_754_048.5;
        r.elapsed_s = 0.25;
        for c in &mut r.checks {
            c.elapsed_s = 0.125;
        }
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"verdict\":\"fail\""), "{json}");
        let back: ScenarioReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn junit_is_escaped_xml() {
        let (mut r, _) = run(vec![0.5, 0.5, 0.5], Vec::new());
        r.checks[0].name = "web <&> \"quotes\"".into();
        let x = r.junit();
        assert!(x.starts_with("<?xml"));
        assert!(
            x.contains("tests=\"3\" failures=\"1\" errors=\"1\" skipped=\"0\""),
            "{x}"
        );
        assert!(
            x.contains("name=\"web &lt;&amp;&gt; &quot;quotes&quot;\""),
            "{x}"
        );
        assert!(
            x.contains("<failure type=\"fail\" message=\"cps &gt; 1 (was 0.5/s)\">"),
            "{x}"
        );
        assert!(
            x.contains("<error type=\"error\" message=\"no interface eth9\"/>"),
            "{x}"
        );
        assert!(
            x.contains("<property name=\"ferotrx.version\" value=\"9.9.9\"/>"),
            "{x}"
        );
        assert!(x.contains("retransmits = 3"), "{x}");
        assert_eq!(x.matches("<testcase ").count(), 3);
        assert_eq!(x.matches("</testcase>").count(), 3);
    }

    #[test]
    fn comparing_two_runs() {
        let (before, _) = run(vec![2.0], Vec::new());
        let (after, _) = run(vec![0.5, 0.5, 0.5], Vec::new());
        let c = compare(&before, &after, 0.2, false);
        let changes: Vec<_> = c
            .checks
            .iter()
            .map(|c| (c.name.as_str(), c.change))
            .collect();
        assert_eq!(
            changes,
            [
                ("web", Change::Regressed),
                ("blocked", Change::Same),
                ("broken", Change::Same)
            ]
        );
        assert_eq!(c.regressions(), 1);
        let web = &c.checks[0];
        assert_eq!(web.metrics.len(), 1);
        assert_eq!(web.metrics[0].metric, "cps");
        assert_eq!(web.metrics[0].worse, Some(true));
        assert_eq!(web.metrics[0].relative, Some(-0.75));
        let text = c.text(&before, &after);
        assert!(
            text.contains("REGRESSED  web (tcp): pass -> fail"),
            "{text}"
        );
        assert!(text.contains("not met: cps > 1 (was 0.5/s)"), "{text}");
        // The failed conditions say what moved; no list of metrics as well.
        assert!(!text.contains("cps: 2/s -> 0.5/s"), "{text}");
        assert!(text.starts_with("before: t "), "{text}");

        let back = compare(&after, &before, 0.2, false);
        assert_eq!(back.checks[0].change, Change::Fixed);
        assert_eq!(back.regressions(), 0);

        // A metric for the worse within passing runs counts with strict.
        let (faster, _) = run(vec![4.0], Vec::new());
        assert_eq!(compare(&faster, &before, 0.2, false).regressions(), 0);
        let strict = compare(&faster, &before, 0.2, true);
        assert_eq!(strict.checks[0].change, Change::Worse);
        assert_eq!(strict.regressions(), 1);
        let text = strict.text(&faster, &before);
        assert!(
            text.contains("WORSE      web (tcp): pass -> pass"),
            "{text}"
        );
        assert!(text.contains("cps: 4/s -> 2/s (-50%), worse"), "{text}");
        // Within the tolerance: nothing moved.
        assert!(compare(&faster, &before, 0.6, true).checks[0]
            .metrics
            .is_empty());

        // Checks only in one of them.
        let mut fewer = before.clone();
        fewer.checks.remove(1);
        let c = compare(&before, &fewer, 0.2, false);
        assert_eq!(c.checks.last().unwrap().change, Change::Removed);
        let c = compare(&fewer, &before, 0.2, false);
        assert_eq!(c.checks[1].change, Change::Added);
    }

    #[test]
    fn utc_times() {
        assert_eq!(format_utc(Duration::ZERO), "1970-01-01T00:00:00Z");
        assert_eq!(
            format_utc(Duration::from_secs(1_793_740_245)),
            "2026-11-03T21:10:45Z"
        );
        assert_eq!(
            format_utc(Duration::from_secs(951_782_400)),
            "2000-02-29T00:00:00Z"
        );
    }
}
