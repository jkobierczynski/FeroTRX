//! `ferotrx scenario`: regression tests from scenario files.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use ferotrx_core::scenario::{
    check_line, compare, run_scenario, CheckKind, Expect, Progress, RunOptions, Scenario,
    ScenarioReport, Verdict, Workload, REPORT_FORMAT,
};

#[derive(Args)]
pub struct ScenarioArgs {
    #[command(subcommand)]
    command: ScenarioCommand,
}

#[derive(Subcommand)]
enum ScenarioCommand {
    /// Run the checks of a scenario file and judge each: pass, fail or
    /// error. Exits with 1 when a check fails or has an error.
    Run(RunArgs),
    /// Read a scenario file and show its checks and conditions, without
    /// sending anything.
    Show(ShowArgs),
    /// Compare two runs (report files): checks that passed before and fail
    /// now, and metrics that moved. Exits with 1 when a check regressed.
    Compare(CompareArgs),
    /// List the runs kept in a history directory (`run --history`).
    History(HistoryArgs),
    /// List the metrics checks can be judged by, per kind.
    Metrics,
}

#[derive(Args)]
struct VarArgs {
    /// Set a variable of the scenario (`${NAME}` in it and in its profiles),
    /// replacing its [vars] value. Repeat for more.
    #[arg(long = "set", value_name = "NAME=VALUE", value_parser = parse_var)]
    set: Vec<(String, String)>,

    /// Interface for checks that name none.
    #[arg(short, long)]
    iface: Option<String>,
}

pub(crate) fn parse_var(s: &str) -> std::result::Result<(String, String), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| format!("'{s}': give NAME=VALUE"))?;
    let k = k.trim();
    if k.is_empty() {
        return Err(format!("'{s}': the name is empty"));
    }
    Ok((k.to_string(), v.to_string()))
}

impl VarArgs {
    fn load(&self, file: &Path) -> Result<Scenario> {
        let mut s = Scenario::from_path(file, &self.set)
            .with_context(|| format!("cannot load {}", file.display()))?;
        if let Some(i) = &self.iface {
            s.set_default_iface(i);
        }
        Ok(s)
    }
}

#[derive(Args)]
struct RunArgs {
    /// The scenario, a TOML file with [[check]] tables.
    file: PathBuf,

    #[command(flatten)]
    vars: VarArgs,

    /// Run only this check (by name); repeat for more.
    #[arg(short, long = "check", value_name = "NAME")]
    checks: Vec<String>,

    /// Write the report as JSON to this file.
    #[arg(long, value_name = "FILE")]
    report: Option<PathBuf>,

    /// Write the report as JUnit XML to this file, for CI test results.
    #[arg(long, value_name = "FILE")]
    junit: Option<PathBuf>,

    /// Keep the report in this directory too, under the scenario's name,
    /// for `scenario history` and `scenario compare --history`.
    #[arg(long, value_name = "DIR")]
    history: Option<PathBuf>,

    /// Compare with an earlier report (or the last run in `--history`
    /// with `--baseline last`) and fail when a check that passed there fails now.
    #[arg(long, value_name = "FILE|last")]
    baseline: Option<PathBuf>,

    #[command(flatten)]
    cmp: CmpArgs,

    /// Print no progress, only the verdicts.
    #[arg(short, long)]
    quiet: bool,

    /// Build the lab router the scenario names in [lab] for the run, and
    /// remove it after (Linux, as root; see `ferotrx lab up`).
    #[arg(long)]
    lab: bool,
}

#[derive(Args)]
struct CmpArgs {
    /// Show metrics that moved by more than this, e.g. 20% (the default) or 0.2.
    #[arg(long, value_name = "PCT", default_value = "20%", value_parser = parse_tolerance)]
    tolerance: f64,

    /// Also count a passing check whose metrics moved for the worse by more
    /// than the tolerance as a regression.
    #[arg(long)]
    strict: bool,
}

fn parse_tolerance(s: &str) -> std::result::Result<f64, String> {
    let (num, pct) = match s.trim().strip_suffix('%') {
        Some(n) => (n, true),
        None => (s.trim(), false),
    };
    let v: f64 = num
        .parse()
        .map_err(|_| format!("'{s}' is not a tolerance, e.g. 20%"))?;
    let v = if pct || v > 1.0 { v / 100.0 } else { v };
    if !(0.0..=100.0).contains(&v) {
        return Err(format!("'{s}' is not a tolerance, e.g. 20%"));
    }
    Ok(v)
}

#[derive(Args)]
struct ShowArgs {
    file: PathBuf,
    #[command(flatten)]
    vars: VarArgs,
}

#[derive(Args)]
struct CompareArgs {
    /// The earlier report (JSON).
    #[arg(required_unless_present = "history")]
    before: Option<PathBuf>,
    /// The later report (JSON).
    #[arg(required_unless_present = "history")]
    after: Option<PathBuf>,

    /// Compare the last two runs kept in this history directory instead.
    #[arg(long, value_name = "DIR", conflicts_with_all = ["before", "after"])]
    history: Option<PathBuf>,

    /// With --history: the scenario (needed when the directory has several).
    #[arg(long, value_name = "NAME")]
    scenario: Option<String>,

    #[command(flatten)]
    cmp: CmpArgs,

    /// Also write the comparison as JSON to this file.
    #[arg(long, value_name = "FILE")]
    json: Option<PathBuf>,
}

#[derive(Args)]
struct HistoryArgs {
    /// The history directory.
    dir: PathBuf,
    /// Only this scenario.
    #[arg(long, value_name = "NAME")]
    scenario: Option<String>,
}

pub fn cmd_scenario(args: ScenarioArgs) -> Result<()> {
    match args.command {
        ScenarioCommand::Run(a) => run(a),
        ScenarioCommand::Show(a) => show(a),
        ScenarioCommand::Compare(a) => cmd_compare(a),
        ScenarioCommand::History(a) => history(a),
        ScenarioCommand::Metrics => {
            metrics();
            Ok(())
        }
    }
}

fn run(args: RunArgs) -> Result<()> {
    let scenario = args.vars.load(&args.file)?;
    for name in &args.checks {
        if !scenario.checks.iter().any(|c| c.name == *name) {
            let names: Vec<&str> = scenario.checks.iter().map(|c| c.name.as_str()).collect();
            bail!("no check called '{name}'; there are: {}", names.join(", "));
        }
    }
    // Read the baseline first: a typo should not cost a whole run.
    let baseline = match &args.baseline {
        Some(p) if p.as_os_str() == "last" => {
            let Some(dir) = &args.history else {
                bail!("--baseline last needs --history");
            };
            let runs = runs_of(&dir.join(dir_name(&scenario.name)))?;
            match runs.last() {
                Some(p) => Some((p.clone(), read_report(p)?)),
                None => {
                    eprintln!(
                        "no earlier run in {}: nothing to compare with",
                        dir.display()
                    );
                    None
                }
            }
        }
        Some(p) => Some((p.clone(), read_report(p)?)),
        None => None,
    };

    let _lab = match (&scenario.lab, args.lab) {
        (Some(spec), true) => Some(build_lab(spec)?),
        (None, true) => bail!("--lab: the scenario names no lab router ([lab])"),
        (Some(_), false) => {
            if !args.quiet {
                eprintln!(
                    "the scenario is written for the lab router ([lab]): --lab builds it, \
                     or start it with ferotrx lab up"
                );
            }
            None
        }
        (None, false) => None,
    };
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::Relaxed))
            .context("cannot install Ctrl-C handler")?;
    }
    let quiet = args.quiet;
    let mut runner = ferotrx_ctl::LabRunner::new();
    if !quiet {
        runner = runner.with_progress(|check, line| eprintln!("  {}: {line}", check.name));
        eprintln!(
            "scenario {}: {} checks",
            scenario.name,
            scenario.checks.len()
        );
    }
    let mut progress = |p: Progress<'_>| match p {
        Progress::Starting { check, attempt } => {
            if !quiet {
                if attempt > 1 {
                    eprintln!("{}: attempt {attempt} of {}", check.name, check.attempts);
                } else {
                    eprintln!("{}: running ({})", check.name, check.kind());
                }
            }
        }
        Progress::Finished(r) => {
            if r.verdict == Verdict::Skipped && !args.checks.is_empty() {
                return;
            }
            println!("{}", check_line(r));
            for f in r.failures() {
                println!("        not met: {f}");
            }
            if let Some(e) = &r.error {
                println!("        error: {e}");
            }
        }
    };
    let report = run_scenario(
        &scenario,
        &mut runner,
        RunOptions {
            only: args.checks.clone(),
            stop,
            version: env!("CARGO_PKG_VERSION").into(),
            progress: Some(&mut progress),
        },
    );
    println!("{}", report.total_line());

    if let Some(path) = &args.report {
        write_json(path, &report)?;
    }
    if let Some(path) = &args.junit {
        std::fs::write(path, report.junit())
            .with_context(|| format!("cannot write {}", path.display()))?;
    }
    if let Some(dir) = &args.history {
        let path = keep(dir, &report)?;
        if !quiet {
            eprintln!("kept in {}", path.display());
        }
    }
    let mut regressions = 0;
    if let Some((path, before)) = &baseline {
        let c = compare(before, &report, args.cmp.tolerance, args.cmp.strict);
        println!("compared with {}:", path.display());
        println!("{}", c.text(before, &report));
        regressions = c.regressions();
    }
    let s = &report.summary;
    if !report.passed() {
        if s.passed + s.failed + s.errors == 0 {
            bail!("no check ran");
        }
        bail!(
            "{} of {} failed{}",
            s.failed + s.errors,
            checks(s.passed + s.failed + s.errors),
            if s.errors > 0 {
                format!(" ({} could not run)", s.errors)
            } else {
                String::new()
            }
        );
    }
    if regressions > 0 {
        bail!("{} regressed against the baseline", checks(regressions));
    }
    Ok(())
}

/// The lab router of a scenario's `[lab]`, removed when dropped.
fn build_lab(spec: &ferotrx_core::scenario::LabSpec) -> Result<ferotrx_io::Lab> {
    if let Some(why) = ferotrx_io::lab_unavailable() {
        bail!("--lab: {why}");
    }
    let d = ferotrx_io::LabConfig::default();
    let lab = ferotrx_io::Lab::up(ferotrx_io::LabConfig {
        ipv6: spec.ipv6.unwrap_or(d.ipv6),
        nat: spec.nat.unwrap_or(d.nat),
        loss: spec.loss.unwrap_or(0.0),
        delay: spec.delay.clone().unwrap_or_default(),
        block_tcp: spec.block_tcp.clone(),
        block_udp: spec.block_udp.clone(),
        dhcp: spec.dhcp,
        queues: spec.queues.unwrap_or(1).clamp(1, 64),
    })
    .context("cannot build the lab")?;
    for n in lab.notes() {
        eprintln!("lab: {n}");
    }
    Ok(lab)
}

/// `1 check`, `3 checks`.
fn checks(n: usize) -> String {
    format!("{n} check{}", if n == 1 { "" } else { "s" })
}

fn show(args: ShowArgs) -> Result<()> {
    let s = args.vars.load(&args.file)?;
    println!("scenario {}", s.name);
    if let Some(d) = &s.description {
        println!("  {d}");
    }
    if let Some(l) = &s.lab {
        println!("runs on {} (--lab builds it)", l.describe());
    }
    if !s.vars.is_empty() {
        let v: Vec<String> = s.vars.iter().map(|(k, v)| format!("{k}={v}")).collect();
        println!("vars: {}", v.join(" "));
    }
    for c in &s.checks {
        let mut line = format!("{} ({}, {})", c.name, c.kind(), c.source);
        match c.expect {
            Expect::Complete if c.kind() == CheckKind::Y1564 => line.push_str(": expect pass"),
            Expect::Blocked if c.kind() == CheckKind::Y1564 => line.push_str(": expect fail"),
            Expect::Complete => line.push_str(": expect complete"),
            Expect::Blocked => line.push_str(": expect blocked"),
            Expect::Any => {}
        }
        println!("{line}");
        if let Some(d) = &c.description {
            println!("    {d}");
        }
        let what = match &c.workload {
            Workload::Tcp(p) => {
                let t = p.templates.len();
                format!(
                    "{} connections at {} per second, {t} template{}",
                    p.connections,
                    p.cps,
                    if t == 1 { "" } else { "s" }
                )
            }
            Workload::Udp(p) => {
                let t = p.templates.len();
                format!(
                    "{} transactions at {} per second, {t} template{}",
                    p.transactions,
                    p.rate,
                    if t == 1 { "" } else { "s" }
                )
            }
            Workload::Traffic(p) => {
                let names: Vec<&str> = p.streams.iter().map(|s| s.name.as_str()).collect();
                format!("streams {}", names.join(", "))
            }
            Workload::Y1564(p) => {
                let names: Vec<&str> = p.config.services.iter().map(|s| s.name.as_str()).collect();
                let tests: Vec<&str> = p.config.tests.iter().map(|t| t.name()).collect();
                format!(
                    "Y.1564 {} of services {}",
                    tests.join(" and "),
                    names.join(", ")
                )
            }
        };
        println!("    runs: {what}");
        let mut on = Vec::new();
        if let Some(i) = &c.iface {
            on.push(format!("iface {i}"));
        }
        if let Some(r) = &c.rx {
            on.push(format!("rx {r} (wait {:?})", c.rx_wait));
        }
        if let Some(d) = c.duration {
            on.push(format!("stops after {d:?}"));
        }
        if c.attempts > 1 {
            on.push(format!("{} attempts", c.attempts));
        }
        if !on.is_empty() {
            println!("    {}", on.join(", "));
        }
        for cond in c.conditions() {
            println!("    require {cond}");
        }
    }
    Ok(())
}

fn metrics() {
    for k in CheckKind::ALL {
        println!("{k}:");
        for m in k.metrics() {
            let unit = match m.unit {
                ferotrx_core::scenario::Unit::Count => "",
                ferotrx_core::scenario::Unit::Percent => " (%)",
                ferotrx_core::scenario::Unit::Millis => " (ms)",
                ferotrx_core::scenario::Unit::Mbps => " (Mbit/s)",
                ferotrx_core::scenario::Unit::PerSecond => " (/s)",
            };
            println!("  {:<18} {}{unit}", m.name, m.help);
        }
    }
}

fn read_report(path: &Path) -> Result<ScenarioReport> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let r: ScenarioReport = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a scenario report", path.display()))?;
    if r.format != REPORT_FORMAT {
        bail!(
            "{} has format '{}', this FeroTRX reads '{REPORT_FORMAT}'",
            path.display(),
            r.format
        );
    }
    Ok(r)
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let text = serde_json::to_string_pretty(value)?;
    std::fs::write(path, text + "\n").with_context(|| format!("cannot write {}", path.display()))
}

/// A scenario name as a directory name.
fn dir_name(scenario: &str) -> String {
    let n: String = scenario
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    match n.trim_matches('.') {
        "" => "scenario".into(),
        n => n.to_string(),
    }
}

/// Keeps a report in `dir/<scenario>/<start time>.json`.
fn keep(dir: &Path, report: &ScenarioReport) -> Result<PathBuf> {
    let sub = dir.join(dir_name(&report.scenario));
    std::fs::create_dir_all(&sub).with_context(|| format!("cannot create {}", sub.display()))?;
    let stem = report.started.replace(':', "-");
    let mut path = sub.join(format!("{stem}.json"));
    let mut n = 2;
    while path.exists() {
        path = sub.join(format!("{stem}-{n}.json"));
        n += 1;
    }
    write_json(&path, report)?;
    Ok(path)
}

/// The reports in a scenario's history directory, oldest first.
fn runs_of(sub: &Path) -> Result<Vec<PathBuf>> {
    if !sub.exists() {
        return Ok(Vec::new());
    }
    let mut runs: Vec<PathBuf> = std::fs::read_dir(sub)
        .with_context(|| format!("cannot read {}", sub.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    // Names start with the UTC start time; a "-2" for a second run in the
    // same second sorts after the first.
    runs.sort_by_key(|p| {
        let stem = p
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let (time, n) = match stem.get(20..).and_then(|r| r.strip_prefix('-')) {
            Some(n) => (stem[..20].to_string(), n.parse::<u32>().unwrap_or(0)),
            None => (stem.clone(), 1),
        };
        (time, n)
    });
    Ok(runs)
}

/// The scenarios kept in a history directory.
fn scenarios_in(dir: &Path) -> Result<Vec<String>> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .with_context(|| format!("cannot read {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    Ok(names)
}

fn pick_scenario(dir: &Path, scenario: &Option<String>) -> Result<String> {
    if let Some(s) = scenario {
        return Ok(dir_name(s));
    }
    let names = scenarios_in(dir)?;
    match names.as_slice() {
        [one] => Ok(one.clone()),
        [] => bail!("{} has no runs", dir.display()),
        many => bail!(
            "{} has runs of several scenarios ({}); pick one with --scenario",
            dir.display(),
            many.join(", ")
        ),
    }
}

fn cmd_compare(args: CompareArgs) -> Result<()> {
    let (before_path, after_path) = match (&args.history, &args.before, &args.after) {
        (Some(dir), _, _) => {
            let name = pick_scenario(dir, &args.scenario)?;
            let runs = runs_of(&dir.join(&name))?;
            let [.., b, a] = runs.as_slice() else {
                bail!("{} has fewer than two runs of {name}", dir.display());
            };
            (b.clone(), a.clone())
        }
        (None, Some(b), Some(a)) => (b.clone(), a.clone()),
        _ => bail!("give two reports, or --history"),
    };
    let before = read_report(&before_path)?;
    let after = read_report(&after_path)?;
    let c = compare(&before, &after, args.cmp.tolerance, args.cmp.strict);
    println!("{}", c.text(&before, &after));
    if let Some(path) = &args.json {
        write_json(path, &c)?;
    }
    let n = c.regressions();
    if n > 0 {
        bail!("{} regressed", checks(n));
    }
    Ok(())
}

fn history(args: HistoryArgs) -> Result<()> {
    let names = match &args.scenario {
        Some(s) => vec![dir_name(s)],
        None => scenarios_in(&args.dir)?,
    };
    if names.is_empty() {
        println!("no runs in {}", args.dir.display());
    }
    for name in names {
        let runs = runs_of(&args.dir.join(&name))?;
        println!("{name}: {} runs", runs.len());
        for path in runs {
            match read_report(&path) {
                Ok(r) => {
                    let s = &r.summary;
                    let bad: Vec<&str> = r
                        .checks
                        .iter()
                        .filter(|c| matches!(c.verdict, Verdict::Fail | Verdict::Error))
                        .map(|c| c.name.as_str())
                        .collect();
                    let mut line = format!(
                        "  {}  {}  {} passed, {} failed, {} errors, {} skipped  v{}",
                        r.started,
                        if r.passed() { "PASSED" } else { "FAILED" },
                        s.passed,
                        s.failed,
                        s.errors,
                        s.skipped,
                        r.version
                    );
                    if !bad.is_empty() {
                        line.push_str(&format!("  ({})", bad.join(", ")));
                    }
                    println!("{line}");
                    println!("      {}", path.display());
                }
                Err(e) => println!("  {}: {e:#}", path.display()),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tolerances() {
        assert_eq!(parse_tolerance("20%").unwrap(), 0.2);
        assert_eq!(parse_tolerance("0.2").unwrap(), 0.2);
        assert_eq!(parse_tolerance("5").unwrap(), 0.05);
        assert!(parse_tolerance("x").is_err());
        assert!(parse_tolerance("-5%").is_err());
    }

    #[test]
    fn history_names_and_order() {
        assert_eq!(dir_name("lab nat/router"), "lab_nat_router");
        assert_eq!(dir_name(".."), "scenario");
        let dir = std::env::temp_dir().join(format!("ferotrx-hist-{}", std::process::id()));
        let sub = dir.join("lab");
        std::fs::create_dir_all(&sub).unwrap();
        for f in [
            "2026-11-03T21-10-45Z-2.json",
            "2026-11-03T21-10-45Z.json",
            "2026-11-02T08-00-00Z.json",
            "2026-11-03T21-10-45Z-10.json",
            "notes.txt",
        ] {
            std::fs::write(sub.join(f), "{}").unwrap();
        }
        let runs: Vec<String> = runs_of(&sub)
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            runs,
            [
                "2026-11-02T08-00-00Z.json",
                "2026-11-03T21-10-45Z.json",
                "2026-11-03T21-10-45Z-2.json",
                "2026-11-03T21-10-45Z-10.json"
            ]
        );
        assert_eq!(pick_scenario(&dir, &None).unwrap(), "lab");
        std::fs::remove_dir_all(&dir).ok();
    }
}
