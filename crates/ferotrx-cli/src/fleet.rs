//! `ferotrx fleet`: runs on several agents (control servers) at once,
//! started together, their counters added up.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use ferotrx_core::fleet::FleetPlan;
use ferotrx_core::parse_duration;
use ferotrx_ctl::fleet::{connect_all, deploy, run_fleet, FleetEvent, FleetOptions, FleetReport};

use crate::scenario::parse_var;

/// `ferotrx fleet`.
#[derive(Args)]
pub struct FleetArgs {
    #[command(subcommand)]
    command: FleetCommand,
}

#[derive(Subcommand)]
enum FleetCommand {
    /// Deploy the plan's profiles to its agents, start every run at one
    /// instant, follow them and add up their counters.
    Run(RunArgs),
    /// Read the plan, reach every agent and show its version and clock;
    /// nothing is sent or started.
    Check(PlanArgs),
    /// Send the profiles and the files they name to the agents, and start
    /// nothing.
    Deploy(PlanArgs),
}

#[derive(Args)]
struct PlanArgs {
    /// The plan: [[agent]] and [[run]] tables (see examples/fleet.toml).
    plan: PathBuf,

    /// Set a variable of the plan (`${NAME}` in it and in its profiles),
    /// replacing its [vars] value. Repeat for more.
    #[arg(long = "set", value_name = "NAME=VALUE", value_parser = parse_var)]
    set: Vec<(String, String)>,
}

#[derive(Args)]
struct RunArgs {
    #[command(flatten)]
    plan: PlanArgs,

    /// Every run goes this long instead of the plan's durations, e.g. 30s.
    #[arg(long, value_name = "TIME", value_parser = parse_duration)]
    duration: Option<Duration>,

    /// Write the report as JSON to this file, and as text next to it (same
    /// name, ending in .txt).
    #[arg(long, value_name = "FILE")]
    report: Option<PathBuf>,

    /// Leave the runs on the agents when they end, to look at them there
    /// (`ferotrx ctl`, the GUI).
    #[arg(long)]
    keep: bool,

    /// Fetch the plan's captures (`[[capture]]`) from the agents into this
    /// folder after the run, one pcap per agent and interface.
    #[arg(long, value_name = "DIR")]
    collect: Option<PathBuf>,

    /// With --collect: also merge them into this pcapng, one interface per
    /// capture, times moved onto this machine's clock.
    #[arg(long, value_name = "FILE", requires = "collect")]
    merge: Option<PathBuf>,

    /// Print no line per interval, only the final report.
    #[arg(short, long)]
    quiet: bool,
}

impl PlanArgs {
    fn load(&self) -> Result<FleetPlan> {
        FleetPlan::from_path(&self.plan, &self.set)
            .with_context(|| format!("cannot read {}", self.plan.display()))
    }
}

pub fn cmd_fleet(args: FleetArgs) -> Result<()> {
    match args.command {
        FleetCommand::Check(p) => check(&p),
        FleetCommand::Deploy(p) => {
            let plan = p.load()?;
            let mut agents = connect_all(&plan, &mut print_event)?;
            let deployed = deploy(&plan, &mut agents, &mut print_event)?;
            let sent: usize = deployed.iter().map(|d| d.files_sent).sum();
            println!(
                "deployed {} profile(s) under {}; {sent} file(s) sent",
                deployed.len(),
                plan.deploy_dir.display()
            );
            Ok(())
        }
        FleetCommand::Run(r) => run(r),
    }
}

fn print_event(e: &FleetEvent) {
    match e {
        FleetEvent::Agent(a) => eprintln!(
            "agent {} at {}: FeroTRX {}, round trip {:.2} ms, clock {:+.1} ms from here{}",
            a.name,
            a.address,
            a.version,
            a.rtt_ms,
            a.offset_ms,
            if a.tls { ", TLS" } else { "" }
        ),
        FleetEvent::Deployed(d) => eprintln!(
            "  {} on {}: {} ({} file(s) sent, {} there already)",
            d.run, d.agent, d.profile, d.files_sent, d.files_kept
        ),
        FleetEvent::Starting { at } => eprintln!(
            "starting every run at {}",
            ferotrx_core::scenario::format_utc(Duration::from_secs_f64(at.max(0.0)))
        ),
        FleetEvent::Sample(s) => eprintln!("{}", s.line()),
    }
}

fn check(p: &PlanArgs) -> Result<()> {
    let plan = p.load()?;
    for line in plan.summary() {
        println!("{line}");
    }
    let mut agents = connect_all(&plan, &mut print_event)?;
    let mut missing = 0;
    for run in &plan.runs {
        for inst in &run.instances {
            let Some(iface) = &inst.iface else {
                continue;
            };
            let a = agents
                .iter_mut()
                .find(|a| a.spec.name == inst.agent)
                .expect("the plan checked its agents");
            match a.client.interfaces() {
                Ok(list) if !list.iter().any(|i| &i.name == iface) => {
                    missing += 1;
                    println!(
                        "warning: run '{}': agent '{}' has no interface {iface}",
                        run.name, inst.agent
                    );
                }
                _ => {}
            }
        }
    }
    let worst = agents.iter().map(|a| a.offset.abs()).fold(0.0f64, f64::max);
    if worst > 0.01 {
        println!(
            "note: clocks differ by up to {:.0} ms: runs still start together, but one-way \
             latency between agents needs their clocks in step (NTP, PTP)",
            worst * 1000.0
        );
    }
    if missing > 0 {
        bail!("{missing} interface(s) not found on the agents");
    }
    println!("ok: every agent answers");
    Ok(())
}

fn run(args: RunArgs) -> Result<()> {
    let plan = args.plan.load()?;
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::Relaxed))
            .context("cannot install Ctrl-C handler")?;
    }
    if !args.quiet {
        for line in plan.summary() {
            eprintln!("{line}");
        }
    }
    let options = FleetOptions {
        stop: Some(stop),
        duration: args.duration,
        keep: args.keep,
        deploy_only: false,
        collect: args.collect.clone(),
        merge: args.merge.clone(),
    };
    let quiet = args.quiet;
    let report = run_fleet(&plan, &options, &mut |e| {
        if !quiet || !matches!(e, FleetEvent::Sample(_)) {
            print_event(e);
        }
    })?;
    let text = report.text();
    println!("{text}");
    if let Some(path) = &args.report {
        save(path, &report, &text)?;
        eprintln!(
            "wrote {} and {}",
            path.display(),
            path.with_extension("txt").display()
        );
    }
    if report.stopped {
        bail!("stopped before the end: the results are partial");
    }
    if !report.passed {
        let failed = report.failed_runs();
        let conditions = report.conditions.iter().filter(|c| !c.pass).count();
        bail!(
            "the fleet failed: {} run(s) failed{}{}",
            failed.len(),
            if failed.is_empty() {
                String::new()
            } else {
                format!(" ({})", failed.join(", "))
            },
            if conditions > 0 {
                format!(", {conditions} condition(s) on the totals")
            } else {
                String::new()
            }
        );
    }
    Ok(())
}

fn save(path: &Path, report: &FleetReport, text: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    std::fs::write(path, json + "\n")
        .with_context(|| format!("cannot write {}", path.display()))?;
    let txt = path.with_extension("txt");
    std::fs::write(&txt, text).with_context(|| format!("cannot write {}", txt.display()))?;
    Ok(())
}
