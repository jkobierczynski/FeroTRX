//! `ferotrx y1564`: Y.1564 service activation tests with JSON and text reports.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Args;
use ferotrx_core::{
    parse_duration, run_y1564, JobServiceRunner, PacketReceiver, PacketSink, RunInfo, Y1564Profile,
    Y1564Report, Y1564Test, LINKTYPE_ETHERNET,
};

use crate::bench::{SharedReceiver, SharedSink};
use crate::SendArgs;

/// `ferotrx y1564`.
#[derive(Args)]
pub struct Y1564Args {
    /// The profile: a TOML file with [[service]] tables and a [y1564] table
    /// (see examples/y1564.toml).
    profile: PathBuf,

    /// Send on this interface (with `--backend dpdk`, a DPDK device).
    #[arg(short, long)]
    iface: String,

    /// Receive on this interface: where the network delivers the frames.
    /// May be the sending interface, for a network that sends them back.
    #[arg(long, value_name = "IFACE")]
    rx: String,

    #[command(flatten)]
    send: SendArgs,

    /// Run these tests instead of the profile's: configuration, performance
    /// (comma separated).
    #[arg(long, value_delimiter = ',', value_name = "TEST")]
    tests: Vec<Y1564Test>,

    /// Test only this service; repeat for more.
    #[arg(long = "service", value_name = "NAME")]
    services: Vec<String>,

    /// Speed of the link instead of the profile's, e.g. 1gbps.
    #[arg(long, value_name = "RATE")]
    line_rate: Option<String>,

    /// Length of each configuration step instead of the profile's, e.g. 60s.
    #[arg(long, value_name = "TIME", value_parser = parse_duration)]
    step_duration: Option<Duration>,

    /// Length of the performance test instead of the profile's, e.g. 15m.
    #[arg(long, value_name = "TIME", value_parser = parse_duration)]
    performance_duration: Option<Duration>,

    /// Write the report as JSON to this file, and as text next to it (same
    /// name, ending in .txt).
    #[arg(long, value_name = "FILE")]
    report: Option<PathBuf>,

    /// Print no line per step, only the final report.
    #[arg(short, long)]
    quiet: bool,
}

/// What the report files contain.
#[derive(serde::Serialize)]
struct JsonReport<'a> {
    format: &'static str,
    info: &'a RunInfo,
    #[serde(flatten)]
    report: &'a Y1564Report,
}

pub fn cmd_y1564(args: Y1564Args) -> Result<()> {
    let text = std::fs::read_to_string(&args.profile)
        .with_context(|| format!("cannot read {}", args.profile.display()))?;
    let mut profile = Y1564Profile::from_toml(&text)
        .with_context(|| format!("cannot read {}", args.profile.display()))?;
    if !args.services.is_empty() {
        profile.keep_services(&args.services)?;
    }
    let config = &mut profile.config;
    if !args.tests.is_empty() {
        config.tests = args.tests.clone();
    }
    if let Some(r) = &args.line_rate {
        config.line_rate_mbps = match r.parse()? {
            ferotrx_core::Rate::Mbps(m) => m,
            _ => bail!("--line-rate is a bit rate such as 1gbps or 100mbps"),
        };
    }
    if let Some(d) = args.step_duration {
        config.step_duration = d;
    }
    if let Some(d) = args.performance_duration {
        config.performance_duration = d;
    }
    config.validate()?;
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::Relaxed))
            .context("cannot install Ctrl-C handler")?;
    }
    config.stop = Some(stop.clone());

    let send = args.send.settings()?.or(&profile.output);
    let workers = send.workers();
    let output = ferotrx_io::Output::Interface {
        name: args.iface.clone(),
        send,
    };
    let mut opened = output
        .open_workers(LINKTYPE_ETHERNET, workers)
        .map_err(|e| anyhow::anyhow!(e))?;
    let mut details: Vec<String> = Vec::new();
    for o in &opened {
        if !details.contains(&o.detail) {
            details.push(o.detail.clone());
        }
    }
    let receiver = ferotrx_io::open_receiver(&args.rx)
        .map_err(|e| anyhow::anyhow!(e))
        .with_context(|| format!("cannot receive on {}", args.rx))?;

    let mut info = RunInfo::new();
    ferotrx_io::describe_host(&mut info);
    info.command = Some(std::env::args().collect::<Vec<_>>().join(" "));
    info.profile = Some(args.profile.display().to_string());
    info.profile_text = Some(text);
    info.backend = Some(details.join("; "));
    info.tx_interface = Some(ferotrx_io::describe_interface(&args.iface));
    info.rx_interface = Some(ferotrx_io::describe_interface(&args.rx));
    if !args.quiet {
        for line in info.lines() {
            eprintln!("{line}");
        }
        let c = &profile.config;
        let services: Vec<String> = c
            .services
            .iter()
            .map(|s| format!("{} (CIR {}, EIR {} Mbit/s)", s.name, s.cir_mbps, s.eir_mbps))
            .collect();
        let tests: Vec<&str> = c.tests.iter().map(|t| t.name()).collect();
        eprintln!(
            "Y.1564: {} for {}; Ctrl-C stops",
            tests.join(", "),
            services.join(", ")
        );
    }

    // One sink per worker, opened once and handed out in turn to each step.
    let sinks: Vec<_> = opened
        .drain(..)
        .map(|o| Arc::new(Mutex::new(o.sink)))
        .collect();
    let mut next = 0;
    let receiver: Arc<Mutex<Box<dyn PacketReceiver>>> = Arc::new(Mutex::new(receiver));
    let mut runner = JobServiceRunner::new(
        profile.frames.clone(),
        Box::new(move || {
            let sink = sinks[next % sinks.len()].clone();
            next += 1;
            Ok(Box::new(SharedSink(sink)) as Box<dyn PacketSink + Send>)
        }),
        Box::new(move || Ok(Box::new(SharedReceiver(receiver.clone())) as Box<dyn PacketReceiver>)),
    )
    .with_stop(stop)
    .with_workers(workers);
    runner.rx_wait = profile.rx_wait;

    let quiet = args.quiet;
    let report = run_y1564(&profile.config, &mut runner, |step| {
        if !quiet {
            for line in step.lines() {
                eprintln!("{line}");
            }
        }
    })?;

    let mut text = info.lines().join("\n");
    text.push_str("\n\n");
    text.push_str(&report.text());
    println!("{text}");
    if let Some(path) = &args.report {
        save(path, &info, &report, &text)?;
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
        let failed: Vec<&str> = report
            .services
            .iter()
            .filter(|s| !s.passed)
            .map(|s| s.service.as_str())
            .collect();
        bail!(
            "the Y.1564 test failed: {} step(s) failed, service(s) {}",
            report.failed_steps(),
            failed.join(", ")
        );
    }
    Ok(())
}

fn save(path: &Path, info: &RunInfo, report: &Y1564Report, text: &str) -> Result<()> {
    if path.extension().is_some_and(|e| e == "txt") {
        bail!("--report is the JSON file; the text report goes next to it as .txt");
    }
    let json = serde_json::to_string_pretty(&JsonReport {
        format: "ferotrx-y1564-1",
        info,
        report,
    })?;
    std::fs::write(path, json + "\n")
        .with_context(|| format!("cannot write {}", path.display()))?;
    let t = path.with_extension("txt");
    std::fs::write(&t, text).with_context(|| format!("cannot write {}", t.display()))
}
