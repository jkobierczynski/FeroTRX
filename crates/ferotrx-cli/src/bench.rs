//! `ferotrx bench`: RFC 2544-style benchmarks with JSON and text reports.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Args;
use ferotrx_core::{
    parse_duration, run_benchmark, BenchProfile, BenchReport, BenchTest, JobTrialRunner,
    PacketReceiver, PacketSink, RunInfo, SinkError, SizeMix, TrialRecord, RFC2544_SIZES,
};

use crate::SendArgs;

/// `ferotrx bench`.
#[derive(Args)]
pub struct BenchArgs {
    /// The benchmark profile: a TOML file with a [benchmark] table (see
    /// examples/bench-rfc2544.toml).
    profile: PathBuf,

    /// Send on this interface (with `--backend dpdk`, a DPDK device).
    #[arg(short, long)]
    iface: String,

    /// Receive on this interface: where the device under test sends the
    /// frames on. May be the sending interface, for a device that sends them back.
    #[arg(long, value_name = "IFACE")]
    rx: String,

    #[command(flatten)]
    send: SendArgs,

    #[command(flatten)]
    addr: crate::link::AddrArgs,

    /// Run these tests instead of the profile's: throughput, latency,
    /// frame_loss, back_to_back (comma separated).
    #[arg(long, value_delimiter = ',', value_name = "TEST")]
    tests: Vec<BenchTest>,

    /// Frame sizes instead of the profile's; repeat for more: a size without
    /// FCS (508), rfc2544 (the seven RFC 2544 sizes), imix, or a mix such as
    /// 60:7,590:4,1514:1.
    #[arg(long = "size", value_name = "SIZE")]
    sizes: Vec<String>,

    /// Speed of the link instead of the profile's, e.g. 1gbps.
    #[arg(long, value_name = "RATE")]
    line_rate: Option<String>,

    /// Length of each trial instead of the profile's, e.g. 60s.
    #[arg(long, value_name = "TIME", value_parser = parse_duration)]
    trial_duration: Option<Duration>,

    /// Repetitions instead of the profile's.
    #[arg(long, value_name = "N")]
    repetitions: Option<u32>,

    /// Write the report as JSON to this file, and as text next to it (same
    /// name, ending in .txt).
    #[arg(long, value_name = "FILE")]
    report: Option<PathBuf>,

    /// Print no line per trial, only the final report.
    #[arg(short, long)]
    quiet: bool,
}

/// A sink shared by the trials: opened once, as DPDK and AF_XDP want.
pub(crate) struct SharedSink(pub(crate) Arc<Mutex<Box<dyn PacketSink + Send>>>);

impl PacketSink for SharedSink {
    fn send(&mut self, data: &[u8]) -> Result<(), SinkError> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).send(data)
    }
    fn flush(&mut self) -> Result<(), SinkError> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).flush()
    }
    fn idle(&mut self) -> Result<(), SinkError> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).idle()
    }
}

/// A receiver shared by the trials, so nothing arrives while one is reopened.
pub(crate) struct SharedReceiver(pub(crate) Arc<Mutex<Box<dyn PacketReceiver>>>);

impl PacketReceiver for SharedReceiver {
    fn recv(&mut self, buf: &mut Vec<u8>) -> Result<Option<Duration>, SinkError> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).recv(buf)
    }
}

/// What the report files contain.
#[derive(serde::Serialize)]
struct JsonReport<'a> {
    format: &'static str,
    info: &'a RunInfo,
    #[serde(flatten)]
    report: &'a BenchReport,
}

pub fn cmd_bench(args: BenchArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.profile)
        .with_context(|| format!("cannot read {}", args.profile.display()))?;
    let mut profile = BenchProfile::from_toml(&text)
        .with_context(|| format!("cannot read {}", args.profile.display()))?;
    let config = &mut profile.config;
    if !args.tests.is_empty() {
        config.tests = args.tests.clone();
    }
    if !args.sizes.is_empty() {
        config.sizes = Vec::new();
        for s in &args.sizes {
            if s.trim().eq_ignore_ascii_case("rfc2544") {
                config.sizes.extend(
                    RFC2544_SIZES
                        .iter()
                        .map(|&n| SizeMix::fixed(n).expect("valid")),
                );
            } else {
                config.sizes.push(s.parse()?);
            }
        }
    }
    if let Some(r) = &args.line_rate {
        config.line_rate_mbps = match r.parse()? {
            ferotrx_core::Rate::Mbps(m) => m,
            _ => bail!("--line-rate is a bit rate such as 1gbps or 100mbps"),
        };
    }
    if let Some(d) = args.trial_duration {
        config.trial_duration = d;
    }
    if let Some(n) = args.repetitions {
        config.repetitions = n;
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
    let output = ferotrx_io::Output::Interface {
        name: args.iface.clone(),
        send,
    };
    let link = args.addr.settings(&profile.link)?;
    // The port's addresses: the gateway's MAC found now and put in the
    // frames once, answers for the port while the benchmark runs.
    let link_service = ferotrx_ctl::start_link(&output, &link).map_err(|e| anyhow::anyhow!(e))?;
    let mut capture = profile.capture()?;
    if let Some(svc) = &link_service {
        let mut macs = svc.macs();
        for p in &mut capture.packets {
            ferotrx_core::Transform::apply(&mut macs, p);
        }
    }
    let capture = Arc::new(capture);
    let workers = match &output {
        ferotrx_io::Output::Interface { send, .. } => send.workers(),
        _ => 1,
    };
    let mut opened = output
        .open_workers(capture.linktype, workers)
        .map_err(|e| anyhow::anyhow!(e))?;
    let mut details: Vec<String> = Vec::new();
    for o in &opened {
        if !details.contains(&o.detail) {
            details.push(o.detail.clone());
        }
    }
    let detail = details.join("; ");
    let receiver = ferotrx_io::open_receiver(&args.rx)
        .map_err(|e| anyhow::anyhow!(e))
        .with_context(|| format!("cannot receive on {}", args.rx))?;

    let mut info = RunInfo::new();
    ferotrx_io::describe_host(&mut info);
    info.command = Some(std::env::args().collect::<Vec<_>>().join(" "));
    info.profile = Some(args.profile.display().to_string());
    info.profile_text = Some(text);
    info.backend = Some(match &link_service {
        Some(svc) => format!("{detail}; port {}", svc.detail()),
        None => detail,
    });
    info.tx_interface = Some(ferotrx_io::describe_interface(&args.iface));
    info.rx_interface = Some(ferotrx_io::describe_interface(&args.rx));
    info.timestamps = Some(
        "send: system clock just before each frame is handed to the sender; \
         receive: the capture driver's timestamp (libpcap/Npcap, software)"
            .into(),
    );
    if !args.quiet {
        for line in info.lines() {
            eprintln!("{line}");
        }
        let c = &profile.config;
        let sizes: Vec<String> = c.sizes.iter().map(ToString::to_string).collect();
        let tests: Vec<&str> = c.tests.iter().map(|t| t.name()).collect();
        eprintln!(
            "benchmark: {} for sizes {}; Ctrl-C stops after the current trial",
            tests.join(", "),
            sizes.join(" ")
        );
    }

    // One sink per worker, opened once and handed out in turn to each trial.
    let sinks: Vec<_> = opened
        .drain(..)
        .map(|o| Arc::new(Mutex::new(o.sink)))
        .collect();
    let mut next = 0;
    let receiver: Arc<Mutex<Box<dyn PacketReceiver>>> = Arc::new(Mutex::new(receiver));
    let mut runner = JobTrialRunner::new(
        capture,
        Box::new(move || {
            let sink = sinks[next % sinks.len()].clone();
            next += 1;
            Ok(Box::new(SharedSink(sink)) as Box<dyn PacketSink + Send>)
        }),
        Box::new(move || Ok(Box::new(SharedReceiver(receiver.clone())) as Box<dyn PacketReceiver>)),
    )
    .with_vary(profile.vary.clone())
    .with_stop(stop)
    .with_workers(workers);
    runner.rx_wait = profile.rx_wait;

    let quiet = args.quiet;
    let report = run_benchmark(&profile.config, &mut runner, |size, t| {
        if !quiet {
            eprintln!("{}", trial_line(&size.size, t));
        }
    })?;

    let mut text = info.lines().join("\n");
    text.push_str("\n\n");
    text.push_str(&report.text());
    println!("{text}");
    if let Some(path) = &args.report {
        save(path, &info, &report, &text)?;
        eprintln!("wrote {} and {}", path.display(), text_path(path).display());
    }
    if report.stopped {
        eprintln!("stopped before the end: the results are partial");
    }
    drop(link_service);
    Ok(())
}

fn trial_line(size: &str, t: &TrialRecord) -> String {
    let what = match t.burst {
        Some(b) => format!("burst of {b}"),
        None => format!("{:.2}%", t.load_pct),
    };
    let verdict = match t.passed {
        Some(true) => ", pass",
        Some(false) => ", fail",
        None => "",
    };
    format!(
        "{} {size} run {}: {what}, offered {:.0}/s, sent {:.0}/s, {} sent, {} lost ({:.3}%), latency avg {}{verdict}{}",
        t.test,
        t.repetition,
        t.offered_pps,
        t.achieved_pps,
        t.tx,
        t.lost,
        t.loss_pct,
        crate::latency::fmt_us(t.latency.avg_us),
        if t.sender_limited() {
            " (the sender did not reach the offered rate)"
        } else {
            ""
        }
    )
}

/// `bench.json` -> `bench.txt`.
fn text_path(path: &Path) -> PathBuf {
    path.with_extension("txt")
}

fn save(path: &Path, info: &RunInfo, report: &BenchReport, text: &str) -> Result<()> {
    if path.extension().is_some_and(|e| e == "txt") {
        bail!("--report is the JSON file; the text report goes next to it as .txt");
    }
    let json = serde_json::to_string_pretty(&JsonReport {
        format: "ferotrx-bench-1",
        info,
        report,
    })?;
    std::fs::write(path, json + "\n")
        .with_context(|| format!("cannot write {}", path.display()))?;
    let t = text_path(path);
    std::fs::write(&t, text).with_context(|| format!("cannot write {}", t.display()))
}
