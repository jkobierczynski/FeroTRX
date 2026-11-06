//! Loss and latency on the command line: `--rx`/`--latency` and `ferotrx rx`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Args;
use ferotrx_core::{
    parse_duration, Capture, Job, Rate, ReplayStats, RunInfo, RxConfig, RxJob, RxSettings, RxStats,
};
use ferotrx_ctl::protocol::FlowCounters;

/// Loss and latency options of `replay`, `run` and `build`.
#[derive(Args, Clone, Default)]
pub struct RxArgs {
    /// Receive on this interface while sending, and report loss and latency
    /// of every stream: sent, received, lost, duplicates, reordering, and
    /// latency (min, avg, p99, max, jitter). It may be the interface sent on,
    /// when the packets come back on it. Puts a 28-byte signature at the end
    /// of each packet's IP payload (in a profile: in the streams marked
    /// `latency`, or in all if none is).
    #[arg(long, value_name = "IFACE")]
    pub rx: Option<String>,

    /// Put the signature in every stream's packets even without --rx, for a
    /// receiver on another machine (`ferotrx rx` there).
    #[arg(long)]
    pub latency: bool,

    /// With --rx: how long to keep receiving after the last packet is sent.
    #[arg(long, value_name = "TIME", default_value = "500ms", value_parser = parse_duration)]
    pub rx_wait: Duration,

    /// With --rx: also write the loss and latency report to this file, as JSON.
    #[arg(long, value_name = "FILE", requires = "rx")]
    pub report: Option<PathBuf>,
}

impl RxArgs {
    /// True when packets get signatures.
    pub fn tags(&self) -> bool {
        self.latency || self.rx.is_some()
    }

    /// Opens the receiver, before anything is sent.
    pub fn open(&self) -> Result<Option<RxSettings>> {
        let Some(iface) = &self.rx else {
            return Ok(None);
        };
        let receiver = ferotrx_io::open_receiver(iface)
            .map_err(|e| anyhow::anyhow!(e))
            .with_context(|| format!("cannot receive on {iface}"))?;
        Ok(Some(RxSettings {
            receiver,
            wait: self.rx_wait,
        }))
    }
}

/// A short progress note on a job's receiver, e.g. `rx 9876, lost 124 (1.24%), avg 5.12ms`.
pub fn progress_note(job: &Job) -> Option<String> {
    job.rx_stats()?;
    let reports = job.flow_reports();
    let tx: u64 = reports.iter().map(|r| r.tx).sum();
    let rx: u64 = reports.iter().map(|r| r.rx).sum();
    let lost = tx.saturating_sub(rx);
    let mut note = format!("rx {rx}, lost {lost} ({:.2}%)", pct(lost, tx));
    let worst = reports.iter().filter_map(|r| r.latency.max()).max();
    if let Some(w) = worst {
        note.push_str(&format!(
            ", max latency {}",
            fmt_us(Some(w.as_nanos() as f64 / 1e3))
        ));
    }
    Some(note)
}

fn pct(n: u64, of: u64) -> f64 {
    if of == 0 {
        0.0
    } else {
        n as f64 * 100.0 / of as f64
    }
}

/// The final loss and latency table of a job with a receiver.
pub struct Report {
    rows: Vec<(String, FlowCounters)>,
    /// Offered and achieved send rates, per row.
    rates: Vec<Option<SendRate>>,
    packets: u64,
    untagged: u64,
    /// Run metadata for the JSON report.
    pub info: Option<RunInfo>,
}

/// What a stream was asked to send and what it sent.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SendRate {
    /// The rate asked for, e.g. `1000pps`, `100mbps` or `topspeed`.
    offered: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    offered_pps: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offered_mbps: Option<f64>,
    /// Measured over the time the stream sent.
    achieved_pps: f64,
    achieved_mbps: f64,
    sent: u64,
    duration_s: f64,
}

impl SendRate {
    fn new(rate: Rate, st: &ReplayStats) -> Self {
        Self {
            offered: rate.to_string(),
            offered_pps: match rate {
                Rate::Pps(p) => Some(p),
                _ => None,
            },
            offered_mbps: match rate {
                Rate::Mbps(m) => Some(m),
                _ => None,
            },
            achieved_pps: st.pps(),
            achieved_mbps: st.mbps(),
            sent: st.packets,
            duration_s: st.elapsed.as_secs_f64(),
        }
    }
}

/// The JSON form of a report (`--report`).
#[derive(serde::Serialize)]
struct JsonReport<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    info: Option<&'a RunInfo>,
    /// Frames received, and those without a signature.
    packets: u64,
    untagged: u64,
    flows: Vec<JsonFlow<'a>>,
}

#[derive(serde::Serialize)]
struct JsonFlow<'a> {
    name: &'a str,
    #[serde(flatten)]
    counters: &'a FlowCounters,
    #[serde(skip_serializing_if = "Option::is_none")]
    send: Option<&'a SendRate>,
}

fn write_report(
    path: &Path,
    info: Option<&RunInfo>,
    packets: u64,
    untagged: u64,
    rows: &[(String, FlowCounters)],
    rates: &[Option<SendRate>],
) -> Result<()> {
    let report = JsonReport {
        info,
        packets,
        untagged,
        flows: rows
            .iter()
            .enumerate()
            .map(|(i, (name, counters))| JsonFlow {
                name,
                counters,
                send: rates.get(i).and_then(Option::as_ref),
            })
            .collect(),
    };
    let text = serde_json::to_string_pretty(&report)?;
    std::fs::write(path, text + "\n").with_context(|| format!("cannot write {}", path.display()))
}

/// Run metadata for a report: this machine, and the interfaces sent and received on.
pub fn run_info(tx: Option<&str>, rx: Option<&str>, backend: Option<String>) -> RunInfo {
    let mut info = RunInfo::new();
    ferotrx_io::describe_host(&mut info);
    info.command = Some(std::env::args().collect::<Vec<_>>().join(" "));
    info.backend = backend;
    info.tx_interface = tx.map(ferotrx_io::describe_interface);
    info.rx_interface = rx.map(ferotrx_io::describe_interface);
    info
}

impl Report {
    /// The report of a job that has ended, if it has a receiver.
    pub fn of(job: &Job) -> Option<Report> {
        let rx = job.rx_stats()?;
        let stats = job.stats();
        let reports = job.flow_reports();
        let rates = reports
            .iter()
            .map(|r| {
                let i = job.stream_names().iter().position(|n| *n == r.stream)?;
                Some(SendRate::new(*job.rates().get(i)?, stats.streams.get(i)?))
            })
            .collect();
        Some(Report {
            rows: reports
                .iter()
                .map(|r| (r.stream.clone(), r.into()))
                .collect(),
            rates,
            packets: rx.packets,
            untagged: rx.untagged,
            info: None,
        })
    }

    /// Writes the report as JSON.
    pub fn save(&self, path: &Path) -> Result<()> {
        write_report(
            path,
            self.info.as_ref(),
            self.packets,
            self.untagged,
            &self.rows,
            &self.rates,
        )
    }

    pub fn print(&self) {
        eprintln!("loss and latency:");
        for line in flow_lines(&self.rows) {
            eprintln!("{line}");
        }
        eprintln!(
            "  received {} frames, {} without a signature",
            self.packets, self.untagged
        );
    }
}

/// One line per flow, under a heading. Rows without `tx` count loss from
/// sequence gaps.
pub fn flow_lines(rows: &[(String, FlowCounters)]) -> Vec<String> {
    if rows.is_empty() {
        return vec!["  no flows with signatures".into()];
    }
    let w = rows.iter().map(|r| r.0.len()).max().unwrap_or(0).max(6);
    let mut lines = vec![format!(
        "  {:<w$} {:>5} {:>10} {:>10} {:>9} {:>8} {:>6} {:>6} {:>9} {:>9} {:>9} {:>9} {:>9}",
        "name",
        "flow",
        "tx",
        "rx",
        "lost",
        "loss",
        "dup",
        "ooo",
        "min",
        "avg",
        "p99",
        "max",
        "jitter"
    )];
    for (name, f) in rows {
        let l = &f.latency;
        lines.push(format!(
            "  {:<w$} {:>5} {:>10} {:>10} {:>9} {:>7.3}% {:>6} {:>6} {:>9} {:>9} {:>9} {:>9} {:>9}",
            name,
            f.flow,
            f.tx.map_or("-".to_string(), |t| t.to_string()),
            f.rx,
            f.lost,
            f.loss_pct,
            f.duplicates,
            f.out_of_order,
            fmt_us(l.min_us),
            fmt_us(l.avg_us),
            fmt_us(l.p99_us),
            fmt_us(l.max_us),
            fmt_us(l.jitter_us),
        ));
        if l.negative > 0 {
            lines.push(format!(
                "  {:<w$} warning: {} packets arrived before they were sent; the clocks of sender and receiver disagree",
                "", l.negative
            ));
        }
    }
    lines
}

/// Microseconds as `850us`, `5.12ms` or `1.30s`; `-` for none.
pub fn fmt_us(us: Option<f64>) -> String {
    match us {
        None => "-".into(),
        Some(v) if v < 1000.0 => format!("{v:.1}us"),
        Some(v) if v < 1e6 => format!("{:.2}ms", v / 1e3),
        Some(v) => format!("{:.2}s", v / 1e6),
    }
}

/// `ferotrx rx`.
#[derive(Args)]
pub struct RxCmdArgs {
    /// Receive on this interface (see `ferotrx interfaces`).
    #[arg(short, long, required_unless_present = "file", conflicts_with = "file")]
    iface: Option<String>,

    /// Read a capture taken on the receiving machine instead (tcpdump,
    /// Wireshark); its timestamps are the receive times.
    #[arg(short, long)]
    file: Option<PathBuf>,

    /// Stop after this long, e.g. 30s; otherwise run until Ctrl-C.
    #[arg(short, long, value_parser = parse_duration)]
    duration: Option<Duration>,

    /// Print no progress lines, only the final table.
    #[arg(short, long)]
    quiet: bool,

    /// Also write the final counters to this file, as JSON.
    #[arg(long, value_name = "FILE")]
    report: Option<PathBuf>,
}

pub fn cmd_rx(args: RxCmdArgs) -> Result<()> {
    if let Some(path) = &args.file {
        let cap =
            Capture::from_path(path).with_context(|| format!("cannot read {}", path.display()))?;
        let stats = RxStats::from_capture(&cap);
        let mut info = run_info(None, None, None);
        info.profile = Some(format!("capture {}", path.display()));
        return print_rx(&stats, args.report.as_deref(), Some(&info));
    }
    let Some(iface) = &args.iface else {
        bail!("give an interface (-i) or a capture (--file)");
    };
    let receiver = ferotrx_io::open_receiver(iface)
        .map_err(|e| anyhow::anyhow!(e))
        .with_context(|| format!("cannot receive on {iface}"))?;
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::Relaxed))
            .context("cannot install Ctrl-C handler")?;
    }
    let job = RxJob::spawn(
        receiver,
        RxConfig {
            duration: args.duration,
            stop: Some(stop),
            interval: None,
        },
    )?;
    if !args.quiet {
        eprintln!("receiving on {iface}; Ctrl-C to stop");
    }
    while !job.wait(Some(Duration::from_secs(1))) {
        if !args.quiet {
            let s = job.stats();
            let (rx, lost) = s
                .flows
                .values()
                .fold((0, 0), |(r, l), f| (r + f.unique(), l + f.seq_lost()));
            eprintln!(
                "progress: {} frames, {} flows, {rx} with signatures, {lost} missing ({:.2}%)",
                s.packets,
                s.flows.len(),
                pct(lost, rx + lost)
            );
        }
    }
    let stats = job.join()?;
    let info = run_info(None, Some(iface), None);
    print_rx(&stats, args.report.as_deref(), Some(&info))
}

fn print_rx(stats: &RxStats, report: Option<&Path>, info: Option<&RunInfo>) -> Result<()> {
    eprintln!(
        "received {} frames ({} bytes) in {:.3} s, {} without a signature",
        stats.packets,
        stats.bytes,
        stats.elapsed.as_secs_f64(),
        stats.untagged
    );
    let rows: Vec<(String, FlowCounters)> = stats
        .flows
        .values()
        .map(|f| (format!("flow {}", f.flow), f.into()))
        .collect();
    for line in flow_lines(&rows) {
        eprintln!("{line}");
    }
    if !rows.is_empty() {
        eprintln!(
            "  (lost = gaps in the sequence numbers between the first and the last packet seen)"
        );
    }
    match report {
        Some(path) => write_report(path, info, stats.packets, stats.untagged, &rows, &[]),
        None => Ok(()),
    }
}
