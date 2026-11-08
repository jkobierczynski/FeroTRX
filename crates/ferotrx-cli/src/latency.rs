//! Loss and latency on the command line: `--rx`/`--latency` and `ferotrx rx`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Args;
use ferotrx_core::{
    parse_duration, Capture, DropCounters, Job, LossReport, Rate, ReplayStats, RunInfo, RxConfig,
    RxJob, RxSettings, RxStats,
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

    /// Write a record of the run to this file, as JSON: what ran where
    /// (version, host, NIC and driver, backend, workers, CPU affinity,
    /// profile and its hash), what each stream sent, what every layer
    /// dropped, and with --rx the loss and latency of every flow and where
    /// the frames were lost.
    #[arg(long, value_name = "FILE")]
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

/// The record of a run that has ended: what each stream sent, what every
/// layer dropped and, with a receiver, the loss and latency table and where
/// the frames were lost.
pub struct Report {
    rows: Vec<(String, FlowCounters)>,
    /// Offered and achieved send rates, per row.
    rates: Vec<Option<SendRate>>,
    packets: u64,
    untagged: u64,
    /// True when the job had a receiver.
    rx: bool,
    streams: Vec<StreamRecord>,
    drops: DropCounters,
    loss: Option<LossReport>,
    workers: usize,
    pinned: Option<String>,
    /// Run metadata for the JSON report.
    pub info: Option<RunInfo>,
}

/// What one stream sent.
#[derive(Clone, Debug, serde::Serialize)]
struct StreamRecord {
    name: String,
    #[serde(flatten)]
    send: SendRate,
    #[serde(skip_serializing_if = "is_zero")]
    send_errors: u64,
    #[serde(skip_serializing_if = "is_zero")]
    late_skipped: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
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
    /// What each stream sent (a run's record; not in `ferotrx rx` reports).
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    streams: &'a [StreamRecord],
    /// What every layer dropped, both sides.
    #[serde(skip_serializing_if = "DropCounters::is_empty")]
    drops: DropCounters,
    /// Where the frames of the streams with signatures were lost.
    #[serde(skip_serializing_if = "Option::is_none")]
    loss: Option<&'a LossReport>,
    /// Frames received, and those without a signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    packets: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    untagged: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flows: Option<Vec<JsonFlow<'a>>>,
}

#[derive(serde::Serialize)]
struct JsonFlow<'a> {
    name: &'a str,
    #[serde(flatten)]
    counters: &'a FlowCounters,
    #[serde(skip_serializing_if = "Option::is_none")]
    send: Option<&'a SendRate>,
}

/// What goes in a JSON report besides the flows.
#[derive(Default)]
struct Extra<'a> {
    streams: &'a [StreamRecord],
    drops: DropCounters,
    loss: Option<&'a LossReport>,
}

fn write_report(
    path: &Path,
    info: Option<&RunInfo>,
    rx: Option<(u64, u64)>,
    rows: &[(String, FlowCounters)],
    rates: &[Option<SendRate>],
    extra: Extra<'_>,
) -> Result<()> {
    let report = JsonReport {
        info,
        streams: extra.streams,
        drops: extra.drops,
        loss: extra.loss,
        packets: rx.map(|r| r.0),
        untagged: rx.map(|r| r.1),
        flows: rx.map(|_| {
            rows.iter()
                .enumerate()
                .map(|(i, (name, counters))| JsonFlow {
                    name,
                    counters,
                    send: rates.get(i).and_then(Option::as_ref),
                })
                .collect()
        }),
    };
    let text = serde_json::to_string_pretty(&report)?;
    std::fs::write(path, text + "\n").with_context(|| format!("cannot write {}", path.display()))
}

/// Writes the record of a TCP, UDP or other run to `path`, as JSON:
/// `{"info": ..., KEY: counters}`.
pub fn save_record<T: serde::Serialize>(
    path: &Path,
    info: &RunInfo,
    key: &str,
    counters: &T,
) -> Result<()> {
    let mut map = serde_json::Map::new();
    map.insert("info".into(), serde_json::to_value(info)?);
    map.insert(key.into(), serde_json::to_value(counters)?);
    let text = serde_json::to_string_pretty(&serde_json::Value::Object(map))?;
    std::fs::write(path, text + "\n").with_context(|| format!("cannot write {}", path.display()))
}

/// Sets the profile of a record from a file, with its text and hash.
pub fn set_profile_file(info: &mut RunInfo, path: &Path) {
    info.set_profile(
        path.display().to_string(),
        std::fs::read_to_string(path).ok(),
    );
}

/// The line on what the ports' layers dropped, when more than the capture
/// buffer (which the summary line has) dropped anything.
pub fn drops_line(drops: &DropCounters) -> Option<String> {
    let only_capture = DropCounters {
        capture_dropped: drops.capture_dropped,
        ..Default::default()
    };
    (*drops != only_capture).then(|| format!("dropped at: {}", drops.describe()))
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
    /// The record of a job that has ended.
    pub fn of(job: &Job) -> Report {
        let stats = job.stats();
        let streams = job
            .stream_names()
            .iter()
            .zip(job.rates())
            .zip(&stats.streams)
            .map(|((name, rate), st)| StreamRecord {
                name: name.clone(),
                send: SendRate::new(*rate, st),
                send_errors: st.send_errors,
                late_skipped: st.late_skipped,
            })
            .collect();
        let mut drops = stats.drops.tx_side();
        let rx = job.rx_stats();
        if let Some(rx) = &rx {
            drops.add(&rx.drops.rx_side());
        }
        let reports = job.flow_reports();
        let rates = reports
            .iter()
            .map(|r| {
                let i = job.stream_names().iter().position(|n| *n == r.stream)?;
                Some(SendRate::new(*job.rates().get(i)?, stats.streams.get(i)?))
            })
            .collect();
        Report {
            rows: reports
                .iter()
                .map(|r| (r.stream.clone(), r.into()))
                .collect(),
            rates,
            packets: rx.as_ref().map_or(0, |r| r.packets),
            untagged: rx.as_ref().map_or(0, |r| r.untagged),
            rx: rx.is_some(),
            streams,
            drops,
            loss: job.loss(),
            workers: job.workers(),
            pinned: job.pinned_cpus().map(ToString::to_string),
            info: None,
        }
    }

    /// Writes the report as JSON, with `info` (and the job's worker count).
    pub fn save(&mut self, path: &Path, mut info: RunInfo) -> Result<()> {
        info.workers = Some(self.workers);
        info.pinned_cpus = self.pinned.clone();
        self.info = Some(info);
        write_report(
            path,
            self.info.as_ref(),
            self.rx.then_some((self.packets, self.untagged)),
            &self.rows,
            &self.rates,
            Extra {
                streams: &self.streams,
                drops: self.drops,
                loss: self.loss.as_ref(),
            },
        )
    }

    /// Prints the loss and latency table (with a receiver) and where frames
    /// were dropped.
    pub fn print(&self) {
        if self.rx {
            eprintln!("loss and latency:");
            for line in flow_lines(&self.rows) {
                eprintln!("{line}");
            }
            eprintln!(
                "  received {} frames, {} without a signature",
                self.packets, self.untagged
            );
        }
        if let Some(loss) = &self.loss {
            eprintln!("  {}", loss.line());
        } else if !self.drops.is_empty() {
            eprintln!("dropped at: {}", self.drops.describe());
        }
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
        info.set_profile(format!("capture {}", path.display()), None);
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
    let drops = stats.drops.rx_side();
    if !drops.is_empty() {
        eprintln!("  dropped here before they were read: {}", drops.describe());
    }
    match report {
        Some(path) => write_report(
            path,
            info,
            Some((stats.packets, stats.untagged)),
            &rows,
            &[],
            Extra {
                drops,
                ..Default::default()
            },
        ),
        None => Ok(()),
    }
}
