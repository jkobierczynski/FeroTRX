use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use ferotrx_core::{
    parse_duration, run_with_progress, Capture, CaptureSource, NullSink, PacketSink, Profile, Rate,
    ReplayStats, Rewrite, RunConfig, Stream, Transform, LINKTYPE_ETHERNET,
};
use ferotrx_io::PcapFileSink;

/// FeroTRX: replay captured traffic at a controlled rate.
#[derive(Parser)]
#[command(name = "ferotrx", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Replay a pcap or pcapng file.
    Replay(ReplayArgs),
    /// Run a traffic profile: several streams at once, each with its own rate and rewrites.
    Run(RunArgs),
    /// Decode a capture: one line per packet, or the full layers and bytes of chosen packets.
    Inspect(InspectArgs),
    /// Show what a capture contains.
    Info {
        /// The pcap or pcapng file.
        file: PathBuf,
    },
    /// List the interfaces packets can be sent on.
    #[cfg(feature = "pcap")]
    Interfaces,
}

#[derive(Args)]
struct ReplayArgs {
    /// The pcap or pcapng file to replay.
    file: PathBuf,

    #[command(flatten)]
    output: Output,

    #[command(flatten)]
    rate: RateArgs,

    /// Times to play the capture; 0 loops until Ctrl-C.
    #[arg(short = 'l', long = "loop", default_value_t = 1)]
    loops: u64,

    /// Rewrite packets before sending; repeat to chain. Examples:
    /// mac_dst=02:00:00:00:00:01, ip_dst=10.0.0.0/8->192.168.20.0,
    /// port_dst=53->5353, vlan_push=20[:PCP], qinq_push=100, vlan_set=30,
    /// vlan_pop, fix_checksums. `_src`/`_dst` can be left off to change both.
    #[arg(short, long = "rewrite", value_name = "SPEC")]
    rewrites: Vec<Rewrite>,

    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Args)]
struct InspectArgs {
    /// The pcap or pcapng file.
    file: PathBuf,

    /// Show the decoded layers and a hex dump of this packet (numbered from 1).
    /// Repeat or use a range: -p 3 -p 10-12.
    #[arg(short, long = "packet", value_name = "N[-M]")]
    packets: Vec<PacketRange>,

    /// Show at most this many packets.
    #[arg(short = 'c', long)]
    count: Option<usize>,

    /// Show the decoded layers of every listed packet, not just a summary line.
    #[arg(short, long)]
    verbose: bool,

    /// Add a hex dump to every listed packet.
    #[arg(short = 'x', long)]
    hex: bool,

    /// Only list packets with problems (bad checksums, truncated headers).
    #[arg(long)]
    problems: bool,

    /// Apply rewrites before decoding, to preview what `replay -r` would send.
    #[arg(short, long = "rewrite", value_name = "SPEC")]
    rewrites: Vec<Rewrite>,
}

/// `N` or `N-M`, numbered from 1.
#[derive(Clone, Copy, Debug)]
struct PacketRange(usize, usize);

impl std::str::FromStr for PacketRange {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, String> {
        let num = |t: &str| {
            t.trim()
                .parse::<usize>()
                .ok()
                .filter(|&n| n > 0)
                .ok_or_else(|| format!("'{t}' is not a packet number (they start at 1)"))
        };
        match s.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (num(a)?, num(b)?);
                if a > b {
                    return Err(format!("range {s} is backwards"));
                }
                Ok(PacketRange(a, b))
            }
            None => num(s).map(|n| PacketRange(n, n)),
        }
    }
}

#[derive(Args)]
struct RunArgs {
    /// The profile, a TOML file with one [[stream]] table per stream.
    profile: PathBuf,

    #[command(flatten)]
    output: Output,

    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Args)]
struct CommonArgs {
    /// Stop after this many packets in total.
    #[arg(long)]
    limit: Option<u64>,

    /// Stop after this long, e.g. 30s or 5m.
    #[arg(short, long, value_parser = parse_duration)]
    duration: Option<Duration>,

    /// Count failed sends and keep going instead of stopping.
    #[arg(long)]
    ignore_errors: bool,

    /// Print no progress lines, only the final summary.
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct Output {
    /// Send on this network interface (see `ferotrx interfaces`).
    #[cfg(feature = "pcap")]
    #[arg(short, long)]
    iface: Option<String>,

    /// Write the packets to this pcap file, stamped with their send time.
    #[arg(short, long)]
    out: Option<PathBuf>,

    /// Discard packets; measures the engine's own speed.
    #[arg(long)]
    null: bool,
}

#[derive(Args)]
#[group(multiple = false)]
struct RateArgs {
    /// Keep the original timing, sped up by this factor (default 1).
    #[arg(short = 'x', long)]
    multiplier: Option<f64>,

    /// Send this many packets per second.
    #[arg(short = 'p', long)]
    pps: Option<f64>,

    /// Send at this many megabits per second.
    #[arg(short = 'M', long)]
    mbps: Option<f64>,

    /// Send as fast as possible.
    #[arg(short = 't', long)]
    topspeed: bool,
}

impl RateArgs {
    fn rate(&self) -> Rate {
        if let Some(pps) = self.pps {
            Rate::Pps(pps)
        } else if let Some(mbps) = self.mbps {
            Rate::Mbps(mbps)
        } else if self.topspeed {
            Rate::TopSpeed
        } else {
            Rate::Original {
                multiplier: self.multiplier.unwrap_or(1.0),
            }
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Replay(args) => cmd_replay(args),
        Command::Run(args) => cmd_run(args),
        Command::Info { file } => cmd_info(&file),
        Command::Inspect(args) => cmd_inspect(args),
        #[cfg(feature = "pcap")]
        Command::Interfaces => cmd_interfaces(),
    }
}

fn load(file: &PathBuf) -> Result<Capture> {
    Capture::from_path(file).with_context(|| format!("cannot read {}", file.display()))
}

fn cmd_info(file: &PathBuf) -> Result<()> {
    let cap = load(file)?;
    let secs = cap.duration().as_secs_f64();
    println!("file:      {}", file.display());
    println!("link type: {}", cap.linktype);
    println!("packets:   {}", cap.len());
    println!("bytes:     {}", cap.total_bytes());
    println!("duration:  {secs:.6} s");
    if secs > 0.0 {
        println!(
            "avg rate:  {:.1} pps, {:.3} Mbps",
            cap.len() as f64 / secs,
            cap.total_bytes() as f64 * 8.0 / 1e6 / secs
        );
    }
    Ok(())
}

fn cmd_inspect(args: InspectArgs) -> Result<()> {
    let mut cap = load(&args.file)?;
    if !args.rewrites.is_empty() {
        if cap.linktype != LINKTYPE_ETHERNET {
            bail!(
                "rewrites need Ethernet frames, capture has link type {}",
                cap.linktype
            );
        }
        let mut rewrites = args.rewrites.clone();
        for p in &mut cap.packets {
            for r in &mut rewrites {
                r.apply(p);
            }
        }
    }
    let first_ts = cap.packets.first().map_or(Duration::ZERO, |p| p.timestamp);
    let chosen = |n: usize| args.packets.iter().any(|r| (r.0..=r.1).contains(&n));
    let detail_only = !args.packets.is_empty();

    let mut shown = 0usize;
    let mut with_problems = 0usize;
    let mut protocols: Vec<(&'static str, usize)> = Vec::new();
    if !detail_only {
        println!(
            "{:>6}  {:>11}  {:<24}  {:<24}  {:<8}  {:>5}  Info",
            "No.", "Time", "Source", "Destination", "Protocol", "Len"
        );
    }
    for (i, p) in cap.packets.iter().enumerate() {
        let n = i + 1;
        let d = ferotrx_packet::decode(cap.linktype, &p.data);
        if !d.problems.is_empty() {
            with_problems += 1;
        }
        match protocols.iter_mut().find(|(name, _)| *name == d.protocol) {
            Some((_, c)) => *c += 1,
            None => protocols.push((d.protocol, 1)),
        }
        if (detail_only && !chosen(n)) || (args.problems && d.problems.is_empty()) {
            continue;
        }
        if args.count.is_some_and(|c| shown >= c) {
            continue;
        }
        shown += 1;
        let t = p.timestamp.saturating_sub(first_ts).as_secs_f64();
        let mut info = d.info.clone();
        if !d.problems.is_empty() {
            info.push_str(" [!]");
        }
        if detail_only {
            println!("Packet {n}: {} bytes, time {t:.6} s", d.len);
        } else {
            println!(
                "{n:>6}  {t:>11.6}  {:<24}  {:<24}  {:<8}  {:>5}  {info}",
                d.source, d.destination, d.protocol, d.len
            );
        }
        if detail_only || args.verbose {
            for line in d.tree().lines() {
                println!("    {line}");
            }
        }
        if detail_only || args.hex {
            for line in ferotrx_packet::hex_dump(&p.data).lines() {
                println!("    {line}");
            }
        }
        if detail_only || args.verbose || args.hex {
            println!();
        }
    }
    if detail_only && shown == 0 {
        bail!(
            "{} has {} packets; none matched",
            args.file.display(),
            cap.len()
        );
    }
    protocols.sort_by_key(|p| std::cmp::Reverse(p.1));
    let list: Vec<String> = protocols.iter().map(|(p, c)| format!("{p} {c}")).collect();
    eprintln!(
        "{} packets ({}), {with_problems} with problems",
        cap.len(),
        list.join(", ")
    );
    Ok(())
}

#[cfg(feature = "pcap")]
fn cmd_interfaces() -> Result<()> {
    let list = ferotrx_io::list_interfaces()
        .map_err(|e| anyhow::anyhow!(e))
        .context("cannot list interfaces")?;
    if list.is_empty() {
        println!("no interfaces found (you may need more privileges)");
    }
    for i in list {
        match i.description {
            Some(d) => println!("{}\t{}", i.name, d),
            None => println!("{}", i.name),
        }
    }
    Ok(())
}

fn open_sink(output: &Output, linktype: u32) -> Result<Box<dyn PacketSink>> {
    #[cfg(feature = "pcap")]
    if let Some(name) = &output.iface {
        if linktype != LINKTYPE_ETHERNET {
            eprintln!("warning: capture link type is {linktype}, not Ethernet; frames may not be valid on {name}");
        }
        let sink = ferotrx_io::InterfaceSink::open(name)
            .map_err(|e| anyhow::anyhow!(e))
            .with_context(|| format!("cannot open interface {name}"))?;
        return Ok(Box::new(sink));
    }
    if let Some(path) = &output.out {
        let sink = PcapFileSink::create(path, linktype)
            .map_err(|e| anyhow::anyhow!(e))
            .with_context(|| format!("cannot create {}", path.display()))?;
        return Ok(Box::new(sink));
    }
    if output.null {
        return Ok(Box::new(NullSink));
    }
    bail!("choose an output")
}

fn cmd_replay(args: ReplayArgs) -> Result<()> {
    let rate = args.rate.rate();
    rate.validate()?;
    let cap = load(&args.file)?;
    if cap.is_empty() {
        bail!("{} has no packets", args.file.display());
    }
    if !args.rewrites.is_empty() && cap.linktype != LINKTYPE_ETHERNET {
        bail!(
            "rewrites need Ethernet frames, {} has link type {}",
            args.file.display(),
            cap.linktype
        );
    }
    let mut stream =
        Stream::new("capture", CaptureSource::new(&cap).loops(args.loops)).with_rate(rate);
    for r in args.rewrites {
        stream.push_transform(r);
    }
    let mut sink = open_sink(&args.output, cap.linktype)?;
    let stats = execute(&mut [stream], &mut sink, &args.common)?;
    print_line(done_label(&stats.total), &stats.total);
    Ok(())
}

fn cmd_run(args: RunArgs) -> Result<()> {
    let profile = Profile::from_path(&args.profile)
        .with_context(|| format!("cannot read {}", args.profile.display()))?;
    let mut streams = profile.load()?;
    let linktype = streams.first().map_or(LINKTYPE_ETHERNET, Stream::linktype);
    let mut sink = open_sink(&args.output, linktype)?;
    if !args.common.quiet {
        for (s, spec) in streams.iter().zip(&profile.streams) {
            let rewrites: Vec<String> = spec.rewrite.iter().map(ToString::to_string).collect();
            eprintln!(
                "stream {}: {} at {}{}",
                s.name,
                spec.pcap.display(),
                s.rate,
                if rewrites.is_empty() {
                    String::new()
                } else {
                    format!(", rewrite {}", rewrites.join(" "))
                }
            );
        }
    }
    let stats = execute(&mut streams, &mut sink, &args.common)?;
    for (s, st) in streams.iter().zip(&stats.streams) {
        print_line(&format!("  {}", s.name), st);
    }
    print_line(done_label(&stats.total), &stats.total);
    Ok(())
}

/// Runs the streams with Ctrl-C handling and once-a-second progress lines.
fn execute(
    streams: &mut [Stream<'_>],
    sink: &mut Box<dyn PacketSink>,
    common: &CommonArgs,
) -> Result<ferotrx_core::RunStats> {
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::Relaxed))
            .context("cannot install Ctrl-C handler")?;
    }
    let config = RunConfig {
        limit: common.limit,
        duration: common.duration,
        ignore_send_errors: common.ignore_errors,
        stop: Some(stop),
    };
    let interval = if common.quiet {
        Duration::MAX
    } else {
        Duration::from_secs(1)
    };
    Ok(run_with_progress(streams, sink, &config, interval, |s| {
        print_line("progress", &s.total)
    })?)
}

fn done_label(s: &ReplayStats) -> &'static str {
    if s.stopped {
        "stopped"
    } else {
        "done"
    }
}

fn print_line(label: &str, s: &ReplayStats) {
    let mut line = format!(
        "{label}: {} packets, {} bytes in {:.3} s ({:.1} pps, {:.3} Mbps)",
        s.packets,
        s.bytes,
        s.elapsed.as_secs_f64(),
        s.pps(),
        s.mbps()
    );
    if s.send_errors > 0 {
        line.push_str(&format!(", {} send errors", s.send_errors));
    }
    eprintln!("{line}");
}
