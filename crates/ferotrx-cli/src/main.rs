use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use ferotrx_core::{
    replay_with_progress, Capture, NullSink, PacketSink, Rate, ReplayConfig, ReplayStats,
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

    /// Stop after this many packets.
    #[arg(long)]
    limit: Option<u64>,

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
        Command::Info { file } => cmd_info(&file),
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
        if linktype != ferotrx_core::LINKTYPE_ETHERNET {
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
    let mut sink = open_sink(&args.output, cap.linktype)?;

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::Relaxed))
            .context("cannot install Ctrl-C handler")?;
    }

    let config = ReplayConfig {
        rate,
        loops: args.loops,
        limit: args.limit,
        ignore_send_errors: args.ignore_errors,
        stop: Some(stop),
    };
    let interval = if args.quiet {
        Duration::MAX
    } else {
        Duration::from_secs(1)
    };
    let stats = replay_with_progress(&cap, &mut sink, &config, interval, |s| {
        print_line("progress", s)
    })?;
    print_line(if stats.stopped { "stopped" } else { "done" }, &stats);
    Ok(())
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
