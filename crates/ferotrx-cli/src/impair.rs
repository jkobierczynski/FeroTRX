//! `ferotrx impair`: a two-port bridge that impairs what it passes on.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Args;
use ferotrx_core::{parse_duration, run_bridge, BridgeConfig, BridgeStats, ImpairSpec};

#[derive(Args)]
pub struct ImpairArgs {
    /// The first interface: what arrives here goes out on --out-iface,
    /// impaired by --impair.
    #[arg(short, long, value_name = "IFACE")]
    iface: String,

    /// The second interface: what arrives here goes back out on --iface,
    /// impaired by --impair-back.
    #[arg(short = 'o', long = "out-iface", value_name = "IFACE")]
    out_iface: String,

    /// Impairments from --iface to --out-iface: KEY=VALUE pairs such as
    /// 'delay=20ms jitter=5ms loss=1% loss_burst=3 duplicate=0.1%
    /// reorder=0.5% corrupt=0.01% rate=10mbit mtu=1400 seed=1' (see
    /// docs/impairments.md).
    #[arg(long, value_name = "SPEC", default_value = "none")]
    impair: ImpairSpec,

    /// Impairments the other way; the same as --impair when left out (with
    /// its own random numbers), `none` for a clean way back.
    #[arg(long, value_name = "SPEC")]
    impair_back: Option<ImpairSpec>,

    /// Stop after this long (default: until Ctrl-C).
    #[arg(short, long, value_parser = parse_duration)]
    duration: Option<Duration>,

    /// Print no progress lines, only the final summary.
    #[arg(short, long)]
    quiet: bool,
}

pub fn cmd_impair(args: ImpairArgs) -> Result<()> {
    if args.iface == args.out_iface {
        bail!("the bridge needs two different interfaces");
    }
    let back = args
        .impair_back
        .clone()
        .unwrap_or_else(|| args.impair.for_lane(1));
    // Both ports take every frame (promiscuous libpcap/Npcap) and leave out
    // what they send themselves.
    let a = ferotrx_io::open_port(&args.iface)
        .map_err(|e| anyhow::anyhow!("cannot open {}: {e}", args.iface))?;
    let b = ferotrx_io::open_port(&args.out_iface)
        .map_err(|e| anyhow::anyhow!("cannot open {}: {e}", args.out_iface))?;
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::Relaxed))
            .context("cannot install Ctrl-C handler")?;
    }
    if !args.quiet {
        eprintln!(
            "bridging {} -> {}: {}; {} -> {}: {}{}",
            args.iface,
            args.out_iface,
            args.impair,
            args.out_iface,
            args.iface,
            back,
            match args.duration {
                Some(d) => format!(", for {d:?}"),
                None => ", until Ctrl-C".into(),
            }
        );
    }
    let config = BridgeConfig {
        duration: args.duration,
        stop: Some(stop),
    };
    let quiet = args.quiet;
    let stats = run_bridge(
        a,
        b,
        &args.impair,
        &back,
        &config,
        Duration::from_secs(1),
        |s| {
            if !quiet && !s.elapsed.is_zero() {
                eprintln!(
                    "progress {:.0} s: forward {} in {} out, back {} in {} out",
                    s.elapsed.as_secs_f64(),
                    s.forward.packets,
                    s.forward.passed,
                    s.back.packets,
                    s.back.passed
                );
            }
        },
    )?;
    print_summary(&args, &stats);
    Ok(())
}

fn print_summary(args: &ImpairArgs, s: &BridgeStats) {
    eprintln!(
        "{} after {:.3} s",
        if s.stopped { "stopped" } else { "done" },
        s.elapsed.as_secs_f64()
    );
    eprintln!("  {} -> {}: {}", args.iface, args.out_iface, s.forward);
    eprintln!("  {} -> {}: {}", args.out_iface, args.iface, s.back);
}
