//! `ferotrx lab`: a lab router on this machine, until Ctrl-C.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use ferotrx_io::{Lab, LabConfig, LAB_INTERFACE, LAB_NAMESPACE};

#[derive(Args)]
pub struct LabArgs {
    #[command(subcommand)]
    cmd: LabCmd,
}

#[derive(Subcommand)]
enum LabCmd {
    /// Build the lab and keep it until Ctrl-C.
    Up(UpArgs),
    /// Remove a lab that was left behind (by a server that was killed).
    Down,
}

#[derive(Args)]
struct UpArgs {
    /// IPv4 only.
    #[arg(long)]
    no_ipv6: bool,
    /// Route without masquerading.
    #[arg(long)]
    no_nat: bool,
    /// Share of forwarded packets the router drops (0.03 is 3%).
    #[arg(long, default_value_t = 0.0)]
    loss: f64,
    /// Delay on the router's links, as tc netem takes it ("5ms", "20ms 5ms").
    #[arg(long, default_value = "")]
    delay: String,
    /// TCP port the router refuses with a reset (repeat for more).
    #[arg(long = "block-tcp", value_name = "PORT")]
    block_tcp: Vec<u16>,
    /// UDP port the router drops (repeat for more).
    #[arg(long = "block-udp", value_name = "PORT")]
    block_udp: Vec<u16>,
    /// DHCP (and router advertisements) on VLAN 10, from dnsmasq.
    #[arg(long)]
    dhcp: bool,
    /// Queues on each end of the link, for --workers with -B af_xdp.
    #[arg(long, default_value_t = 1)]
    queues: u32,
}

pub fn cmd_lab(args: LabArgs) -> Result<()> {
    match args.cmd {
        LabCmd::Down => {
            if let Some(why) = ferotrx_io::lab_unavailable() {
                anyhow::bail!("{why}");
            }
            ferotrx_io::remove_lab();
            eprintln!("removed {LAB_INTERFACE} and the namespace {LAB_NAMESPACE}");
            Ok(())
        }
        LabCmd::Up(a) => {
            let lab = Lab::up(LabConfig {
                ipv6: !a.no_ipv6,
                nat: !a.no_nat,
                loss: a.loss,
                delay: a.delay,
                block_tcp: a.block_tcp,
                block_udp: a.block_udp,
                dhcp: a.dhcp,
                queues: a.queues,
            })
            .context("cannot build the lab")?;
            let stop = Arc::new(AtomicBool::new(false));
            {
                let stop = stop.clone();
                ctrlc::set_handler(move || stop.store(true, Ordering::Relaxed))
                    .context("cannot install Ctrl-C handler")?;
            }
            eprintln!("lab up: send on {LAB_INTERFACE}");
            eprintln!("  clients: VLAN 10, 192.168.10.0/24, gateway 192.168.10.1");
            eprintln!("  servers: VLAN 20, 192.168.20.0/24, gateway 192.168.20.1");
            if lab.config().ipv6 {
                eprintln!("  IPv6: fd00:10::/64 and fd00:20::/64, gateways ::1");
            }
            for n in lab.notes() {
                eprintln!("  note: {n}");
            }
            eprintln!(
                "  for example: sudo ferotrx udp -p examples/lab-udp-mix.toml -i {LAB_INTERFACE}"
            );
            eprintln!("Ctrl-C removes the lab");
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(100));
            }
            lab.down();
            eprintln!("lab removed");
            Ok(())
        }
    }
}
