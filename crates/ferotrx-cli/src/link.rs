//! The port's own addresses and the line's speed on the command line.

use anyhow::{bail, Result};
use clap::Args;
use ferotrx_core::{IpPrefix, IpRange, LinkSettings, MacAddr};

/// The line and the port's own addresses (TRex's L3 port mode).
#[derive(Args, Clone, Default)]
pub struct LinkArgs {
    /// The line's speed, e.g. 1gbps, for --load and rates that are a share of
    /// it; default the profile's line_rate, then the interface's speed.
    #[arg(long, value_name = "RATE")]
    pub line_rate: Option<String>,

    /// Count --mbps on the wire (layer 1: 24 more bytes per frame for
    /// preamble, gap and FCS) instead of the frames alone.
    #[arg(long)]
    pub l1: bool,

    #[command(flatten)]
    pub addr: AddrArgs,
}

/// The port's own addresses (TRex's L3 port mode).
#[derive(Args, Clone, Default)]
pub struct AddrArgs {
    /// The port's own address, e.g. 10.0.0.2/24 or 2001:db8::2/64 (one per
    /// IP version). With --gateway the gateway's MAC goes into every frame,
    /// and the port answers ARP, neighbor solicitations and pings.
    #[arg(long = "ip", value_name = "ADDR/LEN")]
    pub ip: Vec<IpPrefix>,

    /// The next hop: the router, or the receiver when it is on the port's
    /// subnet (one per IP version). Found by ARP or neighbor discovery.
    #[arg(long, value_name = "IP")]
    pub gateway: Vec<std::net::IpAddr>,

    /// The port's MAC address (default: the interface's).
    #[arg(long, value_name = "MAC")]
    pub mac: Option<MacAddr>,

    /// VLAN of the port's ARP, neighbor discovery and answers.
    #[arg(long, value_name = "ID")]
    pub port_vlan: Option<u16>,

    /// More addresses the port answers for, e.g. 10.0.1.1-10.0.1.254 (the
    /// varied sources of a stream); repeat for more.
    #[arg(long, value_name = "RANGE")]
    pub answer: Vec<IpRange>,
}

impl AddrArgs {
    /// The addresses given here, the rest from `fallback` (a profile's).
    pub fn settings(&self, fallback: &LinkSettings) -> Result<LinkSettings> {
        let link = LinkSettings {
            line_rate: None,
            ip: self.ip.clone(),
            gateway: self.gateway.clone(),
            mac: self.mac,
            vlan: self.port_vlan,
            answer: self.answer.clone(),
        }
        .or(fallback);
        link.validate()?;
        Ok(link)
    }
}

impl LinkArgs {
    /// The settings given here, the rest from `fallback` (a profile's).
    pub fn settings(&self, fallback: &LinkSettings) -> Result<LinkSettings> {
        let mut link = self.addr.settings(fallback)?;
        if let Some(r) = &self.line_rate {
            link.line_rate = Some(ferotrx_core::parse_line_rate(r)?);
            link.validate()?;
        }
        Ok(link)
    }

    /// Refuses --l1 where it has nothing to apply to.
    pub fn check_no_l1(&self) -> Result<()> {
        if self.l1 {
            bail!("--l1 applies to --mbps on replay and build; profiles say 100mbps-l1");
        }
        Ok(())
    }
}
