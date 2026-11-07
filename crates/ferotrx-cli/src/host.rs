//! `ferotrx host`: emulated hosts on their own (DHCP, SLAAC, DHCPv6,
//! announcements, multicast groups, router advertisements).

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Args;
use ferotrx_core::{
    parse_duration, parse_ipv4_mode, parse_ipv6_mode, parse_pool, parse_prefix6, DhcpServerConfig,
    Dhcpv6ServerConfig, HostConfig, HostEngine, HostProfile, HostSpec, HostState, HostStats,
    HostStatus, MacAddr, PortJob, RouterConfig, TcpRunConfig,
};
use ferotrx_ctl::protocol::{DhcpServerInfo, HostAddressInfo, HostInfo};

#[derive(Args)]
#[command(args_override_self = true)]
pub struct HostArgs {
    /// A host profile (TOML) with `[[host]]` tables; see examples/lab-hosts.toml.
    /// Without one, the options below make the hosts.
    profile: Option<PathBuf>,

    /// Interface of hosts that name none.
    #[arg(short, long)]
    iface: Option<String>,

    /// Hosts to emulate, alike but for their MACs (counting up from --mac),
    /// static addresses and host names.
    #[arg(short = 'n', long, value_name = "N")]
    count: Option<u32>,

    /// MAC address of the first host (default 02:dc:00:00:01:01).
    #[arg(long)]
    mac: Option<MacAddr>,

    /// 802.1Q VLAN of the hosts.
    #[arg(long, value_name = "ID")]
    vlan: Option<u16>,

    /// IPv4: dhcp, or a static IP/PREFIX (counting up for each host).
    #[arg(long, value_name = "dhcp|IP/PREFIX")]
    ipv4: Option<String>,

    /// Gateway for a static IPv4 address.
    #[arg(long, value_name = "IP")]
    gateway: Option<String>,

    /// IPv6: slaac, dhcpv6, or a static IP/PREFIX (counting up for each host).
    #[arg(long, value_name = "slaac|dhcpv6|IP/PREFIX")]
    ipv6: Option<String>,

    /// Gateway for a static IPv6 address.
    #[arg(long, value_name = "IP")]
    gateway6: Option<String>,

    /// Join this multicast group, IPv4 (IGMP) or IPv6 (MLD); repeat for more.
    #[arg(long, value_name = "GROUP")]
    join: Vec<IpAddr>,

    /// Announce addresses (gratuitous ARP, unsolicited neighbor
    /// advertisements); on by default for dhcp, slaac and dhcpv6.
    #[arg(long)]
    announce: bool,

    /// Host name for DHCP; {n} is the host's number from 1.
    #[arg(long, value_name = "NAME")]
    hostname: Option<String>,

    /// Act as an IPv6 router: advertise this prefix (e.g. fd00:99::/64);
    /// repeat for more.
    #[arg(long, value_name = "PREFIX")]
    ra: Vec<String>,

    /// Time between router advertisements (default 10s).
    #[arg(long, value_parser = parse_duration, value_name = "TIME")]
    ra_interval: Option<Duration>,

    /// Router lifetime in the advertisements; 0 is not a default router (default 30m).
    #[arg(long, value_parser = parse_duration, value_name = "TIME")]
    ra_lifetime: Option<Duration>,

    /// Set the M flag (addresses by DHCPv6) in the advertisements.
    #[arg(long)]
    ra_managed: bool,

    /// Set the O flag (other settings by DHCPv6) in the advertisements.
    #[arg(long)]
    ra_other: bool,

    /// Serve DHCP (an IPv4 range, needs a static --ipv4) or DHCPv6 (an IPv6
    /// range) from this pool, e.g. 10.0.0.100-10.0.0.199; give one of each
    /// for both.
    #[arg(long, value_name = "FIRST-LAST")]
    dhcp_pool: Vec<String>,

    /// Lease time of the DHCP servers (default 1h).
    #[arg(long, value_parser = parse_duration, value_name = "TIME")]
    dhcp_lease: Option<Duration>,

    /// Router option of the DHCP server (default: --gateway).
    #[arg(long, value_name = "IP")]
    dhcp_router: Option<std::net::Ipv4Addr>,

    /// DNS server the DHCP (IPv4) or DHCPv6 (IPv6) server hands out; repeat for more.
    #[arg(long, value_name = "IP")]
    dhcp_dns: Vec<IpAddr>,

    /// Domain name the DHCP servers hand out.
    #[arg(long, value_name = "NAME")]
    dhcp_domain: Option<String>,

    /// Hosts started per second (default: all at once).
    #[arg(long, value_name = "N")]
    rate: Option<f64>,

    /// IGMP version for reports, 1-3 (default 3).
    #[arg(long, value_name = "V")]
    igmp_version: Option<u8>,

    /// MLD version for reports, 1-2 (default 2).
    #[arg(long, value_name = "V")]
    mld_version: Option<u8>,

    /// How long a host may take to get its addresses (default 30s).
    #[arg(long, value_parser = parse_duration, value_name = "TIME")]
    setup_timeout: Option<Duration>,

    /// Keep the leases at the end (no DHCP release) and do not leave groups.
    #[arg(long)]
    no_release: bool,

    /// Skip duplicate address detection for IPv6 addresses.
    #[arg(long)]
    no_dad: bool,

    /// Ask DHCP servers to broadcast their answers.
    #[arg(long)]
    broadcast: bool,

    #[command(flatten)]
    send: crate::SendArgs,

    #[command(flatten)]
    impair: crate::PortImpairArgs,

    /// Stop once every host has its addresses (or failed).
    #[arg(long)]
    until_ready: bool,

    /// Stop after this long, e.g. 30s or 5m (default: until Ctrl-C).
    #[arg(short, long, value_parser = parse_duration)]
    duration: Option<Duration>,

    /// Print no progress lines, only the hosts at the end.
    #[arg(short, long)]
    quiet: bool,

    #[command(flatten)]
    capture: crate::capture::RunCaptureArgs,
}

impl HostArgs {
    fn any_host_option(&self) -> bool {
        self.count.is_some()
            || self.mac.is_some()
            || self.vlan.is_some()
            || self.ipv4.is_some()
            || self.gateway.is_some()
            || self.ipv6.is_some()
            || self.gateway6.is_some()
            || !self.join.is_empty()
            || self.announce
            || self.hostname.is_some()
            || !self.ra.is_empty()
            || !self.dhcp_pool.is_empty()
    }

    /// The hosts the command line describes.
    fn spec(&self) -> Result<HostSpec> {
        let mut h = HostConfig::new(0, self.mac.unwrap_or(MacAddr([0x02, 0xdc, 0, 0, 1, 1])));
        h.vlan = self.vlan;
        h.ipv4 = self
            .ipv4
            .as_deref()
            .map(|s| parse_ipv4_mode(s, self.gateway.as_deref()))
            .transpose()?;
        h.ipv6 = self
            .ipv6
            .as_deref()
            .map(|s| parse_ipv6_mode(s, self.gateway6.as_deref()))
            .transpose()?;
        if self.gateway.is_some() && h.ipv4.is_none() {
            bail!("--gateway goes with --ipv4");
        }
        if self.gateway6.is_some() && h.ipv6.is_none() {
            bail!("--gateway6 goes with --ipv6");
        }
        h.groups = self.join.clone();
        if let Some(g) = h.groups.iter().find(|g| !g.is_multicast()) {
            bail!("{g} is not a multicast group");
        }
        let dynamic = matches!(h.ipv4, Some(ferotrx_core::Ipv4Mode::Dhcp))
            || matches!(
                h.ipv6,
                Some(ferotrx_core::Ipv6Mode::Slaac | ferotrx_core::Ipv6Mode::Dhcpv6)
            );
        h.announce = self.announce || dynamic;
        h.hostname = self.hostname.clone();
        if !self.ra.is_empty() {
            let mut r = RouterConfig::new(
                self.ra
                    .iter()
                    .map(|p| parse_prefix6(p))
                    .collect::<ferotrx_core::Result<_>>()?,
            );
            if let Some(i) = self.ra_interval {
                r.interval = i;
            }
            if let Some(l) = self.ra_lifetime {
                r.lifetime = l;
            }
            r.managed = self.ra_managed;
            r.other = self.ra_other;
            h.router = Some(r);
        } else if self.ra_interval.is_some()
            || self.ra_lifetime.is_some()
            || self.ra_managed
            || self.ra_other
        {
            bail!("the --ra-* options go with --ra PREFIX");
        }
        self.dhcp_servers(&mut h)?;
        let mut spec = HostSpec::new(h);
        spec.count = self.count.unwrap_or(1);
        if spec.count == 0 {
            bail!("--count must be at least 1");
        }
        if spec.count > 1 && !self.dhcp_pool.is_empty() {
            bail!("a DHCP server is one host: leave out --count");
        }
        Ok(spec)
    }

    /// The DHCP and DHCPv6 servers of --dhcp-pool.
    fn dhcp_servers(&self, h: &mut HostConfig) -> Result<()> {
        if self.dhcp_pool.is_empty() {
            if self.dhcp_lease.is_some()
                || self.dhcp_router.is_some()
                || !self.dhcp_dns.is_empty()
                || self.dhcp_domain.is_some()
            {
                bail!("the --dhcp-* options go with --dhcp-pool FIRST-LAST");
            }
            return Ok(());
        }
        for pool in &self.dhcp_pool {
            match parse_pool(pool)? {
                (IpAddr::V4(a), IpAddr::V4(b)) => {
                    if h.dhcp_server.is_some() {
                        bail!("give one IPv4 --dhcp-pool");
                    }
                    let mut s = DhcpServerConfig::new(a, b);
                    s.router = self.dhcp_router;
                    s.dns = self
                        .dhcp_dns
                        .iter()
                        .filter_map(|d| match d {
                            IpAddr::V4(d) => Some(*d),
                            IpAddr::V6(_) => None,
                        })
                        .collect();
                    h.dhcp_server = Some(s);
                }
                (IpAddr::V6(a), IpAddr::V6(b)) => {
                    if h.dhcpv6_server.is_some() {
                        bail!("give one IPv6 --dhcp-pool");
                    }
                    let mut s = Dhcpv6ServerConfig::new(a, b);
                    s.dns = self
                        .dhcp_dns
                        .iter()
                        .filter_map(|d| match d {
                            IpAddr::V6(d) => Some(*d),
                            IpAddr::V4(_) => None,
                        })
                        .collect();
                    h.dhcpv6_server = Some(s);
                }
                _ => unreachable!("parse_pool checks the versions"),
            }
        }
        if self.dhcp_router.is_some() && h.dhcp_server.is_none() {
            bail!("--dhcp-router goes with an IPv4 --dhcp-pool");
        }
        if let Some(s) = h.dhcp_server.as_mut() {
            crate::tcp::set(&mut s.lease, self.dhcp_lease);
            s.domain = self.dhcp_domain.clone();
        }
        if let Some(s) = h.dhcpv6_server.as_mut() {
            crate::tcp::set(&mut s.lease, self.dhcp_lease);
            s.domain = self.dhcp_domain.clone();
        }
        Ok(())
    }
}

pub fn cmd_host(args: HostArgs) -> Result<()> {
    let mut profile = match &args.profile {
        Some(path) => {
            if args.any_host_option() {
                bail!("with a profile, describe the hosts in its [[host]] tables");
            }
            HostProfile::from_path(path)
                .with_context(|| format!("cannot read {}", path.display()))?
        }
        None => {
            if !args.any_host_option() {
                bail!("give a host profile, or the hosts' addresses: --ipv4 dhcp, --ipv6 slaac, --join GROUP, --ra PREFIX, --dhcp-pool FIRST-LAST ...");
            }
            HostProfile {
                hosts: vec![args.spec()?],
                ..HostProfile::default()
            }
        }
    };
    let o = &mut profile.options;
    crate::tcp::set(&mut o.setup_timeout, args.setup_timeout);
    crate::tcp::set(&mut o.igmp_version, args.igmp_version);
    crate::tcp::set(&mut o.mld_version, args.mld_version);
    crate::tcp::set(&mut o.start_rate, args.rate);
    if args.no_release {
        o.release = false;
    }
    if args.no_dad {
        o.dad = false;
    }
    if args.broadcast {
        o.broadcast = true;
    }
    if args.duration.is_some() {
        profile.duration = args.duration;
    }
    profile.output = args.send.settings()?.or(&profile.output);
    args.impair.apply(&mut profile.impair);
    if profile.output.workers() > 1 {
        anyhow::bail!("host runs use one worker: leave out --workers (and `workers` in [output])");
    }

    let interfaces = profile.interfaces(args.iface.as_deref())?;
    let configs = profile.configs(&interfaces, args.iface.as_deref())?;
    let mut engine = HostEngine::new(configs, profile.options.clone())?;
    engine.set_until_settled(args.until_ready);
    let mut ports = Vec::with_capacity(interfaces.len());
    for (i, name) in interfaces.iter().enumerate() {
        let settings = ferotrx_io::PortSettings {
            send: profile.output.clone(),
            macs: engine.port_macs(i),
        };
        let port = ferotrx_io::open_port_with(name, &settings)
            .map_err(|e| anyhow::anyhow!("cannot open {name}: {e}"))?;
        let port = profile.impair.wrap(port, i);
        if !args.quiet {
            if let Some(d) = port.describe() {
                eprintln!("port: {d}");
            }
        }
        ports.push(port);
    }
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::Relaxed))
            .context("cannot install Ctrl-C handler")?;
    }
    if !args.quiet {
        eprintln!(
            "{} host(s) on {}{}",
            profile.host_count(),
            interfaces.join(", "),
            match profile.duration {
                Some(d) => format!(" for {d:?}"),
                None if args.until_ready => ", until all are ready".to_string(),
                None => ", until Ctrl-C".to_string(),
            }
        );
    }
    let capture = args
        .capture
        .start((interfaces.len() == 1).then(|| interfaces[0].as_str()))?;
    let job: PortJob<HostStats> = PortJob::spawn(
        engine,
        ports,
        TcpRunConfig {
            duration: profile.duration,
            stop: Some(stop),
            start_at: None,
        },
    )?;
    let mut shown: Vec<HostState> = Vec::new();
    let mut announce = |stats: &HostStats, quiet: bool| {
        shown.resize(stats.hosts.len(), HostState::Starting);
        for (h, was) in stats.hosts.iter().zip(shown.iter_mut()) {
            if h.state != *was {
                *was = h.state;
                if !quiet {
                    eprintln!("{}", host_line(&HostInfo::from(h)));
                }
            }
        }
    };
    while !job.wait(Some(Duration::from_millis(500))) {
        let stats = job.stats();
        announce(&stats, args.quiet);
    }
    let stats = job.join()?;
    if let Some(c) = capture {
        c.finish(args.quiet)?;
    }
    announce(&stats, args.quiet);
    eprintln!(
        "{} in {:.3} s: {} of {} hosts ready, {} failed; {} frames sent, {} taken",
        if stats.stopped { "stopped" } else { "done" },
        stats.elapsed.as_secs_f64(),
        stats.ready(),
        stats.hosts.len(),
        stats.failed(),
        stats.tx_packets,
        stats.rx_packets
    );
    for line in crate::impair_lines(&stats.impair) {
        eprintln!("  {line}");
    }
    print_hosts(&stats.hosts, "  ");
    if stats.failed() > 0 {
        bail!("{} of {} hosts failed", stats.failed(), stats.hosts.len());
    }
    if stats.ready() < stats.hosts.len() {
        bail!(
            "{} of {} hosts did not get their addresses before the run ended",
            stats.hosts.len() - stats.ready(),
            stats.hosts.len()
        );
    }
    Ok(())
}

fn address(kind: &str, a: &HostAddressInfo) -> String {
    let mut s = format!("{kind} {}", a.address);
    if let Some(g) = &a.gateway {
        s.push_str(&format!(" via {g}"));
    }
    s.push_str(&format!(" ({}", a.source));
    if let Some(server) = &a.server {
        s.push_str(&format!(" from {server}"));
    }
    if let Some(l) = a.lease_s {
        s.push_str(&format!(", lease {l:.0} s"));
    }
    if a.renewals > 0 {
        s.push_str(&format!(", renewed {}x", a.renewals));
    }
    if !a.dns.is_empty() {
        s.push_str(&format!(", dns {}", a.dns.join(" ")));
    }
    s.push(')');
    s
}

/// One line for a host: its state, addresses and groups.
pub(crate) fn host_line(h: &HostInfo) -> String {
    let mut line = format!("host {}", h.mac);
    if let Some(v) = h.vlan {
        line.push_str(&format!(" vlan {v}"));
    }
    match (h.state.as_str(), h.ready_after_s) {
        ("ready", Some(t)) => line.push_str(&format!(" ready after {t:.2} s")),
        (s, _) => line.push_str(&format!(" {s}")),
    }
    let mut parts = Vec::new();
    if let Some(a) = &h.ipv4 {
        parts.push(address("ipv4", a));
    }
    if let Some(a) = &h.ipv6 {
        parts.push(address("ipv6", a));
    }
    if let Some(ll) = &h.link_local {
        if h.ipv6.is_none() {
            parts.push(format!("link-local {ll}"));
        }
    }
    for g in &h.groups {
        parts.push(format!(
            "group {} ({} reports, {} frames received)",
            g.group, g.reports, g.rx_packets
        ));
    }
    for (kind, s) in [("dhcp", &h.dhcp_server), ("dhcpv6", &h.dhcpv6_server)] {
        if let Some(s) = s {
            parts.push(server_summary(kind, s));
        }
    }
    if !parts.is_empty() {
        line.push_str(": ");
        line.push_str(&parts.join("; "));
    }
    if let Some(e) = &h.error {
        line.push_str(&format!(": {e}"));
    }
    line
}

/// A DHCP server role in a host's line: pool, leases and counters.
fn server_summary(kind: &str, s: &DhcpServerInfo) -> String {
    let mut t = format!(
        "{kind} server {} ({} of {} leased; {} discovers, {} offers, {} acks, {} naks, {} releases",
        s.pool,
        s.leases.len(),
        s.pool_size,
        s.discovers,
        s.offers,
        s.acks,
        s.naks,
        s.releases
    );
    if s.declines > 0 {
        t.push_str(&format!(", {} declines", s.declines));
    }
    if s.informs > 0 {
        t.push_str(&format!(", {} informs", s.informs));
    }
    if s.exhausted > 0 {
        t.push_str(&format!(", {} unanswered: pool full", s.exhausted));
    }
    t.push(')');
    t
}

/// The leases of a host's DHCP server roles, one line each.
pub(crate) fn lease_lines(h: &HostInfo) -> Vec<String> {
    let mut out = Vec::new();
    for s in [&h.dhcp_server, &h.dhcpv6_server].into_iter().flatten() {
        for l in &s.leases {
            let mut line = format!(
                "lease {} to {}",
                l.address,
                l.mac.as_deref().unwrap_or(&l.client)
            );
            if let Some(n) = &l.hostname {
                line.push_str(&format!(" ({n})"));
            }
            line.push_str(&format!(", {:.0} s left", l.remaining_s));
            out.push(line);
        }
    }
    out
}

/// Prints the emulated hosts of a run, one line each (and their servers' leases).
pub(crate) fn print_hosts(hosts: &[HostStatus], indent: &str) {
    let infos: Vec<HostInfo> = hosts.iter().map(HostInfo::from).collect();
    for h in &infos {
        eprintln!("{indent}{}", host_line(h));
        for l in lease_lines(h) {
            eprintln!("{indent}  {l}");
        }
    }
}

/// Prints the emulated hosts of a run as the control server reports them.
pub(crate) fn print_host_infos(hosts: &[HostInfo], indent: &str) {
    for h in hosts {
        println!("{indent}{}", host_line(h));
        for l in lease_lines(h) {
            println!("{indent}  {l}");
        }
    }
}
