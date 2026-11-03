//! `ferotrx tcp`: stateful TCP replay.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Args;
use ferotrx_core::{
    parse_connect_addr, parse_duration, parse_port_range, Capture, MacAddr, TcpHostSpec,
    TcpProfile, TcpProgram, TcpRole, TcpRunConfig, TcpSource, TcpStats, TcpTemplateSpec,
};
use ferotrx_ctl::protocol::{RunState, TcpCounters, TcpRunInfo, TcpTemplateCounters};

#[derive(Args)]
#[command(args_override_self = true)]
pub struct TcpArgs {
    /// The capture with the TCP session to replay (both directions, ideally).
    /// Not needed with --profile.
    #[arg(required_unless_present = "profile")]
    file: Option<PathBuf>,

    /// A TCP profile (TOML) with the session (or several `[[template]]`s), the
    /// hosts and the rates; the options below replace its values. See
    /// examples/lab-tcp.toml and examples/lab-tcp-mix.toml.
    #[arg(short, long, conflicts_with = "file")]
    profile: Option<PathBuf>,

    /// Which TCP connection of the capture to replay, numbered from 1
    /// (see --list). Default: the first one that carries data.
    #[arg(long, value_name = "N")]
    flow: Option<usize>,

    /// List the TCP connections in the capture and exit.
    #[arg(long)]
    list: bool,

    /// Show what each end will send, and exit.
    #[arg(long)]
    show: bool,

    /// Interface for the client and the server, unless --client-iface or
    /// --server-iface say otherwise.
    #[arg(short, long)]
    iface: Option<String>,

    #[command(flatten)]
    hosts: HostArgs,

    /// Where the client connects, IP:PORT ([IPv6]:PORT), or IP for each template's port.
    /// Default: the server's address and port. Needed when this machine runs
    /// only the client.
    #[arg(long, value_name = "IP[:PORT]", value_parser = parse_connect)]
    connect: Option<SocketAddr>,

    /// Connect to this many consecutive server addresses from --connect's (or
    /// the server's), in turn. Default: --server-ips.
    #[arg(long, value_name = "N")]
    connect_ips: Option<u32>,

    /// New connections per second, all templates together (default 1, or the profile's).
    #[arg(long)]
    cps: Option<f64>,

    /// Connections to open in all; 0 keeps going until Ctrl-C or --duration
    /// (default 1, or the profile's).
    #[arg(short = 'n', long)]
    connections: Option<u64>,

    /// Most connections open at once; 0 is no limit.
    #[arg(long)]
    concurrency: Option<usize>,

    /// Client source ports, LOW-HIGH (default 1024-65534).
    #[arg(long, value_name = "LOW-HIGH")]
    source_ports: Option<String>,

    /// Maximum segment size (default 1460).
    #[arg(long)]
    mss: Option<u16>,

    /// First retransmission timeout, e.g. 250ms (doubles on each retry).
    #[arg(long, value_parser = parse_duration)]
    rto: Option<Duration>,

    /// Do not check the bytes received against the capture.
    #[arg(long)]
    no_verify: bool,

    /// Stop after this long, e.g. 30s or 5m.
    #[arg(short, long, value_parser = parse_duration)]
    duration: Option<Duration>,

    /// Print no progress lines, only the final summary.
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args)]
struct HostArgs {
    /// Run an emulated client at this address, IP[/PREFIX], IPv4 (default
    /// /24) or IPv6 (default /64). It must not be an address of this machine.
    #[arg(long, value_name = "IP[/PREFIX]")]
    client_ip: Option<String>,
    /// Use this many consecutive client addresses in turn.
    #[arg(long, value_name = "N")]
    client_ips: Option<u32>,
    /// The client's gateway (the router).
    #[arg(long, value_name = "IP")]
    client_gw: Option<IpAddr>,
    /// 802.1Q VLAN of the client.
    #[arg(long, value_name = "ID")]
    client_vlan: Option<u16>,
    /// The client's MAC (default: 02:00 and the last four bytes of its address).
    #[arg(long, value_name = "MAC")]
    client_mac: Option<MacAddr>,
    /// Interface of the client (default: --iface).
    #[arg(long, value_name = "IFACE")]
    client_iface: Option<String>,

    /// Run an emulated server at this address, IP[/PREFIX] (default /24 or /64).
    #[arg(long, value_name = "IP[/PREFIX]")]
    server_ip: Option<String>,
    /// The server's gateway. The server answers whoever sent the SYN, so this
    /// only matters for ARP and neighbor discovery.
    #[arg(long, value_name = "IP")]
    server_gw: Option<IpAddr>,
    /// 802.1Q VLAN of the server.
    #[arg(long, value_name = "ID")]
    server_vlan: Option<u16>,
    /// The server's MAC (default: 02:00 and the last four bytes of its address).
    #[arg(long, value_name = "MAC")]
    server_mac: Option<MacAddr>,
    /// Interface of the server (default: --iface).
    #[arg(long, value_name = "IFACE")]
    server_iface: Option<String>,
    /// Port the server listens on (default: the server port in the capture).
    /// Only with one template; templates in a profile each have a `port`.
    #[arg(long, value_name = "PORT")]
    server_port: Option<u16>,
    /// The server owns this many consecutive addresses from --server-ip;
    /// clients connect to each in turn.
    #[arg(long, value_name = "N")]
    server_ips: Option<u32>,
}

fn parse_connect(s: &str) -> std::result::Result<SocketAddr, String> {
    parse_connect_addr(s).map_err(|e| e.to_string())
}

impl HostArgs {
    fn any_client(&self) -> bool {
        self.client_ips.is_some()
            || self.client_gw.is_some()
            || self.client_vlan.is_some()
            || self.client_mac.is_some()
            || self.client_iface.is_some()
    }

    fn any_server(&self) -> bool {
        self.server_gw.is_some()
            || self.server_vlan.is_some()
            || self.server_mac.is_some()
            || self.server_iface.is_some()
            || self.server_port.is_some()
            || self.server_ips.is_some()
    }

    /// Applies the client and server options to the profile's hosts, creating
    /// a host when its address is given.
    fn apply(&self, p: &mut TcpProfile) -> Result<()> {
        if let Some(ip) = &self.client_ip {
            let h = TcpHostSpec::new(ip)?;
            let old = p.client.take();
            p.client = Some(merge(old, h));
        }
        if let Some(c) = p.client.as_mut() {
            set(&mut c.ips, self.client_ips);
            opt(&mut c.gateway, self.client_gw);
            opt(&mut c.vlan, self.client_vlan);
            opt(&mut c.mac, self.client_mac);
            opt(&mut c.iface, self.client_iface.clone());
        } else if self.any_client() {
            bail!("client options need --client-ip (or a [client] table in the profile)");
        }
        if let Some(ip) = &self.server_ip {
            let h = TcpHostSpec::new(ip)?;
            let old = p.server.take();
            p.server = Some(merge(old, h));
        }
        if let Some(s) = p.server.as_mut() {
            opt(&mut s.gateway, self.server_gw);
            opt(&mut s.vlan, self.server_vlan);
            opt(&mut s.mac, self.server_mac);
            opt(&mut s.iface, self.server_iface.clone());
            opt(&mut s.port, self.server_port);
            set(&mut s.ips, self.server_ips);
        } else if self.any_server() {
            bail!("server options need --server-ip (or a [server] table in the profile)");
        }
        Ok(())
    }
}

/// A host from the command line keeps the profile's other settings.
fn merge(old: Option<TcpHostSpec>, new: TcpHostSpec) -> TcpHostSpec {
    match old {
        Some(o) => TcpHostSpec {
            ip: new.ip,
            prefix: new.prefix,
            ..o
        },
        None => new,
    }
}

fn set<T>(slot: &mut T, v: Option<T>) {
    if let Some(v) = v {
        *slot = v;
    }
}

fn opt<T>(slot: &mut Option<T>, v: Option<T>) {
    if v.is_some() {
        *slot = v;
    }
}

fn flows(file: &PathBuf) -> Result<()> {
    let cap =
        Capture::from_path(file).with_context(|| format!("cannot read {}", file.display()))?;
    let flows = TcpProgram::flows(&cap)?;
    if flows.is_empty() {
        println!("no TCP connections in {}", file.display());
    }
    for (i, f) in flows.iter().enumerate() {
        println!("{:>4}  {f}", i + 1);
    }
    Ok(())
}

fn show(program: &TcpProgram) {
    println!("{program}");
    for (i, m) in program.messages.iter().enumerate() {
        let arrow = match m.from {
            TcpRole::Client => "client ->",
            TcpRole::Server => "<- server",
        };
        let text: String = String::from_utf8_lossy(&m.data[..m.data.len().min(60)])
            .chars()
            .map(|c| if c.is_control() { '.' } else { c })
            .collect();
        println!("{:>4}  {arrow} {:>7} bytes  {text}", i + 1, m.data.len());
    }
    println!("      then the {} closes", program.closer);
}

pub fn cmd_tcp(args: TcpArgs) -> Result<()> {
    if args.list {
        let Some(file) = &args.file else {
            bail!("--list needs a capture file");
        };
        return flows(file);
    }
    let mut profile = match (&args.profile, &args.file) {
        (Some(path), _) => TcpProfile::from_path(path)
            .with_context(|| format!("cannot read {}", path.display()))?,
        (None, Some(file)) => TcpProfile {
            templates: vec![TcpTemplateSpec::new(TcpSource::Pcap {
                path: file.clone(),
                flow: None,
            })],
            ..Default::default()
        },
        (None, None) => bail!("give a capture file or --profile"),
    };
    if let Some(n) = args.flow {
        if n == 0 {
            bail!("flows are numbered from 1");
        }
        let [t] = profile.templates.as_mut_slice() else {
            bail!("--flow needs a single session; set `flow` in each [[template]] instead");
        };
        match &mut t.source {
            TcpSource::Pcap { flow, .. } => *flow = Some(n - 1),
            TcpSource::Program(_) => bail!("--flow needs a capture, not [[message]] tables"),
        }
    }
    args.hosts.apply(&mut profile)?;
    set(&mut profile.cps, args.cps);
    set(&mut profile.connections, args.connections);
    set(&mut profile.concurrency, args.concurrency);
    opt(&mut profile.connect, args.connect);
    opt(&mut profile.connect_ips, args.connect_ips);
    if profile.templates.len() > 1 && args.hosts.server_port.is_some() {
        bail!("--server-port needs a single session; set `port` in each [[template]] instead");
    }
    if let Some(r) = &args.source_ports {
        profile.source_ports = parse_port_range(r)?;
    }
    set(&mut profile.options.mss, args.mss);
    set(&mut profile.options.rto, args.rto);
    if args.no_verify {
        profile.options.verify = false;
    }
    if args.duration.is_some() {
        profile.duration = args.duration;
    }

    if args.show {
        let many = profile.templates.len() > 1;
        for (i, t) in profile.templates.iter().enumerate() {
            if many {
                println!("template {} (weight {}):", t.name(i), t.weight);
            }
            show(&t.program()?);
        }
        return Ok(());
    }
    if profile.client.is_none() && profile.server.is_none() {
        bail!("give --client-ip, --server-ip or both (or a profile with [client] and [server])");
    }

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::Relaxed))
            .context("cannot install Ctrl-C handler")?;
    }
    let started = ferotrx_ctl::start_tcp(
        &profile,
        args.iface.as_deref(),
        TcpRunConfig {
            duration: profile.duration,
            stop: Some(stop),
        },
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    if !args.quiet {
        if profile.templates.len() > 1 {
            for (i, t) in profile.templates.iter().enumerate() {
                eprintln!("template {} (weight {})", t.name(i), t.weight);
            }
        }
        eprintln!("session: {}", started.program);
        for (what, h) in [("client", &profile.client), ("server", &profile.server)] {
            if let Some(h) = h {
                let mut line = format!(
                    "{what}: {}/{} mac {} on {}",
                    h.ip,
                    h.prefix,
                    h.mac(),
                    h.iface.as_deref().or(args.iface.as_deref()).unwrap_or("?")
                );
                if h.ips > 1 {
                    let last = h.last_ip();
                    line.push_str(&format!(" ({} addresses, to {last})", h.ips));
                }
                if let Some(v) = h.vlan {
                    line.push_str(&format!(", vlan {v}"));
                }
                if let Some(g) = h.gateway {
                    line.push_str(&format!(", gateway {g}"));
                }
                eprintln!("{line}");
            }
        }
        if profile.client.is_some() {
            let n = if profile.connections == 0 {
                "until stopped".to_string()
            } else {
                format!("{} connections", profile.connections)
            };
            eprintln!("opening {n} at {} per second", profile.cps);
        } else {
            eprintln!("server only: waiting for connections until Ctrl-C or --duration");
        }
    }
    let job = started.job;
    while !job.wait(Some(Duration::from_secs(1))) {
        if !args.quiet {
            eprintln!("{}", progress_line(&job.stats()));
        }
    }
    let stats = job.join()?;
    print_summary(&stats);
    let failed = stats.client.failed() + stats.server.failed();
    let mismatched = stats.client.mismatched + stats.server.mismatched;
    if failed + mismatched > 0 {
        bail!("{failed} connections failed, {mismatched} carried other bytes than the capture");
    }
    Ok(())
}

fn progress_line(s: &TcpStats) -> String {
    format!(
        "progress: client {} started, {} done, {} open, {} failed; server {} done, {} open; {:.1} cps, {} frames out, {} in",
        s.client.started,
        s.client.completed,
        s.client.active,
        s.client.failed(),
        s.server.completed,
        s.server.active,
        s.cps(),
        s.tx_packets,
        s.rx_packets
    )
}

fn print_summary(s: &TcpStats) {
    eprintln!(
        "{} in {:.3} s: {} frames ({} bytes) sent, {} ({} bytes) received",
        if s.stopped { "stopped" } else { "done" },
        s.elapsed.as_secs_f64(),
        s.tx_packets,
        s.tx_bytes,
        s.rx_packets,
        s.rx_bytes
    );
    for (what, side) in [("client", &s.client), ("server", &s.server)] {
        if side.started == 0 && side.payload_rx == 0 {
            continue;
        }
        eprintln!("  {what}: {}", side_line(&side.into()));
    }
    if s.templates.len() > 1 {
        for t in &s.templates {
            let t = TcpTemplateCounters {
                name: t.name.clone(),
                client: (&t.client).into(),
                server: (&t.server).into(),
            };
            for line in template_lines(&t) {
                eprintln!("{line}");
            }
        }
    }
    if s.client.completed > 0 {
        eprintln!("  {:.1} connections per second", s.cps());
    }
}

/// A template's counters, one line per side that did anything.
fn template_lines(t: &TcpTemplateCounters) -> Vec<String> {
    [("client", &t.client), ("server", &t.server)]
        .into_iter()
        .filter(|(_, c)| c.started > 0 || c.payload_rx > 0)
        .map(|(what, c)| format!("    {} {what}: {}", t.name, side_line(c)))
        .collect()
}

fn side_line(c: &TcpCounters) -> String {
    let mut line = format!(
        "{} connections, {} established, {} completed",
        c.started, c.established, c.completed
    );
    if c.active > 0 {
        line.push_str(&format!(", {} open", c.active));
    }
    for (n, what) in [
        (c.reset, "reset"),
        (c.timed_out, "timed out"),
        (c.mismatched, "with other bytes than the capture"),
    ] {
        if n > 0 {
            line.push_str(&format!(", {n} {what}"));
        }
    }
    line.push_str(&format!(
        "; {} bytes sent, {} received, {} retransmits",
        c.payload_tx, c.payload_rx, c.retransmits
    ));
    line
}

/// Prints a TCP run as the control server reports it.
pub fn print_tcp_run(r: &TcpRunInfo) {
    let state = match r.state {
        RunState::Running => "running",
        RunState::Finished => "finished",
        RunState::Stopped => "stopped",
        RunState::Failed => "failed",
    };
    println!(
        "tcp run {} on {}: {state}, {:.3} s, {:.1} cps",
        r.id,
        r.interfaces.join(", "),
        r.elapsed_s,
        r.cps
    );
    println!("  session: {}", r.program);
    if let Some(e) = &r.error {
        println!("  error: {e}");
    }
    for (what, c) in [("client", &r.client), ("server", &r.server)] {
        if c.started > 0 || c.payload_rx > 0 {
            println!("  {what}: {}", side_line(c));
        }
    }
    if r.templates.len() > 1 {
        for t in &r.templates {
            for line in template_lines(t) {
                println!("{line}");
            }
        }
    }
    println!(
        "  frames: {} sent ({} bytes), {} received ({} bytes)",
        r.tx_packets, r.tx_bytes, r.rx_packets, r.rx_bytes
    );
}
