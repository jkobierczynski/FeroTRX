mod bench;
mod capture;
mod check;
mod fleet;
mod host;
mod impair;
mod lab;
mod latency;
mod remote;
mod scenario;
#[cfg(windows)]
mod service;
mod tcp;
mod udp;
mod y1564;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use ferotrx_core::{
    parse_duration, Backend, Capture, CaptureSource, FieldEngine, FieldVar, ImpairSpec, Job, Pacer,
    PacketSink, Profile, Rate, ReplayStats, Rewrite, RunConfig, RunStats, SendSettings, SizeMix,
    Stream, TrafficModel, Transform, XdpMode, LINKTYPE_ETHERNET,
};

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
    /// Build packets from a description of their layers; show, save or send them.
    Build(BuildArgs),
    /// Capture on an interface with a BPF filter: show the frames decoded,
    /// or write them as pcap to a file, a ring of files, or standard output
    /// for Wireshark (`ferotrx capture -i eth0 -w - | wireshark -k -i -`).
    Capture(capture::CaptureArgs),
    /// Stateful TCP: replay a TCP session from a capture as real connections,
    /// playing the client, the server or both (handshakes, sequence and
    /// acknowledgement tracking, retransmits), e.g. through a NAT router.
    Tcp(tcp::TcpArgs),
    /// Stateful UDP: request/response transactions between emulated clients
    /// and servers, with matching, timeouts and retries: DNS lookups, NTP,
    /// or UDP sessions replayed from a capture.
    Udp(udp::UdpArgs),
    /// Host emulation: emulated hosts that get their addresses by DHCP,
    /// SLAAC or DHCPv6, announce them, join multicast groups (IGMP, MLD),
    /// answer ARP and pings, and can advertise IPv6 prefixes as routers.
    Host(host::HostArgs),
    /// Receive on an interface (or read a capture) and report loss and
    /// latency of the flows with FeroTRX signatures, sent by `--latency` or
    /// `--rx` on another machine.
    Rx(latency::RxCmdArgs),
    /// Benchmark a device the RFC 2544 way: throughput (binary search on the
    /// rate), latency, frame loss and back-to-back bursts, for a list of frame
    /// sizes or mixes such as IMIX; writes a JSON and a text report.
    Bench(bench::BenchArgs),
    /// Test services the Y.1564 way: per service, steps up to the CIR, CIR +
    /// EIR and a policing step; then all services at their CIR for a long
    /// time, with loss, delay, delay variation and availability against
    /// each service's acceptance criteria. Exits with an error if a step fails.
    Y1564(y1564::Y1564Args),
    /// Regression tests: run a scenario file's checks (TCP, UDP, streams
    /// with a receiver) against expected outcomes, write JSON and JUnit
    /// reports, keep a history and compare runs.
    Scenario(scenario::ScenarioArgs),
    /// Runs on several agents (`ferotrx serve` on other machines) at once:
    /// deploys the profiles and their pcaps, starts every run at one
    /// instant, adds up the counters and judges the plan's conditions.
    Fleet(fleet::FleetArgs),
    /// Check profile and scenario files without sending anything: reads the
    /// captures, builds the packets and sets the engines up as a run would,
    /// and prints a summary and warnings. Exits with 1 if any file has errors.
    Check(check::CheckArgs),
    /// A bridge between two interfaces that impairs what it passes on, as a
    /// bad link or WAN would, without netem: delay and jitter, random or
    /// bursty loss, duplicates, reordering, corruption, a rate limit and an
    /// MTU, each way on its own.
    Impair(impair::ImpairArgs),
    /// Show what a capture contains.
    Info {
        /// The pcap or pcapng file.
        file: PathBuf,
    },
    /// List the interfaces packets can be sent on.
    #[cfg(feature = "pcap")]
    Interfaces,
    /// List the ways this build can send on interfaces (pcap, af_xdp, dpdk).
    Backends,
    /// Run a control server: other programs load profiles, start and stop runs
    /// and read live counters over JSON-RPC (see `ferotrx ctl`).
    Serve(remote::ServeArgs),
    /// Control a `ferotrx serve` server, on this machine or another one.
    Ctl(remote::CtlArgs),
    /// Make TLS certificates for `ferotrx serve` and `ferotrx ctl`: a small
    /// lab certificate authority, a server certificate and client certificates.
    Certs(remote::CertsArgs),
    /// The control server as a Windows service: install, remove, start,
    /// stop, status. Runs at boot as LocalSystem, without anyone logged in.
    #[cfg(windows)]
    Service(service::ServiceArgs),
    /// Build a lab router on this machine (Linux, root): a network namespace
    /// that routes and masquerades between VLAN 10 (clients, 192.168.10.0/24)
    /// and VLAN 20 (servers, 192.168.20.0/24), reached on the link ftrx-lab.
    /// The examples/lab-*.toml profiles run through it as they are.
    Lab(lab::LabArgs),
}

#[derive(Args)]
struct ReplayArgs {
    /// The pcap or pcapng file to replay.
    file: PathBuf,

    #[command(flatten)]
    output: Output,

    #[command(flatten)]
    send: SendArgs,

    #[command(flatten)]
    rate: RateArgs,

    /// Traffic model: how packets spread around the rate (needs --pps or
    /// --mbps). Comma separated: poisson (exponential gaps), burst=N (N
    /// packets back to back, same mean rate), ramp_up=10s,hold=1m,ramp_down=10s
    /// (then stop), at=TIME:RATE points such as at=0s:10%,at=30s:100%, seed=N.
    #[arg(long, value_name = "MODEL")]
    model: Option<TrafficModel>,

    /// Times to play the capture; 0 loops until Ctrl-C.
    #[arg(short = 'l', long = "loop", default_value_t = 1)]
    loops: u64,

    /// Rewrite packets before sending; repeat to chain. Examples:
    /// mac_dst=02:00:00:00:00:01, ip_dst=10.0.0.0/8->192.168.20.0,
    /// port_dst=53->5353, vlan_push=20[:PCP], qinq_push=100, vlan_set=30,
    /// vlan_pop, fix_checksums. `_src`/`_dst` can be left off to change both.
    #[arg(short, long = "rewrite", value_name = "SPEC")]
    rewrites: Vec<Rewrite>,

    /// Change a field from packet to packet (field engine); repeat for more
    /// fields. FIELD=MIN..MAX[,inc|dec|random][,step=N][,every=N][,seed=N], e.g.
    /// ip_src=10.0.0.1..10.0.0.254, ip_dst=192.168.20.0/24,random,
    /// port_src=1024..65535, vlan=10..20, mac_src+=0..99, payload@0:4=0..1000,
    /// len=64..1518,random. Fields: mac_src/dst, ip_src/dst, port_src/dst, vlan,
    /// ip_id, ttl, payload@OFFSET[:SIZE], len. Runs after the rewrites.
    #[arg(long = "vary", value_name = "SPEC")]
    vary: Vec<FieldVar>,

    /// Cut or pad every packet to the next size of a mix, after the rewrites
    /// and --vary: imix (60:7,590:4,1514:1), rfc2544, SIZE:WEIGHT,... or
    /// SIZE,SIZE,...; add ,random for random order. Sizes are without FCS.
    /// With latency signatures the frames keep these sizes.
    #[arg(long, value_name = "MIX")]
    sizes: Option<SizeMix>,

    /// Impair the packets on their way out, as a bad link would, without
    /// netem: space or comma separated KEY=VALUE, e.g. 'delay=20ms jitter=5ms
    /// loss=1% loss_burst=3 duplicate=0.1% reorder=0.5% corrupt=0.01%
    /// rate=10mbit mtu=1400 seed=1'. See docs/impairments.md.
    #[arg(long, value_name = "SPEC")]
    impair: Option<ImpairSpec>,

    #[command(flatten)]
    rx: latency::RxArgs,

    #[command(flatten)]
    common: CommonArgs,

    #[command(flatten)]
    capture: capture::RunCaptureArgs,
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

    /// Only packets a BPF filter takes, as tcpdump and Wireshark's capture
    /// filters ('udp port 53', 'host 10.0.0.1'); numbers stay those of the file.
    #[arg(short, long, value_name = "BPF")]
    filter: Option<String>,

    /// Apply rewrites before decoding, to preview what `replay -r` would send.
    #[arg(short, long = "rewrite", value_name = "SPEC")]
    rewrites: Vec<Rewrite>,

    /// Apply field engine variables before decoding, to preview what
    /// `replay --vary` would send (see `ferotrx replay --help`).
    #[arg(long = "vary", value_name = "SPEC")]
    vary: Vec<FieldVar>,
}

#[derive(Args)]
struct BuildArgs {
    /// Packets to build, one argument each, layers joined by '/'. Example:
    /// 'eth(dst=02:00:00:00:00:01)/vlan(id=10)/ipv4(src=192.168.10.100,dst=192.168.20.50)/udp/dns(q=example.com)'.
    /// Layers: eth, vlan, qinq, arp, ipv4, ipv6 (and its hbh, dstopt, frag), tcp, udp, icmp, dns, raw.
    /// Lengths and checksums are filled in unless set.
    #[arg(value_name = "PACKET")]
    specs: Vec<String>,

    /// Read packets from a file, one per line; '#' starts a comment and a line
    /// ending in '/' continues on the next one.
    #[arg(short, long, value_name = "FILE")]
    file: Option<PathBuf>,

    /// Time between packets on the built timeline; with --loop, between the
    /// last packet and the first one again. Sets the send rate when no rate is given.
    #[arg(long, default_value = "1s", value_parser = parse_duration)]
    interval: Duration,

    /// Write the built packets to this pcap file.
    #[arg(short, long)]
    out: Option<PathBuf>,

    /// Send the built packets on this network interface (see `ferotrx interfaces`).
    #[arg(short, long)]
    iface: Option<String>,

    #[command(flatten)]
    send: SendArgs,

    #[command(flatten)]
    rate: RateArgs,

    /// Times to send the packets; 0 loops until Ctrl-C. Only with --iface.
    #[arg(short = 'l', long = "loop", default_value_t = 1)]
    loops: u64,

    /// Show the decoded layers of every packet.
    #[arg(short, long)]
    verbose: bool,

    /// Add a hex dump of every packet.
    #[arg(long)]
    hex: bool,

    /// Change fields from packet to packet (see `ferotrx replay --help`), e.g.
    /// --vary ip_src=10.0.0.1..10.0.0.100 --count 100. When sending, the values
    /// keep moving from loop to loop.
    #[arg(long = "vary", value_name = "SPEC")]
    vary: Vec<FieldVar>,

    /// Make this many packets, going round the given ones (default: one each).
    /// Shown and written packets get the --vary values in turn.
    #[arg(short = 'n', long, value_name = "N")]
    count: Option<usize>,

    /// Traffic model when sending (see `ferotrx replay --help`): how packets spread around the rate, e.g.
    /// --pps 1000 --model poisson.
    #[arg(long, value_name = "MODEL")]
    model: Option<TrafficModel>,

    /// Cut or pad the packets to the sizes of a mix, in turn (see `ferotrx
    /// replay --help`), e.g. --sizes imix -n 12.
    #[arg(long, value_name = "MIX")]
    sizes: Option<SizeMix>,

    /// Loss and latency, when sending with --iface.
    #[command(flatten)]
    rx: latency::RxArgs,

    #[command(flatten)]
    common: CommonArgs,
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
    send: SendArgs,

    /// Traffic model for every stream instead of the profile's (see
    /// `ferotrx replay --help`); the streams need pps or mbps rates.
    #[arg(long, value_name = "MODEL")]
    model: Option<TrafficModel>,

    /// Impairments for every stream instead of the profile's (see
    /// `ferotrx replay --help`); `none` turns the profile's off.
    #[arg(long, value_name = "SPEC")]
    impair: Option<ImpairSpec>,

    #[command(flatten)]
    rx: latency::RxArgs,

    #[command(flatten)]
    common: CommonArgs,

    #[command(flatten)]
    capture: capture::RunCaptureArgs,
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
    /// Send on this network interface (see `ferotrx interfaces`). With
    /// `--backend dpdk`, a DPDK device: a PCI address, a virtual device such as
    /// `net_af_packet0,iface=eth0`, or a port number.
    #[arg(short, long)]
    iface: Option<String>,

    /// Write the packets to this pcap file, stamped with their send time.
    #[arg(short, long)]
    out: Option<PathBuf>,

    /// Discard packets; measures the engine's own speed.
    #[arg(long)]
    null: bool,
}

/// Impairments of a TCP, UDP or host run's ports, over the profile's
/// `impair` and `impair_rx`.
#[derive(Args, Clone, Default)]
pub struct PortImpairArgs {
    /// Impair the frames this run sends, as a bad link would, without netem:
    /// KEY=VALUE pairs such as 'delay=20ms jitter=5ms loss=1% loss_burst=3
    /// duplicate=0.1% reorder=0.5% corrupt=0.01% rate=10mbit mtu=1400 seed=1'
    /// (see docs/impairments.md); `none` turns the profile's off.
    #[arg(long, value_name = "SPEC")]
    pub impair: Option<ImpairSpec>,

    /// Impair the frames this run receives, before the engine sees them.
    #[arg(long, value_name = "SPEC")]
    pub impair_rx: Option<ImpairSpec>,
}

impl PortImpairArgs {
    /// The profile's impairments with the command line's over them.
    pub fn apply(&self, profile: &mut ferotrx_core::PortImpair) {
        if let Some(s) = &self.impair {
            profile.tx = (!s.is_none()).then(|| s.clone());
        }
        if let Some(s) = &self.impair_rx {
            profile.rx = (!s.is_none()).then(|| s.clone());
        }
    }
}

/// What an impairment did, from the control API's counters, on one line
/// as [`ImpairStats`](ferotrx_core::ImpairStats) prints it.
pub fn impair_counters_line(c: &ferotrx_ctl::protocol::ImpairCounters) -> String {
    let mut line = format!("{} in, {} out", c.packets, c.passed);
    for (n, what) in [
        (c.lost, "lost"),
        (c.mtu_dropped, "over the MTU"),
        (c.truncated, "cut to the MTU"),
        (c.queue_dropped, "over the queue limit"),
        (c.duplicated, "duplicated"),
        (c.reordered, "reordered"),
        (c.corrupted, "corrupted"),
        (c.held, "still held"),
    ] {
        if n > 0 {
            line.push_str(&format!(", {n} {what}"));
        }
    }
    if let Some(d) = &c.delay {
        if let (Some(avg), Some(max)) = (d.avg_us, d.max_us) {
            line.push_str(&format!(
                ", held ms avg {:.2} max {:.2}",
                avg / 1000.0,
                max / 1000.0
            ));
        }
    }
    line
}

/// Lines for a TCP or UDP run's port impairments, from the control API.
pub fn port_impair_lines(c: &Option<ferotrx_ctl::protocol::PortImpairCounters>) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(c) = c {
        if let Some(tx) = &c.tx {
            lines.push(format!(
                "impaired sent frames: {}",
                impair_counters_line(tx)
            ));
        }
        if let Some(rx) = &c.rx {
            lines.push(format!(
                "impaired received frames: {}",
                impair_counters_line(rx)
            ));
        }
    }
    lines
}

/// One line of what a run's port impairments did, if they did anything.
pub fn impair_lines(stats: &ferotrx_core::PortImpairStats) -> Vec<String> {
    let mut lines = Vec::new();
    if !stats.tx.is_empty() {
        lines.push(format!("impaired sent frames: {}", stats.tx));
    }
    if !stats.rx.is_empty() {
        lines.push(format!("impaired received frames: {}", stats.rx));
    }
    lines
}

/// How to send on `--iface`. Values left out come from the profile's
/// `[output]` table, then the defaults.
#[derive(Args, Clone, Default)]
pub struct SendArgs {
    /// Sender for --iface: pcap (libpcap/Npcap, the default), af_xdp (Linux)
    /// or dpdk (builds with the `dpdk` feature). `ferotrx backends` lists what this build has.
    #[arg(short = 'B', long, value_name = "NAME")]
    pub backend: Option<Backend>,

    /// Transmit queue of the interface (af_xdp, dpdk; default 0).
    #[arg(long)]
    pub queue: Option<u16>,

    /// AF_XDP mode: auto (default; zero-copy if the driver can), copy (also
    /// called skb or generic; works on every interface, VMs included) or zerocopy.
    #[arg(long, value_name = "MODE")]
    pub xdp_mode: Option<XdpMode>,

    /// Packets handed to the kernel or NIC at once (af_xdp, dpdk, and pcap on
    /// Windows through Npcap's send queue; default 64; 1 sends each packet on
    /// its own). Paced packets are never held back to fill a batch.
    #[arg(long)]
    pub batch: Option<u32>,

    /// DPDK EAL arguments as one string, e.g. '-l 0-1 --no-huge -m 512'.
    #[arg(long, value_name = "ARGS", allow_hyphen_values = true)]
    pub dpdk_args: Option<String>,

    /// Spread the run over this many engine threads (cores; default 1).
    /// Streams are split packet by packet, TCP and UDP runs by flow; with
    /// af_xdp each worker sends on its own queue from --queue up.
    #[arg(long)]
    pub workers: Option<u16>,
}

impl SendArgs {
    pub fn settings(&self) -> Result<SendSettings> {
        let s = SendSettings {
            backend: self.backend,
            queue: self.queue,
            xdp_mode: self.xdp_mode,
            batch: self.batch,
            dpdk_args: self
                .dpdk_args
                .as_deref()
                .map(|a| a.split_whitespace().map(String::from).collect()),
            workers: self.workers,
        };
        s.validate()?;
        Ok(s)
    }
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
    fn is_set(&self) -> bool {
        self.multiplier.is_some() || self.pps.is_some() || self.mbps.is_some() || self.topspeed
    }

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
        Command::Build(args) => cmd_build(args),
        Command::Capture(args) => capture::cmd_capture(args),
        Command::Tcp(args) => tcp::cmd_tcp(args),
        Command::Udp(args) => udp::cmd_udp(args),
        Command::Host(args) => host::cmd_host(args),
        Command::Rx(args) => latency::cmd_rx(args),
        Command::Bench(args) => bench::cmd_bench(args),
        Command::Y1564(args) => y1564::cmd_y1564(args),
        Command::Scenario(args) => scenario::cmd_scenario(args),
        Command::Fleet(args) => fleet::cmd_fleet(args),
        Command::Check(args) => check::cmd_check(args),
        Command::Impair(args) => impair::cmd_impair(args),
        #[cfg(feature = "pcap")]
        Command::Interfaces => cmd_interfaces(),
        Command::Backends => cmd_backends(),
        Command::Serve(args) => remote::cmd_serve(args),
        Command::Ctl(args) => remote::cmd_ctl(args),
        Command::Certs(args) => remote::cmd_certs(args),
        #[cfg(windows)]
        Command::Service(args) => service::cmd_service(args),
        Command::Lab(args) => lab::cmd_lab(args),
    }
}

/// The traffic model of `--model`, checked against the rate.
fn model(rate: Rate, model: &Option<TrafficModel>) -> Result<TrafficModel> {
    let model = model.clone().unwrap_or_default();
    Pacer::check_model(rate, &model)?;
    Ok(model)
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
    if !args.rewrites.is_empty() || !args.vary.is_empty() {
        if cap.linktype != LINKTYPE_ETHERNET {
            bail!(
                "rewrites and vary need Ethernet frames, capture has link type {}",
                cap.linktype
            );
        }
        let mut rewrites = args.rewrites.clone();
        let mut engine = FieldEngine::new(args.vary.iter().cloned());
        for p in &mut cap.packets {
            for r in &mut rewrites {
                r.apply(p);
            }
            engine.apply(p);
        }
    }
    let first_ts = cap.packets.first().map_or(Duration::ZERO, |p| p.timestamp);
    let chosen = |n: usize| args.packets.iter().any(|r| (r.0..=r.1).contains(&n));
    let taken = filter_packets(&cap, args.filter.as_deref())?;
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
    let mut matched = 0usize;
    for (i, p) in cap.packets.iter().enumerate() {
        let n = i + 1;
        if !taken[i] {
            continue;
        }
        matched += 1;
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
    let of = match &args.filter {
        Some(f) => format!(" of {} matched '{f}'", cap.len()),
        None => String::new(),
    };
    eprintln!(
        "{matched} packets{of} ({}), {with_problems} with problems",
        list.join(", ")
    );
    Ok(())
}

/// Which packets of a capture a BPF filter takes (all without one).
fn filter_packets(cap: &Capture, filter: Option<&str>) -> Result<Vec<bool>> {
    let Some(expr) = filter.filter(|f| !f.trim().is_empty()) else {
        return Ok(vec![true; cap.len()]);
    };
    #[cfg(feature = "pcap")]
    {
        let f =
            ferotrx_io::FrameFilter::new(cap.linktype, expr).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(cap.packets.iter().map(|p| f.matches(&p.data)).collect())
    }
    #[cfg(not(feature = "pcap"))]
    bail!("filter '{expr}': this build has no libpcap/Npcap support (feature `pcap`)")
}

/// Reads packet descriptions from a file: one per line, '#' comments, and a
/// line ending in '/' continued on the next.
fn read_specs(path: &PathBuf) -> Result<Vec<String>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let mut specs = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        let line = match line.find('#') {
            // Keep a '#' inside a quoted value.
            Some(i) if line[..i].matches('"').count() % 2 == 0 => &line[..i],
            _ => line,
        }
        .trim();
        if line.is_empty() {
            continue;
        }
        current.push_str(line);
        if !line.ends_with('/') {
            specs.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        bail!("{}: the last packet ends with '/'", path.display());
    }
    Ok(specs)
}

fn cmd_build(args: BuildArgs) -> Result<()> {
    let mut specs = args.specs.clone();
    if let Some(f) = &args.file {
        specs.extend(read_specs(f)?);
    }
    if specs.is_empty() {
        bail!("give a packet to build, e.g. 'eth/ipv4(dst=10.0.0.2)/icmp', or --file");
    }
    let mut cap = Capture::from_specs(&specs, args.interval)?;
    if let Some(n) = args.count {
        if n == 0 {
            bail!("--count must be at least 1");
        }
        let built = cap.packets.clone();
        cap.packets = (0..n)
            .map(|i| {
                let mut p = built[i % built.len()].clone();
                p.timestamp = args
                    .interval
                    .saturating_mul(u32::try_from(i).unwrap_or(u32::MAX));
                p
            })
            .collect();
    }
    if (!args.vary.is_empty() || args.sizes.is_some()) && cap.linktype != LINKTYPE_ETHERNET {
        bail!("vary and sizes need Ethernet frames; start the packets with eth, not ipv4 or ipv6");
    }
    // What is shown and written: the packets with the field engine and sizes applied.
    let mut shown = cap.clone();
    let mut engine = FieldEngine::new(args.vary.iter().cloned());
    let mut sizes = args.sizes.clone();
    for p in &mut shown.packets {
        engine.apply(p);
        if let Some(s) = &mut sizes {
            s.apply(p);
        }
    }

    let sending = args.iface.is_some();
    if !(sending && args.common.quiet) {
        for (i, p) in shown.packets.iter().enumerate() {
            let d = ferotrx_packet::decode(shown.linktype, &p.data);
            println!(
                "{:>4}  {:<24}  {:<24}  {:<8}  {:>5}  {}{}",
                i + 1,
                d.source,
                d.destination,
                d.protocol,
                d.len,
                d.info,
                if d.problems.is_empty() { "" } else { " [!]" }
            );
            if !args.verbose {
                for problem in &d.problems {
                    println!("      !! {problem}");
                }
            }
            if args.verbose {
                for line in d.tree().lines() {
                    println!("      {line}");
                }
            }
            if args.hex {
                for line in ferotrx_packet::hex_dump(&p.data).lines() {
                    println!("      {line}");
                }
            }
            if args.verbose || args.hex {
                println!();
            }
        }
    }

    if let Some(out) = &args.out {
        // Stamp the packets from now, so capture viewers show a sensible date.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let mut stamped = shown.clone();
        for p in &mut stamped.packets {
            p.timestamp += now;
        }
        stamped
            .save(out)
            .with_context(|| format!("cannot write {}", out.display()))?;
        eprintln!("wrote {} packets to {}", cap.len(), out.display());
    }

    if let Some(iface) = &args.iface {
        let rate = args.rate.rate();
        rate.validate()?;
        let period = args
            .interval
            .saturating_mul(u32::try_from(cap.len()).unwrap_or(u32::MAX));
        let linktype = cap.linktype;
        let cap = Arc::new(cap);
        let traffic = model(rate, &args.model)?;
        let make = || {
            let mut stream = Stream::new(
                "built",
                CaptureSource::new(cap.clone())
                    .loops(args.loops)
                    .loop_period(period),
            )
            .with_rate(rate)
            .with_model(traffic.clone());
            if !args.vary.is_empty() {
                // A fresh engine, so the first loop sends what was shown above.
                stream.push_transform(FieldEngine::new(args.vary.iter().cloned()));
            }
            if let Some(mut s) = args.sizes.clone() {
                s.reset();
                stream.push_transform(s);
                stream.keep_size = true;
            }
            if args.rx.tags() {
                stream = stream.with_latency(1);
            }
            stream
        };
        let output = Output {
            iface: Some(iface.clone()),
            out: None,
            null: false,
        };
        let rx = args.rx.open()?;
        let (job, detail) = spawn_stream(make, &output, &args.send, linktype, &args.common, rx)?;
        let (stats, report) = watch(job, &args.common)?;
        print_line(done_label(&stats.total), &stats.total);
        if let Some(mut r) = report {
            r.print();
            if let Some(path) = &args.rx.report {
                r.info = Some(latency::run_info(
                    Some(iface),
                    args.rx.rx.as_deref(),
                    Some(detail),
                ));
                r.save(path)?;
            }
        }
        return Ok(());
    }
    if args.rx.tags() {
        bail!("--rx and --latency apply when sending with --iface");
    }
    if args.out.is_none() && (args.loops != 1 || args.rate.is_set()) {
        eprintln!("note: --loop and rates apply when sending with --iface");
    }
    Ok(())
}

fn cmd_backends() -> Result<()> {
    let have = ferotrx_io::backends();
    for b in Backend::ALL {
        let what = match b {
            Backend::Pcap => "libpcap (Linux, macOS) or Npcap (Windows); works everywhere",
            Backend::AfXdp => "Linux AF_XDP sockets; batched, copy or zero-copy mode",
            Backend::Dpdk => "DPDK user space drivers; needs a DPDK-bound NIC or a vdev",
        };
        let state = if have.contains(&b) { "yes" } else { "no " };
        println!("{state}  {:<7} {what}", b.name());
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
        // Windows: "Ethernet 2" first, which -i takes too.
        let mut line = match &i.alias {
            Some(a) => format!("{a}\t{}", i.name),
            None => i.name.clone(),
        };
        for x in i.description.iter().chain(&i.mac) {
            line.push('\t');
            line.push_str(x);
        }
        if !i.addresses.is_empty() {
            line.push('\t');
            line.push_str(&i.addresses.join(" "));
        }
        println!("{line}");
    }
    Ok(())
}

impl Output {
    fn to_io(&self, send: &SendArgs) -> Result<ferotrx_io::Output> {
        let send = send.settings()?;
        if let Some(name) = &self.iface {
            return Ok(ferotrx_io::Output::Interface {
                name: name.clone(),
                send,
            });
        }
        let mut rest = send.clone();
        rest.workers = None;
        if !rest.is_empty() {
            eprintln!("note: --backend, --queue, --xdp-mode, --batch and --dpdk-args apply to --iface only");
        }
        if let Some(path) = &self.out {
            return Ok(ferotrx_io::Output::File(path.clone()));
        }
        if self.null {
            return Ok(ferotrx_io::Output::Null);
        }
        bail!("choose an output")
    }
}

/// Opens the output once per worker (`--workers`) and starts a job with one
/// copy of the stream `make` builds per worker, each sending its share.
fn spawn_stream(
    make: impl Fn() -> Stream<'static>,
    output: &Output,
    send: &SendArgs,
    linktype: u32,
    common: &CommonArgs,
    rx: Option<ferotrx_core::RxSettings>,
) -> Result<(Job, String)> {
    let workers = send.settings()?.workers();
    let output = output.to_io(send)?;
    warn_linktype(&output, linktype);
    let opened = output
        .open_workers(linktype, workers)
        .map_err(|e| anyhow::anyhow!(e))?;
    let mut details: Vec<String> = Vec::new();
    let mut work: Vec<(Vec<Stream<'static>>, Box<dyn PacketSink + Send>)> = Vec::new();
    for (k, o) in opened.into_iter().enumerate() {
        if !details.contains(&o.detail) {
            details.push(o.detail);
        }
        work.push((vec![make().shard(k, workers)], o.sink));
    }
    let detail = details.join("; ");
    if !common.quiet && matches!(output, ferotrx_io::Output::Interface { .. }) {
        eprintln!("sending with {detail}");
    }
    let job = Job::spawn_workers(work, run_config(common)?, rx)?;
    Ok((job, detail))
}

fn warn_linktype(output: &ferotrx_io::Output, linktype: u32) {
    if let ferotrx_io::Output::Interface { name, .. } = output {
        if linktype != LINKTYPE_ETHERNET {
            eprintln!("warning: capture link type is {linktype}, not Ethernet; frames may not be valid on {name}");
        }
    }
}

fn cmd_replay(args: ReplayArgs) -> Result<()> {
    let rate = args.rate.rate();
    rate.validate()?;
    let cap = load(&args.file)?;
    if cap.is_empty() {
        bail!("{} has no packets", args.file.display());
    }
    if (!args.rewrites.is_empty() || !args.vary.is_empty() || args.sizes.is_some())
        && cap.linktype != LINKTYPE_ETHERNET
    {
        bail!(
            "rewrites, vary and sizes need Ethernet frames, {} has link type {}",
            args.file.display(),
            cap.linktype
        );
    }
    let linktype = cap.linktype;
    let cap = Arc::new(cap);
    let traffic = model(rate, &args.model)?;
    let make = || {
        let mut stream = Stream::new("capture", CaptureSource::new(cap.clone()).loops(args.loops))
            .with_rate(rate)
            .with_model(traffic.clone());
        for r in &args.rewrites {
            stream.push_transform(r.clone());
        }
        if !args.vary.is_empty() {
            stream.push_transform(FieldEngine::new(args.vary.iter().cloned()));
        }
        if let Some(s) = args.sizes.clone() {
            stream.push_transform(s);
            stream.keep_size = true;
        }
        if args.rx.tags() {
            stream = stream.with_latency(1);
        }
        if let Some(spec) = &args.impair {
            stream = stream.with_impair(spec.clone());
        }
        stream
    };
    let rx = args.rx.open()?;
    let capture = args.capture.start(args.output.iface.as_deref())?;
    let (job, detail) = spawn_stream(make, &args.output, &args.send, linktype, &args.common, rx)?;
    let (stats, report) = watch(job, &args.common)?;
    if let Some(c) = capture {
        c.finish(args.common.quiet)?;
    }
    print_line(done_label(&stats.total), &stats.total);
    if let Some(mut r) = report {
        r.print();
        if let Some(path) = &args.rx.report {
            let mut info = latency::run_info(
                args.output.iface.as_deref(),
                args.rx.rx.as_deref(),
                Some(detail),
            );
            info.profile = Some(format!("capture {}", args.file.display()));
            r.info = Some(info);
            r.save(path)?;
        }
    }
    Ok(())
}

fn cmd_run(args: RunArgs) -> Result<()> {
    let mut profile = Profile::from_path(&args.profile)
        .with_context(|| format!("cannot read {}", args.profile.display()))?;
    if args.rx.latency || (args.rx.rx.is_some() && !profile.has_latency()) {
        profile.enable_latency();
    }
    if let Some(m) = &args.model {
        for spec in &mut profile.streams {
            spec.model = model(spec.rate, &Some(m.clone()))
                .with_context(|| format!("stream {}", spec.name))?;
        }
    }
    if let Some(impair) = &args.impair {
        for spec in &mut profile.streams {
            spec.impair = (!impair.is_none()).then(|| impair.clone());
        }
    }
    if !args.common.quiet {
        for spec in &profile.streams {
            let mut line = format!("stream {}: {} at {}", spec.name, spec.source, spec.rate);
            if !spec.rewrite.is_empty() {
                let r: Vec<String> = spec.rewrite.iter().map(ToString::to_string).collect();
                line.push_str(&format!(", rewrite {}", r.join(" ")));
            }
            if !spec.vary.is_empty() {
                let v: Vec<String> = spec.vary.iter().map(ToString::to_string).collect();
                line.push_str(&format!(", vary {}", v.join(" ")));
            }
            if let Some(flow) = spec.latency {
                line.push_str(&format!(", latency flow {flow}"));
            }
            if !spec.model.is_steady() {
                line.push_str(&format!(", model {}", spec.model));
            }
            if let Some(impair) = &spec.impair {
                line.push_str(&format!(", impaired {impair}"));
            }
            eprintln!("{line}");
        }
    }
    let output = args.output.to_io(&args.send)?;
    // Files and the null output take only the worker count, from the profile.
    if let Some(w) = args.send.workers {
        profile.output.workers = Some(w);
    }
    let rx = args.rx.open()?;
    let capture = args.capture.start(args.output.iface.as_deref())?;
    // The same function starts `run.start` runs on the control server.
    let started =
        ferotrx_ctl::start_run_with_rx(&profile, &output, None, run_config(&args.common)?, rx)
            .map_err(|e| anyhow::anyhow!(e))?;
    if !args.common.quiet && matches!(output, ferotrx_io::Output::Interface { .. }) {
        eprintln!("sending with {}", started.detail);
    }
    let job = started.job;
    let names = job.stream_names().to_vec();
    let (stats, report) = watch(job, &args.common)?;
    if let Some(c) = capture {
        c.finish(args.common.quiet)?;
    }
    for (name, st) in names.iter().zip(&stats.streams) {
        print_line(&format!("  {name}"), st);
    }
    print_line(done_label(&stats.total), &stats.total);
    if let Some(mut r) = report {
        r.print();
        if let Some(path) = &args.rx.report {
            let mut info = latency::run_info(
                args.output.iface.as_deref(),
                args.rx.rx.as_deref(),
                Some(started.detail),
            );
            info.profile = Some(args.profile.display().to_string());
            info.profile_text = std::fs::read_to_string(&args.profile).ok();
            r.info = Some(info);
            r.save(path)?;
        }
    }
    Ok(())
}

/// Run settings from the command line, stopped by Ctrl-C.
fn run_config(common: &CommonArgs) -> Result<RunConfig> {
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::Relaxed))
            .context("cannot install Ctrl-C handler")?;
    }
    Ok(RunConfig {
        limit: common.limit,
        duration: common.duration,
        ignore_send_errors: common.ignore_errors,
        stop: Some(stop),
        start_at: None,
    })
}

/// Waits for a job, printing a progress line every second unless quiet.
/// Returns the final counters, and the loss and latency report if the job
/// has a receiver.
fn watch(job: Job, common: &CommonArgs) -> Result<(RunStats, Option<latency::Report>)> {
    while !job.wait(Some(Duration::from_secs(1))) {
        if !common.quiet {
            let mut line = stats_line("progress", &job.stats().total);
            if let Some(note) = latency::progress_note(&job) {
                line.push_str("; ");
                line.push_str(&note);
            }
            eprintln!("{line}");
        }
    }
    let report = latency::Report::of(&job);
    Ok((job.join()?, report))
}

fn done_label(s: &ReplayStats) -> &'static str {
    if s.stopped {
        "stopped"
    } else {
        "done"
    }
}

fn print_line(label: &str, s: &ReplayStats) {
    eprintln!("{}", stats_line(label, s));
    if let Some(impair) = &s.impair {
        eprintln!("{label} impairments: {impair}");
    }
}

fn stats_line(label: &str, s: &ReplayStats) -> String {
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
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_packet_file_builds() {
        let path = PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/packets.txt"
        ));
        let specs = read_specs(&path).unwrap();
        assert_eq!(specs.len(), 7);
        assert!(specs[4].contains("Host: 192.168.20.50"));
        let cap = Capture::from_specs(&specs, Duration::from_secs(1)).unwrap();
        let problems: Vec<_> = cap
            .packets
            .iter()
            .map(|p| ferotrx_packet::decode(cap.linktype, &p.data).problems)
            .collect();
        // Only the packet with the deliberately wrong checksum has a problem.
        assert!(problems[..6].iter().all(Vec::is_empty), "{problems:?}");
        assert_eq!(problems[6], ["UDP checksum is incorrect"]);
    }
}
