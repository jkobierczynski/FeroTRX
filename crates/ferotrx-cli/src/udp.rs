//! `ferotrx udp`: stateful UDP transactions (DNS, NTP, replayed sessions).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};
use ferotrx_core::{
    parse_duration, parse_port_range, Capture, DnsWorkload, TcpRunConfig, UdpApp, UdpProfile,
    UdpProgram, UdpRole, UdpSource, UdpStats, UdpTemplateSpec,
};
use ferotrx_ctl::protocol::{
    LatencyCounters, RunState, UdpCounters, UdpRunInfo, UdpTemplateCounters,
};

use crate::tcp::{opt, parse_connect, set, HostArgs};

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum App {
    /// Replay a UDP session from the capture, datagram for datagram.
    Replay,
    /// DNS: the capture's lookups (queries, and records from its answers),
    /// plus --query and --record.
    Dns,
    /// NTP client requests and server replies.
    Ntp,
}

#[derive(Args)]
#[command(args_override_self = true)]
pub struct UdpArgs {
    /// A capture with the UDP session to replay, or with DNS lookups (--app dns).
    /// Not needed with --profile, --app ntp, or DNS from --query/--record.
    file: Option<PathBuf>,

    /// A UDP profile (TOML) with what to play (or several `[[template]]`s),
    /// the hosts and the rates; the options below replace its values. See
    /// examples/lab-dns.toml.
    #[arg(short, long, conflicts_with = "file")]
    profile: Option<PathBuf>,

    /// What the transactions carry (default: replay with a capture, dns with --query).
    #[arg(long, value_enum)]
    app: Option<App>,

    /// Which UDP session of the capture to replay, numbered from 1 (see --list).
    #[arg(long, value_name = "N")]
    flow: Option<usize>,

    /// A DNS query the client sends, NAME [TYPE] [RCODE], e.g.
    /// "www.lab.local AAAA" or "nope.lab.local A NXDOMAIN"; repeat for more.
    #[arg(long, value_name = "QUERY")]
    query: Vec<String>,

    /// A record the DNS server answers with, NAME [TTL] TYPE DATA, e.g.
    /// "www.lab.local 300 A 192.168.20.80", or NAME RCODE for an error;
    /// repeat for more.
    #[arg(long, value_name = "RECORD")]
    record: Vec<String>,

    /// List the UDP sessions in the capture and exit.
    #[arg(long)]
    list: bool,

    /// Show what the transactions carry, and exit.
    #[arg(long)]
    show: bool,

    /// Interface for the client and the server, unless --client-iface or
    /// --server-iface say otherwise.
    #[arg(short, long)]
    iface: Option<String>,

    #[command(flatten)]
    hosts: HostArgs,

    #[command(flatten)]
    send: crate::SendArgs,

    #[command(flatten)]
    impair: crate::PortImpairArgs,

    #[command(flatten)]
    gtpu: crate::GtpuArgs,

    /// Where the client sends, IP:PORT ([IPv6]:PORT), or IP for each
    /// template's port. Default: the server. Needed when this machine runs
    /// only the client.
    #[arg(long, value_name = "IP[:PORT]", value_parser = parse_connect)]
    connect: Option<SocketAddr>,

    /// Send to this many consecutive server addresses, in turn.
    #[arg(long, value_name = "N")]
    connect_ips: Option<u32>,

    /// Transactions per second, all templates together (default 1, or the profile's).
    #[arg(long)]
    rate: Option<f64>,

    /// How new transactions spread around the rate (see `ferotrx replay --help`):
    /// poisson, burst=N, ramp_up=10s,hold=1m,ramp_down=10s, at=TIME:RATE, seed=N.
    /// Replaces the profile's top-level model.
    #[arg(long, value_name = "MODEL")]
    model: Option<ferotrx_core::TrafficModel>,

    /// Transactions in all; 0 keeps going until Ctrl-C or --duration
    /// (default 1, or the profile's).
    #[arg(short = 'n', long)]
    transactions: Option<u64>,

    /// Most transactions open at once; 0 is no limit.
    #[arg(long)]
    concurrency: Option<usize>,

    /// Client source ports, LOW-HIGH (default 1024-65534); each transaction
    /// gets its own.
    #[arg(long, value_name = "LOW-HIGH")]
    source_ports: Option<String>,

    /// Wait this long for an answer before asking again (default 1s).
    #[arg(long, value_parser = parse_duration)]
    timeout: Option<Duration>,

    /// Ask again this often before a transaction times out (default 2).
    #[arg(long, value_name = "N")]
    retries: Option<u32>,

    /// The server forgets a quiet session after this long (default 5s).
    #[arg(long, value_parser = parse_duration)]
    session_timeout: Option<Duration>,

    /// Keep the capture's timing: wait as long between datagrams as it shows.
    #[arg(long)]
    keep_timing: bool,

    /// Pause this long before answering the other end, e.g. 20ms, or a
    /// distribution such as exp(20ms) (see docs/traffic-models.md).
    #[arg(long, value_parser = crate::tcp::parse_think)]
    think_time: Option<ferotrx_core::Dist>,

    /// Do not check replayed datagrams against the capture.
    #[arg(long)]
    no_verify: bool,

    /// Stop after this long, e.g. 30s or 5m.
    #[arg(short, long, value_parser = parse_duration)]
    duration: Option<Duration>,

    /// Print no progress lines, only the final summary.
    #[arg(short, long)]
    quiet: bool,

    /// Write a record of the run to this file, as JSON: what ran where
    /// (version, host, NIC and driver, ports, workers, CPU affinity,
    /// profile and its hash) and the final counters, with what every layer
    /// of the ports dropped.
    #[arg(long, value_name = "FILE")]
    report: Option<PathBuf>,

    #[command(flatten)]
    capture: crate::capture::RunCaptureArgs,
}

fn sessions(file: &PathBuf) -> Result<()> {
    let cap =
        Capture::from_path(file).with_context(|| format!("cannot read {}", file.display()))?;
    let flows = UdpProgram::flows(&cap);
    if flows.is_empty() {
        println!("no UDP datagrams in {}", file.display());
    }
    for (i, f) in flows.iter().enumerate() {
        println!("{:>4}  {f}", i + 1);
    }
    Ok(())
}

fn show(app: &UdpApp) {
    println!("{app}");
    match app {
        UdpApp::Replay(p) => {
            for (i, m) in p.messages.iter().enumerate() {
                let arrow = match m.from {
                    UdpRole::Client => "client ->",
                    UdpRole::Server => "<- server",
                };
                let text: String = String::from_utf8_lossy(&m.data[..m.data.len().min(60)])
                    .chars()
                    .map(|c| if c.is_control() { '.' } else { c })
                    .collect();
                let gap = if m.delay.is_zero() {
                    String::new()
                } else {
                    format!(" (after {:?})", m.delay)
                };
                println!(
                    "{:>4}  {arrow} {:>6} bytes  {text}{gap}",
                    i + 1,
                    m.data.len()
                );
            }
        }
        UdpApp::App(_) => {
            let Some(w) = app.dns_workload() else {
                return;
            };
            for q in &w.queries {
                println!("  query  {q}");
            }
            for r in &w.records {
                println!("  record {r}");
            }
            for (n, r) in &w.errors {
                println!("  error  {n} {r}");
            }
        }
    }
}

/// The template the command line describes, without a profile.
fn template(args: &UdpArgs) -> Result<UdpTemplateSpec> {
    let dns_given = !args.query.is_empty() || !args.record.is_empty();
    let app = args
        .app
        .unwrap_or(if dns_given { App::Dns } else { App::Replay });
    let source = match app {
        App::Replay => {
            if dns_given {
                bail!("--query and --record go with --app dns");
            }
            let Some(file) = &args.file else {
                bail!("give a capture file, --profile, --app ntp, or DNS --query");
            };
            UdpSource::Pcap {
                path: file.clone(),
                flow: match args.flow {
                    Some(0) => bail!("sessions are numbered from 1"),
                    f => f.map(|f| f - 1),
                },
            }
        }
        App::Dns => {
            if args.flow.is_some() {
                bail!("--flow goes with a replay; --app dns takes every lookup in the capture");
            }
            UdpSource::Dns {
                pcap: args.file.clone(),
                extra: DnsWorkload::parse(&args.query, &args.record)?,
            }
        }
        App::Ntp => {
            if dns_given || args.file.is_some() {
                bail!("--app ntp takes no capture, --query or --record");
            }
            UdpSource::Ntp
        }
    };
    Ok(UdpTemplateSpec::new(source))
}

pub fn cmd_udp(args: UdpArgs) -> Result<()> {
    if args.list {
        let Some(file) = &args.file else {
            bail!("--list needs a capture file");
        };
        return sessions(file);
    }
    let mut profile = match &args.profile {
        Some(path) => {
            if args.app.is_some()
                || args.flow.is_some()
                || !args.query.is_empty()
                || !args.record.is_empty()
            {
                bail!("--app, --flow, --query and --record describe a template; with --profile, set them in the profile");
            }
            UdpProfile::from_path(path)
                .with_context(|| format!("cannot read {}", path.display()))?
        }
        None => UdpProfile {
            templates: vec![template(&args)?],
            ..Default::default()
        },
    };
    args.hosts.apply(
        &mut profile.client,
        &mut profile.server,
        &mut profile.host_options,
    )?;
    set(&mut profile.rate, args.rate);
    if let Some(m) = args.model.clone() {
        profile.model = m;
    }
    set(&mut profile.transactions, args.transactions);
    set(&mut profile.concurrency, args.concurrency);
    opt(&mut profile.connect, args.connect);
    opt(&mut profile.connect_ips, args.connect_ips);
    if profile.templates.len() > 1 && args.hosts.server_port.is_some() {
        bail!("--server-port needs a single template; set `port` in each [[template]] instead");
    }
    if let Some(r) = &args.source_ports {
        profile.source_ports = parse_port_range(r)?;
    }
    let o = &mut profile.options;
    set(&mut o.timeout, args.timeout);
    set(&mut o.retries, args.retries);
    set(&mut o.session_timeout, args.session_timeout);
    set(&mut o.think_time, args.think_time);
    if args.keep_timing {
        o.keep_timing = true;
    }
    if args.no_verify {
        o.verify = false;
    }
    if args.duration.is_some() {
        profile.duration = args.duration;
    }
    profile.output = args.send.settings()?.or(&profile.output);
    args.impair.apply(&mut profile.impair);
    args.gtpu.apply(&mut profile.gtpu);

    if args.show {
        let apps = profile.apps()?;
        let many = apps.len() > 1;
        for (i, (t, app)) in profile.templates.iter().zip(&apps).enumerate() {
            if many {
                println!("{}:", template_line(t, i));
            }
            show(app);
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
    let capture_iface = args
        .iface
        .clone()
        .or_else(|| profile.client.as_ref().and_then(|h| h.iface.clone()))
        .or_else(|| profile.server.as_ref().and_then(|h| h.iface.clone()));
    let capture = args.capture.start(capture_iface.as_deref())?;
    let started = ferotrx_ctl::start_udp(
        &profile,
        args.iface.as_deref(),
        TcpRunConfig {
            duration: profile.duration,
            stop: Some(stop),
            start_at: None,
            pinning: None,
        },
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    if !args.quiet {
        let workers = started.job.workers();
        if workers > 1 {
            eprintln!("workers: {workers} engine threads");
        }
        for d in &started.port_details {
            eprintln!("port: {d}");
        }
        if profile.templates.len() > 1 {
            for (i, t) in profile.templates.iter().enumerate() {
                eprintln!("{}", template_line(t, i));
            }
        }
        eprintln!("transactions: {}", started.program);
        for (what, h) in [("client", &profile.client), ("server", &profile.server)] {
            if let Some(h) = h {
                let mut line = format!(
                    "{what}: {} mac {} on {}",
                    h.address_text(),
                    h.mac(),
                    h.iface.as_deref().or(args.iface.as_deref()).unwrap_or("?")
                );
                if h.ips > 1 {
                    line.push_str(&format!(" ({} addresses, to {})", h.ips, h.last_ip()));
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
        for g in &profile.users {
            eprintln!("users: {g}");
        }
        if profile.client.is_some() {
            let n = if profile.transactions == 0 {
                "until stopped".to_string()
            } else {
                format!("{} transactions", profile.transactions)
            };
            let model = if profile.model.is_steady() {
                String::new()
            } else {
                format!(", model {}", profile.model)
            };
            eprintln!("sending {n} at {} per second{model}", profile.rate);
        } else {
            eprintln!("server only: answering until Ctrl-C or --duration");
        }
    }
    let job = started.job;
    let workers = job.workers();
    let pinned = job.pinned_cpus().map(ToString::to_string);
    while !job.wait(Some(Duration::from_secs(1))) {
        if !args.quiet {
            eprintln!("{}", progress_line(&job.stats()));
        }
    }
    let stats = job.join()?;
    if let Some(c) = capture {
        c.finish(args.quiet)?;
    }
    print_summary(&stats);
    crate::tcp::print_users(&stats.users);
    crate::host::print_hosts(&stats.hosts, "  ");
    if let Some(path) = &args.report {
        let mut info = crate::latency::run_info(
            started.interfaces.first().map(String::as_str),
            None,
            (!started.port_details.is_empty()).then(|| started.port_details.join("; ")),
        );
        info.workers = Some(workers);
        info.pinned_cpus = pinned;
        if let Some(p) = &args.profile {
            crate::latency::set_profile_file(&mut info, p);
        }
        let mut counters = ferotrx_ctl::protocol::UdpRunInfo {
            program: started.program.clone(),
            interfaces: started.interfaces.clone(),
            ports: started.port_details.clone(),
            workers,
            ..Default::default()
        };
        counters.fill(&stats);
        crate::latency::save_record(path, &info, "udp", &counters)?;
    }
    let c = &stats.client;
    let failed = c.timed_out + stats.server.timed_out;
    let mismatched = c.mismatched + stats.server.mismatched;
    if failed + mismatched > 0 {
        bail!("{failed} transactions timed out, {mismatched} got other answers than expected");
    }
    Ok(())
}

fn template_line(t: &UdpTemplateSpec, i: usize) -> String {
    let mut line = match t.rate {
        Some(r) => format!("template {} ({r} per second of its own)", t.name(i)),
        None => format!("template {} (weight {})", t.name(i), t.weight),
    };
    if !t.model.is_steady() {
        line.push_str(&format!(", model {}", t.model));
    }
    if let Some(n) = t.transactions {
        line.push_str(&format!(", {n} transactions"));
    }
    if let Some(n) = t.concurrency {
        line.push_str(&format!(", at most {n} open"));
    }
    if let Some(d) = t.think_time {
        line.push_str(&format!(", think time {d}"));
    }
    if let Some(l) = &t.session {
        line.push_str(&format!(", sessions of {l}"));
    }
    if let Some(g) = t.group {
        line.push_str(&format!(", users group {}", g + 1));
    }
    line
}

fn progress_line(s: &UdpStats) -> String {
    format!(
        "progress: client {} sent, {} answered, {} open, {} timed out; server {} answered; {:.1} per second, {} frames out, {} in",
        s.client.sent,
        s.client.answered,
        s.client.active,
        s.client.timed_out,
        s.server.answered,
        s.tps(),
        s.tx_packets,
        s.rx_packets
    )
}

fn print_summary(s: &UdpStats) {
    eprintln!(
        "{} in {:.3} s: {} frames ({} bytes) sent, {} ({} bytes) received{}",
        if s.stopped { "stopped" } else { "done" },
        s.elapsed.as_secs_f64(),
        s.tx_packets,
        s.tx_bytes,
        s.rx_packets,
        s.rx_bytes,
        if s.rx_dropped > 0 {
            format!(
                "; {} dropped here before they were read (capture buffer full; not network loss)",
                s.rx_dropped
            )
        } else {
            String::new()
        }
    );
    if let Some(line) = crate::latency::drops_line(&s.drops) {
        eprintln!("  {line}");
    }
    for line in crate::impair_lines(&s.impair) {
        eprintln!("  {line}");
    }
    for (what, side) in [("client", &s.client), ("server", &s.server)] {
        if side.sent == 0 && side.datagrams_rx == 0 {
            continue;
        }
        eprintln!("  {what}: {}", side_line(&side.into()));
    }
    if s.templates.len() > 1 {
        for t in &s.templates {
            let t = UdpTemplateCounters {
                name: t.name.clone(),
                client: (&t.client).into(),
                server: (&t.server).into(),
            };
            for line in template_lines(&t) {
                eprintln!("{line}");
            }
        }
    }
    if s.client.answered > 0 {
        eprintln!("  {:.1} transactions per second", s.tps());
    }
}

fn template_lines(t: &UdpTemplateCounters) -> Vec<String> {
    [("client", &t.client), ("server", &t.server)]
        .into_iter()
        .filter(|(_, c)| c.sent > 0 || c.datagrams_rx > 0)
        .map(|(what, c)| format!("    {} {what}: {}", t.name, side_line(c)))
        .collect()
}

pub(crate) fn ms(us: Option<f64>) -> String {
    us.map_or("-".into(), |u| format!("{:.2}", u / 1000.0))
}

pub(crate) fn response_line(r: &LatencyCounters) -> String {
    format!(
        "response time ms min {} avg {} p50 {} p99 {} max {}",
        ms(r.min_us),
        ms(r.avg_us),
        ms(r.p50_us),
        ms(r.p99_us),
        ms(r.max_us)
    )
}

fn side_line(c: &UdpCounters) -> String {
    let mut line = format!("{} transactions, {} answered", c.sent, c.answered);
    if c.active > 0 {
        line.push_str(&format!(", {} open", c.active));
    }
    for (n, what) in [
        (c.timed_out, "timed out"),
        (c.errors, "with error answers"),
        (c.mismatched, "with other answers than expected"),
        (c.unmatched, "datagrams unmatched"),
        (c.retries, "sent again"),
        (c.duplicates, "duplicates"),
    ] {
        if n > 0 {
            line.push_str(&format!(", {n} {what}"));
        }
    }
    line.push_str(&format!(
        "; {} datagrams ({} bytes) sent, {} ({} bytes) received",
        c.datagrams_tx, c.payload_tx, c.datagrams_rx, c.payload_rx
    ));
    if let Some(r) = c
        .response_time
        .as_ref()
        .or(c.app.as_ref().and_then(|a| a.response_time.as_ref()))
    {
        line.push_str(&format!("; {}", response_line(r)));
    }
    if let Some(a) = &c.app {
        if let Some(h) = &a.tls {
            line.push_str(&format!("; {}", crate::tcp::tls_line(h)));
        }
        line.push_str(&format!("; {}", codes_line(a)));
        if let Some(m) = &a.media {
            line.push_str(&format!("; {}", media_line(m)));
        }
    }
    line
}

/// RTP of the calls: `16 media streams (PCMU x16): 4800 packets sent,
/// 4790 received, 10 lost (0.21%), jitter ms avg 0.40 max 1.20, RTCP 32
/// sent 32 received, round trip ms avg 20.1 max 22.0; MOS 4.38 (worst 4.31),
/// R 91.2 (very satisfied x16)`.
pub(crate) fn media_line(m: &ferotrx_ctl::protocol::MediaCounters) -> String {
    let mut codecs: Vec<(&String, &u64)> = m.codecs.iter().collect();
    codecs.sort_by(|x, y| y.1.cmp(x.1).then(x.0.cmp(y.0)));
    let codecs: Vec<String> = codecs.iter().map(|(k, n)| format!("{k} x{n}")).collect();
    let mut line = format!(
        "{} media streams ({}): {} packets sent, {} received, {} lost ({:.2}%)",
        m.streams,
        codecs.join(", "),
        m.packets_sent,
        m.packets_received,
        m.lost,
        m.loss_pct
    );
    for (n, what) in [(m.duplicates, "duplicates"), (m.reordered, "reordered")] {
        if n > 0 {
            line.push_str(&format!(", {n} {what}"));
        }
    }
    if let Some(j) = &m.jitter {
        line.push_str(&format!(
            ", jitter ms avg {} max {}",
            ms(j.avg_us),
            ms(j.max_us)
        ));
    }
    if m.late > 0 {
        line.push_str(&format!(", {} too late for the jitter buffer", m.late));
    }
    if m.loss_bursts > 0 {
        line.push_str(&format!(
            ", {} loss bursts (longest {})",
            m.loss_bursts, m.max_burst
        ));
    }
    line.push_str(&format!(
        ", RTCP {} sent {} received",
        m.rtcp_sent, m.rtcp_received
    ));
    if let Some(r) = &m.rtt {
        line.push_str(&format!(
            ", round trip ms avg {} max {}",
            ms(r.avg_us),
            ms(r.max_us)
        ));
    }
    if m.remote_lost > 0 {
        line.push_str(&format!(", {} of ours lost (their RTCP)", m.remote_lost));
    }
    if let (Some(mos), Some(worst), Some(r)) = (m.mos_avg, m.mos_min, m.r_avg) {
        line.push_str(&format!(
            "; MOS {mos:.2} (worst {worst:.2}), R {r:.1}{}",
            bands_text(&m.bands)
        ));
    }
    line
}

/// ` (satisfied x3, many dissatisfied x1)`, or nothing.
fn bands_text(bands: &[u64]) -> String {
    let v: Vec<String> = ferotrx_core::app::quality::BANDS
        .iter()
        .zip(bands)
        .filter(|(_, n)| **n > 0)
        .map(|(b, n)| format!("{b} x{n}"))
        .collect();
    if v.is_empty() {
        String::new()
    } else {
        format!(" ({})", v.join(", "))
    }
}

/// Transactions by status or response code: `NOERROR x40, NXDOMAIN x2`.
pub(crate) fn codes_line(a: &ferotrx_ctl::protocol::AppCounters) -> String {
    let mut v: Vec<(&String, &u64)> = a.codes.iter().collect();
    v.sort_by(|x, y| y.1.cmp(x.1).then(x.0.cmp(y.0)));
    let codes: Vec<String> = v.iter().map(|(k, n)| format!("{k} x{n}")).collect();
    let mut line = codes.join(", ");
    if a.protocol_errors > 0 {
        line.push_str(&format!(", {} protocol errors", a.protocol_errors));
        if !a.protocol_error_samples.is_empty() {
            line.push_str(&format!(" ({})", a.protocol_error_samples.join("; ")));
        }
    }
    line
}

/// Prints a UDP run as the control server reports it.
pub fn print_udp_run(r: &UdpRunInfo) {
    let state = match r.state {
        RunState::Running => "running",
        RunState::Finished => "finished",
        RunState::Stopped => "stopped",
        RunState::Failed => "failed",
    };
    let on = if r.workers > 1 {
        format!("{} ({} workers)", r.interfaces.join(", "), r.workers)
    } else {
        r.interfaces.join(", ")
    };
    println!(
        "udp run {} on {on}: {state}, {:.3} s, {:.1} per second",
        r.id, r.elapsed_s, r.tps
    );
    println!("  transactions: {}", r.program);
    if let Some(e) = &r.error {
        println!("  error: {e}");
    }
    if !r.drops.is_empty() {
        println!("  dropped at: {}", r.drops.describe());
    }
    for line in crate::port_impair_lines(&r.impair) {
        println!("  {line}");
    }
    for (what, c) in [("client", &r.client), ("server", &r.server)] {
        if c.sent > 0 || c.datagrams_rx > 0 {
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
    crate::tcp::print_user_counters(&r.users);
    crate::host::print_host_infos(&r.hosts, "  ");
}
