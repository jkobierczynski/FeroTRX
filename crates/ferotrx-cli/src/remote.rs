//! `ferotrx serve` and `ferotrx ctl`: the control server and its command line client.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use ferotrx_core::{parse_duration, parse_size, Profile};
use ferotrx_ctl::protocol::{
    Counters, LoadProfileParams, OutputSpec, ProfileInfo, RunInfo, RunState, RxRunInfo, RxSpec,
    RxStartParams, StartParams, TcpStartParams, UdpStartParams, DEFAULT_PORT,
};
use ferotrx_ctl::{
    AuditLog, Client, ClientTls, Controller, FilePolicy, LabPki, Role, Server, ServerConfig,
    ServerTls, Token,
};
use serde_json::Value;

const TOKEN_ENV: &str = "FEROTRX_TOKEN";
const READ_TOKEN_ENV: &str = "FEROTRX_READ_TOKEN";
const ADDR_ENV: &str = "FEROTRX_CTL";
const CA_ENV: &str = "FEROTRX_CA";
const CERT_ENV: &str = "FEROTRX_CERT";
const KEY_ENV: &str = "FEROTRX_KEY";

#[derive(Args)]
pub struct ServeArgs {
    /// Address to listen on. Use 0.0.0.0:4510 (or the lab-facing address) to
    /// accept other machines; that needs a token or client certificates
    /// (or --insecure).
    #[arg(short, long, default_value_t = format!("127.0.0.1:{DEFAULT_PORT}"))]
    listen: String,

    /// Token that logs in as operator (load profiles, start and stop runs).
    /// Also read from FEROTRX_TOKEN.
    #[arg(long)]
    token: Option<String>,

    /// Token that logs in read-only (info, lists, stats, subscriptions).
    /// Also read from FEROTRX_READ_TOKEN.
    #[arg(long)]
    read_token: Option<String>,

    /// TOML file of named tokens: [[token]] tables with name, role
    /// ("read" or "operator") and secret, or sha256 of the secret.
    #[arg(long, value_name = "FILE")]
    tokens: Option<PathBuf>,

    /// Serve TLS with this certificate (PEM, chain with the server's first).
    #[arg(long, value_name = "FILE", requires = "tls_key")]
    tls_cert: Option<PathBuf>,

    /// The private key of --tls-cert (PEM).
    #[arg(long, value_name = "FILE", requires = "tls_cert")]
    tls_key: Option<PathBuf>,

    /// Client certificates from this CA log in as operator (mutual TLS).
    #[arg(long, value_name = "FILE", requires = "tls_cert")]
    client_ca: Option<PathBuf>,

    /// Client certificates from this CA log in read-only.
    #[arg(long, value_name = "FILE", requires = "tls_cert")]
    read_client_ca: Option<PathBuf>,

    /// Clients may only name profiles, pcaps and output files inside this
    /// directory; relative paths start from the first one. Repeatable.
    /// Default: the directory the server was started in.
    #[arg(long = "data-dir", value_name = "DIR")]
    data_dirs: Vec<PathBuf>,

    /// Largest profile a client may upload, e.g. 1M.
    #[arg(long, value_name = "SIZE", default_value = "1M")]
    max_upload: String,

    /// Largest file a client may send with `file.put` (a controller
    /// deploying profiles and pcaps), e.g. 256M; 0 refuses them.
    #[arg(long, value_name = "SIZE", default_value = "256M")]
    max_file: String,

    /// Longest request, e.g. 4M.
    #[arg(long, value_name = "SIZE", default_value = "4M")]
    max_request: String,

    /// Connections open at once.
    #[arg(long, value_name = "N", default_value_t = 64)]
    max_connections: usize,

    /// Close connections that send nothing for this long (and watch no
    /// stats), e.g. 5m; 0 = never.
    #[arg(long, value_name = "TIME", default_value = "5m")]
    idle_timeout: String,

    /// Append the audit log (JSON lines: logins, refusals, profile loads,
    /// run starts and stops) to this file instead of standard error.
    #[arg(long, value_name = "FILE")]
    audit_log: Option<PathBuf>,

    /// Listen on a non-loopback address even without a token or client
    /// certificates: anyone who reaches it can send traffic from this machine.
    #[arg(long)]
    insecure: bool,

    /// Let operators build a lab router on this machine from the GUI or
    /// `ferotrx ctl` (`lab.start`: a network namespace routing VLAN 10 to
    /// VLAN 20 on the link ftrx-lab, see `ferotrx lab`). Linux, as root.
    #[arg(long)]
    lab: bool,

    /// Load this profile at start, under its file name (or NAME=PATH). Repeatable.
    #[arg(short, long = "profile", value_name = "[NAME=]PATH")]
    profiles: Vec<String>,
}

fn env_or(arg: Option<String>, env: &str) -> Option<String> {
    arg.or_else(|| std::env::var(env).ok())
        .filter(|t| !t.is_empty())
}

pub fn cmd_serve(args: ServeArgs) -> Result<()> {
    let mut tokens = Vec::new();
    if let Some(t) = env_or(args.token, TOKEN_ENV) {
        tokens.push(Token::new("operator", Role::Operator, t));
    }
    if let Some(t) = env_or(args.read_token, READ_TOKEN_ENV) {
        tokens.push(Token::new("read", Role::Read, t));
    }
    if let Some(f) = &args.tokens {
        tokens.extend(Token::from_file(f)?);
    }
    let tls = match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => {
            let mut t = ServerTls::from_files(cert, key)?;
            if let Some(ca) = &args.client_ca {
                t = t.with_client_ca_file(Role::Operator, ca)?;
            }
            if let Some(ca) = &args.read_client_ca {
                t = t.with_client_ca_file(Role::Read, ca)?;
            }
            Some(t)
        }
        _ => None,
    };
    let dirs = if args.data_dirs.is_empty() {
        vec![std::env::current_dir()?]
    } else {
        args.data_dirs
    };
    let max_upload = parse_size(&args.max_upload)?;
    let files = FilePolicy::dirs(&dirs)?
        .with_max_upload(max_upload as usize)
        .with_max_file(parse_size(&args.max_file)?);
    let idle = parse_duration(&args.idle_timeout)?;
    let audit = match &args.audit_log {
        Some(p) => AuditLog::to_file(p)
            .with_context(|| format!("cannot open audit log {}", p.display()))?,
        None => AuditLog::to_stderr(),
    };
    let config = ServerConfig {
        tokens,
        tls,
        insecure: args.insecure,
        max_connections: args.max_connections,
        max_request: parse_size(&args.max_request)? as usize,
        idle_timeout: (idle > Duration::ZERO).then_some(idle),
        audit: Some(audit),
        ..Default::default()
    };
    let login = config.login_required();
    let tls_on = config.tls.is_some();
    let has_tokens = !config.tokens.is_empty();

    let controller = Controller::new()
        .with_file_policy(files.clone())
        .with_lab(args.lab);
    if args.lab {
        if let Some(why) = ferotrx_io::lab_unavailable() {
            eprintln!("warning: --lab: {why}");
        }
    }
    for p in &args.profiles {
        let (name, path) = match p.split_once('=') {
            Some((n, path)) => (n.to_string(), PathBuf::from(path)),
            None => {
                let path = PathBuf::from(p);
                let name = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .with_context(|| format!("{p} has no file name"))?;
                (name, path)
            }
        };
        let profile =
            Profile::from_path(&path).with_context(|| format!("cannot read {}", path.display()))?;
        let info = controller.add_profile(&name, profile);
        eprintln!("loaded profile {name} ({} streams)", info.streams.len());
    }
    let server = Server::with_config(&args.listen, controller, config)
        .with_context(|| format!("cannot listen on {}", args.listen))?;
    let addr = server.local_addr()?;
    if !addr.ip().is_loopback() {
        if !login {
            eprintln!("warning: listening on {addr} without a token or client certificates (--insecure); anyone who can reach it can send traffic from this machine");
        } else if has_tokens && !tls_on {
            eprintln!(
                "warning: tokens travel in clear text without TLS; give --tls-cert and --tls-key"
            );
        }
    }
    {
        let controller = server.controller().clone();
        ctrlc::set_handler(move || {
            eprintln!("stopping runs");
            controller.stop_all();
            controller.lab_stop();
            std::process::exit(0);
        })
        .context("cannot install Ctrl-C handler")?;
    }
    let mut notes = Vec::new();
    if tls_on {
        notes.push("TLS");
    }
    if login {
        notes.push("login required");
    }
    eprintln!(
        "ferotrx control server on {addr}{}; Ctrl-C to stop",
        if notes.is_empty() {
            String::new()
        } else {
            format!(" ({})", notes.join(", "))
        }
    );
    let dirs: Vec<String> = files
        .allowed_dirs()
        .unwrap_or_default()
        .iter()
        .map(|d| d.display().to_string())
        .collect();
    eprintln!("data directories: {}", dirs.join(", "));
    server.serve()?;
    Ok(())
}

#[derive(Args)]
pub struct CtlArgs {
    /// Server address. Also read from FEROTRX_CTL.
    #[arg(short, long, value_name = "HOST:PORT")]
    connect: Option<String>,

    /// Token to log in with (--token or --read-token of the server, or one
    /// of its --tokens). Also read from FEROTRX_TOKEN.
    #[arg(long)]
    token: Option<String>,

    /// Connect with TLS and check the server's certificate against this CA
    /// (PEM). Also read from FEROTRX_CA.
    #[arg(long, value_name = "FILE")]
    ca: Option<PathBuf>,

    /// Log in with this client certificate (PEM; needs --ca and --key).
    /// Also read from FEROTRX_CERT.
    #[arg(long, value_name = "FILE")]
    cert: Option<PathBuf>,

    /// The private key of --cert. Also read from FEROTRX_KEY.
    #[arg(long, value_name = "FILE")]
    key: Option<PathBuf>,

    /// Check the server's certificate for this name instead of the host in
    /// --connect.
    #[arg(long, value_name = "NAME")]
    server_name: Option<String>,

    /// Print the server's JSON answers instead of text.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: CtlCommand,
}

#[derive(Subcommand)]
enum CtlCommand {
    /// Show the server's version and what it supports.
    Info,
    /// List the interfaces the server can send on.
    Interfaces,
    /// Load a profile. PATH is on the server, unless --upload sends the local file.
    Load {
        path: PathBuf,
        /// Name to load it under (default: the file name without .toml).
        #[arg(short, long)]
        name: Option<String>,
        /// Send this machine's file to the server. Pcap paths in it are then
        /// taken from --base-dir on the server (default: the server's folder).
        #[arg(short, long)]
        upload: bool,
        /// With --upload: folder on the server that relative pcap paths are in.
        #[arg(long, requires = "upload")]
        base_dir: Option<PathBuf>,
    },
    /// List the loaded profiles.
    Profiles,
    /// Forget a loaded profile.
    Unload { name: String },
    /// Start a run of a loaded profile.
    Start(StartArgs),
    /// Stop a run and show its final counters.
    Stop { id: u64 },
    /// Show the counters of one run, or of every run.
    Stats { id: Option<u64> },
    /// Follow live counters of one run (until it ends) or of every run.
    Watch {
        id: Option<u64>,
        /// Milliseconds between updates.
        #[arg(short, long, default_value_t = 1000)]
        interval: u64,
    },
    /// Forget a run, stopping it first if it is still running.
    Remove { id: u64 },
    /// Start a stateful TCP run from a TCP profile (see `ferotrx tcp --help`).
    /// PATH is on the server, unless --upload sends the local file.
    TcpStart {
        path: PathBuf,
        /// Send this machine's file to the server.
        #[arg(short, long)]
        upload: bool,
        /// With --upload: folder on the server that a relative `pcap` path is in.
        #[arg(long, requires = "upload")]
        base_dir: Option<PathBuf>,
        /// Interface of the server for hosts whose table names none.
        #[arg(short, long)]
        iface: Option<String>,
        /// New connections per second instead of the profile's.
        #[arg(long)]
        cps: Option<f64>,
        /// Connections in all instead of the profile's; 0 = until stopped.
        #[arg(short = 'n', long)]
        connections: Option<u64>,
        /// Stop after this long, e.g. 30s.
        #[arg(short, long)]
        duration: Option<String>,
        /// Engine threads on the server to spread the run over.
        #[arg(long)]
        workers: Option<u16>,
        /// Impair the frames the run sends (see `ferotrx tcp --help`).
        #[arg(long, value_name = "SPEC")]
        impair: Option<String>,
        /// Impair the frames the run receives.
        #[arg(long, value_name = "SPEC")]
        impair_rx: Option<String>,
        /// Congestion control instead of the profile's: newreno or cubic.
        #[arg(long, value_name = "NAME")]
        congestion: Option<String>,
        /// Use ECN (RFC 3168).
        #[arg(long)]
        ecn: bool,
    },
    /// Show the counters of one TCP run, or of every TCP run.
    TcpStats { id: Option<u64> },
    /// Stop a TCP run and show its final counters.
    TcpStop { id: u64 },
    /// Start a stateful UDP run from a UDP profile (see `ferotrx udp --help`).
    /// PATH is on the server, unless --upload sends the local file.
    UdpStart {
        path: PathBuf,
        /// Send this machine's file to the server.
        #[arg(short, long)]
        upload: bool,
        /// With --upload: folder on the server that a relative `pcap` path is in.
        #[arg(long, requires = "upload")]
        base_dir: Option<PathBuf>,
        /// Interface of the server for hosts whose table names none.
        #[arg(short, long)]
        iface: Option<String>,
        /// Transactions per second instead of the profile's.
        #[arg(long)]
        rate: Option<f64>,
        /// Transactions in all instead of the profile's; 0 = until stopped.
        #[arg(short = 'n', long)]
        transactions: Option<u64>,
        /// Stop after this long, e.g. 30s.
        #[arg(short, long)]
        duration: Option<String>,
        /// Engine threads on the server to spread the run over.
        #[arg(long)]
        workers: Option<u16>,
        /// Impair the frames the run sends (see `ferotrx tcp --help`).
        #[arg(long, value_name = "SPEC")]
        impair: Option<String>,
        /// Impair the frames the run receives.
        #[arg(long, value_name = "SPEC")]
        impair_rx: Option<String>,
    },
    /// Show the counters of one UDP run, or of every UDP run.
    UdpStats { id: Option<u64> },
    /// Stop a UDP run and show its final counters.
    UdpStop { id: u64 },
    /// Start a receiver on an interface of the server, counting the loss and
    /// latency of flows with signatures sent from elsewhere (`--latency`).
    RxStart {
        iface: String,
        /// Stop after this long, e.g. 60s; otherwise until `rx-stop`.
        #[arg(short, long)]
        duration: Option<String>,
    },
    /// Show the flows of one receiver, or of every receiver.
    RxStats { id: Option<u64> },
    /// Stop a receiver and show its final counters.
    RxStop { id: u64 },
    /// Call any method with JSON parameters and print the JSON result.
    Call {
        method: String,
        /// Parameters as a JSON object, e.g. '{"id": 1}'.
        params: Option<String>,
    },
}

#[derive(Args)]
struct StartArgs {
    /// Name of a loaded profile.
    profile: String,

    #[command(flatten)]
    output: RemoteOutput,

    #[command(flatten)]
    send: crate::SendArgs,

    /// Rate for every stream instead of the profile's, e.g. 10kpps or 100mbps.
    #[arg(short, long)]
    rate: Option<String>,

    /// Stop after this many packets in total.
    #[arg(long)]
    limit: Option<u64>,

    /// Stop after this long, e.g. 30s or 5m.
    #[arg(short, long)]
    duration: Option<String>,

    /// Count failed sends and keep going instead of failing the run.
    #[arg(long)]
    ignore_errors: bool,

    /// Receive on this interface of the server while the run goes, and
    /// report loss and latency per stream (see `ferotrx run --help`).
    #[arg(long, value_name = "IFACE")]
    rx: Option<String>,

    /// Put a latency signature in every stream's packets.
    #[arg(long)]
    latency: bool,

    /// Impairments for every stream instead of the profile's (see `ferotrx
    /// run --help`).
    #[arg(long, value_name = "SPEC")]
    impair: Option<String>,

    /// With --rx: how long to keep receiving after the last packet, e.g. 1s.
    #[arg(long, value_name = "TIME", requires = "rx")]
    rx_wait: Option<String>,

    /// Follow the run's counters until it ends.
    #[arg(short, long)]
    watch: bool,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct RemoteOutput {
    /// Send on this interface of the server (a DPDK device with `--backend dpdk`).
    #[arg(short, long)]
    iface: Option<String>,

    /// Write to this pcap file on the server.
    #[arg(short, long)]
    out: Option<PathBuf>,

    /// Discard the packets.
    #[arg(long)]
    null: bool,
}

pub fn cmd_ctl(args: CtlArgs) -> Result<()> {
    let addr = args
        .connect
        .or_else(|| std::env::var(ADDR_ENV).ok())
        .unwrap_or_else(|| format!("127.0.0.1:{DEFAULT_PORT}"));
    let addr = if addr.contains(':') {
        addr
    } else {
        format!("{addr}:{DEFAULT_PORT}")
    };
    let path_env =
        |arg: Option<PathBuf>, env: &str| arg.or_else(|| env_or(None, env).map(PathBuf::from));
    let ca = path_env(args.ca, CA_ENV);
    let cert = path_env(args.cert, CERT_ENV);
    let key = path_env(args.key, KEY_ENV);
    let mut c = match ca {
        Some(ca) => {
            let mut tls = ClientTls::from_ca_file(&ca)?;
            match (cert, key) {
                (Some(cert), Some(key)) => tls = tls.with_client_cert_files(&cert, &key)?,
                (None, None) => {}
                _ => bail!("--cert and --key go together"),
            }
            if let Some(n) = args.server_name {
                tls = tls.with_server_name(n);
            }
            Client::connect_tls(&addr, &tls).with_context(|| format!("cannot connect to {addr}"))?
        }
        None => {
            if cert.is_some() || key.is_some() || args.server_name.is_some() {
                bail!("--cert, --key and --server-name need --ca (TLS)");
            }
            Client::connect(&addr).with_context(|| format!("cannot connect to {addr}"))?
        }
    };
    if let Some(token) = env_or(args.token, TOKEN_ENV) {
        c.auth(&token)?;
    }
    let json = args.json;
    match args.command {
        CtlCommand::Info => {
            let i = c.info()?;
            if json {
                return print_json(&i);
            }
            println!("{} {} (protocol {})", i.name, i.version, i.protocol);
            println!(
                "interfaces: {}",
                if i.interfaces {
                    "yes"
                } else {
                    "no (built without interface backends)"
                }
            );
            if !i.backends.is_empty() {
                println!("backends: {}", i.backends.join(", "));
            }
            println!("tls: {}", if i.tls { "yes" } else { "no" });
            println!(
                "login required: {}",
                if i.auth_required { "yes" } else { "no" }
            );
            match (&i.role, &i.user) {
                (Some(r), Some(u)) => println!("logged in as: {u} ({r})"),
                (Some(r), None) => println!("access: {r}"),
                _ => println!("logged in: no"),
            }
        }
        CtlCommand::Interfaces => {
            let list = c.interfaces()?;
            if json {
                return print_json(&list);
            }
            for i in list {
                match i.description {
                    Some(d) => println!("{}\t{d}", i.name),
                    None => println!("{}", i.name),
                }
            }
        }
        CtlCommand::Load {
            path,
            name,
            upload,
            base_dir,
        } => {
            let params = if upload {
                let text = std::fs::read_to_string(&path)
                    .with_context(|| format!("cannot read {}", path.display()))?;
                let name =
                    name.or_else(|| path.file_stem().map(|s| s.to_string_lossy().into_owned()));
                LoadProfileParams {
                    name,
                    toml: Some(text),
                    base_dir,
                    ..Default::default()
                }
            } else {
                LoadProfileParams {
                    name,
                    path: Some(path),
                    ..Default::default()
                }
            };
            let p = c.load_profile(&params)?;
            if json {
                return print_json(&p);
            }
            print_profile(&p);
        }
        CtlCommand::Profiles => {
            let list = c.profiles()?;
            if json {
                return print_json(&list);
            }
            if list.is_empty() {
                println!("no profiles loaded");
            }
            for p in &list {
                print_profile(p);
            }
        }
        CtlCommand::Unload { name } => c.unload_profile(&name)?,
        CtlCommand::Start(s) => {
            let params = StartParams {
                profile: s.profile,
                output: {
                    let send = s.send.settings()?;
                    OutputSpec {
                        iface: s.output.iface,
                        file: s.output.out,
                        null: s.output.null,
                        backend: send.backend.map(|b| b.name().to_string()),
                        queue: send.queue,
                        xdp_mode: send.xdp_mode.map(|m| m.name().to_string()),
                        batch: send.batch,
                        dpdk_args: send.dpdk_args,
                        workers: send.workers,
                    }
                },
                rate: s.rate,
                limit: s.limit,
                duration: s.duration,
                ignore_errors: s.ignore_errors,
                latency: s.latency,
                rx: s.rx.map(|iface| RxSpec {
                    iface,
                    wait: s.rx_wait,
                }),
                impair: s.impair,
                start_at: None,
            };
            let run = c.start(&params)?;
            if json && !s.watch {
                return print_json(&run);
            }
            if !json {
                println!("started run {} ({} to {})", run.id, run.profile, run.output);
            }
            if s.watch {
                return follow(&mut c, Some(run.id), 1000, json);
            }
        }
        CtlCommand::Stop { id } => {
            let run = c.stop(id)?;
            if json {
                return print_json(&run);
            }
            print_run(&run);
        }
        CtlCommand::Stats { id: Some(id) } => {
            let run = c.stats(id)?;
            if json {
                return print_json(&run);
            }
            print_run(&run);
        }
        CtlCommand::Stats { id: None } => {
            let runs = c.runs()?;
            if json {
                return print_json(&runs);
            }
            if runs.is_empty() {
                println!("no runs");
            }
            for r in &runs {
                print_run(r);
            }
        }
        CtlCommand::Watch { id, interval } => return follow(&mut c, id, interval, json),
        CtlCommand::Remove { id } => {
            let run = c.remove(id)?;
            if json {
                return print_json(&run);
            }
            print_run(&run);
        }
        CtlCommand::TcpStart {
            path,
            upload,
            base_dir,
            iface,
            cps,
            connections,
            duration,
            workers,
            impair,
            impair_rx,
            congestion,
            ecn,
        } => {
            let mut params = TcpStartParams {
                iface,
                cps,
                connections,
                duration,
                workers,
                impair,
                impair_rx,
                congestion,
                ecn: ecn.then_some(true),
                ..Default::default()
            };
            if upload {
                params.toml = Some(
                    std::fs::read_to_string(&path)
                        .with_context(|| format!("cannot read {}", path.display()))?,
                );
                params.base_dir = base_dir;
            } else {
                params.path = Some(path);
            }
            let run = c.tcp_start(&params)?;
            if json {
                return print_json(&run);
            }
            crate::tcp::print_tcp_run(&run);
        }
        CtlCommand::TcpStats { id: Some(id) } => {
            let run = c.tcp_stats(id)?;
            if json {
                return print_json(&run);
            }
            crate::tcp::print_tcp_run(&run);
        }
        CtlCommand::TcpStats { id: None } => {
            let runs = c.tcp_runs()?;
            if json {
                return print_json(&runs);
            }
            if runs.is_empty() {
                println!("no TCP runs");
            }
            for r in &runs {
                crate::tcp::print_tcp_run(r);
            }
        }
        CtlCommand::TcpStop { id } => {
            let run = c.tcp_stop(id)?;
            if json {
                return print_json(&run);
            }
            crate::tcp::print_tcp_run(&run);
        }
        CtlCommand::UdpStart {
            path,
            upload,
            base_dir,
            iface,
            rate,
            transactions,
            duration,
            workers,
            impair,
            impair_rx,
        } => {
            let mut params = UdpStartParams {
                iface,
                rate,
                transactions,
                duration,
                workers,
                impair,
                impair_rx,
                ..Default::default()
            };
            if upload {
                params.toml = Some(
                    std::fs::read_to_string(&path)
                        .with_context(|| format!("cannot read {}", path.display()))?,
                );
                params.base_dir = base_dir;
            } else {
                params.path = Some(path);
            }
            let run = c.udp_start(&params)?;
            if json {
                return print_json(&run);
            }
            crate::udp::print_udp_run(&run);
        }
        CtlCommand::UdpStats { id: Some(id) } => {
            let run = c.udp_stats(id)?;
            if json {
                return print_json(&run);
            }
            crate::udp::print_udp_run(&run);
        }
        CtlCommand::UdpStats { id: None } => {
            let runs = c.udp_runs()?;
            if json {
                return print_json(&runs);
            }
            if runs.is_empty() {
                println!("no UDP runs");
            }
            for r in &runs {
                crate::udp::print_udp_run(r);
            }
        }
        CtlCommand::UdpStop { id } => {
            let run = c.udp_stop(id)?;
            if json {
                return print_json(&run);
            }
            crate::udp::print_udp_run(&run);
        }
        CtlCommand::RxStart { iface, duration } => {
            let r = c.rx_start(&RxStartParams { iface, duration })?;
            if json {
                return print_json(&r);
            }
            println!("started receiver {} on {}", r.id, r.counters.iface);
        }
        CtlCommand::RxStats { id: Some(id) } => {
            let r = c.rx_stats(id)?;
            if json {
                return print_json(&r);
            }
            print_rx_run(&r);
        }
        CtlCommand::RxStats { id: None } => {
            let list = c.rx_runs()?;
            if json {
                return print_json(&list);
            }
            if list.is_empty() {
                println!("no receivers");
            }
            for r in &list {
                print_rx_run(r);
            }
        }
        CtlCommand::RxStop { id } => {
            let r = c.rx_stop(id)?;
            if json {
                return print_json(&r);
            }
            print_rx_run(&r);
        }
        CtlCommand::Call { method, params } => {
            let params: Value = match params {
                Some(p) => serde_json::from_str(&p).context("params are not valid JSON")?,
                None => Value::Null,
            };
            print_json(&c.call_value(&method, params)?)?;
        }
    }
    Ok(())
}

/// Prints `stats` updates until the run ends (or for ever, for all runs).
fn follow(c: &mut Client, id: Option<u64>, interval: u64, json: bool) -> Result<()> {
    c.subscribe(id, interval)?;
    loop {
        let u = c.next_stats()?;
        if json {
            println!("{}", serde_json::to_string(&u)?);
        } else if u.last {
            print_run(&u.run);
        } else {
            print_counters(&format!("run {}", u.run.id), &u.run.total);
        }
        if u.last && id.is_some() {
            if u.run.state == RunState::Failed {
                bail!("run {} failed", u.run.id);
            }
            return Ok(());
        }
    }
}

fn print_json(v: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn print_profile(p: &ProfileInfo) {
    println!("profile {}:", p.name);
    for s in &p.streams {
        let mut line = format!("  {}: {} at {}", s.name, s.source, s.rate);
        if s.loops != 1 {
            line.push_str(&format!(
                ", loops {}",
                if s.loops == 0 {
                    "forever".to_string()
                } else {
                    s.loops.to_string()
                }
            ));
        }
        if !s.rewrite.is_empty() {
            line.push_str(&format!(", rewrite {}", s.rewrite.join(" ")));
        }
        if !s.vary.is_empty() {
            line.push_str(&format!(", vary {}", s.vary.join(" ")));
        }
        if let Some(flow) = s.latency {
            line.push_str(&format!(", latency flow {flow}"));
        }
        println!("{line}");
    }
}

fn print_run(r: &RunInfo) {
    let state = match r.state {
        RunState::Running => "running",
        RunState::Finished => "finished",
        RunState::Stopped => "stopped",
        RunState::Failed => "failed",
    };
    println!("run {} ({} to {}): {state}", r.id, r.profile, r.output);
    if let Some(e) = &r.error {
        println!("  error: {e}");
    }
    for s in &r.streams {
        print_counters(&format!("  {}", s.name), &s.counters);
    }
    print_counters("  total", &r.total);
    for s in &r.streams {
        if let Some(i) = &s.impair {
            println!(
                "  {} impairments: {}",
                s.name,
                crate::impair_counters_line(i)
            );
        }
    }
    if let Some(rx) = &r.rx {
        let rows: Vec<_> = r
            .streams
            .iter()
            .filter_map(|s| Some((s.name.clone(), s.latency.clone()?)))
            .collect();
        println!("  loss and latency (received on {}):", rx.iface);
        for line in crate::latency::flow_lines(&rows) {
            println!("{line}");
        }
    }
}

fn print_rx_run(r: &RxRunInfo) {
    let state = format!("{:?}", r.state).to_lowercase();
    println!(
        "receiver {} on {}: {state}, {} frames in {:.3} s, {} without a signature",
        r.id, r.counters.iface, r.counters.packets, r.counters.elapsed_s, r.counters.untagged
    );
    if let Some(e) = &r.error {
        println!("  error: {e}");
    }
    let rows: Vec<_> = r
        .flows
        .iter()
        .map(|f| (format!("flow {}", f.flow), f.clone()))
        .collect();
    for line in crate::latency::flow_lines(&rows) {
        println!("{line}");
    }
}

fn print_counters(label: &str, s: &Counters) {
    let mut line = format!(
        "{label}: {} packets, {} bytes in {:.3} s ({:.1} pps, {:.3} Mbps)",
        s.packets, s.bytes, s.elapsed_s, s.pps, s.mbps
    );
    if s.send_errors > 0 {
        line.push_str(&format!(", {} send errors", s.send_errors));
    }
    println!("{line}");
}

#[derive(Args)]
pub struct CertsArgs {
    /// Directory for the certificates and keys; the CAs in it are reused
    /// when they are there already.
    dir: PathBuf,

    /// Issue the server's certificate for these names and addresses (the
    /// ones clients give to --connect), comma separated or repeated.
    #[arg(long, value_name = "HOST", value_delimiter = ',')]
    server: Vec<String>,

    /// Issue an operator client certificate with this name. Repeatable.
    #[arg(long, value_name = "NAME", value_delimiter = ',')]
    client: Vec<String>,

    /// Issue a read-only client certificate with this name. Repeatable.
    #[arg(long, value_name = "NAME", value_delimiter = ',')]
    read_client: Vec<String>,
}

pub fn cmd_certs(args: CertsArgs) -> Result<()> {
    if args.server.is_empty() && args.client.is_empty() && args.read_client.is_empty() {
        bail!("say what to issue: --server HOST, --client NAME or --read-client NAME");
    }
    let pki = LabPki::new(&args.dir);
    let mut files = Vec::new();
    if !args.server.is_empty() {
        files.extend(pki.issue_server(&args.server)?.files);
    }
    for n in &args.client {
        files.extend(pki.issue_client(n, Role::Operator)?.files);
    }
    for n in &args.read_client {
        files.extend(pki.issue_client(n, Role::Read)?.files);
    }
    for f in &files {
        println!("wrote {}", f.display());
    }
    let d = args.dir.display();
    println!();
    let read_ca = if pki.path("read-ca.pem").exists() {
        format!(" --read-client-ca {d}/read-ca.pem")
    } else {
        String::new()
    };
    println!("server: ferotrx serve -l 0.0.0.0:{DEFAULT_PORT} --tls-cert {d}/server.pem --tls-key {d}/server-key.pem --client-ca {d}/ca.pem{read_ca}");
    let host = args
        .server
        .first()
        .map(|h| {
            if h.contains(':') {
                format!("[{h}]")
            } else {
                h.clone()
            }
        })
        .unwrap_or_else(|| "<server address>".into());
    let names: Vec<&String> = args.client.iter().chain(&args.read_client).collect();
    if names.is_empty() {
        println!("client: ferotrx ctl -c {host} --ca {d}/ca.pem --cert {d}/<name>.pem --key {d}/<name>-key.pem info");
    }
    for n in names {
        println!("client: ferotrx ctl -c {host} --ca {d}/ca.pem --cert {d}/{n}.pem --key {d}/{n}-key.pem info");
    }
    println!("Keep the *-key.pem files private; copy only ca.pem and a client's own pair to it.");
    Ok(())
}
