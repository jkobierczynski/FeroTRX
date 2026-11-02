//! `ferotrx serve` and `ferotrx ctl`: the control server and its command line client.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use ferotrx_core::Profile;
use ferotrx_ctl::protocol::{
    Counters, LoadProfileParams, OutputSpec, ProfileInfo, RunInfo, RunState, StartParams,
    TcpStartParams, DEFAULT_PORT,
};
use ferotrx_ctl::{Client, Controller, Server};
use serde_json::Value;

const TOKEN_ENV: &str = "FEROTRX_TOKEN";
const ADDR_ENV: &str = "FEROTRX_CTL";

#[derive(Args)]
pub struct ServeArgs {
    /// Address to listen on. Use 0.0.0.0:4510 (or the lab-facing address) to
    /// accept other machines, and set a token when you do.
    #[arg(short, long, default_value_t = format!("127.0.0.1:{DEFAULT_PORT}"))]
    listen: String,

    /// Shared secret clients must send with `auth` before anything else.
    /// Also read from FEROTRX_TOKEN.
    #[arg(long)]
    token: Option<String>,

    /// Load this profile at start, under its file name (or NAME=PATH). Repeatable.
    #[arg(short, long = "profile", value_name = "[NAME=]PATH")]
    profiles: Vec<String>,
}

pub fn cmd_serve(args: ServeArgs) -> Result<()> {
    let token = args
        .token
        .or_else(|| std::env::var(TOKEN_ENV).ok())
        .filter(|t| !t.is_empty());
    let controller = Controller::new();
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
    let server = Server::bind(&args.listen, controller, token.clone())
        .with_context(|| format!("cannot listen on {}", args.listen))?;
    let addr = server.local_addr()?;
    if !addr.ip().is_loopback() && token.is_none() {
        eprintln!("warning: listening on {addr} without a token; anyone who can reach it can send traffic from this machine");
    }
    {
        let controller = server.controller().clone();
        ctrlc::set_handler(move || {
            eprintln!("stopping runs");
            controller.stop_all();
            std::process::exit(0);
        })
        .context("cannot install Ctrl-C handler")?;
    }
    eprintln!(
        "ferotrx control server on {addr}{}; Ctrl-C to stop",
        if token.is_some() {
            " (token required)"
        } else {
            ""
        }
    );
    server.serve()?;
    Ok(())
}

#[derive(Args)]
pub struct CtlArgs {
    /// Server address. Also read from FEROTRX_CTL.
    #[arg(short, long, value_name = "HOST:PORT")]
    connect: Option<String>,

    /// Token for a server started with --token. Also read from FEROTRX_TOKEN.
    #[arg(long)]
    token: Option<String>,

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
    },
    /// Show the counters of one TCP run, or of every TCP run.
    TcpStats { id: Option<u64> },
    /// Stop a TCP run and show its final counters.
    TcpStop { id: u64 },
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
    let mut c = Client::connect(&addr).with_context(|| format!("cannot connect to {addr}"))?;
    if let Some(token) = args
        .token
        .or_else(|| std::env::var(TOKEN_ENV).ok())
        .filter(|t| !t.is_empty())
    {
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
            println!(
                "token required: {}",
                if i.auth_required { "yes" } else { "no" }
            );
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
                    }
                },
                rate: s.rate,
                limit: s.limit,
                duration: s.duration,
                ignore_errors: s.ignore_errors,
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
        } => {
            let mut params = TcpStartParams {
                iface,
                cps,
                connections,
                duration,
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
