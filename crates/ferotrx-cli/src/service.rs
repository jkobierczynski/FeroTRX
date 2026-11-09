//! `ferotrx service`: the control server as a Windows service, so that it
//! runs from boot without anyone logged in, as LocalSystem (which may use
//! Npcap even when Npcap is for administrators only).
//!
//! `install` registers `ferotrx service run <serve arguments>` with the
//! service manager; the service manager then starts `run`, which serves
//! until the service is stopped. The service's files live in
//! `%ProgramData%\FeroTRX`: `data` (the default data directory),
//! `audit.log`, `service.log` (why it could not start) and `tokens.toml`
//! (tokens given with --token, as SHA-256 only).

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::remote;

/// The service's name (`sc query FeroTRX`).
pub const NAME: &str = "FeroTRX";
const DISPLAY: &str = "FeroTRX control server";
const DESCRIPTION: &str =
    "Runs ferotrx serve: the FeroTRX GUI and ferotrx ctl load profiles and start runs through it.";

#[derive(Args)]
pub struct ServiceArgs {
    #[command(subcommand)]
    cmd: ServiceCmd,
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Install the service (from an administrator prompt) and start it.
    /// Everything after `--` is given to `ferotrx serve`, e.g.
    /// `ferotrx service install -- --token SECRET`. Without --data-dir it
    /// serves %ProgramData%\FeroTRX\data, without --audit-log it logs to
    /// %ProgramData%\FeroTRX\audit.log.
    Install(InstallArgs),
    /// Stop and remove the service.
    Remove,
    /// Start the installed service.
    Start,
    /// Stop the service (and its runs).
    Stop,
    /// Show whether the service is installed and running, and how it starts.
    Status,
    /// What the service manager starts; not for use from a prompt.
    #[command(hide = true)]
    Run {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        serve: Vec<String>,
    },
}

#[derive(Args)]
struct InstallArgs {
    /// Start only on `ferotrx service start`, not at boot.
    #[arg(long)]
    manual: bool,
    /// Install without starting it now.
    #[arg(long)]
    no_start: bool,
    /// The arguments of `ferotrx serve`.
    #[arg(last = true)]
    serve: Vec<String>,
}

pub fn cmd_service(args: ServiceArgs) -> Result<()> {
    match args.cmd {
        ServiceCmd::Install(a) => install(a),
        ServiceCmd::Remove => remove(),
        ServiceCmd::Start => {
            open(ServiceAccess::START | ServiceAccess::QUERY_STATUS)?
                .start::<&str>(&[])
                .context("cannot start the service")?;
            wait_for(ServiceState::Running)?;
            eprintln!("{NAME} is running");
            Ok(())
        }
        ServiceCmd::Stop => {
            let s = open(ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
            if s.query_status()?.current_state != ServiceState::Stopped {
                s.stop().context("cannot stop the service")?;
            }
            wait_for(ServiceState::Stopped)?;
            eprintln!("{NAME} stopped");
            Ok(())
        }
        ServiceCmd::Status => status(),
        ServiceCmd::Run { serve } => run(serve),
    }
}

/// `%ProgramData%\FeroTRX`.
pub fn home() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"))
        .join("FeroTRX")
}

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access).map_err(|e| {
        anyhow::anyhow!(
            "cannot reach the service manager ({e}); run this from an administrator prompt"
        )
    })
}

fn open(access: ServiceAccess) -> Result<windows_service::service::Service> {
    manager(ServiceManagerAccess::CONNECT)?
        .open_service(NAME, access)
        .map_err(|e| anyhow::anyhow!("cannot open the {NAME} service ({e}); is it installed (ferotrx service install), and is this an administrator prompt?"))
}

fn wait_for(state: ServiceState) -> Result<()> {
    let s = open(ServiceAccess::QUERY_STATUS)?;
    for _ in 0..100 {
        if s.query_status()?.current_state == state {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let now = s.query_status()?;
    bail!(
        "the service is {:?}, not {state:?}, after 10 s; see {}",
        now.current_state,
        home().join("service.log").display()
    )
}

/// Does `args` give option `name` (`--name V` or `--name=V`)?
fn has_option(args: &[String], name: &str) -> bool {
    args.iter()
        .any(|a| a == name || a.starts_with(&format!("{name}=")))
}

/// Takes `--token`/`--read-token` out of `args`, returning their values.
fn take_option(args: &mut Vec<String>, name: &str) -> Option<String> {
    let i = args
        .iter()
        .position(|a| a == name || a.starts_with(&format!("{name}=")))?;
    let a = args.remove(i);
    match a.split_once('=') {
        Some((_, v)) => Some(v.to_string()),
        None if i < args.len() => Some(args.remove(i)),
        None => None,
    }
}

fn sha256_hex(secret: &str) -> String {
    ferotrx_ctl::sha256_hex(secret.as_bytes())
}

/// The serve arguments the service starts with: tokens moved into a file
/// (the command line of a service is readable by every user), and the
/// ProgramData defaults.
fn service_args(
    mut args: Vec<String>,
    home: &std::path::Path,
) -> Result<(Vec<String>, Option<String>)> {
    let mut tokens = String::new();
    for (opt, name, role) in [
        ("--token", "operator", "operator"),
        ("--read-token", "read", "read"),
        ("--admin-token", "admin", "admin"),
    ] {
        if let Some(t) = take_option(&mut args, opt) {
            if t.is_empty() {
                bail!("{opt} needs a value");
            }
            tokens.push_str(&format!(
                "[[token]]\nname = \"{name}\"\nrole = \"{role}\"\nsha256 = \"{}\"\n",
                sha256_hex(&t)
            ));
        }
    }
    let tokens_file = (!tokens.is_empty()).then(|| {
        let f = home.join("tokens.toml");
        args.push("--tokens".into());
        args.push(f.display().to_string());
        tokens
    });
    if !has_option(&args, "--data-dir") {
        args.push("--data-dir".into());
        args.push(home.join("data").display().to_string());
    }
    if !has_option(&args, "--audit-log") {
        args.push("--audit-log".into());
        args.push(home.join("audit.log").display().to_string());
    }
    for bad in ["--port-file", "--parent"] {
        if has_option(&args, bad) {
            bail!("{bad} is for servers that a program starts, not for the service");
        }
    }
    // Check them the way `serve` will, now rather than at boot.
    remote::parse_serve_args(&args).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok((args, tokens_file))
}

fn install(a: InstallArgs) -> Result<()> {
    let home = home();
    let (serve, tokens) = service_args(a.serve, &home)?;
    let m = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    std::fs::create_dir_all(home.join("data"))
        .with_context(|| format!("cannot create {}", home.join("data").display()))?;
    if let Some(t) = tokens {
        std::fs::write(home.join("tokens.toml"), t)
            .with_context(|| format!("cannot write {}", home.join("tokens.toml").display()))?;
    }
    let exe = std::env::current_exe()?;
    let mut launch: Vec<OsString> = vec!["service".into(), "run".into()];
    launch.extend(serve.iter().map(OsString::from));
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: DISPLAY.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: if a.manual {
            ServiceStartType::OnDemand
        } else {
            ServiceStartType::AutoStart
        },
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.clone(),
        launch_arguments: launch,
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    };
    let s = m
        .create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|e| {
            anyhow::anyhow!("cannot install the service ({e}); is it installed already (ferotrx service remove)?")
        })?;
    let _ = s.set_description(DESCRIPTION);
    eprintln!(
        "installed {NAME}: {} service run {}",
        exe.display(),
        serve.join(" ")
    );
    if !a.no_start {
        s.start::<&str>(&[]).context("cannot start the service")?;
        wait_for(ServiceState::Running)?;
        eprintln!("{NAME} is running");
    }
    Ok(())
}

fn remove() -> Result<()> {
    let s = open(ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS)?;
    if s.query_status()?.current_state != ServiceState::Stopped {
        let _ = s.stop();
        wait_for(ServiceState::Stopped)?;
    }
    s.delete().context("cannot remove the service")?;
    drop(s);
    eprintln!("removed {NAME} (its files stay in {})", home().display());
    Ok(())
}

fn status() -> Result<()> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    let s = match m.open_service(
        NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG,
    ) {
        Ok(s) => s,
        Err(_) => {
            println!("{NAME}: not installed");
            return Ok(());
        }
    };
    let st = s.query_status()?;
    let cfg = s.query_config()?;
    println!(
        "{NAME}: {:?}, starts {:?}",
        st.current_state, cfg.start_type
    );
    println!("command: {}", cfg.executable_path.display());
    Ok(())
}

// ----- the service itself -----

define_windows_service!(ffi_service_main, service_main);

/// The arguments `run` was given, for the service's main to read.
static SERVE_ARGS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

fn run(serve: Vec<String>) -> Result<()> {
    let _ = SERVE_ARGS.set(serve);
    service_dispatcher::start(NAME, ffi_service_main).map_err(|e| {
        anyhow::anyhow!("{e}: `ferotrx service run` is what the service manager starts; use `ferotrx serve` from a prompt")
    })
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = serve_as_service() {
        log(&format!("{e:#}"));
    }
}

/// Appends a line to `%ProgramData%\FeroTRX\service.log`: a service has no
/// console to say why it could not start.
fn log(line: &str) {
    use std::io::Write;
    let home = home();
    let _ = std::fs::create_dir_all(&home);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(home.join("service.log"))
    {
        let now = ferotrx_core::unix_seconds(std::time::SystemTime::now());
        let _ = writeln!(f, "{now:.0} {line}");
    }
}

fn serve_as_service() -> Result<()> {
    let (stop_tx, stop_rx) = mpsc::channel();
    let handler = move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(NAME, handler)?;
    let set = |state, accept, exit: ServiceExitCode| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: exit,
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        })
    };
    set(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::NO_ERROR,
    )?;
    let args = SERVE_ARGS.get().cloned().unwrap_or_default();
    // Relative paths start in the service's folder, not System32.
    let _ = std::fs::create_dir_all(home());
    let _ = std::env::set_current_dir(home());
    let server = match remote::parse_serve_args(&args)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .and_then(remote::start_server)
    {
        Ok(s) => s,
        Err(e) => {
            set(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                ServiceExitCode::ServiceSpecific(1),
            )?;
            return Err(e);
        }
    };
    let controller = server.controller().clone();
    log(&format!(
        "serving on {}",
        server
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default()
    ));
    std::thread::spawn(move || {
        if let Err(e) = server.serve() {
            log(&format!("server: {e}"));
        }
    });
    set(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::NO_ERROR,
    )?;
    let _ = stop_rx.recv();
    set(
        ServiceState::StopPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::NO_ERROR,
    )?;
    controller.stop_all();
    log("stopped");
    set(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        ServiceExitCode::NO_ERROR,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_leave_the_command_line() {
        let home = std::path::Path::new("C:\\ProgramData\\FeroTRX");
        let (args, tokens) = service_args(
            vec![
                "--listen".into(),
                "0.0.0.0:4510".into(),
                "--token".into(),
                "s3cret".into(),
                "--read-token=look".into(),
            ],
            home,
        )
        .unwrap();
        let line = args.join(" ");
        assert!(!line.contains("s3cret") && !line.contains("look"), "{line}");
        assert!(line.contains("--tokens C:\\ProgramData\\FeroTRX\\tokens.toml"));
        assert!(line.contains("--data-dir C:\\ProgramData\\FeroTRX\\data"));
        assert!(line.contains("--audit-log C:\\ProgramData\\FeroTRX\\audit.log"));
        let t = tokens.unwrap();
        assert!(!t.contains("s3cret"));
        assert_eq!(ferotrx_ctl::Token::from_toml(&t).unwrap().len(), 2);
    }

    #[test]
    fn given_folders_stay() {
        let (args, tokens) = service_args(
            vec!["--data-dir".into(), "D:\\lab".into()],
            std::path::Path::new("C:\\x"),
        )
        .unwrap();
        assert!(tokens.is_none());
        assert_eq!(args.iter().filter(|a| *a == "--data-dir").count(), 1);
        assert!(service_args(
            vec!["--parent".into(), "1".into()],
            std::path::Path::new("C:\\x")
        )
        .is_err());
        assert!(service_args(vec!["--bogus".into()], std::path::Path::new("C:\\x")).is_err());
    }
}
