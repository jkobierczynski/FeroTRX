//! `ferotrx-gui`: the FeroTRX desktop GUI.

// A window, not a console program, on Windows: no console behind the GUI.
// Started from a terminal it attaches to that console for --help and errors.
#![cfg_attr(windows, windows_subsystem = "windows")]

use clap::Parser;
use ferotrx_gui::conn::ConnSettings;
use ferotrx_gui::{FeroApp, Options};

/// FeroTRX GUI: build streams, send them through `ferotrx serve` servers,
/// and watch the counters.
///
/// Without --connect it shows the servers of the last session (or, the
/// first time, "This computer": a server the GUI starts itself). FEROTRX_CTL, FEROTRX_CA, FEROTRX_CERT, FEROTRX_KEY
/// and FEROTRX_TOKEN work as for `ferotrx ctl`.
#[derive(Parser)]
#[command(name = "ferotrx-gui", version)]
struct Args {
    /// Server to connect to at start (host[:port], port 4510 by default).
    #[arg(short, long, conflicts_with = "local")]
    connect: Option<String>,
    /// Start a server on this computer and connect to it ("This computer").
    #[arg(long)]
    local: bool,
    /// CA certificate (PEM) of the server: connect over TLS.
    #[arg(long, value_name = "FILE")]
    ca: Option<String>,
    /// Client certificate (PEM) for mutual TLS.
    #[arg(long, value_name = "FILE", requires = "key")]
    cert: Option<String>,
    /// Key of --cert (PEM).
    #[arg(long, value_name = "FILE", requires = "cert")]
    key: Option<String>,
    /// Token to log in with (better: FEROTRX_TOKEN).
    #[arg(long)]
    token: Option<String>,
    /// Port to open: an interface of the server, `file` or `null`.
    #[arg(short, long)]
    port: Option<String>,
    /// Profile file whose streams to load into that port.
    #[arg(long, value_name = "FILE")]
    profile: Option<String>,
    /// A scenario to open in the Scenario tab.
    #[arg(long, value_name = "FILE")]
    scenario: Option<String>,
    /// A file to open: a workspace (*.ferotrx), a profile or scenario
    /// (*.ftstream, *.fttcp, *.ftudp, *.ftscenario, *.ftbench, *.fty1564,
    /// *.toml) in the tab of its kind, else a capture (how Windows opens
    /// these files with the GUI).
    file: Option<String>,
    /// A workspace file (*.ferotrx) to open: servers, streams, forms, layout.
    #[arg(short, long, value_name = "FILE")]
    workspace: Option<String>,
    /// A theme file (TOML, see the Appearance window) to use.
    #[arg(long, value_name = "FILE")]
    theme: Option<String>,
}

/// The FeroTRX icon, for the window and the task bar.
const ICON: &[u8] = include_bytes!("../assets/icon-256.png");

#[cfg(windows)]
fn attach_console() {
    use windows_sys::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
    // Only when started from a console; from Explorer there is none, and
    // nothing to print to.
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

fn main() -> eframe::Result {
    #[cfg(windows)]
    attach_console();
    let mut args = Args::parse();
    // A file given on its own: a workspace or a profile by its extension,
    // else a capture.
    let mut capture = args.file.take();
    let mut open = None;
    if let Some(f) = capture.as_deref() {
        if f.to_ascii_lowercase().ends_with(".ferotrx") && args.workspace.is_none() {
            args.workspace = capture.take();
        } else if ferotrx_core::check::FileKind::is_profile_path(std::path::Path::new(f)) {
            open = capture.take();
        }
    }
    let mut connect = Vec::new();
    let env = ConnSettings::from_env();
    if let Some(addr) = args.connect {
        let mut s = env.unwrap_or_default();
        s.addr = addr;
        if let Some(ca) = args.ca {
            s.tls = true;
            s.ca = ca;
        }
        if let Some(c) = args.cert {
            s.cert = c;
        }
        if let Some(k) = args.key {
            s.key = k;
        }
        if let Some(t) = args.token {
            s.token = t;
        }
        connect.push(s);
    } else if args.local {
        connect.push(ConnSettings::this_computer());
    } else if let Some(s) = env {
        connect.push(s);
    }
    let opts = Options {
        connect,
        capture,
        port: args.port,
        profile: args.profile,
        scenario: args.scenario,
        workspace: args.workspace,
        theme: args.theme,
        open,
    };
    let native = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("FeroTRX")
            .with_app_id("ferotrx-gui")
            .with_inner_size([1280.0, 860.0])
            .with_min_inner_size([800.0, 560.0])
            .with_icon(eframe::icon_data::from_png_bytes(ICON).unwrap_or_default()),
        ..Default::default()
    };
    eframe::run_native(
        "FeroTRX",
        native,
        Box::new(|cc| Ok(Box::new(FeroApp::new(cc, opts)))),
    )
}
