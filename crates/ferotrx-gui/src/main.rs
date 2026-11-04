//! `ferotrx-gui`: the FeroTRX desktop GUI.

use clap::Parser;
use ferotrx_gui::conn::ConnSettings;
use ferotrx_gui::{FeroApp, Options};

/// FeroTRX GUI: build streams, send them through `ferotrx serve` servers,
/// and watch the counters.
///
/// Without --connect it connects to the servers of the last session (or
/// offers 127.0.0.1:4510). FEROTRX_CTL, FEROTRX_CA, FEROTRX_CERT, FEROTRX_KEY
/// and FEROTRX_TOKEN work as for `ferotrx ctl`.
#[derive(Parser)]
#[command(name = "ferotrx-gui", version)]
struct Args {
    /// Server to connect to at start (host[:port], port 4510 by default).
    #[arg(short, long)]
    connect: Option<String>,
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
    /// A capture to open in the Capture tab.
    capture: Option<String>,
}

fn main() -> eframe::Result {
    let args = Args::parse();
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
    } else if let Some(s) = env {
        connect.push(s);
    }
    let opts = Options {
        connect,
        capture: args.capture,
        port: args.port,
        profile: args.profile,
    };
    let native = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("FeroTRX")
            .with_app_id("ferotrx-gui")
            .with_inner_size([1280.0, 860.0])
            .with_min_inner_size([800.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native(
        "FeroTRX",
        native,
        Box::new(|cc| Ok(Box::new(FeroApp::new(cc, opts)))),
    )
}
