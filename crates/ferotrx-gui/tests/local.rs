//! "This computer": the GUI starts `ferotrx serve`, logs in with the token
//! it made up, and the server stops when the GUI stops it.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use ferotrx_gui::local::{wait_for_address, LocalServer};

/// target/debug/ferotrx, built by `cargo build -p ferotrx-cli`.
fn ferotrx() -> Option<PathBuf> {
    let deps = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let exe = deps
        .parent()?
        .join(format!("ferotrx{}", std::env::consts::EXE_SUFFIX));
    exe.is_file().then_some(exe)
}

#[test]
fn a_local_server_starts_and_stops() {
    let Some(exe) = ferotrx() else {
        eprintln!("skipped: build ferotrx first (cargo build -p ferotrx-cli)");
        return;
    };
    if ferotrx_gui::local::needs_elevation() {
        eprintln!("skipped: Npcap is for administrators only here (a UAC prompt)");
        return;
    }
    let folder = std::env::temp_dir();
    let mut server = LocalServer::start_with(&exe, &[folder]).unwrap();
    let addr = match wait_for_address(&server.port_file, Duration::from_secs(30)) {
        Ok(a) => a,
        Err(e) => {
            // Say why: a server that ended (a crash, a refused argument)
            // leaves its status and its standard error behind.
            let ended = server.ended().unwrap_or_else(|| "still running".into());
            let log = std::fs::read_to_string(&server.log).unwrap_or_default();
            panic!("{e}: {ended}\nserver.log:\n{log}");
        }
    };
    assert!(addr.starts_with("127.0.0.1:"), "{addr}");

    // Without the token: nothing but login.
    let mut c = ferotrx_ctl::Client::connect(addr.as_str()).unwrap();
    assert!(c.call_value("run.list", serde_json::Value::Null).is_err());
    let mut c = ferotrx_ctl::Client::connect(addr.as_str()).unwrap();
    c.call_value("auth", serde_json::json!({ "token": server.token }))
        .unwrap();
    let info = c.info().unwrap();
    assert_eq!(info.same_machine(), Some(true));
    drop(c);

    let dir = server.dir.clone();
    server.stop();
    assert!(server.ended().is_none(), "stop() already reaped it");
    let until = Instant::now() + Duration::from_secs(5);
    while ferotrx_ctl::Client::connect(addr.as_str()).is_ok() {
        assert!(Instant::now() < until, "the server still answers");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(!dir.exists(), "the session folder stays");
}
