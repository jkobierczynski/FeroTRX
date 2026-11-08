//! Entry points for the control server's fuzz targets in `fuzz/` and its
//! hostile-input tests: any bytes a client sends must not panic, hang or
//! grow memory without bound.
//!
//! Not part of the API: built for tests and with the `fuzzing` feature.
//! The controllers here open no interfaces (every opener fails) and keep
//! files in a folder of their own.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde_json::Value;

use crate::{Controller, FilePolicy, Role, Server, ServerConfig, Token};

/// A target: takes the fuzzer's bytes.
pub type Target = fn(&[u8]);

/// The targets, by name.
pub const TARGETS: &[(&str, Target)] = &[("ctl_call", call), ("ctl_server", server)];

/// The operator token of [`server`]'s server.
pub const OPERATOR_TOKEN: &str = "fuzz-operator";
/// Its read-only token.
pub const READ_TOKEN: &str = "fuzz-read";

/// The files folder of the fuzzing controllers: one per process.
fn data_dir() -> PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let d = std::env::temp_dir().join(format!("ferotrx-fuzz-ctl-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        d
    })
    .clone()
}

fn no_interfaces() -> ferotrx_core::SinkError {
    "fuzzing: no interfaces".into()
}

/// A controller that opens nothing and keeps files small and in
/// [`data_dir`].
pub fn controller() -> Controller {
    let files = FilePolicy::dirs([data_dir()])
        .expect("the fuzzing folder")
        .with_max_upload(64 * 1024)
        .with_max_file(1 << 20);
    Controller::new()
        .with_file_policy(files)
        .with_port_opener(|_, _| Err(no_interfaces()))
        .with_receiver_opener(|_| Err(no_interfaces()))
        .with_capture_opener(|_, _| Err(no_interfaces()))
        .with_bench_sink_opener(|_, _, _, _| Err(no_interfaces()))
}

/// Lines of JSON-RPC requests straight into [`Controller::call`], as a
/// logged-in operator sends them: one request per line.
pub fn call(data: &[u8]) {
    let c = controller();
    for line in data.split(|&b| b == b'\n').take(64) {
        let Ok(v) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        let Some(method) = v.get("method").and_then(Value::as_str) else {
            continue;
        };
        let params = v.get("params").cloned().unwrap_or(Value::Null);
        let _ = c.call(method, params);
    }
    c.forget_all();
}

struct Running {
    addr: SocketAddr,
    server: Arc<Server>,
}

fn running() -> &'static Running {
    static SERVER: OnceLock<Running> = OnceLock::new();
    SERVER.get_or_init(|| {
        let config = ServerConfig {
            tokens: vec![
                Token::new("fuzz-op", Role::Operator, OPERATOR_TOKEN),
                Token::new("fuzz-read", Role::Read, READ_TOKEN),
            ],
            // Many connections one after another from one address: no
            // throttling, or later inputs would only see refusals.
            max_login_failures_per_ip: u32::MAX,
            max_login_failures: u32::MAX,
            max_request: 256 * 1024,
            idle_timeout: Some(Duration::from_secs(5)),
            login_timeout: Duration::from_secs(5),
            ..ServerConfig::default()
        };
        let server = Arc::new(
            Server::with_config("127.0.0.1:0", controller(), config).expect("a loopback port"),
        );
        let addr = server.local_addr().unwrap();
        let s = server.clone();
        std::thread::Builder::new()
            .name("ferotrx-fuzz-server".into())
            .spawn(move || {
                let _ = s.serve();
            })
            .unwrap();
        Running { addr, server }
    })
}

/// Bytes sent to a running control server over one TCP connection, as any
/// client could: the server must answer or close, and stay up for the
/// next input.
pub fn server(data: &[u8]) {
    let r = running();
    let mut s = TcpStream::connect(r.addr).expect("the fuzzing server is up");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    // The server may close early (a line too long, too many failed
    // logins): then the write fails, which is fine.
    let _ = s.write_all(data);
    let _ = s.shutdown(Shutdown::Write);
    let mut sink = [0u8; 16 * 1024];
    let mut got = 0usize;
    loop {
        match s.read(&mut sink) {
            Ok(0) => break,
            Ok(n) => {
                got += n;
                assert!(
                    got < 256 << 20,
                    "the server sent {got} bytes for {} in",
                    data.len()
                );
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                panic!("the server neither answered nor closed within 10 s");
            }
            Err(_) => break,
        }
    }
    r.server.controller().forget_all();
}

/// Starting inputs: a session of an operator and of a read-only login.
pub fn seeds(name: &str) -> Vec<Vec<u8>> {
    let profile = r#"format = 1
[[stream]]
name = "s"
packets = ["eth / ipv4 / udp dport=9 / payload size=18"]
rate = "100pps"
count = 10
"#;
    let calls: Vec<String> = vec![
        r#"{"jsonrpc":"2.0","id":1,"method":"server.info"}"#.into(),
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"profile.load",
            "params":{"name":"p","toml":profile}})
        .to_string(),
        r#"{"jsonrpc":"2.0","id":3,"method":"profile.list"}"#.into(),
        r#"{"jsonrpc":"2.0","id":4,"method":"run.start","params":{"profile":"p","null":true}}"#
            .into(),
        r#"{"jsonrpc":"2.0","id":5,"method":"run.list"}"#.into(),
        r#"{"jsonrpc":"2.0","id":6,"method":"run.stop","params":{"id":1,"wait":true}}"#.into(),
        r#"{"jsonrpc":"2.0","id":7,"method":"file.put","params":{"path":"a/b.txt","data":"aGVsbG8=","offset":0}}"#.into(),
        r#"{"jsonrpc":"2.0","id":8,"method":"file.stat","params":{"path":"a/b.txt"}}"#.into(),
        r#"{"jsonrpc":"2.0","id":9,"method":"file.get","params":{"path":"a/b.txt","offset":0,"length":4}}"#.into(),
        r#"{"jsonrpc":"2.0","id":10,"method":"tcp.start","params":{"profile_toml":"format = 1\napp = \"http\"\n[client]\nip = \"10.0.0.1/24\"\n[server]\nip = \"10.0.0.2/24\"\n","iface":"x"}}"#.into(),
        r#"{"jsonrpc":"2.0","id":11,"method":"capture.start","params":{"iface":"x"}}"#.into(),
        r#"{"jsonrpc":"2.0","id":12,"method":"lab.get"}"#.into(),
        r#"{"jsonrpc":"2.0","id":13,"method":"profile.unload","params":{"name":"p"}}"#.into(),
    ];
    let session = |login: Option<&str>| {
        let mut s = String::new();
        if let Some(t) = login {
            s += &serde_json::json!({"jsonrpc":"2.0","id":0,"method":"auth","params":{"token":t}})
                .to_string();
            s.push('\n');
        }
        for c in &calls {
            s += c;
            s.push('\n');
        }
        s.into_bytes()
    };
    match name {
        "ctl_call" => vec![session(None)],
        "ctl_server" => vec![
            session(Some(OPERATOR_TOKEN)),
            session(Some(READ_TOKEN)),
            session(None),
            br#"{"jsonrpc":"2.0","id":1,"method":"auth","params":{"token":"wrong"}}
{"jsonrpc":"2.0","id":2,"method":"stats.subscribe","params":{"interval_ms":10}}
[1,2]
not json
"#
            .to_vec(),
        ],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(name: &str, f: Target, what: &str, d: &[u8]) {
        if std::panic::catch_unwind(|| f(d)).is_err() {
            let text = String::from_utf8_lossy(&d[..d.len().min(2048)]).into_owned();
            panic!("fuzz target {name} panicked on {what}:\n{text}");
        }
    }

    #[test]
    fn every_target_takes_its_seeds_and_regressions() {
        let regressions =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/regressions");
        for (name, f) in TARGETS {
            for (i, d) in seeds(name).iter().enumerate() {
                run(name, *f, &format!("seed {i}"), d);
            }
            let mut files: Vec<_> = std::fs::read_dir(regressions.join(name))
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .collect();
            files.sort();
            for p in files {
                let d = std::fs::read(&p).unwrap();
                run(name, *f, &p.display().to_string(), &d);
            }
        }
    }

    /// Requests with every method and hostile parameters: wrong types,
    /// huge numbers, deep nesting, long strings.
    #[test]
    fn hostile_requests() {
        let methods = [
            "server.info",
            "interfaces.list",
            "profile.load",
            "profile.get",
            "profile.list",
            "profile.unload",
            "run.start",
            "run.stop",
            "run.stats",
            "run.list",
            "run.remove",
            "tcp.start",
            "tcp.stop",
            "tcp.stats",
            "udp.start",
            "udp.stats",
            "rx.start",
            "rx.stats",
            "scenario.check",
            "scenario.start",
            "scenario.get",
            "bench.start",
            "bench.get",
            "y1564.start",
            "y1564.get",
            "file.put",
            "file.stat",
            "file.get",
            "capture.start",
            "capture.read",
            "capture.get",
            "lab.get",
            "lab.start",
            "lab.stop",
            "stats.subscribe",
            "auth",
            "nope",
        ];
        let deep = "[".repeat(10_000) + &"]".repeat(10_000);
        let long = "x".repeat(300_000);
        let params = [
            "null".to_string(),
            "[]".into(),
            "{}".into(),
            "1e999".into(),
            r#"{"id":18446744073709551615,"wait":true}"#.into(),
            r#"{"id":-1}"#.into(),
            r#"{"profile":"p","rate":"1e300pps","null":true}"#.into(),
            r#"{"path":"../../../../etc/passwd","offset":18446744073709551615,"length":18446744073709551615}"#.into(),
            r#"{"path":"/","data":"!!!","offset":0}"#.into(),
            r#"{"toml":"[[stream]]\nname = 1","name":""}"#.into(),
            r#"{"interval_ms":0}"#.into(),
            deep.clone(),
            format!(r#"{{"path":"{long}"}}"#),
        ];
        let mut text = String::new();
        for m in methods {
            for p in &params {
                text += &format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{m}","params":{p}}}"#);
                text.push('\n');
            }
        }
        run("ctl_call", call, "hostile requests", text.as_bytes());
        let mut login = format!(
            r#"{{"jsonrpc":"2.0","id":0,"method":"auth","params":{{"token":"{OPERATOR_TOKEN}"}}}}"#
        );
        login.push('\n');
        run(
            "ctl_server",
            server,
            "hostile requests",
            (login + &text).as_bytes(),
        );
        run("ctl_server", server, "a deep array", deep.as_bytes());
        run(
            "ctl_server",
            server,
            "a line too long",
            "{".repeat(300_000).as_bytes(),
        );
    }

    /// Writes the seeds as corpora for cargo-fuzz (`fuzz/run.sh` runs it).
    #[test]
    #[ignore]
    fn write_seed_corpora() {
        let root = std::env::var_os("FEROTRX_FUZZ_CORPUS")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus")
            });
        for (name, _) in TARGETS {
            let dir = root.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            for (i, d) in seeds(name).iter().enumerate() {
                std::fs::write(dir.join(format!("seed-{i:03}")), d).unwrap();
            }
        }
    }
}
