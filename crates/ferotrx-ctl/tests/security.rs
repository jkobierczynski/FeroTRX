//! Logins, roles, TLS, file restrictions, limits and the audit log.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferotrx_ctl::protocol::*;
use ferotrx_ctl::{
    AuditLog, Client, ClientError, ClientTls, Controller, FilePolicy, LabPki, RpcError, Server,
    ServerConfig, ServerTls, Token,
};

const PROFILE: &str = r#"
[[stream]]
name = "ping"
packet = "eth/ipv4(dst=192.168.20.50)/icmp"
rate = "1000pps"
loops = 0
"#;

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ferotrx-sec-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A lab PKI with a server certificate for 127.0.0.1, operator `alice`
/// and read-only `dash`.
fn pki(name: &str) -> LabPki {
    let pki = LabPki::new(tmp(name));
    pki.issue_server(&["lab1".into()]).unwrap();
    pki.issue_client("alice", Role::Operator).unwrap();
    pki.issue_client("dash", Role::Read).unwrap();
    pki
}

fn server_tls(pki: &LabPki) -> ServerTls {
    ServerTls::from_files(&pki.path("server.pem"), &pki.path("server-key.pem")).unwrap()
}

fn client_tls(pki: &LabPki, cert: Option<&str>) -> ClientTls {
    let t = ClientTls::from_ca_file(&pki.path("ca.pem")).unwrap();
    match cert {
        Some(n) => t
            .with_client_cert_files(
                &pki.path(&format!("{n}.pem")),
                &pki.path(&format!("{n}-key.pem")),
            )
            .unwrap(),
        None => t,
    }
}

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buf {
    fn records(&self) -> Vec<serde_json::Value> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

fn spawn(controller: Controller, config: ServerConfig) -> SocketAddr {
    Server::with_config("127.0.0.1:0", controller, config)
        .unwrap()
        .spawn()
        .unwrap()
}

fn tls_client(addr: SocketAddr, tls: &ClientTls) -> Result<Client, ClientError> {
    let c = Client::connect_tls(&addr.to_string(), tls)?;
    c.set_timeout(Some(Duration::from_secs(20))).unwrap();
    Ok(c)
}

fn rpc_code(e: ClientError) -> i64 {
    match e {
        ClientError::Rpc(e) => e.code,
        other => panic!("expected an RPC error, got {other}"),
    }
}

fn load(c: &mut Client) -> Result<ProfileInfo, ClientError> {
    c.load_profile(&LoadProfileParams {
        name: Some("lab".into()),
        toml: Some(PROFILE.into()),
        ..Default::default()
    })
}

#[test]
fn tokens_over_tls_give_their_roles() {
    let pki = pki("tokens");
    let audit = Buf::default();
    let addr = spawn(
        Controller::new(),
        ServerConfig {
            tokens: vec![
                Token::new("ci", Role::Operator, "op-secret-1"),
                Token::new("dash", Role::Read, "read-secret-2"),
            ],
            tls: Some(server_tls(&pki)),
            audit: Some(AuditLog::to_writer(audit.clone())),
            ..Default::default()
        },
    );
    let mut c = tls_client(addr, &client_tls(&pki, None)).unwrap();
    let info = c.info().unwrap();
    assert!(info.tls && info.auth_required);
    assert_eq!(info.role, None);
    assert_eq!(rpc_code(c.profiles().unwrap_err()), RpcError::UNAUTHORIZED);

    c.auth("read-secret-2").unwrap();
    assert_eq!(c.info().unwrap().role, Some(Role::Read));
    assert_eq!(c.info().unwrap().user.as_deref(), Some("dash"));
    assert_eq!(rpc_code(load(&mut c).unwrap_err()), RpcError::FORBIDDEN);
    assert!(c.profiles().unwrap().is_empty());

    assert_eq!(
        rpc_code(c.auth("wrong").unwrap_err()),
        RpcError::UNAUTHORIZED
    );
    assert_eq!(rpc_code(c.profiles().unwrap_err()), RpcError::UNAUTHORIZED);

    c.auth("op-secret-1").unwrap();
    load(&mut c).unwrap();
    let run = c
        .start(&StartParams {
            profile: "lab".into(),
            output: OutputSpec {
                null: true,
                ..Default::default()
            },
            duration: Some("300ms".into()),
            ..Default::default()
        })
        .unwrap();
    // Notifications come from another thread over the same TLS session.
    c.subscribe(Some(run.id), 50).unwrap();
    loop {
        if c.next_stats().unwrap().last {
            break;
        }
    }
    drop(c);

    let recs = audit.records();
    let events: Vec<&str> = recs.iter().map(|r| r["event"].as_str().unwrap()).collect();
    for e in ["connect", "login", "denied", "login_failed", "call"] {
        assert!(events.contains(&e), "no {e} in {events:?}");
    }
    let call = recs
        .iter()
        .find(|r| r["event"] == "call" && r["method"] == "profile.load")
        .unwrap();
    assert_eq!(call["user"], "ci");
    assert_eq!(call["params"]["toml"]["bytes"], PROFILE.len());
    let start = recs
        .iter()
        .find(|r| r["event"] == "call" && r["method"] == "run.start")
        .unwrap();
    assert_eq!(start["id"], run.id);
    let text = String::from_utf8(audit.0.lock().unwrap().clone()).unwrap();
    assert!(!text.contains("op-secret-1") && !text.contains("read-secret-2"));
}

#[test]
fn client_certificates_log_in() {
    let pki = pki("mtls");
    let tls = server_tls(&pki)
        .with_client_ca_file(Role::Operator, &pki.path("ca.pem"))
        .unwrap()
        .with_client_ca_file(Role::Read, &pki.path("read-ca.pem"))
        .unwrap();
    let addr = spawn(
        Controller::new(),
        ServerConfig {
            tls: Some(tls),
            ..Default::default()
        },
    );

    let mut alice = tls_client(addr, &client_tls(&pki, Some("alice"))).unwrap();
    let info = alice.info().unwrap();
    assert_eq!(info.role, Some(Role::Operator));
    assert_eq!(info.user.as_deref(), Some("alice"));
    load(&mut alice).unwrap();

    let mut dash = tls_client(addr, &client_tls(&pki, Some("dash"))).unwrap();
    assert_eq!(dash.info().unwrap().role, Some(Role::Read));
    assert_eq!(dash.profiles().unwrap().len(), 1);
    assert_eq!(
        rpc_code(dash.unload_profile("lab").unwrap_err()),
        RpcError::FORBIDDEN
    );

    // Without a certificate the handshake fails (no token could log in).
    let failed = tls_client(addr, &client_tls(&pki, None)).and_then(|mut c| c.info().map(drop));
    assert!(failed.is_err());
}

#[test]
fn the_server_certificate_is_checked() {
    let other = pki("other-ca");
    let pki = pki("server-check");
    let addr = spawn(
        Controller::new(),
        ServerConfig {
            tls: Some(server_tls(&pki)),
            ..Default::default()
        },
    );
    // A CA that did not sign the server's certificate.
    let r = tls_client(addr, &client_tls(&other, None));
    assert!(r.is_err());
    // The wrong name.
    let r = tls_client(addr, &client_tls(&pki, None).with_server_name("lab9"));
    assert!(r.is_err());
    // The right CA and name.
    let mut c = tls_client(addr, &client_tls(&pki, None).with_server_name("lab1")).unwrap();
    assert!(c.info().unwrap().tls);
}

#[test]
fn refuses_an_open_listener_on_the_network() {
    let e = Server::with_config("0.0.0.0:0", Controller::new(), ServerConfig::default())
        .err()
        .unwrap();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    Server::with_config(
        "0.0.0.0:0",
        Controller::new(),
        ServerConfig {
            insecure: true,
            ..Default::default()
        },
    )
    .unwrap();
}

#[test]
fn refuses_cleartext_tokens_on_the_network() {
    let token = || vec![Token::new("op", Role::Operator, "t")];
    // A token without TLS beyond loopback: refused.
    let e = Server::bind("0.0.0.0:0", Controller::new(), Some("t".into()))
        .err()
        .unwrap();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(e.to_string().contains("--allow-cleartext-token"), "{e}");
    let e = Server::with_config(
        "0.0.0.0:0",
        Controller::new(),
        ServerConfig {
            tokens: token(),
            ..Default::default()
        },
    )
    .err()
    .unwrap();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);

    // On loopback it is fine.
    Server::bind("127.0.0.1:0", Controller::new(), Some("t".into())).unwrap();

    // With TLS, with client certificates only, or when told to.
    let pki = pki("cleartext");
    Server::with_config(
        "0.0.0.0:0",
        Controller::new(),
        ServerConfig {
            tokens: token(),
            tls: Some(server_tls(&pki)),
            ..Default::default()
        },
    )
    .unwrap();
    Server::with_config(
        "0.0.0.0:0",
        Controller::new(),
        ServerConfig {
            tls: Some(
                server_tls(&pki)
                    .with_client_ca_file(Role::Operator, &pki.path("ca.pem"))
                    .unwrap(),
            ),
            ..Default::default()
        },
    )
    .unwrap();
    let log = Buf::default();
    Server::with_config(
        "0.0.0.0:0",
        Controller::new(),
        ServerConfig {
            tokens: token(),
            allow_cleartext_tokens: true,
            audit: Some(AuditLog::to_writer(log.clone())),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(log
        .records()
        .iter()
        .any(|r| r["event"] == "cleartext_tokens"));
}

#[test]
fn no_files_by_default_and_unrestricted_only_when_said() {
    // A default controller names no files at all.
    let mut c = Client::connect(spawn(Controller::new(), ServerConfig::default())).unwrap();
    let e = c
        .load_profile(&LoadProfileParams {
            path: Some("/etc/passwd".into()),
            ..Default::default()
        })
        .unwrap_err();
    assert_eq!(rpc_code(e), RpcError::FORBIDDEN);
    let e = c
        .load_profile(&LoadProfileParams {
            name: Some("p".into()),
            toml: Some("[[stream]]\npcap = \"/etc/passwd\"\n".into()),
            ..Default::default()
        })
        .unwrap_err();
    assert_eq!(rpc_code(e), RpcError::FORBIDDEN);
    let e = c.file_stat(Path::new("x")).unwrap_err();
    assert_eq!(rpc_code(e), RpcError::FORBIDDEN);
    // Profiles that name no files still load.
    load(&mut c).unwrap();

    // Unrestricted beyond loopback needs saying so.
    let open = || Controller::new().with_file_policy(FilePolicy::unrestricted());
    let token = || vec![Token::new("op", Role::Operator, "t")];
    let pki = pki("unrestricted");
    let config = || ServerConfig {
        tokens: token(),
        tls: Some(server_tls(&pki)),
        ..Default::default()
    };
    let e = Server::with_config("0.0.0.0:0", open(), config())
        .err()
        .unwrap();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    Server::with_config(
        "0.0.0.0:0",
        open(),
        ServerConfig {
            unrestricted_files: true,
            ..config()
        },
    )
    .unwrap();
    Server::with_config("127.0.0.1:0", open(), ServerConfig::default()).unwrap();
}

fn subscribe(c: &mut Client) -> Result<serde_json::Value, ClientError> {
    c.call_value("stats.subscribe", serde_json::json!({"interval_ms": 1000}))
}

fn server_subscriptions(addr: SocketAddr) -> usize {
    let mut c = Client::connect(addr).unwrap();
    c.info().unwrap().subscriptions.unwrap()
}

fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
    for _ in 0..100 {
        if ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn limits_stats_subscriptions() {
    let addr = spawn(
        Controller::new(),
        ServerConfig {
            max_subscriptions: 2,
            max_total_subscriptions: 3,
            ..Default::default()
        },
    );
    let mut a = Client::connect(addr).unwrap();
    let first = subscribe(&mut a).unwrap();
    subscribe(&mut a).unwrap();
    // A third on the same connection: refused.
    assert_eq!(rpc_code(subscribe(&mut a).unwrap_err()), RpcError::LIMIT);
    // Unsubscribing frees a place.
    a.call_value("stats.unsubscribe", first).unwrap();
    subscribe(&mut a).unwrap();

    // The server's limit counts all connections.
    let mut b = Client::connect(addr).unwrap();
    subscribe(&mut b).unwrap();
    assert_eq!(rpc_code(subscribe(&mut b).unwrap_err()), RpcError::LIMIT);
    wait_for("3 subscriptions", || server_subscriptions(addr) == 3);

    // Closing a connection ends its subscriptions.
    drop(a);
    wait_for("1 subscription", || server_subscriptions(addr) == 1);
    subscribe(&mut b).unwrap();

    // Many rounds leave nothing behind.
    drop(b);
    let mut c = Client::connect(addr).unwrap();
    for _ in 0..200 {
        let s = subscribe(&mut c).unwrap();
        c.call_value("stats.unsubscribe", s).unwrap();
    }
    wait_for("no subscriptions", || server_subscriptions(addr) == 0);
}

fn send_line(s: &mut TcpStream, r: &mut BufReader<TcpStream>, line: &str) -> String {
    s.write_all(line.as_bytes()).unwrap();
    s.write_all(b"\n").unwrap();
    read_line(r)
}

#[test]
fn clients_without_a_login_cannot_take_every_slot() {
    let addr = spawn(
        Controller::new(),
        ServerConfig {
            tokens: vec![Token::new("op", Role::Operator, "t")],
            max_connections: 10,
            max_unauthenticated: 2,
            ..Default::default()
        },
    );
    let info = r#"{"jsonrpc":"2.0","id":1,"method":"server.info"}"#;
    let (mut s1, mut r1) = raw(addr);
    assert!(send_line(&mut s1, &mut r1, info).contains("result"));
    let (mut s2, mut r2) = raw(addr);
    assert!(send_line(&mut s2, &mut r2, info).contains("result"));
    // Two wait to log in: a third is turned away.
    let (_s3, mut r3) = raw(addr);
    assert!(read_line(&mut r3).contains("waiting to log in"));
    // One logs in, which makes room.
    let auth = r#"{"jsonrpc":"2.0","id":2,"method":"auth","params":{"token":"t"}}"#;
    assert!(send_line(&mut s1, &mut r1, auth).contains("true"));
    let (mut s4, mut r4) = raw(addr);
    assert!(send_line(&mut s4, &mut r4, info).contains("result"));
}

#[test]
fn wrong_tokens_from_one_address_are_throttled() {
    let log = Buf::default();
    let addr = spawn(
        Controller::new(),
        ServerConfig {
            tokens: vec![Token::new("op", Role::Operator, "right")],
            max_login_failures_per_ip: 3,
            audit: Some(AuditLog::to_writer(log.clone())),
            ..Default::default()
        },
    );
    // Three wrong tokens, over two connections.
    let mut a = Client::connect(addr).unwrap();
    for _ in 0..2 {
        assert_eq!(
            rpc_code(a.auth("wrong").unwrap_err()),
            RpcError::UNAUTHORIZED
        );
    }
    let mut b = Client::connect(addr).unwrap();
    assert_eq!(
        rpc_code(b.auth("wrong").unwrap_err()),
        RpcError::UNAUTHORIZED
    );
    // Now even the right one is refused unchecked, on a new connection too.
    assert_eq!(rpc_code(b.auth("right").unwrap_err()), RpcError::LIMIT);
    let mut c = Client::connect(addr).unwrap();
    assert_eq!(rpc_code(c.auth("right").unwrap_err()), RpcError::LIMIT);
    assert!(log
        .records()
        .iter()
        .any(|r| r["event"] == "login_throttled"));
    assert!(
        !String::from_utf8(log.0.lock().unwrap().clone())
            .unwrap()
            .contains("right"),
        "tokens never reach the audit log"
    );
}

/// An audit log that fails while `broken` is set.
#[derive(Clone)]
struct Flaky {
    buf: Buf,
    broken: Arc<std::sync::atomic::AtomicBool>,
}

impl Write for Flaky {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.broken.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(std::io::Error::other("no space left on device"));
        }
        self.buf.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn audit_required_refuses_changes_while_the_log_fails() {
    let flaky = Flaky {
        buf: Buf::default(),
        broken: Arc::default(),
    };
    let broken = flaky.broken.clone();
    let addr = spawn(
        Controller::new(),
        ServerConfig {
            audit: Some(AuditLog::to_writer(flaky.clone())),
            audit_required: true,
            ..Default::default()
        },
    );
    let mut c = Client::connect(addr).unwrap();
    load(&mut c).unwrap();
    let health = c.info().unwrap().audit.unwrap();
    assert!(health.ok && health.required);

    broken.store(true, std::sync::atomic::Ordering::Relaxed);
    // The first change after the disk filled up goes through, unlogged; the
    // log now knows it fails.
    load(&mut c).unwrap();
    assert_eq!(rpc_code(load(&mut c).unwrap_err()), RpcError::FORBIDDEN);
    // Reading still works, and says why.
    let health = c.info().unwrap().audit.unwrap();
    assert!(!health.ok);
    assert!(health.failures >= 1);
    assert_eq!(
        health.last_error.as_deref(),
        Some("no space left on device")
    );
    c.profiles().unwrap();

    // Once writing works again, so do changes.
    broken.store(false, std::sync::atomic::Ordering::Relaxed);
    load(&mut c).unwrap();
    assert!(c.info().unwrap().audit.unwrap().ok);
    assert!(flaky
        .buf
        .records()
        .iter()
        .any(|r| r["event"] == "audit_refused"));

    // Without an audit log, audit_required makes no sense.
    let e = Server::with_config(
        "127.0.0.1:0",
        Controller::new(),
        ServerConfig {
            audit_required: true,
            ..Default::default()
        },
    )
    .err()
    .unwrap();
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
}

fn raw(addr: SocketAddr) -> (TcpStream, BufReader<TcpStream>) {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let r = BufReader::new(s.try_clone().unwrap());
    (s, r)
}

fn read_line(r: &mut BufReader<TcpStream>) -> String {
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    line
}

#[test]
fn limits_connections_requests_and_idle_time() {
    let addr = spawn(
        Controller::new(),
        ServerConfig {
            max_connections: 1,
            max_request: 2048,
            idle_timeout: Some(Duration::from_millis(800)),
            ..Default::default()
        },
    );
    let (mut first, mut r1) = raw(addr);
    first
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server.info\"}\n")
        .unwrap();
    assert!(read_line(&mut r1).contains("\"result\""));
    // The second connection is turned away while the first is open.
    let (_second, mut r2) = raw(addr);
    assert!(read_line(&mut r2).contains("too many connections"));
    assert_eq!(read_line(&mut r2), "");

    // The first one is closed once idle.
    assert_eq!(read_line(&mut r1), "");
    drop(first);
    std::thread::sleep(Duration::from_millis(200));

    let (mut s, mut r) = raw(addr);
    s.write_all(&vec![b'x'; 4096]).unwrap();
    assert!(read_line(&mut r).contains("too long"));
    assert_eq!(read_line(&mut r), "");
}

#[test]
fn closes_connections_that_do_not_log_in() {
    let addr = spawn(
        Controller::new(),
        ServerConfig {
            tokens: vec![Token::new("t", Role::Operator, "secret")],
            login_timeout: Duration::from_millis(600),
            ..Default::default()
        },
    );
    let (_s, mut r) = raw(addr);
    assert_eq!(read_line(&mut r), "");

    // Five wrong tokens, and the connection is closed.
    let (mut s, mut r) = raw(addr);
    let mut c = 0;
    for i in 0..5 {
        writeln!(
            s,
            "{{\"jsonrpc\":\"2.0\",\"id\":{i},\"method\":\"auth\",\"params\":{{\"token\":\"x\"}}}}"
        )
        .unwrap();
        if read_line(&mut r).contains("wrong token") {
            c += 1;
        }
    }
    assert_eq!(c, 5);
    assert_eq!(read_line(&mut r), "");
}

fn data_dir(name: &str) -> PathBuf {
    let d = tmp(name);
    std::fs::create_dir_all(d.join("data")).unwrap();
    let web = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/web.pcap");
    std::fs::copy(&web, d.join("data/web.pcap")).unwrap();
    std::fs::copy(&web, d.join("outside.pcap")).unwrap();
    std::fs::write(
        d.join("data/inside.toml"),
        "[[stream]]\nname = \"web\"\npcap = \"web.pcap\"\n",
    )
    .unwrap();
    std::fs::write(
        d.join("data/sneaky.toml"),
        "[[stream]]\nname = \"web\"\npcap = \"../outside.pcap\"\n",
    )
    .unwrap();
    std::fs::write(
        d.join("elsewhere.toml"),
        "[[stream]]\nname = \"web\"\npcap = \"outside.pcap\"\n",
    )
    .unwrap();
    d
}

#[test]
fn files_stay_inside_the_data_directories() {
    let d = data_dir("files");
    let policy = FilePolicy::dirs([d.join("data")])
        .unwrap()
        .with_max_upload(200);
    let addr = spawn(
        Controller::new().with_file_policy(policy),
        ServerConfig::default(),
    );
    let mut c = Client::connect(addr).unwrap();
    c.set_timeout(Some(Duration::from_secs(20))).unwrap();

    // A relative path starts from the data directory.
    let p = c.load_profile_file("inside.toml").unwrap();
    assert_eq!(p.name, "inside");
    for path in [
        d.join("elsewhere.toml"),
        PathBuf::from("../elsewhere.toml"),
        PathBuf::from("sneaky.toml"),
    ] {
        let e = c.load_profile_file(&path).unwrap_err();
        assert_eq!(rpc_code(e), RpcError::FORBIDDEN, "{}", path.display());
    }

    // Uploads: pcaps from the data directory, size-limited, base_dir inside.
    let upload = |c: &mut Client, toml: &str, base: Option<&str>| {
        c.load_profile(&LoadProfileParams {
            name: Some("up".into()),
            toml: Some(toml.into()),
            base_dir: base.map(PathBuf::from),
            ..Default::default()
        })
    };
    upload(
        &mut c,
        "[[stream]]\nname = \"w\"\npcap = \"web.pcap\"\n",
        None,
    )
    .unwrap();
    let e = upload(
        &mut c,
        "[[stream]]\nname = \"w\"\npcap = \"../outside.pcap\"\n",
        None,
    );
    assert_eq!(rpc_code(e.unwrap_err()), RpcError::FORBIDDEN);
    let e = upload(
        &mut c,
        "[[stream]]\nname = \"w\"\npcap = \"web.pcap\"\n",
        Some(".."),
    );
    assert_eq!(rpc_code(e.unwrap_err()), RpcError::FORBIDDEN);
    let big = format!("{PROFILE}\n# {}\n", "x".repeat(300));
    assert_eq!(
        rpc_code(upload(&mut c, &big, None).unwrap_err()),
        RpcError::INVALID_PARAMS
    );

    // Pcap outputs too.
    let start = |c: &mut Client, file: &str| {
        c.start(&StartParams {
            profile: "inside".into(),
            output: OutputSpec {
                file: Some(file.into()),
                ..Default::default()
            },
            limit: Some(3),
            ..Default::default()
        })
    };
    let e = start(&mut c, "../out.pcap").unwrap_err();
    assert_eq!(rpc_code(e), RpcError::FORBIDDEN);
    let run = start(&mut c, "out.pcap").unwrap();
    c.stop(run.id).unwrap();
    assert!(d.join("data/out.pcap").exists());

    // TCP profiles as well.
    let e = c
        .tcp_start(&TcpStartParams {
            path: Some(d.join("elsewhere.toml")),
            ..Default::default()
        })
        .unwrap_err();
    assert_eq!(rpc_code(e), RpcError::FORBIDDEN);
    let e = c
        .tcp_start(&TcpStartParams {
            toml: Some("pcap = \"../outside.pcap\"\n[client]\nip = \"10.0.0.1\"\n".into()),
            ..Default::default()
        })
        .unwrap_err();
    assert_eq!(rpc_code(e), RpcError::FORBIDDEN);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn large_files_come_down_over_tls() {
    // rustls takes at most 64 KiB of plaintext at a time; a file.get reply
    // is far larger and must still arrive whole.
    let pki = pki("download");
    let d = tmp("download-data");
    std::fs::create_dir_all(&d).unwrap();
    let big: Vec<u8> = (0..3_000_000u32).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(d.join("big.bin"), &big).unwrap();
    let addr = spawn(
        Controller::new().with_file_policy(FilePolicy::dirs([d.clone()]).unwrap()),
        ServerConfig {
            tokens: vec![Token::new("ci", Role::Operator, "op-secret-1")],
            tls: Some(server_tls(&pki)),
            ..Default::default()
        },
    );
    let mut c = tls_client(addr, &client_tls(&pki, None)).unwrap();
    c.set_timeout(Some(Duration::from_secs(20))).unwrap();
    c.auth("op-secret-1").unwrap();
    assert_eq!(c.download("big.bin").unwrap(), big);
    assert!(c.info().unwrap().tls);
}
