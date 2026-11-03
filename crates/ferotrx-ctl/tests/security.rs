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
    Server::bind("0.0.0.0:0", Controller::new(), Some("t".into())).unwrap();
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
