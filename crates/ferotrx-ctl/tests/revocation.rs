//! Locking out client certificates and tokens while the server runs:
//! revocation lists, refused fingerprints and `server.reload`.

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferotrx_ctl::protocol::*;
use ferotrx_ctl::{
    fingerprint, AuditLog, Client, ClientError, ClientTls, Controller, Credentials, LabPki,
    Reloader, Server, ServerConfig, ServerTls, Token,
};

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ferotrx-rev-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
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
    fn events(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                v["event"].as_str().unwrap_or("").to_string()
            })
            .collect()
    }
}

/// The server's credentials as the files in `dir` say now: the lab
/// certificates, `crl.pem` and `read-crl.pem` if they are there, the
/// fingerprints in `deny.txt` and the tokens in `tokens.toml`.
fn credentials(pki: &LabPki) -> Result<Credentials, String> {
    let e = |e: ferotrx_ctl::TlsError| e.to_string();
    let mut tls = ServerTls::from_files(&pki.path("server.pem"), &pki.path("server-key.pem"))
        .map_err(e)?
        .with_client_ca_file(Role::Operator, &pki.path("ca.pem"))
        .map_err(e)?;
    if pki.path("read-ca.pem").exists() {
        tls = tls
            .with_client_ca_file(Role::Read, &pki.path("read-ca.pem"))
            .map_err(e)?;
    }
    for crl in ["crl.pem", "read-crl.pem"] {
        if pki.path(crl).exists() {
            tls = tls.with_crl_file(&pki.path(crl)).map_err(e)?;
        }
    }
    if pki.path("deny.txt").exists() {
        tls = tls.with_deny_file(&pki.path("deny.txt")).map_err(e)?;
    }
    let tokens = match std::fs::read_to_string(pki.path("tokens.toml")) {
        Ok(t) => Token::from_toml(&t).map_err(|e| e.to_string())?,
        Err(_) => Vec::new(),
    };
    Ok(Credentials {
        tokens,
        tls: Some(tls),
    })
}

fn client_tls(pki: &LabPki, name: &str) -> ClientTls {
    ClientTls::from_ca_file(&pki.path("ca.pem"))
        .unwrap()
        .with_client_cert_files(
            &pki.path(&format!("{name}.pem")),
            &pki.path(&format!("{name}-key.pem")),
        )
        .unwrap()
}

fn start(pki: &LabPki, audit: &Buf) -> (String, Server) {
    let c = credentials(pki).unwrap();
    let reload = {
        let pki = LabPki::new(pki.dir());
        Reloader::new(move || credentials(&pki))
    };
    let server = Server::with_config(
        "127.0.0.1:0",
        Controller::new(),
        ServerConfig {
            tokens: c.tokens,
            tls: c.tls,
            audit: Some(AuditLog::to_writer(audit.clone())),
            reload: Some(reload),
            ..Default::default()
        },
    )
    .unwrap();
    (server.local_addr().unwrap().to_string(), server)
}

/// Waits until `f` holds, for at most 5 s.
fn eventually(mut f: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn revoked_and_refused_certificates_are_locked_out_after_a_reload() {
    let pki = LabPki::new(tmp("crl"));
    pki.issue_server(&["127.0.0.1".into()]).unwrap();
    for n in ["alice", "bob"] {
        pki.issue_client(n, Role::Operator).unwrap();
    }
    pki.issue_client("dash", Role::Read).unwrap();
    std::fs::write(pki.path("tokens.toml"), "").unwrap();
    let audit = Buf::default();
    let (addr, server) = start(&pki, &audit);
    let handle = server.reload_handle();
    server.spawn().unwrap();
    let mut bob = Client::connect_tls(&addr, &client_tls(&pki, "bob")).unwrap();

    let mut alice = Client::connect_tls(&addr, &client_tls(&pki, "alice")).unwrap();
    let info = alice.info().unwrap();
    assert_eq!(info.role, Some(Role::Operator));
    let expires = info
        .certificate_expires
        .expect("the server certificate's expiry");
    assert!(expires.len() >= 20 && expires.ends_with('Z'), "{expires}");
    let mut dash = Client::connect_tls(&addr, &client_tls(&pki, "dash")).unwrap();
    assert_eq!(dash.info().unwrap().role, Some(Role::Read));

    // Revoke alice; nothing changes until the server reloads.
    pki.revoke("alice").unwrap();
    assert!(pki.path("crl.pem").exists());
    assert!(alice.info().is_ok());
    let r = bob.reload().unwrap();
    assert_eq!(r.crls, 2); // crl.pem and read-crl.pem

    // Her open connection is closed, and new ones are refused in the handshake.
    assert!(
        eventually(|| alice.info().is_err()),
        "alice's connection stayed open"
    );
    let again =
        Client::connect_tls(&addr, &client_tls(&pki, "alice")).and_then(|mut c| c.info().map(drop));
    assert!(again.is_err(), "a revoked certificate logged in");
    // Bob, from the same CA, and the read-only client are not affected.
    assert_eq!(bob.info().unwrap().role, Some(Role::Operator));
    assert!(dash.info().is_ok());

    // A refused fingerprint, read from the deny file on a signal-style reload.
    let der = rustls_pki(&pki, "dash");
    std::fs::write(
        pki.path("deny.txt"),
        format!("# lost laptop\n{}  dash\n", fingerprint(&der)),
    )
    .unwrap();
    let r = handle.reload().unwrap();
    assert_eq!(r.denied_certs, 1);
    assert!(eventually(|| dash.info().is_err()), "dash stayed connected");
    match Client::connect_tls(&addr, &client_tls(&pki, "dash")).and_then(|mut c| c.info()) {
        Err(ClientError::Rpc(e)) => {
            assert_eq!(e.code, RpcError::FORBIDDEN);
            assert!(e.message.contains("no longer accepted"), "{}", e.message);
        }
        other => panic!("dash got in: {other:?}"),
    }

    // A second revocation keeps the first in the list.
    pki.revoke("bob").unwrap();
    pki.issue_client("bob", Role::Operator).unwrap();
    handle.reload().unwrap();
    let again =
        Client::connect_tls(&addr, &client_tls(&pki, "alice")).and_then(|mut c| c.info().map(drop));
    assert!(
        again.is_err(),
        "alice got back in after the second revocation"
    );
    let mut new_bob = Client::connect_tls(&addr, &client_tls(&pki, "bob")).unwrap();
    assert_eq!(new_bob.info().unwrap().role, Some(Role::Operator));

    // A reload that fails keeps what is in force.
    std::fs::write(pki.path("deny.txt"), "not-a-fingerprint\n").unwrap();
    assert!(new_bob.reload().is_err());
    assert!(new_bob.info().is_ok());

    let events = audit.events();
    for e in ["reload", "revoked_cert", "denied_cert"] {
        assert!(events.iter().any(|x| x == e), "no {e} in {events:?}");
    }
    let _ = std::fs::remove_dir_all(pki.dir());
}

#[test]
fn a_withdrawn_token_ends_its_logins() {
    let pki = LabPki::new(tmp("tokens"));
    pki.issue_server(&["127.0.0.1".into()]).unwrap();
    pki.issue_client("alice", Role::Operator).unwrap();
    let tokens = |list: &str| std::fs::write(pki.path("tokens.toml"), list).unwrap();
    tokens(
        "[[token]]\nname = \"ci\"\nrole = \"operator\"\nsecret = \"one\"\n\
         [[token]]\nname = \"dash\"\nrole = \"read\"\nsecret = \"two\"\n",
    );
    let audit = Buf::default();
    let (addr, server) = start(&pki, &audit);
    let handle = server.reload_handle();
    server.spawn().unwrap();
    let ca = ClientTls::from_ca_file(&pki.path("ca.pem")).unwrap();
    let mut ci = Client::connect_tls(&addr, &ca).unwrap();
    ci.auth("one").unwrap();
    let mut dash = Client::connect_tls(&addr, &ca).unwrap();
    dash.auth("two").unwrap();

    // dash's token is gone and ci's now gives read only.
    tokens("[[token]]\nname = \"ci\"\nrole = \"read\"\nsecret = \"one\"\n");
    assert_eq!(handle.reload().unwrap().tokens, 1);
    assert!(eventually(|| dash.info().is_err()));
    assert!(eventually(|| ci
        .info()
        .is_ok_and(|i| i.role == Some(Role::Read))));
    let mut late = Client::connect_tls(&addr, &ca).unwrap();
    assert!(late.auth("two").is_err());
    assert!(audit.events().iter().any(|e| e == "token_withdrawn"));
    let _ = std::fs::remove_dir_all(pki.dir());
}

#[test]
fn reload_needs_a_reloader_and_an_operator() {
    let pki = LabPki::new(tmp("noreload"));
    pki.issue_server(&["127.0.0.1".into()]).unwrap();
    pki.issue_client("dash", Role::Read).unwrap();
    let c = credentials(&pki).unwrap();
    let server = Server::with_config(
        "127.0.0.1:0",
        Controller::new(),
        ServerConfig {
            tls: c.tls,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(server
        .reload()
        .unwrap_err()
        .contains("not started from files"));
    let addr = server.spawn().unwrap().to_string();
    let mut dash = Client::connect_tls(&addr, &client_tls(&pki, "dash")).unwrap();
    match dash.reload() {
        Err(ClientError::Rpc(e)) => assert_eq!(e.code, RpcError::FORBIDDEN),
        other => panic!("a read-only client reloaded: {other:?}"),
    }
    let _ = std::fs::remove_dir_all(pki.dir());
}

/// The DER of a lab certificate.
fn rustls_pki(pki: &LabPki, name: &str) -> Vec<u8> {
    let pem = std::fs::read_to_string(pki.path(&format!("{name}.pem"))).unwrap();
    use base64::Engine;
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap()
}
