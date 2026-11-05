use std::net::SocketAddr;
use std::time::Duration;

use super::*;
use crate::app::{App, AppCx};

fn init(role: AppRole, index: u64) -> SessionInit {
    let a: SocketAddr = "10.0.0.1:40000".parse().unwrap();
    let b: SocketAddr = "10.0.0.2:445".parse().unwrap();
    SessionInit {
        role,
        transport: Transport::Stream,
        index,
        seed: index + 1,
        local: a,
        remote: b,
    }
}

/// Plays a client against a server session of `app`, handing bytes over in
/// pieces of `piece` bytes, until the client closes. The wall clock is
/// 2026.
fn play(app: &App, index: u64, piece: usize) -> (AppCx, AppCx) {
    let mut c = app.session(&init(AppRole::Client, index));
    let mut s = app.session(&init(AppRole::Server, index));
    let (mut cc, mut sc) = (AppCx::default(), AppCx::default());
    let wall = Duration::from_secs(1_780_000_000);
    let now = Duration::from_millis(5);
    let mut x = AppCx::new(now, wall);
    c.start(&mut x);
    let mut to_s: Vec<u8> = x.take_sends().concat();
    let mut closed = x.wants_close();
    cc.absorb(x);
    for _ in 0..100_000 {
        let mut to_c = Vec::new();
        for chunk in std::mem::take(&mut to_s).chunks(piece) {
            let mut y = AppCx::new(now, wall);
            s.receive(chunk, &mut y);
            to_c.extend(y.take_sends().concat());
            sc.absorb(y);
        }
        for chunk in to_c.chunks(piece) {
            let mut y = AppCx::new(now, wall);
            c.receive(chunk, &mut y);
            to_s.extend(y.take_sends().concat());
            closed |= y.wants_close();
            cc.absorb(y);
        }
        if to_s.is_empty() {
            break;
        }
    }
    assert!(closed, "the client did not finish: {:?}", labels(&cc));
    (cc, sc)
}

fn labels(cx: &AppCx) -> Vec<String> {
    cx.transactions().iter().map(|t| t.label.clone()).collect()
}

fn lab() -> Smb {
    let mut s = Smb::default();
    s.client.user = "alice".into();
    s.client.password = "lab".into();
    s.server.users.insert("alice".into(), "lab".into());
    s.server.files = vec![
        ("readme.txt".into(), 5000),
        ("docs/manual.txt".into(), 300_000),
    ];
    s.client.ops = [
        "write up-{n}.bin 200K",
        "read up-{n}.bin",
        "read docs/manual.txt",
        "mkdir dir-{n}",
        "list",
        "rmdir dir-{n}",
        "delete up-{n}.bin",
        "read up-{n}.bin expect OBJECT_NAME_NOT_FOUND",
    ]
    .iter()
    .map(|o| o.parse().unwrap())
    .collect();
    s
}

#[test]
fn every_dialect_logs_in_signs_writes_reads_and_lists() {
    for (dialect, signing) in [
        (msg::SMB311, Signing::Required),
        (msg::SMB311, Signing::Auto),
        (msg::SMB302, Signing::Required),
        (msg::SMB300, Signing::Required),
        (msg::SMB210, Signing::Required),
        (msg::SMB202, Signing::Required),
    ] {
        let mut s = lab();
        s.client.dialects = vec![dialect];
        s.client.signing = signing;
        s.server.require_signing = signing == Signing::Required;
        let app = App::new(s);
        let (c, srv) = play(&app, 3, 1000);
        let want = [
            format!("negotiate {}", dialect_name(dialect)),
            "login".into(),
            "tree connect".into(),
            "write".into(),
            "read".into(),
            "read".into(),
            "mkdir".into(),
            "list".into(),
            "rmdir".into(),
            "delete".into(),
            "read STATUS_OBJECT_NAME_NOT_FOUND".into(),
            "logoff".into(),
        ];
        assert_eq!(labels(&c), want, "{dialect:x}");
        assert!(
            c.all_ok(),
            "{:?} {:?} {:?}",
            c.transactions(),
            c.protocol_errors(),
            c.handshakes()
        );
        assert!(c.protocol_errors().is_empty(), "{:?}", c.protocol_errors());
        assert!(
            srv.protocol_errors().is_empty(),
            "{:?}",
            srv.protocol_errors()
        );
        let h = &c.handshakes()[0];
        let how = if signing == Signing::Required {
            if dialect >= msg::SMB300 {
                "signed AES-CMAC"
            } else {
                "signed HMAC-SHA256"
            }
        } else {
            "unsigned"
        };
        assert_eq!(h.label, format!("SMB {} {how}", dialect_name(dialect)));
        assert!(labels(&srv).iter().any(|l| l == "WRITE"));
    }
}

#[test]
fn a_second_connection_reads_what_the_first_wrote() {
    let mut s = lab();
    s.client.ops = vec!["write shared.bin 70K".parse().unwrap()];
    let app = App::new(s.clone());
    let (c, _) = play(&app, 1, 64 << 10);
    assert!(c.all_ok());
    // The same App, so the same store.
    let smb = app.protocol().as_any().downcast_ref::<Smb>().unwrap();
    let st = smb.store.lock().unwrap();
    let f = st.shares["lab"].get("shared.bin").unwrap();
    assert_eq!(f.data, Smb::content("shared.bin", 0, 70 << 10));
}

#[test]
fn wrong_password_unknown_share_read_only_and_guests() {
    let mut s = lab();
    s.client.password = "guess".into();
    s.client.expect = Some(msg::STATUS_LOGON_FAILURE);
    let (c, _) = play(&App::new(s), 0, 4096);
    assert_eq!(labels(&c)[1], "login STATUS_LOGON_FAILURE");
    assert!(c.all_ok());
    assert_eq!(c.handshakes()[0].label, "failed: STATUS_LOGON_FAILURE");

    let mut s = lab();
    s.client.share = "nothere".into();
    let (c, _) = play(&App::new(s), 0, 4096);
    assert_eq!(labels(&c)[2], "tree connect STATUS_BAD_NETWORK_NAME");
    assert!(!c.all_ok());

    let mut s = lab();
    s.server.shares[0].read_only = true;
    s.client.ops = vec![
        "read readme.txt".parse().unwrap(),
        "write x.bin 1K expect ACCESS_DENIED".parse().unwrap(),
        "delete readme.txt expect ACCESS_DENIED".parse().unwrap(),
    ];
    let (c, _) = play(&App::new(s), 0, 4096);
    assert!(c.all_ok(), "{:?}", labels(&c));

    // No users: anyone, as a guest, unsigned.
    let mut s = lab();
    s.server.users.clear();
    s.client.user = String::new();
    let (c, _) = play(&App::new(s), 0, 4096);
    assert_eq!(labels(&c)[1], "login anonymous");
    assert!(c.all_ok(), "{:?}", labels(&c));
}

#[test]
fn parses_a_table() {
    let t: toml::Table = toml::from_str(
        r#"
        user = "bob"
        password = "pw"
        share = "data"
        dialects = ["3.1.1", "2.1"]
        signing = "required"
        ops = ["write a.bin 1M", "read a.bin", "list docs", "delete a.bin"]
        chunk = "256K"
        window = 8
        users = { bob = "pw" }
        shares = ["data", "public"]
        read_only = ["public"]
        files = { "readme.txt" = "1K" }
        "#,
    )
    .unwrap();
    let s = parse(&t).unwrap();
    assert_eq!(s.client.dialects, vec![msg::SMB311, msg::SMB210]);
    assert_eq!(s.client.ops[0].kind, OpKind::Write(1 << 20));
    assert_eq!(s.client.ops[2].path, "docs");
    assert!(s.server.require_signing && s.server.shares[1].read_only);
    assert_eq!(s.server.files, vec![("readme.txt".to_string(), 1024)]);
    assert!(s.describe().contains("bob on data"));
    let bad: toml::Table = toml::from_str("ops = [\"copy a b\"]").unwrap();
    assert!(parse(&bad).is_err());
}
