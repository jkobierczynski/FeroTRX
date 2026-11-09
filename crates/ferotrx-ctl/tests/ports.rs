//! Port reservations and sessions per user: `ports.acquire`/`release`,
//! `session.*`, runs refused on ports other users hold, and runs that only
//! their owner (or an admin) may stop.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ferotrx_core::{memory_ports, MemoryPort};
use ferotrx_ctl::protocol::*;
use ferotrx_ctl::{Client, ClientError, Controller, Role, RpcError, Server, ServerConfig, Token};

/// A TCP run between "a" and "b" that goes until it is stopped.
const TCP_PROFILE: &str = r#"
port = 7
connections = 0
cps = 50
[[message]]
from = "client"
text = "hello"
[[message]]
from = "server"
text = "hello yourself"
[client]
iface = "a"
ip = "10.9.0.1"
[server]
iface = "b"
ip = "10.9.0.2"
"#;

const PROFILE: &str = r#"
[[stream]]
name = "ping"
packet = "eth/ipv4(dst=10.9.0.2)/icmp"
rate = "10pps"
"#;

/// A controller whose TCP runs open "a" and "b", the two ends of an
/// in-memory cable.
fn controller() -> Controller {
    let spare: Mutex<Option<MemoryPort>> = Mutex::new(None);
    Controller::new().with_port_opener(move |name, _| {
        let mut spare = spare.lock().unwrap();
        match name {
            "a" => {
                let (a, b) = memory_ports();
                *spare = Some(b);
                Ok(Box::new(a))
            }
            "b" => Ok(Box::new(spare.take().ok_or("open a first")?)),
            other => Err(format!("no interface {other}").into()),
        }
    })
}

fn tokens() -> Vec<Token> {
    vec![
        Token::new("alice", Role::Operator, "alice-secret"),
        Token::new("bob", Role::Operator, "bob-secret"),
        Token::new("root", Role::Admin, "root-secret"),
        Token::new("dash", Role::Read, "dash-secret"),
    ]
}

fn spawn(controller: Controller, tokens: Vec<Token>) -> SocketAddr {
    let config = ServerConfig {
        tokens,
        ..Default::default()
    };
    Server::with_config("127.0.0.1:0", controller, config)
        .unwrap()
        .spawn()
        .unwrap()
}

fn login(addr: SocketAddr, secret: Option<&str>) -> Client {
    let mut c = Client::connect(addr).unwrap();
    c.set_timeout(Some(Duration::from_secs(20))).unwrap();
    if let Some(s) = secret {
        c.auth(s).unwrap();
    }
    c
}

fn tcp() -> TcpStartParams {
    TcpStartParams {
        toml: Some(TCP_PROFILE.into()),
        ..Default::default()
    }
}

fn start_on(c: &mut Client, iface: &str) -> Result<RunInfo, ClientError> {
    c.load_profile(&LoadProfileParams {
        name: Some("lab".into()),
        toml: Some(PROFILE.into()),
        ..Default::default()
    })?;
    c.start(&StartParams {
        profile: "lab".into(),
        output: OutputSpec {
            iface: Some(iface.into()),
            ..Default::default()
        },
        ..Default::default()
    })
}

/// The refusal's code, port and reason.
fn refusal(e: ClientError) -> (i64, String, String) {
    match e {
        ClientError::Rpc(e) => {
            let (port, reason) = ferotrx_ctl::refused_port(&e)
                .map(|(p, r)| (p.to_string(), r.to_string()))
                .unwrap_or_default();
            let reason = if reason.is_empty() {
                e.data
                    .as_ref()
                    .and_then(|d| d.get("reason"))
                    .and_then(|r| r.as_str())
                    .unwrap_or_default()
                    .to_string()
            } else {
                reason
            };
            (e.code, port, reason)
        }
        other => panic!("expected an RPC error, got {other}"),
    }
}

fn names(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn acquire(c: &mut Client, ports: &[&str], force: bool) -> Result<Vec<PortInfo>, ClientError> {
    c.acquire(&AcquireParams {
        ports: names(ports),
        force,
        note: Some("soak test".into()),
    })
}

fn wait_stopped(c: &mut Client, id: u64) -> TcpRunInfo {
    let began = Instant::now();
    loop {
        let r = c.tcp_stats(id).unwrap();
        if !r.state.is_running() {
            return r;
        }
        assert!(began.elapsed() < Duration::from_secs(15), "still running");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn reserved_ports_and_running_runs_keep_other_users_off() {
    let addr = spawn(controller(), tokens());
    let mut alice = login(addr, Some("alice-secret"));
    let mut bob = login(addr, Some("bob-secret"));

    let got = acquire(&mut alice, &["a", "b"], false).unwrap();
    assert_eq!(got.len(), 2);
    assert!(got.iter().all(|p| p.owner.as_deref() == Some("alice")));
    assert_eq!(got[0].note.as_deref(), Some("soak test"));

    // Bob may not send on alice's ports, nor reserve them.
    let (code, port, reason) = refusal(bob.tcp_start(&tcp()).unwrap_err());
    assert_eq!((code, reason.as_str()), (RpcError::FORBIDDEN, "reserved"));
    assert_eq!(port, "a");
    let (_, _, reason) = refusal(start_on(&mut bob, "b").unwrap_err());
    assert_eq!(reason, "reserved");
    let (_, _, reason) = refusal(acquire(&mut bob, &["b"], false).unwrap_err());
    assert_eq!(reason, "reserved");
    let (code, _, _) = refusal(acquire(&mut bob, &["b"], true).unwrap_err());
    assert_eq!(code, RpcError::FORBIDDEN, "force needs the admin role");
    let (_, _, reason) = refusal(bob.release(&names(&["a"]), false).unwrap_err());
    assert_eq!(reason, "not_owner");

    // Alice may, and her reservations outlive her connection.
    drop(alice);
    let mut alice = login(addr, Some("alice-secret"));
    let session = alice.session().unwrap();
    assert_eq!(session.user, "alice");
    assert_eq!(session.ports, names(&["a", "b"]));
    let run = alice.tcp_start(&tcp()).unwrap();
    let ports = bob.ports().unwrap();
    assert_eq!(ports.len(), 2);
    assert_eq!(ports[0].runs.len(), 1);
    assert_eq!(ports[0].runs[0].owner, "alice");
    assert_eq!(ports[0].runs[0].id, run.id);

    // Only alice stops her run.
    let (code, _, reason) = refusal(bob.tcp_stop(run.id).unwrap_err());
    assert_eq!((code, reason.as_str()), (RpcError::FORBIDDEN, "not_owner"));

    // Released, the ports still carry her run: bob still waits.
    assert_eq!(alice.release(&[], false).unwrap(), names(&["a", "b"]));
    let (_, _, reason) = refusal(bob.tcp_start(&tcp()).unwrap_err());
    assert_eq!(reason, "in_use");
    let (_, _, reason) = refusal(acquire(&mut bob, &["a"], false).unwrap_err());
    assert_eq!(reason, "in_use");

    let sessions = bob.sessions().unwrap();
    let users: Vec<&str> = sessions.iter().map(|s| s.user.as_str()).collect();
    assert_eq!(users, ["alice", "bob"]);
    assert_eq!(sessions[0].runs.len(), 1);
    assert_eq!(sessions[1].connections, 1);

    alice.tcp_stop(run.id).unwrap();
    let after = bob.tcp_start(&tcp()).unwrap();
    bob.tcp_stop(after.id).unwrap();
}

#[test]
fn admins_take_ports_and_stop_what_sends_on_them() {
    let addr = spawn(controller(), tokens());
    let mut alice = login(addr, Some("alice-secret"));
    let mut root = login(addr, Some("root-secret"));
    let mut dash = login(addr, Some("dash-secret"));

    acquire(&mut alice, &["a", "b"], false).unwrap();
    let run = alice.tcp_start(&tcp()).unwrap();
    assert_eq!(dash.ports().unwrap().len(), 2);
    let (code, _, _) = refusal(acquire(&mut dash, &["c"], false).unwrap_err());
    assert_eq!(code, RpcError::FORBIDDEN, "read logins reserve nothing");

    let (_, _, reason) = refusal(acquire(&mut root, &["a"], false).unwrap_err());
    assert_eq!(reason, "reserved");
    let got = acquire(&mut root, &["a"], true).unwrap();
    assert_eq!(got[0].owner.as_deref(), Some("root"));
    assert!(got[0].runs.is_empty(), "{got:?}");
    let stopped = wait_stopped(&mut alice, run.id);
    assert!(!stopped.state.is_running());

    // b is still alice's; an admin can release it for her.
    let (_, _, reason) = refusal(root.tcp_start(&tcp()).unwrap_err());
    assert_eq!(reason, "reserved");
    assert_eq!(root.release(&names(&["b"]), true).unwrap(), names(&["b"]));
    let mine = root.tcp_start(&tcp()).unwrap();
    // Admins stop others' runs too; alice cannot stop root's.
    let (_, _, reason) = refusal(alice.tcp_stop(mine.id).unwrap_err());
    assert_eq!(reason, "not_owner");
    root.tcp_stop(mine.id).unwrap();
    assert_eq!(alice.session().unwrap().ports, Vec::<String>::new());
}

#[test]
fn servers_without_logins_take_names_and_can_require_acquiring() {
    let addr = spawn(controller().with_require_acquire(true), Vec::new());
    let mut anon = login(addr, None);
    assert!(anon.info().unwrap().require_acquire);
    assert_eq!(anon.session().unwrap().user, ferotrx_ctl::ANONYMOUS);

    let mut carol = login(addr, None);
    assert_eq!(carol.name_session("carol").unwrap().user, "carol");
    assert!(carol.name_session("not a name").is_err());
    let (_, port, reason) = refusal(carol.tcp_start(&tcp()).unwrap_err());
    assert_eq!((port.as_str(), reason.as_str()), ("a", "not_acquired"));
    acquire(&mut carol, &["a", "b"], false).unwrap();
    let run = carol.tcp_start(&tcp()).unwrap();

    let mut dave = login(addr, None);
    dave.name_session("dave").unwrap();
    let (_, _, reason) = refusal(dave.tcp_start(&tcp()).unwrap_err());
    assert_eq!(reason, "reserved");
    // Without logins nobody can be told apart for sure: anyone may force.
    acquire(&mut dave, &["a", "b"], true).unwrap();
    wait_stopped(&mut carol, run.id);
    assert_eq!(dave.session().unwrap().ports, names(&["a", "b"]));
}

#[test]
fn servers_with_logins_refuse_chosen_names() {
    let addr = spawn(controller(), tokens());
    let mut alice = login(addr, Some("alice-secret"));
    let (code, _, _) = refusal(alice.name_session("bob").unwrap_err());
    assert_eq!(code, RpcError::FORBIDDEN);
    assert_eq!(alice.session().unwrap().user, "alice");
}
