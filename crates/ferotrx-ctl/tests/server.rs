use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use ferotrx_core::Capture;
use ferotrx_ctl::protocol::*;
use ferotrx_ctl::{Client, ClientError, Controller, RpcError, Server};

const PROFILE: &str = r#"
[[stream]]
name = "ping"
packet = "eth(dst=02:00:00:00:00:01)/vlan(id=10)/ipv4(src=192.168.10.100,dst=192.168.20.50)/icmp"
rate = "2000pps"
loops = 0

[[stream]]
name = "dns"
packet = "eth/vlan(id=20)/ipv4(dst=192.168.20.53)/udp/dns(q=example.com)"
rate = "1000pps"
loops = 0
"#;

fn server(token: Option<&str>) -> SocketAddr {
    Server::bind("127.0.0.1:0", Controller::new(), token.map(String::from))
        .unwrap()
        .spawn()
        .unwrap()
}

fn client(addr: SocketAddr) -> Client {
    let c = Client::connect(addr).unwrap();
    c.set_timeout(Some(Duration::from_secs(20))).unwrap();
    c
}

fn load(c: &mut Client) -> ProfileInfo {
    c.load_profile(&LoadProfileParams {
        name: Some("lab".into()),
        toml: Some(PROFILE.into()),
        ..Default::default()
    })
    .unwrap()
}

fn null_output() -> OutputSpec {
    OutputSpec {
        null: true,
        ..Default::default()
    }
}

fn rpc_code(e: ClientError) -> i64 {
    match e {
        ClientError::Rpc(e) => e.code,
        other => panic!("expected an RPC error, got {other}"),
    }
}

#[test]
fn load_start_watch_and_finish() {
    let addr = server(None);
    let mut c = client(addr);
    let info = c.info().unwrap();
    assert_eq!(info.protocol, PROTOCOL_VERSION);
    assert!(!info.auth_required);

    let profile = load(&mut c);
    assert_eq!(profile.streams.len(), 2);
    assert_eq!(profile.streams[0].rate, "2000pps");
    assert_eq!(c.profiles().unwrap(), vec![profile]);

    let run = c
        .start(&StartParams {
            profile: "lab".into(),
            output: null_output(),
            duration: Some("600ms".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(run.state, RunState::Running);
    assert_eq!(run.output, "null");

    c.subscribe(Some(run.id), 100).unwrap();
    let mut updates = Vec::new();
    loop {
        let u = c.next_stats().unwrap();
        assert_eq!(u.run.id, run.id);
        let last = u.last;
        updates.push(u);
        if last {
            break;
        }
    }
    assert!(updates.len() >= 3, "{} updates", updates.len());
    let last = &updates.last().unwrap().run;
    assert_eq!(last.state, RunState::Finished);
    // About 3000 pps for 0.6 s.
    assert!(last.total.packets > 900, "{:?}", last.total);
    assert_eq!(last.streams.len(), 2);
    assert_eq!(last.streams[1].name, "dns");
    assert_eq!(
        last.total.packets,
        last.streams[0].counters.packets + last.streams[1].counters.packets
    );
    // Counters only go up.
    for w in updates.windows(2) {
        assert!(w[1].run.total.packets >= w[0].run.total.packets);
    }

    assert_eq!(c.stats(run.id).unwrap().state, RunState::Finished);
    assert_eq!(c.runs().unwrap().len(), 1);
    c.remove(run.id).unwrap();
    assert!(c.runs().unwrap().is_empty());
}

#[test]
fn stop_a_run_from_another_connection() {
    let addr = server(None);
    let mut a = client(addr);
    load(&mut a);
    let run = a
        .start(&StartParams {
            profile: "lab".into(),
            output: null_output(),
            rate: Some("500pps".into()),
            ..Default::default()
        })
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));

    let mut b = client(addr);
    let live = b.stats(run.id).unwrap();
    assert_eq!(live.state, RunState::Running);
    assert!(live.total.packets > 0);
    // The rate override applies to both streams: about 2 x 500 pps.
    assert!(live.total.pps < 1500.0, "{}", live.total.pps);

    let stopped = b.stop(run.id).unwrap();
    assert_eq!(stopped.state, RunState::Stopped);
    assert!(stopped.total.packets >= live.total.packets);
    assert_eq!(a.stats(run.id).unwrap().state, RunState::Stopped);
}

#[test]
fn all_runs_subscription_reports_the_end() {
    let addr = server(None);
    let mut c = client(addr);
    load(&mut c);
    let sub = c.subscribe(None, 50).unwrap();
    let run = c
        .start(&StartParams {
            profile: "lab".into(),
            output: null_output(),
            limit: Some(200),
            ..Default::default()
        })
        .unwrap();
    loop {
        let u = c.next_stats().unwrap();
        assert_eq!(u.subscription, sub);
        if u.last {
            assert_eq!(u.run.id, run.id);
            assert_eq!(u.run.total.packets, 200);
            break;
        }
    }
    c.unsubscribe(sub).unwrap();
    assert_eq!(
        rpc_code(c.unsubscribe(sub).unwrap_err()),
        RpcError::NOT_FOUND
    );
}

#[test]
fn writes_to_a_pcap_file() {
    let dir = std::env::temp_dir().join(format!("ferotrx-ctl-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("out.pcap");

    let mut c = client(server(None));
    load(&mut c);
    let run = c
        .start(&StartParams {
            profile: "lab".into(),
            output: OutputSpec {
                file: Some(path.clone()),
                ..Default::default()
            },
            rate: Some("topspeed".into()),
            limit: Some(50),
            ..Default::default()
        })
        .unwrap();
    c.subscribe(Some(run.id), 50).unwrap();
    while !c.next_stats().unwrap().last {}

    let cap = Capture::from_path(&path).unwrap();
    assert_eq!(cap.len(), 50);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn reports_errors() {
    let mut c = client(server(None));
    let call =
        |c: &mut Client, m: &str, p: serde_json::Value| rpc_code(c.call_value(m, p).unwrap_err());

    assert_eq!(
        call(&mut c, "nope", serde_json::Value::Null),
        RpcError::METHOD_NOT_FOUND
    );
    assert_eq!(
        call(&mut c, "run.stats", serde_json::json!({"id": "x"})),
        RpcError::INVALID_PARAMS
    );
    assert_eq!(
        call(&mut c, "run.stats", serde_json::json!({"id": 9})),
        RpcError::NOT_FOUND
    );
    assert_eq!(
        call(
            &mut c,
            "run.start",
            serde_json::json!({"profile": "lab", "output": {"null": true}})
        ),
        RpcError::NOT_FOUND
    );
    load(&mut c);
    assert_eq!(
        call(
            &mut c,
            "run.start",
            serde_json::json!({"profile": "lab", "output": {}})
        ),
        RpcError::INVALID_PARAMS
    );
    assert_eq!(
        call(
            &mut c,
            "run.start",
            serde_json::json!({"profile": "lab", "output": {"null": true}, "rate": "fast"})
        ),
        RpcError::INVALID_PARAMS
    );
    for output in [
        serde_json::json!({"null": true, "backend": "af_xdp"}),
        serde_json::json!({"iface": "eth0", "backend": "netmap"}),
        serde_json::json!({"iface": "eth0", "xdp_mode": "fast"}),
        serde_json::json!({"iface": "eth0", "batch": 0}),
    ] {
        assert_eq!(
            call(
                &mut c,
                "run.start",
                serde_json::json!({"profile": "lab", "output": output})
            ),
            RpcError::INVALID_PARAMS,
            "{output}"
        );
    }
    // A backend this build lacks, or an interface that does not exist, fails to start.
    assert_eq!(
        call(
            &mut c,
            "run.start",
            serde_json::json!({"profile": "lab", "output": {"iface": "no-such-if0", "backend": "af_xdp"}})
        ),
        RpcError::FAILED
    );
    assert_eq!(
        call(
            &mut c,
            "profile.load",
            serde_json::json!({"name": "bad", "toml": "[[stream]]\nrate = \"1x\""})
        ),
        RpcError::FAILED
    );
    assert_eq!(
        call(
            &mut c,
            "profile.load",
            serde_json::json!({"path": "/does/not/exist.toml"})
        ),
        RpcError::FAILED
    );
    // The connection still works after errors.
    assert_eq!(c.profiles().unwrap().len(), 1);
}

#[test]
fn rejects_malformed_lines() {
    let addr = server(None);
    let stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut w = stream.try_clone().unwrap();
    let mut r = BufReader::new(stream);
    let mut ask = |line: &str| {
        w.write_all(line.as_bytes()).unwrap();
        w.write_all(b"\n").unwrap();
        let mut answer = String::new();
        r.read_line(&mut answer).unwrap();
        serde_json::from_str::<serde_json::Value>(&answer).unwrap()
    };
    assert_eq!(ask("{not json")["error"]["code"], RpcError::PARSE_ERROR);
    assert_eq!(ask("[1,2]")["error"]["code"], RpcError::INVALID_REQUEST);
    let v = ask(r#"{"jsonrpc":"1.0","id":4,"method":"server.info"}"#);
    assert_eq!(v["error"]["code"], RpcError::INVALID_REQUEST);
    assert_eq!(v["id"], 4);
    let v = ask(r#"{"jsonrpc":"2.0","id":"a","method":"server.info"}"#);
    assert_eq!(v["result"]["name"], "ferotrx");
    assert_eq!(v["id"], "a");
}

#[test]
fn token_is_required_when_set() {
    let addr = server(Some("s3cret"));
    let mut c = client(addr);
    // server.info works without auth, so clients can find out they need it.
    assert!(c.info().unwrap().auth_required);
    assert_eq!(rpc_code(c.profiles().unwrap_err()), RpcError::UNAUTHORIZED);
    assert_eq!(
        rpc_code(c.auth("wrong").unwrap_err()),
        RpcError::UNAUTHORIZED
    );
    c.auth("s3cret").unwrap();
    assert!(c.profiles().unwrap().is_empty());

    // Each connection authenticates on its own.
    let mut d = client(addr);
    assert_eq!(rpc_code(d.runs().unwrap_err()), RpcError::UNAUTHORIZED);
}
