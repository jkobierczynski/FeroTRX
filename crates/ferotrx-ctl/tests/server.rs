use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use ferotrx_core::Capture;
use ferotrx_ctl::protocol::*;
use ferotrx_ctl::{Client, ClientError, Controller, FilePolicy, RpcError, Server};

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
vary = ["ip_src=192.168.20.100..192.168.20.199", "port_src=1024..65535,random"]
"#;

fn server(token: Option<&str>) -> SocketAddr {
    // Tests name files anywhere (temporary directories, the examples).
    let controller = Controller::new().with_file_policy(FilePolicy::unrestricted());
    Server::bind("127.0.0.1:0", controller, token.map(String::from))
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
fn runs_split_over_workers() {
    let mut c = client(server(None));
    load(&mut c);
    let run = c
        .start(&StartParams {
            profile: "lab".into(),
            output: OutputSpec {
                workers: Some(2),
                ..null_output()
            },
            duration: Some("300ms".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(run.workers, 2);
    let mut last = run;
    for _ in 0..100 {
        last = c.stats(last.id).unwrap();
        if !last.state.is_running() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(last.state, RunState::Finished, "{last:?}");
    assert!(last.total.packets > 0, "{last:?}");
    // Other send settings still need an interface.
    let err = c
        .start(&StartParams {
            profile: "lab".into(),
            output: OutputSpec {
                workers: Some(2),
                batch: Some(8),
                ..null_output()
            },
            ..Default::default()
        })
        .unwrap_err();
    assert_eq!(rpc_code(err), RpcError::INVALID_PARAMS);
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
    assert!(profile.streams[0].vary.is_empty());
    assert_eq!(
        profile.streams[1].vary,
        [
            "ip_src=192.168.20.100..192.168.20.199",
            "port_src=1024..65535,random"
        ]
    );
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

/// A TCP profile whose client and server talk over an in-memory cable
/// ("a" to "b"), so the test needs no interfaces.
const TCP_PROFILE: &str = r#"
port = 7
connections = 20
cps = 500
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

fn tcp_server() -> SocketAddr {
    use std::sync::Mutex;
    let spare: Mutex<Option<ferotrx_core::MemoryPort>> = Mutex::new(None);
    let controller = Controller::new().with_port_opener(move |name, _| {
        let mut spare = spare.lock().unwrap();
        match name {
            "a" => {
                let (a, b) = ferotrx_core::memory_ports();
                *spare = Some(b);
                Ok(Box::new(a))
            }
            "b" => Ok(Box::new(spare.take().ok_or("open a first")?)),
            other => Err(format!("no interface {other}").into()),
        }
    });
    Server::bind("127.0.0.1:0", controller, None)
        .unwrap()
        .spawn()
        .unwrap()
}

#[test]
fn tcp_runs_start_finish_and_report() {
    let addr = tcp_server();
    let mut c = client(addr);
    let info = c
        .tcp_start(&TcpStartParams {
            toml: Some(TCP_PROFILE.into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(info.interfaces, ["a", "b"]);
    assert!(info.program.contains("2 messages"), "{}", info.program);
    let id = info.id;
    let mut last = info;
    for _ in 0..100 {
        last = c.tcp_stats(id).unwrap();
        if !last.state.is_running() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(last.state, RunState::Finished, "{last:?}");
    assert_eq!(last.client.completed, 20);
    assert_eq!(last.server.completed, 20);
    assert_eq!(last.client.payload_rx, 20 * 14);
    assert_eq!(last.client.mismatched, 0);
    assert_eq!(c.tcp_runs().unwrap().len(), 1);

    // An endless run, stopped on request.
    let endless = c
        .tcp_start(&TcpStartParams {
            toml: Some(TCP_PROFILE.into()),
            connections: Some(0),
            ..Default::default()
        })
        .unwrap();
    assert!(endless.id > id);
    let stopped = c.tcp_stop(endless.id).unwrap();
    assert_eq!(stopped.state, RunState::Stopped);
    c.tcp_remove(endless.id).unwrap();
    assert_eq!(
        rpc_code(c.tcp_stats(endless.id).unwrap_err()),
        RpcError::NOT_FOUND
    );
}

#[test]
fn tcp_runs_split_over_workers() {
    let mut c = client(tcp_server());
    let info = c
        .tcp_start(&TcpStartParams {
            toml: Some(TCP_PROFILE.into()),
            workers: Some(3),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(info.workers, 3);
    let mut last = info;
    for _ in 0..100 {
        last = c.tcp_stats(last.id).unwrap();
        if !last.state.is_running() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(last.state, RunState::Finished, "{last:?}");
    assert_eq!(last.client.completed, 20);
    assert_eq!(last.server.completed, 20);
    assert_eq!(last.client.mismatched, 0);

    // More workers than connections cannot be shared out.
    let err = c
        .tcp_start(&TcpStartParams {
            toml: Some(TCP_PROFILE.into()),
            workers: Some(30),
            ..Default::default()
        })
        .unwrap_err();
    assert!(err.to_string().contains("connections (20)"), "{err}");
}

#[test]
fn tcp_runs_report_each_template() {
    let mut c = client(tcp_server());
    let mix = r#"
connections = 30
cps = 1000
[[template]]
name = "short"
port = 7
weight = 2
[[template.message]]
from = "client"
text = "hi"
[[template]]
name = "long"
port = 8
[[template.message]]
from = "client"
text = "hello there"
[[template.message]]
from = "server"
text = "general"
[client]
iface = "a"
ip = "10.9.0.1"
[server]
iface = "b"
ip = "10.9.0.2"
ips = 3
"#;
    let info = c
        .tcp_start(&TcpStartParams {
            toml: Some(mix.into()),
            ..Default::default()
        })
        .unwrap();
    assert!(
        info.program.contains("short (weight 2)"),
        "{}",
        info.program
    );
    let mut last = info;
    for _ in 0..100 {
        last = c.tcp_stats(last.id).unwrap();
        if !last.state.is_running() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(last.state, RunState::Finished, "{last:?}");
    let done: Vec<(&str, u64, u64)> = last
        .templates
        .iter()
        .map(|t| (t.name.as_str(), t.client.completed, t.server.completed))
        .collect();
    assert_eq!(done, [("short", 20, 20), ("long", 10, 10)]);
    assert_eq!(last.templates[1].client.payload_rx, 10 * 7);
}

#[test]
fn tcp_start_reports_bad_profiles_and_interfaces() {
    let mut c = client(tcp_server());
    let bad = c
        .tcp_start(&TcpStartParams {
            toml: Some("port = 7".into()),
            ..Default::default()
        })
        .unwrap_err();
    assert_eq!(rpc_code(bad), RpcError::FAILED);
    let no_iface = c
        .tcp_start(&TcpStartParams {
            toml: Some(TCP_PROFILE.replace("iface = \"b\"", "iface = \"zz\"")),
            ..Default::default()
        })
        .unwrap_err();
    match no_iface {
        ClientError::Rpc(e) => assert!(e.message.contains("no interface zz"), "{e}"),
        other => panic!("{other}"),
    }
    let neither = c.tcp_start(&TcpStartParams::default()).unwrap_err();
    assert_eq!(rpc_code(neither), RpcError::INVALID_PARAMS);
}

/// A server whose receivers read from in-memory ports; the test sends into
/// the other end of `wire`.
fn rx_server(
    wire: std::sync::Arc<std::sync::Mutex<Option<ferotrx_core::MemoryPort>>>,
) -> SocketAddr {
    let controller = Controller::new().with_receiver_opener(move |name| {
        if name != "mem0" {
            return Err(format!("no interface {name}").into());
        }
        let (a, b) = ferotrx_core::memory_ports();
        *wire.lock().unwrap() = Some(a);
        Ok(Box::new(ferotrx_core::PortReceiver(b)))
    });
    Server::bind("127.0.0.1:0", controller, None)
        .unwrap()
        .spawn()
        .unwrap()
}

#[test]
fn runs_with_a_receiver_report_loss_per_stream() {
    let wire = Default::default();
    let addr = rx_server(wire);
    let mut c = client(addr);
    load(&mut c);
    let run = c
        .start(&StartParams {
            profile: "lab".into(),
            output: null_output(),
            limit: Some(300),
            rx: Some(RxSpec {
                iface: "mem0".into(),
                wait: Some("50ms".into()),
            }),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(run.rx.as_ref().unwrap().iface, "mem0");
    c.subscribe(Some(run.id), 100).unwrap();
    let last = loop {
        let u = c.next_stats().unwrap();
        if u.last {
            break u.run;
        }
    };
    assert_eq!(last.state, RunState::Finished);
    // Nothing comes back from a null output: everything sent is lost.
    for s in &last.streams {
        let l = s.latency.as_ref().expect("every stream gets a signature");
        assert_eq!(l.tx, Some(s.counters.tagged));
        assert_eq!((l.rx, l.lost), (0, s.counters.tagged));
        assert_eq!(l.loss_pct, 100.0);
        assert_eq!(l.latency.avg_us, None);
    }
    assert_eq!(last.total.tagged, 300);

    let err = c
        .start(&StartParams {
            profile: "lab".into(),
            output: null_output(),
            rx: Some(RxSpec {
                iface: "nope0".into(),
                wait: None,
            }),
            ..Default::default()
        })
        .unwrap_err();
    assert_eq!(rpc_code(err), RpcError::FAILED);
}

#[test]
fn a_receiver_alone_counts_flows_from_elsewhere() {
    use ferotrx_core::*;
    let wire: std::sync::Arc<std::sync::Mutex<Option<MemoryPort>>> = Default::default();
    let addr = rx_server(wire.clone());
    let mut c = client(addr);
    let rx = c
        .rx_start(&RxStartParams {
            iface: "mem0".into(),
            duration: None,
        })
        .unwrap();
    assert_eq!(rx.state, RunState::Running);
    // "Another machine" sends two flows into the wire, dropping some packets.
    let mut port = wire.lock().unwrap().take().unwrap();
    let cap =
        Capture::from_specs(&["eth/ipv4(dst=10.0.0.2)/udp(dport=9)"], Duration::ZERO).unwrap();
    for flow in [1u32, 2] {
        let mut streams = [Stream::new("s", CaptureSource::new(&cap).loops(100))
            .with_rate(Rate::TopSpeed)
            .with_latency(flow)];
        let mut sink = VecSink::default();
        run(&mut streams, &mut sink, &RunConfig::default()).unwrap();
        for (i, p) in sink.packets.iter().enumerate() {
            if flow == 2 && i % 10 == 5 {
                continue;
            }
            PacketPort::send(&mut port, p).unwrap();
        }
    }
    PacketPort::send(&mut port, &[0u8; 60]).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let info = c.rx_stats(rx.id).unwrap();
    assert_eq!(info.counters.packets, 191);
    assert_eq!(info.counters.untagged, 1);
    assert_eq!(info.flows.len(), 2);
    assert_eq!(
        (info.flows[0].flow, info.flows[0].rx, info.flows[0].lost),
        (1, 100, 0)
    );
    // Flow 2 lost seq 5, 15, ... 95: all inside the range seen.
    assert_eq!((info.flows[1].rx, info.flows[1].lost), (90, 10));
    assert!((info.flows[1].loss_pct - 10.0).abs() < 1e-9);
    assert!(info.flows[0].latency.max_us.is_some());
    assert_eq!(c.rx_runs().unwrap().len(), 1);
    let done = c.rx_stop(rx.id).unwrap();
    assert_eq!(done.state, RunState::Stopped);
    assert_eq!(c.rx_remove(rx.id).unwrap().id, rx.id);
    assert!(c.rx_runs().unwrap().is_empty());
    assert_eq!(
        rpc_code(c.rx_stats(rx.id).unwrap_err()),
        RpcError::NOT_FOUND
    );
}

/// A UDP profile with a DNS template and an NTP template over the in-memory cable.
const UDP_PROFILE: &str = r#"
transactions = 30
rate = 1000
[[template]]
name = "dns"
queries = ["www.lab.local A", "nope.lab.local A NXDOMAIN"]
records = ["www.lab.local A 10.9.0.80"]
weight = 2
[[template]]
app = "ntp"
[client]
iface = "a"
ip = "10.9.0.1"
[server]
iface = "b"
ip = "10.9.0.2"
"#;

#[test]
fn udp_runs_start_finish_and_report() {
    let mut c = client(tcp_server());
    let info = c
        .udp_start(&UdpStartParams {
            toml: Some(UDP_PROFILE.into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(info.interfaces, ["a", "b"]);
    assert!(
        info.program.contains("dns (weight 2): DNS: 2 queries"),
        "{}",
        info.program
    );
    let mut last = info;
    for _ in 0..100 {
        last = c.udp_stats(last.id).unwrap();
        if !last.state.is_running() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(last.state, RunState::Finished, "{last:?}");
    assert_eq!((last.client.sent, last.client.answered), (30, 30));
    assert_eq!(last.server.answered, 30);
    assert_eq!(last.templates[0].client.answered, 20);
    assert_eq!(last.templates[0].client.errors, 10);
    assert_eq!(last.templates[1].client.answered, 10);
    assert_eq!(
        last.client.mismatched + last.client.unmatched + last.client.timed_out,
        0
    );
    let rt = last.client.response_time.as_ref().unwrap();
    assert!(rt.max_us.unwrap() < 1_000_000.0, "{rt:?}");
    assert!(last.server.response_time.is_none());
    assert_eq!(c.udp_runs().unwrap().len(), 1);

    let endless = c
        .udp_start(&UdpStartParams {
            toml: Some(UDP_PROFILE.into()),
            transactions: Some(0),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(c.udp_stop(endless.id).unwrap().state, RunState::Stopped);
    c.udp_remove(endless.id).unwrap();
    assert_eq!(
        rpc_code(c.udp_stats(endless.id).unwrap_err()),
        RpcError::NOT_FOUND
    );
    let bad = c
        .udp_start(&UdpStartParams {
            toml: Some("app = \"ntp\"\n[client]\nip = \"10.9.0.1\"\niface = \"zz\"".into()),
            ..Default::default()
        })
        .unwrap_err();
    assert_eq!(rpc_code(bad), RpcError::FAILED);
}
