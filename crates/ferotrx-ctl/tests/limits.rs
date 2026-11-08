//! Traffic limits (`ferotrx serve --allow-iface/--allow-dst/--max-*`):
//! starts beyond them are refused with FORBIDDEN and the limit, runs end at
//! `max_duration`, and the frames of all runs are paced and checked.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferotrx_core::{memory_ports, MemoryPort, PacketSink, PortReceiver};
use ferotrx_ctl::protocol::*;
use ferotrx_ctl::{
    AuditLog, Client, ClientError, Controller, Limits, RpcError, Server, ServerConfig,
};

const PROFILE: &str = r#"
[[stream]]
name = "ping"
packet = "eth(dst=02:00:00:00:00:01)/ipv4(src=10.9.0.1,dst=192.168.20.50)/icmp"
rate = "2000pps"
loops = 0

[[stream]]
name = "dns"
packet = "eth/ipv4(dst=10.9.0.53)/udp/dns(q=example.com)"
rate = "1000pps"
loops = 0
"#;

/// Inside the allowed destinations, but varied out of them after 100 frames.
const VARIED: &str = r#"
[[stream]]
name = "walk"
packet = "eth/ipv4(src=10.9.0.1,dst=10.9.0.10)/udp"
rate = "100pps"
loops = 0
vary = ["ip_dst=10.9.0.10..10.9.1.10"]
"#;

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
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// A controller whose TCP/UDP runs open "a" and "b", the two ends of an
/// in-memory cable, and whose benchmarks send on "wire0" and receive on "wire1".
fn controller(limits: Limits) -> Controller {
    let spare: Mutex<Option<MemoryPort>> = Mutex::new(None);
    let other_end: Arc<Mutex<Option<MemoryPort>>> = Default::default();
    let tx_end = other_end.clone();
    Controller::new()
        .with_limits(limits)
        .with_port_opener(move |name, _| {
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
        .with_bench_sink_opener(move |name, _send, _linktype, _workers| {
            if name != "wire0" {
                return Err(format!("no interface {name}").into());
            }
            let (a, b) = memory_ports();
            *tx_end.lock().unwrap() = Some(b);
            let sinks: Vec<Box<dyn PacketSink + Send>> = vec![Box::new(a)];
            Ok((sinks, "memory".into()))
        })
        .with_receiver_opener(move |name| match (name, other_end.lock().unwrap().take()) {
            ("wire1", Some(b)) => Ok(Box::new(PortReceiver(b))),
            _ => Err(format!("no interface {name}").into()),
        })
}

fn spawn(limits: Limits, audit: &Buf) -> SocketAddr {
    let config = ServerConfig {
        audit: Some(AuditLog::to_writer(audit.clone())),
        ..Default::default()
    };
    Server::with_config("127.0.0.1:0", controller(limits), config)
        .unwrap()
        .spawn()
        .unwrap()
}

fn client(addr: SocketAddr) -> Client {
    let c = Client::connect(addr).unwrap();
    c.set_timeout(Some(Duration::from_secs(20))).unwrap();
    c
}

/// The limit a refusal names.
fn limit_of(e: ClientError) -> String {
    match e {
        ClientError::Rpc(e) => {
            assert_eq!(e.code, RpcError::FORBIDDEN, "{}", e.message);
            ferotrx_ctl::refused_limit(&e)
                .unwrap_or_else(|| panic!("no limit in {e:?}"))
                .to_string()
        }
        other => panic!("expected an RPC error, got {other}"),
    }
}

fn limits() -> Limits {
    Limits {
        interfaces: ["a", "b", "x", "wire0", "wire1"].map(String::from).to_vec(),
        destinations: vec!["10.9.0.0/24".parse().unwrap()],
        max_pps: Some(2500.0),
        max_duration: Some(60.0),
        max_runs: Some(2),
        max_flows: Some(1000),
        ..Default::default()
    }
}

fn start(
    c: &mut Client,
    iface: &str,
    rate: Option<&str>,
    duration: Option<&str>,
) -> Result<RunInfo, ClientError> {
    c.start(&StartParams {
        profile: "lab".into(),
        output: OutputSpec {
            iface: Some(iface.into()),
            ..Default::default()
        },
        rate: rate.map(String::from),
        duration: duration.map(String::from),
        ..Default::default()
    })
}

fn wait_tcp(c: &mut Client, id: u64, within: Duration) -> TcpRunInfo {
    let began = Instant::now();
    loop {
        let r = c.tcp_stats(id).unwrap();
        if !r.state.is_running() {
            return r;
        }
        assert!(began.elapsed() < within, "still running: {r:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn starts_beyond_a_limit_are_refused_with_the_limit() {
    let audit = Buf::default();
    let mut c = client(spawn(limits(), &audit));
    let info = c.info().unwrap();
    let l = info
        .limits
        .as_ref()
        .expect("server.info reports the limits");
    assert_eq!(l.limits, limits());

    c.load_profile(&LoadProfileParams {
        name: Some("lab".into()),
        toml: Some(PROFILE.into()),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        limit_of(start(&mut c, "eth9", None, None).unwrap_err()),
        "interfaces"
    );
    // 2000 + 1000 pps.
    assert_eq!(
        limit_of(start(&mut c, "x", None, None).unwrap_err()),
        "max_pps"
    );
    assert_eq!(
        limit_of(start(&mut c, "x", Some("topspeed"), None).unwrap_err()),
        "allow_unlimited"
    );
    assert_eq!(
        limit_of(start(&mut c, "x", Some("500pps"), Some("2m")).unwrap_err()),
        "max_duration"
    );
    // Rates fit; the ping goes to 192.168.20.50.
    let e = start(&mut c, "x", Some("500pps"), None).unwrap_err();
    assert!(e.to_string().contains("192.168.20.50"), "{e}");
    assert_eq!(limit_of(e), "destinations");
    // A variation that walks out of the range is caught in the sample.
    c.load_profile(&LoadProfileParams {
        name: Some("lab".into()),
        toml: Some(VARIED.into()),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        limit_of(start(&mut c, "x", None, None).unwrap_err()),
        "destinations"
    );
    // A receiver on an interface outside the list.
    let e = c
        .start(&StartParams {
            profile: "lab".into(),
            output: OutputSpec {
                null: true,
                ..Default::default()
            },
            rx: Some(RxSpec {
                iface: "eth9".into(),
                wait: None,
            }),
            ..Default::default()
        })
        .unwrap_err();
    assert_eq!(limit_of(e), "interfaces");
    // Files and the null output put nothing on the network.
    let null = c
        .start(&StartParams {
            profile: "lab".into(),
            output: OutputSpec {
                null: true,
                ..Default::default()
            },
            rate: Some("topspeed".into()),
            limit: Some(1000),
            ..Default::default()
        })
        .unwrap();
    c.stop(null.id).unwrap();

    let tcp = |cps: Option<f64>, concurrency: Option<usize>, toml: &str| TcpStartParams {
        toml: Some(toml.into()),
        cps,
        concurrency,
        ..Default::default()
    };
    assert_eq!(
        limit_of(
            c.tcp_start(&tcp(Some(2000.0), None, TCP_PROFILE))
                .unwrap_err()
        ),
        "max_flows"
    );
    assert_eq!(
        limit_of(
            c.tcp_start(&tcp(None, Some(5000), TCP_PROFILE))
                .unwrap_err()
        ),
        "max_flows"
    );
    let elsewhere = TCP_PROFILE.replace("10.9.0.2", "10.8.0.2");
    assert_eq!(
        limit_of(c.tcp_start(&tcp(None, None, &elsewhere)).unwrap_err()),
        "destinations"
    );
    let wrong_iface = TCP_PROFILE.replace("iface = \"b\"", "iface = \"eth9\"");
    assert_eq!(
        limit_of(c.tcp_start(&tcp(None, None, &wrong_iface)).unwrap_err()),
        "interfaces"
    );
    assert_eq!(
        limit_of(
            c.tcp_start(&TcpStartParams {
                duration: Some("5m".into()),
                ..tcp(None, None, TCP_PROFILE)
            })
            .unwrap_err()
        ),
        "max_duration"
    );

    // Two runs at once, not three.
    let endless = |c: &mut Client| {
        c.tcp_start(&TcpStartParams {
            toml: Some(TCP_PROFILE.into()),
            connections: Some(0),
            cps: Some(20.0),
            ..Default::default()
        })
    };
    let one = endless(&mut c).unwrap();
    let two = endless(&mut c).unwrap();
    assert_eq!(limit_of(endless(&mut c).unwrap_err()), "max_runs");
    c.tcp_stop(one.id).unwrap();
    let three = endless(&mut c).unwrap();
    c.tcp_stop(two.id).unwrap();
    c.tcp_stop(three.id).unwrap();

    // Benchmarks search for the top rate: refused while rates are limited.
    let bench = c
        .bench_start(&BenchStartParams {
            toml: Some(BENCH.into()),
            iface: "wire0".into(),
            rx: "wire1".into(),
            ..Default::default()
        })
        .unwrap_err();
    assert_eq!(limit_of(bench), "allow_unlimited");

    let log = audit.text();
    for limit in [
        "interfaces",
        "max_pps",
        "allow_unlimited",
        "max_duration",
        "destinations",
        "max_flows",
        "max_runs",
    ] {
        assert!(
            log.lines()
                .any(|l| l.contains("\"event\":\"limit_refused\"")
                    && l.contains(&format!("\"limit\":\"{limit}\""))),
            "no limit_refused for {limit} in\n{log}"
        );
    }
}

#[test]
fn runs_without_a_duration_end_at_max_duration() {
    let audit = Buf::default();
    let mut c = client(spawn(
        Limits {
            max_duration: Some(1.0),
            ..Default::default()
        },
        &audit,
    ));
    let began = Instant::now();
    let run = c
        .tcp_start(&TcpStartParams {
            toml: Some(TCP_PROFILE.into()),
            connections: Some(0),
            cps: Some(50.0),
            ..Default::default()
        })
        .unwrap();
    let done = wait_tcp(&mut c, run.id, Duration::from_secs(10));
    assert!(
        began.elapsed() >= Duration::from_millis(900),
        "{:?}",
        began.elapsed()
    );
    assert_eq!(done.state, RunState::Finished, "{done:?}");
    assert!(done.client.completed > 10, "{done:?}");
}

const BENCH: &str = r#"
[benchmark]
packet = "eth(dst=02:00:00:00:01:01)/ipv4(src=10.9.0.1,dst=10.9.0.2)/udp(sport=4000,dport=9000)"
tests = ["throughput"]
sizes = [64, 128, 256, 512, 1024, 1280, 1518]
line_rate = "10mbps"
trial_duration = "500ms"
warmup = "0s"
resolution = 1.0
"#;

#[test]
fn runs_that_go_on_are_stopped_at_max_duration() {
    let audit = Buf::default();
    let mut c = client(spawn(
        Limits {
            max_duration: Some(1.0),
            max_pps: Some(1e6),
            allow_unlimited: true,
            ..Default::default()
        },
        &audit,
    ));
    let began = Instant::now();
    let run = c
        .bench_start(&BenchStartParams {
            toml: Some(BENCH.into()),
            iface: "wire0".into(),
            rx: "wire1".into(),
            ..Default::default()
        })
        .unwrap();
    let done = loop {
        let r = c.bench_get(run.id).unwrap();
        if !r.state.is_running() {
            break r;
        }
        assert!(
            began.elapsed() < Duration::from_secs(10),
            "still running: {:?}",
            r.state
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    // Seven sizes of binary search take far longer than a second.
    assert!(
        began.elapsed() < Duration::from_secs(5),
        "{:?}",
        began.elapsed()
    );
    assert_ne!(done.state, RunState::Finished, "{:?}", done.error);
    let log = audit.text();
    assert!(
        log.contains("\"event\":\"limit_stopped\"") && log.contains("\"kind\":\"bench\""),
        "{log}"
    );
}

#[test]
fn frames_to_other_destinations_are_dropped_and_rates_held() {
    // The client may reach the server, but the server's answers to the
    // client go nowhere: the connections cannot complete.
    let audit = Buf::default();
    let mut c = client(spawn(
        Limits {
            destinations: vec!["10.9.0.2".parse().unwrap()],
            max_duration: Some(2.0),
            ..Default::default()
        },
        &audit,
    ));
    let run = c
        .tcp_start(&TcpStartParams {
            toml: Some(TCP_PROFILE.into()),
            connections: Some(5),
            ..Default::default()
        })
        .unwrap();
    let done = wait_tcp(&mut c, run.id, Duration::from_secs(15));
    assert_eq!(done.client.completed, 0, "{done:?}");
    let refused = c.info().unwrap().limits.unwrap().refused_frames;
    assert!(refused > 0);

    // 20 connections of about ten frames each, at 200 frames a second.
    let mut c = client(spawn(
        Limits {
            max_pps: Some(200.0),
            ..Default::default()
        },
        &audit,
    ));
    let began = Instant::now();
    let run = c
        .tcp_start(&TcpStartParams {
            toml: Some(TCP_PROFILE.into()),
            ..Default::default()
        })
        .unwrap();
    let done = wait_tcp(&mut c, run.id, Duration::from_secs(20));
    let took = began.elapsed();
    assert_eq!(done.client.completed, 20, "{done:?}");
    // At least 8 frames a connection (handshake, two messages, two FINs
    // and their ACKs): 160 frames, 0.8 s; unlimited it takes 40 ms.
    assert!(took >= Duration::from_millis(700), "{took:?}");
}
