//! `y1564.*`: a Y.1564 service activation test run by the server over an
//! in-memory wire, as the GUI starts and follows it.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferotrx_core::{memory_ports, MemoryPort, PacketSink, PortReceiver, StepKind};
use ferotrx_ctl::protocol::*;
use ferotrx_ctl::{Client, ClientError, Controller, RpcError, Server};

const PROFILE: &str = r#"
[y1564]
line_rate = "100mbps"
steps = [50, 100]
step_duration = "200ms"
performance_duration = "1200ms"
interval = "250ms"
rx_wait = "100ms"

[[service]]
name = "voice"
packet = "eth(dst=02:00:00:00:01:01)/ipv4(src=10.9.1.2,dst=10.9.2.2,dscp=46)/udp(sport=5004,dport=5004)"
sizes = 252
cir = "2mbps"
ftd = "500ms"

[[service]]
name = "data"
packet = "eth(dst=02:00:00:00:01:01)/ipv4(src=10.9.1.2,dst=10.9.2.3,dscp=10)/udp(sport=4000,dport=9000)"
yellow_packet = "eth(dst=02:00:00:00:01:01)/ipv4(src=10.9.1.2,dst=10.9.2.3,dscp=12)/udp(sport=4000,dport=9000)"
sizes = "emix:ag"
cir = "4mbps"
# Policing offers CIR + 1.25 EIR: well above CIR+EIR and its 5% tolerance.
eir = "4mbps"
"#;

/// A server that sends on "wire0" and receives what was sent on "wire1":
/// a network that delivers everything, and polices nothing.
fn server() -> SocketAddr {
    let other_end: Arc<Mutex<Option<MemoryPort>>> = Default::default();
    let tx_end = other_end.clone();
    let controller = Controller::new()
        .with_bench_sink_opener(move |name, _send, _linktype, workers| {
            if name != "wire0" {
                return Err(format!("no interface {name}").into());
            }
            let (a, b) = memory_ports();
            *tx_end.lock().unwrap() = Some(b);
            let mut sinks: Vec<Box<dyn PacketSink + Send>> = vec![Box::new(a)];
            sinks.truncate(workers.max(1));
            Ok((sinks, "memory".into()))
        })
        .with_receiver_opener(move |name| match (name, other_end.lock().unwrap().take()) {
            ("wire1", Some(b)) => Ok(Box::new(PortReceiver(b))),
            _ => Err(format!("no interface {name}").into()),
        });
    Server::bind("127.0.0.1:0", controller, None)
        .unwrap()
        .spawn()
        .unwrap()
}

fn client(addr: SocketAddr) -> Client {
    let c = Client::connect(addr).unwrap();
    c.set_timeout(Some(Duration::from_secs(20))).unwrap();
    c
}

fn params() -> Y1564StartParams {
    Y1564StartParams {
        toml: Some(PROFILE.into()),
        iface: "wire0".into(),
        rx: "wire1".into(),
        ..Default::default()
    }
}

#[test]
fn a_y1564_test_runs_on_the_server_and_reports_every_step() {
    let mut c = client(server());
    let run = c.y1564_start(&params()).unwrap();
    assert_eq!(run.state, RunState::Running);
    assert_eq!(run.services, ["voice", "data"]);
    let deadline = Instant::now() + Duration::from_secs(30);
    let info = loop {
        let r = c.y1564_get(run.id).unwrap();
        if !r.state.is_running() {
            break r;
        }
        assert!(Instant::now() < deadline, "still running: {r:?}");
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(info.state, RunState::Finished, "{:?}", info.error);
    // voice: 50%, 100%, policing; data: 50%, 100%, CIR+EIR, policing; performance.
    assert_eq!(info.steps.len(), 8);
    let report = info.report.unwrap();
    assert_eq!(report.configuration.len(), 7);
    // Frames more than 5 ms late are skipped, and macOS runners oversleep
    // often enough that the sender falls far short (1.1 of 2 Mbit/s seen).
    // The rate verdicts then judge the sender, not the wire: there, only
    // check them where it kept up.
    let judged = |s: &ferotrx_core::ServiceResult| {
        !cfg!(target_os = "macos") || !s.notes.iter().any(|n| n.contains("fell short"))
    };
    let mut all_judged = true;
    for step in &report.configuration {
        let s = &step.services[0];
        assert_eq!(s.flr_pct, 0.0, "{step:?}");
        if !judged(s) {
            all_judged = false;
        } else if step.step == StepKind::Policing {
            // Nothing polices the memory wire.
            assert!(!s.passed && s.failures[0].contains("not policed"), "{s:?}");
        } else {
            assert!(s.passed, "{step:?}");
        }
    }
    let perf = report.performance.as_ref().unwrap();
    assert!(perf.passed, "{perf:?}");
    for s in &perf.services {
        assert!(!s.intervals.is_empty());
        assert_eq!(s.availability_pct, Some(100.0));
    }
    if all_judged {
        assert!(!report.passed);
        let text = info.text.unwrap();
        assert!(text.contains("Y.1564: FAIL"), "{text}");
    }
    assert_eq!(c.y1564_runs().unwrap().len(), 1);
    c.y1564_remove(run.id).unwrap();
    assert!(c.y1564_runs().unwrap().is_empty());
}

#[test]
fn a_stopped_y1564_test_ends_with_a_partial_report() {
    let mut c = client(server());
    let mut p = params();
    p.step_duration = Some("2s".into());
    p.services = vec!["data".into()];
    p.tests = vec!["configuration".into()];
    let run = c.y1564_start(&p).unwrap();
    assert_eq!(run.services, ["data"]);
    let busy = c.y1564_remove(run.id).unwrap_err();
    assert!(matches!(busy, ClientError::Rpc(_)));
    std::thread::sleep(Duration::from_millis(300));
    let stopped = c.y1564_stop(run.id).unwrap();
    assert_eq!(stopped.state, RunState::Stopped, "{:?}", stopped.error);
    let report = stopped.report.unwrap();
    assert!(report.stopped && !report.passed);
    assert!(report.configuration.len() <= 1);
}

#[test]
fn bad_y1564_tests_are_refused() {
    let mut c = client(server());
    let code = |e: ClientError| match e {
        ClientError::Rpc(e) => e.code,
        other => panic!("{other}"),
    };
    let mut p = params();
    p.tests = vec!["speed".into()];
    assert_eq!(
        code(c.y1564_start(&p).unwrap_err()),
        RpcError::INVALID_PARAMS
    );
    let mut p = params();
    p.services = vec!["fax".into()];
    assert_eq!(
        code(c.y1564_start(&p).unwrap_err()),
        RpcError::INVALID_PARAMS
    );
    let mut p = params();
    p.line_rate = Some("5mbps".into());
    assert_eq!(
        code(c.y1564_start(&p).unwrap_err()),
        RpcError::INVALID_PARAMS
    );
    let mut p = params();
    p.iface = "nope".into();
    assert_eq!(code(c.y1564_start(&p).unwrap_err()), RpcError::FAILED);
    assert_eq!(
        code(c.y1564_start(&Y1564StartParams::default()).unwrap_err()),
        RpcError::INVALID_PARAMS
    );
    assert!(c.y1564_get(99).is_err());
}
