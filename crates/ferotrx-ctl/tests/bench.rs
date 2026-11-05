//! `bench.*`: an RFC 2544 benchmark run by the server over an in-memory
//! wire, as the GUI starts and follows it.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferotrx_core::{memory_ports, MemoryPort, PacketSink, PortReceiver};
use ferotrx_ctl::protocol::*;
use ferotrx_ctl::{Client, ClientError, Controller, RpcError, Server};

const PROFILE: &str = r#"
[benchmark]
packet = "eth(dst=02:00:00:00:01:01)/ipv4(src=10.9.1.2,dst=10.9.2.2)/udp(sport=4000,dport=9000)"
tests = ["throughput", "latency"]
sizes = [252]
line_rate = "10mbps"
trial_duration = "100ms"
warmup = "0s"
resolution = 10.0
"#;

/// A server whose benchmarks send on "wire0" and receive what was sent on
/// "wire1", as a perfect device between two interfaces would.
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

fn params() -> BenchStartParams {
    BenchStartParams {
        toml: Some(PROFILE.into()),
        iface: "wire0".into(),
        rx: "wire1".into(),
        ..Default::default()
    }
}

#[test]
fn a_benchmark_runs_on_the_server_and_reports_every_trial() {
    let mut c = client(server());
    let run = c.bench_start(&params()).unwrap();
    assert_eq!(run.state, RunState::Running);
    assert_eq!(run.tests, ["throughput", "latency"]);
    assert_eq!(run.sizes, ["252"]);
    let info = run.info.as_ref().unwrap();
    assert_eq!(info.backend.as_deref(), Some("memory"));

    let started = Instant::now();
    let mut seen = 0;
    let done = loop {
        let r = c.bench_get(run.id).unwrap();
        assert!(r.trials.len() >= seen, "trials are only added");
        seen = r.trials.len();
        if !r.state.is_running() {
            break r;
        }
        assert!(started.elapsed() < Duration::from_secs(30), "{r:?}");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(done.state, RunState::Finished, "{:?}", done.error);
    let report = done.report.as_ref().unwrap();
    let size = &report.sizes[0];
    assert_eq!(size.size, "252");
    // A perfect wire passes the line rate without loss.
    let t = size.throughput.as_ref().unwrap();
    assert!(t.load_pct > 90.0, "{t:?}");
    assert!(size.latency.is_some());
    assert_eq!(done.trials.len(), size.trials.len());
    assert!(done.trials.iter().all(|t| t.size == "252" && t.trial.lost == 0));
    assert!(done.text.as_ref().unwrap().contains("Throughput"));

    // The report goes through JSON and back, as a client reads it.
    let json = serde_json::to_string(&done).unwrap();
    let back: BenchRunInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(back.report.unwrap().sizes[0].trials.len(), size.trials.len());

    assert_eq!(c.bench_runs().unwrap().len(), 1);
    c.bench_remove(run.id).unwrap();
    assert!(c.bench_runs().unwrap().is_empty());
}

#[test]
fn a_stopped_benchmark_ends_with_a_partial_report() {
    let mut c = client(server());
    let mut p = params();
    p.trial_duration = Some("300ms".into());
    p.sizes = vec!["rfc2544".into()];
    let run = c.bench_start(&p).unwrap();
    assert_eq!(run.sizes.len(), 7);
    // Removing a running benchmark is refused.
    let busy = c.bench_remove(run.id).unwrap_err();
    assert!(matches!(busy, ClientError::Rpc(_)));
    let stopped = c.bench_stop(run.id).unwrap();
    assert_eq!(stopped.state, RunState::Stopped, "{:?}", stopped.error);
    assert!(stopped.report.unwrap().stopped);
}

#[test]
fn bad_benchmarks_are_refused() {
    let mut c = client(server());
    let code = |e: ClientError| match e {
        ClientError::Rpc(e) => e.code,
        other => panic!("{other}"),
    };
    let mut p = params();
    p.tests = vec!["speed".into()];
    assert_eq!(code(c.bench_start(&p).unwrap_err()), RpcError::INVALID_PARAMS);
    let mut p = params();
    p.line_rate = Some("1000pps".into());
    assert_eq!(code(c.bench_start(&p).unwrap_err()), RpcError::INVALID_PARAMS);
    let mut p = params();
    p.iface = "nope".into();
    assert_eq!(code(c.bench_start(&p).unwrap_err()), RpcError::FAILED);
    let p = BenchStartParams::default();
    assert_eq!(code(c.bench_start(&p).unwrap_err()), RpcError::INVALID_PARAMS);
    assert!(c.bench_get(99).is_err());
}
