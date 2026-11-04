//! Scenarios run by `LabRunner` over in-memory cables: no interfaces needed.

use std::path::Path;
use std::sync::{Arc, Mutex};

use ferotrx_core::scenario::{compare, run_scenario, Change, RunOptions, Scenario, Verdict};
use ferotrx_core::{memory_ports, MemoryPort, PortReceiver};
use ferotrx_ctl::LabRunner;

/// "a" and "b" are the two ends of a cable, opened in that order. "void"
/// sends into nothing and never receives: a firewall that drops everything.
/// Traffic is sent on "tx" and received on "rx".
fn runner() -> LabRunner {
    let spare: Arc<Mutex<Option<MemoryPort>>> = Arc::default();
    let tx: Arc<Mutex<Option<MemoryPort>>> = Arc::default();
    let tx2 = tx.clone();
    LabRunner::new()
        .with_port_opener(move |name| {
            let mut spare = spare.lock().unwrap();
            match name {
                "a" => {
                    let (a, b) = memory_ports();
                    *spare = Some(b);
                    Ok(Box::new(a))
                }
                "b" => Ok(Box::new(spare.take().ok_or("open a first")?)),
                "void" => Ok(Box::new(memory_ports().0)),
                other => Err(format!("no interface {other}").into()),
            }
        })
        .with_receiver_opener(move |name| match name {
            "rx" => {
                let (a, b) = memory_ports();
                *tx.lock().unwrap() = Some(a);
                Ok(Box::new(PortReceiver(b)))
            }
            other => Err(format!("no interface {other}").into()),
        })
        .with_sink_opener(move |name, _send, _linktype| match name {
            "tx" => Ok(Box::new(tx2.lock().unwrap().take().ok_or("open rx first")?)),
            "void" => Ok(Box::new(memory_ports().0)),
            other => Err(format!("no interface {other}").into()),
        })
}

const SCENARIO: &str = r#"
name = "memory-lab"

[vars]
client_iface = "a"
server_iface = "b"
send = "tx"

[[check]]
name = "echo"
require = ["cps > 1"]
[check.tcp]
port = 7
connections = 10
cps = 500
[[check.tcp.message]]
from = "client"
text = "hello"
[[check.tcp.message]]
from = "server"
text = "hello yourself"
[check.tcp.client]
iface = "${client_iface}"
ip = "10.9.0.1"
[check.tcp.server]
iface = "${server_iface}"
ip = "10.9.0.2"

[[check]]
name = "dns"
require = ["response_avg < 1s"]
[check.udp]
transactions = 10
rate = 1000
queries = ["www.lab.local A"]
records = ["www.lab.local A 10.9.0.80"]
[check.udp.client]
iface = "${client_iface}"
ip = "10.9.0.1"
[check.udp.server]
iface = "${server_iface}"
ip = "10.9.0.2"

[[check]]
name = "telnet blocked"
expect = "blocked"
duration = "500ms"
[check.tcp]
port = 23
connect = "10.9.0.2"
connections = 2
cps = 100
[[check.tcp.message]]
from = "client"
text = "hi"
[check.tcp.client]
iface = "void"
ip = "10.9.0.1"
gateway = "10.9.0.254"
next_hop_mac = "02:00:00:00:00:fe"

[[check]]
name = "stream"
iface = "${send}"
rx = "rx"
rx_wait = "200ms"
require = ["loss_pct < 1%", "latency_p99 < 1s", "duplicates == 0"]
[check.traffic]
[[check.traffic.stream]]
name = "s"
packet = "eth/ipv4(src=10.9.0.1,dst=10.9.0.2)/udp(sport=1000,dport=2000)/raw(len=100)"
interval = "1ms"
loops = 200
rate = "2000pps"
"#;

#[test]
fn checks_pass_and_fail_as_expected() {
    let scenario = Scenario::from_toml(SCENARIO, Path::new("."), &[]).unwrap();
    let mut runner = runner();
    let before = run_scenario(&scenario, &mut runner, RunOptions::default());
    let lines: Vec<String> = before
        .checks
        .iter()
        .map(|c| format!("{} {:?} {:?} {}", c.name, c.verdict, c.error, c.summary))
        .collect();
    assert!(before.passed(), "{lines:#?}\n{}", before.text());
    let echo = &before.checks[0];
    assert_eq!(echo.metrics["completed"], 10.0);
    assert_eq!(echo.metrics["mismatched"], 0.0);
    let dns = &before.checks[1];
    assert_eq!(dns.metrics["answered"], 10.0);
    assert!(dns.metrics.contains_key("response_avg"));
    let blocked = &before.checks[2];
    assert_eq!(blocked.metrics["established"], 0.0);
    assert!(blocked.metrics["connections"] > 0.0);
    let stream = &before.checks[3];
    assert_eq!(stream.metrics["tx_packets"], 200.0);
    assert_eq!(stream.metrics["rx_packets"], 200.0, "{}", stream.summary);
    assert!(stream.metrics["latency_avg"] >= 0.0);

    // The same scenario after "a firewall change": the server is gone, so
    // the echo and the DNS lookups get nowhere, and the stream is dropped.
    let set = [
        ("server_iface".to_string(), "void".to_string()),
        ("client_iface".to_string(), "void".to_string()),
        ("send".to_string(), "void".to_string()),
    ];
    let mut broken = Scenario::from_toml(SCENARIO, Path::new("."), &set).unwrap();
    for c in &mut broken.checks {
        c.duration = Some(std::time::Duration::from_millis(500));
    }
    let after = run_scenario(&broken, &mut runner, RunOptions::default());
    let v: Vec<_> = after.checks.iter().map(|c| c.verdict).collect();
    // The stream is sent into "void": "rx" receives nothing.
    assert_eq!(
        v,
        [Verdict::Fail, Verdict::Fail, Verdict::Pass, Verdict::Fail],
        "{}",
        after.text()
    );
    assert_eq!(after.checks[3].metrics["rx_packets"], 0.0);
    assert!(after.checks[3].failures()[0].starts_with("rx_packets > 0 (was 0)"));

    let c = compare(&before, &after, 0.2, false);
    let changes: Vec<_> = c.checks.iter().map(|c| c.change).collect();
    assert_eq!(
        changes,
        [
            Change::Regressed,
            Change::Regressed,
            Change::Same,
            Change::Regressed
        ]
    );
    assert_eq!(c.regressions(), 3);
}

#[test]
fn a_missing_interface_is_an_error_not_a_failure() {
    let text = SCENARIO.replace("client_iface = \"a\"", "client_iface = \"eth9\"");
    let scenario = Scenario::from_toml(&text, Path::new("."), &[]).unwrap();
    let report = run_scenario(
        &scenario,
        &mut runner(),
        RunOptions {
            only: vec!["echo".into()],
            ..Default::default()
        },
    );
    assert_eq!(report.checks[0].verdict, Verdict::Error);
    assert!(
        report.checks[0].error.as_deref().unwrap().contains("eth9"),
        "{:?}",
        report.checks[0].error
    );
    assert_eq!(report.summary.skipped, 3);
}
