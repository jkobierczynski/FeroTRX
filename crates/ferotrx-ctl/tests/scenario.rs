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
        .with_port_opener(move |name, _| {
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

/// A controller whose TCP and UDP ports are the cable of [`runner`].
fn controller() -> ferotrx_ctl::Controller {
    let spare: Arc<Mutex<Option<MemoryPort>>> = Arc::default();
    ferotrx_ctl::Controller::new().with_port_opener(move |name, _| {
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
}

/// The checks of SCENARIO that run on ports (no traffic check).
fn port_checks() -> String {
    SCENARIO
        .split("\n[[check]]\nname = \"stream\"")
        .next()
        .unwrap()
        .to_string()
}

fn wait_for(c: &ferotrx_ctl::Controller, id: u64) -> ferotrx_ctl::protocol::ScenarioRunInfo {
    use serde_json::json;
    for _ in 0..300 {
        let v = c.call("scenario.get", json!({ "id": id })).unwrap();
        let info: ferotrx_ctl::protocol::ScenarioRunInfo = serde_json::from_value(v).unwrap();
        if !info.state.is_running() {
            return info;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("scenario run {id} did not end");
}

#[test]
fn the_server_runs_scenarios_and_reports_each_check() {
    use ferotrx_ctl::protocol::{RunState, ScenarioInfo, ScenarioRunInfo};
    use serde_json::json;
    let c = controller();
    let text = port_checks();

    let v = c.call("scenario.check", json!({ "toml": text })).unwrap();
    let info: ScenarioInfo = serde_json::from_value(v).unwrap();
    assert_eq!(info.name, "memory-lab");
    let names: Vec<&str> = info.checks.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["echo", "dns", "telnet blocked"]);
    assert_eq!(info.checks[2].expect, "blocked");
    assert!(info.checks[0].conditions.contains(&"cps > 1".to_string()));

    let v = c.call("scenario.start", json!({ "toml": text })).unwrap();
    let started: ScenarioRunInfo = serde_json::from_value(v).unwrap();
    assert_eq!(started.state, RunState::Running);
    let done = wait_for(&c, started.id);
    assert_eq!(done.state, RunState::Finished);
    let states: Vec<&str> = done.checks.iter().map(|c| c.state.as_str()).collect();
    assert_eq!(states, ["pass", "pass", "pass"], "{done:#?}");
    let report = done.report.as_ref().unwrap();
    assert!(report.passed());
    assert_eq!(
        done.checks[0].report.as_ref().unwrap().metrics["completed"],
        10.0
    );
    assert_eq!(c.scenario_runs().len(), 1);
    // Each check was a TCP or UDP run of the server too, for its statistics.
    let tcp = c.tcp_runs();
    assert_eq!(tcp.len(), 2, "{tcp:#?}");
    assert_eq!(tcp[0].program, "scenario: echo");
    assert_eq!(tcp[0].client.completed, 10);
    assert_eq!(c.udp_runs().len(), 1);

    // `set` and `only`, as `ferotrx scenario run --set --check`.
    let v = c
        .call(
            "scenario.start",
            json!({ "toml": text, "set": { "server_iface": "void" }, "only": ["dns"] }),
        )
        .unwrap();
    let id = v["id"].as_u64().unwrap();
    // The server never answers: stop the run rather than wait for timeouts.
    std::thread::sleep(std::time::Duration::from_millis(300));
    let v = c.call("scenario.stop", json!({ "id": id })).unwrap();
    let stopped: ScenarioRunInfo = serde_json::from_value(v).unwrap();
    assert!(!stopped.state.is_running(), "{stopped:#?}");
    let states: Vec<&str> = stopped.checks.iter().map(|c| c.state.as_str()).collect();
    assert_eq!(states[0], "skipped");
    assert_eq!(states[2], "skipped");
    assert_ne!(states[1], "pass");

    let e = c
        .call("scenario.start", json!({ "toml": text, "only": ["nope"] }))
        .unwrap_err();
    assert!(
        e.message.contains("no check called 'nope'"),
        "{}",
        e.message
    );
    c.call("scenario.remove", json!({ "id": id })).unwrap();
    assert_eq!(c.scenario_runs().len(), 1);
}

#[test]
fn scenario_files_stay_inside_the_data_directories() {
    use ferotrx_ctl::FilePolicy;
    use serde_json::json;
    let d = std::env::temp_dir().join(format!("ferotrx-scn-files-{}", std::process::id()));
    std::fs::create_dir_all(d.join("data")).unwrap();
    std::fs::write(d.join("secret.toml"), "port = 7\n").unwrap();
    std::fs::write(d.join("data/echo.toml"), "port = 7\n[[message]]\nfrom = \"client\"\ntext = \"hi\"\n[client]\niface = \"a\"\nip = \"10.9.0.1\"\n[server]\niface = \"b\"\nip = \"10.9.0.2\"\n").unwrap();
    let c = controller().with_file_policy(FilePolicy::dirs([d.join("data")]).unwrap());
    let scenario = |file: &str| format!("[[check]]\nname = \"x\"\ntcp = \"{file}\"\n");

    let v = c
        .call("scenario.check", json!({ "toml": scenario("echo.toml") }))
        .unwrap();
    assert_eq!(v["checks"][0]["source"], "echo.toml");
    let e = c
        .call(
            "scenario.check",
            json!({ "toml": scenario("../secret.toml") }),
        )
        .unwrap_err();
    assert!(e.message.contains("outside"), "{}", e.message);
    let e = c
        .call(
            "scenario.check",
            json!({ "toml": scenario("echo.toml"), "base_dir": d.display().to_string() }),
        )
        .unwrap_err();
    assert!(e.message.contains("outside"), "{}", e.message);
    std::fs::write(d.join("data/s.toml"), scenario("echo.toml")).unwrap();
    let v = c
        .call("scenario.check", json!({ "path": "s.toml" }))
        .unwrap();
    assert_eq!(v["name"], "s");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_scenario_that_names_a_lab_needs_one_or_lab_false() {
    use serde_json::json;
    let c = controller();
    let text = format!("{}\n[lab]\nblock_tcp = [8080]\n", port_checks());
    let v = c.call("scenario.check", json!({ "toml": text })).unwrap();
    assert_eq!(v["lab"]["block_tcp"], json!([8080]));
    // This controller allows no labs.
    let e = c
        .call("scenario.start", json!({ "toml": text }))
        .unwrap_err();
    assert!(e.message.contains("serve --lab"), "{}", e.message);
    // On what is there.
    let v = c
        .call(
            "scenario.start",
            json!({ "toml": text, "lab": false, "only": ["echo"] }),
        )
        .unwrap();
    let done = wait_for(&c, v["id"].as_u64().unwrap());
    assert!(done.report.unwrap().passed());
}

const Y1564: &str = r#"
name = "service activation"
iface = "tx"
rx = "rx"

[[check]]
name = "performance"
require = ["availability_pct >= 99.9%", "flr_pct < 0.1%"]
[check.y1564.y1564]
tests = ["performance"]
performance_duration = "1s"
interval = "200ms"
rx_wait = "100ms"
[[check.y1564.service]]
name = "data"
packet = "eth/ipv4(src=10.9.0.1,dst=10.9.0.2)/udp(sport=1000,dport=2000)"
cir = "2mbps"

[[check]]
name = "unpoliced"
expect = "fail"
[check.y1564.y1564]
tests = ["configuration"]
steps = [100]
step_duration = "200ms"
rx_wait = "100ms"
[[check.y1564.service]]
name = "data"
packet = "eth/ipv4(src=10.9.0.1,dst=10.9.0.2)/udp(sport=1000,dport=2000)"
cir = "2mbps"
"#;

#[test]
fn y1564_checks_pass_and_an_unpoliced_network_fails_policing() {
    let scenario = Scenario::from_toml(Y1564, Path::new("."), &[]).unwrap();
    let report = run_scenario(&scenario, &mut runner(), RunOptions::default());
    assert!(report.passed(), "{}", report.text());
    let perf = &report.checks[0];
    assert_eq!(perf.metrics["passed"], 1.0);
    assert_eq!(perf.metrics["availability_pct"], 100.0);
    assert!(perf.metrics["ir_mbps"] > 1.8, "{:?}", perf.metrics);
    let unpoliced = &report.checks[1];
    // 100% CIR passes, policing fails: nothing polices the memory wire.
    assert_eq!(unpoliced.metrics["passed"], 0.0);
    assert_eq!(unpoliced.metrics["steps"], 2.0);
    assert_eq!(unpoliced.metrics["steps_failed"], 1.0);
    assert!(
        unpoliced.summary.contains("failed: data"),
        "{}",
        unpoliced.summary
    );
}
