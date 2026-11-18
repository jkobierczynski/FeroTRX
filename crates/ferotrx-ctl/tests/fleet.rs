//! Fleets of agents in this process: control servers with in-memory cables
//! between them, deployed to and started together by `run_fleet`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferotrx_core::fleet::FleetPlan;
use ferotrx_core::scenario::CheckKind;
use ferotrx_core::{memory_ports, MemoryPort};
use ferotrx_ctl::fleet::{run_fleet, FleetEvent, FleetOptions};
use ferotrx_ctl::protocol::*;
use ferotrx_ctl::{Client, ClientError, Controller, FilePolicy, Server};

type Cables = Arc<Mutex<std::collections::HashMap<String, MemoryPort>>>;

/// An agent with its own data directory. Interfaces named `cable-N` are
/// the ends of in-memory cables shared by every agent of `cables`: the
/// first to open one gets one end, the second the other. "a" and "b" are
/// the two ends of a cable of this agent alone.
fn agent(name: &str, cables: &Cables) -> (SocketAddr, PathBuf) {
    let dir = std::env::temp_dir().join(format!("ferotrx-fleet-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cables = cables.clone();
    let own: Arc<Mutex<Option<MemoryPort>>> = Arc::default();
    let controller = Controller::new()
        .with_file_policy(FilePolicy::dirs([&dir]).unwrap())
        .with_port_opener(move |iface, _| {
            if iface.starts_with("cable") {
                let mut all = cables.lock().unwrap();
                return Ok(Box::new(match all.remove(iface) {
                    Some(end) => end,
                    None => {
                        let (a, b) = memory_ports();
                        all.insert(iface.to_string(), b);
                        a
                    }
                }));
            }
            let mut own = own.lock().unwrap();
            match iface {
                "a" => {
                    let (a, b) = memory_ports();
                    *own = Some(b);
                    Ok(Box::new(a))
                }
                "b" => Ok(Box::new(own.take().ok_or("open a first")?)),
                other => Err(format!("no interface {other}").into()),
            }
        })
        .with_capture_opener({
            // cap-east: e, cap-west: w.
            let tag = name.as_bytes().get(4).copied().unwrap_or(b'x');
            move |iface, _| {
                if iface != "cap0" {
                    return Err(format!("no interface {iface}").into());
                }
                // Three frames, 10 ms apart, marked with the agent's initial.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap();
                let frames = (0..3u64).map(move |i| ferotrx_core::Frame {
                    ts: now + Duration::from_millis(10 * i),
                    len: 60,
                    data: vec![tag; 60],
                });
                Ok(Box::new(ferotrx_core::live::VecFrameSource::new(1, frames)))
            }
        });
    let addr = Server::bind("127.0.0.1:0", controller, None)
        .unwrap()
        .spawn()
        .unwrap();
    (addr, dir)
}

/// A folder with the plan's profiles; the pcap one folder up.
fn plans(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ferotrx-fleet-plans-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("plans")).unwrap();
    std::fs::create_dir_all(d.join("captures")).unwrap();
    let pcap = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/http.pcap");
    std::fs::copy(pcap, d.join("captures/http.pcap")).unwrap();
    std::fs::write(
        d.join("plans/server.toml"),
        "pcap = \"../captures/http.pcap\"\n[server]\nip = \"${server}/24\"\n\
         [tcp]\nrto = \"50ms\"\n",
    )
    .unwrap();
    std::fs::write(
        d.join("plans/clients.toml"),
        "pcap = \"../captures/http.pcap\"\nconnect = \"${server}:80\"\ncps = 50\n\
         connections = 6\n[client]\nip = \"${client_ip}/24\"\n[tcp]\nrto = \"50ms\"\n",
    )
    .unwrap();
    std::fs::write(
        d.join("plans/pair.toml"),
        "pcap = \"../captures/http.pcap\"\ncps = 100\nconnections = 4\n\
         [client]\niface = \"a\"\nip = \"10.7.0.10/24\"\n\
         [server]\niface = \"b\"\nip = \"10.7.0.80/24\"\n",
    )
    .unwrap();
    d
}

fn run(plan: &FleetPlan) -> ferotrx_ctl::fleet::FleetReport {
    let mut lines = Vec::new();
    let report = run_fleet(plan, &FleetOptions::default(), &mut |e| {
        if let FleetEvent::Sample(s) = e {
            lines.push(s.line());
        }
    })
    .unwrap();
    assert!(!lines.is_empty());
    report
}

#[test]
fn clients_and_server_on_two_agents() {
    let cables = Cables::default();
    let (east, east_dir) = agent("east", &cables);
    let (srv, srv_dir) = agent("srv", &cables);
    let d = plans("two");
    let text = format!(
        r#"
name = "two agents"
start_delay = "500ms"
interval = "200ms"

[vars]
server = "10.9.0.80"

[[agent]]
name = "east"
address = "{east}"
vars = {{ client_ip = "10.9.0.100" }}

[[agent]]
name = "srv"
address = "{srv}"

[[run]]
name = "server"
agent = "srv"
tcp = "server.toml"
iface = "cable-1"
duration = "1500ms"

[[run]]
name = "clients"
agent = "east"
tcp = "clients.toml"
iface = "cable-1"
delay = "200ms"
require = ["completed == 6"]

[require]
tcp = ["server_completed == 6", "failed == 0"]
"#
    );
    let plan = FleetPlan::from_toml(&text, &d.join("plans"), &[]).unwrap();
    let report = run(&plan);
    assert!(report.passed, "{}", report.text());
    let tcp = report.total(CheckKind::Tcp).unwrap();
    assert_eq!(tcp["completed"], 6.0);
    assert_eq!(tcp["server_completed"], 6.0);
    // Started together, the clients 200 ms after the server. macOS runners
    // oversleep the wait for the start by 100 ms and more (114 ms seen).
    let slack = if cfg!(target_os = "macos") {
        500.0
    } else {
        100.0
    };
    let spread = report.start_spread_ms.unwrap();
    assert!(spread < slack, "{spread} ms");
    for r in &report.runs {
        for i in &r.instances {
            assert!(
                i.start_late_ms.unwrap().abs() < slack,
                "{:?}",
                i.start_late_ms
            );
        }
    }
    for a in &report.agents {
        assert!(a.offset_ms.abs() < 50.0, "{} ms", a.offset_ms);
    }
    // The profiles and the pcap are on the agents, the pcap where the
    // profile's relative path finds it.
    let base = Path::new("fleet/two-agents");
    assert!(east_dir
        .join(base)
        .join("clients/plans/clients.toml")
        .is_file());
    assert!(east_dir
        .join(base)
        .join("clients/captures/http.pcap")
        .is_file());
    assert!(srv_dir
        .join(base)
        .join("server/captures/http.pcap")
        .is_file());
    let text =
        std::fs::read_to_string(east_dir.join(base).join("clients/plans/clients.toml")).unwrap();
    assert!(text.contains("10.9.0.100/24"), "{text}");
    assert_eq!(
        report.deployed.iter().map(|d| d.files_sent).sum::<usize>(),
        2
    );
    // The runs are gone from the agents.
    let mut c = Client::connect(east).unwrap();
    assert!(c.tcp_runs().unwrap().is_empty());

    // Again: the agents have the pcap already.
    let again = run(&plan);
    assert!(again.passed, "{}", again.text());
    assert_eq!(
        again.deployed.iter().map(|d| d.files_sent).sum::<usize>(),
        0
    );
    assert_eq!(
        again.deployed.iter().map(|d| d.files_kept).sum::<usize>(),
        2
    );
    let text = again.text();
    assert!(
        text.contains("Run 'clients' (tcp clients.toml): PASS"),
        "{text}"
    );
    assert!(text.contains("Fleet: PASS"));
    let json = serde_json::to_string(&again).unwrap();
    let back: ferotrx_ctl::fleet::FleetReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.runs.len(), 2);
}

#[test]
fn counters_add_up_over_agents() {
    let cables = Cables::default();
    let (x, _) = agent("x", &cables);
    let (y, _) = agent("y", &cables);
    let d = plans("sum");
    let text = format!(
        r#"
start_delay = "300ms"
interval = "200ms"
[[agent]]
name = "x"
address = "{x}"
[[agent]]
name = "y"
address = "{y}"
[[run]]
name = "pairs"
agents = ["x", "y"]
tcp = "pair.toml"
connections = 5
require = ["connections == 10", "completed_pct == 100"]
[require]
tcp = ["server_completed == 10"]
udp = ["answered > 0"]
"#
    );
    let plan = FleetPlan::from_toml(&text, &d.join("plans"), &[]).unwrap();
    let report = run(&plan);
    let pairs = &report.runs[0];
    assert!(pairs.passed, "{}", report.text());
    assert_eq!(pairs.instances.len(), 2);
    for i in &pairs.instances {
        assert_eq!(
            i.metrics["completed"], 5.0,
            "connections = 5 replaces the profile's 4"
        );
    }
    assert_eq!(pairs.metrics["completed"], 10.0);
    // No UDP run: its condition fails, and with it the fleet.
    assert!(!report.passed);
    let udp = report
        .conditions
        .iter()
        .find(|c| c.condition.starts_with("udp"))
        .unwrap();
    assert!(!udp.pass && udp.actual.is_none());
}

#[test]
fn a_failed_start_starts_nothing() {
    let cables = Cables::default();
    let (x, _) = agent("bad-x", &cables);
    let d = plans("bad");
    let text = format!(
        r#"
start_delay = "2s"
[[agent]]
name = "x"
address = "{x}"
[[run]]
name = "good"
agent = "x"
tcp = "pair.toml"
[[run]]
name = "bad"
agent = "x"
tcp = "server.toml"
iface = "nowhere"
[vars]
server = "10.1.1.1"
"#
    );
    let plan = FleetPlan::from_toml(&text, &d.join("plans"), &[]).unwrap();
    let e = run_fleet(&plan, &FleetOptions::default(), &mut |_| {}).unwrap_err();
    assert!(e.to_string().contains("starting 'bad' on 'x'"), "{e}");
    assert!(e.to_string().contains("nowhere"), "{e}");
    let mut c = Client::connect(x).unwrap();
    assert!(
        c.tcp_runs().unwrap().is_empty(),
        "the good run was taken back"
    );
}

#[test]
fn an_agent_that_is_not_there() {
    let d = plans("gone");
    let text = "[[agent]]\nname = \"gone\"\naddress = \"127.0.0.1:1\"\n\
                [[run]]\nagent = \"gone\"\ntcp = \"pair.toml\"\n";
    let plan = FleetPlan::from_toml(text, &d.join("plans"), &[]).unwrap();
    let e = run_fleet(&plan, &FleetOptions::default(), &mut |_| {}).unwrap_err();
    assert!(
        e.to_string().contains("agent 'gone': cannot connect"),
        "{e}"
    );
}

#[test]
fn files_go_where_they_may() {
    let cables = Cables::default();
    let (x, dir) = agent("files", &cables);
    let mut c = Client::connect(x).unwrap();
    c.set_timeout(Some(Duration::from_secs(10))).unwrap();
    let info = c.info().unwrap();
    assert!(info.time.is_some());
    assert!(info.max_file.unwrap() > 0);
    // An in-process server is on this machine; one that names another
    // host or system (127.0.0.1 forwarded into a VM) is not.
    assert_eq!(info.os.as_deref(), Some(std::env::consts::OS));
    if info.host.is_some() {
        assert_eq!(info.same_machine(), Some(true));
        let mut vm = info.clone();
        vm.host = Some("debian-lab-vm".into());
        assert_eq!(vm.same_machine(), Some(false));
        vm.host = info.host.clone();
        vm.os = Some("plan9".into());
        assert_eq!(vm.same_machine(), Some(false));
    }
    let mut old = info.clone();
    old.host = None;
    assert_eq!(old.same_machine(), None);
    // In pieces, in order.
    c.file_put("sub/dir/f.bin", b"hello ", 0).unwrap();
    let f = c.file_put("sub/dir/f.bin", b"world", 6).unwrap();
    assert_eq!(f.size, 11);
    assert_eq!(
        std::fs::read(dir.join("sub/dir/f.bin")).unwrap(),
        b"hello world"
    );
    assert_eq!(
        f.sha256.as_deref(),
        Some("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
    );
    let code = |e: ClientError| match e {
        ClientError::Rpc(e) => e.code,
        other => panic!("{other}"),
    };
    assert_eq!(
        code(c.file_put("sub/dir/f.bin", b"x", 3).unwrap_err()),
        RpcError::INVALID_PARAMS
    );
    for bad in ["../out.bin", "/etc/x", ""] {
        assert_eq!(
            code(c.file_put(bad, b"x", 0).unwrap_err()),
            RpcError::INVALID_PARAMS,
            "{bad}"
        );
    }
    assert!(!c.file_stat("nothing.bin").unwrap().exists);
    assert!(c.file_stat("sub/dir/f.bin").unwrap().exists);
    // upload() sends a file once.
    let data = vec![7u8; ferotrx_ctl::UPLOAD_PIECE + 10];
    assert!(c.upload("big.bin", &data).unwrap());
    assert!(!c.upload("big.bin", &data).unwrap());
    assert_eq!(std::fs::read(dir.join("big.bin")).unwrap(), data);
    // A start time an hour and more ahead is refused.
    let far = ferotrx_core::unix_seconds(std::time::SystemTime::now()) + 7200.0;
    let e = c
        .tcp_start(&TcpStartParams {
            toml: Some("pcap = \"x.pcap\"".into()),
            start_at: Some(far),
            ..Default::default()
        })
        .unwrap_err();
    assert!(e.to_string().contains("more than an hour ahead"), "{e}");
}

#[test]
fn captures_on_every_agent_are_collected_and_merged() {
    let cables = Cables::default();
    let (east, _) = agent("cap-east", &cables);
    let (west, _) = agent("cap-west", &cables);
    let d = plans("captures");
    let text = format!(
        r#"
name = "captures"
start_delay = "300ms"
interval = "200ms"

[[agent]]
name = "east"
address = "{east}"
iface = "cap0"

[[agent]]
name = "west"
address = "{west}"

[[run]]
agent = "east"
tcp = "pair.toml"
duration = "1s"

[[capture]]
filter = "tcp"
iface = "cap0"
"#
    );
    let plan = FleetPlan::from_toml(&text, &d.join("plans"), &[]).unwrap();
    let out = d.join("collected");
    let merged = out.join("all.pcapng");
    let options = FleetOptions {
        collect: Some(out.clone()),
        merge: Some(merged.clone()),
        ..Default::default()
    };
    let report = run_fleet(&plan, &options, &mut |_| {}).unwrap();
    assert_eq!(report.captures.len(), 2, "{:?}", report.notes);
    for c in &report.captures {
        assert_eq!(c.error, None);
        assert_eq!(c.frames, 3);
        assert_eq!(
            c.file,
            format!("fleet/captures/captures/{}-cap0.pcap", c.agent)
        );
        let local = out.join(format!("{}-cap0.pcap", c.agent));
        assert_eq!(c.collected.as_deref(), Some(local.to_str().unwrap()));
        assert_eq!(ferotrx_core::Capture::from_path(&local).unwrap().len(), 3);
    }
    assert_eq!(report.merged.as_deref(), Some(merged.to_str().unwrap()));
    let all = ferotrx_core::Capture::from_path(&merged).unwrap();
    assert_eq!(all.len(), 6);
    let mut tags: Vec<u8> = all.packets.iter().map(|p| p.data[0]).collect();
    assert!(all
        .packets
        .windows(2)
        .all(|w| w[0].timestamp <= w[1].timestamp));
    tags.sort();
    assert_eq!(tags, b"eeewww".to_vec());
    assert!(report.text().contains("Captures:"));
}

#[test]
fn plans_beyond_an_agents_limits_fail_before_anything_starts() {
    let limited = Controller::new().with_limits(ferotrx_ctl::Limits {
        max_duration: Some(5.0),
        max_flows: Some(50),
        ..Default::default()
    });
    let addr = Server::bind("127.0.0.1:0", limited, None)
        .unwrap()
        .spawn()
        .unwrap();
    let d = plans("limits");
    let plan = |extra: &str| {
        let text = format!(
            "start_delay = \"300ms\"\n[[agent]]\nname = \"lab\"\naddress = \"{addr}\"\n\
             [[run]]\nname = \"pairs\"\nagents = [\"lab\"]\ntcp = \"pair.toml\"\n{extra}"
        );
        FleetPlan::from_toml(&text, &d.join("plans"), &[]).unwrap()
    };
    for (extra, words) in [
        ("duration = \"1m\"", "--max-duration"),
        ("cps = 500", "--max-flows"),
    ] {
        let e = run_fleet(&plan(extra), &FleetOptions::default(), &mut |_| {}).unwrap_err();
        let msg = e.to_string();
        assert!(
            msg.contains(words) && msg.contains("'pairs' on 'lab'"),
            "{msg}"
        );
    }
    // Nothing was deployed.
    let mut c = Client::connect(addr).unwrap();
    assert!(c.tcp_runs().unwrap().is_empty());
}

/// A TCP proxy in front of an agent that the test can cut: `cut(true)`
/// closes every connection through it and refuses new ones (as if the
/// agent's machine went away), `cut(false)` lets them through again.
struct Proxy {
    addr: SocketAddr,
    to: Arc<Mutex<SocketAddr>>,
    cut: Arc<std::sync::atomic::AtomicBool>,
    open: Arc<Mutex<Vec<std::net::TcpStream>>>,
}

impl Proxy {
    fn new(to: SocketAddr) -> Proxy {
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cut: Arc<std::sync::atomic::AtomicBool> = Arc::default();
        let open: Arc<Mutex<Vec<TcpStream>>> = Arc::default();
        let to = Arc::new(Mutex::new(to));
        let (c, o, t) = (cut.clone(), open.clone(), to.clone());
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { continue };
                if c.load(std::sync::atomic::Ordering::SeqCst) {
                    drop(conn);
                    continue;
                }
                let target = *t.lock().unwrap();
                let Ok(up) = TcpStream::connect(target) else {
                    continue;
                };
                {
                    let mut o = o.lock().unwrap();
                    o.push(conn.try_clone().unwrap());
                    o.push(up.try_clone().unwrap());
                }
                for (mut from, mut to) in [
                    (conn.try_clone().unwrap(), up.try_clone().unwrap()),
                    (up, conn),
                ] {
                    std::thread::spawn(move || {
                        let _ = std::io::copy(&mut from, &mut to);
                        let _ = to.shutdown(std::net::Shutdown::Both);
                    });
                }
            }
        });
        Proxy {
            addr,
            to,
            cut,
            open,
        }
    }

    /// New connections go to `to` from now on.
    fn retarget(&self, to: SocketAddr) {
        *self.to.lock().unwrap() = to;
    }

    fn cut(&self, yes: bool) {
        self.cut.store(yes, std::sync::atomic::Ordering::SeqCst);
        if yes {
            for s in self.open.lock().unwrap().drain(..) {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
        }
    }
}

/// A plan with an agent reached directly and one through `flaky`; each
/// runs a TCP client and server on its own cable for `duration`.
fn two_agents(name: &str, steady: SocketAddr, flaky: SocketAddr, extra: &str) -> FleetPlan {
    let d = plans(name);
    std::fs::write(
        d.join("plans/long.toml"),
        "pcap = \"../captures/http.pcap\"\ncps = 20\nconnections = 0\n\
         [client]\niface = \"a\"\nip = \"10.7.0.10/24\"\n\
         [server]\niface = \"b\"\nip = \"10.7.0.80/24\"\n",
    )
    .unwrap();
    let text = format!(
        r#"
start_delay = "300ms"
interval = "200ms"
{extra}
[[agent]]
name = "steady"
address = "{steady}"
[[agent]]
name = "flaky"
address = "{flaky}"
[[run]]
name = "long"
agents = ["steady", "flaky"]
tcp = "long.toml"
duration = "2500ms"
require_each = ["completed > 10"]
"#
    );
    FleetPlan::from_toml(&text, &d.join("plans"), &[]).unwrap()
}

#[test]
fn an_agent_lost_mid_run_is_reported_and_the_others_go_on() {
    let cables = Cables::default();
    let (steady, _) = agent("lose-steady", &cables);
    let (behind, _) = agent("lose-flaky", &cables);
    let proxy = Proxy::new(behind);
    let plan = two_agents("lose", steady, proxy.addr, "reconnect = \"600ms\"");
    let mut events = Vec::new();
    let report = std::thread::scope(|s| {
        s.spawn(|| {
            // Cut once the runs go, and keep it cut.
            std::thread::sleep(Duration::from_millis(1200));
            proxy.cut(true);
        });
        run_fleet(&plan, &FleetOptions::default(), &mut |e| match e {
            FleetEvent::AgentDown { agent, .. } => events.push(format!("down {agent}")),
            FleetEvent::AgentBack { agent, .. } => events.push(format!("back {agent}")),
            FleetEvent::AgentLost(f) => events.push(format!("lost {}", f.agent)),
            _ => {}
        })
        .unwrap()
    });
    let text = report.text();
    assert!(!report.passed, "{text}");
    assert_eq!(events, ["down flaky", "lost flaky"], "{text}");
    assert_eq!(report.failures.len(), 1, "{text}");
    let f = &report.failures[0];
    assert_eq!(f.agent, "flaky");
    assert_eq!(f.runs, ["long"]);
    assert!(f.at_s > 0.5 && f.at_s < 2.0, "{f:?}");
    assert!(f.lost_at_s - f.at_s >= 0.5, "{f:?}");
    assert!(f.last_seen_s.is_some_and(|t| t <= f.at_s), "{f:?}");
    let flaky = report.agents.iter().find(|a| a.name == "flaky").unwrap();
    assert_eq!(flaky.status, "lost");
    assert!(flaky.failure.is_some());
    // The steady agent's part ran to its end and passed on its own.
    let long = &report.runs[0];
    let part = |name: &str| long.instances.iter().find(|i| i.agent == name).unwrap();
    assert_eq!(part("steady").state, Some(RunState::Finished), "{text}");
    assert!(part("steady").error.is_none(), "{text}");
    assert!(part("steady").conditions.iter().all(|c| c.pass), "{text}");
    assert!(
        part("flaky").error.as_deref().unwrap().contains("lost"),
        "{text}"
    );
    // The run took its whole time: the controller did not give up early.
    assert!(report.elapsed_s >= 2.5, "{}", report.elapsed_s);
    assert!(
        text.contains("LOST: agent 'flaky' out of reach from"),
        "{text}"
    );
    // Later samples say so.
    let last = report.samples.last().unwrap();
    let a = last.agents.iter().find(|a| a.agent == "flaky").unwrap();
    assert_eq!(a.status, "lost");
}

#[test]
fn an_agent_whose_connection_broke_is_reached_again() {
    let cables = Cables::default();
    let (steady, _) = agent("back-steady", &cables);
    let (behind, _) = agent("back-flaky", &cables);
    let proxy = Proxy::new(behind);
    let plan = two_agents("back", steady, proxy.addr, "reconnect = \"10s\"");
    let mut events = Vec::new();
    let report = std::thread::scope(|s| {
        s.spawn(|| {
            std::thread::sleep(Duration::from_millis(1000));
            proxy.cut(true);
            std::thread::sleep(Duration::from_millis(500));
            proxy.cut(false);
        });
        run_fleet(&plan, &FleetOptions::default(), &mut |e| match e {
            FleetEvent::AgentDown { agent, .. } => events.push(format!("down {agent}")),
            FleetEvent::AgentBack { agent, .. } => events.push(format!("back {agent}")),
            FleetEvent::AgentLost(f) => events.push(format!("lost {}", f.agent)),
            _ => {}
        })
        .unwrap()
    });
    let text = report.text();
    assert_eq!(events, ["down flaky", "back flaky"], "{text}");
    assert!(report.passed, "{text}");
    let flaky = report.agents.iter().find(|a| a.name == "flaky").unwrap();
    assert_eq!(flaky.status, "reconnected");
    assert_eq!(flaky.reconnects, 1);
    assert!(report.failures.is_empty());
    assert!(
        report.notes.iter().any(|n| n.contains("out of reach")),
        "{text}"
    );
    // Its run went on meanwhile: it finished with every connection counted.
    let part = report.runs[0]
        .instances
        .iter()
        .find(|i| i.agent == "flaky")
        .unwrap();
    assert_eq!(part.state, Some(RunState::Finished), "{text}");
}

#[test]
fn an_agent_restarted_quickly_is_lost_not_reused() {
    // The agent behind the proxy is replaced by a new server process while
    // the connection is cut, and reached again within half a second: too
    // soon for its uptime to give it away. Its instance does: the old run
    // ids must not be sent to the new process.
    let cables = Cables::default();
    let (steady, _) = agent("restart-steady", &cables);
    let (behind, _) = agent("restart-flaky", &cables);
    let (fresh, _) = agent("restart-fresh", &cables);
    let proxy = Proxy::new(behind);
    let plan = two_agents("restart", steady, proxy.addr, "reconnect = \"10s\"");
    let mut events = Vec::new();
    let report = std::thread::scope(|s| {
        s.spawn(|| {
            std::thread::sleep(Duration::from_millis(1000));
            proxy.cut(true);
            proxy.retarget(fresh);
            std::thread::sleep(Duration::from_millis(300));
            proxy.cut(false);
        });
        run_fleet(&plan, &FleetOptions::default(), &mut |e| match e {
            FleetEvent::AgentDown { agent, .. } => events.push(format!("down {agent}")),
            FleetEvent::AgentBack { agent, .. } => events.push(format!("back {agent}")),
            FleetEvent::AgentLost(f) => events.push(format!("lost {}", f.agent)),
            _ => {}
        })
        .unwrap()
    });
    let text = report.text();
    assert_eq!(events, ["down flaky", "lost flaky"], "{text}");
    assert!(!report.passed, "{text}");
    let f = &report.failures[0];
    assert!(f.error.contains("restarted"), "{f:?}");
    // The new process was never asked about the old run.
    let mut c = Client::connect(fresh).unwrap();
    assert!(c.tcp_runs().unwrap().is_empty());
}

#[test]
fn telemetry_and_capabilities_of_every_agent() {
    let cables = Cables::default();
    let (x, _) = agent("tele-x", &cables);
    let d = plans("tele");
    let text = format!(
        "start_delay = \"300ms\"\ninterval = \"200ms\"\n[[agent]]\nname = \"x\"\naddress = \"{x}\"\n\
         [[run]]\nagent = \"x\"\ntcp = \"pair.toml\"\nduration = \"1s\"\n"
    );
    let plan = FleetPlan::from_toml(&text, &d.join("plans"), &[]).unwrap();
    let report = run(&plan);
    assert!(report.passed, "{}", report.text());
    let a = &report.agents[0];
    let caps = a.capabilities.as_ref().unwrap();
    assert!(caps.cpus >= 1);
    for k in ["tcp", "hosts", "scenario", "bench", "y1564"] {
        assert!(caps.kinds.iter().any(|x| x == k), "{k}: {caps:?}");
    }
    assert!(caps.apps.iter().any(|x| x == "http"), "{caps:?}");
    let t = a.telemetry.as_ref().unwrap();
    assert!(t.samples >= 3, "{t:?}");
    assert!(t.offset_min_ms.unwrap() <= t.offset_max_ms.unwrap());
    if cfg!(target_os = "linux") {
        let cpu = t.cpu_max_pct.unwrap();
        assert!((0.0..=100.0).contains(&cpu), "{cpu}");
        assert!(t.memory_min_mb.unwrap() > 0);
    }
    let s = report
        .samples
        .iter()
        .find(|s| !s.agents.is_empty())
        .unwrap();
    assert_eq!(s.agents[0].status, "up");
    assert!(s.line().contains("cpu: x"), "{}", s.line());

    // telemetry = false: no health readings.
    let plan =
        FleetPlan::from_toml(&format!("telemetry = false\n{text}"), &d.join("plans"), &[]).unwrap();
    let report = run(&plan);
    assert_eq!(report.agents[0].telemetry.as_ref().unwrap().samples, 0);
}

#[test]
fn hosts_and_scenarios_in_a_plan() {
    let cables = Cables::default();
    let (x, _) = agent("kinds-x", &cables);
    let (y, _) = agent("kinds-y", &cables);
    let d = plans("kinds");
    std::fs::write(
        d.join("plans/hosts.toml"),
        "format = 1\n[[host]]\niface = \"a\"\ncount = 3\nmac = \"02:00:00:00:07:01\"\nipv4 = \"10.7.0.20/24\"\n",
    )
    .unwrap();
    std::fs::write(
        d.join("plans/check.toml"),
        "format = 1\nname = \"pair\"\n[[check]]\nname = \"pair\"\ntcp = \"pair.toml\"\n\
         require = [\"completed == 4\"]\n",
    )
    .unwrap();
    let text = format!(
        r#"
start_delay = "300ms"
interval = "200ms"
[[agent]]
name = "x"
address = "{x}"
[[agent]]
name = "y"
address = "{y}"
[[run]]
name = "hosts"
agent = "x"
hosts = "hosts.toml"
until_ready = true
duration = "5s"
require = ["ready == 3"]
[[run]]
name = "checks"
agent = "y"
scenario = "check.toml"
require = ["checks_passed == 1"]
[require]
scenario = ["passed == 1"]
hosts = ["ready_pct == 100"]
"#
    );
    let plan = FleetPlan::from_toml(&text, &d.join("plans"), &[]).unwrap();
    let report = run(&plan);
    let text = report.text();
    assert!(report.passed, "{text}");
    assert_eq!(report.totals["hosts"]["ready"], 3.0, "{text}");
    assert_eq!(report.totals["scenario"]["checks"], 1.0, "{text}");
    // Until ready: the hosts ended long before their 5 s.
    assert!(report.elapsed_s < 4.0, "{}", report.elapsed_s);
    // Started together.
    for r in &report.runs {
        assert!(r.instances[0].start_late_ms.is_some(), "{text}");
    }
    assert!(text.contains("hosts: hosts 3, ready 3"), "{text}");
}

#[test]
fn a_plan_that_does_not_fit_starts_nothing() {
    let cables = Cables::default();
    let (x, _) = agent("fit-x", &cables);
    let d = plans("fit");
    let text = format!(
        "start_delay = \"300ms\"\n[[agent]]\nname = \"x\"\naddress = \"{x}\"\n\
         [[run]]\nname = \"fast\"\nagent = \"x\"\ntcp = \"pair.toml\"\nbackend = \"no-such-backend\"\n"
    );
    let plan = FleetPlan::from_toml(&text, &d.join("plans"), &[]).unwrap();
    let e = run_fleet(&plan, &FleetOptions::default(), &mut |_| {}).unwrap_err();
    let msg = e.to_string();
    assert!(
        msg.contains("does not fit") && msg.contains("'fast' on 'x': backend no-such-backend"),
        "{msg}"
    );
    let mut c = Client::connect(x).unwrap();
    assert!(c.tcp_runs().unwrap().is_empty());
}
