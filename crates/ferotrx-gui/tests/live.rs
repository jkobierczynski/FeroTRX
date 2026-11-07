//! The GUI's state and connection code against a real control server in
//! this process: connect, send a port's streams, read the counters back.

use std::time::{Duration, Instant};

use eframe::egui;
use ferotrx_ctl::{Controller, Server};
use ferotrx_gui::app::{Status, Workspace};
use ferotrx_gui::conn::ConnSettings;
use ferotrx_gui::model::{PortKind, StreamDraft};
use ferotrx_gui::{FeroApp, Options};

fn server(token: Option<&str>) -> String {
    Server::bind("127.0.0.1:0", Controller::new(), token.map(String::from))
        .unwrap()
        .spawn()
        .unwrap()
        .to_string()
}

fn app(addr: &str, token: &str) -> FeroApp {
    let s = ConnSettings {
        addr: addr.into(),
        token: token.into(),
        ..Default::default()
    };
    FeroApp::with_workspace(
        egui::Context::default(),
        Workspace::default(),
        Options {
            connect: vec![s],
            ..Default::default()
        },
    )
}

/// Polls until `done` holds, or fails after 20 s.
fn until(app: &mut FeroApp, what: &str, mut done: impl FnMut(&FeroApp) -> bool) {
    let t = Instant::now();
    while !done(app) {
        assert!(
            t.elapsed() < Duration::from_secs(20),
            "timed out waiting for {what}; log: {:?}",
            app.log
        );
        std::thread::sleep(Duration::from_millis(20));
        app.poll();
    }
}

#[test]
fn sends_a_ports_streams_and_reads_the_counters() {
    let addr = server(None);
    let mut app = app(&addr, "");
    let i = app.servers.len() - 1;
    until(&mut app, "connect", |a| {
        a.servers[i].status == Status::Connected
    });

    let port = PortKind::Null;
    let work = app.port_work(i, &port);
    work.profile.streams = vec![
        StreamDraft {
            name: "udp".into(),
            rate: "2000pps".into(),
            limit: Some(200),
            ..Default::default()
        },
        StreamDraft {
            name: "off".into(),
            enabled: false,
            ..Default::default()
        },
    ];
    app.start_port(i, &port);
    until(&mut app, "the run to finish", |a| {
        a.port_run(i, &port)
            .is_some_and(|r| !r.state.is_running() && r.total.packets == 200)
    });
    let run = app.port_run(i, &port).unwrap().clone();
    // Only the enabled stream was sent.
    assert_eq!(run.streams.len(), 1);
    assert_eq!(run.streams[0].name, "udp");
    assert!(app.log.iter().all(|l| !l.error), "{:?}", app.log);

    // Remove it; the next snapshot no longer has it.
    app.remove_run(i, "run", run.id);
    until(&mut app, "the run to go", |a| {
        a.servers[i].snap.runs.is_empty()
    });
}

#[test]
fn bad_streams_and_wrong_tokens_show_in_the_log() {
    let addr = server(Some("secret"));
    let mut wrong = app(&addr, "nope");
    let i = wrong.servers.len() - 1;
    until(&mut wrong, "refusal", |a| {
        matches!(a.servers[i].status, Status::Failed(_))
    });

    let mut app = app(&addr, "secret");
    until(&mut app, "connect", |a| {
        a.servers[i].status == Status::Connected
    });
    let port = PortKind::Null;
    app.port_work(i, &port).profile.streams = vec![StreamDraft {
        packets: vec!["eth/ipv4/tcp(flags=SZ)".into()],
        ..Default::default()
    }];
    app.start_port(i, &port);
    until(&mut app, "an error", |a| a.log.iter().any(|l| l.error));
    let err = app.log.iter().find(|l| l.error).unwrap();
    assert!(err.text.contains("profile refused"), "{}", err.text);
    assert!(app.port_run(i, &port).is_none());
}

#[test]
fn a_group_starts_on_two_servers_and_adds_up() {
    use ferotrx_gui::views::{Member, MemberKind};

    let a = server(None);
    let b = server(None);
    let mut app = FeroApp::with_workspace(
        egui::Context::default(),
        Workspace::default(),
        Options {
            connect: [&a, &b]
                .iter()
                .map(|addr| ConnSettings {
                    addr: addr.to_string(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        },
    );
    until(&mut app, "both connect", |x| {
        x.servers
            .iter()
            .filter(|s| s.status == Status::Connected)
            .count()
            == 2
    });
    let port = PortKind::Null;
    for (n, limit) in [(0, 300), (1, 500)] {
        let i = app
            .servers
            .iter()
            .position(|s| s.settings.addr == [&a, &b][n].as_str())
            .unwrap();
        app.port_work(i, &port).profile.streams = vec![StreamDraft {
            name: format!("s{n}"),
            rate: "5000pps".into(),
            limit: Some(limit),
            ..Default::default()
        }];
        let server = app.servers[i].settings.address();
        app.groups.members.push(Member {
            server,
            kind: MemberKind::Streams,
            port: Some(port.clone()),
            ..Default::default()
        });
    }
    app.start_group();
    until(&mut app, "both runs to finish", |x| {
        x.groups.members.iter().all(|m| {
            x.member_stats(m)
                .is_some_and(|s| !s.running && s.tx_packets > 0)
        })
    });
    let total: u64 = app
        .groups
        .members
        .iter()
        .map(|m| app.member_stats(m).unwrap().tx_packets)
        .sum();
    assert_eq!(total, 800);
    assert!(app.log.iter().all(|l| !l.error), "{:?}", app.log);
}

#[test]
fn a_benchmark_runs_on_the_server_and_its_report_is_saved() {
    use ferotrx_core::{memory_ports, MemoryPort, PacketSink, PortReceiver};
    use std::sync::{Arc, Mutex};

    // A perfect device: what is sent on wire0 arrives on wire1.
    let other_end: Arc<Mutex<Option<MemoryPort>>> = Default::default();
    let tx_end = other_end.clone();
    let controller = Controller::new()
        .with_bench_sink_opener(move |_name, _send, _linktype, _workers| {
            let (a, b) = memory_ports();
            *tx_end.lock().unwrap() = Some(b);
            Ok((
                vec![Box::new(a) as Box<dyn PacketSink + Send>],
                "memory".into(),
            ))
        })
        .with_receiver_opener(move |_name| {
            Ok(Box::new(PortReceiver(
                other_end.lock().unwrap().take().unwrap(),
            )))
        });
    let addr = Server::bind("127.0.0.1:0", controller, None)
        .unwrap()
        .spawn()
        .unwrap()
        .to_string();
    let mut app = app(&addr, "");
    let i = app.servers.len() - 1;
    until(&mut app, "connect", |a| {
        a.servers[i].status == Status::Connected
    });
    app.sel_server = i;
    app.bench.new_bench();
    app.bench.iface = "wire0".into();
    app.bench.rx = "wire1".into();
    app.bench.sizes = "252".into();
    app.bench.line_rate = "10mbps".into();
    app.bench.trial_duration = "100ms".into();
    app.bench.tests = vec!["throughput".into()];
    app.start_bench();
    until(&mut app, "the benchmark to finish", |a| {
        a.servers[i]
            .snap
            .bench
            .iter()
            .any(|r| !r.state.is_running() && r.report.is_some())
    });
    assert!(app.log.iter().all(|l| !l.error), "{:?}", app.log);
    let run = app.servers[i].snap.bench[0].clone();
    assert_eq!(app.bench.run, Some(run.id));
    let t = run.report.as_ref().unwrap().sizes[0]
        .throughput
        .as_ref()
        .unwrap();
    assert!(t.load_pct > 90.0, "{t:?}");

    // Saved as ferotrx bench --report writes it, with the text next to it.
    let dir = std::env::temp_dir().join(format!("ferotrx-gui-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let json = dir.join("bench.json");
    app.bench_file(ferotrx_gui::files::Target::BenchReport, &json);
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
    assert_eq!(v["format"], "ferotrx-bench-1");
    assert_eq!(v["report"]["sizes"][0]["size"], "252");
    assert!(std::fs::read_to_string(dir.join("bench.txt"))
        .unwrap()
        .contains("Throughput"));
    std::fs::remove_dir_all(&dir).ok();
}

/// A server on another computer has none of this computer's files: the
/// GUI sends a profile's capture along, into the server's data directory,
/// and the run finds it there (the http.pcap of lab-tcp, which a server
/// started elsewhere could not read before).
#[test]
fn a_profiles_files_go_to_a_server_elsewhere() {
    use ferotrx_ctl::FilePolicy;
    let data = std::env::temp_dir().join(format!("ftrx-gui-ship-{}", std::process::id()));
    std::fs::create_dir_all(&data).unwrap();
    let ctl = Controller::new().with_file_policy(FilePolicy::dirs([&data]).unwrap());
    let addr = Server::bind("127.0.0.1:0", ctl, None)
        .unwrap()
        .spawn()
        .unwrap()
        .to_string();
    let mut app = app(&addr, "");
    let i = app.servers.len() - 1;
    until(&mut app, "connect", |a| {
        a.servers[i].status == Status::Connected
    });
    let examples = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    let text = std::fs::read_to_string(examples.join("lab-tcp.toml")).unwrap();
    let params = serde_json::json!({
        "toml": text,
        "iface": "nonexistent0",
        ferotrx_gui::app::LOCAL_DIR: examples.canonicalize().unwrap().display().to_string(),
    });
    app.call(
        i,
        "tcp.start",
        params,
        ferotrx_gui::app::Pending::Done("tcp.start sent".into()),
    );
    until(&mut app, "the answer", |a| {
        a.log.iter().any(|l| l.text.contains("tcp.start"))
    });
    let shipped = data
        .join(ferotrx_gui::app::upload_root())
        .join("examples/http.pcap");
    assert!(
        shipped.is_file(),
        "{} missing; log: {:?}",
        shipped.display(),
        app.log
    );
    assert_eq!(
        std::fs::read(&shipped).unwrap(),
        std::fs::read(examples.join("http.pcap")).unwrap()
    );
    // Whatever the run did with the made-up interface, it did not miss the capture.
    assert!(
        !app.log.iter().any(|l| l.text.contains("http.pcap")),
        "{:?}",
        app.log
    );
    std::fs::remove_dir_all(&data).ok();
}

/// TLS ticked for a server without TLS, and the other way round: the error
/// says which, instead of rustls' "corrupt message of type InvalidContentType".
#[test]
fn tls_and_plain_mixed_up_say_so() {
    use ferotrx_ctl::{LabPki, Role, ServerConfig, ServerTls};
    let dir = std::env::temp_dir().join(format!("ftrx-gui-tls-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pki = LabPki::new(&dir);
    pki.issue_server(&["127.0.0.1".into()]).unwrap();
    pki.issue_client("me", Role::Operator).unwrap();

    // TLS to a plain server.
    let plain = server(None);
    let mut app1 = app(&plain, "");
    let i = app1.servers.len() - 1;
    app1.servers[i].settings.tls = true;
    app1.servers[i].settings.ca = pki.path("ca.pem").display().to_string();
    app1.connect(i);
    until(&mut app1, "failure", |a| {
        matches!(a.servers[i].status, Status::Failed(_))
    });
    let Status::Failed(e) = &app1.servers[i].status else {
        unreachable!()
    };
    assert!(e.contains("without TLS"), "{e}");

    // Plain to a TLS server.
    let tls = ServerTls::from_files(&pki.path("server.pem"), &pki.path("server-key.pem")).unwrap();
    let addr = Server::with_config(
        "127.0.0.1:0",
        Controller::new(),
        ServerConfig {
            tls: Some(tls),
            ..Default::default()
        },
    )
    .unwrap()
    .spawn()
    .unwrap()
    .to_string();
    let mut app2 = app(&addr, "");
    let i = app2.servers.len() - 1;
    until(&mut app2, "failure", |a| {
        matches!(a.servers[i].status, Status::Failed(_))
    });
    let Status::Failed(e) = &app2.servers[i].status else {
        unreachable!()
    };
    assert!(e.contains("tick TLS"), "{e}");
    std::fs::remove_dir_all(&dir).ok();
}
