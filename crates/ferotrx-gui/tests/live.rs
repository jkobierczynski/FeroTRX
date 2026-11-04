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
