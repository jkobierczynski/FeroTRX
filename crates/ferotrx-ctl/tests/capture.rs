//! `capture.*` and `file.get` against a server whose captures read frames
//! from memory.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use ferotrx_core::live::VecFrameSource;
use ferotrx_core::{Capture, Frame};
use ferotrx_ctl::protocol::*;
use ferotrx_ctl::{Client, ClientError, Controller, FilePolicy, Server};

fn frames(n: u8) -> Vec<Frame> {
    (0..n)
        .map(|i| Frame {
            ts: Duration::new(1_700_000_000, u32::from(i) * 1_000_000),
            len: 64,
            data: vec![i; 64],
        })
        .collect()
}

fn server(dir: &PathBuf, count: u8) -> SocketAddr {
    server_with(dir, count, Controller::new())
}

fn server_with(dir: &PathBuf, count: u8, controller: Controller) -> SocketAddr {
    let controller = controller
        .with_file_policy(FilePolicy::dirs([dir]).unwrap())
        .with_capture_opener(move |name, options| {
            if name != "mem0" {
                return Err(format!("no interface {name}").into());
            }
            if options.filter.as_deref().is_some_and(|f| f.contains("bad")) {
                return Err("filter 'bad': syntax error".into());
            }
            Ok(Box::new(VecFrameSource::new(1, frames(count))))
        });
    Server::bind("127.0.0.1:0", controller, None)
        .unwrap()
        .spawn()
        .unwrap()
}

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ferotrx-ctl-cap-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn client(addr: SocketAddr) -> Client {
    let c = Client::connect(addr).unwrap();
    c.set_timeout(Some(Duration::from_secs(20))).unwrap();
    c
}

#[test]
fn a_capture_streams_frames_writes_a_file_and_the_file_can_be_fetched() {
    let d = dir("stream");
    let addr = server(&d, 30);
    let mut c = client(addr);
    // Folders on the way are made, as file.put makes them.
    let info = c
        .capture_start(&CaptureStartParams {
            iface: "mem0".into(),
            filter: Some("udp".into()),
            file: Some("caps/a.pcap".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(info.filter.as_deref(), Some("udp"));
    assert_eq!(info.linktype, 1);
    assert!(info.state.is_running());

    let mut got = Vec::new();
    let mut after = 0;
    while got.len() < 30 {
        let r = c
            .capture_read(info.id, after, Some(Duration::from_millis(500)))
            .unwrap();
        assert_eq!(r.missed, 0);
        after = r.next;
        got.extend(r.frames);
    }
    assert_eq!(got[29].n, 30);
    assert_eq!(got[29].frame().unwrap().data, vec![29; 64]);
    assert_eq!(got[1].ts_ns, 1_700_000_000_001_000_000);

    let end = c.capture_stop(info.id).unwrap();
    assert_eq!(end.state, RunState::Stopped);
    assert_eq!(end.frames, 30);
    assert_eq!(end.files, vec![PathBuf::from("caps/a.pcap")]);
    let r = c.capture_read(info.id, after, None).unwrap();
    assert!(!r.more);

    let bytes = c.download("caps/a.pcap").unwrap();
    let cap = Capture::from_reader(&bytes[..]).unwrap();
    assert_eq!(cap.packets.len(), 30);
    assert_eq!(cap.packets[7].data, vec![7; 64]);

    // Pieces, and the end.
    let piece = c.file_get("caps/a.pcap", 0, Some(24)).unwrap();
    assert!(!piece.eof);
    assert_eq!(piece.size, bytes.len() as u64);
    let last = c
        .file_get("caps/a.pcap", bytes.len() as u64 - 10, None)
        .unwrap();
    assert!(last.eof);
    assert!(c
        .file_get("caps/a.pcap", bytes.len() as u64 + 1, None)
        .is_err());

    assert_eq!(c.captures().unwrap().len(), 1);
    c.capture_remove(info.id).unwrap();
    assert!(c.captures().unwrap().is_empty());
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn files_outside_the_data_directory_are_refused() {
    let d = dir("outside");
    let addr = server(&d, 1);
    let mut c = client(addr);
    for path in ["../x.pcap", "/etc/passwd"] {
        let e = c.file_get(path, 0, None).unwrap_err();
        assert!(matches!(e, ClientError::Rpc(_)), "{path}: {e}");
    }
    let e = c
        .capture_start(&CaptureStartParams {
            iface: "mem0".into(),
            // A folder that exists on every system, outside the data directory.
            file: Some(std::env::temp_dir().join("elsewhere.pcap")),
            ..Default::default()
        })
        .unwrap_err();
    assert!(e.to_string().contains("data director"), "{e}");
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn bad_interfaces_and_filters_are_reported() {
    let d = dir("bad");
    let addr = server(&d, 1);
    let mut c = client(addr);
    let e = c
        .capture_start(&CaptureStartParams {
            iface: "nope".into(),
            ..Default::default()
        })
        .unwrap_err();
    assert!(e.to_string().contains("nope"), "{e}");
    let e = c
        .capture_start(&CaptureStartParams {
            iface: "mem0".into(),
            filter: Some("bad".into()),
            ..Default::default()
        })
        .unwrap_err();
    assert!(e.to_string().contains("filter 'bad'"), "{e}");
    let e = c
        .capture_start(&CaptureStartParams {
            iface: "mem0".into(),
            rotate: Some("10M".into()),
            ..Default::default()
        })
        .unwrap_err();
    assert!(e.to_string().contains("rotate needs a file"), "{e}");
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn a_capture_ends_at_its_count() {
    let d = dir("count");
    let addr = server(&d, 20);
    let mut c = client(addr);
    let info = c
        .capture_start(&CaptureStartParams {
            iface: "mem0".into(),
            count: Some(5),
            ..Default::default()
        })
        .unwrap();
    let mut after = 0;
    let mut n = 0;
    loop {
        let r = c
            .capture_read(info.id, after, Some(Duration::from_millis(200)))
            .unwrap();
        n += r.frames.len();
        after = r.next;
        if !r.more {
            break;
        }
    }
    assert_eq!(n, 5);
    assert_eq!(c.capture_get(info.id).unwrap().state, RunState::Finished);
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn a_capture_nobody_reads_stops() {
    // A client that streamed a capture and went away leaves nothing running.
    let d = dir("abandoned");
    let addr = server_with(
        &d,
        3,
        Controller::new().with_capture_abandoned_after(Duration::from_millis(300)),
    );
    let mut c = client(addr);
    let start = |c: &mut Client| {
        c.capture_start(&CaptureStartParams {
            iface: "mem0".into(),
            ..Default::default()
        })
        .unwrap()
        .id
    };
    // Read now and then: it keeps going.
    let read = start(&mut c);
    let mut after = 0;
    for _ in 0..8 {
        after = c.capture_read(read, after, None).unwrap().next;
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(c.capture_get(read).unwrap().state, RunState::Running);
    // Never read again: it stops, and says why.
    std::thread::sleep(Duration::from_millis(1200));
    let info = c.capture_get(read).unwrap();
    assert_eq!(info.state, RunState::Stopped);
    assert!(info.error.unwrap().contains("no client read it"));

    // One that writes a file runs on without readers.
    let file = c
        .capture_start(&CaptureStartParams {
            iface: "mem0".into(),
            file: Some("keep.pcap".into()),
            ..Default::default()
        })
        .unwrap()
        .id;
    std::thread::sleep(Duration::from_millis(800));
    assert_eq!(c.capture_get(file).unwrap().state, RunState::Running);
    c.capture_stop(file).unwrap();
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn the_control_connection_is_left_out() {
    // The opener records the filter it was given.
    let d = dir("ctl");
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Option<String>>::new()));
    let log = seen.clone();
    let controller = Controller::new()
        .with_file_policy(FilePolicy::dirs([&d]).unwrap())
        .with_capture_opener(move |_, options| {
            log.lock().unwrap().push(options.filter.clone());
            Ok(Box::new(VecFrameSource::new(1, frames(1))))
        });
    let addr = Server::bind("127.0.0.1:0", controller, None)
        .unwrap()
        .spawn()
        .unwrap();
    let mut c = client(addr);
    let port = addr.port();
    let start = |c: &mut Client, filter: Option<&str>, ctl_traffic: Option<bool>| {
        let i = c
            .capture_start(&CaptureStartParams {
                iface: "mem0".into(),
                filter: filter.map(Into::into),
                ctl_traffic,
                ..Default::default()
            })
            .unwrap();
        c.capture_remove(i.id).unwrap();
        i
    };
    let i = start(&mut c, Some("udp"), None);
    assert_eq!(i.filter.as_deref(), Some("udp"), "reported as given");
    start(&mut c, None, None);
    start(&mut c, Some("udp"), Some(true));
    assert_eq!(
        *seen.lock().unwrap(),
        [
            Some(format!("(udp) and not tcp port {port}")),
            Some(format!("not tcp port {port}")),
            Some("udp".to_string()),
        ]
    );
    std::fs::remove_dir_all(d).unwrap();
}
