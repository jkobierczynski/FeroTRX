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
    let controller = Controller::new()
        .with_file_policy(FilePolicy::dirs([dir]).unwrap())
        .with_capture_opener(move |name, options| {
            if name != "mem0" {
                return Err(format!("no interface {name}").into());
            }
            if options.filter.as_deref() == Some("bad") {
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
    let info = c
        .capture_start(&CaptureStartParams {
            iface: "mem0".into(),
            filter: Some("udp".into()),
            file: Some("caps/a.pcap".into()),
            ..Default::default()
        })
        .unwrap_err();
    // The folder must exist: captures write into the data directory, they
    // make no folders.
    assert!(matches!(info, ClientError::Rpc(_)), "{info}");
    std::fs::create_dir_all(d.join("caps")).unwrap();
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
            file: Some("/tmp/elsewhere.pcap".into()),
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
