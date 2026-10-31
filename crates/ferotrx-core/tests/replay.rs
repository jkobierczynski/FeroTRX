use std::borrow::Cow;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ferotrx_core::*;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::DataLink;

fn frame(n: u8, len: usize) -> Vec<u8> {
    let mut v = vec![n; len];
    v[0] = n;
    v
}

fn pcap_bytes(packets: &[(Duration, Vec<u8>)]) -> Vec<u8> {
    let header = PcapHeader {
        datalink: DataLink::ETHERNET,
        ..Default::default()
    };
    let mut w = PcapWriter::with_header(Vec::new(), header).unwrap();
    for (ts, data) in packets {
        w.write_packet(&PcapPacket::new(*ts, data.len() as u32, data))
            .unwrap();
    }
    w.into_writer()
}

fn pcapng_bytes(packets: &[(Duration, Vec<u8>)]) -> Vec<u8> {
    let mut w = PcapNgWriter::new(Vec::new()).unwrap();
    w.write_pcapng_block(InterfaceDescriptionBlock {
        linktype: DataLink::ETHERNET,
        snaplen: 0,
        options: vec![],
    })
    .unwrap();
    for (ts, data) in packets {
        w.write_pcapng_block(EnhancedPacketBlock {
            interface_id: 0,
            timestamp: *ts,
            original_len: data.len() as u32,
            data: Cow::Borrowed(data),
            options: vec![],
        })
        .unwrap();
    }
    w.into_inner()
}

fn sample() -> Vec<(Duration, Vec<u8>)> {
    vec![
        (Duration::from_secs(100), frame(1, 60)),
        (
            Duration::from_secs(100) + Duration::from_millis(20),
            frame(2, 100),
        ),
        (
            Duration::from_secs(100) + Duration::from_millis(40),
            frame(3, 1514),
        ),
    ]
}

#[test]
fn loads_pcap() {
    let cap = Capture::from_reader(&pcap_bytes(&sample())[..]).unwrap();
    assert_eq!(cap.linktype, LINKTYPE_ETHERNET);
    assert_eq!(cap.len(), 3);
    assert_eq!(cap.total_bytes(), 60 + 100 + 1514);
    assert_eq!(cap.duration(), Duration::from_millis(40));
    assert_eq!(cap.packets[1].data, frame(2, 100));
}

#[test]
fn loads_pcapng() {
    let cap = Capture::from_reader(&pcapng_bytes(&sample())[..]).unwrap();
    assert_eq!(cap.linktype, LINKTYPE_ETHERNET);
    assert_eq!(cap.len(), 3);
    assert_eq!(cap.packets[2].data.len(), 1514);
}

#[test]
fn rejects_unknown_format() {
    let err = Capture::from_reader(&b"hello world"[..]).unwrap_err();
    assert!(matches!(err, Error::UnknownFormat(_)));
}

#[test]
fn topspeed_replays_every_loop_in_order() {
    let cap = Capture::from_reader(&pcap_bytes(&sample())[..]).unwrap();
    let mut sink = VecSink::default();
    let cfg = ReplayConfig {
        rate: Rate::TopSpeed,
        loops: 4,
        ..Default::default()
    };
    let stats = replay(&cap, &mut sink, &cfg).unwrap();
    assert_eq!(stats.packets, 12);
    assert_eq!(stats.loops_completed, 4);
    assert_eq!(stats.bytes, 4 * cap.total_bytes());
    let firsts: Vec<u8> = sink.packets.iter().map(|p| p[0]).collect();
    assert_eq!(firsts, [1, 2, 3].repeat(4));
}

#[test]
fn limit_stops_mid_capture() {
    let cap = Capture::from_reader(&pcap_bytes(&sample())[..]).unwrap();
    let cfg = ReplayConfig {
        rate: Rate::TopSpeed,
        loops: 0,
        limit: Some(7),
        ..Default::default()
    };
    let stats = replay(&cap, &mut NullSink, &cfg).unwrap();
    assert_eq!(stats.packets, 7);
}

#[test]
fn original_timing_is_respected() {
    // 40 ms capture played at 2x should take about 20 ms.
    let cap = Capture::from_reader(&pcap_bytes(&sample())[..]).unwrap();
    let cfg = ReplayConfig {
        rate: Rate::Original { multiplier: 2.0 },
        ..Default::default()
    };
    let t = Instant::now();
    let stats = replay(&cap, &mut NullSink, &cfg).unwrap();
    let took = t.elapsed();
    assert_eq!(stats.packets, 3);
    assert!(took >= Duration::from_millis(19), "took {took:?}");
    assert!(took < Duration::from_millis(500), "took {took:?}");
}

#[test]
fn pps_rate_is_close_to_target() {
    let cap = Capture::new(1, vec![Packet::new(Duration::ZERO, vec![0; 64])]);
    let cfg = ReplayConfig {
        rate: Rate::Pps(1000.0),
        loops: 101,
        ..Default::default()
    };
    let t = Instant::now();
    replay(&cap, &mut NullSink, &cfg).unwrap();
    let took = t.elapsed();
    // 101 packets at 1000 pps: the last leaves at 100 ms.
    assert!(took >= Duration::from_millis(99), "took {took:?}");
    assert!(took < Duration::from_millis(600), "took {took:?}");
}

#[test]
fn stop_flag_ends_replay() {
    let cap = Capture::new(1, vec![Packet::new(Duration::ZERO, vec![0; 64])]);
    let stop = Arc::new(AtomicBool::new(true));
    let cfg = ReplayConfig {
        rate: Rate::Pps(10.0),
        loops: 0,
        stop: Some(stop),
        ..Default::default()
    };
    let stats = replay(&cap, &mut NullSink, &cfg).unwrap();
    assert!(stats.stopped);
    assert_eq!(stats.packets, 0);
}

struct FailingSink;
impl PacketSink for FailingSink {
    fn send(&mut self, _: &[u8]) -> std::result::Result<(), SinkError> {
        Err("link down".into())
    }
}

#[test]
fn send_errors_stop_or_are_counted() {
    let cap = Capture::from_reader(&pcap_bytes(&sample())[..]).unwrap();
    let cfg = ReplayConfig {
        rate: Rate::TopSpeed,
        ..Default::default()
    };
    assert!(matches!(
        replay(&cap, &mut FailingSink, &cfg),
        Err(Error::Sink { index: 0, .. })
    ));

    let cfg = ReplayConfig {
        ignore_send_errors: true,
        ..cfg
    };
    let stats = replay(&cap, &mut FailingSink, &cfg).unwrap();
    assert_eq!((stats.packets, stats.send_errors), (0, 3));
}

#[test]
fn empty_capture_is_a_no_op() {
    let cfg = ReplayConfig {
        loops: 0,
        ..Default::default()
    };
    let stats = replay(&Capture::default(), &mut NullSink, &cfg).unwrap();
    assert_eq!(stats.packets, 0);
}
