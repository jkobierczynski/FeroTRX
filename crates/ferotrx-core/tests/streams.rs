use std::time::{Duration, Instant};

use ferotrx_core::*;

fn one_packet(tag: u8) -> Capture {
    Capture::new(1, vec![Packet::new(Duration::ZERO, vec![tag; 60])])
}

#[test]
fn paced_streams_interleave_by_deadline() {
    // a: 1000 pps, b: 500 pps, for 20 ms -> about 2:1.
    let (a, b) = (one_packet(1), one_packet(2));
    let mut streams = [
        Stream::new("a", CaptureSource::new(&a).loops(21)).with_rate(Rate::Pps(1000.0)),
        Stream::new("b", CaptureSource::new(&b).loops(11)).with_rate(Rate::Pps(500.0)),
    ];
    let mut sink = VecSink::default();
    let stats = run(&mut streams, &mut sink, &RunConfig::default()).unwrap();
    assert_eq!(stats.streams[0].packets, 21);
    assert_eq!(stats.streams[1].packets, 11);
    assert_eq!(stats.total.packets, 32);
    assert_eq!(stats.total.loops_completed, 32);
    // Deadlines merge: a at 0,1,2.. ms, b at 0,2,4.. ms.
    let order: Vec<u8> = sink.packets.iter().take(6).map(|p| p[0]).collect();
    assert_eq!(order, [1, 2, 1, 1, 2, 1]);
}

#[test]
fn topspeed_does_not_starve_paced_streams() {
    let (a, b) = (one_packet(1), one_packet(2));
    let mut streams = [
        Stream::new("fast", CaptureSource::new(&a).loops(0)).with_rate(Rate::TopSpeed),
        Stream::new("paced", CaptureSource::new(&b).loops(0)).with_rate(Rate::Pps(1000.0)),
    ];
    let cfg = RunConfig {
        duration: Some(Duration::from_millis(50)),
        ..Default::default()
    };
    let t = Instant::now();
    let stats = run(&mut streams, &mut NullSink, &cfg).unwrap();
    assert!(t.elapsed() < Duration::from_millis(500));
    assert!(stats.streams[0].packets > 1000, "{:?}", stats.streams[0]);
    assert!(
        (30..=52).contains(&stats.streams[1].packets),
        "{:?}",
        stats.streams[1]
    );
}

#[test]
fn delay_and_limits() {
    let (a, b) = (one_packet(1), one_packet(2));
    let mut streams = [
        Stream::new("late", CaptureSource::new(&a).loops(0))
            .with_rate(Rate::TopSpeed)
            .with_delay(Duration::from_millis(30))
            .with_limit(Some(3)),
        Stream::new("early", CaptureSource::new(&b).loops(0))
            .with_rate(Rate::TopSpeed)
            .with_limit(Some(5)),
    ];
    let mut sink = VecSink::default();
    let t = Instant::now();
    let stats = run(&mut streams, &mut sink, &RunConfig::default()).unwrap();
    assert!(t.elapsed() >= Duration::from_millis(29));
    assert_eq!((stats.streams[0].packets, stats.streams[1].packets), (3, 5));
    let order: Vec<u8> = sink.packets.iter().map(|p| p[0]).collect();
    assert_eq!(order, [2, 2, 2, 2, 2, 1, 1, 1]);

    // A global limit caps the total.
    let mut streams = [
        Stream::new("a", CaptureSource::new(&a).loops(0)).with_rate(Rate::TopSpeed),
        Stream::new("b", CaptureSource::new(&b).loops(0)).with_rate(Rate::TopSpeed),
    ];
    let cfg = RunConfig {
        limit: Some(10),
        ..Default::default()
    };
    assert_eq!(
        run(&mut streams, &mut NullSink, &cfg)
            .unwrap()
            .total
            .packets,
        10
    );
}

#[test]
fn transforms_run_before_pacing() {
    // Pushing a VLAN tag makes 60 byte frames 64 bytes; at 0.512 Mbps
    // that is 1 ms per packet, so 11 packets take about 10 ms.
    let a = one_packet(1);
    let mut streams = [Stream::new("a", CaptureSource::new(&a).loops(11))
        .with_rate(Rate::Mbps(0.512))
        .with_transform("vlan_push=5".parse::<Rewrite>().unwrap())];
    let mut sink = VecSink::default();
    let stats = run(&mut streams, &mut sink, &RunConfig::default()).unwrap();
    assert_eq!(stats.total.bytes, 11 * 64);
    assert!(stats.total.elapsed >= Duration::from_millis(9));
    assert!(sink.packets.iter().all(|p| p[12..14] == [0x81, 0x00]));
}

#[test]
fn mixed_link_types_are_rejected() {
    let a = one_packet(1);
    let raw = Capture::new(101, vec![Packet::new(Duration::ZERO, vec![0x45; 20])]);
    let mut streams = [
        Stream::new("eth", CaptureSource::new(&a)),
        Stream::new("raw", CaptureSource::new(&raw)),
    ];
    assert!(matches!(
        run(&mut streams, &mut NullSink, &RunConfig::default()),
        Err(Error::MixedLinkTypes(1, 101))
    ));
}

#[cfg(feature = "profile")]
#[test]
fn profile_loads_and_runs() {
    let dir = std::env::temp_dir().join(format!("ferotrx-profile-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // A tiny pcap: header plus two 60 byte frames.
    let mut pcap = Vec::new();
    pcap.extend(0xa1b2c3d4u32.to_le_bytes());
    pcap.extend(2u16.to_le_bytes());
    pcap.extend(4u16.to_le_bytes());
    pcap.extend([0u8; 8]);
    pcap.extend(65535u32.to_le_bytes());
    pcap.extend(1u32.to_le_bytes());
    for i in 0..2u32 {
        pcap.extend(i.to_le_bytes());
        pcap.extend(0u32.to_le_bytes());
        pcap.extend(60u32.to_le_bytes());
        pcap.extend(60u32.to_le_bytes());
        pcap.extend([i as u8; 60]);
    }
    std::fs::write(dir.join("two.pcap"), &pcap).unwrap();
    std::fs::write(
        dir.join("lab.toml"),
        r#"
        [[stream]]
        pcap = "two.pcap"
        rate = "topspeed"
        loops = 3
        rewrite = ["vlan_push=10"]

        [[stream]]
        name = "again"
        pcap = "two.pcap"
        rate = "topspeed"
        "#,
    )
    .unwrap();

    let profile = Profile::from_path(dir.join("lab.toml")).unwrap();
    let mut streams = profile.load().unwrap();
    assert_eq!(streams[0].name, "two");
    let stats = run(&mut streams, &mut NullSink, &RunConfig::default()).unwrap();
    assert_eq!(stats.streams[0].packets, 6);
    assert_eq!(stats.streams[0].bytes, 6 * 64);
    assert_eq!(stats.streams[1].packets, 2);

    std::fs::write(
        dir.join("bad.toml"),
        "[[stream]]\npcap = \"missing.pcap\"\n",
    )
    .unwrap();
    let err = Profile::from_path(dir.join("bad.toml"))
        .unwrap()
        .load()
        .unwrap_err();
    assert!(err.to_string().contains("missing"), "{err}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Every profile in `examples/` must load (its pcaps exist) and run.
#[cfg(feature = "profile")]
#[test]
fn example_profiles_run() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    let mut found = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "toml") {
            found += 1;
            let mut streams = Profile::from_path(&path)
                .and_then(|p| p.load())
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let cfg = RunConfig {
                limit: Some(20),
                ..Default::default()
            };
            let stats = run(&mut streams, &mut NullSink, &cfg).unwrap();
            assert_eq!(stats.total.packets, 20, "{}", path.display());
        }
    }
    assert!(found > 0);
}
