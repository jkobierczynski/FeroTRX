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

/// Every stream profile in `examples/` must load (its pcaps exist) and run.
/// TCP profiles (no `[[stream]]`) are checked by the TCP profile tests.
#[cfg(feature = "profile")]
#[test]
fn example_profiles_run() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    let mut found = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let is_streams = || {
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("[[stream]]")
        };
        if path.extension().is_some_and(|e| e == "toml") && is_streams() {
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

/// Records what the engine asks of a batching sink.
#[derive(Default)]
struct BatchingSink {
    queued: usize,
    sent: Vec<(usize, Instant)>,
    idles: usize,
}

impl PacketSink for BatchingSink {
    fn send(&mut self, _data: &[u8]) -> std::result::Result<(), SinkError> {
        self.queued += 1;
        Ok(())
    }
    fn idle(&mut self) -> std::result::Result<(), SinkError> {
        self.idles += 1;
        if self.queued > 0 {
            self.sent.push((self.queued, Instant::now()));
            self.queued = 0;
        }
        Ok(())
    }
}

#[test]
fn batching_sinks_hand_over_before_each_wait() {
    // Paced: what is queued is handed over before the engine waits for the next
    // packet. The engine only waits when the next deadline is still ahead, so
    // a sleep that overshoots past it skips one hand-over. 10 pps leaves
    // 100 ms gaps: CI's macOS runners overshoot 20 ms gaps, these hold.
    let a = one_packet(1);
    let mut streams =
        [Stream::new("a", CaptureSource::new(&a).loops(5)).with_rate(Rate::Pps(10.0))];
    let mut sink = BatchingSink::default();
    run(&mut streams, &mut sink, &RunConfig::default()).unwrap();
    let handed: usize = sink.sent.iter().map(|&(n, _)| n).sum();
    assert_eq!(handed + sink.queued, 5);
    assert!(sink.sent.len() >= 2, "{:?}", sink.sent.len());
    assert!(sink.queued >= 1); // the last one goes out with flush

    // Top speed: no waits, so nothing is handed over early.
    let mut streams =
        [Stream::new("a", CaptureSource::new(&a).loops(100)).with_rate(Rate::TopSpeed)];
    let mut sink = BatchingSink::default();
    run(&mut streams, &mut sink, &RunConfig::default()).unwrap();
    assert_eq!((sink.idles, sink.queued), (0, 100));
}

struct FailingIdle;

impl PacketSink for FailingIdle {
    fn send(&mut self, _data: &[u8]) -> std::result::Result<(), SinkError> {
        Ok(())
    }
    fn idle(&mut self) -> std::result::Result<(), SinkError> {
        Err("link down".into())
    }
}

#[test]
fn idle_errors_stop_the_run_unless_ignored() {
    let a = one_packet(1);
    let paced = || [Stream::new("a", CaptureSource::new(&a).loops(3)).with_rate(Rate::Pps(1000.0))];
    let err = run(&mut paced(), &mut FailingIdle, &RunConfig::default()).unwrap_err();
    assert!(err.to_string().contains("link down"), "{err}");
    let cfg = RunConfig {
        ignore_send_errors: true,
        ..Default::default()
    };
    assert_eq!(
        run(&mut paced(), &mut FailingIdle, &cfg)
            .unwrap()
            .total
            .packets,
        3
    );
}

#[test]
fn a_ramp_that_ends_ends_the_stream() {
    // 2000 pps for 50 ms, then the shape drops to 0%: about 100 packets
    // even though the stream loops forever.
    let a = one_packet(1);
    let model: TrafficModel = "at=0s:100%,at=50ms:100%,at=50ms:0%".parse().unwrap();
    let mut streams = [Stream::new("a", CaptureSource::new(&a).loops(0))
        .with_rate(Rate::Pps(2000.0))
        .with_model(model)];
    let start = Instant::now();
    let stats = run(&mut streams, &mut NullSink, &RunConfig::default()).unwrap();
    assert_eq!(stats.total.packets, 101);
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn bursts_leave_back_to_back() {
    let a = one_packet(1);
    let mut streams = [Stream::new("a", CaptureSource::new(&a).loops(12))
        .with_rate(Rate::Pps(200.0))
        .with_model("burst=4".parse().unwrap())];
    let start = Instant::now();
    let stats = run(&mut streams, &mut NullSink, &RunConfig::default()).unwrap();
    assert_eq!(stats.total.packets, 12);
    // Three bursts 20 ms apart: the last leaves at 40 ms.
    let took = start.elapsed();
    assert!(took >= Duration::from_millis(40), "{took:?}");
}

#[test]
fn models_need_a_packet_or_bit_rate() {
    let a = one_packet(1);
    let mut streams = [Stream::new("a", CaptureSource::new(&a))
        .with_rate(Rate::TopSpeed)
        .with_model(TrafficModel::poisson())];
    let err = run(&mut streams, &mut NullSink, &RunConfig::default()).unwrap_err();
    assert!(err.to_string().contains("packet or bit rate"), "{err}");
}

#[cfg(feature = "profile")]
#[test]
fn example_files_pass_the_check() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    let mut found = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "toml") {
            found += 1;
            check::check_file(&path, None, &[])
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        }
    }
    assert!(found >= 10);
}

/// A sink that stalls once, as a paused VM would, and notes when each
/// packet went out.
struct StallingSink {
    sent: Vec<Instant>,
    stall_at: usize,
    stall: Duration,
}

impl PacketSink for StallingSink {
    fn send(&mut self, _data: &[u8]) -> std::result::Result<(), SinkError> {
        if self.sent.len() == self.stall_at {
            std::thread::sleep(self.stall);
        }
        self.sent.push(Instant::now());
        Ok(())
    }
}

/// The most packets sent within any `window`.
fn densest(sent: &[Instant], window: Duration) -> usize {
    let mut best = 0;
    let mut j = 0;
    for i in 0..sent.len() {
        while sent[i] - sent[j] > window {
            j += 1;
        }
        best = best.max(i - j + 1);
    }
    best
}

#[test]
fn a_stream_with_a_max_lag_skips_what_a_stall_held_up() {
    let a = one_packet(1);
    let run_stalled = |lag: Option<Duration>| {
        let mut stream =
            Stream::new("s", CaptureSource::new(&a).loops(0)).with_rate(Rate::Pps(1000.0));
        if let Some(lag) = lag {
            stream = stream.with_max_lag(lag);
        }
        let mut sink = StallingSink {
            sent: Vec::new(),
            stall_at: 20,
            stall: Duration::from_millis(60),
        };
        let cfg = RunConfig {
            duration: Some(Duration::from_millis(250)),
            ..Default::default()
        };
        let stats = run(&mut [stream], &mut sink, &cfg).unwrap();
        (
            stats.total.packets,
            densest(&sink.sent, Duration::from_millis(2)),
        )
    };
    // Catching up: about 250 packets, the 60 held up sent back to back.
    let (caught_up, burst) = run_stalled(None);
    assert!(caught_up >= 225, "sent {caught_up}");
    assert!(burst >= 30, "burst {burst}");
    // With 5 ms of lag: at least the 55 held up left out, and no burst of
    // more than 5 ms' worth. (Where sleeps overshoot by more than 5 ms, as on
    // macOS runners, more are left out: the lower bound is loose.)
    let (sent, burst) = run_stalled(Some(Duration::from_millis(5)));
    assert!(
        (50..=caught_up - 45).contains(&sent),
        "sent {sent} of {caught_up}"
    );
    assert!(burst <= 12, "burst {burst}");
}
