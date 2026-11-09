//! Multi-burst streams, streams that start each other, wire rates and live
//! control of a running run.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferotrx_core::*;

fn one_packet(tag: u8) -> Arc<Capture> {
    Arc::new(Capture::new(
        1,
        vec![Packet::new(Duration::ZERO, vec![tag; 60])],
    ))
}

/// Keeps each packet's first byte and when it left.
#[derive(Clone, Default)]
struct Timed(Arc<Mutex<Vec<(u8, Instant)>>>);

impl PacketSink for Timed {
    fn send(&mut self, data: &[u8]) -> std::result::Result<(), SinkError> {
        self.0.lock().unwrap().push((data[0], Instant::now()));
        Ok(())
    }
}

impl Timed {
    fn tags(&self) -> Vec<u8> {
        self.0.lock().unwrap().iter().map(|p| p.0).collect()
    }
    fn times(&self) -> Vec<Instant> {
        self.0.lock().unwrap().iter().map(|p| p.1).collect()
    }
}

#[test]
fn multi_bursts_leave_with_gaps_between_them() {
    let cap = one_packet(1);
    let mut streams = [Stream::new("b", CaptureSource::new(cap).loops(0))
        .with_rate(Rate::Pps(10_000.0))
        .with_bursts(MultiBurst {
            packets: 5,
            count: Some(3),
            gap: Duration::from_millis(40),
        })];
    let mut sink = Timed::default();
    let start = Instant::now();
    let stats = run(&mut streams, &mut sink, &RunConfig::default()).unwrap();
    assert_eq!(stats.total.packets, 15);
    let t = sink.times();
    // The firm check, whatever the machine does: packets never leave early,
    // so burst b starts no sooner than b gaps (and 5 b packets at 0.1 ms)
    // after the run did. Spreading the packets evenly instead would start
    // burst 1 at about 28 ms and fail here.
    for b in 1..3 {
        let due = (Duration::from_millis(40) + Duration::from_micros(500)) * b as u32;
        let at = t[b * 5] - start;
        assert!(at >= due, "burst {b} at {at:?}, due {due:?}");
    }
    // The shape: tight bursts with clear gaps. A stalled CI machine (macOS
    // runners stall for 40 ms and more) can send one burst late, which
    // stretches it and eats the gap after it, so only the best of the three
    // bursts and of the two gaps is checked.
    let tightest = (0..3).map(|b| t[b * 5 + 4] - t[b * 5]).min().unwrap();
    assert!(tightest < Duration::from_millis(20), "bursts: {t:?}");
    let widest = (1..3).map(|b| t[b * 5] - t[b * 5 - 1]).max().unwrap();
    assert!(widest >= Duration::from_millis(30), "gaps: {t:?}");
}

#[test]
fn multi_bursts_split_over_workers_send_the_same_packets() {
    let cap = one_packet(1);
    let make = |k| {
        Stream::new("b", CaptureSource::new(cap.clone()).loops(0))
            .with_rate(Rate::TopSpeed)
            .with_bursts(MultiBurst {
                packets: 7,
                count: Some(4),
                gap: Duration::from_millis(1),
            })
            .shard(k, 3)
    };
    let total: u64 = (0..3)
        .map(|k| {
            run(&mut [make(k)], &mut NullSink, &RunConfig::default())
                .unwrap()
                .total
                .packets
        })
        .sum();
    assert_eq!(total, 28);
}

#[test]
fn next_streams_run_one_after_another_and_loop() {
    // a (2 packets) -> b (3 packets) -> a again, twice more: a b a b a b.
    let (a, b) = (one_packet(1), one_packet(2));
    let mut streams = [
        Stream::new("a", CaptureSource::new(a).loops(2))
            .with_rate(Rate::TopSpeed)
            .with_next(1, None),
        Stream::new("b", CaptureSource::new(b).loops(0))
            .with_rate(Rate::TopSpeed)
            .with_limit(Some(3))
            .with_next(0, Some(2)),
    ];
    let mut sink = Timed::default();
    let stats = run(&mut streams, &mut sink, &RunConfig::default()).unwrap();
    assert_eq!(sink.tags(), [1, 1, 2, 2, 2, 1, 1, 2, 2, 2, 1, 1, 2, 2, 2]);
    assert_eq!((stats.streams[0].packets, stats.streams[1].packets), (6, 9));
    assert_eq!(stats.streams[0].loops_completed, 6);
}

#[test]
fn a_waiting_stream_counts_its_delay_from_its_start() {
    let (a, b) = (one_packet(1), one_packet(2));
    let mut streams = [
        Stream::new("first", CaptureSource::new(a).loops(1))
            .with_rate(Rate::TopSpeed)
            .with_next(1, None),
        Stream::new("second", CaptureSource::new(b).loops(1))
            .with_rate(Rate::TopSpeed)
            .with_delay(Duration::from_millis(30)),
        // Not started by anyone: starts with the run.
        Stream::new("other", CaptureSource::new(one_packet(3)).loops(1)).with_rate(Rate::TopSpeed),
    ];
    let mut sink = Timed::default();
    run(&mut streams, &mut sink, &RunConfig::default()).unwrap();
    let all = sink.0.lock().unwrap().clone();
    let at = |tag| all.iter().find(|p| p.0 == tag).unwrap().1;
    assert!(at(2) - at(1) >= Duration::from_millis(30));
    assert!(at(3) < at(2));
}

#[test]
fn a_stream_can_start_with_the_run_and_again_later() {
    let (a, b) = (one_packet(1), one_packet(2));
    let mut streams = [
        Stream::new("a", CaptureSource::new(a).loops(1))
            .with_rate(Rate::Pps(1000.0))
            .with_delay(Duration::from_millis(5))
            .with_next(1, Some(1)),
        Stream::new("b", CaptureSource::new(b).loops(1))
            .with_rate(Rate::TopSpeed)
            .with_self_start(true),
    ];
    let mut sink = Timed::default();
    run(&mut streams, &mut sink, &RunConfig::default()).unwrap();
    assert_eq!(sink.tags(), [2, 1, 2]);
}

#[test]
fn an_l1_bit_rate_counts_the_wire() {
    // 60-byte frames + 24 on the wire = 84 bytes = 672 bits; at 6.72 Mbit/s
    // that is 10000 frames per second: 0.1 ms each.
    let cap = one_packet(1);
    let (rate, overhead) = "6.72mbps-l1"
        .parse::<RateSpec>()
        .unwrap()
        .resolve(None)
        .unwrap();
    let mut s = Stream::new("w", CaptureSource::new(cap).loops(0)).with_rate(rate);
    s.overhead = overhead;
    let cfg = RunConfig {
        duration: Some(Duration::from_millis(200)),
        ..Default::default()
    };
    let stats = run(&mut [s], &mut NullSink, &cfg).unwrap();
    assert!(
        (1800..=2001).contains(&stats.total.packets),
        "{}",
        stats.total.packets
    );
}

#[test]
fn a_paused_run_holds_and_goes_on_where_it_was() {
    let cap = one_packet(1);
    let stream = Stream::new("p", CaptureSource::new(cap).loops(0)).with_rate(Rate::Pps(2000.0));
    let sink = Timed::default();
    let control = Arc::new(RunControl::new());
    let job = Job::spawn(
        vec![stream],
        Box::new(sink.clone()),
        RunConfig {
            control: Some(control.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    job.control().pause();
    std::thread::sleep(Duration::from_millis(20));
    let held = sink.times().len();
    std::thread::sleep(Duration::from_millis(150));
    assert!(sink.times().len() <= held + 1, "sent while paused");
    let resumed = Instant::now();
    job.control().resume();
    // Wait for the run to go on rather than for a fixed time: a busy CI
    // runner (macOS) can give the sending thread far less than 100 ms of
    // the next 100 ms.
    let deadline = resumed + Duration::from_secs(3);
    while sink.times().len() <= held + 100 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    job.stop();
    job.join().unwrap();
    let times = sink.times();
    // No catch-up burst after the pause: at most a few packets in the first ms.
    let burst = times
        .iter()
        .filter(|&&t| t >= resumed && t < resumed + Duration::from_millis(2))
        .count();
    assert!(burst <= 6, "{burst} packets right after resuming");
    assert!(times.len() > held + 100, "{} then {}", held, times.len());
}

#[test]
fn a_multiplier_changes_the_rate_of_what_is_left() {
    let (a, b) = (one_packet(1), one_packet(2));
    let streams = vec![
        Stream::new("a", CaptureSource::new(a).loops(0)).with_rate(Rate::Pps(1000.0)),
        Stream::new("b", CaptureSource::new(b).loops(0)).with_rate(Rate::Pps(1000.0)),
    ];
    let sink = Timed::default();
    let job = Job::spawn(streams, Box::new(sink.clone()), RunConfig::default()).unwrap();
    job.control().set_multiplier(4.0).unwrap();
    job.control().set_stream_multiplier(1, 0.25).unwrap();
    let set = Instant::now();
    std::thread::sleep(Duration::from_millis(400));
    job.stop();
    job.join().unwrap();
    // a at 4000 pps, b at 1000 pps, counted over 250 ms after the change.
    // Packets never leave early, so the counts cannot be above the new
    // rates however late the run was stopped; a stalled machine can only
    // send fewer.
    let window = set..set + Duration::from_millis(250);
    let sent = sink.0.lock().unwrap().clone();
    let count = |tag| {
        sent.iter()
            .filter(|p| p.0 == tag && window.contains(&p.1))
            .count()
    };
    let (a, b) = (count(1), count(2));
    assert!(a > 2 * b, "a {a}, b {b}");
    assert!((100..=260).contains(&b), "b {b}");
    assert!(a <= 1010, "a {a}");
    // A paused stream with another one going.
    let streams = vec![
        Stream::new("a", CaptureSource::new(one_packet(1)).loops(0)).with_rate(Rate::Pps(1000.0)),
        Stream::new("b", CaptureSource::new(one_packet(2)).loops(0)).with_rate(Rate::Pps(1000.0)),
    ];
    let job = Job::spawn(streams, Box::new(NullSink), RunConfig::default()).unwrap();
    job.control().pause_stream(0);
    std::thread::sleep(Duration::from_millis(200));
    job.stop();
    let stats = job.join().unwrap();
    assert!(stats.streams[0].packets <= 1, "{:?}", stats.streams[0]);
    assert!(stats.streams[1].packets > 100);
}

#[test]
fn a_paused_run_still_ends_at_its_duration() {
    let cap = one_packet(1);
    let control = Arc::new(RunControl::new());
    control.pause();
    let cfg = RunConfig {
        duration: Some(Duration::from_millis(100)),
        control: Some(control),
        ..Default::default()
    };
    let t = Instant::now();
    let mut s = [Stream::new("p", CaptureSource::new(cap).loops(0)).with_rate(Rate::Pps(1000.0))];
    let stats = run(&mut s, &mut NullSink, &cfg).unwrap();
    assert!(t.elapsed() < Duration::from_secs(1));
    assert!(stats.total.packets <= 1);
}
