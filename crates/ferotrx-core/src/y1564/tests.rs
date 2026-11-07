use std::collections::BTreeMap;
use std::time::Duration;

use super::*;

/// A simulated network: a color-aware policer (yellow frames are dropped
/// first), a fixed delay with some variation, and an optional outage.
struct Net {
    /// Information rate let through per service, Mbit/s; `None` passes all.
    police: Option<f64>,
    /// Bytes a burst may bring at once without loss; `None` for any.
    bucket: Option<u64>,
    delay: Duration,
    jitter: Duration,
    /// Nothing passes from this second of a step to that one.
    outage: Option<(u64, u64)>,
    steps: Vec<Y1564Step>,
}

impl Net {
    fn new(police: Option<f64>) -> Self {
        Net {
            police,
            bucket: None,
            delay: Duration::from_millis(2),
            jitter: Duration::from_micros(100),
            outage: None,
            steps: Vec::new(),
        }
    }
}

const T0: u64 = 1_700_000_000;

impl ServiceRunner for Net {
    fn run(&mut self, step: &Y1564Step) -> Result<Vec<FlowResult>> {
        self.steps.push(step.clone());
        let secs = step.duration.as_secs_f64();
        // Room per service under the policer; green frames go first.
        let mut room: BTreeMap<usize, f64> = BTreeMap::new();
        let mut order: Vec<usize> = (0..step.flows.len()).collect();
        order.sort_by_key(|&k| step.flows[k].color == Color::Yellow);
        let mut pass = vec![1.0; step.flows.len()];
        for k in order {
            let f = &step.flows[k];
            if let Some(p) = self.police {
                let left = room.entry(f.service).or_insert(p);
                let through = f.mbps.min(*left);
                *left -= through;
                pass[k] = through / f.mbps;
            }
            if let Some(b) = self.bucket {
                let burst_bytes = f.burst as f64 * (f.frame_len + 4.0);
                if f.burst > 1 && burst_bytes > b as f64 {
                    pass[k] *= b as f64 / burst_bytes;
                }
            }
        }
        Ok(step
            .flows
            .iter()
            .zip(pass)
            .map(|(f, pass)| {
                let tx = (f.pps * secs).round() as u64;
                let up = match self.outage {
                    Some((a, b)) => 1.0 - (b - a) as f64 / secs,
                    None => 1.0,
                };
                let rx = (tx as f64 * pass * up).round() as u64;
                let mut latency = LatencyStats::default();
                for i in 0..100u32 {
                    latency.record(Some(self.delay + self.jitter * (i % 10) / 10));
                }
                let mut intervals = BTreeMap::new();
                if let Some(len) = step.interval {
                    let per = f.pps * len.as_secs_f64() * pass;
                    let n = (secs / len.as_secs_f64()) as u64;
                    let first = Duration::from_secs(T0).as_nanos() / len.as_nanos();
                    for i in 0..n {
                        let t = (i as f64 * len.as_secs_f64()) as u64;
                        let down = self.outage.is_some_and(|(a, b)| t >= a && t < b);
                        let packets = if down { 0 } else { per.round() as u64 };
                        let mut iv = IntervalStats {
                            packets,
                            bytes: packets * f.frame_len as u64,
                            ..Default::default()
                        };
                        if packets > 0 {
                            let seq = f.pps * len.as_secs_f64() * i as f64;
                            iv.first_seq = Some(seq.round() as u64);
                            let ns = self.delay.as_nanos() as u64;
                            iv.timed = packets;
                            iv.latency_sum_ns = u128::from(ns) * u128::from(packets);
                            iv.latency_min_ns = ns;
                            iv.latency_max_ns = ns;
                        }
                        intervals.insert((first + u128::from(i)) as u64, iv);
                    }
                }
                FlowResult {
                    tx,
                    tx_bytes: tx * f.frame_len as u64,
                    rx,
                    rx_bytes: rx * f.frame_len as u64,
                    start: Duration::from_secs(T0),
                    elapsed: step.duration,
                    latency,
                    intervals,
                    ..Default::default()
                }
            })
            .collect())
    }
}

fn service(name: &str, cir: f64, eir: f64) -> ServiceSpec {
    ServiceSpec {
        name: name.into(),
        size: SizeMix::fixed(1000).unwrap(),
        cir_mbps: cir,
        eir_mbps: eir,
        cbs: 0,
        ebs: 0,
        color_aware: true,
        sac: Acceptance {
            flr: 0.1,
            ftd: Some(Duration::from_millis(5)),
            fdv: Some(Duration::from_millis(1)),
            availability: Some(99.0),
        },
    }
}

fn config(services: Vec<ServiceSpec>, tests: &[Y1564Test]) -> Y1564Config {
    Y1564Config {
        services,
        tests: tests.to_vec(),
        step_duration: Duration::from_secs(10),
        performance_duration: Duration::from_secs(60),
        line_rate_mbps: 100.0,
        ..Default::default()
    }
}

fn step<'a>(r: &'a Y1564Report, service: &str, kind: StepKind) -> &'a ServiceResult {
    r.configuration
        .iter()
        .filter(|s| s.step == kind)
        .flat_map(|s| &s.services)
        .find(|s| s.service == service)
        .unwrap_or_else(|| panic!("no {kind} step for {service}"))
}

#[test]
fn a_policer_at_cir_plus_eir_passes_every_step() {
    let c = config(vec![service("data", 8.0, 2.0)], &[Y1564Test::Configuration]);
    let mut net = Net::new(Some(10.0));
    let r = run_y1564(&c, &mut net, |_| {}).unwrap();
    let names: Vec<&str> = r.configuration.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        ["25% CIR", "50% CIR", "75% CIR", "100% CIR", "CIR+EIR", "policing"]
    );
    assert!(r.passed, "{}", r.text());
    // Policing: green 8 + yellow 2.5 offered, 10 let through.
    let p = step(&r, "data", StepKind::Policing);
    assert!((p.ir_mbps - 10.0).abs() < 0.05, "{}", p.ir_mbps);
    assert!(p.yellow_flr_pct.unwrap() > 15.0);
    assert_eq!(p.flr_pct, 0.0);
    // The yellow flow ran at 125% of the EIR.
    let y = &net.steps[5].flows[1];
    assert_eq!((y.color, y.mbps), (Color::Yellow, 2.5));
    assert_eq!(r.services[0].configuration, Some(true));
    assert_eq!(r.services[0].performance, None);
}

#[test]
fn without_a_policer_the_policing_step_fails() {
    let c = config(vec![service("data", 8.0, 2.0)], &[Y1564Test::Configuration]);
    let r = run_y1564(&c, &mut Net::new(None), |_| {}).unwrap();
    assert!(!r.passed);
    assert_eq!(r.failed_steps(), 1);
    let p = step(&r, "data", StepKind::Policing);
    assert!(!p.passed && p.failures[0].contains("not policed"), "{p:?}");
    assert!(step(&r, "data", StepKind::Eir).passed);
}

#[test]
fn a_policer_below_the_cir_fails_the_upper_steps() {
    let c = config(vec![service("data", 8.0, 0.0)], &[Y1564Test::Configuration]);
    let r = run_y1564(&c, &mut Net::new(Some(5.0)), |_| {}).unwrap();
    assert!(step(&r, "data", StepKind::Cir(50.0)).passed);
    let full = step(&r, "data", StepKind::Cir(100.0));
    assert!(!full.passed);
    assert!(
        full.failures[0].starts_with("FLR 37.50% > 0.1%"),
        "{full:?}"
    );
    assert!(!step(&r, "data", StepKind::Cir(75.0)).passed);
    // No EIR: policing sends 125% of the CIR, and no CIR+EIR step.
    assert!(r.configuration.iter().all(|s| s.step != StepKind::Eir));
    assert_eq!(r.services[0].configuration, Some(false));
    assert!(r.text().contains("FAIL"));
}

#[test]
fn delay_and_its_variation_are_judged() {
    let c = config(vec![service("data", 8.0, 0.0)], &[Y1564Test::Configuration]);
    let mut net = Net::new(None);
    net.delay = Duration::from_millis(7);
    let r = run_y1564(&c, &mut net, |_| {}).unwrap();
    let s = step(&r, "data", StepKind::Cir(25.0));
    assert!(s.failures.iter().any(|f| f.starts_with("FTD 7.")), "{s:?}");

    let mut net = Net::new(None);
    net.jitter = Duration::from_millis(3);
    let r = run_y1564(&c, &mut net, |_| {}).unwrap();
    let s = step(&r, "data", StepKind::Cir(25.0));
    assert!(s.failures.iter().any(|f| f.starts_with("FDV")), "{s:?}");
}

#[test]
fn burst_steps_send_cbs_and_ebs_bursts() {
    let mut s = service("data", 8.0, 2.0);
    s.cbs = 20_000;
    s.ebs = 10_000;
    let c = config(vec![s], &[Y1564Test::Configuration]);
    let mut net = Net::new(Some(10.0));
    net.bucket = Some(30_000);
    let r = run_y1564(&c, &mut net, |_| {}).unwrap();
    assert!(r.passed, "{}", r.text());
    let cbs = net.steps.iter().find(|s| s.kind == StepKind::Cbs).unwrap();
    // 20,000 bytes of 1004-byte frames.
    assert_eq!(cbs.flows[0].burst, 19);
    let ebs = net.steps.iter().find(|s| s.kind == StepKind::Ebs).unwrap();
    assert_eq!((ebs.flows[0].burst, ebs.flows[1].burst), (0, 9));
    // A policer bucket smaller than the CBS loses green frames.
    let mut net = Net::new(Some(10.0));
    net.bucket = Some(10_000);
    let r = run_y1564(&c, &mut net, |_| {}).unwrap();
    assert!(!step(&r, "data", StepKind::Cbs).passed);
    assert!(step(&r, "data", StepKind::Ebs).passed);
}

#[test]
fn performance_runs_every_service_at_its_cir_with_intervals() {
    let c = config(
        vec![service("voice", 2.0, 0.0), service("data", 20.0, 5.0)],
        &[Y1564Test::Performance],
    );
    let mut net = Net::new(None);
    let r = run_y1564(&c, &mut net, |_| {}).unwrap();
    assert!(r.passed, "{}", r.text());
    assert_eq!(net.steps.len(), 1);
    let s = &net.steps[0];
    assert_eq!(s.interval, Some(Duration::from_secs(1)));
    assert!(s.flows.iter().all(|f| f.color == Color::Green));
    assert_eq!(s.flows[1].mbps, 20.0);
    let p = r.performance.as_ref().unwrap();
    assert_eq!(p.services.len(), 2);
    for s in &p.services {
        assert_eq!(s.intervals.len(), 60);
        assert_eq!(s.availability_pct, Some(100.0));
        assert_eq!(s.ses, Some(0));
        assert!(
            s.intervals.iter().all(|i| i.flr_pct < 0.5),
            "{:?}",
            s.intervals
        );
    }
    assert!(r.text().contains("Service performance test"));
}

#[test]
fn a_long_outage_makes_a_service_unavailable() {
    let c = config(vec![service("data", 8.0, 0.0)], &[Y1564Test::Performance]);
    let mut net = Net::new(None);
    net.outage = Some((20, 35));
    let r = run_y1564(&c, &mut net, |_| {}).unwrap();
    let s = &r.performance.as_ref().unwrap().services[0];
    assert_eq!(s.ses, Some(15));
    // 15 of 60 seconds unavailable: 75%.
    assert_eq!(s.availability_pct, Some(75.0));
    assert!(!s.passed);
    assert!(s.failures.iter().any(|f| f.starts_with("availability")));

    // A short outage loses frames but leaves the service available.
    let mut net = Net::new(None);
    net.outage = Some((20, 25));
    let r = run_y1564(&c, &mut net, |_| {}).unwrap();
    let s = &r.performance.as_ref().unwrap().services[0];
    assert_eq!((s.ses, s.availability_pct), (Some(5), Some(100.0)));
    assert!(s.failures.iter().all(|f| f.starts_with("FLR")), "{s:?}");
}

#[test]
fn availability_follows_y1563() {
    let mk = |pattern: &str| {
        let mut iv: Vec<IntervalRecord> = pattern
            .chars()
            .map(|c| IntervalRecord {
                start_s: 0.0,
                rx: 0,
                flr_pct: 0.0,
                ftd_ms: None,
                max_ftd_ms: None,
                ses: c == 'x',
                available: true,
            })
            .collect();
        mark_availability(&mut iv, 3);
        iv.iter()
            .map(|i| if i.available { 'A' } else { 'U' })
            .collect::<String>()
    };
    assert_eq!(mk("..xx..xxx.."), "AAAAAAUUUUU");
    assert_eq!(mk("..xxx..x...x"), "..UUUUUUAAA.".replace('.', "A"));
    assert_eq!(mk("xxx...."), "UUUAAAA");
}

#[test]
fn stops_between_steps() {
    let stop = Arc::new(AtomicBool::new(false));
    let mut c = config(vec![service("data", 8.0, 2.0)], &Y1564Test::ALL);
    c.stop = Some(stop.clone());
    let mut n = 0;
    let r = run_y1564(&c, &mut Net::new(Some(10.0)), |_| {
        n += 1;
        if n == 2 {
            stop.store(true, Ordering::Relaxed);
        }
    })
    .unwrap();
    assert!(r.stopped && !r.passed);
    assert_eq!(r.configuration.len(), 2);
    assert!(r.performance.is_none());
}

#[test]
fn checks_the_config() {
    let bad = |c: Y1564Config| c.validate().unwrap_err().to_string();
    let ok = config(vec![service("a", 8.0, 2.0)], &Y1564Test::ALL);
    assert!(ok.validate().is_ok());
    assert!(bad(config(vec![], &Y1564Test::ALL)).contains("no services"));
    assert!(bad(config(vec![service("a", 0.0, 0.0)], &Y1564Test::ALL)).contains("cir"));
    assert!(bad(config(
        vec![service("a", 60.0, 0.0), service("b", 60.0, 0.0)],
        &Y1564Test::ALL
    ))
    .contains("add up"));
    assert!(bad(config(
        vec![service("a", 6.0, 0.0), service("a", 6.0, 0.0)],
        &Y1564Test::ALL
    ))
    .contains("two services"));
    let mut c = ok.clone();
    c.overshoot = 90.0;
    assert!(bad(c).contains("overshoot"));
}

#[test]
fn pps_counts_the_fcs_and_on_layer1_the_preamble_and_gap() {
    let mut c = Y1564Config::default();
    // 10 Mbit/s of 1000-byte frames: 1004 bytes with the FCS.
    assert!((c.pps(10.0, 1000.0) - 1e7 / 8032.0).abs() < 1e-9);
    c.layer1 = true;
    assert!((c.pps(10.0, 1000.0) - 1e7 / 8192.0).abs() < 1e-9);
    assert!((c.mbps(1000, 1_000_000, 1.0) - 8.192).abs() < 1e-9);
}

#[test]
fn a_real_run_over_memory_ports_counts_intervals() {
    use crate::{memory_ports, Capture, PacketReceiver, PacketSink, PortReceiver};
    use std::sync::Mutex;

    let (tx, rx) = memory_ports();
    let (tx, rx) = (
        Arc::new(Mutex::new(Some(tx))),
        Arc::new(Mutex::new(Some(rx))),
    );
    let cap = |dscp: u8| {
        Arc::new(
            Capture::from_specs(
                &[format!("eth/ipv4(dst=10.0.0.2,dscp={dscp})/udp(dport=7)")],
                Duration::ZERO,
            )
            .unwrap(),
        )
    };
    let frames = vec![ServiceFrames {
        green: cap(46),
        yellow: cap(0),
        vary: Vec::new(),
    }];
    let mut runner = JobServiceRunner::new(
        frames,
        Box::new(move || {
            Ok(Box::new(tx.lock().unwrap().take().unwrap()) as Box<dyn PacketSink + Send>)
        }),
        Box::new(move || {
            Ok(Box::new(PortReceiver(rx.lock().unwrap().take().unwrap()))
                as Box<dyn PacketReceiver>)
        }),
    );
    runner.rx_wait = Duration::from_millis(100);
    let mut s = service("data", 2.0, 0.0);
    s.size = SizeMix::fixed(200).unwrap();
    s.sac.ftd = Some(Duration::from_secs(1));
    s.sac.fdv = Some(Duration::from_secs(1));
    let mut c = config(vec![s], &[Y1564Test::Performance]);
    c.performance_duration = Duration::from_millis(2200);
    c.interval = Duration::from_millis(250);
    let r = run_y1564(&c, &mut runner, |_| {}).unwrap();
    let p = &r.performance.as_ref().unwrap().services[0];
    // 2 Mbit/s of 204-byte frames: about 1225 a second. Frames more than
    // 5 ms late are skipped, and macOS runners oversleep often enough to
    // leave out up to a fifth (1.58 Mbit/s seen).
    let low = if cfg!(target_os = "macos") { 1.4 } else { 1.9 };
    let f = &r.performance.as_ref().unwrap().flows[0];
    assert!(f.tx as f64 > 1250.0 * low && f.rx == f.tx, "{f:?}");
    assert!(p.ir_mbps > low && p.ir_mbps < 2.1, "{p:?}");
    // Whole intervals of 250 ms in 2.2 s: 7 or 8.
    assert!((7..=8).contains(&p.intervals.len()), "{:?}", p.intervals);
    assert!(
        p.intervals.iter().all(|i| i.flr_pct < 5.0 && !i.ses),
        "{:?}",
        p.intervals
    );
    assert_eq!(p.availability_pct, Some(100.0));
    assert!(r.passed, "{}", r.text());
}

#[test]
fn a_color_blind_service_is_judged_by_its_rate_when_policed() {
    let mut s = service("data", 8.0, 2.0);
    s.color_aware = false;
    s.ebs = 5_000;
    let c = config(vec![s], &[Y1564Test::Configuration]);
    // A color-blind policer at CIR + EIR drops green and yellow alike.
    struct Blind;
    impl ServiceRunner for Blind {
        fn run(&mut self, step: &Y1564Step) -> Result<Vec<FlowResult>> {
            let total: f64 = step.flows.iter().map(|f| f.mbps).sum();
            let pass = (10.0 / total).min(1.0);
            let secs = step.duration.as_secs_f64();
            Ok(step
                .flows
                .iter()
                .map(|f| {
                    let tx = (f.pps * secs) as u64;
                    let rx = (tx as f64 * pass) as u64;
                    let mut latency = LatencyStats::default();
                    latency.record(Some(Duration::from_millis(1)));
                    FlowResult {
                        tx,
                        rx,
                        tx_bytes: tx * 1000,
                        rx_bytes: rx * 1000,
                        elapsed: step.duration,
                        latency,
                        ..Default::default()
                    }
                })
                .collect())
        }
    }
    let r = run_y1564(&c, &mut Blind, |_| {}).unwrap();
    assert!(r.passed, "{}", r.text());
    let p = step(&r, "data", StepKind::Policing);
    assert!(!p.green_judged && p.flr_pct > 0.0);
    assert!(p.notes[0].starts_with("color blind"));
    assert!(step(&r, "data", StepKind::Eir).green_judged);
    // Color aware, the same network fails: it dropped green frames.
    let mut c = c.clone();
    c.services[0].color_aware = true;
    let r = run_y1564(&c, &mut Blind, |_| {}).unwrap();
    assert!(!step(&r, "data", StepKind::Policing).passed);
}

#[test]
fn intervals_count_what_was_sent_by_sequence_numbers() {
    // Intervals of a second: the sender stalls in the second one (50 sent,
    // all arrive), 10 of the third's 100 are lost, nothing of the fourth
    // arrives, and the fifth is whole.
    let mut intervals = BTreeMap::new();
    let mut add = |k: u64, seqs: &mut dyn Iterator<Item = u64>| {
        let mut iv = IntervalStats::default();
        for s in seqs {
            iv.packets += 1;
            iv.first_seq = Some(iv.first_seq.map_or(s, |f| f.min(s)));
            iv.last_seq = Some(iv.last_seq.map_or(s, |f| f.max(s)));
        }
        intervals.insert(k, iv);
    };
    add(0, &mut (0..100));
    add(1, &mut (100..150));
    add(2, &mut (150..250).filter(|s| s % 10 != 5));
    add(4, &mut (350..450));
    let r = FlowResult {
        tx: 450,
        rx: 340,
        start: Duration::ZERO,
        elapsed: Duration::from_secs(5),
        intervals,
        ..Default::default()
    };
    let c = config(vec![service("a", 1.0, 0.0)], &[Y1564Test::Performance]);
    let got: Vec<f64> = interval_records(&c, &r, Duration::from_secs(1))
        .iter()
        .map(|i| (i.flr_pct * 10.0).round() / 10.0)
        .collect();
    assert_eq!(got, [0.0, 0.0, 10.0, 100.0, 0.0]);
}
