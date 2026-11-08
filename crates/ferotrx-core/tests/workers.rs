//! Runs split over several workers: streams packet by packet, stateful TCP
//! and UDP by flow, through a port-rewriting relay.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ferotrx_core::*;

fn mac(s: &str) -> MacAddr {
    s.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn sock(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn program() -> Arc<TcpProgram> {
    Arc::new(TcpProgram::new(
        80,
        vec![
            TcpMessage::new(TcpRole::Client, "GET / HTTP/1.1\r\n\r\n"),
            TcpMessage::new(TcpRole::Server, vec![b'x'; 5000]),
        ],
    ))
}

fn tcp_config(client_ip: &str, server_ip: &str, connections: u64) -> TcpConfig {
    let mut client = TcpClientConfig::new(
        TcpEndpoint::new(0, mac("02:00:00:00:00:01"), ip(client_ip)).with_ip_count(3),
    );
    client.connections = connections;
    client.cps = 2000.0;
    TcpConfig {
        templates: vec![
            TcpTemplate::new(program(), SocketAddr::new(ip(server_ip), 80)).with_name("a"),
            TcpTemplate::new(program(), SocketAddr::new(ip(server_ip), 8080))
                .with_name("b")
                .with_weight(3),
        ],
        client: Some(client),
        server: Some(TcpServerConfig::new(TcpEndpoint::new(
            1,
            mac("02:00:00:00:00:02"),
            ip(server_ip),
        ))),
        options: TcpOptions::default(),
    }
}

/// Moves frames between two memory ports, changing the source port of
/// TCP/UDP frames from the client side by +10000 and back on the way in, as
/// a NAT router changes ports. Checksums are fixed up incrementally.
fn relay(client_side: MemoryPort, server_side: MemoryPort, stop: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        let (mut c, mut s) = (client_side, server_side);
        let mut buf = Vec::new();
        while !stop.load(Ordering::Relaxed) {
            let mut busy = false;
            while PacketPort::recv(&mut c, &mut buf).unwrap() {
                shift_port(&mut buf, true);
                PacketPort::send(&mut s, &buf).unwrap();
                busy = true;
            }
            while PacketPort::recv(&mut s, &mut buf).unwrap() {
                shift_port(&mut buf, false);
                PacketPort::send(&mut c, &buf).unwrap();
                busy = true;
            }
            if !busy {
                std::thread::sleep(Duration::from_micros(100));
            }
        }
    });
}

fn shift_port(f: &mut [u8], outbound: bool) {
    let (l3, proto) = match u16::from_be_bytes([f[12], f[13]]) {
        0x0800 => (14, f[23]),
        0x86dd => (14, f[20]),
        _ => return,
    };
    let l4 = if f[l3] >> 4 == 4 {
        l3 + usize::from(f[l3] & 0xf) * 4
    } else {
        l3 + 40
    };
    let csum_at = match proto {
        6 => l4 + 16,
        17 => l4 + 6,
        _ => return,
    };
    // Outbound: the source port; inbound: the destination port.
    let at = if outbound { l4 } else { l4 + 2 };
    let old = u16::from_be_bytes([f[at], f[at + 1]]);
    let original = if outbound {
        old
    } else {
        old.wrapping_sub(10000)
    };
    if !(1024..50000).contains(&original) {
        return;
    }
    let new = if outbound { old + 10000 } else { old - 10000 };
    f[at..at + 2].copy_from_slice(&new.to_be_bytes());
    let c = u16::from_be_bytes([f[csum_at], f[csum_at + 1]]);
    if proto == 17 && c == 0 {
        return;
    }
    // RFC 1624: HC' = ~(~HC + ~m + m').
    let mut sum = u32::from(!c) + u32::from(!old) + u32::from(new);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    f[csum_at..csum_at + 2].copy_from_slice(&(!(sum as u16)).to_be_bytes());
}

fn run_tcp_split(config: TcpConfig, workers: usize, through_relay: bool) -> TcpStats {
    let stop = Arc::new(AtomicBool::new(false));
    let (a, b) = memory_ports();
    let ports: Vec<Box<dyn PacketPort>> = if through_relay {
        let (c, d) = memory_ports();
        relay(b, c, stop.clone());
        vec![Box::new(a), Box::new(d)]
    } else {
        vec![Box::new(a), Box::new(b)]
    };
    let (configs, router) = config.split(workers).unwrap();
    assert_eq!(configs.len(), workers);
    let engines: Vec<TcpEngine> = configs
        .into_iter()
        .map(|c| TcpEngine::new(c).unwrap())
        .collect();
    let lanes = split_ports(ports, workers);
    let job = TcpJob::spawn_workers(
        engines,
        lanes,
        router,
        TcpRunConfig {
            duration: Some(Duration::from_secs(60)),
            stop: None,
            start_at: None,
            pinning: None,
        },
    )
    .unwrap();
    assert_eq!(job.workers(), workers);
    let stats = job.join().unwrap();
    stop.store(true, Ordering::Relaxed);
    stats
}

#[test]
fn tcp_over_four_workers_completes_every_connection() {
    let stats = run_tcp_split(tcp_config("10.0.0.10", "10.0.0.2", 203), 4, false);
    assert!(!stats.stopped, "{stats:?}");
    assert_eq!(stats.client.completed, 203, "{:?}", stats.client);
    assert_eq!(stats.server.completed, 203, "{:?}", stats.server);
    assert_eq!(stats.client.mismatched + stats.server.mismatched, 0);
    assert_eq!(stats.client.failed() + stats.server.failed(), 0);
    let per: Vec<u64> = stats.templates.iter().map(|t| t.client.completed).collect();
    assert_eq!(per.iter().sum::<u64>(), 203);
    assert!(per[1] > per[0], "weights 1:3 {per:?}");
}

#[test]
fn tcp_workers_through_a_port_rewriting_relay_over_ipv6() {
    let stats = run_tcp_split(tcp_config("fd00::10", "fd00::2", 120), 3, true);
    assert_eq!(stats.client.completed, 120, "{:?}", stats.client);
    assert_eq!(stats.server.completed, 120, "{:?}", stats.server);
    assert_eq!(stats.client.mismatched + stats.server.mismatched, 0);
}

#[test]
fn tcp_workers_through_a_port_rewriting_relay() {
    let stats = run_tcp_split(tcp_config("10.0.0.10", "10.0.0.2", 150), 2, true);
    assert_eq!(stats.client.completed, 150, "{:?}", stats.client);
    assert_eq!(stats.server.completed, 150, "{:?}", stats.server);
}

#[test]
fn split_shares_out_rates_and_limits() {
    let mut config = tcp_config("10.0.0.10", "10.0.0.2", 10);
    config.templates[1].cps = Some(300.0);
    config.templates[1].connections = 7;
    let (parts, router) = config.split(3).unwrap();
    assert_eq!(router.workers(), 3);
    let conns: Vec<u64> = parts
        .iter()
        .map(|p| p.client.as_ref().unwrap().connections)
        .collect();
    assert_eq!(conns, [4, 3, 3]);
    let tpl: Vec<u64> = parts.iter().map(|p| p.templates[1].connections).collect();
    assert_eq!(tpl, [3, 2, 2]);
    assert!(parts.iter().all(|p| p.templates[1].cps == Some(100.0)));
    let ports: Vec<_> = parts
        .iter()
        .map(|p| p.client.as_ref().unwrap().source_ports.clone())
        .collect();
    assert_eq!(ports[0].start, 1024);
    assert_eq!(ports[0].end, ports[1].start);
    assert_eq!(ports[2].end, 65535);
    assert_ne!(parts[0].options.seed, parts[1].options.seed);

    // A limit smaller than the workers cannot be shared out.
    let err = tcp_config("10.0.0.10", "10.0.0.2", 2).split(3).unwrap_err();
    assert!(err.to_string().contains("connections (2)"), "{err}");
}

#[test]
fn udp_dns_over_three_workers() {
    let dns = Arc::new(
        DnsWorkload::parse(
            &["www.lab.local A", "lab.local MX"],
            &[
                "www.lab.local A 10.0.0.80",
                "lab.local MX 10 mail.lab.local",
            ],
        )
        .unwrap(),
    );
    let mut client = UdpClientConfig::new(UdpEndpoint::new(
        0,
        mac("02:00:00:00:00:01"),
        ip("10.0.0.10"),
    ));
    client.transactions = 301;
    client.rate = 3000.0;
    let config = UdpConfig {
        templates: vec![UdpTemplate::new(UdpApp::dns(dns), sock("10.0.0.53:53"))],
        client: Some(client),
        server: Some(UdpServerConfig::new(UdpEndpoint::new(
            1,
            mac("02:00:00:00:00:02"),
            ip("10.0.0.53"),
        ))),
        options: UdpOptions::default(),
    };
    let (configs, router) = config.split(3).unwrap();
    let engines: Vec<UdpEngine> = configs
        .into_iter()
        .map(|c| UdpEngine::new(c).unwrap())
        .collect();
    let (a, b) = memory_ports();
    let lanes = split_ports(vec![Box::new(a), Box::new(b)], 3);
    let job = UdpJob::spawn_workers(
        engines,
        lanes,
        router,
        TcpRunConfig {
            duration: Some(Duration::from_secs(60)),
            stop: None,
            start_at: None,
            pinning: None,
        },
    )
    .unwrap();
    let stats = job.join().unwrap();
    assert_eq!(stats.client.sent, 301);
    assert_eq!(stats.client.answered, 301, "{:?}", stats.client);
    assert_eq!(stats.server.answered, 301, "{:?}", stats.server);
    assert_eq!(stats.client.unmatched + stats.client.timed_out, 0);
    assert_eq!(stats.client.response_time.count(), 301);
}

#[test]
fn streams_split_over_workers_send_one_stream() {
    let (tx, rx) = memory_ports();
    let cap = Arc::new(
        Capture::from_specs(
            &["eth/ipv4(src=10.0.0.1,dst=10.0.0.2)/udp(sport=1,dport=2)/raw(len=18)"],
            Duration::ZERO,
        )
        .unwrap(),
    );
    let workers: Vec<(Vec<Stream<'static>>, Box<dyn PacketSink + Send>)> = (0..3)
        .map(|k| {
            let s = Stream::new("probe", CaptureSource::new(cap.clone()).loops(0))
                .with_rate(Rate::Pps(30_000.0))
                .with_limit(Some(1000))
                .with_transform(FieldEngine::parse(["port_src=1000..1999"]).unwrap())
                .with_latency(9)
                .shard(k, 3);
            (vec![s], Box::new(tx.clone()) as Box<dyn PacketSink + Send>)
        })
        .collect();
    let rx = RxSettings {
        receiver: Box::new(PortReceiver(rx)),
        wait: Duration::from_millis(100),
    };
    let job = Job::spawn_workers(workers, RunConfig::default(), Some(rx)).unwrap();
    assert_eq!(job.workers(), 3);
    match &job.rates()[0] {
        Rate::Pps(p) => assert!((p - 30_000.0).abs() < 1e-6),
        other => panic!("{other:?}"),
    }
    job.wait(None);
    let stats = job.stats();
    assert_eq!(stats.total.packets, 1000);
    assert_eq!(stats.streams[0].tagged, 1000);
    let report = &job.flow_reports()[0];
    assert_eq!((report.tx, report.rx, report.lost), (1000, 1000, 0));
    let flow = job.rx_stats().unwrap();
    let flow = flow.flow(9).unwrap();
    assert_eq!(flow.duplicates, 0);
    assert_eq!(flow.unique(), 1000);
}

static PINNED: std::sync::Mutex<Vec<(String, usize)>> = std::sync::Mutex::new(Vec::new());

fn record_pin(cpu: usize) -> std::result::Result<(), String> {
    let name = std::thread::current().name().unwrap_or("").to_string();
    PINNED.lock().unwrap().push((name, cpu));
    Ok(())
}

fn refuse_pin(cpu: usize) -> std::result::Result<(), String> {
    Err(format!("no CPU {cpu} here"))
}

fn null_workers(n: usize) -> Vec<(Vec<Stream<'static>>, Box<dyn PacketSink + Send>)> {
    let cap = Arc::new(
        Capture::from_specs(
            &["eth/ipv4(src=10.0.0.1,dst=10.0.0.2)/udp(sport=1,dport=2)/raw(len=18)"],
            Duration::ZERO,
        )
        .unwrap(),
    );
    (0..n)
        .map(|k| {
            let s = Stream::new("pinned", CaptureSource::new(cap.clone()).loops(0))
                .with_limit(Some(100))
                .shard(k, n);
            (vec![s], Box::new(NullSink) as Box<dyn PacketSink + Send>)
        })
        .collect()
}

#[test]
fn workers_are_pinned_in_order_and_wrap() {
    let config = RunConfig {
        pinning: Some(CpuPinning {
            cpus: "6,2".parse().unwrap(),
            pin: record_pin,
        }),
        ..Default::default()
    };
    let job = Job::spawn_workers(null_workers(3), config, None).unwrap();
    assert_eq!(
        job.pinned_cpus().map(ToString::to_string).as_deref(),
        Some("6,2")
    );
    let stats = job.join().unwrap();
    assert_eq!(stats.total.packets, 100);
    let mut pinned: Vec<(String, usize)> = PINNED
        .lock()
        .unwrap()
        .iter()
        .filter(|(n, _)| n.starts_with("ferotrx-worker-"))
        .cloned()
        .collect();
    pinned.sort();
    assert_eq!(
        pinned,
        vec![
            ("ferotrx-worker-0".to_string(), 6),
            ("ferotrx-worker-1".to_string(), 2),
            ("ferotrx-worker-2".to_string(), 6),
        ]
    );
}

#[test]
fn a_worker_that_cannot_be_pinned_fails_the_run() {
    let config = RunConfig {
        pinning: Some(CpuPinning {
            cpus: "1".parse().unwrap(),
            pin: refuse_pin,
        }),
        ..Default::default()
    };
    for n in [1, 2] {
        let job = Job::spawn_workers(null_workers(n), config.clone(), None).unwrap();
        let err = job.join().unwrap_err().to_string();
        assert!(
            err.contains("cannot pin worker 0 to CPU 1: no CPU 1 here"),
            "{err}"
        );
    }
}
