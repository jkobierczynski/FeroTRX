//! Stateful UDP on a simulated network: emulated clients and servers talk
//! through a simulated NAT router that rewrites addresses and ports, moves
//! frames between VLANs, drops some and delays them.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use ferotrx_core::*;

const CLIENT_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0x0a, 0x64]);
const SERVER_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0x14, 0x35]);
const R10_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x10]);
const R20_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x20]);

fn addr(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn csum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for c in data.chunks(2) {
        sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A router between VLAN 10 (192.168.10.0/24) and VLAN 20 (192.168.20.0/24)
/// that masquerades VLAN 10 behind 192.168.20.1, for UDP.
struct UdpNat {
    out_map: HashMap<SocketAddrV4, u16>,
    in_map: HashMap<u16, SocketAddrV4>,
    next_port: u16,
    /// Drop every `drop_every`-th UDP datagram (0: none).
    drop_every: u64,
    seen: u64,
    dropped: u64,
    /// Hold datagrams from VLAN 20 back this long.
    delay: Duration,
    held: VecDeque<(Duration, Vec<u8>)>,
}

impl UdpNat {
    fn new(drop_every: u64) -> Self {
        Self {
            out_map: HashMap::new(),
            in_map: HashMap::new(),
            next_port: 61000,
            drop_every,
            seen: 0,
            dropped: 0,
            delay: Duration::ZERO,
            held: VecDeque::new(),
        }
    }

    fn arp_reply(req: &[u8], mac: MacAddr) -> Vec<u8> {
        let mut r = req.to_vec();
        r[0..6].copy_from_slice(&req[6..12]);
        r[6..12].copy_from_slice(&mac.0);
        let a = 18;
        r[a + 7] = 2;
        r[a + 18..a + 28].copy_from_slice(&req[a + 8..a + 18]);
        r[a + 8..a + 14].copy_from_slice(&mac.0);
        r[a + 14..a + 18].copy_from_slice(&req[a + 24..a + 28]);
        r
    }

    /// Takes a frame off the trunk; returns frames to put back now.
    fn forward(&mut self, mut f: Vec<u8>, now: Duration) -> Vec<Vec<u8>> {
        if f.len() < 18 || f[12..14] != [0x81, 0x00] {
            return vec![];
        }
        let vlan = u16::from_be_bytes([f[14], f[15]]) & 0xfff;
        let ethertype = u16::from_be_bytes([f[16], f[17]]);
        let a = 18;
        if ethertype == 0x0806 {
            let target = Ipv4Addr::new(f[a + 24], f[a + 25], f[a + 26], f[a + 27]);
            return match (vlan, target.octets(), f[a + 7]) {
                (10, [192, 168, 10, 1], 1) => vec![Self::arp_reply(&f, R10_MAC)],
                (20, [192, 168, 20, 1], 1) => vec![Self::arp_reply(&f, R20_MAC)],
                _ => vec![],
            };
        }
        if ethertype != 0x0800 || f[a + 9] != 17 {
            return vec![];
        }
        self.seen += 1;
        if self.drop_every > 0 && self.seen.is_multiple_of(self.drop_every) {
            self.dropped += 1;
            return vec![];
        }
        let ihl = usize::from(f[a] & 0x0f) * 4;
        let u = a + ihl;
        let src = SocketAddrV4::new(
            Ipv4Addr::new(f[a + 12], f[a + 13], f[a + 14], f[a + 15]),
            u16::from_be_bytes([f[u], f[u + 1]]),
        );
        let dst_port = u16::from_be_bytes([f[u + 2], f[u + 3]]);
        match vlan {
            10 => {
                let port = *self.out_map.entry(src).or_insert_with(|| {
                    self.next_port += 1;
                    self.in_map.insert(self.next_port, src);
                    self.next_port
                });
                f[a + 12..a + 16].copy_from_slice(&[192, 168, 20, 1]);
                f[u..u + 2].copy_from_slice(&port.to_be_bytes());
                f[14..16].copy_from_slice(&20u16.to_be_bytes());
                f[6..12].copy_from_slice(&R20_MAC.0);
                f[0..6].copy_from_slice(&SERVER_MAC.0);
            }
            20 => {
                let Some(client) = self.in_map.get(&dst_port).copied() else {
                    return vec![];
                };
                f[a + 16..a + 20].copy_from_slice(&client.ip().octets());
                f[u + 2..u + 4].copy_from_slice(&client.port().to_be_bytes());
                f[14..16].copy_from_slice(&10u16.to_be_bytes());
                f[6..12].copy_from_slice(&R10_MAC.0);
                f[0..6].copy_from_slice(&CLIENT_MAC.0);
            }
            _ => return vec![],
        }
        f[a + 8] -= 1;
        f[a + 10..a + 12].fill(0);
        let c = csum(&f[a..a + ihl]);
        f[a + 10..a + 12].copy_from_slice(&c.to_be_bytes());
        // No UDP checksum after the rewrite (allowed over IPv4).
        f[u + 6..u + 8].fill(0);
        if vlan == 20 && !self.delay.is_zero() {
            self.held.push_back((now + self.delay, f));
            return vec![];
        }
        vec![f]
    }

    fn release(&mut self, now: Duration) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while self.held.front().is_some_and(|(t, _)| *t <= now) {
            out.push(self.held.pop_front().unwrap().1);
        }
        out
    }
}

fn client_endpoint() -> UdpEndpoint {
    UdpEndpoint::new(0, CLIENT_MAC, addr("192.168.10.100"))
        .with_gateway(addr("192.168.10.1"))
        .with_vlan(10)
        .with_ip_count(4)
}

fn server_endpoint() -> UdpEndpoint {
    UdpEndpoint::new(0, SERVER_MAC, addr("192.168.20.53"))
        .with_gateway(addr("192.168.20.1"))
        .with_vlan(20)
}

fn client(transactions: u64, rate: f64) -> UdpClientConfig {
    let mut c = UdpClientConfig::new(client_endpoint());
    c.transactions = transactions;
    c.rate = rate;
    c
}

fn lab_dns() -> Arc<DnsWorkload> {
    Arc::new(
        DnsWorkload::parse(
            &[
                "www.lab.local A",
                "www.lab.local AAAA",
                "lab.local MX",
                "missing.lab.local A NXDOMAIN",
                "broken.lab.local A SERVFAIL",
            ],
            &[
                "www.lab.local CNAME web.lab.local",
                "web.lab.local A 192.168.20.80",
                "web.lab.local AAAA fd00:20::80",
                "lab.local MX 10 mail.lab.local",
                "broken.lab.local SERVFAIL",
            ],
        )
        .unwrap(),
    )
}

fn tpl(app: UdpApp, port: u16) -> UdpTemplate {
    UdpTemplate::new(
        app,
        SocketAddrV4::new("192.168.20.53".parse().unwrap(), port).into(),
    )
}

fn engine(
    templates: Vec<UdpTemplate>,
    client: Option<UdpClientConfig>,
    server: bool,
    options: UdpOptions,
) -> UdpEngine {
    UdpEngine::new(UdpConfig {
        templates,
        client,
        server: server.then(|| UdpServerConfig::new(server_endpoint())),
        options,
    })
    .unwrap()
}

/// Runs engines on a simulated clock, 1 ms per step, every port 0 on the
/// router's trunk. Returns the time taken.
fn simulate(engines: &mut [&mut UdpEngine], router: &mut UdpNat, max: Duration) -> Duration {
    let step = Duration::from_millis(1);
    let mut now = Duration::ZERO;
    let mut wire: Vec<Vec<u8>> = Vec::new();
    while now < max {
        wire.extend(router.release(now));
        for f in std::mem::take(&mut wire) {
            for e in engines.iter_mut() {
                e.handle_frame(0, &f, now);
            }
        }
        for e in engines.iter_mut() {
            e.poll(now);
            assert_eq!(e.error(), None);
            for (port, f) in e.take_output() {
                assert_eq!(port, 0);
                wire.extend(router.forward(f, now));
            }
        }
        let done = engines
            .iter()
            .all(|e| e.is_done() || e.stats().client.sent == 0);
        if done && wire.is_empty() && router.held.is_empty() {
            break;
        }
        now += step;
    }
    now
}

#[test]
fn dns_through_a_lossy_nat_router() {
    let options = UdpOptions {
        timeout: Duration::from_millis(200),
        retries: 5,
        ..Default::default()
    };
    let mut c = engine(
        vec![tpl(UdpApp::Dns(lab_dns()), 53)],
        Some(client(100, 500.0)),
        false,
        options.clone(),
    );
    let mut s = engine(vec![tpl(UdpApp::Dns(lab_dns()), 53)], None, true, options);
    let mut router = UdpNat::new(7);
    let took = simulate(&mut [&mut c, &mut s], &mut router, Duration::from_secs(60));
    let (cs, ss) = (&c.stats().client, &s.stats().server);
    assert!(c.is_done(), "not done after {took:?}: {cs:?}");
    assert_eq!(
        (cs.sent, cs.answered, cs.timed_out, cs.mismatched),
        (100, 100, 0, 0),
        "{cs:?}"
    );
    // The SERVFAIL and NXDOMAIN answers are errors, but expected ones.
    assert_eq!(cs.errors, 40, "{cs:?}");
    assert!(router.dropped > 10, "{}", router.dropped);
    assert!(cs.retries > 0 && cs.retries >= router.dropped / 2, "{cs:?}");
    // Requests asked again whose first try got through are answered again.
    assert_eq!(ss.answered, 100, "{ss:?}");
    assert_eq!(cs.response_time.count(), 100);
    assert_eq!(cs.active, 0);
    // Each transaction had its own source address and port.
    assert_eq!(router.out_map.len(), 100);
}

#[test]
fn one_engine_plays_dns_ntp_and_a_replay_by_weight() {
    let echo = UdpProgram::new(
        7,
        vec![
            UdpMessage::new(UdpRole::Client, "ping"),
            UdpMessage::new(UdpRole::Server, "pong"),
            UdpMessage::new(UdpRole::Client, "ping again"),
            UdpMessage::new(UdpRole::Server, "pong again"),
        ],
    );
    let templates = vec![
        tpl(UdpApp::Dns(lab_dns()), 53).with_weight(3),
        tpl(UdpApp::Ntp, 123),
        tpl(UdpApp::Replay(Arc::new(echo)), 7).with_name("echo"),
    ];
    let options = UdpOptions {
        clock: Duration::from_secs(1_700_000_000),
        ..Default::default()
    };
    let mut e = engine(templates, Some(client(50, 1000.0)), true, options);
    simulate(&mut [&mut e], &mut UdpNat::new(0), Duration::from_secs(10));
    let st = e.stats();
    assert!(e.is_done());
    let sent: Vec<u64> = st.templates.iter().map(|t| t.client.sent).collect();
    assert_eq!(sent, [30, 10, 10]);
    for t in &st.templates {
        assert_eq!(t.client.answered, t.client.sent, "{t:?}");
        assert_eq!(t.server.answered, t.client.sent, "{t:?}");
        assert_eq!(
            t.client.mismatched + t.client.unmatched + t.client.retries,
            0,
            "{t:?}"
        );
    }
    assert_eq!(st.templates[2].client.datagrams_tx, 20);
    assert_eq!(st.templates[2].client.datagrams_rx, 20);
    assert_eq!(st.templates[1].client.errors, 0);
}

#[test]
fn late_answers_time_out_and_count_as_unmatched() {
    let options = UdpOptions {
        timeout: Duration::from_millis(50),
        retries: 1,
        ..Default::default()
    };
    let mut c = engine(
        vec![tpl(UdpApp::Ntp, 123)],
        Some(client(10, 100.0)),
        false,
        options.clone(),
    );
    let mut s = engine(vec![tpl(UdpApp::Ntp, 123)], None, true, options);
    let mut router = UdpNat::new(0);
    router.delay = Duration::from_millis(300);
    simulate(&mut [&mut c, &mut s], &mut router, Duration::from_secs(10));
    let cs = &c.stats().client;
    assert_eq!((cs.sent, cs.answered, cs.timed_out), (10, 0, 10), "{cs:?}");
    assert_eq!(cs.retries, 10);
    // Two answers each (to the request and to its repeat), all too late.
    assert_eq!(cs.unmatched, 20, "{cs:?}");
    assert_eq!(cs.active, 0);
    let ss = &s.stats().server;
    assert_eq!((ss.sent, ss.answered, ss.retries), (10, 10, 10), "{ss:?}");
}

#[test]
fn nobody_answering_times_out() {
    let options = UdpOptions {
        timeout: Duration::from_millis(100),
        retries: 2,
        ..Default::default()
    };
    let mut c = engine(
        vec![tpl(UdpApp::Dns(lab_dns()), 53)],
        Some(client(3, 100.0)),
        false,
        options,
    );
    let took = simulate(&mut [&mut c], &mut UdpNat::new(0), Duration::from_secs(10));
    let cs = &c.stats().client;
    assert_eq!(
        (cs.sent, cs.timed_out, cs.retries, cs.datagrams_tx),
        (3, 3, 6, 9),
        "{cs:?}"
    );
    assert!(
        took >= Duration::from_millis(300) && took < Duration::from_millis(400),
        "{took:?}"
    );
    assert!(c.is_done());
}

#[test]
fn notices_answers_that_differ() {
    // The client expects other records than the server has.
    let client_dns =
        Arc::new(DnsWorkload::parse(&["www.lab.local A NXDOMAIN"], &[] as &[&str]).unwrap());
    let mut c = engine(
        vec![tpl(UdpApp::Dns(client_dns), 53)],
        Some(client(4, 100.0)),
        false,
        UdpOptions::default(),
    );
    let mut s = engine(
        vec![tpl(UdpApp::Dns(lab_dns()), 53)],
        None,
        true,
        UdpOptions::default(),
    );
    // And a replay whose server answers something else.
    let say = |answer: &str| {
        Arc::new(UdpProgram::new(
            9,
            vec![
                UdpMessage::new(UdpRole::Client, "hello"),
                UdpMessage::new(UdpRole::Server, answer.to_string()),
            ],
        ))
    };
    let mut rc = engine(
        vec![tpl(UdpApp::Replay(say("hi")), 9)],
        Some(client(2, 100.0)),
        false,
        UdpOptions::default(),
    );
    let mut rs = engine(
        vec![tpl(UdpApp::Replay(say("bye")), 9)],
        None,
        true,
        UdpOptions::default(),
    );
    simulate(
        &mut [&mut c, &mut s],
        &mut UdpNat::new(0),
        Duration::from_secs(5),
    );
    simulate(
        &mut [&mut rc, &mut rs],
        &mut UdpNat::new(0),
        Duration::from_secs(5),
    );
    let cs = &c.stats().client;
    assert_eq!((cs.answered, cs.mismatched, cs.errors), (4, 4, 0), "{cs:?}");
    let rcs = &rc.stats().client;
    assert_eq!((rcs.answered, rcs.mismatched), (2, 2), "{rcs:?}");
}

#[test]
fn server_counts_strays_and_bad_requests() {
    let mut s = engine(
        vec![tpl(UdpApp::Dns(lab_dns()), 53)],
        None,
        true,
        UdpOptions::default(),
    );
    let mut c = engine(
        vec![
            tpl(UdpApp::Ntp, 53).with_name("not-dns"),
            tpl(UdpApp::Ntp, 4444),
        ],
        Some(client(4, 100.0)),
        false,
        UdpOptions {
            timeout: Duration::from_millis(20),
            retries: 0,
            ..Default::default()
        },
    );
    simulate(
        &mut [&mut c, &mut s],
        &mut UdpNat::new(0),
        Duration::from_secs(5),
    );
    let ss = &s.stats().server;
    // Two NTP requests to the DNS port, two to a closed port.
    assert_eq!((ss.sent, ss.unmatched), (0, 4), "{ss:?}");
    assert_eq!(c.stats().client.timed_out, 4);
}

#[test]
fn rates_concurrency_and_think_time() {
    let dns = UdpApp::Dns(lab_dns());
    let templates = vec![
        tpl(dns.clone(), 53)
            .with_rate(100.0)
            .with_transactions(20)
            .with_think_time(Duration::from_millis(30)),
        tpl(UdpApp::Ntp, 123)
            .with_concurrency(1)
            .with_transactions(5),
    ];
    let mut e = engine(
        templates,
        Some({
            let mut c = client(0, 1000.0);
            c.transactions = 0;
            c
        }),
        true,
        UdpOptions::default(),
    );
    let took = simulate(&mut [&mut e], &mut UdpNat::new(0), Duration::from_secs(5));
    let st = e.stats();
    assert!(e.is_done(), "{st:?}");
    assert_eq!(st.templates[0].client.answered, 20);
    assert_eq!(st.templates[1].client.answered, 5);
    // 20 at 100 per second: about 190 ms, plus the last answer's 30 ms.
    assert!(
        took >= Duration::from_millis(220) && took < Duration::from_millis(260),
        "{took:?}"
    );
    let rt = &st.templates[0].client.response_time;
    assert!(
        rt.min().unwrap() >= Duration::from_millis(30),
        "{:?}",
        rt.min()
    );
}

#[test]
fn keeps_capture_timing() {
    let cap = Capture::from_path(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/dns-lookups.pcap"
    ))
    .unwrap();
    let program = Arc::new(UdpProgram::from_capture(&cap, None).unwrap());
    let run = |keep_timing| {
        let mut e = engine(
            vec![tpl(UdpApp::Replay(program.clone()), 53)],
            Some(client(1, 10.0)),
            true,
            UdpOptions {
                keep_timing,
                ..Default::default()
            },
        );
        simulate(&mut [&mut e], &mut UdpNat::new(0), Duration::from_secs(5));
        assert_eq!(e.stats().client.answered, 1);
        assert_eq!(e.stats().client.mismatched, 0);
        e.stats().client.response_time.min().unwrap()
    };
    // Two 1 ms steps of the simulation, there and back.
    assert_eq!(run(false), Duration::from_millis(2));
    // The capture's server answered after 2 ms.
    assert_eq!(run(true), Duration::from_millis(4));
}

#[test]
fn rejects_what_cannot_work() {
    let bad = |templates: Vec<UdpTemplate>, client: Option<UdpClientConfig>| {
        UdpEngine::new(UdpConfig {
            templates,
            client,
            server: Some(UdpServerConfig::new(server_endpoint())),
            options: UdpOptions::default(),
        })
        .unwrap_err()
        .to_string()
    };
    let e = bad(vec![tpl(UdpApp::Ntp, 123), tpl(UdpApp::Ntp, 123)], None);
    assert!(e.contains("both listen on port 123"), "{e}");
    let server_first = UdpProgram::new(5, vec![UdpMessage::new(UdpRole::Server, "x")]);
    let e = bad(vec![tpl(UdpApp::Replay(Arc::new(server_first)), 5)], None);
    assert!(e.contains("client must send first"), "{e}");
    let empty = Arc::new(DnsWorkload::default());
    let e = bad(vec![tpl(UdpApp::Dns(empty), 53)], Some(client(1, 1.0)));
    assert!(e.contains("no queries"), "{e}");
    let v6 = UdpTemplate::new(UdpApp::Ntp, "[fd00::1]:123".parse().unwrap());
    let e = bad(vec![v6], Some(client(1, 1.0)));
    assert!(e.contains("IPv6"), "{e}");
}
