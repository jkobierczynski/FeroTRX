//! Stateful TCP on a simulated network: emulated clients and servers talk
//! through a simulated NAT router that rewrites addresses and ports, moves
//! frames between VLANs and drops some of them.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use ferotrx_core::*;

const CLIENT_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0x0a, 0x64]);
const SERVER_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0x14, 0x32]);
const R10_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x10]);
const R20_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x20]);

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

/// A router between VLAN 10 (192.168.10.0/24) and VLAN 20 (192.168.20.0/24)
/// that masquerades VLAN 10 behind its VLAN 20 address 192.168.20.1, like
/// Jurgen's lab router. Frames are tagged on both sides.
struct NatRouter {
    /// (client ip, client port) -> router port, and back.
    out_map: HashMap<SocketAddrV4, u16>,
    in_map: HashMap<u16, SocketAddrV4>,
    next_port: u16,
    /// Drop every `drop_every`-th TCP frame (0: none).
    drop_every: u64,
    seen: u64,
    dropped: u64,
}

fn csum(data: &[u8], mut sum: u32) -> u16 {
    for c in data.chunks(2) {
        sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn fix(frame: &mut [u8]) {
    let ip = 18;
    frame[ip + 10..ip + 12].fill(0);
    let s = csum(&frame[ip..ip + 20], 0);
    frame[ip + 10..ip + 12].copy_from_slice(&s.to_be_bytes());
    let total = usize::from(u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]));
    let tcp = ip + 20;
    frame[tcp + 16..tcp + 18].fill(0);
    let mut pseudo = 0u32;
    for c in frame[ip + 12..ip + 20].chunks(2) {
        pseudo += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    pseudo += 6 + (total - 20) as u32;
    let s = csum(&frame[tcp..ip + total], pseudo);
    frame[tcp + 16..tcp + 18].copy_from_slice(&s.to_be_bytes());
}

fn vlan_of(f: &[u8]) -> Option<u16> {
    (f.len() > 18 && f[12..14] == [0x81, 0x00]).then(|| u16::from_be_bytes([f[14], f[15]]) & 0xfff)
}

fn arp_reply(req: &[u8], my_mac: MacAddr) -> Vec<u8> {
    let mut r = req.to_vec();
    r[0..6].copy_from_slice(&req[6..12]);
    r[6..12].copy_from_slice(&my_mac.0);
    let a = 18;
    r[a + 7] = 2;
    r[a + 18..a + 24].copy_from_slice(&req[a + 8..a + 14]);
    r[a + 24..a + 28].copy_from_slice(&req[a + 14..a + 18]);
    r[a + 8..a + 14].copy_from_slice(&my_mac.0);
    r[a + 14..a + 18].copy_from_slice(&req[a + 24..a + 28]);
    r
}

impl NatRouter {
    fn new(drop_every: u64) -> Self {
        Self {
            out_map: HashMap::new(),
            in_map: HashMap::new(),
            next_port: 61000,
            drop_every,
            seen: 0,
            dropped: 0,
        }
    }

    /// Takes a frame from VLAN `vlan`, returns frames to put on the wire.
    fn route(&mut self, mut f: Vec<u8>) -> Option<Vec<u8>> {
        let vlan = vlan_of(&f)?;
        let ethertype = u16::from_be_bytes([f[16], f[17]]);
        if ethertype == 0x0806 {
            let target = Ipv4Addr::new(f[18 + 24], f[18 + 25], f[18 + 26], f[18 + 27]);
            let op = f[18 + 7];
            return match (vlan, target, op) {
                (10, t, 1) if t == ip("192.168.10.1") => Some(arp_reply(&f, R10_MAC)),
                (20, t, 1) if t == ip("192.168.20.1") => Some(arp_reply(&f, R20_MAC)),
                _ => None,
            };
        }
        if ethertype != 0x0800 || f[18 + 9] != 6 {
            return None;
        }
        self.seen += 1;
        if self.drop_every > 0 && self.seen % self.drop_every == 0 {
            self.dropped += 1;
            return None;
        }
        let a = 18;
        let src = Ipv4Addr::new(f[a + 12], f[a + 13], f[a + 14], f[a + 15]);
        let dst = Ipv4Addr::new(f[a + 16], f[a + 17], f[a + 18], f[a + 19]);
        let t = a + 20;
        let sport = u16::from_be_bytes([f[t], f[t + 1]]);
        let dport = u16::from_be_bytes([f[t + 2], f[t + 3]]);
        f[a + 8] -= 1; // TTL
        match vlan {
            10 if f[0..6] == R10_MAC.0 && dst.octets()[2] == 20 => {
                let key = SocketAddrV4::new(src, sport);
                let port = *self.out_map.entry(key).or_insert_with(|| {
                    self.next_port += 1;
                    self.in_map.insert(self.next_port, key);
                    self.next_port
                });
                f[a + 12..a + 16].copy_from_slice(&ip("192.168.20.1").octets());
                f[t..t + 2].copy_from_slice(&port.to_be_bytes());
                f[0..6].copy_from_slice(&SERVER_MAC.0);
                f[6..12].copy_from_slice(&R20_MAC.0);
                f[14..16].copy_from_slice(&20u16.to_be_bytes());
            }
            20 if f[0..6] == R20_MAC.0 && dst == ip("192.168.20.1") => {
                let back = *self.in_map.get(&dport)?;
                f[a + 16..a + 20].copy_from_slice(&back.ip().octets());
                f[t + 2..t + 4].copy_from_slice(&back.port().to_be_bytes());
                f[0..6].copy_from_slice(&CLIENT_MAC.0);
                f[6..12].copy_from_slice(&R10_MAC.0);
                f[14..16].copy_from_slice(&10u16.to_be_bytes());
            }
            _ => return None,
        }
        fix(&mut f);
        Some(f)
    }
}

fn client_endpoint() -> TcpEndpoint {
    TcpEndpoint::new(0, CLIENT_MAC, ip("192.168.10.100"))
        .with_gateway(ip("192.168.10.1"))
        .with_vlan(10)
        .with_ip_count(3)
}

fn server_endpoint() -> TcpEndpoint {
    TcpEndpoint::new(0, SERVER_MAC, ip("192.168.20.50"))
        .with_gateway(ip("192.168.20.1"))
        .with_vlan(20)
}

/// A request and a response of `size` bytes (many segments), server closes.
fn web_program(size: usize) -> TcpProgram {
    let body: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let mut resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n").into_bytes();
    resp.extend(body);
    TcpProgram::new(
        80,
        vec![
            TcpMessage::new(TcpRole::Client, "GET /big HTTP/1.1\r\nHost: lab\r\n\r\n"),
            TcpMessage::new(TcpRole::Server, resp),
            TcpMessage::new(TcpRole::Client, "GET /next HTTP/1.1\r\n\r\n"),
            TcpMessage::new(TcpRole::Server, "HTTP/1.1 204 No Content\r\n\r\n"),
        ],
    )
    .with_closer(TcpRole::Server)
}

fn client(connections: u64, cps: f64, concurrency: usize) -> TcpClientConfig {
    let mut c = TcpClientConfig::new(client_endpoint(), "192.168.20.50:80".parse().unwrap());
    c.connections = connections;
    c.cps = cps;
    c.concurrency = concurrency;
    c
}

/// Runs engines on a simulated clock, 1 ms per step. Every engine's port 0
/// is on the router's trunk. Returns the steps taken.
fn simulate(engines: &mut [&mut TcpEngine], router: &mut NatRouter, max: Duration) -> Duration {
    let step = Duration::from_millis(1);
    let mut now = Duration::ZERO;
    let mut wire: Vec<Vec<u8>> = Vec::new();
    while now < max {
        for f in std::mem::take(&mut wire) {
            // Every engine sees every frame on the trunk, as on a shared segment.
            for e in engines.iter_mut() {
                e.handle_frame(0, &f, now);
            }
        }
        let mut done = true;
        for e in engines.iter_mut() {
            e.poll(now);
            assert_eq!(e.error(), None);
            for (port, f) in e.take_output() {
                assert_eq!(port, 0);
                if let Some(r) = router.route(f) {
                    wire.push(r);
                }
            }
        }
        for e in engines.iter() {
            done &= e.is_done() || e.stats().client.started == 0;
        }
        if done && wire.is_empty() {
            break;
        }
        now += step;
    }
    now
}

#[test]
fn two_engines_through_a_lossy_nat_router() {
    let program = Arc::new(web_program(100_000));
    let mut client = TcpEngine::new(TcpConfig {
        program: program.clone(),
        client: Some(client(20, 200.0, 5)),
        server: None,
        options: TcpOptions::default(),
    })
    .unwrap();
    let mut server = TcpEngine::new(TcpConfig {
        program,
        client: None,
        server: Some(TcpServerConfig {
            endpoint: server_endpoint(),
            port: 80,
        }),
        options: TcpOptions::default(),
    })
    .unwrap();
    let mut router = NatRouter::new(29);
    let took = simulate(
        &mut [&mut client, &mut server],
        &mut router,
        Duration::from_secs(120),
    );
    let (c, s) = (&client.stats().client, &server.stats().server);
    assert!(client.is_done(), "client not done after {took:?}: {c:?}");
    assert_eq!(
        (c.started, c.completed, c.mismatched, c.failed()),
        (20, 20, 0, 0),
        "{c:?}"
    );
    assert_eq!((s.started, s.completed, s.mismatched), (20, 20, 0), "{s:?}");
    assert!(router.dropped > 10, "{}", router.dropped);
    assert!(c.retransmits + s.retransmits > 0);
    assert_eq!(s.payload_tx, 20 * program_bytes(TcpRole::Server));
    assert_eq!(c.payload_rx, s.payload_tx);
    // Three client addresses in turn, each port mapped by the router.
    assert_eq!(router.out_map.len(), 20);
    assert_eq!(
        router
            .out_map
            .keys()
            .map(|k| *k.ip())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3
    );
}

fn program_bytes(role: TcpRole) -> u64 {
    web_program(100_000).bytes(role)
}

#[test]
fn one_engine_plays_both_ends_on_a_trunk() {
    let program = Arc::new(TcpProgram::from_capture(&session_capture(), None).unwrap());
    let mut engine = TcpEngine::new(TcpConfig {
        program,
        client: Some(client(50, 1000.0, 0)),
        server: Some(TcpServerConfig {
            endpoint: server_endpoint(),
            port: 80,
        }),
        options: TcpOptions::default(),
    })
    .unwrap();
    let mut router = NatRouter::new(0);
    simulate(&mut [&mut engine], &mut router, Duration::from_secs(30));
    let st = engine.stats();
    assert!(engine.is_done());
    assert_eq!(
        (st.client.completed, st.server.completed),
        (50, 50),
        "{st:?}"
    );
    assert_eq!(st.client.mismatched + st.server.mismatched, 0);
    assert_eq!(st.client.retransmits + st.server.retransmits, 0);
}

/// The sample web capture: only the client side was captured, so the server's
/// 4000 bytes are inferred.
fn session_capture() -> Capture {
    Capture::from_path(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/web.pcap"
    ))
    .unwrap()
}

#[test]
fn closed_port_is_reset() {
    let program = Arc::new(web_program(10));
    let mut c = client(3, 100.0, 0);
    c.connect = "192.168.20.50:81".parse().unwrap();
    let mut engine = TcpEngine::new(TcpConfig {
        program,
        client: Some(c),
        server: Some(TcpServerConfig {
            endpoint: server_endpoint(),
            port: 80,
        }),
        options: TcpOptions::default(),
    })
    .unwrap();
    simulate(
        &mut [&mut engine],
        &mut NatRouter::new(0),
        Duration::from_secs(10),
    );
    let st = &engine.stats().client;
    assert!(engine.is_done());
    assert_eq!((st.reset, st.completed, st.active), (3, 0, 0), "{st:?}");
}

#[test]
fn gives_up_when_nobody_answers() {
    let mut engine = TcpEngine::new(TcpConfig {
        program: Arc::new(web_program(10)),
        client: Some(client(2, 100.0, 0)),
        server: None,
        options: TcpOptions {
            max_retries: 2,
            ..Default::default()
        },
    })
    .unwrap();
    simulate(
        &mut [&mut engine],
        &mut NatRouter::new(0),
        Duration::from_secs(30),
    );
    let st = &engine.stats().client;
    assert!(engine.is_done());
    assert_eq!(
        (st.timed_out, st.retransmits, st.active),
        (2, 4, 0),
        "{st:?}"
    );
}

#[test]
fn reports_a_missing_gateway() {
    let mut c = client(1, 1.0, 0);
    c.endpoint.gateway = Some(ip("192.168.10.254"));
    let mut engine = TcpEngine::new(TcpConfig {
        program: Arc::new(web_program(10)),
        client: Some(c),
        server: None,
        options: TcpOptions::default(),
    })
    .unwrap();
    let mut router = NatRouter::new(0);
    let mut now = Duration::ZERO;
    while engine.error().is_none() && now < Duration::from_secs(10) {
        engine.poll(now);
        for (_, f) in engine.take_output() {
            assert!(router.route(f).is_none());
        }
        now += Duration::from_millis(10);
    }
    let err = engine.error().expect("ARP fails");
    assert!(err.contains("192.168.10.254"), "{err}");
    assert!(now >= Duration::from_secs(5));
}

#[test]
fn notices_bytes_that_differ() {
    let mut other = web_program(100);
    other.messages[1].data[20] ^= 0xff;
    let mut client_engine = TcpEngine::new(TcpConfig {
        program: Arc::new(web_program(100)),
        client: Some(client(4, 100.0, 0)),
        server: None,
        options: TcpOptions::default(),
    })
    .unwrap();
    let mut server = TcpEngine::new(TcpConfig {
        program: Arc::new(other),
        client: None,
        server: Some(TcpServerConfig {
            endpoint: server_endpoint(),
            port: 80,
        }),
        options: TcpOptions::default(),
    })
    .unwrap();
    simulate(
        &mut [&mut client_engine, &mut server],
        &mut NatRouter::new(0),
        Duration::from_secs(10),
    );
    let st = &client_engine.stats().client;
    assert_eq!((st.completed, st.mismatched), (4, 4), "{st:?}");
    assert_eq!(server.stats().server.mismatched, 0);
}

#[test]
fn answers_arp_and_ping() {
    let mut engine = TcpEngine::new(TcpConfig {
        program: Arc::new(web_program(10)),
        client: None,
        server: Some(TcpServerConfig {
            endpoint: server_endpoint(),
            port: 80,
        }),
        options: TcpOptions::default(),
    })
    .unwrap();
    let spec = "eth(src=02:00:00:00:00:20,dst=ff:ff:ff:ff:ff:ff)/vlan(id=20)/arp(op=1,sip=192.168.20.1,tip=192.168.20.50,smac=02:00:00:00:00:20)";
    let ping = "eth(src=02:00:00:00:00:20,dst=02:00:00:00:14:32)/vlan(id=20)/ipv4(src=192.168.20.1,dst=192.168.20.50)/icmp(id=7,seq=1)";
    let cap = Capture::from_specs(&[spec, ping], Duration::ZERO).unwrap();
    for p in &cap.packets {
        engine.handle_frame(0, &p.data, Duration::ZERO);
    }
    let out = engine.take_output();
    assert_eq!(out.len(), 2);
    let arp = ferotrx_packet::decode(1, &out[0].1);
    assert!(
        arp.info.contains("192.168.20.50 is at 02:00:00:00:14:32"),
        "{}",
        arp.info
    );
    let echo = ferotrx_packet::decode(1, &out[1].1);
    assert!(echo.info.contains("reply"), "{}", echo.info);
    assert!(echo.problems.is_empty(), "{:?}", echo.problems);
}

#[test]
fn says_when_arp_replies_come_back_untagged() {
    // The router answers on VLAN 10, but the switch strips the tag.
    let mut engine = TcpEngine::new(TcpConfig {
        program: Arc::new(web_program(10)),
        client: Some(client(1, 1.0, 0)),
        server: None,
        options: TcpOptions::default(),
    })
    .unwrap();
    let mut router = NatRouter::new(0);
    let mut now = Duration::ZERO;
    while engine.error().is_none() && now < Duration::from_secs(10) {
        engine.poll(now);
        for (_, f) in engine.take_output() {
            if let Some(mut reply) = router.route(f) {
                reply.drain(12..16);
                engine.handle_frame(0, &reply, now);
            }
        }
        now += Duration::from_millis(10);
    }
    let err = engine.error().expect("ARP fails");
    assert!(err.contains("arrive untagged"), "{err}");
}
