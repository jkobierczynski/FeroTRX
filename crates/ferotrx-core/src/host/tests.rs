//! Host emulation against simulated DHCP and DHCPv6 servers, routers and
//! multicast queriers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use super::wire as hw;
use super::*;
use crate::tcp::wire::{self, Path};
use crate::{
    MacAddr, PortEngine, TcpClientConfig, TcpConfig, TcpEndpoint, TcpEngine, TcpMessage,
    TcpOptions, TcpProgram, TcpRole, TcpServerConfig, TcpTemplate,
};

const SERVER_MAC: MacAddr = MacAddr([0x02, 0x99, 0, 0, 0, 1]);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);

fn mac(n: u8) -> MacAddr {
    MacAddr([0x02, 0xdc, 0, 0, 0, n])
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// A DHCPv4 client message, as a server sees it.
struct Request {
    kind: u8,
    xid: u32,
    chaddr: MacAddr,
    ciaddr: Ipv4Addr,
    requested: Option<Ipv4Addr>,
    hostname: Option<String>,
    dst: IpAddr,
    dst_mac: MacAddr,
}

fn parse_request(frame: &[u8]) -> Option<Request> {
    let link = wire::parse_link(frame)?;
    let ip = wire::parse_ip(&frame[link.payload..], true)?;
    let udp = wire::parse_udp(&ip, true)?;
    if udp.dport != 67 {
        return None;
    }
    let p = udp.data;
    if p[0] != 1 {
        return None;
    }
    let mut r = Request {
        kind: 0,
        xid: u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
        chaddr: MacAddr([p[28], p[29], p[30], p[31], p[32], p[33]]),
        ciaddr: Ipv4Addr::new(p[12], p[13], p[14], p[15]),
        requested: None,
        hostname: None,
        dst: ip.dst,
        dst_mac: link.dst,
    };
    let mut o = &p[240..];
    while let Some(&code) = o.first() {
        if code == 255 {
            break;
        }
        if code == 0 {
            o = &o[1..];
            continue;
        }
        let len = usize::from(o[1]);
        let v = &o[2..2 + len];
        match code {
            53 => r.kind = v[0],
            50 => r.requested = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            12 => r.hostname = Some(String::from_utf8_lossy(v).into_owned()),
            _ => {}
        }
        o = &o[2 + len..];
    }
    Some(r)
}

/// A DHCPv4 server: leases 10.77.0.100 and up, `lease` seconds.
struct DhcpServer {
    lease: u32,
    next: u8,
    leases: Vec<(MacAddr, Ipv4Addr)>,
    seen: Vec<Request>,
    /// Answer requests with a NAK.
    nak: bool,
}

impl DhcpServer {
    fn new(lease: u32) -> Self {
        Self {
            lease,
            next: 100,
            leases: Vec::new(),
            seen: Vec::new(),
            nak: false,
        }
    }

    fn address(&mut self, mac: MacAddr) -> Ipv4Addr {
        if let Some((_, ip)) = self.leases.iter().find(|(m, _)| *m == mac) {
            return *ip;
        }
        let ip = Ipv4Addr::new(10, 77, 0, self.next);
        self.next += 1;
        self.leases.push((mac, ip));
        ip
    }

    fn answer(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        let r = parse_request(frame)?;
        let reply = match r.kind {
            hw::DHCPDISCOVER => hw::DHCPOFFER,
            hw::DHCPREQUEST if self.nak => hw::DHCPNAK,
            hw::DHCPREQUEST => hw::DHCPACK,
            _ => {
                self.seen.push(r);
                return None;
            }
        };
        let yiaddr = if reply == hw::DHCPNAK {
            Ipv4Addr::UNSPECIFIED
        } else {
            self.address(r.chaddr)
        };
        let mut p = vec![2, 1, 6, 0];
        p.extend_from_slice(&r.xid.to_be_bytes());
        p.extend_from_slice(&[0; 8]);
        p.extend_from_slice(&yiaddr.octets());
        p.extend_from_slice(&[0; 8]);
        p.extend_from_slice(&r.chaddr.0);
        p.extend_from_slice(&[0; 10 + 192]);
        p.extend_from_slice(&[99, 130, 83, 99, 53, 1, reply, 54, 4]);
        p.extend_from_slice(&SERVER_IP.octets());
        p.extend_from_slice(&[
            1, 4, 255, 255, 255, 0, 3, 4, 10, 77, 0, 1, 6, 4, 10, 77, 0, 53,
        ]);
        p.extend_from_slice(&[51, 4]);
        p.extend_from_slice(&self.lease.to_be_bytes());
        p.push(255);
        let path = Path {
            src_mac: SERVER_MAC,
            dst_mac: r.chaddr,
            vlan: None,
            src: SERVER_IP.into(),
            dst: if yiaddr.is_unspecified() {
                Ipv4Addr::BROADCAST.into()
            } else {
                yiaddr.into()
            },
        };
        self.seen.push(r);
        Some(wire::udp_frame(&path, 67, 68, &p, 1))
    }
}

/// Runs `engine` for `until`, in steps of `step`; `fabric` gets each frame
/// it sends and returns what comes back, as (port, frame).
fn drive<E: PortEngine>(
    engine: &mut E,
    from: Duration,
    until: Duration,
    step: Duration,
    mut fabric: impl FnMut(usize, &[u8], Duration) -> Vec<(usize, Vec<u8>)>,
) {
    let mut now = from;
    while now < until {
        engine.poll(now);
        let out = engine.take_output();
        for (p, f) in out {
            for (q, g) in fabric(p, &f, now) {
                engine.handle_frame(q, &g, now);
            }
        }
        now += step;
    }
}

fn dhcp_host(n: u8) -> HostConfig {
    HostConfig::new(0, mac(n)).with_ipv4(Ipv4Mode::Dhcp)
}

#[test]
fn dhcp_clients_get_renew_and_release_their_leases() {
    let mut hosts = vec![dhcp_host(1), dhcp_host(2)];
    hosts[0].hostname = Some("lab-1".into());
    hosts[1].announce = true;
    let mut engine = HostEngine::new(hosts, HostOptions::default()).unwrap();
    let mut server = DhcpServer::new(10);
    let mut garps = Vec::new();
    drive(&mut engine, ms(0), ms(3000), ms(10), |p, f, _| {
        if let Some(arp) = wire::parse_link(f)
            .filter(|l| l.ethertype == wire::ETHERTYPE_ARP)
            .and_then(|l| wire::parse_arp(&f[l.payload..]))
        {
            garps.push(arp);
        }
        server.answer(f).map(|r| (p, r)).into_iter().collect()
    });
    assert!(engine.all_ready());
    let s = engine.statuses();
    let leased = |m: MacAddr| server.leases.iter().find(|(x, _)| *x == m).unwrap().1;
    let (ip1, ip2) = (leased(mac(1)), leased(mac(2)));
    let a = s[0].ipv4.as_ref().unwrap();
    assert_eq!(a.ip, IpAddr::V4(ip1));
    assert_eq!(a.prefix, 24);
    assert_eq!(a.gateway, Some(IpAddr::V4(SERVER_IP)));
    assert_eq!(a.dns, vec![IpAddr::V4(Ipv4Addr::new(10, 77, 0, 53))]);
    assert_eq!(a.lease, Some(Duration::from_secs(10)));
    assert_eq!(a.source, AddressSource::Dhcp);
    assert_eq!(s[1].ipv4.as_ref().unwrap().ip, IpAddr::V4(ip2));
    assert!(s[0].ready_after.unwrap() < ms(500));
    // Discover and request, each broadcast.
    let first: Vec<_> = server.seen.iter().filter(|r| r.chaddr == mac(1)).collect();
    assert_eq!(
        first.iter().map(|r| r.kind).collect::<Vec<_>>(),
        vec![hw::DHCPDISCOVER, hw::DHCPREQUEST]
    );
    assert_eq!(first[1].requested, Some(ip1));
    assert_eq!(first[0].hostname.as_deref(), Some("lab-1"));
    assert!(first.iter().all(|r| r.dst_mac == wire::BROADCAST));
    // Only the second host announces: two gratuitous ARPs for its address.
    assert_eq!(garps.len(), 2);
    assert!(garps
        .iter()
        .all(|a| a.sender_ip == ip2 && a.target_ip == ip2 && a.sender_mac == mac(2)));

    // T1 is at 5 s: a unicast request to the server, acknowledged.
    server.seen.clear();
    drive(&mut engine, ms(3000), ms(6000), ms(10), |p, f, _| {
        server.answer(f).map(|r| (p, r)).into_iter().collect()
    });
    let renew: Vec<_> = server.seen.iter().filter(|r| r.chaddr == mac(1)).collect();
    assert_eq!(renew.len(), 1);
    assert_eq!(renew[0].kind, hw::DHCPREQUEST);
    assert_eq!(renew[0].ciaddr, ip1);
    assert_eq!(renew[0].dst, IpAddr::V4(SERVER_IP));
    assert_eq!(renew[0].dst_mac, SERVER_MAC);
    assert_eq!(renew[0].requested, None);
    let s = engine.statuses();
    assert_eq!(s[0].ipv4.as_ref().unwrap().renewals, 1);
    assert_eq!(s[0].state, HostState::Ready);

    // The end releases both leases.
    server.seen.clear();
    engine.finish();
    for (_, f) in engine.take_output() {
        server.answer(&f);
    }
    assert_eq!(server.seen.len(), 2);
    assert!(server
        .seen
        .iter()
        .all(|r| r.kind == hw::DHCPRELEASE && r.dst == IpAddr::V4(SERVER_IP)));
}

#[test]
fn a_lease_that_is_not_renewed_runs_out() {
    let mut engine = HostEngine::new(vec![dhcp_host(1)], HostOptions::for_endpoints()).unwrap();
    let mut server = DhcpServer::new(4);
    drive(&mut engine, ms(0), ms(1000), ms(10), |p, f, _| {
        server.answer(f).map(|r| (p, r)).into_iter().collect()
    });
    assert!(engine.all_ready());
    // The server goes away: renewing, rebinding, then the lease ends.
    let mut asked = 0;
    drive(&mut engine, ms(1000), ms(6000), ms(10), |_, f, _| {
        asked += usize::from(parse_request(f).is_some());
        Vec::new()
    });
    assert!(asked >= 2, "renew and rebind: {asked}");
    let e = engine.error().unwrap();
    assert!(e.contains("lease ran out"), "{e}");
}

#[test]
fn no_dhcp_server_fails_with_a_hint() {
    let options = HostOptions {
        setup_timeout: Duration::from_secs(5),
        ..HostOptions::default()
    };
    let mut engine = HostEngine::new(vec![dhcp_host(1), dhcp_host(2)], options).unwrap();
    let mut discovers = 0;
    drive(&mut engine, ms(0), ms(6000), ms(10), |_, f, _| {
        discovers += usize::from(parse_request(f).is_some_and(|r| r.kind == hw::DHCPDISCOVER));
        Vec::new()
    });
    // 0, 1, 3 s (doubling): retransmissions back off.
    assert_eq!(discovers, 2 * 3);
    assert!(
        engine.error().is_none(),
        "not fail_fast: the hosts fail, the run goes on"
    );
    let s = engine.statuses();
    assert!(s.iter().all(|h| h.state == HostState::Failed));
    assert!(s[0].error.as_deref().unwrap().contains("no DHCP offer"));
    assert!(PortEngine::is_done(&engine));
}

#[test]
fn a_nak_starts_over() {
    let mut engine = HostEngine::new(vec![dhcp_host(1)], HostOptions::default()).unwrap();
    let mut server = DhcpServer::new(60);
    server.nak = true;
    drive(&mut engine, ms(0), ms(1500), ms(10), |p, f, _| {
        server.answer(f).map(|r| (p, r)).into_iter().collect()
    });
    assert!(!engine.all_ready());
    assert!(engine.statuses()[0].counters.dhcp_naks >= 1);
    server.nak = false;
    drive(&mut engine, ms(1500), ms(5000), ms(10), |p, f, _| {
        server.answer(f).map(|r| (p, r)).into_iter().collect()
    });
    assert!(engine.all_ready());
}

/// A router on the link: answers solicitations with an advertisement of
/// `prefix`, flags `managed`, and duplicate checks with `taken`.
struct Router {
    mac: MacAddr,
    prefix: (Ipv6Addr, u8),
    managed: bool,
    taken: Option<Ipv6Addr>,
    probes: Vec<Ipv6Addr>,
}

impl Router {
    fn new(prefix: &str) -> Self {
        Self {
            mac: MacAddr([0x02, 0x99, 0, 0, 0, 6]),
            prefix: (prefix.parse().unwrap(), 64),
            managed: false,
            taken: None,
            probes: Vec::new(),
        }
    }

    fn ll(&self) -> Ipv6Addr {
        hw::link_local(self.mac)
    }

    fn answer(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        let link = wire::parse_link(frame)?;
        let ip = wire::parse_ip(&frame[link.payload..], true)?;
        if hw::is_rs(&ip) {
            let prefixes = [self.prefix];
            return Some(hw::router_advert(
                self.mac,
                None,
                self.ll(),
                &hw::AdvertOut {
                    managed: self.managed,
                    other: false,
                    lifetime: 1800,
                    prefixes: &prefixes,
                    valid: 3600,
                    preferred: 1800,
                },
            ));
        }
        let nd = wire::parse_ndp(&ip)?;
        let IpAddr::V6(target) = nd.target else {
            return None;
        };
        if nd.kind == wire::NDP_SOLICIT && ip.src.is_unspecified() {
            self.probes.push(target);
            if self.taken == Some(target) {
                return Some(hw::unsolicited_advert(self.mac, None, target));
            }
        }
        None
    }
}

#[test]
fn slaac_takes_the_advertised_prefix_after_a_duplicate_check() {
    let host = HostConfig::new(0, mac(1))
        .with_ipv6(Ipv6Mode::Slaac)
        .with_announce(true);
    let mut engine = HostEngine::new(vec![host], HostOptions::default()).unwrap();
    let mut router = Router::new("fd00:77::");
    let mut adverts = 0;
    drive(&mut engine, ms(0), ms(800), ms(10), |p, f, _| {
        router.answer(f).map(|r| (p, r)).into_iter().collect()
    });
    // Checking for duplicates for a second: not ready yet.
    let want: Ipv6Addr = "fd00:77::dc:ff:fe00:1".parse().unwrap();
    assert_eq!(router.probes, vec![want]);
    assert_eq!(engine.statuses()[0].state, HostState::Starting);
    drive(&mut engine, ms(800), ms(2500), ms(10), |p, f, _| {
        let link = wire::parse_link(f).unwrap();
        if let Some(ip) = wire::parse_ip(&f[link.payload..], true) {
            if wire::parse_ndp(&ip).is_some_and(|n| n.kind == wire::NDP_ADVERT) {
                adverts += 1;
                assert_eq!(ip.dst, IpAddr::V6(hw::ALL_NODES));
            }
        }
        router.answer(f).map(|r| (p, r)).into_iter().collect()
    });
    let s = engine.statuses();
    assert_eq!(s[0].state, HostState::Ready);
    let a = s[0].ipv6.as_ref().unwrap();
    assert_eq!(a.ip, IpAddr::V6(want));
    assert_eq!(a.prefix, 64);
    assert_eq!(a.gateway, Some(IpAddr::V6(router.ll())));
    assert_eq!(a.source, AddressSource::Slaac);
    assert_eq!(a.lease, Some(Duration::from_secs(3600)));
    assert_eq!(s[0].link_local, Some(hw::link_local(mac(1))));
    assert_eq!(adverts, 2, "two unsolicited neighbor advertisements");
}

#[test]
fn a_duplicate_address_fails_the_host() {
    let host = HostConfig::new(0, mac(1)).with_ipv6(Ipv6Mode::Slaac);
    let mut engine = HostEngine::new(vec![host], HostOptions::for_endpoints()).unwrap();
    let mut router = Router::new("fd00:77::");
    router.taken = Some("fd00:77::dc:ff:fe00:1".parse().unwrap());
    drive(&mut engine, ms(0), ms(2000), ms(10), |p, f, _| {
        router.answer(f).map(|r| (p, r)).into_iter().collect()
    });
    let e = engine.error().unwrap();
    assert!(e.contains("already in use"), "{e}");
}

/// A DHCPv6 server leasing fd00:77::100 and up.
struct Dhcp6Server {
    next: u16,
    seen: Vec<u8>,
}

impl Dhcp6Server {
    fn answer(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        let link = wire::parse_link(frame)?;
        let ip = wire::parse_ip(&frame[link.payload..], true)?;
        let udp = wire::parse_udp(&ip, true)?;
        if udp.dport != 547 {
            return None;
        }
        let m = hw::parse_dhcp6(udp.data)?;
        self.seen.push(m.kind);
        let kind = match m.kind {
            hw::DHCP6_SOLICIT => hw::DHCP6_ADVERTISE,
            hw::DHCP6_REQUEST | hw::DHCP6_RENEW => hw::DHCP6_REPLY,
            _ => return None,
        };
        let addr = Ipv6Addr::new(0xfd00, 0x77, 0, 0, 0, 0, 0, 0x100 + self.next);
        if kind == hw::DHCP6_REPLY && m.kind == hw::DHCP6_REQUEST {
            self.next += 1;
        }
        let opt = |p: &mut Vec<u8>, code: u16, v: &[u8]| {
            p.extend_from_slice(&code.to_be_bytes());
            p.extend_from_slice(&(v.len() as u16).to_be_bytes());
            p.extend_from_slice(v);
        };
        let mut p = vec![kind];
        p.extend_from_slice(&m.xid.to_be_bytes()[1..]);
        opt(&mut p, 1, &m.client_id);
        opt(&mut p, 2, &[0, 3, 0, 1, 2, 0x99, 0, 0, 0, 6]);
        let mut ia = vec![0, 0, 0, 1, 0, 0, 0, 30, 0, 0, 0, 48];
        let mut a = addr.octets().to_vec();
        a.extend_from_slice(&60u32.to_be_bytes());
        a.extend_from_slice(&120u32.to_be_bytes());
        opt(&mut ia, 5, &a);
        opt(&mut p, 3, &ia);
        let src = hw::link_local(MacAddr([2, 0x99, 0, 0, 0, 6]));
        let path = Path {
            src_mac: MacAddr([2, 0x99, 0, 0, 0, 6]),
            dst_mac: link.src,
            vlan: None,
            src: src.into(),
            dst: ip.src,
        };
        Some(wire::udp_frame(&path, 547, 546, &p, 0))
    }
}

#[test]
fn dhcpv6_gets_an_address_and_the_router_from_advertisements() {
    let host = HostConfig::new(0, mac(1)).with_ipv6(Ipv6Mode::Dhcpv6);
    let mut engine = HostEngine::new(vec![host], HostOptions::default()).unwrap();
    let mut router = Router::new("fd00:77::");
    router.managed = true;
    let mut server = Dhcp6Server {
        next: 0,
        seen: Vec::new(),
    };
    drive(&mut engine, ms(0), ms(2000), ms(10), |p, f, _| {
        let mut out: Vec<_> = router.answer(f).map(|r| (p, r)).into_iter().collect();
        out.extend(server.answer(f).map(|r| (p, r)));
        out
    });
    let s = engine.statuses();
    assert_eq!(s[0].state, HostState::Ready, "{:?}", s[0].error);
    let a = s[0].ipv6.as_ref().unwrap();
    assert_eq!(a.ip, IpAddr::V6("fd00:77::100".parse().unwrap()));
    assert_eq!(a.prefix, 64, "the advertised on-link prefix holds it");
    assert_eq!(a.gateway, Some(IpAddr::V6(router.ll())));
    assert_eq!(a.lease, Some(Duration::from_secs(120)));
    assert_eq!(server.seen, vec![hw::DHCP6_SOLICIT, hw::DHCP6_REQUEST]);
    // T1 = 30 s: a renew.
    drive(&mut engine, ms(2000), ms(31_000), ms(50), |p, f, _| {
        server.answer(f).map(|r| (p, r)).into_iter().collect()
    });
    assert_eq!(server.seen.last(), Some(&hw::DHCP6_RENEW));
    assert_eq!(engine.statuses()[0].ipv6.as_ref().unwrap().renewals, 1);
    engine.finish();
    for (_, f) in engine.take_output() {
        server.answer(&f);
    }
    assert_eq!(server.seen.last(), Some(&hw::DHCP6_RELEASE));
}

fn igmp_query(version: u8, group: Ipv4Addr) -> Vec<u8> {
    let mut b = match version {
        2 => vec![0x11, 10, 0, 0],
        _ => vec![0x11, 10, 0, 0],
    };
    b.extend_from_slice(&group.octets());
    if version == 3 {
        b.extend_from_slice(&[0, 0, 0, 0]);
    }
    let s = wire::checksum(&b, 0);
    b[2..4].copy_from_slice(&s.to_be_bytes());
    let mut f = Vec::new();
    wire::push_link(
        &mut f,
        MacAddr([1, 0, 0x5e, 0, 0, 1]),
        SERVER_MAC,
        None,
        0x0800,
    );
    let start = f.len();
    let total = (20 + b.len()) as u16;
    f.extend_from_slice(&[0x45, 0]);
    f.extend_from_slice(&total.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0, 1, 2, 0, 0]);
    f.extend_from_slice(&SERVER_IP.octets());
    f.extend_from_slice(&[224, 0, 0, 1]);
    let s = wire::checksum(&f[start..], 0);
    f[start + 10..start + 12].copy_from_slice(&s.to_be_bytes());
    f.extend_from_slice(&b);
    f
}

/// IGMP reports in `frames`, as (version, record or type, group).
fn igmp_reports(frames: &[Vec<u8>]) -> Vec<(u8, u8, Ipv4Addr)> {
    frames
        .iter()
        .filter_map(|f| {
            let link = wire::parse_link(f)?;
            let ip = wire::parse_ip(&f[link.payload..], true)?;
            if ip.proto != 2 {
                return None;
            }
            let p = ip.payload;
            match p[0] {
                0x22 => Some((3, p[8], Ipv4Addr::new(p[12], p[13], p[14], p[15]))),
                0x16 => Some((2, 0x16, Ipv4Addr::new(p[4], p[5], p[6], p[7]))),
                0x17 => Some((2, 0x17, Ipv4Addr::new(p[4], p[5], p[6], p[7]))),
                _ => None,
            }
        })
        .collect()
}

#[test]
fn igmp_joins_answers_queries_counts_traffic_and_leaves() {
    let group = Ipv4Addr::new(239, 1, 2, 3);
    let host = HostConfig::new(0, mac(1))
        .with_ipv4(Ipv4Mode::Static {
            ip: Ipv4Addr::new(10, 77, 0, 5),
            prefix: 24,
            gateway: None,
        })
        .with_groups(vec![group.into()]);
    let mut engine = HostEngine::new(vec![host], HostOptions::default()).unwrap();
    let mut sent = Vec::new();
    drive(&mut engine, ms(0), ms(2500), ms(10), |_, f, _| {
        sent.push(f.to_vec());
        Vec::new()
    });
    // Two unsolicited IGMPv3 reports, change to exclude {}.
    assert_eq!(
        igmp_reports(&sent),
        vec![
            (3, hw::CHANGE_TO_EXCLUDE, group),
            (3, hw::CHANGE_TO_EXCLUDE, group)
        ]
    );
    // An IGMPv2 general query: one v2 report within its 1 s, and v2 from then on.
    sent.clear();
    engine.handle_frame(0, &igmp_query(2, Ipv4Addr::UNSPECIFIED), ms(2500));
    drive(&mut engine, ms(2500), ms(4000), ms(10), |_, f, _| {
        sent.push(f.to_vec());
        Vec::new()
    });
    assert_eq!(igmp_reports(&sent), vec![(2, 0x16, group)]);
    // A query for another group is not ours.
    sent.clear();
    engine.handle_frame(0, &igmp_query(2, Ipv4Addr::new(239, 9, 9, 9)), ms(4000));
    drive(&mut engine, ms(4000), ms(5500), ms(10), |_, f, _| {
        sent.push(f.to_vec());
        Vec::new()
    });
    assert!(igmp_reports(&sent).is_empty());
    // Traffic to the group is counted.
    let path = Path {
        src_mac: SERVER_MAC,
        dst_mac: hw::multicast_mac4(group),
        vlan: None,
        src: SERVER_IP.into(),
        dst: group.into(),
    };
    let data = wire::udp_frame(&path, 5000, 5001, b"hello", 1);
    assert!(engine.handle_frame(0, &data, ms(5500)));
    assert!(engine.handle_frame(0, &data, ms(5500)));
    let g = &engine.statuses()[0].groups[0];
    assert_eq!((g.rx_packets, g.reports), (2, 3));
    assert_eq!(engine.statuses()[0].counters.queries, 1);
    // A leave at the end, in v2.
    engine.finish();
    let out: Vec<Vec<u8>> = engine.take_output().into_iter().map(|(_, f)| f).collect();
    assert_eq!(igmp_reports(&out), vec![(2, 0x17, group)]);
}

#[test]
fn mld_reports_groups_and_solicited_node_groups() {
    let group: Ipv6Addr = "ff15::1234".parse().unwrap();
    let host = HostConfig::new(0, mac(1))
        .with_ipv6(Ipv6Mode::Static {
            ip: "fd00:77::5".parse().unwrap(),
            prefix: 64,
            gateway: None,
        })
        .with_groups(vec![group.into()]);
    let options = HostOptions {
        dad: false,
        ..HostOptions::default()
    };
    let mut engine = HostEngine::new(vec![host], options).unwrap();
    let mut groups = Vec::new();
    drive(&mut engine, ms(0), ms(2500), ms(10), |_, f, _| {
        let link = wire::parse_link(f).unwrap();
        let ip = wire::parse_ip(&f[link.payload..], true).unwrap();
        if ip.payload[0] == hw::ICMP6_MLD2_REPORT {
            assert_eq!(ip.src, IpAddr::V6(hw::link_local(mac(1))));
            let mut a = [0u8; 16];
            a.copy_from_slice(&ip.payload[12..28]);
            groups.push(Ipv6Addr::from(a));
        }
        Vec::new()
    });
    for g in [
        group,
        wire::solicited_node(hw::link_local(mac(1))),
        wire::solicited_node("fd00:77::5".parse().unwrap()),
    ] {
        assert_eq!(
            groups.iter().filter(|x| **x == g).count(),
            2,
            "{g}: {groups:?}"
        );
    }
    // Only the configured group shows in the status.
    assert_eq!(engine.statuses()[0].groups.len(), 1);
}

#[test]
fn a_router_host_advertises_and_a_slaac_host_takes_its_prefix() {
    let router = HostConfig::new(0, mac(9)).with_router(RouterConfig {
        interval: Duration::from_secs(3),
        ..RouterConfig::new(vec![("fd00:99::".parse().unwrap(), 64)])
    });
    let host = HostConfig::new(0, mac(1)).with_ipv6(Ipv6Mode::Slaac);
    let mut routers = HostEngine::new(vec![router], HostOptions::default()).unwrap();
    let mut hosts = HostEngine::new(vec![host], HostOptions::default()).unwrap();
    let mut now = ms(0);
    let mut adverts = 0;
    while now < ms(3000) {
        for turn in 0..2 {
            let (from, to) = if turn == 0 {
                (&mut routers, &mut hosts)
            } else {
                (&mut hosts, &mut routers)
            };
            from.poll(now);
            for (_, f) in from.take_output() {
                let link = wire::parse_link(&f).unwrap();
                let ip = wire::parse_ip(&f[link.payload..], true).unwrap();
                adverts += usize::from(hw::parse_ra(&ip).is_some());
                to.handle_frame(0, &f, now);
            }
        }
        now += ms(10);
    }
    let a = hosts.statuses()[0].ipv6.clone().unwrap();
    assert_eq!(a.ip, IpAddr::V6("fd00:99::dc:ff:fe00:1".parse().unwrap()));
    assert_eq!(a.gateway, Some(IpAddr::V6(hw::link_local(mac(9)))));
    // The first advertisement at once, one for the solicitation, none more
    // within the 3 s interval.
    assert_eq!(adverts, 2);
    assert_eq!(routers.statuses()[0].counters.ra_sent, 2);
    // The router answers neighbor solicitations for its link-local address.
    let ns = wire::ndp_solicit(
        mac(1),
        None,
        "fd00:99::dc:ff:fe00:1".parse().unwrap(),
        hw::link_local(mac(9)),
    );
    assert!(routers.handle_frame(0, &ns, now));
    let out = routers.take_output();
    assert_eq!(out.len(), 1);
    // Retiring: an advertisement with router lifetime 0.
    routers.finish();
    let out = routers.take_output();
    let link = wire::parse_link(&out[0].1).unwrap();
    let ra = hw::parse_ra(&wire::parse_ip(&out[0].1[link.payload..], true).unwrap()).unwrap();
    assert_eq!(ra.lifetime, 0);
}

#[test]
fn standalone_hosts_answer_arp_and_ping() {
    let host = HostConfig::new(0, mac(1)).with_ipv4(Ipv4Mode::Static {
        ip: Ipv4Addr::new(10, 77, 0, 5),
        prefix: 24,
        gateway: None,
    });
    let mut engine = HostEngine::new(vec![host], HostOptions::default()).unwrap();
    engine.poll(ms(0));
    engine.take_output();
    let req = wire::arp_frame(
        wire::BROADCAST,
        None,
        1,
        SERVER_MAC,
        SERVER_IP,
        MacAddr([0; 6]),
        Ipv4Addr::new(10, 77, 0, 5),
    );
    assert!(engine.handle_frame(0, &req, ms(1)));
    let out = engine.take_output();
    let link = wire::parse_link(&out[0].1).unwrap();
    let arp = wire::parse_arp(&out[0].1[link.payload..]).unwrap();
    assert_eq!((arp.op, arp.sender_mac), (2, mac(1)));
    // Not for another address, nor on another VLAN.
    let other = wire::arp_frame(
        wire::BROADCAST,
        None,
        1,
        SERVER_MAC,
        SERVER_IP,
        MacAddr([0; 6]),
        Ipv4Addr::new(10, 77, 0, 6),
    );
    assert!(!engine.handle_frame(0, &other, ms(1)));
    let tagged = wire::arp_frame(
        wire::BROADCAST,
        Some(5),
        1,
        SERVER_MAC,
        SERVER_IP,
        MacAddr([0; 6]),
        Ipv4Addr::new(10, 77, 0, 5),
    );
    assert!(!engine.handle_frame(0, &tagged, ms(1)));
    // As the ends of a TCP or UDP run, the run's engine answers instead.
    let host = HostConfig::new(0, mac(1)).with_ipv4(Ipv4Mode::Static {
        ip: Ipv4Addr::new(10, 77, 0, 5),
        prefix: 24,
        gateway: None,
    });
    let mut engine = HostEngine::new(vec![host], HostOptions::for_endpoints()).unwrap();
    engine.poll(ms(0));
    assert!(!engine.handle_frame(0, &req, ms(1)));
}

#[test]
fn configurations_are_checked() {
    let bad = [
        HostConfig::new(0, MacAddr([1, 0, 0, 0, 0, 1])).with_ipv4(Ipv4Mode::Dhcp),
        HostConfig::new(0, mac(1)),
        HostConfig::new(0, mac(1)).with_groups(vec!["239.1.1.1".parse().unwrap()]),
        HostConfig::new(0, mac(1))
            .with_ipv4(Ipv4Mode::Dhcp)
            .with_groups(vec!["10.0.0.1".parse().unwrap()]),
        HostConfig::new(0, mac(1)).with_router(RouterConfig::new(Vec::new())),
    ];
    for h in bad {
        assert!(
            HostEngine::new(vec![h.clone()], HostOptions::default()).is_err(),
            "{h:?}"
        );
    }
    assert!(HostEngine::new(vec![dhcp_host(1), dhcp_host(1)], HostOptions::default()).is_err());
    // An IPv6 group needs only the link-local address.
    let h = HostConfig::new(0, mac(1)).with_groups(vec!["ff15::1".parse().unwrap()]);
    assert!(HostEngine::new(vec![h], HostOptions::default()).is_ok());
}

/// With a SLAAC client, a static IPv6 server gets a host too, so that it
/// joins its solicited-node group (MLD snooping bridges need that to pass
/// neighbor solicitations); the engine still answers for the address.
#[test]
fn a_static_ipv6_end_joins_its_solicited_node_group() {
    let program = TcpProgram::new(80, vec![TcpMessage::new(TcpRole::Client, "x")]);
    let server_ip: Ipv6Addr = "fd00:77::20".parse().unwrap();
    let config = TcpConfig {
        templates: vec![TcpTemplate::new(
            Arc::new(program),
            std::net::SocketAddr::new(server_ip.into(), 80),
        )],
        client: Some(TcpClientConfig::new(
            TcpEndpoint::new(0, mac(1), Ipv6Addr::UNSPECIFIED.into()).with_prefix(0),
        )),
        server: Some(TcpServerConfig::new(
            TcpEndpoint::new(1, mac(2), server_ip.into()).with_prefix(64),
        )),
        options: TcpOptions::default(),
    };
    let emu = Emulation {
        addressing: Addressing::Slaac,
        ..Emulation::default()
    };
    let plan = EndpointHosts::new(&config, Some(&emu), None)
        .unwrap()
        .unwrap();
    assert_eq!(plan.hosts().len(), 2);
    let server = &plan.hosts()[1];
    assert!(!server.announce);
    assert!(matches!(server.ipv6, Some(Ipv6Mode::Static { ip, .. }) if ip == server_ip));
    // A static IPv4 server next to a DHCP client stays without a host.
    let v4 = Emulation {
        addressing: Addressing::Dhcp,
        ..Emulation::default()
    };
    let mut config4 = config.clone();
    config4.server.as_mut().unwrap().endpoint =
        TcpEndpoint::new(1, mac(2), "10.77.0.20".parse().unwrap());
    let plan4 = EndpointHosts::new(&config4, Some(&v4), None)
        .unwrap()
        .unwrap();
    assert_eq!(plan4.hosts().len(), 1);
}

/// A TCP client that gets its address by DHCP connects to a static server
/// on the same link; the run starts once the lease is there.
#[test]
fn a_tcp_client_with_a_dhcp_address() {
    let program = TcpProgram::new(
        80,
        vec![
            TcpMessage::new(TcpRole::Client, "GET / HTTP/1.0\r\n\r\n"),
            TcpMessage::new(TcpRole::Server, "HTTP/1.0 200 OK\r\n\r\nhello"),
        ],
    );
    let server_ep = TcpEndpoint::new(
        1,
        MacAddr([2, 0, 10, 77, 0, 20]),
        "10.77.0.20".parse().unwrap(),
    );
    let mut client = TcpClientConfig::new(
        TcpEndpoint::new(0, mac(1), Ipv4Addr::UNSPECIFIED.into()).with_prefix(0),
    );
    client.connections = 3;
    client.cps = 100.0;
    let config = TcpConfig {
        templates: vec![TcpTemplate::new(
            Arc::new(program),
            "10.77.0.20:80".parse().unwrap(),
        )],
        client: Some(client),
        server: Some(TcpServerConfig::new(server_ep)),
        options: TcpOptions::default(),
    };
    let emu = Emulation {
        addressing: Addressing::Dhcp,
        ..Emulation::default()
    };
    let plan = EndpointHosts::new(&config, Some(&emu), None)
        .unwrap()
        .unwrap();
    assert_eq!(plan.hosts().len(), 1);
    assert!(
        plan.hosts()[0].announce,
        "dynamic addresses are announced by default"
    );
    let (checked, mut engine) = plan
        .hosted(config, HostOptions::for_endpoints(), TcpEngine::new)
        .unwrap();
    assert_eq!(checked.port_macs(0), vec![mac(1)]);
    let mut server = DhcpServer::new(3600);
    drive(&mut engine, ms(0), ms(3000), ms(1), |p, f, _| {
        let mut out = vec![(1 - p, f.to_vec())];
        if p == 0 {
            out.extend(server.answer(f).map(|r| (0, r)));
        }
        out
    });
    assert_eq!(engine.error(), None);
    engine.set_elapsed(ms(3000), false);
    let stats = engine.stats();
    assert_eq!(stats.client.completed, 3, "{stats:?}");
    assert_eq!(stats.server.completed, 3);
    assert_eq!(stats.hosts.len(), 1);
    assert_eq!(
        stats.hosts[0].ipv4.as_ref().unwrap().ip,
        IpAddr::V4(Ipv4Addr::new(10, 77, 0, 100))
    );
    assert!(
        stats.elapsed < ms(3000),
        "the engine's clock starts after the setup"
    );
}

/// The server gets its address by DHCP, and clients connect to whatever it got.
#[test]
fn templates_follow_a_dhcp_server() {
    let program = TcpProgram::new(
        7,
        vec![
            TcpMessage::new(TcpRole::Client, "x"),
            TcpMessage::new(TcpRole::Server, "y"),
        ],
    );
    let mut client =
        TcpClientConfig::new(TcpEndpoint::new(0, mac(3), "10.77.0.30".parse().unwrap()));
    client.connections = 1;
    let mut config = TcpConfig {
        templates: vec![TcpTemplate::new(
            Arc::new(program),
            "0.0.0.0:7".parse().unwrap(),
        )],
        client: Some(client),
        server: Some(TcpServerConfig::new(
            TcpEndpoint::new(1, mac(2), Ipv4Addr::UNSPECIFIED.into()).with_prefix(0),
        )),
        options: TcpOptions::default(),
    };
    let emu = Emulation {
        addressing: Addressing::Dhcp,
        ..Emulation::default()
    };
    let plan = EndpointHosts::new(&config, None, Some(&emu))
        .unwrap()
        .unwrap();
    let mut status = HostEngine::new(plan.hosts().to_vec(), HostOptions::default())
        .unwrap()
        .statuses();
    status[0].ipv4 = Some(HostAddress {
        ip: "10.77.0.150".parse().unwrap(),
        prefix: 24,
        gateway: Some("10.77.0.1".parse().unwrap()),
        source: AddressSource::Dhcp,
        server: None,
        dns: Vec::new(),
        lease: None,
        renewals: 0,
    });
    plan.apply(&mut config, &status);
    let s = &config.server.as_ref().unwrap().endpoint;
    assert_eq!((s.ip, s.prefix), ("10.77.0.150".parse().unwrap(), 24));
    assert_eq!(s.gateway, Some("10.77.0.1".parse().unwrap()));
    assert_eq!(
        config.templates[0].connect,
        "10.77.0.150:7".parse().unwrap()
    );
    // The client keeps its static address.
    assert_eq!(
        config.client.as_ref().unwrap().endpoint.ip,
        "10.77.0.30".parse::<IpAddr>().unwrap()
    );
}
