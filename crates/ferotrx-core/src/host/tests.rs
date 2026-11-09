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
    mtu: Option<u32>,
    dns: Vec<Ipv6Addr>,
    search: Vec<String>,
}

impl Router {
    fn new(prefix: &str) -> Self {
        Self {
            mac: MacAddr([0x02, 0x99, 0, 0, 0, 6]),
            prefix: (prefix.parse().unwrap(), 64),
            managed: false,
            taken: None,
            probes: Vec::new(),
            mtu: None,
            dns: Vec::new(),
            search: Vec::new(),
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
                    mtu: self.mtu,
                    dns: &self.dns,
                    search: &self.search,
                    dns_lifetime: 600,
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
        mtu: None,
        domains: Vec::new(),
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

// --- DHCP server roles ----------------------------------------------------

fn dhcp_server_host() -> HostConfig {
    let mut s = DhcpServerConfig::new(Ipv4Addr::new(10, 77, 0, 100), Ipv4Addr::new(10, 77, 0, 102));
    s.lease = Duration::from_secs(10);
    s.dns = vec![Ipv4Addr::new(10, 77, 0, 53)];
    s.domain = Some("lab.test".into());
    s.router = Some(SERVER_IP);
    HostConfig::new(0, SERVER_MAC)
        .with_ipv4(Ipv4Mode::Static {
            ip: SERVER_IP,
            prefix: 24,
            gateway: None,
        })
        .with_dhcp_server(s)
}

/// Runs two engines on one link for `until`, frames both ways.
fn link_up(
    a: &mut HostEngine,
    b: &mut HostEngine,
    from: Duration,
    until: Duration,
    step: Duration,
) {
    let mut now = from;
    while now < until {
        for turn in 0..2 {
            let (x, y) = if turn == 0 {
                (&mut *a, &mut *b)
            } else {
                (&mut *b, &mut *a)
            };
            x.poll(now);
            for (_, f) in x.take_output() {
                y.handle_frame(0, &f, now);
            }
        }
        now += step;
    }
}

#[test]
fn a_dhcp_server_leases_renews_and_takes_releases() {
    let mut server = HostEngine::new(vec![dhcp_server_host()], HostOptions::default()).unwrap();
    let mut clients = (1..=2).map(dhcp_host).collect::<Vec<_>>();
    clients[0].hostname = Some("lab-1".into());
    let mut clients = HostEngine::new(clients, HostOptions::default()).unwrap();
    link_up(&mut server, &mut clients, ms(0), ms(2000), ms(10));
    assert!(clients.all_ready());
    let s = clients.statuses();
    let a = s[0].ipv4.as_ref().unwrap();
    // The clients start in a random order within 100 ms.
    let mut ips: Vec<IpAddr> = s.iter().map(|h| h.ipv4.as_ref().unwrap().ip).collect();
    ips.sort();
    assert_eq!(
        ips,
        vec![
            IpAddr::V4(Ipv4Addr::new(10, 77, 0, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 77, 0, 101))
        ]
    );
    assert_eq!(a.prefix, 24);
    assert_eq!(a.gateway, Some(IpAddr::V4(SERVER_IP)), "the router option");
    assert_eq!(a.server, Some(IpAddr::V4(SERVER_IP)));
    assert_eq!(a.dns, vec![IpAddr::V4(Ipv4Addr::new(10, 77, 0, 53))]);
    assert_eq!(a.lease, Some(Duration::from_secs(10)));
    let st = server.statuses()[0].dhcp_server.clone().unwrap();
    assert_eq!(st.pool, "10.77.0.100-10.77.0.102");
    assert_eq!(st.pool_size, 3);
    assert_eq!(st.leases.len(), 2);
    let l1 = st.leases.iter().find(|l| l.mac == Some(mac(1))).unwrap();
    assert_eq!(l1.ip, a.ip);
    assert_eq!(l1.hostname.as_deref(), Some("lab-1"));
    assert_eq!(st.counters.discovers, 2);
    assert_eq!(st.counters.offers, 2);
    assert_eq!(st.counters.acks, 2);

    // Renewals at T1 (5 s), unicast to the server.
    link_up(&mut server, &mut clients, ms(2000), ms(12_000), ms(10));
    let s = clients.statuses();
    assert!(
        s.iter().all(|h| h.ipv4.as_ref().unwrap().renewals >= 1),
        "{s:?}"
    );
    assert!(s.iter().all(|h| h.state == HostState::Ready));
    let st = server.statuses()[0].dhcp_server.clone().unwrap();
    assert!(st.counters.acks >= 4);
    assert_eq!(st.counters.naks, 0);

    // Releases at the end.
    clients.finish();
    for (_, f) in clients.take_output() {
        server.handle_frame(0, &f, ms(12_000));
    }
    let st = server.statuses()[0].dhcp_server.clone().unwrap();
    assert_eq!(st.counters.releases, 2);
    assert!(st.leases.is_empty());
}

#[test]
fn a_dhcp_server_and_its_clients_in_one_engine() {
    // The server's own engine hands frames between its hosts.
    let mut hosts = vec![dhcp_server_host()];
    hosts.extend((1..=4).map(dhcp_host));
    let mut engine = HostEngine::new(hosts, HostOptions::default()).unwrap();
    let mut wire_frames = 0;
    drive(&mut engine, ms(0), ms(2000), ms(10), |_, _, _| {
        wire_frames += 1;
        Vec::new()
    });
    let s = engine.statuses();
    // Three addresses for four clients.
    assert_eq!(
        s.iter().filter(|h| h.state == HostState::Ready).count(),
        4,
        "{s:?}"
    );
    assert_eq!(
        s.iter().filter(|h| h.state == HostState::Starting).count(),
        1
    );
    let st = s[0].dhcp_server.clone().unwrap();
    assert_eq!(st.leases.len(), 3);
    assert!(st.counters.exhausted >= 1);
    // The frames still go out on the port.
    assert!(wire_frames > 0);
}

/// A DHCPv4 client message for the server tests.
fn client_msg(
    kind: u8,
    mac: MacAddr,
    ciaddr: Ipv4Addr,
    requested: Option<Ipv4Addr>,
    server: Option<Ipv4Addr>,
) -> Vec<u8> {
    hw::dhcp4_message(&hw::Dhcp4Out {
        kind,
        xid: 7,
        secs: 0,
        mac,
        ciaddr,
        requested,
        server,
        hostname: None,
        broadcast: false,
    })
}

fn to_server(
    payload: &[u8],
    src_mac: MacAddr,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
) -> Vec<u8> {
    let path = Path {
        src_mac,
        dst_mac: if dst == Ipv4Addr::BROADCAST {
            wire::BROADCAST
        } else {
            SERVER_MAC
        },
        vlan: None,
        src: src.into(),
        dst: dst.into(),
    };
    wire::udp_frame(&path, sport, 67, payload, 0)
}

/// The server's answer: destination IP and MAC, UDP port and the message.
fn answer_of(engine: &mut HostEngine) -> Vec<(IpAddr, MacAddr, u16, hw::Dhcp4In)> {
    engine
        .take_output()
        .into_iter()
        .filter_map(|(_, f)| {
            let link = wire::parse_link(&f)?;
            let ip = wire::parse_ip(&f[link.payload..], true)?;
            let udp = wire::parse_udp(&ip, true)?;
            let m = hw::parse_dhcp4(udp.data)?;
            Some((ip.dst, link.dst, udp.dport, m))
        })
        .collect()
}

#[test]
fn a_dhcp_server_naks_wrong_addresses_and_answers_relays() {
    let mut engine = HostEngine::new(vec![dhcp_server_host()], HostOptions::default()).unwrap();
    engine.poll(ms(0));
    engine.take_output();
    let z = Ipv4Addr::UNSPECIFIED;
    let b = Ipv4Addr::BROADCAST;
    // Init-reboot with an address of another network: a broadcast NAK.
    let m = client_msg(
        hw::DHCPREQUEST,
        mac(1),
        z,
        Some(Ipv4Addr::new(192, 168, 1, 5)),
        None,
    );
    assert!(engine.handle_frame(0, &to_server(&m, mac(1), z, b, 68), ms(1)));
    let a = answer_of(&mut engine);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].3.kind, hw::DHCPNAK);
    assert_eq!((a[0].0, a[0].1), (IpAddr::V4(b), wire::BROADCAST));
    // Init-reboot with a free pool address: acknowledged, unicast to the MAC.
    let want = Ipv4Addr::new(10, 77, 0, 102);
    let m = client_msg(hw::DHCPREQUEST, mac(1), z, Some(want), None);
    engine.handle_frame(0, &to_server(&m, mac(1), z, b, 68), ms(2));
    let a = answer_of(&mut engine);
    assert_eq!(a[0].3.kind, hw::DHCPACK);
    assert_eq!(a[0].3.yiaddr, want);
    assert_eq!((a[0].0, a[0].1), (IpAddr::V4(want), mac(1)));
    // Another client may not have it.
    let m = client_msg(hw::DHCPREQUEST, mac(2), z, Some(want), None);
    engine.handle_frame(0, &to_server(&m, mac(2), z, b, 68), ms(3));
    assert_eq!(answer_of(&mut engine)[0].3.kind, hw::DHCPNAK);
    // A request for another server's offer is not answered.
    let m = client_msg(
        hw::DHCPREQUEST,
        mac(3),
        z,
        Some(Ipv4Addr::new(10, 77, 0, 100)),
        Some(Ipv4Addr::new(10, 77, 0, 2)),
    );
    engine.handle_frame(0, &to_server(&m, mac(3), z, b, 68), ms(4));
    assert!(answer_of(&mut engine).is_empty());
    // Through a relay: giaddr set, the answer goes to the relay's port 67.
    let relay = Ipv4Addr::new(10, 77, 0, 254);
    let mut m = client_msg(hw::DHCPDISCOVER, mac(4), z, None, None);
    m[24..28].copy_from_slice(&relay.octets());
    let relay_mac = MacAddr([2, 0xaa, 0, 0, 0, 1]);
    engine.handle_frame(0, &to_server(&m, relay_mac, relay, SERVER_IP, 67), ms(5));
    let a = answer_of(&mut engine);
    assert_eq!(a[0].3.kind, hw::DHCPOFFER);
    assert_eq!((a[0].0, a[0].1, a[0].2), (IpAddr::V4(relay), relay_mac, 67));
    // A decline keeps the address from being leased again.
    let got = a[0].3.yiaddr;
    let m = client_msg(hw::DHCPREQUEST, mac(4), z, Some(got), Some(SERVER_IP));
    engine.handle_frame(0, &to_server(&m, mac(4), z, b, 68), ms(6));
    assert_eq!(answer_of(&mut engine)[0].3.kind, hw::DHCPACK);
    let m = client_msg(hw::DHCPDECLINE, mac(4), z, Some(got), Some(SERVER_IP));
    engine.handle_frame(0, &to_server(&m, mac(4), z, b, 68), ms(7));
    let m = client_msg(hw::DHCPDISCOVER, mac(4), z, Some(got), None);
    engine.handle_frame(0, &to_server(&m, mac(4), z, b, 68), ms(8));
    let a = answer_of(&mut engine);
    assert_ne!(a[0].3.yiaddr, got);
    let st = engine.statuses()[0].dhcp_server.clone().unwrap();
    assert_eq!(st.counters.declines, 1);
    assert_eq!(st.counters.naks, 2);
}

#[test]
fn reservations_and_pool_checks() {
    let mut cfg = dhcp_server_host();
    let s = cfg.dhcp_server.as_mut().unwrap();
    s.reservations.push((mac(7), Ipv4Addr::new(10, 77, 0, 7)));
    let mut server = HostEngine::new(vec![cfg.clone()], HostOptions::default()).unwrap();
    let mut clients = HostEngine::new(vec![dhcp_host(7)], HostOptions::default()).unwrap();
    link_up(&mut server, &mut clients, ms(0), ms(1000), ms(10));
    assert_eq!(
        clients.statuses()[0].ipv4.as_ref().unwrap().ip,
        IpAddr::V4(Ipv4Addr::new(10, 77, 0, 7))
    );
    for (change, want) in [
        (
            Box::new(|c: &mut HostConfig| c.ipv4 = Some(Ipv4Mode::Dhcp))
                as Box<dyn Fn(&mut HostConfig)>,
            "static IPv4",
        ),
        (
            Box::new(|c: &mut HostConfig| {
                c.dhcp_server.as_mut().unwrap().pool.1 = Ipv4Addr::new(10, 78, 0, 1)
            }),
            "subnet",
        ),
        (
            Box::new(|c: &mut HostConfig| {
                c.dhcp_server.as_mut().unwrap().pool.0 = Ipv4Addr::new(10, 77, 0, 200)
            }),
            "ends before",
        ),
    ] {
        let mut c = cfg.clone();
        change(&mut c);
        let e = HostEngine::new(vec![c], HostOptions::default())
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains(want), "{e}");
    }
}

#[test]
fn a_dhcpv6_server_with_router_advertisements() {
    let mut router = RouterConfig::new(vec![("fd00:77::".parse().unwrap(), 64)]);
    router.managed = true;
    let mut s6 = Dhcpv6ServerConfig::new(
        "fd00:77::100".parse().unwrap(),
        "fd00:77::1ff".parse().unwrap(),
    );
    s6.lease = Duration::from_secs(20);
    s6.dns = vec!["fd00:77::53".parse().unwrap()];
    s6.domain = Some("lab.test".into());
    let server = HostConfig::new(0, SERVER_MAC)
        .with_router(router)
        .with_dhcpv6_server(s6);
    let mut server = HostEngine::new(vec![server], HostOptions::default()).unwrap();
    let clients = (1..=2)
        .map(|n| HostConfig::new(0, mac(n)).with_ipv6(Ipv6Mode::Dhcpv6))
        .collect();
    let mut clients = HostEngine::new(clients, HostOptions::default()).unwrap();
    link_up(&mut server, &mut clients, ms(0), ms(3000), ms(10));
    let s = clients.statuses();
    assert!(clients.all_ready(), "{s:?}");
    let a = s[0].ipv6.as_ref().unwrap();
    assert_eq!(a.ip, IpAddr::V6("fd00:77::100".parse().unwrap()));
    assert_eq!(a.prefix, 64);
    assert_eq!(a.gateway, Some(IpAddr::V6(hw::link_local(SERVER_MAC))));
    assert_eq!(a.dns, vec![IpAddr::V6("fd00:77::53".parse().unwrap())]);
    assert_eq!(a.lease, Some(Duration::from_secs(20)));
    assert_eq!(
        s[1].ipv6.as_ref().unwrap().ip,
        IpAddr::V6("fd00:77::101".parse().unwrap())
    );
    // Renewals at T1 = 10 s.
    link_up(&mut server, &mut clients, ms(3000), ms(13_000), ms(20));
    assert!(clients
        .statuses()
        .iter()
        .all(|h| h.ipv6.as_ref().unwrap().renewals == 1));
    let st = server.statuses()[0].dhcpv6_server.clone().unwrap();
    assert_eq!(st.leases.len(), 2);
    assert_eq!(st.leases[0].mac, Some(mac(1)));
    assert_eq!(st.counters.discovers, 2);
    assert_eq!(st.counters.offers, 2);
    assert_eq!(st.counters.acks, 4);
    assert_eq!(st.counters.naks, 0);
    clients.finish();
    for (_, f) in clients.take_output() {
        server.handle_frame(0, &f, ms(13_000));
    }
    let st = server.statuses()[0].dhcpv6_server.clone().unwrap();
    assert_eq!(st.counters.releases, 2);
    assert!(st.leases.is_empty());
}

#[test]
fn a_dhcpv6_server_answers_rapid_commit_confirm_and_information_requests() {
    let s6 = Dhcpv6ServerConfig::new(
        "fd00:77::100".parse().unwrap(),
        "fd00:77::100".parse().unwrap(),
    );
    let server = HostConfig::new(0, SERVER_MAC).with_dhcpv6_server(s6);
    let mut engine = HostEngine::new(vec![server], HostOptions::default()).unwrap();
    engine.poll(ms(0));
    engine.take_output();
    let client_ll = hw::link_local(mac(1));
    let send = |engine: &mut HostEngine, body: Vec<u8>, at: u64| -> Option<hw::Dhcp6In> {
        let path = Path {
            src_mac: mac(1),
            dst_mac: wire::multicast_mac(hw::DHCP6_SERVERS),
            vlan: None,
            src: client_ll.into(),
            dst: hw::DHCP6_SERVERS.into(),
        };
        engine.handle_frame(0, &wire::udp_frame(&path, 546, 547, &body, 0), ms(at));
        let out = engine.take_output();
        out.iter().find_map(|(_, f)| {
            let link = wire::parse_link(f)?;
            let ip = wire::parse_ip(&f[link.payload..], true)?;
            assert_eq!(ip.dst, IpAddr::V6(client_ll));
            assert_eq!(link.dst, mac(1));
            let udp = wire::parse_udp(&ip, true)?;
            assert_eq!(udp.dport, 546);
            hw::parse_dhcp6(udp.data)
        })
    };
    let msg = |kind: u8, mac: MacAddr, address: Option<Ipv6Addr>, rapid: bool| {
        let mut b = hw::dhcp6_message(&hw::Dhcp6Out {
            kind,
            xid: 0x123456,
            mac,
            iaid: 1,
            elapsed: 0,
            server_id: None,
            want_address: true,
            address,
            pd: None,
        });
        if rapid {
            b.extend_from_slice(&[0, 14, 0, 0]);
        }
        b
    };
    // A solicit with rapid commit: a reply that binds at once.
    let r = send(&mut engine, msg(hw::DHCP6_SOLICIT, mac(1), None, true), 1).unwrap();
    assert_eq!(r.kind, hw::DHCP6_REPLY);
    assert_eq!(r.xid, 0x123456);
    assert_eq!(r.client_id, hw::duid(mac(1)));
    assert_eq!(r.server_id, hw::duid(SERVER_MAC));
    assert_eq!(
        r.address.unwrap().0,
        "fd00:77::100".parse::<Ipv6Addr>().unwrap()
    );
    // The pool has one address: the next client gets NoAddrsAvail.
    let r = send(&mut engine, msg(hw::DHCP6_SOLICIT, mac(2), None, false), 2).unwrap();
    assert_eq!(r.kind, hw::DHCP6_ADVERTISE);
    assert_eq!(r.status, Some(2));
    assert!(r.address.is_none());
    // Confirm: on link or not.
    let r = send(
        &mut engine,
        msg(4, mac(1), Some("fd00:77::100".parse().unwrap()), false),
        3,
    )
    .unwrap();
    assert_eq!(r.status, None);
    let r = send(
        &mut engine,
        msg(4, mac(1), Some("fd00:78::1".parse().unwrap()), false),
        4,
    )
    .unwrap();
    assert_eq!(r.status, Some(4));
    // Rebind of an address the client does not hold: zero lifetimes.
    let r = send(
        &mut engine,
        msg(
            hw::DHCP6_REBIND,
            mac(2),
            Some("fd00:77::100".parse().unwrap()),
            false,
        ),
        5,
    )
    .unwrap();
    assert_eq!(r.address.unwrap().2, 0);
    let st = engine.statuses()[0].dhcpv6_server.clone().unwrap();
    assert_eq!(st.counters.exhausted, 1);
    assert_eq!(st.leases.len(), 1);
}

fn static4(n: u8) -> HostConfig {
    HostConfig::new(0, mac(n)).with_ipv4(Ipv4Mode::Static {
        ip: Ipv4Addr::new(10, 77, 0, n),
        prefix: 24,
        gateway: None,
    })
}

#[test]
fn a_dhcpv6_server_delegates_prefixes_to_requesting_routers() {
    let mut s6 = Dhcpv6ServerConfig::new(
        "fd00:77::100".parse().unwrap(),
        "fd00:77::1ff".parse().unwrap(),
    );
    s6.lease = Duration::from_secs(20);
    s6.pd_pool = Some(("fd00:aa00::".parse().unwrap(), 48));
    s6.pd_length = 56;
    let mut router = RouterConfig::new(vec![("fd00:77::".parse().unwrap(), 64)]);
    router.managed = true;
    let server = HostConfig::new(0, SERVER_MAC)
        .with_router(router)
        .with_dhcpv6_server(s6);
    let mut server = HostEngine::new(vec![server], HostOptions::default()).unwrap();
    // One with an address and a prefix, one with only a prefix.
    let mut both = HostConfig::new(0, mac(1)).with_ipv6(Ipv6Mode::Dhcpv6);
    both.prefix_delegation = Some(56);
    let mut only = HostConfig::new(0, mac(2));
    only.prefix_delegation = Some(0);
    let mut clients = HostEngine::new(vec![both, only], HostOptions::default()).unwrap();
    link_up(&mut server, &mut clients, ms(0), ms(3000), ms(10));
    let s = clients.statuses();
    assert!(clients.all_ready(), "{s:?}");
    assert_eq!(
        s[0].ipv6.as_ref().unwrap().ip,
        IpAddr::V6("fd00:77::100".parse().unwrap())
    );
    let mut prefixes: Vec<IpAddr> = s
        .iter()
        .map(|h| {
            let p = h.delegated_prefix.as_ref().unwrap();
            assert_eq!(p.prefix, 56);
            assert_eq!(p.lease, Some(Duration::from_secs(20)));
            p.ip
        })
        .collect();
    prefixes.sort();
    assert_eq!(
        prefixes,
        vec![
            IpAddr::V6("fd00:aa00::".parse().unwrap()),
            IpAddr::V6("fd00:aa00:0:100::".parse().unwrap())
        ]
    );
    assert!(s[1].ipv6.is_none());
    let st = server.statuses()[0].dhcpv6_server.clone().unwrap();
    assert_eq!(st.leases.len(), 1);
    assert_eq!(st.delegations.len(), 2);
    assert!(st.delegations.iter().all(|d| d.prefix == Some(56)));
    // Renewed at T1 = 10 s, with the address.
    link_up(&mut server, &mut clients, ms(3000), ms(13_000), ms(20));
    let s = clients.statuses();
    assert!(s.iter().all(|h| h.state == HostState::Ready), "{s:?}");
    assert!(s
        .iter()
        .all(|h| h.delegated_prefix.as_ref().unwrap().renewals == 1));
    // Released at the end.
    clients.finish();
    for (_, f) in clients.take_output() {
        server.handle_frame(0, &f, ms(13_000));
    }
    let st = server.statuses()[0].dhcpv6_server.clone().unwrap();
    assert!(st.leases.is_empty());
    assert!(st.delegations.is_empty());
}

#[test]
fn router_advertisements_bring_the_mtu_dns_servers_and_search_list() {
    let host = HostConfig::new(0, mac(1)).with_ipv6(Ipv6Mode::Slaac);
    let mut engine = HostEngine::new(vec![host], HostOptions::default()).unwrap();
    let mut router = Router::new("fd00:77::");
    router.mtu = Some(1400);
    router.dns = vec!["fd00:77::53".parse().unwrap()];
    router.search = vec!["lab.test".into(), "example.org".into()];
    drive(&mut engine, ms(0), ms(2500), ms(10), |p, f, _| {
        router.answer(f).map(|r| (p, r)).into_iter().collect()
    });
    let s = engine.statuses();
    let a = s[0].ipv6.as_ref().unwrap();
    assert_eq!(a.mtu, Some(1400));
    assert_eq!(a.dns, vec![IpAddr::V6("fd00:77::53".parse().unwrap())]);
    assert_eq!(a.domains, vec!["lab.test", "example.org"]);

    // Our own router host advertises them too.
    let mut cfg = RouterConfig::new(vec![("fd00:99::".parse().unwrap(), 64)]);
    cfg.mtu = Some(1450);
    cfg.dns = vec!["fd00:99::53".parse().unwrap()];
    cfg.search = vec!["lab.test".into()];
    let mut routers = HostEngine::new(
        vec![HostConfig::new(0, mac(9)).with_router(cfg)],
        HostOptions::default(),
    )
    .unwrap();
    let mut hosts = HostEngine::new(
        vec![HostConfig::new(0, mac(1)).with_ipv6(Ipv6Mode::Slaac)],
        HostOptions::default(),
    )
    .unwrap();
    link_up(&mut routers, &mut hosts, ms(0), ms(3000), ms(10));
    let a = hosts.statuses()[0].ipv6.clone().unwrap();
    assert_eq!(a.mtu, Some(1450));
    assert_eq!(a.dns, vec![IpAddr::V6("fd00:99::53".parse().unwrap())]);
    assert_eq!(a.domains, vec!["lab.test"]);
}

#[test]
fn lldp_and_cdp_neighbors_hear_each_other() {
    let mut a = static4(1);
    a.hostname = Some("lab-a".into());
    a.lldp = Some(LldpConfig {
        cdp: true,
        ..LldpConfig::default()
    });
    let mut b = static4(2);
    b.lldp = Some(LldpConfig {
        system_name: Some("lab-b".into()),
        interval: Duration::from_secs(5),
        ..LldpConfig::default()
    });
    let mut x = HostEngine::new(vec![a], HostOptions::default()).unwrap();
    let mut y = HostEngine::new(vec![b], HostOptions::default()).unwrap();
    // Fast transmission: a frame a second at the start (the hosts start at
    // random within 100 ms, so the first may come before the other starts).
    link_up(&mut x, &mut y, ms(0), ms(1500), ms(10));
    let sx = x.statuses()[0].lldp.clone().unwrap();
    let sy = y.statuses()[0].lldp.clone().unwrap();
    assert_eq!(sx.lldp_sent, 2);
    assert_eq!(sx.cdp_sent, 2);
    assert_eq!(sy.cdp_sent, 0);
    // b hears a twice, by LLDP and CDP.
    let mut heard: Vec<(&str, Option<&str>)> = sy
        .neighbors
        .iter()
        .map(|n| (n.protocol.as_str(), n.system_name.as_deref()))
        .collect();
    heard.sort();
    assert_eq!(heard, vec![("cdp", Some("lab-a")), ("lldp", Some("lab-a"))]);
    let n = &sx.neighbors[0];
    assert_eq!(n.system_name.as_deref(), Some("lab-b"));
    assert_eq!(n.mac, mac(2));
    assert_eq!(n.addresses, vec![IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2))]);
    assert_eq!(n.ttl, Duration::from_secs(20));
    // Then at b's interval.
    link_up(&mut x, &mut y, ms(1500), ms(20_000), ms(10));
    let sy = y.statuses()[0].lldp.clone().unwrap();
    assert!((6..=8).contains(&sy.lldp_sent), "{sy:?}");
    assert_eq!(
        x.statuses()[0].lldp.clone().unwrap().neighbors[0].frames,
        sy.lldp_sent
    );
    // Shut down: the neighbor goes at once.
    y.finish();
    for (_, f) in y.take_output() {
        x.handle_frame(0, &f, ms(20_000));
    }
    assert!(x.statuses()[0].lldp.clone().unwrap().neighbors.is_empty());
}

#[test]
fn mdns_hosts_announce_and_find_each_other() {
    let mut a = static4(1);
    a.hostname = Some("lab-a".into());
    a.mdns = Some(MdnsConfig {
        services: vec![MdnsService {
            instance: "Lab web".into(),
            service: "_http._tcp".into(),
            port: 8080,
            txt: vec!["path=/".into()],
        }],
        ..MdnsConfig::default()
    });
    let mut b = static4(2);
    b.mdns = Some(MdnsConfig {
        queries: vec!["_http._tcp".into(), "lab-a.local".into()],
        ..MdnsConfig::default()
    });
    // In one engine: its hosts hear each other.
    let mut engine = HostEngine::new(vec![a.clone(), b.clone()], HostOptions::default()).unwrap();
    drive(&mut engine, ms(0), ms(3000), ms(10), |_, _, _| Vec::new());
    let s = engine.statuses();
    let sa = s[0].mdns.clone().unwrap();
    let sb = s[1].mdns.clone().unwrap();
    assert_eq!(sa.name, "lab-a.local");
    assert!(sa.announcements >= 1);
    assert!(sa.answers_sent >= 1, "{sa:?}");
    assert!(sb.queries_sent >= 1);
    let find = |kind: &str| {
        sb.found
            .iter()
            .find(|f| f.kind == kind)
            .map(|f| f.data.clone())
    };
    assert_eq!(find("PTR").as_deref(), Some("Lab web._http._tcp.local"));
    assert_eq!(find("SRV").as_deref(), Some("0 0 8080 lab-a.local"));
    assert_eq!(find("A").as_deref(), Some("10.77.0.1"));
    assert!(sb
        .found
        .iter()
        .all(|f| f.from == IpAddr::V4(Ipv4Addr::new(10, 77, 0, 1))));
    // A goodbye takes the records away.
    engine.finish();
    let out = engine.take_output();
    let mut x = HostEngine::new(vec![b], HostOptions::default()).unwrap();
    let mut y = HostEngine::new(vec![a], HostOptions::default()).unwrap();
    link_up(&mut x, &mut y, ms(0), ms(3000), ms(10));
    assert!(!x.statuses()[0].mdns.clone().unwrap().found.is_empty());
    y.finish();
    for (_, f) in y.take_output() {
        x.handle_frame(0, &f, ms(3000));
    }
    assert!(x.statuses()[0].mdns.clone().unwrap().found.is_empty());
    assert!(!out.is_empty());
}

#[test]
fn mdns_answers_a_legacy_unicast_query() {
    let mut a = static4(1);
    a.hostname = Some("lab-a".into());
    a.mdns = Some(MdnsConfig::default());
    let mut engine = HostEngine::new(vec![a], HostOptions::default()).unwrap();
    drive(&mut engine, ms(0), ms(500), ms(10), |_, _, _| Vec::new());
    // `dig -p 5353 @224.0.0.251 lab-a.local`: from a random port.
    let mut q = vec![0x42, 0x42, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    crate::udp::dns::put_name(&mut q, "lab-a.local");
    q.extend_from_slice(&[0, 1, 0, 1]);
    let peer = Ipv4Addr::new(10, 77, 0, 9);
    let path = Path {
        src_mac: mac(9),
        dst_mac: MacAddr([0x01, 0x00, 0x5e, 0, 0, 0xfb]),
        vlan: None,
        src: IpAddr::V4(peer),
        dst: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
    };
    let f = wire::udp_frame(&path, 40000, 5353, &q, 1);
    assert!(engine.handle_frame(0, &f, ms(500)));
    let out = engine.take_output();
    let (_, f) = out
        .iter()
        .find(|(_, f)| wire::parse_link(f).unwrap().dst == mac(9))
        .unwrap();
    let link = wire::parse_link(f).unwrap();
    let ip = wire::parse_ip(&f[link.payload..], true).unwrap();
    assert_eq!(ip.dst, IpAddr::V4(peer));
    let udp = wire::parse_udp(&ip, true).unwrap();
    assert_eq!(udp.dport, 40000);
    let m = crate::udp::dns::Message::parse(udp.data).unwrap();
    assert_eq!(m.id, 0x4242);
    assert_eq!(
        m.question,
        Some(("lab-a.local".into(), crate::udp::dns::DnsType::A))
    );
    assert_eq!(
        m.answers[0].data,
        crate::udp::dns::DnsData::A(Ipv4Addr::new(10, 77, 0, 1))
    );
}

#[test]
fn dot1x_supplicants_authenticate_before_they_take_addresses() {
    let mut auth = HostConfig::new(0, SERVER_MAC);
    auth.dot1x_authenticator = Some(AuthenticatorConfig {
        users: vec![("alice".into(), "secret".into())],
    });
    let mut good = dhcp_server_host();
    good.dot1x_authenticator = auth.dot1x_authenticator.clone();
    let mut alice = dhcp_host(1);
    alice.dot1x = Some(Dot1xConfig::new("alice", "secret"));
    let mut mallory = dhcp_host(2);
    mallory.dot1x = Some(Dot1xConfig::new("alice", "guess"));
    let mut server = HostEngine::new(vec![good], HostOptions::default()).unwrap();
    let mut clients = HostEngine::new(vec![alice, mallory], HostOptions::default()).unwrap();
    // Before the authentication: no DHCP.
    let mut first: Vec<u16> = Vec::new();
    clients.poll(ms(0));
    for (_, f) in clients.take_output() {
        first.push(wire::parse_link(&f).unwrap().ethertype);
    }
    assert!(first.iter().all(|t| *t == 0x888e), "{first:x?}");
    link_up(&mut server, &mut clients, ms(0), ms(3000), ms(10));
    let s = clients.statuses();
    let d = s[0].dot1x.clone().unwrap();
    assert_eq!(d.state, Dot1xState::Authorized);
    assert_eq!(d.authenticator, Some(SERVER_MAC));
    assert_eq!(d.method.as_deref(), Some("MD5"));
    assert_eq!(s[0].state, HostState::Ready);
    assert!(s[0].ipv4.is_some());
    let d = s[1].dot1x.clone().unwrap();
    assert_eq!(d.state, Dot1xState::Refused);
    assert_eq!(s[1].state, HostState::Failed);
    assert!(s[1].ipv4.is_none());
    assert!(
        s[1].error.as_deref().unwrap().contains("802.1X"),
        "{:?}",
        s[1].error
    );
    let a = server.statuses()[0].dot1x_authenticator.clone().unwrap();
    assert_eq!(a.successes, 1);
    assert_eq!(a.failures, 1);
    assert_eq!(a.sessions.len(), 2);
    // Logoff at the end.
    clients.finish();
    for (_, f) in clients.take_output() {
        server.handle_frame(0, &f, ms(3000));
    }
    assert_eq!(
        server.statuses()[0]
            .dot1x_authenticator
            .clone()
            .unwrap()
            .logoffs,
        1
    );
}

#[test]
fn dot1x_without_an_authenticator() {
    let mut strict = dhcp_host(1);
    strict.dot1x = Some(Dot1xConfig::new("alice", "secret"));
    let mut lax = static4(2);
    lax.dot1x = Some(Dot1xConfig {
        required: false,
        ..Dot1xConfig::new("bob", "secret")
    });
    let options = HostOptions {
        setup_timeout: Duration::from_secs(15),
        ..HostOptions::default()
    };
    let mut engine = HostEngine::new(vec![strict, lax], options).unwrap();
    drive(&mut engine, ms(0), ms(20_000), ms(50), |_, _, _| Vec::new());
    let s = engine.statuses();
    // Required: it keeps asking until the setup times out.
    assert_eq!(s[0].dot1x.clone().unwrap().state, Dot1xState::Connecting);
    assert_eq!(s[0].state, HostState::Failed);
    assert!(
        s[0].error.as_deref().unwrap().contains("802.1X"),
        "{:?}",
        s[0].error
    );
    // Not required: after three EAPOL-Starts it goes on without.
    let d = s[1].dot1x.clone().unwrap();
    assert_eq!(d.state, Dot1xState::NoAuthenticator);
    assert_eq!(d.starts, 3);
    assert_eq!(s[1].state, HostState::Ready);
}

#[test]
fn flow_records_go_to_the_collector_once_it_answers_arp() {
    let mut host = static4(1);
    let mut cfg = FlowExportConfig::new("10.77.0.9:4739".parse().unwrap());
    cfg.records = 5;
    host.flow_export = Some(cfg);
    let mut engine = HostEngine::new(vec![host], HostOptions::default()).unwrap();
    let collector = mac(9);
    let mut arps = 0;
    let mut got = Vec::new();
    let mut answer = false;
    drive(&mut engine, ms(0), ms(3500), ms(10), |p, f, _| {
        let link = wire::parse_link(f).unwrap();
        if link.ethertype == 0x0806 {
            arps += 1;
            if answer {
                let arp = wire::parse_arp(&f[link.payload..]).unwrap();
                return vec![(
                    p,
                    wire::arp_frame(
                        link.src,
                        None,
                        2,
                        collector,
                        arp.target_ip,
                        link.src,
                        arp.sender_ip,
                    ),
                )];
            }
            answer = true;
            return Vec::new();
        }
        if let Some(ip) = wire::parse_ip(&f[link.payload..], true) {
            if let Some(u) = wire::parse_udp(&ip, true) {
                if u.dport == 4739 {
                    assert_eq!(link.dst, collector);
                    got.push(u.data.to_vec());
                }
            }
        }
        Vec::new()
    });
    // The first request goes unanswered, the second a second later is.
    assert_eq!(arps, 2);
    assert!(!got.is_empty());
    assert!(got.iter().all(|p| p[0..2] == [0, 10]));
    let st = engine.statuses()[0].flow_export.clone().unwrap();
    assert_eq!(st.packets as usize, got.len());
    assert_eq!(st.records, 5 * st.packets);
    assert!(!st.waiting);
}
