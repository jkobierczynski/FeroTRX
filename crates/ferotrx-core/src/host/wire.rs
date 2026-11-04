//! Frames of host emulation: DHCPv4, DHCPv6, router solicitations and
//! advertisements, duplicate address detection, gratuitous ARP and
//! unsolicited neighbor advertisements, IGMP and MLD.
//!
//! Builders return whole Ethernet frames; parsers take what
//! [`crate::tcp::wire`] already split off (the IP payload).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::net::{be16, ETHERTYPE_IPV4, ETHERTYPE_IPV6, IPPROTO_ICMPV6};
use crate::tcp::wire::{
    self, checksum, multicast_mac, ndp_frame, pad, pseudo_sum, push_link, Path, BROADCAST,
    NDP_ADVERT, NDP_SOLICIT,
};
use crate::MacAddr;

pub(crate) const DHCP_SERVER_PORT: u16 = 67;
pub(crate) const DHCP_CLIENT_PORT: u16 = 68;
pub(crate) const DHCP6_CLIENT_PORT: u16 = 546;
pub(crate) const DHCP6_SERVER_PORT: u16 = 547;
pub(crate) const IPPROTO_IGMP: u8 = 2;

pub(crate) const ICMP6_MLD_QUERY: u8 = 130;
pub(crate) const ICMP6_MLD1_REPORT: u8 = 131;
pub(crate) const ICMP6_MLD1_DONE: u8 = 132;
pub(crate) const ICMP6_RS: u8 = 133;
pub(crate) const ICMP6_RA: u8 = 134;
pub(crate) const ICMP6_MLD2_REPORT: u8 = 143;

/// ff02::1, all nodes.
pub(crate) const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
/// ff02::2, all routers.
pub(crate) const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
/// ff02::16, MLDv2-capable routers.
pub(crate) const MLD2_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16);
/// ff02::1:2, all DHCPv6 relay agents and servers.
pub(crate) const DHCP6_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);
/// 224.0.0.2, all routers.
pub(crate) const IGMP_ALL_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 2);
/// 224.0.0.22, IGMPv3-capable routers.
pub(crate) const IGMP3_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 22);

/// The Ethernet address of an IPv4 multicast group (01:00:5e and its low 23 bits).
pub(crate) fn multicast_mac4(group: Ipv4Addr) -> MacAddr {
    let o = group.octets();
    MacAddr([0x01, 0x00, 0x5e, o[1] & 0x7f, o[2], o[3]])
}

/// The link-local address of `mac`: fe80:: and its modified EUI-64.
pub(crate) fn link_local(mac: MacAddr) -> Ipv6Addr {
    with_eui64(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), mac)
}

/// The first 64 bits of `prefix`, then the modified EUI-64 of `mac` (RFC 4291).
pub(crate) fn with_eui64(prefix: Ipv6Addr, mac: MacAddr) -> Ipv6Addr {
    let m = mac.0;
    let mut o = prefix.octets();
    o[8..].copy_from_slice(&[m[0] ^ 0x02, m[1], m[2], 0xff, 0xfe, m[3], m[4], m[5]]);
    Ipv6Addr::from(o)
}

/// The prefix length of an IPv4 netmask, if it is one.
pub(crate) fn mask_len(mask: Ipv4Addr) -> Option<u8> {
    let m = u32::from(mask);
    let len = m.leading_ones();
    (m.checked_shl(len).unwrap_or(0) == 0).then_some(len as u8)
}

// ---------------------------------------------------------------------------
// DHCPv4 (RFC 2131, 2132)

pub(crate) const DHCPDISCOVER: u8 = 1;
pub(crate) const DHCPOFFER: u8 = 2;
pub(crate) const DHCPREQUEST: u8 = 3;
pub(crate) const DHCPDECLINE: u8 = 4;
pub(crate) const DHCPACK: u8 = 5;
pub(crate) const DHCPNAK: u8 = 6;
pub(crate) const DHCPRELEASE: u8 = 7;

const MAGIC: [u8; 4] = [99, 130, 83, 99];

/// What goes into a DHCPv4 message the client sends.
pub(crate) struct Dhcp4Out<'a> {
    pub kind: u8,
    pub xid: u32,
    pub secs: u16,
    pub mac: MacAddr,
    /// The client's address, when it has one (renewing, rebinding, releasing).
    pub ciaddr: Ipv4Addr,
    pub requested: Option<Ipv4Addr>,
    pub server: Option<Ipv4Addr>,
    pub hostname: Option<&'a str>,
    /// Ask the server to broadcast its answers.
    pub broadcast: bool,
}

/// The BOOTP/DHCP payload of a client message.
pub(crate) fn dhcp4_message(m: &Dhcp4Out) -> Vec<u8> {
    let mut p = Vec::with_capacity(300);
    p.extend_from_slice(&[1, 1, 6, 0]);
    p.extend_from_slice(&m.xid.to_be_bytes());
    p.extend_from_slice(&m.secs.to_be_bytes());
    p.extend_from_slice(&(if m.broadcast { 0x8000u16 } else { 0 }).to_be_bytes());
    p.extend_from_slice(&m.ciaddr.octets());
    p.extend_from_slice(&[0; 12]); // yiaddr, siaddr, giaddr
    p.extend_from_slice(&m.mac.0);
    p.extend_from_slice(&[0; 10 + 64 + 128]); // chaddr padding, sname, file
    p.extend_from_slice(&MAGIC);
    p.extend_from_slice(&[53, 1, m.kind]);
    // Client identifier: hardware type 1 and the MAC.
    p.extend_from_slice(&[61, 7, 1]);
    p.extend_from_slice(&m.mac.0);
    if let Some(ip) = m.requested {
        p.extend_from_slice(&[50, 4]);
        p.extend_from_slice(&ip.octets());
    }
    if let Some(ip) = m.server {
        p.extend_from_slice(&[54, 4]);
        p.extend_from_slice(&ip.octets());
    }
    if let Some(h) = m.hostname.filter(|h| !h.is_empty()) {
        let h = &h.as_bytes()[..h.len().min(255)];
        p.extend_from_slice(&[12, h.len() as u8]);
        p.extend_from_slice(h);
    }
    if m.kind != DHCPRELEASE && m.kind != DHCPDECLINE {
        // Maximum message size, then the parameters wanted: subnet mask,
        // router, DNS servers, lease time, renewal and rebinding times.
        p.extend_from_slice(&[57, 2, 0x05, 0xdc]);
        p.extend_from_slice(&[55, 6, 1, 3, 6, 51, 58, 59]);
    }
    p.push(255);
    if p.len() < 300 {
        p.resize(300, 0);
    }
    p
}

/// A DHCPv4 client message in a frame: broadcast from 0.0.0.0 while the
/// client has no address, else from it to `to` through `to_mac`.
pub(crate) fn dhcp4_frame(
    mac: MacAddr,
    vlan: Option<u16>,
    to: Option<(Ipv4Addr, MacAddr)>,
    m: &Dhcp4Out,
) -> Vec<u8> {
    let (src, dst, dst_mac) = match to {
        Some((ip, to_mac)) => (m.ciaddr, ip, to_mac),
        None => (m.ciaddr, Ipv4Addr::BROADCAST, BROADCAST),
    };
    let path = Path {
        src_mac: mac,
        dst_mac,
        vlan,
        src: src.into(),
        dst: dst.into(),
    };
    wire::udp_frame(
        &path,
        DHCP_CLIENT_PORT,
        DHCP_SERVER_PORT,
        &dhcp4_message(m),
        0,
    )
}

/// A DHCPv4 server message to a client.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Dhcp4In {
    pub kind: u8,
    pub xid: u32,
    pub chaddr: [u8; 6],
    pub yiaddr: Ipv4Addr,
    pub server: Option<Ipv4Addr>,
    pub mask: Option<Ipv4Addr>,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub lease: Option<u32>,
    pub t1: Option<u32>,
    pub t2: Option<u32>,
}

/// Parses a DHCPv4 reply (op 2) with its options.
pub(crate) fn parse_dhcp4(p: &[u8]) -> Option<Dhcp4In> {
    if p.len() < 240 || p[0] != 2 || p[1] != 1 || p[2] != 6 || p[236..240] != MAGIC {
        return None;
    }
    let ip = |b: &[u8]| Ipv4Addr::new(b[0], b[1], b[2], b[3]);
    let u32_at = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    let mut m = Dhcp4In {
        kind: 0,
        xid: u32_at(&p[4..8]),
        chaddr: [0; 6],
        yiaddr: ip(&p[16..20]),
        server: None,
        mask: None,
        router: None,
        dns: Vec::new(),
        lease: None,
        t1: None,
        t2: None,
    };
    m.chaddr.copy_from_slice(&p[28..34]);
    let mut o = &p[240..];
    while let Some(&code) = o.first() {
        match code {
            0 => {
                o = &o[1..];
                continue;
            }
            255 => break,
            _ => {}
        }
        let len = usize::from(*o.get(1)?);
        let v = o.get(2..2 + len)?;
        match (code, len) {
            (53, 1) => m.kind = v[0],
            (54, 4) => m.server = Some(ip(v)),
            (1, 4) => m.mask = Some(ip(v)),
            (3, l) if l >= 4 => m.router = Some(ip(v)),
            (6, l) if l >= 4 => m.dns = v.chunks_exact(4).map(ip).collect(),
            (51, 4) => m.lease = Some(u32_at(v)),
            (58, 4) => m.t1 = Some(u32_at(v)),
            (59, 4) => m.t2 = Some(u32_at(v)),
            _ => {}
        }
        o = &o[2 + len..];
    }
    (m.kind != 0).then_some(m)
}

// ---------------------------------------------------------------------------
// DHCPv6 (RFC 8415)

pub(crate) const DHCP6_SOLICIT: u8 = 1;
pub(crate) const DHCP6_ADVERTISE: u8 = 2;
pub(crate) const DHCP6_REQUEST: u8 = 3;
pub(crate) const DHCP6_RENEW: u8 = 5;
pub(crate) const DHCP6_REBIND: u8 = 6;
pub(crate) const DHCP6_REPLY: u8 = 7;
pub(crate) const DHCP6_RELEASE: u8 = 8;

const OPT_CLIENTID: u16 = 1;
const OPT_SERVERID: u16 = 2;
const OPT_IA_NA: u16 = 3;
const OPT_IAADDR: u16 = 5;
const OPT_ORO: u16 = 6;
const OPT_ELAPSED: u16 = 8;
const OPT_STATUS: u16 = 13;
const OPT_DNS: u16 = 23;

/// The client's DUID: link-layer address type (3), Ethernet, the MAC.
pub(crate) fn duid(mac: MacAddr) -> Vec<u8> {
    let mut d = vec![0, 3, 0, 1];
    d.extend_from_slice(&mac.0);
    d
}

fn opt6(p: &mut Vec<u8>, code: u16, value: &[u8]) {
    p.extend_from_slice(&code.to_be_bytes());
    p.extend_from_slice(&(value.len() as u16).to_be_bytes());
    p.extend_from_slice(value);
}

/// What goes into a DHCPv6 message the client sends.
pub(crate) struct Dhcp6Out<'a> {
    pub kind: u8,
    pub xid: u32,
    pub mac: MacAddr,
    pub iaid: u32,
    /// Hundredths of a second since the exchange began.
    pub elapsed: u16,
    pub server_id: Option<&'a [u8]>,
    /// The address asked for or held.
    pub address: Option<Ipv6Addr>,
}

pub(crate) fn dhcp6_message(m: &Dhcp6Out) -> Vec<u8> {
    let mut p = Vec::with_capacity(96);
    p.push(m.kind);
    p.extend_from_slice(&m.xid.to_be_bytes()[1..]);
    opt6(&mut p, OPT_CLIENTID, &duid(m.mac));
    if let Some(s) = m.server_id {
        opt6(&mut p, OPT_SERVERID, s);
    }
    let mut ia = Vec::with_capacity(40);
    ia.extend_from_slice(&m.iaid.to_be_bytes());
    ia.extend_from_slice(&[0; 8]); // T1, T2: the server's choice
    if let Some(a) = m.address {
        let mut addr = a.octets().to_vec();
        addr.extend_from_slice(&[0; 8]); // lifetimes: the server's choice
        opt6(&mut ia, OPT_IAADDR, &addr);
    }
    opt6(&mut p, OPT_IA_NA, &ia);
    opt6(&mut p, OPT_ELAPSED, &m.elapsed.to_be_bytes());
    if m.kind != DHCP6_RELEASE {
        opt6(&mut p, OPT_ORO, &OPT_DNS.to_be_bytes());
    }
    p
}

/// A DHCPv6 client message from `src` (the link-local address) to all servers.
pub(crate) fn dhcp6_frame(mac: MacAddr, vlan: Option<u16>, src: Ipv6Addr, m: &Dhcp6Out) -> Vec<u8> {
    let path = Path {
        src_mac: mac,
        dst_mac: multicast_mac(DHCP6_SERVERS),
        vlan,
        src: src.into(),
        dst: DHCP6_SERVERS.into(),
    };
    wire::udp_frame(
        &path,
        DHCP6_CLIENT_PORT,
        DHCP6_SERVER_PORT,
        &dhcp6_message(m),
        0,
    )
}

/// A DHCPv6 server message to a client.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Dhcp6In {
    pub kind: u8,
    pub xid: u32,
    pub client_id: Vec<u8>,
    pub server_id: Vec<u8>,
    /// A status code other than success, at the top or in the IA.
    pub status: Option<u16>,
    pub t1: u32,
    pub t2: u32,
    /// The address with its preferred and valid lifetimes.
    pub address: Option<(Ipv6Addr, u32, u32)>,
    pub dns: Vec<Ipv6Addr>,
}

fn options6(mut o: &[u8], mut each: impl FnMut(u16, &[u8])) -> Option<()> {
    while !o.is_empty() {
        let code = be16(o, 0)?;
        let len = usize::from(be16(o, 2)?);
        let v = o.get(4..4 + len)?;
        each(code, v);
        o = &o[4 + len..];
    }
    Some(())
}

pub(crate) fn parse_dhcp6(p: &[u8]) -> Option<Dhcp6In> {
    if p.len() < 4 {
        return None;
    }
    let mut m = Dhcp6In {
        kind: p[0],
        xid: u32::from_be_bytes([0, p[1], p[2], p[3]]),
        ..Default::default()
    };
    let mut ok = true;
    let addr = |b: &[u8]| {
        let mut a = [0u8; 16];
        a.copy_from_slice(&b[..16]);
        Ipv6Addr::from(a)
    };
    let u32_at = |b: &[u8], at: usize| u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    options6(&p[4..], |code, v| match code {
        OPT_CLIENTID => m.client_id = v.to_vec(),
        OPT_SERVERID => m.server_id = v.to_vec(),
        OPT_STATUS if v.len() >= 2 => {
            let s = u16::from_be_bytes([v[0], v[1]]);
            if s != 0 {
                m.status = Some(s);
            }
        }
        OPT_DNS => m.dns = v.chunks_exact(16).map(addr).collect(),
        OPT_IA_NA if v.len() >= 12 => {
            m.t1 = u32_at(v, 4);
            m.t2 = u32_at(v, 8);
            let r = options6(&v[12..], |code, v| match code {
                OPT_IAADDR if v.len() >= 24 => {
                    if m.address.is_none() {
                        m.address = Some((addr(v), u32_at(v, 16), u32_at(v, 20)));
                    }
                }
                OPT_STATUS if v.len() >= 2 => {
                    let s = u16::from_be_bytes([v[0], v[1]]);
                    if s != 0 {
                        m.status = Some(s);
                    }
                }
                _ => {}
            });
            ok &= r.is_some();
        }
        _ => {}
    })?;
    ok.then_some(m)
}

/// The name of a DHCPv6 status code.
pub(crate) fn dhcp6_status(code: u16) -> &'static str {
    match code {
        1 => "UnspecFail",
        2 => "NoAddrsAvail",
        3 => "NoBinding",
        4 => "NotOnLink",
        5 => "UseMulticast",
        6 => "NoPrefixAvail",
        _ => "unknown status",
    }
}

// ---------------------------------------------------------------------------
// Router discovery (RFC 4861)

/// A router solicitation from `src` (link-local) with the source link-layer option.
pub(crate) fn router_solicit(mac: MacAddr, vlan: Option<u16>, src: Ipv6Addr) -> Vec<u8> {
    let path = Path {
        src_mac: mac,
        dst_mac: multicast_mac(ALL_ROUTERS),
        vlan,
        src: src.into(),
        dst: ALL_ROUTERS.into(),
    };
    let mut body = vec![ICMP6_RS, 0, 0, 0, 0, 0, 0, 0, 1, 1];
    body.extend_from_slice(&mac.0);
    icmp6_frame(&path, 255, &body, false)
}

/// A prefix in a router advertisement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PrefixInfo {
    pub prefix: Ipv6Addr,
    pub len: u8,
    /// On-link (L).
    pub on_link: bool,
    /// For address autoconfiguration (A).
    pub autonomous: bool,
    pub valid: u32,
    pub preferred: u32,
}

/// A received router advertisement.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RouterAdvert {
    pub managed: bool,
    pub other: bool,
    pub lifetime: u16,
    pub lladdr: Option<MacAddr>,
    pub mtu: Option<u32>,
    pub prefixes: Vec<PrefixInfo>,
}

/// Parses a router advertisement, with the checks RFC 4861 asks for: a
/// link-local source, hop limit 255, code 0, the checksum.
pub(crate) fn parse_ra(ip: &wire::Ip) -> Option<RouterAdvert> {
    let p = ip.payload;
    let IpAddr::V6(src) = ip.src else {
        return None;
    };
    if ip.proto != IPPROTO_ICMPV6
        || p.len() < 16
        || p[0] != ICMP6_RA
        || p[1] != 0
        || ip.hop_limit != 255
        || !is_link_local(src)
        || checksum(p, pseudo_sum(ip.src, ip.dst, IPPROTO_ICMPV6, p.len())) != 0
    {
        return None;
    }
    let mut ra = RouterAdvert {
        managed: p[5] & 0x80 != 0,
        other: p[5] & 0x40 != 0,
        lifetime: be16(p, 6)?,
        lladdr: None,
        mtu: None,
        prefixes: Vec::new(),
    };
    let mut o = &p[16..];
    while o.len() >= 8 {
        let len = usize::from(o[1]) * 8;
        if len == 0 || len > o.len() {
            return None;
        }
        let u32_at = |at: usize| u32::from_be_bytes([o[at], o[at + 1], o[at + 2], o[at + 3]]);
        match (o[0], len) {
            (1, 8) => ra.lladdr = Some(MacAddr([o[2], o[3], o[4], o[5], o[6], o[7]])),
            (5, 8) => ra.mtu = Some(u32_at(4)),
            (3, 32) => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&o[16..32]);
                ra.prefixes.push(PrefixInfo {
                    prefix: Ipv6Addr::from(a),
                    len: o[2],
                    on_link: o[3] & 0x80 != 0,
                    autonomous: o[3] & 0x40 != 0,
                    valid: u32_at(4),
                    preferred: u32_at(8),
                });
            }
            _ => {}
        }
        o = &o[len..];
    }
    Some(ra)
}

/// True for a router solicitation (with the RFC 4861 checks).
pub(crate) fn is_rs(ip: &wire::Ip) -> bool {
    let p = ip.payload;
    ip.proto == IPPROTO_ICMPV6
        && p.len() >= 8
        && p[0] == ICMP6_RS
        && p[1] == 0
        && ip.hop_limit == 255
        && checksum(p, pseudo_sum(ip.src, ip.dst, IPPROTO_ICMPV6, p.len())) == 0
}

/// What an emulated router advertises.
pub(crate) struct AdvertOut<'a> {
    pub managed: bool,
    pub other: bool,
    pub lifetime: u16,
    pub prefixes: &'a [(Ipv6Addr, u8)],
    pub valid: u32,
    pub preferred: u32,
}

/// A router advertisement from `src` (link-local) to all nodes.
pub(crate) fn router_advert(
    mac: MacAddr,
    vlan: Option<u16>,
    src: Ipv6Addr,
    a: &AdvertOut,
) -> Vec<u8> {
    let path = Path {
        src_mac: mac,
        dst_mac: multicast_mac(ALL_NODES),
        vlan,
        src: src.into(),
        dst: ALL_NODES.into(),
    };
    let flags = if a.managed { 0x80 } else { 0 } | if a.other { 0x40 } else { 0 };
    let mut b = vec![ICMP6_RA, 0, 0, 0, 64, flags];
    b.extend_from_slice(&a.lifetime.to_be_bytes());
    b.extend_from_slice(&[0; 8]); // reachable time, retransmission timer: unspecified
    b.extend_from_slice(&[1, 1]);
    b.extend_from_slice(&mac.0);
    for (prefix, len) in a.prefixes {
        b.extend_from_slice(&[3, 4, *len, 0xc0]); // on-link, autonomous
        b.extend_from_slice(&a.valid.to_be_bytes());
        b.extend_from_slice(&a.preferred.to_be_bytes());
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&mask6(*prefix, *len).octets());
    }
    icmp6_frame(&path, 255, &b, false)
}

/// `a` with all but its first `len` bits cleared.
pub(crate) fn mask6(a: Ipv6Addr, len: u8) -> Ipv6Addr {
    let len = u32::from(len.min(128));
    let mask = if len == 0 {
        0
    } else {
        u128::MAX << (128 - len)
    };
    Ipv6Addr::from(u128::from(a) & mask)
}

pub(crate) fn is_link_local(a: Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

// ---------------------------------------------------------------------------
// Neighbor discovery extras: duplicate address detection, unsolicited adverts

/// A duplicate address detection probe: a solicitation for `target` from
/// the unspecified address, without a link-layer option (RFC 4862).
pub(crate) fn dad_solicit(mac: MacAddr, vlan: Option<u16>, target: Ipv6Addr) -> Vec<u8> {
    let group = wire::solicited_node(target);
    let path = Path {
        src_mac: mac,
        dst_mac: multicast_mac(group),
        vlan,
        src: Ipv6Addr::UNSPECIFIED.into(),
        dst: group.into(),
    };
    let mut b = vec![NDP_SOLICIT, 0, 0, 0, 0, 0, 0, 0];
    b.extend_from_slice(&target.octets());
    icmp6_frame(&path, 255, &b, false)
}

/// An unsolicited neighbor advertisement (override set, solicited clear) for
/// `target` at `mac`, to all nodes.
pub(crate) fn unsolicited_advert(mac: MacAddr, vlan: Option<u16>, target: Ipv6Addr) -> Vec<u8> {
    let path = Path {
        src_mac: mac,
        dst_mac: multicast_mac(ALL_NODES),
        vlan,
        src: target.into(),
        dst: ALL_NODES.into(),
    };
    ndp_frame(&path, NDP_ADVERT, 0x20, target, mac)
}

/// A gratuitous ARP: a request for the sender's own address, to everyone.
pub(crate) fn gratuitous_arp(mac: MacAddr, vlan: Option<u16>, ip: Ipv4Addr) -> Vec<u8> {
    wire::arp_frame(BROADCAST, vlan, 1, mac, ip, MacAddr([0; 6]), ip)
}

// ---------------------------------------------------------------------------
// IGMP (RFC 2236, 3376) and MLD (RFC 2710, 3810)

/// A received IGMP or MLD query.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Query {
    /// IGMP 1-3 or MLD 1-2.
    pub version: u8,
    /// The group asked about; unspecified for a general query.
    pub group: IpAddr,
    pub max_response: Duration,
}

/// Parses an IGMP query (the IPv4 payload of protocol 2), checking its checksum.
pub(crate) fn parse_igmp_query(p: &[u8]) -> Option<Query> {
    if p.len() < 8 || p[0] != 0x11 || checksum(p, 0) != 0 {
        return None;
    }
    let group = IpAddr::V4(Ipv4Addr::new(p[4], p[5], p[6], p[7]));
    let (version, max_response) = if p.len() >= 12 {
        // IGMPv3: max response code in tenths of a second, exponential above 127.
        let code = u32::from(p[1]);
        let tenths = if code < 128 {
            code
        } else {
            ((code & 0x0f) | 0x10) << (((code >> 4) & 0x07) + 3)
        };
        (3, Duration::from_millis(u64::from(tenths) * 100))
    } else if p[1] == 0 {
        (1, Duration::from_secs(10))
    } else {
        (2, Duration::from_millis(u64::from(p[1]) * 100))
    };
    Some(Query {
        version,
        group,
        max_response,
    })
}

/// Parses an MLD query (ICMPv6 type 130), checking its checksum.
pub(crate) fn parse_mld_query(ip: &wire::Ip) -> Option<Query> {
    let p = ip.payload;
    if ip.proto != IPPROTO_ICMPV6
        || p.len() < 24
        || p[0] != ICMP6_MLD_QUERY
        || checksum(p, pseudo_sum(ip.src, ip.dst, IPPROTO_ICMPV6, p.len())) != 0
    {
        return None;
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(&p[8..24]);
    let code = u32::from(be16(p, 4)?);
    let (version, ms) = if p.len() >= 28 {
        let ms = if code < 32768 {
            code
        } else {
            ((code & 0x0fff) | 0x1000) << (((code >> 12) & 0x07) + 3)
        };
        (2, ms)
    } else {
        (1, code)
    };
    Some(Query {
        version,
        group: IpAddr::V6(Ipv6Addr::from(a)),
        max_response: Duration::from_millis(u64::from(ms)),
    })
}

/// Group record types of IGMPv3 and MLDv2 reports.
pub(crate) const MODE_IS_EXCLUDE: u8 = 2;
pub(crate) const CHANGE_TO_INCLUDE: u8 = 3;
pub(crate) const CHANGE_TO_EXCLUDE: u8 = 4;

/// An IPv4 datagram with the router alert option, TTL 1 (for IGMP).
fn igmp_datagram(
    mac: MacAddr,
    vlan: Option<u16>,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    body: &[u8],
) -> Vec<u8> {
    let mut f = Vec::with_capacity(18 + 24 + body.len());
    push_link(&mut f, multicast_mac4(dst), mac, vlan, ETHERTYPE_IPV4);
    let start = f.len();
    let total = (24 + body.len()) as u16;
    f.extend_from_slice(&[0x46, 0xc0]);
    f.extend_from_slice(&total.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0, 1, IPPROTO_IGMP, 0, 0]);
    f.extend_from_slice(&src.octets());
    f.extend_from_slice(&dst.octets());
    f.extend_from_slice(&[0x94, 0x04, 0, 0]); // router alert
    let sum = checksum(&f[start..start + 24], 0);
    f[start + 10..start + 12].copy_from_slice(&sum.to_be_bytes());
    let body_at = f.len();
    f.extend_from_slice(body);
    let sum = checksum(&f[body_at..], 0);
    f[body_at + 2..body_at + 4].copy_from_slice(&sum.to_be_bytes());
    pad(f)
}

/// An IGMP report of `version` for `group`, or a leave (`join` false).
pub(crate) fn igmp_report(
    mac: MacAddr,
    vlan: Option<u16>,
    src: Ipv4Addr,
    group: Ipv4Addr,
    version: u8,
    record: u8,
) -> Vec<u8> {
    let leave = record == CHANGE_TO_INCLUDE;
    match version {
        1 | 2 if leave && version == 2 => igmp_datagram(
            mac,
            vlan,
            src,
            IGMP_ALL_ROUTERS,
            &[&[0x17, 0, 0, 0][..], &group.octets()].concat(),
        ),
        1 | 2 => {
            let kind = if version == 1 { 0x12 } else { 0x16 };
            igmp_datagram(
                mac,
                vlan,
                src,
                group,
                &[&[kind, 0, 0, 0][..], &group.octets()].concat(),
            )
        }
        _ => {
            let mut b = vec![0x22, 0, 0, 0, 0, 0, 0, 1, record, 0, 0, 0];
            b.extend_from_slice(&group.octets());
            igmp_datagram(mac, vlan, src, IGMP3_ROUTERS, &b)
        }
    }
}

/// An MLD report of `version` for `group`, or a done (`record` CHANGE_TO_INCLUDE).
pub(crate) fn mld_report(
    mac: MacAddr,
    vlan: Option<u16>,
    src: Ipv6Addr,
    group: Ipv6Addr,
    version: u8,
    record: u8,
) -> Vec<u8> {
    let leave = record == CHANGE_TO_INCLUDE;
    let (dst, body) = if version == 1 {
        let (kind, dst) = if leave {
            (ICMP6_MLD1_DONE, ALL_ROUTERS)
        } else {
            (ICMP6_MLD1_REPORT, group)
        };
        let mut b = vec![kind, 0, 0, 0, 0, 0, 0, 0];
        b.extend_from_slice(&group.octets());
        (dst, b)
    } else {
        let mut b = vec![ICMP6_MLD2_REPORT, 0, 0, 0, 0, 0, 0, 1, record, 0, 0, 0];
        b.extend_from_slice(&group.octets());
        (MLD2_ROUTERS, b)
    };
    let path = Path {
        src_mac: mac,
        dst_mac: multicast_mac(dst),
        vlan,
        src: src.into(),
        dst: dst.into(),
    };
    icmp6_frame(&path, 1, &body, true)
}

/// An ICMPv6 message on `path` with its checksum filled in; `router_alert`
/// puts a hop-by-hop header with the MLD router alert in front.
fn icmp6_frame(path: &Path, hop_limit: u8, body: &[u8], router_alert: bool) -> Vec<u8> {
    let (IpAddr::V6(src), IpAddr::V6(dst)) = (path.src, path.dst) else {
        unreachable!("ICMPv6 needs IPv6 addresses");
    };
    let ext = if router_alert { 8 } else { 0 };
    let mut f = Vec::with_capacity(18 + 40 + ext + body.len());
    push_link(
        &mut f,
        path.dst_mac,
        path.src_mac,
        path.vlan,
        ETHERTYPE_IPV6,
    );
    f.extend_from_slice(&[0x60, 0, 0, 0]);
    f.extend_from_slice(&((ext + body.len()) as u16).to_be_bytes());
    f.push(if router_alert { 0 } else { IPPROTO_ICMPV6 });
    f.push(hop_limit);
    f.extend_from_slice(&src.octets());
    f.extend_from_slice(&dst.octets());
    if router_alert {
        f.extend_from_slice(&[IPPROTO_ICMPV6, 0, 5, 2, 0, 0, 1, 0]);
    }
    let at = f.len();
    f.extend_from_slice(body);
    let sum = checksum(
        &f[at..],
        pseudo_sum(path.src, path.dst, IPPROTO_ICMPV6, body.len()),
    );
    f[at + 2..at + 4].copy_from_slice(&sum.to_be_bytes());
    pad(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::wire::{parse_ip, parse_link, parse_udp};

    const MAC: MacAddr = MacAddr([0x02, 0xdc, 0, 0, 0, 1]);

    fn ip_of(frame: &[u8]) -> wire::Ip<'_> {
        let link = parse_link(frame).unwrap();
        parse_ip(&frame[link.payload..], true).unwrap()
    }

    #[test]
    fn eui64_and_link_local() {
        assert_eq!(
            link_local(MAC),
            "fe80::dc:ff:fe00:1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            with_eui64(
                "fd00:77::".parse().unwrap(),
                MacAddr([0, 0x11, 0x22, 0x33, 0x44, 0x55])
            ),
            "fd00:77::211:22ff:fe33:4455".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(mask_len(Ipv4Addr::new(255, 255, 255, 0)), Some(24));
        assert_eq!(mask_len(Ipv4Addr::new(255, 255, 255, 255)), Some(32));
        assert_eq!(mask_len(Ipv4Addr::new(0, 0, 0, 0)), Some(0));
        assert_eq!(mask_len(Ipv4Addr::new(255, 0, 255, 0)), None);
        assert_eq!(
            multicast_mac4(Ipv4Addr::new(239, 129, 2, 3)).0,
            [1, 0, 0x5e, 1, 2, 3]
        );
    }

    #[test]
    fn dhcp4_discover_is_a_broadcast_with_options() {
        let m = Dhcp4Out {
            kind: DHCPDISCOVER,
            xid: 0x01020304,
            secs: 0,
            mac: MAC,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            requested: None,
            server: None,
            hostname: Some("h1"),
            broadcast: false,
        };
        let f = dhcp4_frame(MAC, Some(10), None, &m);
        let link = parse_link(&f).unwrap();
        assert_eq!(link.dst, BROADCAST);
        assert_eq!(link.vlan, Some(10));
        let ip = parse_ip(&f[link.payload..], true).unwrap();
        assert_eq!(ip.src, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(ip.dst, IpAddr::V4(Ipv4Addr::BROADCAST));
        let udp = parse_udp(&ip, true).unwrap();
        assert_eq!((udp.sport, udp.dport), (68, 67));
        assert_eq!(udp.data.len(), 300);
        assert_eq!(&udp.data[236..243], &[99, 130, 83, 99, 53, 1, 1]);
        assert!(udp.data.windows(4).any(|w| w == [12, 2, b'h', b'1']));
    }

    fn server_reply(kind: u8, xid: u32) -> Vec<u8> {
        let mut p = vec![2, 1, 6, 0];
        p.extend_from_slice(&xid.to_be_bytes());
        p.extend_from_slice(&[0; 8]);
        p.extend_from_slice(&[10, 77, 0, 150]); // yiaddr
        p.extend_from_slice(&[0; 8]);
        p.extend_from_slice(&MAC.0);
        p.extend_from_slice(&[0; 10 + 192]);
        p.extend_from_slice(&MAGIC);
        p.extend_from_slice(&[53, 1, kind, 54, 4, 10, 77, 0, 1, 1, 4, 255, 255, 255, 0]);
        p.extend_from_slice(&[3, 4, 10, 77, 0, 1, 6, 8, 10, 77, 0, 1, 8, 8, 8, 8]);
        p.extend_from_slice(&[51, 4, 0, 0, 0x0e, 0x10, 0, 0, 255]);
        p
    }

    #[test]
    fn dhcp4_reply_options() {
        let m = parse_dhcp4(&server_reply(DHCPACK, 7)).unwrap();
        assert_eq!(m.kind, DHCPACK);
        assert_eq!(m.xid, 7);
        assert_eq!(m.chaddr, MAC.0);
        assert_eq!(m.yiaddr, Ipv4Addr::new(10, 77, 0, 150));
        assert_eq!(m.server, Some(Ipv4Addr::new(10, 77, 0, 1)));
        assert_eq!(m.mask.and_then(mask_len), Some(24));
        assert_eq!(m.router, Some(Ipv4Addr::new(10, 77, 0, 1)));
        assert_eq!(
            m.dns,
            vec![Ipv4Addr::new(10, 77, 0, 1), Ipv4Addr::new(8, 8, 8, 8)]
        );
        assert_eq!(m.lease, Some(3600));
        assert_eq!(m.t1, None);
        assert!(parse_dhcp4(&server_reply(DHCPACK, 7)[..200]).is_none());
    }

    #[test]
    fn dhcp6_round_trip() {
        let sid = [0, 1, 0, 1, 9, 9, 9, 9];
        let m = Dhcp6Out {
            kind: DHCP6_REQUEST,
            xid: 0xabcdef,
            mac: MAC,
            iaid: 5,
            elapsed: 12,
            server_id: Some(&sid),
            address: Some("fd00:77::150".parse().unwrap()),
        };
        let f = dhcp6_frame(MAC, None, link_local(MAC), &m);
        let ip = ip_of(&f);
        assert_eq!(ip.dst, IpAddr::V6(DHCP6_SERVERS));
        let udp = parse_udp(&ip, true).unwrap();
        assert_eq!((udp.sport, udp.dport), (546, 547));
        // What the client sent parses as a message too, with the same parts.
        let back = parse_dhcp6(udp.data).unwrap();
        assert_eq!(back.kind, DHCP6_REQUEST);
        assert_eq!(back.xid, 0xabcdef);
        assert_eq!(back.client_id, duid(MAC));
        assert_eq!(back.server_id, sid);
        assert_eq!(
            back.address.map(|a| a.0),
            Some("fd00:77::150".parse().unwrap())
        );
        assert_eq!(back.status, None);
    }

    #[test]
    fn router_advert_round_trip() {
        let prefixes = [("fd00:99::1".parse().unwrap(), 64)];
        let f = router_advert(
            MAC,
            None,
            link_local(MAC),
            &AdvertOut {
                managed: true,
                other: false,
                lifetime: 1800,
                prefixes: &prefixes,
                valid: 86400,
                preferred: 14400,
            },
        );
        let ip = ip_of(&f);
        let ra = parse_ra(&ip).unwrap();
        assert!(ra.managed && !ra.other);
        assert_eq!(ra.lifetime, 1800);
        assert_eq!(ra.lladdr, Some(MAC));
        assert_eq!(
            ra.prefixes,
            vec![PrefixInfo {
                prefix: "fd00:99::".parse().unwrap(),
                len: 64,
                on_link: true,
                autonomous: true,
                valid: 86400,
                preferred: 14400
            }]
        );
        let rs = router_solicit(MAC, None, link_local(MAC));
        assert!(is_rs(&ip_of(&rs)));
        assert!(!is_rs(&ip));
    }

    #[test]
    fn dad_and_unsolicited_adverts_parse_as_ndp() {
        let target: Ipv6Addr = "fd00:77::5".parse().unwrap();
        let f = dad_solicit(MAC, None, target);
        let ip = ip_of(&f);
        assert!(ip.src.is_unspecified());
        let nd = wire::parse_ndp(&ip).unwrap();
        assert_eq!(
            (nd.kind, nd.target, nd.lladdr),
            (NDP_SOLICIT, target.into(), None)
        );
        let f = unsolicited_advert(MAC, None, target);
        let ip = ip_of(&f);
        assert_eq!(ip.dst, IpAddr::V6(ALL_NODES));
        let nd = wire::parse_ndp(&ip).unwrap();
        assert_eq!((nd.kind, nd.lladdr), (NDP_ADVERT, Some(MAC)));
    }

    #[test]
    fn igmp_reports_carry_router_alert_and_checksums() {
        let src = Ipv4Addr::new(10, 77, 0, 150);
        let group = Ipv4Addr::new(239, 1, 2, 3);
        for (version, dst) in [(2, group), (3, IGMP3_ROUTERS)] {
            let f = igmp_report(MAC, None, src, group, version, CHANGE_TO_EXCLUDE);
            let link = parse_link(&f).unwrap();
            assert_eq!(link.dst, multicast_mac4(dst));
            let ip = parse_ip(&f[link.payload..], true).unwrap();
            assert_eq!((ip.proto, ip.hop_limit, ip.dst), (2, 1, IpAddr::V4(dst)));
            assert_eq!(checksum(ip.payload, 0), 0);
        }
        let leave = igmp_report(MAC, None, src, group, 2, CHANGE_TO_INCLUDE);
        assert_eq!(ip_of(&leave).dst, IpAddr::V4(IGMP_ALL_ROUTERS));
    }

    #[test]
    fn igmp_queries_by_version() {
        let mut v2 = vec![0x11, 100, 0, 0, 0, 0, 0, 0];
        let s = checksum(&v2, 0);
        v2[2..4].copy_from_slice(&s.to_be_bytes());
        let q = parse_igmp_query(&v2).unwrap();
        assert_eq!((q.version, q.max_response), (2, Duration::from_secs(10)));
        assert!(q.group.is_unspecified());
        let mut v3 = vec![0x11, 0x8a, 0, 0, 239, 1, 2, 3, 0, 0, 0, 0];
        let s = checksum(&v3, 0);
        v3[2..4].copy_from_slice(&s.to_be_bytes());
        let q = parse_igmp_query(&v3).unwrap();
        // 0x8a: mantissa 10, exponent 0: (10 | 16) << 3 = 208 tenths.
        assert_eq!(
            (q.version, q.max_response),
            (3, Duration::from_millis(20800))
        );
        assert_eq!(q.group, IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)));
        v3[5] = 9;
        assert!(parse_igmp_query(&v3).is_none());
    }

    #[test]
    fn mld_reports_have_a_hop_by_hop_router_alert() {
        let group: Ipv6Addr = "ff15::1234".parse().unwrap();
        for version in [1, 2] {
            let f = mld_report(
                MAC,
                None,
                link_local(MAC),
                group,
                version,
                CHANGE_TO_EXCLUDE,
            );
            let ip = ip_of(&f);
            assert_eq!((ip.proto, ip.hop_limit), (IPPROTO_ICMPV6, 1));
            assert_eq!(
                checksum(
                    ip.payload,
                    pseudo_sum(ip.src, ip.dst, IPPROTO_ICMPV6, ip.payload.len())
                ),
                0
            );
            let kind = if version == 1 {
                ICMP6_MLD1_REPORT
            } else {
                ICMP6_MLD2_REPORT
            };
            assert_eq!(ip.payload[0], kind);
        }
    }
}
