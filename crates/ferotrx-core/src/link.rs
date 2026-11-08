//! A sending port with addresses of its own, as TRex's L3 port mode and
//! Ostinato's emulated devices have: before a run sends, the next hop's MAC
//! is found with ARP or neighbor discovery and put in every frame, and while
//! it runs the port answers ARP, neighbor solicitations and pings for its
//! addresses. [`NeighborPort`] does the protocol work without any I/O;
//! `ferotrx-io` runs it on an interface.

use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use crate::net::{l3_offset, ETHERTYPE_IPV4, ETHERTYPE_IPV6};
use crate::tcp::wire::{self, Path, BROADCAST, ETHERTYPE_ARP};
use crate::{Error, MacAddr, Packet, Result, Transform};

/// An address with its prefix length, written `10.0.0.2/24` or
/// `2001:db8::2/64` (a bare address is a /32 or /128).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpPrefix {
    pub addr: IpAddr,
    pub len: u8,
}

impl IpPrefix {
    /// True when `ip` is on this prefix's subnet.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let m = u32::MAX.checked_shl(32 - u32::from(self.len)).unwrap_or(0);
                u32::from(a) & m == u32::from(b) & m
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let m = u128::MAX
                    .checked_shl(128 - u32::from(self.len))
                    .unwrap_or(0);
                u128::from(a) & m == u128::from(b) & m
            }
            _ => false,
        }
    }
}

impl FromStr for IpPrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let bad = || Error::InvalidSpec(format!("'{s}' is not an address such as 10.0.0.2/24"));
        let (a, len) = match s.trim().split_once('/') {
            Some((a, l)) => (a, Some(l.parse::<u8>().map_err(|_| bad())?)),
            None => (s.trim(), None),
        };
        let addr: IpAddr = a.parse().map_err(|_| bad())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len = len.unwrap_or(max);
        if len > max {
            return Err(bad());
        }
        Ok(Self { addr, len })
    }
}

impl std::fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// A range of addresses `first-last` (or one address) the port answers for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpRange {
    pub first: IpAddr,
    pub last: IpAddr,
}

impl IpRange {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.first, self.last, ip) {
            (IpAddr::V4(a), IpAddr::V4(b), IpAddr::V4(x)) => (a..=b).contains(&x),
            (IpAddr::V6(a), IpAddr::V6(b), IpAddr::V6(x)) => (a..=b).contains(&x),
            _ => false,
        }
    }
}

impl FromStr for IpRange {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let bad = || {
            Error::InvalidSpec(format!(
                "'{s}' is not an address or a range such as 10.0.1.1-10.0.1.254"
            ))
        };
        let (a, b) = s.trim().split_once('-').unwrap_or((s.trim(), s.trim()));
        let first: IpAddr = a.trim().parse().map_err(|_| bad())?;
        let last: IpAddr = b.trim().parse().map_err(|_| bad())?;
        let ordered = match (first, last) {
            (IpAddr::V4(a), IpAddr::V4(b)) => a <= b,
            (IpAddr::V6(a), IpAddr::V6(b)) => a <= b,
            _ => false,
        };
        if !ordered {
            return Err(bad());
        }
        Ok(Self { first, last })
    }
}

impl std::fmt::Display for IpRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.first == self.last {
            write!(f, "{}", self.first)
        } else {
            write!(f, "{}-{}", self.first, self.last)
        }
    }
}

/// What a traffic profile's `[output]` table says about the link beyond how
/// to send: its speed, and the port's own addresses.
///
/// ```toml
/// [output]
/// line_rate = "1gbps"                     # for rates such as "50%"
/// ip = ["10.0.0.2/24", "2001:db8::2/64"]  # the port's addresses
/// gateway = ["10.0.0.1", "2001:db8::1"]   # the next hop of each family
/// mac = "02:00:00:00:00:10"               # default: the interface's MAC
/// vlan = 10                               # ARP and answers on this VLAN
/// answer = ["10.0.1.1-10.0.1.254"]        # more addresses to answer for
/// ```
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LinkSettings {
    /// The line's speed in Mbit/s, for rates that are a share of it.
    pub line_rate: Option<f64>,
    /// The port's addresses, at most one per IP version.
    pub ip: Vec<IpPrefix>,
    /// Next hops whose MAC the frames get, at most one per IP version: a
    /// router, or the receiving host when it is on the port's subnet.
    pub gateway: Vec<IpAddr>,
    /// The port's MAC; default the interface's.
    pub mac: Option<MacAddr>,
    /// The VLAN tag of the port's ARP, neighbor discovery and answers.
    pub vlan: Option<u16>,
    /// More addresses the port answers ARP, solicitations and pings for,
    /// such as the varied source addresses of a stream.
    pub answer: Vec<IpRange>,
}

impl LinkSettings {
    /// True when the port has addresses of its own (and so resolves and answers).
    pub fn has_addresses(&self) -> bool {
        !self.ip.is_empty() || !self.gateway.is_empty() || !self.answer.is_empty()
    }

    /// Fills what is not set here from `fallback`.
    pub fn or(mut self, fallback: &LinkSettings) -> LinkSettings {
        self.line_rate = self.line_rate.or(fallback.line_rate);
        if self.ip.is_empty() {
            self.ip.clone_from(&fallback.ip);
        }
        if self.gateway.is_empty() {
            self.gateway.clone_from(&fallback.gateway);
        }
        self.mac = self.mac.or(fallback.mac);
        self.vlan = self.vlan.or(fallback.vlan);
        if self.answer.is_empty() {
            self.answer.clone_from(&fallback.answer);
        }
        self
    }

    /// Checks that the addresses fit together.
    pub fn validate(&self) -> Result<()> {
        let bad = |m: String| Err(Error::InvalidSpec(m));
        if let Some(r) = self.line_rate {
            if !(r.is_finite() && r > 0.0) {
                return bad(format!("line_rate must be above 0, got {r} Mbit/s"));
            }
        }
        for v4 in [true, false] {
            let fam = if v4 { "IPv4" } else { "IPv6" };
            let ips: Vec<_> = self.ip.iter().filter(|p| p.addr.is_ipv4() == v4).collect();
            let gws: Vec<_> = self.gateway.iter().filter(|g| g.is_ipv4() == v4).collect();
            if ips.len() > 1 {
                return bad(format!(
                    "give one {fam} address for the port, not {}",
                    ips.len()
                ));
            }
            if gws.len() > 1 {
                return bad(format!("give one {fam} gateway, not {}", gws.len()));
            }
            if let (Some(g), None) = (gws.first(), ips.first()) {
                return bad(format!(
                    "gateway {g} needs an {fam} address for the port (ip = \"...\") to ask from"
                ));
            }
        }
        if self.vlan.is_some_and(|v| v == 0 || v > 4094) {
            return bad("vlan must be 1 to 4094".into());
        }
        Ok(())
    }

    /// The port's address of `ip`'s family.
    pub fn ip_for(&self, v4: bool) -> Option<IpPrefix> {
        self.ip.iter().copied().find(|p| p.addr.is_ipv4() == v4)
    }

    /// The gateway of `ip`'s family.
    pub fn gateway_for(&self, v4: bool) -> Option<IpAddr> {
        self.gateway.iter().copied().find(|g| g.is_ipv4() == v4)
    }
}

/// How long [`NeighborPort`] waits between requests to a next hop.
pub const RESOLVE_RETRY: Duration = Duration::from_millis(500);
/// How long it asks before it gives up.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);

/// Counters of a [`NeighborPort`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NeighborStats {
    pub requests_sent: u64,
    pub arp_answered: u64,
    pub nd_answered: u64,
    pub pings_answered: u64,
}

/// The ARP and neighbor discovery of a port with addresses, sans-IO: feed it
/// received frames with [`on_frame`](Self::on_frame), call
/// [`poll`](Self::poll) now and then, and send what both put in `out`.
///
/// ```
/// use ferotrx_core::*;
/// use std::time::Duration;
///
/// let link = LinkSettings {
///     ip: vec!["10.0.0.2/24".parse().unwrap()],
///     gateway: vec!["10.0.0.1".parse().unwrap()],
///     ..Default::default()
/// };
/// let me: MacAddr = "02:00:00:00:00:10".parse().unwrap();
/// let mut port = NeighborPort::new(&link, me).unwrap();
/// let mut out = Vec::new();
/// assert!(!port.poll(Duration::ZERO, &mut out).unwrap());
/// assert_eq!(out.len(), 1); // an ARP request for 10.0.0.1
/// ```
pub struct NeighborPort {
    mac: MacAddr,
    vlan: Option<u16>,
    ips: Vec<IpPrefix>,
    answer: Vec<IpRange>,
    /// Next hops and their MACs once known.
    hops: Vec<(IpAddr, Option<MacAddr>)>,
    next_ask: Duration,
    since: Option<Duration>,
    ip_id: u16,
    stats: NeighborStats,
}

impl NeighborPort {
    pub fn new(link: &LinkSettings, mac: MacAddr) -> Result<Self> {
        link.validate()?;
        Ok(Self {
            mac: link.mac.unwrap_or(mac),
            vlan: link.vlan,
            ips: link.ip.clone(),
            answer: link.answer.clone(),
            hops: link.gateway.iter().map(|g| (*g, None)).collect(),
            next_ask: Duration::ZERO,
            since: None,
            ip_id: 1,
            stats: NeighborStats::default(),
        })
    }

    /// The port's MAC.
    pub fn mac(&self) -> MacAddr {
        self.mac
    }

    /// The MAC of the IPv4 (`v4`) or IPv6 next hop, once known.
    pub fn next_hop(&self, v4: bool) -> Option<MacAddr> {
        self.hops
            .iter()
            .find(|(ip, _)| ip.is_ipv4() == v4)
            .and_then(|(_, m)| *m)
    }

    /// True when every next hop's MAC is known.
    pub fn resolved(&self) -> bool {
        self.hops.iter().all(|(_, m)| m.is_some())
    }

    pub fn stats(&self) -> NeighborStats {
        self.stats
    }

    fn owns(&self, ip: IpAddr) -> bool {
        self.ips.iter().any(|p| p.addr == ip) || self.answer.iter().any(|r| r.contains(ip))
    }

    /// The port's own address to answer from for `ip`'s family.
    fn own(&self, v4: bool) -> Option<IpAddr> {
        self.ips
            .iter()
            .find(|p| p.addr.is_ipv4() == v4)
            .map(|p| p.addr)
    }

    /// Asks for the next hops not known yet. Returns true once all are
    /// known, and an error when one has not answered within [`RESOLVE_TIMEOUT`].
    pub fn poll(&mut self, now: Duration, out: &mut Vec<Vec<u8>>) -> Result<bool> {
        if self.resolved() {
            return Ok(true);
        }
        let since = *self.since.get_or_insert(now);
        let pending: Vec<IpAddr> = self
            .hops
            .iter()
            .filter(|(_, m)| m.is_none())
            .map(|(ip, _)| *ip)
            .collect();
        if now.saturating_sub(since) >= RESOLVE_TIMEOUT {
            let hop = pending[0];
            let what = if hop.is_ipv4() {
                "ARP reply"
            } else {
                "neighbor advertisement"
            };
            let vlan = self
                .vlan
                .map_or("untagged".into(), |v| format!("on VLAN {v}"));
            return Err(Error::InvalidSpec(format!(
                "no {what} from the gateway {hop} ({vlan}) within {RESOLVE_TIMEOUT:?}; check \
                 the gateway address, the VLAN and the cable, or set mac_dst with a rewrite instead"
            )));
        }
        if now >= self.next_ask {
            self.next_ask = now + RESOLVE_RETRY;
            for hop in pending {
                let frame = match (hop, self.own(hop.is_ipv4())) {
                    (IpAddr::V4(hop), Some(IpAddr::V4(me))) => {
                        wire::arp_frame(BROADCAST, self.vlan, 1, self.mac, me, MacAddr([0; 6]), hop)
                    }
                    (IpAddr::V6(hop), Some(IpAddr::V6(me))) => {
                        wire::ndp_solicit(self.mac, self.vlan, me, hop)
                    }
                    _ => continue,
                };
                self.stats.requests_sent += 1;
                out.push(frame);
            }
        }
        Ok(false)
    }

    /// Learns next hops from ARP and neighbor discovery, and answers ARP
    /// requests, neighbor solicitations and pings for the port's addresses.
    pub fn on_frame(&mut self, frame: &[u8], out: &mut Vec<Vec<u8>>) {
        let Some(link) = wire::parse_link(frame) else {
            return;
        };
        if link.vlan != self.vlan || link.src == self.mac {
            return;
        }
        let payload = &frame[link.payload..];
        match link.ethertype {
            ETHERTYPE_ARP => self.on_arp(&link, payload, out),
            ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => {
                let Some(ip) = wire::parse_ip(payload, false) else {
                    return;
                };
                if let Some(nd) = wire::parse_ndp(&ip) {
                    self.on_ndp(&link, &ip, &nd, out);
                } else if self.owns(ip.dst) && (link.dst == self.mac) {
                    let path = Path {
                        src_mac: self.mac,
                        dst_mac: link.src,
                        vlan: self.vlan,
                        src: ip.dst,
                        dst: ip.src,
                    };
                    let echo = (ip.dst.is_ipv4() && ip.proto == 1)
                        || (!ip.dst.is_ipv4() && ip.proto == 58);
                    if echo {
                        if let Some(f) = wire::icmp_echo_reply(&path, ip.payload, self.ip_id) {
                            self.ip_id = self.ip_id.wrapping_add(1);
                            self.stats.pings_answered += 1;
                            out.push(f);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn on_arp(&mut self, _link: &wire::Link, payload: &[u8], out: &mut Vec<Vec<u8>>) {
        let Some(arp) = wire::parse_arp(payload) else {
            return;
        };
        let sender = IpAddr::V4(arp.sender_ip);
        for (hop, mac) in &mut self.hops {
            if *hop == sender && !arp.sender_ip.is_unspecified() {
                *mac = Some(arp.sender_mac);
            }
        }
        if arp.op == 1 && self.owns(arp.target_ip.into()) {
            self.stats.arp_answered += 1;
            out.push(wire::arp_frame(
                arp.sender_mac,
                self.vlan,
                2,
                self.mac,
                arp.target_ip,
                arp.sender_mac,
                arp.sender_ip,
            ));
        }
    }

    fn on_ndp(&mut self, link: &wire::Link, ip: &wire::Ip, nd: &wire::Ndp, out: &mut Vec<Vec<u8>>) {
        let advert = nd.kind == wire::NDP_ADVERT;
        let about = if advert { nd.target } else { ip.src };
        if let Some(mac) = nd.lladdr.or(advert.then_some(link.src)) {
            for (hop, m) in &mut self.hops {
                if *hop == about {
                    *m = Some(mac);
                }
            }
        }
        if !advert && self.owns(nd.target) && !ip.src.is_unspecified() {
            let path = Path {
                src_mac: self.mac,
                dst_mac: nd.lladdr.unwrap_or(link.src),
                vlan: self.vlan,
                src: nd.target,
                dst: ip.src,
            };
            if let Some(f) = wire::ndp_advert(&path) {
                self.stats.nd_answered += 1;
                out.push(f);
            }
        }
    }
}

/// Puts a port's MAC as the source and the next hop's MAC as the
/// destination of every IPv4 and IPv6 frame (by the frame's IP version;
/// frames of a version without a next hop keep theirs). Profiles put it
/// before a stream's own rewrites, so a `mac_dst` rewrite still wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetMacs {
    pub src: MacAddr,
    pub dst4: Option<MacAddr>,
    pub dst6: Option<MacAddr>,
}

impl Transform for SetMacs {
    fn apply(&mut self, packet: &mut Packet) {
        let d = &mut packet.data;
        let Some((_, ethertype)) = l3_offset(d) else {
            return;
        };
        let dst = match ethertype {
            ETHERTYPE_IPV4 => self.dst4,
            ETHERTYPE_IPV6 => self.dst6,
            _ => None,
        };
        if let Some(dst) = dst {
            d[0..6].copy_from_slice(&dst.0);
            d[6..12].copy_from_slice(&self.src.0);
        }
    }
}

/// The port's addresses, gateways, VLAN and answer ranges in one line.
pub fn describe_link(link: &LinkSettings) -> String {
    let mut parts = Vec::new();
    for p in &link.ip {
        parts.push(format!("ip {p}"));
    }
    for g in &link.gateway {
        parts.push(format!("gateway {g}"));
    }
    if let Some(v) = link.vlan {
        parts.push(format!("vlan {v}"));
    }
    for a in &link.answer {
        parts.push(format!("answers {a}"));
    }
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(last: u8) -> MacAddr {
        MacAddr([2, 0, 0, 0, 0, last])
    }

    fn link() -> LinkSettings {
        LinkSettings {
            ip: vec![
                "10.0.0.2/24".parse().unwrap(),
                "2001:db8::2/64".parse().unwrap(),
            ],
            gateway: vec!["10.0.0.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            answer: vec!["10.0.1.1-10.0.1.9".parse().unwrap()],
            ..Default::default()
        }
    }

    #[test]
    fn prefixes_and_ranges_parse() {
        let p: IpPrefix = "10.1.2.3/16".parse().unwrap();
        assert!(p.contains("10.1.200.1".parse().unwrap()));
        assert!(!p.contains("10.2.0.1".parse().unwrap()));
        assert_eq!("2001:db8::1".parse::<IpPrefix>().unwrap().len, 128);
        assert!("10.0.0.1/33".parse::<IpPrefix>().is_err());
        let r: IpRange = "10.0.0.5-10.0.0.9".parse().unwrap();
        assert!(r.contains("10.0.0.7".parse().unwrap()));
        assert!("10.0.0.9-10.0.0.5".parse::<IpRange>().is_err());
        assert!("10.0.0.1-::1".parse::<IpRange>().is_err());
    }

    #[test]
    fn settings_are_checked() {
        assert!(link().validate().is_ok());
        let only_gw = LinkSettings {
            gateway: vec!["10.0.0.1".parse().unwrap()],
            ..Default::default()
        };
        assert!(only_gw.validate().is_err());
        let two = LinkSettings {
            ip: vec![
                "10.0.0.2/24".parse().unwrap(),
                "10.0.0.3/24".parse().unwrap(),
            ],
            ..Default::default()
        };
        assert!(two.validate().is_err());
    }

    #[test]
    fn resolves_both_families_and_answers() {
        let mut port = NeighborPort::new(&link(), mac(0x10)).unwrap();
        let mut out = Vec::new();
        assert!(!port.poll(Duration::ZERO, &mut out).unwrap());
        assert_eq!(out.len(), 2);
        // Asks again only after the retry time.
        out.clear();
        port.poll(Duration::from_millis(100), &mut out).unwrap();
        assert!(out.is_empty());

        // The router answers ARP...
        let reply = wire::arp_frame(
            mac(0x10),
            None,
            2,
            mac(1),
            "10.0.0.1".parse().unwrap(),
            mac(0x10),
            "10.0.0.2".parse().unwrap(),
        );
        port.on_frame(&reply, &mut out);
        assert_eq!(port.next_hop(true), Some(mac(1)));
        assert!(!port.resolved());
        // ...and neighbor discovery.
        let path = Path {
            src_mac: mac(1),
            dst_mac: mac(0x10),
            vlan: None,
            src: "2001:db8::1".parse().unwrap(),
            dst: "2001:db8::2".parse().unwrap(),
        };
        port.on_frame(&wire::ndp_advert(&path).unwrap(), &mut out);
        assert_eq!(port.next_hop(false), Some(mac(1)));
        assert!(port.poll(Duration::from_secs(1), &mut out).unwrap());

        // It answers ARP for its own address and the answer range, not others.
        for (target, answered) in [("10.0.0.2", true), ("10.0.1.5", true), ("10.0.0.3", false)] {
            out.clear();
            let ask = wire::arp_frame(
                BROADCAST,
                None,
                1,
                mac(1),
                "10.0.0.1".parse().unwrap(),
                MacAddr([0; 6]),
                target.parse().unwrap(),
            );
            port.on_frame(&ask, &mut out);
            assert_eq!(out.len(), usize::from(answered), "{target}");
        }
        // And neighbor solicitations for its IPv6 address.
        out.clear();
        let ns = wire::ndp_solicit(
            mac(1),
            None,
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        );
        port.on_frame(&ns, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(port.stats().arp_answered, 2);
        assert_eq!(port.stats().nd_answered, 1);
    }

    #[test]
    fn gives_up_after_the_timeout() {
        let mut port = NeighborPort::new(&link(), mac(0x10)).unwrap();
        let mut out = Vec::new();
        port.poll(Duration::ZERO, &mut out).unwrap();
        let e = port.poll(RESOLVE_TIMEOUT, &mut out).unwrap_err();
        assert!(e.to_string().contains("10.0.0.1"), "{e}");
    }

    #[test]
    fn set_macs_follows_the_ip_version() {
        let mut t = SetMacs {
            src: mac(0x10),
            dst4: Some(mac(4)),
            dst6: None,
        };
        let mut p4 = Packet::new(Duration::ZERO, crate::net::tests::udp4());
        t.apply(&mut p4);
        assert_eq!(&p4.data[0..6], &mac(4).0);
        assert_eq!(&p4.data[6..12], &mac(0x10).0);
        let mut p6 = Packet::new(Duration::ZERO, crate::net::tests::tcp6());
        let before = p6.data.clone();
        t.apply(&mut p6);
        assert_eq!(p6.data, before);
    }
}
