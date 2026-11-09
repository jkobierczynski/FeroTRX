//! LLDP (IEEE 802.1AB) and CDP (Cisco Discovery Protocol, version 2):
//! hosts announce themselves to switches and list the neighbors they hear.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use super::Me;
use crate::net::be16;
use crate::tcp::wire::{self, pad, push_link};
use crate::{Error, MacAddr, Result};

/// LLDP's nearest-bridge group address.
pub(crate) const LLDP_MAC: MacAddr = MacAddr([0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);
pub(crate) const ETHERTYPE_LLDP: u16 = 0x88cc;
/// CDP's multicast address (with VTP, DTP and others).
pub(crate) const CDP_MAC: MacAddr = MacAddr([0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc]);
const SNAP_CDP: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00];

/// Capabilities by name, with their LLDP bit (802.1AB 8.5.8) and CDP bit.
const CAPABILITIES: [(&str, u16, u32); 8] = [
    ("other", 0x01, 0),
    ("repeater", 0x02, 0x40),
    ("bridge", 0x04, 0x08),
    ("wlan", 0x08, 0),
    ("router", 0x10, 0x01),
    ("telephone", 0x20, 0x80),
    ("docsis", 0x40, 0),
    ("station", 0x80, 0x10),
];

/// What a host announces by LLDP and/or CDP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LldpConfig {
    /// Send LLDP (default on).
    pub lldp: bool,
    /// Send CDP version 2 (default off).
    pub cdp: bool,
    /// System name (default: the host name, else `ferotrx-` and the MAC's
    /// last three bytes).
    pub system_name: Option<String>,
    /// System description (default "FeroTRX emulated host").
    pub description: Option<String>,
    /// Port ID, as an interface name (default: the MAC address).
    pub port_id: Option<String>,
    pub port_description: Option<String>,
    /// CDP platform (default "FeroTRX").
    pub platform: Option<String>,
    /// Capabilities, by name: other, repeater, bridge, wlan, router,
    /// telephone, docsis, station (default station).
    pub capabilities: Vec<String>,
    /// Time between announcements (default 30 s).
    pub interval: Duration,
    /// The time to live is `interval` times this (default 4: 120 s).
    pub hold: u32,
}

impl Default for LldpConfig {
    fn default() -> Self {
        Self {
            lldp: true,
            cdp: false,
            system_name: None,
            description: None,
            port_id: None,
            port_description: None,
            platform: None,
            capabilities: vec!["station".into()],
            interval: Duration::from_secs(30),
            hold: 4,
        }
    }
}

impl LldpConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if !self.lldp && !self.cdp {
            return Err(Error::Host("lldp: turn on lldp, cdp or both".into()));
        }
        if let Some(c) = self
            .capabilities
            .iter()
            .find(|c| !CAPABILITIES.iter().any(|(n, _, _)| n == &c.as_str()))
        {
            return Err(Error::Host(format!(
                "lldp: unknown capability '{c}' (other, repeater, bridge, wlan, router, telephone, docsis, station)"
            )));
        }
        if self.interval < Duration::from_millis(100) || self.hold == 0 {
            return Err(Error::Host(
                "lldp: the interval must be at least 100ms and the hold multiplier at least 1"
                    .into(),
            ));
        }
        for s in [
            &self.system_name,
            &self.description,
            &self.port_id,
            &self.port_description,
            &self.platform,
        ]
        .into_iter()
        .flatten()
        {
            if s.is_empty() || s.len() > 255 {
                return Err(Error::Host(format!(
                    "lldp: '{s}' must be 1 to 255 bytes long"
                )));
            }
        }
        Ok(())
    }

    fn ttl(&self) -> u16 {
        (self.interval.as_secs().max(1) * u64::from(self.hold)).min(65535) as u16
    }

    fn bits(&self) -> (u16, u32) {
        let mut lldp = 0;
        let mut cdp = 0;
        for c in &self.capabilities {
            if let Some((_, l, k)) = CAPABILITIES.iter().find(|(n, _, _)| n == c) {
                lldp |= l;
                cdp |= k;
            }
        }
        (lldp, cdp)
    }
}

/// A neighbor heard by LLDP or CDP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LldpNeighbor {
    /// `lldp` or `cdp`.
    pub protocol: String,
    /// The frames' source MAC.
    pub mac: MacAddr,
    /// Chassis ID (LLDP) or device ID (CDP).
    pub chassis: String,
    pub port: String,
    pub system_name: Option<String>,
    /// System description (LLDP) or software version (CDP).
    pub description: Option<String>,
    /// CDP's platform.
    pub platform: Option<String>,
    /// Enabled capabilities, by name.
    pub capabilities: Vec<String>,
    /// Management addresses.
    pub addresses: Vec<IpAddr>,
    /// The time to live it announced.
    pub ttl: Duration,
    /// Time left before it is forgotten.
    pub remaining: Duration,
    /// Announcements heard.
    pub frames: u64,
}

/// What a host's LLDP/CDP did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LldpStatus {
    pub lldp_sent: u64,
    pub cdp_sent: u64,
    /// LLDP and CDP frames received.
    pub received: u64,
    pub neighbors: Vec<LldpNeighbor>,
}

/// The LLDP/CDP agent of one host.
/// Announcements sent fast at the start and after a new neighbor
/// (802.1AB-2009 txFastInit), and how far apart (msgFastTx).
const FAST_INIT: u32 = 4;
const FAST_TX: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub(crate) struct Lldp {
    cfg: LldpConfig,
    next: Duration,
    /// Fast announcements left (802.1AB txFast).
    fast: u32,
    status: LldpStatus,
    /// Neighbors and when they expire.
    expires: Vec<Duration>,
}

impl Lldp {
    pub fn new(cfg: LldpConfig) -> Self {
        Self {
            cfg,
            next: Duration::ZERO,
            fast: FAST_INIT,
            status: LldpStatus::default(),
            expires: Vec::new(),
        }
    }

    pub fn next_wake(&self) -> Duration {
        self.expires.iter().copied().fold(self.next, Duration::min)
    }

    /// Announcements due now, and neighbors that timed out.
    pub fn poll(&mut self, me: &Me, now: Duration, out: &mut Vec<Vec<u8>>) {
        let mut i = 0;
        while i < self.expires.len() {
            if now >= self.expires[i] {
                self.expires.remove(i);
                self.status.neighbors.remove(i);
            } else {
                i += 1;
            }
        }
        if now < self.next {
            return;
        }
        self.next = if self.fast > 1 {
            now + FAST_TX.min(self.cfg.interval)
        } else {
            now + self.cfg.interval
        };
        self.fast = self.fast.saturating_sub(1);
        self.announce(me, self.cfg.ttl(), out);
    }

    fn announce(&mut self, me: &Me, ttl: u16, out: &mut Vec<Vec<u8>>) {
        if self.cfg.lldp {
            self.status.lldp_sent += 1;
            out.push(lldp_frame(&self.cfg, me, ttl));
        }
        if self.cfg.cdp {
            self.status.cdp_sent += 1;
            out.push(cdp_frame(&self.cfg, me, ttl.min(255) as u8));
        }
    }

    /// Announcements with a time to live of zero, when the host stops.
    pub fn shutdown(&mut self, me: &Me, out: &mut Vec<Vec<u8>>) {
        self.announce(me, 0, out);
    }

    /// Takes an LLDP frame (`ethertype` 0x88cc) or a CDP frame (802.3 with
    /// SNAP); true if it was one.
    pub fn take(&mut self, src: MacAddr, ethertype: u16, payload: &[u8], now: Duration) -> bool {
        let heard = if ethertype == ETHERTYPE_LLDP {
            parse_lldp(src, payload)
        } else if ethertype <= 1500 && payload.starts_with(&SNAP_CDP) {
            parse_cdp(src, &payload[8..])
        } else {
            return false;
        };
        self.status.received += 1;
        let Some(n) = heard else {
            return true;
        };
        let at = self
            .status
            .neighbors
            .iter()
            .position(|o| o.protocol == n.protocol && o.mac == n.mac && o.port == n.port);
        if n.ttl.is_zero() {
            if let Some(i) = at {
                self.status.neighbors.remove(i);
                self.expires.remove(i);
            }
            return true;
        }
        let expires = now + n.ttl;
        match at {
            Some(i) => {
                let frames = self.status.neighbors[i].frames + 1;
                self.status.neighbors[i] = LldpNeighbor { frames, ..n };
                self.expires[i] = expires;
            }
            None => {
                self.status.neighbors.push(LldpNeighbor { frames: 1, ..n });
                self.expires.push(expires);
                // A new neighbor: tell it about us soon (802.1AB fast
                // transmission), so that it need not wait an interval.
                self.fast = FAST_INIT;
                self.next = self.next.min(now + FAST_TX);
            }
        }
        true
    }

    pub fn status(&self, now: Duration) -> LldpStatus {
        let mut s = self.status.clone();
        for (n, e) in s.neighbors.iter_mut().zip(&self.expires) {
            n.remaining = e.saturating_sub(now);
        }
        s
    }
}

fn tlv(out: &mut Vec<u8>, kind: u8, value: &[u8]) {
    let head = (u16::from(kind) << 9) | (value.len() as u16 & 0x1ff);
    out.extend_from_slice(&head.to_be_bytes());
    out.extend_from_slice(value);
}

fn with_subtype(sub: u8, v: &[u8]) -> Vec<u8> {
    let mut x = vec![sub];
    x.extend_from_slice(v);
    x
}

/// An LLDPDU from `me`, with a time to live of `ttl` seconds.
pub(crate) fn lldp_frame(cfg: &LldpConfig, me: &Me, ttl: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(160);
    push_link(&mut f, LLDP_MAC, me.mac, me.vlan, ETHERTYPE_LLDP);
    tlv(&mut f, 1, &with_subtype(4, &me.mac.0)); // chassis: MAC address
    match &cfg.port_id {
        Some(p) => tlv(&mut f, 2, &with_subtype(5, p.as_bytes())), // interface name
        None => tlv(&mut f, 2, &with_subtype(3, &me.mac.0)),       // MAC address
    }
    tlv(&mut f, 3, &ttl.to_be_bytes());
    if let Some(d) = &cfg.port_description {
        tlv(&mut f, 4, d.as_bytes());
    }
    let name = cfg.system_name.clone().unwrap_or_else(|| me.name());
    tlv(&mut f, 5, name.as_bytes());
    tlv(
        &mut f,
        6,
        cfg.description
            .as_deref()
            .unwrap_or("FeroTRX emulated host")
            .as_bytes(),
    );
    let (bits, _) = cfg.bits();
    let mut caps = bits.to_be_bytes().to_vec();
    caps.extend_from_slice(&bits.to_be_bytes());
    tlv(&mut f, 7, &caps);
    let addrs: Vec<IpAddr> = [
        me.ip4.map(|a| IpAddr::V4(a.0)),
        me.ip6.map(|a| IpAddr::V6(a.0)),
    ]
    .into_iter()
    .flatten()
    .collect();
    for a in addrs {
        let (family, bytes) = match a {
            IpAddr::V4(a) => (1u8, a.octets().to_vec()),
            IpAddr::V6(a) => (2u8, a.octets().to_vec()),
        };
        let mut v = vec![(1 + bytes.len()) as u8, family];
        v.extend_from_slice(&bytes);
        v.push(2); // interface numbering: ifIndex
        v.extend_from_slice(&1u32.to_be_bytes());
        v.push(0); // no OID
        tlv(&mut f, 8, &v);
    }
    tlv(&mut f, 0, &[]);
    pad(f)
}

/// The checksum of a CDP packet, with Cisco's handling of an odd last
/// byte (as Wireshark and lldpd check it).
fn cdp_checksum(b: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (words, rest) = b.as_chunks::<2>();
    for w in words {
        sum += u32::from(u16::from_be_bytes(*w));
    }
    if let [v] = rest {
        let v = u32::from(*v);
        if v & 0x80 != 0 {
            sum += (0xff << 8) + v - 1;
        } else {
            sum += v;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    !(sum as u16)
}

fn cdp_tlv(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
    out.extend_from_slice(value);
}

/// A CDPv2 announcement from `me`, with a hold time of `ttl` seconds.
pub(crate) fn cdp_frame(cfg: &LldpConfig, me: &Me, ttl: u8) -> Vec<u8> {
    let mut c = vec![2, ttl, 0, 0];
    let name = cfg.system_name.clone().unwrap_or_else(|| me.name());
    cdp_tlv(&mut c, 0x0001, name.as_bytes());
    let mut addrs = Vec::new();
    let mut count = 0u32;
    if let Some((a, _)) = me.ip4 {
        count += 1;
        addrs.extend_from_slice(&[1, 1, 0xcc, 0, 4]);
        addrs.extend_from_slice(&a.octets());
    }
    if let Some((a, _)) = me.ip6 {
        count += 1;
        addrs.extend_from_slice(&[2, 8, 0xaa, 0xaa, 0x03, 0, 0, 0, 0x86, 0xdd, 0, 16]);
        addrs.extend_from_slice(&a.octets());
    }
    if count > 0 {
        let mut v = count.to_be_bytes().to_vec();
        v.extend_from_slice(&addrs);
        cdp_tlv(&mut c, 0x0002, &v);
    }
    let port = cfg.port_id.clone().unwrap_or_else(|| me.mac.to_string());
    cdp_tlv(&mut c, 0x0003, port.as_bytes());
    let (_, bits) = cfg.bits();
    cdp_tlv(&mut c, 0x0004, &bits.to_be_bytes());
    cdp_tlv(
        &mut c,
        0x0005,
        cfg.description
            .as_deref()
            .unwrap_or("FeroTRX emulated host")
            .as_bytes(),
    );
    cdp_tlv(
        &mut c,
        0x0006,
        cfg.platform.as_deref().unwrap_or("FeroTRX").as_bytes(),
    );
    let sum = cdp_checksum(&c);
    c[2..4].copy_from_slice(&sum.to_be_bytes());
    let mut f = Vec::with_capacity(22 + c.len());
    // 802.3 with a length field: the tag, then the length.
    push_link(&mut f, CDP_MAC, me.mac, me.vlan, (8 + c.len()) as u16);
    f.extend_from_slice(&SNAP_CDP);
    f.extend_from_slice(&c);
    pad(f)
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .trim_end_matches('\0')
        .to_string()
}

fn mac_text(b: &[u8]) -> Option<String> {
    (b.len() == 6).then(|| MacAddr([b[0], b[1], b[2], b[3], b[4], b[5]]).to_string())
}

fn capability_names(lldp: Option<u16>, cdp: Option<u32>) -> Vec<String> {
    CAPABILITIES
        .iter()
        .filter(|(_, l, k)| {
            lldp.is_some_and(|b| b & l != 0) || cdp.is_some_and(|b| *k != 0 && b & k != 0)
        })
        .map(|(n, _, _)| n.to_string())
        .collect()
}

/// An LLDPDU's chassis ID or port ID: MAC and network addresses decoded,
/// names as they are.
fn id_text(sub: u8, v: &[u8]) -> String {
    match (sub, v.len()) {
        (4, 6) => mac_text(v).unwrap_or_default(),
        (3, 6) if v.len() == 6 => mac_text(v).unwrap_or_default(),
        (5, 5) if v[0] == 1 => Ipv4Addr::new(v[1], v[2], v[3], v[4]).to_string(),
        _ => text(v),
    }
}

fn parse_lldp(src: MacAddr, mut p: &[u8]) -> Option<LldpNeighbor> {
    let mut n = LldpNeighbor {
        protocol: "lldp".into(),
        mac: src,
        chassis: String::new(),
        port: String::new(),
        system_name: None,
        description: None,
        platform: None,
        capabilities: Vec::new(),
        addresses: Vec::new(),
        ttl: Duration::ZERO,
        remaining: Duration::ZERO,
        frames: 0,
    };
    let mut seen = 0u8;
    while p.len() >= 2 {
        let head = be16(p, 0)?;
        let kind = (head >> 9) as u8;
        let len = usize::from(head & 0x1ff);
        let v = p.get(2..2 + len)?;
        match kind {
            0 => break,
            1 if !v.is_empty() => {
                n.chassis = id_text(v[0], &v[1..]);
                seen |= 1;
            }
            2 if !v.is_empty() => {
                n.port = id_text(v[0], &v[1..]);
                seen |= 2;
            }
            3 if len >= 2 => {
                n.ttl = Duration::from_secs(u64::from(be16(v, 0)?));
                seen |= 4;
            }
            5 => n.system_name = Some(text(v)),
            6 => n.description = Some(text(v)),
            7 if len >= 4 => n.capabilities = capability_names(Some(be16(v, 2)?), None),
            8 if len >= 2 => {
                let alen = usize::from(v[0]);
                let a = v.get(2..1 + alen)?;
                match (v[1], a.len()) {
                    (1, 4) => n
                        .addresses
                        .push(IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3]))),
                    (2, 16) => {
                        let b: [u8; 16] = a.try_into().ok()?;
                        n.addresses.push(IpAddr::V6(Ipv6Addr::from(b)));
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        p = &p[2 + len..];
    }
    // Chassis ID, port ID and TTL are mandatory, in that order.
    (seen == 7).then_some(n)
}

fn parse_cdp(src: MacAddr, p: &[u8]) -> Option<LldpNeighbor> {
    if p.len() < 4 || !(1..=2).contains(&p[0]) {
        return None;
    }
    let mut n = LldpNeighbor {
        protocol: "cdp".into(),
        mac: src,
        chassis: String::new(),
        port: String::new(),
        system_name: None,
        description: None,
        platform: None,
        capabilities: Vec::new(),
        addresses: Vec::new(),
        ttl: Duration::from_secs(u64::from(p[1])),
        remaining: Duration::ZERO,
        frames: 0,
    };
    let mut o = &p[4..];
    while o.len() >= 4 {
        let kind = be16(o, 0)?;
        let len = usize::from(be16(o, 2)?);
        if len < 4 {
            return None;
        }
        let v = o.get(4..len)?;
        match kind {
            0x0001 => {
                n.chassis = text(v);
                n.system_name = Some(text(v));
            }
            0x0002 if v.len() >= 4 => {
                let mut a = &v[4..];
                while a.len() >= 2 {
                    let plen = usize::from(a[1]);
                    let proto = a.get(2..2 + plen)?;
                    let alen = usize::from(be16(a, 2 + plen)?);
                    let addr = a.get(4 + plen..4 + plen + alen)?;
                    match (proto, alen) {
                        ([0xcc], 4) => n.addresses.push(IpAddr::V4(Ipv4Addr::new(
                            addr[0], addr[1], addr[2], addr[3],
                        ))),
                        ([.., 0x86, 0xdd], 16) => {
                            let b: [u8; 16] = addr.try_into().ok()?;
                            n.addresses.push(IpAddr::V6(Ipv6Addr::from(b)));
                        }
                        _ => {}
                    }
                    a = &a[4 + plen + alen..];
                }
            }
            0x0003 => n.port = text(v),
            0x0004 if v.len() >= 4 => {
                n.capabilities =
                    capability_names(None, Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]])))
            }
            0x0005 => n.description = Some(text(v)),
            0x0006 => n.platform = Some(text(v)),
            _ => {}
        }
        o = &o[len..];
    }
    (!n.chassis.is_empty()).then_some(n)
}

/// The Ethernet type (or 802.3 length) and payload of `frame`.
pub(crate) fn is_ours(link: &wire::Link) -> bool {
    link.ethertype == ETHERTYPE_LLDP || (link.ethertype <= 1500 && link.dst == CDP_MAC)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> Me {
        Me {
            mac: MacAddr([2, 0xdc, 0, 0, 1, 1]),
            vlan: None,
            hostname: Some("lab-1".into()),
            ip4: Some((Ipv4Addr::new(10, 0, 0, 5), 24)),
            gateway4: None,
            ip6: Some(("fd00::5".parse().unwrap(), 64)),
            gateway6: None,
            ll: None,
        }
    }

    #[test]
    fn lldp_and_cdp_round_trip() {
        let cfg = LldpConfig {
            cdp: true,
            port_id: Some("eth0".into()),
            capabilities: vec!["bridge".into(), "router".into()],
            ..LldpConfig::default()
        };
        let me = me();
        let f = lldp_frame(&cfg, &me, 120);
        let link = wire::parse_link(&f).unwrap();
        assert!(is_ours(&link));
        assert_eq!(link.dst, LLDP_MAC);
        let mut a = Lldp::new(LldpConfig::default());
        assert!(a.take(me.mac, link.ethertype, &f[link.payload..], Duration::ZERO));
        let n = &a.status(Duration::from_secs(20)).neighbors[0];
        assert_eq!(n.chassis, "02:dc:00:00:01:01");
        assert_eq!(n.port, "eth0");
        assert_eq!(n.system_name.as_deref(), Some("lab-1"));
        assert_eq!(n.capabilities, vec!["bridge", "router"]);
        assert_eq!(
            n.addresses,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
                "fd00::5".parse::<IpAddr>().unwrap()
            ]
        );
        assert_eq!(n.remaining, Duration::from_secs(100));

        let f = cdp_frame(&cfg, &me, 180);
        let link = wire::parse_link(&f).unwrap();
        assert!(is_ours(&link));
        let p = &f[link.payload..usize::from(link.ethertype) + link.payload];
        assert_eq!(cdp_checksum(&p[8..]), 0, "the checksum adds up");
        assert!(a.take(me.mac, link.ethertype, &f[link.payload..], Duration::ZERO));
        let s = a.status(Duration::ZERO);
        let n = s.neighbors.iter().find(|n| n.protocol == "cdp").unwrap();
        assert_eq!(n.chassis, "lab-1");
        assert_eq!(n.port, "eth0");
        assert_eq!(n.platform.as_deref(), Some("FeroTRX"));
        assert_eq!(n.capabilities, vec!["bridge", "router"]);
        assert_eq!(n.addresses.len(), 2);
        assert_eq!(n.ttl, Duration::from_secs(180));
        // A shutdown (TTL 0) forgets the neighbor; the other times out.
        let mut out = Vec::new();
        let mut b = Lldp::new(cfg.clone());
        b.shutdown(&me, &mut out);
        let link = wire::parse_link(&out[0]).unwrap();
        a.take(
            me.mac,
            link.ethertype,
            &out[0][link.payload..],
            Duration::ZERO,
        );
        assert_eq!(a.status(Duration::ZERO).neighbors.len(), 1);
        a.poll(&me, Duration::from_secs(181), &mut Vec::new());
        assert!(a.status(Duration::ZERO).neighbors.is_empty());
    }

    #[test]
    fn odd_cdp_lengths_use_ciscos_checksum() {
        // An odd last byte with the high bit set (lldpd's test vector style).
        assert_eq!(cdp_checksum(&[0x02, 0xb4, 0x00, 0x00, 0x80]), {
            let sum: u32 = 0x02b4 + 0xff00 + 0x80 - 1;
            let sum = (sum >> 16) + (sum & 0xffff);
            !(sum as u16)
        });
    }
}
