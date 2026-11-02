//! Packet building: describe a packet layer by layer, get its bytes back with
//! every length, type and checksum filled in.
//!
//! A [`PacketSpec`] is a stack of [`LayerSpec`]s, outermost first. Build one in
//! code from the layer structs, or parse the text form (see [`PacketSpec`]'s
//! `FromStr`), which is what the command line and profiles use:
//!
//! ```
//! use ferotrx_packet::{PacketSpec, decode};
//!
//! let spec: PacketSpec = "eth(dst=02:00:00:00:00:01)/vlan(id=10)\
//!     /ipv4(src=192.168.10.100,dst=192.168.20.50)/udp/dns(q=example.com)"
//!     .parse()
//!     .unwrap();
//! let frame = spec.build().unwrap();
//! let d = decode(spec.linktype().unwrap(), &frame);
//! assert_eq!(d.protocol, "DNS");
//! assert_eq!(d.info, "Standard query 0x0001 A example.com");
//! assert!(d.problems.is_empty()); // checksums and lengths are right
//! ```
//!
//! Fields left out get a sensible value: Ethernet and IP types, IP protocol,
//! lengths and checksums follow from the layers, and ports follow from DNS.
//! Setting a field such as `chksum` or `len` explicitly keeps that value, so
//! deliberately broken packets can be built too.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{ones_sum, LINKTYPE_ETHERNET, LINKTYPE_RAW};

/// Why a packet could not be built or its description could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildError(pub String);

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BuildError {}

pub(crate) fn err<T>(msg: impl Into<String>) -> Result<T, BuildError> {
    Err(BuildError(msg.into()))
}

/// Ethernet frames shorter than this (without FCS) are padded with zeros.
pub const ETH_MIN_FRAME: usize = 60;

/// Ethertype used when nothing after the Ethernet header implies one
/// (IEEE local experimental ethertype 1).
pub const ETHERTYPE_EXPERIMENTAL: u16 = 0x88b5;

/// IP protocol used when nothing after the IP header implies one
/// (RFC 3692 experimentation and testing).
pub const IPPROTO_EXPERIMENTAL: u8 = 253;

/// Ethernet II header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ethernet {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    /// Ethertype; `None` takes it from the next layer.
    pub ethertype: Option<u16>,
    /// Pad the frame to 60 bytes, as a network card would.
    pub pad: bool,
}

impl Default for Ethernet {
    fn default() -> Self {
        Self {
            dst: [0x02, 0, 0, 0, 0, 0x02],
            src: [0x02, 0, 0, 0, 0, 0xfe],
            ethertype: None,
            pad: true,
        }
    }
}

/// 802.1Q VLAN tag, or 802.1ad service tag with `tpid` 0x88a8.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vlan {
    pub id: u16,
    pub pcp: u8,
    pub dei: bool,
    /// The tag protocol identifier written in the header in front of this tag.
    pub tpid: u16,
    /// Ethertype after the tag; `None` takes it from the next layer.
    pub ethertype: Option<u16>,
}

impl Default for Vlan {
    fn default() -> Self {
        Self {
            id: 1,
            pcp: 0,
            dei: false,
            tpid: 0x8100,
            ethertype: None,
        }
    }
}

/// ARP for IPv4 over Ethernet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arp {
    /// 1 request, 2 reply.
    pub op: u16,
    /// Sender MAC; `None` copies the Ethernet source.
    pub sender_mac: Option<[u8; 6]>,
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

impl Default for Arp {
    fn default() -> Self {
        Self {
            op: 1,
            sender_mac: None,
            sender_ip: Ipv4Addr::new(192, 0, 2, 1),
            target_mac: [0; 6],
            target_ip: Ipv4Addr::new(192, 0, 2, 2),
        }
    }
}

/// IPv4 header without options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv4 {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub dscp: u8,
    pub ecn: u8,
    pub id: u16,
    pub df: bool,
    pub mf: bool,
    /// Fragment offset in bytes; a multiple of 8.
    pub frag_offset: u16,
    pub ttl: u8,
    /// `None` takes it from the next layer.
    pub proto: Option<u8>,
    /// Total length; `None` computes it.
    pub len: Option<u16>,
    /// Header checksum; `None` computes it.
    pub checksum: Option<u16>,
}

impl Default for Ipv4 {
    fn default() -> Self {
        Self {
            src: Ipv4Addr::new(192, 0, 2, 1),
            dst: Ipv4Addr::new(192, 0, 2, 2),
            dscp: 0,
            ecn: 0,
            id: 1,
            df: false,
            mf: false,
            frag_offset: 0,
            ttl: 64,
            proto: None,
            len: None,
            checksum: None,
        }
    }
}

/// IPv6 header without extension headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6 {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub traffic_class: u8,
    /// 20-bit flow label.
    pub flow_label: u32,
    pub hop_limit: u8,
    /// `None` takes it from the next layer.
    pub next_header: Option<u8>,
    /// Payload length; `None` computes it.
    pub payload_len: Option<u16>,
}

impl Default for Ipv6 {
    fn default() -> Self {
        Self {
            src: "2001:db8::1".parse().expect("valid address"),
            dst: "2001:db8::2".parse().expect("valid address"),
            traffic_class: 0,
            flow_label: 0,
            hop_limit: 64,
            next_header: None,
            payload_len: None,
        }
    }
}

/// TCP header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tcp {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    /// Flag bits: FIN 0x01, SYN 0x02, RST 0x04, PSH 0x08, ACK 0x10, URG 0x20, ECE 0x40, CWR 0x80.
    pub flags: u16,
    pub window: u16,
    pub urgent: u16,
    /// MSS option.
    pub mss: Option<u16>,
    /// Window scale option (shift count).
    pub wscale: Option<u8>,
    /// SACK permitted option.
    pub sack_perm: bool,
    /// `None` computes it.
    pub checksum: Option<u16>,
}

impl Default for Tcp {
    fn default() -> Self {
        Self {
            sport: 49152,
            dport: 80,
            seq: 0,
            ack: 0,
            flags: 0x02,
            window: 64240,
            urgent: 0,
            mss: None,
            wscale: None,
            sack_perm: false,
            checksum: None,
        }
    }
}

/// UDP header.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Udp {
    /// `None`: 53 for a DNS response, else 49152.
    pub sport: Option<u16>,
    /// `None`: 53 for a DNS query, 49152 for a DNS response, else 9 (discard).
    pub dport: Option<u16>,
    /// `None` computes it.
    pub len: Option<u16>,
    /// `None` computes it.
    pub checksum: Option<u16>,
}

/// ICMP, or ICMPv6 when it follows an IPv6 header.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Icmp {
    /// `None`: echo request (8, or 128 for ICMPv6).
    pub icmp_type: Option<u8>,
    pub code: u8,
    /// Identifier, the first half of the rest of the header.
    pub id: u16,
    /// Sequence number, the second half of the rest of the header.
    pub seq: u16,
    /// `None` computes it.
    pub checksum: Option<u16>,
}

/// A DNS message with questions and A/AAAA answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dns {
    pub id: u16,
    /// Response (QR bit).
    pub response: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub rcode: u8,
    /// Question names.
    pub questions: Vec<String>,
    /// Question type for every question (1 = A).
    pub qtype: u16,
    /// Answers for the first question. A v4 address makes an A record, a v6 one AAAA.
    pub answers: Vec<IpAddr>,
    /// TTL of every answer.
    pub ttl: u32,
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            id: 1,
            response: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            rcode: 0,
            questions: Vec::new(),
            qtype: 1,
            answers: Vec::new(),
            ttl: 300,
        }
    }
}

/// One layer of a [`PacketSpec`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LayerSpec {
    Ethernet(Ethernet),
    Vlan(Vlan),
    Arp(Arp),
    Ipv4(Ipv4),
    Ipv6(Ipv6),
    Tcp(Tcp),
    Udp(Udp),
    Icmp(Icmp),
    Dns(Dns),
    /// Bytes copied as they are.
    Raw(Vec<u8>),
}

impl LayerSpec {
    /// The layer's name in the text form, such as `ipv4`.
    pub fn name(&self) -> &'static str {
        match self {
            LayerSpec::Ethernet(_) => "eth",
            LayerSpec::Vlan(_) => "vlan",
            LayerSpec::Arp(_) => "arp",
            LayerSpec::Ipv4(_) => "ipv4",
            LayerSpec::Ipv6(_) => "ipv6",
            LayerSpec::Tcp(_) => "tcp",
            LayerSpec::Udp(_) => "udp",
            LayerSpec::Icmp(_) => "icmp",
            LayerSpec::Dns(_) => "dns",
            LayerSpec::Raw(_) => "raw",
        }
    }

    fn ethertype(&self) -> Option<u16> {
        match self {
            LayerSpec::Vlan(v) => Some(v.tpid),
            LayerSpec::Arp(_) => Some(0x0806),
            LayerSpec::Ipv4(_) => Some(0x0800),
            LayerSpec::Ipv6(_) => Some(0x86dd),
            _ => None,
        }
    }

    fn ip_proto(&self, v6: bool) -> Option<u8> {
        match self {
            LayerSpec::Ipv4(_) => Some(4),
            LayerSpec::Ipv6(_) => Some(41),
            LayerSpec::Tcp(_) => Some(6),
            LayerSpec::Udp(_) => Some(17),
            LayerSpec::Icmp(_) => Some(if v6 { 58 } else { 1 }),
            _ => None,
        }
    }
}

macro_rules! from_layer {
    ($($t:ident),*) => {$(
        impl From<$t> for LayerSpec {
            fn from(l: $t) -> Self {
                LayerSpec::$t(l)
            }
        }
    )*};
}
from_layer!(Ethernet, Vlan, Arp, Ipv4, Ipv6, Tcp, Udp, Icmp, Dns);

/// A packet described layer by layer, outermost first.
///
/// The text form is the layers joined by `/`, each with optional
/// `field=value` pairs in parentheses:
///
/// ```text
/// eth(src=02:00:00:00:00:01,dst=ff:ff:ff:ff:ff:ff)/vlan(id=10,pcp=3)
///   /ipv4(src=10.0.0.1,dst=10.0.0.2,ttl=32,df=1)/tcp(sport=1234,dport=80,flags=SA)
///   /raw(text="hello")
/// ```
///
/// Layers and their fields (defaults in brackets):
///
/// * `eth`: `src` [02:00:00:00:00:fe], `dst` [02:00:00:00:00:02], `type` [from next layer], `pad` [1]
/// * `vlan`: `id` [1], `pcp` [0], `dei` [0], `tpid` [0x8100], `type`.
///   `qinq` is a `vlan` with `tpid=0x88a8`.
/// * `arp`: `op` [request; or reply, 1, 2], `smac` [eth src], `sip`, `tmac` [0], `tip`
/// * `ipv4`: `src` [192.0.2.1], `dst` [192.0.2.2], `ttl` [64], `dscp`, `ecn`, `id` [1],
///   `df`, `mf`, `frag` (offset in bytes), `proto`, `len`, `chksum`
/// * `ipv6`: `src` [2001:db8::1], `dst` [2001:db8::2], `hlim` [64], `tc`, `flow`, `nh`, `plen`
/// * `tcp`: `sport` [49152], `dport` [80], `seq`, `ack`, `flags` [S; letters FSRPAUEC
///   or a number], `win` [64240], `urg`, `mss`, `wscale`, `sackok`, `chksum`
/// * `udp`: `sport`, `dport` [53 around DNS, else 49152 and 9], `len`, `chksum`
/// * `icmp`: `type` [echo request], `code`, `id`, `seq`, `chksum`; ICMPv6 after `ipv6`
/// * `dns`: `id` [1], `q` (repeatable), `qtype` [A], `qr` / `response`, `a` (answer
///   address, repeatable), `ttl` [300], `rd` [1], `ra`, `aa`, `tc`, `opcode`, `rcode`
/// * `raw`: `hex=0a0b0c`, `text="..."`, or `len=N` with `fill` [0]
///
/// Numbers can be decimal or `0x` hex; flags take 1/0, true/false, yes/no.
/// A layer with no fields can be written without parentheses: `eth/ipv4/udp`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PacketSpec {
    pub layers: Vec<LayerSpec>,
}

impl PacketSpec {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a layer inside the ones already there.
    pub fn with(mut self, layer: impl Into<LayerSpec>) -> Self {
        self.layers.push(layer.into());
        self
    }

    /// The pcap link type the packet needs: Ethernet, or raw IP when it starts
    /// with an IP header.
    pub fn linktype(&self) -> Result<u32, BuildError> {
        match self.layers.first() {
            Some(LayerSpec::Ethernet(_)) => Ok(LINKTYPE_ETHERNET),
            Some(LayerSpec::Ipv4(_) | LayerSpec::Ipv6(_)) => Ok(LINKTYPE_RAW),
            Some(other) => err(format!(
                "a packet starts with eth, ipv4 or ipv6, not {}",
                other.name()
            )),
            None => err("a packet needs at least one layer"),
        }
    }

    /// Checks that every layer may follow the one before it.
    fn check_order(&self) -> Result<(), BuildError> {
        self.linktype()?;
        for w in self.layers.windows(2) {
            use LayerSpec as L;
            let ok = match (&w[0], &w[1]) {
                (L::Raw(_) | L::Arp(_) | L::Dns(_), _) => false,
                (_, L::Raw(_)) => true,
                (L::Ethernet(_) | L::Vlan(_), L::Vlan(_) | L::Arp(_) | L::Ipv4(_) | L::Ipv6(_)) => {
                    true
                }
                (
                    L::Ipv4(_) | L::Ipv6(_),
                    L::Ipv4(_) | L::Ipv6(_) | L::Tcp(_) | L::Udp(_) | L::Icmp(_),
                ) => true,
                (L::Tcp(_) | L::Udp(_), L::Dns(_)) => true,
                _ => false,
            };
            if !ok {
                return err(format!("{} cannot follow {}", w[1].name(), w[0].name()));
            }
        }
        Ok(())
    }

    /// Builds the packet's bytes.
    pub fn build(&self) -> Result<Vec<u8>, BuildError> {
        self.check_order()?;
        let n = self.layers.len();
        // Innermost first: each layer wraps the bytes of everything inside it.
        let mut payload: Vec<u8> = Vec::new();
        for i in (0..n).rev() {
            let next = self.layers.get(i + 1);
            let ip = self.layers[..i].iter().rev().find_map(|l| match l {
                LayerSpec::Ipv4(h) => Some(Pseudo::V4(h.src, h.dst)),
                LayerSpec::Ipv6(h) => Some(Pseudo::V6(h.src, h.dst)),
                _ => None,
            });
            let v6 = matches!(ip, Some(Pseudo::V6(..)));
            let mut out = Vec::with_capacity(payload.len() + 64);
            match &self.layers[i] {
                LayerSpec::Ethernet(e) => {
                    out.extend(e.dst);
                    out.extend(e.src);
                    let t = e
                        .ethertype
                        .or_else(|| next.and_then(LayerSpec::ethertype))
                        .unwrap_or(ETHERTYPE_EXPERIMENTAL);
                    out.extend(t.to_be_bytes());
                    out.extend(&payload);
                    if e.pad && i == 0 && out.len() < ETH_MIN_FRAME {
                        out.resize(ETH_MIN_FRAME, 0);
                    }
                }
                LayerSpec::Vlan(v) => {
                    if v.id > 0x0fff || v.pcp > 7 {
                        return err(format!(
                            "vlan: id must be 0-4095 and pcp 0-7 (got id {}, pcp {})",
                            v.id, v.pcp
                        ));
                    }
                    let tci = (u16::from(v.pcp) << 13) | (u16::from(v.dei) << 12) | v.id;
                    out.extend(tci.to_be_bytes());
                    let t = v
                        .ethertype
                        .or_else(|| next.and_then(LayerSpec::ethertype))
                        .unwrap_or(ETHERTYPE_EXPERIMENTAL);
                    out.extend(t.to_be_bytes());
                    out.extend(&payload);
                }
                LayerSpec::Arp(a) => {
                    let eth_src = self.layers[..i].iter().find_map(|l| match l {
                        LayerSpec::Ethernet(e) => Some(e.src),
                        _ => None,
                    });
                    out.extend([0, 1, 0x08, 0, 6, 4]);
                    out.extend(a.op.to_be_bytes());
                    out.extend(a.sender_mac.or(eth_src).unwrap_or([0; 6]));
                    out.extend(a.sender_ip.octets());
                    out.extend(a.target_mac);
                    out.extend(a.target_ip.octets());
                }
                LayerSpec::Ipv4(h) => {
                    if h.frag_offset % 8 != 0 || h.frag_offset > 0x1fff * 8 {
                        return err(format!(
                            "ipv4: fragment offset {} is not a multiple of 8 up to 65528",
                            h.frag_offset
                        ));
                    }
                    if h.dscp > 63 || h.ecn > 3 {
                        return err("ipv4: dscp must be 0-63 and ecn 0-3");
                    }
                    let total = match h.len {
                        Some(l) => l,
                        None => len16(20 + payload.len(), "ipv4 total length")?,
                    };
                    let proto = h
                        .proto
                        .or_else(|| next.and_then(|l| l.ip_proto(false)))
                        .unwrap_or(IPPROTO_EXPERIMENTAL);
                    let frag =
                        (u16::from(h.df) << 14) | (u16::from(h.mf) << 13) | (h.frag_offset / 8);
                    out.extend([0x45, (h.dscp << 2) | h.ecn]);
                    out.extend(total.to_be_bytes());
                    out.extend(h.id.to_be_bytes());
                    out.extend(frag.to_be_bytes());
                    out.extend([h.ttl, proto, 0, 0]);
                    out.extend(h.src.octets());
                    out.extend(h.dst.octets());
                    let c = h.checksum.unwrap_or_else(|| !ones_sum(&[&out]));
                    out[10..12].copy_from_slice(&c.to_be_bytes());
                    out.extend(&payload);
                }
                LayerSpec::Ipv6(h) => {
                    if h.flow_label > 0xfffff {
                        return err("ipv6: flow label is 20 bits (up to 0xfffff)");
                    }
                    let plen = match h.payload_len {
                        Some(l) => l,
                        None => len16(payload.len(), "ipv6 payload length")?,
                    };
                    let nh = h
                        .next_header
                        .or_else(|| next.and_then(|l| l.ip_proto(true)))
                        .unwrap_or(IPPROTO_EXPERIMENTAL);
                    let first = (6u32 << 28) | (u32::from(h.traffic_class) << 20) | h.flow_label;
                    out.extend(first.to_be_bytes());
                    out.extend(plen.to_be_bytes());
                    out.extend([nh, h.hop_limit]);
                    out.extend(h.src.octets());
                    out.extend(h.dst.octets());
                    out.extend(&payload);
                }
                LayerSpec::Tcp(t) => {
                    let mut opts = Vec::new();
                    if let Some(mss) = t.mss {
                        opts.extend([2, 4]);
                        opts.extend(mss.to_be_bytes());
                    }
                    if t.sack_perm {
                        opts.extend([4, 2]);
                    }
                    if let Some(ws) = t.wscale {
                        opts.extend([1, 3, 3, ws]);
                    }
                    while opts.len() % 4 != 0 {
                        opts.push(1); // NOP
                    }
                    let off = (20 + opts.len()) / 4;
                    out.extend(t.sport.to_be_bytes());
                    out.extend(t.dport.to_be_bytes());
                    out.extend(t.seq.to_be_bytes());
                    out.extend(t.ack.to_be_bytes());
                    out.extend(((off as u16) << 12 | (t.flags & 0x01ff)).to_be_bytes());
                    out.extend(t.window.to_be_bytes());
                    out.extend([0, 0]);
                    out.extend(t.urgent.to_be_bytes());
                    out.extend(&opts);
                    if matches!(next, Some(LayerSpec::Dns(_))) {
                        // DNS over TCP carries a two byte length prefix.
                        out.extend(len16(payload.len(), "DNS message")?.to_be_bytes());
                    }
                    out.extend(&payload);
                    let c = match t.checksum {
                        Some(c) => c,
                        None => transport_checksum(ip.as_ref(), 6, &out)?,
                    };
                    out[16..18].copy_from_slice(&c.to_be_bytes());
                }
                LayerSpec::Udp(u) => {
                    let dns_response = match next {
                        Some(LayerSpec::Dns(d)) => Some(d.response),
                        _ => None,
                    };
                    let (sp, dp) = match dns_response {
                        Some(true) => (53, 49152),
                        Some(false) => (49152, 53),
                        None => (49152, 9),
                    };
                    let len = match u.len {
                        Some(l) => l,
                        None => len16(8 + payload.len(), "udp length")?,
                    };
                    out.extend(u.sport.unwrap_or(sp).to_be_bytes());
                    out.extend(u.dport.unwrap_or(dp).to_be_bytes());
                    out.extend(len.to_be_bytes());
                    out.extend([0, 0]);
                    out.extend(&payload);
                    let c = match u.checksum {
                        Some(c) => c,
                        None => match transport_checksum(ip.as_ref(), 17, &out)? {
                            0 => 0xffff,
                            c => c,
                        },
                    };
                    out[6..8].copy_from_slice(&c.to_be_bytes());
                }
                LayerSpec::Icmp(m) => {
                    let ty = m.icmp_type.unwrap_or(if v6 { 128 } else { 8 });
                    out.extend([ty, m.code, 0, 0]);
                    out.extend(m.id.to_be_bytes());
                    out.extend(m.seq.to_be_bytes());
                    out.extend(&payload);
                    let c = match m.checksum {
                        Some(c) => c,
                        None if v6 => transport_checksum(ip.as_ref(), 58, &out)?,
                        None => !ones_sum(&[&out]),
                    };
                    out[2..4].copy_from_slice(&c.to_be_bytes());
                }
                LayerSpec::Dns(d) => dns(d, &mut out)?,
                LayerSpec::Raw(b) => out.extend(b),
            }
            payload = out;
        }
        Ok(payload)
    }
}

enum Pseudo {
    V4(Ipv4Addr, Ipv4Addr),
    V6(Ipv6Addr, Ipv6Addr),
}

fn len16(n: usize, what: &str) -> Result<u16, BuildError> {
    u16::try_from(n).or_else(|_| err(format!("{what} {n} does not fit in 16 bits")))
}

fn transport_checksum(ip: Option<&Pseudo>, proto: u8, seg: &[u8]) -> Result<u16, BuildError> {
    let mut pseudo = Vec::with_capacity(40);
    match ip {
        Some(Pseudo::V4(s, d)) => {
            pseudo.extend(s.octets());
            pseudo.extend(d.octets());
            pseudo.extend([0, proto]);
            pseudo.extend(len16(seg.len(), "segment length")?.to_be_bytes());
        }
        Some(Pseudo::V6(s, d)) => {
            pseudo.extend(s.octets());
            pseudo.extend(d.octets());
            pseudo.extend((seg.len() as u32).to_be_bytes());
            pseudo.extend([0, 0, 0, proto]);
        }
        None => return err("a transport layer needs an ipv4 or ipv6 layer before it"),
    }
    Ok(!ones_sum(&[&pseudo, seg]))
}

fn dns(d: &Dns, out: &mut Vec<u8>) -> Result<(), BuildError> {
    if d.opcode > 15 || d.rcode > 15 {
        return err("dns: opcode and rcode are 0-15");
    }
    if !d.answers.is_empty() && d.questions.is_empty() {
        return err("dns: answers need a question (q=name) to answer");
    }
    let flags = (u16::from(d.response) << 15)
        | (u16::from(d.opcode) << 11)
        | (u16::from(d.aa) << 10)
        | (u16::from(d.tc) << 9)
        | (u16::from(d.rd) << 8)
        | (u16::from(d.ra) << 7)
        | u16::from(d.rcode);
    out.extend(d.id.to_be_bytes());
    out.extend(flags.to_be_bytes());
    out.extend(len16(d.questions.len(), "dns question count")?.to_be_bytes());
    out.extend(len16(d.answers.len(), "dns answer count")?.to_be_bytes());
    out.extend([0, 0, 0, 0]);
    for q in &d.questions {
        dns_name(q, out)?;
        out.extend(d.qtype.to_be_bytes());
        out.extend(1u16.to_be_bytes()); // class IN
    }
    for a in &d.answers {
        out.extend([0xc0, 12]); // pointer to the first question's name
        let (ty, data): (u16, Vec<u8>) = match a {
            IpAddr::V4(v) => (1, v.octets().to_vec()),
            IpAddr::V6(v) => (28, v.octets().to_vec()),
        };
        out.extend(ty.to_be_bytes());
        out.extend(1u16.to_be_bytes());
        out.extend(d.ttl.to_be_bytes());
        out.extend((data.len() as u16).to_be_bytes());
        out.extend(data);
    }
    Ok(())
}

fn dns_name(name: &str, out: &mut Vec<u8>) -> Result<(), BuildError> {
    let name = name.trim_end_matches('.');
    if name.len() > 253 {
        return err(format!("dns: name '{name}' is longer than 253 characters"));
    }
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return err(format!(
                    "dns: name '{name}' has an empty label or one longer than 63 characters"
                ));
            }
            out.push(label.len() as u8);
            out.extend(label.as_bytes());
        }
    }
    out.push(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode;

    fn built(spec: &str) -> (Vec<u8>, crate::Decoded) {
        let s: PacketSpec = spec.parse().unwrap();
        let b = s.build().unwrap();
        let d = decode(s.linktype().unwrap(), &b);
        assert!(
            d.problems.is_empty(),
            "{spec}: {:?}\n{}",
            d.problems,
            d.tree()
        );
        (b, d)
    }

    #[test]
    fn pads_short_ethernet_frames() {
        let (b, d) = built("eth/arp(sip=10.0.0.1,tip=10.0.0.2)");
        assert_eq!(b.len(), 60);
        assert_eq!(d.info, "Who has 10.0.0.2? Tell 10.0.0.1");
        let (b, _) = built("eth(pad=0)/arp");
        assert_eq!(b.len(), 42);
    }

    #[test]
    fn known_icmp_echo_bytes() {
        let (b, _) = built("ipv4(src=10.0.0.1,dst=10.0.0.2,id=0x1c46,df=1)/icmp(id=1,seq=1)");
        assert_eq!(
            b,
            [
                0x45, 0, 0, 28, 0x1c, 0x46, 0x40, 0, 64, 1, 0x0a, 0x99, 10, 0, 0, 1, 10, 0, 0, 2,
                8, 0, 0xf7, 0xfd, 0, 1, 0, 1
            ]
        );
    }

    #[test]
    fn tcp_options_and_flags() {
        let (_, d) = built(
            "eth/ipv4/tcp(sport=1234,dport=443,flags=SA,seq=7,ack=9,mss=1460,wscale=7,sackok=1)",
        );
        assert_eq!(d.info, "1234 → 443 [SYN, ACK] Seq=7 Ack=9 Win=64240 Len=0");
        let tcp = d.layer("TCP").unwrap();
        let opts = tcp.fields.iter().find(|f| f.name == "Options").unwrap();
        assert_eq!(opts.value, "MSS=1460, SACK_PERM, WS=128");
    }

    #[test]
    fn deliberate_bad_checksum() {
        let s: PacketSpec = "eth/ipv4/udp(chksum=0x1234)".parse().unwrap();
        let d = decode(1, &s.build().unwrap());
        assert_eq!(d.problems, ["UDP checksum is incorrect"]);
    }

    #[test]
    fn ipv6_icmpv6_and_dns_over_tcp() {
        let (_, d) = built("eth/ipv6/icmp(id=5,seq=2)/raw(text=\"ping\")");
        assert_eq!(d.protocol, "ICMPv6");
        let (_, d) = built(
            "eth/vlan(id=100,tpid=0x88a8)/vlan(id=10)/ipv6/tcp(dport=53,flags=PA)/dns(q=a.example)",
        );
        assert_eq!(d.protocol, "DNS");
        assert_eq!(d.layers.iter().filter(|l| l.protocol == "VLAN").count(), 2);
    }

    #[test]
    fn dns_response_ports_and_answers() {
        let (_, d) =
            built("eth/ipv4/udp/dns(qr=1,id=0xbeef,q=example.com,a=93.184.216.34,a=2001:db8::5)");
        assert_eq!(d.source, "192.0.2.1");
        let udp = d.layer("UDP").unwrap();
        assert!(udp.title.contains("Src Port: 53"), "{}", udp.title);
        assert!(d.info.contains("A 93.184.216.34"), "{}", d.info);
    }

    #[test]
    fn rejects_bad_stacks() {
        let e = |s: &str| {
            s.parse::<PacketSpec>()
                .and_then(|p| p.build())
                .unwrap_err()
                .0
        };
        assert!(e("tcp").contains("starts with"));
        assert!(e("eth/tcp").contains("tcp cannot follow eth"));
        assert!(e("eth/raw/ipv4").contains("cannot follow raw"));
        assert!(e("eth/vlan(id=5000)").contains("0-4095"));
    }
}
