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

/// Which IPv6 extension header an [`Ipv6Ext`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6ExtKind {
    /// Hop-by-hop options (next header 0).
    HopByHop,
    /// Destination options (60).
    DestOpts,
    /// Fragment header (44).
    Fragment,
}

/// An IPv6 extension header, after an [`Ipv6`] layer or another extension.
///
/// Hop-by-hop and destination options headers are filled with padding (and,
/// for hop-by-hop with `router_alert`, the router alert option MLD uses).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6Ext {
    pub kind: Ipv6ExtKind,
    /// `None` takes it from the next layer.
    pub next_header: Option<u8>,
    /// Header length in bytes for the options headers: a multiple of 8, at
    /// least 8 (the default).
    pub len: usize,
    /// Hop-by-hop: carry a router alert option (value `router_alert`).
    pub router_alert: Option<u16>,
    /// Fragment: offset in bytes, a multiple of 8.
    pub frag_offset: u16,
    /// Fragment: more fragments follow.
    pub more: bool,
    /// Fragment: identification.
    pub id: u32,
}

impl Ipv6Ext {
    pub fn new(kind: Ipv6ExtKind) -> Self {
        Self {
            kind,
            next_header: None,
            len: 8,
            router_alert: None,
            frag_offset: 0,
            more: false,
            id: 1,
        }
    }

    fn proto(&self) -> u8 {
        match self.kind {
            Ipv6ExtKind::HopByHop => 0,
            Ipv6ExtKind::DestOpts => 60,
            Ipv6ExtKind::Fragment => 44,
        }
    }

    fn name(&self) -> &'static str {
        match self.kind {
            Ipv6ExtKind::HopByHop => "hbh",
            Ipv6ExtKind::DestOpts => "dstopt",
            Ipv6ExtKind::Fragment => "frag",
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
    /// `None`: 53 for a DNS response, 2152 for GTP-U, else 49152.
    pub sport: Option<u16>,
    /// `None`: 53 for a DNS query, 49152 for a DNS response, 4789 for VXLAN,
    /// 6081 for Geneve, 2152 for GTP-U, else 9 (discard).
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
    /// ICMPv6 neighbor solicitation (135) and advertisement (136): the target
    /// address after the header. Neighbor advertisement flags (router 0x8000,
    /// solicited 0x4000, override 0x2000) go in `id`.
    pub target: Option<Ipv6Addr>,
    /// Neighbor discovery: a source (135) or target (136) link-layer address
    /// option after the target.
    pub lladdr: Option<[u8; 6]>,
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

/// One MPLS label stack entry. The bottom-of-stack bit is set on the last
/// label before what the stack carries, unless `bos` says otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mpls {
    /// 20-bit label.
    pub label: u32,
    /// Traffic class (the former EXP bits), 0-7.
    pub tc: u8,
    pub ttl: u8,
    /// `None`: set on the last label of the stack.
    pub bos: Option<bool>,
}

impl Default for Mpls {
    fn default() -> Self {
        Self {
            label: 16,
            tc: 0,
            ttl: 64,
            bos: None,
        }
    }
}

/// GRE header (RFC 2784 and 2890), version 0.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Gre {
    /// Carry a checksum over the GRE header and payload.
    pub checksum: bool,
    pub key: Option<u32>,
    pub seq: Option<u32>,
    /// Protocol type; `None` takes it from the next layer (0x6558 for Ethernet).
    pub proto: Option<u16>,
}

/// VXLAN header (RFC 7348); an Ethernet frame follows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vxlan {
    /// 24-bit VXLAN network identifier.
    pub vni: u32,
    /// Flags byte; 0x08 says the VNI is valid.
    pub flags: u8,
}

impl Default for Vxlan {
    fn default() -> Self {
        Self {
            vni: 1,
            flags: 0x08,
        }
    }
}

/// Geneve header (RFC 8926).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Geneve {
    /// 24-bit virtual network identifier.
    pub vni: u32,
    /// Protocol type; `None` takes it from the next layer (0x6558 for Ethernet).
    pub proto: Option<u16>,
    pub oam: bool,
    pub critical: bool,
    /// Option TLVs as bytes, a multiple of 4 up to 252.
    pub options: Vec<u8>,
}

/// GTP-U header (3GPP TS 29.281), version 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gtpu {
    pub teid: u32,
    /// Message type: 255 (T-PDU, the default), 1 echo request, 2 echo
    /// response, 26 error indication, 254 end marker.
    pub msg_type: u8,
    /// Sequence number; sets the S flag.
    pub seq: Option<u16>,
    /// QoS flow identifier of a 5G PDU session container extension header.
    pub qfi: Option<u8>,
    /// PDU session container: uplink (1) or downlink (0, the default).
    pub uplink: bool,
    /// Length after the first 8 bytes; `None` computes it.
    pub len: Option<u16>,
}

impl Default for Gtpu {
    fn default() -> Self {
        Self {
            teid: 1,
            msg_type: 255,
            seq: None,
            qfi: None,
            uplink: false,
            len: None,
        }
    }
}

/// 802.2 LLC header, after an Ethernet header whose type field then holds
/// the frame's length (802.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Llc {
    pub dsap: u8,
    pub ssap: u8,
    pub control: u8,
}

impl Default for Llc {
    fn default() -> Self {
        Self {
            dsap: 0xaa,
            ssap: 0xaa,
            control: 0x03,
        }
    }
}

/// SNAP header after LLC 0xaa/0xaa: an OUI and a protocol ID. With OUI 0 the
/// protocol ID is an ethertype.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snap {
    /// 24-bit organization code.
    pub oui: u32,
    /// `None` takes it from the next layer.
    pub pid: Option<u16>,
}

/// One group record of an IGMPv3 or MLDv2 report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRecord {
    /// 1 MODE_IS_INCLUDE, 2 MODE_IS_EXCLUDE, 3 CHANGE_TO_INCLUDE (leave
    /// without sources), 4 CHANGE_TO_EXCLUDE (join without sources), 5
    /// ALLOW_NEW_SOURCES, 6 BLOCK_OLD_SOURCES.
    pub record_type: u8,
    pub group: IpAddr,
    pub sources: Vec<IpAddr>,
}

/// Which IGMP or MLD message to build.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum McastType {
    Query,
    #[default]
    Report,
    /// IGMP leave group, MLD done.
    Leave,
}

/// An IGMP message (v1, v2 or v3), after an IPv4 header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Igmp {
    pub kind: McastType,
    /// 1, 2 (the default) or 3. Reports with records are always version 3.
    pub version: u8,
    /// Max response code, in tenths of a second (v3: the RFC 3376 code).
    pub max_resp: u8,
    pub group: Ipv4Addr,
    /// v3 query: the sources asked about.
    pub sources: Vec<Ipv4Addr>,
    /// v3 report.
    pub records: Vec<GroupRecord>,
    /// v3 query: suppress router-side processing, robustness variable and
    /// querier's query interval code.
    pub suppress: bool,
    pub qrv: u8,
    pub qqic: u8,
    /// `None` computes it.
    pub checksum: Option<u16>,
}

impl Default for Igmp {
    fn default() -> Self {
        Self {
            kind: McastType::Report,
            version: 2,
            max_resp: 100,
            group: Ipv4Addr::new(239, 1, 1, 1),
            sources: Vec::new(),
            records: Vec::new(),
            suppress: false,
            qrv: 2,
            qqic: 125,
            checksum: None,
        }
    }
}

/// An MLD message (v1 or v2), after an IPv6 header (and usually a hop-by-hop
/// header with a router alert: `hbh(ra=0)`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mld {
    pub kind: McastType,
    /// 1 (the default) or 2. Reports with records are always version 2.
    pub version: u8,
    /// Maximum response delay in milliseconds (v2: the RFC 3810 code).
    pub max_delay: u16,
    pub group: Ipv6Addr,
    pub sources: Vec<Ipv6Addr>,
    pub records: Vec<GroupRecord>,
    pub suppress: bool,
    pub qrv: u8,
    pub qqic: u8,
    pub checksum: Option<u16>,
}

impl Default for Mld {
    fn default() -> Self {
        Self {
            kind: McastType::Report,
            version: 1,
            max_delay: 10000,
            group: "ff0e::1".parse().expect("valid address"),
            sources: Vec::new(),
            records: Vec::new(),
            suppress: false,
            qrv: 2,
            qqic: 125,
            checksum: None,
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
    Ipv6Ext(Ipv6Ext),
    Tcp(Tcp),
    Udp(Udp),
    Icmp(Icmp),
    Dns(Dns),
    Mpls(Mpls),
    Gre(Gre),
    Vxlan(Vxlan),
    Geneve(Geneve),
    Gtpu(Gtpu),
    Llc(Llc),
    Snap(Snap),
    Igmp(Igmp),
    Mld(Mld),
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
            LayerSpec::Ipv6Ext(e) => e.name(),
            LayerSpec::Tcp(_) => "tcp",
            LayerSpec::Udp(_) => "udp",
            LayerSpec::Icmp(_) => "icmp",
            LayerSpec::Dns(_) => "dns",
            LayerSpec::Mpls(_) => "mpls",
            LayerSpec::Gre(_) => "gre",
            LayerSpec::Vxlan(_) => "vxlan",
            LayerSpec::Geneve(_) => "geneve",
            LayerSpec::Gtpu(_) => "gtpu",
            LayerSpec::Llc(_) => "llc",
            LayerSpec::Snap(_) => "snap",
            LayerSpec::Igmp(_) => "igmp",
            LayerSpec::Mld(_) => "mld",
            LayerSpec::Raw(_) => "raw",
        }
    }

    fn ethertype(&self) -> Option<u16> {
        match self {
            LayerSpec::Vlan(v) => Some(v.tpid),
            LayerSpec::Arp(_) => Some(0x0806),
            LayerSpec::Ipv4(_) => Some(0x0800),
            LayerSpec::Ipv6(_) => Some(0x86dd),
            LayerSpec::Mpls(_) => Some(crate::ETHERTYPE_MPLS),
            _ => None,
        }
    }

    /// The protocol type a tunnel header (GRE, Geneve) names for this layer.
    fn tunnel_type(&self) -> Option<u16> {
        match self {
            LayerSpec::Ethernet(_) => Some(crate::ETHERTYPE_TEB),
            other => other.ethertype(),
        }
    }

    fn ip_proto(&self, v6: bool) -> Option<u8> {
        match self {
            LayerSpec::Ipv4(_) => Some(4),
            LayerSpec::Ipv6(_) => Some(41),
            LayerSpec::Ipv6Ext(e) => Some(e.proto()),
            LayerSpec::Tcp(_) => Some(6),
            LayerSpec::Udp(_) => Some(17),
            LayerSpec::Icmp(_) | LayerSpec::Mld(_) => Some(if v6 { 58 } else { 1 }),
            LayerSpec::Gre(_) => Some(47),
            LayerSpec::Igmp(_) => Some(2),
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
from_layer!(
    Ethernet, Vlan, Arp, Ipv4, Ipv6, Ipv6Ext, Tcp, Udp, Icmp, Dns, Mpls, Gre, Vxlan, Geneve, Gtpu,
    Llc, Snap, Igmp, Mld
);

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
/// * IPv6 extension headers, after `ipv6`: `hbh` (hop-by-hop options) and
///   `dstopt` (destination options) with `len` [8, bytes, a multiple of 8], `nh`,
///   and for `hbh` `ra` (router alert value); `frag` with `offset` (bytes), `mf`,
///   `id` [1], `nh`
/// * `tcp`: `sport` [49152], `dport` [80], `seq`, `ack`, `flags` [S; letters FSRPAUEC
///   or a number], `win` [64240], `urg`, `mss`, `wscale`, `sackok`, `chksum`
/// * `udp`: `sport`, `dport` [53 around DNS, else 49152 and 9], `len`, `chksum`
/// * `icmp`: `type` [echo request], `code`, `id`, `seq`, `chksum`; ICMPv6 after `ipv6`,
///   where neighbor solicitations (`type=ns` or 135) and advertisements (`type=na`
///   or 136) also take `target`, `lladdr` and, for advertisements, `flags`
///   (letters RSO). Neighbor discovery wants `ipv6(hlim=255)`.
/// * `dns`: `id` [1], `q` (repeatable), `qtype` [A], `qr` / `response`, `a` (answer
///   address, repeatable), `ttl` [300], `rd` [1], `ra`, `aa`, `tc`, `opcode`, `rcode`
/// * `mpls`: `label` [16], `tc` [0], `ttl` [64], `s` [1 on the last label]; after
///   `eth` or `vlan` (ethertype 0x8847), before more labels, `ipv4`, `ipv6` or
///   `eth` (an Ethernet pseudowire, written with a zero control word)
/// * `llc`: `dsap` [0xaa], `ssap` [0xaa], `ctrl` [3]; after `eth`, whose type
///   field then holds the length (802.3). `snap`: `oui` [0], `pid` [from next layer]
/// * `gre`: `key`, `seq`, `csum` [0; 1 adds a checksum], `proto` [from next layer,
///   0x6558 before `eth`]; after `ipv4` or `ipv6`
/// * `vxlan`: `vni` [1], `flags` [0x08]; after `udp` (port 4789), before `eth`
/// * `geneve`: `vni` [0], `proto` [from next layer], `oam`, `crit`, `opt` (option
///   TLVs as hex); after `udp` (port 6081)
/// * `gtpu`: `teid` [1], `type` [gpdu; or echo, echo_resp, error, end, a number],
///   `seq`, `qfi` (adds a PDU session container), `pdu` [dl; or ul], `len`; after
///   `udp` (port 2152), before `ipv4` or `ipv6`
/// * `igmp`: `type` [report; or query, leave, v3report, v3query], `ver` [2], `mrt`
///   [100, tenths of a second], `group` [239.1.1.1], `src` (v3 query sources,
///   repeatable), `rec` (v3 report group records `TYPE@GROUP[+SOURCE...]` with
///   TYPE `join`, `leave`, `include`, `exclude`, `allow` or `block`; repeatable),
///   `s`, `qrv` [2], `qqic` [125], `chksum`
/// * `mld`: like `igmp` after `ipv6` (add `hbh(ra=0)` and `hlim=1` for a real
///   one): `type` [report; or query, done, v2report, v2query], `ver` [1], `delay`
///   [10000 ms, queries], `group` [ff0e::1], `src`, `rec`, `s`, `qrv`, `qqic`, `chksum`
/// * `raw`: `hex=0a0b0c`, `text="..."`, or `len=N` with `fill` [0]
///
/// Tunnels nest: `eth/ipv4/udp/vxlan(vni=5)/eth/ipv4/tcp`, `eth/ipv4/gre(key=1)/ipv6/udp`,
/// `eth/ipv6/ipv4/icmp` (IP in IP), `eth/mpls(label=100)/mpls(label=200)/ipv4/udp`.
/// The UDP ports of VXLAN, Geneve and GTP-U are filled in, and every length and
/// checksum, outer and inner, is computed.
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
                (
                    L::Ethernet(_) | L::Vlan(_),
                    L::Vlan(_) | L::Arp(_) | L::Ipv4(_) | L::Ipv6(_) | L::Mpls(_),
                ) => true,
                (L::Ethernet(_), L::Llc(_)) => true,
                (L::Llc(_), L::Snap(_)) => true,
                (L::Snap(_), L::Vlan(_) | L::Arp(_) | L::Ipv4(_) | L::Ipv6(_) | L::Mpls(_)) => true,
                (
                    L::Ipv4(_) | L::Ipv6(_) | L::Ipv6Ext(_),
                    L::Ipv4(_) | L::Ipv6(_) | L::Tcp(_) | L::Udp(_) | L::Icmp(_) | L::Gre(_),
                ) => true,
                (L::Ipv4(_), L::Igmp(_)) => true,
                (L::Ipv6(_) | L::Ipv6Ext(_), L::Ipv6Ext(_) | L::Mld(_)) => true,
                (L::Tcp(_) | L::Udp(_), L::Dns(_)) => true,
                (L::Udp(_), L::Vxlan(_) | L::Geneve(_) | L::Gtpu(_)) => true,
                (L::Mpls(_), L::Mpls(_) | L::Ipv4(_) | L::Ipv6(_) | L::Ethernet(_)) => true,
                (
                    L::Gre(_) | L::Geneve(_),
                    L::Ethernet(_) | L::Ipv4(_) | L::Ipv6(_) | L::Mpls(_),
                ) => true,
                (L::Vxlan(_), L::Ethernet(_)) => true,
                (L::Gtpu(_), L::Ipv4(_) | L::Ipv6(_)) => true,
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
                    let t = match next {
                        // 802.3: the type field holds the length.
                        Some(LayerSpec::Llc(_)) if e.ethertype.is_none() => {
                            if payload.len() > 1500 {
                                return err("llc: an 802.3 frame carries at most 1500 bytes");
                            }
                            payload.len() as u16
                        }
                        _ => e
                            .ethertype
                            .or_else(|| next.and_then(LayerSpec::ethertype))
                            .unwrap_or(ETHERTYPE_EXPERIMENTAL),
                    };
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
                LayerSpec::Ipv6Ext(e) => {
                    let nh = e
                        .next_header
                        .or_else(|| next.and_then(|l| l.ip_proto(true)))
                        .unwrap_or(59); // no next header
                    out.push(nh);
                    match e.kind {
                        Ipv6ExtKind::Fragment => {
                            if e.frag_offset % 8 != 0 {
                                return err(format!(
                                    "frag: offset {} is not a multiple of 8",
                                    e.frag_offset
                                ));
                            }
                            out.push(0);
                            out.extend((e.frag_offset | u16::from(e.more)).to_be_bytes());
                            out.extend(e.id.to_be_bytes());
                        }
                        Ipv6ExtKind::HopByHop | Ipv6ExtKind::DestOpts => {
                            if e.len < 8 || e.len % 8 != 0 || e.len > 2048 {
                                return err(format!(
                                    "{}: len {} must be a multiple of 8 from 8 to 2048",
                                    e.name(),
                                    e.len
                                ));
                            }
                            out.push((e.len / 8 - 1) as u8);
                            if let Some(ra) = e.router_alert {
                                if e.kind != Ipv6ExtKind::HopByHop {
                                    return err("ra goes in hbh, not dstopt");
                                }
                                out.extend([5, 2]);
                                out.extend(ra.to_be_bytes());
                            }
                            // Pad1 or PadN up to the length.
                            match e.len - out.len() {
                                0 => {}
                                1 => out.push(0),
                                n => {
                                    out.extend([1, (n - 2) as u8]);
                                    out.resize(e.len, 0);
                                }
                            }
                        }
                    }
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
                    let (sp, dp) = match (dns_response, next) {
                        (Some(true), _) => (53, 49152),
                        (Some(false), _) => (49152, 53),
                        (_, Some(LayerSpec::Vxlan(_))) => (49152, crate::VXLAN_PORT),
                        (_, Some(LayerSpec::Geneve(_))) => (49152, crate::GENEVE_PORT),
                        (_, Some(LayerSpec::Gtpu(_))) => (crate::GTPU_PORT, crate::GTPU_PORT),
                        _ => (49152, 9),
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
                    let nd = v6 && matches!(ty, 135 | 136);
                    if (m.target.is_some() || m.lladdr.is_some()) && !nd {
                        return err(
                            "icmp: target and lladdr are for ICMPv6 neighbor solicitations \
                             and advertisements (type ns or na)",
                        );
                    }
                    if nd {
                        out.extend(m.target.unwrap_or(Ipv6Addr::UNSPECIFIED).octets());
                        if let Some(mac) = m.lladdr {
                            out.extend([if ty == 135 { 1 } else { 2 }, 1]);
                            out.extend(mac);
                        }
                    }
                    out.extend(&payload);
                    let c = match m.checksum {
                        Some(c) => c,
                        None if v6 => transport_checksum(ip.as_ref(), 58, &out)?,
                        None => !ones_sum(&[&out]),
                    };
                    out[2..4].copy_from_slice(&c.to_be_bytes());
                }
                LayerSpec::Dns(d) => dns(d, &mut out)?,
                LayerSpec::Mpls(m) => {
                    if m.label > 0xfffff || m.tc > 7 {
                        return err(format!(
                            "mpls: label is 20 bits (up to 1048575) and tc 0-7 (got label {}, tc {})",
                            m.label, m.tc
                        ));
                    }
                    let bos = m.bos.unwrap_or(!matches!(next, Some(LayerSpec::Mpls(_))));
                    let w = (m.label << 12)
                        | (u32::from(m.tc) << 9)
                        | (u32::from(bos) << 8)
                        | u32::from(m.ttl);
                    out.extend(w.to_be_bytes());
                    if matches!(next, Some(LayerSpec::Ethernet(_))) {
                        // Pseudowire control word (RFC 4448), so the frame
                        // is not taken for IP by its first nibble.
                        out.extend([0, 0, 0, 0]);
                    }
                    out.extend(&payload);
                }
                LayerSpec::Gre(g) => {
                    let proto = g
                        .proto
                        .or_else(|| next.and_then(LayerSpec::tunnel_type))
                        .unwrap_or(ETHERTYPE_EXPERIMENTAL);
                    let flags = (u16::from(g.checksum) << 15)
                        | (u16::from(g.key.is_some()) << 13)
                        | (u16::from(g.seq.is_some()) << 12);
                    out.extend(flags.to_be_bytes());
                    out.extend(proto.to_be_bytes());
                    if g.checksum {
                        out.extend([0, 0, 0, 0]);
                    }
                    if let Some(k) = g.key {
                        out.extend(k.to_be_bytes());
                    }
                    if let Some(q) = g.seq {
                        out.extend(q.to_be_bytes());
                    }
                    out.extend(&payload);
                    if g.checksum {
                        let c = !ones_sum(&[&out]);
                        out[4..6].copy_from_slice(&c.to_be_bytes());
                    }
                }
                LayerSpec::Vxlan(v) => {
                    if v.vni > 0xffffff {
                        return err("vxlan: vni is 24 bits (up to 16777215)");
                    }
                    out.extend([v.flags, 0, 0, 0]);
                    out.extend((v.vni << 8).to_be_bytes());
                    out.extend(&payload);
                }
                LayerSpec::Geneve(g) => {
                    if g.vni > 0xffffff {
                        return err("geneve: vni is 24 bits (up to 16777215)");
                    }
                    if g.options.len() % 4 != 0 || g.options.len() > 252 {
                        return err("geneve: options are a multiple of 4 bytes, up to 252");
                    }
                    let proto = g
                        .proto
                        .or_else(|| next.and_then(LayerSpec::tunnel_type))
                        .unwrap_or(ETHERTYPE_EXPERIMENTAL);
                    out.push((g.options.len() / 4) as u8);
                    out.push((u8::from(g.oam) << 7) | (u8::from(g.critical) << 6));
                    out.extend(proto.to_be_bytes());
                    out.extend((g.vni << 8).to_be_bytes());
                    out.extend(&g.options);
                    out.extend(&payload);
                }
                LayerSpec::Gtpu(g) => {
                    if g.qfi.is_some_and(|q| q > 63) {
                        return err("gtpu: qfi is 6 bits (0-63)");
                    }
                    let ext = g.qfi.is_some();
                    let opt = ext || g.seq.is_some();
                    let flags = 0x30 | (u8::from(ext) << 2) | (u8::from(g.seq.is_some()) << 1);
                    out.extend([flags, g.msg_type, 0, 0]);
                    out.extend(g.teid.to_be_bytes());
                    if opt {
                        out.extend(g.seq.unwrap_or(0).to_be_bytes());
                        out.push(0); // N-PDU number
                        out.push(if ext { 0x85 } else { 0 });
                    }
                    if let Some(q) = g.qfi {
                        // PDU session container: one 4-byte unit, no more extensions.
                        out.extend([1, u8::from(g.uplink) << 4, q, 0]);
                    }
                    out.extend(&payload);
                    let len = match g.len {
                        Some(l) => l,
                        None => len16(out.len() - 8, "gtpu length")?,
                    };
                    out[2..4].copy_from_slice(&len.to_be_bytes());
                }
                LayerSpec::Llc(l) => {
                    out.extend([l.dsap, l.ssap, l.control]);
                    out.extend(&payload);
                }
                LayerSpec::Snap(sn) => {
                    if sn.oui > 0xffffff {
                        return err("snap: oui is 24 bits");
                    }
                    let pid = sn
                        .pid
                        .or_else(|| next.and_then(LayerSpec::ethertype))
                        .unwrap_or(ETHERTYPE_EXPERIMENTAL);
                    out.extend(&sn.oui.to_be_bytes()[1..]);
                    out.extend(pid.to_be_bytes());
                    out.extend(&payload);
                }
                LayerSpec::Igmp(g) => {
                    igmp(g, &mut out)?;
                    out.extend(&payload);
                    let c = g.checksum.unwrap_or_else(|| !ones_sum(&[&out]));
                    out[2..4].copy_from_slice(&c.to_be_bytes());
                }
                LayerSpec::Mld(m) => {
                    mld(m, &mut out)?;
                    out.extend(&payload);
                    let c = match m.checksum {
                        Some(c) => c,
                        None => transport_checksum(ip.as_ref(), 58, &out)?,
                    };
                    out[2..4].copy_from_slice(&c.to_be_bytes());
                }
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

fn record(r: &GroupRecord, v6: bool, out: &mut Vec<u8>) -> Result<(), BuildError> {
    let bytes = |a: &IpAddr| -> Result<Vec<u8>, BuildError> {
        match (a, v6) {
            (IpAddr::V4(a), false) => Ok(a.octets().to_vec()),
            (IpAddr::V6(a), true) => Ok(a.octets().to_vec()),
            _ => err(format!(
                "{}: group record address {a} is not IPv{}",
                if v6 { "mld" } else { "igmp" },
                if v6 { 6 } else { 4 }
            )),
        }
    };
    out.extend([r.record_type, 0]);
    out.extend(len16(r.sources.len(), "group record sources")?.to_be_bytes());
    out.extend(bytes(&r.group)?);
    for s in &r.sources {
        out.extend(bytes(s)?);
    }
    Ok(())
}

fn igmp(g: &Igmp, out: &mut Vec<u8>) -> Result<(), BuildError> {
    if !(1..=3).contains(&g.version) {
        return err("igmp: ver is 1, 2 or 3");
    }
    let v3 = g.version == 3 || !g.records.is_empty();
    match g.kind {
        McastType::Report if v3 => {
            out.extend([0x22, 0, 0, 0, 0, 0]);
            out.extend(len16(g.records.len(), "igmp records")?.to_be_bytes());
            for r in &g.records {
                record(r, false, out)?;
            }
            return Ok(());
        }
        McastType::Report => {
            let t = if g.version == 1 { 0x12 } else { 0x16 };
            out.extend([t, 0, 0, 0]);
        }
        McastType::Leave => out.extend([0x17, 0, 0, 0]),
        McastType::Query => {
            let code = if g.version == 1 { 0 } else { g.max_resp };
            out.extend([0x11, code, 0, 0]);
        }
    }
    out.extend(g.group.octets());
    if g.kind == McastType::Query && g.version == 3 {
        out.push((u8::from(g.suppress) << 3) | (g.qrv & 7));
        out.push(g.qqic);
        out.extend(len16(g.sources.len(), "igmp sources")?.to_be_bytes());
        for s in &g.sources {
            out.extend(s.octets());
        }
    } else if !g.sources.is_empty() {
        return err("igmp: src is for version 3 queries");
    }
    Ok(())
}

fn mld(m: &Mld, out: &mut Vec<u8>) -> Result<(), BuildError> {
    if !(1..=2).contains(&m.version) {
        return err("mld: ver is 1 or 2");
    }
    let v2 = m.version == 2 || !m.records.is_empty();
    match m.kind {
        McastType::Report if v2 => {
            out.extend([143, 0, 0, 0, 0, 0]);
            out.extend(len16(m.records.len(), "mld records")?.to_be_bytes());
            for r in &m.records {
                record(r, true, out)?;
            }
            return Ok(());
        }
        McastType::Report => out.extend([131, 0, 0, 0]),
        McastType::Leave => out.extend([132, 0, 0, 0]),
        McastType::Query => out.extend([130, 0, 0, 0]),
    }
    let delay = if m.kind == McastType::Query {
        m.max_delay
    } else {
        0
    };
    out.extend(delay.to_be_bytes());
    out.extend([0, 0]);
    out.extend(m.group.octets());
    if m.kind == McastType::Query && m.version == 2 {
        out.push((u8::from(m.suppress) << 3) | (m.qrv & 7));
        out.push(m.qqic);
        out.extend(len16(m.sources.len(), "mld sources")?.to_be_bytes());
        for s in &m.sources {
            out.extend(s.octets());
        }
    } else if !m.sources.is_empty() {
        return err("mld: src is for version 2 queries");
    }
    Ok(())
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

    #[test]
    fn ipv6_extension_headers() {
        let (b, d) = built("eth/ipv6/hbh(ra=0)/dstopt(len=16)/udp(dport=7)/raw(len=4)");
        assert_eq!(d.protocol, "UDP");
        let exts: Vec<&str> = d
            .layers
            .iter()
            .filter(|l| l.protocol == "IPv6 ext")
            .map(|l| l.title.as_str())
            .collect();
        assert_eq!(exts, ["IPv6 Hop-by-Hop", "IPv6 Destination Options"]);
        // 40 + 8 + 16 + 8 + 4, and the payload length counts the extensions.
        assert_eq!(b.len(), 14 + 76);
        assert_eq!(u16::from_be_bytes([b[18], b[19]]), 36);
        // Router alert, then PadN.
        assert_eq!(&b[54..62], &[60, 0, 5, 2, 0, 0, 1, 0]);

        let (_, d) = built("eth/ipv6/frag(offset=0,mf=1,id=7)/icmp/raw(len=8)");
        assert_eq!(d.protocol, "ICMPv6");
        let (_, d) = built("eth/ipv6/frag(offset=1448,id=7)/raw(len=8)");
        assert!(d.info.starts_with("Fragment of"), "{}", d.info);

        let e = |s: &str| {
            s.parse::<PacketSpec>()
                .and_then(|p| p.build())
                .unwrap_err()
                .0
        };
        assert!(e("eth/ipv4/hbh").contains("hbh cannot follow ipv4"));
        assert!(e("eth/ipv6/dstopt(len=12)").contains("multiple of 8"));
        assert!(e("eth/ipv6/frag(offset=3)").contains("multiple of 8"));
    }

    #[test]
    fn neighbor_discovery() {
        let (b, d) = built(
            "eth(dst=33:33:ff:00:00:01)/ipv6(src=fd00::2,dst=ff02::1:ff00:1,hlim=255)\
             /icmp(type=ns,target=fd00::1,lladdr=02:00:00:00:00:02)",
        );
        assert_eq!(b.len(), 14 + 40 + 32);
        assert_eq!(
            d.info,
            "Neighbor solicitation for fd00::1 is at 02:00:00:00:00:02"
        );
        let (b, d) = built(
            "eth/ipv6(src=fd00::1,dst=fd00::2,hlim=255)\
             /icmp(type=na,flags=SO,target=fd00::1,lladdr=02:00:00:00:00:01)",
        );
        assert_eq!(b[14 + 40 + 4], 0x60);
        assert_eq!(
            d.info,
            "Neighbor advertisement fd00::1 is at 02:00:00:00:00:01"
        );
        let flags = d
            .layer("ICMPv6")
            .unwrap()
            .fields
            .iter()
            .find(|f| f.name == "Flags");
        assert_eq!(flags.unwrap().value, "solicited, override");
        let e = "eth/ipv4/icmp(target=fd00::1)"
            .parse::<PacketSpec>()
            .unwrap()
            .build();
        assert!(e.unwrap_err().0.contains("neighbor"));
    }
    #[test]
    fn tunnels_build_and_decode() {
        let (b, d) = built(
            "eth/ipv4(src=10.0.0.1,dst=10.0.0.2)/udp/vxlan(vni=5000)\
             /eth(src=02:00:00:00:00:0a,dst=02:00:00:00:00:0b)/ipv4(src=192.168.1.1,dst=192.168.1.2)\
             /udp(sport=1000,dport=2000)/raw(len=10)",
        );
        assert_eq!(d.protocol, "UDP");
        assert_eq!(d.source, "192.168.1.1");
        let vx = d.layer("VXLAN").unwrap();
        assert!(vx.title.ends_with("VNI: 5000"), "{}", vx.title);
        assert_eq!(&b[36..38], &4789u16.to_be_bytes());
        // Inner frame is not padded; the outer one has the lengths of all of it.
        assert_eq!(b.len(), 14 + 20 + 8 + 8 + 14 + 20 + 8 + 10);
        assert_eq!(
            d.layers.iter().filter(|l| l.protocol == "Ethernet").count(),
            2
        );

        let (_, d) = built("eth/ipv6/udp/geneve(vni=7,opt=01020304)/eth/ipv6/icmp");
        assert_eq!(d.protocol, "ICMPv6");
        assert!(d.layer("Geneve").unwrap().title.contains("VNI: 7"));
        let (_, d) = built("eth/ipv4/udp/geneve(vni=8)/ipv4/tcp(flags=S)");
        assert_eq!(d.protocol, "TCP");

        let (b, d) = built(
            "eth/ipv4(src=10.1.0.1,dst=10.2.0.1)/udp/gtpu(teid=0x1234,qfi=9,pdu=ul,seq=7)\
             /ipv4(src=172.16.0.5,dst=8.8.8.8)/udp/dns(q=example.com)",
        );
        assert_eq!(d.protocol, "DNS");
        let gtp = d.layer("GTP").unwrap();
        assert!(gtp.title.contains("TEID: 0x00001234"), "{}", gtp.title);
        let pdu = gtp
            .fields
            .iter()
            .find(|f| f.name == "PDU session container");
        assert_eq!(pdu.unwrap().value, "uplink, QFI 9");
        // GTP-U length counts everything after the first 8 bytes.
        let at = 14 + 20 + 8;
        assert_eq!(
            usize::from(u16::from_be_bytes([b[at + 2], b[at + 3]])),
            b.len() - at - 8
        );
        assert_eq!(&b[34..38], &[0x08, 0x68, 0x08, 0x68]); // 2152 both ways

        let (b, d) = built("eth/ipv4/gre(key=42,seq=3,csum=1)/eth/ipv4/icmp");
        assert_eq!(d.protocol, "ICMP");
        let gre = d.layer("GRE").unwrap();
        assert!(gre.title.contains("Transparent Ethernet"), "{}", gre.title);
        assert_eq!(&b[34..36], &[0xb0, 0x00]);
        let (_, d) = built("eth/ipv6/gre/ipv4/udp/raw(len=4)");
        assert_eq!(d.protocol, "UDP");

        // IP in IP, all four ways.
        for spec in [
            "eth/ipv4/ipv4/icmp",
            "eth/ipv4/ipv6/icmp",
            "eth/ipv6/ipv4/icmp",
            "eth/ipv6/ipv6/icmp",
        ] {
            let (_, d) = built(spec);
            assert_eq!(
                d.layers
                    .iter()
                    .filter(|l| l.protocol.starts_with("IPv"))
                    .count(),
                2,
                "{spec}"
            );
        }
    }

    #[test]
    fn mpls_stacks() {
        let (b, d) =
            built("eth/vlan(id=5)/mpls(label=100,tc=5)/mpls(label=200,ttl=1)/ipv4/udp/raw(len=4)");
        assert_eq!(d.protocol, "UDP");
        // Ethertype 0x8847 after the tag; only the last label has S.
        assert_eq!(&b[16..18], &[0x88, 0x47]);
        assert_eq!(&b[18..22], &[0x00, 0x06, 0x4a, 64]);
        assert_eq!(&b[22..26], &[0x00, 0x0c, 0x81, 1]);
        let (b, d) = built("eth/mpls(label=17)/eth(src=02:00:00:00:00:01)/ipv4/icmp");
        assert_eq!(d.protocol, "ICMP");
        assert_eq!(&b[18..22], &[0, 0, 0, 0], "control word");
        assert!(d.layer("PW").is_some());
        let e = "eth/mpls(label=2000000)"
            .parse::<PacketSpec>()
            .unwrap()
            .build();
        assert!(e.unwrap_err().0.contains("20 bits"));
    }

    #[test]
    fn llc_snap() {
        let (b, d) = built("eth(dst=01:80:c2:00:00:00)/llc(dsap=0x42,ssap=0x42)/raw(len=35)");
        // 802.3 length, then STP's LLC header.
        assert_eq!(&b[12..15], &[0, 38, 0x42]);
        assert_eq!(d.protocol, "STP");
        let (b, d) = built("eth/llc/snap/ipv4/udp/raw(len=4)");
        assert_eq!(d.protocol, "UDP");
        assert_eq!(&b[14..22], &[0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00]);
        let (_, d) =
            built("eth(dst=01:00:0c:cc:cc:cc)/llc/snap(oui=0x00000c,pid=0x2000)/raw(len=20)");
        assert_eq!(d.protocol, "SNAP");
        assert_eq!(d.info, "CDP");
    }

    #[test]
    fn igmp_and_mld_messages() {
        let (b, d) = built(
            "eth/ipv4(dst=224.0.0.22,ttl=1)/igmp(rec=join@239.1.2.3,rec=allow@232.1.1.1+10.0.0.9)",
        );
        assert_eq!(d.protocol, "IGMP");
        assert_eq!(b[34], 0x22);
        assert!(d.info.contains("Join group 239.1.2.3"), "{}", d.info);
        let (_, d) = built("eth/ipv4/igmp(type=query,mrt=100,group=0.0.0.0)");
        assert_eq!(d.info, "v2 Membership Query, general");
        let (b, d) = built("eth/ipv4/igmp(type=v3query,group=239.1.1.1,src=10.0.0.1,src=10.0.0.2)");
        assert_eq!(u16::from_be_bytes([b[16], b[17]]), 20 + 12 + 8);
        assert!(
            d.info.starts_with("v3 Membership Query for 239.1.1.1"),
            "{}",
            d.info
        );
        let (_, d) = built("eth/ipv4/igmp(type=leave,group=239.9.9.9)");
        assert_eq!(d.info, "v2 Leave Group 239.9.9.9");
        let (_, d) = built("eth/ipv4/igmp(ver=1,group=239.9.9.9)");
        assert_eq!(d.info, "v1 Membership Report 239.9.9.9");

        let (_, d) = built("eth/ipv6(hlim=1,dst=ff02::16)/hbh(ra=0)/mld(rec=join@ff3e::1234,rec=block@ff3e::1+2001:db8::1)");
        assert_eq!(d.protocol, "ICMPv6");
        assert!(
            d.info.starts_with("MLDv2 Report / Join group ff3e::1234"),
            "{}",
            d.info
        );
        let (_, d) = built("eth/ipv6/hbh(ra=0)/mld(type=query,group=::)");
        assert_eq!(d.info, "MLDv1 Query, general");
        let (_, d) = built("eth/ipv6/mld(type=v2query,group=ff3e::1,src=2001:db8::5)");
        assert!(d.info.starts_with("MLDv2 Query ff3e::1"), "{}", d.info);
        let (_, d) = built("eth/ipv6/mld(type=done,group=ff3e::1)");
        assert_eq!(d.info, "MLDv1 Done ff3e::1");
        let e = |s: &str| {
            s.parse::<PacketSpec>()
                .and_then(|p| p.build())
                .unwrap_err()
                .0
        };
        assert!(e("eth/ipv4/igmp(rec=join@ff02::1)").contains("invalid rec"));
        assert!(e("eth/ipv6/igmp").contains("igmp cannot follow ipv6"));
    }
}
