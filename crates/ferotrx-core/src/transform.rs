use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::net::{self, MacAddr, TPID_QINQ, TPID_VLAN};
use crate::{Error, Packet, Result};

/// Changes packets on their way from a source to the sink.
///
/// Transforms run in order on every packet of a [`Stream`](crate::Stream), after the
/// source and before pacing, so rates count the bytes that are really sent.
pub trait Transform: Send {
    fn apply(&mut self, packet: &mut Packet);

    /// Moves on as if `n` packets had passed, without seeing them. A stream
    /// split over several workers ([`Stream::shard`](crate::Stream::shard))
    /// calls it for the packets other workers send, so transforms that count
    /// or draw random values give each packet the value it would have had in
    /// a single run. Transforms without state ignore it.
    fn skip(&mut self, _n: u64) {}
}

impl<T: Transform + ?Sized> Transform for Box<T> {
    fn apply(&mut self, packet: &mut Packet) {
        (**self).apply(packet)
    }
    fn skip(&mut self, n: u64) {
        (**self).skip(n)
    }
}

/// Which address or port of a packet a rewrite touches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Src,
    Dst,
    /// Source and destination.
    Both,
}

impl Field {
    fn src(self) -> bool {
        matches!(self, Field::Src | Field::Both)
    }
    fn dst(self) -> bool {
        matches!(self, Field::Dst | Field::Both)
    }
}

/// Sets Ethernet addresses, optionally only those equal to `from`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacRewrite {
    pub field: Field,
    pub from: Option<MacAddr>,
    pub to: MacAddr,
}

impl Transform for MacRewrite {
    fn apply(&mut self, packet: &mut Packet) {
        let data = &mut packet.data;
        if data.len() < net::ETH_HEADER {
            return;
        }
        for (wanted, range) in [(self.field.dst(), 0..6), (self.field.src(), 6..12)] {
            if wanted && self.from.is_none_or(|f| data[range.clone()] == f.0) {
                data[range].copy_from_slice(&self.to.0);
            }
        }
    }
}

/// Rewrites IPv4 or IPv6 addresses and fixes the checksums that cover them.
///
/// Without `from`, every address of the same family as `to` becomes `to`.
/// With `from = (net, len)`, addresses inside `net/len` keep their host bits and
/// take the first `len` bits of `to`, like a pseudo NAT: `10.0.0.0/8 -> 172.16.0.0`
/// turns 10.1.2.3 into 172.1.2.3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpRewrite {
    pub field: Field,
    pub from: Option<(IpAddr, u8)>,
    pub to: IpAddr,
}

impl IpRewrite {
    pub fn new(field: Field, from: Option<(IpAddr, u8)>, to: IpAddr) -> Result<Self> {
        if let Some((net, len)) = from {
            if net.is_ipv4() != to.is_ipv4() {
                return Err(Error::InvalidSpec(format!(
                    "cannot map {net}/{len} to {to}: different address families"
                )));
            }
            let max = if net.is_ipv4() { 32 } else { 128 };
            if len > max {
                return Err(Error::InvalidSpec(format!(
                    "prefix length {len} is longer than {max}"
                )));
            }
        }
        Ok(Self { field, from, to })
    }

    /// The new address for `old`, or `None` to leave it.
    fn map(&self, old: &[u8]) -> Option<Vec<u8>> {
        let (to, bits) = match self.to {
            IpAddr::V4(a) if old.len() == 4 => (u128::from(u32::from(a)), 32),
            IpAddr::V6(a) if old.len() == 16 => (u128::from(a), 128),
            _ => return None,
        };
        let mut buf = [0u8; 16];
        buf[16 - old.len()..].copy_from_slice(old);
        let old_v = u128::from_be_bytes(buf);
        let new_v = match self.from {
            None => to,
            Some((net, len)) => {
                let net_v = match net {
                    IpAddr::V4(a) => u128::from(u32::from(a)),
                    IpAddr::V6(a) => u128::from(a),
                };
                let host_bits = bits - u32::from(len);
                let mask = if host_bits >= bits {
                    0
                } else {
                    (u128::MAX >> (128 - bits)) & !((1u128 << host_bits) - 1)
                };
                if old_v & mask != net_v & mask {
                    return None;
                }
                (to & mask) | (old_v & !mask)
            }
        };
        Some(new_v.to_be_bytes()[16 - old.len()..].to_vec())
    }
}

impl Transform for IpRewrite {
    fn apply(&mut self, packet: &mut Packet) {
        let data = &mut packet.data;
        let Some(layers) = net::parse(data) else {
            return;
        };
        let Some(ip) = &layers.ip else {
            return;
        };
        let sums = layers.sums(data);
        for (wanted, range) in [
            (self.field.src(), ip.src.clone()),
            (self.field.dst(), ip.dst.clone()),
        ] {
            if !wanted {
                continue;
            }
            if let Some(new) = self.map(&data[range.clone()]) {
                net::write_with(data, range, &new, &sums);
            }
        }
    }
}

/// Sets TCP and UDP ports, optionally only those equal to `from`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortRewrite {
    pub field: Field,
    pub from: Option<u16>,
    pub to: u16,
}

impl Transform for PortRewrite {
    fn apply(&mut self, packet: &mut Packet) {
        let data = &mut packet.data;
        let Some(layers) = net::parse(data) else {
            return;
        };
        let Some(at) = layers.ip.as_ref().and_then(|ip| ip.ports(data)) else {
            return;
        };
        let sums = layers.sums(data);
        for (wanted, off) in [(self.field.src(), at), (self.field.dst(), at + 2)] {
            let old = net::be16(data, off).expect("ports() checked the length");
            if wanted && self.from.is_none_or(|f| f == old) {
                net::write_with(data, off..off + 2, &self.to.to_be_bytes(), &sums);
            }
        }
    }
}

/// Adds an outer VLAN tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VlanPush {
    /// Tag protocol: [`TPID_VLAN`] (0x8100) or [`TPID_QINQ`] (0x88a8).
    pub tpid: u16,
    pub id: u16,
    pub pcp: u8,
}

impl Transform for VlanPush {
    fn apply(&mut self, packet: &mut Packet) {
        if packet.data.len() < net::ETH_HEADER {
            return;
        }
        let tci = (u16::from(self.pcp) << 13) | self.id;
        let mut tag = [0u8; 4];
        tag[..2].copy_from_slice(&self.tpid.to_be_bytes());
        tag[2..].copy_from_slice(&tci.to_be_bytes());
        packet.data.splice(12..12, tag);
    }
}

/// Removes the outer VLAN tag, if there is one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VlanPop;

impl Transform for VlanPop {
    fn apply(&mut self, packet: &mut Packet) {
        let data = &mut packet.data;
        if data.len() >= net::ETH_HEADER + 4 && net::be16(data, 12).is_some_and(net::is_vlan_tpid) {
            data.drain(12..16);
        }
    }
}

/// Changes the ID and/or priority of the outer VLAN tag, if there is one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VlanSet {
    pub id: Option<u16>,
    pub pcp: Option<u8>,
}

impl Transform for VlanSet {
    fn apply(&mut self, packet: &mut Packet) {
        let data = &mut packet.data;
        if !net::be16(data, 12).is_some_and(net::is_vlan_tpid) {
            return;
        }
        let Some(mut tci) = net::be16(data, 14) else {
            return;
        };
        if let Some(id) = self.id {
            tci = (tci & 0xf000) | id;
        }
        if let Some(pcp) = self.pcp {
            tci = (tci & 0x1fff) | (u16::from(pcp) << 13);
        }
        net::put16(data, 14, tci);
    }
}

/// Recomputes IPv4 header and TCP/UDP/ICMPv6 checksums, for captures taken
/// with checksum offload where the stored checksums are wrong.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FixChecksums;

impl Transform for FixChecksums {
    fn apply(&mut self, packet: &mut Packet) {
        net::fix_checksums(&mut packet.data);
    }
}

/// Puts every packet into a tunnel: the headers of a packet description
/// ([`ferotrx_packet::PacketSpec`] text) go in front of it.
///
/// When the description ends with `vxlan`, or with `eth` (as in
/// `.../gre/eth` or `.../mpls/eth`), the whole Ethernet frame is carried;
/// otherwise its IP datagram is, and the tunnel's protocol fields follow
/// its IP version. The tunnel's length fields and checksums are set for
/// each packet; the carried packet is left as it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encap {
    spec: String,
    carry_eth: bool,
    /// The headers for an IPv4 and an IPv6 datagram, or for an Ethernet frame.
    v4: Vec<u8>,
    v6: Vec<u8>,
    /// How many tunnels the headers hold, for their lengths and checksums.
    tunnels: usize,
}

impl Encap {
    /// Builds the headers of `spec` once; packets only get a copy.
    #[cfg(feature = "build")]
    pub fn new(spec: &str) -> Result<Self> {
        use ferotrx_packet::{LayerSpec, PacketSpec};
        let bad = |m: String| Error::InvalidSpec(format!("encap '{spec}': {m}"));
        let parsed: PacketSpec = spec.parse().map_err(|e| bad(format!("{e}")))?;
        if !matches!(parsed.layers.first(), Some(LayerSpec::Ethernet(_))) {
            return Err(bad("must start with eth".into()));
        }
        let carry_eth = matches!(
            parsed.layers.last(),
            Some(LayerSpec::Vxlan(_) | LayerSpec::Ethernet(_))
        );
        if parsed.layers.len() < 2 {
            return Err(bad("needs headers after eth".into()));
        }
        let header = |inner: &str, inner_len: usize| -> Result<Vec<u8>> {
            let mut text = spec.trim().to_string();
            if matches!(parsed.layers.last(), Some(LayerSpec::Vxlan(_))) {
                text.push_str("/eth");
            }
            text.push_str(&format!("/{inner}/raw(len=100)"));
            let full: PacketSpec = text.parse().map_err(|e| bad(format!("{e}")))?;
            let mut bytes = full.build().map_err(|e| bad(format!("{e}")))?;
            let cut = bytes
                .len()
                .checked_sub(inner_len + 100)
                .ok_or_else(|| bad("cannot carry a packet".into()))?;
            bytes.truncate(cut);
            Ok(bytes)
        };
        let (v4, v6) = if carry_eth {
            // The placeholder's Ethernet header is cut off with it.
            let h = header("ipv4", 34)?;
            (h.clone(), h)
        } else {
            (header("ipv4", 20)?, header("ipv6", 40)?)
        };
        let mut probe = v4.clone();
        probe.extend(Self::placeholder(carry_eth));
        let tunnels = net::parse(&probe).map_or(0, |l| l.tunnels.len());
        Ok(Self {
            spec: spec.trim().to_string(),
            carry_eth,
            v4,
            v6,
            tunnels,
        })
    }

    #[cfg(not(feature = "build"))]
    pub fn new(spec: &str) -> Result<Self> {
        Err(Error::InvalidSpec(format!(
            "encap '{spec}': this build has no packet builder"
        )))
    }

    #[cfg(feature = "build")]
    fn placeholder(carry_eth: bool) -> Vec<u8> {
        let mut p = Vec::new();
        if carry_eth {
            p.extend([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00]);
        }
        p.extend([
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 59, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ]);
        p
    }

    /// The description the headers came from.
    pub fn spec(&self) -> &str {
        &self.spec
    }
}

impl Transform for Encap {
    fn apply(&mut self, packet: &mut Packet) {
        let data = &packet.data;
        let Some((l3, et)) = net::l3_offset(data) else {
            return;
        };
        let (header, carried) = if self.carry_eth {
            (&self.v4, &data[..])
        } else {
            let header = match et {
                net::ETHERTYPE_IPV4 => &self.v4,
                net::ETHERTYPE_IPV6 => &self.v6,
                _ => return,
            };
            // The outermost datagram, without Ethernet padding.
            let end = net::parse(data)
                .and_then(|l| l.tunnels.first().map(|t| t.ip.clone()).or(l.ip))
                .and_then(|ip| ip.end)
                .unwrap_or(data.len());
            (header, &data[l3..end])
        };
        let mut out = Vec::with_capacity(header.len() + carried.len());
        out.extend_from_slice(header);
        out.extend_from_slice(carried);
        if let Some(mut layers) = net::parse(&out) {
            layers.tunnels.truncate(self.tunnels);
            let end = out.len();
            net::fix_tunnel_lengths(&mut out, &layers, end);
            if let Some(mut layers) = net::parse(&out) {
                layers.tunnels.truncate(self.tunnels);
                net::fix_tunnels(&mut out, &layers);
            }
        }
        packet.data = out;
    }
}

/// Takes the outermost tunnel off: an MPLS label stack in front of the IP
/// header, or the IP in IP, GRE, VXLAN, Geneve or GTP-U tunnel around the
/// packet. Packets without one are left alone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Decap;

impl Transform for Decap {
    fn apply(&mut self, packet: &mut Packet) {
        let data = &packet.data;
        let Some((l3, et)) = net::l3_offset(data) else {
            return;
        };
        if matches!(et, net::ETHERTYPE_MPLS | net::ETHERTYPE_MPLS_MC) {
            let mut at = l3;
            while at + 4 <= data.len() && data[at + 2] & 1 == 0 {
                at += 4;
            }
            at += 4;
            let out = match data.get(at).map(|b| b >> 4) {
                Some(0) if at + 4 + net::ETH_HEADER <= data.len() => data[at + 4..].to_vec(),
                Some(4) => with_type(&data[..l3], net::ETHERTYPE_IPV4, &data[at..]),
                Some(6) => with_type(&data[..l3], net::ETHERTYPE_IPV6, &data[at..]),
                _ => return,
            };
            packet.data = out;
            return;
        }
        let Some(t) = net::parse(data).and_then(|l| l.tunnels.into_iter().next()) else {
            return;
        };
        let end = t.ip.end.unwrap_or(data.len());
        packet.data = if t.inner_type == net::ETHERTYPE_TEB {
            data[t.inner..end].to_vec()
        } else if t.ip.start == l3 {
            with_type(&data[..l3], t.inner_type, &data[t.inner..end])
        } else {
            return;
        };
    }
}

/// The Ethernet header `l2` with its last ethertype set to `et`, then `rest`.
fn with_type(l2: &[u8], et: u16, rest: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(l2.len() + rest.len());
    out.extend_from_slice(l2);
    let n = out.len();
    out[n - 2..].copy_from_slice(&et.to_be_bytes());
    out.extend_from_slice(rest);
    out
}

/// Adds an MPLS label in front of the IP header (or of the labels already there).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MplsPush {
    pub label: u32,
    pub tc: u8,
    pub ttl: u8,
}

impl Transform for MplsPush {
    fn apply(&mut self, packet: &mut Packet) {
        let data = &mut packet.data;
        let Some((l3, et)) = net::l3_offset(data) else {
            return;
        };
        let bos = match et {
            net::ETHERTYPE_IPV4 | net::ETHERTYPE_IPV6 => 1,
            net::ETHERTYPE_MPLS | net::ETHERTYPE_MPLS_MC => 0,
            _ => return,
        };
        let entry =
            (self.label << 12) | (u32::from(self.tc) << 9) | (bos << 8) | u32::from(self.ttl);
        data.splice(l3..l3, entry.to_be_bytes());
        if bos == 1 {
            net::put16(data, l3 - 2, net::ETHERTYPE_MPLS);
        }
    }
}

/// Removes the outermost MPLS label; after the last one the ethertype
/// follows the IP version, and a pseudowire's Ethernet frame comes out whole.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MplsPop;

impl Transform for MplsPop {
    fn apply(&mut self, packet: &mut Packet) {
        let data = &mut packet.data;
        let Some((l3, et)) = net::l3_offset(data) else {
            return;
        };
        if !matches!(et, net::ETHERTYPE_MPLS | net::ETHERTYPE_MPLS_MC) || l3 + 4 > data.len() {
            return;
        }
        if data[l3 + 2] & 1 == 0 {
            data.drain(l3..l3 + 4);
            return;
        }
        match data.get(l3 + 4).map(|b| b >> 4) {
            Some(0) if l3 + 8 + net::ETH_HEADER <= data.len() => {
                data.drain(..l3 + 8);
            }
            Some(v @ (4 | 6)) => {
                let t = if v == 4 {
                    net::ETHERTYPE_IPV4
                } else {
                    net::ETHERTYPE_IPV6
                };
                data.drain(l3..l3 + 4);
                net::put16(data, l3 - 2, t);
            }
            _ => {}
        }
    }
}

/// One of the built-in rewrites, parsed from the text form the CLI and profiles use.
///
/// | Text | Effect |
/// | --- | --- |
/// | `mac_src=TO`, `mac_dst=TO`, `mac=TO` | Set Ethernet addresses; `FROM->TO` only changes `FROM`. |
/// | `ip_src=TO`, `ip_dst=TO`, `ip=TO` | Set IPv4/IPv6 addresses; `NET/LEN->TO` maps a prefix and keeps host bits. |
/// | `port_src=TO`, `port_dst=TO`, `port=TO` | Set TCP/UDP ports; `FROM->TO` only changes `FROM`. |
/// | `vlan_push=ID[:PCP]`, `qinq_push=ID[:PCP]` | Add an outer 802.1Q or 802.1ad tag. |
/// | `vlan_set=ID[:PCP]` | Change the outer tag. |
/// | `vlan_pop` | Remove the outer tag. |
/// | `fix_checksums` | Recompute checksums. |
/// | `encap=SPEC` | Put the packet in a tunnel built from a packet description, such as `eth/ipv4(dst=10.0.0.2)/udp/vxlan(vni=100)`. |
/// | `decap` | Take the outermost tunnel or MPLS label stack off. |
/// | `mpls_push=LABEL[:TC[:TTL]]` | Add an MPLS label (TTL 64 unless given). |
/// | `mpls_pop` | Remove the outermost MPLS label. |
///
/// Address and port rewrites keep checksums correct (or exactly as wrong as they
/// were in the capture). In tunneled packets they change the innermost headers,
/// and the tunnel's UDP and GRE checksums follow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rewrite {
    Mac(MacRewrite),
    Ip(IpRewrite),
    Port(PortRewrite),
    VlanPush(VlanPush),
    VlanPop(VlanPop),
    VlanSet(VlanSet),
    FixChecksums(FixChecksums),
    Encap(Encap),
    Decap(Decap),
    MplsPush(MplsPush),
    MplsPop(MplsPop),
}

impl Transform for Rewrite {
    fn apply(&mut self, packet: &mut Packet) {
        match self {
            Rewrite::Mac(t) => t.apply(packet),
            Rewrite::Ip(t) => t.apply(packet),
            Rewrite::Port(t) => t.apply(packet),
            Rewrite::VlanPush(t) => t.apply(packet),
            Rewrite::VlanPop(t) => t.apply(packet),
            Rewrite::VlanSet(t) => t.apply(packet),
            Rewrite::FixChecksums(t) => t.apply(packet),
            Rewrite::Encap(t) => t.apply(packet),
            Rewrite::Decap(t) => t.apply(packet),
            Rewrite::MplsPush(t) => t.apply(packet),
            Rewrite::MplsPop(t) => t.apply(packet),
        }
    }
}

impl FromStr for Rewrite {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        let (op, arg) = match s.split_once('=') {
            Some((op, arg)) => (op.trim(), Some(arg.trim())),
            None => (s, None),
        };
        let err = |msg: &str| Error::InvalidSpec(format!("rewrite '{s}': {msg}"));
        let need = || {
            arg.filter(|a| !a.is_empty())
                .ok_or_else(|| err("needs a value after '='"))
        };
        let field = |name: &str| match name.rsplit_once('_').map(|(_, f)| f) {
            Some("src") => Field::Src,
            Some("dst") => Field::Dst,
            _ => Field::Both,
        };
        let parse_err = |e: Error| match e {
            Error::InvalidSpec(m) => err(&m),
            other => other,
        };

        Ok(match op {
            "mac" | "mac_src" | "mac_dst" => {
                let (from, to) = from_to(need()?);
                Rewrite::Mac(MacRewrite {
                    field: field(op),
                    from: from.map(str::parse).transpose().map_err(parse_err)?,
                    to: to.parse().map_err(parse_err)?,
                })
            }
            "ip" | "ip_src" | "ip_dst" => {
                let (from, to) = from_to(need()?);
                let to: IpAddr = to.parse().map_err(|_| err(&format!("invalid address '{to}'")))?;
                let from = from
                    .map(|f| parse_prefix(f).map_err(parse_err))
                    .transpose()?;
                Rewrite::Ip(IpRewrite::new(field(op), from, to).map_err(parse_err)?)
            }
            "port" | "port_src" | "port_dst" => {
                let (from, to) = from_to(need()?);
                let port = |p: &str| p.parse::<u16>().map_err(|_| err(&format!("invalid port '{p}'")));
                Rewrite::Port(PortRewrite {
                    field: field(op),
                    from: from.map(port).transpose()?,
                    to: port(to)?,
                })
            }
            "vlan_push" | "qinq_push" => {
                let (id, pcp) = parse_tag(need()?).map_err(parse_err)?;
                Rewrite::VlanPush(VlanPush {
                    tpid: if op == "vlan_push" { TPID_VLAN } else { TPID_QINQ },
                    id,
                    pcp: pcp.unwrap_or(0),
                })
            }
            "vlan_set" => {
                let (id, pcp) = parse_tag(need()?).map_err(parse_err)?;
                Rewrite::VlanSet(VlanSet { id: Some(id), pcp })
            }
            "encap" => Rewrite::Encap(Encap::new(need()?).map_err(parse_err)?),
            "mpls_push" => {
                let v = need()?;
                let mut it = v.split(':').map(str::trim);
                let label = it
                    .next()
                    .and_then(|l| l.parse::<u32>().ok())
                    .filter(|&l| l < 1 << 20)
                    .ok_or_else(|| err("label must be 0 to 1048575"))?;
                let tc = match it.next() {
                    Some(t) => t
                        .parse::<u8>()
                        .ok()
                        .filter(|&t| t < 8)
                        .ok_or_else(|| err("traffic class must be 0 to 7"))?,
                    None => 0,
                };
                let ttl = match it.next() {
                    Some(t) => t.parse::<u8>().map_err(|_| err("TTL must be 0 to 255"))?,
                    None => 64,
                };
                if it.next().is_some() {
                    return Err(err("expected LABEL[:TC[:TTL]]"));
                }
                Rewrite::MplsPush(MplsPush { label, tc, ttl })
            }
            "vlan_pop" | "fix_checksums" | "decap" | "mpls_pop" if arg.is_some() => {
                return Err(err("takes no value"))
            }
            "vlan_pop" => Rewrite::VlanPop(VlanPop),
            "fix_checksums" => Rewrite::FixChecksums(FixChecksums),
            "decap" => Rewrite::Decap(Decap),
            "mpls_pop" => Rewrite::MplsPop(MplsPop),
            _ => return Err(err("unknown rewrite (try mac_dst, ip_src, port_dst, vlan_push, vlan_pop, vlan_set, fix_checksums, encap, decap, mpls_push, mpls_pop)")),
        })
    }
}

impl fmt::Display for Rewrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn field(f: Field) -> &'static str {
            match f {
                Field::Src => "_src",
                Field::Dst => "_dst",
                Field::Both => "",
            }
        }
        match self {
            Rewrite::Mac(r) => {
                write!(f, "mac{}=", field(r.field))?;
                if let Some(from) = r.from {
                    write!(f, "{from}->")?;
                }
                write!(f, "{}", r.to)
            }
            Rewrite::Ip(r) => {
                write!(f, "ip{}=", field(r.field))?;
                if let Some((net, len)) = r.from {
                    write!(f, "{net}/{len}->")?;
                }
                write!(f, "{}", r.to)
            }
            Rewrite::Port(r) => {
                write!(f, "port{}=", field(r.field))?;
                if let Some(from) = r.from {
                    write!(f, "{from}->")?;
                }
                write!(f, "{}", r.to)
            }
            Rewrite::VlanPush(r) => {
                let op = if r.tpid == TPID_QINQ {
                    "qinq_push"
                } else {
                    "vlan_push"
                };
                write!(f, "{op}={}:{}", r.id, r.pcp)
            }
            Rewrite::VlanSet(r) => {
                write!(f, "vlan_set={}", r.id.unwrap_or(0))?;
                if let Some(pcp) = r.pcp {
                    write!(f, ":{pcp}")?;
                }
                Ok(())
            }
            Rewrite::VlanPop(_) => f.write_str("vlan_pop"),
            Rewrite::FixChecksums(_) => f.write_str("fix_checksums"),
            Rewrite::Encap(r) => write!(f, "encap={}", r.spec),
            Rewrite::Decap(_) => f.write_str("decap"),
            Rewrite::MplsPush(r) => write!(f, "mpls_push={}:{}:{}", r.label, r.tc, r.ttl),
            Rewrite::MplsPop(_) => f.write_str("mpls_pop"),
        }
    }
}

/// Splits `FROM->TO` into its parts; a bare `TO` has no `FROM`.
fn from_to(a: &str) -> (Option<&str>, &str) {
    match a.split_once("->") {
        Some((from, to)) => (Some(from.trim()), to.trim()),
        None => (None, a),
    }
}

/// Parses `ADDR/LEN`, or a bare address as an exact match.
fn parse_prefix(s: &str) -> Result<(IpAddr, u8)> {
    let bad = || Error::InvalidSpec(format!("invalid prefix '{s}'"));
    let (addr, len) = match s.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (s, None),
    };
    let addr: IpAddr = addr.trim().parse().map_err(|_| bad())?;
    let len = match len {
        Some(l) => l.trim().parse().map_err(|_| bad())?,
        None if addr.is_ipv4() => 32,
        None => 128,
    };
    Ok((addr, len))
}

/// Parses `ID[:PCP]`.
fn parse_tag(s: &str) -> Result<(u16, Option<u8>)> {
    let (id, pcp) = match s.split_once(':') {
        Some((i, p)) => (i, Some(p)),
        None => (s, None),
    };
    let id: u16 = id
        .trim()
        .parse()
        .ok()
        .filter(|&i| i < 4096)
        .ok_or_else(|| Error::InvalidSpec(format!("VLAN ID '{id}' must be 0 to 4095")))?;
    let pcp = pcp
        .map(|p| {
            p.trim()
                .parse::<u8>()
                .ok()
                .filter(|&v| v < 8)
                .ok_or_else(|| Error::InvalidSpec(format!("priority '{p}' must be 0 to 7")))
        })
        .transpose()?;
    Ok((id, pcp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::tests::{checksums_ok, tcp6, udp4};
    use std::time::Duration;

    fn run(spec: &str, data: Vec<u8>) -> Vec<u8> {
        let mut r: Rewrite = spec.parse().unwrap();
        let mut p = Packet::new(Duration::ZERO, data);
        r.apply(&mut p);
        p.data
    }

    #[test]
    fn mac_rewrite() {
        let out = run("mac_dst=aa:bb:cc:dd:ee:ff", udp4());
        assert_eq!(&out[0..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(&out[6..12], &udp4()[6..12]);
        // `from` that does not match leaves the frame alone.
        assert_eq!(
            run("mac=00:00:00:00:00:09->aa:bb:cc:dd:ee:ff", udp4()),
            udp4()
        );
    }

    #[test]
    fn ip_set_keeps_checksums_valid() {
        let out = run("ip_dst=192.168.1.1", udp4());
        assert_eq!(&out[30..34], &[192, 168, 1, 1]);
        assert_eq!(&out[26..30], &[10, 0, 0, 1]);
        assert!(checksums_ok(&out));
    }

    #[test]
    fn ip_prefix_map_keeps_host_bits() {
        let out = run("ip=10.0.0.0/8->172.16.0.0", udp4());
        assert_eq!(&out[26..30], &[172, 0, 0, 1]);
        assert_eq!(&out[30..34], &[172, 0, 0, 2]);
        assert!(checksums_ok(&out));
        // Outside the prefix: untouched.
        assert_eq!(run("ip=192.168.0.0/16->172.16.0.0", udp4()), udp4());
        // Exact match form.
        let out = run("ip_src=10.0.0.1->1.2.3.4", udp4());
        assert_eq!(&out[26..30], &[1, 2, 3, 4]);
        // Wrong family: untouched.
        assert_eq!(run("ip=2001:db8::9", udp4()), udp4());
    }

    #[test]
    fn ipv6_rewrite_fixes_tcp_checksum() {
        let out = run("ip_dst=2001:db8::/32->fd00::", tcp6());
        assert_eq!(&out[38..42], &[0xfd, 0, 0, 0]);
        assert!(checksums_ok(&out));
    }

    #[test]
    fn port_rewrite() {
        let out = run("port_dst=53->5353", udp4());
        assert_eq!(&out[36..38], &5353u16.to_be_bytes());
        assert!(checksums_ok(&out));
        let out = run("port=8080", tcp6());
        assert_eq!(&out[54..58], &[0x1f, 0x90, 0x1f, 0x90]);
        assert!(checksums_ok(&out));
    }

    #[test]
    fn udp_zero_checksum_stays_zero() {
        let mut p = udp4();
        p[40] = 0;
        p[41] = 0;
        let out = run("ip_dst=1.1.1.1", p);
        assert_eq!(&out[40..42], &[0, 0]);
    }

    #[test]
    fn wrong_checksums_stay_exactly_wrong() {
        let mut p = udp4();
        p[40] ^= 0x55;
        let out = run("ip_dst=1.1.1.1", p);
        let mut fixed = out.clone();
        net::fix_checksums(&mut fixed);
        assert_eq!(out[40] ^ 0x55, fixed[40]);
        assert_eq!(out[41], fixed[41]);
    }

    #[test]
    fn vlan_push_set_pop() {
        let tagged = run("vlan_push=100:5", udp4());
        assert_eq!(tagged.len(), udp4().len() + 4);
        assert_eq!(&tagged[12..16], &[0x81, 0x00, 0xa0, 100]);
        // Rewrites still find the IP header behind the tag.
        let rewritten = run("ip_dst=9.9.9.9", tagged.clone());
        assert_eq!(&rewritten[34..38], &[9, 9, 9, 9]);
        assert!(checksums_ok(&rewritten));

        let set = run("vlan_set=200", tagged.clone());
        assert_eq!(&set[14..16], &[0xa0, 200]);
        assert_eq!(run("vlan_pop", tagged), udp4());
        // Pop on an untagged frame does nothing.
        assert_eq!(run("vlan_pop", udp4()), udp4());
        let qinq = run("qinq_push=7", udp4());
        assert_eq!(&qinq[12..16], &[0x88, 0xa8, 0, 7]);
    }

    #[test]
    fn fix_checksums_repairs() {
        let mut p = udp4();
        p[24] = 0;
        p[25] = 0;
        p[40] = 0x12;
        assert!(!checksums_ok(&p));
        assert!(checksums_ok(&run("fix_checksums", p)));
    }

    #[test]
    fn specs_round_trip_and_reject_garbage() {
        for s in [
            "mac_dst=aa:bb:cc:dd:ee:ff",
            "mac_src=00:00:00:00:00:01->aa:bb:cc:dd:ee:ff",
            "ip=10.0.0.0/8->172.16.0.0",
            "ip_src=2001:db8::/32->fd00::",
            "port_dst=53->5353",
            "vlan_push=100:5",
            "qinq_push=7:0",
            "vlan_set=200:1",
            "vlan_pop",
            "fix_checksums",
        ] {
            let r: Rewrite = s.parse().unwrap();
            assert_eq!(r.to_string(), s);
        }
        for s in [
            "nope",
            "mac_dst=",
            "ip_dst=300.0.0.1",
            "ip=10.0.0.0/8->fd00::",
            "ip=10.0.0.0/40->1.2.3.4",
            "port=70000",
            "vlan_push=5000",
            "vlan_push=10:9",
            "vlan_pop=1",
        ] {
            assert!(s.parse::<Rewrite>().is_err(), "{s} should fail");
        }
    }

    #[cfg(feature = "build")]
    fn clean(frame: &[u8]) -> bool {
        let d = ferotrx_packet::decode(1, frame);
        if !d.problems.is_empty() {
            eprintln!("{:?}", d.problems);
        }
        d.problems.is_empty()
    }

    #[cfg(feature = "build")]
    fn built(spec: &str) -> Vec<u8> {
        spec.parse::<ferotrx_packet::PacketSpec>()
            .unwrap()
            .build()
            .unwrap()
    }

    #[cfg(feature = "build")]
    fn rw(r: &str, frame: &[u8]) -> Vec<u8> {
        let mut r: Rewrite = r.parse().unwrap();
        let mut p = Packet::new(Duration::ZERO, frame.to_vec());
        r.apply(&mut p);
        p.data
    }

    #[cfg(feature = "build")]
    #[test]
    fn encap_and_decap_every_tunnel() {
        let plain = udp4();
        for spec in [
            "eth/ipv4(dst=10.9.0.2)/udp/vxlan(vni=100)",
            "eth/ipv6/udp/geneve(vni=7)",
            "eth/ipv6/udp/geneve(vni=7)/eth",
            "eth/ipv4/udp/gtpu(teid=5,qfi=9)",
            "eth/ipv4/gre(key=3,csum=1)",
            "eth/ipv4/gre/eth",
            "eth/ipv6/ipv4",
            "eth/ipv4",
            "eth/mpls(label=20)/mpls(label=30)",
            "eth/mpls(label=17)/eth",
            "eth/vlan(id=5)/ipv4/udp/vxlan",
        ] {
            let r: Rewrite = format!("encap={spec}").parse().unwrap();
            assert_eq!(r.to_string(), format!("encap={spec}"));
            let t = rw(&format!("encap={spec}"), &plain);
            assert!(clean(&t), "{spec}");
            assert!(t.len() > plain.len(), "{spec}");
            let back = rw("decap", &t);
            assert_eq!(back[back.len() - 32..], plain[14..], "{spec}");
            assert!(checksums_ok(&back), "{spec}");
            // IPv6 inside too.
            let t6 = rw(&format!("encap={spec}"), &tcp6());
            assert!(clean(&t6), "{spec} v6");
        }
        assert!("encap=ipv4/udp".parse::<Rewrite>().is_err());
        assert!("encap=eth".parse::<Rewrite>().is_err());
        assert!("encap=eth/nope".parse::<Rewrite>().is_err());
    }

    #[cfg(feature = "build")]
    #[test]
    fn rewrites_reach_inside_tunnels() {
        for spec in [
            "eth/ipv4(src=10.0.0.1,dst=10.0.0.2)/udp/vxlan(vni=5)/eth/ipv4(src=192.168.1.1,dst=192.168.1.2)/udp(sport=1,dport=2)/raw(len=11)",
            "eth/ipv6/udp/gtpu(teid=9,qfi=1)/ipv4(src=192.168.1.1,dst=192.168.1.2)/tcp/raw(len=3)",
            "eth/ipv4/gre(csum=1,key=4)/ipv6(src=fd00::1)/udp/raw(len=4)",
            "eth/mpls(label=9)/ipv4/ipv4(src=192.168.1.1,dst=192.168.1.2)/udp/raw(len=4)",
        ] {
            let f = built(spec);
            assert!(clean(&f), "{spec}");
            let mut bad = f.clone();
            let n = bad.len();
            bad[n - 1] ^= 1;
            assert!(!clean(&bad), "{spec}: a flipped bit goes unnoticed");
            for r in [
                "ip_src=172.16.0.9",
                "ip_dst=fd00::99",
                "port_dst=4000",
                "mac_src=02:00:00:00:00:77",
                "fix_checksums",
            ] {
                let out = rw(r, &f);
                assert!(clean(&out), "{spec} {r}");
            }
            let out = rw("ip_src=172.16.0.9", &f);
            let inner = net::parse(&out).unwrap().ip.unwrap();
            if inner.version == 4 {
                assert_eq!(out[inner.src], [172, 16, 0, 9], "{spec}");
            }
        }
    }

    #[cfg(feature = "build")]
    #[test]
    fn mpls_push_and_pop() {
        let plain = udp4();
        let one = rw("mpls_push=100:5", &plain);
        let two = rw("mpls_push=200:0:1", &one);
        assert!(clean(&two));
        assert_eq!(net::be16(&two, 12), Some(net::ETHERTYPE_MPLS));
        assert_eq!(&two[14..18], &[0x00, 0x0c, 0x80, 0x01]);
        assert_eq!(&two[18..22], &[0x00, 0x06, 0x4b, 0x40]);
        assert_eq!(rw("mpls_pop", &rw("mpls_pop", &two)), plain);
        assert_eq!(rw("decap", &two), plain);
        assert_eq!(rw("mpls_pop", &plain), plain);
        let pw = built("eth/mpls(label=17)/eth(src=02:00:00:00:00:01)/ipv4/icmp");
        let inner = rw("mpls_pop", &pw);
        assert_eq!(&inner[6..12], &[2, 0, 0, 0, 0, 1]);
        assert!("mpls_push=1048576".parse::<Rewrite>().is_err());
        assert!("mpls_push=1:8".parse::<Rewrite>().is_err());
        assert_eq!(
            "mpls_push=5".parse::<Rewrite>().unwrap().to_string(),
            "mpls_push=5:0:64"
        );
    }
}
