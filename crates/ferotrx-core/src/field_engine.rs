//! The field engine: changes fields from packet to packet, like TRex's field engine.
//!
//! A [`FieldVar`] names a packet field and a range of values; a [`FieldEngine`]
//! holds several of them and, as a [`Transform`], writes the next value of
//! each into every packet that passes. Checksums and lengths are kept right.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::net::{self, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP};
use crate::{Error, MacAddr, Packet, Result, Transform};

const IPPROTO_ICMP: u8 = 1;

/// Which side of a packet an address or port variable writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Src,
    Dst,
    /// Source and destination; only for `+=` variables, which shift both by the same amount.
    Both,
}

/// The packet field a [`FieldVar`] writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VarField {
    /// Ethernet address (48 bits).
    Mac(Side),
    /// IPv4 (32 bits) or IPv6 (128 bits) address.
    Ip(Side),
    /// TCP or UDP port.
    Port(Side),
    /// ID of the outer VLAN tag (12 bits); priority and DEI are kept.
    Vlan,
    /// IPv4 identification.
    IpId,
    /// IPv4 TTL or IPv6 hop limit.
    Ttl,
    /// `size` bytes, big endian, `offset` bytes into the payload: after the
    /// TCP, UDP or ICMP header, after the IP header for other protocols, or
    /// after the Ethernet header and tags for frames that are not IP.
    Payload { offset: usize, size: usize },
    /// Frame length in bytes, without FCS. The payload is cut or padded with
    /// zeros and the IP and UDP lengths follow.
    Len,
    /// Address of the outermost tunnel's IP header; [`VarField::Ip`] writes
    /// the innermost.
    OuterIp(Side),
    /// UDP port of the outermost UDP tunnel (VXLAN, Geneve, GTP-U).
    OuterPort(Side),
    /// GTP-U tunnel endpoint ID (32 bits).
    Teid,
    /// VXLAN or Geneve network identifier (24 bits).
    Vni,
    /// GRE key (32 bits), when the GRE header has one.
    GreKey,
    /// Outermost MPLS label (20 bits).
    Mpls,
}

impl VarField {
    /// Width in bits; for addresses of either IP version, the IPv6 width.
    fn bits(self) -> u32 {
        match self {
            VarField::Mac(_) => 48,
            VarField::Ip(_) | VarField::OuterIp(_) => 128,
            VarField::Port(_) | VarField::OuterPort(_) | VarField::IpId | VarField::Len => 16,
            VarField::Teid | VarField::GreKey => 32,
            VarField::Vni => 24,
            VarField::Mpls => 20,
            VarField::Vlan => 12,
            VarField::Ttl => 8,
            VarField::Payload { size, .. } => size as u32 * 8,
        }
    }
}

/// How a variable moves through its range.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VarOp {
    /// From `min` up by `step`, back to `min` after `max`.
    #[default]
    Inc,
    /// From `max` down by `step`, back to `max` after `min`.
    Dec,
    /// A random value from `min` to `max`.
    Random,
}

/// One variable of a [`FieldEngine`]: a field, a range and how to walk it.
///
/// The text form, used by `--vary` and the `vary` list of profiles, is
/// `FIELD=MIN..MAX` followed by comma separated options:
///
/// ```text
/// ip_src=10.0.0.1..10.0.0.254            # one address per packet, counting up
/// ip_src=10.0.0.0/24,random              # a prefix stands for all its addresses
/// port_src=1024..65535,dec,step=2
/// mac_dst=02:00:00:00:00:01..02:00:00:00:00:10
/// vlan=10..20,every=100                  # next VLAN ID after 100 packets
/// ip_dst+=0..99                          # add 0..99 to the packet's own address
/// payload@0:4=0..0xffffffff,random,seed=7
/// len=64..1518,random
/// ```
///
/// Fields: `mac_src`, `mac_dst`, `ip_src`, `ip_dst`, `port_src`, `port_dst`,
/// `vlan`, `ip_id`, `ttl`, `payload@OFFSET[:SIZE]` (SIZE 1 to 16 bytes,
/// default 1) and `len`. In tunneled packets these change the innermost
/// headers; `outer_ip_src`, `outer_ip_dst`, `outer_port_src` and
/// `outer_port_dst` change the outermost tunnel, and `teid` (GTP-U), `vni`
/// (VXLAN, Geneve), `gre_key` and `mpls` (the outermost label) the tunnel
/// headers themselves. With `+=` the value is added to what the packet
/// holds (wrapping around), and `mac`, `ip` and `port` shift both sides.
///
/// Options: `inc` (the default), `dec`, `random`, `step=N` (default 1),
/// `every=N` (keep each value for N packets, default 1) and `seed=N` (repeat
/// the same random values on every run).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldVar {
    pub field: VarField,
    /// Add the value to the field instead of setting it.
    pub add: bool,
    pub min: u128,
    pub max: u128,
    pub op: VarOp,
    pub step: u128,
    pub every: u64,
    pub seed: Option<u64>,
    /// For `ip_src`/`ip_dst` that set addresses: true for IPv4. Packets of the
    /// other IP version are left alone.
    pub ipv4: bool,
}

impl FieldVar {
    /// A variable that counts up through `min..=max` one packet at a time.
    pub fn new(field: VarField, min: u128, max: u128) -> Result<Self> {
        let v = Self {
            field,
            add: false,
            min,
            max,
            op: VarOp::Inc,
            step: 1,
            every: 1,
            seed: None,
            ipv4: false,
        };
        v.validate()?;
        Ok(v)
    }

    /// Checks the range and options against the field.
    pub fn validate(&self) -> Result<()> {
        let bad = |m: String| Err(Error::InvalidSpec(m));
        if let VarField::Payload { size, .. } = self.field {
            if !(1..=16).contains(&size) {
                return bad(format!("payload size {size} must be 1 to 16 bytes"));
            }
        }
        let bits = match self.field {
            VarField::Ip(_) | VarField::OuterIp(_) if !self.add && self.ipv4 => 32,
            f => f.bits(),
        };
        let limit = u128::MAX >> (128 - bits);
        if self.min > self.max {
            return bad("the range runs backwards; write it as MIN..MAX".into());
        }
        if self.max > limit {
            return bad(format!("{} is larger than the field allows", self.max));
        }
        if self.field == VarField::Len {
            if self.add {
                return bad("len takes a range of lengths, not +=".into());
            }
            if self.min < net::ETH_HEADER as u128 {
                return bad(format!(
                    "len {} is shorter than an Ethernet header",
                    self.min
                ));
            }
        }
        if !self.add
            && matches!(
                self.field,
                VarField::Mac(Side::Both)
                    | VarField::Ip(Side::Both)
                    | VarField::Port(Side::Both)
                    | VarField::OuterIp(Side::Both)
                    | VarField::OuterPort(Side::Both)
            )
        {
            return bad("setting both sides to the same value makes no sense; use _src or _dst, or += to shift both".into());
        }
        if self.step == 0 || self.every == 0 {
            return bad("step and every must be at least 1".into());
        }
        if self.op == VarOp::Random && self.step != 1 {
            return bad("step does not apply to random".into());
        }
        Ok(())
    }

    /// Writes `value` into the field of `data`. Packets without the field are left alone.
    fn write(&self, data: &mut Vec<u8>, value: u128) {
        match self.field {
            VarField::Mac(side) => {
                if data.len() < net::ETH_HEADER {
                    return;
                }
                for (wanted, at) in [(side_dst(side), 0), (side_src(side), 6)] {
                    if wanted {
                        let v = self.value_for(&data[at..at + 6], value);
                        data[at..at + 6].copy_from_slice(&v);
                    }
                }
            }
            VarField::Ip(side) | VarField::OuterIp(side) => {
                let Some(layers) = net::parse(data) else {
                    return;
                };
                let ip = match self.field {
                    VarField::Ip(_) => layers.ip.as_ref(),
                    _ => layers.tunnels.first().map(|t| &t.ip),
                };
                let Some(ip) = ip else { return };
                let width = ip.src.len();
                if !self.add && self.ipv4 != (width == 4) {
                    return;
                }
                let sums = layers.sums(data);
                for (wanted, range) in [
                    (side_src(side), ip.src.clone()),
                    (side_dst(side), ip.dst.clone()),
                ] {
                    if wanted {
                        let v = self.value_for(&data[range.clone()], value);
                        net::write_with(data, range, &v, &sums);
                    }
                }
            }
            VarField::Port(side) | VarField::OuterPort(side) => {
                let Some(layers) = net::parse(data) else {
                    return;
                };
                let at = match self.field {
                    VarField::Port(_) => layers.ip.as_ref().and_then(|ip| ip.ports(data)),
                    _ => layers.tunnels.first().and_then(|t| t.udp),
                };
                let Some(at) = at else { return };
                let sums = layers.sums(data);
                for (wanted, off) in [(side_src(side), at), (side_dst(side), at + 2)] {
                    if wanted {
                        let v = self.value_for(&data[off..off + 2], value);
                        net::write_with(data, off..off + 2, &v, &sums);
                    }
                }
            }
            VarField::Teid | VarField::Vni | VarField::GreKey => {
                let Some(layers) = net::parse(data) else {
                    return;
                };
                let t = layers.tunnels.iter().find(|t| match self.field {
                    VarField::Teid => t.gtp_len.is_some(),
                    VarField::Vni => t.udp.is_some() && t.gtp_len.is_none(),
                    _ => t.gre.is_some(),
                });
                let Some(range) = t.and_then(|t| t.key.clone()) else {
                    return;
                };
                let v = self.value_for(&data[range.clone()], value);
                layers.write(data, range, &v);
            }
            VarField::Mpls => {
                let Some(layers) = net::parse(data) else {
                    return;
                };
                let Some(&at) = layers.mpls.first() else {
                    return;
                };
                let entry = u32::from_be_bytes(data[at..at + 4].try_into().expect("4 bytes"));
                let label = u128::from(entry >> 12);
                let label = if self.add {
                    label.wrapping_add(value)
                } else {
                    value
                } as u32
                    & 0xf_ffff;
                let v = ((label << 12) | (entry & 0xfff)).to_be_bytes();
                layers.write(data, at..at + 4, &v);
            }
            VarField::Vlan => {
                if !net::be16(data, 12).is_some_and(net::is_vlan_tpid) {
                    return;
                }
                let Some(tci) = net::be16(data, 14) else {
                    return;
                };
                let id = u128::from(tci & 0x0fff);
                let id = if self.add {
                    id.wrapping_add(value)
                } else {
                    value
                } as u16
                    & 0x0fff;
                net::put16(data, 14, (tci & 0xf000) | id);
            }
            VarField::IpId => {
                let Some(layers) = net::parse(data) else {
                    return;
                };
                let Some(ip) = &layers.ip else { return };
                if ip.version != 4 {
                    return;
                }
                let at = ip.start + 4;
                let v = self.value_for(&data[at..at + 2], value);
                layers.write(data, at..at + 2, &v);
            }
            VarField::Ttl => {
                let Some(layers) = net::parse(data) else {
                    return;
                };
                let Some(ip) = &layers.ip else { return };
                let at = if ip.version == 4 {
                    ip.start + 8
                } else {
                    ip.start + 7
                };
                let v = self.value_for(&data[at..at + 1], value);
                layers.write(data, at..at + 1, &v);
            }
            VarField::Payload { offset, size } => {
                let (start, end, layers) = payload_start(data);
                let Some(at) = start.checked_add(offset) else {
                    return;
                };
                if at.saturating_add(size) > data.len() {
                    return;
                }
                let v = self.value_for(&data[at..at + size], value);
                match layers {
                    // Ethernet padding after the datagram is not covered by any checksum.
                    Some(layers) if at + size <= end => layers.write(data, at..at + size, &v),
                    _ => data[at..at + size].copy_from_slice(&v),
                }
            }
            VarField::Len => set_len(data, value as usize),
        }
    }

    /// The bytes to write over `old`: `value`, or `old + value` for `+=`.
    fn value_for(&self, old: &[u8], value: u128) -> Vec<u8> {
        let n = old.len();
        let v = if self.add {
            let mut buf = [0u8; 16];
            buf[16 - n..].copy_from_slice(old);
            u128::from_be_bytes(buf).wrapping_add(value)
        } else {
            value
        };
        v.to_be_bytes()[16 - n..].to_vec()
    }

    fn format_value(&self, v: u128) -> String {
        match self.field {
            VarField::Mac(_) if !self.add => {
                let b = v.to_be_bytes();
                let mut m = [0u8; 6];
                m.copy_from_slice(&b[10..]);
                MacAddr(m).to_string()
            }
            VarField::Ip(_) | VarField::OuterIp(_) if !self.add && self.ipv4 => {
                Ipv4Addr::from(v as u32).to_string()
            }
            VarField::Ip(_) | VarField::OuterIp(_) if !self.add => Ipv6Addr::from(v).to_string(),
            _ => v.to_string(),
        }
    }
}

fn side_src(s: Side) -> bool {
    matches!(s, Side::Src | Side::Both)
}

fn side_dst(s: Side) -> bool {
    matches!(s, Side::Dst | Side::Both)
}

/// Length of the TCP, UDP or ICMP header at `at`, when the packet holds it.
fn l4_header_len(data: &[u8], proto: u8, at: usize) -> Option<usize> {
    let len = match proto {
        IPPROTO_TCP => usize::from(*data.get(at + 12)? >> 4) * 4,
        IPPROTO_UDP | IPPROTO_ICMP | IPPROTO_ICMPV6 => 8,
        _ => 0,
    };
    (at + len <= data.len()).then_some(len)
}

/// Where the payload starts, where the IP datagram ends, and the layers
/// whose checksums cover the payload.
fn payload_start(data: &[u8]) -> (usize, usize, Option<net::Layers>) {
    let len = data.len();
    let Some((l3, _)) = net::l3_offset(data) else {
        return (net::ETH_HEADER, len, None);
    };
    let Some(layers) = net::parse(data) else {
        return (l3, len, None);
    };
    let Some(ip) = layers.ip.clone() else {
        return (l3, len, None);
    };
    let end = ip.end.unwrap_or(len);
    let Some((proto, at)) = ip.l4 else {
        // A later fragment: its payload starts right after the IP header.
        return (ip.start + ip.header_len, end, Some(layers));
    };
    let Some(hdr) = l4_header_len(data, proto, at) else {
        // The capture is cut inside the transport header: nothing to write.
        return (len, len, None);
    };
    (at + hdr, end, Some(layers))
}

/// Cuts or pads the frame to `len` bytes and makes the IP and UDP lengths and
/// all checksums match, of the innermost datagram and of the tunnels around
/// it. IP fragments only change length if they are not IP.
pub(crate) fn set_len(data: &mut Vec<u8>, len: usize) {
    let Some(layers) = net::parse(data) else {
        data.resize(len.max(net::ETH_HEADER), 0);
        return;
    };
    let Some(ip) = layers.ip.clone() else {
        if layers.tunnels.is_empty() {
            data.resize(len.max(net::ETH_HEADER), 0);
        }
        return;
    };
    if ip.fragmented {
        return;
    }
    // Never cut into the headers.
    let mut min = ip.start + ip.header_len;
    let l4 = ip
        .l4
        .and_then(|(proto, at)| Some((proto, at, l4_header_len(data, proto, at)?)));
    if let Some((_, at, hdr)) = l4 {
        min = at + hdr;
    }
    let len = len.max(min);
    data.resize(len, 0);
    let ip_len = len - ip.start;
    if ip.version == 4 {
        net::put16(data, ip.start + 2, ip_len.min(0xffff) as u16);
    } else {
        net::put16(
            data,
            ip.start + 4,
            ip_len.saturating_sub(40).min(0xffff) as u16,
        );
    }
    if let Some((IPPROTO_UDP, at, _)) = l4 {
        net::put16(data, at + 4, (len - at).min(0xffff) as u16);
    }
    net::fix_tunnel_lengths(data, &layers, len);
    // The tunnel lengths moved the datagram ends: parse again.
    let Some(layers) = net::parse(data) else {
        return;
    };
    if let Some(ip) = &layers.ip {
        net::fix_ip(data, ip, false);
    }
    // ICMPv4 has no pseudo header, so fix_checksums leaves it; recompute it here.
    if let Some((IPPROTO_ICMP, at, _)) = l4 {
        if ip.version == 4 {
            net::put16(data, at + 2, 0);
            let sum = !net::fold(net::sum_words(&data[at..], 0));
            net::put16(data, at + 2, sum);
        }
    }
    net::fix_tunnels(data, &layers);
}

impl FromStr for FieldVar {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        let err = |msg: &str| Error::InvalidSpec(format!("vary '{s}': {msg}"));
        let mut parts = s.split(',').map(str::trim);
        let head = parts.next().unwrap_or_default();
        let (name, add, values) = match head.split_once("+=") {
            Some((n, v)) => (n.trim(), true, v.trim()),
            None => match head.split_once('=') {
                Some((n, v)) => (n.trim(), false, v.trim()),
                None => return Err(err("expected FIELD=MIN..MAX")),
            },
        };
        let side = |n: &str| match n.rsplit_once('_').map(|(_, s)| s) {
            Some("src") => Side::Src,
            Some("dst") => Side::Dst,
            _ => Side::Both,
        };
        let field = match name {
            "mac" | "mac_src" | "mac_dst" => VarField::Mac(side(name)),
            "ip" | "ip_src" | "ip_dst" => VarField::Ip(side(name)),
            "port" | "port_src" | "port_dst" => VarField::Port(side(name)),
            "vlan" => VarField::Vlan,
            "ip_id" => VarField::IpId,
            "ttl" => VarField::Ttl,
            "len" => VarField::Len,
            "outer_ip" | "outer_ip_src" | "outer_ip_dst" => VarField::OuterIp(side(name)),
            "outer_port" | "outer_port_src" | "outer_port_dst" => VarField::OuterPort(side(name)),
            "teid" => VarField::Teid,
            "vni" => VarField::Vni,
            "gre_key" => VarField::GreKey,
            "mpls" => VarField::Mpls,
            p if p.starts_with("payload@") => {
                let rest = &p["payload@".len()..];
                let (off, size) = match rest.split_once(':') {
                    Some((o, z)) => (o, Some(z)),
                    None => (rest, None),
                };
                let offset = parse_num(off)
                    .and_then(|v| usize::try_from(v).ok())
                    .ok_or_else(|| err(&format!("invalid payload offset '{off}'")))?;
                let size = match size {
                    Some(z) => parse_num(z)
                        .and_then(|v| usize::try_from(v).ok())
                        .ok_or_else(|| err(&format!("invalid payload size '{z}'")))?,
                    None => 1,
                };
                VarField::Payload { offset, size }
            }
            _ => {
                return Err(err(
                    "unknown field (try mac_src, mac_dst, ip_src, ip_dst, port_src, port_dst, vlan, ip_id, ttl, payload@OFFSET[:SIZE], len, outer_ip_src, outer_ip_dst, outer_port_src, outer_port_dst, teid, vni, gre_key, mpls)",
                ))
            }
        };
        if values.is_empty() {
            return Err(err("needs a value or a range MIN..MAX"));
        }

        let mut ipv4 = false;
        let (min, max) = match field {
            VarField::Ip(_) | VarField::OuterIp(_) if !add => {
                let (min, max, v4) = parse_ip_range(values).map_err(|m| err(&m))?;
                ipv4 = v4;
                (min, max)
            }
            VarField::Mac(_) if !add => {
                let mac = |t: &str| {
                    t.trim()
                        .parse::<MacAddr>()
                        .map(|m| {
                            let mut b = [0u8; 16];
                            b[10..].copy_from_slice(&m.0);
                            u128::from_be_bytes(b)
                        })
                        .map_err(|_| err(&format!("invalid MAC address '{}'", t.trim())))
                };
                match values.split_once("..") {
                    Some((a, b)) => (mac(a)?, mac(b)?),
                    None => {
                        let m = mac(values)?;
                        (m, m)
                    }
                }
            }
            _ => {
                let num = |t: &str| {
                    parse_num(t.trim())
                        .ok_or_else(|| err(&format!("invalid number '{}'", t.trim())))
                };
                match values.split_once("..") {
                    Some((a, b)) => (num(a)?, num(b)?),
                    None => {
                        let v = num(values)?;
                        (v, v)
                    }
                }
            }
        };

        let mut var = FieldVar {
            field,
            add,
            min,
            max,
            op: VarOp::Inc,
            step: 1,
            every: 1,
            seed: None,
            ipv4,
        };
        for opt in parts {
            let (key, val) = match opt.split_once('=') {
                Some((k, v)) => (k.trim(), Some(v.trim())),
                None => (opt, None),
            };
            let num = || {
                val.and_then(parse_num)
                    .ok_or_else(|| err(&format!("option '{opt}' needs a number")))
            };
            match (key, val) {
                ("inc", None) => var.op = VarOp::Inc,
                ("dec", None) => var.op = VarOp::Dec,
                ("random", None) => var.op = VarOp::Random,
                ("step", Some(_)) => var.step = num()?,
                ("every", Some(_)) => {
                    var.every = u64::try_from(num()?).map_err(|_| err("every is too large"))?
                }
                ("seed", Some(_)) => {
                    var.seed = Some(u64::try_from(num()?).map_err(|_| err("seed is too large"))?)
                }
                _ => {
                    return Err(err(&format!(
                        "unknown option '{opt}' (try inc, dec, random, step=N, every=N, seed=N)"
                    )))
                }
            }
        }
        var.validate().map_err(|e| match e {
            Error::InvalidSpec(m) => err(&m),
            other => other,
        })?;
        Ok(var)
    }
}

impl fmt::Display for FieldVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn side(s: Side) -> &'static str {
            match s {
                Side::Src => "_src",
                Side::Dst => "_dst",
                Side::Both => "",
            }
        }
        match self.field {
            VarField::Mac(s) => write!(f, "mac{}", side(s))?,
            VarField::Ip(s) => write!(f, "ip{}", side(s))?,
            VarField::Port(s) => write!(f, "port{}", side(s))?,
            VarField::Vlan => f.write_str("vlan")?,
            VarField::IpId => f.write_str("ip_id")?,
            VarField::Ttl => f.write_str("ttl")?,
            VarField::Len => f.write_str("len")?,
            VarField::OuterIp(s) => write!(f, "outer_ip{}", side(s))?,
            VarField::OuterPort(s) => write!(f, "outer_port{}", side(s))?,
            VarField::Teid => f.write_str("teid")?,
            VarField::Vni => f.write_str("vni")?,
            VarField::GreKey => f.write_str("gre_key")?,
            VarField::Mpls => f.write_str("mpls")?,
            VarField::Payload { offset, size: 1 } => write!(f, "payload@{offset}")?,
            VarField::Payload { offset, size } => write!(f, "payload@{offset}:{size}")?,
        }
        f.write_str(if self.add { "+=" } else { "=" })?;
        f.write_str(&self.format_value(self.min))?;
        if self.max != self.min {
            write!(f, "..{}", self.format_value(self.max))?;
        }
        match self.op {
            VarOp::Inc => {}
            VarOp::Dec => f.write_str(",dec")?,
            VarOp::Random => f.write_str(",random")?,
        }
        if self.step != 1 {
            write!(f, ",step={}", self.step)?;
        }
        if self.every != 1 {
            write!(f, ",every={}", self.every)?;
        }
        if let Some(seed) = self.seed {
            write!(f, ",seed={seed}")?;
        }
        Ok(())
    }
}

/// Parses a decimal or `0x` hex number.
pub(crate) fn parse_num(s: &str) -> Option<u128> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u128::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// `A..B`, `NET/LEN` or a single address: the range as numbers, and whether it is IPv4.
fn parse_ip_range(s: &str) -> std::result::Result<(u128, u128, bool), String> {
    let addr = |t: &str| -> std::result::Result<IpAddr, String> {
        t.trim()
            .parse()
            .map_err(|_| format!("invalid address '{}'", t.trim()))
    };
    let num = |a: IpAddr| match a {
        IpAddr::V4(a) => u128::from(u32::from(a)),
        IpAddr::V6(a) => u128::from(a),
    };
    if let Some((a, b)) = s.split_once("..") {
        let (a, b) = (addr(a)?, addr(b)?);
        if a.is_ipv4() != b.is_ipv4() {
            return Err("the range mixes IPv4 and IPv6".into());
        }
        return Ok((num(a), num(b), a.is_ipv4()));
    }
    if let Some((a, len)) = s.split_once('/') {
        let a = addr(a)?;
        let bits = if a.is_ipv4() { 32 } else { 128 };
        let len: u32 = len
            .trim()
            .parse()
            .ok()
            .filter(|&l| l <= bits)
            .ok_or_else(|| format!("invalid prefix length '{}'", len.trim()))?;
        let host = bits - len;
        let host_mask = if host == 128 {
            u128::MAX
        } else {
            (1u128 << host) - 1
        };
        let net = num(a) & !host_mask;
        return Ok((net, net | host_mask, a.is_ipv4()));
    }
    let a = addr(s)?;
    Ok((num(a), num(a), a.is_ipv4()))
}

/// Gives every engine made without a seed different random values.
static SEED_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) fn fresh_seed() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let n = SEED_COUNTER.fetch_add(1, Ordering::Relaxed);
    (now.as_nanos() as u64) ^ n.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

/// splitmix64: small, fast and good enough for traffic.
pub(crate) fn next_random(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

struct VarState {
    var: FieldVar,
    current: u128,
    held: u64,
    rng: u64,
}

impl VarState {
    fn new(var: FieldVar) -> Self {
        let mut s = Self {
            rng: var.seed.unwrap_or_else(fresh_seed),
            current: 0,
            held: 0,
            var,
        };
        s.current = match s.var.op {
            VarOp::Inc => s.var.min,
            VarOp::Dec => s.var.max,
            VarOp::Random => s.random(),
        };
        s
    }

    fn random(&mut self) -> u128 {
        let r =
            (u128::from(next_random(&mut self.rng)) << 64) | u128::from(next_random(&mut self.rng));
        let span = self.var.max - self.var.min;
        if span == u128::MAX {
            r
        } else {
            self.var.min + r % (span + 1)
        }
    }

    /// The value for this packet; moves on after `every` packets.
    fn next(&mut self) -> u128 {
        let value = self.current;
        self.held += 1;
        if self.held >= self.var.every {
            self.held = 0;
            let (min, max, step) = (self.var.min, self.var.max, self.var.step);
            self.current = match self.var.op {
                VarOp::Inc if max - value >= step => value + step,
                VarOp::Inc => min,
                VarOp::Dec if value - min >= step => value - step,
                VarOp::Dec => max,
                VarOp::Random => self.random(),
            };
        }
        value
    }
}

/// A [`Transform`] that writes the next value of each of its variables into
/// every packet, in order, like TRex's field engine.
///
/// Every variable moves on once per packet that passes, whether or not the
/// packet has its field. Address, port, ID, TTL and payload changes update the
/// checksums incrementally, so a checksum that was wrong in the capture stays
/// exactly as wrong; a length change recomputes them.
///
/// ```
/// use ferotrx_core::{FieldEngine, Packet, Transform};
/// use std::time::Duration;
///
/// let mut engine = FieldEngine::parse(["vlan=10..12"]).unwrap();
/// let tagged = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x81, 0, 0, 1, 0x88, 0xb5];
/// let ids: Vec<u8> = (0..4)
///     .map(|_| {
///         let mut p = Packet::new(Duration::ZERO, tagged.clone());
///         engine.apply(&mut p);
///         p.data[15]
///     })
///     .collect();
/// assert_eq!(ids, [10, 11, 12, 10]);
/// ```
pub struct FieldEngine {
    vars: Vec<VarState>,
}

impl FieldEngine {
    pub fn new(vars: impl IntoIterator<Item = FieldVar>) -> Self {
        Self {
            vars: vars.into_iter().map(VarState::new).collect(),
        }
    }

    /// An engine from variables in text form (see [`FieldVar`]).
    pub fn parse<S: AsRef<str>>(specs: impl IntoIterator<Item = S>) -> Result<Self> {
        let vars = specs
            .into_iter()
            .map(|s| s.as_ref().parse())
            .collect::<Result<Vec<FieldVar>>>()?;
        Ok(Self::new(vars))
    }

    pub fn vars(&self) -> impl Iterator<Item = &FieldVar> {
        self.vars.iter().map(|v| &v.var)
    }

    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }
}

impl fmt::Debug for FieldEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.vars()).finish()
    }
}

impl Transform for FieldEngine {
    fn apply(&mut self, packet: &mut Packet) {
        for v in &mut self.vars {
            let value = v.next();
            v.var.write(&mut packet.data, value);
        }
    }

    fn skip(&mut self, n: u64) {
        for v in &mut self.vars {
            for _ in 0..n {
                v.next();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::tests::{checksums_ok, tcp6, udp4};
    use std::time::Duration;

    /// Runs `n` copies of `data` through an engine made from `specs`.
    fn run(specs: &[&str], data: Vec<u8>, n: usize) -> Vec<Vec<u8>> {
        let mut e = FieldEngine::parse(specs).unwrap();
        (0..n)
            .map(|_| {
                let mut p = Packet::new(Duration::ZERO, data.clone());
                e.apply(&mut p);
                p.data
            })
            .collect()
    }

    #[test]
    fn ip_inc_wraps_and_keeps_checksums() {
        let out = run(&["ip_src=10.0.0.1..10.0.0.3"], udp4(), 4);
        let srcs: Vec<u8> = out.iter().map(|p| p[29]).collect();
        assert_eq!(srcs, [1, 2, 3, 1]);
        assert!(out.iter().all(|p| checksums_ok(p)));
        assert!(out.iter().all(|p| p[30..34] == [10, 0, 0, 2]));
    }

    #[test]
    fn dec_and_step() {
        let out = run(&["port_dst=100..110,dec,step=4"], udp4(), 4);
        let ports: Vec<u16> = out
            .iter()
            .map(|p| u16::from_be_bytes([p[36], p[37]]))
            .collect();
        assert_eq!(ports, [110, 106, 102, 110]);
        assert!(out.iter().all(|p| checksums_ok(p)));
    }

    #[test]
    fn every_holds_values() {
        let out = run(&["port_src=1..2,every=3"], udp4(), 7);
        let ports: Vec<u8> = out.iter().map(|p| p[35]).collect();
        assert_eq!(ports, [1, 1, 1, 2, 2, 2, 1]);
    }

    #[test]
    fn random_stays_in_range_and_repeats_with_a_seed() {
        let a = run(&["ip_dst=10.1.0.0/16,random,seed=42"], udp4(), 200);
        let b = run(&["ip_dst=10.1.0.0/16,random,seed=42"], udp4(), 200);
        assert_eq!(a, b);
        assert!(a.iter().all(|p| p[30..32] == [10, 1] && checksums_ok(p)));
        let distinct: std::collections::HashSet<_> = a.iter().map(|p| p[32..34].to_vec()).collect();
        assert!(distinct.len() > 150);
    }

    #[test]
    fn add_shifts_both_sides() {
        let out = run(&["ip+=0..2"], udp4(), 3);
        assert_eq!(out[2][26..34], [10, 0, 0, 3, 10, 0, 0, 4]);
        assert!(out.iter().all(|p| checksums_ok(p)));
        // IPv6, with a carry across bytes.
        let out = run(&["ip_src+=0xffff"], tcp6(), 1);
        assert_eq!(out[0][34..38], [0, 1, 0, 0]);
        assert!(checksums_ok(&out[0]));
    }

    #[test]
    fn ip_family_must_match() {
        assert_eq!(run(&["ip_src=10.0.0.9..10.0.0.10"], tcp6(), 1)[0], tcp6());
        let out = run(&["ip_dst=fd00::1..fd00::5"], tcp6(), 2);
        assert_eq!(out[1][53], 2);
        assert!(checksums_ok(&out[1]));
    }

    #[test]
    fn mac_and_vlan() {
        let out = run(&["mac_dst=02:00:00:00:00:fe..02:00:00:00:01:01"], udp4(), 3);
        assert_eq!(out[2][..6], [2, 0, 0, 0, 1, 0]);
        let mut tagged = udp4();
        tagged.splice(12..12, [0x81, 0x00, 0xa0, 0x05]);
        let out = run(&["vlan=4094..4095", "vlan+=1"], tagged, 2);
        // Set to 4094, then +1; the second packet wraps to 0, then +1.
        assert_eq!(out[0][14..16], [0xaf, 0xff]);
        assert_eq!(out[1][14..16], [0xa0, 0x00]);
        // Untagged frames are left alone.
        assert_eq!(run(&["vlan=5"], udp4(), 1)[0], udp4());
    }

    #[test]
    fn ip_id_and_ttl() {
        let out = run(&["ip_id=7..8", "ttl=1..2"], udp4(), 2);
        assert_eq!(out[1][18..20], [0, 8]);
        assert_eq!(out[1][22], 2);
        assert!(out.iter().all(|p| checksums_ok(p)));
        let out = run(&["ttl=9"], tcp6(), 1);
        assert_eq!(out[0][21], 9);
        assert!(checksums_ok(&out[0]));
    }

    #[test]
    fn payload_bytes_at_odd_offsets() {
        let out = run(&["payload@1:2=0x1234..0x1235"], udp4(), 2);
        assert_eq!(out[1][42..46], [b'a', 0x12, 0x35, b'd']);
        assert!(out.iter().all(|p| checksums_ok(p)));
        // Past the end of the packet: untouched.
        assert_eq!(run(&["payload@3:2=1"], udp4(), 1)[0], udp4());
        // TCP payload starts after the options-aware header.
        let mut p = tcp6();
        p.extend([0u8; 6]);
        p[19] = 26; // IPv6 payload length
        crate::net::fix_checksums(&mut p);
        let out = run(&["payload@5=0xee"], p, 1);
        assert_eq!(out[0][74 + 5], 0xee);
        assert!(checksums_ok(&out[0]));
    }

    #[cfg(feature = "build")]
    #[test]
    fn icmp_payload_keeps_icmp_checksum() {
        let spec: ferotrx_packet::PacketSpec = "eth/ipv4/icmp/raw(len=8)".parse().unwrap();
        let frame = spec.build().unwrap();
        let out = run(&["payload@3:4=0xdeadbeef"], frame, 1);
        let d = ferotrx_packet::decode(1, &out[0]);
        assert!(d.problems.is_empty(), "{:?}", d.problems);
        assert_eq!(out[0][42 + 3..42 + 7], [0xde, 0xad, 0xbe, 0xef]);
    }

    #[cfg(feature = "build")]
    #[test]
    fn len_pads_cuts_and_fixes_lengths() {
        let out = run(&["len=100..101", "len=20"], udp4(), 1);
        // The second variable asks for less than the headers: cut at the UDP header.
        assert_eq!(out[0].len(), 42);
        let out = run(&["len=100..101"], udp4(), 2);
        for (p, len) in out.iter().zip([100usize, 101]) {
            assert_eq!(p.len(), len);
            let d = ferotrx_packet::decode(1, p);
            assert!(d.problems.is_empty(), "{:?}", d.problems);
            assert_eq!(u16::from_be_bytes([p[16], p[17]]) as usize, len - 14);
            assert_eq!(u16::from_be_bytes([p[38], p[39]]) as usize, len - 34);
        }
        let out = run(&["len=60"], tcp6(), 1);
        assert_eq!(out[0].len(), 74);
        let out = run(&["len=200"], tcp6(), 1);
        assert!(ferotrx_packet::decode(1, &out[0]).problems.is_empty());
        let spec: ferotrx_packet::PacketSpec = "eth/ipv4/icmp".parse().unwrap();
        let out = run(&["len=80"], spec.build().unwrap(), 1);
        assert!(ferotrx_packet::decode(1, &out[0]).problems.is_empty());
    }

    #[test]
    fn truncated_packets_do_not_panic() {
        let specs = [
            "mac_src+=1..5",
            "ip_src=10.0.0.1..10.0.0.9",
            "ip_dst+=1",
            "port_src=1..9",
            "vlan=1..9",
            "ip_id=1..9",
            "ttl=1..9",
            "payload@0:4=1..9",
            "len=14..80,random",
        ];
        let mut tagged = udp4();
        tagged.splice(12..12, [0x81, 0x00, 0x00, 0x05]);
        for base in [udp4(), tcp6(), tagged] {
            for n in 0..base.len() {
                run(&specs, base[..n].to_vec(), 2);
            }
        }
    }

    #[test]
    fn text_round_trips() {
        for s in [
            "ip_src=10.0.0.1..10.0.0.254",
            "ip_dst=2001:db8::1..2001:db8::ff,random,seed=3",
            "ip+=0..99,every=10",
            "mac_dst=02:00:00:00:00:01..02:00:00:00:00:10",
            "mac_src+=1",
            "port_src=1024..65535,dec,step=2",
            "vlan=10..20",
            "ip_id=0..65535,random",
            "ttl=1..64",
            "payload@0=0..255",
            "payload@12:4=0..4294967295,random",
            "len=64..1518,random",
        ] {
            let v: FieldVar = s.parse().unwrap();
            assert_eq!(v.to_string(), s);
        }
        let v: FieldVar = "ip_src=10.0.1.0/24".parse().unwrap();
        assert_eq!(v.to_string(), "ip_src=10.0.1.0..10.0.1.255");
        let v: FieldVar = " port_dst = 0x10 .. 0x20 , random ".parse().unwrap();
        assert_eq!(v.to_string(), "port_dst=16..32,random");
    }

    #[test]
    fn rejects_garbage() {
        for s in [
            "",
            "ip_src",
            "nope=1..2",
            "ip_src=10.0.0.9..10.0.0.1",
            "ip_src=10.0.0.1..fd00::1",
            "ip_src=10.0.0.0/33",
            "ip=10.0.0.1..10.0.0.2",
            "port_src=1..70000",
            "vlan=4096",
            "ttl=256",
            "len=10..20",
            "len+=4",
            "payload@0:17=1",
            "payload@x=1",
            "port_src=1..9,random,step=2",
            "port_src=1..9,step=0",
            "port_src=1..9,every=0",
            "port_src=1..9,fast",
            "mac_src=zz..02:00:00:00:00:01",
        ] {
            assert!(s.parse::<FieldVar>().is_err(), "{s} should fail");
        }
    }

    #[cfg(feature = "build")]
    #[test]
    fn tunnels_vary_inside_and_out() {
        let clean = |f: &[u8]| ferotrx_packet::decode(1, f).problems.is_empty();
        for spec in [
            "eth/ipv4(src=10.0.0.1,dst=10.0.0.2)/udp/vxlan(vni=5)/eth/ipv4(src=192.168.1.1,dst=192.168.1.2)/udp(sport=1,dport=2)/raw(len=40)",
            "eth/ipv4/udp/gtpu(teid=9,qfi=1,seq=1)/ipv4(src=192.168.1.1,dst=192.168.1.2)/tcp/raw(len=40)",
            "eth/ipv6/udp/geneve(vni=3)/ipv6(src=fd00::1)/udp/raw(len=40)",
            "eth/ipv4/gre(csum=1,key=4)/ipv4(src=192.168.1.1)/udp/raw(len=40)",
            "eth/mpls(label=9)/mpls(label=10)/ipv4/udp/raw(len=40)",
            "eth/ipv6/ipv4/icmp/raw(len=40)",
        ] {
            let f: Vec<u8> = spec
                .parse::<ferotrx_packet::PacketSpec>()
                .unwrap()
                .build()
                .unwrap();
            for var in [
                "ip_src+=0..300",
                "port_dst=1000..1003",
                "ttl=1..3",
                "ip_id=7..9",
                "payload@3:5=0..0xffffffffff,random,seed=1",
                "len=90..300,random,seed=2",
                "outer_ip_dst+=0..3",
                "outer_port_src=40000..40003",
                "teid=100..103",
                "vni=0xfffff0..0xffffff",
                "gre_key=1..4",
                "mpls=16..19",
            ] {
                for out in run(&[var], f.clone(), 4) {
                    assert!(clean(&out), "{spec} {var}");
                }
            }
        }
        let f: Vec<u8> = "eth/ipv4(dst=10.0.0.2)/udp/gtpu(teid=1)/ipv4/udp/raw(len=4)"
            .parse::<ferotrx_packet::PacketSpec>()
            .unwrap()
            .build()
            .unwrap();
        let out = run(&["teid=7..8", "outer_ip_dst=10.9.9.9"], f, 2);
        let l = net::parse(&out[1]).unwrap();
        let t = &l.tunnels[0];
        assert_eq!(&out[1][t.key.clone().unwrap()], &[0, 0, 0, 8]);
        assert_eq!(&out[1][t.ip.dst.clone()], &[10, 9, 9, 9]);
        let out = run(&["mpls=99"], net::tests::udp4(), 1);
        assert_eq!(out[0], net::tests::udp4());
        for s in [
            "teid=1..0x100000000",
            "vni=0x1000000",
            "mpls=0x100000",
            "outer_ip=10.0.0.1",
        ] {
            assert!(s.parse::<FieldVar>().is_err(), "{s}");
        }
        for s in [
            "outer_ip_src=10.0.0.1..10.0.0.9",
            "teid=1..9,random",
            "mpls+=1",
        ] {
            assert_eq!(s.parse::<FieldVar>().unwrap().to_string(), s);
        }
    }
}
