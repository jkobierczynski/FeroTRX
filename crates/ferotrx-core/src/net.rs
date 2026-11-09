//! Just enough header parsing to rewrite packets: Ethernet with 802.1Q/802.1ad
//! tags, IPv4, IPv6 (with extension headers), TCP, UDP and ICMPv6 checksums,
//! and the tunnels around them: MPLS, IP in IP, GRE, VXLAN, Geneve and GTP-U.
//!
//! [`parse`] finds the innermost IP datagram, which is what address, port and
//! payload rewrites change. The tunnels it passed on the way are listed too,
//! so that a change inside one keeps the outer UDP and GRE checksums right and
//! a change of length reaches every enclosing length field.
//!
//! Every accessor is bounds checked, so truncated or odd packets are left alone
//! instead of causing a panic.

use std::fmt;
use std::ops::Range;
use std::str::FromStr;

use crate::Error;

pub(crate) const ETHERTYPE_IPV4: u16 = 0x0800;
pub(crate) const ETHERTYPE_IPV6: u16 = 0x86dd;
/// 802.1Q VLAN tag.
pub const TPID_VLAN: u16 = 0x8100;
/// 802.1ad service tag (QinQ).
pub const TPID_QINQ: u16 = 0x88a8;

pub(crate) const IPPROTO_TCP: u8 = 6;
pub(crate) const IPPROTO_UDP: u8 = 17;
pub(crate) const IPPROTO_ICMPV6: u8 = 58;
pub(crate) const IPPROTO_IPIP: u8 = 4;
pub(crate) const IPPROTO_IPV6: u8 = 41;
pub(crate) const IPPROTO_GRE: u8 = 47;

/// MPLS unicast and multicast ethertypes.
pub(crate) const ETHERTYPE_MPLS: u16 = 0x8847;
pub(crate) const ETHERTYPE_MPLS_MC: u16 = 0x8848;
/// Transparent Ethernet bridging: GRE and Geneve carrying Ethernet frames.
pub(crate) const ETHERTYPE_TEB: u16 = 0x6558;
pub(crate) const VXLAN_PORT: u16 = 4789;
pub(crate) const GENEVE_PORT: u16 = 6081;
pub(crate) const GTPU_PORT: u16 = 2152;

/// Length of an Ethernet header without tags.
pub(crate) const ETH_HEADER: usize = 14;

pub(crate) fn is_vlan_tpid(t: u16) -> bool {
    matches!(t, TPID_VLAN | TPID_QINQ | 0x9100)
}

pub(crate) fn be16(data: &[u8], at: usize) -> Option<u16> {
    data.get(at..at + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
}

pub(crate) fn put16(data: &mut [u8], at: usize, v: u16) {
    data[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

/// An Ethernet MAC address, written `aa:bb:cc:dd:ee:ff` or `aa-bb-cc-dd-ee-ff`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl FromStr for MacAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let bad = || Error::InvalidSpec(format!("invalid MAC address '{s}'"));
        let mut out = [0u8; 6];
        let mut parts = s.split([':', '-']);
        for byte in &mut out {
            let part = parts.next().ok_or_else(bad)?;
            if part.is_empty() || part.len() > 2 {
                return Err(bad());
            }
            *byte = u8::from_str_radix(part, 16).map_err(|_| bad())?;
        }
        if parts.next().is_some() {
            return Err(bad());
        }
        Ok(MacAddr(out))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

/// Where the interesting headers of an Ethernet frame are.
#[derive(Clone, Debug, Default)]
pub(crate) struct Layers {
    /// The innermost IP datagram.
    pub ip: Option<IpLayer>,
    /// The tunnels around it, outermost first.
    pub tunnels: Vec<Tunnel>,
    /// Offsets of all MPLS label stack entries, outermost first.
    pub mpls: Vec<usize>,
}

/// One tunnel: the delivering IP datagram and the header after it.
#[derive(Clone, Debug)]
pub(crate) struct Tunnel {
    /// The outer IP datagram.
    pub ip: IpLayer,
    /// Offset of the outer UDP header, for VXLAN, Geneve and GTP-U.
    pub udp: Option<usize>,
    /// Offset of the GRE header.
    pub gre: Option<usize>,
    /// Offset of the GRE checksum, when the GRE header has one.
    pub gre_checksum: Option<usize>,
    /// The VNI (VXLAN, Geneve), TEID (GTP-U) or key (GRE).
    pub key: Option<Range<usize>>,
    /// Offset of the GTP-U length field.
    pub gtp_len: Option<usize>,
    /// Offset of the carried packet.
    pub inner: usize,
    /// What the carried packet is, as an ethertype: [`ETHERTYPE_TEB`] for
    /// Ethernet, IPv4, IPv6 or MPLS.
    pub inner_type: u16,
}

impl Layers {
    /// The checksums of the frame, innermost first, with the bytes each covers.
    pub fn sums(&self, data: &[u8]) -> Vec<Sum> {
        let mut out = Vec::new();
        if let Some(ip) = &self.ip {
            ip_sums(ip, data, &mut out);
        }
        for t in self.tunnels.iter().rev() {
            let end = t.ip.end.unwrap_or(data.len());
            if let Some(at) = t.gre_checksum {
                if let Some(gre) = t.gre {
                    out.push(Sum::new(false, at, gre..end, None));
                }
            }
            if let Some(udp) = t.udp {
                out.push(Sum::new(
                    true,
                    udp + 6,
                    udp..end,
                    Some((t.ip.src.clone(), t.ip.dst.clone())),
                ));
            }
            if let Some(at) = t.ip.header_checksum {
                out.push(Sum::new(
                    false,
                    at,
                    t.ip.start..t.ip.start + t.ip.header_len,
                    None,
                ));
            }
        }
        out.retain(|s| s.at + 2 <= data.len());
        out
    }

    /// Overwrites `range` with `new` and keeps every checksum that covers it
    /// right, or exactly as wrong as it was: the innermost IP and transport
    /// checksums, and the GRE and UDP checksums of the tunnels around them.
    pub fn write(&self, data: &mut [u8], range: Range<usize>, new: &[u8]) {
        let sums = self.sums(data);
        write_with(data, range, new, &sums);
    }
}

/// A ones' complement checksum at `at` that covers the bytes of `covers`.
#[derive(Clone, Debug)]
pub(crate) struct Sum {
    /// A UDP checksum: zero means none, and a computed zero is sent as 0xffff.
    udp: bool,
    at: usize,
    covers: [Range<usize>; 3],
}

impl Sum {
    /// A checksum over `covers` and, for a pseudo header, two address ranges.
    fn new(
        udp: bool,
        at: usize,
        covers: Range<usize>,
        pseudo: Option<(Range<usize>, Range<usize>)>,
    ) -> Self {
        let (a, b) = pseudo.unwrap_or((0..0, 0..0));
        Self {
            udp,
            at,
            covers: [covers, a, b],
        }
    }

    fn covers(&self, at: usize) -> bool {
        at != self.at && self.covers.iter().any(|r| r.contains(&at))
    }
}

fn ip_sums(ip: &IpLayer, data: &[u8], out: &mut Vec<Sum>) {
    if let Some(at) = ip.header_checksum {
        out.push(Sum::new(
            false,
            at,
            ip.start..ip.start + ip.header_len,
            None,
        ));
    }
    let end = ip.end.unwrap_or(data.len());
    if let Some((proto, at)) = ip.l4_checksum(data) {
        let (_, l4) = ip.l4.expect("l4_checksum implies l4");
        out.push(Sum::new(
            proto == IPPROTO_UDP,
            at,
            l4..end,
            Some((ip.src.clone(), ip.dst.clone())),
        ));
    } else if let Some((1, l4)) = ip.l4 {
        // ICMPv4 has no pseudo header.
        if ip.version == 4 && l4 + 4 <= data.len() {
            out.push(Sum::new(false, l4 + 2, l4..end, None));
        }
    }
}

/// Overwrites `range` with `new`, then updates each of `sums`, innermost
/// first, by the 16-bit words that changed in what it covers, including the
/// checksums updated before it (RFC 1624). Headers start at even offsets, so
/// words are at even offsets.
pub(crate) fn write_with(data: &mut [u8], range: Range<usize>, new: &[u8], sums: &[Sum]) {
    if data[range.clone()] == *new {
        return;
    }
    let start = range.start & !1;
    let end = (range.end + 1) & !1;
    let mut old_words = vec![0u8; end - start];
    let have = end.min(data.len()) - start;
    old_words[..have].copy_from_slice(&data[start..start + have]);
    let mut new_words = old_words.clone();
    new_words[range.start - start..range.end - start].copy_from_slice(new);
    // (offset, old word, new word)
    let mut changes: Vec<(usize, u16, u16)> = old_words
        .as_chunks::<2>()
        .0
        .iter()
        .zip(new_words.as_chunks::<2>().0)
        .enumerate()
        .filter(|(_, (o, n))| o != n)
        .map(|(i, (o, n))| {
            (
                start + 2 * i,
                u16::from_be_bytes(*o),
                u16::from_be_bytes(*n),
            )
        })
        .collect();
    data[range].copy_from_slice(new);
    for s in sums {
        let Some(old_sum) = be16(data, s.at) else {
            continue;
        };
        if s.udp && old_sum == 0 {
            continue;
        }
        let mut acc = u64::from(!old_sum);
        let mut touched = false;
        for &(at, o, n) in &changes {
            if s.covers(at) {
                acc += u64::from(!o) + u64::from(n);
                touched = true;
            }
        }
        if !touched {
            continue;
        }
        let mut sum = !fold(acc);
        if s.udp && sum == 0 {
            sum = 0xffff;
        }
        put16(data, s.at, sum);
        changes.push((s.at, old_sum, sum));
    }
}

#[derive(Clone, Debug)]
pub(crate) struct IpLayer {
    pub version: u8,
    /// Offset of the IP header.
    pub start: usize,
    pub src: Range<usize>,
    pub dst: Range<usize>,
    /// Offset of the IPv4 header checksum.
    pub header_checksum: Option<usize>,
    /// IPv4 header length.
    pub header_len: usize,
    /// End of the datagram as the IP header states it, when the capture holds all of it.
    pub end: Option<usize>,
    /// True for any fragment, first or not.
    pub fragmented: bool,
    /// Transport protocol and offset, when this packet carries the transport header.
    pub l4: Option<(u8, usize)>,
}

impl IpLayer {
    /// Offset of the transport checksum that covers the IP pseudo header.
    pub fn l4_checksum(&self, data: &[u8]) -> Option<(u8, usize)> {
        let (proto, at) = self.l4?;
        let field = match proto {
            IPPROTO_TCP => at + 16,
            IPPROTO_UDP => at + 6,
            IPPROTO_ICMPV6 if self.version == 6 => at + 2,
            _ => return None,
        };
        (field + 2 <= data.len()).then_some((proto, field))
    }

    /// Offsets of the source and destination ports, for TCP and UDP.
    pub fn ports(&self, data: &[u8]) -> Option<usize> {
        match self.l4? {
            (IPPROTO_TCP | IPPROTO_UDP, at) if at + 4 <= data.len() => Some(at),
            _ => None,
        }
    }
}

/// Offset of the Ethernet payload (after any VLAN tags) and its ethertype.
pub(crate) fn l3_offset(data: &[u8]) -> Option<(usize, u16)> {
    l3_at(data, 0)
}

/// Like [`l3_offset`], for an Ethernet frame that starts at `eth`.
pub(crate) fn l3_at(data: &[u8], eth: usize) -> Option<(usize, u16)> {
    let mut et = be16(data, eth + 12)?;
    let mut off = eth + ETH_HEADER;
    while is_vlan_tpid(et) {
        et = be16(data, off + 2)?;
        off += 4;
    }
    (off <= data.len()).then_some((off, et))
}

/// The ethertype of an IP packet by its version nibble.
fn ip_type(data: &[u8], at: usize) -> Option<u16> {
    match data.get(at)? >> 4 {
        4 => Some(ETHERTYPE_IPV4),
        6 => Some(ETHERTYPE_IPV6),
        _ => None,
    }
}

/// Finds the innermost IP datagram and the tunnels and MPLS labels around it.
pub(crate) fn parse(data: &[u8]) -> Option<Layers> {
    let (mut off, mut et) = l3_offset(data)?;
    let mut layers = Layers::default();
    for _ in 0..8 {
        let ip = match et {
            ETHERTYPE_IPV4 => parse_ipv4(data, off),
            ETHERTYPE_IPV6 => parse_ipv6(data, off),
            ETHERTYPE_MPLS | ETHERTYPE_MPLS_MC => {
                let mut at = off;
                loop {
                    be16(data, at + 2)?;
                    layers.mpls.push(at);
                    let bos = data[at + 2] & 1 != 0;
                    at += 4;
                    if bos || layers.mpls.len() > 16 {
                        break;
                    }
                }
                match data.get(at).map(|b| b >> 4) {
                    // A pseudowire control word, then Ethernet.
                    Some(0) => {
                        let Some((o, e)) = l3_at(data, at + 4) else {
                            break;
                        };
                        (off, et) = (o, e);
                    }
                    _ => {
                        let Some(e) = ip_type(data, at) else {
                            break;
                        };
                        (off, et) = (at, e);
                    }
                }
                continue;
            }
            _ => None,
        };
        let Some(ip) = ip else {
            break;
        };
        let Some(t) = tunnel(data, ip.clone()) else {
            layers.ip = Some(ip);
            break;
        };
        if t.inner_type == ETHERTYPE_TEB {
            let Some((o, e)) = l3_at(data, t.inner) else {
                layers.tunnels.push(t);
                break;
            };
            (off, et) = (o, e);
        } else {
            (off, et) = (t.inner, t.inner_type);
        }
        layers.tunnels.push(t);
    }
    Some(layers)
}

/// The tunnel that `ip` delivers, if it is one this module knows.
fn tunnel(data: &[u8], ip: IpLayer) -> Option<Tunnel> {
    if ip.fragmented {
        return None;
    }
    let (proto, at) = ip.l4?;
    let end = ip.end.unwrap_or(data.len());
    let mut t = Tunnel {
        ip,
        udp: None,
        gre: None,
        gre_checksum: None,
        key: None,
        gtp_len: None,
        inner: at,
        inner_type: 0,
    };
    match proto {
        IPPROTO_IPIP => t.inner_type = ETHERTYPE_IPV4,
        IPPROTO_IPV6 => t.inner_type = ETHERTYPE_IPV6,
        IPPROTO_GRE => {
            let flags = be16(data, at)?;
            // Version 0 only; version 1 is PPTP.
            if flags & 0x0007 != 0 || flags & 0x4000 != 0 {
                return None;
            }
            let mut o = at + 4;
            if flags & 0x8000 != 0 {
                t.gre_checksum = Some(o);
                o += 4;
            }
            if flags & 0x2000 != 0 {
                t.key = Some(o..o + 4);
                o += 4;
            }
            if flags & 0x1000 != 0 {
                o += 4;
            }
            let ty = be16(data, at + 2)?;
            if !matches!(
                ty,
                ETHERTYPE_IPV4 | ETHERTYPE_IPV6 | ETHERTYPE_TEB | ETHERTYPE_MPLS
            ) {
                return None;
            }
            t.gre = Some(at);
            t.inner = o;
            t.inner_type = ty;
        }
        IPPROTO_UDP => {
            let (sport, dport) = (be16(data, at)?, be16(data, at + 2)?);
            let h = at + 8;
            if dport == VXLAN_PORT {
                // The I flag must be set; reserved bits are not checked.
                if data.get(h)? & 0x08 == 0 || h + 8 > end {
                    return None;
                }
                t.key = Some(h + 4..h + 7);
                t.inner = h + 8;
                t.inner_type = ETHERTYPE_TEB;
            } else if dport == GENEVE_PORT {
                let first = *data.get(h)?;
                if first >> 6 != 0 {
                    return None;
                }
                let ty = be16(data, h + 2)?;
                if !matches!(ty, ETHERTYPE_IPV4 | ETHERTYPE_IPV6 | ETHERTYPE_TEB) {
                    return None;
                }
                t.key = Some(h + 4..h + 7);
                t.inner = h + 8 + usize::from(first & 0x3f) * 4;
                t.inner_type = ty;
            } else if dport == GTPU_PORT || sport == GTPU_PORT {
                let flags = *data.get(h)?;
                // Version 1, protocol type GTP, a G-PDU.
                if flags >> 5 != 1 || flags & 0x10 == 0 || *data.get(h + 1)? != 255 {
                    return None;
                }
                t.gtp_len = Some(h + 2);
                t.key = Some(h + 4..h + 8);
                let mut o = h + 8;
                if flags & 0x07 != 0 {
                    let mut next = *data.get(h + 11)?;
                    o = h + 12;
                    while next != 0 {
                        let len = usize::from(*data.get(o)?) * 4;
                        if len == 0 {
                            return None;
                        }
                        next = *data.get(o + len - 1)?;
                        o += len;
                    }
                }
                t.inner = o;
                t.inner_type = ip_type(data, o)?;
            } else {
                return None;
            }
            t.udp = Some(at);
        }
        _ => return None,
    }
    (t.inner <= end).then_some(t)
}

fn parse_ipv4(data: &[u8], off: usize) -> Option<IpLayer> {
    let first = *data.get(off)?;
    let ihl = usize::from(first & 0x0f) * 4;
    if first >> 4 != 4 || ihl < 20 || off + ihl > data.len() {
        return None;
    }
    let total = usize::from(be16(data, off + 2)?);
    let frag = be16(data, off + 6)?;
    let more_fragments = frag & 0x2000 != 0;
    let frag_offset = frag & 0x1fff;
    let proto = data[off + 9];
    let end = off + total;
    Some(IpLayer {
        version: 4,
        start: off,
        src: off + 12..off + 16,
        dst: off + 16..off + 20,
        header_checksum: Some(off + 10),
        header_len: ihl,
        end: (total >= ihl && end <= data.len()).then_some(end),
        fragmented: more_fragments || frag_offset != 0,
        l4: (frag_offset == 0).then_some((proto, off + ihl)),
    })
}

fn parse_ipv6(data: &[u8], off: usize) -> Option<IpLayer> {
    if data.len() < off + 40 || data[off] >> 4 != 6 {
        return None;
    }
    let payload = usize::from(be16(data, off + 4)?);
    let end = off + 40 + payload;
    let mut next = data[off + 6];
    let mut at = off + 40;
    let mut fragmented = false;
    let mut l4 = None;
    for _ in 0..8 {
        match next {
            // Hop-by-hop, routing, destination options.
            0 | 43 | 60 => {
                let len = (usize::from(*data.get(at + 1)?) + 1) * 8;
                next = data[at];
                at += len;
            }
            // Fragment header.
            44 => {
                let frag = be16(data, at + 2)?;
                fragmented = true;
                next = data[at];
                at += 8;
                if frag >> 3 != 0 {
                    break;
                }
            }
            // Authentication header.
            51 => {
                let len = (usize::from(*data.get(at + 1)?) + 2) * 4;
                next = data[at];
                at += len;
            }
            proto => {
                if at <= data.len() {
                    l4 = Some((proto, at));
                }
                break;
            }
        }
    }
    Some(IpLayer {
        version: 6,
        start: off,
        src: off + 8..off + 24,
        dst: off + 24..off + 40,
        header_checksum: None,
        header_len: 40,
        end: (end <= data.len()).then_some(end),
        fragmented,
        l4,
    })
}

/// Adds big endian 16-bit words to a ones' complement sum. An odd last byte is
/// padded with zero.
pub(crate) fn sum_words(data: &[u8], mut sum: u64) -> u64 {
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        sum += u64::from(u16::from_be_bytes(*w));
    }
    if let [last] = rest {
        sum += u64::from(*last) << 8;
    }
    sum
}

pub(crate) fn fold(mut sum: u64) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// Recomputes the IPv4 header checksum and the TCP, UDP or ICMPv6 checksum
/// of the innermost datagram, then the checksums of the tunnels around it.
/// Fragments and truncated packets keep their transport checksum. A tunnel's
/// UDP checksum of zero over IPv4 stays zero: that means it has none.
pub(crate) fn fix_checksums(data: &mut [u8]) {
    let Some(layers) = parse(data) else {
        return;
    };
    if let Some(ip) = &layers.ip {
        fix_ip(data, ip, false);
    }
    fix_tunnels(data, &layers);
}

/// Recomputes the GRE, UDP and IPv4 header checksums of the tunnels in
/// `layers`, innermost first.
pub(crate) fn fix_tunnels(data: &mut [u8], layers: &Layers) {
    for t in layers.tunnels.iter().rev() {
        if let (Some(gre), Some(at), Some(end)) = (t.gre, t.gre_checksum, t.ip.end) {
            put16(data, at, 0);
            let sum = !fold(sum_words(&data[gre..end], 0));
            put16(data, at, sum);
        }
        fix_ip(data, &t.ip, true);
    }
}

pub(crate) fn fix_ip(data: &mut [u8], ip: &IpLayer, keep_zero_udp: bool) {
    if let Some(at) = ip.header_checksum {
        put16(data, at, 0);
        let sum = !fold(sum_words(&data[ip.start..ip.start + ip.header_len], 0));
        put16(data, at, sum);
    }
    let (Some(end), false) = (ip.end, ip.fragmented) else {
        return;
    };
    let Some((proto, field)) = ip.l4_checksum(data) else {
        return;
    };
    let (_, l4) = ip.l4.expect("l4_checksum implies l4");
    if field + 2 > end {
        return;
    }
    if keep_zero_udp && proto == IPPROTO_UDP && ip.version == 4 && be16(data, field) == Some(0) {
        return;
    }
    let len = end - l4;
    put16(data, field, 0);
    let mut sum = sum_words(&data[ip.src.clone()], 0);
    sum = sum_words(&data[ip.dst.clone()], sum);
    sum += u64::from(proto) + len as u64;
    sum = sum_words(&data[l4..end], sum);
    let mut csum = !fold(sum);
    if proto == IPPROTO_UDP && csum == 0 {
        csum = 0xffff;
    }
    put16(data, field, csum);
}

/// Sets the length fields of every tunnel around the innermost datagram so
/// each carries everything up to the end of the frame, or of the datagram
/// it encloses when that ends earlier. Checksums are left as they are.
pub(crate) fn fix_tunnel_lengths(data: &mut [u8], layers: &Layers, end: usize) {
    for t in &layers.tunnels {
        let ip = &t.ip;
        let len = end - ip.start;
        if ip.version == 4 {
            put16(data, ip.start + 2, len.min(0xffff) as u16);
        } else {
            put16(
                data,
                ip.start + 4,
                len.saturating_sub(40).min(0xffff) as u16,
            );
        }
        if let Some(udp) = t.udp {
            put16(data, udp + 4, (end - udp).min(0xffff) as u16);
        }
        if let Some(at) = t.gtp_len {
            put16(data, at, (end - (at + 6)).min(0xffff) as u16);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Ethernet + IPv4 + UDP 10.0.0.1:1000 -> 10.0.0.2:53, 4 byte payload, valid checksums.
    pub fn udp4() -> Vec<u8> {
        let mut p = vec![
            0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x08, 0x00, // eth
            0x45, 0, 0, 32, 0x12, 0x34, 0, 0, 64, 17, 0, 0, // ipv4 to checksum
            10, 0, 0, 1, 10, 0, 0, 2, // addrs
            0x03, 0xe8, 0, 53, 0, 12, 0, 0, // udp
            b'a', b'b', b'c', b'd',
        ];
        fix_checksums(&mut p);
        p
    }

    /// Ethernet + IPv6 + TCP [2001:db8::1]:1234 -> [2001:db8::2]:80, no payload.
    pub fn tcp6() -> Vec<u8> {
        let mut p = vec![
            0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x86, 0xdd, // eth
            0x60, 0, 0, 0, 0, 20, 6, 64, // ipv6
        ];
        p.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        p.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        p.extend([
            0x04, 0xd2, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
        ]);
        fix_checksums(&mut p);
        p
    }

    /// True when the IPv4 header and transport checksums verify.
    pub fn checksums_ok(data: &[u8]) -> bool {
        let mut fixed = data.to_vec();
        fix_checksums(&mut fixed);
        fixed == data
    }

    #[test]
    fn parses_udp4() {
        let p = udp4();
        let ip = parse(&p).unwrap().ip.unwrap();
        assert_eq!(ip.version, 4);
        assert_eq!(&p[ip.src.clone()], &[10, 0, 0, 1]);
        assert_eq!(ip.l4, Some((IPPROTO_UDP, 34)));
        assert_eq!(ip.end, Some(p.len()));
        // Known good IPv4 header checksum for this header.
        let hdr = &p[14..34];
        assert_eq!(fold(sum_words(hdr, 0)), 0xffff);
    }

    #[test]
    fn incremental_matches_full_recompute() {
        let mut p = udp4();
        let l = parse(&p).unwrap();
        let ip = l.ip.clone().unwrap();
        l.write(&mut p, ip.dst.clone(), &[192, 168, 7, 9]);
        assert!(checksums_ok(&p));

        let mut p = tcp6();
        let l = parse(&p).unwrap();
        let ip = l.ip.clone().unwrap();
        let new = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbe, 0xef];
        l.write(&mut p, ip.src.clone(), &new);
        assert!(checksums_ok(&p));
    }

    #[test]
    fn mac_parses_and_prints() {
        let m: MacAddr = "02-AB-cd:00:11:ff".parse().unwrap();
        assert_eq!(m.to_string(), "02:ab:cd:00:11:ff");
        assert!("02:ab:cd:00:11".parse::<MacAddr>().is_err());
        assert!("02:ab:cd:00:11:22:33".parse::<MacAddr>().is_err());
        assert!("zz:ab:cd:00:11:22".parse::<MacAddr>().is_err());
    }

    #[test]
    fn truncated_packets_do_not_panic() {
        let p = udp4();
        for n in 0..p.len() {
            let mut q = p[..n].to_vec();
            let _ = parse(&q);
            fix_checksums(&mut q);
        }
    }
}
