//! Just enough header parsing to rewrite packets: Ethernet with 802.1Q/802.1ad
//! tags, IPv4, IPv6 (with extension headers), TCP, UDP and ICMPv6 checksums.
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
#[derive(Clone, Debug)]
pub(crate) struct Layers {
    pub ip: Option<IpLayer>,
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
    let mut et = be16(data, 12)?;
    let mut off = ETH_HEADER;
    while is_vlan_tpid(et) {
        et = be16(data, off + 2)?;
        off += 4;
    }
    (off <= data.len()).then_some((off, et))
}

pub(crate) fn parse(data: &[u8]) -> Option<Layers> {
    let (off, et) = l3_offset(data)?;
    let ip = match et {
        ETHERTYPE_IPV4 => parse_ipv4(data, off),
        ETHERTYPE_IPV6 => parse_ipv6(data, off),
        _ => None,
    };
    Some(Layers { ip })
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
    let mut chunks = data.chunks_exact(2);
    for w in &mut chunks {
        sum += u64::from(u16::from_be_bytes([w[0], w[1]]));
    }
    if let [last] = chunks.remainder() {
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

/// Updates a checksum after the 16-bit aligned bytes `old` became `new` (RFC 1624).
///
/// This keeps a checksum that was wrong in the capture exactly as wrong, which is
/// what a faithful replay wants.
pub(crate) fn adjust_checksum(checksum: u16, old: &[u8], new: &[u8]) -> u16 {
    debug_assert_eq!(old.len(), new.len());
    let mut sum = u64::from(!checksum);
    let mut olds = old.chunks_exact(2);
    for (o, n) in (&mut olds).zip(new.chunks_exact(2)) {
        sum += u64::from(!u16::from_be_bytes([o[0], o[1]]));
        sum += u64::from(u16::from_be_bytes([n[0], n[1]]));
    }
    !fold(sum)
}

/// Overwrites `range` with `new` and fixes the checksums at `checksums`.
///
/// A UDP checksum of zero means "no checksum" and stays zero; one that computes
/// to zero is sent as 0xffff.
pub(crate) fn replace(data: &mut [u8], range: Range<usize>, new: &[u8], checksums: &[(u8, usize)]) {
    if data[range.clone()] == *new {
        return;
    }
    for &(proto, at) in checksums {
        let Some(old_sum) = be16(data, at) else {
            continue;
        };
        if proto == IPPROTO_UDP && old_sum == 0 {
            continue;
        }
        let mut sum = adjust_checksum(old_sum, &data[range.clone()], new);
        if proto == IPPROTO_UDP && sum == 0 {
            sum = 0xffff;
        }
        put16(data, at, sum);
    }
    data[range].copy_from_slice(new);
}

/// Recomputes the IPv4 header checksum and the TCP, UDP or ICMPv6 checksum.
/// Fragments and truncated packets keep their transport checksum.
pub(crate) fn fix_checksums(data: &mut [u8]) {
    let Some(Layers { ip: Some(ip) }) = parse(data) else {
        return;
    };
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
        let ip = parse(&p).unwrap().ip.unwrap();
        let sums = [
            (0, ip.header_checksum.unwrap()),
            ip.l4_checksum(&p).unwrap(),
        ];
        replace(&mut p, ip.dst.clone(), &[192, 168, 7, 9], &sums);
        assert!(checksums_ok(&p));

        let mut p = tcp6();
        let ip = parse(&p).unwrap().ip.unwrap();
        let sums = [ip.l4_checksum(&p).unwrap()];
        let new = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbe, 0xef];
        replace(&mut p, ip.src.clone(), &new, &sums);
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
