//! Building and parsing the frames the TCP engine sends and receives:
//! Ethernet with an optional 802.1Q tag, ARP, IPv4, IPv6, neighbor
//! discovery, TCP and ICMP and ICMPv6 echo.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::net::{be16, ETHERTYPE_IPV4, ETHERTYPE_IPV6, IPPROTO_ICMPV6, TPID_VLAN};
use crate::MacAddr;

pub(crate) const ETHERTYPE_ARP: u16 = 0x0806;
pub(crate) const BROADCAST: MacAddr = MacAddr([0xff; 6]);

pub(crate) const FIN: u8 = 0x01;
pub(crate) const SYN: u8 = 0x02;
pub(crate) const RST: u8 = 0x04;
pub(crate) const PSH: u8 = 0x08;
pub(crate) const ACK: u8 = 0x10;

/// The link layer part of a received frame.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Link {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub vlan: Option<u16>,
    pub ethertype: u16,
    /// Offset of the payload after the Ethernet header and tag.
    pub payload: usize,
}

pub(crate) fn parse_link(frame: &[u8]) -> Option<Link> {
    let mac = |at: usize| -> Option<MacAddr> {
        let b = frame.get(at..at + 6)?;
        Some(MacAddr([b[0], b[1], b[2], b[3], b[4], b[5]]))
    };
    let dst = mac(0)?;
    let src = mac(6)?;
    let mut ethertype = be16(frame, 12)?;
    let mut payload = 14;
    let mut vlan = None;
    if crate::net::is_vlan_tpid(ethertype) {
        vlan = Some(be16(frame, 14)? & 0x0fff);
        ethertype = be16(frame, 16)?;
        payload = 18;
        // A second tag (QinQ) is not ours.
        if crate::net::is_vlan_tpid(ethertype) {
            return None;
        }
    }
    Some(Link {
        dst,
        src,
        vlan,
        ethertype,
        payload,
    })
}

/// A received ARP packet (Ethernet/IPv4 only).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Arp {
    pub op: u16,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
}

pub(crate) fn parse_arp(p: &[u8]) -> Option<Arp> {
    if p.len() < 28 || be16(p, 0)? != 1 || be16(p, 2)? != ETHERTYPE_IPV4 || p[4] != 6 || p[5] != 4 {
        return None;
    }
    let ip = |at: usize| Ipv4Addr::new(p[at], p[at + 1], p[at + 2], p[at + 3]);
    Some(Arp {
        op: be16(p, 6)?,
        sender_mac: MacAddr([p[8], p[9], p[10], p[11], p[12], p[13]]),
        sender_ip: ip(14),
        target_ip: ip(24),
    })
}

/// A received IPv4 or IPv6 datagram.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ip<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// The transport protocol (for IPv6, after any extension headers).
    pub proto: u8,
    /// TTL or hop limit.
    pub hop_limit: u8,
    pub payload: &'a [u8],
}

/// Parses an IPv4 or IPv6 datagram, by its version. Fragments are not
/// reassembled and come back as `None`.
pub(crate) fn parse_ip(p: &[u8], verify: bool) -> Option<Ip<'_>> {
    match p.first()? >> 4 {
        4 => parse_ipv4(p, verify),
        6 => parse_ipv6(p),
        _ => None,
    }
}

pub(crate) fn parse_ipv4(p: &[u8], verify: bool) -> Option<Ip<'_>> {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(p[0] & 0x0f) * 4;
    let total = usize::from(be16(p, 2)?);
    if ihl < 20 || total < ihl || total > p.len() {
        return None;
    }
    // Fragments are not reassembled.
    if be16(p, 6)? & 0x3fff != 0 {
        return None;
    }
    if verify && checksum(&p[..ihl], 0) != 0 {
        return None;
    }
    Some(Ip {
        src: Ipv4Addr::new(p[12], p[13], p[14], p[15]).into(),
        dst: Ipv4Addr::new(p[16], p[17], p[18], p[19]).into(),
        proto: p[9],
        hop_limit: p[8],
        payload: &p[ihl..total],
    })
}

/// Parses an IPv6 datagram, skipping hop-by-hop, routing and destination
/// options headers. IPv6 has no header checksum to verify.
pub(crate) fn parse_ipv6(p: &[u8]) -> Option<Ip<'_>> {
    if p.len() < 40 || p[0] >> 4 != 6 {
        return None;
    }
    let end = 40 + usize::from(be16(p, 4)?);
    if end > p.len() {
        return None;
    }
    let addr = |at: usize| {
        let mut a = [0u8; 16];
        a.copy_from_slice(&p[at..at + 16]);
        IpAddr::V6(Ipv6Addr::from(a))
    };
    let mut next = p[6];
    let mut at = 40;
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                let len = (usize::from(*p.get(at + 1)?) + 1) * 8;
                next = p[at];
                at += len;
                if at > end {
                    return None;
                }
            }
            // Fragments are not reassembled.
            44 => return None,
            _ => break,
        }
    }
    Some(Ip {
        src: addr(8),
        dst: addr(24),
        proto: next,
        hop_limit: p[7],
        payload: &p[at..end],
    })
}

/// A received TCP segment.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Segment<'a> {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    /// The MSS option, on SYNs.
    pub mss: Option<u16>,
    pub data: &'a [u8],
}

impl Segment<'_> {
    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    /// Sequence space the segment takes: its data plus one for SYN and FIN.
    pub fn seq_len(&self) -> u32 {
        self.data.len() as u32 + u32::from(self.has(SYN)) + u32::from(self.has(FIN))
    }
}

/// Parses a TCP segment; with `verify`, checks its checksum against the IP pseudo header.
pub(crate) fn parse_tcp<'a>(ip: &Ip<'a>, verify: bool) -> Option<Segment<'a>> {
    let p = ip.payload;
    if p.len() < 20 {
        return None;
    }
    let off = usize::from(p[12] >> 4) * 4;
    if off < 20 || off > p.len() {
        return None;
    }
    if verify && checksum(p, pseudo_sum(ip.src, ip.dst, 6, p.len())) != 0 {
        return None;
    }
    Some(Segment {
        sport: be16(p, 0)?,
        dport: be16(p, 2)?,
        seq: u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
        ack: u32::from_be_bytes([p[8], p[9], p[10], p[11]]),
        flags: p[13],
        window: be16(p, 14)?,
        mss: parse_mss(&p[20..off]),
        data: &p[off..],
    })
}

fn parse_mss(mut opts: &[u8]) -> Option<u16> {
    while let Some(&kind) = opts.first() {
        match kind {
            0 => return None,
            1 => opts = &opts[1..],
            _ => {
                let len = usize::from(*opts.get(1)?);
                if len < 2 || len > opts.len() {
                    return None;
                }
                if kind == 2 && len == 4 {
                    return be16(opts, 2);
                }
                opts = &opts[len..];
            }
        }
    }
    None
}

/// Internet checksum of `data`, starting from `sum`.
pub(crate) fn checksum(data: &[u8], mut sum: u32) -> u16 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn pseudo_sum(src: IpAddr, dst: IpAddr, proto: u8, len: usize) -> u32 {
    let words = |a: IpAddr| -> u32 {
        let b = match a {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        b.chunks(2)
            .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
            .sum()
    };
    // IPv6 carries a 32-bit length; its high half adds in as another word.
    words(src) + words(dst) + u32::from(proto) + (len as u32 & 0xffff) + (len as u32 >> 16)
}

/// Writes an Ethernet header (with a tag when `vlan` is set) into `out`.
pub(crate) fn push_link(
    out: &mut Vec<u8>,
    dst: MacAddr,
    src: MacAddr,
    vlan: Option<u16>,
    ethertype: u16,
) {
    out.extend_from_slice(&dst.0);
    out.extend_from_slice(&src.0);
    if let Some(id) = vlan {
        out.extend_from_slice(&TPID_VLAN.to_be_bytes());
        out.extend_from_slice(&(id & 0x0fff).to_be_bytes());
    }
    out.extend_from_slice(&ethertype.to_be_bytes());
}

/// Pads a frame to the Ethernet minimum of 60 bytes (without FCS).
fn pad(mut frame: Vec<u8>) -> Vec<u8> {
    if frame.len() < 60 {
        frame.resize(60, 0);
    }
    frame
}

/// An ARP request or reply.
#[allow(clippy::too_many_arguments)]
pub(crate) fn arp_frame(
    eth_dst: MacAddr,
    vlan: Option<u16>,
    op: u16,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut f = Vec::with_capacity(60);
    push_link(&mut f, eth_dst, sender_mac, vlan, ETHERTYPE_ARP);
    f.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4]);
    f.extend_from_slice(&op.to_be_bytes());
    f.extend_from_slice(&sender_mac.0);
    f.extend_from_slice(&sender_ip.octets());
    f.extend_from_slice(&target_mac.0);
    f.extend_from_slice(&target_ip.octets());
    pad(f)
}

/// Addresses of one direction of a connection, at the link and IP layers.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Path {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub vlan: Option<u16>,
    /// Both of one IP version.
    pub src: IpAddr,
    pub dst: IpAddr,
}

impl Path {
    fn ethertype(&self) -> u16 {
        if self.src.is_ipv4() {
            ETHERTYPE_IPV4
        } else {
            ETHERTYPE_IPV6
        }
    }
}

/// Writes the Ethernet and IP headers of a datagram on `path`. `id` is the
/// IPv4 identification; IPv6 has none.
fn push_ip(f: &mut Vec<u8>, path: &Path, proto: u8, payload_len: usize, id: u16, ttl: u8) {
    push_link(f, path.dst_mac, path.src_mac, path.vlan, path.ethertype());
    let start = f.len();
    match (path.src, path.dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let total = (20 + payload_len) as u16;
            f.extend_from_slice(&[0x45, 0]);
            f.extend_from_slice(&total.to_be_bytes());
            f.extend_from_slice(&id.to_be_bytes());
            f.extend_from_slice(&[0x40, 0, ttl, proto, 0, 0]); // DF
            f.extend_from_slice(&src.octets());
            f.extend_from_slice(&dst.octets());
            let sum = checksum(&f[start..], 0);
            f[start + 10..start + 12].copy_from_slice(&sum.to_be_bytes());
        }
        (src, dst) => {
            let v6 = |a: IpAddr| match a {
                IpAddr::V6(a) => a,
                IpAddr::V4(a) => a.to_ipv6_mapped(),
            };
            f.extend_from_slice(&[0x60, 0, 0, 0]);
            f.extend_from_slice(&(payload_len as u16).to_be_bytes());
            f.extend_from_slice(&[proto, ttl]);
            f.extend_from_slice(&v6(src).octets());
            f.extend_from_slice(&v6(dst).octets());
        }
    }
}

/// The header fields of a TCP segment to send.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TcpHeader {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
}

pub(crate) fn tcp_frame(path: &Path, h: &TcpHeader, data: &[u8], ip_id: u16) -> Vec<u8> {
    let opt_len = if h.mss.is_some() { 4 } else { 0 };
    let tcp_len = 20 + opt_len + data.len();
    let mut f = Vec::with_capacity(18 + 40 + tcp_len);
    push_ip(&mut f, path, 6, tcp_len, ip_id, 64);
    let start = f.len();
    f.extend_from_slice(&h.sport.to_be_bytes());
    f.extend_from_slice(&h.dport.to_be_bytes());
    f.extend_from_slice(&h.seq.to_be_bytes());
    f.extend_from_slice(&h.ack.to_be_bytes());
    f.push(((20 + opt_len) as u8 / 4) << 4);
    f.push(h.flags);
    f.extend_from_slice(&h.window.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0]); // checksum, urgent pointer
    if let Some(mss) = h.mss {
        f.extend_from_slice(&[2, 4]);
        f.extend_from_slice(&mss.to_be_bytes());
    }
    f.extend_from_slice(data);
    let sum = checksum(&f[start..], pseudo_sum(path.src, path.dst, 6, tcp_len));
    f[start + 16..start + 18].copy_from_slice(&sum.to_be_bytes());
    pad(f)
}

/// An ICMP or ICMPv6 echo reply to `request` (the ICMP part of a received
/// echo request), by the IP version of `path`.
pub(crate) fn icmp_echo_reply(path: &Path, request: &[u8], ip_id: u16) -> Option<Vec<u8>> {
    let v4 = path.src.is_ipv4();
    let (req, reply, proto) = if v4 {
        (8, 0, 1)
    } else {
        (128, 129, IPPROTO_ICMPV6)
    };
    if request.len() < 8 || request[0] != req {
        return None;
    }
    let mut f = Vec::with_capacity(18 + 40 + request.len());
    push_ip(&mut f, path, proto, request.len(), ip_id, 64);
    let start = f.len();
    f.extend_from_slice(request);
    f[start] = reply;
    f[start + 2..start + 4].fill(0);
    let pseudo = if v4 {
        0
    } else {
        pseudo_sum(path.src, path.dst, proto, request.len())
    };
    let sum = checksum(&f[start..], pseudo);
    f[start + 2..start + 4].copy_from_slice(&sum.to_be_bytes());
    Some(pad(f))
}

/// A received neighbor solicitation (135) or advertisement (136).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ndp {
    pub kind: u8,
    pub target: IpAddr,
    /// The source (solicitation) or target (advertisement) link-layer address option.
    pub lladdr: Option<MacAddr>,
}

pub(crate) const NDP_SOLICIT: u8 = 135;
pub(crate) const NDP_ADVERT: u8 = 136;

/// Parses a neighbor solicitation or advertisement, checking what RFC 4861
/// asks a receiver to check: hop limit 255, code 0, length and checksum.
pub(crate) fn parse_ndp(ip: &Ip) -> Option<Ndp> {
    let p = ip.payload;
    if ip.proto != IPPROTO_ICMPV6 || ip.hop_limit != 255 || p.len() < 24 || p[1] != 0 {
        return None;
    }
    let kind = p[0];
    if kind != NDP_SOLICIT && kind != NDP_ADVERT {
        return None;
    }
    if checksum(p, pseudo_sum(ip.src, ip.dst, IPPROTO_ICMPV6, p.len())) != 0 {
        return None;
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(&p[8..24]);
    let want = if kind == NDP_SOLICIT { 1 } else { 2 };
    let mut lladdr = None;
    let mut o = &p[24..];
    while o.len() >= 8 {
        let len = usize::from(o[1]) * 8;
        if len == 0 || len > o.len() {
            return None;
        }
        if o[0] == want {
            lladdr = Some(MacAddr([o[2], o[3], o[4], o[5], o[6], o[7]]));
        }
        o = &o[len..];
    }
    Some(Ndp {
        kind,
        target: Ipv6Addr::from(a).into(),
        lladdr,
    })
}

/// The solicited-node multicast address of `ip` (ff02::1:ffXX:XXXX).
pub(crate) fn solicited_node(ip: Ipv6Addr) -> Ipv6Addr {
    let o = ip.octets();
    Ipv6Addr::from([
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, o[13], o[14], o[15],
    ])
}

/// The Ethernet address of an IPv6 multicast group (33:33 and its last four bytes).
pub(crate) fn multicast_mac(ip: Ipv6Addr) -> MacAddr {
    let o = ip.octets();
    MacAddr([0x33, 0x33, o[12], o[13], o[14], o[15]])
}

fn ndp_frame(path: &Path, kind: u8, flags: u8, target: Ipv6Addr, lladdr: MacAddr) -> Vec<u8> {
    let mut f = Vec::with_capacity(18 + 40 + 32);
    push_ip(&mut f, path, IPPROTO_ICMPV6, 32, 0, 255);
    let start = f.len();
    f.extend_from_slice(&[kind, 0, 0, 0, flags, 0, 0, 0]);
    f.extend_from_slice(&target.octets());
    f.extend_from_slice(&[if kind == NDP_SOLICIT { 1 } else { 2 }, 1]);
    f.extend_from_slice(&lladdr.0);
    let sum = checksum(
        &f[start..],
        pseudo_sum(path.src, path.dst, IPPROTO_ICMPV6, 32),
    );
    f[start + 2..start + 4].copy_from_slice(&sum.to_be_bytes());
    pad(f)
}

/// A neighbor solicitation for `target`, from `src` at `mac`, sent to the
/// target's solicited-node multicast address.
pub(crate) fn ndp_solicit(
    mac: MacAddr,
    vlan: Option<u16>,
    src: Ipv6Addr,
    target: Ipv6Addr,
) -> Vec<u8> {
    let group = solicited_node(target);
    let path = Path {
        src_mac: mac,
        dst_mac: multicast_mac(group),
        vlan,
        src: src.into(),
        dst: group.into(),
    };
    ndp_frame(&path, NDP_SOLICIT, 0, target, mac)
}

/// A solicited neighbor advertisement: `path.src` (the target) is at `path.src_mac`.
pub(crate) fn ndp_advert(path: &Path) -> Option<Vec<u8>> {
    let IpAddr::V6(target) = path.src else {
        return None;
    };
    // Solicited and override.
    Some(ndp_frame(path, NDP_ADVERT, 0x60, target, path.src_mac))
}

/// `a < b` in sequence space.
pub(crate) fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// `a <= b` in sequence space.
pub(crate) fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_frames_parse_back() {
        let path = Path {
            src_mac: MacAddr([2, 0, 0, 0, 0, 1]),
            dst_mac: MacAddr([2, 0, 0, 0, 0, 2]),
            vlan: Some(10),
            src: Ipv4Addr::new(10, 0, 0, 1).into(),
            dst: Ipv4Addr::new(10, 0, 0, 2).into(),
        };
        let h = TcpHeader {
            sport: 40000,
            dport: 80,
            seq: 7,
            ack: 9,
            flags: SYN | ACK,
            window: 65535,
            mss: Some(1460),
        };
        let f = tcp_frame(&path, &h, b"hello", 3);
        let link = parse_link(&f).unwrap();
        assert_eq!((link.vlan, link.ethertype), (Some(10), ETHERTYPE_IPV4));
        let ip = parse_ipv4(&f[link.payload..], true).unwrap();
        let seg = parse_tcp(&ip, true).unwrap();
        assert_eq!((seg.sport, seg.seq, seg.mss), (40000, 7, Some(1460)));
        assert_eq!(seg.data, b"hello");
        assert_eq!(seg.seq_len(), 6);
        assert!(crate::net::tests::checksums_ok(&f));

        // The same over IPv6.
        let path = Path {
            src: "fd00::1".parse().unwrap(),
            dst: "fd00::2".parse().unwrap(),
            ..path
        };
        let f = tcp_frame(&path, &h, b"hello", 3);
        let link = parse_link(&f).unwrap();
        assert_eq!(link.ethertype, ETHERTYPE_IPV6);
        let ip = parse_ip(&f[link.payload..], true).unwrap();
        assert_eq!(ip.dst, path.dst);
        let seg = parse_tcp(&ip, true).unwrap();
        assert_eq!(seg.data, b"hello");
        assert!(crate::net::tests::checksums_ok(&f));
        decodes_cleanly(&f);
    }

    /// The decoder finds nothing wrong with the frame (when it is built in).
    fn decodes_cleanly(_f: &[u8]) -> Option<String> {
        #[cfg(feature = "build")]
        {
            let d = ferotrx_packet::decode(1, _f);
            assert!(d.problems.is_empty(), "{:?}", d.problems);
            return Some(d.info);
        }
        #[allow(unreachable_code)]
        None
    }

    #[test]
    fn neighbor_discovery_frames() {
        let mac = MacAddr([2, 0, 0, 0, 0, 1]);
        let me: Ipv6Addr = "fd00:10::100".parse().unwrap();
        let gw: Ipv6Addr = "fd00:10::1".parse().unwrap();
        let ns = ndp_solicit(mac, Some(10), me, gw);
        let link = parse_link(&ns).unwrap();
        assert_eq!(link.dst, MacAddr([0x33, 0x33, 0xff, 0, 0, 1]));
        let ip = parse_ip(&ns[link.payload..], true).unwrap();
        assert_eq!(
            ip.dst,
            IpAddr::from("ff02::1:ff00:1".parse::<Ipv6Addr>().unwrap())
        );
        let n = parse_ndp(&ip).unwrap();
        assert_eq!(
            (n.kind, n.target, n.lladdr),
            (NDP_SOLICIT, gw.into(), Some(mac))
        );
        if let Some(info) = decodes_cleanly(&ns) {
            assert_eq!(
                info,
                "Neighbor solicitation for fd00:10::1 is at 02:00:00:00:00:01"
            );
        }

        let na = ndp_advert(&Path {
            src_mac: mac,
            dst_mac: MacAddr([2, 0, 0, 0, 0, 9]),
            vlan: None,
            src: me.into(),
            dst: gw.into(),
        })
        .unwrap();
        let link = parse_link(&na).unwrap();
        let n = parse_ndp(&parse_ip(&na[link.payload..], true).unwrap()).unwrap();
        assert_eq!(
            (n.kind, n.target, n.lladdr),
            (NDP_ADVERT, me.into(), Some(mac))
        );
        decodes_cleanly(&na);
    }

    #[test]
    fn sequence_comparisons_wrap() {
        assert!(seq_lt(u32::MAX - 1, 3));
        assert!(!seq_lt(3, u32::MAX - 1));
        assert!(seq_le(5, 5));
    }
}
