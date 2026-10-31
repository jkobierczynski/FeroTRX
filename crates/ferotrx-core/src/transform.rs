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
}

impl<T: Transform + ?Sized> Transform for Box<T> {
    fn apply(&mut self, packet: &mut Packet) {
        (**self).apply(packet)
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
            if wanted && self.from.map_or(true, |f| data[range.clone()] == f.0) {
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
        let Some(net::Layers { ip: Some(ip) }) = net::parse(data) else {
            return;
        };
        let mut sums = Vec::with_capacity(2);
        if let Some(at) = ip.header_checksum {
            sums.push((0, at));
        }
        sums.extend(ip.l4_checksum(data));
        for (wanted, range) in [
            (self.field.src(), ip.src.clone()),
            (self.field.dst(), ip.dst.clone()),
        ] {
            if !wanted {
                continue;
            }
            if let Some(new) = self.map(&data[range.clone()]) {
                net::replace(data, range, &new, &sums);
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
        let Some(net::Layers { ip: Some(ip) }) = net::parse(data) else {
            return;
        };
        let Some(at) = ip.ports(data) else {
            return;
        };
        let sums: Vec<_> = ip.l4_checksum(data).into_iter().collect();
        for (wanted, off) in [(self.field.src(), at), (self.field.dst(), at + 2)] {
            let old = net::be16(data, off).expect("ports() checked the length");
            if wanted && self.from.map_or(true, |f| f == old) {
                net::replace(data, off..off + 2, &self.to.to_be_bytes(), &sums);
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
///
/// Address and port rewrites keep checksums correct (or exactly as wrong as they
/// were in the capture).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rewrite {
    Mac(MacRewrite),
    Ip(IpRewrite),
    Port(PortRewrite),
    VlanPush(VlanPush),
    VlanPop(VlanPop),
    VlanSet(VlanSet),
    FixChecksums(FixChecksums),
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
            "vlan_pop" | "fix_checksums" if arg.is_some() => return Err(err("takes no value")),
            "vlan_pop" => Rewrite::VlanPop(VlanPop),
            "fix_checksums" => Rewrite::FixChecksums(FixChecksums),
            _ => return Err(err("unknown rewrite (try mac_dst, ip_src, port_dst, vlan_push, vlan_pop, vlan_set, fix_checksums)")),
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
}
