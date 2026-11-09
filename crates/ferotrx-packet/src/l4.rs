//! Transport layer: TCP, UDP, ICMP, ICMPv6.

use crate::l3::IpCtx;
use crate::{dns, hex16, l3, mcast, ones_sum, tunnel, Decoder};

pub(crate) fn transport(d: &mut Decoder, proto: u8, at: usize, ip: &IpCtx) {
    let end = ip.end.unwrap_or(d.data.len());
    match proto {
        6 => tcp(d, at, end, ip),
        17 => udp(d, at, end, ip),
        1 => icmp(d, at, end, ip),
        58 => icmpv6(d, at, end, ip),
        2 => mcast::igmp(d, at, end, ip),
        4 => l3::ipv4(d, at),
        41 => l3::ipv6(d, at),
        47 => tunnel::gre(d, at, end),
        _ => d.data_to(at, end),
    }
}

fn checksum_field(d: &mut Decoder, what: &str, at: usize, verdict: Option<bool>) {
    checksum_field_with(d, what, at, verdict, false);
}

/// Like `checksum_field`, but a wrong checksum that holds only the pseudo
/// header sum (`offloaded`) is reported as left to the network card, the
/// way Wireshark calls it "unverified", instead of as a problem.
fn checksum_field_with(
    d: &mut Decoder,
    what: &str,
    at: usize,
    verdict: Option<bool>,
    offloaded: bool,
) {
    let v = d.u16(at).unwrap_or(0);
    let note = match verdict {
        Some(true) => "correct",
        Some(false) if offloaded => "not verified, partial: offloaded to the network card",
        Some(false) => {
            d.problem(format!("{what} checksum is incorrect"));
            "incorrect"
        }
        None => "not verified",
    };
    d.field("Checksum", format!("{} [{note}]", hex16(v)), at..at + 2);
}

/// Checks the pseudo header checksum of TCP or UDP at `at`, whose
/// checksum field sits at `at + field`.
fn transport_checksum(d: &mut Decoder, what: &str, proto: u8, at: usize, field: usize, ip: &IpCtx) {
    let verdict = ip.verify(d, proto, at);
    let offloaded = verdict == Some(false)
        && d.u16(at + field)
            .is_some_and(|v| ip.offloaded(proto, at, v));
    checksum_field_with(d, what, at + field, verdict, offloaded);
}

fn tcp(d: &mut Decoder, at: usize, end: usize, ip: &IpCtx) {
    if !d.need(at, 20, "TCP header") {
        d.data_to(at, end);
        return;
    }
    let sp = d.u16(at).unwrap_or(0);
    let dp = d.u16(at + 2).unwrap_or(0);
    let seq = d.u32(at + 4).unwrap_or(0);
    let ack = d.u32(at + 8).unwrap_or(0);
    let off = usize::from(d.data[at + 12] >> 4) * 4;
    let flags = d.u16(at + 12).unwrap_or(0) & 0x01ff;
    let win = d.u16(at + 14).unwrap_or(0);
    let urg = d.u16(at + 18).unwrap_or(0);
    let names = [
        (0x100, "NS"),
        (0x080, "CWR"),
        (0x040, "ECE"),
        (0x020, "URG"),
        (0x010, "ACK"),
        (0x008, "PSH"),
        (0x004, "RST"),
        (0x002, "SYN"),
        (0x001, "FIN"),
    ];
    let set: Vec<&str> = names
        .iter()
        .rev()
        .filter(|(b, _)| flags & b != 0)
        .map(|(_, n)| *n)
        .collect();
    let hdr_end = at + off.max(20);
    let payload = end.saturating_sub(hdr_end);
    d.layer(
        "TCP",
        format!("Transmission Control Protocol, Src Port: {sp}, Dst Port: {dp}, Seq: {seq}, Len: {payload}"),
        at..hdr_end.min(d.data.len()),
    );
    d.field("Source port", sp.to_string(), at..at + 2);
    d.field("Destination port", dp.to_string(), at + 2..at + 4);
    d.field("Sequence number", seq.to_string(), at + 4..at + 8);
    d.field("Acknowledgment number", ack.to_string(), at + 8..at + 12);
    d.field("Header length", format!("{off} bytes"), at + 12..at + 13);
    d.field(
        "Flags",
        format!("0x{flags:03x} ({})", set.join(", ")),
        at + 12..at + 14,
    );
    d.field("Window", win.to_string(), at + 14..at + 16);
    transport_checksum(d, "TCP", 6, at, 16, ip);
    d.field("Urgent pointer", urg.to_string(), at + 18..at + 20);
    if off < 20 {
        d.problem(format!("TCP header length {off} is less than 20"));
        return;
    }
    if off > 20 && d.need(at, off, "TCP options") {
        d.field(
            "Options",
            tcp_options(&d.data[at + 20..at + off]),
            at + 20..at + off,
        );
    }
    let mut info = format!("{sp} → {dp} [{}] Seq={seq}", set.join(", "));
    if flags & 0x010 != 0 {
        info.push_str(&format!(" Ack={ack}"));
    }
    info.push_str(&format!(" Win={win} Len={payload}"));
    d.summary("TCP", info);
    if payload > 0 {
        app(d, sp, dp, hdr_end, end, true);
    }
}

fn tcp_options(o: &[u8]) -> String {
    let mut out = Vec::new();
    let mut i = 0;
    while i < o.len() {
        let kind = o[i];
        match kind {
            0 => break,
            1 => {
                i += 1;
                continue;
            }
            _ => {}
        }
        let Some(&len) = o.get(i + 1) else { break };
        let len = usize::from(len).max(2);
        let body = o.get(i + 2..i + len).unwrap_or(&[]);
        out.push(match (kind, body) {
            (2, [a, b]) => format!("MSS={}", u16::from_be_bytes([*a, *b])),
            (3, [s]) => format!("WS={}", 1u32 << (*s).min(14)),
            (4, _) => "SACK_PERM".to_string(),
            (5, _) => "SACK".to_string(),
            (8, b) if b.len() == 8 => format!(
                "TSval={} TSecr={}",
                u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
                u32::from_be_bytes([b[4], b[5], b[6], b[7]])
            ),
            (k, _) => format!("kind {k}"),
        });
        i += len;
    }
    out.join(", ")
}

fn udp(d: &mut Decoder, at: usize, end: usize, ip: &IpCtx) {
    if !d.need(at, 8, "UDP header") {
        d.data_to(at, end);
        return;
    }
    let sp = d.u16(at).unwrap_or(0);
    let dp = d.u16(at + 2).unwrap_or(0);
    let len = usize::from(d.u16(at + 4).unwrap_or(0));
    let csum = d.u16(at + 6).unwrap_or(0);
    d.layer(
        "UDP",
        format!("User Datagram Protocol, Src Port: {sp}, Dst Port: {dp}"),
        at..at + 8,
    );
    d.field("Source port", sp.to_string(), at..at + 2);
    d.field("Destination port", dp.to_string(), at + 2..at + 4);
    d.field("Length", len.to_string(), at + 4..at + 6);
    if csum == 0 && ip.src.len() == 4 {
        d.field("Checksum", "0x0000 [none]", at + 6..at + 8);
    } else {
        transport_checksum(d, "UDP", 17, at, 6, ip);
    }
    if len < 8 {
        d.problem(format!("UDP length {len} is less than 8"));
    }
    let end = if len >= 8 { end.min(at + len) } else { end };
    let payload = end.saturating_sub(at + 8);
    d.summary("UDP", format!("{sp} → {dp} Len={payload}"));
    if payload > 0 {
        app(d, sp, dp, at + 8, end, false);
    }
}

/// Application protocols, by port.
fn app(d: &mut Decoder, sp: u16, dp: u16, at: usize, end: usize, tcp: bool) {
    let either = |p: u16| sp == p || dp == p;
    if !tcp {
        let tunnel = match () {
            _ if dp == tunnel::VXLAN_PORT => tunnel::vxlan(d, at, end),
            _ if dp == tunnel::GENEVE_PORT => tunnel::geneve(d, at, end),
            _ if either(tunnel::GTPU_PORT) => tunnel::gtpu(d, at, end),
            _ => false,
        };
        if tunnel {
            return;
        }
    }
    if either(53) || either(5353) || either(5355) {
        // DNS over TCP has a two byte length prefix.
        let start = if tcp { at + 2 } else { at };
        if dns::dns(d, start, end, either(5353)) {
            return;
        }
    }
    let name = match () {
        _ if either(80) || either(8080) => Some("HTTP"),
        _ if either(443) => Some("TLS"),
        _ if either(22) => Some("SSH"),
        _ if either(67) || either(68) => Some("DHCP"),
        _ if either(123) => Some("NTP"),
        _ if either(161) || either(162) => Some("SNMP"),
        _ if either(514) => Some("Syslog"),
        _ => None,
    };
    d.data_to(at, end);
    if let Some(name) = name {
        let first_line = d
            .bytes(at..end)
            .filter(|_| name == "HTTP")
            .and_then(|b| b.split(|&c| c == b'\r' || c == b'\n').next())
            .filter(|l| !l.is_empty() && l.iter().all(|c| c.is_ascii_graphic() || *c == b' '))
            .map(|l| String::from_utf8_lossy(l).into_owned());
        if let Some(l) = d.out.layers.last_mut() {
            l.title = format!("{name} ({} bytes)", end - at);
            l.protocol = name;
        }
        if let Some(line) = first_line {
            d.summary(name, line);
        } else {
            d.out.protocol = name;
        }
    }
}

fn icmp_name(t: u8, c: u8) -> String {
    match (t, c) {
        (0, _) => "Echo (ping) reply".into(),
        (3, 0) => "Destination unreachable (network unreachable)".into(),
        (3, 1) => "Destination unreachable (host unreachable)".into(),
        (3, 3) => "Destination unreachable (port unreachable)".into(),
        (3, 4) => "Destination unreachable (fragmentation needed)".into(),
        (3, 13) => "Destination unreachable (administratively prohibited)".into(),
        (3, c) => format!("Destination unreachable (code {c})"),
        (5, _) => "Redirect".into(),
        (8, _) => "Echo (ping) request".into(),
        (11, 0) => "Time-to-live exceeded".into(),
        (11, _) => "Fragment reassembly time exceeded".into(),
        (t, c) => format!("Type {t}, code {c}"),
    }
}

fn icmp(d: &mut Decoder, at: usize, end: usize, ip: &IpCtx) {
    if !d.need(at, 8, "ICMP header") {
        d.data_to(at, end);
        return;
    }
    let (t, c) = (d.data[at], d.data[at + 1]);
    let name = icmp_name(t, c);
    d.layer(
        "ICMP",
        format!("Internet Control Message Protocol, {name}"),
        at..at + 8,
    );
    d.field("Type", format!("{t} ({name})"), at..at + 1);
    d.field("Code", c.to_string(), at + 1..at + 2);
    let verdict = (!ip.fragmented && ip.end.is_some())
        .then(|| d.bytes(at..end).map(|b| ones_sum(&[b]) == 0xffff))
        .flatten();
    checksum_field(d, "ICMP", at + 2, verdict);
    let mut info = name;
    if matches!(t, 0 | 8) {
        let id = d.u16(at + 4).unwrap_or(0);
        let seq = d.u16(at + 6).unwrap_or(0);
        d.field(
            "Identifier",
            format!("{} ({id})", hex16(id)),
            at + 4..at + 6,
        );
        d.field("Sequence", seq.to_string(), at + 6..at + 8);
        info.push_str(&format!(" id={} seq={seq}", hex16(id)));
    }
    d.summary("ICMP", info);
    d.data_to(at + 8, end);
}

fn icmpv6_name(t: u8) -> &'static str {
    match t {
        1 => "Destination unreachable",
        2 => "Packet too big",
        3 => "Time exceeded",
        4 => "Parameter problem",
        128 => "Echo (ping) request",
        129 => "Echo (ping) reply",
        130 => "Multicast listener query",
        131 => "Multicast listener report",
        133 => "Router solicitation",
        134 => "Router advertisement",
        135 => "Neighbor solicitation",
        136 => "Neighbor advertisement",
        137 => "Redirect",
        132 => "Multicast listener done",
        143 => "Multicast listener report v2",
        _ => "unknown",
    }
}

fn icmpv6(d: &mut Decoder, at: usize, end: usize, ip: &IpCtx) {
    if !d.need(at, 4, "ICMPv6 header") {
        d.data_to(at, end);
        return;
    }
    let (t, c) = (d.data[at], d.data[at + 1]);
    let name = icmpv6_name(t);
    d.layer(
        "ICMPv6",
        format!("Internet Control Message Protocol v6, {name}"),
        // Neighbor discovery messages are all header, options included.
        at..if (133..=137).contains(&t) {
            end
        } else {
            (at + 8).min(end)
        },
    );
    d.field("Type", format!("{t} ({name})"), at..at + 1);
    d.field("Code", c.to_string(), at + 1..at + 2);
    checksum_field(d, "ICMPv6", at + 2, ip.verify(d, 58, at));
    let mut info = if name == "unknown" {
        format!("Type {t}, code {c}")
    } else {
        name.to_string()
    };
    match t {
        130..=132 | 143 => {
            mcast::mld(d, t, at, end);
            return;
        }
        128 | 129 if d.need(at, 8, "ICMPv6 echo") => {
            let id = d.u16(at + 4).unwrap_or(0);
            let seq = d.u16(at + 6).unwrap_or(0);
            d.field("Identifier", hex16(id), at + 4..at + 6);
            d.field("Sequence", seq.to_string(), at + 6..at + 8);
            info.push_str(&format!(" id={} seq={seq}", hex16(id)));
        }
        135 | 136 if d.need(at, 24, "ICMPv6 neighbor discovery") => {
            if t == 136 {
                let f = d.data[at + 4];
                let names: Vec<&str> = [(0x80, "router"), (0x40, "solicited"), (0x20, "override")]
                    .iter()
                    .filter(|(bit, _)| f & bit != 0)
                    .map(|(_, n)| *n)
                    .collect();
                let names = if names.is_empty() {
                    "none".to_string()
                } else {
                    names.join(", ")
                };
                d.field("Flags", names, at + 4..at + 5);
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&d.data[at + 8..at + 24]);
            let target = std::net::Ipv6Addr::from(a).to_string();
            d.field("Target", target.clone(), at + 8..at + 24);
            if t == 135 {
                info.push_str(&format!(" for {target}"));
            } else {
                info.push_str(&format!(" {target}"));
            }
            if let Some(mac) = nd_options(d, at + 24, end) {
                info.push_str(&format!(" is at {mac}"));
            }
            d.summary("ICMPv6", info);
            return;
        }
        133 | 134 => {
            let first = if t == 133 { 8 } else { 16 };
            if t == 134 && d.need(at, 16, "ICMPv6 router advertisement") {
                d.field("Cur hop limit", d.data[at + 4].to_string(), at + 4..at + 5);
                let life = d.u16(at + 6).unwrap_or(0);
                d.field("Router lifetime", format!("{life} s"), at + 6..at + 8);
            }
            nd_options(d, at + first, end);
            d.summary("ICMPv6", info);
            return;
        }
        _ => {}
    }
    d.summary("ICMPv6", info);
    d.data_to(at + 8, end);
}

/// Neighbor discovery options from `at` to `end`, as fields of the ICMPv6
/// layer. Returns the link-layer address option's address, if there is one.
fn nd_options(d: &mut Decoder, mut at: usize, end: usize) -> Option<String> {
    let end = end.min(d.data.len());
    let mut lladdr = None;
    while at + 2 <= end {
        let (ty, units) = (d.data[at], usize::from(d.data[at + 1]));
        let len = units * 8;
        if len == 0 || at + len > end {
            d.problem(format!("ICMPv6 option at offset {at} has a bad length"));
            break;
        }
        let r = at..at + len;
        match ty {
            1 | 2 if len >= 8 => {
                let mac = crate::mac(&d.data[at + 2..at + 8]);
                let name = if ty == 1 {
                    "Source link-layer address"
                } else {
                    "Target link-layer address"
                };
                d.field(name, mac.clone(), r);
                lladdr = Some(mac);
            }
            3 if len >= 32 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&d.data[at + 16..at + 32]);
                let p = std::net::Ipv6Addr::from(a);
                d.field("Prefix", format!("{p}/{}", d.data[at + 2]), r);
            }
            5 if len >= 8 => {
                let mtu = d.u32(at + 4).unwrap_or(0);
                d.field("MTU", mtu.to_string(), r);
            }
            _ => d.field("Option", format!("type {ty}, {len} bytes"), r),
        }
        at += len;
    }
    lladdr
}
