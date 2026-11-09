//! Tunnels and label stacks: MPLS, GRE, VXLAN, Geneve and GTP-U.
//!
//! Each decoder reads its header and hands what it carries to the decoder of
//! that protocol, so the layers of the inner packet follow the tunnel's.

use crate::{hex16, l2, l3, ones_sum, Decoder};

/// UDP port of VXLAN (RFC 7348).
pub const VXLAN_PORT: u16 = 4789;
/// UDP port of Geneve (RFC 8926).
pub const GENEVE_PORT: u16 = 6081;
/// UDP port of GTP-U (3GPP TS 29.281).
pub const GTPU_PORT: u16 = 2152;
/// Ethertype of an Ethernet frame inside GRE or Geneve (transparent Ethernet bridging).
pub const ETHERTYPE_TEB: u16 = 0x6558;
/// Ethertype of MPLS unicast.
pub const ETHERTYPE_MPLS: u16 = 0x8847;
/// Ethertype of MPLS multicast.
pub const ETHERTYPE_MPLS_MC: u16 = 0x8848;

/// What a tunnel carries, by ethertype: an Ethernet frame for 0x6558, else
/// whatever the ethertype names.
fn carried(d: &mut Decoder, ethertype: u16, at: usize) {
    if ethertype == ETHERTYPE_TEB {
        l2::ethernet(d, at);
    } else {
        l2::ethertype(d, ethertype, at);
    }
}

/// An MPLS label stack entry, and the ones after it down to the bottom of the
/// stack, then the packet it labels.
pub(crate) fn mpls(d: &mut Decoder, mut at: usize) {
    for _ in 0..16 {
        if !d.need(at, 4, "MPLS label") {
            d.data(at);
            return;
        }
        let w = d.u32(at).unwrap_or(0);
        let (label, tc, bos, ttl) = (w >> 12, (w >> 9) & 7, (w >> 8) & 1 == 1, w & 0xff);
        d.layer(
            "MPLS",
            format!(
                "MultiProtocol Label Switching Header, Label: {label}{}, Exp: {tc}, S: {}, TTL: {ttl}",
                label_name(label).map(|n| format!(" ({n})")).unwrap_or_default(),
                u8::from(bos)
            ),
            at..at + 4,
        );
        d.field("Label", label.to_string(), at..at + 3);
        d.field("Traffic class", tc.to_string(), at + 2..at + 3);
        d.field("Bottom of stack", u8::from(bos).to_string(), at + 2..at + 3);
        d.field("TTL", ttl.to_string(), at + 3..at + 4);
        d.summary("MPLS", format!("MPLS label {label}"));
        at += 4;
        if bos {
            break;
        }
    }
    // What follows the stack is not named; the first nibble tells IP versions
    // apart, and 0 starts a pseudowire control word before an Ethernet frame.
    match d.u8(at).map(|b| b >> 4) {
        Some(4) => l3::ipv4(d, at),
        Some(6) => l3::ipv6(d, at),
        Some(0) if d.data.len() >= at + 4 + 14 => {
            let cw = d.u32(at).unwrap_or(0);
            d.layer("PW", "PW Ethernet Control Word".to_string(), at..at + 4);
            d.field("Sequence number", (cw & 0xffff).to_string(), at + 2..at + 4);
            l2::ethernet(d, at + 4);
        }
        _ => d.data(at),
    }
}

fn label_name(label: u32) -> Option<&'static str> {
    Some(match label {
        0 => "IPv4 Explicit-Null",
        1 => "Router Alert",
        2 => "IPv6 Explicit-Null",
        3 => "Implicit-Null",
        7 => "Entropy Label Indicator",
        13 => "OAM Alert",
        _ => return None,
    })
}

/// GRE (RFC 2784, keys and sequence numbers from RFC 2890; version 1 is the
/// enhanced GRE of PPTP).
pub(crate) fn gre(d: &mut Decoder, at: usize, end: usize) {
    if !d.need(at, 4, "GRE header") {
        d.data_to(at, end);
        return;
    }
    let flags = d.u16(at).unwrap_or(0);
    let proto = d.u16(at + 2).unwrap_or(0);
    let (c, k, s) = (
        flags & 0x8000 != 0,
        flags & 0x2000 != 0,
        flags & 0x1000 != 0,
    );
    let ack = flags & 0x0080 != 0;
    let version = flags & 7;
    let len = 4 + 4 * (usize::from(c) + usize::from(k) + usize::from(s) + usize::from(ack));
    d.layer(
        "GRE",
        format!(
            "Generic Routing Encapsulation ({})",
            match proto {
                ETHERTYPE_TEB => "Transparent Ethernet bridging".to_string(),
                0x880b => "PPP".to_string(),
                t => l2::ethertype_name(t).to_string(),
            }
        ),
        at..(at + len).min(d.data.len()),
    );
    let mut names = Vec::new();
    for (bit, n) in [(c, "checksum"), (k, "key"), (s, "sequence"), (ack, "ack")] {
        if bit {
            names.push(n);
        }
    }
    d.field(
        "Flags",
        format!(
            "0x{flags:04x} ({})",
            if names.is_empty() {
                "none".to_string()
            } else {
                names.join(", ")
            }
        ),
        at..at + 2,
    );
    d.field("Version", version.to_string(), at + 1..at + 2);
    d.field(
        "Protocol type",
        format!("{} ({})", hex16(proto), l2::ethertype_name(proto)),
        at + 2..at + 4,
    );
    if !d.need(at, len, "GRE options") {
        return;
    }
    let mut o = at + 4;
    let mut info = String::from("GRE");
    if c {
        let v = d.u16(o).unwrap_or(0);
        let ok = d
            .bytes(at..end.min(d.data.len()))
            .map(|b| ones_sum(&[b]) == 0xffff);
        let note = match ok {
            Some(true) => "correct",
            Some(false) => {
                d.problem("GRE checksum is incorrect".into());
                "incorrect"
            }
            None => "not verified",
        };
        d.field("Checksum", format!("{} [{note}]", hex16(v)), o..o + 2);
        o += 4;
    }
    if k {
        let key = d.u32(o).unwrap_or(0);
        if version == 1 {
            d.field("Payload length", (key >> 16).to_string(), o..o + 2);
            d.field("Call ID", (key & 0xffff).to_string(), o + 2..o + 4);
        } else {
            d.field("Key", format!("{key} (0x{key:08x})"), o..o + 4);
            info.push_str(&format!(" key {key}"));
        }
        o += 4;
    }
    if s {
        let seq = d.u32(o).unwrap_or(0);
        d.field("Sequence number", seq.to_string(), o..o + 4);
        info.push_str(&format!(" seq {seq}"));
        o += 4;
    }
    if ack {
        d.field(
            "Acknowledgment",
            d.u32(o).unwrap_or(0).to_string(),
            o..o + 4,
        );
        o += 4;
    }
    d.summary("GRE", info);
    if version != 0 || proto == 0x880b {
        d.data_to(o, end);
        return;
    }
    carried(d, proto, o);
}

/// VXLAN (RFC 7348): 8 bytes, then an Ethernet frame.
pub(crate) fn vxlan(d: &mut Decoder, at: usize, end: usize) -> bool {
    if d.data.len() < at + 8 + 14 {
        return false;
    }
    let flags = d.data[at];
    let vni = d.u32(at + 4).unwrap_or(0) >> 8;
    d.layer(
        "VXLAN",
        format!("Virtual eXtensible Local Area Network, VNI: {vni}"),
        at..at + 8,
    );
    d.field(
        "Flags",
        format!(
            "0x{flags:02x}{}",
            if flags & 0x08 != 0 {
                " (VNI valid)"
            } else {
                ""
            }
        ),
        at..at + 1,
    );
    d.field("VNI", vni.to_string(), at + 4..at + 7);
    if flags & 0x08 == 0 {
        d.problem("VXLAN flags do not have the I bit (VNI valid) set".into());
    }
    d.summary("VXLAN", format!("VXLAN VNI {vni}"));
    let _ = end;
    l2::ethernet(d, at + 8);
    true
}

/// Geneve (RFC 8926): 8 bytes, options, then what the protocol type names.
pub(crate) fn geneve(d: &mut Decoder, at: usize, end: usize) -> bool {
    if d.data.len() < at + 8 {
        return false;
    }
    let ver = d.data[at] >> 6;
    let opt_len = usize::from(d.data[at] & 0x3f) * 4;
    let flags = d.data[at + 1];
    let proto = d.u16(at + 2).unwrap_or(0);
    let vni = d.u32(at + 4).unwrap_or(0) >> 8;
    if ver != 0 || d.data.len() < at + 8 + opt_len {
        return false;
    }
    d.layer(
        "Geneve",
        format!("Generic Network Virtualization Encapsulation, VNI: {vni}"),
        at..at + 8 + opt_len,
    );
    d.field("Version", ver.to_string(), at..at + 1);
    d.field("Options length", format!("{opt_len} bytes"), at..at + 1);
    let mut names = Vec::new();
    if flags & 0x80 != 0 {
        names.push("OAM");
    }
    if flags & 0x40 != 0 {
        names.push("critical options");
    }
    d.field(
        "Flags",
        format!(
            "0x{flags:02x}{}",
            if names.is_empty() {
                String::new()
            } else {
                format!(" ({})", names.join(", "))
            }
        ),
        at + 1..at + 2,
    );
    d.field(
        "Protocol type",
        format!(
            "{} ({})",
            hex16(proto),
            if proto == ETHERTYPE_TEB {
                "Transparent Ethernet bridging"
            } else {
                l2::ethertype_name(proto)
            }
        ),
        at + 2..at + 4,
    );
    d.field("VNI", vni.to_string(), at + 4..at + 7);
    let mut o = at + 8;
    while o + 4 <= at + 8 + opt_len {
        let class = d.u16(o).unwrap_or(0);
        let ty = d.data[o + 2];
        let len = usize::from(d.data[o + 3] & 0x1f) * 4;
        let r = o..(o + 4 + len).min(at + 8 + opt_len);
        d.field(
            "Option",
            format!("class {}, type {ty}, {len} bytes", hex16(class)),
            r,
        );
        o += 4 + len;
    }
    d.summary("Geneve", format!("Geneve VNI {vni}"));
    let _ = end;
    carried(d, proto, at + 8 + opt_len);
    true
}

fn gtp_message(t: u8) -> &'static str {
    match t {
        1 => "Echo request",
        2 => "Echo response",
        26 => "Error indication",
        31 => "Supported extension headers notification",
        253 => "Tunnel status",
        254 => "End marker",
        255 => "T-PDU",
        _ => "unknown",
    }
}

/// GTP-U (3GPP TS 29.281): 8 bytes, 4 more when any of E, S and PN is set,
/// extension headers, then the user's IP packet in a T-PDU.
pub(crate) fn gtpu(d: &mut Decoder, at: usize, end: usize) -> bool {
    if d.data.len() < at + 8 || d.data[at] >> 5 != 1 || d.data[at] & 0x10 == 0 {
        return false;
    }
    let flags = d.data[at];
    let msg = d.data[at + 1];
    let len = usize::from(d.u16(at + 2).unwrap_or(0));
    let teid = d.u32(at + 4).unwrap_or(0);
    let (e, s, pn) = (flags & 4 != 0, flags & 2 != 0, flags & 1 != 0);
    let opt = e || s || pn;
    let hdr = 8 + if opt { 4 } else { 0 };
    // Extension headers: a length in 4-byte units, then their contents, the
    // last byte naming the next one.
    let mut o = at + hdr;
    let mut exts = Vec::new();
    let mut next = if opt && d.data.len() >= at + 12 {
        d.data[at + 11]
    } else {
        0
    };
    while e && next != 0 && exts.len() < 8 {
        let Some(units) = d.u8(o).map(usize::from) else {
            break;
        };
        if units == 0 || d.data.len() < o + units * 4 {
            d.problem("GTP-U extension header has a bad length".into());
            break;
        }
        exts.push((next, o, units * 4));
        next = d.data[o + units * 4 - 1];
        o += units * 4;
    }
    d.layer(
        "GTP",
        format!(
            "GPRS Tunneling Protocol, {}, TEID: 0x{teid:08x}",
            gtp_message(msg)
        ),
        at..o.min(d.data.len()),
    );
    let mut names = Vec::new();
    for (b, n) in [(e, "E"), (s, "S"), (pn, "PN")] {
        if b {
            names.push(n);
        }
    }
    d.field(
        "Flags",
        format!(
            "0x{flags:02x} (version 1{}{})",
            if names.is_empty() { "" } else { ", " },
            names.join(", ")
        ),
        at..at + 1,
    );
    d.field(
        "Message type",
        format!("{msg} ({})", gtp_message(msg)),
        at + 1..at + 2,
    );
    d.field("Length", len.to_string(), at + 2..at + 4);
    d.field("TEID", format!("0x{teid:08x} ({teid})"), at + 4..at + 8);
    if opt && d.data.len() >= at + 12 {
        d.field(
            "Sequence number",
            d.u16(at + 8).unwrap_or(0).to_string(),
            at + 8..at + 10,
        );
        d.field(
            "N-PDU number",
            d.data[at + 10].to_string(),
            at + 10..at + 11,
        );
        d.field(
            "Next extension header",
            format!("0x{:02x}", d.data[at + 11]),
            at + 11..at + 12,
        );
    }
    let mut qfi = None;
    for (ty, from, n) in exts {
        if ty == 0x85 && n >= 4 {
            // PDU session container: PDU type, then the QoS flow identifier.
            let pdu = d.data[from + 1] >> 4;
            let q = d.data[from + 2] & 0x3f;
            qfi = Some(q);
            d.field(
                "PDU session container",
                format!("{}, QFI {q}", if pdu == 0 { "downlink" } else { "uplink" }),
                from..from + n,
            );
        } else {
            d.field(
                "Extension header",
                format!("type 0x{ty:02x}, {n} bytes"),
                from..from + n,
            );
        }
    }
    let stated_end = at + 8 + len;
    if stated_end != end.min(d.data.len()) && stated_end <= d.data.len() && end <= d.data.len() {
        d.problem(format!(
            "GTP-U length {len} does not match the {} bytes after its header",
            end.saturating_sub(at + 8)
        ));
    }
    let mut info = format!("{} TEID 0x{teid:08x}", gtp_message(msg));
    if let Some(q) = qfi {
        info.push_str(&format!(" QFI {q}"));
    }
    d.summary("GTP", info);
    if msg == 255 && o < end {
        match d.u8(o).map(|b| b >> 4) {
            Some(4) => l3::ipv4(d, o),
            Some(6) => l3::ipv6(d, o),
            _ => d.data_to(o, end),
        }
    } else {
        d.data_to(o, end);
    }
    true
}

#[cfg(test)]
mod tests {
    use crate::{decode, LINKTYPE_ETHERNET};

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// An ICMP echo over MPLS with two labels, as Wireshark's mpls sample shows it.
    #[test]
    fn mpls_two_labels_then_ipv4() {
        let f = hex("000000000002 000000000001 8847
             0006 40ff  0003 e1ff
             4500001c00004000400100000a0000010a000002
             0800f7ff00000000");
        let d = decode(LINKTYPE_ETHERNET, &f);
        let labels: Vec<_> = d.layers.iter().filter(|l| l.protocol == "MPLS").collect();
        assert_eq!(labels.len(), 2);
        assert!(
            labels[0].title.contains("Label: 100,"),
            "{}",
            labels[0].title
        );
        assert!(
            labels[1].title.contains("Label: 62,"),
            "{}",
            labels[1].title
        );
        assert!(labels[1].title.contains("S: 1"), "{}", labels[1].title);
        assert_eq!(d.protocol, "ICMP");
    }
}
