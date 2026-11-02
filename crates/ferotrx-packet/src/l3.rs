//! Network layer: IPv4 and IPv6 with extension headers.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{hex16, l4, ones_sum, Decoder};

/// What a transport decoder needs to know about the IP header in front of it.
pub(crate) struct IpCtx {
    pub src: Vec<u8>,
    pub dst: Vec<u8>,
    /// End of the datagram per the IP header, when the capture holds all of it.
    pub end: Option<usize>,
    pub fragmented: bool,
}

impl IpCtx {
    /// Verifies a transport checksum that covers the IP pseudo header.
    /// `None` when the capture does not hold the whole segment.
    pub fn verify(&self, d: &Decoder, proto: u8, at: usize) -> Option<bool> {
        let end = self.end?;
        if self.fragmented || at > end {
            return None;
        }
        let seg = d.bytes(at..end)?;
        let len = seg.len() as u32;
        let mut pseudo = Vec::with_capacity(40);
        pseudo.extend(&self.src);
        pseudo.extend(&self.dst);
        if self.src.len() == 4 {
            pseudo.extend([0, proto]);
            pseudo.extend((len as u16).to_be_bytes());
        } else {
            pseudo.extend(len.to_be_bytes());
            pseudo.extend([0, 0, 0, proto]);
        }
        Some(ones_sum(&[&pseudo, seg]) == 0xffff)
    }
}

pub(crate) fn proto_name(p: u8) -> &'static str {
    match p {
        0 => "IPv6 Hop-by-Hop",
        1 => "ICMP",
        2 => "IGMP",
        4 => "IPv4 in IP",
        6 => "TCP",
        17 => "UDP",
        41 => "IPv6 in IP",
        43 => "IPv6 Routing",
        44 => "IPv6 Fragment",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        59 => "No next header",
        60 => "IPv6 Destination Options",
        89 => "OSPF",
        103 => "PIM",
        112 => "VRRP",
        132 => "SCTP",
        _ => "unknown",
    }
}

pub(crate) fn raw_ip(d: &mut Decoder, at: usize) {
    match d.u8(at).map(|b| b >> 4) {
        Some(4) => ipv4(d, at),
        Some(6) => ipv6(d, at),
        _ => {
            d.problem("raw IP packet with an unknown version".into());
            d.data(at);
        }
    }
}

fn v4(b: &[u8]) -> String {
    Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()
}

fn v6(b: &[u8]) -> String {
    let mut a = [0u8; 16];
    a.copy_from_slice(b);
    Ipv6Addr::from(a).to_string()
}

pub(crate) fn ipv4(d: &mut Decoder, at: usize) {
    if !d.need(at, 20, "IPv4 header") {
        d.data(at);
        return;
    }
    let vihl = d.data[at];
    let ihl = usize::from(vihl & 0x0f) * 4;
    let tos = d.data[at + 1];
    let total = usize::from(d.u16(at + 2).unwrap_or(0));
    let id = d.u16(at + 4).unwrap_or(0);
    let frag = d.u16(at + 6).unwrap_or(0);
    let ttl = d.data[at + 8];
    let proto = d.data[at + 9];
    let csum = d.u16(at + 10).unwrap_or(0);
    let src = v4(&d.data[at + 12..at + 16]);
    let dst = v4(&d.data[at + 16..at + 20]);
    let hdr_end = at + ihl.max(20);

    d.layer(
        "IPv4",
        format!("Internet Protocol Version 4, Src: {src}, Dst: {dst}"),
        at..hdr_end.min(d.data.len()),
    );
    d.field("Version", (vihl >> 4).to_string(), at..at + 1);
    d.field("Header length", format!("{ihl} bytes"), at..at + 1);
    d.field(
        "DSCP / ECN",
        format!("{} / {}", tos >> 2, tos & 3),
        at + 1..at + 2,
    );
    d.field("Total length", total.to_string(), at + 2..at + 4);
    d.field(
        "Identification",
        format!("{} ({id})", hex16(id)),
        at + 4..at + 6,
    );
    let df = frag & 0x4000 != 0;
    let mf = frag & 0x2000 != 0;
    let offset = usize::from(frag & 0x1fff) * 8;
    let mut flags = Vec::new();
    if frag & 0x8000 != 0 {
        flags.push("reserved");
    }
    if df {
        flags.push("DF");
    }
    if mf {
        flags.push("MF");
    }
    d.field(
        "Flags",
        if flags.is_empty() {
            "none".to_string()
        } else {
            flags.join(", ")
        },
        at + 6..at + 7,
    );
    d.field("Fragment offset", offset.to_string(), at + 6..at + 8);
    d.field("Time to live", ttl.to_string(), at + 8..at + 9);
    d.field(
        "Protocol",
        format!("{proto} ({})", proto_name(proto)),
        at + 9..at + 10,
    );
    d.addresses(src.clone(), dst.clone());

    if vihl >> 4 != 4 || ihl < 20 {
        d.problem(format!(
            "IPv4 header has version {} and length {ihl}",
            vihl >> 4
        ));
        d.data(at + 20);
        return;
    }
    if !d.need(at, ihl, "IPv4 options") {
        return;
    }
    let ok = ones_sum(&[&d.data[at..at + ihl]]) == 0xffff;
    d.field(
        "Header checksum",
        format!(
            "{} [{}]",
            hex16(csum),
            if ok { "correct" } else { "incorrect" }
        ),
        at + 10..at + 12,
    );
    if !ok {
        d.problem("IPv4 header checksum is incorrect".into());
    }
    d.field("Source", src.clone(), at + 12..at + 16);
    d.field("Destination", dst.clone(), at + 16..at + 20);
    if ihl > 20 {
        d.field("Options", format!("{} bytes", ihl - 20), at + 20..at + ihl);
    }
    d.summary("IPv4", format!("{} (protocol {proto})", proto_name(proto)));

    let end = at + total;
    let ctx = IpCtx {
        src: d.data[at + 12..at + 16].to_vec(),
        dst: d.data[at + 16..at + 20].to_vec(),
        end: (total >= ihl && end <= d.data.len()).then_some(end),
        fragmented: mf || offset != 0,
    };
    if total < ihl {
        d.problem(format!(
            "IPv4 total length {total} is shorter than its header"
        ));
    } else if end > d.data.len() {
        d.problem(format!(
            "IPv4 datagram truncated: {total} bytes, capture has {}",
            d.data.len() - at
        ));
    }
    if offset != 0 {
        d.summary(
            "IPv4",
            format!(
                "Fragment of {} (offset {offset}, id {})",
                proto_name(proto),
                hex16(id)
            ),
        );
        d.data_to(hdr_end, ctx.end.unwrap_or(d.data.len()));
    } else {
        if mf {
            d.summary(
                "IPv4",
                format!("First fragment of {} (id {})", proto_name(proto), hex16(id)),
            );
        }
        l4::transport(d, proto, hdr_end, &ctx);
    }
    padding(d, ctx.end);
}

/// Bytes after the end of the IP datagram (Ethernet padding) as their own layer.
fn padding(d: &mut Decoder, end: Option<usize>) {
    if let Some(end) = end {
        let n = d.data.len().saturating_sub(end);
        if n > 0 {
            d.layer("Padding", format!("Padding ({n} bytes)"), end..d.data.len());
        }
    }
}

const EXT_HEADERS: [u8; 5] = [0, 43, 44, 51, 60];

pub(crate) fn ipv6(d: &mut Decoder, at: usize) {
    if !d.need(at, 40, "IPv6 header") {
        d.data(at);
        return;
    }
    let w = d.u32(at).unwrap_or(0);
    let payload = usize::from(d.u16(at + 4).unwrap_or(0));
    let mut next = d.data[at + 6];
    let hop = d.data[at + 7];
    let src = v6(&d.data[at + 8..at + 24]);
    let dst = v6(&d.data[at + 24..at + 40]);
    d.layer(
        "IPv6",
        format!("Internet Protocol Version 6, Src: {src}, Dst: {dst}"),
        at..at + 40,
    );
    d.field("Version", (w >> 28).to_string(), at..at + 1);
    d.field(
        "Traffic class",
        format!("0x{:02x}", (w >> 20) & 0xff),
        at..at + 2,
    );
    d.field(
        "Flow label",
        format!("0x{:05x}", w & 0xfffff),
        at + 1..at + 4,
    );
    d.field("Payload length", payload.to_string(), at + 4..at + 6);
    d.field(
        "Next header",
        format!("{next} ({})", proto_name(next)),
        at + 6..at + 7,
    );
    d.field("Hop limit", hop.to_string(), at + 7..at + 8);
    d.field("Source", src.clone(), at + 8..at + 24);
    d.field("Destination", dst.clone(), at + 24..at + 40);
    d.addresses(src, dst);
    d.summary("IPv6", format!("{} (next header {next})", proto_name(next)));
    if (w >> 28) != 6 {
        d.problem(format!("IPv6 header has version {}", w >> 28));
    }

    let end = at + 40 + payload;
    let mut ctx = IpCtx {
        src: d.data[at + 8..at + 24].to_vec(),
        dst: d.data[at + 24..at + 40].to_vec(),
        end: (end <= d.data.len()).then_some(end),
        fragmented: false,
    };
    if end > d.data.len() {
        d.problem(format!(
            "IPv6 datagram truncated: {} bytes, capture has {}",
            40 + payload,
            d.data.len() - at
        ));
    }

    let mut o = at + 40;
    for _ in 0..8 {
        if !EXT_HEADERS.contains(&next) {
            break;
        }
        if !d.need(o, 8, "IPv6 extension header") {
            return;
        }
        let nh = d.data[o];
        let len = match next {
            44 => 8,
            51 => (usize::from(d.data[o + 1]) + 2) * 4,
            _ => (usize::from(d.data[o + 1]) + 1) * 8,
        };
        d.layer(
            "IPv6 ext",
            proto_name(next).to_string(),
            o..(o + len).min(d.data.len()),
        );
        d.field(
            "Next header",
            format!("{nh} ({})", proto_name(nh)),
            o..o + 1,
        );
        d.field("Length", format!("{len} bytes"), o + 1..o + 2);
        if next == 44 {
            let f = d.u16(o + 2).unwrap_or(0);
            let id = d.u32(o + 4).unwrap_or(0);
            let offset = usize::from(f >> 3) * 8;
            d.field("Fragment offset", offset.to_string(), o + 2..o + 4);
            d.field("More fragments", (f & 1 == 1).to_string(), o + 3..o + 4);
            d.field("Identification", format!("0x{id:08x}"), o + 4..o + 8);
            ctx.fragmented = true;
            if offset != 0 {
                d.summary(
                    "IPv6",
                    format!("Fragment of {} (offset {offset})", proto_name(nh)),
                );
                d.data_to(o + 8, ctx.end.unwrap_or(d.data.len()));
                padding(d, ctx.end);
                return;
            }
        }
        next = nh;
        o += len;
    }
    if next == 59 {
        d.summary("IPv6", "No next header".into());
    } else {
        l4::transport(d, next, o, &ctx);
    }
    padding(d, ctx.end);
}
