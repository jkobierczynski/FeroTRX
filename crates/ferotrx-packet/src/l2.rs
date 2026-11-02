//! Link layer: Ethernet II, 802.3/LLC, VLAN tags, Linux cooked capture, ARP.

use crate::{hex16, l3, mac, Decoder};

pub(crate) fn ethertype_name(t: u16) -> &'static str {
    match t {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86dd => "IPv6",
        0x8100 => "802.1Q VLAN",
        0x88a8 => "802.1ad QinQ",
        0x9100 => "QinQ (old)",
        0x8035 => "RARP",
        0x8847 => "MPLS unicast",
        0x8848 => "MPLS multicast",
        0x8863 => "PPPoE discovery",
        0x8864 => "PPPoE session",
        0x888e => "802.1X EAPOL",
        0x88cc => "LLDP",
        0x88f7 => "PTP",
        0x8809 => "Slow protocols (LACP)",
        _ => "unknown",
    }
}

fn is_vlan(t: u16) -> bool {
    matches!(t, 0x8100 | 0x88a8 | 0x9100)
}

pub(crate) fn ethernet(d: &mut Decoder, at: usize) {
    if !d.need(at, 14, "Ethernet header") {
        d.data(at);
        return;
    }
    let dst = mac(&d.data[at..at + 6]);
    let src = mac(&d.data[at + 6..at + 12]);
    let t = d.u16(at + 12).unwrap_or(0);
    d.layer(
        "Ethernet",
        format!("Ethernet II, Src: {src}, Dst: {dst}"),
        at..at + 14,
    );
    d.field(
        "Destination",
        mac_kind(&d.data[at..at + 6], &dst),
        at..at + 6,
    );
    d.field("Source", src.clone(), at + 6..at + 12);
    d.addresses(src.clone(), dst.clone());
    d.summary("Ethernet", String::new());
    if t <= 1500 {
        d.field("Length", t.to_string(), at + 12..at + 14);
        llc(d, at + 14);
        return;
    }
    d.field(
        "Type",
        format!("{} ({})", hex16(t), ethertype_name(t)),
        at + 12..at + 14,
    );
    ethertype(d, t, at + 14);
}

fn mac_kind(b: &[u8], s: &str) -> String {
    if b.iter().all(|&x| x == 0xff) {
        format!("{s} (broadcast)")
    } else if b[0] & 1 == 1 {
        format!("{s} (multicast)")
    } else {
        s.to_string()
    }
}

/// Decodes the payload of an ethertype.
pub(crate) fn ethertype(d: &mut Decoder, t: u16, at: usize) {
    match t {
        _ if is_vlan(t) => vlan(d, t, at),
        0x0800 => l3::ipv4(d, at),
        0x86dd => l3::ipv6(d, at),
        0x0806 => arp(d, at),
        _ => {
            let name = ethertype_name(t);
            d.summary(
                "Ethernet",
                if name == "unknown" {
                    format!("Ethertype {}", hex16(t))
                } else {
                    name.to_string()
                },
            );
            d.data(at);
        }
    }
}

fn vlan(d: &mut Decoder, tpid: u16, at: usize) {
    if !d.need(at, 4, "VLAN tag") {
        d.data(at);
        return;
    }
    let tci = d.u16(at).unwrap_or(0);
    let t = d.u16(at + 2).unwrap_or(0);
    let (pcp, dei, id) = (tci >> 13, (tci >> 12) & 1, tci & 0x0fff);
    let name = if tpid == 0x8100 {
        "802.1Q Virtual LAN"
    } else {
        "802.1ad Service VLAN"
    };
    d.layer(
        "VLAN",
        format!("{name}, PRI: {pcp}, DEI: {dei}, ID: {id}"),
        at..at + 4,
    );
    d.field("Priority (PCP)", pcp.to_string(), at..at + 1);
    d.field("Drop eligible (DEI)", dei.to_string(), at..at + 1);
    d.field("ID", id.to_string(), at..at + 2);
    d.field(
        "Type",
        format!("{} ({})", hex16(t), ethertype_name(t)),
        at + 2..at + 4,
    );
    ethertype(d, t, at + 4);
}

fn llc(d: &mut Decoder, at: usize) {
    if !d.need(at, 3, "LLC header") {
        d.data(at);
        return;
    }
    let (dsap, ssap, ctrl) = (d.data[at], d.data[at + 1], d.data[at + 2]);
    let what = match (dsap, ssap) {
        (0x42, 0x42) => "Spanning Tree (STP)",
        (0xaa, 0xaa) => "SNAP",
        (0xe0, 0xe0) => "IPX",
        (0xf0, 0xf0) => "NetBIOS",
        _ => "LLC",
    };
    d.layer(
        "LLC",
        format!("Logical-Link Control, DSAP 0x{dsap:02x}, SSAP 0x{ssap:02x}: {what}"),
        at..at + 3,
    );
    d.field("DSAP", format!("0x{dsap:02x}"), at..at + 1);
    d.field("SSAP", format!("0x{ssap:02x}"), at + 1..at + 2);
    d.field("Control", format!("0x{ctrl:02x}"), at + 2..at + 3);
    d.summary(
        if what == "Spanning Tree (STP)" {
            "STP"
        } else {
            "LLC"
        },
        what.to_string(),
    );
    d.data(at + 3);
}

/// Linux cooked capture v1 (16 byte header).
pub(crate) fn sll(d: &mut Decoder, at: usize) {
    if !d.need(at, 16, "Linux cooked header") {
        d.data(at);
        return;
    }
    let pkt_type = d.u16(at).unwrap_or(0);
    let alen = usize::from(d.u16(at + 4).unwrap_or(0)).min(8);
    let t = d.u16(at + 14).unwrap_or(0);
    let kind = match pkt_type {
        0 => "Unicast to us",
        1 => "Broadcast",
        2 => "Multicast",
        3 => "Unicast to another host",
        4 => "Sent by us",
        _ => "Unknown",
    };
    let addr = mac(&d.data[at + 6..at + 6 + alen]);
    d.layer(
        "SLL",
        format!("Linux cooked capture, {kind}, Src: {addr}"),
        at..at + 16,
    );
    d.field("Packet type", format!("{pkt_type} ({kind})"), at..at + 2);
    d.field("Source", addr.clone(), at + 6..at + 14);
    d.field(
        "Protocol",
        format!("{} ({})", hex16(t), ethertype_name(t)),
        at + 14..at + 16,
    );
    d.addresses(addr, String::new());
    ethertype(d, t, at + 16);
}

fn arp(d: &mut Decoder, at: usize) {
    if !d.need(at, 8, "ARP header") {
        d.data(at);
        return;
    }
    let htype = d.u16(at).unwrap_or(0);
    let ptype = d.u16(at + 2).unwrap_or(0);
    let hlen = usize::from(d.data[at + 4]);
    let plen = usize::from(d.data[at + 5]);
    let op = d.u16(at + 6).unwrap_or(0);
    let end = at + 8 + 2 * (hlen + plen);
    let op_name = match op {
        1 => "request",
        2 => "reply",
        3 => "RARP request",
        4 => "RARP reply",
        _ => "unknown",
    };
    d.layer(
        "ARP",
        format!("Address Resolution Protocol ({op_name})"),
        at..end.min(d.data.len()),
    );
    d.field("Hardware type", htype.to_string(), at..at + 2);
    d.field("Protocol type", hex16(ptype), at + 2..at + 4);
    d.field("Hardware size", hlen.to_string(), at + 4..at + 5);
    d.field("Protocol size", plen.to_string(), at + 5..at + 6);
    d.field("Opcode", format!("{op} ({op_name})"), at + 6..at + 8);
    d.summary("ARP", format!("ARP {op_name}"));
    if !d.need(at + 8, 2 * (hlen + plen), "ARP addresses") {
        return;
    }
    let ip = |b: &[u8]| -> String {
        if b.len() == 4 {
            format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
        } else {
            mac(b)
        }
    };
    let mut o = at + 8;
    let sha = mac(&d.data[o..o + hlen]);
    d.field("Sender MAC", sha.clone(), o..o + hlen);
    o += hlen;
    let spa = ip(&d.data[o..o + plen]);
    d.field("Sender IP", spa.clone(), o..o + plen);
    o += plen;
    let tha = mac(&d.data[o..o + hlen]);
    d.field("Target MAC", tha, o..o + hlen);
    o += hlen;
    let tpa = ip(&d.data[o..o + plen]);
    d.field("Target IP", tpa.clone(), o..o + plen);
    let info = match op {
        1 if spa == tpa => format!("Gratuitous ARP for {spa}"),
        1 => format!("Who has {tpa}? Tell {spa}"),
        2 => format!("{spa} is at {sha}"),
        _ => format!("ARP {op_name}"),
    };
    d.summary("ARP", info);
    if end < d.data.len() {
        let n = d.data.len() - end;
        d.layer("Padding", format!("Padding ({n} bytes)"), end..d.data.len());
    }
}
