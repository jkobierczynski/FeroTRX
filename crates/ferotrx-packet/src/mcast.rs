//! Multicast group management: IGMP (v1, v2 and v3) and MLD (v1 and v2).

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::l3::IpCtx;
use crate::{ones_sum, Decoder};

/// Name of an IGMPv3 or MLDv2 group record type (RFC 3376 4.2.12).
pub(crate) fn record_name(t: u8) -> &'static str {
    match t {
        1 => "MODE_IS_INCLUDE",
        2 => "MODE_IS_EXCLUDE",
        3 => "CHANGE_TO_INCLUDE_MODE",
        4 => "CHANGE_TO_EXCLUDE_MODE",
        5 => "ALLOW_NEW_SOURCES",
        6 => "BLOCK_OLD_SOURCES",
        _ => "unknown",
    }
}

fn v4(b: &[u8]) -> String {
    Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()
}

fn v6(b: &[u8]) -> String {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[..16]);
    Ipv6Addr::from(a).to_string()
}

/// The maximum response time of IGMPv3 and the querier's query interval
/// code: values from 128 up are a floating point form (RFC 3376 4.1.1).
pub(crate) fn igmp_code(c: u8) -> u32 {
    if c < 128 {
        u32::from(c)
    } else {
        (u32::from(c & 0x0f) | 0x10) << (((c >> 4) & 7) + 3)
    }
}

pub(crate) fn igmp(d: &mut Decoder, at: usize, end: usize, ip: &IpCtx) {
    if !d.need(at, 8, "IGMP header") {
        d.data_to(at, end);
        return;
    }
    let len = end.saturating_sub(at);
    let (t, code) = (d.data[at], d.data[at + 1]);
    let csum = d.u16(at + 2).unwrap_or(0);
    let group = v4(&d.data[at + 4..at + 8]);
    let (version, name) = match t {
        0x11 if len >= 12 => (3, "Membership Query"),
        0x11 if code == 0 => (1, "Membership Query"),
        0x11 => (2, "Membership Query"),
        0x12 => (1, "Membership Report"),
        0x16 => (2, "Membership Report"),
        0x17 => (2, "Leave Group"),
        0x22 => (3, "Membership Report"),
        _ => (0, "unknown"),
    };
    let header_end = match (t, version) {
        (0x11, 3) => at + 12,
        (0x22, _) => at + 8,
        _ => at + 8,
    };
    d.layer(
        "IGMP",
        format!("Internet Group Management Protocol, v{version} {name}"),
        at..end.min(d.data.len()),
    );
    d.field("Type", format!("0x{t:02x} ({name})"), at..at + 1);
    if t == 0x22 {
        d.field("Reserved", code.to_string(), at + 1..at + 2);
    } else if version == 3 {
        d.field(
            "Max response time",
            format!("{:.1} s", f64::from(igmp_code(code)) / 10.0),
            at + 1..at + 2,
        );
    } else {
        d.field(
            "Max response time",
            format!("{:.1} s", f64::from(code) / 10.0),
            at + 1..at + 2,
        );
    }
    let verdict = (!ip.fragmented && ip.end.is_some())
        .then(|| d.bytes(at..end).map(|b| ones_sum(&[b]) == 0xffff))
        .flatten();
    let note = match verdict {
        Some(true) => "correct",
        Some(false) => {
            d.problem("IGMP checksum is incorrect".into());
            "incorrect"
        }
        None => "not verified",
    };
    d.field("Checksum", format!("0x{csum:04x} [{note}]"), at + 2..at + 4);
    let mut info = format!("v{version} {name}");
    match (t, version) {
        (0x22, _) => {
            let n = usize::from(d.u16(at + 6).unwrap_or(0));
            d.field("Number of group records", n.to_string(), at + 6..at + 8);
            let records = group_records(d, at + 8, end, 4, n);
            info.push_str(&records);
        }
        (0x11, 3) => {
            d.field("Group address", group.clone(), at + 4..at + 8);
            if d.need(at, 12, "IGMPv3 query") {
                let f = d.data[at + 8];
                d.field(
                    "Suppress router processing",
                    ((f >> 3) & 1).to_string(),
                    at + 8..at + 9,
                );
                d.field("QRV", (f & 7).to_string(), at + 8..at + 9);
                d.field(
                    "QQIC",
                    format!("{} s", igmp_code(d.data[at + 9])),
                    at + 9..at + 10,
                );
                let n = usize::from(d.u16(at + 10).unwrap_or(0));
                d.field("Number of sources", n.to_string(), at + 10..at + 12);
                let mut o = header_end;
                for _ in 0..n {
                    if !d.need(o, 4, "IGMPv3 query source") {
                        break;
                    }
                    let s = v4(&d.data[o..o + 4]);
                    d.field("Source", s, o..o + 4);
                    o += 4;
                }
            }
            info.push_str(&if group == "0.0.0.0" {
                ", general".to_string()
            } else {
                format!(" for {group}")
            });
        }
        _ => {
            d.field("Group address", group.clone(), at + 4..at + 8);
            if group != "0.0.0.0" {
                info.push_str(&format!(" {group}"));
            } else if t == 0x11 {
                info.push_str(", general");
            }
        }
    }
    d.summary("IGMP", info);
}

/// IGMPv3 and MLDv2 group records from `at`: `alen` is 4 or 16. Returns a
/// summary such as ` / Join group 239.1.1.1 for any sources`.
fn group_records(d: &mut Decoder, mut at: usize, end: usize, alen: usize, n: usize) -> String {
    let mut info = String::new();
    for _ in 0..n.min(64) {
        if !d.need(at, 4 + alen, "group record") {
            break;
        }
        let t = d.data[at];
        let aux = usize::from(d.data[at + 1]) * 4;
        let ns = usize::from(d.u16(at + 2).unwrap_or(0));
        let addr = if alen == 4 {
            v4(&d.data[at + 4..at + 8])
        } else {
            v6(&d.data[at + 4..at + 20])
        };
        let len = 4 + alen + ns * alen + aux;
        let r = at..(at + len).min(end).min(d.data.len());
        let mut srcs = Vec::new();
        let mut o = at + 4 + alen;
        for _ in 0..ns.min(64) {
            if o + alen > d.data.len() {
                break;
            }
            srcs.push(if alen == 4 {
                v4(&d.data[o..o + 4])
            } else {
                v6(&d.data[o..o + 16])
            });
            o += alen;
        }
        d.field(
            "Group record",
            format!(
                "{addr} {} ({t}){}",
                record_name(t),
                if srcs.is_empty() {
                    String::new()
                } else {
                    format!(", sources {}", srcs.join(" "))
                }
            ),
            r,
        );
        let what = match (t, ns) {
            (2 | 4, 0) => "Join group",
            (1 | 3, 0) => "Leave group",
            (5, _) | (1, _) | (3, _) => "Join group (sources)",
            (6, _) => "Leave sources of group",
            _ => "Group",
        };
        info.push_str(&format!(" / {what} {addr}"));
        at += len;
    }
    info
}

/// MLDv1 (RFC 2710) and MLDv2 (RFC 3810) messages, ICMPv6 types 130 to 132
/// and 143. The ICMPv6 type, code and checksum fields are already there.
pub(crate) fn mld(d: &mut Decoder, t: u8, at: usize, end: usize) {
    let len = end.saturating_sub(at);
    let name = match t {
        130 if len >= 28 => "MLDv2 Query",
        130 => "MLDv1 Query",
        131 => "MLDv1 Report",
        132 => "MLDv1 Done",
        _ => "MLDv2 Report",
    };
    if let Some(l) = d.out.layers.last_mut() {
        l.title = format!("Internet Control Message Protocol v6, Multicast Listener {name}");
        l.range = at..end.min(d.data.len());
    }
    let mut info = name.to_string();
    if t == 143 {
        if !d.need(at, 8, "MLDv2 report") {
            return;
        }
        let n = usize::from(d.u16(at + 6).unwrap_or(0));
        d.field("Number of records", n.to_string(), at + 6..at + 8);
        info.push_str(&group_records(d, at + 8, end, 16, n));
        d.summary("ICMPv6", info);
        return;
    }
    if !d.need(at, 24, "MLD message") {
        d.summary("ICMPv6", info);
        return;
    }
    let delay = d.u16(at + 4).unwrap_or(0);
    d.field(
        "Maximum response delay",
        format!("{delay} ms"),
        at + 4..at + 6,
    );
    let group = v6(&d.data[at + 8..at + 24]);
    d.field("Multicast address", group.clone(), at + 8..at + 24);
    if t == 130 && len >= 28 {
        let f = d.data[at + 24];
        d.field(
            "Suppress router processing",
            ((f >> 3) & 1).to_string(),
            at + 24..at + 25,
        );
        d.field("QRV", (f & 7).to_string(), at + 24..at + 25);
        d.field(
            "QQIC",
            format!("{} s", igmp_code(d.data[at + 25])),
            at + 25..at + 26,
        );
        let n = usize::from(d.u16(at + 26).unwrap_or(0));
        d.field("Number of sources", n.to_string(), at + 26..at + 28);
        let mut o = at + 28;
        for _ in 0..n.min(64) {
            if !d.need(o, 16, "MLDv2 query source") {
                break;
            }
            let s = v6(&d.data[o..o + 16]);
            d.field("Source", s, o..o + 16);
            o += 16;
        }
    }
    if group != "::" {
        info.push_str(&format!(" {group}"));
    } else if t == 130 {
        info.push_str(", general");
    }
    d.summary("ICMPv6", info);
}
