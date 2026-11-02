//! DNS, mDNS and LLMNR messages.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{hex16, Decoder};

fn type_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        41 => "OPT".into(),
        43 => "DS".into(),
        46 => "RRSIG".into(),
        48 => "DNSKEY".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        t => format!("TYPE{t}"),
    }
}

fn rcode_name(r: u16) -> &'static str {
    match r {
        0 => "No error",
        1 => "Format error",
        2 => "Server failure",
        3 => "No such name",
        4 => "Not implemented",
        5 => "Refused",
        _ => "Other error",
    }
}

/// Reads a possibly compressed name at `at` inside the message starting at `base`.
/// Returns the name and the offset just after it in the original position.
fn name(d: &Decoder, base: usize, end: usize, mut at: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut after = None;
    for _ in 0..128 {
        let len = *d.data.get(at).filter(|_| at < end)?;
        match len {
            0 => {
                let next = after.unwrap_or(at + 1);
                let n = if labels.is_empty() {
                    "<Root>".to_string()
                } else {
                    labels.join(".")
                };
                return Some((n, next));
            }
            l if l & 0xc0 == 0xc0 => {
                let ptr = usize::from(d.u16(at)? & 0x3fff);
                after.get_or_insert(at + 2);
                at = base + ptr;
            }
            l if l & 0xc0 == 0 => {
                let l = usize::from(l);
                let label = d
                    .data
                    .get(at + 1..at + 1 + l)
                    .filter(|_| at + 1 + l <= end)?;
                labels.push(
                    label
                        .iter()
                        .map(|&c| if c.is_ascii_graphic() { c as char } else { '?' })
                        .collect(),
                );
                at += 1 + l;
            }
            _ => return None,
        }
    }
    None
}

/// Decodes a DNS message in `at..end`. Returns false (and adds nothing) when it
/// does not look like DNS.
pub(crate) fn dns(d: &mut Decoder, at: usize, end: usize, mdns: bool) -> bool {
    let end = end.min(d.data.len());
    if at + 12 > end {
        return false;
    }
    let id = d.u16(at).unwrap_or(0);
    let flags = d.u16(at + 2).unwrap_or(0);
    let counts: Vec<u16> = (0..4).map(|i| d.u16(at + 4 + 2 * i).unwrap_or(0)).collect();
    let (qd, an, ns, ar) = (counts[0], counts[1], counts[2], counts[3]);
    if qd > 64 || an > 256 || ns > 256 || ar > 256 {
        return false;
    }
    let response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0xf;
    let rcode = flags & 0xf;
    let proto = if mdns { "mDNS" } else { "DNS" };
    d.layer(
        proto,
        format!(
            "Domain Name System ({})",
            if response { "response" } else { "query" }
        ),
        at..end,
    );
    d.field("Transaction ID", hex16(id), at..at + 2);
    let mut fl = vec![if response { "response" } else { "query" }];
    if flags & 0x0400 != 0 {
        fl.push("authoritative");
    }
    if flags & 0x0200 != 0 {
        fl.push("truncated");
    }
    if flags & 0x0100 != 0 {
        fl.push("recursion desired");
    }
    if flags & 0x0080 != 0 {
        fl.push("recursion available");
    }
    d.field(
        "Flags",
        format!(
            "{} ({}, opcode {opcode}, {})",
            hex16(flags),
            fl.join(", "),
            rcode_name(rcode)
        ),
        at + 2..at + 4,
    );
    d.field("Questions", qd.to_string(), at + 4..at + 6);
    d.field("Answer RRs", an.to_string(), at + 6..at + 8);
    d.field("Authority RRs", ns.to_string(), at + 8..at + 10);
    d.field("Additional RRs", ar.to_string(), at + 10..at + 12);

    let mut o = at + 12;
    let mut info_q = Vec::new();
    let mut info_a = Vec::new();
    let mut broken = false;
    for i in 0..qd {
        let Some((n, next)) = name(d, at, end, o) else {
            broken = true;
            break;
        };
        let (Some(t), Some(_c)) = (d.u16(next), d.u16(next + 2)) else {
            broken = true;
            break;
        };
        d.field(
            &format!("Query {}", i + 1),
            format!("{n} {}", type_name(t)),
            o..next + 4,
        );
        info_q.push(format!("{} {n}", type_name(t)));
        o = next + 4;
    }
    let sections = [("Answer", an), ("Authority", ns), ("Additional", ar)];
    'outer: for (section, count) in sections {
        for i in 0..count {
            if broken {
                break 'outer;
            }
            let Some((n, next)) = name(d, at, end, o) else {
                broken = true;
                break 'outer;
            };
            let (Some(t), Some(ttl), Some(rdlen)) = (d.u16(next), d.u32(next + 4), d.u16(next + 8))
            else {
                broken = true;
                break 'outer;
            };
            let rd = next + 10;
            let rd_end = rd + usize::from(rdlen);
            if rd_end > end {
                broken = true;
                break 'outer;
            }
            let rdata = &d.data[rd..rd_end];
            let value = match (t, rdata.len()) {
                (1, 4) => Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string(),
                (28, 16) => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(rdata);
                    Ipv6Addr::from(a).to_string()
                }
                (2 | 5 | 12, _) => name(d, at, end, rd).map_or("?".into(), |(n, _)| n),
                (15, l) if l > 2 => name(d, at, end, rd + 2).map_or("?".into(), |(n, _)| n),
                (41, _) => format!("EDNS0, UDP size {}", d.u16(next + 2).unwrap_or(0)),
                (_, l) => format!("{l} bytes"),
            };
            let line = if t == 41 {
                value.clone()
            } else {
                format!("{n} {} {value} (TTL {ttl})", type_name(t))
            };
            d.field(&format!("{section} {}", i + 1), line, o..rd_end);
            if section == "Answer" {
                info_a.push(format!("{} {value}", type_name(t)));
            }
            o = rd_end;
        }
    }
    if broken {
        d.problem(format!("{proto} message is malformed or truncated"));
    }

    let mut info = format!(
        "Standard query{} {}",
        if response { " response" } else { "" },
        hex16(id)
    );
    if opcode != 0 {
        info = format!("{proto} opcode {opcode} {}", hex16(id));
    }
    if response && rcode != 0 {
        info.push_str(&format!(" {}", rcode_name(rcode)));
    }
    for q in &info_q {
        info.push(' ');
        info.push_str(q);
    }
    for a in &info_a {
        info.push(' ');
        info.push_str(a);
    }
    d.summary(proto, info);
    true
}
