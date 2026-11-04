//! From bytes back to the text form: turn a captured packet into layers that
//! can be edited and built again.
//!
//! [`import`] reads the headers it knows (Ethernet, VLAN tags, ARP, IPv4,
//! IPv6, TCP, UDP, ICMP and ICMPv6) into [`RawLayer`]s with their field
//! values, and keeps the rest of the packet as a `raw(hex=...)` payload.
//! Lengths and checksums are left out, so the builder computes them again
//! after an edit; a packet whose checksums were right builds back to the
//! same bytes. Whatever cannot be carried over (IPv4 options, TCP options
//! other than MSS, window scale and SACK permitted, a non-zero Ethernet
//! trailer) is listed in [`Imported::notes`].

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{RawLayer, LINKTYPE_ETHERNET, LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_RAW};

/// The layers of an imported packet, and what changed on the way.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Imported {
    pub layers: Vec<RawLayer>,
    /// Things the layers do not reproduce exactly.
    pub notes: Vec<String>,
}

/// Turns one packet of a capture with `linktype` into editable layers.
/// Returns `None` for link types the builder cannot write (only Ethernet and
/// raw IP).
pub fn import(linktype: u32, data: &[u8]) -> Option<Imported> {
    let mut im = Importer {
        data,
        out: Imported::default(),
        end: data.len(),
    };
    match linktype {
        LINKTYPE_ETHERNET => im.ethernet(),
        LINKTYPE_RAW | LINKTYPE_IPV4 | LINKTYPE_IPV6 => match data.first().map(|b| b >> 4) {
            Some(4) => im.ipv4(0),
            Some(6) => im.ipv6(0),
            _ => im.raw(0),
        },
        _ => return None,
    }
    Some(im.out)
}

struct Importer<'a> {
    data: &'a [u8],
    out: Imported,
    /// End of the bytes that belong to the packet (before Ethernet padding).
    end: usize,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn mac(b: &[u8]) -> String {
    b.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

impl Importer<'_> {
    fn u16(&self, at: usize) -> u16 {
        u16::from_be_bytes([self.data[at], self.data[at + 1]])
    }

    fn u32(&self, at: usize) -> u32 {
        u32::from_be_bytes([
            self.data[at],
            self.data[at + 1],
            self.data[at + 2],
            self.data[at + 3],
        ])
    }

    fn has(&self, at: usize, len: usize) -> bool {
        at + len <= self.end
    }

    fn push(&mut self, name: &str, args: Vec<(&str, String)>) -> usize {
        self.out.layers.push(RawLayer {
            name: name.into(),
            args: args.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        });
        self.out.layers.len() - 1
    }

    /// Sets a key on a layer already pushed (an EtherType when what follows
    /// is kept as raw bytes, so the builder cannot infer it).
    fn set(&mut self, layer: usize, key: &str, value: String) {
        self.out.layers[layer].args.push((key.into(), value));
    }

    /// The rest of the packet as a payload layer: as text when it is
    /// printable ASCII (an HTTP request, say), else as hex.
    fn raw(&mut self, at: usize) {
        if at < self.end {
            let b = &self.data[at..self.end];
            let text = b
                .iter()
                .all(|&c| c.is_ascii_graphic() || matches!(c, b' ' | b'\r' | b'\n' | b'\t'));
            if text && b.iter().any(|c| c.is_ascii_alphanumeric()) {
                let t = String::from_utf8_lossy(b).into_owned();
                self.push("raw", vec![("text", t)]);
            } else {
                self.push("raw", vec![("hex", hex(b))]);
            }
        }
    }

    fn ethernet(&mut self) {
        if !self.has(0, 14) {
            self.out
                .notes
                .push("shorter than an Ethernet header".into());
            self.raw_all();
            return;
        }
        let eth = self.push(
            "eth",
            vec![
                ("dst", mac(&self.data[0..6])),
                ("src", mac(&self.data[6..12])),
            ],
        );
        self.after_ethertype(eth, 12);
    }

    /// Imports the frame as one payload (frames the builder can't start).
    fn raw_all(&mut self) {
        self.out.layers.clear();
        self.out.layers.push(RawLayer {
            name: "raw".into(),
            args: vec![("hex".into(), hex(self.data))],
        });
    }

    /// The EtherType at `at` of `layer`, and what follows it.
    fn after_ethertype(&mut self, layer: usize, at: usize) {
        let ty = self.u16(at);
        let next = at + 2;
        match ty {
            0x8100 | 0x88a8 if self.has(next, 4) => {
                let tci = self.u16(next);
                let name = if ty == 0x88a8 { "qinq" } else { "vlan" };
                let mut args = vec![("id", (tci & 0x0fff).to_string())];
                if tci >> 13 != 0 {
                    args.push(("pcp", (tci >> 13).to_string()));
                }
                if tci & 0x1000 != 0 {
                    args.push(("dei", "1".into()));
                }
                let v = self.push(name, args);
                // The TCI is followed by the inner EtherType.
                self.after_ethertype(v, next + 2);
            }
            0x0800 if self.data.get(next).is_some_and(|b| b >> 4 == 4) => {
                if self.has(next, 20) {
                    self.ethernet_padding(next, self.u16(next + 2) as usize);
                }
                self.ipv4(next)
            }
            0x86dd if self.data.get(next).is_some_and(|b| b >> 4 == 6) => {
                if self.has(next, 40) {
                    self.ethernet_padding(next, 40 + self.u16(next + 4) as usize);
                }
                self.ipv6(next)
            }
            0x0806 if self.has(next, 28) && self.u16(next) == 1 && self.u16(next + 2) == 0x0800 => {
                self.ethernet_padding(next, 28);
                self.arp(next)
            }
            _ => {
                self.set(layer, "type", format!("0x{ty:04x}"));
                self.no_pad();
                self.raw(next);
            }
        }
    }

    /// The builder pads Ethernet frames with zeros to 60 bytes; turn that off
    /// when the frame was not padded like that.
    fn ethernet_padding(&mut self, l3: usize, len: usize) {
        let packet_end = (l3 + len).min(self.data.len());
        let trailer = &self.data[packet_end..];
        if trailer.is_empty() {
            if self.data.len() < 60 {
                self.no_pad();
            }
            return;
        }
        if self.data.len() != 60.max(packet_end) || trailer.iter().any(|&b| b != 0) {
            self.out.notes.push(format!(
                "{} trailing bytes after the packet are left out",
                trailer.len()
            ));
            self.no_pad();
        }
        self.end = packet_end;
    }

    fn no_pad(&mut self) {
        if self.data.len() < 60 {
            if let Some(eth) = self.out.layers.iter_mut().find(|l| l.name == "eth") {
                if !eth.args.iter().any(|(k, _)| k == "pad") {
                    eth.args.push(("pad".into(), "0".into()));
                }
            }
        }
    }

    fn arp(&mut self, at: usize) {
        let d = &self.data[at..];
        let op = u16::from_be_bytes([d[6], d[7]]);
        let mut args = vec![];
        if op != 1 {
            args.push(("op", op.to_string()));
        }
        let eth_src = self
            .out
            .layers
            .first()
            .and_then(|l| l.args.iter().find(|(k, _)| k == "src"))
            .map(|(_, v)| v.clone());
        let smac = mac(&d[8..14]);
        if Some(&smac) != eth_src.as_ref() {
            args.push(("smac", smac));
        }
        args.push(("sip", Ipv4Addr::new(d[14], d[15], d[16], d[17]).to_string()));
        args.push(("tmac", mac(&d[18..24])));
        args.push(("tip", Ipv4Addr::new(d[24], d[25], d[26], d[27]).to_string()));
        self.push("arp", args);
        if self.end > at + 28 {
            self.out.notes.push(format!(
                "{} bytes after the ARP header are left out",
                self.end - at - 28
            ));
        }
    }

    fn ipv4(&mut self, at: usize) {
        if !self.has(at, 20) {
            return self.raw(at);
        }
        let d = &self.data[at..];
        let ihl = (d[0] & 0x0f) as usize * 4;
        let total = self.u16(at + 2) as usize;
        if ihl != 20 || total < 20 || !self.has(at, total) {
            if ihl > 20 {
                self.out
                    .notes
                    .push("IPv4 options are not editable: the header is kept as bytes".into());
            }
            self.mark_raw_next(0x0800);
            return self.raw(at);
        }
        self.end = at + total;
        let flags = self.u16(at + 6);
        let mut args = vec![
            ("src", Ipv4Addr::new(d[12], d[13], d[14], d[15]).to_string()),
            ("dst", Ipv4Addr::new(d[16], d[17], d[18], d[19]).to_string()),
        ];
        let tos = d[1];
        if tos >> 2 != 0 {
            args.push(("dscp", (tos >> 2).to_string()));
        }
        if tos & 3 != 0 {
            args.push(("ecn", (tos & 3).to_string()));
        }
        let id = self.u16(at + 4);
        if id != 1 {
            args.push(("id", id.to_string()));
        }
        if flags & 0x4000 != 0 {
            args.push(("df", "1".into()));
        }
        if flags & 0x2000 != 0 {
            args.push(("mf", "1".into()));
        }
        if flags & 0x1fff != 0 {
            // The builder takes the offset in bytes.
            args.push(("frag", ((flags & 0x1fff) * 8).to_string()));
        }
        if d[8] != 64 {
            args.push(("ttl", d[8].to_string()));
        }
        let proto = d[9];
        let l = self.push("ipv4", args);
        // Fragments after the first carry no transport header.
        let first = flags & 0x1fff == 0;
        self.transport(l, proto, at + 20, first);
    }

    fn ipv6(&mut self, at: usize) {
        if !self.has(at, 40) {
            return self.raw(at);
        }
        let d = &self.data[at..];
        let plen = self.u16(at + 4) as usize;
        if !self.has(at, 40 + plen) {
            self.mark_raw_next(0x86dd);
            return self.raw(at);
        }
        self.end = at + 40 + plen;
        let vtf = self.u32(at);
        let mut src = [0u8; 16];
        src.copy_from_slice(&d[8..24]);
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&d[24..40]);
        let mut args = vec![
            ("src", Ipv6Addr::from(src).to_string()),
            ("dst", Ipv6Addr::from(dst).to_string()),
        ];
        let tc = (vtf >> 20) & 0xff;
        if tc != 0 {
            args.push(("tc", tc.to_string()));
        }
        if vtf & 0xfffff != 0 {
            args.push(("flow", (vtf & 0xfffff).to_string()));
        }
        if d[7] != 64 {
            args.push(("hlim", d[7].to_string()));
        }
        let nh = d[6];
        let l = self.push("ipv6", args);
        self.transport(l, nh, at + 40, true);
    }

    /// Marks the layer before a raw payload with the EtherType the builder
    /// could not infer from it.
    fn mark_raw_next(&mut self, ethertype: u16) {
        if let Some(last) = self.out.layers.last_mut() {
            if matches!(last.name.as_str(), "eth" | "vlan" | "qinq") {
                last.args
                    .push(("type".into(), format!("0x{ethertype:04x}")));
            }
        }
        self.no_pad();
    }

    fn transport(&mut self, ip: usize, proto: u8, at: usize, first_fragment: bool) {
        let keep_proto = |me: &mut Self| {
            let key = if me.out.layers[ip].name == "ipv4" {
                "proto"
            } else {
                "nh"
            };
            me.set(ip, key, proto.to_string());
        };
        if !first_fragment {
            keep_proto(self);
            return self.raw(at);
        }
        match proto {
            6 => self.tcp(ip, at),
            17 if self.has(at, 8) => {
                let sport = self.u16(at);
                let dport = self.u16(at + 2);
                let len = self.u16(at + 4) as usize;
                if len < 8 || !self.has(at, len) {
                    keep_proto(self);
                    return self.raw(at);
                }
                self.end = at + len;
                if self.u16(at + 6) == 0 && self.out.layers[ip].name == "ipv4" {
                    self.push(
                        "udp",
                        vec![
                            ("sport", sport.to_string()),
                            ("dport", dport.to_string()),
                            ("chksum", "0".into()),
                        ],
                    );
                } else {
                    self.push(
                        "udp",
                        vec![("sport", sport.to_string()), ("dport", dport.to_string())],
                    );
                }
                self.raw(at + 8);
            }
            // ICMPv6 other than echo (neighbor discovery and the rest) is
            // kept as captured bytes.
            1 | 58 if self.has(at, 8) && (proto == 1 || matches!(self.data[at], 128 | 129)) => {
                let ty = self.data[at];
                let code = self.data[at + 1];
                let echo = matches!((proto, ty), (1, 0 | 8) | (58, 128 | 129));
                let default_ty = if proto == 1 { 8 } else { 128 };
                let mut args = vec![];
                if ty != default_ty {
                    args.push(("type", ty.to_string()));
                }
                if code != 0 {
                    args.push(("code", code.to_string()));
                }
                if echo {
                    args.push(("id", self.u16(at + 4).to_string()));
                    args.push(("seq", self.u16(at + 6).to_string()));
                    self.push("icmp", args);
                    self.raw(at + 8);
                } else {
                    // The builder writes id and seq into the 4 bytes after
                    // the checksum; for other types they are just those bytes.
                    let rest = self.u32(at + 4);
                    if rest != 0 {
                        args.push(("id", (rest >> 16).to_string()));
                        args.push(("seq", (rest & 0xffff).to_string()));
                    }
                    self.push("icmp", args);
                    self.raw(at + 8);
                }
            }
            _ => {
                keep_proto(self);
                self.raw(at)
            }
        }
    }

    fn tcp(&mut self, ip: usize, at: usize) {
        if !self.has(at, 20) {
            let key = if self.out.layers[ip].name == "ipv4" {
                "proto"
            } else {
                "nh"
            };
            self.set(ip, key, "6".into());
            return self.raw(at);
        }
        let off = (self.data[at + 12] >> 4) as usize * 4;
        let flags = self.u16(at + 12) & 0x01ff;
        let mut args = vec![
            ("sport", self.u16(at).to_string()),
            ("dport", self.u16(at + 2).to_string()),
            ("seq", self.u32(at + 4).to_string()),
            ("ack", self.u32(at + 8).to_string()),
            ("flags", tcp_flags(flags)),
            ("win", self.u16(at + 14).to_string()),
        ];
        let urg = self.u16(at + 18);
        if urg != 0 {
            args.push(("urg", urg.to_string()));
        }
        if off > 20 && self.has(at, off) {
            let (opts, dropped) = tcp_options(&self.data[at + 20..at + off]);
            args.extend(opts);
            if dropped {
                self.out.notes.push(
                    "TCP options other than MSS, window scale and SACK permitted are left out"
                        .into(),
                );
            }
        }
        self.push("tcp", args);
        self.raw(at + off.max(20));
    }
}

fn tcp_flags(f: u16) -> String {
    let s: String = [
        (0x02, 'S'),
        (0x10, 'A'),
        (0x08, 'P'),
        (0x01, 'F'),
        (0x04, 'R'),
        (0x20, 'U'),
        (0x40, 'E'),
        (0x80, 'C'),
        (0x100, 'N'),
    ]
    .iter()
    .filter(|(b, _)| f & b != 0)
    .map(|(_, c)| *c)
    .collect();
    if s.is_empty() {
        "0".into()
    } else {
        s
    }
}

/// MSS, window scale and SACK permitted, and whether anything else was there.
fn tcp_options(mut o: &[u8]) -> (Vec<(&'static str, String)>, bool) {
    let mut out = Vec::new();
    let mut dropped = false;
    while let Some(&kind) = o.first() {
        match kind {
            0 => break,
            1 => {
                o = &o[1..];
                continue;
            }
            _ => {}
        }
        let len = o.get(1).copied().unwrap_or(0) as usize;
        if len < 2 || len > o.len() {
            dropped = true;
            break;
        }
        match (kind, len) {
            (2, 4) => out.push(("mss", u16::from_be_bytes([o[2], o[3]]).to_string())),
            (3, 3) => out.push(("wscale", o[2].to_string())),
            (4, 2) => out.push(("sackok", "1".into())),
            _ => dropped = true,
        }
        o = &o[len..];
    }
    (out, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{format_layers, PacketSpec};

    fn round_trip(spec: &str) -> Imported {
        let p: PacketSpec = spec.parse().unwrap();
        let bytes = p.build().unwrap();
        let im = import(p.linktype().unwrap(), &bytes).unwrap();
        let text = format_layers(&im.layers);
        let again: PacketSpec = text
            .parse()
            .unwrap_or_else(|e: crate::BuildError| panic!("{text}: {}", e.0));
        assert_eq!(again.build().unwrap(), bytes, "{spec}\n -> {text}");
        im
    }

    #[test]
    fn built_packets_import_to_the_same_bytes() {
        for spec in [
            "eth/ipv4/udp/raw(len=18)",
            "eth(dst=02:00:00:00:00:01)/vlan(id=10,pcp=5)/ipv4(src=192.168.10.100,dst=192.168.20.50,ttl=3,df=1,dscp=46)/tcp(sport=40000,dport=80,flags=S,mss=1460,wscale=7,sackok=1)",
            "eth/qinq(id=100)/vlan(id=10)/ipv4/icmp(id=1,seq=2)/raw(len=56)",
            "eth/ipv6(src=2001:db8::10,flow=5,hlim=1)/udp(sport=1000,dport=2000)/raw(text=\"hello\")",
            "eth/ipv6/icmp(id=7,seq=9)",
            "eth(dst=ff:ff:ff:ff:ff:ff)/arp(sip=192.168.10.100,tip=192.168.10.1)",
            "eth/ipv4/udp/dns(id=0x1234,q=example.com)",
            "eth/ipv4(src=10.0.0.1,dst=10.0.0.2,df=1)/tcp(sport=40000,dport=80,seq=1001,ack=1,flags=PA)/raw(text=\"GET / HTTP/1.1\\r\\n\\r\\n\")",
            "ipv4/udp/raw(len=4)",
            "eth(type=0x88b5)/raw(len=46)",
            "eth/ipv4(mf=1,id=7)/udp/raw(len=100)",
            "eth/ipv4(frag=1480,id=7)/raw(len=40)",
        ] {
            let im = round_trip(spec);
            assert!(im.notes.is_empty(), "{spec}: {:?}", im.notes);
        }
    }

    #[test]
    fn lengths_and_checksums_are_left_to_the_builder() {
        let p: PacketSpec = "eth/ipv4/udp(chksum=0xdead)/raw(len=4)".parse().unwrap();
        let im = import(LINKTYPE_ETHERNET, &p.build().unwrap()).unwrap();
        let text = format_layers(&im.layers);
        // The wrong checksum is not kept: an edit must not keep it either.
        assert!(!text.contains("chksum"), "{text}");
        assert!(!text.contains("len="), "{text}");
    }

    #[test]
    fn non_ip_link_types_are_refused() {
        assert!(import(crate::LINKTYPE_LINUX_SLL, &[0; 40]).is_none());
    }

    #[test]
    fn truncated_frames_become_payload() {
        let im = import(LINKTYPE_ETHERNET, &[1, 2, 3]).unwrap();
        assert_eq!(format_layers(&im.layers), "raw(hex=010203)");
    }
}
