//! The text form of a [`PacketSpec`]: `eth(dst=...)/ipv4(src=...)/udp/dns(q=...)`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::build::*;

impl FromStr for PacketSpec {
    type Err = BuildError;

    fn from_str(s: &str) -> Result<Self, BuildError> {
        let mut p = Parser {
            s: s.as_bytes(),
            text: s,
            at: 0,
        };
        let mut spec = PacketSpec::new();
        loop {
            p.ws();
            let name = p.ident();
            if name.is_empty() {
                return err(format!(
                    "expected a layer name at position {} of '{s}'",
                    p.at + 1
                ));
            }
            let args = p.args(&name)?;
            spec.layers.push(layer(&name, &args)?);
            p.ws();
            match p.peek() {
                None => break,
                Some(b'/') => p.at += 1,
                Some(c) => {
                    return err(format!(
                        "unexpected '{}' at position {} of '{s}'; layers are joined by '/'",
                        c as char,
                        p.at + 1
                    ))
                }
            }
        }
        Ok(spec)
    }
}

struct Parser<'a> {
    s: &'a [u8],
    text: &'a str,
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.at).copied()
    }

    fn ws(&mut self) {
        while self.peek().is_some_and(|c| c.is_ascii_whitespace()) {
            self.at += 1;
        }
    }

    fn ident(&mut self) -> String {
        let start = self.at;
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_')
        {
            self.at += 1;
        }
        self.text[start..self.at].to_ascii_lowercase()
    }

    /// `(key=value, ...)` after a layer name, or nothing.
    fn args(&mut self, layer: &str) -> Result<Vec<(String, String)>, BuildError> {
        self.ws();
        let mut out = Vec::new();
        if self.peek() != Some(b'(') {
            return Ok(out);
        }
        self.at += 1;
        loop {
            self.ws();
            match self.peek() {
                Some(b')') => {
                    self.at += 1;
                    return Ok(out);
                }
                None => return err(format!("{layer}: missing ')'")),
                _ => {}
            }
            let key = self.ident();
            self.ws();
            if key.is_empty() || self.peek() != Some(b'=') {
                return err(format!(
                    "{layer}: expected field=value at position {} of '{}'",
                    self.at + 1,
                    self.text
                ));
            }
            self.at += 1;
            self.ws();
            let value = self.value(layer)?;
            out.push((key, value));
            self.ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b')') => {}
                None => return err(format!("{layer}: missing ')'")),
                _ => return err(format!("{layer}: expected ',' or ')' after a value")),
            }
        }
    }

    fn value(&mut self, layer: &str) -> Result<String, BuildError> {
        if self.peek() == Some(b'"') {
            self.at += 1;
            let mut v = Vec::new();
            loop {
                match self.peek() {
                    None => return err(format!("{layer}: unterminated string")),
                    Some(b'"') => {
                        self.at += 1;
                        return Ok(String::from_utf8_lossy(&v).into_owned());
                    }
                    Some(b'\\') => {
                        self.at += 1;
                        let c = self
                            .peek()
                            .ok_or(BuildError(format!("{layer}: unterminated string")))?;
                        v.extend(match c {
                            b'n' => b"\n".as_slice(),
                            b'r' => b"\r",
                            b't' => b"\t",
                            b'0' => b"\0",
                            b'"' => b"\"",
                            b'\\' => b"\\",
                            _ => return err(format!("{layer}: unknown escape \\{}", c as char)),
                        });
                        self.at += 1;
                    }
                    Some(c) => {
                        v.push(c);
                        self.at += 1;
                    }
                }
            }
        }
        let start = self.at;
        while self.peek().is_some_and(|c| c != b',' && c != b')') {
            self.at += 1;
        }
        Ok(self.text[start..self.at].trim().to_string())
    }
}

/// Parses `v` for field `key` of `layer`, with the layer and field in the error.
fn val<T>(
    layer: &str,
    key: &str,
    v: &str,
    f: impl FnOnce(&str) -> Option<T>,
) -> Result<T, BuildError> {
    f(v).ok_or_else(|| BuildError(format!("{layer}: invalid {key} '{v}'")))
}

fn num<T: TryFrom<u64>>(v: &str) -> Option<T> {
    let n = match v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(&h.replace('_', ""), 16).ok()?,
        None => v.replace('_', "").parse().ok()?,
    };
    T::try_from(n).ok()
}

fn boolean(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn mac(v: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = v.split([':', '-']);
    for b in &mut out {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 2 {
            return None;
        }
        *b = u8::from_str_radix(p, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

fn hex_bytes(v: &str) -> Option<Vec<u8>> {
    let h: String = v
        .trim_start_matches("0x")
        .chars()
        .filter(|c| !matches!(c, ' ' | ':' | '-' | '_'))
        .collect();
    if h.len() % 2 != 0 {
        return None;
    }
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(h.get(i..i + 2)?, 16).ok())
        .collect()
}

fn tcp_flags(v: &str) -> Option<u16> {
    if let Some(n) = num(v) {
        return Some(n);
    }
    let mut f = 0u16;
    for c in v.chars() {
        f |= match c.to_ascii_uppercase() {
            'F' => 0x01,
            'S' => 0x02,
            'R' => 0x04,
            'P' => 0x08,
            'A' => 0x10,
            'U' => 0x20,
            'E' => 0x40,
            'C' => 0x80,
            'N' => 0x100,
            '.' | '|' | ',' | ' ' => 0,
            _ => return None,
        };
    }
    Some(f)
}

fn qtype(v: &str) -> Option<u16> {
    Some(match v.to_ascii_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "HTTPS" => 65,
        "ANY" => 255,
        _ => return num(v),
    })
}

fn unknown<T>(layer: &str, key: &str, fields: &str) -> Result<T, BuildError> {
    err(format!("{layer}: unknown field '{key}' (fields: {fields})"))
}

fn layer(name: &str, args: &[(String, String)]) -> Result<LayerSpec, BuildError> {
    let n = name;
    Ok(match name {
        "eth" | "ether" | "ethernet" => {
            let mut l = Ethernet::default();
            for (k, v) in args {
                match k.as_str() {
                    "src" => l.src = val(n, k, v, mac)?,
                    "dst" => l.dst = val(n, k, v, mac)?,
                    "type" => l.ethertype = Some(val(n, k, v, num)?),
                    "pad" => l.pad = val(n, k, v, boolean)?,
                    _ => return unknown(n, k, "src, dst, type, pad"),
                }
            }
            l.into()
        }
        "vlan" | "dot1q" | "qinq" => {
            let mut l = Vlan::default();
            if name == "qinq" {
                l.tpid = 0x88a8;
            }
            for (k, v) in args {
                match k.as_str() {
                    "id" | "vid" => l.id = val(n, k, v, num)?,
                    "pcp" | "prio" => l.pcp = val(n, k, v, num)?,
                    "dei" | "cfi" => l.dei = val(n, k, v, boolean)?,
                    "tpid" => l.tpid = val(n, k, v, num)?,
                    "type" => l.ethertype = Some(val(n, k, v, num)?),
                    _ => return unknown(n, k, "id, pcp, dei, tpid, type"),
                }
            }
            l.into()
        }
        "arp" => {
            let mut l = Arp::default();
            for (k, v) in args {
                match k.as_str() {
                    "op" => {
                        l.op = val(n, k, v, |v| match v {
                            "request" | "req" => Some(1),
                            "reply" | "rep" => Some(2),
                            _ => num(v),
                        })?
                    }
                    "smac" => l.sender_mac = Some(val(n, k, v, mac)?),
                    "sip" => l.sender_ip = val(n, k, v, |v| v.parse().ok())?,
                    "tmac" => l.target_mac = val(n, k, v, mac)?,
                    "tip" => l.target_ip = val(n, k, v, |v| v.parse().ok())?,
                    _ => return unknown(n, k, "op, smac, sip, tmac, tip"),
                }
            }
            l.into()
        }
        "ipv4" | "ip" | "ip4" => {
            let mut l = Ipv4::default();
            for (k, v) in args {
                match k.as_str() {
                    "src" => l.src = val(n, k, v, |v| v.parse::<Ipv4Addr>().ok())?,
                    "dst" => l.dst = val(n, k, v, |v| v.parse::<Ipv4Addr>().ok())?,
                    "ttl" => l.ttl = val(n, k, v, num)?,
                    "dscp" => l.dscp = val(n, k, v, num)?,
                    "ecn" => l.ecn = val(n, k, v, num)?,
                    "tos" => {
                        let t: u8 = val(n, k, v, num)?;
                        (l.dscp, l.ecn) = (t >> 2, t & 3);
                    }
                    "id" => l.id = val(n, k, v, num)?,
                    "df" => l.df = val(n, k, v, boolean)?,
                    "mf" => l.mf = val(n, k, v, boolean)?,
                    "frag" => l.frag_offset = val(n, k, v, num)?,
                    "proto" => l.proto = Some(val(n, k, v, num)?),
                    "len" => l.len = Some(val(n, k, v, num)?),
                    "chksum" | "checksum" => l.checksum = Some(val(n, k, v, num)?),
                    _ => {
                        return unknown(
                            n,
                            k,
                            "src, dst, ttl, dscp, ecn, tos, id, df, mf, frag, proto, len, chksum",
                        )
                    }
                }
            }
            l.into()
        }
        "ipv6" | "ip6" => {
            let mut l = Ipv6::default();
            for (k, v) in args {
                match k.as_str() {
                    "src" => l.src = val(n, k, v, |v| v.parse::<Ipv6Addr>().ok())?,
                    "dst" => l.dst = val(n, k, v, |v| v.parse::<Ipv6Addr>().ok())?,
                    "hlim" | "ttl" => l.hop_limit = val(n, k, v, num)?,
                    "tc" => l.traffic_class = val(n, k, v, num)?,
                    "flow" => l.flow_label = val(n, k, v, num)?,
                    "nh" => l.next_header = Some(val(n, k, v, num)?),
                    "plen" | "len" => l.payload_len = Some(val(n, k, v, num)?),
                    _ => return unknown(n, k, "src, dst, hlim, tc, flow, nh, plen"),
                }
            }
            l.into()
        }
        "tcp" => {
            let mut l = Tcp::default();
            for (k, v) in args {
                match k.as_str() {
                    "sport" => l.sport = val(n, k, v, num)?,
                    "dport" => l.dport = val(n, k, v, num)?,
                    "seq" => l.seq = val(n, k, v, num)?,
                    "ack" => l.ack = val(n, k, v, num)?,
                    "flags" => l.flags = val(n, k, v, tcp_flags)?,
                    "win" | "window" => l.window = val(n, k, v, num)?,
                    "urg" => l.urgent = val(n, k, v, num)?,
                    "mss" => l.mss = Some(val(n, k, v, num)?),
                    "wscale" => l.wscale = Some(val(n, k, v, num)?),
                    "sackok" => l.sack_perm = val(n, k, v, boolean)?,
                    "chksum" | "checksum" => l.checksum = Some(val(n, k, v, num)?),
                    _ => {
                        return unknown(
                            n,
                            k,
                            "sport, dport, seq, ack, flags, win, urg, mss, wscale, sackok, chksum",
                        )
                    }
                }
            }
            l.into()
        }
        "udp" => {
            let mut l = Udp::default();
            for (k, v) in args {
                match k.as_str() {
                    "sport" => l.sport = Some(val(n, k, v, num)?),
                    "dport" => l.dport = Some(val(n, k, v, num)?),
                    "len" => l.len = Some(val(n, k, v, num)?),
                    "chksum" | "checksum" => l.checksum = Some(val(n, k, v, num)?),
                    _ => return unknown(n, k, "sport, dport, len, chksum"),
                }
            }
            l.into()
        }
        "icmp" | "icmpv6" | "icmp6" => {
            let mut l = Icmp::default();
            for (k, v) in args {
                match k.as_str() {
                    "type" => l.icmp_type = Some(val(n, k, v, num)?),
                    "code" => l.code = val(n, k, v, num)?,
                    "id" => l.id = val(n, k, v, num)?,
                    "seq" => l.seq = val(n, k, v, num)?,
                    "chksum" | "checksum" => l.checksum = Some(val(n, k, v, num)?),
                    _ => return unknown(n, k, "type, code, id, seq, chksum"),
                }
            }
            l.into()
        }
        "dns" => {
            let mut l = Dns::default();
            for (k, v) in args {
                match k.as_str() {
                    "id" => l.id = val(n, k, v, num)?,
                    "q" | "qname" => l.questions.push(v.clone()),
                    "qtype" => l.qtype = val(n, k, v, qtype)?,
                    "qr" | "response" => l.response = val(n, k, v, boolean)?,
                    "a" | "answer" => l.answers.push(val(n, k, v, |v| v.parse::<IpAddr>().ok())?),
                    "ttl" => l.ttl = val(n, k, v, num)?,
                    "rd" => l.rd = val(n, k, v, boolean)?,
                    "ra" => l.ra = val(n, k, v, boolean)?,
                    "aa" => l.aa = val(n, k, v, boolean)?,
                    "tc" => l.tc = val(n, k, v, boolean)?,
                    "opcode" => l.opcode = val(n, k, v, num)?,
                    "rcode" => l.rcode = val(n, k, v, num)?,
                    _ => {
                        return unknown(
                            n,
                            k,
                            "id, q, qtype, qr, a, ttl, rd, ra, aa, tc, opcode, rcode",
                        )
                    }
                }
            }
            // An answer makes it a response unless qr says otherwise.
            if !l.answers.is_empty() && !args.iter().any(|(k, _)| k == "qr" || k == "response") {
                l.response = true;
            }
            l.into()
        }
        "raw" | "data" | "payload" => {
            let mut bytes: Option<Vec<u8>> = None;
            let mut len: Option<usize> = None;
            let mut fill = 0u8;
            for (k, v) in args {
                match k.as_str() {
                    "hex" => bytes = Some(val(n, k, v, hex_bytes)?),
                    "text" => bytes = Some(v.as_bytes().to_vec()),
                    "len" => len = Some(val(n, k, v, num)?),
                    "fill" => fill = val(n, k, v, num)?,
                    _ => return unknown(n, k, "hex, text, len, fill"),
                }
            }
            let mut b = bytes.unwrap_or_default();
            if let Some(len) = len {
                if len > 65535 {
                    return err(format!("{n}: len {len} is more than 65535"));
                }
                b.resize(len, fill);
            }
            LayerSpec::Raw(b)
        }
        _ => {
            return err(format!(
                "unknown layer '{name}' (layers: eth, vlan, qinq, arp, ipv4, ipv6, tcp, udp, icmp, dns, raw)"
            ))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fields_and_quotes() {
        let s: PacketSpec =
            " eth ( dst = ff:ff:ff:ff:ff:ff ) / ipv4(ttl=0x20, df=yes) / udp / raw(text=\"a, b) \\\"c\\\"\")"
                .parse()
                .unwrap();
        assert_eq!(s.layers.len(), 4);
        assert!(matches!(&s.layers[0], LayerSpec::Ethernet(e) if e.dst == [0xff; 6]));
        assert!(matches!(&s.layers[1], LayerSpec::Ipv4(i) if i.ttl == 32 && i.df));
        assert_eq!(s.layers[3], LayerSpec::Raw(b"a, b) \"c\"".to_vec()));
    }

    #[test]
    fn raw_forms() {
        let r = |s: &str| match &s.parse::<PacketSpec>().unwrap().layers[1] {
            LayerSpec::Raw(b) => b.clone(),
            _ => unreachable!(),
        };
        assert_eq!(r("eth/raw(hex=de:ad be-ef)"), [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(r("eth/raw(len=3,fill=0xaa)"), [0xaa; 3]);
        assert_eq!(r("eth/raw(text=hi,len=4)"), *b"hi\0\0");
    }

    #[test]
    fn helpful_errors() {
        let e = |s: &str| s.parse::<PacketSpec>().unwrap_err().0;
        assert!(e("ipv4(tll=3)").contains("unknown field 'tll'"));
        assert!(e("ipv4(ttl=300)").contains("invalid ttl '300'"));
        assert!(e("eth/foo").contains("unknown layer 'foo'"));
        assert!(e("eth(src=1:2").contains("missing ')'"));
        assert!(e("eth ipv4").contains("joined by '/'"));
        assert!(e("eth/").contains("expected a layer name"));
    }
}
