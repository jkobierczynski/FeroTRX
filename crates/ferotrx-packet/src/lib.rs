//! Packet decoding and building for FeroTRX.
//!
//! [`decode`] turns the bytes of one captured packet into a list of [`Layer`]s,
//! each with named [`Field`]s and the byte range every field came from, plus a
//! one-line summary (source, destination, protocol, info) like a capture viewer
//! shows. Checksums are verified where the capture holds enough of the packet.
//!
//! Decoded protocols: Ethernet II, 802.3/LLC, 802.1Q/802.1ad VLAN tags, Linux
//! cooked capture (SLL), ARP, IPv4, IPv6 with extension headers, TCP, UDP,
//! ICMP, ICMPv6 and DNS (also mDNS and LLMNR). Anything else is shown as data.
//!
//! The decoder never panics on malformed or truncated input; it stops at the
//! first layer it cannot read and records a problem instead.
//!
//! [`PacketSpec`] goes the other way: describe a packet layer by layer
//! (Ethernet, VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, raw bytes) in code or
//! as text like `eth/vlan(id=10)/ipv4(dst=10.0.0.2)/udp/dns(q=example.com)`,
//! and build its bytes with lengths and checksums filled in.
//!
//! ```
//! let frame = [
//!     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 1, 0x08, 0x06, // Ethernet, ARP
//!     0, 1, 0x08, 0, 6, 4, 0, 1, // ARP request
//!     0x02, 0, 0, 0, 0, 1, 192, 168, 1, 10, // sender
//!     0, 0, 0, 0, 0, 0, 192, 168, 1, 1, // target
//! ];
//! let d = ferotrx_packet::decode(ferotrx_packet::LINKTYPE_ETHERNET, &frame);
//! assert_eq!(d.protocol, "ARP");
//! assert_eq!(d.info, "Who has 192.168.1.1? Tell 192.168.1.10");
//! assert_eq!(d.layers.len(), 2);
//! ```

use std::fmt::Write as _;
use std::ops::Range;

mod build;
mod dns;
mod l2;
mod l3;
mod l4;
mod spec;

pub use build::{
    Arp, BuildError, Dns, Ethernet, Icmp, Ipv4, Ipv6, LayerSpec, PacketSpec, Tcp, Udp, Vlan,
    ETHERTYPE_EXPERIMENTAL, ETH_MIN_FRAME, IPPROTO_EXPERIMENTAL,
};

/// Ethernet (DLT_EN10MB).
pub const LINKTYPE_ETHERNET: u32 = 1;
/// Raw IPv4 or IPv6, version taken from the first nibble.
pub const LINKTYPE_RAW: u32 = 101;
/// Linux cooked capture (`tcpdump -i any`).
pub const LINKTYPE_LINUX_SLL: u32 = 113;
/// Raw IPv4.
pub const LINKTYPE_IPV4: u32 = 228;
/// Raw IPv6.
pub const LINKTYPE_IPV6: u32 = 229;

/// One named value of a layer, and the bytes it was read from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub value: String,
    /// Byte range in the packet.
    pub range: Range<usize>,
}

/// One protocol header (or payload) of a packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer {
    /// Short protocol name, such as `IPv4` or `TCP`.
    pub protocol: &'static str,
    /// One-line description, such as `Internet Protocol Version 4, Src: 10.0.0.1, Dst: 10.0.0.2`.
    pub title: String,
    /// Byte range of the header in the packet.
    pub range: Range<usize>,
    pub fields: Vec<Field>,
}

/// A decoded packet.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Decoded {
    pub layers: Vec<Layer>,
    /// Highest level source address found (IP, else MAC).
    pub source: String,
    /// Highest level destination address found (IP, else MAC).
    pub destination: String,
    /// Highest level protocol decoded.
    pub protocol: &'static str,
    /// Summary of the highest level protocol, like a capture viewer's Info column.
    pub info: String,
    /// Truncated headers, bad checksums and other things worth a look.
    pub problems: Vec<String>,
    /// Length of the packet in bytes.
    pub len: usize,
}

impl Decoded {
    /// The layer with this protocol name, if the packet has one.
    pub fn layer(&self, protocol: &str) -> Option<&Layer> {
        self.layers.iter().find(|l| l.protocol == protocol)
    }

    /// The layers as an indented tree, one field per line, with byte offsets.
    pub fn tree(&self) -> String {
        let mut out = String::new();
        for layer in &self.layers {
            let _ = writeln!(
                out,
                "{}  [{}..{}]",
                layer.title, layer.range.start, layer.range.end
            );
            for f in &layer.fields {
                let _ = writeln!(
                    out,
                    "    {}: {}  [{}..{}]",
                    f.name, f.value, f.range.start, f.range.end
                );
            }
        }
        for p in &self.problems {
            let _ = writeln!(out, "!! {p}");
        }
        out
    }
}

/// Decodes one packet of the given pcap link type.
pub fn decode(linktype: u32, data: &[u8]) -> Decoded {
    let mut d = Decoder::new(data);
    match linktype {
        LINKTYPE_ETHERNET => l2::ethernet(&mut d, 0),
        LINKTYPE_LINUX_SLL => l2::sll(&mut d, 0),
        LINKTYPE_RAW => l3::raw_ip(&mut d, 0),
        LINKTYPE_IPV4 => l3::ipv4(&mut d, 0),
        LINKTYPE_IPV6 => l3::ipv6(&mut d, 0),
        other => {
            d.summary("Unknown", format!("Unknown link type {other}"));
            d.data(0);
        }
    }
    d.out
}

/// A classic hex dump: offset, 16 bytes in hex, and their printable ASCII.
pub fn hex_dump(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let _ = write!(out, "{:04x}  ", i * 16);
        for j in 0..16 {
            match chunk.get(j) {
                Some(b) => {
                    let _ = write!(out, "{b:02x} ");
                }
                None => out.push_str("   "),
            }
            if j == 7 {
                out.push(' ');
            }
        }
        out.push(' ');
        for &b in chunk {
            out.push(if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            });
        }
        out.push('\n');
    }
    out
}

/// Builds a [`Decoded`] while the protocol decoders walk the packet.
pub(crate) struct Decoder<'a> {
    pub data: &'a [u8],
    pub out: Decoded,
}

impl<'a> Decoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            out: Decoded {
                protocol: "Data",
                len: data.len(),
                ..Default::default()
            },
        }
    }

    pub fn u8(&self, at: usize) -> Option<u8> {
        self.data.get(at).copied()
    }

    pub fn u16(&self, at: usize) -> Option<u16> {
        self.data
            .get(at..at + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&self, at: usize) -> Option<u32> {
        self.data
            .get(at..at + 4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn bytes(&self, range: Range<usize>) -> Option<&'a [u8]> {
        self.data.get(range)
    }

    /// Checks that `len` bytes from `at` are present; records a problem if not.
    pub fn need(&mut self, at: usize, len: usize, what: &str) -> bool {
        if at + len <= self.data.len() {
            true
        } else {
            self.problem(format!(
                "{what} truncated: needs {len} bytes at offset {at}, packet has {}",
                self.data.len().saturating_sub(at)
            ));
            false
        }
    }

    pub fn layer(&mut self, protocol: &'static str, title: String, range: Range<usize>) {
        self.out.layers.push(Layer {
            protocol,
            title,
            range,
            fields: Vec::new(),
        });
    }

    pub fn field(&mut self, name: &str, value: impl Into<String>, range: Range<usize>) {
        if let Some(l) = self.out.layers.last_mut() {
            l.fields.push(Field {
                name: name.to_string(),
                value: value.into(),
                range,
            });
        }
    }

    pub fn problem(&mut self, p: String) {
        self.out.problems.push(p);
    }

    pub fn addresses(&mut self, src: String, dst: String) {
        self.out.source = src;
        self.out.destination = dst;
    }

    pub fn summary(&mut self, protocol: &'static str, info: String) {
        self.out.protocol = protocol;
        self.out.info = info;
    }

    /// Shows the rest of the packet from `at` as undecoded data.
    pub fn data(&mut self, at: usize) {
        self.data_to(at, self.data.len());
    }

    /// Shows `at..end` as undecoded data.
    pub fn data_to(&mut self, at: usize, end: usize) {
        let end = end.min(self.data.len());
        if end > at {
            self.layer("Data", format!("Data ({} bytes)", end - at), at..end);
        }
    }
}

pub(crate) fn mac(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub(crate) fn hex16(v: u16) -> String {
    format!("0x{v:04x}")
}

/// Ones' complement sum of big endian 16-bit words.
pub(crate) fn ones_sum(chunks: &[&[u8]]) -> u16 {
    let mut sum: u64 = 0;
    for data in chunks {
        let mut it = data.chunks_exact(2);
        for w in &mut it {
            sum += u64::from(u16::from_be_bytes([w[0], w[1]]));
        }
        if let [last] = it.remainder() {
            sum += u64::from(*last) << 8;
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_dump_layout() {
        let d = hex_dump(b"GET / HTTP/1.1\r\nHost");
        let lines: Vec<&str> = d.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("0000  47 45 54 20"));
        assert!(lines[0].ends_with("GET / HTTP/1.1.."));
        assert!(lines[1].starts_with("0010  48 6f 73 74"));
    }

    #[test]
    fn unknown_link_type_is_data() {
        let d = decode(9999, &[1, 2, 3]);
        assert_eq!(d.layers.len(), 1);
        assert_eq!(d.layers[0].protocol, "Data");
    }
}
