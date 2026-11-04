//! Editors for the layers `ferotrx-packet` builds. Keys, defaults and value
//! syntax follow `ferotrx build --help`; tests check them against the builder.

use eframe::egui;
use ferotrx_packet::RawLayer;

use super::{Category, FieldDef as F, FieldKind as K, LayerArgs, ProtocolEditor};

const U8: K = K::Uint(0xff);
const U16: K = K::Uint(0xffff);
const U32: K = K::Uint(0xffff_ffff);
const AUTO: &str = "auto (from the layers)";
const AUTO_SUM: &str = "auto (computed)";

/// A protocol described by a table: the usual case.
#[derive(Clone, Copy)]
pub struct TableEditor {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub title: &'static str,
    pub category: Category,
    pub fields: &'static [F],
    pub next: &'static [&'static str],
}

impl ProtocolEditor for TableEditor {
    fn name(&self) -> &'static str {
        self.name
    }
    fn aliases(&self) -> &'static [&'static str] {
        self.aliases
    }
    fn title(&self) -> &'static str {
        self.title
    }
    fn category(&self) -> Category {
        self.category
    }
    fn fields(&self) -> &'static [F] {
        self.fields
    }
    fn next(&self) -> &'static [&'static str] {
        self.next
    }
}

const L3: &[&str] = &["ipv4", "ipv6", "arp", "vlan", "raw"];

const ETH: TableEditor = TableEditor {
    name: "eth",
    aliases: &["ether", "ethernet"],
    title: "Ethernet II",
    category: Category::Link,
    fields: &[
        F::new("dst", "Destination", K::Mac).default("02:00:00:00:00:02"),
        F::new("src", "Source", K::Mac).default("02:00:00:00:00:fe"),
        F::new("type", "EtherType", U16)
            .default(AUTO)
            .help("Set to send a type the next layer would not give"),
        F::new("pad", "Pad to 60 bytes", K::Bool).default("on"),
    ],
    next: L3,
};

const VLAN_FIELDS: &[F] = &[
    F::new("id", "VLAN ID", K::Uint(4095)).default("1"),
    F::new("pcp", "Priority (PCP)", K::Uint(7)).default("0"),
    F::new("dei", "Drop eligible", K::Bool).default("off"),
    F::new("tpid", "TPID", U16).help("0x8100 for 802.1Q, 0x88a8 for 802.1ad"),
    F::new("type", "EtherType", U16).default(AUTO),
];

const VLAN: TableEditor = TableEditor {
    name: "vlan",
    aliases: &["dot1q"],
    title: "802.1Q VLAN",
    category: Category::Link,
    fields: VLAN_FIELDS,
    next: L3,
};

const QINQ: TableEditor = TableEditor {
    name: "qinq",
    aliases: &[],
    title: "802.1ad outer tag",
    category: Category::Link,
    fields: VLAN_FIELDS,
    next: &["vlan"],
};

const ARP: TableEditor = TableEditor {
    name: "arp",
    aliases: &[],
    title: "ARP",
    category: Category::Network,
    fields: &[
        F::new(
            "op",
            "Operation",
            K::Choice {
                options: &["request", "reply"],
                numeric: true,
            },
        )
        .default("request"),
        F::new("smac", "Sender MAC", K::Mac).default("the Ethernet source"),
        F::new("sip", "Sender IP", K::Ipv4).default("192.0.2.1"),
        F::new("tmac", "Target MAC", K::Mac).default("00:00:00:00:00:00"),
        F::new("tip", "Target IP", K::Ipv4).default("192.0.2.2"),
    ],
    next: &[],
};

const IP_NEXT: &[&str] = &["tcp", "udp", "icmp", "raw"];

const IPV4: TableEditor = TableEditor {
    name: "ipv4",
    aliases: &["ip", "ip4"],
    title: "IPv4",
    category: Category::Network,
    fields: &[
        F::new("src", "Source", K::Ipv4).default("192.0.2.1"),
        F::new("dst", "Destination", K::Ipv4).default("192.0.2.2"),
        F::new("ttl", "TTL", U8).default("64"),
        F::new("dscp", "DSCP", K::Uint(63)).default("0"),
        F::new("ecn", "ECN", K::Uint(3)).default("0"),
        F::new("tos", "TOS byte", U8).help("DSCP and ECN in one byte"),
        F::new("id", "Identification", U16).default("1"),
        F::new("df", "Don't fragment", K::Bool).default("off"),
        F::new("mf", "More fragments", K::Bool).default("off"),
        F::new("frag", "Fragment offset (bytes)", K::Uint(65528))
            .default("0")
            .help("A multiple of 8"),
        F::new("proto", "Protocol", U8).default(AUTO),
        F::new("len", "Total length", U16).default(AUTO),
        F::new("chksum", "Checksum", U16)
            .default(AUTO_SUM)
            .help("Set a value to send a wrong checksum on purpose"),
    ],
    next: IP_NEXT,
};

const IPV6: TableEditor = TableEditor {
    name: "ipv6",
    aliases: &["ip6"],
    title: "IPv6",
    category: Category::Network,
    fields: &[
        F::new("src", "Source", K::Ipv6).default("2001:db8::1"),
        F::new("dst", "Destination", K::Ipv6).default("2001:db8::2"),
        F::new("hlim", "Hop limit", U8).default("64"),
        F::new("tc", "Traffic class", U8).default("0"),
        F::new("flow", "Flow label", K::Uint(0xfffff)).default("0"),
        F::new("nh", "Next header", U8).default(AUTO),
        F::new("plen", "Payload length", U16).default(AUTO),
    ],
    next: &["tcp", "udp", "icmp", "hbh", "dstopt", "frag", "raw"],
};

const HBH: TableEditor = TableEditor {
    name: "hbh",
    aliases: &[],
    title: "IPv6 Hop-by-Hop options",
    category: Category::Network,
    fields: &[
        F::new("len", "Length (bytes)", U8).default("8"),
        F::new("ra", "Router alert", U16).help("0 for MLD"),
        F::new("nh", "Next header", U8).default(AUTO),
    ],
    next: IP_NEXT,
};

const DSTOPT: TableEditor = TableEditor {
    name: "dstopt",
    aliases: &[],
    title: "IPv6 Destination options",
    category: Category::Network,
    fields: &[
        F::new("len", "Length (bytes)", U8).default("8"),
        F::new("nh", "Next header", U8).default(AUTO),
    ],
    next: IP_NEXT,
};

const FRAG: TableEditor = TableEditor {
    name: "frag",
    aliases: &[],
    title: "IPv6 Fragment",
    category: Category::Network,
    fields: &[
        F::new("offset", "Offset (bytes)", K::Uint(65528))
            .default("0")
            .help("A multiple of 8"),
        F::new("mf", "More fragments", K::Bool).default("off"),
        F::new("id", "Identification", U32).default("1"),
        F::new("nh", "Next header", U8).default(AUTO),
    ],
    next: IP_NEXT,
};

const TCP: TableEditor = TableEditor {
    name: "tcp",
    aliases: &[],
    title: "TCP",
    category: Category::Transport,
    fields: &[
        F::new("sport", "Source port", U16).default("49152"),
        F::new("dport", "Destination port", U16).default("80"),
        F::new("seq", "Sequence number", U32).default("0"),
        F::new("ack", "Acknowledgment", U32).default("0"),
        F::new(
            "flags",
            "Flags",
            K::Flags {
                letters: "FSRPAUECN",
            },
        )
        .default("S"),
        F::new("win", "Window", U16).default("64240"),
        F::new("urg", "Urgent pointer", U16).default("0"),
        F::new("mss", "MSS option", U16),
        F::new("wscale", "Window scale option", K::Uint(14)),
        F::new("sackok", "SACK permitted option", K::Bool).default("off"),
        F::new("chksum", "Checksum", U16).default(AUTO_SUM),
    ],
    next: &["raw"],
};

const UDP: TableEditor = TableEditor {
    name: "udp",
    aliases: &[],
    title: "UDP",
    category: Category::Transport,
    fields: &[
        F::new("sport", "Source port", U16).default("auto (53 for DNS, else 49152)"),
        F::new("dport", "Destination port", U16).default("auto (53 for DNS, else 9)"),
        F::new("len", "Length", U16).default(AUTO),
        F::new("chksum", "Checksum", U16)
            .default(AUTO_SUM)
            .help("0 sends no checksum over IPv4"),
    ],
    next: &["dns", "raw"],
};

const ICMP: TableEditor = TableEditor {
    name: "icmp",
    aliases: &["icmpv6", "icmp6"],
    title: "ICMP / ICMPv6",
    category: Category::Transport,
    fields: &[
        F::new(
            "type",
            "Type",
            K::Choice {
                options: &["ns", "na"],
                numeric: true,
            },
        )
        .default("echo request")
        .help("A number, or ns/na for IPv6 neighbor solicitation/advertisement"),
        F::new("code", "Code", U8).default("0"),
        F::new("id", "Identifier", U16).default("0"),
        F::new("seq", "Sequence", U16).default("0"),
        F::new("target", "ND target", K::Ipv6),
        F::new("lladdr", "ND link-layer address", K::Mac),
        F::new("flags", "NA flags", K::Flags { letters: "RSO" })
            .help("Router, Solicited, Override"),
        F::new("chksum", "Checksum", U16).default(AUTO_SUM),
    ],
    next: &["raw"],
};

const DNS: TableEditor = TableEditor {
    name: "dns",
    aliases: &[],
    title: "DNS",
    category: Category::Application,
    fields: &[
        F::new("id", "Transaction ID", U16).default("1"),
        F::new("q", "Question", K::Text).repeat(),
        F::new(
            "qtype",
            "Query type",
            K::Choice {
                options: &[
                    "A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT", "HTTPS", "ANY",
                ],
                numeric: true,
            },
        )
        .default("A"),
        F::new("qr", "Response", K::Bool).default("off, on with answers"),
        F::new("a", "Answer address", K::Ip).repeat(),
        F::new("ttl", "Answer TTL", U32).default("300"),
        F::new("rd", "Recursion desired", K::Bool).default("on"),
        F::new("ra", "Recursion available", K::Bool).default("off"),
        F::new("aa", "Authoritative", K::Bool).default("off"),
        F::new("tc", "Truncated", K::Bool).default("off"),
        F::new("opcode", "Opcode", K::Uint(15)).default("0"),
        F::new("rcode", "Response code", K::Uint(15)).default("0"),
    ],
    next: &[],
};

/// The payload layer: bytes as text, as hex, or a length filled with one byte.
/// It draws its own form to show how an editor can go past the field table.
pub struct PayloadEditor;

const RAW_FIELDS: &[F] = &[
    F::new("text", "Text", K::Text),
    F::new("hex", "Hex", K::Hex),
    F::new("len", "Length", U16).help("Pads (or cuts) the bytes to this length"),
    F::new("fill", "Fill byte", U8).default("0"),
];

impl ProtocolEditor for PayloadEditor {
    fn name(&self) -> &'static str {
        "raw"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["data", "payload"]
    }
    fn title(&self) -> &'static str {
        "Payload"
    }
    fn category(&self) -> Category {
        Category::Payload
    }
    fn fields(&self) -> &'static [F] {
        RAW_FIELDS
    }
    fn new_layer(&self) -> RawLayer {
        let mut l = RawLayer::new("raw");
        l.set("len", "18");
        l
    }

    fn ui(&self, ui: &mut egui::Ui, layer: &mut RawLayer) -> bool {
        #[derive(PartialEq, Clone, Copy)]
        enum Mode {
            Text,
            Hex,
            Fill,
        }
        let mode = if layer.get("hex").is_some() {
            Mode::Hex
        } else if layer.get("text").is_some() {
            Mode::Text
        } else {
            Mode::Fill
        };
        let mut new_mode = mode;
        let mut changed = false;
        ui.horizontal(|ui| {
            ui.label("Content");
            ui.selectable_value(&mut new_mode, Mode::Text, "Text");
            ui.selectable_value(&mut new_mode, Mode::Hex, "Hex");
            ui.selectable_value(&mut new_mode, Mode::Fill, "Fill only");
        });
        if new_mode != mode {
            changed = true;
            // Carry the bytes over where that is lossless.
            let bytes: Vec<u8> = match mode {
                Mode::Text => layer.get("text").unwrap_or_default().as_bytes().to_vec(),
                Mode::Hex => parse_hex(layer.get("hex").unwrap_or_default()),
                Mode::Fill => Vec::new(),
            };
            layer.set("text", "");
            layer.set("hex", "");
            match new_mode {
                Mode::Text => {
                    let t = String::from_utf8(bytes).unwrap_or_default();
                    layer.set_all("text", vec![t]);
                }
                Mode::Hex => {
                    let h: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
                    layer.set_all("hex", vec![h.join(" ")]);
                }
                Mode::Fill => {}
            }
        }
        match new_mode {
            Mode::Text => {
                let mut t = show_escapes(layer.get("text").unwrap_or_default());
                ui.label(
                    egui::RichText::new("Enter starts a new line (\\n). Write \\r for a carriage return, \\t for a tab, \\\\ for a backslash.")
                        .weak()
                        .small(),
                );
                if ui
                    .add(
                        egui::TextEdit::multiline(&mut t)
                            .code_editor()
                            .desired_rows(4)
                            .desired_width(f32::INFINITY),
                    )
                    .changed()
                {
                    layer.set_all("text", vec![read_escapes(&t)]);
                    changed = true;
                }
            }
            Mode::Hex => {
                let mut h = layer.get("hex").unwrap_or_default().to_string();
                let bad = K::Hex.check(&h).is_err();
                let mut edit = egui::TextEdit::multiline(&mut h)
                    .code_editor()
                    .desired_rows(4)
                    .desired_width(f32::INFINITY);
                if bad {
                    edit = edit.text_color(ui.visuals().error_fg_color);
                }
                if ui.add(edit).changed() {
                    layer.set_all("hex", vec![h]);
                    changed = true;
                }
            }
            Mode::Fill => {}
        }
        egui::Grid::new(ui.id().with("raw-len")).show(ui, |ui| {
            for key in ["len", "fill"] {
                let f = RAW_FIELDS.iter().find(|f| f.key == key).expect("field");
                ui.label(f.label).on_hover_text(f.help);
                let mut v = layer.get(key).unwrap_or_default().to_string();
                let mut edit = egui::TextEdit::singleline(&mut v).desired_width(80.0);
                if !f.default.is_empty() {
                    edit = edit.hint_text(f.default);
                }
                if ui.add(edit).changed() {
                    layer.set(key, &v);
                    changed = true;
                }
                ui.end_row();
            }
        });
        changed
    }
}

/// Text with carriage returns, tabs and backslashes written as escapes, so
/// they can be seen and typed; new lines stay new lines.
pub fn show_escapes(t: &str) -> String {
    let mut out = String::with_capacity(t.len());
    for c in t.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c => out.push(c),
        }
    }
    out
}

/// The other way round from [`show_escapes`]; `\n` is read too.
pub fn read_escapes(t: &str) -> String {
    let mut out = String::with_capacity(t.len());
    let mut it = t.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('r') => out.push('\r'),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('0') => out.push('\0'),
            Some('\\') => out.push('\\'),
            Some(o) => {
                out.push('\\');
                out.push(o);
            }
            None => out.push('\\'),
        }
    }
    out
}

fn parse_hex(v: &str) -> Vec<u8> {
    let h: String = v
        .trim_start_matches("0x")
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    (0..h.len() / 2)
        .filter_map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// Every built-in editor, in the order the "add layer" menu lists them.
pub fn builtin_editors() -> Vec<Box<dyn ProtocolEditor>> {
    let mut v: Vec<Box<dyn ProtocolEditor>> = [
        ETH, VLAN, QINQ, ARP, IPV4, IPV6, HBH, DSTOPT, FRAG, TCP, UDP, ICMP, DNS,
    ]
    .into_iter()
    .map(|t| Box::new(t) as Box<dyn ProtocolEditor>)
    .collect();
    v.push(Box::new(PayloadEditor));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_round_trip() {
        let t = "GET / HTTP/1.1\r\nHost: x\\y\t\r\n\r\n";
        let shown = show_escapes(t);
        assert!(shown.contains("\\r\n"), "{shown}");
        assert_eq!(read_escapes(&shown), t);
        assert_eq!(read_escapes("a\\nb"), "a\nb");
    }
}
