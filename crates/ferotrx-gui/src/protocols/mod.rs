//! The protocol registry: what the stream editor knows about each layer of a
//! packet.
//!
//! Every layer of the packet text form (`eth/vlan(id=10)/ipv4/udp/dns`) has a
//! [`ProtocolEditor`] here. An editor names the layer's fields with their
//! kinds (so the form can check a MAC or an IPv4 address as you type and show
//! the builder's default as a hint), says which layers usually come next, and
//! draws the layer's form. Most editors are plain tables of [`FieldDef`]s and
//! use the [`generic_form`]; an editor that needs more (like the payload
//! editor's hex and text modes) draws its own.
//!
//! New protocols, application layers among them, plug in by implementing
//! [`ProtocolEditor`] and calling [`Registry::register`]. A layer no editor
//! knows still opens, in a key/value form, so the GUI never loses fields of a
//! newer engine.

mod builtin;

use eframe::egui;
use ferotrx_packet::RawLayer;

pub use builtin::builtin_editors;

/// Where a protocol sits in the stack, for grouping the "add layer" menu.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Category {
    Link,
    Network,
    Transport,
    Application,
    Payload,
}

impl Category {
    pub const ALL: [Category; 5] = [
        Category::Link,
        Category::Network,
        Category::Transport,
        Category::Application,
        Category::Payload,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Category::Link => "Link",
            Category::Network => "Network",
            Category::Transport => "Transport",
            Category::Application => "Application",
            Category::Payload => "Payload",
        }
    }
}

/// What a field holds, for checking it and choosing its widget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    Mac,
    Ipv4,
    Ipv6,
    /// IPv4 or IPv6.
    Ip,
    /// A number up to `max`, decimal or `0x` hex.
    Uint(u64),
    Bool,
    /// One of these names, or a number up to 255 or 65535 when `numeric`.
    Choice {
        options: &'static [&'static str],
        numeric: bool,
    },
    /// Flag letters (`SA`) or a number; `letters` lists the flags in order.
    Flags {
        letters: &'static str,
    },
    Text,
    Hex,
}

impl FieldKind {
    /// Checks a value as the packet builder would, without building.
    pub fn check(self, v: &str) -> Result<(), String> {
        let v = v.trim();
        let ok = match self {
            FieldKind::Mac => {
                let parts: Vec<_> = v.split([':', '-']).collect();
                parts.len() == 6
                    && parts
                        .iter()
                        .all(|p| !p.is_empty() && p.len() <= 2 && u8::from_str_radix(p, 16).is_ok())
            }
            FieldKind::Ipv4 => v.parse::<std::net::Ipv4Addr>().is_ok(),
            FieldKind::Ipv6 => v.parse::<std::net::Ipv6Addr>().is_ok(),
            FieldKind::Ip => v.parse::<std::net::IpAddr>().is_ok(),
            FieldKind::Uint(max) => parse_uint(v).is_some_and(|n| n <= max),
            FieldKind::Bool => matches!(
                v.to_ascii_lowercase().as_str(),
                "1" | "0" | "true" | "false" | "yes" | "no" | "on" | "off"
            ),
            FieldKind::Choice { options, numeric } => {
                options.iter().any(|o| o.eq_ignore_ascii_case(v))
                    || (numeric && parse_uint(v).is_some_and(|n| n <= 65535))
            }
            FieldKind::Flags { letters } => {
                parse_uint(v).is_some()
                    || v.chars().all(|c| {
                        letters.contains(c.to_ascii_uppercase()) || matches!(c, '.' | '|' | ' ')
                    })
            }
            FieldKind::Text => true,
            FieldKind::Hex => {
                let h: String = v
                    .trim_start_matches("0x")
                    .chars()
                    .filter(|c| !matches!(c, ' ' | ':' | '-' | '_'))
                    .collect();
                h.len().is_multiple_of(2) && h.chars().all(|c| c.is_ascii_hexdigit())
            }
        };
        if ok {
            Ok(())
        } else {
            Err(match self {
                FieldKind::Mac => "expected a MAC like 02:00:00:00:00:01".into(),
                FieldKind::Ipv4 => "expected an IPv4 address".into(),
                FieldKind::Ipv6 => "expected an IPv6 address".into(),
                FieldKind::Ip => "expected an IPv4 or IPv6 address".into(),
                FieldKind::Uint(max) => format!("expected a number from 0 to {max}"),
                FieldKind::Bool => "expected on or off".into(),
                FieldKind::Choice { options, .. } => {
                    format!("expected one of {}", options.join(", "))
                }
                FieldKind::Flags { letters } => format!("expected flag letters from {letters}"),
                FieldKind::Text => String::new(),
                FieldKind::Hex => "expected an even number of hex digits".into(),
            })
        }
    }
}

fn parse_uint(v: &str) -> Option<u64> {
    match v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(&h.replace('_', ""), 16).ok(),
        None => v.replace('_', "").parse().ok(),
    }
}

/// One field of a layer.
#[derive(Clone, Copy, Debug)]
pub struct FieldDef {
    /// The key in the text form, such as `src`.
    pub key: &'static str,
    pub label: &'static str,
    pub kind: FieldKind,
    /// What the builder uses when the field is left empty.
    pub default: &'static str,
    pub help: &'static str,
    /// The key may be given more than once (DNS questions and answers).
    pub repeat: bool,
}

impl FieldDef {
    pub const fn new(key: &'static str, label: &'static str, kind: FieldKind) -> Self {
        Self {
            key,
            label,
            kind,
            default: "",
            help: "",
            repeat: false,
        }
    }

    pub const fn default(mut self, d: &'static str) -> Self {
        self.default = d;
        self
    }

    pub const fn help(mut self, h: &'static str) -> Self {
        self.help = h;
        self
    }

    pub const fn repeat(mut self) -> Self {
        self.repeat = true;
        self
    }
}

/// Knows one layer of the packet text form.
pub trait ProtocolEditor: Send + Sync {
    /// The layer name in the text form, such as `ipv4`.
    fn name(&self) -> &'static str;
    /// Other names the text form accepts for the layer (`ip`, `ether`).
    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }
    /// The name people know, such as `IPv4`.
    fn title(&self) -> &'static str;
    fn category(&self) -> Category;
    fn fields(&self) -> &'static [FieldDef];
    /// Layers that usually follow this one, for the "add layer" shortcut.
    fn next(&self) -> &'static [&'static str] {
        &[]
    }
    /// A new layer of this kind, as added from the menu.
    fn new_layer(&self) -> RawLayer {
        RawLayer::new(self.name())
    }
    /// Draws the layer's form. Returns true when the layer changed.
    fn ui(&self, ui: &mut egui::Ui, layer: &mut RawLayer) -> bool {
        generic_form(ui, self.fields(), layer)
    }
}

/// The editors the GUI knows, looked up by layer name or alias.
pub struct Registry {
    editors: Vec<Box<dyn ProtocolEditor>>,
    unknown: Unknown,
}

impl Default for Registry {
    fn default() -> Self {
        Self::builtin()
    }
}

impl Registry {
    /// No editors: every layer opens in the key/value form.
    pub fn empty() -> Self {
        Self {
            editors: Vec::new(),
            unknown: Unknown,
        }
    }

    /// Editors for every layer the packet builder has.
    pub fn builtin() -> Self {
        let mut r = Self::empty();
        for e in builtin_editors() {
            r.register(e);
        }
        r
    }

    /// Adds an editor. One registered later for the same name replaces the
    /// earlier one, so a plugin can override a built-in form.
    pub fn register(&mut self, editor: Box<dyn ProtocolEditor>) {
        self.editors.retain(|e| e.name() != editor.name());
        self.editors.push(editor);
    }

    /// The editor for a layer name or alias, if one is registered.
    pub fn get(&self, name: &str) -> Option<&dyn ProtocolEditor> {
        let name = name.to_ascii_lowercase();
        self.editors
            .iter()
            .find(|e| e.name() == name || e.aliases().contains(&name.as_str()))
            .map(|e| e.as_ref())
    }

    /// The editor for a layer, falling back to the key/value form.
    pub fn editor(&self, name: &str) -> &dyn ProtocolEditor {
        self.get(name).unwrap_or(&self.unknown)
    }

    /// Registered editors in one category, in registration order.
    pub fn in_category(&self, c: Category) -> impl Iterator<Item = &dyn ProtocolEditor> {
        self.editors
            .iter()
            .filter(move |e| e.category() == c)
            .map(|e| e.as_ref())
    }

    pub fn all(&self) -> impl Iterator<Item = &dyn ProtocolEditor> {
        self.editors.iter().map(|e| e.as_ref())
    }
}

/// Editor for layers no one registered: every argument as key and value.
struct Unknown;

impl ProtocolEditor for Unknown {
    fn name(&self) -> &'static str {
        ""
    }
    fn title(&self) -> &'static str {
        "Unknown layer"
    }
    fn category(&self) -> Category {
        Category::Payload
    }
    fn fields(&self) -> &'static [FieldDef] {
        &[]
    }
}

/// Values of a layer by key.
pub trait LayerArgs {
    fn get(&self, key: &str) -> Option<&str>;
    fn get_all(&self, key: &str) -> Vec<String>;
    /// Sets a key's value, or removes the key when `value` is empty.
    fn set(&mut self, key: &str, value: &str);
    fn set_all(&mut self, key: &str, values: Vec<String>);
}

impl LayerArgs for RawLayer {
    fn get(&self, key: &str) -> Option<&str> {
        self.args
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn get_all(&self, key: &str) -> Vec<String> {
        self.args
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .collect()
    }

    fn set(&mut self, key: &str, value: &str) {
        match self.args.iter().position(|(k, _)| k == key) {
            Some(i) if value.is_empty() => {
                self.args.remove(i);
            }
            Some(i) => self.args[i].1 = value.to_string(),
            None if value.is_empty() => {}
            None => self.args.push((key.to_string(), value.to_string())),
        }
    }

    fn set_all(&mut self, key: &str, values: Vec<String>) {
        let at = self.args.iter().position(|(k, _)| k == key);
        self.args.retain(|(k, _)| k != key);
        let at = at.unwrap_or(self.args.len()).min(self.args.len());
        for (i, v) in values.into_iter().enumerate() {
            self.args.insert(at + i, (key.to_string(), v));
        }
    }
}

/// The form most editors use: one row per [`FieldDef`], then any arguments
/// the definitions do not name, so nothing written by hand is lost.
pub fn generic_form(ui: &mut egui::Ui, fields: &[FieldDef], layer: &mut RawLayer) -> bool {
    let mut changed = false;
    let id = ui.id().with(&layer.name);
    egui::Grid::new(id.with("fields"))
        .num_columns(2)
        .spacing([12.0, 4.0])
        .striped(true)
        .show(ui, |ui| {
            for f in fields {
                let label = ui.label(f.label);
                if !f.help.is_empty() {
                    label.on_hover_text(f.help);
                }
                if f.repeat {
                    changed |= repeat_field(ui, f, layer);
                } else {
                    changed |= field(ui, f, layer);
                }
                ui.end_row();
            }
        });

    let known: Vec<&str> = fields.iter().map(|f| f.key).collect();
    let extra: Vec<usize> = (0..layer.args.len())
        .filter(|&i| !known.contains(&layer.args[i].0.as_str()))
        .collect();
    if !extra.is_empty() {
        ui.add_space(4.0);
        ui.label(egui::RichText::new("Other fields").weak());
    }
    let mut remove = None;
    for i in extra {
        ui.horizontal(|ui| {
            let (k, v) = &mut layer.args[i];
            changed |= ui
                .add(egui::TextEdit::singleline(k).desired_width(80.0))
                .changed();
            ui.label("=");
            changed |= ui
                .add(egui::TextEdit::singleline(v).desired_width(200.0))
                .changed();
            if ui.small_button("✕").on_hover_text("Remove field").clicked() {
                remove = Some(i);
            }
        });
    }
    if let Some(i) = remove {
        layer.args.remove(i);
        changed = true;
    }
    if fields.is_empty() && ui.small_button("+ field").clicked() {
        layer.args.push(("key".into(), "value".into()));
        changed = true;
    }
    changed
}

fn field(ui: &mut egui::Ui, f: &FieldDef, layer: &mut RawLayer) -> bool {
    let mut value = layer.get(f.key).unwrap_or_default().to_string();
    let before = value.clone();
    ui.horizontal(|ui| match f.kind {
        FieldKind::Bool => {
            let shown = match value.to_ascii_lowercase().as_str() {
                "" => "auto",
                "1" | "true" | "yes" | "on" => "on",
                _ => "off",
            };
            egui::ComboBox::from_id_salt((f.key, &layer.name))
                .selected_text(if shown == "auto" && !f.default.is_empty() {
                    format!("auto ({})", f.default)
                } else {
                    shown.to_string()
                })
                .show_ui(ui, |ui| {
                    for (label, v) in [("auto", ""), ("on", "1"), ("off", "0")] {
                        if ui.selectable_label(shown == label, label).clicked() {
                            value = v.to_string();
                        }
                    }
                });
        }
        FieldKind::Choice { options, .. } => {
            text_edit(ui, f, &mut value);
            ui.menu_button("▾", |ui| {
                for o in options {
                    if ui.button(*o).clicked() {
                        value = o.to_string();
                        ui.close();
                    }
                }
            });
        }
        FieldKind::Flags { letters } => {
            text_edit(ui, f, &mut value);
            let upper = value.to_ascii_uppercase();
            if parse_uint(&value).is_none() {
                for c in letters.chars() {
                    let mut on = upper.contains(c);
                    if ui
                        .toggle_value(&mut on, c.to_string())
                        .on_hover_text(flag_name(c))
                        .changed()
                    {
                        value = letters
                            .chars()
                            .filter(|&l| if l == c { on } else { upper.contains(l) })
                            .collect();
                    }
                }
            }
        }
        _ => text_edit(ui, f, &mut value),
    });
    if value != before {
        layer.set(f.key, &value);
        true
    } else {
        false
    }
}

fn flag_name(c: char) -> &'static str {
    match c {
        'F' => "FIN",
        'S' => "SYN",
        'R' => "RST",
        'P' => "PSH",
        'A' => "ACK",
        'U' => "URG",
        'E' => "ECE",
        'C' => "CWR",
        'N' => "NS",
        'O' => "Override",
        _ => "",
    }
}

fn text_edit(ui: &mut egui::Ui, f: &FieldDef, value: &mut String) {
    let bad = !value.is_empty() && f.kind.check(value).is_err();
    let mut edit = egui::TextEdit::singleline(value).desired_width(
        if matches!(
            f.kind,
            FieldKind::Ipv6 | FieldKind::Ip | FieldKind::Text | FieldKind::Hex
        ) {
            260.0
        } else {
            150.0
        },
    );
    if !f.default.is_empty() {
        edit = edit.hint_text(f.default);
    }
    if bad {
        edit = edit.text_color(ui.visuals().error_fg_color);
    }
    let r = ui.add(edit);
    if bad {
        if let Err(e) = f.kind.check(value) {
            r.on_hover_text(e);
        }
    }
}

fn repeat_field(ui: &mut egui::Ui, f: &FieldDef, layer: &mut RawLayer) -> bool {
    let mut values = layer.get_all(f.key);
    let before = values.clone();
    ui.vertical(|ui| {
        let mut remove = None;
        for (i, v) in values.iter_mut().enumerate() {
            ui.horizontal(|ui| {
                text_edit(ui, f, v);
                if ui.small_button("✕").clicked() {
                    remove = Some(i);
                }
            });
        }
        if let Some(i) = remove {
            values.remove(i);
        }
        if ui.small_button("+ add").clicked() {
            values.push(String::new());
        }
    });
    if values != before {
        // Keep empty entries while they are being typed: write them as "".
        layer.set_all(f.key, values);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builder_layer_has_an_editor() {
        let r = Registry::builtin();
        for name in [
            "eth", "ether", "vlan", "dot1q", "qinq", "arp", "ipv4", "ip", "ipv6", "hbh", "dstopt",
            "frag", "tcp", "udp", "icmp", "icmpv6", "dns", "raw", "payload",
        ] {
            assert!(r.get(name).is_some(), "no editor for {name}");
        }
        assert_eq!(r.editor("http2").title(), "Unknown layer");
    }

    #[test]
    fn field_defaults_are_valid_values() {
        // Every default shown as a hint must be a value the builder takes, and
        // the layer with every default set must build.
        for e in Registry::builtin().all() {
            let mut layer = e.new_layer();
            for f in e.fields() {
                if f.default.is_empty() || f.default.contains(' ') {
                    continue;
                }
                assert!(
                    f.kind.check(f.default).is_ok(),
                    "{}.{} default {}",
                    e.name(),
                    f.key,
                    f.default
                );
                layer.set(f.key, f.default);
            }
            layer
                .to_layer()
                .unwrap_or_else(|err| panic!("{}: {}", e.name(), err.0));
        }
    }

    #[test]
    fn field_keys_are_ones_the_builder_knows() {
        // A wrong key in a definition would give "unknown field" on build.
        let samples = |k: FieldKind| match k {
            FieldKind::Mac => "02:00:00:00:00:01",
            FieldKind::Ipv4 => "10.0.0.1",
            FieldKind::Ipv6 | FieldKind::Ip => "2001:db8::1",
            FieldKind::Uint(_) => "1",
            FieldKind::Bool => "1",
            FieldKind::Choice { options, .. } => options[0],
            FieldKind::Flags { letters } => &letters[..1],
            FieldKind::Text => "example.com",
            FieldKind::Hex => "00ff",
        };
        for e in Registry::builtin().all() {
            for f in e.fields() {
                let mut layer = e.new_layer();
                layer.set(f.key, samples(f.kind));
                if let Err(err) = layer.to_layer() {
                    assert!(
                        !err.0.contains("unknown field"),
                        "{}.{}: {}",
                        e.name(),
                        f.key,
                        err.0
                    );
                }
            }
        }
    }

    #[test]
    fn checks_values_like_the_builder() {
        assert!(FieldKind::Mac.check("02:00:00:00:00:01").is_ok());
        assert!(FieldKind::Mac.check("02:00:00:00:01").is_err());
        assert!(FieldKind::Uint(4095).check("0x0fff").is_ok());
        assert!(FieldKind::Uint(4095).check("4096").is_err());
        let flags = FieldKind::Flags {
            letters: "FSRPAUECN",
        };
        assert!(flags.check("SA").is_ok());
        assert!(flags.check("SX").is_err());
        assert!(FieldKind::Hex.check("de ad be ef").is_ok());
        assert!(FieldKind::Hex.check("abc").is_err());
    }

    #[test]
    fn set_and_set_all_keep_order() {
        let mut l = RawLayer::new("dns");
        l.set("id", "1");
        l.set_all("q", vec!["a.example".into(), "b.example".into()]);
        l.set("qtype", "AAAA");
        l.set_all("q", vec!["c.example".into()]);
        assert_eq!(l.to_string(), "dns(id=1,q=c.example,qtype=AAAA)");
        l.set("id", "");
        assert_eq!(l.to_string(), "dns(q=c.example,qtype=AAAA)");
    }

    #[test]
    fn plugins_override_and_add() {
        struct Http;
        impl ProtocolEditor for Http {
            fn name(&self) -> &'static str {
                "http"
            }
            fn title(&self) -> &'static str {
                "HTTP"
            }
            fn category(&self) -> Category {
                Category::Application
            }
            fn fields(&self) -> &'static [FieldDef] {
                const F: &[FieldDef] = &[FieldDef::new("method", "Method", FieldKind::Text)];
                F
            }
        }
        let mut r = Registry::builtin();
        let before = r.all().count();
        r.register(Box::new(Http));
        assert_eq!(r.all().count(), before + 1);
        assert_eq!(r.editor("HTTP").title(), "HTTP");
        assert!(r
            .in_category(Category::Application)
            .any(|e| e.name() == "http"));
    }
}
