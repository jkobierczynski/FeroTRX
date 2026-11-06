//! The packet view: a decoded packet as a tree of layers and fields next to
//! its bytes. Selecting a field highlights its bytes; clicking a byte
//! selects the field it belongs to.

use std::ops::Range;

use eframe::egui::{self, Color32, RichText};
use ferotrx_packet::Decoded;

/// What is selected in a packet view.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Selection {
    pub layer: Option<usize>,
    pub field: Option<usize>,
    /// Bring the selection into view in the tree (after a click on a byte).
    pub scroll: bool,
}

impl Selection {
    /// The bytes of the selected field, or of the selected layer.
    pub fn range(&self, d: &Decoded) -> Option<Range<usize>> {
        let layer = d.layers.get(self.layer?)?;
        match self.field.and_then(|f| layer.fields.get(f)) {
            Some(f) => Some(f.range.clone()),
            None => Some(layer.range.clone()),
        }
    }

    /// The innermost field (or layer) that holds byte `at`.
    pub fn at_byte(d: &Decoded, at: usize) -> Selection {
        let mut best = Selection {
            scroll: true,
            ..Default::default()
        };
        let mut best_len = usize::MAX;
        for (li, l) in d.layers.iter().enumerate() {
            if l.range.contains(&at) && l.range.len() < best_len {
                best.layer = Some(li);
                best.field = None;
                best_len = l.range.len();
            }
            for (fi, f) in l.fields.iter().enumerate() {
                if f.range.contains(&at) && f.range.len() <= best_len {
                    best.layer = Some(li);
                    best.field = Some(fi);
                    best_len = f.range.len();
                }
            }
        }
        best
    }
}

/// The summary line and problems, then the tree.
pub fn tree(ui: &mut egui::Ui, d: &Decoded, sel: &mut Selection) {
    ui.horizontal_wrapped(|ui| {
        ui.strong(d.protocol);
        ui.label(format!("{} → {}", d.source, d.destination));
        ui.label(RichText::new(format!("{} bytes", d.len)).weak());
    });
    if !d.info.is_empty() {
        ui.label(&d.info);
    }
    for p in &d.problems {
        ui.colored_label(ui.visuals().warn_fg_color, format!("⚠ {p}"));
    }
    ui.separator();
    for (li, layer) in d.layers.iter().enumerate() {
        let selected_layer = sel.layer == Some(li) && sel.field.is_none();
        let id = ui.id().with(("layer", li, layer.protocol));
        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, true)
            .show_header(ui, |ui| {
                if ui
                    .selectable_label(selected_layer, RichText::new(&layer.title).strong())
                    .clicked()
                {
                    *sel = Selection {
                        layer: Some(li),
                        field: None,
                        scroll: false,
                    };
                }
            })
            .body(|ui| {
                for (fi, f) in layer.fields.iter().enumerate() {
                    let on = sel.layer == Some(li) && sel.field == Some(fi);
                    let text = format!("{}: {}", f.name, f.value);
                    let r = ui
                        .selectable_label(on, text)
                        .on_hover_text(format!("bytes {}..{}", f.range.start, f.range.end));
                    if on && sel.scroll {
                        r.scroll_to_me(Some(egui::Align::Center));
                        sel.scroll = false;
                    }
                    if r.clicked() {
                        *sel = Selection {
                            layer: Some(li),
                            field: Some(fi),
                            scroll: false,
                        };
                    }
                }
            });
    }
}

/// Where the hex view edits: the byte under the cursor and whether its
/// first digit was typed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HexCursor {
    pub at: usize,
    /// The high digit is typed; the next digit completes the byte.
    pub half: bool,
}

/// What a key press does to the bytes under a [`HexCursor`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HexKey {
    Digit(u8),
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    /// Delete the byte under the cursor.
    Delete,
    /// Delete the byte before the cursor.
    Backspace,
    /// Insert a zero byte at the cursor.
    Insert,
}

impl HexCursor {
    /// Applies a key; returns true when the bytes changed.
    pub fn key(&mut self, bytes: &mut Vec<u8>, k: HexKey) -> bool {
        let len = bytes.len();
        // The cursor may sit just past the end, to append.
        self.at = self.at.min(len);
        let mut changed = false;
        match k {
            HexKey::Digit(d) => {
                if self.at == len {
                    bytes.push(0);
                }
                let b = &mut bytes[self.at];
                if self.half {
                    *b = (*b & 0xf0) | d;
                    self.half = false;
                    self.at += 1;
                } else {
                    *b = (d << 4) | (*b & 0x0f);
                    self.half = true;
                }
                changed = true;
            }
            HexKey::Left => {
                self.at = self.at.saturating_sub(1);
                self.half = false;
            }
            HexKey::Right => {
                self.at = (self.at + 1).min(len);
                self.half = false;
            }
            HexKey::Up => {
                self.at = self.at.saturating_sub(16);
                self.half = false;
            }
            HexKey::Down => {
                self.at = (self.at + 16).min(len);
                self.half = false;
            }
            HexKey::Home => {
                self.at -= self.at % 16;
                self.half = false;
            }
            HexKey::End => {
                self.at = (self.at - self.at % 16 + 15).min(len);
                self.half = false;
            }
            HexKey::Delete if self.at < len => {
                bytes.remove(self.at);
                self.half = false;
                changed = true;
            }
            HexKey::Backspace if self.at > 0 => {
                self.at -= 1;
                bytes.remove(self.at);
                self.half = false;
                changed = true;
            }
            HexKey::Insert => {
                bytes.insert(self.at, 0);
                self.half = false;
                changed = true;
            }
            _ => {}
        }
        changed
    }
}

/// The keys of this frame, for an edited hex view with focus.
fn hex_keys(ui: &egui::Ui) -> Vec<HexKey> {
    ui.input(|i| {
        let mut out = Vec::new();
        for e in &i.events {
            match e {
                egui::Event::Text(t) => {
                    for c in t.chars() {
                        if let Some(d) = c.to_digit(16) {
                            out.push(HexKey::Digit(d as u8));
                        }
                    }
                }
                egui::Event::Key {
                    key, pressed: true, ..
                } => out.push(match key {
                    egui::Key::ArrowLeft => HexKey::Left,
                    egui::Key::ArrowRight => HexKey::Right,
                    egui::Key::ArrowUp => HexKey::Up,
                    egui::Key::ArrowDown => HexKey::Down,
                    egui::Key::Home => HexKey::Home,
                    egui::Key::End => HexKey::End,
                    egui::Key::Delete => HexKey::Delete,
                    egui::Key::Backspace => HexKey::Backspace,
                    egui::Key::Insert => HexKey::Insert,
                    _ => continue,
                }),
                _ => {}
            }
        }
        out
    })
}

/// Offset, hex and ASCII columns, 16 bytes a row.
pub fn hex(ui: &mut egui::Ui, d: &Decoded, bytes: &[u8], sel: &mut Selection) {
    hex_view(ui, d, bytes, sel, None);
}

/// The hex view, editable when `cursor` is given: click a byte and type hex
/// digits over it; arrows move, Delete and Backspace remove bytes, Insert
/// adds a zero byte. Returns the new bytes when they changed.
pub fn hex_view(
    ui: &mut egui::Ui,
    d: &Decoded,
    bytes: &[u8],
    sel: &mut Selection,
    mut cursor: Option<&mut HexCursor>,
) -> Option<Vec<u8>> {
    let range = sel.range(d).unwrap_or(0..0);
    let hi_bg = ui.visuals().selection.bg_fill;
    let hi_fg = ui.visuals().selection.stroke.color;
    let cur_bg = ui.visuals().warn_fg_color;
    let cur_fg = ui.visuals().extreme_bg_color;
    let weak = ui.visuals().weak_text_color();
    let focus_id = ui.id().with("hex-edit");
    let editing = cursor.is_some();
    let focused = editing && ui.memory(|m| m.has_focus(focus_id));
    let mut out = None;
    if focused {
        if let Some(c) = cursor.as_deref_mut() {
            let mut b = bytes.to_vec();
            let mut changed = false;
            for k in hex_keys(ui) {
                changed |= c.key(&mut b, k);
            }
            if changed {
                *sel = Selection::at_byte(d, c.at.min(b.len().saturating_sub(1)));
                sel.scroll = false;
                out = Some(b);
            }
        }
    }
    let at = cursor.as_ref().filter(|_| focused).map(|c| c.at);
    // One row more while editing, to append at the end.
    let shown = if editing {
        bytes.len() + 1
    } else {
        bytes.len()
    };
    let rows = shown.div_ceil(16);
    let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
    let mut clicked = None;
    let r = egui::ScrollArea::vertical()
        .id_salt("hex")
        .auto_shrink([false, true])
        .show_rows(ui, row_h, rows, |ui, rows| {
            ui.spacing_mut().item_spacing.x = 0.0;
            for row in rows {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("{:04x}  ", row * 16))
                            .monospace()
                            .color(weak),
                    );
                    let start = row * 16;
                    let end = (start + 16).min(bytes.len());
                    for i in start..start + 16 {
                        let text = match bytes.get(i) {
                            Some(b) if i < end => format!("{b:02x}"),
                            _ if editing && i == bytes.len() => "··".into(),
                            _ => "  ".into(),
                        };
                        let mut t = RichText::new(text).monospace();
                        if at == Some(i) {
                            t = t.background_color(cur_bg).color(cur_fg);
                        } else if range.contains(&i) {
                            t = t.background_color(hi_bg).color(hi_fg);
                        } else if i >= end {
                            t = t.color(weak);
                        }
                        if i < end || (editing && i == bytes.len()) {
                            let r = ui.add(egui::Label::new(t).sense(egui::Sense::click()));
                            if r.clicked() {
                                clicked = Some(i);
                            }
                        } else {
                            ui.label(t);
                        }
                        let gap = if i % 16 == 7 { "  " } else { " " };
                        let mut g = RichText::new(gap).monospace();
                        if range.contains(&i) && range.contains(&(i + 1)) && i % 16 != 15 {
                            g = g.background_color(hi_bg);
                        }
                        ui.label(g);
                    }
                    ui.label(RichText::new(" ").monospace());
                    for (i, &b) in bytes.iter().enumerate().take(end).skip(start) {
                        let c = if b.is_ascii_graphic() || b == b' ' {
                            b as char
                        } else {
                            '.'
                        };
                        let mut t = RichText::new(c.to_string()).monospace();
                        if at == Some(i) {
                            t = t.background_color(cur_bg).color(cur_fg);
                        } else if range.contains(&i) {
                            t = t.background_color(hi_bg).color(hi_fg);
                        } else if c == '.' {
                            t = t.color(weak);
                        }
                        if ui
                            .add(egui::Label::new(t).sense(egui::Sense::click()))
                            .clicked()
                        {
                            clicked = Some(i);
                        }
                    }
                });
            }
        });
    if let Some(i) = clicked {
        if i < bytes.len() {
            *sel = Selection::at_byte(d, i);
        }
        if let Some(c) = cursor {
            c.at = i;
            c.half = false;
            ui.memory_mut(|m| m.request_focus(focus_id));
        }
    }
    if editing {
        // Keep the keys while the view has focus: arrows must not move
        // the focus to another widget.
        let rect = r.inner_rect;
        let resp = ui.interact(rect, focus_id, egui::Sense::focusable_noninteractive());
        if focused {
            ui.memory_mut(|m| {
                m.set_focus_lock_filter(
                    focus_id,
                    egui::EventFilter {
                        tab: false,
                        horizontal_arrows: true,
                        vertical_arrows: true,
                        escape: false,
                    },
                )
            });
            if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                ui.memory_mut(|m| m.surrender_focus(focus_id));
            }
        }
        let _ = resp;
    }
    out
}

/// Colors for run states in tables.
pub fn state_color(ui: &egui::Ui, running: bool, failed: bool) -> Color32 {
    if failed {
        ui.visuals().error_fg_color
    } else if running {
        crate::theme::good(ui)
    } else {
        ui.visuals().weak_text_color()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_keys_edit_bytes() {
        let mut b = vec![0x00, 0x11, 0x22];
        let mut c = HexCursor::default();
        assert!(c.key(&mut b, HexKey::Digit(0xa)));
        assert!(c.half);
        assert!(c.key(&mut b, HexKey::Digit(0xb)));
        assert_eq!(b, [0xab, 0x11, 0x22]);
        assert_eq!(c.at, 1);
        assert!(c.key(&mut b, HexKey::Delete));
        assert_eq!(b, [0xab, 0x22]);
        assert!(c.key(&mut b, HexKey::Insert));
        assert_eq!(b, [0xab, 0x00, 0x22]);
        assert!(!c.key(&mut b, HexKey::End));
        assert_eq!(c.at, 3, "the end is past the last byte");
        c.key(&mut b, HexKey::Digit(1));
        c.key(&mut b, HexKey::Digit(2));
        assert_eq!(b, [0xab, 0x00, 0x22, 0x12], "typing at the end appends");
        assert!(c.key(&mut b, HexKey::Backspace));
        assert_eq!(b, [0xab, 0x00, 0x22]);
        assert!(!c.key(&mut b, HexKey::Up));
        assert_eq!(c.at, 0);
        assert!(
            !c.key(&mut b, HexKey::Backspace),
            "nothing before the first byte"
        );
    }

    #[test]
    fn a_byte_selects_the_innermost_field() {
        let spec: ferotrx_packet::PacketSpec =
            "eth/ipv4(src=10.0.0.1,dst=10.0.0.2)/udp(sport=1000,dport=53)/raw(len=4)"
                .parse()
                .unwrap();
        let bytes = spec.build().unwrap();
        let d = ferotrx_packet::decode(ferotrx_packet::LINKTYPE_ETHERNET, &bytes);
        // Byte 26 is the first byte of the IPv4 source address.
        let s = Selection::at_byte(&d, 26);
        let layer = &d.layers[s.layer.unwrap()];
        assert_eq!(layer.protocol, "IPv4");
        let field = &layer.fields[s.field.unwrap()];
        assert_eq!(field.value, "10.0.0.1");
        assert_eq!(s.range(&d), Some(26..30));
    }
}
