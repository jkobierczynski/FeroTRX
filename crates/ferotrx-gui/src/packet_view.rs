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

/// Offset, hex and ASCII columns, 16 bytes a row.
pub fn hex(ui: &mut egui::Ui, d: &Decoded, bytes: &[u8], sel: &mut Selection) {
    let range = sel.range(d).unwrap_or(0..0);
    let hi_bg = ui.visuals().selection.bg_fill;
    let hi_fg = ui.visuals().selection.stroke.color;
    let weak = ui.visuals().weak_text_color();
    let rows = bytes.len().div_ceil(16);
    let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
    egui::ScrollArea::vertical()
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
                            _ => "  ".into(),
                        };
                        let mut t = RichText::new(text).monospace();
                        if range.contains(&i) {
                            t = t.background_color(hi_bg).color(hi_fg);
                        }
                        if i < end {
                            if ui
                                .add(egui::Label::new(t).sense(egui::Sense::click()))
                                .clicked()
                            {
                                *sel = Selection::at_byte(d, i);
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
                        if range.contains(&i) {
                            t = t.background_color(hi_bg).color(hi_fg);
                        } else if c == '.' {
                            t = t.color(weak);
                        }
                        ui.label(t);
                    }
                });
            }
        });
}

/// Colors for run states in tables.
pub fn state_color(ui: &egui::Ui, running: bool, failed: bool) -> Color32 {
    if failed {
        ui.visuals().error_fg_color
    } else if running {
        Color32::from_rgb(0x2e, 0xa0, 0x43)
    } else {
        ui.visuals().weak_text_color()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
