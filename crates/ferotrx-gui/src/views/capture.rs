//! The Capture tab: open a pcap or pcapng file on this computer, list its
//! packets, look at one in the packet view, and turn packets into an
//! editable stream for the selected port.

use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use ferotrx_core::Capture;
use ferotrx_packet::{decode, format_layers, import, Decoded};

use crate::app::{FeroApp, Tab};
use crate::model::{Pacing, StreamDraft};
use crate::packet_view::{self, Selection};

#[derive(Default)]
pub struct CaptureState {
    pub path: String,
    pub capture: Option<Capture>,
    pub error: Option<String>,
    /// Decoded packets, filled as rows are shown.
    decoded: Vec<Option<Decoded>>,
    pub selected: Option<usize>,
    pub sel: Selection,
    /// Which packets to take into a stream.
    pub marked: Vec<bool>,
}

impl CaptureState {
    pub fn open(&mut self) {
        match Capture::from_path(self.path.trim()) {
            Ok(c) => {
                self.decoded = vec![None; c.len()];
                self.marked = vec![false; c.len()];
                self.capture = Some(c);
                self.error = None;
                self.selected = None;
            }
            Err(e) => {
                self.capture = None;
                self.error = Some(format!("{}: {e}", self.path));
            }
        }
    }

    fn decoded(&mut self, n: usize) -> Option<&Decoded> {
        let c = self.capture.as_ref()?;
        if self.decoded[n].is_none() {
            self.decoded[n] = Some(decode(c.linktype, &c.packets[n].data));
        }
        self.decoded[n].as_ref()
    }

    /// The marked packets.
    pub fn picked_marks(&self) -> Vec<usize> {
        (0..self.marked.len()).filter(|&i| self.marked[i]).collect()
    }

    /// The packets to import: the marked ones, else the selected one.
    pub fn picked(&self) -> Vec<usize> {
        let m: Vec<usize> = (0..self.marked.len()).filter(|&i| self.marked[i]).collect();
        if m.is_empty() {
            self.selected.into_iter().collect()
        } else {
            m
        }
    }

    /// A stream with the picked packets as editable layers.
    pub fn to_stream(&self, name: String) -> Result<(StreamDraft, Vec<String>), String> {
        let c = self.capture.as_ref().ok_or("no capture open")?;
        let picked = self.picked();
        if picked.is_empty() {
            return Err("select a packet, or tick the ones to take".into());
        }
        let mut notes = Vec::new();
        let mut packets = Vec::new();
        for n in picked {
            let im = import(c.linktype, &c.packets[n].data).ok_or_else(|| {
                format!(
                    "link type {} cannot be rebuilt (only Ethernet and raw IP)",
                    c.linktype
                )
            })?;
            notes.extend(im.notes.iter().map(|x| format!("packet {}: {x}", n + 1)));
            packets.push(format_layers(&im.layers));
        }
        Ok((
            StreamDraft {
                name,
                packets,
                pacing: Pacing::Rate,
                rate: "10pps".into(),
                ..Default::default()
            },
            notes,
        ))
    }
}

impl FeroApp {
    pub fn capture_tab(&mut self, ui: &mut egui::Ui) {
        let mut to_stream = false;
        let mut browse = false;
        let has_port = self.sel_port.is_some();
        let cs = &mut self.capture;
        ui.horizontal(|ui| {
            ui.label("Capture on this computer");
            let r = ui.add(
                egui::TextEdit::singleline(&mut cs.path)
                    .hint_text("examples/web.pcap")
                    .desired_width(360.0),
            );
            if ui.button("Browse…").clicked() {
                browse = true;
            }
            if ui.button("Open").clicked()
                || (r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
            {
                cs.open();
            }
            if let Some(c) = &cs.capture {
                ui.weak(format!(
                    "{} packets, {} bytes, {:.3} s",
                    c.len(),
                    c.total_bytes(),
                    c.duration().as_secs_f64()
                ));
            }
        });
        if browse {
            let current = cs.path.clone();
            self.files.pick(
                crate::files::Target::Capture,
                "Open a capture",
                crate::files::Kind::Capture,
                &current,
            );
        }
        let cs = &mut self.capture;
        if let Some(e) = &cs.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        let Some(cap) = &cs.capture else {
            ui.weak("Open a pcap or pcapng file to inspect it. Packets can be taken into a stream and edited layer by layer.");
            return;
        };
        let count = cap.len();
        let t0 = cap.packets.first().map(|p| p.timestamp).unwrap_or_default();
        let times: Vec<f64> = cap
            .packets
            .iter()
            .map(|p| p.timestamp.saturating_sub(t0).as_secs_f64())
            .collect();
        let lens: Vec<usize> = cap.packets.iter().map(|p| p.data.len()).collect();

        ui.horizontal(|ui| {
            let picked = cs.picked().len();
            ui.add_enabled_ui(picked > 0 && has_port, |ui| {
                if ui
                    .button(format!("Make a stream of {picked} packet(s)"))
                    .on_hover_text("Adds a stream to the selected port; edit it in the Streams tab")
                    .clicked()
                {
                    to_stream = true;
                }
            });
            if !has_port {
                ui.weak("(pick a port on the left first)");
            }
            if ui.small_button("Untick all").clicked() {
                cs.marked.iter_mut().for_each(|m| *m = false);
            }
        });
        ui.separator();

        let row_h = 18.0;
        let mut clicked = None;
        // The packet list above the packet; the line between them drags.
        let h = ui.available_height();
        egui::TopBottomPanel::top("capture-list")
            .resizable(true)
            .frame(egui::Frame::NONE)
            .default_height((h * 0.45).max(120.0))
            .height_range(80.0..=(h - 80.0).max(90.0))
            .show_inside(ui, |ui| {
                // Keep the panel's height: the table alone would shrink it.
                ui.set_min_height(ui.available_height());
                // Clicks on a row select it, rather than starting a text selection.
                ui.style_mut().interaction.selectable_labels = false;
                let list_h = (ui.available_height() - row_h - 4.0).max(row_h);
                TableBuilder::new(ui)
                    .id_salt("capture-table")
                    .striped(true)
                    .sense(egui::Sense::click())
                    .auto_shrink([false, false])
                    .max_scroll_height(list_h)
                    .min_scrolled_height(list_h)
                    .column(Column::exact(22.0))
                    .column(Column::initial(50.0))
                    .column(Column::initial(80.0))
                    .column(Column::initial(150.0).resizable(true).clip(true))
                    .column(Column::initial(150.0).resizable(true).clip(true))
                    .column(Column::initial(70.0))
                    .column(Column::initial(50.0))
                    .column(Column::remainder().clip(true))
                    .header(row_h, |mut h| {
                        for t in [
                            "",
                            "No.",
                            "Time",
                            "Source",
                            "Destination",
                            "Protocol",
                            "Length",
                            "Info",
                        ] {
                            h.col(|ui| {
                                ui.strong(t);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(row_h, count, |mut row| {
                            let n = row.index();
                            row.set_selected(cs.selected == Some(n));
                            row.col(|ui| {
                                ui.checkbox(&mut cs.marked[n], "");
                            });
                            row.col(|ui| {
                                ui.label((n + 1).to_string());
                            });
                            row.col(|ui| {
                                ui.label(format!("{:.6}", times[n]));
                            });
                            let d = cs.decoded(n).cloned().unwrap_or_default();
                            row.col(|ui| {
                                ui.label(&d.source);
                            });
                            row.col(|ui| {
                                ui.label(&d.destination);
                            });
                            row.col(|ui| {
                                let mut t = RichText::new(d.protocol);
                                if !d.problems.is_empty() {
                                    t = t.color(ui.visuals().warn_fg_color);
                                }
                                ui.label(t);
                            });
                            row.col(|ui| {
                                ui.label(lens[n].to_string());
                            });
                            row.col(|ui| {
                                ui.label(&d.info);
                            });
                            if row.response().clicked() {
                                clicked = Some(n);
                            }
                        });
                    });
            });
        if let Some(n) = clicked {
            cs.selected = Some(n);
            cs.sel = Selection::default();
        }
        ui.add_space(4.0);
        if let Some(n) = cs.selected.filter(|&n| n < count) {
            let d = cs.decoded(n).cloned().unwrap_or_default();
            let data = cs
                .capture
                .as_ref()
                .map(|c| c.packets[n].data.clone())
                .unwrap_or_default();
            let w = ui.available_width();
            egui::SidePanel::left("capture-tree")
                .resizable(true)
                .frame(egui::Frame::NONE)
                .default_width(w * 0.45)
                .width_range(200.0..=(w - 200.0).max(220.0))
                .show_inside(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("cap-tree")
                        .auto_shrink([false, false])
                        .show(ui, |ui| packet_view::tree(ui, &d, &mut cs.sel));
                });
            ui.add_space(2.0);
            packet_view::hex(ui, &d, &data, &mut cs.sel);
        }

        if to_stream {
            self.capture_to_stream();
        }
    }

    fn capture_to_stream(&mut self) {
        let (i, Some(port)) = (self.sel_server, self.sel_port.clone()) else {
            return;
        };
        let key = self.port_key(i, &port);
        let base = std::path::Path::new(self.capture.path.trim())
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "capture".into());
        let work = self.port_work(i, &port);
        let name = work.profile.unique_name(&base);
        match self.capture.to_stream(name) {
            Ok((s, notes)) => {
                let work = self.port_work(i, &port);
                work.profile.streams.push(s);
                let n = work.profile.streams.len() - 1;
                self.editor = crate::views::EditorState {
                    stream: Some(n),
                    ..Default::default()
                };
                self.tab = Tab::Streams;
                self.info(&key, "new stream from the capture; checksums and lengths are computed again on build");
                for note in notes {
                    self.info(&key, note);
                }
            }
            Err(e) => self.error(&key, e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_captures_import_to_the_same_bytes() {
        // Every packet of the sample captures turns into layers that build
        // back to the captured bytes, unless the import says what it dropped.
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples");
        for name in ["web.pcap", "dns.pcap", "http.pcap", "dns-lookups.pcap"] {
            let mut cs = CaptureState {
                path: format!("{dir}/{name}"),
                ..Default::default()
            };
            cs.open();
            let cap = cs
                .capture
                .as_ref()
                .unwrap_or_else(|| panic!("{name}: {:?}", cs.error));
            let n = cap.len();
            let mut exact = 0;
            for i in 0..n {
                cs.selected = Some(i);
                let (s, notes) = cs.to_stream("x".into()).unwrap();
                let built = crate::views::streams::build(&s.packets[0])
                    .unwrap_or_else(|e| panic!("{name} #{}: {e}: {}", i + 1, s.packets[0]));
                let cap = cs.capture.as_ref().unwrap();
                if notes.is_empty() {
                    assert_eq!(
                        built.bytes,
                        cap.packets[i].data,
                        "{name} #{}: {}",
                        i + 1,
                        s.packets[0]
                    );
                    exact += 1;
                }
            }
            assert!(exact > 0, "{name}: no packet imported exactly");
        }
    }
}
