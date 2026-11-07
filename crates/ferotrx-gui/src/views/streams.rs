//! The Streams tab: the selected port's toolbar, its stream table and the
//! stream editor (protocol layers, stream control, variable fields, packet
//! view).

use std::path::Path;

use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use ferotrx_packet::{decode, format_layers, parse_layers, Decoded, PacketSpec, RawLayer};

use crate::app::{FeroApp, Status};
use crate::files::{Kind, Target};
use crate::model::{Latency, Pacing, PortKind, ProfileDraft, SourceKind, StreamDraft};
use crate::packet_view::{self, state_color, Selection};
use crate::protocols::{Category, Registry};

/// What the stream editor has open.
#[derive(Default)]
pub struct EditorState {
    pub stream: Option<usize>,
    pub packet: usize,
    /// A layer to open in the layer list (just added or moved).
    pub layer: Option<usize>,
    /// Where "add layer" inserts; the end when `None`.
    pub insert_at: Option<usize>,
    pub page: Page,
    pub sel: Selection,
    /// The last packet built, by its text.
    pub(crate) cache: Option<(String, Result<Built, String>)>,
    /// A stream table filter.
    pub filter: String,
    /// True when the server is on this computer, so its files can be
    /// picked with a dialog. Set each frame.
    pub server_local: bool,
    /// "Browse…" was pressed for the stream's capture.
    pub browse_pcap: bool,
    /// The bytes of the packet view take typing.
    pub hex_edit: bool,
    pub cursor: crate::packet_view::HexCursor,
    /// What the last byte edit could not carry over into the layers.
    pub hex_notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Page {
    #[default]
    Protocols,
    Control,
    Variable,
    Toml,
}

/// A packet built from its text, and decoded again for the packet view.
pub struct Built {
    pub bytes: Vec<u8>,
    pub decoded: Decoded,
    pub linktype: u32,
}

/// Builds and decodes a packet in the text form.
pub fn build(spec: &str) -> Result<Built, String> {
    let p: PacketSpec = spec.parse().map_err(|e: ferotrx_packet::BuildError| e.0)?;
    let bytes = p.build().map_err(|e| e.0)?;
    let linktype = p.linktype().map_err(|e| e.0)?;
    let decoded = decode(linktype, &bytes);
    Ok(Built {
        bytes,
        decoded,
        linktype,
    })
}

/// The text form of edited bytes: the layers they decode to, with lengths
/// and checksums left to the builder. Returns the text and what could not
/// be carried over.
pub fn bytes_to_spec(linktype: u32, bytes: &[u8]) -> Result<(String, Vec<String>), String> {
    if bytes.is_empty() {
        return Err("a packet needs at least one byte".into());
    }
    let im = ferotrx_packet::import(linktype, bytes)
        .ok_or_else(|| format!("bytes of link type {linktype} cannot be edited"))?;
    Ok((format_layers(&im.layers), im.notes))
}

/// Checks one stream as `ferotrx run` would read it.
pub fn check_stream(s: &StreamDraft) -> Result<(), String> {
    let p = ProfileDraft {
        streams: vec![StreamDraft {
            enabled: true,
            ..s.clone()
        }],
        output: None,
    };
    ferotrx_core::Profile::from_toml(&p.to_toml(true), Path::new("."))
        .map(drop)
        .map_err(|e| e.to_string())
}

enum Action {
    Start,
    Stop(u64),
    Check,
    Open,
    Save,
}

impl FeroApp {
    pub fn streams_tab(&mut self, ui: &mut egui::Ui) {
        let i = self.sel_server;
        let Some(port) = self.sel_port.clone() else {
            welcome(
                ui,
                self.servers.get(i).map(|s| &s.status),
                self.servers.get(i).is_some_and(|s| s.settings.local),
            );
            return;
        };
        if i >= self.servers.len() {
            return;
        }
        let mut action = None;
        self.port_toolbar(ui, i, &port, &mut action);
        ui.separator();

        let key = self.port_key(i, &port);
        let work = self.work.ports.entry(key).or_default();
        let streams = &mut work.profile.streams;
        let ed = &mut self.editor;
        ed.server_local = self.servers[i].is_local();
        // The table and the editor share the tab; the line between them drags.
        let h = ui.available_height();
        egui::Panel::top("stream-table")
            .resizable(true)
            .frame(egui::Frame::NONE)
            .default_size((h * 0.3).clamp(110.0, 260.0))
            .size_range(70.0..=(h - 120.0).max(80.0))
            .show(ui, |ui| {
                // Keep the panel's height: the table alone would shrink it.
                ui.set_min_height(ui.available_height());
                stream_table(ui, streams, ed, &mut action)
            });
        ui.add_space(4.0);
        match ed.stream {
            Some(s) if s < streams.len() => {
                stream_editor(ui, &self.registry, ed, &mut streams[s]);
            }
            _ => {
                ui.weak("Select a stream to edit it, or add one with “+ Stream”.");
            }
        }

        match action {
            Some(Action::Start) => self.start_port(i, &port),
            Some(Action::Stop(id)) => self.stop_run(i, "run", id),
            Some(Action::Check) => self.check_port(i, &port),
            Some(Action::Open) => {
                let dir = self.port_work(i, &port).base_dir.clone();
                self.files
                    .pick(Target::OpenProfile, "Open a profile", Kind::Profile, &dir);
            }
            Some(Action::Save) => {
                let dir = self.port_work(i, &port).base_dir.clone();
                let name = format!("{}.toml", port.profile_name());
                self.files.save(
                    Target::SaveProfile,
                    "Save the streams as a profile",
                    Kind::Profile,
                    &dir,
                    &name,
                );
            }
            None => {}
        }
        if std::mem::take(&mut self.editor.browse_pcap) {
            if let Some(s) = self.editor.stream {
                let work = self.port_work(i, &port);
                let current = match work.profile.streams.get(s) {
                    Some(st) if !st.pcap.is_empty() => {
                        crate::files::absolute(&std::path::Path::new(&work.base_dir).join(&st.pcap))
                            .display()
                            .to_string()
                    }
                    _ => work.base_dir.clone(),
                };
                self.files.pick(
                    Target::ReplayPcap(s),
                    "Capture to replay",
                    Kind::Capture,
                    &current,
                );
            }
        }
    }

    fn port_toolbar(
        &mut self,
        ui: &mut egui::Ui,
        i: usize,
        port: &PortKind,
        action: &mut Option<Action>,
    ) {
        let connected = self.servers[i].status == Status::Connected;
        let can = self.servers[i].can_operate();
        let backends = self.servers[i]
            .info
            .as_ref()
            .map(|i| i.backends.clone())
            .unwrap_or_default();
        let ifaces: Vec<String> = self.servers[i]
            .interfaces
            .iter()
            .map(|x| x.name.clone())
            .collect();
        let run = self.port_run(i, port).cloned();
        let addr = self.servers[i].settings.addr.clone();
        let local = self.servers[i].is_local();
        let file_out = &mut self.work.file_out;
        if let PortKind::File = port {
            let mut browse = false;
            ui.horizontal(|ui| {
                ui.label("Output file on the server");
                ui.add(
                    egui::TextEdit::singleline(file_out).hint_text(crate::model::DEFAULT_FILE_OUT),
                )
                .on_hover_text("A relative path is in the server's data directory (where it was started, or --data-dir)");
                browse = ui
                    .add_enabled(local, egui::Button::new("Browse…"))
                    .on_disabled_hover_text("The server is on another computer: type a path there")
                    .clicked();
            });
            if browse {
                let current = file_out.clone();
                self.files.save(
                    Target::FileOut,
                    "Pcap file the port writes",
                    Kind::Capture,
                    &current,
                    crate::model::DEFAULT_FILE_OUT,
                );
            }
        }
        let key = format!("{}|{}", self.servers[i].settings.address(), port.key());
        let cfg = &mut self.work.ports.entry(key).or_default().config;

        ui.horizontal_wrapped(|ui| {
            ui.heading(port.label());
            ui.label(RichText::new(format!("on {addr}")).weak());
            ui.separator();
            let running = run.as_ref().is_some_and(|r| r.state.is_running());
            ui.add_enabled_ui(connected && can && !running, |ui| {
                if ui
                    .button(RichText::new("▶ Start").strong())
                    .on_hover_text("Send the enabled streams on this port")
                    .clicked()
                {
                    *action = Some(Action::Start);
                }
            });
            ui.add_enabled_ui(connected && can && running, |ui| {
                if ui.button("■ Stop").clicked() {
                    if let Some(r) = &run {
                        *action = Some(Action::Stop(r.id));
                    }
                }
            });
            ui.add_enabled_ui(connected && can, |ui| {
                if ui
                    .button("Check")
                    .on_hover_text("Load the streams on the server without sending")
                    .clicked()
                {
                    *action = Some(Action::Check);
                }
            });
            ui.separator();
            if ui
                .button("Open…")
                .on_hover_text("Read a profile file into this port")
                .clicked()
            {
                *action = Some(Action::Open);
            }
            if ui
                .button("Save…")
                .on_hover_text("Write this port's streams as a profile")
                .clicked()
            {
                *action = Some(Action::Save);
            }
            if let Some(r) = &run {
                ui.separator();
                let failed = r.error.is_some();
                ui.colored_label(
                    state_color(ui, r.state.is_running(), failed),
                    format!(
                        "run {}: {:?} · {} pkts · {:.0} pps · {:.2} Mbit/s",
                        r.id, r.state, r.total.packets, r.total.pps, r.total.mbps
                    ),
                )
                .on_hover_text(r.error.clone().unwrap_or_else(|| r.output.clone()));
            }
        });

        egui::CollapsingHeader::new("Port settings")
            .id_salt("port-settings")
            .show(ui, |ui| {
                egui::Grid::new("port-cfg").num_columns(4).spacing([12.0, 4.0]).show(ui, |ui| {
                    if matches!(port, PortKind::Interface(_)) {
                        ui.label("Backend");
                        egui::ComboBox::from_id_salt("backend")
                            .selected_text(if cfg.backend.is_empty() { "default" } else { &cfg.backend })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut cfg.backend, String::new(), "default");
                                for b in &backends {
                                    ui.selectable_value(&mut cfg.backend, b.clone(), b);
                                }
                            });
                        if cfg.backend == "af_xdp" {
                            ui.label("AF_XDP mode");
                            egui::ComboBox::from_id_salt("xdp")
                                .selected_text(if cfg.xdp_mode.is_empty() { "auto" } else { &cfg.xdp_mode })
                                .show_ui(ui, |ui| {
                                    for m in ["", "copy", "zerocopy"] {
                                        ui.selectable_value(
                                            &mut cfg.xdp_mode,
                                            m.to_string(),
                                            if m.is_empty() { "auto" } else { m },
                                        );
                                    }
                                });
                        } else {
                            ui.label("");
                            ui.label("");
                        }
                        ui.end_row();
                    }
                    ui.label("Workers");
                    let mut w = cfg.workers.unwrap_or(1);
                    if ui
                        .add(egui::DragValue::new(&mut w).range(1..=64))
                        .on_hover_text("Engine threads (cores) for this run; with AF_XDP one queue each")
                        .changed()
                    {
                        cfg.workers = (w > 1).then_some(w);
                    }
                    ui.label("");
                    ui.label("");
                    ui.end_row();
                    ui.label("Duration");
                    ui.add(egui::TextEdit::singleline(&mut cfg.duration).hint_text("until stopped").desired_width(100.0))
                        .on_hover_text("30s, 5m, …");
                    ui.label("Rate for all streams");
                    ui.add(egui::TextEdit::singleline(&mut cfg.rate).hint_text("each stream's own").desired_width(100.0))
                        .on_hover_text("1000pps, 20mbps, 2x, topspeed");
                    ui.end_row();
                    ui.label("Receive on");
                    egui::ComboBox::from_id_salt("rx")
                        .selected_text(if cfg.rx_iface.is_empty() { "nothing" } else { &cfg.rx_iface })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut cfg.rx_iface, String::new(), "nothing");
                            for n in &ifaces {
                                ui.selectable_value(&mut cfg.rx_iface, n.clone(), n);
                            }
                        })
                        .response
                        .on_hover_text("An interface of the same server that sees the traffic come back: loss and latency per stream");
                    ui.checkbox(&mut cfg.latency, "Signatures on all streams")
                        .on_hover_text("For a receiver on another machine (ferotrx rx)");
                    ui.end_row();
                    ui.label("Impairments");
                    ui.add(egui::TextEdit::singleline(&mut cfg.impair).hint_text("each stream's own").desired_width(260.0))
                        .on_hover_text("What a bad link does to every stream: delay=20ms jitter=5ms loss=1% loss_burst=3 duplicate=0.1% reorder=0.5% corrupt=0.01% rate=10mbit mtu=1400 seed=1; none turns the streams' own off");
                    ui.end_row();
                });
            });
    }

    /// Draws the file dialog and puts what it picked where it belongs.
    pub fn file_dialog(&mut self, ctx: &egui::Context) {
        let Some((target, path)) = self.files.update(ctx) else {
            return;
        };
        let shown = path.display().to_string();
        let i = self.sel_server;
        match target {
            Target::Capture => {
                self.capture.path = shown;
                self.capture.open();
            }
            Target::StatefulProfile => {
                self.stateful.path = shown;
                self.stateful.check = None;
            }
            Target::Pem(n) => {
                if let Some(s) = &mut self.add_server {
                    match n {
                        0 => s.ca = shown,
                        1 => s.cert = shown,
                        _ => s.key = shown,
                    }
                }
            }
            Target::FileOut => self.work.file_out = shown,
            Target::OpenWorkspace => self.open_workspace(&path),
            Target::OpenTheme => self.appearance.open_file(&path),
            Target::SaveTheme => self.appearance.save_file(&path),
            Target::OpenAppProfile | Target::SaveAppProfile => self.apps_file(target, &path),
            Target::OpenBench | Target::SaveBench | Target::BenchReport => {
                self.bench_file(target, &path)
            }
            Target::OpenY1564 | Target::SaveY1564 | Target::Y1564Report => {
                self.y1564_file(target, &path)
            }
            Target::CompareReport { .. } | Target::SaveComparison => {
                self.compare_file(target, &path)
            }
            Target::SaveWorkspace => {
                let ctx = ctx.clone();
                self.save_workspace(&path, &ctx);
            }
            Target::OpenScenario | Target::SaveScenario | Target::ScenarioReport { .. } => {
                self.scenario_file(target, &path)
            }
            Target::ReplayPcap(n) => {
                let Some(port) = self.sel_port.clone().filter(|_| i < self.servers.len()) else {
                    return;
                };
                let work = self.port_work(i, &port);
                let rel = crate::files::relative_to(&path, &work.base_dir);
                if let Some(s) = work.profile.streams.get_mut(n) {
                    s.pcap = rel;
                }
            }
            Target::OpenProfile | Target::SaveProfile => {
                let Some(port) = self.sel_port.clone().filter(|_| i < self.servers.len()) else {
                    return;
                };
                let save = target == Target::SaveProfile;
                self.profile_file(i, &port, &path, save);
            }
        }
    }

    /// Opens a profile file into a port, or saves the port's streams to one.
    pub fn profile_file(&mut self, i: usize, port: &PortKind, path: &std::path::Path, save: bool) {
        let key = self.port_key(i, port);
        let work = self.port_work(i, port);
        let shown = path.display();
        let outcome = if save {
            std::fs::write(path, work.profile.to_toml(false))
                .map(|_| format!("saved {shown}"))
                .map_err(|e| format!("{shown}: {e}"))
        } else {
            std::fs::read_to_string(path)
                .map_err(|e| format!("{shown}: {e}"))
                .and_then(|t| ProfileDraft::from_toml(&t).map_err(|e| format!("{shown}: {e}")))
                .map(|d| {
                    let n = d.streams.len();
                    work.profile = d;
                    format!("opened {shown} ({n} streams)")
                })
        };
        if outcome.is_ok() {
            work.base_dir = crate::files::folder_of(path);
        }
        match outcome {
            Ok(m) => {
                if !save {
                    let n = self.port_work(i, port).profile.streams.len();
                    self.editor = EditorState {
                        stream: (n > 0).then_some(0),
                        ..Default::default()
                    };
                }
                self.info(&key, m)
            }
            Err(e) => self.error(&key, e),
        }
    }
}

fn welcome(ui: &mut egui::Ui, status: Option<&Status>, local: bool) {
    ui.vertical_centered(|ui| {
        ui.add_space(40.0);
        ui.heading("Pick a port on the left");
        ui.add_space(8.0);
        match status {
            Some(Status::Connected) => {
                ui.label("Each interface of the server is a port. “file” writes a pcap on the server, “null” only counts: both need no privileges.");
            }
            _ if local => {
                ui.label("Click Start under “This computer”: the GUI starts a server on this computer and stops it when you stop it or close the GUI.");
                ui.label("To send from another machine, add its server with Add server… (docs: remote control).");
            }
            _ => {
                ui.label("Connect to a FeroTRX control server first. On the machine that sends:");
                ui.code("sudo ferotrx serve            # this machine, 127.0.0.1:4510");
                ui.label("For another machine, with TLS (docs: remote control):");
                ui.code("ferotrx certs pki --server <this host> --client me\nsudo ferotrx serve -l 0.0.0.0:4510 --tls-cert pki/server.pem --tls-key pki/server-key.pem --client-ca pki/ca.pem");
            }
        }
    });
}

fn stream_table(
    ui: &mut egui::Ui,
    streams: &mut Vec<StreamDraft>,
    ed: &mut EditorState,
    action: &mut Option<Action>,
) {
    let _ = action;
    ui.horizontal(|ui| {
        if ui.button("+ Stream").clicked() {
            let p = ProfileDraft {
                streams: streams.clone(),
                output: None,
            };
            let s = StreamDraft {
                name: p.unique_name("stream"),
                ..Default::default()
            };
            streams.push(s);
            select(ed, Some(streams.len() - 1));
        }
        let sel = ed.stream.filter(|&s| s < streams.len());
        ui.add_enabled_ui(sel.is_some(), |ui| {
            if ui.button("Duplicate").clicked() {
                if let Some(s) = sel {
                    let mut copy = streams[s].clone();
                    let p = ProfileDraft {
                        streams: streams.clone(),
                        output: None,
                    };
                    copy.name = p.unique_name(&copy.name);
                    streams.insert(s + 1, copy);
                    select(ed, Some(s + 1));
                }
            }
            if ui.button("Delete").clicked() {
                if let Some(s) = sel {
                    streams.remove(s);
                    select(ed, None);
                }
            }
            if ui.button("⏶").on_hover_text("Move up").clicked() {
                if let Some(s) = sel.filter(|&s| s > 0) {
                    streams.swap(s, s - 1);
                    ed.stream = Some(s - 1);
                }
            }
            if ui.button("⏷").on_hover_text("Move down").clicked() {
                if let Some(s) = sel.filter(|&s| s + 1 < streams.len()) {
                    streams.swap(s, s + 1);
                    ed.stream = Some(s + 1);
                }
            }
        });
        ui.separator();
        let enabled = streams.iter().filter(|s| s.enabled).count();
        ui.weak(format!("{} streams, {enabled} enabled", streams.len()));
    });

    let row_h = 20.0;
    let mut clicked = None;
    {
        {
            // Clicks on a row select it, rather than starting a text selection.
            ui.style_mut().interaction.selectable_labels = false;
            let max_h = (ui.available_height() - row_h - 4.0).max(row_h);
            TableBuilder::new(ui)
                .id_salt("streams")
                .striped(true)
                .sense(egui::Sense::click())
                .auto_shrink([false, false])
                .max_scroll_height(max_h)
                .min_scrolled_height(max_h)
                .column(Column::exact(24.0))
                .column(Column::initial(120.0).resizable(true))
                .column(Column::initial(360.0).resizable(true).clip(true))
                .column(Column::initial(100.0).resizable(true))
                .column(Column::initial(70.0))
                .column(Column::remainder())
                .header(row_h, |mut h| {
                    for t in ["", "Name", "Packets", "Pacing", "Loops", "Extras"] {
                        h.col(|ui| {
                            ui.strong(t);
                        });
                    }
                })
                .body(|mut body| {
                    for (n, s) in streams.iter_mut().enumerate() {
                        body.row(row_h, |mut row| {
                            row.set_selected(ed.stream == Some(n));
                            row.col(|ui| {
                                ui.checkbox(&mut s.enabled, "")
                                    .on_hover_text("Send this stream");
                            });
                            row.col(|ui| {
                                ui.label(&s.name);
                            });
                            row.col(|ui| {
                                ui.label(RichText::new(s.source_summary()).monospace());
                            });
                            row.col(|ui| {
                                ui.label(s.pacing_summary());
                            });
                            row.col(|ui| {
                                ui.label(if s.loops == 0 {
                                    "∞".into()
                                } else {
                                    s.loops.to_string()
                                });
                            });
                            row.col(|ui| {
                                let mut tags = Vec::new();
                                if s.latency != Latency::Off {
                                    tags.push("latency".to_string());
                                }
                                if !s.vary.is_empty() {
                                    tags.push(format!("vary ×{}", s.vary.len()));
                                }
                                if !s.rewrite.is_empty() {
                                    tags.push(format!("rewrite ×{}", s.rewrite.len()));
                                }
                                if !s.model.is_empty() {
                                    tags.push(s.model.clone());
                                }
                                if !s.sizes.is_empty() {
                                    tags.push(format!("sizes {}", s.sizes));
                                }
                                ui.weak(tags.join(", "));
                            });
                            if row.response().clicked() {
                                clicked = Some(n);
                            }
                        });
                    }
                });
        }
    }
    if let Some(n) = clicked {
        if ed.stream != Some(n) {
            select(ed, Some(n));
        }
    }
}

fn select(ed: &mut EditorState, s: Option<usize>) {
    let page = ed.page;
    *ed = EditorState {
        stream: s,
        page,
        ..Default::default()
    };
}

fn stream_editor(
    ui: &mut egui::Ui,
    registry: &Registry,
    ed: &mut EditorState,
    s: &mut StreamDraft,
) {
    ui.horizontal(|ui| {
        ui.label("Stream");
        ui.add(egui::TextEdit::singleline(&mut s.name).desired_width(160.0));
        ui.separator();
        for (p, label) in [
            (Page::Protocols, "Protocols"),
            (Page::Control, "Stream control"),
            (Page::Variable, "Variable fields"),
            (Page::Toml, "Profile text"),
        ] {
            ui.selectable_value(&mut ed.page, p, label);
        }
    });
    ui.separator();
    match ed.page {
        Page::Protocols => protocols_page(ui, registry, ed, s),
        Page::Control => control_page(ui, s),
        Page::Variable => variable_page(ui, s),
        Page::Toml => {
            let text = ProfileDraft {
                streams: vec![s.clone()],
                output: None,
            }
            .to_toml(false);
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut text.as_str())
                        .code_editor()
                        .desired_width(f32::INFINITY),
                );
            });
        }
    }
}

fn protocols_page(
    ui: &mut egui::Ui,
    registry: &Registry,
    ed: &mut EditorState,
    s: &mut StreamDraft,
) {
    if s.source == SourceKind::Pcap {
        ui.label("This stream replays a capture on the server:");
        ui.horizontal(|ui| {
            ui.label("pcap");
            ui.add(egui::TextEdit::singleline(&mut s.pcap).desired_width(360.0))
                .on_hover_text("A relative path starts at the folder of the profile file, or the server's data directory");
            if ui
                .add_enabled(ed.server_local, egui::Button::new("Browse…"))
                .on_disabled_hover_text("The server is on another computer: type a path there")
                .clicked()
            {
                ed.browse_pcap = true;
            }
        });
        if ui.button("Build packets instead").clicked() {
            s.source = SourceKind::Packets;
            if s.packets.is_empty() {
                s.packets.push(StreamDraft::default().packets[0].clone());
            }
            if s.pacing == Pacing::Original {
                s.pacing = Pacing::Rate;
            }
        }
        return;
    }
    if s.packets.is_empty() {
        s.packets.push(StreamDraft::default().packets[0].clone());
    }
    ed.packet = ed.packet.min(s.packets.len() - 1);

    // The packets of the stream, sent in turn.
    ui.horizontal_wrapped(|ui| {
        ui.label("Packets");
        for n in 0..s.packets.len() {
            if ui
                .selectable_label(ed.packet == n, format!("#{}", n + 1))
                .clicked()
            {
                ed.packet = n;
                ed.layer = None;
                ed.sel = Selection::default();
            }
        }
        if ui
            .small_button("+")
            .on_hover_text("Add a copy of this packet")
            .clicked()
        {
            let copy = s.packets[ed.packet].clone();
            s.packets.insert(ed.packet + 1, copy);
            ed.packet += 1;
        }
        if s.packets.len() > 1
            && ui
                .small_button("✕")
                .on_hover_text("Remove this packet")
                .clicked()
        {
            s.packets.remove(ed.packet);
            ed.packet = ed.packet.saturating_sub(1);
        }
        ui.separator();
        if ui
            .small_button("Replay a capture instead")
            .on_hover_text("Send a pcap file on the server")
            .clicked()
        {
            s.source = SourceKind::Pcap;
        }
    });

    let spec = &mut s.packets[ed.packet];
    // Layers on the left, the packet view on the right; the line between drags.
    let w = ui.available_width();
    egui::Panel::left("layer-editor")
        .resizable(true)
        .frame(egui::Frame::NONE)
        .default_size((w * 0.5).max(300.0))
        .size_range(240.0..=(w - 240.0).max(260.0))
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("layers")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    layer_editor(ui, registry, ed, spec);
                });
        });
    ui.add_space(2.0);
    packet_pane(ui, ed, spec);
}

/// The layer stack and the selected layer's form. Writes changes back to `spec`.
fn layer_editor(ui: &mut egui::Ui, registry: &Registry, ed: &mut EditorState, spec: &mut String) {
    ui.label("Text form");
    let r = ui.add(
        egui::TextEdit::multiline(spec)
            .code_editor()
            .desired_rows(2)
            .desired_width(f32::INFINITY),
    );
    if r.changed() {
        ed.sel = Selection::default();
    }
    let mut layers = match parse_layers(spec) {
        Ok(l) => l,
        Err(e) => {
            ui.colored_label(ui.visuals().error_fg_color, e.0);
            return;
        }
    };
    ui.add_space(6.0);
    ui.strong("Protocol layers");
    let mut changed = false;
    let mut op: Option<(usize, i32)> = None; // (index, -1 up / 1 down / 0 remove)
    let open = ed.layer.take().filter(|&l| l < layers.len());
    for (n, l) in layers.iter_mut().enumerate() {
        let e = registry.editor(&l.name);
        let bad = l.to_layer().err();
        let id = ui.id().with(("layer", n, l.name.clone()));
        let mut state =
            egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, false);
        if open == Some(n) {
            state.set_open(true);
        }
        state
            .show_header(ui, |ui| {
                let title = if e.name().is_empty() {
                    format!("{} (unknown)", l.name)
                } else {
                    e.title().to_string()
                };
                let mut t = RichText::new(format!("{}. {title}", n + 1)).strong();
                if bad.is_some() {
                    t = t.color(ui.visuals().error_fg_color);
                }
                ui.label(t);
                let mut text = l.to_string();
                if text.chars().count() > 48 {
                    text = text.chars().take(47).collect::<String>() + "…";
                }
                ui.add(egui::Label::new(RichText::new(text).monospace().weak().small()).truncate());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("✕").on_hover_text("Remove layer").clicked() {
                        op = Some((n, 0));
                    }
                    if ui.small_button("⏷").on_hover_text("Move down").clicked() {
                        op = Some((n, 1));
                    }
                    if ui.small_button("⏶").on_hover_text("Move up").clicked() {
                        op = Some((n, -1));
                    }
                    if ui
                        .small_button("+")
                        .on_hover_text("Insert a layer after this one")
                        .clicked()
                    {
                        op = Some((n, 2));
                    }
                });
            })
            .body(|ui| {
                ui.push_id(("layer-form", n), |ui| {
                    changed |= e.ui(ui, l);
                });
                if let Err(err) = l.to_layer() {
                    ui.colored_label(ui.visuals().error_fg_color, err.0);
                }
            });
    }
    if let Some((n, d)) = op {
        match d {
            0 => {
                layers.remove(n);
                ed.layer = None;
            }
            -1 if n > 0 => {
                layers.swap(n, n - 1);
                ed.layer = Some(n - 1);
            }
            1 if n + 1 < layers.len() => {
                layers.swap(n, n + 1);
                ed.layer = Some(n + 1);
            }
            2 => ed.insert_at = Some(n + 1),
            _ => {}
        }
        changed |= d != 2;
    }

    // Adding layers: what usually follows the last one, then every protocol.
    ui.horizontal_wrapped(|ui| {
        let at = ed.insert_at.unwrap_or(layers.len()).min(layers.len());
        if at < layers.len() {
            ui.label(format!("Insert after layer {at}:"));
            if ui.small_button("at the end").clicked() {
                ed.insert_at = None;
            }
        }
        let after = at.checked_sub(1).and_then(|p| layers.get(p));
        let next: &[&str] = match after {
            Some(l) => registry.editor(&l.name).next(),
            None => &["eth", "ipv4", "ipv6"],
        };
        let mut add: Option<RawLayer> = None;
        for n in next {
            if let Some(e) = registry.get(n) {
                if ui.small_button(format!("+ {}", e.title())).clicked() {
                    add = Some(e.new_layer());
                }
            }
        }
        ui.menu_button("+ Other layer", |ui| {
            for c in Category::ALL {
                let mut any = false;
                for e in registry.in_category(c) {
                    if !any {
                        ui.label(RichText::new(c.label()).weak());
                        any = true;
                    }
                    if ui.button(e.title()).clicked() {
                        add = Some(e.new_layer());
                        ui.close();
                    }
                }
            }
        });
        if let Some(l) = add {
            layers.insert(at, l);
            ed.layer = Some(at);
            ed.insert_at = None;
            changed = true;
        }
    });

    ui.label(
        RichText::new("Open a layer to edit it. Empty fields take the value shown in grey; lengths and checksums follow the layers unless set.")
            .small()
            .weak(),
    );
    if changed {
        *spec = format_layers(&layers);
        ed.sel = Selection::default();
    }
}

fn packet_pane(ui: &mut egui::Ui, ed: &mut EditorState, spec: &mut String) {
    let fresh = !matches!(&ed.cache, Some((t, _)) if t == spec);
    if fresh {
        ed.cache = Some((spec.clone(), build(spec)));
    }
    let Some((_, result)) = &ed.cache else {
        return;
    };
    let mut edited = None;
    match result {
        Err(e) => {
            ui.strong("Packet view");
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        Ok(b) => {
            ui.horizontal(|ui| {
                ui.strong("Packet view");
                ui.weak(format!("{} bytes", b.bytes.len()));
                if ui
                    .small_button("Copy hex")
                    .on_hover_text("The frame as hex, for raw(hex=...) or other tools")
                    .clicked()
                {
                    let h: String = b.bytes.iter().map(|x| format!("{x:02x}")).collect();
                    ui.ctx().copy_text(h);
                }
                ui.toggle_value(&mut ed.hex_edit, "✏ Edit bytes")
                    .on_hover_text(
                        "Click a byte and type hex digits over it. Arrows move; Delete, Backspace \
                     and Insert remove and add bytes; Esc stops. The layers follow the bytes, \
                     and lengths and checksums are computed again.",
                    );
            });
            if ed.hex_edit && !ed.hex_notes.is_empty() {
                for n in &ed.hex_notes {
                    ui.label(
                        RichText::new(format!("⚠ {n}"))
                            .small()
                            .color(ui.visuals().warn_fg_color),
                    );
                }
            }
            // The tree above the bytes; the line between them drags.
            let h = ui.available_height();
            egui::Panel::top("packet-tree")
                .resizable(true)
                .frame(egui::Frame::NONE)
                .default_size(h * 0.55)
                .size_range(60.0..=(h - 60.0).max(70.0))
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("tree")
                        .auto_shrink([false, false])
                        .show(ui, |ui| packet_view::tree(ui, &b.decoded, &mut ed.sel));
                });
            ui.add_space(2.0);
            let cursor = ed.hex_edit.then_some(&mut ed.cursor);
            if let Some(bytes) =
                packet_view::hex_view(ui, &b.decoded, &b.bytes, &mut ed.sel, cursor)
            {
                edited = Some(bytes_to_spec(b.linktype, &bytes));
            }
        }
    }
    match edited {
        Some(Ok((text, notes))) => {
            *spec = text;
            ed.hex_notes = notes;
        }
        Some(Err(e)) => ed.hex_notes = vec![e],
        None => {}
    }
}

fn control_page(ui: &mut egui::Ui, s: &mut StreamDraft) {
    egui::ScrollArea::vertical().id_salt("control").show(ui, |ui| {
        egui::Grid::new("control").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
            ui.label("Pacing");
            ui.horizontal(|ui| {
                ui.radio_value(&mut s.pacing, Pacing::Rate, "Rate");
                if s.source == SourceKind::Packets {
                    ui.radio_value(&mut s.pacing, Pacing::Interval, "Interval");
                } else {
                    ui.radio_value(&mut s.pacing, Pacing::Original, "Capture timing");
                }
            });
            ui.end_row();
            match s.pacing {
                Pacing::Rate => {
                    ui.label("Rate");
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut s.rate).desired_width(110.0));
                        for r in ["100pps", "10kpps", "10mbps", "1gbps", "topspeed"] {
                            if ui.small_button(r).clicked() {
                                s.rate = r.into();
                            }
                        }
                    });
                    ui.end_row();
                }
                Pacing::Interval => {
                    ui.label("Interval");
                    ui.add(egui::TextEdit::singleline(&mut s.interval).desired_width(110.0))
                        .on_hover_text("Time between packets: 1s, 10ms, 500us");
                    ui.end_row();
                }
                Pacing::Original => {}
            }
            ui.label("Loops");
            ui.horizontal(|ui| {
                ui.add(egui::DragValue::new(&mut s.loops).range(0..=u64::MAX));
                ui.weak(if s.loops == 0 { "until the run ends" } else { "times through the packets" });
            });
            ui.end_row();
            ui.label("Packet limit");
            ui.horizontal(|ui| {
                let mut on = s.limit.is_some();
                if ui.checkbox(&mut on, "").changed() {
                    s.limit = on.then_some(1000);
                }
                if let Some(l) = &mut s.limit {
                    ui.add(egui::DragValue::new(l).range(1..=u64::MAX));
                }
            });
            ui.end_row();
            ui.label("Start delay");
            ui.add(egui::TextEdit::singleline(&mut s.delay).hint_text("0s").desired_width(110.0));
            ui.end_row();
            ui.label("Traffic model");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut s.model).hint_text("constant").desired_width(160.0));
                for m in ["poisson", "burst=16"] {
                    if ui.small_button(m).clicked() {
                        s.model = m.into();
                    }
                }
            })
            .response
            .on_hover_text("poisson, burst=N, ramp_up=10s,hold=30s,ramp_down=10s (docs/traffic-models.md)");
            ui.end_row();
            ui.label("Rate shape");
            string_list(ui, "shape", &mut s.shape, "at=10s:500pps");
            ui.end_row();
            ui.label("Frame sizes");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut s.sizes).hint_text("as built").desired_width(160.0));
                for m in ["imix", "rfc2544"] {
                    if ui.small_button(m).clicked() {
                        s.sizes = m.into();
                    }
                }
            });
            ui.end_row();
            ui.label("Loss and latency");
            ui.horizontal(|ui| {
                let mut kind = match s.latency {
                    Latency::Off => 0,
                    Latency::On => 1,
                    Latency::Flow(_) => 2,
                };
                ui.radio_value(&mut kind, 0, "off");
                ui.radio_value(&mut kind, 1, "signatures");
                ui.radio_value(&mut kind, 2, "flow id");
                s.latency = match (kind, s.latency) {
                    (0, _) => Latency::Off,
                    (1, _) => Latency::On,
                    (_, Latency::Flow(f)) => {
                        let mut f = f;
                        ui.add(egui::DragValue::new(&mut f));
                        Latency::Flow(f)
                    }
                    _ => Latency::Flow(1),
                };
            });
            ui.end_row();
            if !s.extra.is_empty() {
                ui.label("Other keys");
                ui.vertical(|ui| {
                    for (k, v) in &s.extra {
                        ui.monospace(format!("{k} = {v}"));
                    }
                });
                ui.end_row();
            }
        });
        ui.add_space(8.0);
        match check_stream(s) {
            Ok(()) => ui.colored_label(crate::theme::good(ui), "✔ ferotrx reads this stream"),
            Err(e) => ui.colored_label(ui.visuals().error_fg_color, e),
        };
    });
}

fn variable_page(ui: &mut egui::Ui, s: &mut StreamDraft) {
    egui::ScrollArea::vertical().id_salt("variable").show(ui, |ui| {
        ui.strong("Variable fields");
        ui.label(
            RichText::new(
                "Change fields packet by packet: field=FROM..TO with inc (default), dec, random, step=N, every=N, seed=N; \
                 field+=FROM..TO adds to the packet's own value. Fields: mac_src, mac_dst, ip_src, ip_dst, \
                 port_src, port_dst, vlan, ip_id, ttl, len, payload@OFFSET[:SIZE].",
            )
            .small()
            .weak(),
        );
        string_list(ui, "vary", &mut s.vary, "port_src=1024..65535,random");
        ui.horizontal(|ui| {
            for ex in ["ip_src=10.0.0.1..10.0.0.254", "port_src=1024..65535", "len=64..1500,step=64"] {
                if ui.small_button(format!("+ {ex}")).clicked() {
                    s.vary.push(ex.into());
                }
            }
        });
        ui.add_space(10.0);
        ui.strong("Rewrites");
        ui.label(
            RichText::new(
                "Applied to every packet before the variable fields: mac_dst=…, ip_src=…, \
                 ip_src=10.0.0.0/8->192.0.0.0/8, port_dst=…, vlan_push=10, qinq_push=100, vlan_set=20, vlan_pop, fix_checksums",
            )
            .small()
            .weak(),
        );
        string_list(ui, "rewrite", &mut s.rewrite, "vlan_push=10");
        ui.add_space(8.0);
        match check_stream(s) {
            Ok(()) => ui.colored_label(crate::theme::good(ui), "✔ ferotrx reads this stream"),
            Err(e) => ui.colored_label(ui.visuals().error_fg_color, e),
        };
    });
}

/// An editable list of strings. Returns true when it changed.
pub fn string_list(ui: &mut egui::Ui, id: &str, v: &mut Vec<String>, hint: &str) -> bool {
    let mut changed = false;
    ui.push_id(id, |ui| {
        ui.vertical(|ui| {
            let mut remove = None;
            for (n, x) in v.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    changed |= ui
                        .add(
                            egui::TextEdit::singleline(x)
                                .hint_text(hint)
                                .desired_width(300.0)
                                .code_editor(),
                        )
                        .changed();
                    if ui.small_button("✕").clicked() {
                        remove = Some(n);
                    }
                });
            }
            if let Some(n) = remove {
                v.remove(n);
                changed = true;
            }
            if ui.small_button("+ add").clicked() {
                v.push(String::new());
                changed = true;
            }
        });
    });
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edited_bytes_become_layers() {
        let b = build("eth/ipv4(src=10.0.0.1,dst=10.0.0.2)/udp(sport=1000,dport=2000)/raw(text=hello-from-ferotrx-gui-x)")
            .unwrap();
        let mut bytes = b.bytes.clone();
        // The last payload byte: "x" -> "y" (no padding: over 60 bytes).
        *bytes.last_mut().unwrap() = b'y';
        // The IPv4 TTL (byte 14 + 8).
        bytes[22] = 7;
        let (spec, notes) = bytes_to_spec(b.linktype, &bytes).unwrap();
        assert!(notes.is_empty(), "{notes:?}");
        assert!(spec.contains("ttl=7"), "{spec}");
        let again = build(&spec).unwrap();
        // The same bytes, with the UDP and IPv4 checksums computed again.
        assert_eq!(again.bytes.len(), bytes.len());
        assert_eq!(again.bytes[22], 7);
        assert_eq!(*again.bytes.last().unwrap(), b'y');
        assert_ne!(
            again.bytes[24..26],
            b.bytes[24..26],
            "IPv4 checksum follows the TTL"
        );
        assert!(bytes_to_spec(b.linktype, &[]).is_err());
    }

    #[test]
    fn the_default_stream_builds_and_checks() {
        let s = StreamDraft::default();
        let b = build(&s.packets[0]).unwrap();
        assert_eq!(b.decoded.protocol, "UDP");
        check_stream(&s).unwrap();
    }

    #[test]
    fn stream_errors_name_the_problem() {
        let s = StreamDraft {
            packets: vec!["eth/ipv4(src=nope)".into()],
            ..Default::default()
        };
        assert!(check_stream(&s).unwrap_err().contains("invalid src"));
        let s = StreamDraft {
            rate: "fast".into(),
            ..Default::default()
        };
        assert!(check_stream(&s).is_err());
    }
}
