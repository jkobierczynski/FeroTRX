//! The Capture tab: open a pcap or pcapng file on this computer, or capture
//! live on an interface of a server with a BPF filter (`capture.*`), list
//! the packets, look at one in the packet view, save them, hand them to
//! Wireshark as they come, and turn packets into an editable stream for the
//! selected port.

use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use ferotrx_core::{Capture, Packet};
use ferotrx_ctl::protocol::{CaptureInfo, CaptureStartParams};
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
    /// The live capture form, and the capture while it runs.
    pub live_form: LiveForm,
    pub live: Option<LiveCapture>,
}

/// What a live capture is asked for.
#[derive(Clone, Debug, Default)]
pub struct LiveForm {
    pub server: usize,
    pub iface: String,
    pub filter: String,
    /// Also start Wireshark on the frames as they come.
    pub wireshark: bool,
}

/// Most frames the tab keeps of a live capture.
pub const LIVE_MAX_FRAMES: usize = 200_000;

/// A live capture on a server, read on a thread of its own over a
/// connection of its own.
pub struct LiveCapture {
    pub label: String,
    stop: Arc<AtomicBool>,
    shared: Arc<Mutex<LiveShared>>,
}

#[derive(Default)]
struct LiveShared {
    linktype: Option<u32>,
    new: Vec<Packet>,
    info: Option<CaptureInfo>,
    error: Option<String>,
    note: Option<String>,
    done: bool,
}

impl LiveCapture {
    /// Starts a capture with `settings`' server; `wake` repaints the window.
    pub fn start(
        settings: crate::conn::ConnSettings,
        form: &LiveForm,
        wake: impl Fn() + Send + 'static,
    ) -> LiveCapture {
        let stop = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Mutex::new(LiveShared::default()));
        let label = format!("{} on {}", form.iface, settings.address());
        let params = CaptureStartParams {
            iface: form.iface.clone(),
            filter: Some(form.filter.trim().to_string()).filter(|f| !f.is_empty()),
            ..Default::default()
        };
        let wireshark = form.wireshark;
        {
            let stop = stop.clone();
            let shared = shared.clone();
            std::thread::Builder::new()
                .name("live capture".into())
                .spawn(move || {
                    let r = live_loop(&settings, params, wireshark, &stop, &shared, &wake);
                    let mut s = lock(&shared);
                    if let Err(e) = r {
                        s.error = Some(e);
                    }
                    s.done = true;
                    drop(s);
                    wake();
                })
                .expect("spawn the live capture thread");
        }
        LiveCapture {
            label,
            stop,
            shared,
        }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn running(&self) -> bool {
        !lock(&self.shared).done
    }
}

impl Drop for LiveCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Wireshark, reading a pcap stream on its standard input.
fn open_wireshark() -> Result<Child, String> {
    let mut tried = vec!["wireshark".to_string()];
    if cfg!(windows) {
        tried.push(r"C:\Program Files\Wireshark\Wireshark.exe".into());
    }
    if cfg!(target_os = "macos") {
        tried.push("/Applications/Wireshark.app/Contents/MacOS/Wireshark".into());
    }
    for exe in &tried {
        if let Ok(c) = Command::new(exe)
            .args(["-k", "-i", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            return Ok(c);
        }
    }
    Err(format!(
        "cannot start Wireshark (tried {})",
        tried.join(", ")
    ))
}

fn live_loop(
    settings: &crate::conn::ConnSettings,
    params: CaptureStartParams,
    wireshark: bool,
    stop: &AtomicBool,
    shared: &Mutex<LiveShared>,
    wake: &dyn Fn(),
) -> Result<(), String> {
    let mut c = settings.open_client()?;
    let info = c.capture_start(&params).map_err(|e| e.to_string())?;
    let id = info.id;
    let mut pipe = None;
    if wireshark {
        match open_wireshark() {
            Ok(mut child) => {
                let mut ok = false;
                if let Some(stdin) = child.stdin.as_mut() {
                    let mut header = Vec::new();
                    if let Ok(w) = ferotrx_core::PcapStreamWriter::new(
                        &mut header,
                        info.linktype,
                        info.snaplen,
                    ) {
                        drop(w);
                        ok = stdin.write_all(&header).is_ok();
                    }
                }
                if ok {
                    pipe = Some(child);
                }
            }
            Err(e) => lock(shared).note = Some(e),
        }
    }
    {
        let mut s = lock(shared);
        s.linktype = Some(info.linktype);
        s.info = Some(info);
    }
    wake();
    let mut after = 0;
    let mut last_info = std::time::Instant::now();
    let result = loop {
        if stop.load(Ordering::Relaxed) {
            break Ok(());
        }
        let r = match c.capture_read(id, after, Some(Duration::from_millis(250))) {
            Ok(r) => r,
            Err(e) => break Err(e.to_string()),
        };
        after = r.next;
        let mut packets = Vec::with_capacity(r.frames.len());
        for f in &r.frames {
            let Some(frame) = f.frame() else { continue };
            if let Some(child) = &mut pipe {
                let mut rec = Vec::new();
                let sent = ferotrx_core::PcapStreamWriter::new(&mut rec, 1, u32::MAX)
                    .and_then(|mut w| w.write(&frame))
                    .is_ok();
                // Leave out the header the writer put first.
                let gone = !sent
                    || child
                        .stdin
                        .as_mut()
                        .is_none_or(|s| s.write_all(&rec[24..]).and_then(|()| s.flush()).is_err());
                if gone {
                    pipe = None;
                    lock(shared).note =
                        Some("Wireshark was closed; the capture goes on here".into());
                }
            }
            packets.push(Packet::new(frame.ts, frame.data));
        }
        let more = r.more;
        if !packets.is_empty() || r.missed > 0 || last_info.elapsed() > Duration::from_secs(1) {
            let info = c.capture_get(id).ok();
            let mut s = lock(shared);
            s.new.extend(packets);
            if let Some(i) = info {
                s.info = Some(i);
            }
            if r.missed > 0 {
                s.note = Some(format!(
                    "{} frames left the server's buffer before they were read",
                    r.missed
                ));
            }
            drop(s);
            last_info = std::time::Instant::now();
            wake();
        }
        if !more {
            break Ok(());
        }
    };
    if let Ok(i) = c.capture_stop(id) {
        lock(shared).info = Some(i);
    }
    let _ = c.capture_remove(id);
    // Wireshark keeps what it has; closing its input ends the live view.
    drop(pipe.and_then(|mut c| c.stdin.take()));
    result
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

    /// Saves the capture shown as pcap (`Save…`).
    pub fn save(&mut self, path: &std::path::Path) {
        match &self.capture {
            Some(c) => match c.save(path) {
                Ok(()) => {
                    self.path = path.display().to_string();
                    self.error = None;
                }
                Err(e) => self.error = Some(format!("{}: {e}", path.display())),
            },
            None => self.error = Some("nothing to save".into()),
        }
    }

    /// Starts showing a live capture: the list empties and fills as frames come.
    pub fn begin_live(&mut self, live: LiveCapture) {
        self.capture = None;
        self.decoded.clear();
        self.marked.clear();
        self.selected = None;
        self.error = None;
        self.path.clear();
        self.live = Some(live);
    }

    /// Takes the frames that came since the last frame drawn.
    pub fn poll_live(&mut self) {
        let Some(live) = &self.live else {
            return;
        };
        let mut s = lock(&live.shared);
        if let Some(lt) = s.linktype {
            let cap = self
                .capture
                .get_or_insert_with(|| Capture::new(lt, Vec::new()));
            let room = LIVE_MAX_FRAMES.saturating_sub(cap.packets.len());
            let new = std::mem::take(&mut s.new);
            if new.len() > room && s.note.is_none() {
                s.note = Some(format!("the tab keeps the first {LIVE_MAX_FRAMES} frames"));
            }
            cap.packets.extend(new.into_iter().take(room));
            let n = cap.packets.len();
            self.decoded.resize(n, None);
            self.marked.resize(n, false);
        }
        if let Some(e) = s.error.take() {
            self.error = Some(e);
        }
    }

    /// A line on the live capture: counters and notes.
    fn live_status(&self) -> Option<(String, Option<String>, bool)> {
        let live = self.live.as_ref()?;
        let s = lock(&live.shared);
        let mut line = live.label.clone();
        if let Some(i) = &s.info {
            line.push_str(&format!(
                ": {} frames, {} bytes, {} dropped by the kernel",
                i.frames,
                i.bytes,
                i.dropped + i.if_dropped
            ));
        } else if !s.done {
            line.push_str(": starting…");
        }
        Some((line, s.note.clone(), !s.done))
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
        self.capture.poll_live();
        let mut to_stream = false;
        let mut save = false;
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
        self.live_row(ui);
        let cs = &mut self.capture;
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
            ui.weak("Open a pcap or pcapng file to inspect it, or capture live on a server's interface. Packets can be taken into a stream and edited layer by layer.");
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
            if ui
                .small_button("Save…")
                .on_hover_text("Write these packets to a pcap file on this computer")
                .clicked()
            {
                save = true;
            }
        });
        ui.separator();

        let row_h = 18.0;
        let mut clicked = None;
        // The packet list above the packet; the line between them drags.
        let h = ui.available_height();
        egui::Panel::top("capture-list")
            .resizable(true)
            .frame(egui::Frame::NONE)
            .default_size((h * 0.45).max(120.0))
            .size_range(80.0..=(h - 80.0).max(90.0))
            .show(ui, |ui| {
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
            egui::Panel::left("capture-tree")
                .resizable(true)
                .frame(egui::Frame::NONE)
                .default_size(w * 0.45)
                .size_range(200.0..=(w - 200.0).max(220.0))
                .show(ui, |ui| {
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
        if save {
            let current = self.capture.path.clone();
            self.files.save(
                crate::files::Target::SaveCapture,
                "Save the capture",
                crate::files::Kind::Capture,
                &current,
                "capture.pcap",
            );
        }
    }

    /// The live capture row: server, interface, BPF filter, Wireshark,
    /// start and stop.
    fn live_row(&mut self, ui: &mut egui::Ui) {
        let connected: Vec<(usize, String)> = self
            .servers
            .iter()
            .enumerate()
            .filter(|(_, s)| s.info.is_some() && s.conn.is_some())
            .map(|(i, s)| (i, s.settings.address()))
            .collect();
        let running = self.capture.live.as_ref().is_some_and(LiveCapture::running);
        let mut start = false;
        ui.horizontal(|ui| {
            ui.label("Live capture on");
            let form = &mut self.capture.live_form;
            if !connected.iter().any(|(i, _)| *i == form.server) {
                if let Some((i, _)) = connected.first() {
                    form.server = *i;
                }
            }
            let shown = connected
                .iter()
                .find(|(i, _)| *i == form.server)
                .map(|(_, a)| a.clone())
                .unwrap_or_else(|| "no server connected".into());
            ui.add_enabled_ui(!running, |ui| {
                egui::ComboBox::from_id_salt("live-server")
                    .selected_text(shown)
                    .show_ui(ui, |ui| {
                        for (i, a) in &connected {
                            ui.selectable_value(&mut form.server, *i, a);
                        }
                    });
                let ifaces: Vec<String> = self
                    .servers
                    .get(form.server)
                    .map(|s| s.interfaces.iter().map(|i| i.name.clone()).collect())
                    .unwrap_or_default();
                if form.iface.is_empty() || !ifaces.contains(&form.iface) {
                    if let Some(first) = ifaces.first() {
                        if form.iface.is_empty() {
                            form.iface = first.clone();
                        }
                    }
                }
                egui::ComboBox::from_id_salt("live-iface")
                    .selected_text(if form.iface.is_empty() { "interface" } else { &form.iface })
                    .show_ui(ui, |ui| {
                        for n in &ifaces {
                            ui.selectable_value(&mut form.iface, n.clone(), n);
                        }
                    });
                ui.add(
                    egui::TextEdit::singleline(&mut form.filter)
                        .hint_text("BPF filter, e.g. udp port 53")
                        .desired_width(220.0),
                )
                .on_hover_text("A capture filter as tcpdump and Wireshark take them: host 10.0.0.1, tcp port 80 and not arp, vlan 10");
                ui.checkbox(&mut form.wireshark, "Wireshark")
                    .on_hover_text("Also start Wireshark on this computer, reading the frames as they come");
            });
            if running {
                if ui.button("Stop").clicked() {
                    if let Some(l) = &self.capture.live {
                        l.stop();
                    }
                }
            } else {
                let ok = !connected.is_empty() && !self.capture.live_form.iface.is_empty();
                if ui.add_enabled(ok, egui::Button::new("Start")).clicked() {
                    start = true;
                }
            }
        });
        if let Some((line, note, live)) = self.capture.live_status() {
            ui.horizontal(|ui| {
                if live {
                    ui.spinner();
                }
                ui.weak(line);
                if let Some(n) = note {
                    ui.colored_label(ui.visuals().warn_fg_color, n);
                }
            });
        }
        if start {
            let form = self.capture.live_form.clone();
            if let Some(server) = self.servers.get(form.server) {
                let ctx = self.ctx.clone();
                let live = LiveCapture::start(server.settings.clone(), &form, move || {
                    ctx.request_repaint()
                });
                self.capture.begin_live(live);
            }
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
