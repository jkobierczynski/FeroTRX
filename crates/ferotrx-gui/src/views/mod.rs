//! The panels of the window, each an `impl FeroApp` block.

mod capture;
mod stateful;
mod stats;
mod streams;

use eframe::egui::{self, RichText};

pub use capture::CaptureState;
pub use stateful::StatefulState;
pub use streams::EditorState;

use crate::app::{BottomTab, FeroApp, ServerState, Status, Tab};
use crate::conn::ConnSettings;
use crate::model::PortKind;
use crate::packet_view::state_color;

impl FeroApp {
    pub fn ui(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| self.top_bar(ui));
        egui::SidePanel::left("ports")
            .resizable(true)
            .default_width(230.0)
            .show(ctx, |ui| self.ports_panel(ui));
        egui::TopBottomPanel::bottom("bottom")
            .resizable(true)
            .default_height(260.0)
            .min_height(120.0)
            .show(ctx, |ui| self.bottom_panel(ui));
        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Streams => self.streams_tab(ui),
            Tab::Stateful => self.stateful_tab(ui),
            Tab::Capture => self.capture_tab(ui),
            Tab::Charts => self.charts_tab(ui),
        });
        self.dialogs(ctx);
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading(RichText::new("FeroTRX").strong());
            ui.separator();
            for (tab, label, hover) in [
                (
                    Tab::Streams,
                    "Streams",
                    "Build streams for a port and send them",
                ),
                (
                    Tab::Stateful,
                    "Stateful",
                    "TCP sessions and UDP transactions from profiles",
                ),
                (
                    Tab::Capture,
                    "Capture",
                    "Open a capture, look at its packets, edit them",
                ),
                (Tab::Charts, "Charts", "Rates of the runs over time"),
            ] {
                ui.selectable_value(&mut self.tab, tab, label)
                    .on_hover_text(hover);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                egui::widgets::global_theme_preference_switch(ui);
                if ui.button("Add server…").clicked() {
                    self.add_server = Some(ConnSettings::default());
                }
            });
        });
    }

    fn ports_panel(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.strong("Servers and ports");
        ui.separator();
        egui::ScrollArea::vertical().show(ui, |ui| {
            let mut action = None;
            for i in 0..self.servers.len() {
                let s = &self.servers[i];
                let (dot, tip) = match &s.status {
                    Status::Connected => (
                        egui::Color32::from_rgb(0x2e, 0xa0, 0x43),
                        "connected".to_string(),
                    ),
                    Status::Connecting => (ui.visuals().warn_fg_color, "connecting".into()),
                    Status::Disconnected => {
                        (ui.visuals().weak_text_color(), "not connected".into())
                    }
                    Status::Failed(e) => (ui.visuals().error_fg_color, e.clone()),
                };
                let id = ui.id().with(("server", i));
                let header = egui::collapsing_header::CollapsingState::load_with_default_open(
                    ui.ctx(),
                    id,
                    true,
                );
                header
                    .show_header(ui, |ui| {
                        ui.colored_label(dot, "●").on_hover_text(&tip);
                        let r = ui.selectable_label(
                            self.sel_server == i && self.sel_port.is_none(),
                            RichText::new(&s.settings.addr).strong(),
                        );
                        if r.clicked() {
                            action = Some(PanelAction::SelectServer(i));
                        }
                        r.context_menu(|ui| {
                            if s.conn.is_some() {
                                if ui.button("Disconnect").clicked() {
                                    action = Some(PanelAction::Disconnect(i));
                                    ui.close();
                                }
                            } else if ui.button("Connect").clicked() {
                                action = Some(PanelAction::Connect(i));
                                ui.close();
                            }
                            if ui.button("Edit…").clicked() {
                                action = Some(PanelAction::Edit(i));
                                ui.close();
                            }
                            if ui.button("Remove").clicked() {
                                action = Some(PanelAction::Remove(i));
                                ui.close();
                            }
                        });
                    })
                    .body(|ui| {
                        if s.status != Status::Connected {
                            ui.horizontal(|ui| {
                                if s.conn.is_none() && ui.button("Connect").clicked() {
                                    action = Some(PanelAction::Connect(i));
                                }
                                if ui.small_button("Edit…").clicked() {
                                    action = Some(PanelAction::Edit(i));
                                }
                            });
                            if let Status::Failed(e) = &s.status {
                                ui.label(
                                    RichText::new(e).small().color(ui.visuals().error_fg_color),
                                );
                            }
                            return;
                        }
                        if let Some(info) = &s.info {
                            ui.label(
                                RichText::new(format!(
                                    "{} · {}",
                                    info.version,
                                    if info.backends.is_empty() {
                                        "no interfaces".to_string()
                                    } else {
                                        info.backends.join(", ")
                                    }
                                ))
                                .small()
                                .weak(),
                            );
                        }
                        for port in s.ports() {
                            let running = self.port_running(s, i, &port);
                            ui.horizontal(|ui| {
                                ui.colored_label(
                                    state_color(ui, running, false),
                                    if running { "▶" } else { "○" },
                                );
                                let selected =
                                    self.sel_server == i && self.sel_port.as_ref() == Some(&port);
                                let desc = s.interfaces.iter().find(
                                    |x| matches!(&port, PortKind::Interface(n) if *n == x.name),
                                );
                                let mut r = ui.selectable_label(selected, port.label());
                                if let Some(d) = desc.and_then(|d| d.description.as_ref()) {
                                    r = r.on_hover_text(d);
                                }
                                if r.clicked() {
                                    action = Some(PanelAction::SelectPort(i, port.clone()));
                                }
                            });
                        }
                    });
            }
            if let Some(a) = action {
                self.panel_action(a);
            }
        });
    }

    fn port_running(&self, s: &ServerState, i: usize, port: &PortKind) -> bool {
        s.port_runs
            .get(&self.port_key(i, port))
            .and_then(|id| s.run(*id))
            .is_some_and(|r| r.state.is_running())
    }

    fn panel_action(&mut self, a: PanelAction) {
        match a {
            PanelAction::SelectServer(i) => {
                self.sel_server = i;
                self.sel_port = None;
            }
            PanelAction::SelectPort(i, p) => {
                if self.sel_server != i || self.sel_port.as_ref() != Some(&p) {
                    let has = !self.port_work(i, &p).profile.streams.is_empty();
                    self.editor = EditorState {
                        stream: has.then_some(0),
                        ..Default::default()
                    };
                }
                self.sel_server = i;
                self.sel_port = Some(p);
                if self.tab != Tab::Streams && self.tab != Tab::Stateful {
                    self.tab = Tab::Streams;
                }
            }
            PanelAction::Connect(i) => self.connect(i),
            PanelAction::Disconnect(i) => self.disconnect(i),
            PanelAction::Edit(i) => {
                let mut s = self.servers[i].settings.clone();
                s.token = self.servers[i].settings.token.clone();
                self.add_server = Some(s);
            }
            PanelAction::Remove(i) => {
                self.servers.remove(i);
                self.sel_server = 0;
                self.sel_port = None;
            }
        }
    }

    fn bottom_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.bottom, BottomTab::Stats, "Statistics");
            let errors = self.log.iter().filter(|l| l.error).count();
            let label = if errors > 0 {
                format!("Log ({errors} errors)")
            } else {
                "Log".into()
            };
            ui.selectable_value(&mut self.bottom, BottomTab::Log, label);
        });
        ui.separator();
        match self.bottom {
            BottomTab::Stats => self.stats_grid(ui),
            BottomTab::Log => {
                ui.horizontal(|ui| {
                    if ui.small_button("Clear").clicked() {
                        self.log.clear();
                    }
                });
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for l in &self.log {
                            let t =
                                format!("{:>7.1}s  {}  {}", l.at.as_secs_f64(), l.server, l.text);
                            let mut r = RichText::new(t).monospace();
                            if l.error {
                                r = r.color(ui.visuals().error_fg_color);
                            }
                            ui.label(r);
                        }
                    });
            }
        }
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        let mut close = false;
        let mut connect = None;
        let mut browse = None;
        if let Some(s) = &mut self.add_server {
            egui::Window::new("Server")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    egui::Grid::new("server-form").num_columns(2).show(ui, |ui| {
                        ui.label("Address");
                        ui.add(egui::TextEdit::singleline(&mut s.addr).hint_text("host:4510"));
                        ui.end_row();
                        ui.label("Token");
                        ui.add(
                            egui::TextEdit::singleline(&mut s.token)
                                .password(true)
                                .hint_text("if the server wants one"),
                        )
                        .on_hover_text("Not saved: give it again after a restart, or set FEROTRX_TOKEN");
                        ui.end_row();
                        ui.label("TLS");
                        ui.checkbox(&mut s.tls, "Verify the server with a CA certificate");
                        ui.end_row();
                        if s.tls {
                            for (n, (label, v, hint)) in [
                                ("CA certificate", &mut s.ca, "ca.pem"),
                                ("Client certificate", &mut s.cert, "optional, for mutual TLS"),
                                ("Client key", &mut s.key, "optional"),
                                ("Server name", &mut s.server_name, "if not the host above"),
                            ]
                            .into_iter()
                            .enumerate()
                            {
                                ui.label(label);
                                ui.horizontal(|ui| {
                                    ui.add(egui::TextEdit::singleline(v).hint_text(hint).desired_width(280.0));
                                    if n < 3 && ui.button("Browse…").clicked() {
                                        browse = Some((n as u8, v.clone(), label));
                                    }
                                });
                                ui.end_row();
                            }
                        }
                    });
                    ui.label(
                        RichText::new("Start a server with: sudo ferotrx serve (see the remote control guide for TLS and tokens)")
                            .small()
                            .weak(),
                    );
                    ui.horizontal(|ui| {
                        if ui.button("Connect").clicked() {
                            connect = Some(s.clone());
                            close = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                });
        }
        if let Some((n, current, label)) = browse {
            self.files.pick(
                crate::files::Target::Pem(n),
                label,
                crate::files::Kind::Pem,
                &current,
            );
        }
        if close {
            self.add_server = None;
        }
        if let Some(s) = connect {
            let i = match self
                .servers
                .iter()
                .position(|x| x.settings.address() == s.address())
            {
                Some(i) => {
                    self.disconnect(i);
                    self.servers[i].settings = s;
                    i
                }
                None => {
                    self.servers.push(ServerState::new(s));
                    self.servers.len() - 1
                }
            };
            self.sel_server = i;
            self.connect(i);
        }
        self.file_dialog(ctx);
    }
}

enum PanelAction {
    SelectServer(usize),
    SelectPort(usize, PortKind),
    Connect(usize),
    Disconnect(usize),
    Edit(usize),
    Remove(usize),
}
