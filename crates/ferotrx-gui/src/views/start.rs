//! The Start page: where to begin, in four steps, and the Settings window
//! (the user's folders). Also opening any FeroTRX file in the tab it
//! belongs to.

use std::path::{Path, PathBuf};

use eframe::egui::{self, RichText};
use ferotrx_core::check::{kind_of, FileKind};

use crate::app::{FeroApp, Status, Tab};
use crate::files::Target;
use crate::model::PortKind;
use crate::settings::{FolderKind, Settings};

/// What the Start page offers to do, with the example each one opens.
const TASKS: &[(&str, &str, &str)] = &[
    (
        "Send packets",
        "lab-built-packets.ftstream",
        "Streams of packets built field by field, or replayed from captures, on the port you picked.",
    ),
    (
        "TCP and UDP sessions",
        "lab-tcp.fttcp",
        "Both ends of real TCP connections (or UDP transactions) through the device under test.",
    ),
    (
        "Application traffic",
        "lab-http.fttcp",
        "HTTP, HTTPS, DNS, MQTT, SSH, SIP, SMB and HTTP/3 clients and servers.",
    ),
    (
        "Check a network",
        "lab-scenario.ftscenario",
        "A scenario: what must get through, what must be blocked, and how well. Pass or fail.",
    ),
    (
        "Measure a device",
        "bench-rfc2544.ftbench",
        "RFC 2544 throughput, latency and frame loss between two ports.",
    ),
];

/// The Settings window's form, while open.
#[derive(Clone, Debug)]
pub struct SettingsForm {
    pub settings: Settings,
    pub status: Option<Result<String, String>>,
}

/// The tabs a file of each kind opens in, and those an open dialog of a
/// tab takes as they are.
fn wanted(target: &Target) -> Option<&'static [FileKind]> {
    Some(match target {
        Target::OpenProfile => &[FileKind::Traffic],
        Target::StatefulProfile | Target::OpenAppProfile => &[FileKind::Tcp, FileKind::Udp],
        Target::OpenScenario => &[FileKind::Scenario],
        Target::OpenBench => &[FileKind::Bench],
        Target::OpenY1564 => &[FileKind::Y1564],
        _ => return None,
    })
}

/// True when a TCP or UDP profile has application protocols (`app = ...`),
/// which the Applications tab edits.
fn has_app(text: &str) -> bool {
    let Ok(t) = toml::from_str::<toml::Table>(text) else {
        return false;
    };
    t.contains_key("app")
        || t.get("template")
            .and_then(|v| v.as_array())
            .is_some_and(|a| a.iter().any(|x| x.get("app").is_some()))
}

impl FeroApp {
    /// Opens a FeroTRX file of any kind in the tab it belongs to; returns
    /// what to log.
    pub fn open_file(&mut self, path: &Path) -> Result<String, String> {
        let shown = path.display().to_string();
        let text = std::fs::read_to_string(path).map_err(|e| format!("{shown}: {e}"))?;
        let kind = kind_of(path, &text).map_err(|e| format!("{shown}: {e}"))?;
        let (tab, what) = match kind {
            FileKind::Traffic => {
                let i = self.sel_server.min(self.servers.len().saturating_sub(1));
                if self.servers.is_empty() {
                    return Err("add a server first: streams belong to one of its ports".into());
                }
                let port = match &self.sel_port {
                    Some(p) => p.clone(),
                    None => {
                        // The first interface, else the null port.
                        let p = self.servers[i]
                            .ports()
                            .into_iter()
                            .next()
                            .unwrap_or(PortKind::Null);
                        self.sel_port = Some(p.clone());
                        p
                    }
                };
                self.profile_file(i, &port, path, false);
                (Tab::Streams, "Streams")
            }
            FileKind::Tcp | FileKind::Udp if has_app(&text) => {
                self.apps.open(&shown)?;
                (Tab::Apps, "Applications")
            }
            FileKind::Tcp | FileKind::Udp => {
                let st = &mut self.stateful;
                st.kind = if kind == FileKind::Udp {
                    crate::views::stateful::Kind::Udp
                } else {
                    crate::views::stateful::Kind::Tcp
                };
                st.upload = true;
                st.path = shown.clone();
                st.check = None;
                (Tab::Stateful, "Stateful")
            }
            FileKind::Scenario => {
                self.scenario.open(&shown)?;
                self.scenario.upload = true;
                (Tab::Scenario, "Scenario")
            }
            FileKind::Bench => {
                self.bench.upload = true;
                self.bench.open(&shown)?;
                (Tab::Bench, "Benchmark")
            }
            FileKind::Y1564 => {
                self.y1564.upload = true;
                self.y1564.open(&shown)?;
                (Tab::Y1564, "Y.1564")
            }
            FileKind::Hosts => {
                return Err(format!(
                    "{shown} is a host profile: run it with `ferotrx host -p {shown} -i IFACE` (the GUI has no host tab yet)"
                ))
            }
            FileKind::Fleet => {
                return Err(format!(
                    "{shown} is a fleet plan: run it with `ferotrx fleet run {shown}`, or use the Multi-server tab"
                ))
            }
        };
        self.tab = tab;
        self.opened_from_start = true;
        Ok(format!(
            "{shown}: {}, opened in the {what} tab",
            kind.label()
        ))
    }

    /// For an open dialog of a tab: a file of another kind opens in its
    /// own tab instead (a TCP profile picked in Streams goes to Stateful).
    /// True when it did that.
    pub fn open_elsewhere(&mut self, target: &Target, path: &Path) -> bool {
        let Some(kinds) = wanted(target) else {
            return false;
        };
        // A path on the server is not here to look at.
        let local = match target {
            Target::StatefulProfile => self.stateful.upload,
            Target::OpenScenario => self.scenario.upload,
            Target::OpenBench => self.bench.upload,
            Target::OpenY1564 => self.y1564.upload,
            _ => true,
        };
        if !local {
            return false;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            return false;
        };
        let Ok(kind) = kind_of(path, &text) else {
            return false;
        };
        if kinds.contains(&kind) {
            return false;
        }
        match self.open_file(path) {
            Ok(m) => self.info("", m),
            Err(e) => self.error("", e),
        }
        true
    }

    pub fn start_tab(&mut self, ui: &mut egui::Ui) {
        let mut open_example: Option<PathBuf> = None;
        let mut open_any = false;
        let mut add_server = false;
        let mut connect = None;
        let examples = self.settings.examples_dir();
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Where to start");
            ui.label(
                RichText::new(
                    "Four steps. Everything here is also in the tabs above; this page only points the way.",
                )
                .weak(),
            );
            ui.add_space(10.0);

            // 1. A server.
            let server = self.servers.get(self.sel_server);
            let connected = server.is_some_and(|s| s.status == Status::Connected);
            step(ui, 1, connected, "Choose where traffic is sent from", |ui| {
                ui.label("A server (ferotrx serve) sends and receives: “This computer”, which the GUI starts itself, or one on another machine.");
                match server {
                    Some(s) => {
                        let state = match &s.status {
                            Status::Connected => "connected".to_string(),
                            Status::Connecting => "connecting…".into(),
                            Status::Disconnected => "not connected".into(),
                            Status::Failed(e) => format!("failed: {e}"),
                        };
                        ui.horizontal(|ui| {
                            ui.label(format!("Selected: {} ({state})", s.settings.addr));
                            if !connected
                                && !matches!(s.status, Status::Connecting)
                                && ui.button(if s.settings.local { "Start" } else { "Connect" }).clicked()
                            {
                                connect = Some(self.sel_server);
                            }
                        });
                    }
                    None => {
                        ui.label("No server yet.");
                    }
                }
                if ui.button("Add another server…").clicked() {
                    add_server = true;
                }
            });

            // 2. A port.
            let port = self.sel_port.clone();
            let has_port = connected && port.is_some();
            step(ui, 2, has_port, "Pick a port in the list on the left", |ui| {
                ui.label("A port is one of the server's interfaces, the network the device under test is on. “null” only counts packets and “file” writes a capture: both are safe for a first try.");
                if let Some(p) = &port {
                    ui.label(format!("Selected: {}", p.label()));
                }
            });

            // 3. What to do.
            step(ui, 3, self.opened_from_start, "Choose what to do", |ui| {
                ui.label(format!(
                    "Each opens an example from your folder ({}) in its tab. Change it there and save it under your own name.",
                    examples.display()
                ));
                ui.add_space(4.0);
                egui::Grid::new("start-tasks").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                    for (label, file, what) in TASKS {
                        let path = examples.join(file);
                        if ui
                            .add_enabled(path.is_file(), egui::Button::new(*label).min_size([180.0, 0.0].into()))
                            .on_disabled_hover_text(format!("{} is missing: Settings… copies the examples again", path.display()))
                            .clicked()
                        {
                            open_example = Some(path);
                        }
                        ui.label(*what);
                        ui.end_row();
                    }
                    if ui.add(egui::Button::new("Open a file…").min_size([180.0, 0.0].into())).clicked() {
                        open_any = true;
                    }
                    ui.label("Any FeroTRX file: it opens in the tab for its kind (.ftstream, .fttcp, .ftudp, .ftscenario, .ftbench, .fty1564, or .toml).");
                    ui.end_row();
                });
            });

            // 4. Run and watch.
            let ran = self.servers.get(self.sel_server).is_some_and(|s| {
                !s.snap.runs.is_empty()
                    || !s.snap.tcp.is_empty()
                    || !s.snap.udp.is_empty()
                    || !s.snap.scenarios.is_empty()
                    || !s.snap.bench.is_empty()
            });
            step(ui, 4, ran, "Start it, and watch", |ui| {
                ui.label("Press Start (or Run) in the tab. Counters show in Statistics at the bottom, rates and latency over time in Charts, and anything that went wrong in Log.");
                if ran {
                    ui.label(
                        RichText::new(
                            "Next: put what you ran in a scenario (Scenario tab) to check it again with one click, or save everything as a workspace (Workspace menu).",
                        )
                        .strong(),
                    );
                }
            });

            ui.add_space(14.0);
            ui.separator();
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(format!("Your files: {}", self.settings.profiles)).weak());
                if ui.button("Settings…").clicked() {
                    self.settings_form = Some(SettingsForm {
                        settings: self.settings.clone(),
                        status: None,
                    });
                }
                let mut show = self.settings.show_start;
                if ui.checkbox(&mut show, "Show this page when FeroTRX starts").changed() {
                    self.settings.show_start = show;
                    self.save_settings();
                }
            });
        });
        if add_server {
            self.add_server = Some(crate::conn::ConnSettings::default());
        }
        if let Some(i) = connect {
            self.connect(i);
        }
        if let Some(p) = open_example {
            match self.open_file(&p) {
                Ok(m) => self.info("", m),
                Err(e) => self.error("", e),
            }
        }
        if open_any {
            self.files.pick(
                Target::OpenAny,
                "Open a FeroTRX file",
                crate::files::Kind::Profile,
                &examples.display().to_string(),
            );
        }
    }

    /// Writes the settings, and gives the file dialogs their folders.
    pub fn save_settings(&mut self) {
        self.files.settings = self.settings.clone();
        if let Err(e) = self.settings.save() {
            self.error("", format!("settings: {e}"));
        }
    }

    /// The Settings window: the user's folders.
    pub fn settings_window(&mut self, ctx: &egui::Context) {
        let Some(form) = &mut self.settings_form else {
            return;
        };
        let mut open = true;
        let mut apply = false;
        let mut browse = None;
        let mut copy = false;
        egui::Window::new("Settings")
            .open(&mut open)
            .resizable(false)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label(
                    RichText::new(match crate::settings::config_dir() {
                        Some(d) => format!("Saved in {}", d.join("settings.toml").display()),
                        None => "No folder to save settings in (no home folder).".into(),
                    })
                    .weak(),
                );
                ui.add_space(6.0);
                egui::Grid::new("settings").num_columns(3).spacing([10.0, 6.0]).show(ui, |ui| {
                    for (label, kind, hover) in [
                        ("Profiles", FolderKind::Profiles, "Where open and save dialogs for profiles, scenarios, workspaces and themes start. The examples are copied to its examples folder."),
                        ("Captures", FolderKind::Captures, "Where dialogs for captures (pcap, pcapng) start."),
                        ("Reports", FolderKind::Reports, "Where dialogs for reports and comparisons start."),
                    ] {
                        ui.label(label).on_hover_text(hover);
                        let field = match kind {
                            FolderKind::Profiles => &mut form.settings.profiles,
                            FolderKind::Captures => &mut form.settings.captures,
                            FolderKind::Reports => &mut form.settings.reports,
                        };
                        ui.add(egui::TextEdit::singleline(field).desired_width(380.0));
                        if ui.button("Browse…").clicked() {
                            browse = Some((kind, field.clone()));
                        }
                        ui.end_row();
                    }
                });
                ui.checkbox(&mut form.settings.show_start, "Show the Start page when FeroTRX starts");
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        apply = true;
                    }
                    if ui
                        .button("Copy the examples")
                        .on_hover_text("Copies the examples that came with FeroTRX to the examples folder of Profiles; files already there are kept")
                        .clicked()
                    {
                        copy = true;
                    }
                });
                match &form.status {
                    Some(Ok(m)) => {
                        ui.label(RichText::new(m).color(crate::theme::good(ui)));
                    }
                    Some(Err(e)) => {
                        ui.colored_label(ui.visuals().error_fg_color, e);
                    }
                    None => {}
                }
            });
        if let Some((kind, current)) = browse {
            self.files
                .pick_folder(Target::Folder(kind), "Choose a folder", &current);
        }
        if copy {
            let mut s = form.settings.clone();
            s.examples_copied.clear();
            form.status = Some(match s.copy_examples() {
                Ok(n) => Ok(format!(
                    "copied {n} file(s) to {}",
                    s.examples_dir().display()
                )),
                Err(e) => Err(e),
            });
        }
        if apply {
            self.settings = form.settings.clone();
            self.files.settings = self.settings.clone();
            form.status = Some(
                self.settings
                    .save()
                    .map(|p| format!("saved {}", p.display())),
            );
        }
        if !open {
            self.settings_form = None;
        }
    }

    /// The first start: copy the examples to the user's folder, and show the
    /// Start page when the settings say so.
    pub fn prepare_user_folder(&mut self) {
        let first = Settings::first_start();
        match self.settings.copy_examples() {
            Ok(0) => {}
            Ok(n) => self.info(
                "",
                format!(
                    "copied {n} example file(s) to {}",
                    self.settings.examples_dir().display()
                ),
            ),
            Err(e) => self.error("", format!("examples: {e}")),
        }
        if first || self.settings.examples_copied == env!("CARGO_PKG_VERSION") {
            if let Err(e) = self.settings.save() {
                self.error("", format!("settings: {e}"));
            }
        }
        self.files.settings = self.settings.clone();
        if self.settings.show_start {
            self.tab = Tab::Start;
        }
    }
}

/// One numbered step: ✔ when done.
fn step(ui: &mut egui::Ui, n: u8, done: bool, title: &str, body: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        let mark = if done {
            "✔".to_string()
        } else {
            format!("{n}")
        };
        let color = if done {
            crate::theme::good(ui)
        } else {
            ui.visuals().strong_text_color()
        };
        ui.label(RichText::new(mark).heading().color(color));
        ui.label(RichText::new(title).heading());
    });
    ui.indent(("step", n), |ui| body(ui));
    ui.add_space(10.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_profiles_go_to_the_applications_tab() {
        assert!(has_app("app = \"http\"\n"));
        assert!(has_app("[[template]]\napp = \"dns\"\n"));
        assert!(!has_app("pcap = \"http.pcap\"\n"));
    }

    #[test]
    fn open_dialogs_take_their_own_kinds() {
        assert_eq!(wanted(&Target::OpenProfile), Some(&[FileKind::Traffic][..]));
        assert!(wanted(&Target::Capture).is_none());
    }
}
