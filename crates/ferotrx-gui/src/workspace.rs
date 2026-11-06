//! Workspace files: everything the window holds, in one file to save, open
//! again, and hand to someone else.
//!
//! A workspace file (`*.ferotrx`, JSON) has the servers (addresses and TLS
//! files, never tokens), every port's streams and settings, the Stateful,
//! Application, Benchmark and Scenario forms with the text being edited, the
//! capture that was open and which packets were marked, the tab and port on
//! show, and the window's layout (panel sizes, open sections). The GUI also
//! keeps the same state between sessions by itself; a file is for having
//! several (one per lab, per customer, per test plan) and for sharing them.

use std::path::Path;

use eframe::egui;
use serde::{Deserialize, Serialize};

use crate::app::{BottomTab, FeroApp, LastView, Status, Tab, Workspace};

/// What `format` says in a workspace file.
pub const FORMAT: &str = "ferotrx-workspace-1";
/// The extension workspace files get.
pub const EXTENSION: &str = "ferotrx";

/// A workspace file.
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkspaceFile {
    pub format: String,
    /// Servers, ports and their streams.
    #[serde(flatten)]
    pub work: Workspace,
    /// The servers that were connected, by address: connected again on open.
    pub connected: Vec<String>,
    pub view: View,
    pub capture: CaptureSave,
    pub stateful: crate::views::StatefulState,
    pub scenario: crate::views::ScenarioState,
    pub groups: crate::views::GroupsState,
    pub apps: crate::views::AppsState,
    pub bench: crate::views::BenchState,
    pub y1564: crate::views::Y1564State,
    /// The window's layout (egui's memory: panel sizes, open sections,
    /// scroll positions), as RON text.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub layout: String,
}

/// The tabs on show.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct View {
    pub tab: Tab,
    pub bottom: BottomTab,
}

/// The capture of the Capture tab: its file and the packets marked.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureSave {
    pub path: String,
    pub selected: Option<usize>,
    pub marked: Vec<usize>,
}

impl WorkspaceFile {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("a workspace serializes") + "\n"
    }

    pub fn from_json(text: &str) -> Result<Self, String> {
        let w: WorkspaceFile =
            serde_json::from_str(text).map_err(|e| format!("not a workspace file: {e}"))?;
        if w.format != FORMAT {
            return Err(if w.format.is_empty() {
                "not a workspace file: no \"format\"".into()
            } else {
                format!(
                    "workspace format '{}' is not one this GUI reads ({FORMAT})",
                    w.format
                )
            });
        }
        Ok(w)
    }

    pub fn read(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::from_json(&text).map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// `name` with the workspace extension when it has none.
pub fn with_extension(path: &Path) -> std::path::PathBuf {
    if path.extension().is_some() {
        path.to_path_buf()
    } else {
        path.with_extension(EXTENSION)
    }
}

impl FeroApp {
    /// The window's state, to save.
    pub fn workspace_file(&mut self, ctx: Option<&egui::Context>) -> WorkspaceFile {
        self.remember_view();
        let capture = &self.capture;
        WorkspaceFile {
            format: FORMAT.into(),
            work: self.work.clone(),
            connected: self
                .servers
                .iter()
                .filter(|s| s.conn.is_some())
                .map(|s| s.settings.address())
                .collect(),
            view: View {
                tab: self.tab,
                bottom: self.bottom,
            },
            capture: CaptureSave {
                path: capture.path.clone(),
                selected: capture.selected,
                marked: capture.picked_marks(),
            },
            stateful: clone_json(&self.stateful),
            scenario: clone_json(&self.scenario),
            groups: clone_json(&self.groups),
            apps: clone_json(&self.apps),
            bench: clone_json(&self.bench),
            y1564: clone_json(&self.y1564),
            layout: ctx
                .and_then(|c| c.memory(|m| ron::to_string(m).ok()))
                .unwrap_or_default(),
        }
    }

    /// Writes the servers and the view into `self.work`, as saving does.
    pub fn remember_view(&mut self) {
        self.work.servers = self.servers.iter().map(|s| s.settings.clone()).collect();
        self.work.last = self.servers.get(self.sel_server).map(|s| LastView {
            server: s.settings.address(),
            port: self.sel_port.clone(),
            stream: self.editor.stream,
        });
    }

    /// Replaces the window's state with a workspace: servers are
    /// disconnected, replaced, and the ones that were connected connect again.
    pub fn apply_workspace(&mut self, w: WorkspaceFile) {
        for i in 0..self.servers.len() {
            self.disconnect(i);
        }
        let tokens: Vec<(String, String)> = self
            .servers
            .iter()
            .map(|s| (s.settings.address(), s.settings.token.clone()))
            .collect();
        self.servers = w
            .work
            .servers
            .iter()
            .cloned()
            .map(|mut s| {
                // Keep a token given in this session for the same server.
                if let Some((_, t)) = tokens.iter().find(|(a, _)| *a == s.address()) {
                    s.token = t.clone();
                }
                crate::app::ServerState::new(s)
            })
            .collect();
        self.work = w.work;
        self.sel_server = 0;
        self.sel_port = None;
        self.editor = Default::default();
        if let Some(last) = self.work.last.clone() {
            if let Some(i) = self
                .servers
                .iter()
                .position(|s| s.settings.address() == last.server)
            {
                self.sel_server = i;
                self.sel_port = last.port;
                self.editor.stream = last.stream;
            }
        }
        self.tab = w.view.tab;
        self.bottom = w.view.bottom;
        self.stateful = w.stateful;
        self.scenario = w.scenario;
        self.groups = w.groups;
        self.apps = w.apps;
        self.bench = w.bench;
        self.y1564 = w.y1564;
        self.capture = Default::default();
        if !w.capture.path.is_empty() {
            self.capture.path = w.capture.path;
            self.capture.open();
            if self.capture.capture.is_some() {
                self.capture.selected = w.capture.selected;
                for n in w.capture.marked {
                    if let Some(m) = self.capture.marked.get_mut(n) {
                        *m = true;
                    }
                }
            }
        }
        if !w.layout.is_empty() {
            self.pending_layout = Some(w.layout);
        }
        for i in 0..self.servers.len() {
            if w.connected.contains(&self.servers[i].settings.address()) {
                self.connect(i);
            }
        }
        if self.servers.is_empty() {
            self.servers
                .push(crate::app::ServerState::new(Default::default()));
        }
    }

    /// Opens a workspace file.
    pub fn open_workspace(&mut self, path: &Path) {
        match WorkspaceFile::read(path) {
            Ok(w) => {
                let n = w.work.servers.len();
                self.apply_workspace(w);
                self.workspace_path = Some(path.display().to_string());
                self.info(
                    "",
                    format!("opened workspace {} ({n} servers)", path.display()),
                );
            }
            Err(e) => self.error("", e),
        }
    }

    /// Saves the workspace to `path`.
    pub fn save_workspace(&mut self, path: &Path, ctx: &egui::Context) {
        let path = with_extension(path);
        let w = self.workspace_file(Some(ctx));
        match std::fs::write(&path, w.to_json()) {
            Ok(()) => {
                self.workspace_path = Some(path.display().to_string());
                self.info("", format!("saved workspace {}", path.display()));
            }
            Err(e) => self.error("", format!("{}: {e}", path.display())),
        }
    }

    /// Starts again with no servers but one on this computer, nothing
    /// edited, the layout kept.
    pub fn new_workspace(&mut self) {
        let mut w = WorkspaceFile {
            format: FORMAT.into(),
            ..Default::default()
        };
        w.work.servers.push(Default::default());
        self.apply_workspace(w);
        self.workspace_path = None;
        self.info("", "new workspace");
    }

    /// The workspace menu of the top bar.
    pub fn workspace_menu(&mut self, ui: &mut egui::Ui) {
        let title = match &self.workspace_path {
            Some(p) => Path::new(p)
                .file_name()
                .map_or(p.clone(), |n| n.to_string_lossy().into_owned()),
            None => "Workspace".into(),
        };
        ui.menu_button(title, |ui| {
            if ui.button("New").clicked() {
                self.new_workspace();
                ui.close();
            }
            if ui.button("Open…").clicked() {
                let cur = self.workspace_path.clone().unwrap_or_default();
                self.files.pick(
                    crate::files::Target::OpenWorkspace,
                    "Open a workspace",
                    crate::files::Kind::Workspace,
                    &cur,
                );
                ui.close();
            }
            let path = self.workspace_path.clone();
            if ui
                .add_enabled(path.is_some(), egui::Button::new("Save"))
                .clicked()
            {
                if let Some(p) = path {
                    let ctx = ui.ctx().clone();
                    self.save_workspace(Path::new(&p), &ctx);
                }
                ui.close();
            }
            if ui.button("Save as…").clicked() {
                let cur = self.workspace_path.clone().unwrap_or_default();
                self.files.save(
                    crate::files::Target::SaveWorkspace,
                    "Save the workspace",
                    crate::files::Kind::Workspace,
                    &cur,
                    "lab.ferotrx",
                );
                ui.close();
            }
            ui.separator();
            ui.label(
                egui::RichText::new(
                    "Servers, streams, forms, the capture and the layout.\nTokens are never saved.",
                )
                .small()
                .weak(),
            );
        })
        .response
        .on_hover_text(
            self.workspace_path
                .clone()
                .unwrap_or_else(|| "Save everything in one file, open it again".into()),
        );
    }

    /// Restores a layout from a workspace, at the start of a frame.
    pub fn apply_pending_layout(&mut self, ctx: &egui::Context) {
        if let Some(l) = self.pending_layout.take() {
            match ron::from_str::<egui::Memory>(&l) {
                Ok(m) => ctx.memory_mut(|mem| *mem = m),
                Err(e) => self.error("", format!("workspace layout: {e}")),
            }
        }
    }

    /// True when a server of the workspace is connected.
    pub fn any_connected(&self) -> bool {
        self.servers.iter().any(|s| s.status == Status::Connected)
    }
}

/// A copy of a form through its saved fields only.
fn clone_json<T: Serialize + serde::de::DeserializeOwned + Default>(t: &T) -> T {
    serde_json::to_value(t)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_other_files() {
        assert!(WorkspaceFile::from_json("{}").is_err());
        assert!(WorkspaceFile::from_json(r#"{"format":"ferotrx-workspace-9"}"#).is_err());
        assert!(WorkspaceFile::from_json("format = 1").is_err());
        let w = WorkspaceFile::from_json(r#"{"format":"ferotrx-workspace-1"}"#).unwrap();
        assert!(w.work.servers.is_empty());
    }

    #[test]
    fn a_saved_workspace_opens_the_same() {
        use crate::app::Workspace;
        use crate::conn::ConnSettings;
        use crate::model::{PortKind, StreamDraft};
        use crate::{FeroApp, Options};

        let ctx = egui::Context::default();
        let mut a = FeroApp::with_workspace(ctx.clone(), Workspace::default(), Options::default());
        a.servers[0].settings = ConnSettings {
            addr: "10.0.0.9:4510".into(),
            token: "secret".into(),
            ..Default::default()
        };
        a.servers
            .push(crate::app::ServerState::new(ConnSettings::default()));
        let port = PortKind::Interface("eth1".into());
        let s = StreamDraft {
            name: "probe".into(),
            rate: "50pps".into(),
            ..Default::default()
        };
        a.port_work(0, &port).profile.streams.push(s);
        a.sel_port = Some(port.clone());
        a.tab = Tab::Scenario;
        a.stateful.path = "examples/lab-tcp.toml".into();
        a.stateful.rate = "200".into();
        a.scenario.text = "format = 1\n".into();
        let dir = std::env::temp_dir().join(format!("ftrx-ws-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lab");
        a.save_workspace(&path, &ctx);
        let saved = dir.join("lab.ferotrx");
        let text = std::fs::read_to_string(&saved).unwrap();
        assert!(!text.contains("secret"), "tokens are never saved");
        assert!(text.contains("\"format\": \"ferotrx-workspace-1\""));

        let mut b = FeroApp::with_workspace(
            egui::Context::default(),
            Workspace::default(),
            Options::default(),
        );
        b.open_workspace(&saved);
        assert_eq!(b.workspace_path.as_deref(), Some(saved.to_str().unwrap()));
        assert_eq!(b.servers.len(), 2);
        assert_eq!(b.servers[0].settings.addr, "10.0.0.9:4510");
        assert!(b.servers[0].settings.token.is_empty());
        assert_eq!(b.sel_port, Some(port.clone()));
        assert_eq!(b.tab, Tab::Scenario);
        let streams = &b.port_work(0, &port).profile.streams;
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].name, "probe");
        assert_eq!(streams[0].rate, "50pps");
        assert_eq!(b.stateful.rate, "200");
        assert_eq!(b.scenario.text, "format = 1\n");
        assert!(b.pending_layout.is_some(), "the layout comes back too");
        b.apply_pending_layout(&egui::Context::default());
        assert!(!b.log.iter().any(|l| l.error), "{:?}", b.log);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn extension_added() {
        assert_eq!(
            with_extension(Path::new("/tmp/lab")),
            Path::new("/tmp/lab.ferotrx")
        );
        assert_eq!(
            with_extension(Path::new("/tmp/lab.json")),
            Path::new("/tmp/lab.json")
        );
    }
}
