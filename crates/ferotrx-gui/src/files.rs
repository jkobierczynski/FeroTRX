//! File dialogs for every path the GUI asks for, and the folders relative
//! paths in a profile start from.
//!
//! Paths on this computer (profiles to open and save, captures, certificates)
//! are always picked with a dialog. Paths on the server (a capture a stream
//! replays, the file the `file` port writes, a profile the server reads) can
//! be picked the same way when the server runs on this computer; for a
//! server elsewhere they are typed, relative to its data directory.
//!
//! On Windows the dialogs are Explorer's own (`rfd`, on a thread of their
//! own so the window keeps drawing); elsewhere they are drawn in the window
//! (`egui-file-dialog`), which needs no desktop portal or GTK.

use std::path::{Path, PathBuf};

use eframe::egui;
use egui_file_dialog::{FileDialog, Filter};

/// What a picked path is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// A profile on this computer whose streams replace the port's.
    OpenProfile,
    /// Where to save the port's streams as a profile.
    SaveProfile,
    /// A capture for the Capture tab.
    Capture,
    /// Where to save the capture shown (a live one).
    SaveCapture,
    /// The profile of a TCP or UDP run.
    StatefulProfile,
    /// The capture stream `n` of the selected port replays (on the server).
    ReplayPcap(usize),
    /// The output of the `file` port (on the server).
    FileOut,
    /// A certificate or key in the server form: 0 CA, 1 cert, 2 key.
    Pem(u8),
    /// A scenario to open in the Scenario tab (on this computer, or on the
    /// server when it is this computer).
    OpenScenario,
    /// Where to save the scenario being edited.
    SaveScenario,
    /// Where to save the report of the scenario run shown: JSON, or JUnit XML.
    ScenarioReport { junit: bool },
    /// A workspace file to open.
    OpenWorkspace,
    /// Where to save the workspace.
    SaveWorkspace,
    /// A scenario report for one side of a comparison.
    CompareReport { before: bool },
    /// Where to save a comparison.
    SaveComparison,
    /// A TCP or UDP profile for the Applications tab.
    OpenAppProfile,
    /// Where to save the profile of the Applications tab.
    SaveAppProfile,
    /// A benchmark profile for the Benchmark tab.
    OpenBench,
    /// Where to save the benchmark profile.
    SaveBench,
    /// Where to save the report of the benchmark run shown.
    BenchReport,
    /// A Y.1564 profile for the Y.1564 tab.
    OpenY1564,
    /// Where to save the Y.1564 profile.
    SaveY1564,
    /// Where to save the report of the Y.1564 run shown.
    Y1564Report,
    /// A theme file for the Appearance window.
    OpenTheme,
    /// Where to save the theme.
    SaveTheme,
}

/// The kinds of file a dialog lists first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Profile,
    Capture,
    Pem,
    Report,
    Junit,
    Workspace,
    Text,
    Theme,
}

impl Kind {
    fn filter(self) -> (&'static str, &'static [&'static str]) {
        match self {
            Kind::Profile => ("Profiles (*.toml)", &["toml"]),
            Kind::Capture => ("Captures (*.pcap, *.pcapng)", &["pcap", "pcapng", "cap"]),
            Kind::Pem => ("PEM files (*.pem, *.crt, *.key)", &["pem", "crt", "key"]),
            Kind::Report => ("Reports (*.json)", &["json"]),
            Kind::Junit => ("JUnit XML (*.xml)", &["xml"]),
            Kind::Workspace => ("Workspaces (*.ferotrx)", &["ferotrx"]),
            Kind::Text => ("Text (*.txt, *.json)", &["txt", "json"]),
            Kind::Theme => ("Themes (*.toml)", &["toml"]),
        }
    }
}

/// An Explorer dialog running on its own thread.
#[cfg(windows)]
struct Native {
    rx: std::sync::mpsc::Receiver<Option<PathBuf>>,
    /// Extension to add to a saved file named without one.
    save_ext: Option<&'static str>,
}

/// The one file dialog of the window, and what it was opened for.
#[derive(Default)]
pub struct Dialogs {
    dialog: Option<FileDialog>,
    #[cfg(windows)]
    native: Option<Native>,
    target: Option<Target>,
    /// Where the last dialog picked something, to start there next time.
    pub last_dir: Option<PathBuf>,
}

impl Dialogs {
    /// Opens a dialog to pick an existing file.
    pub fn pick(&mut self, target: Target, title: &str, kind: Kind, current: &str) {
        #[cfg(windows)]
        if native_dialogs() {
            return self.native(target, title, kind, current, None);
        }
        let d = self.build(title, kind, current);
        self.show(d, target, false);
    }

    /// Opens a dialog to name a file to write, `name` filled in.
    pub fn save(&mut self, target: Target, title: &str, kind: Kind, current: &str, name: &str) {
        #[cfg(windows)]
        if native_dialogs() {
            return self.native(target, title, kind, current, Some(name));
        }
        let (label, ext) = kind.filter();
        let d = self
            .build(title, kind, current)
            .default_file_name(name)
            .add_save_extension(label, ext[0])
            .default_save_extension(label);
        self.show(d, target, true);
    }

    /// An Explorer dialog: `name` set for a save dialog.
    #[cfg(windows)]
    fn native(
        &mut self,
        target: Target,
        title: &str,
        kind: Kind,
        current: &str,
        name: Option<&str>,
    ) {
        let (label, exts) = kind.filter();
        let mut d = rfd::FileDialog::new()
            .set_title(title)
            .set_directory(self.start_dir(current))
            .add_filter(label, exts)
            .add_filter("All files", &["*"]);
        if let Some(n) = name {
            d = d.set_file_name(n);
        }
        let save = name.is_some();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(if save { d.save_file() } else { d.pick_file() });
        });
        self.native = Some(Native {
            rx,
            save_ext: save.then_some(exts[0]),
        });
        self.target = Some(target);
    }

    fn build(&self, title: &str, kind: Kind, current: &str) -> FileDialog {
        let (label, exts) = kind.filter();
        let exts: Vec<String> = exts.iter().map(|e| e.to_string()).collect();
        FileDialog::new()
            .title(title)
            .initial_directory(self.start_dir(current))
            .add_file_filter(
                label,
                Filter::new(move |p: &Path| {
                    p.extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| exts.iter().any(|x| x.eq_ignore_ascii_case(e)))
                }),
            )
            .add_file_filter("All files", Filter::new(|_: &Path| true))
            .default_file_filter(label)
            .default_size([720.0, 440.0])
    }

    fn show(&mut self, mut d: FileDialog, target: Target, save: bool) {
        if save {
            d.save_file();
        } else {
            d.pick_file();
        }
        self.dialog = Some(d);
        self.target = Some(target);
    }

    /// The folder of the path in the field, else where the last dialog
    /// picked something, else the current directory.
    fn start_dir(&self, current: &str) -> PathBuf {
        let c = current.trim();
        if !c.is_empty() {
            let p = absolute(Path::new(c));
            let dir = if p.is_dir() {
                Some(p.as_path())
            } else {
                p.parent()
            };
            if let Some(d) = dir.filter(|d| d.is_dir()) {
                return d.to_path_buf();
            }
        }
        self.last_dir
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."))
    }

    pub fn is_open(&self) -> bool {
        #[cfg(windows)]
        if self.native.is_some() {
            return true;
        }
        self.dialog.is_some()
    }

    /// Draws the dialog; returns what was picked, once.
    pub fn update(&mut self, ctx: &egui::Context) -> Option<(Target, PathBuf)> {
        #[cfg(windows)]
        if let Some(n) = &self.native {
            let picked = match n.rx.try_recv() {
                Ok(p) => p,
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    // Look again soon: nothing else wakes the window.
                    ctx.request_repaint_after(std::time::Duration::from_millis(100));
                    return None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => None,
            };
            let ext = n.save_ext;
            self.native = None;
            let target = self.target.take()?;
            let mut path = picked?;
            if let (Some(ext), None) = (ext, path.extension()) {
                path.set_extension(ext);
            }
            if let Some(dir) = path.parent() {
                self.last_dir = Some(dir.to_path_buf());
            }
            return Some((target, path));
        }
        let d = self.dialog.as_mut()?;
        d.update(ctx);
        let picked = d.take_picked();
        let open = *d.state() == egui_file_dialog::DialogState::Open;
        if picked.is_none() && open {
            return None;
        }
        self.dialog = None;
        let target = self.target.take()?;
        let path = picked?;
        if let Some(dir) = path.parent() {
            self.last_dir = Some(dir.to_path_buf());
        }
        Some((target, path))
    }
}

/// Explorer dialogs, unless FEROTRX_GUI_DIALOGS=egui asks for the ones drawn
/// in the window.
#[cfg(windows)]
fn native_dialogs() -> bool {
    std::env::var("FEROTRX_GUI_DIALOGS").map_or(true, |v| !v.eq_ignore_ascii_case("egui"))
}

/// `p` from the current directory when it is relative.
pub fn absolute(p: &Path) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

/// The folder a profile file is in, as an absolute path: where its relative
/// paths start.
pub fn folder_of(file: &Path) -> String {
    let p = absolute(file);
    let dir = p.canonicalize().unwrap_or(p);
    dir.parent()
        .map(|d| d.display().to_string())
        .unwrap_or_default()
}

/// `path` relative to `base` when it is inside it, else as it is.
pub fn relative_to(path: &Path, base: &str) -> String {
    if !base.is_empty() {
        if let Ok(r) = path.strip_prefix(base) {
            return r.display().to_string();
        }
    }
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_folders_are_absolute() {
        let dir = env!("CARGO_MANIFEST_DIR");
        let f = folder_of(Path::new(&format!("{dir}/../../examples/lab-tcp.toml")));
        assert!(Path::new(&f).is_absolute());
        assert!(f.ends_with("examples"), "{f}");
        let pcap = Path::new(&f).join("http.pcap");
        assert_eq!(relative_to(&pcap, &f), "http.pcap");
        assert_eq!(relative_to(&pcap, "/elsewhere"), pcap.display().to_string());
        assert_eq!(relative_to(&pcap, ""), pcap.display().to_string());
    }

    #[test]
    fn dialogs_start_in_the_folder_of_the_field() {
        let dir = env!("CARGO_MANIFEST_DIR");
        let d = Dialogs::default();
        assert_eq!(
            d.start_dir(&format!("{dir}/Cargo.toml")),
            PathBuf::from(dir)
        );
        assert_eq!(d.start_dir(dir), PathBuf::from(dir));
        assert!(d.start_dir("").is_dir());
    }
}
