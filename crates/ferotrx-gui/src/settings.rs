//! The user's own settings: which folders file dialogs start in, and
//! whether the Start page shows when the GUI opens.
//!
//! They live in a file of the user's, never in a folder shared by every
//! user (such as `C:\ProgramData`, which only administrators may write):
//!
//! | System  | File |
//! |---------|------|
//! | Windows | `%APPDATA%\FeroTRX\settings.toml` |
//! | macOS   | `~/Library/Application Support/FeroTRX/settings.toml` |
//! | Linux   | `$XDG_CONFIG_HOME/ferotrx/settings.toml` (`~/.config/ferotrx`) |
//!
//! `FEROTRX_GUI_CONFIG` names another folder (tests use it). The window's
//! layout and the forms of the last session are kept by eframe next to it
//! (`%APPDATA%\FeroTRX\data\app.ron` on Windows).
//!
//! The folders default to `Documents\FeroTRX` (`~/Documents/FeroTRX`).
//! The first time, the installed examples are copied to its `examples`
//! folder, so they can be opened, changed and saved without administrator
//! rights.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const FILE: &str = "settings.toml";

/// What a file dialog is looking for, as far as its start folder goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FolderKind {
    /// Profiles, scenarios, workspaces, themes: what the user writes.
    Profiles,
    /// Captures (pcap, pcapng).
    Captures,
    /// Reports and comparisons the GUI saves.
    Reports,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Where profile dialogs start (and where the examples are copied).
    pub profiles: String,
    /// Where capture dialogs start.
    pub captures: String,
    /// Where report dialogs start.
    pub reports: String,
    /// Show the Start page when the GUI opens.
    pub show_start: bool,
    /// The version whose examples were copied last; a newer GUI copies the
    /// examples it adds (it never overwrites a file).
    pub examples_copied: String,
}

impl Default for Settings {
    fn default() -> Self {
        let home = user_folder().display().to_string();
        Self {
            profiles: home.clone(),
            captures: home.clone(),
            reports: user_folder().join("reports").display().to_string(),
            show_start: true,
            examples_copied: String::new(),
        }
    }
}

/// The folder settings.toml is in.
pub fn config_dir() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("FEROTRX_GUI_CONFIG").filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(d));
    }
    let base = directories::BaseDirs::new()?;
    Some(if cfg!(any(windows, target_os = "macos")) {
        // %APPDATA% (Roaming), ~/Library/Application Support.
        base.config_dir().join("FeroTRX")
    } else {
        base.config_dir().join("ferotrx")
    })
}

/// `Documents/FeroTRX`, or `FeroTRX` in the home folder when there is no
/// Documents folder.
pub fn user_folder() -> PathBuf {
    if let Some(d) =
        directories::UserDirs::new().and_then(|u| u.document_dir().map(Path::to_path_buf))
    {
        return d.join("FeroTRX");
    }
    directories::BaseDirs::new()
        .map(|b| b.home_dir().join("FeroTRX"))
        .unwrap_or_else(|| PathBuf::from("FeroTRX"))
}

impl Settings {
    /// The saved settings, or the defaults.
    pub fn load() -> Settings {
        config_dir()
            .and_then(|d| std::fs::read_to_string(d.join(FILE)).ok())
            .and_then(|t| toml::from_str(&t).ok())
            .unwrap_or_default()
    }

    /// True when there are no saved settings yet: the first start.
    pub fn first_start() -> bool {
        config_dir().is_none_or(|d| !d.join(FILE).is_file())
    }

    pub fn save(&self) -> Result<PathBuf, String> {
        let dir = config_dir().ok_or("no folder for the settings (no home folder)")?;
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let path = dir.join(FILE);
        let text = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        Ok(path)
    }

    /// The start folder for a kind of file, if it exists (or can be made).
    pub fn folder(&self, kind: FolderKind) -> Option<PathBuf> {
        let f = match kind {
            FolderKind::Profiles => &self.profiles,
            FolderKind::Captures => &self.captures,
            FolderKind::Reports => &self.reports,
        };
        let p = PathBuf::from(f.trim());
        if f.trim().is_empty() {
            return None;
        }
        if !p.is_dir() {
            std::fs::create_dir_all(&p).ok()?;
        }
        Some(p)
    }

    /// The folder the examples are copied to.
    pub fn examples_dir(&self) -> PathBuf {
        PathBuf::from(self.profiles.trim()).join("examples")
    }

    /// Copies the installed examples to [`examples_dir`](Self::examples_dir)
    /// once per version, each under the extension of its kind (`lab-tcp.toml`
    /// becomes `lab-tcp.fttcp`); files already there are left alone. Returns
    /// how many it copied.
    pub fn copy_examples(&mut self) -> Result<usize, String> {
        let version = env!("CARGO_PKG_VERSION");
        if self.examples_copied == version {
            return Ok(0);
        }
        let Some(src) = installed_examples() else {
            return Ok(0);
        };
        let n = copy_examples(&src, &self.examples_dir())?;
        self.examples_copied = version.into();
        Ok(n)
    }
}

/// The examples that came with the programs: next to them (Windows, the
/// archives), in the package's share folder (Linux), or in the source tree
/// of a development build.
pub fn installed_examples() -> Option<PathBuf> {
    let mut v = Vec::new();
    if let Some(d) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
    {
        v.push(d.join("examples"));
        v.push(d.join("../share/ferotrx/examples"));
        v.push(d.join("../share/doc/ferotrx/examples"));
    }
    v.push(PathBuf::from("/usr/share/ferotrx/examples"));
    v.push(PathBuf::from("/usr/share/doc/ferotrx/examples"));
    v.push(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples"));
    // Cargo's target folders have an `examples` folder of their own: ours
    // has the captures the profiles replay.
    v.into_iter()
        .find(|d| d.join("http.pcap").is_file())
        .map(|d| d.canonicalize().unwrap_or(d))
}

/// Copies every file of `src` (and its folders) to `dest`; a FeroTRX
/// profile gets its kind's extension, and the profiles that name it (a
/// scenario's `tcp = "lab-tcp.toml"`) name it by its new name. Existing
/// files are kept.
pub fn copy_examples(src: &Path, dest: &Path) -> Result<usize, String> {
    let mut renames = Vec::new();
    collect_renames(src, &mut renames);
    let mut n = 0;
    copy_dir(src, dest, &renames, &mut n)?;
    Ok(n)
}

/// (old name, new name) of every profile under `dir` that gets renamed.
fn collect_renames(dir: &Path, out: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_renames(&p, out);
            continue;
        }
        let old = e.file_name().to_string_lossy().into_owned();
        let new = example_name(&p);
        if new != old {
            out.push((old, new));
        }
    }
}

fn copy_dir(
    src: &Path,
    dest: &Path,
    renames: &[(String, String)],
    n: &mut usize,
) -> Result<(), String> {
    let entries = std::fs::read_dir(src).map_err(|e| format!("{}: {e}", src.display()))?;
    std::fs::create_dir_all(dest).map_err(|e| format!("cannot create {}: {e}", dest.display()))?;
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name();
        if p.is_dir() {
            copy_dir(&p, &dest.join(&name), renames, n)?;
            continue;
        }
        let to = dest.join(example_name(&p));
        if to.exists() {
            continue;
        }
        let fail =
            |e: std::io::Error| format!("cannot copy {} to {}: {e}", p.display(), to.display());
        if ferotrx_core::check::FileKind::is_profile_path(&p) {
            let mut text = std::fs::read_to_string(&p).map_err(fail)?;
            for (old, new) in renames {
                text = text.replace(&format!("\"{old}\""), &format!("\"{new}\""));
                text = text.replace(&format!("/{old}"), &format!("/{new}"));
                text = text.replace(&format!(" {old} "), &format!(" {new} "));
            }
            std::fs::write(&to, text).map_err(fail)?;
        } else {
            std::fs::copy(&p, &to).map_err(fail)?;
        }
        *n += 1;
    }
    Ok(())
}

/// The name of an example once copied: a `.toml` profile under its kind's
/// extension, anything else as it is.
pub fn example_name(p: &Path) -> String {
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let is_toml = p
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("toml"));
    if !is_toml {
        return name;
    }
    match std::fs::read_to_string(p)
        .ok()
        .and_then(|t| ferotrx_core::check::detect_kind(&t).ok())
    {
        Some(k) => Path::new(&name)
            .with_extension(k.extension())
            .display()
            .to_string(),
        None => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip() {
        let s = Settings {
            profiles: "/p".into(),
            show_start: false,
            ..Default::default()
        };
        let t = toml::to_string_pretty(&s).unwrap();
        let back: Settings = toml::from_str(&t).unwrap();
        assert_eq!(back, s);
        // Missing keys take their defaults.
        let partial: Settings = toml::from_str("show_start = false").unwrap();
        assert!(!partial.profiles.is_empty());
    }

    #[test]
    fn examples_get_the_extension_of_their_kind() {
        let src = installed_examples().expect("the source tree has examples");
        assert_eq!(example_name(&src.join("lab-tcp.toml")), "lab-tcp.fttcp");
        assert_eq!(example_name(&src.join("lab-dns.toml")), "lab-dns.ftudp");
        assert_eq!(
            example_name(&src.join("lab-two-vlans.toml")),
            "lab-two-vlans.ftstream"
        );
        assert_eq!(
            example_name(&src.join("lab-scenario.toml")),
            "lab-scenario.ftscenario"
        );
        assert_eq!(example_name(&src.join("http.pcap")), "http.pcap");
    }

    #[test]
    fn copying_keeps_what_is_there() {
        let src = installed_examples().unwrap();
        let dest = std::env::temp_dir().join(format!("ftrx-gui-examples-{}", std::process::id()));
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(dest.join("lab-tcp.fttcp"), "mine").unwrap();
        let n = copy_examples(&src, &dest).unwrap();
        assert!(n > 10, "{n}");
        assert_eq!(
            std::fs::read_to_string(dest.join("lab-tcp.fttcp")).unwrap(),
            "mine"
        );
        assert!(dest.join("http.pcap").is_file());
        // A scenario names its profiles by their new names, and still checks out.
        let sc = dest.join("lab-scenario-apps.ftscenario");
        let text = std::fs::read_to_string(&sc).unwrap();
        assert!(text.contains("tcp = \"lab-http.fttcp\""), "{text}");
        ferotrx_core::check::check_file(&sc, None, &[]).unwrap();
        assert_eq!(copy_examples(&src, &dest).unwrap(), 0);
        std::fs::remove_dir_all(&dest).ok();
    }
}
