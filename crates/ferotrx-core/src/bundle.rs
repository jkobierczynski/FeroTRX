//! A profile and the files it names, to send to a server together.
//!
//! A profile names other files by paths relative to its own folder: the
//! capture a stream replays, a body an HTTP server sends, the profiles of a
//! scenario's checks (and theirs in turn). A server on another computer has
//! none of them, so a client sends them along, keeping their places relative
//! to the profile so that its paths hold on the server too. `ferotrx fleet`
//! deploys runs this way, and the GUI sends every profile like this.

use std::path::{Component, Path, PathBuf};

/// How deep profiles naming profiles are followed (scenario → TCP profile →
/// capture is two).
const DEPTH: usize = 4;

/// The files `text` (TOML, read from `dir`) names by relative paths that
/// exist in `dir`: every string value that is the path of a file. A named
/// file that is itself a profile (TOML) is searched as well, from its own
/// folder. Paths are canonical; `${VAR}`s are blanked first.
pub fn files_named(text: &str, dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(t) = toml::from_str::<toml::Table>(&crate::check::blank(text)) {
        walk_table(&t, dir, &mut out, 0);
    }
    out
}

/// [`files_named`] for a table already parsed.
pub fn files_named_in(table: &toml::Table, dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_table(table, dir, &mut out, 0);
    out
}

fn walk_table(t: &toml::Table, dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    for v in t.values() {
        walk(v, dir, out, depth);
    }
}

fn walk(v: &toml::Value, dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    match v {
        toml::Value::String(s) => {
            let p = Path::new(s);
            if s.is_empty() || s.len() > 1024 || s.contains('\n') || p.is_absolute() {
                return;
            }
            let full = dir.join(p);
            if !full.is_file() {
                return;
            }
            let Ok(c) = full.canonicalize() else {
                return;
            };
            if out.contains(&c) {
                return;
            }
            out.push(c.clone());
            if depth + 1 < DEPTH && crate::check::FileKind::is_profile_path(&c) {
                if let Some(t) = std::fs::read_to_string(&c).ok().and_then(|text| {
                    toml::from_str::<toml::Table>(&crate::check::blank(&text)).ok()
                }) {
                    let sub = c.parent().unwrap_or(Path::new("."));
                    walk_table(&t, sub, out, depth + 1);
                }
            }
        }
        toml::Value::Array(a) => a.iter().for_each(|v| walk(v, dir, out, depth)),
        toml::Value::Table(t) => walk_table(t, dir, out, depth),
        _ => {}
    }
}

/// Where a profile's files go under a folder on the server.
#[derive(Clone, Debug, PartialEq)]
pub struct Bundle {
    /// The folder the profile's relative paths start from there (relative
    /// to the server's data directory, with `/`): `base_dir` of a start.
    pub base_dir: String,
    /// Each file here and where it goes there (with `/`).
    pub files: Vec<(PathBuf, String)>,
}

impl Bundle {
    /// The places under `dest` (relative, with `/`) for `files` of a
    /// profile in `dir`: they keep their places relative to the profile.
    /// Files above the profile's folder move the profile down, so that
    /// `../captures/a.pcap` still works.
    pub fn place(dir: &Path, files: &[PathBuf], dest: &str) -> Bundle {
        let here = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
        let mut root = here.clone();
        for f in files {
            let parent = f.parent().unwrap_or(f);
            while !parent.starts_with(&root) {
                if !root.pop() {
                    break;
                }
            }
        }
        let rel = |p: &Path| -> String {
            match p.strip_prefix(&root) {
                Ok(r) => slashed(r),
                Err(_) => p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            }
        };
        let join = |a: &str, b: String| -> String {
            match (a.trim_end_matches('/'), b.as_str()) {
                ("", b) => b.to_string(),
                (a, "") => a.to_string(),
                (a, b) => format!("{a}/{b}"),
            }
        };
        let dest = dest.trim_matches('/');
        Bundle {
            base_dir: join(dest, rel(&here)),
            files: files
                .iter()
                .map(|f| (f.clone(), join(dest, rel(f))))
                .collect(),
        }
    }

    /// The files `text` from `dir` names, placed under `dest`.
    pub fn of(text: &str, dir: &Path, dest: &str) -> Bundle {
        Self::place(dir, &files_named(text, dir), dest)
    }
}

/// A relative path with `/` between its parts, whatever this system uses
/// (the server may be another one).
fn slashed(p: &Path) -> String {
    p.components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// A name usable as one folder name on any system: letters, digits, `-`,
/// `_` and `.` kept, anything else `-`.
pub fn folder_name(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    let out = out.trim_matches(|c| c == '-' || c == '.').to_string();
    if out.is_empty() {
        "x".into()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn examples() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples")
            .canonicalize()
            .unwrap()
    }

    #[test]
    fn a_tcp_profile_takes_its_capture_along() {
        let dir = examples();
        let text = std::fs::read_to_string(dir.join("lab-tcp.toml")).unwrap();
        let b = Bundle::of(&text, &dir, "gui/me/lab-tcp");
        assert_eq!(b.base_dir, "gui/me/lab-tcp");
        assert!(
            b.files
                .iter()
                .any(|(l, r)| l.ends_with("http.pcap") && r == "gui/me/lab-tcp/http.pcap"),
            "{b:?}"
        );
    }

    #[test]
    fn a_scenario_takes_its_profiles_and_their_files() {
        let dir = examples();
        let text = std::fs::read_to_string(dir.join("lab-scenario-impaired.toml")).unwrap();
        let files = files_named(&text, &dir);
        let names: Vec<String> = files
            .iter()
            .map(|f| f.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|n| n == "http.pcap"), "{names:?}");
        assert!(names.iter().any(|n| n.starts_with("lab-tcp")), "{names:?}");
    }

    #[test]
    fn files_above_the_profile_keep_their_place() {
        let dir = std::env::temp_dir().join(format!("ftrx-bundle-{}", std::process::id()));
        let prof = dir.join("profiles");
        let caps = dir.join("captures");
        std::fs::create_dir_all(&prof).unwrap();
        std::fs::create_dir_all(&caps).unwrap();
        std::fs::write(caps.join("a.pcap"), b"x").unwrap();
        let text = "[[stream]]\npcap = \"../captures/a.pcap\"\n";
        let b = Bundle::of(text, &prof, "gui/u/p");
        assert_eq!(b.base_dir, "gui/u/p/profiles");
        assert_eq!(b.files.len(), 1);
        assert_eq!(b.files[0].1, "gui/u/p/captures/a.pcap");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn folder_names_are_plain() {
        assert_eq!(folder_name("Jurgen@DESKTOP 1"), "Jurgen-DESKTOP-1");
        assert_eq!(folder_name("..."), "x");
    }
}
