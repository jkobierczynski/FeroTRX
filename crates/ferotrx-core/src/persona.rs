//! Personas: reusable workload files that say what one kind of user does.
//!
//! A persona file (`office.toml`, `iot.toml`, ...) gives how its users
//! behave (`[user]`: think time between sessions, how long they stay, how
//! fast they arrive) and the sessions they make: `[[tcp]]` and `[[udp]]`
//! tables, written as a TCP or UDP profile's `[[template]]` tables, with
//! weights, application protocols, request sequences, sizes and session
//! lengths. A TCP or UDP profile uses personas with `[[persona]]` tables,
//! each saying how many of its users are online at once:
//!
//! ```toml
//! [[persona]]
//! file = "personas/office.toml"
//! users = 50
//! think = "exp(10s)"          # optional: overrides the persona's [user]
//! port_offset = 1000          # optional: added to the persona's template ports
//! ```
//!
//! The persona's templates join the profile's as `persona/template`; the
//! profile's `[server]` answers them too. A capture (`pcap`) is looked for
//! next to the persona file; other files its tables name, next to the
//! profile. Scenarios and fleet plans run
//! such profiles like any other.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::users::RawUsers;

/// Asked before a file a profile names is read: the path to read, or why
/// not (a control server's data directories).
pub type FileAllow<'a> = &'a dyn Fn(&Path) -> std::result::Result<PathBuf, String>;

/// Allows every file.
pub(crate) fn any_file(p: &Path) -> std::result::Result<PathBuf, String> {
    Ok(p.to_path_buf())
}
use crate::{check_format, Error, Result, UserGroup};

/// A persona file.
#[derive(Clone, Debug)]
pub struct Persona {
    pub name: String,
    pub description: Option<String>,
    /// The persona's own `[user]` table.
    user: RawUsers,
    /// TCP templates, as `[[template]]` tables of a TCP profile.
    pub tcp: Vec<toml::Table>,
    /// UDP templates, as `[[template]]` tables of a UDP profile.
    pub udp: Vec<toml::Table>,
    /// The file's directory, for the captures it names.
    pub dir: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPersona {
    format: Option<u32>,
    name: Option<String>,
    description: Option<String>,
    user: Option<RawUsers>,
    #[serde(default)]
    tcp: Vec<toml::Table>,
    #[serde(default)]
    udp: Vec<toml::Table>,
}

/// A profile's `[[persona]]` table.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUse {
    file: String,
    users: u32,
    name: Option<String>,
    port_offset: Option<u16>,
    think: Option<crate::dist::DistText>,
    lifetime: Option<crate::dist::DistText>,
    arrival: Option<f64>,
}

/// Which templates a profile takes from a persona.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PersonaKind {
    Tcp,
    Udp,
}

impl Persona {
    /// Parses a persona; `dir` is where its captures are looked for.
    pub fn from_toml(text: &str, dir: &Path) -> Result<Self> {
        let raw: RawPersona =
            toml::from_str(text).map_err(|e| Error::Profile(format!("persona: {e}")))?;
        check_format(raw.format)?;
        if raw.tcp.is_empty() && raw.udp.is_empty() {
            return Err(Error::Profile(
                "persona: give [[tcp]] or [[udp]] tables, the sessions its users make".into(),
            ));
        }
        let p = Self {
            name: raw.name.unwrap_or_else(|| "persona".into()),
            description: raw.description,
            user: raw.user.unwrap_or_default(),
            tcp: raw.tcp,
            udp: raw.udp,
            dir: dir.to_path_buf(),
        };
        if p.user.count.is_some() {
            return Err(Error::Profile(format!(
                "persona {}: [user] takes no `count`; the profile's [[persona]] says how many users",
                p.name
            )));
        }
        // The behaviour must parse, whatever the count.
        p.user.group(&p.name, Some(1))?;
        Ok(p)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Profile(format!("cannot read persona {}: {e}", path.display())))?;
        let dir = path.parent().unwrap_or(Path::new("."));
        Self::from_toml(&text, dir).map_err(|e| Error::Profile(format!("{}: {e}", path.display())))
    }

    /// The users of this persona: `users` online at once.
    pub fn group(&self, users: u32) -> Result<UserGroup> {
        self.user.group(&self.name, Some(users))
    }

    /// One line on the persona.
    pub fn describe(&self) -> String {
        let g = self.user.group(&self.name, Some(1));
        let mut s = format!(
            "persona {}: {} TCP and {} UDP template(s)",
            self.name,
            self.tcp.len(),
            self.udp.len()
        );
        if let Ok(g) = g {
            if !g.think.is_zero() {
                s.push_str(&format!(", think {}", g.think));
            }
            if let Some(l) = &g.lifetime {
                s.push_str(&format!(", stay {l}"));
            }
        }
        if let Some(d) = &self.description {
            s.push_str(&format!(": {d}"));
        }
        s
    }
}

/// Takes a profile's `[users]` and `[[persona]]` tables out of `doc`, and
/// adds each persona's templates to its `template` array, marked with
/// their group. Returns the groups: `[users]` first (group 0, for the
/// profile's own templates), then one per persona. `own` tells whether the
/// profile's own templates are in group 0.
pub(crate) fn expand(
    doc: &mut toml::Table,
    base_dir: &Path,
    kind: PersonaKind,
    allow: FileAllow<'_>,
) -> Result<(Vec<UserGroup>, bool)> {
    let mut groups = Vec::new();
    let own = match doc.remove("users") {
        Some(v) => {
            let raw: RawUsers = v
                .try_into()
                .map_err(|e| Error::Profile(format!("[users]: {e}")))?;
            groups.push(raw.group("users", None)?);
            true
        }
        None => false,
    };
    let Some(list) = doc.remove("persona") else {
        return Ok((groups, own));
    };
    let toml::Value::Array(list) = list else {
        return Err(Error::Profile(
            "`persona` is a list of tables: write [[persona]]".into(),
        ));
    };
    if list.is_empty() {
        return Ok((groups, own));
    }
    let top_level = ["pcap", "message", "app", "queries"]
        .iter()
        .any(|k| doc.contains_key(*k));
    if top_level {
        return Err(Error::Profile(
            "with [[persona]], write the profile's own sessions as [[template]] tables".into(),
        ));
    }
    let mut added = Vec::new();
    for (n, v) in list.into_iter().enumerate() {
        let u: RawUse = v
            .try_into()
            .map_err(|e| Error::Profile(format!("persona {}: {e}", n + 1)))?;
        let path = allow(&base_dir.join(&u.file)).map_err(Error::Profile)?;
        let p = Persona::load(&path)?;
        let name = u.name.clone().unwrap_or_else(|| p.name.clone());
        let over = RawUsers {
            count: None,
            think: u.think.clone(),
            lifetime: u.lifetime.clone(),
            arrival: u.arrival,
        };
        let group = groups.len();
        groups.push(p.user.clone().over(&over).group(&name, Some(u.users))?);
        let tables = match kind {
            PersonaKind::Tcp => &p.tcp,
            PersonaKind::Udp => &p.udp,
        };
        if tables.is_empty() {
            return Err(Error::Profile(format!(
                "persona {name} has no [[{}]] sessions",
                match kind {
                    PersonaKind::Tcp => "tcp",
                    PersonaKind::Udp => "udp",
                }
            )));
        }
        for (i, t) in tables.iter().enumerate() {
            let mut t = t.clone();
            if t.contains_key("_group") {
                return Err(Error::Profile(format!(
                    "persona {name}: unknown key _group"
                )));
            }
            let tname = match t.get("name") {
                Some(toml::Value::String(s)) => s.clone(),
                _ => format!("t{}", i + 1),
            };
            t.insert("name".into(), format!("{name}/{tname}").into());
            t.insert("_group".into(), toml::Value::Integer(group as i64));
            absolute(&mut t, "pcap", &p.dir);
            if let Some(off) = u.port_offset {
                let port = match t.get("port") {
                    Some(toml::Value::Integer(p)) => *p,
                    _ => {
                        return Err(Error::Profile(format!(
                            "persona {name}: port_offset needs a `port` in each template \
                             ({tname} has none)"
                        )))
                    }
                };
                let moved = port + i64::from(off);
                if !(1..=65535).contains(&moved) {
                    return Err(Error::Profile(format!(
                        "persona {name}: template {tname}: port {moved} is out of range"
                    )));
                }
                t.insert("port".into(), toml::Value::Integer(moved));
            }
            added.push(toml::Value::Table(t));
        }
    }
    match doc
        .entry("template")
        .or_insert_with(|| toml::Value::Array(Vec::new()))
    {
        toml::Value::Array(a) => a.extend(added),
        _ => {
            return Err(Error::Profile(
                "`template` is a list of tables: write [[template]]".into(),
            ))
        }
    }
    Ok((groups, own))
}

/// Makes a relative file name under `key` absolute, from `dir`.
fn absolute(t: &mut toml::Table, key: &str, dir: &Path) {
    if let Some(toml::Value::String(f)) = t.get(key) {
        let p = Path::new(f);
        if p.is_relative() {
            let full = dir.join(p).to_string_lossy().into_owned();
            t.insert(key.into(), full.into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFICE: &str = r#"
format = 1
name = "office"
description = "web and mail"
[user]
think = "exp(5s)"
lifetime = "30m"
[[tcp]]
name = "web"
app = "http"
port = 80
weight = 3
session_requests = "lognormal(median=4, sigma=0.5)"
[[tcp]]
name = "raw"
pcap = "web.pcap"
port = 8080
"#;

    #[test]
    fn a_persona_adds_its_templates_in_its_own_group() {
        let dir = std::env::temp_dir().join(format!("ftrx-persona-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("p")).unwrap();
        std::fs::write(dir.join("p/office.toml"), OFFICE).unwrap();
        let mut doc: toml::Table = toml::from_str(
            r#"
[users]
count = 5
[[template]]
name = "mine"
pcap = "x.pcap"
[[persona]]
file = "p/office.toml"
users = 20
think = "1s"
port_offset = 1000
"#,
        )
        .unwrap();
        let (groups, own) = expand(&mut doc, &dir, PersonaKind::Tcp, &any_file).unwrap();
        assert!(own);
        assert_eq!(groups.len(), 2);
        assert_eq!((groups[1].name.as_str(), groups[1].users), ("office", 20));
        assert_eq!(groups[1].think.to_string(), "1s");
        assert!(groups[1].lifetime.is_some());
        let t = doc["template"].as_array().unwrap();
        assert_eq!(t.len(), 3);
        assert_eq!(t[1]["name"].as_str(), Some("office/web"));
        assert_eq!(t[1]["port"].as_integer(), Some(1080));
        assert_eq!(t[1]["_group"].as_integer(), Some(1));
        assert!(t[2]["pcap"].as_str().unwrap().ends_with("p/web.pcap"));
        assert!(!doc.contains_key("persona"));
        // No UDP sessions in this persona.
        let mut doc: toml::Table =
            toml::from_str("[[persona]]\nfile = \"p/office.toml\"\nusers = 1\n").unwrap();
        let e = expand(&mut doc, &dir, PersonaKind::Udp, &any_file)
            .unwrap_err()
            .to_string();
        assert!(e.contains("no [[udp]]"), "{e}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn persona_files_are_checked() {
        let d = Path::new(".");
        assert!(Persona::from_toml("format = 1\nname = \"x\"\n", d).is_err());
        let e = Persona::from_toml(
            "format = 1\n[user]\ncount = 3\n[[tcp]]\napp = \"http\"\n",
            d,
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("count"), "{e}");
        let p = Persona::from_toml(OFFICE, d).unwrap();
        assert_eq!(p.group(7).unwrap().users, 7);
        assert!(p.describe().contains("office"));
    }
}
