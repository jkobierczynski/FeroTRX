//! Application protocols by name, for profiles.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use super::App;
use crate::{Error, Result};

/// Reads a protocol's table from a profile (`[http]`, `[template.http]`):
/// the table (empty if the profile has none) and the folder the profile is
/// in, for files it names.
pub type AppParser = Arc<dyn Fn(&toml::Table, &Path) -> Result<App> + Send + Sync>;

/// Application protocols by the name profiles give them with `app = "..."`.
///
/// [`AppRegistry::builtin`] has `http`, `http2`, `dns`, `mqtt`, `ntp` and
/// (feature `ssh`) `ssh`; add your own with
/// [`register`](Self::register) and read profiles with
/// [`TcpProfile::from_toml_with`](crate::TcpProfile::from_toml_with).
///
/// ```
/// use ferotrx_core::app::AppRegistry;
///
/// let reg = AppRegistry::builtin();
/// let table: toml::Table = r#"requests = ["GET /"]"#.parse().unwrap();
/// let app = reg.parse("http", &table, std::path::Path::new(".")).unwrap();
/// assert_eq!(app.name(), "http");
/// assert!(reg.parse("gopher", &table, std::path::Path::new(".")).is_err());
/// ```
#[derive(Clone, Default)]
pub struct AppRegistry {
    parsers: BTreeMap<String, AppParser>,
}

impl AppRegistry {
    /// No protocols.
    pub fn new() -> Self {
        Self::default()
    }

    /// The built-in protocols: `http`, `http2`, `dns`, `mqtt`, `ntp`, `ssh`.
    pub fn builtin() -> Self {
        let mut r = Self::new();
        r.register("http", |t, base| super::http::parse(t, base).map(App::new));
        r.register("http2", |t, base| {
            super::http2::parse(t, base).map(App::new)
        });
        r.register("dns", |t, base| super::dns::parse(t, base).map(App::new));
        r.register("ntp", |t, _| super::ntp::parse(t).map(App::new));
        r.register("mqtt", |t, _| super::mqtt::parse(t).map(App::new));
        #[cfg(feature = "ssh")]
        r.register("ssh", |t, base| super::ssh::parse(t, base).map(App::new));
        r
    }

    /// Adds or replaces the protocol called `name`.
    pub fn register(
        &mut self,
        name: impl Into<String>,
        parse: impl Fn(&toml::Table, &Path) -> Result<App> + Send + Sync + 'static,
    ) {
        self.parsers.insert(name.into(), Arc::new(parse));
    }

    pub fn contains(&self, name: &str) -> bool {
        self.parsers.contains_key(name)
    }

    /// The protocols' names, sorted.
    pub fn names(&self) -> Vec<&str> {
        self.parsers.keys().map(String::as_str).collect()
    }

    /// The protocol `name` configured by `table`.
    pub fn parse(&self, name: &str, table: &toml::Table, base_dir: &Path) -> Result<App> {
        let p = self.parsers.get(name).ok_or_else(|| {
            Error::Profile(format!(
                "unknown app `{name}`; known: {}",
                self.names().join(", ")
            ))
        })?;
        p(table, base_dir).map_err(|e| match e {
            Error::Profile(m) => Error::Profile(format!("[{name}]: {m}")),
            e => Error::Profile(format!("[{name}]: {e}")),
        })
    }
}

impl std::fmt::Debug for AppRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.parsers.keys()).finish()
    }
}

/// Deserializes a protocol's table into `T` (a serde struct of its own).
pub(crate) fn table_into<T: serde::de::DeserializeOwned>(t: &toml::Table) -> Result<T> {
    toml::Value::Table(t.clone())
        .try_into()
        .map_err(|e: toml::de::Error| Error::Profile(e.message().to_string()))
}

/// The protocols a profile's top level and `[[template]]` tables play.
pub(crate) struct ProfileApps {
    pub top: Option<App>,
    /// One per `[[template]]` table, in order.
    pub templates: Vec<Option<App>>,
}

/// Takes the application protocols out of a profile document: where a
/// table (the top level or a `[[template]]`) has `app = "NAME"`, its `NAME`
/// table configures the protocol from `registry`, and `tls = true` or a
/// `[tls]` table runs it over TLS (`app = "https"` is HTTP over TLS). The
/// keys are removed, so
/// the rest of the profile reads as before. `own(name, has_table)` says
/// which names the profile reads itself (UDP's `replay`, and its `dns` and
/// `ntp` without a table); those stay.
pub(crate) fn take_apps(
    doc: &mut toml::Table,
    registry: &AppRegistry,
    base_dir: &Path,
    own: impl Fn(&str, bool) -> bool,
) -> Result<ProfileApps> {
    let take = |t: &mut toml::Table, what: &str| -> Result<Option<App>> {
        let name = match t.get("app") {
            None if t.contains_key("tls") => {
                return Err(Error::Profile(format!(
                    "{what}`tls` needs an application protocol on top, e.g. app = \"https\""
                )))
            }
            None => return Ok(None),
            Some(toml::Value::String(s)) => s.to_ascii_lowercase(),
            Some(_) => return Err(Error::Profile(format!("{what}`app` must be a name"))),
        };
        // `https` is HTTP over TLS: the [http] table and TLS on; `h2` is
        // HTTP/2 over TLS and `h2c` HTTP/2 without, both with [http2].
        let (name, force_tls) = match name.as_str() {
            "https" if !registry.contains("https") => ("http".to_string(), true),
            "h2" if !registry.contains("h2") => ("http2".to_string(), true),
            "h2c" if !registry.contains("h2c") => ("http2".to_string(), false),
            _ => (name, false),
        };
        let table = match t.get(&name) {
            None => None,
            Some(toml::Value::Table(x)) => Some(x.clone()),
            Some(_) => {
                return Err(Error::Profile(format!(
                    "{what}`{name}` must be a table of the protocol's settings"
                )))
            }
        };
        if own(&name, table.is_some()) {
            return Ok(None);
        }
        t.remove("app");
        t.remove(&name);
        let tls = match t.remove("tls") {
            None if force_tls => Some(toml::Table::new()),
            None | Some(toml::Value::Boolean(false)) => None,
            Some(toml::Value::Boolean(true)) => Some(toml::Table::new()),
            Some(toml::Value::Table(x)) => Some(x),
            Some(_) => {
                return Err(Error::Profile(format!(
                    "{what}`tls` must be true or a table of TLS settings"
                )))
            }
        };
        let fail = |e: Error| {
            Error::Profile(format!(
                "{what}{}",
                e.to_string().trim_start_matches("profile: ")
            ))
        };
        let mut table = table.unwrap_or_default();
        if name == "http2" && tls.is_some() && !table.contains_key("scheme") {
            table.insert("scheme".into(), "https".into());
        }
        let app = registry.parse(&name, &table, base_dir).map_err(fail)?;
        match tls {
            None => Ok(Some(app)),
            Some(table) => with_tls(app, &table, base_dir)
                .map(Some)
                .map_err(|e| match e {
                    Error::Profile(m) => fail(Error::Profile(format!("[tls]: {m}"))),
                    e => fail(e),
                }),
        }
    };
    let top = take(doc, "")?;
    let mut templates = Vec::new();
    if let Some(toml::Value::Array(list)) = doc.get_mut("template") {
        for (i, v) in list.iter_mut().enumerate() {
            let label = match v.get("name").and_then(|n| n.as_str()) {
                Some(n) => n.to_string(),
                None => (i + 1).to_string(),
            };
            match v {
                toml::Value::Table(t) => templates.push(take(t, &format!("template {label}: "))?),
                _ => templates.push(None),
            }
        }
    }
    Ok(ProfileApps { top, templates })
}

impl ProfileApps {
    fn any(&self) -> bool {
        self.top.is_some() || self.templates.iter().any(Option::is_some)
    }

    /// Reads a profile's raw form: from `doc` (without the protocols'
    /// tables) if protocols were taken out, else from `text`, whose errors
    /// say where they are.
    pub fn raw<T: serde::de::DeserializeOwned>(&self, text: &str, doc: toml::Table) -> Result<T> {
        let r = if self.any() {
            toml::Value::Table(doc).try_into()
        } else {
            toml::from_str(text)
        };
        r.map_err(|e: toml::de::Error| Error::Profile(e.to_string()))
    }
}

#[cfg(feature = "tls")]
fn with_tls(app: App, table: &toml::Table, base_dir: &Path) -> Result<App> {
    super::tls::parse(app, table, base_dir).map(App::new)
}

#[cfg(not(feature = "tls"))]
fn with_tls(_: App, _: &toml::Table, _: &Path) -> Result<App> {
    Err(Error::Profile(
        "this FeroTRX was built without TLS (feature `tls`)".into(),
    ))
}

/// Parses a profile's text into a document for [`take_apps`].
pub(crate) fn document(text: &str) -> Result<toml::Table> {
    text.parse::<toml::Table>()
        .map_err(|e| Error::Profile(e.to_string()))
}
