//! Editors for application protocol profiles: the `[http]`, `[dns]`,
//! `[mqtt]`, ... tables of TCP and UDP profiles (`docs/app-protocols.md`).
//!
//! Each protocol has an [`AppEditor`] in the [`Registry`](super::Registry):
//! its name in `app = "..."`, the table it reads, the transports and port,
//! and its settings as [`Setting`] tables (with kinds, so the form checks
//! values and shows defaults as hints), the arrays of tables it takes
//! (`[[http.route]]`), and nested tables (`[tls.client]`). The generic form
//! ([`app_form`]) draws all of them; keys the editor does not know stay in
//! the table and can be edited as TOML, so the GUI never drops settings of a
//! newer engine. A protocol with no editor opens in that TOML form alone.
//!
//! New protocols register with [`Registry::register_app`](super::Registry::register_app).

use eframe::egui::{self, RichText};

/// The transports a protocol runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

/// Which end a setting is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Client,
    Server,
    Both,
}

impl End {
    fn label(self) -> &'static str {
        match self {
            End::Client => "Client",
            End::Server => "Server",
            End::Both => "Both ends",
        }
    }
}

/// What a setting holds, for its widget and its TOML type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingKind {
    Text,
    /// Text shown as dots.
    Secret,
    /// A whole number up to this.
    Int(u64),
    /// A number, written as a float (`cps = 12.5`).
    Number,
    Bool,
    /// `500ms`, `5s`: written as a string.
    Duration,
    /// `16K`, `1M`: written as a string; a plain number is written as one.
    Size,
    /// A number written as a number, anything else as a string (`201`, `2xx`).
    Expect,
    /// One of these (or anything else typed).
    Choice(&'static [&'static str]),
    /// A list of strings, one per line.
    List,
    /// Several of these, in this order.
    Multi(&'static [&'static str]),
    /// A table of strings, `key = value` a line (`users`, `headers`, `files`).
    Map,
    /// A file, relative to the profile.
    Path,
}

/// One key of a protocol's table.
#[derive(Clone, Copy, Debug)]
pub struct Setting {
    pub key: &'static str,
    pub label: &'static str,
    pub kind: SettingKind,
    pub end: End,
    /// What the engine uses when the key is left out.
    pub default: &'static str,
    pub help: &'static str,
}

impl Setting {
    pub const fn new(key: &'static str, label: &'static str, kind: SettingKind, end: End) -> Self {
        Self {
            key,
            label,
            kind,
            end,
            default: "",
            help: "",
        }
    }

    pub const fn default(mut self, d: &'static str) -> Self {
        self.default = d;
        self
    }

    pub const fn help(mut self, h: &'static str) -> Self {
        self.help = h;
        self
    }
}

/// An array of tables in a protocol's table, such as `[[http.route]]`.
#[derive(Clone, Copy, Debug)]
pub struct TableList {
    pub key: &'static str,
    /// What one entry is called: "route".
    pub item: &'static str,
    pub end: End,
    pub help: &'static str,
    pub settings: &'static [Setting],
}

/// A table inside a protocol's table, such as `[tls.client]`.
#[derive(Clone, Copy, Debug)]
pub struct SubTable {
    pub key: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    pub settings: &'static [Setting],
}

/// Knows one application protocol of the profiles.
pub trait AppEditor: Send + Sync {
    /// The name in `app = "..."`.
    fn name(&self) -> &'static str;
    /// Other names in `app` that use this editor's table (`https`, `h2`),
    /// with whether they run over TLS.
    fn aliases(&self) -> &'static [(&'static str, bool)] {
        &[]
    }
    /// The name people know.
    fn title(&self) -> &'static str;
    /// The table it reads (`http2` for `h2`); the name by default.
    fn table(&self) -> &'static str {
        self.name()
    }
    fn transports(&self) -> &'static [Transport];
    /// The port it uses unless the profile says otherwise.
    fn port(&self) -> Option<u16>;
    fn settings(&self) -> &'static [Setting];
    fn lists(&self) -> &'static [TableList] {
        &[]
    }
    fn subtables(&self) -> &'static [SubTable] {
        &[]
    }
    /// A starting table for a new template, as TOML.
    fn example(&self) -> &'static str {
        ""
    }
    /// Draws the table's form. Returns true when the table changed.
    fn ui(&self, ui: &mut egui::Ui, table: &mut toml::Table) -> bool {
        app_form(ui, self.settings(), self.lists(), self.subtables(), table)
    }
}

/// What a key's value looks like in a text field.
pub fn value_text(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(n) => n.to_string(),
        toml::Value::Float(f) => f.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        other => other.to_string(),
    }
}

/// The value typed into a field of `kind`, or why it is wrong. `None`:
/// the field is empty (leave the key out).
pub fn parse_value(kind: SettingKind, text: &str) -> Result<Option<toml::Value>, String> {
    let t = text.trim();
    if t.is_empty() {
        return Ok(None);
    }
    let v = match kind {
        SettingKind::Int(max) => {
            let n: u64 = t
                .replace('_', "")
                .parse()
                .map_err(|_| format!("'{t}' is not a whole number"))?;
            if n > max {
                return Err(format!("at most {max}"));
            }
            toml::Value::Integer(n as i64)
        }
        SettingKind::Number => {
            let f: f64 = t.parse().map_err(|_| format!("'{t}' is not a number"))?;
            if !f.is_finite() || f < 0.0 {
                return Err("a number from 0 up".into());
            }
            toml::Value::Float(f)
        }
        SettingKind::Duration => {
            ferotrx_core::parse_duration(t).map_err(|e| e.to_string())?;
            toml::Value::String(t.into())
        }
        SettingKind::Size | SettingKind::Expect => match t.parse::<i64>() {
            Ok(n) => toml::Value::Integer(n),
            Err(_) => toml::Value::String(t.into()),
        },
        _ => toml::Value::String(t.into()),
    };
    Ok(Some(v))
}

/// A one-line field that keeps what is typed while it is wrong.
fn text_field(
    ui: &mut egui::Ui,
    id: egui::Id,
    s: &Setting,
    table: &mut toml::Table,
    width: f32,
) -> bool {
    let current = table.get(s.key).map(value_text).unwrap_or_default();
    let mut buf: String = ui
        .data_mut(|d| d.get_temp::<String>(id))
        .unwrap_or_else(|| current.clone());
    let bad = parse_value(s.kind, &buf).err();
    let mut te = egui::TextEdit::singleline(&mut buf)
        .id(id)
        .desired_width(width)
        .hint_text(s.default);
    if s.kind == SettingKind::Secret {
        te = te.password(true);
    }
    if bad.is_some() {
        te = te.text_color(ui.visuals().error_fg_color);
    }
    let r = ui.add(te);
    let mut changed = false;
    if r.changed() {
        match parse_value(s.kind, &buf) {
            Ok(Some(v)) => {
                changed = table.get(s.key) != Some(&v);
                table.insert(s.key.into(), v);
            }
            Ok(None) => changed = table.remove(s.key).is_some(),
            Err(_) => {}
        }
    }
    let bad = parse_value(s.kind, &buf).err();
    if r.has_focus() || bad.is_some() {
        ui.data_mut(|d| d.insert_temp(id, buf));
    } else {
        ui.data_mut(|d| d.remove::<String>(id));
    }
    if let Some(e) = bad {
        r.on_hover_text(e);
    } else if !s.help.is_empty() {
        r.on_hover_text(s.help);
    }
    changed
}

/// The widget of one setting. Returns true when the table changed.
pub fn setting_widget(ui: &mut egui::Ui, s: &Setting, table: &mut toml::Table) -> bool {
    let id = ui.id().with(("setting", s.key));
    match s.kind {
        SettingKind::Bool => {
            let cur = table.get(s.key).and_then(|v| v.as_bool());
            let mut changed = false;
            ui.horizontal(|ui| {
                let label = match cur {
                    None => format!(
                        "default ({})",
                        if s.default.is_empty() {
                            "off"
                        } else {
                            s.default
                        }
                    ),
                    Some(true) => "on".into(),
                    Some(false) => "off".into(),
                };
                egui::ComboBox::from_id_salt(id)
                    .selected_text(label)
                    .width(110.0)
                    .show_ui(ui, |ui| {
                        let mut v = cur;
                        ui.selectable_value(&mut v, None, "default");
                        ui.selectable_value(&mut v, Some(true), "on");
                        ui.selectable_value(&mut v, Some(false), "off");
                        if v != cur {
                            changed = true;
                            match v {
                                None => {
                                    table.remove(s.key);
                                }
                                Some(b) => {
                                    table.insert(s.key.into(), b.into());
                                }
                            }
                        }
                    })
                    .response
                    .on_hover_text(s.help);
            });
            changed
        }
        SettingKind::Choice(options) => {
            let mut changed = false;
            ui.horizontal(|ui| {
                changed |= text_field(ui, id, s, table, 150.0);
                ui.menu_button("⏷", |ui| {
                    if ui.button("default").clicked() {
                        changed |= table.remove(s.key).is_some();
                        ui.data_mut(|d| d.remove::<String>(id));
                        ui.close();
                    }
                    for o in options {
                        if ui.button(*o).clicked() {
                            table.insert(s.key.into(), toml::Value::String(o.to_string()));
                            ui.data_mut(|d| d.remove::<String>(id));
                            changed = true;
                            ui.close();
                        }
                    }
                });
            });
            changed
        }
        SettingKind::Multi(options) => {
            let cur: Vec<String> = table
                .get(s.key)
                .and_then(|v| v.as_array())
                .map(|a| a.iter().map(value_text).collect())
                .unwrap_or_default();
            let mut next = cur.clone();
            ui.horizontal_wrapped(|ui| {
                for o in options {
                    let mut on = cur.iter().any(|c| c.eq_ignore_ascii_case(o));
                    if ui.checkbox(&mut on, *o).changed() {
                        if on {
                            next.push(o.to_string());
                        } else {
                            next.retain(|c| !c.eq_ignore_ascii_case(o));
                        }
                    }
                }
                if cur.is_empty() {
                    ui.weak(format!(
                        "(none ticked: {})",
                        if s.default.is_empty() {
                            "all"
                        } else {
                            s.default
                        }
                    ));
                }
            })
            .response
            .on_hover_text(s.help);
            if next != cur {
                // Keep the order of the options, then anything else.
                let mut ordered: Vec<String> = options
                    .iter()
                    .filter(|o| next.iter().any(|n| n.eq_ignore_ascii_case(o)))
                    .map(|o| o.to_string())
                    .collect();
                ordered.extend(
                    next.into_iter()
                        .filter(|n| !options.iter().any(|o| o.eq_ignore_ascii_case(n))),
                );
                if ordered.is_empty() {
                    table.remove(s.key);
                } else {
                    table.insert(
                        s.key.into(),
                        toml::Value::Array(ordered.into_iter().map(toml::Value::String).collect()),
                    );
                }
                return true;
            }
            false
        }
        SettingKind::List => {
            let mut v: Vec<String> = match table.get(s.key) {
                Some(toml::Value::Array(a)) => a.iter().map(value_text).collect(),
                Some(other) => vec![value_text(other)],
                None => Vec::new(),
            };
            let hint = if s.default.is_empty() {
                s.help
            } else {
                s.default
            };
            let changed = crate::views::string_list(ui, &format!("{:?}", id), &mut v, hint);
            if changed {
                if v.is_empty() {
                    table.remove(s.key);
                } else {
                    table.insert(
                        s.key.into(),
                        toml::Value::Array(v.into_iter().map(toml::Value::String).collect()),
                    );
                }
            }
            changed
        }
        SettingKind::Map => {
            let cur = match table.get(s.key) {
                Some(toml::Value::Table(t)) => t
                    .iter()
                    .map(|(k, v)| format!("{k} = {}", value_text(v)))
                    .collect::<Vec<_>>()
                    .join("\n"),
                _ => String::new(),
            };
            let mut buf: String = ui
                .data_mut(|d| d.get_temp::<String>(id))
                .unwrap_or_else(|| cur.clone());
            let r = ui
                .add(
                    egui::TextEdit::multiline(&mut buf)
                        .id(id)
                        .desired_rows(2)
                        .desired_width(260.0)
                        .hint_text(if s.default.is_empty() {
                            "name = value, a line each"
                        } else {
                            s.default
                        }),
                )
                .on_hover_text(s.help);
            let mut changed = false;
            if r.changed() {
                let mut t = toml::Table::new();
                for line in buf.lines() {
                    if let Some((k, v)) = line.split_once('=') {
                        let k = k.trim().trim_matches('"');
                        let v = v.trim().trim_matches('"');
                        if !k.is_empty() {
                            t.insert(k.into(), toml::Value::String(v.into()));
                        }
                    }
                }
                if t.is_empty() {
                    changed = table.remove(s.key).is_some();
                } else {
                    changed = true;
                    table.insert(s.key.into(), toml::Value::Table(t));
                }
            }
            if r.has_focus() {
                ui.data_mut(|d| d.insert_temp(id, buf));
            } else {
                ui.data_mut(|d| d.remove::<String>(id));
            }
            changed
        }
        _ => text_field(ui, id, s, table, 220.0),
    }
}

/// The settings of `table` in a grid, grouped by end, then the arrays of
/// tables, the nested tables and the keys no setting names.
pub fn app_form(
    ui: &mut egui::Ui,
    settings: &[Setting],
    lists: &[TableList],
    subtables: &[SubTable],
    table: &mut toml::Table,
) -> bool {
    let mut changed = false;
    for end in [End::Client, End::Server, End::Both] {
        let these: Vec<&Setting> = settings.iter().filter(|s| s.end == end).collect();
        if these.is_empty() {
            continue;
        }
        if settings.iter().any(|s| s.end != end) {
            ui.label(RichText::new(end.label()).strong());
        }
        egui::Grid::new(ui.id().with(("app-grid", end as u8)))
            .num_columns(2)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
                for s in these {
                    let mut l = RichText::new(s.label);
                    if table.contains_key(s.key) {
                        l = l.strong();
                    }
                    ui.label(l)
                        .on_hover_text(format!("{} = …\n{}", s.key, s.help));
                    ui.push_id(s.key, |ui| changed |= setting_widget(ui, s, table));
                    ui.end_row();
                }
            });
        ui.add_space(4.0);
    }
    for l in lists {
        changed |= list_form(ui, l, table);
    }
    for t in subtables {
        let mut sub = match table.get(t.key) {
            Some(toml::Value::Table(x)) => x.clone(),
            _ => toml::Table::new(),
        };
        let r = egui::CollapsingHeader::new(format!("{} ({} keys)", t.label, sub.len()))
            .id_salt(("sub", t.key))
            .show(ui, |ui| {
                ui.weak(t.help);
                app_form(ui, t.settings, &[], &[], &mut sub)
            });
        if r.body_returned == Some(true) {
            changed = true;
            if sub.is_empty() {
                table.remove(t.key);
            } else {
                table.insert(t.key.into(), toml::Value::Table(sub));
            }
        }
    }
    let known: Vec<&str> = settings
        .iter()
        .map(|s| s.key)
        .chain(lists.iter().map(|l| l.key))
        .chain(subtables.iter().map(|t| t.key))
        .collect();
    changed |= other_keys(ui, &known, table);
    changed
}

/// Entries of an array of tables, each in its own section.
fn list_form(ui: &mut egui::Ui, l: &TableList, table: &mut toml::Table) -> bool {
    let mut items: Vec<toml::Table> = match table.get(l.key) {
        Some(toml::Value::Array(a)) => a.iter().filter_map(|v| v.as_table().cloned()).collect(),
        _ => Vec::new(),
    };
    let mut changed = false;
    let mut op: Option<(usize, bool)> = None; // (index, remove? else duplicate)
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("{} ({}s)", l.end.label(), l.item)).strong())
            .on_hover_text(l.help);
        ui.weak(format!(
            "{} {}",
            items.len(),
            if items.len() == 1 {
                l.item.to_string()
            } else {
                format!("{}s", l.item)
            }
        ));
        if ui.small_button(format!("+ {}", l.item)).clicked() {
            items.push(toml::Table::new());
            changed = true;
        }
    });
    for (n, item) in items.iter_mut().enumerate() {
        let title = l
            .settings
            .iter()
            .take(2)
            .filter_map(|s| item.get(s.key).map(value_text))
            .collect::<Vec<_>>()
            .join(" ");
        let id = ui.id().with(("item", l.key, n));
        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, false)
            .show_header(ui, |ui| {
                ui.label(format!(
                    "{} {}: {}",
                    l.item,
                    n + 1,
                    if title.is_empty() {
                        "(new)".into()
                    } else {
                        title
                    }
                ));
                if ui.small_button("copy").on_hover_text("Duplicate").clicked() {
                    op = Some((n, false));
                }
                if ui.small_button("✕").on_hover_text("Remove").clicked() {
                    op = Some((n, true));
                }
            })
            .body(|ui| {
                ui.push_id(("item-form", l.key, n), |ui| {
                    changed |= app_form(ui, l.settings, &[], &[], item);
                });
            });
    }
    match op {
        Some((n, true)) => {
            items.remove(n);
            changed = true;
        }
        Some((n, false)) => {
            let copy = items[n].clone();
            items.insert(n + 1, copy);
            changed = true;
        }
        None => {}
    }
    if changed {
        if items.is_empty() {
            table.remove(l.key);
        } else {
            table.insert(
                l.key.into(),
                toml::Value::Array(items.into_iter().map(toml::Value::Table).collect()),
            );
        }
    }
    ui.add_space(4.0);
    changed
}

/// Keys no setting names, as TOML text: kept, and editable.
pub fn other_keys(ui: &mut egui::Ui, known: &[&str], table: &mut toml::Table) -> bool {
    let others: toml::Table = table
        .iter()
        .filter(|(k, _)| !known.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let id = ui.id().with("other-keys");
    let text = if others.is_empty() {
        String::new()
    } else {
        toml::to_string(&others).unwrap_or_default()
    };
    let mut buf: String = ui
        .data_mut(|d| d.get_temp::<String>(id))
        .unwrap_or_else(|| text.clone());
    let mut changed = false;
    let header = if others.is_empty() && known.is_empty() {
        "Settings (TOML)".to_string()
    } else if others.is_empty() {
        "Other keys".to_string()
    } else {
        format!("Other keys ({})", others.len())
    };
    egui::CollapsingHeader::new(header)
        .id_salt(id)
        .default_open(known.is_empty())
        .show(ui, |ui| {
            ui.weak("Keys this form has no field for, as TOML; they are kept as they are.");
            let r = ui.add(
                egui::TextEdit::multiline(&mut buf)
                    .code_editor()
                    .desired_rows(3)
                    .desired_width(f32::INFINITY)
                    .hint_text("key = \"value\""),
            );
            match toml::from_str::<toml::Table>(&buf) {
                Ok(t) => {
                    if r.changed() {
                        table.retain(|k, _| known.contains(&k));
                        for (k, v) in t {
                            if !known.contains(&k.as_str()) {
                                table.insert(k, v);
                            }
                        }
                        changed = true;
                    }
                }
                Err(e) => {
                    ui.colored_label(ui.visuals().error_fg_color, e.message());
                }
            }
            if r.has_focus() {
                ui.data_mut(|d| d.insert_temp(id, buf.clone()));
            } else {
                ui.data_mut(|d| d.remove::<String>(id));
            }
        });
    changed
}

// ----- the built-in protocols -----

use End::{Both, Client, Server};
use SettingKind as K;

const fn s(key: &'static str, label: &'static str, kind: SettingKind, end: End) -> Setting {
    Setting::new(key, label, kind, end)
}

const HTTP_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"];
const EXPECT_HTTP: &[&str] = &["200", "201", "204", "2xx", "3xx", "404", "success", "any"];

const HTTP_REQUEST: &[Setting] = &[
    s("method", "Method", K::Choice(HTTP_METHODS), Client).default("GET"),
    s("path", "Path", K::Text, Client).default("/"),
    s("headers", "Headers", K::Map, Client),
    s("body", "Body", K::Text, Client),
    s("body_size", "Body size", K::Size, Client).help("Filler of this size: 16K"),
    s("body_file", "Body file", K::Path, Client).help("Relative to the profile"),
    s("content_type", "Content-Type", K::Text, Client),
    s("expect", "Expected status", K::Choice(EXPECT_HTTP), Client).default("below 400"),
];

const HTTP_ROUTE: &[Setting] = &[
    s("path", "Path", K::Text, Server)
        .help("Exact, or a prefix ending in *; * alone takes every path"),
    s("method", "Method", K::Choice(HTTP_METHODS), Server).default("any"),
    s("status", "Status", K::Int(999), Server).default("200"),
    s("reason", "Reason", K::Text, Server).default("the usual phrase"),
    s("body", "Body", K::Text, Server),
    s("body_size", "Body size", K::Size, Server),
    s("body_file", "Body file", K::Path, Server),
    s("content_type", "Content-Type", K::Text, Server),
    s("headers", "Headers", K::Map, Server),
    s("chunked", "Chunked", K::Bool, Server).help("Transfer-Encoding: chunked (HTTP/1.1)"),
    s("close", "Close after", K::Bool, Server).help("Connection: close (GOAWAY in HTTP/2)"),
    s("delay", "Delay", K::Duration, Server)
        .default("0")
        .help("Wait before answering: 20ms"),
];

const HTTP_LISTS: &[TableList] = &[
    TableList {
        key: "request",
        item: "request",
        end: Client,
        help: "Requests with headers or a body; they come after `requests`",
        settings: HTTP_REQUEST,
    },
    TableList {
        key: "route",
        item: "route",
        end: Server,
        help: "The server's answers: the first route that matches. Without routes every request gets 200.",
        settings: HTTP_ROUTE,
    },
];

const HTTP_SETTINGS: &[Setting] = &[
    s("requests", "Requests", K::List, Client)
        .default("GET /")
        .help("METHOD PATH [EXPECTED]: GET /, GET /missing 404"),
    s(
        "per_connection",
        "Per connection",
        K::Int(1_000_000),
        Client,
    )
    .default("1")
    .help("Requests per connection (keep-alive)"),
    s("pipeline", "Pipeline", K::Bool, Client).help("Send a connection's requests at once"),
    s("host", "Host header", K::Text, Client).default("the address connected to"),
    s("user_agent", "User-Agent", K::Text, Client).default("FeroTRX/<version>"),
    s("think_time", "Think time", K::Duration, Client).default("0"),
    s("server", "Server header", K::Text, Server).default("FeroTRX"),
];

const H3_SETTINGS: &[Setting] = &[
    s("requests", "Requests", K::List, Client)
        .default("GET /")
        .help("METHOD PATH [EXPECTED]"),
    s(
        "per_connection",
        "Per connection",
        K::Int(1_000_000),
        Client,
    )
    .default("1"),
    s(
        "concurrent",
        "Concurrent streams",
        K::Int(1_000_000),
        Client,
    )
    .default("10"),
    s("host", ":authority", K::Text, Client).default("the address connected to"),
    s("user_agent", "User-Agent", K::Text, Client).default("FeroTRX/<version>"),
    s("think_time", "Think time", K::Duration, Client).default("0"),
    s("server", "Server header", K::Text, Server).default("FeroTRX"),
    s("huffman", "Huffman", K::Bool, Both).default("on"),
    s("idle_timeout", "Idle timeout", K::Duration, Both).default("30s"),
    s("max_data", "Connection window", K::Size, Both).default("16M"),
    s("stream_window", "Stream window", K::Size, Both).default("1M"),
    s("max_streams", "Max streams", K::Int(1_000_000), Both).default("100"),
    s(
        "max_uni_streams",
        "Max unidirectional streams",
        K::Int(1_000_000),
        Both,
    )
    .default("3"),
    s(
        "initial_window",
        "Initial congestion window",
        K::Int(1_000_000),
        Both,
    )
    .default("10")
    .help("In 1200-byte datagrams"),
    s(
        "key_update_after",
        "Key update after",
        K::Int(u64::MAX),
        Both,
    )
    .default("0")
    .help("Packets in a key phase before a key update (0: never)"),
    s("retry", "Retry", K::Bool, Server).help("Answer each client's first Initial with a Retry"),
];

const HTTP2_SETTINGS: &[Setting] = &[
    s("requests", "Requests", K::List, Client)
        .default("GET /")
        .help("METHOD PATH [EXPECTED]"),
    s(
        "per_connection",
        "Per connection",
        K::Int(1_000_000),
        Client,
    )
    .default("1"),
    s(
        "concurrent",
        "Concurrent streams",
        K::Int(1_000_000),
        Client,
    )
    .default("100"),
    s("host", ":authority", K::Text, Client).default("the address connected to"),
    s("user_agent", "User-Agent", K::Text, Client).default("FeroTRX/<version>"),
    s("think_time", "Think time", K::Duration, Client).default("0"),
    s("scheme", ":scheme", K::Choice(&["http", "https"]), Client).default("http, https over TLS"),
    s(
        "max_concurrent_streams",
        "Max concurrent streams",
        K::Int(u32::MAX as u64),
        Server,
    )
    .default("100"),
    s("server", "Server header", K::Text, Server).default("FeroTRX"),
    s("window", "Initial window", K::Int(i32::MAX as u64), Both).default("65535"),
    s("frame_size", "Max frame size", K::Int(16_777_215), Both).default("16384"),
    s(
        "header_table_size",
        "HPACK table size",
        K::Int(u32::MAX as u64),
        Both,
    )
    .default("4096"),
    s("huffman", "Huffman", K::Bool, Both).default("on"),
];

const DNS_SETTINGS: &[Setting] = &[
    s("queries", "Queries", K::List, Client).help("NAME [TYPE] [RCODE]: www.lab.local AAAA"),
    s("recursion_desired", "Recursion desired", K::Bool, Client).default("on"),
    s(
        "per_connection",
        "Per TCP connection",
        K::Int(1_000_000),
        Client,
    )
    .default("1"),
    s("records", "Records", K::List, Server).help("NAME [TTL] TYPE DATA, or NAME RCODE"),
    s("pcap", "From a capture", K::Path, Both).help("The queries and records of real lookups"),
];

const MQTT_MESSAGE: &[Setting] = &[
    s("topic", "Topic", K::Text, Client),
    s("qos", "QoS", K::Int(2), Client).default("0"),
    s("retain", "Retain", K::Bool, Client),
    s("payload", "Payload", K::Text, Client),
    s("payload_size", "Payload size", K::Size, Client).default("32"),
];

const MQTT_SETTINGS: &[Setting] = &[
    s("version", "Version", K::Choice(&["3.1.1", "5"]), Both).default("3.1.1"),
    s("client_id", "Client id", K::Text, Client).default("ferotrx-{n}"),
    s("username", "User name", K::Text, Client),
    s("password", "Password", K::Secret, Client),
    s("keep_alive", "Keep alive", K::Duration, Client).default("60s"),
    s("clean", "Clean session", K::Bool, Client).default("on"),
    s("subscribe", "Subscribe", K::List, Client).help("FILTER [QOS]: lab/sensors/# 2"),
    s("publish", "Publish", K::List, Client)
        .default("ferotrx/test")
        .help("TOPIC [QOS] [SIZE]"),
    s(
        "per_connection",
        "Per connection",
        K::Int(1_000_000),
        Client,
    )
    .default("the number of messages"),
    s("interval", "Interval", K::Duration, Client).default("0"),
    s("wait", "Wait", K::Duration, Client).default("5s"),
    s(
        "expect",
        "Expected CONNACK",
        K::Choice(&[
            "accepted",
            "bad credentials",
            "not authorized",
            "id rejected",
            "bad version",
        ]),
        Client,
    )
    .default("accepted"),
    s("users", "Logins", K::Map, Server).help("With none, anyone may connect"),
    s("max_qos", "Max QoS", K::Int(2), Server).default("2"),
    s("retain", "Keep retained", K::Bool, Server).default("on"),
];

const MQTT_LISTS: &[TableList] = &[TableList {
    key: "message",
    item: "message",
    end: Client,
    help: "Messages with more settings than `publish` takes",
    settings: MQTT_MESSAGE,
}];

const SSH_CIPHERS: &[&str] = &[
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
];

const SSH_COMMAND: &[Setting] = &[
    s("run", "Command", K::Text, Client),
    s("input", "Stdin", K::Text, Client),
    s("input_size", "Stdin size", K::Size, Client),
    s("exit", "Exit status", K::Int(255), Client).default("0"),
    s("output_size", "Stdout size", K::Size, Client),
];

const SSH_ROUTE: &[Setting] = &[
    s("command", "Command", K::Text, Server),
    s("output", "Output", K::Text, Server),
    s("output_size", "Output size", K::Size, Server),
    s("stderr", "Stderr", K::Text, Server),
    s("exit", "Exit status", K::Int(255), Server).default("0"),
    s("delay", "Delay", K::Duration, Server).default("0"),
];

const SSH_SETTINGS: &[Setting] = &[
    s("user", "User", K::Text, Client).default("lab"),
    s("password", "Password", K::Secret, Client).default("lab"),
    s("key", "Key", K::Path, Client).help("An Ed25519 key file, or generate"),
    s("commands", "Commands", K::List, Client).default("echo hello"),
    s(
        "per_connection",
        "Per connection",
        K::Int(1_000_000),
        Client,
    )
    .default("the number of commands"),
    s("fingerprint", "Host key fingerprint", K::Text, Client).help("SHA256:…"),
    s(
        "expect",
        "Expect",
        K::Choice(&["success", "failure"]),
        Client,
    )
    .default("success"),
    s("rekey_after", "Rekey after", K::Size, Client).default("never"),
    s("window", "Channel window", K::Size, Client).default("2M"),
    s("users", "Logins", K::Map, Server).help("With none, any password"),
    s("authorized_keys", "Authorized keys", K::Text, Server)
        .help("Public key lines, or a file of them"),
    s("host_key", "Host key", K::Path, Server).default("generate"),
    s("banner", "Banner", K::Text, Server),
    s("max_auth_tries", "Max auth tries", K::Int(1000), Server).default("6"),
    s("hostname", "Hostname", K::Text, Server).default("ferotrx"),
    s("ciphers", "Ciphers", K::Multi(SSH_CIPHERS), Both).default("all three"),
    s("version", "Software version", K::Text, Both).default("FeroTRX_<version>"),
];

const SSH_LISTS: &[TableList] = &[
    TableList {
        key: "command",
        item: "command",
        end: Client,
        help: "Commands with stdin, an exit status or an output size",
        settings: SSH_COMMAND,
    },
    TableList {
        key: "route",
        item: "route",
        end: Server,
        help: "What the server answers each command with",
        settings: SSH_ROUTE,
    },
];

const SIP_SETTINGS: &[Setting] = &[
    s("user", "User", K::Text, Client).default("ferotrx"),
    s("password", "Password", K::Secret, Client),
    s("register", "Register", K::Bool, Client).default("on"),
    s("expires", "Expires (s)", K::Int(u32::MAX as u64), Client).default("3600"),
    s("call", "Call", K::Text, Client)
        .default("echo")
        .help("A user, a sip: URI, or empty to only register"),
    s("duration", "Call length", K::Duration, Client).default("5s"),
    s(
        "expect",
        "Expect",
        K::Choice(&["success", "failure", "486", "403"]),
        Client,
    )
    .default("success"),
    s("users", "Logins", K::Map, Server).help("With none, no authentication"),
    s(
        "algorithm",
        "Digest",
        K::Choice(&["MD5", "SHA-256"]),
        Server,
    )
    .default("MD5"),
    s("answer", "Answer", K::Int(699), Server).default("200"),
    s("ring", "Ring", K::Duration, Server).default("0s"),
    s("max_call", "Max call", K::Duration, Server).default("1h"),
    s("domain", "Domain", K::Text, Both).default("the server's address"),
    s(
        "codecs",
        "Codecs",
        K::Multi(&["PCMU", "PCMA", "G722", "G729", "opus"]),
        Both,
    )
    .default("PCMU, PCMA"),
    s("ptime", "Packet time", K::Duration, Both).default("20ms"),
    s("media", "RTP media", K::Bool, Both).default("on"),
    s("t1", "T1", K::Duration, Both).default("500ms"),
];

const SMB_SETTINGS: &[Setting] = &[
    s("user", "User", K::Text, Client).default("guest"),
    s("password", "Password", K::Secret, Client),
    s("domain", "Domain", K::Text, Client).default("WORKGROUP"),
    s("workstation", "Workstation", K::Text, Client).default("FEROTRX"),
    s("share", "Share", K::Text, Client).default("lab"),
    s("ops", "Operations", K::List, Client)
        .default("write, read, list, delete ferotrx-{n}.bin")
        .help("write PATH SIZE, read PATH, list [DIR], delete PATH, mkdir DIR, rmdir DIR"),
    s("chunk", "Chunk", K::Size, Client).default("64K"),
    s("window", "In flight", K::Int(1024), Client).default("4"),
    s("wait", "Wait", K::Duration, Client).default("30s"),
    s(
        "expect",
        "Expect",
        K::Choice(&["LOGON_FAILURE", "BAD_NETWORK_NAME"]),
        Client,
    ),
    s("users", "Logins", K::Map, Server).help("With none, anyone logs in as a guest"),
    s("guest", "Guests too", K::Bool, Server),
    s("shares", "Shares", K::List, Server).default("lab"),
    s("read_only", "Read-only shares", K::List, Server),
    s("files", "Files", K::Map, Server).default("readme.txt = 4K"),
    s("name", "Server name", K::Text, Server).default("FEROTRX"),
    s("workgroup", "Workgroup", K::Text, Server).default("WORKGROUP"),
    s("dns_domain", "DNS domain", K::Text, Server),
    s("max_io", "Max I/O", K::Size, Server).default("1M"),
    s(
        "dialects",
        "Dialects",
        K::Multi(&["3.1.1", "3.0.2", "3.0", "2.1", "2.0.2"]),
        Both,
    )
    .default("all five"),
    s(
        "signing",
        "Signing",
        K::Choice(&["auto", "required", "off"]),
        Both,
    )
    .default("auto"),
];

const TLS_SETTINGS: &[Setting] = &[
    s("server_name", "Server name (SNI)", K::Text, Client),
    s("verify", "Verify the certificate", K::Bool, Client),
    s("ca", "CA file", K::Path, Client),
    s("client_cert", "Client certificate", K::Path, Client),
    s("client_key", "Client key", K::Path, Client),
    s("cert", "Certificate", K::Path, Server).default("generated"),
    s("key", "Key", K::Path, Server).default("generated"),
    s("names", "Certificate names", K::List, Server).default("ferotrx.lab"),
    s("client_ca", "Client CA", K::Path, Server).default("the generated CA"),
    s("versions", "Versions", K::Multi(&["1.2", "1.3"]), Both).default("1.2, 1.3"),
    s("cipher_suites", "Cipher suites", K::List, Both).default("all"),
    s(
        "groups",
        "Groups",
        K::Multi(&["X25519", "secp256r1", "secp384r1"]),
        Both,
    )
    .default("all"),
    s("alpn", "ALPN", K::List, Both),
    s(
        "key_type",
        "Generated key",
        K::Choice(&["ecdsa-p256", "ecdsa-p384", "ed25519"]),
        Both,
    )
    .default("ecdsa-p256"),
    s(
        "client_auth",
        "Client auth",
        K::Choice(&["none", "optional", "required"]),
        Both,
    )
    .default("none"),
    s("resumption", "Resumption", K::Bool, Both).default("on"),
    s("expect", "Expect", K::Choice(&["success", "failure"]), Both).default("success"),
];

const TLS_SUBTABLES: &[SubTable] = &[
    SubTable {
        key: "client",
        label: "Client only ([tls.client])",
        help: "Settings for the client end only, e.g. versions it offers",
        settings: TLS_SETTINGS,
    },
    SubTable {
        key: "server",
        label: "Server only ([tls.server])",
        help: "Settings for the server end only",
        settings: TLS_SETTINGS,
    },
];

/// An editor from tables.
pub struct TableEditor {
    pub name: &'static str,
    pub aliases: &'static [(&'static str, bool)],
    pub title: &'static str,
    pub table: &'static str,
    pub transports: &'static [Transport],
    pub port: Option<u16>,
    pub settings: &'static [Setting],
    pub lists: &'static [TableList],
    pub subtables: &'static [SubTable],
    pub example: &'static str,
}

impl AppEditor for TableEditor {
    fn name(&self) -> &'static str {
        self.name
    }
    fn aliases(&self) -> &'static [(&'static str, bool)] {
        self.aliases
    }
    fn title(&self) -> &'static str {
        self.title
    }
    fn table(&self) -> &'static str {
        self.table
    }
    fn transports(&self) -> &'static [Transport] {
        self.transports
    }
    fn port(&self) -> Option<u16> {
        self.port
    }
    fn settings(&self) -> &'static [Setting] {
        self.settings
    }
    fn lists(&self) -> &'static [TableList] {
        self.lists
    }
    fn subtables(&self) -> &'static [SubTable] {
        self.subtables
    }
    fn example(&self) -> &'static str {
        self.example
    }
}

const TCP: &[Transport] = &[Transport::Tcp];
const UDP: &[Transport] = &[Transport::Udp];
const BOTH: &[Transport] = &[Transport::Tcp, Transport::Udp];

/// The name of the TLS table's editor in the registry.
pub const TLS: &str = "tls";

/// Editors for the protocols the engine has, and TLS.
pub fn builtin_app_editors() -> Vec<Box<dyn AppEditor>> {
    let t = |e: TableEditor| Box::new(e) as Box<dyn AppEditor>;
    vec![
        t(TableEditor {
            name: "http",
            aliases: &[("https", true)],
            title: "HTTP/1.1",
            table: "http",
            transports: TCP,
            port: Some(80),
            settings: HTTP_SETTINGS,
            lists: HTTP_LISTS,
            subtables: &[],
            example: "requests = [\"GET /\", \"GET /missing 404\"]\nper_connection = 2\n",
        }),
        t(TableEditor {
            name: "http2",
            aliases: &[("h2", true), ("h2c", false)],
            title: "HTTP/2",
            table: "http2",
            transports: TCP,
            port: Some(80),
            settings: HTTP2_SETTINGS,
            lists: HTTP_LISTS,
            subtables: &[],
            example: "requests = [\"GET /\", \"GET /style.css\"]\nper_connection = 4\nconcurrent = 4\n",
        }),
        t(TableEditor {
            name: "h3",
            aliases: &[("http3", false)],
            title: "HTTP/3 (QUIC)",
            table: "h3",
            transports: UDP,
            port: Some(443),
            settings: H3_SETTINGS,
            lists: HTTP_LISTS,
            subtables: &[],
            example: "requests = [\"GET /\", \"GET /missing 404\"]\nper_connection = 2\n",
        }),
        t(TableEditor {
            name: "dns",
            aliases: &[],
            title: "DNS",
            table: "dns",
            transports: BOTH,
            port: Some(53),
            settings: DNS_SETTINGS,
            lists: &[],
            subtables: &[],
            example: "queries = [\"www.lab.local A\", \"missing.lab.local A NXDOMAIN\"]\nrecords = [\"www.lab.local A 192.168.20.80\"]\n",
        }),
        t(TableEditor {
            name: "ntp",
            aliases: &[],
            title: "NTP",
            table: "ntp",
            transports: UDP,
            port: Some(123),
            settings: &[],
            lists: &[],
            subtables: &[],
            example: "",
        }),
        t(TableEditor {
            name: "mqtt",
            aliases: &[],
            title: "MQTT",
            table: "mqtt",
            transports: TCP,
            port: Some(1883),
            settings: MQTT_SETTINGS,
            lists: MQTT_LISTS,
            subtables: &[],
            example: "subscribe = [\"lab/# 1\"]\npublish = [\"lab/a 0 16\", \"lab/b 1 16\"]\nper_connection = 2\n",
        }),
        t(TableEditor {
            name: "ssh",
            aliases: &[],
            title: "SSH",
            table: "ssh",
            transports: TCP,
            port: Some(22),
            settings: SSH_SETTINGS,
            lists: SSH_LISTS,
            subtables: &[],
            example: "user = \"admin\"\npassword = \"lab\"\ncommands = [\"uptime\"]\nusers = { admin = \"lab\" }\n",
        }),
        t(TableEditor {
            name: "sip",
            aliases: &[],
            title: "SIP and RTP",
            table: "sip",
            transports: UDP,
            port: Some(5060),
            settings: SIP_SETTINGS,
            lists: &[],
            subtables: &[],
            example: "user = \"alice\"\npassword = \"lab\"\ncall = \"echo\"\nduration = \"3s\"\nusers = { alice = \"lab\" }\n",
        }),
        t(TableEditor {
            name: "smb",
            aliases: &[],
            title: "SMB",
            table: "smb",
            transports: TCP,
            port: Some(445),
            settings: SMB_SETTINGS,
            lists: &[],
            subtables: &[],
            example: "user = \"alice\"\npassword = \"lab\"\nops = [\"write report-{n}.bin 1M\", \"read report-{n}.bin\", \"delete report-{n}.bin\"]\nusers = { alice = \"lab\" }\n",
        }),
        t(TableEditor {
            name: TLS,
            aliases: &[],
            title: "TLS",
            table: "tls",
            transports: TCP,
            port: None,
            settings: TLS_SETTINGS,
            lists: &[],
            subtables: TLS_SUBTABLES,
            example: "versions = [\"1.3\"]\n",
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_get_their_toml_types() {
        assert_eq!(parse_value(K::Int(10), "7").unwrap(), Some(7.into()));
        assert!(parse_value(K::Int(10), "11").is_err());
        assert!(parse_value(K::Int(10), "x").is_err());
        assert_eq!(parse_value(K::Text, "  ").unwrap(), None);
        assert_eq!(parse_value(K::Expect, "201").unwrap(), Some(201.into()));
        assert_eq!(parse_value(K::Expect, "2xx").unwrap(), Some("2xx".into()));
        assert_eq!(parse_value(K::Size, "16K").unwrap(), Some("16K".into()));
        assert_eq!(
            parse_value(K::Duration, "20ms").unwrap(),
            Some("20ms".into())
        );
        assert!(parse_value(K::Duration, "soon").is_err());
    }

    /// Every example table is one the engine reads, so a new template
    /// from the menu starts out valid.
    #[test]
    fn examples_are_valid_profiles() {
        let reg = ferotrx_core::app::AppRegistry::builtin();
        for e in builtin_app_editors() {
            if e.name() == TLS {
                continue;
            }
            assert!(
                reg.contains(e.name()),
                "{} is not an engine protocol",
                e.name()
            );
            let t: toml::Table = toml::from_str(e.example()).unwrap();
            reg.parse(e.name(), &t, std::path::Path::new("."))
                .unwrap_or_else(|err| panic!("{}: {err}", e.name()));
        }
    }

    /// Every key the forms write is one the engine knows: set to a value
    /// of the wrong type, the engine complains about the type, never about
    /// an unknown field (catches typos in the tables above).
    #[test]
    fn the_forms_name_keys_the_engine_knows() {
        let reg = ferotrx_core::app::AppRegistry::builtin();
        let unknown =
            |name: &str, t: &toml::Table| match reg.parse(name, t, std::path::Path::new(".")) {
                Ok(_) => None,
                Err(e) => Some(e.to_string()).filter(|e| e.contains("unknown field")),
            };
        for e in builtin_app_editors() {
            if e.name() == TLS {
                continue;
            }
            let wrong = |k: &SettingKind| match k {
                K::Bool => toml::Value::String("x".into()),
                _ => toml::Value::Boolean(true),
            };
            for st in e.settings() {
                let t: toml::Table = [(st.key.to_string(), wrong(&st.kind))]
                    .into_iter()
                    .collect();
                assert_eq!(unknown(e.name(), &t), None, "{}.{}", e.name(), st.key);
            }
            for l in e.lists() {
                for st in l.settings {
                    let item: toml::Table = [(st.key.to_string(), wrong(&st.kind))]
                        .into_iter()
                        .collect();
                    let t: toml::Table = [(
                        l.key.to_string(),
                        toml::Value::Array(vec![toml::Value::Table(item)]),
                    )]
                    .into_iter()
                    .collect();
                    assert_eq!(
                        unknown(e.name(), &t),
                        None,
                        "{}.{}.{}",
                        e.name(),
                        l.key,
                        st.key
                    );
                }
            }
        }
    }

    #[test]
    fn every_protocol_of_the_engine_has_an_editor() {
        let names: Vec<&str> = builtin_app_editors().iter().map(|e| e.name()).collect();
        for n in ferotrx_core::app::AppRegistry::builtin().names() {
            assert!(names.contains(&n), "no GUI editor for {n}");
        }
    }
}
