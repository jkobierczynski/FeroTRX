//! The Applications tab: edit TCP and UDP profiles with their application
//! protocols in forms (`docs/app-protocols.md`), check them here, and run
//! them on the selected server.
//!
//! The profile is held as TOML text; the forms edit its table and write the
//! text again (comments go when a form changes something; the Text page
//! edits the text as it is). The tree on the left has the profile's run
//! settings, the client and server ends, the TCP or UDP options, and each
//! template with its protocol: the protocol's form comes from its
//! [`AppEditor`](crate::protocols::AppEditor) in the registry, TLS from the
//! `tls` editor.

use std::path::{Path, PathBuf};

use eframe::egui::{self, Color32, RichText};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::app::{FeroApp, Pending, Status};
use crate::files::{Kind, Target};
use crate::protocols::apps::{app_form, other_keys, End, Setting, SettingKind as K, TLS};
use crate::protocols::{Registry, Transport};

/// A new TCP profile: a web client and server through the lab router.
const NEW_TCP: &str = r#"# A stateful TCP profile with application protocols (docs/app-protocols.md).
format = 1
cps = 20
connections = 200
concurrency = 50

[[template]]
name = "web"
app = "http"

[template.http]
requests = ["GET /", "GET /missing 404"]
per_connection = 2

[[template.http.route]]
path = "/"
body = "FeroTRX lab"

[client]
ip = "192.168.10.100/24"
ips = 10
gateway = "192.168.10.1"
vlan = 10

[server]
ip = "192.168.20.80/24"
gateway = "192.168.20.1"
vlan = 20
"#;

/// A new UDP profile: DNS lookups through the lab router.
const NEW_UDP: &str = r#"# A stateful UDP profile with application protocols (docs/app-protocols.md).
format = 1
rate = 50
transactions = 500
concurrency = 50

[[template]]
name = "dns"
app = "dns"

[template.dns]
queries = ["www.lab.local A", "missing.lab.local A NXDOMAIN"]
records = ["www.lab.local A 192.168.20.80"]

[client]
ip = "192.168.10.100/24"
ips = 10
gateway = "192.168.10.1"
vlan = 10

[server]
ip = "192.168.20.53/24"
gateway = "192.168.20.1"
vlan = 20

[udp]
timeout = "500ms"
retries = 2
"#;

/// What the tree has open.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Node {
    #[default]
    Run,
    /// The protocol at the top level of a profile without templates.
    App,
    Template(usize),
    Client,
    Server,
    Options,
    Text,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileKind {
    #[default]
    Tcp,
    Udp,
}

impl ProfileKind {
    pub fn transport(self) -> Transport {
        match self {
            ProfileKind::Tcp => Transport::Tcp,
            ProfileKind::Udp => Transport::Udp,
        }
    }

    pub fn method(self) -> &'static str {
        match self {
            ProfileKind::Tcp => "tcp",
            ProfileKind::Udp => "udp",
        }
    }

    fn core(self) -> ferotrx_core::check::FileKind {
        match self {
            ProfileKind::Tcp => ferotrx_core::check::FileKind::Tcp,
            ProfileKind::Udp => ferotrx_core::check::FileKind::Udp,
        }
    }
}

/// The tab's state; saved in workspaces.
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AppsState {
    /// The profile file on this computer (empty for a new one).
    pub path: String,
    pub kind: ProfileKind,
    /// The profile as TOML.
    pub text: String,
    /// The text as last opened or saved.
    pub saved: String,
    pub node: Node,
    /// For the run: interface, backend and duration, as in the Stateful tab.
    pub iface: String,
    pub backend: String,
    pub duration: String,
    #[serde(skip)]
    pub check: Option<Result<String, String>>,
    /// The text last parsed, and its table or error.
    #[serde(skip)]
    parsed: Option<(String, Result<toml::Table, String>)>,
}

impl AppsState {
    pub fn dirty(&self) -> bool {
        self.text != self.saved
    }

    fn folder(&self) -> PathBuf {
        match self.path.trim() {
            "" => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            p => PathBuf::from(crate::files::folder_of(Path::new(p))),
        }
    }

    pub fn new_profile(&mut self, kind: ProfileKind) {
        self.kind = kind;
        self.path.clear();
        self.text = match kind {
            ProfileKind::Tcp => NEW_TCP,
            ProfileKind::Udp => NEW_UDP,
        }
        .into();
        self.saved.clear();
        self.node = Node::Template(0);
        self.check = None;
    }

    /// Reads a profile file; its kind as `ferotrx check` detects it.
    pub fn open(&mut self, path: &str) -> Result<(), String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        self.kind = match ferotrx_core::check::detect_kind(&text) {
            Ok(ferotrx_core::check::FileKind::Udp) => ProfileKind::Udp,
            Ok(ferotrx_core::check::FileKind::Tcp) => ProfileKind::Tcp,
            Ok(k) => return Err(format!("{path} is a {k:?} file, not a TCP or UDP profile")),
            Err(e) => return Err(format!("{path}: {e}")),
        };
        self.path = path.into();
        self.text = text.clone();
        self.saved = text;
        self.node = Node::Run;
        self.check = None;
        Ok(())
    }

    pub fn save(&mut self, path: &str) -> Result<(), String> {
        std::fs::write(path, &self.text).map_err(|e| format!("{path}: {e}"))?;
        self.path = path.into();
        self.saved = self.text.clone();
        Ok(())
    }

    /// The profile's table, parsed again when the text changed.
    pub fn table(&mut self) -> Result<toml::Table, String> {
        if !matches!(&self.parsed, Some((t, _)) if *t == self.text) {
            let r = toml::from_str::<toml::Table>(&self.text).map_err(|e| e.to_string());
            self.parsed = Some((self.text.clone(), r));
        }
        self.parsed.as_ref().expect("parsed").1.clone()
    }

    /// Writes an edited table back as the text.
    pub fn set_table(&mut self, t: &toml::Table) {
        self.text = toml::to_string(t).unwrap_or_default();
        self.parsed = Some((self.text.clone(), Ok(t.clone())));
        self.check = None;
    }

    /// Checks the profile as `ferotrx check` would, here.
    pub fn check_here(&mut self) {
        self.check = Some(
            ferotrx_core::check::check_text(
                &self.text,
                &self.folder(),
                Some(self.kind.core()),
                &[],
            )
            .map(|c| {
                let mut lines = c.summary;
                lines.extend(c.warnings.into_iter().map(|w| format!("warning: {w}")));
                lines.join("\n")
            })
            .map_err(|e| e.to_string()),
        );
    }

    /// `tcp.start` / `udp.start` parameters with the profile's text.
    pub fn params(&self, local: bool) -> Result<Value, String> {
        if self.text.trim().is_empty() {
            return Err("the profile is empty: open one, or start a new one".into());
        }
        let mut p = json!({ "toml": self.text });
        if local {
            p["base_dir"] = self.folder().display().to_string().into();
        }
        for (k, v) in [
            ("iface", &self.iface),
            ("backend", &self.backend),
            ("duration", &self.duration),
        ] {
            if !v.trim().is_empty() {
                p[k] = v.trim().into();
            }
        }
        Ok(p)
    }
}

const fn s(key: &'static str, label: &'static str, kind: K) -> Setting {
    Setting::new(key, label, kind, End::Both)
}

const TCP_RUN: &[Setting] = &[
    s("cps", "Connections per second", K::Number).default("10"),
    s("connections", "Connections", K::Int(u64::MAX >> 1))
        .default("100")
        .help("0 keeps going"),
    s("concurrency", "Concurrency", K::Int(1 << 24)).help("Most open at once"),
    s("duration", "Duration", K::Duration).default("until done"),
    s("model", "Traffic model", K::Text)
        .default("constant")
        .help("poisson, burst=N, ramp_up=…; docs/traffic-models.md"),
    s("connect", "Connect to", K::Text)
        .help("A real server instead of the emulated one: 192.168.20.10[:port]"),
    s("connect_ips", "Server addresses", K::Int(1 << 24))
        .help("Several addresses from `connect` on"),
    s("source_ports", "Source ports", K::Text).default("1024-65535"),
];

const UDP_RUN: &[Setting] = &[
    s("rate", "Transactions per second", K::Number).default("10"),
    s("transactions", "Transactions", K::Int(u64::MAX >> 1)).help("0 keeps going"),
    s("concurrency", "Concurrency", K::Int(1 << 24)),
    s("duration", "Duration", K::Duration).default("until done"),
    s("model", "Traffic model", K::Text).default("constant"),
    s("connect", "Send to", K::Text).help("A real server instead of the emulated one"),
    s("connect_ips", "Server addresses", K::Int(1 << 24)),
    s("source_ports", "Source ports", K::Text).default("1024-65535"),
];

const TEMPLATE_TCP: &[Setting] = &[
    s("name", "Name", K::Text),
    s("weight", "Weight", K::Int(u32::MAX as u64))
        .default("1")
        .help("Share of the connections"),
    s("port", "Port", K::Int(65535)).default("the protocol's"),
    s("cps", "Connections per second", K::Number).default("the profile's share"),
    s("connections", "Connections", K::Int(u64::MAX >> 1)),
    s("concurrency", "Concurrency", K::Int(1 << 24)),
    s("model", "Traffic model", K::Text),
    s("connect", "Connect to", K::Text),
    s("connect_ips", "Server addresses", K::Int(1 << 24)),
];

const TEMPLATE_UDP: &[Setting] = &[
    s("name", "Name", K::Text),
    s("weight", "Weight", K::Int(u32::MAX as u64)).default("1"),
    s("port", "Port", K::Int(65535)).default("the protocol's"),
    s("rate", "Transactions per second", K::Number),
    s("transactions", "Transactions", K::Int(u64::MAX >> 1)),
    s("concurrency", "Concurrency", K::Int(1 << 24)),
    s("model", "Traffic model", K::Text),
    s("connect", "Send to", K::Text),
    s("connect_ips", "Server addresses", K::Int(1 << 24)),
    s("think_time", "Think time", K::Duration),
];

const ENDPOINT: &[Setting] = &[
    s("ip", "Address", K::Text)
        .help("A free address with its prefix (192.168.10.100/24), or dhcp, slaac, dhcpv6"),
    s("ips", "Addresses", K::Int(1 << 24))
        .default("1")
        .help("Consecutive addresses from `ip`"),
    s("gateway", "Gateway", K::Text).help("The router's address"),
    s("vlan", "VLAN", K::Int(4094)),
    s("iface", "Interface", K::Text).default("the run's"),
    s("mac", "MAC", K::Text).default("02:00:<ip>"),
    s("next_hop_mac", "Next hop MAC", K::Text).default("ARP / NDP"),
    s("port", "Port", K::Int(65535)),
    s("hostname", "Host name", K::Text).help("For DHCP"),
];

const TCP_OPTIONS: &[Setting] = &[
    s("mss", "MSS", K::Int(65535)).default("1460"),
    s("send_window", "Send window", K::Size),
    s("receive_window", "Receive window", K::Size),
    s("window_scaling", "Window scaling", K::Bool).default("on"),
    s("timestamps", "Timestamps", K::Bool).default("on"),
    s("sack", "SACK", K::Bool).default("on"),
    s("rto", "Initial RTO", K::Duration).default("1s"),
    s("min_rto", "Min RTO", K::Duration).default("200ms"),
    s("max_retries", "Max retries", K::Int(1000)),
    s("syn_retries", "SYN retries", K::Int(1000)),
    s("time_wait", "TIME_WAIT", K::Duration),
    s("idle_timeout", "Idle timeout", K::Duration),
    s("think_time", "Think time", K::Duration),
    s("keep_timing", "Keep capture timing", K::Bool),
];

const UDP_OPTIONS: &[Setting] = &[
    s("timeout", "Timeout", K::Duration)
        .default("1s")
        .help("Ask again after this long without an answer"),
    s("retries", "Retries", K::Int(1000)),
    s("session_timeout", "Server session timeout", K::Duration),
    s("media_ports", "Media ports", K::Text).help("For RTP: 16384-32767"),
    s("think_time", "Think time", K::Duration),
    s("keep_timing", "Keep capture timing", K::Bool),
];

/// Keys of a run or template table the forms draw themselves.
const OWN_KEYS: &[&str] = &[
    "format", "app", "tls", "template", "client", "server", "tcp", "udp", "output", "hosts",
];

/// The `app` part of a table (the top level or a template): the protocol,
/// its form and TLS. Returns true when the table changed.
pub fn app_section(
    ui: &mut egui::Ui,
    registry: &Registry,
    transport: Transport,
    table: &mut toml::Table,
) -> bool {
    let mut changed = false;
    let app = table
        .get("app")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let names = registry.app_names(transport);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Protocol").strong());
        let shown = if app.is_empty() {
            "none (a capture or messages)".to_string()
        } else {
            match registry.app(&app) {
                Some((e, _)) => format!("{app} ({})", e.title()),
                None => format!("{app} (no form)"),
            }
        };
        egui::ComboBox::from_id_salt("app-pick")
            .selected_text(shown)
            .width(220.0)
            .show_ui(ui, |ui| {
                if ui.selectable_label(app.is_empty(), "none").clicked() && !app.is_empty() {
                    table.remove("app");
                    changed = true;
                }
                for (name, title) in &names {
                    if ui
                        .selectable_label(app == *name, format!("{name} ({title})"))
                        .clicked()
                        && app != *name
                    {
                        table.insert("app".into(), (*name).into());
                        if let Some((e, _)) = registry.app(name) {
                            if !table.contains_key(e.table()) && !e.example().is_empty() {
                                if let Ok(ex) = toml::from_str::<toml::Table>(e.example()) {
                                    table.insert(e.table().into(), toml::Value::Table(ex));
                                }
                            }
                        }
                        changed = true;
                    }
                }
            });
        if let Some((e, _)) = registry.app(&app) {
            if let Some(p) = e.port() {
                ui.weak(format!("port {p} unless set"));
            }
        }
    });
    if app.is_empty() {
        ui.weak("Without a protocol the template replays a capture (pcap = …) or plays messages; set them under Other keys.");
        return changed;
    }
    let Some((editor, forced_tls)) = registry.app(&app) else {
        // A protocol of a newer engine: its table as TOML.
        let mut sub = sub_table(table, &app);
        if other_keys(ui, &[], &mut sub) {
            put_sub(table, &app, sub);
            changed = true;
        }
        return changed;
    };
    let key = editor.table();
    let mut sub = sub_table(table, key);
    let r = egui::CollapsingHeader::new(
        RichText::new(format!("{} settings ([{key}])", editor.title())).strong(),
    )
    .id_salt(("app-table", key))
    .default_open(true)
    .show(ui, |ui| {
        if editor.settings().is_empty() && editor.lists().is_empty() {
            ui.weak(format!("{} has no settings.", editor.title()));
        }
        editor.ui(ui, &mut sub)
    });
    if r.body_returned == Some(true) {
        put_sub(table, key, sub);
        changed = true;
    }
    if transport == Transport::Tcp {
        if let Some((tls_editor, _)) = registry.app(TLS) {
            let tls_on = forced_tls
                || matches!(
                    table.get("tls"),
                    Some(toml::Value::Boolean(true)) | Some(toml::Value::Table(_))
                );
            ui.horizontal(|ui| {
                let mut on = tls_on;
                ui.add_enabled_ui(!forced_tls, |ui| {
                    if ui
                        .checkbox(&mut on, "Over TLS")
                        .on_disabled_hover_text(format!("{app} always runs over TLS"))
                        .changed()
                    {
                        if on {
                            table.insert("tls".into(), true.into());
                        } else {
                            table.remove("tls");
                        }
                        changed = true;
                    }
                });
            });
            if tls_on {
                let mut t = match table.get("tls") {
                    Some(toml::Value::Table(t)) => t.clone(),
                    _ => toml::Table::new(),
                };
                let r = egui::CollapsingHeader::new("TLS settings ([tls])")
                    .id_salt("tls-table")
                    .show(ui, |ui| tls_editor.ui(ui, &mut t));
                if r.body_returned == Some(true) {
                    changed = true;
                    if t.is_empty() {
                        if forced_tls {
                            table.remove("tls");
                        } else {
                            table.insert("tls".into(), true.into());
                        }
                    } else {
                        table.insert("tls".into(), toml::Value::Table(t));
                    }
                }
            }
        }
    }
    changed
}

fn sub_table(t: &toml::Table, key: &str) -> toml::Table {
    match t.get(key) {
        Some(toml::Value::Table(x)) => x.clone(),
        _ => toml::Table::new(),
    }
}

fn put_sub(t: &mut toml::Table, key: &str, sub: toml::Table) {
    t.insert(key.into(), toml::Value::Table(sub));
}

/// The templates of a profile.
fn templates(t: &toml::Table) -> Vec<toml::Table> {
    match t.get("template") {
        Some(toml::Value::Array(a)) => a.iter().filter_map(|v| v.as_table().cloned()).collect(),
        _ => Vec::new(),
    }
}

fn set_templates(t: &mut toml::Table, list: Vec<toml::Table>) {
    if list.is_empty() {
        t.remove("template");
    } else {
        t.insert(
            "template".into(),
            toml::Value::Array(list.into_iter().map(toml::Value::Table).collect()),
        );
    }
}

/// What the tab's buttons asked for.
#[derive(Default)]
struct Actions {
    new: Option<ProfileKind>,
    browse: bool,
    open: bool,
    save: bool,
    save_as: bool,
    check: bool,
    start: bool,
}

impl FeroApp {
    pub fn apps_tab(&mut self, ui: &mut egui::Ui) {
        let i = self.sel_server;
        let (can, local, addr, ifaces, backends) = match self.servers.get(i) {
            Some(s) => (
                s.status == Status::Connected && s.can_operate(),
                s.settings.is_local(),
                s.settings.addr.clone(),
                s.interfaces
                    .iter()
                    .map(|x| x.name.clone())
                    .collect::<Vec<_>>(),
                s.info
                    .as_ref()
                    .map(|i| i.backends.clone())
                    .unwrap_or_default(),
            ),
            None => (false, false, String::new(), Vec::new(), Vec::new()),
        };
        let mut a = Actions::default();
        let st = &mut self.apps;
        ui.heading("Application profiles");
        ui.label(
            RichText::new(
                "TCP and UDP profiles with HTTP, HTTP/2, DNS, NTP, MQTT, SSH, SIP and SMB, over TLS where they take it. \
                 Both ends are emulated unless the profile leaves one out. See docs/app-protocols.md.",
            )
            .weak(),
        );
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.label("Profile");
            ui.add(
                egui::TextEdit::singleline(&mut st.path)
                    .hint_text("examples/lab-http.toml")
                    .desired_width(280.0),
            );
            if ui.button("Browse…").clicked() {
                a.browse = true;
            }
            if ui.button("Open").clicked() {
                a.open = true;
            }
            if ui
                .button(if st.dirty() { "Save*" } else { "Save" })
                .clicked()
            {
                a.save = true;
            }
            if ui.button("Save as…").clicked() {
                a.save_as = true;
            }
            ui.menu_button("New", |ui| {
                if ui.button("TCP profile (HTTP)").clicked() {
                    a.new = Some(ProfileKind::Tcp);
                    ui.close();
                }
                if ui.button("UDP profile (DNS)").clicked() {
                    a.new = Some(ProfileKind::Udp);
                    ui.close();
                }
            });
            ui.separator();
            ui.radio_value(&mut st.kind, ProfileKind::Tcp, "TCP");
            ui.radio_value(&mut st.kind, ProfileKind::Udp, "UDP");
        });
        ui.horizontal_wrapped(|ui| {
            if ui
                .button("Check")
                .on_hover_text("Read the profile here as ferotrx check does")
                .clicked()
            {
                a.check = true;
            }
            ui.label("Interface");
            egui::ComboBox::from_id_salt("apps-iface")
                .selected_text(if st.iface.is_empty() {
                    "from the profile"
                } else {
                    &st.iface
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut st.iface, String::new(), "from the profile");
                    for n in &ifaces {
                        ui.selectable_value(&mut st.iface, n.clone(), n);
                    }
                });
            egui::ComboBox::from_id_salt("apps-backend")
                .selected_text(if st.backend.is_empty() {
                    "default backend"
                } else {
                    &st.backend
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut st.backend, String::new(), "default");
                    for b in &backends {
                        ui.selectable_value(&mut st.backend, b.clone(), b);
                    }
                });
            ui.add(
                egui::TextEdit::singleline(&mut st.duration)
                    .hint_text("duration")
                    .desired_width(70.0),
            );
            if ui
                .add_enabled(
                    can,
                    egui::Button::new(RichText::new(format!("▶ Run on {addr}")).strong()),
                )
                .on_disabled_hover_text("Connect to a server with the operator role")
                .clicked()
            {
                a.start = true;
            }
        });
        match &st.check {
            Some(Ok(sum)) => {
                ui.colored_label(
                    Color32::from_rgb(0x2e, 0xa0, 0x43),
                    "✔ the profile checks out",
                )
                .on_hover_text(sum);
            }
            Some(Err(e)) => {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
            None => {}
        }
        ui.separator();
        if st.text.trim().is_empty() {
            ui.weak("Open a profile (examples/lab-http.toml, lab-mqtt.toml, lab-sip.toml, …) or start a new one.");
        } else {
            profile_editor(ui, &self.registry, st);
        }
        self.apps_actions(a, i, local, &addr);
    }

    fn apps_actions(&mut self, a: Actions, i: usize, local: bool, addr: &str) {
        let st = &mut self.apps;
        if let Some(k) = a.new {
            st.new_profile(k);
        }
        let path = st.path.trim().to_string();
        if a.open {
            if let Err(e) = st.open(&path) {
                self.error(addr, e);
            }
        }
        let st = &mut self.apps;
        let mut save_as = a.save_as;
        if a.save {
            if path.is_empty() {
                save_as = true;
            } else {
                match st.save(&path) {
                    Ok(()) => self.info(addr, format!("saved {path}")),
                    Err(e) => self.error(addr, e),
                }
            }
        }
        let st = &mut self.apps;
        if a.check {
            st.check_here();
        }
        if a.start {
            st.check_here();
            match (&st.check, st.params(local)) {
                (Some(Err(e)), _) => {
                    let e = format!("profile: {e}");
                    self.error(addr, e);
                }
                (_, Err(e)) => self.error(addr, e),
                (_, Ok(p)) => {
                    let method = format!("{}.start", st.kind.method());
                    let what = format!("{method} sent");
                    self.call(i, &method, p, Pending::Done(what));
                }
            }
        }
        if a.browse {
            self.files.pick(
                Target::OpenAppProfile,
                "A TCP or UDP profile",
                Kind::Profile,
                &path,
            );
        }
        if save_as {
            let name = Path::new(&path)
                .file_name()
                .map_or("profile.toml".into(), |n| n.to_string_lossy().into_owned());
            self.files.save(
                Target::SaveAppProfile,
                "Save the profile",
                Kind::Profile,
                &path,
                &name,
            );
        }
    }

    /// Puts what the file dialog picked for the tab in place.
    pub fn apps_file(&mut self, target: Target, path: &Path) {
        let shown = path.display().to_string();
        let r = match target {
            Target::OpenAppProfile => self.apps.open(&shown).map(|_| format!("opened {shown}")),
            Target::SaveAppProfile => self.apps.save(&shown).map(|_| format!("saved {shown}")),
            _ => return,
        };
        match r {
            Ok(m) => self.info("", m),
            Err(e) => self.error("", e),
        }
    }
}

/// The tree of the profile on the left, the open part's form on the right.
fn profile_editor(ui: &mut egui::Ui, registry: &Registry, st: &mut AppsState) {
    let parsed = st.table();
    let mut table = match &parsed {
        Ok(t) => Some(t.clone()),
        Err(_) => None,
    };
    if table.is_none() {
        st.node = Node::Text;
    }
    let transport = st.kind.transport();
    let mut changed = false;
    let w = ui.available_width();
    egui::SidePanel::left("apps-tree")
        .resizable(true)
        .default_width((w * 0.22).clamp(170.0, 280.0))
        .show_inside(ui, |ui| {
            ui.set_min_height(ui.available_height());
            let Some(t) = table.as_mut() else {
                ui.selectable_value(&mut st.node, Node::Text, "Text");
                return;
            };
            let list = templates(t);
            ui.selectable_value(&mut st.node, Node::Run, "Run settings");
            if list.is_empty() {
                let app = t.get("app").and_then(|v| v.as_str()).unwrap_or("none");
                ui.selectable_value(&mut st.node, Node::App, format!("Protocol: {app}"));
            }
            ui.add_space(4.0);
            ui.label(RichText::new("Templates").weak());
            let mut op: Option<(usize, i8)> = None; // -1 remove, 1 duplicate
            for (n, tp) in list.iter().enumerate() {
                let name = tp
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .unwrap_or_else(|| format!("template {}", n + 1));
                let app = tp.get("app").and_then(|v| v.as_str()).unwrap_or("capture");
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut st.node, Node::Template(n), format!("{name} · {app}"));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("✕").on_hover_text("Remove").clicked() {
                            op = Some((n, -1));
                        }
                        if ui.small_button("copy").on_hover_text("Duplicate").clicked() {
                            op = Some((n, 1));
                        }
                    });
                });
            }
            ui.menu_button("+ Template", |ui| {
                for (name, title) in registry.app_names(transport) {
                    if ui.button(format!("{name} ({title})")).clicked() {
                        let mut tp = toml::Table::new();
                        tp.insert("name".into(), unique_name(&list, name).into());
                        tp.insert("app".into(), name.into());
                        if let Some((e, _)) = registry.app(name) {
                            if let Ok(ex) = toml::from_str::<toml::Table>(e.example()) {
                                if !ex.is_empty() {
                                    tp.insert(e.table().into(), toml::Value::Table(ex));
                                }
                            }
                        }
                        let mut l = list.clone();
                        l.push(tp);
                        st.node = Node::Template(l.len() - 1);
                        set_templates(t, l);
                        changed = true;
                        ui.close();
                    }
                }
            });
            if let Some((n, what)) = op {
                let mut l = list.clone();
                if what < 0 {
                    l.remove(n);
                    st.node = if l.is_empty() {
                        Node::Run
                    } else {
                        Node::Template(n.saturating_sub(1))
                    };
                } else {
                    let mut copy = l[n].clone();
                    if let Some(nm) = copy.get("name").and_then(|v| v.as_str()) {
                        let nm = unique_name(&l, nm);
                        copy.insert("name".into(), nm.into());
                    }
                    l.insert(n + 1, copy);
                    st.node = Node::Template(n + 1);
                }
                set_templates(t, l);
                changed = true;
            }
            ui.add_space(4.0);
            ui.label(RichText::new("Ends").weak());
            ui.selectable_value(
                &mut st.node,
                Node::Client,
                if t.contains_key("client") {
                    "Client"
                } else {
                    "Client (none: only a server)"
                },
            );
            ui.selectable_value(
                &mut st.node,
                Node::Server,
                if t.contains_key("server") {
                    "Server"
                } else {
                    "Server (none: only clients)"
                },
            );
            ui.selectable_value(
                &mut st.node,
                Node::Options,
                if transport == Transport::Tcp {
                    "TCP options"
                } else {
                    "UDP options"
                },
            );
            ui.add_space(4.0);
            ui.selectable_value(&mut st.node, Node::Text, "Text");
        });
    egui::CentralPanel::default().show_inside(ui, |ui| {
        if st.node == Node::Text {
            if let Err(e) = &parsed {
                ui.colored_label(ui.visuals().error_fg_color, format!("not valid TOML: {e}"));
            }
            egui::ScrollArea::both()
                .id_salt("apps-text")
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut st.text)
                            .code_editor()
                            .desired_width(f32::INFINITY)
                            .desired_rows(30),
                    );
                });
            return;
        }
        let Some(t) = table.as_mut() else { return };
        egui::ScrollArea::vertical()
            .id_salt(("apps-form", st.node))
            .auto_shrink([false, false])
            .show(ui, |ui| {
                changed |= node_form(ui, registry, transport, st.node, t);
            });
    });
    if changed {
        if let Some(t) = &table {
            st.set_table(t);
        }
    }
}

fn unique_name(list: &[toml::Table], base: &str) -> String {
    let taken = |n: &str| {
        list.iter()
            .any(|t| t.get("name").and_then(|v| v.as_str()) == Some(n))
    };
    if !taken(base) {
        return base.to_string();
    }
    (2..)
        .map(|i| format!("{base}-{i}"))
        .find(|n| !taken(n))
        .expect("a free name")
}

/// The form of one part of the profile.
fn node_form(
    ui: &mut egui::Ui,
    registry: &Registry,
    transport: Transport,
    node: Node,
    t: &mut toml::Table,
) -> bool {
    let tcp = transport == Transport::Tcp;
    match node {
        Node::Run => {
            ui.strong("Run settings");
            ui.weak(
                "For the whole run; templates share the rate by weight unless they set their own.",
            );
            let run = if tcp { TCP_RUN } else { UDP_RUN };
            let mut own: Vec<&str> = OWN_KEYS.to_vec();
            // The protocol's table at the top, when there are no templates.
            let app_table = t
                .get("app")
                .and_then(|v| v.as_str())
                .and_then(|a| registry.app(a))
                .map(|(e, _)| e.table());
            own.extend(app_table);
            let mut top: toml::Table = t
                .iter()
                .filter(|(k, _)| !own.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if app_form(ui, run, &[], &[], &mut top) {
                t.retain(|k, _| own.contains(&k));
                t.extend(top);
                return true;
            }
            false
        }
        Node::App => {
            ui.strong("The profile's protocol");
            ui.weak("Without templates, the protocol is set at the top of the profile. Add templates to mix several.");
            ui.push_id("top-app", |ui| app_section(ui, registry, transport, t))
                .inner
        }
        Node::Template(n) => {
            let mut list = templates(t);
            let Some(tp) = list.get_mut(n) else {
                ui.weak("No such template.");
                return false;
            };
            ui.strong(format!("Template {}", n + 1));
            let mut changed = false;
            let app_table = tp
                .get("app")
                .and_then(|v| v.as_str())
                .and_then(|a| registry.app(a))
                .map(|(e, _)| e.table());
            let mut own: Vec<&str> = OWN_KEYS.to_vec();
            own.extend(app_table);
            let mut plain: toml::Table = tp
                .iter()
                .filter(|(k, _)| !own.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            ui.push_id(("tpl", n), |ui| {
                if app_form(
                    ui,
                    if tcp { TEMPLATE_TCP } else { TEMPLATE_UDP },
                    &[],
                    &[],
                    &mut plain,
                ) {
                    tp.retain(|k, _| own.contains(&k));
                    tp.extend(plain);
                    changed = true;
                }
                ui.separator();
                changed |= app_section(ui, registry, transport, tp);
            });
            if changed {
                set_templates(t, list);
            }
            changed
        }
        Node::Client | Node::Server => {
            let key = if node == Node::Client {
                "client"
            } else {
                "server"
            };
            let mut end = sub_table(t, key);
            let present = t.contains_key(key);
            let mut changed = false;
            ui.horizontal(|ui| {
                ui.strong(if node == Node::Client { "Client end" } else { "Server end" });
                let mut on = present;
                if ui
                    .checkbox(&mut on, "emulated here")
                    .on_hover_text(if node == Node::Client {
                        "Untick to leave the clients out: the emulated server alone, for real clients"
                    } else {
                        "Untick to leave the server out: the emulated clients against a real server (connect = …)"
                    })
                    .changed()
                {
                    if on {
                        t.insert(key.into(), toml::Value::Table(end.clone()));
                    } else {
                        t.remove(key);
                    }
                    changed = true;
                }
            });
            if !t.contains_key(key) {
                return changed;
            }
            if app_form(ui, ENDPOINT, &[], &[], &mut end) {
                put_sub(t, key, end);
                changed = true;
            }
            changed
        }
        Node::Options => {
            let key = if tcp { "tcp" } else { "udp" };
            ui.strong(if tcp {
                "TCP options ([tcp])"
            } else {
                "UDP options ([udp])"
            });
            let mut o = sub_table(t, key);
            if app_form(
                ui,
                if tcp { TCP_OPTIONS } else { UDP_OPTIONS },
                &[],
                &[],
                &mut o,
            ) {
                if o.is_empty() {
                    t.remove(key);
                } else {
                    put_sub(t, key, o);
                }
                return true;
            }
            false
        }
        Node::Text => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn examples() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples")
    }

    #[test]
    fn new_profiles_check_out() {
        let mut st = AppsState::default();
        for k in [ProfileKind::Tcp, ProfileKind::Udp] {
            st.new_profile(k);
            st.check_here();
            assert!(matches!(st.check, Some(Ok(_))), "{k:?}: {:?}", st.check);
        }
    }

    /// Every example with application protocols opens, survives a write
    /// through the forms' table, and still checks out.
    #[test]
    fn examples_round_trip_through_the_table() {
        for f in [
            "lab-http.toml",
            "lab-mqtt.toml",
            "lab-h2.toml",
            "lab-https.toml",
            "lab-dns.toml",
            "lab-sip.toml",
            "lab-ssh.toml",
            "lab-smb.toml",
        ] {
            let p = examples().join(f);
            let mut st = AppsState::default();
            st.open(p.to_str().unwrap()).unwrap();
            let t = st.table().unwrap();
            st.set_table(&t);
            assert!(st.dirty());
            st.check_here();
            assert!(matches!(st.check, Some(Ok(_))), "{f}: {:?}", st.check);
            let p = st.params(true).unwrap();
            assert!(p["base_dir"].as_str().unwrap().ends_with("examples"), "{p}");
        }
    }

    #[test]
    fn opening_other_files_is_refused() {
        let mut st = AppsState::default();
        let e = st
            .open(examples().join("lab-scenario.toml").to_str().unwrap())
            .unwrap_err();
        assert!(e.contains("not a TCP or UDP profile"), "{e}");
    }

    #[test]
    fn templates_get_free_names() {
        let mk = |n: &str| -> toml::Table {
            [("name".to_string(), toml::Value::String(n.into()))]
                .into_iter()
                .collect()
        };
        let l = vec![mk("web"), mk("web-2")];
        assert_eq!(unique_name(&l, "web"), "web-3");
        assert_eq!(unique_name(&l, "dns"), "dns");
    }

    /// The run, endpoint and option forms name keys the engine reads.
    #[test]
    fn profile_forms_name_known_keys() {
        for (kind, base, run, opts, okey) in [
            (ProfileKind::Tcp, NEW_TCP, TCP_RUN, TCP_OPTIONS, "tcp"),
            (ProfileKind::Udp, NEW_UDP, UDP_RUN, UDP_OPTIONS, "udp"),
        ] {
            let t0: toml::Table = toml::from_str(base).unwrap();
            let try_it = |t: &toml::Table, what: &str| {
                let text = toml::to_string(t).unwrap();
                if let Err(e) =
                    ferotrx_core::check::check_text(&text, Path::new("."), Some(kind.core()), &[])
                {
                    assert!(
                        !e.to_string().contains("unknown field"),
                        "{kind:?} {what}: {e}"
                    );
                }
            };
            let wrong = toml::Value::Array(vec![toml::Value::Boolean(true)]);
            for s in run {
                let mut t = t0.clone();
                t.insert(s.key.into(), wrong.clone());
                try_it(&t, s.key);
            }
            for s in ENDPOINT {
                let mut t = t0.clone();
                if let Some(toml::Value::Table(c)) = t.get_mut("client") {
                    c.insert(s.key.into(), wrong.clone());
                }
                try_it(&t, s.key);
            }
            for s in opts {
                let mut t = t0.clone();
                t.insert(
                    okey.into(),
                    toml::Value::Table([(s.key.to_string(), wrong.clone())].into_iter().collect()),
                );
                try_it(&t, s.key);
            }
            let tpl = if kind == ProfileKind::Tcp {
                TEMPLATE_TCP
            } else {
                TEMPLATE_UDP
            };
            for s in tpl {
                let mut t = t0.clone();
                if let Some(toml::Value::Array(a)) = t.get_mut("template") {
                    if let Some(toml::Value::Table(x)) = a.get_mut(0) {
                        x.insert(s.key.into(), wrong.clone());
                    }
                }
                try_it(&t, s.key);
            }
        }
    }

    /// The TLS form's keys are ones the engine's [tls] table takes.
    #[test]
    fn tls_form_names_known_keys() {
        let reg = Registry::builtin();
        let (tls, _) = reg.app(TLS).unwrap();
        for s in tls.settings() {
            let text = format!(
                "format = 1\ncps = 1\nconnections = 1\napp = \"https\"\n[tls]\n{} = [true]\n[client]\nip = \"10.0.0.1/24\"\n[server]\nip = \"10.0.0.2/24\"\n",
                s.key
            );
            if let Err(e) = ferotrx_core::check::check_text(
                &text,
                Path::new("."),
                Some(ferotrx_core::check::FileKind::Tcp),
                &[],
            ) {
                assert!(
                    !e.to_string().contains("unknown field"),
                    "tls.{}: {e}",
                    s.key
                );
            }
        }
    }
}
