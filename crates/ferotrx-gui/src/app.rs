//! The window: servers and their ports on the left, the selected port's
//! streams and the stream editor in the middle, statistics and the log at
//! the bottom.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use eframe::egui;
use ferotrx_ctl::protocol::{InterfaceEntry, LabInfo, ProfileInfo, RunInfo, ServerInfo};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::conn::{ConnSettings, Connection, Event, Request, Snapshot};
use crate::model::{start_params, PortConfig, PortKind, ProfileDraft};
use crate::protocols::Registry;
use crate::views::{CaptureState, EditorState, ScenarioState, StatefulState};

const STORAGE_KEY: &str = "ferotrx-gui";
/// Points kept per run in the rate charts.
const HISTORY: usize = 600;

/// What the GUI remembers between sessions.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Workspace {
    pub servers: Vec<ConnSettings>,
    /// Streams and settings per server and port (`addr|port key`).
    pub ports: BTreeMap<String, PortWork>,
    /// Output file for the "file" port, on the server.
    pub file_out: String,
    /// The port that was open when the GUI closed.
    pub last: Option<LastView>,
}

/// Where the GUI was, to open there again.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LastView {
    pub server: String,
    pub port: Option<PortKind>,
    pub stream: Option<usize>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PortWork {
    pub profile: ProfileDraft,
    pub config: PortConfig,
    /// The folder of the profile file the streams came from (absolute):
    /// relative pcap paths start there when the server is on this computer.
    pub base_dir: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Status {
    Disconnected,
    Connecting,
    Connected,
    Failed(String),
}

/// A call waiting for its answer, and what to do with it.
#[derive(Debug)]
pub enum Pending {
    /// `profile.load` for a port; start the run when it is loaded.
    LoadThenStart { port: String, params: Value },
    /// `run.start` for a port.
    Started { port: String },
    /// `profile.load` only, to check the streams on the server.
    Checked { port: String },
    /// `lab.get`, `lab.start` or `lab.stop`: keep the lab's state, log this
    /// on success (nothing when empty; an empty one also stays quiet when
    /// an older server does not know the method).
    Lab(String),
    /// `interfaces.list`, after the lab changed the server's links.
    Interfaces,
    /// `scenario.check` of a file on the server.
    ScenarioChecked,
    /// `scenario.start`: show the run.
    ScenarioStarted,
    /// Any other call: log this on success.
    Done(String),
}

/// Rates of one run over time, for the charts.
#[derive(Debug, Default)]
pub struct RateHistory {
    pub label: String,
    /// (seconds since the GUI started, packets/s, Mbit/s)
    pub points: VecDeque<(f64, f64, f64)>,
    last: Option<(f64, u64, u64)>,
}

impl RateHistory {
    fn add(&mut self, t: f64, packets: u64, bytes: u64) {
        if let Some((t0, p0, b0)) = self.last {
            let dt = t - t0;
            if dt > 0.05 {
                let pps = packets.saturating_sub(p0) as f64 / dt;
                let mbps = bytes.saturating_sub(b0) as f64 * 8.0 / dt / 1e6;
                self.points.push_back((t, pps, mbps));
                if self.points.len() > HISTORY {
                    self.points.pop_front();
                }
            }
        }
        self.last = Some((t, packets, bytes));
    }
}

pub struct ServerState {
    pub settings: ConnSettings,
    pub conn: Option<Connection>,
    pub status: Status,
    pub info: Option<ServerInfo>,
    pub interfaces: Vec<InterfaceEntry>,
    pub snap: Snapshot,
    /// Rate history per run (`run:3`, `tcp:1`, ...).
    pub history: BTreeMap<String, RateHistory>,
    pub pending: HashMap<u64, Pending>,
    /// The stream run each port started last.
    pub port_runs: BTreeMap<String, u64>,
    /// The server's lab router, once `lab.get` answered (older servers have none).
    pub lab: Option<LabInfo>,
    /// Why the last `lab.start` or `lab.stop` failed.
    pub lab_error: Option<String>,
}

impl ServerState {
    pub fn new(settings: ConnSettings) -> Self {
        Self {
            settings,
            conn: None,
            status: Status::Disconnected,
            info: None,
            interfaces: Vec::new(),
            snap: Snapshot::default(),
            history: BTreeMap::new(),
            pending: HashMap::new(),
            port_runs: BTreeMap::new(),
            lab: None,
            lab_error: None,
        }
    }

    /// The ports to show: interfaces, then the file and null outputs.
    pub fn ports(&self) -> Vec<PortKind> {
        let mut v: Vec<PortKind> = self
            .interfaces
            .iter()
            .filter(|i| !pseudo_interface(&i.name))
            .map(|i| PortKind::Interface(i.name.clone()))
            .collect();
        v.push(PortKind::File);
        v.push(PortKind::Null);
        v
    }

    pub fn run(&self, id: u64) -> Option<&RunInfo> {
        self.snap.runs.iter().find(|r| r.id == id)
    }

    /// May this connection start and stop runs?
    pub fn can_operate(&self) -> bool {
        match &self.info {
            Some(i) => !matches!(i.role, Some(ferotrx_ctl::Role::Read)),
            None => false,
        }
    }
}

/// libpcap devices that are not network ports (Linux `any`, netfilter,
/// D-Bus, USB and Bluetooth monitors).
pub fn pseudo_interface(name: &str) -> bool {
    name == "any"
        || name == "bluetooth-monitor"
        || ["nflog", "nfqueue", "dbus-", "usbmon", "bluetooth"]
            .iter()
            .any(|p| name.starts_with(p))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Streams,
    Stateful,
    Capture,
    Scenario,
    Charts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BottomTab {
    #[default]
    Stats,
    Log,
}

#[derive(Clone, Debug)]
pub struct LogLine {
    pub at: Duration,
    pub error: bool,
    pub server: String,
    pub text: String,
}

pub struct FeroApp {
    pub registry: Registry,
    pub servers: Vec<ServerState>,
    pub sel_server: usize,
    pub sel_port: Option<PortKind>,
    pub work: Workspace,
    pub tab: Tab,
    pub bottom: BottomTab,
    pub editor: EditorState,
    pub capture: CaptureState,
    pub stateful: StatefulState,
    pub scenario: ScenarioState,
    pub log: Vec<LogLine>,
    pub next_tag: u64,
    pub started: Instant,
    /// The "add server" dialog, while open.
    pub add_server: Option<ConnSettings>,
    /// The file dialog, while open.
    pub files: crate::files::Dialogs,
    /// The lab router window, while open.
    pub lab_form: Option<crate::views::LabForm>,
    pub ctx: egui::Context,
}

/// Command line choices for [`FeroApp::new`].
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Servers to add and connect at start.
    pub connect: Vec<ConnSettings>,
    /// Captures to open in the Capture tab.
    pub capture: Option<String>,
    /// Port of the first server to open: an interface name, `file` or `null`.
    pub port: Option<String>,
    /// A profile file to read into that port's streams.
    pub profile: Option<String>,
    /// A scenario to open in the Scenario tab.
    pub scenario: Option<String>,
}

impl FeroApp {
    pub fn new(cc: &eframe::CreationContext<'_>, opts: Options) -> Self {
        let work: Workspace = cc
            .storage
            .and_then(|s| eframe::get_value(s, STORAGE_KEY))
            .unwrap_or_default();
        crate::fonts::install(&cc.egui_ctx);
        Self::with_workspace(cc.egui_ctx.clone(), work, opts)
    }

    pub fn with_workspace(ctx: egui::Context, work: Workspace, opts: Options) -> Self {
        let mut app = Self {
            registry: Registry::builtin(),
            servers: work.servers.iter().cloned().map(ServerState::new).collect(),
            sel_server: 0,
            sel_port: None,
            work,
            tab: Tab::Streams,
            bottom: BottomTab::Stats,
            editor: EditorState::default(),
            capture: CaptureState::default(),
            stateful: StatefulState::default(),
            scenario: ScenarioState::default(),
            log: Vec::new(),
            next_tag: 1,
            started: Instant::now(),
            add_server: None,
            files: Default::default(),
            lab_form: None,
            ctx,
        };
        if let Some(last) = app.work.last.clone() {
            if let Some(i) = app
                .servers
                .iter()
                .position(|s| s.settings.address() == last.server)
            {
                app.sel_server = i;
                app.sel_port = last.port;
                app.editor.stream = last.stream;
            }
        }
        if app.servers.is_empty() && opts.connect.is_empty() {
            app.servers.push(ServerState::new(ConnSettings::default()));
        }
        for s in opts.connect {
            let i = match app
                .servers
                .iter()
                .position(|x| x.settings.address() == s.address())
            {
                Some(i) => {
                    app.servers[i].settings = s;
                    i
                }
                None => {
                    app.servers.push(ServerState::new(s));
                    app.servers.len() - 1
                }
            };
            app.connect(i);
            app.sel_server = i;
        }
        if let Some(p) = &opts.port {
            app.sel_port = Some(match p.as_str() {
                "null" => PortKind::Null,
                "file" => PortKind::File,
                n => PortKind::Interface(n.to_string()),
            });
            app.editor = EditorState::default();
        }
        if let Some(path) = &opts.profile {
            let port = app.sel_port.clone().unwrap_or(PortKind::Null);
            app.sel_port = Some(port.clone());
            let i = app.sel_server.min(app.servers.len().saturating_sub(1));
            let key = app.port_key(i, &port);
            match std::fs::read_to_string(path)
                .map_err(|e| e.to_string())
                .and_then(|t| ProfileDraft::from_toml(&t))
            {
                Ok(d) => {
                    let n = d.streams.len();
                    let work = app.port_work(i, &port);
                    work.profile = d;
                    work.base_dir = crate::files::folder_of(std::path::Path::new(path));
                    app.editor = EditorState {
                        stream: (n > 0).then_some(0),
                        ..Default::default()
                    };
                    app.info(&key, format!("opened {path} ({n} streams)"));
                }
                Err(e) => app.error(&key, format!("{path}: {e}")),
            }
        }
        if let Some(path) = &opts.scenario {
            if let Err(e) = app.scenario.open(path) {
                app.error("", e);
            }
            app.tab = Tab::Scenario;
        }
        if let Some(path) = opts.capture {
            app.capture.path = path;
            app.capture.open();
            app.tab = Tab::Capture;
        }
        app
    }

    // ----- connections -----

    pub fn connect(&mut self, i: usize) {
        let ctx = self.ctx.clone();
        let s = &mut self.servers[i];
        s.status = Status::Connecting;
        s.pending.clear();
        s.conn = Some(Connection::open(
            s.settings.clone(),
            Duration::from_millis(1000),
            move || ctx.request_repaint(),
        ));
    }

    pub fn disconnect(&mut self, i: usize) {
        let s = &mut self.servers[i];
        s.conn = None;
        s.status = Status::Disconnected;
        s.pending.clear();
    }

    /// Sends a call to server `i` and remembers what to do with its answer.
    pub fn call(&mut self, i: usize, method: &str, params: Value, pending: Pending) {
        let tag = self.next_tag;
        self.next_tag += 1;
        let s = &mut self.servers[i];
        match &s.conn {
            Some(c) if s.status == Status::Connected => {
                c.call(method, params, tag);
                s.pending.insert(tag, pending);
            }
            _ => {
                let name = s.settings.addr.clone();
                self.error(&name, format!("{method}: not connected"));
            }
        }
    }

    pub fn info(&mut self, server: &str, text: impl Into<String>) {
        self.push_log(server, false, text.into());
    }

    pub fn error(&mut self, server: &str, text: impl Into<String>) {
        self.push_log(server, true, text.into());
        self.bottom = BottomTab::Log;
    }

    fn push_log(&mut self, server: &str, error: bool, text: String) {
        self.log.push(LogLine {
            at: self.started.elapsed(),
            error,
            server: server.to_string(),
            text,
        });
        if self.log.len() > 2000 {
            self.log.drain(..500);
        }
    }

    /// Reads every worker's events.
    pub fn poll(&mut self) {
        let now = self.started.elapsed().as_secs_f64();
        for i in 0..self.servers.len() {
            let events = match &self.servers[i].conn {
                Some(c) => c.events(),
                None => continue,
            };
            for e in events {
                self.handle(i, e, now);
            }
        }
    }

    fn handle(&mut self, i: usize, e: Event, now: f64) {
        let name = self.servers[i].settings.addr.clone();
        match e {
            Event::Connected { info, interfaces } => {
                let s = &mut self.servers[i];
                let what = format!(
                    "connected: {} {} (protocol {}){}{}",
                    info.name,
                    info.version,
                    info.protocol,
                    if info.tls { ", TLS" } else { "" },
                    info.role
                        .map(|r| format!(", role {}", r.as_str()))
                        .unwrap_or_default()
                );
                s.info = Some(info);
                s.interfaces = interfaces;
                s.status = Status::Connected;
                self.info(&name, what);
                self.call(i, "lab.get", Value::Null, Pending::Lab(String::new()));
            }
            Event::Closed(err) => {
                let s = &mut self.servers[i];
                s.conn = None;
                s.pending.clear();
                s.status = Status::Failed(err.clone());
                self.error(&name, err);
            }
            Event::Snapshot(snap) => {
                let s = &mut self.servers[i];
                for r in &snap.runs {
                    let h = s.history.entry(format!("run:{}", r.id)).or_default();
                    h.label = format!("run {} {}", r.id, r.output);
                    if r.state.is_running() || h.points.is_empty() {
                        h.add(now, r.total.packets, r.total.bytes);
                    }
                }
                for r in &snap.tcp {
                    let h = s.history.entry(format!("tcp:{}", r.id)).or_default();
                    h.label = format!("tcp {} {}", r.id, r.program);
                    if r.state.is_running() || h.points.is_empty() {
                        h.add(now, r.tx_packets, r.tx_bytes);
                    }
                }
                for r in &snap.udp {
                    let h = s.history.entry(format!("udp:{}", r.id)).or_default();
                    h.label = format!("udp {} {}", r.id, r.program);
                    if r.state.is_running() || h.points.is_empty() {
                        h.add(now, r.tx_packets, r.tx_bytes);
                    }
                }
                for r in &snap.rx {
                    let h = s.history.entry(format!("rx:{}", r.id)).or_default();
                    h.label = format!("rx {} {}", r.id, r.counters.iface);
                    if r.state.is_running() || h.points.is_empty() {
                        h.add(now, r.counters.packets, r.counters.bytes);
                    }
                }
                // Forget runs the server no longer has.
                let alive: Vec<String> = snap
                    .runs
                    .iter()
                    .map(|r| format!("run:{}", r.id))
                    .chain(snap.tcp.iter().map(|r| format!("tcp:{}", r.id)))
                    .chain(snap.udp.iter().map(|r| format!("udp:{}", r.id)))
                    .chain(snap.rx.iter().map(|r| format!("rx:{}", r.id)))
                    .collect();
                s.history.retain(|k, _| alive.contains(k));
                s.snap = *snap;
            }
            Event::Reply { tag, result } => {
                let Some(p) = self.servers[i].pending.remove(&tag) else {
                    return;
                };
                match (p, result) {
                    (Pending::LoadThenStart { port, params }, Ok(_)) => {
                        self.call(i, "run.start", params, Pending::Started { port });
                    }
                    (Pending::Started { port }, Ok(v)) => {
                        match serde_json::from_value::<RunInfo>(v) {
                            Ok(run) => {
                                self.info(
                                    &name,
                                    format!("run {} started on {}", run.id, run.output),
                                );
                                self.servers[i].port_runs.insert(port, run.id);
                            }
                            Err(e) => self.error(&name, format!("run.start: {e}")),
                        }
                        if let Some(c) = &self.servers[i].conn {
                            c.send(Request::Refresh);
                        }
                    }
                    (Pending::Checked { port }, Ok(v)) => {
                        match serde_json::from_value::<ProfileInfo>(v) {
                            Ok(p) => self.info(
                                &name,
                                format!(
                                    "{port}: the server accepts {} stream(s): {}",
                                    p.streams.len(),
                                    p.streams
                                        .iter()
                                        .map(|s| format!("{} ({}, {})", s.name, s.source, s.rate))
                                        .collect::<Vec<_>>()
                                        .join("; ")
                                ),
                            ),
                            Err(e) => self.error(&name, format!("profile.load: {e}")),
                        }
                    }
                    (Pending::Lab(what), Ok(v)) => match serde_json::from_value::<LabInfo>(v) {
                        Ok(lab) => {
                            let was = self.servers[i].lab.as_ref().is_some_and(|l| l.running);
                            let now_running = lab.running;
                            let announce = !what.is_empty();
                            if announce {
                                self.info(&name, what);
                                for l in lab.summary.iter().chain(&lab.notes) {
                                    self.info(&name, format!("  {l}"));
                                }
                            }
                            let iface = lab.interface.clone();
                            self.servers[i].lab = Some(lab);
                            if announce {
                                self.servers[i].lab_error = None;
                            }
                            if was != now_running || announce {
                                self.call(i, "interfaces.list", Value::Null, Pending::Interfaces);
                            }
                            if now_running && !was && announce {
                                self.sel_server = i;
                                self.sel_port = Some(PortKind::Interface(iface.clone()));
                                self.stateful.iface = iface;
                            }
                        }
                        Err(e) => self.error(&name, format!("lab: {e}")),
                    },
                    (Pending::Interfaces, Ok(v)) => {
                        match serde_json::from_value::<Vec<InterfaceEntry>>(v) {
                            Ok(list) => self.servers[i].interfaces = list,
                            Err(e) => self.error(&name, format!("interfaces.list: {e}")),
                        }
                    }
                    (Pending::Lab(what), Err(_)) if what.is_empty() => {}
                    (Pending::Lab(what), Err(e)) => {
                        self.servers[i].lab_error = Some(e.to_string());
                        self.error(&name, format!("{what} failed: {e}"));
                    }
                    (Pending::Done(what), Ok(_)) => self.info(&name, what),
                    (Pending::ScenarioChecked, Ok(v)) => {
                        self.scenario.checked = Some(
                            serde_json::from_value::<ferotrx_ctl::protocol::ScenarioInfo>(v)
                                .map_err(|e| e.to_string()),
                        );
                    }
                    (Pending::ScenarioChecked, Err(e)) => {
                        self.scenario.checked = Some(Err(e.to_string()));
                    }
                    (Pending::ScenarioStarted, Ok(v)) => {
                        match serde_json::from_value::<ferotrx_ctl::protocol::ScenarioRunInfo>(v) {
                            Ok(r) => {
                                self.scenario.run = Some(r.id);
                                let s = &mut self.servers[i];
                                s.snap.scenarios.retain(|x| x.id != r.id);
                                s.snap.scenarios.push(r.clone());
                                self.info(
                                    &name,
                                    format!("scenario {} started as run {}", r.scenario, r.id),
                                );
                            }
                            Err(e) => self.error(&name, format!("scenario.start: {e}")),
                        }
                    }
                    (p, Err(e)) => {
                        let what = match p {
                            Pending::LoadThenStart { port, .. } | Pending::Checked { port } => {
                                format!("{port}: profile refused: {e}")
                            }
                            Pending::Started { port } => format!("{port}: run.start: {e}"),
                            Pending::Done(what) | Pending::Lab(what) => {
                                format!("{what} failed: {e}")
                            }
                            Pending::Interfaces => format!("interfaces.list: {e}"),
                            Pending::ScenarioChecked | Pending::ScenarioStarted => {
                                format!("scenario: {e}")
                            }
                        };
                        self.error(&name, what);
                    }
                }
            }
        }
    }

    // ----- ports -----

    /// The key of a port of server `i` in the workspace.
    pub fn port_key(&self, i: usize, port: &PortKind) -> String {
        format!("{}|{}", self.servers[i].settings.address(), port.key())
    }

    pub fn port_work(&mut self, i: usize, port: &PortKind) -> &mut PortWork {
        let key = self.port_key(i, port);
        self.work.ports.entry(key).or_default()
    }

    /// Loads the port's enabled streams as a profile and starts them.
    pub fn start_port(&mut self, i: usize, port: &PortKind) {
        let key = self.port_key(i, port);
        let work = self.port_work(i, port).clone();
        if !work.profile.streams.iter().any(|s| s.enabled) {
            self.error(&key, "no enabled streams to send");
            return;
        }
        let name = port.profile_name();
        let params = start_params(port, &work.config, &name, &self.work.file_out);
        let load = self.load_params(i, &name, &work);
        self.call(
            i,
            "profile.load",
            load,
            Pending::LoadThenStart { port: key, params },
        );
    }

    pub fn check_port(&mut self, i: usize, port: &PortKind) {
        let key = self.port_key(i, port);
        let work = self.port_work(i, port).clone();
        let load = self.load_params(i, &port.profile_name(), &work);
        self.call(i, "profile.load", load, Pending::Checked { port: key });
    }

    /// `profile.load` with the port's streams. A server on this computer
    /// reads relative pcap paths from the folder the profile file was in, as
    /// `ferotrx run` does; a server elsewhere from its data directory.
    fn load_params(&self, i: usize, name: &str, work: &PortWork) -> Value {
        let mut load = serde_json::json!({ "name": name, "toml": work.profile.to_toml(true) });
        if self.servers[i].settings.is_local() && !work.base_dir.is_empty() {
            load["base_dir"] = work.base_dir.clone().into();
        }
        load
    }

    pub fn stop_run(&mut self, i: usize, kind: &str, id: u64) {
        self.call(
            i,
            &format!("{kind}.stop"),
            serde_json::json!({ "id": id, "wait": false }),
            Pending::Done(format!("{kind} {id} stopped")),
        );
    }

    pub fn remove_run(&mut self, i: usize, kind: &str, id: u64) {
        self.call(
            i,
            &format!("{kind}.remove"),
            serde_json::json!({ "id": id }),
            Pending::Done(format!("{kind} {id} removed")),
        );
    }

    /// The stream run a port started, if the server still has it.
    pub fn port_run(&self, i: usize, port: &PortKind) -> Option<&RunInfo> {
        let s = self.servers.get(i)?;
        let id = *s.port_runs.get(&self.port_key(i, port))?;
        s.run(id)
    }
}

impl eframe::App for FeroApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        self.ui(ctx);
        // Keep the charts moving while something runs.
        if self.servers.iter().any(|s| s.status == Status::Connected) {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        self.work.servers = self.servers.iter().map(|s| s.settings.clone()).collect();
        self.work.last = self.servers.get(self.sel_server).map(|s| LastView {
            server: s.settings.address(),
            port: self.sel_port.clone(),
            stream: self.editor.stream,
        });
        eframe::set_value(storage, STORAGE_KEY, &self.work);
    }
}
