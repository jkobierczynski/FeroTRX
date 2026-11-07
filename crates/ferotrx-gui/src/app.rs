//! The window: servers and their ports on the left, the selected port's
//! streams and the stream editor in the middle, statistics and the log at
//! the bottom.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use eframe::egui;
use ferotrx_ctl::protocol::{
    FlowCounters, InterfaceEntry, LabInfo, ProfileInfo, RunInfo, ServerInfo,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::conn::{ConnSettings, Connection, Event, Request, Snapshot};
use crate::model::{start_params, PortConfig, PortKind, ProfileDraft};
use crate::protocols::Registry;
use crate::views::{CaptureState, EditorState, ScenarioState, StatefulState};

const STORAGE_KEY: &str = "ferotrx-gui";
/// The forms of the last session (a workspace without servers and ports).
const FORMS_KEY: &str = "ferotrx-gui-forms";
const WORKSPACE_KEY: &str = "ferotrx-gui-workspace";
/// The theme: colours, widget style, text sizes.
const THEME_KEY: &str = "ferotrx-gui-theme";
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
    /// `bench.start`: show the run.
    BenchStarted,
    /// `y1564.start`: show the run.
    Y1564Started,
    /// `profile.load` of a multi-server group's member.
    GroupLoaded { member: usize },
    /// A start of a group's member.
    GroupStarted { member: usize },
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

/// One sample of a flow's loss and latency, for the receive charts.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct FlowPoint {
    /// Seconds since the GUI started.
    pub t: f64,
    /// Packets lost in this interval, as a percentage of those expected in it.
    pub loss_pct: f64,
    /// Lost so far, as a percentage of all expected.
    pub total_loss_pct: f64,
    /// Packets out of order and duplicates per second in this interval.
    pub reordered_ps: f64,
    pub duplicates_ps: f64,
    /// Received per second in this interval.
    pub rx_ps: f64,
    /// Latency of the packets of this interval: their average (µs).
    pub avg_us: Option<f64>,
    /// Since the start: percentiles, maximum, and the smoothed jitter (µs).
    pub p50_us: Option<f64>,
    pub p99_us: Option<f64>,
    pub p999_us: Option<f64>,
    pub max_us: Option<f64>,
    pub jitter_us: Option<f64>,
}

/// Loss and latency of one flow over time: a stream of a run with a
/// receiver, or a flow a receiver (`rx.start`) sees.
#[derive(Debug, Default)]
pub struct FlowHistory {
    pub label: String,
    pub points: VecDeque<FlowPoint>,
    last: Option<(f64, FlowCounters)>,
}

impl FlowHistory {
    pub fn add(&mut self, t: f64, f: &FlowCounters) {
        if let Some((t0, f0)) = &self.last {
            let dt = t - t0;
            if dt <= 0.05 {
                return;
            }
            if f.rx < f0.rx || f.lost + f.rx < f0.lost + f0.rx {
                // A new run under the same name: start again.
                self.points.clear();
            } else {
                self.points.push_back(flow_point(t, dt, f0, f));
                if self.points.len() > HISTORY {
                    self.points.pop_front();
                }
            }
        }
        self.last = Some((t, f.clone()));
    }
}

/// The figures of the interval between two samples of a flow's counters.
pub fn flow_point(t: f64, dt: f64, a: &FlowCounters, b: &FlowCounters) -> FlowPoint {
    let expected = |f: &FlowCounters| f.tx.unwrap_or(f.rx + f.lost);
    let d_exp = expected(b).saturating_sub(expected(a));
    let d_rx = b.rx.saturating_sub(a.rx);
    let d_lost = b.lost.saturating_sub(a.lost);
    let loss_pct = if d_exp > 0 {
        (d_lost as f64 * 100.0 / d_exp as f64).min(100.0)
    } else {
        0.0
    };
    // The average of this interval's packets, from the two running averages.
    let avg_us = match (a.latency.avg_us, b.latency.avg_us) {
        (Some(x), Some(y)) if d_rx > 0 => {
            Some(((y * b.rx as f64 - x * a.rx as f64) / d_rx as f64).max(0.0))
        }
        (None, Some(y)) if d_rx > 0 => Some(y),
        _ => None,
    };
    FlowPoint {
        t,
        loss_pct,
        total_loss_pct: b.loss_pct,
        reordered_ps: b.out_of_order.saturating_sub(a.out_of_order) as f64 / dt,
        duplicates_ps: b.duplicates.saturating_sub(a.duplicates) as f64 / dt,
        rx_ps: d_rx as f64 / dt,
        avg_us,
        p50_us: b.latency.p50_us,
        p99_us: b.latency.p99_us,
        p999_us: b.latency.p999_us,
        max_us: b.latency.max_us,
        jitter_us: b.latency.jitter_us,
    }
}

pub struct ServerState {
    pub settings: ConnSettings,
    pub conn: Option<Connection>,
    pub status: Status,
    pub info: Option<ServerInfo>,
    /// The server's clock minus this machine's, in seconds, when it tells
    /// the time: runs of a group start together by it.
    pub clock_offset: Option<f64>,
    pub interfaces: Vec<InterfaceEntry>,
    pub snap: Snapshot,
    /// Rate history per run (`run:3`, `tcp:1`, ...).
    pub history: BTreeMap<String, RateHistory>,
    /// Loss and latency history per flow (`run:3/stream`, `rx:4/7`).
    pub flows: BTreeMap<String, FlowHistory>,
    pub pending: HashMap<u64, Pending>,
    /// The stream run each port started last.
    pub port_runs: BTreeMap<String, u64>,
    /// The server's lab router, once `lab.get` answered (older servers have none).
    pub lab: Option<LabInfo>,
    /// Why the last `lab.start` or `lab.stop` failed.
    pub lab_error: Option<String>,
    /// The server process, for a server the GUI started ("This computer").
    pub local: Option<crate::local::LocalServer>,
}

impl ServerState {
    /// True when the server runs on this computer, so its files are this
    /// computer's: a loopback address, and (from 0.34 servers) the same host
    /// name and operating system. 127.0.0.1 forwarded into a virtual machine
    /// is a loopback address but another computer.
    pub fn is_local(&self) -> bool {
        self.settings.is_local()
            && self
                .info
                .as_ref()
                .and_then(|i| i.same_machine())
                .unwrap_or(true)
    }

    pub fn new(settings: ConnSettings) -> Self {
        Self {
            settings,
            conn: None,
            status: Status::Disconnected,
            info: None,
            clock_offset: None,
            interfaces: Vec::new(),
            snap: Snapshot::default(),
            history: BTreeMap::new(),
            flows: BTreeMap::new(),
            pending: HashMap::new(),
            port_runs: BTreeMap::new(),
            lab: None,
            lab_error: None,
            local: None,
        }
    }

    /// Can this server build the lab router? Not on Windows or macOS, where
    /// there are no network namespaces: there the GUI doesn't offer it.
    pub fn lab_possible(&self) -> bool {
        self.info
            .as_ref()
            .and_then(|i| i.os.as_deref())
            .is_none_or(|os| os == "linux")
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Tab {
    #[default]
    Streams,
    Stateful,
    Apps,
    Capture,
    Scenario,
    Bench,
    Y1564,
    Group,
    Charts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
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
    pub groups: crate::views::GroupsState,
    pub apps: crate::views::AppsState,
    pub bench: crate::views::BenchState,
    pub y1564: crate::views::Y1564State,
    pub log: Vec<LogLine>,
    pub next_tag: u64,
    pub started: Instant,
    /// The "add server" dialog, while open.
    pub add_server: Option<ConnSettings>,
    /// The file dialog, while open.
    pub files: crate::files::Dialogs,
    /// The lab router window, while open.
    pub lab_form: Option<crate::views::LabForm>,
    /// The workspace file last opened or saved.
    pub workspace_path: Option<String>,
    /// A layout from a workspace file, applied at the start of the next frame.
    pub pending_layout: Option<String>,
    /// The theme and the Appearance window.
    pub appearance: crate::theme::Appearance,
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
    /// A workspace file to open (before the other options).
    pub workspace: Option<String>,
    /// A theme file (TOML) to use instead of the saved theme.
    pub theme: Option<String>,
}

impl FeroApp {
    pub fn new(cc: &eframe::CreationContext<'_>, opts: Options) -> Self {
        let work: Workspace = cc
            .storage
            .and_then(|s| eframe::get_value(s, STORAGE_KEY))
            .unwrap_or_default();
        crate::fonts::install(&cc.egui_ctx);
        let forms: Option<crate::workspace::WorkspaceFile> =
            cc.storage.and_then(|s| eframe::get_value(s, FORMS_KEY));
        let path: Option<String> = cc
            .storage
            .and_then(|s| eframe::get_value(s, WORKSPACE_KEY))
            .flatten();
        let mut app = Self::with_workspace(cc.egui_ctx.clone(), work, Options::default());
        if let Some(t) = cc.storage.and_then(|s| eframe::get_value(s, THEME_KEY)) {
            app.appearance.theme = t;
        }
        if let Some(f) = forms {
            app.restore_forms(f);
        }
        if app.workspace_path.is_none() {
            app.workspace_path = path;
        }
        app.apply_options(opts);
        app
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
            groups: Default::default(),
            apps: Default::default(),
            bench: Default::default(),
            y1564: Default::default(),
            log: Vec::new(),
            next_tag: 1,
            started: Instant::now(),
            add_server: None,
            files: Default::default(),
            lab_form: None,
            workspace_path: None,
            pending_layout: None,
            appearance: Default::default(),
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
        app.apply_options(opts);
        app
    }

    /// Does what the command line asked for: a workspace, servers to
    /// connect, a port and profile, a scenario, a capture.
    pub fn apply_options(&mut self, opts: Options) {
        let app = self;
        if let Some(path) = &opts.theme {
            app.appearance.open_file(std::path::Path::new(path));
            if let Some(Err(e)) = app.appearance.status.clone() {
                app.error("", e);
            }
        }
        if let Some(path) = &opts.workspace {
            app.open_workspace(std::path::Path::new(path));
        }
        if app.servers.is_empty() && opts.connect.is_empty() {
            // A first start: this computer, when the server program is here.
            app.servers
                .push(ServerState::new(if crate::local::find_server().is_some() {
                    ConnSettings::this_computer()
                } else {
                    ConnSettings::default()
                }));
        }
        for s in opts.connect {
            let i = match app
                .servers
                .iter()
                .position(|x| x.settings.address() == s.address())
            {
                Some(i) => {
                    // A local server keeps its folders.
                    if !s.local {
                        app.servers[i].settings = s;
                    }
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
    }

    /// The forms of the last session, without its servers and ports.
    fn restore_forms(&mut self, f: crate::workspace::WorkspaceFile) {
        self.stateful = f.stateful;
        self.scenario = f.scenario;
        self.groups = f.groups;
        self.apps = f.apps;
        self.bench = f.bench;
        self.y1564 = f.y1564;
        self.tab = f.view.tab;
        self.bottom = f.view.bottom;
        if !f.capture.path.is_empty() {
            self.capture.path = f.capture.path;
        }
    }

    // ----- connections -----

    pub fn connect(&mut self, i: usize) {
        let ctx = self.ctx.clone();
        let mut settings = self.servers[i].settings.clone();
        if settings.local {
            // Start this computer's server first; the worker waits for it.
            self.servers[i].local = None;
            let folders = crate::local::parse_folders(&settings.folders);
            match crate::local::LocalServer::start(&folders) {
                Ok(l) => {
                    settings.token = l.token.clone();
                    settings.launch = Some(l.port_file.clone());
                    let what = if l.elevated {
                        "starting the local server as administrator (Npcap is for administrators only)"
                    } else {
                        "starting the local server"
                    };
                    self.info(&settings.addr, what);
                    self.servers[i].local = Some(l);
                }
                Err(e) => {
                    let s = &mut self.servers[i];
                    s.status = Status::Failed(e.clone());
                    self.error(&settings.addr, e);
                    return;
                }
            }
        }
        let s = &mut self.servers[i];
        s.status = Status::Connecting;
        s.pending.clear();
        s.conn = Some(Connection::open(
            settings,
            Duration::from_millis(1000),
            move || ctx.request_repaint(),
        ));
    }

    pub fn disconnect(&mut self, i: usize) {
        let s = &mut self.servers[i];
        s.conn = None;
        s.status = Status::Disconnected;
        s.pending.clear();
        // A server the GUI started stops with the connection.
        s.local = None;
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
            if let Some(why) = self.servers[i].local.as_mut().and_then(|l| l.ended()) {
                let s = &mut self.servers[i];
                s.local = None;
                s.conn = None;
                s.pending.clear();
                s.status = Status::Failed(why.clone());
                let name = s.settings.addr.clone();
                self.error(&name, why);
                continue;
            }
            let events = match &self.servers[i].conn {
                Some(c) => c.events(),
                None => continue,
            };
            for e in events {
                self.handle(i, e, now);
            }
        }
        self.sample_group();
    }

    fn handle(&mut self, i: usize, e: Event, now: f64) {
        let name = self.servers[i].settings.addr.clone();
        match e {
            Event::Connected {
                info,
                interfaces,
                clock_offset,
            } => {
                let s = &mut self.servers[i];
                s.clock_offset = clock_offset;
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
                s.info = Some(*info);
                s.interfaces = interfaces;
                s.status = Status::Connected;
                self.info(&name, what);
                self.call(i, "lab.get", Value::Null, Pending::Lab(String::new()));
            }
            Event::Closed(err) => {
                let s = &mut self.servers[i];
                s.conn = None;
                s.local = None;
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
                    for st in &r.streams {
                        if let Some(f) = &st.latency {
                            let h = s
                                .flows
                                .entry(format!("run:{}/{}", r.id, st.name))
                                .or_default();
                            h.label = format!("run {} {}", r.id, st.name);
                            if r.state.is_running() || h.points.is_empty() {
                                h.add(now, f);
                            }
                        }
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
                    for f in &r.flows {
                        let h = s
                            .flows
                            .entry(format!("rx:{}/{}", r.id, f.flow))
                            .or_default();
                        h.label = format!("rx {} flow {}", r.id, f.flow);
                        if r.state.is_running() || h.points.is_empty() {
                            h.add(now, f);
                        }
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
                s.flows.retain(|k, _| {
                    k.split_once('/')
                        .is_some_and(|(run, _)| alive.iter().any(|a| a == run))
                });
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
                    (Pending::GroupLoaded { member }, r) => {
                        self.group_loaded(member, r.map(drop).map_err(|e| e.to_string()))
                    }
                    (Pending::GroupStarted { member }, r) => {
                        self.group_started(member, r.map_err(|e| e.to_string()))
                    }
                    (Pending::ScenarioChecked, Ok(v)) => {
                        self.scenario.checked = Some(
                            serde_json::from_value::<ferotrx_ctl::protocol::ScenarioInfo>(v)
                                .map_err(|e| e.to_string()),
                        );
                    }
                    (Pending::BenchStarted, Ok(v)) => {
                        match serde_json::from_value::<ferotrx_ctl::protocol::BenchRunInfo>(v) {
                            Ok(r) => {
                                self.bench.run = Some(r.id);
                                let s = &mut self.servers[i];
                                s.snap.bench.retain(|x| x.id != r.id);
                                s.snap.bench.push(r.clone());
                                self.info(
                                    &name,
                                    format!("benchmark {} started as run {}", r.profile, r.id),
                                );
                            }
                            Err(e) => self.error(&name, format!("bench.start: {e}")),
                        }
                    }
                    (Pending::Y1564Started, Ok(v)) => {
                        match serde_json::from_value::<ferotrx_ctl::protocol::Y1564RunInfo>(v) {
                            Ok(r) => {
                                self.y1564.run = Some(r.id);
                                let s = &mut self.servers[i];
                                s.snap.y1564.retain(|x| x.id != r.id);
                                s.snap.y1564.push(r.clone());
                                self.info(
                                    &name,
                                    format!("Y.1564 test {} started as run {}", r.profile, r.id),
                                );
                            }
                            Err(e) => self.error(&name, format!("y1564.start: {e}")),
                        }
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
                                // It may have built the lab router.
                                self.call(i, "lab.get", Value::Null, Pending::Lab(String::new()));
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
                            Pending::BenchStarted => format!("benchmark: {e}"),
                            Pending::Y1564Started => format!("Y.1564: {e}"),
                            Pending::ScenarioChecked | Pending::ScenarioStarted => {
                                format!("scenario: {e}")
                            }
                            Pending::GroupLoaded { .. } | Pending::GroupStarted { .. } => {
                                unreachable!("handled above")
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
        if self.servers[i].is_local() && !work.base_dir.is_empty() {
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
        self.appearance.update(ctx);
        self.apply_pending_layout(ctx);
        self.poll();
        self.ui(ctx);
        // Keep the charts moving while something runs.
        if self.servers.iter().any(|s| s.status == Status::Connected) {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        self.remember_view();
        eframe::set_value(storage, STORAGE_KEY, &self.work);
        // The forms too, as a workspace without a layout (eframe keeps that).
        let mut w = self.workspace_file(None);
        w.work = Workspace::default();
        eframe::set_value(storage, FORMS_KEY, &w);
        eframe::set_value(storage, WORKSPACE_KEY, &self.workspace_path);
        eframe::set_value(storage, THEME_KEY, &self.appearance.theme);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Stop the servers the GUI started (they would also notice it end).
        for s in &mut self.servers {
            s.conn = None;
            s.local = None;
        }
    }
}
