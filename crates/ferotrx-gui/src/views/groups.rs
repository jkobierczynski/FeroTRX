//! The Multi-server tab: runs on several `ferotrx serve` servers at once,
//! started and stopped together, with combined counters and rates.
//!
//! A group has members, each a server and what it runs there: a port's
//! streams (as built in the Streams tab), a TCP profile or a UDP profile.
//! Starting the group first loads every member's streams on its server,
//! then sends every start at once, so the runs begin within a poll of each
//! other; stopping sends every stop at once. The counters of the members'
//! runs are added up, and the chart has each member's rate and the total.

use std::collections::{BTreeMap, VecDeque};

use eframe::egui::{self, Color32, RichText};
use egui_plot::{Legend, Line, Plot, PlotPoints};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::app::{FeroApp, Pending, Status};
use crate::model::PortKind;
use crate::packet_view::state_color;
use crate::views::stateful::{Kind, StatefulState};

/// What a member runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberKind {
    /// The streams of a port, as the Streams tab has them.
    #[default]
    Streams,
    Tcp,
    Udp,
}

impl MemberKind {
    /// The method family of its runs.
    pub fn method(self) -> &'static str {
        match self {
            MemberKind::Streams => "run",
            MemberKind::Tcp => "tcp",
            MemberKind::Udp => "udp",
        }
    }

    fn label(self) -> &'static str {
        match self {
            MemberKind::Streams => "Streams of a port",
            MemberKind::Tcp => "TCP profile",
            MemberKind::Udp => "UDP profile",
        }
    }
}

/// One server's part of a group.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Member {
    pub enabled: bool,
    /// The server's address, as [`crate::conn::ConnSettings::address`] gives it.
    pub server: String,
    pub kind: MemberKind,
    /// Streams: the port whose streams it sends.
    pub port: Option<PortKind>,
    /// TCP and UDP: the profile and what replaces its values.
    pub stateful: StatefulState,
    /// The run it started last.
    #[serde(skip)]
    pub run: Option<u64>,
    /// Why its last start failed.
    #[serde(skip)]
    pub error: Option<String>,
}

impl Default for Member {
    fn default() -> Self {
        Self {
            enabled: true,
            server: String::new(),
            kind: MemberKind::Streams,
            port: None,
            stateful: StatefulState::default(),
            run: None,
            error: None,
        }
    }
}

/// The counters of one member's run, as the group adds them up.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MemberStats {
    pub running: bool,
    pub failed: bool,
    pub state: String,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub elapsed_s: f64,
    /// Average send rates since the run started.
    pub pps: f64,
    pub mbps: f64,
    /// TCP connections or UDP transactions: started/sent, completed/answered,
    /// failed (reset, timed out, mismatched).
    pub sessions: u64,
    pub completed: u64,
    pub failed_sessions: u64,
    pub error: Option<String>,
}

impl std::ops::AddAssign<&MemberStats> for MemberStats {
    fn add_assign(&mut self, o: &MemberStats) {
        self.running |= o.running;
        self.failed |= o.failed;
        self.tx_packets += o.tx_packets;
        self.tx_bytes += o.tx_bytes;
        self.rx_packets += o.rx_packets;
        self.elapsed_s = self.elapsed_s.max(o.elapsed_s);
        self.pps += o.pps;
        self.mbps += o.mbps;
        self.sessions += o.sessions;
        self.completed += o.completed;
        self.failed_sessions += o.failed_sessions;
    }
}

/// Where a group stands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Phase {
    #[default]
    Idle,
    /// Waiting for the members' streams to load before starting them all.
    Loading { waiting: usize },
}

/// Seconds from the start calls of a group to the instant its runs start:
/// time for every server to open its interfaces and answer.
pub const GROUP_LEAD_S: f64 = 1.0;

/// The tab's state: the members, and the rates over time.
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GroupsState {
    pub members: Vec<Member>,
    #[serde(skip)]
    pub phase: Phase,
    /// Starts to send once every load answered: (member, method, params).
    #[serde(skip)]
    pub queued: Vec<(usize, String, Value)>,
    /// (seconds, total packets/s) and per member, measured between polls.
    #[serde(skip)]
    pub total: VecDeque<[f64; 2]>,
    #[serde(skip)]
    pub per_member: BTreeMap<usize, VecDeque<[f64; 2]>>,
    #[serde(skip)]
    last: BTreeMap<usize, (f64, u64)>,
}

/// Points kept in the group chart.
const HISTORY: usize = 600;

impl FeroApp {
    fn server_index(&self, addr: &str) -> Option<usize> {
        self.servers
            .iter()
            .position(|s| s.settings.address() == addr)
    }

    /// The counters of member `m`'s last run, if its server still has it.
    pub fn member_stats(&self, m: &Member) -> Option<MemberStats> {
        let s = &self.servers[self.server_index(&m.server)?];
        let id = m.run?;
        let state = |st: ferotrx_ctl::protocol::RunState, e: &Option<String>| MemberStats {
            running: st.is_running(),
            failed: st == ferotrx_ctl::protocol::RunState::Failed,
            state: format!("{st:?}").to_lowercase(),
            error: e.clone(),
            ..Default::default()
        };
        Some(match m.kind {
            MemberKind::Streams => {
                let r = s.snap.runs.iter().find(|r| r.id == id)?;
                MemberStats {
                    tx_packets: r.total.packets,
                    tx_bytes: r.total.bytes,
                    rx_packets: r.rx.as_ref().map_or(0, |x| x.packets),
                    elapsed_s: r.total.elapsed_s,
                    pps: r.total.pps,
                    mbps: r.total.mbps,
                    ..state(r.state, &r.error)
                }
            }
            MemberKind::Tcp => {
                let r = s.snap.tcp.iter().find(|r| r.id == id)?;
                let c = &r.client;
                MemberStats {
                    tx_packets: r.tx_packets,
                    tx_bytes: r.tx_bytes,
                    rx_packets: r.rx_packets,
                    elapsed_s: r.elapsed_s,
                    pps: per_s(r.tx_packets, r.elapsed_s),
                    mbps: per_s(r.tx_bytes * 8, r.elapsed_s) / 1e6,
                    sessions: c.started,
                    completed: c.completed,
                    failed_sessions: c.reset + c.timed_out + c.mismatched,
                    ..state(r.state, &r.error)
                }
            }
            MemberKind::Udp => {
                let r = s.snap.udp.iter().find(|r| r.id == id)?;
                let c = &r.client;
                MemberStats {
                    tx_packets: r.tx_packets,
                    tx_bytes: r.tx_bytes,
                    rx_packets: r.rx_packets,
                    elapsed_s: r.elapsed_s,
                    pps: per_s(r.tx_packets, r.elapsed_s),
                    mbps: per_s(r.tx_bytes * 8, r.elapsed_s) / 1e6,
                    sessions: c.sent,
                    completed: c.answered,
                    failed_sessions: c.timed_out + c.mismatched,
                    ..state(r.state, &r.error)
                }
            }
        })
    }

    /// Starts every enabled member: streams are loaded first, then all
    /// the starts go out, for one instant [`GROUP_LEAD_S`] later.
    pub fn start_group(&mut self) {
        let mut loads = Vec::new();
        let mut starts = Vec::new();
        let mut problems = Vec::new();
        for (n, m) in self.groups.members.iter().enumerate() {
            if !m.enabled {
                continue;
            }
            let Some(i) = self.server_index(&m.server) else {
                problems.push(format!("member {}: pick a server", n + 1));
                continue;
            };
            let s = &self.servers[i];
            if s.status != Status::Connected || !s.can_operate() {
                problems.push(format!(
                    "member {}: {} is not connected with the operator role",
                    n + 1,
                    s.settings.addr
                ));
                continue;
            }
            match m.kind {
                MemberKind::Streams => {
                    let Some(port) = m.port.clone() else {
                        problems.push(format!("member {}: pick a port", n + 1));
                        continue;
                    };
                    let work = self
                        .work
                        .ports
                        .get(&self.port_key(i, &port))
                        .cloned()
                        .unwrap_or_default();
                    if !work.profile.streams.iter().any(|s| s.enabled) {
                        problems.push(format!(
                            "member {}: {} on {} has no enabled streams",
                            n + 1,
                            port.label(),
                            s.settings.addr
                        ));
                        continue;
                    }
                    let name = format!("group-{}-{}", n + 1, port.profile_name());
                    let params =
                        crate::model::start_params(&port, &work.config, &name, &self.work.file_out);
                    let mut load =
                        serde_json::json!({ "name": name, "toml": work.profile.to_toml(true) });
                    if s.is_local() && !work.base_dir.is_empty() {
                        load["base_dir"] = work.base_dir.clone().into();
                    }
                    loads.push((n, i, load));
                    starts.push((n, "run.start".to_string(), params));
                }
                MemberKind::Tcp | MemberKind::Udp => {
                    let mut st = m.stateful.clone();
                    st.kind = if m.kind == MemberKind::Tcp {
                        Kind::Tcp
                    } else {
                        Kind::Udp
                    };
                    st.check = None;
                    match st.params_for(s.is_local()) {
                        Ok(p) => starts.push((n, format!("{}.start", m.kind.method()), p)),
                        Err(e) => problems.push(format!("member {}: {e}", n + 1)),
                    }
                }
            }
        }
        for p in &problems {
            self.error("", format!("group: {p}"));
        }
        if !problems.is_empty() {
            return;
        }
        if starts.is_empty() {
            self.error("", "group: no members to start");
            return;
        }
        for m in &mut self.groups.members {
            m.error = None;
        }
        self.groups.queued = starts;
        self.groups.total.clear();
        self.groups.per_member.clear();
        self.groups.last.clear();
        if loads.is_empty() {
            self.fire_group();
        } else {
            self.groups.phase = Phase::Loading {
                waiting: loads.len(),
            };
            for (n, i, load) in loads {
                self.call(i, "profile.load", load, Pending::GroupLoaded { member: n });
            }
        }
    }

    /// A member's streams loaded (or not): start them all when none is left.
    pub fn group_loaded(&mut self, member: usize, result: Result<(), String>) {
        if let Err(e) = result {
            if let Some(m) = self.groups.members.get_mut(member) {
                m.error = Some(e.clone());
            }
            self.error(
                "",
                format!("group: member {}: {e}; nothing started", member + 1),
            );
            self.groups.phase = Phase::Idle;
            self.groups.queued.clear();
            return;
        }
        if let Phase::Loading { waiting } = &mut self.groups.phase {
            *waiting = waiting.saturating_sub(1);
            if *waiting == 0 {
                self.fire_group();
            }
        }
    }

    fn fire_group(&mut self) {
        self.groups.phase = Phase::Idle;
        let starts = std::mem::take(&mut self.groups.queued);
        let n = starts.len();
        // Every run starts at one instant, in each server's own clock;
        // servers before 0.31.0 start when the call arrives.
        let at = ferotrx_core::unix_seconds(std::time::SystemTime::now()) + GROUP_LEAD_S;
        let mut timed = 0;
        for (member, method, mut params) in starts {
            let Some(i) = self
                .groups
                .members
                .get(member)
                .and_then(|m| self.server_index(&m.server))
            else {
                continue;
            };
            if let (Some(offset), Some(p)) = (self.servers[i].clock_offset, params.as_object_mut())
            {
                p.insert("start_at".into(), (at + offset).into());
                timed += 1;
            }
            self.call(i, &method, params, Pending::GroupStarted { member });
        }
        if timed == n {
            self.info(
                "",
                format!("group: {n} runs start together in {GROUP_LEAD_S} s"),
            );
        } else {
            self.info(
                "",
                format!(
                    "group: {n} runs started; {} on servers before 0.31.0 start as the call arrives",
                    n - timed
                ),
            );
        }
    }

    /// A member's run started: remember its id.
    pub fn group_started(&mut self, member: usize, result: Result<Value, String>) {
        let Some(m) = self.groups.members.get_mut(member) else {
            return;
        };
        match result.map(|v| v.get("id").and_then(Value::as_u64)) {
            Ok(Some(id)) => {
                m.run = Some(id);
                m.error = None;
            }
            Ok(None) => m.error = Some("the server answered without a run id".into()),
            Err(e) => {
                m.error = Some(e.clone());
                self.error("", format!("group: member {}: {e}", member + 1));
            }
        }
        let addr = self.groups.members[member].server.clone();
        if let Some(i) = self.server_index(&addr) {
            if let Some(c) = &self.servers[i].conn {
                c.send(crate::conn::Request::Refresh);
            }
        }
    }

    pub fn stop_group(&mut self) {
        let mut stops = Vec::new();
        for m in &self.groups.members {
            if let (Some(id), Some(i)) = (m.run, self.server_index(&m.server)) {
                if self.member_stats(m).is_some_and(|s| s.running) {
                    stops.push((i, m.kind.method(), id));
                }
            }
        }
        for (i, kind, id) in stops {
            self.stop_run(i, kind, id);
        }
    }

    /// Samples the members' packet counters for the group chart.
    pub fn sample_group(&mut self) {
        let now = self.started.elapsed().as_secs_f64();
        let stats: Vec<(usize, MemberStats)> = self
            .groups
            .members
            .iter()
            .enumerate()
            .filter_map(|(n, m)| self.member_stats(m).map(|s| (n, s)))
            .collect();
        if !stats.iter().any(|(_, s)| s.running) {
            // Keep the last values in the history to look at.
            self.groups.last.clear();
            return;
        }
        let g = &mut self.groups;
        let mut total = 0.0;
        let mut any = false;
        for (n, s) in &stats {
            if let Some((t0, p0)) = g.last.get(n).copied() {
                let dt = now - t0;
                if dt < 0.5 {
                    // Not a new poll yet.
                    return;
                }
                let pps = s.tx_packets.saturating_sub(p0) as f64 / dt;
                total += pps;
                any = true;
                let h = g.per_member.entry(*n).or_default();
                h.push_back([now, pps]);
                if h.len() > HISTORY {
                    h.pop_front();
                }
            }
        }
        for (n, s) in &stats {
            g.last.insert(*n, (now, s.tx_packets));
        }
        if any {
            g.total.push_back([now, total]);
            if g.total.len() > HISTORY {
                g.total.pop_front();
            }
        }
    }

    pub fn groups_tab(&mut self, ui: &mut egui::Ui) {
        let servers: Vec<(String, String, Vec<PortKind>, bool)> = self
            .servers
            .iter()
            .map(|s| {
                (
                    s.settings.address(),
                    s.settings.addr.clone(),
                    s.ports(),
                    s.status == Status::Connected && s.can_operate(),
                )
            })
            .collect();
        let stats: Vec<Option<MemberStats>> = self
            .groups
            .members
            .iter()
            .map(|m| self.member_stats(m))
            .collect();
        let streams_of = |addr: &str, port: &PortKind| -> usize {
            self.servers
                .iter()
                .position(|s| s.settings.address() == addr)
                .and_then(|i| self.work.ports.get(&self.port_key(i, port)))
                .map_or(0, |w| {
                    w.profile.streams.iter().filter(|s| s.enabled).count()
                })
        };
        let counts: Vec<usize> = self
            .groups
            .members
            .iter()
            .map(|m| m.port.as_ref().map_or(0, |p| streams_of(&m.server, p)))
            .collect();
        let running = stats.iter().flatten().any(|s| s.running);
        let loading = matches!(self.groups.phase, Phase::Loading { .. });
        let mut start = false;
        let mut stop = false;
        let mut remove = None;

        ui.heading("Runs on several servers");
        ui.label(
            RichText::new(
                "Each member is a server and what it runs: a port's streams (from the Streams tab), \
                 or a TCP or UDP profile. Start sends every member's run at once; the counters \
                 below add them up.",
            )
            .weak(),
        );
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !loading && !self.groups.members.is_empty(),
                    egui::Button::new(RichText::new("▶ Start all").strong()),
                )
                .clicked()
            {
                start = true;
            }
            if ui
                .add_enabled(running, egui::Button::new("■ Stop all"))
                .clicked()
            {
                stop = true;
            }
            if ui.button("+ Member").clicked() {
                let server = servers
                    .get(self.sel_server)
                    .map(|s| s.0.clone())
                    .unwrap_or_default();
                self.groups.members.push(Member {
                    server,
                    port: self.sel_port.clone(),
                    ..Default::default()
                });
            }
            if ui
                .button("+ Every connected server")
                .on_hover_text("A member per connected server, sending the streams of the port selected on the left")
                .clicked()
            {
                for s in &servers {
                    if s.3 && !self.groups.members.iter().any(|m| m.server == s.0) {
                        self.groups.members.push(Member {
                            server: s.0.clone(),
                            port: self.sel_port.clone().or(Some(PortKind::Null)),
                            ..Default::default()
                        });
                    }
                }
            }
            if loading {
                ui.spinner();
                ui.label("loading the streams on every server…");
            }
        });
        ui.separator();

        let total = {
            let mut t = MemberStats::default();
            for s in stats.iter().flatten() {
                t += s;
            }
            t
        };
        let h = ui.available_height();
        egui::Panel::top("group-members")
            .resizable(true)
            .default_size(h * 0.5)
            .min_size(120.0)
            .frame(egui::Frame::NONE)
            .show(ui, |ui| {
                ui.set_min_height(ui.available_height());
                egui::ScrollArea::both().id_salt("group-scroll").show(ui, |ui| {
                    egui::Grid::new("group-grid")
                        .striped(true)
                        .spacing([10.0, 4.0])
                        .show(ui, |ui| {
                            for t in ["", "Server", "Runs", "What", "State", "Packets", "pps", "Mbit/s", "Sessions", "Done", "Failed", ""] {
                                ui.strong(t);
                            }
                            ui.end_row();
                            for (n, m) in self.groups.members.iter_mut().enumerate() {
                                ui.checkbox(&mut m.enabled, "");
                                let shown = servers
                                    .iter()
                                    .find(|s| s.0 == m.server)
                                    .map_or(m.server.clone(), |s| s.1.clone());
                                egui::ComboBox::from_id_salt(("gm-server", n))
                                    .selected_text(if shown.is_empty() { "pick…".into() } else { shown })
                                    .show_ui(ui, |ui| {
                                        for s in &servers {
                                            let label = if s.3 { s.1.clone() } else { format!("{} (not connected)", s.1) };
                                            ui.selectable_value(&mut m.server, s.0.clone(), label);
                                        }
                                    });
                                egui::ComboBox::from_id_salt(("gm-kind", n))
                                    .selected_text(m.kind.label())
                                    .show_ui(ui, |ui| {
                                        for k in [MemberKind::Streams, MemberKind::Tcp, MemberKind::Udp] {
                                            ui.selectable_value(&mut m.kind, k, k.label());
                                        }
                                    });
                                ui.horizontal(|ui| match m.kind {
                                    MemberKind::Streams => {
                                        let ports = servers
                                            .iter()
                                            .find(|s| s.0 == m.server)
                                            .map(|s| s.2.clone())
                                            .unwrap_or_default();
                                        egui::ComboBox::from_id_salt(("gm-port", n))
                                            .selected_text(m.port.as_ref().map_or("port…".into(), |p| p.label()))
                                            .show_ui(ui, |ui| {
                                                for p in ports {
                                                    let l = p.label();
                                                    ui.selectable_value(&mut m.port, Some(p), l);
                                                }
                                            });
                                        ui.weak(format!("{} streams", counts[n]))
                                            .on_hover_text("Build them in the Streams tab, on that server's port");
                                    }
                                    MemberKind::Tcp | MemberKind::Udp => {
                                        ui.add(egui::TextEdit::singleline(&mut m.stateful.path).hint_text("profile").desired_width(180.0));
                                        ui.checkbox(&mut m.stateful.upload, "from here")
                                            .on_hover_text("Upload the file from this computer; otherwise the path is on the server");
                                        ui.add(egui::TextEdit::singleline(&mut m.stateful.iface).hint_text("interface").desired_width(80.0));
                                        ui.add(egui::TextEdit::singleline(&mut m.stateful.rate).hint_text(if m.kind == MemberKind::Tcp { "cps" } else { "tps" }).desired_width(50.0));
                                        ui.add(egui::TextEdit::singleline(&mut m.stateful.duration).hint_text("duration").desired_width(60.0));
                                    }
                                });
                                let st = stats[n].as_ref();
                                match (st, &m.error) {
                                    (_, Some(e)) => {
                                        ui.colored_label(ui.visuals().error_fg_color, "error").on_hover_text(e);
                                    }
                                    (Some(s), None) => {
                                        let r = ui.colored_label(state_color(ui, s.running, s.failed), &s.state);
                                        if let Some(e) = &s.error {
                                            r.on_hover_text(e);
                                        }
                                    }
                                    (None, None) => {
                                        ui.weak("–");
                                    }
                                }
                                stat_cells(ui, st);
                                if ui.small_button("✕").on_hover_text("Remove the member").clicked() {
                                    remove = Some(n);
                                }
                                ui.end_row();
                            }
                            if !self.groups.members.is_empty() {
                                ui.label("");
                                ui.strong("Total");
                                ui.label("");
                                ui.label(format!("{} members", self.groups.members.iter().filter(|m| m.enabled).count()));
                                ui.colored_label(
                                    state_color(ui, total.running, total.failed),
                                    if total.running { "running" } else { "" },
                                );
                                stat_cells(ui, Some(&total));
                                ui.end_row();
                            }
                        });
                    if self.groups.members.is_empty() {
                        ui.weak("No members yet: connect to the servers (Add server… at the top right), then add a member for each.");
                    }
                });
            });
        let g = &self.groups;
        Plot::new("group-rate")
            .legend(Legend::default())
            .x_axis_label("seconds")
            .y_axis_label("packets/s")
            .include_y(0.0)
            .show(ui, |p| {
                for (n, pts) in &g.per_member {
                    let label = g.members.get(*n).map_or(format!("member {}", n + 1), |m| {
                        let s = servers
                            .iter()
                            .find(|s| s.0 == m.server)
                            .map_or(m.server.as_str(), |s| s.1.as_str());
                        format!("{} {}", n + 1, s)
                    });
                    p.line(Line::new(
                        label,
                        PlotPoints::from(pts.iter().copied().collect::<Vec<_>>()),
                    ));
                }
                if !g.total.is_empty() {
                    p.line(
                        Line::new(
                            "total",
                            PlotPoints::from(g.total.iter().copied().collect::<Vec<_>>()),
                        )
                        .color(Color32::from_rgb(0xd0, 0x60, 0x20))
                        .width(2.5_f32),
                    );
                }
            });
        if let Some(n) = remove {
            self.groups.members.remove(n);
            self.groups.per_member.clear();
        }
        if start {
            self.start_group();
        }
        if stop {
            self.stop_group();
        }
    }
}

fn per_s(n: u64, secs: f64) -> f64 {
    if secs > 0.0 {
        n as f64 / secs
    } else {
        0.0
    }
}

fn stat_cells(ui: &mut egui::Ui, s: Option<&MemberStats>) {
    match s {
        Some(s) => {
            ui.monospace(s.tx_packets.to_string());
            ui.monospace(format!("{:.0}", s.pps));
            ui.monospace(format!("{:.2}", s.mbps));
            ui.monospace(s.sessions.to_string());
            ui.monospace(s.completed.to_string());
            ui.monospace(s.failed_sessions.to_string());
        }
        None => {
            for _ in 0..6 {
                ui.label("");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totals_add_up() {
        let a = MemberStats {
            running: true,
            tx_packets: 10,
            pps: 5.0,
            sessions: 3,
            elapsed_s: 2.0,
            ..Default::default()
        };
        let b = MemberStats {
            failed: true,
            tx_packets: 7,
            pps: 1.5,
            completed: 2,
            elapsed_s: 4.0,
            ..Default::default()
        };
        let mut t = MemberStats::default();
        t += &a;
        t += &b;
        assert!(t.running && t.failed);
        assert_eq!(t.tx_packets, 17);
        assert_eq!(t.pps, 6.5);
        assert_eq!((t.sessions, t.completed), (3, 2));
        assert_eq!(t.elapsed_s, 4.0);
    }
}
