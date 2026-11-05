//! Statistics: a grid with a column per run and a row per counter, and
//! charts of the rates over time.

use eframe::egui::{self, RichText};
use egui_plot::{Legend, Line, Plot, PlotPoints};
use ferotrx_ctl::protocol::{
    FlowCounters, LatencyCounters, RunInfo, RunState, RxRunInfo, TcpRunInfo, UdpRunInfo,
};

use crate::app::{FeroApp, FlowHistory, FlowPoint};
use crate::packet_view::state_color;

/// One run as a column of the grid.
pub struct RunColumn {
    /// `run`, `tcp`, `udp` or `rx`: the method family.
    pub kind: &'static str,
    pub id: u64,
    pub title: String,
    pub state: RunState,
    pub error: Option<String>,
    pub rows: Vec<(String, String)>,
}

fn n(v: u64) -> String {
    // Thin groups of three digits, like 1 234 567.
    let s = v.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push('\u{2009}');
        }
        out.push(c);
    }
    out
}

fn us(v: Option<f64>) -> String {
    match v {
        Some(v) if v >= 1000.0 => format!("{:.2} ms", v / 1000.0),
        Some(v) => format!("{v:.1} µs"),
        None => "–".into(),
    }
}

fn latency_rows(prefix: &str, f: &FlowCounters, rows: &mut Vec<(String, String)>) {
    rows.push((format!("{prefix}received"), n(f.rx)));
    rows.push((
        format!("{prefix}lost"),
        format!("{} ({:.3}%)", n(f.lost), f.loss_pct),
    ));
    if f.out_of_order > 0 || f.duplicates > 0 {
        rows.push((
            format!("{prefix}reordered / dup"),
            format!("{} / {}", n(f.out_of_order), n(f.duplicates)),
        ));
    }
    lat_rows(prefix, &f.latency, rows);
}

/// A SIP run's calls: loss, jitter, round trip and the scores.
fn media_rows(m: &ferotrx_ctl::protocol::MediaCounters, rows: &mut Vec<(String, String)>) {
    rows.push(("calls' media streams".into(), n(m.streams)));
    rows.push((
        "RTP lost / late".into(),
        format!("{} ({:.2}%) / {}", n(m.lost), m.loss_pct, n(m.late)),
    ));
    if let Some(j) = &m.jitter {
        rows.push((
            "RTP jitter avg / max".into(),
            format!("{} / {}", us(j.avg_us), us(j.max_us)),
        ));
    }
    if let Some(r) = &m.rtt {
        rows.push(("RTP round trip".into(), us(r.avg_us)));
    }
    if let (Some(avg), Some(min)) = (m.mos_avg, m.mos_min) {
        rows.push(("MOS avg / worst".into(), format!("{avg:.2} / {min:.2}")));
    }
    if let (Some(avg), Some(min)) = (m.r_avg, m.r_min) {
        rows.push(("R avg / worst".into(), format!("{avg:.1} / {min:.1}")));
    }
}

fn lat_rows(prefix: &str, l: &LatencyCounters, rows: &mut Vec<(String, String)>) {
    rows.push((
        format!("{prefix}latency min/avg/max"),
        format!("{} / {} / {}", us(l.min_us), us(l.avg_us), us(l.max_us)),
    ));
    rows.push((
        format!("{prefix}latency p99 / jitter"),
        format!("{} / {}", us(l.p99_us), us(l.jitter_us)),
    ));
}

impl RunColumn {
    pub fn stream(r: &RunInfo) -> Self {
        let t = &r.total;
        let mut rows = vec![
            ("output".to_string(), r.output.clone()),
            ("profile".into(), r.profile.clone()),
            ("packets".into(), n(t.packets)),
            ("bytes".into(), n(t.bytes)),
            ("avg pps".into(), format!("{:.0}", t.pps)),
            ("avg Mbit/s".into(), format!("{:.2}", t.mbps)),
            ("send errors".into(), n(t.send_errors)),
            ("loops".into(), n(t.loops_completed)),
            ("elapsed".into(), format!("{:.1} s", t.elapsed_s)),
        ];
        if let Some(rx) = &r.rx {
            rows.push(("rx on".into(), rx.iface.clone()));
            rows.push(("rx packets".into(), n(rx.packets)));
        }
        for s in &r.streams {
            rows.push((format!("{}: packets", s.name), n(s.counters.packets)));
            if let Some(l) = &s.latency {
                latency_rows(&format!("{}: ", s.name), l, &mut rows);
            }
        }
        Self {
            kind: "run",
            id: r.id,
            title: format!("run {}", r.id),
            state: r.state,
            error: r.error.clone(),
            rows,
        }
    }

    pub fn tcp(r: &TcpRunInfo) -> Self {
        let c = &r.client;
        let mut rows = vec![
            ("program".to_string(), r.program.clone()),
            ("ports".into(), r.ports.join(", ")),
            ("cps".into(), format!("{:.1}", r.cps)),
            ("started".into(), n(c.started)),
            ("established".into(), n(c.established)),
            ("completed".into(), n(c.completed)),
            ("reset".into(), n(c.reset)),
            ("timed out".into(), n(c.timed_out)),
            ("mismatched".into(), n(c.mismatched)),
            ("active".into(), n(c.active)),
            (
                "retransmits".into(),
                n(c.retransmits + r.server.retransmits),
            ),
            (
                "tx / rx packets".into(),
                format!("{} / {}", n(r.tx_packets), n(r.rx_packets)),
            ),
            ("elapsed".into(), format!("{:.1} s", r.elapsed_s)),
        ];
        if let Some(l) = &c.connect_time {
            lat_rows("connect ", l, &mut rows);
        }
        if let Some(l) = &c.first_byte {
            lat_rows("first byte ", l, &mut rows);
        }
        for t in &r.templates {
            rows.push((
                format!("{}: completed", t.name),
                format!("{} of {}", n(t.client.completed), n(t.client.started)),
            ));
        }
        for h in &r.hosts {
            rows.push((format!("host {}", h.mac), h.state.clone()));
        }
        Self {
            kind: "tcp",
            id: r.id,
            title: format!("tcp {}", r.id),
            state: r.state,
            error: r.error.clone(),
            rows,
        }
    }

    pub fn udp(r: &UdpRunInfo) -> Self {
        let c = &r.client;
        let mut rows = vec![
            ("program".to_string(), r.program.clone()),
            ("ports".into(), r.ports.join(", ")),
            ("tps".into(), format!("{:.1}", r.tps)),
            ("sent".into(), n(c.sent)),
            ("answered".into(), n(c.answered)),
            ("timed out".into(), n(c.timed_out)),
            ("retries".into(), n(c.retries)),
            (
                "unmatched / mismatched".into(),
                format!("{} / {}", n(c.unmatched), n(c.mismatched)),
            ),
            ("active".into(), n(c.active)),
            (
                "tx / rx packets".into(),
                format!("{} / {}", n(r.tx_packets), n(r.rx_packets)),
            ),
            ("elapsed".into(), format!("{:.1} s", r.elapsed_s)),
        ];
        if let Some(l) = &c.response_time {
            lat_rows("response ", l, &mut rows);
        }
        if let Some(m) = c.app.as_ref().and_then(|a| a.media.as_ref()) {
            media_rows(m, &mut rows);
        }
        for t in &r.templates {
            rows.push((
                format!("{}: answered", t.name),
                format!("{} of {}", n(t.client.answered), n(t.client.sent)),
            ));
        }
        Self {
            kind: "udp",
            id: r.id,
            title: format!("udp {}", r.id),
            state: r.state,
            error: r.error.clone(),
            rows,
        }
    }

    pub fn rx(r: &RxRunInfo) -> Self {
        let c = &r.counters;
        let mut rows = vec![
            ("interface".to_string(), c.iface.clone()),
            ("packets".into(), n(c.packets)),
            ("bytes".into(), n(c.bytes)),
            ("elapsed".into(), format!("{:.1} s", c.elapsed_s)),
            ("flows".into(), r.flows.len().to_string()),
        ];
        for f in &r.flows {
            latency_rows(&format!("flow {}: ", f.flow), f, &mut rows);
        }
        Self {
            kind: "rx",
            id: r.id,
            title: format!("rx {}", r.id),
            state: r.state,
            error: r.error.clone(),
            rows,
        }
    }
}

/// Row labels in first-seen order across columns.
pub fn row_labels(cols: &[RunColumn]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for c in cols {
        for (l, _) in &c.rows {
            if !out.contains(l) {
                out.push(l.clone());
            }
        }
    }
    out
}

impl FeroApp {
    pub fn stats_grid(&mut self, ui: &mut egui::Ui) {
        let i = self.sel_server;
        let Some(s) = self.servers.get(i) else {
            return;
        };
        let groups: Vec<(&str, Vec<RunColumn>)> = vec![
            (
                "Stream runs",
                s.snap.runs.iter().map(RunColumn::stream).collect(),
            ),
            ("TCP runs", s.snap.tcp.iter().map(RunColumn::tcp).collect()),
            ("UDP runs", s.snap.udp.iter().map(RunColumn::udp).collect()),
            ("Receivers", s.snap.rx.iter().map(RunColumn::rx).collect()),
        ];
        let can = s.can_operate();
        if groups.iter().all(|(_, c)| c.is_empty()) {
            ui.weak(format!("No runs on {} yet.", s.settings.addr));
            return;
        }
        let mut act: Option<(bool, &'static str, u64)> = None; // (stop?, kind, id)
        egui::ScrollArea::both()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (title, cols) in &groups {
                    if cols.is_empty() {
                        continue;
                    }
                    ui.strong(*title);
                    let labels = row_labels(cols);
                    egui::Grid::new(("grid", *title))
                        .striped(true)
                        .spacing([16.0, 2.0])
                        .show(ui, |ui| {
                            ui.label("");
                            for c in cols {
                                ui.vertical(|ui| {
                                    ui.add(
                                        egui::Label::new(RichText::new(&c.title).strong())
                                            .wrap_mode(egui::TextWrapMode::Extend),
                                    );
                                    ui.horizontal(|ui| {
                                        let failed = c.state == RunState::Failed;
                                        let r = ui.colored_label(
                                            state_color(ui, c.state.is_running(), failed),
                                            format!("{:?}", c.state).to_lowercase(),
                                        );
                                        if let Some(e) = &c.error {
                                            r.on_hover_text(e);
                                        }
                                        if can
                                            && c.state.is_running()
                                            && ui.small_button("■").on_hover_text("Stop").clicked()
                                        {
                                            act = Some((true, c.kind, c.id));
                                        }
                                        if can
                                            && !c.state.is_running()
                                            && ui
                                                .small_button("✕")
                                                .on_hover_text("Remove")
                                                .clicked()
                                        {
                                            act = Some((false, c.kind, c.id));
                                        }
                                    });
                                });
                            }
                            ui.end_row();
                            for l in &labels {
                                ui.label(RichText::new(l).weak());
                                for c in cols {
                                    let v = c
                                        .rows
                                        .iter()
                                        .find(|(k, _)| k == l)
                                        .map(|(_, v)| v.as_str())
                                        .unwrap_or("");
                                    ui.monospace(v);
                                }
                                ui.end_row();
                            }
                        });
                    ui.add_space(8.0);
                }
            });
        match act {
            Some((true, kind, id)) => self.stop_run(i, kind, id),
            Some((false, kind, id)) => self.remove_run(i, kind, id),
            None => {}
        }
    }

    pub fn charts_tab(&mut self, ui: &mut egui::Ui) {
        let Some(s) = self.servers.get(self.sel_server) else {
            return;
        };
        let id = ui.id().with("chart-mode");
        let mut mode = ui.data_mut(|d| *d.get_persisted_mut_or(id, ChartMode::Pps));
        ui.horizontal(|ui| {
            ui.heading(format!("Charts of {}", s.settings.addr));
            ui.separator();
            ui.selectable_value(&mut mode, ChartMode::Pps, "Send packets/s");
            ui.selectable_value(&mut mode, ChartMode::Mbps, "Send Mbit/s");
            ui.selectable_value(&mut mode, ChartMode::Receive, "Loss and latency")
                .on_hover_text("Per flow: streams with a signature in runs with a receiver, and receivers (ferotrx rx)");
        });
        ui.data_mut(|d| d.insert_persisted(id, mode));
        if mode == ChartMode::Receive {
            receive_charts(ui, s);
            return;
        }
        let mbps = mode == ChartMode::Mbps;
        if s.history.is_empty() {
            ui.weak("Start a run to see its rate here. Rates are measured between polls, once a second.");
            return;
        }
        Plot::new("rates")
            .legend(Legend::default())
            .x_axis_label("seconds")
            .y_axis_label(if mbps { "Mbit/s" } else { "packets/s" })
            .include_y(0.0)
            .show(ui, |p| {
                for h in s.history.values() {
                    let pts: Vec<[f64; 2]> = h
                        .points
                        .iter()
                        .map(|&(t, pps, m)| [t, if mbps { m } else { pps }])
                        .collect();
                    p.line(Line::new(h.label.clone(), PlotPoints::from(pts)));
                }
            });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum ChartMode {
    Pps,
    Mbps,
    Receive,
}

/// The latency series a chart can show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LatencySeries {
    Avg,
    P50,
    P99,
    P999,
    Max,
    Jitter,
}

impl LatencySeries {
    const ALL: [LatencySeries; 6] = [
        LatencySeries::Avg,
        LatencySeries::P50,
        LatencySeries::P99,
        LatencySeries::P999,
        LatencySeries::Max,
        LatencySeries::Jitter,
    ];

    fn label(self) -> &'static str {
        match self {
            LatencySeries::Avg => "average",
            LatencySeries::P50 => "p50",
            LatencySeries::P99 => "p99",
            LatencySeries::P999 => "p99.9",
            LatencySeries::Max => "max",
            LatencySeries::Jitter => "jitter",
        }
    }

    fn help(self) -> &'static str {
        match self {
            LatencySeries::Avg => "Average of the packets received in each second",
            LatencySeries::Jitter => "Smoothed variation from packet to packet (RFC 3550)",
            _ => "Since the start of the run, to within 12.5%",
        }
    }

    fn get(self, p: &FlowPoint) -> Option<f64> {
        match self {
            LatencySeries::Avg => p.avg_us,
            LatencySeries::P50 => p.p50_us,
            LatencySeries::P99 => p.p99_us,
            LatencySeries::P999 => p.p999_us,
            LatencySeries::Max => p.max_us,
            LatencySeries::Jitter => p.jitter_us,
        }
    }
}

/// Loss, reordering and latency of every flow over time, in three charts
/// on one time axis.
fn receive_charts(ui: &mut egui::Ui, s: &crate::app::ServerState) {
    if s.flows.is_empty() {
        ui.weak(
            "No flows with signatures yet. Give a port's streams a latency flow and the run a \
             receiver (Streams tab, port settings), or start a receiver with ferotrx rx.",
        );
        return;
    }
    let id = ui.id().with("latency-series");
    let mut on: Vec<bool> = ui.data_mut(|d| {
        d.get_persisted_mut_or(id, vec![true, false, true, false, false, true])
            .clone()
    });
    on.resize(LatencySeries::ALL.len(), false);
    ui.horizontal_wrapped(|ui| {
        ui.label("Latency:");
        for (n, l) in LatencySeries::ALL.iter().enumerate() {
            ui.checkbox(&mut on[n], l.label()).on_hover_text(l.help());
        }
    });
    ui.data_mut(|d| d.insert_persisted(id, on.clone()));
    let group = ui.id().with("rx-axis");
    let h = (ui.available_height() - 24.0) / 3.0;
    let flows: Vec<&FlowHistory> = s.flows.values().collect();
    let line = |label: String, pts: Vec<[f64; 2]>| Line::new(label, PlotPoints::from(pts));
    Plot::new("rx-loss")
        .height(h.max(80.0))
        .legend(Legend::default())
        .link_axis(group, [true, false])
        .link_cursor(group, [true, false])
        .y_axis_label("loss %")
        .include_y(0.0)
        .show(ui, |p| {
            for f in &flows {
                let pts = f.points.iter().map(|x| [x.t, x.loss_pct]).collect();
                p.line(line(format!("{} loss", f.label), pts));
            }
        });
    Plot::new("rx-order")
        .height(h.max(80.0))
        .legend(Legend::default())
        .link_axis(group, [true, false])
        .link_cursor(group, [true, false])
        .y_axis_label("per second")
        .include_y(0.0)
        .show(ui, |p| {
            for f in &flows {
                let r = f.points.iter().map(|x| [x.t, x.reordered_ps]).collect();
                p.line(line(format!("{} reordered", f.label), r));
                if f.points.iter().any(|x| x.duplicates_ps > 0.0) {
                    let d = f.points.iter().map(|x| [x.t, x.duplicates_ps]).collect();
                    p.line(line(format!("{} duplicates", f.label), d));
                }
            }
        });
    Plot::new("rx-latency")
        .height(h.max(80.0))
        .legend(Legend::default())
        .link_axis(group, [true, false])
        .link_cursor(group, [true, false])
        .x_axis_label("seconds")
        .y_axis_label("ms")
        .include_y(0.0)
        .show(ui, |p| {
            for f in &flows {
                for (n, l) in LatencySeries::ALL.iter().enumerate() {
                    if !on[n] {
                        continue;
                    }
                    let pts = f
                        .points
                        .iter()
                        .filter_map(|x| l.get(x).map(|v| [x.t, v / 1000.0]))
                        .collect();
                    p.line(line(format!("{} {}", f.label, l.label()), pts));
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals_of_a_flow() {
        let lat = |avg| LatencyCounters {
            avg_us: Some(avg),
            p99_us: Some(900.0),
            ..Default::default()
        };
        let a = FlowCounters {
            flow: 1,
            tx: Some(1000),
            rx: 1000,
            lost: 0,
            latency: lat(100.0),
            ..Default::default()
        };
        let b = FlowCounters {
            tx: Some(2000),
            rx: 1900,
            lost: 100,
            loss_pct: 5.0,
            out_of_order: 20,
            latency: lat(150.0),
            ..a.clone()
        };
        let p = crate::app::flow_point(10.0, 2.0, &a, &b);
        assert!(
            (p.loss_pct - 10.0).abs() < 1e-9,
            "100 of 1000 lost in the interval"
        );
        assert_eq!(p.total_loss_pct, 5.0);
        assert_eq!(p.reordered_ps, 10.0);
        assert_eq!(p.rx_ps, 450.0);
        // 1900 * 150 - 1000 * 100 = 185000 over 900 packets.
        assert!((p.avg_us.unwrap() - 205.555).abs() < 0.01, "{:?}", p.avg_us);
        assert_eq!(p.p99_us, Some(900.0));

        // A receiver alone counts gaps: expected = rx + lost.
        let a = FlowCounters { tx: None, ..a };
        let b = FlowCounters { tx: None, ..b };
        let p = crate::app::flow_point(10.0, 1.0, &a, &b);
        assert!((p.loss_pct - 10.0).abs() < 1e-9);

        let mut h = FlowHistory::default();
        h.add(1.0, &a);
        h.add(2.0, &b);
        assert_eq!(h.points.len(), 1);
        h.add(3.0, &a);
        assert!(h.points.is_empty(), "a counter going back starts again");
    }

    #[test]
    fn numbers_get_thin_spaces() {
        assert_eq!(n(0), "0");
        assert_eq!(n(999), "999");
        assert_eq!(n(1234567), "1\u{2009}234\u{2009}567");
    }

    #[test]
    fn rows_union_in_order() {
        let a = RunColumn {
            kind: "run",
            id: 1,
            title: String::new(),
            state: RunState::Running,
            error: None,
            rows: vec![("a".into(), "1".into()), ("b".into(), "2".into())],
        };
        let b = RunColumn {
            rows: vec![("a".into(), "1".into()), ("c".into(), "3".into())],
            ..a.clone_shallow()
        };
        assert_eq!(row_labels(&[a, b]), ["a", "b", "c"]);
    }

    impl RunColumn {
        fn clone_shallow(&self) -> Self {
            Self {
                kind: self.kind,
                id: self.id,
                title: self.title.clone(),
                state: self.state,
                error: self.error.clone(),
                rows: Vec::new(),
            }
        }
    }
}
