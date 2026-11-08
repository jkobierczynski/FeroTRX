//! The Benchmark tab: an RFC 2544 benchmark profile, edited here or read on
//! the server, run by the server (`bench.start`) between two of its
//! interfaces, with every trial shown as it ends, the results per frame size
//! and the report to save (docs/benchmarking.md).

use std::path::Path;

use eframe::egui::{self, Color32, RichText};
use egui_plot::{Bar, BarChart, Legend, Plot, Points};
use ferotrx_core::{BenchProfile, BenchReport, BenchTest};
use ferotrx_ctl::protocol::{BenchRunInfo, BenchTrialInfo};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::app::{FeroApp, Pending, Status};
use crate::files::{Kind, Target};

/// What a new benchmark starts from: a short run through the lab router.
pub const NEW_BENCH: &str = r#"# An RFC 2544 benchmark (docs/benchmarking.md).
format = 1

[benchmark]
# Frames to the device's MAC on the sending side; payload cut or padded to
# each size. Here: the lab router, from VLAN 10 to VLAN 20.
packet = "eth(dst=02:00:00:00:01:01)/vlan(id=10)/ipv4(src=192.168.10.100,dst=192.168.20.50)/udp(sport=4000,dport=9000)"
vary = ["port_src=4000..4099"]
tests = ["throughput", "latency"]
# Sizes without FCS: "rfc2544" is 60 to 1514, "imix" one IMIX mix.
sizes = [124, 508, 1514]
line_rate = "100mbps"
trial_duration = "2s"
warmup = "1s"
resolution = 2.0
"#;

#[derive(Serialize, Deserialize)]
#[serde(default)]
pub struct BenchState {
    /// The profile file: on this computer when `upload`, else on the server.
    pub path: String,
    pub upload: bool,
    pub text: String,
    #[serde(skip)]
    saved: String,
    /// Where to send and where to receive, on the server.
    pub iface: String,
    pub rx: String,
    pub backend: String,
    pub workers: String,
    /// Tests to run instead of the profile's (none ticked: the profile's).
    pub tests: Vec<String>,
    /// Instead of the profile's, when not empty: `124, 1514, imix`.
    pub sizes: String,
    pub line_rate: String,
    pub trial_duration: String,
    pub repetitions: String,
    /// The last check of the text here: a summary, or what is wrong.
    #[serde(skip)]
    pub check: Option<Result<String, String>>,
    /// The run shown.
    #[serde(skip)]
    pub run: Option<u64>,
    /// The frame size whose trials the chart shows.
    #[serde(skip)]
    pub size: Option<String>,
}

impl Default for BenchState {
    fn default() -> Self {
        Self {
            path: String::new(),
            upload: true,
            text: String::new(),
            saved: String::new(),
            iface: String::new(),
            rx: String::new(),
            backend: String::new(),
            workers: String::new(),
            tests: Vec::new(),
            sizes: String::new(),
            line_rate: String::new(),
            trial_duration: String::new(),
            repetitions: String::new(),
            check: None,
            run: None,
            size: None,
        }
    }
}

impl BenchState {
    pub fn dirty(&self) -> bool {
        self.upload && self.text != self.saved
    }

    pub fn open(&mut self, path: &str) -> Result<(), String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        self.path = path.to_string();
        self.text = text.clone();
        self.saved = text;
        self.check = None;
        Ok(())
    }

    pub fn save(&mut self, path: &str) -> Result<(), String> {
        std::fs::write(path, &self.text).map_err(|e| format!("{path}: {e}"))?;
        self.path = path.to_string();
        self.saved = self.text.clone();
        Ok(())
    }

    pub fn new_bench(&mut self) {
        self.path.clear();
        self.text = NEW_BENCH.into();
        self.saved.clear();
        self.check = None;
        self.upload = true;
    }

    /// Reads the text here, as `ferotrx check` does.
    pub fn check_local(&mut self) {
        self.check = Some(
            BenchProfile::from_toml(&self.text)
                .and_then(|p| {
                    p.capture()?;
                    Ok(p)
                })
                .map(|p| {
                    let c = &p.config;
                    format!(
                        "{} at {} Mbit/s, sizes {}",
                        c.tests
                            .iter()
                            .map(|t| t.name())
                            .collect::<Vec<_>>()
                            .join(", "),
                        c.line_rate_mbps,
                        c.sizes
                            .iter()
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })
                .map_err(|e| e.to_string()),
        );
    }

    /// `bench.start` parameters.
    pub fn params(&self) -> Result<Value, String> {
        let mut p = json!({});
        if self.upload {
            if self.text.trim().is_empty() {
                return Err("the benchmark is empty: open one, or start a new one".into());
            }
            p["toml"] = self.text.clone().into();
        } else {
            if self.path.trim().is_empty() {
                return Err("name a benchmark profile on the server".into());
            }
            p["path"] = self.path.trim().into();
        }
        if self.iface.is_empty() || self.rx.is_empty() {
            return Err("pick the interface to send on and the one to receive on".into());
        }
        p["iface"] = self.iface.clone().into();
        p["rx"] = self.rx.clone().into();
        if !self.backend.is_empty() {
            p["backend"] = self.backend.clone().into();
        }
        if !self.workers.trim().is_empty() {
            let n: usize = self
                .workers
                .trim()
                .parse()
                .map_err(|_| format!("workers: '{}' is not a number", self.workers))?;
            p["workers"] = n.into();
        }
        if !self.tests.is_empty() {
            p["tests"] = json!(self.tests);
        }
        let sizes: Vec<&str> = self
            .sizes
            .split([',', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if !sizes.is_empty() {
            p["sizes"] = json!(sizes);
        }
        for (key, v) in [
            ("line_rate", &self.line_rate),
            ("trial_duration", &self.trial_duration),
        ] {
            if !v.trim().is_empty() {
                p[key] = v.trim().into();
            }
        }
        if !self.repetitions.trim().is_empty() {
            let n: u32 = self
                .repetitions
                .trim()
                .parse()
                .map_err(|_| format!("repetitions: '{}' is not a number", self.repetitions))?;
            p["repetitions"] = n.into();
        }
        Ok(p)
    }
}

/// A run's report as `ferotrx bench --report` writes it.
pub fn report_json(run: &BenchRunInfo) -> Option<String> {
    let report = run.report.as_ref()?;
    let v = json!({
        "format": "ferotrx-bench-1",
        "info": run.info,
        "report": report,
    });
    serde_json::to_string_pretty(&v).ok().map(|s| s + "\n")
}

fn state_color(ui: &egui::Ui, run: &BenchRunInfo) -> Color32 {
    use ferotrx_ctl::protocol::RunState;
    match run.state {
        RunState::Running => crate::theme::running(ui),
        RunState::Finished => crate::theme::good(ui),
        RunState::Failed => ui.visuals().error_fg_color,
        _ => ui.visuals().weak_text_color(),
    }
}

fn opt(v: Option<f64>, unit: &str) -> String {
    v.map_or("–".into(), |v| format!("{v:.1}{unit}"))
}

#[derive(Default)]
struct Actions {
    browse: Option<bool>,
    open: bool,
    save: bool,
    save_as: bool,
    new: bool,
    check: bool,
    start: bool,
    stop: Option<u64>,
    remove: Option<u64>,
    report: bool,
}

impl FeroApp {
    pub fn bench_tab(&mut self, ui: &mut egui::Ui) {
        let i = self.sel_server;
        let Some(server) = self.servers.get(i) else {
            return;
        };
        let connected = server.status == Status::Connected;
        let can = connected && server.can_operate();
        let addr = server.settings.addr.clone();
        let ifaces: Vec<String> = server.interfaces.iter().map(|x| x.name.clone()).collect();
        let backends = server
            .info
            .as_ref()
            .map(|i| i.backends.clone())
            .unwrap_or_default();
        let runs: Vec<BenchRunInfo> = server.snap.bench.clone();
        let st = &mut self.bench;
        if st.run.is_none_or(|id| !runs.iter().any(|r| r.id == id)) {
            st.run = runs.last().map(|r| r.id);
        }
        let mut a = Actions::default();

        ui.heading(format!("Benchmarks on {addr}"));
        ui.label(
            RichText::new(
                "RFC 2544 throughput, latency, frame loss and back-to-back of a device between two \
                 interfaces of the server: it sends on one and receives on the other. \
                 See docs/benchmarking.md.",
            )
            .weak(),
        );
        ui.add_space(4.0);
        egui::Grid::new("bench-form").num_columns(4).spacing([12.0, 6.0]).show(ui, |ui| {
            ui.label("Profile");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut st.path).hint_text("examples/bench-rfc2544.toml").desired_width(260.0));
                if ui.button("Browse…").clicked() {
                    a.browse = Some(st.upload);
                }
                if st.upload {
                    if ui.button("Open").clicked() {
                        a.open = true;
                    }
                    if ui.button(if st.dirty() { "Save*" } else { "Save" }).clicked() {
                        a.save = true;
                    }
                    if ui.button("Save as…").clicked() {
                        a.save_as = true;
                    }
                    if ui.button("New").on_hover_text("Start from a short benchmark through the lab router").clicked() {
                        a.new = true;
                    }
                }
                ui.checkbox(&mut st.upload, "from this computer")
                    .on_hover_text("Edit the profile here and send it with the run; otherwise the server reads the file");
            });
            ui.end_row();
            for (label, salt, v, hover) in [
                ("Send on", "bench-tx", &mut st.iface, "The interface towards the device"),
                ("Receive on", "bench-rx", &mut st.rx, "The interface the device sends the frames out to"),
            ] {
                ui.label(label);
                egui::ComboBox::from_id_salt(salt)
                    .selected_text(if v.is_empty() { "pick one" } else { v.as_str() })
                    .show_ui(ui, |ui| {
                        for n in &ifaces {
                            ui.selectable_value(v, n.clone(), n);
                        }
                    })
                    .response
                    .on_hover_text(hover);
                ui.end_row();
            }
            ui.label("Tests");
            ui.horizontal(|ui| {
                for t in BenchTest::ALL {
                    let name = t.name();
                    let mut on = st.tests.iter().any(|x| x == name);
                    if ui.checkbox(&mut on, name.replace('_', " ")).changed() {
                        if on {
                            st.tests.push(name.to_string());
                        } else {
                            st.tests.retain(|x| x != name);
                        }
                    }
                }
                ui.weak(if st.tests.is_empty() { "(none ticked: the profile's)" } else { "" });
            });
            ui.end_row();
            ui.label("Sizes");
            ui.add(egui::TextEdit::singleline(&mut st.sizes).hint_text("the profile's; e.g. rfc2544, imix, 124 1514").desired_width(260.0))
                .on_hover_text("Frame sizes without FCS, \"rfc2544\" for the seven RFC 2544 sizes, \"imix\" or a mix such as 60:7,590:4,1514:1");
            ui.end_row();
            ui.label("Line rate");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut st.line_rate).hint_text("the profile's").desired_width(90.0))
                    .on_hover_text("The speed of the link, such as 1gbps");
                ui.label("Trial");
                ui.add(egui::TextEdit::singleline(&mut st.trial_duration).hint_text("the profile's").desired_width(90.0));
                ui.label("Repetitions");
                ui.add(egui::TextEdit::singleline(&mut st.repetitions).hint_text("1").desired_width(40.0));
                ui.label("Workers");
                ui.add(egui::TextEdit::singleline(&mut st.workers).hint_text("1").desired_width(40.0));
                ui.label("Backend");
                egui::ComboBox::from_id_salt("bench-backend")
                    .selected_text(if st.backend.is_empty() { "the profile's" } else { &st.backend })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut st.backend, String::new(), "the profile's");
                        for b in &backends {
                            ui.selectable_value(&mut st.backend, b.clone(), b);
                        }
                    });
            });
            ui.end_row();
        });
        ui.horizontal(|ui| {
            if st.upload
                && ui
                    .button("Check")
                    .on_hover_text("Read the profile here")
                    .clicked()
            {
                a.check = true;
            }
            if ui
                .add_enabled(
                    can,
                    egui::Button::new(RichText::new("▶ Run on the server").strong()),
                )
                .on_disabled_hover_text("Connect with the operator role first")
                .clicked()
            {
                a.start = true;
            }
            if let Some(r) = runs
                .iter()
                .find(|r| Some(r.id) == st.run && r.state.is_running())
            {
                if ui
                    .add_enabled(can, egui::Button::new("■ Stop"))
                    .on_hover_text(
                        "Stop after the trial under way; the report has what was measured",
                    )
                    .clicked()
                {
                    a.stop = Some(r.id);
                }
            }
        });
        match &st.check {
            Some(Ok(s)) => {
                ui.colored_label(crate::theme::good(ui), format!("✔ {s}"));
            }
            Some(Err(e)) => {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
            None => {}
        }
        ui.separator();

        let width = ui.available_width();
        if st.upload {
            egui::Panel::left("bench-editor")
                .resizable(true)
                .default_size(width * 0.35)
                .min_size(200.0)
                .show(ui, |ui| {
                    ui.set_min_height(ui.available_height());
                    // Long lines scroll rather than wrap, as in a code editor.
                    let mut layouter = |ui: &egui::Ui, text: &dyn egui::TextBuffer, _wrap: f32| {
                        let job = egui::text::LayoutJob::simple(
                            text.as_str().to_owned(),
                            egui::TextStyle::Monospace.resolve(ui.style()),
                            ui.visuals().text_color(),
                            f32::INFINITY,
                        );
                        ui.fonts_mut(|f| f.layout_job(job))
                    };
                    egui::ScrollArea::both()
                        .id_salt("bench-text")
                        .show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut st.text)
                                    .code_editor()
                                    .layouter(&mut layouter)
                                    .hint_text("Open a benchmark profile, or press New")
                                    .desired_width(f32::INFINITY)
                                    .desired_rows(30),
                            );
                        });
                });
        }
        egui::CentralPanel::default().show(ui, |ui| {
            bench_results(ui, st, &runs, &mut a);
        });

        let st = &mut self.bench;
        if a.new {
            st.new_bench();
        }
        if a.check {
            st.check_local();
        }
        if a.open {
            let p = st.path.trim().to_string();
            if let Err(e) = st.open(&p) {
                self.error(&addr, e);
            }
        }
        let st = &mut self.bench;
        if a.save {
            if st.path.trim().is_empty() {
                a.save_as = true;
            } else {
                let p = st.path.trim().to_string();
                match st.save(&p) {
                    Ok(()) => self.info(&addr, format!("saved {p}")),
                    Err(e) => self.error(&addr, e),
                }
            }
        }
        if a.start {
            self.start_bench();
        }
        if let Some(id) = a.stop {
            self.stop_run(i, "bench", id);
        }
        if let Some(id) = a.remove {
            self.remove_run(i, "bench", id);
        }
        let current = self.bench.path.clone();
        if let Some(local_file) = a.browse {
            let title = if local_file {
                "Benchmark profile on this computer"
            } else {
                "Benchmark profile on the server"
            };
            self.files.pick(
                Target::OpenBench,
                title,
                Kind::Of(ferotrx_core::check::FileKind::Bench),
                &current,
            );
        }
        if a.save_as {
            let name =
                crate::files::save_name(&current, "bench", ferotrx_core::check::FileKind::Bench);
            self.files.save(
                Target::SaveBench,
                "Save the benchmark profile",
                Kind::Of(ferotrx_core::check::FileKind::Bench),
                &current,
                &name,
            );
        }
        if a.report {
            let name = runs
                .iter()
                .find(|r| Some(r.id) == self.bench.run)
                .map_or("bench.json".into(), |r| format!("bench-{}.json", r.id));
            self.files.save(
                Target::BenchReport,
                "Save the report (JSON, with the text report next to it)",
                Kind::Report,
                &current,
                &name,
            );
        }
    }

    /// Checks the benchmark and starts it on the selected server.
    pub fn start_bench(&mut self) {
        let i = self.sel_server;
        let Some(server) = self.servers.get(i) else {
            return;
        };
        let addr = server.settings.addr.clone();
        let st = &mut self.bench;
        if st.upload {
            st.check_local();
        }
        match (&st.check, st.params()) {
            (Some(Err(e)), _) if st.upload => {
                let e = format!("benchmark: {e}");
                self.error(&addr, e);
            }
            (_, Err(e)) => self.error(&addr, e),
            (_, Ok(p)) => self.call(i, "bench.start", p, Pending::BenchStarted),
        }
    }

    /// What a file dialog of the tab picked.
    pub fn bench_file(&mut self, target: Target, path: &Path) {
        let shown = path.display().to_string();
        let st = &mut self.bench;
        let r = match target {
            Target::OpenBench if st.upload => st.open(&shown),
            Target::OpenBench => {
                st.path = shown.clone();
                Ok(())
            }
            Target::SaveBench => st.save(&shown).map(|_| ()),
            Target::BenchReport => {
                let run = self
                    .servers
                    .get(self.sel_server)
                    .and_then(|s| s.snap.bench.iter().find(|r| Some(r.id) == self.bench.run));
                match run.and_then(|r| Some((report_json(r)?, r.text.clone().unwrap_or_default())))
                {
                    Some((json, text)) => std::fs::write(path, json)
                        .and_then(|_| std::fs::write(path.with_extension("txt"), text))
                        .map_err(|e| format!("{shown}: {e}")),
                    None => Err("the run has no report yet".into()),
                }
            }
            _ => return,
        };
        match r {
            Ok(()) if matches!(target, Target::SaveBench | Target::BenchReport) => {
                self.info("", format!("saved {shown}"))
            }
            Ok(()) => {}
            Err(e) => self.error("", e),
        }
    }
}

fn bench_results(ui: &mut egui::Ui, st: &mut BenchState, runs: &[BenchRunInfo], a: &mut Actions) {
    if runs.is_empty() {
        ui.weak("No benchmark on this server yet: pick the interfaces and press Run.");
        return;
    }
    ui.horizontal(|ui| {
        ui.label("Run");
        let label = |r: &BenchRunInfo| format!("{} · {}", r.id, r.profile);
        egui::ComboBox::from_id_salt("bench-run")
            .selected_text(
                runs.iter()
                    .find(|r| Some(r.id) == st.run)
                    .map(label)
                    .unwrap_or_default(),
            )
            .show_ui(ui, |ui| {
                for r in runs {
                    ui.selectable_value(&mut st.run, Some(r.id), label(r));
                }
            });
    });
    let Some(run) = runs.iter().find(|r| Some(r.id) == st.run) else {
        return;
    };
    ui.horizontal(|ui| {
        ui.colored_label(
            state_color(ui, run),
            RichText::new(format!("{:?}", run.state)).strong(),
        );
        ui.label(format!(
            "{} → {} · {:.0} s · {} trials · tests {} · sizes {}",
            run.iface,
            run.rx,
            run.elapsed_s,
            run.trials.len(),
            run.tests.join(", "),
            run.sizes.join(", ")
        ));
        if !run.state.is_running() {
            if ui
                .add_enabled(run.report.is_some(), egui::Button::new("Save report…"))
                .clicked()
            {
                a.report = true;
            }
            if ui.button("Remove").clicked() {
                a.remove = Some(run.id);
            }
        }
    });
    if let Some(e) = &run.error {
        ui.colored_label(ui.visuals().error_fg_color, e);
    }

    // The sizes so far, newest last.
    let mut sizes: Vec<String> = Vec::new();
    for t in &run.trials {
        if !sizes.contains(&t.size) {
            sizes.push(t.size.clone());
        }
    }
    if st.size.as_ref().is_none_or(|s| !sizes.contains(s)) || run.state.is_running() {
        st.size = sizes.last().cloned();
    }
    egui::ScrollArea::vertical()
        .id_salt("bench-results")
        .show(ui, |ui| {
            if let Some(report) = &run.report {
                ui.strong("Results");
                results_table(ui, report);
                throughput_chart(ui, report);
                ui.add_space(6.0);
            }
            if !sizes.is_empty() {
                ui.horizontal(|ui| {
                    ui.strong("Trials of size");
                    for s in &sizes {
                        ui.selectable_value(&mut st.size, Some(s.clone()), s);
                    }
                });
                let trials: Vec<&BenchTrialInfo> = run
                    .trials
                    .iter()
                    .filter(|t| Some(&t.size) == st.size.as_ref())
                    .collect();
                trials_chart(ui, &trials);
                trials_table(ui, &trials);
            }
            if let Some(text) = &run.text {
                egui::CollapsingHeader::new("Text report")
                    .id_salt("bench-text-report")
                    .show(ui, |ui| {
                        ui.add(
                            egui::Label::new(RichText::new(text).monospace())
                                .wrap_mode(egui::TextWrapMode::Extend),
                        );
                    });
            }
        });
}

fn results_table(ui: &mut egui::Ui, report: &BenchReport) {
    egui::Grid::new("bench-sizes")
        .striped(true)
        .spacing([14.0, 4.0])
        .show(ui, |ui| {
            for h in [
                "Size",
                "Throughput",
                "Mbit/s",
                "frames/s",
                "Latency avg",
                "max",
                "Back-to-back",
                "Frame loss",
                "Sweep sent/s",
            ] {
                ui.strong(h);
            }
            ui.end_row();
            for s in &report.sizes {
                ui.label(if s.grown {
                    format!("{} ({:.0} B)", s.size, s.frame_len)
                } else {
                    s.size.clone()
                });
                match &s.throughput {
                    Some(t) => {
                        let mut l = RichText::new(format!("{:.1} %", t.load_pct));
                        if t.sender_limited {
                            l = l.color(ui.visuals().warn_fg_color);
                        }
                        ui.label(l).on_hover_text(if t.sender_limited {
                            "The sender did not reach the offered rate: this measured the sender"
                        } else {
                            "The highest load without (more than the allowed) loss"
                        });
                        ui.label(format!("{:.1}", t.mbps));
                        ui.label(format!("{:.0}", t.pps));
                    }
                    None => {
                        for _ in 0..3 {
                            ui.weak("–");
                        }
                    }
                }
                match &s.latency {
                    Some(l) => {
                        ui.label(opt(l.latency.avg_us, " µs"));
                        ui.label(opt(l.latency.max_us, " µs"));
                    }
                    None => {
                        ui.weak("–");
                        ui.weak("–");
                    }
                }
                match &s.back_to_back {
                    Some(b) => ui.label(format!("{:.0} frames", b.frames)),
                    None => ui.weak("–"),
                };
                if s.frame_loss.is_empty() {
                    ui.weak("–");
                } else {
                    let worst = s.frame_loss.iter().map(|p| p.loss_pct).fold(0.0, f64::max);
                    ui.label(format!("{} loads, worst {worst:.2} %", s.frame_loss.len()));
                }
                match &s.sweep {
                    Some(w) => ui
                        .label(format!(
                            "{:.0} ±{:.1} %",
                            w.tx_pps.median, w.tx_pps.spread_pct
                        ))
                        .on_hover_text(format!(
                            "Median of {} trials at {:.1} %, {:.0} to {:.0} frames/s; loss {:.3} %",
                            w.trials, w.load_pct, w.tx_pps.min, w.tx_pps.max, w.loss_pct.median
                        )),
                    None => ui.weak("–"),
                };
                ui.end_row();
            }
        });
}

/// Throughput per size, percent of the line rate.
fn throughput_chart(ui: &mut egui::Ui, report: &BenchReport) {
    let bars: Vec<Bar> = report
        .sizes
        .iter()
        .enumerate()
        .filter_map(|(n, s)| {
            let t = s.throughput.as_ref()?;
            Some(
                Bar::new(n as f64, t.load_pct)
                    .name(&s.size)
                    .width(0.6)
                    .fill(crate::theme::running(ui).gamma_multiply(0.6)),
            )
        })
        .collect();
    if bars.is_empty() {
        return;
    }
    let names: Vec<String> = report.sizes.iter().map(|s| s.size.clone()).collect();
    Plot::new("bench-throughput")
        .height(160.0)
        .include_y(0.0)
        .include_y(100.0)
        .allow_drag(false)
        .allow_zoom(false)
        .allow_scroll(false)
        .y_axis_label("throughput, % of line rate")
        .x_axis_formatter(move |m, _| {
            let n = m.value.round();
            if (m.value - n).abs() < 1e-6 && n >= 0.0 {
                names.get(n as usize).cloned().unwrap_or_default()
            } else {
                String::new()
            }
        })
        .show(ui, |p| p.bar_chart(BarChart::new("throughput", bars)));
}

/// The load of every trial of a size in turn: the binary search closing in,
/// passed trials green, lossy ones red.
fn trials_chart(ui: &mut egui::Ui, trials: &[&BenchTrialInfo]) {
    let (mut ok, mut bad) = (Vec::new(), Vec::new());
    for (n, t) in trials.iter().enumerate() {
        let p = [n as f64 + 1.0, t.trial.load_pct];
        if t.trial.passed == Some(false) || (t.trial.passed.is_none() && t.trial.lost > 0) {
            bad.push(p);
        } else {
            ok.push(p);
        }
    }
    let (good, lossy) = (crate::theme::good(ui), ui.visuals().error_fg_color);
    Plot::new("bench-trials")
        .height(160.0)
        .include_y(0.0)
        .include_y(100.0)
        .legend(Legend::default())
        .allow_drag(false)
        .allow_zoom(false)
        .allow_scroll(false)
        .x_axis_label("trial")
        .y_axis_label("offered load, %")
        .show(ui, |p| {
            p.points(Points::new("no loss", ok).radius(4.0_f32).color(good));
            p.points(Points::new("loss", bad).radius(4.0_f32).color(lossy));
        });
}

fn trials_table(ui: &mut egui::Ui, trials: &[&BenchTrialInfo]) {
    egui::Grid::new("bench-trials-table")
        .striped(true)
        .spacing([12.0, 2.0])
        .show(ui, |ui| {
            for h in [
                "#",
                "Test",
                "Rep",
                "Load",
                "Offered pps",
                "Sent pps",
                "Received",
                "Lost",
                "Loss",
                "Latency avg",
                "Passed",
            ] {
                ui.strong(h);
            }
            ui.end_row();
            for (n, t) in trials.iter().enumerate().rev() {
                let r = &t.trial;
                ui.label((n + 1).to_string());
                ui.label(r.test.name().replace('_', " "));
                ui.label(r.repetition.to_string());
                ui.label(match r.burst {
                    Some(b) => format!("burst {b}"),
                    None => format!("{:.1} %", r.load_pct),
                });
                ui.label(format!("{:.0}", r.offered_pps));
                let sent = RichText::new(format!("{:.0}", r.achieved_pps));
                ui.label(if r.sender_limited() {
                    sent.color(ui.visuals().warn_fg_color)
                } else {
                    sent
                });
                ui.label(r.rx.to_string());
                ui.label(r.lost.to_string());
                ui.label(format!("{:.3} %", r.loss_pct));
                ui.label(opt(r.latency.avg_us, " µs"));
                match r.passed {
                    Some(true) => ui.colored_label(crate::theme::good(ui), "✔"),
                    Some(false) => ui.colored_label(ui.visuals().error_fg_color, "✘"),
                    None => ui.weak("–"),
                };
                ui.end_row();
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_benchmark_checks_out() {
        let mut st = BenchState::default();
        st.new_bench();
        st.check_local();
        let s = st.check.clone().unwrap().unwrap();
        assert!(s.starts_with("throughput, latency at 100 Mbit/s"), "{s}");
        // The example of the repository too.
        st.text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/bench-rfc2544.toml"
        ))
        .unwrap();
        st.check_local();
        assert!(st.check.clone().unwrap().is_ok(), "{:?}", st.check);
        st.text = "[benchmark]\ntests = [\"speed\"]".into();
        st.check_local();
        assert!(st.check.clone().unwrap().is_err());
    }

    #[test]
    fn parameters_name_only_what_is_set() {
        let mut st = BenchState::default();
        st.new_bench();
        assert!(st.params().unwrap_err().contains("interface"));
        st.iface = "eth1".into();
        st.rx = "eth2".into();
        let p = st.params().unwrap();
        assert_eq!(p["iface"], "eth1");
        assert!(p.get("tests").is_none() && p.get("sizes").is_none());
        st.tests = vec!["throughput".into()];
        st.sizes = "rfc2544, 1514".into();
        st.line_rate = "1gbps".into();
        st.repetitions = "3".into();
        let p = st.params().unwrap();
        assert_eq!(p["tests"], json!(["throughput"]));
        assert_eq!(p["sizes"], json!(["rfc2544", "1514"]));
        assert_eq!(p["line_rate"], "1gbps");
        assert_eq!(p["repetitions"], 3);
        // The server takes them.
        let _: ferotrx_ctl::protocol::BenchStartParams = serde_json::from_value(p).unwrap();
        st.repetitions = "x".into();
        assert!(st.params().is_err());
        st.upload = false;
        st.repetitions.clear();
        assert!(st.params().unwrap_err().contains("server"));
        st.path = "bench.toml".into();
        assert_eq!(st.params().unwrap()["path"], "bench.toml");
    }
}
