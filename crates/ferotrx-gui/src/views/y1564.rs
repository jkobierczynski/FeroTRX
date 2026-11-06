//! The Y.1564 tab: a service activation profile, edited here or read on the
//! server, run by the server (`y1564.start`) between two of its interfaces,
//! with every step shown as it ends, the performance test per interval, and
//! the report to save (docs/y1564.md).

use std::path::Path;

use eframe::egui::{self, Color32, RichText};
use egui_plot::{Legend, Line, Plot, PlotPoints};
use ferotrx_core::{Color, StepRecord, Y1564Profile, Y1564Test};
use ferotrx_ctl::protocol::Y1564RunInfo;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::app::{FeroApp, Pending, Status};
use crate::files::{Kind, Target};

/// What a new test starts from: two services through the lab router.
pub const NEW_Y1564: &str = r#"# A Y.1564 service activation test (docs/y1564.md).
format = 1

[y1564]
line_rate = "100mbps"
tests = ["configuration", "performance"]
steps = [25, 50, 75, 100]
step_duration = "5s"
performance_duration = "1m"

# Frames to the router's MAC on the sending side. Here: the lab router, from
# VLAN 10 to VLAN 20. Yellow frames get their own DSCP, for a color-aware
# network.
[[service]]
name = "voice"
packet = "eth(dst=02:00:00:00:01:01)/vlan(id=10)/ipv4(src=192.168.10.100,dst=192.168.20.50,dscp=46)/udp(sport=5004,dport=5004)"
sizes = 252
cir = "2mbps"
flr = 0.1
ftd = "20ms"
fdv = "5ms"
availability = 99.9

[[service]]
name = "data"
packet = "eth(dst=02:00:00:00:01:01)/vlan(id=10)/ipv4(src=192.168.10.100,dst=192.168.20.51,dscp=10)/udp(sport=4000,dport=9000)"
yellow_packet = "eth(dst=02:00:00:00:01:01)/vlan(id=10)/ipv4(src=192.168.10.100,dst=192.168.20.51,dscp=12)/udp(sport=4000,dport=9000)"
sizes = "emix:abceg"
cir = "10mbps"
eir = "5mbps"
flr = 0.1
availability = 99.9
"#;

#[derive(Serialize, Deserialize)]
#[serde(default)]
pub struct Y1564State {
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
    /// Only these services, when not empty: `voice, data`.
    pub services: String,
    pub line_rate: String,
    pub step_duration: String,
    pub performance_duration: String,
    /// The last check of the text here: a summary, or what is wrong.
    #[serde(skip)]
    pub check: Option<Result<String, String>>,
    /// The run shown.
    #[serde(skip)]
    pub run: Option<u64>,
}

impl Default for Y1564State {
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
            services: String::new(),
            line_rate: String::new(),
            step_duration: String::new(),
            performance_duration: String::new(),
            check: None,
            run: None,
        }
    }
}

impl Y1564State {
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

    pub fn new_test(&mut self) {
        self.path.clear();
        self.text = NEW_Y1564.into();
        self.saved.clear();
        self.check = None;
        self.upload = true;
    }

    /// Reads the text here, as `ferotrx check` does.
    pub fn check_local(&mut self) {
        self.check = Some(
            Y1564Profile::from_toml(&self.text)
                .map(|p| {
                    let c = &p.config;
                    let services: Vec<String> = c
                        .services
                        .iter()
                        .map(|s| format!("{} ({}+{} Mbit/s)", s.name, s.cir_mbps, s.eir_mbps))
                        .collect();
                    format!(
                        "{} of {} at {} Mbit/s",
                        c.tests
                            .iter()
                            .map(|t| t.name())
                            .collect::<Vec<_>>()
                            .join(" and "),
                        services.join(", "),
                        c.line_rate_mbps
                    )
                })
                .map_err(|e| e.to_string()),
        );
    }

    /// `y1564.start` parameters.
    pub fn params(&self) -> Result<Value, String> {
        let mut p = json!({});
        if self.upload {
            if self.text.trim().is_empty() {
                return Err("the Y.1564 profile is empty: open one, or start a new one".into());
            }
            p["toml"] = self.text.clone().into();
        } else {
            if self.path.trim().is_empty() {
                return Err("name a Y.1564 profile on the server".into());
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
        let services: Vec<&str> = self
            .services
            .split([',', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if !services.is_empty() {
            p["services"] = json!(services);
        }
        for (key, v) in [
            ("line_rate", &self.line_rate),
            ("step_duration", &self.step_duration),
            ("performance_duration", &self.performance_duration),
        ] {
            if !v.trim().is_empty() {
                p[key] = v.trim().into();
            }
        }
        Ok(p)
    }
}

/// A run's report as `ferotrx y1564 --report` writes it.
pub fn report_json(run: &Y1564RunInfo) -> Option<String> {
    let report = run.report.as_ref()?;
    let mut v = serde_json::to_value(report).ok()?;
    if let Some(o) = v.as_object_mut() {
        o.insert("format".into(), "ferotrx-y1564-1".into());
        o.insert("info".into(), json!(run.info));
    }
    serde_json::to_string_pretty(&v).ok().map(|s| s + "\n")
}

fn good() -> Color32 {
    Color32::from_rgb(0x2e, 0xa0, 0x43)
}

fn verdict(ui: &egui::Ui, passed: bool) -> RichText {
    if passed {
        RichText::new("PASS").color(good()).strong()
    } else {
        RichText::new("FAIL")
            .color(ui.visuals().error_fg_color)
            .strong()
    }
}

fn ms(v: Option<f64>) -> String {
    v.map_or("–".into(), |v| format!("{v:.3} ms"))
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
    pub fn y1564_tab(&mut self, ui: &mut egui::Ui) {
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
        let runs: Vec<Y1564RunInfo> = server.snap.y1564.clone();
        let st = &mut self.y1564;
        if st.run.is_none_or(|id| !runs.iter().any(|r| r.id == id)) {
            st.run = runs.last().map(|r| r.id);
        }
        let mut a = Actions::default();

        ui.heading(format!("Y.1564 service activation on {addr}"));
        ui.label(
            RichText::new(
                "Services with a CIR, an EIR and acceptance criteria, tested through a network \
                 between two interfaces of the server: steps up to the CIR, CIR + EIR and \
                 policing per service, then all services at their CIR for a long time. \
                 See docs/y1564.md.",
            )
            .weak(),
        );
        ui.add_space(4.0);
        egui::Grid::new("y1564-form")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label("Profile");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut st.path)
                            .hint_text("examples/y1564.toml")
                            .desired_width(260.0),
                    );
                    if ui.button("Browse…").clicked() {
                        a.browse = Some(st.upload);
                    }
                    if st.upload {
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
                        if ui
                            .button("New")
                            .on_hover_text("Start from two services through the lab router")
                            .clicked()
                        {
                            a.new = true;
                        }
                    }
                    ui.checkbox(&mut st.upload, "from this computer")
                        .on_hover_text(
                            "Edit the profile here and send it with the run; otherwise the \
                             server reads the file",
                        );
                });
                ui.end_row();
                for (label, salt, v, hover) in [
                    (
                        "Send on",
                        "y1564-tx",
                        &mut st.iface,
                        "The interface into the network",
                    ),
                    (
                        "Receive on",
                        "y1564-rx",
                        &mut st.rx,
                        "The interface the network delivers the frames to",
                    ),
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
                    for t in Y1564Test::ALL {
                        let name = t.name();
                        let mut on = st.tests.iter().any(|x| x == name);
                        if ui.checkbox(&mut on, name).changed() {
                            if on {
                                st.tests.push(name.to_string());
                            } else {
                                st.tests.retain(|x| x != name);
                            }
                        }
                    }
                    ui.weak(if st.tests.is_empty() {
                        "(none ticked: the profile's)"
                    } else {
                        ""
                    });
                });
                ui.end_row();
                ui.label("Services");
                ui.add(
                    egui::TextEdit::singleline(&mut st.services)
                        .hint_text("all of the profile's; e.g. voice, data")
                        .desired_width(260.0),
                );
                ui.end_row();
                ui.label("Line rate");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut st.line_rate)
                            .hint_text("the profile's")
                            .desired_width(90.0),
                    )
                    .on_hover_text("The speed of the link, such as 1gbps");
                    ui.label("Step");
                    ui.add(
                        egui::TextEdit::singleline(&mut st.step_duration)
                            .hint_text("the profile's")
                            .desired_width(90.0),
                    )
                    .on_hover_text("Length of each configuration step, such as 60s");
                    ui.label("Performance");
                    ui.add(
                        egui::TextEdit::singleline(&mut st.performance_duration)
                            .hint_text("the profile's")
                            .desired_width(90.0),
                    )
                    .on_hover_text("Length of the performance test, such as 15m");
                    ui.label("Workers");
                    ui.add(
                        egui::TextEdit::singleline(&mut st.workers)
                            .hint_text("1")
                            .desired_width(40.0),
                    );
                    ui.label("Backend");
                    egui::ComboBox::from_id_salt("y1564-backend")
                        .selected_text(if st.backend.is_empty() {
                            "the profile's"
                        } else {
                            &st.backend
                        })
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
                    .on_hover_text("Stop now; the report has what was measured")
                    .clicked()
                {
                    a.stop = Some(r.id);
                }
            }
        });
        match &st.check {
            Some(Ok(s)) => {
                ui.colored_label(good(), format!("✔ {s}"));
            }
            Some(Err(e)) => {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
            None => {}
        }
        ui.separator();

        let width = ui.available_width();
        if st.upload {
            egui::SidePanel::left("y1564-editor")
                .resizable(true)
                .default_width(width * 0.35)
                .min_width(200.0)
                .show_inside(ui, |ui| {
                    ui.set_min_height(ui.available_height());
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
                        .id_salt("y1564-text")
                        .show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut st.text)
                                    .code_editor()
                                    .layouter(&mut layouter)
                                    .hint_text("Open a Y.1564 profile, or press New")
                                    .desired_width(f32::INFINITY)
                                    .desired_rows(30),
                            );
                        });
                });
        }
        egui::CentralPanel::default().show_inside(ui, |ui| {
            results(ui, st, &runs, &mut a);
        });

        let st = &mut self.y1564;
        if a.new {
            st.new_test();
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
        let st = &mut self.y1564;
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
            self.start_y1564();
        }
        if let Some(id) = a.stop {
            self.stop_run(i, "y1564", id);
        }
        if let Some(id) = a.remove {
            self.remove_run(i, "y1564", id);
        }
        let current = self.y1564.path.clone();
        if let Some(local_file) = a.browse {
            let title = if local_file {
                "Y.1564 profile on this computer"
            } else {
                "Y.1564 profile on the server"
            };
            self.files
                .pick(Target::OpenY1564, title, Kind::Profile, &current);
        }
        if a.save_as {
            let name = Path::new(&current)
                .file_name()
                .map_or("y1564.toml".into(), |n| n.to_string_lossy().into_owned());
            self.files.save(
                Target::SaveY1564,
                "Save the Y.1564 profile",
                Kind::Profile,
                &current,
                &name,
            );
        }
        if a.report {
            let name = runs
                .iter()
                .find(|r| Some(r.id) == self.y1564.run)
                .map_or("y1564.json".into(), |r| format!("y1564-{}.json", r.id));
            self.files.save(
                Target::Y1564Report,
                "Save the report (JSON, with the text report next to it)",
                Kind::Report,
                &current,
                &name,
            );
        }
    }

    /// Checks the profile and starts the test on the selected server.
    pub fn start_y1564(&mut self) {
        let i = self.sel_server;
        let Some(server) = self.servers.get(i) else {
            return;
        };
        let addr = server.settings.addr.clone();
        let st = &mut self.y1564;
        if st.upload {
            st.check_local();
        }
        match (&st.check, st.params()) {
            (Some(Err(e)), _) if st.upload => {
                let e = format!("Y.1564: {e}");
                self.error(&addr, e);
            }
            (_, Err(e)) => self.error(&addr, e),
            (_, Ok(p)) => self.call(i, "y1564.start", p, Pending::Y1564Started),
        }
    }

    /// What a file dialog of the tab picked.
    pub fn y1564_file(&mut self, target: Target, path: &Path) {
        let shown = path.display().to_string();
        let st = &mut self.y1564;
        let r = match target {
            Target::OpenY1564 if st.upload => st.open(&shown),
            Target::OpenY1564 => {
                st.path = shown.clone();
                Ok(())
            }
            Target::SaveY1564 => st.save(&shown),
            Target::Y1564Report => {
                let run = self
                    .servers
                    .get(self.sel_server)
                    .and_then(|s| s.snap.y1564.iter().find(|r| Some(r.id) == self.y1564.run));
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
            Ok(()) if matches!(target, Target::SaveY1564 | Target::Y1564Report) => {
                self.info("", format!("saved {shown}"))
            }
            Ok(()) => {}
            Err(e) => self.error("", e),
        }
    }
}

fn results(ui: &mut egui::Ui, st: &mut Y1564State, runs: &[Y1564RunInfo], a: &mut Actions) {
    if runs.is_empty() {
        ui.weak("No Y.1564 test on this server yet: pick the interfaces and press Run.");
        return;
    }
    ui.horizontal(|ui| {
        ui.label("Run");
        let label = |r: &Y1564RunInfo| format!("{} · {}", r.id, r.profile);
        egui::ComboBox::from_id_salt("y1564-run")
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
        use ferotrx_ctl::protocol::RunState;
        let color = match (&run.state, run.report.as_ref().map(|r| r.passed)) {
            (RunState::Running, _) => Color32::from_rgb(0x3a, 0x7b, 0xd5),
            (_, Some(true)) => good(),
            (RunState::Failed, _) | (_, Some(false)) => ui.visuals().error_fg_color,
            _ => ui.visuals().weak_text_color(),
        };
        let state = match run.report.as_ref() {
            Some(r) if r.passed => "Passed".to_string(),
            Some(_) => "Failed".to_string(),
            None => format!("{:?}", run.state),
        };
        ui.colored_label(color, RichText::new(state).strong());
        ui.label(format!(
            "{} → {} · {:.0} s · {} steps · {} · services {}",
            run.iface,
            run.rx,
            run.elapsed_s,
            run.steps.len(),
            run.tests.join(" and "),
            run.services.join(", ")
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
    egui::ScrollArea::vertical()
        .id_salt("y1564-results")
        .show(ui, |ui| {
            let config: Vec<&StepRecord> = run
                .steps
                .iter()
                .filter(|s| s.test == Y1564Test::Configuration)
                .collect();
            if !config.is_empty() {
                ui.strong("Service configuration test");
                steps_table(ui, "y1564-config", &config);
                ui.add_space(6.0);
            }
            if let Some(perf) = run.steps.iter().find(|s| s.test == Y1564Test::Performance) {
                ui.strong(format!(
                    "Service performance test ({:.0} s)",
                    perf.duration_s
                ));
                performance_table(ui, perf);
                interval_charts(ui, perf);
            } else if run.state.is_running() && run.tests.iter().any(|t| t == "performance") {
                ui.weak("The performance test reports when it ends.");
            }
            if let Some(text) = &run.text {
                egui::CollapsingHeader::new("Text report")
                    .id_salt("y1564-text-report")
                    .show(ui, |ui| {
                        ui.add(
                            egui::Label::new(RichText::new(text).monospace())
                                .wrap_mode(egui::TextWrapMode::Extend),
                        );
                    });
            }
        });
}

/// A row per step and service: offered rates, what arrived, the green
/// frames' loss and delay, and the verdict with its reasons.
fn steps_table(ui: &mut egui::Ui, id: &str, steps: &[&StepRecord]) {
    egui::Grid::new(id)
        .striped(true)
        .spacing([14.0, 4.0])
        .show(ui, |ui| {
            for h in [
                "service",
                "step",
                "green Mbit/s",
                "yellow Mbit/s",
                "IR Mbit/s",
                "FLR",
                "FTD",
                "FDV",
                "yellow lost",
                "",
                "",
            ] {
                ui.strong(h);
            }
            ui.end_row();
            for st in steps {
                for s in &st.services {
                    let offered = |c: Color| {
                        st.flows
                            .iter()
                            .find(|f| f.service == s.service && f.color == c)
                            .map_or("–".into(), |f| {
                                let mut t = format!("{:.3}", f.offered_mbps);
                                if let Some(b) = f.burst {
                                    t.push_str(&format!(" (bursts of {b})"));
                                }
                                t
                            })
                    };
                    ui.label(&s.service);
                    ui.label(&st.name);
                    ui.label(offered(Color::Green));
                    ui.label(offered(Color::Yellow));
                    ui.label(format!("{:.3}", s.ir_mbps));
                    ui.label(format!("{:.3}%", s.flr_pct));
                    ui.label(ms(s.ftd_ms));
                    ui.label(ms(s.fdv_ms));
                    ui.label(s.yellow_flr_pct.map_or("–".into(), |v| format!("{v:.2}%")));
                    ui.label(verdict(ui, s.passed));
                    let mut why = s.failures.join("; ");
                    for n in &s.notes {
                        if !why.is_empty() {
                            why.push_str("; ");
                        }
                        why.push_str(n);
                    }
                    ui.weak(why);
                    ui.end_row();
                }
            }
        });
}

fn performance_table(ui: &mut egui::Ui, perf: &StepRecord) {
    egui::Grid::new("y1564-perf")
        .striped(true)
        .spacing([14.0, 4.0])
        .show(ui, |ui| {
            for h in [
                "service",
                "IR Mbit/s",
                "FLR",
                "FTD",
                "FDV",
                "available",
                "SES",
                "",
                "",
            ] {
                ui.strong(h);
            }
            ui.end_row();
            for s in &perf.services {
                ui.label(&s.service);
                ui.label(format!("{:.3}", s.ir_mbps));
                ui.label(format!("{:.4}%", s.flr_pct));
                ui.label(ms(s.ftd_ms));
                ui.label(ms(s.fdv_ms));
                ui.label(
                    s.availability_pct
                        .map_or("–".into(), |v| format!("{v:.3}%")),
                );
                ui.label(s.ses.map_or("–".into(), |v| v.to_string()));
                ui.label(verdict(ui, s.passed));
                ui.weak(s.failures.join("; "));
                ui.end_row();
            }
        });
}

/// Loss and mean delay per interval of the performance test, a line per
/// service.
fn interval_charts(ui: &mut egui::Ui, perf: &StepRecord) {
    if perf.services.iter().all(|s| s.intervals.is_empty()) {
        return;
    }
    ui.columns(2, |cols| {
        Plot::new("y1564-flr")
            .height(180.0)
            .include_y(0.0)
            .legend(Legend::default())
            .x_axis_label("s")
            .y_axis_label("frame loss, %")
            .show(&mut cols[0], |p| {
                for s in &perf.services {
                    let pts: Vec<[f64; 2]> =
                        s.intervals.iter().map(|i| [i.start_s, i.flr_pct]).collect();
                    p.line(Line::new(s.service.clone(), PlotPoints::from(pts)));
                }
            });
        Plot::new("y1564-ftd")
            .height(180.0)
            .include_y(0.0)
            .legend(Legend::default())
            .x_axis_label("s")
            .y_axis_label("mean delay, ms")
            .show(&mut cols[1], |p| {
                for s in &perf.services {
                    let pts: Vec<[f64; 2]> = s
                        .intervals
                        .iter()
                        .filter_map(|i| Some([i.start_s, i.ftd_ms?]))
                        .collect();
                    p.line(Line::new(s.service.clone(), PlotPoints::from(pts)));
                }
            });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_test_checks_out() {
        let mut st = Y1564State::default();
        st.new_test();
        st.check_local();
        let check = st.check.clone().unwrap();
        assert!(
            check.as_ref().is_ok_and(|s| s.contains("voice")),
            "{check:?}"
        );
    }

    #[test]
    fn parameters_name_only_what_is_set() {
        let mut st = Y1564State::default();
        st.new_test();
        assert!(st.params().unwrap_err().contains("interface"));
        st.iface = "eth1".into();
        st.rx = "eth2".into();
        st.services = "voice, data".into();
        st.step_duration = "10s".into();
        st.tests = vec!["configuration".into()];
        let p = st.params().unwrap();
        assert_eq!(p["services"], json!(["voice", "data"]));
        assert_eq!(p["step_duration"], "10s");
        assert_eq!(p["tests"], json!(["configuration"]));
        assert!(p.get("line_rate").is_none());
        assert!(p["toml"].as_str().unwrap().contains("[[service]]"));
        st.workers = "two".into();
        assert!(st.params().is_err());
    }
}
