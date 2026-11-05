//! The Scenario tab: write or open a scenario (checks with expected
//! outcomes, `docs/scenarios.md`), check it on this computer, run it on the
//! server (`scenario.start`) and read the verdict of every check.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use eframe::egui::{self, Color32, RichText};
use ferotrx_core::scenario::{CheckReport, Scenario, ScenarioReport};
use ferotrx_ctl::protocol::{ScenarioCheckInfo, ScenarioInfo, ScenarioRunInfo};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::app::{FeroApp, Pending, Status};
use crate::files::{Kind, Target};

/// What a new scenario starts from: the lab router's checks.
const NEW_SCENARIO: &str = r#"# A scenario: checks with expected outcomes (docs/scenarios.md).
format = 1
name = "my-scenario"
iface = "ftrx-lab"

[vars]
clients = "192.168.10"
servers = "192.168.20"

# Every connection completes through the router.
[[check]]
name = "web"
require = ["timed_out == 0"]
[check.tcp]
pcap = "http.pcap"
connections = 20
cps = 10
[check.tcp.client]
ip = "${clients}.100/24"
gateway = "${clients}.1"
vlan = 10
[check.tcp.server]
ip = "${servers}.80/24"
gateway = "${servers}.1"
vlan = 20

# Nothing answers on a network the router has no route to.
[[check]]
name = "no route"
expect = "blocked"
duration = "3s"
[check.tcp]
port = 80
connect = "192.168.30.80"
connections = 2
[[check.tcp.message]]
from = "client"
text = "GET / HTTP/1.0\r\n\r\n"
[check.tcp.client]
ip = "${clients}.100/24"
gateway = "${clients}.1"
vlan = 10
[check.tcp.tcp]
syn_retries = 1
"#;

#[derive(Serialize, Deserialize)]
#[serde(default)]
pub struct ScenarioState {
    /// The scenario file: on this computer when `upload`, else on the server.
    pub path: String,
    /// Send the text from this computer; otherwise the server reads `path`.
    pub upload: bool,
    pub text: String,
    /// The text as last opened or saved.
    saved: String,
    /// `name=value` pairs that replace `[vars]`.
    pub set: String,
    /// Interface of the checks that name none.
    pub iface: String,
    /// For a server elsewhere: the folder on the server that pcaps named in
    /// the profiles are read from (its data directory when empty).
    pub server_dir: String,
    /// The last check: the checks of the scenario, or what is wrong with it.
    #[serde(skip)]
    pub checked: Option<Result<ScenarioInfo, String>>,
    /// Checks not to run.
    pub skip: BTreeSet<String>,
    /// Build the lab router a scenario names in `[lab]` before the run.
    pub build_lab: bool,
    /// The run shown.
    #[serde(skip)]
    pub run: Option<u64>,
    /// The check whose details are shown.
    #[serde(skip)]
    pub sel_check: Option<String>,
    /// The comparison window.
    pub compare: super::compare::CompareForm,
}

impl Default for ScenarioState {
    fn default() -> Self {
        Self {
            path: String::new(),
            upload: true,
            text: String::new(),
            saved: String::new(),
            set: String::new(),
            iface: String::new(),
            server_dir: String::new(),
            checked: None,
            skip: BTreeSet::new(),
            build_lab: true,
            run: None,
            sel_check: None,
            compare: Default::default(),
        }
    }
}

/// `a=1 b=2` (or one a line) as pairs.
fn parse_set(s: &str) -> Result<Vec<(String, String)>, String> {
    s.split(['\n', ' ', ','])
        .filter(|p| !p.trim().is_empty())
        .map(|p| {
            let (k, v) = p
                .split_once('=')
                .ok_or_else(|| format!("variables: '{p}' is not name=value"))?;
            Ok((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

/// Puts the profile files a scenario names (`tcp = "lab-tcp.toml"`) into it
/// as tables, read from `dir`: for a server on another computer, which has
/// none of the files. Names with a variable in them stay as they are.
pub fn inline_profiles(text: &str, dir: &Path) -> Result<String, String> {
    let mut t: toml::Table = toml::from_str(text)
        .map_err(|e| format!("cannot put the profiles into the scenario to upload it: {e}"))?;
    let mut changed = false;
    if let Some(toml::Value::Array(checks)) = t.get_mut("check") {
        for c in checks.iter_mut() {
            let toml::Value::Table(c) = c else { continue };
            for kind in ["tcp", "udp", "traffic"] {
                let Some(toml::Value::String(file)) = c.get(kind) else {
                    continue;
                };
                if file.contains("${") {
                    continue;
                }
                let path = dir.join(file);
                let body = std::fs::read_to_string(&path)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                let table: toml::Table =
                    toml::from_str(&body).map_err(|e| format!("{}: {e}", path.display()))?;
                c.insert(kind.into(), toml::Value::Table(table));
                changed = true;
            }
        }
    }
    if !changed {
        return Ok(text.to_string());
    }
    toml::to_string(&t).map_err(|e| e.to_string())
}

impl ScenarioState {
    /// The folder the scenario's relative paths start from, on this computer.
    fn folder(&self) -> PathBuf {
        match self.path.trim() {
            "" => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            p => PathBuf::from(crate::files::folder_of(Path::new(p))),
        }
    }

    pub fn dirty(&self) -> bool {
        self.upload && self.text != self.saved
    }

    /// Reads the scenario file into the editor.
    pub fn open(&mut self, path: &str) -> Result<(), String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        self.path = path.to_string();
        self.text = text.clone();
        self.saved = text;
        self.checked = None;
        self.skip.clear();
        Ok(())
    }

    pub fn save(&mut self, path: &str) -> Result<(), String> {
        std::fs::write(path, &self.text).map_err(|e| format!("{path}: {e}"))?;
        self.path = path.to_string();
        self.saved = self.text.clone();
        Ok(())
    }

    pub fn new_scenario(&mut self) {
        self.path.clear();
        self.text = NEW_SCENARIO.into();
        self.saved.clear();
        self.checked = None;
        self.skip.clear();
        self.upload = true;
    }

    /// Checks the text here, reading its profiles from the file's folder.
    pub fn check_local(&mut self) {
        self.checked = Some(parse_set(&self.set).and_then(|set| {
            let mut s =
                Scenario::from_toml(&self.text, &self.folder(), &set).map_err(|e| e.to_string())?;
            if s.name.is_empty() {
                s.name = Path::new(self.path.trim())
                    .file_stem()
                    .map_or("scenario".into(), |n| n.to_string_lossy().into_owned());
            }
            if !self.iface.is_empty() {
                s.set_default_iface(&self.iface);
            }
            Ok(ferotrx_ctl::scenario_info(&s))
        }));
        let names = self.check_names();
        self.skip.retain(|n| names.contains(n));
    }

    fn check_names(&self) -> Vec<String> {
        match &self.checked {
            Some(Ok(i)) => i.checks.iter().map(|c| c.name.clone()).collect(),
            _ => Vec::new(),
        }
    }

    /// `scenario.check` and `scenario.start` parameters. A server on this
    /// computer (`local`) reads the profiles from the scenario's folder; one
    /// elsewhere gets them in the scenario.
    pub fn params(&self, local: bool) -> Result<Value, String> {
        let mut p = json!({});
        if self.upload {
            if self.text.trim().is_empty() {
                return Err("the scenario is empty: open one, or start a new one".into());
            }
            if local {
                p["toml"] = self.text.clone().into();
                p["base_dir"] = self.folder().display().to_string().into();
            } else {
                p["toml"] = inline_profiles(&self.text, &self.folder())?.into();
                if !self.server_dir.trim().is_empty() {
                    p["base_dir"] = self.server_dir.trim().into();
                }
            }
        } else {
            if self.path.trim().is_empty() {
                return Err("name a scenario file on the server".into());
            }
            p["path"] = self.path.trim().into();
        }
        let set: BTreeMap<String, String> = parse_set(&self.set)?.into_iter().collect();
        if !set.is_empty() {
            p["set"] = json!(set);
        }
        if !self.iface.is_empty() {
            p["iface"] = self.iface.clone().into();
        }
        if !self.build_lab {
            p["lab"] = false.into();
        }
        let names = self.check_names();
        if !self.skip.is_empty() && !names.is_empty() {
            let only: Vec<&String> = names.iter().filter(|n| !self.skip.contains(*n)).collect();
            if only.is_empty() {
                return Err("every check is switched off".into());
            }
            p["only"] = json!(only);
        }
        Ok(p)
    }
}

fn verdict_color(ui: &egui::Ui, state: &str) -> Color32 {
    match state {
        "pass" => Color32::from_rgb(0x2e, 0xa0, 0x43),
        "fail" | "error" => ui.visuals().error_fg_color,
        "running" => Color32::from_rgb(0x3a, 0x7b, 0xd5),
        _ => ui.visuals().weak_text_color(),
    }
}

fn verdict_symbol(state: &str) -> &'static str {
    match state {
        "pass" => "✔",
        "fail" => "✘",
        "error" => "⚠",
        "running" => "▶",
        "skipped" => "–",
        _ => "…",
    }
}

/// What the buttons of the tab asked for.
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
    report: Option<bool>,
    compare: bool,
}

impl FeroApp {
    pub fn scenario_tab(&mut self, ui: &mut egui::Ui) {
        let i = self.sel_server;
        let Some(server) = self.servers.get(i) else {
            return;
        };
        let connected = server.status == Status::Connected;
        let can = connected && server.can_operate();
        let local = server.settings.is_local();
        let addr = server.settings.addr.clone();
        let ifaces: Vec<String> = server.interfaces.iter().map(|x| x.name.clone()).collect();
        let runs: Vec<ScenarioRunInfo> = server.snap.scenarios.clone();
        let lab_running = server.lab.as_ref().is_some_and(|l| l.running);
        let st = &mut self.scenario;
        if st.run.is_none_or(|id| !runs.iter().any(|r| r.id == id)) {
            st.run = runs.last().map(|r| r.id);
        }
        let mut a = Actions::default();

        ui.heading(format!("Scenarios on {addr}"));
        ui.label(
            RichText::new(
                "Checks with expected outcomes: what must get through, what must be blocked, how well. \
                 Write or open one here, check it, and run it on the server. See docs/scenarios.md.",
            )
            .weak(),
        );
        if !lab_running {
            ui.label(
                RichText::new(
                    "examples/lab-scenario.toml runs on the lab router: start it with “Lab router…” on the left.",
                )
                .weak(),
            );
        }
        ui.add_space(4.0);
        egui::Grid::new("scn-form").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
            ui.label("Scenario");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut st.path).hint_text("examples/lab-scenario.toml").desired_width(300.0));
                if ui
                    .add_enabled(st.upload || local, egui::Button::new("Browse…"))
                    .on_disabled_hover_text("The server is on another computer: type a path there, or tick “from this computer”")
                    .clicked()
                {
                    a.browse = Some(st.upload);
                }
                if st.upload {
                    if ui.button("Open").on_hover_text("Read the file into the editor").clicked() {
                        a.open = true;
                    }
                    let save = if st.dirty() { "Save*" } else { "Save" };
                    if ui.button(save).clicked() {
                        a.save = true;
                    }
                    if ui.button("Save as…").clicked() {
                        a.save_as = true;
                    }
                    if ui.button("New").on_hover_text("Start from a small scenario for the lab router").clicked() {
                        a.new = true;
                    }
                }
                ui.checkbox(&mut st.upload, "from this computer")
                    .on_hover_text("Edit the scenario here and send it with the run; otherwise the server reads the file, relative to its data directory");
            });
            ui.end_row();
            ui.label("Variables");
            ui.add(egui::TextEdit::singleline(&mut st.set).hint_text("name=value …, replacing [vars]").desired_width(300.0))
                .on_hover_text("As ferotrx scenario run --set: iface=enp0s3 clients=10.0.0");
            ui.end_row();
            ui.label("Interface");
            egui::ComboBox::from_id_salt("scn-iface")
                .selected_text(if st.iface.is_empty() { "from the scenario" } else { &st.iface })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut st.iface, String::new(), "from the scenario");
                    for n in &ifaces {
                        ui.selectable_value(&mut st.iface, n.clone(), n);
                    }
                })
                .response
                .on_hover_text("For the checks that name no interface");
            ui.end_row();
            if st.upload && !local {
                ui.label("Server folder");
                ui.add(egui::TextEdit::singleline(&mut st.server_dir).hint_text("its data directory").desired_width(300.0))
                    .on_hover_text("The server is on another computer: the profiles go with the scenario, but captures they replay (http.pcap) are read on the server, from this folder");
                ui.end_row();
            }
        });
        ui.horizontal(|ui| {
            if ui
                .button("Check")
                .on_hover_text(if st.upload {
                    "Read the scenario and its profiles here, as ferotrx scenario show does"
                } else {
                    "Ask the server to read the scenario"
                })
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
            if let Some(Ok(Some(lab))) = st
                .checked
                .as_ref()
                .map(|c| c.as_ref().map(|i| i.lab.as_ref()))
            {
                ui.checkbox(&mut st.build_lab, "Build the lab it names")
                    .on_hover_text(format!(
                        "The scenario is written for {} ([lab]): the server builds it first \
                     (it needs ferotrx serve --lab). Untick to run on the lab as it is, \
                     e.g. one you changed on purpose.",
                        lab.describe()
                    ));
            }
            if let Some(r) = runs
                .iter()
                .find(|r| Some(r.id) == st.run && r.state.is_running())
            {
                if ui.add_enabled(can, egui::Button::new("■ Stop")).clicked() {
                    a.stop = Some(r.id);
                }
            }
        });
        match &st.checked {
            Some(Ok(info)) => {
                ui.colored_label(
                    Color32::from_rgb(0x2e, 0xa0, 0x43),
                    format!("✔ {}: {} checks", info.name, info.checks.len()),
                );
            }
            Some(Err(e)) => {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
            None => {}
        }
        ui.separator();

        let width = ui.available_width();
        egui::SidePanel::left("scn-editor")
            .resizable(true)
            .default_width(width * 0.45)
            .min_width(200.0)
            .show_inside(ui, |ui| {
                ui.set_min_height(ui.available_height());
                if st.upload {
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
                    egui::ScrollArea::both().id_salt("scn-text").show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut st.text)
                                .code_editor()
                                .layouter(&mut layouter)
                                .hint_text("Open a scenario, or press New")
                                .desired_width(f32::INFINITY)
                                .desired_rows(30),
                        );
                    });
                } else {
                    ui.weak("The server reads the scenario file, and the profiles it names, from its data directory.");
                }
            });
        egui::CentralPanel::default().show_inside(ui, |ui| {
            scenario_results(ui, st, &runs, &mut a);
        });

        let st = &mut self.scenario;
        if a.new {
            st.new_scenario();
        }
        if a.open {
            let p = st.path.trim().to_string();
            if let Err(e) = st.open(&p) {
                self.error(&addr, e);
            }
        }
        let st = &mut self.scenario;
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
        let st = &mut self.scenario;
        if a.check {
            if st.upload {
                st.check_local();
            } else {
                match st.params(local) {
                    Ok(p) => self.call(i, "scenario.check", p, Pending::ScenarioChecked),
                    Err(e) => self.error(&addr, e),
                }
            }
        }
        let st = &mut self.scenario;
        if a.start {
            if st.upload {
                st.check_local();
            }
            match &st.checked {
                Some(Err(e)) if st.upload => {
                    let e = e.clone();
                    self.error(&addr, format!("scenario: {e}"));
                }
                _ => match st.params(local) {
                    Ok(p) => self.call(i, "scenario.start", p, Pending::ScenarioStarted),
                    Err(e) => self.error(&addr, e),
                },
            }
        }
        if a.compare {
            self.open_compare();
        }
        if let Some(id) = a.stop {
            self.stop_run(i, "scenario", id);
        }
        if let Some(id) = a.remove {
            self.remove_run(i, "scenario", id);
        }
        let current = self.scenario.path.clone();
        if let Some(local_file) = a.browse {
            let title = if local_file {
                "Scenario on this computer"
            } else {
                "Scenario on the server"
            };
            self.files
                .pick(Target::OpenScenario, title, Kind::Profile, &current);
        }
        if a.save_as {
            let name = Path::new(&current)
                .file_name()
                .map_or("scenario.toml".into(), |n| n.to_string_lossy().into_owned());
            self.files.save(
                Target::SaveScenario,
                "Save the scenario",
                Kind::Profile,
                &current,
                &name,
            );
        }
        if let Some(junit) = a.report {
            let (kind, ext) = if junit {
                (Kind::Junit, "xml")
            } else {
                (Kind::Report, "json")
            };
            let name = runs
                .iter()
                .find(|r| Some(r.id) == self.scenario.run)
                .map_or(format!("scenario.{ext}"), |r| {
                    format!("{}-{}.{ext}", r.scenario, r.id)
                });
            self.files.save(
                Target::ScenarioReport { junit },
                if junit {
                    "Save the report as JUnit XML"
                } else {
                    "Save the report"
                },
                kind,
                &current,
                &name,
            );
        }
    }

    /// Puts what the file dialog picked for the Scenario tab in place.
    pub fn scenario_file(&mut self, target: Target, path: &Path) {
        let addr = self
            .servers
            .get(self.sel_server)
            .map(|s| s.settings.addr.clone())
            .unwrap_or_default();
        let shown = path.display().to_string();
        let st = &mut self.scenario;
        let outcome = match target {
            Target::OpenScenario if st.upload => st.open(&shown).map(|_| format!("opened {shown}")),
            Target::OpenScenario => {
                st.path = shown;
                st.checked = None;
                return;
            }
            Target::SaveScenario => st.save(&shown).map(|_| format!("saved {shown}")),
            Target::ScenarioReport { junit } => {
                let Some(report) = self
                    .servers
                    .get(self.sel_server)
                    .and_then(|s| s.snap.scenarios.iter().find(|r| Some(r.id) == st.run))
                    .and_then(|r| r.report.clone())
                else {
                    return;
                };
                let body = if junit {
                    report.junit()
                } else {
                    serde_json::to_string_pretty(&report).unwrap_or_default()
                };
                std::fs::write(path, body)
                    .map(|_| format!("report saved in {shown}"))
                    .map_err(|e| format!("{shown}: {e}"))
            }
            _ => return,
        };
        match outcome {
            Ok(m) => self.info(&addr, m),
            Err(e) => self.error(&addr, e),
        }
    }
}

/// The right side of the tab: the runs, the checks of the one shown, and
/// the details of the selected check.
fn scenario_results(
    ui: &mut egui::Ui,
    st: &mut ScenarioState,
    runs: &[ScenarioRunInfo],
    a: &mut Actions,
) {
    let run = runs.iter().find(|r| Some(r.id) == st.run);
    ui.horizontal(|ui| {
        ui.strong("Runs");
        let label = run.map_or("none yet".to_string(), run_label);
        egui::ComboBox::from_id_salt("scn-run")
            .selected_text(label)
            .width(320.0)
            .show_ui(ui, |ui| {
                for r in runs.iter().rev() {
                    ui.selectable_value(&mut st.run, Some(r.id), run_label(r));
                }
            });
        if let Some(r) = run {
            if !r.state.is_running() {
                if ui.small_button("Remove").on_hover_text("Forget this run on the server").clicked() {
                    a.remove = Some(r.id);
                }
                if r.report.is_some() {
                    if ui.small_button("Save report…").on_hover_text("JSON, as ferotrx scenario run --report; ferotrx scenario compare reads it").clicked() {
                        a.report = Some(false);
                    }
                    if ui.small_button("JUnit…").clicked() {
                        a.report = Some(true);
                    }
                }
            }
        }
        if ui
            .small_button("Compare…")
            .on_hover_text("Two runs or report files side by side, as ferotrx scenario compare")
            .clicked()
        {
            a.compare = true;
        }
    });
    let checks: Vec<ScenarioCheckInfo> = match (run, &st.checked) {
        (Some(r), _) => r.checks.clone(),
        (None, Some(Ok(info))) => info.checks.clone(),
        _ => Vec::new(),
    };
    if let Some(r) = run {
        let line = match &r.report {
            Some(rep) => rep.total_line(),
            None if r.state.is_running() => format!("running for {:.0} s", r.elapsed_s),
            None => format!("{:?}", r.state).to_lowercase(),
        };
        let color = match &r.report {
            Some(rep) if rep.passed() => Color32::from_rgb(0x2e, 0xa0, 0x43),
            Some(_) => ui.visuals().error_fg_color,
            None => ui.visuals().text_color(),
        };
        ui.colored_label(color, line);
        if let Some(e) = &r.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
    } else if checks.is_empty() {
        ui.weak("Check the scenario to see its checks, or run it.");
    }
    ui.add_space(4.0);
    let show_skip = run.is_none();
    egui::TopBottomPanel::top("scn-checks")
        .resizable(true)
        .default_height(220.0)
        .min_height(80.0)
        .show_inside(ui, |ui| {
            ui.set_min_height(ui.available_height());
            egui::ScrollArea::vertical()
                .id_salt("scn-checks-scroll")
                .show(ui, |ui| {
                    egui::Grid::new("scn-check-grid")
                        .striped(true)
                        .num_columns(5)
                        .spacing([10.0, 4.0])
                        .show(ui, |ui| {
                            ui.strong(if show_skip { "Run" } else { "" });
                            ui.strong("Check");
                            ui.strong("Kind");
                            ui.strong("Expect");
                            ui.strong(if show_skip { "Conditions" } else { "Result" });
                            ui.end_row();
                            for c in &checks {
                                if show_skip {
                                    let mut on = !st.skip.contains(&c.name);
                                    if ui.checkbox(&mut on, "").changed() {
                                        if on {
                                            st.skip.remove(&c.name);
                                        } else {
                                            st.skip.insert(c.name.clone());
                                        }
                                    }
                                } else {
                                    ui.colored_label(
                                        verdict_color(ui, &c.state),
                                        verdict_symbol(&c.state),
                                    )
                                    .on_hover_text(&c.state);
                                }
                                let selected = st.sel_check.as_deref() == Some(c.name.as_str());
                                if ui.selectable_label(selected, &c.name).clicked() {
                                    st.sel_check = (!selected).then(|| c.name.clone());
                                }
                                ui.label(&c.kind);
                                ui.label(&c.expect);
                                if show_skip {
                                    ui.label(c.conditions.join(", "));
                                } else {
                                    ui.label(result_line(c));
                                }
                                ui.end_row();
                            }
                        });
                });
        });
    egui::CentralPanel::default().show_inside(ui, |ui| {
        let Some(c) = st
            .sel_check
            .as_ref()
            .and_then(|n| checks.iter().find(|c| &c.name == n))
        else {
            ui.weak("Pick a check to see its conditions and counters.");
            return;
        };
        egui::ScrollArea::vertical()
            .id_salt("scn-detail")
            .show(ui, |ui| {
                check_details(ui, c, run.and_then(|r| r.report.as_ref()));
            });
    });
}

fn run_label(r: &ScenarioRunInfo) -> String {
    let what = match &r.report {
        Some(rep) => format!(
            "{} passed, {} failed{}",
            rep.summary.passed,
            rep.summary.failed + rep.summary.errors,
            if rep.stopped { ", stopped" } else { "" }
        ),
        None => format!("{:?}", r.state).to_lowercase(),
    };
    format!("#{} {}: {what}", r.id, r.scenario)
}

/// The Result column: live counters while running, the summary after.
fn result_line(c: &ScenarioCheckInfo) -> String {
    let attempt = if c.attempt > 1 {
        format!(" (attempt {} of {})", c.attempt, c.attempts)
    } else {
        String::new()
    };
    match (&c.report, c.state.as_str()) {
        (_, "running") => format!("{}{attempt}", c.progress),
        (Some(r), _) => {
            if let Some(e) = &r.error {
                format!("error: {e}")
            } else {
                format!("{}{attempt}", r.summary)
            }
        }
        (None, s) => s.to_string(),
    }
}

fn check_details(ui: &mut egui::Ui, c: &ScenarioCheckInfo, _report: Option<&ScenarioReport>) {
    ui.horizontal(|ui| {
        ui.colored_label(verdict_color(ui, &c.state), verdict_symbol(&c.state));
        ui.strong(&c.name);
        ui.weak(format!("{}, {}", c.kind, c.source));
    });
    if let Some(d) = &c.description {
        ui.label(d);
    }
    let mut where_ = Vec::new();
    if let Some(i) = &c.iface {
        where_.push(format!("on {i}"));
    }
    if let Some(r) = &c.rx {
        where_.push(format!("received on {r}"));
    }
    if !where_.is_empty() {
        ui.weak(where_.join(", "));
    }
    ui.add_space(4.0);
    match &c.report {
        Some(r) => report_details(ui, r),
        None => {
            ui.strong("Conditions");
            for cond in &c.conditions {
                ui.label(format!("• {cond}"));
            }
            if !c.progress.is_empty() {
                ui.add_space(4.0);
                ui.monospace(&c.progress);
            }
        }
    }
}

fn report_details(ui: &mut egui::Ui, r: &CheckReport) {
    if let Some(e) = &r.error {
        ui.colored_label(ui.visuals().error_fg_color, format!("could not run: {e}"));
    }
    if !r.summary.is_empty() {
        ui.monospace(&r.summary);
    }
    ui.weak(format!(
        "{} attempt{}, {:.1} s",
        r.attempts,
        if r.attempts == 1 { "" } else { "s" },
        r.elapsed_s
    ));
    if !r.conditions.is_empty() {
        ui.add_space(4.0);
        ui.strong("Conditions");
        egui::Grid::new("scn-conds")
            .num_columns(3)
            .spacing([10.0, 2.0])
            .show(ui, |ui| {
                for cond in &r.conditions {
                    let (sym, color) = if cond.pass {
                        ("✔", Color32::from_rgb(0x2e, 0xa0, 0x43))
                    } else {
                        ("✘", ui.visuals().error_fg_color)
                    };
                    ui.colored_label(color, sym);
                    ui.label(&cond.condition);
                    ui.weak(match cond.actual {
                        Some(v) => format!("was {}", r.format_metric(&cond.metric, v)),
                        None => "no such counter".into(),
                    });
                    ui.end_row();
                }
            });
    }
    if !r.metrics.is_empty() {
        ui.add_space(4.0);
        egui::CollapsingHeader::new("Counters")
            .id_salt("scn-metrics")
            .show(ui, |ui| {
                egui::Grid::new("scn-metric-grid")
                    .striped(true)
                    .num_columns(2)
                    .show(ui, |ui| {
                        for (k, v) in &r.metrics {
                            ui.label(k);
                            ui.monospace(r.format_metric(k, *v));
                            ui.end_row();
                        }
                    });
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn examples() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples")
    }

    #[test]
    fn the_lab_scenario_checks_out_and_goes_to_the_server() {
        let mut st = ScenarioState::default();
        let file = examples().join("lab-scenario.toml");
        st.open(&file.display().to_string()).unwrap();
        st.set = "iface=eth9".into();
        st.check_local();
        let info = st.checked.clone().unwrap().unwrap();
        assert_eq!(info.name, "lab-nat");
        assert_eq!(info.checks[0].iface.as_deref(), Some("eth9"));
        assert_eq!(info.checks.len(), 6);
        assert_eq!(info.lab.as_ref().unwrap().block_tcp, [8080]);

        // A server here reads the profiles from the scenario's folder.
        let p = st.params(true).unwrap();
        assert!(p["base_dir"].as_str().unwrap().ends_with("examples"));
        assert_eq!(p["set"]["iface"], "eth9");
        assert!(p.get("only").is_none());
        assert!(p.get("lab").is_none());
        let shown = ferotrx_ctl::protocol::ScenarioStartParams {
            toml: Some(st.text.clone()),
            ..serde_json::from_value(p.clone()).unwrap()
        };
        assert_eq!(shown.set["iface"], "eth9");

        st.skip.insert("voice stream".into());
        st.build_lab = false;
        let p = st.params(true).unwrap();
        assert_eq!(p["only"].as_array().unwrap().len(), 5);
        assert_eq!(p["lab"], false);
    }

    #[test]
    fn a_server_elsewhere_gets_the_profiles_in_the_scenario() {
        let mut st = ScenarioState {
            path: examples().join("unsaved.toml").display().to_string(),
            text: "name = \"x\"\n[[check]]\nname = \"web\"\ntcp = \"lab-tcp.toml\"\n\
                   [[check]]\nname = \"mix\"\nudp = \"lab-udp-mix.toml\"\nexpect = \"any\"\n\
                   require = [\"answered_pct > 95%\"]\n"
                .into(),
            ..Default::default()
        };
        st.check_local();
        assert!(st.checked.as_ref().unwrap().is_ok(), "{:?}", st.checked);
        let p = st.params(false).unwrap();
        assert!(p.get("base_dir").is_none());
        let text = p["toml"].as_str().unwrap();
        assert!(!text.contains("lab-tcp.toml"), "{text}");
        let s = Scenario::from_toml(text, Path::new("/nowhere"), &[]).unwrap();
        assert_eq!(s.checks[0].source, "inline");
        assert_eq!(s.checks[1].source, "inline");
        st.server_dir = "profiles".into();
        assert_eq!(st.params(false).unwrap()["base_dir"], "profiles");
    }

    #[test]
    fn a_new_scenario_checks_out() {
        let mut st = ScenarioState::default();
        st.new_scenario();
        st.path = examples().join("unsaved.toml").display().to_string();
        st.check_local();
        let info = st.checked.clone().unwrap().unwrap();
        assert_eq!(info.checks.len(), 2);
        assert!(st.dirty());
        assert!(parse_set("a").is_err());
        assert_eq!(parse_set("a=1, b=2").unwrap().len(), 2);
    }
}
