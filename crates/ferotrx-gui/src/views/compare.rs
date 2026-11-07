//! Scenario comparison: two reports side by side, check by check, as
//! `ferotrx scenario compare` prints them. Either side is a run on one of
//! the connected servers or a report file on this computer (from "Save
//! report…", `ferotrx scenario run --report` or a `--history` directory).

use std::path::Path;

use eframe::egui::{self, Color32, RichText};
use ferotrx_core::scenario::{compare, Change, Comparison, ScenarioReport, REPORT_FORMAT};
use serde::{Deserialize, Serialize};

use crate::app::FeroApp;
use crate::files::{Kind, Target};

/// One side of a comparison.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub enum Side {
    /// Nothing picked yet.
    #[default]
    None,
    /// The report of run `id` on the server at `server` (its address).
    Run { server: String, id: u64 },
    /// A report file on this computer.
    File(String),
}

/// The comparison window.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct CompareForm {
    pub open: bool,
    pub before: Side,
    pub after: Side,
    /// Metrics count as moved beyond this share of the earlier value (0.2 = 20%).
    pub tolerance_pct: f64,
    /// A metric moved for the worse counts as a regression.
    pub strict: bool,
    #[serde(skip)]
    pub result: Option<Result<Compared, String>>,
}

impl Default for CompareForm {
    fn default() -> Self {
        Self {
            open: false,
            before: Side::None,
            after: Side::None,
            tolerance_pct: 20.0,
            strict: false,
            result: None,
        }
    }
}

/// A finished comparison and the two reports it came from.
#[derive(Clone, Debug)]
pub struct Compared {
    pub comparison: Comparison,
    pub before: ScenarioReport,
    pub after: ScenarioReport,
}

impl Compared {
    pub fn text(&self) -> String {
        self.comparison.text(&self.before, &self.after)
    }
}

/// Reads a scenario report file.
pub fn read_report(path: &Path) -> Result<ScenarioReport, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let r: ScenarioReport = serde_json::from_str(&text)
        .map_err(|e| format!("{} is not a scenario report: {e}", path.display()))?;
    if r.format != REPORT_FORMAT {
        return Err(format!(
            "{} has format '{}', this GUI reads '{REPORT_FORMAT}'",
            path.display(),
            r.format
        ));
    }
    Ok(r)
}

/// Compares two reports as `ferotrx scenario compare` does.
pub fn compare_reports(
    before: ScenarioReport,
    after: ScenarioReport,
    tolerance_pct: f64,
    strict: bool,
) -> Compared {
    Compared {
        comparison: compare(&before, &after, tolerance_pct / 100.0, strict),
        before,
        after,
    }
}

pub fn change_label(c: Change) -> &'static str {
    match c {
        Change::Same => "same",
        Change::Regressed => "REGRESSED",
        Change::Fixed => "fixed",
        Change::Added => "added",
        Change::Removed => "removed",
        Change::Worse => "WORSE",
    }
}

fn change_color(ui: &egui::Ui, c: Change) -> Color32 {
    match c {
        Change::Regressed | Change::Worse => ui.visuals().error_fg_color,
        Change::Fixed => crate::theme::good(ui),
        Change::Added | Change::Removed => ui.visuals().warn_fg_color,
        Change::Same => ui.visuals().weak_text_color(),
    }
}

impl FeroApp {
    /// The report one side names, from a server's run list or a file.
    fn side_report(&self, side: &Side) -> Result<ScenarioReport, String> {
        match side {
            Side::None => Err("pick a run or a report file for both sides".into()),
            Side::Run { server, id } => self
                .servers
                .iter()
                .find(|s| s.settings.address() == *server)
                .and_then(|s| s.snap.scenarios.iter().find(|r| r.id == *id))
                .ok_or_else(|| format!("run {id} is no longer on {server}"))?
                .report
                .clone()
                .ok_or_else(|| format!("run {id} on {server} has no report yet")),
            Side::File(p) => read_report(Path::new(p)),
        }
    }

    /// Opens the comparison window: the run shown after the one before it
    /// of the same scenario, when there is one.
    pub fn open_compare(&mut self) {
        let f = &mut self.scenario.compare;
        f.open = true;
        f.result = None;
        let Some(s) = self.servers.get(self.sel_server) else {
            return;
        };
        let addr = s.settings.address();
        let done: Vec<_> = s
            .snap
            .scenarios
            .iter()
            .filter(|r| r.report.is_some())
            .collect();
        if let Some(cur) = done
            .iter()
            .find(|r| Some(r.id) == self.scenario.run)
            .or(done.last())
        {
            if f.after == Side::None {
                f.after = Side::Run {
                    server: addr.clone(),
                    id: cur.id,
                };
            }
            if f.before == Side::None {
                if let Some(prev) = done
                    .iter()
                    .rev()
                    .find(|r| r.id < cur.id && r.scenario == cur.scenario)
                {
                    f.before = Side::Run {
                        server: addr,
                        id: prev.id,
                    };
                }
            }
        }
    }

    /// The labels of every run with a report, on every server.
    fn report_runs(&self) -> Vec<(Side, String)> {
        let mut out = Vec::new();
        for s in &self.servers {
            let addr = s.settings.address();
            for r in s.snap.scenarios.iter().rev() {
                if let Some(rep) = &r.report {
                    out.push((
                        Side::Run {
                            server: addr.clone(),
                            id: r.id,
                        },
                        format!(
                            "{} #{} {} {} ({})",
                            s.settings.addr,
                            r.id,
                            r.scenario,
                            rep.started,
                            if rep.passed() { "passed" } else { "failed" }
                        ),
                    ));
                }
            }
        }
        out
    }

    fn side_label(&self, side: &Side, runs: &[(Side, String)]) -> String {
        match side {
            Side::None => "pick…".into(),
            Side::File(p) => Path::new(p)
                .file_name()
                .map_or(p.clone(), |n| n.to_string_lossy().into_owned()),
            s => runs
                .iter()
                .find(|(x, _)| x == s)
                .map_or("a run no longer on the server".into(), |(_, l)| l.clone()),
        }
    }

    pub fn compare_window(&mut self, ctx: &egui::Context) {
        if !self.scenario.compare.open {
            return;
        }
        let runs = self.report_runs();
        let mut open = true;
        let mut pick_file: Option<bool> = None; // true: before
        let mut run_it = false;
        let mut save = false;
        let labels = [
            self.side_label(&self.scenario.compare.before, &runs),
            self.side_label(&self.scenario.compare.after, &runs),
        ];
        egui::Window::new("Compare scenario runs")
            .open(&mut open)
            .default_size([760.0, 480.0])
            .resizable(true)
            .show(ctx, |ui| {
                let f = &mut self.scenario.compare;
                egui::Grid::new("cmp-form").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                    for (n, title) in ["Before", "After"].into_iter().enumerate() {
                        ui.label(title);
                        ui.horizontal(|ui| {
                            let side = if n == 0 { &mut f.before } else { &mut f.after };
                            egui::ComboBox::from_id_salt(("cmp-side", n))
                                .selected_text(labels[n].clone())
                                .width(420.0)
                                .show_ui(ui, |ui| {
                                    if runs.is_empty() {
                                        ui.weak("No finished runs on the connected servers");
                                    }
                                    for (s, l) in &runs {
                                        ui.selectable_value(side, s.clone(), l);
                                    }
                                });
                            if ui.button("Report file…").clicked() {
                                pick_file = Some(n == 0);
                            }
                        });
                        ui.end_row();
                    }
                    ui.label("Tolerance");
                    ui.horizontal(|ui| {
                        ui.add(egui::DragValue::new(&mut f.tolerance_pct).range(0.0..=1000.0).suffix(" %"))
                            .on_hover_text("Metrics that moved by more than this share of the earlier value are listed");
                        ui.checkbox(&mut f.strict, "strict")
                            .on_hover_text("A metric that moved for the worse counts as a regression (--strict)");
                    });
                    ui.end_row();
                });
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("Compare").strong()).clicked() {
                        run_it = true;
                    }
                    if ui.button("⇄ Swap").clicked() {
                        std::mem::swap(&mut f.before, &mut f.after);
                        f.result = None;
                    }
                    let has = matches!(f.result, Some(Ok(_)));
                    if ui.add_enabled(has, egui::Button::new("Save…")).on_hover_text("As text, or JSON when the name ends in .json").clicked() {
                        save = true;
                    }
                    if let Some(Ok(c)) = &f.result {
                        if ui.button("Copy").clicked() {
                            ui.ctx().copy_text(c.text());
                        }
                    }
                });
                ui.separator();
                match &f.result {
                    None => {
                        ui.weak("Pick two runs (or report files) and press Compare. Checks are matched by name, so the two may come from different scenario files or servers.");
                    }
                    Some(Err(e)) => {
                        ui.colored_label(ui.visuals().error_fg_color, e);
                    }
                    Some(Ok(c)) => comparison_view(ui, c),
                }
            });
        self.scenario.compare.open = open;
        if run_it {
            let (b, a) = (
                self.scenario.compare.before.clone(),
                self.scenario.compare.after.clone(),
            );
            let r = self
                .side_report(&b)
                .and_then(|b| Ok((b, self.side_report(&a)?)));
            let f = &mut self.scenario.compare;
            f.result = Some(r.map(|(b, a)| compare_reports(b, a, f.tolerance_pct, f.strict)));
        }
        let f = &self.scenario.compare;
        if let Some(before) = pick_file {
            let cur = match if before { &f.before } else { &f.after } {
                Side::File(p) => p.clone(),
                _ => String::new(),
            };
            self.files.pick(
                Target::CompareReport { before },
                "A scenario report",
                Kind::Report,
                &cur,
            );
        }
        if save {
            self.files.save(
                Target::SaveComparison,
                "Save the comparison",
                Kind::Text,
                "",
                "comparison.txt",
            );
        }
    }

    /// Puts what the file dialog picked for the comparison in place.
    pub fn compare_file(&mut self, target: Target, path: &Path) {
        let f = &mut self.scenario.compare;
        match target {
            Target::CompareReport { before } => {
                let side = Side::File(path.display().to_string());
                if before {
                    f.before = side;
                } else {
                    f.after = side;
                }
                f.result = None;
            }
            Target::SaveComparison => {
                let Some(Ok(c)) = &f.result else { return };
                let json = path.extension().is_some_and(|e| e == "json");
                let body = if json {
                    serde_json::to_string_pretty(&c.comparison).unwrap_or_default() + "\n"
                } else {
                    c.text() + "\n"
                };
                let shown = path.display().to_string();
                match std::fs::write(path, body) {
                    Ok(()) => self.info("", format!("comparison saved in {shown}")),
                    Err(e) => self.error("", format!("{shown}: {e}")),
                }
            }
            _ => {}
        }
    }
}

/// The verdicts and moved metrics, a row per check.
fn comparison_view(ui: &mut egui::Ui, c: &Compared) {
    let cmp = &c.comparison;
    let n = |ch: Change| cmp.checks.iter().filter(|x| x.change == ch).count();
    let reg = cmp.regressions();
    ui.horizontal_wrapped(|ui| {
        ui.colored_label(
            if reg > 0 {
                ui.visuals().error_fg_color
            } else {
                crate::theme::good(ui)
            },
            RichText::new(if reg > 0 {
                format!("✘ {reg} regressed")
            } else {
                "✔ no regressions".into()
            })
            .strong(),
        );
        ui.label(format!(
            "{} fixed, {} worse, {} added, {} removed, {} the same",
            n(Change::Fixed),
            n(Change::Worse),
            n(Change::Added),
            n(Change::Removed),
            n(Change::Same)
        ));
    });
    ui.label(
        RichText::new(format!("before: {}\nafter:  {}", cmp.before, cmp.after))
            .weak()
            .small(),
    );
    let v = |v: Option<ferotrx_core::scenario::Verdict>| v.map_or("–", |v| v.as_str());
    egui::ScrollArea::vertical()
        .id_salt("cmp-rows")
        .show(ui, |ui| {
            egui::Grid::new("cmp-grid")
                .striped(true)
                .num_columns(4)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    ui.strong("Check");
                    ui.strong("Change");
                    ui.strong("Verdict");
                    ui.strong("Metrics moved");
                    ui.end_row();
                    for ch in &cmp.checks {
                        ui.label(format!("{} ({})", ch.name, ch.kind));
                        ui.colored_label(change_color(ui, ch.change), change_label(ch.change));
                        ui.label(format!("{} → {}", v(ch.before), v(ch.after)));
                        let report = c
                            .after
                            .checks
                            .iter()
                            .chain(&c.before.checks)
                            .find(|r| r.name == ch.name);
                        let fmt = |m: &str, x: f64| {
                            report.map_or(x.to_string(), |r| r.format_metric(m, x))
                        };
                        ui.vertical(|ui| {
                            if ch.change == Change::Regressed {
                                if let Some(a) = c.after.checks.iter().find(|a| a.name == ch.name) {
                                    for f in a.failures() {
                                        ui.colored_label(
                                            ui.visuals().error_fg_color,
                                            format!("not met: {f}"),
                                        );
                                    }
                                    if let Some(e) = &a.error {
                                        ui.colored_label(
                                            ui.visuals().error_fg_color,
                                            format!("error: {e}"),
                                        );
                                    }
                                }
                            }
                            for m in &ch.metrics {
                                let rel = m
                                    .relative
                                    .map_or(String::new(), |r| format!(" ({:+.0}%)", r * 100.0));
                                let t = format!(
                                    "{}: {} → {}{rel}",
                                    m.metric,
                                    fmt(&m.metric, m.before),
                                    fmt(&m.metric, m.after)
                                );
                                match m.worse {
                                    Some(true) => {
                                        ui.colored_label(ui.visuals().warn_fg_color, t + " worse")
                                    }
                                    Some(false) => {
                                        ui.colored_label(crate::theme::good(ui), t + " better")
                                    }
                                    None => ui.label(t),
                                };
                            }
                        });
                        ui.end_row();
                    }
                });
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferotrx_core::scenario::{CheckReport, Verdict};

    fn report(verdicts: &[(&str, Verdict)]) -> ScenarioReport {
        let mut r: ScenarioReport = serde_json::from_value(serde_json::json!({
            "format": REPORT_FORMAT,
            "scenario": "lab",
            "started": "2026-11-05T00:00:00Z",
            "version": "0",
            "started_unix": 0.0,
            "elapsed_s": 1.0,
            "stopped": false,
            "summary": {"checks": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0},
            "checks": []
        }))
        .expect("a minimal report");
        for (name, v) in verdicts {
            let mut c: CheckReport = serde_json::from_value(serde_json::json!({
                "name": name, "kind": "tcp", "expect": "complete", "verdict": "pass",
                "attempts": 1, "elapsed_s": 1.0
            }))
            .expect("a minimal check");
            c.verdict = *v;
            r.checks.push(c);
        }
        r
    }

    #[test]
    fn regressions_found_and_files_read() {
        let before = report(&[("web", Verdict::Pass), ("dns", Verdict::Fail)]);
        let after = report(&[
            ("web", Verdict::Fail),
            ("dns", Verdict::Pass),
            ("ntp", Verdict::Pass),
        ]);
        let c = compare_reports(before.clone(), after, 20.0, false);
        assert_eq!(c.comparison.regressions(), 1);
        let ch = |n: &str| {
            c.comparison
                .checks
                .iter()
                .find(|x| x.name == n)
                .unwrap()
                .change
        };
        assert_eq!(ch("web"), Change::Regressed);
        assert_eq!(ch("dns"), Change::Fixed);
        assert_eq!(ch("ntp"), Change::Added);
        assert!(c.text().contains("REGRESSED"));

        let dir = std::env::temp_dir().join(format!("ftrx-cmp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("before.json");
        std::fs::write(&p, serde_json::to_string(&before).unwrap()).unwrap();
        assert_eq!(read_report(&p).unwrap().checks.len(), 2);
        std::fs::write(&p, "{}").unwrap();
        assert!(read_report(&p).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
