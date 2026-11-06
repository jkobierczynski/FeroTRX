//! The Stateful tab: start TCP session and UDP transaction runs from their
//! profiles, on the selected server.

use std::path::Path;

use eframe::egui::{self, RichText};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::app::{FeroApp, Pending, Status};
use crate::model::PortKind;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Tcp,
    Udp,
}

impl Kind {
    pub fn method(self) -> &'static str {
        match self {
            Kind::Tcp => "tcp",
            Kind::Udp => "udp",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StatefulState {
    pub kind: Kind,
    /// Upload a file from this computer, or name one on the server.
    pub upload: bool,
    pub path: String,
    pub iface: String,
    pub backend: String,
    /// cps (TCP) or transactions per second (UDP).
    pub rate: String,
    /// connections (TCP) or transactions (UDP).
    pub count: String,
    pub concurrency: String,
    pub duration: String,
    pub workers: String,
    /// TCP: `newreno` or `cubic`; empty is the profile's.
    pub congestion: String,
    /// TCP: `on` or `off`; empty is the profile's.
    pub ecn: String,
    #[serde(skip)]
    pub check: Option<Result<String, String>>,
}

/// What the Profile row asked for.
enum Browse {
    Local,
    Server,
}

impl StatefulState {
    /// `tcp.start` / `udp.start` parameters; reads the file when uploading.
    /// A server on this computer (`local`) reads the relative paths of an
    /// uploaded profile from the profile's own folder, as `ferotrx tcp` does.
    pub fn params_for(&self, local: bool) -> Result<Value, String> {
        let mut p = self.params()?;
        if local && self.upload {
            p["base_dir"] = crate::files::folder_of(Path::new(self.path.trim())).into();
        }
        Ok(p)
    }

    pub fn params(&self) -> Result<Value, String> {
        let mut p = Map::new();
        if self.path.trim().is_empty() {
            return Err("name a profile file".into());
        }
        if self.upload {
            let text = std::fs::read_to_string(self.path.trim())
                .map_err(|e| format!("{}: {e}", self.path))?;
            p.insert("toml".into(), text.into());
        } else {
            p.insert("path".into(), self.path.trim().into());
        }
        if !self.iface.is_empty() {
            p.insert("iface".into(), self.iface.clone().into());
        }
        if !self.backend.is_empty() {
            p.insert("backend".into(), self.backend.clone().into());
        }
        let num = |v: &str, what: &str| -> Result<Option<f64>, String> {
            let v = v.trim();
            if v.is_empty() {
                return Ok(None);
            }
            v.parse::<f64>()
                .map(Some)
                .map_err(|_| format!("{what}: '{v}' is not a number"))
        };
        let (rate_key, count_key) = match self.kind {
            Kind::Tcp => ("cps", "connections"),
            Kind::Udp => ("rate", "transactions"),
        };
        if let Some(r) = num(&self.rate, rate_key)? {
            p.insert(rate_key.into(), json!(r));
        }
        if let Some(c) = num(&self.count, count_key)? {
            p.insert(count_key.into(), json!(c as u64));
        }
        if let Some(c) = num(&self.concurrency, "concurrency")? {
            p.insert("concurrency".into(), json!(c as u64));
        }
        if !self.duration.trim().is_empty() {
            p.insert("duration".into(), self.duration.trim().into());
        }
        if let Some(w) = num(&self.workers, "workers")? {
            p.insert("workers".into(), json!(w as u64));
        }
        if self.kind == Kind::Tcp {
            if !self.congestion.is_empty() {
                p.insert("congestion".into(), self.congestion.clone().into());
            }
            if !self.ecn.is_empty() {
                p.insert("ecn".into(), (self.ecn == "on").into());
            }
        }
        Ok(p.into())
    }

    /// Checks a local file as `ferotrx check` does.
    pub fn check_local(&mut self) {
        let kind = match self.kind {
            Kind::Tcp => ferotrx_core::check::FileKind::Tcp,
            Kind::Udp => ferotrx_core::check::FileKind::Udp,
        };
        self.check = Some(
            ferotrx_core::check::check_file(Path::new(self.path.trim()), Some(kind), &[])
                .map(|c| {
                    let mut lines = c.summary;
                    lines.extend(c.warnings.into_iter().map(|w| format!("warning: {w}")));
                    lines.join("\n")
                })
                .map_err(|e| e.to_string()),
        );
    }
}

impl FeroApp {
    pub fn stateful_tab(&mut self, ui: &mut egui::Ui) {
        let i = self.sel_server;
        let Some(server) = self.servers.get(i) else {
            return;
        };
        let connected = server.status == Status::Connected && server.can_operate();
        let ifaces: Vec<String> = server.interfaces.iter().map(|x| x.name.clone()).collect();
        let backends = server
            .info
            .as_ref()
            .map(|i| i.backends.clone())
            .unwrap_or_default();
        let addr = server.settings.addr.clone();
        let local = server.settings.is_local();
        let mut browse = None;
        if let Some(PortKind::Interface(n)) = &self.sel_port {
            if self.stateful.iface.is_empty() {
                self.stateful.iface = n.clone();
            }
        }
        let st = &mut self.stateful;
        let mut start = false;
        ui.heading(format!("Stateful runs on {addr}"));
        ui.label(
            RichText::new(
                "Both ends of every session are emulated on one interface (own MACs and addresses); \
                 the device under test sits between them. Profiles: docs/stateful-tcp.md and docs/stateful-udp.md.",
            )
            .weak(),
        );
        ui.add_space(6.0);
        egui::Grid::new("stateful").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
            ui.label("Kind");
            ui.horizontal(|ui| {
                ui.radio_value(&mut st.kind, Kind::Tcp, "TCP sessions");
                ui.radio_value(&mut st.kind, Kind::Udp, "UDP transactions (DNS, NTP, replays)");
            });
            ui.end_row();
            ui.label("Profile");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut st.path).hint_text("examples/lab-tcp.toml").desired_width(320.0));
                if ui
                    .add_enabled(st.upload || local, egui::Button::new("Browse…"))
                    .on_disabled_hover_text("The server is on another computer: type a path there, or tick “from this computer”")
                    .clicked()
                {
                    browse = Some(if st.upload { Browse::Local } else { Browse::Server });
                }
                ui.checkbox(&mut st.upload, "from this computer")
                    .on_hover_text("Upload the file; otherwise the path is on the server, relative to its data directory");
                if st.upload && ui.button("Check").clicked() {
                    st.check_local();
                }
            });
            ui.end_row();
            ui.label("Interface");
            egui::ComboBox::from_id_salt("st-iface")
                .selected_text(if st.iface.is_empty() { "from the profile" } else { &st.iface })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut st.iface, String::new(), "from the profile");
                    for n in &ifaces {
                        ui.selectable_value(&mut st.iface, n.clone(), n);
                    }
                });
            ui.end_row();
            ui.label("Backend");
            egui::ComboBox::from_id_salt("st-backend")
                .selected_text(if st.backend.is_empty() { "default" } else { &st.backend })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut st.backend, String::new(), "default");
                    for b in &backends {
                        ui.selectable_value(&mut st.backend, b.clone(), b);
                    }
                });
            ui.end_row();
            let (rate, count) = match st.kind {
                Kind::Tcp => ("Connections per second", "Connections"),
                Kind::Udp => ("Transactions per second", "Transactions"),
            };
            for (label, v, hint) in [
                (rate, &mut st.rate, "from the profile"),
                (count, &mut st.count, "from the profile"),
                ("Concurrency", &mut st.concurrency, "from the profile"),
                ("Duration", &mut st.duration, "until done"),
                ("Workers", &mut st.workers, "1"),
            ] {
                ui.label(label);
                ui.add(egui::TextEdit::singleline(v).hint_text(hint).desired_width(140.0));
                ui.end_row();
            }
            if st.kind == Kind::Tcp {
                for (label, v, id, choices) in [
                    ("Congestion control", &mut st.congestion, "st-cc", &["newreno", "cubic"]),
                    ("ECN", &mut st.ecn, "st-ecn", &["on", "off"]),
                ] {
                    ui.label(label);
                    egui::ComboBox::from_id_salt(id)
                        .selected_text(if v.is_empty() { "from the profile" } else { v.as_str() })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(v, String::new(), "from the profile");
                            for c in choices {
                                ui.selectable_value(v, c.to_string(), *c);
                            }
                        });
                    ui.end_row();
                }
            }
        });
        ui.add_enabled_ui(connected, |ui| {
            if ui.button(RichText::new("▶ Start").strong()).clicked() {
                start = true;
            }
        });
        if let Some(c) = &st.check {
            match c {
                Ok(s) => {
                    ui.colored_label(crate::theme::good(ui), "✔ the profile checks out");
                    ui.monospace(s);
                }
                Err(e) => {
                    ui.colored_label(ui.visuals().error_fg_color, e);
                }
            }
        }
        if start {
            let method = format!("{}.start", st.kind.method());
            match st.params_for(local) {
                Ok(p) => {
                    let what = format!("{method} sent");
                    self.call(i, &method, p, Pending::Done(what));
                }
                Err(e) => self.error(&addr, e),
            }
        }
        if let Some(b) = browse {
            let title = match b {
                Browse::Local => "Profile on this computer",
                Browse::Server => "Profile on the server",
            };
            let current = self.stateful.path.clone();
            self.files.pick(
                crate::files::Target::StatefulProfile,
                title,
                crate::files::Kind::Profile,
                &current,
            );
        }
        ui.add_space(10.0);
        ui.separator();
        ui.label(RichText::new("Running and finished runs are in Statistics below.").weak());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_match_the_server_types() {
        let st = StatefulState {
            kind: Kind::Tcp,
            path: "examples/lab-tcp.toml".into(),
            iface: "veth0".into(),
            rate: "200".into(),
            count: "1000".into(),
            duration: "10s".into(),
            workers: "2".into(),
            congestion: "cubic".into(),
            ecn: "on".into(),
            ..Default::default()
        };
        let p = st.params().unwrap();
        let t: ferotrx_ctl::protocol::TcpStartParams = serde_json::from_value(p).unwrap();
        assert_eq!(
            (t.congestion.as_deref(), t.ecn),
            (Some("cubic"), Some(true))
        );
        assert_eq!(t.cps, Some(200.0));
        assert_eq!(t.connections, Some(1000));
        assert_eq!(t.workers, Some(2));
        let st = StatefulState {
            kind: Kind::Udp,
            rate: "50".into(),
            count: "9".into(),
            ..st
        };
        let u: ferotrx_ctl::protocol::UdpStartParams =
            serde_json::from_value(st.params().unwrap()).unwrap();
        assert_eq!(u.rate, Some(50.0));
        assert_eq!(u.transactions, Some(9));
        assert!(StatefulState {
            rate: "fast".into(),
            ..st
        }
        .params()
        .is_err());
    }

    #[test]
    fn local_checks_use_the_engine() {
        let dir = env!("CARGO_MANIFEST_DIR");
        let mut st = StatefulState {
            kind: Kind::Tcp,
            upload: true,
            path: format!("{dir}/../../examples/lab-tcp.toml"),
            ..Default::default()
        };
        st.check_local();
        assert!(matches!(st.check, Some(Ok(_))), "{:?}", st.check);
        st.kind = Kind::Udp;
        st.check_local();
        assert!(matches!(st.check, Some(Err(_))));
    }
}
