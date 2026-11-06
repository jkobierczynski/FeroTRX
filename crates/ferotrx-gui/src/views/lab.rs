//! The lab router window: build, change and remove the lab router of a
//! server (`lab.start`, `lab.stop`), so that the lab examples run as they
//! are on a single machine.

use eframe::egui::{self, RichText};
use serde_json::{json, Value};

use crate::app::{FeroApp, Pending};

/// The form of the lab window, for one server.
#[derive(Clone, Debug)]
pub struct LabForm {
    pub server: usize,
    pub ipv6: bool,
    pub nat: bool,
    /// Percent of forwarded packets to drop.
    pub loss: String,
    pub delay: String,
    /// Ports, separated by commas or spaces.
    pub block_tcp: String,
    pub block_udp: String,
    pub dhcp: bool,
    /// Queues on each end of the link, for workers with AF_XDP.
    pub queues: String,
}

impl LabForm {
    pub fn new(server: usize) -> Self {
        Self {
            server,
            ipv6: true,
            nat: true,
            loss: String::new(),
            delay: String::new(),
            block_tcp: String::new(),
            block_udp: String::new(),
            dhcp: false,
            queues: String::new(),
        }
    }

    /// `lab.start` parameters.
    pub fn params(&self) -> Result<Value, String> {
        let ports = |v: &str, what: &str| -> Result<Vec<u16>, String> {
            v.split(|c: char| c == ',' || c.is_whitespace())
                .filter(|p| !p.is_empty())
                .map(|p| {
                    p.parse::<u16>()
                        .map_err(|_| format!("{what}: '{p}' is not a port"))
                })
                .collect()
        };
        let loss = match self.loss.trim().trim_end_matches('%') {
            "" => None,
            l => {
                let pct: f64 = l
                    .parse()
                    .map_err(|_| format!("loss: '{l}' is not a number"))?;
                if !(0.0..=100.0).contains(&pct) {
                    return Err("loss is a percentage, 0 to 100".into());
                }
                Some(pct / 100.0)
            }
        };
        let mut p = json!({
            "ipv6": self.ipv6,
            "nat": self.nat,
            "dhcp": self.dhcp,
            "block_tcp": ports(&self.block_tcp, "TCP ports")?,
            "block_udp": ports(&self.block_udp, "UDP ports")?,
        });
        if let Some(l) = loss {
            p["loss"] = json!(l);
        }
        match self.queues.trim() {
            "" => {}
            q => {
                let n: u32 = q
                    .parse()
                    .ok()
                    .filter(|n| (1..=64).contains(n))
                    .ok_or_else(|| format!("queues: '{q}' is not a number from 1 to 64"))?;
                p["queues"] = json!(n);
            }
        }
        if !self.delay.trim().is_empty() {
            p["delay"] = json!(self.delay.trim());
        }
        Ok(p)
    }
}

const TOPOLOGY: &str = "\
this server            router (namespace ferotrx-lab)
ftrx-lab --- trunk --- rt.10  192.168.10.1/24  fd00:10::1
  VLAN 10: clients     rt.20  192.168.20.1/24  fd00:20::1
  VLAN 20: servers     routes, tracks, NAT to VLAN 20";

impl FeroApp {
    pub fn lab_window(&mut self, ctx: &egui::Context) {
        let Some(form) = &mut self.lab_form else {
            return;
        };
        let i = form.server;
        let Some(server) = self.servers.get(i) else {
            self.lab_form = None;
            return;
        };
        let addr = server.settings.addr.clone();
        let lab = server.lab.clone().unwrap_or_default();
        let lab_error = server.lab_error.clone();
        let can = server.can_operate();
        let mut open = true;
        let mut start = false;
        let mut stop = false;
        egui::Window::new(format!("Lab router on {addr}"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(520.0)
            .show(ctx, |ui| {
                ui.label(
                    "A router on the server, in a Linux network namespace, that the lab \
                     examples (examples/lab-*.toml) fit as they are: send on ftrx-lab.",
                );
                ui.add_space(4.0);
                ui.add(egui::Label::new(RichText::new(TOPOLOGY).monospace()).extend());
                ui.add_space(6.0);
                if let Some(why) = &lab.unavailable {
                    ui.colored_label(ui.visuals().warn_fg_color, why);
                }
                egui::Grid::new("lab-form").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                    ui.label("Addresses");
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut form.ipv6, "IPv6 too");
                        ui.checkbox(&mut form.nat, "NAT towards the servers");
                    });
                    ui.end_row();
                    ui.label("Loss");
                    ui.add(egui::TextEdit::singleline(&mut form.loss).hint_text("0 %").desired_width(80.0))
                        .on_hover_text("Percent of the forwarded packets the router drops");
                    ui.end_row();
                    ui.label("Delay");
                    ui.add(egui::TextEdit::singleline(&mut form.delay).hint_text("none, or 5ms, 20ms 5ms").desired_width(160.0))
                        .on_hover_text("tc netem delay on each router link (needs sch_netem)");
                    ui.end_row();
                    ui.label("Reset TCP to ports");
                    ui.add(egui::TextEdit::singleline(&mut form.block_tcp).hint_text("e.g. 80").desired_width(160.0))
                        .on_hover_text("A firewall rule: see a test fail on purpose");
                    ui.end_row();
                    ui.label("Drop UDP to ports");
                    ui.add(egui::TextEdit::singleline(&mut form.block_udp).hint_text("e.g. 53").desired_width(160.0));
                    ui.end_row();
                    ui.label("DHCP");
                    ui.checkbox(&mut form.dhcp, "on VLAN 10, 192.168.10.200-250 (dnsmasq)")
                        .on_hover_text("For hosts with ip = \"dhcp\" (examples/lab-tcp-dhcp.toml); with IPv6 also router advertisements and DHCPv6");
                    ui.end_row();
                    ui.label("Queues");
                    ui.add(egui::TextEdit::singleline(&mut form.queues).hint_text("1").desired_width(80.0))
                        .on_hover_text("Queues on each end of the ftrx-lab link: as many as the workers of an AF_XDP run (Port settings or Stateful: Workers, backend af_xdp)");
                    ui.end_row();
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let ok = can && lab.unavailable.is_none();
                    let label = if lab.running { "Rebuild" } else { "▶ Start the lab" };
                    if ui.add_enabled(ok, egui::Button::new(RichText::new(label).strong())).clicked() {
                        start = true;
                    }
                    if ui.add_enabled(can && lab.running, egui::Button::new("■ Remove the lab")).clicked() {
                        stop = true;
                    }
                });
                if let Some(e) = &lab_error {
                    ui.colored_label(ui.visuals().error_fg_color, e);
                }
                ui.separator();
                if lab.running {
                    ui.colored_label(crate::theme::good(ui), "● running");
                    for l in &lab.summary {
                        ui.label(l);
                    }
                    for n in &lab.notes {
                        ui.colored_label(ui.visuals().warn_fg_color, n);
                    }
                    ui.label(
                        RichText::new(
                            "Pick the port ftrx-lab for streams, or interface ftrx-lab in the \
                             Stateful tab, and open a lab example.",
                        )
                        .weak(),
                    );
                } else {
                    ui.weak("Not running.");
                }
            });
        if start {
            match form.params() {
                Ok(p) => self.call(i, "lab.start", p, Pending::Lab("lab router built".into())),
                Err(e) => self.error(&addr, e),
            }
        }
        if stop {
            self.call(
                i,
                "lab.stop",
                Value::Null,
                Pending::Lab("lab router removed".into()),
            );
        }
        if !open {
            self.lab_form = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_match_the_server_types() {
        let mut f = LabForm::new(0);
        f.loss = "3%".into();
        f.block_tcp = "80, 443".into();
        f.delay = "5ms".into();
        let p: ferotrx_ctl::protocol::LabStartParams =
            serde_json::from_value(f.params().unwrap()).unwrap();
        assert_eq!(p.loss, Some(0.03));
        assert_eq!(p.block_tcp, vec![80, 443]);
        assert_eq!(p.delay.as_deref(), Some("5ms"));
        assert_eq!(p.ipv6, Some(true));
        assert_eq!(p.queues, None);
        f.queues = "4".into();
        let p: ferotrx_ctl::protocol::LabStartParams =
            serde_json::from_value(f.params().unwrap()).unwrap();
        assert_eq!(p.queues, Some(4));
        f.queues = "0".into();
        assert!(f.params().is_err());
        f.queues.clear();
        f.block_udp = "dns".into();
        assert!(f.params().is_err());
        f.block_udp.clear();
        f.loss = "200".into();
        assert!(f.params().is_err());
    }
}
