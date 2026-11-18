//! The plan's captures on the agents: started before the runs, stopped
//! after them, fetched and merged on the controller.

use std::time::Duration;

use ferotrx_core::fleet::FleetPlan;
use ferotrx_core::Result;

use super::{agent_index, failed, Agent, CaptureRecord, Slot};
use crate::protocol::*;
use crate::Client;

/// What has a control connection to an agent, while it is reachable.
pub(super) trait HasClient {
    fn client(&mut self) -> Option<&mut Client>;
}

impl HasClient for Agent {
    fn client(&mut self) -> Option<&mut Client> {
        Some(&mut self.client)
    }
}

impl HasClient for Slot {
    fn client(&mut self) -> Option<&mut Client> {
        if self.up() {
            Some(&mut self.agent.client)
        } else {
            None
        }
    }
}

/// A capture of the plan, on its agent.
pub(super) struct Capturing {
    agent: usize,
    id: Option<u64>,
    pub(super) record: CaptureRecord,
}

/// Starts the plan's captures, before the runs so they see the start. Each
/// writes `deploy_dir/captures/NAME.pcap` on its agent.
pub(super) fn start_captures(plan: &FleetPlan, agents: &mut [Agent]) -> Result<Vec<Capturing>> {
    let mut out: Vec<Capturing> = Vec::new();
    for c in &plan.captures {
        let a = agent_index(agents, &c.agent);
        // With `/` whatever the controller's system: the agent may be another.
        let mut parts: Vec<String> = plan
            .deploy_dir
            .components()
            .map(|p| p.as_os_str().to_string_lossy().into_owned())
            .collect();
        parts.push("captures".into());
        parts.push(format!("{}.pcap", c.name));
        let file = std::path::PathBuf::from(parts.join("/"));
        let got = agents[a].client.capture_start(&CaptureStartParams {
            iface: c.iface.clone(),
            filter: c.filter.clone(),
            snaplen: c.snaplen,
            file: Some(file.clone()),
            stream: Some(false),
            ..Default::default()
        });
        match got {
            Ok(info) => out.push(Capturing {
                agent: a,
                id: Some(info.id),
                record: CaptureRecord {
                    agent: c.agent.clone(),
                    iface: c.iface.clone(),
                    filter: c.filter.clone(),
                    file: file.display().to_string(),
                    ..Default::default()
                },
            }),
            Err(e) => {
                stop_captures(agents, &mut out, true);
                return Err(failed(format!(
                    "capture on {} of '{}': {e}",
                    c.iface, c.agent
                )));
            }
        }
    }
    Ok(out)
}

/// Stops the captures and reads their counters; with `remove`, forgets
/// them on the agents (their files stay).
pub(super) fn stop_captures<A: HasClient>(
    agents: &mut [A],
    captures: &mut [Capturing],
    remove: bool,
) {
    for c in captures.iter_mut() {
        let Some(id) = c.id else { continue };
        let Some(client) = agents[c.agent].client() else {
            c.record.error.get_or_insert("the agent was lost".into());
            continue;
        };
        match client.capture_stop(id) {
            Ok(i) => {
                c.record.frames = i.frames;
                c.record.bytes = i.bytes;
                c.record.dropped = i.dropped;
                c.record.if_dropped = i.if_dropped;
                if let Some(e) = i.error {
                    c.record.error.get_or_insert(e);
                }
            }
            Err(e) => {
                c.record.error.get_or_insert(e.to_string());
            }
        }
        if remove {
            let _ = client.capture_remove(id);
        }
    }
}

/// Fetches each capture's pcap into `dir` as `AGENT-IFACE.pcap`.
pub(super) fn collect_captures(
    slots: &mut [Slot],
    captures: &mut [Capturing],
    dir: &std::path::Path,
) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        for c in captures.iter_mut() {
            c.record
                .error
                .get_or_insert(format!("cannot make {}: {e}", dir.display()));
        }
        return;
    }
    for c in captures.iter_mut() {
        if c.record.error.is_some() {
            continue;
        }
        let name = std::path::Path::new(&c.record.file)
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        let local = dir.join(name);
        let Some(client) = slots[c.agent].client() else {
            c.record.error = Some("the agent was lost".into());
            continue;
        };
        let got = client
            .download(&c.record.file)
            .map_err(|e| e.to_string())
            .and_then(|data| {
                std::fs::write(&local, data)
                    .map_err(|e| format!("cannot write {}: {e}", local.display()))
            });
        match got {
            Ok(()) => c.record.collected = Some(local.display().to_string()),
            Err(e) => c.record.error = Some(e),
        }
    }
}

/// Merges the collected captures into one pcapng: one interface per
/// capture (named `AGENT:IFACE`), every frame's time moved from its agent's
/// clock to the controller's, in time order. Returns the frames written.
pub(super) fn merge_captures(
    slots: &[Slot],
    captures: &[Capturing],
    out: &std::path::Path,
) -> std::result::Result<u64, String> {
    use ferotrx_core::{Capture, PcapngWriter};
    let mut inputs = Vec::new();
    for c in captures {
        let Some(path) = &c.record.collected else {
            continue;
        };
        let cap = Capture::from_path(path).map_err(|e| format!("{path}: {e}"))?;
        inputs.push((c, cap));
    }
    if inputs.is_empty() {
        return Err("no capture was fetched".into());
    }
    let file = std::fs::File::create(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let mut w = PcapngWriter::new(std::io::BufWriter::new(file), "FeroTRX fleet")
        .map_err(|e| e.to_string())?;
    // (time on the controller's clock in ns, input, packet)
    let mut all: Vec<(i128, usize, usize)> = Vec::new();
    for (i, (c, cap)) in inputs.iter().enumerate() {
        let name = format!("{}:{}", c.record.agent, c.record.iface);
        w.add_interface(cap.linktype, ferotrx_core::live::DEFAULT_SNAPLEN, &name)
            .map_err(|e| e.to_string())?;
        let offset_ns = (slots[c.agent].agent.offset * 1e9) as i128;
        for (p, pkt) in cap.packets.iter().enumerate() {
            all.push((pkt.timestamp.as_nanos() as i128 - offset_ns, i, p));
        }
    }
    all.sort();
    for (t, i, p) in &all {
        let pkt = &inputs[*i].1.packets[*p];
        let frame = ferotrx_core::Frame {
            ts: Duration::from_nanos((*t).max(0) as u64),
            len: pkt.data.len() as u32,
            data: pkt.data.clone(),
        };
        w.write(*i as u32, &frame).map_err(|e| e.to_string())?;
    }
    w.flush().map_err(|e| e.to_string())?;
    Ok(all.len() as u64)
}
