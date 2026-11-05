//! What the GUI edits, apart from any widget: streams, the ports they are
//! sent on, and the TOML profiles they turn into.
//!
//! A port's streams become an ordinary FeroTRX profile (`[[stream]]` tables),
//! uploaded with `profile.load` and started with `run.start`, so whatever the
//! GUI sends can be saved and sent again with `ferotrx run`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use toml::{Table, Value};

/// Where a stream's packets come from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceKind {
    /// Packets built from the text form, edited layer by layer.
    #[default]
    Packets,
    /// A capture file on the server (relative to its data directory).
    Pcap,
}

/// How a stream is paced.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Pacing {
    /// `rate`: `100pps`, `20mbps`, `2x` (pcap timing twice as fast).
    #[default]
    Rate,
    /// `interval` between packets: `1s`, `10ms`.
    Interval,
    /// A pcap's own timing (no rate).
    Original,
}

/// Loss and latency signatures for a stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Latency {
    #[default]
    Off,
    On,
    Flow(u32),
}

/// One stream as the editor holds it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct StreamDraft {
    pub name: String,
    /// Sent when the port starts. Not part of the profile file.
    pub enabled: bool,
    pub source: SourceKind,
    /// Packets in the text form, one per entry, sent in turn.
    pub packets: Vec<String>,
    pub pcap: String,
    pub pacing: Pacing,
    pub rate: String,
    pub interval: String,
    /// Times through the packets; 0 loops until the run ends.
    pub loops: u64,
    pub limit: Option<u64>,
    pub delay: String,
    pub rewrite: Vec<String>,
    pub vary: Vec<String>,
    pub latency: Latency,
    pub sizes: String,
    pub model: String,
    pub shape: Vec<String>,
    /// Keys of a loaded `[[stream]]` this editor does not know, written back
    /// unchanged.
    pub extra: BTreeMap<String, String>,
}

impl Default for StreamDraft {
    fn default() -> Self {
        Self {
            name: "stream".into(),
            enabled: true,
            source: SourceKind::Packets,
            packets: vec!["eth/ipv4/udp(dport=9)/raw(len=18)".into()],
            pcap: String::new(),
            pacing: Pacing::Rate,
            rate: "10pps".into(),
            interval: "1s".into(),
            loops: 0,
            limit: None,
            delay: String::new(),
            rewrite: Vec::new(),
            vary: Vec::new(),
            latency: Latency::Off,
            sizes: String::new(),
            model: String::new(),
            shape: Vec::new(),
            extra: BTreeMap::new(),
        }
    }
}

impl StreamDraft {
    /// A short description of the source for the stream table.
    pub fn source_summary(&self) -> String {
        match self.source {
            SourceKind::Pcap => format!("pcap {}", self.pcap),
            SourceKind::Packets => match self.packets.as_slice() {
                [] => "no packets".into(),
                [one] => one.clone(),
                [first, rest @ ..] => format!("{first} (+{} more)", rest.len()),
            },
        }
    }

    pub fn pacing_summary(&self) -> String {
        match self.pacing {
            Pacing::Rate => self.rate.clone(),
            Pacing::Interval => format!("every {}", self.interval),
            Pacing::Original => "pcap timing".into(),
        }
    }

    /// The stream as a `[[stream]]` table.
    pub fn to_table(&self) -> Table {
        let mut t = Table::new();
        let s = |v: &str| Value::String(v.to_string());
        let list = |v: &[String]| Value::Array(v.iter().map(|x| s(x)).collect());
        t.insert("name".into(), s(&self.name));
        match self.source {
            SourceKind::Pcap => {
                t.insert("pcap".into(), s(&self.pcap));
            }
            SourceKind::Packets if self.packets.len() == 1 => {
                t.insert("packet".into(), s(&self.packets[0]));
            }
            SourceKind::Packets => {
                t.insert("packets".into(), list(&self.packets));
            }
        }
        match self.pacing {
            Pacing::Rate if !self.rate.trim().is_empty() => {
                t.insert("rate".into(), s(self.rate.trim()));
            }
            Pacing::Interval if !self.interval.trim().is_empty() => {
                t.insert("interval".into(), s(self.interval.trim()));
            }
            _ => {}
        }
        t.insert("loops".into(), Value::Integer(self.loops as i64));
        if let Some(l) = self.limit {
            t.insert("limit".into(), Value::Integer(l as i64));
        }
        let mut opt = |k: &str, v: &str| {
            if !v.trim().is_empty() {
                t.insert(k.into(), s(v.trim()));
            }
        };
        opt("delay", &self.delay);
        opt("sizes", &self.sizes);
        opt("model", &self.model);
        let clean = |v: &[String]| -> Vec<String> {
            v.iter()
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        };
        for (k, v) in [
            ("rewrite", clean(&self.rewrite)),
            ("vary", clean(&self.vary)),
            ("shape", clean(&self.shape)),
        ] {
            if !v.is_empty() {
                t.insert(k.into(), list(&v));
            }
        }
        match self.latency {
            Latency::Off => {}
            Latency::On => {
                t.insert("latency".into(), Value::Boolean(true));
            }
            Latency::Flow(f) => {
                t.insert("latency".into(), Value::Integer(f.into()));
            }
        }
        for (k, v) in &self.extra {
            if let Ok(v) = v.parse::<Value>() {
                t.insert(k.clone(), v);
            } else if let Ok(t2) = format!("x = {v}").parse::<Table>() {
                if let Some(v) = t2.get("x") {
                    t.insert(k.clone(), v.clone());
                }
            }
        }
        t
    }

    /// Reads a `[[stream]]` table. Unknown keys go to `extra`.
    pub fn from_table(t: &Table) -> Result<Self, String> {
        let mut d = StreamDraft {
            packets: Vec::new(),
            rate: String::new(),
            interval: String::new(),
            pacing: Pacing::Original,
            ..Default::default()
        };
        let str_of = |k: &str, v: &Value| -> Result<String, String> {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("stream key {k}: expected a string"))
        };
        let list_of = |k: &str, v: &Value| -> Result<Vec<String>, String> {
            v.as_array()
                .ok_or_else(|| format!("stream key {k}: expected a list"))?
                .iter()
                .map(|x| str_of(k, x))
                .collect()
        };
        let int_of = |k: &str, v: &Value| -> Result<u64, String> {
            v.as_integer()
                .and_then(|i| u64::try_from(i).ok())
                .ok_or_else(|| format!("stream key {k}: expected a number"))
        };
        for (k, v) in t {
            match k.as_str() {
                "name" => d.name = str_of(k, v)?,
                "pcap" => {
                    d.source = SourceKind::Pcap;
                    d.pcap = str_of(k, v)?;
                }
                "packet" => d.packets.insert(0, str_of(k, v)?),
                "packets" => d.packets.extend(list_of(k, v)?),
                "rate" => {
                    d.pacing = Pacing::Rate;
                    d.rate = str_of(k, v)?;
                }
                "interval" => {
                    d.pacing = Pacing::Interval;
                    d.interval = str_of(k, v)?;
                }
                "loops" => d.loops = int_of(k, v)?,
                "limit" => d.limit = Some(int_of(k, v)?),
                "delay" => d.delay = str_of(k, v)?,
                "rewrite" => d.rewrite = list_of(k, v)?,
                "vary" => d.vary = list_of(k, v)?,
                "shape" => d.shape = list_of(k, v)?,
                "sizes" => d.sizes = str_of(k, v)?,
                "model" => d.model = str_of(k, v)?,
                "latency" => {
                    d.latency = match v {
                        Value::Boolean(true) => Latency::On,
                        Value::Boolean(false) => Latency::Off,
                        v => Latency::Flow(
                            u32::try_from(int_of(k, v)?)
                                .map_err(|_| "latency: flow id too large".to_string())?,
                        ),
                    }
                }
                _ => {
                    d.extra.insert(k.clone(), v.to_string());
                }
            }
        }
        if d.rate.is_empty() {
            d.rate = "10pps".into();
        }
        if d.interval.is_empty() {
            d.interval = "1s".into();
        }
        // A built stream without rate or interval gets the profile default
        // of one packet a second; show it as such.
        if d.source == SourceKind::Packets && d.pacing == Pacing::Original {
            d.pacing = Pacing::Interval;
        }
        Ok(d)
    }
}

/// The streams of one port, and the profile keys around them.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProfileDraft {
    pub streams: Vec<StreamDraft>,
    /// The `[output]` table of a loaded profile, kept as TOML text.
    pub output: Option<String>,
}

impl ProfileDraft {
    /// The profile file. `enabled_only` leaves out disabled streams, as a run does.
    pub fn to_toml(&self, enabled_only: bool) -> String {
        let mut root = Table::new();
        root.insert("format".into(), Value::Integer(1));
        if let Some(out) = self.output.as_deref().and_then(|o| o.parse::<Table>().ok()) {
            root.insert("output".into(), Value::Table(out));
        }
        let streams: Vec<Value> = self
            .streams
            .iter()
            .filter(|s| s.enabled || !enabled_only)
            .map(|s| Value::Table(s.to_table()))
            .collect();
        root.insert("stream".into(), Value::Array(streams));
        let body = toml::to_string_pretty(&root).unwrap_or_default();
        format!(
            "# Written by ferotrx-gui. Run it with: ferotrx run <this file> -i <interface>\n{body}"
        )
    }

    pub fn from_toml(text: &str) -> Result<Self, String> {
        let root: Table = text.parse().map_err(|e: toml::de::Error| e.to_string())?;
        let mut p = ProfileDraft::default();
        for (k, v) in &root {
            match k.as_str() {
                "format" => {}
                "output" => {
                    let t = v.as_table().ok_or("[output] must be a table")?;
                    p.output = Some(toml::to_string(t).map_err(|e| e.to_string())?);
                }
                "stream" => {
                    for s in v.as_array().ok_or("stream must be [[stream]] tables")? {
                        let t = s.as_table().ok_or("stream must be [[stream]] tables")?;
                        p.streams.push(StreamDraft::from_table(t)?);
                    }
                }
                other => {
                    return Err(format!(
                        "'{other}' is not part of a stream profile (TCP, UDP and host profiles open in the Stateful tab)"
                    ))
                }
            }
        }
        Ok(p)
    }

    /// A name for a new stream that no other stream of the port has.
    pub fn unique_name(&self, base: &str) -> String {
        let taken = |n: &str| self.streams.iter().any(|s| s.name == n);
        if !taken(base) {
            return base.to_string();
        }
        (2..)
            .map(|i| format!("{base}-{i}"))
            .find(|n| !taken(n))
            .expect("some name is free")
    }
}

/// How a port sends, set in its toolbar. Empty strings mean "the default".
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PortConfig {
    pub backend: String,
    pub xdp_mode: String,
    pub queue: Option<u16>,
    /// Engine threads to spread the run over; `None` is one.
    pub workers: Option<u16>,
    pub duration: String,
    /// Rate for all streams, overriding theirs.
    pub rate: String,
    /// Receive on this interface of the same server, for loss and latency.
    pub rx_iface: String,
    pub latency: bool,
    /// Impairments for all streams (`ImpairSpec` text), overriding theirs.
    pub impair: String,
}

/// The ports a server offers: its interfaces, and two that need no
/// privileges, for trying a profile out.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PortKind {
    Interface(String),
    /// Write a pcap file on the server (the path is in the workspace).
    File,
    /// Count the packets and drop them.
    Null,
}

impl PortKind {
    pub fn label(&self) -> String {
        match self {
            PortKind::Interface(n) => n.clone(),
            PortKind::File => "file (pcap on the server)".into(),
            PortKind::Null => "null (count only)".into(),
        }
    }

    /// A key that names the port across sessions, for saved streams.
    pub fn key(&self) -> String {
        match self {
            PortKind::Interface(n) => format!("if:{n}"),
            PortKind::File => "file".into(),
            PortKind::Null => "null".into(),
        }
    }

    /// The profile name the port's streams are loaded under on the server.
    pub fn profile_name(&self) -> String {
        let base: String = self
            .key()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        format!("gui-{base}")
    }
}

/// Where the `file` port writes when no path is set.
pub const DEFAULT_FILE_OUT: &str = "gui-out.pcap";

/// `run.start` parameters for a port's streams.
///
/// `file_out` is the output of the `file` port, on the server.
pub fn start_params(
    port: &PortKind,
    cfg: &PortConfig,
    profile: &str,
    file_out: &str,
) -> serde_json::Value {
    let mut output = serde_json::Map::new();
    match port {
        PortKind::Interface(n) => {
            output.insert("iface".into(), n.clone().into());
        }
        PortKind::File => {
            let f = if file_out.trim().is_empty() {
                DEFAULT_FILE_OUT
            } else {
                file_out.trim()
            };
            output.insert("file".into(), f.into());
        }
        PortKind::Null => {
            output.insert("null".into(), true.into());
        }
    }
    if matches!(port, PortKind::Interface(_)) {
        if !cfg.backend.is_empty() {
            output.insert("backend".into(), cfg.backend.clone().into());
        }
        if !cfg.xdp_mode.is_empty() {
            output.insert("xdp_mode".into(), cfg.xdp_mode.clone().into());
        }
        if let Some(q) = cfg.queue {
            output.insert("queue".into(), q.into());
        }
    }
    if let Some(w) = cfg.workers.filter(|&w| w > 1) {
        output.insert("workers".into(), w.into());
    }
    let mut p = serde_json::Map::new();
    p.insert("profile".into(), profile.into());
    p.insert("output".into(), output.into());
    if !cfg.duration.trim().is_empty() {
        p.insert("duration".into(), cfg.duration.trim().into());
    }
    if !cfg.rate.trim().is_empty() {
        p.insert("rate".into(), cfg.rate.trim().into());
    }
    if cfg.latency {
        p.insert("latency".into(), true.into());
    }
    if !cfg.rx_iface.is_empty() {
        p.insert("rx".into(), serde_json::json!({ "iface": cfg.rx_iface }));
    }
    if !cfg.impair.trim().is_empty() {
        p.insert("impair".into(), cfg.impair.trim().into());
    }
    p.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = r#"
format = 1
[output]
backend = "af_xdp"

[[stream]]
name = "dns"
packets = ["eth/ipv4/udp/dns(q=a.example)", "eth/ipv4/udp/dns(q=b.example)"]
rate = "50pps"
loops = 0
delay = "2s"
vary = ["port_src=1024..65535"]
latency = 7

[[stream]]
name = "web"
pcap = "web.pcap"
rate = "x2"
loops = 3
limit = 100
rewrite = ["vlan_push=10"]
future_key = { a = 1 }
"#;

    #[test]
    fn profiles_round_trip() {
        let p = ProfileDraft::from_toml(PROFILE).unwrap();
        assert_eq!(p.streams.len(), 2);
        assert_eq!(p.streams[0].packets.len(), 2);
        assert_eq!(p.streams[0].latency, Latency::Flow(7));
        assert_eq!(p.streams[1].source, SourceKind::Pcap);
        assert_eq!(p.streams[1].limit, Some(100));
        assert!(p.streams[1].extra.contains_key("future_key"));
        let again = ProfileDraft::from_toml(&p.to_toml(false)).unwrap();
        assert_eq!(again, p);
    }

    #[test]
    fn disabled_streams_stay_out_of_runs() {
        let mut p = ProfileDraft::from_toml(PROFILE).unwrap();
        p.streams[0].enabled = false;
        let run = ProfileDraft::from_toml(&p.to_toml(true)).unwrap();
        assert_eq!(run.streams.len(), 1);
        assert_eq!(run.streams[0].name, "web");
    }

    #[test]
    fn stateful_profiles_are_refused() {
        let e = ProfileDraft::from_toml("[client]\nip = \"10.0.0.1\"\n").unwrap_err();
        assert!(e.contains("Stateful"), "{e}");
    }

    #[test]
    fn unique_names() {
        let mut p = ProfileDraft::default();
        p.streams.push(StreamDraft::default());
        assert_eq!(p.unique_name("stream"), "stream-2");
        assert_eq!(p.unique_name("other"), "other");
    }

    #[test]
    fn start_params_per_port() {
        let cfg = PortConfig {
            backend: "af_xdp".into(),
            duration: "10s".into(),
            rx_iface: "veth1".into(),
            workers: Some(4),
            impair: "delay=5ms loss=1%".into(),
            ..Default::default()
        };
        let p = start_params(
            &PortKind::Interface("veth0".into()),
            &cfg,
            "gui-if-veth0",
            "",
        );
        assert_eq!(p["output"]["iface"], "veth0");
        assert_eq!(p["output"]["backend"], "af_xdp");
        assert_eq!(p["rx"]["iface"], "veth1");
        assert_eq!(p["output"]["workers"], 4);
        assert_eq!(p["impair"], "delay=5ms loss=1%");
        let p = start_params(&PortKind::Null, &cfg, "gui-null", "");
        assert_eq!(p["output"]["null"], true);
        assert!(p["output"].get("backend").is_none());
        // The parameters must be what the server takes.
        let _: ferotrx_ctl::protocol::StartParams = serde_json::from_value(p).unwrap();
        assert_eq!(
            PortKind::Interface("en0.10".into()).profile_name(),
            "gui-if-en0-10"
        );
    }
}
