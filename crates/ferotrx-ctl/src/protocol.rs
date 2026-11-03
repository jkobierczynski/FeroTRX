//! The wire format: JSON-RPC 2.0 messages, one JSON object per line, and the
//! parameter and result types of every method.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use ferotrx_core::{
    FlowReport, FlowStats, LatencyStats, ReplayStats, RunStats, RxStats, TcpSideStats, TcpStats,
    UdpSideStats, UdpStats,
};

/// Version of the method set below. Bumped when a method changes incompatibly.
pub const PROTOCOL_VERSION: u32 = 2;

/// Port the server listens on unless told otherwise.
pub const DEFAULT_PORT: u16 = 4510;

/// A request from a client. Without an `id` it is a notification and gets no response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub params: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
}

impl Request {
    pub fn new(method: impl Into<String>, params: Value, id: u64) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
            id: Some(id.into()),
        }
    }
}

/// A response to a [`Request`]: exactly one of `result` and `error` is set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    pub id: Value,
}

impl Response {
    pub fn new(id: Value, outcome: Result<Value, RpcError>) -> Self {
        let (result, error) = match outcome {
            Ok(v) => (Some(v), None),
            Err(e) => (None, Some(e)),
        };
        Self {
            jsonrpc: "2.0".into(),
            result,
            error,
            id,
        }
    }
}

/// A message the server sends on its own, such as a `stats` update.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Notification {
    pub jsonrpc: String,
    pub method: String,
    pub params: Value,
}

impl Notification {
    pub fn new(method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
        }
    }
}

/// A JSON-RPC error object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcError {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;
    /// The connection has not sent `auth` with the server's token.
    pub const UNAUTHORIZED: i64 = -32001;
    /// No profile, run or subscription by that name or id.
    pub const NOT_FOUND: i64 = -32002;
    /// The request was understood but could not be carried out, e.g. a profile
    /// that does not parse or an interface that cannot be opened.
    pub const FAILED: i64 = -32003;
    /// The connection may not do this: a read-only login calling a method
    /// that changes something, or a path outside the server's data directories.
    pub const FORBIDDEN: i64 = -32004;

    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(Self::INVALID_PARAMS, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(Self::NOT_FOUND, message)
    }

    pub fn failed(message: impl std::fmt::Display) -> Self {
        Self::new(Self::FAILED, message.to_string())
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(Self::FORBIDDEN, message)
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (code {})", self.message, self.code)
    }
}

impl std::error::Error for RpcError {}

// ----- server.info, auth, interfaces.list -----

/// Result of `server.info`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    pub protocol: u32,
    /// True when the server can send on network interfaces.
    pub interfaces: bool,
    /// The interface backends the server has: `pcap`, `af_xdp`, `dpdk`.
    #[serde(default)]
    pub backends: Vec<String>,
    /// True when connections must log in (`auth` with a token, or a client
    /// certificate) before anything but `server.info`.
    pub auth_required: bool,
    /// True when this connection is encrypted with TLS.
    #[serde(default)]
    pub tls: bool,
    /// What this connection may do, once logged in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
    /// Who this connection is logged in as: the token's name or the client
    /// certificate's common name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// What a connection may do.
///
/// `read` sees everything (`server.info`, `interfaces.list`, `*.get`,
/// `*.list`, `*.stats`, `stats.subscribe`) and changes nothing; `operator`
/// may also load profiles and start, stop and remove runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Read,
    Operator,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Read => "read",
            Role::Operator => "operator",
        }
    }

    /// The role a method needs, or `None` for the methods anyone may call
    /// (`server.info`, `auth`).
    pub fn required_for(method: &str) -> Option<Role> {
        match method {
            "server.info" | "auth" => None,
            "interfaces.list" | "profile.get" | "profile.list" | "run.stats" | "run.list"
            | "tcp.stats" | "tcp.list" | "udp.stats" | "udp.list" | "rx.stats" | "rx.list"
            | "stats.subscribe" | "stats.unsubscribe" => Some(Role::Read),
            _ => Some(Role::Operator),
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "read" | "read-only" | "readonly" => Ok(Role::Read),
            "operator" => Ok(Role::Operator),
            _ => Err(format!("unknown role '{s}' (use read or operator)")),
        }
    }
}

/// Parameters of `auth`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthParams {
    pub token: String,
}

/// One entry of the `interfaces.list` result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InterfaceEntry {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ----- profile.* -----

/// Parameters of `profile.load`: a profile file on the server, or its TOML text.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadProfileParams {
    /// Name to load it under; defaults to the file name without `.toml`.
    /// Required with `toml`. Loading a name again replaces that profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Path of the profile file on the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// The profile itself, as TOML text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toml: Option<String>,
    /// With `toml`: folder that relative pcap paths are taken from
    /// (default: the server's working folder).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_dir: Option<PathBuf>,
}

/// Parameters that name a profile: `profile.get`, `profile.unload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileName {
    pub name: String,
}

/// A loaded profile, as `profile.load`, `profile.get` and `profile.list` show it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProfileInfo {
    pub name: String,
    pub streams: Vec<StreamInfo>,
}

/// One stream of a [`ProfileInfo`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StreamInfo {
    pub name: String,
    /// The pcap file, or a description of the built packets.
    pub source: String,
    pub rate: String,
    pub loops: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    pub delay_s: f64,
    pub rewrite: Vec<String>,
    /// Field engine variables (the profile's `vary` list).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vary: Vec<String>,
    /// Latency flow id, for a stream the profile marks with `latency`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<u32>,
}

// ----- run.* -----

/// Where a run sends its packets: set exactly one of `iface`, `file` and `null`.
///
/// With `iface`, the other fields choose how to send; any left out come from
/// the profile's `[output]` table, then the defaults.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSpec {
    /// A network interface on the server, e.g. `enp0s3` (a DPDK device with
    /// the `dpdk` backend).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    /// `pcap` (default), `af_xdp` or `dpdk`; see `server.info` for what the server has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// Transmit queue (af_xdp, dpdk).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<u16>,
    /// AF_XDP mode: `auto`, `copy` or `zerocopy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xdp_mode: Option<String>,
    /// Packets handed over at once (af_xdp, dpdk).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<u32>,
    /// DPDK EAL arguments. EAL starts once per server process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpdk_args: Option<Vec<String>>,
    /// A pcap file on the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    /// Discard the packets.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub null: bool,
}

/// Parameters of `run.start`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartParams {
    /// Name of a loaded profile.
    pub profile: String,
    pub output: OutputSpec,
    /// Rate for every stream, overriding the profile, e.g. `10kpps` or `100mbps`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<String>,
    /// Stop after this many packets in total.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// Stop after this long, e.g. `30s` or `5m`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
    /// Count failed sends and keep going instead of failing the run.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ignore_errors: bool,
    /// Put a latency signature in the packets of every stream, not only
    /// those the profile marks with `latency`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub latency: bool,
    /// Receive on an interface of the server while the run goes, and report
    /// loss and latency of the streams with signatures (all of them if the
    /// profile marks none).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx: Option<RxSpec>,
}

/// Where a run receives its own packets back, for loss and latency.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RxSpec {
    /// The interface on the server, e.g. `enp0s8`. It may be the one the run
    /// sends on, if the packets come back on it (a router on a stick).
    pub iface: String,
    /// How long to keep receiving after the last packet is sent, e.g. `500ms`
    /// (the default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait: Option<String>,
}

/// Parameters that name a run: `run.stats`, `run.remove`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunId {
    pub id: u64,
}

/// Parameters of `run.stop`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopParams {
    pub id: u64,
    /// Wait for the run to end before answering (default true).
    #[serde(default = "yes")]
    pub wait: bool,
}

fn yes() -> bool {
    true
}

/// What a run is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunState {
    Running,
    /// Ended by itself: every stream finished, or a limit or duration was reached.
    Finished,
    /// Ended by `run.stop`.
    Stopped,
    /// Ended by an error; see `error`.
    Failed,
}

impl RunState {
    pub fn is_running(self) -> bool {
        self == RunState::Running
    }
}

/// A run, as `run.start`, `run.stop`, `run.stats`, `run.list` and `stats`
/// notifications show it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RunInfo {
    pub id: u64,
    pub profile: String,
    pub output: String,
    pub state: RunState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub total: Counters,
    pub streams: Vec<StreamCounters>,
    /// What the run's receiver saw, when it has one (`rx` in `run.start`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx: Option<RxCounters>,
}

/// Counters of a run or of one stream.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Counters {
    pub packets: u64,
    pub bytes: u64,
    /// Packets sent with a latency signature.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub tagged: u64,
    pub send_errors: u64,
    pub loops_completed: u64,
    pub elapsed_s: f64,
    /// Average packets per second since the run started.
    pub pps: f64,
    /// Average megabits per second (10^6 bits) since the run started.
    pub mbps: f64,
}

impl From<&ReplayStats> for Counters {
    fn from(s: &ReplayStats) -> Self {
        Self {
            packets: s.packets,
            bytes: s.bytes,
            tagged: s.tagged,
            send_errors: s.send_errors,
            loops_completed: s.loops_completed,
            elapsed_s: s.elapsed.as_secs_f64(),
            pps: s.pps(),
            mbps: s.mbps(),
        }
    }
}

/// Counters of one stream, with its name.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StreamCounters {
    pub name: String,
    #[serde(flatten)]
    pub counters: Counters,
    /// Loss and latency, for a stream with a signature in a run with a receiver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<FlowCounters>,
}

impl RunInfo {
    pub(crate) fn counters(stats: &RunStats, names: &[String]) -> (Counters, Vec<StreamCounters>) {
        let streams = names
            .iter()
            .zip(&stats.streams)
            .map(|(name, s)| StreamCounters {
                name: name.clone(),
                counters: s.into(),
                latency: None,
            })
            .collect();
        ((&stats.total).into(), streams)
    }
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

// ----- loss and latency -----

/// What a receiver saw: every frame, and those without a signature.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RxCounters {
    /// The interface received on.
    pub iface: String,
    pub packets: u64,
    pub bytes: u64,
    /// Frames without a latency signature (other traffic on the interface).
    pub untagged: u64,
    pub elapsed_s: f64,
}

impl RxCounters {
    pub fn new(iface: &str, s: &RxStats) -> Self {
        Self {
            iface: iface.to_string(),
            packets: s.packets,
            bytes: s.bytes,
            untagged: s.untagged,
            elapsed_s: s.elapsed.as_secs_f64(),
        }
    }
}

/// Loss and latency of one flow.
///
/// In a run, `tx` is what the stream sent with a signature and `lost` is
/// `tx - rx` (packets on their way count while the run goes). On a receiver
/// alone (`rx.start`) `tx` is absent and `lost` is the gaps in the sequence
/// numbers, between the first and the highest one seen.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct FlowCounters {
    pub flow: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx: Option<u64>,
    /// Packets received, duplicates not counted.
    pub rx: u64,
    pub lost: u64,
    /// `lost` as a percentage of the packets expected.
    pub loss_pct: f64,
    pub duplicates: u64,
    pub out_of_order: u64,
    pub latency: LatencyCounters,
}

/// Latency figures of a flow, in microseconds; absent until a packet arrived.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LatencyCounters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_us: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avg_us: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_us: Option<f64>,
    /// Smoothed variation from packet to packet (RFC 3550).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter_us: Option<f64>,
    /// Percentiles, to within 12.5%.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p50_us: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p99_us: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p999_us: Option<f64>,
    /// Packets that seemed to arrive before they were sent: the sender's and
    /// the receiver's clocks disagree.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub negative: u64,
}

impl From<&LatencyStats> for LatencyCounters {
    fn from(l: &LatencyStats) -> Self {
        let us = |d: Option<std::time::Duration>| d.map(|d| d.as_nanos() as f64 / 1000.0);
        Self {
            min_us: us(l.min()),
            avg_us: us(l.mean()),
            max_us: us(l.max()),
            jitter_us: us(l.jitter()),
            p50_us: us(l.percentile(0.5)),
            p99_us: us(l.percentile(0.99)),
            p999_us: us(l.percentile(0.999)),
            negative: l.negative,
        }
    }
}

fn pct(lost: u64, of: u64) -> f64 {
    if of == 0 {
        0.0
    } else {
        lost as f64 * 100.0 / of as f64
    }
}

impl From<&FlowReport> for FlowCounters {
    fn from(r: &FlowReport) -> Self {
        Self {
            flow: r.flow,
            tx: Some(r.tx),
            rx: r.rx,
            lost: r.lost,
            loss_pct: pct(r.lost, r.tx),
            duplicates: r.duplicates,
            out_of_order: r.out_of_order,
            latency: (&r.latency).into(),
        }
    }
}

impl From<&FlowStats> for FlowCounters {
    fn from(f: &FlowStats) -> Self {
        let lost = f.seq_lost();
        Self {
            flow: f.flow,
            tx: None,
            rx: f.unique(),
            lost,
            loss_pct: pct(lost, f.unique() + lost),
            duplicates: f.duplicates,
            out_of_order: f.out_of_order,
            latency: (&f.latency).into(),
        }
    }
}

/// Parameters of `rx.start`: receive on an interface of the server and count
/// the flows of latency signatures that arrive, sent by another FeroTRX.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RxStartParams {
    pub iface: String,
    /// Stop after this long, e.g. `60s`; without it, until `rx.stop`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
}

/// A receiver, as `rx.start`, `rx.stats`, `rx.stop` and `rx.list` report it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RxRunInfo {
    /// Id; shared with `run.*` and `tcp.*` runs, so they never clash.
    pub id: u64,
    pub state: RunState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(flatten)]
    pub counters: RxCounters,
    pub flows: Vec<FlowCounters>,
}

// ----- tcp.* -----

/// Parameters of `tcp.start`: a TCP profile (see `ferotrx_core::TcpProfile`)
/// as a file or as TOML text, and values that replace the profile's.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpStartParams {
    /// A TCP profile file on the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// The profile's text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toml: Option<String>,
    /// Folder that `pcap` paths in `toml` are relative to (default: the server's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_dir: Option<PathBuf>,
    /// Interface for hosts whose table names none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connections: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<usize>,
    /// Stop after this long, e.g. `30s`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
}

/// A stateful TCP run, as `tcp.start`, `tcp.stats`, `tcp.stop` and `tcp.list` report it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TcpRunInfo {
    /// Run id; ids are shared with `run.*` runs, so they never clash.
    pub id: u64,
    /// The session played, e.g. `10.1.2.30:51000 -> 10.1.2.80:80: 4 messages, ...`.
    pub program: String,
    /// The interfaces the run uses.
    pub interfaces: Vec<String>,
    pub state: RunState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// All templates together.
    pub client: TcpCounters,
    pub server: TcpCounters,
    /// Each template's counters, in the profile's order.
    #[serde(default)]
    pub templates: Vec<TcpTemplateCounters>,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub elapsed_s: f64,
    /// Completed client connections per second.
    pub cps: f64,
}

/// The counters of one template of a [`TcpRunInfo`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpTemplateCounters {
    pub name: String,
    pub client: TcpCounters,
    pub server: TcpCounters,
}

/// Connection counters of one side of a [`TcpRunInfo`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpCounters {
    pub started: u64,
    pub established: u64,
    pub completed: u64,
    pub reset: u64,
    pub timed_out: u64,
    pub mismatched: u64,
    pub active: u64,
    pub payload_tx: u64,
    pub payload_rx: u64,
    pub retransmits: u64,
    /// Retransmission timeouts (also counted in `retransmits`).
    #[serde(default)]
    pub timeouts: u64,
    /// Old duplicate segments dropped by PAWS.
    #[serde(default)]
    pub paws_dropped: u64,
    /// Most bytes one connection had in flight at once.
    #[serde(default)]
    pub max_in_flight: u64,
}

impl From<&TcpSideStats> for TcpCounters {
    fn from(s: &TcpSideStats) -> Self {
        Self {
            started: s.started,
            established: s.established,
            completed: s.completed,
            reset: s.reset,
            timed_out: s.timed_out,
            mismatched: s.mismatched,
            active: s.active,
            payload_tx: s.payload_tx,
            payload_rx: s.payload_rx,
            retransmits: s.retransmits,
            timeouts: s.timeouts,
            paws_dropped: s.paws_dropped,
            max_in_flight: s.max_in_flight,
        }
    }
}

impl TcpRunInfo {
    pub(crate) fn fill(&mut self, s: &TcpStats) {
        self.client = (&s.client).into();
        self.server = (&s.server).into();
        self.templates = s
            .templates
            .iter()
            .map(|t| TcpTemplateCounters {
                name: t.name.clone(),
                client: (&t.client).into(),
                server: (&t.server).into(),
            })
            .collect();
        self.tx_packets = s.tx_packets;
        self.tx_bytes = s.tx_bytes;
        self.rx_packets = s.rx_packets;
        self.rx_bytes = s.rx_bytes;
        self.elapsed_s = s.elapsed.as_secs_f64();
        self.cps = s.cps();
    }
}

// ----- udp.* -----

/// Parameters of `udp.start`: a UDP profile (see `ferotrx_core::UdpProfile`)
/// as a file or as TOML text, and values that replace the profile's.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpStartParams {
    /// A UDP profile file on the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// The profile's text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toml: Option<String>,
    /// Folder that `pcap` paths in `toml` are relative to (default: the server's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_dir: Option<PathBuf>,
    /// Interface for hosts whose table names none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    /// Transactions per second.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transactions: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<usize>,
    /// Stop after this long, e.g. `30s`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
}

/// A stateful UDP run, as `udp.start`, `udp.stats`, `udp.stop` and `udp.list` report it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UdpRunInfo {
    /// Run id; shared with the other runs, so they never clash.
    pub id: u64,
    /// What the transactions carry, e.g. `DNS: 8 queries, 8 records`.
    pub program: String,
    pub interfaces: Vec<String>,
    pub state: RunState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// All templates together.
    pub client: UdpCounters,
    pub server: UdpCounters,
    /// Each template's counters, in the profile's order.
    #[serde(default)]
    pub templates: Vec<UdpTemplateCounters>,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub elapsed_s: f64,
    /// Answered client transactions per second.
    pub tps: f64,
}

/// The counters of one template of a [`UdpRunInfo`].
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct UdpTemplateCounters {
    pub name: String,
    pub client: UdpCounters,
    pub server: UdpCounters,
}

/// Transaction counters of one side of a [`UdpRunInfo`]; see
/// `ferotrx_core::UdpSideStats`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct UdpCounters {
    pub sent: u64,
    pub answered: u64,
    pub timed_out: u64,
    pub unmatched: u64,
    pub mismatched: u64,
    pub errors: u64,
    pub retries: u64,
    pub duplicates: u64,
    pub active: u64,
    pub datagrams_tx: u64,
    pub datagrams_rx: u64,
    pub payload_tx: u64,
    pub payload_rx: u64,
    /// Client: from each request to its answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_time: Option<LatencyCounters>,
}

impl From<&UdpSideStats> for UdpCounters {
    fn from(s: &UdpSideStats) -> Self {
        Self {
            sent: s.sent,
            answered: s.answered,
            timed_out: s.timed_out,
            unmatched: s.unmatched,
            mismatched: s.mismatched,
            errors: s.errors,
            retries: s.retries,
            duplicates: s.duplicates,
            active: s.active,
            datagrams_tx: s.datagrams_tx,
            datagrams_rx: s.datagrams_rx,
            payload_tx: s.payload_tx,
            payload_rx: s.payload_rx,
            response_time: (s.response_time.count() > 0).then(|| (&s.response_time).into()),
        }
    }
}

impl UdpRunInfo {
    pub(crate) fn fill(&mut self, s: &UdpStats) {
        self.client = (&s.client).into();
        self.server = (&s.server).into();
        self.templates = s
            .templates
            .iter()
            .map(|t| UdpTemplateCounters {
                name: t.name.clone(),
                client: (&t.client).into(),
                server: (&t.server).into(),
            })
            .collect();
        self.tx_packets = s.tx_packets;
        self.tx_bytes = s.tx_bytes;
        self.rx_packets = s.rx_packets;
        self.rx_bytes = s.rx_bytes;
        self.elapsed_s = s.elapsed.as_secs_f64();
        self.tps = s.tps();
    }
}

// ----- stats.* -----

/// Parameters of `stats.subscribe`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscribeParams {
    /// Only this run; without it, every run that is running at each tick.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    /// Milliseconds between updates (default 1000, at least 50).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_ms: Option<u64>,
}

/// Result of `stats.subscribe`, and the parameter of `stats.unsubscribe`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subscription {
    pub subscription: u64,
}

/// Parameters of a `stats` notification.
///
/// A subscription for one run sends a last update when the run ends, then
/// ends itself; `last` is true on that update.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StatsUpdate {
    pub subscription: u64,
    pub run: RunInfo,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub last: bool,
}
