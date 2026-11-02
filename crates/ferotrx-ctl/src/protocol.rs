//! The wire format: JSON-RPC 2.0 messages, one JSON object per line, and the
//! parameter and result types of every method.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use ferotrx_core::{ReplayStats, RunStats};

/// Version of the method set below. Bumped when a method changes incompatibly.
pub const PROTOCOL_VERSION: u32 = 1;

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
    /// True when connections must send `auth` first.
    pub auth_required: bool,
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
}

// ----- run.* -----

/// Where a run sends its packets: set exactly one field.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSpec {
    /// A network interface on the server, e.g. `enp0s3`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
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
}

/// Counters of a run or of one stream.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Counters {
    pub packets: u64,
    pub bytes: u64,
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
}

impl RunInfo {
    pub(crate) fn counters(stats: &RunStats, names: &[String]) -> (Counters, Vec<StreamCounters>) {
        let streams = names
            .iter()
            .zip(&stats.streams)
            .map(|(name, s)| StreamCounters {
                name: name.clone(),
                counters: s.into(),
            })
            .collect();
        ((&stats.total).into(), streams)
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
