//! Traffic limits a server owner sets, which remote operators cannot exceed
//! (`ferotrx serve --allow-iface eth1 --max-pps 10kpps ...`).
//!
//! Nothing is limited by default: benchmarking must work out of the box.
//! With [`Limits`] on the [`Controller`](crate::Controller), every start
//! method (`run.start`, `tcp.start`, `udp.start`, `bench.start`,
//! `y1564.start`, `scenario.start`) checks what it is asked for first and
//! refuses with `FORBIDDEN` (-32004) and the limit in the error's
//! `data.limit`. What a start cannot know beforehand, such as the packet
//! rate of a capture replayed with its own timing or a destination a field
//! variation makes up, is held while the traffic flows: the sinks and ports
//! of the server's runs go through a [`Guard`] that paces all of them
//! together below `max_pps` and `max_bps` and refuses frames to other
//! destinations.
//!
//! Limits apply to everything that comes in through the control API; the
//! command line (`ferotrx run`, `ferotrx tcp` and the rest) is not limited.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::json;

use ferotrx_core::{PacketPort, PacketSink, Profile, Rate, SinkError, LINKTYPE_ETHERNET};

use crate::protocol::RpcError;

/// A range of addresses: `10.0.0.0/8`, `2001:db8::/32`, or one address
/// (`192.168.20.50` is `/32`, an IPv6 address `/128`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net {
    addr: IpAddr,
    prefix: u8,
}

impl Net {
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, String> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!("{addr}/{prefix}: the prefix is at most {max}"));
        }
        Ok(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => same_prefix(&a.octets(), &b.octets(), self.prefix),
            (IpAddr::V6(a), IpAddr::V6(b)) => same_prefix(&a.octets(), &b.octets(), self.prefix),
            // An IPv4-mapped IPv6 address is an IPv4 one.
            (IpAddr::V4(_), IpAddr::V6(b)) => b
                .to_ipv4_mapped()
                .is_some_and(|v4| self.contains(v4.into())),
            (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

fn same_prefix(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = usize::from(prefix / 8);
    if a[..full] != b[..full] {
        return false;
    }
    let rest = prefix % 8;
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    a[full] & mask == b[full] & mask
}

impl FromStr for Net {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let t = s.trim();
        let (ip, prefix) = match t.split_once('/') {
            Some((ip, p)) => (ip, Some(p)),
            None => (t, None),
        };
        let addr: IpAddr = ip
            .parse()
            .map_err(|_| format!("'{s}' is not an address or a range such as 10.0.0.0/8"))?;
        let prefix = match prefix {
            Some(p) => p
                .parse()
                .map_err(|_| format!("'{s}': the prefix after / is a number"))?,
            None if addr.is_ipv4() => 32,
            None => 128,
        };
        Net::new(addr, prefix)
    }
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl Serialize for Net {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Net {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Addresses that never leave the link, which frames may always go to:
/// the IPv4 broadcast, 224.0.0.0/24 (IGMP, DHCP relays' neighbours) and
/// ff02::/16 and ff01::/16 (NDP, MLD, DHCPv6).
fn link_scoped(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_broadcast() || a.octets()[..3] == [224, 0, 0],
        IpAddr::V6(a) => matches!(a.segments()[0], 0xff01 | 0xff02),
    }
}

/// What remote operators of a server may do at most (`ferotrx serve`'s
/// `--allow-iface`, `--allow-dst`, `--max-*` and `--allow-unlimited`, or
/// the `[limits]` table of its `--config` file). Empty lists and `None`
/// are no limit. `server.info` reports them.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Limits {
    /// The interfaces runs, receivers and captures may use.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    /// The addresses frames may be sent to: built packets, rewrites and
    /// what is replayed, and the servers TCP and UDP clients reach.
    /// Link-scoped addresses (broadcast, 224.0.0.0/24, ff02::/16) and ARP
    /// are always allowed; frames that are neither IP nor ARP are not.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destinations: Vec<Net>,
    /// Packets per second of all runs together.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_pps: Option<f64>,
    /// Bits per second of all runs together, counting the bytes of each
    /// frame as sent (without FCS), as `mbps` rates do.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bps: Option<f64>,
    /// Longest a run may go, in seconds; runs without a duration end there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration: Option<f64>,
    /// Runs that send (traffic, TCP, UDP, benchmarks, Y.1564, scenarios)
    /// going at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_runs: Option<usize>,
    /// A TCP or UDP run's connections (transactions) open at once, and new
    /// ones per second.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_flows: Option<u64>,
    /// With a rate limit, runs may still ask for unlimited rates (top speed,
    /// benchmark searches); they then go as fast as the limit lets them.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_unlimited: bool,
}

/// `[limits]` as written in a file: rates and times as text or numbers.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsFile {
    #[serde(default)]
    interfaces: Vec<String>,
    #[serde(default)]
    destinations: Vec<String>,
    max_pps: Option<NumberOrText>,
    max_bps: Option<NumberOrText>,
    max_duration: Option<NumberOrText>,
    max_runs: Option<usize>,
    max_flows: Option<u64>,
    #[serde(default)]
    allow_unlimited: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum NumberOrText {
    Number(f64),
    Text(String),
}

impl NumberOrText {
    fn text(&self) -> String {
        match self {
            NumberOrText::Number(n) => n.to_string(),
            NumberOrText::Text(t) => t.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerFile {
    format: Option<u32>,
    limits: Option<LimitsFile>,
}

/// Parses a packet rate: a number of packets per second, or `10kpps`, `1mpps`.
pub fn parse_pps(s: &str) -> Result<f64, String> {
    let v = match s.trim().parse::<f64>() {
        Ok(v) => v,
        Err(_) => match s.parse::<Rate>() {
            Ok(Rate::Pps(v)) => v,
            _ => {
                return Err(format!(
                    "'{s}' is not a packet rate such as 10000 or 10kpps"
                ))
            }
        },
    };
    positive(s, v)
}

/// Parses a bit rate: a number of bits per second, or `100mbps`, `1gbps`.
pub fn parse_bps(s: &str) -> Result<f64, String> {
    let v = match s.trim().parse::<f64>() {
        Ok(v) => v,
        Err(_) => match s.parse::<Rate>() {
            Ok(Rate::Mbps(v)) => v * 1e6,
            _ => return Err(format!("'{s}' is not a bit rate such as 100mbps or 1gbps")),
        },
    };
    positive(s, v)
}

fn positive(s: &str, v: f64) -> Result<f64, String> {
    if v.is_finite() && v > 0.0 {
        Ok(v)
    } else {
        Err(format!("'{s}': a limit is more than 0"))
    }
}

/// Parses a time limit: `30s`, `10m`, `2h`, or seconds.
pub fn parse_limit_duration(s: &str) -> Result<Duration, String> {
    let d = match s.trim().parse::<f64>() {
        Ok(v) if v.is_finite() && v > 0.0 => Duration::from_secs_f64(v),
        Ok(_) => return Err(format!("'{s}': a limit is more than 0")),
        Err(_) => ferotrx_core::parse_duration(s).map_err(|e| e.to_string())?,
    };
    if d.is_zero() {
        return Err(format!("'{s}': a limit is more than 0"));
    }
    Ok(d)
}

/// The error of a start that would go beyond a limit: `FORBIDDEN`, with
/// the limit's name in `data.limit`.
pub(crate) fn refused(limit: &str, message: String) -> RpcError {
    let mut e = RpcError::forbidden(message);
    e.data = Some(json!({ "limit": limit }));
    e
}

/// The limit a refusal names (`data.limit`), if it was one.
pub fn refused_limit(e: &RpcError) -> Option<&str> {
    if e.code != RpcError::FORBIDDEN {
        return None;
    }
    e.data.as_ref()?.get("limit")?.as_str()
}

fn rate_text(pps: f64) -> String {
    if pps >= 1e6 {
        format!("{} Mpps", trim(pps / 1e6))
    } else if pps >= 1e3 {
        format!("{} kpps", trim(pps / 1e3))
    } else {
        format!("{} pps", trim(pps))
    }
}

fn bits_text(bps: f64) -> String {
    if bps >= 1e9 {
        format!("{} Gbit/s", trim(bps / 1e9))
    } else if bps >= 1e6 {
        format!("{} Mbit/s", trim(bps / 1e6))
    } else if bps >= 1e3 {
        format!("{} kbit/s", trim(bps / 1e3))
    } else {
        format!("{} bit/s", trim(bps))
    }
}

fn trim(v: f64) -> String {
    let s = format!("{v:.3}");
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

fn secs_text(s: f64) -> String {
    let d = Duration::from_secs_f64(s);
    let whole = d.as_secs();
    if d.subsec_millis() == 0 && whole >= 60 && whole.is_multiple_of(60) {
        if whole.is_multiple_of(3600) {
            format!("{}h", whole / 3600)
        } else {
            format!("{}m", whole / 60)
        }
    } else {
        format!("{}s", trim(s))
    }
}

/// What a traffic profile asks for, added up over its streams.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Demand {
    pub pps: f64,
    pub bps: f64,
    /// A stream at top speed (or a test that searches for the top rate).
    pub unlimited: bool,
}

impl Demand {
    /// The streams of `profile` at their rates, or all at `rate`.
    pub fn of_profile(profile: &Profile, rate: Option<Rate>) -> Self {
        let mut d = Demand::default();
        for s in &profile.streams {
            d.add(rate.unwrap_or(s.rate));
        }
        d
    }

    pub fn add(&mut self, rate: Rate) {
        match rate {
            Rate::Pps(v) => self.pps += v,
            Rate::Mbps(v) => self.bps += v * 1e6,
            Rate::TopSpeed => self.unlimited = true,
            // The capture's own timing: not known here, held by the guard.
            Rate::Original { .. } => {}
        }
    }
}

impl Limits {
    /// True when nothing is limited.
    pub fn is_empty(&self) -> bool {
        *self == Limits::default()
            || *self
                == Limits {
                    allow_unlimited: true,
                    ..Default::default()
                }
    }

    /// True when a packet or bit rate is limited.
    pub fn rate_limited(&self) -> bool {
        self.max_pps.is_some() || self.max_bps.is_some()
    }

    pub fn max_duration(&self) -> Option<Duration> {
        self.max_duration.map(Duration::from_secs_f64)
    }

    /// Reads the `[limits]` table of a server configuration file:
    ///
    /// ```toml
    /// format = 1
    ///
    /// [limits]
    /// interfaces = ["enp0s8", "enp0s9"]
    /// destinations = ["192.168.20.0/24", "2001:db8:20::/64"]
    /// max_pps = "50kpps"          # or a number
    /// max_bps = "200mbps"         # or a number of bits per second
    /// max_duration = "10m"
    /// max_runs = 4
    /// max_flows = 2000
    /// allow_unlimited = false
    /// ```
    pub fn from_toml(text: &str) -> Result<Limits, String> {
        let file: ServerFile = toml::from_str(text).map_err(|e| e.to_string())?;
        ferotrx_core::check_format(file.format).map_err(|e| e.to_string())?;
        let Some(f) = file.limits else {
            return Ok(Limits::default());
        };
        let mut l = Limits {
            interfaces: f.interfaces,
            destinations: f
                .destinations
                .iter()
                .map(|d| d.parse())
                .collect::<Result<_, _>>()?,
            max_runs: f.max_runs,
            max_flows: f.max_flows,
            allow_unlimited: f.allow_unlimited,
            ..Default::default()
        };
        if let Some(v) = &f.max_pps {
            l.max_pps = Some(parse_pps(&v.text()).map_err(|e| format!("max_pps: {e}"))?);
        }
        if let Some(v) = &f.max_bps {
            l.max_bps = Some(parse_bps(&v.text()).map_err(|e| format!("max_bps: {e}"))?);
        }
        if let Some(v) = &f.max_duration {
            let d = parse_limit_duration(&v.text()).map_err(|e| format!("max_duration: {e}"))?;
            l.max_duration = Some(d.as_secs_f64());
        }
        l.validate()?;
        Ok(l)
    }

    /// Checks the numbers: none may be 0.
    pub fn validate(&self) -> Result<(), String> {
        let pos = |v: Option<f64>| v.is_none_or(|v| v.is_finite() && v > 0.0);
        if !pos(self.max_pps) || !pos(self.max_bps) || !pos(self.max_duration) {
            return Err("rate and time limits are more than 0".into());
        }
        if self.max_runs == Some(0) || self.max_flows == Some(0) {
            return Err("max_runs and max_flows are at least 1".into());
        }
        if self.interfaces.iter().any(|i| i.trim().is_empty()) {
            return Err("an allowed interface has no name".into());
        }
        Ok(())
    }

    /// One line per limit, for the server's start message and the GUI.
    pub fn describe(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.interfaces.is_empty() {
            out.push(format!("interfaces: {}", self.interfaces.join(", ")));
        }
        if !self.destinations.is_empty() {
            let d: Vec<String> = self.destinations.iter().map(Net::to_string).collect();
            out.push(format!("destinations: {}", d.join(", ")));
        }
        if let Some(v) = self.max_pps {
            out.push(format!("at most {} in all", rate_text(v)));
        }
        if let Some(v) = self.max_bps {
            out.push(format!("at most {} in all", bits_text(v)));
        }
        if self.rate_limited() {
            out.push(if self.allow_unlimited {
                "top-speed runs and benchmarks allowed, held to the rate limits".into()
            } else {
                "no top-speed runs or benchmarks".into()
            });
        }
        if let Some(v) = self.max_duration {
            out.push(format!("runs end after {}", secs_text(v)));
        }
        if let Some(v) = self.max_runs {
            out.push(format!("{v} run(s) at once"));
        }
        if let Some(v) = self.max_flows {
            out.push(format!("{v} TCP/UDP flows open at once and per second"));
        }
        out
    }

    /// The interface may be used.
    pub fn check_iface(&self, name: &str) -> Result<(), RpcError> {
        if self.interfaces.is_empty() || self.interfaces.iter().any(|i| i == name) {
            return Ok(());
        }
        Err(refused(
            "interfaces",
            format!(
                "interface {name} is not allowed on this server; it allows {} (--allow-iface)",
                self.interfaces.join(", ")
            ),
        ))
    }

    /// Frames may be sent to `ip`.
    pub fn dst_allowed(&self, ip: IpAddr) -> bool {
        self.destinations.is_empty()
            || link_scoped(ip)
            || self.destinations.iter().any(|n| n.contains(ip))
    }

    /// Frames may be sent to `count` consecutive addresses from `first`.
    pub fn check_dsts(&self, first: IpAddr, count: u32, what: &str) -> Result<(), RpcError> {
        if self.destinations.is_empty() {
            return Ok(());
        }
        // The first and the last are enough unless a range has a gap; ranges
        // here are short, so check each one up to a bound, then the ends.
        let count = count.max(1);
        let step = (count / 4096).max(1);
        let mut k = 0;
        while k < count {
            let ip = nth_ip(first, k);
            if !self.dst_allowed(ip) {
                return Err(self.dst_refused(ip, what));
            }
            k = k.saturating_add(step);
        }
        let last = nth_ip(first, count - 1);
        if !self.dst_allowed(last) {
            return Err(self.dst_refused(last, what));
        }
        Ok(())
    }

    fn dst_refused(&self, ip: IpAddr, what: &str) -> RpcError {
        let d: Vec<String> = self.destinations.iter().map(Net::to_string).collect();
        refused(
            "destinations",
            format!(
                "{what} goes to {ip}, which this server does not send to; it allows {} (--allow-dst)",
                d.join(", ")
            ),
        )
    }

    /// A run asking for `requested` may go: not longer than `max_duration`.
    pub fn check_duration(&self, requested: Option<Duration>) -> Result<(), RpcError> {
        if let (Some(max), Some(d)) = (self.max_duration, requested) {
            if d.as_secs_f64() > max + 1e-9 {
                return Err(refused(
                    "max_duration",
                    format!(
                        "runs on this server go for at most {} (--max-duration); this one asks for {}",
                        secs_text(max),
                        secs_text(d.as_secs_f64())
                    ),
                ));
            }
        }
        Ok(())
    }

    /// The duration a run gets: the one asked for, else `max_duration`.
    pub fn duration_or_max(&self, requested: Option<Duration>) -> Option<Duration> {
        requested.or(self.max_duration())
    }

    /// The rates `what` asks for fit the limits.
    pub fn check_demand(&self, d: Demand, what: &str) -> Result<(), RpcError> {
        if !self.rate_limited() {
            return Ok(());
        }
        if d.unlimited && !self.allow_unlimited {
            return Err(refused(
                "allow_unlimited",
                format!(
                    "{what} asks for an unlimited rate, and this server limits rates ({}); \
                     give a rate, or start the server with --allow-unlimited",
                    self.rate_limits_text()
                ),
            ));
        }
        if let Some(max) = self.max_pps {
            if d.pps > max * (1.0 + 1e-9) {
                return Err(refused(
                    "max_pps",
                    format!(
                        "{what} asks for {}, and this server sends at most {} (--max-pps)",
                        rate_text(d.pps),
                        rate_text(max)
                    ),
                ));
            }
        }
        if let Some(max) = self.max_bps {
            if d.bps > max * (1.0 + 1e-9) {
                return Err(refused(
                    "max_bps",
                    format!(
                        "{what} asks for {}, and this server sends at most {} (--max-bps)",
                        bits_text(d.bps),
                        bits_text(max)
                    ),
                ));
            }
        }
        Ok(())
    }

    fn rate_limits_text(&self) -> String {
        let mut v = Vec::new();
        if let Some(p) = self.max_pps {
            v.push(rate_text(p));
        }
        if let Some(b) = self.max_bps {
            v.push(bits_text(b));
        }
        v.join(", ")
    }

    /// A TCP or UDP run opening `per_second` new flows a second, at most
    /// `at_once` open at once (0: no limit of its own), fits `max_flows`.
    /// Returns the limit on open flows the run gets: `at_once`, or
    /// `max_flows` when it had none.
    pub fn check_flows(
        &self,
        per_second: f64,
        at_once: usize,
        what: &str,
    ) -> Result<usize, RpcError> {
        let Some(max) = self.max_flows else {
            return Ok(at_once);
        };
        if per_second > max as f64 * (1.0 + 1e-9) {
            return Err(refused(
                "max_flows",
                format!(
                    "{what} opens {} a second, and this server allows at most {max} (--max-flows)",
                    trim(per_second)
                ),
            ));
        }
        if at_once as u64 > max {
            return Err(refused(
                "max_flows",
                format!(
                    "{what} keeps {at_once} open at once, and this server allows at most {max} (--max-flows)"
                ),
            ));
        }
        Ok(if at_once == 0 {
            usize::try_from(max).unwrap_or(usize::MAX)
        } else {
            at_once
        })
    }

    /// Another run may start while `running` go.
    pub fn check_runs(&self, running: usize) -> Result<(), RpcError> {
        match self.max_runs {
            Some(max) if running >= max => Err(refused(
                "max_runs",
                format!(
                    "{running} run(s) are going, and this server runs at most {max} at once \
                     (--max-runs); stop one first"
                ),
            )),
            _ => Ok(()),
        }
    }
}

fn nth_ip(first: IpAddr, k: u32) -> IpAddr {
    match first {
        IpAddr::V4(a) => IpAddr::V4(u32::from(a).wrapping_add(k).into()),
        IpAddr::V6(a) => IpAddr::V6(u128::from(a).wrapping_add(u128::from(k)).into()),
    }
}

/// Where a frame goes, as far as the limits care.
#[derive(Debug, PartialEq)]
enum Dst {
    Ip(IpAddr),
    Arp,
    Unknown,
}

const LINKTYPE_RAW: u32 = 101;
const LINKTYPE_IPV4: u32 = 228;
const LINKTYPE_IPV6: u32 = 229;

fn ip_dst(p: &[u8]) -> Dst {
    match p.first().map(|b| b >> 4) {
        Some(4) if p.len() >= 20 => Dst::Ip(IpAddr::from(<[u8; 4]>::try_from(&p[16..20]).unwrap())),
        Some(6) if p.len() >= 40 => {
            Dst::Ip(IpAddr::from(<[u8; 16]>::try_from(&p[24..40]).unwrap()))
        }
        _ => Dst::Unknown,
    }
}

fn frame_dst(frame: &[u8], linktype: u32) -> Dst {
    match linktype {
        LINKTYPE_ETHERNET => {}
        LINKTYPE_RAW | LINKTYPE_IPV4 | LINKTYPE_IPV6 | 12 | 14 => return ip_dst(frame),
        _ => return Dst::Unknown,
    }
    if frame.len() < 14 {
        return Dst::Unknown;
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut at = 14;
    // VLAN tags, also stacked (802.1ad, QinQ).
    while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
        if frame.len() < at + 4 {
            return Dst::Unknown;
        }
        ethertype = u16::from_be_bytes([frame[at + 2], frame[at + 3]]);
        at += 4;
    }
    match ethertype {
        0x0800 | 0x86dd => ip_dst(&frame[at..]),
        0x0806 => Dst::Arp,
        _ => Dst::Unknown,
    }
}

/// Why `frame` may not be sent under `limits`' destinations, if it may not.
pub(crate) fn check_frame(limits: &Limits, frame: &[u8], linktype: u32) -> Result<(), String> {
    if limits.destinations.is_empty() {
        return Ok(());
    }
    match frame_dst(frame, linktype) {
        Dst::Ip(ip) if limits.dst_allowed(ip) => Ok(()),
        Dst::Arp => Ok(()),
        Dst::Ip(ip) => Err(format!(
            "a frame to {ip}, which this server does not send to (--allow-dst)"
        )),
        Dst::Unknown => Err(
            "a frame that is neither IP nor ARP, so its destination cannot be \
                             checked against the server's --allow-dst"
                .to_string(),
        ),
    }
}

/// How much of the rate may be saved up while nothing is sent: a burst of
/// at most this much of the limit after a pause.
const BURST: Duration = Duration::from_millis(5);

/// The limits as the frames of all the server's runs go out: one shared
/// pacer below `max_pps` and `max_bps`, and the destination check.
pub(crate) struct Guard {
    limits: Limits,
    /// When the next frame may leave, all runs together.
    next: Mutex<Option<Instant>>,
    refused: AtomicU64,
}

impl Guard {
    /// A guard for `limits`, or `None` when they hold nothing back while
    /// frames go out (no rate or destination limit).
    pub fn new(limits: &Limits) -> Option<Arc<Guard>> {
        (limits.rate_limited() || !limits.destinations.is_empty()).then(|| {
            Arc::new(Guard {
                limits: limits.clone(),
                next: Mutex::new(None),
                refused: AtomicU64::new(0),
            })
        })
    }

    /// Frames refused because of where they went.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Why `frame` may not go out, if it may not.
    fn admit(&self, frame: &[u8], linktype: u32) -> Result<(), String> {
        let r = check_frame(&self.limits, frame, linktype);
        if r.is_err() {
            self.refused.fetch_add(1, Ordering::Relaxed);
        }
        r
    }

    /// How long to wait before a frame of `bytes` may leave.
    fn wait(&self, bytes: usize) -> Duration {
        let l = &self.limits;
        if !l.rate_limited() {
            return Duration::ZERO;
        }
        let per_packet = l.max_pps.map_or(0.0, |p| 1.0 / p);
        let per_byte = l.max_bps.map_or(0.0, |b| bytes as f64 * 8.0 / b);
        let cost = Duration::from_secs_f64(per_packet.max(per_byte));
        let now = Instant::now();
        let floor = now.checked_sub(BURST).unwrap_or(now);
        let mut next = self.next.lock().unwrap_or_else(|e| e.into_inner());
        let at = next.map_or(floor, |t| t.max(floor));
        *next = Some(at + cost);
        at.saturating_duration_since(now)
    }
}

/// A sink held to the server's limits: frames to other destinations are
/// refused with an error (the run fails, unless it ignores send errors;
/// the frame is not sent either way), and all sinks together are paced.
pub(crate) struct GuardSink {
    pub inner: Box<dyn PacketSink + Send>,
    pub guard: Arc<Guard>,
    pub linktype: u32,
}

impl PacketSink for GuardSink {
    fn send(&mut self, data: &[u8]) -> Result<(), SinkError> {
        self.guard.admit(data, self.linktype)?;
        let wait = self.guard.wait(data.len());
        if !wait.is_zero() {
            self.inner.idle()?;
            std::thread::sleep(wait);
        }
        self.inner.send(data)
    }

    fn flush(&mut self) -> Result<(), SinkError> {
        self.inner.flush()
    }

    fn idle(&mut self) -> Result<(), SinkError> {
        self.inner.idle()
    }
}

/// Wraps `sink` in the guard, if there is one.
pub(crate) fn guard_sink(
    guard: &Option<Arc<Guard>>,
    sink: Box<dyn PacketSink + Send>,
    linktype: u32,
) -> Box<dyn PacketSink + Send> {
    match guard {
        Some(g) => Box::new(GuardSink {
            inner: sink,
            guard: g.clone(),
            linktype,
        }),
        None => sink,
    }
}

/// A port of a TCP or UDP run held to the server's limits. Frames to other
/// destinations are dropped (as a firewall would), not failed: a server
/// end must not stop because some client outside the limits reached it.
pub(crate) struct GuardPort {
    pub inner: Box<dyn PacketPort>,
    pub guard: Arc<Guard>,
}

impl PacketPort for GuardPort {
    fn send(&mut self, frame: &[u8]) -> Result<(), SinkError> {
        if self.guard.admit(frame, LINKTYPE_ETHERNET).is_err() {
            return Ok(());
        }
        let wait = self.guard.wait(frame.len());
        if !wait.is_zero() {
            self.inner.flush()?;
            std::thread::sleep(wait);
        }
        self.inner.send(frame)
    }

    fn recv(&mut self, buf: &mut Vec<u8>) -> Result<bool, SinkError> {
        self.inner.recv(buf)
    }

    fn flush(&mut self) -> Result<(), SinkError> {
        self.inner.flush()
    }

    fn describe(&self) -> Option<String> {
        self.inner.describe()
    }

    fn split(&mut self, n: usize) -> Option<Vec<Box<dyn PacketPort>>> {
        let lanes = self.inner.split(n)?;
        Some(
            lanes
                .into_iter()
                .map(|inner| {
                    Box::new(GuardPort {
                        inner,
                        guard: self.guard.clone(),
                    }) as Box<dyn PacketPort>
                })
                .collect(),
        )
    }

    fn rx_dropped(&mut self) -> Option<u64> {
        self.inner.rx_dropped()
    }

    fn impairments(&mut self) -> Option<ferotrx_core::PortImpairStats> {
        self.inner.impairments()
    }
}

/// Wraps `port` in the guard, if there is one.
pub(crate) fn guard_port(
    guard: &Option<Arc<Guard>>,
    port: Box<dyn PacketPort>,
) -> Box<dyn PacketPort> {
    match guard {
        Some(g) => Box::new(GuardPort {
            inner: port,
            guard: g.clone(),
        }),
        None => port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    fn ipv4_to(dst: [u8; 4]) -> Vec<u8> {
        let mut ip = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1];
        ip.extend_from_slice(&dst);
        ip
    }

    #[test]
    fn nets_parse_and_contain() {
        let n: Net = "192.168.20.0/24".parse().unwrap();
        assert!(n.contains("192.168.20.77".parse().unwrap()));
        assert!(!n.contains("192.168.21.1".parse().unwrap()));
        assert!(n.contains("::ffff:192.168.20.5".parse().unwrap()));
        let one: Net = "10.1.2.3".parse().unwrap();
        assert_eq!(one.to_string(), "10.1.2.3/32");
        assert!(one.contains("10.1.2.3".parse().unwrap()));
        assert!(!one.contains("10.1.2.4".parse().unwrap()));
        let v6: Net = "2001:db8::/33".parse().unwrap();
        assert!(v6.contains("2001:db8:7fff::1".parse().unwrap()));
        assert!(!v6.contains("2001:db8:8000::1".parse().unwrap()));
        assert!("10.0.0.0/33".parse::<Net>().is_err());
        assert!("eth0".parse::<Net>().is_err());
        let all: Net = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn frames_are_checked_by_their_destination() {
        let l = Limits {
            destinations: vec!["192.168.20.0/24".parse().unwrap()],
            ..Default::default()
        };
        let g = Guard::new(&l).unwrap();
        assert!(g
            .admit(&eth(0x0800, &ipv4_to([192, 168, 20, 9])), 1)
            .is_ok());
        assert!(g.admit(&eth(0x0800, &ipv4_to([8, 8, 8, 8])), 1).is_err());
        // Under two VLAN tags.
        let mut tagged = vec![0u8; 12];
        tagged.extend_from_slice(&[0x88, 0xa8, 0, 10, 0x81, 0x00, 0, 20, 0x08, 0x00]);
        tagged.extend_from_slice(&ipv4_to([8, 8, 4, 4]));
        assert!(g.admit(&tagged, 1).is_err());
        // Link-scoped and ARP pass; other ethertypes do not.
        assert!(g
            .admit(&eth(0x0800, &ipv4_to([255, 255, 255, 255])), 1)
            .is_ok());
        assert!(g.admit(&eth(0x0800, &ipv4_to([224, 0, 0, 22])), 1).is_ok());
        assert!(g.admit(&eth(0x0800, &ipv4_to([239, 1, 1, 1])), 1).is_err());
        assert!(g.admit(&eth(0x0806, &[0; 28]), 1).is_ok());
        assert!(g.admit(&eth(0x88cc, &[0; 40]), 1).is_err());
        assert!(g.admit(&[0u8; 6], 1).is_err());
        // Raw IP captures.
        assert!(g.admit(&ipv4_to([192, 168, 20, 1]), LINKTYPE_RAW).is_ok());
        assert!(g.admit(&ipv4_to([192, 168, 30, 1]), LINKTYPE_RAW).is_err());
        let mut v6 = vec![0x60, 0, 0, 0, 0, 0, 58, 64];
        v6.extend_from_slice(&[0; 16]);
        let mut dst = [0u8; 16];
        dst[0] = 0xff;
        dst[1] = 0x02;
        v6.extend_from_slice(&dst);
        assert!(g.admit(&eth(0x86dd, &v6), 1).is_ok());
        assert_eq!(g.refused(), 6);
    }

    #[test]
    fn the_guard_paces_all_frames_together() {
        let l = Limits {
            max_pps: Some(2000.0),
            ..Default::default()
        };
        let g = Guard::new(&l).unwrap();
        let start = Instant::now();
        let mut waited = Duration::ZERO;
        for _ in 0..200 {
            let w = g.wait(100);
            if !w.is_zero() {
                std::thread::sleep(w);
                waited += w;
            }
        }
        // 200 frames at 2000 pps take 100 ms, less the burst allowance.
        let took = start.elapsed();
        assert!(took >= Duration::from_millis(90), "{took:?}");
        assert!(waited > Duration::ZERO);

        let bits = Limits {
            max_bps: Some(8e6),
            ..Default::default()
        };
        let g = Guard::new(&bits).unwrap();
        // 1000-byte frames at 8 Mbit/s: one a millisecond.
        let mut total = Duration::ZERO;
        for _ in 0..50 {
            total += g.wait(1000);
        }
        assert!(total >= Duration::from_millis(40), "{total:?}");
    }

    #[test]
    fn starts_are_checked_against_each_limit() {
        let l = Limits {
            interfaces: vec!["eth1".into()],
            destinations: vec!["10.0.0.0/24".parse().unwrap()],
            max_pps: Some(1000.0),
            max_bps: Some(10e6),
            max_duration: Some(60.0),
            max_runs: Some(2),
            max_flows: Some(100),
            allow_unlimited: false,
        };
        assert!(l.check_iface("eth1").is_ok());
        let e = l.check_iface("eth0").unwrap_err();
        assert_eq!(e.code, RpcError::FORBIDDEN);
        assert_eq!(refused_limit(&e), Some("interfaces"));

        assert!(l.check_dsts("10.0.0.10".parse().unwrap(), 200, "x").is_ok());
        let e = l
            .check_dsts("10.0.0.10".parse().unwrap(), 300, "x")
            .unwrap_err();
        assert_eq!(refused_limit(&e), Some("destinations"));
        assert!(e.message.contains("10.0.1."), "{}", e.message);

        assert!(l.check_duration(Some(Duration::from_secs(60))).is_ok());
        assert!(l.check_duration(None).is_ok());
        let e = l.check_duration(Some(Duration::from_secs(61))).unwrap_err();
        assert_eq!(refused_limit(&e), Some("max_duration"));
        assert_eq!(l.duration_or_max(None), Some(Duration::from_secs(60)));

        let ok = Demand {
            pps: 1000.0,
            bps: 5e6,
            unlimited: false,
        };
        assert!(l.check_demand(ok, "x").is_ok());
        let e = l
            .check_demand(Demand { pps: 1001.0, ..ok }, "x")
            .unwrap_err();
        assert_eq!(refused_limit(&e), Some("max_pps"));
        let e = l.check_demand(Demand { bps: 11e6, ..ok }, "x").unwrap_err();
        assert_eq!(refused_limit(&e), Some("max_bps"));
        let e = l
            .check_demand(
                Demand {
                    unlimited: true,
                    ..ok
                },
                "x",
            )
            .unwrap_err();
        assert_eq!(refused_limit(&e), Some("allow_unlimited"));
        let open = Limits {
            allow_unlimited: true,
            ..l.clone()
        };
        assert!(open
            .check_demand(
                Demand {
                    unlimited: true,
                    ..ok
                },
                "x"
            )
            .is_ok());

        assert_eq!(l.check_flows(50.0, 0, "x").unwrap(), 100);
        assert_eq!(l.check_flows(50.0, 10, "x").unwrap(), 10);
        assert_eq!(
            refused_limit(&l.check_flows(101.0, 0, "x").unwrap_err()),
            Some("max_flows")
        );
        assert_eq!(
            refused_limit(&l.check_flows(1.0, 101, "x").unwrap_err()),
            Some("max_flows")
        );

        assert!(l.check_runs(1).is_ok());
        assert_eq!(
            refused_limit(&l.check_runs(2).unwrap_err()),
            Some("max_runs")
        );

        // Nothing limited: everything goes.
        let none = Limits::default();
        assert!(none.is_empty());
        assert!(none.check_iface("anything").is_ok());
        assert!(none
            .check_demand(
                Demand {
                    unlimited: true,
                    ..ok
                },
                "x"
            )
            .is_ok());
        assert!(Guard::new(&none).is_none());
    }

    #[test]
    fn limits_read_from_a_file() {
        let l = Limits::from_toml(
            r#"
            format = 1
            [limits]
            interfaces = ["enp0s8"]
            destinations = ["192.168.20.0/24", "2001:db8::/64"]
            max_pps = "50kpps"
            max_bps = 2e8
            max_duration = "10m"
            max_runs = 4
            max_flows = 2000
            allow_unlimited = true
            "#,
        )
        .unwrap();
        assert_eq!(l.max_pps, Some(50_000.0));
        assert_eq!(l.max_bps, Some(2e8));
        assert_eq!(l.max_duration, Some(600.0));
        assert_eq!(l.destinations.len(), 2);
        assert!(l.allow_unlimited);
        let text = l.describe().join("\n");
        assert!(text.contains("50 kpps"), "{text}");
        assert!(text.contains("200 Mbit/s"), "{text}");
        assert!(text.contains("runs end after 10m"), "{text}");
        // Round trip through server.info's JSON.
        let back: Limits = serde_json::from_value(serde_json::to_value(&l).unwrap()).unwrap();
        assert_eq!(back, l);

        assert!(Limits::from_toml("[limits]\nmax_ppps = 3").is_err());
        assert!(Limits::from_toml("[limits]\nmax_pps = \"fast\"").is_err());
        assert!(Limits::from_toml("[limits]\nmax_runs = 0").is_err());
        assert_eq!(Limits::from_toml("").unwrap(), Limits::default());
        assert_eq!(parse_bps("1gbps").unwrap(), 1e9);
        assert_eq!(parse_pps("10kpps").unwrap(), 10_000.0);
        assert!(parse_pps("10mbps").is_err());
    }
}
