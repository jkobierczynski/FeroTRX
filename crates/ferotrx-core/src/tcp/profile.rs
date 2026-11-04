//! TCP profiles: a stateful TCP run described in a TOML file.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use crate::profile::OutputFile;
use crate::{Addressing, Emulation, SendSettings};

use super::engine::{
    TcpClientConfig, TcpConfig, TcpEndpoint, TcpOptions, TcpServerConfig, TcpTemplate,
};
use super::program::{TcpMessage, TcpProgram, TcpRole};
use crate::{
    check_format, parse_duration, parse_model, Capture, Error, MacAddr, Result, TrafficModel,
};

/// A stateful TCP run: what to play, the emulated client and server hosts,
/// and how many connections to open how fast.
///
/// ```toml
/// pcap = "http.pcap"          # the session to replay, relative to this file
/// flow = 1                    # which TCP connection in it (default: the first with data)
/// cps = 50                    # new connections per second (default 1)
/// model = "poisson"           # optional: how they spread around cps (Poisson,
///                             # bursts, ramp_up/hold/ramp_down; see TrafficModel)
/// # shape = ["0s:10%", "1m:100%"]  # or the rate over time in points
/// connections = 1000          # in all; 0 = until stopped (default 1)
/// concurrency = 100           # most open at once; 0 = no limit (default)
/// duration = "60s"            # optional
///
/// [client]                    # leave out to run only the server
/// iface = "enp0s3"
/// ip = "192.168.10.100/24"    # the emulated host; not an address of this machine
/// ips = 10                    # use 192.168.10.100-109 in turn (default 1)
/// gateway = "192.168.10.1"    # the router
/// vlan = 10                   # optional 802.1Q tag
/// # mac = "02:00:00:00:0a:64" # default: 02:00 and the four bytes of `ip`
///
/// [server]                    # leave out to run only the client; then set `connect`
/// iface = "enp0s3"
/// ip = "192.168.20.50/24"
/// gateway = "192.168.20.1"
/// vlan = 20
/// # port = 80                 # default: the server port in the capture
///
/// # connect = "192.168.20.50:80"  # where the client connects (default: the server)
///
/// [tcp]                       # optional; the defaults are shown
/// mss = 1460
/// rto = "250ms"               # until the round-trip time is measured
/// min_rto = "200ms"
/// max_retries = 8             # retransmissions of data before giving up
/// syn_retries = 6             # retransmissions of a SYN or SYN-ACK
/// idle_timeout = "30s"        # reset a connection with nothing received this long
/// time_wait = "4s"
/// arp_timeout = "5s"
/// send_window = "4M"          # most bytes in flight per connection
/// receive_window = "4M"       # the window announced; above 64K needs window scaling
/// window_scaling = true       # RFC 7323
/// timestamps = true           # RFC 7323: RTT from every ACK, and PAWS
/// sack = true                 # RFC 2018
/// verify = true
/// keep_timing = false         # wait the capture's gaps between messages
/// think_time = "0s"           # pause before answering the other end's message
/// ```
///
/// Instead of `pcap`, a session can be written out as `[[message]]` tables,
/// each with `from = "client"` or `"server"` and `text` (with `\r\n` escapes)
/// or `hex`, and optionally `delay` (the gap before it, played with
/// `keep_timing`), plus `port` for the server port and optionally `closer`.
///
/// To mix several kinds of connections, give `[[template]]` tables instead of
/// `pcap` or `[[message]]`, like TRex ASTF templates. `cps`, `connections` and
/// `concurrency` are for all templates together; each new connection gets a
/// template by `weight`. The server tells templates apart by port, so each
/// needs its own. A template can also have its own `cps`: then it opens
/// connections at that rate on its own instead of sharing the top-level
/// `cps` by weight. Its own `connections` and `concurrency` limit it further;
/// the top-level ones still hold for all templates together.
///
/// ```toml
/// cps = 100
/// connections = 0
/// concurrency = 500
///
/// [[template]]
/// name = "web"                # for the counters (default: the capture's name)
/// pcap = "http.pcap"
/// weight = 3                  # 3 of every 4 connections
/// # port = 80                 # the server's port (default: the capture's)
/// # connect = "192.168.20.1:8080"  # where clients connect (default: the servers)
///
/// [[template]]
/// name = "bulk"
/// pcap = "download.pcap"
/// port = 8080
/// cps = 2                     # its own rate, besides the 100 per second above
/// model = "burst=5"           # its own traffic model (needs its own cps)
/// connections = 50            # at most 50 of these
/// concurrency = 4             # at most 4 open at once
///
/// [[template]]
/// name = "echo"
/// port = 7
/// [[template.message]]
/// from = "client"
/// text = "ping\r\n"
/// [[template.message]]
/// from = "server"
/// text = "pong\r\n"
///
/// [client]
/// ip = "192.168.10.100/24"
/// ips = 250                   # client addresses, used in turn
/// gateway = "192.168.10.1"
///
/// [server]
/// ip = "192.168.20.50/24"
/// ips = 10                    # servers 192.168.20.50-59; clients connect to each in turn
/// gateway = "192.168.20.1"
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct TcpProfile {
    /// What the connections play: one template, or several mixed by weight.
    pub templates: Vec<TcpTemplateSpec>,
    pub client: Option<TcpHostSpec>,
    pub server: Option<TcpHostSpec>,
    /// Where the client connects, for templates without their own `connect`;
    /// defaults to the server host. The port may be left out (0): then each
    /// template's port.
    pub connect: Option<SocketAddr>,
    /// How many consecutive server addresses from `connect`'s the client
    /// connects to, in turn. Default: the server host's `ips` when connecting
    /// to it, else 1.
    pub connect_ips: Option<u32>,
    pub cps: f64,
    /// How new connections spread around `cps`.
    pub model: TrafficModel,
    pub connections: u64,
    pub concurrency: usize,
    pub source_ports: Range<u16>,
    pub duration: Option<Duration>,
    pub options: TcpOptions,
    /// How the interfaces send and receive (the `[output]` table): libpcap,
    /// AF_XDP or DPDK. The command line's settings win over these.
    pub output: SendSettings,
    /// Settings of the emulated hosts (the `[hosts]` table), for a client
    /// or server that gets its address by DHCP, SLAAC or DHCPv6, announces
    /// it or joins groups.
    pub host_options: crate::HostOptions,
}

/// One template of a [`TcpProfile`]: a kind of connection.
#[derive(Clone, Debug, PartialEq)]
pub struct TcpTemplateSpec {
    /// Name for the counters; default: the capture's file name, or `tN`.
    pub name: Option<String>,
    pub source: TcpSource,
    /// Share of the client's new connections (default 1; 0: server only).
    pub weight: u32,
    /// The port the server accepts this template on; default: the program's.
    pub port: Option<u16>,
    /// Where clients connect for this template; default: the profile's.
    /// Port 0 means the template's port.
    pub connect: Option<SocketAddr>,
    /// Server addresses from `connect`'s, in turn; default: the profile's.
    pub connect_ips: Option<u32>,
    /// The template's own rate of new connections, apart from the profile's `cps`.
    pub cps: Option<f64>,
    /// How the template's own connections spread around its `cps`.
    pub model: TrafficModel,
    /// Most connections of this template (default: no limit of its own).
    pub connections: Option<u64>,
    /// Most connections of this template open at once (default: no limit of its own).
    pub concurrency: Option<usize>,
}

impl TcpTemplateSpec {
    /// A template playing `source`, weight 1, everything else by default.
    pub fn new(source: TcpSource) -> Self {
        Self {
            name: None,
            source,
            weight: 1,
            port: None,
            connect: None,
            connect_ips: None,
            cps: None,
            model: TrafficModel::default(),
            connections: None,
            concurrency: None,
        }
    }

    /// The template's name: the one given, the capture's file name, or `tN`
    /// for the `index`th template (from 0).
    pub fn name(&self, index: usize) -> String {
        if let Some(n) = &self.name {
            return n.clone();
        }
        match &self.source {
            TcpSource::Pcap { path, flow } => {
                let stem = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| format!("t{}", index + 1));
                match flow {
                    Some(f) => format!("{stem}#{}", f + 1),
                    None => stem,
                }
            }
            TcpSource::Program(_) => format!("t{}", index + 1),
        }
    }

    /// Loads the program the template plays.
    pub fn program(&self) -> Result<TcpProgram> {
        match &self.source {
            TcpSource::Pcap { path, flow } => {
                let cap = Capture::from_path(path)
                    .map_err(|e| Error::Tcp(format!("cannot read {}: {e}", path.display())))?;
                TcpProgram::from_capture(&cap, *flow)
            }
            TcpSource::Program(p) => Ok(p.clone()),
        }
    }
}

/// What a [`TcpTemplateSpec`] plays.
#[derive(Clone, Debug, PartialEq)]
pub enum TcpSource {
    /// A TCP connection in a capture: `flow` is its index (from 0), or `None`
    /// for the first one with data.
    Pcap { path: PathBuf, flow: Option<usize> },
    /// A program written out in the profile.
    Program(TcpProgram),
}

impl std::fmt::Display for TcpSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpSource::Pcap { path, flow: None } => write!(f, "{}", path.display()),
            TcpSource::Pcap {
                path,
                flow: Some(i),
            } => write!(f, "{} flow {}", path.display(), i + 1),
            TcpSource::Program(p) => write!(f, "{} messages", p.messages.len()),
        }
    }
}

/// One emulated host of a [`TcpProfile`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpHostSpec {
    /// The interface; the command line's `--iface` if left out.
    pub iface: Option<String>,
    /// IPv4 or IPv6.
    pub ip: IpAddr,
    pub prefix: u8,
    pub ips: u32,
    pub gateway: Option<IpAddr>,
    pub vlan: Option<u16>,
    pub mac: Option<MacAddr>,
    pub next_hop_mac: Option<MacAddr>,
    /// The server's listening port.
    pub port: Option<u16>,
    /// How the host gets its address (`ip = "dhcp"`, `"slaac"`,
    /// `"dhcpv6"`), whether it announces it, and the groups it joins.
    pub emulation: Emulation,
}

impl TcpHostSpec {
    /// A host at `ip`, written `a.b.c.d` or `a.b.c.d/prefix` (default /24),
    /// or an IPv6 address with an optional prefix (default /64); or `dhcp`,
    /// `slaac` or `dhcpv6` for a host that gets its address that way (its
    /// `ip` is then 0.0.0.0 or :: until it has one).
    pub fn new(ip: &str) -> Result<Self> {
        if let Some(a) = Addressing::parse(ip) {
            let mut h = Self::new(&a.placeholder().to_string())?;
            h.prefix = 0;
            h.emulation.addressing = a;
            return Ok(h);
        }
        let (ip, prefix) = parse_ip_prefix(ip)?;
        Ok(Self {
            iface: None,
            ip,
            prefix,
            ips: 1,
            gateway: None,
            vlan: None,
            mac: None,
            next_hop_mac: None,
            port: None,
            emulation: Emulation::default(),
        })
    }

    /// True when the host gets its address by DHCP, SLAAC or DHCPv6.
    pub fn is_dynamic(&self) -> bool {
        self.emulation.addressing.is_dynamic()
    }

    /// The address as written: `ip/prefix`, or `dhcp`, `slaac`, `dhcpv6`.
    pub fn address_text(&self) -> String {
        if self.is_dynamic() {
            self.emulation.addressing.to_string()
        } else {
            format!("{}/{}", self.ip, self.prefix)
        }
    }

    /// The host's MAC address: the one given, or 02:00 followed by its IPv4
    /// address, or by the last four bytes of its IPv6 address. A host that
    /// gets its address by DHCP, SLAAC or DHCPv6 has no address to take it
    /// from: profiles give it 02:dc:00:00:00:01 (client) or 02 (server)
    /// unless it has a `mac`.
    pub fn mac(&self) -> MacAddr {
        if self.is_dynamic() && self.mac.is_none() {
            return MacAddr([0x02, 0xdc, 0, 0, 0, 1]);
        }
        self.mac.unwrap_or_else(|| {
            let o = match self.ip {
                IpAddr::V4(a) => a.octets(),
                IpAddr::V6(a) => {
                    let b = a.octets();
                    [b[12], b[13], b[14], b[15]]
                }
            };
            MacAddr([0x02, 0x00, o[0], o[1], o[2], o[3]])
        })
    }

    /// The host's last address, when it has more than one.
    pub fn last_ip(&self) -> IpAddr {
        let n = u128::from(self.ips.max(1) - 1);
        match self.ip {
            IpAddr::V4(a) => Ipv4Addr::from(u32::from(a).wrapping_add(n as u32)).into(),
            IpAddr::V6(a) => std::net::Ipv6Addr::from(u128::from(a).wrapping_add(n)).into(),
        }
    }

    pub(crate) fn endpoint(&self, port: usize) -> TcpEndpoint {
        TcpEndpoint {
            port,
            mac: self.mac(),
            ip: self.ip,
            ip_count: self.ips,
            prefix: self.prefix,
            gateway: self.gateway,
            next_hop_mac: self.next_hop_mac,
            vlan: self.vlan,
        }
    }
}

/// Parses `ADDRESS` or `ADDRESS/PREFIX`, IPv4 or IPv6; the prefix defaults
/// to 24 for IPv4 and 64 for IPv6.
pub fn parse_ip_prefix(s: &str) -> Result<(IpAddr, u8)> {
    let bad = || {
        Error::InvalidSpec(format!(
            "invalid address '{s}' (use e.g. 192.168.10.100/24 or fd00:10::100/64)"
        ))
    };
    let (ip, prefix) = match s.trim().split_once('/') {
        Some((ip, p)) => (ip, Some(p.parse::<u8>().map_err(|_| bad())?)),
        None => (s.trim(), None),
    };
    let ip: IpAddr = ip.trim().parse().map_err(|_| bad())?;
    let (max, default) = if ip.is_ipv4() { (32, 24) } else { (128, 64) };
    let prefix = prefix.unwrap_or(default);
    if prefix > max {
        return Err(bad());
    }
    Ok((ip, prefix))
}

/// Parses `LOW-HIGH` (both included) into a source port range.
pub fn parse_port_range(s: &str) -> Result<Range<u16>> {
    let bad = || Error::InvalidSpec(format!("invalid port range '{s}' (use e.g. 1024-65535)"));
    let (lo, hi) = s.split_once('-').ok_or_else(bad)?;
    let lo: u16 = lo.trim().parse().map_err(|_| bad())?;
    let hi: u16 = hi.trim().parse().map_err(|_| bad())?;
    if lo == 0 || hi < lo || hi == u16::MAX {
        return Err(bad());
    }
    Ok(lo..hi + 1)
}

impl Default for TcpProfile {
    fn default() -> Self {
        Self {
            templates: vec![TcpTemplateSpec::new(TcpSource::Program(TcpProgram::new(
                80,
                Vec::new(),
            )))],
            client: None,
            server: None,
            connect: None,
            connect_ips: None,
            cps: 1.0,
            model: TrafficModel::default(),
            connections: 1,
            concurrency: 0,
            source_ports: 1024..65535,
            duration: None,
            options: TcpOptions::default(),
            output: SendSettings::default(),
            host_options: crate::HostOptions::for_endpoints(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    format: Option<u32>,
    model: Option<String>,
    #[serde(default)]
    shape: Vec<String>,
    pcap: Option<String>,
    flow: Option<usize>,
    port: Option<u16>,
    closer: Option<String>,
    #[serde(default)]
    message: Vec<RawMessage>,
    #[serde(default)]
    template: Vec<RawTemplate>,
    cps: Option<f64>,
    connections: Option<u64>,
    concurrency: Option<usize>,
    source_ports: Option<String>,
    connect: Option<String>,
    connect_ips: Option<u32>,
    duration: Option<String>,
    client: Option<RawHost>,
    server: Option<RawHost>,
    tcp: Option<RawOptions>,
    output: Option<OutputFile>,
    hosts: Option<crate::host::RawHostOptions>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTemplate {
    name: Option<String>,
    pcap: Option<String>,
    flow: Option<usize>,
    port: Option<u16>,
    closer: Option<String>,
    #[serde(default)]
    message: Vec<RawMessage>,
    weight: Option<u32>,
    connect: Option<String>,
    connect_ips: Option<u32>,
    cps: Option<f64>,
    model: Option<String>,
    #[serde(default)]
    shape: Vec<String>,
    connections: Option<u64>,
    concurrency: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawMessage {
    pub from: String,
    pub text: Option<String>,
    pub hex: Option<String>,
    pub delay: Option<String>,
}

impl RawMessage {
    /// The message's role, bytes and delay.
    pub(crate) fn parts(self) -> Result<(TcpRole, Vec<u8>, Duration)> {
        let data = match (self.text, self.hex) {
            (Some(t), None) => t.into_bytes(),
            (None, Some(h)) => hex(&h)?,
            _ => return Err(Error::Profile("give `text` or `hex`".into())),
        };
        let delay = self
            .delay
            .map(|d| parse_duration(&d))
            .transpose()?
            .unwrap_or_default();
        Ok((role(&self.from)?, data, delay))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawHost {
    iface: Option<String>,
    ip: String,
    ips: Option<u32>,
    gateway: Option<String>,
    vlan: Option<u16>,
    mac: Option<String>,
    next_hop_mac: Option<String>,
    port: Option<u16>,
    announce: Option<bool>,
    groups: Option<Vec<String>>,
    hostname: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOptions {
    mss: Option<u16>,
    rto: Option<String>,
    min_rto: Option<String>,
    max_retries: Option<u32>,
    syn_retries: Option<u32>,
    time_wait: Option<String>,
    idle_timeout: Option<String>,
    arp_timeout: Option<String>,
    send_window: Option<RawSize>,
    receive_window: Option<RawSize>,
    window_scaling: Option<bool>,
    timestamps: Option<bool>,
    sack: Option<bool>,
    verify: Option<bool>,
    keep_timing: Option<bool>,
    think_time: Option<String>,
    seed: Option<u64>,
}

/// A size in bytes: a number, or text such as `"64K"` or `"4M"`.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawSize {
    Bytes(u64),
    Text(String),
}

impl RawSize {
    fn bytes(self, what: &str) -> Result<u32> {
        let n = match self {
            RawSize::Bytes(n) => n,
            RawSize::Text(t) => parse_size(&t)?,
        };
        u32::try_from(n).map_err(|_| Error::Profile(format!("{what} {n} is too large")))
    }
}

/// Parses a size in bytes: `65535`, or with a suffix `K`, `M` or `G` (powers
/// of 1024; `KB`, `KiB` and lower case work too), e.g. `64K` or `4M`.
pub fn parse_size(s: &str) -> Result<u64> {
    let bad = || Error::InvalidSpec(format!("invalid size '{s}' (use e.g. 65535, 64K or 4M)"));
    let t = s.trim();
    let digits = t
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(digits);
    let unit = unit.trim().to_ascii_lowercase();
    let unit = unit
        .strip_suffix("ib")
        .or_else(|| unit.strip_suffix('b'))
        .unwrap_or(&unit);
    let mult: u64 = match unit {
        "" => 1,
        "k" => 1 << 10,
        "m" => 1 << 20,
        "g" => 1 << 30,
        _ => return Err(bad()),
    };
    let v: f64 = num.parse().map_err(|_| bad())?;
    let n = v * mult as f64;
    if !(n.is_finite() && n >= 0.0 && n < u64::MAX as f64) {
        return Err(bad());
    }
    Ok(n.round() as u64)
}

fn role(s: &str) -> Result<TcpRole> {
    match s {
        "client" => Ok(TcpRole::Client),
        "server" => Ok(TcpRole::Server),
        other => Err(Error::Profile(format!("'{other}' is not client or server"))),
    }
}

fn hex(s: &str) -> Result<Vec<u8>> {
    let digits: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b':')
        .collect();
    if !digits.len().is_multiple_of(2) {
        return Err(Error::Profile(format!(
            "hex '{s}' has an odd number of digits"
        )));
    }
    digits
        .chunks(2)
        .map(|c| {
            std::str::from_utf8(c)
                .ok()
                .and_then(|t| u8::from_str_radix(t, 16).ok())
                .ok_or_else(|| Error::Profile(format!("'{s}' is not hex")))
        })
        .collect()
}

/// Parses where clients connect: `IP:PORT` (`[IPv6]:PORT`), or `IP` (port 0:
/// each template's).
pub fn parse_connect_addr(c: &str) -> Result<SocketAddr> {
    let bad = || {
        Error::Profile(format!(
            "invalid connect address '{c}' (use IP:PORT, [IPv6]:PORT or IP)"
        ))
    };
    let c = c.trim();
    if let Ok(a) = c.parse::<SocketAddr>() {
        return Ok(a);
    }
    let ip = c
        .strip_prefix('[')
        .and_then(|c| c.strip_suffix(']'))
        .unwrap_or(c);
    Ok(SocketAddr::new(ip.parse().map_err(|_| bad())?, 0))
}

/// What a profile or template plays: `pcap` (and `flow`), or `[[message]]`
/// tables with `port` and `closer`. In a template, `port` may go with `pcap`.
fn source(
    pcap: Option<String>,
    flow: Option<usize>,
    port: Option<u16>,
    closer: Option<String>,
    messages: Vec<RawMessage>,
    base_dir: &Path,
    template: bool,
) -> Result<TcpSource> {
    match (pcap, messages.is_empty()) {
        (Some(path), true) => {
            if closer.is_some() || (port.is_some() && !template) {
                return Err(Error::Profile(
                    "`port` and `closer` go with [[message]]; with `pcap`, set [server] port"
                        .into(),
                ));
            }
            Ok(TcpSource::Pcap {
                path: base_dir.join(path),
                flow: match flow {
                    Some(0) => return Err(Error::Profile("flows are numbered from 1".into())),
                    f => f.map(|f| f - 1),
                },
            })
        }
        (None, false) => {
            if flow.is_some() {
                return Err(Error::Profile("`flow` goes with `pcap`".into()));
            }
            let port = port
                .ok_or_else(|| Error::Profile("a profile with [[message]] needs `port`".into()))?;
            let mut out = Vec::new();
            for (i, m) in messages.into_iter().enumerate() {
                let (from, data, delay) = m
                    .parts()
                    .map_err(|e| Error::Profile(format!("message {}: {e}", i + 1)))?;
                out.push(TcpMessage::new(from, data).with_delay(delay));
            }
            let mut program = TcpProgram::new(port, out);
            if let Some(c) = closer {
                program.closer = role(&c)?;
            }
            Ok(TcpSource::Program(program))
        }
        (Some(_), false) => Err(Error::Profile(
            "give `pcap` or [[message]], not both".into(),
        )),
        (None, true) => Err(Error::Profile("give `pcap` or [[message]] tables".into())),
    }
}

impl RawHost {
    pub(crate) fn spec(self, what: &str) -> Result<TcpHostSpec> {
        let ctx = |e: Error| Error::Profile(format!("[{what}]: {e}"));
        let mut h = TcpHostSpec::new(&self.ip).map_err(ctx)?;
        h.iface = self.iface;
        h.ips = self.ips.unwrap_or(1);
        h.gateway = self
            .gateway
            .map(|g| {
                g.parse()
                    .map_err(|_| ctx(Error::InvalidSpec(format!("invalid gateway '{g}'"))))
            })
            .transpose()?;
        h.vlan = self.vlan;
        h.mac = self.mac.map(|m| m.parse()).transpose().map_err(ctx)?;
        h.next_hop_mac = self
            .next_hop_mac
            .map(|m| m.parse())
            .transpose()
            .map_err(ctx)?;
        h.port = self.port;
        h.emulation.announce = self.announce;
        h.emulation.hostname = self.hostname;
        h.emulation.groups =
            parse_groups(self.groups.as_deref().unwrap_or_default()).map_err(ctx)?;
        if h.is_dynamic() && h.mac.is_none() {
            let n = if what == "server" { 2 } else { 1 };
            h.mac = Some(MacAddr([0x02, 0xdc, 0, 0, 0, n]));
        }
        Ok(h)
    }
}

/// Parses multicast group addresses, IPv4 or IPv6.
pub fn parse_groups(groups: &[String]) -> Result<Vec<IpAddr>> {
    groups
        .iter()
        .map(|g| {
            let ip: IpAddr = g
                .trim()
                .parse()
                .map_err(|_| Error::InvalidSpec(format!("invalid group address '{g}'")))?;
            if !ip.is_multicast() {
                return Err(Error::InvalidSpec(format!("{ip} is not a multicast group")));
            }
            Ok(ip)
        })
        .collect()
}

impl TcpProfile {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)?;
        Self::from_toml(&text, path.parent().unwrap_or(Path::new(".")))
    }

    /// Parses a profile; `pcap` paths are relative to `base_dir`.
    pub fn from_toml(text: &str, base_dir: &Path) -> Result<Self> {
        let raw: RawProfile = toml::from_str(text).map_err(|e| Error::Profile(e.to_string()))?;
        check_format(raw.format)?;
        let model = parse_model(raw.model.as_deref(), &raw.shape)
            .map_err(|e| Error::Profile(e.to_string()))?;
        let top_level = raw.pcap.is_some()
            || raw.flow.is_some()
            || raw.port.is_some()
            || raw.closer.is_some()
            || !raw.message.is_empty();
        let templates = if raw.template.is_empty() {
            let source = source(
                raw.pcap,
                raw.flow,
                raw.port,
                raw.closer,
                raw.message,
                base_dir,
                false,
            )?;
            vec![TcpTemplateSpec::new(source)]
        } else {
            if top_level {
                return Err(Error::Profile(
                    "give `pcap` or [[message]] at the top, or [[template]] tables, not both"
                        .into(),
                ));
            }
            let mut out = Vec::new();
            for (i, t) in raw.template.into_iter().enumerate() {
                let label = t.name.clone().unwrap_or_else(|| (i + 1).to_string());
                let ctx = |e: Error| match e {
                    Error::Profile(m) => Error::Profile(format!("template {label}: {m}")),
                    e => Error::Profile(format!("template {label}: {e}")),
                };
                let src = source(t.pcap, t.flow, t.port, t.closer, t.message, base_dir, true)
                    .map_err(ctx)?;
                out.push(TcpTemplateSpec {
                    name: t.name,
                    source: src,
                    weight: t.weight.unwrap_or(1),
                    port: t.port,
                    connect: t
                        .connect
                        .map(|c| parse_connect_addr(&c))
                        .transpose()
                        .map_err(ctx)?,
                    connect_ips: t.connect_ips,
                    model: parse_model(t.model.as_deref(), &t.shape).map_err(ctx)?,
                    cps: t.cps,
                    connections: t.connections,
                    concurrency: t.concurrency,
                });
            }
            out
        };
        let mut p = TcpProfile {
            templates,
            model,
            ..Default::default()
        };
        p.client = raw.client.map(|h| h.spec("client")).transpose()?;
        p.server = raw.server.map(|h| h.spec("server")).transpose()?;
        p.connect = raw.connect.map(|c| parse_connect_addr(&c)).transpose()?;
        p.connect_ips = raw.connect_ips;
        if p.templates.len() > 1 && p.server.as_ref().is_some_and(|s| s.port.is_some()) {
            return Err(Error::Profile(
                "with several templates, give each its `port` instead of [server] port".into(),
            ));
        }
        if let Some(cps) = raw.cps {
            p.cps = cps;
        }
        if let Some(n) = raw.connections {
            p.connections = n;
        }
        if let Some(n) = raw.concurrency {
            p.concurrency = n;
        }
        if let Some(r) = raw.source_ports {
            p.source_ports = parse_port_range(&r)?;
        }
        p.duration = raw.duration.map(|d| parse_duration(&d)).transpose()?;
        p.output = raw
            .output
            .map_or(Ok(SendSettings::default()), OutputFile::settings)?;
        p.host_options = crate::host::host_options(raw.hosts, crate::HostOptions::for_endpoints())
            .map_err(|e| Error::Profile(format!("[hosts]: {e}")))?;
        if let Some(o) = raw.tcp {
            let d = |v: Option<String>, dflt: Duration| -> Result<Duration> {
                v.map_or(Ok(dflt), |s| parse_duration(&s))
            };
            let defaults = TcpOptions::default();
            p.options = TcpOptions {
                mss: o.mss.unwrap_or(defaults.mss),
                rto: d(o.rto, defaults.rto)?,
                min_rto: d(o.min_rto, defaults.min_rto)?,
                max_retries: o.max_retries.unwrap_or(defaults.max_retries),
                syn_retries: o.syn_retries.unwrap_or(defaults.syn_retries),
                time_wait: d(o.time_wait, defaults.time_wait)?,
                idle_timeout: d(o.idle_timeout, defaults.idle_timeout)?,
                arp_timeout: d(o.arp_timeout, defaults.arp_timeout)?,
                send_window: o
                    .send_window
                    .map_or(Ok(defaults.send_window), |w| w.bytes("send_window"))?,
                receive_window: o
                    .receive_window
                    .map_or(Ok(defaults.receive_window), |w| w.bytes("receive_window"))?,
                window_scaling: o.window_scaling.unwrap_or(defaults.window_scaling),
                timestamps: o.timestamps.unwrap_or(defaults.timestamps),
                sack: o.sack.unwrap_or(defaults.sack),
                verify: o.verify.unwrap_or(defaults.verify),
                keep_timing: o.keep_timing.unwrap_or(defaults.keep_timing),
                think_time: d(o.think_time, defaults.think_time)?,
                seed: o.seed.unwrap_or(defaults.seed),
            };
        }
        if p.client.is_none() && p.server.is_none() {
            return Err(Error::Profile(
                "give a [client] table, a [server] table or both".into(),
            ));
        }
        Ok(p)
    }

    /// Loads the programs the templates play, in order.
    pub fn programs(&self) -> Result<Vec<TcpProgram>> {
        self.templates
            .iter()
            .enumerate()
            .map(|(i, t)| {
                t.program()
                    .map_err(|e| Error::Tcp(format!("template {}: {e}", t.name(i))))
            })
            .collect()
    }

    /// The interfaces the hosts use, without repeats: port `i` of the engine
    /// is interface `i`. Hosts without an interface use `default`.
    pub fn interfaces(&self, default: Option<&str>) -> Result<Vec<String>> {
        let mut out: Vec<String> = Vec::new();
        for (what, host) in [("client", &self.client), ("server", &self.server)] {
            let Some(h) = host else { continue };
            let name = h
                .iface
                .as_deref()
                .or(default)
                .ok_or_else(|| Error::Tcp(format!("the {what} has no interface")))?;
            if !out.iter().any(|n| n == name) {
                out.push(name.to_string());
            }
        }
        Ok(out)
    }

    /// The emulated hosts `config`'s client and server need (DHCP, SLAAC,
    /// DHCPv6, announcements, groups), if any; `config` as
    /// [`config`](Self::config) makes it.
    pub fn endpoint_hosts(&self, config: &TcpConfig) -> Result<Option<crate::EndpointHosts>> {
        crate::EndpointHosts::new(
            config,
            self.client.as_ref().map(|h| &h.emulation),
            self.server.as_ref().map(|h| &h.emulation),
        )
    }

    /// The engine configuration, with ports numbered as in `interfaces`.
    /// `programs` are the templates' programs, as [`programs`](Self::programs)
    /// loads them.
    pub fn config(
        &self,
        programs: &[Arc<TcpProgram>],
        interfaces: &[String],
        default: Option<&str>,
    ) -> Result<TcpConfig> {
        if programs.len() != self.templates.len() {
            return Err(Error::Tcp(format!(
                "{} programs for {} templates",
                programs.len(),
                self.templates.len()
            )));
        }
        let port = |h: &TcpHostSpec| -> Result<usize> {
            let name = h.iface.as_deref().or(default).unwrap_or_default();
            interfaces
                .iter()
                .position(|n| n == name)
                .ok_or_else(|| Error::Tcp(format!("interface {name} is not open")))
        };
        let single = self.templates.len() == 1;
        if !single
            && self.connect.is_some_and(|c| c.port() != 0)
            && self.templates.iter().any(|t| t.connect.is_none())
        {
            return Err(Error::Tcp(
                "with several templates, `connect` takes an address without a port \
                 (each template's port is used), or give each template its own `connect`"
                    .into(),
            ));
        }
        let mut templates = Vec::new();
        for (i, (t, program)) in self.templates.iter().zip(programs).enumerate() {
            let name = t.name(i);
            let listen = t
                .port
                .or(if single {
                    self.server.as_ref().and_then(|s| s.port)
                } else {
                    None
                })
                .unwrap_or(program.server_port);
            // Where clients connect: the template's, the profile's, or the server.
            let (connect, ips) = match (t.connect, self.connect, &self.server) {
                (Some(c), _, _) => (c, t.connect_ips.or(self.connect_ips).unwrap_or(1)),
                (None, Some(c), _) => (c, t.connect_ips.or(self.connect_ips).unwrap_or(1)),
                (None, None, Some(s)) => (
                    SocketAddr::new(s.ip, 0),
                    t.connect_ips.or(self.connect_ips).unwrap_or(s.ips),
                ),
                (None, None, None) if self.client.is_some() => {
                    return Err(Error::Tcp(
                        "a client without a server needs the address to connect to".into(),
                    ))
                }
                (None, None, None) => (SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0), 1),
            };
            let connect = if connect.port() == 0 {
                SocketAddr::new(connect.ip(), listen)
            } else {
                connect
            };
            templates.push(TcpTemplate {
                name,
                program: program.clone(),
                connect,
                connect_ips: ips,
                listen_port: listen,
                weight: t.weight,
                cps: t.cps,
                model: t.model.clone(),
                connections: t.connections.unwrap_or(0),
                concurrency: t.concurrency.unwrap_or(0),
            });
        }
        let server = match &self.server {
            Some(h) => Some(TcpServerConfig::new(h.endpoint(port(h)?))),
            None => None,
        };
        let client = match &self.client {
            Some(h) => {
                let mut c = TcpClientConfig::new(h.endpoint(port(h)?));
                c.cps = self.cps;
                c.model = self.model.clone();
                c.connections = self.connections;
                c.concurrency = self.concurrency;
                c.source_ports = self.source_ports.clone();
                Some(c)
            }
            None => None,
        };
        Ok(TcpConfig {
            templates,
            client,
            server,
            options: self.options.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_lab_profile() {
        let p = TcpProfile::from_toml(
            r#"
            pcap = "web.pcap"
            flow = 2
            cps = 20
            connections = 0
            [client]
            ip = "192.168.10.100/24"
            ips = 5
            gateway = "192.168.10.1"
            vlan = 10
            [server]
            iface = "eth1"
            ip = "192.168.20.50"
            vlan = 20
            [tcp]
            rto = "100ms"
            verify = false
            "#,
            Path::new("/lab"),
        )
        .unwrap();
        assert_eq!(
            p.templates[0].source,
            TcpSource::Pcap {
                path: "/lab/web.pcap".into(),
                flow: Some(1)
            }
        );
        assert_eq!(p.templates[0].name(0), "web#2");
        let c = p.client.as_ref().unwrap();
        assert_eq!((c.ips, c.vlan, c.prefix), (5, Some(10), 24));
        assert_eq!(c.mac().to_string(), "02:00:c0:a8:0a:64");
        assert_eq!(p.options.rto, Duration::from_millis(100));
        assert!(!p.options.verify);
        assert_eq!(p.interfaces(Some("eth0")).unwrap(), ["eth0", "eth1"]);
        assert!(p.interfaces(None).is_err());

        let program = Arc::new(TcpProgram::new(8080, Vec::new()));
        let cfg = p
            .config(&[program], &["eth0".into(), "eth1".into()], Some("eth0"))
            .unwrap();
        assert_eq!(cfg.templates[0].connect.to_string(), "192.168.20.50:8080");
        assert_eq!(cfg.templates[0].listen_port, 8080);
        let client = cfg.client.unwrap();
        assert_eq!(
            (client.endpoint.port, cfg.server.unwrap().endpoint.port),
            (0, 1)
        );
    }

    #[test]
    fn parses_an_ipv6_profile() {
        let p = TcpProfile::from_toml(
            r#"
            cps = 10
            [[template]]
            name = "web"
            port = 80
            [[template.message]]
            from = "client"
            text = "GET"
            [[template]]
            name = "alt"
            port = 8080
            connect = "[fd00:20::1]:18080"
            [[template.message]]
            from = "client"
            text = "hi"
            [client]
            ip = "fd00:10::100"
            ips = 300
            gateway = "fd00:10::1"
            [server]
            ip = "fd00:20::50/120"
            ips = 2
            "#,
            Path::new("."),
        )
        .unwrap();
        let c = p.client.as_ref().unwrap();
        assert_eq!(c.prefix, 64);
        assert_eq!(c.mac().to_string(), "02:00:00:00:01:00");
        assert_eq!(c.last_ip().to_string(), "fd00:10::22b");
        assert_eq!(p.server.as_ref().unwrap().prefix, 120);
        let programs = p
            .programs()
            .unwrap()
            .into_iter()
            .map(Arc::new)
            .collect::<Vec<_>>();
        let cfg = p.config(&programs, &["eth0".into()], Some("eth0")).unwrap();
        assert_eq!(cfg.templates[0].connect.to_string(), "[fd00:20::50]:80");
        assert_eq!(cfg.templates[0].connect_ips, 2);
        assert_eq!(cfg.templates[1].connect.to_string(), "[fd00:20::1]:18080");
        assert_eq!(
            cfg.client.unwrap().endpoint.gateway,
            Some("fd00:10::1".parse().unwrap())
        );

        assert_eq!(
            parse_connect_addr("[fd00::1]").unwrap().to_string(),
            "[fd00::1]:0"
        );
        assert_eq!(parse_connect_addr("fd00::1").unwrap().port(), 0);
        assert!(parse_ip_prefix("fd00::1/129").is_err());
        assert!(parse_ip_prefix("10.0.0.1/33").is_err());
    }

    #[test]
    fn parses_tcp_options_and_template_rates() {
        let p = TcpProfile::from_toml(
            r#"
            cps = 10
            connections = 100
            [[template]]
            name = "web"
            port = 80
            [[template.message]]
            from = "client"
            text = "GET"
            [[template]]
            name = "bulk"
            port = 8080
            cps = 2.5
            connections = 20
            concurrency = 3
            [[template.message]]
            from = "server"
            text = "data"
            [client]
            ip = "10.0.0.1"
            [server]
            ip = "10.0.0.2"
            [tcp]
            rto = "1s"
            min_rto = "50ms"
            syn_retries = 2
            max_retries = 4
            idle_timeout = "2m"
            send_window = "8M"
            receive_window = 65535
            window_scaling = false
            timestamps = false
            sack = false
            "#,
            Path::new("."),
        )
        .unwrap();
        let o = &p.options;
        assert_eq!(
            (
                o.rto,
                o.min_rto,
                o.syn_retries,
                o.max_retries,
                o.idle_timeout
            ),
            (
                Duration::from_secs(1),
                Duration::from_millis(50),
                2,
                4,
                Duration::from_secs(120)
            )
        );
        assert_eq!((o.send_window, o.receive_window), (8 << 20, 65535));
        assert!(!o.window_scaling && !o.timestamps && !o.sack && o.verify);
        let programs = p
            .programs()
            .unwrap()
            .into_iter()
            .map(Arc::new)
            .collect::<Vec<_>>();
        let cfg = p.config(&programs, &["eth0".into()], Some("eth0")).unwrap();
        let t = &cfg.templates;
        assert_eq!((t[0].cps, t[0].connections, t[0].concurrency), (None, 0, 0));
        assert_eq!(
            (t[1].cps, t[1].connections, t[1].concurrency),
            (Some(2.5), 20, 3)
        );

        assert_eq!(parse_size("64K").unwrap(), 65536);
        assert_eq!(parse_size("4MiB").unwrap(), 4 << 20);
        assert_eq!(parse_size("1.5m").unwrap(), 3 << 19);
        assert_eq!(parse_size(" 1000 ").unwrap(), 1000);
        assert!(parse_size("4X").is_err());
        assert!(parse_size("").is_err());
        let err = TcpProfile::from_toml(
            "[client]\nip = \"10.0.0.1\"\nport = 1\n[tcp]\nsend_window = \"8G\"",
            Path::new("."),
        );
        assert!(err.is_err());
    }

    #[test]
    fn parses_written_out_messages() {
        let p = TcpProfile::from_toml(
            r#"
            port = 7
            closer = "server"
            connect = "10.0.0.1:7"
            [[message]]
            from = "client"
            text = "hello\r\n"
            [[message]]
            from = "server"
            hex = "68 65 6c 6c 6f"
            [client]
            ip = "10.0.0.2"
            "#,
            Path::new("."),
        )
        .unwrap();
        let prog = p.programs().unwrap().remove(0);
        assert_eq!(prog.messages[1].data, b"hello");
        assert_eq!(prog.closer, TcpRole::Server);
        assert_eq!(p.connect.unwrap().port(), 7);
    }

    #[test]
    fn rejects_bad_profiles() {
        for (text, want) in [
            ("[client]\nip = \"10.0.0.1\"", "give `pcap`"),
            ("pcap = \"a.pcap\"", "[client] table"),
            (
                "pcap = \"a.pcap\"\nflow = 0\n[client]\nip = \"10.0.0.1\"",
                "from 1",
            ),
            (
                "pcap = \"a.pcap\"\n[client]\nip = \"10.0.0.300\"",
                "invalid address",
            ),
            (
                "pcap = \"a.pcap\"\nbogus = 1\n[client]\nip = \"10.0.0.1\"",
                "unknown field",
            ),
        ] {
            let err = TcpProfile::from_toml(text, Path::new("."))
                .unwrap_err()
                .to_string();
            assert!(err.contains(want), "{text}: {err}");
        }
        assert_eq!(parse_port_range("2000-2009").unwrap(), 2000..2010);
        assert!(parse_port_range("0-5").is_err());
    }

    #[test]
    fn parses_templates() {
        let p = TcpProfile::from_toml(
            r#"
            cps = 100
            connect_ips = 4
            [[template]]
            pcap = "http.pcap"
            weight = 3
            [[template]]
            name = "echo"
            port = 7
            weight = 0
            [[template.message]]
            from = "client"
            text = "ping"
            [[template]]
            name = "fwd"
            pcap = "http.pcap"
            port = 8080
            connect = "192.168.20.1:18080"
            connect_ips = 1
            [client]
            ip = "192.168.10.100"
            [server]
            ip = "192.168.20.50"
            ips = 10
            "#,
            Path::new("/lab"),
        )
        .unwrap();
        assert_eq!(p.templates.len(), 3);
        let names: Vec<String> = p
            .templates
            .iter()
            .enumerate()
            .map(|(i, t)| t.name(i))
            .collect();
        assert_eq!(names, ["http", "echo", "fwd"]);
        let programs = [
            Arc::new(TcpProgram::new(80, Vec::new())),
            Arc::new(p.templates[1].program().unwrap()),
            Arc::new(TcpProgram::new(80, Vec::new())),
        ];
        let cfg = p.config(&programs, &["eth0".into()], Some("eth0")).unwrap();
        let t: Vec<(String, u32, u16, u32)> = cfg
            .templates
            .iter()
            .map(|t| {
                (
                    t.connect.to_string(),
                    t.connect_ips,
                    t.listen_port,
                    t.weight,
                )
            })
            .collect();
        assert_eq!(
            t,
            [
                ("192.168.20.50:80".to_string(), 4, 80, 3),
                ("192.168.20.50:7".to_string(), 4, 7, 0),
                ("192.168.20.1:18080".to_string(), 1, 8080, 1),
            ]
        );
    }

    #[test]
    fn rejects_bad_templates() {
        for (text, want) in [
            (
                "pcap = \"a.pcap\"\n[[template]]\npcap = \"b.pcap\"\n[client]\nip = \"10.0.0.1\"",
                "not both",
            ),
            (
                "[[template]]\npcap = \"a.pcap\"\n[[template]]\nflow = 2\n[client]\nip = \"10.0.0.1\"",
                "template 2: give `pcap`",
            ),
            (
                "[[template]]\npcap = \"a.pcap\"\n[[template]]\npcap = \"b.pcap\"\n[server]\nip = \"10.0.0.1\"\nport = 80",
                "each its `port`",
            ),
        ] {
            let err = TcpProfile::from_toml(text, Path::new("."))
                .unwrap_err()
                .to_string();
            assert!(err.contains(want), "{text}: {err}");
        }
        let p = TcpProfile::from_toml(
            "connect = \"10.0.0.9:80\"\n[[template]]\npcap = \"a.pcap\"\n[[template]]\npcap = \"b.pcap\"\n[client]\nip = \"10.0.0.1\"",
            Path::new("."),
        )
        .unwrap();
        let progs = [
            Arc::new(TcpProgram::new(80, Vec::new())),
            Arc::new(TcpProgram::new(81, Vec::new())),
        ];
        let err = p.config(&progs, &["e".into()], Some("e")).unwrap_err();
        assert!(err.to_string().contains("without a port"), "{err}");
    }

    #[test]
    fn output_table_picks_the_backend() {
        let text = |output: &str| {
            format!(
                "port = 80\n[[message]]\nfrom = \"client\"\ntext = \"hi\"\n\
                 [client]\nip = \"10.0.0.1\"\n{output}"
            )
        };
        let p = TcpProfile::from_toml(&text(""), Path::new(".")).unwrap();
        assert!(p.output.is_empty());
        let p = TcpProfile::from_toml(
            &text("[output]\nbackend = \"af_xdp\"\nqueue = 1\nbatch = 32\n"),
            Path::new("."),
        )
        .unwrap();
        assert_eq!(p.output.backend(), crate::Backend::AfXdp);
        assert_eq!((p.output.queue(), p.output.batch()), (1, 32));
        let e = TcpProfile::from_toml(&text("[output]\nbackend = \"nope\"\n"), Path::new("."));
        assert!(e.unwrap_err().to_string().contains("[output]"));
    }

    #[test]
    fn example_tcp_profile_parses() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/lab-tcp.toml");
        let p = TcpProfile::from_path(path).unwrap();
        let program = p.programs().unwrap().remove(0);
        assert!(program.bytes(TcpRole::Server) > 0);
        assert!(p.client.is_some() && p.server.is_some());

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/lab-tcp-mix.toml"
        );
        let p = TcpProfile::from_path(path).unwrap();
        let programs: Vec<Arc<TcpProgram>> =
            p.programs().unwrap().into_iter().map(Arc::new).collect();
        let cfg = p.config(&programs, &["eth0".into()], Some("eth0")).unwrap();
        let ports: Vec<(u16, u32)> = cfg
            .templates
            .iter()
            .map(|t| (t.listen_port, t.connect_ips))
            .collect();
        assert_eq!(ports, [(80, 4), (8080, 4), (7, 4)]);
        crate::TcpEngine::new(cfg).unwrap();
    }
}
