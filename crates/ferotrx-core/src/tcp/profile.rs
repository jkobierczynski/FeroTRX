//! TCP profiles: a stateful TCP run described in a TOML file.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use super::engine::{
    TcpClientConfig, TcpConfig, TcpEndpoint, TcpOptions, TcpServerConfig, TcpTemplate,
};
use super::program::{TcpMessage, TcpProgram, TcpRole};
use crate::{parse_duration, Capture, Error, MacAddr, Result};

/// A stateful TCP run: what to play, the emulated client and server hosts,
/// and how many connections to open how fast.
///
/// ```toml
/// pcap = "http.pcap"          # the session to replay, relative to this file
/// flow = 1                    # which TCP connection in it (default: the first with data)
/// cps = 50                    # new connections per second (default 1)
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
/// [tcp]                       # optional
/// mss = 1460
/// rto = "250ms"
/// verify = true
/// ```
///
/// Instead of `pcap`, a session can be written out as `[[message]]` tables,
/// each with `from = "client"` or `"server"` and `text` (with `\r\n` escapes)
/// or `hex`, plus `port` for the server port and optionally `closer`.
///
/// To mix several kinds of connections, give `[[template]]` tables instead of
/// `pcap` or `[[message]]`, like TRex ASTF templates. `cps`, `connections` and
/// `concurrency` are for all templates together; each new connection gets a
/// template by `weight`. The server tells templates apart by port, so each
/// needs its own.
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
    pub connections: u64,
    pub concurrency: usize,
    pub source_ports: Range<u16>,
    pub duration: Option<Duration>,
    pub options: TcpOptions,
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
}

impl TcpHostSpec {
    /// A host at `ip`, written `a.b.c.d` or `a.b.c.d/prefix` (default /24),
    /// or an IPv6 address with an optional prefix (default /64).
    pub fn new(ip: &str) -> Result<Self> {
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
        })
    }

    /// The host's MAC address: the one given, or 02:00 followed by its IPv4
    /// address, or by the last four bytes of its IPv6 address.
    pub fn mac(&self) -> MacAddr {
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

    fn endpoint(&self, port: usize) -> TcpEndpoint {
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
            connections: 1,
            concurrency: 0,
            source_ports: 1024..65535,
            duration: None,
            options: TcpOptions::default(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
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
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMessage {
    from: String,
    text: Option<String>,
    hex: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHost {
    iface: Option<String>,
    ip: String,
    ips: Option<u32>,
    gateway: Option<String>,
    vlan: Option<u16>,
    mac: Option<String>,
    next_hop_mac: Option<String>,
    port: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOptions {
    mss: Option<u16>,
    rto: Option<String>,
    max_retries: Option<u32>,
    time_wait: Option<String>,
    idle_timeout: Option<String>,
    arp_timeout: Option<String>,
    verify: Option<bool>,
    seed: Option<u64>,
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
    if digits.len() % 2 != 0 {
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
                let ctx = |e: Error| Error::Profile(format!("message {}: {e}", i + 1));
                let data = match (m.text, m.hex) {
                    (Some(t), None) => t.into_bytes(),
                    (None, Some(h)) => hex(&h).map_err(ctx)?,
                    _ => return Err(ctx(Error::Profile("give `text` or `hex`".into()))),
                };
                out.push(TcpMessage::new(role(&m.from).map_err(ctx)?, data));
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
    fn spec(self, what: &str) -> Result<TcpHostSpec> {
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
        Ok(h)
    }
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
                });
            }
            out
        };
        let mut p = TcpProfile {
            templates,
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
        if let Some(o) = raw.tcp {
            let d = |v: Option<String>, dflt: Duration| -> Result<Duration> {
                v.map_or(Ok(dflt), |s| parse_duration(&s))
            };
            let defaults = TcpOptions::default();
            p.options = TcpOptions {
                mss: o.mss.unwrap_or(defaults.mss),
                rto: d(o.rto, defaults.rto)?,
                max_retries: o.max_retries.unwrap_or(defaults.max_retries),
                time_wait: d(o.time_wait, defaults.time_wait)?,
                idle_timeout: d(o.idle_timeout, defaults.idle_timeout)?,
                arp_timeout: d(o.arp_timeout, defaults.arp_timeout)?,
                verify: o.verify.unwrap_or(defaults.verify),
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
