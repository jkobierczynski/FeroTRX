//! TCP profiles: a stateful TCP run described in a TOML file.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use super::engine::{TcpClientConfig, TcpConfig, TcpEndpoint, TcpOptions, TcpServerConfig};
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
#[derive(Clone, Debug, PartialEq)]
pub struct TcpProfile {
    pub source: TcpSource,
    pub client: Option<TcpHostSpec>,
    pub server: Option<TcpHostSpec>,
    /// Where the client connects; defaults to the server host and port.
    pub connect: Option<SocketAddrV4>,
    pub cps: f64,
    pub connections: u64,
    pub concurrency: usize,
    pub source_ports: Range<u16>,
    pub duration: Option<Duration>,
    pub options: TcpOptions,
}

/// What a [`TcpProfile`] plays.
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
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub ips: u32,
    pub gateway: Option<Ipv4Addr>,
    pub vlan: Option<u16>,
    pub mac: Option<MacAddr>,
    pub next_hop_mac: Option<MacAddr>,
    /// The server's listening port.
    pub port: Option<u16>,
}

impl TcpHostSpec {
    /// A host at `ip`, written `a.b.c.d` or `a.b.c.d/prefix` (default /24).
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

    /// The host's MAC address: the one given, or 02:00 followed by its IPv4 address.
    pub fn mac(&self) -> MacAddr {
        self.mac.unwrap_or_else(|| {
            let o = self.ip.octets();
            MacAddr([0x02, 0x00, o[0], o[1], o[2], o[3]])
        })
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

/// Parses `a.b.c.d` or `a.b.c.d/prefix`; the prefix defaults to 24.
pub fn parse_ip_prefix(s: &str) -> Result<(Ipv4Addr, u8)> {
    let bad = || {
        Error::InvalidSpec(format!(
            "invalid IPv4 address '{s}' (use e.g. 192.168.10.100/24)"
        ))
    };
    let (ip, prefix) = match s.trim().split_once('/') {
        Some((ip, p)) => (
            ip,
            p.parse::<u8>().ok().filter(|p| *p <= 32).ok_or_else(bad)?,
        ),
        None => (s.trim(), 24),
    };
    Ok((ip.parse().map_err(|_| bad())?, prefix))
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
            source: TcpSource::Program(TcpProgram::new(80, Vec::new())),
            client: None,
            server: None,
            connect: None,
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
    cps: Option<f64>,
    connections: Option<u64>,
    concurrency: Option<usize>,
    source_ports: Option<String>,
    connect: Option<String>,
    duration: Option<String>,
    client: Option<RawHost>,
    server: Option<RawHost>,
    tcp: Option<RawOptions>,
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
        let source = match (raw.pcap, raw.message.is_empty()) {
            (Some(path), true) => {
                if raw.port.is_some() || raw.closer.is_some() {
                    return Err(Error::Profile(
                        "`port` and `closer` go with [[message]]; with `pcap`, set [server] port"
                            .into(),
                    ));
                }
                TcpSource::Pcap {
                    path: base_dir.join(path),
                    flow: match raw.flow {
                        Some(0) => return Err(Error::Profile("flows are numbered from 1".into())),
                        f => f.map(|f| f - 1),
                    },
                }
            }
            (None, false) => {
                let port = raw.port.ok_or_else(|| {
                    Error::Profile("a profile with [[message]] needs `port`".into())
                })?;
                let mut messages = Vec::new();
                for (i, m) in raw.message.into_iter().enumerate() {
                    let ctx = |e: Error| Error::Profile(format!("message {}: {e}", i + 1));
                    let data = match (m.text, m.hex) {
                        (Some(t), None) => t.into_bytes(),
                        (None, Some(h)) => hex(&h).map_err(ctx)?,
                        _ => return Err(ctx(Error::Profile("give `text` or `hex`".into()))),
                    };
                    messages.push(TcpMessage::new(role(&m.from).map_err(ctx)?, data));
                }
                let mut program = TcpProgram::new(port, messages);
                if let Some(c) = raw.closer {
                    program.closer = role(&c)?;
                }
                TcpSource::Program(program)
            }
            (Some(_), false) => {
                return Err(Error::Profile(
                    "give `pcap` or [[message]], not both".into(),
                ))
            }
            (None, true) => return Err(Error::Profile("give `pcap` or [[message]] tables".into())),
        };
        let mut p = TcpProfile {
            source,
            ..Default::default()
        };
        p.client = raw.client.map(|h| h.spec("client")).transpose()?;
        p.server = raw.server.map(|h| h.spec("server")).transpose()?;
        p.connect = raw
            .connect
            .map(|c| {
                c.parse().map_err(|_| {
                    Error::Profile(format!("invalid connect address '{c}' (use IP:PORT)"))
                })
            })
            .transpose()?;
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

    /// Loads the program the profile plays.
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
    pub fn config(
        &self,
        program: Arc<TcpProgram>,
        interfaces: &[String],
        default: Option<&str>,
    ) -> Result<TcpConfig> {
        let port = |h: &TcpHostSpec| -> Result<usize> {
            let name = h.iface.as_deref().or(default).unwrap_or_default();
            interfaces
                .iter()
                .position(|n| n == name)
                .ok_or_else(|| Error::Tcp(format!("interface {name} is not open")))
        };
        let server = match &self.server {
            Some(h) => Some(TcpServerConfig {
                endpoint: h.endpoint(port(h)?),
                port: h.port.unwrap_or(program.server_port),
            }),
            None => None,
        };
        let client = match &self.client {
            Some(h) => {
                let connect = match (self.connect, &server) {
                    (Some(c), _) => c,
                    (None, Some(s)) => SocketAddrV4::new(s.endpoint.ip, s.port),
                    (None, None) => {
                        return Err(Error::Tcp(
                            "a client without a server needs the address to connect to".into(),
                        ))
                    }
                };
                let mut c = TcpClientConfig::new(h.endpoint(port(h)?), connect);
                c.cps = self.cps;
                c.connections = self.connections;
                c.concurrency = self.concurrency;
                c.source_ports = self.source_ports.clone();
                Some(c)
            }
            None => None,
        };
        Ok(TcpConfig {
            program,
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
            p.source,
            TcpSource::Pcap {
                path: "/lab/web.pcap".into(),
                flow: Some(1)
            }
        );
        let c = p.client.as_ref().unwrap();
        assert_eq!((c.ips, c.vlan, c.prefix), (5, Some(10), 24));
        assert_eq!(c.mac().to_string(), "02:00:c0:a8:0a:64");
        assert_eq!(p.options.rto, Duration::from_millis(100));
        assert!(!p.options.verify);
        assert_eq!(p.interfaces(Some("eth0")).unwrap(), ["eth0", "eth1"]);
        assert!(p.interfaces(None).is_err());

        let program = Arc::new(TcpProgram::new(8080, Vec::new()));
        let cfg = p
            .config(program, &["eth0".into(), "eth1".into()], Some("eth0"))
            .unwrap();
        let client = cfg.client.unwrap();
        assert_eq!(client.connect.to_string(), "192.168.20.50:8080");
        assert_eq!(
            (client.endpoint.port, cfg.server.unwrap().endpoint.port),
            (0, 1)
        );
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
        let prog = p.program().unwrap();
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
                "invalid IPv4",
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
    fn example_tcp_profile_parses() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/lab-tcp.toml");
        let p = TcpProfile::from_path(path).unwrap();
        let program = p.program().unwrap();
        assert!(program.bytes(TcpRole::Server) > 0);
        assert!(p.client.is_some() && p.server.is_some());
    }
}
