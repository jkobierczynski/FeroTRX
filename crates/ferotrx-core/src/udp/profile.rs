//! UDP profiles: a stateful UDP run described in a TOML file.

use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use crate::profile::OutputFile;
use crate::SendSettings;

use super::dns::DnsWorkload;
use super::engine::{UdpApp, UdpClientConfig, UdpConfig, UdpOptions, UdpServerConfig, UdpTemplate};
use super::program::{UdpMessage, UdpProgram};
use crate::tcp::profile::{RawHost, RawMessage};
use crate::{
    check_format, parse_connect_addr, parse_duration, parse_model, parse_port_range, Capture,
    Error, Result, TcpHostSpec, TrafficModel,
};

/// A stateful UDP run: what the transactions carry, the emulated client and
/// server hosts, and how many transactions to start how fast.
///
/// ```toml
/// app = "dns"                 # dns, ntp or replay (default: replay with
///                             # `pcap` or [[message]], dns with `queries`)
/// queries = ["www.lab.local A", "lab.local MX", "missing.lab.local A NXDOMAIN"]
/// records = [
///   "www.lab.local 300 A 192.168.20.80",
///   "lab.local MX 10 mail.lab.local",
///   "broken.lab.local SERVFAIL",   # answered with this error
/// ]
/// # pcap = "dns-lookups.pcap"   # with app = "dns": queries and records from a capture
/// rate = 200                  # transactions per second (default 1)
/// model = "poisson"           # optional: how they spread around the rate, as
///                             # for TCP profiles (see TrafficModel); also `shape`
/// transactions = 10000        # in all; 0 = until stopped (default 1)
/// concurrency = 100           # most open at once; 0 = no limit (default)
/// duration = "60s"            # optional
///
/// [client]                    # as in TCP profiles
/// ip = "192.168.10.100/24"
/// gateway = "192.168.10.1"
///
/// [server]
/// ip = "192.168.20.53/24"
/// gateway = "192.168.20.1"
/// # port = 53                 # default: 53 for DNS, 123 for NTP, the capture's
///
/// [udp]                       # optional; the defaults are shown
/// timeout = "1s"              # wait this long for an answer, then ask again
/// retries = 2                 # ask again this often, then the transaction times out
/// session_timeout = "5s"      # the server forgets a quiet session after this
/// arp_timeout = "5s"
/// keep_timing = false         # wait the capture's gaps between datagrams
/// think_time = "0s"           # pause before answering the other end
/// verify = true               # check replayed datagrams byte for byte
/// ```
///
/// A replay takes a UDP session from a capture (`pcap`, `flow`) or written
/// out as `[[message]]` tables (`from`, `text` or `hex`, optional `delay`)
/// with `port`. To mix kinds of transactions, give `[[template]]` tables,
/// each with what it plays and optionally `name`, `weight`, `port`,
/// `connect`, `connect_ips`, its own `rate`, `transactions`, `concurrency`
/// and `think_time`, as for TCP templates.
#[derive(Clone, Debug, PartialEq)]
pub struct UdpProfile {
    pub templates: Vec<UdpTemplateSpec>,
    pub client: Option<TcpHostSpec>,
    pub server: Option<TcpHostSpec>,
    /// Where the client sends, for templates without their own `connect`;
    /// defaults to the server host. Port 0: each template's port.
    pub connect: Option<SocketAddr>,
    pub connect_ips: Option<u32>,
    /// Transactions per second, all templates without their own rate together.
    pub rate: f64,
    /// How transactions spread around `rate`.
    pub model: TrafficModel,
    pub transactions: u64,
    pub concurrency: usize,
    pub source_ports: Range<u16>,
    pub duration: Option<Duration>,
    pub options: UdpOptions,
    /// How the interfaces send and receive (the `[output]` table): libpcap,
    /// AF_XDP or DPDK. The command line's settings win over these.
    pub output: SendSettings,
}

/// One template of a [`UdpProfile`].
#[derive(Clone, Debug, PartialEq)]
pub struct UdpTemplateSpec {
    pub name: Option<String>,
    pub source: UdpSource,
    pub weight: u32,
    pub port: Option<u16>,
    pub connect: Option<SocketAddr>,
    pub connect_ips: Option<u32>,
    pub rate: Option<f64>,
    pub model: TrafficModel,
    pub transactions: Option<u64>,
    pub concurrency: Option<usize>,
    pub think_time: Option<Duration>,
}

impl UdpTemplateSpec {
    pub fn new(source: UdpSource) -> Self {
        Self {
            name: None,
            source,
            weight: 1,
            port: None,
            connect: None,
            connect_ips: None,
            rate: None,
            model: TrafficModel::default(),
            transactions: None,
            concurrency: None,
            think_time: None,
        }
    }

    /// The template's name: the one given, the capture's file name, `dns`,
    /// `ntp`, or `tN` for the `index`th template (from 0).
    pub fn name(&self, index: usize) -> String {
        if let Some(n) = &self.name {
            return n.clone();
        }
        let stem = |p: &Path| {
            p.file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| format!("t{}", index + 1))
        };
        match &self.source {
            UdpSource::Pcap { path, flow } => match flow {
                Some(f) => format!("{}#{}", stem(path), f + 1),
                None => stem(path),
            },
            UdpSource::Program(_) => format!("t{}", index + 1),
            UdpSource::Dns { .. } => "dns".into(),
            UdpSource::Ntp => "ntp".into(),
        }
    }

    /// Loads what the template plays.
    pub fn app(&self) -> Result<UdpApp> {
        let read = |path: &Path| {
            Capture::from_path(path)
                .map_err(|e| Error::Udp(format!("cannot read {}: {e}", path.display())))
        };
        Ok(match &self.source {
            UdpSource::Pcap { path, flow } => {
                UdpApp::Replay(Arc::new(UdpProgram::from_capture(&read(path)?, *flow)?))
            }
            UdpSource::Program(p) => UdpApp::Replay(Arc::new(p.clone())),
            UdpSource::Dns { pcap, extra } => {
                let mut w = match pcap {
                    Some(path) => DnsWorkload::from_capture(&read(path)?)?,
                    None => DnsWorkload {
                        recursion_desired: extra.recursion_desired,
                        ..Default::default()
                    },
                };
                w.queries.extend(extra.queries.iter().cloned());
                w.records.extend(extra.records.iter().cloned());
                w.errors.extend(extra.errors.iter().cloned());
                if pcap.is_some() && !extra.recursion_desired {
                    w.recursion_desired = false;
                }
                UdpApp::Dns(Arc::new(w))
            }
            UdpSource::Ntp => UdpApp::Ntp,
        })
    }
}

/// What a [`UdpTemplateSpec`] plays.
#[derive(Clone, Debug, PartialEq)]
pub enum UdpSource {
    /// A UDP session in a capture, replayed: `flow` is its index (from 0),
    /// or `None` for the first.
    Pcap {
        path: PathBuf,
        flow: Option<usize>,
    },
    /// A session written out in the profile.
    Program(UdpProgram),
    /// DNS: the lookups of a capture, if given, plus the queries, records
    /// and errors of `extra`.
    Dns {
        pcap: Option<PathBuf>,
        extra: DnsWorkload,
    },
    Ntp,
}

impl std::fmt::Display for UdpSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdpSource::Pcap { path, flow: None } => write!(f, "{}", path.display()),
            UdpSource::Pcap {
                path,
                flow: Some(i),
            } => write!(f, "{} session {}", path.display(), i + 1),
            UdpSource::Program(p) => write!(f, "{} datagrams", p.messages.len()),
            UdpSource::Dns { pcap: Some(p), .. } => write!(f, "DNS from {}", p.display()),
            UdpSource::Dns { pcap: None, extra } => write!(f, "{extra}"),
            UdpSource::Ntp => f.write_str("NTP"),
        }
    }
}

impl Default for UdpProfile {
    fn default() -> Self {
        Self {
            templates: vec![UdpTemplateSpec::new(UdpSource::Ntp)],
            client: None,
            server: None,
            connect: None,
            connect_ips: None,
            rate: 1.0,
            model: TrafficModel::default(),
            transactions: 1,
            concurrency: 0,
            source_ports: 1024..65535,
            duration: None,
            options: UdpOptions::default(),
            output: SendSettings::default(),
        }
    }
}

/// What a profile or template plays, as written.
struct RawWhat {
    app: Option<String>,
    pcap: Option<String>,
    flow: Option<usize>,
    port: Option<u16>,
    message: Vec<RawMessage>,
    queries: Option<Vec<String>>,
    records: Option<Vec<String>>,
    recursion: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    format: Option<u32>,
    model: Option<String>,
    #[serde(default)]
    shape: Vec<String>,
    app: Option<String>,
    pcap: Option<String>,
    flow: Option<usize>,
    port: Option<u16>,
    #[serde(default)]
    message: Vec<RawMessage>,
    queries: Option<Vec<String>>,
    records: Option<Vec<String>>,
    recursion: Option<bool>,
    #[serde(default)]
    template: Vec<RawTemplate>,
    rate: Option<f64>,
    transactions: Option<u64>,
    concurrency: Option<usize>,
    source_ports: Option<String>,
    connect: Option<String>,
    connect_ips: Option<u32>,
    duration: Option<String>,
    client: Option<RawHost>,
    server: Option<RawHost>,
    udp: Option<RawOptions>,
    output: Option<OutputFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTemplate {
    name: Option<String>,
    app: Option<String>,
    pcap: Option<String>,
    flow: Option<usize>,
    port: Option<u16>,
    #[serde(default)]
    message: Vec<RawMessage>,
    queries: Option<Vec<String>>,
    records: Option<Vec<String>>,
    recursion: Option<bool>,
    weight: Option<u32>,
    connect: Option<String>,
    connect_ips: Option<u32>,
    rate: Option<f64>,
    model: Option<String>,
    #[serde(default)]
    shape: Vec<String>,
    transactions: Option<u64>,
    concurrency: Option<usize>,
    think_time: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOptions {
    timeout: Option<String>,
    retries: Option<u32>,
    session_timeout: Option<String>,
    arp_timeout: Option<String>,
    keep_timing: Option<bool>,
    think_time: Option<String>,
    verify: Option<bool>,
    seed: Option<u64>,
}

impl RawWhat {
    fn is_empty(&self) -> bool {
        self.app.is_none()
            && self.pcap.is_none()
            && self.flow.is_none()
            && self.port.is_none()
            && self.message.is_empty()
            && self.queries.is_none()
            && self.records.is_none()
            && self.recursion.is_none()
    }

    fn source(self, base_dir: &Path) -> Result<UdpSource> {
        let dns_given =
            self.queries.is_some() || self.records.is_some() || self.recursion.is_some();
        let app = match self.app.as_deref() {
            Some(a) => a.to_ascii_lowercase(),
            None if dns_given => "dns".into(),
            None => "replay".into(),
        };
        let no = |what: &str, app: &str| {
            Error::Profile(format!("`{what}` does not go with app = \"{app}\""))
        };
        match app.as_str() {
            "replay" => {
                if dns_given {
                    return Err(no("queries`/`records", "replay"));
                }
                match (self.pcap, self.message.is_empty()) {
                    (Some(path), true) => Ok(UdpSource::Pcap {
                        path: base_dir.join(path),
                        flow: match self.flow {
                            Some(0) => {
                                return Err(Error::Profile("sessions are numbered from 1".into()))
                            }
                            f => f.map(|f| f - 1),
                        },
                    }),
                    (None, false) => {
                        if self.flow.is_some() {
                            return Err(Error::Profile("`flow` goes with `pcap`".into()));
                        }
                        let port = self.port.ok_or_else(|| {
                            Error::Profile("[[message]] tables need `port`".into())
                        })?;
                        let mut out = Vec::new();
                        for (i, m) in self.message.into_iter().enumerate() {
                            let (from, data, delay) = m
                                .parts()
                                .map_err(|e| Error::Profile(format!("message {}: {e}", i + 1)))?;
                            out.push(UdpMessage::new(from, data).with_delay(delay));
                        }
                        let p = UdpProgram::new(port, out);
                        p.validate()?;
                        Ok(UdpSource::Program(p))
                    }
                    (Some(_), false) => Err(Error::Profile(
                        "give `pcap` or [[message]], not both".into(),
                    )),
                    (None, true) => Err(Error::Profile(
                        "give `app`, `pcap`, [[message]] tables or DNS `queries`".into(),
                    )),
                }
            }
            "dns" => {
                if !self.message.is_empty() {
                    return Err(no("[[message]]", "dns"));
                }
                if self.flow.is_some() {
                    return Err(no("flow", "dns"));
                }
                let mut extra = DnsWorkload::parse(
                    &self.queries.unwrap_or_default(),
                    &self.records.unwrap_or_default(),
                )
                .map_err(|e| Error::Profile(e.to_string()))?;
                extra.recursion_desired = self.recursion.unwrap_or(true);
                Ok(UdpSource::Dns {
                    pcap: self.pcap.map(|p| base_dir.join(p)),
                    extra,
                })
            }
            "ntp" => {
                if dns_given
                    || self.pcap.is_some()
                    || !self.message.is_empty()
                    || self.flow.is_some()
                {
                    return Err(Error::Profile(
                        "app = \"ntp\" takes no pcap, messages or DNS settings".into(),
                    ));
                }
                Ok(UdpSource::Ntp)
            }
            other => Err(Error::Profile(format!(
                "unknown app '{other}' (use replay, dns or ntp)"
            ))),
        }
    }
}

impl UdpProfile {
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
        let top = RawWhat {
            app: raw.app,
            pcap: raw.pcap,
            flow: raw.flow,
            port: raw.port,
            message: raw.message,
            queries: raw.queries,
            records: raw.records,
            recursion: raw.recursion,
        };
        let mut top_port = None;
        let templates = if raw.template.is_empty() {
            top_port = top.port;
            vec![UdpTemplateSpec::new(top.source(base_dir)?)]
        } else {
            if !top.is_empty() {
                return Err(Error::Profile(
                    "give what to play at the top, or [[template]] tables, not both".into(),
                ));
            }
            let mut out = Vec::new();
            for (i, t) in raw.template.into_iter().enumerate() {
                let label = t.name.clone().unwrap_or_else(|| (i + 1).to_string());
                let ctx = |e: Error| match e {
                    Error::Profile(m) => Error::Profile(format!("template {label}: {m}")),
                    e => Error::Profile(format!("template {label}: {e}")),
                };
                let what = RawWhat {
                    app: t.app,
                    pcap: t.pcap,
                    flow: t.flow,
                    port: t.port,
                    message: t.message,
                    queries: t.queries,
                    records: t.records,
                    recursion: t.recursion,
                };
                out.push(UdpTemplateSpec {
                    name: t.name,
                    source: what.source(base_dir).map_err(ctx)?,
                    weight: t.weight.unwrap_or(1),
                    port: t.port,
                    connect: t
                        .connect
                        .map(|c| parse_connect_addr(&c))
                        .transpose()
                        .map_err(ctx)?,
                    connect_ips: t.connect_ips,
                    rate: t.rate,
                    model: parse_model(t.model.as_deref(), &t.shape).map_err(ctx)?,
                    transactions: t.transactions,
                    concurrency: t.concurrency,
                    think_time: t
                        .think_time
                        .map(|d| parse_duration(&d))
                        .transpose()
                        .map_err(ctx)?,
                });
            }
            out
        };
        let mut p = UdpProfile {
            templates,
            model,
            ..Default::default()
        };
        if let (Some(port), [t]) = (top_port, p.templates.as_mut_slice()) {
            t.port = Some(port);
        }
        p.client = raw.client.map(|h| h.spec("client")).transpose()?;
        p.server = raw.server.map(|h| h.spec("server")).transpose()?;
        p.connect = raw.connect.map(|c| parse_connect_addr(&c)).transpose()?;
        p.connect_ips = raw.connect_ips;
        if p.templates.len() > 1 && p.server.as_ref().is_some_and(|s| s.port.is_some()) {
            return Err(Error::Profile(
                "with several templates, give each its `port` instead of [server] port".into(),
            ));
        }
        if let Some(r) = raw.rate {
            p.rate = r;
        }
        if let Some(n) = raw.transactions {
            p.transactions = n;
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
        if let Some(o) = raw.udp {
            let d = |v: Option<String>, dflt: Duration| -> Result<Duration> {
                v.map_or(Ok(dflt), |s| parse_duration(&s))
            };
            let defaults = UdpOptions::default();
            p.options = UdpOptions {
                timeout: d(o.timeout, defaults.timeout)?,
                retries: o.retries.unwrap_or(defaults.retries),
                session_timeout: d(o.session_timeout, defaults.session_timeout)?,
                arp_timeout: d(o.arp_timeout, defaults.arp_timeout)?,
                keep_timing: o.keep_timing.unwrap_or(defaults.keep_timing),
                think_time: d(o.think_time, defaults.think_time)?,
                verify: o.verify.unwrap_or(defaults.verify),
                seed: o.seed.unwrap_or(defaults.seed),
                clock: defaults.clock,
            };
        }
        if p.client.is_none() && p.server.is_none() {
            return Err(Error::Profile(
                "give a [client] table, a [server] table or both".into(),
            ));
        }
        Ok(p)
    }

    /// Loads what the templates play, in order.
    pub fn apps(&self) -> Result<Vec<UdpApp>> {
        self.templates
            .iter()
            .enumerate()
            .map(|(i, t)| {
                t.app()
                    .map_err(|e| Error::Udp(format!("template {}: {e}", t.name(i))))
            })
            .collect()
    }

    /// The interfaces the hosts use, without repeats; port `i` of the engine
    /// is interface `i`. Hosts without an interface use `default`.
    pub fn interfaces(&self, default: Option<&str>) -> Result<Vec<String>> {
        let mut out: Vec<String> = Vec::new();
        for (what, host) in [("client", &self.client), ("server", &self.server)] {
            let Some(h) = host else { continue };
            let name = h
                .iface
                .as_deref()
                .or(default)
                .ok_or_else(|| Error::Udp(format!("the {what} has no interface")))?;
            if !out.iter().any(|n| n == name) {
                out.push(name.to_string());
            }
        }
        Ok(out)
    }

    /// The engine configuration, ports numbered as in `interfaces`; `apps`
    /// as [`apps`](Self::apps) loads them.
    pub fn config(
        &self,
        apps: &[UdpApp],
        interfaces: &[String],
        default: Option<&str>,
    ) -> Result<UdpConfig> {
        if apps.len() != self.templates.len() {
            return Err(Error::Udp(format!(
                "{} apps for {} templates",
                apps.len(),
                self.templates.len()
            )));
        }
        let port = |h: &TcpHostSpec| -> Result<usize> {
            let name = h.iface.as_deref().or(default).unwrap_or_default();
            interfaces
                .iter()
                .position(|n| n == name)
                .ok_or_else(|| Error::Udp(format!("interface {name} is not open")))
        };
        let single = self.templates.len() == 1;
        if !single
            && self.connect.is_some_and(|c| c.port() != 0)
            && self.templates.iter().any(|t| t.connect.is_none())
        {
            return Err(Error::Udp(
                "with several templates, `connect` takes an address without a port \
                 (each template's port is used), or give each template its own `connect`"
                    .into(),
            ));
        }
        let mut templates = Vec::new();
        for (i, (t, app)) in self.templates.iter().zip(apps).enumerate() {
            let listen = t
                .port
                .or(if single {
                    self.server.as_ref().and_then(|s| s.port)
                } else {
                    None
                })
                .unwrap_or(app.default_port());
            let (connect, ips) = match (t.connect, self.connect, &self.server) {
                (Some(c), _, _) | (None, Some(c), _) => {
                    (c, t.connect_ips.or(self.connect_ips).unwrap_or(1))
                }
                (None, None, Some(s)) => (
                    SocketAddr::new(s.ip, 0),
                    t.connect_ips.or(self.connect_ips).unwrap_or(s.ips),
                ),
                (None, None, None) if self.client.is_some() => {
                    return Err(Error::Udp(
                        "a client without a server needs the address to send to".into(),
                    ))
                }
                (None, None, None) => (SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0), 1),
            };
            let connect = if connect.port() == 0 {
                SocketAddr::new(connect.ip(), listen)
            } else {
                connect
            };
            templates.push(UdpTemplate {
                name: t.name(i),
                app: app.clone(),
                connect,
                connect_ips: ips,
                listen_port: listen,
                weight: t.weight,
                rate: t.rate,
                model: t.model.clone(),
                transactions: t.transactions.unwrap_or(0),
                concurrency: t.concurrency.unwrap_or(0),
                think_time: t.think_time,
            });
        }
        let server = match &self.server {
            Some(h) => Some(UdpServerConfig::new(h.endpoint(port(h)?))),
            None => None,
        };
        let client = match &self.client {
            Some(h) => {
                let mut c = UdpClientConfig::new(h.endpoint(port(h)?));
                c.rate = self.rate;
                c.model = self.model.clone();
                c.transactions = self.transactions;
                c.concurrency = self.concurrency;
                c.source_ports = self.source_ports.clone();
                Some(c)
            }
            None => None,
        };
        Ok(UdpConfig {
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
    use crate::{DnsType, Rcode};

    fn examples() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples")
    }

    #[test]
    fn output_table_picks_the_backend() {
        let p = UdpProfile::from_toml(
            "app = \"ntp\"\n[client]\nip = \"10.0.0.1\"\n[output]\nbackend = \"dpdk\"\n\
             dpdk_args = [\"--no-huge\"]\n",
            Path::new("."),
        )
        .unwrap();
        assert_eq!(p.output.backend(), crate::Backend::Dpdk);
        assert_eq!(p.output.dpdk_args(), ["--no-huge".to_string()]);
    }

    #[test]
    fn parses_a_dns_profile() {
        let p = UdpProfile::from_toml(
            r#"
            queries = ["www.lab.local", "lab.local MX", "nope.lab.local A NXDOMAIN"]
            records = ["www.lab.local A 192.168.20.80", "lab.local MX 10 mail.lab.local", "bad.lab.local REFUSED"]
            rate = 200
            transactions = 0
            concurrency = 50
            [client]
            ip = "192.168.10.100/24"
            gateway = "192.168.10.1"
            [server]
            ip = "192.168.20.53/24"
            [udp]
            timeout = "300ms"
            retries = 4
            think_time = "2ms"
            "#,
            &examples(),
        )
        .unwrap();
        assert_eq!(p.templates.len(), 1);
        assert_eq!(p.templates[0].name(0), "dns");
        assert_eq!((p.rate, p.transactions, p.concurrency), (200.0, 0, 50));
        assert_eq!(p.options.timeout, Duration::from_millis(300));
        assert_eq!(p.options.retries, 4);
        let apps = p.apps().unwrap();
        let UdpApp::Dns(w) = &apps[0] else {
            panic!("{apps:?}")
        };
        assert_eq!(w.queries[1].qtype, DnsType::MX);
        assert_eq!(w.errors, vec![("bad.lab.local".into(), Rcode::REFUSED)]);
        let names = p.interfaces(Some("eth0")).unwrap();
        let c = p.config(&apps, &names, Some("eth0")).unwrap();
        assert_eq!(c.templates[0].connect.to_string(), "192.168.20.53:53");
        assert_eq!(c.templates[0].listen_port, 53);
        assert_eq!(c.client.unwrap().rate, 200.0);
    }

    #[test]
    fn parses_templates_of_each_kind() {
        let p = UdpProfile::from_toml(
            r#"
            rate = 100
            [[template]]
            name = "lookups"
            app = "dns"
            pcap = "dns-lookups.pcap"
            weight = 3
            [[template]]
            app = "ntp"
            rate = 5
            transactions = 10
            [[template]]
            name = "echo"
            port = 7
            think_time = "10ms"
            [[template.message]]
            from = "client"
            text = "ping"
            [[template.message]]
            from = "server"
            hex = "706f6e67"
            delay = "5ms"
            [[template]]
            pcap = "dns-lookups.pcap"
            flow = 2
            port = 5353
            [client]
            ip = "10.0.0.1"
            [server]
            ip = "10.0.0.2"
            "#,
            &examples(),
        )
        .unwrap();
        let names: Vec<String> = p
            .templates
            .iter()
            .enumerate()
            .map(|(i, t)| t.name(i))
            .collect();
        assert_eq!(names, ["lookups", "ntp", "echo", "dns-lookups#2"]);
        let apps = p.apps().unwrap();
        let c = p.config(&apps, &["eth0".into()], Some("eth0")).unwrap();
        let ports: Vec<u16> = c.templates.iter().map(|t| t.listen_port).collect();
        assert_eq!(ports, [53, 123, 7, 5353]);
        assert_eq!(c.templates[1].rate, Some(5.0));
        assert_eq!(c.templates[2].think_time, Some(Duration::from_millis(10)));
        let UdpApp::Replay(echo) = &c.templates[2].app else {
            panic!()
        };
        assert_eq!(echo.messages[1].data, b"pong");
        assert_eq!(echo.messages[1].delay, Duration::from_millis(5));
        let UdpApp::Dns(w) = &c.templates[0].app else {
            panic!()
        };
        assert_eq!(w.queries.len(), 8);
    }

    #[test]
    fn rejects_what_does_not_fit() {
        let bad = |text: &str| {
            UdpProfile::from_toml(&format!("{text}\n[client]\nip = \"10.0.0.1\""), &examples())
                .unwrap_err()
                .to_string()
        };
        assert!(bad("app = \"ntp\"\npcap = \"x.pcap\"").contains("ntp"));
        assert!(bad("app = \"dns\"\nflow = 1\npcap = \"x\"").contains("flow"));
        assert!(bad("app = \"bogus\"").contains("unknown app"));
        assert!(bad("").contains("give"));
        assert!(bad("queries = [\"x BADTYPE\"]").contains("BADTYPE"));
        assert!(bad("[[message]]\nfrom = \"client\"\ntext = \"x\"").contains("port"));
        assert!(
            bad("port = 9\n[[message]]\nfrom = \"server\"\ntext = \"x\"")
                .contains("client must send first")
        );
        assert!(bad("app = \"ntp\"\n[udp]\nbogus = 1").contains("bogus"));
    }
}
