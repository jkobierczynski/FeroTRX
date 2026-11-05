//! Host profiles: emulated hosts for `ferotrx host`, from TOML.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use super::engine::{HostConfig, HostOptions, Ipv4Mode, Ipv6Mode, RouterConfig};
use super::server::{DhcpServerConfig, Dhcpv6ServerConfig};
use crate::profile::OutputFile;
use crate::tcp::profile::{parse_groups, parse_ip_prefix};
use crate::{check_format, parse_duration, Error, MacAddr, Result, SendSettings};

/// Emulated hosts, their settings and the run's, from a TOML file:
///
/// ```toml
/// format = 1
/// duration = "60s"            # optional; else until Ctrl-C
///
/// [options]                   # all optional
/// setup_timeout = "30s"
/// rate = 50                   # hosts started per second (default: all at once)
/// igmp_version = 3
/// mld_version = 2
///
/// [[host]]                    # ten DHCP clients that also autoconfigure IPv6
/// count = 10                  # MACs (and static addresses) count up
/// mac = "02:dc:00:00:01:01"
/// ipv4 = "dhcp"               # or "192.168.10.50/24" with `gateway`
/// ipv6 = "slaac"              # or "dhcpv6", or "fd00:10::50/64" with `gateway6`
/// vlan = 10
/// groups = ["239.1.1.1", "ff15::1"]
/// hostname = "lab-{n}"        # {n}: the host's number, from 1
///
/// [[host]]                    # an IPv6 router for another link
/// iface = "eth1"
/// mac = "02:dc:00:00:02:01"
/// [host.router]
/// prefixes = ["fd00:99::/64"]
/// interval = "10s"
///
/// [[host]]                    # a DHCP and DHCPv6 server for a third link
/// iface = "eth2"
/// ipv4 = "10.20.0.1/24"
/// [host.dhcp_server]
/// pool = "10.20.0.100-10.20.0.199"
/// lease = "1h"
/// router = "10.20.0.1"         # default: the host's gateway
/// dns = ["10.20.0.53"]
/// domain = "lab.test"
/// reservations = { "02:00:00:00:00:07" = "10.20.0.7" }
/// [host.dhcpv6_server]
/// pool = "fd00:20::100-fd00:20::1ff"
/// dns = ["fd00:20::53"]
/// ```
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HostProfile {
    pub hosts: Vec<HostSpec>,
    pub options: HostOptions,
    pub duration: Option<Duration>,
    /// How the interfaces send and receive (the `[output]` table).
    pub output: SendSettings,
    /// Impairments of the frames the hosts send (`impair`) and receive
    /// (`impair_rx`).
    pub impair: crate::PortImpair,
}

/// One `[[host]]` table: `count` hosts alike but for their MACs, static
/// addresses and host names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostSpec {
    /// The interface; the command line's `--iface` if left out.
    pub iface: Option<String>,
    pub count: u32,
    /// The first host's settings; `port` is set when the hosts are made.
    pub host: HostConfig,
}

impl HostSpec {
    pub fn new(host: HostConfig) -> Self {
        Self {
            iface: None,
            count: 1,
            host,
        }
    }

    /// The `n`th host (from 0): MAC and static addresses `n` higher, `{n}`
    /// in the host name its number from 1.
    pub fn nth(&self, n: u32) -> HostConfig {
        let mut h = self.host.clone();
        let m = &h.mac.0;
        let low = u64::from_be_bytes([0, 0, m[0], m[1], m[2], m[3], m[4], m[5]]) + u64::from(n);
        let b = low.to_be_bytes();
        h.mac = MacAddr([b[2], b[3], b[4], b[5], b[6], b[7]]);
        if let Some(Ipv4Mode::Static { ip, .. }) = &mut h.ipv4 {
            *ip = Ipv4Addr::from(u32::from(*ip).wrapping_add(n));
        }
        if let Some(Ipv6Mode::Static { ip, .. }) = &mut h.ipv6 {
            *ip = Ipv6Addr::from(u128::from(*ip).wrapping_add(u128::from(n)));
        }
        if let Some(name) = &mut h.hostname {
            *name = name.replace("{n}", &(n + 1).to_string());
        }
        h
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    format: Option<u32>,
    duration: Option<String>,
    options: Option<RawOptions>,
    #[serde(default)]
    host: Vec<RawHost>,
    output: Option<OutputFile>,
    impair: Option<crate::profile::ImpairFile>,
    impair_rx: Option<crate::profile::ImpairFile>,
}

/// The `[options]` of a host profile, also the `[hosts]` table of TCP and
/// UDP profiles.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawOptions {
    setup_timeout: Option<String>,
    retry: Option<String>,
    igmp_version: Option<u8>,
    mld_version: Option<u8>,
    dad: Option<bool>,
    dad_wait: Option<String>,
    release: Option<bool>,
    broadcast: Option<bool>,
    rate: Option<f64>,
    announcements: Option<u32>,
    announce_interval: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawHost {
    iface: Option<String>,
    count: Option<u32>,
    mac: Option<String>,
    vlan: Option<u16>,
    ipv4: Option<String>,
    gateway: Option<String>,
    ipv6: Option<String>,
    gateway6: Option<String>,
    groups: Option<Vec<String>>,
    announce: Option<bool>,
    hostname: Option<String>,
    router: Option<RawRouter>,
    dhcp_server: Option<RawDhcpServer>,
    dhcpv6_server: Option<RawDhcpServer>,
}

/// `[host.dhcp_server]` and `[host.dhcpv6_server]`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDhcpServer {
    pool: String,
    lease: Option<String>,
    router: Option<String>,
    dns: Option<Vec<String>>,
    domain: Option<String>,
    reservations: Option<std::collections::BTreeMap<String, String>>,
    prefix: Option<u8>,
    rapid_commit: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouter {
    prefixes: Vec<String>,
    interval: Option<String>,
    lifetime: Option<String>,
    managed: Option<bool>,
    other: Option<bool>,
}

/// Parses `dhcp` or `ADDRESS/PREFIX` for IPv4.
pub fn parse_ipv4_mode(s: &str, gateway: Option<&str>) -> Result<Ipv4Mode> {
    let gateway = gateway
        .map(|g| {
            g.trim()
                .parse::<Ipv4Addr>()
                .map_err(|_| Error::InvalidSpec(format!("invalid IPv4 gateway '{g}'")))
        })
        .transpose()?;
    match s.trim().to_ascii_lowercase().as_str() {
        "dhcp" | "dhcp4" | "dhcpv4" => {
            if gateway.is_some() {
                return Err(Error::InvalidSpec(
                    "a DHCP host gets its gateway from the server; leave out `gateway`".into(),
                ));
            }
            Ok(Ipv4Mode::Dhcp)
        }
        _ => match parse_ip_prefix(s)? {
            (IpAddr::V4(ip), prefix) => Ok(Ipv4Mode::Static {
                ip,
                prefix,
                gateway,
            }),
            _ => Err(Error::InvalidSpec(format!(
                "ipv4 = '{s}' is not an IPv4 address (use `ipv6` for IPv6)"
            ))),
        },
    }
}

/// Parses `slaac`, `dhcpv6` or `ADDRESS/PREFIX` for IPv6.
pub fn parse_ipv6_mode(s: &str, gateway: Option<&str>) -> Result<Ipv6Mode> {
    let gateway = gateway
        .map(|g| {
            g.trim()
                .parse::<Ipv6Addr>()
                .map_err(|_| Error::InvalidSpec(format!("invalid IPv6 gateway '{g}'")))
        })
        .transpose()?;
    let dynamic = |m: Ipv6Mode| {
        if gateway.is_some() {
            return Err(Error::InvalidSpec(
                "the gateway comes from router advertisements; leave out `gateway6`".into(),
            ));
        }
        Ok(m)
    };
    match s.trim().to_ascii_lowercase().as_str() {
        "slaac" => dynamic(Ipv6Mode::Slaac),
        "dhcpv6" | "dhcp6" => dynamic(Ipv6Mode::Dhcpv6),
        _ => match parse_ip_prefix(s)? {
            (IpAddr::V6(ip), prefix) => Ok(Ipv6Mode::Static {
                ip,
                prefix,
                gateway,
            }),
            _ => Err(Error::InvalidSpec(format!(
                "ipv6 = '{s}' is not an IPv6 address (use `ipv4` for IPv4)"
            ))),
        },
    }
}

/// Parses a DHCP pool, `FIRST-LAST` of one IP version.
pub fn parse_pool(s: &str) -> Result<(IpAddr, IpAddr)> {
    let bad = || {
        Error::InvalidSpec(format!(
            "pool '{s}' is not FIRST-LAST, e.g. 10.0.0.100-10.0.0.199"
        ))
    };
    let (a, b) = s.split_once('-').ok_or_else(bad)?;
    let a: IpAddr = a.trim().parse().map_err(|_| bad())?;
    let b: IpAddr = b.trim().parse().map_err(|_| bad())?;
    if a.is_ipv4() != b.is_ipv4() {
        return Err(Error::InvalidSpec(format!(
            "pool '{s}' mixes IPv4 and IPv6"
        )));
    }
    Ok((a, b))
}

fn v4(s: &str, what: &str) -> Result<Ipv4Addr> {
    s.trim()
        .parse()
        .map_err(|_| Error::InvalidSpec(format!("{what} '{s}' is not an IPv4 address")))
}

fn v6(s: &str, what: &str) -> Result<Ipv6Addr> {
    s.trim()
        .parse()
        .map_err(|_| Error::InvalidSpec(format!("{what} '{s}' is not an IPv6 address")))
}

impl RawDhcpServer {
    fn v4(self) -> Result<DhcpServerConfig> {
        let (IpAddr::V4(a), IpAddr::V4(b)) = parse_pool(&self.pool)? else {
            return Err(Error::InvalidSpec(format!(
                "dhcp_server pool '{}' is not IPv4 (use [host.dhcpv6_server])",
                self.pool
            )));
        };
        if self.rapid_commit.is_some() {
            return Err(Error::InvalidSpec(
                "rapid_commit is a DHCPv6 setting".into(),
            ));
        }
        let mut c = DhcpServerConfig::new(a, b);
        if let Some(l) = self.lease {
            c.lease = parse_duration(&l)?;
        }
        c.router = self.router.map(|r| v4(&r, "router")).transpose()?;
        c.dns = self
            .dns
            .unwrap_or_default()
            .iter()
            .map(|d| v4(d, "dns server"))
            .collect::<Result<_>>()?;
        c.domain = self.domain;
        c.prefix = self.prefix;
        for (mac, ip) in self.reservations.unwrap_or_default() {
            c.reservations.push((mac.parse()?, v4(&ip, "reservation")?));
        }
        Ok(c)
    }

    fn v6(self) -> Result<Dhcpv6ServerConfig> {
        let (IpAddr::V6(a), IpAddr::V6(b)) = parse_pool(&self.pool)? else {
            return Err(Error::InvalidSpec(format!(
                "dhcpv6_server pool '{}' is not IPv6 (use [host.dhcp_server])",
                self.pool
            )));
        };
        if self.router.is_some() {
            return Err(Error::InvalidSpec(
                "DHCPv6 has no router option: clients take the gateway from router advertisements ([host.router])".into(),
            ));
        }
        let mut c = Dhcpv6ServerConfig::new(a, b);
        if let Some(l) = self.lease {
            c.lease = parse_duration(&l)?;
        }
        c.dns = self
            .dns
            .unwrap_or_default()
            .iter()
            .map(|d| v6(d, "dns server"))
            .collect::<Result<_>>()?;
        c.domain = self.domain;
        if let Some(p) = self.prefix {
            c.prefix = p;
        }
        if let Some(r) = self.rapid_commit {
            c.rapid_commit = r;
        }
        for (mac, ip) in self.reservations.unwrap_or_default() {
            c.reservations.push((mac.parse()?, v6(&ip, "reservation")?));
        }
        Ok(c)
    }
}

/// Parses an IPv6 prefix for router advertisements, `fd00:99::/64`.
pub fn parse_prefix6(s: &str) -> Result<(Ipv6Addr, u8)> {
    match s.split_once('/') {
        Some(_) => match parse_ip_prefix(s)? {
            (IpAddr::V6(p), len) => Ok((super::wire::mask6(p, len), len)),
            _ => Err(Error::InvalidSpec(format!("{s} is not an IPv6 prefix"))),
        },
        None => Err(Error::InvalidSpec(format!(
            "give the prefix with its length, e.g. {s}/64"
        ))),
    }
}

impl RawHost {
    fn spec(self, index: usize, next_mac: &mut u64) -> Result<HostSpec> {
        let label = format!("host {}", index + 1);
        let ctx = |e: Error| match e {
            Error::InvalidSpec(m) | Error::Profile(m) | Error::Host(m) => {
                Error::Profile(format!("{label}: {m}"))
            }
            e => Error::Profile(format!("{label}: {e}")),
        };
        let count = self.count.unwrap_or(1);
        if count == 0 {
            return Err(ctx(Error::InvalidSpec("count must be at least 1".into())));
        }
        let mac = match self.mac {
            Some(m) => m.parse::<MacAddr>().map_err(ctx)?,
            None => {
                let b = next_mac.to_be_bytes();
                MacAddr([b[2], b[3], b[4], b[5], b[6], b[7]])
            }
        };
        let m = mac.0;
        *next_mac =
            u64::from_be_bytes([0, 0, m[0], m[1], m[2], m[3], m[4], m[5]]) + u64::from(count);
        let mut host = HostConfig::new(0, mac);
        host.vlan = self.vlan;
        host.ipv4 = match &self.ipv4 {
            Some(s) => Some(parse_ipv4_mode(s, self.gateway.as_deref()).map_err(ctx)?),
            None if self.gateway.is_some() => {
                return Err(ctx(Error::InvalidSpec("`gateway` goes with `ipv4`".into())))
            }
            None => None,
        };
        host.ipv6 = match &self.ipv6 {
            Some(s) => Some(parse_ipv6_mode(s, self.gateway6.as_deref()).map_err(ctx)?),
            None if self.gateway6.is_some() => {
                return Err(ctx(Error::InvalidSpec(
                    "`gateway6` goes with `ipv6`".into(),
                )))
            }
            None => None,
        };
        host.groups = parse_groups(self.groups.as_deref().unwrap_or_default()).map_err(ctx)?;
        host.hostname = self.hostname;
        let dynamic = matches!(host.ipv4, Some(Ipv4Mode::Dhcp))
            || matches!(host.ipv6, Some(Ipv6Mode::Slaac | Ipv6Mode::Dhcpv6));
        host.announce = self.announce.unwrap_or(dynamic);
        if let Some(r) = self.router {
            let mut router = RouterConfig::new(
                r.prefixes
                    .iter()
                    .map(|p| parse_prefix6(p))
                    .collect::<Result<_>>()
                    .map_err(ctx)?,
            );
            if let Some(i) = r.interval {
                router.interval = parse_duration(&i).map_err(ctx)?;
            }
            if let Some(l) = r.lifetime {
                router.lifetime = parse_duration(&l).map_err(ctx)?;
            }
            router.managed = r.managed.unwrap_or(false);
            router.other = r.other.unwrap_or(false);
            host.router = Some(router);
        }
        host.dhcp_server = self
            .dhcp_server
            .map(RawDhcpServer::v4)
            .transpose()
            .map_err(ctx)?;
        host.dhcpv6_server = self
            .dhcpv6_server
            .map(RawDhcpServer::v6)
            .transpose()
            .map_err(ctx)?;
        if count > 1 && (host.dhcp_server.is_some() || host.dhcpv6_server.is_some()) {
            return Err(ctx(Error::InvalidSpec(
                "a DHCP server is one host: leave out `count`".into(),
            )));
        }
        Ok(HostSpec {
            iface: self.iface,
            count,
            host,
        })
    }
}

/// `base` with the settings of an `[options]` (or `[hosts]`) table.
pub(crate) fn host_options(raw: Option<RawOptions>, base: HostOptions) -> Result<HostOptions> {
    let mut options = base;
    let Some(o) = raw else {
        return Ok(options);
    };
    let d = |v: Option<String>, dflt: Duration| -> Result<Duration> {
        v.map_or(Ok(dflt), |s| parse_duration(&s))
    };
    options.setup_timeout = d(o.setup_timeout, options.setup_timeout)?;
    options.retry = d(o.retry, options.retry)?;
    options.dad_wait = d(o.dad_wait, options.dad_wait)?;
    options.announce_interval = d(o.announce_interval, options.announce_interval)?;
    options.igmp_version = o.igmp_version.unwrap_or(options.igmp_version);
    options.mld_version = o.mld_version.unwrap_or(options.mld_version);
    options.dad = o.dad.unwrap_or(options.dad);
    options.release = o.release.unwrap_or(options.release);
    options.broadcast = o.broadcast.unwrap_or(options.broadcast);
    options.start_rate = o.rate.unwrap_or(options.start_rate);
    options.announcements = o.announcements.unwrap_or(options.announcements);
    Ok(options)
}

/// The first MAC of hosts without a `mac`.
const FIRST_MAC: u64 = 0x02dc_0000_0101;

impl HostProfile {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())?;
        Self::from_toml(&text)
    }

    pub fn from_toml(text: &str) -> Result<Self> {
        let raw: RawProfile = toml::from_str(text).map_err(|e| Error::Profile(e.to_string()))?;
        check_format(raw.format)?;
        if raw.host.is_empty() {
            return Err(Error::Profile("give at least one [[host]] table".into()));
        }
        let mut next_mac = FIRST_MAC;
        let hosts = raw
            .host
            .into_iter()
            .enumerate()
            .map(|(i, h)| h.spec(i, &mut next_mac))
            .collect::<Result<Vec<_>>>()?;
        let options = host_options(raw.options, HostOptions::default())?;
        let profile = Self {
            hosts,
            options,
            duration: raw.duration.map(|d| parse_duration(&d)).transpose()?,
            output: raw
                .output
                .map_or(Ok(SendSettings::default()), OutputFile::settings)?,
            impair: crate::PortImpair {
                tx: crate::profile::ImpairFile::into_option(raw.impair, "impair")?,
                rx: crate::profile::ImpairFile::into_option(raw.impair_rx, "impair_rx")?,
            },
        };
        // Catch bad settings now, not when the interfaces are open.
        let ifaces = profile.interfaces(Some("-")).unwrap_or_default();
        crate::HostEngine::new(
            profile.configs(&ifaces, Some("-"))?,
            profile.options.clone(),
        )
        .map_err(|e| Error::Profile(e.to_string()))?;
        Ok(profile)
    }

    /// How many hosts the profile makes.
    pub fn host_count(&self) -> u64 {
        self.hosts.iter().map(|h| u64::from(h.count)).sum()
    }

    /// The interfaces the hosts use, without repeats; port `i` is
    /// interface `i`. Hosts without an interface use `default`.
    pub fn interfaces(&self, default: Option<&str>) -> Result<Vec<String>> {
        let mut out: Vec<String> = Vec::new();
        for (i, h) in self.hosts.iter().enumerate() {
            let name = h.iface.as_deref().or(default).ok_or_else(|| {
                Error::Host(format!(
                    "host {} has no interface: give `iface` or --iface",
                    i + 1
                ))
            })?;
            if !out.iter().any(|n| n == name) {
                out.push(name.to_string());
            }
        }
        Ok(out)
    }

    /// Every host, with its port numbered as in `interfaces`.
    pub fn configs(&self, interfaces: &[String], default: Option<&str>) -> Result<Vec<HostConfig>> {
        let mut out = Vec::new();
        for spec in &self.hosts {
            let name = spec.iface.as_deref().or(default).unwrap_or_default();
            let port = interfaces
                .iter()
                .position(|n| n == name)
                .ok_or_else(|| Error::Host(format!("interface {name} is not open")))?;
            for n in 0..spec.count {
                let mut h = spec.nth(n);
                h.port = port;
                out.push(h);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EndpointHosts, TcpProfile, UdpProfile};
    use std::sync::Arc;

    #[test]
    fn parses_the_example() {
        let p =
            HostProfile::from_toml(include_str!("../../../../examples/lab-hosts.toml")).unwrap();
        assert_eq!(p.host_count(), 52);
        assert_eq!(p.options.start_rate, 20.0);
        let configs = p.configs(&["eth0".into()], Some("eth0")).unwrap();
        assert_eq!(configs.len(), 52);
        assert_eq!(configs[49].mac, MacAddr([2, 0xdc, 0, 0, 1, 0x32]));
        assert_eq!(configs[49].hostname.as_deref(), Some("lab-50"));
        assert_eq!(configs[0].ipv4, Some(Ipv4Mode::Dhcp));
        assert_eq!(configs[0].ipv6, Some(Ipv6Mode::Slaac));
        assert!(
            configs[0].announce,
            "dynamic addresses are announced by default"
        );
        assert_eq!(configs[0].groups.len(), 2);
        assert_eq!(
            configs[50].ipv4,
            Some(Ipv4Mode::Static {
                ip: Ipv4Addr::new(192, 168, 10, 50),
                prefix: 24,
                gateway: Some(Ipv4Addr::new(192, 168, 10, 1)),
            })
        );
        let r = configs[51].router.as_ref().unwrap();
        assert_eq!(r.prefixes, vec![("fd00:20::".parse().unwrap(), 64)]);
        assert_eq!(r.lifetime, Duration::from_secs(1800));
    }

    #[test]
    fn parses_the_dhcp_server_example() {
        let p = HostProfile::from_toml(include_str!("../../../../examples/lab-dhcp-server.toml"))
            .unwrap();
        assert_eq!(p.host_count(), 4);
        let c = p.configs(&["eth0".into()], Some("eth0")).unwrap();
        let s = c[0].dhcp_server.as_ref().unwrap();
        assert_eq!(
            s.pool,
            (Ipv4Addr::new(10, 88, 0, 100), Ipv4Addr::new(10, 88, 0, 199))
        );
        assert_eq!(s.lease, Duration::from_secs(600));
        assert_eq!(s.router, Some(Ipv4Addr::new(10, 88, 0, 1)));
        assert_eq!(s.domain.as_deref(), Some("lab.test"));
        assert_eq!(
            s.reservations,
            vec![(
                MacAddr([2, 0xdc, 0, 0, 0x0e, 7]),
                Ipv4Addr::new(10, 88, 0, 7)
            )]
        );
        let s6 = c[0].dhcpv6_server.as_ref().unwrap();
        assert_eq!(s6.pool.0, "fd00:88::100".parse::<Ipv6Addr>().unwrap());
        assert!(s6.rapid_commit);
        assert!(c[0].router.as_ref().unwrap().managed);
        assert_eq!(c[3].hostname.as_deref(), Some("client-3"));
    }

    #[test]
    fn rejects_bad_dhcp_servers() {
        for (text, want) in [
            (
                "[[host]]\nipv4 = \"dhcp\"\n[host.dhcp_server]\npool = \"10.0.0.10-10.0.0.20\"",
                "static IPv4",
            ),
            (
                "[[host]]\nipv4 = \"10.0.0.1/24\"\n[host.dhcp_server]\npool = \"10.0.0.10\"",
                "FIRST-LAST",
            ),
            (
                "[[host]]\nipv4 = \"10.0.0.1/24\"\n[host.dhcp_server]\npool = \"fd00::1-fd00::9\"",
                "not IPv4",
            ),
            (
                "[[host]]\nipv4 = \"10.0.0.1/24\"\n[host.dhcp_server]\npool = \"10.0.1.10-10.0.1.20\"",
                "subnet",
            ),
            (
                "[[host]]\ncount = 2\nipv4 = \"10.0.0.1/24\"\n[host.dhcp_server]\npool = \"10.0.0.10-10.0.0.20\"",
                "count",
            ),
            (
                "[[host]]\n[host.dhcpv6_server]\npool = \"fd00::10-fd00:1::20\"",
                "more than one",
            ),
            (
                "[[host]]\n[host.dhcpv6_server]\npool = \"fd00::10-fd00::20\"\nrouter = \"fd00::1\"",
                "router advertisements",
            ),
        ] {
            let e = HostProfile::from_toml(text).unwrap_err().to_string();
            assert!(e.contains(want), "{text}: {e}");
        }
        // A DHCPv6 server alone needs no address of its own.
        HostProfile::from_toml("[[host]]\n[host.dhcpv6_server]\npool = \"fd00::10-fd00::20\"")
            .unwrap();
    }

    #[test]
    fn counts_up_static_addresses_and_macs() {
        let p = HostProfile::from_toml(
            "[[host]]\ncount = 3\nipv4 = \"10.0.0.254/24\"\nipv6 = \"fd00::ff/64\"\n[[host]]\nipv4 = \"dhcp\"",
        )
        .unwrap();
        let c = p.configs(&["x".into()], Some("x")).unwrap();
        assert_eq!(c[0].mac, MacAddr([2, 0xdc, 0, 0, 1, 1]));
        assert_eq!(c[2].mac, MacAddr([2, 0xdc, 0, 0, 1, 3]));
        // The next table without a MAC goes on from there.
        assert_eq!(c[3].mac, MacAddr([2, 0xdc, 0, 0, 1, 4]));
        assert!(
            matches!(c[2].ipv4, Some(Ipv4Mode::Static { ip, .. }) if ip == Ipv4Addr::new(10, 0, 1, 0))
        );
        assert!(
            matches!(c[2].ipv6, Some(Ipv6Mode::Static { ip, .. }) if ip == "fd00::101".parse::<Ipv6Addr>().unwrap())
        );
        assert!(!c[0].announce);
    }

    #[test]
    fn rejects_bad_hosts() {
        for (text, want) in [
            (
                "[[host]]\nipv4 = \"dhcp\"\ngateway = \"10.0.0.1\"",
                "gateway",
            ),
            ("[[host]]\nipv4 = \"fd00::1\"", "not an IPv4"),
            (
                "[[host]]\nipv6 = \"slaac\"\ngroups = [\"239.1.1.1\"]",
                "IGMP",
            ),
            (
                "[[host]]\nipv4 = \"dhcp\"\ngroups = [\"10.1.1.1\"]",
                "multicast",
            ),
            ("[[host]]\n[host.router]\nprefixes = [\"fd00::\"]", "length"),
            ("[[host]]\ncount = 0\nipv4 = \"dhcp\"", "count"),
            ("[[host]]\nipv4 = \"dhcp\"\nbogus = 1", "unknown field"),
            (
                "[options]\nigmp_version = 4\n[[host]]\nipv4 = \"dhcp\"",
                "IGMP version",
            ),
            ("format = 1", "[[host]]"),
        ] {
            let e = HostProfile::from_toml(text).unwrap_err().to_string();
            assert!(e.contains(want), "{text}: {e}");
        }
    }

    #[test]
    fn tcp_and_udp_profiles_with_dynamic_hosts() {
        let p = TcpProfile::from_path(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/lab-tcp-dhcp.toml"
        ))
        .unwrap();
        let c = p.client.as_ref().unwrap();
        assert!(c.is_dynamic());
        assert_eq!(c.address_text(), "dhcp");
        assert_eq!(c.emulation.hostname.as_deref(), Some("ferotrx-client"));
        assert_eq!(p.host_options.setup_timeout, Duration::from_secs(20));
        assert!(!p.host_options.answer && p.host_options.fail_fast);
        let programs: Vec<_> = p.programs().unwrap().into_iter().map(Arc::new).collect();
        let config = p.config(&programs, &["eth0".into()], Some("eth0")).unwrap();
        let plan = p.endpoint_hosts(&config).unwrap().unwrap();
        assert_eq!(plan.hosts().len(), 1);
        assert_eq!(plan.hosts()[0].vlan, Some(10));
        assert_eq!(plan.hosts()[0].hostname.as_deref(), Some("ferotrx-client"));

        // A DHCP server gets a MAC of its own; clients connect to it.
        let p = UdpProfile::from_toml(
            "app = \"dns\"\nqueries = [\"a.lab AAAA\"]\nrecords = [\"a.lab 60 AAAA fd00::1\"]\n[client]\nip = \"slaac\"\n[server]\nip = \"dhcpv6\"\n",
            Path::new("."),
        )
        .unwrap();
        assert_eq!(
            p.client.as_ref().unwrap().mac(),
            MacAddr([2, 0xdc, 0, 0, 0, 1])
        );
        assert_eq!(
            p.server.as_ref().unwrap().mac(),
            MacAddr([2, 0xdc, 0, 0, 0, 2])
        );
        let apps = p.apps().unwrap();
        let config = p.config(&apps, &["eth0".into()], Some("eth0")).unwrap();
        let plan = p.endpoint_hosts(&config).unwrap().unwrap();
        assert_eq!(plan.hosts().len(), 2);
        let mut example = config.clone();
        plan.apply_example(&mut example);
        assert_eq!(
            example.templates[0].connect.ip(),
            "2001:db8::14".parse::<IpAddr>().unwrap()
        );
        crate::UdpEngine::new(example).unwrap();

        // One address only, and groups of the host's version.
        for text in [
            "pcap = \"x.pcap\"\n[client]\nip = \"dhcp\"\nips = 4\n[server]\nip = \"10.0.0.2\"",
            "pcap = \"x.pcap\"\n[client]\nip = \"dhcp\"\ngroups = [\"ff15::1\"]\n[server]\nip = \"10.0.0.2\"",
        ] {
            let p = TcpProfile::from_toml(text, Path::new(".")).unwrap();
            let program = Arc::new(crate::TcpProgram::new(80, Vec::new()));
            let config = p.config(&[program], &["eth0".into()], Some("eth0")).unwrap();
            assert!(EndpointHosts::new(&config, p.client.as_ref().map(|c| &c.emulation), None).is_err(), "{text}");
        }
    }
}
