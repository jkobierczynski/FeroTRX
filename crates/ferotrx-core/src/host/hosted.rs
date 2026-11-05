//! Host emulation in front of a TCP or UDP engine: the client and server get
//! their addresses first (DHCP, SLAAC, DHCPv6), then the engine starts with
//! them; leases are renewed, queries answered and groups kept while it runs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use super::engine::{
    AddressSource, HostConfig, HostEngine, HostOptions, HostStats, HostStatus, Ipv4Mode, Ipv6Mode,
};
use crate::tcp::{PortEngine, TcpConfig, TcpEndpoint, TcpStats};
use crate::udp::{UdpConfig, UdpStats};
use crate::{Error, Result};

/// How an emulated TCP or UDP end gets its address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Addressing {
    /// The address in the profile (default).
    #[default]
    Static,
    /// IPv4 by DHCP.
    Dhcp,
    /// IPv6 by stateless autoconfiguration.
    Slaac,
    /// IPv6 by DHCPv6 (gateway from router advertisements).
    Dhcpv6,
}

impl Addressing {
    /// `dhcp`, `slaac` or `dhcpv6`, as in a profile's `ip`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "dhcp" | "dhcp4" | "dhcpv4" => Some(Addressing::Dhcp),
            "slaac" => Some(Addressing::Slaac),
            "dhcpv6" | "dhcp6" => Some(Addressing::Dhcpv6),
            _ => None,
        }
    }

    pub fn is_dynamic(self) -> bool {
        self != Addressing::Static
    }

    /// The address a host has until it gets its own: 0.0.0.0 or ::.
    pub fn placeholder(self) -> IpAddr {
        match self {
            Addressing::Dhcp => Ipv4Addr::UNSPECIFIED.into(),
            _ => Ipv6Addr::UNSPECIFIED.into(),
        }
    }
}

impl std::fmt::Display for Addressing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Addressing::Static => "static",
            Addressing::Dhcp => "dhcp",
            Addressing::Slaac => "slaac",
            Addressing::Dhcpv6 => "dhcpv6",
        })
    }
}

/// Host emulation for one end of a TCP or UDP run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Emulation {
    pub addressing: Addressing,
    /// Gratuitous ARP or unsolicited neighbor advertisements once the
    /// address is set (default: on for DHCP, SLAAC and DHCPv6, off for
    /// static addresses).
    pub announce: Option<bool>,
    /// Multicast groups to join, of the host's IP version.
    pub groups: Vec<IpAddr>,
    /// Host name for DHCP.
    pub hostname: Option<String>,
}

impl Emulation {
    /// True when the end needs host emulation at all.
    pub fn is_needed(&self) -> bool {
        self.addressing.is_dynamic() || self.announce == Some(true) || !self.groups.is_empty()
    }

    fn host(&self, ep: &TcpEndpoint, what: &str) -> Result<Option<HostConfig>> {
        let err = |m: String| Err(Error::Host(format!("{what}: {m}")));
        if self.addressing.is_dynamic() && ep.ip_count > 1 {
            return err(format!(
                "{} gives one address; `ips` must be 1",
                self.addressing
            ));
        }
        let v4 = match self.addressing {
            Addressing::Dhcp => true,
            Addressing::Slaac | Addressing::Dhcpv6 => false,
            Addressing::Static => ep.ip.is_ipv4(),
        };
        if let Some(g) = self.groups.iter().find(|g| g.is_ipv4() != v4) {
            return err(format!(
                "group {g} is not of the host's IP version (the host is {})",
                if v4 { "IPv4" } else { "IPv6" }
            ));
        }
        let mut h = HostConfig::new(ep.port, ep.mac);
        h.vlan = ep.vlan;
        h.groups = self.groups.clone();
        h.announce = self.announce.unwrap_or(self.addressing.is_dynamic());
        h.hostname = self.hostname.clone();
        match (self.addressing, ep.ip) {
            (Addressing::Dhcp, _) => h.ipv4 = Some(Ipv4Mode::Dhcp),
            (Addressing::Slaac, _) => h.ipv6 = Some(Ipv6Mode::Slaac),
            (Addressing::Dhcpv6, _) => h.ipv6 = Some(Ipv6Mode::Dhcpv6),
            (Addressing::Static, IpAddr::V4(ip)) => {
                h.ipv4 = Some(Ipv4Mode::Static {
                    ip,
                    prefix: ep.prefix,
                    gateway: match ep.gateway {
                        Some(IpAddr::V4(g)) => Some(g),
                        _ => None,
                    },
                })
            }
            (Addressing::Static, IpAddr::V6(ip)) => {
                h.ipv6 = Some(Ipv6Mode::Static {
                    ip,
                    prefix: ep.prefix,
                    gateway: match ep.gateway {
                        Some(IpAddr::V6(g)) => Some(g),
                        _ => None,
                    },
                })
            }
        }
        Ok(Some(h))
    }
}

/// An engine configuration with a client and a server endpoint, and
/// templates that say where clients connect: [`TcpConfig`], [`UdpConfig`].
pub trait EndpointConfig: Clone + Send + 'static {
    /// The client's and the server's endpoints.
    fn endpoints_mut(&mut self) -> [Option<&mut TcpEndpoint>; 2];
    /// Where each template's clients connect.
    fn connects_mut(&mut self) -> Vec<&mut SocketAddr>;
}

impl EndpointConfig for TcpConfig {
    fn endpoints_mut(&mut self) -> [Option<&mut TcpEndpoint>; 2] {
        [
            self.client.as_mut().map(|c| &mut c.endpoint),
            self.server.as_mut().map(|s| &mut s.endpoint),
        ]
    }
    fn connects_mut(&mut self) -> Vec<&mut SocketAddr> {
        self.templates.iter_mut().map(|t| &mut t.connect).collect()
    }
}

impl EndpointConfig for UdpConfig {
    fn endpoints_mut(&mut self) -> [Option<&mut TcpEndpoint>; 2] {
        [
            self.client.as_mut().map(|c| &mut c.endpoint),
            self.server.as_mut().map(|s| &mut s.endpoint),
        ]
    }
    fn connects_mut(&mut self) -> Vec<&mut SocketAddr> {
        self.templates.iter_mut().map(|t| &mut t.connect).collect()
    }
}

/// The emulated hosts behind a TCP or UDP configuration's client and
/// server, and how their addresses go back into it.
#[derive(Clone, Debug, PartialEq)]
pub struct EndpointHosts {
    hosts: Vec<HostConfig>,
    /// Index in `hosts` of the client's and the server's host.
    index: [Option<usize>; 2],
    /// The server's address before it has one, which templates connect to.
    server_placeholder: Option<IpAddr>,
}

impl EndpointHosts {
    /// The hosts that `config`'s client and server need, from their
    /// emulation settings; `None` when neither needs any.
    pub fn new<C: EndpointConfig>(
        config: &C,
        client: Option<&Emulation>,
        server: Option<&Emulation>,
    ) -> Result<Option<Self>> {
        let mut config = config.clone();
        let mut out = Self {
            hosts: Vec::new(),
            index: [None, None],
            server_placeholder: None,
        };
        let ends: Vec<_> = config
            .endpoints_mut()
            .into_iter()
            .map(|ep| ep.cloned())
            .collect();
        for (i, (ep, emu)) in ends.iter().zip([client, server]).enumerate() {
            let (Some(ep), Some(emu)) = (ep, emu.filter(|e| e.is_needed())) else {
                continue;
            };
            let what = if i == 0 { "client" } else { "server" };
            if let Some(h) = emu.host(ep, what)? {
                out.index[i] = Some(out.hosts.len());
                out.hosts.push(h);
                if i == 1 && emu.addressing.is_dynamic() {
                    out.server_placeholder = Some(ep.ip);
                }
            }
        }
        // With hosts emulated, a static IPv6 end on its own gets a host as
        // well, so that it joins its solicited-node group: a switch or
        // bridge with MLD snooping would otherwise not pass it the
        // neighbor solicitations for its address.
        if !out.hosts.is_empty() {
            for (i, ep) in ends.iter().enumerate() {
                let Some(ep) = ep.as_ref().filter(|ep| ep.ip.is_ipv6()) else {
                    continue;
                };
                if out.index[i].is_some() {
                    continue;
                }
                let what = if i == 0 { "client" } else { "server" };
                if let Some(h) = Emulation::default().host(ep, what)? {
                    out.index[i] = Some(out.hosts.len());
                    out.hosts.push(h);
                }
            }
        }
        if let [Some(c), Some(s)] = out.index {
            let (a, b) = (&out.hosts[c], &out.hosts[s]);
            if a.port == b.port && a.vlan == b.vlan && a.mac == b.mac {
                return Err(Error::Host(
                    "the client and the server have the same MAC address on one port and VLAN; give one a `mac`".into(),
                ));
            }
        }
        Ok((!out.hosts.is_empty()).then_some(out))
    }

    pub fn hosts(&self) -> &[HostConfig] {
        &self.hosts
    }

    /// Puts the hosts' addresses into `config`: the client's and server's
    /// address, prefix and (unless set) gateway, and the server's address
    /// where templates connect to it.
    pub fn apply<C: EndpointConfig>(&self, config: &mut C, statuses: &[HostStatus]) {
        let mut server_ip = None;
        for (i, ep) in config.endpoints_mut().into_iter().enumerate() {
            let (Some(ep), Some(h)) = (ep, self.index[i]) else {
                continue;
            };
            let Some(st) = statuses.get(h) else { continue };
            let a = if self.hosts[h].ipv4.is_some()
                && (ep.ip.is_ipv4() || self.hosts[h].ipv6.is_none())
            {
                st.ipv4.as_ref()
            } else {
                st.ipv6.as_ref()
            };
            let Some(a) = a.filter(|a| a.source != AddressSource::Static) else {
                continue;
            };
            ep.ip = a.ip;
            ep.prefix = a.prefix;
            if ep.gateway.is_none() {
                ep.gateway = a.gateway;
            }
            if i == 1 {
                server_ip = Some(a.ip);
            }
        }
        if let (Some(old), Some(new)) = (self.server_placeholder, server_ip) {
            for c in config.connects_mut() {
                if c.ip() == old {
                    c.set_ip(new);
                }
            }
        }
    }

    /// Fills in documentation addresses (192.0.2.0/24, 2001:db8::/64) for the
    /// addresses not known yet, to check a configuration before the run.
    pub fn apply_example<C: EndpointConfig>(&self, config: &mut C) {
        let statuses: Vec<HostStatus> = self
            .hosts
            .iter()
            .enumerate()
            .map(|(h, cfg)| {
                let n = if self.index[0] == Some(h) { 10 } else { 20 };
                let addr = |ip: IpAddr, source| super::engine::HostAddress {
                    ip,
                    prefix: if ip.is_ipv4() { 24 } else { 64 },
                    gateway: None,
                    source,
                    server: None,
                    dns: Vec::new(),
                    lease: None,
                    renewals: 0,
                };
                HostStatus {
                    port: cfg.port,
                    mac: cfg.mac,
                    vlan: cfg.vlan,
                    state: Default::default(),
                    error: None,
                    ready_after: None,
                    ipv4: matches!(cfg.ipv4, Some(Ipv4Mode::Dhcp))
                        .then(|| addr(Ipv4Addr::new(192, 0, 2, n).into(), AddressSource::Dhcp)),
                    ipv6: matches!(cfg.ipv6, Some(Ipv6Mode::Slaac | Ipv6Mode::Dhcpv6)).then(|| {
                        addr(
                            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, u16::from(n)).into(),
                            AddressSource::Slaac,
                        )
                    }),
                    link_local: None,
                    groups: Vec::new(),
                    dhcp_server: None,
                    dhcpv6_server: None,
                    counters: Default::default(),
                }
            })
            .collect();
        self.apply(config, &statuses);
    }

    /// Builds the run: checks `config` with example addresses (returning
    /// that engine, to describe the run before it starts), and a
    /// [`Hosted`] engine that builds the real one once the hosts have their
    /// addresses.
    pub fn hosted<C, E, B>(
        &self,
        config: C,
        options: HostOptions,
        build: B,
    ) -> Result<(E, Hosted<E>)>
    where
        C: EndpointConfig,
        E: PortEngine,
        E::Stats: HostedStats,
        B: Fn(C) -> Result<E> + Send + 'static,
    {
        let mut example = config.clone();
        self.apply_example(&mut example);
        let checked = build(example)?;
        let hosts = HostEngine::new(self.hosts.clone(), options)?;
        let me = self.clone();
        let engine = Hosted::new(hosts, move |statuses: &[HostStatus]| {
            let mut config = config;
            me.apply(&mut config, statuses);
            build(config)
        });
        Ok((checked, engine))
    }
}

/// Counters of an engine that can carry its hosts' states.
pub trait HostedStats {
    /// Puts the hosts' states and addresses into the counters.
    fn set_hosts(&mut self, hosts: Vec<HostStatus>);
}

impl HostedStats for TcpStats {
    fn set_hosts(&mut self, hosts: Vec<HostStatus>) {
        self.hosts = hosts;
    }
}

impl HostedStats for UdpStats {
    fn set_hosts(&mut self, hosts: Vec<HostStatus>) {
        self.hosts = hosts;
    }
}

impl HostedStats for HostStats {
    fn set_hosts(&mut self, hosts: Vec<HostStatus>) {
        self.hosts = hosts;
    }
}

type Build<E> = Box<dyn FnOnce(&[HostStatus]) -> Result<E> + Send>;

/// A [`HostEngine`] in front of another engine (TCP or UDP): it sets the
/// hosts up first, then builds the engine with their addresses and runs it,
/// keeping the hosts going (renewals, query answers) beside it.
///
/// Frames go to the hosts first; what they do not take goes to the engine.
/// The engine's clock starts when it is built, so its rates and elapsed
/// time do not count the setup. The run's duration does.
pub struct Hosted<E: PortEngine> {
    hosts: HostEngine,
    build: Option<Build<E>>,
    inner: Option<E>,
    /// When the engine was built.
    t0: Duration,
    stats: E::Stats,
    error: Option<String>,
}

impl<E> Hosted<E>
where
    E: PortEngine,
    E::Stats: HostedStats,
{
    /// `build` makes the engine from the hosts' states once all are ready.
    pub fn new<B>(hosts: HostEngine, build: B) -> Self
    where
        B: FnOnce(&[HostStatus]) -> Result<E> + Send + 'static,
    {
        Self {
            hosts,
            build: Some(Box::new(build)),
            inner: None,
            t0: Duration::ZERO,
            stats: E::Stats::default(),
            error: None,
        }
    }

    pub fn hosts(&self) -> &HostEngine {
        &self.hosts
    }

    /// The engine, once the hosts are ready.
    pub fn inner(&self) -> Option<&E> {
        self.inner.as_ref()
    }

    fn refresh(&mut self) {
        self.stats = match &self.inner {
            Some(e) => e.stats().clone(),
            None => E::Stats::default(),
        };
        self.stats.set_hosts(self.hosts.statuses());
    }
}

impl<E> PortEngine for Hosted<E>
where
    E: PortEngine,
    E::Stats: HostedStats,
{
    type Stats = E::Stats;

    fn handle_frame(&mut self, port: usize, frame: &[u8], now: Duration) {
        if !self.hosts.handle_frame(port, frame, now) {
            if let Some(e) = self.inner.as_mut() {
                e.handle_frame(port, frame, now.saturating_sub(self.t0));
            }
        }
    }

    fn poll(&mut self, now: Duration) {
        self.hosts.poll(now);
        if let Some(e) = self.hosts.error() {
            if self.error.is_none() {
                self.error = Some(e.to_string());
                self.refresh();
            }
            return;
        }
        if self.inner.is_none() && self.hosts.all_ready() {
            if let Some(build) = self.build.take() {
                match build(&self.hosts.statuses()) {
                    Ok(e) => {
                        self.inner = Some(e);
                        self.t0 = now;
                    }
                    Err(e) => {
                        self.error = Some(e.to_string());
                        return;
                    }
                }
            }
        }
        if let Some(e) = self.inner.as_mut() {
            e.poll(now.saturating_sub(self.t0));
        }
    }

    fn take_output(&mut self) -> Vec<(usize, Vec<u8>)> {
        let mut out = self.hosts.take_output();
        if let Some(e) = self.inner.as_mut() {
            out.append(&mut e.take_output());
        }
        out
    }

    fn error(&self) -> Option<&str> {
        self.error
            .as_deref()
            .or_else(|| self.inner.as_ref().and_then(|e| e.error()))
    }

    fn is_done(&self) -> bool {
        self.inner.as_ref().is_some_and(|e| e.is_done())
    }

    fn set_elapsed(&mut self, elapsed: Duration, stopped: bool) {
        self.hosts.set_elapsed(elapsed, stopped);
        let t0 = self.t0;
        if let Some(e) = self.inner.as_mut() {
            e.set_elapsed(elapsed.saturating_sub(t0), stopped);
        }
        self.refresh();
    }

    fn finish(&mut self) {
        if let Some(e) = self.inner.as_mut() {
            e.finish();
        }
        self.hosts.finish();
    }

    fn set_rx_dropped(&mut self, frames: u64) {
        if let Some(e) = self.inner.as_mut() {
            e.set_rx_dropped(frames);
        }
        self.refresh();
    }

    fn stats(&self) -> &E::Stats {
        &self.stats
    }

    fn wrap_error(message: String) -> Error {
        E::wrap_error(message)
    }
}

/// The host engine runs on its own too (`ferotrx host`): it ends when every
/// host has failed, or with [`HostEngine::set_until_settled`] once every host
/// is ready or failed.
impl PortEngine for HostEngine {
    type Stats = HostStats;
    fn handle_frame(&mut self, port: usize, frame: &[u8], now: Duration) {
        HostEngine::handle_frame(self, port, frame, now);
    }
    fn poll(&mut self, now: Duration) {
        HostEngine::poll(self, now)
    }
    fn take_output(&mut self) -> Vec<(usize, Vec<u8>)> {
        HostEngine::take_output(self)
    }
    fn error(&self) -> Option<&str> {
        HostEngine::error(self)
    }
    fn is_done(&self) -> bool {
        HostEngine::is_done(self)
    }
    fn set_elapsed(&mut self, elapsed: Duration, stopped: bool) {
        HostEngine::set_elapsed(self, elapsed, stopped)
    }
    fn finish(&mut self) {
        HostEngine::finish(self)
    }
    fn stats(&self) -> &HostStats {
        HostEngine::stats(self)
    }
    fn wrap_error(message: String) -> Error {
        Error::Host(message)
    }
}
