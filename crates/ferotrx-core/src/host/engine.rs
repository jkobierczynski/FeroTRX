//! The host emulation engine: addresses by DHCP, SLAAC or DHCPv6,
//! announcements, multicast memberships and router advertisements.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use super::server::{
    self as srv, DhcpServerConfig, DhcpServerStatus, Dhcpv6ServerConfig, Server4, Server6,
};
use super::wire::{self as hw, Dhcp4Out, Dhcp6Out};
use crate::net::{ETHERTYPE_IPV4, ETHERTYPE_IPV6, IPPROTO_ICMPV6, IPPROTO_UDP};
use crate::tcp::wire::{self, Path, NDP_ADVERT, NDP_SOLICIT};
use crate::{Error, MacAddr, Result};

/// How a host gets its IPv4 address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ipv4Mode {
    /// A fixed address, prefix length and optional gateway.
    Static {
        ip: Ipv4Addr,
        prefix: u8,
        gateway: Option<Ipv4Addr>,
    },
    /// From a DHCP server (RFC 2131): address, subnet, router and DNS
    /// servers, renewed at T1 and rebound at T2 while the run lasts.
    Dhcp,
}

/// How a host gets its IPv6 address. The host always has a link-local
/// address (fe80:: and its EUI-64) besides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ipv6Mode {
    /// A fixed address, prefix length and optional gateway.
    Static {
        ip: Ipv6Addr,
        prefix: u8,
        gateway: Option<Ipv6Addr>,
    },
    /// Stateless autoconfiguration (RFC 4862): a router solicitation, the
    /// first /64 prefix of a router advertisement marked for
    /// autoconfiguration, plus the host's EUI-64; the router that advertised
    /// it is the gateway.
    Slaac,
    /// From a DHCPv6 server (RFC 8415, one address in an IA_NA); the
    /// gateway and on-link prefix come from router advertisements.
    Dhcpv6,
}

/// Makes a host an IPv6 router for its link: it sends router
/// advertisements with these prefixes, and answers router solicitations.
/// Other hosts (or devices under test) take addresses from them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterConfig {
    /// Prefixes to advertise, on-link and for autoconfiguration (use /64).
    pub prefixes: Vec<(Ipv6Addr, u8)>,
    /// Time between unsolicited advertisements (default 10 s).
    pub interval: Duration,
    /// Router lifetime: how long hosts may use it as their default router;
    /// zero advertises the prefixes without being a default router
    /// (default 30 min).
    pub lifetime: Duration,
    /// The M flag: addresses are also available by DHCPv6.
    pub managed: bool,
    /// The O flag: other settings are available by DHCPv6.
    pub other: bool,
}

impl RouterConfig {
    pub fn new(prefixes: Vec<(Ipv6Addr, u8)>) -> Self {
        Self {
            prefixes,
            interval: Duration::from_secs(10),
            lifetime: Duration::from_secs(1800),
            managed: false,
            other: false,
        }
    }
}

/// One emulated host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostConfig {
    /// Index of the port the host is on.
    pub port: usize,
    pub mac: MacAddr,
    pub vlan: Option<u16>,
    pub ipv4: Option<Ipv4Mode>,
    pub ipv6: Option<Ipv6Mode>,
    /// Multicast groups to join, IPv4 (IGMP) or IPv6 (MLD). IPv4 groups need
    /// an IPv4 address.
    pub groups: Vec<IpAddr>,
    /// Announce the addresses once they are set up: gratuitous ARP for
    /// IPv4, unsolicited neighbor advertisements for IPv6.
    pub announce: bool,
    /// Host name for DHCP (option 12).
    pub hostname: Option<String>,
    /// Send router advertisements; see [`RouterConfig`].
    pub router: Option<RouterConfig>,
    /// Lease IPv4 addresses as a DHCP server; needs a static `ipv4`.
    pub dhcp_server: Option<DhcpServerConfig>,
    /// Lease IPv6 addresses as a DHCPv6 server.
    pub dhcpv6_server: Option<Dhcpv6ServerConfig>,
}

impl HostConfig {
    /// A host on `port` at `mac` with no addresses yet.
    pub fn new(port: usize, mac: MacAddr) -> Self {
        Self {
            port,
            mac,
            vlan: None,
            ipv4: None,
            ipv6: None,
            groups: Vec::new(),
            announce: false,
            hostname: None,
            router: None,
            dhcp_server: None,
            dhcpv6_server: None,
        }
    }

    pub fn with_ipv4(mut self, mode: Ipv4Mode) -> Self {
        self.ipv4 = Some(mode);
        self
    }

    pub fn with_ipv6(mut self, mode: Ipv6Mode) -> Self {
        self.ipv6 = Some(mode);
        self
    }

    pub fn with_vlan(mut self, vlan: u16) -> Self {
        self.vlan = Some(vlan);
        self
    }

    pub fn with_groups(mut self, groups: Vec<IpAddr>) -> Self {
        self.groups = groups;
        self
    }

    pub fn with_announce(mut self, announce: bool) -> Self {
        self.announce = announce;
        self
    }

    pub fn with_router(mut self, router: RouterConfig) -> Self {
        self.router = Some(router);
        self
    }

    pub fn with_dhcp_server(mut self, server: DhcpServerConfig) -> Self {
        self.dhcp_server = Some(server);
        self
    }

    pub fn with_dhcpv6_server(mut self, server: Dhcpv6ServerConfig) -> Self {
        self.dhcpv6_server = Some(server);
        self
    }

    /// True if the host serves DHCP or DHCPv6, or advertises as a router.
    pub fn serves(&self) -> bool {
        self.router.is_some() || self.dhcp_server.is_some() || self.dhcpv6_server.is_some()
    }

    fn validate(&self) -> Result<()> {
        let what = format!("host {}", self.mac);
        let err = |m: String| Err(Error::Host(format!("{what}: {m}")));
        if self.mac.0[0] & 1 != 0 || self.mac.0 == [0; 6] {
            return err("the MAC address must be a unicast address".into());
        }
        if matches!(self.vlan, Some(v) if v == 0 || v > 4094) {
            return err("VLAN must be 1-4094".into());
        }
        if self.ipv4.is_none() && self.ipv6.is_none() && !self.serves() && self.groups.is_empty() {
            return err("give it an IPv4 or IPv6 address (static, dhcp, slaac or dhcpv6), groups to join, router advertisements or a DHCPv6 server".into());
        }
        if let Some(s) = &self.dhcp_server {
            let own = match &self.ipv4 {
                Some(Ipv4Mode::Static { ip, prefix, .. }) => Some((*ip, *prefix)),
                _ => None,
            };
            if let Err(Error::Host(m)) = srv::validate4(s, own) {
                return err(m);
            }
        }
        if let Some(s) = &self.dhcpv6_server {
            if let Err(Error::Host(m)) = srv::validate6(s) {
                return err(m);
            }
        }
        match &self.ipv4 {
            Some(Ipv4Mode::Static {
                ip,
                prefix,
                gateway,
            }) => {
                if *prefix > 32 {
                    return err(format!("prefix /{prefix} is longer than 32"));
                }
                if ip.is_multicast() || ip.is_unspecified() || ip.is_broadcast() {
                    return err(format!("{ip} is not a unicast address"));
                }
                if gateway.is_some_and(|g| g == *ip) {
                    return err("the gateway is the host's own address".into());
                }
            }
            Some(Ipv4Mode::Dhcp) | None => {}
        }
        if let Some(Ipv6Mode::Static { ip, prefix, .. }) = &self.ipv6 {
            if *prefix > 128 {
                return err(format!("prefix /{prefix} is longer than 128"));
            }
            if ip.is_multicast() || ip.is_unspecified() {
                return err(format!("{ip} is not a unicast address"));
            }
        }
        for g in &self.groups {
            if !g.is_multicast() {
                return err(format!("{g} is not a multicast group"));
            }
            if g.is_ipv4() && self.ipv4.is_none() {
                return err(format!(
                    "joining {g} (IGMP) needs an IPv4 address: static or dhcp"
                ));
            }
        }
        if let Some(r) = &self.router {
            if r.prefixes.is_empty() {
                return err("router advertisements need at least one prefix".into());
            }
            if let Some((p, l)) = r.prefixes.iter().find(|(_, l)| *l > 128) {
                return err(format!("prefix {p}/{l} is longer than 128"));
            }
            if r.interval < Duration::from_millis(100) {
                return err("the advertisement interval must be at least 100ms".into());
            }
            if r.lifetime > Duration::from_secs(9000) {
                return err("the router lifetime is at most 9000s (RFC 4861)".into());
            }
        }
        Ok(())
    }
}

/// Settings shared by all hosts of a [`HostEngine`].
#[derive(Clone, Debug, PartialEq)]
pub struct HostOptions {
    /// How long a host may take to get its addresses (default 30 s).
    pub setup_timeout: Duration,
    /// First wait before a DHCP, DHCPv6 or router solicitation message is
    /// sent again; doubles up to 4 s (default 1 s).
    pub retry: Duration,
    /// IGMP version for reports (1-3, default 3). A host answers a query of
    /// an older version in that version from then on.
    pub igmp_version: u8,
    /// MLD version for reports (1-2, default 2), with the same fallback.
    pub mld_version: u8,
    /// Check IPv6 addresses for duplicates before using them (RFC 4862).
    pub dad: bool,
    /// How long to wait for an answer to the duplicate check (default 1 s).
    pub dad_wait: Duration,
    /// Release DHCP and DHCPv6 leases and leave groups at the end.
    pub release: bool,
    /// Set the broadcast flag in DHCP requests (for servers or relays that
    /// cannot send to a client without an address).
    pub broadcast: bool,
    /// Answer ARP, neighbor solicitations and pings for the hosts'
    /// addresses. Off when the hosts are the ends of a TCP or UDP run, whose
    /// engine answers those itself.
    pub answer: bool,
    /// Stop with an error when a host does not get its addresses in time or
    /// loses them; else the host is marked failed (and a lost lease is
    /// asked for again) and the others go on.
    pub fail_fast: bool,
    /// Hosts that start per second (0: all at once), so a DHCP server is not
    /// asked by thousands at the same moment.
    pub start_rate: f64,
    /// Announcements of each address (gratuitous ARPs or unsolicited
    /// neighbor advertisements) when `announce` is on (default 2).
    pub announcements: u32,
    /// Time between announcements (default 1 s).
    pub announce_interval: Duration,
}

impl Default for HostOptions {
    fn default() -> Self {
        Self {
            setup_timeout: Duration::from_secs(30),
            retry: Duration::from_secs(1),
            igmp_version: 3,
            mld_version: 2,
            dad: true,
            dad_wait: Duration::from_secs(1),
            release: true,
            broadcast: false,
            answer: true,
            fail_fast: false,
            start_rate: 0.0,
            announcements: 2,
            announce_interval: Duration::from_secs(1),
        }
    }
}

impl HostOptions {
    /// Options for hosts that are the ends of a TCP or UDP run: the run's
    /// engine answers ARP and pings, and a host without its address stops
    /// the run.
    pub fn for_endpoints() -> Self {
        Self {
            answer: false,
            fail_fast: true,
            ..Self::default()
        }
    }

    fn validate(&self) -> Result<()> {
        if !(1..=3).contains(&self.igmp_version) {
            return Err(Error::Host("IGMP version must be 1, 2 or 3".into()));
        }
        if !(1..=2).contains(&self.mld_version) {
            return Err(Error::Host("MLD version must be 1 or 2".into()));
        }
        if self.retry.is_zero() || self.setup_timeout.is_zero() {
            return Err(Error::Host(
                "the retry time and setup timeout must be above zero".into(),
            ));
        }
        if !self.start_rate.is_finite() || self.start_rate < 0.0 {
            return Err(Error::Host("the start rate must be 0 or more".into()));
        }
        Ok(())
    }
}

/// Where an address came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressSource {
    Static,
    Dhcp,
    Slaac,
    Dhcpv6,
}

impl std::fmt::Display for AddressSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AddressSource::Static => "static",
            AddressSource::Dhcp => "dhcp",
            AddressSource::Slaac => "slaac",
            AddressSource::Dhcpv6 => "dhcpv6",
        })
    }
}

/// A host's address of one IP version, once it has one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostAddress {
    pub ip: IpAddr,
    pub prefix: u8,
    pub gateway: Option<IpAddr>,
    pub source: AddressSource,
    /// The DHCP server (its address for DHCPv4; for DHCPv6 the router or
    /// server the reply came from).
    pub server: Option<IpAddr>,
    /// DNS servers the DHCP server gave.
    pub dns: Vec<IpAddr>,
    /// The lease time (valid lifetime for DHCPv6 and SLAAC), if limited.
    pub lease: Option<Duration>,
    /// Times the lease was renewed (or rebound).
    pub renewals: u64,
}

/// Where a host is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HostState {
    /// Getting its addresses.
    #[default]
    Starting,
    /// Has all its addresses.
    Ready,
    /// Did not get an address in time, or lost one; see `error`.
    Failed,
}

impl std::fmt::Display for HostState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            HostState::Starting => "starting",
            HostState::Ready => "ready",
            HostState::Failed => "failed",
        })
    }
}

/// A multicast group a host joined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupStatus {
    pub group: IpAddr,
    /// Membership reports sent (unsolicited and answers to queries).
    pub reports: u64,
    /// Frames to the group received, and their bytes.
    pub rx_packets: u64,
    pub rx_bytes: u64,
}

/// Messages a host sent and received.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostCounters {
    /// DHCP and DHCPv6 messages sent (discover, solicit, request, renew,
    /// rebind, release).
    pub dhcp_sent: u64,
    /// DHCP and DHCPv6 messages received for the host (offer, advertise,
    /// ack, reply), naks included.
    pub dhcp_received: u64,
    pub dhcp_naks: u64,
    pub rs_sent: u64,
    pub ra_received: u64,
    pub ra_sent: u64,
    /// Duplicate address detection probes sent.
    pub dad_probes: u64,
    /// Gratuitous ARPs and unsolicited neighbor advertisements sent.
    pub announcements: u64,
    /// IGMP and MLD queries that asked about the host's groups.
    pub queries: u64,
    /// ARP requests and neighbor solicitations answered.
    pub resolutions_answered: u64,
    pub pings_answered: u64,
}

/// One host's state, addresses and counters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostStatus {
    pub port: usize,
    pub mac: MacAddr,
    pub vlan: Option<u16>,
    pub state: HostState,
    /// Why the host failed.
    pub error: Option<String>,
    /// How long the host took to get its addresses.
    pub ready_after: Option<Duration>,
    pub ipv4: Option<HostAddress>,
    pub ipv6: Option<HostAddress>,
    /// The host's link-local address, when it uses IPv6.
    pub link_local: Option<Ipv6Addr>,
    pub groups: Vec<GroupStatus>,
    pub counters: HostCounters,
    /// The leases and counters of its DHCP server role.
    pub dhcp_server: Option<DhcpServerStatus>,
    /// The leases and counters of its DHCPv6 server role.
    pub dhcpv6_server: Option<DhcpServerStatus>,
}

/// Counters of a [`HostEngine`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostStats {
    pub hosts: Vec<HostStatus>,
    /// Frames the host emulation sent, and bytes.
    pub tx_packets: u64,
    pub tx_bytes: u64,
    /// Frames the host emulation took (for its hosts), and bytes.
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub elapsed: Duration,
    pub stopped: bool,
}

impl HostStats {
    pub fn ready(&self) -> usize {
        self.hosts
            .iter()
            .filter(|h| h.state == HostState::Ready)
            .count()
    }

    pub fn failed(&self) -> usize {
        self.hosts
            .iter()
            .filter(|h| h.state == HostState::Failed)
            .count()
    }
}

/// Longest wait between retransmissions while getting an address.
const MAX_RETRY: Duration = Duration::from_secs(4);
/// Unsolicited membership reports sent on a join (the robustness variable).
const ROBUSTNESS: u8 = 2;
/// Time between unsolicited membership reports.
const REPORT_INTERVAL: Duration = Duration::from_secs(1);
/// Requests in the requesting state before going back to discovering.
const MAX_REQUESTS: u32 = 4;
/// Router solicitations before a DHCPv6 host stops waiting for a router.
const MAX_RS_WAIT: u32 = 3;
/// Shortest time between two advertisements of an emulated router.
const MIN_RA_GAP: Duration = Duration::from_secs(1);
const NEVER: Duration = Duration::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum D4Phase {
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
}

#[derive(Debug)]
struct Dhcp4 {
    phase: D4Phase,
    xid: u32,
    began: Duration,
    next_tx: Duration,
    interval: Duration,
    tries: u32,
    offer: Option<(Ipv4Addr, Ipv4Addr)>,
    server: Ipv4Addr,
    server_mac: MacAddr,
    ip: Ipv4Addr,
    bound_at: Duration,
    t1: Duration,
    t2: Duration,
    lease: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum D6Phase {
    Soliciting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
}

#[derive(Debug)]
struct Dhcp6 {
    phase: D6Phase,
    xid: u32,
    began: Duration,
    next_tx: Duration,
    interval: Duration,
    tries: u32,
    server_id: Vec<u8>,
    addr: Option<Ipv6Addr>,
    bound_at: Duration,
    t1: Duration,
    t2: Duration,
    valid: Duration,
}

#[derive(Debug, Default)]
struct V6 {
    rs_next: Option<Duration>,
    rs_interval: Duration,
    rs_count: u32,
    ra_seen: bool,
    router: Option<Ipv6Addr>,
    /// On-link prefixes from router advertisements.
    on_link: Vec<(Ipv6Addr, u8)>,
    slaac_valid: Option<Duration>,
    /// The address being checked for duplicates, its prefix, and when the check ends.
    tentative: Option<(Ipv6Addr, u8, Duration)>,
    address: Option<(Ipv6Addr, u8)>,
    d6: Option<Dhcp6>,
}

#[derive(Debug)]
struct Group {
    addr: IpAddr,
    /// Solicited-node groups the host joins for its own addresses: reported
    /// over MLD, not shown in the status.
    auto: bool,
    join_left: u8,
    next_report: Option<Duration>,
    status: usize,
}

#[derive(Debug, Default)]
struct Announce {
    left: u32,
    next: Duration,
}

struct Emu {
    cfg: HostConfig,
    status: HostStatus,
    start_at: Duration,
    started: bool,
    rng: u64,
    ll: Ipv6Addr,
    uses_v6: bool,
    v4_ready: bool,
    v6_ready: bool,
    d4: Option<Dhcp4>,
    v6: V6,
    announce4: Announce,
    announce6: Announce,
    groups: Vec<Group>,
    igmp_version: u8,
    mld_version: u8,
    ra_next: Duration,
    ra_last: Option<Duration>,
    srv4: Option<Server4>,
    srv6: Option<Server6>,
}

impl Emu {
    fn rand(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    /// A random time below `max`.
    fn rand_below(&mut self, max: Duration) -> Duration {
        let ms = max.as_millis().max(1) as u64;
        Duration::from_millis(self.rand() % ms)
    }

    fn xid(&mut self) -> u32 {
        (self.rand() >> 16) as u32
    }

    fn ready(&self) -> bool {
        (self.cfg.ipv4.is_none() || self.v4_ready) && (self.cfg.ipv6.is_none() || self.v6_ready)
    }

    fn ip4(&self) -> Option<Ipv4Addr> {
        match self.status.ipv4.as_ref()?.ip {
            IpAddr::V4(a) => Some(a),
            IpAddr::V6(_) => None,
        }
    }

    fn ip6(&self) -> Option<Ipv6Addr> {
        self.v6.address.map(|(a, _)| a)
    }

    /// True if `ip` is one of the host's addresses the engine answers for:
    /// the link-local one always, the others when `all`.
    fn answers_for(&self, ip: IpAddr, all: bool) -> bool {
        match ip {
            IpAddr::V6(a) if self.uses_v6 && a == self.ll => true,
            _ if !all => false,
            IpAddr::V4(a) => self.v4_ready && self.ip4() == Some(a),
            IpAddr::V6(a) => self.ip6() == Some(a),
        }
    }

    fn join(&mut self, addr: IpAddr, auto: bool, now: Duration) {
        if self.groups.iter().any(|g| g.addr == addr) {
            return;
        }
        let status = if auto {
            usize::MAX
        } else {
            self.status.groups.push(GroupStatus {
                group: addr,
                reports: 0,
                rx_packets: 0,
                rx_bytes: 0,
            });
            self.status.groups.len() - 1
        };
        self.groups.push(Group {
            addr,
            auto,
            join_left: ROBUSTNESS,
            next_report: Some(now),
            status,
        });
    }
}

/// Emulated hosts that get their addresses (DHCP, SLAAC, DHCPv6 or
/// static), announce them, join multicast groups and answer queries for
/// them, and optionally act as IPv6 routers.
///
/// Sans-IO like the TCP and UDP engines: feed it frames with
/// [`handle_frame`](Self::handle_frame), call [`poll`](Self::poll) often and
/// send what [`take_output`](Self::take_output) returns. It runs on its own
/// ([`run_engine`](crate::run_engine), `ferotrx host`) or in front of a TCP
/// or UDP engine, as [`Hosted`](super::Hosted).
pub struct HostEngine {
    hosts: Vec<Emu>,
    options: HostOptions,
    out: Vec<(usize, Vec<u8>)>,
    stats: HostStats,
    error: Option<String>,
    wake: Duration,
    finished: bool,
    until_settled: bool,
    /// The latest time seen, for lease times in statuses.
    now: Duration,
    /// Hand frames between the engine's own hosts (a server role and its
    /// clients on one port): the ports do not deliver what they send.
    loopback: bool,
    /// Frames of `out` already handed to the engine's own hosts.
    looped: usize,
}

impl HostEngine {
    pub fn new(hosts: Vec<HostConfig>, options: HostOptions) -> Result<Self> {
        options.validate()?;
        if hosts.is_empty() {
            return Err(Error::Host("no hosts to emulate".into()));
        }
        for (i, h) in hosts.iter().enumerate() {
            h.validate()?;
            if hosts[..i]
                .iter()
                .any(|o| o.port == h.port && o.vlan == h.vlan && o.mac == h.mac)
            {
                return Err(Error::Host(format!(
                    "two hosts with MAC {} on the same port and VLAN",
                    h.mac
                )));
            }
        }
        let gap = if options.start_rate > 0.0 {
            Duration::from_secs_f64(1.0 / options.start_rate)
        } else {
            Duration::ZERO
        };
        let emus = hosts
            .into_iter()
            .enumerate()
            .map(|(i, cfg)| {
                let m = cfg.mac.0;
                let seed = u64::from_be_bytes([0x5a, 0xa5, m[0], m[1], m[2], m[3], m[4], m[5]])
                    ^ (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    | 1;
                let uses_v6 = cfg.ipv6.is_some()
                    || cfg.router.is_some()
                    || cfg.dhcpv6_server.is_some()
                    || cfg.groups.iter().any(|g| g.is_ipv6());
                let ll = hw::link_local(cfg.mac);
                let srv4 = match (&cfg.dhcp_server, &cfg.ipv4) {
                    (
                        Some(s),
                        Some(Ipv4Mode::Static {
                            ip,
                            prefix,
                            gateway,
                        }),
                    ) => Some(Server4::new(s.clone(), *ip, *prefix, *gateway)),
                    _ => None,
                };
                let srv6 = cfg.dhcpv6_server.as_ref().map(|s| {
                    let own = match &cfg.ipv6 {
                        Some(Ipv6Mode::Static { ip, .. }) => Some(*ip),
                        _ => None,
                    };
                    Server6::new(s.clone(), cfg.mac, own)
                });
                Emu {
                    status: HostStatus {
                        port: cfg.port,
                        mac: cfg.mac,
                        vlan: cfg.vlan,
                        state: HostState::Starting,
                        error: None,
                        ready_after: None,
                        ipv4: None,
                        ipv6: None,
                        link_local: uses_v6.then_some(ll),
                        groups: Vec::new(),
                        counters: HostCounters::default(),
                        dhcp_server: None,
                        dhcpv6_server: None,
                    },
                    start_at: gap.saturating_mul(i as u32),
                    started: false,
                    rng: seed,
                    ll,
                    uses_v6,
                    v4_ready: false,
                    v6_ready: false,
                    d4: None,
                    v6: V6::default(),
                    announce4: Announce::default(),
                    announce6: Announce::default(),
                    groups: Vec::new(),
                    igmp_version: options.igmp_version,
                    mld_version: options.mld_version,
                    ra_next: NEVER,
                    ra_last: None,
                    srv4,
                    srv6,
                    cfg,
                }
            })
            .collect::<Vec<Emu>>();
        // A server role with other hosts on its port and VLAN.
        let loopback = emus.iter().any(|s| {
            s.cfg.serves()
                && emus.iter().any(|o| {
                    o.cfg.mac != s.cfg.mac && o.cfg.port == s.cfg.port && o.cfg.vlan == s.cfg.vlan
                })
        });
        Ok(Self {
            hosts: emus,
            options,
            out: Vec::new(),
            stats: HostStats::default(),
            error: None,
            wake: Duration::ZERO,
            finished: false,
            until_settled: false,
            now: Duration::ZERO,
            loopback,
            looped: 0,
        })
    }

    pub fn options(&self) -> &HostOptions {
        &self.options
    }

    /// The hosts' configurations, in order.
    pub fn configs(&self) -> impl Iterator<Item = &HostConfig> {
        self.hosts.iter().map(|h| &h.cfg)
    }

    /// The MAC addresses of the hosts on `port`, for ports that filter by
    /// MAC (AF_XDP).
    pub fn port_macs(&self, port: usize) -> Vec<MacAddr> {
        let mut macs = Vec::new();
        for h in self.hosts.iter().filter(|h| h.cfg.port == port) {
            if !macs.contains(&h.cfg.mac) {
                macs.push(h.cfg.mac);
            }
        }
        macs
    }

    /// The counters, with each host's state and addresses. The host list
    /// is brought up to date by [`set_elapsed`](Self::set_elapsed).
    pub fn stats(&self) -> &HostStats {
        &self.stats
    }

    /// Each host's state and addresses, as of now.
    pub fn statuses(&self) -> Vec<HostStatus> {
        self.hosts
            .iter()
            .map(|h| {
                let mut s = h.status.clone();
                s.dhcp_server = h.srv4.as_ref().map(|v| v.status(self.now));
                s.dhcpv6_server = h.srv6.as_ref().map(|v| v.status(self.now));
                s
            })
            .collect()
    }

    /// The status of host `i`.
    pub fn status(&self, i: usize) -> Option<&HostStatus> {
        self.hosts.get(i).map(|h| &h.status)
    }

    /// True when every host has its addresses (or failed, unless
    /// `fail_fast`).
    pub fn all_settled(&self) -> bool {
        self.hosts
            .iter()
            .all(|h| h.status.state != HostState::Starting)
    }

    /// True when every host has its addresses.
    pub fn all_ready(&self) -> bool {
        self.hosts
            .iter()
            .all(|h| h.status.state == HostState::Ready)
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Makes a run of the hosts alone end once every host is ready (or
    /// failed), instead of when it is stopped.
    pub fn set_until_settled(&mut self, yes: bool) {
        self.until_settled = yes;
    }

    /// True when every host failed, or with
    /// [`set_until_settled`](Self::set_until_settled), when all are settled.
    pub fn is_done(&self) -> bool {
        self.hosts
            .iter()
            .all(|h| h.status.state == HostState::Failed)
            || self.until_settled && self.all_settled()
    }

    pub fn take_output(&mut self) -> Vec<(usize, Vec<u8>)> {
        for (_, f) in &self.out {
            self.stats.tx_packets += 1;
            self.stats.tx_bytes += f.len() as u64;
        }
        self.looped = 0;
        std::mem::take(&mut self.out)
    }

    pub fn set_elapsed(&mut self, elapsed: Duration, stopped: bool) {
        self.stats.elapsed = elapsed;
        self.stats.stopped = stopped;
        self.stats.hosts = self.statuses();
    }

    fn fail(&mut self, h: usize, message: String) {
        let host = &mut self.hosts[h];
        let message = format!("host {}: {message}", host.cfg.mac);
        host.status.state = HostState::Failed;
        host.status.error = Some(message.clone());
        if self.options.fail_fast && self.error.is_none() {
            self.error = Some(message);
        }
    }

    /// Takes a frame for the hosts; returns true if it was theirs (DHCP,
    /// router discovery, IGMP/MLD, a duplicate check, a group's traffic, or
    /// something answered), false if another engine should see it.
    pub fn handle_frame(&mut self, port: usize, frame: &[u8], now: Duration) -> bool {
        self.now = self.now.max(now);
        let taken = self.take_frame(port, frame, now);
        self.loop_back(now);
        taken
    }

    /// Hands the frames the hosts sent to the engine's other hosts on the
    /// same port, when one of them serves (see `loopback`).
    fn loop_back(&mut self, now: Duration) {
        if !self.loopback {
            return;
        }
        while self.looped < self.out.len() {
            let i = self.looped;
            self.looped += 1;
            let (port, frame) = (self.out[i].0, std::mem::take(&mut self.out[i].1));
            if let Some(link) = wire::parse_link(&frame) {
                let local = link.dst.0[0] & 1 != 0
                    || self.hosts.iter().any(|h| {
                        h.started
                            && h.cfg.port == port
                            && h.cfg.vlan == link.vlan
                            && h.cfg.mac == link.dst
                    });
                if local {
                    self.take_frame(port, &frame, now);
                }
            }
            self.out[i].1 = frame;
        }
    }

    fn take_frame(&mut self, port: usize, frame: &[u8], now: Duration) -> bool {
        let Some(link) = wire::parse_link(frame) else {
            return false;
        };
        let payload = &frame[link.payload..];
        let taken = match link.ethertype {
            wire::ETHERTYPE_ARP => self.on_arp(port, &link, payload),
            ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => self.on_ip(port, &link, payload, now),
            _ => false,
        };
        if taken {
            self.stats.rx_packets += 1;
            self.stats.rx_bytes += frame.len() as u64;
        }
        taken
    }

    /// The started hosts on the frame's port and VLAN, but its sender.
    fn on_link(&self, port: usize, link: &wire::Link) -> impl Iterator<Item = usize> + '_ {
        let vlan = link.vlan;
        let link = *link;
        self.hosts
            .iter()
            .enumerate()
            .filter(move |(_, h)| {
                h.cfg.port == port && h.cfg.vlan == vlan && h.started && h.cfg.mac != link.src
            })
            .map(|(i, _)| i)
    }

    fn on_arp(&mut self, port: usize, link: &wire::Link, payload: &[u8]) -> bool {
        if !self.options.answer {
            return false;
        }
        let Some(arp) = wire::parse_arp(payload) else {
            return false;
        };
        if arp.op != 1 {
            return false;
        }
        let targets: Vec<usize> = self
            .on_link(port, link)
            .filter(|&h| self.hosts[h].answers_for(arp.target_ip.into(), true))
            .collect();
        for &h in &targets {
            let host = &mut self.hosts[h];
            host.status.counters.resolutions_answered += 1;
            self.out.push((
                port,
                wire::arp_frame(
                    arp.sender_mac,
                    host.cfg.vlan,
                    2,
                    host.cfg.mac,
                    arp.target_ip,
                    arp.sender_mac,
                    arp.sender_ip,
                ),
            ));
        }
        !targets.is_empty()
    }

    fn on_ip(&mut self, port: usize, link: &wire::Link, payload: &[u8], now: Duration) -> bool {
        let Some(ip) = wire::parse_ip(payload, true) else {
            return false;
        };
        if (link.ethertype == ETHERTYPE_IPV4) != ip.src.is_ipv4() {
            return false;
        }
        let mut taken = match (ip.dst, ip.proto) {
            (IpAddr::V4(_), hw::IPPROTO_IGMP) => self.on_igmp(port, link, &ip, now),
            (IpAddr::V4(_), IPPROTO_UDP) => self.on_udp4(port, link, &ip, now),
            (IpAddr::V6(_), IPPROTO_ICMPV6) => self.on_icmp6(port, link, &ip, now),
            (IpAddr::V6(_), IPPROTO_UDP) => self.on_udp6(port, link, &ip, now),
            (IpAddr::V4(_), 1) => self.on_ping(port, link, &ip),
            _ => false,
        };
        if ip.dst.is_multicast() {
            let len = (link.payload + payload.len()) as u64;
            let members: Vec<usize> = self.on_link(port, link).collect();
            for h in members {
                let host = &mut self.hosts[h];
                if let Some(g) = host.groups.iter().find(|g| g.addr == ip.dst && !g.auto) {
                    let s = &mut host.status.groups[g.status];
                    s.rx_packets += 1;
                    s.rx_bytes += len;
                    taken = true;
                }
            }
        }
        taken
    }

    fn on_ping(&mut self, port: usize, link: &wire::Link, ip: &wire::Ip) -> bool {
        let all = self.options.answer;
        let Some(h) = self
            .on_link(port, link)
            .find(|&h| self.hosts[h].cfg.mac == link.dst && self.hosts[h].answers_for(ip.dst, all))
        else {
            return false;
        };
        let host = &mut self.hosts[h];
        let path = Path {
            src_mac: host.cfg.mac,
            dst_mac: link.src,
            vlan: host.cfg.vlan,
            src: ip.dst,
            dst: ip.src,
        };
        match wire::icmp_echo_reply(&path, ip.payload, 0) {
            Some(f) => {
                host.status.counters.pings_answered += 1;
                self.out.push((port, f));
                true
            }
            None => false,
        }
    }

    // --- DHCPv4 -----------------------------------------------------------

    fn on_udp4(&mut self, port: usize, link: &wire::Link, ip: &wire::Ip, now: Duration) -> bool {
        // Not verified: a server's checksum may be left to an offload that
        // never happens (veth).
        let Some(udp) = wire::parse_udp(ip, false) else {
            return false;
        };
        if udp.dport == hw::DHCP_SERVER_PORT {
            return self.on_dhcp4_server(port, link, ip, udp.data, now);
        }
        if udp.sport != hw::DHCP_SERVER_PORT || udp.dport != hw::DHCP_CLIENT_PORT {
            return false;
        }
        let Some(m) = hw::parse_dhcp4(udp.data) else {
            return false;
        };
        let Some(h) = self.on_link(port, link).find(|&h| {
            let host = &self.hosts[h];
            host.cfg.mac.0 == m.chaddr && host.d4.as_ref().is_some_and(|d| d.xid == m.xid)
        }) else {
            return false;
        };
        self.hosts[h].status.counters.dhcp_received += 1;
        self.on_dhcp4(h, link.src, &m, now);
        true
    }

    /// A client (or relay) message to the hosts' DHCP servers.
    fn on_dhcp4_server(
        &mut self,
        port: usize,
        link: &wire::Link,
        ip: &wire::Ip,
        data: &[u8],
        now: Duration,
    ) -> bool {
        let Some(m) = srv::parse_dhcp4_request(data) else {
            return false;
        };
        let servers: Vec<usize> = self
            .on_link(port, link)
            .filter(|&h| {
                let host = &self.hosts[h];
                host.v4_ready
                    && host.srv4.as_ref().is_some_and(|s| {
                        (link.dst == wire::BROADCAST || link.dst == host.cfg.mac)
                            && (ip.dst == IpAddr::V4(Ipv4Addr::BROADCAST)
                                || ip.dst == IpAddr::V4(s.ip()))
                    })
            })
            .collect();
        for &h in &servers {
            let host = &mut self.hosts[h];
            let (mac, vlan) = (host.cfg.mac, host.cfg.vlan);
            if let Some(f) = host
                .srv4
                .as_mut()
                .and_then(|s| s.handle(mac, vlan, link.src, &m, now))
            {
                self.out.push((port, f));
            }
        }
        !servers.is_empty()
    }

    fn send_dhcp4(&mut self, h: usize, kind: u8, now: Duration) {
        let broadcast = self.options.broadcast;
        let host = &mut self.hosts[h];
        let Some(d) = host.d4.as_ref() else {
            return;
        };
        let secs = now
            .saturating_sub(d.began)
            .as_secs()
            .min(u64::from(u16::MAX)) as u16;
        let (ciaddr, requested, server, to) = match (kind, d.phase) {
            (hw::DHCPRELEASE, _) => (d.ip, None, Some(d.server), Some((d.server, d.server_mac))),
            (_, D4Phase::Selecting) => (Ipv4Addr::UNSPECIFIED, None, None, None),
            (_, D4Phase::Requesting) => {
                let (ip, server) = d
                    .offer
                    .unwrap_or((Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED));
                (Ipv4Addr::UNSPECIFIED, Some(ip), Some(server), None)
            }
            (_, D4Phase::Renewing) => (d.ip, None, None, Some((d.server, d.server_mac))),
            (_, D4Phase::Rebinding | D4Phase::Bound) => (d.ip, None, None, None),
        };
        let m = Dhcp4Out {
            kind,
            xid: d.xid,
            secs,
            mac: host.cfg.mac,
            ciaddr,
            requested,
            server,
            hostname: host.cfg.hostname.as_deref(),
            broadcast: broadcast && to.is_none(),
        };
        let f = hw::dhcp4_frame(host.cfg.mac, host.cfg.vlan, to, &m);
        host.status.counters.dhcp_sent += 1;
        self.out.push((host.cfg.port, f));
    }

    fn dhcp4_restart(&mut self, h: usize, now: Duration, delay: Duration) {
        let retry = self.options.retry;
        let host = &mut self.hosts[h];
        let xid = host.xid();
        host.d4 = Some(Dhcp4 {
            phase: D4Phase::Selecting,
            xid,
            began: now,
            next_tx: now + delay,
            interval: retry,
            tries: 0,
            offer: None,
            server: Ipv4Addr::UNSPECIFIED,
            server_mac: MacAddr([0; 6]),
            ip: Ipv4Addr::UNSPECIFIED,
            bound_at: now,
            t1: NEVER,
            t2: NEVER,
            lease: NEVER,
        });
    }

    fn on_dhcp4(&mut self, h: usize, from_mac: MacAddr, m: &hw::Dhcp4In, now: Duration) {
        let retry = self.options.retry;
        let fail_fast = self.options.fail_fast;
        let Some(phase) = self.hosts[h].d4.as_ref().map(|d| d.phase) else {
            return;
        };
        match (phase, m.kind) {
            (D4Phase::Selecting, hw::DHCPOFFER) => {
                let Some(server) = m.server else { return };
                if m.yiaddr.is_unspecified() {
                    return;
                }
                let d = self.hosts[h].d4.as_mut().expect("dhcp");
                d.offer = Some((m.yiaddr, server));
                d.phase = D4Phase::Requesting;
                d.interval = retry;
                d.tries = 1;
                d.next_tx = now + retry;
                self.send_dhcp4(h, hw::DHCPREQUEST, now);
            }
            (D4Phase::Requesting | D4Phase::Renewing | D4Phase::Rebinding, hw::DHCPACK) => {
                if m.yiaddr.is_unspecified() {
                    return;
                }
                let host = &mut self.hosts[h];
                let d = host.d4.as_mut().expect("dhcp");
                if phase != D4Phase::Requesting && m.yiaddr != d.ip {
                    let msg = format!(
                        "the DHCP server moved the host from {} to {} on renewal",
                        d.ip, m.yiaddr
                    );
                    if fail_fast {
                        self.fail(h, msg);
                        return;
                    }
                }
                let lease = m.lease.map_or(NEVER, |s| {
                    if s == u32::MAX {
                        NEVER
                    } else {
                        Duration::from_secs(u64::from(s))
                    }
                });
                let part = |t: Option<u32>, num: u32, den: u32| match t {
                    Some(s) => Duration::from_secs(u64::from(s)),
                    None if lease == NEVER => NEVER,
                    None => lease * num / den,
                };
                d.phase = D4Phase::Bound;
                d.ip = m.yiaddr;
                d.server = m.server.or(d.offer.map(|o| o.1)).unwrap_or(d.server);
                d.server_mac = from_mac;
                d.bound_at = now;
                d.lease = lease;
                d.t1 = part(m.t1, 1, 2).min(lease);
                d.t2 = part(m.t2, 7, 8).min(lease).max(d.t1);
                let renewed = phase != D4Phase::Requesting;
                let addr = HostAddress {
                    ip: m.yiaddr.into(),
                    prefix: m.mask.and_then(hw::mask_len).unwrap_or(24),
                    gateway: m.router.map(IpAddr::V4),
                    source: AddressSource::Dhcp,
                    server: Some(d.server.into()),
                    dns: m.dns.iter().map(|a| IpAddr::V4(*a)).collect(),
                    lease: (lease != NEVER).then_some(lease),
                    renewals: host.status.ipv4.as_ref().map_or(0, |a| a.renewals)
                        + u64::from(renewed),
                };
                host.status.ipv4 = Some(addr);
                if !host.v4_ready {
                    host.v4_ready = true;
                    self.on_v4_ready(h, now);
                }
            }
            (D4Phase::Requesting | D4Phase::Renewing | D4Phase::Rebinding, hw::DHCPNAK) => {
                self.hosts[h].status.counters.dhcp_naks += 1;
                if phase == D4Phase::Requesting {
                    self.dhcp4_restart(h, now, retry);
                } else {
                    self.lost_v4(h, now, "the DHCP server refused to renew the lease (NAK)");
                }
            }
            _ => {}
        }
    }

    fn lost_v4(&mut self, h: usize, now: Duration, why: &str) {
        if self.options.fail_fast {
            self.fail(h, why.to_string());
            return;
        }
        let host = &mut self.hosts[h];
        host.v4_ready = false;
        host.status.ipv4 = None;
        if host.status.state == HostState::Ready {
            host.status.state = HostState::Starting;
            host.start_at = now;
        }
        self.dhcp4_restart(h, now, Duration::ZERO);
    }

    fn poll_dhcp4(&mut self, h: usize, now: Duration) {
        let Some(d) = self.hosts[h].d4.as_mut() else {
            return;
        };
        match d.phase {
            D4Phase::Selecting | D4Phase::Requesting => {
                if now < d.next_tx {
                    return;
                }
                if d.phase == D4Phase::Requesting && d.tries >= MAX_REQUESTS {
                    d.phase = D4Phase::Selecting;
                    d.offer = None;
                    d.interval = self.options.retry;
                }
                d.tries += 1;
                d.next_tx = now + d.interval;
                d.interval = (d.interval * 2).min(MAX_RETRY);
                let kind = if d.phase == D4Phase::Selecting {
                    hw::DHCPDISCOVER
                } else {
                    hw::DHCPREQUEST
                };
                self.send_dhcp4(h, kind, now);
            }
            D4Phase::Bound | D4Phase::Renewing | D4Phase::Rebinding => {
                let since = now.saturating_sub(d.bound_at);
                if d.lease != NEVER && since >= d.lease {
                    self.lost_v4(h, now, "the DHCP lease ran out without a renewal");
                    return;
                }
                let next = match d.phase {
                    D4Phase::Bound if since >= d.t2 => D4Phase::Rebinding,
                    D4Phase::Bound if since >= d.t1 => D4Phase::Renewing,
                    D4Phase::Renewing if since >= d.t2 => D4Phase::Rebinding,
                    p => p,
                };
                if next != d.phase {
                    d.phase = next;
                    d.xid = d.xid.wrapping_add(1);
                    d.began = now;
                    d.next_tx = now;
                }
                if d.phase == D4Phase::Bound || now < d.next_tx {
                    return;
                }
                // Half the time to the next step, at least a second (RFC 2131 4.4.5).
                let until = if d.phase == D4Phase::Renewing {
                    d.t2
                } else {
                    d.lease
                };
                let left = until.saturating_sub(since);
                d.next_tx = now + (left / 2).max(Duration::from_secs(1));
                self.send_dhcp4(h, hw::DHCPREQUEST, now);
            }
        }
    }

    fn on_v4_ready(&mut self, h: usize, now: Duration) {
        let announcements = self.options.announcements;
        let host = &mut self.hosts[h];
        if host.cfg.announce {
            host.announce4 = Announce {
                left: announcements,
                next: now,
            };
        }
        let groups: Vec<IpAddr> = host
            .cfg
            .groups
            .iter()
            .copied()
            .filter(|g| g.is_ipv4())
            .collect();
        for g in groups {
            host.join(g, false, now);
        }
        self.check_ready(h, now);
    }

    // --- IPv6: router discovery, SLAAC, DAD, DHCPv6 ----------------------

    fn on_icmp6(&mut self, port: usize, link: &wire::Link, ip: &wire::Ip, now: Duration) -> bool {
        let Some(&kind) = ip.payload.first() else {
            return false;
        };
        match kind {
            NDP_SOLICIT | NDP_ADVERT => {
                let Some(nd) = wire::parse_ndp(ip) else {
                    return false;
                };
                self.on_ndp(port, link, ip, &nd)
            }
            hw::ICMP6_RA => {
                let Some(ra) = hw::parse_ra(ip) else {
                    return false;
                };
                let IpAddr::V6(src) = ip.src else {
                    return false;
                };
                let hosts: Vec<usize> = self.on_link(port, link).collect();
                let mut taken = false;
                for h in hosts {
                    if self.hosts[h].cfg.mac == link.src {
                        continue;
                    }
                    taken = true;
                    self.on_ra(h, src, &ra, now);
                }
                taken
            }
            hw::ICMP6_RS => {
                if !hw::is_rs(ip) {
                    return false;
                }
                let hosts: Vec<usize> = self.on_link(port, link).collect();
                let mut taken = false;
                for h in hosts {
                    let host = &mut self.hosts[h];
                    if host.cfg.router.is_none() || host.cfg.mac == link.src {
                        continue;
                    }
                    taken = true;
                    let soon = host.ra_last.map_or(now, |t| (t + MIN_RA_GAP).max(now));
                    host.ra_next = host.ra_next.min(soon);
                    self.wake = self.wake.min(host.ra_next);
                }
                taken
            }
            hw::ICMP6_MLD_QUERY => {
                let Some(q) = hw::parse_mld_query(ip) else {
                    return false;
                };
                let hosts: Vec<usize> = self.on_link(port, link).collect();
                for h in hosts {
                    self.on_query(h, &q, now);
                }
                true
            }
            hw::ICMP6_MLD1_REPORT | hw::ICMP6_MLD1_DONE | hw::ICMP6_MLD2_REPORT => true,
            128 => self.on_ping(port, link, ip),
            _ => false,
        }
    }

    fn on_ndp(&mut self, port: usize, link: &wire::Link, ip: &wire::Ip, nd: &wire::Ndp) -> bool {
        let IpAddr::V6(target) = nd.target else {
            return false;
        };
        let hosts: Vec<usize> = self.on_link(port, link).collect();
        let mut taken = false;
        for h in hosts {
            if self.hosts[h].cfg.mac == link.src {
                continue;
            }
            // Someone else has (an advert) or wants (a probe from ::) the
            // address being checked.
            let tentative = self.hosts[h].v6.tentative.map(|t| t.0);
            if tentative == Some(target) && (nd.kind == NDP_ADVERT || ip.src.is_unspecified()) {
                let by = nd.lladdr.unwrap_or(link.src);
                self.fail(
                    h,
                    format!("{target} is already in use on the link (by {by}; duplicate address detection)"),
                );
                taken = true;
                continue;
            }
            if nd.kind != NDP_SOLICIT || ip.src.is_unspecified() {
                continue;
            }
            let host = &mut self.hosts[h];
            if !host.answers_for(nd.target, self.options.answer) {
                continue;
            }
            let path = Path {
                src_mac: host.cfg.mac,
                dst_mac: nd.lladdr.unwrap_or(link.src),
                vlan: host.cfg.vlan,
                src: nd.target,
                dst: ip.src,
            };
            if let Some(f) = wire::ndp_advert(&path) {
                host.status.counters.resolutions_answered += 1;
                self.out.push((port, f));
                taken = true;
            }
        }
        taken
    }

    fn on_ra(&mut self, h: usize, src: Ipv6Addr, ra: &hw::RouterAdvert, now: Duration) {
        let dad = self.options.dad;
        let dad_wait = self.options.dad_wait;
        let host = &mut self.hosts[h];
        host.status.counters.ra_received += 1;
        let Some(mode) = host.cfg.ipv6.clone() else {
            return;
        };
        if matches!(mode, Ipv6Mode::Static { .. }) {
            return;
        }
        let v6 = &mut host.v6;
        v6.ra_seen = true;
        for p in ra.prefixes.iter().filter(|p| p.on_link && p.valid > 0) {
            let net = (hw::mask6(p.prefix, p.len), p.len);
            if !v6.on_link.contains(&net) {
                v6.on_link.push(net);
            }
        }
        // While setting up, the newest router with a lifetime is the
        // gateway; a run keeps the one it started with.
        if !host.v6_ready {
            if ra.lifetime > 0 {
                v6.router = Some(src);
            } else if v6.router == Some(src) {
                v6.router = None;
            }
        }
        if mode == Ipv6Mode::Slaac && v6.tentative.is_none() && v6.address.is_none() {
            if let Some(p) = ra
                .prefixes
                .iter()
                .find(|p| p.autonomous && p.len == 64 && p.valid > 0 && p.preferred <= p.valid)
            {
                let addr = hw::with_eui64(p.prefix, host.cfg.mac);
                v6.slaac_valid =
                    (p.valid != u32::MAX).then(|| Duration::from_secs(u64::from(p.valid)));
                self.tentative(h, addr, 64, now, dad, dad_wait);
                return;
            }
        }
        self.check_ready(h, now);
    }

    fn tentative(
        &mut self,
        h: usize,
        addr: Ipv6Addr,
        prefix: u8,
        now: Duration,
        dad: bool,
        wait: Duration,
    ) {
        let host = &mut self.hosts[h];
        host.join(wire::solicited_node(addr).into(), true, now);
        if dad {
            host.v6.tentative = Some((addr, prefix, now + wait));
            host.status.counters.dad_probes += 1;
            self.out.push((
                host.cfg.port,
                hw::dad_solicit(host.cfg.mac, host.cfg.vlan, addr),
            ));
            self.wake = self.wake.min(now + wait);
        } else {
            host.v6.tentative = Some((addr, prefix, now));
            self.wake = now;
        }
    }

    fn on_udp6(&mut self, port: usize, link: &wire::Link, ip: &wire::Ip, now: Duration) -> bool {
        let Some(udp) = wire::parse_udp(ip, false) else {
            return false;
        };
        if udp.dport == hw::DHCP6_SERVER_PORT {
            return self.on_dhcp6_server(port, link, ip, udp.data, now);
        }
        if udp.sport != hw::DHCP6_SERVER_PORT || udp.dport != hw::DHCP6_CLIENT_PORT {
            return false;
        }
        let Some(m) = hw::parse_dhcp6(udp.data) else {
            return false;
        };
        let Some(h) = self.on_link(port, link).find(|&h| {
            let host = &self.hosts[h];
            m.client_id == hw::duid(host.cfg.mac)
                && host.v6.d6.as_ref().is_some_and(|d| d.xid == m.xid)
        }) else {
            return false;
        };
        self.hosts[h].status.counters.dhcp_received += 1;
        self.on_dhcp6(h, ip.src, &m, now);
        true
    }

    /// A client message to the hosts' DHCPv6 servers.
    fn on_dhcp6_server(
        &mut self,
        port: usize,
        link: &wire::Link,
        ip: &wire::Ip,
        data: &[u8],
        now: Duration,
    ) -> bool {
        let IpAddr::V6(src) = ip.src else {
            return false;
        };
        let Some(m) = srv::parse_dhcp6_request(data) else {
            return false;
        };
        let servers: Vec<usize> = self
            .on_link(port, link)
            .filter(|&h| {
                let host = &self.hosts[h];
                host.srv6.is_some()
                    && (ip.dst == IpAddr::V6(hw::DHCP6_SERVERS)
                        || ip.dst == IpAddr::V6(host.ll)
                        || host.ip6().is_some_and(|a| ip.dst == IpAddr::V6(a)))
            })
            .collect();
        for &h in &servers {
            let host = &mut self.hosts[h];
            let (mac, vlan, ll) = (host.cfg.mac, host.cfg.vlan, host.ll);
            if let Some(f) = host
                .srv6
                .as_mut()
                .and_then(|s| s.handle(mac, vlan, ll, link.src, src, &m, now))
            {
                self.out.push((port, f));
            }
        }
        !servers.is_empty()
    }

    fn send_dhcp6(&mut self, h: usize, kind: u8, now: Duration) {
        let host = &mut self.hosts[h];
        let Some(d) = host.v6.d6.as_ref() else {
            return;
        };
        let elapsed = (now.saturating_sub(d.began).as_millis() / 10).min(0xffff) as u16;
        let m = Dhcp6Out {
            kind,
            xid: d.xid & 0x00ff_ffff,
            mac: host.cfg.mac,
            iaid: u32::from_be_bytes([
                host.cfg.mac.0[2],
                host.cfg.mac.0[3],
                host.cfg.mac.0[4],
                host.cfg.mac.0[5],
            ]),
            elapsed,
            server_id: (!d.server_id.is_empty()
                && kind != hw::DHCP6_REBIND
                && kind != hw::DHCP6_SOLICIT)
                .then_some(d.server_id.as_slice()),
            address: d.addr,
        };
        let f = hw::dhcp6_frame(host.cfg.mac, host.cfg.vlan, host.ll, &m);
        host.status.counters.dhcp_sent += 1;
        self.out.push((host.cfg.port, f));
    }

    fn dhcp6_restart(&mut self, h: usize, now: Duration) {
        let retry = self.options.retry;
        let host = &mut self.hosts[h];
        let xid = host.xid() & 0x00ff_ffff;
        // A random first delay (RFC 8415 18.2.1), short for a lab.
        let delay = host.rand_below(Duration::from_millis(100));
        host.v6.d6 = Some(Dhcp6 {
            phase: D6Phase::Soliciting,
            xid,
            began: now,
            next_tx: now + delay,
            interval: retry,
            tries: 0,
            server_id: Vec::new(),
            addr: None,
            bound_at: now,
            t1: NEVER,
            t2: NEVER,
            valid: NEVER,
        });
    }

    fn on_dhcp6(&mut self, h: usize, from: IpAddr, m: &hw::Dhcp6In, now: Duration) {
        let retry = self.options.retry;
        let dad = self.options.dad;
        let dad_wait = self.options.dad_wait;
        let Some(phase) = self.hosts[h].v6.d6.as_ref().map(|d| d.phase) else {
            return;
        };
        match (phase, m.kind) {
            (D6Phase::Soliciting, hw::DHCP6_ADVERTISE) => {
                let (Some((addr, _, _)), None) = (m.address, m.status) else {
                    return;
                };
                if m.server_id.is_empty() {
                    return;
                }
                let d = self.hosts[h].v6.d6.as_mut().expect("dhcpv6");
                d.phase = D6Phase::Requesting;
                d.server_id = m.server_id.clone();
                d.addr = Some(addr);
                d.xid = d.xid.wrapping_add(1) & 0x00ff_ffff;
                d.began = now;
                d.interval = retry;
                d.tries = 1;
                d.next_tx = now + retry;
                self.send_dhcp6(h, hw::DHCP6_REQUEST, now);
            }
            (D6Phase::Requesting | D6Phase::Renewing | D6Phase::Rebinding, hw::DHCP6_REPLY) => {
                if let Some(code) = m.status {
                    let why = format!(
                        "the DHCPv6 server answered {} ({code})",
                        hw::dhcp6_status(code)
                    );
                    self.hosts[h].status.counters.dhcp_naks += 1;
                    if phase == D6Phase::Requesting {
                        self.dhcp6_restart(h, now);
                    } else {
                        self.lost_v6(h, now, &why);
                    }
                    return;
                }
                let Some((addr, preferred, valid)) = m.address else {
                    return;
                };
                let fail_fast = self.options.fail_fast;
                let host = &mut self.hosts[h];
                let d = host.v6.d6.as_mut().expect("dhcpv6");
                if phase != D6Phase::Requesting && d.addr != Some(addr) && fail_fast {
                    let msg = format!("the DHCPv6 server moved the host to {addr} on renewal");
                    self.fail(h, msg);
                    return;
                }
                let secs = |s: u32| {
                    if s == u32::MAX {
                        NEVER
                    } else {
                        Duration::from_secs(u64::from(s))
                    }
                };
                let valid = secs(valid);
                let preferred = secs(preferred);
                d.phase = D6Phase::Bound;
                d.addr = Some(addr);
                d.bound_at = now;
                d.valid = valid;
                d.t1 = if m.t1 > 0 {
                    secs(m.t1)
                } else if preferred == NEVER {
                    NEVER
                } else {
                    preferred / 2
                };
                d.t2 = if m.t2 > 0 {
                    secs(m.t2)
                } else if preferred == NEVER {
                    NEVER
                } else {
                    preferred * 4 / 5
                };
                d.t1 = d.t1.min(valid);
                d.t2 = d.t2.min(valid).max(d.t1);
                let renewed = phase != D6Phase::Requesting;
                if let Some(a) = host.status.ipv6.as_mut() {
                    a.lease = (valid != NEVER).then_some(valid);
                    a.renewals += u64::from(renewed);
                    a.server = Some(from);
                    a.dns = m.dns.iter().map(|a| IpAddr::V6(*a)).collect();
                } else if !renewed {
                    host.status.ipv6 = Some(HostAddress {
                        ip: addr.into(),
                        prefix: 128,
                        gateway: None,
                        source: AddressSource::Dhcpv6,
                        server: Some(from),
                        dns: m.dns.iter().map(|a| IpAddr::V6(*a)).collect(),
                        lease: (valid != NEVER).then_some(valid),
                        renewals: 0,
                    });
                }
                if host.v6.address.is_none() && host.v6.tentative.is_none() {
                    self.tentative(h, addr, 128, now, dad, dad_wait);
                }
            }
            _ => {}
        }
    }

    fn lost_v6(&mut self, h: usize, now: Duration, why: &str) {
        if self.options.fail_fast {
            self.fail(h, why.to_string());
            return;
        }
        let host = &mut self.hosts[h];
        host.v6_ready = false;
        host.v6.address = None;
        host.v6.tentative = None;
        host.status.ipv6 = None;
        if host.status.state == HostState::Ready {
            host.status.state = HostState::Starting;
            host.start_at = now;
        }
        if host.cfg.ipv6 == Some(Ipv6Mode::Dhcpv6) {
            self.dhcp6_restart(h, now);
        } else {
            host.v6.rs_next = Some(now);
        }
    }

    fn poll_v6(&mut self, h: usize, now: Duration) {
        let retry = self.options.retry;
        let host = &mut self.hosts[h];
        // Router solicitations until a router answers; a DHCPv6 host stops
        // asking after a few and goes on without one.
        if let Some(at) = host.v6.rs_next {
            if host.v6.ra_seen {
                host.v6.rs_next = None;
            } else if now >= at {
                let slaac = host.cfg.ipv6 == Some(Ipv6Mode::Slaac);
                if slaac || host.v6.rs_count < MAX_RS_WAIT {
                    host.v6.rs_interval = if host.v6.rs_interval.is_zero() {
                        retry
                    } else {
                        (host.v6.rs_interval * 2).min(MAX_RETRY)
                    };
                    host.v6.rs_next = Some(now + host.v6.rs_interval);
                    host.v6.rs_count += 1;
                    host.status.counters.rs_sent += 1;
                    self.out.push((
                        host.cfg.port,
                        hw::router_solicit(host.cfg.mac, host.cfg.vlan, host.ll),
                    ));
                } else {
                    host.v6.rs_next = None;
                    self.check_ready(h, now);
                }
            }
        }
        let host = &mut self.hosts[h];
        // The duplicate check ends.
        if let Some((addr, prefix, until)) = host.v6.tentative {
            if now >= until {
                host.v6.tentative = None;
                host.v6.address = Some((addr, prefix));
                self.address_v6(h, now);
            }
        }
        // DHCPv6 retransmissions, renewals and expiry.
        let host = &mut self.hosts[h];
        let Some(d) = host.v6.d6.as_mut() else {
            return;
        };
        match d.phase {
            D6Phase::Soliciting | D6Phase::Requesting => {
                if now < d.next_tx {
                    return;
                }
                if d.phase == D6Phase::Requesting && d.tries >= MAX_REQUESTS {
                    d.phase = D6Phase::Soliciting;
                    d.server_id.clear();
                    d.addr = None;
                    d.interval = retry;
                }
                d.tries += 1;
                d.next_tx = now + d.interval;
                d.interval = (d.interval * 2).min(MAX_RETRY);
                let kind = if d.phase == D6Phase::Soliciting {
                    hw::DHCP6_SOLICIT
                } else {
                    hw::DHCP6_REQUEST
                };
                self.send_dhcp6(h, kind, now);
            }
            D6Phase::Bound | D6Phase::Renewing | D6Phase::Rebinding => {
                let since = now.saturating_sub(d.bound_at);
                if d.valid != NEVER && since >= d.valid {
                    self.lost_v6(h, now, "the DHCPv6 lease ran out without a renewal");
                    return;
                }
                let next = match d.phase {
                    D6Phase::Bound if since >= d.t2 => D6Phase::Rebinding,
                    D6Phase::Bound if since >= d.t1 => D6Phase::Renewing,
                    D6Phase::Renewing if since >= d.t2 => D6Phase::Rebinding,
                    p => p,
                };
                if next != d.phase {
                    d.phase = next;
                    d.xid = d.xid.wrapping_add(1) & 0x00ff_ffff;
                    d.began = now;
                    d.next_tx = now;
                    d.interval = retry;
                }
                if d.phase == D6Phase::Bound || now < d.next_tx {
                    return;
                }
                d.next_tx = now + d.interval;
                d.interval = (d.interval * 2).min(Duration::from_secs(600));
                let kind = if d.phase == D6Phase::Renewing {
                    hw::DHCP6_RENEW
                } else {
                    hw::DHCP6_REBIND
                };
                self.send_dhcp6(h, kind, now);
            }
        }
    }

    /// The IPv6 address passed its duplicate check.
    fn address_v6(&mut self, h: usize, now: Duration) {
        let announcements = self.options.announcements;
        let host = &mut self.hosts[h];
        let Some((addr, prefix)) = host.v6.address else {
            return;
        };
        let (source, gateway, prefix) = match &host.cfg.ipv6 {
            Some(Ipv6Mode::Static { gateway, .. }) => (AddressSource::Static, *gateway, prefix),
            Some(Ipv6Mode::Slaac) => (AddressSource::Slaac, host.v6.router, prefix),
            _ => {
                // A DHCPv6 address is on the link of an advertised on-link
                // prefix that holds it; else take the usual /64.
                let p = host
                    .v6
                    .on_link
                    .iter()
                    .filter(|(net, len)| hw::mask6(addr, *len) == *net)
                    .map(|(_, len)| *len)
                    .max()
                    .unwrap_or(64);
                (AddressSource::Dhcpv6, host.v6.router, p)
            }
        };
        host.v6.address = Some((addr, prefix));
        let old = host.status.ipv6.take();
        host.status.ipv6 = Some(HostAddress {
            ip: addr.into(),
            prefix,
            gateway: gateway.map(IpAddr::V6),
            source,
            server: old.as_ref().and_then(|o| o.server),
            dns: old.as_ref().map(|o| o.dns.clone()).unwrap_or_default(),
            lease: match source {
                AddressSource::Slaac => host.v6.slaac_valid,
                _ => old.as_ref().and_then(|o| o.lease),
            },
            renewals: old.map_or(0, |o| o.renewals),
        });
        if host.cfg.announce {
            host.announce6 = Announce {
                left: announcements,
                next: now,
            };
        }
        self.check_ready(h, now);
    }

    /// True once a DHCPv6 host has its address and has heard a router (or
    /// stopped asking for one).
    fn v6_complete(host: &Emu) -> bool {
        match host.cfg.ipv6 {
            None => true,
            Some(Ipv6Mode::Dhcpv6) => {
                host.v6.address.is_some() && (host.v6.ra_seen || host.v6.rs_next.is_none())
            }
            Some(_) => host.v6.address.is_some(),
        }
    }

    fn check_ready(&mut self, h: usize, now: Duration) {
        let host = &mut self.hosts[h];
        if !host.v6_ready && host.cfg.ipv6.is_some() && Self::v6_complete(host) {
            host.v6_ready = true;
            // The gateway may have been learned after the address.
            if let (Some(a), Some(Ipv6Mode::Dhcpv6 | Ipv6Mode::Slaac)) =
                (host.status.ipv6.as_mut(), &host.cfg.ipv6)
            {
                a.gateway = host.v6.router.map(IpAddr::V6);
            }
        }
        if host.cfg.ipv6.is_none() || host.v6_ready {
            let groups: Vec<IpAddr> = host
                .cfg
                .groups
                .iter()
                .copied()
                .filter(|g| g.is_ipv6())
                .collect();
            for g in groups {
                host.join(g, false, now);
            }
        }
        if host.status.state == HostState::Starting && host.ready() {
            host.status.state = HostState::Ready;
            host.status.ready_after = Some(now.saturating_sub(host.start_at));
        }
        self.wake = now;
    }

    // --- Multicast groups -------------------------------------------------

    fn on_igmp(&mut self, port: usize, link: &wire::Link, ip: &wire::Ip, now: Duration) -> bool {
        if let Some(q) = hw::parse_igmp_query(ip.payload) {
            let hosts: Vec<usize> = self.on_link(port, link).collect();
            for h in hosts {
                self.on_query(h, &q, now);
            }
        }
        // Reports and leaves of others: nothing to do (no report suppression
        // in IGMPv3, and v2 suppression would hide the host from snooping
        // switches that track every member).
        true
    }

    fn on_query(&mut self, h: usize, q: &hw::Query, now: Duration) {
        let host = &mut self.hosts[h];
        let v4 = q.group.is_ipv4();
        if v4 {
            host.igmp_version = host.igmp_version.min(q.version);
        } else {
            host.mld_version = host.mld_version.min(q.version);
        }
        let mut asked = false;
        let max = q.max_response.max(Duration::from_millis(1));
        for i in 0..host.groups.len() {
            let g = &host.groups[i];
            if g.addr.is_ipv4() != v4 || !(q.group.is_unspecified() || q.group == g.addr) {
                continue;
            }
            asked = true;
            let at = now + host.rand_below(max);
            let g = &mut host.groups[i];
            g.next_report = Some(g.next_report.map_or(at, |t| t.min(at)));
            self.wake = self.wake.min(at);
        }
        if asked {
            host.status.counters.queries += 1;
        }
    }

    fn poll_groups(&mut self, h: usize, now: Duration) {
        let host = &mut self.hosts[h];
        let src4 = if host.v4_ready { host.ip4() } else { None };
        for i in 0..host.groups.len() {
            let g = &mut host.groups[i];
            let Some(at) = g.next_report else { continue };
            if now < at {
                continue;
            }
            let joining = g.join_left > 0;
            if joining {
                g.join_left -= 1;
            }
            g.next_report = (g.join_left > 0).then_some(now + REPORT_INTERVAL);
            let record = if joining {
                hw::CHANGE_TO_EXCLUDE
            } else {
                hw::MODE_IS_EXCLUDE
            };
            let frame = match g.addr {
                IpAddr::V4(group) => {
                    let Some(src) = src4 else { continue };
                    hw::igmp_report(
                        host.cfg.mac,
                        host.cfg.vlan,
                        src,
                        group,
                        host.igmp_version,
                        record,
                    )
                }
                IpAddr::V6(group) => hw::mld_report(
                    host.cfg.mac,
                    host.cfg.vlan,
                    host.ll,
                    group,
                    host.mld_version,
                    record,
                ),
            };
            if g.status != usize::MAX {
                host.status.groups[g.status].reports += 1;
            }
            self.out.push((host.cfg.port, frame));
        }
    }

    // --- Timers -----------------------------------------------------------

    fn start(&mut self, h: usize, now: Duration) {
        let dad = self.options.dad;
        let dad_wait = self.options.dad_wait;
        let host = &mut self.hosts[h];
        host.started = true;
        host.start_at = now;
        if host.uses_v6 {
            let ll = host.ll;
            host.join(wire::solicited_node(ll).into(), true, now);
        }
        if host.srv6.is_some() {
            // So that snooping switches send the clients' messages here.
            host.join(hw::DHCP6_SERVERS.into(), true, now);
        }
        match host.cfg.ipv4.clone() {
            Some(Ipv4Mode::Static {
                ip,
                prefix,
                gateway,
            }) => {
                host.status.ipv4 = Some(HostAddress {
                    ip: ip.into(),
                    prefix,
                    gateway: gateway.map(IpAddr::V4),
                    source: AddressSource::Static,
                    server: None,
                    dns: Vec::new(),
                    lease: None,
                    renewals: 0,
                });
                host.v4_ready = true;
                self.on_v4_ready(h, now);
            }
            Some(Ipv4Mode::Dhcp) => {
                let delay = self.hosts[h].rand_below(Duration::from_millis(100));
                self.dhcp4_restart(h, now, delay);
            }
            None => {}
        }
        let host = &mut self.hosts[h];
        match host.cfg.ipv6.clone() {
            Some(Ipv6Mode::Static { ip, prefix, .. }) => {
                self.tentative(h, ip, prefix, now, dad, dad_wait);
            }
            Some(Ipv6Mode::Slaac) => host.v6.rs_next = Some(now),
            Some(Ipv6Mode::Dhcpv6) => {
                host.v6.rs_next = Some(now);
                self.dhcp6_restart(h, now);
            }
            None => {}
        }
        let host = &mut self.hosts[h];
        if host.cfg.router.is_some() {
            host.ra_next = now;
        }
        self.check_ready(h, now);
    }

    /// Runs the hosts' timers: retransmissions, renewals, announcements,
    /// reports and advertisements.
    pub fn poll(&mut self, now: Duration) {
        self.now = self.now.max(now);
        if self.finished || now < self.wake {
            return;
        }
        let mut wake = NEVER;
        for h in 0..self.hosts.len() {
            if !self.hosts[h].started {
                if now < self.hosts[h].start_at {
                    wake = wake.min(self.hosts[h].start_at);
                    continue;
                }
                self.start(h, now);
            }
            if self.hosts[h].status.state == HostState::Failed {
                continue;
            }
            self.poll_host(h, now);
            wake = wake.min(self.next_wake(h));
        }
        self.wake = wake;
        self.loop_back(now);
    }

    fn poll_host(&mut self, h: usize, now: Duration) {
        let timeout = self.options.setup_timeout;
        self.poll_dhcp4(h, now);
        self.poll_v6(h, now);
        if self.hosts[h].status.state == HostState::Failed {
            return;
        }
        let host = &mut self.hosts[h];
        if host.status.state == HostState::Starting && now.saturating_sub(host.start_at) >= timeout
        {
            let why = self.setup_failure(h, timeout);
            self.fail(h, why);
            return;
        }
        self.poll_groups(h, now);
        let interval = self.options.announce_interval;
        let host = &mut self.hosts[h];
        if host.announce4.left > 0 && now >= host.announce4.next {
            if let Some(ip) = host.ip4() {
                host.announce4.left -= 1;
                host.announce4.next = now + interval;
                host.status.counters.announcements += 1;
                self.out.push((
                    host.cfg.port,
                    hw::gratuitous_arp(host.cfg.mac, host.cfg.vlan, ip),
                ));
            }
        }
        if host.announce6.left > 0 && now >= host.announce6.next {
            if let Some(ip) = host.ip6() {
                host.announce6.left -= 1;
                host.announce6.next = now + interval;
                host.status.counters.announcements += 1;
                self.out.push((
                    host.cfg.port,
                    hw::unsolicited_advert(host.cfg.mac, host.cfg.vlan, ip),
                ));
            }
        }
        if now >= host.ra_next {
            if let Some(r) = &host.cfg.router {
                host.ra_next = now + r.interval;
                host.ra_last = Some(now);
                host.status.counters.ra_sent += 1;
                let f = advert(host, r.lifetime);
                self.out.push((host.cfg.port, f));
            }
        }
    }

    fn setup_failure(&self, h: usize, timeout: Duration) -> String {
        let host = &self.hosts[h];
        if let Some(d) = host.d4.as_ref().filter(|_| !host.v4_ready) {
            return match (d.phase, d.offer) {
                (D4Phase::Requesting, Some((ip, server))) => format!(
                    "DHCP server {server} offered {ip}, but did not acknowledge the request within {timeout:?}"
                ),
                _ => format!(
                    "no DHCP offer within {timeout:?} ({} discovers sent); check that a DHCP server or relay serves this link and VLAN",
                    host.status.counters.dhcp_sent
                ),
            };
        }
        match (&host.cfg.ipv6, host.v6.d6.as_ref()) {
            (Some(Ipv6Mode::Dhcpv6), Some(d))
                if host.v6.address.is_none() && host.v6.tentative.is_none() =>
            {
                if d.phase == D6Phase::Requesting {
                    format!("the DHCPv6 server advertised an address but did not answer the request within {timeout:?}")
                } else {
                    format!("no DHCPv6 advertise with an address within {timeout:?}; check that a DHCPv6 server or relay serves this link")
                }
            }
            (Some(Ipv6Mode::Slaac), _) if host.v6.address.is_none() => {
                if host.v6.ra_seen {
                    format!("router advertisements came, but none with a /64 prefix for autoconfiguration (A flag), within {timeout:?}")
                } else {
                    format!(
                        "no router advertisement within {timeout:?} ({} solicitations sent)",
                        host.status.counters.rs_sent
                    )
                }
            }
            _ => format!("did not get its addresses within {timeout:?}"),
        }
    }

    fn next_wake(&self, h: usize) -> Duration {
        let host = &self.hosts[h];
        let mut w = NEVER;
        let mut at = |t: Duration| w = w.min(t);
        if host.status.state == HostState::Starting {
            at(host.start_at + self.options.setup_timeout);
        }
        if let Some(d) = &host.d4 {
            match d.phase {
                D4Phase::Selecting | D4Phase::Requesting => at(d.next_tx),
                D4Phase::Bound => {
                    at(d.bound_at.saturating_add(d.t1));
                }
                D4Phase::Renewing | D4Phase::Rebinding => {
                    at(d.next_tx);
                    at(d.bound_at.saturating_add(d.t2));
                    at(d.bound_at.saturating_add(d.lease));
                }
            }
        }
        if let Some(d) = &host.v6.d6 {
            match d.phase {
                D6Phase::Soliciting | D6Phase::Requesting => at(d.next_tx),
                D6Phase::Bound => at(d.bound_at.saturating_add(d.t1)),
                D6Phase::Renewing | D6Phase::Rebinding => {
                    at(d.next_tx);
                    at(d.bound_at.saturating_add(d.t2));
                    at(d.bound_at.saturating_add(d.valid));
                }
            }
        }
        if let Some(t) = host.v6.rs_next {
            at(t);
        }
        if let Some((_, _, t)) = host.v6.tentative {
            at(t);
        }
        for g in &host.groups {
            if let Some(t) = g.next_report {
                at(t);
            }
        }
        if host.announce4.left > 0 {
            at(host.announce4.next);
        }
        if host.announce6.left > 0 {
            at(host.announce6.next);
        }
        at(host.ra_next);
        w
    }

    /// Releases leases, leaves groups and retires routers, when the run ends.
    pub fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        let release = self.options.release;
        for h in 0..self.hosts.len() {
            if !self.hosts[h].started {
                continue;
            }
            if release {
                if self.hosts[h].v4_ready
                    && self.hosts[h].d4.as_ref().is_some_and(|d| {
                        d.phase != D4Phase::Selecting && d.phase != D4Phase::Requesting
                    })
                {
                    self.send_dhcp4(h, hw::DHCPRELEASE, Duration::ZERO);
                }
                if self.hosts[h].v6.d6.as_ref().is_some_and(|d| {
                    matches!(
                        d.phase,
                        D6Phase::Bound | D6Phase::Renewing | D6Phase::Rebinding
                    )
                }) {
                    if let Some(d) = self.hosts[h].v6.d6.as_mut() {
                        d.xid = d.xid.wrapping_add(1) & 0x00ff_ffff;
                        d.began = Duration::ZERO;
                    }
                    self.send_dhcp6(h, hw::DHCP6_RELEASE, Duration::ZERO);
                }
            }
            let host = &mut self.hosts[h];
            let src4 = if host.v4_ready { host.ip4() } else { None };
            for g in host.groups.iter().filter(|g| !g.auto) {
                let frame = match g.addr {
                    IpAddr::V4(group) => match src4 {
                        Some(src) if host.igmp_version > 1 => hw::igmp_report(
                            host.cfg.mac,
                            host.cfg.vlan,
                            src,
                            group,
                            host.igmp_version,
                            hw::CHANGE_TO_INCLUDE,
                        ),
                        _ => continue,
                    },
                    IpAddr::V6(group) => hw::mld_report(
                        host.cfg.mac,
                        host.cfg.vlan,
                        host.ll,
                        group,
                        host.mld_version,
                        hw::CHANGE_TO_INCLUDE,
                    ),
                };
                self.out.push((host.cfg.port, frame));
            }
            if host.cfg.router.is_some() {
                host.status.counters.ra_sent += 1;
                let f = advert(host, Duration::ZERO);
                self.out.push((host.cfg.port, f));
            }
        }
        self.loop_back(self.now);
    }
}

/// A router advertisement of `host`'s router settings, with `lifetime`.
fn advert(host: &Emu, lifetime: Duration) -> Vec<u8> {
    let r = host.cfg.router.as_ref().expect("a router");
    hw::router_advert(
        host.cfg.mac,
        host.cfg.vlan,
        host.ll,
        &hw::AdvertOut {
            managed: r.managed,
            other: r.other,
            lifetime: lifetime.as_secs().min(9000) as u16,
            prefixes: &r.prefixes,
            valid: 86400,
            preferred: 14400,
        },
    )
}
