//! Host emulation: emulated hosts that get their addresses and behave on
//! the link like real ones.
//!
//! * Addresses: static, from a DHCP server ([`Ipv4Mode::Dhcp`]: discover,
//!   offer, request, ack; renewal at T1, rebinding at T2, release at the
//!   end), by stateless autoconfiguration ([`Ipv6Mode::Slaac`]: router
//!   solicitation, the advertised /64 prefix plus the EUI-64, duplicate
//!   address detection) or from a DHCPv6 server ([`Ipv6Mode::Dhcpv6`]:
//!   solicit, advertise, request, reply; renew, rebind, release). IPv6 hosts
//!   always have a link-local address too.
//! * Announcements: gratuitous ARP and unsolicited neighbor advertisements
//!   once an address is set, so switches and neighbors learn it.
//! * Multicast: IGMPv1-3 and MLDv1-2 reports for the groups a host joins
//!   (and, over MLD, the solicited-node groups of its own addresses), answers
//!   to general and group queries, leaves at the end; frames to a group are
//!   counted.
//! * Routers: a host with a [`RouterConfig`] sends router advertisements
//!   with prefixes, and answers router solicitations.
//! * DHCP servers: a host with a [`DhcpServerConfig`] (and a static IPv4
//!   address) or a [`Dhcpv6ServerConfig`] leases addresses from a pool to
//!   clients on its link, real ones or the engine's own hosts, and
//!   delegates prefixes to requesting routers (`pd_pool`); a host with
//!   `prefix_delegation` asks for one.
//! * Link services: LLDP and CDP announcements with the neighbors heard
//!   ([`LldpConfig`]), an mDNS/DNS-SD responder and queries
//!   ([`MdnsConfig`]), 802.1X authentication with EAP-MD5 before the host
//!   uses the link ([`Dot1xConfig`], and an [`AuthenticatorConfig`] role),
//!   and NetFlow v9 / IPFIX export of flow records ([`FlowExportConfig`]).
//!
//! [`HostEngine`] runs the hosts, sans-IO like the TCP and UDP engines; on
//! its own (`ferotrx host`) it also answers ARP, neighbor solicitations and
//! pings for its hosts. [`Hosted`] puts it in front of a TCP or UDP engine,
//! whose client and server then get their addresses first
//! ([`EndpointHosts`]); `docs/host-emulation.md` has the details.

mod eapol;
mod engine;
mod flow;
mod hosted;
mod lldp;
mod mdns;
#[cfg(feature = "profile")]
mod profile;
mod server;
pub(crate) mod wire;

pub use eapol::{
    AuthenticatorConfig, AuthenticatorStatus, Dot1xConfig, Dot1xSession, Dot1xState, Dot1xStatus,
};
pub use engine::{
    AddressSource, GroupStatus, HostAddress, HostConfig, HostCounters, HostEngine, HostOptions,
    HostState, HostStats, HostStatus, Ipv4Mode, Ipv6Mode, RouterConfig,
};
pub use flow::{FlowExportConfig, FlowExportStatus, FlowVersion};
pub use hosted::{Addressing, Emulation, EndpointConfig, EndpointHosts, Hosted, HostedStats};
pub use lldp::{LldpConfig, LldpNeighbor, LldpStatus};
pub use mdns::{MdnsConfig, MdnsRecord, MdnsService, MdnsStatus};
#[cfg(feature = "profile")]
pub(crate) use profile::{host_options, RawOptions as RawHostOptions};
#[cfg(feature = "profile")]
pub use profile::{
    parse_collector, parse_ipv4_mode, parse_ipv6_mode, parse_pool, parse_prefix6, HostProfile,
    HostSpec,
};
pub use server::{
    DhcpLease, DhcpServerConfig, DhcpServerCounters, DhcpServerStatus, Dhcpv6ServerConfig,
};

#[cfg(test)]
mod tests;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::MacAddr;

/// What the link services need to know about their host.
#[derive(Clone, Debug)]
pub(crate) struct Me {
    pub mac: MacAddr,
    pub vlan: Option<u16>,
    pub hostname: Option<String>,
    /// The IPv4 address, once the host has it.
    pub ip4: Option<(Ipv4Addr, u8)>,
    pub gateway4: Option<Ipv4Addr>,
    /// The global IPv6 address, once the host has it.
    pub ip6: Option<(Ipv6Addr, u8)>,
    pub gateway6: Option<Ipv6Addr>,
    /// The link-local address, when the host uses IPv6.
    pub ll: Option<Ipv6Addr>,
}

impl Me {
    /// A name for the host: its host name, else one from its MAC.
    pub fn name(&self) -> String {
        match &self.hostname {
            Some(n) => n.clone(),
            None => {
                let m = self.mac.0;
                format!("ferotrx-{:02x}{:02x}{:02x}", m[3], m[4], m[5])
            }
        }
    }

    /// The next hop towards `ip`: itself on the host's link (or with no
    /// gateway), else the gateway.
    pub fn next_hop(&self, ip: IpAddr) -> Option<IpAddr> {
        match ip {
            IpAddr::V4(a) => {
                let (own, len) = self.ip4?;
                let mask = if len == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(len.min(32)))
                };
                let on_link = u32::from(a) & mask == u32::from(own) & mask;
                Some(match self.gateway4 {
                    Some(g) if !on_link => IpAddr::V4(g),
                    _ => ip,
                })
            }
            IpAddr::V6(a) => {
                let on_link = wire::is_link_local(a)
                    || self
                        .ip6
                        .is_some_and(|(own, len)| wire::mask6(a, len) == wire::mask6(own, len));
                Some(match self.gateway6 {
                    Some(g) if !on_link => IpAddr::V6(g),
                    _ => ip,
                })
            }
        }
    }

    /// The host's source address towards `ip`'s IP version.
    pub fn source(&self, ip: IpAddr) -> Option<IpAddr> {
        match ip {
            IpAddr::V4(_) => self.ip4.map(|a| IpAddr::V4(a.0)),
            IpAddr::V6(a) if wire::is_link_local(a) => self.ll.map(IpAddr::V6),
            IpAddr::V6(_) => self
                .ip6
                .map(|a| IpAddr::V6(a.0))
                .or(self.ll.map(IpAddr::V6)),
        }
    }
}

/// Unicast next hops a host's services send to, resolved by ARP or
/// neighbor solicitations.
#[derive(Debug, Default)]
pub(crate) struct Resolver {
    entries: Vec<Resolved>,
}

#[derive(Debug)]
struct Resolved {
    ip: IpAddr,
    mac: Option<MacAddr>,
    next_try: Duration,
    tries: u32,
}

/// Time between ARP requests or solicitations for an unresolved next hop.
const RESOLVE_RETRY: Duration = Duration::from_secs(1);

impl Resolver {
    /// The MAC of `ip`, if known; else `Err(true)` when a request is due now.
    pub fn lookup(&mut self, ip: IpAddr, now: Duration) -> Result<MacAddr, bool> {
        let i = match self.entries.iter().position(|e| e.ip == ip) {
            Some(i) => i,
            None => {
                self.entries.push(Resolved {
                    ip,
                    mac: None,
                    next_try: now,
                    tries: 0,
                });
                self.entries.len() - 1
            }
        };
        let e = &mut self.entries[i];
        if let Some(m) = e.mac {
            return Ok(m);
        }
        if now >= e.next_try {
            e.tries += 1;
            e.next_try = now + RESOLVE_RETRY;
            return Err(true);
        }
        Err(false)
    }

    /// Learns `ip` at `mac`, if it is being resolved; true if it was.
    pub fn learn(&mut self, ip: IpAddr, mac: MacAddr) -> bool {
        match self.entries.iter_mut().find(|e| e.ip == ip) {
            Some(e) => {
                e.mac = Some(mac);
                true
            }
            None => false,
        }
    }

    /// When the next request for an unresolved next hop is due.
    pub fn next_wake(&self) -> Duration {
        self.entries
            .iter()
            .filter(|e| e.mac.is_none())
            .map(|e| e.next_try)
            .min()
            .unwrap_or(Duration::MAX)
    }
}
