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
//!
//! [`HostEngine`] runs the hosts, sans-IO like the TCP and UDP engines; on
//! its own (`ferotrx host`) it also answers ARP, neighbor solicitations and
//! pings for its hosts. [`Hosted`] puts it in front of a TCP or UDP engine,
//! whose client and server then get their addresses first
//! ([`EndpointHosts`]); `docs/host-emulation.md` has the details.

mod engine;
mod hosted;
#[cfg(feature = "profile")]
mod profile;
pub(crate) mod wire;

pub use engine::{
    AddressSource, GroupStatus, HostAddress, HostConfig, HostCounters, HostEngine, HostOptions,
    HostState, HostStats, HostStatus, Ipv4Mode, Ipv6Mode, RouterConfig,
};
pub use hosted::{Addressing, Emulation, EndpointConfig, EndpointHosts, Hosted, HostedStats};
#[cfg(feature = "profile")]
pub(crate) use profile::{host_options, RawOptions as RawHostOptions};
#[cfg(feature = "profile")]
pub use profile::{parse_ipv4_mode, parse_ipv6_mode, parse_prefix6, HostProfile, HostSpec};

#[cfg(test)]
mod tests;
