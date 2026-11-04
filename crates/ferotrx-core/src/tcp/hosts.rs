//! Emulated hosts: ARP, neighbor discovery and resolving next hops, shared by
//! the TCP and UDP engines.

use std::net::IpAddr;
use std::time::Duration;

use super::engine::TcpEndpoint;
use super::program::TcpRole;
use super::wire::{self, Path, BROADCAST};
use crate::MacAddr;

/// How often an unanswered ARP request or neighbor solicitation is repeated.
pub(crate) const ARP_RETRY: Duration = Duration::from_millis(500);
/// Most next hops a client resolves.
pub(crate) const MAX_HOPS: usize = 1024;

/// One emulated host and, for a client, its next hops.
pub(crate) struct Host {
    pub ep: TcpEndpoint,
    pub role: TcpRole,
    /// The client's next hops (the gateway, or servers on its link) and
    /// their MACs, once known.
    pub hops: Vec<(IpAddr, Option<MacAddr>)>,
    pub arp_next: Duration,
    pub arp_since: Option<Duration>,
    /// A reply from the next hop seen on the right port but another VLAN
    /// (`Some(None)`: untagged), for the error message if ARP fails.
    pub arp_elsewhere: Option<Option<u16>>,
}

impl Host {
    pub fn new(role: TcpRole, ep: TcpEndpoint, hops: Vec<(IpAddr, Option<MacAddr>)>) -> Self {
        Self {
            ep,
            role,
            hops,
            arp_next: Duration::ZERO,
            arp_since: None,
            arp_elsewhere: None,
        }
    }

    /// The MAC address of next hop `hop`, once known.
    pub fn hop_mac(&self, hop: IpAddr) -> Option<MacAddr> {
        self.hops
            .iter()
            .find(|(h, _)| *h == hop)
            .and_then(|(_, m)| *m)
    }

    /// True when every next hop's MAC address is known.
    pub fn resolved(&self) -> bool {
        self.hops.iter().all(|(_, mac)| mac.is_some())
    }
}

/// Learns next hops' MACs from ARP, and answers requests for the hosts' addresses.
pub(crate) fn on_arp(
    hosts: &mut [Host],
    out: &mut Vec<(usize, Vec<u8>)>,
    port: usize,
    link: &wire::Link,
    payload: &[u8],
) {
    let Some(arp) = wire::parse_arp(payload) else {
        return;
    };
    for host in hosts {
        if host.ep.port != port || !host.ep.ip.is_ipv4() {
            continue;
        }
        let sender_ip = IpAddr::V4(arp.sender_ip);
        if host.ep.vlan != link.vlan {
            if arp.op == 2 && host.hops.iter().any(|(h, _)| *h == sender_ip) {
                host.arp_elsewhere = Some(link.vlan);
            }
            continue;
        }
        if host.ep.next_hop_mac.is_none() {
            for (hop, mac) in host.hops.iter_mut() {
                if *hop == sender_ip {
                    *mac = Some(arp.sender_mac);
                }
            }
        }
        if arp.op == 1 && host.ep.owns(arp.target_ip.into()) {
            out.push((
                port,
                wire::arp_frame(
                    arp.sender_mac,
                    host.ep.vlan,
                    2,
                    host.ep.mac,
                    arp.target_ip,
                    arp.sender_mac,
                    arp.sender_ip,
                ),
            ));
        }
    }
}

/// Neighbor discovery: learns next hops' MACs from their advertisements
/// and solicitations, and answers solicitations for the hosts' addresses.
pub(crate) fn on_ndp(
    hosts: &mut [Host],
    out: &mut Vec<(usize, Vec<u8>)>,
    port: usize,
    link: &wire::Link,
    ip: &wire::Ip,
    nd: &wire::Ndp,
) {
    let advert = nd.kind == wire::NDP_ADVERT;
    // Who the message tells about: the target of an advertisement, the
    // sender of a solicitation.
    let about = if advert { nd.target } else { ip.src };
    let mac = nd.lladdr.or(advert.then_some(link.src));
    for host in hosts {
        if host.ep.port != port || host.ep.ip.is_ipv4() {
            continue;
        }
        if host.ep.vlan != link.vlan {
            if advert && host.hops.iter().any(|(h, _)| *h == about) {
                host.arp_elsewhere = Some(link.vlan);
            }
            continue;
        }
        if let (None, Some(mac)) = (host.ep.next_hop_mac, mac) {
            for (hop, m) in host.hops.iter_mut() {
                if *hop == about {
                    *m = Some(mac);
                }
            }
        }
        // Duplicate address detection (from ::) is not answered: the
        // emulated addresses are not configured anywhere else.
        if !advert && host.ep.owns(nd.target) && !ip.src.is_unspecified() {
            let path = Path {
                src_mac: host.ep.mac,
                dst_mac: nd.lladdr.unwrap_or(link.src),
                vlan: host.ep.vlan,
                src: nd.target,
                dst: ip.src,
            };
            if let Some(f) = wire::ndp_advert(&path) {
                out.push((port, f));
            }
        }
    }
}

/// Asks for the MACs of next hops not known yet. Returns an error when one
/// has not answered within `timeout`.
pub(crate) fn resolve(
    hosts: &mut [Host],
    out: &mut Vec<(usize, Vec<u8>)>,
    now: Duration,
    timeout: Duration,
) -> Option<String> {
    for host in hosts {
        let pending: Vec<IpAddr> = host
            .hops
            .iter()
            .filter(|(_, mac)| mac.is_none())
            .map(|(h, _)| *h)
            .collect();
        let Some(&hop) = pending.first() else {
            continue;
        };
        let since = *host.arp_since.get_or_insert(now);
        if now.saturating_sub(since) >= timeout {
            let vlan =
                |v: Option<u16>| v.map_or("untagged".to_string(), |v| format!("on VLAN {v}"));
            let more = match pending.len() {
                1 => String::new(),
                n => format!(" (nor from {} other next hops)", n - 1),
            };
            let reply = if hop.is_ipv4() {
                "ARP reply"
            } else {
                "neighbor advertisement"
            };
            return Some(match host.arp_elsewhere {
                Some(seen) => format!(
                    "no {reply} from {hop} (the {}'s next hop) {} within {:?}{more}, but its replies \
                     arrive {}: the switch or interface changes the tag; set the {}'s VLAN to match, \
                     or use a VLAN the switch keeps tagged (VLAN 1 is often sent untagged); \
                     with AF_XDP, also check that the NIC keeps tags (ethtool -K IFACE rxvlan off)",
                    host.role,
                    vlan(host.ep.vlan),
                    timeout,
                    vlan(seen),
                    host.role
                ),
                None => format!(
                    "no {reply} from {hop} (the {}'s next hop) {} within {:?}{more}; \
                     check the gateway address, the VLAN, and that the port can receive",
                    host.role,
                    vlan(host.ep.vlan),
                    timeout
                ),
            });
        }
        if now >= host.arp_next {
            host.arp_next = now + ARP_RETRY;
            for hop in pending {
                let frame = match (host.ep.ip, hop) {
                    (IpAddr::V4(me), IpAddr::V4(hop)) => wire::arp_frame(
                        BROADCAST,
                        host.ep.vlan,
                        1,
                        host.ep.mac,
                        me,
                        MacAddr([0; 6]),
                        hop,
                    ),
                    (IpAddr::V6(me), IpAddr::V6(hop)) => {
                        wire::ndp_solicit(host.ep.mac, host.ep.vlan, me, hop)
                    }
                    _ => continue,
                };
                out.push((host.ep.port, frame));
            }
        }
    }
    None
}
