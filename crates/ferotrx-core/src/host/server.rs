//! DHCP servers of emulated hosts: DHCPv4 (RFC 2131, 2132) and DHCPv6
//! (RFC 8415, addresses in IA_NA options).
//!
//! A server is a role of a host with a static address, like the router role:
//! [`HostConfig::dhcp_server`](super::HostConfig::dhcp_server) and
//! [`HostConfig::dhcpv6_server`](super::HostConfig::dhcpv6_server). It leases
//! addresses from a pool, keeps them for the same client (by client
//! identifier, or DUID and IAID), honours reservations by MAC, and takes
//! renewals, rebinding, releases, declines and informs. Leases live in
//! memory for the run.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use super::wire as hw;
use crate::net::be16;
use crate::tcp::wire::{self, Path, BROADCAST};
use crate::{Error, MacAddr, Result};

/// Settings of a DHCPv4 server role. The host needs a static IPv4 address,
/// which is the server identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhcpServerConfig {
    /// The first and last address to lease.
    pub pool: (Ipv4Addr, Ipv4Addr),
    /// Lease time (default 1 h); renewal at half, rebinding at 7/8.
    pub lease: Duration,
    /// The router option; the host's own `gateway` if left out.
    pub router: Option<Ipv4Addr>,
    /// DNS servers (option 6).
    pub dns: Vec<Ipv4Addr>,
    /// Domain name (option 15).
    pub domain: Option<String>,
    /// Fixed addresses for these MACs, inside or outside the pool (but in
    /// the subnet).
    pub reservations: Vec<(MacAddr, Ipv4Addr)>,
    /// The subnet's prefix length given to clients; the host's own if left
    /// out.
    pub prefix: Option<u8>,
}

impl DhcpServerConfig {
    pub fn new(first: Ipv4Addr, last: Ipv4Addr) -> Self {
        Self {
            pool: (first, last),
            lease: Duration::from_secs(3600),
            router: None,
            dns: Vec::new(),
            domain: None,
            reservations: Vec::new(),
            prefix: None,
        }
    }
}

/// Settings of a DHCPv6 server role. It answers on the host's link-local
/// address; clients learn their gateway and on-link prefix from router
/// advertisements (a router role with `managed` set, or another router).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dhcpv6ServerConfig {
    /// The first and last address to lease.
    pub pool: (Ipv6Addr, Ipv6Addr),
    /// Valid and preferred lifetime (default 1 h); renewal at half,
    /// rebinding at 4/5.
    pub lease: Duration,
    /// DNS servers (option 23).
    pub dns: Vec<Ipv6Addr>,
    /// Domain search list (option 24).
    pub domain: Option<String>,
    /// Fixed addresses for these MACs (by the DUID's link-layer address or
    /// the frame's source).
    pub reservations: Vec<(MacAddr, Ipv6Addr)>,
    /// Answer a solicit that asks for it with a reply at once (RFC 8415
    /// 18.3.1; default on).
    pub rapid_commit: bool,
    /// Length of the on-link prefix of the pool, for confirm messages
    /// (default 64).
    pub prefix: u8,
}

impl Dhcpv6ServerConfig {
    pub fn new(first: Ipv6Addr, last: Ipv6Addr) -> Self {
        Self {
            pool: (first, last),
            lease: Duration::from_secs(3600),
            dns: Vec::new(),
            domain: None,
            reservations: Vec::new(),
            rapid_commit: true,
            prefix: 64,
        }
    }
}

/// What a DHCP server role did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DhcpServerCounters {
    /// Client messages taken.
    pub received: u64,
    /// Discovers (DHCPv6: solicits).
    pub discovers: u64,
    /// Offers (DHCPv6: advertises).
    pub offers: u64,
    /// Requests, renewals and rebinds (DHCPv6: requests, renews, rebinds,
    /// confirms).
    pub requests: u64,
    /// Acks with an address (DHCPv6: replies that bound one).
    pub acks: u64,
    /// Naks (DHCPv6: replies with an error status or zero lifetimes).
    pub naks: u64,
    pub releases: u64,
    pub declines: u64,
    /// Informs (DHCPv6: information requests).
    pub informs: u64,
    /// Discovers and solicits left unanswered: no free address.
    pub exhausted: u64,
}

/// A lease a DHCP server role gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhcpLease {
    pub ip: IpAddr,
    /// The client's MAC, when known.
    pub mac: Option<MacAddr>,
    /// The client identifier (DHCPv6: DUID and IAID), in hex.
    pub client: String,
    pub hostname: Option<String>,
    /// Time left.
    pub remaining: Duration,
}

/// A DHCP server role's leases and counters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DhcpServerStatus {
    /// The pool, `FIRST-LAST`.
    pub pool: String,
    pub pool_size: u64,
    /// Bound leases, by address.
    pub leases: Vec<DhcpLease>,
    pub counters: DhcpServerCounters,
}

/// How long an offered address is kept for the client that was offered it.
const OFFER_HOLD: Duration = Duration::from_secs(30);
/// How long a declined address is not leased again.
const DECLINE_HOLD: Duration = Duration::from_secs(600);

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Checks a server role's settings against its host's address.
pub(crate) fn validate4(cfg: &DhcpServerConfig, host: Option<(Ipv4Addr, u8)>) -> Result<()> {
    let Some((ip, host_prefix)) = host else {
        return Err(Error::Host(
            "a DHCP server needs a static IPv4 address (its server identifier)".into(),
        ));
    };
    let prefix = cfg.prefix.unwrap_or(host_prefix);
    if !(1..=30).contains(&prefix) {
        return Err(Error::Host(format!(
            "a DHCP server's subnet needs a prefix of /1 to /30, not /{prefix}"
        )));
    }
    let net = |a: Ipv4Addr| u32::from(a) & (u32::MAX << (32 - u32::from(prefix)));
    let (first, last) = cfg.pool;
    if u32::from(first) > u32::from(last) {
        return Err(Error::Host(format!(
            "the DHCP pool {first}-{last} ends before it starts"
        )));
    }
    for a in [first, last]
        .into_iter()
        .chain(cfg.reservations.iter().map(|r| r.1))
    {
        if net(a) != net(ip) {
            return Err(Error::Host(format!(
                "{a} is not in the DHCP server's subnet {}/{prefix}",
                Ipv4Addr::from(net(ip))
            )));
        }
    }
    if cfg.lease < Duration::from_secs(1) || cfg.lease.as_secs() >= u64::from(u32::MAX) {
        return Err(Error::Host(
            "the DHCP lease time must be from 1 s to 136 years".into(),
        ));
    }
    if cfg.domain.as_ref().is_some_and(|d| d.len() > 255) {
        return Err(Error::Host("the DHCP domain name is too long".into()));
    }
    Ok(())
}

pub(crate) fn validate6(cfg: &Dhcpv6ServerConfig) -> Result<()> {
    let (first, last) = cfg.pool;
    for a in [first, last]
        .into_iter()
        .chain(cfg.reservations.iter().map(|r| r.1))
    {
        if a.is_multicast() || a.is_unspecified() || a.is_loopback() || hw::is_link_local(a) {
            return Err(Error::Host(format!(
                "{a} is not an address a DHCPv6 server can lease"
            )));
        }
    }
    if u128::from(first) > u128::from(last) {
        return Err(Error::Host(format!(
            "the DHCPv6 pool {first}-{last} ends before it starts"
        )));
    }
    if cfg.prefix == 0 || cfg.prefix > 128 {
        return Err(Error::Host("the DHCPv6 prefix length must be 1-128".into()));
    }
    if hw::mask6(first, cfg.prefix) != hw::mask6(last, cfg.prefix) {
        return Err(Error::Host(format!(
            "the DHCPv6 pool {first}-{last} spans more than one /{} prefix",
            cfg.prefix
        )));
    }
    if cfg.lease < Duration::from_secs(1) || cfg.lease.as_secs() >= u64::from(u32::MAX) {
        return Err(Error::Host(
            "the DHCPv6 lease time must be from 1 s to 136 years".into(),
        ));
    }
    if let Some(d) = &cfg.domain {
        if dns_name(d).is_none() {
            return Err(Error::Host(format!("'{d}' is not a domain name")));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The lease table, for both versions (addresses as u128)

#[derive(Debug)]
struct Lease {
    client: Vec<u8>,
    mac: Option<MacAddr>,
    hostname: Option<String>,
    bound: bool,
    expires: Duration,
}

#[derive(Debug)]
struct Pool {
    first: u128,
    last: u128,
    cursor: u128,
    leases: BTreeMap<u128, Lease>,
    clients: HashMap<Vec<u8>, u128>,
    declined: HashMap<u128, Duration>,
    /// Addresses never leased: the server's own, the router's.
    excluded: Vec<u128>,
    reservations: Vec<(MacAddr, u128)>,
}

impl Pool {
    fn new(
        first: u128,
        last: u128,
        excluded: Vec<u128>,
        reservations: Vec<(MacAddr, u128)>,
    ) -> Self {
        Self {
            first,
            last,
            cursor: first,
            leases: BTreeMap::new(),
            clients: HashMap::new(),
            declined: HashMap::new(),
            excluded,
            reservations,
        }
    }

    fn size(&self) -> u128 {
        self.last - self.first + 1
    }

    fn in_pool(&self, a: u128) -> bool {
        (self.first..=self.last).contains(&a)
    }

    fn reserved_for(&self, mac: Option<MacAddr>) -> Option<u128> {
        let mac = mac?;
        self.reservations
            .iter()
            .find(|(m, _)| *m == mac)
            .map(|r| r.1)
    }

    /// True if `a` may be leased to `client` (at `mac`) now.
    fn usable(&self, a: u128, client: &[u8], mac: Option<MacAddr>, now: Duration) -> bool {
        if self.excluded.contains(&a) || self.declined.get(&a).is_some_and(|t| *t > now) {
            return false;
        }
        let mine = self.reserved_for(mac) == Some(a);
        if !mine && (!self.in_pool(a) || self.reservations.iter().any(|r| r.1 == a)) {
            return false;
        }
        match self.leases.get(&a) {
            None => true,
            Some(l) => l.client == client || l.expires <= now,
        }
    }

    /// The address to give `client`: its reservation, the address it had,
    /// the one it asks for, a never leased one, an expired one.
    fn pick(
        &mut self,
        client: &[u8],
        mac: Option<MacAddr>,
        hint: Option<u128>,
        now: Duration,
    ) -> Option<u128> {
        if let Some(a) = self.reserved_for(mac) {
            return self.usable(a, client, mac, now).then_some(a);
        }
        if let Some(&a) = self.clients.get(client) {
            if self.usable(a, client, mac, now) {
                return Some(a);
            }
        }
        if let Some(a) = hint.filter(|&a| self.usable(a, client, mac, now)) {
            return Some(a);
        }
        // Among any `taken + 1` consecutive addresses one was never leased.
        let taken = (self.leases.len()
            + self.declined.len()
            + self.excluded.len()
            + self.reservations.len()) as u128;
        let size = self.size();
        let mut a = self.cursor;
        for _ in 0..size.min(taken + 1) {
            if !self.leases.contains_key(&a) && self.usable(a, client, mac, now) {
                self.cursor = if a == self.last { self.first } else { a + 1 };
                return Some(a);
            }
            a = if a == self.last { self.first } else { a + 1 };
        }
        let expired = self
            .leases
            .range(self.first..=self.last)
            .find(|(&a, l)| l.expires <= now && self.usable(a, client, mac, now))
            .map(|(&a, _)| a);
        expired
    }

    fn bind(
        &mut self,
        a: u128,
        client: &[u8],
        mac: Option<MacAddr>,
        hostname: Option<String>,
        bound: bool,
        expires: Duration,
    ) {
        if let Some(old) = self.clients.insert(client.to_vec(), a) {
            if old != a && self.leases.get(&old).is_some_and(|l| l.client == client) {
                self.leases.remove(&old);
            }
        }
        if let Some(prev) = self.leases.get(&a) {
            if prev.client != client && self.clients.get(&prev.client) == Some(&a) {
                let c = prev.client.clone();
                self.clients.remove(&c);
            }
        }
        let hostname = hostname.or_else(|| {
            self.leases
                .get(&a)
                .filter(|l| l.client == client)
                .and_then(|l| l.hostname.clone())
        });
        self.leases.insert(
            a,
            Lease {
                client: client.to_vec(),
                mac,
                hostname,
                bound,
                expires,
            },
        );
    }

    /// The lease of `client` at `a`, if it has it.
    fn held(&self, a: u128, client: &[u8]) -> Option<&Lease> {
        self.leases.get(&a).filter(|l| l.client == client)
    }

    /// Ends `client`'s lease of `a` (it keeps the association, so the
    /// client gets the same address again if it is still free).
    fn release(&mut self, a: u128, client: &[u8], now: Duration) -> bool {
        match self.leases.get_mut(&a) {
            Some(l) if l.client == client => {
                l.bound = false;
                l.expires = now;
                true
            }
            _ => false,
        }
    }

    fn decline(&mut self, a: u128, client: &[u8], now: Duration) -> bool {
        if self.held(a, client).is_none() {
            return false;
        }
        self.leases.remove(&a);
        self.clients.remove(client);
        self.declined.insert(a, now + DECLINE_HOLD);
        true
    }

    fn bound(&self, now: Duration) -> impl Iterator<Item = (u128, &Lease)> {
        self.leases
            .iter()
            .filter(move |(_, l)| l.bound && l.expires > now)
            .map(|(&a, l)| (a, l))
    }
}

fn secs(d: Duration) -> u32 {
    d.as_secs().min(u64::from(u32::MAX - 1)) as u32
}

// ---------------------------------------------------------------------------
// DHCPv4

/// A client message as the server sees it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Dhcp4Request {
    pub kind: u8,
    pub htype: u8,
    pub hlen: u8,
    pub xid: u32,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 16],
    pub requested: Option<Ipv4Addr>,
    pub server: Option<Ipv4Addr>,
    pub client_id: Option<Vec<u8>>,
    pub hostname: Option<String>,
    /// Option 82, returned as it came (RFC 3046).
    pub relay_info: Option<Vec<u8>>,
}

impl Dhcp4Request {
    fn mac(&self) -> Option<MacAddr> {
        (self.htype == 1 && self.hlen == 6).then(|| {
            let c = &self.chaddr;
            MacAddr([c[0], c[1], c[2], c[3], c[4], c[5]])
        })
    }

    /// The client's key: its identifier, else hardware type and address.
    fn key(&self) -> Vec<u8> {
        self.client_id.clone().unwrap_or_else(|| {
            let mut k = vec![self.htype];
            k.extend_from_slice(&self.chaddr[..usize::from(self.hlen.min(16))]);
            k
        })
    }
}

/// Parses a DHCPv4 client message (op 1).
pub(crate) fn parse_dhcp4_request(p: &[u8]) -> Option<Dhcp4Request> {
    if p.len() < 240 || p[0] != 1 || p[236..240] != [99, 130, 83, 99] {
        return None;
    }
    let ip = |b: &[u8]| Ipv4Addr::new(b[0], b[1], b[2], b[3]);
    let mut m = Dhcp4Request {
        htype: p[1],
        hlen: p[2],
        xid: u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
        flags: u16::from_be_bytes([p[10], p[11]]),
        ciaddr: ip(&p[12..16]),
        giaddr: ip(&p[24..28]),
        kind: 0,
        chaddr: [0; 16],
        requested: None,
        server: None,
        client_id: None,
        hostname: None,
        relay_info: None,
    };
    m.chaddr.copy_from_slice(&p[28..44]);
    let mut o = &p[240..];
    while let Some(&code) = o.first() {
        match code {
            0 => {
                o = &o[1..];
                continue;
            }
            255 => break,
            _ => {}
        }
        let len = usize::from(*o.get(1)?);
        let v = o.get(2..2 + len)?;
        match (code, len) {
            (53, 1) => m.kind = v[0],
            (50, 4) => m.requested = Some(ip(v)),
            (54, 4) => m.server = Some(ip(v)),
            (61, l) if l >= 2 => m.client_id = Some(v.to_vec()),
            (12, l) if l > 0 => {
                m.hostname = Some(
                    String::from_utf8_lossy(v)
                        .trim_end_matches('\0')
                        .to_string(),
                )
            }
            (82, _) => m.relay_info = Some(v.to_vec()),
            _ => {}
        }
        o = &o[2 + len..];
    }
    (m.kind != 0).then_some(m)
}

/// The answer to a client message, before it goes in a frame.
struct Reply4 {
    kind: u8,
    yiaddr: Ipv4Addr,
    /// Lease time, for offers and acks of an address.
    lease: Option<Duration>,
}

/// The DHCPv4 server role of one host.
pub(crate) struct Server4 {
    cfg: DhcpServerConfig,
    ip: Ipv4Addr,
    mask: Ipv4Addr,
    router: Option<Ipv4Addr>,
    pool: Pool,
    pub(crate) counters: DhcpServerCounters,
}

impl Server4 {
    pub(crate) fn new(
        cfg: DhcpServerConfig,
        ip: Ipv4Addr,
        prefix: u8,
        gateway: Option<Ipv4Addr>,
    ) -> Self {
        let prefix = cfg.prefix.unwrap_or(prefix);
        let mask = Ipv4Addr::from(u32::MAX << (32 - u32::from(prefix.clamp(1, 32))));
        let router = cfg.router.or(gateway);
        let mut excluded = vec![u128::from(u32::from(ip))];
        if let Some(r) = router {
            excluded.push(u128::from(u32::from(r)));
        }
        let pool = Pool::new(
            u128::from(u32::from(cfg.pool.0)),
            u128::from(u32::from(cfg.pool.1)),
            excluded,
            cfg.reservations
                .iter()
                .map(|(m, a)| (*m, u128::from(u32::from(*a))))
                .collect(),
        );
        Self {
            cfg,
            ip,
            mask,
            router,
            pool,
            counters: DhcpServerCounters::default(),
        }
    }

    pub(crate) fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    fn same_subnet(&self, a: Ipv4Addr) -> bool {
        let m = u32::from(self.mask);
        u32::from(a) & m == u32::from(self.ip) & m
    }

    /// Answers a client message: the frame to send, if any.
    pub(crate) fn handle(
        &mut self,
        mac: MacAddr,
        vlan: Option<u16>,
        from_mac: MacAddr,
        m: &Dhcp4Request,
        now: Duration,
    ) -> Option<Vec<u8>> {
        self.counters.received += 1;
        let reply = self.answer(m, now)?;
        match reply.kind {
            hw::DHCPOFFER => self.counters.offers += 1,
            hw::DHCPACK if reply.lease.is_some() => self.counters.acks += 1,
            hw::DHCPNAK => self.counters.naks += 1,
            _ => {}
        }
        Some(self.frame(mac, vlan, from_mac, m, &reply))
    }

    fn answer(&mut self, m: &Dhcp4Request, now: Duration) -> Option<Reply4> {
        let key = m.key();
        let cmac = m.mac();
        let a32 = |a: Ipv4Addr| u128::from(u32::from(a));
        let lease = self.cfg.lease;
        let ack = |a: u128| Reply4 {
            kind: hw::DHCPACK,
            yiaddr: Ipv4Addr::from(a as u32),
            lease: Some(lease),
        };
        let nak = Reply4 {
            kind: hw::DHCPNAK,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            lease: None,
        };
        match m.kind {
            hw::DHCPDISCOVER => {
                self.counters.discovers += 1;
                let Some(a) = self.pool.pick(&key, cmac, m.requested.map(a32), now) else {
                    self.counters.exhausted += 1;
                    return None;
                };
                let live = self
                    .pool
                    .held(a, &key)
                    .is_some_and(|l| l.bound && l.expires > now);
                if !live {
                    self.pool.bind(
                        a,
                        &key,
                        cmac,
                        m.hostname.clone(),
                        false,
                        now + OFFER_HOLD.min(lease),
                    );
                }
                Some(Reply4 {
                    kind: hw::DHCPOFFER,
                    yiaddr: Ipv4Addr::from(a as u32),
                    lease: Some(lease),
                })
            }
            hw::DHCPREQUEST => {
                self.counters.requests += 1;
                if let Some(server) = m.server {
                    // Selecting: an answer to an offer.
                    let wanted = m
                        .requested
                        .or((!m.ciaddr.is_unspecified()).then_some(m.ciaddr));
                    if server != self.ip {
                        // The client took another server's offer.
                        if let Some(&a) = self.pool.clients.get(&key) {
                            if self.pool.held(a, &key).is_some_and(|l| !l.bound) {
                                self.pool.release(a, &key, now);
                            }
                        }
                        return None;
                    }
                    let a = a32(wanted?);
                    let offered = self.pool.held(a, &key).is_some_and(|l| l.expires > now);
                    if offered || self.pool.usable(a, &key, cmac, now) {
                        self.pool
                            .bind(a, &key, cmac, m.hostname.clone(), true, now + lease);
                        return Some(ack(a));
                    }
                    return Some(nak);
                }
                // Init-reboot (requested address), renewing or rebinding (ciaddr).
                let wanted = m
                    .requested
                    .or((!m.ciaddr.is_unspecified()).then_some(m.ciaddr))?;
                let a = a32(wanted);
                if !self.same_subnet(wanted) && m.giaddr.is_unspecified() {
                    return Some(nak);
                }
                if self.pool.usable(a, &key, cmac, now) {
                    self.pool
                        .bind(a, &key, cmac, m.hostname.clone(), true, now + lease);
                    Some(ack(a))
                } else {
                    Some(nak)
                }
            }
            hw::DHCPDECLINE => {
                if let Some(a) = m.requested {
                    if self.pool.decline(a32(a), &key, now) {
                        self.counters.declines += 1;
                    }
                }
                None
            }
            hw::DHCPRELEASE => {
                if m.server.is_none_or(|s| s == self.ip)
                    && self.pool.release(a32(m.ciaddr), &key, now)
                {
                    self.counters.releases += 1;
                }
                None
            }
            DHCPINFORM => {
                self.counters.informs += 1;
                if m.ciaddr.is_unspecified() {
                    return None;
                }
                Some(Reply4 {
                    kind: hw::DHCPACK,
                    yiaddr: Ipv4Addr::UNSPECIFIED,
                    lease: None,
                })
            }
            _ => None,
        }
    }

    fn frame(
        &self,
        mac: MacAddr,
        vlan: Option<u16>,
        from_mac: MacAddr,
        m: &Dhcp4Request,
        r: &Reply4,
    ) -> Vec<u8> {
        let mut p = Vec::with_capacity(300);
        p.extend_from_slice(&[2, m.htype, m.hlen, 0]);
        p.extend_from_slice(&m.xid.to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(&m.flags.to_be_bytes());
        // ciaddr is returned in acks of renewals and informs.
        let ciaddr = if r.kind == hw::DHCPNAK || r.kind == hw::DHCPOFFER {
            Ipv4Addr::UNSPECIFIED
        } else {
            m.ciaddr
        };
        p.extend_from_slice(&ciaddr.octets());
        p.extend_from_slice(&r.yiaddr.octets());
        p.extend_from_slice(&[0; 4]); // siaddr: no boot server
        p.extend_from_slice(&m.giaddr.octets());
        p.extend_from_slice(&m.chaddr);
        p.extend_from_slice(&[0; 64 + 128]);
        p.extend_from_slice(&[99, 130, 83, 99, 53, 1, r.kind, 54, 4]);
        p.extend_from_slice(&self.ip.octets());
        if r.kind != hw::DHCPNAK {
            if let Some(l) = r.lease {
                let l = secs(l);
                for (code, v) in [(51u8, l), (58, l / 2), (59, (u64::from(l) * 7 / 8) as u32)] {
                    p.extend_from_slice(&[code, 4]);
                    p.extend_from_slice(&v.to_be_bytes());
                }
            }
            p.extend_from_slice(&[1, 4]);
            p.extend_from_slice(&self.mask.octets());
            if let Some(rt) = self.router {
                p.extend_from_slice(&[3, 4]);
                p.extend_from_slice(&rt.octets());
            }
            if !self.cfg.dns.is_empty() {
                let n = self.cfg.dns.len().min(63);
                p.extend_from_slice(&[6, (n * 4) as u8]);
                for d in &self.cfg.dns[..n] {
                    p.extend_from_slice(&d.octets());
                }
            }
            if let Some(d) = self.cfg.domain.as_deref().filter(|d| !d.is_empty()) {
                let d = &d.as_bytes()[..d.len().min(255)];
                p.extend_from_slice(&[15, d.len() as u8]);
                p.extend_from_slice(d);
            }
        }
        if let Some(info) = &m.relay_info {
            p.extend_from_slice(&[82, info.len() as u8]);
            p.extend_from_slice(info);
        }
        p.push(255);
        if p.len() < 300 {
            p.resize(300, 0);
        }
        // Where the answer goes (RFC 2131 4.1).
        let (dst, dst_mac, dport) = if !m.giaddr.is_unspecified() {
            (m.giaddr, from_mac, hw::DHCP_SERVER_PORT)
        } else if r.kind == hw::DHCPNAK {
            (Ipv4Addr::BROADCAST, BROADCAST, hw::DHCP_CLIENT_PORT)
        } else if !m.ciaddr.is_unspecified() {
            (m.ciaddr, from_mac, hw::DHCP_CLIENT_PORT)
        } else if m.flags & 0x8000 != 0 || m.mac().is_none() {
            (Ipv4Addr::BROADCAST, BROADCAST, hw::DHCP_CLIENT_PORT)
        } else {
            (r.yiaddr, m.mac().unwrap_or(from_mac), hw::DHCP_CLIENT_PORT)
        };
        let path = Path {
            src_mac: mac,
            dst_mac,
            vlan,
            src: self.ip.into(),
            dst: dst.into(),
        };
        wire::udp_frame(&path, hw::DHCP_SERVER_PORT, dport, &p, 0)
    }

    pub(crate) fn status(&self, now: Duration) -> DhcpServerStatus {
        DhcpServerStatus {
            pool: format!("{}-{}", self.cfg.pool.0, self.cfg.pool.1),
            pool_size: self.pool.size() as u64,
            leases: self
                .pool
                .bound(now)
                .map(|(a, l)| DhcpLease {
                    ip: IpAddr::V4(Ipv4Addr::from(a as u32)),
                    mac: l.mac,
                    client: hex(&l.client),
                    hostname: l.hostname.clone(),
                    remaining: l.expires.saturating_sub(now),
                })
                .collect(),
            counters: self.counters.clone(),
        }
    }
}

const DHCPINFORM: u8 = 8;

// ---------------------------------------------------------------------------
// DHCPv6

const OPT_CLIENTID: u16 = 1;
const OPT_SERVERID: u16 = 2;
const OPT_IA_NA: u16 = 3;
const OPT_IAADDR: u16 = 5;
const OPT_STATUS: u16 = 13;
const OPT_RAPID_COMMIT: u16 = 14;
const OPT_DNS: u16 = 23;
const OPT_DOMAIN_LIST: u16 = 24;

const CONFIRM: u8 = 4;
const DECLINE: u8 = 9;
const INFORMATION_REQUEST: u8 = 11;

const STATUS_SUCCESS: u16 = 0;
const STATUS_NO_ADDRS: u16 = 2;
const STATUS_NO_BINDING: u16 = 3;
const STATUS_NOT_ON_LINK: u16 = 4;

/// An IA_NA of a client message.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct IaNa {
    pub iaid: u32,
    pub addresses: Vec<Ipv6Addr>,
}

/// A DHCPv6 client message.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Dhcp6Request {
    pub kind: u8,
    pub xid: u32,
    pub client_id: Option<Vec<u8>>,
    pub server_id: Option<Vec<u8>>,
    pub ias: Vec<IaNa>,
    pub rapid_commit: bool,
}

fn options6(mut o: &[u8], mut each: impl FnMut(u16, &[u8])) -> Option<()> {
    while !o.is_empty() {
        let code = be16(o, 0)?;
        let len = usize::from(be16(o, 2)?);
        let v = o.get(4..4 + len)?;
        each(code, v);
        o = &o[4 + len..];
    }
    Some(())
}

fn addr6(b: &[u8]) -> Ipv6Addr {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[..16]);
    Ipv6Addr::from(a)
}

pub(crate) fn parse_dhcp6_request(p: &[u8]) -> Option<Dhcp6Request> {
    let kind = *p.first()?;
    if p.len() < 4
        || !matches!(
            kind,
            hw::DHCP6_SOLICIT
                | hw::DHCP6_REQUEST
                | CONFIRM
                | hw::DHCP6_RENEW
                | hw::DHCP6_REBIND
                | hw::DHCP6_RELEASE
                | DECLINE
                | INFORMATION_REQUEST
        )
    {
        return None;
    }
    let mut m = Dhcp6Request {
        kind,
        xid: u32::from_be_bytes([0, p[1], p[2], p[3]]),
        ..Default::default()
    };
    let mut ok = true;
    options6(&p[4..], |code, v| match code {
        OPT_CLIENTID => m.client_id = Some(v.to_vec()),
        OPT_SERVERID => m.server_id = Some(v.to_vec()),
        OPT_RAPID_COMMIT => m.rapid_commit = true,
        OPT_IA_NA if v.len() >= 12 => {
            let mut ia = IaNa {
                iaid: u32::from_be_bytes([v[0], v[1], v[2], v[3]]),
                addresses: Vec::new(),
            };
            ok &= options6(&v[12..], |code, v| {
                if code == OPT_IAADDR && v.len() >= 24 {
                    ia.addresses.push(addr6(v));
                }
            })
            .is_some();
            m.ias.push(ia);
        }
        _ => {}
    })?;
    ok.then_some(m)
}

/// A domain name in DNS wire format, if it is one.
fn dns_name(name: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    (out.len() <= 255).then_some(out)
}

fn opt6(p: &mut Vec<u8>, code: u16, value: &[u8]) {
    p.extend_from_slice(&code.to_be_bytes());
    p.extend_from_slice(&(value.len() as u16).to_be_bytes());
    p.extend_from_slice(value);
}

fn status_opt(code: u16, text: &str) -> Vec<u8> {
    let mut v = code.to_be_bytes().to_vec();
    v.extend_from_slice(text.as_bytes());
    v
}

/// An IA_NA in an answer: its addresses with lifetimes, or a status.
struct IaOut {
    iaid: u32,
    t1: u32,
    t2: u32,
    addresses: Vec<(Ipv6Addr, u32, u32)>,
    status: Option<u16>,
}

/// The DHCPv6 server role of one host.
pub(crate) struct Server6 {
    cfg: Dhcpv6ServerConfig,
    duid: Vec<u8>,
    pool: Pool,
    pub(crate) counters: DhcpServerCounters,
}

impl Server6 {
    pub(crate) fn new(cfg: Dhcpv6ServerConfig, mac: MacAddr, own: Option<Ipv6Addr>) -> Self {
        let pool = Pool::new(
            u128::from(cfg.pool.0),
            u128::from(cfg.pool.1),
            own.map(u128::from).into_iter().collect(),
            cfg.reservations
                .iter()
                .map(|(m, a)| (*m, u128::from(*a)))
                .collect(),
        );
        Self {
            cfg,
            duid: hw::duid(mac),
            pool,
            counters: DhcpServerCounters::default(),
        }
    }

    /// Answers a client message from `src` (at `from_mac`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle(
        &mut self,
        mac: MacAddr,
        vlan: Option<u16>,
        ll: Ipv6Addr,
        from_mac: MacAddr,
        src: Ipv6Addr,
        m: &Dhcp6Request,
        now: Duration,
    ) -> Option<Vec<u8>> {
        // Messages for another server are not ours to count.
        if m.server_id.as_ref().is_some_and(|s| *s != self.duid) {
            return None;
        }
        self.counters.received += 1;
        let body = self.answer(m, from_mac, now)?;
        let path = Path {
            src_mac: mac,
            dst_mac: from_mac,
            vlan,
            src: ll.into(),
            dst: src.into(),
        };
        Some(wire::udp_frame(
            &path,
            hw::DHCP6_SERVER_PORT,
            hw::DHCP6_CLIENT_PORT,
            &body,
            0,
        ))
    }

    /// The client's MAC: from a link-layer DUID (types 1 and 3, Ethernet),
    /// else the frame's source.
    fn client_mac(duid: &[u8], from_mac: MacAddr) -> MacAddr {
        let ll = match duid {
            [0, 1, 0, 1, rest @ ..] if rest.len() == 10 => Some(&rest[4..]),
            [0, 3, 0, 1, rest @ ..] if rest.len() == 6 => Some(rest),
            _ => None,
        };
        ll.map_or(from_mac, |b| MacAddr([b[0], b[1], b[2], b[3], b[4], b[5]]))
    }

    fn lifetimes(&self) -> (u32, u32, u32, u32) {
        let l = secs(self.cfg.lease);
        (l / 2, (u64::from(l) * 4 / 5) as u32, l, l)
    }

    fn answer(&mut self, m: &Dhcp6Request, from_mac: MacAddr, now: Duration) -> Option<Vec<u8>> {
        let (t1, t2, preferred, valid) = self.lifetimes();
        let lease = self.cfg.lease;
        let mut kind = hw::DHCP6_REPLY;
        let mut ias = Vec::new();
        let mut status: Option<(u16, &str)> = None;
        let mut rapid = false;
        if m.kind == INFORMATION_REQUEST {
            self.counters.informs += 1;
            return Some(self.message(kind, m, &ias, None, false));
        }
        let client = m.client_id.clone()?;
        let mac = Self::client_mac(&client, from_mac);
        let key = |iaid: u32| {
            let mut k = client.clone();
            k.extend_from_slice(&iaid.to_be_bytes());
            k
        };
        let in_pool = |a: Ipv6Addr| u128::from(a);
        match m.kind {
            hw::DHCP6_SOLICIT | hw::DHCP6_REQUEST => {
                let solicit = m.kind == hw::DHCP6_SOLICIT;
                if solicit {
                    self.counters.discovers += 1;
                    if m.server_id.is_some() {
                        return None;
                    }
                    rapid = m.rapid_commit && self.cfg.rapid_commit;
                    if !rapid {
                        kind = hw::DHCP6_ADVERTISE;
                    }
                } else {
                    self.counters.requests += 1;
                    m.server_id.as_ref()?;
                }
                let commit = !solicit || rapid;
                for ia in &m.ias {
                    let k = key(ia.iaid);
                    let hint = ia.addresses.first().map(|a| in_pool(*a));
                    match self.pool.pick(&k, Some(mac), hint, now) {
                        Some(a) => {
                            let live = self
                                .pool
                                .held(a, &k)
                                .is_some_and(|l| l.bound && l.expires > now);
                            if commit {
                                self.pool.bind(a, &k, Some(mac), None, true, now + lease);
                            } else if !live {
                                self.pool.bind(
                                    a,
                                    &k,
                                    Some(mac),
                                    None,
                                    false,
                                    now + OFFER_HOLD.min(lease),
                                );
                            }
                            ias.push(IaOut {
                                iaid: ia.iaid,
                                t1,
                                t2,
                                addresses: vec![(Ipv6Addr::from(a), preferred, valid)],
                                status: None,
                            });
                        }
                        None => ias.push(IaOut {
                            iaid: ia.iaid,
                            t1: 0,
                            t2: 0,
                            addresses: Vec::new(),
                            status: Some(STATUS_NO_ADDRS),
                        }),
                    }
                }
                let granted = ias.iter().any(|ia| !ia.addresses.is_empty());
                if !granted {
                    if solicit {
                        self.counters.exhausted += 1;
                    }
                    status = Some((STATUS_NO_ADDRS, "no addresses available"));
                    // An advertise without addresses carries only the status.
                    if solicit {
                        ias.clear();
                    }
                }
                if solicit && !rapid {
                    self.counters.offers += 1;
                } else if granted {
                    self.counters.acks += 1;
                } else {
                    self.counters.naks += 1;
                }
            }
            hw::DHCP6_RENEW | hw::DHCP6_REBIND => {
                self.counters.requests += 1;
                if m.kind == hw::DHCP6_RENEW {
                    m.server_id.as_ref()?;
                }
                let mut granted = false;
                let mut refused = false;
                for ia in &m.ias {
                    let k = key(ia.iaid);
                    let mut out = IaOut {
                        iaid: ia.iaid,
                        t1,
                        t2,
                        addresses: Vec::new(),
                        status: None,
                    };
                    for &a in &ia.addresses {
                        let x = in_pool(a);
                        if self.pool.usable(x, &k, Some(mac), now) {
                            self.pool.bind(x, &k, Some(mac), None, true, now + lease);
                            out.addresses.push((a, preferred, valid));
                            granted = true;
                        } else {
                            // Not for this client (any more): stop using it.
                            out.addresses.push((a, 0, 0));
                            refused = true;
                        }
                    }
                    if ia.addresses.is_empty() {
                        if let Some(a) = self.pool.pick(&k, Some(mac), None, now) {
                            self.pool.bind(a, &k, Some(mac), None, true, now + lease);
                            out.addresses.push((Ipv6Addr::from(a), preferred, valid));
                            granted = true;
                        } else {
                            out.status = Some(STATUS_NO_BINDING);
                            refused = true;
                        }
                    }
                    ias.push(out);
                }
                if refused || !granted {
                    self.counters.naks += 1;
                }
                if granted {
                    self.counters.acks += 1;
                }
            }
            hw::DHCP6_RELEASE | DECLINE => {
                m.server_id.as_ref()?;
                for ia in &m.ias {
                    let k = key(ia.iaid);
                    for &a in &ia.addresses {
                        let x = in_pool(a);
                        if m.kind == DECLINE {
                            if self.pool.decline(x, &k, now) {
                                self.counters.declines += 1;
                            }
                        } else if self.pool.release(x, &k, now) {
                            self.counters.releases += 1;
                        }
                    }
                }
                status = Some((STATUS_SUCCESS, "done"));
            }
            CONFIRM => {
                self.counters.requests += 1;
                let addrs: Vec<Ipv6Addr> =
                    m.ias.iter().flat_map(|ia| ia.addresses.clone()).collect();
                if addrs.is_empty() {
                    return None;
                }
                let net = hw::mask6(self.cfg.pool.0, self.cfg.prefix);
                status = if addrs.iter().all(|a| hw::mask6(*a, self.cfg.prefix) == net) {
                    Some((STATUS_SUCCESS, "on link"))
                } else {
                    self.counters.naks += 1;
                    Some((STATUS_NOT_ON_LINK, "not on link"))
                };
            }
            _ => return None,
        }
        Some(self.message(kind, m, &ias, status, rapid))
    }

    fn message(
        &self,
        kind: u8,
        m: &Dhcp6Request,
        ias: &[IaOut],
        status: Option<(u16, &str)>,
        rapid: bool,
    ) -> Vec<u8> {
        let mut p = Vec::with_capacity(128);
        p.push(kind);
        p.extend_from_slice(&m.xid.to_be_bytes()[1..]);
        if let Some(c) = &m.client_id {
            opt6(&mut p, OPT_CLIENTID, c);
        }
        opt6(&mut p, OPT_SERVERID, &self.duid);
        for ia in ias {
            let mut v = Vec::with_capacity(48);
            v.extend_from_slice(&ia.iaid.to_be_bytes());
            v.extend_from_slice(&ia.t1.to_be_bytes());
            v.extend_from_slice(&ia.t2.to_be_bytes());
            for (a, pref, valid) in &ia.addresses {
                let mut x = a.octets().to_vec();
                x.extend_from_slice(&pref.to_be_bytes());
                x.extend_from_slice(&valid.to_be_bytes());
                opt6(&mut v, OPT_IAADDR, &x);
            }
            if let Some(s) = ia.status {
                let text = match s {
                    STATUS_NO_ADDRS => "no addresses available",
                    STATUS_NO_BINDING => "no binding",
                    _ => "",
                };
                opt6(&mut v, OPT_STATUS, &status_opt(s, text));
            }
            opt6(&mut p, OPT_IA_NA, &v);
        }
        if let Some((code, text)) = status {
            opt6(&mut p, OPT_STATUS, &status_opt(code, text));
        }
        if rapid {
            opt6(&mut p, OPT_RAPID_COMMIT, &[]);
        }
        let config = !matches!(m.kind, hw::DHCP6_RELEASE | DECLINE | CONFIRM);
        if config && !self.cfg.dns.is_empty() {
            let v: Vec<u8> = self.cfg.dns.iter().flat_map(|d| d.octets()).collect();
            opt6(&mut p, OPT_DNS, &v);
        }
        if let Some(d) = self
            .cfg
            .domain
            .as_deref()
            .filter(|_| config)
            .and_then(dns_name)
        {
            opt6(&mut p, OPT_DOMAIN_LIST, &d);
        }
        p
    }

    pub(crate) fn status(&self, now: Duration) -> DhcpServerStatus {
        DhcpServerStatus {
            pool: format!("{}-{}", self.cfg.pool.0, self.cfg.pool.1),
            pool_size: self.pool.size().min(u128::from(u64::MAX)) as u64,
            leases: self
                .pool
                .bound(now)
                .map(|(a, l)| DhcpLease {
                    ip: IpAddr::V6(Ipv6Addr::from(a)),
                    mac: l.mac,
                    client: hex(&l.client),
                    hostname: l.hostname.clone(),
                    remaining: l.expires.saturating_sub(now),
                })
                .collect(),
            counters: self.counters.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> MacAddr {
        MacAddr([2, 0xdc, 0, 0, 0, n])
    }

    #[test]
    fn the_pool_keeps_addresses_per_client_and_reuses_expired_ones() {
        let mut p = Pool::new(10, 12, vec![11], vec![(mac(9), 20)]);
        let s = Duration::from_secs;
        let a = p.pick(b"a", Some(mac(1)), None, s(0)).unwrap();
        assert_eq!(a, 10);
        p.bind(a, b"a", Some(mac(1)), None, true, s(10));
        // 11 is the server's own.
        let b = p.pick(b"b", Some(mac(2)), None, s(0)).unwrap();
        assert_eq!(b, 12);
        p.bind(b, b"b", Some(mac(2)), None, true, s(10));
        assert_eq!(p.pick(b"c", Some(mac(3)), None, s(5)), None);
        // The reservation, outside the pool.
        assert_eq!(p.pick(b"r", Some(mac(9)), None, s(5)), Some(20));
        // Nobody else gets a reserved address.
        assert!(!p.usable(20, b"c", Some(mac(3)), s(5)));
        // The same client gets the same address again.
        assert_eq!(p.pick(b"a", Some(mac(1)), Some(12), s(5)), Some(10));
        // After the leases run out, a new client takes one.
        assert_eq!(p.pick(b"c", Some(mac(3)), None, s(11)), Some(10));
        p.bind(10, b"c", Some(mac(3)), None, true, s(30));
        assert!(!p.clients.contains_key(&b"a"[..]));
        // A declined address is not leased for a while.
        assert!(p.decline(10, b"c", s(12)));
        assert_eq!(p.pick(b"d", Some(mac(4)), Some(10), s(12)), Some(12));
        assert!(p.release(12, b"b", s(12)));
        assert!(!p.release(12, b"x", s(12)));
    }

    #[test]
    fn domain_names_in_wire_format() {
        assert_eq!(dns_name("lab.test").unwrap(), b"\x03lab\x04test\x00");
        assert!(dns_name("a..b").is_none());
    }
}
