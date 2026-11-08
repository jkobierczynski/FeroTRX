//! Splitting a stateful TCP or UDP run over several workers, and sending
//! each received frame to the worker it belongs to.
//!
//! Every worker runs an engine of its own with the same emulated client and
//! server hosts (same MAC and IP addresses). The client's source ports are
//! cut into one slice per worker, and so are its rates and limits; servers
//! are the same in every worker. A frame that arrives then belongs to:
//!
//! * the worker whose slice holds its destination port, if it goes to a
//!   client address: an answer to a connection that worker opened;
//! * the worker a hash of its addresses and ports picks, otherwise: a server
//!   accepts the connections the hash gives it, and every later frame of the
//!   connection hashes the same way;
//! * worker 0, for ARP requests, neighbor solicitations, pings and anything
//!   else that is not TCP or UDP, so each host answers once;
//! * every worker, for ARP replies, neighbor and router advertisements,
//!   multicast listener and IGMP queries, and broadcast or multicast
//!   datagrams, since each engine looks up its next hops by itself.
//!
//! Because the client and the server half of a connection can sit in
//! different workers, the slices also hold through NAT: the router changes
//! the client's port on the way out and puts it back on the way in.

use std::net::IpAddr;
use std::ops::Range;

use crate::net::{self, be16, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP};
use crate::tcp::engine::{ip_offset, TcpEndpoint};
use crate::{
    share, worker_seed, Error, MergeStats, Result, TcpConfig, TcpSideStats, TcpStats,
    TcpTemplateStats, TrafficModel, UdpConfig, UdpSideStats, UdpStats, UdpTemplateStats,
};

const ETHERTYPE_ARP: u16 = 0x0806;
const IPPROTO_IGMP: u8 = 2;

/// Where a received frame goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// To this worker only.
    Worker(usize),
    /// To every worker.
    All,
}

/// A client host whose source ports are split over the workers.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ClientPorts {
    ip: IpAddr,
    count: u32,
    ports: Range<u16>,
}

/// Says which worker of a split stateful run a received frame belongs to;
/// see the [module docs](self) for the rules. Made by
/// [`TcpConfig::split`] and [`UdpConfig::split`].
///
/// ```
/// use ferotrx_core::*;
///
/// let router = FlowRouter::new(4).with_client("10.0.0.1".parse().unwrap(), 1, 1024..2048);
/// assert_eq!(router.workers(), 4);
/// assert_eq!(router.slice(1024..2048, 1), 1280..1536);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowRouter {
    workers: usize,
    clients: Vec<ClientPorts>,
}

impl FlowRouter {
    /// A router for `workers` workers, with no client hosts yet.
    pub fn new(workers: usize) -> Self {
        Self {
            workers: workers.max(1),
            clients: Vec::new(),
        }
    }

    /// Adds a client host with `count` addresses from `ip` whose source ports
    /// `ports` are cut into one slice per worker ([`slice`](Self::slice)).
    pub fn with_client(mut self, ip: IpAddr, count: u32, ports: Range<u16>) -> Self {
        self.clients.push(ClientPorts { ip, count, ports });
        self
    }

    pub fn workers(&self) -> usize {
        self.workers
    }

    /// Worker `k`'s slice of `ports`: as even as can be, in order.
    pub fn slice(&self, ports: Range<u16>, k: usize) -> Range<u16> {
        slice(ports, k, self.workers)
    }

    /// Which worker `frame` belongs to.
    pub fn route(&self, frame: &[u8]) -> Route {
        if self.workers == 1 {
            return Route::Worker(0);
        }
        let group = frame.first().is_some_and(|b| b & 1 != 0);
        let Some((off, ethertype)) = net::l3_offset(frame) else {
            return Route::Worker(0);
        };
        if ethertype == ETHERTYPE_ARP {
            // Requests are answered once; replies feed every worker's cache.
            return match be16(frame, off + 6) {
                Some(2) => Route::All,
                _ => Route::Worker(0),
            };
        }
        let Some(ip) = net::parse(frame).and_then(|l| l.ip) else {
            return if group { Route::All } else { Route::Worker(0) };
        };
        if ip.fragmented {
            return Route::Worker(0);
        }
        match ip.l4 {
            Some((IPPROTO_TCP | IPPROTO_UDP, at)) if at + 4 <= frame.len() => {
                let dport = be16(frame, at + 2).unwrap_or(0);
                if let Some(dst) = addr(&frame[ip.dst.clone()]) {
                    if let Some(k) = self.client_worker(dst, dport) {
                        return Route::Worker(k);
                    }
                }
                if group {
                    return Route::All;
                }
                let mut h = Fnv::default();
                h.write(&frame[ip.src.clone()]);
                h.write(&frame[ip.dst.clone()]);
                h.write(&frame[at..at + 4]);
                h.write(&[ip.l4.map_or(0, |l| l.0)]);
                Route::Worker((h.finish() % self.workers as u64) as usize)
            }
            Some((IPPROTO_ICMPV6, at)) if ip.version == 6 => match frame.get(at) {
                // Neighbor solicitations: answered once.
                Some(135) => Route::Worker(0),
                // Router advertisements, neighbor advertisements, multicast
                // listener queries and reports.
                Some(130..=132 | 134 | 136 | 143) => Route::All,
                _ => Route::Worker(0),
            },
            Some((IPPROTO_IGMP, _)) if ip.version == 4 => Route::All,
            _ if group => Route::All,
            _ => Route::Worker(0),
        }
    }

    fn client_worker(&self, dst: IpAddr, port: u16) -> Option<usize> {
        let c = self.clients.iter().find(|c| {
            c.ports.contains(&port) && ip_offset(c.ip, dst).is_some_and(|d| d < u128::from(c.count))
        })?;
        Some(slice_of(c.ports.clone(), port, self.workers))
    }
}

/// Worker `k` of `n`'s slice of `ports`.
fn slice(ports: Range<u16>, k: usize, n: usize) -> Range<u16> {
    let len = u64::from(ports.end.saturating_sub(ports.start));
    let at = |k: usize| ports.start + (len * k as u64 / n.max(1) as u64) as u16;
    at(k)..at(k + 1)
}

/// The worker whose slice of `ports` holds `port`.
fn slice_of(ports: Range<u16>, port: u16, n: usize) -> usize {
    let len = u64::from(ports.end - ports.start).max(1);
    let mut k = (u64::from(port - ports.start) * n as u64 / len) as usize;
    k = k.min(n - 1);
    while k > 0 && slice(ports.clone(), k, n).start > port {
        k -= 1;
    }
    while k + 1 < n && slice(ports.clone(), k, n).end <= port {
        k += 1;
    }
    k
}

fn addr(b: &[u8]) -> Option<IpAddr> {
    match b.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(b).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(b).ok()?)),
        _ => None,
    }
}

/// FNV-1a: quick, and the same everywhere, so a flow always hashes alike.
struct Fnv(u64);

impl Default for Fnv {
    fn default() -> Self {
        Fnv(0xcbf2_9ce4_8422_2325)
    }
}

impl Fnv {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0 ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    fn finish(&self) -> u64 {
        // Fold the high bits in, for small worker counts.
        self.0 ^ (self.0 >> 32)
    }
}

fn split_err(kind: &str, msg: String) -> Error {
    let msg = format!("cannot split the run over workers: {msg}");
    if kind == "udp" {
        Error::Udp(msg)
    } else {
        Error::Tcp(msg)
    }
}

/// Worker `k`'s share of a limit where 0 means none; fails if some worker
/// would get 0 (which would mean no limit).
fn limit_share(kind: &str, what: &str, total: u64, k: usize, n: usize) -> Result<u64> {
    if total > 0 && total < n as u64 {
        return Err(split_err(
            kind,
            format!("{what} ({total}) is less than the number of workers ({n})"),
        ));
    }
    Ok(share(total, k, n))
}

fn model_for(model: &TrafficModel, k: usize) -> TrafficModel {
    let mut m = model.clone();
    m.seed = m.seed.map(|s| worker_seed(s, k));
    m
}

/// Checks that client ports and server ports cannot be mixed up.
fn check_ports(
    kind: &str,
    client: &TcpEndpoint,
    ports: &Range<u16>,
    server: Option<&TcpEndpoint>,
    listen: impl Iterator<Item = u16>,
    n: usize,
) -> Result<()> {
    if (ports.end.saturating_sub(ports.start) as usize) < n {
        return Err(split_err(
            kind,
            format!(
                "the client's source ports {}-{} are fewer than the workers ({n})",
                ports.start,
                ports.end.saturating_sub(1)
            ),
        ));
    }
    if let Some(server) = server {
        let shared = (0..client.ip_count).any(|i| server.owns(client.nth_ip(i)));
        if shared {
            if let Some(p) = listen.into_iter().find(|p| ports.contains(p)) {
                return Err(split_err(
                    kind,
                    format!(
                        "the server listens on port {p}, inside the client's source ports, \
                         on the same address"
                    ),
                ));
            }
        }
    }
    Ok(())
}

impl TcpConfig {
    /// Splits the run over `workers` engines: each gets a slice of the
    /// client's source ports, its share of the connection rate, of
    /// `connections` and of `concurrency` (top level and per template), and
    /// a seed of its own; servers are the same in all. The router says which
    /// engine each received frame belongs to.
    ///
    /// Fails if a limit is smaller than the number of workers, or the source
    /// ports are fewer.
    pub fn split(&self, workers: usize) -> Result<(Vec<TcpConfig>, FlowRouter)> {
        let n = workers.max(1);
        let mut router = FlowRouter::new(n);
        if n == 1 {
            return Ok((vec![self.clone()], router));
        }
        if let Some(c) = &self.client {
            check_ports(
                "tcp",
                &c.endpoint,
                &c.source_ports,
                self.server.as_ref().map(|s| &s.endpoint),
                self.templates.iter().map(|t| t.listen_port),
                n,
            )?;
            router = router.with_client(c.endpoint.ip, c.endpoint.ip_count, c.source_ports.clone());
        }
        let mut out = Vec::with_capacity(n);
        for k in 0..n {
            let mut cfg = self.clone();
            if let Some(c) = &mut cfg.client {
                c.cps /= n as f64;
                c.model = model_for(&c.model, k);
                c.connections = limit_share("tcp", "connections", c.connections, k, n)?;
                c.concurrency =
                    limit_share("tcp", "concurrency", c.concurrency as u64, k, n)? as usize;
                c.source_ports = slice(c.source_ports.clone(), k, n);
            }
            for t in &mut cfg.templates {
                let what = |w: &str| format!("template '{}': {w}", t.name);
                t.cps = t.cps.map(|r| r / n as f64);
                t.model = model_for(&t.model, k);
                t.connections = limit_share("tcp", &what("connections"), t.connections, k, n)?;
                t.concurrency =
                    limit_share("tcp", &what("concurrency"), t.concurrency as u64, k, n)? as usize;
            }
            cfg.options.seed = worker_seed(self.options.seed, k);
            out.push(cfg);
        }
        Ok((out, router))
    }
}

impl UdpConfig {
    /// Splits the run over `workers` engines, as [`TcpConfig::split`] does:
    /// source ports, rates, `transactions` and `concurrency` are shared out.
    pub fn split(&self, workers: usize) -> Result<(Vec<UdpConfig>, FlowRouter)> {
        let n = workers.max(1);
        let mut router = FlowRouter::new(n);
        if n == 1 {
            return Ok((vec![self.clone()], router));
        }
        if let Some(t) = self.templates.iter().find(|t| match &t.app {
            crate::UdpApp::App(a) => a.protocol().media_ports() > 0,
            crate::UdpApp::Replay(_) => false,
        }) {
            return Err(crate::Error::Udp(format!(
                "template {}: {} carries media on ports of its own, which cannot be split over several workers yet; use workers = 1",
                t.name,
                t.app.kind()
            )));
        }
        if let Some(c) = &self.client {
            check_ports(
                "udp",
                &c.endpoint,
                &c.source_ports,
                self.server.as_ref().map(|s| &s.endpoint),
                self.templates.iter().map(|t| t.listen_port),
                n,
            )?;
            router = router.with_client(c.endpoint.ip, c.endpoint.ip_count, c.source_ports.clone());
        }
        let mut out = Vec::with_capacity(n);
        for k in 0..n {
            let mut cfg = self.clone();
            if let Some(c) = &mut cfg.client {
                c.rate /= n as f64;
                c.model = model_for(&c.model, k);
                c.transactions = limit_share("udp", "transactions", c.transactions, k, n)?;
                c.concurrency =
                    limit_share("udp", "concurrency", c.concurrency as u64, k, n)? as usize;
                c.source_ports = slice(c.source_ports.clone(), k, n);
            }
            for t in &mut cfg.templates {
                let what = |w: &str| format!("template '{}': {w}", t.name);
                t.rate = t.rate.map(|r| r / n as f64);
                t.model = model_for(&t.model, k);
                t.transactions = limit_share("udp", &what("transactions"), t.transactions, k, n)?;
                t.concurrency =
                    limit_share("udp", &what("concurrency"), t.concurrency as u64, k, n)? as usize;
            }
            cfg.options.seed = worker_seed(self.options.seed, k);
            out.push(cfg);
        }
        Ok((out, router))
    }
}

impl MergeStats for TcpSideStats {
    fn merge(&mut self, o: &Self) {
        self.started += o.started;
        self.established += o.established;
        self.completed += o.completed;
        self.reset += o.reset;
        self.timed_out += o.timed_out;
        self.mismatched += o.mismatched;
        self.active += o.active;
        self.payload_tx += o.payload_tx;
        self.payload_rx += o.payload_rx;
        self.retransmits += o.retransmits;
        self.timeouts += o.timeouts;
        self.paws_dropped += o.paws_dropped;
        self.max_in_flight = self.max_in_flight.max(o.max_in_flight);
        self.connect_time.merge(&o.connect_time);
        self.first_byte.merge(&o.first_byte);
        self.app.merge(&o.app);
    }
}

impl MergeStats for TcpTemplateStats {
    fn merge(&mut self, o: &Self) {
        self.client.merge(&o.client);
        self.server.merge(&o.server);
    }
}

/// Sums, the longest elapsed time, stopped if any worker was; the hosts of
/// the first worker.
impl MergeStats for TcpStats {
    fn merge(&mut self, o: &Self) {
        self.client.merge(&o.client);
        self.server.merge(&o.server);
        merge_templates(&mut self.templates, &o.templates);
        self.tx_packets += o.tx_packets;
        self.tx_bytes += o.tx_bytes;
        self.rx_packets += o.rx_packets;
        self.rx_bytes += o.rx_bytes;
        self.rx_dropped += o.rx_dropped;
        self.drops.merge_workers(&o.drops);
        self.impair.merge(&o.impair);
        self.elapsed = self.elapsed.max(o.elapsed);
        self.stopped |= o.stopped;
        if self.hosts.is_empty() {
            self.hosts.clone_from(&o.hosts);
        }
    }
}

impl MergeStats for UdpSideStats {
    fn merge(&mut self, o: &Self) {
        self.sent += o.sent;
        self.answered += o.answered;
        self.timed_out += o.timed_out;
        self.unmatched += o.unmatched;
        self.mismatched += o.mismatched;
        self.errors += o.errors;
        self.retries += o.retries;
        self.duplicates += o.duplicates;
        self.active += o.active;
        self.datagrams_tx += o.datagrams_tx;
        self.datagrams_rx += o.datagrams_rx;
        self.payload_tx += o.payload_tx;
        self.payload_rx += o.payload_rx;
        self.response_time.merge(&o.response_time);
        self.app.merge(&o.app);
    }
}

impl MergeStats for UdpTemplateStats {
    fn merge(&mut self, o: &Self) {
        self.client.merge(&o.client);
        self.server.merge(&o.server);
    }
}

impl MergeStats for UdpStats {
    fn merge(&mut self, o: &Self) {
        self.client.merge(&o.client);
        self.server.merge(&o.server);
        merge_templates(&mut self.templates, &o.templates);
        self.tx_packets += o.tx_packets;
        self.tx_bytes += o.tx_bytes;
        self.rx_packets += o.rx_packets;
        self.rx_bytes += o.rx_bytes;
        self.rx_dropped += o.rx_dropped;
        self.drops.merge_workers(&o.drops);
        self.impair.merge(&o.impair);
        self.elapsed = self.elapsed.max(o.elapsed);
        self.stopped |= o.stopped;
        if self.hosts.is_empty() {
            self.hosts.clone_from(&o.hosts);
        }
    }
}

fn merge_templates<T: MergeStats + Clone>(a: &mut Vec<T>, b: &[T]) {
    if a.is_empty() {
        a.extend_from_slice(b);
        return;
    }
    for (x, y) in a.iter_mut().zip(b) {
        x.merge(y);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_frame(
        dst_mac: [u8; 6],
        proto: u8,
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
    ) -> Vec<u8> {
        let mut f = vec![0u8; 14 + 20 + 8];
        f[..6].copy_from_slice(&dst_mac);
        f[12..14].copy_from_slice(&[0x08, 0x00]);
        f[14] = 0x45;
        f[16..18].copy_from_slice(&28u16.to_be_bytes());
        f[23] = proto;
        f[26..30].copy_from_slice(&src);
        f[30..34].copy_from_slice(&dst);
        f[34..36].copy_from_slice(&sport.to_be_bytes());
        f[36..38].copy_from_slice(&dport.to_be_bytes());
        f
    }

    const MAC: [u8; 6] = [2, 0, 10, 0, 0, 1];

    #[test]
    fn slices_cover_the_ports_once() {
        for n in 1..10 {
            let ports = 1024..65535u16;
            let mut next = ports.start;
            for k in 0..n {
                let s = slice(ports.clone(), k, n);
                assert_eq!(s.start, next);
                next = s.end;
            }
            assert_eq!(next, ports.end);
            for p in [1024u16, 1025, 30000, 65534] {
                let k = slice_of(ports.clone(), p, n);
                assert!(slice(ports.clone(), k, n).contains(&p), "{p} {n}");
            }
        }
        assert_eq!(slice(10..13, 1, 4), 10..11);
        assert_eq!(slice_of(10..13, 12, 4), 3);
    }

    #[test]
    fn routes_clients_by_port_and_servers_by_hash() {
        let r = FlowRouter::new(4).with_client("10.0.0.1".parse().unwrap(), 2, 1000..1400);
        let client =
            |ip: [u8; 4], port| r.route(&ipv4_frame(MAC, IPPROTO_TCP, [10, 0, 1, 1], ip, 80, port));
        assert_eq!(client([10, 0, 0, 1], 1000), Route::Worker(0));
        assert_eq!(client([10, 0, 0, 2], 1150), Route::Worker(1));
        assert_eq!(client([10, 0, 0, 1], 1399), Route::Worker(3));
        // Not a client address, or outside the ports: the hash.
        let mut seen = [0; 4];
        for sport in 2000..2400u16 {
            let f = ipv4_frame(MAC, IPPROTO_TCP, [10, 0, 0, 1], [10, 0, 1, 1], sport, 80);
            let Route::Worker(k) = r.route(&f) else {
                panic!()
            };
            assert_eq!(
                r.route(&f),
                Route::Worker(k),
                "the same flow, the same worker"
            );
            seen[k] += 1;
        }
        assert!(seen.iter().all(|&c| c > 50), "{seen:?}");
        // UDP broadcasts (DHCP) to everyone; ICMP to worker 0.
        let bcast = ipv4_frame([0xff; 6], IPPROTO_UDP, [10, 0, 0, 254], [255; 4], 67, 68);
        assert_eq!(r.route(&bcast), Route::All);
        let ping = ipv4_frame(MAC, 1, [10, 0, 0, 254], [10, 0, 0, 1], 0x0800, 0);
        assert_eq!(r.route(&ping), Route::Worker(0));
    }

    #[test]
    fn routes_arp_and_neighbor_discovery() {
        let r = FlowRouter::new(3);
        let mut arp = vec![0xffu8; 6];
        arp.extend_from_slice(&[2, 0, 0, 0, 0, 9, 0x08, 0x06]);
        arp.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
        arp.resize(42, 0);
        assert_eq!(r.route(&arp), Route::Worker(0), "request");
        arp[21] = 2;
        assert_eq!(r.route(&arp), Route::All, "reply");

        let mut nd = vec![0x33u8, 0x33, 0xff, 0, 0, 1, 2, 0, 0, 0, 0, 9, 0x86, 0xdd];
        nd.extend_from_slice(&[0x60, 0, 0, 0, 0, 24, IPPROTO_ICMPV6, 255]);
        nd.extend_from_slice(&[0u8; 32]);
        nd.extend_from_slice(&[135, 0, 0, 0]);
        nd.resize(14 + 40 + 24, 0);
        assert_eq!(r.route(&nd), Route::Worker(0), "solicitation");
        nd[54] = 136;
        assert_eq!(r.route(&nd), Route::All, "advertisement");
        nd[54] = 134;
        assert_eq!(r.route(&nd), Route::All, "router advertisement");
    }
}
