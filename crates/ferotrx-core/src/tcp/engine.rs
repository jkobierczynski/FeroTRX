//! The TCP engine: emulated hosts that open, play and close TCP connections.
//!
//! The engine does no I/O and reads no clock. It is fed received frames and the
//! current time, and it queues the frames it wants sent; [`run_tcp`](super::run_tcp)
//! connects it to real ports. That keeps it platform free and lets tests run it
//! on a simulated network with a simulated clock.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;

use super::hosts::{self, Host, MAX_HOPS};
use super::program::{TcpProgram, TcpRole};
use super::wire::{self, Path, Segment, TcpHeader, TcpOpts, ACK, FIN, PSH, RST, SYN};
use crate::net::{ETHERTYPE_IPV4, ETHERTYPE_IPV6, IPPROTO_ICMPV6};
use crate::traffic::EventClock;
use crate::{Error, MacAddr, Result, TrafficModel};

/// An address as a number, for address ranges of either IP version.
pub(crate) fn ip_num(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(a) => u128::from(u32::from(a)),
        IpAddr::V6(a) => u128::from(a),
    }
}

/// Address bits of `ip`'s version: 32 or 128.
pub(crate) fn ip_bits(ip: IpAddr) -> u32 {
    if ip.is_ipv4() {
        32
    } else {
        128
    }
}

/// The highest address of `ip`'s version, as a number.
pub(crate) fn ip_max(ip: IpAddr) -> u128 {
    u128::MAX >> (128 - ip_bits(ip))
}

/// The address `n` after `ip`, wrapping around within its version.
pub(crate) fn ip_add(ip: IpAddr, n: u128) -> IpAddr {
    match ip {
        IpAddr::V4(a) => Ipv4Addr::from(u32::from(a).wrapping_add(n as u32)).into(),
        IpAddr::V6(a) => Ipv6Addr::from(u128::from(a).wrapping_add(n)).into(),
    }
}

/// How far `ip` is after `first`, if both are of one version.
pub(crate) fn ip_offset(first: IpAddr, ip: IpAddr) -> Option<u128> {
    (first.is_ipv4() == ip.is_ipv4()).then(|| ip_num(ip).wrapping_sub(ip_num(first)) & ip_max(ip))
}

pub(crate) fn ip_version(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() {
        "IPv4"
    } else {
        "IPv6"
    }
}

/// The MSS for connections over `ip`'s version: `mss` is for IPv4, and IPv6
/// headers are 20 bytes longer.
pub(crate) fn mss_for(ip: IpAddr, mss: u16) -> u16 {
    if ip.is_ipv4() {
        mss
    } else {
        mss.saturating_sub(20)
    }
}

/// An emulated host: the addresses one end of the connections uses.
///
/// The host answers ARP (IPv4), neighbor solicitations (IPv6) and ping for
/// its addresses, so routers can reach it.
/// Its addresses must not belong to the machine FeroTRX runs on, or the
/// machine's own TCP stack will answer the connections with resets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpEndpoint {
    /// Index of the port (interface) this host sends and receives on.
    pub port: usize,
    pub mac: MacAddr,
    /// The host's (first) address, IPv4 or IPv6.
    pub ip: IpAddr,
    /// How many consecutive addresses from `ip` the host owns. A client opens
    /// connections from each in turn.
    pub ip_count: u32,
    /// Prefix length of the host's subnet: other addresses in it are reached
    /// directly, the rest through `gateway`.
    pub prefix: u8,
    /// The router, of the same IP version as `ip`.
    pub gateway: Option<IpAddr>,
    /// The MAC address of the next hop, if known; skips ARP or neighbor discovery.
    pub next_hop_mac: Option<MacAddr>,
    /// 802.1Q tag on every frame, and the tag frames must carry to be ours.
    pub vlan: Option<u16>,
}

impl TcpEndpoint {
    /// A host on `port` with one address in a /24 (IPv4) or /64 (IPv6), no
    /// gateway, no VLAN.
    pub fn new(port: usize, mac: MacAddr, ip: IpAddr) -> Self {
        Self {
            port,
            mac,
            ip,
            ip_count: 1,
            prefix: if ip.is_ipv4() { 24 } else { 64 },
            gateway: None,
            next_hop_mac: None,
            vlan: None,
        }
    }

    pub fn with_prefix(mut self, prefix: u8) -> Self {
        self.prefix = prefix;
        self
    }

    pub fn with_gateway(mut self, gateway: IpAddr) -> Self {
        self.gateway = Some(gateway);
        self
    }

    pub fn with_vlan(mut self, vlan: u16) -> Self {
        self.vlan = Some(vlan);
        self
    }

    pub fn with_ip_count(mut self, count: u32) -> Self {
        self.ip_count = count;
        self
    }

    pub fn with_next_hop_mac(mut self, mac: MacAddr) -> Self {
        self.next_hop_mac = Some(mac);
        self
    }

    /// True if `ip` is one of the host's addresses.
    pub fn owns(&self, ip: IpAddr) -> bool {
        ip_offset(self.ip, ip).is_some_and(|d| d < u128::from(self.ip_count))
    }

    pub(crate) fn nth_ip(&self, n: u32) -> IpAddr {
        ip_add(self.ip, u128::from(n % self.ip_count.max(1)))
    }

    /// The address frames to `dst` go to first: `dst` itself or the gateway.
    pub fn next_hop(&self, dst: IpAddr) -> IpAddr {
        let bits = ip_bits(self.ip);
        let prefix = u32::from(self.prefix).min(bits);
        let mask = if prefix == 0 {
            0
        } else {
            ip_max(self.ip) & !(ip_max(self.ip) >> prefix)
        };
        let on_link =
            dst.is_ipv4() == self.ip.is_ipv4() && ip_num(dst) & mask == ip_num(self.ip) & mask;
        match self.gateway {
            Some(gw) if !on_link => gw,
            _ => dst,
        }
    }

    pub(crate) fn validate(&self, what: &str) -> Result<()> {
        if self.ip_count == 0 {
            return Err(Error::Tcp(format!("{what}: ip_count must be at least 1")));
        }
        let bits = ip_bits(self.ip);
        if u32::from(self.prefix) > bits {
            return Err(Error::Tcp(format!(
                "{what}: prefix /{} is longer than {bits}",
                self.prefix
            )));
        }
        if ip_max(self.ip) - ip_num(self.ip) < u128::from(self.ip_count - 1) {
            return Err(Error::Tcp(format!(
                "{what}: address range from {} runs past the last {} address",
                self.ip,
                ip_version(self.ip)
            )));
        }
        if let Some(gw) = self.gateway {
            if gw.is_ipv4() != self.ip.is_ipv4() {
                return Err(Error::Tcp(format!(
                    "{what}: the gateway {gw} is {} but the host is {}",
                    ip_version(gw),
                    ip_version(self.ip)
                )));
            }
        }
        if let IpAddr::V6(a) = self.ip {
            if a.is_multicast() || a.is_unspecified() {
                return Err(Error::Tcp(format!("{what}: {a} is not a unicast address")));
            }
        }
        if matches!(self.vlan, Some(v) if v == 0 || v > 4094) {
            return Err(Error::Tcp(format!("{what}: VLAN must be 1-4094")));
        }
        if self.mac.0[0] & 1 != 0 {
            return Err(Error::Tcp(format!(
                "{what}: {} is a multicast MAC address",
                self.mac
            )));
        }
        Ok(())
    }
}

/// One kind of connection: a program, where clients connect to play it, and
/// the port servers accept it on.
///
/// Like a TRex ASTF template. A run can mix several: the client picks the
/// template of each new connection by weight, and the server picks the
/// program by the port the SYN arrives on.
#[derive(Clone, Debug, PartialEq)]
pub struct TcpTemplate {
    /// A short name for reports, e.g. `http`.
    pub name: String,
    pub program: Arc<TcpProgram>,
    /// Where clients connect: the first server address, and the port. Behind
    /// a port forward, the router's address and the forwarded port. Of the
    /// client's IP version.
    pub connect: SocketAddr,
    /// How many consecutive server addresses from `connect`'s the client
    /// connects to, in turn (default 1).
    pub connect_ips: u32,
    /// The port servers accept this template's connections on (default:
    /// `connect`'s port).
    pub listen_port: u16,
    /// Share of the new connections the client opens with this template,
    /// relative to the others (default 1). 0: the client never opens it,
    /// but the server still accepts it.
    pub weight: u32,
    /// This template's own rate of new connections. Templates without one
    /// share the client's `cps` by weight; a template with one opens at that
    /// rate on its own, and its weight only matters if it is 0.
    pub cps: Option<f64>,
    /// How this template's own connections spread around its `cps`
    /// (Poisson arrivals, bursts, a ramp); only with `cps`.
    pub model: TrafficModel,
    /// Most connections this template opens; 0 is no limit of its own.
    pub connections: u64,
    /// Most of this template's connections open at once; 0 is no limit of its own.
    pub concurrency: usize,
}

impl TcpTemplate {
    /// A template that connects to `connect` and listens on its port, weight 1.
    pub fn new(program: Arc<TcpProgram>, connect: SocketAddr) -> Self {
        Self {
            name: "default".into(),
            program,
            connect,
            connect_ips: 1,
            listen_port: connect.port(),
            weight: 1,
            cps: None,
            model: TrafficModel::default(),
            connections: 0,
            concurrency: 0,
        }
    }

    /// Spreads this template's own connections around its `cps` by `model`.
    pub fn with_model(mut self, model: TrafficModel) -> Self {
        self.model = model;
        self
    }

    /// Opens this template's connections at `cps` per second, on its own.
    pub fn with_cps(mut self, cps: f64) -> Self {
        self.cps = Some(cps);
        self
    }

    pub fn with_connections(mut self, connections: u64) -> Self {
        self.connections = connections;
        self
    }

    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    pub fn with_connect_ips(mut self, count: u32) -> Self {
        self.connect_ips = count;
        self
    }

    pub fn with_listen_port(mut self, port: u16) -> Self {
        self.listen_port = port;
        self
    }

    fn nth_server(&self, n: u64) -> IpAddr {
        let k = n % u64::from(self.connect_ips.max(1));
        ip_add(self.connect.ip(), u128::from(k))
    }
}

/// The client side: opens connections to the servers and plays the client's part.
///
/// `connections` and `concurrency` hold for all templates together, on top
/// of any limits the templates have of their own.
#[derive(Clone, Debug, PartialEq)]
pub struct TcpClientConfig {
    pub endpoint: TcpEndpoint,
    /// New connections per second, for the templates without their own `cps`
    /// together.
    pub cps: f64,
    /// How new connections spread around `cps`: Poisson arrivals, bursts,
    /// a ramp up and down (a ramp that ends at 0% stops opening connections).
    pub model: TrafficModel,
    /// Connections to open in all; 0 keeps opening them until the run stops.
    pub connections: u64,
    /// Most connections open at once; 0 is no limit.
    pub concurrency: usize,
    /// Source ports to use, in turn.
    pub source_ports: Range<u16>,
}

impl TcpClientConfig {
    pub fn new(endpoint: TcpEndpoint) -> Self {
        Self {
            endpoint,
            cps: 1.0,
            model: TrafficModel::default(),
            connections: 1,
            concurrency: 0,
            source_ports: 1024..65535,
        }
    }
}

/// The server side: accepts connections on the templates' ports and plays the
/// server's part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpServerConfig {
    pub endpoint: TcpEndpoint,
}

impl TcpServerConfig {
    pub fn new(endpoint: TcpEndpoint) -> Self {
        Self { endpoint }
    }
}

/// TCP settings shared by both sides.
///
/// See `docs/tcp-engine.md` for what the engine does with them.
#[derive(Clone, Debug, PartialEq)]
pub struct TcpOptions {
    /// Maximum segment size announced and used over IPv4 (default 1460).
    /// IPv6 connections use 20 bytes less, for the longer IP header, so their
    /// frames are as long. With timestamps, segments carry 12 bytes less
    /// data, for the option.
    pub mss: u16,
    /// Retransmission timeout before the first round-trip time is measured;
    /// doubles on each retry (default 250 ms). Once measured, the timeout
    /// follows the round-trip time (RFC 6298).
    pub rto: Duration,
    /// The shortest retransmission timeout the round-trip time can give
    /// (default 200 ms).
    pub min_rto: Duration,
    /// Retransmissions of data before a connection is given up and reset (default 8).
    pub max_retries: u32,
    /// Retransmissions of a SYN or SYN-ACK before the connection is given up (default 6).
    pub syn_retries: u32,
    /// How long the end that closed first keeps answering a repeated FIN
    /// (default 4 s). The source port is not reused meanwhile.
    pub time_wait: Duration,
    /// A connection with nothing received for this long is reset (default 30 s).
    pub idle_timeout: Duration,
    /// How long the client waits for an ARP reply (IPv4) or a neighbor
    /// advertisement (IPv6) from its next hop (default 5 s).
    pub arp_timeout: Duration,
    /// Most bytes each end keeps in flight, unacknowledged: its send buffer
    /// (default 4 MiB). The other end's window and congestion control may
    /// allow less.
    pub send_window: u32,
    /// The receive window each end announces, in bytes (default 4 MiB). More
    /// than 65535 needs window scaling.
    pub receive_window: u32,
    /// Offer window scaling (RFC 7323), so windows can be larger than 64 KB
    /// (default true).
    pub window_scaling: bool,
    /// Offer timestamps (RFC 7323): round-trip times from every ACK, and
    /// PAWS, which drops old duplicate segments (default true).
    pub timestamps: bool,
    /// Offer selective acknowledgements (RFC 2018): report the segments that
    /// arrived after a gap, and retransmit only the gaps (default true).
    pub sack: bool,
    /// Check that the bytes each end receives are the ones the program says
    /// (default true). Connections that differ count as `mismatched`.
    pub verify: bool,
    /// Keep the capture's message timing: before each message, wait as long
    /// as the capture shows between the previous message and it (see
    /// [`TcpMessage::delay`](super::TcpMessage::delay); default false).
    pub keep_timing: bool,
    /// Think time: how long an end waits after the other end's message
    /// before it sends its own (default 0). Adds to `keep_timing`'s gaps.
    pub think_time: Duration,
    /// Seed for initial sequence numbers.
    pub seed: u64,
}

impl Default for TcpOptions {
    fn default() -> Self {
        Self {
            mss: 1460,
            rto: Duration::from_millis(250),
            min_rto: Duration::from_millis(200),
            max_retries: 8,
            syn_retries: 6,
            time_wait: Duration::from_secs(4),
            idle_timeout: Duration::from_secs(30),
            arp_timeout: Duration::from_secs(5),
            send_window: 4 << 20,
            receive_window: 4 << 20,
            window_scaling: true,
            timestamps: true,
            sack: true,
            verify: true,
            keep_timing: false,
            think_time: Duration::ZERO,
            seed: 0x5eed_f00d,
        }
    }
}

/// Largest window scale shift (RFC 7323).
const MAX_WSCALE: u8 = 14;
/// Longest retransmission timeout, after backing off.
const MAX_RTO: Duration = Duration::from_secs(8);

impl TcpOptions {
    /// The window scale shift announced: the smallest that fits the receive window.
    fn wscale(&self) -> u8 {
        let mut s = 0;
        while s < MAX_WSCALE && (self.receive_window >> s) > 0xffff {
            s += 1;
        }
        s
    }

    fn validate(&self) -> Result<()> {
        if self.mss < 64 {
            return Err(Error::Tcp("mss must be at least 64".into()));
        }
        if self.rto.is_zero() {
            return Err(Error::Tcp("rto must be more than zero".into()));
        }
        if self.min_rto > MAX_RTO {
            return Err(Error::Tcp(format!("min_rto must be at most {MAX_RTO:?}")));
        }
        if self.idle_timeout.is_zero() {
            return Err(Error::Tcp("idle_timeout must be more than zero".into()));
        }
        if self.send_window < u32::from(self.mss) {
            return Err(Error::Tcp(format!(
                "the send window ({} bytes) must hold at least one segment ({} bytes)",
                self.send_window, self.mss
            )));
        }
        if self.receive_window < u32::from(self.mss) {
            return Err(Error::Tcp(format!(
                "the receive window ({} bytes) must hold at least one segment ({} bytes)",
                self.receive_window, self.mss
            )));
        }
        let max = 0xffffu32 << MAX_WSCALE;
        if self.receive_window > max {
            return Err(Error::Tcp(format!(
                "the receive window can be at most {max} bytes (window scaling's limit)"
            )));
        }
        Ok(())
    }
}

/// Everything a [`TcpEngine`] does: the templates, and a client, a server or both.
#[derive(Clone, Debug)]
pub struct TcpConfig {
    pub templates: Vec<TcpTemplate>,
    pub client: Option<TcpClientConfig>,
    pub server: Option<TcpServerConfig>,
    pub options: TcpOptions,
}

/// Counters of one side.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TcpSideStats {
    /// Connections opened (client: SYN sent; server: SYN accepted).
    pub started: u64,
    /// Connections whose handshake finished.
    pub established: u64,
    /// Connections that played the whole program and closed with FINs.
    pub completed: u64,
    /// Connections ended by a reset from the other end.
    pub reset: u64,
    /// Connections given up after retransmitting too often or idling too long.
    pub timed_out: u64,
    /// Connections whose received bytes differed from the program, or that the
    /// other end closed early. Also counted in `completed` if they closed cleanly.
    pub mismatched: u64,
    /// Connections open now.
    pub active: u64,
    /// Application bytes sent and received, retransmissions not counted.
    pub payload_tx: u64,
    pub payload_rx: u64,
    /// Segments sent again after a timeout, three duplicate ACKs, or a
    /// gap that SACK reported.
    pub retransmits: u64,
    /// Retransmission timeouts: segments resent because no ACK came in time
    /// (also counted in `retransmits`).
    pub timeouts: u64,
    /// Segments dropped by PAWS: older timestamps than the connection has seen.
    pub paws_dropped: u64,
    /// Most bytes one connection had in flight, unacknowledged, at once.
    pub max_in_flight: u64,
}

impl TcpSideStats {
    /// Connections that ended without completing.
    pub fn failed(&self) -> u64 {
        self.reset + self.timed_out
    }
}

/// Counters of one template in a TCP run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TcpTemplateStats {
    pub name: String,
    pub client: TcpSideStats,
    pub server: TcpSideStats,
}

/// Counters of a TCP run.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TcpStats {
    /// All templates together.
    pub client: TcpSideStats,
    pub server: TcpSideStats,
    /// Each template's share, in the order of [`TcpConfig::templates`].
    pub templates: Vec<TcpTemplateStats>,
    /// Frames and bytes sent and received on the ports, all kinds.
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub elapsed: Duration,
    /// True if the run was stopped or hit its duration before the client finished.
    pub stopped: bool,
}

impl TcpStats {
    /// Completed client connections per second.
    pub fn cps(&self) -> f64 {
        let s = self.elapsed.as_secs_f64();
        if s > 0.0 {
            self.client.completed as f64 / s
        } else {
            0.0
        }
    }
}

#[derive(Clone, Debug)]
enum Action {
    /// Send this range of the own stream, after waiting this long (message
    /// timing and think time).
    Send(Range<usize>, Duration),
    /// Wait for this many bytes from the other end.
    Recv(usize),
}

/// What every connection reads: the program turned into each side's actions.
struct Shared {
    actions: [Vec<Action>; 2],
    streams: [Vec<u8>; 2],
    closer: TcpRole,
    options: TcpOptions,
}

fn idx(role: TcpRole) -> usize {
    match role {
        TcpRole::Client => 0,
        TcpRole::Server => 1,
    }
}

impl Shared {
    fn new(program: &TcpProgram, options: TcpOptions) -> Self {
        let mut actions = [Vec::new(), Vec::new()];
        let mut offsets = [0usize, 0usize];
        let mut previous: Option<TcpRole> = None;
        for m in &program.messages {
            let me = idx(m.from);
            let start = offsets[me];
            offsets[me] += m.data.len();
            let mut wait = if options.keep_timing {
                m.delay
            } else {
                Duration::ZERO
            };
            if previous == Some(m.from.peer()) {
                wait += options.think_time;
            }
            previous = Some(m.from);
            actions[me].push(Action::Send(start..offsets[me], wait));
            actions[1 - me].push(Action::Recv(m.data.len()));
        }
        Shared {
            actions,
            streams: [
                program.stream(TcpRole::Client),
                program.stream(TcpRole::Server),
            ],
            closer: program.closer,
            options,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    SynSent,
    SynRcvd,
    Open,
    TimeWait,
}

struct Conn {
    role: TcpRole,
    /// Index of the connection's template.
    tpl: usize,
    port: usize,
    path: Path,
    lport: u16,
    rport: u16,
    state: State,
    /// The largest segment the other end takes, options not counted.
    mss: usize,

    iss: u32,
    snd_una: u32,
    /// Next sequence number to send; goes back to `snd_una` after a timeout.
    snd_nxt: u32,
    /// Highest sequence number sent so far, plus one.
    snd_max: u32,
    /// The other end's window, scaled.
    snd_wnd: usize,
    cwnd: usize,
    ssthresh: usize,
    /// Bytes from `snd_una` on, not yet acknowledged.
    snd_buf: VecDeque<u8>,
    fin_queued: bool,
    /// Sequence number of our FIN once sent.
    fin_seq: Option<u32>,
    fin_acked: bool,
    /// True if our FIN went out before the other end's arrived.
    closed_first: bool,
    /// Ranges above `snd_una` the other end has selectively acknowledged:
    /// sorted, apart.
    sacked: Vec<(u32, u32)>,
    /// In loss recovery: `snd_max` when it began. It ends when that is acknowledged.
    recover: Option<u32>,
    /// In loss recovery: the gaps up to here have been retransmitted.
    high_rxt: u32,
    /// Most bytes in flight so far.
    peak_in_flight: u64,

    /// Window scaling in use (both ends offered it), and the shift counts:
    /// the other end's for its windows, ours for the windows we send.
    ws_ok: bool,
    snd_shift: u8,
    rcv_shift: u8,
    /// Timestamps in use, the other end's latest TSval to echo, and the
    /// offset of our clock.
    ts_ok: bool,
    ts_recent: u32,
    ts_offset: u32,
    /// SACK in use.
    sack_ok: bool,

    irs: u32,
    rcv_nxt: u32,
    /// Ranges received above `rcv_nxt`, out of order: sorted, apart. Their
    /// bytes were checked on arrival and are taken when the gap fills.
    ooo: Vec<(u32, u32)>,
    /// Start of the latest out-of-order segment, for the first SACK block.
    ooo_last: u32,
    /// Where a FIN that came ahead of missing data is.
    fin_pending: Option<u32>,
    fin_rcvd: bool,
    need_ack: bool,
    dup_acks: u32,

    step: usize,
    /// Received bytes not yet taken by a `Recv` action.
    unread: usize,
    rx_total: usize,
    mismatched: bool,
    /// When the next message may go, while it waits (message timing).
    hold: Option<Duration>,

    rto: Duration,
    srtt: Option<Duration>,
    rttvar: Duration,
    /// A segment timed for the round-trip time, without timestamps: the
    /// sequence number that acknowledges it, and when it went out.
    rtt_probe: Option<(u32, Duration)>,
    retries: u32,
    /// Retransmission timer, or the end of TIME_WAIT.
    deadline: Option<Duration>,
    last_rx: Duration,
    counted: bool,
    /// The earliest time this connection is queued for in the engine's
    /// timers (`Duration::MAX`: not queued).
    scheduled: Duration,
}

type Key = (SocketAddr, SocketAddr);

struct Out<'a> {
    frames: &'a mut Vec<(usize, Vec<u8>)>,
    ip_id: &'a mut u16,
    stats: &'a mut TcpStats,
}

impl TcpStats {
    /// Applies `f` to `role`'s counters, overall and of template `tpl`.
    fn add(&mut self, role: TcpRole, tpl: usize, f: impl Fn(&mut TcpSideStats)) {
        let pick = |c: &mut TcpSideStats, s: &mut TcpSideStats, f: &dyn Fn(&mut TcpSideStats)| {
            match role {
                TcpRole::Client => f(c),
                TcpRole::Server => f(s),
            }
        };
        pick(&mut self.client, &mut self.server, &f);
        if let Some(t) = self.templates.get_mut(tpl) {
            pick(&mut t.client, &mut t.server, &f);
        }
    }
}

impl Out<'_> {
    fn add(&mut self, role: TcpRole, tpl: usize, f: impl Fn(&mut TcpSideStats)) {
        self.stats.add(role, tpl, f);
    }

    fn segment(&mut self, port: usize, path: &Path, h: &TcpHeader, data: &[u8]) {
        *self.ip_id = self.ip_id.wrapping_add(1);
        self.frames
            .push((port, wire::tcp_frame(path, h, data, *self.ip_id)));
    }
}

/// What happened to a connection after an event.
#[derive(PartialEq, Eq)]
enum Fate {
    Keep,
    Remove,
}

/// Bytes from `a` to `b` in sequence space.
fn span(a: u32, b: u32) -> usize {
    b.wrapping_sub(a) as usize
}

/// Adds `(l, r)` to `ranges` (sorted from `base`, apart), merging what touches.
fn add_range(ranges: &mut Vec<(u32, u32)>, base: u32, l: u32, r: u32) {
    ranges.push((l, r));
    ranges.sort_by_key(|&(l, _)| l.wrapping_sub(base));
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for &(l, r) in ranges.iter() {
        match merged.last_mut() {
            Some(last) if wire::seq_le(l, last.1) => {
                if wire::seq_lt(last.1, r) {
                    last.1 = r;
                }
            }
            _ => merged.push((l, r)),
        }
    }
    *ranges = merged;
}

/// Most out-of-order ranges a connection keeps.
const MAX_OOO: usize = 64;

/// The connection-specific parts of a new [`Conn`].
struct ConnInit {
    role: TcpRole,
    tpl: usize,
    port: usize,
    path: Path,
    lport: u16,
    rport: u16,
    state: State,
    mss: usize,
    iss: u32,
    ts_offset: u32,
}

impl Conn {
    fn new(i: ConnInit, o: &TcpOptions, now: Duration) -> Self {
        let mss = i.mss;
        Conn {
            role: i.role,
            tpl: i.tpl,
            port: i.port,
            path: i.path,
            lport: i.lport,
            rport: i.rport,
            state: i.state,
            mss,
            iss: i.iss,
            snd_una: i.iss,
            snd_nxt: i.iss.wrapping_add(1),
            snd_max: i.iss.wrapping_add(1),
            snd_wnd: 0,
            cwnd: 10 * mss,
            ssthresh: usize::MAX,
            snd_buf: VecDeque::new(),
            fin_queued: false,
            fin_seq: None,
            fin_acked: false,
            closed_first: false,
            sacked: Vec::new(),
            recover: None,
            high_rxt: i.iss,
            peak_in_flight: 0,
            ws_ok: o.window_scaling,
            snd_shift: 0,
            rcv_shift: if o.window_scaling { o.wscale() } else { 0 },
            ts_ok: o.timestamps,
            ts_recent: 0,
            ts_offset: i.ts_offset,
            sack_ok: o.sack,
            irs: 0,
            rcv_nxt: 0,
            ooo: Vec::new(),
            ooo_last: 0,
            fin_pending: None,
            fin_rcvd: false,
            need_ack: false,
            dup_acks: 0,
            step: 0,
            unread: 0,
            rx_total: 0,
            mismatched: false,
            hold: None,
            rto: o.rto,
            srtt: None,
            rttvar: Duration::ZERO,
            rtt_probe: Some((i.iss.wrapping_add(1), now)),
            retries: 0,
            deadline: Some(now + o.rto),
            last_rx: now,
            counted: false,
            scheduled: Duration::MAX,
        }
    }

    /// When [`on_timer`](Self::on_timer) next has something to do: the
    /// retransmission or TIME_WAIT deadline, the end of a message's wait, or
    /// the idle timeout.
    fn next_wake(&self, o: &TcpOptions) -> Duration {
        let mut at = self.deadline.unwrap_or(Duration::MAX);
        if self.state != State::TimeWait {
            at = at.min(self.last_rx.saturating_add(o.idle_timeout));
        }
        if self.state == State::Open {
            if let Some(h) = self.hold {
                at = at.min(h);
            }
        }
        at
    }

    /// Takes what the other end's SYN or SYN-ACK says it can do: each
    /// option is used only if both ends offer it.
    fn negotiate(&mut self, seg: &Segment) {
        self.irs = seg.seq;
        self.rcv_nxt = seg.seq.wrapping_add(1);
        self.mss = self.mss.min(usize::from(seg.opts.mss.unwrap_or(536)));
        match seg.opts.wscale {
            Some(ws) if self.ws_ok => self.snd_shift = ws.min(MAX_WSCALE),
            _ => {
                self.ws_ok = false;
                self.snd_shift = 0;
                self.rcv_shift = 0;
            }
        }
        match seg.opts.ts {
            Some((val, _)) if self.ts_ok => self.ts_recent = val,
            _ => self.ts_ok = false,
        }
        self.sack_ok &= seg.opts.sack_ok;
        // A SYN's window is never scaled.
        self.snd_wnd = usize::from(seg.window);
        self.cwnd = 10 * self.smss();
    }

    /// Data bytes per segment: the MSS less the timestamp option.
    fn smss(&self) -> usize {
        self.mss - if self.ts_ok { 12 } else { 0 }
    }

    fn tsval(&self, now: Duration) -> u32 {
        (now.as_millis() as u32).wrapping_add(self.ts_offset)
    }

    /// The receive window we announce, in bytes. The program takes received
    /// bytes at once, so the whole buffer is always free.
    fn rcv_window(&self, o: &TcpOptions) -> usize {
        let w = o.receive_window as usize;
        let w = if self.ws_ok {
            w.min(0xffff << self.rcv_shift)
        } else {
            w.min(0xffff)
        };
        (w >> self.rcv_shift) << self.rcv_shift
    }

    fn header(&self, o: &TcpOptions, seq: u32, flags: u8, now: Duration) -> TcpHeader {
        let window = if flags & SYN != 0 {
            (o.receive_window as usize).min(0xffff)
        } else {
            self.rcv_window(o) >> self.rcv_shift
        };
        TcpHeader {
            sport: self.lport,
            dport: self.rport,
            seq,
            ack: if flags & ACK != 0 { self.rcv_nxt } else { 0 },
            flags,
            window: window as u16,
            opts: TcpOpts {
                ts: self.ts_ok.then(|| (self.tsval(now), self.ts_recent)),
                ..Default::default()
            },
        }
    }

    fn send_syn(&self, o: &TcpOptions, out: &mut Out, now: Duration) {
        let flags = if self.state == State::SynRcvd {
            SYN | ACK
        } else {
            SYN
        };
        let mut h = self.header(o, self.iss, flags, now);
        h.opts.mss = Some(mss_for(self.path.src, o.mss));
        h.opts.wscale = self.ws_ok.then_some(self.rcv_shift);
        h.opts.sack_ok = self.sack_ok;
        out.segment(self.port, &self.path, &h, &[]);
    }

    fn send_rst(&self, o: &TcpOptions, out: &mut Out, now: Duration) {
        let h = self.header(o, self.snd_nxt, RST | ACK, now);
        out.segment(self.port, &self.path, &h, &[]);
    }

    /// A pure ACK, with SACK blocks for what arrived out of order: first the
    /// block of the latest segment, then the others (RFC 2018).
    fn send_ack(&mut self, o: &TcpOptions, out: &mut Out, now: Duration) {
        let mut h = self.header(o, self.snd_nxt, ACK, now);
        if self.sack_ok && !self.ooo.is_empty() {
            let max = if self.ts_ok { 3 } else { 4 };
            let first = self.ooo.iter().position(|&(l, r)| {
                wire::seq_le(l, self.ooo_last) && wire::seq_lt(self.ooo_last, r)
            });
            let order = first
                .into_iter()
                .chain((0..self.ooo.len()).filter(|&i| Some(i) != first));
            for i in order.take(max) {
                h.opts.sack[h.opts.sack_n] = self.ooo[i];
                h.opts.sack_n += 1;
            }
        }
        out.segment(self.port, &self.path, &h, &[]);
        self.need_ack = false;
    }

    /// Bytes of `snd_buf` already sent.
    fn sent_off(&self) -> usize {
        if self.fin_seq.is_some() {
            self.snd_buf.len()
        } else {
            span(self.snd_una, self.snd_nxt).min(self.snd_buf.len())
        }
    }

    fn emit_data(&self, o: &TcpOptions, out: &mut Out, off: usize, len: usize, now: Duration) {
        let data: Vec<u8> = self.snd_buf.range(off..off + len).copied().collect();
        let mut flags = ACK;
        if off + len == self.snd_buf.len() {
            flags |= PSH;
        }
        let h = self.header(o, self.snd_una.wrapping_add(off as u32), flags, now);
        out.segment(self.port, &self.path, &h, &data);
    }

    /// Plays the program as far as it can go now.
    fn advance(&mut self, sh: &Shared, out: &mut Out, now: Duration) {
        let me = idx(self.role);
        loop {
            match sh.actions[me].get(self.step) {
                Some(Action::Send(r, wait)) => {
                    if !wait.is_zero() {
                        // Message timing: hold the message until its time.
                        match self.hold {
                            None => {
                                self.hold = Some(now + *wait);
                                break;
                            }
                            Some(t) if now < t => break,
                            Some(_) => self.hold = None,
                        }
                    }
                    self.snd_buf.extend(&sh.streams[me][r.clone()]);
                    let n = r.len() as u64;
                    out.add(self.role, self.tpl, |s| s.payload_tx += n);
                    self.step += 1;
                }
                Some(Action::Recv(n)) => {
                    if self.unread >= *n {
                        self.unread -= n;
                        self.step += 1;
                    } else if self.fin_rcvd {
                        // The other end closed before sending what it should have.
                        self.mismatched = true;
                        self.step = sh.actions[me].len();
                    } else {
                        break;
                    }
                }
                None => {
                    if self.unread > 0 {
                        // More bytes than the program has.
                        self.mismatched = true;
                        self.unread = 0;
                    }
                    if !self.fin_queued && (sh.closer == self.role || self.fin_rcvd) {
                        self.fin_queued = true;
                    }
                    break;
                }
            }
        }
    }

    /// The selectively acknowledged range `seq` is in: its end.
    fn sacked_end(&self, seq: u32) -> Option<u32> {
        self.sacked
            .iter()
            .find(|&&(l, r)| wire::seq_le(l, seq) && wire::seq_lt(seq, r))
            .map(|&(_, r)| r)
    }

    /// The start of the first selectively acknowledged range after `seq`.
    fn sacked_after(&self, seq: u32) -> Option<u32> {
        self.sacked
            .iter()
            .find(|&&(l, _)| wire::seq_lt(seq, l))
            .map(|&(l, _)| l)
    }

    /// Selectively acknowledged bytes below `snd_nxt`.
    fn sacked_below_nxt(&self) -> usize {
        self.sacked
            .iter()
            .map(|&(l, r)| {
                let r = if wire::seq_lt(self.snd_nxt, r) {
                    self.snd_nxt
                } else {
                    r
                };
                if wire::seq_lt(l, r) {
                    span(l, r)
                } else {
                    0
                }
            })
            .sum()
    }

    /// In recovery with SACK: bytes in the gaps below the highest SACKed byte
    /// not yet retransmitted, taken as lost (RFC 6675, simplified).
    fn lost_bytes(&self) -> usize {
        let mut pos = if wire::seq_lt(self.high_rxt, self.snd_una) {
            self.snd_una
        } else {
            self.high_rxt
        };
        let mut lost = 0;
        for &(l, r) in &self.sacked {
            if wire::seq_lt(pos, l) {
                lost += span(pos, l);
            }
            if wire::seq_lt(pos, r) {
                pos = r;
            }
        }
        lost
    }

    /// Bytes taken to be in the network (RFC 6675's "pipe"): sent, less what
    /// was selectively acknowledged and what is taken as lost.
    fn pipe(&self) -> usize {
        let out = span(self.snd_una, self.snd_nxt);
        let gone = self.sacked_below_nxt()
            + match self.recover {
                Some(_) if self.sack_ok && !self.sacked.is_empty() => self.lost_bytes(),
                // NewReno: each duplicate ACK is a segment that left the network.
                Some(_) => self.dup_acks as usize * self.smss(),
                None => 0,
            };
        out.saturating_sub(gone)
    }

    /// Sends what the windows allow, the FIN when its turn comes, and an ACK
    /// if one is owed and nothing else carried it.
    fn transmit(&mut self, o: &TcpOptions, out: &mut Out, now: Duration) {
        if !matches!(self.state, State::Open) {
            return;
        }
        // An ACK with SACK blocks goes on its own, so the blocks fit.
        if self.need_ack && self.sack_ok && !self.ooo.is_empty() {
            self.send_ack(o, out, now);
        }
        let smss = self.smss();
        let wnd = self.snd_wnd.min(o.send_window as usize);
        let mut off = self.sent_off();
        let mut sent = false;
        while off < self.snd_buf.len() {
            let seq = self.snd_una.wrapping_add(off as u32);
            if let Some(end) = self.sacked_end(seq) {
                // Resending after a timeout: the other end has these.
                off = span(self.snd_una, end);
                self.snd_nxt = end;
                continue;
            }
            // With nothing in flight, one segment goes even into a zero
            // window, to probe it.
            let limit = wnd.max(if off == 0 { smss } else { 0 });
            if off >= limit || self.pipe() >= self.cwnd {
                break;
            }
            let mut len = smss.min(self.snd_buf.len() - off).min(limit - off);
            if let Some(l) = self.sacked_after(seq) {
                len = len.min(span(seq, l));
            }
            let new_data = wire::seq_le(self.snd_max, seq);
            self.emit_data(o, out, off, len, now);
            off += len;
            self.snd_nxt = self.snd_una.wrapping_add(off as u32);
            if wire::seq_lt(self.snd_max, self.snd_nxt) {
                self.snd_max = self.snd_nxt;
            }
            if new_data && !self.ts_ok && self.rtt_probe.is_none() {
                self.rtt_probe = Some((self.snd_nxt, now));
            }
            sent = true;
        }
        if self.fin_queued && self.fin_seq.is_none() && off == self.snd_buf.len() {
            let seq = self.snd_una.wrapping_add(off as u32);
            let h = self.header(o, seq, FIN | ACK, now);
            out.segment(self.port, &self.path, &h, &[]);
            self.fin_seq = Some(seq);
            self.snd_nxt = seq.wrapping_add(1);
            if wire::seq_lt(self.snd_max, self.snd_nxt) {
                self.snd_max = self.snd_nxt;
            }
            if !self.fin_rcvd {
                self.closed_first = true;
            }
            sent = true;
        }
        if sent {
            self.need_ack = false;
            if self.deadline.is_none() {
                self.deadline = Some(now + self.rto);
            }
            let flight = span(self.snd_una, self.snd_max) as u64;
            if flight > self.peak_in_flight {
                self.peak_in_flight = flight;
                out.add(self.role, self.tpl, |s| {
                    s.max_in_flight = s.max_in_flight.max(flight)
                });
            }
        } else if self.need_ack {
            self.send_ack(o, out, now);
        }
    }

    /// Unacknowledged sequence space sent (data, FIN).
    fn in_flight(&self) -> bool {
        self.snd_max != self.snd_una
    }

    /// The retransmission timeout from the round-trip time (RFC 6298), or
    /// the configured one before the first measurement.
    fn base_rto(&self, o: &TcpOptions) -> Duration {
        match self.srtt {
            Some(srtt) => {
                (srtt + (4 * self.rttvar).max(Duration::from_millis(1))).clamp(o.min_rto, MAX_RTO)
            }
            None => o.rto,
        }
    }

    fn rtt_sample(&mut self, r: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(srtt) => {
                let diff = srtt.abs_diff(r);
                self.rttvar = (self.rttvar * 3 + diff) / 4;
                self.srtt = Some((srtt * 7 + r) / 8);
            }
        }
    }

    /// Measures the round-trip time from an ACK that acknowledges something
    /// new: from its timestamp echo, or from the segment being timed.
    fn measure_rtt(&mut self, seg: &Segment, now: Duration) {
        if self.ts_ok {
            if let Some((_, ecr)) = seg.opts.ts {
                let ms = self.tsval(now).wrapping_sub(ecr);
                if ecr != 0 && ms < 60_000 {
                    self.rtt_sample(Duration::from_millis(u64::from(ms)));
                    self.rtt_probe = None;
                    return;
                }
            }
        }
        if let Some((end, at)) = self.rtt_probe {
            if wire::seq_le(end, seg.ack) {
                self.rtt_sample(now.saturating_sub(at));
                self.rtt_probe = None;
            }
        }
    }

    /// Whether a reset ends this connection (RFC 793, RFC 1337).
    fn rst_acceptable(&self, o: &TcpOptions, seg: &Segment) -> bool {
        match self.state {
            // Only one that answers our SYN.
            State::SynSent => seg.has(ACK) && seg.ack == self.iss.wrapping_add(1),
            // RFC 1337: a reset does not cut TIME_WAIT short. The other end
            // may still be resending its FIN because our last ACK was lost;
            // a router that drops the state of a closing connection (or
            // answers one of its packets itself) would otherwise make us
            // answer that FIN with a reset.
            State::TimeWait => false,
            // In the window, so a stray reset from an old connection on the
            // same ports does not end this one.
            _ => {
                let off = seg.seq.wrapping_sub(self.rcv_nxt) as usize;
                off < self.rcv_window(o).max(1)
            }
        }
    }

    /// Handles a segment for this connection.
    fn on_segment(&mut self, sh: &Shared, out: &mut Out, seg: &Segment, now: Duration) -> Fate {
        let o = &sh.options;
        self.last_rx = now;
        if seg.has(RST) {
            if !self.rst_acceptable(o, seg) {
                return Fate::Keep;
            }
            if !self.counted {
                out.add(self.role, self.tpl, |s| s.reset += 1);
            }
            return Fate::Remove;
        }
        match self.state {
            State::SynSent => {
                if seg.has(SYN) && seg.has(ACK) && seg.ack == self.iss.wrapping_add(1) {
                    self.negotiate(seg);
                    self.snd_una = seg.ack;
                    // From the timestamp echo, or the SYN if it was not resent.
                    self.measure_rtt(seg, now);
                    self.establish(o, out, now);
                    self.need_ack = true;
                    self.advance(sh, out, now);
                    self.transmit(o, out, now);
                } else if seg.has(ACK) {
                    // Not for this connection attempt.
                    let h = TcpHeader {
                        sport: self.lport,
                        dport: self.rport,
                        seq: seg.ack,
                        ack: 0,
                        flags: RST,
                        window: 0,
                        opts: TcpOpts::default(),
                    };
                    out.segment(self.port, &self.path, &h, &[]);
                }
                return Fate::Keep;
            }
            State::SynRcvd => {
                if seg.has(SYN) && !seg.has(ACK) {
                    // Our SYN-ACK was lost.
                    self.rtt_probe = None;
                    self.send_syn(o, out, now);
                    return Fate::Keep;
                }
                if !seg.has(ACK) || seg.ack != self.iss.wrapping_add(1) {
                    return Fate::Keep;
                }
                self.snd_una = seg.ack;
                self.snd_wnd = usize::from(seg.window) << self.snd_shift;
                self.measure_rtt(seg, now);
                self.establish(o, out, now);
                self.advance(sh, out, now);
            }
            State::TimeWait => {
                if seg.has(FIN) {
                    // Our last ACK was lost: send it again and wait longer.
                    let h = self.header(o, self.snd_nxt, ACK, now);
                    out.segment(self.port, &self.path, &h, &[]);
                    self.deadline = Some(now + o.time_wait);
                }
                return Fate::Keep;
            }
            State::Open => {
                // PAWS (RFC 7323): a segment with an older timestamp than the
                // last one is an old duplicate.
                if let (true, Some((val, _))) = (self.ts_ok, seg.opts.ts) {
                    if wire::seq_lt(val, self.ts_recent) {
                        out.add(self.role, self.tpl, |s| s.paws_dropped += 1);
                        if seg.seq_len() > 0 {
                            self.send_ack(o, out, now);
                        }
                        return Fate::Keep;
                    }
                }
            }
        }
        if seg.has(SYN) {
            // A repeated SYN-ACK: our ACK was lost.
            self.need_ack = true;
            self.transmit(o, out, now);
            return Fate::Keep;
        }
        if let (true, Some((val, _))) = (self.ts_ok, seg.opts.ts) {
            // Echo the timestamp of the segment that the next ACK acknowledges.
            if wire::seq_le(seg.seq, self.rcv_nxt) && wire::seq_le(self.ts_recent, val) {
                self.ts_recent = val;
            }
        }
        if seg.has(ACK) {
            self.on_ack(o, out, seg, now);
        }
        self.on_data(sh, out, seg);
        self.advance(sh, out, now);
        self.transmit(o, out, now);
        self.check_closed(o, out, now)
    }

    fn establish(&mut self, o: &TcpOptions, out: &mut Out, now: Duration) {
        self.state = State::Open;
        self.snd_nxt = self.snd_una;
        self.snd_max = self.snd_una;
        self.high_rxt = self.snd_una;
        self.retries = 0;
        self.rto = self.base_rto(o);
        self.deadline = None;
        self.last_rx = now;
        out.add(self.role, self.tpl, |s| s.established += 1);
    }

    fn on_ack(&mut self, o: &TcpOptions, out: &mut Out, seg: &Segment, now: Duration) {
        let ack = seg.ack;
        if wire::seq_lt(self.snd_max, ack) {
            // Acknowledges something never sent.
            self.need_ack = true;
            return;
        }
        self.snd_wnd = usize::from(seg.window) << self.snd_shift;
        if self.sack_ok {
            for &(l, r) in seg.opts.sack_blocks() {
                let l = if wire::seq_lt(l, self.snd_una) {
                    self.snd_una
                } else {
                    l
                };
                if wire::seq_lt(l, r) && wire::seq_le(r, self.snd_max) {
                    add_range(&mut self.sacked, self.snd_una, l, r);
                }
            }
        }
        let smss = self.smss();
        if wire::seq_lt(self.snd_una, ack) {
            let acked = span(self.snd_una, ack);
            let data = acked.min(self.snd_buf.len());
            self.snd_buf.drain(..data);
            if acked > data {
                // The FIN is acknowledged too.
                self.fin_acked = true;
            }
            self.measure_rtt(seg, now);
            self.snd_una = ack;
            if wire::seq_lt(self.snd_nxt, ack) {
                self.snd_nxt = ack;
            }
            self.sacked.retain(|&(_, r)| wire::seq_lt(ack, r));
            if let Some(first) = self.sacked.first_mut() {
                if wire::seq_lt(first.0, ack) {
                    first.0 = ack;
                }
            }
            self.retries = 0;
            self.rto = self.base_rto(o);
            match self.recover {
                Some(rec) if wire::seq_le(rec, ack) => {
                    // Everything sent before the loss is acknowledged.
                    self.recover = None;
                    self.dup_acks = 0;
                    self.cwnd = self.ssthresh.max(smss);
                }
                Some(_) => {
                    // A partial ACK: more was lost.
                    self.dup_acks = 0;
                }
                None => {
                    self.dup_acks = 0;
                    if self.cwnd < self.ssthresh {
                        // Slow start.
                        self.cwnd += data.min(smss);
                    } else {
                        // Congestion avoidance: about a segment per round trip.
                        self.cwnd += (smss * smss / self.cwnd).max(1);
                    }
                    self.cwnd = self.cwnd.min(o.send_window as usize);
                }
            }
            self.deadline = self.in_flight().then_some(now + self.rto);
        } else if ack == self.snd_una && seg.data.is_empty() && !seg.has(FIN) && self.in_flight() {
            self.dup_acks += 1;
            if self.recover.is_none() && self.dup_acks == 3 {
                // Fast retransmit, then fast recovery.
                let flight = span(self.snd_una, self.snd_max);
                self.ssthresh = (flight / 2).max(2 * smss);
                self.cwnd = self.ssthresh;
                self.recover = Some(self.snd_max);
                self.high_rxt = self.snd_una;
                self.retransmit_gaps(o, out, now, true);
            }
        }
        if self.recover.is_some() {
            self.retransmit_gaps(o, out, now, false);
        }
    }

    /// In loss recovery: retransmits the gaps, as far as the congestion
    /// window allows (`force`: at least one). With SACK, the gaps below the
    /// highest SACKed byte; without, the first unacknowledged segment, once
    /// per partial ACK (NewReno).
    fn retransmit_gaps(&mut self, o: &TcpOptions, out: &mut Out, now: Duration, mut force: bool) {
        let smss = self.smss();
        loop {
            if !force && self.pipe() >= self.cwnd {
                break;
            }
            let start = if wire::seq_lt(self.high_rxt, self.snd_una) {
                self.snd_una
            } else {
                self.high_rxt
            };
            let (from, to) = match self.sacked.last() {
                Some(&(_, high)) if self.sack_ok => {
                    let mut pos = start;
                    for &(l, r) in &self.sacked {
                        if wire::seq_le(l, pos) && wire::seq_lt(pos, r) {
                            pos = r;
                        }
                    }
                    if !wire::seq_lt(pos, high) {
                        break;
                    }
                    (pos, self.sacked_after(pos).unwrap_or(high))
                }
                _ => {
                    if wire::seq_lt(self.snd_una, start) || !self.in_flight() {
                        break;
                    }
                    (self.snd_una, self.snd_max)
                }
            };
            let off = span(self.snd_una, from);
            if off < self.snd_buf.len() {
                let len = smss.min(self.snd_buf.len() - off).min(span(from, to));
                self.emit_data(o, out, off, len, now);
                self.high_rxt = from.wrapping_add(len as u32);
            } else if let Some(f) = self.fin_seq {
                let h = self.header(o, f, FIN | ACK, now);
                out.segment(self.port, &self.path, &h, &[]);
                self.high_rxt = f.wrapping_add(1);
            } else {
                break;
            }
            self.rtt_probe = None;
            out.add(self.role, self.tpl, |s| s.retransmits += 1);
            force = false;
        }
    }

    /// Takes the data and FIN of a segment, in order or not.
    fn on_data(&mut self, sh: &Shared, out: &mut Out, seg: &Segment) {
        let len = seg.data.len();
        if len > 0 {
            if !self.fin_rcvd {
                let wnd_end = self
                    .rcv_nxt
                    .wrapping_add(self.rcv_window(&sh.options) as u32);
                let seq = seg.seq;
                let mut end = seq.wrapping_add(len as u32);
                if wire::seq_lt(wnd_end, end) {
                    end = wnd_end;
                }
                if wire::seq_le(seq, self.rcv_nxt) && wire::seq_lt(self.rcv_nxt, end) {
                    let skip = span(seq, self.rcv_nxt);
                    let data = &seg.data[skip..span(seq, end)];
                    self.verify_at(sh, self.rx_total, data);
                    self.deliver(out, data.len());
                    self.rcv_nxt = end;
                    self.take_ooo(out);
                } else if wire::seq_lt(self.rcv_nxt, seq) && wire::seq_lt(seq, end) {
                    let at = span(self.irs.wrapping_add(1), seq);
                    self.verify_at(sh, at, &seg.data[..span(seq, end)]);
                    add_range(&mut self.ooo, self.rcv_nxt, seq, end);
                    self.ooo.truncate(MAX_OOO);
                    self.ooo_last = seq;
                }
            }
            self.need_ack = true;
        }
        if seg.has(FIN) {
            let fin_at = seg.seq.wrapping_add(len as u32);
            if !self.fin_rcvd {
                if fin_at == self.rcv_nxt {
                    self.take_fin();
                } else if wire::seq_lt(self.rcv_nxt, fin_at) {
                    self.fin_pending = Some(fin_at);
                }
            }
            self.need_ack = true;
        }
    }

    /// Takes the out-of-order ranges the in-order data has reached.
    fn take_ooo(&mut self, out: &mut Out) {
        while let Some(&(l, r)) = self.ooo.first() {
            if wire::seq_lt(self.rcv_nxt, l) {
                break;
            }
            self.ooo.remove(0);
            if wire::seq_lt(self.rcv_nxt, r) {
                self.deliver(out, span(self.rcv_nxt, r));
                self.rcv_nxt = r;
            }
        }
        if self.fin_pending == Some(self.rcv_nxt) {
            self.take_fin();
        }
    }

    fn take_fin(&mut self) {
        self.fin_rcvd = true;
        self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        self.fin_pending = None;
        self.ooo.clear();
    }

    /// Checks received bytes at offset `at` of the other end's stream.
    fn verify_at(&mut self, sh: &Shared, at: usize, data: &[u8]) {
        if sh.options.verify && !self.mismatched {
            let expected = &sh.streams[idx(self.role.peer())];
            if expected.get(at..at + data.len()) != Some(data) {
                self.mismatched = true;
            }
        }
    }

    /// Counts `n` bytes that arrived in order.
    fn deliver(&mut self, out: &mut Out, n: usize) {
        let b = n as u64;
        out.add(self.role, self.tpl, |s| s.payload_rx += b);
        self.rx_total += n;
        self.unread += n;
    }

    fn check_closed(&mut self, o: &TcpOptions, out: &mut Out, now: Duration) -> Fate {
        if !(self.fin_rcvd && self.fin_acked) {
            return Fate::Keep;
        }
        self.finish(out);
        if self.closed_first {
            self.state = State::TimeWait;
            self.deadline = Some(now + o.time_wait);
            Fate::Keep
        } else {
            Fate::Remove
        }
    }

    /// Counts a clean close.
    fn finish(&mut self, out: &mut Out) {
        if self.counted {
            return;
        }
        self.counted = true;
        let mismatched = u64::from(self.mismatched);
        out.add(self.role, self.tpl, |s| {
            s.completed += 1;
            s.active = s.active.saturating_sub(1);
            s.mismatched += mismatched;
        });
    }

    /// Runs timers. Returns `Remove` when the connection is over.
    fn on_timer(&mut self, sh: &Shared, out: &mut Out, now: Duration) -> Fate {
        let o = &sh.options;
        if self.state != State::TimeWait && now.saturating_sub(self.last_rx) >= o.idle_timeout {
            self.send_rst(o, out, now);
            out.add(self.role, self.tpl, |s| s.timed_out += 1);
            return Fate::Remove;
        }
        if self.state == State::Open && self.hold.is_some_and(|t| now >= t) {
            self.advance(sh, out, now);
            self.transmit(o, out, now);
        }
        let Some(deadline) = self.deadline else {
            return Fate::Keep;
        };
        if now < deadline {
            return Fate::Keep;
        }
        if self.state == State::TimeWait {
            return Fate::Remove;
        }
        self.retries += 1;
        let limit = match self.state {
            State::SynSent | State::SynRcvd => o.syn_retries,
            _ => o.max_retries,
        };
        if self.retries > limit {
            self.send_rst(o, out, now);
            out.add(self.role, self.tpl, |s| s.timed_out += 1);
            return Fate::Remove;
        }
        out.add(self.role, self.tpl, |s| {
            s.retransmits += 1;
            s.timeouts += 1;
        });
        self.rto = (self.rto * 2).min(MAX_RTO);
        self.deadline = Some(now + self.rto);
        // Karn: nothing retransmitted is timed.
        self.rtt_probe = None;
        match self.state {
            State::SynSent | State::SynRcvd => self.send_syn(o, out, now),
            State::Open => {
                // Back to slow start from the first unacknowledged byte,
                // skipping what the other end has selectively acknowledged.
                let smss = self.smss();
                self.ssthresh = (span(self.snd_una, self.snd_max) / 2).max(2 * smss);
                self.cwnd = smss;
                self.recover = None;
                self.dup_acks = 0;
                self.snd_nxt = self.snd_una;
                if !self.fin_acked {
                    self.fin_seq = None;
                }
                self.transmit(o, out, now);
            }
            State::TimeWait => {}
        }
        Fate::Keep
    }
}

/// Small, fast, seeded random numbers for initial sequence numbers.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 16) as u32
    }
}

/// Emulated TCP clients and servers that replay a [`TcpProgram`].
///
/// Feed it received frames with [`handle_frame`](Self::handle_frame), call
/// [`poll`](Self::poll) often, and send what [`take_output`](Self::take_output)
/// returns. [`run_tcp`](super::run_tcp) does this on real ports.
pub struct TcpEngine {
    /// Each template's program as both ends play it.
    shared: Arc<[Shared]>,
    templates: Vec<TcpTemplate>,
    /// Template index by the port the server accepts it on.
    listen: HashMap<u16, usize>,
    client: Option<TcpClientConfig>,
    server: Option<TcpServerConfig>,
    hosts: Vec<Host>,
    conns: HashMap<Key, Conn>,
    /// When connections need their timers looked at. A connection may be in
    /// here more than once; only the entry at its `scheduled` time counts.
    timers: BinaryHeap<Reverse<(Duration, Key)>>,
    out: Vec<(usize, Vec<u8>)>,
    ip_id: u16,
    stats: TcpStats,
    rng: Rng,
    conn_clock: EventClock,
    port_cursor: u64,
    /// Smooth weighted round robin over the templates.
    wrr: Vec<i64>,
    /// Connections each template has opened, to step through its servers.
    opened: Vec<u64>,
    /// When each template with its own `cps` opens its next connection.
    tpl_clock: Vec<Option<EventClock>>,
    next_timer_scan: Duration,
    error: Option<String>,
    started: bool,
}

/// How often connection timers are looked at.
const TIMER_TICK: Duration = Duration::from_millis(1);

/// Queues `conn` in `timers` for when it next needs its timer, if that is
/// sooner than it is queued for.
fn schedule(
    timers: &mut BinaryHeap<Reverse<(Duration, Key)>>,
    key: Key,
    conn: &mut Conn,
    o: &TcpOptions,
) {
    let wake = conn.next_wake(o);
    if wake < conn.scheduled {
        conn.scheduled = wake;
        timers.push(Reverse((wake, key)));
    }
}

impl TcpEngine {
    pub fn new(config: TcpConfig) -> Result<Self> {
        let TcpConfig {
            templates,
            client,
            server,
            options,
        } = config;
        if client.is_none() && server.is_none() {
            return Err(Error::Tcp("give a client, a server or both".into()));
        }
        if templates.is_empty() {
            return Err(Error::Tcp("give at least one template".into()));
        }
        options.validate()?;
        let mut listen = HashMap::new();
        for (i, t) in templates.iter().enumerate() {
            let what = format!("template {}", t.name);
            if t.connect_ips == 0 {
                return Err(Error::Tcp(format!(
                    "{what}: connect_ips must be at least 1"
                )));
            }
            let ip = t.connect.ip();
            if ip_max(ip) - ip_num(ip) < u128::from(t.connect_ips - 1) {
                return Err(Error::Tcp(format!(
                    "{what}: server address range from {ip} runs past the last {} address",
                    ip_version(ip)
                )));
            }
            if let Some(c) = &client {
                if t.weight > 0 && ip.is_ipv4() != c.endpoint.ip.is_ipv4() {
                    return Err(Error::Tcp(format!(
                        "{what}: the client is {} ({}) but connects to {} address {ip}",
                        ip_version(c.endpoint.ip),
                        c.endpoint.ip,
                        if ip.is_ipv4() { "IPv4" } else { "IPv6" }
                    )));
                }
            }
            if let Some(cps) = t.cps {
                if !(cps.is_finite() && cps > 0.0) {
                    return Err(Error::Tcp(format!(
                        "{what}: connections per second must be more than 0, not {cps}"
                    )));
                }
            } else if !t.model.is_steady() {
                return Err(Error::Tcp(format!(
                    "{what}: a traffic model needs the template's own cps"
                )));
            }
            t.model
                .validate()
                .map_err(|e| Error::Tcp(format!("{what}: {e}")))?;
            if client.is_some() && t.connect.port() == 0 {
                return Err(Error::Tcp(format!("{what}: connect to port 0")));
            }
            if server.is_some() {
                if let Some(j) = listen.insert(t.listen_port, i) {
                    return Err(Error::Tcp(format!(
                        "templates {} and {} both listen on port {}; the server tells \
                         templates apart by port",
                        templates[j].name, t.name, t.listen_port
                    )));
                }
            }
        }
        let mut hosts = Vec::new();
        if let Some(c) = &client {
            c.endpoint.validate("client")?;
            if !(c.cps.is_finite() && c.cps > 0.0) {
                return Err(Error::Tcp(format!(
                    "connections per second must be more than 0, not {}",
                    c.cps
                )));
            }
            c.model.validate().map_err(|e| Error::Tcp(e.to_string()))?;
            if c.source_ports.is_empty() || c.source_ports.start == 0 {
                return Err(Error::Tcp("the source port range is empty".into()));
            }
            if templates.iter().all(|t| t.weight == 0) {
                return Err(Error::Tcp(
                    "every template has weight 0: the client has nothing to open".into(),
                ));
            }
            // The next hops to resolve: the gateway, or the servers on the link.
            let mut hops: Vec<(IpAddr, Option<MacAddr>)> = Vec::new();
            for t in templates.iter().filter(|t| t.weight > 0) {
                for n in 0..u64::from(t.connect_ips) {
                    let hop = c.endpoint.next_hop(t.nth_server(n));
                    if !hops.iter().any(|(h, _)| *h == hop) {
                        if hops.len() == MAX_HOPS {
                            return Err(Error::Tcp(format!(
                                "the client reaches more than {MAX_HOPS} servers directly; \
                                 give it a gateway"
                            )));
                        }
                        hops.push((hop, c.endpoint.next_hop_mac));
                    }
                }
            }
            hosts.push(Host::new(TcpRole::Client, c.endpoint.clone(), hops));
        }
        if let Some(s) = &server {
            s.endpoint.validate("server")?;
            if let Some(c) = &client {
                let (a, b) = (&c.endpoint, &s.endpoint);
                let overlap =
                    a.port == b.port && a.vlan == b.vlan && (a.owns(b.ip) || b.owns(a.ip));
                if overlap {
                    return Err(Error::Tcp(
                        "the client and the server share an address on the same port and VLAN"
                            .into(),
                    ));
                }
                if a.port == b.port && a.vlan == b.vlan && a.mac == b.mac {
                    return Err(Error::Tcp(format!(
                        "the client and the server both use MAC {} on the same port and VLAN; \
                         give one of them another MAC",
                        a.mac
                    )));
                }
            }
            hosts.push(Host::new(TcpRole::Server, s.endpoint.clone(), Vec::new()));
        }
        let seed = options.seed | 1;
        let shared: Vec<Shared> = templates
            .iter()
            .map(|t| Shared::new(&t.program, options.clone()))
            .collect();
        let stats = TcpStats {
            templates: templates
                .iter()
                .map(|t| TcpTemplateStats {
                    name: t.name.clone(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        Ok(Self {
            shared: shared.into(),
            wrr: vec![0; templates.len()],
            opened: vec![0; templates.len()],
            tpl_clock: templates
                .iter()
                .map(|t| t.cps.map(|cps| EventClock::new(cps, &t.model)))
                .collect(),
            conn_clock: client.as_ref().map_or_else(
                || EventClock::new(1.0, &TrafficModel::default()),
                |c| EventClock::new(c.cps, &c.model),
            ),
            templates,
            listen,
            client,
            server,
            hosts,
            conns: HashMap::new(),
            timers: BinaryHeap::new(),
            out: Vec::new(),
            ip_id: 0,
            stats,
            rng: Rng(seed),
            port_cursor: 0,
            next_timer_scan: Duration::ZERO,
            error: None,
            started: false,
        })
    }

    /// The templates, in the order of [`TcpStats::templates`].
    pub fn templates(&self) -> &[TcpTemplate] {
        &self.templates
    }

    /// The MAC addresses of the emulated hosts on port `port`: the frames the
    /// port must receive, besides broadcasts and multicasts.
    pub fn port_macs(&self, port: usize) -> Vec<MacAddr> {
        let mut macs: Vec<MacAddr> = Vec::new();
        for h in self.hosts.iter().filter(|h| h.ep.port == port) {
            if !macs.contains(&h.ep.mac) {
                macs.push(h.ep.mac);
            }
        }
        macs
    }

    pub fn stats(&self) -> &TcpStats {
        &self.stats
    }

    /// Sets the elapsed time and stop flag in the counters.
    pub fn set_elapsed(&mut self, elapsed: Duration, stopped: bool) {
        self.stats.elapsed = elapsed;
        self.stats.stopped = stopped;
    }

    /// Frames to send, as (port, frame). Empties the queue.
    pub fn take_output(&mut self) -> Vec<(usize, Vec<u8>)> {
        let out = std::mem::take(&mut self.out);
        for (_, f) in &out {
            self.stats.tx_packets += 1;
            self.stats.tx_bytes += f.len() as u64;
        }
        out
    }

    /// The error that stopped the engine, such as an ARP request nobody answered.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// True when the client has opened all its connections (or its traffic
    /// model's ramp has ended) and they, and the server's, have ended. Never true without a client or with an endless one.
    pub fn is_done(&self) -> bool {
        let Some(c) = &self.client else {
            return false;
        };
        let all = c.connections > 0 && self.stats.client.started >= c.connections;
        // Or every template that opens connections has opened all of its own,
        // or its traffic model's ramp has ended.
        let each = self.templates.iter().enumerate().all(|(i, t)| {
            t.weight == 0
                || (t.connections > 0 && self.opened[i] >= t.connections)
                || self.tpl_clock[i]
                    .as_ref()
                    .unwrap_or(&self.conn_clock)
                    .ended()
        });
        (all || each) && self.conns.values().all(|k| k.state == State::TimeWait)
    }

    /// Connections open now, both sides.
    pub fn open_connections(&self) -> usize {
        self.conns
            .values()
            .filter(|c| c.state != State::TimeWait)
            .count()
    }

    /// Handles one frame received on `port`.
    pub fn handle_frame(&mut self, port: usize, frame: &[u8], now: Duration) {
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += frame.len() as u64;
        let Some(link) = wire::parse_link(frame) else {
            return;
        };
        let payload = &frame[link.payload..];
        match link.ethertype {
            wire::ETHERTYPE_ARP => {
                hosts::on_arp(&mut self.hosts, &mut self.out, port, &link, payload)
            }
            ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => self.on_ip(port, &link, payload, now),
            _ => {}
        }
    }

    fn on_ip(&mut self, port: usize, link: &wire::Link, payload: &[u8], now: Duration) {
        let Some(ip) = wire::parse_ip(payload, true) else {
            return;
        };
        if (link.ethertype == ETHERTYPE_IPV4) != ip.src.is_ipv4() {
            return;
        }
        if ip.proto == IPPROTO_ICMPV6 && ip.src.is_ipv6() {
            if let Some(nd) = wire::parse_ndp(&ip) {
                hosts::on_ndp(&mut self.hosts, &mut self.out, port, link, &ip, &nd);
                return;
            }
        }
        let Some(h) = self.hosts.iter().position(|h| {
            h.ep.port == port && h.ep.vlan == link.vlan && h.ep.mac == link.dst && h.ep.owns(ip.dst)
        }) else {
            return;
        };
        let path = Path {
            src_mac: self.hosts[h].ep.mac,
            dst_mac: link.src,
            vlan: link.vlan,
            src: ip.dst,
            dst: ip.src,
        };
        match ip.proto {
            1 | IPPROTO_ICMPV6 => {
                self.ip_id = self.ip_id.wrapping_add(1);
                if let Some(f) = wire::icmp_echo_reply(&path, ip.payload, self.ip_id) {
                    self.out.push((port, f));
                }
            }
            6 => {
                if let Some(seg) = wire::parse_tcp(&ip, true) {
                    self.on_tcp(h, port, path, &seg, now);
                }
            }
            _ => {}
        }
    }

    fn on_tcp(&mut self, host: usize, port: usize, path: Path, seg: &Segment, now: Duration) {
        let key = (
            SocketAddr::new(path.src, seg.dport),
            SocketAddr::new(path.dst, seg.sport),
        );
        let shared = self.shared.clone();
        let mut out = Out {
            frames: &mut self.out,
            ip_id: &mut self.ip_id,
            stats: &mut self.stats,
        };
        let role = self.hosts[host].role;
        // A new SYN on the ports of a connection in TIME_WAIT starts a new one.
        if seg.has(SYN) && !seg.has(ACK) && role == TcpRole::Server {
            if let Some(c) = self.conns.get(&key) {
                if c.state == State::TimeWait {
                    self.conns.remove(&key);
                }
            }
        }
        if let Some(conn) = self.conns.get_mut(&key) {
            if conn.on_segment(&shared[conn.tpl], &mut out, seg, now) == Fate::Remove {
                if let Some(c) = self.conns.remove(&key) {
                    if !c.counted {
                        out.add(c.role, c.tpl, |s| s.active = s.active.saturating_sub(1));
                    }
                }
            } else {
                schedule(&mut self.timers, key, conn, &shared[conn.tpl].options);
            }
            return;
        }
        let listening = match &self.server {
            Some(_) if role == TcpRole::Server => self.listen.get(&seg.dport).copied(),
            _ => None,
        };
        if let (Some(tpl), true) = (listening, seg.has(SYN) && !seg.has(ACK) && !seg.has(RST)) {
            let iss = self.rng.next();
            let ts_offset = self.rng.next();
            let opts = &shared[tpl].options;
            let mut conn = Conn::new(
                ConnInit {
                    role,
                    tpl,
                    port,
                    path,
                    lport: seg.dport,
                    rport: seg.sport,
                    state: State::SynRcvd,
                    mss: usize::from(mss_for(path.src, opts.mss)),
                    iss,
                    ts_offset,
                },
                opts,
                now,
            );
            conn.negotiate(seg);
            conn.send_syn(opts, &mut out, now);
            out.add(role, tpl, |s| {
                s.started += 1;
                s.active += 1;
            });
            schedule(&mut self.timers, key, &mut conn, opts);
            self.conns.insert(key, conn);
            return;
        }
        if !seg.has(RST) {
            // Nobody here: reset, as a host would.
            let h = if seg.has(ACK) {
                TcpHeader {
                    sport: seg.dport,
                    dport: seg.sport,
                    seq: seg.ack,
                    ack: 0,
                    flags: RST,
                    window: 0,
                    opts: TcpOpts::default(),
                }
            } else {
                TcpHeader {
                    sport: seg.dport,
                    dport: seg.sport,
                    seq: 0,
                    ack: seg.seq.wrapping_add(seg.seq_len()),
                    flags: RST | ACK,
                    window: 0,
                    opts: TcpOpts::default(),
                }
            };
            out.segment(port, &path, &h, &[]);
        }
    }

    /// Runs timers, resolves the client's next hop and opens new connections.
    pub fn poll(&mut self, now: Duration) {
        if self.error.is_some() {
            return;
        }
        if !self.started {
            self.started = true;
            self.conn_clock.start(now);
            for clock in self.tpl_clock.iter_mut().flatten() {
                clock.start(now);
            }
        }
        let timeout = self.shared[0].options.arp_timeout;
        self.error = hosts::resolve(&mut self.hosts, &mut self.out, now, timeout);
        if self.error.is_some() {
            return;
        }
        if now >= self.next_timer_scan {
            self.next_timer_scan = now + TIMER_TICK;
            self.run_timers(now);
        }
        self.open_connections_due(now);
    }

    fn run_timers(&mut self, now: Duration) {
        let shared = self.shared.clone();
        let mut out = Out {
            frames: &mut self.out,
            ip_id: &mut self.ip_id,
            stats: &mut self.stats,
        };
        while let Some(&Reverse((at, key))) = self.timers.peek() {
            if at > now {
                break;
            }
            self.timers.pop();
            let Some(c) = self.conns.get_mut(&key) else {
                continue; // gone
            };
            if c.scheduled != at {
                continue; // queued again since, for another time
            }
            c.scheduled = Duration::MAX;
            let sh = &shared[c.tpl];
            if c.on_timer(sh, &mut out, now) == Fate::Keep {
                // Something still due (a message that cannot go yet) is
                // looked at again on the next tick.
                let wake = c.next_wake(&sh.options).max(now + TIMER_TICK);
                c.scheduled = wake;
                self.timers.push(Reverse((wake, key)));
            } else if let Some(c) = self.conns.remove(&key) {
                if !c.counted {
                    out.add(c.role, c.tpl, |s| s.active = s.active.saturating_sub(1));
                }
            }
        }
    }

    /// True if template `tpl` may open a connection now, by its own limits.
    fn template_ready(&self, tpl: usize) -> bool {
        let t = &self.templates[tpl];
        t.weight > 0
            && (t.connections == 0 || self.opened[tpl] < t.connections)
            && (t.concurrency == 0
                || (self.stats.templates[tpl].client.active as usize) < t.concurrency)
    }

    /// True if template `tpl` has opened all its connections.
    fn template_exhausted(&self, tpl: usize) -> bool {
        let t = &self.templates[tpl];
        t.weight == 0 || (t.connections > 0 && self.opened[tpl] >= t.connections)
    }

    fn open_connections_due(&mut self, now: Duration) {
        let Some(client) = &self.client else { return };
        let Some(host) = self.hosts.iter().find(|h| h.role == TcpRole::Client) else {
            return;
        };
        if !host.resolved() {
            return;
        }
        let ep = host.ep.clone();
        let (connections, concurrency) = (client.connections, client.concurrency);
        let ports = client.source_ports.clone();
        // The run-wide limits, for all templates together.
        let room = |e: &Self| {
            !(connections > 0 && e.stats.client.started >= connections)
                && !(concurrency > 0 && e.stats.client.active as usize >= concurrency)
        };

        // Templates with their own rate, each on its own schedule.
        for tpl in 0..self.templates.len() {
            let mut opened = 0;
            while self.tpl_clock[tpl].as_ref().is_some_and(|c| c.due(now))
                && opened < 256
                && !self.template_exhausted(tpl)
            {
                if !room(self) || !self.template_ready(tpl) {
                    // Do not save up connections while at a limit.
                    if let Some(c) = &mut self.tpl_clock[tpl] {
                        c.hold(now);
                    }
                    break;
                }
                if !self.open_one(tpl, &ep, &ports, now) {
                    break;
                }
                if let Some(c) = &mut self.tpl_clock[tpl] {
                    c.advance();
                }
                opened += 1;
            }
        }

        // The others share the client's rate, by weight.
        let shared: Vec<usize> = (0..self.templates.len())
            .filter(|&i| self.templates[i].cps.is_none() && !self.template_exhausted(i))
            .collect();
        if shared.is_empty() {
            return;
        }
        let mut opened = 0;
        while self.conn_clock.due(now) && opened < 256 {
            if connections > 0 && self.stats.client.started >= connections {
                return;
            }
            let ready: Vec<usize> = shared
                .iter()
                .copied()
                .filter(|&i| self.template_ready(i))
                .collect();
            if !room(self) || ready.is_empty() {
                if shared.iter().all(|&i| self.template_exhausted(i)) {
                    return;
                }
                // Do not save up connections while at the limit.
                self.conn_clock.hold(now);
                return;
            }
            let tpl = self.pick_template(&ready);
            if !self.open_one(tpl, &ep, &ports, now) {
                // Undo the pick, so the mix stays as weighted.
                self.unpick_template(tpl, &ready);
                return;
            }
            self.conn_clock.advance();
            opened += 1;
        }
    }

    /// The template of the next connection, from `ready`: smooth weighted
    /// round robin, so the weights hold over any stretch of connections, not
    /// only on average.
    fn pick_template(&mut self, ready: &[usize]) -> usize {
        let total: i64 = ready
            .iter()
            .map(|&i| i64::from(self.templates[i].weight))
            .sum();
        let mut best = ready[0];
        for &i in ready {
            self.wrr[i] += i64::from(self.templates[i].weight);
            if self.wrr[i] > self.wrr[best] {
                best = i;
            }
        }
        self.wrr[best] -= total;
        best
    }

    fn unpick_template(&mut self, tpl: usize, ready: &[usize]) {
        let total: i64 = ready
            .iter()
            .map(|&i| i64::from(self.templates[i].weight))
            .sum();
        self.wrr[tpl] += total;
        for &i in ready {
            self.wrr[i] -= i64::from(self.templates[i].weight);
        }
    }

    fn open_one(
        &mut self,
        tpl: usize,
        ep: &TcpEndpoint,
        ports: &Range<u16>,
        now: Duration,
    ) -> bool {
        let t = &self.templates[tpl];
        let connect = SocketAddr::new(t.nth_server(self.opened[tpl]), t.connect.port());
        let hop = ep.next_hop(connect.ip());
        let Some(mac) = self.hosts[0].hop_mac(hop) else {
            return false;
        };
        let span = u64::from(ports.end - ports.start);
        let count = u64::from(ep.ip_count);
        let mut found = None;
        for _ in 0..(span * count).min(1 << 20) {
            let k = self.port_cursor;
            self.port_cursor = self.port_cursor.wrapping_add(1);
            let ip = ep.nth_ip((k % count) as u32);
            let port = ports.start + ((k / count) % span) as u16;
            let key = (SocketAddr::new(ip, port), connect);
            if !self.conns.contains_key(&key) {
                found = Some(key);
                break;
            }
        }
        let Some(key) = found else {
            // Every source address and port is in use.
            return false;
        };
        self.opened[tpl] += 1;
        let opts = &self.shared[tpl].options;
        let iss = self.rng.next();
        let ts_offset = self.rng.next();
        let mut conn = Conn::new(
            ConnInit {
                role: TcpRole::Client,
                tpl,
                port: ep.port,
                path: Path {
                    src_mac: ep.mac,
                    dst_mac: mac,
                    vlan: ep.vlan,
                    src: key.0.ip(),
                    dst: connect.ip(),
                },
                lport: key.0.port(),
                rport: connect.port(),
                state: State::SynSent,
                mss: usize::from(mss_for(connect.ip(), opts.mss)),
                iss,
                ts_offset,
            },
            opts,
            now,
        );
        let mut out = Out {
            frames: &mut self.out,
            ip_id: &mut self.ip_id,
            stats: &mut self.stats,
        };
        conn.send_syn(opts, &mut out, now);
        out.add(TcpRole::Client, tpl, |s| {
            s.started += 1;
            s.active += 1;
        });
        schedule(&mut self.timers, key, &mut conn, opts);
        self.conns.insert(key, conn);
        true
    }
}

impl std::fmt::Debug for TcpEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpEngine")
            .field("connections", &self.conns.len())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}
