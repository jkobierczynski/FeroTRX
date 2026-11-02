//! The TCP engine: emulated hosts that open, play and close TCP connections.
//!
//! The engine does no I/O and reads no clock. It is fed received frames and the
//! current time, and it queues the frames it wants sent; [`run_tcp`](super::run_tcp)
//! connects it to real ports. That keeps it platform free and lets tests run it
//! on a simulated network with a simulated clock.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;

use super::program::{TcpProgram, TcpRole};
use super::wire::{self, Path, Segment, TcpHeader, ACK, BROADCAST, FIN, PSH, RST, SYN};
use crate::net::ETHERTYPE_IPV4;
use crate::{Error, MacAddr, Result};

/// An emulated host: the addresses one end of the connections uses.
///
/// The host answers ARP and ping for its addresses, so routers can reach it.
/// Its addresses must not belong to the machine FeroTRX runs on, or the
/// machine's own TCP stack will answer the connections with resets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpEndpoint {
    /// Index of the port (interface) this host sends and receives on.
    pub port: usize,
    pub mac: MacAddr,
    /// The host's (first) address.
    pub ip: Ipv4Addr,
    /// How many consecutive addresses from `ip` the host owns. A client opens
    /// connections from each in turn.
    pub ip_count: u32,
    /// Prefix length of the host's subnet: other addresses in it are reached
    /// directly, the rest through `gateway`.
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    /// The MAC address of the next hop, if known; skips ARP.
    pub next_hop_mac: Option<MacAddr>,
    /// 802.1Q tag on every frame, and the tag frames must carry to be ours.
    pub vlan: Option<u16>,
}

impl TcpEndpoint {
    /// A host on `port` with one address in a /24, no gateway, no VLAN.
    pub fn new(port: usize, mac: MacAddr, ip: Ipv4Addr) -> Self {
        Self {
            port,
            mac,
            ip,
            ip_count: 1,
            prefix: 24,
            gateway: None,
            next_hop_mac: None,
            vlan: None,
        }
    }

    pub fn with_prefix(mut self, prefix: u8) -> Self {
        self.prefix = prefix;
        self
    }

    pub fn with_gateway(mut self, gateway: Ipv4Addr) -> Self {
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
    pub fn owns(&self, ip: Ipv4Addr) -> bool {
        let (first, ip) = (u32::from(self.ip), u32::from(ip));
        ip.wrapping_sub(first) < self.ip_count
    }

    fn nth_ip(&self, n: u32) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.ip).wrapping_add(n % self.ip_count.max(1)))
    }

    /// The address frames to `dst` go to first: `dst` itself or the gateway.
    pub fn next_hop(&self, dst: Ipv4Addr) -> Ipv4Addr {
        let mask = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix.min(32)))
        };
        let on_link = u32::from(dst) & mask == u32::from(self.ip) & mask;
        match self.gateway {
            Some(gw) if !on_link => gw,
            _ => dst,
        }
    }

    fn validate(&self, what: &str) -> Result<()> {
        if self.ip_count == 0 {
            return Err(Error::Tcp(format!("{what}: ip_count must be at least 1")));
        }
        if self.prefix > 32 {
            return Err(Error::Tcp(format!(
                "{what}: prefix /{} is longer than 32",
                self.prefix
            )));
        }
        if u64::from(u32::from(self.ip)) + u64::from(self.ip_count) > 1 << 32 {
            return Err(Error::Tcp(format!(
                "{what}: address range runs past 255.255.255.255"
            )));
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

/// The client side: opens connections to the server and plays the client's part.
#[derive(Clone, Debug, PartialEq)]
pub struct TcpClientConfig {
    pub endpoint: TcpEndpoint,
    /// Where the client connects to. Usually the server host's address and
    /// the program's port; behind a port forward, the router's address.
    pub connect: SocketAddrV4,
    /// New connections per second.
    pub cps: f64,
    /// Connections to open in all; 0 keeps opening them until the run stops.
    pub connections: u64,
    /// Most connections open at once; 0 is no limit.
    pub concurrency: usize,
    /// Source ports to use, in turn.
    pub source_ports: Range<u16>,
}

impl TcpClientConfig {
    pub fn new(endpoint: TcpEndpoint, connect: SocketAddrV4) -> Self {
        Self {
            endpoint,
            connect,
            cps: 1.0,
            connections: 1,
            concurrency: 0,
            source_ports: 1024..65535,
        }
    }
}

/// The server side: accepts connections and plays the server's part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpServerConfig {
    pub endpoint: TcpEndpoint,
    /// The port to listen on.
    pub port: u16,
}

/// TCP settings shared by both sides.
#[derive(Clone, Debug, PartialEq)]
pub struct TcpOptions {
    /// Maximum segment size announced and used (default 1460).
    pub mss: u16,
    /// First retransmission timeout; doubles on each retry (default 250 ms).
    pub rto: Duration,
    /// Retransmissions before a connection is given up and reset (default 8).
    pub max_retries: u32,
    /// How long the end that closed first keeps answering a repeated FIN
    /// (default 4 s). The source port is not reused meanwhile.
    pub time_wait: Duration,
    /// A connection with nothing received for this long is reset (default 30 s).
    pub idle_timeout: Duration,
    /// How long the client waits for an ARP reply from its next hop (default 5 s).
    pub arp_timeout: Duration,
    /// Check that the bytes each end receives are the ones the program says
    /// (default true). Connections that differ count as `mismatched`.
    pub verify: bool,
    /// Seed for initial sequence numbers.
    pub seed: u64,
}

impl Default for TcpOptions {
    fn default() -> Self {
        Self {
            mss: 1460,
            rto: Duration::from_millis(250),
            max_retries: 8,
            time_wait: Duration::from_secs(4),
            idle_timeout: Duration::from_secs(30),
            arp_timeout: Duration::from_secs(5),
            verify: true,
            seed: 0x5eed_f00d,
        }
    }
}

/// Everything a [`TcpEngine`] does: the program, and a client, a server or both.
#[derive(Clone, Debug)]
pub struct TcpConfig {
    pub program: Arc<TcpProgram>,
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
    /// Segments sent again after a timeout or three duplicate ACKs.
    pub retransmits: u64,
}

impl TcpSideStats {
    /// Connections that ended without completing.
    pub fn failed(&self) -> u64 {
        self.reset + self.timed_out
    }
}

/// Counters of a TCP run.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TcpStats {
    pub client: TcpSideStats,
    pub server: TcpSideStats,
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
    /// Send this range of the own stream.
    Send(Range<usize>),
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
        for m in &program.messages {
            let me = idx(m.from);
            let start = offsets[me];
            offsets[me] += m.data.len();
            actions[me].push(Action::Send(start..offsets[me]));
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
    port: usize,
    path: Path,
    lport: u16,
    rport: u16,
    state: State,
    mss: usize,

    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    snd_wnd: usize,
    cwnd: usize,
    /// Bytes from `snd_una` on, not yet acknowledged.
    snd_buf: VecDeque<u8>,
    fin_queued: bool,
    /// Sequence number of our FIN once sent.
    fin_seq: Option<u32>,
    fin_acked: bool,
    /// True if our FIN went out before the other end's arrived.
    closed_first: bool,

    rcv_nxt: u32,
    fin_rcvd: bool,
    need_ack: bool,
    dup_acks: u32,

    step: usize,
    /// Received bytes not yet taken by a `Recv` action.
    unread: usize,
    rx_total: usize,
    mismatched: bool,

    rto: Duration,
    retries: u32,
    /// Retransmission timer, or the end of TIME_WAIT.
    deadline: Option<Duration>,
    last_rx: Duration,
    counted: bool,
}

type Key = (SocketAddrV4, SocketAddrV4);

struct Out<'a> {
    frames: &'a mut Vec<(usize, Vec<u8>)>,
    ip_id: &'a mut u16,
    stats: &'a mut TcpStats,
}

impl Out<'_> {
    fn side(&mut self, role: TcpRole) -> &mut TcpSideStats {
        match role {
            TcpRole::Client => &mut self.stats.client,
            TcpRole::Server => &mut self.stats.server,
        }
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

impl Conn {
    fn header(&self, seq: u32, flags: u8) -> TcpHeader {
        TcpHeader {
            sport: self.lport,
            dport: self.rport,
            seq,
            ack: if flags & ACK != 0 { self.rcv_nxt } else { 0 },
            flags,
            window: u16::MAX,
            mss: None,
        }
    }

    fn send_syn(&self, out: &mut Out, mss: u16) {
        let mut h = self.header(
            self.iss,
            if self.state == State::SynRcvd {
                SYN | ACK
            } else {
                SYN
            },
        );
        h.mss = Some(mss);
        out.segment(self.port, &self.path, &h, &[]);
    }

    fn send_rst(&self, out: &mut Out) {
        let h = self.header(self.snd_nxt, RST | ACK);
        out.segment(self.port, &self.path, &h, &[]);
    }

    /// Bytes of `snd_buf` already sent.
    fn sent_off(&self) -> usize {
        if self.fin_seq.is_some() {
            self.snd_buf.len()
        } else {
            (self.snd_nxt.wrapping_sub(self.snd_una) as usize).min(self.snd_buf.len())
        }
    }

    fn emit_data(&self, out: &mut Out, off: usize, len: usize) {
        let data: Vec<u8> = self.snd_buf.range(off..off + len).copied().collect();
        let mut flags = ACK;
        if off + len == self.snd_buf.len() {
            flags |= PSH;
        }
        let h = self.header(self.snd_una.wrapping_add(off as u32), flags);
        out.segment(self.port, &self.path, &h, &data);
    }

    /// Plays the program as far as it can go now.
    fn advance(&mut self, sh: &Shared, out: &mut Out) {
        let me = idx(self.role);
        loop {
            match sh.actions[me].get(self.step) {
                Some(Action::Send(r)) => {
                    self.snd_buf.extend(&sh.streams[me][r.clone()]);
                    out.side(self.role).payload_tx += r.len() as u64;
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

    /// Sends what the window allows, the FIN when its turn comes, and an ACK if
    /// one is owed and nothing else carried it.
    fn transmit(&mut self, out: &mut Out, now: Duration) {
        if !matches!(self.state, State::Open) {
            return;
        }
        let mut off = self.sent_off();
        let in_flight_limit = self
            .snd_wnd
            .min(self.cwnd)
            .max(if off == 0 { self.mss } else { 0 });
        let mut sent = false;
        while off < self.snd_buf.len() && off < in_flight_limit {
            let len = self
                .mss
                .min(self.snd_buf.len() - off)
                .min(in_flight_limit - off);
            self.emit_data(out, off, len);
            off += len;
            self.snd_nxt = self.snd_una.wrapping_add(off as u32);
            sent = true;
        }
        if self.fin_queued && self.fin_seq.is_none() && off == self.snd_buf.len() {
            let seq = self.snd_una.wrapping_add(off as u32);
            let h = self.header(seq, FIN | ACK);
            out.segment(self.port, &self.path, &h, &[]);
            self.fin_seq = Some(seq);
            self.snd_nxt = seq.wrapping_add(1);
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
        } else if self.need_ack {
            let h = self.header(self.snd_nxt, ACK);
            out.segment(self.port, &self.path, &h, &[]);
            self.need_ack = false;
        }
    }

    fn in_flight(&self) -> bool {
        self.snd_nxt != self.snd_una
    }

    /// Handles a segment for this connection.
    fn on_segment(&mut self, sh: &Shared, out: &mut Out, seg: &Segment, now: Duration) -> Fate {
        self.last_rx = now;
        if seg.has(RST) {
            if !self.counted {
                out.side(self.role).reset += 1;
            }
            return Fate::Remove;
        }
        match self.state {
            State::SynSent => {
                if seg.has(SYN) && seg.has(ACK) && seg.ack == self.iss.wrapping_add(1) {
                    self.rcv_nxt = seg.seq.wrapping_add(1);
                    self.snd_una = seg.ack;
                    self.snd_wnd = usize::from(seg.window);
                    self.mss = self.mss.min(usize::from(seg.mss.unwrap_or(536)));
                    self.establish(sh, out, now);
                    self.need_ack = true;
                    self.advance(sh, out);
                    self.transmit(out, now);
                } else if seg.has(ACK) {
                    // Not for this connection attempt.
                    let h = TcpHeader {
                        sport: self.lport,
                        dport: self.rport,
                        seq: seg.ack,
                        ack: 0,
                        flags: RST,
                        window: 0,
                        mss: None,
                    };
                    out.segment(self.port, &self.path, &h, &[]);
                }
                return Fate::Keep;
            }
            State::SynRcvd => {
                if seg.has(SYN) && !seg.has(ACK) {
                    // Our SYN-ACK was lost.
                    self.send_syn(out, sh.options.mss);
                    return Fate::Keep;
                }
                if !seg.has(ACK) || seg.ack != self.iss.wrapping_add(1) {
                    return Fate::Keep;
                }
                self.snd_una = seg.ack;
                self.snd_wnd = usize::from(seg.window);
                self.establish(sh, out, now);
                self.advance(sh, out);
            }
            State::TimeWait => {
                if seg.has(FIN) {
                    // Our last ACK was lost: send it again and wait longer.
                    let h = self.header(self.snd_nxt, ACK);
                    out.segment(self.port, &self.path, &h, &[]);
                    self.deadline = Some(now + sh.options.time_wait);
                }
                return Fate::Keep;
            }
            State::Open => {}
        }
        if seg.has(SYN) {
            // A repeated SYN-ACK: our ACK was lost.
            self.need_ack = true;
            self.transmit(out, now);
            return Fate::Keep;
        }
        if seg.has(ACK) {
            self.on_ack(sh, out, seg, now);
        }

        let len = seg.data.len() as u32;
        if len > 0 {
            let end = seg.seq.wrapping_add(len);
            if wire::seq_le(seg.seq, self.rcv_nxt)
                && wire::seq_lt(self.rcv_nxt, end)
                && !self.fin_rcvd
            {
                let skip = self.rcv_nxt.wrapping_sub(seg.seq) as usize;
                self.receive(sh, out, &seg.data[skip..]);
                self.rcv_nxt = end;
            }
            self.need_ack = true;
        }
        if seg.has(FIN) {
            let fin_at = seg.seq.wrapping_add(len);
            if !self.fin_rcvd && fin_at == self.rcv_nxt {
                self.fin_rcvd = true;
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            }
            self.need_ack = true;
        }
        self.advance(sh, out);
        self.transmit(out, now);
        self.check_closed(sh, out, now)
    }

    fn establish(&mut self, sh: &Shared, out: &mut Out, now: Duration) {
        self.state = State::Open;
        self.snd_nxt = self.snd_una;
        self.retries = 0;
        self.rto = sh.options.rto;
        self.deadline = None;
        self.last_rx = now;
        out.side(self.role).established += 1;
    }

    fn on_ack(&mut self, sh: &Shared, out: &mut Out, seg: &Segment, now: Duration) {
        self.snd_wnd = usize::from(seg.window);
        let ack = seg.ack;
        if wire::seq_lt(self.snd_una, ack) && wire::seq_le(ack, self.snd_nxt) {
            let acked = ack.wrapping_sub(self.snd_una) as usize;
            let data = acked.min(self.snd_buf.len());
            self.snd_buf.drain(..data);
            if let Some(f) = self.fin_seq {
                if wire::seq_lt(f, ack) {
                    self.fin_acked = true;
                }
            }
            self.snd_una = ack;
            self.dup_acks = 0;
            self.retries = 0;
            self.rto = sh.options.rto;
            self.cwnd = (self.cwnd + data.min(self.mss)).min(1 << 20);
            self.deadline = self.in_flight().then_some(now + self.rto);
        } else if ack == self.snd_una && seg.data.is_empty() && !seg.has(FIN) && self.in_flight() {
            self.dup_acks += 1;
            if self.dup_acks == 3 {
                // Fast retransmit of the first unacknowledged segment.
                out.side(self.role).retransmits += 1;
                if self.snd_buf.is_empty() {
                    if let Some(f) = self.fin_seq {
                        let h = self.header(f, FIN | ACK);
                        out.segment(self.port, &self.path, &h, &[]);
                    }
                } else {
                    let len = self.mss.min(self.snd_buf.len());
                    self.emit_data(out, 0, len);
                }
            }
        }
    }

    fn receive(&mut self, sh: &Shared, out: &mut Out, data: &[u8]) {
        out.side(self.role).payload_rx += data.len() as u64;
        if sh.options.verify && !self.mismatched {
            let expected = &sh.streams[idx(self.role.peer())];
            let start = self.rx_total;
            if expected.get(start..start + data.len()) != Some(data) {
                self.mismatched = true;
            }
        }
        self.rx_total += data.len();
        self.unread += data.len();
    }

    fn check_closed(&mut self, sh: &Shared, out: &mut Out, now: Duration) -> Fate {
        if !(self.fin_rcvd && self.fin_acked) {
            return Fate::Keep;
        }
        self.finish(out);
        if self.closed_first {
            self.state = State::TimeWait;
            self.deadline = Some(now + sh.options.time_wait);
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
        let mismatched = self.mismatched;
        let side = out.side(self.role);
        side.completed += 1;
        side.active = side.active.saturating_sub(1);
        if mismatched {
            side.mismatched += 1;
        }
    }

    /// Runs timers. Returns `Remove` when the connection is over.
    fn on_timer(&mut self, sh: &Shared, out: &mut Out, now: Duration) -> Fate {
        if self.state != State::TimeWait
            && now.saturating_sub(self.last_rx) >= sh.options.idle_timeout
        {
            self.send_rst(out);
            out.side(self.role).timed_out += 1;
            return Fate::Remove;
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
        if self.retries > sh.options.max_retries {
            self.send_rst(out);
            out.side(self.role).timed_out += 1;
            return Fate::Remove;
        }
        out.side(self.role).retransmits += 1;
        self.rto = (self.rto * 2).min(Duration::from_secs(8));
        self.deadline = Some(now + self.rto);
        match self.state {
            State::SynSent | State::SynRcvd => self.send_syn(out, sh.options.mss),
            State::Open => {
                // Go back to the first unacknowledged byte.
                self.snd_nxt = self.snd_una;
                if !self.fin_acked {
                    self.fin_seq = None;
                }
                self.cwnd = 2 * self.mss;
                self.transmit(out, now);
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

struct Host {
    ep: TcpEndpoint,
    role: TcpRole,
    /// The client's next hop and its MAC, once known.
    next_hop: Option<Ipv4Addr>,
    next_hop_mac: Option<MacAddr>,
    arp_next: Duration,
    arp_since: Option<Duration>,
    /// A reply from the next hop seen on the right port but another VLAN
    /// (`Some(None)`: untagged), for the error message if ARP fails.
    arp_elsewhere: Option<Option<u16>>,
}

/// Emulated TCP clients and servers that replay a [`TcpProgram`].
///
/// Feed it received frames with [`handle_frame`](Self::handle_frame), call
/// [`poll`](Self::poll) often, and send what [`take_output`](Self::take_output)
/// returns. [`run_tcp`](super::run_tcp) does this on real ports.
pub struct TcpEngine {
    shared: Arc<Shared>,
    client: Option<TcpClientConfig>,
    server: Option<TcpServerConfig>,
    hosts: Vec<Host>,
    conns: HashMap<Key, Conn>,
    out: Vec<(usize, Vec<u8>)>,
    ip_id: u16,
    stats: TcpStats,
    rng: Rng,
    next_conn_at: Duration,
    port_cursor: u64,
    next_timer_scan: Duration,
    error: Option<String>,
    started: bool,
}

/// How often connection timers are looked at.
const TIMER_TICK: Duration = Duration::from_millis(1);
/// How often an unanswered ARP request is repeated.
const ARP_RETRY: Duration = Duration::from_millis(500);

impl TcpEngine {
    pub fn new(config: TcpConfig) -> Result<Self> {
        let TcpConfig {
            program,
            client,
            server,
            options,
        } = config;
        if client.is_none() && server.is_none() {
            return Err(Error::Tcp("give a client, a server or both".into()));
        }
        if options.mss < 64 {
            return Err(Error::Tcp("mss must be at least 64".into()));
        }
        if options.rto.is_zero() {
            return Err(Error::Tcp("rto must be more than zero".into()));
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
            if c.source_ports.is_empty() || c.source_ports.start == 0 {
                return Err(Error::Tcp("the source port range is empty".into()));
            }
            let hop = c.endpoint.next_hop(*c.connect.ip());
            hosts.push(Host {
                role: TcpRole::Client,
                next_hop: Some(hop),
                next_hop_mac: c.endpoint.next_hop_mac,
                ep: c.endpoint.clone(),
                arp_next: Duration::ZERO,
                arp_since: None,
                arp_elsewhere: None,
            });
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
            }
            hosts.push(Host {
                role: TcpRole::Server,
                next_hop: None,
                next_hop_mac: None,
                ep: s.endpoint.clone(),
                arp_next: Duration::ZERO,
                arp_since: None,
                arp_elsewhere: None,
            });
        }
        let seed = options.seed | 1;
        Ok(Self {
            shared: Arc::new(Shared::new(&program, options)),
            client,
            server,
            hosts,
            conns: HashMap::new(),
            out: Vec::new(),
            ip_id: 0,
            stats: TcpStats::default(),
            rng: Rng(seed),
            next_conn_at: Duration::ZERO,
            port_cursor: 0,
            next_timer_scan: Duration::ZERO,
            error: None,
            started: false,
        })
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

    /// True when the client has opened all its connections and they, and the
    /// server's, have ended. Never true without a client or with an endless one.
    pub fn is_done(&self) -> bool {
        match &self.client {
            Some(c) if c.connections > 0 => {
                self.stats.client.started >= c.connections
                    && self.conns.values().all(|k| k.state == State::TimeWait)
            }
            _ => false,
        }
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
            wire::ETHERTYPE_ARP => self.on_arp(port, &link, payload),
            ETHERTYPE_IPV4 => self.on_ipv4(port, &link, payload, now),
            _ => {}
        }
    }

    fn on_arp(&mut self, port: usize, link: &wire::Link, payload: &[u8]) {
        let Some(arp) = wire::parse_arp(payload) else {
            return;
        };
        for host in &mut self.hosts {
            if host.ep.port != port {
                continue;
            }
            if host.ep.vlan != link.vlan {
                if host.next_hop == Some(arp.sender_ip) && arp.op == 2 {
                    host.arp_elsewhere = Some(link.vlan);
                }
                continue;
            }
            if host.next_hop == Some(arp.sender_ip) && host.ep.next_hop_mac.is_none() {
                host.next_hop_mac = Some(arp.sender_mac);
            }
            if arp.op == 1 && host.ep.owns(arp.target_ip) {
                self.out.push((
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

    fn on_ipv4(&mut self, port: usize, link: &wire::Link, payload: &[u8], now: Duration) {
        let Some(ip) = wire::parse_ipv4(payload, true) else {
            return;
        };
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
            1 => {
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
            SocketAddrV4::new(path.src, seg.dport),
            SocketAddrV4::new(path.dst, seg.sport),
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
            if conn.on_segment(&shared, &mut out, seg, now) == Fate::Remove {
                if let Some(c) = self.conns.remove(&key) {
                    if !c.counted {
                        let side = out.side(c.role);
                        side.active = side.active.saturating_sub(1);
                    }
                }
            }
            return;
        }
        let listening =
            matches!(&self.server, Some(s) if role == TcpRole::Server && s.port == seg.dport);
        if listening && seg.has(SYN) && !seg.has(ACK) && !seg.has(RST) {
            let iss = self.rng.next();
            let opts = &shared.options;
            let conn = Conn {
                role,
                port,
                path,
                lport: seg.dport,
                rport: seg.sport,
                state: State::SynRcvd,
                mss: usize::from(opts.mss.min(seg.mss.unwrap_or(536))),
                iss,
                snd_una: iss,
                snd_nxt: iss.wrapping_add(1),
                snd_wnd: usize::from(seg.window),
                cwnd: 10 * usize::from(opts.mss),
                snd_buf: VecDeque::new(),
                fin_queued: false,
                fin_seq: None,
                fin_acked: false,
                closed_first: false,
                rcv_nxt: seg.seq.wrapping_add(1),
                fin_rcvd: false,
                need_ack: false,
                dup_acks: 0,
                step: 0,
                unread: 0,
                rx_total: 0,
                mismatched: false,
                rto: opts.rto,
                retries: 0,
                deadline: Some(now + opts.rto),
                last_rx: now,
                counted: false,
            };
            conn.send_syn(&mut out, opts.mss);
            let side = out.side(role);
            side.started += 1;
            side.active += 1;
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
                    mss: None,
                }
            } else {
                TcpHeader {
                    sport: seg.dport,
                    dport: seg.sport,
                    seq: 0,
                    ack: seg.seq.wrapping_add(seg.seq_len()),
                    flags: RST | ACK,
                    window: 0,
                    mss: None,
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
            self.next_conn_at = now;
        }
        self.resolve(now);
        if self.error.is_some() {
            return;
        }
        if now >= self.next_timer_scan {
            self.next_timer_scan = now + TIMER_TICK;
            self.run_timers(now);
        }
        self.open_connections_due(now);
    }

    fn resolve(&mut self, now: Duration) {
        let timeout = self.shared.options.arp_timeout;
        for host in &mut self.hosts {
            let Some(hop) = host.next_hop else { continue };
            if host.next_hop_mac.is_some() {
                continue;
            }
            let since = *host.arp_since.get_or_insert(now);
            if now.saturating_sub(since) >= timeout {
                let vlan =
                    |v: Option<u16>| v.map_or("untagged".to_string(), |v| format!("on VLAN {v}"));
                self.error = Some(match host.arp_elsewhere {
                    Some(seen) => format!(
                        "no ARP reply from {hop} (the {}'s next hop) {} within {:?}, but its replies \
                         arrive {}: the switch or interface changes the tag; set the {}'s VLAN to match, \
                         or use a VLAN the switch keeps tagged (VLAN 1 is often sent untagged)",
                        host.role,
                        vlan(host.ep.vlan),
                        timeout,
                        vlan(seen),
                        host.role
                    ),
                    None => format!(
                        "no ARP reply from {hop} (the {}'s next hop) {} within {:?}; \
                         check the gateway address, the VLAN, and that the port can receive",
                        host.role,
                        vlan(host.ep.vlan),
                        timeout
                    ),
                });
                return;
            }
            if now >= host.arp_next {
                host.arp_next = now + ARP_RETRY;
                self.out.push((
                    host.ep.port,
                    wire::arp_frame(
                        BROADCAST,
                        host.ep.vlan,
                        1,
                        host.ep.mac,
                        host.ep.ip,
                        MacAddr([0; 6]),
                        hop,
                    ),
                ));
            }
        }
    }

    fn run_timers(&mut self, now: Duration) {
        let shared = self.shared.clone();
        let mut out = Out {
            frames: &mut self.out,
            ip_id: &mut self.ip_id,
            stats: &mut self.stats,
        };
        self.conns.retain(|_, c| {
            let keep = c.on_timer(&shared, &mut out, now) == Fate::Keep;
            if !keep && !c.counted {
                let side = out.side(c.role);
                side.active = side.active.saturating_sub(1);
            }
            keep
        });
    }

    fn open_connections_due(&mut self, now: Duration) {
        let Some(client) = &self.client else { return };
        let Some(host) = self.hosts.iter().find(|h| h.role == TcpRole::Client) else {
            return;
        };
        let Some(mac) = host.next_hop_mac else { return };
        let interval = Duration::from_secs_f64(1.0 / client.cps);
        let ep = host.ep.clone();
        let (connect, connections, concurrency) =
            (client.connect, client.connections, client.concurrency);
        let ports = client.source_ports.clone();
        let mut opened = 0;
        while self.next_conn_at <= now && opened < 256 {
            if connections > 0 && self.stats.client.started >= connections {
                return;
            }
            if concurrency > 0 && self.stats.client.active as usize >= concurrency {
                // Do not save up connections while at the limit.
                self.next_conn_at = self.next_conn_at.max(now.saturating_sub(interval));
                return;
            }
            if !self.open_one(&ep, mac, connect, &ports, now) {
                return;
            }
            self.next_conn_at += interval;
            opened += 1;
        }
    }

    fn open_one(
        &mut self,
        ep: &TcpEndpoint,
        mac: MacAddr,
        connect: SocketAddrV4,
        ports: &Range<u16>,
        now: Duration,
    ) -> bool {
        let span = u64::from(ports.end - ports.start);
        let count = u64::from(ep.ip_count);
        let mut found = None;
        for _ in 0..(span * count).min(1 << 20) {
            let k = self.port_cursor;
            self.port_cursor = self.port_cursor.wrapping_add(1);
            let ip = ep.nth_ip((k % count) as u32);
            let port = ports.start + ((k / count) % span) as u16;
            let key = (SocketAddrV4::new(ip, port), connect);
            if !self.conns.contains_key(&key) {
                found = Some(key);
                break;
            }
        }
        let Some(key) = found else {
            // Every source address and port is in use.
            return false;
        };
        let opts = &self.shared.options;
        let iss = self.rng.next();
        let conn = Conn {
            role: TcpRole::Client,
            port: ep.port,
            path: Path {
                src_mac: ep.mac,
                dst_mac: mac,
                vlan: ep.vlan,
                src: *key.0.ip(),
                dst: *connect.ip(),
            },
            lport: key.0.port(),
            rport: connect.port(),
            state: State::SynSent,
            mss: usize::from(opts.mss),
            iss,
            snd_una: iss,
            snd_nxt: iss.wrapping_add(1),
            snd_wnd: 0,
            cwnd: 10 * usize::from(opts.mss),
            snd_buf: VecDeque::new(),
            fin_queued: false,
            fin_seq: None,
            fin_acked: false,
            closed_first: false,
            rcv_nxt: 0,
            fin_rcvd: false,
            need_ack: false,
            dup_acks: 0,
            step: 0,
            unread: 0,
            rx_total: 0,
            mismatched: false,
            rto: opts.rto,
            retries: 0,
            deadline: Some(now + opts.rto),
            last_rx: now,
            counted: false,
        };
        let mut out = Out {
            frames: &mut self.out,
            ip_id: &mut self.ip_id,
            stats: &mut self.stats,
        };
        conn.send_syn(&mut out, opts.mss);
        self.stats.client.started += 1;
        self.stats.client.active += 1;
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
