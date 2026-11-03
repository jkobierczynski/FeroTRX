//! Turning a TCP session in a capture into a program both ends can play.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::ops::Range;
use std::time::Duration;

use super::wire::{self, FIN, RST, SYN};
use crate::net::{ETHERTYPE_IPV4, ETHERTYPE_IPV6};
use crate::{Capture, Error, Result, LINKTYPE_ETHERNET};

/// Which end of a TCP connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TcpRole {
    /// The end that opens the connection (sends the SYN).
    Client,
    /// The end that listens and accepts.
    Server,
}

impl TcpRole {
    pub fn peer(self) -> TcpRole {
        match self {
            TcpRole::Client => TcpRole::Server,
            TcpRole::Server => TcpRole::Client,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            TcpRole::Client => "client",
            TcpRole::Server => "server",
        }
    }

    fn index(self) -> usize {
        match self {
            TcpRole::Client => 0,
            TcpRole::Server => 1,
        }
    }
}

impl fmt::Display for TcpRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One application message: bytes one end sends before it waits for the other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpMessage {
    pub from: TcpRole,
    pub data: Vec<u8>,
}

impl TcpMessage {
    pub fn new(from: TcpRole, data: impl Into<Vec<u8>>) -> Self {
        Self {
            from,
            data: data.into(),
        }
    }
}

/// What a TCP connection carries, in order, as both ends replay it.
///
/// Like a TRex ASTF program, it is a list of messages: the client sends its
/// first message, the server waits until it has all of it and sends its answer,
/// and so on. Then the end that closed first in the capture sends its FIN.
/// The two ends play it over a real TCP connection (handshake, sequence and
/// acknowledgement numbers, retransmits), so a NAT router or firewall in
/// between sees a real session.
///
/// ```
/// use ferotrx_core::{TcpMessage, TcpProgram, TcpRole};
///
/// let program = TcpProgram::new(80, vec![
///     TcpMessage::new(TcpRole::Client, "GET / HTTP/1.1\r\n\r\n"),
///     TcpMessage::new(TcpRole::Server, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
/// ]);
/// assert_eq!(program.bytes(TcpRole::Client), 18);
/// assert_eq!(program.closer, TcpRole::Client);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpProgram {
    /// The client's address in the capture, if the program came from one.
    pub client: Option<SocketAddr>,
    /// The server's address in the capture, if the program came from one.
    pub server: Option<SocketAddr>,
    /// The port the server listens on.
    pub server_port: u16,
    pub messages: Vec<TcpMessage>,
    /// The end that sends the first FIN.
    pub closer: TcpRole,
    /// Bytes the capture did not hold but the other end acknowledged, so their
    /// length is known; they are replayed as zeros. This happens when only one
    /// direction was captured.
    pub inferred_bytes: u64,
}

impl TcpProgram {
    /// A program from messages; the client closes.
    pub fn new(server_port: u16, messages: Vec<TcpMessage>) -> Self {
        let mut p = Self {
            client: None,
            server: None,
            server_port,
            messages: Vec::new(),
            closer: TcpRole::Client,
            inferred_bytes: 0,
        };
        for m in messages {
            p.push(m);
        }
        p
    }

    /// Sets which end closes first.
    pub fn with_closer(mut self, closer: TcpRole) -> Self {
        self.closer = closer;
        self
    }

    /// Adds a message, joining it to the last one if it is from the same end.
    fn push(&mut self, m: TcpMessage) {
        if m.data.is_empty() {
            return;
        }
        match self.messages.last_mut() {
            Some(last) if last.from == m.from => last.data.extend_from_slice(&m.data),
            _ => self.messages.push(m),
        }
    }

    /// Bytes `role` sends over the whole connection.
    pub fn bytes(&self, role: TcpRole) -> u64 {
        self.messages
            .iter()
            .filter(|m| m.from == role)
            .map(|m| m.data.len() as u64)
            .sum()
    }

    /// Everything `role` sends, joined.
    pub fn stream(&self, role: TcpRole) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.bytes(role) as usize);
        for m in self.messages.iter().filter(|m| m.from == role) {
            out.extend_from_slice(&m.data);
        }
        out
    }

    /// The TCP connections in a capture, in the order they first appear.
    pub fn flows(capture: &Capture) -> Result<Vec<TcpFlow>> {
        Ok(collect(capture)?.into_iter().map(|f| f.info).collect())
    }

    /// The program of one connection in a capture: `flow` is its index in
    /// [`flows`](Self::flows), or `None` for the first one that carries data.
    ///
    /// Both directions are reassembled by sequence number, so retransmitted and
    /// reordered segments do not matter. When only one direction was captured,
    /// the other one's bytes are inferred from the acknowledgements (see
    /// [`inferred_bytes`](Self::inferred_bytes)).
    pub fn from_capture(capture: &Capture, flow: Option<usize>) -> Result<Self> {
        let flows = collect(capture)?;
        if flows.is_empty() {
            return Err(Error::Tcp("the capture has no IPv4 TCP connections".into()));
        }
        let chosen = match flow {
            Some(i) => flows.get(i).ok_or_else(|| {
                Error::Tcp(format!(
                    "there is no TCP connection {} in the capture; it has {}",
                    i + 1,
                    flows.len()
                ))
            })?,
            None => flows
                .iter()
                .find(|f| f.info.client_bytes + f.info.server_bytes > 0)
                .ok_or_else(|| {
                    Error::Tcp("no TCP connection in the capture carries data".into())
                })?,
        };
        Ok(chosen.program())
    }
}

/// A TCP connection found in a capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpFlow {
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub packets: u64,
    /// Payload bytes the client sent, inferred bytes included.
    pub client_bytes: u64,
    pub server_bytes: u64,
    /// True when the capture has the client's SYN.
    pub handshake: bool,
    /// When the first packet was captured, from the start of the capture.
    pub start: Duration,
    /// Number of application messages, counting both directions.
    pub messages: usize,
}

impl fmt::Display for TcpFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} -> {}: {} packets, {} messages, {} bytes from the client, {} from the server",
            self.client,
            self.server,
            self.packets,
            self.messages,
            self.client_bytes,
            self.server_bytes
        )?;
        if !self.handshake {
            f.write_str(" (no SYN captured)")?;
        }
        Ok(())
    }
}

/// One captured segment of a connection.
struct Seen {
    ts: Duration,
    from_a: bool,
    seq: u32,
    ack: u32,
    flags: u8,
    data: Vec<u8>,
}

struct Flow {
    /// The end that sent the first packet, as (ip, port).
    a: SocketAddr,
    b: SocketAddr,
    segments: Vec<Seen>,
    info: TcpFlow,
}

fn collect(capture: &Capture) -> Result<Vec<Flow>> {
    let first_ts = capture
        .packets
        .first()
        .map_or(Duration::ZERO, |p| p.timestamp);
    let mut flows: Vec<Flow> = Vec::new();
    let mut index: HashMap<(SocketAddr, SocketAddr), usize> = HashMap::new();
    for p in &capture.packets {
        let Some(ip_at) = ip_offset(capture.linktype, &p.data) else {
            continue;
        };
        let Some(ip) = wire::parse_ip(&p.data[ip_at..], false) else {
            continue;
        };
        if ip.proto != 6 {
            continue;
        }
        let Some(seg) = wire::parse_tcp(&ip, false) else {
            continue;
        };
        let src = SocketAddr::new(ip.src, seg.sport);
        let dst = SocketAddr::new(ip.dst, seg.dport);
        let key = if src <= dst { (src, dst) } else { (dst, src) };
        let i = *index.entry(key).or_insert_with(|| {
            flows.push(Flow {
                a: src,
                b: dst,
                segments: Vec::new(),
                info: TcpFlow {
                    client: src,
                    server: dst,
                    packets: 0,
                    client_bytes: 0,
                    server_bytes: 0,
                    handshake: false,
                    start: p.timestamp.saturating_sub(first_ts),
                    messages: 0,
                },
            });
            flows.len() - 1
        });
        let flow = &mut flows[i];
        // A connection that was closed and opened again on the same ports is a
        // new connection; keep the first one only.
        if seg.has(SYN) && !seg.has(wire::ACK) && flow.segments.iter().any(|s| s.flags & SYN != 0) {
            continue;
        }
        flow.segments.push(Seen {
            ts: p.timestamp,
            from_a: src == flow.a,
            seq: seg.seq,
            ack: seg.ack,
            flags: seg.flags,
            data: seg.data.to_vec(),
        });
    }
    for flow in &mut flows {
        let program = flow.program();
        flow.info.packets = flow.segments.len() as u64;
        flow.info.client = program.client.unwrap_or(flow.a);
        flow.info.server = program.server.unwrap_or(flow.b);
        flow.info.client_bytes = program.bytes(TcpRole::Client);
        flow.info.server_bytes = program.bytes(TcpRole::Server);
        flow.info.messages = program.messages.len();
        flow.info.handshake = flow
            .segments
            .iter()
            .any(|s| s.flags & SYN != 0 && s.flags & wire::ACK == 0);
    }
    Ok(flows)
}

/// Where the IPv4 or IPv6 header starts, for the link types captures commonly use.
fn ip_offset(linktype: u32, data: &[u8]) -> Option<usize> {
    let ip = |et: u16| et == ETHERTYPE_IPV4 || et == ETHERTYPE_IPV6;
    match linktype {
        LINKTYPE_ETHERNET => {
            let link = wire::parse_link(data)?;
            ip(link.ethertype).then_some(link.payload)
        }
        // Raw IP, raw IPv4, raw IPv6.
        101 | 228 | 229 => Some(0),
        // Linux cooked capture (SLL).
        113 => ip(crate::net::be16(data, 14)?).then_some(16),
        // Linux cooked capture v2 (SLL2).
        276 => ip(crate::net::be16(data, 0)?).then_some(20),
        _ => None,
    }
}

/// Bytes of one direction, reassembled by sequence number.
#[derive(Default)]
struct Direction {
    data: Vec<u8>,
    /// For each byte, whether the capture held it.
    have: Vec<bool>,
    /// (time, end offset): by `time`, bytes up to `end` had been sent.
    marks: Vec<(Duration, usize)>,
    fin: Option<(Duration, usize)>,
}

/// Largest stream offset accepted, so a bogus sequence number cannot make us
/// allocate gigabytes.
const MAX_STREAM: usize = 64 << 20;

impl Direction {
    fn put(&mut self, at: usize, bytes: &[u8]) {
        let end = at + bytes.len();
        if end > self.data.len() {
            self.data.resize(end, 0);
            self.have.resize(end, false);
        }
        self.data[at..end].copy_from_slice(bytes);
        self.have[at..end].fill(true);
    }

    fn reach(&mut self, end: usize) {
        if end > self.data.len() {
            self.data.resize(end, 0);
            self.have.resize(end, false);
        }
    }

    fn inferred(&self) -> u64 {
        self.have.iter().filter(|h| !**h).count() as u64
    }
}

impl Flow {
    fn program(&self) -> TcpProgram {
        // The client is the end that sent a SYN without ACK; failing that the
        // end that received the SYN-ACK; failing that the first sender.
        let a_is_client = self
            .segments
            .iter()
            .find(|s| s.flags & SYN != 0)
            .is_none_or(|s| s.from_a == (s.flags & wire::ACK == 0));
        let (client, server) = if a_is_client {
            (self.a, self.b)
        } else {
            (self.b, self.a)
        };
        let from_client = |s: &Seen| s.from_a == a_is_client;

        // The first sequence number of each direction's data.
        let base = |client_side: bool| -> Option<u32> {
            let mine = self
                .segments
                .iter()
                .filter(|s| from_client(s) == client_side);
            if let Some(syn) = mine.clone().find(|s| s.flags & SYN != 0) {
                return Some(syn.seq.wrapping_add(1));
            }
            if let Some(first) = mine.clone().next() {
                // The lowest sequence number seen, in sequence space.
                let mut low = first.seq;
                for s in mine {
                    if wire::seq_lt(s.seq, low) {
                        low = s.seq;
                    }
                }
                return Some(low);
            }
            // Nothing from this side: the other side's first acknowledgement.
            self.segments
                .iter()
                .find(|s| from_client(s) != client_side && s.flags & wire::ACK != 0)
                .map(|s| s.ack)
        };
        let bases = [base(true), base(false)];
        let mut dirs = [Direction::default(), Direction::default()];
        let captured = [true, false].map(|c| self.segments.iter().any(|s| from_client(s) == c));

        for s in &self.segments {
            let d = usize::from(!from_client(s));
            let Some(b) = bases[d] else { continue };
            let syn = u32::from(s.flags & SYN != 0);
            let rel = s.seq.wrapping_add(syn).wrapping_sub(b) as usize;
            if !s.data.is_empty() && rel + s.data.len() <= MAX_STREAM {
                dirs[d].put(rel, &s.data);
                dirs[d].marks.push((s.ts, rel + s.data.len()));
            }
            if s.flags & FIN != 0 {
                let at = rel + s.data.len();
                if at <= MAX_STREAM && dirs[d].fin.is_none() {
                    dirs[d].fin = Some((s.ts, at));
                }
            }
            // What this segment acknowledges tells how far the other side got.
            let o = 1 - d;
            if s.flags & wire::ACK != 0 && s.flags & RST == 0 {
                if let Some(ob) = bases[o] {
                    let mut end = s.ack.wrapping_sub(ob) as usize;
                    if let Some((_, fin_at)) = dirs[o].fin {
                        end = end.min(fin_at);
                    }
                    // When the other direction was not captured, an acknowledgement
                    // one past its bytes, after this side sent its FIN, is for the
                    // other side's FIN.
                    if !captured[o]
                        && dirs[o].fin.is_none()
                        && dirs[d].fin.is_some()
                        && end == dirs[o].data.len() + 1
                    {
                        dirs[o].fin = Some((s.ts, end - 1));
                    } else if end > 0 && end <= MAX_STREAM {
                        dirs[o].reach(end);
                        dirs[o].marks.push((s.ts, end));
                    }
                }
            }
        }
        // A FIN acknowledged above its data counts one too many.
        for d in &mut dirs {
            if let Some((_, fin_at)) = d.fin {
                d.data
                    .truncate(fin_at.max(d.have.iter().rposition(|h| *h).map_or(0, |i| i + 1)));
                d.have.truncate(d.data.len());
                for m in &mut d.marks {
                    m.1 = m.1.min(d.data.len());
                }
            }
        }

        // Merge the two directions into messages, by when each byte was first seen.
        let milestones = |d: &Direction| -> Vec<(Duration, usize)> {
            let mut marks = d.marks.clone();
            marks.sort_by_key(|m| m.1);
            let mut out: Vec<(Duration, usize)> = Vec::new();
            let mut t = Duration::ZERO;
            for (ts, end) in marks {
                t = t.max(ts);
                match out.last_mut() {
                    Some(last) if last.1 == end => {}
                    _ => out.push((t, end)),
                }
            }
            // Earliest time each end offset was reached: walking back keeps times
            // from going up when a later segment was captured first.
            for i in (0..out.len().saturating_sub(1)).rev() {
                out[i].0 = out[i].0.min(out[i + 1].0);
            }
            out
        };
        let m = [milestones(&dirs[0]), milestones(&dirs[1])];
        let mut pieces: Vec<(TcpRole, Range<usize>)> = Vec::new();
        let (mut i, mut j, mut done) = (0, 0, [0usize, 0usize]);
        while i < m[0].len() || j < m[1].len() {
            let take_client = match (m[0].get(i), m[1].get(j)) {
                (Some(c), Some(s)) => c.0 <= s.0,
                (Some(_), None) => true,
                _ => false,
            };
            let (role, mark) = if take_client {
                i += 1;
                (TcpRole::Client, m[0][i - 1])
            } else {
                j += 1;
                (TcpRole::Server, m[1][j - 1])
            };
            let k = role.index();
            if mark.1 > done[k] {
                pieces.push((role, done[k]..mark.1));
                done[k] = mark.1;
            }
        }

        let mut program = TcpProgram::new(server.port(), Vec::new());
        for (role, range) in pieces {
            program.push(TcpMessage::new(
                role,
                dirs[role.index()].data[range].to_vec(),
            ));
        }
        program.client = Some(client);
        program.server = Some(server);
        program.inferred_bytes = dirs[0].inferred() + dirs[1].inferred();
        program.closer = match (dirs[0].fin, dirs[1].fin) {
            (Some(c), Some(s)) if s.0 < c.0 => TcpRole::Server,
            (None, Some(_)) => TcpRole::Server,
            _ => TcpRole::Client,
        };
        // Without any FIN, a RST from the server means the server ended it.
        if dirs[0].fin.is_none() && dirs[1].fin.is_none() {
            if let Some(rst) = self.segments.iter().find(|s| s.flags & RST != 0) {
                if !from_client(rst) {
                    program.closer = TcpRole::Server;
                }
            }
        }
        program
    }
}

impl fmt::Display for TcpProgram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let (Some(c), Some(s)) = (self.client, self.server) {
            write!(f, "{c} -> {s}: ")?;
        } else {
            write!(f, "port {}: ", self.server_port)?;
        }
        write!(
            f,
            "{} messages, {} bytes from the client, {} from the server, {} closes",
            self.messages.len(),
            self.bytes(TcpRole::Client),
            self.bytes(TcpRole::Server),
            self.closer
        )?;
        if self.inferred_bytes > 0 {
            write!(
                f,
                " ({} bytes not captured, sent as zeros)",
                self.inferred_bytes
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tcp::wire::{tcp_frame, Path, TcpHeader, ACK, PSH};
    use crate::{MacAddr, Packet};

    /// A capture of one HTTP-like session: SYN, SYN-ACK, ACK, request,
    /// response in two segments (the second captured twice), FINs.
    pub fn session(both_ways: bool) -> Capture {
        session_between("10.1.2.20", "10.1.2.80", both_ways)
    }

    /// [`session`] between two given addresses.
    pub fn session_between(c: &str, s: &str, both_ways: bool) -> Capture {
        let c: std::net::IpAddr = c.parse().unwrap();
        let s: std::net::IpAddr = s.parse().unwrap();
        let to_s = Path {
            src_mac: MacAddr([2, 0, 0, 0, 0, 1]),
            dst_mac: MacAddr([2, 0, 0, 0, 0, 2]),
            vlan: None,
            src: c,
            dst: s,
        };
        let to_c = Path {
            src_mac: to_s.dst_mac,
            dst_mac: to_s.src_mac,
            vlan: None,
            src: s,
            dst: c,
        };
        let req = b"GET / HTTP/1.1\r\n\r\n";
        let resp1 = b"HTTP/1.1 200 OK\r\n";
        let resp2 = b"Content-Length: 0\r\n\r\n";
        let (cs, ss) = (1000u32, 5000u32);
        let h = |sport, dport, seq, ack, flags| TcpHeader {
            sport,
            dport,
            seq,
            ack,
            flags,
            window: 65535,
            opts: Default::default(),
        };
        let r1 = resp1.len() as u32;
        let r2 = resp2.len() as u32;
        let q = req.len() as u32;
        let mut pkts = vec![
            (true, tcp_frame(&to_s, &h(40000, 80, cs, 0, SYN), &[], 1)),
            (
                false,
                tcp_frame(&to_c, &h(80, 40000, ss, cs + 1, SYN | ACK), &[], 1),
            ),
            (
                true,
                tcp_frame(&to_s, &h(40000, 80, cs + 1, ss + 1, ACK), &[], 2),
            ),
            (
                true,
                tcp_frame(&to_s, &h(40000, 80, cs + 1, ss + 1, PSH | ACK), req, 3),
            ),
            (
                false,
                tcp_frame(&to_c, &h(80, 40000, ss + 1, cs + 1 + q, ACK), resp1, 2),
            ),
            (
                false,
                tcp_frame(
                    &to_c,
                    &h(80, 40000, ss + 1 + r1, cs + 1 + q, PSH | ACK),
                    resp2,
                    3,
                ),
            ),
            (
                false,
                tcp_frame(
                    &to_c,
                    &h(80, 40000, ss + 1 + r1, cs + 1 + q, PSH | ACK),
                    resp2,
                    4,
                ),
            ),
            (
                true,
                tcp_frame(
                    &to_s,
                    &h(40000, 80, cs + 1 + q, ss + 1 + r1 + r2, ACK),
                    &[],
                    4,
                ),
            ),
            (
                false,
                tcp_frame(
                    &to_c,
                    &h(80, 40000, ss + 1 + r1 + r2, cs + 1 + q, FIN | ACK),
                    &[],
                    5,
                ),
            ),
            (
                true,
                tcp_frame(
                    &to_s,
                    &h(40000, 80, cs + 1 + q, ss + 2 + r1 + r2, FIN | ACK),
                    &[],
                    5,
                ),
            ),
            (
                false,
                tcp_frame(
                    &to_c,
                    &h(80, 40000, ss + 2 + r1 + r2, cs + 2 + q, ACK),
                    &[],
                    6,
                ),
            ),
        ];
        if !both_ways {
            pkts.retain(|p| p.0);
        }
        Capture::new(
            1,
            pkts.into_iter()
                .enumerate()
                .map(|(i, (_, f))| Packet::new(Duration::from_millis(i as u64 * 10), f))
                .collect(),
        )
    }

    #[test]
    fn extracts_a_two_way_session() {
        let cap = session(true);
        let flows = TcpProgram::flows(&cap).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].client.to_string(), "10.1.2.20:40000");
        assert!(flows[0].handshake);
        let p = TcpProgram::from_capture(&cap, None).unwrap();
        assert_eq!(p.server_port, 80);
        assert_eq!(p.messages.len(), 2);
        assert_eq!(p.messages[0].data, b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(
            p.messages[1],
            TcpMessage::new(
                TcpRole::Server,
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            )
        );
        assert_eq!(p.closer, TcpRole::Server);
        assert_eq!(p.inferred_bytes, 0);
    }

    #[test]
    fn extracts_an_ipv6_session() {
        let cap = session_between("fd00::20", "fd00::80", true);
        let flows = TcpProgram::flows(&cap).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].client.to_string(), "[fd00::20]:40000");
        assert_eq!(flows[0].server.to_string(), "[fd00::80]:80");
        let p = TcpProgram::from_capture(&cap, None).unwrap();
        let v4 = TcpProgram::from_capture(&session(true), None).unwrap();
        assert_eq!(p.messages, v4.messages);
        assert_eq!(p.closer, TcpRole::Server);
    }

    #[test]
    fn infers_the_direction_not_captured() {
        let p = TcpProgram::from_capture(&session(false), None).unwrap();
        assert_eq!(p.messages.len(), 2);
        assert_eq!(p.messages[0].data, b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(p.messages[1].from, TcpRole::Server);
        assert_eq!(p.messages[1].data, vec![0u8; 38]);
        assert_eq!(p.inferred_bytes, 38);
    }

    #[test]
    fn sample_web_capture_has_three_flows() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/web.pcap");
        let cap = Capture::from_path(path).unwrap();
        let flows = TcpProgram::flows(&cap).unwrap();
        assert_eq!(flows.len(), 3);
        let p = TcpProgram::from_capture(&cap, Some(1)).unwrap();
        assert!(String::from_utf8_lossy(&p.messages[0].data).starts_with("GET /page1.html"));
        assert_eq!(p.bytes(TcpRole::Server), 4000);
        assert!(TcpProgram::from_capture(&cap, Some(3)).is_err());
    }
}
