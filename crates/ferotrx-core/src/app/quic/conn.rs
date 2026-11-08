//! A QUIC version 1 connection (RFC 9000, 9001, 9002), sans-IO: datagrams
//! in with [`Conn::recv`], datagrams out with [`Conn::poll_transmit`],
//! timers with [`Conn::timeout`] and [`Conn::on_timeout`], streams for the
//! protocol on top.
//!
//! What it does: the three packet number spaces with their keys from
//! rustls (Initial keys from the client's connection id), header and
//! packet protection, coalesced packets, CRYPTO streams, ACKs (delayed in
//! the application space), loss detection with packet and time thresholds
//! and probe timeouts, NewReno congestion control, the server's
//! anti-amplification limit, streams in both directions with flow control
//! of streams and the connection and stream limits, key updates, idle
//! timeouts, CONNECTION_CLOSE with the closing and draining periods,
//! version negotiation and Retry.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use rustls::quic::{self as rq, DirectionalKeys, KeyChange, Keys, PacketKeySet, Secrets};
use rustls::Side;

use super::frame::{code, error_name, parse_frames, Ack, Frame, Params, RangeSet, Reader};
use crate::app::AppRng;

/// QUIC version 1.
pub const VERSION: u32 = 1;
/// The datagrams this end sends at most (and Initial datagrams at least).
pub const MAX_DATAGRAM: usize = 1200;
/// Our connection ids' length.
pub const CID_LEN: usize = 8;
const TAG: usize = 16;
/// Packet numbers always go in 4 bytes.
const PN_LEN: usize = 4;
const INITIAL_RTT: Duration = Duration::from_millis(333);
const GRANULARITY: Duration = Duration::from_millis(1);
const PACKET_THRESHOLD: u64 = 3;
const MAX_ACK_RANGES: usize = 32;
/// Our `max_ack_delay`.
const ACK_DELAY: Duration = Duration::from_millis(25);
const ACK_DELAY_EXPONENT: u64 = 3;

/// A packet number space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Initial = 0,
    Handshake = 1,
    Data = 2,
}

const LEVELS: [Level; 3] = [Level::Initial, Level::Handshake, Level::Data];

/// The transport settings of one end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuicSettings {
    /// Idle timeout; zero for none (the other end's still counts).
    pub idle_timeout: Duration,
    /// Connection flow control: what the other end may send before we read.
    pub max_data: u64,
    /// Stream flow control: what the other end may send on a stream.
    pub stream_window: u64,
    /// Bidirectional streams the other end may open (then more as they end).
    pub max_streams_bidi: u64,
    /// Unidirectional streams the other end may open.
    pub max_streams_uni: u64,
    /// The first congestion window, in datagrams.
    pub initial_window: u64,
    /// Start a key update after this many packets in a key phase; 0: never
    /// (the other end's are always followed).
    pub key_update_after: u64,
    /// Server: send a Retry first, and take only Initials with its token.
    pub retry: bool,
}

impl Default for QuicSettings {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(30),
            max_data: 16 << 20,
            stream_window: 1 << 20,
            max_streams_bidi: 100,
            max_streams_uni: 3,
            initial_window: 10,
            key_update_after: 0,
            retry: false,
        }
    }
}

/// How a connection ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseInfo {
    /// This end closed it (else the other end did, or it timed out).
    pub local: bool,
    /// An application error code rather than a transport one.
    pub app: bool,
    pub code: u64,
    pub reason: String,
    /// Nothing came for the idle timeout.
    pub idle: bool,
}

impl CloseInfo {
    /// `NO_ERROR`, `PROTOCOL_VIOLATION: bad frame`, `idle timeout`.
    pub fn describe(&self, app_name: impl Fn(u64) -> String) -> String {
        if self.idle {
            return "idle timeout".into();
        }
        let name = if self.app {
            app_name(self.code)
        } else {
            error_name(self.code)
        };
        if self.reason.is_empty() {
            name
        } else {
            format!("{name}: {}", self.reason)
        }
    }

    /// Ended without an error.
    pub fn clean(&self, app_ok: impl Fn(u64) -> bool) -> bool {
        !self.idle
            && if self.app {
                app_ok(self.code)
            } else {
                self.code == code::NO_ERROR
            }
    }
}

/// What happened, for the protocol on top.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The handshake finished.
    Connected,
    /// A stream has data (or its end) to read.
    Readable(u64),
    /// The other end reset a stream it sent on.
    Reset { id: u64, code: u64 },
    /// The other end asks us to stop sending on a stream.
    StopSending { id: u64, code: u64 },
    /// More streams of ours may open.
    StreamsAvailable,
    /// The connection is over (closing or draining starts).
    Closed(CloseInfo),
}

/// An outgoing byte stream with offsets: what is sent, lost and acknowledged.
#[derive(Debug, Default)]
struct SendBuf {
    data: VecDeque<u8>,
    /// The offset of `data[0]`; all below it is acknowledged.
    base: u64,
    /// Bytes not yet sent from here.
    next: u64,
    lost: RangeSet,
    acked: RangeSet,
    fin: bool,
    fin_sent: bool,
    fin_lost: bool,
    fin_acked: bool,
}

impl SendBuf {
    fn end(&self) -> u64 {
        self.base + self.data.len() as u64
    }

    fn push(&mut self, d: &[u8]) {
        self.data.extend(d);
    }

    fn bytes(&self, off: u64, len: usize) -> Vec<u8> {
        let at = (off - self.base) as usize;
        self.data.range(at..at + len).copied().collect()
    }

    /// Something to send: lost bytes first, then new ones up to `limit`
    /// (flow control). Returns (offset, bytes, fin).
    fn take(&mut self, max: usize, limit: u64) -> Option<(u64, Vec<u8>, bool)> {
        while let Some(r) = self.lost.first() {
            // Parts acknowledged meanwhile are not sent again.
            let start = r.start.max(self.base);
            if start >= r.end {
                self.lost.remove(r);
                continue;
            }
            let len = ((r.end - start) as usize).min(max);
            if len == 0 {
                return None;
            }
            self.lost.remove(start.min(r.start)..start + len as u64);
            let fin = self.fin && start + len as u64 == self.end();
            if fin {
                self.fin_lost = false;
            }
            return Some((start, self.bytes(start, len), fin));
        }
        let end = self.end();
        let upto = end.min(limit.max(self.next));
        let len = ((upto - self.next) as usize).min(max);
        let fin_now =
            self.fin && self.next + len as u64 == end && (!self.fin_sent || self.fin_lost);
        if len == 0 && !fin_now {
            return None;
        }
        if len == 0 && max == 0 {
            return None;
        }
        let off = self.next;
        let data = self.bytes(off, len);
        self.next += len as u64;
        if fin_now {
            self.fin_sent = true;
            self.fin_lost = false;
        }
        Some((off, data, fin_now))
    }

    /// Bytes waiting (lost ones, or new within `limit`), or a FIN.
    fn wants(&self, limit: u64) -> bool {
        !self.lost.is_empty()
            || self.end().min(limit) > self.next
            || (self.fin && self.next == self.end() && (!self.fin_sent || self.fin_lost))
    }

    fn on_lost(&mut self, off: u64, len: u64, fin: bool) {
        let r = off.max(self.base)..off + len;
        if !r.is_empty() && !self.acked.contains_range(&r) {
            self.lost.insert(r);
        }
        if fin && !self.fin_acked {
            self.fin_lost = true;
        }
    }

    fn on_acked(&mut self, off: u64, len: u64, fin: bool) {
        if len > 0 {
            self.acked.insert(off..off + len);
            self.lost.remove(off..off + len);
        }
        if fin {
            self.fin_acked = true;
            self.fin_lost = false;
        }
        let to = self.acked.contiguous_from(self.base);
        if to > self.base {
            let n = (to - self.base) as usize;
            self.data.drain(..n.min(self.data.len()));
            self.base = to;
            self.acked.trim_below(to);
        }
    }

    /// Everything, and the end, acknowledged.
    fn done(&self) -> bool {
        self.fin && self.fin_acked && self.data.is_empty()
    }
}

/// An incoming byte stream, put back in order.
#[derive(Debug, Default)]
struct RecvBuf {
    chunks: BTreeMap<u64, Vec<u8>>,
    /// Read up to here.
    read: u64,
    /// The highest offset received.
    highest: u64,
    fin: Option<u64>,
    fin_read: bool,
}

impl RecvBuf {
    /// Takes a frame's bytes; returns how far `highest` moved, or a
    /// transport error.
    fn insert(&mut self, off: u64, data: &[u8], fin: bool) -> Result<u64, (u64, &'static str)> {
        let end = off + data.len() as u64;
        if let Some(f) = self.fin {
            if end > f || (fin && end != f) {
                return Err((code::FINAL_SIZE_ERROR, "data beyond the final size"));
            }
        }
        if fin {
            if end < self.highest {
                return Err((code::FINAL_SIZE_ERROR, "a final size below data received"));
            }
            self.fin = Some(end);
        }
        let grew = end.saturating_sub(self.highest);
        self.highest = self.highest.max(end);
        if end > self.read && !data.is_empty() {
            let (off, data) = if off < self.read {
                (self.read, &data[(self.read - off) as usize..])
            } else {
                (off, data)
            };
            match self.chunks.get(&off) {
                Some(have) if have.len() >= data.len() => {}
                _ => {
                    self.chunks.insert(off, data.to_vec());
                }
            }
        }
        Ok(grew)
    }

    /// Whether `read` would give something.
    fn readable(&self) -> bool {
        self.chunks
            .first_key_value()
            .is_some_and(|(&o, _)| o <= self.read)
            || (self.fin == Some(self.read) && !self.fin_read)
    }

    /// The bytes in order from where reading stopped, and whether that is
    /// the end.
    fn read(&mut self) -> (Vec<u8>, bool) {
        let mut out = Vec::new();
        while let Some((&o, _)) = self.chunks.first_key_value() {
            if o > self.read {
                break;
            }
            let d = self.chunks.pop_first().unwrap().1;
            let end = o + d.len() as u64;
            if end > self.read {
                out.extend_from_slice(&d[(self.read - o) as usize..]);
                self.read = end;
            }
        }
        let fin = self.fin == Some(self.read);
        if fin {
            self.fin_read = true;
        }
        (out, fin)
    }
}

#[derive(Debug)]
struct Stream {
    send: SendBuf,
    recv: RecvBuf,
    /// The most the other end lets us send on it.
    send_max: u64,
    /// The most we let it send; and the window we keep open.
    recv_max: u64,
    max_stream_data_pending: bool,
    /// We send on it (not a stream the other end opened one way).
    can_send: bool,
    /// We receive on it.
    can_recv: bool,
    /// The other end reset it, or we stopped reading.
    recv_reset: bool,
    send_reset: Option<u64>,
    reset_pending: bool,
    stop_pending: Option<u64>,
}

impl Stream {
    fn finished(&self) -> bool {
        let sent = !self.can_send || self.send.done() || self.send_reset.is_some();
        let recvd = !self.can_recv || self.recv.fin_read || self.recv_reset;
        sent && recvd
    }
}

/// What a sent packet carried, for when it is acknowledged or lost.
#[derive(Clone, Debug)]
enum Retx {
    Crypto {
        off: u64,
        len: u64,
    },
    Stream {
        id: u64,
        off: u64,
        len: u64,
        fin: bool,
    },
    MaxData,
    MaxStreamData(u64),
    MaxStreams(bool),
    HandshakeDone,
    Reset(u64),
    StopSending(u64),
}

#[derive(Debug)]
struct Sent {
    time: Duration,
    size: usize,
    ack_eliciting: bool,
    in_flight: bool,
    frames: Vec<Retx>,
    /// The key phase it went in (1-RTT).
    phase: bool,
}

#[derive(Default)]
struct Space {
    keys: Option<Keys>,
    discarded: bool,
    next_pn: u64,
    sent: BTreeMap<u64, Sent>,
    largest_acked: Option<u64>,
    loss_time: Option<Duration>,
    last_ack_eliciting: Option<Duration>,
    crypto_send: SendBuf,
    crypto_recv: RecvBuf,
    received: RangeSet,
    largest_recv: Option<(u64, Duration)>,
    /// Ack-eliciting packets received since our last ACK.
    unacked: u64,
    /// Send an ACK now (or at `ack_at`).
    ack_now: bool,
    ack_at: Option<Duration>,
    /// Probe packets to send (PTO).
    probes: u8,
}

impl Space {
    fn in_flight_eliciting(&self) -> bool {
        self.sent.values().any(|s| s.ack_eliciting && s.in_flight)
    }
}

/// The 1-RTT keys, for both key phases.
struct OneRtt {
    local_hp: Box<dyn rq::HeaderProtectionKey>,
    remote_hp: Box<dyn rq::HeaderProtectionKey>,
    local: Box<dyn rq::PacketKey>,
    remote: Box<dyn rq::PacketKey>,
    /// The other end's previous keys (late packets after an update).
    prev_remote: Option<Box<dyn rq::PacketKey>>,
    next: PacketKeySet,
    secrets: Secrets,
    phase: bool,
    /// The first packet number sent in this phase, and whether one of this
    /// phase was acknowledged (needed before the next update).
    phase_start: u64,
    phase_acked: bool,
    sent_in_phase: u64,
}

impl OneRtt {
    fn update(&mut self, next_pn: u64) {
        let next = self.secrets.next_packet_keys();
        let old = std::mem::replace(&mut self.next, next);
        self.local = old.local;
        let prev = std::mem::replace(&mut self.remote, old.remote);
        self.prev_remote = Some(prev);
        self.phase = !self.phase;
        self.phase_start = next_pn;
        self.phase_acked = false;
        self.sent_in_phase = 0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Handshake,
    Open,
    /// We closed: CONNECTION_CLOSE again for packets until then.
    Closing(Duration),
    /// The other end closed: silent until then.
    Draining(Duration),
    Closed,
}

/// Counters of one connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_lost: u64,
    /// Packets we could not decrypt (or for keys gone).
    pub packets_dropped: u64,
    pub ptos: u64,
    pub key_updates: u64,
    pub bytes_sent: u64,
}

/// A QUIC connection; see the [module](self) docs.
pub struct Conn {
    side: Side,
    tls: rq::Connection,
    settings: QuicSettings,
    state: State,
    /// Ours.
    scid: Vec<u8>,
    /// The other end's (where we send to).
    dcid: Vec<u8>,
    /// The client's first destination id (client) / the one the client
    /// chose (server), for the transport parameters.
    odcid: Vec<u8>,
    /// Client: switched to the server's id after its first packet.
    got_server_cid: bool,
    /// Client: a Retry's token, and the Retry's source id.
    token: Vec<u8>,
    retry_scid: Option<Vec<u8>>,
    spaces: [Space; 3],
    one_rtt: Option<OneRtt>,
    /// Where `write_hs` output goes.
    write_level: Level,
    peer_params: Option<Params>,
    handshake_done: bool,
    confirmed: bool,
    handshake_done_pending: bool,
    // Recovery.
    smoothed_rtt: Option<Duration>,
    rttvar: Duration,
    min_rtt: Duration,
    latest_rtt: Duration,
    pto_count: u32,
    last_sent: Duration,
    // Congestion control (NewReno).
    cwnd: u64,
    ssthresh: u64,
    in_flight: u64,
    recovery_start: Option<Duration>,
    pace_tokens: f64,
    pace_at: Duration,
    /// Pacing held data back until then.
    pace_wake: Option<Duration>,
    // Anti-amplification.
    validated: bool,
    bytes_in: u64,
    bytes_out: u64,
    // Streams.
    streams: BTreeMap<u64, Stream>,
    next_bidi: u64,
    next_uni: u64,
    peer_max_bidi: u64,
    peer_max_uni: u64,
    /// Peer streams we allow, and the ones that ended (for MAX_STREAMS).
    local_max_bidi: u64,
    local_max_uni: u64,
    peer_ended_bidi: u64,
    peer_ended_uni: u64,
    peer_opened_bidi: u64,
    peer_opened_uni: u64,
    max_streams_pending: [bool; 2],
    // Connection flow control.
    peer_max_data: u64,
    data_sent: u64,
    local_max_data: u64,
    data_received: u64,
    data_read: u64,
    max_data_pending: bool,
    // Other frames.
    path_responses: Vec<[u8; 8]>,
    close: Option<Frame>,
    close_info: Option<CloseInfo>,
    /// CONNECTION_CLOSE datagrams still to send.
    close_resend: u8,
    events: VecDeque<Event>,
    last_activity: Duration,
    idle_armed: bool,
    /// Round-robin cursor over streams.
    cursor: u64,
    pub stats: ConnStats,
}

fn initial_keys(dcid: &[u8], side: Side) -> Keys {
    let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .and_then(|s| s.quic_suite())
        .expect("AES-128-GCM for QUIC");
    suite.keys(dcid, side, rq::Version::V1)
}

/// The Retry integrity tag (RFC 9001 section 5.8) over the pseudo-packet.
pub fn retry_tag(odcid: &[u8], packet: &[u8]) -> [u8; 16] {
    use ring::aead;
    const KEY: [u8; 16] = [
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8,
        0x4e,
    ];
    const NONCE: [u8; 12] = [
        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
    ];
    let mut aad = Vec::with_capacity(1 + odcid.len() + packet.len());
    aad.push(odcid.len() as u8);
    aad.extend_from_slice(odcid);
    aad.extend_from_slice(packet);
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &KEY).unwrap());
    let mut empty = Vec::new();
    let tag = key
        .seal_in_place_separate_tag(
            aead::Nonce::assume_unique_for_key(NONCE),
            aead::Aad::from(&aad),
            &mut empty,
        )
        .unwrap();
    tag.as_ref().try_into().unwrap()
}

/// A long header's first fields, as a server reads a datagram that may
/// open a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LongHeader {
    pub version: u32,
    /// 0 Initial, 1 0-RTT, 2 Handshake, 3 Retry.
    pub kind: u8,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    /// Initial: its token.
    pub token: Vec<u8>,
}

/// The long header at the start of `d`, if it has one.
pub fn long_header(d: &[u8]) -> Option<LongHeader> {
    let mut r = Reader::new(d);
    let first = r.u8()?;
    if first & 0x80 == 0 {
        return None;
    }
    let version = r.u32()?;
    let n = r.u8()? as usize;
    let dcid = r.bytes(n)?.to_vec();
    let n = r.u8()? as usize;
    let scid = r.bytes(n)?.to_vec();
    let kind = (first >> 4) & 0x3;
    let mut token = Vec::new();
    if version == VERSION && kind == 0 {
        let n = r.varint()? as usize;
        token = r.bytes(n)?.to_vec();
    }
    Some(LongHeader {
        version,
        kind,
        dcid,
        scid,
        token,
    })
}

/// A Version Negotiation packet answering a packet from `scid` to `dcid`.
pub fn version_negotiation(dcid: &[u8], scid: &[u8], rng: &mut AppRng) -> Vec<u8> {
    let mut out = vec![0x80 | (rng.next_u64() as u8 & 0x7f)];
    out.extend_from_slice(&0u32.to_be_bytes());
    out.push(scid.len() as u8);
    out.extend_from_slice(scid);
    out.push(dcid.len() as u8);
    out.extend_from_slice(dcid);
    out.extend_from_slice(&VERSION.to_be_bytes());
    // A reserved version, as a client must ignore (grease).
    out.extend_from_slice(&0x1a2a_3a4au32.to_be_bytes());
    out
}

/// A Retry packet from a server, with `token`.
pub fn retry_packet(client_scid: &[u8], new_scid: &[u8], odcid: &[u8], token: &[u8]) -> Vec<u8> {
    let mut out = vec![0xf0];
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.push(client_scid.len() as u8);
    out.extend_from_slice(client_scid);
    out.push(new_scid.len() as u8);
    out.extend_from_slice(new_scid);
    out.extend_from_slice(token);
    let tag = retry_tag(odcid, &out);
    out.extend_from_slice(&tag);
    out
}

fn decode_pn(truncated: u64, len: usize, largest: Option<u64>) -> u64 {
    let expected = largest.map_or(0, |l| l + 1);
    let win = 1u64 << (len * 8);
    let hwin = win / 2;
    let mask = win - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate + hwin <= expected && candidate < (1 << 62) - win {
        candidate + win
    } else if candidate > expected + hwin && candidate >= win {
        candidate - win
    } else {
        candidate
    }
}

impl Conn {
    /// A client connection to `server_name`, with ALPN from `config`.
    pub fn client(
        config: Arc<rustls::ClientConfig>,
        server_name: rustls::pki_types::ServerName<'static>,
        settings: QuicSettings,
        seed: u64,
        now: Duration,
    ) -> Result<Conn, String> {
        let mut rng = AppRng::new(seed);
        let mut scid = vec![0; CID_LEN];
        rng.fill(&mut scid);
        let mut dcid = vec![0; CID_LEN];
        rng.fill(&mut dcid);
        let params = local_params(&settings, &scid, None, None);
        let tls = rq::ClientConnection::new(config, rq::Version::V1, server_name, params.encode())
            .map_err(|e| e.to_string())?;
        let mut c = Conn::new(Side::Client, tls.into(), settings, scid, dcid.clone(), now);
        c.odcid = dcid.clone();
        c.spaces[0].keys = Some(initial_keys(&dcid, Side::Client));
        // The client's address counts as valid for itself.
        c.validated = true;
        c.drive_tls();
        Ok(c)
    }

    /// A server connection for a client's first Initial (`h`). With
    /// `retry_odcid`, the client came back after our Retry, whose source id
    /// it now sends to: the parameters name the first id.
    pub fn server(
        config: Arc<rustls::ServerConfig>,
        h: &LongHeader,
        settings: QuicSettings,
        seed: u64,
        now: Duration,
        retry_odcid: Option<Vec<u8>>,
    ) -> Result<Conn, String> {
        let mut rng = AppRng::new(seed);
        let scid = if retry_odcid.is_some() {
            h.dcid.clone()
        } else {
            let mut s = vec![0; CID_LEN];
            rng.fill(&mut s);
            s
        };
        let odcid = retry_odcid.clone().unwrap_or_else(|| h.dcid.clone());
        let retry_scid = retry_odcid.as_ref().map(|_| h.dcid.clone());
        let params = local_params(&settings, &scid, Some(&odcid), retry_scid.as_deref());
        let tls = rq::ServerConnection::new(config, rq::Version::V1, params.encode())
            .map_err(|e| e.to_string())?;
        let mut c = Conn::new(
            Side::Server,
            tls.into(),
            settings,
            scid,
            h.scid.clone(),
            now,
        );
        c.odcid = h.dcid.clone();
        c.spaces[0].keys = Some(initial_keys(&h.dcid, Side::Server));
        // A token from our Retry proves the address.
        c.validated = retry_odcid.is_some();
        Ok(c)
    }

    fn new(
        side: Side,
        tls: rq::Connection,
        settings: QuicSettings,
        scid: Vec<u8>,
        dcid: Vec<u8>,
        now: Duration,
    ) -> Conn {
        let cwnd = settings.initial_window.max(2) * MAX_DATAGRAM as u64;
        Conn {
            side,
            tls,
            state: State::Handshake,
            scid,
            dcid,
            odcid: Vec::new(),
            got_server_cid: false,
            token: Vec::new(),
            retry_scid: None,
            spaces: Default::default(),
            one_rtt: None,
            write_level: Level::Initial,
            peer_params: None,
            handshake_done: false,
            confirmed: false,
            handshake_done_pending: false,
            smoothed_rtt: None,
            rttvar: INITIAL_RTT / 2,
            min_rtt: Duration::MAX,
            latest_rtt: Duration::ZERO,
            pto_count: 0,
            last_sent: now,
            cwnd,
            ssthresh: u64::MAX,
            in_flight: 0,
            recovery_start: None,
            pace_tokens: (10 * MAX_DATAGRAM) as f64,
            pace_at: now,
            pace_wake: None,
            validated: false,
            bytes_in: 0,
            bytes_out: 0,
            streams: BTreeMap::new(),
            next_bidi: 0,
            next_uni: 0,
            peer_max_bidi: 0,
            peer_max_uni: 0,
            local_max_bidi: settings.max_streams_bidi,
            local_max_uni: settings.max_streams_uni,
            peer_ended_bidi: 0,
            peer_ended_uni: 0,
            peer_opened_bidi: 0,
            peer_opened_uni: 0,
            max_streams_pending: [false; 2],
            peer_max_data: 0,
            data_sent: 0,
            local_max_data: settings.max_data,
            data_received: 0,
            data_read: 0,
            max_data_pending: false,
            path_responses: Vec::new(),
            close: None,
            close_info: None,
            close_resend: 0,
            events: VecDeque::new(),
            last_activity: now,
            idle_armed: false,
            cursor: 0,
            stats: ConnStats::default(),
            settings,
        }
    }

    pub fn is_client(&self) -> bool {
        self.side == Side::Client
    }

    /// The handshake finished (and the connection is not closed).
    pub fn is_established(&self) -> bool {
        self.state == State::Open
    }

    /// Closed, closing or draining: nothing more for the application.
    pub fn is_closed(&self) -> bool {
        matches!(
            self.state,
            State::Closing(_) | State::Draining(_) | State::Closed
        )
    }

    /// The closing or draining period is over too.
    pub fn is_gone(&self) -> bool {
        self.state == State::Closed
    }

    pub fn close_info(&self) -> Option<&CloseInfo> {
        self.close_info.as_ref()
    }

    pub fn tls(&self) -> &rq::Connection {
        &self.tls
    }

    /// Our connection id.
    pub fn scid(&self) -> &[u8] {
        &self.scid
    }

    /// The client's first destination id.
    pub fn odcid(&self) -> &[u8] {
        &self.odcid
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn smoothed_rtt(&self) -> Option<Duration> {
        self.smoothed_rtt
    }

    // ----- the handshake -----

    /// Hands rustls what arrived in CRYPTO frames, and takes what it sends
    /// and the keys it makes.
    fn drive_tls(&mut self) {
        loop {
            let level = self.write_level;
            let mut out = Vec::new();
            let change = self.tls.write_hs(&mut out);
            if !out.is_empty() {
                self.spaces[level as usize].crypto_send.push(&out);
            }
            match change {
                Some(KeyChange::Handshake { keys }) => {
                    self.spaces[1].keys = Some(keys);
                    self.write_level = Level::Handshake;
                }
                Some(KeyChange::OneRtt { keys, next }) => {
                    let mut secrets = next;
                    let next = secrets.next_packet_keys();
                    self.one_rtt = Some(OneRtt {
                        local_hp: keys.local.header,
                        remote_hp: keys.remote.header,
                        local: keys.local.packet,
                        remote: keys.remote.packet,
                        prev_remote: None,
                        next,
                        secrets,
                        phase: false,
                        phase_start: 0,
                        phase_acked: false,
                        sent_in_phase: 0,
                    });
                    self.write_level = Level::Data;
                }
                None if out.is_empty() => break,
                None => {}
            }
        }
        // A client's rustls answers with the parameters of a stored session
        // until the server's EncryptedExtensions came, before its Finished.
        let fresh = self.side == Side::Server || self.one_rtt.is_some();
        if self.peer_params.is_none() && fresh {
            if let Some(p) = self.tls.quic_transport_parameters() {
                match Params::parse(p) {
                    Ok(p) => {
                        if let Err(e) = self.check_params(&p) {
                            self.fail(code::TRANSPORT_PARAMETER_ERROR, e);
                            return;
                        }
                        self.peer_max_data = p.initial_max_data;
                        self.peer_max_bidi = p.initial_max_streams_bidi;
                        self.peer_max_uni = p.initial_max_streams_uni;
                        self.peer_params = Some(p);
                    }
                    Err(e) => {
                        self.fail(code::TRANSPORT_PARAMETER_ERROR, e);
                        return;
                    }
                }
            }
        }
        if !self.handshake_done && !self.tls.is_handshaking() && self.one_rtt.is_some() {
            self.handshake_done = true;
            if self.state == State::Handshake {
                self.state = State::Open;
                self.events.push_back(Event::Connected);
            }
            if self.side == Side::Server {
                // The server's handshake is confirmed at once.
                self.confirmed = true;
                self.handshake_done_pending = true;
                self.discard(Level::Handshake);
            }
        }
    }

    fn check_params(&self, p: &Params) -> Result<(), String> {
        match self.side {
            Side::Client => {
                if p.original_dcid.as_deref() != Some(&self.odcid[..]) {
                    return Err("original_destination_connection_id does not match".into());
                }
                if p.initial_scid.as_deref() != Some(&self.dcid[..]) {
                    return Err("initial_source_connection_id does not match".into());
                }
                if p.retry_scid != self.retry_scid {
                    return Err("retry_source_connection_id does not match".into());
                }
            }
            Side::Server => {
                if p.initial_scid.as_deref() != Some(&self.dcid[..]) {
                    return Err("initial_source_connection_id does not match".into());
                }
                if p.original_dcid.is_some() || p.retry_scid.is_some() {
                    return Err("a client sent server-only parameters".into());
                }
            }
        }
        Ok(())
    }

    fn discard(&mut self, level: Level) {
        let s = &mut self.spaces[level as usize];
        if s.discarded {
            return;
        }
        s.discarded = true;
        s.keys = None;
        for (_, p) in std::mem::take(&mut s.sent) {
            if p.in_flight {
                self.in_flight = self.in_flight.saturating_sub(p.size as u64);
            }
        }
        s.loss_time = None;
        s.last_ack_eliciting = None;
        s.ack_now = false;
        s.ack_at = None;
        s.probes = 0;
        self.pto_count = 0;
    }

    // ----- receiving -----

    /// A datagram from the other end.
    pub fn recv(&mut self, datagram: &[u8], now: Duration) {
        if self.state == State::Closed {
            return;
        }
        self.bytes_in += datagram.len() as u64;
        let mut rest = datagram;
        while !rest.is_empty() {
            let Some(n) = self.recv_packet(rest, now) else {
                break;
            };
            rest = &rest[n..];
        }
    }

    /// One packet at the start of `d`; returns its length (None: the rest
    /// of the datagram cannot be read).
    fn recv_packet(&mut self, d: &[u8], now: Duration) -> Option<usize> {
        let first = *d.first()?;
        if first & 0x80 != 0 {
            let mut r = Reader::new(d);
            r.u8()?;
            let version = r.u32()?;
            let n = r.u8()? as usize;
            let dcid = r.bytes(n)?.to_vec();
            let n = r.u8()? as usize;
            let scid = r.bytes(n)?.to_vec();
            if version == 0 {
                // Version Negotiation: only before anything came back.
                if self.side == Side::Client
                    && !self.got_server_cid
                    && self.state == State::Handshake
                {
                    let mut vs = Vec::new();
                    while let Some(v) = r.u32() {
                        vs.push(v);
                    }
                    if !vs.contains(&VERSION) {
                        self.close_info = Some(CloseInfo {
                            local: false,
                            app: false,
                            code: code::CONNECTION_REFUSED,
                            reason: format!(
                                "version negotiation: the server speaks {}",
                                vs.iter()
                                    .map(|v| format!("0x{v:08x}"))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ),
                            idle: false,
                        });
                        self.events
                            .push_back(Event::Closed(self.close_info.clone().unwrap()));
                        self.state = State::Closed;
                    }
                }
                return None;
            }
            if version != VERSION {
                return None;
            }
            if dcid != self.scid && !(self.side == Side::Server && dcid == self.odcid) {
                self.stats.packets_dropped += 1;
                return None;
            }
            let kind = (first >> 4) & 0x3;
            if kind == 3 {
                self.on_retry(d, &scid);
                return None;
            }
            let level = match kind {
                0 => {
                    let n = r.varint()? as usize;
                    r.bytes(n)?;
                    Level::Initial
                }
                2 => Level::Handshake,
                _ => {
                    // 0-RTT: we never accept early data.
                    let len = r.varint()? as usize;
                    return Some(r.pos() + len);
                }
            };
            let len = r.varint()? as usize;
            let pn_off = r.pos();
            let total = pn_off.checked_add(len)?;
            if total > d.len() {
                return None;
            }
            if self.side == Side::Client && level == Level::Initial && !self.got_server_cid {
                // The server's id from now on.
                self.got_server_cid = true;
                self.dcid = scid;
            }
            self.unprotect(level, &d[..total], pn_off, now);
            Some(total)
        } else {
            if d.len() < 1 + self.scid.len() || d[1..1 + self.scid.len()] != self.scid[..] {
                self.stats.packets_dropped += 1;
                return None;
            }
            self.unprotect(Level::Data, d, 1 + self.scid.len(), now);
            Some(d.len())
        }
    }

    fn on_retry(&mut self, d: &[u8], scid: &[u8]) {
        if self.side != Side::Client || self.got_server_cid || self.retry_scid.is_some() {
            return;
        }
        if d.len() < 16 + 7 {
            return;
        }
        let (body, tag) = d.split_at(d.len() - 16);
        if retry_tag(&self.odcid, body) != tag {
            return;
        }
        // The token: after the source id.
        let at = 1 + 4 + 1 + d[5] as usize + 1 + scid.len();
        let token = body[at..].to_vec();
        if token.is_empty() {
            return;
        }
        self.token = token;
        self.retry_scid = Some(scid.to_vec());
        self.dcid = scid.to_vec();
        // New Initial keys from the new id; everything sent goes again.
        self.spaces[0].keys = Some(initial_keys(scid, Side::Client));
        let s = &mut self.spaces[0];
        for (_, p) in std::mem::take(&mut s.sent) {
            if p.in_flight {
                self.in_flight = self.in_flight.saturating_sub(p.size as u64);
            }
        }
        s.crypto_send.next = s.crypto_send.base;
        s.crypto_send.lost = RangeSet::new();
        s.loss_time = None;
        s.last_ack_eliciting = None;
        self.pto_count = 0;
    }

    fn unprotect(&mut self, level: Level, pkt: &[u8], pn_off: usize, now: Duration) {
        let mut buf = pkt.to_vec();
        let sample_at = pn_off + 4;
        if buf.len() < sample_at + 16 {
            self.stats.packets_dropped += 1;
            return;
        }
        let sample = buf[sample_at..sample_at + 16].to_vec();
        let (head, tail) = buf.split_at_mut(pn_off);
        let pn_bytes = &mut tail[..4];
        let hp_ok = match level {
            Level::Data => self.one_rtt.as_ref().map(|k| {
                k.remote_hp
                    .decrypt_in_place(&sample, &mut head[0], pn_bytes)
            }),
            l => self.spaces[l as usize].keys.as_ref().map(|k| {
                k.remote
                    .header
                    .decrypt_in_place(&sample, &mut head[0], pn_bytes)
            }),
        };
        if !matches!(hp_ok, Some(Ok(()))) {
            self.stats.packets_dropped += 1;
            return;
        }
        let first = buf[0];
        let pn_len = (first & 0x03) as usize + 1;
        let mut truncated = 0u64;
        for &b in &buf[pn_off..pn_off + pn_len] {
            truncated = (truncated << 8) | u64::from(b);
        }
        let space = &self.spaces[level as usize];
        let pn = decode_pn(truncated, pn_len, space.largest_recv.map(|l| l.0));
        let hdr_len = pn_off + pn_len;
        let (header, payload) = buf.split_at_mut(hdr_len);
        let plain: Option<Vec<u8>> = match level {
            Level::Data => {
                let phase = first & 0x04 != 0;
                let Some(k) = self.one_rtt.as_mut() else {
                    self.stats.packets_dropped += 1;
                    return;
                };
                if phase == k.phase {
                    let mut p = payload.to_vec();
                    match k.remote.decrypt_in_place(pn, header, &mut p) {
                        Ok(pl) => Some(pl.to_vec()),
                        Err(_) => {
                            // Late, from before the other end's update?
                            let mut p = payload.to_vec();
                            k.prev_remote.as_ref().and_then(|prev| {
                                prev.decrypt_in_place(pn, header, &mut p)
                                    .ok()
                                    .map(|x| x.to_vec())
                            })
                        }
                    }
                } else {
                    // A packet of the other phase: a key update, or late.
                    let mut p = payload.to_vec();
                    let late =
                        space.largest_recv.is_some_and(|l| pn < l.0) && k.prev_remote.is_some();
                    if late {
                        k.prev_remote.as_ref().and_then(|prev| {
                            prev.decrypt_in_place(pn, header, &mut p)
                                .ok()
                                .map(|x| x.to_vec())
                        })
                    } else {
                        match k.next.remote.decrypt_in_place(pn, header, &mut p) {
                            Ok(pl) => {
                                let pl = pl.to_vec();
                                let next_pn = self.spaces[2].next_pn;
                                let k = self.one_rtt.as_mut().unwrap();
                                k.update(next_pn);
                                self.stats.key_updates += 1;
                                Some(pl)
                            }
                            Err(_) => None,
                        }
                    }
                }
            }
            l => {
                let mut p = payload.to_vec();
                self.spaces[l as usize].keys.as_ref().and_then(|k| {
                    k.remote
                        .packet
                        .decrypt_in_place(pn, header, &mut p)
                        .ok()
                        .map(|x| x.to_vec())
                })
            }
        };
        let Some(plain) = plain else {
            self.stats.packets_dropped += 1;
            return;
        };
        // Reserved bits must be zero once the packet is unprotected.
        let reserved = if first & 0x80 != 0 { 0x0c } else { 0x18 };
        if first & reserved != 0 {
            self.fail(code::PROTOCOL_VIOLATION, "reserved header bits set".into());
            return;
        }
        let space = &mut self.spaces[level as usize];
        if space.received.contains(pn) {
            return; // a duplicate
        }
        self.stats.packets_received += 1;
        self.last_activity = now;
        self.idle_armed = true;
        if self.side == Side::Server && level == Level::Handshake {
            // The client has our Initial keys' answer: its address is good,
            // and Initial keys are no longer needed.
            self.validated = true;
            self.discard(Level::Initial);
        }
        self.on_packet(level, pn, &plain, now);
    }

    fn on_packet(&mut self, level: Level, pn: u64, payload: &[u8], now: Duration) {
        let frames = match parse_frames(payload) {
            Ok(f) if !f.is_empty() => f,
            Ok(_) => {
                self.fail(code::PROTOCOL_VIOLATION, "a packet without frames".into());
                return;
            }
            Err(b) => {
                self.fail(
                    code::FRAME_ENCODING_ERROR,
                    format!("a bad frame of type 0x{:x}", b.0),
                );
                return;
            }
        };
        let eliciting = frames.iter().any(|f| f.ack_eliciting());
        {
            let space = &mut self.spaces[level as usize];
            let out_of_order = space.largest_recv.is_some_and(|l| pn != l.0 + 1);
            space.received.insert(pn..pn + 1);
            while space.received.len() > MAX_ACK_RANGES {
                let f = space.received.first().unwrap();
                space.received.remove(f);
            }
            if space.largest_recv.is_none_or(|l| pn > l.0) {
                space.largest_recv = Some((pn, now));
            }
            if eliciting {
                space.unacked += 1;
                if level != Level::Data || space.unacked >= 2 || out_of_order {
                    space.ack_now = true;
                } else if space.ack_at.is_none() {
                    space.ack_at = Some(now + ACK_DELAY);
                }
            }
        }
        if let State::Closing(_) = self.state {
            self.close_resend = self.close_resend.max(1);
        }
        for f in frames {
            if self.is_closed() && !matches!(f, Frame::ConnectionClose { .. }) {
                continue;
            }
            if level != Level::Data && !f.handshake_ok() {
                self.fail(
                    code::PROTOCOL_VIOLATION,
                    "a frame not allowed in Initial or Handshake packets".into(),
                );
                return;
            }
            self.on_frame(level, f, now);
            if self.state == State::Closed {
                return;
            }
        }
        if level != Level::Data {
            self.drive_tls();
        }
    }

    fn on_frame(&mut self, level: Level, f: Frame, now: Duration) {
        match f {
            Frame::Padding(_) | Frame::Ping => {}
            Frame::Ack(a) => self.on_ack(level, &a, now),
            Frame::Crypto { offset, data } => {
                let s = &mut self.spaces[level as usize];
                if offset + data.len() as u64 > s.crypto_recv.read + (1 << 16) {
                    self.fail(code::CRYPTO_BUFFER_EXCEEDED, String::new());
                    return;
                }
                if s.crypto_recv.insert(offset, &data, false).is_err() {
                    return;
                }
                if !s.crypto_recv.readable() {
                    return;
                }
                let (bytes, _) = s.crypto_recv.read();
                if let Err(e) = self.tls.read_hs(&bytes) {
                    let alert = self.tls.alert().map(u8::from).unwrap_or(80);
                    self.drive_tls();
                    self.fail(code::CRYPTO_ERROR + u64::from(alert), e.to_string());
                }
            }
            Frame::HandshakeDone => {
                if self.side == Side::Server {
                    self.fail(
                        code::PROTOCOL_VIOLATION,
                        "HANDSHAKE_DONE from a client".into(),
                    );
                    return;
                }
                if !self.confirmed {
                    self.confirmed = true;
                    self.discard(Level::Handshake);
                }
            }
            Frame::NewToken(_) => {
                if self.side == Side::Server {
                    self.fail(code::PROTOCOL_VIOLATION, "NEW_TOKEN from a client".into());
                }
            }
            Frame::Stream {
                id,
                offset,
                data,
                fin,
            } => self.on_stream(id, offset, &data, fin),
            Frame::ResetStream {
                id,
                code: c,
                final_size,
            } => {
                if !self.recv_stream_ok(id) {
                    return;
                }
                if let Some(s) = self.streams.get_mut(&id) {
                    if !s.recv_reset {
                        let grew = final_size.saturating_sub(s.recv.highest);
                        s.recv.highest = s.recv.highest.max(final_size);
                        s.recv_reset = true;
                        self.data_received += grew;
                        self.events.push_back(Event::Reset { id, code: c });
                        self.maybe_end(id);
                    }
                }
            }
            Frame::StopSending { id, code: c } => {
                if !self.send_stream_ok(id) {
                    return;
                }
                if let Some(s) = self.streams.get_mut(&id) {
                    if s.send_reset.is_none() {
                        s.send_reset = Some(c);
                        s.reset_pending = true;
                        self.events.push_back(Event::StopSending { id, code: c });
                    }
                }
            }
            Frame::MaxData(m) => self.peer_max_data = self.peer_max_data.max(m),
            Frame::MaxStreamData { id, max } => {
                if !self.send_stream_ok(id) {
                    return;
                }
                if let Some(s) = self.streams.get_mut(&id) {
                    s.send_max = s.send_max.max(max);
                }
            }
            Frame::MaxStreams { bidi, max } => {
                if max > 1 << 60 {
                    self.fail(code::FRAME_ENCODING_ERROR, "MAX_STREAMS over 2^60".into());
                    return;
                }
                let cur = if bidi {
                    &mut self.peer_max_bidi
                } else {
                    &mut self.peer_max_uni
                };
                if max > *cur {
                    *cur = max;
                    self.events.push_back(Event::StreamsAvailable);
                }
            }
            Frame::DataBlocked(_)
            | Frame::StreamDataBlocked { .. }
            | Frame::StreamsBlocked { .. }
            | Frame::NewConnectionId { .. }
            | Frame::RetireConnectionId(_)
            | Frame::PathResponse(_) => {}
            Frame::PathChallenge(d) => self.path_responses.push(d),
            Frame::ConnectionClose {
                app,
                code: c,
                reason,
                ..
            } => {
                if self.close_info.is_none() {
                    let info = CloseInfo {
                        local: false,
                        app,
                        code: c,
                        reason: String::from_utf8_lossy(&reason).into_owned(),
                        idle: false,
                    };
                    self.close_info = Some(info.clone());
                    self.events.push_back(Event::Closed(info));
                }
                if !matches!(self.state, State::Draining(_) | State::Closed) {
                    self.state = State::Draining(now + 3 * self.pto());
                }
            }
        }
    }

    // ----- streams -----

    fn local(&self, id: u64) -> bool {
        (id & 1 == 1) == (self.side == Side::Server)
    }

    /// The other end may send on `id` (else the connection fails).
    fn recv_stream_ok(&mut self, id: u64) -> bool {
        let uni = id & 2 != 0;
        if self.local(id) {
            if uni {
                self.fail(
                    code::STREAM_STATE_ERROR,
                    "data on our send-only stream".into(),
                );
                return false;
            }
            let opened = id >> 2 < self.next_bidi;
            if !opened {
                self.fail(
                    code::STREAM_STATE_ERROR,
                    "a stream of ours not opened".into(),
                );
                return false;
            }
            return true;
        }
        self.open_peer_stream(id)
    }

    /// We may send on `id`.
    fn send_stream_ok(&mut self, id: u64) -> bool {
        let uni = id & 2 != 0;
        if self.local(id) {
            let next = if uni { self.next_uni } else { self.next_bidi };
            if id >> 2 >= next {
                self.fail(
                    code::STREAM_STATE_ERROR,
                    "a stream of ours not opened".into(),
                );
                return false;
            }
            return true;
        }
        if uni {
            self.fail(
                code::STREAM_STATE_ERROR,
                "flow control for a receive-only stream".into(),
            );
            return false;
        }
        self.open_peer_stream(id)
    }

    /// Opens a stream of the other end's (and the ones below it).
    fn open_peer_stream(&mut self, id: u64) -> bool {
        let uni = id & 2 != 0;
        let n = id >> 2;
        let (limit, opened) = if uni {
            (self.local_max_uni, self.peer_opened_uni)
        } else {
            (self.local_max_bidi, self.peer_opened_bidi)
        };
        if n >= limit {
            self.fail(
                code::STREAM_LIMIT_ERROR,
                format!("stream {id} over the limit"),
            );
            return false;
        }
        if n < opened {
            return true; // open, or ended already
        }
        let p = self.peer_params.clone().unwrap_or_default();
        for k in opened..=n {
            let sid = (k << 2) | (id & 3);
            let s = Stream {
                send: SendBuf::default(),
                recv: RecvBuf::default(),
                send_max: if uni {
                    0
                } else {
                    p.initial_max_stream_data_bidi_local
                },
                recv_max: self.settings.stream_window,
                max_stream_data_pending: false,
                can_send: !uni,
                can_recv: true,
                recv_reset: false,
                send_reset: None,
                reset_pending: false,
                stop_pending: None,
            };
            self.streams.insert(sid, s);
        }
        if uni {
            self.peer_opened_uni = n + 1;
        } else {
            self.peer_opened_bidi = n + 1;
        }
        true
    }

    fn on_stream(&mut self, id: u64, offset: u64, data: &[u8], fin: bool) {
        if !self.recv_stream_ok(id) {
            return;
        }
        let Some(s) = self.streams.get_mut(&id) else {
            return; // ended already: a repeat
        };
        if s.recv_reset {
            return;
        }
        if offset + data.len() as u64 > s.recv_max {
            self.fail(
                code::FLOW_CONTROL_ERROR,
                format!("stream {id} over its window"),
            );
            return;
        }
        let grew = match s.recv.insert(offset, data, fin) {
            Ok(g) => g,
            Err((c, why)) => {
                self.fail(c, why.into());
                return;
            }
        };
        let readable = s.recv.readable();
        self.data_received += grew;
        if self.data_received > self.local_max_data {
            self.fail(
                code::FLOW_CONTROL_ERROR,
                "over the connection's window".into(),
            );
            return;
        }
        if readable {
            self.events.push_back(Event::Readable(id));
        }
    }

    /// Opens a stream of ours; None while the other end allows no more.
    pub fn open(&mut self, bidi: bool) -> Option<u64> {
        if self.state != State::Open {
            return None;
        }
        let p = self.peer_params.clone().unwrap_or_default();
        let (next, max) = if bidi {
            (self.next_bidi, self.peer_max_bidi)
        } else {
            (self.next_uni, self.peer_max_uni)
        };
        if next >= max {
            return None;
        }
        let id =
            (next << 2) | if bidi { 0 } else { 2 } | if self.side == Side::Server { 1 } else { 0 };
        if bidi {
            self.next_bidi += 1;
        } else {
            self.next_uni += 1;
        }
        self.streams.insert(
            id,
            Stream {
                send: SendBuf::default(),
                recv: RecvBuf::default(),
                send_max: if bidi {
                    p.initial_max_stream_data_bidi_remote
                } else {
                    p.initial_max_stream_data_uni
                },
                recv_max: if bidi { self.settings.stream_window } else { 0 },
                max_stream_data_pending: false,
                can_send: true,
                can_recv: bidi,
                recv_reset: false,
                send_reset: None,
                reset_pending: false,
                stop_pending: None,
            },
        );
        Some(id)
    }

    /// Streams of ours that may still open.
    pub fn streams_left(&self, bidi: bool) -> u64 {
        if bidi {
            self.peer_max_bidi.saturating_sub(self.next_bidi)
        } else {
            self.peer_max_uni.saturating_sub(self.next_uni)
        }
    }

    /// Queues bytes on a stream (and its end with `fin`).
    pub fn write(&mut self, id: u64, data: &[u8], fin: bool) {
        if let Some(s) = self.streams.get_mut(&id) {
            if s.can_send && !s.send.fin && s.send_reset.is_none() {
                s.send.push(data);
                s.send.fin |= fin;
            }
        }
    }

    /// Bytes queued on a stream and not yet acknowledged.
    pub fn unsent(&self, id: u64) -> u64 {
        self.streams
            .get(&id)
            .map_or(0, |s| s.send.end() - s.send.base)
    }

    /// Stream bytes (or ends) of ours not yet acknowledged.
    pub fn sending(&self) -> bool {
        self.streams.values().any(|s| {
            s.can_send
                && s.send_reset.is_none()
                && (!s.send.data.is_empty() || (s.send.fin && !s.send.fin_acked))
        })
    }

    /// What arrived on a stream in order, and whether it ended.
    pub fn read(&mut self, id: u64) -> (Vec<u8>, bool) {
        let Some(s) = self.streams.get_mut(&id) else {
            return (Vec::new(), false);
        };
        let (d, fin) = s.recv.read();
        self.data_read += d.len() as u64;
        // Open the windows again once half is used.
        if !fin && s.recv_max - s.recv.read < self.settings.stream_window / 2 {
            s.recv_max = s.recv.read + self.settings.stream_window;
            s.max_stream_data_pending = true;
        }
        if self.local_max_data - self.data_read < self.settings.max_data / 2 {
            self.local_max_data = self.data_read + self.settings.max_data;
            self.max_data_pending = true;
        }
        if fin {
            self.maybe_end(id);
        }
        (d, fin)
    }

    /// Resets our sending side of a stream.
    pub fn reset(&mut self, id: u64, code: u64) {
        if let Some(s) = self.streams.get_mut(&id) {
            if s.can_send && s.send_reset.is_none() && !s.send.done() {
                s.send_reset = Some(code);
                s.reset_pending = true;
            }
        }
    }

    /// Asks the other end to stop sending on a stream; what comes is dropped.
    pub fn stop_sending(&mut self, id: u64, code: u64) {
        if let Some(s) = self.streams.get_mut(&id) {
            if s.can_recv && !s.recv_reset && !s.recv.fin_read {
                s.stop_pending = Some(code);
                s.recv_reset = true;
            }
        }
        self.maybe_end(id);
    }

    /// A stream whose both directions are over goes; the other end's
    /// count toward more of its streams.
    fn maybe_end(&mut self, id: u64) {
        let Some(s) = self.streams.get(&id) else {
            return;
        };
        if !s.finished() || s.reset_pending || s.stop_pending.is_some() {
            return;
        }
        self.streams.remove(&id);
        if self.local(id) {
            return;
        }
        if id & 2 != 0 {
            self.peer_ended_uni += 1;
            let ideal = self.peer_ended_uni + self.settings.max_streams_uni;
            if ideal - self.local_max_uni >= self.settings.max_streams_uni.div_ceil(2) {
                self.local_max_uni = ideal;
                self.max_streams_pending[1] = true;
            }
        } else {
            self.peer_ended_bidi += 1;
            let ideal = self.peer_ended_bidi + self.settings.max_streams_bidi;
            if ideal - self.local_max_bidi >= self.settings.max_streams_bidi.div_ceil(2) {
                self.local_max_bidi = ideal;
                self.max_streams_pending[0] = true;
            }
        }
    }

    // ----- acknowledgements, loss, congestion -----

    fn pto_base(&self) -> Duration {
        let srtt = self.smoothed_rtt.unwrap_or(INITIAL_RTT);
        srtt + (4 * self.rttvar).max(GRANULARITY)
    }

    fn pto(&self) -> Duration {
        let ack_delay = self
            .peer_params
            .as_ref()
            .map_or(ACK_DELAY, |p| Duration::from_millis(p.max_ack_delay));
        self.pto_base() + ack_delay
    }

    fn on_ack(&mut self, level: Level, a: &Ack, now: Duration) {
        let li = level as usize;
        if a.largest() >= self.spaces[li].next_pn {
            self.fail(
                code::PROTOCOL_VIOLATION,
                "an ACK of a packet never sent".into(),
            );
            return;
        }
        let space = &mut self.spaces[li];
        space.largest_acked = Some(
            space
                .largest_acked
                .map_or(a.largest(), |l| l.max(a.largest())),
        );
        let mut newly = Vec::new();
        for &(lo, hi) in &a.ranges {
            let pns: Vec<u64> = space.sent.range(lo..=hi).map(|(&k, _)| k).collect();
            for pn in pns {
                newly.push((pn, space.sent.remove(&pn).unwrap()));
            }
        }
        if newly.is_empty() {
            return;
        }
        // An RTT sample from the largest, when it is new and ack-eliciting.
        if let Some((pn, p)) = newly.iter().max_by_key(|(pn, _)| *pn) {
            if *pn == a.largest() && newly.iter().any(|(_, p)| p.ack_eliciting) {
                let exp = self
                    .peer_params
                    .as_ref()
                    .map_or(ACK_DELAY_EXPONENT, |p| p.ack_delay_exponent);
                let mut delay = Duration::from_micros(a.delay << exp);
                if level != Level::Data {
                    delay = Duration::ZERO;
                }
                self.rtt_sample(now.saturating_sub(p.time), delay);
            }
        }
        let phase_now = self.one_rtt.as_ref().map(|k| k.phase);
        for (_, p) in &newly {
            if p.in_flight {
                self.in_flight = self.in_flight.saturating_sub(p.size as u64);
                // NewReno: grow, except for packets from before a recovery.
                if self.recovery_start.is_none_or(|r| p.time > r) {
                    if self.cwnd < self.ssthresh {
                        self.cwnd += p.size as u64;
                    } else {
                        self.cwnd += MAX_DATAGRAM as u64 * p.size as u64 / self.cwnd;
                    }
                }
            }
            if level == Level::Data && phase_now == Some(p.phase) {
                if let Some(k) = self.one_rtt.as_mut() {
                    k.phase_acked = true;
                }
            }
            for r in &p.frames {
                self.on_frame_acked(level, r);
            }
        }
        self.pto_count = 0;
        self.detect_lost(level, now);
    }

    fn rtt_sample(&mut self, rtt: Duration, ack_delay: Duration) {
        self.latest_rtt = rtt;
        self.min_rtt = self.min_rtt.min(rtt);
        match self.smoothed_rtt {
            None => {
                self.smoothed_rtt = Some(rtt);
                self.rttvar = rtt / 2;
            }
            Some(srtt) => {
                let max_delay = self
                    .peer_params
                    .as_ref()
                    .map_or(ACK_DELAY, |p| Duration::from_millis(p.max_ack_delay));
                let delay = if self.confirmed {
                    ack_delay.min(max_delay)
                } else {
                    ack_delay
                };
                let adjusted = if rtt >= self.min_rtt + delay {
                    rtt - delay
                } else {
                    rtt
                };
                let diff = srtt.abs_diff(adjusted);
                self.rttvar = (self.rttvar * 3 + diff) / 4;
                self.smoothed_rtt = Some((srtt * 7 + adjusted) / 8);
            }
        }
    }

    fn on_frame_acked(&mut self, level: Level, r: &Retx) {
        match *r {
            Retx::Crypto { off, len } => {
                self.spaces[level as usize]
                    .crypto_send
                    .on_acked(off, len, false);
            }
            Retx::Stream { id, off, len, fin } => {
                if let Some(s) = self.streams.get_mut(&id) {
                    s.send.on_acked(off, len, fin);
                    if s.send.done() {
                        self.maybe_end(id);
                    }
                }
            }
            Retx::Reset(id) | Retx::StopSending(id) => self.maybe_end(id),
            _ => {}
        }
    }

    fn on_frame_lost(&mut self, level: Level, r: Retx) {
        match r {
            Retx::Crypto { off, len } => {
                self.spaces[level as usize]
                    .crypto_send
                    .on_lost(off, len, false);
            }
            Retx::Stream { id, off, len, fin } => {
                if let Some(s) = self.streams.get_mut(&id) {
                    if s.send_reset.is_none() {
                        s.send.on_lost(off, len, fin);
                    }
                }
            }
            Retx::MaxData => self.max_data_pending = true,
            Retx::MaxStreamData(id) => {
                if let Some(s) = self.streams.get_mut(&id) {
                    if !s.recv.fin_read && !s.recv_reset {
                        s.max_stream_data_pending = true;
                    }
                }
            }
            Retx::MaxStreams(bidi) => self.max_streams_pending[usize::from(!bidi)] = true,
            Retx::HandshakeDone => self.handshake_done_pending = true,
            Retx::Reset(id) => {
                if let Some(s) = self.streams.get_mut(&id) {
                    s.reset_pending = true;
                }
            }
            Retx::StopSending(id) => {
                if let Some(s) = self.streams.get_mut(&id) {
                    if s.stop_pending.is_none() {
                        s.stop_pending = Some(0x10c); // H3_REQUEST_CANCELLED
                    }
                }
            }
        }
    }

    fn detect_lost(&mut self, level: Level, now: Duration) {
        let li = level as usize;
        let Some(largest) = self.spaces[li].largest_acked else {
            return;
        };
        let delay = (self
            .latest_rtt
            .max(self.smoothed_rtt.unwrap_or(INITIAL_RTT))
            * 9
            / 8)
        .max(GRANULARITY);
        let space = &mut self.spaces[li];
        space.loss_time = None;
        let mut lost = Vec::new();
        for (&pn, p) in &space.sent {
            if pn > largest {
                break;
            }
            if p.time + delay <= now || largest >= pn + PACKET_THRESHOLD {
                lost.push(pn);
            } else {
                let t = p.time + delay;
                space.loss_time = Some(space.loss_time.map_or(t, |l: Duration| l.min(t)));
            }
        }
        let mut congestion = None;
        let mut frames = Vec::new();
        for pn in lost {
            let p = space.sent.remove(&pn).unwrap();
            if p.in_flight {
                self.in_flight = self.in_flight.saturating_sub(p.size as u64);
                congestion = Some(congestion.map_or(p.time, |t: Duration| t.max(p.time)));
            }
            if p.ack_eliciting {
                self.stats.packets_lost += 1;
            }
            frames.extend(p.frames);
        }
        for r in frames {
            self.on_frame_lost(level, r);
        }
        if let Some(sent) = congestion {
            if self.recovery_start.is_none_or(|r| sent > r) {
                self.recovery_start = Some(now);
                self.ssthresh = (self.cwnd / 2).max(2 * MAX_DATAGRAM as u64);
                self.cwnd = self.ssthresh;
            }
        }
    }

    /// When the loss or probe timer goes off, and in which space.
    fn loss_timer(&self) -> Option<(Duration, Level, bool)> {
        // The earliest loss time first.
        let mut best: Option<(Duration, Level, bool)> = None;
        for l in LEVELS {
            if let Some(t) = self.spaces[l as usize].loss_time {
                if best.is_none_or(|b| t < b.0) {
                    best = Some((t, l, true));
                }
            }
        }
        if best.is_some() {
            return best;
        }
        let backoff = 1u32 << self.pto_count.min(10);
        let any = LEVELS
            .iter()
            .any(|&l| self.spaces[l as usize].in_flight_eliciting());
        if !any {
            // A client with nothing in flight still probes until the
            // handshake is confirmed (anti-deadlock), from its last send.
            if self.side == Side::Client && !self.confirmed && !self.is_closed() {
                let l = if self.spaces[1].keys.is_some() {
                    Level::Handshake
                } else {
                    Level::Initial
                };
                return Some((self.last_sent + self.pto_base() * backoff, l, false));
            }
            return None;
        }
        for l in LEVELS {
            let s = &self.spaces[l as usize];
            if !s.in_flight_eliciting() {
                continue;
            }
            if l == Level::Data && !self.confirmed {
                continue;
            }
            let Some(t) = s.last_ack_eliciting else {
                continue;
            };
            let d = if l == Level::Data {
                self.pto()
            } else {
                self.pto_base()
            };
            let at = t + d * backoff;
            if best.is_none_or(|b| at < b.0) {
                best = Some((at, l, false));
            }
        }
        best
    }

    /// When [`on_timeout`](Self::on_timeout) has something to do.
    pub fn timeout(&self) -> Option<Duration> {
        match self.state {
            State::Closed => return None,
            State::Closing(t) | State::Draining(t) => return Some(t),
            _ => {}
        }
        let mut t = self.idle_deadline();
        if let Some(p) = self.pace_wake {
            t = Some(t.map_or(p, |x| x.min(p)));
        }
        if let Some((at, _, _)) = self.loss_timer() {
            t = Some(t.map_or(at, |x| x.min(at)));
        }
        for s in &self.spaces {
            if let Some(a) = s.ack_at {
                t = Some(t.map_or(a, |x| x.min(a)));
            }
        }
        t
    }

    fn idle_deadline(&self) -> Option<Duration> {
        let mine = self.settings.idle_timeout;
        let theirs = self.peer_params.as_ref().map_or(Duration::ZERO, |p| {
            Duration::from_millis(p.max_idle_timeout)
        });
        let t = match (mine.is_zero(), theirs.is_zero()) {
            (true, true) => return None,
            (true, false) => theirs,
            (false, true) => mine,
            (false, false) => mine.min(theirs),
        };
        Some(self.last_activity + t.max(3 * self.pto()))
    }

    pub fn on_timeout(&mut self, now: Duration) {
        match self.state {
            State::Closed => return,
            State::Closing(t) | State::Draining(t) => {
                if now >= t {
                    self.state = State::Closed;
                }
                return;
            }
            _ => {}
        }
        if self.idle_deadline().is_some_and(|t| now >= t) {
            let info = CloseInfo {
                local: true,
                app: false,
                code: code::NO_ERROR,
                reason: String::new(),
                idle: true,
            };
            self.close_info = Some(info.clone());
            self.events.push_back(Event::Closed(info));
            self.state = State::Closed;
            return;
        }
        for s in &mut self.spaces {
            if s.ack_at.is_some_and(|a| now >= a) {
                s.ack_at = None;
                s.ack_now = true;
            }
        }
        if let Some((at, level, loss)) = self.loss_timer() {
            if now >= at {
                if loss {
                    self.detect_lost(level, now);
                } else {
                    self.on_pto(level);
                }
            }
        }
    }

    fn on_pto(&mut self, level: Level) {
        self.pto_count += 1;
        self.stats.ptos += 1;
        // Send the oldest packets' data again, and probes regardless of the
        // congestion window.
        let li = level as usize;
        let frames: Vec<Retx> = self.spaces[li]
            .sent
            .values()
            .filter(|p| p.ack_eliciting)
            .take(2)
            .flat_map(|p| p.frames.clone())
            .collect();
        for r in frames {
            self.on_frame_lost(level, r);
        }
        if self.side == Side::Client && !self.confirmed && level == Level::Initial {
            // Probe with the Initial data again.
            let s = &mut self.spaces[0].crypto_send;
            if s.next > s.base {
                let (b, n) = (s.base, s.next);
                s.on_lost(b, n - b, false);
            }
        }
        self.spaces[li].probes = 2;
    }

    // ----- sending -----

    /// Closes the connection with an error (or NO_ERROR); `app` for the
    /// application's codes.
    pub fn close(&mut self, app: bool, code_: u64, reason: &str, now: Duration) {
        if self.is_closed() {
            return;
        }
        let info = CloseInfo {
            local: true,
            app,
            code: code_,
            reason: reason.to_string(),
            idle: false,
        };
        self.close_info = Some(info.clone());
        self.events.push_back(Event::Closed(info));
        self.close = Some(Frame::ConnectionClose {
            app,
            code: code_,
            frame_type: 0,
            reason: reason.as_bytes().to_vec(),
        });
        // Three times: the other end may wait for its idle timeout if
        // none arrives.
        self.close_resend = 3;
        self.state = State::Closing(now + 3 * self.pto());
    }

    fn fail(&mut self, code_: u64, reason: String) {
        if self.is_closed() {
            return;
        }
        let now = self.last_activity;
        self.close(false, code_, &reason, now);
    }

    /// The next datagram to send, if any.
    pub fn poll_transmit(&mut self, now: Duration) -> Option<Vec<u8>> {
        match self.state {
            State::Closed | State::Draining(_) => return None,
            State::Closing(_) if self.close_resend == 0 => return None,
            _ => {}
        }
        let mut budget = MAX_DATAGRAM;
        if !self.validated {
            let allowed = (3 * self.bytes_in).saturating_sub(self.bytes_out) as usize;
            budget = budget.min(allowed);
        }
        if budget < 64 {
            return None;
        }
        let probing = self.spaces.iter().any(|s| s.probes > 0);
        let cwnd_room = self.cwnd.saturating_sub(self.in_flight) as usize;
        // Pacing: new data at 1.25 congestion windows per RTT, in bursts of
        // up to ten datagrams.
        self.pace_wake = None;
        let paced = match self.smoothed_rtt {
            Some(srtt) if !srtt.is_zero() && self.handshake_done => {
                let rate = self.cwnd as f64 * 1.25 / srtt.as_secs_f64(); // bytes/s
                let cap = (10 * MAX_DATAGRAM) as f64;
                let dt = now.saturating_sub(self.pace_at).as_secs_f64();
                self.pace_tokens = (self.pace_tokens + dt * rate).min(cap);
                self.pace_at = now;
                if self.pace_tokens < MAX_DATAGRAM as f64 {
                    let wait = (MAX_DATAGRAM as f64 - self.pace_tokens) / rate;
                    self.pace_wake = Some(now + Duration::from_secs_f64(wait.max(1e-6)));
                    true
                } else {
                    false
                }
            }
            _ => false,
        };
        let cwnd_room = if paced { 0 } else { cwnd_room };
        let mut packets: Vec<(Level, Vec<u8>, Vec<Retx>, bool)> = Vec::new();
        let mut used = 0;
        for level in LEVELS {
            let li = level as usize;
            let has_keys = match level {
                Level::Data => self.one_rtt.is_some(),
                _ => self.spaces[li].keys.is_some(),
            };
            if !has_keys {
                continue;
            }
            let header = self.header_len(level);
            let room = budget.saturating_sub(used + header + TAG);
            if room < 32 {
                break;
            }
            let probe = self.spaces[li].probes > 0;
            let may_elicit = probe || (!probing && cwnd_room > used + header + TAG + 32);
            let (payload, retx, eliciting) = self.frames(level, room, may_elicit, now);
            if payload.is_empty() {
                continue;
            }
            if probe && eliciting {
                self.spaces[li].probes -= 1;
            }
            used += header + payload.len() + TAG;
            packets.push((level, payload, retx, eliciting));
        }
        if packets.is_empty() {
            return None;
        }
        // Initial datagrams of a client, and a server's with ack-eliciting
        // Initials, are at least 1200 bytes (within what we may send).
        let pad = packets
            .iter()
            .any(|p| p.0 == Level::Initial && (self.side == Side::Client || p.3));
        if pad && used < MAX_DATAGRAM && budget >= MAX_DATAGRAM {
            let last = packets.last_mut().unwrap();
            let n = MAX_DATAGRAM - used;
            last.1.extend(std::iter::repeat_n(0, n));
        }
        let mut out = Vec::with_capacity(MAX_DATAGRAM);
        let mut discard_initial = false;
        let eliciting_any = packets.iter().any(|p| p.3);
        for (level, payload, retx, eliciting) in packets {
            if level == Level::Handshake && self.side == Side::Client {
                discard_initial = true;
            }
            let size = self.seal(level, &payload, &mut out, retx, eliciting, now);
            self.bytes_out += size as u64;
        }
        if discard_initial {
            self.discard(Level::Initial);
        }
        if eliciting_any {
            self.pace_tokens = (self.pace_tokens - out.len() as f64).max(0.0);
        }
        if let State::Closing(_) = self.state {
            self.close_resend -= 1;
        }
        self.last_sent = now;
        self.stats.bytes_sent += out.len() as u64;
        Some(out)
    }

    fn header_len(&self, level: Level) -> usize {
        match level {
            Level::Data => 1 + self.dcid.len() + PN_LEN,
            Level::Initial => {
                1 + 4
                    + 1
                    + self.dcid.len()
                    + 1
                    + self.scid.len()
                    + super::frame::varint_len(self.token.len() as u64)
                    + self.token.len()
                    + 2
                    + PN_LEN
            }
            Level::Handshake => 1 + 4 + 1 + self.dcid.len() + 1 + self.scid.len() + 2 + PN_LEN,
        }
    }

    /// The frames of one packet in `level` within `room` bytes.
    fn frames(
        &mut self,
        level: Level,
        room: usize,
        may_elicit: bool,
        now: Duration,
    ) -> (Vec<u8>, Vec<Retx>, bool) {
        let li = level as usize;
        let mut out = Vec::new();
        let mut retx = Vec::new();
        if let State::Closing(_) = self.state {
            if let Some(Frame::ConnectionClose {
                app,
                code: c,
                frame_type,
                reason,
            }) = self.close.clone()
            {
                // An application's close cannot go in Initial or Handshake
                // packets: APPLICATION_ERROR there.
                let f = if app && level != Level::Data {
                    Frame::ConnectionClose {
                        app: false,
                        code: 0xc,
                        frame_type: 0,
                        reason: Vec::new(),
                    }
                } else {
                    Frame::ConnectionClose {
                        app,
                        code: c,
                        frame_type,
                        reason: reason[..reason.len().min(room.saturating_sub(16))].to_vec(),
                    }
                };
                // The highest space only, unless the other end may not have
                // its keys yet.
                let highest = LEVELS
                    .iter()
                    .rev()
                    .find(|&&l| match l {
                        Level::Data => self.one_rtt.is_some(),
                        _ => self.spaces[l as usize].keys.is_some(),
                    })
                    .copied();
                if Some(level) == highest || !self.handshake_done {
                    f.encode(&mut out);
                }
            }
            return (out, retx, false);
        }
        // ACK.
        let s = &mut self.spaces[li];
        if (s.ack_now || (s.unacked > 0 && may_elicit)) && !s.received.is_empty() {
            let ranges: Vec<(u64, u64)> = s
                .received
                .ranges()
                .iter()
                .rev()
                .take(MAX_ACK_RANGES)
                .map(|r| (r.start, r.end - 1))
                .collect();
            let delay = s.largest_recv.map_or(0, |(_, t)| {
                (now.saturating_sub(t).as_micros() as u64) >> ACK_DELAY_EXPONENT
            });
            let f = Frame::Ack(Ack { ranges, delay });
            if f.encoded_len() <= room {
                f.encode(&mut out);
                s.ack_now = false;
                s.ack_at = None;
                s.unacked = 0;
            }
        }
        if !may_elicit {
            return (out, retx, false);
        }
        let start = out.len();
        // CRYPTO.
        loop {
            let left = room.saturating_sub(out.len());
            if left < 16 {
                break;
            }
            let s = &mut self.spaces[li];
            let max = left - Frame::crypto_overhead(s.crypto_send.end(), left);
            let Some((off, data, _)) = s.crypto_send.take(max, u64::MAX) else {
                break;
            };
            if data.is_empty() {
                break;
            }
            retx.push(Retx::Crypto {
                off,
                len: data.len() as u64,
            });
            Frame::Crypto { offset: off, data }.encode(&mut out);
        }
        if level == Level::Data && self.state == State::Open {
            self.data_frames(room, &mut out, &mut retx);
        }
        let mut eliciting = out.len() > start;
        if !eliciting && self.spaces[li].probes > 0 && room > out.len() {
            Frame::Ping.encode(&mut out);
            eliciting = true;
        }
        (out, retx, eliciting)
    }

    fn data_frames(&mut self, room: usize, out: &mut Vec<u8>, retx: &mut Vec<Retx>) {
        if self.handshake_done_pending && out.len() < room {
            self.handshake_done_pending = false;
            Frame::HandshakeDone.encode(out);
            retx.push(Retx::HandshakeDone);
        }
        for d in std::mem::take(&mut self.path_responses) {
            Frame::PathResponse(d).encode(out);
        }
        if self.max_data_pending && out.len() + 9 < room {
            self.max_data_pending = false;
            Frame::MaxData(self.local_max_data).encode(out);
            retx.push(Retx::MaxData);
        }
        for (i, bidi) in [(0, true), (1, false)] {
            if self.max_streams_pending[i] && out.len() + 9 < room {
                self.max_streams_pending[i] = false;
                let max = if bidi {
                    self.local_max_bidi
                } else {
                    self.local_max_uni
                };
                Frame::MaxStreams { bidi, max }.encode(out);
                retx.push(Retx::MaxStreams(bidi));
            }
        }
        let ids: Vec<u64> = self.streams.keys().copied().collect();
        for &id in &ids {
            let s = self.streams.get_mut(&id).unwrap();
            if s.max_stream_data_pending && out.len() + 17 < room {
                s.max_stream_data_pending = false;
                Frame::MaxStreamData {
                    id,
                    max: s.recv_max,
                }
                .encode(out);
                retx.push(Retx::MaxStreamData(id));
            }
            if let (true, Some(c)) = (s.reset_pending, s.send_reset) {
                if out.len() + 25 < room {
                    s.reset_pending = false;
                    Frame::ResetStream {
                        id,
                        code: c,
                        final_size: s.send.next,
                    }
                    .encode(out);
                    retx.push(Retx::Reset(id));
                }
            }
            if let Some(c) = s.stop_pending {
                if out.len() + 17 < room {
                    s.stop_pending = None;
                    Frame::StopSending { id, code: c }.encode(out);
                    retx.push(Retx::StopSending(id));
                }
            }
        }
        // Stream data, round robin from the cursor.
        if ids.is_empty() {
            return;
        }
        let at = ids.iter().position(|&i| i >= self.cursor).unwrap_or(0);
        let order: Vec<u64> = ids[at..].iter().chain(&ids[..at]).copied().collect();
        for id in order {
            let left = room.saturating_sub(out.len());
            if left < 24 {
                break;
            }
            let conn_left = self.peer_max_data.saturating_sub(self.data_sent);
            let Some(s) = self.streams.get_mut(&id) else {
                continue;
            };
            if !s.can_send || s.send_reset.is_some() {
                continue;
            }
            let limit = s.send_max.min(s.send.next + conn_left);
            if !s.send.wants(limit) {
                continue;
            }
            let max = left - Frame::stream_overhead(id, s.send.end(), left);
            let before = s.send.next;
            let Some((off, data, fin)) = s.send.take(max, limit) else {
                continue;
            };
            self.data_sent += s.send.next - before;
            retx.push(Retx::Stream {
                id,
                off,
                len: data.len() as u64,
                fin,
            });
            Frame::Stream {
                id,
                offset: off,
                data,
                fin,
            }
            .encode(out);
            self.cursor = id + 1;
        }
    }

    /// Protects one packet and appends it; returns its size.
    fn seal(
        &mut self,
        level: Level,
        payload: &[u8],
        out: &mut Vec<u8>,
        retx: Vec<Retx>,
        eliciting: bool,
        now: Duration,
    ) -> usize {
        let li = level as usize;
        // A key update of our own, when it is due and allowed.
        if level == Level::Data && self.settings.key_update_after > 0 && self.confirmed {
            let next_pn = self.spaces[2].next_pn;
            if let Some(k) = self.one_rtt.as_mut() {
                if k.phase_acked && k.sent_in_phase >= self.settings.key_update_after {
                    k.update(next_pn);
                    self.stats.key_updates += 1;
                }
            }
        }
        let pn = self.spaces[li].next_pn;
        self.spaces[li].next_pn += 1;
        let start = out.len();
        let phase = self.one_rtt.as_ref().is_some_and(|k| k.phase);
        match level {
            Level::Data => {
                out.push(0x40 | if phase { 0x04 } else { 0 } | (PN_LEN as u8 - 1));
                out.extend_from_slice(&self.dcid);
            }
            _ => {
                let ty = if level == Level::Initial { 0 } else { 2 };
                out.push(0xc0 | (ty << 4) | (PN_LEN as u8 - 1));
                out.extend_from_slice(&VERSION.to_be_bytes());
                out.push(self.dcid.len() as u8);
                out.extend_from_slice(&self.dcid);
                out.push(self.scid.len() as u8);
                out.extend_from_slice(&self.scid);
                if level == Level::Initial {
                    super::frame::put_varint(out, self.token.len() as u64);
                    out.extend_from_slice(&self.token);
                }
                let len = (PN_LEN + payload.len() + TAG) as u16;
                out.extend_from_slice(&(len | 0x4000).to_be_bytes());
            }
        }
        let pn_off = out.len();
        out.extend_from_slice(&(pn as u32).to_be_bytes());
        let hdr_end = out.len();
        out.extend_from_slice(payload);
        let (keys_packet, keys_hp): (&dyn rq::PacketKey, &dyn rq::HeaderProtectionKey) = match level
        {
            Level::Data => {
                let k = self.one_rtt.as_ref().unwrap();
                (&*k.local, &*k.local_hp)
            }
            l => {
                let k: &DirectionalKeys = &self.spaces[l as usize].keys.as_ref().unwrap().local;
                (&*k.packet, &*k.header)
            }
        };
        let (head, body) = out[start..].split_at_mut(hdr_end - start);
        let tag = keys_packet
            .encrypt_in_place(pn, head, body)
            .expect("QUIC packet encryption");
        out.extend_from_slice(tag.as_ref());
        let sample_at = pn_off + 4;
        let sample = out[sample_at..sample_at + 16].to_vec();
        let (h, rest) = out[start..].split_at_mut(pn_off - start);
        keys_hp
            .encrypt_in_place(&sample, &mut h[0], &mut rest[..PN_LEN])
            .expect("QUIC header protection");
        let size = out.len() - start;
        self.stats.packets_sent += 1;
        if level == Level::Data {
            if let Some(k) = self.one_rtt.as_mut() {
                k.sent_in_phase += 1;
            }
        }
        if eliciting {
            self.in_flight += size as u64;
            self.spaces[li].last_ack_eliciting = Some(now);
            // The idle timer restarts with the first ack-eliciting packet
            // after one received.
            if self.idle_armed {
                self.idle_armed = false;
                self.last_activity = now;
            }
        }
        self.spaces[li].sent.insert(
            pn,
            Sent {
                time: now,
                size,
                ack_eliciting: eliciting,
                in_flight: eliciting,
                frames: retx,
                phase,
            },
        );
        size
    }
}

fn local_params(
    s: &QuicSettings,
    scid: &[u8],
    odcid: Option<&[u8]>,
    retry_scid: Option<&[u8]>,
) -> Params {
    Params {
        original_dcid: odcid.map(<[u8]>::to_vec),
        max_idle_timeout: s.idle_timeout.as_millis() as u64,
        max_udp_payload_size: 1452,
        initial_max_data: s.max_data,
        initial_max_stream_data_bidi_local: s.stream_window,
        initial_max_stream_data_bidi_remote: s.stream_window,
        initial_max_stream_data_uni: s.stream_window,
        initial_max_streams_bidi: s.max_streams_bidi,
        initial_max_streams_uni: s.max_streams_uni,
        ack_delay_exponent: ACK_DELAY_EXPONENT,
        max_ack_delay: ACK_DELAY.as_millis() as u64,
        disable_active_migration: true,
        active_connection_id_limit: 2,
        initial_scid: Some(scid.to_vec()),
        retry_scid: retry_scid.map(<[u8]>::to_vec),
        stateless_reset_token: None,
    }
}

#[cfg(any(test, feature = "fuzzing"))]
#[allow(dead_code)]
impl Conn {
    /// For the fuzz targets: takes `payload` as the plaintext of a 1-RTT
    /// packet numbered `pn`.
    pub(crate) fn fuzz_packet(&mut self, pn: u64, payload: &[u8], now: Duration) {
        self.on_packet(Level::Data, pn, payload, now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_numbers_as_in_the_rfc() {
        // RFC 9000 appendix A.3.
        assert_eq!(decode_pn(0x9b32, 2, Some(0xa82f30ea)), 0xa82f9b32);
        assert_eq!(decode_pn(5, 4, None), 5);
        assert_eq!(decode_pn(0xff, 1, Some(0x100)), 0xff);
    }

    #[test]
    fn retry_tag_as_in_the_rfc() {
        // RFC 9001 appendix A.4.
        let odcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let packet = [
            0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
            0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
        ];
        let tag = [
            0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24,
            0x96, 0xba,
        ];
        assert_eq!(retry_tag(&odcid, &packet), tag);
    }

    #[test]
    fn send_buffers_resend_what_was_lost() {
        let mut b = SendBuf::default();
        b.push(&[1; 100]);
        b.fin = true;
        let (o, d, f) = b.take(60, u64::MAX).unwrap();
        assert_eq!((o, d.len(), f), (0, 60, false));
        let (o, d, f) = b.take(60, u64::MAX).unwrap();
        assert_eq!((o, d.len(), f), (60, 40, true));
        assert!(b.take(60, u64::MAX).is_none());
        b.on_lost(0, 60, false);
        b.on_acked(60, 40, true);
        assert!(!b.done());
        let (o, d, _) = b.take(30, u64::MAX).unwrap();
        assert_eq!((o, d.len()), (0, 30));
        b.on_acked(0, 30, false);
        let (o, d, _) = b.take(100, u64::MAX).unwrap();
        assert_eq!((o, d.len()), (30, 30));
        b.on_acked(30, 30, false);
        assert!(b.done());
        // Flow control holds new bytes back.
        let mut b = SendBuf::default();
        b.push(&[0; 10]);
        assert_eq!(b.take(100, 4).unwrap().1.len(), 4);
        assert!(!b.wants(4));
        assert!(b.wants(10));
    }

    #[test]
    fn receive_buffers_put_bytes_in_order() {
        let mut r = RecvBuf::default();
        assert_eq!(r.insert(5, b"world", true), Ok(10));
        assert!(!r.readable());
        assert_eq!(r.insert(0, b"hello", false), Ok(0));
        assert_eq!(r.read(), (b"helloworld".to_vec(), true));
        assert!(r.insert(8, b"xyz", false).is_err());
        let mut r = RecvBuf::default();
        r.insert(0, b"abcdef", false).unwrap();
        r.insert(2, b"cdefgh", false).unwrap();
        assert_eq!(r.read().0, b"abcdefgh");
    }
}
