//! Application protocols on top of the TCP and UDP engines.
//!
//! The engines move bytes: [`TcpEngine`](crate::TcpEngine) runs real
//! connections and [`UdpEngine`](crate::UdpEngine) runs request/response
//! transactions with retries. What goes over them can be a replay of a
//! capture, or an application protocol that reacts to what the other end
//! sends: a server that parses each HTTP request and answers with the route
//! that matches, a client that checks the status code, a DNS server that
//! looks the question up. Protocols plug in here instead of being written
//! into the engines:
//!
//! * [`AppProtocol`] is a configured protocol, such as HTTP with its requests
//!   and routes. It makes one [`AppSession`] per connection (TCP) or
//!   transaction (UDP), for the client or the server end.
//! * [`AppSession`] is sans-IO: the engine hands it the bytes that arrived
//!   in order (a stream) or one datagram, and it answers through an
//!   [`AppCx`]: bytes to send, a timer, "close now", and the transactions it
//!   finished, each with a label (an HTTP status, a DNS response code), whether
//!   it went as expected and its response time.
//! * [`App`] is a shared handle to a protocol, as templates hold it.
//! * [`AppStats`] are the counters per side and template: transactions,
//!   failures, error answers, labels and response times.
//! * [`AppRegistry`] (feature `profile`) maps the `app = "..."` name in a
//!   profile to the code that reads the protocol's table, so programs can add
//!   their own protocols.
//!
//! The built-in protocols are [`http`] (HTTP/1.1 client and server),
//! [`http2`] (HTTP/2 client and server, h2 and h2c), [`dns`]
//! (over UDP, and over TCP with length prefixes), [`mqtt`] (client and
//! broker, 3.1.1 and 5.0), [`ntp`] and [`ssh`] (feature `ssh`: client and
//! server, OpenSSH-compatible); [`tls`]
//! (feature `tls`) runs any stream protocol over TLS (HTTPS = TLS + HTTP).

pub mod dns;
pub mod http;
pub mod http2;
pub mod mqtt;
pub mod ntp;
pub mod quality;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "profile")]
mod registry;
pub mod sip;
pub mod smb;
#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(feature = "tls")]
pub mod tls;

use std::any::Any;
use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::{LatencyStats, Result, TcpRole};

#[cfg(feature = "profile")]
pub(crate) use registry::{document, take_apps};
#[cfg(feature = "profile")]
pub use registry::{AppParser, AppRegistry};

/// Which end of a connection or transaction a session plays.
pub type AppRole = TcpRole;

/// How the engine carries a session's bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport {
    /// A TCP connection: bytes in order, no message boundaries.
    Stream,
    /// UDP: each [`AppCx::send`] is one datagram, and each received datagram
    /// comes on its own.
    Datagram,
}

impl Transport {
    pub fn name(self) -> &'static str {
        match self {
            Transport::Stream => "tcp",
            Transport::Datagram => "udp",
        }
    }
}

/// What a new session is for.
#[derive(Clone, Debug)]
pub struct SessionInit {
    pub role: AppRole,
    pub transport: Transport,
    /// The number of the connection or transaction, from 0, counted per
    /// template and side: a client picks its requests by it.
    pub index: u64,
    /// A seed of its own, for ids and random bytes.
    pub seed: u64,
    /// This end's address and port.
    pub local: SocketAddr,
    /// The other end's.
    pub remote: SocketAddr,
}

/// A configured application protocol: makes the sessions of one template.
///
/// Implement it (and [`AppSession`]) to add a protocol; wrap it in an
/// [`App`] to put it in a [`TcpTemplate`](crate::TcpTemplate) or a
/// [`UdpApp`](crate::UdpApp).
pub trait AppProtocol: Send + Sync + 'static {
    /// The protocol's name, as `app = "..."` gives it: `http`, `dns`.
    fn name(&self) -> &str;
    /// A line about what it plays, e.g. `HTTP/1.1: 3 requests, 2 routes`.
    fn describe(&self) -> String;
    /// The port its servers listen on unless a template says otherwise.
    fn default_port(&self) -> u16;
    /// Whether it runs over `transport`.
    fn supports(&self, transport: Transport) -> bool;
    /// Checks that it can play `role` over `transport`, such as a client
    /// that has requests to send.
    fn validate(&self, _role: AppRole, _transport: Transport) -> Result<()> {
        Ok(())
    }
    /// Over UDP: whether a session plays a whole dialog (SIP) instead of
    /// one request and its answer. The UDP engine then hands the session
    /// every datagram of its addresses, sends what it sends when it sends
    /// it, and leaves timers and retransmissions to it: the session ends
    /// when it calls [`AppCx::close`] (a server's: nothing is open now; it
    /// stays for repeats, and opens again when it takes something new), or
    /// when nothing arrives for the session timeout while it has no timer.
    fn dialog(&self) -> bool {
        false
    }
    /// Over UDP: how many consecutive ports each session gets for media
    /// (2 for RTP and RTCP), from the engine's media port range. The session
    /// learns the first with [`AppCx::media_port`], sends from them with
    /// [`AppCx::send_media`] and gets what arrives on them in
    /// [`AppSession::media`]. Only for [`dialog`](Self::dialog) protocols.
    fn media_ports(&self) -> u16 {
        0
    }
    /// A session for one connection or transaction.
    fn session(&self, init: &SessionInit) -> Box<dyn AppSession>;
    /// For downcasting to the concrete protocol (`app.as_any().downcast_ref`).
    fn as_any(&self) -> &dyn Any;
}

/// What a session did with a received datagram or bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Receive {
    /// It was for this session.
    Taken,
    /// A datagram that belongs to another transaction (a late answer, a
    /// wrong id): the UDP engine counts it as unmatched and keeps waiting.
    /// Over TCP every byte is the session's; this is taken as a protocol error.
    NotMine,
}

/// One end of a connection or transaction, as a protocol plays it.
///
/// The engine calls it as things happen and the session answers through the
/// [`AppCx`]. Over TCP, [`start`](Self::start) comes when the connection is
/// open, [`receive`](Self::receive) with the bytes that arrived in order,
/// [`peer_closed`](Self::peer_closed) after the other end's FIN. After that,
/// or once the session called [`AppCx::close`], the engine closes the
/// connection when nothing is left to send. Over UDP the client's `start`
/// sends the request; the server's session starts on the first datagram,
/// with `receive`. The UDP engine sends a request again when its answer is
/// late, and a server's last answer again when a request repeats.
pub trait AppSession: Send {
    fn start(&mut self, _cx: &mut AppCx) {}
    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive;
    fn peer_closed(&mut self, _cx: &mut AppCx) {}
    /// The time given to [`AppCx::wake_at`] has come.
    fn timer(&mut self, _cx: &mut AppCx) {}
    /// A datagram arrived on one of the session's media ports (see
    /// [`AppProtocol::media_ports`]) from `from`.
    fn media(&mut self, _port: u16, _from: SocketAddr, _data: &[u8], _cx: &mut AppCx) {}
}

/// A transaction a session finished: an HTTP request and its response, a DNS
/// query and its answer.
#[derive(Clone, Debug, PartialEq)]
pub struct AppTransaction {
    /// What it ended with, for the counters: `200`, `NXDOMAIN`.
    pub label: String,
    /// It went as the profile expects (a client got the expected status).
    pub ok: bool,
    /// The answer was an error: an HTTP status of 400 or more, a DNS
    /// response code other than NOERROR. It can still be `ok` when expected.
    pub error: bool,
    /// Client: from the request to the whole answer.
    pub response_time: Option<Duration>,
}

impl AppTransaction {
    pub fn new(label: impl Into<String>, ok: bool) -> Self {
        Self {
            label: label.into(),
            ok,
            error: false,
            response_time: None,
        }
    }

    pub fn with_error(mut self, error: bool) -> Self {
        self.error = error;
        self
    }

    pub fn with_response_time(mut self, t: Duration) -> Self {
        self.response_time = Some(t);
        self
    }
}

/// What a session tells the engine while it handles an event.
/// A finished TLS (or other) handshake, as a layer under a protocol counts
/// it with [`AppCx::handshake`].
#[derive(Clone, Debug, PartialEq)]
pub struct AppHandshake {
    /// What was negotiated (`TLSv1.3 TLS13_AES_128_GCM_SHA256`), or why it
    /// failed (`failed: alert HandshakeFailure`).
    pub label: String,
    /// The handshake succeeded.
    pub succeeded: bool,
    /// The outcome is the one expected (a failure can be).
    pub expected: bool,
    /// A resumed session (a ticket or session id).
    pub resumed: bool,
    /// From the first handshake message to the end.
    pub time: Option<Duration>,
}

/// What a media stream (RTP and its RTCP) carried, as a session counts it
/// with [`AppCx::media`] when the stream ends.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MediaReport {
    /// The codec, e.g. `PCMU`.
    pub codec: String,
    pub packets_sent: u64,
    pub packets_received: u64,
    /// Packets that never came: the sequence numbers between the first and
    /// the last received that are missing.
    pub lost: u64,
    pub duplicates: u64,
    /// Packets that came after one with a later sequence number.
    pub reordered: u64,
    /// The interarrival jitter (RFC 3550) when the stream ended.
    pub jitter: Duration,
    pub rtcp_sent: u64,
    pub rtcp_received: u64,
    /// Packets that came too late for the jitter buffer (counted as lost
    /// for the score, not in `lost`).
    pub late: u64,
    /// Runs of lost or late packets, and the longest run.
    pub loss_bursts: u64,
    pub max_burst: u64,
    /// The burst ratio (G.113): 1 for random loss, more for bursts.
    pub burst_ratio: f64,
    /// The mean round trip from the other end's RTCP reports; none before
    /// one came back with our sender report's time in it.
    pub rtt: Option<Duration>,
    /// What the other end's last RTCP report said about our packets: lost
    /// in all, and its jitter.
    pub remote_lost: Option<u64>,
    pub remote_jitter: Option<Duration>,
    /// The one-way delay the score took: half the round trip, the jitter
    /// buffer and one packet time.
    pub delay: Duration,
    /// The E-model's R (0 to 100) and the estimated MOS (1 to 4.5); none
    /// when nothing came.
    pub r_factor: Option<f64>,
    pub mos: Option<f64>,
}

#[derive(Debug, Default)]
pub struct AppCx {
    now: Duration,
    wall: Duration,
    sends: Vec<Vec<u8>>,
    media_port: Option<u16>,
    media_sends: Vec<(u16, u16, Vec<u8>)>,
    media: Vec<MediaReport>,
    close: bool,
    goodbye: bool,
    resent: u64,
    wake: Option<Duration>,
    transactions: Vec<AppTransaction>,
    protocol_errors: Vec<String>,
    handshakes: Vec<AppHandshake>,
}

impl AppCx {
    /// A context at engine time `now`; `wall` is the time of day (since
    /// 1970), when the engine knows it, else `now`.
    pub fn new(now: Duration, wall: Duration) -> Self {
        Self {
            now,
            wall,
            ..Default::default()
        }
    }

    /// The engine's clock: time since the run started.
    pub fn now(&self) -> Duration {
        self.now
    }

    /// The time of day, as time since 1970, for protocols that send it (NTP).
    pub fn wall(&self) -> Duration {
        self.wall
    }

    /// Sends `data`: appended to the stream, or one datagram.
    pub fn send(&mut self, data: impl Into<Vec<u8>>) {
        let d = data.into();
        if !d.is_empty() {
            self.sends.push(d);
        }
    }

    /// The session's first media port (see [`AppProtocol::media_ports`]).
    pub fn media_port(&self) -> Option<u16> {
        self.media_port
    }

    /// A context for a session with media ports from `port`.
    pub fn with_media_port(mut self, port: Option<u16>) -> Self {
        self.media_port = port;
        self
    }

    /// Sends one datagram from media port `from` (one of the session's) to
    /// port `to` of the other end's address.
    pub fn send_media(&mut self, from: u16, to: u16, data: impl Into<Vec<u8>>) {
        self.media_sends.push((from, to, data.into()));
    }

    /// The media datagrams sent, as (from port, to port, data). Empties it.
    pub fn take_media_sends(&mut self) -> Vec<(u16, u16, Vec<u8>)> {
        std::mem::take(&mut self.media_sends)
    }

    /// Counts a media stream that ended.
    pub fn media(&mut self, m: MediaReport) {
        self.media.push(m);
    }

    pub fn media_reports(&self) -> &[MediaReport] {
        &self.media
    }

    /// Counts packets the protocol sent again (QUIC's lost packets): the
    /// UDP engine's "sent again".
    pub fn resent(&mut self, n: u64) {
        self.resent += n;
    }

    pub fn resent_count(&self) -> u64 {
        self.resent
    }

    /// Closes the connection once what was sent has gone (TCP), or ends
    /// the transaction (UDP).
    pub fn close(&mut self) {
        self.close = true;
    }

    /// The other end said goodbye in the protocol (SSH's DISCONNECT): its
    /// socket is closed or closing, so a TCP reset from it after this does
    /// not fail the connection. Whatever we still had in flight is not for
    /// anyone.
    pub fn goodbye(&mut self) {
        self.goodbye = true;
    }

    pub fn said_goodbye(&self) -> bool {
        self.goodbye
    }

    /// Calls [`AppSession::timer`] at `at` (engine time); a later call
    /// replaces it.
    pub fn wake_at(&mut self, at: Duration) {
        self.wake = Some(at);
    }

    /// Counts a finished transaction.
    pub fn transaction(&mut self, t: AppTransaction) {
        self.transactions.push(t);
    }

    /// Counts something the other end sent that the protocol cannot take:
    /// it fails the connection or transaction.
    pub fn protocol_error(&mut self, what: impl Into<String>) {
        self.protocol_errors.push(what.into());
    }

    /// Counts a finished handshake; one with an unexpected outcome marks
    /// the connection mismatched.
    pub fn handshake(&mut self, h: AppHandshake) {
        self.handshakes.push(h);
    }

    /// Takes over what a session run with `inner` (a protocol on top of
    /// this one) did, except its bytes, which it returns: they are for the
    /// layer in between to wrap.
    pub fn absorb(&mut self, mut inner: AppCx) -> Vec<Vec<u8>> {
        self.close |= inner.close;
        self.goodbye |= inner.goodbye;
        self.resent += inner.resent;
        if inner.wake.is_some() {
            self.wake = inner.wake;
        }
        self.transactions.append(&mut inner.transactions);
        self.protocol_errors.append(&mut inner.protocol_errors);
        self.handshakes.append(&mut inner.handshakes);
        self.media.append(&mut inner.media);
        self.media_sends.append(&mut inner.media_sends);
        inner.sends
    }

    /// What was sent, in order. Empties it.
    pub fn take_sends(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.sends)
    }

    pub fn wants_close(&self) -> bool {
        self.close
    }

    pub fn wake(&self) -> Option<Duration> {
        self.wake
    }

    pub fn transactions(&self) -> &[AppTransaction] {
        &self.transactions
    }

    pub fn protocol_errors(&self) -> &[String] {
        &self.protocol_errors
    }

    pub fn handshakes(&self) -> &[AppHandshake] {
        &self.handshakes
    }

    /// True if nothing that happened failed: no protocol errors, every
    /// transaction and handshake as expected.
    pub fn all_ok(&self) -> bool {
        self.protocol_errors.is_empty()
            && self.transactions.iter().all(|t| t.ok)
            && self.handshakes.iter().all(|h| h.expected)
    }

    /// True if a transaction ended with an error answer.
    pub fn any_error(&self) -> bool {
        self.transactions.iter().any(|t| t.error)
    }

    /// Adds what happened to `stats`.
    pub fn count_into(&self, stats: &mut AppStats) {
        for t in &self.transactions {
            stats.record(t);
        }
        stats.protocol_errors += self.protocol_errors.len() as u64;
        for e in &self.protocol_errors {
            stats.sample_error(e);
        }
        for h in &self.handshakes {
            stats.record_handshake(h);
            if h.succeeded {
                stats.handshake_done_at(self.now);
            }
        }
        for m in &self.media {
            stats.media.record(m);
        }
    }
}

/// A shared, configured application protocol, as a template holds it.
#[derive(Clone)]
pub struct App(Arc<dyn AppProtocol>);

impl App {
    pub fn new(protocol: impl AppProtocol) -> Self {
        Self(Arc::new(protocol))
    }

    pub fn from_arc(protocol: Arc<dyn AppProtocol>) -> Self {
        Self(protocol)
    }

    pub fn protocol(&self) -> &dyn AppProtocol {
        &*self.0
    }

    pub fn name(&self) -> &str {
        self.0.name()
    }

    pub fn describe(&self) -> String {
        self.0.describe()
    }

    pub fn default_port(&self) -> u16 {
        self.0.default_port()
    }

    pub fn supports(&self, t: Transport) -> bool {
        self.0.supports(t)
    }

    pub fn session(&self, init: &SessionInit) -> Box<dyn AppSession> {
        self.0.session(init)
    }

    /// The concrete protocol, if it is a `T`.
    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        self.0.as_any().downcast_ref()
    }

    /// Checks that the protocol runs over `transport` and can play `role`.
    pub fn validate(&self, role: AppRole, transport: Transport) -> Result<()> {
        if !self.supports(transport) {
            return Err(crate::Error::Profile(format!(
                "{} does not run over {}",
                self.name(),
                transport.name().to_uppercase()
            )));
        }
        self.0.validate(role, transport)
    }
}

impl fmt::Debug for App {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "App({}: {})", self.name(), self.describe())
    }
}

impl fmt::Display for App {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

/// Two handles are equal when they are the same protocol object, or the
/// same protocol described the same way.
impl PartialEq for App {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
            || (self.name() == other.name() && self.describe() == other.describe())
    }
}

/// Application counters of one side (of a template, or of all).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AppStats {
    /// Transactions finished: requests answered (client), answers sent (server).
    pub transactions: u64,
    /// Transactions that did not go as expected (wrong status or answer).
    pub failed: u64,
    /// Transactions answered with an error status or code.
    pub errors: u64,
    /// Things the other end sent that the protocol could not take.
    pub protocol_errors: u64,
    /// What the first few protocol errors were (up to
    /// [`ERROR_SAMPLES`](Self::ERROR_SAMPLES), each once).
    pub protocol_error_samples: Vec<String>,
    /// Transactions by label (`200`, `404`, `NOERROR`, `NXDOMAIN`).
    pub codes: BTreeMap<String, u64>,
    /// Client: from each request to its whole answer.
    pub response_time: LatencyStats,
    /// Handshakes that ended, either way (TLS).
    pub handshakes: u64,
    /// Handshakes that failed, expected or not.
    pub handshake_failures: u64,
    /// Handshakes with another outcome than the expected one.
    pub handshakes_unexpected: u64,
    /// Handshakes that resumed a session.
    pub resumed: u64,
    /// What the handshakes negotiated, or why they failed, with counts.
    pub negotiated: BTreeMap<String, u64>,
    /// From each handshake's first message to its end.
    pub handshake_time: LatencyStats,
    /// The same for the handshakes that made a new session and for those
    /// that resumed one.
    pub full_time: LatencyStats,
    pub resumed_time: LatencyStats,
    /// When the first and the last handshake that succeeded ended (engine
    /// time), for the rate.
    pub first_handshake: Option<Duration>,
    pub last_handshake: Option<Duration>,
    /// Media streams (RTP), for protocols that carry them (SIP).
    pub media: MediaStats,
}

/// Media streams of one side: what [`MediaReport`]s added up to.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MediaStats {
    /// Streams that ended.
    pub streams: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub lost: u64,
    pub duplicates: u64,
    pub reordered: u64,
    /// Each stream's jitter at its end.
    pub jitter: LatencyStats,
    pub rtcp_sent: u64,
    pub rtcp_received: u64,
    /// Streams by codec.
    pub codecs: BTreeMap<String, u64>,
    /// Packets too late for the jitter buffer.
    pub late: u64,
    /// Runs of lost or late packets, and the longest in any stream.
    pub loss_bursts: u64,
    pub max_burst: u64,
    /// Each stream's mean RTCP round trip, for those that measured one.
    pub rtt: LatencyStats,
    /// Lost packets the other ends reported (RTCP) about ours.
    pub remote_lost: u64,
    /// Streams with a score (something came), and the sums and worst of
    /// their R and MOS.
    pub scored: u64,
    pub r_sum: f64,
    pub r_min: Option<f64>,
    pub mos_sum: f64,
    pub mos_min: Option<f64>,
    /// Scored streams by G.109 band of R (see
    /// [`quality::BANDS`](quality::BANDS)): 90 and up, 80, 70, 60, 50,
    /// below 50.
    pub bands: [u64; 6],
}

impl MediaStats {
    pub fn record(&mut self, m: &MediaReport) {
        self.streams += 1;
        self.packets_sent += m.packets_sent;
        self.packets_received += m.packets_received;
        self.lost += m.lost;
        self.duplicates += m.duplicates;
        self.reordered += m.reordered;
        self.jitter.record(Some(m.jitter));
        self.rtcp_sent += m.rtcp_sent;
        self.rtcp_received += m.rtcp_received;
        *self.codecs.entry(m.codec.clone()).or_default() += 1;
        self.late += m.late;
        self.loss_bursts += m.loss_bursts;
        self.max_burst = self.max_burst.max(m.max_burst);
        if let Some(rtt) = m.rtt {
            self.rtt.record(Some(rtt));
        }
        self.remote_lost += m.remote_lost.unwrap_or(0);
        if let (Some(r), Some(mos)) = (m.r_factor, m.mos) {
            self.scored += 1;
            self.r_sum += r;
            self.mos_sum += mos;
            self.r_min = Some(self.r_min.map_or(r, |x| x.min(r)));
            self.mos_min = Some(self.mos_min.map_or(mos, |x| x.min(mos)));
            self.bands[quality::band(r)] += 1;
        }
    }

    pub fn merge(&mut self, o: &Self) {
        self.streams += o.streams;
        self.packets_sent += o.packets_sent;
        self.packets_received += o.packets_received;
        self.lost += o.lost;
        self.duplicates += o.duplicates;
        self.reordered += o.reordered;
        self.jitter.merge(&o.jitter);
        self.rtcp_sent += o.rtcp_sent;
        self.rtcp_received += o.rtcp_received;
        for (k, v) in &o.codecs {
            *self.codecs.entry(k.clone()).or_default() += v;
        }
        self.late += o.late;
        self.loss_bursts += o.loss_bursts;
        self.max_burst = self.max_burst.max(o.max_burst);
        self.rtt.merge(&o.rtt);
        self.remote_lost += o.remote_lost;
        self.scored += o.scored;
        self.r_sum += o.r_sum;
        self.mos_sum += o.mos_sum;
        let min = |a: Option<f64>, b: Option<f64>| match (a, b) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.r_min = min(self.r_min, o.r_min);
        self.mos_min = min(self.mos_min, o.mos_min);
        for (a, b) in self.bands.iter_mut().zip(o.bands) {
            *a += b;
        }
    }

    /// Lost packets as a share of those expected (received and lost).
    pub fn loss(&self) -> f64 {
        let expected = self.packets_received + self.lost;
        if expected == 0 {
            0.0
        } else {
            self.lost as f64 / expected as f64
        }
    }

    /// Lost and late packets as a share of those expected: the loss a
    /// phone's jitter buffer sees.
    pub fn playout_loss(&self) -> f64 {
        let expected = self.packets_received + self.lost;
        if expected == 0 {
            0.0
        } else {
            ((self.lost + self.late) as f64 / expected as f64).min(1.0)
        }
    }

    /// The mean R and MOS of the scored streams.
    pub fn r_avg(&self) -> Option<f64> {
        (self.scored > 0).then(|| self.r_sum / self.scored as f64)
    }

    pub fn mos_avg(&self) -> Option<f64> {
        (self.scored > 0).then(|| self.mos_sum / self.scored as f64)
    }

    /// The scored streams by band, best first, those with any:
    /// `satisfied x3, many dissatisfied x1`.
    pub fn bands_text(&self) -> String {
        quality::BANDS
            .iter()
            .zip(self.bands)
            .filter(|(_, n)| *n > 0)
            .map(|(b, n)| format!("{b} x{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl AppStats {
    pub fn record(&mut self, t: &AppTransaction) {
        self.transactions += 1;
        self.failed += u64::from(!t.ok);
        self.errors += u64::from(t.error);
        *self.codes.entry(t.label.clone()).or_default() += 1;
        if let Some(rt) = t.response_time {
            self.response_time.record(Some(rt));
        }
    }

    /// How many protocol errors [`protocol_error_samples`](Self::protocol_error_samples) keeps.
    pub const ERROR_SAMPLES: usize = 5;

    /// Keeps `e` among the samples of protocol errors, if there is room
    /// and it is new.
    pub fn sample_error(&mut self, e: &str) {
        if self.protocol_error_samples.len() < Self::ERROR_SAMPLES
            && !self.protocol_error_samples.iter().any(|s| s == e)
        {
            self.protocol_error_samples.push(e.to_string());
        }
    }

    pub fn record_handshake(&mut self, h: &AppHandshake) {
        self.handshakes += 1;
        self.handshake_failures += u64::from(!h.succeeded);
        self.handshakes_unexpected += u64::from(!h.expected);
        self.resumed += u64::from(h.resumed);
        *self.negotiated.entry(h.label.clone()).or_default() += 1;
        if let Some(t) = h.time {
            self.handshake_time.record(Some(t));
            if h.succeeded {
                if h.resumed {
                    self.resumed_time.record(Some(t));
                } else {
                    self.full_time.record(Some(t));
                }
            }
        }
    }

    /// Notes that a handshake succeeded at `at` (engine time).
    pub fn handshake_done_at(&mut self, at: Duration) {
        self.first_handshake = Some(self.first_handshake.map_or(at, |f| f.min(at)));
        self.last_handshake = Some(self.last_handshake.map_or(at, |l| l.max(at)));
    }

    /// Handshakes that succeeded with a new session (not resumed).
    pub fn full_handshakes(&self) -> u64 {
        (self.handshakes - self.handshake_failures).saturating_sub(self.resumed)
    }

    /// Successful handshakes per second, from the first to end to the last;
    /// none before two ended at different times.
    pub fn handshake_rate(&self) -> Option<f64> {
        let ok = self.handshakes - self.handshake_failures;
        let span = self.last_handshake?.checked_sub(self.first_handshake?)?;
        (ok > 1 && !span.is_zero()).then(|| (ok - 1) as f64 / span.as_secs_f64())
    }

    pub fn is_empty(&self) -> bool {
        self.transactions == 0
            && self.protocol_errors == 0
            && self.handshakes == 0
            && self.media.streams == 0
    }

    pub fn merge(&mut self, o: &Self) {
        self.transactions += o.transactions;
        self.failed += o.failed;
        self.errors += o.errors;
        self.protocol_errors += o.protocol_errors;
        for e in &o.protocol_error_samples {
            self.sample_error(e);
        }
        for (k, v) in &o.codes {
            *self.codes.entry(k.clone()).or_default() += v;
        }
        self.response_time.merge(&o.response_time);
        self.handshakes += o.handshakes;
        self.handshake_failures += o.handshake_failures;
        self.handshakes_unexpected += o.handshakes_unexpected;
        self.resumed += o.resumed;
        for (k, v) in &o.negotiated {
            *self.negotiated.entry(k.clone()).or_default() += v;
        }
        self.handshake_time.merge(&o.handshake_time);
        self.full_time.merge(&o.full_time);
        self.resumed_time.merge(&o.resumed_time);
        let pick = |a: Option<Duration>,
                    b: Option<Duration>,
                    f: fn(Duration, Duration) -> Duration| {
            match (a, b) {
                (Some(a), Some(b)) => Some(f(a, b)),
                (a, b) => a.or(b),
            }
        };
        self.first_handshake = pick(self.first_handshake, o.first_handshake, Duration::min);
        self.last_handshake = pick(self.last_handshake, o.last_handshake, Duration::max);
        self.media.merge(&o.media);
    }

    /// What the handshakes negotiated, most first:
    /// `TLSv1.3 TLS13_AES_128_GCM_SHA256 x40`.
    pub fn negotiated_text(&self) -> String {
        counts_text(&self.negotiated)
    }

    /// The labels and their counts, most first: `200 x40, 404 x2`.
    pub fn codes_text(&self) -> String {
        counts_text(&self.codes)
    }
}

fn counts_text(m: &BTreeMap<String, u64>) -> String {
    let mut v: Vec<(&String, &u64)> = m.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    v.iter()
        .map(|(k, n)| format!("{k} x{n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

impl fmt::Display for AppStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} transactions, {} failed, {} error answers",
            self.transactions, self.failed, self.errors
        )?;
        if self.protocol_errors > 0 {
            write!(f, ", {} protocol errors", self.protocol_errors)?;
        }
        if !self.codes.is_empty() {
            write!(f, " ({})", self.codes_text())?;
        }
        if self.handshakes > 0 {
            write!(
                f,
                "; {} handshakes, {} resumed, {} failed ({})",
                self.handshakes,
                self.resumed,
                self.handshake_failures,
                self.negotiated_text()
            )?;
            if let Some(r) = self.handshake_rate() {
                write!(f, ", {r:.1}/s")?;
            }
        }
        let m = &self.media;
        if m.streams > 0 {
            write!(
                f,
                "; {} media streams, {} packets sent, {} received, {} lost ({:.2}%)",
                m.streams,
                m.packets_sent,
                m.packets_received,
                m.lost,
                m.loss() * 100.0
            )?;
            if let (Some(mos), Some(worst)) = (m.mos_avg(), m.mos_min) {
                write!(f, ", MOS {mos:.2} (worst {worst:.2})")?;
            }
        }
        Ok(())
    }
}

/// Small, fast, seeded random numbers for sessions.
#[derive(Clone, Debug)]
pub struct AppRng(u64);

impl AppRng {
    pub fn new(seed: u64) -> Self {
        // Never zero, and seeds close together give unrelated streams.
        let mut s = seed ^ 0x9e37_79b9_7f4a_7c15;
        s = (s ^ (s >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        s = (s ^ (s >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Self((s ^ (s >> 31)) | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// `n` bytes of readable filler for generated bodies: a repeating line, so
/// a capture shows what it is.
pub fn filler(n: usize) -> Vec<u8> {
    const LINE: &[u8] = b"FeroTRX generated body 0123456789 abcdefghijklmnopqrstuvwxyz\n";
    LINE.iter().copied().cycle().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_errors_keep_a_few_samples() {
        let mut st = AppStats::default();
        for e in ["a", "b", "a", "c", "d", "e", "f"] {
            st.sample_error(e);
        }
        assert_eq!(st.protocol_error_samples, ["a", "b", "c", "d", "e"]);
        let mut other = AppStats::default();
        other.sample_error("z");
        other.merge(&st);
        assert_eq!(other.protocol_error_samples, ["z", "a", "b", "c", "d"]);
    }

    #[test]
    fn stats_count_and_merge() {
        let mut a = AppStats::default();
        a.record(&AppTransaction::new("200", true).with_response_time(Duration::from_millis(2)));
        a.record(&AppTransaction::new("404", false).with_error(true));
        let mut b = AppStats::default();
        b.record(&AppTransaction::new("200", true));
        b.protocol_errors = 1;
        a.merge(&b);
        assert_eq!(
            (a.transactions, a.failed, a.errors, a.protocol_errors),
            (3, 1, 1, 1)
        );
        assert_eq!(a.codes_text(), "200 x2, 404 x1");
        assert_eq!(a.response_time.count(), 1);
        assert!(a.to_string().starts_with("3 transactions, 1 failed"));
    }

    #[test]
    fn rng_and_filler() {
        let mut r = AppRng::new(0);
        assert_ne!(r.next_u64(), r.next_u64());
        assert_ne!(AppRng::new(1).next_u64(), AppRng::new(2).next_u64());
        let f = filler(100);
        assert_eq!(f.len(), 100);
        assert!(f.starts_with(b"FeroTRX"));
    }
}
