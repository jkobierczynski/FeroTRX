//! SIP over UDP (RFC 3261): user agents that register and call, a server
//! that registers and answers, and the RTP audio of each call.
//!
//! The client of each session registers (REGISTER, answering a digest
//! challenge with its password), calls (INVITE with an SDP offer, ACK),
//! sends and receives RTP and RTCP for the call's `duration`, then hangs up
//! (BYE). Requests go again on SIP's timers (T1, doubling) until answered,
//! and give up after 64 T1. It answers the server's BYE and OPTIONS.
//!
//! The server registers users (with digest authentication when it has
//! `users`), answers INVITEs with 100 Trying, 180 Ringing and, after
//! `ring`, its `answer` (200 with an SDP answer, or a refusal such as 486),
//! sends the 200 again until the ACK, plays RTP back for the call, answers
//! BYE, CANCEL and OPTIONS, and answers repeated requests with its last
//! answer. Several calls (Call-IDs) can share one client address and port,
//! as with SIPp. It hangs up itself after `max_call`.
//!
//! Each finished exchange is a transaction, labeled with its method and
//! status: `REGISTER 200`, `INVITE 486`, `BYE 200`, and `BYE received`
//! for the other end's hang-up. Each call's media is a
//! [`MediaReport`](super::MediaReport): packets each way, loss, duplicates,
//! reordering and jitter (RFC 3550), RTCP.
//!
//! Media follows the signaling: it goes to the other end's signaling
//! address, at the port its SDP gives, and then to wherever its RTP comes
//! from (symmetric RTP, so it works through NAT). A server behind which
//! the caller's SDP address differs from where its SIP came from (NAT)
//! waits for the caller's first packet before it sends.

pub mod digest;
pub mod msg;
pub mod rtp;

use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use self::digest::{Algorithm, Challenge, Credentials};
use self::msg::{param, uri_of, uri_user, Msg, Start};
use self::rtp::{Codec, Sdp, Stream};
use super::{
    AppCx, AppProtocol, AppRng, AppRole, AppSession, AppTransaction, Receive, SessionInit,
    Transport,
};
use crate::{Error, Result};

/// What a client's call (or registration, without a call) should end with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum SipExpect {
    /// Every request answered 2xx.
    #[default]
    Success,
    /// Refused: the INVITE (or the REGISTER without a call) answered 300 or more.
    Failure,
    /// Refused with this status.
    Code(u16),
}

impl SipExpect {
    fn refusal_ok(&self, code: u16) -> bool {
        match self {
            SipExpect::Success => false,
            SipExpect::Failure => code >= 300,
            SipExpect::Code(c) => *c == code,
        }
    }
}

/// The client's part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SipClient {
    pub user: String,
    /// For digest challenges; none: a challenge ends the session.
    pub password: Option<String>,
    /// REGISTER before calling.
    pub register: bool,
    /// The registration's lifetime, in seconds.
    pub expires: u32,
    /// Whom to call (a user at the domain, or a full `sip:` URI); none:
    /// only register.
    pub call: Option<String>,
    /// How long a call lasts once answered.
    pub duration: Duration,
    pub expect: SipExpect,
}

impl Default for SipClient {
    fn default() -> Self {
        Self {
            user: "ferotrx".into(),
            password: None,
            register: true,
            expires: 3600,
            call: Some("echo".into()),
            duration: Duration::from_secs(5),
            expect: SipExpect::Success,
        }
    }
}

/// The server's part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SipServer {
    /// Users and passwords; empty: no authentication.
    pub users: BTreeMap<String, String>,
    /// The digest algorithm the server asks for.
    pub algorithm: Algorithm,
    /// The final answer to INVITEs: 200, or a refusal (486, 603).
    pub answer: u16,
    /// How long it rings (180) before it answers.
    pub ring: Duration,
    /// The server hangs up calls that last longer.
    pub max_call: Duration,
}

impl Default for SipServer {
    fn default() -> Self {
        Self {
            users: BTreeMap::new(),
            algorithm: Algorithm::Md5,
            answer: 200,
            ring: Duration::ZERO,
            max_call: Duration::from_secs(3600),
        }
    }
}

/// SIP: both ends' settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sip {
    pub client: SipClient,
    pub server: SipServer,
    /// The domain in URIs; none: the server's address.
    pub domain: Option<String>,
    /// Offered (client) or accepted (server) audio codecs, best first.
    pub codecs: Vec<Codec>,
    pub ptime: Duration,
    /// RTP and RTCP during calls.
    pub media: bool,
    /// SIP's T1: the first retransmission interval (500 ms).
    pub t1: Duration,
}

impl Default for Sip {
    fn default() -> Self {
        Self {
            client: SipClient::default(),
            server: SipServer::default(),
            domain: None,
            codecs: vec![
                Codec::named("PCMU").expect("known"),
                Codec::named("PCMA").expect("known"),
            ],
            ptime: Duration::from_millis(20),
            media: true,
            t1: Duration::from_millis(500),
        }
    }
}

const T2: Duration = Duration::from_secs(4);
const AGENT: &str = concat!("FeroTRX/", env!("CARGO_PKG_VERSION"));
const ALLOW: &str = "INVITE, ACK, CANCEL, BYE, OPTIONS, REGISTER";

impl AppProtocol for Sip {
    fn name(&self) -> &str {
        "sip"
    }

    fn describe(&self) -> String {
        let c = &self.client;
        let mut parts = Vec::new();
        if c.register {
            parts.push(format!("{} registers", c.user));
        }
        if let Some(to) = &c.call {
            let codecs: Vec<&str> = self.codecs.iter().map(|c| c.name.as_str()).collect();
            parts.push(format!(
                "calls {to} for {:?}{}",
                c.duration,
                if self.media {
                    format!(" ({} {:?})", codecs.join("/"), self.ptime)
                } else {
                    " (no media)".into()
                }
            ));
        }
        let users = if self.server.users.is_empty() {
            String::new()
        } else {
            format!(", {} users", self.server.users.len())
        };
        format!(
            "SIP: {}; server answers {}{users}",
            parts.join(", "),
            self.server.answer
        )
    }

    fn default_port(&self) -> u16 {
        5060
    }

    fn supports(&self, t: Transport) -> bool {
        t == Transport::Datagram
    }

    fn dialog(&self) -> bool {
        true
    }

    fn media_ports(&self) -> u16 {
        if self.media {
            2
        } else {
            0
        }
    }

    fn validate(&self, role: AppRole, _: Transport) -> Result<()> {
        let bad = |m: &str| Err(Error::Profile(format!("SIP: {m}")));
        if self.codecs.is_empty() {
            return bad("give at least one codec");
        }
        if self.t1.is_zero() || self.ptime.is_zero() {
            return bad("t1 and ptime must be more than zero");
        }
        match role {
            AppRole::Client => {
                let c = &self.client;
                if !c.register && c.call.is_none() {
                    return bad("the client neither registers nor calls");
                }
                if c.user.is_empty() || c.user.contains([' ', '@', '<', '>', ';', ':']) {
                    return bad("user must be one word, without @ < > ; :");
                }
            }
            AppRole::Server => {
                let a = self.server.answer;
                if !(200..700).contains(&a) || (300..400).contains(&a) {
                    return bad("answer must be 200 or a refusal of 400 to 699");
                }
            }
        }
        Ok(())
    }

    fn session(&self, init: &SessionInit) -> Box<dyn AppSession> {
        let ua = Ua {
            sip: Arc::new(self.clone()),
            local: init.local,
            remote: init.remote,
            rng: AppRng::new(init.seed),
        };
        match init.role {
            AppRole::Client => Box::new(Client::new(ua)),
            AppRole::Server => Box::new(Server::new(ua)),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl fmt::Display for Sip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

/// What both ends share: the settings, the addresses, random ids.
struct Ua {
    sip: Arc<Sip>,
    local: SocketAddr,
    remote: SocketAddr,
    rng: AppRng,
}

fn host(a: &SocketAddr) -> String {
    match a {
        SocketAddr::V4(v) => v.ip().to_string(),
        SocketAddr::V6(v) => format!("[{}]", v.ip()),
    }
}

impl Ua {
    fn hex(&mut self, n: usize) -> String {
        let mut s = String::new();
        while s.len() < n {
            s.push_str(&format!("{:016x}", self.rng.next_u64()));
        }
        s.truncate(n);
        s
    }

    fn branch(&mut self) -> String {
        format!("z9hG4bK{}", self.hex(16))
    }

    /// The domain: the setting, or the server's address.
    fn domain(&self, server: &SocketAddr) -> String {
        self.sip.domain.clone().unwrap_or_else(|| host(server))
    }

    fn via(&self, branch: &str) -> String {
        format!("SIP/2.0/UDP {};branch={branch};rport", self.local)
    }

    fn contact(&self, user: &str) -> String {
        format!("<sip:{user}@{}>", self.local)
    }

    fn cname(&self, user: &str) -> String {
        format!("{user}@{}", host(&self.local))
    }

    /// A request of ours: Via, Max-Forwards, From, To, Call-ID, CSeq.
    #[allow(clippy::too_many_arguments)]
    fn request(
        &self,
        method: &str,
        uri: &str,
        branch: &str,
        from: &str,
        to: &str,
        call_id: &str,
        cseq: u32,
    ) -> Msg {
        let mut m = Msg::request(method, uri);
        m.header("Via", self.via(branch))
            .header("Max-Forwards", "70")
            .header("From", from)
            .header("To", to)
            .header("Call-ID", call_id)
            .header("CSeq", format!("{cseq} {method}"))
            .header("User-Agent", AGENT);
        m
    }

    /// A response to `req`, with our tag on To when given and it has none,
    /// and `received`/`rport` on the top Via (RFC 3581).
    fn response(&self, req: &Msg, code: u16, to_tag: Option<&str>) -> Msg {
        let mut r = Msg::response(code);
        for (i, via) in req.get_all("Via").into_iter().enumerate() {
            let via = if i == 0 {
                mark_via(&via, &self.remote)
            } else {
                via
            };
            r.header("Via", via);
        }
        r.copy(req, "From");
        if let Some(to) = req.get("To") {
            match to_tag {
                Some(t) if param(to, "tag").is_none() && code > 100 => {
                    r.header("To", format!("{to};tag={t}"))
                }
                _ => r.header("To", to),
            };
        }
        r.copy(req, "Call-ID").copy(req, "CSeq");
        r.header("Server", AGENT);
        r
    }

    /// An SDP offer or answer for our media port.
    fn sdp(&mut self, port: u16, codecs: &[Codec]) -> Vec<u8> {
        let session = self.rng.next_u64() >> 34;
        rtp::sdp(self.local.ip(), port, codecs, self.sip.ptime, session)
    }
}

/// Adds `received` and the `rport` value to a Via that asked for them.
fn mark_via(via: &str, from: &SocketAddr) -> String {
    let parts: Vec<&str> = via.split(';').collect();
    if !parts
        .iter()
        .skip(1)
        .any(|p| p.trim().eq_ignore_ascii_case("rport"))
    {
        return via.to_string();
    }
    let mut out = parts[0].to_string();
    for p in &parts[1..] {
        if p.trim().eq_ignore_ascii_case("rport") {
            out.push_str(&format!(";rport={};received={}", from.port(), from.ip()));
        } else if !p.trim().to_ascii_lowercase().starts_with("received=") {
            out.push(';');
            out.push_str(p);
        }
    }
    out
}

/// One of our requests, sent again on SIP's timers until answered.
struct Txn {
    method: String,
    cseq: u32,
    branch: String,
    bytes: Vec<u8>,
    first: Duration,
    interval: Duration,
    /// When to send again; None: not any more (an INVITE that got a 1xx).
    next: Option<Duration>,
    /// Timer B or F: when to give up.
    deadline: Duration,
    /// A digest challenge was answered already.
    authed: bool,
}

impl Txn {
    fn new(
        method: &str,
        cseq: u32,
        branch: String,
        bytes: Vec<u8>,
        now: Duration,
        t1: Duration,
    ) -> Self {
        Self {
            method: method.into(),
            cseq,
            branch,
            bytes,
            first: now,
            interval: t1,
            next: Some(now + t1),
            deadline: now + t1 * 64,
            authed: false,
        }
    }

    fn matches(&self, m: &Msg) -> bool {
        m.branch().as_deref() == Some(self.branch.as_str())
            && m.cseq()
                .is_some_and(|(n, meth)| n == self.cseq && meth == self.method)
    }

    /// A provisional answer: an INVITE stops going again (and waits up to
    /// three minutes for its answer); others go every T2.
    fn provisional(&mut self, now: Duration) {
        if self.method == "INVITE" {
            self.next = None;
            self.deadline = self.deadline.max(now + Duration::from_secs(180));
        } else {
            self.interval = T2;
        }
    }

    /// Sends again when due; true when it timed out.
    fn tick(&mut self, now: Duration, cx: &mut AppCx) -> bool {
        if now >= self.deadline {
            return true;
        }
        if let Some(n) = self.next {
            if now >= n {
                cx.send(self.bytes.clone());
                self.interval = if self.method == "INVITE" {
                    self.interval * 2
                } else {
                    (self.interval * 2).min(T2)
                };
                self.next = Some(now + self.interval);
            }
        }
        false
    }

    fn wake(&self) -> Duration {
        self.next.map_or(self.deadline, |n| n.min(self.deadline))
    }
}

/// The best digest challenge of a 401 or 407: SHA-256 before MD5.
fn challenge(m: &Msg) -> Option<(Challenge, &'static str)> {
    let (h, answer) = match m.code()? {
        401 => ("WWW-Authenticate", "Authorization"),
        407 => ("Proxy-Authenticate", "Proxy-Authorization"),
        _ => return None,
    };
    let mut all: Vec<Challenge> = m
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(h))
        .filter_map(|(_, v)| Challenge::parse(v))
        .collect();
    all.sort_by_key(|c| c.algorithm != Algorithm::Sha256);
    all.into_iter().next().map(|c| (c, answer))
}

fn min_wake(w: &mut Option<Duration>, t: Option<Duration>) {
    if let Some(t) = t {
        *w = Some(w.map_or(t, |x| x.min(t)));
    }
}

/// Sends a stream's media through the context.
fn media_out(cx: &mut AppCx) -> impl FnMut(u16, u16, Vec<u8>) + '_ {
    |from, to, d| cx.send_media(from, to, d)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Registering,
    Inviting,
    Talking,
    Hanging,
    Done,
}

struct Client {
    ua: Ua,
    phase: Phase,
    tag: String,
    reg_call_id: String,
    call_id: String,
    cseq: u32,
    txn: Option<Txn>,
    invite_started: Duration,
    to_tag: Option<String>,
    /// Where in-dialog requests go: the 200's Contact.
    target: String,
    routes: Vec<String>,
    /// Our ACK to the 200, for 200s that come again.
    ack: Option<Vec<u8>>,
    /// Our ACKs to refusals and challenges, by the INVITE's branch: the
    /// server sends its answer again until one arrives (Timer D).
    refusal_acks: Vec<(String, Vec<u8>)>,
    stream: Option<Stream>,
    hangup_at: Option<Duration>,
}

impl Client {
    fn new(mut ua: Ua) -> Self {
        let tag = ua.hex(10);
        let host = host(&ua.local);
        let reg_call_id = format!("{}@{host}", ua.hex(20));
        let call_id = format!("{}@{host}", ua.hex(20));
        Self {
            ua,
            phase: Phase::Registering,
            tag,
            reg_call_id,
            call_id,
            cseq: 0,
            txn: None,
            invite_started: Duration::ZERO,
            to_tag: None,
            target: String::new(),
            routes: Vec::new(),
            ack: None,
            refusal_acks: Vec::new(),
            stream: None,
            hangup_at: None,
        }
    }

    fn c(&self) -> &SipClient {
        &self.ua.sip.client
    }

    fn domain(&self) -> String {
        self.ua.domain(&self.ua.remote)
    }

    fn from(&self) -> String {
        format!("<sip:{}@{}>;tag={}", self.c().user, self.domain(), self.tag)
    }

    fn callee(&self) -> String {
        let to = self.c().call.clone().unwrap_or_default();
        if to.starts_with("sip:") || to.starts_with("sips:") {
            to
        } else {
            format!("sip:{to}@{}", self.domain())
        }
    }

    /// Whether `step` is the one `expect` is about.
    fn last_step(&self, method: &str) -> bool {
        match method {
            "INVITE" => true,
            "REGISTER" => self.c().call.is_none(),
            _ => false,
        }
    }

    fn register(&mut self, now: Duration, cx: &mut AppCx, auth: Option<(String, String)>) {
        self.cseq += 1;
        let branch = self.ua.branch();
        let d = self.domain();
        let user = self.c().user.clone();
        let mut m = self.ua.request(
            "REGISTER",
            &format!("sip:{d}"),
            &branch,
            &self.from(),
            &format!("<sip:{user}@{d}>"),
            &self.reg_call_id,
            self.cseq,
        );
        m.header("Contact", self.ua.contact(&user))
            .header("Expires", self.c().expires.to_string())
            .header("Allow", ALLOW);
        let authed = auth.is_some();
        if let Some((h, v)) = auth {
            m.header(&h, v);
        }
        self.send_txn("REGISTER", branch, m, now, cx, authed);
    }

    fn invite(&mut self, now: Duration, cx: &mut AppCx, auth: Option<(String, String)>) {
        self.phase = Phase::Inviting;
        self.cseq += 1;
        let branch = self.ua.branch();
        let uri = self.callee();
        let user = self.c().user.clone();
        let mut m = self.ua.request(
            "INVITE",
            &uri,
            &branch,
            &self.from(),
            &format!("<{uri}>"),
            &self.call_id,
            self.cseq,
        );
        m.header("Contact", self.ua.contact(&user))
            .header("Allow", ALLOW);
        let authed = auth.is_some();
        if let Some((h, v)) = auth {
            m.header(&h, v);
        } else {
            self.invite_started = now;
        }
        let sip = self.ua.sip.clone();
        match cx.media_port().filter(|_| sip.media) {
            Some(port) => {
                let body = self.ua.sdp(port, &sip.codecs);
                m.set_body("application/sdp", body);
            }
            None => {
                // No media: an offer with the port 0 would decline it; just
                // offer nothing.
            }
        }
        self.send_txn("INVITE", branch, m, now, cx, authed);
    }

    fn send_txn(
        &mut self,
        method: &str,
        branch: String,
        m: Msg,
        now: Duration,
        cx: &mut AppCx,
        authed: bool,
    ) {
        let bytes = m.to_bytes();
        cx.send(bytes.clone());
        let mut t = Txn::new(method, self.cseq, branch, bytes, now, self.ua.sip.t1);
        t.authed = authed;
        self.txn = Some(t);
    }

    /// An in-dialog request (ACK, BYE): to the 200's Contact, with the routes.
    fn in_dialog(&mut self, method: &str, cseq: u32) -> (Msg, String) {
        let branch = self.ua.branch();
        let to = match &self.to_tag {
            Some(t) => format!("<{}>;tag={t}", self.callee()),
            None => format!("<{}>", self.callee()),
        };
        let mut m = self.ua.request(
            method,
            &self.target.clone(),
            &branch,
            &self.from(),
            &to,
            &self.call_id.clone(),
            cseq,
        );
        for r in &self.routes {
            m.header("Route", r.clone());
        }
        (m, branch)
    }

    /// The ACK of a refusal: the INVITE's branch and Request-URI (RFC 3261
    /// section 17.1.1.3).
    fn ack_refusal(&mut self, resp: &Msg, txn: &Txn, cx: &mut AppCx) {
        let uri = self.callee();
        let to = resp.get("To").unwrap_or("").to_string();
        let mut m = self.ua.request(
            "ACK",
            &uri,
            &txn.branch,
            &self.from(),
            &to,
            &self.call_id,
            txn.cseq,
        );
        m.headers.retain(|(n, _)| n != "CSeq");
        m.header("CSeq", format!("{} ACK", txn.cseq));
        let bytes = m.to_bytes();
        cx.send(bytes.clone());
        self.refusal_acks.push((txn.branch.clone(), bytes));
    }

    fn record(&self, cx: &mut AppCx, label: String, ok: bool, error: bool, rt: Option<Duration>) {
        let mut t = AppTransaction::new(label, ok).with_error(error);
        t.response_time = rt;
        cx.transaction(t);
    }

    fn end(&mut self, cx: &mut AppCx) {
        if let Some(mut s) = self.stream.take() {
            let wall = cx.wall();
            let r = s.stop(wall, media_out(cx));
            cx.media(r);
        }
        self.phase = Phase::Done;
        self.txn = None;
        cx.close();
    }

    fn on_response(&mut self, m: Msg, now: Duration, cx: &mut AppCx) {
        let Some(code) = m.code() else { return };
        let txn = match self.txn.take() {
            Some(t) if t.matches(&m) => t,
            other => {
                self.txn = other;
                // A 200 to our INVITE again: its ACK was lost.
                if code / 100 == 2
                    && m.call_id() == Some(self.call_id.as_str())
                    && m.cseq().is_some_and(|(_, meth)| meth == "INVITE")
                {
                    if let Some(a) = &self.ack {
                        cx.send(a.clone());
                    }
                }
                // A refusal or challenge again: its ACK was lost.
                if code >= 300 {
                    if let Some(b) = m.branch() {
                        if let Some((_, a)) = self.refusal_acks.iter().find(|(x, _)| *x == b) {
                            cx.send(a.clone());
                        }
                    }
                }
                return;
            }
        };
        let method = txn.method.clone();
        if code < 200 {
            let mut txn = txn;
            txn.provisional(now);
            if let Some(t) = m.tag("To") {
                self.to_tag = Some(t);
            }
            self.txn = Some(txn);
            return;
        }
        if method == "INVITE" && code >= 300 {
            self.ack_refusal(&m, &txn, cx);
        }
        // A challenge we can answer.
        if (code == 401 || code == 407) && !txn.authed {
            if let (Some((ch, header)), Some(pw)) = (challenge(&m), self.c().password.clone()) {
                let user = self.c().user.clone();
                let uri = if method == "REGISTER" {
                    format!("sip:{}", self.domain())
                } else {
                    self.callee()
                };
                let cnonce = self.ua.hex(16);
                let auth = Some((
                    header.to_string(),
                    ch.answer(&user, &pw, &method, &uri, &cnonce),
                ));
                match method.as_str() {
                    "REGISTER" => self.register(now, cx, auth),
                    _ => self.invite(now, cx, auth),
                }
                return;
            }
        }
        let rt = Some(now.saturating_sub(match method.as_str() {
            "INVITE" => self.invite_started,
            _ => txn.first,
        }));
        let label = format!("{method} {code}");
        let expect = self.c().expect.clone();
        if code >= 300 {
            let ok = method != "BYE" && expect.refusal_ok(code);
            self.record(cx, label, ok, code >= 400, rt);
            self.end(cx);
            return;
        }
        match method.as_str() {
            "REGISTER" => {
                let ok = expect == SipExpect::Success || !self.last_step("REGISTER");
                self.record(cx, label, ok, false, rt);
                if self.c().call.is_some() && ok {
                    self.invite(now, cx, None);
                } else {
                    self.end(cx);
                }
            }
            "INVITE" => {
                let ok = expect == SipExpect::Success;
                self.record(cx, label, ok, false, rt);
                self.answered(&m, now, cx, ok);
            }
            _ => {
                self.record(cx, label, true, false, rt);
                self.end(cx);
            }
        }
    }

    /// The 200 to our INVITE: ACK it, start the media, hang up later.
    fn answered(&mut self, m: &Msg, now: Duration, cx: &mut AppCx, ok: bool) {
        self.to_tag = m.tag("To");
        self.target = m
            .get("Contact")
            .map(uri_of)
            .unwrap_or_else(|| self.callee());
        let mut routes = m.get_all("Record-Route");
        routes.reverse();
        self.routes = routes;
        let (ack, _) = self.in_dialog("ACK", self.cseq);
        let ack = ack.to_bytes();
        cx.send(ack.clone());
        self.ack = Some(ack);
        self.phase = Phase::Talking;
        let sip = self.ua.sip.clone();
        if let (Some(port), Some(sdp)) =
            (cx.media_port().filter(|_| sip.media), Sdp::parse(&m.body))
        {
            if let Some(codec) = sdp
                .pick(&sip.codecs, false)
                .or_else(|| sdp.pick(&sip.codecs, true))
            {
                let cname = self.ua.cname(&self.c().user);
                let mut s = Stream::new(codec, sip.ptime, port, &mut self.ua.rng, cname);
                s.set_remote(sdp.port);
                s.start(now);
                self.stream = Some(s);
            }
        }
        self.hangup_at = Some(if ok { now + self.c().duration } else { now });
    }

    fn hang_up(&mut self, now: Duration, cx: &mut AppCx) {
        self.hangup_at = None;
        self.phase = Phase::Hanging;
        if let Some(mut s) = self.stream.take() {
            let wall = cx.wall();
            let r = s.stop(wall, media_out(cx));
            cx.media(r);
        }
        self.cseq += 1;
        let (m, branch) = self.in_dialog("BYE", self.cseq);
        self.send_txn("BYE", branch, m, now, cx, false);
    }

    fn on_request(&mut self, m: Msg, cx: &mut AppCx) {
        let method = m.method().unwrap_or("").to_string();
        match method.as_str() {
            "ACK" => {}
            "BYE" if m.call_id() == Some(self.call_id.as_str()) => {
                cx.send(self.ua.response(&m, 200, None).to_bytes());
                if self.phase != Phase::Done {
                    self.record(cx, "BYE received".into(), true, false, None);
                    self.end(cx);
                }
            }
            "BYE" => cx.send(self.ua.response(&m, 481, None).to_bytes()),
            "OPTIONS" => {
                let mut r = self.ua.response(&m, 200, Some(&self.tag.clone()));
                r.header("Allow", ALLOW);
                cx.send(r.to_bytes());
            }
            "INVITE"
                if m.call_id() == Some(self.call_id.as_str()) && self.phase == Phase::Talking =>
            {
                // A re-INVITE (a session refresh): the same media again.
                let mut r = self.ua.response(&m, 200, None);
                r.header("Contact", self.ua.contact(&self.c().user.clone()));
                if let (Some(port), Some(s)) = (cx.media_port(), &self.stream) {
                    let codec = s.codec.clone();
                    let body = self.ua.sdp(port, &[codec]);
                    r.set_body("application/sdp", body);
                }
                cx.send(r.to_bytes());
            }
            _ => {
                let mut r = self.ua.response(&m, 501, Some(&self.tag.clone()));
                r.header("Allow", ALLOW);
                cx.send(r.to_bytes());
            }
        }
    }

    fn run_timers(&mut self, now: Duration, cx: &mut AppCx) {
        if let Some(t) = self.txn.as_mut() {
            if t.tick(now, cx) {
                let label = format!("{} timeout", t.method);
                self.record(cx, label, false, true, None);
                self.end(cx);
                return;
            }
        }
        if let Some(s) = self.stream.as_mut() {
            let wall = cx.wall();
            s.tick(now, wall, media_out(cx));
        }
        if self.hangup_at.is_some_and(|h| now >= h) {
            self.hang_up(now, cx);
        }
    }

    fn schedule(&self, cx: &mut AppCx) {
        if self.phase == Phase::Done {
            return;
        }
        let mut w = None;
        min_wake(&mut w, self.txn.as_ref().map(Txn::wake));
        min_wake(&mut w, self.stream.as_ref().and_then(Stream::wake));
        min_wake(&mut w, self.hangup_at);
        if let Some(w) = w {
            cx.wake_at(w);
        }
    }
}

impl AppSession for Client {
    fn start(&mut self, cx: &mut AppCx) {
        let now = cx.now();
        if self.c().register {
            self.register(now, cx, None);
        } else {
            self.invite(now, cx, None);
        }
        self.schedule(cx);
    }

    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        let Some(m) = Msg::parse(data) else {
            return if data.iter().all(u8::is_ascii_whitespace) {
                Receive::Taken // a keep-alive
            } else {
                Receive::NotMine
            };
        };
        let now = cx.now();
        match m.start {
            Start::Response { .. } => self.on_response(m, now, cx),
            Start::Request { .. } => self.on_request(m, cx),
        }
        self.schedule(cx);
        Receive::Taken
    }

    fn timer(&mut self, cx: &mut AppCx) {
        let now = cx.now();
        self.run_timers(now, cx);
        self.schedule(cx);
    }

    fn media(&mut self, port: u16, from: SocketAddr, data: &[u8], cx: &mut AppCx) {
        if let Some(s) = self.stream.as_mut() {
            s.receive(port, from.port(), data, cx.now());
        }
        self.schedule(cx);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallState {
    /// Rang; answers at the time.
    Ringing(Duration),
    /// Answered 200; waits for the ACK.
    Answered,
    Confirmed,
    /// We sent BYE.
    Hanging,
    /// Refused (or challenged); the refusal goes again until the ACK.
    Refused,
}

struct Call {
    state: CallState,
    invite: Msg,
    tag: String,
    /// The final answer (200 or a refusal), sent again until the ACK.
    ok: Option<Txn>,
    stream: Option<Stream>,
    hangup_at: Option<Duration>,
    bye: Option<Txn>,
    offer: Option<Sdp>,
}

struct Server {
    ua: Ua,
    calls: HashMap<String, Call>,
    /// Our last answer to each request (branch and method), for repeats.
    answers: Vec<(String, String, Vec<u8>, Duration)>,
    nonces: Vec<String>,
    cseq: u32,
}

impl Server {
    fn new(ua: Ua) -> Self {
        Self {
            ua,
            calls: HashMap::new(),
            answers: Vec::new(),
            nonces: Vec::new(),
            cseq: 0,
        }
    }

    fn s(&self) -> &SipServer {
        &self.ua.sip.server
    }

    fn send(&mut self, req: &Msg, resp: Msg, now: Duration, cx: &mut AppCx) {
        let bytes = resp.to_bytes();
        cx.send(bytes.clone());
        if let (Some(b), Some(m)) = (req.branch(), req.method()) {
            let m = m.to_string();
            match self.answers.iter_mut().find(|a| a.0 == b && a.1 == m) {
                Some(a) => {
                    a.2 = bytes;
                    a.3 = now;
                }
                None => self.answers.push((b, m, bytes, now)),
            }
        }
    }

    fn record(&self, cx: &mut AppCx, label: String, code: u16) {
        let challenge = code == 401 || code == 407;
        cx.transaction(AppTransaction::new(label, true).with_error(code >= 400 && !challenge));
    }

    /// Checks the request's digest credentials: Ok(user) or the answer to
    /// send (a challenge, or 403).
    fn authenticate(&mut self, m: &Msg, proxy: bool) -> std::result::Result<(), Msg> {
        if self.s().users.is_empty() {
            return Ok(());
        }
        let (code, header, ask) = if proxy {
            (407, "Proxy-Authorization", "Proxy-Authenticate")
        } else {
            (401, "Authorization", "WWW-Authenticate")
        };
        let method = m.method().unwrap_or("");
        if let Some(cred) = m.get(header).and_then(Credentials::parse) {
            let pw = self.s().users.get(&cred.username).cloned();
            let known = self.nonces.contains(&cred.nonce);
            return match pw {
                Some(pw) if known && cred.check(&pw, method) => Ok(()),
                _ => Err({
                    let t = self.ua.hex(10);
                    self.ua.response(m, 403, Some(&t))
                }),
            };
        }
        let nonce = self.ua.hex(24);
        self.nonces.push(nonce.clone());
        if self.nonces.len() > 32 {
            self.nonces.remove(0);
        }
        let domain = self.ua.domain(&self.ua.local);
        let ch = Challenge {
            realm: domain,
            nonce,
            opaque: None,
            algorithm: self.s().algorithm,
            qop_auth: true,
        };
        let mut r = {
            let t = self.ua.hex(10);
            self.ua.response(m, code, Some(&t))
        };
        r.header(ask, ch.header());
        Err(r)
    }

    fn on_request(&mut self, m: Msg, now: Duration, cx: &mut AppCx) -> Receive {
        let method = m.method().unwrap_or("").to_string();
        // A request again: our answer was lost.
        if method != "ACK" {
            if let Some(b) = m.branch() {
                if let Some(a) = self.answers.iter().find(|a| a.0 == b && a.1 == method) {
                    cx.send(a.2.clone());
                    return Receive::Taken;
                }
            }
        }
        let call_id = m.call_id().unwrap_or("").to_string();
        match method.as_str() {
            "REGISTER" => {
                let r = match self.authenticate(&m, false) {
                    Ok(()) => {
                        let mut r = {
                            let t = self.ua.hex(10);
                            self.ua.response(&m, 200, Some(&t))
                        };
                        let expires = m.get("Expires").unwrap_or("3600").to_string();
                        if let Some(c) = m.get("Contact") {
                            r.header("Contact", format!("{c};expires={expires}"));
                        }
                        r.header("Expires", expires);
                        r
                    }
                    Err(r) => r,
                };
                let code = r.code().unwrap_or(500);
                self.record(cx, format!("REGISTER {code}"), code);
                self.send(&m, r, now, cx);
            }
            "INVITE" => self.on_invite(m, call_id, now, cx),
            "ACK" => {
                if self
                    .calls
                    .get(&call_id)
                    .is_some_and(|c| c.state == CallState::Refused)
                {
                    self.calls.remove(&call_id);
                } else if let Some(c) = self.calls.get_mut(&call_id) {
                    if c.state == CallState::Answered {
                        c.state = CallState::Confirmed;
                        c.ok = None;
                        c.hangup_at = Some(now + self.ua.sip.server.max_call);
                        if let Some(s) = c.stream.as_mut() {
                            s.start(now);
                        }
                    }
                }
            }
            "BYE" => match self.calls.remove(&call_id) {
                Some(mut c) => {
                    if let Some(mut s) = c.stream.take() {
                        let wall = cx.wall();
                        let r = s.stop(wall, media_out(cx));
                        cx.media(r);
                    }
                    let r = self.ua.response(&m, 200, None);
                    self.record(cx, "BYE 200".into(), 200);
                    self.send(&m, r, now, cx);
                }
                None => {
                    let r = self.ua.response(&m, 481, None);
                    self.record(cx, "BYE 481".into(), 481);
                    self.send(&m, r, now, cx);
                }
            },
            "CANCEL" => {
                let pending = self.calls.get(&call_id).is_some_and(|c| {
                    matches!(c.state, CallState::Ringing(_)) && c.invite.branch() == m.branch()
                });
                if pending {
                    let c = self.calls.remove(&call_id).expect("checked");
                    let r = self.ua.response(&m, 200, Some(&c.tag));
                    self.send(&m, r, now, cx);
                    let r = self.ua.response(&c.invite, 487, Some(&c.tag));
                    self.record(cx, "CANCEL 200".into(), 200);
                    self.refuse(c.invite, r, call_id, now, cx);
                } else {
                    let r = self.ua.response(&m, 481, None);
                    self.record(cx, "CANCEL 481".into(), 481);
                    self.send(&m, r, now, cx);
                }
            }
            "OPTIONS" => {
                let mut r = {
                    let t = self.ua.hex(10);
                    self.ua.response(&m, 200, Some(&t))
                };
                r.header("Allow", ALLOW).header("Accept", "application/sdp");
                self.record(cx, "OPTIONS 200".into(), 200);
                self.send(&m, r, now, cx);
            }
            _ => {
                let mut r = {
                    let t = self.ua.hex(10);
                    self.ua.response(&m, 501, Some(&t))
                };
                r.header("Allow", ALLOW);
                self.record(cx, format!("{method} 501"), 501);
                self.send(&m, r, now, cx);
            }
        }
        Receive::Taken
    }

    fn on_invite(&mut self, m: Msg, call_id: String, now: Duration, cx: &mut AppCx) {
        // After a challenge: the INVITE again, with credentials.
        if self
            .calls
            .get(&call_id)
            .is_some_and(|c| c.state == CallState::Refused)
        {
            self.calls.remove(&call_id);
        }
        // A re-INVITE in a call: the same answer again.
        if let Some(c) = self.calls.get(&call_id) {
            if m.tag("To").as_deref() == Some(c.tag.as_str()) {
                let mut r = self.ua.response(&m, 200, None);
                r.header("Contact", self.contact(&c.invite));
                if let (Some(port), Some(s)) = (cx.media_port(), &c.stream) {
                    let codec = s.codec.clone();
                    let body = self.ua.sdp(port, &[codec]);
                    r.set_body("application/sdp", body);
                }
                self.send(&m, r, now, cx);
                return;
            }
            // A new INVITE for a call that is still on (another branch):
            // not ours to take twice.
            let r = {
                let t = self.ua.hex(10);
                self.ua.response(&m, 486, Some(&t))
            };
            self.send(&m, r, now, cx);
            return;
        }
        if let Err(r) = self.authenticate(&m, true) {
            let code = r.code().unwrap_or(500);
            self.record(cx, format!("INVITE {code}"), code);
            self.refuse(m, r, call_id, now, cx);
            return;
        }
        let tag = self.ua.hex(10);
        let r = self.ua.response(&m, 100, None);
        self.send(&m, r, now, cx);
        let offer = Sdp::parse(&m.body);
        let ring = self.s().ring;
        let mut call = Call {
            state: CallState::Ringing(now + ring),
            invite: m,
            tag,
            ok: None,
            stream: None,
            hangup_at: None,
            bye: None,
            offer,
        };
        if !ring.is_zero() || self.s().answer == 200 {
            let r = self.ua.response(&call.invite, 180, Some(&call.tag));
            let invite = call.invite.clone();
            self.send(&invite, r, now, cx);
        }
        if ring.is_zero() {
            self.answer(&mut call, now, cx);
        }
        self.calls.insert(call_id, call);
    }

    /// Sends a refusal of an INVITE, and again until its ACK (timer G).
    fn refuse(&mut self, invite: Msg, r: Msg, call_id: String, now: Duration, cx: &mut AppCx) {
        let bytes = r.to_bytes();
        let tag = r.tag("To").unwrap_or_default();
        self.send(&invite, r, now, cx);
        let t1 = self.ua.sip.t1;
        self.calls.insert(
            call_id,
            Call {
                state: CallState::Refused,
                invite,
                tag,
                ok: Some(Txn::new("response", 0, String::new(), bytes, now, t1)),
                stream: None,
                hangup_at: None,
                bye: None,
                offer: None,
            },
        );
    }

    fn contact(&self, invite: &Msg) -> String {
        let user = invite
            .get("To")
            .map(uri_of)
            .and_then(|u| uri_user(&u).map(str::to_string))
            .unwrap_or_else(|| "ferotrx".into());
        self.ua.contact(&user)
    }

    /// Answers a ringing call: 200 with an SDP answer, or the refusal;
    /// either goes again until the ACK.
    fn answer(&mut self, call: &mut Call, now: Duration, cx: &mut AppCx) {
        let sip = self.ua.sip.clone();
        let mut code = sip.server.answer;
        let mut stream = None;
        let mut body = None;
        if code == 200 {
            if let Some(offer) = &call.offer {
                match (
                    cx.media_port().filter(|_| sip.media),
                    offer.pick(&sip.codecs, false),
                ) {
                    (Some(port), Some(codec)) => {
                        body = Some(self.ua.sdp(port, std::slice::from_ref(&codec)));
                        let user = uri_user(&uri_of(call.invite.get("To").unwrap_or("")))
                            .unwrap_or("ferotrx")
                            .to_string();
                        let cname = self.ua.cname(&user);
                        let mut s = Stream::new(codec, sip.ptime, port, &mut self.ua.rng, cname);
                        s.set_remote(offer.port);
                        // Behind NAT the offer's address is not where the
                        // caller is: wait for its first packet.
                        s.send_early = offer.ip.is_none_or(|ip| ip == self.ua.remote.ip());
                        stream = Some(s);
                    }
                    (Some(_), None) => code = 488,
                    (None, _) => {
                        // No media of ours: answer without SDP.
                    }
                }
            }
        }
        let mut r = self.ua.response(&call.invite, code, Some(&call.tag));
        self.record(cx, format!("INVITE {code}"), code);
        if code != 200 {
            let invite = call.invite.clone();
            let bytes = r.to_bytes();
            self.send(&invite, r, now, cx);
            call.ok = Some(Txn::new("response", 0, String::new(), bytes, now, sip.t1));
            call.state = CallState::Refused;
            return;
        }
        r.header("Contact", self.contact(&call.invite))
            .header("Allow", ALLOW);
        if let Some(b) = body {
            r.set_body("application/sdp", b);
        }
        let invite = call.invite.clone();
        let bytes = r.to_bytes();
        self.send(&invite, r, now, cx);
        call.ok = Some(Txn::new("response", 0, String::new(), bytes, now, sip.t1));
        call.stream = stream;
        call.state = CallState::Answered;
    }

    /// We hang up a call that lasted `max_call`: BYE to the caller's Contact.
    fn hang_up(&mut self, call_id: &str, now: Duration, cx: &mut AppCx) {
        self.cseq += 1;
        let cseq = self.cseq;
        let branch = self.ua.branch();
        let Some(c) = self.calls.get_mut(call_id) else {
            return;
        };
        c.hangup_at = None;
        c.state = CallState::Hanging;
        if let Some(mut s) = c.stream.take() {
            let wall = cx.wall();
            let r = s.stop(wall, media_out(cx));
            cx.media(r);
        }
        let inv = &c.invite;
        let target = inv
            .get("Contact")
            .map(uri_of)
            .unwrap_or_else(|| inv.get("From").map(uri_of).unwrap_or_default());
        let to = inv.get("To").unwrap_or("");
        let from = if param(to, "tag").is_some() {
            to.to_string()
        } else {
            format!("{to};tag={}", c.tag)
        };
        let mut m = self.ua.request(
            "BYE",
            &target,
            &branch,
            &from,
            inv.get("From").unwrap_or(""),
            call_id,
            cseq,
        );
        for r in inv.get_all("Record-Route") {
            m.header("Route", r);
        }
        let bytes = m.to_bytes();
        cx.send(bytes.clone());
        c.bye = Some(Txn::new("BYE", cseq, branch, bytes, now, self.ua.sip.t1));
    }

    fn on_response(&mut self, m: Msg, now: Duration, cx: &mut AppCx) -> Receive {
        let Some(code) = m.code() else {
            return Receive::NotMine;
        };
        let call_id = m.call_id().unwrap_or("").to_string();
        let Some(c) = self.calls.get_mut(&call_id) else {
            return Receive::Taken; // late
        };
        match c.bye.as_mut() {
            Some(t) if t.matches(&m) => {
                if code < 200 {
                    t.provisional(now);
                } else {
                    self.calls.remove(&call_id);
                    self.record(cx, format!("BYE sent {code}"), code);
                }
            }
            _ => {}
        }
        Receive::Taken
    }

    fn run_timers(&mut self, now: Duration, cx: &mut AppCx) {
        let ids: Vec<String> = self.calls.keys().cloned().collect();
        for id in ids {
            let Some(c) = self.calls.get_mut(&id) else {
                continue;
            };
            if let CallState::Ringing(at) = c.state {
                if now >= at {
                    let mut call = self.calls.remove(&id).expect("there");
                    self.answer(&mut call, now, cx);
                    self.calls.insert(id.clone(), call);
                    continue;
                }
            }
            if let Some(t) = c.ok.as_mut() {
                if t.tick(now, cx) {
                    // The caller never ACKed: a lost ACK of a refusal does
                    // no harm, of a 200 it does.
                    if let Some(c) = self.calls.remove(&id) {
                        if c.state != CallState::Refused {
                            cx.transaction(
                                AppTransaction::new("INVITE no ACK", false).with_error(true),
                            );
                        }
                    }
                    continue;
                }
            }
            if let Some(t) = c.bye.as_mut() {
                if t.tick(now, cx) {
                    self.calls.remove(&id);
                    cx.transaction(AppTransaction::new("BYE timeout", false).with_error(true));
                    continue;
                }
            }
            if let Some(s) = c.stream.as_mut() {
                let wall = cx.wall();
                s.tick(now, wall, media_out(cx));
            }
            if c.hangup_at.is_some_and(|h| now >= h) {
                self.hang_up(&id, now, cx);
            }
        }
    }

    fn finish_event(&mut self, now: Duration, cx: &mut AppCx) {
        let keep = self.ua.sip.t1 * 64;
        self.answers.retain(|a| now.saturating_sub(a.3) < keep);
        if self.calls.is_empty() {
            cx.close();
            return;
        }
        let mut w = None;
        for c in self.calls.values() {
            if let CallState::Ringing(at) = c.state {
                min_wake(&mut w, Some(at));
            }
            min_wake(&mut w, c.ok.as_ref().map(Txn::wake));
            min_wake(&mut w, c.bye.as_ref().map(Txn::wake));
            min_wake(&mut w, c.stream.as_ref().and_then(Stream::wake));
            min_wake(&mut w, c.hangup_at);
        }
        if let Some(w) = w {
            cx.wake_at(w);
        }
    }
}

impl AppSession for Server {
    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        let now = cx.now();
        let Some(m) = Msg::parse(data) else {
            if data.iter().all(u8::is_ascii_whitespace) {
                // A keep-alive (CRLF): answered with one (RFC 5626).
                if !data.is_empty() {
                    cx.send(b"\r\n".to_vec());
                }
                self.finish_event(now, cx);
                return Receive::Taken;
            }
            return Receive::NotMine;
        };
        let r = match m.start {
            Start::Request { .. } => {
                // A finished session takes only what it answered before or
                // the calls it has; anything else opens a session of its own.
                self.on_request(m, now, cx)
            }
            Start::Response { .. } => self.on_response(m, now, cx),
        };
        self.finish_event(now, cx);
        r
    }

    fn timer(&mut self, cx: &mut AppCx) {
        let now = cx.now();
        self.run_timers(now, cx);
        self.finish_event(now, cx);
    }

    fn media(&mut self, port: u16, from: SocketAddr, data: &[u8], cx: &mut AppCx) {
        let now = cx.now();
        for c in self.calls.values_mut() {
            if let Some(s) = c.stream.as_mut() {
                if port == s.local || port == s.local + 1 {
                    s.receive(port, from.port(), data, now);
                }
            }
        }
        self.finish_event(now, cx);
    }
}

#[cfg(feature = "profile")]
mod raw {
    use serde::Deserialize;
    use std::collections::BTreeMap;

    #[derive(Deserialize)]
    #[serde(untagged)]
    pub enum Expect {
        Word(String),
        Code(u16),
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Sip {
        pub user: Option<String>,
        pub password: Option<String>,
        pub register: Option<bool>,
        pub expires: Option<u32>,
        pub call: Option<String>,
        pub duration: Option<String>,
        pub expect: Option<Expect>,
        pub domain: Option<String>,
        pub codecs: Option<Vec<String>>,
        pub ptime: Option<String>,
        pub media: Option<bool>,
        pub t1: Option<String>,
        #[serde(default)]
        pub users: BTreeMap<String, String>,
        pub algorithm: Option<String>,
        pub answer: Option<u16>,
        pub ring: Option<String>,
        pub max_call: Option<String>,
    }
}

/// Reads a `[sip]` table.
#[cfg(feature = "profile")]
pub fn parse(t: &toml::Table) -> Result<Sip> {
    let r: raw::Sip = super::registry::table_into(t)?;
    let dur = |v: Option<String>, d: Duration| v.map_or(Ok(d), |s| crate::parse_duration(&s));
    let mut sip = Sip::default();
    let c = &mut sip.client;
    if let Some(u) = r.user {
        c.user = u;
    }
    c.password = r.password;
    c.register = r.register.unwrap_or(true);
    if let Some(e) = r.expires {
        c.expires = e;
    }
    // `call = ""` only registers.
    c.call = match r.call {
        Some(s) if s.is_empty() => None,
        Some(s) => Some(s),
        None => c.call.take(),
    };
    c.duration = dur(r.duration, c.duration)?;
    c.expect = match r.expect {
        None => SipExpect::Success,
        Some(raw::Expect::Code(n)) if (300..700).contains(&n) => SipExpect::Code(n),
        Some(raw::Expect::Code(n)) => {
            return Err(Error::Profile(format!(
                "SIP: expect = {n}: give a refusal of 300 to 699, or \"success\""
            )))
        }
        Some(raw::Expect::Word(w)) => match w.to_ascii_lowercase().as_str() {
            "success" => SipExpect::Success,
            "failure" => SipExpect::Failure,
            _ => {
                return Err(Error::Profile(format!(
                    "SIP: expect `{w}`: use \"success\", \"failure\" or a status code"
                )))
            }
        },
    };
    sip.domain = r.domain;
    if let Some(cs) = r.codecs {
        sip.codecs = cs
            .iter()
            .map(|n| {
                Codec::named(n).ok_or_else(|| {
                    Error::Profile(format!(
                        "SIP: unknown codec `{n}`; use PCMU, PCMA, G722, G729 or opus"
                    ))
                })
            })
            .collect::<Result<_>>()?;
    }
    sip.ptime = dur(r.ptime, sip.ptime)?;
    sip.media = r.media.unwrap_or(true);
    sip.t1 = dur(r.t1, sip.t1)?;
    let s = &mut sip.server;
    s.users = r.users;
    if let Some(a) = r.algorithm {
        s.algorithm = Algorithm::from_name(&a)
            .ok_or_else(|| Error::Profile(format!("SIP: algorithm `{a}`: use MD5 or SHA-256")))?;
    }
    if let Some(a) = r.answer {
        s.answer = a;
    }
    s.ring = dur(r.ring, s.ring)?;
    s.max_call = dur(r.max_call, s.max_call)?;
    sip.validate(AppRole::Server, Transport::Datagram)?;
    Ok(sip)
}

#[cfg(test)]
mod tests;
