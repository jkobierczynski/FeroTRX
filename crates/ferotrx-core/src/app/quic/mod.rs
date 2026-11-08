//! QUIC and HTTP/3: clients that send the configured HTTP requests over
//! HTTP/3 and check their status codes, and a server that answers them
//! from the same routes as [`http`](super::http), over UDP (`app = "h3"`,
//! port 443, an `[h3]` table).
//!
//! [`conn`] is QUIC version 1 (RFC 9000, 9001, 9002) without help from
//! another QUIC library: rustls does the TLS 1.3 handshake and derives the
//! keys, and the connection does the rest (packets and their protection,
//! loss recovery, congestion control, streams and flow control, key
//! updates, Retry). [`h3`] is HTTP/3 on top, with [`qpack`] field
//! compression (static table only). The TLS settings come from the
//! profile's `[tls]` table, as for HTTPS; QUIC needs TLS 1.3, and ALPN is
//! `h3` unless the table says otherwise.
//!
//! ```
//! use ferotrx_core::app::http::HttpRequest;
//! use ferotrx_core::app::quic::Http3;
//!
//! let mut h3 = Http3::default();
//! h3.http.client.requests = vec![HttpRequest::get("/"), HttpRequest::get("/app.js")];
//! h3.http.client.per_connection = 10;
//! h3.concurrent = 4;
//! assert!(h3.validate_settings().is_ok());
//! ```

pub mod conn;
pub mod frame;
pub mod h3;
pub mod qpack;

#[cfg(test)]
mod tests;

use std::any::Any;
use std::sync::Arc;
use std::time::Duration;

use super::http::Http;
use super::tls::TlsSettings;
use super::{
    AppCx, AppHandshake, AppProtocol, AppRng, AppRole, AppSession, Receive, SessionInit, Transport,
};
use crate::{Error, Result};
use conn::{long_header, CloseInfo, Conn, Event, QuicSettings};
use h3::{H3Client, H3Server};

/// HTTP/3 over QUIC as an [`AppProtocol`].
#[derive(Clone)]
pub struct Http3 {
    pub http: Http,
    pub quic: QuicSettings,
    /// Client: requests in flight at once on a connection (streams), at
    /// most what the server allows.
    pub concurrent: u32,
    /// Huffman code header strings where it makes them shorter.
    pub huffman: bool,
    client_tls: TlsSettings,
    server_tls: TlsSettings,
    client_config: Arc<rustls::ClientConfig>,
    server_config: Arc<rustls::ServerConfig>,
}

impl std::fmt::Debug for Http3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http3")
            .field("http", &self.http)
            .field("quic", &self.quic)
            .field("concurrent", &self.concurrent)
            .finish()
    }
}

impl Default for Http3 {
    fn default() -> Self {
        Self::with_tls(
            Http::default(),
            TlsSettings::default(),
            TlsSettings::default(),
        )
        .expect("the default TLS settings work for QUIC")
    }
}

impl Http3 {
    /// HTTP/3 with TLS settings for each end (`alpn` empty for `h3`).
    pub fn with_tls(http: Http, mut client: TlsSettings, mut server: TlsSettings) -> Result<Self> {
        for (end, s) in [("client", &mut client), ("server", &mut server)] {
            if !s.versions.is_empty() && !s.versions.contains(&super::tls::TlsVersion::Tls13) {
                return Err(Error::Profile(format!(
                    "{end}: QUIC needs TLS 1.3, and `versions` leaves it out"
                )));
            }
            s.versions = vec![super::tls::TlsVersion::Tls13];
            if s.alpn.is_empty() {
                s.alpn = vec!["h3".into()];
            }
        }
        let (c, sv) = super::tls::configs(&client, &server)?;
        Ok(Self {
            http,
            quic: QuicSettings::default(),
            concurrent: 10,
            huffman: true,
            client_tls: client,
            server_tls: server,
            client_config: Arc::new(c),
            server_config: Arc::new(sv),
        })
    }

    pub fn client_tls(&self) -> &TlsSettings {
        &self.client_tls
    }

    pub fn server_tls(&self) -> &TlsSettings {
        &self.server_tls
    }

    /// Checks the settings' ranges.
    pub fn validate_settings(&self) -> Result<()> {
        let bad = |m: &str| Err(Error::Profile(format!("h3: {m}")));
        if self.concurrent == 0 {
            return bad("concurrent must be at least 1");
        }
        let q = &self.quic;
        if q.max_streams_bidi == 0 {
            return bad("max_streams must be at least 1");
        }
        if q.max_streams_uni < 3 {
            return bad("max_uni_streams must be at least 3 (HTTP/3 needs three)");
        }
        if q.stream_window < 1024 || q.max_data < 1024 {
            return bad("windows must be at least 1024 bytes");
        }
        if q.initial_window < 2 {
            return bad("initial_window must be at least 2 datagrams");
        }
        Ok(())
    }
}

impl AppProtocol for Http3 {
    fn name(&self) -> &str {
        "h3"
    }

    fn describe(&self) -> String {
        let c = &self.http.client;
        let mut d = format!(
            "HTTP/3 over QUIC: {} request(s), {} per connection, up to {} at once",
            c.requests.len(),
            c.per_connection,
            self.concurrent
        );
        if self.http.server.routes.is_empty() {
            d.push_str(", server answers 200 to all");
        } else {
            d.push_str(&format!(", {} route(s)", self.http.server.routes.len()));
        }
        if self.quic.retry {
            d.push_str(", Retry");
        }
        if self.quic.key_update_after > 0 {
            d.push_str(&format!(
                ", key updates every {} packets",
                self.quic.key_update_after
            ));
        }
        if self.client_tls.verify {
            d.push_str(", verified");
        }
        if self.client_tls.expect_failure || self.server_tls.expect_failure {
            d.push_str(", expected to fail");
        }
        d
    }

    fn default_port(&self) -> u16 {
        443
    }

    fn supports(&self, t: Transport) -> bool {
        t == Transport::Datagram
    }

    fn validate(&self, role: AppRole, t: Transport) -> Result<()> {
        self.validate_settings()?;
        self.http
            .validate(role, Transport::Stream)
            .map_err(|e| Error::Profile(e.to_string().replace("http:", "h3:")))?;
        if !self.supports(t) {
            return Err(Error::Profile("h3 runs over UDP".into()));
        }
        Ok(())
    }

    fn dialog(&self) -> bool {
        true
    }

    fn session(&self, init: &SessionInit) -> Box<dyn AppSession> {
        Box::new(QuicSession::new(self, init))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl QuicSession {
    fn new(h3: &Http3, init: &SessionInit) -> Self {
        let cfg = Arc::new(h3.clone());
        let role = match init.role {
            AppRole::Client => {
                let host = h3.http.client.host.clone().unwrap_or_else(|| {
                    match (init.remote, init.remote.port() == 443) {
                        (std::net::SocketAddr::V4(a), true) => a.ip().to_string(),
                        (std::net::SocketAddr::V6(a), true) => format!("[{}]", a.ip()),
                        (a, _) => a.to_string(),
                    }
                });
                Role::Client(H3Client::new(cfg.clone(), host, init.index))
            }
            AppRole::Server => Role::Server(H3Server::new(cfg.clone())),
        };
        QuicSession {
            cfg,
            init: init.clone(),
            conn: None,
            role,
            rng: AppRng::new(init.seed),
            began: None,
            reported: false,
            ended: false,
            lost: 0,
            failed_start: None,
        }
    }
}

enum Role {
    Client(H3Client),
    Server(H3Server),
}

/// One end of a QUIC connection with HTTP/3 on it.
struct QuicSession {
    cfg: Arc<Http3>,
    init: SessionInit,
    conn: Option<Conn>,
    role: Role,
    rng: AppRng,
    began: Option<Duration>,
    /// The handshake was counted.
    reported: bool,
    /// The end of the connection was counted.
    ended: bool,
    /// Lost packets counted so far.
    lost: u64,
    /// Client: why there is no connection.
    failed_start: Option<String>,
}

/// The token of our Retry: a mark and the client's first destination id.
const TOKEN_MARK: &[u8] = b"FeroTRX retry ";

impl QuicSession {
    fn expect_failure(&self) -> bool {
        match self.role {
            Role::Client(_) => self.cfg.client_tls.expect_failure,
            Role::Server(_) => self.cfg.server_tls.expect_failure,
        }
    }

    /// The server's first datagram: opens the connection, or answers with
    /// Version Negotiation or a Retry.
    fn accept(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        let Some(h) = long_header(data) else {
            return Receive::NotMine;
        };
        if h.version != conn::VERSION {
            if data.len() >= conn::MAX_DATAGRAM {
                cx.send(conn::version_negotiation(&h.dcid, &h.scid, &mut self.rng));
                cx.transaction(super::AppTransaction::new("version negotiation", true));
            }
            cx.close();
            return Receive::Taken;
        }
        if h.kind != 0 || data.len() < conn::MAX_DATAGRAM || h.dcid.len() < 8 {
            return Receive::NotMine;
        }
        let mut odcid = None;
        if self.cfg.quic.retry {
            match h.token.strip_prefix(TOKEN_MARK) {
                Some(o) if !o.is_empty() => odcid = Some(o.to_vec()),
                _ if h.token.is_empty() => {
                    let mut scid = vec![0; conn::CID_LEN];
                    self.rng.fill(&mut scid);
                    let mut token = TOKEN_MARK.to_vec();
                    token.extend_from_slice(&h.dcid);
                    cx.send(conn::retry_packet(&h.scid, &scid, &h.dcid, &token));
                    self.began.get_or_insert(cx.now());
                    // No connection yet: the client comes back with the token.
                    cx.wake_at(cx.now() + Duration::from_secs(10));
                    return Receive::Taken;
                }
                _ => return Receive::NotMine, // a token not from us
            }
        }
        match Conn::server(
            self.cfg.server_config.clone(),
            &h,
            self.cfg.quic.clone(),
            self.init.seed,
            cx.now(),
            odcid,
        ) {
            Ok(c) => {
                self.conn = Some(c);
                Receive::Taken
            }
            Err(e) => {
                cx.protocol_error(format!("QUIC: {e}"));
                cx.close();
                Receive::Taken
            }
        }
    }

    /// Hands the connection's events to HTTP/3 and the counters, then sends
    /// what is due and sets the timer.
    fn drive(&mut self, cx: &mut AppCx) {
        let Some(mut conn) = self.conn.take() else {
            return;
        };
        let now = cx.now();
        self.events(&mut conn, cx);
        // The end of the work.
        if !conn.is_closed() {
            match &mut self.role {
                Role::Client(c) => {
                    c.fill(&mut conn, cx);
                    if c.finished() && !c.done {
                        c.done = true;
                        conn.close(true, h3::code::NO_ERROR, "", now);
                    }
                }
                Role::Server(s) => {
                    s.flush(&mut conn, cx);
                    if s.closing && !s.busy() && !conn.sending() {
                        conn.close(true, h3::code::NO_ERROR, "", now);
                    }
                }
            }
            // Events of our own close.
            self.events(&mut conn, cx);
        }
        while let Some(d) = conn.poll_transmit(now) {
            cx.send(d);
        }
        let lost = conn.stats.packets_lost;
        if lost > self.lost {
            cx.resent(lost - self.lost);
            self.lost = lost;
        }
        if conn.is_closed() {
            cx.close();
        }
        // The connection's timer, unless HTTP/3 asked for an earlier wake
        // (a route's delay, the client's think time): wake_at keeps only
        // the last time it was given.
        if let Some(t) = conn.timeout() {
            let t = t.max(now);
            cx.wake_at(cx.wake().map_or(t, |w| w.min(t)));
        }
        self.conn = Some(conn);
    }

    fn events(&mut self, conn: &mut Conn, cx: &mut AppCx) {
        let now = cx.now();
        let expect_failure = self.expect_failure();
        while let Some(e) = conn.poll_event() {
            if e == Event::Connected && !self.reported {
                self.reported = true;
                let suite = conn
                    .tls()
                    .negotiated_cipher_suite()
                    .map(|s| format!(" {:?}", s.suite()))
                    .unwrap_or_default();
                let alpn = conn
                    .tls()
                    .alpn_protocol()
                    .map(|p| format!(" {}", String::from_utf8_lossy(p)))
                    .unwrap_or_default();
                let resumed = conn.tls().handshake_kind() == Some(rustls::HandshakeKind::Resumed);
                cx.handshake(AppHandshake {
                    label: format!("QUIC v1{suite}{alpn}"),
                    succeeded: true,
                    expected: !expect_failure,
                    resumed,
                    time: self.began.map(|b| now.saturating_sub(b)),
                });
            }
            if let Event::Closed(info) = &e {
                self.on_closed(info, expect_failure, cx);
                continue;
            }
            let r = match &mut self.role {
                Role::Client(c) => c.event(conn, &e, cx),
                Role::Server(s) => s.event(conn, &e, cx),
            };
            if let Err((code, why)) = r {
                cx.protocol_error(format!("HTTP/3: {}: {why}", h3::error_name(code)));
                conn.close(true, code, &why, now);
            }
        }
    }

    fn on_closed(&mut self, info: &CloseInfo, expect_failure: bool, cx: &mut AppCx) {
        if self.ended {
            return;
        }
        self.ended = true;
        let what = info.describe(h3::error_name);
        // Some ends close with application error 0 (aioquic).
        let clean = info.clean(|c| c == h3::code::NO_ERROR || c == 0);
        if !self.reported {
            self.reported = true;
            cx.handshake(AppHandshake {
                label: format!("failed: QUIC {what}"),
                succeeded: false,
                expected: expect_failure,
                resumed: false,
                time: self.began.map(|b| cx.now().saturating_sub(b)),
            });
            return;
        }
        match &self.role {
            Role::Client(c) => {
                let left = c.unanswered();
                if left > 0 {
                    for _ in 0..c.in_flight() {
                        cx.transaction(
                            super::AppTransaction::new("unanswered", false).with_error(true),
                        );
                    }
                    cx.protocol_error(format!(
                        "the connection ended ({what}) with {left} request(s) unanswered"
                    ));
                }
            }
            Role::Server(s) => {
                // An idle timeout once nothing is asked is the client gone
                // quietly (its CONNECTION_CLOSE lost).
                if !clean && !(info.idle && !s.busy()) {
                    cx.protocol_error(format!("the connection ended: {what}"));
                }
            }
        }
    }
}

impl AppSession for QuicSession {
    fn start(&mut self, cx: &mut AppCx) {
        self.began = Some(cx.now());
        let names = &self.cfg.client_tls.server_names;
        let name = match names.get((self.init.index % names.len().max(1) as u64) as usize) {
            Some(n) => rustls::pki_types::ServerName::try_from(n.clone()).ok(),
            None => Some(rustls::pki_types::ServerName::IpAddress(
                self.init.remote.ip().into(),
            )),
        };
        let r = match name {
            Some(n) => Conn::client(
                self.cfg.client_config.clone(),
                n,
                self.cfg.quic.clone(),
                self.init.seed,
                cx.now(),
            ),
            None => Err("no valid server name".into()),
        };
        match r {
            Ok(c) => {
                self.conn = Some(c);
                self.drive(cx);
            }
            Err(e) => {
                self.failed_start = Some(e.clone());
                cx.handshake(AppHandshake {
                    label: format!("failed: {e}"),
                    succeeded: false,
                    expected: self.cfg.client_tls.expect_failure,
                    resumed: false,
                    time: None,
                });
                cx.close();
            }
        }
    }

    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        if self.conn.is_none() {
            if matches!(self.role, Role::Client(_)) {
                cx.close();
                return Receive::Taken;
            }
            if self.began.is_none() {
                self.began = Some(cx.now());
            }
            let r = self.accept(data, cx);
            if self.conn.is_none() {
                return r;
            }
        } else if let Some(c) = &self.conn {
            // A new connection from the same address and port, after this
            // one ended: a session of its own.
            if c.is_closed() && matches!(self.role, Role::Server(_)) {
                if let Some(h) = long_header(data) {
                    if h.kind == 0 && h.dcid != c.scid() && h.dcid != c.odcid() {
                        return Receive::NotMine;
                    }
                }
            }
        }
        let now = cx.now();
        if let Some(c) = self.conn.as_mut() {
            c.recv(data, now);
        }
        self.drive(cx);
        Receive::Taken
    }

    fn timer(&mut self, cx: &mut AppCx) {
        let now = cx.now();
        match self.conn.as_mut() {
            Some(c) => {
                if c.timeout().is_some_and(|t| now >= t) {
                    c.on_timeout(now);
                }
                self.drive(cx);
            }
            None => {
                // A Retry the client never followed.
                cx.close();
            }
        }
    }
}

/// Reads an `[h3]` table: the keys of `[http]` (requests, routes,
/// `per_connection`, `host`, ...), QUIC's and HTTP/3's own, and the TLS
/// settings in `tls` (the profile's `[tls]` table).
#[cfg(feature = "profile")]
pub fn parse(t: &toml::Table, base: &std::path::Path) -> Result<Http3> {
    const OWN: &[&str] = &[
        "concurrent",
        "huffman",
        "idle_timeout",
        "max_data",
        "stream_window",
        "max_streams",
        "max_uni_streams",
        "initial_window",
        "key_update_after",
        "retry",
        "tls",
    ];
    let mut rest = t.clone();
    if rest.contains_key("pipeline") {
        return Err(Error::Profile(
            "`pipeline` is HTTP/1.1's; HTTP/3 sends requests at once up to `concurrent`".into(),
        ));
    }
    let mut own = toml::Table::new();
    for k in OWN {
        if let Some(v) = rest.remove(*k) {
            own.insert((*k).to_string(), v);
        }
    }
    let http = super::http::parse(&rest, base)
        .map_err(|e| Error::Profile(e.to_string().trim_start_matches("profile: ").to_string()))?;
    super::http::status_checks_only(&http, "HTTP/3")?;
    let (client, server) = match own.get("tls") {
        Some(toml::Value::Table(x)) => super::tls::parse_ends(x, base).map_err(|e| {
            Error::Profile(format!(
                "[tls]: {}",
                e.to_string().trim_start_matches("profile: ")
            ))
        })?,
        _ => (TlsSettings::default(), TlsSettings::default()),
    };
    let mut h3 = Http3::with_tls(http, client, server)?;
    let num = |k: &str| -> Result<Option<u64>> {
        match own.get(k) {
            None => Ok(None),
            Some(toml::Value::Integer(n)) if *n >= 0 => Ok(Some(*n as u64)),
            Some(toml::Value::String(s)) if k.contains("data") || k.contains("window") => {
                crate::tcp::parse_size(s)
                    .map(Some)
                    .map_err(|e| Error::Profile(format!("`{k}`: {e}")))
            }
            Some(_) => Err(Error::Profile(format!("`{k}` must be a number"))),
        }
    };
    let flag = |k: &str| -> Result<Option<bool>> {
        match own.get(k) {
            None => Ok(None),
            Some(toml::Value::Boolean(b)) => Ok(Some(*b)),
            Some(_) => Err(Error::Profile(format!("`{k}` must be true or false"))),
        }
    };
    if let Some(n) = num("concurrent")? {
        h3.concurrent = n.min(u64::from(u32::MAX)) as u32;
    }
    if let Some(b) = flag("huffman")? {
        h3.huffman = b;
    }
    match own.get("idle_timeout") {
        None => {}
        Some(toml::Value::String(s)) => {
            h3.quic.idle_timeout = crate::parse_duration(s)
                .map_err(|e| Error::Profile(format!("`idle_timeout`: {e}")))?
        }
        Some(_) => {
            return Err(Error::Profile(
                "`idle_timeout` must be a time, e.g. \"30s\"".into(),
            ))
        }
    }
    if let Some(n) = num("max_data")? {
        h3.quic.max_data = n;
    }
    if let Some(n) = num("stream_window")? {
        h3.quic.stream_window = n;
    }
    if let Some(n) = num("max_streams")? {
        h3.quic.max_streams_bidi = n;
    }
    if let Some(n) = num("max_uni_streams")? {
        h3.quic.max_streams_uni = n;
    }
    if let Some(n) = num("initial_window")? {
        h3.quic.initial_window = n;
    }
    if let Some(n) = num("key_update_after")? {
        h3.quic.key_update_after = n;
    }
    if let Some(b) = flag("retry")? {
        h3.quic.retry = b;
    }
    h3.validate_settings()?;
    Ok(h3)
}

/// For the fuzz targets: connects a client and a server in memory, then
/// hands `payloads` to one end (`server_side`) as the plaintext of 1-RTT
/// packets, as if they had been decrypted, so the frames reach the
/// connection and HTTP/3 behind the packet protection.
#[cfg(any(test, feature = "fuzzing"))]
#[allow(dead_code)]
pub(crate) fn fuzz_established(h3: &Http3, server_side: bool, payloads: &[&[u8]]) {
    let init = |role, seed, local: &str, remote: &str| SessionInit {
        role,
        transport: Transport::Datagram,
        index: 0,
        seed,
        local: local.parse().unwrap(),
        remote: remote.parse().unwrap(),
    };
    let mut c = QuicSession::new(
        h3,
        &init(AppRole::Client, 7, "10.0.0.1:40000", "10.0.0.2:443"),
    );
    let mut s = QuicSession::new(
        h3,
        &init(AppRole::Server, 9, "10.0.0.2:443", "10.0.0.1:40000"),
    );
    let mut now = Duration::from_millis(1);
    let mut cx = AppCx::new(now, now);
    c.start(&mut cx);
    let mut to_server = cx.take_sends();
    let mut to_client = Vec::new();
    for _ in 0..64 {
        now += Duration::from_millis(1);
        for d in std::mem::take(&mut to_server) {
            let mut cx = AppCx::new(now, now);
            s.receive(&d, &mut cx);
            to_client.extend(cx.take_sends());
        }
        for d in std::mem::take(&mut to_client) {
            let mut cx = AppCx::new(now, now);
            c.receive(&d, &mut cx);
            to_server.extend(cx.take_sends());
        }
        let up = |q: &QuicSession| q.conn.as_ref().is_some_and(|c| c.is_established());
        // The client's requests end the connection soon after: stop at
        // the first moment the end under test is up.
        if up(if server_side { &s } else { &c }) {
            break;
        }
    }
    let end = if server_side { &mut s } else { &mut c };
    debug_assert!(end.conn.as_ref().is_some_and(|c| c.is_established()));
    for (pn, p) in (1 << 20..).zip(payloads) {
        now += Duration::from_millis(1);
        let mut cx = AppCx::new(now, now);
        let Some(conn) = end.conn.as_mut() else {
            return;
        };
        conn.fuzz_packet(pn, p, now);
        end.drive(&mut cx);
        if cx.wants_close() {
            return;
        }
    }
}

/// Seeds for the fuzz target: 1-RTT payloads of a request and of the
/// frames a connection sees.
#[cfg(any(test, feature = "fuzzing"))]
#[allow(dead_code)]
pub(crate) fn fuzz_seed_payloads() -> Vec<Vec<Vec<u8>>> {
    use frame::Frame;
    let enc = |fs: &[Frame]| {
        let mut out = Vec::new();
        for f in fs {
            f.encode(&mut out);
        }
        out
    };
    let mut req = Vec::new();
    let fields = qpack::encode(
        [
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "lab"),
            (":path", "/"),
        ],
        false,
    );
    h3::frame(&mut req, h3::HEADERS, &fields);
    h3::frame(&mut req, h3::DATA, b"hello");
    let mut settings = vec![0]; // a control stream
    h3::frame(&mut settings, h3::SETTINGS, &[]);
    vec![
        vec![enc(&[Frame::Stream {
            id: 0,
            offset: 0,
            data: req.clone(),
            fin: true,
        }])],
        vec![
            enc(&[Frame::Stream {
                id: 2,
                offset: 0,
                data: settings,
                fin: false,
            }]),
            enc(&[Frame::Ping, Frame::MaxData(1 << 30)]),
            enc(&[Frame::MaxStreams {
                bidi: true,
                max: 1000,
            }]),
            enc(&[Frame::NewConnectionId {
                seq: 1,
                retire_prior_to: 0,
                cid: vec![7; 8],
                token: [1; 16],
            }]),
            enc(&[Frame::ResetStream {
                id: 0,
                code: 1,
                final_size: 5,
            }]),
            enc(&[Frame::ConnectionClose {
                app: true,
                code: 0x100,
                frame_type: 0,
                reason: b"bye".to_vec(),
            }]),
        ],
    ]
}
