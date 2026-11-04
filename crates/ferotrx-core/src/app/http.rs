//! HTTP/1.1: a client that sends configured requests and checks the
//! status codes, and a server that answers from configured routes.
//!
//! Both ends parse what they get as HTTP: header sections, `Content-Length`
//! and chunked bodies, `HEAD`, `1xx`/`204`/`304` without a body, responses
//! that end with the connection, keep-alive with several requests per
//! connection, pipelining. So either end also works against real software:
//! the emulated server answers `curl`, the emulated client loads pages from
//! a real web server.
//!
//! ```
//! use ferotrx_core::app::http::{Http, HttpRequest, HttpRoute};
//!
//! let mut http = Http::default();
//! http.client.requests = vec![HttpRequest::get("/"), HttpRequest::get("/missing").expect("404")];
//! http.client.per_connection = 2;
//! http.server.routes = vec![HttpRoute::new("/", 200).with_body("hello\n")];
//! assert_eq!(http.server.route("GET", "/missing").status, 404);
//! assert_eq!(http.server.route("GET", "/").status, 200);
//! ```

use std::any::Any;
use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use super::{
    AppCx, AppProtocol, AppRole, AppSession, AppTransaction, Receive, SessionInit, Transport,
};
use crate::{Error, Result};

/// Which status codes a client takes as the expected answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum StatusMatch {
    /// Anything below 400 (the default).
    #[default]
    Success,
    /// Any status.
    Any,
    /// This code.
    Code(u16),
    /// This class: 2 for 2xx.
    Class(u8),
}

impl StatusMatch {
    pub fn matches(self, status: u16) -> bool {
        match self {
            StatusMatch::Success => status < 400,
            StatusMatch::Any => true,
            StatusMatch::Code(c) => status == c,
            StatusMatch::Class(c) => status / 100 == u16::from(c),
        }
    }
}

impl std::str::FromStr for StatusMatch {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let bad = || {
            Error::Profile(format!(
                "`{s}` is not a status: give 200, 2xx, success or any"
            ))
        };
        let s = s.trim();
        match s.to_ascii_lowercase().as_str() {
            "success" | "ok" => return Ok(StatusMatch::Success),
            "any" | "*" => return Ok(StatusMatch::Any),
            _ => {}
        }
        let b = s.as_bytes();
        if b.len() == 3 && b[0].is_ascii_digit() && b[1..].eq_ignore_ascii_case(b"xx") {
            return match b[0] - b'0' {
                c @ 1..=5 => Ok(StatusMatch::Class(c)),
                _ => Err(bad()),
            };
        }
        match s.parse::<u16>() {
            Ok(c) if (100..=999).contains(&c) => Ok(StatusMatch::Code(c)),
            _ => Err(bad()),
        }
    }
}

impl fmt::Display for StatusMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StatusMatch::Success => f.write_str("success"),
            StatusMatch::Any => f.write_str("any"),
            StatusMatch::Code(c) => write!(f, "{c}"),
            StatusMatch::Class(c) => write!(f, "{c}xx"),
        }
    }
}

/// A request the client sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    /// The request target, e.g. `/index.html?q=1`.
    pub path: String,
    /// Extra header lines, after `Host`, `User-Agent` and `Accept`.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub expect: StatusMatch,
}

impl HttpRequest {
    pub fn new(method: &str, path: &str) -> Self {
        Self {
            method: method.to_ascii_uppercase(),
            path: path.to_string(),
            headers: Vec::new(),
            body: Vec::new(),
            expect: StatusMatch::Success,
        }
    }

    pub fn get(path: &str) -> Self {
        Self::new("GET", path)
    }

    /// Sets the expected status (`200`, `4xx`, `any`); panics if it is not one.
    pub fn expect(mut self, status: &str) -> Self {
        self.expect = status.parse().expect("a status");
        self
    }

    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// The request as it goes on the wire.
    fn bytes(&self, host: &str, user_agent: &str) -> Vec<u8> {
        let mut m = format!("{} {} HTTP/1.1\r\nHost: {host}\r\n", self.method, self.path);
        if !user_agent.is_empty() && !has(&self.headers, "user-agent") {
            m.push_str(&format!("User-Agent: {user_agent}\r\n"));
        }
        if !has(&self.headers, "accept") {
            m.push_str("Accept: */*\r\n");
        }
        for (k, v) in &self.headers {
            m.push_str(&format!("{k}: {v}\r\n"));
        }
        let needs_length =
            !self.body.is_empty() || matches!(self.method.as_str(), "POST" | "PUT" | "PATCH");
        if needs_length
            && !has(&self.headers, "content-length")
            && !has(&self.headers, "transfer-encoding")
        {
            m.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }
        m.push_str("\r\n");
        let mut b = m.into_bytes();
        b.extend_from_slice(&self.body);
        b
    }
}

impl std::str::FromStr for HttpRequest {
    type Err = Error;
    /// `METHOD PATH [EXPECT]`, e.g. `GET /`, `GET /missing 404`, or only a
    /// path for a GET.
    fn from_str(s: &str) -> Result<Self> {
        let w: Vec<&str> = s.split_whitespace().collect();
        let bad = || {
            Error::Profile(format!(
                "`{s}`: give METHOD PATH [EXPECTED STATUS], e.g. `GET / 200`"
            ))
        };
        let (method, path, expect) = match w.as_slice() {
            [p] if p.starts_with('/') => ("GET", *p, None),
            [m, p] => (*m, *p, None),
            [m, p, e] => (*m, *p, Some(*e)),
            _ => return Err(bad()),
        };
        if !method.bytes().all(|b| b.is_ascii_alphabetic()) || path.is_empty() {
            return Err(bad());
        }
        let mut r = HttpRequest::new(method, path);
        if let Some(e) = expect {
            r.expect = e.parse()?;
        }
        Ok(r)
    }
}

/// A server route: requests for `path` (and `method`) get this response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRoute {
    /// Only this method; `None`: any.
    pub method: Option<String>,
    /// The path (without the query), or a prefix ending in `*`; `*` alone
    /// takes every path.
    pub path: String,
    pub status: u16,
    /// The reason phrase; `None`: the usual one for the status.
    pub reason: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Arc<[u8]>,
    /// Send the body chunked instead of with `Content-Length`.
    pub chunked: bool,
    /// Close the connection after this response.
    pub close: bool,
    /// Wait this long before answering.
    pub delay: Duration,
}

impl HttpRoute {
    pub fn new(path: &str, status: u16) -> Self {
        Self {
            method: None,
            path: path.to_string(),
            status,
            reason: None,
            headers: Vec::new(),
            body: Arc::from(&b""[..]),
            chunked: false,
            close: false,
            delay: Duration::ZERO,
        }
    }

    pub fn with_body(mut self, body: impl AsRef<[u8]>) -> Self {
        self.body = Arc::from(body.as_ref());
        self
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn matches(&self, method: &str, path: &str) -> bool {
        if self
            .method
            .as_deref()
            .is_some_and(|m| !m.eq_ignore_ascii_case(method))
        {
            return false;
        }
        match self.path.strip_suffix('*') {
            Some(prefix) => path.starts_with(prefix),
            None => self.path == path,
        }
    }

    /// The response to a request for it, with `head` true for a HEAD request.
    fn bytes(&self, server: &str, head: bool, close: bool) -> Vec<u8> {
        let reason = self
            .reason
            .as_deref()
            .unwrap_or_else(|| reason(self.status));
        let mut m = format!("HTTP/1.1 {} {reason}\r\n", self.status);
        if !server.is_empty() && !has(&self.headers, "server") {
            m.push_str(&format!("Server: {server}\r\n"));
        }
        for (k, v) in &self.headers {
            m.push_str(&format!("{k}: {v}\r\n"));
        }
        let bodiless = self.status < 200 || self.status == 204 || self.status == 304;
        if !bodiless {
            if self.chunked {
                m.push_str("Transfer-Encoding: chunked\r\n");
            } else {
                m.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
            }
        }
        if close {
            m.push_str("Connection: close\r\n");
        }
        m.push_str("\r\n");
        let mut b = m.into_bytes();
        if head || bodiless {
            return b;
        }
        if self.chunked {
            for c in self.body.chunks(CHUNK) {
                b.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
                b.extend_from_slice(c);
                b.extend_from_slice(b"\r\n");
            }
            b.extend_from_slice(b"0\r\n\r\n");
        } else {
            b.extend_from_slice(&self.body);
        }
        b
    }
}

/// Size of the chunks of a chunked body.
const CHUNK: usize = 8192;

fn has(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
}

/// The usual reason phrase of a status.
pub fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

/// What the client sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpClient {
    /// The requests, in turn across connections.
    pub requests: Vec<HttpRequest>,
    /// Requests per connection (keep-alive); then the client closes.
    pub per_connection: u32,
    /// Send a connection's requests at once instead of each after the
    /// previous answer.
    pub pipeline: bool,
    /// The `Host` header; `None`: the address connected to.
    pub host: Option<String>,
    /// The `User-Agent` header; empty: none.
    pub user_agent: String,
    /// Pause between an answer and the next request.
    pub think_time: Duration,
}

impl Default for HttpClient {
    fn default() -> Self {
        Self {
            requests: vec![HttpRequest::get("/")],
            per_connection: 1,
            pipeline: false,
            host: None,
            user_agent: format!("FeroTRX/{}", env!("CARGO_PKG_VERSION")),
            think_time: Duration::ZERO,
        }
    }
}

/// How the server answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpServer {
    /// The first route that matches answers; with none, every request gets
    /// `200 OK` and a short body.
    pub routes: Vec<HttpRoute>,
    /// The `Server` header; empty: none.
    pub server: String,
}

impl Default for HttpServer {
    fn default() -> Self {
        Self {
            routes: Vec::new(),
            server: "FeroTRX".into(),
        }
    }
}

impl HttpServer {
    /// The route that answers `method` `path` (query left out).
    pub fn route(&self, method: &str, path: &str) -> std::borrow::Cow<'_, HttpRoute> {
        let path = path.split(['?', '#']).next().unwrap_or(path);
        if self.routes.is_empty() {
            return std::borrow::Cow::Owned(
                HttpRoute::new("*", 200)
                    .with_body("FeroTRX\n")
                    .with_header("Content-Type", "text/plain"),
            );
        }
        match self.routes.iter().find(|r| r.matches(method, path)) {
            Some(r) => std::borrow::Cow::Borrowed(r),
            None => std::borrow::Cow::Owned(
                HttpRoute::new("*", 404)
                    .with_body("not found\n")
                    .with_header("Content-Type", "text/plain"),
            ),
        }
    }
}

/// HTTP/1.1 as an [`AppProtocol`]: both ends' settings.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Http {
    pub client: HttpClient,
    pub server: HttpServer,
}

impl AppProtocol for Http {
    fn name(&self) -> &str {
        "http"
    }

    fn describe(&self) -> String {
        let c = &self.client;
        let mut s = format!(
            "HTTP/1.1: {} request(s), {} per connection{}",
            c.requests.len(),
            c.per_connection,
            if c.pipeline { ", pipelined" } else { "" }
        );
        if self.server.routes.is_empty() {
            s.push_str(", server answers 200 to all");
        } else {
            s.push_str(&format!(", {} route(s)", self.server.routes.len()));
        }
        s
    }

    fn default_port(&self) -> u16 {
        80
    }

    fn supports(&self, t: Transport) -> bool {
        t == Transport::Stream
    }

    fn validate(&self, role: AppRole, _t: Transport) -> Result<()> {
        if role == AppRole::Client {
            if self.client.requests.is_empty() {
                return Err(Error::Profile("http: the client has no requests".into()));
            }
            if self.client.per_connection == 0 {
                return Err(Error::Profile(
                    "http: per_connection must be at least 1".into(),
                ));
            }
        }
        Ok(())
    }

    fn session(&self, init: &SessionInit) -> Box<dyn AppSession> {
        let cfg = Arc::new(self.clone());
        match init.role {
            AppRole::Client => {
                let host = self
                    .client
                    .host
                    .clone()
                    .unwrap_or_else(|| match init.remote {
                        std::net::SocketAddr::V4(a) if a.port() == 80 => a.ip().to_string(),
                        std::net::SocketAddr::V6(a) if a.port() == 80 => format!("[{}]", a.ip()),
                        a => a.to_string(),
                    });
                Box::new(ClientSession {
                    cfg,
                    host,
                    first: init.index * u64::from(self.client.per_connection.max(1)),
                    sent: 0,
                    answered: 0,
                    outstanding: VecDeque::new(),
                    parser: Parser::default(),
                    status: 0,
                    stop: false,
                })
            }
            AppRole::Server => Box::new(ServerSession {
                cfg,
                parser: Parser::default(),
                request: None,
                queue: VecDeque::new(),
                closing: false,
            }),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ----- parsing -----

/// A parsed start line and header section.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Head {
    /// The three parts of the start line: method, target, version for a
    /// request; version, status, reason for a response.
    pub start: [String; 3],
    pub headers: Vec<(String, String)>,
}

impl Head {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// True if a `Connection` header lists `token`.
    fn connection(&self, token: &str) -> bool {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("connection"))
            .any(|(_, v)| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    }

    fn chunked(&self) -> bool {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
            .any(|(_, v)| {
                v.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("chunked"))
            })
    }

    fn content_length(&self) -> std::result::Result<Option<u64>, String> {
        match self.header("content-length") {
            None => Ok(None),
            Some(v) => v
                .trim()
                .parse()
                .map(Some)
                .map_err(|_| format!("bad Content-Length `{v}`")),
        }
    }

    /// The peer wants the connection closed after this message.
    fn wants_close(&self, request: bool) -> bool {
        let version = if request {
            &self.start[2]
        } else {
            &self.start[0]
        };
        self.connection("close") || (version == "HTTP/1.0" && !self.connection("keep-alive"))
    }
}

/// How a message's body ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    None,
    Length(u64),
    Chunked,
    /// Until the connection closes (a response without a length).
    UntilClose,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum PState {
    #[default]
    Head,
    Fixed(u64),
    ChunkSize,
    ChunkData(u64),
    ChunkEnd,
    Trailer,
    UntilClose,
}

/// What the parser found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Head(Head),
    /// The message's body ended, after this many body bytes.
    Done(u64),
}

/// Longest header section taken.
const MAX_HEAD: usize = 64 * 1024;

/// An incremental parser for a stream of HTTP/1.1 messages. Bodies are
/// counted, not kept.
#[derive(Debug, Default)]
pub struct Parser {
    buf: Vec<u8>,
    state: PState,
    body: u64,
}

impl Parser {
    /// Takes `data`. `framing` says how the body of a message with the
    /// given head ends. Returns what was completed, in order.
    pub fn feed(
        &mut self,
        data: &[u8],
        mut framing: impl FnMut(&Head) -> std::result::Result<Framing, String>,
    ) -> std::result::Result<Vec<Event>, String> {
        let mut buf = std::mem::take(&mut self.buf);
        buf.extend_from_slice(data);
        let mut pos = 0;
        let mut events = Vec::new();
        loop {
            let rest = &buf[pos..];
            match self.state {
                PState::Head => {
                    let Some((head_end, body_at)) = find_head_end(rest) else {
                        if rest.len() > MAX_HEAD {
                            return Err("header section too long".into());
                        }
                        break;
                    };
                    let head = parse_head(&rest[..head_end])?;
                    pos += body_at;
                    self.body = 0;
                    let f = framing(&head)?;
                    events.push(Event::Head(head));
                    self.state = match f {
                        Framing::None | Framing::Length(0) => {
                            events.push(Event::Done(0));
                            PState::Head
                        }
                        Framing::Length(n) => PState::Fixed(n),
                        Framing::Chunked => PState::ChunkSize,
                        Framing::UntilClose => PState::UntilClose,
                    };
                }
                PState::Fixed(left) | PState::ChunkData(left) => {
                    if rest.is_empty() {
                        break;
                    }
                    let n = (left as usize).min(rest.len());
                    self.body += n as u64;
                    pos += n;
                    let chunk = matches!(self.state, PState::ChunkData(_));
                    self.state = match (left == n as u64, chunk) {
                        (false, false) => PState::Fixed(left - n as u64),
                        (false, true) => PState::ChunkData(left - n as u64),
                        (true, true) => PState::ChunkEnd,
                        (true, false) => {
                            events.push(Event::Done(self.body));
                            PState::Head
                        }
                    };
                }
                PState::UntilClose => {
                    self.body += rest.len() as u64;
                    pos = buf.len();
                    break;
                }
                PState::ChunkSize | PState::ChunkEnd | PState::Trailer => {
                    let Some(nl) = rest.iter().position(|&b| b == b'\n') else {
                        if rest.len() > 4096 {
                            return Err("chunk line too long".into());
                        }
                        break;
                    };
                    let line = String::from_utf8_lossy(&rest[..nl]).into_owned();
                    let line = line.trim_end_matches('\r');
                    pos += nl + 1;
                    self.state = match self.state {
                        PState::ChunkSize => {
                            let size = line.split(';').next().unwrap_or("").trim();
                            let n = u64::from_str_radix(size, 16)
                                .map_err(|_| format!("bad chunk size `{size}`"))?;
                            if n == 0 {
                                PState::Trailer
                            } else {
                                PState::ChunkData(n)
                            }
                        }
                        PState::ChunkEnd if line.is_empty() => PState::ChunkSize,
                        PState::ChunkEnd => return Err("no CRLF after a chunk".into()),
                        _ if line.is_empty() => {
                            events.push(Event::Done(self.body));
                            PState::Head
                        }
                        s => s,
                    };
                }
            }
        }
        buf.drain(..pos);
        self.buf = buf;
        Ok(events)
    }

    /// The connection closed: ends a body that runs until then. An error if a
    /// message was cut short.
    pub fn close(&mut self) -> std::result::Result<Option<Event>, String> {
        match self.state {
            PState::UntilClose => {
                self.state = PState::Head;
                Ok(Some(Event::Done(self.body)))
            }
            PState::Head if self.buf.iter().all(|b| b.is_ascii_whitespace()) => Ok(None),
            _ => Err("the connection closed in the middle of a message".into()),
        }
    }

    /// True between messages.
    pub fn idle(&self) -> bool {
        self.state == PState::Head && self.buf.is_empty()
    }
}

/// The end of the header section: (where the head ends, where the body begins).
fn find_head_end(b: &[u8]) -> Option<(usize, usize)> {
    // Empty lines before a message are skipped (RFC 9112 2.2).
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\n' {
            // A line ends at i; an empty line follows if b[i+1] is \n or \r\n.
            if b.get(i + 1) == Some(&b'\n') {
                return Some((i, i + 2));
            }
            if b.get(i + 1) == Some(&b'\r') && b.get(i + 2) == Some(&b'\n') {
                return Some((i, i + 3));
            }
        }
        i += 1;
    }
    None
}

fn parse_head(b: &[u8]) -> std::result::Result<Head, String> {
    let text = std::str::from_utf8(b).map_err(|_| "header section is not text".to_string())?;
    let mut lines = text
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .skip_while(|l| l.is_empty());
    let start = lines.next().ok_or("no start line")?;
    let mut parts = start.splitn(3, ' ');
    let a = parts.next().unwrap_or("").to_string();
    let b2 = parts
        .next()
        .ok_or_else(|| format!("bad start line `{start}`"))?
        .to_string();
    let c = parts.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            break;
        }
        let (k, v) = l
            .split_once(':')
            .ok_or_else(|| format!("bad header line `{l}`"))?;
        if k.is_empty() || k.contains([' ', '\t']) {
            return Err(format!("bad header name `{k}`"));
        }
        headers.push((k.to_string(), v.trim().to_string()));
    }
    Ok(Head {
        start: [a, b2, c],
        headers,
    })
}

/// How a request's body ends.
fn request_framing(h: &Head) -> std::result::Result<Framing, String> {
    if !h.start[2].starts_with("HTTP/1.") {
        return Err(format!("not an HTTP/1.x request: `{}`", h.start.join(" ")));
    }
    if h.chunked() {
        return Ok(Framing::Chunked);
    }
    Ok(h.content_length()?.map_or(Framing::None, Framing::Length))
}

/// How a response's body ends, for a request with `method`.
fn response_framing(h: &Head, method: &str) -> std::result::Result<Framing, String> {
    if !h.start[0].starts_with("HTTP/1.") {
        return Err(format!("not an HTTP/1.x response: `{}`", h.start.join(" ")));
    }
    let status: u16 = h.start[1]
        .parse()
        .map_err(|_| format!("bad status `{}`", h.start[1]))?;
    if method == "HEAD" || status < 200 || status == 204 || status == 304 {
        return Ok(Framing::None);
    }
    if h.chunked() {
        return Ok(Framing::Chunked);
    }
    Ok(h.content_length()?
        .map_or(Framing::UntilClose, Framing::Length))
}

// ----- sessions -----

struct ClientSession {
    cfg: Arc<Http>,
    host: String,
    /// Number of the connection's first request, across connections.
    first: u64,
    sent: u32,
    answered: u32,
    /// Requests sent and not answered yet: which, and when it went.
    outstanding: VecDeque<(usize, Duration)>,
    parser: Parser,
    /// Status of the response being read.
    status: u16,
    /// The server said it closes: send nothing more.
    stop: bool,
}

impl ClientSession {
    fn request_index(&self, k: u32) -> usize {
        ((self.first + u64::from(k)) % self.cfg.client.requests.len() as u64) as usize
    }

    fn send_next(&mut self, cx: &mut AppCx) {
        let c = &self.cfg.client;
        if self.stop || self.sent >= c.per_connection {
            return;
        }
        let i = self.request_index(self.sent);
        let ua = c.user_agent.clone();
        cx.send(c.requests[i].bytes(&self.host, &ua));
        self.outstanding.push_back((i, cx.now()));
        self.sent += 1;
    }

    fn fail(&mut self, cx: &mut AppCx, what: String) {
        cx.protocol_error(what);
        self.stop = true;
        cx.close();
    }

    fn take(&mut self, events: Vec<Event>, cx: &mut AppCx) {
        for e in events {
            match e {
                Event::Head(h) => {
                    self.status = h.start[1].parse().unwrap_or(0);
                    if h.wants_close(false) {
                        self.stop = true;
                    }
                }
                Event::Done(_) => {
                    if (100..200).contains(&self.status) {
                        continue; // an interim response; the real one follows
                    }
                    let Some((i, at)) = self.outstanding.pop_front() else {
                        self.fail(cx, "a response nobody asked for".into());
                        return;
                    };
                    let req = &self.cfg.client.requests[i];
                    cx.transaction(
                        AppTransaction::new(
                            self.status.to_string(),
                            req.expect.matches(self.status),
                        )
                        .with_error(self.status >= 400)
                        .with_response_time(cx.now().saturating_sub(at)),
                    );
                    self.answered += 1;
                }
            }
        }
        let c = &self.cfg.client;
        if self.answered >= c.per_connection || (self.stop && self.outstanding.is_empty()) {
            if self.answered < c.per_connection {
                cx.protocol_error(format!(
                    "the server closed after {} of {} requests",
                    self.answered, c.per_connection
                ));
            }
            cx.close();
        } else if !c.pipeline && self.outstanding.is_empty() {
            if c.think_time.is_zero() {
                self.send_next(cx);
            } else {
                cx.wake_at(cx.now() + c.think_time);
            }
        }
    }
}

impl AppSession for ClientSession {
    fn start(&mut self, cx: &mut AppCx) {
        if self.cfg.client.pipeline {
            for _ in 0..self.cfg.client.per_connection {
                self.send_next(cx);
            }
        } else {
            self.send_next(cx);
        }
    }

    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        if self.outstanding.is_empty() && self.parser.idle() {
            self.fail(cx, "the server sent before it was asked".into());
            return Receive::Taken;
        }
        let reqs = &self.cfg.client.requests;
        let method = |o: &VecDeque<(usize, Duration)>| {
            o.front()
                .map_or("GET", |&(i, _)| reqs[i].method.as_str())
                .to_string()
        };
        let m = method(&self.outstanding);
        match self.parser.feed(data, |h| response_framing(h, &m)) {
            Ok(events) => self.take(events, cx),
            Err(e) => self.fail(cx, e),
        }
        Receive::Taken
    }

    fn peer_closed(&mut self, cx: &mut AppCx) {
        match self.parser.close() {
            Ok(Some(e)) => self.take(vec![e], cx),
            Ok(None) => {}
            Err(e) => {
                self.fail(cx, e);
                return;
            }
        }
        if self.answered < self.cfg.client.per_connection && !self.stop {
            self.stop = true;
            cx.protocol_error(format!(
                "the server closed after {} of {} requests",
                self.answered, self.cfg.client.per_connection
            ));
        }
        cx.close();
    }

    fn timer(&mut self, cx: &mut AppCx) {
        self.send_next(cx);
    }
}

struct ServerSession {
    cfg: Arc<Http>,
    parser: Parser,
    /// The request being read: method, target, close after it.
    request: Option<(String, String, bool)>,
    /// Answers waiting for their route's delay: when, the bytes, close after.
    queue: VecDeque<(Duration, Vec<u8>, bool)>,
    closing: bool,
}

impl ServerSession {
    fn flush(&mut self, cx: &mut AppCx) {
        while let Some((at, _, _)) = self.queue.front() {
            if *at > cx.now() {
                cx.wake_at(*at);
                return;
            }
            let (_, bytes, close) = self.queue.pop_front().unwrap_or_default();
            cx.send(bytes);
            if close {
                self.closing = true;
                self.queue.clear();
                cx.close();
                return;
            }
        }
    }

    fn bad_request(&mut self, cx: &mut AppCx, what: String) {
        cx.protocol_error(what);
        let r = HttpRoute::new("*", 400).with_body("bad request\n");
        self.queue.push_back((
            cx.now(),
            r.bytes(&self.cfg.server.server, false, true),
            true,
        ));
        self.flush(cx);
    }
}

impl AppSession for ServerSession {
    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        if self.closing {
            return Receive::Taken;
        }
        let events = match self.parser.feed(data, request_framing) {
            Ok(e) => e,
            Err(e) => {
                self.bad_request(cx, e);
                return Receive::Taken;
            }
        };
        for e in events {
            match e {
                Event::Head(h) => {
                    let close = h.wants_close(true);
                    self.request = Some((h.start[0].clone(), h.start[1].clone(), close));
                }
                Event::Done(_) => {
                    let Some((method, target, close)) = self.request.take() else {
                        continue;
                    };
                    let route = self.cfg.server.route(&method, &target);
                    let close = close || route.close;
                    let bytes = route.bytes(&self.cfg.server.server, method == "HEAD", close);
                    let at = cx.now() + route.delay;
                    cx.transaction(
                        AppTransaction::new(route.status.to_string(), true)
                            .with_error(route.status >= 400),
                    );
                    self.queue.push_back((at, bytes, close));
                }
            }
        }
        self.flush(cx);
        Receive::Taken
    }

    fn peer_closed(&mut self, cx: &mut AppCx) {
        if let Err(e) = self.parser.close() {
            cx.protocol_error(e);
        }
        // Answer what was asked, then close.
        match self.queue.back_mut() {
            Some(last) => last.2 = true,
            None => cx.close(),
        }
        self.flush(cx);
    }

    fn timer(&mut self, cx: &mut AppCx) {
        self.flush(cx);
    }
}

// ----- profiles -----

#[cfg(feature = "profile")]
mod raw {
    use std::collections::BTreeMap;

    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(untagged)]
    pub enum Size {
        N(u64),
        S(String),
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    pub enum Status {
        N(u16),
        S(String),
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Http {
        #[serde(default)]
        pub requests: Vec<String>,
        #[serde(default)]
        pub request: Vec<Request>,
        #[serde(default)]
        pub route: Vec<Route>,
        pub per_connection: Option<u32>,
        pub pipeline: Option<bool>,
        pub host: Option<String>,
        pub user_agent: Option<String>,
        pub think_time: Option<String>,
        pub server: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Request {
        pub method: Option<String>,
        pub path: String,
        #[serde(default)]
        pub headers: BTreeMap<String, String>,
        pub body: Option<String>,
        pub body_size: Option<Size>,
        pub body_file: Option<String>,
        pub content_type: Option<String>,
        pub expect: Option<Status>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Route {
        pub method: Option<String>,
        pub path: String,
        pub status: Option<u16>,
        pub reason: Option<String>,
        #[serde(default)]
        pub headers: BTreeMap<String, String>,
        pub body: Option<String>,
        pub body_size: Option<Size>,
        pub body_file: Option<String>,
        pub content_type: Option<String>,
        pub chunked: Option<bool>,
        pub close: Option<bool>,
        pub delay: Option<String>,
    }
}

/// A body from `body`, `body_size` (filler) or `body_file`.
#[cfg(feature = "profile")]
fn body(
    text: Option<String>,
    size: Option<raw::Size>,
    file: Option<String>,
    base: &std::path::Path,
) -> Result<Vec<u8>> {
    match (text, size, file) {
        (None, None, None) => Ok(Vec::new()),
        (Some(t), None, None) => Ok(t.into_bytes()),
        (None, Some(s), None) => {
            let n = match s {
                raw::Size::N(n) => n,
                raw::Size::S(s) => crate::parse_size(&s)?,
            };
            if n > 1 << 30 {
                return Err(Error::Profile(format!("body_size {n} is over 1G")));
            }
            Ok(super::filler(n as usize))
        }
        (None, None, Some(f)) => {
            let p = base.join(f);
            std::fs::read(&p)
                .map_err(|e| Error::Profile(format!("cannot read {}: {e}", p.display())))
        }
        _ => Err(Error::Profile(
            "give one of `body`, `body_size` and `body_file`".into(),
        )),
    }
}

/// Reads an `[http]` table.
#[cfg(feature = "profile")]
pub fn parse(t: &toml::Table, base: &std::path::Path) -> Result<Http> {
    let r: raw::Http = super::registry::table_into(t)?;
    let mut http = Http::default();
    let c = &mut http.client;
    let mut requests = Vec::new();
    for s in &r.requests {
        requests.push(s.parse::<HttpRequest>()?);
    }
    for (i, q) in r.request.into_iter().enumerate() {
        let ctx = |e: Error| Error::Profile(format!("request {}: {e}", i + 1));
        let mut req = HttpRequest::new(q.method.as_deref().unwrap_or("GET"), &q.path);
        req.headers = q.headers.into_iter().collect();
        if let Some(ct) = q.content_type {
            req.headers.push(("Content-Type".into(), ct));
        }
        req.body = body(q.body, q.body_size, q.body_file, base).map_err(ctx)?;
        if let Some(e) = q.expect {
            req.expect = match e {
                raw::Status::N(n) => n.to_string().parse(),
                raw::Status::S(s) => s.parse(),
            }
            .map_err(ctx)?;
        }
        requests.push(req);
    }
    if !requests.is_empty() {
        c.requests = requests;
    }
    if let Some(n) = r.per_connection {
        c.per_connection = n;
    }
    c.pipeline = r.pipeline.unwrap_or(false);
    c.host = r.host;
    if let Some(ua) = r.user_agent {
        c.user_agent = ua;
    }
    if let Some(t) = r.think_time {
        c.think_time = crate::parse_duration(&t)?;
    }
    if let Some(s) = r.server {
        http.server.server = s;
    }
    for (i, q) in r.route.into_iter().enumerate() {
        let ctx = |e: Error| Error::Profile(format!("route {} ({}): {e}", i + 1, q.path));
        let status = q.status.unwrap_or(200);
        if !(100..=999).contains(&status) {
            return Err(ctx(Error::Profile(format!(
                "status {status} is not 100-999"
            ))));
        }
        let mut route = HttpRoute::new(&q.path, status);
        route.method = q.method.map(|m| m.to_ascii_uppercase());
        route.reason = q.reason;
        route.headers = q.headers.into_iter().collect();
        if let Some(ct) = q.content_type {
            route.headers.push(("Content-Type".into(), ct));
        }
        route.body = Arc::from(body(q.body, q.body_size, q.body_file, base).map_err(ctx)?);
        route.chunked = q.chunked.unwrap_or(false);
        route.close = q.close.unwrap_or(false);
        if let Some(d) = q.delay {
            route.delay = crate::parse_duration(&d).map_err(ctx)?;
        }
        http.server.routes.push(route);
    }
    http.validate(AppRole::Client, Transport::Stream)?;
    Ok(http)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_all(p: &mut Parser, data: &[u8], response: bool) -> Vec<Event> {
        let f = |h: &Head| {
            if response {
                response_framing(h, "GET")
            } else {
                request_framing(h)
            }
        };
        p.feed(data, f).unwrap()
    }

    #[test]
    fn parses_messages_in_any_pieces() {
        let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloHTTP/1.1 404 Not Found\r\n\
                     Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\nX-T: 1\r\n\r\n\
                     HTTP/1.1 204 No Content\r\n\r\n";
        for step in [1usize, 2, 7, 1000] {
            let mut p = Parser::default();
            let mut events = Vec::new();
            for c in wire.chunks(step) {
                events.extend(feed_all(&mut p, c, true));
            }
            let done: Vec<u64> = events
                .iter()
                .filter_map(|e| match e {
                    Event::Done(n) => Some(*n),
                    _ => None,
                })
                .collect();
            assert_eq!(done, vec![5, 5, 0], "step {step}");
            assert!(p.idle());
        }
    }

    #[test]
    fn body_until_close_and_errors() {
        let mut p = Parser::default();
        let e = feed_all(&mut p, b"HTTP/1.0 200 OK\r\n\r\nsome bytes", true);
        assert_eq!(e.len(), 1);
        assert_eq!(p.close().unwrap(), Some(Event::Done(10)));
        let mut p = Parser::default();
        assert!(p
            .feed(b"HTTP/1.1 abc\r\n\r\n", |h| response_framing(h, "GET"))
            .is_err());
        let mut p = Parser::default();
        assert!(p.feed(b"GET / SPDY/3\r\n\r\n", request_framing).is_err());
        let mut p = Parser::default();
        feed_all(
            &mut p,
            b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc",
            false,
        );
        assert!(p.close().is_err());
    }

    #[test]
    fn requests_and_statuses_from_text() {
        let r: HttpRequest = "post /x 2xx".parse().unwrap();
        assert_eq!((r.method.as_str(), r.path.as_str()), ("POST", "/x"));
        assert!(r.expect.matches(201) && !r.expect.matches(301));
        let r: HttpRequest = "/only".parse().unwrap();
        assert_eq!(r.method, "GET");
        assert!("GET".parse::<HttpRequest>().is_err());
        assert!("GET / 7xx".parse::<HttpRequest>().is_err());
        assert!(StatusMatch::Success.matches(302) && !StatusMatch::Success.matches(404));
        let b = String::from_utf8(HttpRequest::new("POST", "/u").bytes("h", "ua")).unwrap();
        assert!(b.contains("Content-Length: 0\r\n"), "{b}");
    }

    fn pair(http: Http) -> (Box<dyn AppSession>, Box<dyn AppSession>) {
        let init = |role| SessionInit {
            role,
            transport: Transport::Stream,
            index: 0,
            seed: 1,
            local: "10.0.0.1:1000".parse().unwrap(),
            remote: "10.0.0.2:80".parse().unwrap(),
        };
        (
            http.session(&init(AppRole::Client)),
            http.session(&init(AppRole::Server)),
        )
    }

    /// Plays both ends against each other; returns both contexts' totals.
    fn play(http: Http) -> (super::super::AppStats, super::super::AppStats, bool) {
        let (mut c, mut s) = pair(http);
        let mut cs = super::super::AppStats::default();
        let mut ss = super::super::AppStats::default();
        let mut cx = AppCx::new(Duration::ZERO, Duration::ZERO);
        c.start(&mut cx);
        let mut to_server = cx.take_sends();
        let mut closed = cx.wants_close();
        cx.count_into(&mut cs);
        for _ in 0..20 {
            let mut to_client = Vec::new();
            for d in to_server.drain(..) {
                let mut x = AppCx::new(Duration::from_millis(1), Duration::ZERO);
                s.receive(&d, &mut x);
                to_client.extend(x.take_sends());
                x.count_into(&mut ss);
            }
            for d in to_client {
                let mut x = AppCx::new(Duration::from_millis(2), Duration::ZERO);
                c.receive(&d, &mut x);
                to_server.extend(x.take_sends());
                closed |= x.wants_close();
                x.count_into(&mut cs);
            }
            if to_server.is_empty() {
                break;
            }
        }
        (cs, ss, closed)
    }

    #[test]
    fn client_and_server_play_keep_alive_and_pipelining() {
        let mut http = Http::default();
        http.client.requests = vec![
            HttpRequest::get("/"),
            HttpRequest::get("/nope").expect("404"),
            HttpRequest::new("HEAD", "/big"),
            HttpRequest::new("POST", "/up")
                .with_body(vec![7u8; 3000])
                .expect("201"),
        ];
        http.client.per_connection = 4;
        http.server.routes = vec![
            HttpRoute::new("/", 200).with_body("hi"),
            HttpRoute::new("/big", 200).with_body(super::super::filler(20000)),
            HttpRoute {
                method: Some("POST".into()),
                chunked: true,
                ..HttpRoute::new("/up*", 201).with_body("stored")
            },
        ];
        for pipeline in [false, true] {
            http.client.pipeline = pipeline;
            let (c, s, closed) = play(http.clone());
            assert_eq!((c.transactions, c.failed, c.errors), (4, 0, 1), "{c:?}");
            assert_eq!(c.codes_text(), "200 x2, 201 x1, 404 x1");
            assert_eq!(s.transactions, 4);
            assert_eq!(c.response_time.count(), 4);
            assert!(closed);
        }
    }

    #[test]
    fn unexpected_statuses_fail_and_garbage_is_a_bad_request() {
        let mut http = Http::default();
        http.client.requests = vec![HttpRequest::get("/x")];
        http.server.routes = vec![HttpRoute::new("/", 200)];
        let (c, _, _) = play(http.clone());
        assert_eq!((c.transactions, c.failed), (1, 1));
        let (_, mut s) = pair(http);
        let mut cx = AppCx::new(Duration::ZERO, Duration::ZERO);
        s.receive(b"\x16\x03\x01 not http at all\r\n\r\n", &mut cx);
        let out = cx.take_sends();
        assert!(out[0].starts_with(b"HTTP/1.1 400"));
        assert!(cx.wants_close());
        assert_eq!(cx.protocol_errors().len(), 1);
    }

    #[cfg(feature = "profile")]
    #[test]
    fn parses_a_table() {
        let t: toml::Table = r#"
            requests = ["GET /", "GET /missing 404"]
            per_connection = 2
            think_time = "5ms"
            host = "www.lab.local"
            [[request]]
            method = "post"
            path = "/upload"
            body_size = "1K"
            expect = 201
            [[route]]
            path = "/"
            body = "hello"
            content_type = "text/plain"
            [[route]]
            path = "/upload"
            method = "POST"
            status = 201
            delay = "2ms"
            chunked = true
        "#
        .parse()
        .unwrap();
        let h = parse(&t, std::path::Path::new(".")).unwrap();
        assert_eq!(h.client.requests.len(), 3);
        assert_eq!(h.client.requests[2].body.len(), 1024);
        assert_eq!(h.client.requests[2].expect, StatusMatch::Code(201));
        assert_eq!(h.server.routes[1].delay, Duration::from_millis(2));
        assert!(h.describe().contains("3 request(s), 2 per connection"));
        let bad: toml::Table = "routes = []".parse().unwrap();
        assert!(parse(&bad, std::path::Path::new(".")).is_err());
    }
}
