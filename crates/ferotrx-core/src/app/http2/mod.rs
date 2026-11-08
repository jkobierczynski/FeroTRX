//! HTTP/2 (RFC 9113): a client that multiplexes the configured requests on
//! one connection and checks their status codes, and a server that answers
//! them from the same routes as [`http`](super::http).
//!
//! Both ends speak real HTTP/2: the connection preface, SETTINGS and their
//! acknowledgements, HEADERS and CONTINUATION with HPACK ([`hpack`]: static
//! and dynamic tables, Huffman coding), DATA under connection and stream
//! flow control with WINDOW_UPDATE, PING, RST_STREAM and GOAWAY. Over TLS
//! ALPN picks `h2` (`app = "h2"`, or `app = "http2"` with `tls = true`);
//! without TLS the client starts with the preface ("prior knowledge", what
//! `curl --http2-prior-knowledge` does). The server also takes HTTP/1.1 on
//! the same port: a connection that does not start with the preface, or
//! that ALPN gave `http/1.1`, gets the HTTP/1.1 server with the same routes.
//!
//! ```
//! use ferotrx_core::app::http::HttpRequest;
//! use ferotrx_core::app::http2::Http2;
//!
//! let mut h2 = Http2::default();
//! h2.http.client.requests = vec![HttpRequest::get("/"), HttpRequest::get("/style.css")];
//! h2.http.client.per_connection = 10;
//! h2.settings.concurrent = 4; // streams in flight at once
//! assert!(h2.validate_settings().is_ok());
//! ```

pub mod hpack;
mod tables;

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use super::http::{Http, HttpRoute};
use super::{
    AppCx, AppProtocol, AppRole, AppSession, AppTransaction, Receive, SessionInit, Transport,
};
use crate::{Error, Result};
use hpack::{Decoder, Encoder};

/// What an HTTP/2 client sends first.
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Frame types.
const DATA: u8 = 0;
const HEADERS: u8 = 1;
const PRIORITY: u8 = 2;
const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const PUSH_PROMISE: u8 = 5;
const PING: u8 = 6;
const GOAWAY: u8 = 7;
const WINDOW_UPDATE: u8 = 8;
const CONTINUATION: u8 = 9;

// Flags.
const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY_FLAG: u8 = 0x20;

// Error codes.
const NO_ERROR: u32 = 0;
const PROTOCOL_ERROR: u32 = 1;
const FLOW_CONTROL_ERROR: u32 = 3;
const STREAM_CLOSED: u32 = 5;
const FRAME_SIZE_ERROR: u32 = 6;
const ENHANCE_YOUR_CALM: u32 = 11;
/// The longest header block (HEADERS and its CONTINUATION frames) taken:
/// a peer that sends CONTINUATION without end would fill memory.
const MAX_HEADER_BLOCK: usize = 256 * 1024;
const REFUSED_STREAM: u32 = 7;
const COMPRESSION_ERROR: u32 = 9;

/// The largest flow-control window.
const MAX_WINDOW: i64 = (1 << 31) - 1;

/// The name of an HTTP/2 error code.
pub fn error_name(code: u32) -> String {
    match code {
        0 => "NO_ERROR".into(),
        1 => "PROTOCOL_ERROR".into(),
        2 => "INTERNAL_ERROR".into(),
        3 => "FLOW_CONTROL_ERROR".into(),
        4 => "SETTINGS_TIMEOUT".into(),
        5 => "STREAM_CLOSED".into(),
        6 => "FRAME_SIZE_ERROR".into(),
        7 => "REFUSED_STREAM".into(),
        8 => "CANCEL".into(),
        9 => "COMPRESSION_ERROR".into(),
        10 => "CONNECT_ERROR".into(),
        11 => "ENHANCE_YOUR_CALM".into(),
        12 => "INADEQUATE_SECURITY".into(),
        13 => "HTTP_1_1_REQUIRED".into(),
        c => format!("error 0x{c:x}"),
    }
}

/// The HTTP/2 settings of both ends, and how the client uses streams.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Http2Settings {
    /// Client: requests in flight at once on a connection (streams), at
    /// most what the server allows.
    pub concurrent: u32,
    /// Server: `SETTINGS_MAX_CONCURRENT_STREAMS`; a client opening more gets
    /// `REFUSED_STREAM`.
    pub max_concurrent_streams: u32,
    /// `SETTINGS_INITIAL_WINDOW_SIZE` of each stream, and the size of the
    /// connection's window (raised with a WINDOW_UPDATE when over 65535).
    pub window: u32,
    /// `SETTINGS_MAX_FRAME_SIZE`: the largest frame this end takes.
    pub frame_size: u32,
    /// `SETTINGS_HEADER_TABLE_SIZE`: this end's HPACK table, and the most
    /// its encoder uses of the other end's.
    pub header_table_size: u32,
    /// Huffman code header strings where it makes them shorter.
    pub huffman: bool,
    /// Client: the `:scheme` (`https` over TLS).
    pub scheme: String,
}

impl Default for Http2Settings {
    fn default() -> Self {
        Self {
            concurrent: 100,
            max_concurrent_streams: 100,
            window: 65_535,
            frame_size: 16_384,
            header_table_size: 4096,
            huffman: true,
            scheme: "http".into(),
        }
    }
}

/// HTTP/2 as an [`AppProtocol`]: the HTTP requests and routes, and the
/// HTTP/2 settings.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Http2 {
    pub http: Http,
    pub settings: Http2Settings,
}

impl Http2 {
    /// Checks the settings' ranges.
    pub fn validate_settings(&self) -> Result<()> {
        let s = &self.settings;
        let bad = |m: String| Err(Error::Profile(format!("http2: {m}")));
        if s.concurrent == 0 {
            return bad("concurrent must be at least 1".into());
        }
        if i64::from(s.window) > MAX_WINDOW {
            return bad(format!("window {} is over 2^31-1", s.window));
        }
        if !(16_384..=16_777_215).contains(&s.frame_size) {
            return bad(format!("frame_size {} is not 16384-16777215", s.frame_size));
        }
        Ok(())
    }
}

impl AppProtocol for Http2 {
    fn name(&self) -> &str {
        "http2"
    }

    fn describe(&self) -> String {
        let c = &self.http.client;
        let s = &self.settings;
        let mut d = format!(
            "HTTP/2: {} request(s), {} per connection, up to {} at once",
            c.requests.len(),
            c.per_connection,
            s.concurrent
        );
        if self.http.server.routes.is_empty() {
            d.push_str(", server answers 200 to all");
        } else {
            d.push_str(&format!(", {} route(s)", self.http.server.routes.len()));
        }
        if s.max_concurrent_streams != Http2Settings::default().max_concurrent_streams {
            d.push_str(&format!(", {} stream(s) at once", s.max_concurrent_streams));
        }
        d
    }

    fn default_port(&self) -> u16 {
        80
    }

    fn supports(&self, t: Transport) -> bool {
        t == Transport::Stream
    }

    fn validate(&self, role: AppRole, t: Transport) -> Result<()> {
        self.validate_settings()?;
        self.http
            .validate(role, t)
            .map_err(|e| Error::Profile(e.to_string().replace("http:", "http2:")))
    }

    fn session(&self, init: &SessionInit) -> Box<dyn AppSession> {
        let cfg = Arc::new(self.clone());
        match init.role {
            AppRole::Client => {
                let host = self.http.client.host.clone().unwrap_or_else(|| {
                    let default = matches!(init.remote.port(), 80 | 443);
                    match init.remote {
                        std::net::SocketAddr::V4(a) if default => a.ip().to_string(),
                        std::net::SocketAddr::V6(a) if default => format!("[{}]", a.ip()),
                        a => a.to_string(),
                    }
                });
                let per = u64::from(self.http.client.per_connection.max(1));
                Box::new(ClientSession {
                    conn: Conn::new(true, &self.settings),
                    cfg,
                    host,
                    first: init.index * per,
                    next_id: 1,
                    sent: 0,
                    answered: 0,
                    inflight: BTreeMap::new(),
                    retry: Default::default(),
                    gate: None,
                    stop: false,
                    done: false,
                })
            }
            AppRole::Server => Box::new(ServerSession {
                state: ServerState::Preface(Vec::new()),
                init: init.clone(),
                cfg,
            }),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ----- frames and the connection -----

/// One frame: type, flags, stream and payload.
fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut f = Vec::with_capacity(9 + n);
    f.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8, kind, flags]);
    f.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// What the connection read, for the client or server on top.
#[derive(Debug, PartialEq)]
enum Ev {
    /// A complete header block on a stream.
    Head {
        id: u32,
        fields: Vec<(String, String)>,
        end: bool,
    },
    /// Body bytes (their number) on a stream.
    Data { id: u32, len: usize, end: bool },
    /// The other end reset a stream.
    Reset { id: u32, code: u32 },
    /// The other end goes away: streams after `last` were not handled.
    GoAway { last: u32, code: u32 },
}

/// A connection error: code and what happened.
type ConnError = (u32, String);

/// A body waiting for flow control.
#[derive(Debug)]
struct Pending {
    body: Arc<[u8]>,
    at: usize,
}

#[derive(Debug)]
struct Stream {
    /// What this end may still send on it.
    send_window: i64,
    /// What the other end may still send on it.
    recv_window: i64,
    /// Received since the last WINDOW_UPDATE.
    recv_used: u32,
    out: Option<Pending>,
    local_done: bool,
    remote_done: bool,
}

/// The part of HTTP/2 both ends share: framing, settings, HPACK, flow
/// control.
#[derive(Debug)]
struct Conn {
    client: bool,
    me: Http2Settings,
    enc: Encoder,
    dec: Decoder,
    buf: Vec<u8>,
    /// The other end's settings that matter for sending.
    peer_frame: usize,
    peer_window: i64,
    peer_streams: u32,
    send_window: i64,
    recv_window: i64,
    recv_used: u32,
    /// The connection window this end keeps the other at.
    conn_window: u32,
    streams: BTreeMap<u32, Stream>,
    /// A header block waiting for CONTINUATION: stream, END_STREAM, bytes.
    cont: Option<(u32, bool, Vec<u8>)>,
    /// The other end's first SETTINGS came.
    settings_seen: bool,
    /// Highest stream the other end opened.
    last_peer_stream: u32,
}

impl Conn {
    fn new(client: bool, me: &Http2Settings) -> Self {
        Self {
            client,
            enc: Encoder::new(me.header_table_size as usize, me.huffman),
            dec: Decoder::new(me.header_table_size as usize),
            me: me.clone(),
            buf: Vec::new(),
            peer_frame: 16_384,
            peer_window: 65_535,
            peer_streams: u32::MAX,
            send_window: 65_535,
            recv_window: 65_535,
            recv_used: 0,
            conn_window: me.window.max(65_535),
            streams: BTreeMap::new(),
            cont: None,
            settings_seen: false,
            last_peer_stream: 0,
        }
    }

    /// This end's SETTINGS (only what differs from the defaults), and the
    /// WINDOW_UPDATE that sets the connection's window.
    fn hello(&mut self, cx: &mut AppCx) {
        let s = &self.me;
        let mut p = Vec::new();
        let mut set = |id: u16, v: u32| {
            p.extend_from_slice(&id.to_be_bytes());
            p.extend_from_slice(&v.to_be_bytes());
        };
        if s.header_table_size != 4096 {
            set(1, s.header_table_size);
        }
        if self.client {
            set(2, 0); // no server push
        } else {
            set(3, s.max_concurrent_streams);
        }
        if s.window != 65_535 {
            set(4, s.window);
        }
        if s.frame_size != 16_384 {
            set(5, s.frame_size);
        }
        cx.send(frame(SETTINGS, 0, 0, &p));
        if self.conn_window > 65_535 {
            let inc = self.conn_window - 65_535;
            self.recv_window += i64::from(inc);
            cx.send(frame(WINDOW_UPDATE, 0, 0, &inc.to_be_bytes()));
        }
    }

    fn open(&mut self, id: u32) {
        self.streams.insert(
            id,
            Stream {
                send_window: self.peer_window,
                recv_window: i64::from(self.me.window),
                recv_used: 0,
                out: None,
                local_done: false,
                remote_done: false,
            },
        );
    }

    /// Streams open now (not closed both ways).
    fn active(&self) -> usize {
        self.streams.len()
    }

    fn tidy(&mut self, id: u32) {
        if self
            .streams
            .get(&id)
            .is_some_and(|s| s.local_done && s.remote_done && s.out.is_none())
        {
            self.streams.remove(&id);
        }
    }

    /// Sends a header block, split into HEADERS and CONTINUATION frames.
    fn send_headers<'a>(
        &mut self,
        id: u32,
        fields: impl IntoIterator<Item = (&'a str, &'a str)>,
        end: bool,
        cx: &mut AppCx,
    ) {
        let block = self.enc.encode(fields);
        let mut parts = block.chunks(self.peer_frame).peekable();
        let mut kind = HEADERS;
        let mut flags = if end { END_STREAM } else { 0 };
        if block.is_empty() {
            cx.send(frame(HEADERS, flags | END_HEADERS, id, &[]));
        }
        while let Some(p) = parts.next() {
            let last = parts.peek().is_none();
            cx.send(frame(
                kind,
                flags | if last { END_HEADERS } else { 0 },
                id,
                p,
            ));
            kind = CONTINUATION;
            flags = 0;
        }
        if end {
            if let Some(s) = self.streams.get_mut(&id) {
                s.local_done = true;
            }
            self.tidy(id);
        }
    }

    /// Sends `body` on a stream as flow control allows, then END_STREAM.
    fn send_body(&mut self, id: u32, body: Arc<[u8]>, cx: &mut AppCx) {
        if let Some(s) = self.streams.get_mut(&id) {
            s.out = Some(Pending { body, at: 0 });
        }
        self.pump(cx);
    }

    /// Bodies wait for flow control.
    fn pending(&self) -> bool {
        self.streams.values().any(|s| s.out.is_some())
    }

    /// Sends what the windows allow of the waiting bodies, by stream.
    fn pump(&mut self, cx: &mut AppCx) {
        let mut finished = Vec::new();
        for (&id, s) in &mut self.streams {
            let Some(p) = &mut s.out else { continue };
            loop {
                let left = p.body.len() - p.at;
                let room = self.send_window.min(s.send_window);
                if left > 0 && room <= 0 {
                    break;
                }
                let n = left.min(room.max(0) as usize).min(self.peer_frame);
                let end = n == left;
                cx.send(frame(
                    DATA,
                    if end { END_STREAM } else { 0 },
                    id,
                    &p.body[p.at..p.at + n],
                ));
                p.at += n;
                self.send_window -= n as i64;
                s.send_window -= n as i64;
                if end {
                    s.out = None;
                    s.local_done = true;
                    finished.push(id);
                    break;
                }
            }
        }
        for id in finished {
            self.tidy(id);
        }
    }

    fn reset(&mut self, id: u32, code: u32, cx: &mut AppCx) {
        cx.send(frame(RST_STREAM, 0, id, &code.to_be_bytes()));
        self.streams.remove(&id);
    }

    fn goaway(&self, code: u32, cx: &mut AppCx) {
        let mut p = self.last_peer_stream.to_be_bytes().to_vec();
        p.extend_from_slice(&code.to_be_bytes());
        cx.send(frame(GOAWAY, 0, 0, &p));
    }

    /// Reads what arrived: the events for the end on top.
    fn feed(&mut self, data: &[u8], cx: &mut AppCx) -> std::result::Result<Vec<Ev>, ConnError> {
        self.buf.extend_from_slice(data);
        let mut events = Vec::new();
        let mut at = 0;
        let result = loop {
            let b = &self.buf[at..];
            if b.len() < 9 {
                break Ok(());
            }
            let len = (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]);
            if len > self.me.frame_size as usize {
                break Err((
                    FRAME_SIZE_ERROR,
                    format!(
                        "a frame of {len} bytes, over the {} allowed",
                        self.me.frame_size
                    ),
                ));
            }
            if b.len() < 9 + len {
                break Ok(());
            }
            let (kind, flags, id) = (b[3], b[4], u32_at(b, 5) & 0x7fff_ffff);
            let payload = b[9..9 + len].to_vec();
            at += 9 + len;
            if let Err(e) = self.frame(kind, flags, id, &payload, &mut events, cx) {
                break Err(e);
            }
        };
        self.buf.drain(..at);
        result.map(|()| events)
    }

    fn frame(
        &mut self,
        kind: u8,
        flags: u8,
        id: u32,
        p: &[u8],
        events: &mut Vec<Ev>,
        cx: &mut AppCx,
    ) -> std::result::Result<(), ConnError> {
        let proto = |m: &str| Err((PROTOCOL_ERROR, m.to_string()));
        if let Some((cid, _, _)) = &self.cont {
            if kind != CONTINUATION || id != *cid {
                return proto("a frame between HEADERS and their CONTINUATION");
            }
        }
        if !self.settings_seen && !(kind == SETTINGS && flags & ACK == 0) {
            return proto("the first frame is not SETTINGS");
        }
        let size = |n: usize| -> std::result::Result<(), ConnError> {
            if p.len() == n {
                Ok(())
            } else {
                Err((
                    FRAME_SIZE_ERROR,
                    format!("frame type {kind} of {} bytes", p.len()),
                ))
            }
        };
        match kind {
            DATA => {
                if id == 0 {
                    return proto("DATA on stream 0");
                }
                let n = p.len() as i64;
                self.recv_window -= n;
                if self.recv_window < 0 {
                    return Err((FLOW_CONTROL_ERROR, "DATA over the connection window".into()));
                }
                self.recv_used += p.len() as u32;
                if self.recv_used >= self.conn_window / 2 {
                    cx.send(frame(WINDOW_UPDATE, 0, 0, &self.recv_used.to_be_bytes()));
                    self.recv_window += i64::from(self.recv_used);
                    self.recv_used = 0;
                }
                let body = unpad(flags, p)?;
                let end = flags & END_STREAM != 0;
                let half = self.me.window / 2;
                let Some(s) = self.streams.get_mut(&id) else {
                    if (id > self.last_peer_stream && !self.client) || id.is_multiple_of(2) {
                        return proto("DATA on a stream not opened");
                    }
                    self.reset(id, STREAM_CLOSED, cx);
                    return Ok(());
                };
                if s.remote_done {
                    self.reset(id, STREAM_CLOSED, cx);
                    return Ok(());
                }
                s.recv_window -= n;
                if s.recv_window < 0 {
                    return Err((FLOW_CONTROL_ERROR, "DATA over a stream's window".into()));
                }
                s.recv_used += p.len() as u32;
                if end {
                    s.remote_done = true;
                } else if s.recv_used >= half.max(1) {
                    cx.send(frame(WINDOW_UPDATE, 0, id, &s.recv_used.to_be_bytes()));
                    s.recv_window += i64::from(s.recv_used);
                    s.recv_used = 0;
                }
                events.push(Ev::Data {
                    id,
                    len: body.len(),
                    end,
                });
                self.tidy(id);
            }
            HEADERS => {
                if id == 0 {
                    return proto("HEADERS on stream 0");
                }
                let mut block = unpad(flags, p)?;
                if flags & PRIORITY_FLAG != 0 {
                    if block.len() < 5 {
                        return Err((FRAME_SIZE_ERROR, "HEADERS too short".into()));
                    }
                    block = &block[5..];
                }
                let end = flags & END_STREAM != 0;
                if flags & END_HEADERS != 0 {
                    self.head(id, block, end, events, cx)?;
                } else {
                    self.cont = Some((id, end, block.to_vec()));
                }
            }
            CONTINUATION => {
                let Some((cid, end, mut block)) = self.cont.take() else {
                    return proto("CONTINUATION without HEADERS");
                };
                if block.len() + p.len() > MAX_HEADER_BLOCK {
                    return Err((
                        ENHANCE_YOUR_CALM,
                        format!("a header block over {MAX_HEADER_BLOCK} bytes"),
                    ));
                }
                block.extend_from_slice(p);
                if flags & END_HEADERS != 0 {
                    self.head(cid, &block, end, events, cx)?;
                } else {
                    self.cont = Some((cid, end, block));
                }
            }
            PRIORITY => size(5)?,
            RST_STREAM => {
                size(4)?;
                if id == 0 {
                    return proto("RST_STREAM on stream 0");
                }
                self.streams.remove(&id);
                events.push(Ev::Reset {
                    id,
                    code: u32_at(p, 0),
                });
            }
            SETTINGS => {
                if id != 0 {
                    return proto("SETTINGS on a stream");
                }
                if flags & ACK != 0 {
                    return size(0);
                }
                if !p.len().is_multiple_of(6) {
                    return Err((FRAME_SIZE_ERROR, "SETTINGS not a multiple of 6".into()));
                }
                for s in p.chunks(6) {
                    let v = u32_at(s, 2);
                    match u16::from_be_bytes([s[0], s[1]]) {
                        1 => self.enc.peer_limit(v as usize),
                        2 if v > 1 => return proto("SETTINGS_ENABLE_PUSH not 0 or 1"),
                        3 => self.peer_streams = v,
                        4 => {
                            if i64::from(v) > MAX_WINDOW {
                                return Err((
                                    FLOW_CONTROL_ERROR,
                                    "SETTINGS_INITIAL_WINDOW_SIZE over 2^31-1".into(),
                                ));
                            }
                            let delta = i64::from(v) - self.peer_window;
                            for st in self.streams.values_mut() {
                                st.send_window += delta;
                            }
                            self.peer_window = i64::from(v);
                        }
                        5 => {
                            if !(16_384..=16_777_215).contains(&v) {
                                return proto("SETTINGS_MAX_FRAME_SIZE out of range");
                            }
                            self.peer_frame = v as usize;
                        }
                        _ => {} // header list size, unknown settings
                    }
                }
                self.settings_seen = true;
                cx.send(frame(SETTINGS, ACK, 0, &[]));
                self.pump(cx);
            }
            PUSH_PROMISE => return proto("PUSH_PROMISE, with push turned off"),
            PING => {
                size(8)?;
                if id != 0 {
                    return proto("PING on a stream");
                }
                if flags & ACK == 0 {
                    cx.send(frame(PING, ACK, 0, p));
                }
            }
            GOAWAY => {
                if p.len() < 8 {
                    return Err((FRAME_SIZE_ERROR, "GOAWAY too short".into()));
                }
                events.push(Ev::GoAway {
                    last: u32_at(p, 0) & 0x7fff_ffff,
                    code: u32_at(p, 4),
                });
            }
            WINDOW_UPDATE => {
                size(4)?;
                let inc = i64::from(u32_at(p, 0) & 0x7fff_ffff);
                if inc == 0 {
                    return proto("a WINDOW_UPDATE of 0");
                }
                if id == 0 {
                    self.send_window += inc;
                    if self.send_window > MAX_WINDOW {
                        return Err((FLOW_CONTROL_ERROR, "connection window over 2^31-1".into()));
                    }
                } else if let Some(s) = self.streams.get_mut(&id) {
                    s.send_window += inc;
                    if s.send_window > MAX_WINDOW {
                        return Err((FLOW_CONTROL_ERROR, "stream window over 2^31-1".into()));
                    }
                }
                self.pump(cx);
            }
            _ => {} // unknown frame types are ignored
        }
        Ok(())
    }

    /// A complete header block.
    fn head(
        &mut self,
        id: u32,
        block: &[u8],
        end: bool,
        events: &mut Vec<Ev>,
        cx: &mut AppCx,
    ) -> std::result::Result<(), ConnError> {
        let fields = self.dec.decode(block).map_err(|e| (COMPRESSION_ERROR, e))?;
        if !self.streams.contains_key(&id) {
            let theirs = if self.client {
                id.is_multiple_of(2)
            } else {
                id % 2 == 1
            };
            if !theirs || id <= self.last_peer_stream {
                if !self.client && id % 2 == 1 && id <= self.last_peer_stream {
                    // Trailers or more on a stream already closed.
                    self.reset(id, STREAM_CLOSED, cx);
                    return Ok(());
                }
                return Err((PROTOCOL_ERROR, format!("HEADERS on stream {id}, not open")));
            }
            self.last_peer_stream = id;
            self.open(id);
        }
        if let Some(s) = self.streams.get_mut(&id) {
            if end {
                s.remote_done = true;
            }
        }
        events.push(Ev::Head { id, fields, end });
        self.tidy(id);
        Ok(())
    }
}

/// A DATA or HEADERS payload without its padding.
fn unpad(flags: u8, p: &[u8]) -> std::result::Result<&[u8], ConnError> {
    if flags & PADDED == 0 {
        return Ok(p);
    }
    let pad = usize::from(
        *p.first()
            .ok_or((FRAME_SIZE_ERROR, "padding missing".to_string()))?,
    );
    if pad + 1 > p.len() {
        return Err((PROTOCOL_ERROR, "more padding than payload".into()));
    }
    Ok(&p[1..p.len() - pad])
}

/// Headers HTTP/2 does not carry (RFC 9113 8.2.2).
fn connection_specific(name: &str) -> bool {
    matches!(
        name,
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade" | "host"
    )
}

fn has(fields: &[(String, String)], name: &str) -> bool {
    fields.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

// ----- client -----

struct ClientSession {
    cfg: Arc<Http2>,
    conn: Conn,
    host: String,
    /// Number of the connection's first request, across connections.
    first: u64,
    next_id: u32,
    sent: u32,
    answered: u32,
    /// Streams in flight: request, when it went, the status so far.
    inflight: BTreeMap<u32, (usize, Duration, u16)>,
    /// Requests the server refused (`REFUSED_STREAM`): sent again.
    retry: std::collections::VecDeque<usize>,
    /// No new request before this (think time).
    gate: Option<Duration>,
    /// No new streams (GOAWAY, or a connection error).
    stop: bool,
    done: bool,
}

impl ClientSession {
    fn fill(&mut self, cx: &mut AppCx) {
        let cfg = self.cfg.clone();
        let c = &cfg.http.client;
        if let Some(g) = self.gate {
            if g > cx.now() {
                cx.wake_at(g);
                return;
            }
            self.gate = None;
        }
        let limit = self.cfg.settings.concurrent.min(self.conn.peer_streams) as usize;
        while !self.stop
            && (self.sent < c.per_connection || !self.retry.is_empty())
            && self.inflight.len() < limit.max(1)
        {
            self.send_request(cx);
            if !c.think_time.is_zero() {
                break; // one at a time, as a user would
            }
        }
    }

    fn send_request(&mut self, cx: &mut AppCx) {
        let c = &self.cfg.http.client;
        let i = match self.retry.pop_front() {
            Some(i) => i,
            None => {
                self.sent += 1;
                ((self.first + u64::from(self.sent - 1)) % c.requests.len() as u64) as usize
            }
        };
        let req = &c.requests[i];
        let id = self.next_id;
        self.next_id += 2;
        let mut fields: Vec<(String, String)> = vec![
            (":method".into(), req.method.clone()),
            (":scheme".into(), self.cfg.settings.scheme.clone()),
            (":authority".into(), self.host.clone()),
            (":path".into(), req.path.clone()),
        ];
        if !c.user_agent.is_empty() && !has(&req.headers, "user-agent") {
            fields.push(("user-agent".into(), c.user_agent.clone()));
        }
        if !has(&req.headers, "accept") {
            fields.push(("accept".into(), "*/*".into()));
        }
        for (k, v) in &req.headers {
            let k = k.to_ascii_lowercase();
            if !connection_specific(&k) {
                fields.push((k, v.clone()));
            }
        }
        let needs_length =
            !req.body.is_empty() || matches!(req.method.as_str(), "POST" | "PUT" | "PATCH");
        if needs_length && !has(&req.headers, "content-length") {
            fields.push(("content-length".into(), req.body.len().to_string()));
        }
        self.conn.open(id);
        let end = req.body.is_empty();
        self.conn.send_headers(
            id,
            fields.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            end,
            cx,
        );
        if !end {
            self.conn.send_body(id, Arc::from(req.body.as_slice()), cx);
        }
        self.inflight.insert(id, (i, cx.now(), 0));
    }

    fn answer(&mut self, id: u32, cx: &mut AppCx) {
        let Some((i, at, status)) = self.inflight.remove(&id) else {
            return;
        };
        let req = &self.cfg.http.client.requests[i];
        let mut t = AppTransaction::new(status.to_string(), true)
            .with_error(status >= 400)
            .with_response_time(cx.now().saturating_sub(at))
            .with_name(req.label());
        if let Err(why) = req.judge(status, &[], 0, None) {
            t = t.failed_because(why);
        }
        cx.transaction(t);
        self.answered += 1;
        let think = self.cfg.http.client.think_time;
        if !think.is_zero() {
            self.gate = Some(cx.now() + think);
        }
    }

    fn fail(&mut self, cx: &mut AppCx, code: u32, what: String) {
        cx.protocol_error(what);
        self.conn.goaway(code, cx);
        self.stop = true;
        self.done = true;
        cx.close();
    }

    fn take(&mut self, events: Vec<Ev>, cx: &mut AppCx) {
        for e in events {
            match e {
                Ev::Head { id, fields, end } => {
                    let Some(entry) = self.inflight.get_mut(&id) else {
                        continue;
                    };
                    if entry.2 == 0 || (100..200).contains(&entry.2) {
                        let Some(status) = field(&fields, ":status").and_then(|s| s.parse().ok())
                        else {
                            self.fail(cx, PROTOCOL_ERROR, "a response without :status".into());
                            return;
                        };
                        entry.2 = status;
                    }
                    if end {
                        self.answer(id, cx);
                    }
                }
                Ev::Data { id, end, .. } => {
                    if end {
                        self.answer(id, cx);
                    }
                }
                Ev::Reset { id, code } if code == REFUSED_STREAM => {
                    // Not handled at all: ask again once there is room.
                    if let Some((i, _, _)) = self.inflight.remove(&id) {
                        self.retry.push_back(i);
                    }
                }
                Ev::Reset { id, code } => {
                    if self.inflight.remove(&id).is_some() {
                        cx.transaction(
                            AppTransaction::new(format!("reset {}", error_name(code)), false)
                                .with_error(true),
                        );
                        self.answered += 1;
                    }
                }
                Ev::GoAway { last, code } => {
                    self.stop = true;
                    if code != NO_ERROR {
                        cx.protocol_error(format!("GOAWAY {}", error_name(code)));
                    }
                    self.inflight.retain(|&id, _| id <= last);
                }
            }
        }
        self.after(cx);
    }

    fn after(&mut self, cx: &mut AppCx) {
        let per = self.cfg.http.client.per_connection;
        if self.answered >= per || (self.stop && self.inflight.is_empty()) {
            if self.answered < per {
                cx.protocol_error(format!(
                    "the server stopped after {} of {per} requests",
                    self.answered
                ));
            }
            // GOAWAY, then let the server close first: a server that
            // closes on GOAWAY (nghttpd) would otherwise reset the
            // connection over bytes it never read (our FIN, TLS
            // close_notify). Close ourselves if it does not.
            self.conn.goaway(NO_ERROR, cx);
            self.done = true;
            cx.wake_at(cx.now() + LINGER);
        } else {
            self.fill(cx);
        }
    }
}

/// How long a client that is done waits for the server to close after its
/// GOAWAY.
const LINGER: Duration = Duration::from_millis(200);

impl AppSession for ClientSession {
    fn start(&mut self, cx: &mut AppCx) {
        cx.send(PREFACE);
        self.conn.hello(cx);
        self.fill(cx);
    }

    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        if self.done {
            return Receive::Taken;
        }
        match self.conn.feed(data, cx) {
            Ok(events) => self.take(events, cx),
            Err((code, what)) => self.fail(cx, code, what),
        }
        Receive::Taken
    }

    fn peer_closed(&mut self, cx: &mut AppCx) {
        if !self.done {
            self.done = true;
            cx.protocol_error(format!(
                "the server closed after {} of {} requests",
                self.answered, self.cfg.http.client.per_connection
            ));
        }
        cx.close();
    }

    fn timer(&mut self, cx: &mut AppCx) {
        if self.done {
            cx.close(); // the server did not close after our GOAWAY
        } else {
            self.fill(cx);
        }
    }
}

// ----- server -----

enum ServerState {
    /// Not sure yet: HTTP/2 if the bytes so far start the preface.
    Preface(Vec<u8>),
    H2(Box<H2Server>),
    /// A client that speaks HTTP/1.1.
    H1(Box<dyn AppSession>),
}

struct ServerSession {
    state: ServerState,
    init: SessionInit,
    cfg: Arc<Http2>,
}

struct H2Server {
    cfg: Arc<Http2>,
    conn: Conn,
    /// Requests being read: method and path.
    requests: BTreeMap<u32, (Option<String>, Option<String>)>,
    /// Answers waiting for their route's delay: when, stream, route, HEAD.
    queue: Vec<(Duration, u32, HttpRoute, bool)>,
    /// Close once the answers are out (a route said so).
    closing: bool,
    /// The client sent GOAWAY: no GOAWAY back.
    peer_goaway: bool,
    peer_done: bool,
    done: bool,
}

impl H2Server {
    fn fail(&mut self, cx: &mut AppCx, code: u32, what: String) {
        cx.protocol_error(what);
        self.conn.goaway(code, cx);
        self.done = true;
        cx.close();
    }

    fn request(&mut self, id: u32, cx: &mut AppCx) {
        let Some((method, path)) = self.requests.remove(&id) else {
            return;
        };
        let (Some(method), Some(path)) = (method, path) else {
            cx.protocol_error("a request without :method or :path");
            self.conn.reset(id, PROTOCOL_ERROR, cx);
            return;
        };
        let route = self.cfg.http.server.route(&method, &path).into_owned();
        cx.transaction(
            AppTransaction::new(route.status.to_string(), true).with_error(route.status >= 400),
        );
        self.queue
            .push((cx.now() + route.delay, id, route, method == "HEAD"));
    }

    fn flush(&mut self, cx: &mut AppCx) {
        let now = cx.now();
        let mut due = Vec::new();
        self.queue.retain(|q| {
            if q.0 <= now {
                due.push((q.1, q.2.clone(), q.3));
                false
            } else {
                true
            }
        });
        for (id, route, head) in due {
            if !self.conn.streams.contains_key(&id) {
                continue; // reset meanwhile
            }
            let server = &self.cfg.http.server.server;
            let mut fields: Vec<(String, String)> =
                vec![(":status".into(), route.status.to_string())];
            if !server.is_empty() && !has(&route.headers, "server") {
                fields.push(("server".into(), server.clone()));
            }
            for (k, v) in &route.headers {
                let k = k.to_ascii_lowercase();
                if !connection_specific(&k) && k != "content-length" {
                    fields.push((k, v.clone()));
                }
            }
            let bodiless = route.status < 200 || route.status == 204 || route.status == 304;
            if !bodiless {
                fields.push(("content-length".into(), route.body.len().to_string()));
            }
            let end = head || bodiless || route.body.is_empty();
            self.conn.send_headers(
                id,
                fields.iter().map(|(k, v)| (k.as_str(), v.as_str())),
                end,
                cx,
            );
            if !end {
                self.conn.send_body(id, route.body.clone(), cx);
            }
            if route.close {
                self.closing = true;
            }
        }
        if let Some(next) = self.queue.iter().map(|q| q.0).min() {
            cx.wake_at(next);
        }
        let drained = self.queue.is_empty() && (self.peer_done || !self.conn.pending());
        if (self.closing || self.peer_done) && drained && !self.done {
            if !self.peer_done && !self.peer_goaway {
                self.conn.goaway(NO_ERROR, cx);
            }
            self.done = true;
            cx.close();
        }
    }

    fn take(&mut self, events: Vec<Ev>, cx: &mut AppCx) {
        for e in events {
            match e {
                Ev::Head { id, fields, end } => {
                    let new = !self.requests.contains_key(&id);
                    if new && self.closing {
                        self.conn.reset(id, REFUSED_STREAM, cx);
                        continue;
                    }
                    if new && self.conn.active() > self.cfg.settings.max_concurrent_streams as usize
                    {
                        self.conn.reset(id, REFUSED_STREAM, cx);
                        continue;
                    }
                    let r = self.requests.entry(id).or_default();
                    if new {
                        r.0 = field(&fields, ":method").map(str::to_string);
                        r.1 = field(&fields, ":path").map(str::to_string);
                    }
                    if end {
                        self.request(id, cx);
                    }
                }
                Ev::Data { id, end, .. } => {
                    if end {
                        self.request(id, cx);
                    }
                }
                Ev::Reset { id, .. } => {
                    self.requests.remove(&id);
                    self.queue.retain(|q| q.1 != id);
                }
                Ev::GoAway { code, .. } => {
                    if code != NO_ERROR {
                        cx.protocol_error(format!("GOAWAY {}", error_name(code)));
                    }
                    // The client is done, but it closes: closing here
                    // too would race its close_notify and FIN, and the
                    // kernel would answer what we had not read with a RST.
                    self.peer_goaway = true;
                }
            }
        }
        self.flush(cx);
    }

    fn receive(&mut self, data: &[u8], cx: &mut AppCx) {
        if self.done {
            return;
        }
        match self.conn.feed(data, cx) {
            Ok(events) => self.take(events, cx),
            Err((code, what)) => self.fail(cx, code, what),
        }
    }
}

impl ServerSession {
    fn h2(&self) -> H2Server {
        H2Server {
            cfg: self.cfg.clone(),
            conn: Conn::new(false, &self.cfg.settings),
            requests: BTreeMap::new(),
            queue: Vec::new(),
            closing: false,
            peer_goaway: false,
            peer_done: false,
            done: false,
        }
    }
}

impl AppSession for ServerSession {
    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        match &mut self.state {
            ServerState::Preface(buf) => {
                buf.extend_from_slice(data);
                let n = buf.len().min(PREFACE.len());
                if buf[..n] != PREFACE[..n] {
                    // Not HTTP/2: the HTTP/1.1 server takes it.
                    let mut s = self.cfg.http.session(&self.init);
                    let bytes = std::mem::take(buf);
                    s.start(cx);
                    let r = s.receive(&bytes, cx);
                    self.state = ServerState::H1(s);
                    return r;
                }
                if buf.len() < PREFACE.len() {
                    return Receive::Taken;
                }
                let rest = buf.split_off(PREFACE.len());
                let mut h = self.h2();
                h.conn.hello(cx);
                h.receive(&rest, cx);
                self.state = ServerState::H2(Box::new(h));
            }
            ServerState::H2(h) => h.receive(data, cx),
            ServerState::H1(s) => return s.receive(data, cx),
        }
        Receive::Taken
    }

    fn peer_closed(&mut self, cx: &mut AppCx) {
        match &mut self.state {
            ServerState::Preface(buf) => {
                if !buf.is_empty() {
                    cx.protocol_error("the client closed in the HTTP/2 preface");
                }
                cx.close();
            }
            ServerState::H2(h) => {
                h.peer_done = true;
                h.flush(cx);
            }
            ServerState::H1(s) => s.peer_closed(cx),
        }
    }

    fn timer(&mut self, cx: &mut AppCx) {
        match &mut self.state {
            ServerState::Preface(_) => {}
            ServerState::H2(h) => h.flush(cx),
            ServerState::H1(s) => s.timer(cx),
        }
    }
}

// ----- profiles -----

/// The keys of an `[http2]` table that are HTTP/2's own; the rest are
/// `[http]` keys.
#[cfg(feature = "profile")]
const OWN_KEYS: &[&str] = &[
    "concurrent",
    "max_concurrent_streams",
    "window",
    "frame_size",
    "header_table_size",
    "huffman",
    "scheme",
];

/// Reads an `[http2]` table: the keys of `[http]` (requests, routes,
/// `per_connection`, `host`, ...) and HTTP/2's own.
#[cfg(feature = "profile")]
pub fn parse(t: &toml::Table, base: &std::path::Path) -> Result<Http2> {
    let mut rest = t.clone();
    if rest.contains_key("pipeline") {
        return Err(Error::Profile(
            "`pipeline` is HTTP/1.1's; HTTP/2 sends requests at once up to `concurrent`".into(),
        ));
    }
    let mut own = toml::Table::new();
    for k in OWN_KEYS {
        if let Some(v) = rest.remove(*k) {
            own.insert((*k).to_string(), v);
        }
    }
    let http = super::http::parse(&rest, base)
        .map_err(|e| Error::Profile(e.to_string().trim_start_matches("profile: ").to_string()))?;
    super::http::status_checks_only(&http, "HTTP/2")?;
    let mut s = Http2Settings::default();
    let num = |k: &str| -> Result<Option<u32>> {
        match own.get(k) {
            None => Ok(None),
            Some(toml::Value::Integer(n)) => u32::try_from(*n)
                .map(Some)
                .map_err(|_| Error::Profile(format!("`{k}` {n} is out of range"))),
            Some(_) => Err(Error::Profile(format!("`{k}` must be a number"))),
        }
    };
    if let Some(n) = num("concurrent")? {
        s.concurrent = n;
    }
    if let Some(n) = num("max_concurrent_streams")? {
        s.max_concurrent_streams = n;
    }
    if let Some(n) = num("window")? {
        s.window = n;
    }
    if let Some(n) = num("frame_size")? {
        s.frame_size = n;
    }
    if let Some(n) = num("header_table_size")? {
        s.header_table_size = n;
    }
    match own.get("huffman") {
        None => {}
        Some(toml::Value::Boolean(b)) => s.huffman = *b,
        Some(_) => return Err(Error::Profile("`huffman` must be true or false".into())),
    }
    match own.get("scheme") {
        None => {}
        Some(toml::Value::String(v)) => s.scheme = v.clone(),
        Some(_) => return Err(Error::Profile("`scheme` must be a string".into())),
    }
    let h2 = Http2 { http, settings: s };
    h2.validate_settings()?;
    Ok(h2)
}

#[cfg(test)]
mod tests {
    use super::super::http::HttpRequest;
    use super::*;

    fn init(role: AppRole, index: u64) -> SessionInit {
        SessionInit {
            role,
            transport: Transport::Stream,
            index,
            seed: 1,
            local: "10.0.0.1:40000".parse().unwrap(),
            remote: "10.0.0.2:80".parse().unwrap(),
        }
    }

    /// Runs a client and a server session against each other, handing bytes
    /// over in pieces of `piece`; returns both ends' contexts merged.
    fn run(h2: &Http2, index: u64, piece: usize) -> (AppCx, AppCx) {
        let mut c = h2.session(&init(AppRole::Client, index));
        let mut s = h2.session(&init(AppRole::Server, 0));
        let (mut call, mut sall) = (
            AppCx::new(Duration::ZERO, Duration::ZERO),
            AppCx::new(Duration::ZERO, Duration::ZERO),
        );
        let mut now = Duration::ZERO;
        let mut cx = AppCx::new(now, now);
        c.start(&mut cx);
        let mut to_server: Vec<u8> = cx.take_sends().concat();
        let mut c_wake = cx.wake();
        let mut c_closed = cx.wants_close();
        call.absorb(cx);
        let mut to_client: Vec<u8> = Vec::new();
        let (mut s_wake, mut s_closed) = (None, false);
        for _ in 0..10_000_000 {
            if to_server.is_empty() && to_client.is_empty() {
                let next = [c_wake, s_wake].into_iter().flatten().min();
                match next {
                    Some(t) => now = now.max(t),
                    None => break,
                }
                if c_wake.is_some_and(|t| t <= now) {
                    c_wake = None;
                    let mut cx = AppCx::new(now, now);
                    c.timer(&mut cx);
                    to_server.extend(cx.take_sends().concat());
                    c_wake = cx.wake().or(c_wake);
                    c_closed |= cx.wants_close();
                    call.absorb(cx);
                }
                if s_wake.is_some_and(|t| t <= now) {
                    s_wake = None;
                    let mut cx = AppCx::new(now, now);
                    s.timer(&mut cx);
                    to_client.extend(cx.take_sends().concat());
                    s_wake = cx.wake().or(s_wake);
                    s_closed |= cx.wants_close();
                    sall.absorb(cx);
                }
                continue;
            }
            if !to_server.is_empty() {
                let n = piece.min(to_server.len());
                let d: Vec<u8> = to_server.drain(..n).collect();
                let mut cx = AppCx::new(now, now);
                s.receive(&d, &mut cx);
                to_client.extend(cx.take_sends().concat());
                if cx.wake().is_some() {
                    s_wake = cx.wake();
                }
                s_closed |= cx.wants_close();
                sall.absorb(cx);
            }
            if !to_client.is_empty() {
                let n = piece.min(to_client.len());
                let d: Vec<u8> = to_client.drain(..n).collect();
                let mut cx = AppCx::new(now, now);
                c.receive(&d, &mut cx);
                to_server.extend(cx.take_sends().concat());
                if cx.wake().is_some() {
                    c_wake = cx.wake();
                }
                c_closed |= cx.wants_close();
                call.absorb(cx);
            }
            if s_closed && !c_closed && to_client.is_empty() {
                let mut cx = AppCx::new(now, now);
                c.peer_closed(&mut cx);
                c_closed |= cx.wants_close();
                call.absorb(cx);
                to_server.clear(); // the server is gone
            }
            if c_closed && !s_closed && to_server.is_empty() {
                let mut cx = AppCx::new(now, now);
                s.peer_closed(&mut cx);
                s_closed |= cx.wants_close();
                to_client.extend(cx.take_sends().concat());
                sall.absorb(cx);
                to_client.clear(); // the client is gone
            }
        }
        assert!(c_closed, "the client did not finish");
        (call, sall)
    }

    fn labels(cx: &AppCx) -> Vec<String> {
        cx.transactions().iter().map(|t| t.label.clone()).collect()
    }

    fn sample() -> Http2 {
        let mut h2 = Http2::default();
        h2.http.client.requests = vec![
            HttpRequest::get("/"),
            HttpRequest::get("/missing").expect("404"),
            HttpRequest::new("POST", "/upload").with_body(vec![7u8; 100_000]),
        ];
        h2.http.client.per_connection = 6;
        h2.http.server.routes = vec![
            HttpRoute::new("/", 200).with_body(vec![b'x'; 200_000]),
            HttpRoute::new("/upload", 201),
        ];
        h2
    }

    #[test]
    fn requests_multiplex_with_flow_control_in_any_pieces() {
        for piece in [1, 7, 100, 1 << 20] {
            let (c, s) = run(&sample(), 0, piece);
            assert!(
                c.protocol_errors().is_empty(),
                "{piece}: {:?}",
                c.protocol_errors()
            );
            assert!(
                s.protocol_errors().is_empty(),
                "{piece}: {:?}",
                s.protocol_errors()
            );
            let mut l = labels(&c);
            l.sort();
            assert_eq!(l, ["200", "200", "201", "201", "404", "404"], "{piece}");
            assert!(c.all_ok());
            assert_eq!(labels(&s).len(), 6);
        }
    }

    #[test]
    fn settings_limit_streams_and_frames() {
        let mut h2 = sample();
        h2.settings.concurrent = 2;
        h2.settings.window = 1_000_000;
        h2.settings.frame_size = 65_536;
        h2.settings.header_table_size = 0;
        h2.settings.huffman = false;
        let (c, s) = run(&h2, 1, 1000);
        assert!(c.all_ok(), "{:?}", c.protocol_errors());
        assert_eq!(labels(&s).len(), 6);
        // The server allows one stream: the client keeps to it.
        h2.settings.concurrent = 10;
        h2.settings.max_concurrent_streams = 1;
        let (c, s) = run(&h2, 0, 1 << 20);
        assert!(c.all_ok(), "{:?} {:?}", c.protocol_errors(), labels(&c));
        // What it sent before it knew was refused and sent again.
        assert_eq!(labels(&c).len(), 6);
        assert_eq!(labels(&s).len(), 6);
    }

    #[test]
    fn think_time_and_delays() {
        let mut h2 = sample();
        h2.http.client.think_time = Duration::from_millis(50);
        h2.http.server.routes[0].delay = Duration::from_millis(20);
        let (c, _) = run(&h2, 0, 1 << 20);
        assert!(c.all_ok());
        let rt: Vec<_> = c
            .transactions()
            .iter()
            .filter(|t| t.label == "200")
            .map(|t| t.response_time.unwrap())
            .collect();
        assert!(rt.iter().all(|t| *t >= Duration::from_millis(20)), "{rt:?}");
    }

    #[test]
    fn route_close_sends_goaway() {
        let mut h2 = sample();
        h2.http.server.routes[0].close = true;
        h2.settings.concurrent = 1;
        let (c, _) = run(&h2, 0, 1 << 20);
        // The first request's answer closes: the rest are not answered.
        assert_eq!(labels(&c), ["200"]);
        assert!(
            c.protocol_errors()[0].contains("stopped after 1 of 6"),
            "{:?}",
            c.protocol_errors()
        );
    }

    #[test]
    fn the_server_takes_http1_too() {
        let h2 = sample();
        let mut s = h2.session(&init(AppRole::Server, 0));
        let mut cx = AppCx::new(Duration::ZERO, Duration::ZERO);
        s.receive(b"GET /missing HTTP/1.1\r\nHost: x\r\n\r\n", &mut cx);
        let out = cx.take_sends().concat();
        assert!(
            out.starts_with(b"HTTP/1.1 404"),
            "{}",
            String::from_utf8_lossy(&out)
        );
    }

    #[test]
    fn bad_peers_get_goaway() {
        let h2 = sample();
        // A preface and then no SETTINGS.
        let mut s = h2.session(&init(AppRole::Server, 0));
        let mut cx = AppCx::new(Duration::ZERO, Duration::ZERO);
        let mut b = PREFACE.to_vec();
        b.extend(frame(PING, 0, 0, &[0; 8]));
        s.receive(&b, &mut cx);
        assert!(cx.wants_close());
        assert!(cx.protocol_errors()[0].contains("not SETTINGS"));
        let out = cx.take_sends().concat();
        // SETTINGS first, then GOAWAY PROTOCOL_ERROR.
        assert_eq!(out[3], SETTINGS);
        let tail = &out[out.len() - 17..];
        assert_eq!(tail[3], GOAWAY);
        assert_eq!(u32_at(tail, 13), PROTOCOL_ERROR);

        // A frame larger than allowed.
        let mut s = h2.session(&init(AppRole::Server, 0));
        let mut cx = AppCx::new(Duration::ZERO, Duration::ZERO);
        let mut b = PREFACE.to_vec();
        b.extend(frame(SETTINGS, 0, 0, &[]));
        b.extend(frame(DATA, 0, 1, &vec![0; 20_000]));
        s.receive(&b, &mut cx);
        assert!(
            cx.protocol_errors()[0].contains("over the 16384"),
            "{:?}",
            cx.protocol_errors()
        );

        // Push from a server, to a client that turned it off.
        let mut c = h2.session(&init(AppRole::Client, 0));
        let mut cx = AppCx::new(Duration::ZERO, Duration::ZERO);
        c.start(&mut cx);
        let mut b = frame(SETTINGS, 0, 0, &[]);
        b.extend(frame(PUSH_PROMISE, END_HEADERS, 1, &[0, 0, 0, 2]));
        let mut cx = AppCx::new(Duration::ZERO, Duration::ZERO);
        c.receive(&b, &mut cx);
        assert!(cx.protocol_errors()[0].contains("PUSH_PROMISE"));
        assert!(cx.wants_close());
    }

    #[test]
    fn resets_count_as_failed() {
        let h2 = sample();
        let mut c = h2.session(&init(AppRole::Client, 0));
        let mut cx = AppCx::new(Duration::ZERO, Duration::ZERO);
        c.start(&mut cx);
        let mut b = frame(SETTINGS, 0, 0, &[]);
        b.extend(frame(RST_STREAM, 0, 1, &8u32.to_be_bytes()));
        let mut cx = AppCx::new(Duration::ZERO, Duration::ZERO);
        c.receive(&b, &mut cx);
        assert_eq!(cx.transactions()[0].label, "reset CANCEL");
        assert!(!cx.all_ok());
    }

    #[cfg(feature = "profile")]
    #[test]
    fn tables() {
        let t: toml::Table = r#"
            requests = ["GET /", "GET /x 404"]
            per_connection = 8
            concurrent = 4
            window = 1048576
            frame_size = 32768
            huffman = false
            [[route]]
            path = "/"
            body = "hi"
        "#
        .parse()
        .unwrap();
        let h2 = parse(&t, std::path::Path::new(".")).unwrap();
        assert_eq!(h2.http.client.per_connection, 8);
        assert_eq!(h2.settings.concurrent, 4);
        assert_eq!(h2.settings.window, 1 << 20);
        assert!(!h2.settings.huffman);
        assert_eq!(h2.http.server.routes.len(), 1);
        let bad: toml::Table = "pipeline = true".parse().unwrap();
        assert!(parse(&bad, std::path::Path::new(".")).is_err());
        let bad: toml::Table = "frame_size = 100".parse().unwrap();
        assert!(parse(&bad, std::path::Path::new(".")).is_err());
        let bad: toml::Table = "nonsense = 1".parse().unwrap();
        assert!(parse(&bad, std::path::Path::new(".")).is_err());
    }
}
