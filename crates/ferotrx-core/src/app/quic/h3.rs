//! HTTP/3 (RFC 9114) on a [`Conn`]: the control streams with SETTINGS,
//! the QPACK streams (which carry nothing: no dynamic table), requests on
//! bidirectional streams as HEADERS and DATA frames, GOAWAY.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use super::conn::{Conn, Event};
use super::frame::{put_varint, Reader};
use super::qpack;
use super::Http3;
use crate::app::http::HttpRoute;
use crate::app::{AppCx, AppTransaction};

// Frame types.
pub const DATA: u64 = 0x0;
pub const HEADERS: u64 = 0x1;
pub const CANCEL_PUSH: u64 = 0x3;
pub const SETTINGS: u64 = 0x4;
pub const PUSH_PROMISE: u64 = 0x5;
pub const GOAWAY: u64 = 0x7;
pub const MAX_PUSH_ID: u64 = 0xd;

// Unidirectional stream types.
const CONTROL: u64 = 0x0;
const PUSH: u64 = 0x1;
const ENCODER: u64 = 0x2;
const DECODER: u64 = 0x3;

// Settings.
const QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
const MAX_FIELD_SECTION_SIZE: u64 = 0x6;
const QPACK_BLOCKED_STREAMS: u64 = 0x7;

/// HTTP/3 error codes.
pub mod code {
    pub const NO_ERROR: u64 = 0x100;
    pub const GENERAL_PROTOCOL_ERROR: u64 = 0x101;
    pub const INTERNAL_ERROR: u64 = 0x102;
    pub const STREAM_CREATION_ERROR: u64 = 0x103;
    pub const CLOSED_CRITICAL_STREAM: u64 = 0x104;
    pub const FRAME_UNEXPECTED: u64 = 0x105;
    pub const FRAME_ERROR: u64 = 0x106;
    pub const ID_ERROR: u64 = 0x108;
    pub const SETTINGS_ERROR: u64 = 0x109;
    pub const MISSING_SETTINGS: u64 = 0x10a;
    pub const REQUEST_REJECTED: u64 = 0x10b;
    pub const REQUEST_CANCELLED: u64 = 0x10c;
    pub const MESSAGE_ERROR: u64 = 0x10e;
    pub const DECOMPRESSION_FAILED: u64 = 0x200;
}

/// The name of an HTTP/3 (or QPACK) error code.
pub fn error_name(c: u64) -> String {
    match c {
        0x100 => "H3_NO_ERROR".into(),
        0x101 => "H3_GENERAL_PROTOCOL_ERROR".into(),
        0x102 => "H3_INTERNAL_ERROR".into(),
        0x103 => "H3_STREAM_CREATION_ERROR".into(),
        0x104 => "H3_CLOSED_CRITICAL_STREAM".into(),
        0x105 => "H3_FRAME_UNEXPECTED".into(),
        0x106 => "H3_FRAME_ERROR".into(),
        0x107 => "H3_EXCESSIVE_LOAD".into(),
        0x108 => "H3_ID_ERROR".into(),
        0x109 => "H3_SETTINGS_ERROR".into(),
        0x10a => "H3_MISSING_SETTINGS".into(),
        0x10b => "H3_REQUEST_REJECTED".into(),
        0x10c => "H3_REQUEST_CANCELLED".into(),
        0x10d => "H3_REQUEST_INCOMPLETE".into(),
        0x10e => "H3_MESSAGE_ERROR".into(),
        0x10f => "H3_CONNECT_ERROR".into(),
        0x110 => "H3_VERSION_FALLBACK".into(),
        0x200 => "QPACK_DECOMPRESSION_FAILED".into(),
        0x201 => "QPACK_ENCODER_STREAM_ERROR".into(),
        0x202 => "QPACK_DECODER_STREAM_ERROR".into(),
        c => format!("error 0x{c:x}"),
    }
}

/// Appends a frame.
pub fn frame(out: &mut Vec<u8>, ty: u64, payload: &[u8]) {
    put_varint(out, ty);
    put_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/// One frame from the front of `buf`, if it is all there: (type, payload,
/// length taken).
/// A frame's type, payload and length in all.
type Taken<'a> = (u64, &'a [u8], usize);

fn take_frame(buf: &[u8]) -> Result<Option<Taken<'_>>, ()> {
    let mut r = Reader::new(buf);
    let Some(ty) = r.varint() else {
        return Ok(None);
    };
    let Some(len) = r.varint() else {
        return Ok(None);
    };
    if len > 1 << 24 && ty != DATA {
        return Err(());
    }
    let at = r.pos();
    if (buf.len() - at) < len as usize {
        return Ok(None);
    }
    Ok(Some((ty, &buf[at..at + len as usize], at + len as usize)))
}

/// A connection error: the code and why.
pub type H3Error = (u64, String);

/// Request (or response) stream state, as frames arrive.
#[derive(Default)]
struct Message {
    buf: Vec<u8>,
    fields: Option<Vec<(String, String)>>,
    body: u64,
    trailers: bool,
    fin: bool,
}

impl Message {
    /// Takes the frames in `buf`; Err is a connection error.
    fn frames(&mut self, interim: impl Fn(&[(String, String)]) -> bool) -> Result<(), H3Error> {
        loop {
            let (ty, payload, n) = match take_frame(&self.buf) {
                Ok(Some(f)) => f,
                Ok(None) => return Ok(()),
                Err(()) => return Err((code::FRAME_ERROR, "a frame too long".into())),
            };
            match ty {
                HEADERS => {
                    let f = qpack::decode(payload).map_err(|e| (code::DECOMPRESSION_FAILED, e))?;
                    if self.fields.is_none() {
                        if !interim(&f) {
                            self.fields = Some(f);
                        }
                    } else if !self.trailers {
                        self.trailers = true;
                    } else {
                        return Err((code::FRAME_UNEXPECTED, "HEADERS after trailers".into()));
                    }
                }
                DATA => {
                    if self.fields.is_none() || self.trailers {
                        return Err((code::FRAME_UNEXPECTED, "DATA outside a message".into()));
                    }
                    self.body += payload.len() as u64;
                }
                CANCEL_PUSH | SETTINGS | GOAWAY | MAX_PUSH_ID | 0x2 | 0x6 | 0x8 | 0x9 => {
                    return Err((
                        code::FRAME_UNEXPECTED,
                        format!("frame 0x{ty:x} on a request stream"),
                    ))
                }
                PUSH_PROMISE => {
                    return Err((code::ID_ERROR, "a push we never allowed".into()));
                }
                _ => {} // unknown and reserved frames
            }
            self.buf.drain(..n);
        }
    }
}

fn field<'a>(f: &'a [(String, String)], name: &str) -> Option<&'a str> {
    f.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn connection_specific(name: &str) -> bool {
    matches!(
        name,
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade" | "te"
    )
}

/// The peer's unidirectional streams: their type once read.
#[derive(Default)]
struct UniStreams {
    kinds: BTreeMap<u64, Option<u64>>,
    bufs: BTreeMap<u64, Vec<u8>>,
    control: Option<u64>,
    encoder: Option<u64>,
    decoder: Option<u64>,
    settings: bool,
}

/// What both ends of HTTP/3 share: our control streams and the peer's.
pub struct H3Common {
    uni: UniStreams,
    opened: bool,
    control: Option<u64>,
    /// The other end's GOAWAY (a stream or push id).
    pub goaway: Option<u64>,
    huffman: bool,
}

impl H3Common {
    pub fn new(huffman: bool) -> Self {
        Self {
            uni: UniStreams::default(),
            opened: false,
            control: None,
            goaway: None,
            huffman,
        }
    }

    /// Opens our control stream with SETTINGS and the two QPACK streams.
    pub fn open(&mut self, conn: &mut Conn) {
        if self.opened {
            return;
        }
        self.opened = true;
        if let Some(id) = conn.open(false) {
            let mut b = Vec::new();
            put_varint(&mut b, CONTROL);
            let mut s = Vec::new();
            for (k, v) in [
                (QPACK_MAX_TABLE_CAPACITY, 0),
                (QPACK_BLOCKED_STREAMS, 0),
                (MAX_FIELD_SECTION_SIZE, 1 << 16),
                // A reserved setting, which the other end must ignore.
                (0x1f * 7 + 0x21, 0),
            ] {
                put_varint(&mut s, k);
                put_varint(&mut s, v);
            }
            frame(&mut b, SETTINGS, &s);
            conn.write(id, &b, false);
            self.control = Some(id);
        }
        for ty in [ENCODER, DECODER] {
            if let Some(id) = conn.open(false) {
                let mut b = Vec::new();
                put_varint(&mut b, ty);
                conn.write(id, &b, false);
            }
        }
    }

    /// Sends GOAWAY on our control stream.
    pub fn send_goaway(&mut self, conn: &mut Conn, id: u64) {
        if let Some(c) = self.control {
            let mut p = Vec::new();
            put_varint(&mut p, id);
            let mut b = Vec::new();
            frame(&mut b, GOAWAY, &p);
            conn.write(c, &b, false);
        }
    }

    pub fn encode(&self, fields: &[(String, String)]) -> Vec<u8> {
        qpack::encode(
            fields.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            self.huffman,
        )
    }

    /// Data on a unidirectional stream of the other end's.
    pub fn uni(&mut self, conn: &mut Conn, id: u64) -> Result<(), H3Error> {
        let (d, fin) = conn.read(id);
        let kind = self.uni.kinds.entry(id).or_insert(None);
        let buf = self.uni.bufs.entry(id).or_default();
        buf.extend_from_slice(&d);
        if kind.is_none() {
            let mut r = Reader::new(buf);
            let Some(ty) = r.varint() else {
                return Ok(());
            };
            let n = r.pos();
            buf.drain(..n);
            *kind = Some(ty);
            let slot = match ty {
                CONTROL => Some(&mut self.uni.control),
                ENCODER => Some(&mut self.uni.encoder),
                DECODER => Some(&mut self.uni.decoder),
                PUSH => {
                    return Err((
                        code::STREAM_CREATION_ERROR,
                        "a push stream we never allowed".into(),
                    ))
                }
                _ => None,
            };
            if let Some(slot) = slot {
                if slot.is_some() {
                    return Err((
                        code::STREAM_CREATION_ERROR,
                        format!("a second stream of type 0x{ty:x}"),
                    ));
                }
                *slot = Some(id);
            } else {
                // Unknown (grease): not read.
                conn.stop_sending(id, code::STREAM_CREATION_ERROR);
                self.uni.bufs.remove(&id);
                return Ok(());
            }
        }
        let kind = self.uni.kinds[&id];
        match kind {
            Some(CONTROL) => {
                if fin {
                    return Err((
                        code::CLOSED_CRITICAL_STREAM,
                        "the control stream ended".into(),
                    ));
                }
                let buf = self.uni.bufs.get_mut(&id).unwrap();
                let mut taken = 0;
                let mut out = Vec::new();
                loop {
                    let (ty, payload, n) = match take_frame(&buf[taken..]) {
                        Ok(Some(f)) => f,
                        Ok(None) => break,
                        Err(()) => return Err((code::FRAME_ERROR, "a frame too long".into())),
                    };
                    out.push((ty, payload.to_vec()));
                    taken += n;
                }
                buf.drain(..taken);
                for (ty, payload) in out {
                    self.control_frame(ty, &payload)?;
                }
            }
            Some(ENCODER) | Some(DECODER) => {
                if fin {
                    return Err((code::CLOSED_CRITICAL_STREAM, "a QPACK stream ended".into()));
                }
                let buf = self.uni.bufs.get_mut(&id).unwrap();
                if kind == Some(ENCODER) && !buf.is_empty() {
                    // With capacity 0 the encoder may only set it to 0.
                    let ok = buf.iter().all(|&b| b == 0x20);
                    if !ok {
                        return Err((0x201, "instructions for a dynamic table".into()));
                    }
                }
                buf.clear();
            }
            _ => {}
        }
        Ok(())
    }

    fn control_frame(&mut self, ty: u64, payload: &[u8]) -> Result<(), H3Error> {
        if !self.uni.settings && ty != SETTINGS {
            return Err((
                code::MISSING_SETTINGS,
                "the control stream starts without SETTINGS".into(),
            ));
        }
        match ty {
            SETTINGS => {
                if self.uni.settings {
                    return Err((code::FRAME_UNEXPECTED, "SETTINGS twice".into()));
                }
                self.uni.settings = true;
                let mut r = Reader::new(payload);
                let mut seen = std::collections::BTreeSet::new();
                while !r.is_empty() {
                    let (Some(k), Some(_v)) = (r.varint(), r.varint()) else {
                        return Err((code::FRAME_ERROR, "a truncated setting".into()));
                    };
                    if !seen.insert(k) {
                        return Err((code::SETTINGS_ERROR, format!("setting 0x{k:x} twice")));
                    }
                    if matches!(k, 0x2..=0x5) {
                        return Err((code::SETTINGS_ERROR, format!("HTTP/2's setting 0x{k:x}")));
                    }
                }
            }
            GOAWAY => {
                let id = Reader::new(payload)
                    .varint()
                    .ok_or((code::FRAME_ERROR, "a truncated GOAWAY".to_string()))?;
                if self.goaway.is_some_and(|g| id > g) {
                    return Err((code::ID_ERROR, "GOAWAY with a larger id".into()));
                }
                self.goaway = Some(id);
            }
            CANCEL_PUSH | MAX_PUSH_ID => {}
            DATA | HEADERS | PUSH_PROMISE | 0x2 | 0x6 | 0x8 | 0x9 => {
                return Err((
                    code::FRAME_UNEXPECTED,
                    format!("frame 0x{ty:x} on the control stream"),
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

/// An HTTP/3 client: sends the configured requests, up to `concurrent` at
/// once, and checks their answers.
pub struct H3Client {
    cfg: Arc<Http3>,
    pub common: H3Common,
    host: String,
    first: u64,
    sent: u32,
    pub answered: u32,
    /// Streams in flight: request index, when it went, the answer so far.
    inflight: BTreeMap<u64, (usize, Duration, Message)>,
    retry: VecDeque<usize>,
    gate: Option<Duration>,
    pub done: bool,
}

impl H3Client {
    pub fn new(cfg: Arc<Http3>, host: String, index: u64) -> Self {
        let per = u64::from(cfg.http.client.per_connection.max(1));
        let huffman = cfg.huffman;
        Self {
            cfg,
            common: H3Common::new(huffman),
            host,
            first: index * per,
            sent: 0,
            answered: 0,
            inflight: BTreeMap::new(),
            retry: VecDeque::new(),
            gate: None,
            done: false,
        }
    }

    pub fn in_flight(&self) -> usize {
        self.inflight.len()
    }

    /// Opens request streams while there is room.
    pub fn fill(&mut self, conn: &mut Conn, cx: &mut AppCx) {
        let cfg = self.cfg.clone();
        let c = &cfg.http.client;
        if self.done || self.common.goaway.is_some() {
            return;
        }
        if let Some(g) = self.gate {
            if g > cx.now() {
                cx.wake_at(g);
                return;
            }
            self.gate = None;
        }
        while (self.sent < c.per_connection || !self.retry.is_empty())
            && self.inflight.len() < cfg.concurrent.max(1) as usize
            && conn.streams_left(true) > 0
        {
            let i = match self.retry.pop_front() {
                Some(i) => i,
                None => {
                    self.sent += 1;
                    ((self.first + u64::from(self.sent - 1)) % c.requests.len() as u64) as usize
                }
            };
            let req = &c.requests[i];
            let Some(id) = conn.open(true) else {
                self.retry.push_front(i);
                break;
            };
            let mut fields: Vec<(String, String)> = vec![
                (":method".into(), req.method.clone()),
                (":scheme".into(), "https".into()),
                (":authority".into(), self.host.clone()),
                (":path".into(), req.path.clone()),
            ];
            let has = |n: &str| req.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
            if !c.user_agent.is_empty() && !has("user-agent") {
                fields.push(("user-agent".into(), c.user_agent.clone()));
            }
            if !has("accept") {
                fields.push(("accept".into(), "*/*".into()));
            }
            for (k, v) in &req.headers {
                let k = k.to_ascii_lowercase();
                if !connection_specific(&k) && k != "host" {
                    fields.push((k, v.clone()));
                }
            }
            let needs_length =
                !req.body.is_empty() || matches!(req.method.as_str(), "POST" | "PUT" | "PATCH");
            if needs_length && !has("content-length") {
                fields.push(("content-length".into(), req.body.len().to_string()));
            }
            let mut b = Vec::new();
            frame(&mut b, HEADERS, &self.common.encode(&fields));
            if !req.body.is_empty() {
                frame(&mut b, DATA, &req.body);
            }
            conn.write(id, &b, true);
            self.inflight.insert(id, (i, cx.now(), Message::default()));
            if !c.think_time.is_zero() {
                break;
            }
        }
    }

    /// Handles a connection event; Err is a connection error.
    pub fn event(&mut self, conn: &mut Conn, e: &Event, cx: &mut AppCx) -> Result<(), H3Error> {
        match *e {
            Event::Connected => {
                self.common.open(conn);
                self.fill(conn, cx);
            }
            Event::StreamsAvailable => self.fill(conn, cx),
            Event::Readable(id) if id & 2 != 0 => {
                self.common.uni(conn, id)?;
                if let Some(g) = self.common.goaway {
                    // Requests from the GOAWAY's id on will not be answered.
                    self.inflight.retain(|&id, _| id < g);
                }
            }
            Event::Readable(id) => {
                let (d, fin) = conn.read(id);
                let Some(entry) = self.inflight.get_mut(&id) else {
                    return Ok(());
                };
                entry.2.buf.extend_from_slice(&d);
                entry.2.fin |= fin;
                entry.2.frames(|f| {
                    field(f, ":status")
                        .and_then(|s| s.parse::<u16>().ok())
                        .is_some_and(|s| (100..200).contains(&s))
                })?;
                if entry.2.fin {
                    let (i, at, m) = self.inflight.remove(&id).unwrap();
                    let status = m
                        .fields
                        .as_ref()
                        .and_then(|f| field(f, ":status"))
                        .and_then(|s| s.parse::<u16>().ok());
                    let req = &self.cfg.http.client.requests[i];
                    match status {
                        Some(s) if m.buf.is_empty() => {
                            let mut t = AppTransaction::new(s.to_string(), true)
                                .with_error(s >= 400)
                                .with_response_time(cx.now().saturating_sub(at))
                                .with_name(req.label());
                            if let Err(why) = req.judge(s, &[], 0, None) {
                                t = t.failed_because(why);
                            }
                            cx.transaction(t)
                        }
                        _ => {
                            cx.transaction(
                                AppTransaction::new("incomplete", false).with_error(true),
                            );
                            cx.protocol_error("a response without :status, or cut short");
                        }
                    }
                    self.answered += 1;
                    let think = self.cfg.http.client.think_time;
                    if !think.is_zero() {
                        self.gate = Some(cx.now() + think);
                    }
                    self.fill(conn, cx);
                }
            }
            Event::Reset { id, code: c } => {
                if let Some((i, _, _)) = self.inflight.remove(&id) {
                    if c == code::REQUEST_REJECTED {
                        self.retry.push_back(i);
                    } else {
                        cx.transaction(
                            AppTransaction::new(format!("reset {}", error_name(c)), false)
                                .with_error(true),
                        );
                        self.answered += 1;
                    }
                    self.fill(conn, cx);
                }
            }
            Event::StopSending { id, .. } => conn.reset(id, code::REQUEST_CANCELLED),
            Event::Closed(_) => {}
        }
        Ok(())
    }

    /// All requests answered, or none can be sent any more.
    pub fn finished(&self) -> bool {
        let per = self.cfg.http.client.per_connection;
        self.answered >= per || (self.common.goaway.is_some() && self.inflight.is_empty())
    }

    /// Requests that will not get an answer now (the connection ended).
    pub fn unanswered(&self) -> u32 {
        self.cfg
            .http
            .client
            .per_connection
            .saturating_sub(self.answered)
    }
}

/// An HTTP/3 server: answers requests from the routes.
pub struct H3Server {
    cfg: Arc<Http3>,
    pub common: H3Common,
    requests: BTreeMap<u64, Message>,
    /// Answers waiting for their route's delay.
    queue: Vec<(Duration, u64, HttpRoute, bool)>,
    /// Streams answered: the highest request stream id seen, for GOAWAY.
    highest: Option<u64>,
    pub closing: bool,
}

impl H3Server {
    pub fn new(cfg: Arc<Http3>) -> Self {
        let huffman = cfg.huffman;
        Self {
            cfg,
            common: H3Common::new(huffman),
            requests: BTreeMap::new(),
            queue: Vec::new(),
            highest: None,
            closing: false,
        }
    }

    /// Answers waiting, or requests being read.
    pub fn busy(&self) -> bool {
        !self.queue.is_empty() || !self.requests.is_empty()
    }

    pub fn event(&mut self, conn: &mut Conn, e: &Event, cx: &mut AppCx) -> Result<(), H3Error> {
        match *e {
            Event::Connected => self.common.open(conn),
            Event::Readable(id) if id & 2 != 0 => self.common.uni(conn, id)?,
            Event::Readable(id) => {
                let (d, fin) = conn.read(id);
                if self.closing && !self.requests.contains_key(&id) {
                    conn.reset(id, code::REQUEST_REJECTED);
                    conn.stop_sending(id, code::REQUEST_REJECTED);
                    return Ok(());
                }
                let m = self.requests.entry(id).or_default();
                m.buf.extend_from_slice(&d);
                m.fin |= fin;
                m.frames(|_| false)?;
                self.highest = Some(self.highest.map_or(id, |h| h.max(id)));
                if m.fin {
                    let m = self.requests.remove(&id).unwrap();
                    if !m.buf.is_empty() || m.fields.is_none() {
                        conn.reset(id, code::MESSAGE_ERROR);
                        cx.protocol_error("a request cut short");
                        return Ok(());
                    }
                    let f = m.fields.unwrap();
                    let (Some(method), Some(path)) = (field(&f, ":method"), field(&f, ":path"))
                    else {
                        conn.reset(id, code::MESSAGE_ERROR);
                        cx.protocol_error("a request without :method or :path");
                        return Ok(());
                    };
                    let route = self.cfg.http.server.route(method, path).into_owned();
                    cx.transaction(
                        AppTransaction::new(route.status.to_string(), true)
                            .with_error(route.status >= 400),
                    );
                    self.queue
                        .push((cx.now() + route.delay, id, route, method == "HEAD"));
                    self.flush(conn, cx);
                }
            }
            Event::Reset { id, .. } => {
                self.requests.remove(&id);
                self.queue.retain(|q| q.1 != id);
            }
            Event::StopSending { id, .. } => {
                self.queue.retain(|q| q.1 != id);
                conn.reset(id, code::REQUEST_CANCELLED);
            }
            Event::StreamsAvailable | Event::Closed(_) => {}
        }
        Ok(())
    }

    /// Sends the answers that are due.
    pub fn flush(&mut self, conn: &mut Conn, cx: &mut AppCx) {
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
            let server = &self.cfg.http.server.server;
            let mut fields: Vec<(String, String)> =
                vec![(":status".into(), route.status.to_string())];
            let has = |n: &str| route.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
            if !server.is_empty() && !has("server") {
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
            let mut b = Vec::new();
            frame(&mut b, HEADERS, &self.common.encode(&fields));
            if !head && !bodiless && !route.body.is_empty() {
                // Frames of up to 64 KiB.
                for chunk in route.body.chunks(64 << 10) {
                    frame(&mut b, DATA, chunk);
                }
            }
            conn.write(id, &b, true);
            if route.close && !self.closing {
                self.closing = true;
                let next = self.highest.map_or(0, |h| h + 4);
                self.common.send_goaway(conn, next);
            }
        }
        if let Some(next) = self.queue.iter().map(|q| q.0).min() {
            cx.wake_at(next);
        }
    }
}

/// For the fuzz targets: reads `b` as a request stream's frames.
#[cfg(any(test, feature = "fuzzing"))]
#[allow(dead_code)]
pub(crate) fn fuzz_frames(b: &[u8]) {
    let mut m = Message {
        buf: b.to_vec(),
        ..Default::default()
    };
    let _ = m.frames(|f| field(f, ":status").is_some_and(|s| s.starts_with('1')));
}
