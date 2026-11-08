//! MQTT 3.1.1 and 5.0: a client that connects, subscribes and publishes
//! with QoS 0, 1 and 2, and a broker.
//!
//! The client of each connection sends CONNECT (client id, keep-alive,
//! clean session, user name and password), checks the CONNACK, subscribes
//! to its topic filters, publishes its share of the messages (QoS 0, 1 or
//! 2, retained or not, paced by `interval`), waits for every
//! acknowledgement (PUBACK, or PUBREC/PUBREL/PUBCOMP) and for its own
//! messages to come back on the filters they match, then sends DISCONNECT.
//! It answers the broker's PUBLISH as the QoS asks and sends PINGREQ when
//! it has been quiet for the keep-alive time.
//!
//! The broker accepts connections (checking users when it has some),
//! grants subscriptions up to its `max_qos`, acknowledges publishes,
//! keeps retained messages (shared by all its connections) and delivers
//! publishes to the subscriptions of the connection that sent them, which
//! is what an echo test needs. It does not route between connections.
//!
//! Each finished exchange is a transaction: `CONNACK accepted` (or the
//! refusal), `SUBACK`, `PUBACK`, `PUBCOMP`, `published` (QoS 0), and the
//! messages that came in (`received`, `retained`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::{
    AppCx, AppProtocol, AppRole, AppSession, AppTransaction, Receive, SessionInit, Transport,
};
use crate::{Error, Result};

/// The protocol version.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MqttVersion {
    #[default]
    V311,
    V5,
}

impl MqttVersion {
    fn level(self) -> u8 {
        match self {
            MqttVersion::V311 => 4,
            MqttVersion::V5 => 5,
        }
    }
}

impl std::str::FromStr for MqttVersion {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim() {
            "3.1.1" | "311" | "4" => Ok(MqttVersion::V311),
            "5" | "5.0" => Ok(MqttVersion::V5),
            _ => Err(Error::Profile(format!(
                "unknown MQTT version `{s}`; use 3.1.1 or 5"
            ))),
        }
    }
}

impl fmt::Display for MqttVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MqttVersion::V311 => "3.1.1",
            MqttVersion::V5 => "5.0",
        })
    }
}

/// A topic filter the client subscribes to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subscription {
    pub filter: String,
    pub qos: u8,
}

impl std::str::FromStr for Subscription {
    type Err = Error;
    /// `FILTER [QOS]`: `lab/#`, `lab/alerts 1`.
    fn from_str(s: &str) -> Result<Self> {
        let mut w = s.split_whitespace();
        let filter = w
            .next()
            .ok_or_else(|| Error::Profile("empty subscription".into()))?
            .to_string();
        let qos = match w.next() {
            Some(q) => qos(q)?,
            None => 0,
        };
        if w.next().is_some() {
            return Err(Error::Profile(format!(
                "subscription `{s}`: write FILTER [QOS]"
            )));
        }
        check_filter(&filter)?;
        Ok(Self { filter, qos })
    }
}

/// A message the client publishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MqttMessage {
    pub topic: String,
    pub qos: u8,
    pub retain: bool,
    pub payload: Arc<[u8]>,
}

impl MqttMessage {
    pub fn new(topic: impl Into<String>, qos: u8, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            topic: topic.into(),
            qos,
            retain: false,
            payload: payload.into().into(),
        }
    }
}

impl std::str::FromStr for MqttMessage {
    type Err = Error;
    /// `TOPIC [QOS] [SIZE]`: `lab/temp`, `lab/temp 1`, `lab/temp 2 1K`.
    fn from_str(s: &str) -> Result<Self> {
        let mut w = s.split_whitespace();
        let topic = w
            .next()
            .ok_or_else(|| Error::Profile("empty message".into()))?
            .to_string();
        if topic.contains(['+', '#']) {
            return Err(Error::Profile(format!(
                "`{topic}`: a topic to publish to has no wildcards"
            )));
        }
        let qos = match w.next() {
            Some(q) => qos(q)?,
            None => 0,
        };
        let size = match w.next() {
            Some(n) => crate::parse_size(n)? as usize,
            None => 32,
        };
        if w.next().is_some() {
            return Err(Error::Profile(format!(
                "message `{s}`: write TOPIC [QOS] [SIZE]"
            )));
        }
        Ok(Self::new(topic, qos, super::filler(size)))
    }
}

fn qos(s: &str) -> Result<u8> {
    match s.trim_start_matches("qos").trim_start_matches("QoS") {
        "0" => Ok(0),
        "1" => Ok(1),
        "2" => Ok(2),
        _ => Err(Error::Profile(format!("QoS `{s}`: use 0, 1 or 2"))),
    }
}

fn check_filter(f: &str) -> Result<()> {
    let levels: Vec<&str> = f.split('/').collect();
    for (i, l) in levels.iter().enumerate() {
        if (l.contains('#') && (*l != "#" || i + 1 != levels.len()))
            || (l.contains('+') && *l != "+")
        {
            return Err(Error::Profile(format!("bad topic filter `{f}`")));
        }
    }
    if f.is_empty() {
        return Err(Error::Profile("empty topic filter".into()));
    }
    Ok(())
}

/// Whether `topic` matches the filter `filter` (`+` one level, `#` the rest).
pub fn topic_matches(filter: &str, topic: &str) -> bool {
    if topic.starts_with('$') && !filter.starts_with('$') {
        return false;
    }
    let mut f = filter.split('/');
    let mut t = topic.split('/');
    loop {
        match (f.next(), t.next()) {
            (Some("#"), _) => return true,
            (Some("+"), Some(_)) => {}
            (Some(a), Some(b)) if a == b => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

/// What the client expects the CONNACK to say.
pub type ConnackExpect = Option<String>;

/// The client part.
#[derive(Clone, Debug, PartialEq)]
pub struct MqttClient {
    pub version: MqttVersion,
    /// `{n}` is the connection's number.
    pub client_id: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub keep_alive: Duration,
    pub clean: bool,
    pub subscribe: Vec<Subscription>,
    /// Published in turn across all connections.
    pub publish: Vec<MqttMessage>,
    /// Messages each connection publishes.
    pub per_connection: u32,
    /// Between one publish and the next.
    pub interval: Duration,
    /// How long to wait for acknowledgements and echoes after the last
    /// publish before giving up on them.
    pub wait: Duration,
    /// The CONNACK reason expected (`accepted` if none), e.g. `not
    /// authorized` for a test with a wrong password.
    pub expect: ConnackExpect,
}

impl Default for MqttClient {
    fn default() -> Self {
        Self {
            version: MqttVersion::default(),
            client_id: "ferotrx-{n}".into(),
            username: None,
            password: None,
            keep_alive: Duration::from_secs(60),
            clean: true,
            subscribe: Vec::new(),
            publish: vec![MqttMessage::new("ferotrx/test", 0, super::filler(32))],
            per_connection: 1,
            interval: Duration::ZERO,
            wait: Duration::from_secs(5),
            expect: None,
        }
    }
}

/// The broker part.
#[derive(Clone, Debug, PartialEq)]
pub struct MqttServer {
    /// The highest QoS granted to subscriptions.
    pub max_qos: u8,
    /// User names and passwords; empty for no login.
    pub users: BTreeMap<String, String>,
    /// Keep retained messages.
    pub retain: bool,
}

impl Default for MqttServer {
    fn default() -> Self {
        Self {
            max_qos: 2,
            users: BTreeMap::new(),
            retain: true,
        }
    }
}

type Retained = Arc<Mutex<BTreeMap<String, (u8, Arc<[u8]>)>>>;

/// MQTT client and broker; see the [module](self) docs.
#[derive(Clone, Debug, Default)]
pub struct Mqtt {
    pub client: MqttClient,
    pub server: MqttServer,
    retained: Retained,
}

impl Mqtt {
    pub fn new(client: MqttClient, server: MqttServer) -> Self {
        Self {
            client,
            server,
            retained: Retained::default(),
        }
    }
}

impl AppProtocol for Mqtt {
    fn name(&self) -> &str {
        "mqtt"
    }

    fn describe(&self) -> String {
        let c = &self.client;
        let mut s = format!(
            "MQTT {}: {} message(s), {} per connection",
            c.version,
            c.publish.len(),
            c.per_connection
        );
        if !c.subscribe.is_empty() {
            s += &format!(", {} subscription(s)", c.subscribe.len());
        }
        let top = c.publish.iter().map(|m| m.qos).max().unwrap_or(0);
        s += &format!(", QoS up to {top}");
        if !c.interval.is_zero() {
            s += &format!(", every {:?}", c.interval);
        }
        if c.username.is_some() {
            s += ", with login";
        }
        if !self.server.users.is_empty() {
            s += &format!("; broker with {} user(s)", self.server.users.len());
        }
        s
    }

    fn default_port(&self) -> u16 {
        1883
    }

    fn supports(&self, transport: Transport) -> bool {
        transport == Transport::Stream
    }

    fn validate(&self, role: AppRole, _transport: Transport) -> Result<()> {
        if role == AppRole::Client {
            if self.client.per_connection > 0 && self.client.publish.is_empty() {
                return Err(Error::Profile("MQTT: no messages to publish".into()));
            }
            if self.client.client_id.len() > 65535 {
                return Err(Error::Profile("MQTT: client_id is too long".into()));
            }
        }
        if self.server.max_qos > 2 {
            return Err(Error::Profile("MQTT: max_qos is 0, 1 or 2".into()));
        }
        Ok(())
    }

    fn session(&self, init: &SessionInit) -> Box<dyn AppSession> {
        let cfg = Arc::new(self.clone());
        match init.role {
            AppRole::Client => Box::new(ClientSession::new(cfg, init.index)),
            AppRole::Server => Box::new(ServerSession {
                cfg,
                buf: Vec::new(),
                version: None,
                subs: Vec::new(),
                inbound_qos2: BTreeSet::new(),
                next_id: 1,
            }),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// ---- packets --------------------------------------------------------------

const CONNECT: u8 = 1;
const CONNACK: u8 = 2;
const PUBLISH: u8 = 3;
const PUBACK: u8 = 4;
const PUBREC: u8 = 5;
const PUBREL: u8 = 6;
const PUBCOMP: u8 = 7;
const SUBSCRIBE: u8 = 8;
const SUBACK: u8 = 9;
const UNSUBSCRIBE: u8 = 10;
const UNSUBACK: u8 = 11;
const PINGREQ: u8 = 12;
const PINGRESP: u8 = 13;
const DISCONNECT: u8 = 14;

fn varint(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let mut b = (n % 128) as u8;
        n /= 128;
        if n > 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
}

fn string(s: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s);
}

fn packet(first: u8, body: &[u8]) -> Vec<u8> {
    let mut p = vec![first];
    varint(body.len(), &mut p);
    p.extend_from_slice(body);
    p
}

/// One packet from the front of `buf`: (first byte, body, length used), or
/// none while it is incomplete.
type Split<'a> = std::result::Result<Option<(u8, &'a [u8], usize)>, String>;

/// The longest packet taken. MQTT allows 256 MiB; a peer announcing that
/// much would have it buffered before anything is checked.
const MAX_PACKET: usize = 16 << 20;

fn split(buf: &[u8]) -> Split<'_> {
    if buf.is_empty() {
        return Ok(None);
    }
    let (mut len, mut mul, mut i) = (0usize, 1usize, 1usize);
    loop {
        let Some(&b) = buf.get(i) else {
            return Ok(None);
        };
        len += (b & 0x7f) as usize * mul;
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
        mul *= 128;
        if i > 4 {
            return Err("remaining length over four bytes".into());
        }
    }
    if len > MAX_PACKET {
        return Err(format!(
            "a packet of {len} bytes, over the {MAX_PACKET} taken"
        ));
    }
    if buf.len() < i + len {
        return Ok(None);
    }
    Ok(Some((buf[0], &buf[i..i + len], i + len)))
}

/// Reads the fields of a packet body.
struct Rd<'a>(&'a [u8]);

impl<'a> Rd<'a> {
    fn u8(&mut self) -> std::result::Result<u8, String> {
        let (&b, rest) = self.0.split_first().ok_or("packet too short")?;
        self.0 = rest;
        Ok(b)
    }
    fn u16(&mut self) -> std::result::Result<u16, String> {
        Ok(u16::from_be_bytes([self.u8()?, self.u8()?]))
    }
    fn bytes(&mut self, n: usize) -> std::result::Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("packet too short".into());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn string(&mut self) -> std::result::Result<&'a [u8], String> {
        let n = self.u16()? as usize;
        self.bytes(n)
    }
    fn varint(&mut self) -> std::result::Result<usize, String> {
        let (mut n, mut mul) = (0usize, 1usize);
        for _ in 0..4 {
            let b = self.u8()?;
            n += (b & 0x7f) as usize * mul;
            if b & 0x80 == 0 {
                return Ok(n);
            }
            mul *= 128;
        }
        Err("variable integer over four bytes".into())
    }
    /// Skips MQTT 5 properties.
    fn properties(&mut self, v: MqttVersion) -> std::result::Result<(), String> {
        if v == MqttVersion::V5 {
            let n = self.varint()?;
            self.bytes(n)?;
        }
        Ok(())
    }
    fn rest(&self) -> &'a [u8] {
        self.0
    }
}

fn props(v: MqttVersion, out: &mut Vec<u8>) {
    if v == MqttVersion::V5 {
        out.push(0);
    }
}

fn publish_packet(v: MqttVersion, id: u16, m: &MqttMessage, qos: u8, retain: bool) -> Vec<u8> {
    let mut b = Vec::with_capacity(m.topic.len() + m.payload.len() + 8);
    string(m.topic.as_bytes(), &mut b);
    if qos > 0 {
        b.extend_from_slice(&id.to_be_bytes());
    }
    props(v, &mut b);
    b.extend_from_slice(&m.payload);
    packet((PUBLISH << 4) | (qos << 1) | u8::from(retain), &b)
}

fn ack(kind: u8, id: u16) -> Vec<u8> {
    let first = (kind << 4) | if kind == PUBREL { 2 } else { 0 };
    packet(first, &id.to_be_bytes())
}

/// The name of a CONNACK code.
fn connack_name(v: MqttVersion, code: u8) -> String {
    let name = match (v, code) {
        (_, 0) => "accepted",
        (MqttVersion::V311, 1) | (MqttVersion::V5, 0x84) => "bad version",
        (MqttVersion::V311, 2) | (MqttVersion::V5, 0x85) => "id rejected",
        (MqttVersion::V311, 3) | (MqttVersion::V5, 0x88) => "unavailable",
        (MqttVersion::V311, 4) | (MqttVersion::V5, 0x86) => "bad credentials",
        (MqttVersion::V311, 5) | (MqttVersion::V5, 0x87) => "not authorized",
        (MqttVersion::V5, 0x80) => "unspecified error",
        (MqttVersion::V5, 0x81) => "malformed packet",
        (MqttVersion::V5, 0x82) => "protocol error",
        (MqttVersion::V5, 0x89) => "server busy",
        (MqttVersion::V5, 0x8a) => "banned",
        _ => return format!("code 0x{code:02x}"),
    };
    name.into()
}

fn refusal(v: MqttVersion, name: &str) -> u8 {
    match (v, name) {
        (MqttVersion::V311, "bad version") => 1,
        (MqttVersion::V311, "id rejected") => 2,
        (MqttVersion::V311, "bad credentials") => 4,
        (MqttVersion::V311, _) => 5,
        (MqttVersion::V5, "bad version") => 0x84,
        (MqttVersion::V5, "id rejected") => 0x85,
        (MqttVersion::V5, "bad credentials") => 0x86,
        (MqttVersion::V5, _) => 0x87,
    }
}

// ---- client ---------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Connecting,
    Subscribing,
    Publishing,
    Done,
}

struct Pending {
    sent: Duration,
    qos: u8,
}

struct ClientSession {
    cfg: Arc<Mqtt>,
    index: u64,
    buf: Vec<u8>,
    stage: Stage,
    asked: Duration,
    published: u32,
    next_at: Duration,
    next_id: u16,
    pending: BTreeMap<u16, Pending>,
    echoes_due: u32,
    echoes: u32,
    deadline: Option<Duration>,
    inbound_qos2: BTreeSet<u16>,
    last_sent: Duration,
}

impl ClientSession {
    fn new(cfg: Arc<Mqtt>, index: u64) -> Self {
        Self {
            cfg,
            index,
            buf: Vec::new(),
            stage: Stage::Connecting,
            asked: Duration::ZERO,
            published: 0,
            next_at: Duration::ZERO,
            next_id: 1,
            pending: BTreeMap::new(),
            echoes_due: 0,
            echoes: 0,
            deadline: None,
            inbound_qos2: BTreeSet::new(),
            last_sent: Duration::ZERO,
        }
    }

    fn v(&self) -> MqttVersion {
        self.cfg.client.version
    }

    fn send(&mut self, cx: &mut AppCx, p: Vec<u8>) {
        self.last_sent = cx.now();
        cx.send(p);
    }

    fn id(&mut self) -> u16 {
        let id = self.next_id;
        self.next_id = if self.next_id == u16::MAX {
            1
        } else {
            self.next_id + 1
        };
        id
    }

    fn connect(&mut self, cx: &mut AppCx) {
        let c = &self.cfg.client;
        let mut b = Vec::new();
        string(b"MQTT", &mut b);
        b.push(self.v().level());
        let mut flags = 0u8;
        if c.clean {
            flags |= 0x02;
        }
        if c.username.is_some() {
            flags |= 0x80;
        }
        if c.password.is_some() {
            flags |= 0x40;
        }
        b.push(flags);
        let ka = c.keep_alive.as_secs().min(65535) as u16;
        b.extend_from_slice(&ka.to_be_bytes());
        props(self.v(), &mut b);
        let id = c.client_id.replace("{n}", &self.index.to_string());
        string(id.as_bytes(), &mut b);
        if let Some(u) = &c.username {
            string(u.as_bytes(), &mut b);
        }
        if let Some(p) = &c.password {
            string(p.as_bytes(), &mut b);
        }
        self.asked = cx.now();
        self.send(cx, packet(CONNECT << 4, &b));
    }

    fn subscribe(&mut self, cx: &mut AppCx) {
        let id = self.id();
        let mut b = id.to_be_bytes().to_vec();
        props(self.v(), &mut b);
        for s in &self.cfg.client.subscribe {
            string(s.filter.as_bytes(), &mut b);
            b.push(s.qos);
        }
        self.asked = cx.now();
        self.stage = Stage::Subscribing;
        self.send(cx, packet((SUBSCRIBE << 4) | 2, &b));
    }

    /// Publishes what is due now, and sets the timer.
    fn publish_due(&mut self, cx: &mut AppCx) {
        let c = self.cfg.client.clone();
        while self.stage == Stage::Publishing
            && self.published < c.per_connection
            && cx.now() >= self.next_at
        {
            let k = (self.index * u64::from(c.per_connection) + u64::from(self.published)) as usize
                % c.publish.len();
            let m = &c.publish[k];
            let id = if m.qos > 0 { self.id() } else { 0 };
            let p = publish_packet(self.v(), id, m, m.qos, m.retain);
            self.send(cx, p);
            if m.qos > 0 {
                self.pending.insert(
                    id,
                    Pending {
                        sent: cx.now(),
                        qos: m.qos,
                    },
                );
            } else {
                cx.transaction(AppTransaction::new("published", true));
            }
            if c.subscribe
                .iter()
                .any(|s| topic_matches(&s.filter, &m.topic))
            {
                self.echoes_due += 1;
            }
            self.published += 1;
            self.next_at = cx.now() + c.interval;
        }
        if self.stage == Stage::Publishing
            && self.published >= c.per_connection
            && self.deadline.is_none()
        {
            self.deadline = Some(cx.now() + c.wait);
        }
        self.maybe_done(cx);
        self.set_timer(cx);
    }

    fn maybe_done(&mut self, cx: &mut AppCx) {
        if self.stage == Stage::Publishing
            && self.published >= self.cfg.client.per_connection
            && self.pending.is_empty()
            && self.echoes >= self.echoes_due
        {
            self.finish(cx);
        }
    }

    fn finish(&mut self, cx: &mut AppCx) {
        if self.stage == Stage::Done {
            return;
        }
        self.stage = Stage::Done;
        let mut b = Vec::new();
        if self.v() == MqttVersion::V5 {
            b.extend_from_slice(&[0, 0]);
        }
        self.send(cx, packet(DISCONNECT << 4, &b));
        cx.close();
    }

    fn set_timer(&self, cx: &mut AppCx) {
        if self.stage == Stage::Done {
            return;
        }
        let c = &self.cfg.client;
        let mut at = Vec::new();
        if self.stage == Stage::Publishing && self.published < c.per_connection {
            at.push(self.next_at);
        }
        if let Some(d) = self.deadline {
            at.push(d);
        }
        if !c.keep_alive.is_zero() {
            at.push(self.last_sent + c.keep_alive);
        }
        if let Some(t) = at.into_iter().min() {
            cx.wake_at(t.max(cx.now()));
        }
    }

    fn packet(
        &mut self,
        first: u8,
        body: &[u8],
        cx: &mut AppCx,
    ) -> std::result::Result<(), String> {
        let v = self.v();
        let mut r = Rd(body);
        match first >> 4 {
            CONNACK if self.stage == Stage::Connecting => {
                r.u8()?;
                let code = r.u8()?;
                let name = connack_name(v, code);
                let want = self.cfg.client.expect.as_deref().unwrap_or("accepted");
                let ok = name.eq_ignore_ascii_case(want);
                cx.transaction(
                    AppTransaction::new(format!("CONNACK {name}"), ok)
                        .with_error(code != 0)
                        .with_response_time(cx.now().saturating_sub(self.asked)),
                );
                if code != 0 {
                    self.stage = Stage::Done;
                    cx.close();
                } else if !self.cfg.client.subscribe.is_empty() {
                    self.subscribe(cx);
                } else {
                    self.stage = Stage::Publishing;
                    self.next_at = cx.now();
                    if self.cfg.client.per_connection == 0 {
                        self.finish(cx);
                    } else {
                        self.publish_due(cx);
                    }
                }
            }
            SUBACK if self.stage == Stage::Subscribing => {
                r.u16()?;
                r.properties(v)?;
                let codes = r.rest();
                let ok = codes.len() == self.cfg.client.subscribe.len()
                    && codes.iter().all(|&c| c < 0x80);
                cx.transaction(
                    AppTransaction::new("SUBACK", ok)
                        .with_error(!ok)
                        .with_response_time(cx.now().saturating_sub(self.asked)),
                );
                self.stage = Stage::Publishing;
                self.next_at = cx.now();
                if self.cfg.client.per_connection == 0 {
                    self.finish(cx);
                } else {
                    self.publish_due(cx);
                }
            }
            PUBACK | PUBCOMP => {
                let id = r.u16()?;
                let kind = first >> 4;
                match self.pending.get(&id) {
                    Some(p) if (p.qos == 1) == (kind == PUBACK) => {
                        let p = self.pending.remove(&id).expect("pending");
                        let label = if kind == PUBACK { "PUBACK" } else { "PUBCOMP" };
                        let code = r.u8().unwrap_or(0);
                        cx.transaction(
                            AppTransaction::new(label, code < 0x80)
                                .with_error(code >= 0x80)
                                .with_response_time(cx.now().saturating_sub(p.sent)),
                        );
                        self.maybe_done(cx);
                    }
                    _ => return Err(format!("acknowledgement for unknown packet {id}")),
                }
            }
            PUBREC => {
                let id = r.u16()?;
                if !self.pending.get(&id).is_some_and(|p| p.qos == 2) {
                    return Err(format!("PUBREC for unknown packet {id}"));
                }
                self.send(cx, ack(PUBREL, id));
            }
            PUBREL => {
                let id = r.u16()?;
                self.inbound_qos2.remove(&id);
                self.send(cx, ack(PUBCOMP, id));
            }
            PUBLISH => {
                let qos = (first >> 1) & 3;
                let retained = first & 1 == 1;
                r.string()?;
                let id = if qos > 0 { r.u16()? } else { 0 };
                r.properties(v)?;
                match qos {
                    1 => self.send(cx, ack(PUBACK, id)),
                    2 => {
                        self.inbound_qos2.insert(id);
                        self.send(cx, ack(PUBREC, id));
                    }
                    _ => {}
                }
                if retained {
                    cx.transaction(AppTransaction::new("retained", true));
                } else {
                    self.echoes += 1;
                    cx.transaction(AppTransaction::new("received", true));
                    self.maybe_done(cx);
                }
            }
            PINGRESP => {}
            DISCONNECT => {
                if self.stage != Stage::Done {
                    cx.protocol_error("the broker disconnected");
                }
                self.stage = Stage::Done;
                cx.close();
            }
            k => return Err(format!("unexpected packet type {k} from the broker")),
        }
        Ok(())
    }
}

impl AppSession for ClientSession {
    fn start(&mut self, cx: &mut AppCx) {
        self.connect(cx);
        self.set_timer(cx);
    }

    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        if self.stage == Stage::Done {
            // After DISCONNECT the broker reads nothing more: what it sent
            // before it saw it (other clients' messages) goes unanswered.
            return Receive::Taken;
        }
        self.buf.extend_from_slice(data);
        let mut used = 0;
        loop {
            if self.stage == Stage::Done {
                break;
            }
            match split(&self.buf[used..]) {
                Ok(Some((first, body, n))) => {
                    let body = body.to_vec();
                    used += n;
                    if let Err(e) = self.packet(first, &body, cx) {
                        cx.protocol_error(e);
                        self.stage = Stage::Done;
                        cx.close();
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    cx.protocol_error(e);
                    self.stage = Stage::Done;
                    cx.close();
                    break;
                }
            }
        }
        self.buf.drain(..used);
        self.set_timer(cx);
        Receive::Taken
    }

    fn peer_closed(&mut self, cx: &mut AppCx) {
        if self.stage != Stage::Done {
            cx.protocol_error("the broker closed the connection first");
            self.stage = Stage::Done;
        }
    }

    fn timer(&mut self, cx: &mut AppCx) {
        if self.stage == Stage::Done {
            return;
        }
        let now = cx.now();
        if self.deadline.is_some_and(|d| now >= d) {
            // What is still missing failed.
            for _ in 0..self.pending.len() {
                cx.transaction(AppTransaction::new("no acknowledgement", false));
            }
            for _ in self.echoes..self.echoes_due {
                cx.transaction(AppTransaction::new("not received", false));
            }
            self.pending.clear();
            self.finish(cx);
            return;
        }
        let ka = self.cfg.client.keep_alive;
        if !ka.is_zero() && now >= self.last_sent + ka {
            self.send(cx, packet(PINGREQ << 4, &[]));
        }
        self.publish_due(cx);
    }
}

// ---- broker ---------------------------------------------------------------

struct ServerSession {
    cfg: Arc<Mqtt>,
    buf: Vec<u8>,
    version: Option<MqttVersion>,
    subs: Vec<Subscription>,
    inbound_qos2: BTreeSet<u16>,
    next_id: u16,
}

impl ServerSession {
    fn v(&self) -> MqttVersion {
        self.version.unwrap_or_default()
    }

    fn deliver(&mut self, cx: &mut AppCx, m: &MqttMessage, qos: u8, retain: bool) {
        let id = if qos > 0 {
            let id = self.next_id;
            self.next_id = if id == u16::MAX { 1 } else { id + 1 };
            id
        } else {
            0
        };
        cx.send(publish_packet(self.v(), id, m, qos, retain));
    }

    fn connack(&mut self, cx: &mut AppCx, code: u8) {
        let mut b = vec![0, code];
        props(self.v(), &mut b);
        cx.send(packet(CONNACK << 4, &b));
    }

    fn packet(
        &mut self,
        first: u8,
        body: &[u8],
        cx: &mut AppCx,
    ) -> std::result::Result<(), String> {
        let mut r = Rd(body);
        let kind = first >> 4;
        if self.version.is_none() && kind != CONNECT {
            return Err(format!("packet type {kind} before CONNECT"));
        }
        match kind {
            CONNECT => {
                if self.version.is_some() {
                    return Err("a second CONNECT".into());
                }
                let name = r.string()?;
                let level = r.u8()?;
                if name != b"MQTT" && name != b"MQIsdp" {
                    return Err("not MQTT".into());
                }
                let v = match level {
                    4 => MqttVersion::V311,
                    5 => MqttVersion::V5,
                    _ => {
                        self.version = Some(MqttVersion::V311);
                        self.connack(cx, 1);
                        cx.transaction(
                            AppTransaction::new("CONNACK bad version", true).with_error(true),
                        );
                        cx.close();
                        return Ok(());
                    }
                };
                self.version = Some(v);
                let flags = r.u8()?;
                r.u16()?;
                r.properties(v)?;
                let id = r.string()?.to_vec();
                if flags & 0x04 != 0 {
                    // A will: its properties, topic and message.
                    r.properties(v)?;
                    r.string()?;
                    r.string()?;
                }
                let user = if flags & 0x80 != 0 {
                    Some(r.string()?.to_vec())
                } else {
                    None
                };
                let pass = if flags & 0x40 != 0 {
                    Some(r.string()?.to_vec())
                } else {
                    None
                };
                let users = &self.cfg.server.users;
                let refused = if id.is_empty() && flags & 0x02 == 0 {
                    Some("id rejected")
                } else if !users.is_empty() {
                    let ok = match (&user, &pass) {
                        (Some(u), Some(p)) => users
                            .get(&*String::from_utf8_lossy(u))
                            .is_some_and(|w| w.as_bytes() == &p[..]),
                        _ => false,
                    };
                    (!ok).then_some(if user.is_some() {
                        "bad credentials"
                    } else {
                        "not authorized"
                    })
                } else {
                    None
                };
                match refused {
                    Some(why) => {
                        self.connack(cx, refusal(v, why));
                        cx.transaction(
                            AppTransaction::new(format!("CONNACK {why}"), true).with_error(true),
                        );
                        cx.close();
                    }
                    None => {
                        self.connack(cx, 0);
                        cx.transaction(AppTransaction::new("CONNACK accepted", true));
                    }
                }
            }
            SUBSCRIBE => {
                let id = r.u16()?;
                r.properties(self.v())?;
                let mut codes = Vec::new();
                let mut new = Vec::new();
                while !r.rest().is_empty() {
                    let f = String::from_utf8_lossy(r.string()?).into_owned();
                    let q = r.u8()? & 3;
                    if check_filter(&f).is_err() || q > 2 {
                        codes.push(0x80);
                        continue;
                    }
                    let q = q.min(self.cfg.server.max_qos);
                    codes.push(q);
                    self.subs.retain(|s| s.filter != f);
                    let s = Subscription { filter: f, qos: q };
                    new.push(s.clone());
                    self.subs.push(s);
                }
                if codes.is_empty() {
                    return Err("SUBSCRIBE without topic filters".into());
                }
                let mut b = id.to_be_bytes().to_vec();
                props(self.v(), &mut b);
                b.extend_from_slice(&codes);
                cx.send(packet(SUBACK << 4, &b));
                cx.transaction(AppTransaction::new("subscribe", true));
                if self.cfg.server.retain {
                    let kept: Vec<(String, u8, Arc<[u8]>)> = {
                        let r = self.cfg.retained.lock().expect("retained");
                        r.iter()
                            .map(|(t, (q, p))| (t.clone(), *q, p.clone()))
                            .collect()
                    };
                    for (topic, q, payload) in kept {
                        if let Some(s) = new.iter().find(|s| topic_matches(&s.filter, &topic)) {
                            let m = MqttMessage {
                                topic,
                                qos: q,
                                retain: true,
                                payload,
                            };
                            self.deliver(cx, &m, q.min(s.qos), true);
                        }
                    }
                }
            }
            UNSUBSCRIBE => {
                let id = r.u16()?;
                r.properties(self.v())?;
                let mut n = 0;
                while !r.rest().is_empty() {
                    let f = String::from_utf8_lossy(r.string()?).into_owned();
                    self.subs.retain(|s| s.filter != f);
                    n += 1;
                }
                let mut b = id.to_be_bytes().to_vec();
                if self.v() == MqttVersion::V5 {
                    b.push(0);
                    b.extend(std::iter::repeat_n(0u8, n));
                }
                cx.send(packet(UNSUBACK << 4, &b));
            }
            PUBLISH => {
                let qos = (first >> 1) & 3;
                let retain = first & 1 == 1;
                let topic = String::from_utf8_lossy(r.string()?).into_owned();
                let id = if qos > 0 { r.u16()? } else { 0 };
                r.properties(self.v())?;
                if qos == 3 {
                    return Err("PUBLISH with QoS 3".into());
                }
                let payload: Arc<[u8]> = r.rest().into();
                let dup = qos == 2 && !self.inbound_qos2.insert(id);
                match qos {
                    1 => cx.send(ack(PUBACK, id)),
                    2 => cx.send(ack(PUBREC, id)),
                    _ => {}
                }
                if dup {
                    return Ok(());
                }
                if retain && self.cfg.server.retain {
                    let mut kept = self.cfg.retained.lock().expect("retained");
                    if payload.is_empty() {
                        kept.remove(&topic);
                    } else {
                        kept.insert(topic.clone(), (qos, payload.clone()));
                    }
                }
                cx.transaction(AppTransaction::new(format!("publish QoS {qos}"), true));
                let m = MqttMessage {
                    topic,
                    qos,
                    retain: false,
                    payload,
                };
                let best = self
                    .subs
                    .iter()
                    .filter(|s| topic_matches(&s.filter, &m.topic))
                    .map(|s| s.qos)
                    .max();
                if let Some(sq) = best {
                    self.deliver(cx, &m, qos.min(sq), false);
                }
            }
            PUBREL => {
                let id = r.u16()?;
                self.inbound_qos2.remove(&id);
                cx.send(ack(PUBCOMP, id));
            }
            PUBREC => {
                let id = r.u16()?;
                cx.send(ack(PUBREL, id));
            }
            PUBACK | PUBCOMP => {}
            PINGREQ => cx.send(packet(PINGRESP << 4, &[])),
            DISCONNECT => cx.close(),
            k => return Err(format!("unexpected packet type {k} from a client")),
        }
        Ok(())
    }
}

impl AppSession for ServerSession {
    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        self.buf.extend_from_slice(data);
        let mut used = 0;
        loop {
            match split(&self.buf[used..]) {
                Ok(Some((first, body, n))) => {
                    let body = body.to_vec();
                    used += n;
                    if let Err(e) = self.packet(first, &body, cx) {
                        cx.protocol_error(e);
                        cx.close();
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    cx.protocol_error(e);
                    cx.close();
                    break;
                }
            }
        }
        self.buf.drain(..used);
        Receive::Taken
    }

    fn peer_closed(&mut self, cx: &mut AppCx) {
        cx.close();
    }
}

// ---- profiles -------------------------------------------------------------

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
    #[serde(deny_unknown_fields)]
    pub struct Mqtt {
        pub version: Option<String>,
        pub client_id: Option<String>,
        pub username: Option<String>,
        pub password: Option<String>,
        pub keep_alive: Option<String>,
        pub clean: Option<bool>,
        #[serde(default)]
        pub subscribe: Vec<String>,
        #[serde(default)]
        pub publish: Vec<String>,
        #[serde(default)]
        pub message: Vec<Message>,
        pub per_connection: Option<u32>,
        pub interval: Option<String>,
        pub wait: Option<String>,
        pub expect: Option<String>,
        pub max_qos: Option<u8>,
        #[serde(default)]
        pub users: BTreeMap<String, String>,
        pub retain: Option<bool>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Message {
        pub topic: String,
        pub qos: Option<u8>,
        pub retain: Option<bool>,
        pub payload: Option<String>,
        pub payload_size: Option<Size>,
    }
}

/// Reads an `[mqtt]` table.
#[cfg(feature = "profile")]
pub fn parse(t: &toml::Table) -> Result<Mqtt> {
    let r: raw::Mqtt = super::registry::table_into(t)?;
    let mut c = MqttClient::default();
    if let Some(v) = r.version {
        c.version = v.parse()?;
    }
    if let Some(id) = r.client_id {
        c.client_id = id;
    }
    c.username = r.username;
    c.password = r.password;
    if let Some(k) = r.keep_alive {
        c.keep_alive = crate::parse_duration(&k)?;
    }
    if let Some(cl) = r.clean {
        c.clean = cl;
    }
    c.subscribe = r
        .subscribe
        .iter()
        .map(|s| s.parse())
        .collect::<Result<_>>()?;
    let mut msgs: Vec<MqttMessage> = r.publish.iter().map(|s| s.parse()).collect::<Result<_>>()?;
    for m in r.message {
        let q = m.qos.unwrap_or(0);
        if q > 2 {
            return Err(Error::Profile(format!("`{}`: QoS is 0, 1 or 2", m.topic)));
        }
        let payload = match (m.payload, m.payload_size) {
            (Some(p), None) => p.into_bytes(),
            (None, Some(raw::Size::N(n))) => super::filler(n as usize),
            (None, Some(raw::Size::S(s))) => super::filler(crate::parse_size(&s)? as usize),
            (None, None) => super::filler(32),
            _ => {
                return Err(Error::Profile(
                    "give `payload` or `payload_size`, not both".into(),
                ))
            }
        };
        let mut msg = MqttMessage::new(m.topic, q, payload);
        msg.retain = m.retain.unwrap_or(false);
        msgs.push(msg);
    }
    if !msgs.is_empty() {
        c.publish = msgs;
    }
    c.per_connection = r.per_connection.unwrap_or(c.publish.len() as u32);
    if let Some(i) = r.interval {
        c.interval = crate::parse_duration(&i)?;
    }
    if let Some(w) = r.wait {
        c.wait = crate::parse_duration(&w)?;
    }
    c.expect = r.expect.map(|e| e.to_ascii_lowercase());
    let mut s = MqttServer::default();
    if let Some(q) = r.max_qos {
        s.max_qos = q;
    }
    s.users = r.users;
    if let Some(rt) = r.retain {
        s.retain = rt;
    }
    let m = Mqtt::new(c, s);
    m.validate(AppRole::Client, Transport::Stream)?;
    m.validate(AppRole::Server, Transport::Stream)?;
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn init(role: AppRole, index: u64) -> SessionInit {
        let a: SocketAddr = "10.0.0.1:40000".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:1883".parse().unwrap();
        SessionInit {
            role,
            transport: Transport::Stream,
            index,
            seed: 1,
            local: a,
            remote: b,
        }
    }

    /// Plays a client and a broker session, handing bytes over in pieces of
    /// `piece` bytes and firing timers, until the client closes.
    fn play(m: &Mqtt, index: u64, piece: usize) -> (AppCx, AppCx) {
        let app = super::super::App::new(m.clone());
        let mut c = app.session(&init(AppRole::Client, index));
        let mut s = app.session(&init(AppRole::Server, index));
        let (mut cc, mut sc) = (AppCx::default(), AppCx::default());
        let mut now = Duration::ZERO;
        let mut x = AppCx::new(now, now);
        c.start(&mut x);
        let mut to_s: Vec<u8> = x.take_sends().concat();
        let mut wake = x.wake();
        let mut closed = x.wants_close();
        cc.absorb(x);
        for _ in 0..10_000 {
            let mut to_c = Vec::new();
            for chunk in std::mem::take(&mut to_s).chunks(piece) {
                let mut y = AppCx::new(now, now);
                s.receive(chunk, &mut y);
                to_c.extend(y.take_sends().concat());
                sc.absorb(y);
            }
            for chunk in to_c.chunks(piece) {
                let mut y = AppCx::new(now, now);
                c.receive(chunk, &mut y);
                to_s.extend(y.take_sends().concat());
                wake = y.wake().or(wake);
                closed |= y.wants_close();
                cc.absorb(y);
            }
            if closed && to_s.is_empty() {
                // The DISCONNECT still goes to the broker.
                break;
            }
            if to_s.is_empty() {
                let Some(w) = wake.take() else { break };
                now = now.max(w);
                let mut y = AppCx::new(now, now);
                c.timer(&mut y);
                to_s.extend(y.take_sends().concat());
                wake = y.wake();
                closed |= y.wants_close();
                cc.absorb(y);
            }
        }
        if !to_s.is_empty() {
            let mut y = AppCx::new(now, now);
            s.receive(&to_s, &mut y);
            sc.absorb(y);
        }
        (cc, sc)
    }

    fn labels(cx: &AppCx) -> Vec<String> {
        cx.transactions().iter().map(|t| t.label.clone()).collect()
    }

    #[test]
    fn topics_match() {
        assert!(topic_matches("lab/#", "lab/a/b"));
        assert!(topic_matches("lab/#", "lab"));
        assert!(topic_matches("lab/+/t", "lab/x/t"));
        assert!(!topic_matches("lab/+", "lab/x/t"));
        assert!(!topic_matches("#", "$SYS/x"));
        assert!(check_filter("a/#/b").is_err());
        assert!(check_filter("a+/b").is_err());
    }

    #[test]
    fn publishes_with_every_qos_and_gets_its_echoes() {
        for v in [MqttVersion::V311, MqttVersion::V5] {
            let mut m = Mqtt::default();
            m.client.version = v;
            m.client.subscribe = vec!["lab/#".parse().unwrap()];
            m.client.subscribe[0].qos = 2;
            m.client.publish = vec![
                "lab/a 0 10".parse().unwrap(),
                "lab/b 1 20".parse().unwrap(),
                "lab/c 2 1K".parse().unwrap(),
                "other/d 1".parse().unwrap(),
            ];
            m.client.per_connection = 4;
            for piece in [1, 7, 10_000] {
                let (c, s) = play(&m, 0, piece);
                assert!(
                    c.all_ok() && s.all_ok(),
                    "{v}: {:?} {:?}",
                    c.transactions(),
                    c.protocol_errors()
                );
                let l = labels(&c);
                for want in [
                    "CONNACK accepted",
                    "SUBACK",
                    "published",
                    "PUBACK",
                    "PUBCOMP",
                ] {
                    assert!(l.contains(&want.to_string()), "{v}: {l:?}");
                }
                // Three of the four match lab/#.
                assert_eq!(l.iter().filter(|x| *x == "received").count(), 3, "{l:?}");
                assert_eq!(
                    labels(&s)
                        .iter()
                        .filter(|x| x.starts_with("publish"))
                        .count(),
                    4
                );
            }
        }
    }

    #[test]
    fn logins_retained_messages_and_paced_publishes() {
        let mut m = Mqtt::default();
        m.server.users.insert("alice".into(), "secret".into());
        m.client.username = Some("alice".into());
        m.client.password = Some("wrong".into());
        let (c, _) = play(&m, 0, 100);
        assert_eq!(labels(&c), ["CONNACK bad credentials"]);
        assert!(!c.all_ok());
        m.client.expect = Some("bad credentials".into());
        let (c, _) = play(&m, 0, 100);
        assert!(c.all_ok());

        m.client.password = Some("secret".into());
        m.client.expect = None;
        let mut kept = MqttMessage::new("lab/state", 1, b"on".to_vec());
        kept.retain = true;
        m.client.publish = vec![kept];
        let (c, _) = play(&m, 0, 100);
        assert!(c.all_ok(), "{:?}", c.transactions());
        // A later connection subscribing gets the retained message first.
        m.client.subscribe = vec!["lab/+".parse().unwrap()];
        m.client.publish = vec!["lab/x 0".parse().unwrap()];
        m.client.per_connection = 3;
        m.client.interval = Duration::from_millis(10);
        let (c, _) = play(&m, 1, 100);
        let l = labels(&c);
        assert_eq!(l.iter().filter(|x| *x == "retained").count(), 1, "{l:?}");
        assert_eq!(l.iter().filter(|x| *x == "received").count(), 3, "{l:?}");
        assert!(c.all_ok());
    }

    #[test]
    fn missing_acknowledgements_and_echoes_fail_after_the_wait() {
        let mut m = Mqtt::default();
        m.client.subscribe = vec!["lab/#".parse().unwrap()];
        m.client.publish = vec!["lab/a 1".parse().unwrap()];
        m.client.wait = Duration::from_millis(50);
        let app = super::super::App::new(m);
        let mut c = app.session(&init(AppRole::Client, 0));
        let mut x = AppCx::default();
        c.start(&mut x);
        // A broker that accepts and acknowledges the subscription, then
        // says nothing more.
        let mut x = AppCx::default();
        c.receive(&packet(CONNACK << 4, &[0, 0]), &mut x);
        c.receive(&packet(SUBACK << 4, &[0, 1, 0]), &mut x);
        assert!(x.all_ok(), "{:?}", x.protocol_errors());
        let w = x.wake().expect("a timer for the wait");
        let mut y = AppCx::new(w, w);
        c.timer(&mut y);
        let l = labels(&y);
        assert_eq!(l, ["no acknowledgement", "not received"]);
        assert!(y.wants_close() && !y.all_ok());
    }

    #[cfg(feature = "profile")]
    #[test]
    fn parses_a_table() {
        let t: toml::Table = r#"
            version = "5"
            client_id = "lab-{n}"
            subscribe = ["lab/# 1"]
            publish = ["lab/temp 1 64", "lab/alert 2"]
            per_connection = 10
            interval = "10ms"
            users = { alice = "secret" }
            [[message]]
            topic = "lab/state"
            payload = "on"
            retain = true
        "#
        .parse()
        .unwrap();
        let m = parse(&t).unwrap();
        assert_eq!(m.client.version, MqttVersion::V5);
        assert_eq!(m.client.publish.len(), 3);
        assert!(m.client.publish[2].retain);
        assert_eq!(m.client.per_connection, 10);
        assert!(m
            .describe()
            .starts_with("MQTT 5.0: 3 message(s), 10 per connection"));
        for bad in [
            "publish = [\"a/# 1\"]",
            "subscribe = [\"a 3\"]",
            "version = \"4.0\"",
            "qos = 1",
        ] {
            let t: toml::Table = bad.parse().unwrap();
            assert!(parse(&t).is_err(), "{bad}");
        }
    }
}
