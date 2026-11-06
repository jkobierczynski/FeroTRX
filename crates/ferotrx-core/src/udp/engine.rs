//! The UDP engine: emulated clients and servers that play request/response
//! transactions.
//!
//! Like the TCP engine it does no I/O and reads no clock: it is fed received
//! frames and the time, and queues the frames it wants sent.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;

use super::dns::DnsWorkload;
use super::program::{UdpProgram, UdpRole};
use crate::app::{App, AppCx, AppRole, AppSession, Receive, SessionInit, Transport};
use crate::net::{ETHERTYPE_IPV4, ETHERTYPE_IPV6, IPPROTO_ICMPV6};
use crate::tcp::engine::{ip_add, ip_max, ip_num, ip_version, TcpEndpoint};
use crate::tcp::hosts::{self, Host, MAX_HOPS};
use crate::tcp::wire::{self, Path};
use crate::traffic::EventClock;
use crate::{Error, LatencyStats, PortEngine, Result, TrafficModel};

/// An emulated host of a UDP run: the same as a TCP one.
pub type UdpEndpoint = TcpEndpoint;

/// What a template's transactions carry.
#[derive(Clone, Debug, PartialEq)]
pub enum UdpApp {
    /// Datagrams as in the program (from a capture or written out), checked
    /// byte for byte.
    Replay(Arc<UdpProgram>),
    /// An application protocol (see [`crate::app`]): DNS, NTP or one of
    /// your own. Each transaction is one request and its answer; the
    /// protocol makes the request, matches the answer (by DNS id and
    /// question, NTP timestamp) and, on the server, makes the answer.
    App(App),
}

impl UdpApp {
    /// DNS lookups: the client sends the workload's queries in turn, each
    /// with its own transaction id, and the server answers from its records.
    /// Answers are matched by id and question.
    pub fn dns(workload: Arc<DnsWorkload>) -> Self {
        UdpApp::App(App::new(crate::app::dns::Dns::new(workload)))
    }

    /// NTP: client requests and server replies, matched by the client's
    /// transmit timestamp.
    pub fn ntp() -> Self {
        UdpApp::App(App::new(crate::app::ntp::Ntp))
    }

    /// The usual server port: the program's, or the protocol's (53, 123).
    pub fn default_port(&self) -> u16 {
        match self {
            UdpApp::Replay(p) => p.server_port,
            UdpApp::App(a) => a.default_port(),
        }
    }

    /// `replay`, or the protocol's name: `dns`, `ntp`.
    pub fn kind(&self) -> &str {
        match self {
            UdpApp::Replay(_) => "replay",
            UdpApp::App(a) => a.name(),
        }
    }

    /// The DNS workload, if the template plays DNS.
    pub fn dns_workload(&self) -> Option<&Arc<DnsWorkload>> {
        match self {
            UdpApp::App(a) => a
                .downcast_ref::<crate::app::dns::Dns>()
                .map(|d| &d.workload),
            UdpApp::Replay(_) => None,
        }
    }
}

impl fmt::Display for UdpApp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UdpApp::Replay(p) => write!(f, "{p}"),
            UdpApp::App(a) => write!(f, "{}", a.describe()),
        }
    }
}

/// One kind of UDP transaction: what it carries, where clients send it, the
/// port servers answer it on, and its share of the traffic.
///
/// Like a [`TcpTemplate`](crate::TcpTemplate): a run mixes templates by
/// weight, or each runs at its own `rate`.
#[derive(Clone, Debug, PartialEq)]
pub struct UdpTemplate {
    /// A short name for reports, e.g. `dns`.
    pub name: String,
    pub app: UdpApp,
    /// Where clients send: the first server address, and the port.
    pub connect: SocketAddr,
    /// How many consecutive server addresses from `connect`'s the client
    /// sends to, in turn (default 1).
    pub connect_ips: u32,
    /// The port servers answer this template on (default: `connect`'s port).
    pub listen_port: u16,
    /// Share of the transactions the client starts with this template
    /// (default 1). 0: the client never starts it, the server still answers.
    pub weight: u32,
    /// This template's own transactions per second, apart from the client's.
    pub rate: Option<f64>,
    /// How this template's own transactions spread around its `rate`; only
    /// with `rate`.
    pub model: TrafficModel,
    /// Most transactions of this template; 0 is no limit of its own.
    pub transactions: u64,
    /// Most of this template's transactions open at once; 0 is no limit.
    pub concurrency: usize,
    /// Think time for this template, instead of the options'.
    pub think_time: Option<Duration>,
}

impl UdpTemplate {
    /// A template that sends to `connect` and listens on its port, weight 1.
    pub fn new(app: UdpApp, connect: SocketAddr) -> Self {
        Self {
            name: app.kind().into(),
            app,
            connect,
            connect_ips: 1,
            listen_port: connect.port(),
            weight: 1,
            rate: None,
            model: TrafficModel::default(),
            transactions: 0,
            concurrency: 0,
            think_time: None,
        }
    }

    /// Spreads this template's own transactions around its `rate` by `model`.
    pub fn with_model(mut self, model: TrafficModel) -> Self {
        self.model = model;
        self
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    /// Starts this template's transactions at `rate` per second, on its own.
    pub fn with_rate(mut self, rate: f64) -> Self {
        self.rate = Some(rate);
        self
    }

    pub fn with_transactions(mut self, n: u64) -> Self {
        self.transactions = n;
        self
    }

    pub fn with_concurrency(mut self, n: usize) -> Self {
        self.concurrency = n;
        self
    }

    pub fn with_connect_ips(mut self, n: u32) -> Self {
        self.connect_ips = n;
        self
    }

    pub fn with_listen_port(mut self, port: u16) -> Self {
        self.listen_port = port;
        self
    }

    pub fn with_think_time(mut self, t: Duration) -> Self {
        self.think_time = Some(t);
        self
    }

    fn nth_server(&self, n: u64) -> IpAddr {
        ip_add(
            self.connect.ip(),
            u128::from(n % u64::from(self.connect_ips.max(1))),
        )
    }
}

/// The client side: starts transactions and plays the client's part.
#[derive(Clone, Debug, PartialEq)]
pub struct UdpClientConfig {
    pub endpoint: UdpEndpoint,
    /// Transactions per second, for the templates without their own `rate`.
    pub rate: f64,
    /// How transactions spread around `rate`: Poisson arrivals, bursts, a
    /// ramp (one that ends at 0% stops starting transactions).
    pub model: TrafficModel,
    /// Transactions in all; 0 keeps going until the run stops.
    pub transactions: u64,
    /// Most transactions open at once; 0 is no limit.
    pub concurrency: usize,
    /// Source ports, in turn: each transaction gets its own.
    pub source_ports: Range<u16>,
}

impl UdpClientConfig {
    pub fn new(endpoint: UdpEndpoint) -> Self {
        Self {
            endpoint,
            rate: 1.0,
            model: TrafficModel::default(),
            transactions: 1,
            concurrency: 0,
            source_ports: 1024..65535,
        }
    }
}

/// The server side: answers on the templates' ports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpServerConfig {
    pub endpoint: UdpEndpoint,
}

impl UdpServerConfig {
    pub fn new(endpoint: UdpEndpoint) -> Self {
        Self { endpoint }
    }
}

/// UDP settings shared by both sides.
#[derive(Clone, Debug, PartialEq)]
pub struct UdpOptions {
    /// How long the client waits for an answer before it asks again
    /// (default 1 s).
    pub timeout: Duration,
    /// How often the client asks again before the transaction times out
    /// (default 2).
    pub retries: u32,
    /// How long the server keeps a session with nothing received: to answer
    /// repeated requests, or waiting for the client's next datagram (default 5 s).
    pub session_timeout: Duration,
    /// How long the client waits for its next hop's ARP reply or neighbor
    /// advertisement (default 5 s).
    pub arp_timeout: Duration,
    /// Keep the capture's timing: before each datagram, wait as long as the
    /// capture shows (default false).
    pub keep_timing: bool,
    /// How long an end waits after the other end's datagram before it sends
    /// its own (default 0). Templates can set their own.
    pub think_time: Duration,
    /// Check replayed datagrams byte for byte (default true).
    pub verify: bool,
    /// Seed for DNS transaction ids.
    pub seed: u64,
    /// Unix time at the start of the run, for NTP timestamps. `ferotrx-ctl`
    /// sets it from the system clock.
    pub clock: Duration,
    /// The ports sessions get for media (SIP's RTP and RTCP), on each end
    /// (default 16384-32767).
    pub media_ports: Range<u16>,
}

impl Default for UdpOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(1),
            retries: 2,
            session_timeout: Duration::from_secs(5),
            arp_timeout: Duration::from_secs(5),
            keep_timing: false,
            think_time: Duration::ZERO,
            verify: true,
            seed: 0x5eed_d115,
            clock: Duration::ZERO,
            media_ports: 16384..32768,
        }
    }
}

/// Everything a [`UdpEngine`] does.
#[derive(Clone, Debug)]
pub struct UdpConfig {
    pub templates: Vec<UdpTemplate>,
    pub client: Option<UdpClientConfig>,
    pub server: Option<UdpServerConfig>,
    pub options: UdpOptions,
}

/// Counters of one side of a UDP run.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct UdpSideStats {
    /// Transactions started (client: first request sent; server: first
    /// request received).
    pub sent: u64,
    /// Transactions played to the end: every datagram the program expects
    /// arrived (client), or every answer went out (server).
    pub answered: u64,
    /// Client: transactions given up after the retries; server: sessions
    /// that waited longer than the session timeout for the client.
    pub timed_out: u64,
    /// Datagrams that belonged to no transaction: late answers, wrong DNS
    /// ids or NTP timestamps, ports nobody listens on, malformed requests.
    pub unmatched: u64,
    /// Transactions whose datagrams differed from the program, or DNS
    /// answers to another question or with an unexpected response code.
    /// Also counted in `answered`.
    pub mismatched: u64,
    /// Transactions answered with an error: a DNS response code other than
    /// NOERROR, an NTP kiss-o'-death. Also counted in `answered`.
    pub errors: u64,
    /// Client: requests sent again after a timeout. Server: answers sent
    /// again for repeated requests.
    pub retries: u64,
    /// Answers that came again after the transaction moved on (to a request
    /// sent twice), or repeated requests while the server held its answer.
    pub duplicates: u64,
    /// Transactions open now.
    pub active: u64,
    pub datagrams_tx: u64,
    pub datagrams_rx: u64,
    /// UDP payload bytes, repeats included.
    pub payload_tx: u64,
    pub payload_rx: u64,
    /// Client: from each request (its first try) to its answer.
    pub response_time: LatencyStats,
    /// What the application protocol counted: transactions by response
    /// code (`NOERROR`, `NXDOMAIN`), failures, protocol errors. Empty for
    /// replays.
    pub app: crate::AppStats,
}

/// Counters of one template in a UDP run.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct UdpTemplateStats {
    pub name: String,
    pub client: UdpSideStats,
    pub server: UdpSideStats,
}

/// Counters of a UDP run.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct UdpStats {
    pub client: UdpSideStats,
    pub server: UdpSideStats,
    /// Each template's share, in the order of [`UdpConfig::templates`].
    pub templates: Vec<UdpTemplateStats>,
    /// Frames and bytes on the ports, all kinds.
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    /// Frames the ports dropped before the engine could read them (a full
    /// capture buffer): lost on this machine, not on the network.
    pub rx_dropped: u64,
    /// What the ports' impairments did ([`PortImpair`](crate::PortImpair)):
    /// frames sent and frames received; empty without them.
    pub impair: crate::PortImpairStats,
    pub elapsed: Duration,
    /// True if the run was stopped or hit its duration before the client finished.
    pub stopped: bool,
    /// The emulated hosts behind the client and server, when they get their
    /// addresses by DHCP, SLAAC or DHCPv6, announce them or join groups
    /// (see [`Hosted`](crate::Hosted)); empty otherwise.
    pub hosts: Vec<crate::HostStatus>,
}

impl UdpStats {
    /// Answered client transactions per second.
    pub fn tps(&self) -> f64 {
        let s = self.elapsed.as_secs_f64();
        if s > 0.0 {
            self.client.answered as f64 / s
        } else {
            0.0
        }
    }

    /// Applies `f` to `role`'s counters, overall and of template `tpl` (if any).
    fn add(&mut self, role: UdpRole, tpl: usize, f: impl Fn(&mut UdpSideStats)) {
        let side = |c: &mut UdpSideStats, s: &mut UdpSideStats, f: &dyn Fn(&mut UdpSideStats)| {
            match role {
                UdpRole::Client => f(c),
                UdpRole::Server => f(s),
            }
        };
        side(&mut self.client, &mut self.server, &f);
        if let Some(t) = self.templates.get_mut(tpl) {
            side(&mut t.client, &mut t.server, &f);
        }
    }
}

/// One datagram of a template's transaction, and how long to wait before it.
#[derive(Clone, Copy, Debug)]
struct Step {
    from: UdpRole,
    wait: Duration,
}

fn plan(t: &UdpTemplate, o: &UdpOptions) -> Vec<Step> {
    let think = t.think_time.unwrap_or(o.think_time);
    match &t.app {
        UdpApp::Replay(p) => {
            let mut prev: Option<UdpRole> = None;
            p.messages
                .iter()
                .map(|m| {
                    let mut wait = if o.keep_timing {
                        m.delay
                    } else {
                        Duration::ZERO
                    };
                    if prev == Some(m.from.peer()) {
                        wait += think;
                    }
                    prev = Some(m.from);
                    Step { from: m.from, wait }
                })
                .collect()
        }
        UdpApp::App(_) => vec![
            Step {
                from: UdpRole::Client,
                wait: Duration::ZERO,
            },
            Step {
                from: UdpRole::Server,
                wait: think,
            },
        ],
    }
}

/// What happened to a session after an event.
#[derive(PartialEq, Eq)]
enum Fate {
    Keep,
    Remove,
    /// A finished server session that the datagram is not for: a new
    /// session takes it.
    Replace,
}

type Key = (SocketAddr, SocketAddr);

struct Session {
    role: UdpRole,
    tpl: usize,
    port: usize,
    path: Path,
    lport: u16,
    rport: u16,
    step: usize,
    /// When the next datagram may go, while it waits.
    hold: Option<Duration>,
    /// Client: when to ask again.
    deadline: Option<Duration>,
    tries: u32,
    last_sent: Vec<u8>,
    /// Client: when the request now waiting for an answer first went out.
    asked_at: Option<Duration>,
    last_rx: Duration,
    /// The last datagram from the other end that the program took: the
    /// server's last request, the client's last answer.
    last_req: Vec<u8>,
    /// The application protocol's session, for templates that play one.
    app: Option<Box<dyn AppSession>>,
    /// Datagrams the session made that wait to go: the client's request,
    /// the server's answer.
    app_out: Vec<Vec<u8>>,
    /// Whether `start` was called (client).
    app_started: bool,
    /// The fit of a datagram the server's new session already took.
    app_fit: Option<(bool, bool)>,
    mismatched: bool,
    error: bool,
    /// Server: everything played; the session stays to answer repeats.
    done: bool,
    /// The earliest time the session is queued for in the engine's timers
    /// (`Duration::MAX`: not queued).
    scheduled: Duration,
    /// The protocol plays a whole dialog (see [`crate::AppProtocol::dialog`]).
    dialog: bool,
    /// Dialogs: when the protocol wants its timer.
    wake: Option<Duration>,
    /// Dialogs: the first of the session's media ports, and how many.
    media: Option<(u16, u16)>,
    /// Dialogs: the protocol took the last datagram.
    taken: bool,
}

/// Small, fast, seeded random numbers for DNS ids.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// The media ports sessions hold: (address, port) to the session's key.
#[derive(Default)]
struct MediaPorts {
    held: HashMap<SocketAddr, Key>,
    cursor: u32,
}

impl MediaPorts {
    /// `n` consecutive free ports on `ip` from `range`, the first a
    /// multiple of `n` from the range's start, held for `key`.
    fn take(&mut self, range: &Range<u16>, ip: IpAddr, n: u16, key: Key) -> Option<u16> {
        let n = n.max(1);
        let slots = u32::from(range.end.saturating_sub(range.start)) / u32::from(n);
        for _ in 0..slots {
            let slot = self.cursor % slots;
            self.cursor = self.cursor.wrapping_add(1);
            let first = range.start + (slot * u32::from(n)) as u16;
            if (0..n).all(|i| !self.held.contains_key(&SocketAddr::new(ip, first + i))) {
                for i in 0..n {
                    self.held.insert(SocketAddr::new(ip, first + i), key);
                }
                return Some(first);
            }
        }
        None
    }

    fn free(&mut self, s: &Session) {
        if let Some((first, n)) = s.media {
            for i in 0..n {
                self.held.remove(&SocketAddr::new(s.path.src, first + i));
            }
        }
    }
}

/// What the engine shares with a session while it handles an event.
struct Ctx<'a> {
    templates: &'a [UdpTemplate],
    plans: &'a [Vec<Step>],
    options: &'a UdpOptions,
    out: &'a mut Vec<(usize, Vec<u8>)>,
    ip_id: &'a mut u16,
    stats: &'a mut UdpStats,
    media: &'a mut MediaPorts,
}

impl Ctx<'_> {
    fn add(&mut self, role: UdpRole, tpl: usize, f: impl Fn(&mut UdpSideStats)) {
        self.stats.add(role, tpl, f);
    }

    fn send(&mut self, s: &Session, data: &[u8]) {
        self.send_ports(s, s.lport, s.rport, data);
    }

    fn send_ports(&mut self, s: &Session, lport: u16, rport: u16, data: &[u8]) {
        *self.ip_id = self.ip_id.wrapping_add(1);
        self.out.push((
            s.port,
            wire::udp_frame(&s.path, lport, rport, data, *self.ip_id),
        ));
        let n = data.len() as u64;
        self.add(s.role, s.tpl, |c| {
            c.datagrams_tx += 1;
            c.payload_tx += n;
        });
    }
}

/// How a datagram fits the step a session waits for.
enum Fit {
    /// It is the datagram; `ok` false when it differs from what was
    /// expected, `error` for an error answer.
    Yes { ok: bool, error: bool },
    /// It belongs to something else.
    No,
}

impl Session {
    fn steps<'a>(&self, cx: &'a Ctx) -> &'a [Step] {
        &cx.plans[self.tpl]
    }

    fn waiting(&self, cx: &Ctx) -> bool {
        self.steps(cx)
            .get(self.step)
            .is_some_and(|s| s.from != self.role)
    }

    /// What this end sends at the current step.
    fn payload(&mut self, cx: &mut Ctx, now: Duration) -> Option<Vec<u8>> {
        match &cx.templates[self.tpl].app {
            UdpApp::Replay(p) => p.messages.get(self.step).map(|m| m.data.clone()),
            UdpApp::App(_) => {
                if self.role == UdpRole::Client && !self.app_started {
                    self.app_started = true;
                    let mut ax = AppCx::new(now, cx.options.clock + now);
                    if let Some(a) = self.app.as_mut() {
                        a.start(&mut ax);
                    }
                    self.app_out.extend(ax.take_sends());
                    cx.stats
                        .add(self.role, self.tpl, |s| ax.count_into(&mut s.app));
                }
                if self.app_out.is_empty() {
                    None
                } else {
                    Some(self.app_out.remove(0))
                }
            }
        }
    }

    /// Whether `data` is the datagram the current step waits for.
    fn fits(&mut self, cx: &mut Ctx, data: &[u8], now: Duration) -> Fit {
        match &cx.templates[self.tpl].app {
            UdpApp::Replay(p) => {
                let expected = p.messages.get(self.step).map(|m| m.data.as_slice());
                Fit::Yes {
                    ok: !cx.options.verify || expected == Some(data),
                    error: false,
                }
            }
            UdpApp::App(_) => {
                if let Some((ok, error)) = self.app_fit.take() {
                    return Fit::Yes { ok, error };
                }
                let Some(a) = self.app.as_mut() else {
                    return Fit::No;
                };
                let mut ax = AppCx::new(now, cx.options.clock + now);
                if a.receive(data, &mut ax) == Receive::NotMine {
                    return Fit::No;
                }
                self.app_out.extend(ax.take_sends());
                let (ok, error) = (ax.all_ok(), ax.any_error());
                let rt = self.asked_at.map(|at| now.saturating_sub(at));
                let (role, tpl) = (self.role, self.tpl);
                cx.stats.add(role, tpl, |s| {
                    for t in ax.transactions() {
                        let mut t = t.clone();
                        if role == UdpRole::Client && t.response_time.is_none() {
                            t.response_time = rt;
                        }
                        s.app.record(&t);
                    }
                    s.app.protocol_errors += ax.protocol_errors().len() as u64;
                    for e in ax.protocol_errors() {
                        s.app.sample_error(e);
                    }
                });
                Fit::Yes { ok, error }
            }
        }
    }

    /// Dialogs: calls the protocol's session with `f` and does what it
    /// asks: sends its datagrams, keeps its timer, counts what it did, ends
    /// the session or (a server's) opens it again.
    fn dialog_call(
        &mut self,
        cx: &mut Ctx,
        now: Duration,
        f: impl FnOnce(&mut dyn AppSession, &mut AppCx) -> Receive,
    ) -> Fate {
        let Some(mut app) = self.app.take() else {
            return Fate::Remove;
        };
        let mut ax =
            AppCx::new(now, cx.options.clock + now).with_media_port(self.media.map(|m| m.0));
        let r = f(&mut *app, &mut ax);
        self.app = Some(app);
        self.taken = r == Receive::Taken;
        if r == Receive::NotMine {
            if self.done && self.role == UdpRole::Server {
                return Fate::Replace;
            }
            cx.add(self.role, self.tpl, |s| s.unmatched += 1);
            return Fate::Keep;
        }
        // Media first: a stream's last RTCP before the BYE or its answer.
        for (from, to, d) in ax.take_media_sends() {
            if self
                .media
                .is_some_and(|(first, n)| (first..first + n).contains(&from))
            {
                cx.send_ports(self, from, to, &d);
            }
        }
        for d in ax.take_sends() {
            cx.send(self, &d);
        }
        if let Some(w) = ax.wake() {
            self.wake = Some(w);
        }
        let (role, tpl) = (self.role, self.tpl);
        let resent = ax.resent_count();
        cx.add(role, tpl, |s| {
            ax.count_into(&mut s.app);
            s.retries += resent;
        });
        if self.done && self.role == UdpRole::Server && !ax.wants_close() {
            // Something new on a finished server session.
            self.done = false;
            self.mismatched = false;
            self.error = false;
            cx.add(role, tpl, |s| {
                s.sent += 1;
                s.active += 1;
            });
        }
        self.mismatched |= !ax.all_ok();
        self.error |= ax.any_error();
        if ax.wants_close() {
            return self.finish(cx, now);
        }
        Fate::Keep
    }

    /// Dialogs: a datagram on the session's addresses.
    fn dialog_datagram(&mut self, cx: &mut Ctx, data: &[u8], now: Duration) -> Fate {
        let n = data.len() as u64;
        cx.add(self.role, self.tpl, |s| {
            s.datagrams_rx += 1;
            s.payload_rx += n;
        });
        self.last_rx = now;
        self.dialog_call(cx, now, |a, ax| a.receive(data, ax))
    }

    /// Dialogs: a datagram on one of the session's media ports.
    fn on_media(
        &mut self,
        cx: &mut Ctx,
        port: u16,
        from: SocketAddr,
        data: &[u8],
        now: Duration,
    ) -> Fate {
        let n = data.len() as u64;
        cx.add(self.role, self.tpl, |s| {
            s.datagrams_rx += 1;
            s.payload_rx += n;
        });
        self.last_rx = now;
        self.dialog_call(cx, now, |a, ax| {
            a.media(port, from, data, ax);
            Receive::Taken
        })
    }

    fn dialog_timer(&mut self, cx: &mut Ctx, now: Duration) -> Fate {
        if self.wake.is_some_and(|w| now >= w) {
            self.wake = None;
            let f = self.dialog_call(cx, now, |a, ax| {
                a.timer(ax);
                Receive::Taken
            });
            if f != Fate::Keep {
                return f;
            }
        }
        if self.wake.is_some() || now.saturating_sub(self.last_rx) < cx.options.session_timeout {
            return Fate::Keep;
        }
        if !self.done {
            cx.add(self.role, self.tpl, |s| {
                s.timed_out += 1;
                s.active = s.active.saturating_sub(1);
            });
        }
        Fate::Remove
    }

    /// Plays the session as far as it can go now.
    fn advance(&mut self, cx: &mut Ctx, now: Duration) -> Fate {
        loop {
            let Some(step) = self.steps(cx).get(self.step).copied() else {
                return self.finish(cx, now);
            };
            if step.from != self.role {
                return Fate::Keep;
            }
            if !step.wait.is_zero() {
                match self.hold {
                    None => {
                        self.hold = Some(now + step.wait);
                        return Fate::Keep;
                    }
                    Some(t) if now < t => return Fate::Keep,
                    Some(_) => self.hold = None,
                }
            }
            let Some(data) = self.payload(&mut *cx, now) else {
                // Nothing to send (a request the server cannot answer).
                self.step = self.steps(cx).len();
                continue;
            };
            cx.send(self, &data);
            self.last_sent = data;
            self.step += 1;
            if self.waiting(cx) && self.role == UdpRole::Client {
                self.asked_at = Some(now);
                self.deadline = Some(now + cx.options.timeout);
                self.tries = 0;
            }
        }
    }

    /// The program is over: count it.
    fn finish(&mut self, cx: &mut Ctx, now: Duration) -> Fate {
        if !self.done {
            self.done = true;
            let (m, e) = (u64::from(self.mismatched), u64::from(self.error));
            cx.add(self.role, self.tpl, |s| {
                s.answered += 1;
                s.active = s.active.saturating_sub(1);
                s.mismatched += m;
                s.errors += e;
            });
        }
        self.deadline = None;
        match self.role {
            // A dialog client lingers, to answer what the server sends
            // again (a refusal whose ACK was lost), until it is quiet for
            // the session timeout; it no longer holds the run open.
            UdpRole::Client if self.dialog => {
                // Its media ports go back now: the call is over.
                cx.media.free(self);
                self.media = None;
                self.wake = None;
                self.last_rx = self.last_rx.max(now);
                Fate::Keep
            }
            UdpRole::Client => Fate::Remove,
            UdpRole::Server => {
                self.last_rx = self.last_rx.max(now);
                Fate::Keep
            }
        }
    }

    fn on_datagram(&mut self, cx: &mut Ctx, data: &[u8], now: Duration) -> Fate {
        if self.dialog {
            return self.dialog_datagram(cx, data, now);
        }
        let n = data.len() as u64;
        cx.add(self.role, self.tpl, |s| {
            s.datagrams_rx += 1;
            s.payload_rx += n;
        });
        if self.role == UdpRole::Server && self.step > 0 && data == self.last_req.as_slice() {
            // A request again: our answer was lost, or is still held back.
            // `last_sent` is only set once we answered this request, so the
            // answer goes again also while we already wait for the next one.
            if self.hold.is_none() && !self.last_sent.is_empty() {
                let again = self.last_sent.clone();
                cx.send(self, &again);
                cx.add(self.role, self.tpl, |s| s.retries += 1);
            } else {
                cx.add(self.role, self.tpl, |s| s.duplicates += 1);
            }
            self.last_rx = now;
            return Fate::Keep;
        }
        if !self.waiting(cx) {
            if self.role == UdpRole::Client && !self.last_sent.is_empty() {
                cx.add(self.role, self.tpl, |s| s.duplicates += 1);
            } else {
                cx.add(self.role, self.tpl, |s| s.unmatched += 1);
            }
            return Fate::Keep;
        }
        match self.fits(cx, data, now) {
            Fit::No => {
                cx.add(self.role, self.tpl, |s| s.unmatched += 1);
                Fate::Keep
            }
            Fit::Yes { ok: false, .. }
                if self.role == UdpRole::Client && self.step > 0 && data == self.last_req =>
            {
                // The previous answer again: the server answered a request
                // we asked again whose first answer was only late.
                cx.add(self.role, self.tpl, |s| s.duplicates += 1);
                Fate::Keep
            }
            Fit::Yes { ok, error } => {
                self.mismatched |= !ok;
                self.error |= error;
                self.last_rx = now;
                self.deadline = None;
                if let Some(at) = self.asked_at.take() {
                    let rt = now.saturating_sub(at);
                    cx.add(self.role, self.tpl, |s| s.response_time.record(Some(rt)));
                }
                self.last_req = data.to_vec();
                if self.role == UdpRole::Server {
                    // Not answered yet: a repeat of it is not answered with
                    // an older answer.
                    self.last_sent.clear();
                }
                self.step += 1;
                self.advance(cx, now)
            }
        }
    }

    /// When [`on_timer`](Self::on_timer) next has something to do.
    fn next_wake(&self, o: &UdpOptions) -> Duration {
        if self.dialog {
            return self
                .wake
                .unwrap_or_else(|| self.last_rx.saturating_add(o.session_timeout));
        }
        let mut at = self.hold.unwrap_or(Duration::MAX);
        match self.role {
            UdpRole::Server => at = at.min(self.last_rx.saturating_add(o.session_timeout)),
            UdpRole::Client => {
                if let Some(d) = self.deadline {
                    at = at.min(d);
                }
            }
        }
        at
    }

    fn on_timer(&mut self, cx: &mut Ctx, now: Duration) -> Fate {
        if self.dialog {
            return self.dialog_timer(cx, now);
        }
        if self.hold.is_some_and(|t| now >= t) && self.advance(cx, now) == Fate::Remove {
            return Fate::Remove;
        }
        match self.role {
            UdpRole::Server => {
                if now.saturating_sub(self.last_rx) < cx.options.session_timeout {
                    return Fate::Keep;
                }
                if !self.done {
                    cx.add(self.role, self.tpl, |s| {
                        s.timed_out += 1;
                        s.active = s.active.saturating_sub(1);
                    });
                }
                Fate::Remove
            }
            UdpRole::Client => {
                let Some(deadline) = self.deadline else {
                    return Fate::Keep;
                };
                if now < deadline {
                    return Fate::Keep;
                }
                self.tries += 1;
                if self.tries > cx.options.retries {
                    cx.add(self.role, self.tpl, |s| {
                        s.timed_out += 1;
                        s.active = s.active.saturating_sub(1);
                    });
                    return Fate::Remove;
                }
                let again = self.last_sent.clone();
                cx.send(self, &again);
                cx.add(self.role, self.tpl, |s| s.retries += 1);
                self.deadline = Some(now + cx.options.timeout);
                Fate::Keep
            }
        }
    }
}

/// Emulated UDP clients and servers that play request/response transactions.
///
/// Each client transaction gets its own source address and port, so a NAT
/// router or a firewall in between sees each as a flow of its own. The
/// client asks again when an answer is late, up to `retries` times; the
/// server answers a repeated request with its answer again.
///
/// Feed it frames with [`handle_frame`](Self::handle_frame), call
/// [`poll`](Self::poll) often and send what [`take_output`](Self::take_output)
/// returns; [`UdpJob`](crate::UdpJob) does this on real ports.
///
/// ```
/// use ferotrx_core::*;
/// use std::sync::Arc;
///
/// let (a, b) = memory_ports();
/// let dns = DnsWorkload::parse(&["www.lab.local AAAA"], &["www.lab.local AAAA fd00::80"]).unwrap();
/// let ep = |port, last: u8| UdpEndpoint::new(port, MacAddr([2, 0, 0, 0, 0, last]), format!("10.0.0.{last}").parse().unwrap());
/// let mut client = UdpClientConfig::new(ep(0, 1));
/// client.transactions = 20;
/// client.rate = 1000.0;
/// let engine = UdpEngine::new(UdpConfig {
///     templates: vec![UdpTemplate::new(UdpApp::dns(Arc::new(dns)), "10.0.0.2:53".parse().unwrap())],
///     client: Some(client),
///     server: Some(UdpServerConfig::new(ep(1, 2))),
///     options: UdpOptions::default(),
/// }).unwrap();
/// let job = UdpJob::spawn(engine, vec![Box::new(a), Box::new(b)], TcpRunConfig::default()).unwrap();
/// let stats = job.join().unwrap();
/// assert_eq!(stats.client.answered, 20);
/// assert_eq!(stats.server.answered, 20);
/// assert_eq!(stats.client.response_time.count(), 20);
/// ```
pub struct UdpEngine {
    templates: Vec<UdpTemplate>,
    plans: Vec<Vec<Step>>,
    options: UdpOptions,
    listen: HashMap<u16, usize>,
    client: Option<UdpClientConfig>,
    hosts: Vec<Host>,
    sessions: HashMap<Key, Session>,
    media: MediaPorts,
    /// When sessions need their timers looked at; only the entry at a
    /// session's `scheduled` time counts.
    timers: BinaryHeap<Reverse<(Duration, Key)>>,
    out: Vec<(usize, Vec<u8>)>,
    ip_id: u16,
    stats: UdpStats,
    rng: Rng,
    txn_clock: EventClock,
    port_cursor: u64,
    wrr: Vec<i64>,
    opened: Vec<u64>,
    tpl_clock: Vec<Option<EventClock>>,
    txn_count: u64,
    next_timer_scan: Duration,
    error: Option<String>,
    started: bool,
}

/// How often session timers are looked at.
const TIMER_TICK: Duration = Duration::from_millis(1);

fn udp_err(e: Error) -> Error {
    match e {
        Error::Tcp(m) => Error::Udp(m),
        e => e,
    }
}

impl UdpEngine {
    pub fn new(config: UdpConfig) -> Result<Self> {
        let UdpConfig {
            templates,
            client,
            server,
            options,
        } = config;
        if client.is_none() && server.is_none() {
            return Err(Error::Udp("give a client, a server or both".into()));
        }
        if templates.is_empty() {
            return Err(Error::Udp("give at least one template".into()));
        }
        if options.timeout.is_zero() {
            return Err(Error::Udp("the timeout must be more than zero".into()));
        }
        if options.session_timeout.is_zero() {
            return Err(Error::Udp(
                "the session timeout must be more than zero".into(),
            ));
        }
        let mut listen = HashMap::new();
        for (i, t) in templates.iter().enumerate() {
            let what = format!("template {}", t.name);
            match &t.app {
                UdpApp::Replay(p) => p.validate().map_err(|e| {
                    Error::Udp(format!(
                        "{what}: {}",
                        e.to_string().trim_start_matches("udp: ")
                    ))
                })?,
                UdpApp::App(a) => {
                    let check = |role| {
                        a.validate(role, Transport::Datagram).map_err(|e| {
                            Error::Udp(format!(
                                "{what}: {}",
                                e.to_string().trim_start_matches("profile: ")
                            ))
                        })
                    };
                    if server.is_some() {
                        check(AppRole::Server)?;
                    }
                    if client.is_some() && t.weight > 0 {
                        check(AppRole::Client)?;
                    }
                }
            }
            if t.connect_ips == 0 {
                return Err(Error::Udp(format!(
                    "{what}: connect_ips must be at least 1"
                )));
            }
            let ip = t.connect.ip();
            if ip_max(ip) - ip_num(ip) < u128::from(t.connect_ips - 1) {
                return Err(Error::Udp(format!(
                    "{what}: server address range from {ip} runs past the last {} address",
                    ip_version(ip)
                )));
            }
            if let Some(c) = &client {
                if t.weight > 0 && ip.is_ipv4() != c.endpoint.ip.is_ipv4() {
                    return Err(Error::Udp(format!(
                        "{what}: the client is {} ({}) but sends to {} address {ip}",
                        ip_version(c.endpoint.ip),
                        c.endpoint.ip,
                        ip_version(ip)
                    )));
                }
                if t.connect.port() == 0 {
                    return Err(Error::Udp(format!("{what}: send to port 0")));
                }
            }
            if let Some(r) = t.rate {
                if !(r.is_finite() && r > 0.0) {
                    return Err(Error::Udp(format!(
                        "{what}: transactions per second must be more than 0, not {r}"
                    )));
                }
            } else if !t.model.is_steady() {
                return Err(Error::Udp(format!(
                    "{what}: a traffic model needs the template's own rate"
                )));
            }
            t.model
                .validate()
                .map_err(|e| Error::Udp(format!("{what}: {e}")))?;
            if server.is_some() {
                if let Some(j) = listen.insert(t.listen_port, i) {
                    return Err(Error::Udp(format!(
                        "templates {} and {} both listen on port {}; the server tells \
                         templates apart by port",
                        templates[j].name, t.name, t.listen_port
                    )));
                }
            }
        }
        let mut hosts = Vec::new();
        if let Some(c) = &client {
            c.endpoint.validate("client").map_err(udp_err)?;
            if !(c.rate.is_finite() && c.rate > 0.0) {
                return Err(Error::Udp(format!(
                    "transactions per second must be more than 0, not {}",
                    c.rate
                )));
            }
            c.model.validate().map_err(|e| Error::Udp(e.to_string()))?;
            if c.source_ports.is_empty() || c.source_ports.start == 0 {
                return Err(Error::Udp("the source port range is empty".into()));
            }
            if templates.iter().all(|t| t.weight == 0) {
                return Err(Error::Udp(
                    "every template has weight 0: the client has nothing to send".into(),
                ));
            }
            let mut hops: Vec<(IpAddr, Option<crate::MacAddr>)> = Vec::new();
            for t in templates.iter().filter(|t| t.weight > 0) {
                for n in 0..u64::from(t.connect_ips) {
                    let hop = c.endpoint.next_hop(t.nth_server(n));
                    if !hops.iter().any(|(h, _)| *h == hop) {
                        if hops.len() == MAX_HOPS {
                            return Err(Error::Udp(format!(
                                "the client reaches more than {MAX_HOPS} servers directly; \
                                 give it a gateway"
                            )));
                        }
                        hops.push((hop, c.endpoint.next_hop_mac));
                    }
                }
            }
            hosts.push(Host::new(UdpRole::Client, c.endpoint.clone(), hops));
        }
        if let Some(s) = &server {
            s.endpoint.validate("server").map_err(udp_err)?;
            if let Some(c) = &client {
                let (a, b) = (&c.endpoint, &s.endpoint);
                if a.port == b.port && a.vlan == b.vlan && (a.owns(b.ip) || b.owns(a.ip)) {
                    return Err(Error::Udp(
                        "the client and the server share an address on the same port and VLAN"
                            .into(),
                    ));
                }
                if a.port == b.port && a.vlan == b.vlan && a.mac == b.mac {
                    return Err(Error::Udp(format!(
                        "the client and the server both use MAC {} on the same port and VLAN; \
                         give one of them another MAC",
                        a.mac
                    )));
                }
            }
            hosts.push(Host::new(UdpRole::Server, s.endpoint.clone(), Vec::new()));
        }
        let stats = UdpStats {
            templates: templates
                .iter()
                .map(|t| UdpTemplateStats {
                    name: t.name.clone(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        let n = templates.len();
        Ok(Self {
            plans: templates.iter().map(|t| plan(t, &options)).collect(),
            tpl_clock: templates
                .iter()
                .map(|t| t.rate.map(|r| EventClock::new(r, &t.model)))
                .collect(),
            txn_clock: client.as_ref().map_or_else(
                || EventClock::new(1.0, &TrafficModel::default()),
                |c| EventClock::new(c.rate, &c.model),
            ),
            rng: Rng(options.seed | 1),
            options,
            templates,
            listen,
            client,
            hosts,
            sessions: HashMap::new(),
            media: MediaPorts::default(),
            timers: BinaryHeap::new(),
            out: Vec::new(),
            ip_id: 0,
            stats,
            port_cursor: 0,
            wrr: vec![0; n],
            opened: vec![0; n],
            txn_count: 0,
            next_timer_scan: Duration::ZERO,
            error: None,
            started: false,
        })
    }

    /// The templates, in the order of [`UdpStats::templates`].
    pub fn templates(&self) -> &[UdpTemplate] {
        &self.templates
    }

    /// The MAC addresses of the emulated hosts on port `port`: the frames the
    /// port must receive, besides broadcasts and multicasts.
    pub fn port_macs(&self, port: usize) -> Vec<crate::MacAddr> {
        let mut macs: Vec<crate::MacAddr> = Vec::new();
        for h in self.hosts.iter().filter(|h| h.ep.port == port) {
            if !macs.contains(&h.ep.mac) {
                macs.push(h.ep.mac);
            }
        }
        macs
    }

    pub fn stats(&self) -> &UdpStats {
        &self.stats
    }

    /// Sets the elapsed time and stop flag in the counters.
    pub fn set_elapsed(&mut self, elapsed: Duration, stopped: bool) {
        self.stats.elapsed = elapsed;
        self.stats.stopped = stopped;
    }

    /// Sets the frames the ports dropped before the engine read them.
    pub fn set_rx_dropped(&mut self, frames: u64) {
        self.stats.rx_dropped = frames;
    }

    /// Puts what the ports' impairments did in the counters.
    pub fn set_impairments(&mut self, stats: &crate::PortImpairStats) {
        self.stats.impair = stats.clone();
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

    /// The error that stopped the engine, such as an unanswered ARP request.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// True when the client has started all its transactions and they have
    /// ended, and no server session waits for a client. Never true without
    /// a client or with an endless one.
    pub fn is_done(&self) -> bool {
        let Some(c) = &self.client else {
            return false;
        };
        let all = c.transactions > 0 && self.stats.client.sent >= c.transactions;
        // Or every template has started all of its own, or its traffic
        // model's ramp has ended.
        let each = (0..self.templates.len()).all(|i| {
            self.exhausted(i)
                || self.tpl_clock[i]
                    .as_ref()
                    .unwrap_or(&self.txn_clock)
                    .ended()
        });
        (all || each)
            && self
                .sessions
                .values()
                .all(|s| s.done && (s.role == UdpRole::Server || s.dialog))
    }

    /// Transactions open now, both sides.
    pub fn open_transactions(&self) -> usize {
        self.sessions.values().filter(|s| !s.done).count()
    }

    fn ctx(&mut self) -> (Ctx<'_>, &mut HashMap<Key, Session>) {
        (
            Ctx {
                templates: &self.templates,
                plans: &self.plans,
                options: &self.options,
                out: &mut self.out,
                ip_id: &mut self.ip_id,
                stats: &mut self.stats,
                media: &mut self.media,
            },
            &mut self.sessions,
        )
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
            wire::ETHERTYPE_ARP => {
                hosts::on_arp(&mut self.hosts, &mut self.out, port, &link, payload)
            }
            ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => self.on_ip(port, &link, payload, now),
            _ => {}
        }
    }

    fn on_ip(&mut self, port: usize, link: &wire::Link, payload: &[u8], now: Duration) {
        let Some(ip) = wire::parse_ip(payload, true) else {
            return;
        };
        if (link.ethertype == ETHERTYPE_IPV4) != ip.src.is_ipv4() {
            return;
        }
        if ip.proto == IPPROTO_ICMPV6 && ip.src.is_ipv6() {
            if let Some(nd) = wire::parse_ndp(&ip) {
                hosts::on_ndp(&mut self.hosts, &mut self.out, port, link, &ip, &nd);
                return;
            }
        }
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
            1 | IPPROTO_ICMPV6 => {
                self.ip_id = self.ip_id.wrapping_add(1);
                if let Some(f) = wire::icmp_echo_reply(&path, ip.payload, self.ip_id) {
                    self.out.push((port, f));
                }
            }
            17 => {
                if let Some(d) = wire::parse_udp(&ip, true) {
                    let role = self.hosts[h].role;
                    self.on_udp(role, port, path, &d, now);
                }
            }
            _ => {}
        }
    }

    fn on_udp(
        &mut self,
        role: UdpRole,
        port: usize,
        path: Path,
        d: &wire::Datagram,
        now: Duration,
    ) {
        let key = (
            SocketAddr::new(path.src, d.dport),
            SocketAddr::new(path.dst, d.sport),
        );
        let listening = match role {
            UdpRole::Server => self.listen.get(&d.dport).copied(),
            UdpRole::Client => None,
        };
        let (mut cx, sessions) = self.ctx();
        if let Some(s) = sessions.get_mut(&key) {
            // A finished server session that gets another request starts a
            // new transaction on the same ports.
            let fresh =
                !s.dialog && s.role == UdpRole::Server && s.done && d.data != s.last_req.as_slice();
            if !fresh {
                match s.on_datagram(&mut cx, d.data, now) {
                    Fate::Keep => {
                        self.schedule(key);
                        return;
                    }
                    Fate::Remove => {
                        if let Some(s) = sessions.remove(&key) {
                            cx.media.free(&s);
                        }
                        return;
                    }
                    Fate::Replace => {}
                }
            }
            if let Some(s) = sessions.remove(&key) {
                cx.media.free(&s);
            }
        } else if let Some(&owner) = cx.media.held.get(&key.0) {
            // On a session's media port.
            if let Some(s) = sessions.get_mut(&owner) {
                let fate = s.on_media(&mut cx, d.dport, key.1, d.data, now);
                if fate == Fate::Remove {
                    if let Some(s) = sessions.remove(&owner) {
                        cx.media.free(&s);
                    }
                } else {
                    self.schedule(owner);
                }
            }
            return;
        }
        let Some(tpl) = listening else {
            let n = d.data.len() as u64;
            cx.add(role, usize::MAX, |s| {
                s.datagrams_rx += 1;
                s.payload_rx += n;
                s.unmatched += 1;
            });
            return;
        };
        let mut s = Session {
            role,
            tpl,
            port,
            path,
            lport: d.dport,
            rport: d.sport,
            step: 0,
            hold: None,
            deadline: None,
            tries: 0,
            last_sent: Vec::new(),
            asked_at: None,
            last_rx: now,
            last_req: Vec::new(),
            app: match &cx.templates[tpl].app {
                UdpApp::App(a) => Some(a.session(&SessionInit {
                    role: AppRole::Server,
                    transport: Transport::Datagram,
                    index: 0,
                    seed: (now.as_nanos() as u64) ^ (u64::from(d.sport) << 32),
                    local: key.0,
                    remote: key.1,
                })),
                UdpApp::Replay(_) => None,
            },
            app_out: Vec::new(),
            app_started: true,
            app_fit: None,
            mismatched: false,
            error: false,
            done: false,
            scheduled: Duration::MAX,
            dialog: false,
            wake: None,
            media: None,
            taken: false,
        };
        if let UdpApp::App(a) = &cx.templates[tpl].app {
            if a.protocol().dialog() {
                s.dialog = true;
                let n = a.protocol().media_ports();
                if n > 0 {
                    let Some(first) = cx.media.take(&cx.options.media_ports, key.0.ip(), n, key)
                    else {
                        cx.add(role, tpl, |c| c.unmatched += 1);
                        return;
                    };
                    s.media = Some((first, n));
                }
                cx.add(role, tpl, |c| {
                    c.sent += 1;
                    c.active += 1;
                });
                match s.on_datagram(&mut cx, d.data, now) {
                    Fate::Keep if s.taken => {
                        sessions.insert(key, s);
                        self.schedule(key);
                    }
                    Fate::Keep => {
                        // Not for us after all.
                        cx.media.free(&s);
                        cx.add(role, tpl, |c| {
                            c.sent -= 1;
                            c.active -= 1;
                        });
                    }
                    _ => cx.media.free(&s),
                }
                return;
            }
        }
        // Only a datagram that can start the transaction opens a session.
        match s.fits(&mut cx, d.data, now) {
            Fit::No => {
                let n = d.data.len() as u64;
                cx.add(role, tpl, |c| {
                    c.datagrams_rx += 1;
                    c.payload_rx += n;
                    c.unmatched += 1;
                });
                return;
            }
            // The protocol's session took it already: the step after
            // reads this instead of handing the datagram over again.
            Fit::Yes { ok, error } if s.app.is_some() => s.app_fit = Some((ok, error)),
            Fit::Yes { .. } => {}
        }
        cx.add(role, tpl, |c| {
            c.sent += 1;
            c.active += 1;
        });
        if s.on_datagram(&mut cx, d.data, now) == Fate::Keep {
            sessions.insert(key, s);
            self.schedule(key);
        }
    }

    /// Queues session `key` for when it next needs its timer, if that is
    /// sooner than it is queued for.
    fn schedule(&mut self, key: Key) {
        if let Some(s) = self.sessions.get_mut(&key) {
            let wake = s.next_wake(&self.options);
            if wake < s.scheduled {
                s.scheduled = wake;
                self.timers.push(Reverse((wake, key)));
            }
        }
    }

    fn run_timers(&mut self, now: Duration) {
        while let Some(&Reverse((at, key))) = self.timers.peek() {
            if at > now {
                break;
            }
            self.timers.pop();
            let (mut cx, sessions) = self.ctx();
            let Some(s) = sessions.get_mut(&key) else {
                continue; // gone
            };
            if s.scheduled != at {
                continue; // queued again since, for another time
            }
            s.scheduled = Duration::MAX;
            if s.on_timer(&mut cx, now) == Fate::Keep {
                let wake = s.next_wake(cx.options).max(now + TIMER_TICK);
                s.scheduled = wake;
                self.timers.push(Reverse((wake, key)));
            } else if let Some(s) = sessions.remove(&key) {
                cx.media.free(&s);
            }
        }
    }

    /// Runs timers, resolves the client's next hops and starts transactions.
    pub fn poll(&mut self, now: Duration) {
        if self.error.is_some() {
            return;
        }
        if !self.started {
            self.started = true;
            self.txn_clock.start(now);
            for clock in self.tpl_clock.iter_mut().flatten() {
                clock.start(now);
            }
        }
        self.error = hosts::resolve(
            &mut self.hosts,
            &mut self.out,
            now,
            self.options.arp_timeout,
        );
        if self.error.is_some() {
            return;
        }
        if now >= self.next_timer_scan {
            self.next_timer_scan = now + TIMER_TICK;
            self.run_timers(now);
        }
        self.start_due(now);
    }

    fn ready(&self, tpl: usize) -> bool {
        let t = &self.templates[tpl];
        t.weight > 0
            && (t.transactions == 0 || self.opened[tpl] < t.transactions)
            && (t.concurrency == 0
                || (self.stats.templates[tpl].client.active as usize) < t.concurrency)
    }

    fn exhausted(&self, tpl: usize) -> bool {
        let t = &self.templates[tpl];
        t.weight == 0 || (t.transactions > 0 && self.opened[tpl] >= t.transactions)
    }

    fn start_due(&mut self, now: Duration) {
        let Some(client) = &self.client else { return };
        if !self.hosts[0].resolved() {
            return;
        }
        let (total, concurrency) = (client.transactions, client.concurrency);
        let room = |e: &Self| {
            !(total > 0 && e.stats.client.sent >= total)
                && !(concurrency > 0 && e.stats.client.active as usize >= concurrency)
        };
        for tpl in 0..self.templates.len() {
            let mut started = 0;
            while self.tpl_clock[tpl].as_ref().is_some_and(|c| c.due(now))
                && started < 256
                && !self.exhausted(tpl)
            {
                if !room(self) || !self.ready(tpl) {
                    if let Some(c) = &mut self.tpl_clock[tpl] {
                        c.hold(now);
                    }
                    break;
                }
                if !self.start_one(tpl, now) {
                    break;
                }
                if let Some(c) = &mut self.tpl_clock[tpl] {
                    c.advance();
                }
                started += 1;
            }
        }
        let shared: Vec<usize> = (0..self.templates.len())
            .filter(|&i| self.templates[i].rate.is_none() && !self.exhausted(i))
            .collect();
        if shared.is_empty() {
            return;
        }
        let mut started = 0;
        while self.txn_clock.due(now) && started < 256 {
            if total > 0 && self.stats.client.sent >= total {
                return;
            }
            let ready: Vec<usize> = shared.iter().copied().filter(|&i| self.ready(i)).collect();
            if !room(self) || ready.is_empty() {
                self.txn_clock.hold(now);
                return;
            }
            let tpl = self.pick(&ready);
            if !self.start_one(tpl, now) {
                self.unpick(tpl, &ready);
                return;
            }
            self.txn_clock.advance();
            started += 1;
        }
    }

    /// Smooth weighted round robin, as for TCP templates.
    fn pick(&mut self, ready: &[usize]) -> usize {
        let total: i64 = ready
            .iter()
            .map(|&i| i64::from(self.templates[i].weight))
            .sum();
        let mut best = ready[0];
        for &i in ready {
            self.wrr[i] += i64::from(self.templates[i].weight);
            if self.wrr[i] > self.wrr[best] {
                best = i;
            }
        }
        self.wrr[best] -= total;
        best
    }

    fn unpick(&mut self, tpl: usize, ready: &[usize]) {
        let total: i64 = ready
            .iter()
            .map(|&i| i64::from(self.templates[i].weight))
            .sum();
        self.wrr[tpl] += total;
        for &i in ready {
            self.wrr[i] -= i64::from(self.templates[i].weight);
        }
    }

    fn start_one(&mut self, tpl: usize, now: Duration) -> bool {
        let Some(client) = &self.client else {
            return false;
        };
        let ep = client.endpoint.clone();
        let ports = client.source_ports.clone();
        let t = &self.templates[tpl];
        let to = SocketAddr::new(t.nth_server(self.opened[tpl]), t.connect.port());
        let Some(mac) = self.hosts[0].hop_mac(ep.next_hop(to.ip())) else {
            return false;
        };
        let span = u64::from(ports.end - ports.start);
        let count = u64::from(ep.ip_count);
        let mut found = None;
        for _ in 0..(span * count).min(1 << 20) {
            let k = self.port_cursor;
            self.port_cursor = self.port_cursor.wrapping_add(1);
            let ip = ep.nth_ip((k % count) as u32);
            let port = ports.start + ((k / count) % span) as u16;
            let key = (SocketAddr::new(ip, port), to);
            if !self.sessions.contains_key(&key) {
                found = Some(key);
                break;
            }
        }
        let Some(key) = found else {
            return false;
        };
        let index = self.opened[tpl];
        self.opened[tpl] += 1;
        let txn = self.txn_count;
        self.txn_count += 1;
        let r = self.rng.next();
        let app = match &self.templates[tpl].app {
            UdpApp::App(a) => Some(a.session(&SessionInit {
                role: AppRole::Client,
                transport: Transport::Datagram,
                index,
                seed: r ^ txn,
                local: key.0,
                remote: to,
            })),
            UdpApp::Replay(_) => None,
        };
        let mut s = Session {
            role: UdpRole::Client,
            tpl,
            port: ep.port,
            path: Path {
                src_mac: ep.mac,
                dst_mac: mac,
                vlan: ep.vlan,
                src: key.0.ip(),
                dst: to.ip(),
            },
            lport: key.0.port(),
            rport: to.port(),
            step: 0,
            hold: None,
            deadline: None,
            tries: 0,
            last_sent: Vec::new(),
            asked_at: None,
            last_rx: now,
            last_req: Vec::new(),
            app,
            app_out: Vec::new(),
            app_started: false,
            app_fit: None,
            mismatched: false,
            error: false,
            done: false,
            scheduled: Duration::MAX,
            dialog: false,
            wake: None,
            media: None,
            taken: false,
        };
        let (mut cx, sessions) = self.ctx();
        if let UdpApp::App(a) = &cx.templates[tpl].app {
            if a.protocol().dialog() {
                s.dialog = true;
                let n = a.protocol().media_ports();
                if n > 0 {
                    let Some(first) = cx.media.take(&cx.options.media_ports, key.0.ip(), n, key)
                    else {
                        return false;
                    };
                    s.media = Some((first, n));
                }
            }
        }
        cx.add(UdpRole::Client, tpl, |c| {
            c.sent += 1;
            c.active += 1;
        });
        let fate = if s.dialog {
            s.dialog_call(&mut cx, now, |a, ax| {
                a.start(ax);
                Receive::Taken
            })
        } else {
            s.advance(&mut cx, now)
        };
        if fate == Fate::Keep {
            sessions.insert(key, s);
            self.schedule(key);
        } else {
            cx.media.free(&s);
        }
        true
    }
}

impl PortEngine for UdpEngine {
    type Stats = UdpStats;
    fn handle_frame(&mut self, port: usize, frame: &[u8], now: Duration) {
        UdpEngine::handle_frame(self, port, frame, now)
    }
    fn poll(&mut self, now: Duration) {
        UdpEngine::poll(self, now)
    }
    fn take_output(&mut self) -> Vec<(usize, Vec<u8>)> {
        UdpEngine::take_output(self)
    }
    fn error(&self) -> Option<&str> {
        UdpEngine::error(self)
    }
    fn is_done(&self) -> bool {
        UdpEngine::is_done(self)
    }
    fn set_elapsed(&mut self, elapsed: Duration, stopped: bool) {
        UdpEngine::set_elapsed(self, elapsed, stopped)
    }
    fn set_rx_dropped(&mut self, frames: u64) {
        UdpEngine::set_rx_dropped(self, frames)
    }
    fn set_impairments(&mut self, stats: &crate::PortImpairStats) {
        UdpEngine::set_impairments(self, stats)
    }
    fn stats(&self) -> &UdpStats {
        UdpEngine::stats(self)
    }
    fn wrap_error(message: String) -> Error {
        Error::Udp(message)
    }
}

impl fmt::Debug for UdpEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpEngine")
            .field("templates", &self.templates.len())
            .field("sessions", &self.sessions.len())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}
