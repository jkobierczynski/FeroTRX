//! Entry points for the fuzz targets in `fuzz/` and for the hostile-input
//! tests: each takes any bytes and must not panic, hang, or allocate
//! without bound, whatever the bytes are.
//!
//! Not part of the API: built for tests and with the `fuzzing` feature.
//! Each target is a function of `&[u8]`; [`TARGETS`] lists them by the
//! names the fuzz crate uses, and [`seeds`] gives each a starting corpus
//! (transcripts of real sessions, frames of real runs, the example files).
//!
//! Inputs that hold several pieces use one layout: a selector byte first
//! where the target has choices, then pieces of an op byte, a two-byte
//! little-endian length and that many bytes (see [`Input`]).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::app::{App, AppCx, AppRole, AppSession, SessionInit, Transport};
use crate::{
    Capture, HostEngine, HostProfile, PortEngine, RxStats, TcpConfig, TcpEngine, TcpProfile,
    UdpApp, UdpConfig, UdpEngine, UdpProfile,
};

/// The most a session or an engine may send in reply to one input. A
/// reply bigger than this from a few kilobytes in is an amplification loop.
const MAX_OUTPUT: usize = 64 << 20;

/// A target: takes the fuzzer's bytes.
pub type Target = fn(&[u8]);

/// The targets, by name.
pub const TARGETS: &[(&str, Target)] = &[
    ("app", app),
    ("tcp_engine", tcp_engine),
    ("udp_engine", udp_engine),
    ("host_engine", host_engine),
    ("wire", wire),
    ("packet", packet),
    ("pcap", pcap),
    ("profile", profile),
    ("text", text),
    ("ssh", ssh),
    ("quic", quic),
];

/// Reads a fuzz input piece by piece; past the end it reads zeros and
/// empty pieces.
pub struct Input<'a> {
    data: &'a [u8],
}

impl<'a> Input<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn byte(&mut self) -> u8 {
        let (b, rest) = self
            .data
            .split_first()
            .map_or((0, &[][..]), |(b, r)| (*b, r));
        self.data = rest;
        b
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.byte(), self.byte()])
    }

    /// A piece: a two-byte length, then up to that many bytes.
    pub fn chunk(&mut self) -> &'a [u8] {
        let n = (self.u16() as usize).min(self.data.len());
        let (c, rest) = self.data.split_at(n);
        self.data = rest;
        c
    }

    /// The pieces left, without op bytes.
    pub fn chunks(mut self) -> Vec<&'a [u8]> {
        let mut out = Vec::new();
        while !self.is_empty() {
            out.push(self.chunk());
        }
        out
    }
}

/// Writes inputs in the layout [`Input`] reads.
#[derive(Default)]
pub struct InputWriter(pub Vec<u8>);

impl InputWriter {
    pub fn byte(mut self, b: u8) -> Self {
        self.0.push(b);
        self
    }

    pub fn chunk(mut self, c: &[u8]) -> Self {
        let c = &c[..c.len().min(u16::MAX as usize)];
        self.0.extend_from_slice(&(c.len() as u16).to_le_bytes());
        self.0.extend_from_slice(c);
        self
    }
}

// ----- the labs: protocols and engines from small profiles -----

/// One application protocol as a profile configures it, with the engine
/// configurations of a run between two ends.
struct Lab {
    transport: Transport,
    app: App,
    tcp: Option<TcpConfig>,
    udp: Option<UdpConfig>,
}

const ENDS: &str = "[client]\nip = \"10.0.0.1/24\"\n[server]\nip = \"10.0.0.2/24\"\n";

/// TCP protocols: the name and the profile's extra lines.
const TCP_APPS: &[(&str, &str)] = &[
    (
        "http",
        "app = \"http\"\n[http]\nper_connection = 2\nrequests = [\"GET /\", \"GET /big\", \"GET /missing 404\"]\n\
         [[http.route]]\npath = \"/big\"\nbody_size = \"20K\"\n[[http.request]]\nmethod = \"POST\"\npath = \"/up\"\nbody_size = \"3K\"\n",
    ),
    ("https", "app = \"https\"\n"),
    ("http2", "app = \"http2\"\n"),
    ("h2", "app = \"http2\"\ntls = true\n"),
    ("tls", "app = \"tls\"\n"),
    (
        "dns-tcp",
        "app = \"dns\"\n[dns]\nqueries = [\"www.lab.local A\", \"lab.local MX\"]\n\
         records = [\"www.lab.local 300 A 10.0.0.2\", \"lab.local 300 MX 10 mail.lab.local\"]\n",
    ),
    ("mqtt", "app = \"mqtt\"\n"),
    ("smb", "app = \"smb\"\n"),
    ("ssh", "app = \"ssh\"\n"),
];

/// UDP protocols.
const UDP_APPS: &[(&str, &str)] = &[
    (
        "dns",
        "queries = [\"www.lab.local A\", \"lab.local TXT\"]\n\
         records = [\"www.lab.local 300 A 10.0.0.2\", \"lab.local 300 TXT \\\"x\\\"\"]\n",
    ),
    ("ntp", "app = \"ntp\"\n"),
    ("sip", "app = \"sip\"\n"),
    ("h3", "app = \"h3\"\n"),
];

fn labs() -> &'static [Lab] {
    static LABS: OnceLock<Vec<Lab>> = OnceLock::new();
    LABS.get_or_init(|| {
        let dir = empty_dir();
        let mut out = Vec::new();
        for (name, extra) in TCP_APPS {
            let text =
                format!("format = 1\nconnections = 2\nconcurrency = 2\ncps = 1000\n{extra}{ENDS}");
            let p = TcpProfile::from_toml(&text, &dir)
                .unwrap_or_else(|e| panic!("fuzz lab {name}: {e}"));
            let programs: Vec<_> = p
                .programs()
                .unwrap_or_else(|e| panic!("fuzz lab {name}: {e}"))
                .into_iter()
                .map(Arc::new)
                .collect();
            let tcp = p
                .config(&programs, &["lab".to_string()], Some("lab"))
                .unwrap_or_else(|e| panic!("fuzz lab {name}: {e}"));
            let app = p.templates[0].app().expect("an app").clone();
            out.push(Lab {
                transport: Transport::Stream,
                app,
                tcp: Some(tcp),
                udp: None,
            });
        }
        for (name, extra) in UDP_APPS {
            let text = format!(
                "format = 1\ntransactions = 3\nconcurrency = 2\nrate = 1000\n{extra}{ENDS}"
            );
            let p = UdpProfile::from_toml(&text, &dir)
                .unwrap_or_else(|e| panic!("fuzz lab {name}: {e}"));
            let apps = p.apps().unwrap_or_else(|e| panic!("fuzz lab {name}: {e}"));
            let udp = p
                .config(&apps, &["lab".to_string()], Some("lab"))
                .unwrap_or_else(|e| panic!("fuzz lab {name}: {e}"));
            let UdpApp::App(app) = apps[0].clone() else {
                panic!("fuzz lab {name}: not an application protocol");
            };
            out.push(Lab {
                transport: Transport::Datagram,
                app,
                tcp: None,
                udp: Some(udp),
            });
        }
        out
    })
}

/// An empty folder for profiles' relative paths.
fn empty_dir() -> PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let d = std::env::temp_dir().join(format!("ferotrx-fuzz-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        d
    })
    .clone()
}

// ----- application sessions -----

const CLIENT: &str = "10.0.0.1:40000";
const SERVER: &str = "10.0.0.2:80";
/// A wall clock for sessions that put the time in messages (NTP, RTCP).
const WALL: Duration = Duration::from_secs(1_800_000_000);
const MEDIA_PORT: u16 = 20000;

fn session(lab: &Lab, role: AppRole, seed: u64) -> Box<dyn AppSession> {
    let (local, remote) = match role {
        AppRole::Client => (CLIENT, SERVER),
        AppRole::Server => (SERVER, CLIENT),
    };
    lab.app.session(&SessionInit {
        role,
        transport: lab.transport,
        index: 0,
        seed,
        local: local.parse().unwrap(),
        remote: remote.parse().unwrap(),
    })
}

fn cx(now: Duration) -> AppCx {
    AppCx::new(now, WALL + now).with_media_port(Some(MEDIA_PORT))
}

/// Counts what a call sent and checks it stays bounded.
fn sent(cx: &mut AppCx, total: &mut usize) {
    *total += cx.take_sends().iter().map(Vec::len).sum::<usize>();
    *total += cx
        .take_media_sends()
        .iter()
        .map(|(_, _, d)| d.len())
        .sum::<usize>();
    assert!(*total <= MAX_OUTPUT, "a session sent {total} bytes");
}

/// One application session, either end, of any protocol, playing what
/// the input says arrived: selector (protocol, role), then pieces whose op
/// byte says how much time passes (low 6 bits, ms) and what the piece is
/// (high 2 bits: received bytes or a datagram; the timer firing; a media
/// datagram).
pub fn app(data: &[u8]) {
    let labs = labs();
    let mut input = Input::new(data);
    let sel = input.byte() as usize;
    let lab = &labs[sel % labs.len()];
    let role = if (sel / labs.len()).is_multiple_of(2) {
        AppRole::Server
    } else {
        AppRole::Client
    };
    let mut s = session(lab, role, 1);
    let mut now = Duration::from_millis(1);
    let mut total = 0;
    let mut wake = None;
    let mut cx0 = cx(now);
    if role == AppRole::Client || lab.transport == Transport::Stream {
        s.start(&mut cx0);
    }
    wake = cx0.wake().or(wake);
    sent(&mut cx0, &mut total);
    let mut closed = cx0.wants_close();
    while !input.is_empty() && !closed {
        let op = input.byte();
        let piece = input.chunk();
        now += Duration::from_millis(u64::from(op & 0x3f));
        let mut cx = match op >> 6 {
            2 => {
                let Some(w) = wake.take() else { continue };
                now = now.max(w);
                let mut cx = cx(now);
                s.timer(&mut cx);
                cx
            }
            3 if lab.app.protocol().media_ports() > 0 => {
                let mut cx = cx(now);
                let from: SocketAddr = "10.0.0.1:30000".parse().unwrap();
                s.media(MEDIA_PORT + u16::from(op & 1), from, piece, &mut cx);
                cx
            }
            _ => {
                let mut cx = cx(now);
                s.receive(piece, &mut cx);
                cx
            }
        };
        wake = cx.wake().or(wake);
        sent(&mut cx, &mut total);
        closed = cx.wants_close();
    }
    if lab.transport == Transport::Stream && !closed {
        let mut cx = cx(now);
        s.peer_closed(&mut cx);
        wake = cx.wake().or(wake);
        sent(&mut cx, &mut total);
    }
    // Timers to the end: a session must not wake itself forever.
    for _ in 0..200 {
        let Some(w) = wake.take() else { break };
        now = now.max(w);
        let mut cx = cx(now);
        s.timer(&mut cx);
        wake = cx.wake().filter(|&w| w >= now);
        sent(&mut cx, &mut total);
    }
}

/// Plays a client against a server in memory: what each sent, as pieces
/// of a seed for the other end's role.
fn transcript(lab: &Lab) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut c = session(lab, AppRole::Client, 1);
    let mut s: Option<Box<dyn AppSession>> = None;
    let (mut to_s, mut to_c) = (Vec::new(), Vec::new());
    let mut now = Duration::from_millis(1);
    let mut cx0 = cx(now);
    c.start(&mut cx0);
    let mut queue: Vec<(bool, Vec<u8>)> = cx0.take_sends().into_iter().map(|d| (true, d)).collect();
    if lab.transport == Transport::Stream {
        let mut sx = cx(now);
        let srv = s.insert(session(lab, AppRole::Server, 2));
        srv.start(&mut sx);
        queue.extend(sx.take_sends().into_iter().map(|d| (false, d)));
    }
    let (mut cw, mut sw) = (cx0.wake(), None);
    for _ in 0..400 {
        now += Duration::from_millis(1);
        for (up, d) in std::mem::take(&mut queue) {
            let mut x = cx(now);
            if up {
                to_s.push(d.clone());
                let srv = s.get_or_insert_with(|| session(lab, AppRole::Server, 2));
                srv.receive(&d, &mut x);
                sw = x.wake().or(sw);
                queue.extend(x.take_sends().into_iter().map(|d| (false, d)));
            } else {
                to_c.push(d.clone());
                c.receive(&d, &mut x);
                cw = x.wake().or(cw);
                queue.extend(x.take_sends().into_iter().map(|d| (true, d)));
            }
        }
        if cw.is_some_and(|w| w <= now) {
            let mut x = cx(now);
            c.timer(&mut x);
            cw = x.wake();
            queue.extend(x.take_sends().into_iter().map(|d| (true, d)));
        }
        if let (Some(srv), true) = (s.as_mut(), sw.is_some_and(|w| w <= now)) {
            let mut x = cx(now);
            srv.timer(&mut x);
            sw = x.wake();
            queue.extend(x.take_sends().into_iter().map(|d| (false, d)));
        }
        if queue.is_empty() && cw.is_none() && sw.is_none() {
            break;
        }
        if to_s.len() + to_c.len() > 200 {
            break;
        }
    }
    (to_s, to_c)
}

fn app_seeds() -> Vec<Vec<u8>> {
    let labs = labs();
    let mut out = Vec::new();
    for (i, lab) in labs.iter().enumerate() {
        let (to_s, to_c) = transcript(lab);
        for (role, pieces) in [(0, to_s), (1, to_c)] {
            let mut w = InputWriter::default().byte((i + role * labs.len()) as u8);
            for p in &pieces {
                w = w.byte(1).chunk(p);
            }
            out.push(w.0);
        }
    }
    out
}

// ----- engines -----

/// Runs two engines on a link the input tampers with: for each frame on
/// the wire an op byte says pass, drop, duplicate, overwrite some bytes
/// (op 6: offset, piece; checksums fixed), or put a frame of the input's
/// next to it (op 7). Past the input every frame passes.
fn link<E: PortEngine>(a: &mut E, b: &mut E, input: &mut Input) {
    let step = Duration::from_millis(1);
    let mut now = Duration::ZERO;
    let mut wire: Vec<(bool, Vec<u8>)> = Vec::new();
    let mut total = 0usize;
    for _ in 0..3000 {
        for (to_b, f) in std::mem::take(&mut wire) {
            for g in tamper(f, input) {
                if to_b {
                    b.handle_frame(0, &g, now);
                } else {
                    a.handle_frame(0, &g, now);
                }
            }
        }
        a.poll(now);
        b.poll(now);
        for (_, f) in a.take_output() {
            total += f.len();
            wire.push((true, f));
        }
        for (_, f) in b.take_output() {
            total += f.len();
            wire.push((false, f));
        }
        assert!(total <= MAX_OUTPUT, "the engines sent {total} bytes");
        if a.is_done() && wire.is_empty() && input.is_empty() {
            break;
        }
        now += step;
    }
}

fn tamper(mut f: Vec<u8>, input: &mut Input) -> Vec<Vec<u8>> {
    if input.is_empty() {
        return vec![f];
    }
    match input.byte() & 7 {
        4 => vec![],
        5 => vec![f.clone(), f],
        6 => {
            let at = input.u16() as usize;
            let piece = input.chunk();
            if !f.is_empty() {
                let at = at % f.len();
                let n = piece.len().min(f.len() - at);
                f[at..at + n].copy_from_slice(&piece[..n]);
                crate::net::fix_checksums(&mut f);
            }
            vec![f]
        }
        7 => {
            let mut g = input.chunk().to_vec();
            crate::net::fix_checksums(&mut g);
            vec![g, f]
        }
        _ => vec![f],
    }
}

fn tcp_labs() -> Vec<&'static Lab> {
    labs().iter().filter(|l| l.tcp.is_some()).collect()
}

fn udp_labs() -> Vec<&'static Lab> {
    labs().iter().filter(|l| l.udp.is_some()).collect()
}

/// A TCP client and server engine of one protocol (selector) on a link
/// the input tampers with (see [`link`]).
pub fn tcp_engine(data: &[u8]) {
    let labs = tcp_labs();
    let mut input = Input::new(data);
    let lab = labs[input.byte() as usize % labs.len()];
    let cfg = lab.tcp.clone().unwrap();
    let mut client = TcpEngine::new(TcpConfig {
        server: None,
        ..cfg.clone()
    })
    .unwrap();
    let mut server = TcpEngine::new(TcpConfig {
        client: None,
        ..cfg
    })
    .unwrap();
    link(&mut client, &mut server, &mut input);
}

/// A UDP client and server engine, as [`tcp_engine`].
pub fn udp_engine(data: &[u8]) {
    let labs = udp_labs();
    let mut input = Input::new(data);
    let lab = labs[input.byte() as usize % labs.len()];
    let cfg = lab.udp.clone().unwrap();
    let mut client = UdpEngine::new(UdpConfig {
        server: None,
        ..cfg.clone()
    })
    .unwrap();
    let mut server = UdpEngine::new(UdpConfig {
        client: None,
        ..cfg
    })
    .unwrap();
    link(&mut client, &mut server, &mut input);
}

const HOST_SERVER: &str = r#"format = 1
[[host]]
mac = "02:dc:00:00:0d:01"
ipv4 = "10.88.0.1/24"
ipv6 = "fd00:88::1/64"
[host.dhcp_server]
pool = "10.88.0.100-10.88.0.199"
lease = "10s"
router = "10.88.0.1"
dns = ["10.88.0.1"]
domain = "lab.test"
[host.dhcpv6_server]
pool = "fd00:88::100-fd00:88::1ff"
lease = "10s"
dns = ["fd00:88::1"]
[host.router]
prefixes = ["fd00:88::/64"]
"#;

const HOST_CLIENTS: &str = r#"format = 1
[[host]]
count = 2
mac = "02:dc:00:00:0e:01"
ipv4 = "dhcp"
ipv6 = "dhcpv6"
hostname = "client-{n}"
[[host]]
mac = "02:dc:00:00:0f:01"
ipv4 = "10.88.0.9/24"
ipv6 = "slaac"
groups = ["239.1.2.3", "ff15::1:2"]
announce = true
"#;

fn host_engines() -> (HostEngine, HostEngine) {
    let make = |text: &str| {
        let p = HostProfile::from_toml(text).unwrap_or_else(|e| panic!("fuzz hosts: {e}"));
        let ifaces = p.interfaces(Some("lab")).unwrap();
        HostEngine::new(p.configs(&ifaces, Some("lab")).unwrap(), p.options.clone()).unwrap()
    };
    (make(HOST_CLIENTS), make(HOST_SERVER))
}

/// Host emulation (DHCPv4/v6 clients and server, SLAAC, router
/// advertisements, ARP/NDP, IGMP/MLD) on a link the input tampers with.
pub fn host_engine(data: &[u8]) {
    let (mut clients, mut server) = host_engines();
    let mut input = Input::new(data);
    link(&mut clients, &mut server, &mut input);
}

/// Frames of real runs: every lab's engines and the hosts, untampered.
fn lab_frames() -> Vec<Vec<u8>> {
    struct Tap<E>(E, Vec<Vec<u8>>);
    impl<E: PortEngine> Tap<E> {
        fn out(&mut self) -> Vec<(usize, Vec<u8>)> {
            let o = self.0.take_output();
            self.1.extend(o.iter().map(|(_, f)| f.clone()).take(64));
            o
        }
    }
    fn run<E: PortEngine>(a: E, b: E) -> Vec<Vec<u8>> {
        let (mut a, mut b) = (Tap(a, Vec::new()), Tap(b, Vec::new()));
        let mut now = Duration::ZERO;
        for _ in 0..2000 {
            a.0.poll(now);
            b.0.poll(now);
            for (_, f) in a.out() {
                b.0.handle_frame(0, &f, now);
            }
            for (_, f) in b.out() {
                a.0.handle_frame(0, &f, now);
            }
            if a.0.is_done() || a.1.len() + b.1.len() > 120 {
                break;
            }
            now += Duration::from_millis(1);
        }
        a.1.into_iter().chain(b.1).collect()
    }
    let mut out = Vec::new();
    for lab in labs() {
        if let Some(cfg) = &lab.tcp {
            out.extend(run(
                TcpEngine::new(TcpConfig {
                    server: None,
                    ..cfg.clone()
                })
                .unwrap(),
                TcpEngine::new(TcpConfig {
                    client: None,
                    ..cfg.clone()
                })
                .unwrap(),
            ));
        }
        if let Some(cfg) = &lab.udp {
            out.extend(run(
                UdpEngine::new(UdpConfig {
                    server: None,
                    ..cfg.clone()
                })
                .unwrap(),
                UdpEngine::new(UdpConfig {
                    client: None,
                    ..cfg.clone()
                })
                .unwrap(),
            ));
        }
    }
    let (c, s) = host_engines();
    out.extend(run(c, s));
    out.sort();
    out.dedup();
    out
}

// ----- frames and files -----

/// Every parser a received frame meets: Ethernet, ARP, IPv4/IPv6, TCP and
/// its options, UDP, NDP, router advertisements, MLD and IGMP queries,
/// DHCPv4/v6, the checksum fixer of rewrites, and the loss/latency
/// signature reader with per-interval counters. The input is the frames,
/// as pieces.
pub fn wire(data: &[u8]) {
    use crate::host::wire as hw;
    use crate::tcp::wire as tw;
    let mut rx = RxStats {
        interval: Some(Duration::from_millis(10)),
        ..Default::default()
    };
    for (i, f) in Input::new(data).chunks().into_iter().enumerate() {
        rx.record(f, Duration::from_millis(i as u64));
        let _ = crate::Signature::find(f);
        let mut copy = f.to_vec();
        crate::net::fix_checksums(&mut copy);
        let Some(l) = tw::parse_link(f) else { continue };
        let p = &f[l.payload.min(f.len())..];
        if l.ethertype == tw::ETHERTYPE_ARP {
            let _ = tw::parse_arp(p);
        }
        for verify in [false, true] {
            let Some(ip) = tw::parse_ip(p, verify) else {
                continue;
            };
            let _ = tw::parse_ndp(&ip);
            let _ = hw::parse_ra(&ip);
            let _ = hw::parse_mld_query(&ip);
            if ip.proto == 2 {
                let _ = hw::parse_igmp_query(ip.payload);
            }
            if let Some(s) = tw::parse_tcp(&ip, verify) {
                let _ = s.opts;
            }
            if let Some(d) = tw::parse_udp(&ip, verify) {
                let _ = hw::parse_dhcp4(d.data);
                let _ = hw::parse_dhcp6(d.data);
            }
        }
    }
    let _ = rx.flow(0);
}

/// The packet decoder of `inspect`, the GUI and captures, and the GUI's
/// import into packet descriptions: selector (link type), then the frame.
pub fn packet(data: &[u8]) {
    let mut input = Input::new(data);
    let linktype = match input.byte() % 4 {
        0 => crate::LINKTYPE_ETHERNET,
        1 => 101, // raw IP
        2 => 113, // Linux cooked
        _ => 0,   // BSD loopback
    };
    let frame = input.data;
    let d = ferotrx_packet::decode(linktype, frame);
    let _ = d.tree();
    if let Some(imported) = ferotrx_packet::import(linktype, frame) {
        // What import writes must read back.
        let _ = ferotrx_packet::parse_layers(&ferotrx_packet::format_layers(&imported.layers));
    }
    let _ = ferotrx_packet::hex_dump(&frame[..frame.len().min(256)]);
}

/// A capture file (pcap or pcapng) as `file.put` and `--input` take it.
pub fn pcap(data: &[u8]) {
    if let Ok(c) = Capture::from_reader(data) {
        let _ = RxStats::from_capture(&c);
        for p in c.packets.iter().take(64) {
            let _ = ferotrx_packet::decode(c.linktype, &p.data);
        }
    }
}

/// Text that names paths the profile parsers would read: devices and
/// kernel files could block or never end.
fn names_special_files(text: &str) -> bool {
    [
        "/dev", "/proc", "/sys", "\\\\.\\", "//./", "con:", "CON", "\\\\?\\",
    ]
    .iter()
    .any(|p| text.contains(p))
}

/// A profile of any kind (traffic, TCP, UDP, hosts, benchmark, Y.1564,
/// scenario, fleet) as `ferotrx check`, `profile.load` and the GUI read
/// it: selector (kind, or detected), then the text.
pub fn profile(data: &[u8]) {
    use crate::check::{check_text, FileKind};
    let mut input = Input::new(data);
    let sel = input.byte();
    let Ok(text) = std::str::from_utf8(input.data) else {
        return;
    };
    if names_special_files(text) {
        return;
    }
    let kinds = FileKind::ALL;
    let kind = kinds.get(sel as usize % (kinds.len() + 1)).copied();
    let dir = empty_dir();
    let _ = check_text(text, &dir, kind, &[]);
    let _ = crate::check::detect_kind(text);
}

/// The one-line parsers of command lines, profiles and the GUI: packet
/// descriptions, impairments, field variations, size mixes, traffic
/// models and rate shapes, rates, durations, sizes.
pub fn text(data: &[u8]) {
    let mut input = Input::new(data);
    let sel = input.byte();
    let Ok(t) = std::str::from_utf8(input.data) else {
        return;
    };
    match sel % 9 {
        0 => {
            if let Ok(layers) = ferotrx_packet::parse_layers(t) {
                let _ = ferotrx_packet::format_layers(&layers);
            }
            let _ = Capture::from_specs(&[t], Duration::from_millis(1));
        }
        1 => {
            let _ = t.parse::<crate::ImpairSpec>();
        }
        2 => {
            let _ = t.parse::<crate::FieldVar>();
        }
        3 => {
            let _ = t.parse::<crate::SizeMix>();
        }
        4 => {
            let _ = t.parse::<crate::TrafficModel>();
            let _ = crate::parse_shape_point(t);
            let _ = crate::parse_model(Some(t), &[t.to_string()]);
        }
        5 => {
            let _ = t.parse::<crate::Rate>();
        }
        6 => {
            let _ = crate::parse_duration(t);
        }
        7 => {
            let _ = crate::parse_size(t);
            let _ = crate::parse_bit_rate(t);
        }
        _ => {
            let _ = crate::parse_ip_prefix(t);
            let _ = crate::parse_port_range(t);
            let _ = crate::parse_connect_addr(t);
            let _ = crate::parse_pool(t);
        }
    }
}

// ----- behind the encryption -----

fn ssh_app() -> &'static crate::app::ssh::Ssh {
    static SSH: OnceLock<crate::app::ssh::Ssh> = OnceLock::new();
    SSH.get_or_init(crate::app::ssh::Ssh::default)
}

/// SSH after the key exchange: selector (low bit: server or client), then
/// the decrypted payloads as pieces.
pub fn ssh(data: &[u8]) {
    let mut input = Input::new(data);
    let server = input.byte() & 1 == 0;
    let packets = input.chunks();
    let mut cx = cx(Duration::from_millis(1));
    crate::app::ssh::fuzz_messages(ssh_app(), server, &packets, &mut cx);
    let mut total = 0;
    sent(&mut cx, &mut total);
}

fn h3_app() -> &'static crate::app::quic::Http3 {
    static H3: OnceLock<crate::app::quic::Http3> = OnceLock::new();
    H3.get_or_init(crate::app::quic::Http3::default)
}

/// QUIC and HTTP/3 behind the packet protection, plus their parsers on
/// their own: selector (bit 0: server or client end; bit 1: also the
/// parsers on each piece), then 1-RTT payloads as pieces.
pub fn quic(data: &[u8]) {
    use crate::app::quic::{frame, qpack};
    let mut input = Input::new(data);
    let sel = input.byte();
    let payloads = input.chunks();
    if sel & 2 != 0 {
        for p in &payloads {
            let _ = frame::parse_frames(p);
            let _ = frame::Params::parse(p);
            let _ = qpack::decode(p);
            crate::app::quic::h3::fuzz_frames(p);
        }
    }
    crate::app::quic::fuzz_established(h3_app(), sel & 1 == 0, &payloads);
}

// ----- seeds -----

/// A starting corpus for target `name`.
pub fn seeds(name: &str) -> Vec<Vec<u8>> {
    let examples = examples_dir();
    let files = |ext: &str| -> Vec<Vec<u8>> {
        let mut v: Vec<_> = std::fs::read_dir(&examples)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == ext))
            .collect();
        v.sort();
        v.iter().filter_map(|p| std::fs::read(p).ok()).collect()
    };
    match name {
        "app" => app_seeds(),
        "tcp_engine" => (0..tcp_labs().len() as u8)
            .flat_map(|i| [vec![i], vec![i, 4, 0, 5, 0, 6, 9, 0, 1, 0, 0xff]])
            .collect(),
        "udp_engine" => (0..udp_labs().len() as u8)
            .flat_map(|i| [vec![i], vec![i, 4, 5, 6, 30, 0, 2, 0, 0xff, 0xff]])
            .collect(),
        "host_engine" => vec![vec![], vec![0, 0, 4, 5, 6, 40, 0, 1, 0, 0]],
        "wire" => lab_frames()
            .chunks(8)
            .map(|fs| fs.iter().fold(InputWriter::default(), |w, f| w.chunk(f)).0)
            .collect(),
        "packet" => {
            let mut v: Vec<Vec<u8>> = lab_frames()
                .into_iter()
                .map(|f| [vec![0], f].concat())
                .collect();
            for c in files("pcap")
                .iter()
                .filter_map(|b| Capture::from_reader(&b[..]).ok())
            {
                v.extend(
                    c.packets
                        .iter()
                        .take(16)
                        .map(|p| [vec![0], p.data.clone()].concat()),
                );
            }
            v
        }
        "pcap" => files("pcap"),
        "profile" => {
            let mut v = files("toml");
            let fleet = examples.join("fleet");
            if let Ok(d) = std::fs::read_dir(fleet) {
                let mut ps: Vec<_> = d.flatten().map(|e| e.path()).collect();
                ps.sort();
                v.extend(ps.iter().filter_map(|p| std::fs::read(p).ok()));
            }
            v.into_iter().map(|t| [vec![0xff], t].concat()).collect()
        }
        "text" => {
            let lines: &[(u8, &str)] = &[
                (
                    0,
                    "eth / ipv4 src=10.0.0.1 dst=10.0.0.2 / udp dport=53 / raw hex=00ff",
                ),
                (0, "eth vlan=10 / ipv6 / tcp flags=S / payload size=20"),
                (
                    1,
                    "delay=10ms jitter=2ms dist=pareto loss=1% loss_burst=3 reorder=5%",
                ),
                (
                    1,
                    "rate=10mbit limit=50 mtu=1400 mtu_action=truncate duplicate=1%",
                ),
                (2, "ipv4.src=10.0.0.1-10.0.0.9,step=2"),
                (2, "udp.sport=random:1000-2000"),
                (3, "imix"),
                (3, "64:7,570:4,1518:1"),
                (4, "poisson"),
                (4, "burst=8"),
                (4, "ramp_up=2s,hold=5s,ramp_down=1s"),
                (4, "10s:500pps"),
                (5, "1.5gbps"),
                (6, "1h2m3.5s"),
                (7, "16K"),
                (8, "10.0.0.0/24"),
                (8, "1000-2000"),
                (8, "[fd00::1]:443"),
            ];
            lines
                .iter()
                .map(|(k, l)| [vec![*k], l.as_bytes().to_vec()].concat())
                .collect()
        }
        "ssh" => {
            let msgs = crate::app::ssh::fuzz_seed_messages();
            let w = msgs
                .iter()
                .fold(InputWriter::default().byte(0), |w, m| w.chunk(m));
            vec![w.0]
        }
        "quic" => crate::app::quic::fuzz_seed_payloads()
            .into_iter()
            .map(|ps| {
                ps.iter()
                    .fold(InputWriter::default().byte(2), |w, p| w.chunk(p))
                    .0
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// The repository's `examples` folder.
fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

#[cfg(test)]
mod tests;
