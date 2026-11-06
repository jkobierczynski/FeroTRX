//! Stateful TCP over a simulated long, slow or impaired path: two engines on
//! one link with a delay, a bit rate, a queue and frames dropped, duplicated
//! or delayed on purpose. Checks window scaling, timestamps (RTT and PAWS),
//! SACK and the per-template rates.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use ferotrx_core::*;

const CLIENT_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x01]);
const SERVER_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x02]);

fn addr(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// A TCP segment on the wire, read back (untagged IPv4 or IPv6).
#[derive(Clone, Copy, Debug)]
struct Seen {
    /// Offset of the TCP header.
    tcp: usize,
    hdr_len: usize,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: usize,
}

fn tcp_of(f: &[u8]) -> Option<Seen> {
    let ethertype = u16::from_be_bytes([f[12], f[13]]);
    let (tcp, total_end) = match ethertype {
        0x0800 if f[23] == 6 => {
            let ihl = usize::from(f[14] & 0x0f) * 4;
            (
                14 + ihl,
                14 + usize::from(u16::from_be_bytes([f[16], f[17]])),
            )
        }
        0x86dd if f[20] == 6 => (54, 54 + usize::from(u16::from_be_bytes([f[18], f[19]]))),
        _ => return None,
    };
    let be32 = |at: usize| u32::from_be_bytes([f[at], f[at + 1], f[at + 2], f[at + 3]]);
    let hdr_len = usize::from(f[tcp + 12] >> 4) * 4;
    Some(Seen {
        tcp,
        hdr_len,
        seq: be32(tcp + 4),
        ack: be32(tcp + 8),
        flags: f[tcp + 13],
        payload: total_end - tcp - hdr_len,
    })
}

fn csum(data: &[u8], mut sum: u32) -> u16 {
    for c in data.chunks(2) {
        sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Recomputes the TCP checksum of an untagged IPv4 or IPv6 frame.
fn fix_tcp_checksum(f: &mut [u8]) {
    let s = tcp_of(f).unwrap();
    let (addrs, end) = if u16::from_be_bytes([f[12], f[13]]) == 0x86dd {
        (22..54, 54 + usize::from(u16::from_be_bytes([f[18], f[19]])))
    } else {
        (26..34, 14 + usize::from(u16::from_be_bytes([f[16], f[17]])))
    };
    f[s.tcp + 16..s.tcp + 18].fill(0);
    let mut pseudo = 0u32;
    for c in f[addrs].chunks(2) {
        pseudo += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    pseudo += 6 + (end - s.tcp) as u32;
    let sum = csum(&f[s.tcp..end], pseudo);
    f[s.tcp + 16..s.tcp + 18].copy_from_slice(&sum.to_be_bytes());
}

/// What the link does to a frame.
enum Fate {
    Pass,
    Drop,
    /// Deliver it, and a copy.
    Duplicate,
    /// Deliver it this much later than it would have arrived.
    Delay(Duration),
}

/// One direction of the link: a queue served at `rate`, then `delay`.
struct Direction {
    /// When the link finishes sending what is queued.
    busy_until: Duration,
    /// Frames on their way, by arrival time.
    flight: VecDeque<(Duration, Vec<u8>)>,
    /// Frames waiting or being sent, for the queue limit: their departure times.
    queued: VecDeque<Duration>,
    dropped_queue: u64,
    /// Frames marked Congestion Experienced instead of dropped.
    marked: u64,
}

struct Link {
    delay: Duration,
    /// Bytes per second; 0 is no limit.
    rate: u64,
    /// Most frames waiting to be sent, per direction.
    queue: usize,
    /// ECN: with this many frames waiting, ECN-capable frames are marked
    /// CE (a simple AQM such as RED's or CoDel's marking).
    mark_at: Option<usize>,
    dirs: [Direction; 2],
}

/// The ECN bits of an untagged IPv4 or IPv6 frame.
fn ecn_of(f: &[u8]) -> u8 {
    match u16::from_be_bytes([f[12], f[13]]) {
        0x0800 => f[15] & 3,
        _ => (f[15] >> 4) & 3,
    }
}

/// Marks an ECN-capable frame Congestion Experienced, fixing the IPv4
/// header checksum.
fn mark_ce(f: &mut [u8]) {
    if u16::from_be_bytes([f[12], f[13]]) == 0x0800 {
        f[15] |= 3;
        let ihl = usize::from(f[14] & 0x0f) * 4;
        f[24..26].fill(0);
        let sum = csum(&f[14..14 + ihl], 0);
        f[24..26].copy_from_slice(&sum.to_be_bytes());
    } else {
        f[15] |= 3 << 4;
    }
}

impl Link {
    fn new(delay: Duration, rate_mbit: u64, queue: usize) -> Self {
        let dir = || Direction {
            busy_until: Duration::ZERO,
            flight: VecDeque::new(),
            queued: VecDeque::new(),
            dropped_queue: 0,
            marked: 0,
        };
        Link {
            delay,
            rate: rate_mbit * 1_000_000 / 8,
            queue,
            mark_at: None,
            dirs: [dir(), dir()],
        }
    }

    /// Marks ECN-capable frames CE from `n` frames waiting on.
    fn marking(mut self, n: usize) -> Self {
        self.mark_at = Some(n);
        self
    }

    /// Puts a frame on direction `d` (0: client to server, 1: back).
    fn send(&mut self, d: usize, mut frame: Vec<u8>, now: Duration, extra: Duration) {
        let (delay, rate, queue) = (self.delay, self.rate, self.queue);
        let dir = &mut self.dirs[d];
        while dir.queued.front().is_some_and(|&t| t <= now) {
            dir.queued.pop_front();
        }
        if dir.queued.len() >= queue {
            dir.dropped_queue += 1;
            return;
        }
        if self
            .mark_at
            .is_some_and(|n| dir.queued.len() >= n && ecn_of(&frame) != 0)
        {
            mark_ce(&mut frame);
            dir.marked += 1;
        }
        let start = dir.busy_until.max(now);
        let tx = (frame.len() as u64 * 1_000_000_000)
            .checked_div(rate)
            .map_or(Duration::ZERO, Duration::from_nanos);
        dir.busy_until = start + tx;
        dir.queued.push_back(dir.busy_until);
        let at = dir.busy_until + delay + extra;
        let pos = dir.flight.partition_point(|(t, _)| *t <= at);
        dir.flight.insert(pos, (at, frame));
    }

    fn arrived(&mut self, d: usize, now: Duration) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let dir = &mut self.dirs[d];
        while dir.flight.front().is_some_and(|(t, _)| *t <= now) {
            out.push(dir.flight.pop_front().unwrap().1);
        }
        out
    }
}

/// What the simulation saw on the wire.
#[derive(Default, Debug)]
struct Watch {
    /// TCP payload bytes the server sent, retransmissions included.
    server_data_bytes: u64,
    /// Data frames the impairment dropped, and their bytes.
    dropped: u64,
    dropped_bytes: u64,
    /// Header lengths of the first SYN, SYN-ACK and server data segment.
    syn_hdr: Option<usize>,
    synack_hdr: Option<usize>,
    data_hdr: Option<usize>,
    /// The highest ACK the client sent, and a data frame of the server's.
    client_ack: Option<u32>,
    sample: Option<Vec<u8>>,
}

type Impair<'a> = dyn FnMut(usize, &[u8], &mut Watch, Duration) -> (Fate, Vec<Vec<u8>>) + 'a;

/// Runs a client engine and a server engine on the two ends of `link`, in
/// 100 µs steps, until the client is done or `max` passes. `impair` decides
/// each frame's fate and may inject frames; it gets the direction (0: client
/// to server).
fn run(
    client: &mut TcpEngine,
    server: &mut TcpEngine,
    link: &mut Link,
    max: Duration,
    impair: &mut Impair,
) -> (Duration, Watch) {
    run_from(client, server, link, Duration::ZERO, max, impair)
}

/// [`run`] from `from` until `until`, to go on with an earlier run.
fn run_from(
    client: &mut TcpEngine,
    server: &mut TcpEngine,
    link: &mut Link,
    from: Duration,
    max: Duration,
    impair: &mut Impair,
) -> (Duration, Watch) {
    let step = Duration::from_micros(100);
    let mut now = from;
    let mut w = Watch::default();
    while now < max {
        for f in link.arrived(0, now) {
            server.handle_frame(0, &f, now);
        }
        for f in link.arrived(1, now) {
            client.handle_frame(0, &f, now);
        }
        for (d, e) in [(0, &mut *client), (1, &mut *server)] {
            e.poll(now);
            assert_eq!(e.error(), None);
            for (_, f) in e.take_output() {
                if let Some(s) = tcp_of(&f) {
                    match (d, s.flags & 0x12) {
                        (0, 0x02) => {
                            w.syn_hdr.get_or_insert(s.hdr_len);
                        }
                        (1, 0x12) => {
                            w.synack_hdr.get_or_insert(s.hdr_len);
                        }
                        _ => {}
                    }
                    if d == 0
                        && s.flags & 0x10 != 0
                        && w.client_ack
                            .is_none_or(|a| (s.ack.wrapping_sub(a) as i32) > 0)
                    {
                        w.client_ack = Some(s.ack);
                    }
                    if d == 1 && s.payload > 0 {
                        w.data_hdr.get_or_insert(s.hdr_len);
                        w.server_data_bytes += s.payload as u64;
                    }
                }
                let (fate, inject) = impair(d, &f, &mut w, now);
                for i in inject {
                    link.send(d, i, now, Duration::ZERO);
                }
                match fate {
                    Fate::Pass => link.send(d, f, now, Duration::ZERO),
                    Fate::Drop => {
                        if let Some(s) = tcp_of(&f) {
                            if s.payload > 0 {
                                w.dropped += 1;
                                w.dropped_bytes += s.payload as u64;
                            }
                        }
                    }
                    Fate::Duplicate => {
                        link.send(d, f.clone(), now, Duration::ZERO);
                        link.send(d, f, now, Duration::ZERO);
                    }
                    Fate::Delay(x) => link.send(d, f, now, x),
                }
            }
        }
        if client.is_done() {
            break;
        }
        now += step;
    }
    (now, w)
}

fn pass(_: usize, _: &[u8], _: &mut Watch, _: Duration) -> (Fate, Vec<Vec<u8>>) {
    (Fate::Pass, Vec::new())
}

/// A download: a short request, `size` bytes back, the server closes.
fn download(size: usize) -> TcpProgram {
    let body: Vec<u8> = (0..size).map(|i| (i * 7 % 251) as u8).collect();
    TcpProgram::new(
        80,
        vec![
            TcpMessage::new(TcpRole::Client, "GET /big HTTP/1.1\r\n\r\n"),
            TcpMessage::new(TcpRole::Server, body),
        ],
    )
    .with_closer(TcpRole::Server)
}

fn engines(
    program: TcpProgram,
    connections: u64,
    v6: bool,
    client_opts: TcpOptions,
    server_opts: TcpOptions,
) -> (TcpEngine, TcpEngine) {
    let (c_ip, s_ip, connect) = if v6 {
        ("fd00::1", "fd00::2", "[fd00::2]:80")
    } else {
        ("10.0.0.1", "10.0.0.2", "10.0.0.2:80")
    };
    let tpl = TcpTemplate::new(Arc::new(program), connect.parse().unwrap());
    let mut c = TcpClientConfig::new(TcpEndpoint::new(0, CLIENT_MAC, addr(c_ip)));
    c.connections = connections;
    c.cps = 100.0;
    let client = TcpEngine::new(TcpConfig {
        templates: vec![tpl.clone()],
        client: Some(c),
        server: None,
        options: client_opts,
    })
    .unwrap();
    let server = TcpEngine::new(TcpConfig {
        templates: vec![tpl],
        client: None,
        server: Some(TcpServerConfig::new(TcpEndpoint::new(
            0,
            SERVER_MAC,
            addr(s_ip),
        ))),
        options: server_opts,
    })
    .unwrap();
    (client, server)
}

fn assert_clean(client: &TcpEngine, server: &TcpEngine, n: u64) {
    let (c, s) = (&client.stats().client, &server.stats().server);
    assert!(client.is_done(), "{c:?}");
    assert_eq!((c.completed, c.failed(), c.mismatched), (n, 0, 0), "{c:?}");
    assert_eq!((s.completed, s.failed(), s.mismatched), (n, 0, 0), "{s:?}");
}

const MB: usize = 1 << 20;

/// 50 Mbit/s and 80 ms round trip: 500 KB in flight fill the path.
fn long_fat_pipe() -> Link {
    Link::new(Duration::from_millis(40), 50, 2000)
}

#[test]
fn window_scaling_keeps_more_than_64k_in_flight() {
    for v6 in [false, true] {
        let (mut client, mut server) = engines(
            download(4 * MB),
            1,
            v6,
            TcpOptions::default(),
            TcpOptions::default(),
        );
        let (took, w) = run(
            &mut client,
            &mut server,
            &mut long_fat_pipe(),
            Duration::from_secs(30),
            &mut pass,
        );
        assert_clean(&client, &server, 1);
        let s = &server.stats().server;
        assert!(s.max_in_flight > 400_000, "{v6}: {s:?}");
        // MSS, SACK permitted, timestamps, window scale: 20 bytes of options.
        assert_eq!((w.syn_hdr, w.synack_hdr), (Some(40), Some(40)));
        // Timestamps on every data segment, and the frames still fit 1500 bytes.
        assert_eq!(w.data_hdr, Some(32));
        // 4 MiB at 50 Mbit/s is 0.67 s; slow start takes a few round trips more.
        assert!(took < Duration::from_millis(1500), "{v6}: {took:?}");
        assert_eq!(s.timeouts, 0, "{s:?}");
        // The handshake takes one round trip, the first byte another (the
        // client asks first, the server answers).
        let c = &client.stats().client;
        let ms = |d: Option<Duration>| d.unwrap().as_millis();
        assert_eq!(c.connect_time.count(), 1);
        assert!((80..=85).contains(&ms(c.connect_time.mean())), "{c:?}");
        assert!((160..=170).contains(&ms(c.first_byte.mean())), "{c:?}");
        assert_eq!(server.stats().server.connect_time.count(), 0);
    }
}

#[test]
fn without_window_scaling_64k_is_the_limit() {
    let off = TcpOptions {
        window_scaling: false,
        ..Default::default()
    };
    // Either end not offering it is enough.
    for (c, s) in [
        (off.clone(), TcpOptions::default()),
        (TcpOptions::default(), off.clone()),
    ] {
        let (mut client, mut server) = engines(download(MB), 1, false, c, s);
        let (took, w) = run(
            &mut client,
            &mut server,
            &mut long_fat_pipe(),
            Duration::from_secs(30),
            &mut pass,
        );
        assert_clean(&client, &server, 1);
        let s = &server.stats().server;
        assert!(s.max_in_flight <= 65535, "{s:?}");
        assert!(s.max_in_flight > 60_000, "{s:?}");
        // 1 MiB at 64 KB per 80 ms round trip: over a second.
        assert!(took > Duration::from_millis(1200), "{took:?}");
        assert!(w.syn_hdr.is_some());
    }
}

#[test]
fn the_send_and_receive_windows_limit_the_flight() {
    for (c, s) in [
        (
            TcpOptions {
                receive_window: 200_000,
                ..Default::default()
            },
            TcpOptions::default(),
        ),
        (
            TcpOptions::default(),
            TcpOptions {
                send_window: 200_000,
                ..Default::default()
            },
        ),
    ] {
        let (mut client, mut server) = engines(download(2 * MB), 1, false, c, s);
        run(
            &mut client,
            &mut server,
            &mut long_fat_pipe(),
            Duration::from_secs(30),
            &mut pass,
        );
        assert_clean(&client, &server, 1);
        let s = &server.stats().server;
        assert!(
            s.max_in_flight <= 200_000 && s.max_in_flight > 150_000,
            "{s:?}"
        );
    }
}

#[test]
fn options_are_used_only_when_both_ends_offer_them() {
    let none = TcpOptions {
        window_scaling: false,
        timestamps: false,
        sack: false,
        ..Default::default()
    };
    let (mut client, mut server) =
        engines(download(100_000), 1, false, TcpOptions::default(), none);
    let (_, w) = run(
        &mut client,
        &mut server,
        &mut Link::new(Duration::from_millis(1), 0, 1000),
        Duration::from_secs(10),
        &mut pass,
    );
    assert_clean(&client, &server, 1);
    // The client offers all; the server answers with the MSS only, and no
    // segment carries a timestamp after that.
    assert_eq!(
        (w.syn_hdr, w.synack_hdr, w.data_hdr),
        (Some(40), Some(24), Some(20))
    );
}

/// Drops data frames from the server, the first time each is sent, when
/// `pick` says so for their count: retransmissions pass.
fn drop_first_sends(
    pick: impl Fn(u64) -> bool,
) -> impl FnMut(usize, &[u8], &mut Watch, Duration) -> (Fate, Vec<Vec<u8>>) {
    let mut count = 0u64;
    let mut seen = std::collections::HashSet::new();
    move |d, f, _, _| {
        let Some(s) = tcp_of(f) else {
            return (Fate::Pass, Vec::new());
        };
        if d == 1 && s.payload > 0 && seen.insert(s.seq) {
            count += 1;
            if pick(count) {
                return (Fate::Drop, Vec::new());
            }
        }
        (Fate::Pass, Vec::new())
    }
}

#[test]
fn sack_retransmits_only_the_holes() {
    // Three holes in every 200 segments, a few segments apart: SACK fills
    // them all in one round trip; without it, NewReno takes a round trip each.
    let mut took = Vec::new();
    for sack in [true, false] {
        let opts = TcpOptions {
            sack,
            ..Default::default()
        };
        let (mut client, mut server) = engines(download(4 * MB), 1, false, opts.clone(), opts);
        let (t, w) = run(
            &mut client,
            &mut server,
            &mut Link::new(Duration::from_millis(20), 100, 5000),
            Duration::from_secs(60),
            &mut drop_first_sends(|n| matches!(n % 200, 50 | 54 | 58)),
        );
        assert_clean(&client, &server, 1);
        let s = &server.stats().server;
        let resent = w.server_data_bytes - s.payload_tx;
        assert!(w.dropped > 30, "{w:?}");
        if sack {
            // Each hole once, and no timeouts: the dropped bytes, nothing more.
            assert_eq!(s.timeouts, 0, "{s:?}");
            assert_eq!(resent, w.dropped_bytes, "{w:?}, {s:?}");
            assert_eq!(s.retransmits, w.dropped, "{w:?}, {s:?}");
        }
        took.push(t);
    }
    assert!(took[0] < took[1], "{took:?}");
}

#[test]
fn recovers_from_burst_losses_at_the_queue() {
    // A queue too short for slow start's overshoot: bursts of drops.
    for sack in [true, false] {
        let opts = TcpOptions {
            sack,
            ..Default::default()
        };
        let (mut client, mut server) = engines(download(4 * MB), 1, false, opts.clone(), opts);
        let mut link = Link::new(Duration::from_millis(20), 50, 60);
        let (took, _) = run(
            &mut client,
            &mut server,
            &mut link,
            Duration::from_secs(60),
            &mut pass,
        );
        assert_clean(&client, &server, 1);
        let (dropped, s) = (link.dirs[1].dropped_queue, &server.stats().server);
        assert!(dropped > 10, "{dropped}");
        if sack {
            // Every hole resent once, in recovery, without waiting for a timeout.
            assert_eq!((s.retransmits, s.timeouts), (dropped, 0), "{s:?}");
            assert!(took < Duration::from_secs(3), "{took:?}");
        }
        assert!(took < Duration::from_secs(10), "sack {sack}: {took:?}");
    }
}

#[test]
fn survives_reordering_duplication_and_loss_both_ways() {
    for v6 in [false, true] {
        let mut n = 0u64;
        let mut impair = |_: usize, f: &[u8], _: &mut Watch, _: Duration| {
            if tcp_of(f).is_none() {
                return (Fate::Pass, Vec::new());
            }
            n += 1;
            let fate = if n.is_multiple_of(41) {
                Fate::Drop
            } else if n.is_multiple_of(13) {
                Fate::Duplicate
            } else if n.is_multiple_of(7) {
                Fate::Delay(Duration::from_millis(3))
            } else {
                Fate::Pass
            };
            (fate, Vec::new())
        };
        let mut program = download(300_000);
        program
            .messages
            .push(TcpMessage::new(TcpRole::Client, vec![b'x'; 50_000]));
        program
            .messages
            .push(TcpMessage::new(TcpRole::Server, "done\r\n"));
        let (mut client, mut server) = engines(
            program,
            10,
            v6,
            TcpOptions::default(),
            TcpOptions::default(),
        );
        run(
            &mut client,
            &mut server,
            &mut Link::new(Duration::from_millis(5), 100, 1000),
            Duration::from_secs(60),
            &mut impair,
        );
        assert_clean(&client, &server, 10);
        let (c, s) = (&client.stats().client, &server.stats().server);
        assert!(c.retransmits + s.retransmits > 0);
    }
}

#[test]
fn paws_drops_old_duplicates() {
    // An old segment comes back with its old timestamp but a sequence number
    // in the window, as when sequence numbers wrap on a fast link: PAWS drops
    // it. Its bytes are wrong, so taking it would show as a mismatch.
    for timestamps in [true, false] {
        let opts = TcpOptions {
            timestamps,
            ..Default::default()
        };
        let mut injected = false;
        let mut impair = |d: usize, f: &[u8], w: &mut Watch, now: Duration| {
            let mut inject = Vec::new();
            if let Some(s) = tcp_of(f) {
                if d == 1 && s.payload > 1000 && w.sample.is_none() {
                    w.sample = Some(f.to_vec());
                }
                if d == 1 && !injected && now > Duration::from_millis(100) {
                    if let (Some(mut old), Some(ack)) = (w.sample.clone(), w.client_ack) {
                        let o = tcp_of(&old).unwrap();
                        // Just ahead of what the client has: out of order, in the window.
                        let seq = ack.wrapping_add(3000);
                        old[o.tcp + 4..o.tcp + 8].copy_from_slice(&seq.to_be_bytes());
                        let p = o.tcp + o.hdr_len;
                        for b in &mut old[p..p + 100] {
                            *b ^= 0x5a;
                        }
                        fix_tcp_checksum(&mut old);
                        inject.push(old);
                        injected = true;
                    }
                }
            }
            (Fate::Pass, inject)
        };
        let (mut client, mut server) = engines(download(4 * MB), 1, false, opts.clone(), opts);
        run(
            &mut client,
            &mut server,
            &mut Link::new(Duration::from_millis(10), 100, 5000),
            Duration::from_secs(30),
            &mut impair,
        );
        assert!(injected);
        let c = &client.stats().client;
        assert!(client.is_done(), "{c:?}");
        if timestamps {
            assert_eq!(
                (c.completed, c.mismatched, c.paws_dropped),
                (1, 0, 1),
                "{c:?}"
            );
        } else {
            assert_eq!((c.mismatched, c.paws_dropped), (1, 0), "{c:?}");
        }
    }
}

#[test]
fn rtt_sets_the_retransmission_timeout() {
    // 300 ms round trip, more than the first timeout: the handshake's round
    // trip is measured, so the data does not time out.
    let (mut client, mut server) = engines(
        download(500_000),
        1,
        false,
        TcpOptions::default(),
        TcpOptions::default(),
    );
    run(
        &mut client,
        &mut server,
        &mut Link::new(Duration::from_millis(150), 20, 2000),
        Duration::from_secs(30),
        &mut pass,
    );
    assert_clean(&client, &server, 1);
    let (c, s) = (&client.stats().client, &server.stats().server);
    // Only the SYN and the SYN-ACK, sent before any round trip was known,
    // time out; the 500 KB of data do not.
    assert!(c.timeouts <= 1, "{c:?}");
    assert!(s.timeouts <= 1, "{s:?}");
}

#[test]
fn templates_keep_their_own_rates_and_limits() {
    let echo = |port, reply: &str| {
        TcpProgram::new(
            port,
            vec![
                TcpMessage::new(TcpRole::Client, "hi\r\n"),
                TcpMessage::new(TcpRole::Server, reply.to_string()),
            ],
        )
        .with_closer(TcpRole::Server)
    };
    let shared = TcpTemplate::new(Arc::new(echo(7, "a")), "10.0.0.2:7".parse().unwrap())
        .with_name("shared")
        .with_connections(30);
    let paced = TcpTemplate::new(Arc::new(echo(8, "b")), "10.0.0.2:8".parse().unwrap())
        .with_name("paced")
        .with_cps(20.0)
        .with_connections(10);
    let slow = TcpTemplate::new(Arc::new(download(200_000)), "10.0.0.2:80".parse().unwrap())
        .with_name("slow")
        .with_connections(4)
        .with_concurrency(1);
    let templates = vec![shared, paced, slow];
    let mut c = TcpClientConfig::new(TcpEndpoint::new(0, CLIENT_MAC, addr("10.0.0.1")));
    c.connections = 0; // the templates' own limits end the run
    c.cps = 200.0;
    let mut client = TcpEngine::new(TcpConfig {
        templates: templates.clone(),
        client: Some(c),
        server: None,
        options: TcpOptions::default(),
    })
    .unwrap();
    let mut server = TcpEngine::new(TcpConfig {
        templates,
        client: None,
        server: Some(TcpServerConfig::new(TcpEndpoint::new(
            0,
            SERVER_MAC,
            addr("10.0.0.2"),
        ))),
        options: TcpOptions::default(),
    })
    .unwrap();
    let mut most_slow_open = 0;
    let mut watch = |_: usize, _: &[u8], _: &mut Watch, _: Duration| (Fate::Pass, Vec::new());
    let mut link = Link::new(Duration::from_millis(5), 20, 1000);
    // Step by hand to watch the slow template's open connections.
    let mut took = Duration::ZERO;
    for _ in 0..100 {
        let (t, _) = run_from(
            &mut client,
            &mut server,
            &mut link,
            took,
            took + Duration::from_millis(20),
            &mut watch,
        );
        took = t;
        most_slow_open = most_slow_open.max(client.stats().templates[2].client.active);
        if client.is_done() {
            break;
        }
    }
    assert!(client.is_done(), "{:?}", client.stats());
    let st = client.stats();
    let started: Vec<u64> = st.templates.iter().map(|t| t.client.started).collect();
    assert_eq!(started, [30, 10, 4]);
    assert_eq!(st.client.completed, 44, "{st:?}");
    assert_eq!(most_slow_open, 1);
    // Ten at 20 per second take about half a second.
    assert!(took >= Duration::from_millis(450), "{took:?}");
}

/// An echo of one line; the server closes.
fn echo() -> TcpProgram {
    TcpProgram::new(
        80,
        vec![
            TcpMessage::new(TcpRole::Client, "hello from FeroTRX\r\n"),
            TcpMessage::new(TcpRole::Server, "hello from FeroTRX\r\n"),
        ],
    )
    .with_closer(TcpRole::Server)
}

/// `f` with its TCP sequence number and flags replaced, checksum fixed.
fn rewrite(f: &[u8], seq: u32, flags: u8) -> Vec<u8> {
    let mut f = f.to_vec();
    let s = tcp_of(&f).unwrap();
    f[s.tcp + 4..s.tcp + 8].copy_from_slice(&seq.to_be_bytes());
    f[s.tcp + 13] = flags;
    fix_tcp_checksum(&mut f);
    f
}

#[test]
fn a_reset_does_not_end_time_wait() {
    // The server closes first and waits in TIME_WAIT; its last ACK is lost,
    // and a router answers it with a reset of its own, as Linux does when
    // conntrack finds a packet INVALID and leaves it addressed to the router.
    // The server stays (RFC 1337), answers the client's repeated FIN, and the
    // client completes instead of getting a reset.
    for v6 in [false, true] {
        let mut server_fin = false;
        let mut client_fin: Option<Vec<u8>> = None;
        let mut rst: Option<Vec<u8>> = None;
        let mut injected = false;
        let mut impair = |d: usize, f: &[u8], _: &mut Watch, _: Duration| {
            let Some(s) = tcp_of(f) else {
                return (Fate::Pass, Vec::new());
            };
            if d == 1 && s.flags & 0x01 != 0 {
                server_fin = true;
            }
            if d == 0 && s.flags & 0x01 != 0 && s.payload == 0 {
                client_fin.get_or_insert_with(|| f.to_vec());
            }
            if d == 1 && server_fin && rst.is_none() && s.flags == 0x10 && s.payload == 0 {
                if let Some(fin) = &client_fin {
                    // The router's RST in reply to that ACK: its sequence
                    // number is the ACK's. It goes to the server, ahead of
                    // the client's next segment.
                    rst = Some(rewrite(fin, s.ack, 0x04));
                    return (Fate::Drop, Vec::new());
                }
            }
            if d == 0 && !injected {
                if let Some(r) = rst.take() {
                    injected = true;
                    return (Fate::Pass, vec![r]);
                }
            }
            (Fate::Pass, Vec::new())
        };
        let (mut client, mut server) =
            engines(echo(), 1, v6, TcpOptions::default(), TcpOptions::default());
        run(
            &mut client,
            &mut server,
            &mut Link::new(Duration::from_millis(5), 100, 100),
            Duration::from_secs(20),
            &mut impair,
        );
        assert!(injected, "v6 {v6}");
        assert_clean(&client, &server, 1);
    }
}

#[test]
fn resets_outside_the_window_are_ignored() {
    // A stray reset, far from what the client expects, in the middle of a
    // download: the connection goes on.
    let mut injected = false;
    let mut impair = |d: usize, f: &[u8], w: &mut Watch, now: Duration| {
        let mut inject = Vec::new();
        if let (Some(s), Some(ack)) = (tcp_of(f), w.client_ack) {
            if d == 1 && s.payload > 0 && !injected && now > Duration::from_millis(50) {
                injected = true;
                inject.push(rewrite(f, ack.wrapping_add(1 << 30), 0x04));
            }
        }
        (Fate::Pass, inject)
    };
    let (mut client, mut server) = engines(
        download(MB),
        1,
        false,
        TcpOptions::default(),
        TcpOptions::default(),
    );
    run(
        &mut client,
        &mut server,
        &mut Link::new(Duration::from_millis(10), 100, 2000),
        Duration::from_secs(20),
        &mut impair,
    );
    assert!(injected);
    assert_clean(&client, &server, 1);
}

#[test]
fn a_reset_after_the_last_ack_completes() {
    // The client closes first. Its last ACK is lost, and so are the server's
    // resent FINs until the client has left TIME_WAIT; the client then
    // answers the next one with a reset, as a host does. The server had sent
    // everything and had the client's FIN: it completed, and does not count
    // a reset.
    let program = TcpProgram::new(
        80,
        vec![
            TcpMessage::new(TcpRole::Client, "hello from FeroTRX\r\n"),
            TcpMessage::new(TcpRole::Server, "hello from FeroTRX\r\n"),
        ],
    )
    .with_closer(TcpRole::Client);
    let (mut client, mut server) = engines(
        program,
        1,
        false,
        TcpOptions::default(),
        TcpOptions::default(),
    );
    let mut link = Link::new(Duration::from_millis(5), 100, 100);
    let mut server_fin: Option<Duration> = None;
    let mut client_rst = false;
    let step = Duration::from_micros(100);
    let mut now = Duration::ZERO;
    while now < Duration::from_secs(30) {
        for f in link.arrived(0, now) {
            server.handle_frame(0, &f, now);
        }
        for f in link.arrived(1, now) {
            client.handle_frame(0, &f, now);
        }
        for (d, e) in [(0, &mut client), (1, &mut server)] {
            e.poll(now);
            for (_, f) in e.take_output() {
                let Some(s) = tcp_of(&f) else {
                    link.send(d, f, now, Duration::ZERO);
                    continue;
                };
                let drop = match d {
                    // The client's ACKs once the server has sent its FIN.
                    0 => {
                        client_rst |= s.flags & 0x04 != 0;
                        server_fin.is_some() && s.flags == 0x10
                    }
                    // The server's FINs after its first, for 6 s.
                    _ if s.flags & 0x01 != 0 => match server_fin {
                        None => {
                            server_fin = Some(now);
                            false
                        }
                        Some(t) => now < t + Duration::from_secs(6),
                    },
                    _ => false,
                };
                if !drop {
                    link.send(d, f, now, Duration::ZERO);
                }
            }
        }
        if server_fin.is_some() && server.open_connections() == 0 {
            break;
        }
        now += step;
    }
    assert!(client_rst, "the client never reset");
    let (c, s) = (&client.stats().client, &server.stats().server);
    assert_eq!((c.completed, c.failed()), (1, 0), "{c:?}");
    assert_eq!((s.completed, s.failed(), s.reset), (1, 0, 0), "{s:?}");
}

fn with(congestion: Congestion, ecn: bool) -> TcpOptions {
    TcpOptions {
        congestion,
        ecn,
        ..Default::default()
    }
}

/// Runs a download of `size` over `link` with `opts` at both ends, losing
/// every `nth` data segment the server sends (0: none); returns how long
/// it took and the server's counters.
fn download_over(
    link: &mut Link,
    size: usize,
    opts: TcpOptions,
    nth: u64,
) -> (Duration, TcpSideStats, TcpSideStats) {
    let (mut client, mut server) = engines(download(size), 1, false, opts.clone(), opts);
    let mut n = 0u64;
    let mut impair = |d: usize, f: &[u8], _: &mut Watch, _: Duration| {
        if nth > 0 && d == 1 && tcp_of(f).is_some_and(|s| s.payload > 0) {
            n += 1;
            if n.is_multiple_of(nth) {
                return (Fate::Drop, Vec::new());
            }
        }
        (Fate::Pass, Vec::new())
    };
    let (took, _) = run(
        &mut client,
        &mut server,
        link,
        Duration::from_secs(120),
        &mut impair,
    );
    assert_clean(&client, &server, 1);
    (
        took,
        client.stats().client.clone(),
        server.stats().server.clone(),
    )
}

#[test]
fn cubic_fills_a_long_fat_lossy_pipe_faster_than_newreno() {
    // 100 Mbit/s, 200 ms round trip, one data segment in 2000 lost. Its
    // windows are set by the losses: NewReno halves and grows back a
    // segment per round trip; CUBIC backs off to 70% and grows back on its
    // curve, by time instead of round trips, so it keeps more in flight
    // (here 32 MB take 19 s instead of 45 s).
    let path = || Link::new(Duration::from_millis(100), 100, 2000);
    let mut took = Vec::new();
    for c in Congestion::ALL {
        let (t, _, s) = download_over(&mut path(), 32 * MB, with(c, false), 2000);
        // The losses, each resent once, in recovery.
        assert!(s.retransmits >= 10 && s.timeouts == 0, "{c}: {s:?}");
        took.push(t);
    }
    let (reno, cubic) = (took[0], took[1]);
    assert!(
        cubic.as_secs_f64() < reno.as_secs_f64() * 0.6,
        "newreno {reno:?}, cubic {cubic:?}"
    );
}

#[test]
fn ecn_with_a_marking_queue_needs_no_retransmits() {
    // A short queue that slow start overflows; with ECN it marks from 20
    // frames waiting, and the sender slows down before the queue is full.
    for c in Congestion::ALL {
        let mut link = Link::new(Duration::from_millis(20), 50, 60).marking(20);
        let (_, client, server) = download_over(&mut link, 4 * MB, with(c, true), 0);
        assert_eq!(link.dirs[1].dropped_queue, 0, "{c}");
        assert!(link.dirs[1].marked > 0, "{c}");
        assert_eq!(
            (server.retransmits, server.timeouts),
            (0, 0),
            "{c}: {server:?}"
        );
        assert_eq!((client.ecn_connections, server.ecn_connections), (1, 1));
        // Every mark the client saw came back as ECE; the server reduced at
        // most once a round trip for them.
        assert_eq!(client.ce_marks, link.dirs[1].marked, "{c}");
        assert!(
            server.ecn_reductions > 0 && server.ecn_reductions <= client.ce_marks,
            "{c}: {server:?}"
        );
        // Without ECN, the same queue overflows.
        let mut link = Link::new(Duration::from_millis(20), 50, 60).marking(20);
        let (_, client, server) = download_over(&mut link, 4 * MB, with(c, false), 0);
        assert!(
            link.dirs[1].dropped_queue > 0 && server.retransmits > 0,
            "{c}"
        );
        assert_eq!(link.dirs[1].marked, 0, "{c}: nothing ECN-capable");
        assert_eq!((client.ecn_connections, server.ce_marks), (0, 0));
    }
}

#[test]
fn ecn_is_used_only_when_both_ends_agree_and_marks_new_data_only() {
    for (c_ecn, s_ecn) in [(true, true), (true, false), (false, true)] {
        let (mut client, mut server) = engines(
            download(MB),
            1,
            false,
            with(Congestion::NewReno, c_ecn),
            with(Congestion::NewReno, s_ecn),
        );
        let both = c_ecn && s_ecn;
        let (mut syn, mut synack) = (None, None);
        let (mut ect_data, mut ect_other, mut ect_resent) = (0, 0, 0);
        let mut highest = 0u32;
        let mut drops = 0;
        let mut impair = |d: usize, f: &[u8], _: &mut Watch, _: Duration| {
            let Some(s) = tcp_of(f) else {
                return (Fate::Pass, Vec::new());
            };
            match (d, s.flags & 0x12) {
                (0, 0x02) => {
                    syn.get_or_insert(s.flags);
                }
                (1, 0x12) => {
                    synack.get_or_insert(s.flags);
                }
                _ => {}
            }
            let ect = ecn_of(f) == 0b10;
            if d == 1 && s.payload > 0 {
                let end = s.seq.wrapping_add(s.payload as u32);
                let resent = highest != 0 && (end.wrapping_sub(highest) as i32) <= 0;
                if resent {
                    ect_resent += u32::from(ect);
                } else {
                    ect_data += u32::from(ect);
                    highest = end;
                    // Lose a few, for retransmissions.
                    if s.seq % 97 == 0 || drops < 3 && end > 100_000 && end < 200_000 {
                        drops += 1;
                        return (Fate::Drop, Vec::new());
                    }
                }
            } else if s.payload == 0 {
                ect_other += u32::from(ect);
            }
            (Fate::Pass, Vec::new())
        };
        run(
            &mut client,
            &mut server,
            &mut Link::new(Duration::from_millis(5), 100, 1000),
            Duration::from_secs(30),
            &mut impair,
        );
        assert_clean(&client, &server, 1);
        // ECE and CWR on the SYN when the client offers it; ECE alone on
        // the SYN-ACK when the server agrees.
        assert_eq!(syn.unwrap() & 0xc0, if c_ecn { 0xc0 } else { 0 });
        assert_eq!(synack.unwrap() & 0xc0, if both { 0x40 } else { 0 });
        let s = &server.stats().server;
        assert_eq!(s.ecn_connections, u64::from(both));
        assert!(s.retransmits > 0, "{s:?}");
        // New data is ECN-capable; retransmissions, SYNs and pure ACKs never.
        assert_eq!(ect_data > 0, both, "{c_ecn} {s_ecn}");
        assert_eq!((ect_resent, ect_other), (0, 0));
    }
}

#[test]
fn a_template_has_its_own_congestion_control_and_ecn() {
    // The run's options say NewReno without ECN; the template says CUBIC
    // with ECN, at both ends.
    let mut tpl = TcpTemplate::new(Arc::new(download(MB)), "10.0.0.2:80".parse().unwrap());
    tpl.congestion = Some(Congestion::Cubic);
    tpl.ecn = Some(true);
    let mut c = TcpClientConfig::new(TcpEndpoint::new(0, CLIENT_MAC, addr("10.0.0.1")));
    c.connections = 1;
    let mut client = TcpEngine::new(TcpConfig {
        templates: vec![tpl.clone()],
        client: Some(c),
        server: None,
        options: TcpOptions::default(),
    })
    .unwrap();
    let mut server = TcpEngine::new(TcpConfig {
        templates: vec![tpl],
        client: None,
        server: Some(TcpServerConfig::new(TcpEndpoint::new(
            0,
            SERVER_MAC,
            addr("10.0.0.2"),
        ))),
        options: TcpOptions::default(),
    })
    .unwrap();
    let mut link = Link::new(Duration::from_millis(20), 50, 60).marking(20);
    run(
        &mut client,
        &mut server,
        &mut link,
        Duration::from_secs(30),
        &mut pass,
    );
    assert_clean(&client, &server, 1);
    let s = &server.stats().server;
    assert_eq!(s.ecn_connections, 1, "{s:?}");
    assert!(link.dirs[1].marked > 0 && s.ecn_reductions > 0, "{s:?}");
}

#[test]
fn both_ends_agree_on_ecn_whichever_syn_the_server_saw() {
    // A lost SYN-ACK: the client asks again without ECN, the server answers
    // the first SYN's agreement again, and both use ECN. A lost first SYN:
    // the server only sees the one without ECN, and neither does.
    for (lose, want) in [(1usize, 1u64), (0, 0)] {
        let (mut client, mut server) = engines(
            download(100_000),
            1,
            false,
            with(Congestion::NewReno, true),
            with(Congestion::NewReno, true),
        );
        let mut syns = Vec::new();
        let mut lost = false;
        let mut impair = |d: usize, f: &[u8], _: &mut Watch, _: Duration| {
            if let Some(s) = tcp_of(f).filter(|s| s.flags & 0x02 != 0) {
                if d == 0 {
                    syns.push(s.flags & 0xc0);
                }
                if d == lose && !lost {
                    lost = true;
                    return (Fate::Drop, Vec::new());
                }
            }
            (Fate::Pass, Vec::new())
        };
        run(
            &mut client,
            &mut server,
            &mut Link::new(Duration::from_millis(5), 100, 1000),
            Duration::from_secs(10),
            &mut impair,
        );
        assert_clean(&client, &server, 1);
        // The first SYN asked, the second did not.
        assert_eq!(syns, [0xc0, 0], "lose {lose}");
        let (c, s) = (&client.stats().client, &server.stats().server);
        assert_eq!(
            (c.ecn_connections, s.ecn_connections),
            (want, want),
            "lose {lose}"
        );
    }
}
