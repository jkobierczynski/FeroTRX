use super::*;
use crate::app::http::{HttpRequest, HttpRoute};
use std::net::SocketAddr;

fn init(role: AppRole, index: u64, seed: u64) -> SessionInit {
    let a: SocketAddr = "10.0.0.1:40000".parse().unwrap();
    let b: SocketAddr = "10.0.0.2:443".parse().unwrap();
    SessionInit {
        role,
        transport: Transport::Datagram,
        index,
        seed,
        local: if role == AppRole::Client { a } else { b },
        remote: if role == AppRole::Client { b } else { a },
    }
}

/// What one end did over a run.
#[derive(Default, Debug)]
struct Seen {
    transactions: Vec<String>,
    failed: usize,
    handshakes: Vec<String>,
    errors: Vec<String>,
    resent: u64,
    datagrams: usize,
    closed: bool,
}

impl Seen {
    fn take(&mut self, ax: &AppCx) {
        for t in ax.transactions() {
            self.transactions.push(t.label.clone());
            if !t.ok {
                self.failed += 1;
            }
        }
        for h in ax.handshakes() {
            self.handshakes.push(h.label.clone());
        }
        self.errors.extend(ax.protocol_errors().iter().cloned());
        self.resent += ax.resent_count();
        self.closed |= ax.wants_close();
    }
}

/// Plays one connection over a link with `delay` each way, dropping
/// datagrams by `drop(n, to_server)`, until both ends are quiet.
fn play_with(
    h3: &Http3,
    index: u64,
    delay: Duration,
    mut drop: impl FnMut(usize, bool) -> bool,
) -> (Seen, Seen, Duration) {
    let app: &dyn AppProtocol = h3;
    let mut c = app.session(&init(AppRole::Client, index, 7 + index));
    let mut s: Option<Box<dyn AppSession>> = None;
    let (mut cs, mut ss) = (Seen::default(), Seen::default());
    let mut queue: Vec<(Duration, bool, Vec<u8>)> = Vec::new();
    let (mut cw, mut sw): (Option<Duration>, Option<Duration>) = (None, None);
    let mut n = 0;
    let mut now = Duration::ZERO;
    let mut ax = AppCx::new(now, now);
    c.start(&mut ax);
    let mut send =
        |ax: &mut AppCx, to_server: bool, now: Duration, q: &mut Vec<_>, seen: &mut Seen| {
            for d in ax.take_sends() {
                seen.datagrams += 1;
                n += 1;
                if !drop(n, to_server) {
                    q.push((now + delay, to_server, d));
                }
            }
        };
    cw = ax.wake().or(cw);
    send(&mut ax, true, now, &mut queue, &mut cs);
    cs.take(&ax);
    let limit = Duration::from_secs(120);
    loop {
        let next_q = queue.iter().map(|q| q.0).min();
        let next = [next_q, cw, sw].into_iter().flatten().min();
        let Some(t) = next else { break };
        if t > limit {
            break;
        }
        now = t.max(now);
        if next_q == Some(t) {
            let i = queue.iter().position(|q| q.0 == t).unwrap();
            let (_, to_server, d) = queue.remove(i);
            let mut ax = AppCx::new(now, now);
            if to_server {
                let sess = s.get_or_insert_with(|| app.session(&init(AppRole::Server, 0, 99)));
                sess.receive(&d, &mut ax);
                if let Some(w) = ax.wake() {
                    sw = Some(w);
                }
                send(&mut ax, false, now, &mut queue, &mut ss);
                ss.take(&ax);
            } else {
                c.receive(&d, &mut ax);
                if let Some(w) = ax.wake() {
                    cw = Some(w);
                }
                send(&mut ax, true, now, &mut queue, &mut cs);
                cs.take(&ax);
            }
        } else if cw == Some(t) {
            cw = None;
            let mut ax = AppCx::new(now, now);
            c.timer(&mut ax);
            if let Some(w) = ax.wake() {
                cw = Some(w);
            }
            send(&mut ax, true, now, &mut queue, &mut cs);
            cs.take(&ax);
        } else {
            sw = None;
            let mut ax = AppCx::new(now, now);
            if let Some(sess) = s.as_mut() {
                sess.timer(&mut ax);
            }
            if let Some(w) = ax.wake() {
                sw = Some(w);
            }
            send(&mut ax, false, now, &mut queue, &mut ss);
            ss.take(&ax);
        }
    }
    (cs, ss, now)
}

fn play(h3: &Http3) -> (Seen, Seen, Duration) {
    play_with(h3, 0, Duration::from_millis(10), |_, _| false)
}

fn sample() -> Http3 {
    let mut h3 = Http3::default();
    let mut big = HttpRoute::new("/big", 200);
    big.body = vec![b'x'; 300_000].into();
    let mut nf = HttpRoute::new("/missing", 404);
    nf.body = b"no".to_vec().into();
    h3.http.server.routes = vec![HttpRoute::new("/", 200), big, nf];
    let mut post = HttpRequest::new("POST", "/");
    post.body = vec![b'p'; 5000];
    let mut missing = HttpRequest::get("/missing");
    missing.expect = crate::app::http::StatusMatch::Code(404);
    h3.http.client.requests = vec![
        HttpRequest::get("/"),
        HttpRequest::get("/big"),
        post,
        missing,
    ];
    h3.http.client.per_connection = 8;
    h3.concurrent = 3;
    h3
}

#[test]
fn requests_over_http3() {
    let h3 = sample();
    let (c, s, t) = play(&h3);
    assert_eq!(c.errors, Vec::<String>::new(), "{c:?}");
    assert_eq!(s.errors, Vec::<String>::new(), "{s:?}");
    assert_eq!(c.transactions.len(), 8, "{c:?}");
    assert_eq!(c.failed, 0, "{c:?}");
    assert_eq!(s.transactions.len(), 8);
    assert!(c.transactions.iter().filter(|l| *l == "404").count() == 2);
    assert_eq!(c.handshakes, ["QUIC v1 TLS13_AES_256_GCM_SHA384 h3"]);
    assert_eq!(s.handshakes, c.handshakes);
    assert!(c.closed && s.closed);
    assert_eq!(c.resent, 0);
    // A few round trips, not timeouts.
    assert!(t < Duration::from_secs(2), "{t:?}");
}

#[test]
fn survives_loss_both_ways() {
    let h3 = sample();
    for seed in 0..6u64 {
        let mut rng = AppRng::new(seed);
        let (c, s, _) = play_with(&h3, seed, Duration::from_millis(5), |_, _| {
            rng.next_u64() % 100 < 10
        });
        assert_eq!(c.errors, Vec::<String>::new(), "seed {seed}: {c:?}");
        assert_eq!(c.transactions.len(), 8, "seed {seed}: {c:?}");
        assert_eq!(c.failed, 0, "seed {seed}");
        assert!(c.resent + s.resent > 0, "seed {seed}");
        assert_eq!(s.errors, Vec::<String>::new(), "seed {seed}: {s:?}");
    }
}

#[test]
fn lost_handshake_packets_come_again() {
    let h3 = sample();
    // The client's first Initial, then the server's first flight.
    let (c, _, _) = play_with(&h3, 0, Duration::from_millis(5), |n, _| n == 1 || n == 2);
    assert_eq!(c.transactions.len(), 8, "{c:?}");
    assert_eq!(c.errors, Vec::<String>::new());
}

#[test]
fn retry_and_key_updates() {
    let mut h3 = sample();
    h3.quic.retry = true;
    h3.quic.key_update_after = 20;
    let (c, s, _) = play(&h3);
    assert_eq!(c.errors, Vec::<String>::new(), "{c:?}");
    assert_eq!(s.errors, Vec::<String>::new(), "{s:?}");
    assert_eq!(c.transactions.len(), 8);
    assert_eq!(c.handshakes.len(), 1);
}

#[test]
fn a_wrong_alpn_fails_the_handshake() {
    let client = TlsSettings {
        alpn: vec!["h3-29".into()],
        expect_failure: true,
        ..Default::default()
    };
    let mut h3 = Http3::with_tls(Http::default(), client, TlsSettings::default()).unwrap();
    h3.http.client.requests = vec![HttpRequest::get("/")];
    let (c, _, _) = play(&h3);
    assert_eq!(c.handshakes.len(), 1, "{c:?}");
    assert!(
        c.handshakes[0].starts_with("failed: QUIC CRYPTO_ERROR 0x78 no_application_protocol"),
        "{c:?}"
    );
    assert!(c.transactions.is_empty());
}

#[test]
fn route_close_sends_goaway() {
    let mut h3 = sample();
    let mut bye = HttpRoute::new("/", 200);
    bye.close = true;
    h3.http.server.routes = vec![bye];
    h3.http.client.requests = vec![HttpRequest::get("/")];
    h3.http.client.per_connection = 5;
    h3.concurrent = 1;
    let (c, s, _) = play(&h3);
    assert_eq!(c.transactions, ["200"], "{c:?}");
    assert!(c.errors.iter().all(|e| e.contains("unanswered")), "{c:?}");
    assert_eq!(s.errors, Vec::<String>::new());
}

#[cfg(feature = "profile")]
#[test]
fn parses_a_table() {
    let t: toml::Table = r#"
        requests = ["GET /", "GET /a"]
        per_connection = 4
        concurrent = 2
        idle_timeout = "5s"
        stream_window = "256K"
        retry = true
        key_update_after = 100
        tls = { server_name = "lab.example", names = ["lab.example"], verify = true }
    "#
    .parse()
    .unwrap();
    let h3 = parse(&t, std::path::Path::new(".")).unwrap();
    assert_eq!(h3.concurrent, 2);
    assert_eq!(h3.quic.idle_timeout, Duration::from_secs(5));
    assert_eq!(h3.quic.stream_window, 256 * 1024);
    assert!(h3.quic.retry);
    assert!(h3.client_tls().verify);
    assert_eq!(h3.client_tls().alpn, ["h3"]);
    let (c, s, _) = play(&h3);
    assert_eq!(c.transactions.len(), 4, "{c:?} {s:?}");
    let bad: toml::Table = r#"tls = { versions = ["1.2"] }"#.parse().unwrap();
    assert!(parse(&bad, std::path::Path::new(".")).is_err());
}

/// A route's delay must wake the server on time even while the
/// connection's own timer is later: these seeds lost a packet in a way
/// that left the delayed POST unanswered until the idle timeout.
#[cfg(feature = "profile")]
#[test]
fn a_delayed_route_answers_under_loss() {
    let t: toml::Table = r#"
        requests = ["GET /", "GET /style.css", "GET /app.js", "GET /big", "GET /missing 404", "POST /api 201"]
        per_connection = 12
        concurrent = 6
        idle_timeout = "10s"
        [[route]]
        path = "/"
        body = "<html></html>\n"
        [[route]]
        path = "/style.css"
        body = "body { color: teal }\n"
        [[route]]
        path = "/app.js"
        body_size = "20K"
        [[route]]
        path = "/big"
        body_size = "300K"
        [[route]]
        method = "POST"
        path = "/api"
        status = 201
        delay = "2ms"
    "#
    .parse()
    .unwrap();
    let h3 = parse(&t, std::path::Path::new(".")).unwrap();
    for seed in [750u64, 975, 1273, 1486] {
        let mut rng = AppRng::new(seed * 7 + 3);
        let (c, s, t) = play_with(&h3, seed, Duration::from_micros(300), |_, _| {
            rng.next_u64() % 100 < 3
        });
        assert_eq!(c.errors, Vec::<String>::new(), "seed {seed}: {c:?}");
        assert_eq!(s.errors, Vec::<String>::new(), "seed {seed}: {s:?}");
        assert_eq!(c.transactions.len(), 12, "seed {seed}: {c:?}");
        assert_eq!(c.failed, 0, "seed {seed}");
        assert!(t < Duration::from_secs(5), "seed {seed}: {t:?}");
    }
}
