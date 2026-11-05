//! Application protocols on the TCP and UDP engines: HTTP and DNS over TCP
//! between two engines on a link that drops and reorders segments, profiles
//! with `app = "..."`, and a protocol of our own through the registry.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ferotrx_core::app::http::{Http, HttpRequest, HttpRoute};
use ferotrx_core::app::{
    AppCx, AppRegistry, AppRole, AppSession, AppTransaction, Receive, SessionInit,
};
use ferotrx_core::*;

const CLIENT_MAC: MacAddr = MacAddr([0x02, 0, 10, 0, 0, 1]);
const SERVER_MAC: MacAddr = MacAddr([0x02, 0, 10, 0, 0, 2]);

fn ep(mac: MacAddr, ip: &str) -> TcpEndpoint {
    TcpEndpoint::new(0, mac, ip.parse().unwrap()).with_prefix(24)
}

/// A link between the engines that drops every `drop_every`-th TCP frame
/// and holds every `delay_every`-th back by 5 ms, so later ones overtake it.
struct Link {
    drop_every: u64,
    delay_every: u64,
    seen: u64,
    dropped: u64,
    held: Vec<(Duration, Vec<u8>)>,
}

impl Link {
    fn new(drop_every: u64, delay_every: u64) -> Self {
        Self {
            drop_every,
            delay_every,
            seen: 0,
            dropped: 0,
            held: Vec::new(),
        }
    }

    fn pass(&mut self, f: Vec<u8>, now: Duration, out: &mut Vec<Vec<u8>>) {
        let tcp = f.len() > 23 && f[12..14] == [0x08, 0x00] && f[23] == 6;
        if tcp {
            self.seen += 1;
            if self.drop_every > 0 && self.seen.is_multiple_of(self.drop_every) {
                self.dropped += 1;
                return;
            }
            if self.delay_every > 0 && self.seen.is_multiple_of(self.delay_every) {
                self.held.push((now + Duration::from_millis(5), f));
                return;
            }
        }
        out.push(f);
    }

    fn due(&mut self, now: Duration) -> Vec<Vec<u8>> {
        let (due, keep): (Vec<_>, Vec<_>) = self.held.drain(..).partition(|(t, _)| *t <= now);
        self.held = keep;
        due.into_iter().map(|(_, f)| f).collect()
    }
}

/// Runs engines on one link with a simulated clock, 1 ms per step, until the
/// clients are done or `max`.
fn simulate<E: PortEngine>(engines: &mut [&mut E], link: &mut Link, max: Duration) -> Duration {
    let step = Duration::from_millis(1);
    let mut now = Duration::ZERO;
    let mut wire: Vec<Vec<u8>> = Vec::new();
    while now < max {
        wire.extend(link.due(now));
        for f in std::mem::take(&mut wire) {
            for e in engines.iter_mut() {
                e.handle_frame(0, &f, now);
            }
        }
        for e in engines.iter_mut() {
            e.poll(now);
            assert_eq!(e.error(), None);
            for (_, f) in e.take_output() {
                link.pass(f, now, &mut wire);
            }
        }
        if engines.iter().any(|e| e.is_done()) && wire.is_empty() && link.held.is_empty() {
            break;
        }
        now += step;
    }
    now
}

/// A client engine and a server engine playing `templates`.
fn tcp_pair(templates: Vec<TcpTemplate>, connections: u64) -> (TcpEngine, TcpEngine) {
    let mut c = TcpClientConfig::new(ep(CLIENT_MAC, "10.0.0.1").with_ip_count(4));
    c.connections = connections;
    c.cps = 500.0;
    c.concurrency = 20;
    let client = TcpEngine::new(TcpConfig {
        templates: templates.clone(),
        client: Some(c),
        server: None,
        options: TcpOptions::default(),
    })
    .unwrap();
    let server = TcpEngine::new(TcpConfig {
        templates,
        client: None,
        server: Some(TcpServerConfig::new(ep(SERVER_MAC, "10.0.0.80"))),
        options: TcpOptions::default(),
    })
    .unwrap();
    (client, server)
}

fn web() -> Http {
    let mut http = Http::default();
    http.client.requests = vec![
        HttpRequest::get("/"),
        HttpRequest::get("/big"),
        HttpRequest::get("/missing").expect("404"),
        HttpRequest::new("POST", "/upload")
            .with_body(vec![b'x'; 5000])
            .expect("201"),
    ];
    http.client.per_connection = 3;
    http.server.routes = vec![
        HttpRoute::new("/", 200).with_body("hello\n"),
        HttpRoute {
            chunked: true,
            ..HttpRoute::new("/big", 200).with_body(app::filler(150_000))
        },
        HttpRoute {
            method: Some("POST".into()),
            delay: Duration::from_millis(3),
            ..HttpRoute::new("/upload", 201)
        },
    ];
    http
}

#[test]
fn http_keep_alive_over_a_lossy_reordering_link() {
    let t = TcpTemplate::with_app_protocol(App::new(web()), "10.0.0.80:80".parse().unwrap());
    let (mut client, mut server) = tcp_pair(vec![t], 40);
    let mut link = Link::new(37, 11);
    let took = simulate(
        &mut [&mut client, &mut server],
        &mut link,
        Duration::from_secs(120),
    );
    let c = &client.stats().client;
    let s = &server.stats().server;
    assert!(client.is_done(), "not done after {took:?}: {c:?}");
    assert!(link.dropped > 20, "{}", link.dropped);
    assert!(c.retransmits + s.retransmits > 0);
    assert_eq!(
        (c.started, c.completed, c.mismatched, c.failed()),
        (40, 40, 0, 0),
        "{c:?}"
    );
    assert_eq!((s.completed, s.mismatched), (40, 0), "{s:?}");
    // 120 requests, the four kinds in turn.
    assert_eq!(
        (c.app.transactions, c.app.failed, c.app.protocol_errors),
        (120, 0, 0),
        "{:?}",
        c.app
    );
    assert_eq!(c.app.codes.get("200"), Some(&60));
    assert_eq!(c.app.codes.get("404"), Some(&30));
    assert_eq!(c.app.codes.get("201"), Some(&30));
    assert_eq!(c.app.errors, 30);
    assert_eq!(c.app.response_time.count(), 120);
    assert_eq!(s.app.transactions, 120);
    assert_eq!(client.stats().templates[0].client.app.transactions, 120);
}

#[test]
fn pipelined_requests_and_a_server_that_closes() {
    let mut http = web();
    http.client.pipeline = true;
    http.client.per_connection = 4;
    let t = TcpTemplate::with_app_protocol(App::new(http.clone()), "10.0.0.80:80".parse().unwrap());
    let (mut client, mut server) = tcp_pair(vec![t], 10);
    simulate(
        &mut [&mut client, &mut server],
        &mut Link::new(0, 7),
        Duration::from_secs(60),
    );
    let c = &client.stats().client;
    assert_eq!((c.completed, c.mismatched), (10, 0), "{c:?}");
    assert_eq!((c.app.transactions, c.app.failed), (40, 0), "{:?}", c.app);

    // The server closes after the first answer: the client counts the
    // requests that got no answer as a failure of the connection.
    http.server.routes[0].close = true;
    http.client.pipeline = false;
    http.client.requests = vec![HttpRequest::get("/")];
    http.client.per_connection = 2;
    let t = TcpTemplate::with_app_protocol(App::new(http), "10.0.0.80:80".parse().unwrap());
    let (mut client, mut server) = tcp_pair(vec![t], 5);
    simulate(
        &mut [&mut client, &mut server],
        &mut Link::new(0, 0),
        Duration::from_secs(30),
    );
    let c = &client.stats().client;
    assert_eq!((c.completed, c.mismatched), (5, 5), "{c:?}");
    assert_eq!(
        (c.app.transactions, c.app.protocol_errors),
        (5, 5),
        "{:?}",
        c.app
    );
}

fn lab_dns() -> Arc<DnsWorkload> {
    Arc::new(
        DnsWorkload::parse(
            &[
                "www.lab.local A",
                "lab.local MX",
                "nope.lab.local A NXDOMAIN",
            ],
            &[
                "www.lab.local A 10.0.0.80",
                "lab.local MX 10 mail.lab.local",
            ],
        )
        .unwrap(),
    )
}

#[test]
fn dns_over_tcp_and_http_mixed_by_port() {
    let mut dns = app::dns::Dns::new(lab_dns());
    dns.per_connection = 3;
    let templates = vec![
        TcpTemplate::with_app_protocol(App::new(web()), "10.0.0.80:80".parse().unwrap()),
        TcpTemplate::with_app_protocol(App::new(dns), "10.0.0.80:53".parse().unwrap()),
    ];
    let (mut client, mut server) = tcp_pair(templates, 20);
    simulate(
        &mut [&mut client, &mut server],
        &mut Link::new(23, 0),
        Duration::from_secs(60),
    );
    let st = client.stats();
    assert_eq!(
        (st.client.completed, st.client.mismatched),
        (20, 0),
        "{:?}",
        st.client
    );
    let d = &st.templates[1].client.app;
    assert_eq!((d.transactions, d.failed), (30, 0), "{d:?}");
    assert_eq!(
        (d.codes.get("NOERROR"), d.codes.get("NXDOMAIN")),
        (Some(&20), Some(&10))
    );
    assert_eq!(st.templates[0].client.app.transactions, 30);
    assert_eq!(server.stats().templates[1].server.app.transactions, 30);
}

#[test]
fn profiles_name_the_protocol_and_its_table() {
    let text = r#"
        connections = 12
        cps = 200
        [[template]]
        name = "web"
        app = "http"
        port = 8080
        [template.http]
        requests = ["GET /", "GET /nope 404"]
        per_connection = 2
        [[template.http.route]]
        path = "/"
        body_size = "20K"
        [[template]]
        app = "dns"
        weight = 2
        [template.dns]
        queries = ["www.lab.local A"]
        records = ["www.lab.local A 10.0.0.80"]
        per_connection = 2
        [client]
        ip = "10.0.0.1/24"
        [server]
        ip = "10.0.0.80/24"
    "#;
    let p = TcpProfile::from_toml(text, Path::new(".")).unwrap();
    assert_eq!(p.templates[0].name(0), "web");
    assert_eq!(p.templates[1].name(1), "dns");
    assert_eq!(p.templates[0].app().unwrap().name(), "http");
    let programs: Vec<_> = p.programs().unwrap().into_iter().map(Arc::new).collect();
    let config = p
        .config(&programs, &["lo".to_string()], Some("lo"))
        .unwrap();
    assert_eq!(config.templates[0].listen_port, 8080);
    assert_eq!(config.templates[1].listen_port, 53);
    let mut client_cfg = config.clone();
    client_cfg.server = None;
    let mut server_cfg = config;
    server_cfg.client = None;
    let mut client = TcpEngine::new(client_cfg).unwrap();
    let mut server = TcpEngine::new(server_cfg).unwrap();
    simulate(
        &mut [&mut client, &mut server],
        &mut Link::new(0, 0),
        Duration::from_secs(30),
    );
    let st = client.stats();
    assert_eq!(
        (st.client.completed, st.client.mismatched),
        (12, 0),
        "{:?}",
        st.client
    );
    assert_eq!(st.templates[0].client.app.transactions, 8);
    assert_eq!(st.templates[1].client.app.transactions, 16);

    for (bad, why) in [
        (
            "app = \"gopher\"\n[client]\nip = \"10.0.0.1/24\"",
            "unknown app `gopher`",
        ),
        (
            "app = \"http\"\npcap = \"x.pcap\"\n[client]\nip = \"10.0.0.1/24\"",
            "takes no `pcap`",
        ),
        (
            "app = \"http\"\n[http]\nrequests = [\"FETCH\"]\n[server]\nip = \"10.0.0.1/24\"",
            "METHOD PATH",
        ),
        (
            "app = \"http\"\n[http]\nnope = 1\n[server]\nip = \"10.0.0.1/24\"",
            "nope",
        ),
    ] {
        let e = TcpProfile::from_toml(bad, Path::new("."))
            .unwrap_err()
            .to_string();
        assert!(e.contains(why), "{bad}: {e}");
    }
    // Without `app`, errors still say where they are.
    let e = TcpProfile::from_toml("cps = \"x\"", Path::new("."))
        .unwrap_err()
        .to_string();
    assert!(e.contains("line 1"), "{e}");
}

/// A protocol of our own: the client sends `ping N`, the server answers
/// `pong N`; over UDP and TCP (one line per transaction).
struct Ping;

struct PingSession {
    role: AppRole,
    n: u64,
    at: Duration,
}

impl AppProtocol for Ping {
    fn name(&self) -> &str {
        "ping"
    }
    fn describe(&self) -> String {
        "ping/pong".into()
    }
    fn default_port(&self) -> u16 {
        7777
    }
    fn supports(&self, _t: Transport) -> bool {
        true
    }
    fn session(&self, init: &SessionInit) -> Box<dyn AppSession> {
        Box::new(PingSession {
            role: init.role,
            n: init.index,
            at: Duration::ZERO,
        })
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl AppSession for PingSession {
    fn start(&mut self, cx: &mut AppCx) {
        if self.role == AppRole::Client {
            self.at = cx.now();
            cx.send(format!("ping {}\n", self.n));
        }
    }
    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        let text = String::from_utf8_lossy(data);
        match self.role {
            AppRole::Server => match text.strip_prefix("ping ") {
                Some(n) => {
                    cx.send(format!("pong {n}"));
                    cx.transaction(AppTransaction::new("pong", true));
                    Receive::Taken
                }
                None => Receive::NotMine,
            },
            AppRole::Client => {
                if text.trim() != format!("pong {}", self.n) {
                    return Receive::NotMine;
                }
                cx.transaction(
                    AppTransaction::new("pong", true).with_response_time(cx.now() - self.at),
                );
                cx.close();
                Receive::Taken
            }
        }
    }
    fn peer_closed(&mut self, cx: &mut AppCx) {
        cx.close();
    }
}

#[test]
fn a_protocol_of_our_own_over_udp_and_tcp() {
    let mut reg = AppRegistry::builtin();
    reg.register("ping", |_, _| Ok(App::new(Ping)));
    assert!(reg.names().contains(&"ping"));

    let text = "app = \"ping\"\ntransactions = 25\nrate = 500\n[client]\nip = \"10.0.0.1/24\"\n[server]\nip = \"10.0.0.80/24\"\n";
    assert!(
        UdpProfile::from_toml(text, Path::new(".")).is_err(),
        "not built in"
    );
    let p = UdpProfile::from_toml_with(text, Path::new("."), &reg).unwrap();
    let apps = p.apps().unwrap();
    let config = p.config(&apps, &["lo".to_string()], Some("lo")).unwrap();
    assert_eq!(config.templates[0].listen_port, 7777);
    let (mut cc, mut sc) = (config.clone(), config);
    cc.server = None;
    sc.client = None;
    let (mut client, mut server) = (UdpEngine::new(cc).unwrap(), UdpEngine::new(sc).unwrap());
    simulate(
        &mut [&mut client, &mut server],
        &mut Link::new(0, 0),
        Duration::from_secs(10),
    );
    let c = &client.stats().client;
    assert_eq!((c.sent, c.answered, c.mismatched), (25, 25, 0), "{c:?}");
    assert_eq!((c.app.transactions, c.app.response_time.count()), (25, 25));
    assert_eq!(server.stats().server.app.transactions, 25);

    let tcp = TcpProfile::from_toml_with(
        "app = \"ping\"\nconnections = 5\n[client]\nip = \"10.0.0.1/24\"\n[server]\nip = \"10.0.0.80/24\"\n",
        Path::new("."),
        &reg,
    )
    .unwrap();
    let programs: Vec<_> = tcp.programs().unwrap().into_iter().map(Arc::new).collect();
    let config = tcp
        .config(&programs, &["lo".to_string()], Some("lo"))
        .unwrap();
    let (mut cc, mut sc) = (config.clone(), config);
    cc.server = None;
    sc.client = None;
    let (mut client, mut server) = (TcpEngine::new(cc).unwrap(), TcpEngine::new(sc).unwrap());
    simulate(
        &mut [&mut client, &mut server],
        &mut Link::new(0, 0),
        Duration::from_secs(10),
    );
    let c = &client.stats().client;
    assert_eq!(
        (c.completed, c.mismatched, c.app.transactions),
        (5, 0, 5),
        "{c:?}"
    );
}

#[test]
fn dns_from_a_table_in_udp_profiles_and_protocols_that_do_not_fit() {
    let text = r#"
        transactions = 30
        rate = 1000
        app = "dns"
        [dns]
        queries = ["www.lab.local A", "nope.lab.local A NXDOMAIN"]
        records = ["www.lab.local A 10.0.0.80"]
        [client]
        ip = "10.0.0.1/24"
        [server]
        ip = "10.0.0.80/24"
    "#;
    let p = UdpProfile::from_toml(text, Path::new(".")).unwrap();
    let apps = p.apps().unwrap();
    assert_eq!(apps[0].dns_workload().unwrap().queries.len(), 2);
    let config = p.config(&apps, &["lo".to_string()], Some("lo")).unwrap();
    let (mut cc, mut sc) = (config.clone(), config);
    cc.server = None;
    sc.client = None;
    let (mut client, mut server) = (UdpEngine::new(cc).unwrap(), UdpEngine::new(sc).unwrap());
    simulate(
        &mut [&mut client, &mut server],
        &mut Link::new(0, 0),
        Duration::from_secs(10),
    );
    let c = &client.stats().client;
    assert_eq!((c.answered, c.mismatched, c.errors), (30, 0, 15), "{c:?}");
    assert_eq!(c.app.codes.get("NXDOMAIN"), Some(&15));

    let e = UdpProfile::from_toml(
        "app = \"http\"\n[server]\nip = \"10.0.0.80/24\"\n",
        Path::new("."),
    )
    .unwrap_err()
    .to_string();
    assert!(e.contains("does not run over UDP"), "{e}");
    let e = UdpProfile::from_toml(
        "app = \"dns\"\nqueries = [\"a.b A\"]\n[dns]\nqueries = [\"c.d A\"]\n[server]\nip = \"10.0.0.80/24\"\n",
        Path::new("."),
    )
    .unwrap_err()
    .to_string();
    assert!(e.contains("from its [dns] table"), "{e}");
}

#[test]
fn https_over_a_lossy_reordering_link() {
    use ferotrx_core::app::tls::{Tls, TlsSettings};
    let tls = Tls::new(
        App::new(web()),
        TlsSettings {
            alpn: vec!["http/1.1".into()],
            ..Default::default()
        },
    )
    .unwrap();
    let t = TcpTemplate::with_app_protocol(App::new(tls), "10.0.0.80:443".parse().unwrap());
    let (mut client, mut server) = tcp_pair(vec![t], 30);
    let mut link = Link::new(41, 13);
    let took = simulate(
        &mut [&mut client, &mut server],
        &mut link,
        Duration::from_secs(120),
    );
    let c = &client.stats().client;
    let s = &server.stats().server;
    assert!(client.is_done(), "not done after {took:?}: {c:?}");
    assert!(link.dropped > 10, "{}", link.dropped);
    assert_eq!((c.completed, c.mismatched, c.failed()), (30, 0, 0), "{c:?}");
    // The last server connections may still be closing when the clients
    // are done.
    assert_eq!((s.completed + s.active, s.mismatched), (30, 0), "{s:?}");
    assert_eq!((c.app.transactions, c.app.failed), (90, 0), "{:?}", c.app);
    assert_eq!(
        (
            c.app.handshakes,
            c.app.handshake_failures,
            c.app.handshakes_unexpected
        ),
        (30, 0, 0),
        "{:?}",
        c.app.negotiated
    );
    assert!(c.app.resumed > 0, "no session resumed: {:?}", c.app);
    assert_eq!(c.app.handshake_time.count(), 30);
    assert!(c
        .app
        .negotiated
        .keys()
        .all(|k| k.starts_with("TLSv1.3 ") && k.ends_with(" http/1.1")));
    assert_eq!(s.app.handshakes, 30);
}

#[test]
fn https_profiles_and_handshakes_that_must_fail() {
    let run = |text: &str| {
        let p = TcpProfile::from_toml(text, Path::new(".")).unwrap();
        let programs: Vec<_> = p.programs().unwrap().into_iter().map(Arc::new).collect();
        let config = p
            .config(&programs, &["lo".to_string()], Some("lo"))
            .unwrap();
        assert_eq!(config.templates[0].listen_port, 443);
        let mut client_cfg = config.clone();
        client_cfg.server = None;
        let mut server_cfg = config;
        server_cfg.client = None;
        let mut client = TcpEngine::new(client_cfg).unwrap();
        let mut server = TcpEngine::new(server_cfg).unwrap();
        simulate(
            &mut [&mut client, &mut server],
            &mut Link::new(0, 0),
            Duration::from_secs(30),
        );
        (client.stats().client.clone(), server.stats().server.clone())
    };
    let base = r#"
        connections = 6
        cps = 200
        app = "https"
        [http]
        requests = ["GET /"]
        [client]
        ip = "10.0.0.1/24"
        [server]
        ip = "10.0.0.80/24"
    "#;
    let (c, s) = run(base);
    assert_eq!(
        (c.completed, c.mismatched, c.app.transactions),
        (6, 0, 6),
        "{c:?}"
    );
    assert_eq!(s.app.handshakes, 6);

    // TLS 1.2 with one suite, a verified certificate and client certificates.
    let (c, s) = run(&format!(
        r#"{base}
        [tls]
        versions = ["1.2"]
        cipher_suites = ["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"]
        verify = true
        server_name = "www.lab.local"
        names = ["www.lab.local"]
        client_auth = "required"
    "#
    ));
    assert_eq!(
        (c.completed, c.mismatched, c.app.transactions),
        (6, 0, 6),
        "{:?}",
        c.app
    );
    assert_eq!(
        c.app.negotiated.keys().collect::<Vec<_>>(),
        ["TLSv1.2 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 http/1.1"]
    );
    assert_eq!(s.mismatched, 0);

    // A client that offers only TLS 1.2 to a server that wants 1.3: refused,
    // and expected to be.
    let refused = |expect: &str| {
        format!(
            r#"{base}
            [tls.client]
            versions = ["1.2"]
            {expect}
            [tls.server]
            versions = ["1.3"]
            {expect}
        "#
        )
    };
    let (c, s) = run(&refused(r#"expect = "failure""#));
    assert_eq!(c.app.handshake_failures, 6, "{:?}", c.app);
    assert_eq!((c.mismatched, s.mismatched), (0, 0), "{:?}", c.app);
    assert_eq!(c.app.transactions, 0);
    let (c, _) = run(&refused(""));
    assert_eq!(
        (c.app.handshakes_unexpected, c.mismatched),
        (6, 6),
        "{:?}",
        c.app
    );

    // Mistakes in the table.
    for (bad, says) in [
        ("[tls]\nversions = [\"1.0\"]", "not supported"),
        (
            "[tls]\ncipher_suites = [\"RC4_MD5\"]",
            "unknown cipher suite",
        ),
        ("[tls]\nverion = [\"1.3\"]", "verion"),
    ] {
        let e = TcpProfile::from_toml(&format!("{base}\n{bad}"), Path::new("."))
            .unwrap_err()
            .to_string();
        assert!(e.contains(says) && e.contains("[tls]"), "{e}");
    }
}

#[test]
fn mqtt_qos_over_a_lossy_reordering_link_and_in_profiles() {
    use ferotrx_core::app::mqtt::{Mqtt, MqttVersion};
    let mut m = Mqtt::default();
    m.client.version = MqttVersion::V5;
    m.client.subscribe = vec!["lab/# 2".parse().unwrap()];
    m.client.publish = vec![
        "lab/a 0 100".parse().unwrap(),
        "lab/b 1 3K".parse().unwrap(),
        "lab/c 2 20K".parse().unwrap(),
    ];
    m.client.per_connection = 6;
    m.client.interval = Duration::from_millis(2);
    let t = TcpTemplate::with_app_protocol(App::new(m), "10.0.0.80:1883".parse().unwrap());
    let (mut client, mut server) = tcp_pair(vec![t], 20);
    let mut link = Link::new(43, 17);
    let took = simulate(
        &mut [&mut client, &mut server],
        &mut link,
        Duration::from_secs(120),
    );
    let c = &client.stats().client;
    assert!(client.is_done(), "not done after {took:?}: {c:?}");
    assert!(link.dropped > 5, "{}", link.dropped);
    assert_eq!((c.completed, c.mismatched, c.failed()), (20, 0, 0), "{c:?}");
    assert_eq!(c.app.failed, 0, "{:?}", c.app.codes);
    assert_eq!(c.app.codes.get("received"), Some(&120), "{:?}", c.app.codes);
    assert_eq!(c.app.codes.get("PUBACK"), Some(&40));
    assert_eq!(c.app.codes.get("PUBCOMP"), Some(&40));
    assert_eq!(c.app.codes.get("published"), Some(&40));

    // In a profile, with a login the broker refuses.
    let text = r#"
        connections = 4
        cps = 200
        app = "mqtt"
        [mqtt]
        username = "u"
        password = "p"
        users = { u = "q" }
        expect = "bad credentials"
        [client]
        ip = "10.0.0.1/24"
        [server]
        ip = "10.0.0.80/24"
    "#;
    let p = TcpProfile::from_toml(text, Path::new(".")).unwrap();
    let programs: Vec<_> = p.programs().unwrap().into_iter().map(Arc::new).collect();
    let config = p
        .config(&programs, &["lo".to_string()], Some("lo"))
        .unwrap();
    assert_eq!(config.templates[0].listen_port, 1883);
    let mut client_cfg = config.clone();
    client_cfg.server = None;
    let mut server_cfg = config;
    server_cfg.client = None;
    let mut client = TcpEngine::new(client_cfg).unwrap();
    let mut server = TcpEngine::new(server_cfg).unwrap();
    simulate(
        &mut [&mut client, &mut server],
        &mut Link::new(0, 0),
        Duration::from_secs(30),
    );
    let c = &client.stats().client;
    assert_eq!((c.completed, c.mismatched), (4, 0), "{c:?}");
    assert_eq!(c.app.codes.get("CONNACK bad credentials"), Some(&4));
}

#[test]
fn http2_over_a_lossy_reordering_link() {
    use ferotrx_core::app::http2::Http2;
    let mut h2 = Http2 {
        http: web(),
        ..Default::default()
    };
    h2.http.client.per_connection = 8;
    h2.settings.concurrent = 4;
    let t = TcpTemplate::with_app_protocol(App::new(h2), "10.0.0.80:80".parse().unwrap());
    let (mut client, mut server) = tcp_pair(vec![t], 20);
    let mut link = Link::new(37, 11);
    let took = simulate(
        &mut [&mut client, &mut server],
        &mut link,
        Duration::from_secs(120),
    );
    let c = &client.stats().client;
    let s = &server.stats().server;
    assert!(client.is_done(), "not done after {took:?}: {c:?}");
    assert!(link.dropped > 10, "{}", link.dropped);
    assert_eq!((c.completed, c.mismatched, c.failed()), (20, 0, 0), "{c:?}");
    assert_eq!((s.completed + s.active, s.mismatched), (20, 0), "{s:?}");
    assert_eq!((c.app.transactions, c.app.failed), (160, 0), "{:?}", c.app);
    assert_eq!(c.app.codes["404"], 40, "{:?}", c.app.codes);
    assert_eq!(s.app.transactions, 160);
}

#[test]
fn http2_profiles_over_tls_and_without() {
    let run = |text: &str| {
        let p = TcpProfile::from_toml(text, Path::new(".")).unwrap();
        let programs: Vec<_> = p.programs().unwrap().into_iter().map(Arc::new).collect();
        let config = p
            .config(&programs, &["lo".to_string()], Some("lo"))
            .unwrap();
        let port = config.templates[0].listen_port;
        let mut client_cfg = config.clone();
        client_cfg.server = None;
        let mut server_cfg = config;
        server_cfg.client = None;
        let mut client = TcpEngine::new(client_cfg).unwrap();
        let mut server = TcpEngine::new(server_cfg).unwrap();
        simulate(
            &mut [&mut client, &mut server],
            &mut Link::new(0, 0),
            Duration::from_secs(30),
        );
        (
            port,
            client.stats().client.clone(),
            server.stats().server.clone(),
        )
    };
    let body = r#"
        connections = 5
        cps = 200
        [http2]
        requests = ["GET /", "GET /missing 404"]
        per_connection = 4
        window = 1048576
        [[http2.route]]
        path = "/"
        body = "hello over h2\n"
        [client]
        ip = "10.0.0.1/24"
        [server]
        ip = "10.0.0.80/24"
    "#;
    // h2: over TLS, ALPN h2.
    let (port, c, s) = run(&format!("app = \"h2\"\n{body}"));
    assert_eq!(port, 443);
    assert_eq!(
        (c.completed, c.mismatched, c.app.transactions),
        (5, 0, 20),
        "{:?}",
        c.app
    );
    assert!(
        c.app.negotiated.keys().all(|k| k.ends_with(" h2")),
        "{:?}",
        c.app.negotiated
    );
    assert_eq!(s.app.transactions, 20);
    // h2c: without TLS, and the same with app = "http2".
    for app in ["h2c", "http2"] {
        let (port, c, _) = run(&format!("app = \"{app}\"\n{body}"));
        assert_eq!(port, 80);
        assert_eq!((c.completed, c.mismatched, c.app.transactions), (5, 0, 20));
        assert_eq!(c.app.handshakes, 0);
    }
    // An HTTP/1.1 client and an HTTP/2 server on one port (ALPN gives the
    // server's second choice).
    let text = r#"format = 1
        connections = 4
        cps = 200
        [client]
        ip = "10.0.0.1/24"
        [server]
        ip = "10.0.0.80/24"
        [[template]]
        name = "h1"
        app = "https"
        [template.http]
        requests = ["GET /"]
        [[template]]
        name = "h2"
        app = "h2"
        [template.http2]
        requests = ["GET /"]
        "#;
    let p = TcpProfile::from_toml(text, Path::new(".")).unwrap();
    assert_eq!(p.templates.len(), 2);
    let e = TcpProfile::from_toml(
        &format!(
            "app = \"http2\"\n[http2]\npipeline = true\n{}",
            "[server]\nip = \"10.0.0.80/24\"\n"
        ),
        Path::new("."),
    )
    .unwrap_err()
    .to_string();
    assert!(e.contains("pipeline"), "{e}");
}

#[test]
fn ssh_over_a_lossy_reordering_link_and_in_profiles() {
    use ferotrx_core::app::ssh::{Input, Ssh, SshCommand};
    let mut s = Ssh::default();
    s.client.commands = vec![
        SshCommand::new("echo hello"),
        SshCommand {
            output_size: Some(200_000),
            ..SshCommand::new("head -c 200000 /dev/zero")
        },
        SshCommand {
            input: Input::Filler(100_000),
            output_size: Some(100_000),
            ..SshCommand::new("cat")
        },
    ];
    s.client.per_connection = 3;
    s.client.rekey_after = Some(150_000);
    let t = TcpTemplate::with_app_protocol(App::new(s), "10.0.0.80:22".parse().unwrap());
    let (mut client, mut server) = tcp_pair(vec![t], 10);
    let mut link = Link::new(41, 13);
    let took = simulate(
        &mut [&mut client, &mut server],
        &mut link,
        Duration::from_secs(120),
    );
    let c = &client.stats().client;
    let sv = &server.stats().server;
    assert!(client.is_done(), "not done after {took:?}: {c:?}");
    assert!(link.dropped > 5, "{}", link.dropped);
    assert_eq!((c.completed, c.mismatched, c.failed()), (10, 0, 0), "{c:?}");
    assert_eq!((sv.completed + sv.active, sv.mismatched), (10, 0), "{sv:?}");
    assert_eq!(c.app.failed, 0, "{:?}", c.app.codes);
    assert_eq!(c.app.codes["auth password"], 10, "{:?}", c.app.codes);
    assert_eq!(c.app.codes["exit 0"], 30);
    assert!(c.app.codes["rekey"] >= 10, "{:?}", c.app.codes);
    assert_eq!((c.app.handshakes, c.app.handshake_failures), (10, 0));

    // In a profile, with a login the server refuses.
    let text = r#"
        connections = 4
        cps = 200
        app = "ssh"
        [ssh]
        user = "root"
        password = "guess"
        users = { root = "lab" }
        expect = "failure"
        [client]
        ip = "10.0.0.1/24"
        [server]
        ip = "10.0.0.80/24"
    "#;
    let p = TcpProfile::from_toml(text, Path::new(".")).unwrap();
    let programs: Vec<_> = p.programs().unwrap().into_iter().map(Arc::new).collect();
    let config = p
        .config(&programs, &["lo".to_string()], Some("lo"))
        .unwrap();
    assert_eq!(config.templates[0].listen_port, 22);
    let mut client_cfg = config.clone();
    client_cfg.server = None;
    let mut server_cfg = config;
    server_cfg.client = None;
    let mut client = TcpEngine::new(client_cfg).unwrap();
    let mut server = TcpEngine::new(server_cfg).unwrap();
    simulate(
        &mut [&mut client, &mut server],
        &mut Link::new(0, 0),
        Duration::from_secs(30),
    );
    let c = &client.stats().client;
    assert_eq!((c.completed, c.mismatched), (4, 0), "{c:?}");
    assert_eq!(c.app.codes.get("auth refused"), Some(&4));
}
