use super::*;
use crate::app::MediaReport;
use std::collections::BTreeMap as Map;

/// One end of a simulated link: a session and what it did.
struct End {
    s: Option<Box<dyn AppSession>>,
    addr: SocketAddr,
    media: u16,
    wake: Option<Duration>,
    closed: bool,
    labels: Map<String, (u64, u64)>,
    media_reports: Vec<MediaReport>,
    sent: u64,
}

impl End {
    fn new(addr: &str, media: u16) -> Self {
        Self {
            s: None,
            addr: addr.parse().unwrap(),
            media,
            wake: None,
            closed: false,
            labels: Map::new(),
            media_reports: Vec::new(),
            sent: 0,
        }
    }

    fn ok(&self, label: &str) -> u64 {
        self.labels.get(label).map_or(0, |l| l.0)
    }

    fn failed(&self, label: &str) -> u64 {
        self.labels.get(label).map_or(0, |l| l.1)
    }
}

enum What {
    Sig(Vec<u8>),
    Media { to: u16, from: u16, data: Vec<u8> },
}

/// Plays a client against a server over a link that takes 2 ms and drops
/// the datagrams `drop` says (by their number), until both are quiet or
/// `limit`. Returns (client, server).
fn play(sip: &Sip, limit: Duration, drop: impl Fn(u64) -> bool) -> (End, End) {
    let mut ends = [
        End::new("10.0.0.1:40000", 16384),
        End::new("10.0.0.2:5060", 20000),
    ];
    let mk = |role, me: &End, peer: &End| {
        sip.session(&SessionInit {
            role,
            transport: Transport::Datagram,
            index: 0,
            seed: me.addr.port().into(),
            local: me.addr,
            remote: peer.addr,
        })
    };
    ends[0].s = Some(mk(AppRole::Client, &ends[0], &ends[1]));
    let mut queue: Vec<(Duration, usize, What)> = Vec::new();
    let mut n = 0u64;
    let mut now = Duration::ZERO;
    let apply = |e: &mut End,
                 cx: &mut AppCx,
                 from: usize,
                 now: Duration,
                 queue: &mut Vec<_>,
                 n: &mut u64| {
        for d in cx.take_sends() {
            *n += 1;
            e.sent += 1;
            if !drop(*n) {
                queue.push((now + Duration::from_millis(2), 1 - from, What::Sig(d)));
            }
        }
        for (f, to, d) in cx.take_media_sends() {
            *n += 1;
            if !drop(*n) {
                queue.push((
                    now + Duration::from_millis(2),
                    1 - from,
                    What::Media {
                        to,
                        from: f,
                        data: d,
                    },
                ));
            }
        }
        e.wake = cx.wake();
        if cx.wants_close() {
            e.closed = true;
        }
        for t in cx.transactions() {
            let l = e.labels.entry(t.label.clone()).or_default();
            if t.ok {
                l.0 += 1;
            } else {
                l.1 += 1;
            }
        }
        e.media_reports.extend(cx.media_reports().iter().cloned());
    };
    {
        let e = &mut ends[0];
        let mut cx = AppCx::new(now, now).with_media_port(Some(e.media));
        e.s.as_mut().unwrap().start(&mut cx);
        apply(e, &mut cx, 0, now, &mut queue, &mut n);
    }
    loop {
        queue.sort_by_key(|q| q.0);
        let next_q = queue.first().map(|q| q.0);
        let wakes: Vec<Duration> = ends
            .iter()
            .filter(|e| !(e.closed && e.s.is_some() && e.addr.port() == 40000))
            .filter_map(|e| e.wake)
            .collect();
        let next_w = wakes.iter().min().copied();
        let t = match (next_q, next_w) {
            (None, None) => break,
            (a, b) => a.unwrap_or(Duration::MAX).min(b.unwrap_or(Duration::MAX)),
        };
        if t > limit {
            break;
        }
        now = t;
        if next_q == Some(t) {
            let (_, to, what) = queue.remove(0);
            if ends[to].s.is_none() {
                let (a, b) = ends.split_at_mut(1);
                b[0].s = Some(mk(AppRole::Server, &b[0], &a[0]));
            }
            // A closed client lingers (the engine keeps it until it is
            // quiet), so it still gets what the server sends again.
            let e = &mut ends[to];
            let mut cx = AppCx::new(now, now).with_media_port(Some(e.media));
            let peer = if to == 0 { "10.0.0.2" } else { "10.0.0.1" };
            match what {
                What::Sig(d) => {
                    if to == 1 {
                        e.closed = false;
                    }
                    e.s.as_mut().unwrap().receive(&d, &mut cx);
                }
                What::Media {
                    to: port,
                    from,
                    data,
                } => {
                    let from = SocketAddr::new(peer.parse().unwrap(), from);
                    e.s.as_mut().unwrap().media(port, from, &data, &mut cx);
                }
            }
            let was_closed = to == 0 && e.closed;
            apply(e, &mut cx, to, now, &mut queue, &mut n);
            e.closed |= was_closed;
        } else {
            for i in 0..2 {
                if ends[i].wake.is_some_and(|w| w <= now) && !(i == 0 && ends[0].closed) {
                    let e = &mut ends[i];
                    e.wake = None;
                    let mut cx = AppCx::new(now, now).with_media_port(Some(e.media));
                    e.s.as_mut().unwrap().timer(&mut cx);
                    apply(e, &mut cx, i, now, &mut queue, &mut n);
                }
            }
        }
    }
    let [c, s] = ends;
    (c, s)
}

fn lab() -> Sip {
    let mut sip = Sip::default();
    sip.client.user = "alice".into();
    sip.client.password = Some("secret".into());
    sip.client.call = Some("bob".into());
    sip.client.duration = Duration::from_secs(2);
    sip.server.users.insert("alice".into(), "secret".into());
    sip.domain = Some("lab.local".into());
    sip
}

#[test]
fn registers_calls_and_hangs_up() {
    let mut sip = lab();
    sip.client.duration = Duration::from_secs(6);
    let (c, s) = play(&sip, Duration::from_secs(60), |_| false);
    assert!(c.closed, "{:?}", c.labels);
    assert_eq!(
        (c.ok("REGISTER 200"), c.ok("INVITE 200"), c.ok("BYE 200")),
        (1, 1, 1),
        "{:?}",
        c.labels
    );
    assert_eq!(c.labels.len(), 3);
    // The server challenged both requests once.
    assert_eq!(s.ok("REGISTER 401"), 1, "{:?}", s.labels);
    assert_eq!(s.ok("INVITE 407"), 1);
    assert_eq!(
        s.ok("REGISTER 200") + s.ok("INVITE 200") + s.ok("BYE 200"),
        3
    );
    assert!(s.closed);
    // Six seconds of 20 ms packets, each way.
    let (cm, sm) = (&c.media_reports[0], &s.media_reports[0]);
    assert_eq!(cm.codec, "PCMU");
    assert!((299..=302).contains(&cm.packets_sent), "{cm:?}");
    assert!(cm.packets_received >= 295, "{cm:?}");
    assert_eq!((cm.lost, sm.lost, cm.duplicates), (0, 0, 0));
    assert!(sm.packets_received >= 295, "{sm:?}");
    assert!(cm.rtcp_sent >= 1 && sm.rtcp_received >= 1);
}

#[test]
fn survives_loss() {
    // Every fourth datagram lost: SIP retransmits, RTP counts the loss.
    let sip = lab();
    let (c, s) = play(&sip, Duration::from_secs(120), |n| n % 4 == 0);
    assert_eq!(
        (c.ok("REGISTER 200"), c.ok("INVITE 200"), c.ok("BYE 200")),
        (1, 1, 1),
        "{:?} / {:?}",
        c.labels,
        s.labels
    );
    // Which way loses packets depends on how the sends interleave.
    let (cm, sm) = (&c.media_reports[0], &s.media_reports[0]);
    assert!(cm.lost + sm.lost > 0, "{cm:?} {sm:?}");
    assert!(cm.packets_received > 0 && sm.packets_received > 0);
    assert!(s.closed, "{:?}", s.labels);
}

#[test]
fn wrong_password_and_busy_and_sha256() {
    let mut sip = lab();
    sip.client.password = Some("guess".into());
    sip.client.expect = SipExpect::Code(403);
    let (c, _) = play(&sip, Duration::from_secs(30), |_| false);
    assert_eq!(c.ok("REGISTER 403"), 1, "{:?}", c.labels);
    assert!(c.closed);

    let mut sip = lab();
    sip.server.answer = 486;
    sip.server.ring = Duration::from_millis(300);
    sip.server.algorithm = Algorithm::Sha256;
    sip.client.expect = SipExpect::Failure;
    let (c, s) = play(&sip, Duration::from_secs(30), |_| false);
    assert_eq!(
        (c.ok("REGISTER 200"), c.ok("INVITE 486")),
        (1, 1),
        "{:?}",
        c.labels
    );
    assert_eq!(s.ok("INVITE 486"), 1);
    assert!(c.media_reports.is_empty());

    // Expecting success but refused: a failure.
    let mut sip = lab();
    sip.server.answer = 603;
    let (c, _) = play(&sip, Duration::from_secs(30), |_| false);
    assert_eq!(c.failed("INVITE 603"), 1, "{:?}", c.labels);
}

#[test]
fn acks_a_refusal_again_after_closing() {
    // Whichever datagram of a refused call is lost, the server gets its ACK
    // within a few T1 and does not wait the 32 s of Timer H (the 407
    // challenge comes first, so both refusals are tried).
    for lost in 1..=8 {
        let mut sip = lab();
        sip.client.register = false;
        sip.client.call = Some("carol".into());
        sip.server.answer = 486;
        sip.client.expect = SipExpect::Code(486);
        let (c, s) = play(&sip, Duration::from_secs(10), |n| n == lost);
        assert_eq!(c.ok("INVITE 486"), 1, "lost {lost}: {:?}", c.labels);
        assert!(c.closed, "lost {lost}");
        assert!(s.closed, "lost {lost}: server still waits: {:?}", s.labels);
        assert_eq!(s.ok("INVITE 486"), 1, "lost {lost}: {:?}", s.labels);
    }
}

#[test]
fn without_registration_auth_or_media() {
    let mut sip = lab();
    sip.client.register = false;
    sip.server.users.clear();
    sip.media = false;
    let (c, s) = play(&sip, Duration::from_secs(30), |_| false);
    assert_eq!(
        (c.ok("INVITE 200"), c.ok("BYE 200")),
        (1, 1),
        "{:?}",
        c.labels
    );
    assert!(c.media_reports.is_empty() && s.media_reports.is_empty());

    // Only registering.
    let mut sip = lab();
    sip.client.call = None;
    let (c, _) = play(&sip, Duration::from_secs(30), |_| false);
    assert_eq!(c.labels.len(), 1);
    assert_eq!(c.ok("REGISTER 200"), 1);
}

#[test]
fn server_hangs_up_long_calls() {
    let mut sip = lab();
    sip.client.duration = Duration::from_secs(600);
    sip.server.max_call = Duration::from_secs(3);
    sip.media = false;
    let (c, s) = play(&sip, Duration::from_secs(60), |_| false);
    assert_eq!(c.ok("BYE received"), 1, "{:?}", c.labels);
    assert_eq!(s.ok("BYE sent 200"), 1, "{:?}", s.labels);
    assert!(c.closed && s.closed);
}

#[test]
fn times_out_without_a_server() {
    let sip = lab();
    // Everything the client sends is lost.
    let (c, _) = play(&sip, Duration::from_secs(60), |_| true);
    assert_eq!(c.failed("REGISTER timeout"), 1, "{:?}", c.labels);
    // T1 500 ms doubling up to T2 4 s for 32 s: 11 sends.
    assert_eq!(c.sent, 11);
}

/// A request as SIPp's built-in UAC sends it.
fn sipp_invite(branch: &str) -> Vec<u8> {
    let body = "v=0\r\n\
o=user1 53655765 2353687637 IN IP4 10.0.0.1\r\n\
s=-\r\n\
c=IN IP4 10.0.0.1\r\n\
t=0 0\r\n\
m=audio 6000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n";
    format!(
        "INVITE sip:service@10.0.0.2:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5061;branch={branch}\r\n\
From: sipp <sip:sipp@10.0.0.1:5061>;tag=1\r\n\
To: service <sip:service@10.0.0.2:5060>\r\n\
Call-ID: 1-1@10.0.0.1\r\n\
CSeq: 1 INVITE\r\n\
Contact: sip:sipp@10.0.0.1:5061\r\n\
Max-Forwards: 70\r\n\
Subject: Performance Test\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[test]
fn server_answers_repeats_and_options() {
    let mut sip = Sip::default();
    sip.server.ring = Duration::from_millis(100);
    let init = SessionInit {
        role: AppRole::Server,
        transport: Transport::Datagram,
        index: 0,
        seed: 1,
        local: "10.0.0.2:5060".parse().unwrap(),
        remote: "10.0.0.1:5061".parse().unwrap(),
    };
    let mut s = sip.session(&init);
    let t = Duration::ZERO;
    let mut cx = AppCx::new(t, t).with_media_port(Some(20000));
    let inv = sipp_invite("z9hG4bK-1");
    assert_eq!(s.receive(&inv, &mut cx), Receive::Taken);
    let out = cx.take_sends();
    assert_eq!(out.len(), 2); // 100, 180
    assert!(out[1].starts_with(b"SIP/2.0 180 Ringing"));
    assert!(!cx.wants_close());
    // The INVITE again: the 180 again.
    let mut cx = AppCx::new(t, t).with_media_port(Some(20000));
    s.receive(&inv, &mut cx);
    assert_eq!(cx.take_sends(), vec![out[1].clone()]);
    // Ringing over: 200 with SDP.
    let t = Duration::from_millis(100);
    let mut cx = AppCx::new(t, t).with_media_port(Some(20000));
    s.timer(&mut cx);
    let ok = cx.take_sends();
    let m = Msg::parse(&ok[0]).unwrap();
    assert_eq!(m.code(), Some(200));
    let sdp = Sdp::parse(&m.body).unwrap();
    assert_eq!((sdp.port, sdp.formats[0].0), (20000, 0));
    assert!(m.tag("To").is_some());
    // No received= (the Via had no rport).
    assert!(!m.get("Via").unwrap().contains("received"));
    // The SDP address is the sender's: RTP goes out at once.
    let t = Duration::from_millis(150);
    let mut cx = AppCx::new(t, t).with_media_port(Some(20000));
    let ack = String::from_utf8(inv.clone())
        .unwrap()
        .replace("INVITE sip", "ACK sip")
        .replace("1 INVITE", "1 ACK");
    let ack = format!(
        "{}Content-Length: 0\r\n\r\n",
        ack.split("Content-Type").next().unwrap()
    );
    assert_eq!(s.receive(ack.as_bytes(), &mut cx), Receive::Taken);
    let mut cx = AppCx::new(Duration::from_millis(200), t).with_media_port(Some(20000));
    s.timer(&mut cx);
    let media = cx.take_media_sends();
    assert!(!media.is_empty());
    assert_eq!((media[0].0, media[0].1), (20000, 6000));
    // OPTIONS while in the call; not closed.
    let mut cx = AppCx::new(t, t).with_media_port(Some(20000));
    let opt =
        b"OPTIONS sip:10.0.0.2 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5061;branch=z9hG4bKo;rport\r\n\
From: <sip:x@y>;tag=9\r\nTo: <sip:10.0.0.2>\r\nCall-ID: o1\r\nCSeq: 1 OPTIONS\r\n\r\n";
    s.receive(opt, &mut cx);
    let r = Msg::parse(&cx.take_sends()[0]).unwrap();
    assert_eq!(r.code(), Some(200));
    assert!(r
        .get("Via")
        .unwrap()
        .contains("rport=5061;received=10.0.0.1"));
    assert!(!cx.wants_close());
    assert_eq!(s.receive(b"not sip", &mut cx), Receive::NotMine);
}
