//! Hostile peers: oversized lengths, endless headers, slow trickles and
//! floods of streams, against the application servers as the engines run
//! them. Each must stay bounded (stop taking bytes it cannot use, with a
//! protocol error) and keep working for peers that only go slowly.

use std::path::Path;
use std::time::Duration;

use ferotrx_core::app::{App, AppCx, AppRole, AppSession, SessionInit, Transport};
use ferotrx_core::TcpProfile;

fn app(extra: &str) -> App {
    let text = format!(
        "format = 1\n{extra}\n[client]\nip = \"10.0.0.1/24\"\n[server]\nip = \"10.0.0.2/24\"\n"
    );
    TcpProfile::from_toml(&text, Path::new("."))
        .unwrap()
        .templates[0]
        .app()
        .unwrap()
        .clone()
}

fn server(app: &App) -> Box<dyn AppSession> {
    let mut s = app.session(&SessionInit {
        role: AppRole::Server,
        transport: Transport::Stream,
        index: 0,
        seed: 1,
        local: "10.0.0.2:80".parse().unwrap(),
        remote: "10.0.0.1:40000".parse().unwrap(),
    });
    s.start(&mut AppCx::new(Duration::ZERO, Duration::ZERO));
    s
}

/// What a server did with what it was fed.
#[derive(Debug, Default)]
struct Outcome {
    /// Bytes taken before it closed (all of them if it did not).
    fed: usize,
    closed: bool,
    errors: Vec<String>,
    sent: usize,
    transactions: usize,
}

/// Feeds `first`, then `more()` pieces until the server closes or `limit`
/// bytes went in.
fn feed(
    s: &mut dyn AppSession,
    first: &[u8],
    mut more: impl FnMut() -> Vec<u8>,
    limit: usize,
) -> Outcome {
    let mut o = Outcome::default();
    let mut piece = first.to_vec();
    let mut now = Duration::from_millis(1);
    while o.fed < limit {
        let mut cx = AppCx::new(now, now);
        s.receive(&piece, &mut cx);
        o.fed += piece.len();
        o.sent += cx.take_sends().iter().map(Vec::len).sum::<usize>();
        o.errors.extend(cx.protocol_errors().iter().cloned());
        o.transactions += cx.transactions().len();
        if cx.wants_close() {
            o.closed = true;
            break;
        }
        piece = more();
        if piece.is_empty() {
            break;
        }
        now += Duration::from_micros(10);
    }
    o
}

const MIB: usize = 1 << 20;

#[test]
fn http_endless_headers_end_with_an_error() {
    let a = app("app = \"http\"");
    let mut s = server(&a);
    let o = feed(
        &mut *s,
        b"GET / HTTP/1.1\r\nHost: lab\r\n",
        || b"X-Fill: aaaaaaaaaaaaaaaa\r\n".to_vec(),
        8 * MIB,
    );
    assert!(o.closed && o.fed < MIB, "{o:?}");
    assert!(o.errors.iter().any(|e| e.contains("too long")), "{o:?}");
}

#[test]
fn http_one_endless_header_line_ends_with_an_error() {
    let a = app("app = \"http\"");
    let mut s = server(&a);
    let o = feed(
        &mut *s,
        b"GET / HTTP/1.1\r\nX: ",
        || vec![b'a'; 4096],
        8 * MIB,
    );
    assert!(o.closed && o.fed < MIB, "{o:?}");
}

#[test]
fn http_oversized_lengths_do_not_break_the_server() {
    let a = app("app = \"http\"");
    for head in [
        "POST / HTTP/1.1\r\nHost: lab\r\nContent-Length: 18446744073709551616\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: lab\r\nContent-Length: 18446744073709551615\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: lab\r\nContent-Length: -1\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: lab\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffffffff\r\n",
        "POST / HTTP/1.1\r\nHost: lab\r\nTransfer-Encoding: chunked\r\n\r\nfffffffffffffff\r\n",
    ] {
        let mut s = server(&a);
        // A body that never ends must not be kept: 4 MiB in, and it either
        // refused the length or is still only counting.
        let o = feed(&mut *s, head.as_bytes(), || vec![b'z'; 64 * 1024], 4 * MIB);
        assert!(o.closed || o.fed >= 4 * MIB, "{head:?}: {o:?}");
    }
}

#[test]
fn http_endless_chunk_line_ends_with_an_error() {
    let a = app("app = \"http\"");
    let mut s = server(&a);
    let o = feed(
        &mut *s,
        b"POST / HTTP/1.1\r\nHost: lab\r\nTransfer-Encoding: chunked\r\n\r\n1",
        || vec![b'0'; 4096],
        8 * MIB,
    );
    assert!(o.closed && o.fed < MIB, "{o:?}");
}

#[test]
fn http_a_request_one_byte_at_a_time_is_answered() {
    let a = app("app = \"http\"");
    let mut s = server(&a);
    let req = b"GET / HTTP/1.1\r\nHost: lab\r\nConnection: close\r\n\r\n";
    let mut i = 1;
    let o = feed(
        &mut *s,
        &req[..1],
        || {
            let p = req.get(i..i + 1).map(<[u8]>::to_vec).unwrap_or_default();
            i += 1;
            p
        },
        MIB,
    );
    assert!(o.errors.is_empty(), "{o:?}");
    assert!(o.sent > 0 && o.transactions == 1, "{o:?}");
}

fn h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut f = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, kind, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// The client preface and an empty SETTINGS.
fn h2_preface() -> Vec<u8> {
    let mut p = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    p.extend(h2_frame(4, 0, 0, &[]));
    p
}

/// `:method GET`, `:scheme http`, `:path /` from the static table, and
/// `:authority lab` as a literal.
const H2_GET: &[u8] = &[0x82, 0x86, 0x84, 0x41, 3, b'l', b'a', b'b'];

#[test]
fn http2_endless_continuation_ends_with_an_error() {
    let a = app("app = \"http2\"");
    let mut s = server(&a);
    let mut first = h2_preface();
    first.extend(h2_frame(1, 0, 1, H2_GET)); // HEADERS without END_HEADERS
    let o = feed(
        &mut *s,
        &first,
        || h2_frame(9, 0, 1, &[0x40; 16000]),
        64 * MIB,
    );
    assert!(
        o.closed && o.fed < 2 * MIB,
        "{:?}",
        (o.closed, o.fed, &o.errors)
    );
}

#[test]
fn http2_oversized_frame_ends_with_an_error() {
    let a = app("app = \"http2\"");
    let mut s = server(&a);
    let mut first = h2_preface();
    first.extend_from_slice(&[0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 1]);
    let o = feed(&mut *s, &first, || vec![0; 64 * 1024], 32 * MIB);
    assert!(o.closed && o.fed < MIB, "{o:?}");
}

#[test]
fn http2_a_flood_of_streams_is_refused_not_kept() {
    let a = app("app = \"http2\"");
    let mut s = server(&a);
    let mut id = 1u32;
    // Streams opened and never finished (no END_STREAM): the server must
    // refuse those over its limit rather than keep them all.
    let o = feed(
        &mut *s,
        &h2_preface(),
        || {
            let f = h2_frame(1, 0x4, id, H2_GET);
            id += 2;
            if id > 40_000 {
                Vec::new()
            } else {
                f
            }
        },
        64 * MIB,
    );
    assert!(o.fed > 0, "{o:?}");
    // Refusals (RST_STREAM) or a GOAWAY went out; it did not just take them.
    assert!(o.closed || o.sent > 1000, "{:?}", (o.closed, o.fed, o.sent));
}

#[test]
fn http2_rapid_reset_does_not_break_the_server() {
    let a = app("app = \"http2\"");
    let mut s = server(&a);
    let mut id = 1u32;
    let o = feed(
        &mut *s,
        &h2_preface(),
        || {
            let mut f = h2_frame(1, 0x5, id, H2_GET);
            f.extend(h2_frame(3, 0, id, &8u32.to_be_bytes()));
            id += 2;
            if id > 20_000 {
                Vec::new()
            } else {
                f
            }
        },
        64 * MIB,
    );
    assert!(o.fed > 0);
}

#[test]
fn mqtt_oversized_remaining_length_ends_with_an_error() {
    let a = app("app = \"mqtt\"");
    let mut s = server(&a);
    // CONNECT with the largest remaining length (268435455).
    let o = feed(
        &mut *s,
        &[0x10, 0xff, 0xff, 0xff, 0x7f],
        || vec![0; 64 * 1024],
        300 * MIB,
    );
    assert!(o.closed && o.fed < MIB, "{o:?}");
}

#[test]
fn smb_oversized_message_ends_with_an_error() {
    let a = app("app = \"smb\"");
    let mut s = server(&a);
    // Direct TCP allows 16 MiB messages: one is buffered, and no more.
    let o = feed(
        &mut *s,
        &[0, 0xff, 0xff, 0xff],
        || vec![0; 64 * 1024],
        64 * MIB,
    );
    assert!(
        o.closed && o.fed <= 17 * MIB,
        "{:?}",
        (o.closed, o.fed, &o.errors)
    );
    let mut s = server(&a);
    // With an SMB 2 header in front, the message is read (and refused) and
    // the zeros after it are empty messages: read and dropped, not kept.
    let o = feed(
        &mut *s,
        &[0, 0xff, 0xff, 0xff, 0xfe, b'S', b'M', b'B'],
        || vec![0; 64 * 1024],
        64 * MIB,
    );
    assert!(!o.errors.is_empty(), "{:?}", (o.closed, o.fed, &o.errors));
}

#[test]
fn ssh_oversized_packet_ends_with_an_error() {
    let a = app("app = \"ssh\"");
    let mut s = server(&a);
    let mut first = b"SSH-2.0-hostile\r\n".to_vec();
    first.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 4]);
    let o = feed(&mut *s, &first, || vec![0; 64 * 1024], 32 * MIB);
    assert!(o.closed && o.fed < MIB, "{o:?}");
}

#[test]
fn ssh_endless_banner_lines_end_with_an_error() {
    let a = app("app = \"ssh\"");
    let mut s = server(&a);
    let o = feed(
        &mut *s,
        b"hello\r\n",
        || b"another line before the version\r\n".to_vec(),
        8 * MIB,
    );
    assert!(o.closed && o.fed < MIB, "{o:?}");
    let mut s = server(&a);
    let o = feed(&mut *s, b"x", || vec![b'x'; 4096], 8 * MIB);
    assert!(o.closed && o.fed < MIB, "{o:?}");
}

#[test]
fn dns_over_tcp_trickled_and_flooded() {
    let a = app(
        "app = \"dns\"\n[dns]\nqueries = [\"www.lab.local A\"]\nrecords = [\"www.lab.local 300 A 10.0.0.2\"]",
    );
    // A query one byte at a time is answered.
    let q: Vec<u8> = {
        let mut m = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in ["www", "lab", "local"] {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.extend_from_slice(&[0, 0, 1, 0, 1]);
        let mut f = (m.len() as u16).to_be_bytes().to_vec();
        f.extend(m);
        f
    };
    let mut s = server(&a);
    let mut i = 1;
    let o = feed(
        &mut *s,
        &q[..1],
        || {
            let p = q.get(i..i + 1).map(<[u8]>::to_vec).unwrap_or_default();
            i += 1;
            p
        },
        MIB,
    );
    assert!(o.sent > 0 && o.errors.is_empty(), "{o:?}");
    // Thousands of queries at once are answered as they come.
    let mut s = server(&a);
    let burst: Vec<u8> = q.iter().copied().cycle().take(q.len() * 5000).collect();
    let o = feed(&mut *s, &burst, Vec::new, 64 * MIB);
    assert!(
        o.sent > 0 && o.errors.is_empty(),
        "{:?}",
        (o.closed, o.fed, o.sent, &o.errors)
    );
}
