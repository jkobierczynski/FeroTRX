//! DNS as an application protocol: over UDP (one query per transaction) and
//! over TCP (queries with two-byte length prefixes, RFC 7766, several per
//! connection).
//!
//! The workload, queries and records come from [`DnsWorkload`]; the client
//! checks that each answer has its query's id and question and the expected
//! response code, and the server answers as a small authoritative server.

use std::any::Any;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use super::{
    AppCx, AppProtocol, AppRng, AppRole, AppSession, AppTransaction, Receive, SessionInit,
    Transport,
};
use crate::udp::dns::{check_answer, DnsCheck, Message};
use crate::{DnsWorkload, Error, Rcode, Result};

/// DNS: the workload, and how many queries a TCP connection carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dns {
    pub workload: Arc<DnsWorkload>,
    /// Queries per TCP connection, one after the other (default 1). Over
    /// UDP each transaction is one query.
    pub per_connection: u32,
}

impl Dns {
    pub fn new(workload: Arc<DnsWorkload>) -> Self {
        Self {
            workload,
            per_connection: 1,
        }
    }
}

impl AppProtocol for Dns {
    fn name(&self) -> &str {
        "dns"
    }

    fn describe(&self) -> String {
        let mut s = self.workload.to_string();
        if self.per_connection > 1 {
            s.push_str(&format!(", {} per TCP connection", self.per_connection));
        }
        s
    }

    fn default_port(&self) -> u16 {
        53
    }

    fn supports(&self, _t: Transport) -> bool {
        true
    }

    fn validate(&self, role: AppRole, _t: Transport) -> Result<()> {
        if role == AppRole::Client && self.workload.queries.is_empty() {
            return Err(Error::Profile("dns: the client has no queries".into()));
        }
        if self.per_connection == 0 {
            return Err(Error::Profile(
                "dns: per_connection must be at least 1".into(),
            ));
        }
        Ok(())
    }

    fn session(&self, init: &SessionInit) -> Box<dyn AppSession> {
        let per = match init.transport {
            Transport::Stream => self.per_connection.max(1),
            Transport::Datagram => 1,
        };
        match init.role {
            AppRole::Client => Box::new(Client {
                w: self.workload.clone(),
                stream: init.transport == Transport::Stream,
                first: init.index * u64::from(per),
                per,
                sent: 0,
                rng: AppRng::new(init.seed),
                waiting: VecDeque::new(),
                buf: Vec::new(),
                answered: 0,
            }),
            AppRole::Server => Box::new(Server {
                w: self.workload.clone(),
                stream: init.transport == Transport::Stream,
                buf: Vec::new(),
            }),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// The response code of a DNS message.
fn rcode_of(m: &[u8]) -> Rcode {
    Rcode(m.get(3).map_or(0, |b| b & 0x0f))
}

/// Takes the length-prefixed messages at the front of `buf`.
fn frames(buf: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0;
    while buf.len() >= at + 2 {
        let n = usize::from(u16::from_be_bytes([buf[at], buf[at + 1]]));
        if buf.len() < at + 2 + n {
            break;
        }
        out.push(buf[at + 2..at + 2 + n].to_vec());
        at += 2 + n;
    }
    buf.drain(..at);
    out
}

fn framed(m: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(m.len() + 2);
    v.extend_from_slice(&(m.len() as u16).to_be_bytes());
    v.extend_from_slice(m);
    v
}

struct Client {
    w: Arc<DnsWorkload>,
    stream: bool,
    first: u64,
    per: u32,
    sent: u32,
    rng: AppRng,
    /// Queries waiting for their answers: number, id, when sent.
    waiting: VecDeque<(u64, u16, Duration)>,
    buf: Vec<u8>,
    answered: u32,
}

impl Client {
    fn send_next(&mut self, cx: &mut AppCx) {
        let n = self.first + u64::from(self.sent);
        let Some(q) = self.w.query(n) else { return };
        let id = self.rng.next_u64() as u16;
        let m = self.w.query_message(id, q);
        cx.send(if self.stream { framed(&m) } else { m });
        self.waiting.push_back((n, id, cx.now()));
        self.sent += 1;
    }

    /// Checks an answer. `None` if it is not for the query waited for.
    fn check(&mut self, m: &[u8], cx: &mut AppCx) -> Option<()> {
        let &(n, id, at) = self.waiting.front()?;
        let q = self.w.query(n)?;
        match check_answer(m, id, q) {
            DnsCheck::NotOurs => None,
            DnsCheck::Answer { rcode, ok } => {
                self.waiting.pop_front();
                let mut t =
                    AppTransaction::new(rcode.to_string(), ok).with_error(rcode != Rcode::NOERROR);
                if self.stream {
                    // Over UDP the engine times the transaction, retries and all.
                    t = t.with_response_time(cx.now().saturating_sub(at));
                }
                cx.transaction(t);
                self.answered += 1;
                Some(())
            }
        }
    }
}

impl AppSession for Client {
    fn start(&mut self, cx: &mut AppCx) {
        self.send_next(cx);
    }

    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        if !self.stream {
            return match self.check(data, cx) {
                Some(()) => {
                    cx.close();
                    Receive::Taken
                }
                None => Receive::NotMine,
            };
        }
        self.buf.extend_from_slice(data);
        for m in frames(&mut self.buf) {
            if self.check(&m, cx).is_none() {
                cx.protocol_error("a DNS answer to no query sent");
                cx.close();
                return Receive::Taken;
            }
            if self.answered >= self.per {
                cx.close();
            } else {
                self.send_next(cx);
            }
        }
        Receive::Taken
    }

    fn peer_closed(&mut self, cx: &mut AppCx) {
        if self.answered < self.per {
            cx.protocol_error(format!(
                "the server closed after {} of {} answers",
                self.answered, self.per
            ));
        }
        cx.close();
    }
}

struct Server {
    w: Arc<DnsWorkload>,
    stream: bool,
    buf: Vec<u8>,
}

impl Server {
    /// The answer to a query with a question; `None` for anything else.
    fn answer(&self, m: &[u8], cx: &mut AppCx) -> Option<Vec<u8>> {
        match Message::parse(m) {
            Some(msg) if !msg.response && msg.question.is_some() => {}
            _ => return None,
        }
        let a = self.w.answer(m)?;
        let rcode = rcode_of(&a);
        cx.transaction(
            AppTransaction::new(rcode.to_string(), true).with_error(rcode != Rcode::NOERROR),
        );
        Some(a)
    }
}

impl AppSession for Server {
    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        if !self.stream {
            return match self.answer(data, cx) {
                Some(a) => {
                    cx.send(a);
                    Receive::Taken
                }
                None => Receive::NotMine,
            };
        }
        self.buf.extend_from_slice(data);
        for m in frames(&mut self.buf) {
            match self.answer(&m, cx) {
                Some(a) => cx.send(framed(&a)),
                None => {
                    cx.protocol_error("not a DNS query");
                    cx.close();
                    return Receive::Taken;
                }
            }
        }
        Receive::Taken
    }

    fn peer_closed(&mut self, cx: &mut AppCx) {
        cx.close();
    }
}

/// Reads a `[dns]` table: `queries`, `records` (as in UDP profiles), `pcap`
/// for the lookups of a capture, `recursion_desired`, `per_connection`.
#[cfg(feature = "profile")]
pub fn parse(t: &toml::Table, base: &std::path::Path) -> Result<Dns> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Raw {
        #[serde(default)]
        queries: Vec<String>,
        #[serde(default)]
        records: Vec<String>,
        pcap: Option<String>,
        recursion_desired: Option<bool>,
        per_connection: Option<u32>,
    }
    let r: Raw = super::registry::table_into(t)?;
    let mut w = match &r.pcap {
        Some(p) => {
            let path = base.join(p);
            let cap = crate::Capture::from_path(&path)
                .map_err(|e| Error::Profile(format!("cannot read {}: {e}", path.display())))?;
            DnsWorkload::from_capture(&cap)?
        }
        None => DnsWorkload {
            recursion_desired: true,
            ..Default::default()
        },
    };
    let extra = DnsWorkload::parse(&r.queries, &r.records)?;
    w.queries.extend(extra.queries);
    w.records.extend(extra.records);
    w.errors.extend(extra.errors);
    if let Some(rd) = r.recursion_desired {
        w.recursion_desired = rd;
    }
    let mut d = Dns::new(Arc::new(w));
    if let Some(n) = r.per_connection {
        d.per_connection = n;
    }
    d.validate(AppRole::Server, Transport::Stream)?;
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lab() -> Dns {
        let w = DnsWorkload::parse(
            &[
                "www.lab.local A",
                "nope.lab.local A NXDOMAIN",
                "lab.local MX",
            ],
            &[
                "www.lab.local A 10.0.0.80",
                "lab.local MX 10 mail.lab.local",
            ],
        )
        .unwrap();
        Dns::new(Arc::new(w))
    }

    fn init(role: AppRole, transport: Transport) -> SessionInit {
        SessionInit {
            role,
            transport,
            index: 0,
            seed: 5,
            local: "10.0.0.1:1000".parse().unwrap(),
            remote: "10.0.0.2:53".parse().unwrap(),
        }
    }

    #[test]
    fn over_tcp_several_queries_per_connection() {
        let mut d = lab();
        d.per_connection = 3;
        let mut c = d.session(&init(AppRole::Client, Transport::Stream));
        let mut s = d.session(&init(AppRole::Server, Transport::Stream));
        let mut cx = AppCx::new(Duration::ZERO, Duration::ZERO);
        c.start(&mut cx);
        let mut wire = cx.take_sends().concat();
        let mut codes = Vec::new();
        for _ in 0..5 {
            let mut sx = AppCx::new(Duration::ZERO, Duration::ZERO);
            // Byte by byte: the framing must cope.
            for b in wire.chunks(1) {
                s.receive(b, &mut sx);
            }
            let answers = sx.take_sends().concat();
            let mut cx = AppCx::new(Duration::from_millis(1), Duration::ZERO);
            c.receive(&answers, &mut cx);
            codes.extend(cx.transactions().iter().map(|t| (t.label.clone(), t.ok)));
            assert!(cx.protocol_errors().is_empty());
            wire = cx.take_sends().concat();
            if cx.wants_close() {
                break;
            }
        }
        assert_eq!(
            codes,
            vec![
                ("NOERROR".to_string(), true),
                ("NXDOMAIN".to_string(), true),
                ("NOERROR".to_string(), true)
            ]
        );
    }

    #[test]
    fn over_udp_matches_by_id() {
        let d = lab();
        let mut c = d.session(&init(AppRole::Client, Transport::Datagram));
        let mut s = d.session(&init(AppRole::Server, Transport::Datagram));
        let mut cx = AppCx::new(Duration::ZERO, Duration::ZERO);
        c.start(&mut cx);
        let q = cx.take_sends().remove(0);
        let mut sx = AppCx::new(Duration::ZERO, Duration::ZERO);
        assert_eq!(s.receive(&q, &mut sx), Receive::Taken);
        let mut a = sx.take_sends().remove(0);
        assert_eq!(
            s.receive(&a, &mut sx),
            Receive::NotMine,
            "an answer is no query"
        );
        let mut wrong = a.clone();
        wrong[0] ^= 0xff;
        let mut cx = AppCx::new(Duration::ZERO, Duration::ZERO);
        assert_eq!(c.receive(&wrong, &mut cx), Receive::NotMine);
        a.truncate(a.len());
        assert_eq!(c.receive(&a, &mut cx), Receive::Taken);
        assert_eq!(cx.transactions()[0].label, "NOERROR");
        assert!(cx.wants_close());
    }
}
