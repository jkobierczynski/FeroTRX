//! DNS as a UDP workload: queries the client sends, and a small
//! authoritative server that answers them from a list of records.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use super::program::{udp_flows, UdpRole};
use crate::{Capture, Error, Result};

/// A DNS record type, such as `A` (1) or `AAAA` (28).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DnsType(pub u16);

impl DnsType {
    pub const A: DnsType = DnsType(1);
    pub const NS: DnsType = DnsType(2);
    pub const CNAME: DnsType = DnsType(5);
    pub const SOA: DnsType = DnsType(6);
    pub const PTR: DnsType = DnsType(12);
    pub const MX: DnsType = DnsType(15);
    pub const TXT: DnsType = DnsType(16);
    pub const AAAA: DnsType = DnsType(28);
    pub const SRV: DnsType = DnsType(33);
    pub const ANY: DnsType = DnsType(255);

    const NAMES: [(&'static str, DnsType); 10] = [
        ("A", Self::A),
        ("NS", Self::NS),
        ("CNAME", Self::CNAME),
        ("SOA", Self::SOA),
        ("PTR", Self::PTR),
        ("MX", Self::MX),
        ("TXT", Self::TXT),
        ("AAAA", Self::AAAA),
        ("SRV", Self::SRV),
        ("ANY", Self::ANY),
    ];
}

impl fmt::Display for DnsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match Self::NAMES.iter().find(|(_, t)| t == self) {
            Some((n, _)) => f.write_str(n),
            None => write!(f, "TYPE{}", self.0),
        }
    }
}

impl FromStr for DnsType {
    type Err = Error;
    /// A name such as `AAAA` (any case), or `TYPE65` for others.
    fn from_str(s: &str) -> Result<Self> {
        let u = s.trim().to_ascii_uppercase();
        if let Some((_, t)) = Self::NAMES.iter().find(|(n, _)| *n == u) {
            return Ok(*t);
        }
        u.strip_prefix("TYPE")
            .and_then(|n| n.parse().ok())
            .map(DnsType)
            .ok_or_else(|| Error::InvalidSpec(format!("unknown DNS record type '{s}'")))
    }
}

/// A DNS response code, such as `NOERROR` (0) or `NXDOMAIN` (3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Rcode(pub u8);

impl Rcode {
    pub const NOERROR: Rcode = Rcode(0);
    pub const FORMERR: Rcode = Rcode(1);
    pub const SERVFAIL: Rcode = Rcode(2);
    pub const NXDOMAIN: Rcode = Rcode(3);
    pub const NOTIMP: Rcode = Rcode(4);
    pub const REFUSED: Rcode = Rcode(5);

    const NAMES: [(&'static str, Rcode); 6] = [
        ("NOERROR", Self::NOERROR),
        ("FORMERR", Self::FORMERR),
        ("SERVFAIL", Self::SERVFAIL),
        ("NXDOMAIN", Self::NXDOMAIN),
        ("NOTIMP", Self::NOTIMP),
        ("REFUSED", Self::REFUSED),
    ];

    /// True for a name such as `NXDOMAIN` (any case).
    pub fn is_name(s: &str) -> bool {
        s.parse::<Rcode>().is_ok() && !s.chars().all(|c| c.is_ascii_digit())
    }
}

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match Self::NAMES.iter().find(|(_, r)| r == self) {
            Some((n, _)) => f.write_str(n),
            None => write!(f, "RCODE{}", self.0),
        }
    }
}

impl FromStr for Rcode {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let u = s.trim().to_ascii_uppercase();
        if let Some((_, r)) = Self::NAMES.iter().find(|(n, _)| *n == u) {
            return Ok(*r);
        }
        u.strip_prefix("RCODE")
            .unwrap_or(&u)
            .parse::<u8>()
            .ok()
            .filter(|r| *r < 16)
            .map(Rcode)
            .ok_or_else(|| Error::InvalidSpec(format!("unknown DNS response code '{s}'")))
    }
}

/// The data of a [`DnsRecord`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// A domain name: CNAME, NS and PTR records.
    Name(String),
    Mx {
        preference: u16,
        exchange: String,
    },
    /// Character strings of up to 255 bytes each.
    Txt(Vec<String>),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// Any other type, as it is on the wire.
    Raw(Vec<u8>),
}

/// A record the DNS server answers with.
///
/// Written as text like a zone file line: `NAME [TTL] TYPE DATA`, e.g.
/// `www.lab.local 300 A 10.1.2.80`, `lab.local MX 10 mail.lab.local`,
/// `lab.local TXT "v=spf1 mx -all"`, `_sip._udp.lab.local SRV 0 5 5060 sip.lab.local`.
/// The TTL defaults to 300 s.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: DnsType,
    pub ttl: u32,
    pub data: DnsData,
}

impl fmt::Display for DnsRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} ", self.name, self.ttl, self.rtype)?;
        match &self.data {
            DnsData::A(a) => write!(f, "{a}"),
            DnsData::Aaaa(a) => write!(f, "{a}"),
            DnsData::Name(n) => f.write_str(n),
            DnsData::Mx {
                preference,
                exchange,
            } => write!(f, "{preference} {exchange}"),
            DnsData::Txt(t) => {
                let quoted: Vec<String> = t.iter().map(|s| format!("{s:?}")).collect();
                f.write_str(&quoted.join(" "))
            }
            DnsData::Srv {
                priority,
                weight,
                port,
                target,
            } => write!(f, "{priority} {weight} {port} {target}"),
            DnsData::Raw(r) => write!(f, "\\# {} {}", r.len(), hex(r)),
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

/// Splits on blanks, keeping "quoted strings" (with \" escapes) together.
fn words(s: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut chars = s.trim().chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut w = String::new();
        if c == '"' {
            chars.next();
            loop {
                match chars.next() {
                    Some('"') => break,
                    Some('\\') => w.extend(chars.next()),
                    Some(c) => w.push(c),
                    None => {
                        return Err(Error::InvalidSpec(format!("unclosed quote in '{s}'")));
                    }
                }
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                w.push(c);
                chars.next();
            }
        }
        out.push(w);
    }
    Ok(out)
}

/// A name as compared and written: no trailing dot, lower case.
fn norm(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl FromStr for DnsRecord {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let bad = |why: &str| Error::InvalidSpec(format!("DNS record '{s}': {why}"));
        let w = words(s)?;
        if w.len() < 3 {
            return Err(bad("use NAME [TTL] TYPE DATA"));
        }
        let name = w[0].trim_end_matches('.').to_string();
        let (ttl, at) = match w[1].parse::<u32>() {
            Ok(t) => (t, 2),
            Err(_) => (300, 1),
        };
        let rtype: DnsType = w
            .get(at)
            .ok_or_else(|| bad("no type"))?
            .parse()
            .map_err(|_| bad("unknown type"))?;
        let rest = &w[at + 1..];
        let one = || -> Result<&str> {
            match rest {
                [v] => Ok(v.as_str()),
                _ => Err(bad("expected one value")),
            }
        };
        let num = |v: &str| v.parse::<u16>().map_err(|_| bad("expected a number"));
        let data = match rtype {
            DnsType::A => DnsData::A(one()?.parse().map_err(|_| bad("not an IPv4 address"))?),
            DnsType::AAAA => DnsData::Aaaa(one()?.parse().map_err(|_| bad("not an IPv6 address"))?),
            DnsType::CNAME | DnsType::NS | DnsType::PTR => {
                DnsData::Name(one()?.trim_end_matches('.').to_string())
            }
            DnsType::MX => match rest {
                [p, e] => DnsData::Mx {
                    preference: num(p)?,
                    exchange: e.trim_end_matches('.').to_string(),
                },
                _ => return Err(bad("MX takes PREFERENCE EXCHANGE")),
            },
            DnsType::TXT if !rest.is_empty() => {
                if rest.iter().any(|t| t.len() > 255) {
                    return Err(bad("TXT strings are at most 255 bytes"));
                }
                DnsData::Txt(rest.to_vec())
            }
            DnsType::SRV => match rest {
                [p, w, port, t] => DnsData::Srv {
                    priority: num(p)?,
                    weight: num(w)?,
                    port: num(port)?,
                    target: t.trim_end_matches('.').to_string(),
                },
                _ => return Err(bad("SRV takes PRIORITY WEIGHT PORT TARGET")),
            },
            _ => match rest {
                [m, _len, h] if m == "\\#" => {
                    DnsData::Raw(parse_hex(h).ok_or_else(|| bad("bad hex data"))?)
                }
                _ => return Err(bad("give other types as \\# LENGTH HEX")),
            },
        };
        Ok(DnsRecord {
            name,
            rtype,
            ttl,
            data,
        })
    }
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// One query the DNS client sends.
///
/// Written as `NAME [TYPE] [RCODE]`, e.g. `www.lab.local AAAA` or
/// `missing.lab.local A NXDOMAIN`. The type defaults to `A`. With an
/// `RCODE`, an answer with another response code counts as mismatched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsQuery {
    pub name: String,
    pub qtype: DnsType,
    /// The response code the answer must have, if checked.
    pub expect: Option<Rcode>,
}

impl DnsQuery {
    pub fn new(name: impl Into<String>, qtype: DnsType) -> Self {
        Self {
            name: name.into().trim_end_matches('.').to_string(),
            qtype,
            expect: None,
        }
    }
}

impl fmt::Display for DnsQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.name, self.qtype)?;
        if let Some(r) = self.expect {
            write!(f, " {r}")?;
        }
        Ok(())
    }
}

impl FromStr for DnsQuery {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let bad = |why: &str| Error::InvalidSpec(format!("DNS query '{s}': {why}"));
        let w = words(s)?;
        let (name, rest) = w.split_first().ok_or_else(|| bad("no name"))?;
        let mut q = DnsQuery::new(name.as_str(), DnsType::A);
        match rest {
            [] => {}
            [t] if Rcode::is_name(t) => q.expect = Some(t.parse()?),
            [t] => q.qtype = t.parse()?,
            [t, r] => {
                q.qtype = t.parse()?;
                q.expect = Some(r.parse()?);
            }
            _ => return Err(bad("use NAME [TYPE] [RCODE]")),
        }
        Ok(q)
    }
}

/// A DNS workload: the queries clients send, in turn, and the records and
/// errors the server answers them with.
///
/// The server is authoritative for the records it has: a query for a name
/// with records of its type gets them (following CNAMEs), a name with
/// records of other types gets an empty answer, a name in `errors` gets that
/// response code (`SERVFAIL`, `REFUSED`, ...), and any other name `NXDOMAIN`.
///
/// ```
/// use ferotrx_core::{DnsWorkload, Rcode};
///
/// let dns = DnsWorkload::parse(
///     &["www.lab.local A", "lab.local MX", "nope.lab.local A NXDOMAIN"],
///     &["www.lab.local 60 A 10.1.2.80", "lab.local MX 10 mail.lab.local", "broken.lab.local SERVFAIL"],
/// ).unwrap();
/// assert_eq!(dns.queries.len(), 3);
/// assert_eq!(dns.errors, vec![("broken.lab.local".to_string(), Rcode::SERVFAIL)]);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DnsWorkload {
    pub queries: Vec<DnsQuery>,
    pub records: Vec<DnsRecord>,
    /// Names the server answers with an error response code.
    pub errors: Vec<(String, Rcode)>,
    /// Set the RD (recursion desired) flag in queries (default true, as stub
    /// resolvers do).
    pub recursion_desired: bool,
}

impl DnsWorkload {
    /// From query lines (see [`DnsQuery`]) and record lines (see
    /// [`DnsRecord`]); a record line `NAME RCODE` makes the server answer
    /// `NAME` with that error.
    pub fn parse<Q: AsRef<str>, R: AsRef<str>>(queries: &[Q], records: &[R]) -> Result<Self> {
        let mut w = DnsWorkload {
            recursion_desired: true,
            ..Default::default()
        };
        for q in queries {
            w.queries.push(q.as_ref().parse()?);
        }
        for r in records {
            w.add_record_line(r.as_ref())?;
        }
        Ok(w)
    }

    /// Adds a record line, or an error line `NAME RCODE`.
    pub fn add_record_line(&mut self, line: &str) -> Result<()> {
        let w = words(line)?;
        if let [name, code] = w.as_slice() {
            if Rcode::is_name(code) {
                self.errors
                    .push((name.trim_end_matches('.').to_string(), code.parse()?));
                return Ok(());
            }
        }
        self.records.push(line.parse()?);
        Ok(())
    }

    /// The DNS lookups in a capture: every query becomes a query of the
    /// workload (expecting the response code its answer had, when the
    /// capture has the answer), and the answers' records and error codes
    /// become the server's.
    pub fn from_capture(capture: &Capture) -> Result<Self> {
        let mut w = DnsWorkload {
            recursion_desired: true,
            ..Default::default()
        };
        let flows = udp_flows(capture);
        for flow in &flows {
            for m in &flow.program.messages {
                let Some(msg) = Message::parse(&m.data) else {
                    continue;
                };
                let Some(q) = &msg.question else { continue };
                if m.from == UdpRole::Client && !msg.response {
                    w.recursion_desired = msg.rd;
                    w.queries.push(DnsQuery::new(q.0.as_str(), q.1));
                    continue;
                }
                if !msg.response {
                    continue;
                }
                // The answer to the latest matching query sets what it expects.
                if let Some(query) = w
                    .queries
                    .iter_mut()
                    .rev()
                    .find(|x| norm(&x.name) == norm(&q.0) && x.qtype == q.1)
                {
                    query.expect.get_or_insert(msg.rcode);
                }
                if msg.rcode != Rcode::NOERROR {
                    if !w.errors.iter().any(|(n, _)| norm(n) == norm(&q.0)) {
                        w.errors.push((q.0.clone(), msg.rcode));
                    }
                    continue;
                }
                for r in msg.answers {
                    if !w.records.contains(&r) {
                        w.records.push(r);
                    }
                }
            }
        }
        if w.queries.is_empty() {
            return Err(Error::Udp("the capture has no DNS queries".into()));
        }
        Ok(w)
    }

    /// The query of transaction `n`: the queries in turn.
    pub fn query(&self, n: u64) -> Option<&DnsQuery> {
        if self.queries.is_empty() {
            return None;
        }
        self.queries.get((n % self.queries.len() as u64) as usize)
    }

    /// A query message for `q` with transaction id `id`.
    pub fn query_message(&self, id: u16, q: &DnsQuery) -> Vec<u8> {
        let mut m = Vec::with_capacity(32 + q.name.len());
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&if self.recursion_desired { 0x0100u16 } else { 0 }.to_be_bytes());
        m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        put_name(&mut m, &q.name);
        m.extend_from_slice(&q.qtype.0.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m
    }

    /// The server's answer to `query`, or `None` if it is not a DNS query
    /// worth answering (a response, or too short to have an id).
    pub fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 12 || query[2] & 0x80 != 0 {
            return None;
        }
        let id = [query[0], query[1]];
        let opcode = (query[2] >> 3) & 0x0f;
        let rd = query[2] & 0x01;
        let header = |rcode: Rcode, an: u16, with_q: bool| {
            let mut m = Vec::with_capacity(512);
            m.extend_from_slice(&id);
            // QR, opcode, AA, RD as asked; RA.
            m.push(0x80 | (opcode << 3) | 0x04 | rd);
            m.push(0x80 | rcode.0);
            m.extend_from_slice(&u16::from(with_q).to_be_bytes());
            m.extend_from_slice(&an.to_be_bytes());
            m.extend_from_slice(&[0, 0, 0, 0]);
            m
        };
        if opcode != 0 {
            return Some(header(Rcode::NOTIMP, 0, false));
        }
        let parsed = Message::parse(query);
        let (Some(msg), true) = (&parsed, be16(query, 4) == Some(1)) else {
            return Some(header(Rcode::FORMERR, 0, false));
        };
        let Some((qname, qtype, q_end)) = &msg.question_at else {
            return Some(header(Rcode::FORMERR, 0, false));
        };
        let (rcode, answers) = self.lookup(qname, *qtype);
        let mut m = header(rcode, answers.len() as u16, true);
        // The question as asked, case and all.
        m.extend_from_slice(&query[12..*q_end]);
        for r in &answers {
            put_record(&mut m, r);
        }
        Some(m)
    }

    /// The response code and the records for a question.
    pub fn lookup(&self, name: &str, qtype: DnsType) -> (Rcode, Vec<&DnsRecord>) {
        let mut cur = norm(name);
        if let Some((_, r)) = self.errors.iter().find(|(n, _)| norm(n) == cur) {
            return (*r, Vec::new());
        }
        let mut answers: Vec<&DnsRecord> = Vec::new();
        let mut exists = false;
        for _ in 0..8 {
            let at: Vec<&DnsRecord> = self
                .records
                .iter()
                .filter(|r| norm(&r.name) == cur)
                .collect();
            exists |= !at.is_empty();
            let wanted: Vec<&DnsRecord> = at
                .iter()
                .copied()
                .filter(|r| r.rtype == qtype || qtype == DnsType::ANY)
                .collect();
            if !wanted.is_empty() {
                answers.extend(wanted);
                break;
            }
            match at.iter().find(|r| r.rtype == DnsType::CNAME) {
                Some(c) if qtype != DnsType::CNAME => {
                    answers.push(c);
                    let DnsData::Name(target) = &c.data else {
                        break;
                    };
                    cur = norm(target);
                }
                _ => break,
            }
        }
        if exists {
            (Rcode::NOERROR, answers)
        } else {
            (Rcode::NXDOMAIN, answers)
        }
    }
}

impl fmt::Display for DnsWorkload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DNS: {} queries, {} records",
            self.queries.len(),
            self.records.len()
        )?;
        if !self.errors.is_empty() {
            write!(f, ", {} error names", self.errors.len())?;
        }
        Ok(())
    }
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

pub(crate) fn put_name(m: &mut Vec<u8>, name: &str) {
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
    {
        let l = &label.as_bytes()[..label.len().min(63)];
        m.push(l.len() as u8);
        m.extend_from_slice(l);
    }
    m.push(0);
}

fn put_record(m: &mut Vec<u8>, r: &DnsRecord) {
    put_record_class(m, r, 1);
}

/// A resource record with `class` (mDNS sets its top bit to flush caches).
pub(crate) fn put_record_class(m: &mut Vec<u8>, r: &DnsRecord, class: u16) {
    put_name(m, &r.name);
    m.extend_from_slice(&r.rtype.0.to_be_bytes());
    m.extend_from_slice(&class.to_be_bytes());
    m.extend_from_slice(&r.ttl.to_be_bytes());
    let len_at = m.len();
    m.extend_from_slice(&[0, 0]);
    match &r.data {
        DnsData::A(a) => m.extend_from_slice(&a.octets()),
        DnsData::Aaaa(a) => m.extend_from_slice(&a.octets()),
        DnsData::Name(n) => put_name(m, n),
        DnsData::Mx {
            preference,
            exchange,
        } => {
            m.extend_from_slice(&preference.to_be_bytes());
            put_name(m, exchange);
        }
        DnsData::Txt(t) => {
            for s in t {
                let s = &s.as_bytes()[..s.len().min(255)];
                m.push(s.len() as u8);
                m.extend_from_slice(s);
            }
        }
        DnsData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            for v in [priority, weight, port] {
                m.extend_from_slice(&v.to_be_bytes());
            }
            put_name(m, target);
        }
        DnsData::Raw(r) => m.extend_from_slice(r),
    }
    let len = (m.len() - len_at - 2) as u16;
    m[len_at..len_at + 2].copy_from_slice(&len.to_be_bytes());
}

/// Reads a possibly compressed name at `at`. Returns it and the offset after it.
pub(crate) fn read_name(m: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut after = None;
    for _ in 0..128 {
        let len = *m.get(at)?;
        match len {
            0 => return Some((labels.join("."), after.unwrap_or(at + 1))),
            l if l & 0xc0 == 0xc0 => {
                after.get_or_insert(at + 2);
                at = usize::from(be16(m, at)? & 0x3fff);
            }
            l if l & 0xc0 == 0 => {
                let l = usize::from(l);
                let label = m.get(at + 1..at + 1 + l)?;
                labels.push(String::from_utf8_lossy(label).into_owned());
                at += 1 + l;
            }
            _ => return None,
        }
    }
    None
}

/// Reads the resource record at `at`: the record (`None` when its data does
/// not parse) and the offset after it; `None` when the message ends early.
pub(crate) fn read_record(m: &[u8], at: usize) -> Option<(Option<DnsRecord>, usize)> {
    let (name, next) = read_name(m, at)?;
    let rtype = be16(m, next)?;
    let ttl_hi = be16(m, next + 4)?;
    let ttl_lo = be16(m, next + 6)?;
    let len = be16(m, next + 8)?;
    let start = next + 10;
    let end = start + usize::from(len);
    let rdata = m.get(start..end)?;
    let rtype = DnsType(rtype);
    let name_at = |off: usize| read_name(m, off).map(|(n, _)| n);
    let data = (|| match rtype {
        DnsType::A if rdata.len() == 4 => Some(DnsData::A(Ipv4Addr::new(
            rdata[0], rdata[1], rdata[2], rdata[3],
        ))),
        DnsType::AAAA if rdata.len() == 16 => {
            let b: [u8; 16] = rdata.try_into().ok()?;
            Some(DnsData::Aaaa(Ipv6Addr::from(b)))
        }
        DnsType::CNAME | DnsType::NS | DnsType::PTR => name_at(start).map(DnsData::Name),
        DnsType::MX if rdata.len() >= 3 => name_at(start + 2).map(|e| DnsData::Mx {
            preference: u16::from_be_bytes([rdata[0], rdata[1]]),
            exchange: e,
        }),
        DnsType::TXT => {
            let mut t = Vec::new();
            let mut i = 0;
            while i < rdata.len() {
                let l = usize::from(rdata[i]);
                let s = rdata.get(i + 1..i + 1 + l)?;
                t.push(String::from_utf8_lossy(s).into_owned());
                i += 1 + l;
            }
            Some(DnsData::Txt(t))
        }
        DnsType::SRV if rdata.len() >= 7 => name_at(start + 6).map(|t| DnsData::Srv {
            priority: u16::from_be_bytes([rdata[0], rdata[1]]),
            weight: u16::from_be_bytes([rdata[2], rdata[3]]),
            port: u16::from_be_bytes([rdata[4], rdata[5]]),
            target: t,
        }),
        _ => Some(DnsData::Raw(rdata.to_vec())),
    })();
    let record = data.map(|data| DnsRecord {
        name,
        rtype,
        ttl: (u32::from(ttl_hi) << 16) | u32::from(ttl_lo),
        data,
    });
    Some((record, end))
}

/// The parts of a DNS message the engine looks at.
#[derive(Clone, Debug)]
pub(crate) struct Message {
    pub id: u16,
    pub response: bool,
    pub rd: bool,
    pub rcode: Rcode,
    /// The first question.
    pub question: Option<(String, DnsType)>,
    /// The first question and where it ends.
    question_at: Option<(String, DnsType, usize)>,
    pub answers: Vec<DnsRecord>,
}

impl Message {
    pub fn parse(m: &[u8]) -> Option<Message> {
        if m.len() < 12 {
            return None;
        }
        let qd = be16(m, 4)?;
        let an = be16(m, 6)?;
        let mut msg = Message {
            id: be16(m, 0)?,
            response: m[2] & 0x80 != 0,
            rd: m[2] & 0x01 != 0,
            rcode: Rcode(m[3] & 0x0f),
            question: None,
            question_at: None,
            answers: Vec::new(),
        };
        let mut at = 12;
        for i in 0..qd {
            let (name, next) = read_name(m, at)?;
            let qtype = DnsType(be16(m, next)?);
            be16(m, next + 2)?;
            at = next + 4;
            if i == 0 {
                msg.question = Some((name.clone(), qtype));
                msg.question_at = Some((name, qtype, at));
            }
        }
        for _ in 0..an {
            let Some((record, end)) = read_record(m, at) else {
                break;
            };
            if let Some(r) = record {
                msg.answers.push(r);
            }
            at = end;
        }
        Some(msg)
    }
}

/// What a client makes of an answer to its query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DnsCheck {
    /// Not an answer to this query (another id): unmatched.
    NotOurs,
    /// The answer, with its response code; `ok` is false when the question
    /// or the expected response code differ.
    Answer { rcode: Rcode, ok: bool },
}

pub(crate) fn check_answer(answer: &[u8], id: u16, q: &DnsQuery) -> DnsCheck {
    let Some(msg) = Message::parse(answer) else {
        return DnsCheck::NotOurs;
    };
    if !msg.response || msg.id != id {
        return DnsCheck::NotOurs;
    }
    let same_q = msg
        .question
        .as_ref()
        .is_none_or(|(n, t)| norm(n) == norm(&q.name) && *t == q.qtype);
    let ok = same_q && q.expect.is_none_or(|e| e == msg.rcode);
    DnsCheck::Answer {
        rcode: msg.rcode,
        ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lab() -> DnsWorkload {
        DnsWorkload::parse(
            &["www.lab.local", "lab.local MX", "nope.lab.local A NXDOMAIN"],
            &[
                "www.lab.local CNAME web.lab.local",
                "web.lab.local 60 A 10.1.2.80",
                "web.lab.local AAAA fd00::80",
                "lab.local MX 10 mail.lab.local",
                "lab.local TXT \"v=spf1 mx -all\" \"second\"",
                "_sip._udp.lab.local SRV 0 5 5060 sip.lab.local",
                "broken.lab.local SERVFAIL",
            ],
        )
        .unwrap()
    }

    #[test]
    fn parses_lines() {
        let w = lab();
        assert_eq!(w.queries[0].qtype, DnsType::A);
        assert_eq!(w.queries[2].expect, Some(Rcode::NXDOMAIN));
        assert_eq!(w.records.len(), 6);
        assert_eq!(w.records[1].ttl, 60);
        assert_eq!(
            w.records[4].data,
            DnsData::Txt(vec!["v=spf1 mx -all".into(), "second".into()])
        );
        assert_eq!(
            w.records[3].to_string(),
            "lab.local 300 MX 10 mail.lab.local"
        );
        assert!("x A 1.2.3".parse::<DnsRecord>().is_err());
        assert!("x MX mail".parse::<DnsRecord>().is_err());
        assert_eq!("x TYPE99".parse::<DnsQuery>().unwrap().qtype, DnsType(99));
        assert_eq!(
            "x refused".parse::<DnsQuery>().unwrap().expect,
            Some(Rcode::REFUSED)
        );
    }

    #[test]
    fn answers_through_cnames_and_with_errors() {
        let w = lab();
        let ask = |name: &str, t: DnsType| {
            let q = DnsQuery::new(name, t);
            let a = w.answer(&w.query_message(0x1234, &q)).unwrap();
            let m = Message::parse(&a).unwrap();
            assert!(m.response);
            assert_eq!(m.id, 0x1234);
            assert_eq!(m.question.as_ref().unwrap().0, name);
            assert_eq!(
                check_answer(&a, 0x1234, &q),
                DnsCheck::Answer {
                    rcode: m.rcode,
                    ok: true
                }
            );
            assert_eq!(check_answer(&a, 0x1235, &q), DnsCheck::NotOurs);
            m
        };
        let m = ask("WWW.lab.local", DnsType::A);
        assert_eq!(m.rcode, Rcode::NOERROR);
        assert_eq!(m.answers.len(), 2);
        assert_eq!(m.answers[1].data, DnsData::A("10.1.2.80".parse().unwrap()));
        let m = ask("www.lab.local", DnsType::AAAA);
        assert_eq!(
            m.answers[1].data,
            DnsData::Aaaa("fd00::80".parse().unwrap())
        );
        let m = ask("lab.local", DnsType::A);
        assert_eq!((m.rcode, m.answers.len()), (Rcode::NOERROR, 0));
        assert_eq!(ask("nope.lab.local", DnsType::A).rcode, Rcode::NXDOMAIN);
        assert_eq!(ask("broken.lab.local", DnsType::A).rcode, Rcode::SERVFAIL);
        let m = ask("_sip._udp.lab.local", DnsType::SRV);
        assert_eq!(
            m.answers[0].to_string(),
            "_sip._udp.lab.local 300 SRV 0 5 5060 sip.lab.local"
        );
        let m = ask("lab.local", DnsType::ANY);
        assert_eq!(m.answers.len(), 2);
        // An expected code that differs.
        let mut q = DnsQuery::new("www.lab.local", DnsType::A);
        q.expect = Some(Rcode::NXDOMAIN);
        let a = w.answer(&w.query_message(7, &q)).unwrap();
        assert_eq!(
            check_answer(&a, 7, &q),
            DnsCheck::Answer {
                rcode: Rcode::NOERROR,
                ok: false
            }
        );
        // Garbage gets FORMERR, a response nothing.
        assert_eq!(
            Message::parse(&w.answer(&[0; 12]).unwrap()).unwrap().rcode,
            Rcode::FORMERR
        );
        assert!(w.answer(&a).is_none());
    }

    #[test]
    fn learns_from_a_capture() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/dns-lookups.pcap"
        );
        let w = DnsWorkload::from_capture(&Capture::from_path(path).unwrap()).unwrap();
        assert_eq!(w.queries.len(), 8);
        assert_eq!(w.queries[5].to_string(), "missing.lab.local A NXDOMAIN");
        assert_eq!(w.queries[0].expect, Some(Rcode::NOERROR));
        assert_eq!(
            w.errors,
            vec![("missing.lab.local".to_string(), Rcode::NXDOMAIN)]
        );
        // The CNAME is in two answers but kept once.
        assert_eq!(w.records.len(), 8, "{:#?}", w.records);
        let (rcode, a) = w.lookup("www.lab.local", DnsType::AAAA);
        assert_eq!((rcode, a.len()), (Rcode::NOERROR, 2));
        let (_, a) = w.lookup("80.2.1.10.in-addr.arpa", DnsType::PTR);
        assert_eq!(a[0].data, DnsData::Name("web.lab.local".into()));
        let (_, a) = w.lookup("lab.local", DnsType::TXT);
        assert_eq!(a[0].data, DnsData::Txt(vec!["v=spf1 mx -all".into()]));
        // The query-only sample has queries but nothing to answer with.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/dns.pcap");
        let w = DnsWorkload::from_capture(&Capture::from_path(path).unwrap()).unwrap();
        assert_eq!((w.queries.len(), w.records.len()), (20, 0));
    }
}
