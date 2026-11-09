//! Multicast DNS (RFC 6762) and DNS service discovery (RFC 6763): a
//! responder for the host's name and services, and queries for others'.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use super::Me;
use crate::net::be16;
use crate::tcp::wire::{self, Path};
use crate::udp::dns::{
    put_name, put_record_class, read_name, read_record, DnsData, DnsRecord, DnsType,
};
use crate::{Error, MacAddr, Result};

pub(crate) const MDNS_PORT: u16 = 5353;
pub(crate) const MDNS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub(crate) const MDNS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
const SERVICES: &str = "_services._dns-sd._udp.local";
/// Announcements when the host's addresses are set (RFC 6762 8.3: at least two).
const ANNOUNCEMENTS: u8 = 2;
/// Records found by queries that are kept.
const MAX_FOUND: usize = 256;

/// A service a host publishes by DNS-SD.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MdnsService {
    /// The instance name, e.g. `Lab printer` (empty: the host's name).
    pub instance: String,
    /// The service type, e.g. `_ipp._tcp`.
    pub service: String,
    pub port: u16,
    /// TXT record strings, `key=value`.
    pub txt: Vec<String>,
}

impl MdnsService {
    fn kind(&self) -> String {
        format!("{}.local", self.service)
    }

    fn full(&self) -> String {
        format!("{}.{}.local", self.instance, self.service)
    }
}

/// A host's mDNS responder and queries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MdnsConfig {
    /// The host's name in `.local` (default: its host name, else
    /// `ferotrx-` and the MAC's last three bytes).
    pub name: Option<String>,
    pub services: Vec<MdnsService>,
    /// Names to look up: a host (`printer.local`: A and AAAA) or a service
    /// type (`_http._tcp.local`: PTR).
    pub queries: Vec<String>,
    /// Time between rounds of queries (default 10 s).
    pub interval: Duration,
    /// Time to live of the host's records (default 120 s).
    pub ttl: u32,
}

impl Default for MdnsConfig {
    fn default() -> Self {
        Self {
            name: None,
            services: Vec::new(),
            queries: Vec::new(),
            interval: Duration::from_secs(10),
            ttl: 120,
        }
    }
}

fn local(name: &str) -> String {
    let n = name.trim_end_matches('.');
    if n.to_ascii_lowercase().ends_with(".local") {
        n.to_string()
    } else {
        format!("{n}.local")
    }
}

fn is_service(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("._tcp") || n.contains("._udp")
}

impl MdnsConfig {
    pub(crate) fn validate(&self, host: &super::HostConfig) -> Result<()> {
        if host.ipv4.is_none() && host.ipv6.is_none() {
            return Err(Error::Host(
                "mdns: the host needs an IPv4 or IPv6 address (static, dhcp, slaac or dhcpv6)"
                    .into(),
            ));
        }
        for s in &self.services {
            let t = s.service.to_ascii_lowercase();
            if !(t.starts_with('_') && (t.ends_with("._tcp") || t.ends_with("._udp"))) {
                return Err(Error::Host(format!(
                    "mdns: service type '{}' is not like _http._tcp",
                    s.service
                )));
            }
            if s.instance.len() > 63 || s.port == 0 {
                return Err(Error::Host(format!(
                    "mdns: service '{}' needs a name of 1-63 bytes and a port",
                    s.instance
                )));
            }
        }
        if let Some(n) = &self.name {
            if n.is_empty() || n.contains(' ') || n.len() > 63 {
                return Err(Error::Host(format!("mdns: '{n}' is not a host name")));
            }
        }
        if self.interval < Duration::from_millis(100) {
            return Err(Error::Host(
                "mdns: the query interval must be at least 100ms".into(),
            ));
        }
        Ok(())
    }
}

/// A record an mDNS query found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MdnsRecord {
    pub name: String,
    /// `A`, `AAAA`, `PTR`, `SRV`, `TXT` or another type.
    pub kind: String,
    /// The data as in a zone file.
    pub data: String,
    /// Who answered.
    pub from: IpAddr,
}

/// What a host's mDNS did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MdnsStatus {
    /// The host's name, `NAME.local`.
    pub name: String,
    /// Unsolicited announcements sent.
    pub announcements: u64,
    pub queries_sent: u64,
    /// Answers sent to others' queries.
    pub answers_sent: u64,
    /// mDNS messages received.
    pub received: u64,
    /// Answers from others that claimed the host's name for another address.
    pub conflicts: u64,
    /// Records the queries found.
    pub found: Vec<MdnsRecord>,
}

/// One host's mDNS.
#[derive(Debug)]
pub(crate) struct Mdns {
    cfg: MdnsConfig,
    name: String,
    announce_left: u8,
    next_announce: Duration,
    next_query: Duration,
    /// The addresses last announced.
    announced: (Option<Ipv4Addr>, Option<Ipv6Addr>, Option<Ipv6Addr>),
    status: MdnsStatus,
}

/// Where an mDNS message goes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct To {
    pub ip: IpAddr,
    pub mac: MacAddr,
    pub port: u16,
}

impl To {
    fn group(v4: bool) -> Self {
        if v4 {
            Self {
                ip: MDNS_V4.into(),
                mac: super::wire::multicast_mac4(MDNS_V4),
                port: MDNS_PORT,
            }
        } else {
            Self {
                ip: MDNS_V6.into(),
                mac: wire::multicast_mac(MDNS_V6),
                port: MDNS_PORT,
            }
        }
    }
}

fn header(id: u16, flags: u16, qd: u16, an: u16, ar: u16) -> Vec<u8> {
    let mut m = Vec::with_capacity(512);
    for v in [id, flags, qd, an, 0, ar] {
        m.extend_from_slice(&v.to_be_bytes());
    }
    m
}

fn kind_name(t: DnsType) -> String {
    t.to_string()
}

/// A record's data as in a zone file.
fn data_text(d: &DnsData) -> String {
    let r = DnsRecord {
        name: String::new(),
        rtype: DnsType::A,
        ttl: 0,
        data: d.clone(),
    };
    // "<name> <ttl> <type> <data>": keep the data.
    r.to_string()
        .splitn(4, ' ')
        .nth(3)
        .unwrap_or_default()
        .to_string()
}

impl Mdns {
    /// The responder for `cfg`, named `default` when the configuration
    /// gives no name.
    pub fn new(mut cfg: MdnsConfig, default: &str) -> Self {
        let name = local(cfg.name.as_deref().unwrap_or(default));
        let label = name[..name.len() - ".local".len()].to_string();
        for s in cfg.services.iter_mut().filter(|s| s.instance.is_empty()) {
            s.instance = label.clone();
        }
        Self {
            status: MdnsStatus {
                name: name.clone(),
                ..MdnsStatus::default()
            },
            cfg,
            name,
            announce_left: 0,
            next_announce: Duration::MAX,
            next_query: Duration::MAX,
            announced: (None, None, None),
        }
    }

    pub fn next_wake(&self) -> Duration {
        let a = if self.announce_left > 0 {
            self.next_announce
        } else {
            Duration::MAX
        };
        a.min(self.next_query)
    }

    /// The families the host can use now: IPv4 when it has its address,
    /// IPv6 when it has a link-local one.
    fn families(me: &Me) -> Vec<bool> {
        let mut f = Vec::new();
        if me.ip4.is_some() {
            f.push(true);
        }
        if me.ll.is_some() {
            f.push(false);
        }
        f
    }

    /// The host's own records, with `ttl`.
    fn records(&self, me: &Me, ttl: u32) -> Vec<(DnsRecord, bool)> {
        let host = self.name.clone();
        let rec = |name: &str, rtype: DnsType, data: DnsData| DnsRecord {
            name: name.to_string(),
            rtype,
            ttl,
            data,
        };
        let mut out = Vec::new();
        if let Some((a, _)) = me.ip4 {
            out.push((rec(&host, DnsType::A, DnsData::A(a)), true));
        }
        for a in [me.ip6.map(|a| a.0), me.ll].into_iter().flatten() {
            out.push((rec(&host, DnsType::AAAA, DnsData::Aaaa(a)), true));
        }
        for s in &self.cfg.services {
            out.push((rec(&s.kind(), DnsType::PTR, DnsData::Name(s.full())), false));
            out.push((
                rec(
                    &s.full(),
                    DnsType::SRV,
                    DnsData::Srv {
                        priority: 0,
                        weight: 0,
                        port: s.port,
                        target: host.clone(),
                    },
                ),
                true,
            ));
            let txt = if s.txt.is_empty() {
                vec![String::new()]
            } else {
                s.txt.clone()
            };
            out.push((rec(&s.full(), DnsType::TXT, DnsData::Txt(txt)), true));
            out.push((rec(SERVICES, DnsType::PTR, DnsData::Name(s.kind())), false));
        }
        out
    }

    /// Announcements and queries due now.
    pub fn poll(&mut self, me: &Me, now: Duration, out: &mut Vec<(To, Vec<u8>)>) {
        let families = Self::families(me);
        if families.is_empty() {
            return;
        }
        let addrs = (me.ip4.map(|a| a.0), me.ip6.map(|a| a.0), me.ll);
        if addrs != self.announced {
            // New addresses: announce them, then (re)start the queries.
            self.announced = addrs;
            self.announce_left = ANNOUNCEMENTS;
            self.next_announce = now;
            if !self.cfg.queries.is_empty() && self.next_query == Duration::MAX {
                self.next_query = now + Duration::from_millis(250);
            }
        }
        if self.announce_left > 0 && now >= self.next_announce {
            self.announce_left -= 1;
            self.next_announce = now + Duration::from_secs(1);
            let records = self.records(me, self.cfg.ttl);
            let m = response(0, &[], &records, &[], false);
            for &v4 in &families {
                self.status.announcements += 1;
                out.push((To::group(v4), m.clone()));
            }
        }
        if now >= self.next_query {
            self.next_query = now + self.cfg.interval;
            let mut qs = Vec::new();
            for q in &self.cfg.queries {
                let name = local(q);
                if is_service(&name) {
                    qs.push((name, DnsType::PTR));
                } else {
                    qs.push((name.clone(), DnsType::A));
                    qs.push((name, DnsType::AAAA));
                }
            }
            let mut m = header(0, 0, qs.len() as u16, 0, 0);
            for (name, t) in &qs {
                put_name(&mut m, name);
                m.extend_from_slice(&t.0.to_be_bytes());
                m.extend_from_slice(&1u16.to_be_bytes());
            }
            for &v4 in &families {
                self.status.queries_sent += 1;
                out.push((To::group(v4), m.clone()));
            }
        }
    }

    /// Goodbyes (TTL 0) for the host's records, when it stops.
    pub fn goodbye(&mut self, me: &Me, out: &mut Vec<(To, Vec<u8>)>) {
        if self.announced == (None, None, None) {
            return;
        }
        let records = self.records(me, 0);
        let m = response(0, &[], &records, &[], false);
        for v4 in Self::families(me) {
            out.push((To::group(v4), m.clone()));
        }
    }

    /// Takes an mDNS message from `src` (port `sport`, at `src_mac`); puts
    /// the answers to send in `out`.
    #[allow(clippy::too_many_arguments)]
    pub fn take(
        &mut self,
        me: &Me,
        src: IpAddr,
        sport: u16,
        src_mac: MacAddr,
        m: &[u8],
        out: &mut Vec<(To, Vec<u8>)>,
    ) {
        if m.len() < 12 {
            return;
        }
        self.status.received += 1;
        let (Some(id), Some(flags), Some(qd), Some(an), Some(ns), Some(ar)) = (
            be16(m, 0),
            be16(m, 2),
            be16(m, 4),
            be16(m, 6),
            be16(m, 8),
            be16(m, 10),
        ) else {
            return;
        };
        let mut at = 12;
        let mut questions = Vec::new();
        for _ in 0..qd {
            let Some((name, next)) = read_name(m, at) else {
                return;
            };
            let (Some(t), Some(class)) = (be16(m, next), be16(m, next + 2)) else {
                return;
            };
            questions.push((name, DnsType(t), class));
            at = next + 4;
        }
        if flags & 0x8000 != 0 {
            self.take_response(
                me,
                src,
                m,
                at,
                u32::from(an) + u32::from(ns) + u32::from(ar),
            );
            return;
        }
        // A query: answer what is ours.
        let legacy = sport != MDNS_PORT;
        let records = self.records(
            me,
            if legacy {
                self.cfg.ttl.min(10)
            } else {
                self.cfg.ttl
            },
        );
        let mut answers: Vec<(DnsRecord, bool)> = Vec::new();
        let mut unicast = legacy;
        for (name, t, class) in &questions {
            for (r, unique) in &records {
                let fits = r.name.eq_ignore_ascii_case(name)
                    && (*t == DnsType::ANY || *t == r.rtype)
                    && !answers.iter().any(|(a, _)| a == r);
                if fits {
                    answers.push((r.clone(), *unique));
                    unicast |= class & 0x8000 != 0;
                }
            }
        }
        if answers.is_empty() {
            return;
        }
        // With a PTR to an instance, its SRV, TXT and the host's addresses.
        let mut extra: Vec<(DnsRecord, bool)> = Vec::new();
        for (a, _) in &answers {
            if let DnsData::Name(target) = &a.data {
                for (r, u) in &records {
                    let related = r.name.eq_ignore_ascii_case(target)
                        || (r.name == self.name && a.rtype == DnsType::PTR && target != SERVICES);
                    if related
                        && !answers.iter().any(|(x, _)| x == r)
                        && !extra.iter().any(|(x, _)| x == r)
                    {
                        extra.push((r.clone(), *u));
                    }
                }
            }
        }
        self.status.answers_sent += 1;
        let echo: Vec<(String, DnsType)> = if legacy {
            questions.iter().map(|(n, t, _)| (n.clone(), *t)).collect()
        } else {
            Vec::new()
        };
        let msg = response(if legacy { id } else { 0 }, &echo, &answers, &extra, legacy);
        let to = if unicast {
            To {
                ip: src,
                mac: src_mac,
                port: sport,
            }
        } else {
            To::group(src.is_ipv4())
        };
        out.push((to, msg));
    }

    fn take_response(&mut self, me: &Me, src: IpAddr, m: &[u8], mut at: usize, count: u32) {
        for _ in 0..count {
            let Some((record, end)) = read_record(m, at) else {
                return;
            };
            at = end;
            let Some(r) = record else { continue };
            // Someone else answering for the host's name with another address.
            if r.name.eq_ignore_ascii_case(&self.name) && r.ttl > 0 {
                let ours = match &r.data {
                    DnsData::A(a) => me.ip4.map(|x| x.0) == Some(*a),
                    DnsData::Aaaa(a) => me.ip6.map(|x| x.0) == Some(*a) || me.ll == Some(*a),
                    _ => true,
                };
                if !ours {
                    self.status.conflicts += 1;
                }
            }
            if self.cfg.queries.is_empty() {
                continue;
            }
            let found = MdnsRecord {
                name: r.name.clone(),
                kind: kind_name(r.rtype),
                data: data_text(&r.data),
                from: src,
            };
            if r.ttl == 0 {
                self.status.found.retain(|f| {
                    !(f.name == found.name && f.kind == found.kind && f.data == found.data)
                });
                continue;
            }
            let known =
                self.status.found.iter().position(|f| {
                    f.name == found.name && f.kind == found.kind && f.data == found.data
                });
            match known {
                Some(i) => self.status.found[i].from = src,
                None if self.status.found.len() < MAX_FOUND => self.status.found.push(found),
                None => {}
            }
        }
    }

    pub fn status(&self) -> MdnsStatus {
        self.status.clone()
    }
}

/// A response message: unique records get the cache-flush bit, except in
/// answers to legacy unicast queries (which echo the questions).
fn response(
    id: u16,
    questions: &[(String, DnsType)],
    answers: &[(DnsRecord, bool)],
    extra: &[(DnsRecord, bool)],
    legacy: bool,
) -> Vec<u8> {
    let mut m = header(
        id,
        0x8400,
        questions.len() as u16,
        answers.len() as u16,
        extra.len() as u16,
    );
    for (name, t) in questions {
        put_name(&mut m, name);
        m.extend_from_slice(&t.0.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
    }
    for (r, unique) in answers.iter().chain(extra) {
        let class = if *unique && !legacy { 0x8001 } else { 1 };
        put_record_class(&mut m, r, class);
    }
    m
}

/// An mDNS frame from `me` to `to`, with TTL (hop limit) 255.
pub(crate) fn frame(me: &Me, to: &To, m: &[u8]) -> Option<Vec<u8>> {
    let src = match to.ip {
        IpAddr::V4(_) => IpAddr::V4(me.ip4?.0),
        IpAddr::V6(_) => IpAddr::V6(me.ll?),
    };
    let path = Path {
        src_mac: me.mac,
        dst_mac: to.mac,
        vlan: me.vlan,
        src,
        dst: to.ip,
    };
    Some(wire::udp_frame_ttl(&path, MDNS_PORT, to.port, m, 0, 255))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udp::dns::Message;

    fn me() -> Me {
        Me {
            mac: MacAddr([2, 0xdc, 0, 0, 1, 1]),
            vlan: None,
            hostname: Some("lab-1".into()),
            ip4: Some((Ipv4Addr::new(10, 0, 0, 5), 24)),
            gateway4: None,
            ip6: None,
            gateway6: None,
            ll: None,
        }
    }

    fn query(name: &str, t: DnsType, id: u16) -> Vec<u8> {
        let mut m = header(id, 0, 1, 0, 0);
        put_name(&mut m, name);
        m.extend_from_slice(&t.0.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m
    }

    #[test]
    fn a_responder_answers_for_its_name_and_services() {
        let cfg = MdnsConfig {
            services: vec![MdnsService {
                instance: "Lab web".into(),
                service: "_http._tcp".into(),
                port: 8080,
                txt: vec!["path=/".into()],
            }],
            ..MdnsConfig::default()
        };
        let me = me();
        let mut a = Mdns::new(cfg, &me.name());
        let mut out = Vec::new();
        a.poll(&me, Duration::ZERO, &mut out);
        assert_eq!(out.len(), 1, "an announcement");
        assert_eq!(out[0].0.ip, IpAddr::V4(MDNS_V4));
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let peer_mac = MacAddr([2, 0, 0, 0, 0, 9]);
        // A legacy unicast query (like dig -p 5353) gets a unicast answer
        // with its id and question.
        out.clear();
        a.take(
            &me,
            peer,
            40000,
            peer_mac,
            &query("LAB-1.local", DnsType::A, 77),
            &mut out,
        );
        assert_eq!(out[0].0.ip, peer);
        assert_eq!(out[0].0.port, 40000);
        let msg = Message::parse(&out[0].1).unwrap();
        assert_eq!(msg.id, 77);
        assert_eq!(msg.answers[0].data, DnsData::A(Ipv4Addr::new(10, 0, 0, 5)));
        // A service browse: the PTR, with SRV, TXT and A as additional records.
        out.clear();
        a.take(
            &me,
            peer,
            MDNS_PORT,
            peer_mac,
            &query("_http._tcp.local", DnsType::PTR, 0),
            &mut out,
        );
        assert_eq!(out[0].0.ip, IpAddr::V4(MDNS_V4));
        let m = &out[0].1;
        assert_eq!(be16(m, 6), Some(1));
        assert_eq!(be16(m, 10), Some(3));
        // A querier on another host finds them.
        let mut b = Mdns::new(
            MdnsConfig {
                queries: vec!["_http._tcp".into()],
                ..MdnsConfig::default()
            },
            &me.name(),
        );
        b.take(
            &me,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            MDNS_PORT,
            me.mac,
            m,
            &mut Vec::new(),
        );
        let found = b.status().found;
        let kinds: Vec<&str> = found.iter().map(|f| f.kind.as_str()).collect();
        assert_eq!(kinds, vec!["PTR", "A", "SRV", "TXT"]);
        assert_eq!(found[0].data, "Lab web._http._tcp.local");
        assert_eq!(found[1].data, "10.0.0.5");
        assert_eq!(found[2].data, "0 0 8080 lab-1.local");
        // Not ours: no answer.
        out.clear();
        a.take(
            &me,
            peer,
            MDNS_PORT,
            peer_mac,
            &query("other.local", DnsType::A, 0),
            &mut out,
        );
        assert!(out.is_empty());
    }
}
