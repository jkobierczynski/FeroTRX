//! NetFlow version 9 (RFC 3954) and IPFIX (RFC 7011) export: a host that
//! sends flow records to a collector, like a router or probe would, for
//! testing collectors and the paths to them. The flows are made up (seeded)
//! from address ranges.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{Error, Result};

/// NetFlow v9 or IPFIX.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FlowVersion {
    V9,
    #[default]
    Ipfix,
}

impl std::fmt::Display for FlowVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            FlowVersion::V9 => "netflow9",
            FlowVersion::Ipfix => "ipfix",
        })
    }
}

impl std::str::FromStr for FlowVersion {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "9" | "v9" | "netflow9" | "netflow" => Ok(FlowVersion::V9),
            "10" | "ipfix" => Ok(FlowVersion::Ipfix),
            _ => Err(Error::InvalidSpec(format!(
                "flow export version '{s}' is not 9 (NetFlow v9) or 10 (IPFIX)"
            ))),
        }
    }
}

/// A host's flow exporter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowExportConfig {
    /// The collector's address and port (NetFlow usually 2055, IPFIX 4739).
    pub collector: SocketAddr,
    pub version: FlowVersion,
    /// Time between export packets (default 1 s).
    pub interval: Duration,
    /// Flow records in each export (default 10).
    pub records: u32,
    /// Time between template resends (default 10 s; UDP needs them resent).
    pub template_interval: Duration,
    /// Source ID (NetFlow v9) or observation domain (IPFIX) (default 1).
    pub domain: u32,
    /// The flows' source and destination addresses come from these
    /// prefixes (default 10.1.0.0/16 and 10.2.0.0/16), both of one family.
    pub src: (IpAddr, u8),
    pub dst: (IpAddr, u8),
    /// Seed of the made-up flows.
    pub seed: u64,
}

impl FlowExportConfig {
    pub fn new(collector: SocketAddr) -> Self {
        Self {
            collector,
            version: FlowVersion::Ipfix,
            interval: Duration::from_secs(1),
            records: 10,
            template_interval: Duration::from_secs(10),
            domain: 1,
            src: (IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16),
            dst: (IpAddr::V4(Ipv4Addr::new(10, 2, 0, 0)), 16),
            seed: 1,
        }
    }

    pub(crate) fn validate(&self, host: &super::HostConfig) -> Result<()> {
        let err = |m: String| Err(Error::Host(format!("flow_export: {m}")));
        let c = self.collector.ip();
        if c.is_multicast() || c.is_unspecified() || self.collector.port() == 0 {
            return err(format!("{} is not a collector address", self.collector));
        }
        if c.is_ipv4() && host.ipv4.is_none() || c.is_ipv6() && host.ipv6.is_none() {
            return err(format!(
                "the host needs an {} address to reach {}",
                if c.is_ipv4() { "IPv4" } else { "IPv6" },
                self.collector
            ));
        }
        if self.src.0.is_ipv4() != self.dst.0.is_ipv4() {
            return err("the source and destination ranges must be of one IP version".into());
        }
        let max = if self.src.0.is_ipv4() { 32 } else { 128 };
        if self.src.1 > max || self.dst.1 > max {
            return err("a prefix length is too long".into());
        }
        if self.records == 0 || self.records > 1000 {
            return err("records must be 1-1000 per export".into());
        }
        if self.interval < Duration::from_millis(10) || self.template_interval.is_zero() {
            return err("the interval must be at least 10ms".into());
        }
        Ok(())
    }
}

/// What a host's flow exporter did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlowExportStatus {
    pub collector: String,
    /// `netflow9` or `ipfix`.
    pub version: String,
    /// Export packets sent, and their bytes (UDP payload).
    pub packets: u64,
    pub bytes: u64,
    /// Flow records sent.
    pub records: u64,
    /// Template records sent.
    pub templates: u64,
    /// True while the next hop to the collector is not resolved.
    pub waiting: bool,
}

/// Field IDs (the same numbers in NetFlow v9 and IPFIX) and lengths.
const IN_BYTES: u16 = 1;
const IN_PKTS: u16 = 2;
const PROTOCOL: u16 = 4;
const TOS: u16 = 5;
const TCP_FLAGS: u16 = 6;
const L4_SRC_PORT: u16 = 7;
const IPV4_SRC_ADDR: u16 = 8;
const INPUT_SNMP: u16 = 10;
const L4_DST_PORT: u16 = 11;
const IPV4_DST_ADDR: u16 = 12;
const OUTPUT_SNMP: u16 = 14;
const LAST_SWITCHED: u16 = 21;
const FIRST_SWITCHED: u16 = 22;
const IPV6_SRC_ADDR: u16 = 27;
const IPV6_DST_ADDR: u16 = 28;
const FLOW_START_MS: u16 = 152;
const FLOW_END_MS: u16 = 153;

const TEMPLATE_V4: u16 = 256;
const TEMPLATE_V6: u16 = 257;

/// The fields of the template for `v6` addresses in `version`.
fn fields(version: FlowVersion, v6: bool) -> Vec<(u16, u16)> {
    let a = if v6 { 16 } else { 4 };
    let (src, dst) = if v6 {
        (IPV6_SRC_ADDR, IPV6_DST_ADDR)
    } else {
        (IPV4_SRC_ADDR, IPV4_DST_ADDR)
    };
    let mut f = vec![
        (src, a),
        (dst, a),
        (L4_SRC_PORT, 2),
        (L4_DST_PORT, 2),
        (PROTOCOL, 1),
        (TOS, 1),
        (TCP_FLAGS, 1),
        (INPUT_SNMP, 4),
        (OUTPUT_SNMP, 4),
    ];
    match version {
        FlowVersion::V9 => f.extend([
            (IN_PKTS, 4),
            (IN_BYTES, 4),
            (FIRST_SWITCHED, 4),
            (LAST_SWITCHED, 4),
        ]),
        FlowVersion::Ipfix => f.extend([
            (IN_PKTS, 8),
            (IN_BYTES, 8),
            (FLOW_START_MS, 8),
            (FLOW_END_MS, 8),
        ]),
    }
    f
}

/// One host's exporter.
#[derive(Debug)]
pub(crate) struct Exporter {
    cfg: FlowExportConfig,
    status: FlowExportStatus,
    next: Duration,
    next_template: Duration,
    /// NetFlow v9: export packets sent; IPFIX: data records sent.
    sequence: u32,
    rng: u64,
    /// Unix time at engine time zero, in ms.
    epoch_ms: u64,
}

impl Exporter {
    pub fn new(cfg: FlowExportConfig) -> Self {
        let epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        Self::with_epoch(cfg, epoch_ms)
    }

    pub fn with_epoch(cfg: FlowExportConfig, epoch_ms: u64) -> Self {
        Self {
            status: FlowExportStatus {
                collector: cfg.collector.to_string(),
                version: cfg.version.to_string(),
                waiting: true,
                ..FlowExportStatus::default()
            },
            rng: cfg.seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1,
            cfg,
            next: Duration::ZERO,
            next_template: Duration::ZERO,
            sequence: 0,
            epoch_ms,
        }
    }

    pub fn collector(&self) -> SocketAddr {
        self.cfg.collector
    }

    pub fn set_waiting(&mut self, waiting: bool) {
        self.status.waiting = waiting;
    }

    pub fn next_wake(&self) -> Duration {
        self.next
    }

    fn rand(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn addr_in(&mut self, (base, len): (IpAddr, u8)) -> IpAddr {
        match base {
            IpAddr::V4(b) => {
                let host = 32 - u32::from(len);
                let mask = if host >= 32 {
                    u32::MAX
                } else {
                    (1u32 << host) - 1
                };
                let r = (self.rand() as u32) & mask;
                // Not the network address, unless that is all there is.
                let r = if mask == 0 { 0 } else { r.max(1) };
                IpAddr::V4(Ipv4Addr::from((u32::from(b) & !mask) | r))
            }
            IpAddr::V6(b) => {
                let host = 128 - u32::from(len);
                let mask = if host >= 128 {
                    u128::MAX
                } else {
                    (1u128 << host) - 1
                };
                let r = ((u128::from(self.rand()) << 64) | u128::from(self.rand())) & mask;
                let r = if mask == 0 { 0 } else { r.max(1) };
                IpAddr::V6(Ipv6Addr::from((u128::from(b) & !mask) | r))
            }
        }
    }

    /// One made-up flow record of the template's layout, ending at `now`.
    fn record(&mut self, now: Duration, out: &mut Vec<u8>) {
        let src = self.addr_in(self.cfg.src);
        let dst = self.addr_in(self.cfg.dst);
        let tcp = !self.rand().is_multiple_of(4);
        let packets = 1 + self.rand() % 1000;
        let size = 64 + self.rand() % 1437;
        let dur_ms = self.rand() % 30_000;
        let end_ms = now.as_millis() as u64;
        let start_ms = end_ms.saturating_sub(dur_ms);
        for a in [src, dst] {
            match a {
                IpAddr::V4(a) => out.extend_from_slice(&a.octets()),
                IpAddr::V6(a) => out.extend_from_slice(&a.octets()),
            }
        }
        let sport = 1024 + (self.rand() % 64000) as u16;
        let dport = [80u16, 443, 53, 22, 25, 123, 3389, 8080][(self.rand() % 8) as usize];
        out.extend_from_slice(&sport.to_be_bytes());
        out.extend_from_slice(&dport.to_be_bytes());
        out.push(if tcp { 6 } else { 17 });
        out.push(0);
        out.push(if tcp { 0x1b } else { 0 }); // SYN, ACK, PSH, FIN
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&2u32.to_be_bytes());
        match self.cfg.version {
            FlowVersion::V9 => {
                out.extend_from_slice(&(packets as u32).to_be_bytes());
                out.extend_from_slice(&((packets * size) as u32).to_be_bytes());
                out.extend_from_slice(&(start_ms as u32).to_be_bytes());
                out.extend_from_slice(&(end_ms as u32).to_be_bytes());
            }
            FlowVersion::Ipfix => {
                out.extend_from_slice(&packets.to_be_bytes());
                out.extend_from_slice(&(packets * size).to_be_bytes());
                out.extend_from_slice(&(self.epoch_ms + start_ms).to_be_bytes());
                out.extend_from_slice(&(self.epoch_ms + end_ms).to_be_bytes());
            }
        }
    }

    /// The export packets (UDP payloads) due now.
    pub fn poll(&mut self, now: Duration, out: &mut Vec<Vec<u8>>) {
        if now < self.next {
            return;
        }
        self.next = now + self.cfg.interval;
        let v6 = self.cfg.src.0.is_ipv6();
        let tid = if v6 { TEMPLATE_V6 } else { TEMPLATE_V4 };
        let version = self.cfg.version;
        let fields = fields(version, v6);
        let rec_len: usize = fields.iter().map(|f| usize::from(f.1)).sum();
        let with_template = now >= self.next_template;
        if with_template {
            self.next_template = now + self.cfg.template_interval;
        }
        // Records per packet, so that a packet stays under 1400 bytes.
        let per_packet = ((1400 - 100) / rec_len).max(1);
        let mut left = self.cfg.records as usize;
        let mut first = true;
        while left > 0 {
            let n = left.min(per_packet);
            left -= n;
            let mut sets = Vec::new();
            let mut count = 0u16;
            if first && with_template {
                let set_id: u16 = if version == FlowVersion::V9 { 0 } else { 2 };
                let mut t = Vec::new();
                t.extend_from_slice(&tid.to_be_bytes());
                t.extend_from_slice(&(fields.len() as u16).to_be_bytes());
                for (id, len) in &fields {
                    t.extend_from_slice(&id.to_be_bytes());
                    t.extend_from_slice(&len.to_be_bytes());
                }
                sets.extend_from_slice(&set_id.to_be_bytes());
                sets.extend_from_slice(&((4 + t.len()) as u16).to_be_bytes());
                sets.extend_from_slice(&t);
                count += 1;
                self.status.templates += 1;
            }
            first = false;
            let mut data = Vec::with_capacity(n * rec_len);
            for _ in 0..n {
                self.record(now, &mut data);
            }
            // Pad the set to four bytes.
            while (4 + data.len()) % 4 != 0 {
                data.push(0);
            }
            sets.extend_from_slice(&tid.to_be_bytes());
            sets.extend_from_slice(&((4 + data.len()) as u16).to_be_bytes());
            sets.extend_from_slice(&data);
            count += n as u16;
            let unix = ((self.epoch_ms + now.as_millis() as u64) / 1000) as u32;
            let mut p = Vec::with_capacity(20 + sets.len());
            match version {
                FlowVersion::V9 => {
                    p.extend_from_slice(&9u16.to_be_bytes());
                    p.extend_from_slice(&count.to_be_bytes());
                    p.extend_from_slice(&(now.as_millis() as u32).to_be_bytes()); // uptime
                    p.extend_from_slice(&unix.to_be_bytes());
                    p.extend_from_slice(&self.sequence.to_be_bytes());
                    p.extend_from_slice(&self.cfg.domain.to_be_bytes());
                    self.sequence = self.sequence.wrapping_add(1);
                }
                FlowVersion::Ipfix => {
                    p.extend_from_slice(&10u16.to_be_bytes());
                    p.extend_from_slice(&((16 + sets.len()) as u16).to_be_bytes());
                    p.extend_from_slice(&unix.to_be_bytes());
                    p.extend_from_slice(&self.sequence.to_be_bytes());
                    p.extend_from_slice(&self.cfg.domain.to_be_bytes());
                    self.sequence = self.sequence.wrapping_add(n as u32);
                }
            }
            p.extend_from_slice(&sets);
            self.status.packets += 1;
            self.status.bytes += p.len() as u64;
            self.status.records += n as u64;
            out.push(p);
        }
    }

    pub fn status(&self) -> FlowExportStatus {
        self.status.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::be16;

    fn sets(p: &[u8], at: usize) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        let mut o = &p[at..];
        while o.len() >= 4 {
            let id = be16(o, 0).unwrap();
            let len = usize::from(be16(o, 2).unwrap());
            out.push((id, o[4..len].to_vec()));
            o = &o[len..];
        }
        out
    }

    #[test]
    fn ipfix_packets_with_templates_and_records() {
        let mut cfg = FlowExportConfig::new("10.0.0.9:4739".parse().unwrap());
        cfg.records = 50;
        let mut e = Exporter::with_epoch(cfg, 1_700_000_000_000);
        let mut out = Vec::new();
        e.poll(Duration::from_secs(5), &mut out);
        // 50 records of 55 bytes, 23 to a packet: three packets, the
        // template in the first.
        assert_eq!(out.len(), 3);
        let p = &out[0];
        assert_eq!(be16(p, 0), Some(10));
        assert_eq!(usize::from(be16(p, 2).unwrap()), p.len());
        assert_eq!(u32::from_be_bytes([p[4], p[5], p[6], p[7]]), 1_700_000_005);
        let s = sets(p, 16);
        assert_eq!(s[0].0, 2);
        assert_eq!(be16(&s[0].1, 0), Some(TEMPLATE_V4));
        assert_eq!(be16(&s[0].1, 2), Some(13));
        assert_eq!(s[1].0, TEMPLATE_V4);
        let rec = 4 + 4 + 2 + 2 + 1 + 1 + 1 + 4 + 4 + 8 * 4;
        let first = s[1].1.len() / rec;
        // The second packet's sequence counts the first one's records.
        let q = &out[1];
        assert_eq!(u32::from_be_bytes([q[8], q[9], q[10], q[11]]), first as u32);
        assert_eq!(sets(q, 16)[0].0, TEMPLATE_V4);
        let st = e.status();
        assert_eq!((st.packets, st.records, st.templates), (3, 50, 1));
        // Addresses from the ranges.
        assert_eq!(s[1].1[0..2], [10, 1]);
        assert_eq!(s[1].1[4..6], [10, 2]);
        // No template again until template_interval passes.
        out.clear();
        e.poll(Duration::from_secs(6), &mut out);
        assert!(sets(&out[0], 16).iter().all(|(id, _)| *id == TEMPLATE_V4));
    }

    #[test]
    fn netflow_v9_counts_records_and_packets() {
        let mut cfg = FlowExportConfig::new("[fd00::9]:2055".parse().unwrap());
        cfg.version = FlowVersion::V9;
        cfg.src = ("fd00:1::".parse().unwrap(), 64);
        cfg.dst = ("fd00:2::".parse().unwrap(), 64);
        cfg.records = 3;
        let mut e = Exporter::with_epoch(cfg, 0);
        let mut out = Vec::new();
        e.poll(Duration::ZERO, &mut out);
        let p = &out[0];
        assert_eq!(be16(p, 0), Some(9));
        assert_eq!(be16(p, 2), Some(4), "a template and three records");
        let s = sets(p, 20);
        assert_eq!(s[0].0, 0);
        assert_eq!(be16(&s[0].1, 0), Some(TEMPLATE_V6));
        assert_eq!(s[1].0, TEMPLATE_V6);
        assert_eq!(s[1].1[0..4], [0xfd, 0, 0, 1]);
        out.clear();
        e.poll(Duration::from_secs(1), &mut out);
        assert_eq!(
            u32::from_be_bytes([out[0][12], out[0][13], out[0][14], out[0][15]]),
            1
        );
    }
}
