//! Emulated clients and servers inside GTP-U tunnels, as between a base
//! station and a user plane function in a mobile network (TRex runs its
//! ASTF traffic like this).
//!
//! A [`GtpuPort`] wraps the port of a TCP, UDP or application run. What the
//! engine sends from a tunneled host loses its Ethernet header and goes out
//! as outer Ethernet / IP / UDP 2152 / GTP-U to the far end of the tunnel,
//! with a TEID of its own for each client address: the first client gets
//! `teid`, the next `teid + 1`, and so on. GTP-U arriving at the local
//! address is unwrapped and handed to the engine as an Ethernet frame. The
//! engine's ARP requests and neighbor solicitations for its gateway are
//! answered inside the port, since a tunnel has no link layer; the outer
//! gateway is found with ARP or neighbor discovery like any host's.

use std::collections::VecDeque;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::{Duration, Instant};

use crate::net::{be16, MacAddr, ETHERTYPE_IPV4, ETHERTYPE_IPV6, GTPU_PORT, IPPROTO_UDP};
use crate::tcp::wire::{self, Path};
use crate::{Error, PacketPort, Result, SinkError, TcpHostSpec};

const ETHERTYPE_ARP: u16 = 0x0806;

/// The MAC address the engine sees as its gateway inside a tunnel.
pub const TUNNEL_GATEWAY_MAC: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x47, 0x54]);

/// Frames held for an outer gateway whose MAC is not known yet.
const PENDING: usize = 256;

/// How long to wait before asking for the outer gateway's MAC again.
const RESOLVE_EVERY: Duration = Duration::from_millis(500);

/// Frames a `recv` reads from the port before it gives up for now.
const RX_BATCH: usize = 64;

/// One end of a GTP-U tunnel, written
/// `local=IP,remote=IP[,gateway=IP][,teid=N][,qfi=N][,vlan=ID][,mac=MAC]`.
///
/// `local` is this end's outer address and `remote` the far end's. The outer
/// gateway defaults to `remote` (on the same link). `teid` is the first
/// client's tunnel ID (default 1). `qfi` adds a PDU session container with
/// that QoS flow ID (uplink on the client's end, downlink on the server's).
/// `vlan` tags the outer frames. `mac` is the outer source MAC, by default
/// 02:00 followed by the last four bytes of `local`. `mtu` is the outer
/// link's (default 1500): the MSS of TCP SYNs through the tunnel, both ways,
/// is lowered to fit, as routers clamp it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GtpuSpec {
    pub local: IpAddr,
    pub remote: IpAddr,
    pub gateway: Option<IpAddr>,
    pub teid: u32,
    pub qfi: Option<u8>,
    pub vlan: Option<u16>,
    pub mac: Option<MacAddr>,
    /// The outer link's MTU (default 1500): TCP SYNs in the tunnel get
    /// their MSS lowered so segments fit with the tunnel's headers.
    pub mtu: u16,
}

impl GtpuSpec {
    /// The largest TCP MSS a segment of IP version `v6` can have inside the
    /// tunnel without going over the MTU.
    fn mss(&self, inner_v6: bool) -> u16 {
        let outer = if self.local.is_ipv6() { 40 } else { 20 } + 8;
        let gtp = if self.qfi.is_some() { 16 } else { 8 };
        let inner = if inner_v6 { 40 } else { 20 } + 20;
        self.mtu.saturating_sub(outer + gtp + inner)
    }

    /// The outer source MAC.
    pub fn mac(&self) -> MacAddr {
        self.mac.unwrap_or_else(|| {
            let o = match self.local {
                IpAddr::V4(a) => a.octets(),
                IpAddr::V6(a) => {
                    let b = a.octets();
                    [b[12], b[13], b[14], b[15]]
                }
            };
            MacAddr([0x02, 0x00, o[0], o[1], o[2], o[3]])
        })
    }

    fn gateway(&self) -> IpAddr {
        self.gateway.unwrap_or(self.remote)
    }
}

impl FromStr for GtpuSpec {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let err = |m: String| Error::InvalidSpec(format!("gtpu '{s}': {m}"));
        let mut local = None;
        let mut remote = None;
        let mut spec = GtpuSpec {
            local: Ipv4Addr::UNSPECIFIED.into(),
            remote: Ipv4Addr::UNSPECIFIED.into(),
            gateway: None,
            teid: 1,
            qfi: None,
            vlan: None,
            mac: None,
            mtu: 1500,
        };
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let (k, v) = part
                .split_once('=')
                .map(|(k, v)| (k.trim(), v.trim()))
                .ok_or_else(|| err(format!("'{part}' needs a value")))?;
            let ip = |v: &str| {
                v.parse::<IpAddr>()
                    .map_err(|_| err(format!("invalid address '{v}'")))
            };
            let num = |v: &str| {
                crate::field_engine::parse_num(v)
                    .ok_or_else(|| err(format!("invalid number '{v}'")))
            };
            match k {
                "local" => local = Some(ip(v)?),
                "remote" => remote = Some(ip(v)?),
                "gateway" | "gw" => spec.gateway = Some(ip(v)?),
                "teid" => {
                    spec.teid = u32::try_from(num(v)?).map_err(|_| err("teid is 32 bits".into()))?
                }
                "qfi" => {
                    spec.qfi = Some(
                        u8::try_from(num(v)?)
                            .ok()
                            .filter(|q| *q < 64)
                            .ok_or_else(|| err("qfi must be 0 to 63".into()))?,
                    )
                }
                "vlan" => {
                    spec.vlan = Some(
                        u16::try_from(num(v)?)
                            .ok()
                            .filter(|v| *v < 4096)
                            .ok_or_else(|| err("vlan must be 0 to 4095".into()))?,
                    )
                }
                "mac" => spec.mac = Some(v.parse().map_err(|_| err(format!("invalid MAC '{v}'")))?),
                "mtu" => {
                    spec.mtu = u16::try_from(num(v)?)
                        .ok()
                        .filter(|m| *m >= 576)
                        .ok_or_else(|| err("mtu must be 576 to 65535".into()))?
                }
                _ => {
                    return Err(err(format!(
                        "unknown key '{k}' (try local, remote, gateway, teid, qfi, vlan, mac, mtu)"
                    )))
                }
            }
        }
        spec.local = local.ok_or_else(|| err("needs local=IP".into()))?;
        spec.remote = remote.ok_or_else(|| err("needs remote=IP".into()))?;
        if spec.local.is_ipv4() != spec.remote.is_ipv4()
            || spec
                .gateway
                .is_some_and(|g| g.is_ipv4() != spec.local.is_ipv4())
        {
            return Err(err(
                "local, remote and gateway must be of one IP version".into()
            ));
        }
        Ok(spec)
    }
}

impl fmt::Display for GtpuSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "local={},remote={}", self.local, self.remote)?;
        if let Some(g) = self.gateway {
            write!(f, ",gateway={g}")?;
        }
        write!(f, ",teid={}", self.teid)?;
        if let Some(q) = self.qfi {
            write!(f, ",qfi={q}")?;
        }
        if let Some(v) = self.vlan {
            write!(f, ",vlan={v}")?;
        }
        if let Some(m) = self.mac {
            write!(f, ",mac={m}")?;
        }
        if self.mtu != 1500 {
            write!(f, ",mtu={}", self.mtu)?;
        }
        Ok(())
    }
}

/// The GTP-U tunnels of a TCP or UDP run: the client's end and the server's
/// (`[gtpu]` in profiles, with `client` and `server` in the text form of
/// [`GtpuSpec`]; `--client-gtpu` and `--server-gtpu` on the command line).
/// Either can be left out, for a run against a real peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GtpuTunnels {
    pub client: Option<GtpuSpec>,
    pub server: Option<GtpuSpec>,
}

impl GtpuTunnels {
    pub fn is_none(&self) -> bool {
        self.client.is_none() && self.server.is_none()
    }

    /// The tunnel ends on each port, with ports numbered as `interfaces`
    /// lists them (the profile's `interfaces`).
    pub fn ends(
        &self,
        interfaces: &[String],
        default_iface: Option<&str>,
        client: Option<&TcpHostSpec>,
        server: Option<&TcpHostSpec>,
    ) -> Result<Vec<Vec<GtpuEnd>>> {
        let mut out = vec![Vec::new(); interfaces.len()];
        let clients = client.map(|h| (h.ip, h.ips.max(1)));
        for (what, spec, host, uplink) in [
            ("client", &self.client, client, true),
            ("server", &self.server, server, false),
        ] {
            let Some(spec) = spec else { continue };
            let host =
                host.ok_or_else(|| Error::Tcp(format!("gtpu: there is no {what} to tunnel")))?;
            if host.is_dynamic() {
                return Err(Error::Tcp(format!(
                    "gtpu: the {what} gets its address by DHCP, SLAAC or DHCPv6; give it an address"
                )));
            }
            let name = host.iface.as_deref().or(default_iface).unwrap_or_default();
            let Some(port) = interfaces.iter().position(|n| n == name) else {
                continue;
            };
            out[port].push(GtpuEnd {
                spec: spec.clone(),
                hosts: (host.ip, host.ips.max(1)),
                clients,
                host_mac: host.mac(),
                host_vlan: host.vlan,
                uplink,
            });
        }
        Ok(out)
    }
}

/// The `[gtpu]` table of TCP and UDP profiles: `client` and `server`, each a
/// [`GtpuSpec`] in its text form.
#[cfg(feature = "profile")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawGtpu {
    client: Option<String>,
    server: Option<String>,
}

#[cfg(feature = "profile")]
impl RawGtpu {
    pub(crate) fn tunnels(raw: Option<RawGtpu>) -> Result<GtpuTunnels> {
        let Some(raw) = raw else {
            return Ok(GtpuTunnels::default());
        };
        let parse = |s: Option<String>| {
            s.map(|s| s.parse::<GtpuSpec>())
                .transpose()
                .map_err(|e| Error::Profile(format!("[gtpu]: {e}")))
        };
        Ok(GtpuTunnels {
            client: parse(raw.client)?,
            server: parse(raw.server)?,
        })
    }
}

/// One tunnel end on a port, as [`GtpuTunnels::ends`] finds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GtpuEnd {
    pub spec: GtpuSpec,
    /// The emulated hosts the tunnel carries: first address and count.
    pub hosts: (IpAddr, u32),
    /// The clients, whose index picks the TEID.
    pub clients: Option<(IpAddr, u32)>,
    /// The emulated host's MAC and VLAN, for the frames handed to the engine.
    pub host_mac: MacAddr,
    pub host_vlan: Option<u16>,
    /// The client's end: PDU session containers say uplink.
    pub uplink: bool,
}

/// `addr - first` when `addr` is one of the `n` addresses from `first`.
fn index_in(addr: IpAddr, (first, n): (IpAddr, u32)) -> Option<u32> {
    let d = match (addr, first) {
        (IpAddr::V4(a), IpAddr::V4(f)) => u128::from(u32::from(a).wrapping_sub(u32::from(f))),
        (IpAddr::V6(a), IpAddr::V6(f)) => u128::from(a).wrapping_sub(u128::from(f)),
        _ => return None,
    };
    (d < u128::from(n)).then_some(d as u32)
}

/// What a [`GtpuPort`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GtpuStats {
    /// Frames sent into a tunnel.
    pub encapsulated: u64,
    /// GTP-U packets received and handed to the engine.
    pub decapsulated: u64,
    /// Frames dropped while the outer gateway did not answer.
    pub unresolved: u64,
    /// GTP-U packets for the local address that were not G-PDUs carrying IP.
    pub ignored: u64,
}

struct End {
    cfg: GtpuEnd,
    mac: MacAddr,
    gateway_mac: Option<MacAddr>,
    asked: Option<Instant>,
    pending: VecDeque<Vec<u8>>,
}

/// A [`PacketPort`] that carries emulated hosts through GTP-U tunnels; see
/// the [module documentation](self).
pub struct GtpuPort {
    inner: Box<dyn PacketPort>,
    ends: Vec<End>,
    /// Frames for the engine made inside the port: answers to its ARP and
    /// neighbor solicitations.
    to_engine: VecDeque<Vec<u8>>,
    ip_id: u16,
    stats: GtpuStats,
}

impl GtpuPort {
    pub fn new(inner: Box<dyn PacketPort>, ends: Vec<GtpuEnd>) -> Self {
        Self {
            inner,
            ends: ends
                .into_iter()
                .map(|cfg| End {
                    mac: cfg.spec.mac(),
                    cfg,
                    gateway_mac: None,
                    asked: None,
                    pending: VecDeque::new(),
                })
                .collect(),
            to_engine: VecDeque::new(),
            ip_id: 0,
            stats: GtpuStats::default(),
        }
    }

    pub fn stats(&self) -> GtpuStats {
        self.stats
    }

    /// The tunnel end that carries `ip`.
    fn end_of(&self, ip: IpAddr) -> Option<usize> {
        self.ends
            .iter()
            .position(|e| index_in(ip, e.cfg.hosts).is_some())
    }

    /// Answers the engine's ARP request or neighbor solicitation for
    /// anything on the other side of the tunnel. True when `frame` was one.
    fn answer_engine(&mut self, frame: &[u8]) -> bool {
        let Some(link) = wire::parse_link(frame) else {
            return false;
        };
        let p = &frame[link.payload..];
        match link.ethertype {
            ETHERTYPE_ARP => {
                if let Some(a) = wire::parse_arp(p) {
                    if a.op == 1 && self.end_of(a.sender_ip.into()).is_some() {
                        self.to_engine.push_back(wire::arp_frame(
                            a.sender_mac,
                            link.vlan,
                            2,
                            TUNNEL_GATEWAY_MAC,
                            a.target_ip,
                            a.sender_mac,
                            a.sender_ip,
                        ));
                    }
                }
                true
            }
            ETHERTYPE_IPV6 => {
                let Some(ip) = wire::parse_ipv6(p) else {
                    return false;
                };
                if ip.proto != crate::net::IPPROTO_ICMPV6 || self.end_of(ip.src).is_none() {
                    return false;
                }
                match p.get(40).copied() {
                    // Neighbor solicitation: say the target is the gateway.
                    Some(wire::NDP_SOLICIT) => {
                        if let Some(n) = wire::parse_ndp(&ip) {
                            let path = Path {
                                src_mac: TUNNEL_GATEWAY_MAC,
                                dst_mac: link.src,
                                vlan: link.vlan,
                                src: n.target,
                                dst: ip.src,
                            };
                            self.to_engine.extend(wire::ndp_advert(&path));
                        }
                        true
                    }
                    // Other neighbor discovery and multicast listener
                    // messages have no one to reach.
                    Some(130..=137 | 143) => true,
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// Puts the IP datagram of `frame` into its tunnel, or returns false
    /// when no tunnel carries its source.
    fn encapsulate(&mut self, frame: &[u8]) -> std::result::Result<bool, SinkError> {
        let Some(link) = wire::parse_link(frame) else {
            return Ok(false);
        };
        if link.ethertype != ETHERTYPE_IPV4 && link.ethertype != ETHERTYPE_IPV6 {
            return Ok(false);
        }
        let p = &frame[link.payload..];
        let Some(ip) = wire::parse_ip(p, false) else {
            return Ok(false);
        };
        let Some(e) = self.end_of(ip.src) else {
            return Ok(false);
        };
        // The datagram without Ethernet padding.
        let len = match link.ethertype {
            ETHERTYPE_IPV4 => usize::from(be16(p, 2).unwrap_or(0)),
            _ => 40 + usize::from(be16(p, 4).unwrap_or(0)),
        }
        .min(p.len());
        let end = &self.ends[e];
        let clamped = clamp_mss(frame, end.cfg.spec.mss(ip.dst.is_ipv6()));
        let p = clamped.as_deref().map_or(p, |f| &f[link.payload..]);
        let datagram = &p[..len];
        let client = end
            .cfg
            .clients
            .and_then(|c| index_in(ip.src, c).or_else(|| index_in(ip.dst, c)))
            .unwrap_or(0);
        let teid = end.cfg.spec.teid.wrapping_add(client);
        let mut gtp = Vec::with_capacity(16 + datagram.len());
        match end.cfg.spec.qfi {
            Some(q) => {
                gtp.extend([0x34, 0xff, 0, 0]);
                gtp.extend(teid.to_be_bytes());
                gtp.extend([0, 0, 0, 0x85, 1, u8::from(end.cfg.uplink) << 4, q, 0]);
            }
            None => {
                gtp.extend([0x30, 0xff, 0, 0]);
                gtp.extend(teid.to_be_bytes());
            }
        }
        let glen = (gtp.len() - 8 + datagram.len()) as u16;
        gtp[2..4].copy_from_slice(&glen.to_be_bytes());
        gtp.extend_from_slice(datagram);
        self.ip_id = self.ip_id.wrapping_add(1);
        let id = self.ip_id;
        let end = &mut self.ends[e];
        let out = outer_udp(end, MacAddr([0; 6]), &gtp, id);
        self.stats.encapsulated += 1;
        match end.gateway_mac {
            Some(mac) => {
                let mut out = out;
                out[..6].copy_from_slice(&mac.0);
                self.inner.send(&out)?;
            }
            None => {
                if end.pending.len() >= PENDING {
                    end.pending.pop_front();
                    self.stats.unresolved += 1;
                }
                end.pending.push_back(out);
                self.resolve(e)?;
            }
        }
        Ok(true)
    }

    /// Asks for the outer gateway's MAC, at most every [`RESOLVE_EVERY`].
    fn resolve(&mut self, e: usize) -> std::result::Result<(), SinkError> {
        let end = &mut self.ends[e];
        if end.gateway_mac.is_some() || end.asked.is_some_and(|t| t.elapsed() < RESOLVE_EVERY) {
            return Ok(());
        }
        end.asked = Some(Instant::now());
        let spec = &end.cfg.spec;
        let frame = match (spec.local, spec.gateway()) {
            (IpAddr::V4(l), IpAddr::V4(g)) => wire::arp_frame(
                MacAddr([0xff; 6]),
                spec.vlan,
                1,
                end.mac,
                l,
                MacAddr([0; 6]),
                g,
            ),
            (IpAddr::V6(l), IpAddr::V6(g)) => wire::ndp_solicit(end.mac, spec.vlan, l, g),
            _ => return Ok(()),
        };
        self.inner.send(&frame)
    }

    /// Handles a frame from the network: true with `buf` holding a frame
    /// for the engine, false when it was the port's own business.
    fn handle_network(&mut self, buf: &mut Vec<u8>) -> std::result::Result<bool, SinkError> {
        let Some(link) = wire::parse_link(buf) else {
            return Ok(true);
        };
        let p = &buf[link.payload..];
        match link.ethertype {
            ETHERTYPE_ARP => {
                let Some(a) = wire::parse_arp(p) else {
                    return Ok(true);
                };
                let Some(e) = self.ends.iter().position(|e| {
                    e.cfg.spec.local == IpAddr::V4(a.target_ip)
                        || e.cfg.spec.gateway() == IpAddr::V4(a.sender_ip)
                }) else {
                    return Ok(true);
                };
                self.learn(e, a.sender_ip.into(), a.sender_mac)?;
                if a.op == 1 && self.ends[e].cfg.spec.local == IpAddr::V4(a.target_ip) {
                    let end = &self.ends[e];
                    let reply = wire::arp_frame(
                        a.sender_mac,
                        link.vlan,
                        2,
                        end.mac,
                        a.target_ip,
                        a.sender_mac,
                        a.sender_ip,
                    );
                    self.inner.send(&reply)?;
                }
                Ok(false)
            }
            ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => {
                let Some(ip) = wire::parse_ip(p, false) else {
                    return Ok(true);
                };
                let Some(e) = self.ends.iter().position(|e| {
                    e.cfg.spec.local == ip.dst
                        || (ip.dst.is_multicast() && e.cfg.spec.local.is_ipv6())
                }) else {
                    return Ok(true);
                };
                if ip.proto == crate::net::IPPROTO_ICMPV6 {
                    if let Some(n) = wire::parse_ndp(&ip) {
                        let local = self.ends[e].cfg.spec.local;
                        if let Some(mac) = n.lladdr {
                            if n.kind == wire::NDP_ADVERT || n.target == local {
                                self.learn(
                                    e,
                                    if n.kind == wire::NDP_ADVERT {
                                        n.target
                                    } else {
                                        ip.src
                                    },
                                    mac,
                                )?;
                            }
                        }
                        if n.kind == wire::NDP_SOLICIT && n.target == local {
                            let end = &self.ends[e];
                            let path = Path {
                                src_mac: end.mac,
                                dst_mac: n.lladdr.unwrap_or(link.src),
                                vlan: link.vlan,
                                src: local,
                                dst: ip.src,
                            };
                            if let Some(f) = wire::ndp_advert(&path) {
                                self.inner.send(&f)?;
                            }
                        }
                        return Ok(false);
                    }
                    return Ok(ip.dst != self.ends[e].cfg.spec.local);
                }
                if ip.dst != self.ends[e].cfg.spec.local {
                    return Ok(true);
                }
                if ip.proto != IPPROTO_UDP {
                    return Ok(true);
                }
                let Some(d) = wire::parse_udp(&ip, false) else {
                    return Ok(true);
                };
                if d.dport != GTPU_PORT {
                    return Ok(true);
                }
                let Some(inner) = gpdu(d.data) else {
                    self.stats.ignored += 1;
                    return Ok(false);
                };
                let et = if inner[0] >> 4 == 4 {
                    ETHERTYPE_IPV4
                } else {
                    ETHERTYPE_IPV6
                };
                let end = &self.ends[e].cfg;
                let mut f = Vec::with_capacity(18 + inner.len());
                wire::push_link(&mut f, end.host_mac, TUNNEL_GATEWAY_MAC, end.host_vlan, et);
                f.extend_from_slice(inner);
                if let Some(c) = clamp_mss(&f, end.spec.mss(et == ETHERTYPE_IPV6)) {
                    f = c;
                }
                *buf = wire::pad(f);
                self.stats.decapsulated += 1;
                Ok(true)
            }
            _ => Ok(true),
        }
    }

    /// Notes the outer gateway's MAC and sends what waited for it.
    fn learn(&mut self, e: usize, ip: IpAddr, mac: MacAddr) -> std::result::Result<(), SinkError> {
        let end = &mut self.ends[e];
        if end.cfg.spec.gateway() != ip {
            return Ok(());
        }
        end.gateway_mac = Some(mac);
        let pending: Vec<Vec<u8>> = end.pending.drain(..).collect();
        for mut f in pending {
            f[..6].copy_from_slice(&mac.0);
            self.inner.send(&f)?;
        }
        Ok(())
    }
}

/// A copy of `frame` with the MSS option lowered to `mss`, when it is a TCP
/// SYN asking for more.
fn clamp_mss(frame: &[u8], mss: u16) -> Option<Vec<u8>> {
    let layers = crate::net::parse(frame)?;
    let ip = layers.ip.as_ref()?;
    let (crate::net::IPPROTO_TCP, at) = ip.l4? else {
        return None;
    };
    if frame.get(at + 13)? & 0x02 == 0 {
        return None;
    }
    let end = at + usize::from(frame.get(at + 12)? >> 4) * 4;
    let mut o = at + 20;
    while o < end.min(frame.len()) {
        match frame[o] {
            0 => break,
            1 => o += 1,
            kind => {
                let len = usize::from(*frame.get(o + 1)?);
                if len < 2 {
                    return None;
                }
                if kind == 2 && len == 4 {
                    let old = be16(frame, o + 2)?;
                    if old <= mss {
                        return None;
                    }
                    let mut out = frame.to_vec();
                    layers.write(&mut out, o + 2..o + 4, &mss.to_be_bytes());
                    return Some(out);
                }
                o += len;
            }
        }
    }
    None
}

/// The IP datagram a GTP-U G-PDU carries, if `g` is one.
fn gpdu(g: &[u8]) -> Option<&[u8]> {
    let flags = *g.first()?;
    if flags >> 5 != 1 || flags & 0x10 == 0 || *g.get(1)? != 0xff {
        return None;
    }
    let total = 8 + usize::from(be16(g, 2)?);
    let mut o = 8;
    if flags & 0x07 != 0 {
        let mut next = *g.get(11)?;
        o = 12;
        while next != 0 {
            let len = usize::from(*g.get(o)?) * 4;
            if len == 0 {
                return None;
            }
            next = *g.get(o + len - 1)?;
            o += len;
        }
    }
    let inner = g.get(o..total.min(g.len()))?;
    matches!(inner.first()? >> 4, 4 | 6).then_some(inner)
}

/// The outer frame of a GTP-U packet `gtp` from `end`, to `dst_mac`.
fn outer_udp(end: &End, dst_mac: MacAddr, gtp: &[u8], id: u16) -> Vec<u8> {
    let spec = &end.cfg.spec;
    let path = Path {
        src_mac: end.mac,
        dst_mac,
        vlan: spec.vlan,
        src: spec.local,
        dst: spec.remote,
    };
    let udp_len = 8 + gtp.len();
    let mut f = Vec::with_capacity(18 + 40 + udp_len);
    wire::push_ip(&mut f, &path, IPPROTO_UDP, udp_len, id, 64);
    let start = f.len();
    f.extend_from_slice(&GTPU_PORT.to_be_bytes());
    f.extend_from_slice(&GTPU_PORT.to_be_bytes());
    f.extend_from_slice(&(udp_len as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(gtp);
    // IPv4 may leave the UDP checksum out, as GTP-U endpoints do; IPv6 may not.
    if spec.local.is_ipv6() {
        let mut sum = wire::checksum(
            &f[start..],
            wire::pseudo_sum(spec.local, spec.remote, IPPROTO_UDP, udp_len),
        );
        if sum == 0 {
            sum = 0xffff;
        }
        f[start + 6..start + 8].copy_from_slice(&sum.to_be_bytes());
    }
    wire::pad(f)
}

impl PacketPort for GtpuPort {
    fn send(&mut self, frame: &[u8]) -> std::result::Result<(), SinkError> {
        if self.answer_engine(frame) {
            return Ok(());
        }
        if self.encapsulate(frame)? {
            return Ok(());
        }
        self.inner.send(frame)
    }

    fn recv(&mut self, buf: &mut Vec<u8>) -> std::result::Result<bool, SinkError> {
        if let Some(f) = self.to_engine.pop_front() {
            *buf = f;
            return Ok(true);
        }
        for _ in 0..RX_BATCH {
            if !self.inner.recv(buf)? {
                break;
            }
            if self.handle_network(buf)? {
                return Ok(true);
            }
        }
        // Keep asking for gateways that frames wait for.
        for e in 0..self.ends.len() {
            if !self.ends[e].pending.is_empty() {
                self.resolve(e)?;
            }
        }
        Ok(false)
    }

    fn flush(&mut self) -> std::result::Result<(), SinkError> {
        self.inner.flush()
    }

    fn describe(&self) -> Option<String> {
        let tunnels: Vec<String> = self
            .ends
            .iter()
            .map(|e| {
                let s = &e.cfg.spec;
                let n = e.cfg.clients.map_or(1, |c| c.1);
                let teids = if n > 1 {
                    format!("TEIDs {}-{}", s.teid, s.teid.wrapping_add(n - 1))
                } else {
                    format!("TEID {}", s.teid)
                };
                format!("GTP-U {} -> {} ({teids})", s.local, s.remote)
            })
            .collect();
        let what = tunnels.join(", ");
        Some(match self.inner.describe() {
            Some(d) => format!("{d}, {what}"),
            None => what,
        })
    }

    // No split: the network spreads tunnels over receive queues by their
    // outer addresses, not by the clients inside, so the workers share the
    // port and one reader passes each frame to the worker of its client.

    fn rx_dropped(&mut self) -> Option<u64> {
        self.inner.rx_dropped()
    }

    fn drops(&mut self) -> crate::DropCounters {
        self.inner.drops()
    }

    fn impairments(&mut self) -> Option<crate::PortImpairStats> {
        self.inner.impairments()
    }
}

/// Wraps `port` in a [`GtpuPort`] when it has tunnel ends.
pub fn gtpu_port(port: Box<dyn PacketPort>, ends: Vec<GtpuEnd>) -> Box<dyn PacketPort> {
    if ends.is_empty() {
        port
    } else {
        Box::new(GtpuPort::new(port, ends))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::memory_ports;
    use crate::{
        TcpClientConfig, TcpConfig, TcpEndpoint, TcpEngine, TcpJob, TcpMessage, TcpOptions,
        TcpProgram, TcpRole, TcpRunConfig, TcpServerConfig, TcpTemplate,
    };

    /// Keeps a copy of every frame the port sends.
    struct Tap(Box<dyn PacketPort>, Arc<Mutex<Vec<Vec<u8>>>>);

    impl PacketPort for Tap {
        fn send(&mut self, f: &[u8]) -> std::result::Result<(), SinkError> {
            self.1.lock().unwrap().push(f.to_vec());
            self.0.send(f)
        }
        fn recv(&mut self, buf: &mut Vec<u8>) -> std::result::Result<bool, SinkError> {
            self.0.recv(buf)
        }
    }

    fn run(v6: bool, qfi: bool) {
        let (a, b) = memory_ports();
        let wire = Arc::new(Mutex::new(Vec::new()));
        let ip = |s4: &str, s6: &str| -> IpAddr { if v6 { s6 } else { s4 }.parse().unwrap() };
        let (client_ip, server_ip) = (ip("10.0.0.10", "fd00::10"), ip("10.0.1.2", "fd00:1::2"));
        let (enb, upf) = (
            ip("192.0.2.1", "2001:db8::1"),
            ip("192.0.2.2", "2001:db8::2"),
        );
        let program = TcpProgram::new(
            80,
            vec![
                TcpMessage::new(TcpRole::Client, "ping"),
                TcpMessage::new(TcpRole::Server, "pong"),
            ],
        );
        let mut cep = TcpEndpoint::new(0, "02:00:00:00:00:01".parse().unwrap(), client_ip);
        cep.ip_count = 3;
        cep.gateway = Some(ip("10.0.0.1", "fd00::1"));
        let mut sep = TcpEndpoint::new(1, "02:00:00:00:00:02".parse().unwrap(), server_ip);
        sep.gateway = Some(ip("10.0.1.1", "fd00:1::1"));
        let mut client = TcpClientConfig::new(cep);
        client.connections = 9;
        client.cps = 300.0;
        let engine = TcpEngine::new(TcpConfig {
            templates: vec![TcpTemplate::new(
                Arc::new(program),
                std::net::SocketAddr::new(server_ip, 80),
            )],
            client: Some(client),
            server: Some(TcpServerConfig::new(sep)),
            options: TcpOptions::default(),
        })
        .unwrap();
        let spec = |local, remote| GtpuSpec {
            local,
            remote,
            gateway: None,
            teid: 1000,
            qfi: qfi.then_some(9),
            vlan: None,
            mac: None,
            mtu: 1500,
        };
        let end = |spec, hosts, mac: &str, uplink| GtpuEnd {
            spec,
            hosts,
            clients: Some((client_ip, 3)),
            host_mac: mac.parse().unwrap(),
            host_vlan: None,
            uplink,
        };
        let ports: Vec<Box<dyn PacketPort>> = vec![
            gtpu_port(
                Box::new(Tap(Box::new(a), wire.clone())),
                vec![end(
                    spec(enb, upf),
                    (client_ip, 3),
                    "02:00:00:00:00:01",
                    true,
                )],
            ),
            gtpu_port(
                Box::new(b),
                vec![end(
                    spec(upf, enb),
                    (server_ip, 1),
                    "02:00:00:00:00:02",
                    false,
                )],
            ),
        ];
        let config = TcpRunConfig {
            duration: Some(Duration::from_secs(10)),
            ..Default::default()
        };
        let stats = TcpJob::spawn(engine, ports, config)
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(stats.client.completed, 9, "{stats:?}");
        let wire = wire.lock().unwrap();
        let mut teids = std::collections::BTreeSet::new();
        let mut gtp = 0;
        for f in wire.iter() {
            let l = crate::net::parse(f).unwrap();
            if let Some(t) = l.tunnels.first() {
                gtp += 1;
                assert_eq!(t.ip.src.len(), if v6 { 16 } else { 4 });
                teids.insert(u32::from_be_bytes(
                    f[t.key.clone().unwrap()].try_into().unwrap(),
                ));
                let inner = l.ip.unwrap();
                assert_eq!(f[inner.src].len(), if v6 { 16 } else { 4 });
                #[cfg(feature = "build")]
                {
                    let d = ferotrx_packet::decode(1, f);
                    assert!(d.problems.is_empty(), "{:?}", d.problems);
                }
            }
        }
        assert!(gtp > 9 * 3, "{gtp} GTP-U frames");
        assert_eq!(teids.into_iter().collect::<Vec<_>>(), [1000, 1001, 1002]);
    }

    #[test]
    fn tcp_runs_through_gtpu_with_a_teid_per_client() {
        run(false, false);
        run(false, true);
        run(true, true);
    }

    #[test]
    fn spec_text_round_trips() {
        let s: GtpuSpec = "local=10.1.0.1, remote=10.2.0.1,teid=0x10,qfi=9,vlan=7"
            .parse()
            .unwrap();
        assert_eq!(
            s.to_string(),
            "local=10.1.0.1,remote=10.2.0.1,teid=16,qfi=9,vlan=7"
        );
        assert_eq!(s.mac().to_string(), "02:00:0a:01:00:01");
        for bad in [
            "local=10.1.0.1",
            "remote=10.1.0.1",
            "local=10.1.0.1,remote=fd00::1",
            "local=10.1.0.1,remote=10.1.0.2,qfi=64",
            "local=10.1.0.1,remote=10.1.0.2,nope=1",
            "local=10.1.0.1,remote=10.1.0.2,teid=0x100000000",
        ] {
            assert!(bad.parse::<GtpuSpec>().is_err(), "{bad}");
        }
    }
}
