//! UDP sessions from captures: the datagrams each end sends, in order.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use crate::tcp::program::ip_offset;
use crate::tcp::wire;
use crate::{Capture, Error, Result, TcpRole};

/// Which end of a UDP session: the client sends first, the server answers.
pub type UdpRole = TcpRole;

/// One datagram of a [`UdpProgram`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpMessage {
    pub from: UdpRole,
    pub data: Vec<u8>,
    /// How long after the previous datagram (from either end) this one went
    /// out in the capture; zero for the first. Played with
    /// [`UdpOptions::keep_timing`](super::UdpOptions::keep_timing).
    pub delay: Duration,
}

impl UdpMessage {
    pub fn new(from: UdpRole, data: impl Into<Vec<u8>>) -> Self {
        Self {
            from,
            data: data.into(),
            delay: Duration::ZERO,
        }
    }

    /// Sets the gap before the datagram.
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

/// A UDP session as both ends replay it: datagrams in order.
///
/// The client sends the first datagram; each end waits for the other's
/// datagrams before it sends its next ones. A datagram that does not come
/// in time is asked for again: the client sends its last datagram again,
/// and the server answers a repeated request with its answer again, as UDP
/// protocols do.
///
/// ```
/// use ferotrx_core::{UdpMessage, UdpProgram, UdpRole};
///
/// let p = UdpProgram::new(7, vec![
///     UdpMessage::new(UdpRole::Client, "ping"),
///     UdpMessage::new(UdpRole::Server, "pong"),
/// ]);
/// assert_eq!(p.requests(), 1);
/// assert!(p.validate().is_ok());
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpProgram {
    /// The client's address in the capture, if the program came from one.
    pub client: Option<SocketAddr>,
    /// The server's address in the capture, if the program came from one.
    pub server: Option<SocketAddr>,
    /// The port the server listens on.
    pub server_port: u16,
    pub messages: Vec<UdpMessage>,
}

impl UdpProgram {
    pub fn new(server_port: u16, messages: Vec<UdpMessage>) -> Self {
        Self {
            client: None,
            server: None,
            server_port,
            messages,
        }
    }

    /// Datagrams the client sends.
    pub fn requests(&self) -> usize {
        self.messages
            .iter()
            .filter(|m| m.from == UdpRole::Client)
            .count()
    }

    /// Checks that the program can be played: it has datagrams, and the
    /// client sends first (a server cannot know of a client before that).
    pub fn validate(&self) -> Result<()> {
        match self.messages.first() {
            None => Err(Error::Udp("the session has no datagrams".into())),
            Some(m) if m.from != UdpRole::Client => Err(Error::Udp(
                "the session starts with a datagram from the server; the client must send first"
                    .into(),
            )),
            _ => match self.messages.iter().find(|m| m.data.len() > MAX_DATAGRAM) {
                Some(m) => Err(Error::Udp(format!(
                    "a datagram of {} bytes is longer than UDP allows ({MAX_DATAGRAM})",
                    m.data.len()
                ))),
                None => Ok(()),
            },
        }
    }

    /// The UDP sessions in a capture, in the order they first appear: one
    /// for each pair of addresses and ports, both directions together.
    pub fn flows(capture: &Capture) -> Vec<UdpFlow> {
        udp_flows(capture).into_iter().map(|f| f.info).collect()
    }

    /// The program of one session in a capture: `flow` is its index in
    /// [`flows`](Self::flows), or `None` for the first one.
    pub fn from_capture(capture: &Capture, flow: Option<usize>) -> Result<Self> {
        let mut flows = udp_flows(capture);
        if flows.is_empty() {
            return Err(Error::Udp("the capture has no UDP datagrams".into()));
        }
        let n = flows.len();
        let i = flow.unwrap_or(0);
        if i >= n {
            return Err(Error::Udp(format!(
                "there is no UDP session {} in the capture; it has {n}",
                i + 1
            )));
        }
        Ok(flows.swap_remove(i).program)
    }
}

/// Longest UDP payload over IPv4.
pub(crate) const MAX_DATAGRAM: usize = 65507;

impl fmt::Display for UdpProgram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let (Some(c), Some(s)) = (self.client, self.server) {
            write!(f, "{c} -> {s}: ")?;
        } else {
            write!(f, "port {}: ", self.server_port)?;
        }
        let bytes = |r: UdpRole| -> usize {
            self.messages
                .iter()
                .filter(|m| m.from == r)
                .map(|m| m.data.len())
                .sum()
        };
        write!(
            f,
            "{} datagrams, {} bytes from the client, {} from the server",
            self.messages.len(),
            bytes(UdpRole::Client),
            bytes(UdpRole::Server)
        )
    }
}

/// A UDP session found in a capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpFlow {
    /// The end that sent the first datagram.
    pub client: SocketAddr,
    pub server: SocketAddr,
    /// Datagrams each way.
    pub client_datagrams: u64,
    pub server_datagrams: u64,
    pub client_bytes: u64,
    pub server_bytes: u64,
    /// When the first datagram was captured, from the start of the capture.
    pub start: Duration,
}

impl fmt::Display for UdpFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} -> {}: {} datagrams ({} bytes) from the client, {} ({} bytes) from the server",
            self.client,
            self.server,
            self.client_datagrams,
            self.client_bytes,
            self.server_datagrams,
            self.server_bytes
        )
    }
}

pub(crate) struct Flow {
    pub info: UdpFlow,
    pub program: UdpProgram,
}

/// The UDP sessions of a capture, with their programs.
pub(crate) fn udp_flows(capture: &Capture) -> Vec<Flow> {
    let first_ts = capture
        .packets
        .first()
        .map_or(Duration::ZERO, |p| p.timestamp);
    let mut flows: Vec<Flow> = Vec::new();
    let mut last_ts: Vec<Duration> = Vec::new();
    let mut index: HashMap<(SocketAddr, SocketAddr), usize> = HashMap::new();
    for p in &capture.packets {
        let Some(ip_at) = ip_offset(capture.linktype, &p.data) else {
            continue;
        };
        let Some(ip) = wire::parse_ip(&p.data[ip_at..], false) else {
            continue;
        };
        if ip.proto != 17 {
            continue;
        }
        let Some(d) = wire::parse_udp(&ip, false) else {
            continue;
        };
        let src = SocketAddr::new(ip.src, d.sport);
        let dst = SocketAddr::new(ip.dst, d.dport);
        let key = if src <= dst { (src, dst) } else { (dst, src) };
        let i = *index.entry(key).or_insert_with(|| {
            let mut program = UdpProgram::new(dst.port(), Vec::new());
            program.client = Some(src);
            program.server = Some(dst);
            flows.push(Flow {
                info: UdpFlow {
                    client: src,
                    server: dst,
                    client_datagrams: 0,
                    server_datagrams: 0,
                    client_bytes: 0,
                    server_bytes: 0,
                    start: p.timestamp.saturating_sub(first_ts),
                },
                program,
            });
            last_ts.push(p.timestamp);
            flows.len() - 1
        });
        let flow = &mut flows[i];
        let from = if src == flow.info.client {
            flow.info.client_datagrams += 1;
            flow.info.client_bytes += d.data.len() as u64;
            UdpRole::Client
        } else {
            flow.info.server_datagrams += 1;
            flow.info.server_bytes += d.data.len() as u64;
            UdpRole::Server
        };
        let delay = if flow.program.messages.is_empty() {
            Duration::ZERO
        } else {
            p.timestamp.saturating_sub(last_ts[i])
        };
        last_ts[i] = p.timestamp;
        flow.program
            .messages
            .push(UdpMessage::new(from, d.data).with_delay(delay));
    }
    flows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str) -> Capture {
        Capture::from_path(format!(
            "{}/../../examples/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn finds_sessions_with_both_directions() {
        let cap = sample("dns-lookups.pcap");
        let flows = UdpProgram::flows(&cap);
        assert_eq!(flows.len(), 8);
        assert_eq!(flows[0].client.to_string(), "10.1.2.40:41000");
        assert_eq!(flows[0].server.to_string(), "10.1.2.53:53");
        assert_eq!(
            (flows[0].client_datagrams, flows[0].server_datagrams),
            (1, 1)
        );
        let p = UdpProgram::from_capture(&cap, Some(2)).unwrap();
        assert_eq!(p.server_port, 53);
        assert_eq!(p.messages.len(), 2);
        assert_eq!(p.messages[1].from, UdpRole::Server);
        assert_eq!(p.messages[1].delay, Duration::from_millis(2));
        assert!(p.validate().is_ok());
        assert!(UdpProgram::from_capture(&cap, Some(8)).is_err());
        // Only queries: twenty one-datagram sessions.
        assert_eq!(UdpProgram::flows(&sample("dns.pcap")).len(), 20);
        assert!(UdpProgram::from_capture(&sample("web.pcap"), None).is_err());
    }

    #[test]
    fn the_client_sends_first() {
        let p = UdpProgram::new(9, vec![UdpMessage::new(UdpRole::Server, "x")]);
        assert!(p.validate().is_err());
        assert!(UdpProgram::new(9, vec![]).validate().is_err());
    }
}
