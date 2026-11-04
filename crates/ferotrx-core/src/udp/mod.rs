//! Stateful UDP: request/response transactions, such as DNS lookups.
//!
//! A stateless replay of UDP sends the captured datagrams one way. Here both
//! ends are emulated instead, as for TCP: the client starts transactions at a
//! set rate, each from its own source address and port, waits for the
//! answers, asks again when they are late, and counts what came back; the
//! server answers on the templates' ports.
//!
//! * [`UdpProgram`] is a session from a capture (or written out): the
//!   datagrams each end sends, in order, with the gaps between them.
//! * [`DnsWorkload`] is DNS: the queries a client sends in turn, and the
//!   records (and error codes) a small authoritative server answers with.
//! * [`UdpApp`] says which a template plays: a replay, DNS, or NTP.
//! * [`UdpTemplate`] is a kind of transaction with its own weight, rate,
//!   limits and think time; a run mixes them like TCP templates.
//! * [`UdpEngine`] emulates the hosts (ARP, neighbor discovery, ping) and
//!   plays the transactions: answers are matched to their requests (by DNS
//!   id and question, NTP timestamp, or session), late ones are asked for
//!   again, and the counters say what was sent, answered, timed out and
//!   unmatched, with response times.
//! * [`UdpJob`] runs it on [`PacketPort`](crate::PacketPort)s.

pub(crate) mod dns;
mod engine;
pub(crate) mod ntp;
#[cfg(feature = "profile")]
mod profile;
mod program;

pub use dns::{DnsData, DnsQuery, DnsRecord, DnsType, DnsWorkload, Rcode};
pub use engine::{
    UdpApp, UdpClientConfig, UdpConfig, UdpEndpoint, UdpEngine, UdpOptions, UdpServerConfig,
    UdpSideStats, UdpStats, UdpTemplate, UdpTemplateStats,
};
#[cfg(feature = "profile")]
pub use profile::{UdpProfile, UdpSource, UdpTemplateSpec};
pub use program::{UdpFlow, UdpMessage, UdpProgram, UdpRole};

/// A UDP run on its own thread; see [`PortJob`](crate::PortJob).
pub type UdpJob = crate::PortJob<UdpStats>;
