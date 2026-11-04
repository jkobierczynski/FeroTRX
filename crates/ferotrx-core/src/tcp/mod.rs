//! Stateful TCP: replaying TCP sessions as real connections.
//!
//! A stateless replay sends the captured packets as they are, which a NAT
//! router or a stateful firewall drops or rewrites: the sequence numbers do not
//! match any connection it knows, and nobody answers. Here both ends of a
//! session are emulated instead, like TRex's advanced stateful mode:
//!
//! * [`TcpProgram`] turns a session from a capture into the messages each end
//!   sends, in order.
//! * [`TcpTemplate`] is a kind of connection: a program, the servers clients
//!   connect to and the port servers accept it on. A run mixes templates by
//!   weight, like TRex ASTF templates.
//! * [`TcpEngine`] emulates the client and server hosts. It answers ARP and
//!   ping, opens connections at a set rate with real handshakes, tracks
//!   sequence and acknowledgement numbers, retransmits lost segments, plays
//!   the program and closes with FINs. It negotiates window scaling,
//!   timestamps (with PAWS) and SACK, measures round-trip times for its
//!   retransmission timeout, and does Reno/NewReno congestion control with
//!   SACK-based recovery; `docs/tcp-engine.md` has the details. A router in between can rewrite
//!   addresses and ports as it likes: each end only talks to what it sees.
//! * [`run_tcp`] and [`TcpJob`] run the engine on [`PacketPort`]s, ports that
//!   send and receive. `ferotrx-io` opens them on interfaces.
//!
//! The client and the server can run in one engine (two ports, or one port
//! with two VLANs) or in two engines on different machines.

pub(crate) mod engine;
pub(crate) mod hosts;
#[cfg(feature = "profile")]
pub(crate) mod profile;
pub(crate) mod program;
mod run;
pub(crate) mod wire;

pub use engine::{
    TcpClientConfig, TcpConfig, TcpEndpoint, TcpEngine, TcpOptions, TcpServerConfig, TcpSideStats,
    TcpStats, TcpTemplate, TcpTemplateStats,
};
#[cfg(feature = "profile")]
pub use profile::{
    parse_connect_addr, parse_groups, parse_ip_prefix, parse_port_range, parse_size, TcpHostSpec,
    TcpProfile, TcpSource, TcpTemplateSpec,
};
pub use program::{TcpFlow, TcpMessage, TcpProgram, TcpRole};
pub use run::{
    memory_ports, run_engine, run_tcp, split_port, split_ports, MemoryPort, PacketPort, PortEngine,
    PortJob, TcpJob, TcpRunConfig,
};
