//! Stateful TCP: replaying TCP sessions as real connections.
//!
//! A stateless replay sends the captured packets as they are, which a NAT
//! router or a stateful firewall drops or rewrites: the sequence numbers do not
//! match any connection it knows, and nobody answers. Here both ends of a
//! session are emulated instead, like TRex's advanced stateful mode:
//!
//! * [`TcpProgram`] turns a session from a capture into the messages each end
//!   sends, in order.
//! * [`TcpEngine`] emulates the client and server hosts. It answers ARP and
//!   ping, opens connections at a set rate with real handshakes, tracks
//!   sequence and acknowledgement numbers, retransmits lost segments, plays
//!   the program and closes with FINs. A router in between can rewrite
//!   addresses and ports as it likes: each end only talks to what it sees.
//! * [`run_tcp`] and [`TcpJob`] run the engine on [`PacketPort`]s, ports that
//!   send and receive. `ferotrx-io` opens them on interfaces.
//!
//! The client and the server can run in one engine (two ports, or one port
//! with two VLANs) or in two engines on different machines.

mod engine;
#[cfg(feature = "profile")]
mod profile;
mod program;
mod run;
mod wire;

pub use engine::{
    TcpClientConfig, TcpConfig, TcpEndpoint, TcpEngine, TcpOptions, TcpServerConfig, TcpSideStats,
    TcpStats,
};
#[cfg(feature = "profile")]
pub use profile::{parse_ip_prefix, parse_port_range, TcpHostSpec, TcpProfile, TcpSource};
pub use program::{TcpFlow, TcpMessage, TcpProgram, TcpRole};
pub use run::{memory_ports, run_tcp, MemoryPort, PacketPort, TcpJob, TcpRunConfig};
