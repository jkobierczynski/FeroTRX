//! Core library of FeroTRX, a traffic replay tool.
//!
//! The library is the single engine behind the `ferotrx` command line tool
//! and any other program that wants to replay traffic. Packets flow through a
//! pipeline:
//!
//! ```text
//! PacketSource -> Transform... -> Pacer -> PacketSink
//! ```
//!
//! * [`Capture`] loads a pcap or pcapng file, or builds packets from text
//!   descriptions (feature `build`); [`CaptureSource`] plays it in loops.
//! * [`Transform`]s change packets on the way; [`Rewrite`] has the built-in ones
//!   (MAC, IP and port rewrites, VLAN tags, checksum repair), and
//!   [`FieldEngine`] changes fields from packet to packet (address, port, VLAN
//!   and payload ranges, packet sizes), keeping checksums and lengths right.
//! * [`Rate`] and [`Pacer`] decide when each packet should leave.
//! * A [`Stream`] ties a source, its transforms and a rate together, and [`run`]
//!   plays several streams at once into one [`PacketSink`].
//! * A [`Profile`] describes streams in a TOML file (feature `profile`, on by default).
//! * [`replay`] is the one-capture shortcut.
//! * [`Job`] runs streams on a background thread that can be watched and stopped;
//!   the CLI and the `ferotrx-ctl` control server both run traffic this way.
//! * Stateful TCP: [`TcpProgram`] turns a TCP session in a capture into what
//!   each end sends, and [`TcpEngine`] replays it over real connections, as an
//!   emulated client and server with handshakes, sequence and acknowledgement
//!   tracking and retransmits, so it passes NAT routers and stateful firewalls.
//!   [`TcpJob`] runs it on [`PacketPort`]s, ports that send and receive.
//! * Stateful UDP: [`UdpEngine`] plays request/response transactions between
//!   emulated clients and servers, with matching, timeouts and retries:
//!   sessions from captures ([`UdpProgram`]), DNS lookups ([`DnsWorkload`])
//!   and NTP. [`UdpJob`] runs it on ports.
//! * Loss and latency: a stream made with [`Stream::with_latency`] carries a
//!   [`Signature`] (flow, sequence number, send time) in every packet; a
//!   [`PacketReceiver`] on the far side counts arrivals into [`RxStats`]:
//!   loss, duplicates, reordering, and latency with jitter and percentiles.
//!   [`Job::spawn_with_rx`] sends and receives together, and [`FlowReport`]
//!   compares the two.
//!
//! Sinks that talk to real interfaces or files live in the `ferotrx-io` crate,
//! so this crate has no platform specific code. [`SendSettings`] names the
//! sender a run asks for (libpcap/Npcap, AF_XDP or DPDK, see [`Backend`]);
//! `ferotrx-io` implements them.
//!
//! ```
//! use ferotrx_core::{Capture, Packet, Rate, ReplayConfig, VecSink, replay};
//! use std::time::Duration;
//!
//! let capture = Capture::new(1, vec![
//!     Packet::new(Duration::ZERO, vec![0u8; 60]),
//!     Packet::new(Duration::from_millis(1), vec![0u8; 60]),
//! ]);
//! let mut sink = VecSink::default();
//! let config = ReplayConfig { rate: Rate::TopSpeed, loops: 3, ..Default::default() };
//! let stats = replay(&capture, &mut sink, &config).unwrap();
//! assert_eq!(stats.packets, 6);
//! assert_eq!(sink.packets.len(), 6);
//! ```
//!
//! Two streams with rewrites, run together:
//!
//! ```
//! use ferotrx_core::*;
//! use std::time::Duration;
//!
//! let capture = Capture::new(1, vec![Packet::new(Duration::ZERO, vec![0u8; 60])]);
//! let mut streams = [
//!     Stream::new("a", CaptureSource::new(&capture).loops(5))
//!         .with_rate(Rate::TopSpeed)
//!         .with_transform("vlan_push=10".parse::<Rewrite>().unwrap()),
//!     Stream::new("b", CaptureSource::new(&capture).loops(3))
//!         .with_rate(Rate::TopSpeed),
//! ];
//! let mut sink = VecSink::default();
//! let stats = run(&mut streams, &mut sink, &RunConfig::default()).unwrap();
//! assert_eq!(stats.total.packets, 8);
//! assert_eq!(stats.streams[0].bytes, 5 * 64);
//! ```

mod capture;
mod error;
mod field_engine;
mod job;
mod latency;
mod net;
mod pacer;
#[cfg(feature = "profile")]
mod profile;
mod replay;
mod send;
mod sink;
mod source;
mod stream;
mod tcp;
mod transform;
mod udp;

pub use capture::{Capture, Packet, LINKTYPE_ETHERNET};
pub use error::{Error, Result};
pub use field_engine::{FieldEngine, FieldVar, Side, VarField, VarOp};
pub use job::{Job, JobState, RxSettings, JOB_STATS_INTERVAL};
pub use latency::{
    wall_clock, FlowReport, FlowStats, LatencyStats, PacketReceiver, PortReceiver, RxConfig, RxJob,
    RxStats, Signature, SIGNATURE_LEN,
};
pub use net::{MacAddr, TPID_QINQ, TPID_VLAN};
pub use pacer::{parse_duration, Pacer, Rate};
#[cfg(feature = "profile")]
pub use profile::{Profile, StreamSource, StreamSpec, DEFAULT_INTERVAL};
pub use replay::{replay, replay_with_progress, ReplayConfig, ReplayStats};
pub use send::{Backend, SendSettings, XdpMode, DEFAULT_BATCH};
pub use sink::{NullSink, PacketSink, SinkError, VecSink};
pub use source::{CaptureSource, PacketSource};
pub use stream::{run, run_with_progress, RunConfig, RunStats, Stream};
pub use tcp::{
    memory_ports, run_engine, run_tcp, MemoryPort, PacketPort, PortEngine, PortJob,
    TcpClientConfig, TcpConfig, TcpEndpoint, TcpEngine, TcpFlow, TcpJob, TcpMessage, TcpOptions,
    TcpProgram, TcpRole, TcpRunConfig, TcpServerConfig, TcpSideStats, TcpStats, TcpTemplate,
    TcpTemplateStats,
};
#[cfg(feature = "profile")]
pub use tcp::{
    parse_connect_addr, parse_ip_prefix, parse_port_range, parse_size, TcpHostSpec, TcpProfile,
    TcpSource, TcpTemplateSpec,
};
pub use transform::{
    Field, FixChecksums, IpRewrite, MacRewrite, PortRewrite, Rewrite, Transform, VlanPop, VlanPush,
    VlanSet,
};
pub use udp::{
    DnsData, DnsQuery, DnsRecord, DnsType, DnsWorkload, Rcode, UdpApp, UdpClientConfig, UdpConfig,
    UdpEndpoint, UdpEngine, UdpFlow, UdpJob, UdpMessage, UdpOptions, UdpProgram, UdpRole,
    UdpServerConfig, UdpSideStats, UdpStats, UdpTemplate, UdpTemplateStats,
};
#[cfg(feature = "profile")]
pub use udp::{UdpProfile, UdpSource, UdpTemplateSpec};
