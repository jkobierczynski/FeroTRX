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
//! * [`Rate`] and [`Pacer`] decide when each packet should leave; a
//!   [`TrafficModel`] adds Poisson arrivals, bursts and ramps around the rate.
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
//! * Host emulation: [`HostEngine`] runs emulated hosts that get their
//!   addresses by DHCP, SLAAC or DHCPv6, announce them (gratuitous ARP,
//!   unsolicited neighbor advertisements), join multicast groups (IGMP, MLD)
//!   and can advertise IPv6 prefixes as routers; [`Hosted`] puts them in
//!   front of the TCP or UDP engine, so its client and server get their
//!   addresses that way.
//! * Loss and latency: a stream made with [`Stream::with_latency`] carries a
//!   [`Signature`] (flow, sequence number, send time) in every packet; a
//!   [`PacketReceiver`] on the far side counts arrivals into [`RxStats`]:
//!   loss, duplicates, reordering, and latency with jitter and percentiles.
//!   [`Job::spawn_with_rx`] sends and receives together, and [`FlowReport`]
//!   compares the two.
//! * Benchmarks: [`SizeMix`] gives packets sizes from a list or a mix such as
//!   IMIX, and [`run_benchmark`] runs RFC 2544-style tests (throughput by a
//!   binary search on the rate, latency, frame loss, back-to-back bursts) as
//!   trials of a [`TrialRunner`], such as [`JobTrialRunner`]; [`BenchReport`]
//!   holds the results and [`RunInfo`] what they were measured on.
//! * Regression tests: a [`scenario::Scenario`] lists checks (TCP, UDP or
//!   streams with a receiver) with expected outcomes, such as "completes",
//!   "is blocked" or `loss_pct < 1%`; [`scenario::run_scenario`] judges each
//!   and [`scenario::compare`] holds two runs against each other.
//! * Several cores: [`Stream::shard`] and [`Job::spawn_workers`] split
//!   streams packet by packet over worker threads; [`TcpConfig::split`],
//!   [`UdpConfig::split`], a [`FlowRouter`] and [`PortJob::spawn_workers`]
//!   split stateful runs by flow (`docs/multi-core.md`).
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

pub mod app;
mod bench;
pub mod bundle;
mod capture;
#[cfg(feature = "profile")]
pub mod check;
mod control;
mod drops;
mod error;
mod field_engine;
#[cfg(feature = "profile")]
pub mod fleet;
mod flows;
#[cfg(all(
    any(test, feature = "fuzzing"),
    feature = "profile",
    feature = "ssh",
    feature = "quic"
))]
#[doc(hidden)]
pub mod fuzzing;
mod host;
mod impair;
mod job;
mod latency;
mod link;
pub mod live;
mod net;
mod pacer;
#[cfg(feature = "profile")]
mod profile;
mod replay;
#[cfg(feature = "profile")]
pub mod scenario;
mod send;
mod sink;
mod size_mix;
mod source;
mod start;
mod stream;
mod tcp;
mod traffic;
mod transform;
mod udp;
mod workers;
mod y1564;

pub use app::{
    App, AppHandshake, AppProtocol, AppSession, AppStats, MediaReport, MediaStats, RequestCounts,
    Transport,
};
#[cfg(feature = "profile")]
pub use bench::BenchProfile;
pub use bench::{
    run_benchmark, utc_timestamp, BenchConfig, BenchReport, BenchTest, BurstResult, ConfigSummary,
    InterfaceDetails, JobTrialRunner, LatencyResult, LatencySummary, LossPoint, RunInfo,
    SizeReport, ThroughputResult, Trial, TrialRecord, TrialResult, TrialRunner,
};
pub use capture::{Capture, Packet, LINKTYPE_ETHERNET};
pub use drops::{DropCounters, LossReport};
pub use control::{ControlState, RunControl, StreamControl, MAX_MULTIPLIER};
pub use error::{Error, Result};
pub use field_engine::{FieldEngine, FieldVar, Side, VarField, VarOp};
pub use flows::{FlowRouter, Route};
#[cfg(feature = "profile")]
pub use host::{
    parse_ipv4_mode, parse_ipv6_mode, parse_pool, parse_prefix6, HostProfile, HostSpec,
};
pub use host::{
    AddressSource, Addressing, DhcpLease, DhcpServerConfig, DhcpServerCounters, DhcpServerStatus,
    Dhcpv6ServerConfig, Emulation, EndpointConfig, EndpointHosts, GroupStatus, HostAddress,
    HostConfig, HostCounters, HostEngine, HostOptions, HostState, HostStats, HostStatus, Hosted,
    HostedStats, Ipv4Mode, Ipv6Mode, RouterConfig,
};
pub use impair::{
    impair_port, parse_bit_rate, run_bridge, BridgeConfig, BridgeStats, ImpairMonitor, ImpairPort,
    ImpairSpec, ImpairStats, Impairer, JitterDist, MtuAction, PortImpair, PortImpairStats,
    DEFAULT_IMPAIR_LIMIT,
};
pub use job::{Job, JobState, RxSettings, JOB_STATS_INTERVAL};
pub use latency::{
    signed_len, wall_clock, FlowReport, FlowStats, IntervalStats, LatencyStats, PacketReceiver,
    PortReceiver, RxConfig, RxJob, RxStats, Signature, SIGNATURE_LEN,
};
pub use link::{
    describe_link, IpPrefix, IpRange, LinkSettings, NeighborPort, NeighborStats, SetMacs,
    RESOLVE_RETRY, RESOLVE_TIMEOUT,
};
pub use live::{
    CaptureCounters, CaptureDirection, CaptureFiles, CaptureJob, CaptureJobConfig, CaptureOptions,
    CaptureRead, Frame, FrameSource, PcapStreamWriter, PcapngWriter, Rotate, SourceCounters,
};
pub use net::{MacAddr, TPID_QINQ, TPID_VLAN};
pub use pacer::{parse_duration, Pacer, Rate, RateSpec, WIRE_OVERHEAD};
#[cfg(feature = "profile")]
pub use profile::{
    check_format, parse_line_rate, parse_model, Profile, StreamSource, StreamSpec,
    DEFAULT_INTERVAL, FORMAT_VERSION,
};
pub use replay::{replay, replay_with_progress, ReplayConfig, ReplayStats};
pub use send::{Backend, SendSettings, XdpMode, DEFAULT_BATCH, MAX_WORKERS};
pub use sink::{share_sink, NullSink, PacketSink, SinkError, VecSink};
pub use size_mix::{SizeMix, FCS_LEN, L1_OVERHEAD, RFC2544_SIZES};
pub use source::{CaptureSource, PacketSource};
pub use start::{from_unix_seconds, unix_seconds, wait_until};
pub use stream::{run, run_with_progress, MultiBurst, RunConfig, RunStats, Stream};
pub use tcp::{
    memory_ports, parse_size, run_engine, run_tcp, split_port, split_ports, CcAck, CcWindow,
    Congestion, CongestionController, Cubic, MemoryPort, NewReno, PacketPort, PortEngine, PortJob,
    TcpClientConfig, TcpConfig, TcpEndpoint, TcpEngine, TcpFlow, TcpJob, TcpMessage, TcpOptions,
    TcpProgram, TcpRole, TcpRunConfig, TcpServerConfig, TcpSideStats, TcpStats, TcpTemplate,
    TcpTemplateStats,
};
#[cfg(feature = "profile")]
pub use tcp::{
    parse_connect_addr, parse_groups, parse_ip_prefix, parse_port_range, TcpHostSpec, TcpProfile,
    TcpSource, TcpTemplateSpec,
};
pub use traffic::{parse_shape_point, Arrivals, Schedule, ShapePoint, TrafficModel};
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
pub use workers::{merge_all, share, worker_seed, MergeStats};
#[cfg(feature = "profile")]
pub use y1564::Y1564Profile;
pub use y1564::{
    run_y1564, Acceptance, Color, FlowRecord, FlowResult, IntervalRecord, JobServiceRunner,
    ServiceFrames, ServiceResult, ServiceRunner, ServiceSpec, ServiceSummary, ServiceVerdict,
    StepFlow, StepKind, StepRecord, Y1564Config, Y1564Report, Y1564Step, Y1564Summary, Y1564Test,
};
