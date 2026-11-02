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
//!   (MAC, IP and port rewrites, VLAN tags, checksum repair).
//! * [`Rate`] and [`Pacer`] decide when each packet should leave.
//! * A [`Stream`] ties a source, its transforms and a rate together, and [`run`]
//!   plays several streams at once into one [`PacketSink`].
//! * A [`Profile`] describes streams in a TOML file (feature `profile`, on by default).
//! * [`replay`] is the one-capture shortcut.
//!
//! Sinks that talk to real interfaces or files live in the `ferotrx-io` crate,
//! so this crate has no platform specific code.
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
mod net;
mod pacer;
#[cfg(feature = "profile")]
mod profile;
mod replay;
mod sink;
mod source;
mod stream;
mod transform;

pub use capture::{Capture, Packet, LINKTYPE_ETHERNET};
pub use error::{Error, Result};
pub use net::{MacAddr, TPID_QINQ, TPID_VLAN};
pub use pacer::{parse_duration, Pacer, Rate};
#[cfg(feature = "profile")]
pub use profile::{Profile, StreamSource, StreamSpec, DEFAULT_INTERVAL};
pub use replay::{replay, replay_with_progress, ReplayConfig, ReplayStats};
pub use sink::{NullSink, PacketSink, SinkError, VecSink};
pub use source::{CaptureSource, PacketSource};
pub use stream::{run, run_with_progress, RunConfig, RunStats, Stream};
pub use transform::{
    Field, FixChecksums, IpRewrite, MacRewrite, PortRewrite, Rewrite, Transform, VlanPop, VlanPush,
    VlanSet,
};
