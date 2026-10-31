//! Core library of FeroTRX, a traffic replay tool.
//!
//! The library is the single engine behind the `ferotrx` command line tool
//! and any other program that wants to replay traffic:
//!
//! * [`Capture`] loads a pcap or pcapng file into memory.
//! * [`Rate`] and [`Pacer`] decide when each packet should leave.
//! * [`replay`] drives a [`PacketSink`] at that pace and returns [`ReplayStats`].
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

mod capture;
mod error;
mod pacer;
mod replay;
mod sink;

pub use capture::{Capture, Packet, LINKTYPE_ETHERNET};
pub use error::{Error, Result};
pub use pacer::{Pacer, Rate};
pub use replay::{replay, replay_with_progress, ReplayConfig, ReplayStats};
pub use sink::{NullSink, PacketSink, SinkError, VecSink};
