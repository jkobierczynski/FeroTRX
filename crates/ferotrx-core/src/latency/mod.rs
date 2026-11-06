//! Loss and latency: the receive side, like TRex's flow and latency statistics.
//!
//! * A stream marked with [`Stream::with_latency`](crate::Stream::with_latency)
//!   carries a [`Signature`] at the end of every packet's IP payload: its flow
//!   id, a sequence number and the send time, written just before the packet
//!   leaves. Lengths and checksums stay right, so packets pass routers, NAT
//!   and firewalls like any other.
//! * A [`PacketReceiver`] gets frames on the far side, and [`RxStats`] counts
//!   them per flow: packets, duplicates, reordering, sequence gaps, and
//!   latency (minimum, mean, maximum, jitter, percentiles).
//! * [`RxJob`] runs a receiver on its own thread; a [`Job`](crate::Job) can
//!   run one alongside its streams ([`Job::spawn_with_rx`](crate::Job::spawn_with_rx)),
//!   and [`FlowReport`] then puts what was sent next to what arrived.

mod rx;
mod signature;
mod stats;

pub use rx::{PacketReceiver, PortReceiver, RxConfig, RxJob};
pub(crate) use signature::{reserve, reserve_inside, stamp};
pub use signature::{signed_len, wall_clock, Signature, SIGNATURE_LEN};
pub use stats::{FlowReport, FlowStats, IntervalStats, LatencyStats, RxStats};
