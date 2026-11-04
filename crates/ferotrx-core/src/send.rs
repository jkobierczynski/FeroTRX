//! Names and settings of the ways packets can leave a network interface.
//!
//! This is plain configuration data: the core library only describes which
//! sender a run asks for. The senders themselves (libpcap/Npcap, AF_XDP, DPDK)
//! live in the `ferotrx-io` crate, which turns [`SendSettings`] into a
//! [`PacketSink`](crate::PacketSink).

use std::fmt;
use std::str::FromStr;

use crate::{Error, Result};

/// How packets are put on the wire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Backend {
    /// libpcap on Linux and macOS, Npcap on Windows. Works everywhere; one
    /// system call per packet.
    #[default]
    Pcap,
    /// Linux AF_XDP sockets: packets are queued in shared memory rings and
    /// handed to the kernel in batches. Copy mode works on any interface,
    /// zero-copy needs driver support.
    AfXdp,
    /// DPDK: the NIC is driven from user space (a separately built feature).
    Dpdk,
}

impl Backend {
    /// Every backend, in the order they are documented.
    pub const ALL: [Backend; 3] = [Backend::Pcap, Backend::AfXdp, Backend::Dpdk];

    /// The name used on the command line, in profiles and over the control API.
    pub fn name(self) -> &'static str {
        match self {
            Backend::Pcap => "pcap",
            Backend::AfXdp => "af_xdp",
            Backend::Dpdk => "dpdk",
        }
    }
}

/// Parses `pcap` (also `npcap`), `af_xdp` (also `afxdp`, `af-xdp`, `xdp`) or `dpdk`.
impl FromStr for Backend {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "pcap" | "libpcap" | "npcap" => Ok(Backend::Pcap),
            "af_xdp" | "afxdp" | "af-xdp" | "xdp" => Ok(Backend::AfXdp),
            "dpdk" => Ok(Backend::Dpdk),
            _ => Err(Error::InvalidSpec(format!(
                "unknown backend '{s}' (use pcap, af_xdp or dpdk)"
            ))),
        }
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// How an AF_XDP socket attaches to the interface's queue.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum XdpMode {
    /// Try zero-copy and fall back to copy mode when the driver cannot do it.
    #[default]
    Auto,
    /// Copy mode (generic, SKB): works on every interface, including virtual
    /// NICs such as VirtualBox's, veth and bridges.
    Copy,
    /// Zero-copy: the NIC reads frames straight from the socket's memory.
    /// Fails unless the driver supports it.
    ZeroCopy,
}

impl XdpMode {
    pub fn name(self) -> &'static str {
        match self {
            XdpMode::Auto => "auto",
            XdpMode::Copy => "copy",
            XdpMode::ZeroCopy => "zerocopy",
        }
    }
}

/// Parses `auto`, `copy` (also `skb`, `generic`) or `zerocopy` (also `zc`).
impl FromStr for XdpMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(XdpMode::Auto),
            "copy" | "skb" | "generic" => Ok(XdpMode::Copy),
            "zerocopy" | "zero-copy" | "zero_copy" | "zc" => Ok(XdpMode::ZeroCopy),
            _ => Err(Error::InvalidSpec(format!(
                "unknown AF_XDP mode '{s}' (use auto, copy or zerocopy)"
            ))),
        }
    }
}

impl fmt::Display for XdpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Packets queued before they are handed to the kernel or NIC, when
/// [`SendSettings::batch`] is not set.
pub const DEFAULT_BATCH: u32 = 64;

/// Most worker threads one run can use.
pub const MAX_WORKERS: u16 = 64;

/// How to send on an interface. Every field is optional, so settings from
/// several places can be layered with [`SendSettings::or`]: the command line or
/// control request first, then the profile's `[output]` table, then the defaults.
///
/// ```
/// use ferotrx_core::{Backend, SendSettings, XdpMode};
///
/// let cli = SendSettings { backend: Some(Backend::AfXdp), ..Default::default() };
/// let profile = SendSettings { xdp_mode: Some(XdpMode::Copy), batch: Some(32), ..Default::default() };
/// let s = cli.or(&profile);
/// assert_eq!(s.backend(), Backend::AfXdp);
/// assert_eq!(s.xdp_mode(), XdpMode::Copy);
/// assert_eq!(s.batch(), 32);
/// assert_eq!(s.queue(), 0);
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SendSettings {
    /// The sender (default [`Backend::Pcap`]).
    pub backend: Option<Backend>,
    /// The interface's transmit queue (AF_XDP and DPDK; default 0).
    pub queue: Option<u16>,
    /// AF_XDP attach mode (default [`XdpMode::Auto`]).
    pub xdp_mode: Option<XdpMode>,
    /// Packets queued before they are handed over (AF_XDP and DPDK; default
    /// [`DEFAULT_BATCH`]). Paced streams hand over whatever is queued before
    /// each wait, so batching never delays a packet.
    pub batch: Option<u32>,
    /// Arguments for DPDK's EAL, e.g. `["-l", "0-1", "--no-huge", "-m", "512"]`.
    pub dpdk_args: Option<Vec<String>>,
    /// Engine threads (cores) the run is spread over (default 1). Streams
    /// are split packet by packet, stateful runs by flow; with AF_XDP each
    /// worker sends on its own queue, from `queue` up. See `docs/multi-core.md`.
    pub workers: Option<u16>,
}

impl SendSettings {
    /// Fills every field that is not set here from `fallback`.
    pub fn or(mut self, fallback: &SendSettings) -> SendSettings {
        self.backend = self.backend.or(fallback.backend);
        self.queue = self.queue.or(fallback.queue);
        self.xdp_mode = self.xdp_mode.or(fallback.xdp_mode);
        self.batch = self.batch.or(fallback.batch);
        if self.dpdk_args.is_none() {
            self.dpdk_args.clone_from(&fallback.dpdk_args);
        }
        self.workers = self.workers.or(fallback.workers);
        self
    }

    pub fn is_empty(&self) -> bool {
        *self == SendSettings::default()
    }

    pub fn backend(&self) -> Backend {
        self.backend.unwrap_or_default()
    }

    pub fn queue(&self) -> u16 {
        self.queue.unwrap_or(0)
    }

    pub fn xdp_mode(&self) -> XdpMode {
        self.xdp_mode.unwrap_or_default()
    }

    pub fn batch(&self) -> u32 {
        self.batch.unwrap_or(DEFAULT_BATCH).max(1)
    }

    pub fn dpdk_args(&self) -> &[String] {
        self.dpdk_args.as_deref().unwrap_or(&[])
    }

    /// Engine threads the run uses (default 1).
    pub fn workers(&self) -> usize {
        usize::from(self.workers.unwrap_or(1).max(1))
    }

    /// Checks the values that have limits.
    pub fn validate(&self) -> Result<()> {
        if let Some(b) = self.batch {
            if !(1..=4096).contains(&b) {
                return Err(Error::InvalidSpec(format!(
                    "batch must be between 1 and 4096, got {b}"
                )));
            }
        }
        if let Some(w) = self.workers {
            if !(1..=MAX_WORKERS).contains(&w) {
                return Err(Error::InvalidSpec(format!(
                    "workers must be between 1 and {MAX_WORKERS}, got {w}"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for b in Backend::ALL {
            assert_eq!(b.name().parse::<Backend>().unwrap(), b);
        }
        assert_eq!("AF-XDP".parse::<Backend>().unwrap(), Backend::AfXdp);
        assert_eq!("npcap".parse::<Backend>().unwrap(), Backend::Pcap);
        assert!("netmap".parse::<Backend>().is_err());
        for m in [XdpMode::Auto, XdpMode::Copy, XdpMode::ZeroCopy] {
            assert_eq!(m.to_string().parse::<XdpMode>().unwrap(), m);
        }
        assert_eq!("skb".parse::<XdpMode>().unwrap(), XdpMode::Copy);
    }

    #[test]
    fn layering_keeps_the_first_value() {
        let a = SendSettings {
            dpdk_args: Some(vec!["--no-huge".into()]),
            ..Default::default()
        };
        let b = SendSettings {
            backend: Some(Backend::Dpdk),
            dpdk_args: Some(vec!["-l".into(), "0".into()]),
            queue: Some(2),
            ..Default::default()
        };
        let s = a.or(&b);
        assert_eq!(s.backend(), Backend::Dpdk);
        assert_eq!(s.dpdk_args(), ["--no-huge"]);
        assert_eq!(s.queue(), 2);
        assert_eq!(s.batch(), DEFAULT_BATCH);
        assert!(SendSettings::default().is_empty());
        assert!(SendSettings {
            batch: Some(0),
            ..Default::default()
        }
        .validate()
        .is_err());
    }
}
