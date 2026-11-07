//! Packet sinks for FeroTRX.
//!
//! * [`PcapFileSink`] writes packets to a pcap file, stamped with the time they were sent.
//!   It works everywhere and needs no privileges.
//! * [`InterfaceSink`] sends packets on a network interface through libpcap
//!   (Linux, macOS) or Npcap (Windows). Enabled by the default `pcap` feature.
//! * `AfXdpSink` sends through a Linux AF_XDP socket, in batches. Enabled by
//!   the default `af-xdp` feature, on Linux only; needs no system libraries.
//! * `DpdkSink` sends through DPDK. Enabled by the `dpdk` feature, which needs
//!   DPDK installed to build.
//! * [`PcapPort`] sends and receives on an interface through libpcap/Npcap,
//!   for stateful TCP and UDP (`ferotrx_core::TcpEngine`); [`open_port`]
//!   opens one. `XdpPort` (Linux, AF_XDP with an XDP program of its own) and
//!   `DpdkPort` do the same faster; [`open_port_with`] opens any of the three.
//! * [`PcapReceiver`] receives on an interface with the kernel's timestamps,
//!   to measure loss and latency (`ferotrx_core::RxStats`); [`open_receiver`]
//!   opens one.
//! * [`open_capture`] captures on an interface with a BPF filter, as a
//!   `ferotrx_core::FrameSource`; [`FrameFilter`] applies a BPF filter to
//!   frames already captured.
//! * [`Output`] names one of these (or [`NullSink`]) and opens it; the CLI and
//!   the control server both choose outputs this way. Which interface sender is
//!   used is a [`Backend`], chosen with [`SendSettings`].

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ferotrx_core::{PacketSink, SinkError};

pub use ferotrx_core::{Backend, NullSink, SendSettings, XdpMode};

#[cfg(all(feature = "af-xdp", target_os = "linux"))]
mod afxdp;
#[cfg(all(feature = "af-xdp", target_os = "linux"))]
pub use afxdp::{AfXdpConfig, AfXdpSink};
#[cfg(all(feature = "af-xdp", target_os = "linux"))]
mod xdp;
#[cfg(all(feature = "af-xdp", target_os = "linux"))]
pub use xdp::{XdpPort, XdpPortConfig};

#[cfg(feature = "dpdk")]
mod dpdk;

mod capture;
mod host;
mod lab;
mod port;
#[cfg(windows)]
pub mod windows;
pub use capture::{check_filter, open_capture};
#[cfg(feature = "pcap")]
pub use capture::{FrameFilter, LiveCapture};
#[cfg(feature = "dpdk")]
pub use dpdk::{DpdkConfig, DpdkPort, DpdkSink};
pub use host::{describe_host, describe_interface, hostname, process_alive};
pub use lab::{
    lab_unavailable, remove_lab, Lab, LabConfig, LAB_INTERFACE, LAB_NAMESPACE, LAB_RECEIVER_IP,
    LAB_RECEIVER_IP6, LAB_RECEIVER_MAC, LAB_ROUTER_MAC,
};
pub use port::{interface_mac, open_port, open_port_with, open_receiver, PortSettings};
#[cfg(feature = "pcap")]
pub use port::{PcapPort, PcapReceiver};

/// Writes every packet to a pcap file with nanosecond timestamps of when it was sent.
pub struct PcapFileSink {
    writer: BufWriter<File>,
}

impl PcapFileSink {
    pub fn create(path: impl AsRef<Path>, linktype: u32) -> Result<Self, SinkError> {
        let mut writer = BufWriter::new(File::create(path)?);
        // Classic pcap global header, little endian, nanosecond timestamps.
        writer.write_all(&0xa1b2_3c4du32.to_le_bytes())?; // magic
        writer.write_all(&2u16.to_le_bytes())?; // version major
        writer.write_all(&4u16.to_le_bytes())?; // version minor
        writer.write_all(&0i32.to_le_bytes())?; // timezone offset
        writer.write_all(&0u32.to_le_bytes())?; // timestamp accuracy
        writer.write_all(&SNAPLEN.to_le_bytes())?;
        writer.write_all(&linktype.to_le_bytes())?;
        Ok(Self { writer })
    }
}

const SNAPLEN: u32 = 262_144;

/// The interface backends this build can use, in [`Backend::ALL`] order.
pub fn backends() -> Vec<Backend> {
    Backend::ALL
        .into_iter()
        .filter(|b| backend_missing(*b).is_none())
        .collect()
}

/// Why `backend` cannot be used in this build, or `None` if it can.
fn backend_missing(backend: Backend) -> Option<&'static str> {
    match backend {
        Backend::Pcap if cfg!(feature = "pcap") => None,
        Backend::Pcap => Some("this build has no libpcap/Npcap support (feature `pcap`)"),
        Backend::AfXdp if cfg!(all(feature = "af-xdp", target_os = "linux")) => None,
        Backend::AfXdp if cfg!(not(target_os = "linux")) => Some("AF_XDP only exists on Linux"),
        Backend::AfXdp => Some("this build has no AF_XDP support (feature `af-xdp`)"),
        Backend::Dpdk if cfg!(feature = "dpdk") => None,
        Backend::Dpdk => {
            Some("this build has no DPDK support (rebuild with `--features dpdk`, DPDK installed)")
        }
    }
}

/// Where a run sends its packets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// A network interface, sent on as `send` says. With the DPDK backend the
    /// name is a DPDK device: a PCI address, a virtual device such as
    /// `net_af_packet0,iface=eth0`, or a port number.
    Interface { name: String, send: SendSettings },
    /// A pcap file, stamped with each packet's send time.
    File(PathBuf),
    /// Nowhere: packets are discarded.
    Null,
}

/// An opened [`Output`], with a line on how it sends.
pub struct Opened {
    pub sink: Box<dyn PacketSink + Send>,
    /// For example `pcap on enp0s3` or `af_xdp on enp0s3 queue 0, copy mode`.
    pub detail: String,
}

impl Output {
    /// A network interface with the default sender (libpcap/Npcap).
    pub fn interface(name: impl Into<String>) -> Self {
        Output::Interface {
            name: name.into(),
            send: SendSettings::default(),
        }
    }

    /// Fills the send settings this output does not set from `defaults`, for
    /// example a profile's `[output]` table. Other outputs are unchanged.
    pub fn with_defaults(self, defaults: &SendSettings) -> Self {
        match self {
            Output::Interface { name, send } => Output::Interface {
                name,
                send: send.or(defaults),
            },
            other => other,
        }
    }

    /// Opens the output for packets of `linktype`.
    pub fn open(&self, linktype: u32) -> Result<Box<dyn PacketSink + Send>, SinkError> {
        Ok(self.open_detailed(linktype)?.sink)
    }

    /// Opens the output once per worker of a run on several cores: one
    /// libpcap/Npcap handle per worker, or one AF_XDP socket per worker on
    /// consecutive queues from `queue` (the interface needs that many). DPDK
    /// ports, files and the null output are opened once and shared by the
    /// workers, taking turns behind a lock ([`ferotrx_core::share_sink`]).
    pub fn open_workers(&self, linktype: u32, workers: usize) -> Result<Vec<Opened>, SinkError> {
        let workers = workers.max(1);
        if workers == 1 {
            return Ok(vec![self.open_detailed(linktype)?]);
        }
        match self {
            Output::Interface { name, send } if send.backend() != Backend::Dpdk => {
                let mut out = Vec::with_capacity(workers);
                for k in 0..workers {
                    let mut send = send.clone();
                    if send.backend() == Backend::AfXdp {
                        let queue = u32::from(send.queue()) + k as u32;
                        send.queue = Some(u16::try_from(queue).map_err(|_| "queue out of range")?);
                    }
                    let mut opened = open_interface(name, &send).map_err(|e| {
                        // A missing interface is not about queues.
                        if send.backend() == Backend::AfXdp && interface_exists(name) {
                            format!(
                                "worker {k} sends on queue {}: {e} (each AF_XDP worker needs \
                                 a queue of its own; see `ethtool -l {name}`)",
                                send.queue()
                            )
                            .into()
                        } else {
                            e
                        }
                    })?;
                    opened.detail = format!("worker {k}: {}", opened.detail);
                    out.push(opened);
                }
                Ok(out)
            }
            Output::Null => Ok((0..workers)
                .map(|_| Opened {
                    sink: Box::new(NullSink),
                    detail: "null".into(),
                })
                .collect()),
            _ => {
                let opened = self.open_detailed(linktype)?;
                let detail = format!("{} (shared by {workers} workers)", opened.detail);
                Ok(ferotrx_core::share_sink(opened.sink, workers)
                    .into_iter()
                    .map(|sink| Opened {
                        sink,
                        detail: detail.clone(),
                    })
                    .collect())
            }
        }
    }

    /// Opens the output, and says how it sends.
    pub fn open_detailed(&self, linktype: u32) -> Result<Opened, SinkError> {
        match self {
            Output::Interface { name, send } => open_interface(name, send),
            Output::File(path) => Ok(Opened {
                sink: Box::new(
                    PcapFileSink::create(path, linktype)
                        .map_err(|e| format!("cannot create {}: {e}", path.display()))?,
                ),
                detail: format!("file {}", path.display()),
            }),
            Output::Null => Ok(Opened {
                sink: Box::new(NullSink),
                detail: "null".into(),
            }),
        }
    }
}

fn open_interface(name: &str, send: &SendSettings) -> Result<Opened, SinkError> {
    send.validate()?;
    let backend = send.backend();
    if let Some(why) = backend_missing(backend) {
        return Err(format!("cannot send on {name} with {backend}: {why}").into());
    }
    let fail =
        |e: SinkError| -> SinkError { format!("cannot open {name} with {backend}: {e}").into() };
    match backend {
        #[cfg(feature = "pcap")]
        Backend::Pcap => {
            let sink = InterfaceSink::open_batched(name, send.batch()).map_err(fail)?;
            let detail = match sink.batch() {
                1 => format!("pcap on {name}"),
                b => format!("pcap on {name}, batches of {b} (Npcap send queue)"),
            };
            Ok(Opened {
                sink: Box::new(sink),
                detail,
            })
        }
        #[cfg(all(feature = "af-xdp", target_os = "linux"))]
        Backend::AfXdp => {
            let sink = AfXdpSink::open(
                name,
                &AfXdpConfig {
                    queue: send.queue(),
                    mode: send.xdp_mode(),
                    batch: send.batch(),
                },
            )
            .map_err(fail)?;
            Ok(Opened {
                detail: sink.describe(),
                sink: Box::new(sink),
            })
        }
        #[cfg(feature = "dpdk")]
        Backend::Dpdk => {
            let sink = DpdkSink::open(
                name,
                &DpdkConfig {
                    queue: send.queue(),
                    batch: send.batch(),
                    eal_args: send.dpdk_args().to_vec(),
                },
            )
            .map_err(fail)?;
            Ok(Opened {
                detail: sink.describe(),
                sink: Box::new(sink),
            })
        }
        #[allow(unreachable_patterns)]
        _ => {
            let _ = fail;
            unreachable!("backend_missing covers backends this build lacks")
        }
    }
}

impl std::fmt::Display for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Output::Interface { name, send } if send.backend() == Backend::Pcap => {
                write!(f, "interface {name}")
            }
            Output::Interface { name, send } => {
                write!(f, "interface {name} via {}", send.backend())
            }
            Output::File(path) => write!(f, "file {}", path.display()),
            Output::Null => f.write_str("null"),
        }
    }
}

impl PacketSink for PcapFileSink {
    fn send(&mut self, data: &[u8]) -> Result<(), SinkError> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let len = u32::try_from(data.len())?;
        let captured = len.min(SNAPLEN);
        self.writer
            .write_all(&(ts.as_secs() as u32).to_le_bytes())?;
        self.writer.write_all(&ts.subsec_nanos().to_le_bytes())?;
        self.writer.write_all(&captured.to_le_bytes())?;
        self.writer.write_all(&len.to_le_bytes())?;
        self.writer.write_all(&data[..captured as usize])?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), SinkError> {
        self.writer.flush()?;
        Ok(())
    }
}

/// A network interface that packets can be sent on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InterfaceInfo {
    /// What to open it by (`\Device\NPF_{GUID}` with Npcap).
    pub name: String,
    pub description: Option<String>,
    /// The name people know it by, when that is not `name`: "Ethernet 2"
    /// on Windows, which `-i` takes too.
    pub alias: Option<String>,
    /// Its MAC address (`aa:bb:cc:dd:ee:ff`), when known.
    pub mac: Option<String>,
    /// Its IP addresses.
    pub addresses: Vec<String>,
}

/// The device libpcap/Npcap should open for `name`, once it can be used:
/// on Windows, Npcap is loaded and an adapter name such as "Ethernet 2"
/// becomes its `\Device\NPF_{GUID}`.
#[cfg(feature = "pcap")]
pub(crate) fn pcap_device(name: &str) -> Result<String, SinkError> {
    #[cfg(windows)]
    {
        windows::load_npcap()?;
        Ok(windows::resolve(name))
    }
    #[cfg(not(windows))]
    Ok(name.to_string())
}

#[cfg(feature = "pcap")]
mod interface {
    use super::*;

    /// Lists the interfaces libpcap or Npcap can open.
    pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, SinkError> {
        #[cfg(windows)]
        crate::windows::load_npcap()?;
        #[cfg(windows)]
        let adapters = crate::windows::adapters();
        Ok(pcap::Device::list()?
            .into_iter()
            .map(|d| {
                #[cfg_attr(not(windows), allow(unused_mut))]
                let mut i = InterfaceInfo {
                    addresses: d.addresses.iter().map(|a| a.addr.to_string()).collect(),
                    mac: crate::interface_mac(&d.name).map(|m| m.to_string()),
                    name: d.name,
                    description: d.desc,
                    alias: None,
                };
                #[cfg(windows)]
                if let Some(a) = crate::windows::adapter_of(&adapters, &i.name) {
                    i.alias = Some(a.friendly_name.clone()).filter(|n| !n.is_empty());
                    i.mac = a.mac.clone();
                }
                i
            })
            .collect())
    }

    /// Sends packets on a network interface. Needs root or CAP_NET_RAW on Linux,
    /// access to /dev/bpf* on macOS, and Npcap installed on Windows.
    ///
    /// On Windows, packets go to Npcap in batches (`pcap_sendqueue_transmit`):
    /// one trip into the kernel for up to `batch` packets instead of one each,
    /// which is what makes Npcap fast. Like AF_XDP, a batch is handed over
    /// before every wait for a paced packet ([`PacketSink::idle`]), so batching
    /// never holds a paced packet back; `batch = 1` sends each one on its own.
    pub struct InterfaceSink {
        capture: pcap::Capture<pcap::Active>,
        #[cfg(windows)]
        queue: Option<SendQueue>,
    }

    /// Packets queued for one `pcap_sendqueue_transmit`.
    #[cfg(windows)]
    struct SendQueue {
        queue: pcap::sendqueue::SendQueue,
        /// Packets in it.
        queued: u32,
        /// Packets it holds at most.
        batch: u32,
    }

    // SAFETY: the queue is a buffer Npcap allocated, owned by this value and
    // used by one thread at a time, like the capture handle beside it.
    #[cfg(windows)]
    unsafe impl Send for SendQueue {}

    /// Room for a full batch of jumbo frames and their headers, up to 16 MiB;
    /// a batch of bigger frames is handed over when the queue is full.
    #[cfg(windows)]
    fn queue_bytes(batch: u32) -> u32 {
        batch.saturating_mul(9216 + 32).min(16 << 20)
    }

    impl InterfaceSink {
        /// Opens `name`, sending one packet at a time.
        pub fn open(name: &str) -> Result<Self, SinkError> {
            Self::open_batched(name, 1)
        }

        /// Opens `name`; on Windows, hands packets to Npcap `batch` at a time.
        pub fn open_batched(name: &str, batch: u32) -> Result<Self, SinkError> {
            let dev = crate::pcap_device(name)?;
            let capture = pcap::Capture::from_device(dev.as_str())?
                .snaplen(65535)
                .open()
                .map_err(|e| format!("cannot open {name}: {e}"))?;
            #[cfg(windows)]
            let queue = if batch > 1 {
                Some(SendQueue {
                    queue: pcap::sendqueue::SendQueue::new(queue_bytes(batch))?,
                    queued: 0,
                    batch,
                })
            } else {
                None
            };
            #[cfg(not(windows))]
            let _ = batch;
            Ok(Self {
                capture,
                #[cfg(windows)]
                queue,
            })
        }

        /// Packets handed to the system at once (1 where nothing is batched).
        pub fn batch(&self) -> u32 {
            #[cfg(windows)]
            if let Some(q) = &self.queue {
                return q.batch;
            }
            1
        }

        /// Adds a packet to the queue; false when it has no room.
        #[cfg(windows)]
        fn queue_one(&mut self, data: &[u8]) -> bool {
            let Some(q) = &mut self.queue else {
                return false;
            };
            let ok = q.queue.queue(None, data).is_ok();
            if ok {
                q.queued += 1;
            }
            ok
        }

        /// Hands the queued packets to Npcap.
        #[cfg(windows)]
        fn transmit(&mut self) -> Result<(), SinkError> {
            if let Some(q) = &mut self.queue {
                if q.queued > 0 {
                    q.queued = 0;
                    q.queue
                        .transmit(&mut self.capture, pcap::sendqueue::SendSync::Off)?;
                }
            }
            Ok(())
        }
    }

    impl PacketSink for InterfaceSink {
        fn send(&mut self, data: &[u8]) -> Result<(), SinkError> {
            #[cfg(windows)]
            if self.queue.is_some() {
                let mut queued = self.queue_one(data);
                if !queued {
                    // Full: hand it over, and try again in an empty queue.
                    self.transmit()?;
                    queued = self.queue_one(data);
                }
                if !queued {
                    // Bigger than the whole queue.
                    self.capture.sendpacket(data)?;
                }
                if self.queue.as_ref().is_some_and(|q| q.queued >= q.batch) {
                    self.transmit()?;
                }
                return Ok(());
            }
            self.capture.sendpacket(data)?;
            Ok(())
        }

        fn idle(&mut self) -> Result<(), SinkError> {
            #[cfg(windows)]
            self.transmit()?;
            Ok(())
        }

        fn flush(&mut self) -> Result<(), SinkError> {
            #[cfg(windows)]
            self.transmit()?;
            Ok(())
        }
    }

    impl Drop for InterfaceSink {
        fn drop(&mut self) {
            let _ = self.flush();
        }
    }
}

#[cfg(feature = "pcap")]
pub use interface::{list_interfaces, InterfaceSink};

/// True when this machine (this network namespace) has an interface `name`.
fn interface_exists(name: &str) -> bool {
    if cfg!(target_os = "linux") {
        Path::new("/sys/class/net").join(name).exists()
    } else {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferotrx_core::{replay, Capture, Packet, Rate, ReplayConfig};
    use std::time::Duration;

    #[test]
    fn backends_this_build_lacks_say_why() {
        let have = backends();
        for b in Backend::ALL {
            let out = Output::Interface {
                name: "no-such-if0".into(),
                send: SendSettings {
                    backend: Some(b),
                    ..Default::default()
                },
            };
            if have.contains(&b) {
                continue;
            }
            let err = out.open(1).err().expect("cannot open").to_string();
            assert!(err.contains(b.name()), "{err}");
        }
        assert!(have.contains(&Backend::Pcap) == cfg!(feature = "pcap"));
    }

    #[test]
    fn output_takes_profile_defaults() {
        let profile = SendSettings {
            backend: Some(Backend::AfXdp),
            batch: Some(8),
            ..Default::default()
        };
        let out = Output::Interface {
            name: "eth0".into(),
            send: SendSettings {
                batch: Some(32),
                ..Default::default()
            },
        }
        .with_defaults(&profile);
        let Output::Interface { send, .. } = &out else {
            panic!()
        };
        assert_eq!((send.backend(), send.batch()), (Backend::AfXdp, 32));
        assert_eq!(out.to_string(), "interface eth0 via af_xdp");
        assert_eq!(Output::Null.with_defaults(&profile), Output::Null);
    }

    /// Sends on a real interface through AF_XDP. Needs root; set
    /// FEROTRX_TEST_XDP_IFACE to an interface it may send junk on, e.g. one end
    /// of a veth pair: `ip link add xt0 type veth peer name xt1`.
    #[cfg(all(feature = "af-xdp", target_os = "linux"))]
    #[test]
    fn af_xdp_sends_on_a_real_interface() {
        let Ok(name) = std::env::var("FEROTRX_TEST_XDP_IFACE") else {
            eprintln!("skipped: set FEROTRX_TEST_XDP_IFACE to run");
            return;
        };
        let counter = format!("/sys/class/net/{name}/statistics/tx_packets");
        let read = || -> u64 {
            std::fs::read_to_string(&counter)
                .unwrap()
                .trim()
                .parse()
                .unwrap()
        };
        for batch in [1, 64] {
            let before = read();
            let mut sink = AfXdpSink::open(
                &name,
                &AfXdpConfig {
                    queue: 0,
                    mode: XdpMode::Copy,
                    batch,
                },
            )
            .unwrap();
            assert!(!sink.is_zero_copy());
            // More packets than the UMEM has frames, so frames must be recycled.
            for i in 0..10_000u32 {
                let mut frame = vec![0u8; 60];
                frame[..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
                frame[12..14].copy_from_slice(&[0x88, 0xb5]); // local experimental ethertype
                frame[14..18].copy_from_slice(&i.to_be_bytes());
                sink.send(&frame).unwrap();
            }
            sink.flush().unwrap();
            assert_eq!(read() - before, 10_000, "batch {batch}");
        }
        let too_big = vec![0u8; 5000];
        let mut sink = AfXdpSink::open(
            &name,
            &AfXdpConfig {
                queue: 0,
                mode: XdpMode::Copy,
                batch: 1,
            },
        )
        .unwrap();
        assert!(sink.send(&too_big).is_err());
    }

    #[test]
    fn file_sink_round_trips() {
        let dir = std::env::temp_dir().join(format!("ferotrx-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("out.pcap");

        let cap = Capture::new(
            1,
            (0..5u8)
                .map(|i| Packet::new(Duration::ZERO, vec![i; 64]))
                .collect(),
        );
        let mut sink = PcapFileSink::create(&path, cap.linktype).unwrap();
        let cfg = ReplayConfig {
            rate: Rate::TopSpeed,
            loops: 2,
            ..Default::default()
        };
        replay(&cap, &mut sink, &cfg).unwrap();
        drop(sink);

        let back = Capture::from_path(&path).unwrap();
        assert_eq!(back.len(), 10);
        assert_eq!(back.packets[3].data, vec![3u8; 64]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
