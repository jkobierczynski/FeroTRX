//! Ports that send and receive, for stateful TCP, and receivers for loss and
//! latency measurement.

use ferotrx_core::{MacAddr, SinkError};

/// The MAC address of a network interface, where the system says it simply
/// (Linux: `/sys/class/net/<name>/address`). `None` elsewhere or if unknown.
pub fn interface_mac(name: &str) -> Option<MacAddr> {
    #[cfg(windows)]
    {
        let adapters = crate::windows::adapters();
        let dev = crate::windows::resolve_in(&adapters, name);
        crate::windows::adapter_of(&adapters, &dev)?
            .mac
            .as_deref()?
            .parse()
            .ok()
    }
    #[cfg(not(windows))]
    if cfg!(target_os = "linux") && !name.contains('/') {
        let text = std::fs::read_to_string(format!("/sys/class/net/{name}/address")).ok()?;
        text.trim().parse().ok()
    } else {
        None
    }
}

#[cfg(feature = "pcap")]
mod pcap_port {
    use super::*;
    use ferotrx_core::PacketPort;

    /// Sends and receives on a network interface through libpcap or Npcap, in
    /// promiscuous mode, so emulated hosts can use MAC addresses of their own.
    /// Frames this port sends are not received back where the system can
    /// tell them apart (Linux, macOS).
    pub struct PcapPort {
        capture: pcap::Capture<pcap::Active>,
        nic: crate::nic::NicCounters,
    }

    impl PcapPort {
        pub fn open(name: &str) -> Result<Self, SinkError> {
            let dev = crate::pcap_device(name)?;
            let capture = pcap::Capture::from_device(dev.as_str())?
                .promisc(true)
                .immediate_mode(true)
                .snaplen(65535)
                .buffer_size(32 << 20)
                .open()
                .map_err(|e| format!("cannot open {name}: {e}"))?;
            // Npcap cannot filter by direction; the engine ignores its own frames.
            let _ = capture.direction(pcap::Direction::In);
            let capture = capture.setnonblock()?;
            Ok(Self {
                capture,
                nic: crate::nic::NicCounters::new(name),
            })
        }
    }

    impl PacketPort for PcapPort {
        fn send(&mut self, frame: &[u8]) -> Result<(), SinkError> {
            self.capture.sendpacket(frame)?;
            Ok(())
        }

        fn recv(&mut self, buf: &mut Vec<u8>) -> Result<bool, SinkError> {
            match self.capture.next_packet() {
                Ok(p) => {
                    buf.clear();
                    buf.extend_from_slice(p.data);
                    Ok(true)
                }
                Err(pcap::Error::TimeoutExpired | pcap::Error::NoMorePackets) => Ok(false),
                Err(e) => Err(e.into()),
            }
        }

        fn rx_dropped(&mut self) -> Option<u64> {
            // Frames the kernel had for this capture but no room for.
            self.capture.stats().ok().map(|s| u64::from(s.dropped))
        }

        fn drops(&mut self) -> ferotrx_core::DropCounters {
            let mut d = self.nic.since_start();
            d.capture_dropped = self.rx_dropped().unwrap_or(0);
            d
        }
    }
}

#[cfg(feature = "pcap")]
pub use pcap_port::PcapPort;

#[cfg(feature = "pcap")]
mod pcap_receiver {
    use std::time::Duration;

    use ferotrx_core::{PacketReceiver, SinkError};

    /// Receives on a network interface through libpcap or Npcap, in
    /// promiscuous mode, for measuring loss and latency. Each frame comes with
    /// the time the kernel (or Npcap's driver) took it in, which is more
    /// accurate than the time the program reads it. Frames sent on the same
    /// interface are left out where the system can tell them apart.
    pub struct PcapReceiver {
        capture: pcap::Capture<pcap::Active>,
        nic: crate::nic::NicCounters,
    }

    impl PcapReceiver {
        pub fn open(name: &str) -> Result<Self, SinkError> {
            let dev = crate::pcap_device(name)?;
            let inactive = || -> Result<pcap::Capture<pcap::Inactive>, SinkError> {
                Ok(pcap::Capture::from_device(dev.as_str())?
                    .promisc(true)
                    .immediate_mode(true)
                    .snaplen(65535)
                    .buffer_size(16 << 20))
            };
            // Windows: Npcap's default time stamps count from the
            // performance counter and drift away from the system clock that
            // the sender stamps its signatures with; the precise system
            // time (KeQuerySystemTimePrecise) does not. Older Npcap without
            // it opens with the default.
            #[cfg(windows)]
            let capture = {
                let precise = inactive()?;
                // The pcap crate offers tstamp_type only when its build
                // found a new enough wpcap.dll; call Npcap directly.
                extern "C" {
                    fn pcap_set_tstamp_type(
                        p: *mut std::ffi::c_void,
                        t: std::ffi::c_int,
                    ) -> std::ffi::c_int;
                }
                const PCAP_TSTAMP_HOST_HIPREC: std::ffi::c_int = 2;
                // SAFETY: the handle of a capture not yet activated.
                unsafe { pcap_set_tstamp_type(precise.as_ptr().cast(), PCAP_TSTAMP_HOST_HIPREC) };
                precise
                    .open()
                    .or_else(|_| inactive()?.open().map_err(SinkError::from))
            };
            #[cfg(not(windows))]
            let capture = inactive()?.open();
            let capture = capture.map_err(|e| format!("cannot open {name}: {e}"))?;
            let _ = capture.direction(pcap::Direction::In);
            // Non-blocking, with short naps when nothing is waiting: read
            // timeouts are not honoured in immediate mode everywhere (Linux
            // waits for the next packet). The naps do not touch the
            // timestamps, which the kernel takes.
            let capture = capture.setnonblock()?;
            Ok(Self {
                capture,
                nic: crate::nic::NicCounters::new(name),
            })
        }
    }

    impl PacketReceiver for PcapReceiver {
        fn drops(&mut self) -> ferotrx_core::DropCounters {
            let mut d = self.nic.rx();
            // ps_drop: no room in the capture buffer. ps_ifdrop is left
            // out: Linux libpcap reads it from the NIC counters above.
            d.capture_dropped = self.capture.stats().map_or(0, |s| u64::from(s.dropped));
            d
        }

        fn recv(&mut self, buf: &mut Vec<u8>) -> Result<Option<Duration>, SinkError> {
            match self.capture.next_packet() {
                Ok(p) => {
                    buf.clear();
                    buf.extend_from_slice(p.data);
                    let ts = p.header.ts;
                    let at = Duration::from_secs(u64::try_from(ts.tv_sec).unwrap_or(0))
                        + Duration::from_micros(u64::try_from(ts.tv_usec).unwrap_or(0));
                    Ok(Some(at))
                }
                Err(pcap::Error::TimeoutExpired | pcap::Error::NoMorePackets) => {
                    std::thread::sleep(Duration::from_micros(100));
                    Ok(None)
                }
                Err(e) => Err(e.into()),
            }
        }
    }
}

#[cfg(feature = "pcap")]
pub use pcap_receiver::PcapReceiver;

/// Opens an interface to receive on, for loss and latency measurement.
pub fn open_receiver(name: &str) -> Result<Box<dyn ferotrx_core::PacketReceiver>, SinkError> {
    #[cfg(feature = "pcap")]
    {
        Ok(Box::new(PcapReceiver::open(name)?))
    }
    #[cfg(not(feature = "pcap"))]
    {
        Err(format!(
            "cannot receive on {name}: this build has no libpcap/Npcap support (feature `pcap`)"
        )
        .into())
    }
}

/// How to open a [`PacketPort`](ferotrx_core::PacketPort) with
/// [`open_port_with`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortSettings {
    /// The backend and its settings, as for sending (default libpcap/Npcap).
    pub send: ferotrx_core::SendSettings,
    /// The emulated hosts' MAC addresses on this interface. AF_XDP and DPDK
    /// ports take only frames for these, besides broadcasts and multicasts;
    /// libpcap ports take everything.
    pub macs: Vec<MacAddr>,
}

/// Opens an interface as a [`PacketPort`](ferotrx_core::PacketPort) with
/// libpcap/Npcap.
pub fn open_port(name: &str) -> Result<Box<dyn ferotrx_core::PacketPort>, SinkError> {
    open_pcap_port(name)
}

/// Opens an interface as a [`PacketPort`](ferotrx_core::PacketPort) with the
/// backend `settings` choose. With the DPDK backend the name is a DPDK device,
/// as for [`Output::Interface`](crate::Output::Interface).
pub fn open_port_with(
    name: &str,
    settings: &PortSettings,
) -> Result<Box<dyn ferotrx_core::PacketPort>, SinkError> {
    use ferotrx_core::Backend;
    let send = &settings.send;
    send.validate()?;
    let backend = send.backend();
    if let Some(why) = crate::backend_missing(backend) {
        return Err(format!("cannot open {name} with {backend}: {why}").into());
    }
    let fail =
        |e: SinkError| -> SinkError { format!("cannot open {name} with {backend}: {e}").into() };
    match backend {
        Backend::Pcap => open_pcap_port(name),
        #[cfg(all(feature = "af-xdp", target_os = "linux"))]
        Backend::AfXdp => {
            let config = crate::XdpPortConfig {
                queue: send.queue(),
                mode: send.xdp_mode(),
                batch: send.batch(),
                generic: false,
            };
            Ok(Box::new(
                crate::XdpPort::open(name, &settings.macs, &config).map_err(fail)?,
            ))
        }
        #[cfg(feature = "dpdk")]
        Backend::Dpdk => {
            let config = crate::DpdkConfig {
                queue: send.queue(),
                batch: send.batch(),
                eal_args: send.dpdk_args().to_vec(),
            };
            Ok(Box::new(
                crate::DpdkPort::open(name, &config).map_err(fail)?,
            ))
        }
        #[allow(unreachable_patterns)]
        _ => {
            let _ = fail;
            unreachable!("backend_missing covers backends this build lacks")
        }
    }
}

fn open_pcap_port(name: &str) -> Result<Box<dyn ferotrx_core::PacketPort>, SinkError> {
    #[cfg(feature = "pcap")]
    {
        Ok(Box::new(PcapPort::open(name)?))
    }
    #[cfg(not(feature = "pcap"))]
    {
        Err(format!("cannot open {name}: this build has no libpcap/Npcap support (feature `pcap`), which stateful TCP needs to receive").into())
    }
}
