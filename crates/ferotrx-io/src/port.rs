//! Ports that send and receive, for stateful TCP.

use ferotrx_core::{MacAddr, SinkError};

/// The MAC address of a network interface, where the system says it simply
/// (Linux: `/sys/class/net/<name>/address`). `None` elsewhere or if unknown.
pub fn interface_mac(name: &str) -> Option<MacAddr> {
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
    }

    impl PcapPort {
        pub fn open(name: &str) -> Result<Self, SinkError> {
            let capture = pcap::Capture::from_device(name)?
                .promisc(true)
                .immediate_mode(true)
                .snaplen(65535)
                .buffer_size(8 << 20)
                .open()
                .map_err(|e| format!("cannot open {name}: {e}"))?;
            // Npcap cannot filter by direction; the engine ignores its own frames.
            let _ = capture.direction(pcap::Direction::In);
            let capture = capture.setnonblock()?;
            Ok(Self { capture })
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
    }
}

#[cfg(feature = "pcap")]
pub use pcap_port::PcapPort;

/// Opens an interface as a [`PacketPort`](ferotrx_core::PacketPort).
pub fn open_port(name: &str) -> Result<Box<dyn ferotrx_core::PacketPort>, SinkError> {
    #[cfg(feature = "pcap")]
    {
        Ok(Box::new(PcapPort::open(name)?))
    }
    #[cfg(not(feature = "pcap"))]
    {
        Err(format!("cannot open {name}: this build has no libpcap/Npcap support (feature `pcap`), which stateful TCP needs to receive").into())
    }
}
