//! Packet sinks for FeroTRX.
//!
//! * [`PcapFileSink`] writes packets to a pcap file, stamped with the time they were sent.
//!   It works everywhere and needs no privileges.
//! * [`InterfaceSink`] sends packets on a network interface through libpcap
//!   (Linux, macOS) or Npcap (Windows). Enabled by the default `pcap` feature.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ferotrx_core::{PacketSink, SinkError};

pub use ferotrx_core::NullSink;

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: Option<String>,
}

#[cfg(feature = "pcap")]
mod interface {
    use super::*;

    /// Lists the interfaces libpcap or Npcap can open.
    pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, SinkError> {
        Ok(pcap::Device::list()?
            .into_iter()
            .map(|d| InterfaceInfo {
                name: d.name,
                description: d.desc,
            })
            .collect())
    }

    /// Sends packets on a network interface. Needs root or CAP_NET_RAW on Linux,
    /// access to /dev/bpf* on macOS, and Npcap installed on Windows.
    pub struct InterfaceSink {
        capture: pcap::Capture<pcap::Active>,
    }

    impl InterfaceSink {
        pub fn open(name: &str) -> Result<Self, SinkError> {
            let capture = pcap::Capture::from_device(name)?.snaplen(65535).open()?;
            Ok(Self { capture })
        }
    }

    impl PacketSink for InterfaceSink {
        fn send(&mut self, data: &[u8]) -> Result<(), SinkError> {
            self.capture.sendpacket(data)?;
            Ok(())
        }
    }
}

#[cfg(feature = "pcap")]
pub use interface::{list_interfaces, InterfaceSink};

#[cfg(test)]
mod tests {
    use super::*;
    use ferotrx_core::{replay, Capture, Packet, Rate, ReplayConfig};
    use std::time::Duration;

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
