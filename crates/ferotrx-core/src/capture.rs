use std::fs::File;
use std::io::{BufReader, Cursor, Read};
use std::path::Path;
use std::time::Duration;

use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::{Block, PcapNgReader};

use crate::{Error, Result};

/// Link type number for Ethernet frames (DLT_EN10MB).
pub const LINKTYPE_ETHERNET: u32 = 1;

/// One captured packet: its original timestamp and its bytes, starting at the link layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub timestamp: Duration,
    pub data: Vec<u8>,
}

impl Packet {
    pub fn new(timestamp: Duration, data: Vec<u8>) -> Self {
        Self { timestamp, data }
    }
}

/// A capture loaded into memory, ready to replay.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Capture {
    /// Link type of every packet (1 = Ethernet).
    pub linktype: u32,
    pub packets: Vec<Packet>,
}

impl Capture {
    pub fn new(linktype: u32, packets: Vec<Packet>) -> Self {
        Self { linktype, packets }
    }

    /// Loads a pcap or pcapng file. The format is detected from its magic number.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path)?;
        Self::from_reader(BufReader::new(file))
    }

    /// Loads a pcap or pcapng capture from any reader.
    pub fn from_reader<R: Read>(mut reader: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        let reader = Cursor::new(magic).chain(reader);
        match magic {
            [0xd4, 0xc3, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0xc3, 0xd4]
            | [0x4d, 0x3c, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0x3c, 0x4d] => Self::read_pcap(reader),
            [0x0a, 0x0d, 0x0d, 0x0a] => Self::read_pcapng(reader),
            other => Err(Error::UnknownFormat(other)),
        }
    }

    fn read_pcap<R: Read>(reader: R) -> Result<Self> {
        let mut reader = PcapReader::new(reader)?;
        let linktype = u32::from(reader.header().datalink);
        let mut packets = Vec::new();
        while let Some(pkt) = reader.next_packet() {
            let pkt = pkt?;
            packets.push(Packet::new(pkt.timestamp, pkt.data.into_owned()));
        }
        Ok(Self { linktype, packets })
    }

    fn read_pcapng<R: Read>(reader: R) -> Result<Self> {
        let mut reader = PcapNgReader::new(reader)?;
        let mut linktype: Option<u32> = None;
        let mut packets = Vec::new();
        let mut last_ts = Duration::ZERO;

        let check_link = |lt: u32, current: &mut Option<u32>| -> Result<()> {
            match *current {
                None => {
                    *current = Some(lt);
                    Ok(())
                }
                Some(seen) if seen == lt => Ok(()),
                Some(seen) => Err(Error::MixedLinkTypes(seen, lt)),
            }
        };

        while let Some(block) = reader.next_block() {
            match block?.into_owned() {
                Block::EnhancedPacket(epb) => {
                    let lt = reader
                        .packet_interface(&epb)
                        .map(|idb| u32::from(idb.linktype))
                        .ok_or_else(|| {
                            Error::Malformed(format!(
                                "packet on unknown interface {}",
                                epb.interface_id
                            ))
                        })?;
                    check_link(lt, &mut linktype)?;
                    last_ts = epb.timestamp;
                    packets.push(Packet::new(epb.timestamp, epb.data.into_owned()));
                }
                Block::SimplePacket(spb) => {
                    // Simple packets carry no timestamp and belong to the first interface.
                    let lt = reader
                        .interfaces()
                        .first()
                        .map(|idb| u32::from(idb.linktype))
                        .ok_or_else(|| {
                            Error::Malformed("simple packet before any interface".into())
                        })?;
                    check_link(lt, &mut linktype)?;
                    packets.push(Packet::new(last_ts, spb.data.into_owned()));
                }
                _ => {}
            }
        }
        Ok(Self {
            linktype: linktype.unwrap_or(LINKTYPE_ETHERNET),
            packets,
        })
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Total bytes of all packets.
    pub fn total_bytes(&self) -> u64 {
        self.packets.iter().map(|p| p.data.len() as u64).sum()
    }

    /// Time from the first to the last packet in the original capture.
    pub fn duration(&self) -> Duration {
        match (self.packets.first(), self.packets.last()) {
            (Some(first), Some(last)) => last.timestamp.saturating_sub(first.timestamp),
            _ => Duration::ZERO,
        }
    }
}
