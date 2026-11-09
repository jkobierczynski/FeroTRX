//! The signature a latency stream carries in every packet.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::field_engine::set_len;
use crate::net;

/// Bytes a signature adds to each packet.
pub const SIGNATURE_LEN: usize = 28;

const MAGIC: [u8; 4] = *b"FTRX";
const VERSION: u8 = 1;

/// What a latency stream writes at the end of each packet's IP payload: which
/// flow the packet belongs to, its sequence number in that flow, and when it
/// was sent.
///
/// The 28 bytes, big endian:
///
/// | Bytes | Field |
/// | --- | --- |
/// | 0..4 | `FTRX` |
/// | 4 | version (1) |
/// | 5 | reserved, 0 |
/// | 6..8 | checksum compensation |
/// | 8..12 | flow id |
/// | 12..20 | sequence number, from 0 |
/// | 20..28 | send time, nanoseconds since the Unix epoch |
///
/// The compensation word makes the 16-bit ones' complement sum of the
/// signature zero, whatever the sequence number and time are. So the TCP, UDP
/// or ICMP checksum computed when the packet is prepared stays right when the
/// sequence number and time are written just before the packet leaves.
///
/// ```
/// use ferotrx_core::Signature;
/// use std::time::Duration;
///
/// let sig = Signature { flow: 7, seq: 42, tx_time: Duration::from_secs(1_700_000_000) };
/// let bytes = sig.encode();
/// assert_eq!(&bytes[..4], b"FTRX");
/// assert_eq!(Signature::decode(&bytes), Some(sig));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Signature {
    pub flow: u32,
    pub seq: u64,
    /// Send time, since the Unix epoch.
    pub tx_time: Duration,
}

impl Signature {
    /// The signature's bytes.
    pub fn encode(&self) -> [u8; SIGNATURE_LEN] {
        let mut b = [0u8; SIGNATURE_LEN];
        b[..4].copy_from_slice(&MAGIC);
        b[4] = VERSION;
        b[8..12].copy_from_slice(&self.flow.to_be_bytes());
        b[12..20].copy_from_slice(&self.seq.to_be_bytes());
        let ns = u64::try_from(self.tx_time.as_nanos()).unwrap_or(u64::MAX);
        b[20..28].copy_from_slice(&ns.to_be_bytes());
        compensate(&mut b);
        b
    }

    /// Reads a signature from exactly [`SIGNATURE_LEN`] bytes.
    pub fn decode(b: &[u8]) -> Option<Signature> {
        if b.len() != SIGNATURE_LEN || b[..4] != MAGIC || b[4] != VERSION {
            return None;
        }
        let u64_at = |at: usize| u64::from_be_bytes(b[at..at + 8].try_into().expect("8 bytes"));
        Some(Signature {
            flow: u32::from_be_bytes(b[8..12].try_into().expect("4 bytes")),
            seq: u64_at(12),
            tx_time: Duration::from_nanos(u64_at(20)),
        })
    }

    /// Finds the signature in a received frame: at the end of the IP payload,
    /// where a latency stream puts it, or for frames that are not IP, at the
    /// end of the frame (padding allowed).
    ///
    /// Routers may change addresses, ports, TTLs, VLAN tags and checksums on
    /// the way; none of that moves the signature.
    pub fn find(frame: &[u8]) -> Option<Signature> {
        if let Some(ip) = net::parse(frame).and_then(|l| l.ip) {
            if let Some(end) = ip.end {
                if end >= ip.start + ip.header_len + SIGNATURE_LEN {
                    if let Some(sig) = Signature::decode(&frame[end - SIGNATURE_LEN..end]) {
                        return Some(sig);
                    }
                }
            }
        }
        // Not IP, or IP that lost its signature position: look near the end,
        // where it sits before any Ethernet padding.
        if frame.len() < SIGNATURE_LEN {
            return None;
        }
        let from = frame.len().saturating_sub(64 + SIGNATURE_LEN);
        (from..=frame.len().saturating_sub(SIGNATURE_LEN))
            .rev()
            .find_map(|at| {
                if frame[at..at + 4] == MAGIC {
                    Signature::decode(&frame[at..at + SIGNATURE_LEN])
                } else {
                    None
                }
            })
    }
}

/// Sets the compensation word so the signature's ones' complement sum is zero.
fn compensate(b: &mut [u8; SIGNATURE_LEN]) {
    b[6] = 0;
    b[7] = 0;
    let fix = !net::fold(net::sum_words(b, 0));
    b[6..8].copy_from_slice(&fix.to_be_bytes());
}

/// Makes room for a signature of `flow` at the end of the frame's IP payload,
/// fixing the IP and UDP lengths and the checksums, and returns its offset.
///
/// Ethernet padding is dropped first. Frames that are not IP get it at their
/// end. IP fragments and truncated packets get none (`None`): a signature
/// after a fragment would not survive reassembly.
pub(crate) fn reserve(data: &mut Vec<u8>, flow: u32) -> Option<usize> {
    let template = Signature {
        flow,
        seq: 0,
        tx_time: Duration::ZERO,
    }
    .encode();
    match net::parse(data).and_then(|l| l.ip) {
        Some(ip) => {
            let end = ip.end.filter(|_| !ip.fragmented)?;
            data.truncate(end);
            data.extend_from_slice(&template);
            let len = data.len();
            set_len(data, len);
            Some(end)
        }
        None if data.len() >= net::ETH_HEADER => {
            let at = data.len();
            data.extend_from_slice(&template);
            Some(at)
        }
        None => None,
    }
}

/// Like [`reserve`], but the signature takes the place of the last
/// [`SIGNATURE_LEN`] bytes of the IP payload, so the frame keeps its length.
/// A payload shorter than that grows just enough to hold it.
pub(crate) fn reserve_inside(data: &mut Vec<u8>, flow: u32) -> Option<usize> {
    let end = match net::parse(data).and_then(|l| l.ip) {
        Some(ip) if ip.fragmented => return None,
        Some(ip) => ip.end?,
        None => data.len(),
    };
    set_len(data, end.saturating_sub(SIGNATURE_LEN));
    reserve(data, flow)
}

/// The length a frame of `len` bytes has once [`reserve_inside`] put a
/// signature in it: `len`, or more when its payload was too short.
pub fn signed_len(frame: &[u8], len: usize) -> usize {
    let mut f = frame.to_vec();
    set_len(&mut f, len);
    match reserve_inside(&mut f, 0) {
        Some(_) => f.len(),
        None => len,
    }
}

/// Writes the sequence number and send time into the signature reserved at `at`.
/// The checksums stay right (see [`Signature`]).
pub(crate) fn stamp(data: &mut [u8], at: usize, flow: u32, seq: u64, tx_time: Duration) {
    if let Some(slot) = data.get_mut(at..at + SIGNATURE_LEN) {
        slot.copy_from_slice(&Signature { flow, seq, tx_time }.encode());
    }
}

/// The time now, since the Unix epoch, as signatures carry it.
pub fn wall_clock() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::tests::{checksums_ok, tcp6, udp4};

    #[test]
    fn checksum_neutral_at_any_value() {
        for (flow, seq, ns) in [(0, 0, 0), (1, 2, 3), (u32::MAX, u64::MAX, u64::MAX)] {
            let b = Signature {
                flow,
                seq,
                tx_time: Duration::from_nanos(ns),
            }
            .encode();
            assert_eq!(net::fold(net::sum_words(&b, 0)) % 0xffff, 0);
        }
    }

    #[test]
    fn reserve_and_stamp_keep_checksums() {
        for mut frame in [udp4(), tcp6()] {
            // An odd payload length puts the signature on an odd offset.
            for extra in [0usize, 1] {
                let mut f = frame.clone();
                if extra == 1 {
                    f.push(0xab);
                    let len = f.len();
                    set_len(&mut f, len);
                }
                assert!(checksums_ok(&f));
                let before = f.len();
                let at = reserve(&mut f, 9).unwrap();
                assert_eq!(f.len(), before + SIGNATURE_LEN);
                assert!(checksums_ok(&f), "after reserve");
                stamp(&mut f, at, 9, 12345, Duration::from_millis(987_654_321));
                assert!(checksums_ok(&f), "after stamp");
                let sig = Signature::find(&f).unwrap();
                assert_eq!((sig.flow, sig.seq), (9, 12345));
                assert_eq!(sig.tx_time, Duration::from_millis(987_654_321));
            }
            // Ethernet padding is dropped, and the signature is found despite
            // new padding after it.
            frame.extend_from_slice(&[0; 10]);
            let at = reserve(&mut frame, 1).unwrap();
            frame.extend_from_slice(&[0; 7]);
            stamp(&mut frame, at, 1, 5, Duration::ZERO);
            assert_eq!(Signature::find(&frame).unwrap().seq, 5);
        }
    }

    #[test]
    fn reserve_inside_keeps_the_length() {
        let mut f = udp4();
        set_len(&mut f, 200);
        let at = reserve_inside(&mut f, 2).unwrap();
        assert_eq!(f.len(), 200);
        assert!(checksums_ok(&f));
        stamp(&mut f, at, 2, 77, Duration::from_secs(5));
        assert!(checksums_ok(&f));
        assert_eq!(Signature::find(&f).unwrap().seq, 77);
        // Too short: grows to the headers and the signature.
        let mut f = udp4();
        set_len(&mut f, 60);
        reserve_inside(&mut f, 2).unwrap();
        assert_eq!(f.len(), 14 + 20 + 8 + SIGNATURE_LEN);
        assert_eq!(signed_len(&udp4(), 60), 70);
        assert_eq!(signed_len(&udp4(), 1000), 1000);
        assert!(checksums_ok(&f));
    }

    #[test]
    fn frames_that_are_not_ip() {
        let mut f = vec![0u8; 14];
        f[12..14].copy_from_slice(&[0x88, 0xb5]);
        let at = reserve(&mut f, 3).unwrap();
        assert_eq!(at, 14);
        stamp(&mut f, at, 3, 1, Duration::ZERO);
        f.resize(60, 0); // padded by the NIC
        assert_eq!(Signature::find(&f).unwrap().flow, 3);
        assert_eq!(Signature::find(&[0u8; 60]), None);
        for n in 0..SIGNATURE_LEN {
            assert_eq!(Signature::find(&vec![0u8; n]), None);
        }
        assert_eq!(reserve(&mut vec![0u8; 4], 1), None);
    }

    #[cfg(feature = "build")]
    #[test]
    fn signatures_sit_inside_tunnels() {
        for spec in [
            "eth/ipv4/udp/vxlan(vni=5)/eth/ipv4/udp/raw(len=40)",
            "eth/ipv4/udp/gtpu(teid=9,qfi=1)/ipv6/udp/raw(len=40)",
            "eth/ipv4/gre(csum=1)/ipv4/tcp/raw(len=4)",
            "eth/mpls(label=3)/ipv6/ipv4/udp/raw(len=4)",
        ] {
            let mut f: Vec<u8> = spec
                .parse::<ferotrx_packet::PacketSpec>()
                .unwrap()
                .build()
                .unwrap();
            let before = f.len();
            let at = reserve(&mut f, 7).unwrap();
            assert_eq!(f.len(), before + SIGNATURE_LEN, "{spec}");
            stamp(&mut f, at, 7, 42, Duration::from_millis(5));
            let d = ferotrx_packet::decode(1, &f);
            assert!(d.problems.is_empty(), "{spec}: {:?}", d.problems);
            let sig = Signature::find(&f).unwrap();
            assert_eq!((sig.flow, sig.seq), (7, 42), "{spec}");
            let mut g = f.clone();
            assert!(reserve_inside(&mut g, 8).is_some());
            assert_eq!(g.len(), f.len(), "{spec}");
        }
    }
}
