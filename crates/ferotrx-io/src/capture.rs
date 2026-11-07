//! Live captures through libpcap or Npcap, with BPF filters.

use ferotrx_core::live::{CaptureOptions, FrameSource};
use ferotrx_core::SinkError;

#[cfg(feature = "pcap")]
mod imp {
    use std::time::Duration;

    use ferotrx_core::live::{
        CaptureDirection, CaptureOptions, Frame, FrameSource, SourceCounters,
    };
    use ferotrx_core::SinkError;

    /// Captures on an interface through libpcap or Npcap.
    pub struct LiveCapture {
        capture: pcap::Capture<pcap::Active>,
        linktype: u32,
        snaplen: u32,
        /// Time stamps come in nanoseconds.
        nanos: bool,
    }

    impl LiveCapture {
        pub fn open(name: &str, o: &CaptureOptions) -> Result<Self, SinkError> {
            let dev = crate::pcap_device(name)?;
            let snaplen = o.snaplen.clamp(64, 262_144);
            let inactive = |nano: bool| -> Result<pcap::Capture<pcap::Inactive>, SinkError> {
                let c = pcap::Capture::from_device(dev.as_str())?
                    .promisc(o.promisc)
                    .immediate_mode(true)
                    .snaplen(snaplen as i32)
                    .buffer_size(o.buffer.min(i32::MAX as u32) as i32);
                Ok(if nano {
                    c.precision(pcap::Precision::Nano)
                } else {
                    c
                })
            };
            // Nanosecond time stamps where the system has them (Linux);
            // libpcap says so by accepting the setting, which the pcap crate
            // does not report, so try and fall back.
            let (capture, nanos) = match inactive(cfg!(target_os = "linux"))?.open() {
                Ok(c) => (c, cfg!(target_os = "linux")),
                Err(_) if cfg!(target_os = "linux") => (inactive(false)?.open()?, false),
                Err(e) => return Err(format!("cannot capture on {name}: {e}").into()),
            };
            let mut capture = capture;
            match o.direction {
                CaptureDirection::Both => {}
                d => {
                    let dir = if d == CaptureDirection::In {
                        pcap::Direction::In
                    } else {
                        pcap::Direction::Out
                    };
                    capture.direction(dir).map_err(|e| {
                        format!("cannot capture only {d} on {name}: {e} (Npcap cannot choose a direction)")
                    })?;
                }
            }
            if let Some(f) = o.filter.as_deref().filter(|f| !f.trim().is_empty()) {
                capture
                    .filter(f, true)
                    .map_err(|e| format!("filter '{f}': {e}"))?;
            }
            let linktype = capture.get_datalink().0 as u32;
            let capture = capture.setnonblock()?;
            Ok(Self {
                capture,
                linktype,
                snaplen,
                nanos,
            })
        }
    }

    impl FrameSource for LiveCapture {
        fn linktype(&self) -> u32 {
            self.linktype
        }

        fn snaplen(&self) -> u32 {
            self.snaplen
        }

        fn next_frame(&mut self) -> Result<Option<Frame>, SinkError> {
            match self.capture.next_packet() {
                Ok(p) => {
                    let ts = p.header.ts;
                    let sec = u64::try_from(ts.tv_sec).unwrap_or(0);
                    let frac = u64::try_from(ts.tv_usec).unwrap_or(0);
                    let ts = if self.nanos {
                        Duration::from_secs(sec) + Duration::from_nanos(frac)
                    } else {
                        Duration::from_secs(sec) + Duration::from_micros(frac)
                    };
                    Ok(Some(Frame {
                        ts,
                        len: p.header.len,
                        data: p.data.to_vec(),
                    }))
                }
                Err(pcap::Error::TimeoutExpired | pcap::Error::NoMorePackets) => {
                    std::thread::sleep(Duration::from_micros(500));
                    Ok(None)
                }
                Err(e) => Err(e.into()),
            }
        }

        fn counters(&mut self) -> SourceCounters {
            self.capture
                .stats()
                .map(|s| SourceCounters {
                    received: u64::from(s.received),
                    dropped: u64::from(s.dropped),
                    if_dropped: u64::from(s.if_dropped),
                })
                .unwrap_or_default()
        }
    }

    /// A compiled BPF filter, to choose frames that were already captured
    /// (from a file, or another machine).
    pub struct FrameFilter {
        program: pcap::BpfProgram,
    }

    impl FrameFilter {
        /// Compiles `expr` for frames of this link type.
        pub fn new(linktype: u32, expr: &str) -> Result<Self, SinkError> {
            let dead = pcap::Capture::dead(pcap::Linktype(linktype as i32))?;
            let program = dead
                .compile(expr, true)
                .map_err(|e| format!("filter '{expr}': {e}"))?;
            Ok(Self { program })
        }

        /// True if the filter takes this frame.
        pub fn matches(&self, frame: &[u8]) -> bool {
            self.program.filter(frame)
        }
    }
}

#[cfg(feature = "pcap")]
pub use imp::{FrameFilter, LiveCapture};

/// Opens a live capture on an interface (see `ferotrx interfaces`), with the
/// options' BPF filter.
pub fn open_capture(
    name: &str,
    options: &CaptureOptions,
) -> Result<Box<dyn FrameSource>, SinkError> {
    #[cfg(feature = "pcap")]
    {
        Ok(Box::new(LiveCapture::open(name, options)?))
    }
    #[cfg(not(feature = "pcap"))]
    {
        let _ = options;
        Err(format!(
            "cannot capture on {name}: this build has no libpcap/Npcap support (feature `pcap`)"
        )
        .into())
    }
}

/// Checks that a BPF filter compiles for this link type, so a mistake is
/// found before a capture starts.
pub fn check_filter(linktype: u32, expr: &str) -> Result<(), SinkError> {
    #[cfg(feature = "pcap")]
    {
        FrameFilter::new(linktype, expr).map(|_| ())
    }
    #[cfg(not(feature = "pcap"))]
    {
        let _ = linktype;
        Err(format!("cannot check filter '{expr}': this build has no libpcap/Npcap support").into())
    }
}

#[cfg(all(test, feature = "pcap"))]
mod tests {
    use super::*;

    fn udp_frame(dport: u16) -> Vec<u8> {
        let mut f = vec![0u8; 42];
        f[12] = 0x08; // IPv4
        f[14] = 0x45;
        f[16..18].copy_from_slice(&28u16.to_be_bytes());
        f[22] = 64;
        f[23] = 17; // UDP
        f[26..30].copy_from_slice(&[10, 0, 0, 1]);
        f[30..34].copy_from_slice(&[10, 0, 0, 2]);
        f[34..36].copy_from_slice(&1234u16.to_be_bytes());
        f[36..38].copy_from_slice(&dport.to_be_bytes());
        f[38..40].copy_from_slice(&8u16.to_be_bytes());
        f
    }

    #[test]
    fn filters_choose_frames() {
        let f = FrameFilter::new(1, "udp port 53").unwrap();
        assert!(f.matches(&udp_frame(53)));
        assert!(!f.matches(&udp_frame(123)));
        let f = FrameFilter::new(1, "host 10.0.0.2 and not tcp").unwrap();
        assert!(f.matches(&udp_frame(9)));
    }

    #[test]
    fn a_bad_filter_says_why() {
        let e = check_filter(1, "udp prot 53").unwrap_err().to_string();
        assert!(e.contains("udp prot 53"), "{e}");
    }
}
