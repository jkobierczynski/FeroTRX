use std::time::Duration;

use crate::{Error, Result};

/// How fast a capture is replayed.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Rate {
    /// Keep the original gaps between packets, sped up by `multiplier`
    /// (2.0 = twice as fast, 0.5 = half speed).
    Original { multiplier: f64 },
    /// A fixed number of packets per second, evenly spaced.
    Pps(f64),
    /// A fixed bit rate in megabits per second (10^6 bits), counting the bytes sent.
    Mbps(f64),
    /// As fast as the sink accepts packets.
    TopSpeed,
}

impl Default for Rate {
    fn default() -> Self {
        Rate::Original { multiplier: 1.0 }
    }
}

impl Rate {
    /// Checks that the rate is finite and positive.
    pub fn validate(&self) -> Result<()> {
        let (name, value) = match *self {
            Rate::Original { multiplier } => ("multiplier", multiplier),
            Rate::Pps(v) => ("pps", v),
            Rate::Mbps(v) => ("mbps", v),
            Rate::TopSpeed => return Ok(()),
        };
        if value.is_finite() && value > 0.0 {
            Ok(())
        } else {
            Err(Error::InvalidRate(format!(
                "{name} must be a positive number, got {value}"
            )))
        }
    }
}

/// Computes when each packet should be sent, as an offset from the start of the replay.
///
/// The pacer is pure arithmetic, with no clock, so it is easy to test and reuse
/// in other schedulers.
#[derive(Clone, Debug)]
pub struct Pacer {
    rate: Rate,
    packets: u64,
    bits: u128,
}

impl Pacer {
    pub fn new(rate: Rate) -> Self {
        Self {
            rate,
            packets: 0,
            bits: 0,
        }
    }

    pub fn rate(&self) -> Rate {
        self.rate
    }

    /// Returns the send deadline of the next packet, or `None` to send it now.
    ///
    /// `capture_offset` is the packet's position on the original timeline, measured
    /// from the first packet of the replay; only [`Rate::Original`] uses it.
    pub fn next_deadline(
        &mut self,
        capture_offset: Duration,
        len_bytes: usize,
    ) -> Option<Duration> {
        let deadline = match self.rate {
            Rate::Original { multiplier } => Some(capture_offset.div_f64(multiplier)),
            Rate::Pps(pps) => Some(Duration::from_secs_f64(self.packets as f64 / pps)),
            Rate::Mbps(mbps) => Some(Duration::from_secs_f64(self.bits as f64 / (mbps * 1e6))),
            Rate::TopSpeed => None,
        };
        self.packets += 1;
        self.bits += len_bytes as u128 * 8;
        deadline
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_rate_scales_offsets() {
        let mut p = Pacer::new(Rate::Original { multiplier: 2.0 });
        assert_eq!(p.next_deadline(Duration::ZERO, 100), Some(Duration::ZERO));
        assert_eq!(
            p.next_deadline(Duration::from_millis(10), 100),
            Some(Duration::from_millis(5))
        );
    }

    #[test]
    fn pps_spaces_packets_evenly() {
        let mut p = Pacer::new(Rate::Pps(1000.0));
        let d: Vec<_> = (0..3)
            .map(|_| p.next_deadline(Duration::ZERO, 64).unwrap())
            .collect();
        assert_eq!(
            d,
            vec![
                Duration::ZERO,
                Duration::from_millis(1),
                Duration::from_millis(2)
            ]
        );
    }

    #[test]
    fn mbps_counts_bytes() {
        // 1 Mbps, 125 byte packets = 1000 bits each = 1 ms per packet.
        let mut p = Pacer::new(Rate::Mbps(1.0));
        assert_eq!(p.next_deadline(Duration::ZERO, 125), Some(Duration::ZERO));
        assert_eq!(
            p.next_deadline(Duration::ZERO, 125),
            Some(Duration::from_millis(1))
        );
        assert_eq!(
            p.next_deadline(Duration::ZERO, 125),
            Some(Duration::from_millis(2))
        );
    }

    #[test]
    fn topspeed_has_no_deadline() {
        let mut p = Pacer::new(Rate::TopSpeed);
        assert_eq!(p.next_deadline(Duration::from_secs(5), 64), None);
    }

    #[test]
    fn invalid_rates_are_rejected() {
        assert!(Rate::Pps(0.0).validate().is_err());
        assert!(Rate::Mbps(-1.0).validate().is_err());
        assert!(Rate::Original {
            multiplier: f64::NAN
        }
        .validate()
        .is_err());
        assert!(Rate::TopSpeed.validate().is_ok());
        assert!(Rate::Pps(10.0).validate().is_ok());
    }
}
