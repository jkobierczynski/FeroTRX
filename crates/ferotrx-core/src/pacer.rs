use std::fmt;
use std::str::FromStr;
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

/// Parses `1000pps`, `5kpps`, `1mpps`, `100mbps`, `500kbps`, `1gbps`, `2x` (multiplier
/// of the original timing) or `topspeed`.
impl FromStr for Rate {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let t = s.trim().to_ascii_lowercase();
        if t == "topspeed" || t == "top" {
            return Ok(Rate::TopSpeed);
        }
        type Make = fn(f64) -> Rate;
        let units: [(&str, Make); 8] = [
            ("mpps", |v| Rate::Pps(v * 1e6)),
            ("kpps", |v| Rate::Pps(v * 1e3)),
            ("pps", Rate::Pps),
            ("gbps", |v| Rate::Mbps(v * 1e3)),
            ("mbps", Rate::Mbps),
            ("kbps", |v| Rate::Mbps(v / 1e3)),
            ("bps", |v| Rate::Mbps(v / 1e6)),
            ("x", |v| Rate::Original { multiplier: v }),
        ];
        for (suffix, make) in units {
            if let Some(num) = t.strip_suffix(suffix) {
                let v: f64 = num.trim().parse().map_err(|_| {
                    Error::InvalidRate(format!("'{s}' is not a number followed by {suffix}"))
                })?;
                let rate = make(v);
                rate.validate()?;
                return Ok(rate);
            }
        }
        Err(Error::InvalidRate(format!(
            "'{s}': use e.g. 1000pps, 10kpps, 100mbps, 1gbps, 2x or topspeed"
        )))
    }
}

impl fmt::Display for Rate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rate::Original { multiplier } => write!(f, "{multiplier}x"),
            Rate::Pps(v) => write!(f, "{v}pps"),
            Rate::Mbps(v) => write!(f, "{v}mbps"),
            Rate::TopSpeed => f.write_str("topspeed"),
        }
    }
}

/// Parses a duration such as `500ms`, `2s`, `1.5m`, `100us`, `1h`.
pub fn parse_duration(s: &str) -> Result<Duration> {
    let t = s.trim().to_ascii_lowercase();
    let bad = || Error::InvalidSpec(format!("invalid duration '{s}' (use e.g. 500ms, 2s, 1m)"));
    let units: [(&str, f64); 6] = [
        ("ns", 1e-9),
        ("us", 1e-6),
        ("ms", 1e-3),
        ("s", 1.0),
        ("m", 60.0),
        ("h", 3600.0),
    ];
    for (suffix, scale) in units {
        if let Some(num) = t.strip_suffix(suffix) {
            let v: f64 = num.trim().parse().map_err(|_| bad())?;
            return Duration::try_from_secs_f64(v * scale).map_err(|_| bad());
        }
    }
    Err(bad())
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
    #[test]
    fn rates_parse() {
        assert_eq!("1000pps".parse::<Rate>().unwrap(), Rate::Pps(1000.0));
        assert_eq!("10kpps".parse::<Rate>().unwrap(), Rate::Pps(10_000.0));
        assert_eq!("1.5gbps".parse::<Rate>().unwrap(), Rate::Mbps(1500.0));
        assert_eq!("100 Mbps".parse::<Rate>().unwrap(), Rate::Mbps(100.0));
        assert_eq!(
            "2x".parse::<Rate>().unwrap(),
            Rate::Original { multiplier: 2.0 }
        );
        assert_eq!("topspeed".parse::<Rate>().unwrap(), Rate::TopSpeed);
        for bad in ["", "fast", "0pps", "-1mbps", "x", "10"] {
            assert!(bad.parse::<Rate>().is_err(), "{bad}");
        }
        let r = Rate::Pps(250.0);
        assert_eq!(r.to_string().parse::<Rate>().unwrap(), r);
    }

    #[test]
    fn durations_parse() {
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("2s").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_duration("1.5m").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("100us").unwrap(), Duration::from_micros(100));
        for bad in ["", "5", "fast", "-1s"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }
}
