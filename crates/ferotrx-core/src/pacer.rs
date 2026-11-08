use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use crate::{Error, Result, Schedule, TrafficModel, FCS_LEN, L1_OVERHEAD};

/// Bytes a frame takes on an Ethernet wire beyond the bytes FeroTRX sends:
/// preamble and start delimiter (8), the gap between frames (12) and the
/// frame check sequence (4), which frame sizes in FeroTRX never count.
pub const WIRE_OVERHEAD: u32 = (L1_OVERHEAD + FCS_LEN) as u32;

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

/// A rate as a profile or the command line gives it: a [`Rate`], or a share
/// of the line's speed, and whether a bit rate counts the bytes on the wire
/// (layer 1, with [`WIRE_OVERHEAD`] per frame) or only the frames (layer 2, the
/// default).
///
/// Parses everything [`Rate`] does, plus `50%` (a share of the line rate, on
/// the wire) and bit rates with `-l1` or `-l2` after them: `100mbps-l1`,
/// `1gbps-l2`.
///
/// ```
/// use ferotrx_core::{Rate, RateSpec};
/// let r: RateSpec = "25%".parse().unwrap();
/// assert_eq!(r.resolve(Some(1000.0)).unwrap(), (Rate::Mbps(250.0), 24));
/// assert!(r.resolve(None).is_err());
/// let r: RateSpec = "100mbps-l1".parse().unwrap();
/// assert_eq!(r.resolve(None).unwrap(), (Rate::Mbps(100.0), 24));
/// assert_eq!("1kpps".parse::<RateSpec>().unwrap().resolve(None).unwrap(), (Rate::Pps(1000.0), 0));
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RateSpec {
    /// A rate; `l1` makes a bit rate count [`WIRE_OVERHEAD`] per frame.
    Rate { rate: Rate, l1: bool },
    /// A percentage of the line rate (0 to 100), on the wire.
    Line(f64),
}

impl Default for RateSpec {
    fn default() -> Self {
        RateSpec::Rate {
            rate: Rate::default(),
            l1: false,
        }
    }
}

impl From<Rate> for RateSpec {
    fn from(rate: Rate) -> Self {
        RateSpec::Rate { rate, l1: false }
    }
}

impl RateSpec {
    /// The rate and the bytes per frame its pacer counts on top
    /// ([`Pacer::with_overhead`]), with `line_mbps` the line's speed in
    /// Mbit/s, which a percentage needs.
    pub fn resolve(&self, line_mbps: Option<f64>) -> Result<(Rate, u32)> {
        match *self {
            RateSpec::Rate { rate, l1 } => Ok((rate, if l1 { WIRE_OVERHEAD } else { 0 })),
            RateSpec::Line(pct) => match line_mbps {
                Some(line) if line.is_finite() && line > 0.0 => {
                    let rate = Rate::Mbps(line * pct / 100.0);
                    rate.validate()?;
                    Ok((rate, WIRE_OVERHEAD))
                }
                _ => Err(Error::InvalidRate(format!(
                    "{pct}% needs the line's speed: set line_rate in [output] (or \
                     --line-rate), or send on an interface whose speed is known"
                ))),
            },
        }
    }

    /// True for a share of the line rate.
    pub fn needs_line_rate(&self) -> bool {
        matches!(self, RateSpec::Line(_))
    }

    /// The rate, when it does not depend on the line.
    pub fn rate(&self) -> Option<Rate> {
        match self {
            RateSpec::Rate { rate, .. } => Some(*rate),
            RateSpec::Line(_) => None,
        }
    }
}

impl FromStr for RateSpec {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let t = s.trim().to_ascii_lowercase();
        if let Some(num) = t.strip_suffix('%') {
            let v: f64 = num
                .trim()
                .parse()
                .map_err(|_| Error::InvalidRate(format!("'{s}' is not a number followed by %")))?;
            if !(v.is_finite() && v > 0.0 && v <= 100.0) {
                return Err(Error::InvalidRate(format!(
                    "'{s}': a share of the line rate is above 0% and at most 100%"
                )));
            }
            return Ok(RateSpec::Line(v));
        }
        let (body, l1) = if let Some(b) = t.strip_suffix("-l1") {
            (b, Some(true))
        } else if let Some(b) = t.strip_suffix("-l2") {
            (b, Some(false))
        } else {
            (t.as_str(), None)
        };
        let rate: Rate = body.parse()?;
        if l1.is_some() && !matches!(rate, Rate::Mbps(_)) {
            return Err(Error::InvalidRate(format!(
                "'{s}': -l1 and -l2 go after a bit rate, such as 100mbps-l1"
            )));
        }
        Ok(RateSpec::Rate {
            rate,
            l1: l1.unwrap_or(false),
        })
    }
}

impl fmt::Display for RateSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RateSpec::Rate { rate, l1: true } => write!(f, "{rate}-l1"),
            RateSpec::Rate { rate, .. } => write!(f, "{rate}"),
            RateSpec::Line(p) => write!(f, "{p}%"),
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
/// in other schedulers. With a [`TrafficModel`] (see [`with_model`](Self::with_model))
/// packets arrive in bursts, as a Poisson process or along a ramp around the rate.
#[derive(Clone, Debug)]
pub struct Pacer {
    rate: Rate,
    packets: u64,
    bits: u128,
    /// The schedule of a non-steady model, for pps and Mbit/s rates.
    schedule: Option<Schedule>,
    ended: bool,
    /// Bytes counted per packet on top of its length by a bit rate.
    overhead: u32,
}

impl Pacer {
    pub fn new(rate: Rate) -> Self {
        Self {
            rate,
            packets: 0,
            bits: 0,
            schedule: None,
            ended: false,
            overhead: 0,
        }
    }

    /// Counts `bytes` more per packet against a bit rate: [`WIRE_OVERHEAD`]
    /// makes it a rate on the wire (layer 1), with preamble, gap and FCS.
    pub fn with_overhead(mut self, bytes: u32) -> Self {
        self.overhead = bytes;
        self
    }

    /// A pacer whose packets follow `model` around `rate`. Models need a
    /// packet or bit rate; see [`check_model`](Self::check_model).
    pub fn with_model(rate: Rate, model: &TrafficModel) -> Result<Self> {
        Self::check_model(rate, model)?;
        let mut p = Self::new(rate);
        p.schedule = match rate {
            _ if model.is_steady() => None,
            Rate::Pps(pps) => Some(model.schedule(pps)),
            Rate::Mbps(mbps) => Some(model.schedule(mbps * 1e6)),
            Rate::Original { .. } | Rate::TopSpeed => None,
        };
        Ok(p)
    }

    /// Checks that `model` fits `rate`: anything but the steady model needs a
    /// packet or bit rate, since a capture's own timing or top speed has no
    /// mean rate to shape.
    pub fn check_model(rate: Rate, model: &TrafficModel) -> Result<()> {
        model.validate()?;
        if model.is_steady() || matches!(rate, Rate::Pps(_) | Rate::Mbps(_)) {
            Ok(())
        } else {
            Err(Error::InvalidRate(format!(
                "traffic model '{model}' needs a packet or bit rate (such as 1000pps or \
                 100mbps), not {rate}"
            )))
        }
    }

    pub fn rate(&self) -> Rate {
        self.rate
    }

    /// True once a traffic model's shape has run out: the stream is over.
    pub fn ended(&self) -> bool {
        self.ended
    }

    /// Returns the send deadline of the next packet, or `None` to send it now.
    ///
    /// `capture_offset` is the packet's position on the original timeline, measured
    /// from the first packet of the replay; only [`Rate::Original`] uses it.
    /// When a model's shape has ended, returns `None` and [`ended`](Self::ended)
    /// turns true.
    pub fn next_deadline(
        &mut self,
        capture_offset: Duration,
        len_bytes: usize,
    ) -> Option<Duration> {
        let len_bytes = len_bytes + self.overhead as usize;
        if let Some(schedule) = &mut self.schedule {
            let units = match self.rate {
                Rate::Mbps(_) => len_bytes as f64 * 8.0,
                _ => 1.0,
            };
            let at = schedule.next(units);
            self.ended = at.is_none();
            self.packets += 1;
            self.bits += len_bytes as u128 * 8;
            return at;
        }
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
    fn models_shape_pps_and_mbps() {
        let model: TrafficModel = "burst=2".parse().unwrap();
        let mut p = Pacer::with_model(Rate::Pps(100.0), &model).unwrap();
        let d: Vec<_> = (0..4)
            .map(|_| p.next_deadline(Duration::ZERO, 64).unwrap())
            .collect();
        assert_eq!(d[0], d[1]);
        assert_eq!(d[2], Duration::from_millis(20));
        // 1 Mbit/s, ramping off after 1 s: 125-byte packets, 1000 per second
        // at 100%, about 1000 / 2 during the ramp down.
        let model: TrafficModel = "ramp_up=0s,hold=0s,ramp_down=1s".parse().unwrap();
        let mut p = Pacer::with_model(Rate::Mbps(1.0), &model).unwrap();
        let mut n = 0;
        while p.next_deadline(Duration::ZERO, 125).is_some() {
            n += 1;
        }
        assert!(p.ended());
        assert_eq!(n, 501);
        assert!(Pacer::with_model(Rate::TopSpeed, &model).is_err());
        assert!(Pacer::with_model(Rate::TopSpeed, &TrafficModel::default()).is_ok());
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
    fn rate_specs_parse() {
        assert_eq!("50%".parse::<RateSpec>().unwrap(), RateSpec::Line(50.0));
        assert_eq!(
            "1gbps-l1".parse::<RateSpec>().unwrap(),
            RateSpec::Rate {
                rate: Rate::Mbps(1000.0),
                l1: true
            }
        );
        assert_eq!(
            "1gbps-l2".parse::<RateSpec>().unwrap(),
            RateSpec::Rate {
                rate: Rate::Mbps(1000.0),
                l1: false
            }
        );
        for bad in ["0%", "101%", "x%", "10pps-l1", "2x-l2"] {
            assert!(bad.parse::<RateSpec>().is_err(), "{bad}");
        }
        for text in ["50%", "100mbps-l1", "10pps", "topspeed"] {
            let r: RateSpec = text.parse().unwrap();
            assert_eq!(r.to_string().parse::<RateSpec>().unwrap(), r);
        }
    }

    #[test]
    fn an_l1_rate_counts_the_wire_overhead() {
        // 1 Mbit/s on the wire, 101-byte frames: 125 bytes = 1 ms each.
        let mut p = Pacer::new(Rate::Mbps(1.0)).with_overhead(WIRE_OVERHEAD);
        p.next_deadline(Duration::ZERO, 101);
        assert_eq!(
            p.next_deadline(Duration::ZERO, 101),
            Some(Duration::from_millis(1))
        );
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
