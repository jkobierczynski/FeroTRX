//! Random distributions for workload realism: session lengths, think times,
//! user lifetimes.
//!
//! A [`Dist`] draws numbers of one [`Quantity`]: times, counts or byte sizes.
//! It is written as text, in a profile or on the command line:
//!
//! ```text
//! 5s                                   fixed (the plain value)
//! exp(5s)                              exponential with mean 5 s
//! lognormal(median=2s, sigma=1)        log-normal: half below 2 s, a long tail
//! lognormal(mean=10, sigma=0.8)        ... given by its mean instead
//! pareto(min=1K, shape=1.5)            Pareto: at least 1 KiB, a heavy tail
//! uniform(1s, 5s)                      uniform between the two
//! normal(mean=200ms, sd=50ms)          normal, cut at 0
//! lognormal(median=8, sigma=1, max=100)  any of them cut to [min, max]
//! ```
//!
//! Times take `us`, `ms`, `s`, `m` and `h`; byte sizes `K`, `M` and `G`
//! (powers of 1024); counts are plain numbers. Draws come from a seeded
//! generator ([`DistRng`]), so a run with a seed repeats.

use std::fmt;
use std::time::Duration;

use crate::field_engine::{fresh_seed, next_random};
use crate::{parse_duration, Error, Result};

/// The longest time a draw gives: 100 years, far beyond any run, and far
/// enough from [`Duration::MAX`] that adding draws to a clock cannot overflow.
pub const MAX_TIME: Duration = Duration::from_secs(100 * 365 * 24 * 3600);

/// What a distribution's numbers are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quantity {
    /// Seconds (written `500ms`, `2s`, `5m`).
    Time,
    /// A number of things: requests, rounds.
    Count,
    /// Bytes (written `1500`, `64K`, `2M`).
    Bytes,
}

impl Quantity {
    fn parse(self, s: &str) -> Result<f64> {
        let s = s.trim();
        match self {
            Quantity::Time => Ok(parse_duration(s)?.as_secs_f64()),
            Quantity::Count => s
                .parse::<f64>()
                .ok()
                .filter(|v| v.is_finite() && *v >= 0.0)
                .ok_or_else(|| Error::InvalidSpec(format!("'{s}' is not a count"))),
            Quantity::Bytes => Ok(crate::tcp::parse_size(s)? as f64),
        }
    }

    /// The value as written back: `1.5s`, `12`, `64K`.
    pub fn format(self, v: f64) -> String {
        match self {
            Quantity::Time => {
                if v == 0.0 {
                    "0s".into()
                } else if v < 1e-3 {
                    format!("{}us", trim(v * 1e6))
                } else if v < 1.0 {
                    format!("{}ms", trim(v * 1e3))
                } else if v >= 3600.0 && (v / 3600.0).fract() == 0.0 {
                    format!("{}h", v / 3600.0)
                } else if v >= 60.0 && (v / 60.0).fract() == 0.0 {
                    format!("{}m", v / 60.0)
                } else {
                    format!("{}s", trim(v))
                }
            }
            Quantity::Count => trim(v),
            Quantity::Bytes => {
                if v >= 1048576.0 && (v / 1048576.0).fract() == 0.0 {
                    format!("{}M", v / 1048576.0)
                } else if v >= 1024.0 && (v / 1024.0).fract() == 0.0 {
                    format!("{}K", v / 1024.0)
                } else {
                    trim(v)
                }
            }
        }
    }
}

fn trim(v: f64) -> String {
    let s = format!("{:.3}", v);
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s.is_empty() {
        "0".into()
    } else {
        s.into()
    }
}

/// The shape of a [`Dist`]; the numbers are in the quantity's base unit
/// (seconds, items, bytes).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Shape {
    Fixed(f64),
    /// Exponential with this mean.
    Exponential {
        mean: f64,
    },
    /// Log-normal: `exp(mu + sigma * z)` for a standard normal `z`; the
    /// median is `exp(mu)`.
    LogNormal {
        mu: f64,
        sigma: f64,
    },
    /// Pareto (type I): at least `min`, tail index `shape` (a mean only for
    /// a shape above 1).
    Pareto {
        min: f64,
        shape: f64,
    },
    Uniform {
        low: f64,
        high: f64,
    },
    /// Normal, cut at 0.
    Normal {
        mean: f64,
        sd: f64,
    },
}

/// A distribution of times, counts or sizes, optionally cut to `[min, max]`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Dist {
    pub quantity: Quantity,
    pub shape: Shape,
    pub min: Option<f64>,
    pub max: Option<f64>,
}

/// Distributions come only from finite numbers, so equality is total.
impl Eq for Dist {}

impl Dist {
    /// Always `v`.
    pub fn fixed(quantity: Quantity, v: f64) -> Self {
        Self {
            quantity,
            shape: Shape::Fixed(v),
            min: None,
            max: None,
        }
    }

    /// A fixed time.
    pub fn time(d: Duration) -> Self {
        Self::fixed(Quantity::Time, d.as_secs_f64())
    }

    /// Always zero: no wait.
    pub fn zero() -> Self {
        Self::fixed(Quantity::Time, 0.0)
    }

    /// True for a fixed 0.
    pub fn is_zero(&self) -> bool {
        self.shape == Shape::Fixed(0.0) && self.min.is_none_or(|m| m <= 0.0)
    }

    /// True if it always gives the same value.
    pub fn is_fixed(&self) -> bool {
        matches!(self.shape, Shape::Fixed(_))
    }

    /// Parses the text form (see the module's documentation).
    pub fn parse(quantity: Quantity, text: &str) -> Result<Self> {
        let t = text.trim();
        let bad = |why: String| {
            Error::InvalidSpec(format!(
                "distribution '{text}': {why} (use e.g. 5s, exp(5s), lognormal(median=2s, sigma=1), pareto(min=1s, shape=1.5), uniform(1s, 5s), normal(mean=1s, sd=200ms))"
            ))
        };
        let Some(open) = t.find('(') else {
            let v = quantity.parse(t).map_err(|e| bad(e.to_string()))?;
            return Ok(Self::fixed(quantity, v));
        };
        let name = t[..open].trim().to_ascii_lowercase();
        let inner = t[open + 1..]
            .strip_suffix(')')
            .ok_or_else(|| bad("a missing ')'".into()))?;
        let mut named: Vec<(String, String)> = Vec::new();
        let mut plain: Vec<String> = Vec::new();
        for part in inner.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match part.split_once('=') {
                Some((k, v)) => named.push((k.trim().to_ascii_lowercase(), v.trim().to_string())),
                None => plain.push(part.to_string()),
            }
        }
        let mut take = |key: &str| -> Option<String> {
            let i = named.iter().position(|(k, _)| k == key)?;
            Some(named.remove(i).1)
        };
        let num = |s: &str| -> Result<f64> {
            s.trim()
                .parse::<f64>()
                .ok()
                .filter(|v| v.is_finite())
                .ok_or_else(|| bad(format!("'{s}' is not a number")))
        };
        let val = |s: &str| quantity.parse(s).map_err(|e| bad(e.to_string()));
        let min = take("min").map(|s| val(&s)).transpose()?;
        let max = take("max").map(|s| val(&s)).transpose()?;
        let shape = match name.as_str() {
            "fixed" | "const" => {
                let v = take("value").or_else(|| plain.first().cloned());
                Shape::Fixed(val(&v.ok_or_else(|| bad("give the value".into()))?)?)
            }
            "exp" | "exponential" => {
                let m = take("mean").or_else(|| plain.first().cloned());
                let mean = val(&m.ok_or_else(|| bad("give the mean".into()))?)?;
                if mean <= 0.0 {
                    return Err(bad("the mean must be above 0".into()));
                }
                Shape::Exponential { mean }
            }
            "lognormal" | "log-normal" | "lognorm" => {
                let sigma = num(&take("sigma").ok_or_else(|| bad("give sigma".into()))?)?;
                if sigma <= 0.0 {
                    return Err(bad("sigma must be above 0".into()));
                }
                let mu = match (take("median"), take("mean"), take("mu")) {
                    (Some(m), None, None) => {
                        let m = val(&m)?;
                        if m <= 0.0 {
                            return Err(bad("the median must be above 0".into()));
                        }
                        m.ln()
                    }
                    (None, Some(m), None) => {
                        let m = val(&m)?;
                        if m <= 0.0 {
                            return Err(bad("the mean must be above 0".into()));
                        }
                        m.ln() - sigma * sigma / 2.0
                    }
                    (None, None, Some(mu)) => num(&mu)?,
                    _ => return Err(bad("give one of median, mean or mu".into())),
                };
                Shape::LogNormal { mu, sigma }
            }
            "pareto" => {
                let m = take("min")
                    .map(|s| val(&s))
                    .transpose()?
                    .or(min)
                    .ok_or_else(|| bad("give min (the scale)".into()))?;
                let shape = num(&take("shape").ok_or_else(|| bad("give shape".into()))?)?;
                if m <= 0.0 || shape <= 0.0 {
                    return Err(bad("min and shape must be above 0".into()));
                }
                Shape::Pareto { min: m, shape }
            }
            "uniform" => {
                let (lo, hi) = match (take("low").or(take("from")), take("high").or(take("to"))) {
                    (Some(l), Some(h)) => (val(&l)?, val(&h)?),
                    _ if plain.len() == 2 => (val(&plain[0])?, val(&plain[1])?),
                    _ => return Err(bad("give the low and high ends".into())),
                };
                if hi < lo {
                    return Err(bad("the high end is below the low one".into()));
                }
                Shape::Uniform { low: lo, high: hi }
            }
            "normal" | "gauss" => {
                let mean = val(&take("mean").ok_or_else(|| bad("give the mean".into()))?)?;
                let sd = val(&take("sd")
                    .or(take("stddev"))
                    .ok_or_else(|| bad("give sd".into()))?)?;
                Shape::Normal { mean, sd }
            }
            other => return Err(bad(format!("unknown distribution '{other}'"))),
        };
        if let Some((k, _)) = named.first() {
            return Err(bad(format!("unknown setting '{k}'")));
        }
        // Pareto's `min` is its scale, not a cut.
        let min = if matches!(shape, Shape::Pareto { .. } | Shape::Fixed(_)) {
            None
        } else {
            min
        };
        let max = if matches!(shape, Shape::Fixed(_)) {
            None
        } else {
            max
        };
        if let (Some(lo), Some(hi)) = (min, max) {
            if hi < lo {
                return Err(bad("max is below min".into()));
            }
        }
        Ok(Self {
            quantity,
            shape,
            min,
            max,
        })
    }

    /// One draw.
    pub fn sample(&self, rng: &mut DistRng) -> f64 {
        let v = match self.shape {
            Shape::Fixed(v) => v,
            Shape::Exponential { mean } => -mean * rng.open01().ln(),
            Shape::LogNormal { mu, sigma } => (mu + sigma * rng.normal()).exp(),
            Shape::Pareto { min, shape } => min / rng.open01().powf(1.0 / shape),
            Shape::Uniform { low, high } => low + (high - low) * rng.unit(),
            Shape::Normal { mean, sd } => mean + sd * rng.normal(),
        };
        let mut v = v.max(0.0);
        if let Some(lo) = self.min {
            v = v.max(lo);
        }
        if let Some(hi) = self.max {
            v = v.min(hi);
        }
        v
    }

    /// One draw as a time.
    ///
    /// Draws are capped at [`MAX_TIME`] (100 years), so a heavy-tailed draw
    /// added to an engine's clock cannot overflow.
    pub fn sample_time(&self, rng: &mut DistRng) -> Duration {
        Duration::try_from_secs_f64(self.sample(rng))
            .unwrap_or(MAX_TIME)
            .min(MAX_TIME)
    }

    /// One draw as a whole number (rounded), at least `at_least`.
    pub fn sample_count(&self, rng: &mut DistRng, at_least: u64) -> u64 {
        let v = self.sample(rng).round();
        (if v >= u64::MAX as f64 {
            u64::MAX
        } else {
            v as u64
        })
        .max(at_least)
    }

    /// The mean before any cut, if it has one (Pareto with a shape of 1 or
    /// less has none).
    pub fn mean(&self) -> Option<f64> {
        match self.shape {
            Shape::Fixed(v) => Some(v),
            Shape::Exponential { mean } => Some(mean),
            Shape::LogNormal { mu, sigma } => Some((mu + sigma * sigma / 2.0).exp()),
            Shape::Pareto { min, shape } => (shape > 1.0).then(|| shape * min / (shape - 1.0)),
            Shape::Uniform { low, high } => Some((low + high) / 2.0),
            Shape::Normal { mean, .. } => Some(mean),
        }
    }

    /// The median before any cut.
    pub fn median(&self) -> f64 {
        match self.shape {
            Shape::Fixed(v) => v,
            Shape::Exponential { mean } => mean * std::f64::consts::LN_2,
            Shape::LogNormal { mu, .. } => mu.exp(),
            Shape::Pareto { min, shape } => min * 2f64.powf(1.0 / shape),
            Shape::Uniform { low, high } => (low + high) / 2.0,
            Shape::Normal { mean, .. } => mean,
        }
    }
}

impl fmt::Display for Dist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let q = |v: f64| self.quantity.format(v);
        match self.shape {
            Shape::Fixed(v) => return write!(f, "{}", q(v)),
            Shape::Exponential { mean } => write!(f, "exp({}", q(mean))?,
            Shape::LogNormal { mu, sigma } => {
                write!(f, "lognormal(median={}, sigma={}", q(mu.exp()), trim(sigma))?
            }
            Shape::Pareto { min, shape } => {
                write!(f, "pareto(min={}, shape={}", q(min), trim(shape))?
            }
            Shape::Uniform { low, high } => write!(f, "uniform({}, {}", q(low), q(high))?,
            Shape::Normal { mean, sd } => write!(f, "normal(mean={}, sd={}", q(mean), q(sd))?,
        }
        if let Some(m) = self.min {
            write!(f, ", min={}", q(m))?;
        }
        if let Some(m) = self.max {
            write!(f, ", max={}", q(m))?;
        }
        f.write_str(")")
    }
}

/// The seeded generator distributions draw from.
#[derive(Clone, Debug)]
pub struct DistRng {
    state: u64,
    spare: Option<f64>,
}

impl DistRng {
    pub fn new(seed: u64) -> Self {
        Self {
            state: seed,
            spare: None,
        }
    }

    /// A generator with a fresh seed.
    pub fn fresh() -> Self {
        Self::new(fresh_seed())
    }

    pub fn next_u64(&mut self) -> u64 {
        next_random(&mut self.state)
    }

    /// Uniform in [0, 1).
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform in (0, 1].
    fn open01(&mut self) -> f64 {
        1.0 - self.unit()
    }

    /// Standard normal (Box-Muller, both values used).
    pub fn normal(&mut self) -> f64 {
        if let Some(z) = self.spare.take() {
            return z;
        }
        let (u1, u2) = (self.open01(), self.unit());
        let r = (-2.0 * u1.ln()).sqrt();
        let a = 2.0 * std::f64::consts::PI * u2;
        self.spare = Some(r * a.sin());
        r * a.cos()
    }
}

/// How long a session lasts: a number of requests (rounds), a time, or a
/// number of bytes (both ways together).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SessionLength {
    Requests(Dist),
    Duration(Dist),
    Bytes(Dist),
}

impl SessionLength {
    /// From a template's `session_requests`, `session_duration` and
    /// `session_bytes` (at most one).
    pub fn from_keys(
        requests: Option<&str>,
        duration: Option<&str>,
        bytes: Option<&str>,
    ) -> Result<Option<Self>> {
        match (requests, duration, bytes) {
            (None, None, None) => Ok(None),
            (Some(r), None, None) => Ok(Some(Self::Requests(Dist::parse(Quantity::Count, r)?))),
            (None, Some(d), None) => Ok(Some(Self::Duration(Dist::parse(Quantity::Time, d)?))),
            (None, None, Some(b)) => Ok(Some(Self::Bytes(Dist::parse(Quantity::Bytes, b)?))),
            _ => Err(Error::Profile(
                "give one of session_requests, session_duration and session_bytes".into(),
            )),
        }
    }

    /// Draws one session's budget, which starts at `now`.
    pub fn draw(&self, rng: &mut DistRng, now: Duration) -> SessionBudget {
        match self {
            SessionLength::Requests(d) => SessionBudget {
                requests: Some(d.sample_count(rng, 1)),
                ..SessionBudget::default()
            },
            SessionLength::Duration(d) => SessionBudget {
                until: Some(now.saturating_add(d.sample_time(rng))),
                ..SessionBudget::default()
            },
            SessionLength::Bytes(d) => SessionBudget {
                bytes: Some(d.sample_count(rng, 1)),
                ..SessionBudget::default()
            },
        }
    }
}

impl fmt::Display for SessionLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionLength::Requests(d) => write!(f, "{d} requests"),
            SessionLength::Duration(d) => write!(f, "{d} long"),
            SessionLength::Bytes(d) => write!(f, "{d} bytes"),
        }
    }
}

/// One session's drawn length: the session goes on (starts another request
/// or round) while all that are set allow it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionBudget {
    /// Requests (rounds) in all.
    pub requests: Option<u64>,
    /// Engine time after which no new request starts.
    pub until: Option<Duration>,
    /// Bytes sent and received after which no new request starts.
    pub bytes: Option<u64>,
}

impl SessionBudget {
    /// Exactly `n` requests.
    pub fn requests(n: u64) -> Self {
        Self {
            requests: Some(n),
            ..Self::default()
        }
    }

    /// True when nothing limits the session here (the protocol's own count holds).
    pub fn is_open(&self) -> bool {
        self.requests.is_none() && self.until.is_none() && self.bytes.is_none()
    }

    /// Whether another request may start, after `done` requests, at `now`,
    /// with `bytes` moved so far.
    pub fn more(&self, done: u64, now: Duration, bytes: u64) -> bool {
        self.requests.is_none_or(|n| done < n)
            && self.until.is_none_or(|t| now < t)
            && self.bytes.is_none_or(|b| bytes < b)
    }
}

/// Counts of things per session (requests per connection), with a
/// histogram for percentiles: exact up to 8, then within 12.5%.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CountStats(crate::LatencyStats);

impl CountStats {
    pub fn record(&mut self, n: u64) {
        self.0.record(Some(Duration::from_nanos(n)));
    }

    pub fn count(&self) -> u64 {
        self.0.count()
    }

    pub fn mean(&self) -> Option<f64> {
        self.0.mean_ns()
    }

    pub fn min(&self) -> Option<u64> {
        self.0.min().map(|d| d.as_nanos() as u64)
    }

    pub fn max(&self) -> Option<u64> {
        self.0.max().map(|d| d.as_nanos() as u64)
    }

    /// The value a fraction `p` (0.0 to 1.0) of the sessions did not exceed.
    pub fn percentile(&self, p: f64) -> Option<u64> {
        self.0.percentile(p).map(|d| d.as_nanos() as u64)
    }

    pub fn merge(&mut self, other: &CountStats) {
        self.0.merge(&other.0);
    }
}

/// A distribution as a profile writes it: text (`"exp(5s)"`) or a plain
/// number (`session_requests = 5`).
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(untagged)]
pub(crate) enum DistText {
    Text(String),
    Int(i64),
    Float(f64),
}

impl DistText {
    pub(crate) fn text(&self) -> String {
        match self {
            DistText::Text(t) => t.clone(),
            DistText::Int(n) => n.to_string(),
            DistText::Float(x) => x.to_string(),
        }
    }

    pub(crate) fn parse(&self, q: Quantity) -> Result<Dist> {
        Dist::parse(q, &self.text())
    }
}

/// `SessionLength::from_keys` for profile values.
pub(crate) fn session_from(
    requests: Option<&DistText>,
    duration: Option<&DistText>,
    bytes: Option<&DistText>,
) -> Result<Option<SessionLength>> {
    let (r, d, b) = (
        requests.map(DistText::text),
        duration.map(DistText::text),
        bytes.map(DistText::text),
    );
    SessionLength::from_keys(r.as_deref(), d.as_deref(), b.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draws(d: &Dist, n: usize) -> Vec<f64> {
        let mut rng = DistRng::new(42);
        let mut v: Vec<f64> = (0..n).map(|_| d.sample(&mut rng)).collect();
        v.sort_by(f64::total_cmp);
        v
    }

    fn mean(v: &[f64]) -> f64 {
        v.iter().sum::<f64>() / v.len() as f64
    }

    #[test]
    fn heavy_tailed_times_are_capped() {
        let d = Dist::parse(Quantity::Time, "pareto(min=1s, shape=0.01)").unwrap();
        let mut rng = DistRng::new(3);
        let most = (0..1000).map(|_| d.sample_time(&mut rng)).max().unwrap();
        assert_eq!(most, MAX_TIME);
        let _ = Duration::from_secs(3600).saturating_add(most) + most;
    }

    #[test]
    fn parses_every_shape() {
        let t = |s| Dist::parse(Quantity::Time, s).unwrap();
        assert_eq!(t("250ms").shape, Shape::Fixed(0.25));
        assert_eq!(t("exp(5s)").shape, Shape::Exponential { mean: 5.0 });
        assert_eq!(
            t("exponential(mean=2s)").shape,
            Shape::Exponential { mean: 2.0 }
        );
        assert_eq!(
            t("uniform(1s, 3s)").shape,
            Shape::Uniform {
                low: 1.0,
                high: 3.0
            }
        );
        let l = t("lognormal(median=2s, sigma=1, max=1m)");
        assert!(matches!(l.shape, Shape::LogNormal { sigma, .. } if sigma == 1.0));
        assert!((l.median() - 2.0).abs() < 1e-9);
        assert_eq!(l.max, Some(60.0));
        let p = Dist::parse(Quantity::Bytes, "pareto(min=1K, shape=1.5)").unwrap();
        assert_eq!(
            p.shape,
            Shape::Pareto {
                min: 1024.0,
                shape: 1.5
            }
        );
        assert_eq!(p.mean(), Some(3072.0));
        let c = Dist::parse(Quantity::Count, "lognormal(mean=10, sigma=0.5)").unwrap();
        assert!((c.mean().unwrap() - 10.0).abs() < 1e-9);
        for bad in [
            "exp()",
            "lognormal(median=2s)",
            "weibull(1s)",
            "uniform(3s, 1s)",
            "exp(5s, foo=1)",
            "exp(5s",
            "pareto(shape=2)",
            "lognormal(median=1s, sigma=1, min=5s, max=1s)",
        ] {
            assert!(Dist::parse(Quantity::Time, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn writes_back_what_it_reads() {
        for (q, s) in [
            (Quantity::Time, "exp(5s)"),
            (Quantity::Time, "lognormal(median=2s, sigma=1, max=90s)"),
            (Quantity::Bytes, "pareto(min=1K, shape=1.5)"),
            (Quantity::Count, "uniform(2, 10)"),
            (Quantity::Time, "normal(mean=200ms, sd=50ms)"),
            (Quantity::Count, "12"),
            (Quantity::Time, "exp(5m)"),
        ] {
            let d = Dist::parse(q, s).unwrap();
            assert_eq!(d.to_string(), s);
            assert_eq!(Dist::parse(q, &d.to_string()).unwrap(), d);
        }
    }

    #[test]
    fn draws_match_the_distribution() {
        let n = 200_000;
        let e = draws(&Dist::parse(Quantity::Time, "exp(2s)").unwrap(), n);
        assert!((mean(&e) - 2.0).abs() < 0.03, "{}", mean(&e));
        assert!((e[n / 2] - 2.0 * std::f64::consts::LN_2).abs() < 0.03);

        let l = draws(
            &Dist::parse(Quantity::Count, "lognormal(median=8, sigma=0.7)").unwrap(),
            n,
        );
        assert!((l[n / 2] - 8.0).abs() < 0.1, "{}", l[n / 2]);
        let want = (8f64.ln() + 0.49 / 2.0).exp();
        assert!((mean(&l) - want).abs() / want < 0.02);

        let p = draws(
            &Dist::parse(Quantity::Bytes, "pareto(min=1000, shape=2.5)").unwrap(),
            n,
        );
        assert!(p[0] >= 1000.0);
        assert!((mean(&p) - 2500.0 / 1.5).abs() / (2500.0 / 1.5) < 0.03);
        assert!((p[n / 2] - 1000.0 * 2f64.powf(0.4)).abs() < 15.0);

        let u = draws(&Dist::parse(Quantity::Time, "uniform(1s, 3s)").unwrap(), n);
        assert!(u[0] >= 1.0 && u[n - 1] < 3.0);
        assert!((mean(&u) - 2.0).abs() < 0.01);

        let c = draws(
            &Dist::parse(Quantity::Time, "normal(mean=1s, sd=200ms, max=1.2s)").unwrap(),
            n,
        );
        assert!(c[n - 1] <= 1.2);
    }

    #[test]
    fn same_seed_same_draws() {
        let d = Dist::parse(Quantity::Time, "lognormal(median=1s, sigma=2)").unwrap();
        let (mut a, mut b) = (DistRng::new(7), DistRng::new(7));
        for _ in 0..100 {
            assert_eq!(d.sample(&mut a), d.sample(&mut b));
        }
    }

    #[test]
    fn budgets() {
        let b = SessionBudget::requests(3);
        assert!(b.more(2, Duration::ZERO, 0));
        assert!(!b.more(3, Duration::ZERO, 0));
        let mut rng = DistRng::new(1);
        let t = SessionLength::Duration(Dist::time(Duration::from_secs(5)))
            .draw(&mut rng, Duration::from_secs(10));
        assert!(t.more(100, Duration::from_secs(14), 0));
        assert!(!t.more(0, Duration::from_secs(15), 0));
        let by = SessionLength::Bytes(Dist::fixed(Quantity::Bytes, 1000.0))
            .draw(&mut rng, Duration::ZERO);
        assert!(by.more(5, Duration::ZERO, 999));
        assert!(!by.more(5, Duration::ZERO, 1000));
        assert!(SessionLength::from_keys(Some("3"), Some("1s"), None).is_err());
    }

    #[test]
    fn count_stats() {
        let mut c = CountStats::default();
        for n in [1, 2, 3, 4, 5] {
            c.record(n);
        }
        assert_eq!(c.count(), 5);
        assert_eq!(c.percentile(0.5), Some(3));
        assert_eq!(c.mean(), Some(3.0));
        c.record(6);
        assert_eq!(c.mean(), Some(3.5), "with its fraction");
    }
}
