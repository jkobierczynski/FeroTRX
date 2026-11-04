//! Traffic models: how packets, connections or transactions are spread over
//! time around a mean rate.
//!
//! A [`TrafficModel`] adds three things to a plain rate:
//!
//! * **Arrivals**: evenly spaced (the default) or Poisson, with exponential
//!   gaps around the same mean.
//! * **Bursts**: `burst = N` sends N packets back to back, then waits; the
//!   bursts are spaced so the mean rate stays the same.
//! * **A rate shape over time**: a ramp up, a hold and a ramp down, or any
//!   list of points (`10s:50%`), straight lines between them. A shape that
//!   ends at 0% ends the traffic.
//!
//! The arithmetic is exact: the shape gives the rate `R·f(t)`, the work done
//! by time `t` is `R·∫f`, and each event is placed where that work reaches the
//! event's share. Evenly spaced packets at a flat rate land where the plain
//! [`Pacer`](crate::Pacer) put them before.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use crate::field_engine::{fresh_seed, next_random};
use crate::{parse_duration, Error, Result};

/// When events arrive around the mean rate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Arrivals {
    /// Evenly spaced.
    #[default]
    Even,
    /// A Poisson process: independent, exponentially distributed gaps.
    Poisson,
}

/// One point of a rate shape: at `at` after the start, the rate is
/// `factor` times the set rate (1.0 = 100%).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ShapePoint {
    pub at: Duration,
    pub factor: f64,
}

/// How events are spread over time around a rate. The default is evenly
/// spaced, no bursts, a flat rate: the plain behaviour.
///
/// Written as a comma separated list (`--model`, `model = "..."`):
///
/// ```text
/// poisson                         exponential gaps around the mean rate
/// even                            evenly spaced (default)
/// burst=32                        32 packets back to back, then a pause
/// ramp_up=10s,hold=1m,ramp_down=10s
///                                 0 -> 100% in 10 s, 1 minute flat, down
///                                 to 0 and stop
/// at=0s:20%,at=30s:100%,at=60s:0% the rate in points, straight lines
///                                 between them; after the last one the
///                                 rate stays, and 0% ends the traffic
/// seed=7                          repeatable Poisson gaps
/// ```
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TrafficModel {
    pub arrivals: Arrivals,
    /// Events per burst; 0 and 1 mean no bursts.
    pub burst: u32,
    /// The rate over time; empty is a flat 100%.
    pub shape: Vec<ShapePoint>,
    /// Seed of the random gaps; `None` picks a fresh one per run.
    pub seed: Option<u64>,
}

impl TrafficModel {
    /// Poisson arrivals at the mean rate.
    pub fn poisson() -> Self {
        Self {
            arrivals: Arrivals::Poisson,
            ..Self::default()
        }
    }

    /// True for the plain model: even, no bursts, flat.
    pub fn is_steady(&self) -> bool {
        self.arrivals == Arrivals::Even && self.burst <= 1 && self.shape.is_empty()
    }

    pub fn with_burst(mut self, burst: u32) -> Self {
        self.burst = burst;
        self
    }

    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    pub fn with_arrivals(mut self, arrivals: Arrivals) -> Self {
        self.arrivals = arrivals;
        self
    }

    /// A shape that ramps from 0 to the full rate in `up`, holds it for
    /// `hold` and, with `down`, ramps back to 0 in `down` and ends.
    pub fn with_ramp(mut self, up: Duration, hold: Duration, down: Option<Duration>) -> Self {
        self.shape = ramp_points(up, hold, down);
        self
    }

    /// Replaces the rate shape.
    pub fn with_shape(mut self, points: Vec<ShapePoint>) -> Self {
        self.shape = points;
        self
    }

    /// Checks the shape: points in time order, factors finite and not negative.
    pub fn validate(&self) -> Result<()> {
        let mut last = None;
        for p in &self.shape {
            if !(p.factor.is_finite() && p.factor >= 0.0) {
                return Err(model_err(format!(
                    "rate at {:?} must be 0% or more, not {}%",
                    p.at,
                    p.factor * 100.0
                )));
            }
            if last.is_some_and(|l| p.at < l) {
                return Err(model_err("shape points must be in time order".into()));
            }
            last = Some(p.at);
        }
        if !self.shape.is_empty() && self.shape.iter().all(|p| p.factor == 0.0) {
            return Err(model_err("the shape never sends: every point is 0%".into()));
        }
        Ok(())
    }

    /// When the shape ends (the last point, if it is 0%), from the start.
    pub fn ends_after(&self) -> Option<Duration> {
        match self.shape.last() {
            Some(p) if p.factor == 0.0 => Some(p.at),
            _ => None,
        }
    }

    /// The rate factor at `t` (1.0 = the set rate).
    pub fn factor_at(&self, t: Duration) -> f64 {
        Curve::new(&self.shape).factor_at(t.as_secs_f64())
    }

    /// A scheduler of events at `rate` per second under this model.
    pub fn schedule(&self, rate: f64) -> Schedule {
        Schedule::new(rate, self)
    }
}

fn ramp_points(up: Duration, hold: Duration, down: Option<Duration>) -> Vec<ShapePoint> {
    let mut points = vec![ShapePoint {
        at: Duration::ZERO,
        factor: if up.is_zero() { 1.0 } else { 0.0 },
    }];
    if !up.is_zero() {
        points.push(ShapePoint {
            at: up,
            factor: 1.0,
        });
    }
    if let Some(down) = down {
        let top = up + hold;
        if !hold.is_zero() {
            points.push(ShapePoint {
                at: top,
                factor: 1.0,
            });
        }
        points.push(ShapePoint {
            at: top + down,
            factor: 0.0,
        });
    }
    points
}

fn model_err(msg: String) -> Error {
    Error::InvalidSpec(format!("traffic model: {msg}"))
}

/// Parses `TIME:PERCENT`, such as `30s:50%` (or `30s:0.5`).
pub fn parse_shape_point(s: &str) -> Result<ShapePoint> {
    let bad = || {
        model_err(format!(
            "'{s}': a shape point is TIME:RATE, such as 30s:50%"
        ))
    };
    let (at, factor) = s.trim().split_once(':').ok_or_else(bad)?;
    let at = parse_duration(at)?;
    let factor = factor.trim();
    let factor = match factor.strip_suffix('%') {
        Some(pct) => pct.trim().parse::<f64>().map_err(|_| bad())? / 100.0,
        None => factor.parse::<f64>().map_err(|_| bad())?,
    };
    Ok(ShapePoint { at, factor })
}

impl FromStr for TrafficModel {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut m = TrafficModel::default();
        let (mut up, mut hold, mut down) = (None, None, None);
        for item in s.split(',').map(str::trim).filter(|i| !i.is_empty()) {
            let (key, value) = match item.split_once('=') {
                Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim()),
                None => (item.to_ascii_lowercase(), ""),
            };
            match (key.as_str(), value) {
                ("even" | "constant" | "steady", "") => m.arrivals = Arrivals::Even,
                ("poisson", "") => m.arrivals = Arrivals::Poisson,
                ("burst", v) => {
                    m.burst = v.parse().map_err(|_| {
                        model_err(format!("burst must be a number of packets, not '{v}'"))
                    })?
                }
                ("seed", v) => {
                    m.seed = Some(
                        v.parse()
                            .map_err(|_| model_err(format!("seed must be a number, not '{v}'")))?,
                    )
                }
                ("ramp_up" | "ramp-up" | "up", v) => up = Some(parse_duration(v)?),
                ("hold", v) => hold = Some(parse_duration(v)?),
                ("ramp_down" | "ramp-down" | "down", v) => down = Some(parse_duration(v)?),
                ("at" | "point", v) => m.shape.push(parse_shape_point(v)?),
                _ => {
                    return Err(model_err(format!(
                        "unknown '{item}': use poisson, even, burst=N, ramp_up=D, hold=D, \
                         ramp_down=D, at=TIME:RATE or seed=N"
                    )))
                }
            }
        }
        if up.is_some() || hold.is_some() || down.is_some() {
            if !m.shape.is_empty() {
                return Err(model_err(
                    "use either ramp_up/hold/ramp_down or at= points, not both".into(),
                ));
            }
            if hold.is_some() && down.is_none() {
                return Err(model_err(
                    "hold needs a ramp_down (without one the rate holds anyway)".into(),
                ));
            }
            m.shape = ramp_points(up.unwrap_or_default(), hold.unwrap_or_default(), down);
        }
        m.validate()?;
        Ok(m)
    }
}

impl fmt::Display for TrafficModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts: Vec<String> = Vec::new();
        if self.arrivals == Arrivals::Poisson {
            parts.push("poisson".into());
        }
        if self.burst > 1 {
            parts.push(format!("burst={}", self.burst));
        }
        for p in &self.shape {
            parts.push(format!(
                "at={}s:{}%",
                p.at.as_secs_f64(),
                (p.factor * 1e6).round() / 1e4
            ));
        }
        if let Some(seed) = self.seed {
            parts.push(format!("seed={seed}"));
        }
        if parts.is_empty() {
            parts.push("even".into());
        }
        f.write_str(&parts.join(","))
    }
}

/// The rate factor over time and its integral, in seconds.
#[derive(Clone, Debug)]
struct Curve {
    /// Linear pieces: start time, factor at the start, slope, integral so far.
    pieces: Vec<Piece>,
    /// The factor after the last piece.
    tail: f64,
    /// Where the tail starts, and the integral there.
    tail_t: f64,
    tail_w: f64,
}

#[derive(Clone, Copy, Debug)]
struct Piece {
    t0: f64,
    t1: f64,
    f0: f64,
    slope: f64,
    w0: f64,
}

impl Curve {
    fn new(points: &[ShapePoint]) -> Self {
        let mut pieces = Vec::new();
        let Some(first) = points.first() else {
            return Self {
                pieces,
                tail: 1.0,
                tail_t: 0.0,
                tail_w: 0.0,
            };
        };
        let (mut t, mut f, mut w) = (0.0, first.factor, 0.0);
        for p in points {
            let t1 = p.at.as_secs_f64();
            if t1 > t {
                let slope = (p.factor - f) / (t1 - t);
                pieces.push(Piece {
                    t0: t,
                    t1,
                    f0: f,
                    slope,
                    w0: w,
                });
                w += (f + p.factor) / 2.0 * (t1 - t);
            }
            t = t1;
            f = p.factor;
        }
        Self {
            pieces,
            tail: f,
            tail_t: t,
            tail_w: w,
        }
    }

    fn factor_at(&self, t: f64) -> f64 {
        for p in &self.pieces {
            if t < p.t1 {
                return p.f0 + p.slope * (t - p.t0).max(0.0);
            }
        }
        self.tail
    }

    /// The integral of the factor from 0 to `t`.
    fn work_at(&self, t: f64) -> f64 {
        for p in &self.pieces {
            if t < p.t1 {
                let d = (t - p.t0).max(0.0);
                return p.w0 + p.f0 * d + p.slope * d * d / 2.0;
            }
        }
        self.tail_w + self.tail * (t - self.tail_t).max(0.0)
    }

    /// The earliest time the integral reaches `w`, or `None` if it never does.
    fn time_at(&self, w: f64) -> Option<f64> {
        for p in &self.pieces {
            let rem = w - p.w0;
            if rem <= 0.0 {
                return Some(p.t0);
            }
            let d = p.t1 - p.t0;
            let span = p.f0 * d + p.slope * d * d / 2.0;
            if rem <= span {
                // Solve slope/2·τ² + f0·τ = rem, in the form that holds for
                // any slope sign and avoids dividing by a small slope.
                let disc = (p.f0 * p.f0 + 2.0 * p.slope * rem).max(0.0);
                let tau = 2.0 * rem / (p.f0 + disc.sqrt());
                return Some(p.t0 + tau.clamp(0.0, d));
            }
        }
        let rem = w - self.tail_w;
        if rem <= 0.0 {
            Some(self.tail_t)
        } else if self.tail > 0.0 {
            Some(self.tail_t + rem / self.tail)
        } else {
            None
        }
    }
}

/// Places events (packets, connections, transactions) in time under a
/// [`TrafficModel`], as offsets from the start.
///
/// Each event has a size in work units: 1 for "per second" rates, its bits
/// for bit rates. Call [`next`](Self::next) once per event with its size.
#[derive(Clone, Debug)]
pub struct Schedule {
    /// Work units per second at 100%.
    rate: f64,
    curve: Curve,
    flat: bool,
    poisson: bool,
    burst: u32,
    rng: u64,
    /// Work at which the current burst starts.
    start: f64,
    /// Work of the events of the current burst so far.
    burst_work: f64,
    in_burst: u32,
}

impl Schedule {
    /// A schedule of `rate` work units per second under `model`.
    pub fn new(rate: f64, model: &TrafficModel) -> Self {
        let burst = model.burst.max(1);
        Self {
            rate,
            curve: Curve::new(&model.shape),
            flat: model.shape.is_empty(),
            poisson: model.arrivals == Arrivals::Poisson,
            burst,
            rng: model.seed.unwrap_or_else(fresh_seed),
            start: 0.0,
            burst_work: 0.0,
            in_burst: burst,
        }
    }

    /// The time of the next event of `units` work, or `None` when the shape
    /// has ended.
    pub fn next(&mut self, units: f64) -> Option<Duration> {
        if self.in_burst >= self.burst {
            let gap = if self.poisson { self.exp1() } else { 1.0 };
            self.start += gap * self.burst_work;
            self.burst_work = 0.0;
            self.in_burst = 0;
        }
        let at = self.time_of(self.start);
        self.burst_work += units;
        self.in_burst += 1;
        at
    }

    /// Does not save up events while the caller could not keep up: moves the
    /// schedule so that at most one event is owed at `now`, and returns the
    /// new time of the pending event (the one [`next`](Self::next) returned last).
    pub fn hold(&mut self, now: Duration) -> Option<Duration> {
        let owed = self.curve.work_at(now.as_secs_f64()) * self.rate - 1.0;
        if owed > self.start {
            self.start = owed;
        }
        self.time_of(self.start)
    }

    fn time_of(&self, work: f64) -> Option<Duration> {
        let t = if self.flat {
            Some(work / self.rate)
        } else {
            self.curve.time_at(work / self.rate)
        }?;
        Duration::try_from_secs_f64(t).ok()
    }

    /// An exponential random number with mean 1.
    fn exp1(&mut self) -> f64 {
        // 53 random bits in [0, 1); 1 - u is in (0, 1], so ln never sees 0.
        let u = (next_random(&mut self.rng) >> 11) as f64 / (1u64 << 53) as f64;
        -(1.0 - u).ln()
    }
}

/// A [`Schedule`] of events one unit each, from a start time on: the
/// helper the TCP and UDP engines open connections and transactions with.
#[derive(Clone, Debug)]
pub(crate) struct EventClock {
    model: TrafficModel,
    rate: f64,
    sched: Schedule,
    origin: Duration,
    next: Option<Duration>,
}

impl EventClock {
    pub(crate) fn new(rate: f64, model: &TrafficModel) -> Self {
        Self {
            model: model.clone(),
            rate,
            sched: model.schedule(rate),
            origin: Duration::ZERO,
            next: Some(Duration::ZERO),
        }
    }

    /// Starts the schedule over at `now`.
    pub(crate) fn start(&mut self, now: Duration) {
        self.sched = self.model.schedule(self.rate);
        self.origin = now;
        self.next = self.sched.next(1.0).map(|t| now + t);
    }

    /// True if an event is due at `now`.
    pub(crate) fn due(&self, now: Duration) -> bool {
        self.next.is_some_and(|n| n <= now)
    }

    /// True once the shape has ended and no events are left.
    pub(crate) fn ended(&self) -> bool {
        self.next.is_none()
    }

    /// The event happened; schedules the next one.
    pub(crate) fn advance(&mut self) {
        self.next = self.sched.next(1.0).map(|t| self.origin + t);
    }

    /// The caller is at a limit: do not save up events.
    pub(crate) fn hold(&mut self, now: Duration) {
        if self.next.is_some() {
            self.next = self
                .sched
                .hold(now.saturating_sub(self.origin))
                .map(|t| self.origin + t);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn times(model: &TrafficModel, rate: f64, n: usize) -> Vec<f64> {
        let mut s = model.schedule(rate);
        (0..n)
            .map_while(|_| s.next(1.0).map(|d| d.as_secs_f64()))
            .collect()
    }

    #[test]
    fn steady_is_evenly_spaced() {
        let t = times(&TrafficModel::default(), 1000.0, 4);
        assert_eq!(t, vec![0.0, 0.001, 0.002, 0.003]);
    }

    #[test]
    fn poisson_keeps_the_mean_and_varies_gaps() {
        let m = TrafficModel::poisson().with_seed(42);
        let t = times(&m, 1000.0, 20_001);
        let mean = t[20_000] / 20_000.0;
        assert!((mean - 0.001).abs() < 0.00005, "mean gap {mean}");
        let gaps: Vec<f64> = t.windows(2).map(|w| w[1] - w[0]).collect();
        let var = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
        // Exponential gaps: the standard deviation equals the mean.
        assert!(
            (var.sqrt() / mean - 1.0).abs() < 0.05,
            "cv {}",
            var.sqrt() / mean
        );
        // The same seed gives the same gaps.
        assert_eq!(times(&m, 1000.0, 50), t[..50].to_vec());
    }

    #[test]
    fn bursts_go_back_to_back_at_the_mean_rate() {
        let m = TrafficModel::default().with_burst(4);
        let t = times(&m, 1000.0, 12);
        assert_eq!(&t[0..4], &[0.0; 4]);
        assert!(t[4..8].iter().all(|&x| (x - 0.004).abs() < 1e-12));
        assert!(t[8..12].iter().all(|&x| (x - 0.008).abs() < 1e-12));
    }

    #[test]
    fn ramp_up_hold_and_down() {
        let m: TrafficModel = "ramp_up=10s,hold=10s,ramp_down=10s".parse().unwrap();
        assert_eq!(m.ends_after(), Some(Duration::from_secs(30)));
        // 10 events per second at 100%: 50 during the ramp up, 100 while
        // holding, 50 ramping down, then the shape ends.
        let t = times(&m, 10.0, 1000);
        assert_eq!(t.len(), 201, "{:?}", &t[t.len() - 3..]);
        // The ramp up: n events by t = 10·t²/20, so event 50 at 10 s.
        assert!((t[50] - 10.0).abs() < 1e-9);
        assert!((t[8] - (8.0f64 * 2.0).sqrt()).abs() < 1e-9);
        assert!((t[150] - 20.0).abs() < 1e-9);
        assert!((t[200] - 30.0).abs() < 1e-6);
        assert!(t.windows(2).all(|w| w[1] >= w[0]));
    }

    #[test]
    fn shape_points_and_factor() {
        let m: TrafficModel = "at=0s:50%,at=10s:100%,poisson,seed=1".parse().unwrap();
        assert_eq!(m.arrivals, Arrivals::Poisson);
        assert!((m.factor_at(Duration::from_secs(5)) - 0.75).abs() < 1e-12);
        assert_eq!(m.factor_at(Duration::from_secs(60)), 1.0);
        assert_eq!(m.ends_after(), None);
        let flat_first: TrafficModel = "at=5s:20%,at=6s:100%".parse().unwrap();
        // Before the first point the rate is that point's.
        assert!((flat_first.factor_at(Duration::from_secs(1)) - 0.2).abs() < 1e-12);
        let t = times(&flat_first, 10.0, 3);
        assert!((t[1] - 0.5).abs() < 1e-9, "{t:?}");
    }

    #[test]
    fn models_parse_and_print() {
        for text in [
            "poisson",
            "even,burst=8",
            "poisson,burst=4,at=0s:0%,at=2.5s:100%,seed=9",
        ] {
            let m: TrafficModel = text.parse().unwrap();
            let again: TrafficModel = m.to_string().parse().unwrap();
            assert_eq!(m, again, "{text}");
        }
        assert!("".parse::<TrafficModel>().unwrap().is_steady());
        for bad in [
            "fast",
            "burst=x",
            "hold=5s",
            "at=5s",
            "at=5s:-10%",
            "at=5s:10%,at=1s:20%",
            "at=0s:0%",
            "ramp_up=1s,at=0s:10%",
        ] {
            assert!(bad.parse::<TrafficModel>().is_err(), "{bad}");
        }
    }

    #[test]
    fn hold_owes_at_most_one_event() {
        let mut c = EventClock::new(10.0, &TrafficModel::default());
        c.start(Duration::ZERO);
        assert!(c.due(Duration::ZERO));
        c.advance();
        // A long stall: afterwards only the event one gap back and the one
        // now are due, as the engines had it before models.
        let now = Duration::from_secs(5);
        c.hold(now);
        assert!(c.due(now));
        c.advance();
        assert!(c.due(now));
        c.advance();
        assert!(!c.due(now));
        assert!(c.due(now + Duration::from_millis(100)));
    }

    #[test]
    fn clock_ends_with_the_shape() {
        let m: TrafficModel = "ramp_up=0s,hold=1s,ramp_down=0s".parse().unwrap();
        let mut c = EventClock::new(5.0, &m);
        c.start(Duration::from_secs(100));
        let mut n = 0;
        while !c.ended() && n < 100 {
            n += 1;
            c.advance();
        }
        // Events at 0, 0.2, ... 1.0 s: the one at the very end still counts.
        assert_eq!(n, 6);
    }
}
