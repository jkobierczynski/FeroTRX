//! Built-in impairments: what a bad link does to frames, without netem.
//!
//! An [`Impairer`] holds frames as a link would and lets them out later, or
//! not at all: it delays them (with jitter), loses them (at random or in
//! bursts), duplicates, reorders and corrupts them, sends them no faster than
//! a rate, and drops or cuts frames over an MTU. It is sans-IO: it reads no
//! clock, and the caller gives it the time with each frame and asks for the
//! frames that are due. Everything random comes from a seed, so a run with the
//! same seed and the same frames at the same times impairs them the same way.
//!
//! [`ImpairPort`] puts impairers on a [`PacketPort`] (frames sent, frames
//! received or both), which is how TCP, UDP and host runs and the two-port
//! bridge ([`run_bridge`]) use them; streams have their own
//! ([`Stream::impair`](crate::Stream::impair)).
//!
//! The spec is text, as on the command line:
//!
//! ```
//! use ferotrx_core::ImpairSpec;
//! let spec: ImpairSpec = "delay=20ms jitter=5ms loss=1% loss_burst=3 rate=10mbit seed=7"
//!     .parse()
//!     .unwrap();
//! assert_eq!(spec.loss, 0.01);
//! assert_eq!(spec.rate, Some(10e6));
//! ```

use std::cmp::Ordering as CmpOrdering;
use std::collections::BinaryHeap;
use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::field_engine::{fresh_seed, next_random};
use crate::latency::LatencyStats;
use crate::net::{self, IPPROTO_TCP, IPPROTO_UDP};
use crate::{
    parse_duration, Error, MergeStats, PacketPort, Result, SinkError, FCS_LEN, L1_OVERHEAD,
};

/// How the jitter spreads the delay of each frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum JitterDist {
    /// Evenly between `delay - jitter` and `delay + jitter`.
    #[default]
    Uniform,
    /// Normal around `delay`, with `jitter` as the standard deviation.
    Normal,
    /// `delay` at least, plus a long tail (Pareto, shape 3) whose mean is
    /// `jitter`: most frames come quickly and a few very late, as on a busy
    /// queue.
    Pareto,
}

impl JitterDist {
    fn name(self) -> &'static str {
        match self {
            JitterDist::Uniform => "uniform",
            JitterDist::Normal => "normal",
            JitterDist::Pareto => "pareto",
        }
    }
}

impl FromStr for JitterDist {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "uniform" => Ok(JitterDist::Uniform),
            "normal" => Ok(JitterDist::Normal),
            "pareto" => Ok(JitterDist::Pareto),
            other => Err(spec_err(format!(
                "distribution '{other}': use uniform, normal or pareto"
            ))),
        }
    }
}

/// What happens to a frame bigger than the MTU.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MtuAction {
    /// The frame is dropped, as a link that cannot carry it does.
    #[default]
    Drop,
    /// The frame is cut to the MTU, its headers left as they were.
    Truncate,
}

/// What an [`Impairer`] does, as text `key=value` pairs separated by spaces or
/// commas (see [`FromStr`](#impl-FromStr-for-ImpairSpec)).
#[derive(Clone, Debug, PartialEq)]
pub struct ImpairSpec {
    /// Added to every frame.
    pub delay: Duration,
    /// How far the delay varies around `delay`; see [`JitterDist`].
    pub jitter: Duration,
    pub distribution: JitterDist,
    /// How much each frame's jitter follows the last one's, 0 to 1.
    pub correlation: f64,
    /// Frames lost, as a share (0 to 1).
    pub loss: f64,
    /// The mean length of a loss burst, in frames; `None` for random loss.
    /// With it, loss follows a Gilbert-Elliott model: a good state that
    /// loses nothing and a bad state that loses `loss_bad` of the frames,
    /// left after `loss_burst / loss_bad` frames on average.
    pub loss_burst: Option<f64>,
    /// The share of frames lost in the bad state of a bursty loss (default 1).
    pub loss_bad: f64,
    /// Frames sent twice, as a share.
    pub duplicate: f64,
    /// Frames that skip the delay and so pass the ones before them, as a
    /// share. Needs a delay.
    pub reorder: f64,
    /// Frames with one bit flipped, as a share. The bit is in the payload
    /// past the TCP or UDP header where there is one.
    pub corrupt: f64,
    /// Recompute the IP and TCP/UDP checksums of corrupted frames, so that
    /// the corruption reaches the application instead of being dropped at
    /// the first checksum check.
    pub fix_checksums: bool,
    /// The link's rate in bits per second (each frame with 24 bytes of
    /// preamble, gap and FCS); frames queue for it after the delay.
    pub rate: Option<f64>,
    /// The most frames held at once; more are dropped (tail drop).
    pub limit: usize,
    /// The largest IP packet (frame after its Ethernet and VLAN headers).
    pub mtu: Option<usize>,
    pub mtu_action: MtuAction,
    /// Keep the frames in order through the jitter (default), as one queue
    /// does; `false` lets a frame with less delay pass one with more.
    pub keep_order: bool,
    /// Seed of the random numbers; `None` for a fresh one each run.
    pub seed: Option<u64>,
}

/// Frames an impairer holds at most when the spec does not say.
pub const DEFAULT_IMPAIR_LIMIT: usize = 10_000;

impl Default for ImpairSpec {
    fn default() -> Self {
        Self {
            delay: Duration::ZERO,
            jitter: Duration::ZERO,
            distribution: JitterDist::Uniform,
            correlation: 0.0,
            loss: 0.0,
            loss_burst: None,
            loss_bad: 1.0,
            duplicate: 0.0,
            reorder: 0.0,
            corrupt: 0.0,
            fix_checksums: false,
            rate: None,
            limit: DEFAULT_IMPAIR_LIMIT,
            mtu: None,
            mtu_action: MtuAction::Drop,
            keep_order: true,
            seed: None,
        }
    }
}

fn spec_err(msg: String) -> Error {
    Error::InvalidSpec(format!("impairment: {msg}"))
}

/// A share: `1%`, `0.5%` or `0.01`.
fn parse_share(key: &str, v: &str) -> Result<f64> {
    let bad = || {
        spec_err(format!(
            "{key}={v}: use a percentage (1%) or a share (0.01)"
        ))
    };
    let x = match v.strip_suffix('%') {
        Some(p) => p.trim().parse::<f64>().map_err(|_| bad())? / 100.0,
        None => v.parse::<f64>().map_err(|_| bad())?,
    };
    if !(0.0..=1.0).contains(&x) {
        return Err(spec_err(format!("{key}={v} must be between 0 and 100%")));
    }
    Ok(x)
}

/// A rate in bits per second: `10mbit`, `1gbit`, `500kbit`, `64000bit`, or
/// with `bps` (bits, as for stream rates).
pub fn parse_bit_rate(v: &str) -> Result<f64> {
    let t = v.trim().to_ascii_lowercase();
    let t = t.strip_suffix("/s").unwrap_or(&t);
    let num = t
        .strip_suffix("bit")
        .or_else(|| t.strip_suffix("bps"))
        .ok_or_else(|| spec_err(format!("rate={v}: use e.g. 10mbit, 1gbit, 500kbit")))?;
    let (num, scale) = match num.chars().last() {
        Some('k') => (&num[..num.len() - 1], 1e3),
        Some('m') => (&num[..num.len() - 1], 1e6),
        Some('g') => (&num[..num.len() - 1], 1e9),
        _ => (num, 1.0),
    };
    let x: f64 = num
        .trim()
        .parse()
        .map_err(|_| spec_err(format!("rate={v} is not a number")))?;
    if !(x.is_finite() && x > 0.0) {
        return Err(spec_err(format!("rate={v} must be positive")));
    }
    Ok(x * scale)
}

fn parse_bool(key: &str, v: &str) -> Result<bool> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => Err(spec_err(format!("{key}={v}: use true or false"))),
    }
}

impl ImpairSpec {
    /// True when the spec does nothing to frames.
    pub fn is_none(&self) -> bool {
        self.delay.is_zero()
            && self.jitter.is_zero()
            && self.loss == 0.0
            && self.duplicate == 0.0
            && self.reorder == 0.0
            && self.corrupt == 0.0
            && self.rate.is_none()
            && self.mtu.is_none()
    }

    /// Sets one `key` to `value`, as in the text form.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let v = value.trim();
        let dur = |v: &str| parse_duration(v).map_err(|e| spec_err(format!("{key}: {e}")));
        let num = |v: &str| {
            v.parse::<f64>()
                .ok()
                .filter(|x| x.is_finite())
                .ok_or_else(|| spec_err(format!("{key}={v} is not a number")))
        };
        match key.trim() {
            "delay" => self.delay = dur(v)?,
            "jitter" => self.jitter = dur(v)?,
            "distribution" | "dist" => self.distribution = v.parse()?,
            "correlation" => self.correlation = parse_share(key, v)?,
            "loss" => self.loss = parse_share(key, v)?,
            "loss_burst" => self.loss_burst = Some(num(v)?),
            "loss_bad" => self.loss_bad = parse_share(key, v)?,
            "duplicate" => self.duplicate = parse_share(key, v)?,
            "reorder" => self.reorder = parse_share(key, v)?,
            "corrupt" => self.corrupt = parse_share(key, v)?,
            "fix_checksums" => self.fix_checksums = parse_bool(key, v)?,
            "rate" => self.rate = Some(parse_bit_rate(v)?),
            "limit" => {
                self.limit = v
                    .parse()
                    .map_err(|_| spec_err(format!("limit={v} is not a whole number")))?
            }
            "mtu" => {
                self.mtu = Some(
                    v.parse()
                        .map_err(|_| spec_err(format!("mtu={v} is not a whole number")))?,
                )
            }
            "mtu_action" => {
                self.mtu_action = match v.to_ascii_lowercase().as_str() {
                    "drop" => MtuAction::Drop,
                    "truncate" => MtuAction::Truncate,
                    _ => return Err(spec_err(format!("mtu_action={v}: use drop or truncate"))),
                }
            }
            "keep_order" => self.keep_order = parse_bool(key, v)?,
            "seed" => {
                self.seed = Some(
                    v.parse()
                        .map_err(|_| spec_err(format!("seed={v} is not a whole number")))?,
                )
            }
            other => {
                return Err(spec_err(format!(
                    "unknown key '{other}' (delay, jitter, distribution, correlation, loss, \
                     loss_burst, loss_bad, duplicate, reorder, corrupt, fix_checksums, rate, \
                     limit, mtu, mtu_action, keep_order, seed)"
                )))
            }
        }
        Ok(())
    }

    /// Checks that the values make sense together.
    pub fn validate(&self) -> Result<()> {
        if let Some(b) = self.loss_burst {
            if b < 1.0 {
                return Err(spec_err(format!("loss_burst={b} must be 1 or more")));
            }
            if self.loss > 0.0 && self.loss_bad <= 0.0 {
                return Err(spec_err("loss_bad must be more than 0".into()));
            }
            if self.loss >= self.loss_bad && self.loss > 0.0 {
                return Err(spec_err(format!(
                    "loss={} must be less than loss_bad={} with bursts",
                    self.loss, self.loss_bad
                )));
            }
        }
        if self.reorder > 0.0 && self.delay.is_zero() {
            return Err(spec_err(
                "reorder needs a delay: reordered frames skip it to pass the others".into(),
            ));
        }
        if self.limit == 0 {
            return Err(spec_err("limit must be at least 1".into()));
        }
        if let Some(m) = self.mtu {
            if m < 20 {
                return Err(spec_err(format!("mtu={m} is too small (at least 20)")));
            }
        }
        Ok(())
    }

    /// The same spec with `seed` set from `seed` and `index` (one per worker
    /// or direction) when it has one, so that each impairer draws its own
    /// numbers.
    pub fn for_lane(&self, index: usize) -> Self {
        let mut s = self.clone();
        s.seed = self.seed.map(|seed| crate::worker_seed(seed, index));
        s
    }
}

/// Parses `key=value` pairs separated by spaces or commas, for example
/// `delay=20ms jitter=5ms distribution=normal loss=1% loss_burst=3
/// duplicate=0.1% reorder=0.5% corrupt=0.01% rate=10mbit limit=1000 mtu=1400
/// seed=1`. An empty string or `none` is no impairment.
impl FromStr for ImpairSpec {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut spec = ImpairSpec::default();
        let t = s.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("none") {
            return Ok(spec);
        }
        for part in t.split([' ', ',', '\t', '\n']).filter(|p| !p.is_empty()) {
            let (k, v) = part
                .split_once('=')
                .ok_or_else(|| spec_err(format!("'{part}' is not key=value")))?;
            spec.set(k, v)?;
        }
        spec.validate()?;
        Ok(spec)
    }
}

fn pct(x: f64) -> String {
    format!("{}%", (x * 1e6).round() / 1e4)
}

fn fmt_dur(d: Duration) -> String {
    let us = d.as_micros();
    if us.is_multiple_of(1000) {
        format!("{}ms", us / 1000)
    } else {
        format!("{us}us")
    }
}

/// The text form, which [`FromStr`] reads back; `none` for no impairment.
impl fmt::Display for ImpairSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = ImpairSpec::default();
        let mut parts = Vec::new();
        if !self.delay.is_zero() {
            parts.push(format!("delay={}", fmt_dur(self.delay)));
        }
        if !self.jitter.is_zero() {
            parts.push(format!("jitter={}", fmt_dur(self.jitter)));
        }
        if self.distribution != d.distribution {
            parts.push(format!("distribution={}", self.distribution.name()));
        }
        if self.correlation != 0.0 {
            parts.push(format!("correlation={}", pct(self.correlation)));
        }
        if self.loss != 0.0 {
            parts.push(format!("loss={}", pct(self.loss)));
        }
        if let Some(b) = self.loss_burst {
            parts.push(format!("loss_burst={b}"));
        }
        if self.loss_bad != 1.0 {
            parts.push(format!("loss_bad={}", pct(self.loss_bad)));
        }
        for (k, v) in [
            ("duplicate", self.duplicate),
            ("reorder", self.reorder),
            ("corrupt", self.corrupt),
        ] {
            if v != 0.0 {
                parts.push(format!("{k}={}", pct(v)));
            }
        }
        if self.fix_checksums {
            parts.push("fix_checksums=true".into());
        }
        if let Some(r) = self.rate {
            parts.push(format!("rate={r}bit"));
        }
        if self.limit != d.limit {
            parts.push(format!("limit={}", self.limit));
        }
        if let Some(m) = self.mtu {
            parts.push(format!("mtu={m}"));
        }
        if self.mtu_action == MtuAction::Truncate {
            parts.push("mtu_action=truncate".into());
        }
        if !self.keep_order {
            parts.push("keep_order=false".into());
        }
        if let Some(s) = self.seed {
            parts.push(format!("seed={s}"));
        }
        if parts.is_empty() {
            f.write_str("none")
        } else {
            f.write_str(&parts.join(" "))
        }
    }
}

/// What an [`Impairer`] did.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ImpairStats {
    /// Frames and bytes that came in.
    pub packets: u64,
    pub bytes: u64,
    /// Frames that went out (duplicates included).
    pub passed: u64,
    /// Frames lost by the loss model.
    pub lost: u64,
    /// Frames over the MTU that were dropped, or cut.
    pub mtu_dropped: u64,
    pub truncated: u64,
    /// Frames dropped because the queue held `limit` already.
    pub queue_dropped: u64,
    pub duplicated: u64,
    pub corrupted: u64,
    /// Frames sent ahead of earlier ones.
    pub reordered: u64,
    /// Frames held now, and the most held at once.
    pub held: u64,
    pub max_held: u64,
    /// The time frames were held, delay and rate queue together.
    pub delay: LatencyStats,
}

impl ImpairStats {
    /// Frames that did not go out: lost, over the MTU or over the limit.
    pub fn dropped(&self) -> u64 {
        self.lost + self.mtu_dropped + self.queue_dropped
    }

    /// True when nothing came in.
    pub fn is_empty(&self) -> bool {
        self.packets == 0
    }
}

impl MergeStats for ImpairStats {
    fn merge(&mut self, o: &Self) {
        self.packets += o.packets;
        self.bytes += o.bytes;
        self.passed += o.passed;
        self.lost += o.lost;
        self.mtu_dropped += o.mtu_dropped;
        self.truncated += o.truncated;
        self.queue_dropped += o.queue_dropped;
        self.duplicated += o.duplicated;
        self.corrupted += o.corrupted;
        self.reordered += o.reordered;
        self.held += o.held;
        self.max_held = self.max_held.max(o.max_held);
        self.delay.merge(&o.delay);
    }
}

/// One line: `1000 in, 990 out, 10 lost, delay ms avg 20.1 max 25.0`.
impl fmt::Display for ImpairStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} in, {} out", self.packets, self.passed)?;
        for (n, what) in [
            (self.lost, "lost"),
            (self.mtu_dropped, "over the MTU"),
            (self.truncated, "cut to the MTU"),
            (self.queue_dropped, "over the queue limit"),
            (self.duplicated, "duplicated"),
            (self.reordered, "reordered"),
            (self.corrupted, "corrupted"),
            (self.held, "still held"),
        ] {
            if n > 0 {
                write!(f, ", {n} {what}")?;
            }
        }
        if let (Some(avg), Some(min), Some(max)) =
            (self.delay.mean(), self.delay.min(), self.delay.max())
        {
            let ms = |d: Duration| d.as_secs_f64() * 1000.0;
            write!(
                f,
                ", held ms avg {:.2} min {:.2} max {:.2}",
                ms(avg),
                ms(min),
                ms(max)
            )?;
        }
        Ok(())
    }
}

/// The impairments of a port's two directions: frames FeroTRX sent (`tx`)
/// and frames it received (`rx`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PortImpairStats {
    pub tx: ImpairStats,
    pub rx: ImpairStats,
}

impl PortImpairStats {
    /// True when no frame went through an impairer.
    pub fn is_empty(&self) -> bool {
        self.tx.is_empty() && self.rx.is_empty()
    }
}

impl MergeStats for PortImpairStats {
    fn merge(&mut self, o: &Self) {
        self.tx.merge(&o.tx);
        self.rx.merge(&o.rx);
    }
}

struct Held {
    due: Duration,
    seq: u64,
    pushed: Duration,
    frame: Vec<u8>,
}

impl PartialEq for Held {
    fn eq(&self, o: &Self) -> bool {
        (self.due, self.seq) == (o.due, o.seq)
    }
}
impl Eq for Held {}
impl PartialOrd for Held {
    fn partial_cmp(&self, o: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(o))
    }
}
impl Ord for Held {
    // Reversed: the heap's top is the earliest frame.
    fn cmp(&self, o: &Self) -> CmpOrdering {
        (o.due, o.seq).cmp(&(self.due, self.seq))
    }
}

/// A link that impairs frames; see the [module docs](self).
///
/// ```
/// use ferotrx_core::{ImpairSpec, Impairer};
/// use std::time::Duration;
///
/// let mut link = Impairer::new("delay=10ms".parse().unwrap());
/// link.push(&[0u8; 60], Duration::ZERO);
/// assert!(link.pop_due(Duration::from_millis(9)).is_none());
/// assert_eq!(link.next_due(), Some(Duration::from_millis(10)));
/// assert_eq!(link.pop_due(Duration::from_millis(10)).unwrap().len(), 60);
/// ```
pub struct Impairer {
    spec: ImpairSpec,
    rng: u64,
    /// Bursty loss: in the bad state.
    bad: bool,
    /// Gilbert-Elliott transitions: good to bad, bad to good.
    p: f64,
    r: f64,
    /// The last jitter drawn, in seconds, for correlation.
    last_jitter: f64,
    queue: BinaryHeap<Held>,
    seq: u64,
    /// The latest due time of an in-order frame.
    last_due: Duration,
    /// When the rate-limited link is free again.
    link_free: Duration,
    stats: ImpairStats,
}

impl fmt::Debug for Impairer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Impairer")
            .field("spec", &self.spec.to_string())
            .field("held", &self.queue.len())
            .finish_non_exhaustive()
    }
}

impl Impairer {
    /// An impairer for `spec`, which should have passed
    /// [`validate`](ImpairSpec::validate) (parsing does that).
    pub fn new(spec: ImpairSpec) -> Self {
        let (p, r) = match spec.loss_burst {
            Some(len) if spec.loss > 0.0 => {
                // The bad state lasts len / loss_bad frames on average, and the
                // share of time in it gives `loss` overall.
                let r = (spec.loss_bad / len).min(1.0);
                let bad = spec.loss / spec.loss_bad;
                ((bad * r / (1.0 - bad)).min(1.0), r)
            }
            _ => (0.0, 1.0),
        };
        Self {
            rng: spec.seed.unwrap_or_else(fresh_seed),
            spec,
            bad: false,
            p,
            r,
            last_jitter: 0.0,
            queue: BinaryHeap::new(),
            seq: 0,
            last_due: Duration::ZERO,
            link_free: Duration::ZERO,
            stats: ImpairStats::default(),
        }
    }

    pub fn spec(&self) -> &ImpairSpec {
        &self.spec
    }

    pub fn stats(&self) -> &ImpairStats {
        &self.stats
    }

    /// Frames held now.
    pub fn held(&self) -> usize {
        self.queue.len()
    }

    /// A random number in [0, 1).
    fn uniform(&mut self) -> f64 {
        (next_random(&mut self.rng) >> 11) as f64 / (1u64 << 53) as f64
    }

    fn chance(&mut self, share: f64) -> bool {
        share > 0.0 && self.uniform() < share
    }

    fn lose(&mut self) -> bool {
        if self.spec.loss == 0.0 {
            return false;
        }
        if self.spec.loss_burst.is_none() {
            return self.chance(self.spec.loss);
        }
        // Move between the states first, then lose in the state we are in.
        let flip = if self.bad { self.r } else { self.p };
        if self.chance(flip) {
            self.bad = !self.bad;
        }
        self.bad && (self.spec.loss_bad >= 1.0 || self.chance(self.spec.loss_bad))
    }

    /// The delay of the next frame.
    fn draw_delay(&mut self) -> Duration {
        let base = self.spec.delay.as_secs_f64();
        let j = self.spec.jitter.as_secs_f64();
        if j == 0.0 {
            return self.spec.delay;
        }
        let fresh = match self.spec.distribution {
            JitterDist::Uniform => (self.uniform() * 2.0 - 1.0) * j,
            JitterDist::Normal => {
                // Box-Muller; 1 - u is never 0.
                let u1 = 1.0 - self.uniform();
                let u2 = self.uniform();
                (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos() * j
            }
            JitterDist::Pareto => {
                // Pareto with shape 3 and scale 2j has mean 3j; less its scale,
                // the extra delay has mean j.
                const ALPHA: f64 = 3.0;
                let xm = j * (ALPHA - 1.0);
                let u = 1.0 - self.uniform();
                xm / u.powf(1.0 / ALPHA) - xm
            }
        };
        let c = self.spec.correlation;
        let jitter = if c > 0.0 {
            c * self.last_jitter + (1.0 - c) * fresh
        } else {
            fresh
        };
        self.last_jitter = jitter;
        Duration::from_secs_f64((base + jitter).max(0.0))
    }

    /// Takes in one frame at `now`.
    pub fn push(&mut self, frame: &[u8], now: Duration) {
        self.stats.packets += 1;
        self.stats.bytes += frame.len() as u64;
        let mut frame = frame.to_vec();
        if let Some(mtu) = self.spec.mtu {
            let l3 = net::l3_offset(&frame).map_or(net::ETH_HEADER, |(off, _)| off);
            if frame.len() > l3 + mtu {
                match self.spec.mtu_action {
                    MtuAction::Drop => {
                        self.stats.mtu_dropped += 1;
                        return;
                    }
                    MtuAction::Truncate => {
                        frame.truncate(l3 + mtu);
                        self.stats.truncated += 1;
                    }
                }
            }
        }
        if self.lose() {
            self.stats.lost += 1;
            return;
        }
        let copies = if self.chance(self.spec.duplicate) {
            self.stats.duplicated += 1;
            2
        } else {
            1
        };
        if self.chance(self.spec.corrupt) {
            self.corrupt(&mut frame);
            self.stats.corrupted += 1;
        }
        for k in 0..copies {
            let f = if k + 1 == copies {
                std::mem::take(&mut frame)
            } else {
                frame.clone()
            };
            self.hold(f, now);
        }
    }

    fn hold(&mut self, frame: Vec<u8>, now: Duration) {
        if self.queue.len() >= self.spec.limit {
            self.stats.queue_dropped += 1;
            return;
        }
        let reorder = self.chance(self.spec.reorder);
        let mut due = if reorder {
            now
        } else {
            let d = now + self.draw_delay();
            if self.spec.keep_order {
                d.max(self.last_due)
            } else {
                d
            }
        };
        if let Some(rate) = self.spec.rate {
            let bits = ((frame.len() + L1_OVERHEAD + FCS_LEN) * 8) as f64;
            let start = due.max(self.link_free);
            due = start + Duration::from_secs_f64(bits / rate);
            self.link_free = due;
        }
        if reorder {
            if due < self.last_due {
                self.stats.reordered += 1;
            }
        } else {
            self.last_due = self.last_due.max(due);
        }
        self.seq += 1;
        self.queue.push(Held {
            due,
            seq: self.seq,
            pushed: now,
            frame,
        });
        self.stats.held = self.queue.len() as u64;
        self.stats.max_held = self.stats.max_held.max(self.stats.held);
    }

    /// Flips one random bit: in the payload past the TCP or UDP header if
    /// there is one, else past the IP header, else past the Ethernet header.
    fn corrupt(&mut self, frame: &mut [u8]) {
        let start = match net::parse(frame).and_then(|l| l.ip) {
            Some(ip) => match ip.l4 {
                Some((IPPROTO_UDP, at)) => at + 8,
                Some((IPPROTO_TCP, at)) => {
                    at + frame.get(at + 12).map_or(20, |b| usize::from(b >> 4) * 4)
                }
                Some((_, at)) => at,
                None => ip.start + ip.header_len,
            },
            None => net::ETH_HEADER,
        };
        let end = net::parse(frame)
            .and_then(|l| l.ip)
            .and_then(|ip| ip.end)
            .unwrap_or(frame.len());
        let start = if start < end {
            start
        } else {
            net::ETH_HEADER.min(frame.len())
        };
        if start >= end {
            return;
        }
        let bit = next_random(&mut self.rng) as usize % ((end - start) * 8);
        frame[start + bit / 8] ^= 1 << (bit % 8);
        if self.spec.fix_checksums {
            net::fix_checksums(frame);
        }
    }

    /// When the next held frame is due.
    pub fn next_due(&self) -> Option<Duration> {
        self.queue.peek().map(|h| h.due)
    }

    /// The next frame due by `now`, if any.
    pub fn pop_due(&mut self, now: Duration) -> Option<Vec<u8>> {
        if self.queue.peek()?.due > now {
            return None;
        }
        let h = self.queue.pop()?;
        self.stats.passed += 1;
        self.stats.held = self.queue.len() as u64;
        self.stats
            .delay
            .record(Some(h.due.saturating_sub(h.pushed)));
        Some(h.frame)
    }

    /// Lets go of every held frame now, due or not, as when a run ends.
    pub fn drain_all(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(self.queue.len());
        while let Some(due) = self.next_due() {
            out.extend(self.pop_due(due));
        }
        out
    }
}

/// Shared counters of an [`ImpairPort`], readable while it runs.
pub type ImpairMonitor = Arc<Mutex<PortImpairStats>>;

/// How often an [`ImpairPort`] updates its [`ImpairMonitor`].
const PUBLISH_EVERY: Duration = Duration::from_millis(100);

/// Frames an [`ImpairPort`] reads from its port per `recv` before it hands
/// one out.
const RX_DRAIN: usize = 256;

/// A [`PacketPort`] with impairments on the frames it sends (`tx`), on the
/// frames it receives (`rx`), or both.
///
/// Held frames leave when they are due, as the port is used: frames sent at
/// `send` and `flush`, frames received at `recv`. The engines that use ports
/// do so every fraction of a millisecond.
pub struct ImpairPort {
    inner: Box<dyn PacketPort>,
    tx: Option<Impairer>,
    rx: Option<Impairer>,
    epoch: Instant,
    monitor: ImpairMonitor,
    published: Duration,
    buf: Vec<u8>,
}

impl ImpairPort {
    /// Wraps `inner`; `None` leaves that direction alone.
    pub fn new(inner: Box<dyn PacketPort>, tx: Option<ImpairSpec>, rx: Option<ImpairSpec>) -> Self {
        Self {
            inner,
            tx: tx.map(Impairer::new),
            rx: rx.map(Impairer::new),
            epoch: Instant::now(),
            monitor: ImpairMonitor::default(),
            published: Duration::ZERO,
            buf: Vec::with_capacity(2048),
        }
    }

    /// The port's counters, updated about every 100 ms and at `flush`.
    pub fn monitor(&self) -> ImpairMonitor {
        self.monitor.clone()
    }

    fn now(&self) -> Duration {
        self.epoch.elapsed()
    }

    fn release_tx(&mut self, now: Duration) -> std::result::Result<(), SinkError> {
        if let Some(tx) = &mut self.tx {
            while let Some(f) = tx.pop_due(now) {
                self.inner.send(&f)?;
            }
        }
        Ok(())
    }

    fn publish(&mut self, now: Duration, force: bool) {
        if force || now >= self.published + PUBLISH_EVERY {
            self.published = now;
            let mut m = self.monitor.lock().unwrap_or_else(|e| e.into_inner());
            m.tx = self
                .tx
                .as_ref()
                .map(|i| i.stats().clone())
                .unwrap_or_default();
            m.rx = self
                .rx
                .as_ref()
                .map(|i| i.stats().clone())
                .unwrap_or_default();
        }
    }

    /// The counters now.
    pub fn stats(&self) -> PortImpairStats {
        PortImpairStats {
            tx: self
                .tx
                .as_ref()
                .map(|i| i.stats().clone())
                .unwrap_or_default(),
            rx: self
                .rx
                .as_ref()
                .map(|i| i.stats().clone())
                .unwrap_or_default(),
        }
    }

    /// When the next held frame is due, in either direction.
    pub fn next_due(&self) -> Option<Instant> {
        let a = self.tx.as_ref().and_then(Impairer::next_due);
        let b = self.rx.as_ref().and_then(Impairer::next_due);
        let due = match (a, b) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }?;
        Some(self.epoch + due)
    }
}

impl PacketPort for ImpairPort {
    fn send(&mut self, frame: &[u8]) -> std::result::Result<(), SinkError> {
        let now = self.now();
        self.release_tx(now)?;
        match &mut self.tx {
            Some(tx) => {
                tx.push(frame, now);
                // A frame with nothing to wait for goes now.
                self.release_tx(now)
            }
            None => self.inner.send(frame),
        }
    }

    fn recv(&mut self, buf: &mut Vec<u8>) -> std::result::Result<bool, SinkError> {
        let now = self.now();
        let Some(rx) = &mut self.rx else {
            return self.inner.recv(buf);
        };
        for _ in 0..RX_DRAIN {
            if !self.inner.recv(&mut self.buf)? {
                break;
            }
            rx.push(&self.buf, now);
        }
        let got = match rx.pop_due(now) {
            Some(f) => {
                *buf = f;
                true
            }
            None => false,
        };
        self.publish(now, false);
        Ok(got)
    }

    fn flush(&mut self) -> std::result::Result<(), SinkError> {
        let now = self.now();
        self.release_tx(now)?;
        self.publish(now, false);
        self.inner.flush()
    }

    fn describe(&self) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(tx) = &self.tx {
            parts.push(format!("sent frames {}", tx.spec()));
        }
        if let Some(rx) = &self.rx {
            parts.push(format!("received frames {}", rx.spec()));
        }
        let what = parts.join("; ");
        Some(match self.inner.describe() {
            Some(d) => format!("{d}, impaired ({what})"),
            None => format!("impaired ({what})"),
        })
    }

    fn rx_dropped(&mut self) -> Option<u64> {
        self.inner.rx_dropped()
    }

    fn drops(&mut self) -> crate::DropCounters {
        self.inner.drops()
    }

    fn impairments(&mut self) -> Option<PortImpairStats> {
        let now = self.now();
        self.publish(now, true);
        Some(self.stats())
    }
}

/// Wraps `port` in an [`ImpairPort`] when either spec impairs anything.
pub fn impair_port(
    port: Box<dyn PacketPort>,
    tx: Option<&ImpairSpec>,
    rx: Option<&ImpairSpec>,
) -> Box<dyn PacketPort> {
    let tx = tx.filter(|s| !s.is_none()).cloned();
    let rx = rx.filter(|s| !s.is_none()).cloned();
    if tx.is_none() && rx.is_none() {
        port
    } else {
        Box::new(ImpairPort::new(port, tx, rx))
    }
}

/// The impairments of a TCP, UDP or host run's ports: `tx` on the frames
/// FeroTRX sends (the profile's `impair`), `rx` on the frames it receives
/// (`impair_rx`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PortImpair {
    pub tx: Option<ImpairSpec>,
    pub rx: Option<ImpairSpec>,
}

impl PortImpair {
    /// No impairment either way (specs that do nothing count as none).
    pub fn is_none(&self) -> bool {
        self.tx.as_ref().is_none_or(ImpairSpec::is_none)
            && self.rx.as_ref().is_none_or(ImpairSpec::is_none)
    }

    /// Wraps `port` in an [`ImpairPort`] if there is anything to do. Port
    /// `index` of the run gets its own random numbers when the specs have a
    /// seed.
    pub fn wrap(&self, port: Box<dyn PacketPort>, index: usize) -> Box<dyn PacketPort> {
        let tx = self.tx.as_ref().map(|s| s.for_lane(2 * index));
        let rx = self.rx.as_ref().map(|s| s.for_lane(2 * index + 1));
        impair_port(port, tx.as_ref(), rx.as_ref())
    }

    /// Fills in each direction the other has not set.
    pub fn or(&self, other: &PortImpair) -> PortImpair {
        PortImpair {
            tx: self.tx.clone().or_else(|| other.tx.clone()),
            rx: self.rx.clone().or_else(|| other.rx.clone()),
        }
    }
}

/// `sent delay=10ms; received loss=1%`, or `none`.
impl fmt::Display for PortImpair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if let Some(s) = self.tx.as_ref().filter(|s| !s.is_none()) {
            parts.push(format!("sent {s}"));
        }
        if let Some(s) = self.rx.as_ref().filter(|s| !s.is_none()) {
            parts.push(format!("received {s}"));
        }
        if parts.is_empty() {
            f.write_str("none")
        } else {
            f.write_str(&parts.join("; "))
        }
    }
}

/// When a [`run_bridge`] ends.
#[derive(Clone, Debug, Default)]
pub struct BridgeConfig {
    pub duration: Option<Duration>,
    pub stop: Option<Arc<AtomicBool>>,
}

/// What a bridge passed each way.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BridgeStats {
    /// Frames from the first port to the second, and back.
    pub forward: ImpairStats,
    pub back: ImpairStats,
    pub elapsed: Duration,
    pub stopped: bool,
}

/// Joins two ports with a wire that impairs: what `a` receives goes out on
/// `b` impaired by `forward`, and what `b` receives goes out on `a` impaired
/// by `back`, until the run is stopped or its duration passes. `progress`
/// gets the counters every `interval`.
///
/// The ports should not hand back the frames they send themselves (a pcap
/// port on Linux or macOS does not), or the bridge sends them round again.
pub fn run_bridge<F>(
    a: Box<dyn PacketPort>,
    b: Box<dyn PacketPort>,
    forward: &ImpairSpec,
    back: &ImpairSpec,
    config: &BridgeConfig,
    interval: Duration,
    mut progress: F,
) -> Result<BridgeStats>
where
    F: FnMut(&BridgeStats),
{
    let bridge_err = |what: &str, e: SinkError| Error::InvalidSpec(format!("bridge: {what}: {e}"));
    // Each port sends what the other received.
    let mut a = ImpairPort::new(a, Some(back.clone()), None);
    let mut b = ImpairPort::new(b, Some(forward.clone()), None);
    let start = Instant::now();
    let mut next_progress = interval;
    let mut buf = Vec::with_capacity(2048);
    let stats = |a: &ImpairPort, b: &ImpairPort, elapsed, stopped| BridgeStats {
        forward: b.stats().tx,
        back: a.stats().tx,
        elapsed,
        stopped,
    };
    loop {
        let mut busy = false;
        for _ in 0..RX_DRAIN {
            if !a
                .recv(&mut buf)
                .map_err(|e| bridge_err("receiving on the first port", e))?
            {
                break;
            }
            b.send(&buf)
                .map_err(|e| bridge_err("sending on the second port", e))?;
            busy = true;
        }
        for _ in 0..RX_DRAIN {
            if !b
                .recv(&mut buf)
                .map_err(|e| bridge_err("receiving on the second port", e))?
            {
                break;
            }
            a.send(&buf)
                .map_err(|e| bridge_err("sending on the first port", e))?;
            busy = true;
        }
        a.flush()
            .map_err(|e| bridge_err("sending on the first port", e))?;
        b.flush()
            .map_err(|e| bridge_err("sending on the second port", e))?;
        let now = start.elapsed();
        let stopped = config
            .stop
            .as_ref()
            .is_some_and(|s| s.load(Ordering::Relaxed));
        if stopped || config.duration.is_some_and(|d| now >= d) {
            let s = stats(&a, &b, now, stopped);
            progress(&s);
            return Ok(s);
        }
        if now >= next_progress {
            next_progress = now + interval;
            progress(&stats(&a, &b, now, false));
        }
        if !busy {
            // Sleep until a held frame is due, at most a little while.
            let nap = [a.next_due(), b.next_due()]
                .into_iter()
                .flatten()
                .min()
                .map_or(Duration::from_micros(100), |due| {
                    due.saturating_duration_since(Instant::now())
                })
                .min(Duration::from_micros(100));
            if !nap.is_zero() {
                std::thread::sleep(nap);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_ports;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn spec(s: &str) -> ImpairSpec {
        s.parse().unwrap()
    }

    /// Pushes `n` frames `gap` apart and returns each frame's (sequence,
    /// delay) as it comes out, in order of leaving.
    fn run(spec: &ImpairSpec, n: u32, gap: Duration) -> (Vec<(u32, Duration)>, ImpairStats) {
        let mut link = Impairer::new(spec.clone());
        let mut out = Vec::new();
        let mut sent = Vec::new();
        let mut now = Duration::ZERO;
        let take = |link: &mut Impairer, now: Duration, out: &mut Vec<(u32, Duration)>| {
            while let Some(f) = link.pop_due(now) {
                let seq = u32::from_be_bytes(f[14..18].try_into().unwrap());
                out.push((seq, now));
            }
        };
        for i in 0..n {
            let mut frame = vec![0u8; 100];
            frame[12] = 0x88; // not IP
            frame[13] = 0xb5;
            frame[14..18].copy_from_slice(&i.to_be_bytes());
            sent.push(now);
            link.push(&frame, now);
            // Step the clock in 100 us ticks up to the next frame.
            let next = now + gap;
            while now < next {
                take(&mut link, now, &mut out);
                now += Duration::from_micros(100);
            }
        }
        while let Some(due) = link.next_due() {
            take(&mut link, due, &mut out);
        }
        let out = out
            .into_iter()
            .map(|(seq, at)| (seq, at - sent[seq as usize]))
            .collect();
        (out, link.stats().clone())
    }

    #[test]
    fn specs_parse_print_and_check() {
        let s = spec("delay=20ms, jitter=5ms distribution=normal loss=1% loss_burst=3 duplicate=0.5% reorder=1% corrupt=0.1% rate=10mbit limit=1000 mtu=1400 seed=1");
        assert_eq!(s.delay, ms(20));
        assert_eq!(s.distribution, JitterDist::Normal);
        assert_eq!(s.loss_burst, Some(3.0));
        assert_eq!(s.rate, Some(10e6));
        assert_eq!(s.mtu, Some(1400));
        assert_eq!(s.seed, Some(1));
        assert_eq!(spec(&s.to_string()), s);
        assert!(spec("none").is_none());
        assert_eq!(spec("").to_string(), "none");
        assert_eq!(parse_bit_rate("1.5gbit").unwrap(), 1.5e9);
        assert_eq!(parse_bit_rate("64000bps").unwrap(), 64000.0);
        for bad in [
            "loss=150%",
            "reorder=1%",
            "loss=5% loss_burst=0.5",
            "speed=1",
            "delay",
            "rate=fast",
            "loss=60% loss_burst=2 loss_bad=50%",
        ] {
            assert!(bad.parse::<ImpairSpec>().is_err(), "{bad}");
        }
    }

    #[test]
    fn delay_and_jitter_match_the_spec() {
        // Fixed delay: every frame exactly 10 ms late, in order.
        let (out, stats) = run(&spec("delay=10ms"), 100, ms(1));
        assert_eq!(out.len(), 100);
        assert!(out
            .iter()
            .all(|&(_, d)| d >= ms(10) && d < ms(10) + Duration::from_micros(150)));
        assert_eq!(stats.passed, 100);
        // Uniform jitter, frames far apart so the order costs nothing: the
        // mean is the delay and every frame is within delay +- jitter.
        for dist in ["uniform", "normal"] {
            let s = spec(&format!("delay=20ms jitter=4ms distribution={dist} seed=3"));
            let (out, stats) = run(&s, 2000, ms(30));
            let mean = out.iter().map(|&(_, d)| d.as_secs_f64()).sum::<f64>() / 2000.0;
            assert!((mean * 1000.0 - 20.0).abs() < 0.3, "{dist}: {mean}");
            let var = out
                .iter()
                .map(|&(_, d)| (d.as_secs_f64() - mean).powi(2))
                .sum::<f64>()
                / 2000.0;
            // Uniform on +-4 ms has sd 4/sqrt(3) = 2.31; normal has sd 4.
            let want = if dist == "uniform" { 2.31 } else { 4.0 };
            assert!(
                (var.sqrt() * 1000.0 - want).abs() < 0.3,
                "{dist}: {}",
                var.sqrt()
            );
            if dist == "uniform" {
                assert!(out
                    .iter()
                    .all(|&(_, d)| d >= ms(16) && d <= ms(24) + Duration::from_micros(100)));
            }
            assert_eq!(stats.delay.count(), 2000);
        }
        // Pareto: never below the delay, mean extra = jitter, a long tail.
        let (out, _) = run(
            &spec("delay=10ms jitter=2ms distribution=pareto seed=9"),
            4000,
            ms(100),
        );
        assert!(out.iter().all(|&(_, d)| d >= ms(10)));
        let extra = out
            .iter()
            .map(|&(_, d)| d.as_secs_f64() - 0.010)
            .sum::<f64>()
            / 4000.0;
        assert!((extra * 1000.0 - 2.0).abs() < 0.3, "{extra}");
        assert!(out.iter().any(|&(_, d)| d > ms(18)));
    }

    #[test]
    fn jitter_keeps_order_unless_told() {
        let s = spec("delay=20ms jitter=10ms seed=5");
        let (out, stats) = run(&s, 500, ms(1));
        assert!(out.windows(2).all(|w| w[0].0 < w[1].0));
        assert_eq!(stats.reordered, 0);
        let mut s2 = s.clone();
        s2.keep_order = false;
        let (out, _) = run(&s2, 500, ms(1));
        assert!(out.windows(2).any(|w| w[0].0 > w[1].0));
    }

    #[test]
    fn loss_random_and_in_bursts() {
        let (out, stats) = run(&spec("loss=5% seed=11"), 20_000, ms(1));
        let lost = 20_000 - out.len();
        assert_eq!(stats.lost as usize, lost);
        assert!((lost as f64 / 20_000.0 - 0.05).abs() < 0.006, "{lost}");
        // Bursts: the same loss, in runs of 4 on average.
        let (out, stats) = run(&spec("loss=5% loss_burst=4 seed=11"), 40_000, ms(1));
        let got: std::collections::HashSet<u32> = out.iter().map(|&(s, _)| s).collect();
        let mut runs = Vec::new();
        let mut run_len = 0;
        for i in 0..40_000u32 {
            if got.contains(&i) {
                if run_len > 0 {
                    runs.push(run_len);
                }
                run_len = 0;
            } else {
                run_len += 1;
            }
        }
        let share = stats.lost as f64 / 40_000.0;
        assert!((share - 0.05).abs() < 0.01, "{share}");
        let mean = runs.iter().sum::<u32>() as f64 / runs.len() as f64;
        assert!((mean - 4.0).abs() < 0.6, "{mean}");
    }

    #[test]
    fn duplicates_reorders_and_corruption() {
        let (out, stats) = run(&spec("duplicate=10% seed=2"), 5000, ms(1));
        assert_eq!(out.len() as u64, 5000 + stats.duplicated);
        assert!((stats.duplicated as f64 / 5000.0 - 0.1).abs() < 0.02);
        // Reordered frames skip the 10 ms delay and pass 10 frames.
        let (out, stats) = run(&spec("delay=10ms reorder=5% seed=4"), 5000, ms(1));
        assert!(
            (stats.reordered as f64 / 5000.0 - 0.05).abs() < 0.01,
            "{}",
            stats.reordered
        );
        let passed = out.windows(2).filter(|w| w[0].0 > w[1].0).count();
        assert!(passed > 0);

        // Corruption flips one bit in the UDP payload; checksums stay or are fixed.
        let frame = net::tests::udp4();
        for fix in [false, true] {
            let mut link = Impairer::new(spec(&format!("corrupt=100% fix_checksums={fix} seed=1")));
            link.push(&frame, Duration::ZERO);
            let out = link.pop_due(Duration::ZERO).unwrap();
            let diff: Vec<usize> = (0..frame.len()).filter(|&i| frame[i] != out[i]).collect();
            assert!(!diff.is_empty());
            assert!(
                diff.iter()
                    .all(|&i| i >= 42
                        || (fix && (24..26).contains(&i) || fix && (40..42).contains(&i))),
                "{diff:?}"
            );
            assert_eq!(net::tests::checksums_ok(&out), fix);
            assert_eq!(link.stats().corrupted, 1);
        }
    }

    #[test]
    fn rate_mtu_and_limit() {
        // 1000-byte frames on 1 Mbit/s: (1000 + 24) * 8 = 8.192 ms each, so
        // 100 frames sent at once leave over 819 ms.
        let mut link = Impairer::new(spec("rate=1mbit"));
        for _ in 0..100 {
            link.push(&[0u8; 1000], Duration::ZERO);
        }
        let mut last = Duration::ZERO;
        let mut n = 0;
        while let Some(due) = link.next_due() {
            link.pop_due(due).unwrap();
            assert!(due >= last);
            last = due;
            n += 1;
        }
        assert_eq!(n, 100);
        assert!((last.as_secs_f64() - 0.8192).abs() < 1e-6, "{last:?}");

        // Too many at once for the queue: tail drop.
        let mut link = Impairer::new(spec("rate=1mbit limit=10"));
        for _ in 0..50 {
            link.push(&[0u8; 1000], Duration::ZERO);
        }
        assert_eq!(link.stats().queue_dropped, 40);
        assert_eq!(link.stats().max_held, 10);

        // MTU: an IPv4 frame of 46 bytes of IP over a 40-byte MTU.
        let frame = net::tests::udp4();
        let ip_len = frame.len() - 14;
        let mut drop = Impairer::new(spec(&format!("mtu={}", ip_len - 1)));
        drop.push(&frame, Duration::ZERO);
        assert_eq!(drop.stats().mtu_dropped, 1);
        assert!(drop.pop_due(Duration::ZERO).is_none());
        let mut cut = Impairer::new(spec(&format!("mtu={} mtu_action=truncate", ip_len - 1)));
        cut.push(&frame, Duration::ZERO);
        assert_eq!(cut.pop_due(Duration::ZERO).unwrap().len(), frame.len() - 1);
        let mut fits = Impairer::new(spec(&format!("mtu={ip_len}")));
        fits.push(&frame, Duration::ZERO);
        assert_eq!(fits.pop_due(Duration::ZERO).unwrap(), frame);
    }

    #[test]
    fn same_seed_same_result() {
        let s = spec("delay=5ms jitter=3ms loss=10% loss_burst=2 duplicate=5% seed=42");
        assert_eq!(run(&s, 1000, ms(1)).0, run(&s, 1000, ms(1)).0);
        assert_ne!(run(&s, 1000, ms(1)).0, run(&s.for_lane(1), 1000, ms(1)).0);
    }

    #[test]
    fn ports_impair_each_way() {
        let (a, mut b) = memory_ports();
        let mut port = ImpairPort::new(
            Box::new(a),
            Some(spec("delay=30ms")),
            Some(spec("loss=100%")),
        );
        port.send(&[1u8; 60]).unwrap();
        port.flush().unwrap();
        let mut buf = Vec::new();
        assert!(!b.recv(&mut buf).unwrap());
        std::thread::sleep(ms(35));
        port.flush().unwrap();
        assert!(b.recv(&mut buf).unwrap());
        // Everything received is lost.
        PacketPort::send(&mut b, &[2u8; 60]).unwrap();
        assert!(!port.recv(&mut buf).unwrap());
        let stats = port.impairments().unwrap();
        assert_eq!(stats.tx.passed, 1);
        assert_eq!(stats.rx.lost, 1);
        assert_eq!(port.monitor().lock().unwrap().rx.lost, 1);
        assert!(port.describe().unwrap().contains("delay=30ms"));
    }

    #[test]
    fn bridge_forwards_impaired_both_ways() {
        let (a_near, mut a_far) = memory_ports();
        let (b_near, mut b_far) = memory_ports();
        let stop = Arc::new(AtomicBool::new(false));
        let config = BridgeConfig {
            duration: Some(ms(300)),
            stop: Some(stop),
        };
        let handle = std::thread::spawn(move || {
            run_bridge(
                Box::new(a_near),
                Box::new(b_near),
                &spec("delay=20ms"),
                &spec("loss=100%"),
                &config,
                Duration::MAX,
                |_| {},
            )
        });
        let sent = Instant::now();
        for i in 0..10u8 {
            PacketPort::send(&mut a_far, &[i; 60]).unwrap();
            PacketPort::send(&mut b_far, &[i; 60]).unwrap();
        }
        let mut buf = Vec::new();
        let mut got = 0;
        while got < 10 && sent.elapsed() < ms(250) {
            if b_far.recv(&mut buf).unwrap() {
                assert_eq!(buf[0], got);
                assert!(sent.elapsed() >= ms(20));
                got += 1;
            }
        }
        let stats = handle.join().unwrap().unwrap();
        assert_eq!(got, 10);
        assert!(!a_far.recv(&mut buf).unwrap());
        assert_eq!(stats.forward.passed, 10);
        assert_eq!(stats.back.lost, 10);
    }

    #[test]
    fn streams_carry_their_impairments() {
        use crate::{Capture, CaptureSource, Rate, RunConfig, Stream, VecSink};
        let cap =
            Arc::new(Capture::from_specs(&["eth/ipv4/udp/raw(len=8)"], Duration::ZERO).unwrap());
        let stream = Stream::new("s", CaptureSource::new(cap).loops(200))
            .with_rate(Rate::Pps(10_000.0))
            .with_impair(spec("delay=30ms loss=10% seed=3"));
        let mut sink = VecSink::default();
        let t = Instant::now();
        let stats = crate::run(&mut [stream], &mut sink, &RunConfig::default()).unwrap();
        // 20 ms of sending, then the last packet's 30 ms on the link.
        assert!(t.elapsed() >= ms(49), "{:?}", t.elapsed());
        let imp = stats.total.impair.clone().unwrap();
        assert_eq!(stats.total.packets, 200);
        assert_eq!(imp.packets, 200);
        assert_eq!(sink.packets.len() as u64, 200 - imp.lost);
        assert!(imp.lost > 5 && imp.lost < 40, "{}", imp.lost);
        assert!(imp.delay.min().unwrap() >= ms(30));
        assert_eq!(stats.streams[0].impair.as_ref().unwrap().lost, imp.lost);
    }

    #[test]
    fn tcp_gets_through_a_lossy_link() {
        use crate::{
            TcpClientConfig, TcpConfig, TcpEndpoint, TcpEngine, TcpJob, TcpMessage, TcpOptions,
            TcpProgram, TcpRole, TcpRunConfig, TcpServerConfig, TcpTemplate,
        };
        let (a, b) = memory_ports();
        let program = TcpProgram::new(
            80,
            vec![
                TcpMessage::new(TcpRole::Client, "ping"),
                TcpMessage::new(TcpRole::Server, "pong"),
            ],
        );
        let server_ep = TcpEndpoint::new(
            1,
            "02:00:00:00:00:02".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
        );
        let mut client = TcpClientConfig::new(TcpEndpoint::new(
            0,
            "02:00:00:00:00:01".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        ));
        client.connections = 20;
        client.cps = 200.0;
        let options = TcpOptions {
            min_rto: ms(20),
            ..Default::default()
        };
        let engine = TcpEngine::new(TcpConfig {
            templates: vec![TcpTemplate::new(
                Arc::new(program),
                "10.0.0.2:80".parse().unwrap(),
            )],
            client: Some(client),
            server: Some(TcpServerConfig::new(server_ep)),
            options,
        })
        .unwrap();
        let impair = PortImpair {
            tx: Some(spec("delay=2ms loss=10% seed=1")),
            rx: Some(spec("delay=2ms loss=10% seed=2")),
        };
        let ports = vec![
            impair.wrap(Box::new(a), 0),
            Box::new(b) as Box<dyn PacketPort>,
        ];
        let config = TcpRunConfig {
            duration: Some(Duration::from_secs(20)),
            ..Default::default()
        };
        let stats = TcpJob::spawn(engine, ports, config)
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(stats.client.completed, 20, "{stats:?}");
        assert!(
            stats.impair.tx.lost > 0 && stats.impair.rx.lost > 0,
            "{:?}",
            stats.impair
        );
        assert!(stats.client.retransmits + stats.server.retransmits > 0);
        assert!(stats.impair.tx.delay.min().unwrap() >= ms(2));
    }
}
