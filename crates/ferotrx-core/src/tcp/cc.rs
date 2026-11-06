//! Congestion control: how fast a connection may send, and how it backs off
//! when the network shows congestion (a loss, or an ECN mark).
//!
//! The engine keeps the congestion window and the slow start threshold and
//! asks a [`CongestionController`] to change them at each event. NewReno
//! (RFC 5681, RFC 6582) is the default; CUBIC (RFC 9438) with HyStart++
//! (RFC 9406) slow start is the other choice.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use super::wire;

/// Which congestion control a connection uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Congestion {
    /// Reno with NewReno's recovery: the window grows by about a segment per
    /// round trip and halves on congestion (RFC 5681, RFC 6582).
    #[default]
    NewReno,
    /// CUBIC (RFC 9438): the window grows as a cubic function of the time
    /// since the last congestion and backs off to 70%; HyStart++ (RFC 9406)
    /// leaves slow start when round-trip times grow, before a loss.
    Cubic,
}

impl Congestion {
    pub const ALL: [Congestion; 2] = [Congestion::NewReno, Congestion::Cubic];

    pub fn name(self) -> &'static str {
        match self {
            Congestion::NewReno => "newreno",
            Congestion::Cubic => "cubic",
        }
    }

    /// A new controller of this kind, for one connection.
    pub fn controller(self) -> Box<dyn CongestionController> {
        match self {
            Congestion::NewReno => Box::new(NewReno),
            Congestion::Cubic => Box::new(Cubic::default()),
        }
    }
}

impl fmt::Display for Congestion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Congestion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "newreno" | "reno" => Ok(Congestion::NewReno),
            "cubic" => Ok(Congestion::Cubic),
            other => Err(format!(
                "unknown congestion control {other:?} (newreno or cubic)"
            )),
        }
    }
}

/// The window a controller changes, in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CcWindow {
    /// The congestion window: most bytes in flight.
    pub cwnd: usize,
    /// The slow start threshold: below it the window grows fast.
    pub ssthresh: usize,
    /// Data bytes per segment.
    pub smss: usize,
}

impl CcWindow {
    pub fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }
}

/// What an acknowledgement of new data tells a controller.
#[derive(Clone, Copy, Debug)]
pub struct CcAck {
    pub now: Duration,
    /// Bytes newly acknowledged.
    pub acked: usize,
    /// The round-trip time this ACK measured, if it did.
    pub rtt: Option<Duration>,
    /// The smoothed round-trip time, once measured.
    pub srtt: Option<Duration>,
    /// The acknowledgement number, and the highest sequence number sent
    /// (plus one), to tell round trips apart.
    pub ack: u32,
    pub snd_max: u32,
}

/// A congestion control algorithm, one per connection. The engine calls it
/// at each event; it changes the window. Loss recovery itself (which
/// segments go again) is the engine's.
pub trait CongestionController: Send + fmt::Debug {
    fn kind(&self) -> Congestion;

    /// New data was acknowledged, outside loss recovery: grow the window.
    fn on_ack(&mut self, w: &mut CcWindow, a: &CcAck);

    /// Congestion: three duplicate ACKs or SACK showed a loss, or an ECN
    /// echo came. `flight` is the bytes in flight. Sets the threshold and
    /// the window to go on with.
    fn on_congestion(&mut self, w: &mut CcWindow, flight: usize, now: Duration);

    /// Loss recovery ended: everything sent before the loss is acknowledged.
    fn on_recovered(&mut self, w: &mut CcWindow, _now: Duration) {
        w.cwnd = w.ssthresh.max(w.smss);
    }

    /// The retransmission timer expired: back to one segment and slow start.
    fn on_timeout(&mut self, w: &mut CcWindow, flight: usize, now: Duration);
}

/// Slow start's growth for `acked` bytes: at most a segment per ACK (RFC
/// 3465 with L = 1).
fn slow_start(w: &mut CcWindow, acked: usize) {
    w.cwnd += acked.min(w.smss);
}

/// Reno with NewReno recovery.
#[derive(Clone, Copy, Debug, Default)]
pub struct NewReno;

impl CongestionController for NewReno {
    fn kind(&self) -> Congestion {
        Congestion::NewReno
    }

    fn on_ack(&mut self, w: &mut CcWindow, a: &CcAck) {
        if w.in_slow_start() {
            slow_start(w, a.acked);
        } else {
            // Congestion avoidance: about a segment per round trip.
            w.cwnd += (w.smss * w.smss / w.cwnd).max(1);
        }
    }

    fn on_congestion(&mut self, w: &mut CcWindow, flight: usize, _now: Duration) {
        w.ssthresh = (flight / 2).max(2 * w.smss);
        w.cwnd = w.ssthresh;
    }

    fn on_timeout(&mut self, w: &mut CcWindow, flight: usize, _now: Duration) {
        w.ssthresh = (flight / 2).max(2 * w.smss);
        w.cwnd = w.smss;
    }
}

/// CUBIC's constant C, in segments per second cubed.
const CUBIC_C: f64 = 0.4;
/// CUBIC's multiplicative decrease.
const CUBIC_BETA: f64 = 0.7;
/// The round-trip time CUBIC assumes before one is measured.
const CUBIC_DEFAULT_RTT: Duration = Duration::from_millis(100);

/// CUBIC (RFC 9438) with HyStart++ in the first slow start.
#[derive(Clone, Debug, Default)]
pub struct Cubic {
    /// The window before the last reduction, in segments (W_max).
    w_max: f64,
    /// When the current congestion avoidance epoch began, the time to grow
    /// back to `w_max` (K, in seconds), and the window then.
    epoch: Option<Duration>,
    k: f64,
    /// The window Reno would have (W_est), in segments.
    w_est: f64,
    /// Fractions of a segment the window grew by, carried to the next ACK.
    carry: f64,
    hystart: HyStart,
}

impl Cubic {
    /// The cubic window `t` seconds into the epoch, in segments.
    fn w_cubic(&self, t: f64) -> f64 {
        CUBIC_C * (t - self.k).powi(3) + self.w_max
    }

    /// A reduction: remember where the window was (with fast convergence:
    /// less if it was already below the last maximum), and back off.
    fn reduce(&mut self, w: &mut CcWindow, flight: usize) {
        // An application-limited connection has a window it never used: back
        // off from what was in flight instead (RFC 9438, 4.6).
        let base = w.cwnd.min(flight.max(2 * w.smss));
        let seg = base as f64 / w.smss as f64;
        self.w_max = if seg < self.w_max {
            seg * (1.0 + CUBIC_BETA) / 2.0
        } else {
            seg
        };
        w.ssthresh = ((base as f64 * CUBIC_BETA) as usize).max(2 * w.smss);
        self.epoch = None;
        self.carry = 0.0;
        self.hystart.done = true;
    }
}

impl CongestionController for Cubic {
    fn kind(&self) -> Congestion {
        Congestion::Cubic
    }

    fn on_ack(&mut self, w: &mut CcWindow, a: &CcAck) {
        if w.in_slow_start() {
            let grow = self.hystart.on_ack(a, w.smss);
            match grow {
                Grow::By(n) => w.cwnd += n,
                Grow::Leave => w.ssthresh = w.cwnd,
            }
            return;
        }
        let smss = w.smss as f64;
        let cwnd = w.cwnd as f64 / smss;
        let start = *self.epoch.get_or_insert_with(|| {
            // A new epoch: grow back to the last maximum in K seconds, or
            // from here if there was none or the window is past it.
            if self.w_max <= cwnd {
                self.w_max = cwnd;
                self.k = 0.0;
            } else {
                self.k = ((self.w_max - cwnd) / CUBIC_C).cbrt();
            }
            self.w_est = cwnd;
            a.now
        });
        let acked = a.acked as f64 / smss;
        // The Reno-friendly estimate (RFC 9438, 4.3).
        let alpha = if self.w_est < self.w_max {
            3.0 * (1.0 - CUBIC_BETA) / (1.0 + CUBIC_BETA)
        } else {
            1.0
        };
        self.w_est += alpha * acked / cwnd;
        let t = a.now.saturating_sub(start).as_secs_f64();
        let rtt = a.srtt.unwrap_or(CUBIC_DEFAULT_RTT).as_secs_f64();
        let grow = if self.w_cubic(t) < self.w_est {
            // Reno would be faster: grow as it would.
            (self.w_est - cwnd).max(0.0)
        } else {
            // Toward where the curve is a round trip from now, at most 1.5
            // times the window.
            let target = self.w_cubic(t + rtt).clamp(cwnd, 1.5 * cwnd);
            (target - cwnd) / cwnd * acked
        };
        self.carry += grow * smss;
        let whole = self.carry.floor();
        self.carry -= whole;
        w.cwnd += whole as usize;
    }

    fn on_congestion(&mut self, w: &mut CcWindow, flight: usize, _now: Duration) {
        self.reduce(w, flight);
        w.cwnd = w.ssthresh;
    }

    fn on_timeout(&mut self, w: &mut CcWindow, flight: usize, _now: Duration) {
        self.reduce(w, flight);
        w.cwnd = w.smss;
    }
}

/// HyStart++ (RFC 9406) constants.
const HYSTART_MIN_RTT_THRESH: Duration = Duration::from_millis(4);
const HYSTART_MAX_RTT_THRESH: Duration = Duration::from_millis(16);
const HYSTART_MIN_RTT_DIVISOR: u32 = 8;
const HYSTART_N_RTT_SAMPLE: u32 = 8;
const HYSTART_CSS_GROWTH_DIVISOR: usize = 4;
const HYSTART_CSS_ROUNDS: u32 = 5;

/// What slow start does with an ACK.
#[derive(Debug, PartialEq, Eq)]
enum Grow {
    By(usize),
    /// Leave slow start for congestion avoidance.
    Leave,
}

/// HyStart++: watches the smallest round-trip time of each round. When it
/// grows by more than a threshold, the queue is filling: slow start slows
/// to a quarter (Conservative Slow Start) and, if the round-trip times stay
/// up for five rounds, ends without a loss.
#[derive(Clone, Debug, Default)]
struct HyStart {
    /// The end of the current round: when this is acknowledged, a new one starts.
    window_end: Option<u32>,
    last_round_min: Option<Duration>,
    round_min: Option<Duration>,
    samples: u32,
    /// In Conservative Slow Start: the round-trip time it began with, and
    /// the rounds since.
    css_baseline: Option<Duration>,
    css_rounds: u32,
    /// Only the first slow start uses it.
    done: bool,
}

impl HyStart {
    fn on_ack(&mut self, a: &CcAck, smss: usize) -> Grow {
        let standard = a.acked.min(smss);
        if self.done {
            return Grow::By(standard);
        }
        if self.window_end.is_none_or(|end| wire::seq_le(end, a.ack)) {
            // A new round.
            self.last_round_min = self.round_min.take();
            self.samples = 0;
            self.window_end = Some(a.snd_max);
            if self.css_baseline.is_some() {
                self.css_rounds += 1;
                if self.css_rounds >= HYSTART_CSS_ROUNDS {
                    self.done = true;
                    return Grow::Leave;
                }
            }
        }
        if let Some(rtt) = a.rtt {
            self.round_min = Some(self.round_min.map_or(rtt, |m| m.min(rtt)));
            self.samples += 1;
        }
        let enough = self.samples >= HYSTART_N_RTT_SAMPLE;
        match (self.css_baseline, self.last_round_min, self.round_min) {
            (None, Some(last), Some(cur)) if enough => {
                let thresh = (last / HYSTART_MIN_RTT_DIVISOR)
                    .clamp(HYSTART_MIN_RTT_THRESH, HYSTART_MAX_RTT_THRESH);
                if cur >= last + thresh {
                    self.css_baseline = Some(cur);
                    self.css_rounds = 0;
                }
            }
            (Some(base), _, Some(cur)) if enough && cur < base => {
                // The delay went down again: it was not the queue.
                self.css_baseline = None;
            }
            _ => {}
        }
        if self.css_baseline.is_some() {
            Grow::By((standard / HYSTART_CSS_GROWTH_DIVISOR).max(1))
        } else {
            Grow::By(standard)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMSS: usize = 1000;

    fn window(cwnd: usize, ssthresh: usize) -> CcWindow {
        CcWindow {
            cwnd: cwnd * SMSS,
            ssthresh: ssthresh * SMSS,
            smss: SMSS,
        }
    }

    fn ack(now_ms: u64, acked: usize, rtt_ms: Option<u64>, ack: u32, snd_max: u32) -> CcAck {
        CcAck {
            now: Duration::from_millis(now_ms),
            acked,
            rtt: rtt_ms.map(Duration::from_millis),
            srtt: Some(Duration::from_millis(rtt_ms.unwrap_or(100))),
            ack,
            snd_max,
        }
    }

    #[test]
    fn names_parse() {
        for c in Congestion::ALL {
            assert_eq!(c.name().parse::<Congestion>(), Ok(c));
            assert_eq!(c.controller().kind(), c);
        }
        assert_eq!("Reno".parse::<Congestion>(), Ok(Congestion::NewReno));
        assert!("bbr".parse::<Congestion>().is_err());
    }

    #[test]
    fn newreno_halves_and_grows_a_segment_per_round_trip() {
        let mut c = NewReno;
        let mut w = window(100, usize::MAX / SMSS);
        c.on_congestion(&mut w, 100 * SMSS, Duration::ZERO);
        assert_eq!((w.cwnd, w.ssthresh), (50 * SMSS, 50 * SMSS));
        // A window's worth of ACKs: one more segment.
        for i in 0..50 {
            c.on_ack(&mut w, &ack(i, SMSS, None, 0, 0));
        }
        assert!(
            (50 * SMSS + 900..=51 * SMSS + 100).contains(&w.cwnd),
            "{w:?}"
        );
        c.on_timeout(&mut w, 40 * SMSS, Duration::ZERO);
        assert_eq!((w.cwnd, w.ssthresh), (SMSS, 20 * SMSS));
    }

    /// Runs `c` in congestion avoidance from `w` for `secs` with a fixed
    /// round trip, a window of ACKs per round trip; returns the window
    /// after each round trip, in segments.
    fn grow(
        c: &mut dyn CongestionController,
        w: &mut CcWindow,
        from: u64,
        secs: u64,
    ) -> Vec<usize> {
        let rtt = 100;
        let mut out = Vec::new();
        let mut now = from;
        while now < from + secs * 1000 {
            let n = w.cwnd / SMSS;
            for i in 0..n {
                let a = ack(now + rtt * i as u64 / n as u64, SMSS, Some(rtt), 0, 0);
                c.on_ack(w, &a);
            }
            now += rtt;
            out.push(w.cwnd / SMSS);
        }
        out
    }

    #[test]
    fn cubic_backs_off_to_70_percent_and_returns_in_k_seconds() {
        let mut c = Cubic::default();
        let mut w = window(100, usize::MAX / SMSS);
        c.on_congestion(&mut w, 100 * SMSS, Duration::ZERO);
        assert_eq!((w.cwnd, w.ssthresh), (70 * SMSS, 70 * SMSS));
        // K = cbrt(100 * 0.3 / 0.4) = 4.2 s; the plateau around W_max.
        let after = grow(&mut c, &mut w, 0, 6);
        let k = (30.0f64 / 0.4).cbrt();
        assert!((k - 4.217).abs() < 0.01, "{k}");
        let at = |s: f64| after[(s * 10.0) as usize - 1];
        assert!((92..=100).contains(&at(3.0)), "{after:?}");
        assert!((97..=103).contains(&at(4.2)), "{after:?}");
        // Then faster again, past the old maximum.
        assert!(at(6.0) > at(4.2) && at(6.0) > 100, "{after:?}");
        // NewReno grows a segment per round trip: from 70 it needs 3 s to
        // get back to 100, CUBIC is ahead after a second.
        let mut r = NewReno;
        let mut rw = window(100, usize::MAX / SMSS);
        r.on_congestion(&mut rw, 100 * SMSS, Duration::ZERO);
        let reno = grow(&mut r, &mut rw, 0, 6);
        assert!(reno[9] < after[9], "{reno:?} {after:?}");
    }

    #[test]
    fn cubic_fast_convergence_gives_up_bandwidth() {
        let mut c = Cubic::default();
        let mut w = window(100, usize::MAX / SMSS);
        c.on_congestion(&mut w, 100 * SMSS, Duration::ZERO);
        assert_eq!(c.w_max, 100.0);
        // A second loss below the old maximum: remember less than the window.
        c.on_congestion(&mut w, 70 * SMSS, Duration::from_secs(1));
        assert!((c.w_max - 70.0 * 0.85).abs() < 1e-9, "{}", c.w_max);
        assert_eq!(w.cwnd, 49 * SMSS);
    }

    #[test]
    fn cubic_uses_what_was_in_flight_when_application_limited() {
        let mut c = Cubic::default();
        let mut w = window(100, usize::MAX / SMSS);
        c.on_timeout(&mut w, 10 * SMSS, Duration::ZERO);
        assert_eq!((w.cwnd, w.ssthresh), (SMSS, 7 * SMSS));
    }

    /// Slow start rounds with a fixed `rtt(round)`, one ACK per segment.
    /// Returns the round that left slow start.
    fn slow_start_rounds(
        c: &mut Cubic,
        w: &mut CcWindow,
        rounds: u32,
        rtt: impl Fn(u32) -> u64,
    ) -> Option<u32> {
        let mut seq = 0u32;
        let mut now = 0;
        for round in 0..rounds {
            if !w.in_slow_start() {
                return Some(round - 1);
            }
            let n = w.cwnd / SMSS;
            let end = seq + (n * SMSS) as u32;
            for _ in 0..n {
                seq += SMSS as u32;
                let a = ack(now, SMSS, Some(rtt(round)), seq, end + (n * SMSS) as u32);
                c.on_ack(w, &a);
            }
            now += rtt(round);
        }
        None
    }

    #[test]
    fn hystart_leaves_slow_start_when_the_delay_grows() {
        // 50 ms until round 5, then a filling queue adds 10 ms a round.
        let mut c = Cubic::default();
        let mut w = window(10, usize::MAX / SMSS);
        let left = slow_start_rounds(&mut c, &mut w, 20, |r| 50 + 10 * r.saturating_sub(4) as u64);
        let left = left.expect("still in slow start");
        assert!(c.hystart.done && !w.in_slow_start());
        // Conservative slow start's rounds after the delay grew, and it
        // grew by a quarter a round meanwhile, not double.
        assert!((8..=12).contains(&left), "{left} {w:?}");
        assert!(w.cwnd < ((10 * SMSS) << left) / 4, "{left} {w:?}");
        // Without the delay, slow start goes on.
        let mut c = Cubic::default();
        let mut w = window(10, usize::MAX / SMSS);
        assert_eq!(slow_start_rounds(&mut c, &mut w, 8, |_| 50), None);
        assert!(w.in_slow_start() && w.cwnd >= (10 * SMSS) << 7, "{w:?}");
    }

    #[test]
    fn hystart_goes_back_to_slow_start_when_the_delay_falls() {
        let mut c = Cubic::default();
        let mut w = window(10, usize::MAX / SMSS);
        // One slow round (a spike), then back to normal.
        let left = slow_start_rounds(&mut c, &mut w, 8, |r| if r == 2 { 80 } else { 50 });
        assert_eq!(left, None);
        assert!(w.in_slow_start() && !c.hystart.done, "{c:?}");
        assert!(c.hystart.css_baseline.is_none(), "{c:?}");
    }
}
