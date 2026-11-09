//! The sweep: a repeatable measurement of what the sender and the path
//! carry per frame size, with the spread over several trials.
//!
//! For every size, one warm-up trial at the sweep load is sent and thrown
//! away (caches, ARP tables, the NIC's rings and the CPU's clock settle),
//! then `repetitions` trials at that load. Each figure is reported as the
//! median of the trials with their minimum, maximum and spread, so two
//! sweeps can be compared, and a single slow trial does not move it.

use std::time::Duration;

use super::{Bench, BenchTest, SizeReport, Step, TrialRecord};
use crate::SizeMix;

/// The middle and the spread of one figure over the trials of a sweep.
#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Spread {
    pub median: f64,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    /// Sample standard deviation (0 for one trial).
    pub stddev: f64,
    /// `max - min` in percent of the median: how far apart the trials are.
    pub spread_pct: f64,
}

impl Spread {
    /// The spread of `values`; `None` when there are none.
    pub fn of(values: &[f64]) -> Option<Spread> {
        let mut v: Vec<f64> = values.iter().copied().filter(|x| x.is_finite()).collect();
        if v.is_empty() {
            return None;
        }
        v.sort_by(f64::total_cmp);
        let n = v.len();
        let median = if n % 2 == 1 {
            v[n / 2]
        } else {
            (v[n / 2 - 1] + v[n / 2]) / 2.0
        };
        let mean = v.iter().sum::<f64>() / n as f64;
        let stddev = if n > 1 {
            (v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64).sqrt()
        } else {
            0.0
        };
        let (min, max) = (v[0], v[n - 1]);
        Some(Spread {
            median,
            min,
            max,
            mean,
            stddev,
            spread_pct: if median != 0.0 {
                (max - min) / median.abs() * 100.0
            } else {
                0.0
            },
        })
    }
}

/// A sweep's results for one frame size.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SweepResult {
    /// Offered load, percent of the line rate.
    pub load_pct: f64,
    pub offered_pps: f64,
    /// Trials measured (the warm-up not counted).
    pub trials: u32,
    /// Sent: frames per second, Mbit/s of frames, Mbit/s on the wire.
    pub tx_pps: Spread,
    pub tx_mbps: Spread,
    pub tx_l1_mbps: Spread,
    /// Received frames per second.
    pub rx_pps: Spread,
    pub loss_pct: Spread,
    /// Latency medians and 99th percentiles of the trials, in microseconds.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub latency_p50_us: Option<Spread>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub latency_p99_us: Option<Spread>,
    /// Trials where the sender stayed below 97% of the offered rate.
    pub sender_limited: u32,
}

impl SweepResult {
    /// The results of `trials` (the sweep trials of one size).
    pub fn of(trials: &[&TrialRecord], load_pct: f64, offered_pps: f64) -> Option<SweepResult> {
        let col = |f: fn(&TrialRecord) -> f64| trials.iter().map(|t| f(t)).collect::<Vec<_>>();
        let lat = |f: fn(&TrialRecord) -> Option<f64>| {
            Spread::of(&trials.iter().filter_map(|t| f(t)).collect::<Vec<_>>())
        };
        Some(SweepResult {
            load_pct,
            offered_pps,
            trials: trials.len() as u32,
            tx_pps: Spread::of(&col(|t| t.achieved_pps))?,
            tx_mbps: Spread::of(&col(|t| t.achieved_mbps))?,
            tx_l1_mbps: Spread::of(&col(|t| t.achieved_l1_mbps))?,
            rx_pps: Spread::of(&col(|t| t.rx_pps))?,
            loss_pct: Spread::of(&col(|t| t.loss_pct))?,
            latency_p50_us: lat(|t| t.latency.p50_us),
            latency_p99_us: lat(|t| t.latency.p99_us),
            sender_limited: trials.iter().filter(|t| t.sender_limited()).count() as u32,
        })
    }
}

/// The warm-up of a sweep when the profile sets none.
const SWEEP_WARMUP: Duration = Duration::from_secs(1);

impl Bench<'_> {
    pub(super) fn sweep(&mut self, size: &SizeMix, sr: &mut SizeReport) -> Step<()> {
        let c = self.config;
        let load = c.max_load;
        self.check_stop()?;
        let mut warm = self.trial(BenchTest::Sweep, size, sr, load);
        warm.duration = Some(if c.warmup.is_zero() {
            c.trial_duration.min(SWEEP_WARMUP)
        } else {
            c.warmup
        });
        warm.packets = None;
        warm.warmup = true;
        self.runner.run(&warm)?;
        let first = sr.trials.len();
        let t = self.trial(BenchTest::Sweep, size, sr, load);
        for rep in 1..=c.repetitions {
            self.run(&t, sr, rep, |_| None)?;
        }
        let trials: Vec<&TrialRecord> = sr.trials[first..].iter().collect();
        sr.sweep = SweepResult::of(&trials, load, t.pps);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spread_of_values() {
        let s = Spread::of(&[10.0, 12.0, 11.0, 9.0]).unwrap();
        assert_eq!((s.median, s.min, s.max, s.mean), (10.5, 9.0, 12.0, 10.5));
        assert!((s.spread_pct - 3.0 / 10.5 * 100.0).abs() < 1e-9);
        assert!((s.stddev - 1.2909944487358056).abs() < 1e-9);
        let one = Spread::of(&[5.0]).unwrap();
        assert_eq!((one.median, one.stddev, one.spread_pct), (5.0, 0.0, 0.0));
        assert!(Spread::of(&[]).is_none());
    }
}
