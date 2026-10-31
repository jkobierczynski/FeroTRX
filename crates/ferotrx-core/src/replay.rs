use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::{Capture, Error, Pacer, PacketSink, Rate, Result};

/// Settings for one replay run.
#[derive(Clone, Debug)]
pub struct ReplayConfig {
    pub rate: Rate,
    /// Times to play the capture. 0 loops forever (until `stop` or `limit`).
    pub loops: u64,
    /// Stop after this many packets in total.
    pub limit: Option<u64>,
    /// Count failed sends and carry on, instead of stopping at the first failure.
    pub ignore_send_errors: bool,
    /// Set to true from another thread (for example a Ctrl-C handler) to stop early.
    pub stop: Option<Arc<AtomicBool>>,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            rate: Rate::default(),
            loops: 1,
            limit: None,
            ignore_send_errors: false,
            stop: None,
        }
    }
}

/// Counters for a replay, final or in progress.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReplayStats {
    pub packets: u64,
    pub bytes: u64,
    pub send_errors: u64,
    pub loops_completed: u64,
    pub elapsed: Duration,
    /// True when the replay ended because `stop` was set.
    pub stopped: bool,
}

impl ReplayStats {
    /// Achieved packets per second.
    pub fn pps(&self) -> f64 {
        per_second(self.packets as f64, self.elapsed)
    }

    /// Achieved megabits per second (10^6 bits).
    pub fn mbps(&self) -> f64 {
        per_second(self.bytes as f64 * 8.0 / 1e6, self.elapsed)
    }
}

fn per_second(value: f64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs > 0.0 {
        value / secs
    } else {
        0.0
    }
}

/// Replays `capture` into `sink` as `config` says, and returns the final counters.
pub fn replay<S: PacketSink + ?Sized>(
    capture: &Capture,
    sink: &mut S,
    config: &ReplayConfig,
) -> Result<ReplayStats> {
    replay_with_progress(capture, sink, config, Duration::MAX, |_| {})
}

/// Like [`replay`], and calls `progress` with the running counters about every `interval`.
pub fn replay_with_progress<S, F>(
    capture: &Capture,
    sink: &mut S,
    config: &ReplayConfig,
    interval: Duration,
    mut progress: F,
) -> Result<ReplayStats>
where
    S: PacketSink + ?Sized,
    F: FnMut(&ReplayStats),
{
    config.rate.validate()?;
    let mut stats = ReplayStats::default();
    if capture.is_empty() {
        return Ok(stats);
    }

    let first_ts = capture.packets[0].timestamp;
    let span = capture.duration();
    // One loop lasts the capture's span plus one average gap, so the first packet
    // of the next loop does not land on top of the last packet of this one.
    let gap = if capture.len() > 1 {
        span / (capture.len() as u32 - 1).max(1)
    } else {
        Duration::ZERO
    };
    let loop_period = span + gap;

    let stop_requested = || {
        config
            .stop
            .as_ref()
            .is_some_and(|s| s.load(Ordering::Relaxed))
    };
    let mut pacer = Pacer::new(config.rate);
    let start = Instant::now();
    let mut next_report = start.checked_add(interval);
    let mut loop_index: u64 = 0;

    'outer: while config.loops == 0 || loop_index < config.loops {
        let loop_offset = loop_period.saturating_mul(loop_index.min(u32::MAX as u64) as u32);
        for packet in &capture.packets {
            if config
                .limit
                .is_some_and(|l| stats.packets + stats.send_errors >= l)
            {
                break 'outer;
            }
            let capture_offset = loop_offset + packet.timestamp.saturating_sub(first_ts);
            if let Some(deadline) = pacer.next_deadline(capture_offset, packet.data.len()) {
                if !wait_until(start + deadline, &stop_requested) {
                    stats.stopped = true;
                    break 'outer;
                }
            } else if stop_requested() {
                stats.stopped = true;
                break 'outer;
            }

            match sink.send(&packet.data) {
                Ok(()) => {
                    stats.packets += 1;
                    stats.bytes += packet.data.len() as u64;
                }
                Err(_) if config.ignore_send_errors => stats.send_errors += 1,
                Err(source) => {
                    stats.elapsed = start.elapsed();
                    let _ = sink.flush();
                    return Err(Error::Sink {
                        index: stats.packets + stats.send_errors,
                        source,
                    });
                }
            }

            if let Some(at) = next_report {
                let now = Instant::now();
                if now >= at {
                    stats.elapsed = now - start;
                    progress(&stats);
                    next_report = now.checked_add(interval);
                }
            }
        }
        loop_index += 1;
        stats.loops_completed = loop_index;
    }

    sink.flush().map_err(|source| Error::Sink {
        index: stats.packets,
        source,
    })?;
    stats.elapsed = start.elapsed();
    Ok(stats)
}

/// Waits until `target`, sleeping while far away and spinning for the last stretch,
/// because OS sleeps are too coarse for sub-millisecond gaps.
/// Returns false if a stop was requested while waiting.
fn wait_until(target: Instant, stop_requested: &impl Fn() -> bool) -> bool {
    const SPIN: Duration = Duration::from_micros(200);
    const MAX_SLEEP: Duration = Duration::from_millis(50);
    loop {
        if stop_requested() {
            return false;
        }
        let now = Instant::now();
        if now >= target {
            return true;
        }
        let remaining = target - now;
        if remaining > SPIN {
            std::thread::sleep((remaining - SPIN).min(MAX_SLEEP));
        } else {
            std::hint::spin_loop();
        }
    }
}
