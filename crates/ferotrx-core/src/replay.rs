use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use crate::{
    run_with_progress, Capture, CaptureSource, PacketSink, Rate, Result, RunConfig, Stream,
};

/// Settings for one replay run.
#[derive(Clone, Debug)]
pub struct ReplayConfig {
    pub rate: Rate,
    /// Times to play the capture. 0 loops forever (until `stop` or `limit`).
    pub loops: u64,
    /// Stop after this many packets in total.
    pub limit: Option<u64>,
    /// Stop after this much time.
    pub duration: Option<Duration>,
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
            duration: None,
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
///
/// This is a [`run`](crate::run) of one [`Stream`] over a [`CaptureSource`].
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
    let mut streams = [
        Stream::new("capture", CaptureSource::new(capture).loops(config.loops))
            .with_rate(config.rate),
    ];
    let run_config = RunConfig {
        limit: config.limit,
        duration: config.duration,
        ignore_send_errors: config.ignore_send_errors,
        stop: config.stop.clone(),
    };
    let mut sink = sink;
    let stats = run_with_progress(&mut streams, &mut sink, &run_config, interval, |s| {
        progress(&s.total)
    })?;
    Ok(stats.total)
}
