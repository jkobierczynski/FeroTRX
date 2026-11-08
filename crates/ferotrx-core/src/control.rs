//! Live control of a running [`run`](crate::run): pause, resume and the rate,
//! for the whole run or one stream, while it goes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use crate::{Error, Result};

/// The highest rate multiplier [`RunControl`] takes.
pub const MAX_MULTIPLIER: f64 = 1e6;

/// Changes a run while it goes: pause and resume, and a rate multiplier, for
/// the whole run and for each stream (by its index in the run).
///
/// A run reads it between packets ([`RunConfig::control`](crate::RunConfig::control));
/// the schedule is kept, not restarted: a paused stream picks up where it
/// stopped, and a new multiplier speeds up or slows down what is still to
/// come (a capture's own timing, a packet or bit rate and a traffic model's
/// shape alike), so the packets already sent keep their times. Every worker of
/// a run split over several cores shares one control.
///
/// ```
/// use ferotrx_core::*;
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// let cap = Arc::new(Capture::new(1, vec![Packet::new(Duration::ZERO, vec![0u8; 60])]));
/// let stream = Stream::new("a", CaptureSource::new(cap).loops(0)).with_rate(Rate::Pps(1000.0));
/// let job = Job::spawn(vec![stream], Box::new(NullSink), RunConfig::default()).unwrap();
/// job.control().pause();
/// std::thread::sleep(Duration::from_millis(100));
/// let held = job.stats().total.packets;
/// std::thread::sleep(Duration::from_millis(200));
/// assert!(job.stats().total.packets <= held + 1);
/// job.control().set_multiplier(2.0).unwrap();
/// job.control().resume();
/// job.stop();
/// job.join().unwrap();
/// ```
#[derive(Debug, Default)]
pub struct RunControl {
    /// Bumped on every change, so a run sees it without taking the lock.
    generation: AtomicU64,
    state: Mutex<ControlState>,
}

/// What a [`RunControl`] says now.
#[derive(Clone, Debug, PartialEq)]
pub struct ControlState {
    pub paused: bool,
    /// The whole run's rate multiplier (1 = as asked).
    pub multiplier: f64,
    /// Per stream, by index; streams past the end are as asked.
    pub streams: Vec<StreamControl>,
}

impl Default for ControlState {
    fn default() -> Self {
        Self {
            paused: false,
            multiplier: 1.0,
            streams: Vec::new(),
        }
    }
}

/// One stream's part of a [`ControlState`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StreamControl {
    pub paused: bool,
    pub multiplier: f64,
}

impl Default for StreamControl {
    fn default() -> Self {
        Self {
            paused: false,
            multiplier: 1.0,
        }
    }
}

impl ControlState {
    /// Stream `i`'s settings.
    pub fn stream(&self, i: usize) -> StreamControl {
        self.streams.get(i).copied().unwrap_or_default()
    }

    /// How fast stream `i`'s schedule runs: 0 while it or the run is
    /// paused, else the run's multiplier times the stream's.
    pub fn speed(&self, i: usize) -> f64 {
        let s = self.stream(i);
        if self.paused || s.paused {
            0.0
        } else {
            self.multiplier * s.multiplier
        }
    }
}

fn check(multiplier: f64) -> Result<f64> {
    if multiplier.is_finite() && multiplier > 0.0 && multiplier <= MAX_MULTIPLIER {
        Ok(multiplier)
    } else {
        Err(Error::InvalidRate(format!(
            "a rate multiplier must be above 0 and at most {MAX_MULTIPLIER}, got {multiplier}"
        )))
    }
}

impl RunControl {
    pub fn new() -> Self {
        Self::default()
    }

    fn change(&self, f: impl FnOnce(&mut ControlState)) {
        f(&mut self.lock());
        self.generation.fetch_add(1, Ordering::Release);
    }

    fn lock(&self) -> MutexGuard<'_, ControlState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn stream_mut(state: &mut ControlState, i: usize) -> &mut StreamControl {
        if state.streams.len() <= i {
            state.streams.resize(i + 1, StreamControl::default());
        }
        &mut state.streams[i]
    }

    /// A number that changes whenever the control does.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// What it says now.
    pub fn state(&self) -> ControlState {
        self.lock().clone()
    }

    /// Holds every stream where it is.
    pub fn pause(&self) {
        self.change(|s| s.paused = true);
    }

    /// Lets the run go on (streams paused one by one stay paused).
    pub fn resume(&self) {
        self.change(|s| s.paused = false);
    }

    /// Runs every stream at `multiplier` times the rate it was asked for
    /// (times its own multiplier).
    pub fn set_multiplier(&self, multiplier: f64) -> Result<()> {
        let m = check(multiplier)?;
        self.change(|s| s.multiplier = m);
        Ok(())
    }

    pub fn pause_stream(&self, i: usize) {
        self.change(|s| Self::stream_mut(s, i).paused = true);
    }

    pub fn resume_stream(&self, i: usize) {
        self.change(|s| Self::stream_mut(s, i).paused = false);
    }

    /// Runs stream `i` at `multiplier` times its rate (times the run's multiplier).
    pub fn set_stream_multiplier(&self, i: usize, multiplier: f64) -> Result<()> {
        let m = check(multiplier)?;
        self.change(|s| Self::stream_mut(s, i).multiplier = m);
        Ok(())
    }
}

/// Maps a stream's own schedule (the times its pacer gives) to the run's
/// clock, as the speed changes: the time since the run started is
/// `anchor_real + (schedule - anchor_sched) / speed`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LaneClock {
    anchor_real: f64,
    anchor_sched: f64,
    speed: f64,
}

impl Default for LaneClock {
    fn default() -> Self {
        Self {
            anchor_real: 0.0,
            anchor_sched: 0.0,
            speed: 1.0,
        }
    }
}

impl LaneClock {
    /// Where the schedule is at `real` seconds into the run.
    pub(crate) fn sched(&self, real: f64) -> f64 {
        self.anchor_sched + (real - self.anchor_real).max(0.0) * self.speed
    }

    /// When (seconds into the run) the schedule reaches `sched`; infinite
    /// while paused.
    pub(crate) fn real(&self, sched: f64) -> f64 {
        if self.speed <= 0.0 {
            return f64::INFINITY;
        }
        self.anchor_real + (sched - self.anchor_sched).max(0.0) / self.speed
    }

    /// From `real` on, the schedule runs at `speed`.
    pub(crate) fn set_speed(&mut self, real: f64, speed: f64) {
        self.anchor_sched = self.sched(real);
        self.anchor_real = real;
        self.speed = speed;
    }

    /// The schedule starts over at 0 from `real` (a stream started by another
    /// one's end).
    pub(crate) fn restart(&mut self, real: f64) {
        self.anchor_real = real;
        self.anchor_sched = 0.0;
    }

    pub(crate) fn paused(&self) -> bool {
        self.speed <= 0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn speeds_combine_and_pause() {
        let c = RunControl::new();
        let g = c.generation();
        c.set_multiplier(2.0).unwrap();
        c.set_stream_multiplier(1, 0.5).unwrap();
        assert!(c.generation() > g);
        let s = c.state();
        assert_eq!((s.speed(0), s.speed(1), s.speed(5)), (2.0, 1.0, 2.0));
        c.pause_stream(0);
        assert_eq!(c.state().speed(0), 0.0);
        c.pause();
        assert_eq!(c.state().speed(1), 0.0);
        c.resume();
        assert_eq!((c.state().speed(0), c.state().speed(1)), (0.0, 1.0));
        assert!(c.set_multiplier(0.0).is_err());
        assert!(c.set_multiplier(f64::NAN).is_err());
    }

    #[test]
    fn a_clock_keeps_the_schedule_across_changes() {
        let mut k = LaneClock::default();
        assert_eq!(k.real(1.0), 1.0);
        // At 1 s, twice as fast: schedule time 3 comes at 2 s.
        k.set_speed(1.0, 2.0);
        assert_eq!(k.real(3.0), 2.0);
        // Paused at 2 s for ever...
        k.set_speed(2.0, 0.0);
        assert!(k.real(3.5).is_infinite());
        assert_eq!(k.sched(10.0), 3.0);
        // ...resumed at 10 s at 1x: schedule 3.5 is at 10.5 s.
        k.set_speed(10.0, 1.0);
        assert_eq!(k.real(3.5), 10.5);
    }
}
