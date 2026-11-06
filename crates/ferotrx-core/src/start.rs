//! Starting at a given wall-clock time, so that runs on several machines
//! begin together.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

/// Longest nap while waiting, so a stop is seen soon.
const NAP: Duration = Duration::from_millis(20);

/// Waits until the wall clock reaches `at` (at once for `None` or a time
/// gone by), or until `stop` is set, and returns the time it ended.
///
/// It sleeps in short naps and spins the last millisecond, so the start is
/// within about a millisecond of `at` on an idle machine.
///
/// ```
/// use std::sync::atomic::AtomicBool;
/// use std::time::{Duration, SystemTime};
///
/// let at = SystemTime::now() + Duration::from_millis(30);
/// let started = ferotrx_core::wait_until(Some(at), &AtomicBool::new(false));
/// assert!(started >= at);
/// ```
pub fn wait_until(at: Option<SystemTime>, stop: &AtomicBool) -> SystemTime {
    let Some(at) = at else {
        return SystemTime::now();
    };
    loop {
        let now = SystemTime::now();
        let Ok(left) = at.duration_since(now) else {
            return now;
        };
        if left.is_zero() || stop.load(Ordering::Relaxed) {
            return now;
        }
        if left > Duration::from_millis(1) {
            std::thread::sleep((left - Duration::from_millis(1)).min(NAP));
        } else {
            std::thread::yield_now();
        }
    }
}

/// Seconds since the Unix epoch, as the control protocol carries times.
pub fn unix_seconds(t: SystemTime) -> f64 {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => d.as_secs_f64(),
        Err(e) => -e.duration().as_secs_f64(),
    }
}

/// The time `s` seconds after the Unix epoch; `None` for a value that is
/// not a finite time.
pub fn from_unix_seconds(s: f64) -> Option<SystemTime> {
    if !s.is_finite() || s.abs() > 1e11 {
        return None;
    }
    let d = Duration::from_secs_f64(s.abs());
    if s >= 0.0 {
        SystemTime::UNIX_EPOCH.checked_add(d)
    } else {
        SystemTime::UNIX_EPOCH.checked_sub(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_for_the_time() {
        let stop = AtomicBool::new(false);
        let at = SystemTime::now() + Duration::from_millis(50);
        let t = wait_until(Some(at), &stop);
        let late = t.duration_since(at).unwrap();
        // Shared CI machines (macOS ones most) oversleep by tens of ms.
        let slack = Duration::from_millis(if cfg!(target_os = "macos") { 100 } else { 20 });
        assert!(late < slack, "{late:?}");
        // A time gone by, or none, starts at once.
        let t0 = SystemTime::now();
        wait_until(Some(t0 - Duration::from_secs(5)), &stop);
        wait_until(None, &stop);
        assert!(t0.elapsed().unwrap() < slack);
    }

    #[test]
    fn a_stop_ends_the_wait() {
        let stop = AtomicBool::new(true);
        let t0 = SystemTime::now();
        wait_until(Some(t0 + Duration::from_secs(30)), &stop);
        assert!(t0.elapsed().unwrap() < Duration::from_secs(1));
    }

    #[test]
    fn unix_seconds_round_trip() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_millis(1_762_400_000_123);
        let s = unix_seconds(t);
        assert!((s - 1_762_400_000.123).abs() < 1e-6);
        let back = from_unix_seconds(s).unwrap();
        let diff = back.duration_since(t).unwrap_or_else(|e| e.duration());
        assert!(diff < Duration::from_micros(1));
        assert!(from_unix_seconds(f64::NAN).is_none());
        assert!(from_unix_seconds(1e300).is_none());
    }
}
