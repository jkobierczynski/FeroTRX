//! Running one profile on several cores: what the workers share and how
//! their counters add up.
//!
//! * Streams: each worker runs its own copy of the streams, made with
//!   [`Stream::shard`](crate::Stream::shard), into its own sink;
//!   [`Job::spawn_workers`](crate::Job::spawn_workers) runs them.
//! * Stateful TCP and UDP: [`TcpConfig::split`](crate::TcpConfig::split) and
//!   [`UdpConfig::split`](crate::UdpConfig::split) give each worker an engine
//!   of its own with a part of the client's source ports and of the rates, and
//!   a [`FlowRouter`](crate::FlowRouter) that says which worker each received
//!   frame belongs to; [`PortJob::spawn_workers`](crate::PortJob::spawn_workers)
//!   runs them.
//!
//! `docs/multi-core.md` explains the whole scheme.

use crate::{ReplayStats, RunStats};

/// Worker `index`'s share of `total` things split over `count` workers: as
/// even as can be, the first workers taking one more when it does not divide.
///
/// ```
/// let shares: Vec<u64> = (0..3).map(|k| ferotrx_core::share(10, k, 3)).collect();
/// assert_eq!(shares, [4, 3, 3]);
/// ```
pub fn share(total: u64, index: usize, count: usize) -> u64 {
    let (k, n) = (index as u64, count.max(1) as u64);
    total / n + u64::from(k < total % n)
}

/// A seed for worker `index`, from the run's `seed`: worker 0 keeps it, so a
/// run on one worker is the same as before.
pub fn worker_seed(seed: u64, index: usize) -> u64 {
    seed.wrapping_add((index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15))
}

/// Counters that add up over workers.
pub trait MergeStats {
    /// Adds `other`'s counters, from another worker of the same run, to these.
    fn merge(&mut self, other: &Self);
}

/// Adds every worker's counters together.
pub fn merge_all<S: MergeStats + Clone + Default>(parts: &[S]) -> S {
    let mut iter = parts.iter();
    let mut total = iter.next().cloned().unwrap_or_default();
    for p in iter {
        total.merge(p);
    }
    total
}

/// Sums; the longest elapsed time; stopped if any worker was. Loops are the
/// most any worker has seen: every worker walks the whole source, sending its
/// share of each pass.
impl MergeStats for ReplayStats {
    fn merge(&mut self, o: &Self) {
        self.packets += o.packets;
        self.bytes += o.bytes;
        self.send_errors += o.send_errors;
        self.loops_completed = self.loops_completed.max(o.loops_completed);
        self.tagged += o.tagged;
        self.elapsed = self.elapsed.max(o.elapsed);
        self.stopped |= o.stopped;
    }
}

impl MergeStats for RunStats {
    fn merge(&mut self, o: &Self) {
        for (a, b) in self.streams.iter_mut().zip(&o.streams) {
            a.merge(b);
        }
        let loops = self.streams.iter().map(|s| s.loops_completed).sum();
        self.total.merge(&o.total);
        self.total.loops_completed = loops;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shares_add_up() {
        for total in [0, 1, 7, 100, 101] {
            for count in 1..9 {
                let sum: u64 = (0..count).map(|k| share(total, k, count)).sum();
                assert_eq!(sum, total);
            }
        }
        assert_eq!(worker_seed(42, 0), 42);
        assert_ne!(worker_seed(42, 1), worker_seed(42, 2));
    }
}
