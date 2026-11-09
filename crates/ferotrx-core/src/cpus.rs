//! Pinning worker threads to CPUs: a list of CPUs (`0-3,8`), and the hook
//! the platform crate gives to pin the calling thread to one of them.

use std::fmt;
use std::str::FromStr;

use crate::{Error, Result};

/// A list of CPUs, as `0-3,8,10-11` (Linux's `cpuset` form). Order is kept:
/// worker `k` runs on the `k`-th CPU (wrapping when there are more workers
/// than CPUs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CpuList(pub Vec<usize>);

/// The highest CPU number accepted.
pub const MAX_CPU: usize = 4095;

impl CpuList {
    /// The CPU of worker `k`.
    pub fn for_worker(&self, k: usize) -> Option<usize> {
        (!self.0.is_empty()).then(|| self.0[k % self.0.len()])
    }

    /// The CPUs `workers` threads run on, in worker order, each once.
    pub fn used_by(&self, workers: usize) -> CpuList {
        CpuList(self.0.iter().copied().take(workers.max(1)).collect())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromStr for CpuList {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let bad = || {
            Error::InvalidSpec(format!(
                "'{s}' is not a list of CPUs such as 0-3,8 (numbers up to {MAX_CPU})"
            ))
        };
        let mut out = Vec::new();
        for part in s.split(',').map(str::trim) {
            if part.is_empty() {
                return Err(bad());
            }
            let (a, b) = match part.split_once('-') {
                Some((a, b)) => (a.trim(), b.trim()),
                None => (part, part),
            };
            let a: usize = a.parse().map_err(|_| bad())?;
            let b: usize = b.parse().map_err(|_| bad())?;
            if a > b || b > MAX_CPU {
                return Err(bad());
            }
            for c in a..=b {
                if out.contains(&c) {
                    return Err(Error::InvalidSpec(format!(
                        "CPU {c} is listed twice in '{s}'"
                    )));
                }
                out.push(c);
            }
        }
        Ok(CpuList(out))
    }
}

impl fmt::Display for CpuList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = &self.0;
        let mut i = 0;
        let mut first = true;
        while i < c.len() {
            let mut j = i;
            while j + 1 < c.len() && c[j + 1] == c[j] + 1 {
                j += 1;
            }
            if !first {
                f.write_str(",")?;
            }
            first = false;
            if j > i {
                write!(f, "{}-{}", c[i], c[j])?;
            } else {
                write!(f, "{}", c[i])?;
            }
            i = j + 1;
        }
        Ok(())
    }
}

/// Pins the calling thread to one CPU; given by the platform crate
/// (`ferotrx_io::pin_thread`).
pub type PinFn = fn(usize) -> std::result::Result<(), String>;

/// Which CPUs a run's workers go on, and how to pin a thread.
#[derive(Clone)]
pub struct CpuPinning {
    pub cpus: CpuList,
    pub pin: PinFn,
}

impl fmt::Debug for CpuPinning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CpuPinning({})", self.cpus)
    }
}

impl CpuPinning {
    /// Pins the calling thread, worker `k`'s, to its CPU.
    pub fn pin_worker(&self, k: usize) -> Result<()> {
        match self.cpus.for_worker(k) {
            Some(cpu) => (self.pin)(cpu).map_err(|e| {
                Error::InvalidSpec(format!("cannot pin worker {k} to CPU {cpu}: {e}"))
            }),
            None => Ok(()),
        }
    }
}

/// Pins worker `k` when there is a pinning.
pub(crate) fn pin(pinning: &Option<CpuPinning>, k: usize) -> Result<()> {
    match pinning {
        Some(p) => p.pin_worker(k),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_parse_and_print() {
        let l: CpuList = "0-3, 8,10-11".parse().unwrap();
        assert_eq!(l.0, vec![0, 1, 2, 3, 8, 10, 11]);
        assert_eq!(l.to_string(), "0-3,8,10-11");
        assert_eq!("5".parse::<CpuList>().unwrap().0, vec![5]);
        // Order is kept: worker 0 on CPU 6.
        let l: CpuList = "6,2".parse().unwrap();
        assert_eq!(
            (l.for_worker(0), l.for_worker(1), l.for_worker(2)),
            (Some(6), Some(2), Some(6))
        );
        for bad in ["", "a", "3-1", "1,,2", "1,1", "5000"] {
            assert!(bad.parse::<CpuList>().is_err(), "{bad}");
        }
    }

    #[test]
    fn a_failed_pin_names_the_worker() {
        fn no(_: usize) -> std::result::Result<(), String> {
            Err("not allowed".into())
        }
        let p = Some(CpuPinning {
            cpus: "4".parse().unwrap(),
            pin: no,
        });
        let e = pin(&p, 2).unwrap_err().to_string();
        assert!(e.contains("worker 2 to CPU 4: not allowed"), "{e}");
        assert!(pin(&None, 0).is_ok());
    }
}
