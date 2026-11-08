//! The drop counters an operating system keeps for a network interface, read
//! as deltas over a run: what the NIC had no room for, dropped as bad, or
//! failed to send.
//!
//! Linux reads `/sys/class/net/IFACE/statistics`, Windows `GetIfEntry2`.
//! Other systems (macOS) have no reading: the counters stay zero.

use ferotrx_core::DropCounters;

/// The counters of one interface when the run started, to report what went
/// up since.
#[derive(Clone, Debug)]
pub struct NicCounters {
    name: String,
    start: Option<DropCounters>,
}

impl NicCounters {
    /// Starts counting on `interface` (a Linux name, or a Windows adapter
    /// name or Npcap device). An interface without counters reports zero.
    pub fn new(interface: &str) -> NicCounters {
        let name = interface.to_string();
        let start = read(&name);
        NicCounters { name, start }
    }

    /// What went up since [`new`](Self::new), on both sides.
    pub fn since_start(&self) -> DropCounters {
        match (&self.start, read(&self.name)) {
            (Some(start), Some(now)) => now.since(start),
            _ => DropCounters::default(),
        }
    }

    /// The receiving side of [`since_start`](Self::since_start).
    pub fn rx(&self) -> DropCounters {
        self.since_start().rx_side()
    }

    /// The sending side of [`since_start`](Self::since_start).
    pub fn tx(&self) -> DropCounters {
        self.since_start().tx_side()
    }
}

/// The interface's counters now, if it has any.
pub fn read(interface: &str) -> Option<DropCounters> {
    imp::read(interface)
}

#[cfg(target_os = "linux")]
mod imp {
    use ferotrx_core::DropCounters;

    pub fn read(interface: &str) -> Option<DropCounters> {
        if interface.is_empty() || interface.contains('/') || interface.starts_with('.') {
            return None;
        }
        let dir = format!("/sys/class/net/{interface}/statistics");
        let n = |name: &str| -> Option<u64> {
            std::fs::read_to_string(format!("{dir}/{name}"))
                .ok()?
                .trim()
                .parse()
                .ok()
        };
        // An interface without the directory has no counters at all.
        let rx_errors = n("rx_errors")?;
        let z = |name: &str| n(name).unwrap_or(0);
        Some(from_sysfs(
            z("rx_missed_errors"),
            z("rx_fifo_errors"),
            rx_errors,
            z("tx_errors"),
            z("tx_dropped"),
        ))
    }

    /// Linux counts `rx_missed_errors` and `rx_fifo_errors` inside
    /// `rx_errors` too: they go to "missed" only. `rx_dropped` is left out:
    /// it counts frames the stack did not want (an unknown protocol, a
    /// VLAN nobody listens to) after captures saw them, not frames lost.
    pub fn from_sysfs(
        missed: u64,
        fifo: u64,
        errors: u64,
        tx_errors: u64,
        tx_dropped: u64,
    ) -> DropCounters {
        let nic_rx_missed = missed + fifo;
        DropCounters {
            nic_rx_missed,
            nic_rx_errors: errors.saturating_sub(nic_rx_missed),
            nic_tx_errors: tx_errors + tx_dropped,
            ..Default::default()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn missed_frames_are_not_counted_twice() {
            let d = from_sysfs(3, 1, 10, 4, 5);
            assert_eq!(
                (d.nic_rx_missed, d.nic_rx_errors, d.nic_tx_errors),
                (4, 6, 9)
            );
        }

        #[test]
        fn loopback_has_counters() {
            assert!(read("lo").is_some());
            assert!(read("no-such-iface0").is_none());
            assert!(read("../lo").is_none());
        }
    }
}

#[cfg(windows)]
mod imp {
    use ferotrx_core::DropCounters;

    pub fn read(interface: &str) -> Option<DropCounters> {
        let adapters = crate::windows::adapters();
        let device = crate::windows::resolve_in(&adapters, interface);
        let a = crate::windows::adapter_of(&adapters, &device)?;
        let [in_discards, in_errors, out_discards, out_errors] =
            crate::windows::if_counters(a.luid)?;
        Some(DropCounters {
            nic_rx_missed: in_discards,
            nic_rx_errors: in_errors,
            nic_tx_errors: out_discards + out_errors,
            ..Default::default()
        })
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod imp {
    use ferotrx_core::DropCounters;

    pub fn read(_interface: &str) -> Option<DropCounters> {
        None
    }
}
