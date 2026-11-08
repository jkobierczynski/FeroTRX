//! Where frames went missing: drop counters from every layer a frame passes
//! (the NIC, an AF_XDP ring, the capture buffer), and a loss report that
//! splits what a run lost into what the generator never sent, what the
//! network lost and what the receiver dropped before FeroTRX read it.

/// Frames dropped on one side of a port, by layer, as the OS or driver
/// counts them. Zero where a layer has no counter or the port does not
/// pass through it. The NIC counters are deltas over the run, of everything
/// on the interface (not only FeroTRX's frames).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct DropCounters {
    /// Received frames the NIC had no room for: Linux `rx_missed_errors`
    /// and `rx_fifo_errors`, Windows `InDiscards`, DPDK `imissed` and
    /// `rx_nombuf`.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_zero"))]
    pub nic_rx_missed: u64,
    /// Received frames the NIC or driver dropped as bad or unwanted: Linux
    /// `rx_errors` and `rx_dropped`, Windows `InErrors`, DPDK `ierrors`.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_zero"))]
    pub nic_rx_errors: u64,
    /// Received frames an AF_XDP socket lost: its ring was full, the fill
    /// ring was empty, or the kernel dropped them (`XDP_STATISTICS`).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_zero"))]
    pub ring_rx_dropped: u64,
    /// Frames the capture buffer had no room for (libpcap/Npcap `ps_drop`).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_zero"))]
    pub capture_dropped: u64,
    /// Frames the NIC failed to send: Linux `tx_errors` and `tx_dropped`,
    /// Windows `OutDiscards` and `OutErrors`, DPDK `oerrors`.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_zero"))]
    pub nic_tx_errors: u64,
    /// Frames an AF_XDP socket refused to send (`tx_invalid_descs`).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_zero"))]
    pub ring_tx_invalid: u64,
}

#[cfg(feature = "serde")]
fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl DropCounters {
    /// Received frames dropped before FeroTRX read them, every layer.
    pub fn rx_total(&self) -> u64 {
        self.nic_rx_missed + self.nic_rx_errors + self.ring_rx_dropped + self.capture_dropped
    }

    /// Frames handed to the sender that did not leave, every layer.
    pub fn tx_total(&self) -> u64 {
        self.nic_tx_errors + self.ring_tx_invalid
    }

    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Adds `o`'s counters (another worker's port, another queue).
    pub fn add(&mut self, o: &DropCounters) {
        self.nic_rx_missed += o.nic_rx_missed;
        self.nic_rx_errors += o.nic_rx_errors;
        self.ring_rx_dropped += o.ring_rx_dropped;
        self.capture_dropped += o.capture_dropped;
        self.nic_tx_errors += o.nic_tx_errors;
        self.ring_tx_invalid += o.ring_tx_invalid;
    }

    /// Adds another worker's counters of the same run: the ring and
    /// capture counters are each worker's own and add up, the NIC counters
    /// are the whole interface's, which every worker reads, so the highest
    /// reading is kept.
    pub fn merge_workers(&mut self, o: &DropCounters) {
        self.nic_rx_missed = self.nic_rx_missed.max(o.nic_rx_missed);
        self.nic_rx_errors = self.nic_rx_errors.max(o.nic_rx_errors);
        self.nic_tx_errors = self.nic_tx_errors.max(o.nic_tx_errors);
        self.ring_rx_dropped += o.ring_rx_dropped;
        self.capture_dropped += o.capture_dropped;
        self.ring_tx_invalid += o.ring_tx_invalid;
    }

    /// The counters that went up from `before` to `self` (a later reading
    /// of the same counters); a counter that went down (reset) counts from 0.
    pub fn since(&self, before: &DropCounters) -> DropCounters {
        let d = |now: u64, then: u64| now.checked_sub(then).unwrap_or(now);
        DropCounters {
            nic_rx_missed: d(self.nic_rx_missed, before.nic_rx_missed),
            nic_rx_errors: d(self.nic_rx_errors, before.nic_rx_errors),
            ring_rx_dropped: d(self.ring_rx_dropped, before.ring_rx_dropped),
            capture_dropped: d(self.capture_dropped, before.capture_dropped),
            nic_tx_errors: d(self.nic_tx_errors, before.nic_tx_errors),
            ring_tx_invalid: d(self.ring_tx_invalid, before.ring_tx_invalid),
        }
    }

    /// The receiving side only.
    pub fn rx_side(&self) -> DropCounters {
        DropCounters {
            nic_tx_errors: 0,
            ring_tx_invalid: 0,
            ..*self
        }
    }

    /// The sending side only.
    pub fn tx_side(&self) -> DropCounters {
        DropCounters {
            nic_tx_errors: self.nic_tx_errors,
            ring_tx_invalid: self.ring_tx_invalid,
            ..Default::default()
        }
    }

    /// The non-zero counters, e.g. `capture 12, nic rx missed 3`.
    pub fn describe(&self) -> String {
        let parts: Vec<String> = [
            ("nic rx missed", self.nic_rx_missed),
            ("nic rx errors", self.nic_rx_errors),
            ("af_xdp ring", self.ring_rx_dropped),
            ("capture buffer", self.capture_dropped),
            ("nic tx errors", self.nic_tx_errors),
            ("af_xdp tx invalid", self.ring_tx_invalid),
        ]
        .iter()
        .filter(|(_, n)| *n > 0)
        .map(|(name, n)| format!("{name} {n}"))
        .collect();
        if parts.is_empty() {
            "none".into()
        } else {
            parts.join(", ")
        }
    }
}

/// What a run lost, split by where: the generator (frames never sent), the
/// network (sent but never seen by the receiving port) and the receiver
/// (seen by its NIC, ring or capture buffer but dropped before FeroTRX read
/// them).
///
/// Only flows with signatures can be followed end to end, so `offered`,
/// `sent` and `received` count those. The layer counters have no idea of
/// flows and count everything on their interface: each is capped at the
/// loss still unexplained, in the order receiver, then generator's
/// sender drops, so other traffic never shows up as more loss than there is.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct LossReport {
    /// Frames the streams with signatures tried to send.
    pub offered: u64,
    /// Of those, handed to the sender.
    pub sent: u64,
    /// Received by FeroTRX (once each).
    pub received: u64,
    /// Never handed over or never left: send errors, frames skipped for
    /// being late, and what the sending NIC or ring dropped.
    pub generator: u64,
    /// Sent but not seen at the receiving port.
    pub network: u64,
    /// Seen at the receiving port, dropped before FeroTRX read them.
    pub receiver: u64,
    /// The parts of `generator`.
    pub send_errors: u64,
    pub late_skipped: u64,
    pub tx_dropped: u64,
    /// The layer counters behind `receiver` and `tx_dropped`, uncapped.
    pub drops: DropCounters,
}

impl LossReport {
    /// Splits the loss of a run. `sent` and `received` count frames with
    /// signatures; `send_errors` and `late_skipped` those the streams with
    /// signatures failed to send or skipped; `drops` both sides' counters.
    pub fn new(
        sent: u64,
        received: u64,
        send_errors: u64,
        late_skipped: u64,
        drops: DropCounters,
    ) -> LossReport {
        let lost = sent.saturating_sub(received);
        let receiver = drops.rx_total().min(lost);
        let tx_dropped = drops.tx_total().min(lost - receiver);
        LossReport {
            offered: sent + send_errors + late_skipped,
            sent,
            received,
            generator: send_errors + late_skipped + tx_dropped,
            network: lost - receiver - tx_dropped,
            receiver,
            send_errors,
            late_skipped,
            tx_dropped,
            drops,
        }
    }

    /// The loss of a run whose streams' flow ids are `flows` (in the order
    /// of `tx.streams`, see [`Job::flows`](crate::Job::flows)), from the
    /// sender's and receiver's counters. `None` when no stream has a
    /// signature.
    pub fn for_run(
        flows: &[Option<u32>],
        tx: &crate::RunStats,
        rx: &crate::RxStats,
    ) -> Option<LossReport> {
        let mut any = false;
        let (mut sent, mut received, mut errors, mut late) = (0, 0, 0, 0);
        for (flow, st) in flows.iter().zip(&tx.streams) {
            let Some(flow) = flow else { continue };
            any = true;
            sent += st.tagged;
            received += rx.flow(*flow).map_or(0, crate::FlowStats::unique);
            errors += st.send_errors;
            late += st.late_skipped;
        }
        if !any {
            return None;
        }
        let mut drops = tx.drops.tx_side();
        drops.add(&rx.drops.rx_side());
        Some(LossReport::new(sent, received, errors, late, drops))
    }

    /// Every frame offered and not received.
    pub fn lost(&self) -> u64 {
        self.generator + self.network + self.receiver
    }

    /// `part` as a percentage of the frames offered.
    pub fn pct(&self, part: u64) -> f64 {
        if self.offered == 0 {
            0.0
        } else {
            part as f64 * 100.0 / self.offered as f64
        }
    }

    /// One line, e.g. `lost 124 of 10000: generator 0, network 120, receiver 4 (capture buffer 4)`.
    pub fn line(&self) -> String {
        let mut s = format!(
            "lost {} of {}: generator {}, network {}, receiver {}",
            self.lost(),
            self.offered,
            self.generator,
            self.network,
            self.receiver
        );
        if !self.drops.is_empty() {
            s.push_str(&format!(" (dropped at: {})", self.drops.describe()));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_is_split_and_counters_are_capped() {
        // 1000 sent, 900 received: 100 lost. The receiver's capture buffer
        // dropped 30, the NIC 500 (mostly other traffic): the receiver
        // explains at most the 100 lost.
        let drops = DropCounters {
            capture_dropped: 30,
            ..Default::default()
        };
        let r = LossReport::new(1000, 900, 5, 2, drops);
        assert_eq!(
            (r.offered, r.generator, r.network, r.receiver),
            (1007, 7, 70, 30)
        );
        assert_eq!(r.lost(), 107);
        let drops = DropCounters {
            nic_rx_missed: 500,
            nic_tx_errors: 10,
            ..Default::default()
        };
        let r = LossReport::new(1000, 900, 0, 0, drops);
        assert_eq!((r.generator, r.network, r.receiver), (0, 0, 100));
        // Sender drops explain what the receiver does not.
        let drops = DropCounters {
            capture_dropped: 60,
            ring_tx_invalid: 70,
            ..Default::default()
        };
        let r = LossReport::new(1000, 900, 0, 0, drops);
        assert_eq!((r.generator, r.network, r.receiver), (40, 0, 60));
        assert!(r.line().contains("capture buffer 60"), "{}", r.line());
        // More received than sent (duplicates are not counted, but a
        // receiver that started early may see more): no loss.
        let r = LossReport::new(10, 12, 0, 0, DropCounters::default());
        assert_eq!(r.lost(), 0);
    }

    #[test]
    fn counters_add_and_subtract() {
        let a = DropCounters {
            capture_dropped: 5,
            nic_rx_missed: 7,
            ..Default::default()
        };
        let mut b = a;
        b.add(&a);
        assert_eq!(b.rx_total(), 24);
        assert_eq!(b.since(&a), a);
        let mut w = a;
        w.merge_workers(&a);
        assert_eq!((w.capture_dropped, w.nic_rx_missed), (10, 7));
        // A counter that went back to 0 (the NIC was reset) counts from there.
        let reset = DropCounters::default();
        assert_eq!(reset.since(&a), DropCounters::default());
        assert_eq!(a.tx_side(), DropCounters::default());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn counters_in_json_leave_out_zeros() {
        let a = DropCounters {
            capture_dropped: 5,
            nic_rx_missed: 7,
            ..Default::default()
        };
        let reset = DropCounters::default();
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, r#"{"nic_rx_missed":7,"capture_dropped":5}"#);
        assert_eq!(serde_json::from_str::<DropCounters>("{}").unwrap(), reset);
    }
}
