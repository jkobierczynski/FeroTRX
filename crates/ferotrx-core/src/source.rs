use std::borrow::Borrow;
use std::time::Duration;

use crate::{Capture, Packet, Result};

/// Where a [`Stream`](crate::Stream) gets its packets from.
///
/// Implement this to feed the engine from something other than a capture in
/// memory, for example a packet generator or a file read on the fly.
pub trait PacketSource: Send {
    /// Link type of the packets (1 = Ethernet).
    fn linktype(&self) -> u32;

    /// Writes the next packet into `packet`, reusing its buffer, or returns
    /// `Ok(false)` when the source has no more packets.
    ///
    /// `packet.timestamp` must be the packet's offset on the source's own timeline,
    /// counted from its first packet. [`Rate::Original`](crate::Rate::Original) uses it.
    fn next_into(&mut self, packet: &mut Packet) -> Result<bool>;

    /// Complete passes over the underlying data so far, such as loops of a capture.
    fn passes(&self) -> u64 {
        0
    }
}

impl<S: PacketSource + ?Sized> PacketSource for Box<S> {
    fn linktype(&self) -> u32 {
        (**self).linktype()
    }
    fn next_into(&mut self, packet: &mut Packet) -> Result<bool> {
        (**self).next_into(packet)
    }
    fn passes(&self) -> u64 {
        (**self).passes()
    }
}

/// Plays a [`Capture`] one or more times, on one continuous timeline.
///
/// `C` is anything that borrows a capture: `&Capture`, `Arc<Capture>` or `Capture`.
#[derive(Clone, Debug)]
pub struct CaptureSource<C> {
    capture: C,
    loops: u64,
    pos: usize,
    pass: u64,
    first_ts: Duration,
    loop_period: Duration,
}

impl<C: Borrow<Capture>> CaptureSource<C> {
    /// Plays `capture` once.
    pub fn new(capture: C) -> Self {
        let cap = capture.borrow();
        let first_ts = cap.packets.first().map_or(Duration::ZERO, |p| p.timestamp);
        let span = cap.duration();
        // One loop lasts the capture's span plus one average gap, so the first packet
        // of the next loop does not land on top of the last packet of this one.
        let gap = if cap.len() > 1 {
            span / (cap.len() as u32 - 1).max(1)
        } else {
            Duration::ZERO
        };
        Self {
            capture,
            loops: 1,
            pos: 0,
            pass: 0,
            first_ts,
            loop_period: span + gap,
        }
    }

    /// Sets how long one pass over the capture lasts on the source's timeline,
    /// so the next pass starts that long after the previous one did. By default
    /// it is the capture's span plus one average gap between packets.
    pub fn loop_period(mut self, period: Duration) -> Self {
        self.loop_period = period;
        self
    }

    /// Plays the capture `loops` times; 0 loops forever.
    pub fn loops(mut self, loops: u64) -> Self {
        self.loops = loops;
        self
    }

    pub fn capture(&self) -> &Capture {
        self.capture.borrow()
    }
}

impl<C: Borrow<Capture> + Send> PacketSource for CaptureSource<C> {
    fn linktype(&self) -> u32 {
        self.capture.borrow().linktype
    }

    fn next_into(&mut self, packet: &mut Packet) -> Result<bool> {
        let cap = self.capture.borrow();
        if cap.is_empty() || (self.loops != 0 && self.pass >= self.loops) {
            return Ok(false);
        }
        let src = &cap.packets[self.pos];
        let loop_offset = self
            .loop_period
            .saturating_mul(self.pass.min(u64::from(u32::MAX)) as u32);
        packet.timestamp = loop_offset + src.timestamp.saturating_sub(self.first_ts);
        packet.data.clear();
        packet.data.extend_from_slice(&src.data);
        self.pos += 1;
        if self.pos == cap.len() {
            self.pos = 0;
            self.pass += 1;
        }
        Ok(true)
    }

    fn passes(&self) -> u64 {
        self.pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loops_on_one_timeline() {
        let cap = Capture::new(
            1,
            vec![
                Packet::new(Duration::from_secs(10), vec![1]),
                Packet::new(Duration::from_secs(12), vec![2]),
            ],
        );
        let mut src = CaptureSource::new(&cap).loops(2);
        let mut p = Packet::new(Duration::ZERO, Vec::new());
        let mut seen = Vec::new();
        while src.next_into(&mut p).unwrap() {
            seen.push((p.timestamp.as_secs(), p.data[0], src.passes()));
        }
        // Period is span (2 s) + average gap (2 s).
        assert_eq!(seen, [(0, 1, 0), (2, 2, 1), (4, 1, 1), (6, 2, 2)]);
    }

    #[test]
    fn single_packet_with_a_loop_period() {
        let cap = Capture::new(1, vec![Packet::new(Duration::from_secs(3), vec![1])]);
        let mut src = CaptureSource::new(&cap)
            .loops(3)
            .loop_period(Duration::from_millis(250));
        let mut p = Packet::new(Duration::ZERO, Vec::new());
        let mut seen = Vec::new();
        while src.next_into(&mut p).unwrap() {
            seen.push(p.timestamp.as_millis());
        }
        assert_eq!(seen, [0, 250, 500]);
    }
}
