/// Error returned by a [`PacketSink`].
pub type SinkError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Anything that can transmit a packet: a network interface, a file, memory.
///
/// Implement this to plug a new output into the replay engine.
pub trait PacketSink {
    /// Sends one packet, starting at the link layer header.
    fn send(&mut self, data: &[u8]) -> Result<(), SinkError>;

    /// Flushes buffered packets. Called once when a replay ends.
    fn flush(&mut self) -> Result<(), SinkError> {
        Ok(())
    }

    /// Called when the engine is about to wait for the next packet's send time.
    ///
    /// Sinks that queue packets and hand them over in batches (AF_XDP, DPDK)
    /// hand over what they have here, so batching never holds a paced packet
    /// back. Sinks that send every packet right away ignore it.
    fn idle(&mut self) -> Result<(), SinkError> {
        Ok(())
    }

    /// Frames the layers below dropped on the way out since the sink was
    /// opened (the NIC's, an AF_XDP ring's); zero where there are no
    /// counters.
    fn drops(&mut self) -> crate::DropCounters {
        crate::DropCounters::default()
    }
}

impl<S: PacketSink + ?Sized> PacketSink for &mut S {
    fn send(&mut self, data: &[u8]) -> Result<(), SinkError> {
        (**self).send(data)
    }
    fn flush(&mut self) -> Result<(), SinkError> {
        (**self).flush()
    }
    fn idle(&mut self) -> Result<(), SinkError> {
        (**self).idle()
    }
    fn drops(&mut self) -> crate::DropCounters {
        (**self).drops()
    }
}

impl<S: PacketSink + ?Sized> PacketSink for Box<S> {
    fn send(&mut self, data: &[u8]) -> Result<(), SinkError> {
        (**self).send(data)
    }
    fn flush(&mut self) -> Result<(), SinkError> {
        (**self).flush()
    }
    fn idle(&mut self) -> Result<(), SinkError> {
        (**self).idle()
    }
    fn drops(&mut self) -> crate::DropCounters {
        (**self).drops()
    }
}

/// Discards every packet. Useful to measure the engine's own speed.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullSink;

impl PacketSink for NullSink {
    fn send(&mut self, _data: &[u8]) -> Result<(), SinkError> {
        Ok(())
    }
}

/// Keeps every packet in memory. Useful in tests and for post-processing.
#[derive(Debug, Default, Clone)]
pub struct VecSink {
    pub packets: Vec<Vec<u8>>,
}

impl PacketSink for VecSink {
    fn send(&mut self, data: &[u8]) -> Result<(), SinkError> {
        self.packets.push(data.to_vec());
        Ok(())
    }
}

/// `n` sinks that all send into `sink`, taking turns behind a lock, for
/// workers of a run on several cores whose output cannot be opened once per
/// worker (a file, a DPDK queue). Each turn sends what the worker queued
/// since its last one, at `idle` and `flush`, or when 64 packets are queued.
pub fn share_sink(sink: Box<dyn PacketSink + Send>, n: usize) -> Vec<Box<dyn PacketSink + Send>> {
    if n <= 1 {
        return vec![sink];
    }
    let shared = std::sync::Arc::new(std::sync::Mutex::new(sink));
    (0..n)
        .map(|_| {
            Box::new(SharedSink {
                sink: shared.clone(),
                queued: Vec::new(),
            }) as Box<dyn PacketSink + Send>
        })
        .collect()
}

/// One worker's turn on a shared sink; see [`share_sink`].
struct SharedSink {
    sink: std::sync::Arc<std::sync::Mutex<Box<dyn PacketSink + Send>>>,
    queued: Vec<Vec<u8>>,
}

impl SharedSink {
    fn hand_over(&mut self, flush: bool) -> Result<(), SinkError> {
        let mut sink = self.sink.lock().unwrap_or_else(|e| e.into_inner());
        for p in self.queued.drain(..) {
            sink.send(&p)?;
        }
        if flush {
            sink.flush()
        } else {
            sink.idle()
        }
    }
}

impl PacketSink for SharedSink {
    fn send(&mut self, data: &[u8]) -> Result<(), SinkError> {
        self.queued.push(data.to_vec());
        if self.queued.len() >= 64 {
            self.hand_over(false)?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), SinkError> {
        self.hand_over(true)
    }

    fn idle(&mut self) -> Result<(), SinkError> {
        if self.queued.is_empty() {
            return Ok(());
        }
        self.hand_over(false)
    }
}
