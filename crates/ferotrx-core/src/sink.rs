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
