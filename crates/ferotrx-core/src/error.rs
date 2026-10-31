use std::io;

/// Errors returned by the FeroTRX core library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("capture is not a pcap or pcapng file (magic {0:02x?})")]
    UnknownFormat([u8; 4]),
    #[error("malformed capture: {0}")]
    Malformed(String),
    #[error("capture mixes link types {0} and {1}; replay needs a single link type")]
    MixedLinkTypes(u32, u32),
    #[error("invalid rate: {0}")]
    InvalidRate(String),
    #[error("sending packet {index} failed: {source}")]
    Sink {
        index: u64,
        #[source]
        source: crate::SinkError,
    },
}

impl From<pcap_file::PcapError> for Error {
    fn from(e: pcap_file::PcapError) -> Self {
        match e {
            pcap_file::PcapError::IoError(io) => Error::Io(io),
            other => Error::Malformed(other.to_string()),
        }
    }
}

/// Result type of the FeroTRX core library.
pub type Result<T> = std::result::Result<T, Error>;
