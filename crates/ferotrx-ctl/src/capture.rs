//! Live captures the control server runs for its clients (`capture.*`).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ferotrx_core::{CaptureJob, CaptureOptions, FrameSource, JobState, SinkError};

use crate::protocol::{CaptureInfo, CaptureReadResult, CapturedFrame, RunState};

/// Opens an interface to capture on (`ferotrx_io::open_capture`, or frames
/// from memory in tests).
pub type CaptureOpener =
    dyn Fn(&str, &CaptureOptions) -> Result<Box<dyn FrameSource>, SinkError> + Send + Sync;

/// Captures that may run at once on one server.
pub const MAX_CAPTURES: usize = 16;

/// Most frames one `capture.read` returns.
pub const READ_MAX_FRAMES: usize = 1000;
/// About the most frame bytes one `capture.read` returns.
pub const READ_MAX_BYTES: usize = 4 << 20;
/// Longest a `capture.read` waits for a frame.
pub const READ_MAX_WAIT: Duration = Duration::from_millis(2000);

pub(crate) struct CaptureRun {
    pub id: u64,
    pub iface: String,
    pub filter: Option<String>,
    pub job: CaptureJob,
    pub stopped_by_request: AtomicBool,
    /// The file as the client named it, to report the files by.
    pub file: Option<PathBuf>,
    pub started: f64,
}

impl CaptureRun {
    pub fn info(&self) -> CaptureInfo {
        let c = self.job.counters();
        let (state, error) = match self.job.state() {
            JobState::Running => (RunState::Running, None),
            JobState::Finished if self.stopped_by_request.load(Ordering::Relaxed) => {
                (RunState::Stopped, None)
            }
            JobState::Finished => (RunState::Finished, None),
            JobState::Failed(e) => (RunState::Failed, Some(e)),
        };
        CaptureInfo {
            id: self.id,
            iface: self.iface.clone(),
            filter: self.filter.clone(),
            linktype: self.job.linktype(),
            snaplen: self.job.snaplen(),
            state,
            error,
            frames: c.frames,
            bytes: c.bytes,
            received: c.source.received,
            dropped: c.source.dropped,
            if_dropped: c.source.if_dropped,
            elapsed: c.elapsed,
            files: self.client_files(),
            started: Some(self.started),
        }
    }

    /// The files written, named the way the client named the first.
    fn client_files(&self) -> Vec<PathBuf> {
        let Some(asked) = &self.file else {
            return Vec::new();
        };
        let dir = asked.parent().unwrap_or(Path::new(""));
        self.job
            .files()
            .iter()
            .filter_map(|f| f.file_name().map(|n| dir.join(n)))
            .collect()
    }

    pub fn read(
        &self,
        after: u64,
        max: Option<usize>,
        wait: Option<Duration>,
    ) -> CaptureReadResult {
        if let Some(w) = wait {
            self.job.wait_for(after, w.min(READ_MAX_WAIT));
        }
        let running = self.job.is_running();
        let max = max.unwrap_or(READ_MAX_FRAMES).clamp(1, READ_MAX_FRAMES);
        let r = self.job.read(after, max, READ_MAX_BYTES);
        let total = self.job.counters().frames;
        CaptureReadResult {
            id: self.id,
            linktype: self.job.linktype(),
            snaplen: self.job.snaplen(),
            frames: r
                .frames
                .iter()
                .map(|(n, f)| CapturedFrame::new(*n, f))
                .collect(),
            next: r.next,
            missed: r.missed,
            more: running || r.next < total,
        }
    }
}
