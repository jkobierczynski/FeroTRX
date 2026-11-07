//! Live captures the control server runs for its clients (`capture.*`).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ferotrx_core::{CaptureJob, CaptureOptions, FrameSource, JobState, SinkError};

use crate::protocol::{CaptureInfo, CaptureReadResult, CapturedFrame, RunState};

/// Opens an interface to capture on (`ferotrx_io::open_capture`, or frames
/// from memory in tests).
pub type CaptureOpener =
    dyn Fn(&str, &CaptureOptions) -> Result<Box<dyn FrameSource>, SinkError> + Send + Sync;

/// Captures that may run at once on one server.
pub const MAX_CAPTURES: usize = 16;

/// A capture that only streams to a client (no file) stops when no client
/// has read it for this long: the client is gone.
pub const ABANDONED_AFTER: Duration = Duration::from_secs(60);

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
    /// When a client last read it (or it started).
    pub last_read: Mutex<Instant>,
    /// Stopped because no client read it.
    pub abandoned: AtomicBool,
}

impl CaptureRun {
    pub fn info(&self) -> CaptureInfo {
        let c = self.job.counters();
        let (state, error) = match self.job.state() {
            JobState::Running => (RunState::Running, None),
            JobState::Finished if self.abandoned.load(Ordering::Relaxed) => (
                RunState::Stopped,
                Some("stopped: no client read it for a while".to_string()),
            ),
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

    /// Stops the capture once no client has read it for `after`; returns
    /// when it has ended either way.
    pub fn watch_readers(&self, after: Duration) {
        let tick = (after / 4).clamp(Duration::from_millis(10), Duration::from_secs(1));
        while self.job.is_running() {
            std::thread::sleep(tick);
            let idle = self
                .last_read
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .elapsed();
            if idle > after && self.job.is_running() {
                self.abandoned.store(true, Ordering::Relaxed);
                self.job.stop();
                return;
            }
        }
    }

    pub fn read(
        &self,
        after: u64,
        max: Option<usize>,
        wait: Option<Duration>,
    ) -> CaptureReadResult {
        *self.last_read.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
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
