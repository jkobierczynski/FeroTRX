//! Live capture: frames taken from an interface as they pass, written to
//! pcap files or streams and kept in a bounded buffer for readers.
//!
//! The interface side is a [`FrameSource`]; `ferotrx-io` opens one through
//! libpcap or Npcap with a BPF filter (`ferotrx_io::open_capture`).
//! [`CaptureJob`] runs a source on a thread of its own, the way the control
//! server and fleet agents capture; `ferotrx capture` reads a source
//! directly. [`PcapStreamWriter`] writes the classic pcap format packet by
//! packet (to a file, a pipe or standard output for `wireshark -k -i -`),
//! [`PcapngWriter`] the pcapng format with several interfaces, as for
//! captures merged from several machines, and [`CaptureFiles`] a pcap file or
//! a ring of them.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{JobState, SinkError};

/// Bytes kept of each frame unless told otherwise (as tcpdump and Wireshark).
pub const DEFAULT_SNAPLEN: u32 = 262_144;

/// One captured frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// When it was taken, as time since the Unix epoch.
    pub ts: Duration,
    /// Its length on the wire; `data` may be shorter (the snap length).
    pub len: u32,
    /// Its bytes from the link layer on.
    pub data: Vec<u8>,
}

impl Frame {
    /// A whole frame taken now.
    pub fn now(data: Vec<u8>) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            ts,
            len: data.len() as u32,
            data,
        }
    }
}

/// Which frames of an interface to take.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum CaptureDirection {
    /// Received and sent.
    #[default]
    Both,
    /// Received only.
    In,
    /// Sent only.
    Out,
}

impl std::str::FromStr for CaptureDirection {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "both" | "inout" | "in-out" | "any" => Ok(Self::Both),
            "in" | "rx" => Ok(Self::In),
            "out" | "tx" => Ok(Self::Out),
            _ => Err(format!("unknown direction '{s}' (use in, out or both)")),
        }
    }
}

impl std::fmt::Display for CaptureDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Both => "both",
            Self::In => "in",
            Self::Out => "out",
        })
    }
}

/// How to open a live capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureOptions {
    /// A BPF filter, as tcpdump and Wireshark's capture filters take them
    /// (`"udp port 53"`, `"host 10.0.0.1 and not arp"`).
    pub filter: Option<String>,
    /// Bytes kept of each frame.
    pub snaplen: u32,
    /// Take frames for other machines too.
    pub promisc: bool,
    pub direction: CaptureDirection,
    /// The kernel's buffer, in bytes.
    pub buffer: u32,
}

impl Default for CaptureOptions {
    fn default() -> Self {
        Self {
            filter: None,
            snaplen: DEFAULT_SNAPLEN,
            promisc: true,
            direction: CaptureDirection::Both,
            buffer: 32 << 20,
        }
    }
}

/// What the capturing system counted (libpcap's `pcap_stats`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SourceCounters {
    /// Frames that passed the filter (on Linux; elsewhere, may count all).
    pub received: u64,
    /// Frames the kernel had no room for: the reader was too slow.
    pub dropped: u64,
    /// Frames the interface or its driver dropped.
    pub if_dropped: u64,
}

/// Frames from an interface.
pub trait FrameSource: Send {
    /// The link type of the frames (1 = Ethernet).
    fn linktype(&self) -> u32;

    /// Bytes kept of each frame.
    fn snaplen(&self) -> u32 {
        DEFAULT_SNAPLEN
    }

    /// The next frame, or `None` if none came for a little while. Must not
    /// block for more than about 50 ms, so a capture can be stopped quickly.
    fn next_frame(&mut self) -> Result<Option<Frame>, SinkError>;

    /// What the system counted so far.
    fn counters(&mut self) -> SourceCounters {
        SourceCounters::default()
    }

    /// True once no more frames will come (a capture on another machine
    /// that ended). Interfaces never finish.
    fn finished(&self) -> bool {
        false
    }
}

/// Frames from memory, for tests.
pub struct VecFrameSource {
    linktype: u32,
    frames: VecDeque<Frame>,
}

impl VecFrameSource {
    pub fn new(linktype: u32, frames: impl IntoIterator<Item = Frame>) -> Self {
        Self {
            linktype,
            frames: frames.into_iter().collect(),
        }
    }
}

impl FrameSource for VecFrameSource {
    fn linktype(&self) -> u32 {
        self.linktype
    }

    fn next_frame(&mut self) -> Result<Option<Frame>, SinkError> {
        Ok(self.frames.pop_front())
    }
}

impl<S: FrameSource + ?Sized> FrameSource for Box<S> {
    fn linktype(&self) -> u32 {
        (**self).linktype()
    }
    fn snaplen(&self) -> u32 {
        (**self).snaplen()
    }
    fn next_frame(&mut self) -> Result<Option<Frame>, SinkError> {
        (**self).next_frame()
    }
    fn counters(&mut self) -> SourceCounters {
        (**self).counters()
    }
    fn finished(&self) -> bool {
        (**self).finished()
    }
}

/// Writes the classic pcap format (nanosecond timestamps) frame by frame,
/// for files, pipes and standard output. Readers see whole frames: each is
/// written at once, and [`flush`](Self::flush) hands them on.
pub struct PcapStreamWriter<W: Write> {
    out: W,
    snaplen: u32,
    bytes: u64,
}

/// Length of the pcap file header.
pub const PCAP_HEADER_LEN: u64 = 24;
/// Length of a pcap record header.
pub const PCAP_RECORD_LEN: u64 = 16;

impl<W: Write> PcapStreamWriter<W> {
    /// Writes the file header.
    pub fn new(mut out: W, linktype: u32, snaplen: u32) -> io::Result<Self> {
        let mut h = Vec::with_capacity(24);
        h.extend_from_slice(&0xa1b2_3c4du32.to_le_bytes()); // nanoseconds
        h.extend_from_slice(&2u16.to_le_bytes());
        h.extend_from_slice(&4u16.to_le_bytes());
        h.extend_from_slice(&0i32.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        h.extend_from_slice(&snaplen.max(1).to_le_bytes());
        h.extend_from_slice(&linktype.to_le_bytes());
        out.write_all(&h)?;
        Ok(Self {
            out,
            snaplen: snaplen.max(1),
            bytes: PCAP_HEADER_LEN,
        })
    }

    pub fn write(&mut self, f: &Frame) -> io::Result<()> {
        let caplen = (f.data.len() as u32).min(self.snaplen);
        let mut rec = Vec::with_capacity(16 + caplen as usize);
        rec.extend_from_slice(&(f.ts.as_secs() as u32).to_le_bytes());
        rec.extend_from_slice(&f.ts.subsec_nanos().to_le_bytes());
        rec.extend_from_slice(&caplen.to_le_bytes());
        rec.extend_from_slice(&f.len.max(caplen).to_le_bytes());
        rec.extend_from_slice(&f.data[..caplen as usize]);
        self.out.write_all(&rec)?;
        self.bytes += rec.len() as u64;
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    /// Bytes written so far, header included.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn into_inner(self) -> W {
        self.out
    }
}

/// Writes the pcapng format: one section, any number of interfaces (each
/// with its own link type and name), nanosecond timestamps.
pub struct PcapngWriter<W: Write> {
    out: W,
    snaplens: Vec<u32>,
}

impl<W: Write> PcapngWriter<W> {
    /// Writes the section header.
    pub fn new(mut out: W, application: &str) -> io::Result<Self> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&(-1i64).to_le_bytes()); // section length unknown
        push_option(&mut body, 4, application.as_bytes()); // shb_userappl
        push_option(&mut body, 0, &[]);
        write_block(&mut out, 0x0a0d_0d0a, &body)?;
        Ok(Self {
            out,
            snaplens: Vec::new(),
        })
    }

    /// Adds an interface and returns its number.
    pub fn add_interface(&mut self, linktype: u32, snaplen: u32, name: &str) -> io::Result<u32> {
        let mut body = Vec::new();
        body.extend_from_slice(&(linktype as u16).to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&snaplen.to_le_bytes());
        if !name.is_empty() {
            push_option(&mut body, 2, name.as_bytes()); // if_name
        }
        push_option(&mut body, 9, &[9]); // if_tsresol: nanoseconds
        push_option(&mut body, 0, &[]);
        write_block(&mut self.out, 1, &body)?;
        self.snaplens.push(snaplen.max(1));
        Ok(self.snaplens.len() as u32 - 1)
    }

    /// Writes a frame on an interface from [`add_interface`](Self::add_interface).
    pub fn write(&mut self, interface: u32, f: &Frame) -> io::Result<()> {
        let snaplen = *self.snaplens.get(interface as usize).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no such pcapng interface")
        })?;
        let caplen = (f.data.len() as u32).min(snaplen);
        let ns = f.ts.as_nanos() as u64;
        let mut body = Vec::with_capacity(20 + caplen as usize + 3);
        body.extend_from_slice(&interface.to_le_bytes());
        body.extend_from_slice(&((ns >> 32) as u32).to_le_bytes());
        body.extend_from_slice(&(ns as u32).to_le_bytes());
        body.extend_from_slice(&caplen.to_le_bytes());
        body.extend_from_slice(&f.len.max(caplen).to_le_bytes());
        body.extend_from_slice(&f.data[..caplen as usize]);
        pad4(&mut body);
        write_block(&mut self.out, 6, &body)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    pub fn into_inner(self) -> W {
        self.out
    }
}

fn pad4(b: &mut Vec<u8>) {
    while b.len() % 4 != 0 {
        b.push(0);
    }
}

fn push_option(b: &mut Vec<u8>, code: u16, value: &[u8]) {
    b.extend_from_slice(&code.to_le_bytes());
    b.extend_from_slice(&(value.len() as u16).to_le_bytes());
    b.extend_from_slice(value);
    pad4(b);
}

fn write_block<W: Write>(out: &mut W, kind: u32, body: &[u8]) -> io::Result<()> {
    let total = (12 + body.len()) as u32;
    let mut block = Vec::with_capacity(total as usize);
    block.extend_from_slice(&kind.to_le_bytes());
    block.extend_from_slice(&total.to_le_bytes());
    block.extend_from_slice(body);
    block.extend_from_slice(&total.to_le_bytes());
    out.write_all(&block)
}

/// When [`CaptureFiles`] starts a new file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Rotate {
    /// One file.
    #[default]
    Never,
    /// When a file reaches this many bytes.
    Size(u64),
    /// After this long.
    Time(Duration),
}

impl std::str::FromStr for Rotate {
    type Err = String;

    /// `100M`, `1G`, `500K` or `30s`, `5m`, `1h`.
    fn from_str(s: &str) -> Result<Self, String> {
        let t = s.trim();
        let lower = t.to_ascii_lowercase();
        let (num, mult) = if let Some(n) = lower.strip_suffix(['k']) {
            (n, 1u64 << 10)
        } else if let Some(n) = lower.strip_suffix(['g']) {
            (n, 1 << 30)
        } else if let Some(n) = lower.strip_suffix("kb") {
            (n, 1 << 10)
        } else if let Some(n) = lower.strip_suffix("mb") {
            (n, 1 << 20)
        } else if let Some(n) = lower.strip_suffix("gb") {
            (n, 1 << 30)
        } else if let Some(n) = lower.strip_suffix(['b']) {
            (n, 1)
        } else if lower.ends_with('m') && !lower.ends_with("ms") && t.ends_with('M') {
            (&lower[..lower.len() - 1], 1 << 20)
        } else {
            return crate::parse_duration(t)
                .map(Rotate::Time)
                .map_err(|_| format!("'{s}': give a size (100M, 1G) or a time (30s, 5m)"));
        };
        let n: f64 = num
            .trim()
            .parse()
            .map_err(|_| format!("'{s}': give a size (100M, 1G) or a time (30s, 5m)"))?;
        if n <= 0.0 {
            return Err(format!("'{s}' must be more than zero"));
        }
        Ok(Rotate::Size((n * mult as f64) as u64))
    }
}

/// Writes a capture to a pcap file, or to a ring of files: with
/// [`Rotate::Size`] or [`Rotate::Time`] the files are named `NAME-00001.pcap`,
/// `NAME-00002.pcap`, ... and only the newest `keep` are kept, if set.
pub struct CaptureFiles {
    path: PathBuf,
    linktype: u32,
    snaplen: u32,
    rotate: Rotate,
    keep: Option<usize>,
    current: Option<PcapStreamWriter<BufWriter<File>>>,
    opened: Instant,
    index: u32,
    files: VecDeque<PathBuf>,
}

impl CaptureFiles {
    /// Opens the first file.
    pub fn create(
        path: impl AsRef<Path>,
        linktype: u32,
        snaplen: u32,
        rotate: Rotate,
        keep: Option<usize>,
    ) -> io::Result<Self> {
        let mut files = Self {
            path: path.as_ref().to_path_buf(),
            linktype,
            snaplen,
            rotate,
            keep: keep.filter(|&k| k > 0),
            current: None,
            opened: Instant::now(),
            index: 0,
            files: VecDeque::new(),
        };
        files.next_file()?;
        Ok(files)
    }

    /// The name of the `n`th file of a ring.
    pub fn ring_name(path: &Path, n: u32) -> PathBuf {
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "capture".into());
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().into_owned())
            .unwrap_or_else(|| "pcap".into());
        path.with_file_name(format!("{stem}-{n:05}.{ext}"))
    }

    fn next_file(&mut self) -> io::Result<()> {
        if let Some(mut w) = self.current.take() {
            w.flush()?;
        }
        self.index += 1;
        let name = match self.rotate {
            Rotate::Never => self.path.clone(),
            _ => Self::ring_name(&self.path, self.index),
        };
        let file = File::create(&name)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", name.display())))?;
        self.current = Some(PcapStreamWriter::new(
            BufWriter::new(file),
            self.linktype,
            self.snaplen,
        )?);
        self.opened = Instant::now();
        self.files.push_back(name);
        if let Some(keep) = self.keep {
            while self.files.len() > keep {
                if let Some(old) = self.files.pop_front() {
                    let _ = std::fs::remove_file(old);
                }
            }
        }
        Ok(())
    }

    pub fn write(&mut self, f: &Frame) -> io::Result<()> {
        let full = match (self.rotate, &self.current) {
            (Rotate::Size(max), Some(w)) => {
                w.bytes() > PCAP_HEADER_LEN
                    && w.bytes() + PCAP_RECORD_LEN + f.data.len() as u64 > max
            }
            (Rotate::Time(t), Some(_)) => self.opened.elapsed() >= t,
            _ => false,
        };
        if full {
            self.next_file()?;
        }
        match &mut self.current {
            Some(w) => w.write(f),
            None => Ok(()),
        }
    }

    pub fn flush(&mut self) -> io::Result<()> {
        match &mut self.current {
            Some(w) => w.flush(),
            None => Ok(()),
        }
    }

    /// The files written and still there, oldest first.
    pub fn files(&self) -> Vec<PathBuf> {
        self.files.iter().cloned().collect()
    }
}

impl Drop for CaptureFiles {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// How a [`CaptureJob`] runs.
pub struct CaptureJobConfig {
    /// Stop after this many frames.
    pub count: Option<u64>,
    /// Stop after this long.
    pub duration: Option<Duration>,
    /// Where to write the frames, if anywhere.
    pub files: Option<CaptureFiles>,
    /// Frames kept for [`CaptureJob::read`]: at most this many...
    pub buffer_frames: usize,
    /// ... and at most this many bytes. 0 keeps none.
    pub buffer_bytes: usize,
    /// Set from outside to stop the job.
    pub stop: Option<Arc<AtomicBool>>,
}

impl Default for CaptureJobConfig {
    fn default() -> Self {
        Self {
            count: None,
            duration: None,
            files: None,
            buffer_frames: 10_000,
            buffer_bytes: 16 << 20,
            stop: None,
        }
    }
}

/// What a capture has done so far.
#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CaptureCounters {
    /// Frames taken.
    pub frames: u64,
    /// Their bytes on the wire.
    pub bytes: u64,
    /// What the system counted.
    pub source: SourceCounters,
    /// Frames that left the read buffer before anyone read them.
    pub unread_dropped: u64,
    /// Seconds since the capture started (until it ended).
    pub elapsed: f64,
}

/// Frames read from a [`CaptureJob`].
#[derive(Clone, Debug, Default)]
pub struct CaptureRead {
    /// Frames numbered from 1, in order.
    pub frames: Vec<(u64, Frame)>,
    /// The number to read after next time.
    pub next: u64,
    /// Frames after the given number that had left the buffer already.
    pub missed: u64,
}

struct CaptureLive {
    state: JobState,
    counters: CaptureCounters,
    /// Frames kept for readers, with their numbers.
    buffer: VecDeque<(u64, Frame)>,
    buffer_bytes: usize,
    files: Vec<PathBuf>,
    start: Instant,
    end: Option<Instant>,
}

struct CaptureShared {
    live: Mutex<CaptureLive>,
    changed: Condvar,
}

impl CaptureShared {
    fn lock(&self) -> MutexGuard<'_, CaptureLive> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A capture running on a thread of its own: frames counted, written to
/// files and kept in a bounded buffer that readers take from by number.
pub struct CaptureJob {
    shared: Arc<CaptureShared>,
    stop: Arc<AtomicBool>,
    linktype: u32,
    snaplen: u32,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl CaptureJob {
    pub fn spawn(
        mut source: Box<dyn FrameSource>,
        mut config: CaptureJobConfig,
    ) -> io::Result<CaptureJob> {
        let stop = config
            .stop
            .get_or_insert_with(|| Arc::new(AtomicBool::new(false)))
            .clone();
        let linktype = source.linktype();
        let snaplen = source.snaplen();
        let shared = Arc::new(CaptureShared {
            live: Mutex::new(CaptureLive {
                state: JobState::Running,
                counters: CaptureCounters::default(),
                buffer: VecDeque::new(),
                buffer_bytes: 0,
                files: config
                    .files
                    .as_ref()
                    .map(CaptureFiles::files)
                    .unwrap_or_default(),
                start: Instant::now(),
                end: None,
            }),
            changed: Condvar::new(),
        });
        let thread = {
            let shared = shared.clone();
            let stop = stop.clone();
            std::thread::Builder::new()
                .name("ferotrx-capture".into())
                .spawn(move || {
                    let result = capture_loop(&mut *source, &mut config, &stop, &shared);
                    let counters = source.counters();
                    let mut live = shared.lock();
                    live.counters.source = counters;
                    if let Some(f) = &config.files {
                        live.files = f.files();
                    }
                    live.end = Some(Instant::now());
                    live.counters.elapsed = live.start.elapsed().as_secs_f64();
                    live.state = match result {
                        Ok(()) => JobState::Finished,
                        Err(e) => JobState::Failed(e.to_string()),
                    };
                    drop(live);
                    shared.changed.notify_all();
                })?
        };
        Ok(CaptureJob {
            shared,
            stop,
            linktype,
            snaplen,
            thread: Mutex::new(Some(thread)),
        })
    }

    pub fn linktype(&self) -> u32 {
        self.linktype
    }

    pub fn snaplen(&self) -> u32 {
        self.snaplen
    }

    pub fn state(&self) -> JobState {
        self.shared.lock().state.clone()
    }

    pub fn is_running(&self) -> bool {
        self.state() == JobState::Running
    }

    /// Asks the capture to stop; it does within about 50 ms.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Waits until the capture ends or `timeout` passes (`None` waits for
    /// ever). Returns true if it has ended.
    pub fn wait(&self, timeout: Option<Duration>) -> bool {
        let deadline = timeout.and_then(|t| Instant::now().checked_add(t));
        let mut live = self.shared.lock();
        while live.state == JobState::Running {
            match deadline {
                None => {
                    live = self
                        .shared
                        .changed
                        .wait(live)
                        .unwrap_or_else(|e| e.into_inner())
                }
                Some(d) => {
                    let now = Instant::now();
                    if now >= d {
                        return false;
                    }
                    live = self
                        .shared
                        .changed
                        .wait_timeout(live, d - now)
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
            }
        }
        drop(live);
        if let Some(t) = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = t.join();
        }
        true
    }

    pub fn counters(&self) -> CaptureCounters {
        let live = self.shared.lock();
        let mut c = live.counters.clone();
        c.elapsed = live
            .end
            .unwrap_or_else(Instant::now)
            .duration_since(live.start)
            .as_secs_f64();
        c
    }

    /// The files written (with a ring, those still there), once known; the
    /// first one from the start.
    pub fn files(&self) -> Vec<PathBuf> {
        self.shared.lock().files.clone()
    }

    /// Frames numbered after `after`, at most `max` of them and about
    /// `max_bytes` (always at least one if there is one).
    pub fn read(&self, after: u64, max: usize, max_bytes: usize) -> CaptureRead {
        let live = self.shared.lock();
        let first = live.buffer.front().map(|(n, _)| *n);
        let missed = match first {
            Some(first) if first > after + 1 => first - after - 1,
            None if live.counters.frames > after => live.counters.frames - after,
            _ => 0,
        };
        let mut out = CaptureRead {
            frames: Vec::new(),
            next: after.max(live.counters.frames.min(after + missed)),
            missed,
        };
        let mut bytes = 0;
        for (n, f) in live.buffer.iter() {
            if *n <= after {
                continue;
            }
            if out.frames.len() >= max
                || (!out.frames.is_empty() && bytes + f.data.len() > max_bytes)
            {
                break;
            }
            bytes += f.data.len();
            out.next = *n;
            out.frames.push((*n, f.clone()));
        }
        out
    }

    /// Waits up to `timeout` for a frame numbered after `after`, or the end.
    pub fn wait_for(&self, after: u64, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let mut live = self.shared.lock();
        while live.counters.frames <= after && live.state == JobState::Running {
            let now = Instant::now();
            if now >= deadline {
                return;
            }
            live = self
                .shared
                .changed
                .wait_timeout(live, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

impl Drop for CaptureJob {
    fn drop(&mut self) {
        self.stop();
    }
}

fn capture_loop(
    source: &mut dyn FrameSource,
    config: &mut CaptureJobConfig,
    stop: &AtomicBool,
    shared: &CaptureShared,
) -> Result<(), SinkError> {
    let start = Instant::now();
    let mut frames = 0u64;
    let mut last_flush = Instant::now();
    let mut last_counters = Instant::now();
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if config.count.is_some_and(|c| frames >= c) {
            break;
        }
        if config.duration.is_some_and(|d| start.elapsed() >= d) {
            break;
        }
        let next = source.next_frame()?;
        if next.is_none() && source.finished() {
            break;
        }
        if let Some(f) = next {
            frames += 1;
            if let Some(files) = &mut config.files {
                files.write(&f)?;
            }
            let mut live = shared.lock();
            live.counters.frames = frames;
            live.counters.bytes += u64::from(f.len.max(f.data.len() as u32));
            if config.buffer_bytes > 0 && config.buffer_frames > 0 {
                live.buffer_bytes += f.data.len();
                live.buffer.push_back((frames, f));
                while live.buffer.len() > config.buffer_frames
                    || (live.buffer_bytes > config.buffer_bytes && live.buffer.len() > 1)
                {
                    if let Some((_, old)) = live.buffer.pop_front() {
                        live.buffer_bytes -= old.data.len();
                    }
                }
            }
            drop(live);
            shared.changed.notify_all();
        } else if let Some(files) = &mut config.files {
            // Nothing waiting: let readers of the file see what there is.
            if last_flush.elapsed() >= Duration::from_millis(100) {
                files.flush()?;
                last_flush = Instant::now();
            }
        }
        if last_counters.elapsed() >= Duration::from_millis(250) {
            let c = source.counters();
            let mut live = shared.lock();
            live.counters.source = c;
            if let Some(f) = &config.files {
                live.files = f.files();
            }
            last_counters = Instant::now();
        }
    }
    if let Some(files) = &mut config.files {
        files.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Capture;

    fn frame(i: u8) -> Frame {
        Frame {
            ts: Duration::new(1_700_000_000, u32::from(i) * 1000),
            len: 60,
            data: vec![i; 60],
        }
    }

    #[test]
    fn pcap_stream_reads_back() {
        let mut w = PcapStreamWriter::new(Vec::new(), 1, 65535).unwrap();
        for i in 0..3 {
            w.write(&frame(i)).unwrap();
        }
        let bytes = w.into_inner();
        let cap = Capture::from_reader(&bytes[..]).unwrap();
        assert_eq!(cap.linktype, 1);
        assert_eq!(cap.packets.len(), 3);
        assert_eq!(cap.packets[2].data, vec![2; 60]);
        assert_eq!(cap.packets[1].timestamp, Duration::new(1_700_000_000, 1000));
    }

    #[test]
    fn snaplen_cuts_frames_but_keeps_the_wire_length() {
        let mut w = PcapStreamWriter::new(Vec::new(), 1, 20).unwrap();
        w.write(&frame(7)).unwrap();
        let bytes = w.into_inner();
        assert_eq!(bytes.len(), 24 + 16 + 20);
        assert_eq!(u32::from_le_bytes(bytes[32..36].try_into().unwrap()), 20);
        assert_eq!(u32::from_le_bytes(bytes[36..40].try_into().unwrap()), 60);
    }

    #[test]
    fn pcapng_with_two_interfaces_reads_back() {
        let mut w = PcapngWriter::new(Vec::new(), "ferotrx test").unwrap();
        let a = w.add_interface(1, 65535, "agent-a").unwrap();
        let b = w.add_interface(1, 65535, "agent-b").unwrap();
        w.write(a, &frame(1)).unwrap();
        w.write(b, &frame(2)).unwrap();
        let mut odd = frame(3);
        odd.data.truncate(3);
        odd.len = 3;
        w.write(a, &odd).unwrap();
        let bytes = w.into_inner();
        let cap = Capture::from_reader(&bytes[..]).unwrap();
        assert_eq!(cap.packets.len(), 3);
        assert_eq!(cap.packets[1].data, vec![2; 60]);
        assert_eq!(cap.packets[1].timestamp, Duration::new(1_700_000_000, 2000));
        assert_eq!(cap.packets[2].data, vec![3; 3]);
    }

    #[test]
    fn rotate_parses_sizes_and_times() {
        assert_eq!("100M".parse::<Rotate>(), Ok(Rotate::Size(100 << 20)));
        assert_eq!("1G".parse::<Rotate>(), Ok(Rotate::Size(1 << 30)));
        assert_eq!("512k".parse::<Rotate>(), Ok(Rotate::Size(512 << 10)));
        assert_eq!("10MB".parse::<Rotate>(), Ok(Rotate::Size(10 << 20)));
        assert_eq!(
            "30s".parse::<Rotate>(),
            Ok(Rotate::Time(Duration::from_secs(30)))
        );
        assert_eq!(
            "5m".parse::<Rotate>(),
            Ok(Rotate::Time(Duration::from_secs(300)))
        );
        assert!("x".parse::<Rotate>().is_err());
    }

    #[test]
    fn a_ring_keeps_the_newest_files() {
        let dir = std::env::temp_dir().join(format!("ferotrx-ring-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cap.pcap");
        // Header 24 + 2 records of 76: three records do not fit.
        let mut files = CaptureFiles::create(&path, 1, 65535, Rotate::Size(200), Some(2)).unwrap();
        for i in 0..7 {
            files.write(&frame(i)).unwrap();
        }
        let list = files.files();
        drop(files);
        assert_eq!(
            list,
            vec![
                CaptureFiles::ring_name(&path, 3),
                CaptureFiles::ring_name(&path, 4)
            ]
        );
        assert!(!CaptureFiles::ring_name(&path, 1).exists());
        let last = Capture::from_path(&list[1]).unwrap();
        assert_eq!(last.packets.len(), 1);
        let before = Capture::from_path(&list[0]).unwrap();
        assert_eq!(before.packets.len(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_job_counts_buffers_and_stops_at_its_count() {
        let src = VecFrameSource::new(1, (0..10).map(frame));
        let job = CaptureJob::spawn(
            Box::new(src),
            CaptureJobConfig {
                count: Some(8),
                buffer_frames: 5,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(job.wait(Some(Duration::from_secs(5))));
        assert_eq!(job.state(), JobState::Finished);
        assert_eq!(job.counters().frames, 8);
        let r = job.read(0, 100, 1 << 20);
        assert_eq!(r.missed, 3);
        assert_eq!(r.frames.len(), 5);
        assert_eq!(r.frames[0].0, 4);
        assert_eq!(r.next, 8);
        let r = job.read(6, 1, 1 << 20);
        assert_eq!(r.missed, 0);
        assert_eq!(r.frames.len(), 1);
        assert_eq!(r.frames[0].0, 7);
        assert_eq!(r.next, 7);
        let r = job.read(8, 10, 1 << 20);
        assert!(r.frames.is_empty());
        assert_eq!(r.next, 8);
    }
}
