//! `ferotrx capture`: capture on an interface with a BPF filter, show the
//! frames decoded, or write them as pcap to a file, a ring of files or
//! standard output (for `wireshark -k -i -`).

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Args;
use ferotrx_core::live::{
    CaptureDirection, CaptureFiles, CaptureOptions, Frame, FrameSource, PcapStreamWriter, Rotate,
    SourceCounters, DEFAULT_SNAPLEN,
};
use ferotrx_core::parse_duration;

#[derive(Args, Clone, Debug)]
pub struct CaptureArgs {
    /// The interface to capture on (see `ferotrx interfaces`).
    #[arg(short, long)]
    pub interface: String,

    /// A BPF filter, as tcpdump and Wireshark's capture filters take them:
    /// 'udp port 53', 'host 10.0.0.1 and not arp'. May also be given after
    /// the options, unquoted, as tcpdump takes it.
    #[arg(short, long, value_name = "BPF")]
    pub filter: Option<String>,

    /// The filter as words after the options: `ferotrx capture -i eth0 tcp port 80`.
    #[arg(value_name = "BPF", trailing_var_arg = true, conflicts_with = "filter")]
    pub expression: Vec<String>,

    /// Write the frames as pcap to this file instead of showing them; `-`
    /// writes to standard output, flushed as frames come, for
    /// `ferotrx capture -i eth0 -w - | wireshark -k -i -`.
    #[arg(short, long, value_name = "FILE")]
    pub write: Option<PathBuf>,

    /// With -w FILE: start a new file at this size (100M, 1G) or after this
    /// long (30s, 5m); files are named NAME-00001.pcap, NAME-00002.pcap, ...
    #[arg(long, value_name = "SIZE|TIME", requires = "write")]
    pub rotate: Option<Rotate>,

    /// With --rotate: keep only the newest N files.
    #[arg(long, value_name = "N", requires = "rotate")]
    pub files: Option<usize>,

    /// Also show the frames while writing them (on standard error with -w -).
    #[arg(long)]
    pub print: bool,

    /// Stop after this many frames.
    #[arg(short = 'c', long)]
    pub count: Option<u64>,

    /// Stop after this long, e.g. 30s; otherwise run until Ctrl-C.
    #[arg(short, long, value_parser = parse_duration)]
    pub duration: Option<Duration>,

    /// Bytes kept of each frame.
    #[arg(short, long, default_value_t = DEFAULT_SNAPLEN)]
    pub snaplen: u32,

    /// Only frames for this machine (and broadcasts), not the others the
    /// interface sees.
    #[arg(long)]
    pub no_promisc: bool,

    /// Frames received (in), sent (out) or both. Npcap cannot choose.
    #[arg(long, default_value = "both")]
    pub direction: CaptureDirection,

    /// The kernel's capture buffer in MiB.
    #[arg(long, value_name = "MIB", default_value_t = 32)]
    pub buffer: u32,

    /// Show the decoded layers of every frame.
    #[arg(short, long)]
    pub verbose: bool,

    /// Add a hex dump to every frame.
    #[arg(short = 'x', long)]
    pub hex: bool,

    /// No progress or summary lines.
    #[arg(short, long)]
    pub quiet: bool,
}

impl CaptureArgs {
    pub fn options(&self) -> CaptureOptions {
        let filter = match &self.filter {
            Some(f) => Some(f.clone()),
            None if !self.expression.is_empty() => Some(self.expression.join(" ")),
            None => None,
        };
        CaptureOptions {
            filter: filter.filter(|f| !f.trim().is_empty()),
            snaplen: self.snaplen,
            promisc: !self.no_promisc,
            direction: self.direction,
            buffer: self.buffer.saturating_mul(1 << 20),
        }
    }
}

/// Where frames go.
enum Sink {
    Show,
    Stdout(PcapStreamWriter<io::BufWriter<io::Stdout>>),
    Files(CaptureFiles),
}

pub fn cmd_capture(args: CaptureArgs) -> Result<()> {
    let options = args.options();
    if let Some(dir) = args.write.as_ref().and_then(|p| p.parent()) {
        if !dir.as_os_str().is_empty()
            && !dir.is_dir()
            && args.write.as_deref() != Some(std::path::Path::new("-"))
        {
            bail!("{} is not a folder", dir.display());
        }
    }
    let source =
        ferotrx_io::open_capture(&args.interface, &options).map_err(|e| anyhow::anyhow!("{e}"))?;
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::Relaxed))
            .context("cannot catch Ctrl-C")?;
    }
    let mut source = source;
    capture(&mut *source, &args, &options, &stop)
}

/// Captures from `source` until a limit, Ctrl-C (`stop`) or a closed pipe.
pub fn capture(
    source: &mut dyn FrameSource,
    args: &CaptureArgs,
    options: &CaptureOptions,
    stop: &AtomicBool,
) -> Result<()> {
    let linktype = source.linktype();
    let snaplen = source.snaplen();
    let to_stdout = args.write.as_deref() == Some(std::path::Path::new("-"));
    let mut sink = match &args.write {
        None => Sink::Show,
        Some(_) if to_stdout => Sink::Stdout(
            PcapStreamWriter::new(io::BufWriter::new(io::stdout()), linktype, snaplen)
                .context("cannot write to standard output")?,
        ),
        Some(path) => Sink::Files(
            CaptureFiles::create(
                path,
                linktype,
                snaplen,
                args.rotate.unwrap_or_default(),
                args.files,
            )
            .with_context(|| format!("cannot write {}", path.display()))?,
        ),
    };
    let show = matches!(sink, Sink::Show) || args.print;
    let progress = !args.quiet && !show;
    if !args.quiet {
        let what = options
            .filter
            .as_deref()
            .map_or(String::new(), |f| format!(" with filter '{f}'"));
        let dest = match &args.write {
            None => String::new(),
            Some(_) if to_stdout => ", pcap to standard output".to_string(),
            Some(p) => format!(", to {}", p.display()),
        };
        eprintln!(
            "capturing on {}{what}{dest} (link type {linktype}); Ctrl-C stops",
            args.interface
        );
    }
    if show && !args.verbose && !args.hex {
        line_out(
            to_stdout,
            &format!(
                "{:>6}  {:>11}  {:<24}  {:<24}  {:<8}  {:>5}  Info",
                "No.", "Time", "Source", "Destination", "Protocol", "Len"
            ),
        );
    }

    let start = Instant::now();
    let mut first_ts: Option<Duration> = None;
    let mut frames = 0u64;
    let mut bytes = 0u64;
    let mut last_flush = Instant::now();
    let mut last_progress = Instant::now();
    let mut pipe_closed = false;
    let mut progressed = false;
    loop {
        if stop.load(Ordering::Relaxed)
            || args.count.is_some_and(|c| frames >= c)
            || args.duration.is_some_and(|d| start.elapsed() >= d)
        {
            break;
        }
        let frame = source.next_frame().map_err(|e| anyhow::anyhow!("{e}"))?;
        let Some(frame) = frame else {
            if source.finished() {
                break;
            }
            if let Err(e) = flush(&mut sink) {
                if e.kind() == io::ErrorKind::BrokenPipe {
                    pipe_closed = true;
                    break;
                }
                return Err(e).context("cannot write the capture");
            }
            last_flush = Instant::now();
            if progress && last_progress.elapsed() >= Duration::from_secs(1) {
                eprint!("\r{frames} frames, {bytes} bytes   ");
                progressed = true;
                last_progress = Instant::now();
            }
            continue;
        };
        frames += 1;
        bytes += u64::from(frame.len);
        let first = *first_ts.get_or_insert(frame.ts);
        if show {
            show_frame(linktype, frames, first, &frame, args, to_stdout);
        }
        let written = match &mut sink {
            Sink::Show => Ok(()),
            Sink::Stdout(w) => w.write(&frame),
            Sink::Files(f) => f.write(&frame),
        };
        let written = written.and_then(|()| {
            if last_flush.elapsed() >= Duration::from_millis(50) {
                last_flush = Instant::now();
                flush(&mut sink)
            } else {
                Ok(())
            }
        });
        if let Err(e) = written {
            if e.kind() == io::ErrorKind::BrokenPipe {
                pipe_closed = true;
                break;
            }
            return Err(e).context("cannot write the capture");
        }
        if progress && last_progress.elapsed() >= Duration::from_secs(1) {
            eprint!("\r{frames} frames, {bytes} bytes   ");
            progressed = true;
            last_progress = Instant::now();
        }
    }
    if !pipe_closed {
        flush(&mut sink).context("cannot write the capture")?;
    }
    let counters = source.counters();
    if progressed {
        eprintln!();
    }
    if !args.quiet {
        eprintln!("{}", summary(frames, bytes, &counters, start.elapsed()));
        if let Sink::Files(f) = &sink {
            let list = f.files();
            match list.as_slice() {
                [one] => eprintln!("written to {}", one.display()),
                many => eprintln!(
                    "written to {} files, {} to {}",
                    many.len(),
                    many.first()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                    many.last()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default()
                ),
            }
        }
        if pipe_closed {
            eprintln!("the reader closed the pipe");
        }
    }
    if frames == 0
        && args.count.is_some()
        && !stop.load(Ordering::Relaxed)
        && args.duration.is_none()
    {
        bail!("no frames captured");
    }
    Ok(())
}

fn flush(sink: &mut Sink) -> io::Result<()> {
    match sink {
        Sink::Show => io::stdout().flush(),
        Sink::Stdout(w) => w.flush(),
        Sink::Files(f) => f.flush(),
    }
}

/// A line of output: standard output, or standard error when standard
/// output carries the pcap.
fn line_out(to_stderr: bool, line: &str) {
    if to_stderr {
        eprintln!("{line}");
    } else {
        let mut out = io::stdout().lock();
        let _ = writeln!(out, "{line}");
    }
}

fn show_frame(linktype: u32, n: u64, first: Duration, f: &Frame, args: &CaptureArgs, err: bool) {
    let d = ferotrx_packet::decode(linktype, &f.data);
    let t = f.ts.saturating_sub(first).as_secs_f64();
    let mut info = d.info.clone();
    if !d.problems.is_empty() {
        info.push_str(" [!]");
    }
    if (f.len as usize) > f.data.len() {
        info.push_str(&format!(" [{} of {} bytes]", f.data.len(), f.len));
    }
    if args.verbose || args.hex {
        line_out(err, &format!("Frame {n}: {} bytes, time {t:.6} s", f.len));
    } else {
        line_out(
            err,
            &format!(
                "{n:>6}  {t:>11.6}  {:<24}  {:<24}  {:<8}  {:>5}  {info}",
                d.source, d.destination, d.protocol, f.len
            ),
        );
    }
    if args.verbose {
        for line in d.tree().lines() {
            line_out(err, &format!("    {line}"));
        }
    }
    if args.hex {
        for line in ferotrx_packet::hex_dump(&f.data).lines() {
            line_out(err, &format!("    {line}"));
        }
    }
    if args.verbose || args.hex {
        line_out(err, "");
    }
}

/// `12 frames (3456 bytes) in 2.0 s; the system counted 12, dropped 0 (kernel) and 0 (interface)`.
pub fn summary(frames: u64, bytes: u64, c: &SourceCounters, elapsed: Duration) -> String {
    format!(
        "{frames} frames ({bytes} bytes) in {:.1} s; the system counted {} received, {} dropped by the kernel, {} by the interface",
        elapsed.as_secs_f64(),
        c.received,
        c.dropped,
        c.if_dropped
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferotrx_core::live::VecFrameSource;

    fn args(extra: &[&str]) -> CaptureArgs {
        use clap::Parser;
        #[derive(Parser)]
        struct T {
            #[command(flatten)]
            a: CaptureArgs,
        }
        let mut v = vec!["t", "-i", "lo"];
        v.extend_from_slice(extra);
        T::parse_from(v).a
    }

    #[test]
    fn the_filter_may_follow_the_options() {
        let a = args(&["-c", "3", "tcp", "port", "80"]);
        assert_eq!(a.options().filter.as_deref(), Some("tcp port 80"));
        let a = args(&["-f", "udp"]);
        assert_eq!(a.options().filter.as_deref(), Some("udp"));
        assert_eq!(args(&[]).options().filter, None);
        assert!(!args(&["--no-promisc"]).options().promisc);
        assert_eq!(args(&["--buffer", "2"]).options().buffer, 2 << 20);
    }

    #[test]
    fn writes_a_ring_of_files_and_stops_at_the_count() {
        let dir = std::env::temp_dir().join(format!("ferotrx-cap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.pcap");
        let p = path.to_string_lossy().into_owned();
        let a = args(&["-w", &p, "-c", "5", "-q"]);
        let frames = (0..9u8).map(|i| Frame {
            ts: Duration::from_millis(u64::from(i)),
            len: 60,
            data: vec![i; 60],
        });
        let mut src = VecFrameSource::new(1, frames);
        capture(&mut src, &a, &a.options(), &AtomicBool::new(false)).unwrap();
        let cap = ferotrx_core::Capture::from_path(&path).unwrap();
        assert_eq!(cap.packets.len(), 5);
        assert_eq!(cap.packets[4].data, vec![4; 60]);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

/// Frames of a capture running on a control server, read with
/// `capture.read`: `ferotrx ctl capture` feeds them to the same display and
/// pcap writers as a local capture.
pub struct RemoteSource<'a> {
    client: &'a mut ferotrx_ctl::Client,
    pub id: u64,
    linktype: u32,
    snaplen: u32,
    after: u64,
    queue: std::collections::VecDeque<Frame>,
    /// Frames that left the server's buffer before they were read.
    pub missed: u64,
    done: bool,
}

impl<'a> RemoteSource<'a> {
    pub fn new(
        client: &'a mut ferotrx_ctl::Client,
        info: &ferotrx_ctl::protocol::CaptureInfo,
    ) -> Self {
        Self {
            client,
            id: info.id,
            linktype: info.linktype,
            snaplen: info.snaplen,
            after: 0,
            queue: Default::default(),
            missed: 0,
            done: false,
        }
    }

    pub fn client(&mut self) -> &mut ferotrx_ctl::Client {
        self.client
    }
}

impl FrameSource for RemoteSource<'_> {
    fn linktype(&self) -> u32 {
        self.linktype
    }

    fn snaplen(&self) -> u32 {
        self.snaplen
    }

    fn next_frame(&mut self) -> std::result::Result<Option<Frame>, ferotrx_core::SinkError> {
        if let Some(f) = self.queue.pop_front() {
            return Ok(Some(f));
        }
        if self.done {
            return Ok(None);
        }
        let r = self
            .client
            .capture_read(self.id, self.after, Some(Duration::from_millis(50)))?;
        self.after = r.next;
        self.missed += r.missed;
        if r.missed > 0 {
            eprintln!(
                "warning: {} frames left the server's buffer before they were read",
                r.missed
            );
        }
        self.done = !r.more;
        for f in r.frames {
            let frame = f
                .frame()
                .ok_or_else(|| format!("frame {} of capture.read is not base64", f.n))?;
            self.queue.push_back(frame);
        }
        Ok(self.queue.pop_front())
    }

    fn counters(&mut self) -> SourceCounters {
        match self.client.capture_get(self.id) {
            Ok(i) => SourceCounters {
                received: i.received,
                dropped: i.dropped,
                if_dropped: i.if_dropped,
            },
            Err(_) => SourceCounters::default(),
        }
    }

    fn finished(&self) -> bool {
        self.done && self.queue.is_empty()
    }
}

/// `--capture` on runs: what the run's interface carries, both ways,
/// written to a pcap while the run goes.
#[derive(Args, Clone, Debug, Default)]
pub struct RunCaptureArgs {
    /// Capture on the run's interface while it goes (both directions) into
    /// this pcap file. Frames sent through AF_XDP or DPDK skip the kernel's
    /// taps and are not in it; the frames received are.
    #[arg(long, value_name = "FILE")]
    pub capture: Option<PathBuf>,

    /// The interface for --capture, when it is not the run's.
    #[arg(long, value_name = "IFACE", requires = "capture")]
    pub capture_iface: Option<String>,

    /// A BPF filter for --capture.
    #[arg(long, value_name = "BPF", requires = "capture")]
    pub capture_filter: Option<String>,
}

/// A capture running next to a run.
pub struct RunCapture {
    job: ferotrx_core::CaptureJob,
    iface: String,
}

impl RunCaptureArgs {
    /// Starts the capture, before the run starts.
    pub fn start(&self, run_iface: Option<&str>) -> Result<Option<RunCapture>> {
        let Some(path) = &self.capture else {
            return Ok(None);
        };
        let Some(iface) = self.capture_iface.as_deref().or(run_iface) else {
            bail!("--capture: give --capture-iface, this run has no single interface");
        };
        let options = CaptureOptions {
            filter: self.capture_filter.clone(),
            ..Default::default()
        };
        let source = ferotrx_io::open_capture(iface, &options)
            .map_err(|e| anyhow::anyhow!("--capture: {e}"))?;
        let files = CaptureFiles::create(
            path,
            source.linktype(),
            source.snaplen(),
            Rotate::Never,
            None,
        )
        .with_context(|| format!("cannot write {}", path.display()))?;
        let job = ferotrx_core::CaptureJob::spawn(
            source,
            ferotrx_core::CaptureJobConfig {
                files: Some(files),
                buffer_frames: 0,
                buffer_bytes: 0,
                ..Default::default()
            },
        )?;
        Ok(Some(RunCapture {
            job,
            iface: iface.to_string(),
        }))
    }
}

impl RunCapture {
    /// Stops the capture once the run has ended, after a moment for the
    /// last frames, and says what it took.
    pub fn finish(self, quiet: bool) -> Result<()> {
        std::thread::sleep(Duration::from_millis(200));
        self.job.stop();
        self.job.wait(Some(Duration::from_secs(5)));
        if let ferotrx_core::JobState::Failed(e) = self.job.state() {
            bail!("the capture on {} failed: {e}", self.iface);
        }
        if !quiet {
            let c = self.job.counters();
            let file = self
                .job
                .files()
                .first()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            eprintln!(
                "captured {} frames on {} into {file} ({} dropped by the kernel)",
                c.frames, self.iface, c.source.dropped
            );
        }
        Ok(())
    }
}
