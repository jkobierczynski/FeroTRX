//! Benchmarks in the manner of RFC 2544: throughput, latency, frame loss and
//! back-to-back frames, for a list of frame sizes or size mixes (IMIX).
//!
//! A benchmark is a series of *trials*. Each trial sends one frame size at
//! one rate for a set time (or a set number of frames), with a latency
//! [`Signature`](crate::Signature) in every frame, and counts what came back
//! on the receive side. [`run_benchmark`] decides which trials to run, the
//! way RFC 2544 describes, and puts the results in a [`BenchReport`]:
//!
//! * **Throughput**: the highest rate at which no more than
//!   `loss_threshold` percent of the frames are lost, found by a binary
//!   search between `min_load` and `max_load` (percent of the line rate)
//!   until the step is below `resolution`.
//! * **Latency**: latency statistics at the throughput rate (or a set load).
//! * **Frame loss**: loss at `max_load`, then in steps of `frame_loss_step`
//!   down, until `frame_loss_clean` steps in a row lose nothing.
//! * **Back-to-back**: the longest burst at `max_load` that passes without
//!   loss, by a binary search on its length up to `burst_max` frames.
//!
//! The trials themselves are run by a [`TrialRunner`]: [`JobTrialRunner`]
//! sends with a [`Job`](crate::Job) on any [`PacketSink`](crate::PacketSink)
//! and receives with any [`PacketReceiver`](crate::PacketReceiver); tests use
//! simulated devices.
//!
//! Rates are given as a load: percent of `line_rate_mbps`, the speed of the
//! link, where every frame also takes its FCS, preamble and inter-frame gap
//! (24 bytes) on the wire, as RFC 2544 counts. Frame sizes are without the FCS,
//! as FeroTRX sends them.

mod info;
#[cfg(feature = "profile")]
mod profile;
mod report;
mod runner;

use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use info::{utc_timestamp, InterfaceDetails, RunInfo};
#[cfg(feature = "profile")]
pub use profile::BenchProfile;
pub use runner::JobTrialRunner;

use crate::{Error, LatencyStats, Result, SizeMix, FCS_LEN, L1_OVERHEAD};

/// One of the RFC 2544 tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum BenchTest {
    Throughput,
    Latency,
    FrameLoss,
    BackToBack,
}

impl BenchTest {
    pub const ALL: [BenchTest; 4] = [
        BenchTest::Throughput,
        BenchTest::Latency,
        BenchTest::FrameLoss,
        BenchTest::BackToBack,
    ];

    pub fn name(self) -> &'static str {
        match self {
            BenchTest::Throughput => "throughput",
            BenchTest::Latency => "latency",
            BenchTest::FrameLoss => "frame_loss",
            BenchTest::BackToBack => "back_to_back",
        }
    }
}

impl FromStr for BenchTest {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "throughput" => Ok(BenchTest::Throughput),
            "latency" => Ok(BenchTest::Latency),
            "frame_loss" | "loss" => Ok(BenchTest::FrameLoss),
            "back_to_back" | "b2b" | "burst" => Ok(BenchTest::BackToBack),
            _ => Err(Error::InvalidSpec(format!(
                "unknown test '{s}' (throughput, latency, frame_loss, back_to_back)"
            ))),
        }
    }
}

impl std::fmt::Display for BenchTest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// What to measure and how; see the [module documentation](self).
#[derive(Clone, Debug)]
pub struct BenchConfig {
    /// The tests, run in this order for every size.
    pub tests: Vec<BenchTest>,
    /// Frame sizes (without FCS) or mixes such as IMIX; one set of tests each.
    pub sizes: Vec<SizeMix>,
    /// Speed of the link in Mbit/s (10^6), counting 24 bytes of FCS,
    /// preamble and gap per frame.
    pub line_rate_mbps: f64,
    /// How long each trial sends.
    pub trial_duration: Duration,
    /// End trials after this many frames too, whichever comes first.
    pub trial_packets: Option<u64>,
    /// Frames sent before the tests of each size, not counted: RFC 2544's
    /// learning frames, so switches and routers know the addresses.
    pub warmup: Duration,
    /// Load of the warm-up, in percent of the line rate.
    pub warmup_load: f64,
    /// Times each search or measurement is repeated; results are averaged.
    pub repetitions: u32,
    /// Throughput: highest loss, in percent, that still passes.
    pub loss_threshold: f64,
    /// Lowest and highest load tried, in percent of the line rate.
    pub min_load: f64,
    pub max_load: f64,
    /// Throughput search: stop when the step is below this, in percent of
    /// the line rate. Back-to-back: in percent of `burst_max`.
    pub resolution: f64,
    /// Most trials in one search.
    pub max_trials: u32,
    /// Latency test load in percent; default: the throughput found (or
    /// `max_load` when throughput is not measured).
    pub latency_load: Option<f64>,
    /// Frame loss test: step between loads, in percent of the line rate.
    pub frame_loss_step: f64,
    /// Frame loss test: stop after this many loads in a row without loss.
    pub frame_loss_clean: u32,
    /// Back-to-back: the longest burst tried, in frames.
    pub burst_max: u64,
    /// Stop the whole benchmark after this long; the report is partial.
    pub max_time: Option<Duration>,
    /// Set to true from another thread to stop between trials.
    pub stop: Option<Arc<AtomicBool>>,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            tests: vec![BenchTest::Throughput, BenchTest::Latency],
            sizes: crate::RFC2544_SIZES
                .iter()
                .map(|&s| SizeMix::fixed(s).expect("valid size"))
                .collect(),
            line_rate_mbps: 1000.0,
            trial_duration: Duration::from_secs(10),
            trial_packets: None,
            warmup: Duration::ZERO,
            warmup_load: 10.0,
            repetitions: 1,
            loss_threshold: 0.0,
            min_load: 0.1,
            max_load: 100.0,
            resolution: 0.5,
            max_trials: 20,
            latency_load: None,
            frame_loss_step: 10.0,
            frame_loss_clean: 2,
            burst_max: 100_000,
            max_time: None,
            stop: None,
        }
    }
}

impl BenchConfig {
    /// Checks that the numbers make sense together.
    pub fn validate(&self) -> Result<()> {
        let bad = |m: &str| Err(Error::Bench(m.to_string()));
        let load = |v: f64| v.is_finite() && v > 0.0 && v <= 100.0;
        if self.tests.is_empty() {
            return bad("no tests to run");
        }
        if self.sizes.is_empty() {
            return bad("no frame sizes");
        }
        if !(self.line_rate_mbps.is_finite() && self.line_rate_mbps > 0.0) {
            return bad("line rate must be a positive number");
        }
        if !load(self.min_load) || !load(self.max_load) || self.min_load > self.max_load {
            return bad("loads must be above 0 and at most 100, min_load <= max_load");
        }
        if !load(self.warmup_load) {
            return bad("warmup_load must be above 0 and at most 100");
        }
        if let Some(l) = self.latency_load {
            if !load(l) {
                return bad("latency_load must be above 0 and at most 100");
            }
        }
        if !(self.resolution.is_finite() && self.resolution > 0.0) {
            return bad("resolution must be above 0");
        }
        if !(self.frame_loss_step.is_finite() && self.frame_loss_step > 0.0) {
            return bad("frame_loss_step must be above 0");
        }
        if !(self.loss_threshold.is_finite() && (0.0..100.0).contains(&self.loss_threshold)) {
            return bad("loss_threshold is a percentage from 0 up to 100");
        }
        if self.trial_duration.is_zero() {
            return bad("trial duration must be above 0");
        }
        if self.trial_packets == Some(0) || self.burst_max == 0 {
            return bad("trial_packets and burst_max must be at least 1");
        }
        if self.repetitions == 0 || self.max_trials == 0 || self.frame_loss_clean == 0 {
            return bad("repetitions, max_trials and frame_loss_clean must be at least 1");
        }
        Ok(())
    }

    /// Frames per second at `load` percent of the line rate, for frames of
    /// `frame_len` bytes (without FCS) on average.
    pub fn pps(&self, load: f64, frame_len: f64) -> f64 {
        load / 100.0 * self.line_rate_mbps * 1e6
            / ((frame_len + (FCS_LEN + L1_OVERHEAD) as f64) * 8.0)
    }

    fn summary(&self) -> ConfigSummary {
        ConfigSummary {
            tests: self.tests.clone(),
            sizes: self.sizes.iter().map(ToString::to_string).collect(),
            line_rate_mbps: self.line_rate_mbps,
            trial_duration_s: self.trial_duration.as_secs_f64(),
            trial_packets: self.trial_packets,
            warmup_s: self.warmup.as_secs_f64(),
            warmup_load: self.warmup_load,
            repetitions: self.repetitions,
            loss_threshold: self.loss_threshold,
            min_load: self.min_load,
            max_load: self.max_load,
            resolution: self.resolution,
            max_trials: self.max_trials,
            latency_load: self.latency_load,
            frame_loss_step: self.frame_loss_step,
            frame_loss_clean: self.frame_loss_clean,
            burst_max: self.burst_max,
            max_time_s: self.max_time.map(|d| d.as_secs_f64()),
        }
    }
}

/// One trial for a [`TrialRunner`] to run.
#[derive(Clone, Debug)]
pub struct Trial {
    pub test: BenchTest,
    /// The size or mix to send; [`SizeMix::reset`] before use.
    pub size: SizeMix,
    /// Average frame length as sent, without FCS.
    pub frame_len: f64,
    /// Percent of the line rate.
    pub load: f64,
    /// Frames per second for that load.
    pub pps: f64,
    /// Send for this long, or until `packets` are sent, whichever is first.
    pub duration: Option<Duration>,
    pub packets: Option<u64>,
    /// A warm-up: nothing is measured, and no receiver is needed.
    pub warmup: bool,
}

/// What a trial measured.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TrialResult {
    /// Frames and bytes sent.
    pub tx: u64,
    pub tx_bytes: u64,
    /// Frames received once (duplicates not counted), and bytes received.
    pub rx: u64,
    pub rx_bytes: u64,
    pub duplicates: u64,
    pub out_of_order: u64,
    /// From the first to the last frame sent.
    pub elapsed: Duration,
    pub latency: LatencyStats,
}

impl TrialResult {
    pub fn lost(&self) -> u64 {
        self.tx.saturating_sub(self.rx)
    }

    /// Lost frames in percent of those sent.
    pub fn loss_pct(&self) -> f64 {
        if self.tx == 0 {
            0.0
        } else {
            self.lost() as f64 * 100.0 / self.tx as f64
        }
    }
}

/// Runs the trials of a benchmark.
pub trait TrialRunner {
    fn run(&mut self, trial: &Trial) -> Result<TrialResult>;

    /// The length a frame asked to be `size` bytes really gets: more when its
    /// headers and the 28-byte signature do not fit.
    fn sent_len(&self, size: usize) -> usize {
        size
    }
}

/// Latency figures in microseconds.
#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct LatencySummary {
    pub count: u64,
    pub min_us: Option<f64>,
    pub avg_us: Option<f64>,
    pub p50_us: Option<f64>,
    pub p99_us: Option<f64>,
    pub p999_us: Option<f64>,
    pub max_us: Option<f64>,
    /// RFC 3550 jitter.
    pub jitter_us: Option<f64>,
    /// Frames that seemed to arrive before they were sent (clocks disagree).
    pub negative: u64,
}

impl From<&LatencyStats> for LatencySummary {
    fn from(l: &LatencyStats) -> Self {
        let us = |d: Option<Duration>| d.map(|d| d.as_nanos() as f64 / 1000.0);
        Self {
            count: l.count(),
            min_us: us(l.min()),
            avg_us: us(l.mean()),
            p50_us: us(l.percentile(0.5)),
            p99_us: us(l.percentile(0.99)),
            p999_us: us(l.percentile(0.999)),
            max_us: us(l.max()),
            jitter_us: us(l.jitter()),
            negative: l.negative,
        }
    }
}

/// One trial in the report: what was offered and what was achieved.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TrialRecord {
    pub test: BenchTest,
    /// Repetition, from 1.
    pub repetition: u32,
    /// Offered load, percent of the line rate.
    pub load_pct: f64,
    /// Back-to-back: the burst length in frames.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub burst: Option<u64>,
    /// Offered rate: frames per second, and Mbit/s of frames (without FCS).
    pub offered_pps: f64,
    pub offered_mbps: f64,
    /// Achieved send rate, measured: frames per second, Mbit/s of frames, and
    /// Mbit/s on the wire (with FCS, preamble and gap).
    pub achieved_pps: f64,
    pub achieved_mbps: f64,
    pub achieved_l1_mbps: f64,
    /// Frames and Mbit/s of frames received, per second of sending.
    pub rx_pps: f64,
    pub rx_mbps: f64,
    pub tx: u64,
    pub rx: u64,
    pub lost: u64,
    pub loss_pct: f64,
    pub duplicates: u64,
    pub out_of_order: u64,
    pub duration_s: f64,
    /// Whether the trial passed the test's loss criterion, where it has one.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub passed: Option<bool>,
    pub latency: LatencySummary,
}

impl TrialRecord {
    fn new(trial: &Trial, r: &TrialResult, repetition: u32, passed: Option<bool>) -> Self {
        let secs = r.elapsed.as_secs_f64();
        let per_s = |v: f64| if secs > 0.0 { v / secs } else { 0.0 };
        let wire = (FCS_LEN + L1_OVERHEAD) as f64;
        Self {
            test: trial.test,
            repetition,
            load_pct: trial.load,
            burst: trial
                .packets
                .filter(|_| trial.test == BenchTest::BackToBack),
            offered_pps: trial.pps,
            offered_mbps: trial.pps * trial.frame_len * 8.0 / 1e6,
            achieved_pps: per_s(r.tx as f64),
            achieved_mbps: per_s(r.tx_bytes as f64 * 8.0 / 1e6),
            achieved_l1_mbps: per_s((r.tx_bytes as f64 + r.tx as f64 * wire) * 8.0 / 1e6),
            rx_pps: per_s(r.rx as f64),
            rx_mbps: per_s(r.rx_bytes as f64 * 8.0 / 1e6),
            tx: r.tx,
            rx: r.rx,
            lost: r.lost(),
            loss_pct: r.loss_pct(),
            duplicates: r.duplicates,
            out_of_order: r.out_of_order,
            duration_s: secs,
            passed,
            latency: (&r.latency).into(),
        }
    }

    /// True when the sender reached less than 97% of the offered rate: the
    /// trial measured the sender, not the device under test.
    pub fn sender_limited(&self) -> bool {
        self.burst.is_none() && self.achieved_pps < self.offered_pps * 0.97
    }
}

/// Throughput of one size: the highest load that passed, per repetition and
/// on average.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ThroughputResult {
    /// Average over the repetitions; 0 when no load passed.
    pub load_pct: f64,
    /// Achieved rate of the passing trials, averaged.
    pub pps: f64,
    pub mbps: f64,
    pub l1_mbps: f64,
    /// The load found by each repetition (0 when none passed).
    pub repetitions: Vec<f64>,
    /// The sender did not reach the offered rate in a passing trial: the
    /// result may be the sender's limit rather than the device's.
    pub sender_limited: bool,
}

/// Latency of one size at one load, over all its trials.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct LatencyResult {
    pub load_pct: f64,
    pub trials: u32,
    pub loss_pct: f64,
    pub latency: LatencySummary,
}

/// Frame loss at one load, over its repetitions.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct LossPoint {
    pub load_pct: f64,
    pub offered_pps: f64,
    pub tx: u64,
    pub rx: u64,
    pub loss_pct: f64,
}

/// Back-to-back: the longest burst without loss.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BurstResult {
    pub load_pct: f64,
    /// Average over the repetitions.
    pub frames: f64,
    /// That many frames at the burst's rate, in microseconds.
    pub duration_us: f64,
    pub repetitions: Vec<u64>,
    /// A repetition passed with `burst_max` frames: the device may take longer bursts.
    pub at_limit: bool,
}

/// Everything measured for one frame size or mix.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SizeReport {
    /// The size or mix as configured, e.g. `508` or `imix`.
    pub size: String,
    /// Average frame length sent, without FCS.
    pub frame_len: f64,
    /// Frames were sent longer than asked: their payload had no room for the
    /// 28-byte signature.
    pub grown: bool,
    /// Frames per second at 100% of the line rate.
    pub line_pps: f64,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub throughput: Option<ThroughputResult>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub latency: Option<LatencyResult>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub frame_loss: Vec<LossPoint>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub back_to_back: Option<BurstResult>,
    /// Every trial, in the order run.
    pub trials: Vec<TrialRecord>,
}

/// The settings a benchmark ran with, for the report.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ConfigSummary {
    pub tests: Vec<BenchTest>,
    pub sizes: Vec<String>,
    pub line_rate_mbps: f64,
    pub trial_duration_s: f64,
    pub trial_packets: Option<u64>,
    pub warmup_s: f64,
    pub warmup_load: f64,
    pub repetitions: u32,
    pub loss_threshold: f64,
    pub min_load: f64,
    pub max_load: f64,
    pub resolution: f64,
    pub max_trials: u32,
    pub latency_load: Option<f64>,
    pub frame_loss_step: f64,
    pub frame_loss_clean: u32,
    pub burst_max: u64,
    pub max_time_s: Option<f64>,
}

/// The results of [`run_benchmark`].
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BenchReport {
    pub config: ConfigSummary,
    /// The benchmark was stopped (or ran out of time) before the end.
    pub stopped: bool,
    pub elapsed_s: f64,
    pub sizes: Vec<SizeReport>,
}

struct Bench<'a> {
    config: &'a BenchConfig,
    runner: &'a mut dyn TrialRunner,
    progress: &'a mut dyn FnMut(&SizeReport, &TrialRecord),
    start: Instant,
}

/// Stops the benchmark between trials.
struct Stopped;

type Step<T> = std::result::Result<T, StepError>;

enum StepError {
    Stopped,
    Failed(Error),
}

impl From<Error> for StepError {
    fn from(e: Error) -> Self {
        StepError::Failed(e)
    }
}

impl From<Stopped> for StepError {
    fn from(_: Stopped) -> Self {
        StepError::Stopped
    }
}

/// Runs the tests of `config` for every size, one trial at a time, and calls
/// `progress` after each trial. A stop request or `max_time` ends it between
/// trials, with what was measured so far.
///
/// ```
/// use ferotrx_core::*;
/// use std::time::Duration;
///
/// // A device that forwards up to 50,000 frames per second.
/// struct Device;
/// impl TrialRunner for Device {
///     fn run(&mut self, t: &Trial) -> Result<TrialResult> {
///         let secs = t.duration.unwrap().as_secs_f64();
///         let tx = (t.pps * secs) as u64;
///         let rx = (50_000.0f64.min(t.pps) * secs) as u64;
///         Ok(TrialResult { tx, rx, elapsed: t.duration.unwrap(), ..Default::default() })
///     }
/// }
/// let config = BenchConfig {
///     tests: vec![BenchTest::Throughput],
///     sizes: vec![SizeMix::fixed(1514).unwrap()],
///     line_rate_mbps: 1000.0,
///     trial_duration: Duration::from_secs(1),
///     ..Default::default()
/// };
/// let report = run_benchmark(&config, &mut Device, |_, _| {}).unwrap();
/// let t = report.sizes[0].throughput.as_ref().unwrap();
/// // 50,000 of 81,274 frames per second at line rate: about 61.5%.
/// assert!((t.load_pct - 61.5).abs() < 0.5, "{}", t.load_pct);
/// ```
pub fn run_benchmark(
    config: &BenchConfig,
    runner: &mut dyn TrialRunner,
    mut progress: impl FnMut(&SizeReport, &TrialRecord),
) -> Result<BenchReport> {
    config.validate()?;
    let mut bench = Bench {
        config,
        runner,
        progress: &mut progress,
        start: Instant::now(),
    };
    let mut report = BenchReport {
        config: config.summary(),
        stopped: false,
        elapsed_s: 0.0,
        sizes: Vec::new(),
    };
    for size in &config.sizes {
        let frame_len = size.mean_with(|s| bench.runner.sent_len(s));
        let mut sr = SizeReport {
            size: size.to_string(),
            frame_len,
            grown: size
                .entries()
                .iter()
                .any(|&(s, _)| bench.runner.sent_len(s) != s),
            line_pps: config.pps(100.0, frame_len),
            throughput: None,
            latency: None,
            frame_loss: Vec::new(),
            back_to_back: None,
            trials: Vec::new(),
        };
        let result = bench.size(size, &mut sr);
        report.sizes.push(sr);
        match result {
            Ok(()) => {}
            Err(StepError::Stopped) => {
                report.stopped = true;
                break;
            }
            Err(StepError::Failed(e)) => return Err(e),
        }
    }
    report.elapsed_s = bench.start.elapsed().as_secs_f64();
    Ok(report)
}

impl Bench<'_> {
    fn check_stop(&self) -> std::result::Result<(), Stopped> {
        let c = self.config;
        if c.stop.as_ref().is_some_and(|s| s.load(Ordering::Relaxed))
            || c.max_time.is_some_and(|t| self.start.elapsed() >= t)
        {
            Err(Stopped)
        } else {
            Ok(())
        }
    }

    fn trial(&self, test: BenchTest, size: &SizeMix, sr: &SizeReport, load: f64) -> Trial {
        let c = self.config;
        Trial {
            test,
            size: size.clone(),
            frame_len: sr.frame_len,
            load,
            pps: c.pps(load, sr.frame_len),
            duration: Some(c.trial_duration),
            packets: c.trial_packets,
            warmup: false,
        }
    }

    /// Runs a trial, records it and tells `progress`.
    fn run(
        &mut self,
        trial: &Trial,
        sr: &mut SizeReport,
        repetition: u32,
        pass: impl Fn(&TrialResult) -> Option<bool>,
    ) -> Step<(TrialResult, bool)> {
        self.check_stop()?;
        let result = self.runner.run(trial)?;
        let passed = pass(&result);
        let record = TrialRecord::new(trial, &result, repetition, passed);
        (self.progress)(sr, &record);
        sr.trials.push(record);
        Ok((result, passed.unwrap_or(false)))
    }

    fn size(&mut self, size: &SizeMix, sr: &mut SizeReport) -> Step<()> {
        let c = self.config;
        if !c.warmup.is_zero() {
            self.check_stop()?;
            let mut t = self.trial(BenchTest::Throughput, size, sr, c.warmup_load);
            t.duration = Some(c.warmup);
            t.packets = None;
            t.warmup = true;
            self.runner.run(&t)?;
        }
        for &test in &c.tests {
            match test {
                BenchTest::Throughput => self.throughput(size, sr)?,
                BenchTest::Latency => self.latency(size, sr)?,
                BenchTest::FrameLoss => self.frame_loss(size, sr)?,
                BenchTest::BackToBack => self.back_to_back(size, sr)?,
            }
        }
        Ok(())
    }

    fn throughput(&mut self, size: &SizeMix, sr: &mut SizeReport) -> Step<()> {
        let c = self.config;
        let threshold = c.loss_threshold;
        let pass = |r: &TrialResult| Some(r.rx > 0 && r.loss_pct() <= threshold);
        let mut loads = Vec::new();
        let mut passing: Vec<TrialRecord> = Vec::new();
        for rep in 1..=c.repetitions {
            let mut best: Option<(f64, usize)> = None;
            let mut trials = 1;
            let t = self.trial(BenchTest::Throughput, size, sr, c.max_load);
            if self.run(&t, sr, rep, pass)?.1 {
                best = Some((c.max_load, sr.trials.len() - 1));
            } else {
                let (mut lo, mut hi) = (c.min_load, c.max_load);
                while trials < c.max_trials && hi - lo > c.resolution {
                    let mid = (lo + hi) / 2.0;
                    let t = self.trial(BenchTest::Throughput, size, sr, mid);
                    trials += 1;
                    if self.run(&t, sr, rep, pass)?.1 {
                        best = Some((mid, sr.trials.len() - 1));
                        lo = mid;
                    } else {
                        hi = mid;
                    }
                }
                if best.is_none() && trials < c.max_trials {
                    let t = self.trial(BenchTest::Throughput, size, sr, c.min_load);
                    if self.run(&t, sr, rep, pass)?.1 {
                        best = Some((c.min_load, sr.trials.len() - 1));
                    }
                }
            }
            match best {
                Some((load, i)) => {
                    loads.push(load);
                    passing.push(sr.trials[i].clone());
                }
                None => loads.push(0.0),
            }
        }
        let n = loads.len() as f64;
        let avg = |f: fn(&TrialRecord) -> f64| passing.iter().map(f).sum::<f64>() / n;
        sr.throughput = Some(ThroughputResult {
            load_pct: loads.iter().sum::<f64>() / n,
            pps: avg(|t| t.achieved_pps),
            mbps: avg(|t| t.achieved_mbps),
            l1_mbps: avg(|t| t.achieved_l1_mbps),
            sender_limited: passing.iter().any(TrialRecord::sender_limited),
            repetitions: loads,
        });
        Ok(())
    }

    fn latency(&mut self, size: &SizeMix, sr: &mut SizeReport) -> Step<()> {
        let c = self.config;
        let load = match (c.latency_load, &sr.throughput) {
            (Some(l), _) => l,
            (None, Some(t)) if t.load_pct > 0.0 => t.load_pct,
            (None, Some(_)) => return Ok(()), // nothing passed: no rate to measure at
            (None, None) => c.max_load,
        };
        let mut all = LatencyStats::default();
        let (mut tx, mut lost) = (0u64, 0u64);
        for rep in 1..=c.repetitions {
            let t = self.trial(BenchTest::Latency, size, sr, load);
            let (r, _) = self.run(&t, sr, rep, |_| None)?;
            all.merge(&r.latency);
            tx += r.tx;
            lost += r.lost();
        }
        sr.latency = Some(LatencyResult {
            load_pct: load,
            trials: c.repetitions,
            loss_pct: if tx == 0 {
                0.0
            } else {
                lost as f64 * 100.0 / tx as f64
            },
            latency: (&all).into(),
        });
        Ok(())
    }

    fn frame_loss(&mut self, size: &SizeMix, sr: &mut SizeReport) -> Step<()> {
        let c = self.config;
        let mut load = c.max_load;
        let mut clean = 0;
        while load > 1e-9 {
            let (mut tx, mut rx) = (0u64, 0u64);
            let t = self.trial(BenchTest::FrameLoss, size, sr, load);
            for rep in 1..=c.repetitions {
                let (r, _) = self.run(&t, sr, rep, |r| Some(r.lost() == 0))?;
                tx += r.tx;
                rx += r.rx;
            }
            let lost = tx.saturating_sub(rx);
            sr.frame_loss.push(LossPoint {
                load_pct: load,
                offered_pps: t.pps,
                tx,
                rx,
                loss_pct: if tx == 0 {
                    0.0
                } else {
                    lost as f64 * 100.0 / tx as f64
                },
            });
            clean = if lost == 0 && rx > 0 { clean + 1 } else { 0 };
            if clean >= c.frame_loss_clean {
                break;
            }
            load -= c.frame_loss_step;
        }
        Ok(())
    }

    fn back_to_back(&mut self, size: &SizeMix, sr: &mut SizeReport) -> Step<()> {
        let c = self.config;
        let burst = |b: &mut Self, sr: &SizeReport, frames: u64| {
            let mut t = b.trial(BenchTest::BackToBack, size, sr, c.max_load);
            t.packets = Some(frames);
            // Long enough for the burst; the frame count ends it.
            t.duration =
                Some(Duration::from_secs_f64(frames as f64 / t.pps) * 2 + c.trial_duration);
            t
        };
        let pass = |r: &TrialResult| Some(r.tx > 0 && r.lost() == 0);
        let tolerance = ((c.burst_max as f64 * c.resolution / 100.0) as u64).max(1);
        let mut found = Vec::new();
        let mut at_limit = false;
        for rep in 1..=c.repetitions {
            let t = burst(self, sr, c.burst_max);
            if self.run(&t, sr, rep, pass)?.1 {
                found.push(c.burst_max);
                at_limit = true;
                continue;
            }
            let (mut lo, mut hi) = (0u64, c.burst_max);
            let mut trials = 1;
            while trials < c.max_trials && hi - lo > tolerance {
                let mid = (lo + (hi - lo) / 2).max(1);
                let t = burst(self, sr, mid);
                trials += 1;
                if self.run(&t, sr, rep, pass)?.1 {
                    lo = mid;
                } else {
                    hi = mid;
                }
            }
            found.push(lo);
        }
        let frames = found.iter().sum::<u64>() as f64 / found.len() as f64;
        let pps = c.pps(c.max_load, sr.frame_len);
        sr.back_to_back = Some(BurstResult {
            load_pct: c.max_load,
            frames,
            duration_us: frames / pps * 1e6,
            repetitions: found,
            at_limit,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A simulated device: forwards up to `capacity` frames per second, holds
    /// a queue of `buffer` frames, and adds `delay` of latency.
    struct Device {
        capacity: f64,
        buffer: u64,
        delay: Duration,
        trials: Vec<Trial>,
    }

    impl Device {
        fn new(capacity: f64, buffer: u64) -> Self {
            Self {
                capacity,
                buffer,
                delay: Duration::from_micros(50),
                trials: Vec::new(),
            }
        }
    }

    impl TrialRunner for Device {
        fn run(&mut self, t: &Trial) -> Result<TrialResult> {
            self.trials.push(t.clone());
            let full = t.duration.unwrap().as_secs_f64() * t.pps;
            let tx = t.packets.map_or(full, |p| (p as f64).min(full)) as u64;
            let secs = tx as f64 / t.pps;
            let served = (self.capacity * secs) as u64 + self.buffer;
            let rx = tx.min(served);
            let mut latency = LatencyStats::default();
            for _ in 0..rx.min(1000) {
                latency.record(Some(self.delay));
            }
            Ok(TrialResult {
                tx,
                tx_bytes: (tx as f64 * t.frame_len) as u64,
                rx,
                elapsed: Duration::from_secs_f64(secs),
                latency,
                ..Default::default()
            })
        }

        fn sent_len(&self, size: usize) -> usize {
            size.max(70)
        }
    }

    fn config(tests: &[BenchTest], sizes: &str) -> BenchConfig {
        BenchConfig {
            tests: tests.to_vec(),
            sizes: sizes.split(' ').map(|s| s.parse().unwrap()).collect(),
            line_rate_mbps: 100.0,
            trial_duration: Duration::from_secs(1),
            ..Default::default()
        }
    }

    #[test]
    fn line_rate_counts_the_wire_overhead() {
        let c = BenchConfig::default();
        // 64-byte frames at 1 Gbit/s: 1,488,095 frames per second.
        assert!((c.pps(100.0, 60.0) - 1_488_095.2).abs() < 1.0);
        assert!((c.pps(50.0, 1514.0) - 40_637.2).abs() < 1.0);
    }

    #[test]
    fn throughput_search_converges() {
        let mut dev = Device::new(5000.0, 0);
        let c = config(&[BenchTest::Throughput], "1020");
        let report = run_benchmark(&c, &mut dev, |_, _| {}).unwrap();
        let s = &report.sizes[0];
        assert!(!s.grown);
        let t = s.throughput.as_ref().unwrap();
        // 5000 fps of 1044 bytes on the wire = 41.76 Mbit/s of 100.
        assert!(t.load_pct <= 41.76 && t.load_pct > 41.76 - 0.5, "{t:?}");
        assert!((t.pps - 4990.0).abs() < 50.0, "{t:?}");
        assert!(!t.sender_limited);
        assert!(s.trials.len() <= 20);
        assert_eq!(s.trials[0].load_pct, 100.0);
        assert_eq!(s.trials[0].passed, Some(false));
    }

    #[test]
    fn throughput_at_line_rate_and_threshold() {
        let mut dev = Device::new(1e9, 0);
        let c = config(&[BenchTest::Throughput], "508");
        let report = run_benchmark(&c, &mut dev, |_, _| {}).unwrap();
        assert_eq!(report.sizes[0].trials.len(), 1);
        assert_eq!(report.sizes[0].throughput.as_ref().unwrap().load_pct, 100.0);

        // A 10% loss threshold lets a device that forwards 95% pass at 100%.
        let line = c.pps(100.0, 508.0);
        let mut dev = Device::new(line * 0.95, 0);
        let mut c = config(&[BenchTest::Throughput], "508");
        c.loss_threshold = 10.0;
        let report = run_benchmark(&c, &mut dev, |_, _| {}).unwrap();
        assert_eq!(report.sizes[0].throughput.as_ref().unwrap().load_pct, 100.0);
    }

    #[test]
    fn nothing_passes() {
        let mut dev = Device::new(0.0, 0);
        let c = config(&[BenchTest::Throughput, BenchTest::Latency], "124");
        let report = run_benchmark(&c, &mut dev, |_, _| {}).unwrap();
        let s = &report.sizes[0];
        assert_eq!(s.throughput.as_ref().unwrap().load_pct, 0.0);
        assert!(s.latency.is_none());
        assert_eq!(s.trials.last().unwrap().load_pct, c.min_load);
    }

    #[test]
    fn latency_runs_at_the_throughput() {
        let mut dev = Device::new(5000.0, 0);
        let mut c = config(&[BenchTest::Throughput, BenchTest::Latency], "1020");
        c.repetitions = 2;
        let report = run_benchmark(&c, &mut dev, |_, _| {}).unwrap();
        let s = &report.sizes[0];
        let t = s.throughput.as_ref().unwrap();
        assert_eq!(t.repetitions.len(), 2);
        let l = s.latency.as_ref().unwrap();
        assert_eq!(l.load_pct, t.load_pct);
        assert_eq!(l.trials, 2);
        assert_eq!(l.loss_pct, 0.0);
        assert_eq!(l.latency.min_us, Some(50.0));
        assert_eq!(l.latency.count, 2000);
        let lat: Vec<_> = s
            .trials
            .iter()
            .filter(|t| t.test == BenchTest::Latency)
            .collect();
        assert_eq!(lat.len(), 2);
        assert_eq!(lat[1].repetition, 2);
    }

    #[test]
    fn frame_loss_steps_down_until_clean() {
        let line = config(&[], "1020").pps(100.0, 1020.0);
        let mut dev = Device::new(line * 0.55, 0);
        let c = config(&[BenchTest::FrameLoss], "1020");
        let report = run_benchmark(&c, &mut dev, |_, _| {}).unwrap();
        let loads: Vec<f64> = report.sizes[0]
            .frame_loss
            .iter()
            .map(|p| p.load_pct.round())
            .collect();
        assert_eq!(loads, [100.0, 90.0, 80.0, 70.0, 60.0, 50.0, 40.0]);
        let first = &report.sizes[0].frame_loss[0];
        assert!((first.loss_pct - 45.0).abs() < 0.5, "{first:?}");
        assert_eq!(report.sizes[0].frame_loss[5].loss_pct, 0.0);
    }

    #[test]
    fn back_to_back_finds_the_buffer() {
        // Half the line rate drains while a burst comes in: the buffer plus
        // what drains is the longest burst, buffer * 2 for a device at 50%.
        let line = config(&[], "508").pps(100.0, 508.0);
        let mut dev = Device::new(line * 0.5, 300);
        let mut c = config(&[BenchTest::BackToBack], "508");
        c.burst_max = 10_000;
        c.resolution = 0.1;
        let report = run_benchmark(&c, &mut dev, |_, _| {}).unwrap();
        let b = report.sizes[0].back_to_back.as_ref().unwrap();
        assert!((b.frames - 600.0).abs() <= 10.0, "{b:?}");
        assert!(!b.at_limit);
        assert!(dev.trials.iter().all(|t| t.packets.is_some()));
        let r = &report.sizes[0].trials[0];
        assert_eq!(r.burst, Some(10_000));
        assert!(!r.sender_limited());

        let mut dev = Device::new(1e9, 0);
        let report = run_benchmark(&c, &mut dev, |_, _| {}).unwrap();
        let b = report.sizes[0].back_to_back.as_ref().unwrap();
        assert!(b.at_limit);
        assert_eq!(b.frames, 10_000.0);
    }

    #[test]
    fn sizes_grow_warmup_and_stop() {
        let mut dev = Device::new(1e9, 0);
        let mut c = config(&[BenchTest::Throughput], "60 imix");
        c.warmup = Duration::from_millis(100);
        let mut seen = 0;
        let report = run_benchmark(&c, &mut dev, |_, _| seen += 1).unwrap();
        assert_eq!(seen, 2);
        assert!(report.sizes[0].grown);
        assert_eq!(report.sizes[0].frame_len, 70.0);
        assert_eq!(report.sizes[1].size, "imix");
        assert!(report.sizes[1].grown);
        assert!(
            (report.sizes[1].frame_len - (70.0 * 7.0 + 590.0 * 4.0 + 1514.0) / 12.0).abs() < 1e-9
        );
        let warm: Vec<_> = dev.trials.iter().filter(|t| t.warmup).collect();
        assert_eq!(warm.len(), 2);
        assert_eq!(warm[0].load, c.warmup_load);

        let stop = Arc::new(AtomicBool::new(true));
        c.stop = Some(stop);
        let report = run_benchmark(&c, &mut dev, |_, _| {}).unwrap();
        assert!(report.stopped);
        assert_eq!(report.sizes.len(), 1);
        assert!(report.sizes[0].trials.is_empty());
    }

    #[test]
    fn sender_limits_are_flagged() {
        struct Slow;
        impl TrialRunner for Slow {
            fn run(&mut self, t: &Trial) -> Result<TrialResult> {
                let d = t.duration.unwrap();
                let tx = (t.pps.min(1000.0) * d.as_secs_f64()) as u64;
                Ok(TrialResult {
                    tx,
                    rx: tx,
                    elapsed: d,
                    ..Default::default()
                })
            }
        }
        let c = config(&[BenchTest::Throughput], "1020");
        let report = run_benchmark(&c, &mut Slow, |_, _| {}).unwrap();
        let t = report.sizes[0].throughput.as_ref().unwrap();
        assert_eq!(t.load_pct, 100.0);
        assert!(t.sender_limited);
        assert!((t.pps - 1000.0).abs() < 1.0);
    }

    #[test]
    fn bad_configs() {
        let ok = config(&[BenchTest::Throughput], "64");
        assert!(ok.validate().is_ok());
        for f in [
            |c: &mut BenchConfig| c.tests.clear(),
            |c: &mut BenchConfig| c.max_load = 120.0,
            |c: &mut BenchConfig| c.min_load = 0.0,
            |c: &mut BenchConfig| c.line_rate_mbps = 0.0,
            |c: &mut BenchConfig| c.repetitions = 0,
            |c: &mut BenchConfig| c.loss_threshold = 100.0,
            |c: &mut BenchConfig| c.trial_duration = Duration::ZERO,
        ] {
            let mut c = ok.clone();
            f(&mut c);
            assert!(c.validate().is_err());
        }
        assert_eq!("b2b".parse::<BenchTest>().unwrap(), BenchTest::BackToBack);
        assert_eq!(
            "frame-loss".parse::<BenchTest>().unwrap(),
            BenchTest::FrameLoss
        );
        assert!("speed".parse::<BenchTest>().is_err());
    }
}
