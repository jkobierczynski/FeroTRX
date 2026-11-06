//! Ethernet service activation tests in the manner of ITU-T Y.1564.
//!
//! A *service* is a class of traffic with a bandwidth profile: a committed
//! information rate (CIR) whose frames must get through within the service
//! acceptance criteria (SAC: frame loss ratio, frame transfer delay, frame
//! delay variation, availability), an excess information rate (EIR) on top
//! that the network may drop, and the burst sizes the policer allows (CBS,
//! EBS). [`run_y1564`] tests services the way Y.1564 describes:
//!
//! * **Service configuration test**, one service at a time:
//!   * steps up to the CIR (by default 25, 50, 75 and 100%), green frames
//!     only; each step passes when the green frames meet the SAC;
//!   * CIR + EIR: green frames at the CIR and yellow ones at the EIR; the
//!     green frames must meet the SAC, the yellow ones may be dropped, and
//!     what arrives must be at least the CIR and at most CIR + EIR;
//!   * traffic policing: green at the CIR and yellow at 125% of the EIR (or
//!     25% of the CIR when there is no EIR); the green frames must meet the
//!     SAC and what arrives must be at most CIR + EIR, so a policer must be
//!     there and work;
//!   * CBS and EBS bursts, when the service gives them: green frames in
//!     bursts of CBS bytes at line rate averaging the CIR, then green at the
//!     CIR with yellow bursts of EBS bytes averaging the EIR; the green frames
//!     must meet the SAC.
//! * **Service performance test**: all services together, green frames at
//!   their CIR, for a long time (15 minutes by default); per service the
//!   frame loss, delay, delay variation and availability, with loss and
//!   delay per interval (1 second by default).
//!
//! Green and yellow frames are separate flows, each with its own latency
//! [`Signature`](crate::Signature), so they are counted apart even when the
//! frames are alike. A network that tells them apart (color aware) needs them
//! marked: give yellow frames their own description, e.g. another DSCP or
//! VLAN priority. For a color-blind service, where the network cannot tell
//! green from yellow, the policing and EBS steps judge only the information
//! rate: a policer may drop any frame above the CIR.
//!
//! Rates count Ethernet frames with their FCS (layer 2, as MEF bandwidth
//! profiles do), or also the preamble and gap with `layer1`. The steps are
//! run by a [`ServiceRunner`]: [`JobServiceRunner`] sends with a
//! [`Job`](crate::Job) and receives with a [`RxJob`](crate::RxJob); tests use
//! simulated networks.
//!
//! Availability follows ITU-T Y.1563: an interval whose frame loss ratio is
//! above `ses_flr` (50%) is severely errored; ten of them in a row start
//! unavailable time (from the first of them), and ten intervals in a row that
//! are not end it (from the first of those).

#[cfg(feature = "profile")]
mod profile;
mod report;
mod runner;

use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(feature = "profile")]
pub use profile::Y1564Profile;
pub use runner::{JobServiceRunner, ServiceFrames};

use crate::bench::LatencySummary;
use crate::{Error, IntervalStats, LatencyStats, Result, SizeMix, FCS_LEN, L1_OVERHEAD};

/// The two Y.1564 tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Y1564Test {
    /// Steps per service: up to the CIR, CIR + EIR, policing, bursts.
    Configuration,
    /// All services at their CIR for a long time.
    Performance,
}

impl Y1564Test {
    pub const ALL: [Y1564Test; 2] = [Y1564Test::Configuration, Y1564Test::Performance];

    pub fn name(self) -> &'static str {
        match self {
            Y1564Test::Configuration => "configuration",
            Y1564Test::Performance => "performance",
        }
    }
}

impl FromStr for Y1564Test {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "configuration" | "config" | "service_configuration" => Ok(Y1564Test::Configuration),
            "performance" | "perf" | "service_performance" => Ok(Y1564Test::Performance),
            _ => Err(Error::Bench(format!(
                "unknown Y.1564 test '{s}': use configuration or performance"
            ))),
        }
    }
}

impl std::fmt::Display for Y1564Test {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Green frames are within the CIR and must meet the acceptance criteria;
/// yellow frames are the excess (EIR) and may be dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Color {
    Green,
    Yellow,
}

impl Color {
    pub fn name(self) -> &'static str {
        match self {
            Color::Green => "green",
            Color::Yellow => "yellow",
        }
    }
}

/// Service acceptance criteria. Loss is always judged; delay, delay
/// variation and availability only when given.
#[derive(Clone, Debug, PartialEq)]
pub struct Acceptance {
    /// Highest frame loss ratio of the green frames, percent.
    pub flr: f64,
    /// Highest mean frame transfer delay (one way).
    pub ftd: Option<Duration>,
    /// Highest frame delay variation: the 99th percentile of the delay
    /// minus its minimum.
    pub fdv: Option<Duration>,
    /// Lowest availability in the performance test, percent.
    pub availability: Option<f64>,
}

impl Default for Acceptance {
    fn default() -> Self {
        Self {
            flr: 0.0,
            ftd: None,
            fdv: None,
            availability: None,
        }
    }
}

/// One service: its bandwidth profile, frame sizes and acceptance criteria.
/// The frames themselves are the runner's ([`ServiceFrames`]).
#[derive(Clone, Debug)]
pub struct ServiceSpec {
    pub name: String,
    /// Frame sizes without FCS, or a mix such as EMIX.
    pub size: SizeMix,
    /// Committed information rate, Mbit/s.
    pub cir_mbps: f64,
    /// Excess information rate, Mbit/s (0 for none).
    pub eir_mbps: f64,
    /// Committed and excess burst sizes in bytes; 0 skips that burst test.
    pub cbs: u64,
    pub ebs: u64,
    pub sac: Acceptance,
    /// Yellow frames are marked apart from green ones, so the network can
    /// drop yellow first: the green frames must meet the SAC in every step.
    /// Without it (color blind) the policing and EBS steps judge only the
    /// information rate, as a policer may drop any frame above the CIR.
    pub color_aware: bool,
}

/// What to test and how; see the [module documentation](self).
#[derive(Clone, Debug)]
pub struct Y1564Config {
    pub services: Vec<ServiceSpec>,
    pub tests: Vec<Y1564Test>,
    /// Configuration test steps up to the CIR, percent of the CIR.
    pub steps: Vec<f64>,
    /// How long each configuration step sends.
    pub step_duration: Duration,
    /// Policing step: yellow frames at this percent of the EIR (of the
    /// CIR, minus 100, when the EIR is 0).
    pub overshoot: f64,
    /// Run the CBS and EBS burst steps of services that give burst sizes.
    pub burst_tests: bool,
    pub performance_duration: Duration,
    /// Performance test: loss and delay are also reported per interval.
    pub interval: Duration,
    /// Margin on the information rate checks, percent.
    pub ir_tolerance: f64,
    /// An interval with more loss than this, percent, is severely errored.
    pub ses_flr: f64,
    /// Severely errored intervals in a row that make the service
    /// unavailable, and good ones in a row that end it.
    pub unavailable_after: u32,
    /// Speed of the link in Mbit/s, for the burst steps and to check that
    /// the services fit.
    pub line_rate_mbps: f64,
    /// Count the preamble and gap (20 bytes a frame) in rates too.
    pub layer1: bool,
    /// Stop after this long; the report is partial.
    pub max_time: Option<Duration>,
    /// Set to true from another thread to stop.
    pub stop: Option<Arc<AtomicBool>>,
}

impl Default for Y1564Config {
    fn default() -> Self {
        Self {
            services: Vec::new(),
            tests: Y1564Test::ALL.to_vec(),
            steps: vec![25.0, 50.0, 75.0, 100.0],
            step_duration: Duration::from_secs(60),
            overshoot: 125.0,
            burst_tests: true,
            performance_duration: Duration::from_secs(15 * 60),
            interval: Duration::from_secs(1),
            ir_tolerance: 5.0,
            ses_flr: 50.0,
            unavailable_after: 10,
            line_rate_mbps: 1000.0,
            layer1: false,
            max_time: None,
            stop: None,
        }
    }
}

impl Y1564Config {
    /// Checks that the numbers make sense together.
    pub fn validate(&self) -> Result<()> {
        let bad = |m: String| Err(Error::Bench(m));
        let pos = |v: f64| v.is_finite() && v > 0.0;
        if self.services.is_empty() {
            return bad("no services to test".into());
        }
        if self.tests.is_empty() {
            return bad("no tests to run".into());
        }
        if !pos(self.line_rate_mbps) {
            return bad("line rate must be a positive number".into());
        }
        let mut cir_total = 0.0;
        for (i, s) in self.services.iter().enumerate() {
            if s.name.is_empty() {
                return bad(format!("service {}: give it a name", i + 1));
            }
            if self.services[..i].iter().any(|o| o.name == s.name) {
                return bad(format!("two services are named '{}'", s.name));
            }
            if !pos(s.cir_mbps) {
                return bad(format!("service '{}': cir must be above 0", s.name));
            }
            if !(s.eir_mbps.is_finite() && s.eir_mbps >= 0.0) {
                return bad(format!("service '{}': eir must be 0 or more", s.name));
            }
            if s.cir_mbps + s.eir_mbps > self.line_rate_mbps {
                return bad(format!(
                    "service '{}': cir + eir is more than the line rate",
                    s.name
                ));
            }
            if !(s.sac.flr.is_finite() && (0.0..100.0).contains(&s.sac.flr)) {
                return bad(format!(
                    "service '{}': flr is a percentage from 0 up to 100",
                    s.name
                ));
            }
            if let Some(a) = s.sac.availability {
                if !(a.is_finite() && (0.0..=100.0).contains(&a)) {
                    return bad(format!(
                        "service '{}': availability is a percentage up to 100",
                        s.name
                    ));
                }
            }
            cir_total += s.cir_mbps;
        }
        if self.tests.contains(&Y1564Test::Performance) && cir_total > self.line_rate_mbps {
            return bad("the services' CIRs add up to more than the line rate".into());
        }
        if self.tests.contains(&Y1564Test::Configuration) && self.steps.is_empty() {
            return bad("no configuration steps".into());
        }
        if let Some(s) = self.steps.iter().find(|&&s| !(pos(s) && s <= 100.0)) {
            return bad(format!(
                "step {s}: steps are above 0 and at most 100 percent"
            ));
        }
        if !(self.overshoot.is_finite() && self.overshoot > 100.0) {
            return bad("overshoot must be above 100 percent".into());
        }
        if self.step_duration.is_zero() || self.performance_duration.is_zero() {
            return bad("step and performance durations must be above 0".into());
        }
        if self.interval.is_zero() {
            return bad("interval must be above 0".into());
        }
        if !(self.ir_tolerance.is_finite() && self.ir_tolerance >= 0.0) {
            return bad("ir_tolerance must be 0 or more".into());
        }
        if !(pos(self.ses_flr) && self.ses_flr <= 100.0) {
            return bad("ses_flr is a percentage above 0, at most 100".into());
        }
        if self.unavailable_after == 0 {
            return bad("unavailable_after must be at least 1".into());
        }
        Ok(())
    }

    /// Bytes per frame on top of its length without FCS, as rates count it.
    pub fn overhead(&self) -> f64 {
        (FCS_LEN + if self.layer1 { L1_OVERHEAD } else { 0 }) as f64
    }

    /// Frames per second for `mbps`, frames of `frame_len` bytes (without
    /// FCS) on average.
    pub fn pps(&self, mbps: f64, frame_len: f64) -> f64 {
        mbps * 1e6 / ((frame_len + self.overhead()) * 8.0)
    }

    /// Mbit/s of `frames` frames of `bytes` bytes (without FCS) in `secs`.
    pub fn mbps(&self, frames: u64, bytes: u64, secs: f64) -> f64 {
        if secs <= 0.0 {
            return 0.0;
        }
        (bytes as f64 + frames as f64 * self.overhead()) * 8.0 / 1e6 / secs
    }

    fn summary(&self) -> Y1564Summary {
        Y1564Summary {
            tests: self.tests.clone(),
            services: self
                .services
                .iter()
                .map(|s| ServiceSummary {
                    name: s.name.clone(),
                    size: s.size.to_string(),
                    cir_mbps: s.cir_mbps,
                    eir_mbps: s.eir_mbps,
                    cbs: s.cbs,
                    ebs: s.ebs,
                    flr_pct: s.sac.flr,
                    ftd_ms: s.sac.ftd.map(ms),
                    fdv_ms: s.sac.fdv.map(ms),
                    availability_pct: s.sac.availability,
                })
                .collect(),
            steps: self.steps.clone(),
            step_duration_s: self.step_duration.as_secs_f64(),
            overshoot: self.overshoot,
            performance_duration_s: self.performance_duration.as_secs_f64(),
            interval_s: self.interval.as_secs_f64(),
            ir_tolerance: self.ir_tolerance,
            ses_flr: self.ses_flr,
            unavailable_after: self.unavailable_after,
            line_rate_mbps: self.line_rate_mbps,
            layer1: self.layer1,
        }
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Which step of a test.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "pct", rename_all = "snake_case")
)]
pub enum StepKind {
    /// Green frames at this percent of the CIR.
    Cir(f64),
    /// Green at the CIR, yellow at the EIR.
    Eir,
    /// Green at the CIR, yellow above the EIR.
    Policing,
    /// Green frames in bursts of CBS bytes.
    Cbs,
    /// Green at the CIR, yellow in bursts of EBS bytes.
    Ebs,
    /// All services' green frames at their CIR.
    Performance,
}

impl std::fmt::Display for StepKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StepKind::Cir(p) => write!(f, "{p}% CIR"),
            StepKind::Eir => f.write_str("CIR+EIR"),
            StepKind::Policing => f.write_str("policing"),
            StepKind::Cbs => f.write_str("CBS burst"),
            StepKind::Ebs => f.write_str("EBS burst"),
            StepKind::Performance => f.write_str("performance"),
        }
    }
}

/// One flow of a step: a service's green or yellow frames at a rate.
#[derive(Clone, Debug)]
pub struct StepFlow {
    /// Index into [`Y1564Config::services`].
    pub service: usize,
    pub color: Color,
    /// The sizes to send; [`SizeMix::reset`] before use.
    pub size: SizeMix,
    /// Average frame length as sent, without FCS.
    pub frame_len: f64,
    /// Offered rate, Mbit/s as the config counts, and frames per second.
    pub mbps: f64,
    pub pps: f64,
    /// Frames back to back in each burst, at the same mean rate; 0 or 1 for
    /// evenly spaced frames.
    pub burst: u32,
}

/// One step for a [`ServiceRunner`]: flows sent together for a while.
#[derive(Clone, Debug)]
pub struct Y1564Step {
    pub test: Y1564Test,
    pub kind: StepKind,
    pub flows: Vec<StepFlow>,
    pub duration: Duration,
    /// Count arrivals per interval of send time (performance test).
    pub interval: Option<Duration>,
}

/// What one flow of a step measured.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FlowResult {
    /// Frames and bytes (without FCS) sent.
    pub tx: u64,
    pub tx_bytes: u64,
    /// Frames received once, and their bytes.
    pub rx: u64,
    pub rx_bytes: u64,
    pub duplicates: u64,
    pub out_of_order: u64,
    /// When sending started (since the Unix epoch, as signatures count) and
    /// how long it went on.
    pub start: Duration,
    pub elapsed: Duration,
    pub latency: LatencyStats,
    /// With [`Y1564Step::interval`]: arrivals per interval of send time,
    /// keyed by the send time divided by the interval.
    pub intervals: std::collections::BTreeMap<u64, IntervalStats>,
}

/// Runs the steps of a Y.1564 test.
pub trait ServiceRunner {
    /// Sends the step's flows together and returns what each measured, in
    /// the order of [`Y1564Step::flows`].
    fn run(&mut self, step: &Y1564Step) -> Result<Vec<FlowResult>>;

    /// The length a frame of `service` asked to be `size` bytes really gets.
    fn sent_len(&self, _service: usize, size: usize) -> usize {
        size
    }
}

/// One flow of a step in the report.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FlowRecord {
    pub service: String,
    pub color: Color,
    pub offered_mbps: f64,
    pub offered_pps: f64,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub burst: Option<u32>,
    /// Rate sent, and rate received (the information rate), Mbit/s.
    pub tx_mbps: f64,
    pub ir_mbps: f64,
    pub tx: u64,
    pub rx: u64,
    pub lost: u64,
    /// Frame loss ratio, percent.
    pub flr_pct: f64,
    pub duplicates: u64,
    pub out_of_order: u64,
    /// Mean frame transfer delay and delay variation (p99 - min), ms.
    pub ftd_ms: Option<f64>,
    pub fdv_ms: Option<f64>,
    pub latency: LatencySummary,
    /// The sender reached less than 97% of the offered rate.
    pub sender_limited: bool,
}

/// Loss and delay of a service's green frames sent in one interval.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IntervalRecord {
    /// Seconds from the start of sending.
    pub start_s: f64,
    pub rx: u64,
    pub flr_pct: f64,
    pub ftd_ms: Option<f64>,
    pub max_ftd_ms: Option<f64>,
    /// Severely errored: loss above `ses_flr`.
    pub ses: bool,
    pub available: bool,
}

/// A service's result in a step: the verdict and why.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServiceResult {
    pub service: String,
    /// Green frames: loss ratio, delay and delay variation.
    pub flr_pct: f64,
    pub ftd_ms: Option<f64>,
    pub fdv_ms: Option<f64>,
    /// Information rate received, green and yellow together, Mbit/s.
    pub ir_mbps: f64,
    /// Yellow frames lost, percent (allowed).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub yellow_flr_pct: Option<f64>,
    /// Performance test: percent of the intervals available, severely
    /// errored intervals, and every interval.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub availability_pct: Option<f64>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ses: Option<u64>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub intervals: Vec<IntervalRecord>,
    pub passed: bool,
    /// Whether the green frames' loss, delay and delay variation were judged
    /// (not in the policing and EBS steps of a color-blind service).
    pub green_judged: bool,
    /// What failed, e.g. `FLR 2.1% > 0.1%`; empty when it passed.
    pub failures: Vec<String>,
    /// Remarks that do not fail the step, e.g. a sender that fell short.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub notes: Vec<String>,
}

/// One step in the report.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StepRecord {
    pub test: Y1564Test,
    pub step: StepKind,
    /// The step's name, e.g. `50% CIR`.
    pub name: String,
    pub duration_s: f64,
    pub flows: Vec<FlowRecord>,
    pub services: Vec<ServiceResult>,
    pub passed: bool,
}

/// A service as configured, for the report.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServiceSummary {
    pub name: String,
    pub size: String,
    pub cir_mbps: f64,
    pub eir_mbps: f64,
    pub cbs: u64,
    pub ebs: u64,
    pub flr_pct: f64,
    pub ftd_ms: Option<f64>,
    pub fdv_ms: Option<f64>,
    pub availability_pct: Option<f64>,
}

/// The settings a test ran with, for the report.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Y1564Summary {
    pub tests: Vec<Y1564Test>,
    pub services: Vec<ServiceSummary>,
    pub steps: Vec<f64>,
    pub step_duration_s: f64,
    pub overshoot: f64,
    pub performance_duration_s: f64,
    pub interval_s: f64,
    pub ir_tolerance: f64,
    pub ses_flr: f64,
    pub unavailable_after: u32,
    pub line_rate_mbps: f64,
    pub layer1: bool,
}

/// Pass or fail of one service over the whole run.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServiceVerdict {
    pub service: String,
    /// `None` when that test did not run (or not to the end).
    pub configuration: Option<bool>,
    pub performance: Option<bool>,
    pub passed: bool,
}

/// The results of [`run_y1564`].
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Y1564Report {
    pub config: Y1564Summary,
    /// Configuration steps, service by service.
    pub configuration: Vec<StepRecord>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub performance: Option<StepRecord>,
    pub services: Vec<ServiceVerdict>,
    /// Every step that ran passed, and nothing was stopped.
    pub passed: bool,
    pub stopped: bool,
    pub elapsed_s: f64,
}

impl Y1564Report {
    /// Steps that failed.
    pub fn failed_steps(&self) -> usize {
        self.configuration
            .iter()
            .chain(&self.performance)
            .filter(|s| !s.passed)
            .count()
    }

    /// Green frame loss, worst over the steps, percent.
    pub fn worst<F: Fn(&ServiceResult) -> Option<f64>>(&self, f: F) -> Option<f64> {
        self.configuration
            .iter()
            .chain(&self.performance)
            .flat_map(|s| &s.services)
            .filter_map(f)
            .reduce(f64::max)
    }

    /// Lowest availability of a service in the performance test.
    pub fn min_availability(&self) -> Option<f64> {
        self.performance
            .as_ref()?
            .services
            .iter()
            .filter_map(|s| s.availability_pct)
            .reduce(f64::min)
    }
}

/// Runs the tests of `config`, one step at a time, and calls `progress`
/// after each step. A stop request or `max_time` ends it between steps (and
/// stops a step the runner is told to stop), with what was measured so far.
///
/// ```
/// use ferotrx_core::*;
/// use std::time::Duration;
///
/// // A network with a policer at 10 Mbit/s: it passes everything below and
/// // drops what is above, yellow frames first.
/// struct Policed;
/// impl ServiceRunner for Policed {
///     fn run(&mut self, step: &Y1564Step) -> Result<Vec<FlowResult>> {
///         let secs = step.duration.as_secs_f64();
///         let mut room = 10.0;
///         Ok(step.flows.iter().map(|f| {
///             let passed = f.mbps.min(room);
///             room -= passed;
///             let tx = (f.pps * secs) as u64;
///             let rx = (tx as f64 * passed / f.mbps) as u64;
///             FlowResult {
///                 tx, rx,
///                 tx_bytes: tx * 1000, rx_bytes: rx * 1000,
///                 elapsed: step.duration,
///                 ..Default::default()
///             }
///         }).collect())
///     }
/// }
/// let config = Y1564Config {
///     services: vec![ServiceSpec {
///         name: "data".into(),
///         size: SizeMix::fixed(1000).unwrap(),
///         cir_mbps: 8.0,
///         eir_mbps: 2.0,
///         cbs: 0,
///         ebs: 0,
///         sac: Acceptance::default(),
///         color_aware: true,
///     }],
///     tests: vec![Y1564Test::Configuration],
///     step_duration: Duration::from_secs(10),
///     ..Default::default()
/// };
/// let report = run_y1564(&config, &mut Policed, |_| {}).unwrap();
/// // 25, 50, 75, 100% of the CIR, CIR+EIR and policing all pass.
/// assert_eq!(report.configuration.len(), 6);
/// assert!(report.passed);
/// ```
pub fn run_y1564(
    config: &Y1564Config,
    runner: &mut dyn ServiceRunner,
    mut progress: impl FnMut(&StepRecord),
) -> Result<Y1564Report> {
    config.validate()?;
    let start = Instant::now();
    let mut report = Y1564Report {
        config: config.summary(),
        configuration: Vec::new(),
        performance: None,
        services: Vec::new(),
        passed: false,
        stopped: false,
        elapsed_s: 0.0,
    };
    let stopped = || {
        config
            .stop
            .as_ref()
            .is_some_and(|s| s.load(Ordering::Relaxed))
            || config.max_time.is_some_and(|t| start.elapsed() >= t)
    };
    let frame_lens: Vec<f64> = config
        .services
        .iter()
        .enumerate()
        .map(|(i, s)| s.size.mean_with(|n| runner.sent_len(i, n)))
        .collect();
    let flow = |service: usize, color: Color, mbps: f64, burst_bytes: u64| {
        let s = &config.services[service];
        let frame_len = frame_lens[service];
        let burst = if burst_bytes > 0 {
            (burst_bytes as f64 / (frame_len + FCS_LEN as f64))
                .floor()
                .clamp(1.0, f64::from(u32::MAX)) as u32
        } else {
            0
        };
        StepFlow {
            service,
            color,
            size: s.size.clone(),
            frame_len,
            mbps,
            pps: config.pps(mbps, frame_len),
            burst,
        }
    };
    'outer: for &test in &config.tests {
        match test {
            Y1564Test::Configuration => {
                for (i, s) in config.services.iter().enumerate() {
                    let mut steps: Vec<(StepKind, Vec<StepFlow>)> = config
                        .steps
                        .iter()
                        .map(|&p| {
                            (
                                StepKind::Cir(p),
                                vec![flow(i, Color::Green, s.cir_mbps * p / 100.0, 0)],
                            )
                        })
                        .collect();
                    let green = flow(i, Color::Green, s.cir_mbps, 0);
                    if s.eir_mbps > 0.0 {
                        steps.push((
                            StepKind::Eir,
                            vec![green.clone(), flow(i, Color::Yellow, s.eir_mbps, 0)],
                        ));
                    }
                    let over = if s.eir_mbps > 0.0 {
                        s.eir_mbps * config.overshoot / 100.0
                    } else {
                        s.cir_mbps * (config.overshoot - 100.0) / 100.0
                    };
                    // Never more than the link carries.
                    let over = over.min(config.line_rate_mbps - s.cir_mbps);
                    if over > 0.0 {
                        steps.push((
                            StepKind::Policing,
                            vec![green.clone(), flow(i, Color::Yellow, over, 0)],
                        ));
                    }
                    if config.burst_tests && s.cbs > 0 {
                        steps.push((
                            StepKind::Cbs,
                            vec![flow(i, Color::Green, s.cir_mbps, s.cbs)],
                        ));
                    }
                    if config.burst_tests && s.ebs > 0 && s.eir_mbps > 0.0 {
                        steps.push((
                            StepKind::Ebs,
                            vec![green.clone(), flow(i, Color::Yellow, s.eir_mbps, s.ebs)],
                        ));
                    }
                    for (kind, flows) in steps {
                        if stopped() {
                            report.stopped = true;
                            break 'outer;
                        }
                        let step = Y1564Step {
                            test,
                            kind,
                            flows,
                            duration: config.step_duration,
                            interval: None,
                        };
                        let results = runner.run(&step)?;
                        let record = judge(config, &step, &results);
                        progress(&record);
                        report.configuration.push(record);
                    }
                }
            }
            Y1564Test::Performance => {
                if stopped() {
                    report.stopped = true;
                    break;
                }
                let step = Y1564Step {
                    test,
                    kind: StepKind::Performance,
                    flows: config
                        .services
                        .iter()
                        .enumerate()
                        .map(|(i, s)| flow(i, Color::Green, s.cir_mbps, 0))
                        .collect(),
                    duration: config.performance_duration,
                    interval: Some(config.interval),
                };
                let results = runner.run(&step)?;
                let record = judge(config, &step, &results);
                progress(&record);
                report.performance = Some(record);
                if stopped() {
                    // Stopped during the run: the measurement is partial.
                    report.stopped = true;
                }
            }
        }
    }
    report.services = config
        .services
        .iter()
        .map(|s| {
            let of = |steps: &mut dyn Iterator<Item = &StepRecord>| {
                let mut any = false;
                let mut ok = true;
                for st in steps {
                    for r in st.services.iter().filter(|r| r.service == s.name) {
                        any = true;
                        ok &= r.passed;
                    }
                }
                any.then_some(ok)
            };
            let configuration = of(&mut report.configuration.iter());
            let performance = of(&mut report.performance.iter());
            ServiceVerdict {
                service: s.name.clone(),
                configuration,
                performance,
                passed: configuration != Some(false) && performance != Some(false),
            }
        })
        .collect();
    let ran = !report.configuration.is_empty() || report.performance.is_some();
    report.passed = ran && !report.stopped && report.failed_steps() == 0;
    report.elapsed_s = start.elapsed().as_secs_f64();
    Ok(report)
}

fn pct(lost: u64, of: u64) -> f64 {
    if of == 0 {
        0.0
    } else {
        lost as f64 * 100.0 / of as f64
    }
}

fn fdv(l: &LatencyStats) -> Option<Duration> {
    Some(l.percentile(0.99)?.saturating_sub(l.min()?))
}

/// Puts a step's results against the acceptance criteria.
fn judge(config: &Y1564Config, step: &Y1564Step, results: &[FlowResult]) -> StepRecord {
    let flows: Vec<FlowRecord> = step
        .flows
        .iter()
        .zip(results)
        .map(|(f, r)| {
            let secs = r.elapsed.as_secs_f64();
            let lost = r.tx.saturating_sub(r.rx);
            let tx_mbps = config.mbps(r.tx, r.tx_bytes, secs);
            FlowRecord {
                service: config.services[f.service].name.clone(),
                color: f.color,
                offered_mbps: f.mbps,
                offered_pps: f.pps,
                burst: (f.burst > 1).then_some(f.burst),
                tx_mbps,
                ir_mbps: config.mbps(r.rx, r.rx_bytes, secs),
                tx: r.tx,
                rx: r.rx,
                lost,
                flr_pct: pct(lost, r.tx),
                duplicates: r.duplicates,
                out_of_order: r.out_of_order,
                ftd_ms: r.latency.mean().map(ms),
                fdv_ms: fdv(&r.latency).map(ms),
                latency: (&r.latency).into(),
                sender_limited: secs > 0.0 && (r.tx as f64) < f.pps * secs * 0.97,
            }
        })
        .collect();
    let mut services = Vec::new();
    for (i, s) in config.services.iter().enumerate() {
        let mine: Vec<usize> = (0..step.flows.len().min(results.len()))
            .filter(|&k| step.flows[k].service == i)
            .collect();
        if mine.is_empty() {
            continue;
        }
        let green = mine
            .iter()
            .find(|&&k| step.flows[k].color == Color::Green)
            .copied();
        let yellow = mine
            .iter()
            .find(|&&k| step.flows[k].color == Color::Yellow)
            .copied();
        let mut failures = Vec::new();
        let mut notes = Vec::new();
        let ir_mbps: f64 = mine.iter().map(|&k| flows[k].ir_mbps).sum();
        let (mut flr_pct, mut ftd_ms, mut fdv_ms) = (0.0, None, None);
        let green_judged =
            s.color_aware || !matches!(step.kind, StepKind::Policing | StepKind::Ebs);
        if let Some(g) = green.filter(|_| !green_judged) {
            let fr = &flows[g];
            flr_pct = fr.flr_pct;
            ftd_ms = fr.ftd_ms;
            fdv_ms = fr.fdv_ms;
            notes.push("color blind: green frames may be dropped above the CIR, not judged".into());
        }
        if let Some(g) = green.filter(|_| green_judged) {
            let (fr, r) = (&flows[g], &results[g]);
            flr_pct = fr.flr_pct;
            ftd_ms = fr.ftd_ms;
            fdv_ms = fr.fdv_ms;
            if r.tx == 0 {
                failures.push("no green frames were sent".to_string());
            } else if flr_pct > s.sac.flr {
                failures.push(format!("FLR {} > {}%", fmt_pct(flr_pct), s.sac.flr));
            }
            if let Some(max) = s.sac.ftd {
                match r.latency.mean() {
                    Some(d) if d > max => {
                        failures.push(format!("FTD {:.3} ms > {:.3} ms", ms(d), ms(max)))
                    }
                    None if r.tx > 0 => failures.push("no FTD: nothing arrived".into()),
                    _ => {}
                }
            }
            if let Some(max) = s.sac.fdv {
                match fdv(&r.latency) {
                    Some(d) if d > max => {
                        failures.push(format!("FDV {:.3} ms > {:.3} ms", ms(d), ms(max)))
                    }
                    None if r.tx > 0 => failures.push("no FDV: nothing arrived".into()),
                    _ => {}
                }
            }
        }
        let tol = config.ir_tolerance / 100.0;
        let max_ir = (s.cir_mbps + s.eir_mbps) * (1.0 + tol);
        match step.kind {
            StepKind::Eir => {
                let min_ir = s.cir_mbps * (1.0 - tol);
                if ir_mbps < min_ir {
                    failures.push(format!(
                        "IR {ir_mbps:.3} Mbit/s < CIR {} Mbit/s",
                        s.cir_mbps
                    ));
                }
                if ir_mbps > max_ir {
                    failures.push(format!(
                        "IR {ir_mbps:.3} Mbit/s > CIR+EIR {} Mbit/s",
                        s.cir_mbps + s.eir_mbps
                    ));
                }
            }
            StepKind::Policing => {
                if ir_mbps > max_ir {
                    failures.push(format!(
                        "IR {ir_mbps:.3} Mbit/s > CIR+EIR {} Mbit/s: not policed",
                        s.cir_mbps + s.eir_mbps
                    ));
                }
                let min_ir = s.cir_mbps * (1.0 - tol);
                if ir_mbps < min_ir {
                    failures.push(format!(
                        "IR {ir_mbps:.3} Mbit/s < CIR {} Mbit/s: policed too hard",
                        s.cir_mbps
                    ));
                }
            }
            StepKind::Ebs if !green_judged && ir_mbps < s.cir_mbps * (1.0 - tol) => {
                failures.push(format!(
                    "IR {ir_mbps:.3} Mbit/s < CIR {} Mbit/s",
                    s.cir_mbps
                ));
            }
            _ => {}
        }
        let (mut availability_pct, mut ses, mut intervals) = (None, None, Vec::new());
        if let (Some(g), Some(len)) = (green, step.interval) {
            intervals = interval_records(config, &results[g], len);
            if !intervals.is_empty() {
                let up = intervals.iter().filter(|i| i.available).count();
                availability_pct = Some(up as f64 * 100.0 / intervals.len() as f64);
                ses = Some(intervals.iter().filter(|i| i.ses).count() as u64);
            }
            if let Some(min) = s.sac.availability {
                match availability_pct {
                    Some(a) if a < min => failures.push(format!("availability {a:.3}% < {min}%")),
                    None => notes.push("no whole interval to judge availability by".into()),
                    _ => {}
                }
            }
        }
        for &k in &mine {
            if flows[k].sender_limited {
                notes.push(format!(
                    "{} frames sent at {:.3} of {:.3} Mbit/s offered: the sender fell short",
                    flows[k].color.name(),
                    flows[k].tx_mbps,
                    flows[k].offered_mbps
                ));
            }
        }
        services.push(ServiceResult {
            service: s.name.clone(),
            flr_pct,
            ftd_ms,
            fdv_ms,
            ir_mbps,
            yellow_flr_pct: yellow.map(|k| flows[k].flr_pct),
            availability_pct,
            ses,
            intervals,
            green_judged,
            passed: failures.is_empty(),
            failures,
            notes,
        });
    }
    StepRecord {
        test: step.test,
        step: step.kind,
        name: step.kind.to_string(),
        duration_s: results
            .iter()
            .map(|r| r.elapsed.as_secs_f64())
            .fold(0.0, f64::max),
        passed: services.iter().all(|s| s.passed),
        flows,
        services,
    }
}

fn fmt_pct(v: f64) -> String {
    if v == 0.0 || v >= 0.1 {
        format!("{v:.2}%")
    } else {
        format!("{v:.4}%")
    }
}

/// Loss and delay per whole interval of sending, and availability.
///
/// Frames sent in an interval are taken as the flow's mean send rate times
/// the interval: the sender keeps an even pace, so this is within a frame or
/// two of the truth, and needs no counting on the sending side.
fn interval_records(config: &Y1564Config, r: &FlowResult, len: Duration) -> Vec<IntervalRecord> {
    let secs = r.elapsed.as_secs_f64();
    let ns = len.as_nanos();
    if secs <= 0.0 || ns == 0 || r.tx == 0 {
        return Vec::new();
    }
    let per_interval = r.tx as f64 / secs * len.as_secs_f64();
    let start = r.start.as_nanos();
    let end = start + r.elapsed.as_nanos();
    let first = start.div_ceil(ns);
    let last = end / ns; // intervals [k*ns, (k+1)*ns) with k < last
    let mut out: Vec<IntervalRecord> = (first..last)
        .map(|k| {
            let got = u64::try_from(k)
                .ok()
                .and_then(|k| r.intervals.get(&k))
                .cloned()
                .unwrap_or_default();
            let lost = (per_interval - got.packets as f64).max(0.0);
            let flr_pct = lost * 100.0 / per_interval;
            IntervalRecord {
                start_s: (k * ns - start) as f64 / 1e9,
                rx: got.packets,
                flr_pct,
                ftd_ms: got.mean().map(ms),
                max_ftd_ms: got.max().map(ms),
                ses: flr_pct > config.ses_flr,
                available: true,
            }
        })
        .collect();
    mark_availability(&mut out, config.unavailable_after as usize);
    out
}

/// Y.1563 availability: `n` severely errored intervals in a row start
/// unavailable time at the first of them; `n` good ones in a row end it at
/// the first of those.
fn mark_availability(intervals: &mut [IntervalRecord], n: usize) {
    let mut unavailable = false;
    let mut run = 0;
    for i in 0..intervals.len() {
        let ses = intervals[i].ses;
        if unavailable {
            intervals[i].available = false;
            if ses {
                run = 0;
            } else {
                run += 1;
                if run == n {
                    for iv in &mut intervals[i + 1 - n..=i] {
                        iv.available = true;
                    }
                    unavailable = false;
                    run = 0;
                }
            }
        } else if ses {
            run += 1;
            if run == n {
                for iv in &mut intervals[i + 1 - n..=i] {
                    iv.available = false;
                }
                unavailable = true;
                run = 0;
            }
        } else {
            run = 0;
        }
    }
}

#[cfg(test)]
mod tests;
