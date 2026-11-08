//! [`JobServiceRunner`]: steps sent with a [`Job`] and counted by an [`RxJob`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{Color, FlowResult, ServiceRunner, Y1564Step};
use crate::{
    signed_len, wall_clock, Capture, CaptureSource, Error, FieldEngine, FieldVar, FlowReport, Job,
    PacketReceiver, PacketSink, Rate, Result, RunConfig, RxConfig, RxJob, RxSettings, SinkError,
    Stream, TrafficModel,
};

/// How far a flow may fall behind its schedule before frames are left out
/// instead of sent late. After a stall (a paused VM, a busy CPU), catching up
/// would send the missed frames back to back: a burst a policer rightly
/// drops, which would count against the network. Left out, they show as
/// "the sender fell short" instead. 5 ms is about the CBS of a 10 Mbit/s
/// service of 6000 bytes.
pub const MAX_LAG: Duration = Duration::from_millis(5);

type OpenSink = Box<dyn FnMut() -> std::result::Result<Box<dyn PacketSink + Send>, SinkError>>;
type OpenReceiver = Box<dyn FnMut() -> std::result::Result<Box<dyn PacketReceiver>, SinkError>>;

/// The frames of one service (Ethernet frames, sent in turn; their payload is
/// cut or padded to each size).
#[derive(Clone, Debug)]
pub struct ServiceFrames {
    pub green: Arc<Capture>,
    /// Yellow frames: marked apart for a color-aware network, or the same.
    pub yellow: Arc<Capture>,
    pub vary: Vec<FieldVar>,
}

/// Runs Y.1564 steps for real: each step is a [`Job`] with one stream per
/// flow, each with its own latency flow id, while an [`RxJob`] counts what
/// arrives, per interval of send time when the step asks for it.
///
/// ```
/// use ferotrx_core::*;
/// use std::sync::{Arc, Mutex};
/// use std::time::Duration;
///
/// let (tx, rx) = memory_ports();
/// let (tx, rx) = (Arc::new(Mutex::new(Some(tx))), Arc::new(Mutex::new(Some(rx))));
/// let cap = Arc::new(Capture::from_specs(&["eth/ipv4(dst=10.0.0.2)/udp(dport=7)"], Duration::ZERO).unwrap());
/// let frames = ServiceFrames { green: cap.clone(), yellow: cap, vary: Vec::new() };
/// let mut runner = JobServiceRunner::new(
///     vec![frames],
///     Box::new(move || Ok(Box::new(tx.lock().unwrap().take().unwrap()) as Box<dyn PacketSink + Send>)),
///     Box::new(move || Ok(Box::new(PortReceiver(rx.lock().unwrap().take().unwrap())) as Box<dyn PacketReceiver>)),
/// );
/// runner.rx_wait = Duration::from_millis(50);
/// let step = Y1564Step {
///     test: Y1564Test::Configuration,
///     kind: StepKind::Cir(100.0),
///     flows: vec![StepFlow {
///         service: 0,
///         color: Color::Green,
///         size: SizeMix::fixed(200).unwrap(),
///         frame_len: 200.0,
///         mbps: 3.2,
///         pps: 2000.0,
///         burst: 0,
///     }],
///     duration: Duration::from_millis(100),
///     interval: None,
/// };
/// let r = &runner.run(&step).unwrap()[0];
/// assert!(r.tx > 150 && r.rx == r.tx, "{r:?}");
/// ```
pub struct JobServiceRunner {
    services: Vec<ServiceFrames>,
    open_sink: OpenSink,
    open_receiver: OpenReceiver,
    /// How long to keep receiving after the last frame of a step.
    pub rx_wait: Duration,
    stop: Option<Arc<AtomicBool>>,
    next_flow: u32,
    workers: usize,
    pinning: Option<crate::CpuPinning>,
}

impl JobServiceRunner {
    pub fn new(
        services: Vec<ServiceFrames>,
        open_sink: OpenSink,
        open_receiver: OpenReceiver,
    ) -> Self {
        Self {
            services,
            open_sink,
            open_receiver,
            rx_wait: RxSettings::DEFAULT_WAIT,
            stop: None,
            next_flow: 1,
            workers: 1,
            pinning: None,
        }
    }

    /// Sends each step from `workers` threads, each with its share of every
    /// flow's rate.
    pub fn with_workers(mut self, workers: usize) -> Self {
        self.workers = workers.max(1);
        self
    }

    /// Pins the workers to CPUs (see [`crate::CpuPinning`]).
    pub fn with_pinning(mut self, pinning: Option<crate::CpuPinning>) -> Self {
        self.pinning = pinning;
        self
    }

    /// A step that is running stops early when `stop` is set.
    pub fn with_stop(mut self, stop: Arc<AtomicBool>) -> Self {
        self.stop = Some(stop);
        self
    }
}

impl ServiceRunner for JobServiceRunner {
    fn sent_len(&self, service: usize, size: usize) -> usize {
        let Some(s) = self.services.get(service) else {
            return size;
        };
        s.green
            .packets
            .iter()
            .chain(&s.yellow.packets)
            .map(|p| signed_len(&p.data, size))
            .max()
            .unwrap_or(size)
    }

    fn run(&mut self, step: &Y1564Step) -> Result<Vec<FlowResult>> {
        let failed =
            |what: &str, e: SinkError| Error::Bench(format!("cannot open the {what}: {e}"));
        let mut flows = Vec::with_capacity(step.flows.len());
        for _ in &step.flows {
            flows.push(self.next_flow);
            self.next_flow = self.next_flow.checked_add(1).unwrap_or(1);
        }
        let mut workers = Vec::with_capacity(self.workers);
        for k in 0..self.workers {
            let mut streams = Vec::with_capacity(step.flows.len());
            for (f, &flow) in step.flows.iter().zip(&flows) {
                let frames = self
                    .services
                    .get(f.service)
                    .ok_or_else(|| Error::Bench(format!("no frames for service {}", f.service)))?;
                let capture = match f.color {
                    Color::Green => frames.green.clone(),
                    Color::Yellow => frames.yellow.clone(),
                };
                let mut size = f.size.clone();
                size.reset();
                let mut stream = Stream::new(
                    format!("{}/{}", f.service, f.color.name()),
                    CaptureSource::new(capture).loops(0),
                )
                .with_rate(Rate::Pps(f.pps))
                .with_latency(flow)
                .keep_size(true)
                .with_max_lag(MAX_LAG);
                if f.burst > 1 {
                    stream = stream.with_model(TrafficModel::default().with_burst(f.burst));
                }
                if !frames.vary.is_empty() {
                    stream.push_transform(FieldEngine::new(frames.vary.iter().cloned()));
                }
                stream.push_transform(size);
                streams.push(stream.shard(k, self.workers));
            }
            let sink = (self.open_sink)().map_err(|e| failed("output", e))?;
            workers.push((streams, sink));
        }
        let receiver = (self.open_receiver)().map_err(|e| failed("receiver", e))?;
        let rx = RxJob::spawn(
            receiver,
            RxConfig {
                interval: step.interval,
                ..Default::default()
            },
        )?;
        let config = RunConfig {
            duration: Some(step.duration),
            pinning: self.pinning.clone(),
            ..Default::default()
        };
        let start = wall_clock();
        let job = Job::spawn_workers(workers, config, None)?;
        while !job.wait(Some(Duration::from_millis(50))) {
            if self
                .stop
                .as_ref()
                .is_some_and(|s| s.load(Ordering::Relaxed))
            {
                job.stop();
            }
        }
        let names = job.stream_names().to_vec();
        let ids = job.flows().to_vec();
        let stats = job.join();
        // Frames still on their way get `rx_wait` to arrive.
        rx.wait(Some(self.rx_wait));
        rx.stop();
        let rx_stats = rx.join()?;
        let stats = stats?;
        let reports = FlowReport::for_run(&names, &ids, &stats, &rx_stats);
        Ok(stats
            .streams
            .iter()
            .zip(&flows)
            .map(|(st, flow)| {
                let report = reports.iter().find(|r| r.flow == *flow);
                let got = rx_stats.flow(*flow);
                FlowResult {
                    tx: st.tagged,
                    tx_bytes: st.bytes,
                    rx: report.map_or(0, |r| r.rx),
                    rx_bytes: got.map_or(0, |f| {
                        // Bytes of frames received once.
                        f.bytes.checked_div(f.packets).unwrap_or(0) * f.unique()
                    }),
                    duplicates: report.map_or(0, |r| r.duplicates),
                    out_of_order: report.map_or(0, |r| r.out_of_order),
                    start,
                    elapsed: st.elapsed,
                    latency: report.map(|r| r.latency.clone()).unwrap_or_default(),
                    intervals: got.map(|f| f.intervals.clone()).unwrap_or_default(),
                }
            })
            .collect())
    }
}
