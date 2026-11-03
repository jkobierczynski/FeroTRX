//! [`JobTrialRunner`]: trials sent with a [`Job`] and counted by a receiver.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{Trial, TrialResult, TrialRunner};
use crate::{
    signed_len, Capture, CaptureSource, Error, FieldEngine, FieldVar, Job, PacketReceiver,
    PacketSink, Rate, Result, RunConfig, RxSettings, SinkError, Stream,
};

type OpenSink = Box<dyn FnMut() -> std::result::Result<Box<dyn PacketSink + Send>, SinkError>>;
type OpenReceiver = Box<dyn FnMut() -> std::result::Result<Box<dyn PacketReceiver>, SinkError>>;

/// Runs benchmark trials for real: each trial is a [`Job`] that sends the
/// given packets, cut or padded to the trial's frame size, at the trial's
/// rate, with a latency signature in every frame, while a receiver counts
/// what arrives.
///
/// The sink and the receiver are opened afresh for every trial, through the
/// two functions given, so nothing of one trial is counted in the next; each
/// trial also uses its own flow id.
///
/// ```
/// use ferotrx_core::*;
/// use std::sync::{Arc, Mutex};
/// use std::time::Duration;
///
/// // A wire in memory: what is sent comes straight back.
/// let (tx, rx) = memory_ports();
/// let (tx, rx) = (Arc::new(Mutex::new(Some(tx))), Arc::new(Mutex::new(Some(rx))));
/// let cap = Capture::from_specs(&["eth/ipv4(dst=10.0.0.2)/udp(dport=7)"], Duration::ZERO).unwrap();
/// let mut runner = JobTrialRunner::new(
///     Arc::new(cap),
///     Box::new(move || Ok(Box::new(tx.lock().unwrap().take().unwrap()) as Box<dyn PacketSink + Send>)),
///     Box::new(move || Ok(Box::new(PortReceiver(rx.lock().unwrap().take().unwrap())) as Box<dyn PacketReceiver>)),
/// );
/// runner.rx_wait = Duration::from_millis(50);
/// let trial = Trial {
///     test: BenchTest::Throughput,
///     size: SizeMix::fixed(200).unwrap(),
///     frame_len: 200.0,
///     load: 1.0,
///     pps: 2000.0,
///     duration: Some(Duration::from_millis(100)),
///     packets: None,
///     warmup: false,
/// };
/// let r = runner.run(&trial).unwrap();
/// assert!(r.tx > 150 && r.rx == r.tx, "{r:?}");
/// assert_eq!(r.tx_bytes, r.tx * 200);
/// ```
pub struct JobTrialRunner {
    capture: Arc<Capture>,
    vary: Vec<FieldVar>,
    open_sink: OpenSink,
    open_receiver: OpenReceiver,
    /// How long to keep receiving after the last frame of a trial.
    pub rx_wait: Duration,
    stop: Option<Arc<AtomicBool>>,
    next_flow: u32,
}

impl JobTrialRunner {
    /// Trials send the packets of `capture` (Ethernet frames) round and round.
    pub fn new(capture: Arc<Capture>, open_sink: OpenSink, open_receiver: OpenReceiver) -> Self {
        Self {
            capture,
            vary: Vec::new(),
            open_sink,
            open_receiver,
            rx_wait: RxSettings::DEFAULT_WAIT,
            stop: None,
            next_flow: 1,
        }
    }

    /// Changes fields from packet to packet (see [`FieldVar`]), before the
    /// frame size is set.
    pub fn with_vary(mut self, vary: Vec<FieldVar>) -> Self {
        self.vary = vary;
        self
    }

    /// A trial that is running stops early when `stop` is set.
    pub fn with_stop(mut self, stop: Arc<AtomicBool>) -> Self {
        self.stop = Some(stop);
        self
    }
}

impl TrialRunner for JobTrialRunner {
    fn sent_len(&self, size: usize) -> usize {
        self.capture
            .packets
            .iter()
            .map(|p| signed_len(&p.data, size))
            .max()
            .unwrap_or(size)
    }

    fn run(&mut self, trial: &Trial) -> Result<TrialResult> {
        let flow = self.next_flow;
        self.next_flow = self.next_flow.checked_add(1).unwrap_or(1);
        let mut size = trial.size.clone();
        size.reset();
        let mut stream = Stream::new("bench", CaptureSource::new(self.capture.clone()).loops(0))
            .with_rate(Rate::Pps(trial.pps))
            .with_limit(trial.packets)
            .with_latency(flow)
            .keep_size(true);
        if !self.vary.is_empty() {
            stream.push_transform(FieldEngine::new(self.vary.iter().cloned()));
        }
        stream.push_transform(size);
        let failed =
            |what: &str, e: SinkError| Error::Bench(format!("cannot open the {what}: {e}"));
        let sink = (self.open_sink)().map_err(|e| failed("output", e))?;
        let rx = if trial.warmup {
            None
        } else {
            let receiver = (self.open_receiver)().map_err(|e| failed("receiver", e))?;
            Some(RxSettings {
                receiver,
                wait: self.rx_wait,
            })
        };
        // The job gets a stop flag of its own: dropping a job sets its flag,
        // which must not stop the whole benchmark.
        let config = RunConfig {
            duration: trial.duration,
            ..Default::default()
        };
        let job = Job::spawn_with_rx(vec![stream], sink, config, rx)?;
        while !job.wait(Some(Duration::from_millis(50))) {
            if self
                .stop
                .as_ref()
                .is_some_and(|s| s.load(Ordering::Relaxed))
            {
                job.stop();
            }
        }
        let report = job.flow_reports().into_iter().next();
        let stats = job.join()?;
        let st = &stats.streams[0];
        let mut result = TrialResult {
            tx: st.tagged,
            tx_bytes: st.bytes,
            elapsed: st.elapsed,
            ..Default::default()
        };
        if let Some(r) = report {
            result.rx = r.rx;
            result.rx_bytes = r.rx_bytes;
            result.duplicates = r.duplicates;
            result.out_of_order = r.out_of_order;
            result.latency = r.latency;
        }
        Ok(result)
    }
}
