//! Benchmarks on the server, for `bench.*`: RFC 2544 tests as `ferotrx
//! bench` runs them, on a thread of their own, with every trial reported
//! as it ends.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use ferotrx_core::{
    run_benchmark, BenchProfile, JobTrialRunner, PacketReceiver, PacketSink, RunInfo, SendSettings,
    SinkError,
};

use crate::protocol::{BenchRunInfo, BenchTrialInfo, RunState};

/// Opens the sending interface of a benchmark: its name, how to send, the
/// link type and the number of workers; one sink per worker, and a line on
/// how they send.
pub type BenchSinkOpener = dyn Fn(
        &str,
        &SendSettings,
        u32,
        usize,
    ) -> Result<(Vec<Box<dyn PacketSink + Send>>, String), SinkError>
    + Send
    + Sync;

/// The default: libpcap/Npcap, or the backend the settings name.
pub fn open_bench_sinks(
    name: &str,
    send: &SendSettings,
    linktype: u32,
    workers: usize,
) -> Result<(Vec<Box<dyn PacketSink + Send>>, String), SinkError> {
    let opened = ferotrx_io::Output::Interface {
        name: name.to_string(),
        send: send.clone(),
    }
    .open_workers(linktype, workers)?;
    let mut details: Vec<String> = Vec::new();
    let mut sinks = Vec::new();
    for o in opened {
        if !details.contains(&o.detail) {
            details.push(o.detail);
        }
        sinks.push(o.sink);
    }
    Ok((sinks, details.join("; ")))
}

/// A sink shared by the trials: opened once, as DPDK and AF_XDP want.
pub(crate) struct SharedSink(pub(crate) Arc<Mutex<Box<dyn PacketSink + Send>>>);

impl PacketSink for SharedSink {
    fn send(&mut self, data: &[u8]) -> Result<(), SinkError> {
        lock(&self.0).send(data)
    }
    fn flush(&mut self) -> Result<(), SinkError> {
        lock(&self.0).flush()
    }
    fn idle(&mut self) -> Result<(), SinkError> {
        lock(&self.0).idle()
    }
}

/// A receiver shared by the trials, so nothing arrives while one is reopened.
pub(crate) struct SharedReceiver(pub(crate) Arc<Mutex<Box<dyn PacketReceiver>>>);

impl PacketReceiver for SharedReceiver {
    fn recv(&mut self, buf: &mut Vec<u8>) -> Result<Option<Duration>, SinkError> {
        lock(&self.0).recv(buf)
    }
}

/// Everything a benchmark run needs, ready to go.
pub(crate) struct BenchJob {
    pub profile: BenchProfile,
    pub profile_name: String,
    pub profile_text: String,
    pub iface: String,
    pub rx: String,
    pub send: SendSettings,
}

/// A benchmark running on a thread of its own.
pub(crate) struct BenchRun {
    info: Mutex<BenchRunInfo>,
    stop: Arc<AtomicBool>,
    started: Instant,
    ended: (Mutex<bool>, Condvar),
}

impl BenchRun {
    /// Opens the interfaces (an error here fails `bench.start`) and starts
    /// the trials.
    pub fn spawn(
        id: u64,
        mut job: BenchJob,
        open_sinks: &BenchSinkOpener,
        open_receiver: &crate::controller::ReceiverOpener,
    ) -> Result<Arc<Self>, String> {
        let mut capture = job.profile.capture().map_err(|e| e.to_string())?;
        // The port's own addresses: the gateway's MAC put in the frames once,
        // the port answered for until the benchmark ends.
        let output = ferotrx_io::Output::Interface {
            name: job.iface.clone(),
            send: job.send.clone(),
        };
        let link =
            crate::controller::start_link(&output, &job.profile.link).map_err(|e| e.to_string())?;
        if let Some(svc) = &link {
            let mut macs = svc.macs();
            for p in &mut capture.packets {
                ferotrx_core::Transform::apply(&mut macs, p);
            }
        }
        let capture = Arc::new(capture);
        let workers = job.send.workers();
        let (sinks, detail) = open_sinks(&job.iface, &job.send, capture.linktype, workers)
            .map_err(|e| format!("cannot send on {}: {e}", job.iface))?;
        if sinks.is_empty() {
            return Err(format!("cannot send on {}: no sink", job.iface));
        }
        let receiver =
            open_receiver(&job.rx).map_err(|e| format!("cannot receive on {}: {e}", job.rx))?;

        let mut info = RunInfo::new();
        ferotrx_io::describe_host(&mut info);
        info.command = Some("bench.start".into());
        info.profile = Some(job.profile_name.clone());
        info.profile_text = Some(job.profile_text.clone());
        info.backend = Some(match &link {
            Some(svc) => format!("{detail}; port {}", svc.detail()),
            None => detail,
        });
        info.tx_interface = Some(ferotrx_io::describe_interface(&job.iface));
        info.rx_interface = Some(ferotrx_io::describe_interface(&job.rx));
        info.timestamps = Some(
            "send: system clock just before each frame is handed to the sender; \
             receive: the capture driver's timestamp (libpcap/Npcap, software)"
                .into(),
        );

        let stop = Arc::new(AtomicBool::new(false));
        job.profile.config.stop = Some(stop.clone());
        let c = &job.profile.config;
        let run = Arc::new(BenchRun {
            info: Mutex::new(BenchRunInfo {
                id,
                profile: job.profile_name.clone(),
                iface: job.iface.clone(),
                rx: job.rx.clone(),
                state: RunState::Running,
                error: None,
                elapsed_s: 0.0,
                tests: c.tests.iter().map(|t| t.name().to_string()).collect(),
                sizes: c.sizes.iter().map(ToString::to_string).collect(),
                trials: Vec::new(),
                info: Some(info),
                report: None,
                text: None,
            }),
            stop: stop.clone(),
            started: Instant::now(),
            ended: (Mutex::new(false), Condvar::new()),
        });

        let sinks: Vec<_> = sinks.into_iter().map(|s| Arc::new(Mutex::new(s))).collect();
        let mut next = 0;
        let receiver: Arc<Mutex<Box<dyn PacketReceiver>>> = Arc::new(Mutex::new(receiver));
        let vary = job.profile.vary.clone();
        let rx_wait = job.profile.rx_wait;
        // The runner's openers are not Send: build it on the run's thread.
        let make_runner = move || {
            let mut runner = JobTrialRunner::new(
                capture,
                Box::new(move || {
                    let sink = sinks[next % sinks.len()].clone();
                    next += 1;
                    Ok(Box::new(SharedSink(sink)) as Box<dyn PacketSink + Send>)
                }),
                Box::new(move || {
                    Ok(Box::new(SharedReceiver(receiver.clone())) as Box<dyn PacketReceiver>)
                }),
            )
            .with_vary(vary)
            .with_stop(stop)
            .with_workers(workers);
            runner.rx_wait = rx_wait;
            runner
        };

        let r = run.clone();
        std::thread::Builder::new()
            .name(format!("bench-{id}"))
            .spawn(move || {
                r.main(job.profile, make_runner());
                drop(link);
            })
            .map_err(|e| format!("cannot start the benchmark: {e}"))?;
        Ok(run)
    }

    fn main(self: Arc<Self>, profile: BenchProfile, mut runner: JobTrialRunner) {
        let me = self.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_benchmark(&profile.config, &mut runner, |size, t| {
                lock(&me.info).trials.push(BenchTrialInfo {
                    size: size.size.clone(),
                    trial: t.clone(),
                });
            })
        }));
        {
            let mut info = lock(&self.info);
            info.elapsed_s = self.started.elapsed().as_secs_f64();
            match result {
                Ok(Ok(report)) => {
                    info.state = if report.stopped {
                        RunState::Stopped
                    } else {
                        RunState::Finished
                    };
                    let mut text = info
                        .info
                        .as_ref()
                        .map(|i| i.lines().join("\n"))
                        .unwrap_or_default();
                    text.push_str("\n\n");
                    text.push_str(&report.text());
                    info.text = Some(text);
                    info.report = Some(report);
                }
                Ok(Err(e)) => {
                    info.state = RunState::Failed;
                    info.error = Some(e.to_string());
                }
                Err(e) => {
                    info.state = RunState::Failed;
                    info.error = Some(
                        e.downcast_ref::<String>()
                            .cloned()
                            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                            .unwrap_or_else(|| "the benchmark panicked".into()),
                    );
                }
            }
        }
        *lock(&self.ended.0) = true;
        self.ended.1.notify_all();
    }

    pub fn info(&self) -> BenchRunInfo {
        let mut info = lock(&self.info).clone();
        if info.state.is_running() {
            info.elapsed_s = self.started.elapsed().as_secs_f64();
        }
        info
    }

    pub fn is_running(&self) -> bool {
        !*lock(&self.ended.0)
    }

    /// Asks the run to stop after the trial under way; the report is partial.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Waits up to `timeout` for the run to end; true if it has.
    pub fn wait(&self, timeout: Duration) -> bool {
        let ended = lock(&self.ended.0);
        let (ended, _) = self
            .ended
            .1
            .wait_timeout_while(ended, timeout, |e| !*e)
            .unwrap_or_else(|e| e.into_inner());
        *ended
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
