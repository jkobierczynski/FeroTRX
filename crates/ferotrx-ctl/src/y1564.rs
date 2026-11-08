//! Y.1564 tests on the server, for `y1564.*`: service activation tests as
//! `ferotrx y1564` runs them, on a thread of their own, with every step
//! reported as it ends.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use ferotrx_core::{
    run_y1564, JobServiceRunner, PacketReceiver, PacketSink, RunInfo, SendSettings, Y1564Profile,
    LINKTYPE_ETHERNET,
};

use crate::bench::{BenchSinkOpener, SharedReceiver, SharedSink};
use crate::protocol::{RunState, Y1564RunInfo};

/// A [`JobServiceRunner`] for `profile` that sends through `sinks` (opened
/// once, taken in turn by the workers) and receives with `receiver`.
pub(crate) fn service_runner(
    profile: &Y1564Profile,
    sinks: Vec<Box<dyn PacketSink + Send>>,
    receiver: Box<dyn PacketReceiver>,
    stop: Arc<AtomicBool>,
) -> JobServiceRunner {
    let workers = sinks.len().max(1);
    let sinks: Vec<_> = sinks.into_iter().map(|s| Arc::new(Mutex::new(s))).collect();
    let receiver: Arc<Mutex<Box<dyn PacketReceiver>>> = Arc::new(Mutex::new(receiver));
    let mut next = 0;
    let mut runner = JobServiceRunner::new(
        profile.frames.clone(),
        Box::new(move || {
            let sink = sinks[next % sinks.len()].clone();
            next += 1;
            Ok(Box::new(SharedSink(sink)) as Box<dyn PacketSink + Send>)
        }),
        Box::new(move || Ok(Box::new(SharedReceiver(receiver.clone())) as Box<dyn PacketReceiver>)),
    )
    .with_stop(stop)
    .with_workers(workers);
    runner.rx_wait = profile.rx_wait;
    runner
}

/// Everything a Y.1564 run needs, ready to go.
pub(crate) struct Y1564Job {
    pub profile: Y1564Profile,
    pub profile_name: String,
    pub profile_text: String,
    pub iface: String,
    pub rx: String,
    pub send: SendSettings,
}

/// A Y.1564 test running on a thread of its own.
pub(crate) struct Y1564Run {
    info: Mutex<Y1564RunInfo>,
    stop: Arc<AtomicBool>,
    started: Instant,
    ended: (Mutex<bool>, Condvar),
}

impl Y1564Run {
    /// Opens the interfaces (an error here fails `y1564.start`) and starts
    /// the steps.
    pub fn spawn(
        id: u64,
        mut job: Y1564Job,
        open_sinks: &BenchSinkOpener,
        open_receiver: &crate::controller::ReceiverOpener,
    ) -> Result<Arc<Self>, String> {
        let workers = job.send.workers();
        let (sinks, detail) = open_sinks(&job.iface, &job.send, LINKTYPE_ETHERNET, workers)
            .map_err(|e| format!("cannot send on {}: {e}", job.iface))?;
        if sinks.is_empty() {
            return Err(format!("cannot send on {}: no sink", job.iface));
        }
        let receiver =
            open_receiver(&job.rx).map_err(|e| format!("cannot receive on {}: {e}", job.rx))?;

        let mut info = RunInfo::new();
        ferotrx_io::describe_host(&mut info);
        info.command = Some("y1564.start".into());
        info.set_profile(job.profile_name.clone(), Some(job.profile_text.clone()));
        info.backend = Some(detail);
        info.workers = Some(workers);
        let pinning = crate::controller::pinning(job.send.cpus.as_ref());
        info.pinned_cpus = pinning
            .as_ref()
            .map(|p| p.cpus.used_by(workers).to_string());
        info.tx_interface = Some(ferotrx_io::describe_interface(&job.iface));
        info.rx_interface = Some(ferotrx_io::describe_interface(&job.rx));

        let stop = Arc::new(AtomicBool::new(false));
        job.profile.config.stop = Some(stop.clone());
        let c = &job.profile.config;
        let run = Arc::new(Y1564Run {
            info: Mutex::new(Y1564RunInfo {
                id,
                profile: job.profile_name.clone(),
                iface: job.iface.clone(),
                rx: job.rx.clone(),
                state: RunState::Running,
                error: None,
                elapsed_s: 0.0,
                tests: c.tests.iter().map(|t| t.name().to_string()).collect(),
                services: c.services.iter().map(|s| s.name.clone()).collect(),
                steps: Vec::new(),
                info: Some(info),
                report: None,
                text: None,
            }),
            stop: stop.clone(),
            started: Instant::now(),
            ended: (Mutex::new(false), Condvar::new()),
        });
        let mut sinks = Some(sinks);
        let mut receiver = Some(receiver);
        let r = run.clone();
        std::thread::Builder::new()
            .name(format!("y1564-{id}"))
            .spawn(move || {
                // The runner's openers are not Send: build it here.
                let runner = service_runner(
                    &job.profile,
                    sinks.take().unwrap_or_default(),
                    receiver.take().expect("a receiver"),
                    stop,
                )
                .with_pinning(pinning);
                r.main(job.profile, runner)
            })
            .map_err(|e| format!("cannot start the Y.1564 test: {e}"))?;
        Ok(run)
    }

    fn main(self: Arc<Self>, profile: Y1564Profile, mut runner: JobServiceRunner) {
        let me = self.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_y1564(&profile.config, &mut runner, |step| {
                lock(&me.info).steps.push(step.clone());
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
                            .unwrap_or_else(|| "the Y.1564 test panicked".into()),
                    );
                }
            }
        }
        *lock(&self.ended.0) = true;
        self.ended.1.notify_all();
    }

    pub fn info(&self) -> Y1564RunInfo {
        let mut info = lock(&self.info).clone();
        if info.state.is_running() {
            info.elapsed_s = self.started.elapsed().as_secs_f64();
        }
        info
    }

    pub fn is_running(&self) -> bool {
        !*lock(&self.ended.0)
    }

    /// Asks the run to stop; a step under way ends early, and the report is
    /// partial.
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
