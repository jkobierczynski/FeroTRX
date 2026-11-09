//! A profile gives the same packets whatever the number of workers, and
//! from run to run: the same count, the same field values and the same
//! latency sequence numbers. Only the send time in the signature (and the
//! word that keeps its checksum neutral) differs.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferotrx_core::*;

/// Collects what every worker sends, from any thread.
#[derive(Clone, Default)]
struct Collect(Arc<Mutex<Vec<Vec<u8>>>>);

impl PacketSink for Collect {
    fn send(&mut self, data: &[u8]) -> std::result::Result<(), SinkError> {
        self.0.lock().unwrap().push(data.to_vec());
        Ok(())
    }
}

const PACKETS: u64 = 3000;
const FLOW: u32 = 11;

fn capture() -> Arc<Capture> {
    Arc::new(
        Capture::from_specs(
            &[
                "eth(src=02:00:00:00:00:01,dst=02:00:00:00:00:02)/ipv4(src=10.0.0.1,dst=10.0.0.2)/udp(sport=1,dport=53)/raw(len=40)",
                "eth(src=02:00:00:00:00:01,dst=02:00:00:00:00:02)/ipv4(src=10.0.0.1,dst=10.0.0.3)/tcp(sport=2,dport=80)/raw(len=100)",
            ],
            Duration::ZERO,
        )
        .unwrap(),
    )
}

/// The profile: two packets in turn, ports and IP ids varied, a latency
/// signature in every packet, at top speed or a seeded Poisson rate.
fn stream(cap: &Arc<Capture>, model: Option<&str>) -> Stream<'static> {
    let s = Stream::new("repeat", CaptureSource::new(cap.clone()).loops(0))
        .with_limit(Some(PACKETS))
        .with_transform(
            FieldEngine::parse([
                "port_src=1000..1999",
                "ip_id=7..65000,step=3",
                "ip_dst=10.1.0.0/22,random,seed=5",
            ])
            .unwrap(),
        )
        .with_latency(FLOW);
    match model {
        Some(m) => s
            .with_rate(Rate::Pps(200_000.0))
            .with_model(m.parse().unwrap()),
        None => s.with_rate(Rate::TopSpeed),
    }
}

/// What `workers` workers send, the send time taken out of the signatures,
/// sorted by sequence number.
fn sent(workers: usize, model: Option<&str>) -> Vec<(u64, Vec<u8>)> {
    let cap = capture();
    let sink = Collect::default();
    let work: Vec<(Vec<Stream<'static>>, Box<dyn PacketSink + Send>)> = (0..workers)
        .map(|k| {
            (
                vec![stream(&cap, model).shard(k, workers)],
                Box::new(sink.clone()) as Box<dyn PacketSink + Send>,
            )
        })
        .collect();
    let job = Job::spawn_workers(work, RunConfig::default(), None).unwrap();
    let stats = job.join().unwrap();
    assert_eq!(stats.total.packets, PACKETS, "{workers} worker(s)");
    let mut out: Vec<(u64, Vec<u8>)> = sink
        .0
        .lock()
        .unwrap()
        .iter()
        .map(|f| {
            let sig = Signature::find(f).expect("a signature in every packet");
            assert_eq!(sig.flow, FLOW);
            let mut f = f.clone();
            // The signature ends the IP payload, which ends the frame here.
            let at = f.len() - SIGNATURE_LEN;
            f[at + 6..at + 8].fill(0);
            f[at + 20..at + 28].fill(0);
            (sig.seq, f)
        })
        .collect();
    out.sort();
    out
}

fn assert_same(a: &[(u64, Vec<u8>)], b: &[(u64, Vec<u8>)], what: &str) {
    assert_eq!(a.len(), b.len(), "{what}: packet counts differ");
    let seqs: Vec<u64> = a.iter().map(|(s, _)| *s).collect();
    assert_eq!(
        seqs,
        (0..PACKETS).collect::<Vec<_>>(),
        "{what}: sequence numbers"
    );
    for (x, y) in a.iter().zip(b) {
        assert_eq!(x, y, "{what}: packet with sequence number {} differs", x.0);
    }
}

#[test]
fn one_and_several_workers_send_the_same_packets() {
    let one = sent(1, None);
    for n in [2, 3, 4] {
        assert_same(&one, &sent(n, None), &format!("1 vs {n} workers"));
    }
}

#[test]
fn repeated_runs_send_the_same_packets() {
    let first = sent(3, None);
    for _ in 0..2 {
        assert_same(&first, &sent(3, None), "repeated run");
    }
}

#[test]
fn a_seeded_model_repeats_its_packets() {
    let model = Some("poisson,seed=9");
    let a = sent(1, model);
    assert_same(&a, &sent(1, model), "seeded poisson, repeated");
    assert_same(&a, &sent(4, model), "seeded poisson, 1 vs 4 workers");
}
