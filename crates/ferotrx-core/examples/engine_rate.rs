//! How many TCP connections per second the engine itself manages, with the
//! client and the server joined by memory ports (no network, one thread).
//!
//! `cargo run --release -p ferotrx-core --example engine_rate -- 20000`
//! asks for 20000 connections per second for four seconds; each connection
//! sends 144 bytes and gets 6198 back, as examples/http.pcap does. Where the
//! rate reached falls short of the one asked for, or retransmissions show,
//! the engine is the limit.

use std::sync::Arc;
use std::time::Instant;

use ferotrx_core::*;

fn main() {
    let cps: f64 = std::env::args()
        .nth(1)
        .map(|a| a.parse().expect("connections per second"))
        .unwrap_or(10_000.0);
    let program = TcpProgram::new(
        80,
        vec![
            TcpMessage::new(TcpRole::Client, vec![b'q'; 144]),
            TcpMessage::new(TcpRole::Server, vec![b'r'; 6198]),
        ],
    );
    let (a, b) = memory_ports();
    let server = TcpEndpoint::new(
        1,
        "02:00:00:00:00:02".parse().unwrap(),
        "10.0.0.2".parse().unwrap(),
    );
    let mut ep = TcpEndpoint::new(
        0,
        "02:00:00:00:00:01".parse().unwrap(),
        "10.0.0.1".parse().unwrap(),
    );
    ep.ip_count = 50;
    let mut client = TcpClientConfig::new(ep);
    client.connections = (cps * 4.0) as u64;
    client.cps = cps;
    let engine = TcpEngine::new(TcpConfig {
        templates: vec![TcpTemplate::new(
            Arc::new(program),
            "10.0.0.2:80".parse().unwrap(),
        )],
        client: Some(client),
        server: Some(TcpServerConfig::new(server)),
        options: TcpOptions::default(),
    })
    .unwrap();
    let start = Instant::now();
    let job = TcpJob::spawn(
        engine,
        vec![Box::new(a), Box::new(b)],
        TcpRunConfig::default(),
    )
    .unwrap();
    let s = job.join().unwrap();
    let secs = start.elapsed().as_secs_f64();
    println!(
        "{} completed, {} timed out, {} retransmits: {:.0} connections per second over {secs:.2} s",
        s.client.completed,
        s.client.timed_out,
        s.client.retransmits,
        s.client.completed as f64 / secs,
    );
}
