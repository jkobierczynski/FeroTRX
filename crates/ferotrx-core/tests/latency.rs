//! Loss and latency measurement end to end, over an impaired in-memory link.

use std::sync::Arc;
use std::time::Duration;

use ferotrx_core::*;

/// A link that drops, duplicates and reorders, in front of a memory port.
struct Impaired {
    port: MemoryPort,
    n: u64,
    held: Option<Vec<u8>>,
}

impl PacketSink for Impaired {
    fn send(&mut self, data: &[u8]) -> std::result::Result<(), SinkError> {
        self.n += 1;
        if self.n % 10 == 0 {
            return Ok(()); // lost
        }
        if self.n % 25 == 1 {
            // Held back, to go after the next one.
            self.held = Some(data.to_vec());
            return Ok(());
        }
        PacketPort::send(&mut self.port, data)?;
        if let Some(h) = self.held.take() {
            PacketPort::send(&mut self.port, &h)?;
        }
        if self.n % 33 == 0 {
            PacketPort::send(&mut self.port, data)?; // duplicated
        }
        Ok(())
    }

    fn flush(&mut self) -> std::result::Result<(), SinkError> {
        if let Some(h) = self.held.take() {
            PacketPort::send(&mut self.port, &h)?;
        }
        Ok(())
    }
}

#[test]
fn loss_duplicates_and_reordering_are_counted() {
    let (tx, rx) = memory_ports();
    let cap = Arc::new(
        Capture::from_specs(
            &[
                "eth/ipv4(src=10.0.0.1,dst=10.0.0.2)/udp(sport=1,dport=2)/raw(len=18)",
                "eth/ipv6(src=fd00::1,dst=fd00::2)/udp(sport=1,dport=2)/raw(len=3)",
            ],
            Duration::ZERO,
        )
        .unwrap(),
    );
    let streams = vec![
        Stream::new("probe", CaptureSource::new(cap.clone()).loops(500))
            .with_rate(Rate::Pps(20_000.0))
            .with_latency(5),
        // Untagged traffic next to it.
        Stream::new("bulk", CaptureSource::new(cap).loops(10)).with_rate(Rate::TopSpeed),
    ];
    let sink = Impaired {
        port: tx,
        n: 0,
        held: None,
    };
    let rx = RxSettings {
        receiver: Box::new(PortReceiver(rx)),
        wait: Duration::from_millis(100),
    };
    let job = Job::spawn_with_rx(streams, Box::new(sink), RunConfig::default(), Some(rx)).unwrap();
    assert!(job.wait(Some(Duration::from_secs(20))));
    assert_eq!(job.flows(), [Some(5), None]);
    let stats = job.stats();
    assert_eq!(stats.streams[0].tagged, 1000);
    assert_eq!(stats.streams[1].tagged, 0);

    let reports = job.flow_reports();
    assert_eq!(reports.len(), 1);
    let r = &reports[0];
    assert_eq!((r.stream.as_str(), r.flow, r.tx), ("probe", 5, 1000));
    // Every 10th of all 1020 packets is dropped; the bulk ones mix in, so
    // count from the receiver's side.
    let rxs = job.rx_stats().unwrap();
    let f = rxs.flow(5).unwrap();
    assert!(r.lost > 50 && r.lost < 150, "{r:?}");
    assert_eq!(r.lost, r.tx - f.unique());
    assert!(f.duplicates > 0 && f.out_of_order > 0, "{f:?}");
    assert_eq!(f.seq_lost() + f.unique(), f.next_seq - f.first_seq);
    assert!(r.loss() > 0.05 && r.loss() < 0.15);
    let max = r.latency.max().unwrap();
    assert!(max < Duration::from_secs(2), "{max:?}");
    assert!(r.latency.percentile(0.5).unwrap() <= max);
    assert_eq!(
        rxs.untagged + rxs.flows.values().map(|f| f.packets).sum::<u64>(),
        rxs.packets
    );
}

#[test]
fn tagged_packets_stay_valid_after_rewrites_and_vary() {
    let cap = Capture::from_specs(
        &[
            "eth/vlan(id=10)/ipv4(src=10.0.0.1,dst=10.0.0.2)/udp(sport=1,dport=2)/raw(len=7)",
            "eth/ipv4(src=10.0.0.1,dst=10.0.0.2)/tcp(sport=1,dport=80)/raw(text=\"GET\")",
            "eth/ipv4(src=10.0.0.1,dst=10.0.0.2)/icmp(id=1)",
            "eth/ipv6(src=fd00::1,dst=fd00::2)/icmp6",
        ],
        Duration::ZERO,
    )
    .unwrap();
    let mut streams = [Stream::new("s", CaptureSource::new(&cap).loops(3))
        .with_rate(Rate::TopSpeed)
        .with_transform("ip_dst=192.168.20.50".parse::<Rewrite>().unwrap())
        .with_transform(FieldEngine::new([
            "ip_src=192.168.10.1..192.168.10.9"
                .parse::<FieldVar>()
                .unwrap(),
            "len=60..200,random".parse().unwrap(),
        ]))
        .with_latency(3)];
    let mut sink = VecSink::default();
    let stats = run(&mut streams, &mut sink, &RunConfig::default()).unwrap();
    assert_eq!(stats.total.tagged, 12);
    for (i, p) in sink.packets.iter().enumerate() {
        let d = ferotrx_packet::decode(1, p);
        assert!(d.problems.is_empty(), "packet {i}: {:?}", d.problems);
        let sig = Signature::find(p).unwrap();
        assert_eq!((sig.flow, sig.seq), (3, i as u64));
    }
}
