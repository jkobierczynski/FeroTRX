# Using FeroTRX as a library

Everything the `ferotrx` command does is in the crates, so your own programs
can do it too. `ferotrx-core` has the engine and no platform code;
`ferotrx-io` opens interfaces and files; `ferotrx-packet` decodes and builds
packets; `ferotrx-ctl` is the control server and client. `cargo doc --open`
has the full API. From Python, use the control server through the
[Python client](python-client.md).

## Replaying a capture

```rust
use ferotrx_core::{replay, Capture, Rate, ReplayConfig};
use ferotrx_io::InterfaceSink;

let capture = Capture::from_path("capture.pcap")?;
let mut sink = InterfaceSink::open("eth0")?;
let config = ReplayConfig { rate: Rate::Pps(10_000.0), loops: 5, ..Default::default() };
let stats = replay(&capture, &mut sink, &config)?;
println!("{} packets at {:.0} pps", stats.packets, stats.pps());
```

## Streams and rewrites

Several streams with rewrites:

```rust
use ferotrx_core::{run, Capture, CaptureSource, Rate, Rewrite, RunConfig, Stream};

let capture = Capture::from_path("capture.pcap")?;
let mut streams = [
    Stream::new("vlan10", CaptureSource::new(&capture).loops(0))
        .with_rate(Rate::Pps(1000.0))
        .with_transform("vlan_push=10".parse::<Rewrite>()?),
    Stream::new("vlan20", CaptureSource::new(&capture).loops(0))
        .with_rate("50mbps".parse()?)
        .with_transform("vlan_push=20".parse::<Rewrite>()?),
];
let config = RunConfig { duration: Some(std::time::Duration::from_secs(30)), ..Default::default() };
let stats = run(&mut streams, &mut sink, &config)?;
```

## The field engine

```rust
use ferotrx_core::{FieldEngine, FieldVar, VarField, Side};

let engine = FieldEngine::parse(["ip_src=10.0.0.1..10.0.0.254", "port_src=1024..65535,random"])?;
let stream = Stream::new("many-clients", CaptureSource::new(&capture).loops(0)).with_transform(engine);

// Or without text:
let var = FieldVar::new(VarField::Port(Side::Dst), 5000, 5099)?;
let engine = FieldEngine::new([var]);
```

## Building packets

```rust
use ferotrx_packet::{Ethernet, Ipv4, PacketSpec, Udp, Vlan};

let frame = PacketSpec::new()
    .with(Ethernet { dst: [0x02, 0, 0, 0, 0, 0x01], ..Default::default() })
    .with(Vlan { id: 10, ..Default::default() })
    .with(Ipv4 { dst: "192.168.20.50".parse()?, ..Default::default() })
    .with(Udp { dport: Some(5000), ..Default::default() })
    .build()?;

// Or from text, straight into a capture that streams can play:
let capture = ferotrx_core::Capture::from_specs(&["eth/ipv4/udp/dns(q=example.com)"], Duration::from_millis(10))?;
```

## Runs in the background

Running in the background, as the CLI and the control server do:

```rust
use ferotrx_core::{Job, Profile, RunConfig};
use ferotrx_io::Output;

let profile = Profile::from_path("lab.toml")?;
let job = ferotrx_ctl::start_run(&profile, &Output::interface("eth0"), None, RunConfig::default())?;
std::thread::sleep(std::time::Duration::from_secs(5));
println!("{} packets so far", job.stats().total.packets);
job.stop();
let stats = job.join()?;
```

## Sending through AF_XDP

```rust
use ferotrx_core::{Backend, SendSettings, XdpMode};
use ferotrx_io::Output;

let output = Output::Interface {
    name: "enp0s3".into(),
    send: SendSettings { backend: Some(Backend::AfXdp), xdp_mode: Some(XdpMode::Copy), ..Default::default() },
};
let mut sink = output.open(ferotrx_core::LINKTYPE_ETHERNET)?;
```

## The pipeline

Packets flow `PacketSource -> Transform... -> Pacer -> PacketSink`. Implement
`PacketSource` to generate packets, `Transform` to change them, and `PacketSink`
to send them anywhere else. `Profile::from_path(...)?.load()?` builds the streams
of a TOML profile.

## Loss and latency

A stream with a signature, sent through a sink
and counted by a receiver on the far side (here the two ends of an in-memory
link; `ferotrx_io::open_receiver("eth1")` opens a real interface):

```rust
use ferotrx_core::*;

let (tx, rx) = memory_ports();
let streams = vec![Stream::new("probe", CaptureSource::new(capture).loops(0))
    .with_rate(Rate::Pps(1000.0))
    .with_latency(1)];
let config = RunConfig { duration: Some(std::time::Duration::from_secs(10)), ..Default::default() };
let job = Job::spawn_with_rx(streams, Box::new(tx), config, Some(RxSettings::new(Box::new(PortReceiver(rx)))))?;
job.wait(None);
for r in job.flow_reports() {
    println!("{}: {} sent, {} lost, p99 {:?}", r.stream, r.tx, r.lost, r.latency.percentile(0.99));
}
```

`RxStats::record(frame, receive_time)` does the counting for frames from
anywhere, and `Signature::find(frame)` reads a signature.

## Benchmarks

`run_benchmark` decides the trials, a `TrialRunner`
runs them. `JobTrialRunner` sends with a `Job` on any sink and counts with
any receiver; a simulated device works too:

```rust
use ferotrx_core::*;

let config = BenchConfig {
    tests: vec![BenchTest::Throughput, BenchTest::BackToBack],
    sizes: vec!["508".parse()?, "imix".parse()?],
    line_rate_mbps: 1000.0,
    ..Default::default()
};
let mut runner = JobTrialRunner::new(capture, open_sink, open_receiver);
let report = run_benchmark(&config, &mut runner, |size, trial| {
    println!("{} {}: {:.2}% lost {}", size.size, trial.test, trial.load_pct, trial.lost)
})?;
println!("{}", report.text());
```

## Stateful TCP

Here with the client and the server on two in-memory
ports (`ferotrx_io::open_port("eth0")` opens a real one):

```rust
use std::sync::Arc;
use ferotrx_core::*;

let program = TcpProgram::from_capture(&Capture::from_path("http.pcap")?, None)?;
let mut client = TcpClientConfig::new(
    TcpEndpoint::new(0, "02:00:00:00:00:01".parse()?, "10.0.0.1".parse()?),
);
client.cps = 100.0;
client.connections = 1000;
let server = TcpServerConfig::new(
    TcpEndpoint::new(1, "02:00:00:00:00:02".parse()?, "10.0.0.2".parse()?).with_ip_count(4),
);
// One template; add more, each with its own port, and weights to mix them.
let web = TcpTemplate::new(Arc::new(program), "10.0.0.2:80".parse()?)
    .with_name("web")
    .with_connect_ips(4);
let engine = TcpEngine::new(TcpConfig {
    templates: vec![web],
    client: Some(client),
    server: Some(server),
    options: TcpOptions::default(),
})?;
let (a, b) = memory_ports();
let job = TcpJob::spawn(engine, vec![Box::new(a), Box::new(b)], TcpRunConfig::default())?;
let stats = job.join()?;
println!("{} connections completed", stats.client.completed);
for t in &stats.templates {
    println!("  {}: {}", t.name, t.client.completed);
}
```

`TcpEngine` does no I/O and reads no clock: it takes received frames and the
time, and returns frames to send, so it can also run on a simulated network
(see `crates/ferotrx-core/tests/tcp.rs`, which puts it behind a simulated
lossy NAT router).

## Stateful UDP

The same way, here DNS:

```rust
let dns = DnsWorkload::parse(&["www.lab.local AAAA"], &["www.lab.local AAAA fd00::80"])?;
let mut client = UdpClientConfig::new(
    UdpEndpoint::new(0, "02:00:00:00:00:01".parse()?, "10.0.0.1".parse()?),
);
client.rate = 1000.0;
client.transactions = 10_000;
let engine = UdpEngine::new(UdpConfig {
    templates: vec![UdpTemplate::new(UdpApp::Dns(Arc::new(dns)), "10.0.0.2:53".parse()?)],
    client: Some(client),
    server: Some(UdpServerConfig::new(
        UdpEndpoint::new(1, "02:00:00:00:00:02".parse()?, "10.0.0.2".parse()?),
    )),
    options: UdpOptions::default(),
})?;
let (a, b) = memory_ports();
let stats = UdpJob::spawn(engine, vec![Box::new(a), Box::new(b)], TcpRunConfig::default())?.join()?;
println!("{} answered, p99 {:?}", stats.client.answered, stats.client.response_time.percentile(0.99));
```
