# FeroTRX

FeroTRX is a traffic replay tool written in Rust, inspired by
[Cisco TRex](https://trex-tgn.cisco.com/). It replays pcap and pcapng captures
at a controlled rate on Linux, macOS and Windows, and its engine is a library
you can use from your own programs.

## Status

Milestone 1 (pcap replay) is in progress. See the plan for what comes next:
rewriting, a control API, flow multiplication, packet inspection and building,
and faster Linux backends.

## Crates

| Crate | What it is |
| --- | --- |
| `ferotrx-core` | The core API: load captures, pace packets, run replays, collect stats. No platform code. |
| `ferotrx-io` | Packet sinks: network interfaces through libpcap/Npcap, pcap files. |
| `ferotrx-cli` | The `ferotrx` command line tool. |

## Build

You need a stable Rust toolchain and libpcap:

* **Linux:** `sudo apt install libpcap-dev` (or your distribution's package).
* **macOS:** libpcap ships with the OS.
* **Windows:** install [Npcap](https://npcap.com/) to run, and put the Npcap SDK's
  `Lib\x64` folder on the `LIB` path to build.

```sh
cargo build --release
```

To build without libpcap (file and null output only):
`cargo build -p ferotrx-cli --no-default-features`.

## Usage

```sh
ferotrx info capture.pcap                        # packets, bytes, duration, average rate
ferotrx interfaces                               # interfaces you can send on
sudo ferotrx replay capture.pcap -i eth0         # original timing
sudo ferotrx replay capture.pcap -i eth0 -x 10   # 10 times faster
sudo ferotrx replay capture.pcap -i eth0 --pps 50000 --loop 0   # 50k pps until Ctrl-C
ferotrx replay capture.pcap --mbps 100 --out sent.pcap          # write instead of send
ferotrx replay capture.pcap --topspeed --null --loop 1000       # engine speed test
```

Sending on an interface needs root or `CAP_NET_RAW` on Linux, access to
`/dev/bpf*` on macOS, and Npcap on Windows.

## Library

```rust
use ferotrx_core::{replay, Capture, Rate, ReplayConfig};
use ferotrx_io::InterfaceSink;

let capture = Capture::from_path("capture.pcap")?;
let mut sink = InterfaceSink::open("eth0")?;
let config = ReplayConfig { rate: Rate::Pps(10_000.0), loops: 5, ..Default::default() };
let stats = replay(&capture, &mut sink, &config)?;
println!("{} packets at {:.0} pps", stats.packets, stats.pps());
```

Implement the `PacketSink` trait to send packets anywhere else.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
