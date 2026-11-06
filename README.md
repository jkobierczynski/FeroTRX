# FeroTRX

FeroTRX is a traffic generator and replay tool written in Rust, inspired by
[Cisco TRex](https://trex-tgn.cisco.com/). It replays captures and builds
packets at a controlled rate, plays real TCP and UDP sessions through NAT
routers and firewalls with both ends emulated, measures loss and latency,
benchmarks devices the RFC 2544 way and runs regression tests, on Linux,
macOS and Windows. Its engine is a library you can use from your own
programs, and a control server lets scripts and the Python client drive it
remotely.

The current version is 0.25.0; see [DEVELOPMENT.md](DEVELOPMENT.md) for what
each milestone added and what comes next.

## Features

* **Replay** pcap and pcapng captures at their own timing, a multiple of it,
  a packet or bit rate, or top speed, looped. [Guide](docs/replay.md)
* **Rewrite and vary** packets on the way: MAC and IP addresses (also by
  prefix), ports, VLAN and QinQ tags, checksums; per-packet field ranges like
  TRex's field engine. [Guide](docs/replay.md#rewriting)
* **Profiles**: several streams at once from a TOML file, each with its own
  capture or built packets, rate, loops, delay, rewrites and size mix.
  [Guide](docs/replay.md#profiles)
* **Inspect and build packets**: decode captures layer by layer with byte
  ranges and checksum checks; build Ethernet, VLAN, ARP, IPv4, IPv6 (with
  extension headers), TCP, UDP, ICMP/ICMPv6 and DNS packets from one line of
  text. [Guide](docs/packets.md)
* **Traffic models**: Poisson arrivals, bursts, ramps and rate shapes for
  streams, connections and transactions. [Guide](docs/traffic-models.md)
* **Stateful TCP**: real connections with handshakes, retransmits, window
  scaling, timestamps and SACK, from captures or written-out sessions,
  mixed from weighted templates. [Guide](docs/stateful-tcp.md)
* **Stateful UDP**: DNS, NTP and replayed UDP sessions with matching,
  timeouts and retries. [Guide](docs/stateful-udp.md)
* **Application protocols**: HTTP/1.1 clients and servers (keep-alive,
  pipelining, chunked bodies, routes, status checks, response times) and DNS
  over UDP and TCP that react to the other end, so they also work against
  `curl` or a real web server; TLS 1.2 and 1.3 under any of them (HTTPS, DNS
  over TLS) with real handshakes, chosen versions, cipher suites and
  certificates, client certificates and resumption; HTTP/2 over TLS (h2)
  and without (h2c) with HPACK, multiplexed streams and flow control; MQTT
  3.1.1 and 5.0 clients and a broker with QoS 0, 1 and 2; SSH clients and
  servers (curve25519, Ed25519, ChaCha20-Poly1305 and AES-GCM, password and
  key logins, commands, re-keying) that work with OpenSSH; SIP phones and a
  SIP server (registration with digest authentication, calls) with RTP
  audio at codec rates and its loss and jitter, which work with SIPp; SMB 2 and 3
  file clients and a file server (NTLMv2 logins, signing, files and
  directories) that work with smbclient and Samba; an interface for protocols of your own.
  [Guide](docs/app-protocols.md)
* **Host emulation**: emulated hosts get addresses by DHCP, SLAAC or DHCPv6,
  announce them, join multicast groups and act as IPv6 routers and DHCP or
  DHCPv6 servers.
  [Guide](docs/host-emulation.md)
* **Loss and latency** per stream, from a signature in each packet.
  [Guide](docs/loss-latency.md)
* **Benchmarking**: RFC 2544 throughput, latency, frame loss and
  back-to-back, with IMIX and other size mixes. [Guide](docs/benchmarking.md)
* **Y.1564 service activation**: services with a CIR, EIR and burst sizes,
  the configuration steps and policing, and a performance test with
  availability, judged against FLR, FTD and FDV. [Guide](docs/y1564.md)
* **Regression scenarios**: checks with expected outcomes, JSON and JUnit
  reports, run history and comparisons, for CI. [Guide](docs/scenarios.md)
* **Fleets of agents**: one plan deploys TCP, UDP and traffic profiles to
  several `ferotrx serve` agents, starts them at one instant on a shared
  clock and adds up their counters. [Guide](docs/fleet.md)
* **Fast backends**: libpcap/Npcap everywhere, AF_XDP on Linux, DPDK as a
  build option, for stateless and stateful runs.
  [Guide](docs/backends.md)
* **Several cores**: `--workers N` spreads one run over N engine threads,
  streams packet by packet and TCP/UDP runs by flow, one AF_XDP queue per
  worker. [Guide](docs/multi-core.md)
* **Remote control**: a JSON-RPC server with TLS, client certificates,
  read-only and operator roles and an audit log; a command line client and a
  Python package. [Guide](docs/remote-control.md),
  [Python](docs/python-client.md)
* **Desktop GUI**: `ferotrx-gui` drives local and remote servers: ports,
  streams built layer by layer with a live packet view, captures turned into
  editable streams and bytes edited in hex, forms for application protocol
  profiles, benchmarks, scenarios and their comparison, runs on several
  servers at once, counters, rate, loss and latency charts, all saved as a
  workspace. [Guide](docs/gui.md)
* **IPv4 and IPv6** throughout.

## Install

Every release on the [Releases page](https://github.com/jkobierczynski/FeroTRX/releases)
has a Debian package, archives for Linux and macOS and a zip for Windows
(which needs [Npcap](https://npcap.com/)). To build from source you need
stable Rust and libpcap (`sudo apt install libpcap-dev` on Debian):

```sh
cargo build --release              # target/release/ferotrx
cargo build --release --features dpdk   # with DPDK
```

Details, and the permissions sending needs: [docs/install.md](docs/install.md).

## Quickstart

The sample files in [`examples/`](examples) work as they are. Without root
and without sending anything:

```sh
ferotrx info examples/web.pcap                    # packets, bytes, duration, rate
ferotrx inspect examples/web.pcap -p 1            # layers, fields and hex dump
ferotrx build 'eth/ipv4(dst=10.0.0.2)/udp/dns(q=example.com)' -v
ferotrx run examples/lab-two-vlans.toml --out lab.pcap --duration 15s   # a profile into a file
ferotrx tcp examples/http.pcap --show             # what each end of a TCP session sends
ferotrx check examples/*.toml                     # every example profile and scenario
```

On an interface (root, or `CAP_NET_RAW`):

```sh
ferotrx interfaces
sudo ferotrx replay examples/web.pcap -i eth0 --pps 1000 --loop 0
sudo ferotrx run examples/lab-two-vlans.toml -i eth0 --duration 60s
sudo ferotrx tcp -p examples/lab-tcp.toml -i eth0
```

No lab at hand? Each script in [`scripts/`](scripts) builds a router in Linux
network namespaces and runs a feature through it, for example
`sudo scripts/tcp-nat-netns.sh`; see [docs/lab-scripts.md](docs/lab-scripts.md).

## Documentation

The manual is in [docs/](docs/README.md):

| Guide | What it covers |
| --- | --- |
| [Installing and building](docs/install.md) | packages, building, DPDK, permissions |
| [Replaying captures, rewrites and profiles](docs/replay.md) | `replay`, `run`, rewrites, `--vary`, TOML profiles |
| [Inspecting and building packets](docs/packets.md) | `inspect`, `build`, the packet syntax |
| [Traffic models and file checks](docs/traffic-models.md) | Poisson, bursts, ramps, shapes; `check` |
| [Fast send backends](docs/backends.md) | AF_XDP and DPDK |
| [Stateful TCP](docs/stateful-tcp.md) and [the engine](docs/tcp-engine.md) | `tcp`, TCP profiles, templates |
| [Stateful UDP and DNS](docs/stateful-udp.md) and [the engine](docs/udp-engine.md) | `udp`, DNS, NTP |
| [Application protocols](docs/app-protocols.md) | HTTP/1.1 and HTTP/2, HTTPS and TLS, DNS over UDP, TCP and TLS, MQTT, SSH, SIP and RTP, SMB, NTP, your own |
| [Host emulation](docs/host-emulation.md) | `host`, DHCP, SLAAC, IGMP/MLD |
| [TCP and UDP over AF_XDP and DPDK](docs/fast-ports.md) | fast ports for stateful runs |
| [One run on several cores](docs/multi-core.md) | `--workers`, splitting streams and flows |
| [Loss and latency](docs/loss-latency.md) | signatures, `--rx`, `rx` |
| [Benchmarking](docs/benchmarking.md) | `bench`, RFC 2544 |
| [Y.1564 service activation](docs/y1564.md) | `y1564`, CIR/EIR, policing, availability |
| [Scenarios and regression tests](docs/scenarios.md) | `scenario` |
| [Remote control](docs/remote-control.md) | `serve`, `ctl`, the protocol, security |
| [Fleets: runs on several agents](docs/fleet.md) | `fleet run`, plans, shared start, sums |
| [The Python client](docs/python-client.md) | the `ferotrx` Python package |
| [The desktop GUI](docs/gui.md) | `ferotrx-gui`: ports, stream and packet editor, application profiles, benchmarks, Y.1564, workspaces |
| [Using FeroTRX as a library](docs/library.md) | the Rust API |
| [Lab scripts](docs/lab-scripts.md) | network namespace labs, as run in CI |

Every command also has `--help`.

## Crates

| Crate | What it is |
| --- | --- |
| `ferotrx-core` | The core API: captures, rewrites, streams, profiles, pacing, the scheduler, the stateful TCP and UDP engines, host emulation, loss and latency counting, benchmarks and scenarios. No platform code. |
| `ferotrx-packet` | Packet decoding (layers, fields with byte ranges, checksum checks, summaries), building, and import of captured packets back into the text form. No dependencies. |
| `ferotrx-io` | Network interfaces through libpcap/Npcap, AF_XDP or DPDK; pcap files; ports for stateful runs; receivers for loss and latency. |
| `ferotrx-ctl` | Remote control: the JSON-RPC server and client, and the runner that plays scenario checks on interfaces. |
| `ferotrx-cli` | The `ferotrx` command line tool. |
| `ferotrx-gui` | The `ferotrx-gui` desktop GUI (egui), a client of the control server. |
| `python/` | The Python client for the control server (package `ferotrx`); not a crate. |

```rust
use ferotrx_core::{replay, Capture, Rate, ReplayConfig};
use ferotrx_io::InterfaceSink;

let capture = Capture::from_path("capture.pcap")?;
let mut sink = InterfaceSink::open("eth0")?;
let config = ReplayConfig { rate: Rate::Pps(10_000.0), loops: 5, ..Default::default() };
let stats = replay(&capture, &mut sink, &config)?;
println!("{} packets at {:.0} pps", stats.packets, stats.pps());
```

More in [docs/library.md](docs/library.md).

## Development

[DEVELOPMENT.md](DEVELOPMENT.md) has the design, the milestones done and the
open work (linked to GitHub issues); [RELEASING.md](RELEASING.md) says how
releases are made.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
