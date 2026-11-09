# FeroTRX manual

Start with [installing](install.md), then the guide for what you want to do.
The [README](../README.md) has the overview and a quickstart.

## Getting started

* [Installing and building](install.md): packages, building from source,
  DPDK, permissions to send.
* [Lab scripts](lab-scripts.md): try every feature in Linux network
  namespaces, without a lab.
* [Feature status](status.md): what is done, partial, experimental or
  planned; [interoperability](interop.md): the real implementations each
  protocol is tested against.

## Stateless traffic

* [Replaying captures, rewrites and profiles](replay.md): `ferotrx replay`
  and `ferotrx run`, rates and loops, rewrites, the field engine (`--vary`),
  multi-stream TOML profiles.
* [Inspecting and building packets](packets.md): `ferotrx inspect`,
  `ferotrx build` and its packet syntax.
* [Traffic models and file checks](traffic-models.md): Poisson arrivals,
  bursts, ramps and rate shapes; `ferotrx check`; the `format` version.
* [Fast send backends](backends.md): AF_XDP and DPDK.

## Stateful traffic

* [Stateful TCP](stateful-tcp.md): `ferotrx tcp`, TCP profiles, templates.
  Engine internals: [The stateful TCP engine](tcp-engine.md).
* [Stateful UDP and DNS](stateful-udp.md): `ferotrx udp`, DNS, NTP and UDP
  sessions. Engine internals: [The stateful UDP engine](udp-engine.md).
* [Application protocols](app-protocols.md): HTTP/1.1 and HTTP/2 clients
  and servers, DNS over UDP and TCP, MQTT, SSH, SIP with RTP, SMB, HTTP/3 over QUIC, NTP, as `app = "..."` in TCP and UDP profiles; TLS
  under them (HTTPS, DNS over TLS): versions, cipher suites, certificates,
  handshake counters; writing your own.
* [Host emulation](host-emulation.md): `ferotrx host`, DHCP, SLAAC, DHCPv6, DHCP servers,
  IGMP/MLD, router advertisements.
* [TCP and UDP over AF_XDP and DPDK](fast-ports.md).
* [One run on several cores](multi-core.md): `--workers`, for streams and
  for stateful TCP and UDP; `--cpus` pins them.
* [Performance](performance.md): the sweep method, repeatability, and the
  numbers measured so far (and where).

## Measuring and testing

* [Loss and latency](loss-latency.md): signatures, `--rx`, `ferotrx rx`,
  where frames were lost, run records (`--report`).
* [Call quality, jitter and latency](call-quality.md): RTP loss, jitter,
  late packets and RTCP round trips per call, E-model R and MOS, TCP
  connect and first-byte times.
* [Impairments](impairments.md): delay, jitter, loss and bursts,
  duplicates, reordering, corruption, rate limits and MTU on streams, on
  TCP/UDP/host ports and in a two-port bridge (`ferotrx impair`), without
  netem.
* [Capturing traffic](capture.md): `ferotrx capture` with BPF filters,
  pcap to files, rings or Wireshark, captures on remote servers and fleet
  agents, `inspect -f`.
* [Benchmarking](benchmarking.md): `ferotrx bench`, RFC 2544, IMIX.
* [Y.1564 service activation](y1564.md): `ferotrx y1564`, services with a
  CIR and EIR, configuration steps, policing, the performance test.
* [Scenarios and regression tests](scenarios.md): `ferotrx scenario`,
  expected outcomes, JUnit reports, comparing runs.

## Development

* [Fuzzing and hostile-input tests](fuzzing.md): the fuzz targets, running
  long campaigns, what to do with a crash.
* [CI: what runs when](ci.md): which CI work is skipped because an
  equivalent tree already passed, and what still runs in full.

## Automation

* [Remote control](remote-control.md): `ferotrx serve` and `ferotrx ctl`,
  the JSON-RPC protocol and its methods, TLS, roles and the security model.
* [Fleets](fleet.md): `ferotrx fleet`, one plan that deploys profiles to
  several agents, starts them together and adds up their counters.
* [The Python client](python-client.md).
* [FeroTRX on Windows](windows.md): the installer, Npcap, interface
  names, the GUI on Windows.
* [The desktop GUI](gui.md): `ferotrx-gui`, ports, the stream and packet
  editor, captures, live statistics, local or remote servers.
* [Using FeroTRX as a library](library.md): the Rust API.

## Project

* [Development](../DEVELOPMENT.md): design, milestones done, what is next.
* [Releasing](../RELEASING.md).
* [Priorities report, November 2026](priorities-report-2026-11.md): an
  outside review, kept as received.
* [Outside reviews](reviews/README.md): the project state and security
  reviews of 6 November 2026, our check of each claim, and the
  [security plan](reviews/2026-11-security-plan.md).
