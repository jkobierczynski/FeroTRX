# FeroTRX manual

Start with [installing](install.md), then the guide for what you want to do.
The [README](../README.md) has the overview and a quickstart.

## Getting started

* [Installing and building](install.md): packages, building from source,
  DPDK, permissions to send.
* [Lab scripts](lab-scripts.md): try every feature in Linux network
  namespaces, without a lab.

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
* [Host emulation](host-emulation.md): `ferotrx host`, DHCP, SLAAC, DHCPv6,
  IGMP/MLD, router advertisements.
* [TCP and UDP over AF_XDP and DPDK](fast-ports.md).
* [One run on several cores](multi-core.md): `--workers`, for streams and
  for stateful TCP and UDP.

## Measuring and testing

* [Loss and latency](loss-latency.md): signatures, `--rx`, `ferotrx rx`.
* [Benchmarking](benchmarking.md): `ferotrx bench`, RFC 2544, IMIX.
* [Scenarios and regression tests](scenarios.md): `ferotrx scenario`,
  expected outcomes, JUnit reports, comparing runs.

## Automation

* [Remote control](remote-control.md): `ferotrx serve` and `ferotrx ctl`,
  the JSON-RPC protocol and its methods, TLS, roles and the security model.
* [The Python client](python-client.md).
* [Using FeroTRX as a library](library.md): the Rust API.

## Project

* [Development](../DEVELOPMENT.md): design, milestones done, what is next.
* [Releasing](../RELEASING.md).
* [Priorities report, November 2026](priorities-report-2026-11.md): an
  outside review, kept as received.
