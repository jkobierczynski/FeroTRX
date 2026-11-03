# FeroTRX development

What has been built so far, milestone by milestone, and what is still to do.
Each milestone bumps the minor version (see [RELEASING.md](RELEASING.md)).
Open work is tracked in GitHub issues; this file gives the overview.

## Design in one paragraph

The engine lives in `ferotrx-core` and stays platform-free: a source →
transform → pace → sink pipeline for stateless traffic, streams and TOML
profiles, a sans-IO TCP engine for stateful sessions, and the receive-side
statistics. Everything that touches the operating system (libpcap/Npcap,
AF_XDP, DPDK, pcap files) is in `ferotrx-io`, behind the `PacketSink` and
`PacketPort` traits. `ferotrx-packet` decodes and builds packets,
`ferotrx-ctl` is the JSON-RPC remote control, and `ferotrx-cli` is the
`ferotrx` command. The CLI, the control server and your own programs all use
the same library.

## Done

| Milestone | What it added | PR | Version |
|---|---|---|---|
| M1, pcap replay | Replay pcap/pcapng on an interface through libpcap/Npcap at original timing, a multiplier, pps or Mbps; loops; `ferotrx info` | #1 | |
| M2, rewriting and profiles | MAC/IP/port/VLAN/QinQ rewrites, checksum fixing, several streams at once from a TOML profile (`ferotrx run`); sample pcaps (#3) | #2, #3 | |
| M3, packet inspection | `ferotrx-packet` decoder, `ferotrx inspect` with checksum checks | #4 | |
| M4, packet building | `ferotrx build`, the PacketSpec text syntax, built packets in profiles | #5 | |
| M5, remote control | `ferotrx-ctl`: JSON-RPC 2.0 over TCP (port 4510), `ferotrx serve` / `ferotrx ctl`, live stats subscriptions, optional token, 127.0.0.1 by default | #6 | |
| M6, fast send backends | AF_XDP on Linux (copy and zero-copy), DPDK as an opt-in feature; `-B/--backend`, `[output]` in profiles | #7 | |
| M7, field engine | Per-packet field ranges (`--vary`, `vary` in profiles): addresses, ports, lengths, TTL, payload bytes | #8 | |
| M8, stateful TCP | Sans-IO TCP engine with both ends emulated (own MACs, ARP, ping), handshakes, retransmission with backoff, fast retransmit, byte-for-byte checks; `ferotrx tcp`, TCP profiles, `tcp.*` control methods; `scripts/tcp-nat-netns.sh` | #9 | 0.1.0 |
| Releases | Release workflow: .deb, Linux/macOS/Windows archives and checksums on each `vX.Y.Z` tag | #10 | |
| M9, receive side | Loss, duplicates, reordering, latency (min/avg/p50/p99/p99.9/max) and RFC 3550 jitter per stream from a 28-byte signature; `--rx`, `ferotrx rx`, `--report` JSON, `rx.*` control methods; `scripts/latency-netns.sh` | #11 | 0.2.0 |
| M10, multi-flow TCP templates | `[[template]]` tables with weights (smooth weighted round robin), per-template ports, server address ranges, per-template counters | #12 | 0.3.0 |
| M11, IPv6 everywhere | Stateful TCP over IPv6 with neighbor discovery, IPv6 extension headers and ND in the packet builder, `IPV6=1` for both lab scripts | #13 | 0.4.0 |
| M12, TCP maturity | Window scaling, timestamps and PAWS, SACK with out-of-order receive and hole-only retransmits, RTT-based timeouts (RFC 6298), NewReno/SACK recovery; windows, timeouts and SYN retries in profiles and on the command line; per-template `cps`, `connections`, `concurrency`; [docs/tcp-engine.md](docs/tcp-engine.md); simulated long-fat-pipe and impairment tests, `BDP=1` and `NETEM=` in the lab script | #15 | 0.5.0 |

The lab scripts (`scripts/*.sh`) build a NAT router in network namespaces
and run in CI, over IPv4 and IPv6, with and without loss, and for TCP also
on a long fat pipe and with reordering and duplicates (netem).

## Still to do

The priorities come from an outside review (November 2026, kept in
[docs/priorities-report-2026-11.md](docs/priorities-report-2026-11.md)),
checked against 0.4.0. Each issue has the full checklist.

**P0: correctness and security**

- [x] **M12, TCP maturity (0.5.0)**, [#15](https://github.com/jkobierczynski/FeroTRX/issues/15):
      window scaling, timestamps/PAWS, SACK; windows and timeouts in profiles;
      per-template rates; large bandwidth-delay and impairment tests
- [ ] **M13, secure remote control (0.6.0)**, [#16](https://github.com/jkobierczynski/FeroTRX/issues/16):
      TLS and optional mutual TLS, read-only and operator roles, file
      restrictions, limits, audit log, no open listener without a token

**P1: measurements and more session types**

- [ ] **M14, benchmarking (0.7.0)**, [#17](https://github.com/jkobierczynski/FeroTRX/issues/17):
      IMIX and size distributions, RFC 2544-style throughput/loss/latency/
      back-to-back, run metadata in reports, documented method
- [ ] **M15, stateful UDP and transactions (0.8.0)**, [#18](https://github.com/jkobierczynski/FeroTRX/issues/18):
      UDP sessions with matching/timeouts/retries, DNS first, per-template
      transaction rates, message timing for TCP replay

**P2: the differentiator, then by demand**

- [ ] **M16, scenario and regression tests (0.9.0)**, [#19](https://github.com/jkobierczynski/FeroTRX/issues/19):
      scenario files with expected outcomes, pass/fail for CI, comparing runs
- [ ] **Later**, [#20](https://github.com/jkobierczynski/FeroTRX/issues/20):
      stateful TCP over AF_XDP/DPDK, traffic models (bursts, Poisson, ramps),
      host emulation (DHCP, RA, IGMP/MLD), a Python client package, profile
      validation, generated TLS and HTTP workloads

**P3: when the engine is stable**

- [ ] **Distributed agents and a GUI**, [#21](https://github.com/jkobierczynski/FeroTRX/issues/21)

**Not planned for now:** a packet-analysis suite (use Wireshark), a long
list of shallow protocols, DPDK as the main backend, Kubernetes
orchestration, full network simulation.

Note: FeroTRX measures loss, duplication, reordering and latency; it does not
inject them. The lab scripts use netem for that.
