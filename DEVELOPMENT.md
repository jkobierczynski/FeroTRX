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
| M12, TCP maturity | Window scaling, timestamps and PAWS, SACK with out-of-order receive and hole-only retransmits, RTT-based timeouts (RFC 6298), NewReno/SACK recovery; windows, timeouts and SYN retries in profiles and on the command line; per-template `cps`, `connections`, `concurrency`; [docs/tcp-engine.md](docs/tcp-engine.md); simulated long-fat-pipe and impairment tests, `BDP=1` and `NETEM=` in the lab script | #22 | 0.5.0 |
| M13, secure remote control | TLS (rustls) and mutual TLS for `serve`/`ctl`, read-only and operator roles by token, tokens file or client CA, data directories for profiles, pcaps and outputs, upload/request/connection limits, idle and login timeouts, JSON-lines audit log, no open listener on the network without a login (`--insecure`), `ferotrx certs` lab CA; threat model and deployment notes in the README | #24 | 0.6.0 |
| M15, stateful UDP and transactions | Sans-IO UDP engine with both ends emulated: sessions from captures or `[[message]]`, response matching, timeouts, retries, server sessions that answer repeats; DNS (queries, A/AAAA/CNAME/MX/TXT/NS/PTR/SRV/SOA, NXDOMAIN and error responses), NTP; per-template `rate`, `transactions`, `concurrency`, `think_time`; counters sent/answered/timed out/unmatched with response times; `ferotrx udp`, UDP profiles, `udp.*` control methods; TCP `--keep-timing` and `--think-time`; [docs/udp-engine.md](docs/udp-engine.md); `scripts/udp-netns.sh` with a `dig` check | #26 | 0.8.0 |
| M14, benchmarking | `ferotrx bench`: RFC 2544 throughput (binary search on the rate with a loss threshold), latency, frame loss and back-to-back; frame sizes and size mixes (IMIX, weighted, random) also in profiles and on `replay`/`build`; signatures that keep the frame size; warm-up, repetitions, stop conditions in a benchmark profile; offered against achieved rates and run metadata (version, kernel, CPU, sender, drivers, NICs, profile) in JSON and text reports; [docs/benchmarking.md](docs/benchmarking.md); `scripts/bench-netns.sh` | #25 | 0.8.0 |
| M16, scenario and regression tests | Scenario files: checks that each run TCP, UDP or streams with a receiver, from profile files or inline, with an expected outcome (`complete`, `blocked`) and conditions on metrics with units (`loss_pct < 1%`, `latency_p99 < 20ms`, `rx_mbps > 50Mbit/s`); variables (`--set`); attempts for jittery labs; pass/fail/error per check and the exit code; JSON and JUnit XML reports; run history and comparisons (regressed, fixed, metrics that moved, `--strict`, `--baseline`); `ferotrx scenario run/show/compare/history/metrics`; `ferotrx_ctl::LabRunner`; [docs/scenarios.md](docs/scenarios.md); `scripts/scenario-netns.sh` (a firewall change caught) | #28 | 0.9.0 |
| M17, traffic models and file checks | Traffic models for streams (`model`, `shape`, `--model`): Poisson arrivals, bursts that keep the mean rate, ramps up/hold/down and rate shapes from points (exact, with a quadratic solve per piece), a ramp that ends ends the stream; the same for TCP connections and UDP transactions (top level and per template with its own rate); `ferotrx check` for every kind of file (captures read, packets built, engines set up; summary, warnings, `--strict`, `--kind`); `format = 1` version field in all files; `StreamInfo.model` in the control API; [docs/traffic-models.md](docs/traffic-models.md); `examples/lab-models.toml` | #29 | 0.10.0 |
| M18, stateful TCP and UDP over AF_XDP and DPDK | AF_XDP ports that receive: an XDP program loaded with raw `bpf()` calls (MAC map, XSKMAP, BPF link, driver or generic mode), one full-duplex AF_XDP socket per receive queue, broadcasts and multicasts through a filtered AF_PACKET socket with VLAN tags put back; DPDK ports that receive (promiscuous, burst copy-out in the C shim); `ferotrx_io::open_port_with` and `PortSettings`, `PacketPort::describe`; `-B/--xdp-mode/--queue/--batch/--dpdk-args` and `[output]` for `ferotrx tcp` and `ferotrx udp`, the same fields and `ports` in `tcp.*`/`udp.*`; timer queues instead of per-millisecond scans in the TCP and UDP engines (about 13k to 25k cps for the engine alone); AF_XDP and DPDK runs of the NAT lab scripts in CI; [docs/fast-ports.md](docs/fast-ports.md); `engine_rate` example | #30 | 0.11.0 |
| M19, host emulation | `HostEngine` (sans-IO) and `ferotrx host`: DHCPv4 clients (discover/offer/request/ack, renew at T1, rebind at T2, release, NAK handling), SLAAC (router solicitations, EUI-64 addresses from advertised prefixes, duplicate address detection), DHCPv6 (IA_NA solicit/advertise/request/reply, renew, rebind, release; gateway from router advertisements), gratuitous ARP and unsolicited neighbor advertisements, IGMPv1-3 and MLDv1-2 joins, query answers with version fallback, leaves, per-group receive counters, solicited-node MLD reports, IPv6 router advertisements (prefixes, M/O flags, lifetime, answers to solicitations); host profiles (`[[host]]` with `count`, `[host.router]`, `[options]`); `Hosted` in front of the TCP and UDP engines: `ip = "dhcp"`/`"slaac"`/`"dhcpv6"`, `announce`, `groups`, `hostname` for a client or server and a `[hosts]` table, `--client-ip dhcp`, `--client-join`, `--announce`; `hosts` in `tcp.*`/`udp.*` run info; `ferotrx check` for host profiles; [docs/host-emulation.md](docs/host-emulation.md); `scripts/hosts-netns.sh` (dnsmasq, a bridge with IGMP/MLD snooping) in CI over IPv4/IPv6, libpcap and AF_XDP | #31 | 0.12.0 |
| M20, one run on several cores | `--workers N` (and `workers` in `[output]`, `run.start`, `tcp.start`, `udp.start`) for `replay`, `build`, `run`, `bench`, `tcp` and `udp`: streams split packet by packet over worker threads (`Stream::shard`: packet `i` from worker `i mod N`, sources and the field engine skip the others' packets, rates and limits shared out, latency sequence numbers kept), one libpcap handle or AF_XDP queue per worker (`Output::open_workers`), `Job::spawn_workers`; stateful TCP and UDP split by flow (`TcpConfig::split`/`UdpConfig::split`: a slice of the client's source ports, rates, limits and a seed per worker, the same servers everywhere), `FlowRouter` (client ports by slice, server flows by hash, ARP requests/solicitations/pings to worker 0, replies and advertisements to all), AF_XDP ports split by receive queue (`PacketPort::split`), shared ports with one reader for libpcap and DPDK, `PortJob::spawn_workers`, counters added up (`MergeStats`); `workers` in run info; `QUEUES=` in the TCP and UDP lab scripts and multi-worker lab runs in CI; [docs/multi-core.md](docs/multi-core.md); `engine_rate` takes a worker count | #34 | 0.14.0 (merged after M21; 0.13.0 not released on its own) |
| M21, Python client | `python/`: the `ferotrx` package (pip-installable, standard library only, Python 3.10+, `py.typed`): blocking `Client` (thread-safe) and asyncio `AsyncClient` (concurrent calls, several live subscriptions) for every control method (`profile.*`, `run.*`, `tcp.*`, `udp.*`, `rx.*`, `stats.*`), uploads of local profiles, `watch()` and `wait()` helpers, TLS, client certificates and tokens (also from `FEROTRX_*` like `ferotrx ctl`), dataclass results that keep unknown fields, an exception per error code; [docs/python-client.md](docs/python-client.md), examples; tests against real `ferotrx serve` processes (roles, TLS, mTLS from `ferotrx certs`) on Linux, macOS and Windows, and TCP, DNS and loss/latency across a veth pair on Linux | | 0.14.0 |

The lab scripts (`scripts/*.sh`) build a NAT router (or, for host
emulation, a bridged LAN with a DHCP server) in network namespaces
and run in CI, over IPv4 and IPv6, with and without loss, for UDP and DNS also
with `dig` against the emulated server, and for TCP also
on a long fat pipe and with reordering and duplicates (netem); the benchmark
script puts a rate limit (token bucket) on the router and checks that
`ferotrx bench` finds it. A regression scenario runs against the same router
before and after a firewall change.

## Still to do

The priorities come from an outside review (November 2026, kept in
[docs/priorities-report-2026-11.md](docs/priorities-report-2026-11.md)),
checked against 0.4.0. Each issue has the full checklist.

**P0: correctness and security**

- [x] **M12, TCP maturity (0.5.0)**, [#15](https://github.com/jkobierczynski/FeroTRX/issues/15):
      window scaling, timestamps/PAWS, SACK; windows and timeouts in profiles;
      per-template rates; large bandwidth-delay and impairment tests
- [x] **M13, secure remote control (0.6.0)**, [#16](https://github.com/jkobierczynski/FeroTRX/issues/16):
      TLS and optional mutual TLS, read-only and operator roles, file
      restrictions, limits, audit log, no open listener without a token

**P1: measurements and more session types**

- [x] **M14, benchmarking (0.8.0, after M15)**, [#17](https://github.com/jkobierczynski/FeroTRX/issues/17):
      IMIX and size distributions, RFC 2544-style throughput/loss/latency/
      back-to-back, run metadata in reports, documented method (the
      optional receive path through AF_XDP is not done yet; libpcap receives)
- [x] **M15, stateful UDP and transactions (0.8.0)**, [#18](https://github.com/jkobierczynski/FeroTRX/issues/18):
      UDP sessions with matching/timeouts/retries, DNS first, per-template
      transaction rates, message timing for TCP replay

**P2: the differentiator, then by demand**

- [x] **M16, scenario and regression tests (0.9.0)**, [#19](https://github.com/jkobierczynski/FeroTRX/issues/19):
      scenario files with expected outcomes, pass/fail for CI, comparing runs
- [x] **M17, traffic models and file checks (0.10.0)**, from [#20](https://github.com/jkobierczynski/FeroTRX/issues/20):
      bursts, Poisson arrivals, ramps and rate shapes; `ferotrx check` and a
      profile format version (session length distributions are not done yet)
- [x] **M18, stateful TCP and UDP over AF_XDP and DPDK (0.11.0)**, from [#20](https://github.com/jkobierczynski/FeroTRX/issues/20):
      receiving through an XDP program of FeroTRX's own and AF_XDP sockets,
      or DPDK; timer queues in the engines
- [x] **M19, host emulation (0.12.0)**, from [#20](https://github.com/jkobierczynski/FeroTRX/issues/20):
      DHCP, SLAAC and DHCPv6 addresses, gratuitous ARP and unsolicited
      neighbor advertisements, router advertisements (received and sent),
      IGMP/MLD joins, for `ferotrx host` and the ends of TCP and UDP runs
      (ARP probes, prefix delegation and `host.*` control methods are not
      done yet)
- [x] **M20, one run on several cores (0.13.0, ships in 0.14.0)**, from [#20](https://github.com/jkobierczynski/FeroTRX/issues/20):
      streams split packet by packet and TCP/UDP runs by flow over worker
      threads, one AF_XDP queue per worker (hosts with DHCP/SLAAC addresses
      and DPDK multi-queue are not split yet)
- [x] **M21, Python client (0.14.0)**, from [#20](https://github.com/jkobierczynski/FeroTRX/issues/20):
      the `ferotrx` package in `python/`, blocking and asyncio, tested
      against real servers in CI
- [ ] **Later**, [#20](https://github.com/jkobierczynski/FeroTRX/issues/20):
      generated TLS and HTTP workloads, session length distributions

**P3: when the engine is stable**

- [ ] **Distributed agents and a GUI**, [#21](https://github.com/jkobierczynski/FeroTRX/issues/21)

**Not planned for now:** a packet-analysis suite (use Wireshark), a long
list of shallow protocols, DPDK as the main backend, Kubernetes
orchestration, full network simulation.

Note: FeroTRX measures loss, duplication, reordering and latency; it does not
inject them. The lab scripts use netem for that.
