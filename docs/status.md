# Feature status

What works how well, as of 0.45.0. The milestones and their notes are in
[DEVELOPMENT.md](../DEVELOPMENT.md); which real implementations each
protocol is tested against is in [interop.md](interop.md).

- **Done**: complete for what it claims, tested in CI (unit tests and, where
  it touches the network, a lab script in network namespaces).
- **Partial**: works and is tested, but a named part is missing (listed).
- **Experimental**: works in the lab, but is not exercised in CI the way
  the rest is, or depends on hardware CI does not have.
- **Planned**: has an issue, not started.

## Sending and receiving

| Feature | Status | Notes |
|---|---|---|
| pcap replay, rewriting, loops, rates | Done | [replay.md](replay.md) |
| Profiles of streams (TOML), field engine, traffic models | Done | [traffic-models.md](traffic-models.md); session length distributions not done |
| Multi-burst and `next` streams, `50%` and L1 rates, live pause/resume/rate | Done | M50 |
| The port's own addresses (ARP, neighbor discovery, answers) | Partial | scenario traffic checks do not resolve addresses or shares of the line |
| Packet building and inspection | Done | [packets.md](packets.md) |
| libpcap/Npcap sending (Linux, macOS, Windows) | Done | Windows batches through Npcap's send queue |
| AF_XDP sending and stateful ports (Linux) | Done | copy and zero-copy, driver and generic mode; [fast-ports.md](fast-ports.md) |
| DPDK sending and stateful ports | Experimental | built and unit-tested in CI (`dpdk` job), no NIC there to send on; several queues are not split over workers |
| Several cores (`--workers`) | Partial | hosts with DHCP/SLAAC addresses, SIP media and DPDK multi-queue are not split |
| Loss and latency (signatures, `--rx`, `ferotrx rx`) | Partial | receiving through libpcap only, not AF_XDP; one-way latency needs synced clocks |
| Loss split by where (generator, network, receiver), drop counters | Partial | NIC counters on Linux and Windows (not macOS); AF_XDP ring and capture buffer; DPDK port-wide |
| Run records (`--report` on replay, run, build, tcp, udp, bench, y1564) | Done | M51 |
| Built-in impairments, two-port bridge | Partial | not in `ferotrx bench`; no field in the GUI's stream editor |
| Live capture (`ferotrx capture`, `--capture`, remote captures) | Partial | no copies of frames AF_XDP or DPDK send |

## Stateful traffic

| Feature | Status | Notes |
|---|---|---|
| TCP engine (SACK, window scaling, timestamps, RTO, NewReno, CUBIC, ECN) | Partial | no BBR, Accurate ECN or L4S; no cap on half-open connections in the server |
| TCP templates, rates, concurrency, think time | Done | [stateful-tcp.md](stateful-tcp.md) |
| UDP engine, DNS, NTP | Done | [stateful-udp.md](stateful-udp.md) |
| HTTP/1.1 with response checks | Done | |
| TLS 1.2/1.3, handshake load, resumption | Partial | no hello-only emulation of TLS 1.0/1.1 |
| HTTP/2 | Partial | no server push, priorities or `Upgrade: h2c`; only status checks |
| QUIC and HTTP/3 | Partial | no 0-RTT, migration, QPACK dynamic table, path MTU discovery; only status checks |
| MQTT 3.1.1 and 5 | Done | |
| SSH | Partial | no sftp/scp, forwarding, RSA/ECDSA keys |
| SIP and RTP, call quality (E-model) | Partial | UDP only (no TCP/TLS), no SRTP, DTMF or proxy role |
| SMB 2 and 3 | Partial | no encryption, Kerberos, leases, durable handles |
| Host emulation (DHCP, SLAAC, DHCPv6, IGMP/MLD, RA) | Partial | no ARP probes, prefix delegation, `host.*` control methods |
| DHCP server role (v4, v6) | Partial | no pools per relay, DHCPv6 relay messages or prefix delegation |

## Measurement methods

| Feature | Status | Notes |
|---|---|---|
| RFC 2544 benchmarks | Done | [benchmarking.md](benchmarking.md) |
| Y.1564 service activation | Partial | delay across two machines needs synced clocks; no far-end reflector |
| Scenarios (pass/fail, history, compare, JUnit) | Done | [scenarios.md](scenarios.md) |
| Fleet of agents | Partial | no discovery; no benchmarks, Y.1564, scenarios or hosts in plans; calls not in parallel |

## Control and tools

| Feature | Status | Notes |
|---|---|---|
| Control API (JSON-RPC over TCP, TLS, mTLS, roles, audit) | Done | [remote-control.md](remote-control.md) |
| Revocation (CRL, deny list), traffic guardrails | Partial | pcap readers and run outputs reopen files by path; no limits per user |
| Python client | Done | [python-client.md](python-client.md) |
| Desktop GUI | Partial | no MOS charts |
| Windows app (MSI, service, Npcap) | Done | [windows.md](windows.md) |
| Fuzzing | Done | [fuzzing.md](fuzzing.md) |

## Planned

From the comparison with TRex and Ostinato:
[#105](https://github.com/jkobierczynski/FeroTRX/issues/105) performance
evidence (M52),
[#106](https://github.com/jkobierczynski/FeroTRX/issues/106) to
[#109](https://github.com/jkobierczynski/FeroTRX/issues/109) realism,
tunnels, accurate latency and fleet robustness (M53 to M56).
