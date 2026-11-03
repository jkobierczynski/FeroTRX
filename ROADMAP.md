# FeroTRX roadmap

What is still to do, grouped by priority and split into milestones. Each
milestone bumps the minor version (see [RELEASING.md](RELEASING.md)); 0.4.0
(M11, IPv6) is the current release.

This list started from an outside priorities review (3 November 2026) checked
against the code at 0.4.0. Things the review asked for that FeroTRX already
has are listed at the end, so they are not planned twice. The review itself is in
[docs/priorities-report-2026-11.md](docs/priorities-report-2026-11.md).

Tick a box in the pull request that does the work.

## P0: correctness of stateful TCP

### M12, TCP maturity (0.5.0)

- [ ] TCP window scaling (RFC 7323), negotiated in the handshake, so a
      connection can keep more than 64 KB in flight
- [ ] TCP timestamps and PAWS (RFC 7323)
- [ ] SACK (RFC 2018): send SACK blocks, and retransmit only the holes
- [ ] Configurable send/receive windows, `rto`, `idle_timeout` and SYN
      retries in TCP profiles and on the command line (they exist in the
      engine's options but are not all exposed)
- [ ] Per-template rates: `cps`, `connections` and `concurrency` per
      `[[template]]`, under the run-wide limits
- [ ] Document what the engine does for congestion control (slow start,
      fast retransmit, backoff) and what it does not try to be
- [ ] Tests: a large bandwidth-delay path (netem delay + rate) that shows more
      than 64 KB in flight; loss, duplication and reordering in the netns
      scripts; IPv4 and IPv6

## P0: secure the control plane

### M13, secure remote control (0.6.0)

- [ ] TLS for `serve`/`ctl` (rustls), so the token no longer travels in clear
      text; optional mutual TLS with client certificates
- [ ] Two roles: read-only (`server.info`, stats, subscriptions) and operator
      (load profiles, start/stop runs), each with its own token or certificate
- [ ] Restrict files: profiles and pcaps only from configured directories,
      uploads size-limited
- [ ] Limits: connections, request size, idle timeout
- [ ] Audit log of logins, profile loads/uploads and run start/stop
- [ ] Refuse to listen on a non-loopback address without a token (or TLS)
      unless `--insecure` is given
- [ ] Threat model and deployment notes in the README

## P1: trustworthy measurements

### M14, benchmarking (0.7.0)

- [ ] Packet-size distributions and IMIX presets for built and varied packets
- [ ] RFC 2544-style tests: throughput by binary search on the rate (with a
      loss threshold), frame loss at set rates, latency at a set rate,
      back-to-back bursts
- [ ] Warm-up, repetitions and stop conditions in a benchmark profile
- [ ] Reports carry offered vs achieved rate, and run metadata: FeroTRX
      version, backend, interface, driver, NIC, CPU, kernel, the profile used
- [ ] Human-readable report next to the JSON one
- [ ] Document the measurement method and its limits (timestamp source,
      clock sync, 28-byte signature growth)
- [ ] Optional: receive through AF_XDP for rates libpcap cannot keep up with

## P1: more session types

### M15, stateful UDP and transactions (0.8.0)

- [ ] UDP client/server sessions from captures or `[[message]]`, like TCP
      templates: response matching, timeouts, retries
- [ ] Per-template transaction rate, concurrency and think time
- [ ] DNS as the first workload (queries, common record types, error
      responses), then NTP and user-defined request/response
- [ ] Counters per template: sent, answered, timed out, unmatched
- [ ] Application message timing for TCP replay (`--keep-timing`: the gaps
      between messages in the capture), plus think time between messages

## P2: the differentiator

### M16, scenario and regression tests (0.9.0)

- [ ] Scenario files: a list of checks, each a stateless, TCP or UDP run with
      an expected outcome (completes, is blocked, loss under X, latency under
      Y, throughput over Z)
- [ ] Pass/fail per check and overall exit code, JUnit/JSON output for CI
- [ ] Run history and comparing two runs (before/after a firewall change,
      two devices, IPv4 vs IPv6 policy)
- [ ] Example scenario run through the netns router in CI

## P2: later, by demand

- [ ] Stateful TCP over AF_XDP (and DPDK), for higher connection rates
- [ ] Traffic models: bursts, Poisson arrivals, ramp-up/down, session length
      distributions
- [ ] Host emulation: DHCP client, gratuitous ARP, router advertisements,
      IGMP/MLD joins
- [ ] Python client package for the control API (beyond
      `examples/ctl-client.py`)
- [ ] Profile validation command (`ferotrx check profile.toml`) and a
      profile format version field
- [ ] TLS handshake generation (new sessions, not replayed ones), then
      HTTP/1.1 request/response workloads with success checks

## P3: when the engine is stable

- [ ] Distributed agents: a controller that deploys profiles, starts agents
      together and adds up their stats
- [ ] GUI as another client of the control API

## Not planned for now

A packet-analysis suite (use Wireshark), a long list of shallow protocols,
DPDK as the main backend, Kubernetes orchestration, full network simulation.

## Already there (from the review's list)

- IPv6 stateful TCP with neighbor discovery (M11)
- Loss, duplicates, reordering, latency percentiles (p50/p99/p99.9) and
  RFC 3550 jitter on the receive side, with a JSON report (M9)
- Multi-template TCP with weights and per-template counters (M10)
- Retransmission with exponential backoff, fast retransmit on three duplicate
  ACKs, idle timeout, completed/reset/timed-out/mismatched counters (M8)
- Control server binds to 127.0.0.1 by default (M5)

Note: FeroTRX measures loss, duplication, reordering and latency; it does not
inject them. Impairment is done with netem in the lab scripts.
