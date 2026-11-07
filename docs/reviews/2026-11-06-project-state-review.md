> Outside review of 6 November 2026, written from the documentation at 0.33.0, kept as received.
> What is right, wrong or out of date as of 0.34.0 is in [2026-11-06-review-check.md](2026-11-06-review-check.md).

# FeroTRX --- Project State, Competitive Position and Feature-Gap Report

**Review date:** 6 November 2026\
**Repository:** https://github.com/jkobierczynski/FeroTRX\
**Reviewed version reference:** Cargo package version 0.33.0\
**Review type:** Static review of repository documentation, roadmap and
project metadata

------------------------------------------------------------------------

## 1. Executive summary

FeroTRX has developed beyond the scope of a conventional packet replay
utility. The documented feature set now describes a broad network
traffic engineering and infrastructure-validation platform: traffic
generation, stateful application protocols, host emulation, traffic
impairment, benchmarking, a GUI, Python integration and distributed
agents.

The strongest strategic direction is therefore **network traffic
engineering and infrastructure validation**, rather than raw packet
speed. Throughput remains an important measurement, but it should not
define the product's identity.

The project has a potentially compelling combination:

-   Stateful traffic generation across multiple application protocols.
-   Host and network-behaviour emulation.
-   Traffic impairment and network-condition testing.
-   Performance and service-quality measurement.
-   Scenario-based testing and distributed execution.
-   CLI, Python and GUI workflows.

The main challenge is no longer simply adding protocol names to the
feature list. It is proving that the implemented features are
interoperable, realistic, measurable, reliable under load and
straightforward to use in repeatable infrastructure tests.

**Overall assessment:** FeroTRX has a broad and differentiated
documented feature set. The next phase should prioritize correctness,
interoperability, observability, repeatability and realistic workloads
over accumulating more protocols.

## 2. Scope and confidence

This is a static repository review based on the repository's README,
Cargo metadata, development roadmap and available project documentation.

It is **not** a full source-code security audit, a successful-build
verification, a runtime protocol-conformance test or an independent
physical-NIC benchmark. Roadmap entries marked implemented should be
treated as project claims until validated with automated tests and
external interoperability testing.

The documentation itself has a version mismatch:

  -----------------------------------------------------------------------
  Source                              Version/state observed
  ----------------------------------- -----------------------------------
  `Cargo.toml`                        0.33.0

  README                              Still references 0.25.0

  `DEVELOPMENT.md`                    Documents later milestones, through
                                      the 0.33-era roadmap
  -----------------------------------------------------------------------

This should be corrected. The README is the project's public front door;
it should describe the current release rather than leave prospective
users with an outdated picture.

## 3. Current documented capability

The following is a summary of capabilities described in project
documentation. It should not be interpreted as independent validation of
every implementation.

### Traffic generation and packet handling

-   PCAP/PCAPNG-based traffic input and replay.
-   Layer 2--4 traffic handling, including IPv4 and IPv6.
-   Stateful TCP and UDP traffic generation.
-   Multi-core execution.
-   Linux-oriented high-performance backends, including AF_XDP and
    DPDK-related support.
-   Traffic shaping and impairment mechanisms.

### Application protocols

The documented application-protocol scope includes:

-   HTTP/1.1, HTTPS/TLS and HTTP/2.
-   QUIC and HTTP/3.
-   MQTT.
-   DNS and NTP.
-   SSH.
-   SIP/RTP.
-   SMB.

This is a substantial range. It gives FeroTRX a broader
application-testing angle than tools focused mainly on replaying
captured packets.

### Host and network emulation

Documented host/network capabilities include:

-   DHCPv4 and DHCPv6 server behaviour.
-   Host emulation.
-   SLAAC and multicast-related behaviour, including IGMP/MLD areas.
-   Network traffic and impairment scenarios.

### Measurement and test workflows

The documentation describes:

-   RFC 2544 benchmarking.
-   ITU-T Y.1564 service-activation testing.
-   TCP and application-level timing measurements.
-   RTP quality metrics, including MOS/R-factor-related calculations.
-   Delay, jitter, loss, duplication, reordering, corruption and
    rate-limiting impairments.
-   GUI workflows for protocol profiles, workspaces, benchmarking and
    scenario comparison.
-   CLI, JSON-RPC and Python client interfaces.
-   Distributed agents controlled by a central workflow.

The combination of generation, emulation, impairment and measurement is
more important than any individual protocol feature. It is the
foundation for repeatable end-to-end infrastructure tests.

## 4. Competitive landscape

FeroTRX overlaps with several established projects, but the tools do not
all solve exactly the same problem.

  -----------------------------------------------------------------------
  Tool                    Primary strength        FeroTRX's relative
                                                  position
  ----------------------- ----------------------- -----------------------
  **Cisco TRex**          High-performance        TRex is a serious
                          traffic generation,     performance benchmark.
                          stateful/stateless      FeroTRX's opportunity
                          traffic and scalable    is a more integrated
                          benchmarking            application-aware
                                                  workflow, not an
                                                  unverified claim of
                                                  equivalent line-rate
                                                  performance.

  **Ostinato**            GUI-driven packet       Ostinato is a strong
                          crafting, streams, PCAP usability and
                          workflows, Python and   packet-crafting
                          remote traffic          reference. FeroTRX can
                          generation              differentiate through
                                                  stateful application
                                                  sessions, host
                                                  emulation, impairments
                                                  and integrated test
                                                  scenarios.

  **Tcpreplay**           Efficient replay and    Tcpreplay is a focused
                          manipulation of         replay tool. FeroTRX
                          captured packet traffic aims at a broader
                                                  lifecycle involving
                                                  generated workloads,
                                                  application behaviour
                                                  and measurement.

  **MoonGen**             Low-level               MoonGen is a useful
                          high-performance packet reference for
                          generation using DPDK   performance
                          and LuaJIT, with        engineering. FeroTRX's
                          precise rate control    differentiator is
                          and timestamping        breadth and integrated
                                                  testing rather than
                                                  only low-level packet
                                                  performance.
  -----------------------------------------------------------------------

### Competitive conclusion

FeroTRX should not try to win every category simultaneously.

-   Against **Tcpreplay**, emphasize stateful generation, emulation and
    measurement.
-   Against **Ostinato**, emphasize application workflows, realistic
    clients and repeatable validation scenarios.
-   Against **MoonGen**, emphasize the complete test workflow; continue
    improving and independently measuring performance.
-   Against **TRex**, be precise about performance claims. Do not claim
    comparable 100G/200G/400G performance without repeatable testing on
    equivalent physical hardware and NIC configurations.

A key distinction: replaying packets from a capture is not the same as
creating valid, stateful application sessions. FeroTRX's
application-aware direction is valuable if protocol behaviour is robust
and interoperable.

## 5. Remaining feature gaps

The gaps below are drawn from items explicitly marked incomplete in the
development roadmap, together with engineering priorities that follow
from the platform's intended use.

### 5.1 Protocol completeness

  -----------------------------------------------------------------------
  Area                                Documented remaining work
  ----------------------------------- -----------------------------------
  QUIC / HTTP/3                       0-RTT, connection migration, QPACK
                                      dynamic table and path MTU
                                      discovery

  SSH                                 SFTP/SCP, port forwarding, and
                                      additional key algorithms such as
                                      RSA/ECDSA

  SMB                                 Encryption, Kerberos,
                                      leases/oplocks and durable handles

  SIP/RTP                             SIP over TCP/TLS, SRTP, DTMF, proxy
                                      role and multi-worker media

  DHCPv6                              Relay-message handling and prefix
                                      delegation; more complete
                                      relay/pool behaviour

  TCP congestion control              BBR-like pacing, Accurate ECN and
                                      L4S-related support
  -----------------------------------------------------------------------

These are meaningful gaps, but completing every item is not
automatically the best use of engineering time. Prioritize based on the
target test cases and interoperability demand.

### 5.2 Realistic traffic models

One important gap is the difference between generating protocol traffic
and modelling realistic populations of users or devices.

Useful capabilities include:

-   Configurable session-duration distributions, such as exponential,
    log-normal and heavy-tailed/Pareto.
-   Think-time distributions between user actions.
-   Client arrival and departure patterns.
-   Concurrent-user and concurrent-session targets.
-   Per-persona protocol mixes and workload profiles.
-   Long-lived versus short-lived connection models.
-   Realistic upload/download sizes and request sequences.

A traffic profile should describe behaviour, not merely a packet rate.

Example personas:

-   Office workstation: DNS, HTTPS, SaaS-style requests, file access and
    periodic background traffic.
-   Industrial engineering station: management protocols, occasional
    large transfers and scheduled maintenance activity.
-   IoT device: periodic telemetry, reconnects and broker interactions.
-   Voice endpoint: registration, call setup, call duration and RTP
    quality.
-   Server workload: inbound requests, response sizes and concurrent
    sessions.

### 5.3 Measurement and observability

This is one of the highest-value areas to strengthen.

FeroTRX should make it easy to distinguish between traffic that was
requested, transmitted, received and successfully processed.

Recommended metrics include:

-   Packets and bytes requested, transmitted and received.
-   NIC-level drops and queue errors.
-   Kernel and AF_XDP ring starvation/drop counters.
-   DPDK queue and buffer errors.
-   Application-level failures and protocol timeouts.
-   TCP connection establishment, retransmissions, RTT and goodput.
-   TLS handshake time and failures.
-   HTTP request latency, response status and validation failures.
-   UDP loss, jitter and reordering.
-   SIP call setup and completion statistics.
-   RTP loss, late packets, jitter and MOS/R-factor trends.

The platform should clearly separate **generator-side loss**, **network
loss** and **receiver/application loss**. Without that distinction, test
results can be misleading.

Further improvements:

-   Time-series charts and exportable results.
-   Baseline-versus-current comparisons.
-   Percentiles and confidence intervals, not only averages.
-   Reproducible run metadata: software version, host, NIC, driver,
    backend, CPU affinity and test profile.
-   One-way latency only where clock synchronization and timestamp
    quality justify it.
-   PTP/hardware timestamp support where the target environment supports
    it.

### 5.4 Distributed testing

The distributed-agent architecture is promising, but a controller and
agents are only the starting point.

High-value additions include:

-   Agent discovery and capability reporting.
-   Health checks, reconnect and failure handling.
-   Resource and NIC telemetry from each agent.
-   Coordinated start/stop and explicit clock-synchronization status.
-   Partial-run recovery and clear reporting when an agent fails.
-   Centralized result aggregation.
-   Multi-agent scenario and benchmark support.
-   Topology-aware deployment of clients, servers and traffic sources.

A useful test might place clients on one side of a firewall, servers on
the other, and additional agents on separate network segments to
generate competing workloads and observe the resulting behaviour.

### 5.5 Scenario and workflow depth

FeroTRX should make common infrastructure tests easy to define and
repeat.

Potential scenario templates:

-   Firewall throughput and concurrent-session capacity.
-   NAT/PAT port exhaustion.
-   Firewall or load-balancer failover.
-   VPN throughput and reconnect behaviour.
-   TLS inspection performance.
-   DNS resolver failover and cache behaviour.
-   SD-WAN path changes and application impact.
-   SIP call quality under congestion and packet loss.
-   QUIC connection migration and path changes.
-   DHCP address-allocation capacity.
-   IDS/IPS inspection under mixed application workloads.

Each scenario should define the topology, workload, duration, impairment
conditions, measurements and pass/fail criteria.

### 5.6 Interoperability and robustness

Protocol implementation is not complete merely because a client can
communicate with its own server.

Build a continuous interoperability matrix using independent
implementations, for example:

  Protocol area   Useful external implementations
  --------------- --------------------------------------
  HTTP/TLS        curl, nginx, Apache, OpenSSL, GnuTLS
  HTTP/2          nghttp2-based implementations
  QUIC/HTTP/3     aioquic, quiche, ngtcp2
  MQTT            Mosquitto, EMQX
  SSH             OpenSSH
  SIP/RTP         SIPp, Asterisk, FreeSWITCH
  SMB             Samba and Windows Server
  DNS             BIND, Unbound, CoreDNS

Test both directions where applicable: FeroTRX client against external
server, and external client against FeroTRX server.

Also invest in:

-   Protocol state-machine tests.
-   Malformed-input and parser fuzzing.
-   Long-duration soak tests.
-   Connection churn and resource-leak tests.
-   Cancellation, timeout and reconnect tests.
-   Regression captures for every discovered interoperability bug.

## 6. Performance claims: keep the evidence honest

The multi-core documentation reported sandbox measurements along these
lines:

  Backend/test     One worker   Four workers
  -------------- ------------ --------------
  Null sink          5.8 Mpps        23 Mpps
  AF_XDP copy       0.90 Mpps       3.4 Mpps
  libpcap           0.66 Mpps       1.4 Mpps

These figures are useful as development measurements, but they were
obtained in a four-core sandbox with virtual interfaces. They are
**not** evidence of production physical-NIC throughput or a fair
comparison with TRex or MoonGen.

For credible performance claims, publish reproducible test conditions:

-   Exact NIC model, firmware and link speed.
-   CPU model, core count, NUMA topology and memory configuration.
-   Kernel, driver and backend versions.
-   Packet sizes and traffic profile.
-   Number of queues and worker affinity.
-   Offered load, achieved throughput and loss.
-   Duration, warm-up and repeated-run methodology.

Report both packet rate and bit rate, and include loss and latency. A
headline throughput number without those details is not very
informative.

## 7. Recommended priorities

The recommended roadmap is deliberately selective. Reliability and test
credibility should precede a long tail of protocol features.

### P0 --- Make current capabilities trustworthy

1.  Synchronize README, Cargo version and roadmap.
2.  Create a visible feature-status matrix: implemented, experimental,
    partial and planned.
3.  Add external interoperability tests for the most important
    protocols.
4.  Improve packet/drop/error accounting across NIC, kernel, backend and
    application layers.
5.  Add fuzzing, soak tests and resource-leak tests.
6.  Verify multi-core correctness and repeatability, not just aggregate
    throughput.

### P1 --- Make traffic realistic and results useful

1.  Implement session-duration, think-time and arrival distributions.
2.  Add reusable traffic personas and workload profiles.
3.  Improve application-level assertions and response validation.
4.  Add time-series observability and baseline comparisons.
5.  Make scenario definitions reproducible and exportable.
6.  Add richer per-agent telemetry and failure reporting.

### P2 --- Mature distributed and specialist workflows

1.  Improve agent discovery, health and recovery.
2.  Expand multi-agent scenario execution and result aggregation.
3.  Add the most demanded protocol-completeness items.
4.  Complete GUI support for impairments and quality metrics.
5.  Add remote-reflector and synchronized measurement workflows where
    needed.

## 8. Product positioning

Recommended positioning:

> **FeroTRX --- Network Traffic Engineering and Infrastructure
> Validation**

This communicates a platform rather than a single-purpose speed tool.

The product identity should cover four related activities:

1.  **Generate** --- create packet, protocol and application workloads.
2.  **Emulate** --- represent hosts, clients, services and network
    behaviour.
3.  **Impair** --- introduce controlled loss, delay, jitter and other
    network conditions.
4.  **Validate** --- measure performance, correctness, resilience and
    service quality.

That positioning leaves room for future work in security-appliance
testing, network regression, application-aware testing and distributed
infrastructure validation.

## 9. Final assessment

FeroTRX's strongest opportunity is not to become another generic packet
generator. It is to become a practical, application-aware network
testing platform that combines traffic generation, host emulation,
impairments, measurement and repeatable scenarios.

The project already documents a broad feature set. The next competitive
leap will come from demonstrating that those features work together
reliably:

-   Realistic workloads rather than synthetic packet counts alone.
-   Independent protocol interoperability rather than self-to-self tests
    alone.
-   Accurate loss and latency accounting rather than headline throughput
    alone.
-   Repeatable scenarios rather than one-off command lines.
-   Distributed test orchestration with useful failure and health
    reporting.

**The immediate recommendation:** focus the next development cycle on P0
reliability and evidence, then build traffic realism and observability.
Avoid adding many more protocols until the existing ones are
demonstrably robust.

------------------------------------------------------------------------

## 10. Reference links

-   FeroTRX repository: https://github.com/jkobierczynski/FeroTRX
-   FeroTRX development roadmap:
    https://github.com/jkobierczynski/FeroTRX
-   Cisco TRex: https://trex-tgn.cisco.com/
-   TRex source:
    https://github.com/cisco-system-traffic-generator/trex-core
-   Ostinato: https://ostinato.org/
-   Ostinato features: https://ostinato.org/features
-   Tcpreplay: https://tcpreplay.appneta.com/
-   Tcpreplay source: https://github.com/appneta/tcpreplay
-   MoonGen source: https://github.com/emmericp/moongen
