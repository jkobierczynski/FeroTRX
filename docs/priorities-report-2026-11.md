> Outside review written on 3 November 2026 from the README at 0.3.0, kept as received.
> Some points were already done by then (IPv6 stateful TCP, receive-side percentiles);
> see [DEVELOPMENT.md](../DEVELOPMENT.md) and issues #15 to #21 for the checked to-do list.

# FeroTRX Priorities Report

**Project:** [FeroTRX](https://github.com/jkobierczynski/FeroTRX)\
**Report date:** 3 November 2026\
**Purpose:** Competitive positioning, feature-gap assessment, and
recommended implementation priorities

------------------------------------------------------------------------

## 1. Executive summary

FeroTRX has the foundations of a capable Rust-based traffic replay and
generation engine. Its documented feature set already goes beyond simple
PCAP replay: it combines packet rewriting, stateless generation,
multi-stream profiles, impairment simulation, remote control, and
stateful TCP functionality, with multiple transmission backends.

The main risk is not a lack of features in general. It is the gap
between an ambitious feature surface and the level of protocol
completeness, security, repeatability, and measurement quality expected
from a tool used to validate production network equipment.

**Recommended direction:** make FeroTRX a dependable,
automation-friendly open-source alternative to TRex for focused network
testing, while retaining the usability and simplicity associated with
Tcpreplay. The strongest longer-term differentiator is network-appliance
regression testing: repeatable scenarios that test whether firewalls,
routers, load balancers, IDS/IPS platforms, and network changes behave
as expected.

The recommended order is:

1.  Complete and harden stateful TCP.
2.  Secure the remote-control plane.
3.  Add stateful UDP and a small number of useful application protocols.
4.  Build trustworthy, repeatable benchmark reporting.
5.  Improve per-template traffic control and scenario orchestration.
6.  Add realistic traffic scheduling and host/network emulation.
7.  Introduce distributed agents only after single-host results are
    reliable.
8.  Add a GUI when the engine, data model, and workflows have
    stabilized.

A broad protocol checklist or a sophisticated GUI should not take
precedence over correctness and trustworthy measurements.

## 2. Competitive landscape

FeroTRX overlaps with several established tools, but no single
competitor is a perfect one-to-one match.

  -----------------------------------------------------------------------
  Tool                    Main strength           What FeroTRX should
                                                  learn from it
  ----------------------- ----------------------- -----------------------
  **Cisco TRex**          High-performance        Stateful traffic depth,
                          stateless and stateful  scalable flow models,
                          traffic generation,     Python-driven testing,
                          including ASTF          and performance
                          application traffic and methodology
                          automation              

  **Tcpreplay**           Straightforward PCAP    Simple and predictable
                          replay, packet editing, PCAP workflows;
                          replay-rate control,    low-friction CLI
                          and interface-based     experience
                          workflows               

  **Ostinato**            GUI-oriented packet     Stream editing,
                          crafting, stream        approachable workflows,
                          configuration, traffic  and visibility into
                          generation, and         traffic configuration
                          automation              

  **MoonGen**             High-performance packet Performance-oriented
                          generation built around architecture and
                          DPDK and programmable   flexible
                          traffic logic           traffic-generation
                                                  primitives

  **Scapy**               Flexible packet         Extensibility and
                          construction, protocol  protocol-specific
                          experimentation, and    packet manipulation
                          scripting               
  -----------------------------------------------------------------------

### Positioning

Three plausible positions exist:

-   **Modern Tcpreplay replacement:** the most achievable near-term
    position. Emphasize robust PCAP/PCAPNG replay, manipulation,
    repeatability, and a good CLI.
-   **Lightweight open-source TRex alternative:** the strongest overall
    opportunity. Focus on a usable stateful engine, traffic profiles,
    automation, and credible performance measurements without trying to
    match every TRex feature.
-   **Network-appliance validation platform:** the most differentiated
    long-term position. Add scenario-based testing and comparative
    validation for firewalls, routers, IDS/IPS, NAT, QoS, and load
    balancers.

The second position is the best product target; the third is the best
differentiator to build toward.

## 3. Current documented capability baseline

The project README describes a substantial feature set, including:

-   PCAP and PCAPNG replay.
-   Original-timing replay and rate controls such as multiplier, PPS,
    and Mbps.
-   IPv4 and IPv6 stateless traffic replay/generation.
-   MAC, IP, and port rewriting.
-   VLAN and QinQ manipulation.
-   Per-packet field variation and multi-stream profiles.
-   Packet construction, inspection, and checksum handling.
-   JSON-RPC remote control.
-   Multiple transmission paths, including AF_XDP and DPDK, as well as
    libpcap/Npcap.
-   Traffic impairment features such as loss, duplication, reordering,
    and latency.
-   Stateful TCP client/server emulation and multi-template TCP
    profiles.
-   IPv6 support in stateless traffic paths.

### Documented stateful TCP limitations

The README also identifies limitations that should be treated as
important engineering work:

-   No TCP window scaling.
-   No SACK support.
-   No TCP timestamps/PAWS support.
-   A 64 KB maximum in-flight window per connection.
-   No preservation of original application-message timing in stateful
    replay.
-   Stateful TCP restricted to IPv4.
-   Stateful TCP restricted to the libpcap/Npcap transmission path.

These limitations matter because stateful traffic can appear to work in
simple tests while behaving unlike real endpoints under higher
bandwidth-delay products, packet loss, retransmission, or IPv6-only
conditions.

**Evidence boundary:** this baseline is based on documented project
capabilities and limitations, not a fresh source-code audit or
independently measured performance test. Treat the priorities below as a
product and engineering assessment, not proof that a particular
implementation is absent or defective in every code path.

## 4. Prioritized feature gaps

Priority definitions:

-   **P0 --- Critical:** address before positioning the tool as
    production-ready for serious stateful testing or remote operation.
-   **P1 --- High:** core capability needed to compete credibly as a
    general-purpose traffic-testing tool.
-   **P2 --- Medium:** substantial value, but should follow protocol
    correctness and measurement reliability.
-   **P3 --- Later:** useful expansion after the core product is stable.

### P0 --- Complete stateful TCP

**Why it matters:** Stateful TCP is a major dividing line between a
packet replay utility and a credible traffic-testing platform. Missing
TCP mechanisms can distort results or cause failures that are artifacts
of the generator rather than the device under test.

Recommended work:

1.  Implement TCP window scaling and configurable receive/send windows.
2.  Add SACK support and robust retransmission/recovery behavior.
3.  Add TCP timestamps and PAWS handling.
4.  Remove or clearly document the 64 KB in-flight limitation; support
    realistic windows where the architecture permits.
5.  Add configurable connection establishment, idle, retransmission, and
    teardown timeouts.
6.  Add congestion-control behavior or clearly defined
    traffic-generation semantics where full endpoint congestion control
    is not intended.
7.  Add IPv6 stateful TCP.
8.  Support stateful TCP across the relevant high-performance transmit
    backends, or document precisely why a backend cannot support it.
9.  Add application-message timing and think-time controls for stateful
    replay.
10. Test behavior under loss, duplication, reordering, latency,
    asymmetric paths, and large bandwidth-delay products.

**Acceptance criteria:**

-   Interoperability tests against common operating systems and network
    stacks.
-   Tests covering loss, reordering, retransmission, SACK, timestamps,
    and window scaling.
-   IPv4 and IPv6 test coverage.
-   Large-window tests that demonstrate behavior beyond the current 64
    KB ceiling where supported.
-   Repeatable results with clear counters for connection attempts,
    successes, failures, resets, retransmissions, and timeouts.

### P0 --- Secure the remote-control plane

**Why it matters:** a remote interface that can configure or initiate
packet transmission is a high-impact control surface. The README
documents an authentication token being sent in cleartext. That is not
an acceptable default for a service exposed beyond a tightly controlled
local test environment.

Recommended work:

1.  Use TLS for remote control; support mutual TLS for managed
    deployments.
2.  Replace shared, weakly scoped tokens with managed credentials.
3.  Add role-based access control, at minimum separating read-only
    monitoring from configuration and traffic execution.
4.  Add audit logs for authentication, configuration changes, profile
    uploads, and traffic start/stop actions.
5.  Restrict access to interfaces, files, and profile operations.
6.  Add connection limits, request limits, and sensible timeouts.
7.  Bind to loopback by default, or require an explicit configuration
    step before listening on non-local interfaces.
8.  Document the threat model and secure deployment configuration.

**Acceptance criteria:**

-   No credentials or tokens transmitted in cleartext.
-   Secure-by-default listener behavior.
-   Tests for authentication, authorization, and rejected operations.
-   Auditable records of control-plane actions.
-   Clear documentation of privilege requirements and network exposure.

### P1 --- Stateful UDP and application transactions

**Why it matters:** many useful network tests are request/response
workloads rather than raw packet streams or long-lived TCP connections.
UDP is also important for DNS, NTP, DHCP, monitoring, and many
industrial and infrastructure protocols.

Recommended work:

1.  Add UDP client/server sessions.
2.  Support request and response templates.
3.  Add response matching, timeouts, retries, and per-session state.
4.  Track transactions per template and per flow.
5.  Support configurable transaction rate, concurrency, and think time.
6.  Add source/destination address and port pools.
7.  Start with DNS as the first application-level workload, then add NTP
    and generic user-defined UDP transactions.
8.  Keep protocol logic modular so additional protocols do not become
    tightly coupled to the core engine.

**Acceptance criteria:**

-   Correct transaction accounting, including timeouts and unmatched
    responses.
-   Configurable concurrency and request rate.
-   Reproducible client/server tests.
-   DNS query/response tests covering common record types and error
    responses.

### P1 --- Standardized benchmarking and reporting

**Why it matters:** traffic generation is only half the job. Users need
to know whether the device under test forwarded the offered traffic
correctly, and whether a result can be reproduced and compared.

Recommended work:

1.  Implement RFC 2544-style test workflows: throughput, frame loss,
    latency, and back-to-back tests.
2.  Add IMIX and configurable packet-size distributions.
3.  Support rate-search procedures for maximum sustainable throughput.
4.  Record offered load, transmitted packets/bytes, received
    packets/bytes where available, loss, latency, jitter, and errors.
5.  Report latency percentiles, not just averages, where measurement
    methodology supports them.
6.  Record test duration, warm-up, repetitions, and stop conditions.
7.  Capture test configuration, software version, backend, NIC, driver,
    CPU, and relevant system details.
8.  Export machine-readable JSON and human-readable reports.
9.  Make measurement limitations explicit, especially where
    transmit-only operation cannot independently establish receive-side
    loss or latency.

**Acceptance criteria:**

-   A benchmark can be repeated from a saved configuration.
-   Results include enough metadata to compare runs honestly.
-   The tool distinguishes offered load from achieved throughput.
-   Measurement methodology and limitations are documented.
-   Automated tests validate report generation and calculations.

### P1 --- Stronger per-template traffic control

**Why it matters:** multiple templates are much more useful when each
can represent a distinct workload with independent controls. Otherwise,
profiles risk becoming collections of packets rather than composable
test scenarios.

Recommended work:

-   Per-template connections per second, concurrency, bandwidth, and
    packet rate.
-   Weighted scheduling and fair allocation.
-   Independent start, stop, pause, and ramp controls.
-   Per-template source and destination pools.
-   Per-template counters and error reporting.
-   Think time, session duration, and transaction-rate controls.
-   Explicit profile validation before execution.

**Acceptance criteria:**

-   Each template can be configured and measured independently.
-   Aggregate limits and per-template limits behave predictably.
-   Scheduling is deterministic enough for repeatable tests.
-   Invalid or conflicting profiles fail early with actionable errors.

### P2 --- Application protocol support

Add protocols based on practical demand, not the length of the protocol
list.

Suggested order:

1.  HTTP/1.1 request/response workloads.
2.  TLS handshake and HTTPS workload support.
3.  DNS, if not already covered by the stateful UDP milestone.
4.  SSH and other common TCP service patterns where useful.
5.  DHCP, SIP/RTP, MQTT, SMB, and other protocols based on user demand.
6.  HTTP/2 and QUIC/HTTP/3 only when the underlying session model is
    mature enough.

Be precise about the distinction between replaying encrypted application
traffic from a capture and generating new TLS sessions or application
transactions. They are different capabilities with different
implementation and measurement requirements.

**Acceptance criteria:**

-   Protocol modules use a common session/transaction interface.
-   Application success and failure are observable, not inferred only
    from packet counts.
-   Protocol behavior is configurable and testable.
-   Unsupported protocol semantics are documented rather than silently
    approximated.

### P2 --- Host and network emulation

Useful network tests often require more than sending packets from one
interface. FeroTRX could progressively model endpoint identities and
basic network behavior.

Potential capabilities:

-   Virtual MAC and IP address pools.
-   VLAN-aware endpoint profiles.
-   ARP and gratuitous ARP behavior.
-   IPv6 neighbor discovery and router advertisements.
-   DHCP client/server behavior.
-   IGMP/MLD membership behavior.
-   Basic gateway and endpoint response behavior.

Avoid turning this into a full network simulator. Implement only the
endpoint and control-plane behavior needed by realistic test scenarios.

### P2 --- Realistic traffic scheduling

Add traffic models that represent how real systems behave:

-   Bursts and multi-burst patterns.
-   Poisson or other configurable arrival distributions.
-   Inter-packet timing distributions.
-   Ramp-up and ramp-down.
-   Session duration distributions.
-   Think time and idle periods.
-   Packet-size distributions.
-   Conditional start/stop rules.

These capabilities are valuable, but should follow the core session and
measurement model. Otherwise, the tool risks offering sophisticated
traffic patterns whose results are difficult to interpret.

### P3 --- Distributed traffic generation

Distributed agents can increase scale and allow multi-site or
multi-interface scenarios, but they add operational complexity.

Recommended design:

-   A controller that owns test definitions and result aggregation.
-   Agents that execute assigned workloads.
-   Version and capability negotiation.
-   Profile deployment and integrity checking.
-   Synchronized starts and explicit clock-skew reporting.
-   Per-agent health and interface status.
-   Aggregated and per-agent statistics.
-   Clear handling of partial agent failure.

Do not make distributed execution a prerequisite for a reliable
single-host product.

### P3 --- GUI and visual management

A GUI could improve accessibility, but it should be built on a stable
engine and profile model.

Useful GUI features eventually include:

-   Stream and packet-profile editor.
-   Scenario builder.
-   Live throughput, loss, latency, and connection graphs.
-   Per-template and per-flow statistics.
-   Run history and result comparison.
-   Interface and agent status.
-   Exportable reports.

Keep the CLI and Rust library first-class. A GUI should be another
client of the same engine and configuration model, not a separate
implementation of traffic behavior.

## 5. The strongest differentiator: network-appliance regression testing

The most interesting opportunity is to make FeroTRX useful not only for
generating load, but also for answering a practical question:

**Did this network device or configuration change break anything?**

Build a scenario layer above the traffic engine. A scenario should
define:

-   Topology and interfaces.
-   Source and destination identities.
-   Traffic templates and rates.
-   Expected application outcomes.
-   Expected forwarding or blocking behavior.
-   Performance thresholds.
-   Duration and repetition.
-   Pass/fail conditions.
-   Evidence and result artifacts.

Example scenario:

  -----------------------------------------------------------------------
  Test                                Expected result
  ----------------------------------- -----------------------------------
  HTTP from approved zone to          Succeeds
  application zone                    

  DNS to approved resolver            Succeeds

  SSH from user zone to management    Blocked
  zone                                

  Throughput under defined IMIX load  Above configured threshold

  Latency under load                  Below configured threshold

  IPv6 policy equivalent to IPv4      Same intended security outcome
  policy                              
  -----------------------------------------------------------------------

Potential test targets include:

-   Firewall policy and NAT changes.
-   IDS/IPS inspection behavior.
-   QoS and traffic shaping.
-   Load-balancer health and persistence.
-   High-availability failover.
-   Firmware upgrades.
-   Firewall migrations, including before/after comparisons.
-   IPv4/IPv6 policy consistency.

### Differential testing

A particularly valuable feature would be running the same scenario
against two devices or two configurations and comparing:

-   Packet loss.
-   Throughput.
-   Latency distribution.
-   TCP connection completion.
-   Application transaction success.
-   Connection setup rate.
-   Policy outcomes.

This is directly useful for firewall migrations, firmware upgrades,
configuration changes, and vendor comparisons. It could become a
stronger differentiator than simply supporting more packet formats.

## 6. Recommended roadmap

The following is a capability-oriented roadmap. The milestones are
suggested sequencing, not estimates of calendar duration.

  ------------------------------------------------------------------------
  Milestone               Focus                   Exit condition
  ----------------------- ----------------------- ------------------------
  **0.5**                 Stateful TCP maturity   Robust IPv4/IPv6 TCP
                                                  behavior, documented
                                                  limits, interoperability
                                                  and impairment tests

  **0.6**                 Security and automation TLS/mTLS, authorization,
                                                  audit logging, stable
                                                  API, Python SDK, JSON
                                                  result output

  **0.7**                 Stateful UDP and        UDP sessions, DNS
                          application             workload, per-template
                          transactions            rates, transaction
                                                  accounting

  **0.8**                 Benchmarking            Repeatable throughput,
                                                  loss, latency, jitter,
                                                  and IMIX workflows with
                                                  machine-readable reports

  **0.9**                 Advanced traffic and    Scheduling models,
                          network emulation       address pools, and
                                                  selected
                                                  endpoint/control-plane
                                                  behavior

  **1.0**                 Appliance regression    Scenario definitions,
                          testing                 pass/fail rules, run
                                                  history, and
                                                  differential results

  **1.x**                 Scale and usability     Distributed agents,
                                                  richer GUI, and
                                                  additional application
                                                  protocols based on
                                                  demand
  ------------------------------------------------------------------------

### Suggested release gates

Do not declare a milestone complete merely because a command-line option
exists. Require:

-   Automated tests.
-   Documented semantics and limitations.
-   Reproducible examples.
-   Performance measurements where relevant.
-   Backward-compatibility decisions for profile formats and APIs.
-   Security review for control-plane changes.

## 7. What not to prioritize yet

The following are tempting, but have a poor return until the core engine
is more mature:

-   Replacing Wireshark or implementing a comprehensive packet-analysis
    suite.
-   Supporting every application protocol.
-   Building a large GUI before the configuration and result models
    stabilize.
-   Making DPDK the only supported or preferred architecture.
-   Kubernetes orchestration before single-host and agent execution are
    dependable.
-   AI-generated traffic as a headline feature.
-   Full network simulation.

FeroTRX should integrate with established analysis tools and formats
where possible rather than trying to replace them.

## 8. Suggested engineering principles

1.  **Separate engine, protocol, scenario, and interface layers.** Keep
    the Rust engine reusable by the CLI, API, Python bindings, and
    future GUI.
2.  **Make test definitions declarative.** Profiles should be versioned,
    validated, reviewable, and reproducible.
3.  **Treat measurement as a first-class feature.** Every performance
    claim needs a stated methodology and known limitations.
4.  **Make security defaults conservative.** Remote packet injection and
    traffic control deserve the same care as other privileged management
    interfaces.
5.  **Prefer a few complete protocols over many superficial ones.** A
    correct HTTP or DNS workload is more valuable than a long list of
    protocol names with limited semantics.
6.  **Keep performance claims evidence-based.** Publish reproducible
    benchmarks with hardware, NIC, driver, backend, packet sizes, and
    test configuration.
7.  **Use differential testing internally.** Compare FeroTRX output and
    behavior against established tools and known-good endpoints where
    practical.

## 9. Qualitative assessment

The following scores are directional judgments based on the documented
feature set, not measured benchmark results or a source-level audit.

  ------------------------------------------------------------------------
  Area                                    Assessment Comment
  --------------------- ---------------------------- ---------------------
  Technical ambition                          8.5/10 Broad scope for a
  and breadth                                        relatively young
                                                     project

  Stateless generation                          9/10 Strong documented
                                                     feature coverage

  Packet manipulation                           9/10 Useful rewriting and
                                                     variation
                                                     capabilities

  Performance                                   8/10 Multiple transmit
  architecture                                       paths are promising;
                                                     independent
                                                     benchmarking is
                                                     needed

  Stateful TCP maturity                         7/10 Useful foundation,
                                                     but documented
                                                     protocol limitations
                                                     remain

  Benchmarking and                              6/10 Needs more
  reporting                                          standardized,
                                                     repeatable
                                                     measurement workflows

  Automation                                    8/10 Remote control is
                                                     useful; security and
                                                     higher-level
                                                     SDK/workflow maturity
                                                     matter

  Production readiness                          6/10 Security, protocol
                                                     edge cases, and
                                                     measurement
                                                     confidence need
                                                     attention

  Differentiation                               9/10 Appliance regression
  potential                                          and differential
                                                     testing are promising
  ------------------------------------------------------------------------

## 10. Final recommendation

Do not try to beat TRex by implementing every feature it has. That is a
long and expensive path, and it risks producing a broad but shallow
tool.

Instead:

1.  Make stateful TCP dependable.
2.  Secure the control plane.
3.  Add stateful UDP and a small set of useful application workloads.
4.  Make benchmarks repeatable and results trustworthy.
5.  Build scenario-based network-appliance regression testing on top of
    the engine.

The product should be the **Rust traffic engine and its declarative test
model**. The CLI, remote controller, Python SDK, and eventual GUI should
all be interfaces to that same core.

That gives FeroTRX a credible near-term identity as a modern,
automation-friendly traffic replay and generation tool, while creating a
path toward a more distinctive open-source network validation platform.

------------------------------------------------------------------------

## References

-   [FeroTRX GitHub
    repository](https://github.com/jkobierczynski/FeroTRX)
-   [Tcpreplay documentation](https://tcpreplay.appneta.com/)
-   [Ostinato](https://ostinato.org/)
-   [Cisco TRex](https://trex-tgn.cisco.com/)
-   [Cisco TRex GitHub
    repository](https://github.com/cisco-system-traffic-generator/trex)
-   [MoonGen](https://github.com/emmericp/MoonGen)
-   [Scapy documentation](https://scapy.readthedocs.io/)
-   [RFC 2544 --- Benchmarking Methodology for Network Interconnect
    Devices](https://www.rfc-editor.org/rfc/rfc2544)

*Prepared from the project capabilities and limitations documented in
the README and the comparative assessment described in the accompanying
conversation. Revalidate the implementation against the current
repository before using this report as a formal release or security
sign-off.*
