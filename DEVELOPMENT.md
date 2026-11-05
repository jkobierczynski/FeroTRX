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
`ferotrx-ctl` is the JSON-RPC remote control, `ferotrx-cli` is the
`ferotrx` command, and `ferotrx-gui` is a desktop client of the control API. The CLI, the control server and your own programs all use
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
| M13, secure remote control | TLS (rustls) and mutual TLS for `serve`/`ctl`, read-only and operator roles by token, tokens file or client CA, data directories for profiles, pcaps and outputs, upload/request/connection limits, idle and login timeouts, JSON-lines audit log, no open listener on the network without a login (`--insecure`), `ferotrx certs` lab CA; threat model and deployment notes in docs/remote-control.md | #24 | 0.6.0 |
| M15, stateful UDP and transactions | Sans-IO UDP engine with both ends emulated: sessions from captures or `[[message]]`, response matching, timeouts, retries, server sessions that answer repeats; DNS (queries, A/AAAA/CNAME/MX/TXT/NS/PTR/SRV/SOA, NXDOMAIN and error responses), NTP; per-template `rate`, `transactions`, `concurrency`, `think_time`; counters sent/answered/timed out/unmatched with response times; `ferotrx udp`, UDP profiles, `udp.*` control methods; TCP `--keep-timing` and `--think-time`; [docs/udp-engine.md](docs/udp-engine.md); `scripts/udp-netns.sh` with a `dig` check | #26 | 0.8.0 |
| M14, benchmarking | `ferotrx bench`: RFC 2544 throughput (binary search on the rate with a loss threshold), latency, frame loss and back-to-back; frame sizes and size mixes (IMIX, weighted, random) also in profiles and on `replay`/`build`; signatures that keep the frame size; warm-up, repetitions, stop conditions in a benchmark profile; offered against achieved rates and run metadata (version, kernel, CPU, sender, drivers, NICs, profile) in JSON and text reports; [docs/benchmarking.md](docs/benchmarking.md); `scripts/bench-netns.sh` | #25 | 0.8.0 |
| M16, scenario and regression tests | Scenario files: checks that each run TCP, UDP or streams with a receiver, from profile files or inline, with an expected outcome (`complete`, `blocked`) and conditions on metrics with units (`loss_pct < 1%`, `latency_p99 < 20ms`, `rx_mbps > 50Mbit/s`); variables (`--set`); attempts for jittery labs; pass/fail/error per check and the exit code; JSON and JUnit XML reports; run history and comparisons (regressed, fixed, metrics that moved, `--strict`, `--baseline`); `ferotrx scenario run/show/compare/history/metrics`; `ferotrx_ctl::LabRunner`; [docs/scenarios.md](docs/scenarios.md); `scripts/scenario-netns.sh` (a firewall change caught) | #28 | 0.9.0 |
| M17, traffic models and file checks | Traffic models for streams (`model`, `shape`, `--model`): Poisson arrivals, bursts that keep the mean rate, ramps up/hold/down and rate shapes from points (exact, with a quadratic solve per piece), a ramp that ends ends the stream; the same for TCP connections and UDP transactions (top level and per template with its own rate); `ferotrx check` for every kind of file (captures read, packets built, engines set up; summary, warnings, `--strict`, `--kind`); `format = 1` version field in all files; `StreamInfo.model` in the control API; [docs/traffic-models.md](docs/traffic-models.md); `examples/lab-models.toml` | #29 | 0.10.0 |
| M18, stateful TCP and UDP over AF_XDP and DPDK | AF_XDP ports that receive: an XDP program loaded with raw `bpf()` calls (MAC map, XSKMAP, BPF link, driver or generic mode), one full-duplex AF_XDP socket per receive queue, broadcasts and multicasts through a filtered AF_PACKET socket with VLAN tags put back; DPDK ports that receive (promiscuous, burst copy-out in the C shim); `ferotrx_io::open_port_with` and `PortSettings`, `PacketPort::describe`; `-B/--xdp-mode/--queue/--batch/--dpdk-args` and `[output]` for `ferotrx tcp` and `ferotrx udp`, the same fields and `ports` in `tcp.*`/`udp.*`; timer queues instead of per-millisecond scans in the TCP and UDP engines (about 13k to 25k cps for the engine alone); AF_XDP and DPDK runs of the NAT lab scripts in CI; [docs/fast-ports.md](docs/fast-ports.md); `engine_rate` example | #30 | 0.11.0 |
| M19, host emulation | `HostEngine` (sans-IO) and `ferotrx host`: DHCPv4 clients (discover/offer/request/ack, renew at T1, rebind at T2, release, NAK handling), SLAAC (router solicitations, EUI-64 addresses from advertised prefixes, duplicate address detection), DHCPv6 (IA_NA solicit/advertise/request/reply, renew, rebind, release; gateway from router advertisements), gratuitous ARP and unsolicited neighbor advertisements, IGMPv1-3 and MLDv1-2 joins, query answers with version fallback, leaves, per-group receive counters, solicited-node MLD reports, IPv6 router advertisements (prefixes, M/O flags, lifetime, answers to solicitations); host profiles (`[[host]]` with `count`, `[host.router]`, `[options]`); `Hosted` in front of the TCP and UDP engines: `ip = "dhcp"`/`"slaac"`/`"dhcpv6"`, `announce`, `groups`, `hostname` for a client or server and a `[hosts]` table, `--client-ip dhcp`, `--client-join`, `--announce`; `hosts` in `tcp.*`/`udp.*` run info; `ferotrx check` for host profiles; [docs/host-emulation.md](docs/host-emulation.md); `scripts/hosts-netns.sh` (dnsmasq, a bridge with IGMP/MLD snooping) in CI over IPv4/IPv6, libpcap and AF_XDP | #31 | 0.12.0 |
| M20, one run on several cores | `--workers N` (and `workers` in `[output]`, `run.start`, `tcp.start`, `udp.start`) for `replay`, `build`, `run`, `bench`, `tcp` and `udp`: streams split packet by packet over worker threads (`Stream::shard`: packet `i` from worker `i mod N`, sources and the field engine skip the others' packets, rates and limits shared out, latency sequence numbers kept), one libpcap handle or AF_XDP queue per worker (`Output::open_workers`), `Job::spawn_workers`; stateful TCP and UDP split by flow (`TcpConfig::split`/`UdpConfig::split`: a slice of the client's source ports, rates, limits and a seed per worker, the same servers everywhere), `FlowRouter` (client ports by slice, server flows by hash, ARP requests/solicitations/pings to worker 0, replies and advertisements to all), AF_XDP ports split by receive queue (`PacketPort::split`), shared ports with one reader for libpcap and DPDK, `PortJob::spawn_workers`, counters added up (`MergeStats`); `workers` in run info; `QUEUES=` in the TCP and UDP lab scripts and multi-worker lab runs in CI; [docs/multi-core.md](docs/multi-core.md); `engine_rate` takes a worker count | #34 | 0.14.0 (merged after M21; 0.13.0 not released on its own) |
| M21, Python client | `python/`: the `ferotrx` package (pip-installable, standard library only, Python 3.10+, `py.typed`): blocking `Client` (thread-safe) and asyncio `AsyncClient` (concurrent calls, several live subscriptions) for every control method (`profile.*`, `run.*`, `tcp.*`, `udp.*`, `rx.*`, `stats.*`), uploads of local profiles, `watch()` and `wait()` helpers, TLS, client certificates and tokens (also from `FEROTRX_*` like `ferotrx ctl`), dataclass results that keep unknown fields, an exception per error code; [docs/python-client.md](docs/python-client.md), examples; tests against real `ferotrx serve` processes (roles, TLS, mTLS from `ferotrx certs`) on Linux, macOS and Windows, and TCP, DNS and loss/latency across a veth pair on Linux | | 0.14.0 |
| M22, desktop GUI | `ferotrx-gui` (egui/eframe; Linux X11/Wayland, macOS, Windows), a client of the control API: several servers at once (plain, TLS, client certificates, tokens; `--connect`, `FEROTRX_*`), their interfaces plus `file` and `null` as ports; per port a stream table (enable, duplicate, reorder) sent as one profile (`profile.load` + `run.start`) with backend, AF_XDP mode, workers, duration, rate and receive interface; a stream editor with protocol layers (forms from a protocol registry, values checked as typed, defaults as hints, text form kept in step), stream control (rate or interval, loops, limit, delay, model, shape, sizes, latency) and variable fields/rewrites, checked locally with the engine's profile parser; a packet view (decode tree and hex, field to bytes and back); TCP/UDP runs from server or uploaded profiles with local `check`; a capture viewer whose packets become editable streams; statistics grid (column per run, row per counter, stop/remove) and rate charts; workspace kept between sessions; `ferotrx_packet::import` (captured packet back to editable layers, rebuilding to the same bytes), `parse_layers`/`format_layers`/`RawLayer`; extension point `ProtocolEditor` + `Registry` for new protocols and editors; [docs/gui.md](docs/gui.md); tests against an in-process server | | 0.15.0 |
| M23, application protocols | `ferotrx_core::app`: `AppProtocol`/`AppSession` (sans-IO, driven by the TCP engine with bytes in order and by the UDP engine per transaction), `App`, `AppRegistry` (profiles name a protocol with `app = "NAME"` and a `[NAME]` table; programs register their own), `AppStats` (transactions, failures, error answers, protocol errors, codes, response times) in TCP and UDP counters, the control API (`app`), the Python client (`AppCounters`) and scenario metrics; HTTP/1.1 client (requests with expected status, bodies, headers, keep-alive, pipelining, think time) and server (routes, chunked bodies, delays, `Connection: close`), parsing in any segment sizes; DNS ported to the engine and over TCP (RFC 7766); NTP ported; `examples/lab-http.toml`; `scripts/app-netns.sh` (emulated ends, `curl` against the server, the client against `python3 -m http.server`) in CI; [docs/app-protocols.md](docs/app-protocols.md) | #38 | 0.16.0 |
| M24, TLS and HTTPS | `ferotrx_core::app::tls` (feature `tls`, rustls with ring): TLS as a layer under any stream protocol (`app = "https"`, `tls = true` or a `[tls]` table; DNS over TLS on 853): real TLS 1.2/1.3 handshakes, `versions`, `cipher_suites`, `groups`, `alpn`, `server_name` (SNI), `verify` with `ca` or a CA generated per profile (rcgen; `names`, `key_type` ECDSA P-256/P-384/Ed25519), server `cert`/`key`, `client_auth` none/optional/required with `client_ca`, client certificates, `resumption`, `expect = "failure"`, `[tls.client]`/`[tls.server]` per end; handshake counters (`AppHandshake`; handshakes, failures, unexpected outcomes, resumed, negotiated version/suite/ALPN or failure reason, handshake time) in the CLI, ctl (`app.tls`), Python (`HandshakeCounters`) and scenario metrics (`tls_*`, `handshake_*`); `examples/lab-https.toml`; `scripts/app-netns.sh` runs HTTPS/DoT between emulated ends, `curl` over TLS 1.2 and 1.3, and the client against `openssl s_server` (RSA, ECDHE_RSA) | | 0.17.0 |
| M25, MQTT | `ferotrx_core::app::mqtt`: MQTT 3.1.1 and 5.0 client (CONNECT with client id, login, keep-alive and clean session; SUBSCRIBE; PUBLISH with QoS 0, 1 and 2, retained, paced by `interval`, used in turn across connections; waits for PUBACK/PUBREC/PUBREL/PUBCOMP and for its own messages back; PINGREQ; DISCONNECT; `expect` for CONNACK refusals) and broker (logins, `max_qos`, retained messages shared by its connections, delivery to the sending connection's subscriptions); `app = "mqtt"` (1883, 8883 over TLS); `examples/lab-mqtt.toml`; `scripts/app-netns.sh` runs MQTT between emulated ends, `mosquitto_pub`/`mosquitto_sub` against the emulated broker and the emulated clients against `mosquitto` | | 0.18.0 |
| M26, HTTP/2 | `ferotrx_core::app::http2`: HTTP/2 client and server (`app = "h2"` over TLS with ALPN `h2`, `app = "h2c"` or `"http2"` with prior knowledge; port 443/80), an `[http2]` table with the `[http]` keys and `concurrent`, `max_concurrent_streams`, `window`, `frame_size`, `header_table_size`, `huffman`, `scheme`; frames (SETTINGS/ACK, HEADERS+CONTINUATION, DATA, PING, RST_STREAM, GOAWAY, WINDOW_UPDATE, padding, priorities ignored), HPACK written in-house (`http2::hpack`: static and dynamic tables, size updates, Huffman, never-indexed `authorization`/`cookie`; RFC 7541 examples as tests), stream and connection flow control, multiplexed requests up to `concurrent`, `REFUSED_STREAM` asked again, resets and GOAWAY counted; the server answers HTTP/1.1 on the same port (no preface, or ALPN `http/1.1`); `examples/lab-h2.toml`; `scripts/app-netns.sh` runs HTTP/2 between emulated ends, `curl --http2`/`--http1.1`/`--http2-prior-knowledge` and `h2load` against the emulated server, and the emulated client against `nghttpd` over TLS and without | | 0.19.0 |
| M28, SIP and RTP | `ferotrx_core::app::sip`: SIP over UDP (`app = "sip"`, port 5060, a `[sip]` table): phones that REGISTER (digest MD5 or SHA-256 with `qop=auth`, `password`), INVITE with an SDP offer (`codecs` PCMU, PCMA, G722, G729, opus; `ptime`), ACK, talk for `duration` and BYE, `expect` success, failure or a status; a server that registers `users` (401/403), answers 100, 180 and after `ring` its `answer` (200 with an SDP answer, or 486/603/488), sends finals again until the ACK, answers BYE, CANCEL and OPTIONS and repeated requests, several Call-IDs per address, hangs up after `max_call`; SIP's timers (T1 doubling, T2, 64 T1); RTP at codec rates (G.711 as a 1 kHz tone) and RTCP (SR, SDES, BYE), symmetric RTP through NAT, receive counters (lost, duplicates, reordered, RFC 3550 jitter) as `MediaReport`/`MediaStats` (`media` in ctl/Python `AppCounters`, `media_*` and `jitter_*` scenario metrics); UDP engine dialog sessions (`AppProtocol::dialog`) and media ports (`AppProtocol::media_ports`, `[udp] media_ports`); `examples/lab-sip.toml`; `scripts/sip-netns.sh` runs calls between emulated ends, SIPp's caller and digest registrations against the emulated server, and the emulated phones against SIPp's answering end | | 0.21.0 |
| M27, SSH | `ferotrx_core::app::ssh` (feature `ssh`, ring): SSH-2 client and server (`app = "ssh"`, port 22): version exchange, curve25519-sha256 key exchange with an ssh-ed25519 host key (generated or an OpenSSH key file) and its signature checked (and `fingerprint`), chacha20-poly1305@openssh.com, aes256-gcm@openssh.com and aes128-gcm@openssh.com (`ciphers`), re-keying both ways (`rekey_after`), DISCONNECT; logins by Ed25519 key (`key`, `authorized_keys`) and password (`users`), `expect = "failure"`, `max_auth_tries`, `banner`; session channels with flow control: `exec` with input, exit status and output size checks (`commands`, `[[ssh.command]]`), server routes (`[[ssh.route]]` with output, stderr, exit status, delay) and built-ins (`echo`, `cat`, `head -c N /dev/zero`, ...), a small shell with pty echo; transactions `auth ...`, `exit N`, `rekey`, key exchanges as handshakes (`SSH key exchanges` in the summary); `AppCx::goodbye` (a reset after the peer's DISCONNECT completes the connection); `examples/lab-ssh.toml`; `scripts/app-netns.sh` runs SSH between emulated ends, OpenSSH's `ssh` (each cipher, re-keys, a pty shell, `sshpass` passwords) against the emulated server, and the emulated client against `sshd` | | 0.20.0 |

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
- [x] **M23, application protocols (0.16.0)**: an extensible protocol
      engine over TCP and UDP, HTTP/1.1 client and server, DNS over UDP and
      TCP, NTP; [docs/app-protocols.md](docs/app-protocols.md)
- [x] **M24, TLS and HTTPS (0.17.0)**, [#36](https://github.com/jkobierczynski/FeroTRX/issues/36):
      real TLS 1.2/1.3 handshakes under any stream protocol, versions,
      cipher suites, certificates, client certificates, handshake counters
      (not done: hello-only emulation of TLS 1.0/1.1)
- [x] **M25, MQTT (0.18.0)**, from [#37](https://github.com/jkobierczynski/FeroTRX/issues/37):
      3.1.1 and 5.0 clients and a broker, QoS 0-2, retained messages, logins
- [x] **M26, HTTP/2 (0.19.0)**, from [#37](https://github.com/jkobierczynski/FeroTRX/issues/37):
      h2 over TLS and h2c, HPACK, multiplexed streams, flow control; the
      server also answers HTTP/1.1 (not done: server push, priorities,
      `Upgrade: h2c`)
- [x] **M27, SSH (0.20.0)**, from [#37](https://github.com/jkobierczynski/FeroTRX/issues/37):
      clients and servers that work with OpenSSH both ways, key and
      password logins, commands, re-keying (not done: sftp/scp, forwarding,
      RSA/ECDSA keys)
- [x] **M28, SIP and RTP (0.21.0)**, from [#37](https://github.com/jkobierczynski/FeroTRX/issues/37):
      SIP phones and server over UDP (registration with digest, calls,
      hang-ups, SIP's timers), RTP/RTCP audio with loss and jitter, SIPp
      both ways (not done: SIP over TCP/TLS, SRTP, DTMF, a proxy role, media
      on several workers)
- [ ] **More application protocols**, [#37](https://github.com/jkobierczynski/FeroTRX/issues/37): SMB,
      QUIC/HTTP/3, a DHCP server role; the order is in
      [docs/app-protocols.md](docs/app-protocols.md#what-comes-next)
- [ ] **Later**, [#20](https://github.com/jkobierczynski/FeroTRX/issues/20):
      session length distributions

**P3: when the engine is stable**

- [x] **M22, desktop GUI (0.15.0)**, from [#21](https://github.com/jkobierczynski/FeroTRX/issues/21):
      `ferotrx-gui`, a client of the control API with ports, a stream and
      packet editor, captures, TCP/UDP runs and live statistics; a protocol
      editor registry for application layers and packet editing to come
- [x] **GUI from the first lab session**: draggable splits, file dialogs,
      profile-relative paths, and a lab router the control server builds
      (`serve --lab`, `lab.*`, `ferotrx lab up`) so the lab examples run on
      one machine
- [x] **Scenarios in the GUI**: prepare a scenario locally, run it on the
      server (`scenario.*` methods), see its report; `examples/lab-scenario.toml`
- [ ] **Distributed agents**, [#21](https://github.com/jkobierczynski/FeroTRX/issues/21)

**Not planned for now:** a packet-analysis suite (use Wireshark), a long
list of shallow protocols, DPDK as the main backend, Kubernetes
orchestration, full network simulation.

Note: FeroTRX measures loss, duplication, reordering and latency; it does not
inject them. The lab scripts use netem for that.
