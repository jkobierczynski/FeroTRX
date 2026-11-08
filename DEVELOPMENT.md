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
| M27, SSH | `ferotrx_core::app::ssh` (feature `ssh`, ring): SSH-2 client and server (`app = "ssh"`, port 22): version exchange, curve25519-sha256 key exchange with an ssh-ed25519 host key (generated or an OpenSSH key file) and its signature checked (and `fingerprint`), chacha20-poly1305@openssh.com, aes256-gcm@openssh.com and aes128-gcm@openssh.com (`ciphers`), re-keying both ways (`rekey_after`), DISCONNECT; logins by Ed25519 key (`key`, `authorized_keys`) and password (`users`), `expect = "failure"`, `max_auth_tries`, `banner`; session channels with flow control: `exec` with input, exit status and output size checks (`commands`, `[[ssh.command]]`), server routes (`[[ssh.route]]` with output, stderr, exit status, delay) and built-ins (`echo`, `cat`, `head -c N /dev/zero`, ...), a small shell with pty echo; transactions `auth ...`, `exit N`, `rekey`, key exchanges as handshakes (`SSH key exchanges` in the summary); `AppCx::goodbye` (a reset after the peer's DISCONNECT completes the connection); `examples/lab-ssh.toml`; `scripts/app-netns.sh` runs SSH between emulated ends, OpenSSH's `ssh` (each cipher, re-keys, a pty shell, `sshpass` passwords) against the emulated server, and the emulated client against `sshd` | | 0.20.0 |
| M28, SIP and RTP | `ferotrx_core::app::sip`: SIP over UDP (`app = "sip"`, port 5060, a `[sip]` table): phones that REGISTER (digest MD5 or SHA-256 with `qop=auth`, `password`), INVITE with an SDP offer (`codecs` PCMU, PCMA, G722, G729, opus; `ptime`), ACK, talk for `duration` and BYE, `expect` success, failure or a status; a server that registers `users` (401/403), answers 100, 180 and after `ring` its `answer` (200 with an SDP answer, or 486/603/488), sends finals again until the ACK, answers BYE, CANCEL and OPTIONS and repeated requests, several Call-IDs per address, hangs up after `max_call`; SIP's timers (T1 doubling, T2, 64 T1); RTP at codec rates (G.711 as a 1 kHz tone) and RTCP (SR, SDES, BYE), symmetric RTP through NAT, receive counters (lost, duplicates, reordered, RFC 3550 jitter) as `MediaReport`/`MediaStats` (`media` in ctl/Python `AppCounters`, `media_*` and `jitter_*` scenario metrics); UDP engine dialog sessions (`AppProtocol::dialog`) and media ports (`AppProtocol::media_ports`, `[udp] media_ports`); `examples/lab-sip.toml`; `scripts/sip-netns.sh` runs calls between emulated ends, SIPp's caller and digest registrations against the emulated server, and the emulated phones against SIPp's answering end | | 0.21.0 |
| M29, DHCP server role | `ferotrx_core::host` server roles: a DHCPv4 server (`[host.dhcp_server]`, `--dhcp-pool`; RFC 2131/2132: pool, lease time with T1/T2, router, DNS, domain, reservations by MAC, offers held 30 s, addresses kept per client identifier, requested addresses, NAKs as an authoritative server, renew/rebind, release, decline with a 10 min hold, inform, relay answers to `giaddr` with option 82 returned, RFC 2131 4.1 reply addressing) and a DHCPv6 server (`[host.dhcpv6_server]`; RFC 8415 IA_NA: solicit/advertise, rapid commit, request, renew, rebind with zero lifetimes for addresses a client may not keep, release, decline, confirm, information request, DNS and domain search list, reservations; joins ff02::1:2 over MLD); `DhcpServerStatus` leases and counters in `HostStatus`, ctl/Python `HostInfo.dhcp_server`/`dhcpv6_server`, lease lines in `ferotrx host`; the host engine hands frames between a server and its own clients on one port (loopback); `examples/lab-dhcp-server.toml`; `scripts/hosts-netns.sh` check 4: busybox `udhcpc` and `udhcpc6` against the FeroTRX server plus emulated clients | | 0.25.0 |
| M30, SMB | `ferotrx_core::app::smb`: SMB 2 and 3 over TCP (`app = "smb"`, port 445, an `[smb]` table): dialects 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1 (`dialects`, the 3.1.1 preauth integrity hash), NTLMv2 logins in SPNEGO (`user`, `password`, `domain`; guests and anonymous; `expect` a status such as `LOGON_FAILURE`), signing with HMAC-SHA256 (2.x) and AES-CMAC (3.x, keys from the SP800-108 KDF; `signing` auto, required or off), credits and compounds; client `ops` (write, read with every byte checked, list, delete, mkdir, rmdir, each with an expected status) in `chunk`s with `window` in flight; a server with shares in memory shared by all its connections (`users`, `shares`, `read_only`, `files`), create dispositions, delete on close, rename, directory listings in the classes Windows and Samba use, file and file system information, VALIDATE_NEGOTIATE; own MD4, SHA-512, HMAC, RC4, AES-128 and AES-CMAC; transactions per operation, logins as handshakes (`SMB logins` in the summary); `examples/lab-smb.toml`; `scripts/smb-netns.sh` runs the emulated ends, smbclient against the emulated server and the emulated clients against Samba's `smbd` | | 0.23.0 |
| M31, QUIC and HTTP/3 | `ferotrx_core::app::quic` (feature `quic`): QUIC version 1 (RFC 9000, 9001, 9002) sans-IO, with rustls for the TLS 1.3 handshake and keys: three packet number spaces, header and packet protection, coalesced packets, padded Initials, CRYPTO streams, delayed ACKs, loss detection by packet and time thresholds and probe timeouts, NewReno with pacing, the 3x anti-amplification limit, bidirectional and unidirectional streams with stream and connection flow control and growing stream limits, key updates (`key_update_after`), Retry (`retry`) and Version Negotiation, idle timeouts, CONNECTION_CLOSE with closing and draining; HTTP/3 (RFC 9114) on it with control and QPACK streams, SETTINGS, HEADERS and DATA, GOAWAY (`route.close`), QPACK (RFC 9204) with the static table and Huffman literals; `app = "h3"` in UDP profiles with an `[h3]` table (the HTTP requests and routes, `concurrent`, windows, `idle_timeout`) and `[tls]` (TLS 1.3, ALPN `h3`); handshakes as `QUIC v1 ...`, lost packets as "sent again" (`AppCx::resent`); `examples/lab-h3.toml`; `scripts/h3-netns.sh` with `scripts/h3-peer.py` runs the emulated ends, aioquic's client against the emulated server and the emulated clients against aioquic's server | | 0.24.0 |
| M36, the GUI's application-level workflow | `ferotrx-gui`: an Applications tab with forms for application protocol profiles (HTTP, HTTP/2, HTTP/3, DNS, NTP, MQTT, SSH, SIP/RTP, SMB, TLS) from an `AppEditor` registry next to the packet `ProtocolEditor`s, checked against the engine's keys; workspaces saved and opened as `.ferotrx` files (`--workspace`; servers, ports, every tab's forms, the window layout; no tokens); editable hex view kept in step with the layers; loss, reordering and latency per flow over time in Charts; scenario comparison of runs or report files; a Multi-server tab that starts and stops runs on several servers together with combined counters; a Benchmark tab on the new `bench.*` control methods (RFC 2544 runs on the server, every trial as it ends, results and throughput charts, reports as `ferotrx bench --report`); `check_text` in core | | 0.26.0 |
| M33, built-in impairments | `ferotrx_core::Impairer`, sans-IO and seeded: delay with jitter (uniform, normal, Pareto; correlation; order kept or not), random and Gilbert-Elliott bursty loss (`loss_burst`, `loss_bad`), duplication, reordering (frames that skip the delay), corruption (one bit past the L4 header, checksums kept or fixed), a rate limit with a tail-drop queue (`rate`, `limit`), MTU drop or truncate; `ImpairSpec` text (`delay=20ms loss=1% ...`) and TOML tables; streams (`Stream::impair`, `impair` per `[[stream]]`, `--impair` on `replay`/`run`, counters in `ReplayStats::impair`); `ImpairPort` on any `PacketPort`, each way (`impair`/`impair_rx` in TCP, UDP and host profiles, `--impair`/`--impair-rx`, counters in `TcpStats`/`UdpStats`/`HostStats::impair`); the two-port bridge `ferotrx impair -i A -o B` (`run_bridge`); ctl `impair`/`impair_rx` parameters and `ImpairCounters`, `ferotrx ctl` options, Python fields, GUI field and rows; scenario checks' `impair`/`impair_rx` and the `impair_dropped` metric; [docs/impairments.md](docs/impairments.md); `scripts/impair-netns.sh` (no netem) and `tcp-nat-netns.sh --impair` in CI | #61 | 0.28.0 |
| M34, TCP congestion control and ECN | `ferotrx_core::CongestionController` (the engine calls it on new ACKs, congestion and timeouts), `NewReno` (default) and `Cubic` (RFC 9438: cubic growth by time, 0.7 back-off, fast convergence, the Reno-friendly estimate; HyStart++ from RFC 9406 in the first slow start); ECN (RFC 3168): ECE+CWR in the SYN, ECT(0) on new data only, CE echoed with ECE until CWR, one reduction a round trip, SYN retries without ECN; `congestion` and `ecn` in `[tcp]` and per `[[template]]`, `--congestion`/`--ecn`, ctl `tcp.start` parameters, counters `ecn_connections`/`ce_marks`/`ecn_reductions` (ctl, Python, GUI, scenario metrics); timeout fixes found on long paths (the RTO's variation part at least `min_rto`, as Linux; a fast retransmit restarts the timer; no fast retransmit for what was sent before a timeout, RFC 6582); simulated-link tests (CUBIC 19 s against NewReno 45 s on a lossy 200 ms path, ECN with a marking queue and no retransmissions); `tcp-nat-netns.sh` `ECN=1` (tbf into fq_codel `ecn`, and Linux cubic as the sender) in CI | #62 | 0.29.0 |
| M35, Y.1564 service activation | `ferotrx_core::run_y1564` with a `ServiceRunner` (`JobServiceRunner` sends green and yellow flows as streams with signatures, receives with an `RxJob`); `[y1564]` profiles with `[[service]]` tables (CIR, EIR, CBS, EBS, EMIX letters, VLAN/DSCP through the packet, color aware or blind, SAC: FLR, FTD, FDV, availability); configuration steps (25-100% CIR, CIR+EIR, policing overshoot, CBS and EBS bursts) and the performance test with per-interval counters in the receiver (by the send time in the signature) and Y.1563 availability; text and JSON reports; `ferotrx y1564`, `ferotrx check`, scenario `y1564` checks and metrics, ctl `y1564.*`, Python `y1564_*`, the GUI's Y.1564 tab; `scripts/y1564-netns.sh` (tc `police`, or htb without `act_police`) in CI | #63 | 0.30.0 |
| M37, distributed agents | Fleet plans (`ferotrx_core::fleet::FleetPlan`: `[[agent]]` with token or TLS, per-agent `vars`; `[[run]]` with a TCP, UDP or traffic profile on one or more agents, run settings, `delay`, `rx_agent`, `require` on the sum and `require_each` on each part; `[require]` on the sums per kind); the controller `ferotrx_ctl::fleet` (clock offsets from `server.info`, deploy with `file.put` and SHA-256 skips, every start call with `start_at` in the agent's clock, a failed start stops the rest, counters summed per run and per kind, `ferotrx-fleet-1` JSON and text reports); `start_at`/`started_at` on `run.start`, `tcp.start`, `udp.start` (core `wait_until`), `file.put`/`file.stat` and `serve --max-file`; `ferotrx fleet run|check|deploy`, `ferotrx check` on plans; Python `file_put`/`file_stat`/`upload_file` and `start_at`; the GUI's Multi-server groups start on a shared clock; [docs/fleet.md](docs/fleet.md); `scripts/fleet-netns.sh` (three agents, one cut off) in CI | #64 | 0.31.0 |
| M38, TLS handshake load | New TLS sessions made per connection, not replayed: `resumption = false` (a full handshake each time; the server keeps no sessions and sends no tickets) or a share of resumed sessions spread over the connections (`resumption = 0.3` or `"30%"`); `server_name` as a list of SNI names used in turn; `app = "tls"`, handshakes only (`hold` keeps a connection open after its handshake); a TLS 1.3 client that keeps sessions waits for the server's tickets before it closes; counters for new sessions, handshakes per second and the times of new and resumed handshakes apart (`AppStats::full_time`/`resumed_time`/`handshake_rate`, ctl/Python `HandshakeCounters.full`/`rate`/`full_time`/`resumed_time`, scenario and fleet metrics `tls_full`, `tls_rate`, `handshake_full_*`, `handshake_resumed_*`); GUI: `tls` as a protocol, `resumption` as a share, `hold`; `examples/lab-tls.toml`; `scripts/tls-netns.sh` (`openssl s_time -new`/`-reuse` against the emulated server, the emulated client against `openssl s_server`) in CI | | 0.32.0 |
| M39, HTTP/1.1 workloads with success checks | Response checks per `[[http.request]]` (`ferotrx_core::app::http::ResponseChecks`, `HttpRequest::judge`): `expect_contains`, `expect_lacks`, `expect_body`/`expect_body_file`, `expect_size` (exact, range, `>=`, `<=`), `expect_headers` (value, `prefix*`, `*` present, `!` absent), `name`; the parser keeps bodies (up to 16 MB) only when a check needs their bytes; every transaction carries its request's name and why it failed (`AppTransaction::with_name`/`failed_because`), counted per request (`AppStats::requests`, `RequestCounts`) and by reason (`AppStats::failures`, 20 kinds); HTTP/2 and HTTP/3 count per request too and refuse checks other than the status; ctl/Python `AppCounters.requests`/`failures` (`RequestCounters`), CLI `passed per request`, scenario and fleet metrics `app_passed`, `app_passed_pct`; GUI request fields; `examples/lab-http-checks.toml`; `scripts/http-netns.sh` (a run that must pass, one that must fail one check, checks against `python3 -m http.server`) in CI | | 0.33.0 |
| M40, a proper Windows app | `ferotrx-gui` and `ferotrx` as Windows programs: an MSI installer (WiX 5, `packaging/windows`: Program Files, Start menu, `PATH`, `*.ferotrx` opens in the GUI, upgrade in place) built and installed/uninstalled in CI and published with each release; icon, version information and manifest (per-monitor DPI, UTF-8) in both programs; the GUI without a console window (it attaches to the terminal it was started from); Explorer file dialogs (`rfd`); `wpcap.dll` loaded late from `System32\Npcap` (`ferotrx_io::windows::load_npcap`), so the programs start without Npcap and say what is missing; Windows adapter names ("Ethernet 2") listed and accepted wherever an interface is named, MAC and addresses in `interfaces` (CLI, ctl `InterfaceEntry.alias`/`mac`/`addresses`, Python, GUI); the GUI's Appearance window (`ferotrx_gui::theme`: built-in themes, colours per mode including the status colours every tab uses, corner radius, borders, density, shadows, animations, scroll bars, text sizes and zoom, theme files, `--theme`); the window icon on every system; [docs/windows.md](docs/windows.md) | #70 | 0.34.0 |
| M43, control-plane hardening | From the security review of 2026-11-06 ([#71](https://github.com/jkobierczynski/FeroTRX/issues/71)): a server beyond loopback refuses tokens without TLS (`--allow-cleartext-token` / `ServerConfig::allow_cleartext_tokens` for an isolated lab, logged as `cleartext_tokens`); `Controller::new()` and `FilePolicy::default()` name no files (`FilePolicy::none`), and `FilePolicy::unrestricted` beyond loopback needs `ServerConfig::unrestricted_files`; `stats.subscribe` limited per connection (`--max-subscriptions`, 16) and per server (256), ended subscriptions stop counting at once, error -32005 (`LIMIT`); at most 16 connections waiting to log in, 10 s to log in, wrong tokens counted per address (20 a minute) and in total (200) with logins refused unchecked beyond that (`login_throttled`); audit write failures counted, reported on stderr and in `server.info` (`audit`: ok, failures, last error), `--audit-required` refuses operator calls while the log fails (`audit_refused`); `server.info` shows connections and subscriptions; Python `LimitExceeded`, `AuditHealth`; `scripts/fleet-netns.sh` runs its agents over TLS | | 0.35.0 |
| M41, a local server built into the GUI | "This computer" in the GUI (`ferotrx_gui::local`): **Start** runs the `ferotrx` next to the GUI as `serve -l 127.0.0.1:0` with a token made up per session (only its SHA-256 on disk), the port read from `--port-file`, stopped by removing that file or when the GUI ends (`--parent`), folders set per server; `ferotrx-gui --local`; on Windows a UAC prompt only when Npcap is for administrators only (`ferotrx_io::windows::npcap_admin_only`, `is_elevated`), on Linux and macOS a hint for the rights to send; `ferotrx service install\|remove\|start\|stop\|status` (the `windows-service` crate: LocalSystem, tokens moved off the command line into `%ProgramData%\FeroTRX\tokens.toml` as SHA-256, data and audit log there by default; the installer stops it on upgrade and removes it on uninstall); the lab router hidden for servers that are not Linux; CI starts the GUI's server and installs, uses and removes the service on Windows | #77 | 0.36.0 |
| M42, Npcap for real use | Windows sending in batches through Npcap's send queue (`pcap_sendqueue_transmit`, `InterfaceSink::open_batched`): `--batch`/`[output] batch` now applies to `pcap` on Windows (default 64, 1 = packet by packet), handed over before every paced wait like AF_XDP; the receiver asks Npcap for precise system time stamps (`host_hiprec`, `KeQuerySystemTimePrecise`) so latency does not drift, falling back on older Npcap; Windows CI runs null and file runs through the service; [docs/windows.md](docs/windows.md#sending-fast) (measured on a Windows host with a Realtek 5GbE adapter: 10k pps packet by packet, 61k pps in batches of 64, 67k in batches of 512) | #82 | 0.37.0 |
| M44, CI and release supply chain | From the security review of 2026-11-06 ([#72](https://github.com/jkobierczynski/FeroTRX/issues/72), SEC-07): every action in `ci.yml` and `release.yml` pinned to a commit with its version in a comment; read-only `GITHUB_TOKEN` by default, the publish job alone may write and sign; `.github/dependabot.yml` (actions, Cargo, the Python tools; weekly, grouped); a **Dependencies** CI job (not required) with `cargo deny check` (`deny.toml`: RustSec advisories, allowed licenses, crates.io only) and GitHub's dependency review on pull requests; releases carry CycloneDX SBOMs of `ferotrx` and `ferotrx-gui` and a build provenance attestation for every file (`gh attestation verify`); `SECURITY.md` (private vulnerability reporting, what is in scope); [RELEASING.md](RELEASING.md) on checking a release | #81 | 0.38.0 |
| M48, capture and monitor | `ferotrx capture -i IFACE [BPF]` ([#94](https://github.com/jkobierczynski/FeroTRX/issues/94)): BPF filters through libpcap/Npcap (`ferotrx_io::LiveCapture`, `FrameFilter`), decoded lines (`-v`, `-x`), pcap to a file, a ring (`--rotate 100M\|5m --files N`) or standard output for `wireshark -k -i -`, nanosecond stamps on Linux, `--direction`, libpcap's drop counters; `inspect -f BPF`; `--capture FILE` (`--capture-iface`, `--capture-filter`) next to `replay`, `run`, `tcp`, `udp` and `host`; core `live` (`FrameSource`, `CaptureJob`, `PcapStreamWriter`, `PcapngWriter`, `CaptureFiles`); ctl `capture.start/read/get/list/stop/remove` (long-polled reads, bounded buffer with a `missed` count, captures nobody reads stop after a minute; the server's own control port left out unless `ctl_traffic`, `--ctl-traffic`) and `file.get`; `ferotrx ctl capture` (a remote capture shown or piped to a local Wireshark, `--save`), `capture-start`, `captures`, `capture-stop`, `fetch`; fleet `[[capture]]` with `fleet run --collect DIR --merge FILE` (one pcapng, times on the controller's clock); Python `capture_*`, `capture_pcap`, `file_get`, `download`; the GUI's live capture (any server, BPF filter, Wireshark alongside, Save…); large replies over TLS fixed (rustls takes 64 KiB at a time); [docs/capture.md](docs/capture.md); `scripts/capture-netns.sh` and fleet captures in CI. Not done: copies of frames AF_XDP/DPDK send, a live merged fleet feed | | 0.39.0 |
| M49, files and first steps | From a first session on Windows, where paths went wrong: settings of the user's own (`ferotrx_gui::settings`: `%APPDATA%\FeroTRX\settings.toml`, `~/.config/ferotrx`, Application Support) with default folders for profiles, captures and reports that every file dialog starts in (Settings… window); the installed examples copied to `Documents\FeroTRX\examples` on first start (renamed to their kinds, references between them kept); an extension per file kind, TOML inside, `.toml` still read (`FileKind::extension`/`from_path`/`label`, `check::kind_of`; `.ftstream`, `.fttcp`, `.ftudp`, `.fthost`, `.ftscenario`, `.ftbench`, `.fty1564`, `.ftfleet`, themes `.fttheme`), registered by the MSI to open in the GUI, `ferotrx check` by extension first; any file opens in the tab of its kind (`ferotrx-gui FILE`, Open a file…, a wrong kind picked in a tab's Open…); the files a profile names (captures, bodies, a scenario's profiles and theirs) sent to any server the GUI did not start, into `gui/<user>-<computer>/` of its data directory, skipped by SHA-256 (core `bundle`, shared with fleet deploy; conn `UploadThenCall`); the Start tab (four steps, examples per task, next step); a clear error for TLS ticked against a plain server (rustls' `InvalidContentType`) and the other way round; [docs/gui.md](docs/gui.md#where-to-start) | | 0.40.0 |
| M45, fuzzing and hostile-input tests | 13 cargo-fuzz targets in `fuzz/` (`ferotrx_core::fuzzing`, `ferotrx_ctl::fuzzing`, feature `fuzzing`): application sessions of every protocol, the TCP/UDP/host engines on a tampering link, received-frame parsers and the rx signature reader, the packet decoder, pcap/pcapng, profiles of every kind, one-line syntaxes, SSH after the key exchange, QUIC/HTTP/3 behind packet protection, JSON-RPC into the controller and over a live server; `fuzz/run.sh` with seeds from real sessions; CI `Fuzz` workflow (changed targets 60 s on pull requests, all 10 min nightly); hostile-input tests (seeds, `fuzz/regressions/`, mutations, hostile requests) and hostile peers (`tests/hostile.rs`) in `cargo test`. Fixed: a QUIC 0-RTT packet whose length ran past the datagram crashed HTTP/3 ends (remotely), the signature reader panicked on frames under 28 bytes, HTTP/2 kept an endless CONTINUATION, MQTT buffered 256 MiB packets; [docs/fuzzing.md](docs/fuzzing.md) | | 0.41.0 |
| M32, jitter, latency and call quality | `ferotrx_core::app::quality`: the ITU-T G.107 E-model with G.107's defaults (R from delay, loss, burst ratio and the codec's `Ie`/`Bpl` from G.113; MOS; G.109 bands); RTP receivers that judge packets against a jitter buffer (`jitter_buffer`, late packets), settle the loss pattern behind a 1024-packet window (loss bursts, longest, burst ratio), read the other end's RTCP sender and reception reports (round trip from LSR/DLSR, what it saw of our packets) and fill in their own (peer SSRC, LSR, DLSR); `rtcp_interval`, `ie`, `bpl` in `[sip]`; per call in `MediaReport` (`late`, `loss_bursts`, `max_burst`, `burst_ratio`, `rtt`, `remote_lost`, `remote_jitter`, `delay`, `r_factor`, `mos`), summed in `MediaStats` (mean and worst R and MOS, bands); TCP clients' `connect_time` and `first_byte`; ctl/Python `MediaCounters` and `TcpCounters` fields, CLI and GUI lines; scenario metrics `mos`, `mos_min`, `r_factor`, `r_factor_min`, `rtt_avg`, `rtt_max`, `media_late`, `media_playout_loss_pct`, `max_burst`, `connect_*`, `first_byte_*`; [docs/call-quality.md](docs/call-quality.md); `scripts/sip-netns.sh` checks clean scores and, with netem, 200 ms and 5% loss | | 0.27.0 |

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

**Next, first priority (Jurgen, 2026-11-07)**

- [x] **M48, capture and monitor (0.39.0)**, [#94](https://github.com/jkobierczynski/FeroTRX/issues/94):
      `ferotrx capture` with BPF filters, live decoded lines, pcap to a file
      or to stdout for `wireshark -k -i -`; `capture.*` and `file.get` in the
      control API, so a remote server's capture streams to a local Wireshark;
      fleet plans capture on every agent and collect (and merge) the pcaps
      after the run; a live capture view in the GUI; captures next to runs
      (not done: copies from AF_XDP/DPDK ports). Went before M45 to M47.

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
- [x] **M38, TLS handshake load (0.32.0)**, from [#20](https://github.com/jkobierczynski/FeroTRX/issues/20):
      new sessions per connection (or a share resumed), handshake-only
      connections, SNI names in turn, handshakes per second and new and
      resumed handshake times; `openssl s_time` in the lab script
- [x] **M39, HTTP/1.1 workloads with success checks (0.33.0)**, from [#20](https://github.com/jkobierczynski/FeroTRX/issues/20):
      body texts, exact bodies, sizes and headers per request, passes and
      failures per request with the reasons (not done: body and header
      checks over HTTP/2 and HTTP/3)
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
- [x] **M29, DHCP server role (0.25.0)**, from [#37](https://github.com/jkobierczynski/FeroTRX/issues/37):
      DHCPv4 and DHCPv6 servers as host roles (pools, reservations, lease
      times, renewals, releases, declines, relays, rapid commit), for real
      clients and the run's own emulated hosts; busybox udhcpc/udhcpc6 in
      the lab script (not done: pools per relay, DHCPv6 relay messages and
      prefix delegation, leases that outlive the run)
- [x] **M30, SMB (0.23.0)**, from [#37](https://github.com/jkobierczynski/FeroTRX/issues/37):
      SMB 2.0.2 to 3.1.1 clients and an in-memory file server, NTLMv2
      logins, HMAC-SHA256 and AES-CMAC signing, files and directories,
      smbclient and Samba both ways (not done: encryption, Kerberos,
      leases and oplocks, durable handles)
- [x] **M31, QUIC and HTTP/3 (0.24.0)**, from [#37](https://github.com/jkobierczynski/FeroTRX/issues/37):
      QUIC version 1 of our own (rustls for TLS 1.3 and keys): loss
      recovery, congestion control with pacing, flow control, key updates,
      Retry; HTTP/3 with QPACK's static table; aioquic both ways (not done:
      0-RTT, migration, QPACK's dynamic table, path MTU discovery)
- [ ] **Later**, [#20](https://github.com/jkobierczynski/FeroTRX/issues/20):
      session length distributions

**P2, after the protocols of #37: quality and network behaviour**

- [x] **M32, jitter, latency and call quality (0.27.0)**, [#49](https://github.com/jkobierczynski/FeroTRX/issues/49):
      per-call RTP loss, late packets, bursts and RTCP round trips, RTCP
      reception reports read and filled in, E-model R-factor and MOS, TCP
      connect and first-byte times; [docs/call-quality.md](docs/call-quality.md)
      (not done: one-way latency with a shared clock, MOS charts in the GUI)
- [x] **M33, built-in impairments (0.28.0)**, [#50](https://github.com/jkobierczynski/FeroTRX/issues/50):
      delay/jitter, loss (incl. bursts), duplication, reordering, corruption
      and rate limits in the pipeline and on ports, a two-port bridge mode;
      [docs/impairments.md](docs/impairments.md) (not done: impairments in
      `ferotrx bench`, a per-stream impairment field in the GUI's stream editor)
- [x] **M34, TCP congestion control choices (0.29.0)**, [#51](https://github.com/jkobierczynski/FeroTRX/issues/51):
      a controller trait, CUBIC with HyStart++, ECN; [docs/tcp-engine.md](docs/tcp-engine.md)
      (not done: BBR-like pacing, Accurate ECN and L4S)
- [x] **M35, Y.1564 service activation (0.30.0)**, [#52](https://github.com/jkobierczynski/FeroTRX/issues/52):
      CIR/EIR services, configuration and performance tests, FLR/FTD/FDV,
      availability; [docs/y1564.md](docs/y1564.md) (not done: delay across
      two machines without synced clocks, a loopback reflector at the far end)
- [x] **M36, finish the GUI's application-level workflow (0.26.0)**, [#54](https://github.com/jkobierczynski/FeroTRX/issues/54):
      editors for application protocol profiles, workspace save/open, hex
      editing, receive-side loss/latency charts over time, benchmarking
      (`bench.*`), scenario comparison, runs across several servers at once
      and Y.1564 tests (not done: MOS charts after M32)

**Security, from the outside review of 6 November 2026**

The [security review](docs/reviews/2026-11-06-security-review.md), each
finding [checked against 0.34.0](docs/reviews/2026-11-06-review-check.md),
and [the plan](docs/reviews/2026-11-security-plan.md) with its order: M43
and M44 first, then M41 and M42, then M45 to M47 (after M48,
capture, which Jurgen put first on 2026-11-07).

- [x] **M43, control-plane hardening (0.35.0)**, [#71](https://github.com/jkobierczynski/FeroTRX/issues/71):
      no cleartext tokens off loopback, bounded `stats.subscribe`, no file
      access by default in the library, separate slots and rate limits for
      logins, audit health and a fail-closed option (SEC-01, 02, 04, 06)
- [x] **M44, CI and release supply chain (0.38.0)**, [#72](https://github.com/jkobierczynski/FeroTRX/issues/72):
      actions pinned by SHA, least-privilege tokens, `cargo deny`, dependency
      review, SBOM, provenance attestations, `SECURITY.md` (SEC-07)
- [x] **M45, fuzzing and hostile-input tests (0.41.0)**, [#73](https://github.com/jkobierczynski/FeroTRX/issues/73):
      `cargo-fuzz` targets for the control server, profiles, packet decoding
      and every application protocol, in CI and nightly; hostile-input and
      hostile-peer tests in the normal suite; [docs/fuzzing.md](docs/fuzzing.md)
      (not done: a limit on half-open connections of the TCP server engine)
- [ ] **M46, certificate revocation and safe file access (0.42.0)**, [#74](https://github.com/jkobierczynski/FeroTRX/issues/74):
      CRLs, a fingerprint deny list, reload, shorter lab certificates; file
      opens without symbolic-link races (SEC-05, SEC-03)
- [ ] **M47, traffic guardrails (0.43.0)**, [#75](https://github.com/jkobierczynski/FeroTRX/issues/75):
      server-side limits on interfaces, destinations, rates, duration and
      runs that remote operators cannot exceed

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
- [x] **M49, files and first steps (0.40.0)**: a Start page, the user's
      own settings and folders (`%APPDATA%\FeroTRX`, `Documents\FeroTRX`),
      an extension per file kind, files opened in the tab of their kind,
      and a profile's files sent along to any server
- [x] **M37, distributed agents (0.31.0)**, [#21](https://github.com/jkobierczynski/FeroTRX/issues/21):
      a controller that deploys profiles to `ferotrx serve` agents, starts
      them on a shared clock and adds up their counters; [docs/fleet.md](docs/fleet.md)
      (not done: agents finding each other, benchmarks, Y.1564, scenarios
      and host emulation in plans, calls to the agents in parallel)
- [x] **M40, a proper Windows app (0.34.0)**, [#69](https://github.com/jkobierczynski/FeroTRX/issues/69):
      MSI installer, icon and version information, no console window,
      Explorer dialogs, Windows adapter names, Npcap loaded late with a
      clear message; the GUI's Appearance window (themes, colours, widget
      style, text sizes); [docs/windows.md](docs/windows.md); releases are
      signed afterwards on Jurgen's PC with `sign-release.ps1` (Certum
      SimplySign; [docs/windows.md](docs/windows.md#signing-a-release))
- [x] **M41, a local server built into the GUI (0.36.0)**, [#69](https://github.com/jkobierczynski/FeroTRX/issues/69):
      "This computer" started by the GUI, elevation only when Npcap needs
      it, `ferotrx serve` as a Windows service (`ferotrx service`); the
      GUI hides the lab router on servers that are not Linux
- [x] **M42, Npcap for real use (0.37.0)**, [#69](https://github.com/jkobierczynski/FeroTRX/issues/69):
      batched sending, high-precision timestamps (measured on a Windows host:
      10k pps packet by packet, 61k in batches of 64)

**Not planned for now:** a packet-analysis suite (use Wireshark), a long
list of shallow protocols, DPDK as the main backend, Kubernetes
orchestration, full network simulation.
