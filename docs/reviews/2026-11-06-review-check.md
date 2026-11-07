# Checking the November 6 reviews against the code

The two outside reviews of 6 November 2026,
[the project state review](2026-11-06-project-state-review.md) and
[the security review](2026-11-06-security-review.md), checked claim by claim
against `main` at 0.34.0 (commit `7fa426e`, after M40). The security review
read commit `fc3dc04` (0.33.0); the project state review read 0.33.0 too.
Nothing in the remote control changed between those commits and this one.

Verdicts: **right** (true today), **partly right** (true, but some of it is
already handled or the detail is off), **out of date** (was true, no longer),
**wrong**.

The plan for the security findings is in
[2026-11-security-plan.md](2026-11-security-plan.md).

## Security review

| Finding | Verdict | What the code does today |
| --- | --- | --- |
| SEC-01, tokens without TLS off loopback | **Right** | `Server::with_config` (`crates/ferotrx-ctl/src/server.rs`) refuses a non-loopback address only when there is no login at all. A token counts as a login, so `serve --listen 0.0.0.0:4510 --token T` starts; `cmd_serve` (`crates/ferotrx-cli/src/remote.rs`) only prints "tokens travel in clear text". `Server::bind(addr, controller, Some(token))` does the same for library users, and `tests/security.rs` even asserts that it binds on `0.0.0.0`. Our own `scripts/fleet-netns.sh` and the `docs/fleet.md` example run agents this way, and so does a GUI on a Windows host talking to `serve` in a VM. |
| SEC-02, unbounded `stats.subscribe` | **Partly right** | Each `stats.subscribe` spawns an OS thread (`Connection::subscribe`) and nothing limits how many per connection or in total; a read-only login is enough. The minimum interval is 50 ms and the default connection limit is 64, as the review says. Already handled: a connection that closes cancels all its subscriptions (`Connection::run` sets every cancel flag), and a publisher stops when its write fails. Not mentioned by the review: the `subs` map keeps an entry for every subscription that ended by itself, until the connection closes. |
| SEC-03, symlink races in `files.rs` | **Right**, and two more problems | Paths are checked with `canonicalize` and then opened again by path (`readable`, `writable`, `put`), so a file swapped for a symbolic link between the check and the open is followed; `docs/remote-control.md` says so. Nothing uses `O_NOFOLLOW` or descriptor-relative opens. Found while checking: `put_path` calls `create_dir_all` **before** `writable` checks the parent, so `file.put` with `link/new/f`, where `link` is a symbolic link inside the data directory pointing outside it, creates `new/` outside before the request is refused. And `stat` (`file.stat`) reads the whole file into memory to hash it, whatever its size. Both need operator rights. |
| SEC-04, `Controller::new()` is unrestricted | **Right** | `Controller::new()` sets `FilePolicy::unrestricted()`, and `FilePolicy::default()` is unrestricted too. `ferotrx serve` always passes `FilePolicy::dirs`, so the command is safe; a program that embeds `Server` with a default `Controller` gives every operator the whole filesystem. `Server::with_config` does not look at the file policy at all. |
| SEC-05, no certificate revocation | **Right**, one test already passes | No CRLs and no denylist: client certificates go through rustls' `WebPkiClientVerifier` without `with_crls`, and the docs say "to lock someone out, issue new CAs and restart". Tokens and CAs are read once at start (no reload). Expiry, which the review lists as an acceptance test, is already enforced: webpki rejects an expired client certificate. `ferotrx certs` (LabPki) issues CAs and certificates valid until 2035, which makes revocation more important. |
| SEC-06, audit write errors ignored | **Right** | `AuditLog::record` does `let _ = out.write_all(..)`; there is no failure counter, no health in `server.info`, no fail-closed mode, no rotation (append only). Checked as well: tokens never reach the audit log (`auth` is not an operator call, so its parameters are not logged), uploaded profile text and `file.put` data are logged by size only, and the file is created with mode 0640. |
| SEC-07, GitHub Actions | **Right** | `ci.yml` and `release.yml` use tags (`actions/checkout@v4`, `dtolnay/rust-toolchain@stable`, `Swatinem/rust-cache@v2`, `actions/upload-artifact@v4`, `actions/download-artifact@v4`, `actions/setup-python@v5`, `taiki-e/install-action@v2`). Neither workflow sets top-level `permissions`; only the release `publish` job asks for `contents: write`. No `cargo audit`/`cargo deny`, no dependency review, no Dependabot, no SBOM, no attestations, no `SECURITY.md`. The release workflow does build `--locked` and writes `SHA256SUMS`, as the review says. On tags: `release.yml` is written so that pushing a tag again *replaces* the release, so moving tags is currently a feature, not an accident. |

### Section 3, protocol implementations

**Right.** There is no `fuzz/` directory, no `cargo-fuzz` target and no
property-testing crate. Hostile input is covered only by unit tests of
malformed messages in some parsers and by seeded random-loss stress loops
(QUIC `play_with`, the TCP path tests). Interoperability is better than the
review assumes: the lab scripts run OpenSSH, curl, h2load, mosquitto, SIPp,
smbclient/Samba, aioquic, openssl `s_time`, dig and busybox udhcpc against
our ends, in CI. The review also leaves out the parsers closest to an
attacker: the JSON-RPC request line and the TOML profiles a client uploads
(`profile.load` with `toml`), both reachable by any operator, and
`ferotrx-packet`'s decoder, which reads everything a receiving port sees.

### Sections 4 and 5

The positive findings are right: constant-time token comparison
(`auth::same`), SHA-256 hashed tokens in `--tokens` files, separate read and
operator CAs, request/upload/connection limits, a 500 ms pause per wrong
token and a closed connection after five, login and idle timeouts,
`tests/security.rs` and `python/tests/test_security.py`. Clients (CLI,
Python, GUI) always verify the server certificate, and the GUI never saves
tokens.

Of the "additional improvements":

* **Global login rate limiting: right, and there is a related gap.** The
  limit of five wrong tokens is per connection; reconnecting starts again.
  Connections that have not logged in also share the 64 connection slots
  with everyone else and may hold one for the 30 s login timeout, so a
  client without a token can keep operators out (a denial of service
  before login).
* Subscription limits, safe library defaults, TLS for remote tokens: the
  same as SEC-02, SEC-04, SEC-01.
* Per-agent traffic quotas and the "traffic-generation safeguards": right,
  none exist. An operator can start any rate on any interface for any
  time; that is by design today and documented ("What it does not protect
  against: an operator").
* Signed releases, SBOM, `SECURITY.md`, reproducible builds: none exist.

## Project state review

| Claim | Verdict | Notes |
| --- | --- | --- |
| README says 0.25.0 while `Cargo.toml` says 0.33.0 | **Right** (and now further behind) | `Cargo.toml` is 0.34.0; the README still says 0.25.0. Fixed in this pull request, and RELEASING.md now lists the README line in the version bump. |
| DEVELOPMENT.md documents through the 0.33 era | **Out of date** | It now has M40 (0.34.0) and M41/M42 planned. |
| Feature list (section 3) | **Right** | Matches DEVELOPMENT.md and docs/. "DHCPv4 and DHCPv6 server behaviour" is right since M29; host emulation also does the client side. |
| QUIC/HTTP/3 gaps: 0-RTT, migration, QPACK dynamic table, path MTU discovery | **Right** | Listed as not done under M31. |
| SSH gaps: SFTP/SCP, forwarding, RSA/ECDSA | **Right** | Listed under M27. |
| SMB gaps: encryption, Kerberos, leases/oplocks, durable handles | **Right** | Listed under M30. |
| SIP/RTP gaps: TCP/TLS, SRTP, DTMF, proxy, media on several workers | **Right** | Listed under M28. |
| DHCPv6 relay messages and prefix delegation | **Right** | Listed under M29 (and prefix delegation for the client under M19). |
| TCP: BBR-like pacing, Accurate ECN, L4S | **Right** | Listed under M34. |
| Session-duration, think-time and arrival distributions (5.2) | **Partly right** | Arrivals are done (M17: Poisson, bursts, ramps, shapes, per template); think time exists as a fixed `think_time`. Session length distributions and personas are not done (#20). |
| Measurement (5.3): requested/sent/received, drops, percentiles, run metadata, baselines | **Partly right** | Much exists: per-stream sent counts, `rx_dropped` ("dropped here before they were read"), latency percentiles, `RunInfo` (host, NIC, driver) in bench and Y.1564 reports, scenario `compare --baseline`, GUI receive charts. Missing: NIC and AF_XDP ring/DPDK queue counters, run metadata on ordinary runs, confidence intervals, PTP/hardware timestamps, a clear generator/network/receiver loss split in one report. |
| Distributed testing (5.4) | **Right** | Fleet (M37) deploys, starts on a shared clock and adds up counters. Discovery, health and reconnect, per-agent telemetry and partial-run recovery are not done (listed under M37). |
| Scenario templates (5.5) | **Right** | Scenarios exist (M16); ready-made templates for firewall, NAT exhaustion, failover etc. do not. |
| Interoperability matrix (5.6) | **Partly right** | Already tested both ways in CI: OpenSSH, curl, h2load, mosquitto, SIPp, Samba/smbclient, aioquic, openssl, dig, udhcpc. Not tested: nginx/Apache, GnuTLS, quiche/ngtcp2, EMQX, Asterisk/FreeSWITCH, Windows Server SMB, BIND/Unbound/CoreDNS as servers for our DNS client. There is no published matrix. |
| Performance figures (section 6) | **Right** | docs/multi-core.md reports exactly these sandbox numbers (5.8/23, 0.90/3.4, 0.66/1.4 Mpps) and says they come from a 4-core sandbox with veths. FeroTRX makes no physical-NIC or TRex-class claim anywhere. |
| Feature-status matrix (P0.2) | **Right** | None exists; DEVELOPMENT.md's "not done" notes are the closest thing. |
| Fuzzing, soak and leak tests (P0.5) | **Right** | See the security review's section 3 above. |

The project state review makes no security claims and asks for no fixes; its
priorities (a status matrix, an interoperability matrix, measurement
clarity, traffic realism) are input for planning after the security work and
are not turned into issues by this pull request.
