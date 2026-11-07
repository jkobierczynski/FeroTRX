> Outside source-level security review of 6 November 2026 (commit `fc3dc04`, 0.33.0), kept as received.
> Each finding is checked against 0.34.0 in [2026-11-06-review-check.md](2026-11-06-review-check.md);
> the fixes are planned in [2026-11-security-plan.md](2026-11-security-plan.md) and issues #71 to #75.

# FeroTRX -- Security Review

**Repository:** https://github.com/jkobierczynski/FeroTRX\
**Review date:** 6 November 2026\
**Inspected snapshot:** `fc3dc043b325adc69e589578a3005d6f2771d10f`\
**Language:** Rust\
**Scope:** Remote control, authentication, TLS/mTLS, file handling,
network protocol implementations, SSH, QUIC, packet processing,
dependencies and CI/CD.

> **Scope limitation:** This is a source-level security review, not a
> completed penetration test, formal cryptographic audit, or proof of
> exploitability. The review inspected selected source files and tests;
> it did not execute FeroTRX against malicious traffic. Findings should
> be revalidated against the current repository before implementation or
> release decisions.

## 1. Executive assessment

FeroTRX has a promising security foundation for a relatively young
traffic-generation project. Positive design choices include:

-   Rust and its memory-safety guarantees.
-   TLS and mutual TLS support.
-   Separate read-only and operator roles.
-   Connection and request-size limits.
-   Login timeouts and failed-login handling.
-   File access restrictions in the CLI remote-control server.
-   Audit logging.
-   Dedicated security tests for authentication, TLS and file
    restrictions.

The most important issue identified is that **remote token
authentication can be used without TLS**. The CLI warns that tokens will
travel in cleartext, but it does not refuse to start in that
configuration. An attacker able to observe the management network could
capture a reusable token and potentially gain operator access.

The review also identified resource-exhaustion concerns around
statistics subscriptions, filesystem race conditions, insecure defaults
in the library API, lack of certificate revocation, audit-log error
handling, and CI supply-chain hardening opportunities.

## 2. Findings -- prioritized

### SEC-01 -- Remote tokens accepted without TLS

**Severity: High -- fix first**

**Relevant files:** - `crates/ferotrx-cli/src/remote.rs` -
`crates/ferotrx-ctl/src/server.rs`

The server checks whether authentication is required before allowing a
non-loopback listener. Token authentication satisfies that requirement,
but TLS is not mandatory.

A configuration such as the following is therefore possible:

``` bash
ferotrx serve \
  --listen 0.0.0.0:4510 \
  --token "some-secret-token"
```

The CLI warns that tokens travel in cleartext without TLS, but continues
running.

**Potential attack scenario:**

1.  An attacker can observe traffic on the management network.
2.  An operator authenticates using the token.
3.  The attacker captures the reusable token.
4.  The attacker connects to FeroTRX and authenticates.
5.  The attacker may start traffic-generation jobs and manipulate the
    remote engine.

This is especially serious because operator access can allow traffic to
be generated from the machine hosting FeroTRX.

**Recommended fix:**

  Configuration                            Expected behavior
  ---------------------------------------- -------------------
  Loopback + token, no TLS                 Allow
  External interface + mTLS                Allow
  External interface + token + TLS         Allow
  External interface + token, no TLS       Reject by default
  External interface + no authentication   Reject

Make this a hard security check rather than a warning. An explicit
`--allow-cleartext-token` override could be provided for isolated
laboratory environments, with a prominent warning.

**Acceptance tests:**

-   Non-loopback token-only configuration fails by default.
-   Non-loopback token plus TLS succeeds.
-   Non-loopback mTLS succeeds.
-   Loopback token-only configuration remains supported.
-   The explicit insecure override works only when deliberately supplied
    and is logged.

### SEC-02 -- Unbounded statistics subscriptions

**Severity: Medium -- resource exhaustion**

**Relevant file:** `crates/ferotrx-ctl/src/server.rs`, particularly
`subscribe()`.

Each `stats.subscribe` request creates a new operating-system thread.

The inspected implementation has a minimum subscription interval of 50
ms and a default maximum of 64 simultaneous connections. No
per-connection or global subscription limit was apparent in the
inspected code.

A single authenticated read-only client could therefore create a large
number of subscriptions. Read-only access should not provide an easy
route to exhausting the control server's resources.

**Recommended fixes:**

-   Maximum subscriptions per connection: 8--16, configurable if needed.
-   Global subscription limit.
-   Subscription count exposed in server statistics.
-   Reject excess subscriptions with a proper JSON-RPC error.
-   Ensure subscriptions terminate when their connection disappears.
-   Consider a bounded worker pool rather than one operating-system
    thread per subscription.

**Acceptance tests:**

-   Per-connection and global limits are enforced.
-   Excess requests return a predictable error.
-   Disconnecting a client cancels all its subscriptions.
-   Repeated subscribe/unsubscribe cycles do not leak threads or
    resources.

### SEC-03 -- File access and symbolic-link race conditions

**Severity: Medium -- filesystem security**

**Relevant file:** `crates/ferotrx-ctl/src/files.rs`

The file policy has several positive controls:

-   Canonical path checking.
-   Restriction to configured data directories.
-   Rejection of `..` traversal.
-   Symbolic-link resolution during validation.
-   Upload size limits.

However, the remote-control documentation acknowledges that a file can
be replaced by a symbolic link after its path has been checked. This
creates a time-of-check/time-of-use (TOCTOU) race.

This matters particularly if the data directory is writable by another
local account or process.

**Recommended fixes:**

1.  Use descriptor-based filesystem operations where practical.
2.  Avoid reopening files by path after validation without rechecking.
3.  Use `O_NOFOLLOW` on Linux where appropriate.
4.  Revalidate file identity before using files loaded into profiles.
5.  Ensure data directories are not writable by untrusted local users.

This is not necessarily remotely exploitable by itself, but it weakens
the filesystem isolation guarantee.

**Acceptance tests:**

-   Race tests attempt to replace checked files with symlinks.
-   File operations remain confined to approved directories.
-   File identity is checked where the design relies on a previously
    validated object.

### SEC-04 -- Unrestricted filesystem policy in the library API

**Severity: Medium -- secure defaults**

**Relevant files:** - `crates/ferotrx-ctl/src/controller.rs` -
`crates/ferotrx-cli/src/remote.rs`

The CLI explicitly configures `FilePolicy::dirs()`. However,
`Controller::new()` initializes the file policy with
`FilePolicy::unrestricted()`.

Consequently, a developer embedding FeroTRX as a Rust library and
creating a remote server using the default controller could
unintentionally expose filesystem access beyond the intended data
directory.

The standard CLI configuration avoids this issue, but the library API
does not have the same safe default.

**Recommended fixes:**

-   Make `Controller::new()` use a restricted filesystem policy.
-   Require explicit opt-in for unrestricted access.
-   Have the server refuse remote startup with unrestricted filesystem
    access unless explicitly overridden.
-   Clearly document the security implications of the unrestricted mode.

**Acceptance tests:**

-   A default controller cannot access arbitrary filesystem paths
    through remote methods.
-   Unrestricted access requires an explicit configuration choice.
-   Remote startup warns or fails when an unsafe policy is selected.

### SEC-05 -- No certificate revocation mechanism

**Severity: Medium -- identity lifecycle**

**Relevant file:** `crates/ferotrx-ctl/src/tls.rs`

FeroTRX supports client certificates and separate certificate
authorities for operator and read-only users. This is a sound design.

However, the current documentation acknowledges that certificate
revocation is not implemented. If an operator certificate is
compromised, revoking that individual certificate without replacing the
CA or changing the trust configuration is not supported.

**Recommended improvements:**

-   Certificate fingerprint denylist.
-   Certificate expiration monitoring.
-   Documented certificate rotation procedure.
-   Revocation support or an equivalent operational mechanism.
-   Individual identities rather than shared certificates.

For a distributed fleet of traffic-generation agents, this becomes
increasingly important.

**Acceptance tests:**

-   A denied certificate fingerprint cannot authenticate.
-   Certificate expiry is enforced.
-   Rotation can be performed without unnecessarily replacing unrelated
    identities.
-   Revocation/denylist changes have a documented reload or restart
    procedure.

### SEC-06 -- Audit log failures are silently ignored

**Severity: Medium -- audit integrity**

**Relevant file:** `crates/ferotrx-ctl/src/audit.rs`

The audit implementation deliberately ignores write errors. This avoids
a full disk preventing the server from responding, but it creates an
operational blind spot: an administrator may believe operations are
being audited when the audit log is no longer being written.

For a network testing platform, knowing who started a traffic-generation
operation is important.

**Recommended improvements:**

-   Track audit write failures.
-   Expose audit health in server status.
-   Emit a separate error through stderr or another monitoring channel.
-   Support an optional fail-closed mode for environments requiring
    complete auditability.
-   Consider log rotation and retention.

Retain fail-open behavior as an option rather than necessarily
terminating every server instance when logging fails.

**Acceptance tests:**

-   Simulated write failures are detected and surfaced.
-   Audit health changes to degraded when writes fail.
-   Fail-closed mode prevents sensitive operations when audit
    persistence is unavailable.
-   Tokens and other secrets are never written to audit logs.

### SEC-07 -- GitHub Actions supply-chain hardening

**Severity: Medium/Low -- CI/CD**

**Relevant files:** - `.github/workflows/ci.yml` -
`.github/workflows/release.yml`

The inspected workflows use version references such as:

``` yaml
- uses: actions/checkout@v4
- uses: dtolnay/rust-toolchain@stable
- uses: Swatinem/rust-cache@v2
- uses: actions/upload-artifact@v4
```

These are mutable references rather than immutable commit-SHA
references, creating an avoidable supply-chain risk.

**Recommended improvements:**

1.  Pin third-party GitHub Actions to full commit SHAs.
2.  Explicitly define minimal `GITHUB_TOKEN` permissions at workflow/job
    level.
3.  Add automated Rust dependency vulnerability scanning.
4.  Add dependency review to pull requests.
5.  Consider signed release attestations and artifact provenance.
6.  Verify that release tags are protected against unauthorized
    movement.

The release workflow already uses `--locked` for Cargo builds and
generates SHA-256 checksums. Those are good foundations.

## 3. Protocol implementation security

FeroTRX contains multiple protocol implementations, including complex
custom parsing and state machines. This is a significant security attack
surface.

  -----------------------------------------------------------------------
  Component                           Security areas requiring scrutiny
  ----------------------------------- -----------------------------------
  QUIC / HTTP/3                       Connection state, frame parsing,
                                      packet protection, flow control,
                                      loss recovery and QPACK

  SSH                                 Transport, key exchange, packet
                                      protection, authentication and
                                      connection handling

  SMB 2/3                             NTLMv2, signing, file operations,
                                      client/server state and message
                                      parsing

  HTTP/2                              HPACK decoding, stream state and
                                      flow-control handling

  MQTT                                Variable-length fields, QoS state
                                      transitions and malformed packets

  SIP/RTP                             Header parsing, transaction state,
                                      sequence handling and payload
                                      validation
  -----------------------------------------------------------------------

The sampled QUIC frame parser, QPACK decoder and SSH transport
implementation did not establish a directly exploitable parser
vulnerability. However, the complexity warrants more testing than
ordinary unit tests.

### Recommended protocol security testing

  Area     Testing to introduce
  -------- --------------------------------------------------------------
  QUIC     Malformed frames, ACK ranges, stream offsets, connection IDs
  QPACK    Huffman edge cases, integer overflow, malformed references
  SSH      Malformed packet lengths, KEX negotiation, rekeying
  SMB      Malformed SMB headers, compound requests, NTLM inputs
  HTTP/2   HPACK decoding, stream state, flow-control violations
  MQTT     Invalid packet lengths, QoS state transitions
  SIP      Malformed headers, digest authentication, transaction state
  RTP      Sequence number wraparound, malformed payloads

### Automated fuzzing

A dedicated fuzzing workspace and `cargo-fuzz` targets were not
identified in the inspected repository tree. This should be addressed.

Suggested layout:

``` text
fuzz/
├── fuzz_targets/
│   ├── fuzz_packet_decode.rs
│   ├── fuzz_quic_frames.rs
│   ├── fuzz_qpack_decode.rs
│   ├── fuzz_ssh_transport.rs
│   ├── fuzz_http2_hpack.rs
│   ├── fuzz_smb_decode.rs
│   ├── fuzz_mqtt_decode.rs
│   └── fuzz_sip_decode.rs
```

Recommended approach:

-   `cargo-fuzz` with libFuzzer.
-   AddressSanitizer where applicable.
-   Persistent regression corpus.
-   Fuzzing on every security-sensitive parser change.
-   Longer-running fuzz jobs nightly.
-   Differential testing against established implementations.

For QUIC and SSH, interoperability testing is particularly important. A
protocol implementation can pass its own unit tests while still
mishandling malformed or unusual peer behavior.

Rust eliminates many memory-safety problems, but it does not eliminate
integer overflow, excessive allocation, state-machine errors,
authentication mistakes or denial-of-service vulnerabilities.

## 4. Positive security findings

  Security control                 Assessment
  -------------------------------- -----------------
  Rust memory-safety foundations   Good
  rustls TLS implementation        Good
  Mutual TLS                       Good
  Read/operator separation         Good
  Token comparison                 Good
  Connection limits                Good
  Request-size limits              Good
  Login timeouts                   Good
  Failed-login handling            Good
  Filesystem restrictions in CLI   Good
  Audit logging                    Good foundation
  Dedicated security tests         Good

### Authentication

The token implementation supports:

-   Plain tokens held in memory.
-   SHA-256 token hashes in configuration.
-   Separate read-only and operator credentials.
-   Failed-login delays.
-   Connection termination after five failed attempts.

The SHA-256 option is useful because the configuration file need not
contain the original token. However, tokens should still be high-entropy
random values; SHA-256 is not a password-hardening function.

### TLS

The implementation uses rustls and supports separate client certificate
authorities for read-only and operator identities. This is a sensible
design for a distributed traffic-generation platform.

### Filesystem restrictions

The CLI's use of dedicated data directories is a good security boundary.
It is substantially better than allowing remote clients to specify
arbitrary filesystem paths.

### Testing

The dedicated `ferotrx-ctl/tests/security.rs` suite is encouraging. It
tests authentication, certificate verification, access roles, connection
limits, request sizes and filesystem restrictions.

## 5. Additional security improvements

Beyond the findings above, the following controls should be considered
as FeroTRX matures.

  -----------------------------------------------------------------------
  Feature                 Priority                Reason
  ----------------------- ----------------------- -----------------------
  Global login rate       High                    Prevent distributed
  limiting                                        token guessing

  Subscription limits     High                    Prevent resource
                                                  exhaustion

  Per-agent traffic       High                    Prevent accidental or
  quotas                                          malicious network
                                                  flooding

  Fuzzing infrastructure  High                    Protect custom protocol
                                                  implementations

  Safe library filesystem High                    Prevent insecure
  defaults                                        embedding

  TLS enforcement for     High                    Prevent credential
  remote tokens                                   interception

  Certificate revocation  Medium                  Manage compromised
                                                  identities

  Audit-health monitoring Medium                  Preserve operational
                                                  accountability

  Signed release          Medium                  Supply-chain assurance
  attestations                                    

  SBOM generation         Medium                  Dependency transparency

  Security policy /       Medium                  Responsible
  SECURITY.md                                     vulnerability
                                                  disclosure

  Reproducible builds     Medium                  Release integrity
  -----------------------------------------------------------------------

### Traffic-generation safeguards

One aspect specific to FeroTRX deserves separate consideration.

FeroTRX can generate substantial traffic using libpcap, AF_XDP and DPDK.
An authenticated operator can potentially cause serious network
disruption, even without exploiting a software vulnerability.

Consider optional operational safeguards:

-   Maximum PPS per interface.
-   Maximum bandwidth per interface.
-   Maximum concurrent flows.
-   Maximum duration per job.
-   Explicit confirmation for unlimited-rate transmission.
-   Interface allowlists.
-   Optional destination subnet allowlists.
-   Global traffic-generation quotas.

These should be configurable rather than permanently restricting
legitimate benchmarking.

For production deployments, consider making unlimited-rate transmission
an explicit privileged capability.

## 6. Recommended remediation order

### Phase 1 -- Remote control security

**Priority: Immediate**

-   Enforce TLS for non-loopback token authentication.
-   Add global and per-connection subscription limits.
-   Introduce login rate limiting.
-   Make filesystem restrictions safe by default in the library API.

### Phase 2 -- Protocol security

**Priority: High**

-   Introduce cargo-fuzz.
-   Fuzz QUIC, SSH, SMB, HTTP/2 and packet decoders.
-   Add malformed-input regression tests.
-   Test memory and CPU consumption under hostile input.

### Phase 3 -- Operational security

**Priority: Medium**

-   Implement certificate revocation or fingerprint denylisting.
-   Improve audit failure reporting.
-   Introduce traffic-generation guardrails.
-   Harden filesystem operations against symlink races.

### Phase 4 -- Software supply chain

**Priority: Medium**

-   Pin GitHub Actions by commit SHA.
-   Add cargo audit and dependency scanning.
-   Generate SBOMs.
-   Sign releases and publish provenance attestations.

## 7. Overall security assessment

These are qualitative engineering assessments, not measured
vulnerability statistics or certification results.

  Category                              Assessment
  ----------------------------------- ------------
  Memory safety foundations                   9/10
  Remote authentication design                7/10
  TLS / certificate architecture              8/10
  Authorization / RBAC                        8/10
  Filesystem security                         7/10
  Resource-exhaustion protection              6/10
  Protocol implementation assurance           5/10
  Auditability                                7/10
  Supply-chain security                       6/10

### Overall assessment: 7.0/10

FeroTRX has a good security foundation, but still needs more work before
I would recommend exposing its control plane to an untrusted network or
treating it as a production-grade traffic-generation appliance.

The biggest concern is not the Rust implementation itself. It is the
combination of:

1.  A powerful remotely accessible control plane.
2.  Multiple complex, custom protocol implementations.
3.  High-performance packet processing.
4.  The ability to generate potentially disruptive traffic.

That combination makes resource-exhaustion resistance, authentication
enforcement and protocol fuzzing particularly important.

**Recommendation:** Make FeroTRX security hardening a dedicated
development milestone, with SEC-01 through SEC-07 tracked as work items.
Do not prioritize adding more application protocols over the immediate
remote-control security fixes.

## 8. Source references

-   [Remote server
    implementation](https://github.com/jkobierczynski/FeroTRX/blob/main/crates/ferotrx-ctl/src/server.rs)
-   [Authentication](https://github.com/jkobierczynski/FeroTRX/blob/main/crates/ferotrx-ctl/src/auth.rs)
-   [TLS
    implementation](https://github.com/jkobierczynski/FeroTRX/blob/main/crates/ferotrx-ctl/src/tls.rs)
-   [Filesystem
    policy](https://github.com/jkobierczynski/FeroTRX/blob/main/crates/ferotrx-ctl/src/files.rs)
-   [Security
    tests](https://github.com/jkobierczynski/FeroTRX/blob/main/crates/ferotrx-ctl/tests/security.rs)
-   [Remote control security
    documentation](https://github.com/jkobierczynski/FeroTRX/blob/main/docs/remote-control.md)
-   [CI
    workflow](https://github.com/jkobierczynski/FeroTRX/blob/main/.github/workflows/ci.yml)
-   [Release
    workflow](https://github.com/jkobierczynski/FeroTRX/blob/main/.github/workflows/release.yml)

------------------------------------------------------------------------

*Prepared from a source-level review of the repository snapshot
identified above. Revalidate findings against the current code before
treating this document as a release audit or security certification.*
