# Security plan, November 2026

How the findings of [the security review of 6 November 2026](2026-11-06-security-review.md)
get fixed, after [checking them against 0.34.0](2026-11-06-review-check.md).
Every finding still applies; SEC-02 is partly handled already (a closed
connection cancels its subscriptions). Five milestones, each its own issue
and pull request, each a minor version.

## Order

| Order | Milestone | Findings | Why here | Version |
| --- | --- | --- | --- | --- |
| 1 | **M43, control-plane hardening**, [#71](https://github.com/jkobierczynski/FeroTRX/issues/71) | SEC-01, SEC-02, SEC-04, SEC-06, login limits | The only findings a remote client can use: a sniffed token gives operator rights, a read-only login can exhaust threads, a client without a token can take every connection slot. Small, all in `ferotrx-ctl`. M41 (the GUI starting its own server, a Windows service) should be built on these rules, not retrofitted. | 0.35.0 |
| 2 | **M44, CI and release supply chain**, [#72](https://github.com/jkobierczynski/FeroTRX/issues/72) | SEC-07, `SECURITY.md`, `cargo deny`, SBOM, provenance | No code changes, little risk, protects every later release. | 0.36.0 |
| 3, 4 | M41, M42 from [#69](https://github.com/jkobierczynski/FeroTRX/issues/69) (Windows) | | Already planned and started; not protocol work, so the review's "no new protocols before the fixes" does not apply. | 0.37.0, 0.38.0 |
| 5 | **M45, fuzzing and hostile-input tests**, [#73](https://github.com/jkobierczynski/FeroTRX/issues/73) | Section 3 | The largest job; finds panics, unbounded allocations and hangs in the parsers that read traffic and client uploads. | 0.39.0 |
| 6 | **M46, certificate revocation and safe file access**, [#74](https://github.com/jkobierczynski/FeroTRX/issues/74) | SEC-05, SEC-03, two file bugs found while checking | Needs an operator or a local user to matter. | 0.40.0 |
| 7 | **M47, traffic guardrails**, [#75](https://github.com/jkobierczynski/FeroTRX/issues/75) | Section 5 safeguards, per-agent quotas | Protects against a careless or malicious operator; opt-in, so nothing changes for benchmarking. | 0.41.0 |

Versions follow merge order, as before. If M41 and M42 go after all five
security milestones instead, M45 to M47 become 0.37.0 to 0.39.0 and M41/M42
become 0.40.0/0.41.0.

## What changes for users

Only M43 changes behaviour that works today:

* `ferotrx serve --listen <not loopback> --token T` without `--tls-cert`
  stops starting. Fix: `ferotrx certs DIR --server NAME` and add
  `--tls-cert`/`--tls-key` (clients add `--ca`), or, in an isolated lab,
  `--allow-cleartext-token`. This hits `scripts/fleet-netns.sh`, the
  `docs/fleet.md` example and a GUI on a Windows host using a token to reach
  `serve` in a VM; M43 updates the script and the docs.
* Library users of `Controller::new()` get no file access until they pass a
  `FilePolicy`; `FilePolicy::unrestricted()` off loopback needs
  `ServerConfig::unrestricted_files`.
* More than 16 `stats.subscribe` on one connection get an error. The GUI and
  Python client use one or two.

M44 to M47 add options and checks without changing defaults, except that M46
makes `ferotrx certs` issue 1-year certificates instead of ones valid until
2035.

## Decisions in each milestone

* M43: the limit numbers (16 subscriptions per connection, 256 per server,
  16 pre-login slots, 10 s login timeout, 20 wrong tokens per minute per
  IP) are first guesses and become options.
* M44: whether a pushed-again tag may still replace its release (today it
  does on purpose) or `v*` tags get protected. Tag rulesets are a
  repository setting only Jurgen can change.
* M46: CRLs plus a fingerprint deny list, not OCSP: lab PKIs have no
  responder, and a deny list also works for certificates from someone
  else's CA.
* M47: limits apply to remote operators only; the local CLI stays
  unlimited.

## Not planned from the reviews

* Reproducible builds: worth it once releases are signed; revisit after M44.
* A third role between read and operator: M47's server limits cover the
  need.
* The project state review's other priorities (feature-status matrix,
  interoperability matrix, measurement clarity, traffic realism) are input
  for planning after this, not security work.
