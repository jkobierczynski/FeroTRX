# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue:
use **[Report a vulnerability](https://github.com/jkobierczynski/FeroTRX/security/advisories/new)**
on the repository's Security tab (GitHub's private vulnerability reporting).
Only the maintainer sees the report, and we can work on a fix and an
advisory together there.

Say what is affected (version or commit, operating system, backend), how to
reproduce it, and what an attacker gains. A first answer comes within a week.
Once a fix is released, the advisory is published with credit to you unless
you would rather not be named.

## Supported versions

FeroTRX is before 1.0: fixes go into the next minor release (0.x.0) from
`main`; older releases get no patch releases. Run the latest release.

## What counts as a vulnerability

FeroTRX generates traffic on purpose, often as root, so the line matters.
[docs/remote-control.md](docs/remote-control.md#security) says what the
control server protects against and what it does not. In short:

* **In scope:** anyone without a token or certificate getting past
  `server.info`; a read-only login changing anything; a client reaching
  files outside the server's data directories; tokens or keys leaking (in
  logs, files, error messages); a panic, hang or unbounded memory use caused
  by a client's request, an uploaded profile, or traffic arriving on an
  interface FeroTRX listens on; problems in the release packages or how
  they are built.
* **Not a vulnerability by itself:** an operator sending heavy or malformed
  traffic (that is what the tool is for); someone who already has an
  operator token or certificate; local users of a machine where the server
  listens on loopback; a server started with `--insecure` or
  `--allow-cleartext-token`.

## Checking a release

Every release file has a build provenance attestation, and each release
carries `SHA256SUMS` and an SBOM; [RELEASING.md](RELEASING.md#checking-a-release)
shows how to check them.
