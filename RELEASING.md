# Releasing FeroTRX

Releases are built and published by [`.github/workflows/release.yml`](.github/workflows/release.yml)
when a version tag `vX.Y.Z` is pushed. The release gets:

| File | For |
| --- | --- |
| `ferotrx_X.Y.Z-1_amd64.deb` | Debian 12+ and Ubuntu 22.04+ (x86_64); depends on `libpcap0.8` |
| `ferotrx-vX.Y.Z-x86_64-linux.tar.gz` | Other Linux distributions (x86_64, glibc 2.36+, libpcap) |
| `ferotrx-vX.Y.Z-aarch64-macos.tar.gz` | macOS on Apple silicon |
| `ferotrx-vX.Y.Z-x86_64-macos.tar.gz` | macOS on Intel |
| `ferotrx-vX.Y.Z-x86_64-windows.msi`, `ferotrx-vX.Y.Z-x86_64-windows.zip` | Windows x86_64 (installer and archive); needs [Npcap](https://npcap.com/) |
| `ferotrx-X.Y.Z-py3-none-any.whl`, `ferotrx-X.Y.Z.tar.gz` | The Python client (`pip install ferotrx-X.Y.Z-py3-none-any.whl`), any OS |
| `ferotrx-vX.Y.Z-ferotrx-cli.cdx.json`, `ferotrx-vX.Y.Z-ferotrx-gui.cdx.json` | SBOM (CycloneDX JSON): every crate in `ferotrx` and `ferotrx-gui`, with version, license and checksum |
| `SHA256SUMS` | Checksums of all of the above |

Every file also has a signed build provenance attestation, stored with
GitHub (see [Checking a release](#checking-a-release)).

Each archive holds the `ferotrx` binary, `README.md`, `LICENSE`, `examples/` and the manual in `docs/`.
The packages are built with the default features (libpcap, AF_XDP on Linux).
DPDK stays opt-in and is not packaged: build it from source with `--features dpdk`.

## Version numbers

Each milestone bumps the minor version: v0.1.0, v0.2.0, v0.3.0, …
The milestone's pull request bumps `version` under `[workspace.package]` in
`Cargo.toml`, and the `version = "…"` of the internal crates under
`[workspace.dependencies]`, then runs `cargo build` so `Cargo.lock` follows.
The Python client's version goes up with it: `version` in
`python/pyproject.toml` and `__version__` in `python/src/ferotrx/__init__.py`
(a test checks that the three agree). Update the "current version" line in
`README.md` as well.

The workflow refuses a tag that does not match the workspace version
(tag `v0.2.0` needs `version = "0.2.0"`), and a Python client whose version
is not the workspace's.

## Cutting a release

With the version bump merged into `main`:

```sh
git checkout main && git pull
git tag -a v0.2.0 -m "FeroTRX v0.2.0"
git push origin v0.2.0
```

Then watch the **Release** workflow under the repository's Actions tab. When it
is green, the release is on the Releases page, with notes generated from the
merged pull requests.

## Redoing a release (moving a tag)

To publish a release again from another commit, for example after fixing the
packaging, move the tag and push it again:

```sh
git checkout main && git pull
git tag -fa v0.1.0 -m "FeroTRX v0.1.0"
git push --force origin v0.1.0
```

The workflow deletes the existing GitHub Release for that tag (the tag itself
stays) and creates it again with fresh packages and notes. Deleting the tag
first (`git push origin :refs/tags/v0.1.0`) and pushing it again works the
same way. Re-running a finished Release workflow from the Actions tab rebuilds
the same commit and replaces the release as well.

The workflow that runs is the one in the tagged commit, so a tag must point at
a commit that has `.github/workflows/release.yml`.

Moving a tag publishes new files with new attestations. Attestations of the
replaced files stay valid for those files: they still say which commit and
workflow run built them, so a download from before the move can still be
traced.

## Checking a release

With the [GitHub CLI](https://cli.github.com/), check that a downloaded file
was built by this repository's release workflow:

```sh
gh attestation verify ferotrx_0.38.0-1_amd64.deb --repo jkobierczynski/FeroTRX
```

It prints the workflow, commit and tag that built the file, and fails for a
file that was changed or built anywhere else. Without `gh`, compare the file
with `SHA256SUMS` (`sha256sum -c SHA256SUMS --ignore-missing`); that shows it
is the file on the release page, not who built it.

The SBOM files list every Rust crate compiled into the programs, for all
targets, with its version and license. Feed them to a scanner such as
`grype sbom:ferotrx-v0.38.0-ferotrx-cli.cdx.json` or `osv-scanner --sbom=...`.
The Python client has no dependencies, so it has no SBOM.

## How the build is protected

* Every action in `.github/workflows` is pinned to a commit, with its
  version in a comment; Dependabot (`.github/dependabot.yml`) proposes
  updates each week, as it does for `Cargo.lock` and the Python tools.
* Workflows get a read-only token; only the publish job may write (to
  create the release) and sign attestations.
* Builds use `--locked`, so they compile exactly what `Cargo.lock` says.
* CI's **Dependencies** job runs `cargo deny check` (RustSec advisories,
  licenses, crate sources; settings in `deny.toml`) and, on pull requests,
  GitHub's dependency review of what the change adds. It is not a required
  check: an advisory published today should not block an unrelated merge,
  but it shows red until it is fixed or listed in `deny.toml` with a reason.

## Trying the packaging without releasing

Pull requests that change the release workflow or the CLI's `Cargo.toml` build
all packages without publishing; they are attached to the workflow run as
artifacts. **Actions → Release → Run workflow** does the same for any branch.

Locally, the Debian package is built with
[cargo-deb](https://github.com/kornelski/cargo-deb):

```sh
cargo install cargo-deb
cargo deb -p ferotrx-cli          # writes target/debian/ferotrx_*.deb
```
