# Releasing FeroTRX

Releases are built and published by [`.github/workflows/release.yml`](.github/workflows/release.yml)
when a version tag `vX.Y.Z` is pushed. The release gets:

| File | For |
| --- | --- |
| `ferotrx_X.Y.Z-1_amd64.deb` | Debian 12+ and Ubuntu 22.04+ (x86_64); depends on `libpcap0.8` |
| `ferotrx-vX.Y.Z-x86_64-linux.tar.gz` | Other Linux distributions (x86_64, glibc 2.36+, libpcap) |
| `ferotrx-vX.Y.Z-aarch64-macos.tar.gz` | macOS on Apple silicon |
| `ferotrx-vX.Y.Z-x86_64-macos.tar.gz` | macOS on Intel |
| `ferotrx-vX.Y.Z-x86_64-windows.zip` | Windows x86_64; needs [Npcap](https://npcap.com/) |
| `SHA256SUMS` | Checksums of all of the above |

Each archive holds the `ferotrx` binary, `README.md`, `LICENSE` and `examples/`.
The packages are built with the default features (libpcap, AF_XDP on Linux).
DPDK stays opt-in and is not packaged: build it from source with `--features dpdk`.

## Version numbers

Each milestone bumps the minor version: v0.1.0, v0.2.0, v0.3.0, …
The milestone's pull request bumps `version` under `[workspace.package]` in
`Cargo.toml`, and the `version = "…"` of the internal crates under
`[workspace.dependencies]`, then runs `cargo build` so `Cargo.lock` follows.

The workflow refuses a tag that does not match the workspace version
(tag `v0.2.0` needs `version = "0.2.0"`).

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
