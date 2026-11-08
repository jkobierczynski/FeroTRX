# Fuzzing and hostile-input tests

Everything FeroTRX reads from the network or from a client must not panic,
hang or allocate without bound, whatever the bytes are: frames on a
receiving port, a peer's TCP or UDP payload, a control client's requests,
an uploaded profile or capture. Rust rules out memory corruption; it does
not rule out these. Two things check it:

* **Hostile-input tests** in the normal test suite (`cargo test`): every
  fuzz target runs on its seeds, on every input that once broke it
  (`fuzz/regressions/<target>/`), and on a few hundred seeded random
  mutations of the seeds. The control server gets requests with every
  method and hostile parameters (wrong types, huge numbers, deep nesting,
  long lines, paths outside its folder). They run on every CI build.
* **Fuzz targets** in `fuzz/` for [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
  (libFuzzer, coverage guided). On pull requests CI runs each target whose
  code changed for 60 s; every night it runs all of them for 10 minutes
  (workflow `Fuzz`, not a required check). Long campaigns run by hand.

## The targets

| Target | What it feeds | Where the input goes |
|---|---|---|
| `app` | one application session, client or server, of HTTP/1.1, HTTPS, HTTP/2 (h2c and h2), TLS, DNS over TCP and UDP, MQTT, SMB, SSH, NTP, SIP (with RTP/RTCP on its media ports), HTTP/3 | `AppSession::receive`, `timer`, `media`, `peer_closed` |
| `tcp_engine` | a TCP client and server engine of each of those TCP protocols, on a link the input tampers with (drop, duplicate, overwrite bytes with checksums fixed, inject frames) | `TcpEngine::handle_frame` |
| `udp_engine` | the same for the UDP engine (DNS, NTP, SIP, HTTP/3) | `UdpEngine::handle_frame` |
| `host_engine` | host emulation: DHCPv4/v6 clients and servers, SLAAC, router advertisements, ARP/NDP, IGMP/MLD | `HostEngine::handle_frame` |
| `wire` | every parser a received frame meets: Ethernet/VLAN, ARP, IPv4/IPv6, TCP and its options, UDP, NDP, RA, MLD/IGMP queries, DHCPv4/v6, the checksum fixer, the loss/latency signature reader with interval counters | |
| `packet` | the decoder of `inspect`, captures and the GUI, and the GUI's import into packet descriptions | `ferotrx_packet::decode`, `import` |
| `pcap` | a pcap or pcapng file, as `--input`, `file.put` and profiles read them | `Capture::from_reader` |
| `profile` | a profile of every kind (traffic, TCP, UDP, hosts, bench, Y.1564, scenario, fleet), as `ferotrx check`, `profile.load` and the GUI read it | `check::check_text` |
| `text` | one-line syntaxes: packet descriptions, `--impair`, `--vary`, size mixes, traffic models and shapes, rates, durations, sizes, addresses and ranges | |
| `ssh` | SSH messages after the key exchange (as if decrypted) to a server or a client | the sessions' message handlers |
| `quic` | QUIC frames in 1-RTT packets (as if decrypted) to an established connection with HTTP/3 on it, plus the frame, transport parameter, QPACK and HTTP/3 frame parsers | `Conn`, `H3Server`/`H3Client` |
| `ctl_call` | JSON-RPC requests straight into a `Controller` | `Controller::call` |
| `ctl_server` | any bytes over a TCP connection to a running control server with logins | `Connection::handle_line` and everything behind it |

The targets are functions in `ferotrx_core::fuzzing` and
`ferotrx_ctl::fuzzing` (feature `fuzzing`, not an API); `fuzz/fuzz_targets/`
only calls them. Inputs with several parts share one layout, described at
the top of `crates/ferotrx-core/src/fuzzing/mod.rs`: a selector byte (which
protocol, which end), then pieces of an op byte, a two-byte little-endian
length and the bytes.

The encrypted protocols are fuzzed twice: through `app` and the engines,
where the input meets the handshake and the record layer (TLS, the SSH
transport before keys, QUIC Initial protection), and through `ssh` and
`quic`, which skip the encryption to reach what is behind it. The control
server targets open no interfaces (every opener fails) and keep their files
in a temporary folder with small upload limits.

## Running the fuzzers

Once:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

Then, from the repository:

```sh
fuzz/run.sh                         # every target, 60 s each (13 minutes)
fuzz/run.sh -t 3600 app ctl_server  # these two, an hour each
fuzz/run.sh -t 28800 -j 4 app       # one target, 8 hours, 4 processes
fuzz/run.sh --changed origin/main   # only targets whose code you changed
fuzz/run.sh --list                  # the targets and the files each covers
```

`run.sh` first writes the seeds to `fuzz/seeds/<target>/` (transcripts of
real sessions between FeroTRX's own clients and servers, frames of real
runs, the example profiles and captures), then runs
`cargo +nightly fuzz run <target>` with `-rss_limit_mb=2048` (more memory
is a finding), `-timeout=10` (one input taking longer is a finding) and
`-max_len=65536` (and `-detect_leaks=0` for `ctl_server`, whose
connection threads outlive an input, which LeakSanitizer reports as a
leak). New interesting inputs collect in `fuzz/corpus/<target>/`,
so the next run starts where this one stopped; keep that folder between
campaigns. Anything after `--` goes to libFuzzer.

How long: a minute per target finds the shallow bugs; the protocol
targets (`app`, `tcp_engine`, `udp_engine`, `quic`, `ssh`, `ctl_server`)
keep finding new paths for hours. A useful after-hours campaign is the six
of them for 1 to 2 hours each with `-j` set to the cores you can spare, and
once in a while a whole night on one. libFuzzer prints `cov:` (edges seen)
every few seconds; when it stops growing for an hour, move on.

To run one target by hand:

```sh
cd fuzz
cargo +nightly fuzz run app corpus/app seeds/app -- -max_total_time=600 -rss_limit_mb=2048 -timeout=10
```

## When it finds something

libFuzzer stops, prints the panic (or `out-of-memory`, `timeout`) with a
backtrace, and saves the input as `fuzz/artifacts/<target>/crash-<sha1>`
(or `oom-...`, `timeout-...`). Then:

1. **Reproduce:** `cd fuzz && cargo +nightly fuzz run <target> artifacts/<target>/crash-...`
   runs that one input.
2. **Minimize:** `cargo +nightly fuzz tmin <target> artifacts/<target>/crash-...`
   shrinks it to the smallest input that still fails (written as
   `minimized-from-...`).
3. **Report:** open an issue with the target name, the panic message and
   backtrace, and the minimized input attached (or `xxd` of it if it is
   small). A crash in the control server or anything a peer can send is a
   security bug: report it privately as [SECURITY.md](../SECURITY.md) says.
4. **Keep it:** once fixed, copy the minimized input to
   `fuzz/regressions/<target>/` under a name that says what it was
   (`short-frame-signature`). The hostile-input tests run every file there,
   so the bug stays fixed; also add a unit test next to the code where it
   says more.

A crash in CI is kept as the `fuzz-artifacts` artifact of the run.

To shrink a corpus that grew large: `cargo +nightly fuzz cmin <target>`.
To see what a target reaches: `cargo +nightly fuzz coverage <target>`, then
`llvm-cov show` as cargo-fuzz explains.

## Hostile peers

Beyond random bytes, the engines are checked against peers that misbehave
on purpose (`tests/hostile.rs` in `ferotrx-core`): oversized lengths in
every length field, endless headers, a peer that trickles one byte at a
time, floods of new streams and connections. The checks are that memory
stays bounded, the run reports protocol errors, and nothing hangs.

## The hostile-input tests alone

```sh
cargo test -p ferotrx-core --lib fuzzing
cargo test -p ferotrx-ctl --lib fuzzing
FEROTRX_HOSTILE_ITERS=5000 cargo test --release -p ferotrx-core --lib fuzzing
```

`FEROTRX_HOSTILE_ITERS` sets the mutations per target (150 in debug builds,
1500 in release).
