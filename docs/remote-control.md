# Remote control

`ferotrx serve` runs a control server; other programs load profiles, start and
stop runs and read live counters over it. `ferotrx ctl` is its command line client.
Runs started remotely go through the same engine code as `ferotrx run`.

```sh
# On the traffic box (here the lab's Debian host): certificates once, then the
# server, reachable from the lab network over TLS.
ferotrx certs /etc/ferotrx/pki --server 192.168.56.10 --client alice --read-client dashboard
sudo ferotrx serve --listen 0.0.0.0:4510 --data-dir /srv/profiles \
     --tls-cert /etc/ferotrx/pki/server.pem --tls-key /etc/ferotrx/pki/server-key.pem \
     --client-ca /etc/ferotrx/pki/ca.pem --read-client-ca /etc/ferotrx/pki/read-ca.pem \
     -p examples/lab-two-vlans.toml

# From anywhere that can reach it, with ca.pem and alice's certificate and key copied over:
export FEROTRX_CTL=192.168.56.10 FEROTRX_CA=ca.pem FEROTRX_CERT=alice.pem FEROTRX_KEY=alice-key.pem
ferotrx ctl info
ferotrx ctl load /srv/profiles/voip.toml               # a file on the server
ferotrx ctl load my-test.toml --upload                 # or send a local one
ferotrx ctl start lab-two-vlans -i enp0s3 -d 60s --watch   # live counters until it ends
ferotrx ctl start voip -i enp0s3 --rate 10kpps         # override every stream's rate
ferotrx ctl start voip -i enp0s3 -B af_xdp             # send through AF_XDP on the server
ferotrx ctl stats                                      # every run
ferotrx ctl stop 2
ferotrx ctl --json stats 2                             # JSON for scripts
```

## The protocol

The protocol is [JSON-RPC 2.0](https://www.jsonrpc.org/specification) over TCP,
one JSON object per line, on port 4510. Any language with sockets and JSON can
use it. From Python, use the `ferotrx` package in [`python/`](../python)
([docs/python-client.md](python-client.md)); from Rust, `ferotrx_ctl::Client`; with a
window, the [desktop GUI](gui.md).
[`examples/ctl-client.py`](../examples/ctl-client.py) shows the protocol in one
file of plain Python.

```python
import ferotrx  # pip install ./python

with ferotrx.Client("192.168.56.10", ca="ca.pem", cert="alice.pem", key="alice-key.pem") as c:
    c.load_profile("my-test.toml", upload=True)
    run = c.start("my-test", iface="enp0s3", duration="60s")
    for update in c.watch(run.id):
        print(f"{update.run.total.pps:.0f} pps")
```

| Method | Params | Result |
| --- | --- | --- |
| `server.info` | | name, version, protocol, interfaces, backends, auth_required, tls, this connection's role and user, the server's clock `time` (Unix seconds) and `max_file` |
| `auth` | `token` | `true`; the connection now has the token's role |
| `interfaces.list` | | `[{name, description}]` |
| `profile.load` | `path` (on the server) or `toml` (+ `base_dir`), optional `name` | the profile's streams |
| `profile.get`, `profile.unload` | `name` | profile / `true` |
| `profile.list` | | loaded profiles |
| `run.start` | `profile`, `output` (`{"iface": ..}`, `{"file": ..}` or `{"null": true}`; with `iface` also optional `backend`, `xdp_mode`, `queue`, `batch`, `dpdk_args`), optional `rate`, `limit`, `duration`, `ignore_errors`, `latency`, `rx` (`{"iface": .., "wait": "500ms"}`), `start_at` | the run (`started_at` once it started) |
| `run.stop` | `id`, `wait` (default true) | the run, final counters |
| `run.stats`, `run.remove` | `id` | the run |
| `run.list` | | every run |
| `tcp.start` | a TCP profile as `path` (on the server) or `toml` (+ `base_dir`); optional `iface`, `cps`, `connections`, `concurrency`, `duration`, `start_at` | the TCP run |
| `tcp.stop` | `id`, `wait` (default true) | the TCP run, final counters |
| `tcp.stats`, `tcp.remove` | `id` | the TCP run |
| `tcp.list` | | every TCP run |
| `udp.start` | a UDP profile as `path` (on the server) or `toml` (+ `base_dir`); optional `iface`, `rate`, `transactions`, `concurrency`, `duration`, `start_at` | the UDP run |
| `udp.stop` | `id`, `wait` (default true) | the UDP run, final counters |
| `udp.stats`, `udp.remove` | `id` | the UDP run |
| `udp.list` | | every UDP run |
| `file.put` | `path` (relative, in the first data directory), `data` (base64), `offset` (0 starts the file; pieces in order) | the file's `size` so far |
| `file.stat` | `path` | `exists`, `size`, `sha256` |
| `file.get` | `path`, optional `offset`, `length` (at most 4 MiB a call) | `data` (base64), `offset`, `size` of the whole file, `eof` |
| `capture.start` | `iface`, optional `filter` (BPF), `snaplen`, `promisc`, `direction` (`in`, `out`, `both`), `count`, `duration`, `file` (a pcap in the data directory), `rotate` (`100M`, `5m`), `files`, `stream` (default true: keep frames for `capture.read`), `ctl_traffic` (default false: TCP on the server's control port is left out) | the capture: `id`, `state`, `linktype`, `frames`, `bytes`, libpcap's `received`/`dropped`/`if_dropped`, `files` ([capturing](capture.md)) |
| `capture.read` | `id`, `after` (frame number, 0 for the first), optional `max` (1000), `wait_ms` (at most 2000) | `frames` (`n`, `ts_ns`, `len`, base64 `data`), `next`, `missed` (frames gone from the server's buffer), `more` (false once it ended and all was read) |
| `capture.get`, `capture.stop`, `capture.remove` | `id` (`stop` also `wait`) | the capture |
| `capture.list` | | every capture |
| `rx.start` | `iface`, optional `duration` | the receiver, its flows |
| `rx.stop` | `id`, `wait` (default true) | the receiver, final counters |
| `rx.stats`, `rx.remove` | `id` | the receiver |
| `rx.list` | | every receiver |
| `scenario.check` | a scenario as `path` (on the server) or `toml` (+ `base_dir`); optional `set` (`{name: value}`, as `--set`), `iface` | its checks and their conditions; nothing runs |
| `scenario.start` | as `scenario.check`, and optional `only` (check names), `lab` (default true: build the lab router the scenario names in `[lab]` first; needs `--lab`) | the scenario run: its checks run one after the other on the server |
| `scenario.get`, `scenario.remove` | `id` | the scenario run: `state`, each check's `state` (`waiting`, `running`, `pass`, `fail`, `error`, `skipped`), live `progress` and `report`, and the whole report once it has ended |
| `scenario.stop` | `id`, `wait` (default true) | the scenario run: the running check ends, the rest are skipped |
| `scenario.list` | | every scenario run |
| `bench.start` | a [benchmark profile](benchmarking.md) as `path` (on the server) or `toml`; `iface` (send) and `rx` (receive); optional `tests`, `sizes` (`"rfc2544"`, `"imix"`, `"124"`, …), `line_rate`, `trial_duration`, `repetitions`, `backend`, `xdp_mode`, `queue`, `workers` | the benchmark run, started on a thread of the server |
| `bench.get`, `bench.remove` | `id` | the benchmark run: `state`, `elapsed_s`, `tests`, `sizes`, every finished `trial` with its `size`, the run `info` (host, interfaces, backend), and once it has ended the `report` (as in `ferotrx bench --report`) and its `text` |
| `bench.stop` | `id`, `wait` (default true) | the benchmark run: it ends after the trial under way, with a partial report |
| `bench.list` | | every benchmark run |
| `y1564.start` | a [Y.1564 profile](y1564.md) as `path` or `toml`; `iface` and `rx`; optional `tests`, `services`, `line_rate`, `step_duration`, `performance_duration`, `backend`, `xdp_mode`, `queue`, `workers` | the Y.1564 run, on a thread of the server |
| `y1564.get`, `y1564.remove` | `id` | the Y.1564 run: `state`, `elapsed_s`, `tests`, `services`, every finished `steps` record (flows and service verdicts), the run `info`, and once it has ended the `report` (as in `ferotrx y1564 --report`) and its `text` |
| `y1564.stop` | `id`, `wait` (default true) | the run: the step under way ends early, and the report is partial |
| `y1564.list` | | every Y.1564 run |
| `lab.start` | optional `ipv6`, `nat`, `loss`, `delay`, `block_tcp`, `block_udp`, `dhcp`, `queues` | the lab router, built (server started with `--lab`; see [lab scripts](lab-scripts.md#a-standing-lab-router)) |
| `lab.stop` | | the lab router, removed |
| `lab.get` | | the lab router, or why there can be none |
| `stats.subscribe` | optional `id`, `interval_ms` (default 1000) | `{subscription}` |
| `stats.unsubscribe` | `subscription` | `true` |

A run has a `state` (`running`, `finished`, `stopped`, `failed` with `error`),
`total` counters (`packets`, `bytes`, `send_errors`, `loops_completed`,
`elapsed_s`, `pps`, `mbps`) and the same counters per stream. After
`stats.subscribe`, the server pushes `stats` notifications on the connection:

```json
{"jsonrpc":"2.0","method":"stats","params":{"subscription":1,"run":{"id":1,"state":"running","total":{"packets":51200,"pps":5000.1,...},"streams":[...]}}}
```

A capture without a `file` that no client has read for a minute stops by
itself (its `error` says so), so a client that went away leaves nothing
running. `capture.get` and `capture.list` need the read role; the other
`capture.*` calls and `file.get` need operator. The audit log records
captures' starts and stops but not each `capture.read`.

A subscription to one run ends with an update marked `"last": true` when the
run ends. TCP and UDP counters (`tcp.stats`, `udp.stats`) carry `app`
for each side that ran an [application protocol](app-protocols.md#counters):
transactions, failures, error answers, protocol errors, `codes`,
`response_time`, and over TLS `tls` (handshakes, failures, resumed sessions,
what was negotiated, handshake times). Error codes are the JSON-RPC ones plus -32001 (log in first),
-32002 (no such profile, run or subscription), -32003 (could not be done,
e.g. a profile that does not parse or an interface that will not open),
-32004 (forbidden: a read-only login changing something, or a path outside
the data directories) and -32005 (a limit: too many `stats` subscriptions,
or too many wrong tokens; try again later).

## Servers that programs start

A program that runs a server of its own, as the GUI does for
[This computer](gui.md#this-computer), can let the system pick the port and
tie the server's life to its own:

```sh
ferotrx serve -l 127.0.0.1:0 --tokens session/tokens.toml \
    --port-file session/port --parent $$
```

`--port-file FILE` writes the address the server listens on to FILE once it
listens (whole, by a rename) and stops the server when FILE is removed;
`--parent PID` stops it when that process ends. Either way its runs stop
first, as with Ctrl-C.

On Windows, `ferotrx service install -- <serve options>` runs the server as
a service from boot; see [Windows](windows.md#the-windows-service).

## Security

**What is at stake.** The control server sends traffic from the machine's
interfaces, often as root (pcap, AF_XDP and DPDK need it), and reads profiles
and pcaps and writes pcap files with the server's privileges. Whoever can
call `run.start` can flood a network the box is attached to; whoever can
call `profile.load` with any path could read files. So the server keeps
everyone out who has not logged in, keeps read-only users from changing
anything, and keeps everyone inside its data directories.

**What it protects against:** someone on the lab or management network who
can reach the port but has no token or certificate (they get `server.info`
and nothing else; the server refuses to listen on such a network without a
login unless you say `--insecure`); someone who can watch or tamper with that
network (TLS, so tokens and traffic no longer go in clear text); a dashboard
or colleague who should only look (read-only role); a client naming
`/etc/shadow` or `../../` (data directories, symbolic links followed);
clients that hog the server (connection, request and upload limits, idle and
login timeouts, a pause and in the end a closed connection after wrong
tokens). Every login, refusal and change is in the audit log.

**What it does not protect against:** an operator, who by design can send
any traffic the profiles allow (within the [traffic limits](#traffic-limits)
the server's owner set) and write pcap files anywhere in the data
directories; anyone who has a token or key file (keep them private: `ferotrx
certs` writes keys readable only by their owner); local users of the box
(listen on 127.0.0.1, the default, when you do not need the network); and
denial of service by a client that is allowed in. The server checks paths
when a profile is loaded, so a file swapped for a symbolic link afterwards is
not caught. There is no rate limit per client and no certificate revocation:
to lock someone out, issue new CAs (or tokens) and restart.

**Logins and roles.** `read` may call `server.info`, `interfaces.list`, the
`*.get`, `*.list` and `*.stats` methods and `stats.subscribe`; `operator` may
also load and unload profiles and start, stop and remove runs. Log in with a
token (`auth`) or a client certificate:

| `ferotrx serve` option | Logs in as |
| --- | --- |
| `--token T` (or `FEROTRX_TOKEN`) | operator |
| `--read-token T` (or `FEROTRX_READ_TOKEN`) | read |
| `--tokens FILE`: `[[token]]` tables with `name`, `role` and `secret` (or `sha256` of it) | the token's role, under its name in the audit log |
| `--client-ca FILE` (needs TLS) | operator, for certificates from that CA |
| `--read-client-ca FILE` (needs TLS) | read, for certificates from that CA |

With client CAs and no tokens, a client without a certificate cannot connect;
with both, it can and logs in with a token. With none of these, every
connection may do everything, which is fine on 127.0.0.1.

**TLS.** `--tls-cert` and `--tls-key` (PEM) turn on TLS (rustls; TLS 1.2 and
1.3). `ferotrx certs DIR --server NAMES --client NAME --read-client NAME`
makes what a lab needs: a CA (`ca.pem`) that signs the server certificate (for
those names plus `localhost`, `127.0.0.1` and `::1`) and
operator client certificates, a second CA (`read-ca.pem`) for read-only
client certificates, and a certificate and key per name; run it again to add
clients, it reuses the CAs. Clients check the server against `--ca` (or
`FEROTRX_CA`), for the host in `--connect` (or `--server-name`); in Python,
`ferotrx.Client(host, ca="ca.pem", cert=..., key=...)` (see
[docs/python-client.md](python-client.md)).
Certificates from your own PKI work as well: any PEM certificate and key.

**Files.** Profiles, the pcaps they name, `base_dir` and pcap outputs must be
inside the `--data-dir` directories (repeatable; default: the directory the
server was started in); relative paths start from the first one. Uploaded
profiles may be at most `--max-upload` (1M); a request at most
`--max-request` (4M). Profiles given with `-p` at start are not checked.
`file.put` writes files of at most `--max-file` bytes (256M; 0 refuses
files) under the first data directory; [fleets](fleet.md) send profiles and
pcaps to the agents with it.

**Starting together.** `run.start`, `tcp.start` and `udp.start` take
`start_at`, Unix seconds by the server's clock (`server.info` tells it).
The run opens its interfaces at once and waits for that time; a time gone
by starts at once, one more than an hour ahead is refused.

**Tokens need TLS beyond loopback.** A server that listens on anything but
127.0.0.1 or ::1 refuses to start with tokens and no `--tls-cert`: a token
sent in clear text can be copied by anyone who can watch the network. Make a
certificate with `ferotrx certs`, or, on an isolated lab network only, give
`--allow-cleartext-token` (the server then warns, and writes
`cleartext_tokens` to the audit log at start). Client certificates alone and
`--insecure` (no login at all) are not affected.

**Limits.** `--max-connections` (64), of which at most 16 may be waiting to
log in (so clients without a token cannot keep everyone else out);
`--idle-timeout` (5m; connections watching stats are never idle); 10 s to
log in; half a second after each wrong token and the connection closed
after five; and per minute at most 20 wrong tokens from one address and 200
from all together, after which logins from there (or from everywhere) are
refused unchecked, with -32005 (`login_throttled` in the audit log), until
the minute has passed. A connection may run `--max-subscriptions` (16)
`stats` subscriptions, the server 256 in all; more answer -32005. A closed
connection ends its subscriptions. `server.info` shows the connections and
subscriptions open.

### Traffic limits

By default an operator may send any rate on any interface for as long as
they like: benchmarking must work out of the box. A server's owner can set
limits that remote operators cannot exceed, whoever they log in as (there is
no role between read and operator for this; the limits cover every
operator). The command line on the box itself (`ferotrx run`, `tcp`, `bench`
and the rest) is not limited.

| `ferotrx serve` option | `[limits]` key | Limit |
| --- | --- | --- |
| `--allow-iface NAME` (repeatable) | `interfaces` | the interfaces runs send on, receivers (`rx`) listen on and captures read |
| `--allow-dst CIDR` (repeatable) | `destinations` | where frames go: built packets, rewrites and variations, replayed pcaps, and the servers TCP and UDP clients connect to |
| `--max-pps RATE` | `max_pps` | packets per second, all runs together (`50kpps`, or a number) |
| `--max-bps RATE` | `max_bps` | bits per second, all runs together (`200mbps`, `1gbps`, or a number); frame bytes without FCS, as `mbps` rates count them |
| `--max-duration TIME` | `max_duration` | how long a run goes (`10m`) |
| `--max-runs N` | `max_runs` | runs that send going at once: traffic, TCP, UDP, benchmarks, Y.1564 tests and scenarios |
| `--max-flows N` | `max_flows` | a TCP or UDP run's connections (transactions) open at once, and new ones per second |
| `--allow-unlimited` | `allow_unlimited` | with a rate limit, still allow top speed, benchmarks and Y.1564 tests |

The same limits can sit in a file, given with `--config FILE`; options on
the command line win over it:

```toml
format = 1

[limits]
interfaces = ["enp0s8", "enp0s9"]
destinations = ["192.168.20.0/24", "2001:db8:20::/64"]
max_pps = "50kpps"
max_bps = "200mbps"
max_duration = "10m"
max_runs = 4
max_flows = 2000
```

**At the start.** `run.start`, `tcp.start`, `udp.start`, `bench.start`,
`y1564.start` and `scenario.start` check what they are asked for and refuse
with `FORBIDDEN` (-32004), a message that names the option, and the limit in
the error's `data` (`{"limit": "max_pps"}`; in Python `RpcError.limit`):

* an interface outside `--allow-iface` (also for `rx.start` and
  `capture.start`);
* a profile whose streams add up to more than `--max-pps` or `--max-bps`
  (`pps` and `mbps` rates; captures replayed at their own timing cannot be
  known beforehand and are held while they run, see below);
* top speed (`rate = "topspeed"`, `--topspeed`), benchmarks (they search for
  the highest rate) and Y.1564 tests (bursts at the line rate) while a rate
  is limited, unless `--allow-unlimited`;
* a stream frame to an address outside `--allow-dst`: the first 4096 frames
  of each stream are built, with rewrites and variations, and looked at; a
  TCP or UDP client connecting outside it (every server address of the
  range);
* a duration longer than `--max-duration`;
* a TCP run with more new connections per second (its `cps` and the
  templates' own), or more open at once, than `--max-flows`; for UDP, its
  transactions. A profile without a limit on open connections gets
  `--max-flows`;
* another run while `--max-runs` go.

**While the traffic flows.** The interfaces of the server's runs send
through one guard:

* all runs together are paced below `--max-pps` and `--max-bps`, so a
  capture replayed at its own timing, a run at top speed (with
  `--allow-unlimited`) or several runs at once cannot go past them; after a
  pause at most 5 ms of the rate goes out at once;
* with `--allow-dst`, every frame is checked: IPv4 and IPv6 (also behind
  VLAN tags) to an allowed address, ARP, and link-scoped addresses
  (255.255.255.255, 224.0.0.0/24, ff01::/16, ff02::/16 for DHCP, IGMP,
  NDP, MLD) go out; anything else does not, including frames that are
  neither IP nor ARP, which cannot be checked. A stream's frame there fails
  the run; a TCP or UDP port drops it (as a firewall would), so a server
  end does not stop because some client outside the range reached it.
  `server.info` counts these frames (`refused_frames`);
* runs without a duration end at `--max-duration`, and anything still going
  5 s after it (benchmarks, a TCP run closing its connections) is stopped
  (`limit_stopped` in the audit log). A scenario may take
  `--max-duration` for each of its checks and attempts; checks without a
  duration get `--max-duration`.

Files written by a run (`"file"` output) and the null output put nothing on
the network: interfaces, destinations and rates do not apply to them, the
duration and run limits do.

`server.info` reports the limits (`limits`, with `refused_frames`), `ferotrx
ctl info` prints them, the GUI shows "limits set by the server's owner"
under the server with the list on hover, and [fleets](fleet.md) check each
agent's limits before they deploy anything.

Finished runs are kept for `*.list` and `*.get` until removed, at most 256
of each kind (runs, TCP, UDP, receivers, captures, benchmarks, Y.1564,
scenarios): starting more forgets the oldest finished ones, so a client
cannot grow the server's memory by never removing runs. This holds with or
without limits.

**Audit log.** JSON lines on standard error, or appended to `--audit-log
FILE`: `connect`, `refused`, `tls_error`, `login` (by token or certificate,
with the certificate's SHA-256), `login_failed`, `denied`, `call` (every
operator method with its parameters, uploaded profiles and `file.put` data by size, and whether
it worked), `disconnect` (with the reason), `login_throttled`,
`cleartext_tokens`, `audit_refused`, `limit_refused` (a start beyond a
[traffic limit](#traffic-limits), with the method and the limit) and
`limit_stopped` (a run stopped at `--max-duration`, with its kind and id).
Tokens are never written.

A write that fails (a full disk) does not stop the server: it says so once
on standard error (and again when writing works), and `server.info` shows
`audit` with `ok`, the number of `failures` and the `last_error`. With
`--audit-required`, operator calls are refused (-32004) while the log cannot
be written; read calls still work, and each refusal tries the log again, so
changes work again as soon as writing does. The server does not rotate the
file: use logrotate with `copytruncate`.

```json
{"by":"certificate","cert_sha256":"f265cc3d…","conn":3,"event":"login","peer":"192.168.56.1:43846","role":"operator","time":"2026-11-03T18:13:04.415Z","user":"alice"}
{"conn":3,"event":"call","id":1,"method":"run.start","ok":true,"params":{"output":{"iface":"enp0s3"},"profile":"lab"},"peer":"192.168.56.1:43846","role":"operator","time":"2026-11-03T18:13:04.416Z","user":"alice"}
```

**Deploying.** Put the control port on a management network or VLAN, not the
network under test. Use TLS with client certificates for people and scripts
that start traffic, a read-only certificate or token for dashboards, and give
each person or system their own so the audit log tells them apart. Keep
profiles and pcaps in a directory of their own and make it the only
`--data-dir`. Under systemd, send standard error (and so the audit log) to the
journal, or give `--audit-log` a file on a disk that is backed up. Leave the
server on 127.0.0.1 (the default) when only local scripts use it.
