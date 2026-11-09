# The Python client

FeroTRX 0.14.0 (M21) ships `ferotrx`, a Python package for the control
server (`ferotrx serve`). It does what `ferotrx ctl` does, from Python:
load profiles, start and stop runs, stateful TCP and UDP runs and receivers,
and follow their counters, with typed results. It lives in
[`python/`](../python) in this repository.

* A blocking client, `ferotrx.Client`, safe to share between threads.
* An asyncio client, `ferotrx.AsyncClient`, with concurrent calls on one
  connection and any number of live subscriptions at once.
* TLS, mutual TLS (client certificates) and tokens, read from the same
  environment variables as `ferotrx ctl`.
* Dataclasses for every result (`RunInfo`, `TcpRunInfo`, …), an exception
  class per error code, `py.typed` for mypy and IDEs.
* Only the standard library; Python 3.10 or newer, on Linux, macOS and Windows.

## Install

```sh
pip install "git+https://github.com/jkobierczynski/FeroTRX#subdirectory=python"
pip install ./python                  # from a checkout
pip install -e './python[dev]'        # to work on it
```

The package version is FeroTRX's: `ferotrx` 0.14.0 belongs with
`ferotrx serve` 0.14.0. It speaks control protocol 2 (`ferotrx.PROTOCOL_VERSION`)
and reads servers that add fields (kept in `extra`) or leave some out
(defaults), so it works across releases of the same protocol.

## Connecting

```python
import ferotrx

c = ferotrx.Client()                          # 127.0.0.1:4510, or $FEROTRX_CTL
c = ferotrx.Client("lab")                     # port 4510
c = ferotrx.Client("192.168.56.10:4600", token="s3cret")
c = ferotrx.Client("[fe80::1%eth0]:4510")
c = ferotrx.Client.from_env()                 # as ferotrx ctl: FEROTRX_CTL, FEROTRX_TOKEN,
                                              # FEROTRX_CA, FEROTRX_CERT, FEROTRX_KEY
```

The client connects when it is made and logs in with `token` if one is given
(a wrong token raises `Unauthorized` there). Use it as a context manager, or
call `close()`; closing the connection does not stop runs on the server.

`timeout` (seconds, default 30, None for ever) bounds the connection and each
wait for an answer. A call that times out raises `TimeoutError`; the blocking
client then closes, because the late answer could be taken for the next one.
`set_timeout()` changes it.

### TLS and client certificates

Give `ca` to check the server against a CA, and `cert` and `key` to log in
with a client certificate (mutual TLS); `ferotrx certs` makes all three for
a lab:

```sh
ferotrx certs pki --server 192.168.56.10 --client alice --read-client bob
ferotrx serve -l 0.0.0.0:4510 --tls-cert pki/server.pem --tls-key pki/server-key.pem \
    --client-ca pki/ca.pem --read-client-ca pki/read-ca.pem
```

```python
c = ferotrx.Client("192.168.56.10", ca="pki/ca.pem",
                   cert="pki/alice.pem", key="pki/alice-key.pem")
c.info().role                 # Role.OPERATOR; bob's certificate gives Role.READ
c.info().user                 # "alice"
```

The server's certificate is checked for the host you connect to, or for
`server_name`. `tls=True` uses the system's CAs (a certificate from your own
PKI). For full control pass an `ssl.SSLContext` as `tls`;
`ferotrx.tls_context(ca, cert, key)` makes the one the client would. A plain
connection to a TLS server raises `ProtocolError` ("the server speaks TLS")
or `ConnectionClosed`.

### Roles

A `read` login (`--read-token`, a certificate from `--read-client-ca`) sees
everything and changes nothing: `info`, `interfaces`, `profile`, `profiles`,
`stats`, `runs`, the `tcp_`/`udp_`/`rx_` equivalents, `subscribe`, `watch`.
Everything else needs `operator` and raises `Forbidden` otherwise. Paths
outside the server's `--data-dir` raise `Forbidden` too, and so do starts
beyond the server's [traffic limits](remote-control.md#traffic-limits): then
`e.limit` names the limit (`"max_pps"`, `"interfaces"`, ...), and
`client.info().limits` lists them beforehand. `client.reload()` (operator) makes the server read
its tokens, certificates and revocation lists again ([locking someone
out](remote-control.md#locking-someone-out)); `client.info().certificate_expires`
says when its TLS certificate runs out.

### Sharing a server: ports and sessions

Several users share a server by reserving its ports ([several
users](remote-control.md#several-users), servers from 0.49.0):

```python
with ferotrx.Client("lab", token=os.environ["MY_TOKEN"]) as c:
    c.acquire(["enp0s8", "enp0s9"], note="soak test")   # all or none
    try:
        run = c.start("lab", iface="enp0s8")
    except ferotrx.Forbidden as e:
        print(e.reason, e.port, e.owner)    # e.g. reserved enp0s8 alice
    print(c.session())                      # you: ports and running runs
    print(c.ports(), c.sessions())          # everybody
    c.release()                             # all of yours
```

A start on a port another user reserved, or that another user's run sends
on, raises `Forbidden` with `.reason` `"reserved"` or `"in_use"`
(`"not_acquired"` on a `--require-acquire` server); stopping someone else's
run raises it with `"not_owner"`. An admin login may `acquire(port,
force=True)`, which stops the other user's runs on it, and
`release(port, force=True)`. On a server without logins, `Client(...,
user="alice")` (or `FEROTRX_USER` with `Client.from_env`) names your session.

## Stateless runs

```python
p = c.load_profile("/srv/profiles/voip.toml")          # a file on the server
p = c.load_profile("my-test.toml", upload=True)         # send this machine's file
p = c.load_profile(name="ping", toml='''
[[stream]]
name = "ping"
packet = "eth/ipv4(dst=192.168.20.50)/icmp"
rate = "100pps"
''')
[s.name for s in p.streams]

run = c.start("voip", iface="enp0s3", duration="60s")
run = c.start("voip", iface="enp0s3", backend="af_xdp", xdp_mode="copy", rate="10kpps")
run = c.start("voip", file="out.pcap", limit=1000)      # a pcap file on the server
run = c.start("voip", null=True)                        # discard: measure the pipeline

c.stats(run.id).total.pps
c.stop(run.id)                    # waits for the end; wait=False answers at once
c.wait(run.id, timeout=120)       # poll until it ends
c.runs(); c.remove(run.id)        # runs stay listed until removed
```

`start` takes exactly one of `iface`, `file` and `null=True`; with `iface`,
`backend` (`pcap`, `af_xdp`, `dpdk`; see `c.info().backends`), `queue`,
`xdp_mode`, `batch`, `dpdk_args`, `workers` (engine threads, see
[multi-core.md](multi-core.md)) and `cpus` (`"2-5"`: pin worker k to the
k-th CPU) choose how to send, and the profile's
`[output]` fills in what is left out. `rate`, `limit` and `duration` stop or
pace the run, `ignore_errors` counts failed sends instead of failing.
`line_rate` is what `"50%"` rates are a share of, and `ip`, `gateway`, `mac`,
`vlan` and `answer` give the port addresses of its own (see
[the port's own addresses](replay.md#the-ports-own-addresses-l3-mode));
`run.link` says what was found.

A running run can be held and its rate changed in place, with no catch-up
burst afterwards:

```python
run = c.start("voip", iface="enp0s3", ip="10.0.0.2/24", gateway="10.0.0.1")
c.pause(run.id)                     # the whole run; c.pause(run.id, "bulk") one stream
c.resume(run.id)
c.update(run.id, multiplier=2.0)    # every stream twice as fast
c.update(run.id, streams={"voice": "200pps", "bulk": 0.5})  # a rate, or a multiplier
c.stats(run.id).stream("bulk").multiplier
```

### Live counters

```python
for update in c.watch(run.id, interval_ms=500):
    t = update.run.total
    print(t.elapsed_s, t.packets, t.pps, t.mbps)
print(update.run.state)          # the last update has update.last set
```

`watch` subscribes, yields updates until the run ends and unsubscribes if you
leave the loop early. Underneath are `subscribe(id=None, interval_ms=None)`
(None: every running run), `next_stats(subscription, timeout)` and
`unsubscribe()`. Updates that arrive during other calls are kept, so calls
can be made inside the loop.

### Loss and latency

```python
run = c.start("voip", iface="enp0s3", rx="enp0s8", latency=True, duration="30s")
done = c.wait(run.id)
for s in done.streams:
    if s.latency:
        print(s.name, s.latency.loss_pct, s.latency.latency.p99_us)
if done.loss:                        # where the frames were lost
    print(done.loss.generator, done.loss.network, done.loss.receiver)
print(done.drops.capture_dropped, done.drops.nic_rx_missed)

rx = c.rx_start("enp0s8")            # a receiver alone, for another FeroTRX's traffic
...
for flow in c.rx_stop(rx.id).flows:
    print(flow.flow, flow.rx, flow.lost, flow.latency.avg_us)
```

## Stateful TCP and UDP

```python
tcp = c.tcp_start("/srv/profiles/lab-tcp.toml", connections=500, cps=100)
tcp = c.tcp_start("lab-tcp.toml", upload=True, backend="af_xdp")
tcp = c.tcp_start(toml=profile_text, iface="enp0s3")
done = c.tcp_wait(tcp.id, timeout=300)
done.client.completed, done.client.retransmits, done.cps
done.template("web").client.reset

udp = c.udp_start("/srv/profiles/lab-dns.toml", transactions=1000, rate=200)
done = c.udp_wait(udp.id)
done.client.answered, done.client.timed_out, done.client.response_time.p99_us
```

`tcp_start` takes `cps`, `connections` (0: until stopped), `concurrency` and
`duration`; `udp_start` takes `rate` (transactions per second),
`transactions`, `concurrency` and `duration`; both take `iface` for hosts
whose table names none, `base_dir` for relative pcap paths in uploaded or
`toml` profiles, and the backend settings. Then `tcp_stats`, `tcp_stop`,
`tcp_runs`, `tcp_remove`, `tcp_wait`, and the same for `udp_` and `rx_`.

With an [application protocol](app-protocols.md) (HTTP, DNS, NTP), each
side also has `app`, an `AppCounters` (`transactions`, `failed`, `errors`,
`protocol_errors`, `codes` by status or response code, `response_time`, and
over TLS `tls`, a `HandshakeCounters` with `handshakes`, `failed`,
`unexpected`, `resumed`, `negotiated` and `time`), or `None` when it counted
nothing:

```python
web = done.template("web").client.app
assert web.failed == 0 and web.codes.get("404", 0) > 0
```

## Y.1564

```python
run = c.y1564_start("y1564.toml", upload=True, iface="enp0s3", rx="enp0s8",
                    step_duration="10s", performance_duration="1m")
done = c.y1564_wait(run.id)
done.passed                       # every step passed
for step in done.steps:
    for s in step["services"]:
        print(step["name"], s["service"], s["flr_pct"], s["passed"])
```

`y1564_start` also takes `toml`, `tests`, `services`, `line_rate` and the
backend settings; then `y1564_get`, `y1564_stop`, `y1564_runs` and
`y1564_remove`. The report is in `done.report`, as in
`ferotrx y1564 --report` ([Y.1564](y1564.md)).

## Files and a shared start

```python
import time
c.upload_file("lab/http.pcap", "examples/http.pcap")   # skipped if the server has it
c.file_stat("lab/http.pcap").sha256

servers = [ferotrx.Client(h, token=tok) for h in ("10.99.0.11", "10.99.0.12")]
offsets = [s.info().time - time.time() for s in servers]
at = time.time() + 2
for s, off in zip(servers, offsets):
    s.tcp_start("lab/web-clients.toml", start_at=at + off)
```

`upload_file` sends in pieces of 1 MiB with `file_put`, to the server's
first data directory. `start`, `tcp_start` and `udp_start` take
`start_at`, Unix seconds by the server's clock; the run's `started_at` says
when it began. [Fleets](fleet.md) do all this from one plan.

## Captures and files

```python
cap = c.capture_start("enp0s8", filter="udp port 53", duration="30s")
r = c.capture_read(cap.id, 0, wait=1.0)        # CaptureRead: frames, next, missed, more
for f in r.frames:
    print(f.n, f.ts_ns, len(f.bytes))

cap = c.capture_start("enp0s8", filter="tcp port 80")
with open("web.pcap", "wb") as out:            # or a pipe into Wireshark
    c.capture_pcap(cap.id, out)                # until the capture ends
c.capture_remove(cap.id)

c.capture_start("enp0s8", file="caps/night.pcap", rotate="1G", files=8, stream=False)
data = c.download("caps/night-00001.pcap")     # file_get in pieces, checked by SHA-256
```

`capture_start` takes the parameters of `capture.start`
([remote control](remote-control.md#the-protocol)); `captures`,
`capture_get`, `capture_stop` and `capture_remove` work as for runs. The
asyncio client has the same methods. More in [capturing](capture.md).

## Errors

| Exception | Code | When |
| --- | --- | --- |
| `Unauthorized` | -32001 | not logged in, or a wrong token |
| `NotFound` | -32002 | no profile, run or subscription by that name or id |
| `Failed` | -32003 | a profile that does not parse, an interface that cannot be opened |
| `Forbidden` | -32004 | the role may not do that, a path outside the data directories, or a start beyond a traffic limit (`limit`) |
| `InvalidParams` | -32602 | missing, unknown or mistyped parameters |
| `MethodNotFound` | -32601 | an older server, or a typo in `call()` |
| `ConnectionClosed` | | the server went away, or the client was closed |
| `ProtocolError` | | the server sent something that is not JSON-RPC |

All of them are `ferotrx.FerotrxError`s, and the server's errors are
`ferotrx.RpcError`s with `code`, `message`, `data` and `method`. Bad
arguments that the client can see itself (both `iface` and `null`, a `toml`
profile without a name) raise `ValueError` before anything is sent.

## The asyncio client

`AsyncClient` has the same methods as coroutines. Calls on one connection may
run at once (answers are matched by id), and several `watch` loops can run on
one connection:

```python
import asyncio
from ferotrx import AsyncClient

async def main():
    async with await AsyncClient.connect("lab", token="s3cret") as c:
        await c.load_profile("voip.toml", upload=True)
        a = await c.start("voip", iface="enp0s3", duration="10s")
        tcp = await c.tcp_start("/srv/profiles/lab-tcp.toml")

        async def follow(run_id):
            async for u in c.watch(run_id):
                print(run_id, u.run.total.pps)

        await asyncio.gather(follow(a.id), c.tcp_wait(tcp.id))

asyncio.run(main())
```

`AsyncClient.from_env()` and `ferotrx.aio.connect()` work as for the blocking
client. A call that times out raises `TimeoutError` and leaves the connection
open; its answer is dropped when it comes.

## Raw calls and records

`c.call(method, params)` sends any method and returns its JSON result, for
methods newer than the package. Every record has `from_dict()` and
`to_dict()`, and `extra` holds the members it has no field for. States and
roles are `RunState` and `Role` enums (`str` subclasses, so they compare
equal to `"running"` or `"read"`); a value the package does not know stays a
plain string.

## Examples

* [`python/examples/replay.py`](../python/examples/replay.py): upload a
  profile, run it, print live counters (TLS and tokens from the command line).
* [`python/examples/tcp_sessions.py`](../python/examples/tcp_sessions.py):
  a TCP run as a pass/fail check, with per-template counters.
* [`python/examples/async_watch.py`](../python/examples/async_watch.py):
  follow several servers at once with the asyncio client.
* [`python/examples/reserve_ports.py`](../python/examples/reserve_ports.py):
  reserve a port on a shared server, run a TCP profile on it, give it back.

## Tests

`python/tests` starts real `ferotrx serve` processes (the workspace's
`target/debug/ferotrx`, or `FEROTRX_BIN`) with tokens, roles, TLS and client
certificates from `ferotrx certs`, and checks every method family against
them, blocking and asyncio. `tests/test_lab.py` sends real traffic: TCP
sessions, DNS transactions and a stream with a receiver across a veth pair,
through a server running as root (`FEROTRX_TEST_LAB`, `FEROTRX_TEST_IFACES`).
CI runs the package's tests, mypy (strict) and ruff on Linux, macOS and
Windows, and the lab tests on Linux.
