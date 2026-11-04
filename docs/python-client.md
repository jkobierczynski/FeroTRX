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
outside the server's `--data-dir` raise `Forbidden` too.

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
`xdp_mode`, `batch`, `dpdk_args` and `workers` (engine threads, see
[multi-core.md](multi-core.md)) choose how to send, and the profile's
`[output]` fills in what is left out. `rate`, `limit` and `duration` stop or
pace the run, `ignore_errors` counts failed sends instead of failing.

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

## Errors

| Exception | Code | When |
| --- | --- | --- |
| `Unauthorized` | -32001 | not logged in, or a wrong token |
| `NotFound` | -32002 | no profile, run or subscription by that name or id |
| `Failed` | -32003 | a profile that does not parse, an interface that cannot be opened |
| `Forbidden` | -32004 | the role may not do that, or a path outside the data directories |
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

## Tests

`python/tests` starts real `ferotrx serve` processes (the workspace's
`target/debug/ferotrx`, or `FEROTRX_BIN`) with tokens, roles, TLS and client
certificates from `ferotrx certs`, and checks every method family against
them, blocking and asyncio. `tests/test_lab.py` sends real traffic: TCP
sessions, DNS transactions and a stream with a receiver across a veth pair,
through a server running as root (`FEROTRX_TEST_LAB`, `FEROTRX_TEST_IFACES`).
CI runs the package's tests, mypy (strict) and ruff on Linux, macOS and
Windows, and the lab tests on Linux.
