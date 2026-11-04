# Scenarios and regression tests

A scenario answers the question "did this change to the network break
anything?". It is a TOML file with a list of checks. Each check is a run
FeroTRX already knows how to make (stateful TCP, stateful UDP, or stateless
streams with a receiver) and what should come of it: the sessions complete,
or they are blocked, plus conditions on what was measured, such as
`loss_pct < 1%` or `latency_p99 < 20ms`.

`ferotrx scenario run` runs the checks one after the other, gives each a
verdict (pass, fail, error), exits with 1 when any check failed, and writes
the results as JSON and JUnit XML. Runs can be kept in a history directory
and compared: before and after a firewall change, two devices, IPv4 against
IPv6.

```sh
ferotrx scenario show examples/scenario-nat.toml        # what it will do; sends nothing
sudo ferotrx scenario run examples/scenario-nat.toml \
     --history runs/ --report run.json --junit run.xml
# ... change the router ...
sudo ferotrx scenario run examples/scenario-nat.toml --history runs/ --baseline last
ferotrx scenario compare --history runs/                 # the last two runs
ferotrx scenario compare before.json after.json          # any two reports
ferotrx scenario history runs/                           # every kept run
ferotrx scenario metrics                                 # what conditions can test
```

## An example run

With [`examples/scenario-nat.toml`](../examples/scenario-nat.toml) through the namespace
router of `scripts/scenario-netns.sh`:

```text
PASS   web through NAT (tcp, 1.1 s): 50 connections: 50 established, 50 completed; 0 retransmits; 51.0 cps
PASS   port 8080 blocked (tcp, 3.1 s) expect blocked: 3 connections: 0 established, 0 completed, 3 still open; 8 retransmits; 0.0 cps
PASS   DNS through NAT (udp, 1.1 s): 100 transactions: 100 answered, 25 with error codes; answers in 0.35ms on average; 101.0 per second
PASS   NTP blocked (udp, 3.1 s) expect blocked: 3 transactions: 0 answered, 2 timed out, 3 retries; 0.0 per second
PASS   voice stream (traffic, 3.6 s): 3001 packets sent at 1.841 Mbit/s, 3001 received, 0 lost (0.00%); latency avg 0.02ms, p99 0.08ms
PASSED: 5 passed, 0 failed, 0 errors, 0 skipped in 12.0 s
```

and after the router starts resetting TCP to port 80:

```text
FAIL   web through NAT (tcp, 11.1 s, 2 attempts): 50 connections: 0 established, 0 completed, 50 timed out; 100 retransmits; 0.0 cps
        not met: completed_pct == 100 (was 0%)
        not met: cps > 10 (was 0/s)
        not met: timed_out == 0 (was 50)
...
REGRESSED  web through NAT (tcp): pass -> fail
same       port 8080 blocked (tcp): pass -> pass
...
1 regressed, 0 fixed, 0 worse, 0 added, 0 removed, 4 the same (metrics moved by more than 20% shown)
error: 1 of 5 checks failed
```

`sudo scripts/scenario-netns.sh` runs exactly this: it breaks the router
and checks that the second run catches it. CI runs it and keeps the reports.

## The file

```toml
name = "nat-router"                 # default: the file name
description = "web and DNS pass, 8080 and NTP are blocked"

# Defaults for every check (each check may set its own):
iface = "enp0s3"     # interface for hosts that name none; traffic: sent on
rx = "enp0s8"        # traffic checks: received on
rx_wait = "500ms"    # traffic checks: keep receiving this long after the last packet
duration = "30s"     # stop every run after this long
attempts = 2         # run a failing check again before calling it failed

[vars]               # ${NAME} anywhere in the file and in the profiles it names
server = "192.168.20.80"
client_iface = "c0"

[[check]]
name = "web through NAT"            # unique: reports and comparisons go by name
description = "every HTTP connection completes"
tcp = "lab-tcp.toml"                # a profile file, relative to this file ...
require = ["cps > 10", "retransmits < 100"]

[[check]]
name = "port 8080 blocked"
expect = "blocked"
duration = "3s"
[check.tcp]                         # ... or the profile right here
port = 8080
connections = 3
[[check.tcp.message]]
from = "client"
text = "GET / HTTP/1.0\r\n\r\n"
[check.tcp.client]
iface = "${client_iface}"
ip = "192.168.10.100/24"
gateway = "192.168.10.1"
[check.tcp.server]
ip = "${server}/24"
```

A check has exactly one of:

| Key | Profile | What runs |
| --- | --- | --- |
| `tcp` | a TCP profile (`ferotrx tcp -p`) | stateful TCP connections, as `ferotrx tcp` |
| `udp` | a UDP profile (`ferotrx udp -p`) | stateful UDP transactions, as `ferotrx udp` |
| `traffic` | a traffic profile (`ferotrx run`) | the streams, with a receiver on `rx`, as `ferotrx run --rx` |

The value is a path to the profile or the profile's tables under
`[check.tcp]`, `[check.udp]` or `[check.traffic]` (nested tables are written
`[check.tcp.client]`, `[[check.tcp.message]]`, `[[check.traffic.stream]]`).
Everything the profile files allow works here. Pcap paths are relative to
the file they are written in.

### The lab router a scenario needs

A scenario written for the [lab router](lab-scripts.md#a-standing-lab-router)
says how the router is built in a `[lab]` table, with the options of
`ferotrx lab up`:

```toml
[lab]
block_tcp = [8080]     # the firewall resets TCP to 8080
block_udp = [123]      # and drops NTP
# ipv6 = false, nat = false, loss = 0.03, delay = "5ms", dhcp = true, queues = 4
```

A control server started with `--lab` builds that router before the run
(`scenario.start`, the GUI's Scenario tab), unless one built the same way
is running; `"lab": false` (GUI: untick "Build the lab it names") runs on the
lab as it is, for example one broken on purpose. `ferotrx scenario run --lab`
builds it for the run and removes it after; without `--lab` the checks run
on what is there.

Scenarios for the lab router, each naming the router it needs:

| File | Router | Checks |
| --- | --- | --- |
| [`lab-scenario.toml`](../examples/lab-scenario.toml) | resets TCP 8080, drops UDP 123 | `scenario-nat.toml` in the lab: web and DNS through the NAT, 8080 and NTP blocked, a voice stream, no route to an unknown network |
| [`lab-scenario-apps.toml`](../examples/lab-scenario-apps.toml) | resets TCP 8080 | HTTP (keep-alive, uploads, chunked answers) and DNS over TCP, HTTPS with verified certificates, the DNS zone of `lab-dns.toml`, HTTP on 8080 refused |
| [`lab-scenario-impaired.toml`](../examples/lab-scenario-impaired.toml) | 2% loss, 20 ms delay | TCP and DNS recover by retransmitting; the stream shows the loss and the delay |
| [`lab-scenario-ipv6.toml`](../examples/lab-scenario-ipv6.toml) | IPv6, routed without NAT | web, DNS and a stream over IPv6 |

While a scenario runs on a control server, each check is also a TCP, UDP
or stream run of the server (`tcp.list`, `udp.list`, `run.list`, named after
the check), so its counters show in the GUI's statistics and charts as it
goes.

Other keys of a check: `name`, `description`, `expect`, `require`, `iface`,
`rx`, `rx_wait`, `duration`, `attempts`. Unknown keys are an error, so a typo
does not silently turn into a check that tests nothing.

### Variables

`${NAME}` is replaced by the variable's value everywhere in the scenario
and in the profile files its checks name, before they are read. Values
come from `[vars]` and from `--set NAME=VALUE`, which wins. An unknown
variable is an error. This is how one scenario runs against two devices or
two address families:

```sh
sudo ferotrx scenario run lab.toml --set server=192.168.20.80 --history runs/
sudo ferotrx scenario run lab.toml --set server=fd00:20::80 --set prefix=64 --history runs/
ferotrx scenario compare --history runs/
```

`--iface` sets the interface of every check that has none.

## Expected outcomes

`expect` stands for a few conditions; `require` adds the check's own.

| `expect` | TCP | UDP | Traffic |
| --- | --- | --- | --- |
| `complete` (default) | `connections > 0`, `completed_pct == 100`, `mismatched == 0` | `transactions > 0`, `answered_pct == 100`, `mismatched == 0` | `tx_packets > 0`, `rx_packets > 0` |
| `blocked` | `connections > 0`, `established == 0` | `transactions > 0`, `answered == 0` | `tx_packets > 0`, `rx_packets == 0` |
| `any` | only `require` | only `require` | only `require` |

`complete` means every session played as captured, byte for byte (unless the
profile turns `verify` off). A blocked check should have a `duration`: the
client keeps trying (SYN retransmissions, UDP retries) until it gives up or
the run is stopped. A check needs a client: a profile that only runs a
server makes no connections and fails `connections > 0`.

### Conditions

A condition is `METRIC OP VALUE`, with `<`, `<=`, `>`, `>=`, `==` (or `=`)
and `!=`. Values may carry a unit that fits the metric:

| Metric unit | Written as |
| --- | --- |
| percent | `1%` or `1` |
| time (milliseconds) | `5ms`, `500us`, `0.2s`, or a plain number of ms |
| throughput (Mbit/s) | `20Mbit/s`, `500kbit/s`, `1Gbit/s`, `Mbps`, or a plain number of Mbit/s |
| rate | `100/s`, `100pps`, `100cps`, `100tps`, or a plain number |
| count | a plain number |

A condition on a metric the run did not measure (latency when nothing
arrived) fails. A misspelt metric is an error that lists the right names.

### Metrics

`ferotrx scenario metrics` prints this list.

**TCP** (the client side; `server_` for the server's): `connections`,
`established`, `established_pct`, `completed`, `completed_pct`, `failed`
(reset or timed out), `failed_pct`, `reset`, `timed_out`, `mismatched`
(other bytes than the capture), `open` (still open when the run ended),
`retransmits`, `timeouts`, `cps` (completed per second),
`server_connections`, `server_completed`, `server_failed`,
`server_mismatched`; with an [application protocol](app-protocols.md),
also `app_transactions`, `app_failed`, `app_failed_pct`, `app_errors`
(HTTP 4xx/5xx, DNS error codes), `protocol_errors` and `response_min`,
`response_avg`, `response_p99`, `response_max` (ms, from a request to its
whole answer); over TLS `tls_handshakes`, `tls_failed`, `tls_unexpected`
(another outcome than the profile's `expect`), `tls_resumed` and
`handshake_min`, `handshake_avg`, `handshake_p99`, `handshake_max` (ms).

**UDP**: `transactions`, `answered`, `answered_pct`, `timed_out`,
`timed_out_pct`, `mismatched` (another answer than expected), `unmatched`
(datagrams that matched nothing), `errors` (answers with an error code,
expected ones included; also counted in `answered`), `retries`,
`response_min`, `response_avg`, `response_p99`, `response_max` (ms, from
the first request to the answer), `tps`, `server_answered`.

**Traffic**: `tx_packets`, `tx_mbps`, `tx_pps`, `send_errors`, `rx_packets`
(with a signature, duplicates not counted), `rx_mbps` (every frame the
receiver saw, over the sending time), `lost`, `loss_pct`, `duplicates`,
`out_of_order`, `out_of_order_pct`, `latency_min`, `latency_avg` (over all
streams), `latency_p50`, `latency_p99`, `latency_max`, `jitter` (ms; the
percentiles, maximum and jitter are of the worst stream). Every stream
carries a latency signature unless the profile marks some with `latency`;
see [loss-latency.md](loss-latency.md) for what the signature does to the
packets. A traffic check needs a `duration` when a stream loops for ever.

## Jittery machines

A lab VM stalls now and then: a few hundred milliseconds of latency, a
burst of loss. Three things keep a scenario from failing on that rather than
on the network:

* `attempts = 2` (or more) runs a failing check again; it passes if any
  attempt passes. The report says how many attempts it took. An error (the
  run could not be made) is not retried.
* Conditions on averages (`latency_avg`) and generous percentiles are steadier
  than on maxima.
* Stateful checks recover by themselves: TCP retransmits and UDP clients ask
  again, so `completed_pct == 100` holds through short stalls. Lower the
  profile's `syn_retries` or `retries` only as far as a blocked path must
  fail fast.

## Verdicts and reports

Each check ends as:

* **pass**: every condition held (in some attempt);
* **fail**: the run went, and a condition did not hold;
* **error**: the run could not be made (no such interface, a pcap that
  cannot be read, no permission);
* **skipped**: left out with `--check NAME`, or after Ctrl-C.

`ferotrx scenario run` prints a line per check as it ends, with what was not
met, and exits with 1 when a check failed or had an error. `--check NAME`
(repeatable) runs only those checks. Ctrl-C ends the running check and
skips the rest; the reports are still written.

`--report FILE` writes JSON (`"format": "ferotrx-scenario-1"`): the scenario,
the FeroTRX version, the start time (UTC), the variables, and per check the
verdict, the attempts, a summary line, each condition with the value
measured, and every metric. `--junit FILE` writes JUnit XML that CI systems
show as test results: one test suite for the scenario, one test case per
check, failed conditions as the failure message and the metrics as the
test's output.

## History and comparing runs

`--history DIR` keeps every run as `DIR/<scenario>/<start time>.json`.
`ferotrx scenario history DIR` lists them with their totals and failed
checks.

`ferotrx scenario compare BEFORE.json AFTER.json` (or `--history DIR` for
the last two runs) matches checks by name and prints each one's change:

* **REGRESSED**: passed before, fails or has an error now. Its unmet
  conditions are shown.
* **fixed**: failed before, passes now.
* **same**, **added**, **removed**.

Under unchanged checks, metrics that moved by more than `--tolerance`
(20% by default) are listed, marked better or worse. Small moves of small
numbers (one retransmit more, a millisecond of latency, half a percent) are
left out as noise. `--strict` also counts a passing check whose metrics moved
for the worse as a regression (**WORSE**). The command exits with 1 when
anything regressed; `--json FILE` writes the comparison.

`scenario run --baseline FILE` (or `--baseline last` with `--history`)
compares right after the run and fails when a check regressed, which is the
one command a CI job or a change window needs.

## In CI

```yaml
- name: Regression scenario
  run: sudo ferotrx scenario run lab/scenario.toml --junit scenario.xml --report scenario.json
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: scenario
    path: scenario.*
```

`scripts/scenario-netns.sh` is the worked example, and FeroTRX's own CI runs
it: it builds a NAT router in a network namespace (routing, masquerading,
a firewall that drops TCP 8080 and UDP 123), runs
[`examples/scenario-nat.toml`](../examples/scenario-nat.toml), which must
pass, then makes the router reset TCP to port 80 and runs it again with
`--baseline last`, which must fail with exactly "web through NAT" regressed.

## On a control server, and from the GUI

`ferotrx serve` runs scenarios too (`scenario.check`, `scenario.start`,
`scenario.get`, `scenario.stop`; see [remote control](remote-control.md#the-protocol)).
The scenario is a file on the server or its text, with `base_dir` for the
profile files it names; every file is checked against the server's data
directories, as for `tcp.start`. `scenario.get` shows each check as it
goes, and the report, the same as `--report` writes, once the run has ended.

```sh
ferotrx ctl call scenario.start '{"path": "examples/lab-scenario.toml"}'
ferotrx ctl call scenario.get '{"id": 1}' --json | jq '.checks[] | {name, state}'
```

The GUI's Scenario tab is built on this: edit or open a scenario on your
own computer, check it there (the profiles too), run it on the server and
read the verdict, conditions and counters of each check (see
[the GUI](gui.md#scenarios)). [`examples/lab-scenario.toml`](../examples/lab-scenario.toml)
holds the checks of `scenario-nat.toml` for the lab router, which it names
in `[lab]`: the server builds that router, firewall rules and all, first.

## From a program

The scenario code is in `ferotrx_core::scenario` (file format, conditions,
reports, comparisons) and does no I/O; `ferotrx_ctl::LabRunner` runs checks
on interfaces with the same functions as `ferotrx tcp`, `ferotrx udp` and
`ferotrx run`. Any other `CheckRunner` works too, for example one over
in-memory ports in tests (see `crates/ferotrx-ctl/tests/scenario.rs`).

```rust
use ferotrx_core::scenario::{run_scenario, RunOptions, Scenario};

let scenario = Scenario::from_path("lab.toml", &[("server".into(), "10.0.0.2".into())])?;
let report = run_scenario(&scenario, &mut ferotrx_ctl::LabRunner::new(), RunOptions::default());
std::fs::write("lab.xml", report.junit())?;
assert!(report.passed(), "{}", report.text());
```

## Limits

* Checks run one after the other, not at the same time, and on one
  machine: no agents yet.
* Latency needs the sender and the receiver on the same machine (or clocks
  in step), as for `--rx`.
* A comparison goes by check names; renaming a check shows it as removed and
  added.
