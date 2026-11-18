# Fleets: runs on several agents at once

One machine runs out of ports, cores or places in the network long before a
lab does. A fleet spreads a test over several machines. Each one runs
`ferotrx serve`, and each `ferotrx serve` is an agent. One plan file says
what each agent runs. `ferotrx fleet run` then does four things:

* checks that each agent can run its part (kinds of runs, interfaces,
  backends, cores, limits);
* sends every profile, and the pcaps and other files it names, to its
  agents;
* starts every run at one instant;
* adds up the agents' counters while the runs go, and reads each agent's
  health (CPU, memory, clock);
* rides out a dropped control connection, and reports an agent that is
  gone for good with what it had running;
* judges the plan's conditions on each part and on the sums.

The controller calls the agents in parallel, one thread per agent, so a
slow or dead agent does not hold up the others.

```sh
# on each agent: TLS (tokens are refused in clear text beyond loopback),
# with a certificate from `ferotrx certs DIR --server lab-east` (see
# remote-control.md for client certificates)
ferotrx serve --listen 0.0.0.0:4510 --token "$FEROTRX_TOKEN" \
    --tls-cert server.pem --tls-key server-key.pem --data-dir /srv/ferotrx

# on the controller
FEROTRX_TOKEN=... ferotrx fleet check examples/fleet/fleet.toml
FEROTRX_TOKEN=... ferotrx fleet run examples/fleet/fleet.toml --report fleet.json
```

`fleet run` writes `fleet.json` and `fleet.txt`. It prints the sums once
per `interval` and exits with an error when a run or a condition fails, so
CI can act on it.

## The plan

```toml
format = 1
name = "web-lab"
start_delay = "2s"        # from the start calls to the shared start
interval = "1s"           # sums this often
duration = "60s"          # every run, unless it has its own
reconnect = "10s"         # how long to try again an agent whose connection broke
on_agent_loss = "continue"  # or "stop": stop every run once an agent is lost
telemetry = true          # read each agent's CPU, memory and clock each interval
# deploy_dir = "fleet/web-lab"   # on the agents, in their data directory

[vars]                    # ${NAME} here and in the profiles; --set NAME=VALUE
server_ip = "10.98.0.80"

[[agent]]
name = "east"
address = "10.99.0.11:4510"
token_env = "FEROTRX_TOKEN"      # or token = "..."; with TLS (below) beyond loopback
ca = "lab-ca.pem"                # the CA of the agent's certificate
iface = "enp0s8"                 # for runs that name none
vars = { client_ip = "10.98.0.100" }   # this agent's ${client_ip}

[[agent]]
name = "srv"
address = "lab-srv.example:4510"
ca = "lab-ca.pem"                # TLS: the CA of the agent's certificate,
cert = "ctl.pem"                 # and a client certificate to log in with
key = "ctl.key"
iface = "enp0s8"

[[run]]
name = "web server"
agent = "srv"
tcp = "web-server.toml"          # or udp = ..., traffic = ...; a file or a table

[[run]]
name = "web clients"
agents = ["east", "west"]        # the same profile on each
tcp = "web-clients.toml"
delay = "500ms"                  # after the shared start
connections = 50                 # as tcp.start takes them
require = ["cps > 40"]           # on the sum over its agents
require_each = ["completed_pct == 100"]   # on each agent's part

[[run]]
name = "probe"
agent = "east"
rx_agent = "srv"                 # receive on another agent
rx = "enp0s8"
rate = "500pps"
limit = 2500
[run.traffic]
[[run.traffic.stream]]
packet = "eth(dst=02:00:00:00:99:02)/ipv4(src=10.98.0.99,dst=10.98.0.98)/udp"
loops = 0

[require]                        # on the sums over every run of a kind
tcp = ["failed == 0"]
traffic = ["loss_pct < 0.1"]
```

A run is a profile of one kind on one or more agents:

| Key | Kind | Ends | Since |
|---|---|---|---|
| `tcp` | [stateful TCP](tcp-engine.md) | at its `duration`, or when its work is done | 0.31.0 |
| `udp` | [stateful UDP](udp-engine.md) | likewise | 0.31.0 |
| `traffic` | streams, as `ferotrx run` | likewise | 0.31.0 |
| `hosts` | [emulated hosts](host-emulation.md) | at its `duration`; with `until_ready`, once every host is ready | 0.51.0 |
| `scenario` | a [scenario](scenarios.md), its checks one after the other on the agent | when its checks are done | 0.51.0 |
| `bench` | an [RFC 2544 benchmark](benchmarking.md) | when its trials are done | 0.51.0 |
| `y1564` | a [Y.1564 test](y1564.md) | when its steps are done | 0.51.0 |

The last column is the agent version a kind needs; `fleet check` and
`fleet run` refuse a plan that gives an agent a kind it does not know.
Scenarios, benchmarks and Y.1564 tests run to their own end, so a plan's
`duration` does not apply to them and a run of theirs refuses one.

 Each agent
gets its own copy. In that copy, `${NAME}` comes from the plan's `[vars]`,
then from the agent's `vars`; `${agent}` is the agent's name. So two client
agents can play the same profile from different addresses. Each run can
also carry the settings its start call takes:

| Key | Runs | What |
|---|---|---|
| `iface` | all | the interface (default: the agent's `iface`); TCP and UDP hosts may name their own |
| `backend`, `xdp_mode`, `queue`, `workers` | all | as `-B`, `--xdp-mode`, `--queue` and `--workers` |
| `duration` | all | stop after this long (default: the plan's) |
| `delay` | all | start this long after the shared start |
| `impair`, `impair_rx` | all; `impair_rx` TCP and UDP | [impairments](impairments.md) |
| `cps`, `connections`, `concurrency` | TCP | replace the profile's |
| `rate`, `transactions`, `concurrency` | UDP | `rate` in transactions per second |
| `rate`, `limit`, `latency` | traffic | `rate` for every stream (`"10kpps"`, `"100mbps"`) |
| `rx`, `rx_wait`, `rx_agent` | traffic | receive on `rx`, on the sending agent or on `rx_agent` |
| `rx` | bench, y1564 | the interface the frames come back on (default: `iface`) |
| `until_ready` | hosts | end once every host has its addresses |
| `tests`, `line_rate` | bench, y1564 | replace the profile's tests and line rate (`"1gbps"`) |
| `sizes` | bench | replace the frame sizes |
| `services` | y1564 | test only these services |
| `only`, `lab` | scenario | run only these checks; build the scenario's `[lab]` (default: as the profile says) |

`backend`, `xdp_mode` and `queue` are for every kind but scenarios, whose
checks name their own; `workers` is not for hosts or scenarios. A setting a
kind does not take is refused when the plan is read, naming the kinds it is
for.

`require` and `require_each` take the [scenario conditions](scenarios.md#conditions)
and metrics of the run's kind. `require` judges the counters added up over
the run's agents; `require_each` judges every agent's part on its own. With
`require_each`, an agent that never got going fails the run even when the
others make up the sum. `[require]` judges the sums over every run of a
kind. A condition on a kind no run has fails. A run of a kind that has a
verdict (scenario, bench, y1564) also fails when the agent's run failed,
and a hosts run when a host failed, with or without conditions.

The metrics of the new kinds are summed over agents like the others:

| Kind | Metrics |
|---|---|
| hosts | `hosts`, `ready`, `ready_pct`, `failed`, `ready_avg`, `ready_max`, `tx_packets`, `rx_packets` |
| scenario | `passed` (1 when every agent's scenario passed), `checks`, `checks_passed`, `checks_failed`, `checks_passed_pct` |
| bench | `passed`, `trials`, `throughput_pct` and `throughput_mbps`/`throughput_pps` (the worst size), `latency_avg`, `latency_max`, `frame_loss_pct`, `sender_limited` |
| y1564 | the [Y.1564 metrics](scenarios.md#metrics) of each agent's test, combined |

A bench metric of a test that did not run (`frame_loss_pct` without a
frame loss test) has no value, and a condition on it fails as "not
measured".

`ferotrx check plan.toml` reads a plan without reaching any agent. It
fills in every agent's copy of every profile, reads them all, and warns
about absolute paths, which are not sent along.

## Captures

`[[capture]]` captures on agents for the length of the fleet run, with a
[BPF filter](capture.md):

```toml
[[capture]]
agents = ["east", "srv"]   # or agent = "srv"; default: every agent
iface = "d0"               # required
filter = "tcp port 80"     # optional
snaplen = 128              # optional, bytes kept of each frame
```

The controller's connections to the agents are not in the captures (an
agent leaves its control port out). Each capture starts before the runs and stops after them, into
`deploy_dir/captures/AGENT-IFACE.pcap` on its agent. `fleet run --collect
DIR` fetches them (`file.get`, checked by SHA-256) into `DIR/AGENT-IFACE.pcap`;
`--merge FILE` also writes one pcapng with an interface per capture, named
`agent:iface`, and every time stamp moved onto the controller's clock by
that agent's offset, so frames from different agents sort into the order
they happened (as well as the clocks were read). The report lists each
capture with its frames, bytes, drops and where it was collected.

```sh
ferotrx fleet run plan.toml --collect caps --merge caps/all.pcapng
wireshark caps/all.pcapng
```

## What happens

1. **Connect.** The controller logs in to every agent (token, or TLS with
   a client certificate), all at once, giving each 5 s. It needs the
   operator role. It reads each agent's clock five times with
   `server.info` and keeps the reading with the shortest round trip: the
   offset is the agent's time minus the middle of that round trip, as NTP
   takes it.
2. **Fit.** It asks each agent for its capabilities (`server.capabilities`)
   and health (`server.health`), and checks the plan against them before
   anything is sent: every kind of run the agent gets must be one it knows,
   every backend one it has, `workers` no more than its cores, and the
   plan within its [traffic limits](remote-control.md#traffic-limits). A
   misfit stops the fleet there, naming the run, the agent and what is
   missing. An agent that is over 80% busy, or already has runs going, gets
   a warning. An interface the agent does not list is a warning too
   (it may be made by a scenario's lab, or come up later); `fleet check`
   counts it as an error.
3. **Deploy.** Each run's profile goes to `deploy_dir/RUN/` on its agents
   with `file.put`. The text sent has the variables filled in. Every file
   the profile names by a relative path goes along, such as a pcap, a
   certificate or a key. The files keep their places relative to the
   profile, so `pcap = "../http.pcap"` still finds its file. The controller
   asks `file.stat` for each file's SHA-256 first and does not send a file
   the agent already has. `ferotrx fleet deploy` does only this step.
4. **Start.** The controller picks the shared start `start_delay` from now.
   Each start call (`tcp.start`, `udp.start`, `profile.load` and
   `run.start`, `host.start`, `scenario.start`, `bench.start` and
   `y1564.start`) carries `start_at`, the run's start in that agent's own
   clock: the shared start, plus the run's `delay`, plus the agent's
   offset. Each agent opens its interfaces at once and waits for that
   time. A receiver on another agent (`rx_agent`) starts first, with
   `rx.start`. If any start call fails, the controller stops and removes
   the runs that did start, so nothing runs half. The start calls go to
   the agents in parallel, so `start_delay` need not grow with their
   number.
5. **Follow.** Once per `interval` the controller reads every run's
   counters and adds them up per kind: connections, completions and cps;
   transactions and answers; packets, Mbit/s, loss and latency. The fleet
   ends when every run has ended, or on Ctrl-C (`stopped` in the report).
   It also ends 10 s after the longest run should have ended; the
   controller then stops what is left. With `telemetry` (the default) it
   also reads each agent's `server.health`: CPU load of the machine and of
   the server process, free memory, and the clock offset again, from the
   round trip of that call. Each sample line ends with each agent's CPU.
   CPU and memory are read on Linux agents; others report only the clock.
6. **Report.** The report has each agent with its version, round trip,
   clock offset, cores, its capabilities, its status and its telemetry:
   highest CPU, clock offset range, least free memory, and the drops per
   layer its runs counted (generator, NIC, network, receiver; see
   [loss and latency](loss-latency.md)). For each run it has each agent's counters, how late that
   agent started against the plan, and the run's and each part's
   conditions. Then come the sums per kind, the `[require]` results, and
   the samples taken along the way. The runs are then removed from the
   agents; `--keep` leaves them there to look at with `ferotrx ctl` or the
   GUI. Deployed files stay, so the next run sends nothing again.

## When an agent goes away

A broken control connection does not stop a run: the agent keeps running
it, and only the controller has lost sight of it. So the controller tries
again for `reconnect` (10 s), once per interval, and reads the run's
counters as soon as it is back. The report then says the agent
`reconnected`, how often, and how long it was out of reach; the run's
counters are complete.

```text
agent east: control connection lost (connection reset by peer); connecting again
agent east: back after 2.1 s
```

An agent that does not come back within `reconnect` is lost. The fleet goes
on with the others (`on_agent_loss = "continue"`) or stops every run
(`"stop"`). Either way the fleet fails, and the report says what was lost:

```text
LOST: agent 'west' out of reach from 5.2 s, given up at 8.2 s (connection refused); it had web clients; its counters are from 5.0 s
```

`failures` in the JSON report has one entry per lost agent: when the
connection broke (`at_s`) and when it was given up (`lost_at_s`), the error,
the runs it had, and the time of its last counters. Those counters stay in
the report, marked lost, and its parts of runs fail with that error. An
agent the controller cannot reach to stop its runs at the end is noted;
its runs go on to their own `duration`.

`start_spread_ms` is the latest start minus the earliest, after the planned
delays, judged by the controller's clock. On one machine it is well under a
millisecond. Across a LAN it is about the uncertainty of the clock
readings, half a round trip.

## Clocks

The runs start together whether or not the agents' clocks agree, because
the controller measures each offset. Loss counts do not depend on clocks
either. One-way latency between two agents does. The receiving agent
measures delay against the sender's timestamps in the signatures, so the
two clocks must be in step: NTP within a millisecond or so, or PTP for
microseconds. `fleet check` prints the offsets it measured. A large one
means the latency figures of a run with `rx_agent` are off by that much.

## On the command line

```text
ferotrx fleet run PLAN [--set NAME=VALUE]... [--duration TIME] [--report FILE] [--keep] [-q]
                      [--collect DIR [--merge FILE]]
ferotrx fleet check PLAN [--set NAME=VALUE]...
ferotrx fleet deploy PLAN [--set NAME=VALUE]...
```

`--duration` replaces every run's duration. `fleet check` reaches every
agent and prints its version, clock offset, cores, memory, interfaces, backends,
kinds of runs and load, then checks that the plan fits (as in step 2 above). It fails on a
misfit or on an interface an agent lacks. It sends nothing and starts
nothing.

```text
agent east at 10.99.0.11:4510: FeroTRX 0.51.0, round trip 0.11 ms, clock -0.0 ms from here, TLS
  east: 4 CPU(s), 15960 MiB, 5 interface(s), backends pcap af_xdp, runs traffic tcp udp rx hosts scenario bench y1564 capture; CPU 3% busy now
ok: every agent answers, and the plan fits them
...
   2.9s  2/4 running  tcp: connections 100, completed 100, failed 0, retransmits 0, cps 51.0  traffic: sent 1412, ...
...
Run 'web clients' (tcp web-clients.toml): PASS
  east         finished  connections 50, completed 50, failed 0, retransmits 0, cps 25.5; started +0.0 ms
    ok   completed == 50 (got 50.000)
  west         finished  connections 50, completed 50, failed 0, retransmits 0, cps 25.5; started +0.0 ms
    ok   completed == 50 (got 50.000)
  all                    connections 100, completed 100, failed 0, retransmits 0, cps 51.0
...
Fleet: PASS
```

## The agent's side

The control server gives the controller what it needs, and any client may
use the same calls ([remote control](remote-control.md)):

* `server.info` tells the server's clock (`time`, Unix seconds) and the
  largest file it takes (`max_file`).
* `server.capabilities` (0.51.0) tells the server's version, cores, memory,
  backends, interfaces, the kinds of runs and applications it has, its OS
  and its traffic limits. `server.health` tells its clock, uptime, CPU load
  (machine and process, since the last call), free memory, runs going and
  open connections. Both need only the read role.
* `host.start` (0.51.0) runs emulated hosts, like `tcp.start` a TCP
  profile; `scenario.start`, `bench.start` and `y1564.start` take
  `start_at` as the others do.
* `run.start`, `tcp.start` and `udp.start` take `start_at`, in Unix
  seconds by the server's clock. The run waits for that time; a time gone
  by starts at once, and one more than an hour ahead is refused. The run's
  `started_at` tells when it really started.
* `file.put` writes a file in the server's first data directory, in pieces
  of base64. The path must be relative, without `..`, and the file at most
  `--max-file` bytes (256M; 0 refuses files). `file.stat` gives a file's
  size and SHA-256. The audit log records how many bytes came, not the
  bytes. `file.get` reads a file back in pieces (captures, reports).
* `capture.start` captures on the agent's interface into a file in its
  data directory ([capturing](capture.md#on-a-remote-server)).
* `server.info` reports the agent's [traffic limits](remote-control.md#traffic-limits)
  (servers from 0.42.0). Before it deploys anything, the controller checks
  what the plan starts on each agent against them: interfaces (also of
  receivers), durations (the plan's or `--duration`), rates, `cps`,
  `concurrency` and how many runs go at once. A plan an agent would refuse
  fails there, naming the run, the agent and the option. The agents check
  again at each start, also what is inside the profiles; a refusal then
  stops what already started, as any failed start does.

In Rust these are `ferotrx_ctl::fleet` (`run_fleet`, `connect_all`,
`deploy`) and `ferotrx_core::fleet::FleetPlan`. In Python they are
`Client.file_put`, `file_stat`, `upload_file` and the `start_at` parameter
([the Python client](python-client.md)). The GUI's Multi-server tab starts
its groups with `start_at` too ([the GUI](gui.md#several-servers-at-once)).

## Lab script

`scripts/fleet-netns.sh` builds three agents in network namespaces. They
share a management bridge with the controller and a data bridge with each
other, and each has a cable of its own between two interfaces (`l0`,
`l1`). The script runs `examples/fleet/fleet.toml`: a web server on one
agent, web clients on two, and a probe stream from one client agent to the
server's agent. Everything must pass: 100 connections, the probe without
loss, starts within `SPREAD` ms (100), the files on the agents, and nothing
sent again by a second deploy. Captures on two agents (`tcp port 80`) are
collected and merged, and tcpdump must read back every frame the agents
counted. Then the script cuts one client agent off
the LAN, and the fleet must fail on that agent's part.

Part 3 kills one client agent (`kill -9`) 5 s into the run: the fleet must
fail, name that agent as lost with its run, and the other client agent
must still complete its connections. Part 4 resets the controller's
connection to one agent with iptables and refuses it for 2 s: the
controller must reconnect, and the fleet pass with every connection.
Part 5 runs `examples/fleet/fleet-kinds.toml` (emulated hosts, a scenario,
a benchmark and a Y.1564 test, one per agent, started together) and checks
each verdict, the agents' capabilities and their telemetry. It needs
iptables. CI runs it.

```sh
sudo scripts/fleet-netns.sh
sudo KEEP=/tmp/fleet scripts/fleet-netns.sh   # keep the reports and the agents' files
```

## Not done

* Agents do not find each other; the plan lists them.
* Captures are collected after the run; there is no live, merged feed.
* A lost agent is not restarted, and its run is not handed to another
  agent.
* Telemetry comes once per `interval` over the control connection; there
  is no separate monitoring channel or export (Prometheus and the like).
