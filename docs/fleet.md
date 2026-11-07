# Fleets: runs on several agents at once

One machine runs out of ports, cores or places in the network long before a
lab does. A fleet spreads a test over several machines. Each one runs
`ferotrx serve`, and each `ferotrx serve` is an agent. One plan file says
what each agent runs. `ferotrx fleet run` then does four things:

* sends every profile, and the pcaps and other files it names, to its
  agents;
* starts every run at one instant;
* adds up the agents' counters while the runs go;
* judges the plan's conditions on each part and on the sums.

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

A run is a TCP, UDP or traffic profile on one or more agents. Each agent
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

`require` and `require_each` take the [scenario conditions](scenarios.md#conditions)
and metrics of the run's kind. `require` judges the counters added up over
the run's agents; `require_each` judges every agent's part on its own. With
`require_each`, an agent that never got going fails the run even when the
others make up the sum. `[require]` judges the sums over every run of a
kind. A condition on a kind no run has fails.

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
   a client certificate). It needs the operator role. It reads each agent's
   clock five times with `server.info` and keeps the reading with the
   shortest round trip: the offset is the agent's time minus the middle of
   that round trip, as NTP takes it.
2. **Deploy.** Each run's profile goes to `deploy_dir/RUN/` on its agents
   with `file.put`. The text sent has the variables filled in. Every file
   the profile names by a relative path goes along, such as a pcap, a
   certificate or a key. The files keep their places relative to the
   profile, so `pcap = "../http.pcap"` still finds its file. The controller
   asks `file.stat` for each file's SHA-256 first and does not send a file
   the agent already has. `ferotrx fleet deploy` does only this step.
3. **Start.** The controller picks the shared start `start_delay` from now.
   Each start call (`tcp.start`, `udp.start`, `profile.load` and
   `run.start`) carries `start_at`, the run's start in that agent's own
   clock: the shared start, plus the run's `delay`, plus the agent's
   offset. Each agent opens its interfaces at once and waits for that
   time. A receiver on another agent (`rx_agent`) starts first, with
   `rx.start`. If any start call fails, the controller stops and removes
   the runs that did start, so nothing runs half.
4. **Follow.** Once per `interval` the controller reads every run's
   counters and adds them up per kind: connections, completions and cps;
   transactions and answers; packets, Mbit/s, loss and latency. The fleet
   ends when every run has ended, or on Ctrl-C (`stopped` in the report).
   It also ends 10 s after the longest run should have ended; the
   controller then stops what is left.
5. **Report.** The report has each agent with its version, round trip and
   clock offset. For each run it has each agent's counters, how late that
   agent started against the plan, and the run's and each part's
   conditions. Then come the sums per kind, the `[require]` results, and
   the samples taken along the way. The runs are then removed from the
   agents; `--keep` leaves them there to look at with `ferotrx ctl` or the
   GUI. Deployed files stay, so the next run sends nothing again.

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
agent and prints its version and clock offset. It warns when an agent lacks
an interface its runs name. It sends nothing and starts nothing.

```text
agent east at 10.99.0.11:4510: FeroTRX 0.31.0, round trip 0.11 ms, clock -0.0 ms from here
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

In Rust these are `ferotrx_ctl::fleet` (`run_fleet`, `connect_all`,
`deploy`) and `ferotrx_core::fleet::FleetPlan`. In Python they are
`Client.file_put`, `file_stat`, `upload_file` and the `start_at` parameter
([the Python client](python-client.md)). The GUI's Multi-server tab starts
its groups with `start_at` too ([the GUI](gui.md#several-servers-at-once)).

## Lab script

`scripts/fleet-netns.sh` builds three agents in network namespaces. They
share a management bridge with the controller and a data bridge with each
other. The script runs `examples/fleet/fleet.toml`: a web server on one
agent, web clients on two, and a probe stream from one client agent to the
server's agent. Everything must pass: 100 connections, the probe without
loss, starts within `SPREAD` ms (100), the files on the agents, and nothing
sent again by a second deploy. Captures on two agents (`tcp port 80`) are
collected and merged, and tcpdump must read back every frame the agents
counted. Then the script cuts one client agent off
the LAN, and the fleet must fail on that agent's part. CI runs it.

```sh
sudo scripts/fleet-netns.sh
sudo KEEP=/tmp/fleet scripts/fleet-netns.sh   # keep the reports and the agents' files
```

## Not done

* Agents do not find each other; the plan lists them.
* Captures are collected after the run; there is no live, merged feed.
* Runs of other kinds (benchmarks, Y.1564, scenarios, host emulation) are
  not in plans yet; each agent can run them on its own.
* The controller talks to the agents one after the other. With hundreds
  of agents, the start calls would need a longer `start_delay`.
