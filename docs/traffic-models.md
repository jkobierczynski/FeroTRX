# Traffic models and file checks

FeroTRX 0.10.0 (M17) adds two things: traffic models, which decide how
packets, connections and transactions spread over time around a rate, and
`ferotrx check`, which checks profile and scenario files without sending.
FeroTRX 0.50.0 (M53) adds [sessions and users](#sessions-and-users) (session
lengths, think times, users kept online) and [personas](#personas).

## Traffic models

Without a model, a stream at `1000pps` sends a packet every millisecond, and
a TCP client at `cps = 50` opens a connection every 20 ms. Real traffic is
not like that. A model changes the spacing and keeps the rate as the mean.

| Part | Written | What it does |
|---|---|---|
| Arrivals | `even` (default), `poisson` | Evenly spaced, or a Poisson process: independent events with exponentially distributed gaps, as from many independent users. |
| Bursts | `burst=N` | N packets (connections, transactions) back to back, then a pause; the bursts are spaced so the mean rate stays the same. With `poisson`, the bursts arrive as a Poisson process. |
| Ramp | `ramp_up=D`, `hold=D`, `ramp_down=D` | From 0 to the full rate in `ramp_up`, the full rate for `hold`, back to 0 in `ramp_down`, then the traffic ends. `hold` needs `ramp_down`. |
| Shape | `at=TIME:RATE`, repeated, or `shape = [...]` in a profile | The rate over time as points, straight lines between them, such as `at=0s:10%,at=30s:100%,at=60s:50%`. Before the first point the rate is the first point's; after the last it stays. A last point at 0% ends the traffic. |
| Seed | `seed=N` | Repeatable Poisson gaps; without it each run gets its own. |

A model is written as a comma separated list, the same everywhere:

```sh
ferotrx replay web.pcap -i eth0 --pps 2000 --model poisson -l 0 -d 60s
ferotrx replay web.pcap -i eth0 --mbps 200 --model burst=32 -l 0 -d 60s
ferotrx build "eth()/ipv4(dst=10.0.0.2)/udp()" -i eth0 --pps 50000 -l 0 \
    --model ramp_up=30s,hold=1m,ramp_down=30s
ferotrx run lab.toml -i eth0 --model poisson    # every stream of the profile
ferotrx tcp lab-tcp.toml --cps 200 -n 0 --model ramp_up=20s,hold=1m,ramp_down=20s
ferotrx udp lab-dns.toml --rate 500 -n 0 --model poisson -d 60s
```

In a traffic profile, each `[[stream]]` can have its own `model`, and `shape`
for the points:

```toml
format = 1

[[stream]]
name = "dns"
pcap = "dns.pcap"
rate = "200pps"
loops = 0
model = "poisson"

[[stream]]
name = "ramp"
packet = "eth(dst=02:00:00:00:00:01)/ipv4(src=192.168.10.102,dst=192.168.20.50)/udp()"
rate = "5kpps"
loops = 0
shape = ["0s:0%", "30s:100%", "90s:100%", "120s:0%"]
```

TCP and UDP profiles take `model` and `shape` at the top (for the
connections or transactions that share `cps` or `rate`) and in each
`[[template]]` that has its own `cps` or `rate`. A template without its own
rate shares the top-level schedule, so a model there is refused.

```toml
cps = 100
connections = 0
model = "poisson"

[[template]]
name = "bulk"
pcap = "download.pcap"
port = 8080
cps = 2
model = "burst=5"          # five downloads at once, every 2.5 s on average
```

[`examples/lab-models.toml`](../examples/lab-models.toml) has a Poisson, a
bursty and a ramped stream.

### Rules

* A model needs a packet or bit rate (`pps`, `mbps`). A capture's own timing
  (`1x`) and `topspeed` have no mean rate to shape, so a model there is an
  error.
* With a bit rate, Poisson gaps and burst pauses scale with the packet
  sizes, so the mean bit rate holds for mixed sizes too.
* A ramp that ends at 0% ends the stream even with `loops = 0`, and a TCP or
  UDP client stops opening connections or starting transactions. A TCP or
  UDP run with `connections = 0` / `transactions = 0` then finishes by
  itself once the open ones end.
* A stream that plays its packets only a few times (`loops = 1`) may run
  out of packets before a ramp ends; `ferotrx check` warns about it.
* When a TCP or UDP client is held back by `concurrency` or by a template
  that is not ready, it does not save up connections: at most one is owed
  when it can go on, as without a model.

### How it is computed

The rate at time t is `R·f(t)`, where f is the shape (1 without one). The
work done by time t is `W(t) = R·∫f`. Each event has a size in work units:
1 for a per-second rate, its bits for a bit rate. The pacer keeps the work
of the events so far and places the next event where `W(t)` reaches it.
Evenly spaced events add their own size; Poisson events add their size times
an exponential random number with mean 1; a burst starts where the work of
the burst before it is done, and all its events share that time. Straight
lines between shape points make `W` quadratic in each piece, which is solved
exactly, so a ramp from 0 to 100 pps in 10 s sends its 500 packets at the
times `sqrt(2·n/10)`, not in steps. With no model, the times are the same as
before 0.10.0.

## Sessions and users

A model spreads connections over time, but every connection is still alike:
one pass of a capture or of an application's request list. Real users come
and go, make sessions of different lengths, and pause between requests and
between sessions. FeroTRX 0.50.0 (M53) adds this to TCP and UDP profiles.

### Distributions

Session lengths, think times and user lifetimes are drawn from a
distribution, written the same everywhere:

| Written | Distribution |
|---|---|
| `5s`, `12`, `64K` | Fixed: always that value. |
| `exp(5s)` | Exponential with that mean (Poisson-like pauses). |
| `lognormal(median=2s, sigma=1)` | Log-normal: half below the median, a long tail; `mean=` instead of `median=` gives it by its mean. |
| `pareto(min=1K, shape=1.5)` | Pareto: at least `min`, a heavy tail (the smaller `shape`, the heavier). |
| `uniform(1s, 5s)` | Uniform between the two. |
| `normal(mean=200ms, sd=50ms)` | Normal, cut at 0. |

Any of them takes `min=` and `max=` to cut the draws to a range, such as
`lognormal(median=8, sigma=1, max=100)`. Times take `us`, `ms`, `s`, `m` and
`h`; byte sizes `K`, `M` and `G` (powers of 1024); counts are plain numbers.
Draws come from the run's seed (`[tcp] seed`, `[udp] seed`), so a seeded
run draws the same values again.

### Session lengths

A TCP template (or the top of a TCP profile, as the default for all
templates) takes one of:

| Key | A session ends after |
|---|---|
| `session_requests` | That many requests (HTTP), streams (HTTP/2, HTTP/3) or rounds of a capture. |
| `session_duration` | That much time: no new request or round starts after it. |
| `session_bytes` | That many bytes, sent and received together. |

and `think_time`, the pause between the requests or rounds of a session, as
a distribution (`--think-time` on the command line takes one too). A
session is one connection. Session lengths work with `app = "http"`,
`"https"`, `"h2"`/`"h2c"` and, in UDP profiles, `"h3"`, whose requests are
played in turn from the request list; and with a capture (`pcap`) whose
client speaks first, which is played again in rounds on the same
connection. Other protocols play their own sessions (`per_connection` and
the like) and refuse session lengths.

```toml
[[template]]
name = "web"
app = "http"
session_requests = "lognormal(median=5, sigma=0.8, max=50)"
think_time = "exp(1s)"

[[template]]
name = "app"
pcap = "http.pcap"
port = 8080
session_duration = "uniform(10s, 30s)"
think_time = "2s"
```

With a capture, `think_time` pauses both ends before they speak (as it did
before 0.50.0), so a round takes about twice the think time plus the round
trips.

### Users

A `[users]` table keeps a number of users online instead of opening
connections at a rate:

```toml
[users]
count = 50                  # online at once
think = "exp(5s)"           # between a user's sessions
lifetime = "exp(5m)"        # how long a user stays, then a new one comes
arrival = 10                # users per second at the start, until all are on
```

Each user has a client address of its own when `[client] ips` has enough
for them (else users share addresses in turn), makes one session at a time on a template picked by weight,
waits `think` after it ends and makes the next. With `lifetime`, a user
leaves when the session it is in ends after its time is up, and a new user
comes in its place, so `count` stays online. Without `arrival`, all users
start at once. With users, `cps`, `rate` and `connections` don't apply:
the run goes on until `-d` or Ctrl-C.

The summary has a `users:` line per group: users online, how many came and
left, sessions, the think times drawn and how long the users that left
stayed. The run's counters have `session_requests` (requests per session:
min, mean, median, p99, max) and `session_time`. The same are in the JSON
report (`tcp.users`, `udp.users`, `tcp.client.session_requests`), the control
API (`UserCounters`, `CountCounters`), Python, and as scenario metrics
(`users_online`, `users_arrived`, `users_departed`, `user_sessions`,
`user_think_avg`, `user_lifetime_avg`, `session_requests_avg`/`p50`/`p99`/`max`,
`session_time_min`/`avg`/`p99`/`max`).

Set `[tcp] idle_timeout` above the longest think time between requests, or
connections that wait are reset; `ferotrx check` warns when the median
think time is more than half of it.

Over UDP, a user's session is a transaction (a DNS lookup, an NTP request)
or a dialog (a SIP call, an HTTP/3 connection); `think` paces them. Session
lengths over UDP need a protocol that plays a whole session (`h3`).

[`examples/lab-sessions.toml`](../examples/lab-sessions.toml) keeps 50
users browsing in visits of a log-normal number of pages.

## Personas

A persona is a file that says what one kind of user does: how it pauses
and how long it stays (`[user]`, as `[users]` without `count`), and the
sessions it makes, as `[[tcp]]` and `[[udp]]` tables written like a
profile's `[[template]]`:

```toml
format = 1
name = "iot"
description = "MQTT telemetry in short connections, NTP"

[user]
think = "exp(30s)"
arrival = 20

[[tcp]]
name = "telemetry"
app = "mqtt"
port = 1883
[tcp.mqtt]
publish = ["lab/sensors/temp 1 32"]

[[udp]]
name = "ntp"
app = "ntp"
port = 123
```

A TCP profile takes the persona's `[[tcp]]` tables, a UDP profile its
`[[udp]]` tables, with a `[[persona]]` table each that says how many of its
users are online:

```toml
[[persona]]
file = "personas/office.toml"
users = 30

[[persona]]
file = "personas/iot.toml"
users = 100
think = "exp(5s)"           # optional: overrides the persona's [user]
lifetime = "exp(10m)"       # optional, as are arrival and name
port_offset = 1000          # optional: added to the persona's ports
```

The persona's templates join the profile's as `PERSONA/TEMPLATE`
(`office/intranet`), each group of users makes sessions only on its own
persona's templates, and the profile's `[server]` answers them all. A
profile can have both `[[persona]]` tables and its own `[users]` and
templates. A capture a persona names is looked for next to the persona
file. On a control server (`serve`, fleet agents), persona files must be in
a data directory like any other file; deploy them beside the profile.

Scenarios and fleet plans run profiles with personas like any other, and
`ferotrx check` checks a persona file on its own (kind `persona`): both its
TCP and UDP sides, with their apps.

[`examples/personas/`](../examples/personas) has four: `office` (intranet
over HTTPS, API posts, DNS), `iot` (MQTT telemetry, NTP), `voice` (SIP
calls with RTP, HTTP provisioning) and `server` (HTTP/2 API sessions with a
heavy tail). [`examples/lab-personas.toml`](../examples/lab-personas.toml)
and [`lab-personas-udp.toml`](../examples/lab-personas-udp.toml) mix them on
the lab router.

### Checking the numbers

`scripts/realism-netns.sh` (in CI) runs users through a NAT router in
network namespaces and checks that what was measured matches what was
asked: the median and mean of log-normal session lengths, exponential think
times, users online and their stay, capture rounds for a session duration,
UDP lookups at users ÷ think time, and every persona group making sessions.

## `ferotrx check`

```sh
ferotrx check examples/*.toml
ferotrx check lab-tcp.toml --kind tcp
ferotrx check scenario.toml --set server=192.168.20.80
ferotrx check -q --strict profiles/*.toml      # in CI: fail on warnings too
```

`check` reads each file, works out its kind (traffic, TCP, UDP, benchmark
profile or scenario), and does what a run would do before the first packet:
reads the captures, builds the packets, applies the field engine settings,
and sets up the TCP and UDP engines (which checks addresses, ports, rates,
templates and models). For a scenario it does this for every check. It
prints a summary line per stream, template or check, and warnings for
things that are allowed but probably not meant: a ramp on a stream that
runs out of packets first, or a template with weight 0 that nothing would
use. It exits with 1 if any file has an error, and with `--strict` also if
any has a warning.

The kind comes from the top-level keys: `[[check]]` is a scenario,
`[benchmark]` a benchmark profile, `[[stream]]` a traffic profile, `[user]`
or `[[tcp]]`/`[[udp]]` tables a persona; `rate`,
`app`, `queries`, `records`, `transactions` or `[udp]` (at the top or in a
template) make a UDP profile, and anything else is taken as TCP. `--kind`
overrides the guess.

The library has the same as `ferotrx_core::check::check_file`, and the
control API reports a stream's model in `StreamInfo.model`.

## Profile format version

Every kind of file may start with `format = 1`. Files without it are read as
format 1, which is what FeroTRX 0.10.0 reads. A file that says a newer
format is refused with "format N is newer than this FeroTRX reads", instead
of failing on whatever key is new. When a later release changes the meaning
of an existing key, it will raise the format number.
