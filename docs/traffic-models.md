# Traffic models and file checks

FeroTRX 0.10.0 (M17) adds two things: traffic models, which decide how
packets, connections and transactions spread over time around a rate, and
`ferotrx check`, which checks profile and scenario files without sending.

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
`[benchmark]` a benchmark profile, `[[stream]]` a traffic profile; `rate`,
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
