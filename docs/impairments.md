# Impairments

FeroTRX can make a network worse on purpose, the way a bad link, a WAN or a
congested queue would, without netem or a separate emulator: it delays
frames (with jitter), loses them at random or in bursts, duplicates,
reorders and corrupts them, sends them no faster than a rate, and drops or
cuts frames over an MTU. It works on every platform FeroTRX runs on, the
numbers are seeded and repeatable, and every run counts what was done.

There are three places to use them:

* **Streams** (`ferotrx replay`/`run --impair`, `impair` in a `[[stream]]`):
  a stream's packets are impaired on their way to the output, so a receiver
  on the far side (`--rx`, `ferotrx rx`) sees the loss, delay and jitter.
* **TCP, UDP and host runs** (`--impair` and `--impair-rx`, or `impair` and
  `impair_rx` in the profile): the frames the run sends and the frames it
  receives, each way on its own. The engines then deal with what a real
  network would do to them: retransmissions, timeouts, retries.
* **A bridge between two interfaces** (`ferotrx impair`): real hosts on
  either side talk through it, impaired one way and the other.

## The spec

An impairment is a list of `key=value` pairs separated by spaces or commas,
on the command line and in profiles alike:

    delay=20ms jitter=5ms loss=1% loss_burst=3 rate=10mbit seed=7

| Key | Example | Meaning |
|---|---|---|
| `delay` | `20ms` | Added to every frame. |
| `jitter` | `5ms` | How far the delay varies (see `distribution`). |
| `distribution` | `normal` | `uniform` (default): evenly in delay ± jitter. `normal`: jitter is the standard deviation. `pareto`: at least `delay`, plus a long tail whose mean is `jitter`. |
| `correlation` | `25%` | How much each frame's jitter follows the last one's. |
| `keep_order` | `false` | Jitter keeps frames in order by default, as one queue does; `false` lets a frame with less delay pass one with more. |
| `loss` | `1%` | Frames lost (also `0.01`). |
| `loss_burst` | `3` | Mean length of a loss burst, in frames; without it loss is random. |
| `loss_bad` | `50%` | With bursts: the share lost in the bad state (default 100%). |
| `duplicate` | `0.5%` | Frames sent twice. |
| `reorder` | `1%` | Frames that skip the delay and so pass the ones before them. Needs a delay. |
| `corrupt` | `0.1%` | Frames with one bit flipped, in the payload past the TCP or UDP header. |
| `fix_checksums` | `true` | Recompute the checksums of corrupted frames, so the damage reaches the application instead of being dropped at the first checksum check. |
| `rate` | `10mbit` | The link's rate (`kbit`, `mbit`, `gbit`, or `bps`); frames queue for it after the delay. Each frame counts 24 more bytes (preamble, gap, FCS). |
| `limit` | `1000` | Frames held at once (default 10000); more are dropped (tail drop). With `rate` it is the queue's size. |
| `mtu` | `1400` | The largest IP packet (the frame after its Ethernet and VLAN headers). |
| `mtu_action` | `truncate` | `drop` (default) or `truncate` frames over the MTU. |
| `seed` | `7` | Seed of the random numbers; without it every run differs. |

`none` is no impairment, which turns a profile's off from the command line.

The order frames go through is: MTU, loss, duplication, corruption, delay
and jitter (or a reorder), then the rate queue.

**Bursty loss** is a Gilbert-Elliott model: a good state that loses nothing
and a bad state that loses `loss_bad` of its frames. FeroTRX picks the
transitions so that the loss over all is `loss` and a burst lasts
`loss_burst` lost frames on average. G.113's burst ratio (see [Call
quality](call-quality.md)) measured on such a link is above 1.

## Streams

```sh
ferotrx replay voice.pcap -i eth0 --rx eth1 --impair "delay=40ms jitter=10ms loss=2% seed=1"
ferotrx run lab.toml -i eth0 --impair "rate=20mbit limit=200"    # every stream
```

In a profile, per stream, as text or as a table:

```toml
[[stream]]
name = "voice"
packet = "eth/ipv4(src=10.0.0.1,dst=10.0.0.2)/udp(dport=5004)/raw(len=160)"
rate = "50pps"
loops = 0
latency = true
impair = "delay=40ms jitter=10ms distribution=normal loss=2% loss_burst=2"

[[stream]]
name = "bulk"
pcap = "bulk.pcap"
[stream.impair]
rate = "10mbit"
limit = 100
```

Packets count as sent when they go into the impairment. At the end the run
waits until the held packets are out (unless it is stopped). With
`--workers`, every worker has its own impairment with its share of the
rate. The run's report adds a line per stream:

    done impairments: 4001 in, 3923 out, 78 lost, held ms avg 15.71 min 12.04 max 18.00

## TCP, UDP and host runs

```sh
ferotrx tcp -p lab-tcp.toml --impair "delay=20ms loss=2% seed=1" --impair-rx "loss=2%"
ferotrx udp -p lab-dns.toml --impair "loss=10%"
ferotrx host lab-hosts.toml --impair-rx "loss=30%"      # DHCP retries
```

`--impair` is for the frames the run sends, `--impair-rx` for the frames it
receives, before the engine sees them. In profiles they are the top-level
`impair` and `impair_rx` (text or tables, as for streams). Each port of the
run gets its own impairments (and random numbers). The summary shows what
they did:

    impaired sent frames: 3608 in, 3548 out, 60 lost, held ms avg 5.00 min 5.00 max 5.00
    impaired received frames: 3549 in, 3464 out, 85 lost

Impaired ports cannot split for `--workers` the way AF_XDP ports do; the
workers share the port, which is slower but keeps one rate limit.

## The bridge

```sh
sudo ferotrx impair -i eth1 -o eth2 --impair "delay=50ms jitter=5ms loss=1%" -d 10m
```

Everything that arrives on `-i` goes out on `-o` impaired by `--impair`,
and everything that arrives on `-o` goes back out on `-i` impaired by
`--impair-back` (the same as `--impair` when left out, with its own random
numbers; `none` for a clean way back). Both interfaces are opened with
libpcap or Npcap in promiscuous mode, so put the bridge between two links
that nothing else bridges. It prints the counters every second and at the
end:

    done after 9.000 s
      ia -> ib: 400 in, 377 out, 23 lost, held ms avg 19.95 min 18.01 max 21.99
      ib -> ia: 377 in, 377 out, held ms avg 10.00 min 10.00 max 10.00

Linux hosts behind it should send full checksums (`ethtool -K IFACE tx
off`) when they share the machine through veth pairs: offloaded frames are
passed on with partial checksums.

## Scenarios

A check can make the network worse for itself only (see
[Scenarios](scenarios.md)), with `impair` (traffic, TCP and UDP checks) and
`impair_rx` (TCP and UDP):

```toml
[[check]]
name = "web over a lossy WAN"
tcp = "lab-tcp.toml"
impair = "delay=40ms loss=2% seed=1"
impair_rx = "loss=2% seed=2"
require = ["completed_pct >= 99%", "impair_dropped > 0"]
```

`impair_dropped` is the frames the run's own impairments dropped (lost,
over the MTU or over the queue limit).

## Control API, Python and GUI

`run.start` takes `impair` (for every stream); `tcp.start` and `udp.start`
take `impair` and `impair_rx`. Run info has `impair` counters
(`ImpairCounters`: `packets`, `passed`, `lost`, `mtu_dropped`, `truncated`,
`queue_dropped`, `duplicated`, `corrupted`, `reordered`, `held`, `max_held`
and the `delay` held), per stream and in all for `run.*`, and as
`impair.tx`/`impair.rx` for `tcp.*` and `udp.*`. `ferotrx ctl start`,
`tcp-start` and `udp-start` have the same options. The Python client's
`start`, `tcp_start` and `udp_start` take them as keyword arguments, and
the records have `ImpairCounters` and `PortImpairCounters`. The GUI's port
settings have an Impairments field for all streams, and the run statistics
show the counters.

In the library, `ferotrx_core::Impairer` is the sans-IO impairment (push
frames with the time, pop them when due), `ImpairPort` wraps any
`PacketPort`, `Stream::impair` impairs a stream, and `run_bridge` is the
bridge.

## What the numbers mean, and do not

The impairments are as exact as the clock FeroTRX runs on: held frames
leave within a fraction of a millisecond of their time on an idle machine.
On a busy machine or VM, the scheduler adds its own delay and jitter on top.
The rate limit counts frames as a link would, but FeroTRX's own sending is
not faster than its output allows.

## In the lab

`scripts/impair-netns.sh` builds two hosts in network namespaces with
`ferotrx impair` between them and checks, without netem: ping's round trip
and loss through a delayed, jittered and lossy bridge; pings over an MTU
lost and duplicates counted by ping; a stream's own `impair` (delay, jitter
and 2% loss) as a receiver in the other namespace measures it; and a rate
limit at half the stream's rate losing about half, with the queue's delay.
CI also runs `scripts/tcp-nat-netns.sh` with `--impair` and `--impair-rx` on
the TCP run.
