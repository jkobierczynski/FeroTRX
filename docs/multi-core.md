# One run on several cores

FeroTRX 0.13.0 (M20) can spread one run over several engine threads, called
workers, one per core. Until now every run had one thread for its streams or
its TCP/UDP engine, which capped a stateful run at about 25 000 connections
per second and a stateless one at what one thread can hand to the NIC.

```sh
# Streams: every worker sends its share of each stream on its own AF_XDP queue.
sudo ferotrx run examples/lab-two-vlans.toml -i enp1s0 -B af_xdp --workers 4

# Stateful TCP and UDP: each worker runs an engine with a slice of the clients.
sudo ferotrx tcp -p examples/lab-tcp.toml -i enp1s0 -B af_xdp --workers 4 --cps 40000 -n 0 -d 30s
sudo ferotrx udp -p examples/lab-dns.toml -i enp1s0 --workers 2 --rate 20000 -n 0 -d 30s
```

The worker count is `--workers N` on `replay`, `build`, `run`, `bench`,
`tcp` and `udp`, `workers = N` in a profile's `[output]` table (stream, TCP and UDP
profiles), and `workers` in `run.start` (in `output`), `tcp.start` and
`udp.start` on the control server, whose run info then says `workers`. The
default is 1, which runs exactly as before. At most 64.

What comes out is the same as one thread would send: the same packets, rates
and limits, the same counters (added up over the workers). What changes is how
much can go out.

## Streams

Each worker runs its own copy of every stream into its own sink. Packet `i` of
a stream goes out from worker `i mod N`: worker `k` sends packets `k`, `k+N`,
`k+2N` and so on, and skips the others without building them (sources jump
ahead, the field engine and size mixes step their counters). So the workers
together send every packet once, with the field values, sizes and latency
sequence numbers a single thread would give it.

* Rates are shared: a pps or Mbit/s rate is divided by `N`. Evenly spaced pps
  streams start each worker `k / pps` later, so their packets interleave as
  one stream's would. Original timing keeps the capture's timestamps, which
  every worker follows. Top speed is top speed on every worker.
* `limit` per stream and the run's total limit are shared out; `loops` holds
  as it is, since every worker walks the whole capture.
* Traffic models (Poisson, bursts, ramps) run on every worker at its share of
  the rate; Poisson arrivals added up are Poisson arrivals at the full rate.
  A model's `seed` is offset per worker.
* Sinks: libpcap/Npcap gets one handle per worker. AF_XDP gets one socket per
  worker, on consecutive queues from `--queue` (the interface needs that many
  queues: `ethtool -l IFACE`, `ethtool -L IFACE combined N`). DPDK ports,
  pcap files and the null output are opened once and shared behind a lock.
* Loss and latency: one receiver counts every worker's packets as one flow.
  Packets from different workers can arrive slightly out of order (they leave
  from different queues), which shows as reordering, not loss.

## Stateful TCP and UDP

Every worker runs an engine with the same emulated hosts, the same MAC and IP
addresses, and the same servers. What is split is the client side:

* The client's source ports (`source_ports`, default 1024-65534) are cut into
  one slice per worker, so each connection or transaction belongs to the
  worker that opened it.
* The connection or transaction rate, `connections`/`transactions` and
  `concurrency` are shared out, at the top level and per template. A limit
  smaller than the number of workers is an error (a worker would get none).
* Each worker gets its own seed (initial sequence numbers, DNS ids).

A frame that comes in goes to the worker it belongs to:

| Frame | Worker |
| --- | --- |
| TCP or UDP to a client address, on a port in a worker's slice | that worker: an answer on a connection it opened |
| Other TCP or UDP | a hash of the addresses and ports: the server side of a connection always lands on the same worker |
| ARP requests, neighbor solicitations, pings, anything else | worker 0, so each host answers once |
| ARP replies, neighbor and router advertisements, IGMP/MLD queries, broadcasts and multicasts | every worker: each engine resolves its next hops itself |

So the client and the server half of one connection usually sit on different
workers, which is fine: they only talk through the network. This holds
through NAT too: the router may change the client's port on the way out but
puts it back on the way in, and the server half follows the hash of whatever
the router made of it.

How frames reach the workers:

* **AF_XDP:** the port is split by receive queue. With at least `N` queues,
  each worker owns the AF_XDP sockets of every `N`-th queue and sends on the
  first of them; the NIC spreads the flows over the queues (RSS), and a
  worker passes frames that belong to another worker on to it. Broadcasts and
  multicasts come in on worker 0. Run as many workers as the interface has
  queues, or a divisor of it.
* **libpcap/Npcap, DPDK, or AF_XDP with fewer queues than workers:** the port
  is shared. Worker 0 reads it and passes frames on; every worker sends its
  own frames, a batch at a time behind a lock. One reader keeps the frames of
  each flow in order. This spreads the engine work, which is what limits a
  stateful run, but the port itself stays one thread's worth.

The run ends when it is stopped, its duration passes, or every worker's engine
is done (all their connections closed, held for 20 ms so a frame on its way
cannot be missed).

Not yet split over workers: hosts that get their addresses by DHCP, SLAAC or
DHCPv6, announce them or join groups (`ip = "dhcp"` and friends in TCP/UDP
runs, and `ferotrx host`). Those runs need `workers = 1`.

## How much it helps

Numbers from the four-core sandbox this was built in; a real NIC with more
queues and cores goes further.

| Run | 1 worker | 4 workers |
| --- | --- | --- |
| Stream at top speed, null sink | 5.8 Mpps | 23 Mpps |
| Stream at top speed, AF_XDP (copy) on a 4-queue veth | 0.90 Mpps | 3.4 Mpps |
| Stream at top speed, libpcap on a veth | 0.66 Mpps | 1.4 Mpps |
| TCP engine on memory ports (`engine_rate` example, 144 + 6198 bytes per connection) | 25k cps | about 45k cps |
| TCP through the netns NAT router, AF_XDP, 4-queue veth, 18k cps asked | collapses (2.2k cps, retransmit spiral) | 17.2k cps, no failures |

The memory-port line is lower than the others suggest because memory ports
are shared behind a lock (as libpcap ports are); with AF_XDP each worker has
its own queue. `cargo run --release -p ferotrx-core --example engine_rate --
60000 4` measures it on your machine.

An overloaded stateful run still collapses into retransmissions; more workers
move that point up. `--concurrency` keeps a run under it.

## In the library

* `Stream::shard(k, n)` makes worker `k`'s part of a stream;
  `Job::spawn_workers` runs one set of streams and a sink per worker.
* `TcpConfig::split(n)` and `UdpConfig::split(n)` give the engines' configs
  and a `FlowRouter`; `split_ports` splits the ports into lanes (through
  `PacketPort::split`, which AF_XDP ports implement); `PortJob::spawn_workers`
  runs them.
* `MergeStats` adds the counters up; `share` and `worker_seed` are the
  helpers the splits use.
* `ferotrx_io::Output::open_workers` opens an output once per worker.
