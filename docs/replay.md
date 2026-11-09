# Replaying captures, rewrites and profiles

The stateless side of FeroTRX: replay captures at a controlled rate, change
packets on the way, vary fields from packet to packet, and run several
streams at once from a TOML profile.

## Replaying a capture

Sending on an interface needs root or `CAP_NET_RAW` on Linux (see
[install.md](install.md#permissions)); `--out` and `--null` need nothing.

```sh
ferotrx info capture.pcap                        # packets, bytes, duration, average rate
ferotrx interfaces                               # interfaces you can send on
sudo ferotrx replay capture.pcap -i eth0         # original timing
sudo ferotrx replay capture.pcap -i eth0 -x 10   # 10 times faster
sudo ferotrx replay capture.pcap -i eth0 --pps 50000 --loop 0   # 50k pps until Ctrl-C
ferotrx replay capture.pcap --mbps 100 --out sent.pcap          # write instead of send
ferotrx replay capture.pcap --topspeed --null --loop 1000       # engine speed test
sudo ferotrx replay capture.pcap -i eth0 --rx eth1 --pps 1000   # loss and latency, received on eth1
```

## Rewriting

`--rewrite` (`-r`) changes packets before they are sent. Repeat it to chain
rewrites; they run in order. Address and port rewrites keep checksums correct.

```sh
ferotrx replay capture.pcap -i eth0 \
  -r vlan_push=20 \
  -r mac_dst=02:00:00:00:00:01 \
  -r ip_dst=10.0.0.0/8->192.168.0.0 \
  -r port_dst=53->5353
```

| Rewrite | Effect |
| --- | --- |
| `mac_src=TO`, `mac_dst=TO`, `mac=TO` | Set Ethernet addresses. `FROM->TO` only changes `FROM`. |
| `ip_src=TO`, `ip_dst=TO`, `ip=TO` | Set IPv4 or IPv6 addresses. `NET/LEN->TO` maps a prefix: the first `LEN` bits come from `TO`, the rest are kept. |
| `port_src=TO`, `port_dst=TO`, `port=TO` | Set TCP and UDP ports. `FROM->TO` only changes `FROM`. |
| `vlan_push=ID[:PCP]`, `qinq_push=ID[:PCP]` | Add an outer 802.1Q or 802.1ad tag. |
| `vlan_set=ID[:PCP]` | Change the outer tag. |
| `vlan_pop` | Remove the outer tag. |
| `fix_checksums` | Recompute IPv4, TCP, UDP and ICMPv6 checksums (for captures taken with checksum offload), and those of the tunnels around them. |
| `encap=SPEC` | Put the packet in a tunnel. `SPEC` is a [packet description](packets.md) of the outer headers, such as `eth/ipv4(dst=10.0.0.2)/udp/vxlan(vni=100)`. |
| `decap` | Take the outermost tunnel or MPLS label stack off. |
| `mpls_push=LABEL[:TC[:TTL]]` | Add an MPLS label in front of the IP header or the labels already there (TTL 64 unless given). |
| `mpls_pop` | Remove the outermost MPLS label. |

Without `_src` or `_dst`, a rewrite changes both.

### Tunnels

Packets inside MPLS, IP in IP (4in4, 6in4, 4in6, 6in6), GRE, VXLAN (UDP
4789), Geneve (UDP 6081) and GTP-U (UDP 2152) are rewritten inside: `ip_src`,
`port_dst` and the other address, port and payload rewrites and `--vary`
fields change the innermost headers, and the tunnel's UDP and GRE checksums
are kept right with them. Latency signatures go at the end of the innermost
payload too, so `--rx` measures through a tunnel endpoint that decapsulates.

`encap=` takes the outer headers as a packet description. When it ends with
`vxlan`, or with `eth` (`.../gre/eth` for Ethernet over GRE, `.../mpls/eth`
for an Ethernet pseudowire with a control word), the whole Ethernet frame is
carried; otherwise the IP datagram is, and the tunnel's protocol field (GRE
protocol, Geneve protocol, IP protocol 4 or 41) follows each packet's IP
version. Lengths and the tunnel's checksums are set for every packet.

```sh
# A capture through a VXLAN tunnel to 10.0.0.2, one VNI per 100 packets
sudo ferotrx replay web.pcap -i eth0 \
  -r 'encap=eth(dst=02:00:00:00:00:01)/ipv4(src=10.0.0.1,dst=10.0.0.2)/udp/vxlan(vni=100)' \
  --vary vni=100..199,every=100

# The same capture as GTP-U from a base station, one TEID per client
sudo ferotrx replay web.pcap -i eth0 --loop 50 \
  -r 'encap=eth/ipv4(src=10.1.0.1,dst=10.2.0.1)/udp/gtpu(teid=1000,qfi=9,pdu=ul)' \
  --vary ip_src+=0..49,every=21 --vary teid=1000..1049,every=21

# Two MPLS labels on top, then take the tunnel off a GRE capture
ferotrx inspect gre.pcap -r decap -r mpls_push=100 -r mpls_push=200:5
```

Plain rewrites changed the outer headers of tunneled captures before 0.47.0;
use `outer_ip_src` and friends in `--vary` for the tunnel itself.

## Field engine

`--vary` changes a field from packet to packet, like TRex's field engine: one
packet gets the first value of the range, the next packet the next value, and
so on. Repeat it for more fields. It runs after the rewrites and works on
`replay`, `build` and `inspect` (to preview), and as `vary` in profiles.
IPv4, TCP, UDP, ICMP and ICMPv6 checksums are kept right; a length change also
fixes the IP and UDP length fields. In tunneled packets the plain fields are
the innermost headers' and the tunnel's lengths and checksums follow.

```sh
# 20000 SYNs from 200 clients and random source ports, through the NAT router
sudo ferotrx build 'eth(dst=02:00:00:00:00:01)/vlan(id=10)/ipv4(dst=192.168.20.50)/tcp(dport=80,flags=S)' \
  -i enp0s3 --pps 1000 --loop 0 --limit 20000 \
  --vary ip_src=192.168.10.1..192.168.10.200 --vary port_src=1024..65535,random

# See what that sends: 10 packets, decoded
ferotrx build 'eth/ipv4/udp(dport=9)/raw(len=20)' -n 10 \
  --vary ip_src=10.0.0.0/24,random --vary len=64..1518,random

# Replay a capture as 100 different clients, one per loop (web.pcap has 21 packets)
sudo ferotrx replay examples/web.pcap -i enp0s3 --loop 100 --vary ip_src+=0..99,every=21
```

The form is `FIELD=MIN..MAX`, then options separated by commas:

| Field | Values |
| --- | --- |
| `mac_src`, `mac_dst` | MAC addresses: `02:00:00:00:00:01..02:00:00:00:00:ff` |
| `ip_src`, `ip_dst` | IPv4 or IPv6 addresses, `A..B` or a prefix `10.0.0.0/24`; packets of the other IP version are left alone |
| `port_src`, `port_dst` | TCP and UDP ports |
| `vlan` | ID of the outer VLAN tag (priority kept); untagged frames are left alone |
| `ip_id`, `ttl` | IPv4 identification; IPv4 TTL or IPv6 hop limit |
| `payload@OFFSET[:SIZE]` | SIZE bytes (1 to 16, default 1), big endian, OFFSET bytes after the TCP, UDP or ICMP header |
| `len` | Frame length without FCS: the payload is cut or padded with zeros, never the headers |
| `outer_ip_src`, `outer_ip_dst` | Addresses of the outermost tunnel |
| `outer_port_src`, `outer_port_dst` | UDP ports of the outermost VXLAN, Geneve or GTP-U tunnel |
| `teid`, `vni`, `gre_key` | GTP-U TEID, VXLAN or Geneve VNI, GRE key (when the header has one) |
| `mpls` | The outermost MPLS label (TC, S and TTL kept) |

| Option | Effect |
| --- | --- |
| `inc` (default) | Count up by `step`; after `MAX` start again at `MIN`. |
| `dec` | Count down from `MAX`. |
| `random` | Any value from `MIN` to `MAX`. `seed=N` repeats the same values every run. |
| `step=N` | Count by N (default 1). |
| `every=N` | Keep each value for N packets. Give a second variable `every=` the first one's range size to go through every combination. |

`FIELD+=MIN..MAX` adds the value to what the packet already has instead of
setting it (also for `mac`, `ip` and `port` without `_src`/`_dst`, which shift
both sides). Numbers can be decimal or `0x` hex. Every variable moves on once
per packet, whether or not that packet has its field.

## Profiles

A profile runs several streams at once into one output, each with its own
capture, rate, loops, start delay, rewrites and field engine (`vary`). The scheduler always sends the
packet with the earliest deadline, so paced streams keep their rate and top
speed streams fill the gaps.

```toml
[[stream]]
name = "dns"
pcap = "dns.pcap"            # relative to the profile
rate = "500pps"              # 1000pps, 10kpps, 100mbps, 1gbps, 2x, topspeed
loops = 0                    # 0 = until the run ends
rewrite = ["vlan_push=10", "ip_dst=192.168.20.50"]
vary = ["ip_src=192.168.10.1..192.168.10.254", "port_src=1024..65535,random"]

[[stream]]
pcap = "web.pcap"
rate = "20mbps"
delay = "5s"
limit = 100000
```

```sh
sudo ferotrx run lab.toml -i eth0 --duration 60s
```

[`examples/lab-two-vlans.toml`](../examples/lab-two-vlans.toml) is a commented
profile for a lab with a NAT router between two VLANs. It uses the small
sample captures `examples/dns.pcap` and `examples/web.pcap`, so it runs as is:

```sh
sudo ferotrx run examples/lab-two-vlans.toml -i eth0 --duration 60s
ferotrx run examples/lab-two-vlans.toml --out lab.pcap --duration 15s   # dry run to a file
```

A stream can also send built packets instead of a capture: give `packet` (one)
or `packets` (a list) instead of `pcap`. `interval` sets their spacing at rate
1x (default 1 s); `rate` overrides it as usual, and rewrites work too.

```toml
[[stream]]
name = "ping-vlan20"
packet = "eth(dst=02:00:00:00:00:01)/vlan(id=10)/ipv4(src=192.168.10.100,dst=192.168.20.50)/icmp(id=1)/raw(len=56)"
rate = "10pps"
loops = 0
```

[`examples/lab-built-packets.toml`](../examples/lab-built-packets.toml) has more.

### Rates that are a share of the line

Besides packets and bits per second, a rate can be a share of the line,
`rate = "50%"` (or `--load 50` on `replay` and `build`). It counts the frames
as the wire carries them: 24 more bytes per frame for preamble, gap and FCS.
The line's speed comes from `line_rate` in `[output]`, `--line-rate`, or the
interface's own speed (Linux reads it with ethtool; give it where that does
not work, and for `--out` and `--null`). Bit rates count the frames alone by
default; `100mbps-l1` (or `--l1` with `--mbps`) counts them on the wire like
a share does, and `100mbps-l2` says the default out loud.

```toml
[output]
line_rate = "10gbps"

[[stream]]
pcap = "web.pcap"
rate = "25%"                 # 2.5 Gbit/s on the wire
```

### Bursts and streams that start each other

`burst_size` sends packets in bursts at the stream's rate, with `burst_gap`
between them, and `bursts` ends the stream after that many (TRex's
multi-burst). `next` names the stream to start when this one ends; a stream
that some earlier stream names waits for it instead of starting with the
run (`start = true` starts it with the run as well). Naming an earlier stream
makes a loop, run `next_count` times (default: until the run ends).

```toml
[[stream]]
name = "probe"
packet = "eth/ipv4(dst=10.0.2.2)/udp/raw(len=18)"
rate = "10kpps"
burst_size = 64              # 64 packets at 10 kpps,
burst_gap = "5ms"            # 5 ms quiet,
bursts = 10                  # ten times, then
next = "bulk"                # start "bulk"

[[stream]]
name = "bulk"
pcap = "web.pcap"
rate = "50%"
limit = 10000
next = "probe"               # and back, three more times
next_count = 3
```

### The port's own addresses (L3 mode)

Instead of writing MACs into every packet, a port can have an address of
its own, as TRex's L3 port mode does. With `ip` and `gateway` FeroTRX asks
for the gateway's MAC by ARP (IPv4) or neighbor discovery (IPv6) before it
sends, puts it in every frame as the destination (and the port's MAC as the
source), and while the run goes on answers ARP, neighbor solicitations and
pings for the port's addresses, so the router can reach it. The gateway is
the router, or the receiver itself when that is on the port's subnet. A
stream's own `mac_dst`/`mac_src` rewrites still win. `answer` adds address
ranges the port answers for too, such as the varied sources of a stream
whose replies come back to the port.

```toml
[output]
ip = ["10.0.0.2/24", "2001:db8::2/64"]   # one per IP version
gateway = ["10.0.0.1", "2001:db8::1"]
vlan = 10                                # ARP and answers in VLAN 10
answer = ["10.0.1.1-10.0.1.254"]
# mac = "02:00:00:00:00:10"              # default: the interface's
```

```sh
sudo ferotrx run lab.toml -i eth0 --ip 10.0.0.2/24 --gateway 10.0.0.1
sudo ferotrx build 'eth/ipv4(src=10.0.0.2,dst=10.0.2.2)/udp' -i eth0 --ip 10.0.0.2/24 --gateway 10.0.0.1 --load 10
```

`replay`, `build`, `run`, `bench`, and `run.start` and `bench.start` of the
control server take the same; it fails with a clear error when the gateway
does not answer within 3 s. Answers go out on the same interface through
libpcap, also when the streams send with `af_xdp`; DPDK ports are not seen
by the kernel and are refused (rewrite `mac_dst` there). Scenario traffic
checks do not resolve addresses or shares of the line yet.

### Changing a running run

Through the control server a running run can be paused and resumed, as a
whole or stream by stream, and its rate changed in place, without starting
the schedule again: a paused stream goes on where it was, with no catch-up
burst, and a new rate applies to what is left (`ferotrx ctl pause|resume|update`,
`run.pause`, `run.resume`, `run.update`, Python `pause()`, `resume()`,
`update()`, the GUI's Pause button and rate multiplier). See
[remote-control.md](remote-control.md#changing-a-running-run).

### Traffic models: Poisson, bursts, ramps

With a packet or bit rate, `model` (or `--model` on `replay`, `build`, `run`,
`tcp` and `udp`) spreads the packets around the rate instead of spacing them
evenly; the rate stays the mean. `poisson` gives exponentially distributed
gaps, `burst=N` sends N packets back to back, `ramp_up=30s,hold=1m,ramp_down=30s`
ramps the rate up and down and then ends the stream, and `shape` (or
`at=TIME:RATE` points) draws any rate over time. TCP and UDP profiles take the
same for their connections and transactions.

```toml
[[stream]]
pcap = "dns.pcap"
rate = "2000pps"
loops = 0
model = "poisson,burst=4"
shape = ["0s:10%", "30s:100%", "120s:100%", "150s:0%"]
```

```sh
sudo ferotrx replay web.pcap -i eth0 --mbps 100 -l 0 --model ramp_up=1m,hold=5m,ramp_down=1m
```

[`examples/lab-models.toml`](../examples/lab-models.toml) has examples, and
[docs/traffic-models.md](traffic-models.md) the details.

### Checking files

`ferotrx check FILE...` reads traffic, TCP, UDP and benchmark profiles and
scenarios as a run would (captures, built packets, engine setup) without
sending, prints a summary and warnings, and exits with 1 on errors (`--strict`:
on warnings too), which suits CI. Every file may say `format = 1`; a file
from a newer FeroTRX with a higher format is refused with a clear message.
