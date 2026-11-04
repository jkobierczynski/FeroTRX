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
| `fix_checksums` | Recompute IPv4, TCP, UDP and ICMPv6 checksums (for captures taken with checksum offload). |

Without `_src` or `_dst`, a rewrite changes both.

## Field engine

`--vary` changes a field from packet to packet, like TRex's field engine: one
packet gets the first value of the range, the next packet the next value, and
so on. Repeat it for more fields. It runs after the rewrites and works on
`replay`, `build` and `inspect` (to preview), and as `vary` in profiles.
IPv4, TCP, UDP, ICMP and ICMPv6 checksums are kept right; a length change also
fixes the IP and UDP length fields.

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
