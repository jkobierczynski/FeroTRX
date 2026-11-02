# FeroTRX

FeroTRX is a traffic replay tool written in Rust, inspired by
[Cisco TRex](https://trex-tgn.cisco.com/). It replays pcap and pcapng captures
at a controlled rate on Linux, macOS and Windows, rewrites them on the way
(addresses, ports, VLAN tags), varies fields from packet to packet, builds packets from scratch, runs several streams
at once from a profile, replays TCP sessions statefully (real connections, both ends emulated, through NAT
routers and firewalls), and its engine is a library you can use from your own programs.

## Status

* **M1, pcap replay:** done.
* **M2, rewriting and multi-stream profiles:** done.
* **M3, packet inspection (`ferotrx-packet`, `ferotrx inspect`):** done.
* **M4, packet building (`ferotrx build`, built packets in profiles):** done.
* **M5, remote control (`ferotrx-ctl`, `ferotrx serve`, `ferotrx ctl`):** done.
* **M6, fast send backends (AF_XDP on Linux, DPDK as an option):** done.
* **M7, field engine (per-packet field ranges, `--vary`, `vary` in profiles):** done.
* **M8, stateful TCP (`ferotrx tcp`, TCP profiles, `tcp.*` control methods):** this release.

## Crates

| Crate | What it is |
| --- | --- |
| `ferotrx-core` | The core API: captures, rewrites, streams, profiles, pacing, the scheduler and the stateful TCP engine. No platform code. |
| `ferotrx-packet` | Packet decoding (layers, fields with byte ranges, checksum checks, summaries) and building. No dependencies. |
| `ferotrx-io` | Packet sinks: network interfaces through libpcap/Npcap, AF_XDP or DPDK; pcap files. Send-and-receive ports for stateful TCP. |
| `ferotrx-ctl` | Remote control: a JSON-RPC server and client to load profiles, start and stop runs, and read live counters. |
| `ferotrx-cli` | The `ferotrx` command line tool. |

## Build

You need a stable Rust toolchain and libpcap:

* **Linux:** `sudo apt install libpcap-dev` (or your distribution's package).
* **macOS:** libpcap ships with the OS.
* **Windows:** install [Npcap](https://npcap.com/) to run, and put the Npcap SDK's
  `Lib\x64` folder on the `LIB` path to build.

```sh
cargo build --release
```

To build without libpcap (file and null output only):
`cargo build -p ferotrx-cli --no-default-features`.

AF_XDP support is built in on Linux and needs no extra libraries. DPDK support
is optional: install DPDK 21.11 or newer with its pkg-config file
(`sudo apt install dpdk-dev` on Debian and Ubuntu) and build with
`cargo build --release --features dpdk`. `ferotrx backends` shows what a build has.

## Usage

```sh
ferotrx info capture.pcap                        # packets, bytes, duration, average rate
ferotrx interfaces                               # interfaces you can send on
sudo ferotrx replay capture.pcap -i eth0         # original timing
sudo ferotrx replay capture.pcap -i eth0 -x 10   # 10 times faster
sudo ferotrx replay capture.pcap -i eth0 --pps 50000 --loop 0   # 50k pps until Ctrl-C
ferotrx replay capture.pcap --mbps 100 --out sent.pcap          # write instead of send
ferotrx replay capture.pcap --topspeed --null --loop 1000       # engine speed test
```

### Inspecting

`ferotrx inspect` decodes a capture: Ethernet, 802.3/LLC, VLAN and QinQ tags,
Linux cooked captures, ARP, IPv4, IPv6 with extension headers, TCP, UDP, ICMP,
ICMPv6 and DNS/mDNS, and names common ports (HTTP, TLS, SSH, DHCP, NTP, SNMP).
It checks IPv4, TCP, UDP, ICMP and ICMPv6 checksums and flags truncated headers.

```sh
ferotrx inspect capture.pcap                  # one line per packet
ferotrx inspect capture.pcap -p 3 -p 10-12    # layers, fields and hex dump of chosen packets
ferotrx inspect capture.pcap -v -c 20         # layers of the first 20 packets
ferotrx inspect capture.pcap --problems       # only bad checksums and truncated packets
ferotrx inspect capture.pcap -p 1 -r vlan_push=10 -r ip_dst=192.168.20.50   # preview rewrites
```

```text
   No.         Time  Source        Destination   Protocol    Len  Info
     1     0.000000  10.1.2.20     10.1.2.80     TCP          54  50000 → 80 [SYN] Seq=1000 Win=64240 Len=0
     3     0.011000  10.1.2.20     10.1.2.80     HTTP        140  GET /page0.html HTTP/1.1
```

Every field in the `-p` view shows the byte range it came from, so you can find
it in the hex dump below it.

### Building packets

`ferotrx build` makes packets from a description of their layers, joined by
`/`, each with optional `field=value` pairs. Lengths, types, ports for DNS and
all checksums are filled in; anything you set explicitly is kept, so you can
also build broken packets on purpose (`udp(chksum=0x1234)`, `ipv4(len=9)`).
Ethernet frames are padded to 60 bytes.

```sh
# Show what a packet looks like, layer by layer, with a hex dump
ferotrx build 'eth(dst=02:00:00:00:00:01)/vlan(id=10)/ipv4(src=192.168.10.100,dst=192.168.20.50)/udp/dns(q=example.com)' -v --hex

# Write packets to a pcap file (one argument per packet, 1 s apart)
ferotrx build 'eth/ipv4(dst=10.0.0.2)/tcp(dport=443,flags=S,mss=1460)' \
              'eth/ipv4(dst=10.0.0.2)/icmp(id=1,seq=1)/raw(len=56)' -o built.pcap

# Send them: 100 pps, 1000 times over
sudo ferotrx build -f packets.txt -i eth0 --pps 100 --loop 1000
```

`-f FILE` reads packets from a file, one per line; `#` starts a comment and a
line ending in `/` continues on the next. See
[`examples/packets.txt`](examples/packets.txt). Without a rate, packets go out
`--interval` apart (default 1 s), like `ping`.

| Layer | Fields (defaults) |
| --- | --- |
| `eth` | `src` (02:00:00:00:00:fe), `dst` (02:00:00:00:00:02), `type` (from the next layer), `pad` (1) |
| `vlan`, `qinq` | `id` (1), `pcp`, `dei`, `tpid` (0x8100; 0x88a8 for `qinq`), `type` |
| `arp` | `op` (request, reply or a number), `smac` (Ethernet source), `sip`, `tmac`, `tip` |
| `ipv4` | `src` (192.0.2.1), `dst` (192.0.2.2), `ttl` (64), `dscp`, `ecn`, `tos`, `id` (1), `df`, `mf`, `frag` (bytes), `proto`, `len`, `chksum` |
| `ipv6` | `src` (2001:db8::1), `dst` (2001:db8::2), `hlim` (64), `tc`, `flow`, `nh`, `plen` |
| `tcp` | `sport` (49152), `dport` (80), `seq`, `ack`, `flags` (S; any of FSRPAUEC, or a number), `win` (64240), `urg`, `mss`, `wscale`, `sackok`, `chksum` |
| `udp` | `sport`, `dport` (53 on the server side of DNS, else 49152 → 9), `len`, `chksum` |
| `icmp` | `type` (echo request), `code`, `id`, `seq`, `chksum`; ICMPv6 after `ipv6` |
| `dns` | `id` (1), `q` (name, repeatable), `qtype` (A, AAAA, MX, ... or a number), `qr`, `a` (answer address, repeatable; makes it a response), `ttl` (300), `rd` (1), `ra`, `aa`, `tc`, `opcode`, `rcode` |
| `raw` | `hex=0a0b0c`, `text="..."` (quotes allow `,` `)` and `\"`), `len=N` with `fill` (0) |

Numbers can be decimal or `0x` hex; on/off fields take 1/0, true/false or
yes/no. A packet that starts with `ipv4` or `ipv6` is written with the raw IP
link type instead of Ethernet.

### Rewriting

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

### Field engine

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

### Profiles

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

[`examples/lab-two-vlans.toml`](examples/lab-two-vlans.toml) is a commented
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

[`examples/lab-built-packets.toml`](examples/lab-built-packets.toml) has more.

Sending on an interface needs root or `CAP_NET_RAW` on Linux, access to
`/dev/bpf*` on macOS, and Npcap on Windows.

### Fast send backends

By default packets go out through libpcap (Npcap on Windows), one system call
per packet, which works everywhere. On Linux two faster senders sit behind the
same engine; pick one with `--backend` (`-B`):

| Backend | What it is | Needs |
| --- | --- | --- |
| `pcap` (default) | libpcap/Npcap | Linux, macOS or Windows |
| `af_xdp` | AF_XDP socket: packets are copied into shared memory and handed to the kernel in batches. No XDP program is loaded; sending needs none. | Linux 5.4+, root (or `CAP_NET_RAW` + `CAP_NET_ADMIN`) |
| `dpdk` | DPDK user space drivers, packets handed to the NIC in bursts | a build with `--features dpdk`; a NIC bound to `vfio-pci` and hugepages, or a DPDK virtual device |

```sh
ferotrx backends                                                  # what this build has
sudo ferotrx replay capture.pcap -i enp0s3 -B af_xdp -t --loop 0  # AF_XDP, top speed
sudo ferotrx run lab.toml -i enp0s3 -B af_xdp --xdp-mode copy     # force copy mode
sudo ferotrx replay capture.pcap -B dpdk -i 0000:03:00.0 --dpdk-args '-l 0-1' -t
sudo ferotrx replay capture.pcap -B dpdk -i net_af_packet0,iface=enp0s3 \
     --dpdk-args '--no-huge -m 512 --no-pci -l 0' -t              # DPDK without a DPDK NIC
```

Options for `af_xdp` and `dpdk`:

* `--xdp-mode auto|copy|zerocopy` (AF_XDP): `auto` tries zero-copy and falls
  back to copy mode. Copy mode (also called SKB or generic mode) works on every
  interface, including VirtualBox and other virtual NICs, veth pairs and
  bridges; zero-copy needs a driver that supports it (i40e, ice, mlx5, ixgbe, ...).
* `--queue N`: the transmit queue (default 0). One AF_XDP socket per queue.
* `--batch N`: packets handed to the kernel or NIC at once (default 64). Paced
  streams are never held back to fill a batch: whatever is queued goes out
  before the engine waits for the next packet's time.
* `--dpdk-args '...'` (DPDK): arguments for DPDK's EAL, such as cores (`-l 0-1`),
  memory (`--no-huge -m 512`) or allowed devices (`-a 0000:03:00.0`). With
  `-B dpdk`, `-i` names a DPDK device: a PCI address, a virtual device such
  as `net_af_packet0,iface=eth0` or `net_pcap0,iface=eth0`, or a port number.

Packets sent through AF_XDP or DPDK skip the kernel's packet taps, so tcpdump
or Wireshark on the sending machine does not show them. Capture on the receiver
or the router, or watch `/sys/class/net/<iface>/statistics/tx_packets`.

Packets can be up to 4096 bytes with either fast backend. The line printed at
the start says what was opened, e.g. `sending with af_xdp on enp0s3 queue 0, copy mode`.

A profile can choose the sender in an `[output]` table; command line flags and
control requests override it value by value:

```toml
[output]
backend = "af_xdp"           # pcap (default), af_xdp or dpdk
xdp_mode = "copy"            # auto (default), copy or zerocopy
queue = 0
batch = 64
dpdk_args = ["--no-huge", "-m", "512"]
```

On a VirtualBox VM such as the lab's Debian host, the virtual NIC has no
zero-copy support, so AF_XDP runs in copy mode; it still saves the per-packet
system call of libpcap. On a veth pair here it sends about 1.0 Mpps against
0.66 Mpps for libpcap. Bridged adapters need promiscuous mode "Allow all" as before.

### Remote control

`ferotrx serve` runs a control server; other programs load profiles, start and
stop runs and read live counters over it. `ferotrx ctl` is its command line client.
Runs started remotely go through the same engine code as `ferotrx run`.

```sh
# On the traffic box (here the lab's Debian host), reachable from the lab network:
sudo ferotrx serve --listen 0.0.0.0:4510 --token s3cret -p examples/lab-two-vlans.toml

# From anywhere that can reach it:
export FEROTRX_CTL=192.168.56.10 FEROTRX_TOKEN=s3cret
ferotrx ctl info
ferotrx ctl load /srv/profiles/voip.toml               # a file on the server
ferotrx ctl load my-test.toml --upload                 # or send a local one
ferotrx ctl start lab-two-vlans -i enp0s3 -d 60s --watch   # live counters until it ends
ferotrx ctl start voip -i enp0s3 --rate 10kpps         # override every stream's rate
ferotrx ctl start voip -i enp0s3 -B af_xdp             # send through AF_XDP on the server
ferotrx ctl stats                                      # every run
ferotrx ctl stop 2
ferotrx ctl --json stats 2                             # JSON for scripts
```

The protocol is [JSON-RPC 2.0](https://www.jsonrpc.org/specification) over TCP,
one JSON object per line, on port 4510. Any language with sockets and JSON can
use it; see [`examples/ctl-client.py`](examples/ctl-client.py) for Python with
no extra packages, or `ferotrx_ctl::Client` from Rust.

| Method | Params | Result |
| --- | --- | --- |
| `server.info` | | name, version, protocol, interfaces, backends, auth_required |
| `auth` | `token` | `true` |
| `interfaces.list` | | `[{name, description}]` |
| `profile.load` | `path` (on the server) or `toml` (+ `base_dir`), optional `name` | the profile's streams |
| `profile.get`, `profile.unload` | `name` | profile / `true` |
| `profile.list` | | loaded profiles |
| `run.start` | `profile`, `output` (`{"iface": ..}`, `{"file": ..}` or `{"null": true}`; with `iface` also optional `backend`, `xdp_mode`, `queue`, `batch`, `dpdk_args`), optional `rate`, `limit`, `duration`, `ignore_errors` | the run |
| `run.stop` | `id`, `wait` (default true) | the run, final counters |
| `run.stats`, `run.remove` | `id` | the run |
| `run.list` | | every run |
| `tcp.start` | a TCP profile as `path` (on the server) or `toml` (+ `base_dir`); optional `iface`, `cps`, `connections`, `concurrency`, `duration` | the TCP run |
| `tcp.stop` | `id`, `wait` (default true) | the TCP run, final counters |
| `tcp.stats`, `tcp.remove` | `id` | the TCP run |
| `tcp.list` | | every TCP run |
| `stats.subscribe` | optional `id`, `interval_ms` (default 1000) | `{subscription}` |
| `stats.unsubscribe` | `subscription` | `true` |

A run has a `state` (`running`, `finished`, `stopped`, `failed` with `error`),
`total` counters (`packets`, `bytes`, `send_errors`, `loops_completed`,
`elapsed_s`, `pps`, `mbps`) and the same counters per stream. After
`stats.subscribe`, the server pushes `stats` notifications on the connection:

```json
{"jsonrpc":"2.0","method":"stats","params":{"subscription":1,"run":{"id":1,"state":"running","total":{"packets":51200,"pps":5000.1,...},"streams":[...]}}}
```

A subscription to one run ends with an update marked `"last": true` when the
run ends. Error codes are the JSON-RPC ones plus -32001 (send `auth` first),
-32002 (no such profile, run or subscription) and -32003 (could not be done,
e.g. a profile that does not parse or an interface that will not open).

The server listens on 127.0.0.1 unless told otherwise. It sends traffic and
reads and writes files with its own privileges, so on a shared network give it
a `--token` (or `FEROTRX_TOKEN`); the token travels in clear text, so keep the
control port on a lab or management network.

### Stateful TCP

A replay sends captured packets as they are. That is fine for a switch, but a
NAT router or a stateful firewall drops them or rewrites them into nonsense:
their sequence numbers belong to no connection it knows, and nobody answers.
`ferotrx tcp` replays a TCP session as real connections instead, like TRex's
advanced stateful mode: FeroTRX emulates the client and the server hosts,
opens connections at a set rate with real handshakes, tracks sequence and
acknowledgement numbers on both sides, retransmits what gets lost, plays what
each end sent in the capture, and closes with FINs. The router in between can
translate addresses and ports as it likes; each end only answers what it sees.

```sh
ferotrx tcp --list capture.pcap                   # the TCP connections in a capture
ferotrx tcp capture.pcap --flow 2 --show          # what each end will send
sudo ferotrx tcp -p examples/lab-tcp.toml -i enp0s3            # the lab profile
sudo ferotrx tcp examples/http.pcap -i enp0s3 \
     --client-ip 192.168.10.100/24 --client-ips 10 --client-gw 192.168.10.1 --client-vlan 10 \
     --server-ip 192.168.20.50/24 --server-gw 192.168.20.1 --server-vlan 20 \
     --cps 50 -n 1000 --concurrency 100
```

A run through the namespace router of `scripts/tcp-nat-netns.sh` (below), with
the client and server on links `c0` and `s0`:

```text
session: 10.1.2.30:51000 -> 10.1.2.80:80: 4 messages, 144 bytes from the client, 6198 from the server, client closes
client: 192.168.10.100/24 mac 02:00:c0:a8:0a:64 on c0 (10 addresses), gateway 192.168.10.1
server: 192.168.20.50/24 mac 02:00:c0:a8:14:32 on s0, gateway 192.168.20.1
opening 1000 connections at 50 per second
done in 19.980 s: 17012 frames (7314720 bytes) sent, 17012 (7268504 bytes) received
  client: 1000 connections, 1000 established, 1000 completed; 144000 bytes sent, 6198000 received, 0 retransmits
  server: 1000 connections, 1000 established, 1000 completed; 6198000 bytes sent, 144000 received, 0 retransmits
  50.0 connections per second
```

How it works:

* **The session.** The chosen connection is reassembled in both directions
  by sequence number (retransmissions and reordering in the capture do not
  matter) and turned into messages: the client sends its first request, the
  server waits for all of it and answers, and so on; then the end that closed
  first in the capture sends its FIN. If only one direction was captured, the
  other side's byte counts come from the acknowledgements and are sent as zeros
  (`--show` says so). `examples/http.pcap` has both directions of an HTTP/1.1
  connection with two requests.
* **The hosts.** Each emulated host has its own IP address (or a range of
  them with `--client-ips`), a MAC address (02:00 followed by its IPv4 address,
  or `--client-mac`), an optional VLAN tag and a gateway. It answers ARP and
  ping, so the router can reach it, and the interface is opened in promiscuous
  mode. Use addresses that are free in each subnet, not addresses of the machine
  FeroTRX runs on, or its own TCP stack answers with resets.
* **Where they run.** Client and server can share one interface (a trunk
  with a VLAN each, as in the lab profile), use one interface each
  (`--client-iface`, `--server-iface`), or run on different machines: run
  `ferotrx tcp ... --server-ip ...` on one and `ferotrx tcp ... --client-ip ...
  --connect 192.168.20.50:80` on the other. Behind a port forward, `--connect`
  is the router's outside address.
* **Rates.** `--cps` new connections per second, `-n` connections in all (0
  until Ctrl-C or `--duration`), `--concurrency` most open at once, client
  source ports from `--source-ports` (1024-65534) on each client address.
* **Checks.** Each end compares every byte it receives with the capture.
  The summary counts completed, reset, timed out and mismatched connections and
  retransmits per side, and the command exits with an error if any connection
  failed or carried other bytes, so it can gate a test.

A TCP profile holds all of this in a TOML file; see
[`examples/lab-tcp.toml`](examples/lab-tcp.toml):

```toml
pcap = "http.pcap"
cps = 20
connections = 200
concurrency = 50

[client]
ip = "192.168.10.100/24"
ips = 10
gateway = "192.168.10.1"
vlan = 10

[server]
ip = "192.168.20.50/24"
gateway = "192.168.20.1"
vlan = 20

[tcp]
rto = "250ms"
verify = true
```

Instead of `pcap`, a session can be written out as `[[message]]` tables
(`from = "client"`, `text = "..."` or `hex = "..."`, plus `port`). Over the
control API, `tcp.start` takes the same profile (`ferotrx ctl tcp-start
lab-tcp.toml --upload -i enp0s3`), and `tcp.stats` reports the counters.

To try it without a lab, `sudo scripts/tcp-nat-netns.sh` builds a router in
a Linux network namespace (VLANs 10 and 20 on a trunk, routing, connection
tracking, masquerading and a rule that drops packets conntrack finds invalid)
and runs the sample session `examples/http.pcap` through it (with its own addresses, so your edits to the lab profile do not matter). `LOSS=0.03` makes the router drop 3% of
what it forwards. Here it completed 20,000 connections at 2,000 per second, and
with 3% loss every connection still completed thanks to retransmits.

Limits of this release: IPv4 only; one session per run (several flows of a
capture, as templates chosen per connection, would be a next step); libpcap or
Npcap for sending and receiving (AF_XDP and DPDK are for stateless runs);
no TCP window scaling, SACK or timestamps, so each connection keeps at most
64 KB in flight; and the program is replayed by bytes and order, not by the
timing between messages.

## Library

```rust
use ferotrx_core::{replay, Capture, Rate, ReplayConfig};
use ferotrx_io::InterfaceSink;

let capture = Capture::from_path("capture.pcap")?;
let mut sink = InterfaceSink::open("eth0")?;
let config = ReplayConfig { rate: Rate::Pps(10_000.0), loops: 5, ..Default::default() };
let stats = replay(&capture, &mut sink, &config)?;
println!("{} packets at {:.0} pps", stats.packets, stats.pps());
```

Several streams with rewrites:

```rust
use ferotrx_core::{run, Capture, CaptureSource, Rate, Rewrite, RunConfig, Stream};

let capture = Capture::from_path("capture.pcap")?;
let mut streams = [
    Stream::new("vlan10", CaptureSource::new(&capture).loops(0))
        .with_rate(Rate::Pps(1000.0))
        .with_transform("vlan_push=10".parse::<Rewrite>()?),
    Stream::new("vlan20", CaptureSource::new(&capture).loops(0))
        .with_rate("50mbps".parse()?)
        .with_transform("vlan_push=20".parse::<Rewrite>()?),
];
let config = RunConfig { duration: Some(std::time::Duration::from_secs(30)), ..Default::default() };
let stats = run(&mut streams, &mut sink, &config)?;
```

The field engine in code:

```rust
use ferotrx_core::{FieldEngine, FieldVar, VarField, Side};

let engine = FieldEngine::parse(["ip_src=10.0.0.1..10.0.0.254", "port_src=1024..65535,random"])?;
let stream = Stream::new("many-clients", CaptureSource::new(&capture).loops(0)).with_transform(engine);

// Or without text:
let var = FieldVar::new(VarField::Port(Side::Dst), 5000, 5099)?;
let engine = FieldEngine::new([var]);
```

Building packets in code:

```rust
use ferotrx_packet::{Ethernet, Ipv4, PacketSpec, Udp, Vlan};

let frame = PacketSpec::new()
    .with(Ethernet { dst: [0x02, 0, 0, 0, 0, 0x01], ..Default::default() })
    .with(Vlan { id: 10, ..Default::default() })
    .with(Ipv4 { dst: "192.168.20.50".parse()?, ..Default::default() })
    .with(Udp { dport: Some(5000), ..Default::default() })
    .build()?;

// Or from text, straight into a capture that streams can play:
let capture = ferotrx_core::Capture::from_specs(&["eth/ipv4/udp/dns(q=example.com)"], Duration::from_millis(10))?;
```

Running in the background, as the CLI and the control server do:

```rust
use ferotrx_core::{Job, Profile, RunConfig};
use ferotrx_io::Output;

let profile = Profile::from_path("lab.toml")?;
let job = ferotrx_ctl::start_run(&profile, &Output::interface("eth0"), None, RunConfig::default())?;
std::thread::sleep(std::time::Duration::from_secs(5));
println!("{} packets so far", job.stats().total.packets);
job.stop();
let stats = job.join()?;
```

Sending through AF_XDP from code:

```rust
use ferotrx_core::{Backend, SendSettings, XdpMode};
use ferotrx_io::Output;

let output = Output::Interface {
    name: "enp0s3".into(),
    send: SendSettings { backend: Some(Backend::AfXdp), xdp_mode: Some(XdpMode::Copy), ..Default::default() },
};
let mut sink = output.open(ferotrx_core::LINKTYPE_ETHERNET)?;
```

Packets flow `PacketSource -> Transform... -> Pacer -> PacketSink`. Implement
`PacketSource` to generate packets, `Transform` to change them, and `PacketSink`
to send them anywhere else. `Profile::from_path(...)?.load()?` builds the streams
of a TOML profile.

Stateful TCP in code, here with the client and the server on two in-memory
ports (`ferotrx_io::open_port("eth0")` opens a real one):

```rust
use std::sync::Arc;
use ferotrx_core::*;

let program = TcpProgram::from_capture(&Capture::from_path("http.pcap")?, None)?;
let mut client = TcpClientConfig::new(
    TcpEndpoint::new(0, "02:00:00:00:00:01".parse()?, "10.0.0.1".parse()?),
    "10.0.0.2:80".parse()?,
);
client.cps = 100.0;
client.connections = 1000;
let server = TcpServerConfig {
    endpoint: TcpEndpoint::new(1, "02:00:00:00:00:02".parse()?, "10.0.0.2".parse()?),
    port: 80,
};
let engine = TcpEngine::new(TcpConfig {
    program: Arc::new(program),
    client: Some(client),
    server: Some(server),
    options: TcpOptions::default(),
})?;
let (a, b) = memory_ports();
let job = TcpJob::spawn(engine, vec![Box::new(a), Box::new(b)], TcpRunConfig::default())?;
let stats = job.join()?;
println!("{} connections completed", stats.client.completed);
```

`TcpEngine` does no I/O and reads no clock: it takes received frames and the
time, and returns frames to send, so it can also run on a simulated network
(see `crates/ferotrx-core/tests/tcp.rs`, which puts it behind a simulated
lossy NAT router).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
