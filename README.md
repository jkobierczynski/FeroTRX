# FeroTRX

FeroTRX is a traffic replay tool written in Rust, inspired by
[Cisco TRex](https://trex-tgn.cisco.com/). It replays pcap and pcapng captures
at a controlled rate on Linux, macOS and Windows, rewrites them on the way
(addresses, ports, VLAN tags), varies fields from packet to packet, builds packets from scratch, runs several streams
at once from a profile, shapes traffic over time (Poisson arrivals, bursts, ramps), replays TCP sessions statefully (real connections, both ends emulated, through NAT
routers and firewalls, many sessions at once from templates), plays stateful UDP
transactions (DNS lookups, NTP, replayed UDP sessions, with matching, timeouts and retries), measures loss and latency on the receive side, benchmarks devices the RFC 2544 way (throughput, latency, frame loss, back-to-back, with IMIX and other size mixes), runs regression scenarios (checks with expected outcomes, pass/fail for CI, comparing runs), checks profile files without sending, spreads one run over several cores, all over IPv4 and IPv6, and its engine is a library you can use from your own programs.

## Status

* **M1, pcap replay:** done.
* **M2, rewriting and multi-stream profiles:** done.
* **M3, packet inspection (`ferotrx-packet`, `ferotrx inspect`):** done.
* **M4, packet building (`ferotrx build`, built packets in profiles):** done.
* **M5, remote control (`ferotrx-ctl`, `ferotrx serve`, `ferotrx ctl`):** done.
* **M6, fast send backends (AF_XDP on Linux, DPDK as an option):** done.
* **M7, field engine (per-packet field ranges, `--vary`, `vary` in profiles):** done.
* **M8, stateful TCP (`ferotrx tcp`, TCP profiles, `tcp.*` control methods):** done.
* **M9, receive side: loss and latency per stream (`--rx`, `ferotrx rx`, `rx.*` control methods):** done (0.2.0).
* **M10, multi-flow TCP templates (`[[template]]` in TCP profiles, server address ranges, per-template counters):** done (0.3.0).
* **M11, IPv6 everywhere (stateful TCP with neighbor discovery, IPv6 extension headers and neighbor discovery in the packet builder, IPv6 lab scripts):** done (0.4.0).
* **M12, TCP maturity (window scaling, timestamps and PAWS, SACK, RTT-based timeouts, windows and timeouts in profiles, per-template rates):** done (0.5.0).
* **M13, secure remote control (TLS and mutual TLS, read-only and operator roles, data directories, limits, audit log, `ferotrx certs`):** done (0.6.0).
* **M14, benchmarking (`ferotrx bench`: RFC 2544 throughput, latency, frame loss and back-to-back; IMIX and size mixes; run metadata and text reports):** done (0.8.0).
* **M15, stateful UDP and transactions (`ferotrx udp`: DNS, NTP and UDP sessions with matching, timeouts and retries, per-template rates and think time; message timing for TCP):** done (0.8.0).
* **M16, scenario and regression tests (`ferotrx scenario`: checks with expected outcomes, JSON and JUnit reports, run history and comparisons):** done (0.9.0).
* **M17, traffic models and file checks (Poisson arrivals, bursts, ramps and rate shapes for streams, TCP connections and UDP transactions; `ferotrx check`; a `format` version in every file):** done (0.10.0).
* **M18, stateful TCP and UDP over AF_XDP and DPDK (an XDP program of its own for receiving, `-B` for `ferotrx tcp` and `ferotrx udp`, a timer queue in the engines):** done (0.11.0).
* **M19, host emulation (`ferotrx host`; DHCP, SLAAC and DHCPv6 addresses, gratuitous ARP and unsolicited neighbor advertisements, IGMP/MLD joins, router advertisements; `ip = "dhcp"` for TCP and UDP ends):** done (0.12.0).
* **M20, one run on several cores (`--workers`: streams split packet by packet, TCP and UDP runs by flow, one AF_XDP queue per worker):** done (ships in 0.14.0). See [docs/multi-core.md](docs/multi-core.md).
* **M21, Python client (`pip install ./python`: blocking and asyncio clients for the control server, typed results, TLS and tokens):** this release (0.14.0).

## Crates

| Crate | What it is |
| --- | --- |
| `ferotrx-core` | The core API: captures, rewrites, streams, profiles, pacing, the scheduler, the stateful TCP and UDP engines, loss and latency counting, and scenarios (checks, verdicts, reports, comparisons). No platform code. |
| `ferotrx-packet` | Packet decoding (layers, fields with byte ranges, checksum checks, summaries) and building. No dependencies. |
| `ferotrx-io` | Packet sinks: network interfaces through libpcap/Npcap, AF_XDP or DPDK; pcap files. Send-and-receive ports for stateful TCP and UDP, receivers for loss and latency. |
| `ferotrx-ctl` | Remote control: a JSON-RPC server and client to load profiles, start and stop runs, and read live counters; the runner that plays scenario checks on interfaces. |
| `ferotrx-cli` | The `ferotrx` command line tool. |
| `python/` (Python package `ferotrx`) | The Python client for the control server: blocking and asyncio, typed results, TLS and tokens. Not a crate; see [docs/python-client.md](docs/python-client.md). |

## Install

Every release on the [Releases page](https://github.com/jkobierczynski/FeroTRX/releases)
has ready-made packages:

* **Debian and Ubuntu (x86_64):** download `ferotrx_*_amd64.deb` and run
  `sudo apt install ./ferotrx_*_amd64.deb`.
* **Other Linux, macOS:** unpack the `.tar.gz` for your system and put `ferotrx` on your `PATH`
  (Linux needs libpcap: `libpcap0.8` on Debian, `libpcap` elsewhere).
* **Windows:** unpack the `.zip`; install [Npcap](https://npcap.com/) to send and receive.

The packages have the default backends (libpcap/Npcap, and AF_XDP on Linux).
For DPDK, build from source. How releases are made: [RELEASING.md](RELEASING.md).

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
sudo ferotrx replay capture.pcap -i eth0 --rx eth1 --pps 1000   # loss and latency, received on eth1
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
| `hbh`, `dstopt` | IPv6 hop-by-hop and destination options headers, after `ipv6`: `len` (8 bytes, a multiple of 8, filled with padding), `nh`; `hbh` also `ra` (router alert value) |
| `frag` | IPv6 fragment header, after `ipv6`: `offset` (bytes), `mf`, `id` (1), `nh` |
| `tcp` | `sport` (49152), `dport` (80), `seq`, `ack`, `flags` (S; any of FSRPAUEC, or a number), `win` (64240), `urg`, `mss`, `wscale`, `sackok`, `chksum` |
| `udp` | `sport`, `dport` (53 on the server side of DNS, else 49152 → 9), `len`, `chksum` |
| `icmp` | `type` (echo request), `code`, `id`, `seq`, `chksum`; ICMPv6 after `ipv6`, where `type=ns` and `type=na` (neighbor solicitation and advertisement) also take `target`, `lladdr` and, for `na`, `flags` (letters RSO); neighbor discovery wants `ipv6(hlim=255)` |
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

#### Traffic models: Poisson, bursts, ramps

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

[`examples/lab-models.toml`](examples/lab-models.toml) has examples, and
[docs/traffic-models.md](docs/traffic-models.md) the details.

#### Checking files

`ferotrx check FILE...` reads traffic, TCP, UDP and benchmark profiles and
scenarios as a run would (captures, built packets, engine setup) without
sending, prints a summary and warnings, and exits with 1 on errors (`--strict`:
on warnings too), which suits CI. Every file may say `format = 1`; a file
from a newer FeroTRX with a higher format is refused with a clear message.

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

Stateful TCP and UDP runs (`ferotrx tcp`, `ferotrx udp`) take the same
options and `[output]` table, and then receive through AF_XDP or DPDK too:
FeroTRX loads a small XDP program that hands frames for the emulated hosts'
MAC addresses to its AF_XDP sockets and leaves the rest to the kernel. That
roughly doubles to triples the connection rate one run reaches; see
[docs/fast-ports.md](docs/fast-ports.md).

```sh
sudo ferotrx tcp -p examples/lab-tcp.toml -i enp0s3 -B af_xdp --cps 5000 -n 50000
```

### Remote control

`ferotrx serve` runs a control server; other programs load profiles, start and
stop runs and read live counters over it. `ferotrx ctl` is its command line client.
Runs started remotely go through the same engine code as `ferotrx run`.

```sh
# On the traffic box (here the lab's Debian host): certificates once, then the
# server, reachable from the lab network over TLS.
ferotrx certs /etc/ferotrx/pki --server 192.168.56.10 --client alice --read-client dashboard
sudo ferotrx serve --listen 0.0.0.0:4510 --data-dir /srv/profiles \
     --tls-cert /etc/ferotrx/pki/server.pem --tls-key /etc/ferotrx/pki/server-key.pem \
     --client-ca /etc/ferotrx/pki/ca.pem --read-client-ca /etc/ferotrx/pki/read-ca.pem \
     -p examples/lab-two-vlans.toml

# From anywhere that can reach it, with ca.pem and alice's certificate and key copied over:
export FEROTRX_CTL=192.168.56.10 FEROTRX_CA=ca.pem FEROTRX_CERT=alice.pem FEROTRX_KEY=alice-key.pem
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
use it. From Python, use the `ferotrx` package in [`python/`](python)
([docs/python-client.md](docs/python-client.md)); from Rust, `ferotrx_ctl::Client`.
[`examples/ctl-client.py`](examples/ctl-client.py) shows the protocol in one
file of plain Python.

```python
import ferotrx  # pip install ./python

with ferotrx.Client("192.168.56.10", ca="ca.pem", cert="alice.pem", key="alice-key.pem") as c:
    c.load_profile("my-test.toml", upload=True)
    run = c.start("my-test", iface="enp0s3", duration="60s")
    for update in c.watch(run.id):
        print(f"{update.run.total.pps:.0f} pps")
```

| Method | Params | Result |
| --- | --- | --- |
| `server.info` | | name, version, protocol, interfaces, backends, auth_required, tls, and this connection's role and user |
| `auth` | `token` | `true`; the connection now has the token's role |
| `interfaces.list` | | `[{name, description}]` |
| `profile.load` | `path` (on the server) or `toml` (+ `base_dir`), optional `name` | the profile's streams |
| `profile.get`, `profile.unload` | `name` | profile / `true` |
| `profile.list` | | loaded profiles |
| `run.start` | `profile`, `output` (`{"iface": ..}`, `{"file": ..}` or `{"null": true}`; with `iface` also optional `backend`, `xdp_mode`, `queue`, `batch`, `dpdk_args`), optional `rate`, `limit`, `duration`, `ignore_errors`, `latency`, `rx` (`{"iface": .., "wait": "500ms"}`) | the run |
| `run.stop` | `id`, `wait` (default true) | the run, final counters |
| `run.stats`, `run.remove` | `id` | the run |
| `run.list` | | every run |
| `tcp.start` | a TCP profile as `path` (on the server) or `toml` (+ `base_dir`); optional `iface`, `cps`, `connections`, `concurrency`, `duration` | the TCP run |
| `tcp.stop` | `id`, `wait` (default true) | the TCP run, final counters |
| `tcp.stats`, `tcp.remove` | `id` | the TCP run |
| `tcp.list` | | every TCP run |
| `udp.start` | a UDP profile as `path` (on the server) or `toml` (+ `base_dir`); optional `iface`, `rate`, `transactions`, `concurrency`, `duration` | the UDP run |
| `udp.stop` | `id`, `wait` (default true) | the UDP run, final counters |
| `udp.stats`, `udp.remove` | `id` | the UDP run |
| `udp.list` | | every UDP run |
| `rx.start` | `iface`, optional `duration` | the receiver, its flows |
| `rx.stop` | `id`, `wait` (default true) | the receiver, final counters |
| `rx.stats`, `rx.remove` | `id` | the receiver |
| `rx.list` | | every receiver |
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
run ends. Error codes are the JSON-RPC ones plus -32001 (log in first),
-32002 (no such profile, run or subscription), -32003 (could not be done,
e.g. a profile that does not parse or an interface that will not open) and
-32004 (forbidden: a read-only login changing something, or a path outside
the data directories).

#### Security

**What is at stake.** The control server sends traffic from the machine's
interfaces, often as root (pcap, AF_XDP and DPDK need it), and reads profiles
and pcaps and writes pcap files with the server's privileges. Whoever can
call `run.start` can flood a network the box is attached to; whoever can
call `profile.load` with any path could read files. So the server keeps
everyone out who has not logged in, keeps read-only users from changing
anything, and keeps everyone inside its data directories.

**What it protects against:** someone on the lab or management network who
can reach the port but has no token or certificate (they get `server.info`
and nothing else; the server refuses to listen on such a network without a
login unless you say `--insecure`); someone who can watch or tamper with that
network (TLS, so tokens and traffic no longer go in clear text); a dashboard
or colleague who should only look (read-only role); a client naming
`/etc/shadow` or `../../` (data directories, symbolic links followed);
clients that hog the server (connection, request and upload limits, idle and
login timeouts, a pause and in the end a closed connection after wrong
tokens). Every login, refusal and change is in the audit log.

**What it does not protect against:** an operator, who by design can send
any traffic the profiles allow and write pcap files anywhere in the data
directories; anyone who has a token or key file (keep them private: `ferotrx
certs` writes keys readable only by their owner); local users of the box
(listen on 127.0.0.1, the default, when you do not need the network); and
denial of service by a client that is allowed in. The server checks paths
when a profile is loaded, so a file swapped for a symbolic link afterwards is
not caught. There is no rate limit per client and no certificate revocation:
to lock someone out, issue new CAs (or tokens) and restart.

**Logins and roles.** `read` may call `server.info`, `interfaces.list`, the
`*.get`, `*.list` and `*.stats` methods and `stats.subscribe`; `operator` may
also load and unload profiles and start, stop and remove runs. Log in with a
token (`auth`) or a client certificate:

| `ferotrx serve` option | Logs in as |
| --- | --- |
| `--token T` (or `FEROTRX_TOKEN`) | operator |
| `--read-token T` (or `FEROTRX_READ_TOKEN`) | read |
| `--tokens FILE`: `[[token]]` tables with `name`, `role` and `secret` (or `sha256` of it) | the token's role, under its name in the audit log |
| `--client-ca FILE` (needs TLS) | operator, for certificates from that CA |
| `--read-client-ca FILE` (needs TLS) | read, for certificates from that CA |

With client CAs and no tokens, a client without a certificate cannot connect;
with both, it can and logs in with a token. With none of these, every
connection may do everything, which is fine on 127.0.0.1.

**TLS.** `--tls-cert` and `--tls-key` (PEM) turn on TLS (rustls; TLS 1.2 and
1.3). `ferotrx certs DIR --server NAMES --client NAME --read-client NAME`
makes what a lab needs: a CA (`ca.pem`) that signs the server certificate (for
those names plus `localhost`, `127.0.0.1` and `::1`) and
operator client certificates, a second CA (`read-ca.pem`) for read-only
client certificates, and a certificate and key per name; run it again to add
clients, it reuses the CAs. Clients check the server against `--ca` (or
`FEROTRX_CA`), for the host in `--connect` (or `--server-name`); in Python,
`ferotrx.Client(host, ca="ca.pem", cert=..., key=...)` (see
[docs/python-client.md](docs/python-client.md)).
Certificates from your own PKI work as well: any PEM certificate and key.

**Files.** Profiles, the pcaps they name, `base_dir` and pcap outputs must be
inside the `--data-dir` directories (repeatable; default: the directory the
server was started in); relative paths start from the first one. Uploaded
profiles may be at most `--max-upload` (1M); a request at most
`--max-request` (4M). Profiles given with `-p` at start are not checked.

**Limits.** `--max-connections` (64), `--idle-timeout` (5m; connections
watching stats are never idle), 30 s to log in, half a second after each
wrong token and the connection closed after five.

**Audit log.** JSON lines on standard error, or appended to `--audit-log
FILE`: `connect`, `refused`, `tls_error`, `login` (by token or certificate,
with the certificate's SHA-256), `login_failed`, `denied`, `call` (every
operator method with its parameters, uploaded profiles by size, and whether
it worked) and `disconnect` (with the reason). Tokens are never written.

```json
{"by":"certificate","cert_sha256":"f265cc3d…","conn":3,"event":"login","peer":"192.168.56.1:43846","role":"operator","time":"2026-11-03T18:13:04.415Z","user":"alice"}
{"conn":3,"event":"call","id":1,"method":"run.start","ok":true,"params":{"output":{"iface":"enp0s3"},"profile":"lab"},"peer":"192.168.56.1:43846","role":"operator","time":"2026-11-03T18:13:04.416Z","user":"alice"}
```

**Deploying.** Put the control port on a management network or VLAN, not the
network under test. Use TLS with client certificates for people and scripts
that start traffic, a read-only certificate or token for dashboards, and give
each person or system their own so the audit log tells them apart. Keep
profiles and pcaps in a directory of their own and make it the only
`--data-dir`. Under systemd, send standard error (and so the audit log) to the
journal, or give `--audit-log` a file on a disk that is backed up. Leave the
server on 127.0.0.1 (the default) when only local scripts use it.

### Loss and latency

Mark a stream with `latency`, or give `--rx`, and every packet it sends
carries a 28-byte signature at the end of its IP payload: a flow id, a
sequence number and the time it left. A receiver on the far side counts what
arrives per flow, like TRex's latency streams and flow statistics: packets
lost, duplicated and reordered, and latency (min, average, p50, p99, p99.9,
max and RFC 3550 jitter). Lengths and checksums are fixed when the signature
is added, and the signature is written so that the checksums stay right when
the sequence number and time are filled in at the last moment, so the packets
pass routers, NAT and firewalls like any other UDP, TCP or ICMP packet.

```sh
# Send on one interface and receive on another (or the same one, when the
# router sends the packets back on it); the table comes at the end.
sudo ferotrx run examples/lab-latency.toml -i enp0s3 --rx enp0s8 -d 60s
sudo ferotrx replay capture.pcap -i enp0s3 --rx enp0s8 --pps 1000 -l 0 -d 30s
sudo ferotrx build 'eth(dst=02:00:00:00:01:01)/ipv4(dst=192.168.20.50)/udp(dport=7)/raw(len=64)' \
     -i enp0s3 --rx enp0s8 --pps 1000 -l 0 -d 30s --report report.json

# Receiver on another machine: there, then here with signatures and no --rx.
sudo ferotrx rx -i enp0s3 -d 70s
sudo ferotrx run examples/lab-latency.toml -i enp0s3 -d 60s --latency
# Or capture on the receiver with tcpdump and read it afterwards:
ferotrx rx --file receiver.pcap
```

A run through the namespace router of `scripts/latency-netns.sh` (routing and
masquerading, with 3% loss), two streams with signatures and one without:

```text
loss and latency:
  name    flow         tx         rx      lost     loss    dup    ooo       min       avg       p99       max    jitter
  voice      1       4001       3887       114   2.849%      0      0     1.3us     5.5us    19.5us    62.0us     0.4us
  bulk       7       8000       7747       253   3.163%      0      0     0.9us     5.8us    34.8us   931.0us     2.1us
  received 12414 frames, 780 without a signature
```

How it works and what to know:

* **Which streams.** In a profile, `latency = true` gives a stream its number
  (1 for the first) as flow id, `latency = 7` sets it. With `--rx`, a
  profile that marks no stream gets signatures in all of them; `--latency`
  marks every stream. `replay` and `build` send one stream, flow 1.
* **Loss.** With `--rx`, loss is what the stream sent minus what arrived;
  the receiver keeps going for `--rx-wait` (500 ms) after the last packet for
  those still on their way. On a receiver alone (`ferotrx rx`), it is the gaps
  in the sequence numbers between the first and the highest seen.
  Duplicates are told from late packets over a window of 4096 sequence numbers.
* **Latency** is the receive time, taken by the kernel (libpcap's
  timestamps, microseconds), minus the send time written just before the
  packet is handed to the sender. On one machine both come from the same
  clock. Across machines their clocks must agree (NTP gets them within about
  a millisecond, PTP far closer); packets that seem to arrive before they left
  are counted and reported as a clock problem. Percentiles are kept to within
  12.5%.
* **Size.** Each packet grows by 28 bytes, so packets already at the MTU no
  longer fit; IP fragments get no signature. Frames that are not IP get the
  signature at their end.
* **Receiving.** The receiver opens the interface in promiscuous mode through
  libpcap or Npcap, so the destination needs no listener and its own stack
  ignores the packets; frames this machine sends on the same interface are
  left out. `--report FILE` writes the table as JSON for scripts.
* **Remote control.** `ferotrx ctl start lab -i enp0s3 --rx enp0s8` reports
  loss and latency per stream in `run.stats` and the `stats` notifications,
  and `ferotrx ctl rx-start enp0s3` runs a receiver alone (`rx.*` methods).

`sudo scripts/latency-netns.sh` builds a router in a Linux network namespace,
with masquerading, a delay (`DELAY=5ms` by default, with the kernel's netem)
and loss (`LOSS=0.02`), runs a profile with two latency streams and one
plain one through it, and checks the report against what the router was told
to do. CI runs it with and without loss.

### Benchmarking

`ferotrx bench` measures a device between two interfaces the RFC 2544 way:
**throughput** (the highest rate without loss, by a binary search on the
rate), **latency** at that rate, **frame loss** from line rate down, and
**back-to-back** (the longest burst at line rate without loss), for each frame
size of a list and for size mixes such as IMIX. Trials, warm-up,
repetitions, the loss threshold and the stop conditions come from a
benchmark profile; every trial is reported with the rate offered next to the
rate achieved, and the report starts with what it ran on (FeroTRX version,
kernel, CPU, sender, interface drivers and NICs, the profile).

```sh
sudo ferotrx bench examples/bench-rfc2544.toml -i eth1 --rx eth2 --report bench.json
# Writes bench.json and bench.txt. Override the profile from the command line:
sudo ferotrx bench examples/bench-rfc2544.toml -i eth1 --rx eth2 \
     --tests throughput,latency --size 508 --size imix --trial-duration 60s
```

```toml
[benchmark]
packet = "eth(src=02:00:00:00:01:02,dst=02:00:00:00:01:01)/ipv4(src=10.9.1.2,dst=10.9.2.2)/udp(sport=4000,dport=9000)"
vary = ["port_src=4000..4255"]
tests = ["throughput", "latency", "frame_loss", "back_to_back"]
sizes = ["rfc2544", "imix"]    # sizes without FCS: 60, 124, ... 1514, and a mix
line_rate = "1gbps"
trial_duration = "10s"
warmup = "2s"
repetitions = 1
loss_threshold = 0.0           # percent
```

Through the namespace router of `scripts/bench-netns.sh`, which forwards
20 Mbit/s (a token bucket) with a 25 ms queue, on a 100 Mbit/s line rate:

```text
Throughput (highest load losing at most 0%, searched to 1%):
  size   frame   load %     frames/s     Mbit/s  L1 Mbit/s  note
  1020    1020    20.39         2442      19.93      20.40
  imix   363.7    21.17         6828      19.87      21.18

Frame loss:
  size   load %    offered/s         sent     received   loss %
  1020   100.00        11973        11974         2480   79.288
  1020    80.00         9579         9579         2506   73.839
  ...
Back-to-back (longest burst without loss):
  size   load %     frames      burst  note
  1020   100.00         78     6.51ms
  imix   100.00        312     9.68ms
```

Sizes are frame lengths without the 4-byte FCS (RFC 2544's 64 to 1518 bytes
are 60 to 1514 here); loads are percent of the line rate counting 24 bytes of
FCS, preamble and gap per frame. Each frame carries the 28-byte signature
in place of the end of its payload, so it keeps its size (a 60-byte UDP/IPv4
frame has no room and goes out as 70). `imix` (60:7, 590:4, 1514:1) and other
mixes also work in traffic profiles (`sizes = "imix"`) and on `replay` and
`build` (`--sizes imix`). How it measures, and the limits of the method
(software timestamps, clocks, the sender's and the receiver's speed), are in
[docs/benchmarking.md](docs/benchmarking.md). `sudo scripts/bench-netns.sh`
runs the lab above and checks the results; CI runs it.

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
client: 192.168.10.100/24 mac 02:00:c0:a8:0a:64 on c0 (10 addresses, to 192.168.10.109), gateway 192.168.10.1
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
  or the last four bytes of its IPv6 address, or `--client-mac`), an optional
  VLAN tag and a gateway. It answers ARP and ping, or over IPv6 neighbor
  solicitations and ICMPv6 ping, so the router can reach it, and the interface
  is opened in promiscuous mode. Use addresses that are free in each subnet, not addresses of the machine
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
* **Servers.** `--server-ips 4` gives the server four consecutive addresses,
  and the clients connect to each in turn (`--connect-ips` when the server
  runs elsewhere).
* **Checks.** Each end compares every byte it receives with the capture.
  The summary counts completed, reset, timed out and mismatched connections and
  retransmits per side, and the command exits with an error if any connection
  failed or carried other bytes, so it can gate a test.

* **IPv6.** Give IPv6 addresses (`--client-ip fd00:10::100/64 --client-gw
  fd00:10::1`, `--connect '[fd00:20::50]:80'`; the prefix defaults to /64) and
  the hosts find their next hop with neighbor discovery instead of ARP. Client,
  gateway and servers must all be of one IP version. The MSS is 20 bytes less
  than over IPv4 (1440 by default), so frames stay as long. Captures of IPv6
  sessions work as well as IPv4 ones, and either plays over either. See
  [`examples/lab-tcp-v6.toml`](examples/lab-tcp-v6.toml).
* **TCP behavior.** Both ends negotiate window scaling, timestamps (with
  PAWS) and SACK, so a connection can keep megabytes in flight on a long path
  and recover from several losses per round trip without a timeout. The
  retransmission timeout follows the measured round-trip time. Congestion
  control is Reno/NewReno with SACK-based recovery; see
  [docs/tcp-engine.md](docs/tcp-engine.md) for what the engine does and does
  not do. `--send-window` and `--receive-window` (e.g. `4M`, the default),
  `--rto`, `--min-rto`, `--syn-retries`, `--max-retries`, `--idle-timeout`,
  and `--no-window-scaling`, `--no-timestamps`, `--no-sack` change it; the
  summary shows timeouts and the most bytes a connection had in flight.

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

[tcp]                       # optional; the defaults
rto = "250ms"               # until the round-trip time is measured
min_rto = "200ms"
syn_retries = 6
max_retries = 8
idle_timeout = "30s"
send_window = "4M"          # most bytes in flight per connection
receive_window = "4M"
window_scaling = true
timestamps = true
sack = true
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
`IPV6=1` builds the same lab over IPv6 (fd00:10::/64 and fd00:20::/64, with
neighbor discovery between the router and the emulated hosts, and IPv6
masquerading where the kernel has it); `MIX=1` and `NO_VLAN=1` combine with
it. `NETEM="delay 5ms reorder 10% 50% duplicate 2% loss 2%"` has the router
impair what it forwards with netem, and `BDP=1` plays a 2 MB download over a
50 Mbit/s path with an 80 ms round trip and checks that more than 64 KB were
in flight. `IPV6=1 scripts/latency-netns.sh` measures loss and latency over IPv6, with
the bulk stream varying its IPv6 source address.

#### Templates: many kinds of connections at once

Like TRex ASTF templates, a TCP profile can mix several sessions in one run:
give `[[template]]` tables instead of a top-level `pcap` or `[[message]]`.
Each new connection gets a template by `weight` (a smooth weighted round
robin, so a 3:1:1 mix holds over every five connections, not only on
average). `cps`, `connections` and `concurrency` count all templates
together. A template can have its own `cps`: it then opens connections at
that rate on its own, besides the shared rate. Its own `connections` and
`concurrency` limit it further, within the run-wide ones; when every template
has used up its own `connections`, the run ends. The server tells templates apart by the port the SYN arrives on, so
each template has its own `port` (default: the capture's). See
[`examples/lab-tcp-mix.toml`](examples/lab-tcp-mix.toml):

```toml
cps = 100
connections = 2000
concurrency = 200

[[template]]
name = "http"
pcap = "http.pcap"
weight = 3

[[template]]
name = "download"
pcap = "web.pcap"
flow = 1
port = 8080          # the capture's port 80 is taken by "http"

[[template]]
name = "echo"
port = 7
[[template.message]]
from = "client"
text = "hello\r\n"
[[template.message]]
from = "server"
text = "hello\r\n"

[client]
ip = "192.168.10.100/24"
ips = 100            # 100 client addresses, used in turn
gateway = "192.168.10.1"

[server]
ip = "192.168.20.50/24"
ips = 4              # 4 servers; each template connects to each in turn
gateway = "192.168.20.1"
```

A template can also say where its clients connect (`connect = "IP:PORT"`,
for a port forward) and to how many servers (`connect_ips`); `weight = 0`
makes a template the server accepts but the client never opens, for when
the client runs on another machine. The summary, `tcp.stats` (`templates`)
and `ferotrx ctl tcp-stats` show each template's counters under the totals:

```text
done in 9.981 s: 7015 frames (2718100 bytes) sent, 7015 (2697830 bytes) received
  client: 500 connections, 500 established, 500 completed; 53800 bytes sent, 2261400 received, 0 retransmits
  server: 500 connections, 500 established, 500 completed; 2261400 bytes sent, 53800 received, 0 retransmits
    http client: 300 connections, 300 established, 300 completed; 43200 bytes sent, 1859400 received, 0 retransmits
    http server: 300 connections, 300 established, 300 completed; 1859400 bytes sent, 43200 received, 0 retransmits
    download client: 100 connections, 100 established, 100 completed; 8600 bytes sent, 400000 received, 0 retransmits
    download server: 100 connections, 100 established, 100 completed; 400000 bytes sent, 8600 received, 0 retransmits
    echo client: 100 connections, 100 established, 100 completed; 2000 bytes sent, 2000 received, 0 retransmits
    echo server: 100 connections, 100 established, 100 completed; 2000 bytes sent, 2000 received, 0 retransmits
  50.1 connections per second
```

`sudo MIX=1 scripts/tcp-nat-netns.sh` runs such a mix (the HTTP session, a
download on port 8080 and an echo, 3:1:1, from ten clients to four servers)
through the namespace router and checks that every template completed
connections on both sides and that the router reached all four servers. CI
runs it on the VLAN trunk, and on two links with 3% loss.

* **Message timing.** By default each end answers as soon as the other
  end's message is in. `--keep-timing` (`[tcp] keep_timing`) waits the gaps
  the capture shows between messages, and `--think-time 50ms` adds a pause
  before every answer; `--show` lists the gaps.

Sending and receiving goes through libpcap or Npcap by default; `-B af_xdp`
or `-B dpdk` uses the fast ports for higher connection rates (see
[docs/fast-ports.md](docs/fast-ports.md)). More on the engine in
[docs/tcp-engine.md](docs/tcp-engine.md).

### Stateful UDP and DNS

`ferotrx udp` does for request/response protocols over UDP what `ferotrx tcp`
does for TCP: FeroTRX emulates the clients and the servers, the clients start
transactions at a set rate, each from its own source address and port, wait
for the answers and ask again when they are late, and every answer is matched
to its request. Three kinds of transactions:

* **DNS** (`--app dns`): the client sends queries in turn, each with its own
  transaction id, and the server answers from its records: A, AAAA, CNAME,
  MX, TXT, SRV, NS, PTR, error codes for chosen names, NXDOMAIN for the rest.
  Answers are matched by id and question, and a query can expect a response
  code. The queries and records can come from a capture of real lookups.
* **NTP** (`--app ntp`): client requests and stratum 2 replies, matched by
  timestamp.
* **Replay**: a UDP session from a capture (or written out), datagram for
  datagram, checked byte for byte.

```sh
ferotrx udp --list capture.pcap                          # the UDP sessions in a capture
ferotrx udp examples/dns-lookups.pcap --app dns --show   # its queries and records
sudo ferotrx udp -p examples/lab-dns.toml -i enp0s3      # the lab profile
sudo ferotrx udp -i enp0s3 --query "www.lab.local AAAA" --query "nope.lab.local A NXDOMAIN" \
     --record "www.lab.local AAAA fd00:20::80" \
     --client-ip 192.168.10.100/24 --client-gw 192.168.10.1 --client-vlan 10 \
     --server-ip 192.168.20.53/24 --server-gw 192.168.20.1 --server-vlan 20 \
     --rate 500 -n 10000 --timeout 300ms --retries 3
# Only the client, against a real DNS server:
sudo ferotrx udp -p examples/lab-dns.toml -i enp0s3 --connect 192.168.20.2
```

A run through the namespace router of `scripts/udp-netns.sh`, with 5% loss:

```text
done in 3.011 s: 1258 frames (114602 bytes) sent, 1200 (112030 bytes) received
  client: 600 transactions, 600 answered, 170 with error answers, 58 sent again; 658 datagrams (20810 bytes) sent, 600 (42845 bytes) received; response time ms min 0.07 avg 29.21 p50 0.16 p99 285.21 max 903.01
  server: 600 transactions, 600 answered; 600 datagrams (42845 bytes) sent, 600 (19023 bytes) received
  199.3 transactions per second
```

The counters per side (and per template) are transactions `sent`,
`answered`, `timed out`, `with error answers` (DNS response codes other than
NOERROR, expected or not), `with other answers than expected`, unmatched
datagrams (late answers, wrong ids, closed ports), requests sent again, and
response times. The command exits with an error if any transaction timed out
or got another answer than expected. Hosts, `--connect`, `--server-ips`,
`--source-ports` and `--concurrency` work as for TCP; `--timeout`,
`--retries`, `--session-timeout`, `--think-time` and `--keep-timing` are
UDP's own. [docs/udp-engine.md](docs/udp-engine.md) has the details.

A UDP profile ([`examples/lab-dns.toml`](examples/lab-dns.toml)):

```toml
queries = ["www.lab.local A", "lab.local MX", "missing.lab.local A NXDOMAIN"]
records = [
  "www.lab.local 300 CNAME web.lab.local",
  "web.lab.local 300 A 192.168.20.80",
  "lab.local MX 10 mail.lab.local",
  "broken.lab.local SERVFAIL",
]
rate = 100
transactions = 1000
concurrency = 100

[client]
ip = "192.168.10.100/24"
ips = 10
gateway = "192.168.10.1"
vlan = 10

[server]
ip = "192.168.20.53/24"
gateway = "192.168.20.1"
vlan = 20

[udp]                       # optional; the defaults
timeout = "1s"              # then ask again
retries = 2
session_timeout = "5s"      # the server forgets a quiet session
keep_timing = false
think_time = "0s"
verify = true
```

`[[template]]` tables mix kinds of transactions by weight, each with its own
`port` and optionally its own `rate`, `transactions`, `concurrency` and
`think_time` ([`examples/lab-udp-mix.toml`](examples/lab-udp-mix.toml): DNS
from a capture, NTP at its own rate, and a two-round echo with capture
timing). `udp.start` takes the same profile over the control API (`ferotrx
ctl udp-start lab-dns.toml --upload -i enp0s3`), and `udp.stats` reports the
counters with response times.

`sudo scripts/udp-netns.sh` plays 600 lookups through the namespace router,
then runs the DNS server alone and asks it with `dig` (A, AAAA, MX, NXDOMAIN,
SERVFAIL); `LOSS=0.03`, `MIX=1`, `IPV6=1` and `NO_VLAN=1` work as for the TCP
script. CI runs all of them.

### Host emulation

Emulated hosts can get their addresses the way real ones do, announce them
and join multicast groups. `ferotrx host` runs hosts on their own; in
`ferotrx tcp` and `ferotrx udp` the client or server can do the same before
the run starts.

```sh
# 20 DHCP clients on VLAN 10 that join 239.1.2.3, for a minute
sudo ferotrx host -i enp0s3 --vlan 10 -n 20 --ipv4 dhcp --join 239.1.2.3 -d 1m
# 50 dual-stack hosts (DHCP and SLAAC), a static host, an IPv6 router
sudo ferotrx host examples/lab-hosts.toml -i enp0s3
# advertise fd00:99::/64 as a router, for devices that autoconfigure
sudo ferotrx host -i enp0s3 --ra fd00:99::/64 --ra-interval 5s
# a TCP client that gets its address (and gateway) by DHCP first
sudo ferotrx tcp -p examples/lab-tcp-dhcp.toml -i enp0s3
sudo ferotrx tcp examples/http.pcap --client-ip slaac --server-ip fd00:20::50/64 -i enp0s3 ...
```

```text
host 02:dc:00:00:01:01 ready after 0.01 s: ipv4 10.77.0.174/24 via 10.77.0.1 (dhcp from 10.77.0.1, lease 120 s); group 239.1.2.3 (1 reports, 0 frames received)
```

* **DHCPv4**: discover/offer/request/ack with the client id and host name,
  renewal at T1 (unicast) and rebinding at T2, release at the end.
* **SLAAC**: router solicitation, the advertised /64 plus the EUI-64,
  duplicate address detection, the router as gateway.
* **DHCPv6**: solicit/advertise/request/reply for one address, renew,
  rebind, release; the gateway from router advertisements.
* **Announcements**: gratuitous ARP, unsolicited neighbor advertisements.
* **Multicast**: IGMPv1-3 and MLDv1-2 reports when joining, answers to
  queries (falling back to an older querier's version), leaves at the end,
  received frames counted per group; IPv6 hosts also report their
  solicited-node groups.
* **Routers**: a host with `--ra` (a `[host.router]` table) sends router
  advertisements with prefixes and flags and answers solicitations.

In TCP and UDP profiles, `ip = "dhcp"` (or `"slaac"`, `"dhcpv6"`) with
`hostname`, `announce` and `groups` in `[client]` or `[server]`, and a
`[hosts]` table for the settings; on the command line `--client-ip dhcp`,
`--client-join GROUP`, `--announce`. The summary and `tcp.stats`/`udp.stats`
show each host's lease. [docs/host-emulation.md](docs/host-emulation.md) has
the details; `sudo scripts/hosts-netns.sh` (and `IPV6=1`) checks it against
dnsmasq and a bridge with IGMP/MLD snooping, in CI too.

### Regression scenarios

Did the firewall change break anything? A scenario file lists checks, each a
TCP, UDP or traffic run FeroTRX already knows (a profile file, or the
profile's tables inline) with an expected outcome: the sessions complete,
or they are blocked, plus conditions on what was measured.

```toml
name = "nat-router"
attempts = 2                       # run a failing check once more (jittery VMs)

[vars]                             # ${NAME} below and in the profiles; --set NAME=VALUE
server_net = "192.168.20"

[[check]]
name = "web through NAT"
tcp = "lab-tcp.toml"               # every connection completes, byte for byte
require = ["cps > 10", "timed_out == 0"]

[[check]]
name = "port 8080 blocked"
expect = "blocked"                 # no handshake completes
duration = "3s"
[check.tcp]
port = 8080
# ... [[check.tcp.message]], [check.tcp.client], [check.tcp.server]

[[check]]
name = "voice stream"
iface = "c0"                       # sent here, received on rx, with signatures
rx = "s0"
duration = "3s"
require = ["loss_pct < 2%", "latency_avg < 50ms", "rx_mbps > 1Mbit/s"]
traffic = "lab-latency.toml"
```

```sh
ferotrx scenario show examples/scenario-nat.toml         # the checks and their conditions
sudo ferotrx scenario run examples/scenario-nat.toml --history runs/ --junit nat.xml
# ... change the router ...
sudo ferotrx scenario run examples/scenario-nat.toml --history runs/ --baseline last
ferotrx scenario compare --history runs/
```

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

Each check ends as pass, fail, or error (the run could not be made), and
the command exits with 1 unless all pass. `--report` writes JSON,
`--junit` JUnit XML for CI test results, `--history DIR` keeps every run,
and `ferotrx scenario compare` matches two runs check by check: regressed,
fixed, and metrics that moved by more than `--tolerance` (`--strict` counts
those as regressions too). Conditions test metrics such as `completed_pct`,
`retransmits`, `answered_pct`, `response_p99`, `loss_pct`, `latency_p99`,
`jitter`, `rx_mbps` (`ferotrx scenario metrics` lists them all), with units:
`1%`, `20ms`, `500us`, `50Mbit/s`, `100/s`.
[docs/scenarios.md](docs/scenarios.md) has the whole format.

`sudo scripts/scenario-netns.sh` runs [`examples/scenario-nat.toml`](examples/scenario-nat.toml)
against the namespace router, breaks the router and checks that the second
run catches it. CI runs it and keeps the reports.

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

Loss and latency in code: a stream with a signature, sent through a sink
and counted by a receiver on the far side (here the two ends of an in-memory
link; `ferotrx_io::open_receiver("eth1")` opens a real interface):

```rust
use ferotrx_core::*;

let (tx, rx) = memory_ports();
let streams = vec![Stream::new("probe", CaptureSource::new(capture).loops(0))
    .with_rate(Rate::Pps(1000.0))
    .with_latency(1)];
let config = RunConfig { duration: Some(std::time::Duration::from_secs(10)), ..Default::default() };
let job = Job::spawn_with_rx(streams, Box::new(tx), config, Some(RxSettings::new(Box::new(PortReceiver(rx)))))?;
job.wait(None);
for r in job.flow_reports() {
    println!("{}: {} sent, {} lost, p99 {:?}", r.stream, r.tx, r.lost, r.latency.percentile(0.99));
}
```

`RxStats::record(frame, receive_time)` does the counting for frames from
anywhere, and `Signature::find(frame)` reads a signature.

A benchmark in code: `run_benchmark` decides the trials, a `TrialRunner`
runs them. `JobTrialRunner` sends with a `Job` on any sink and counts with
any receiver; a simulated device works too:

```rust
use ferotrx_core::*;

let config = BenchConfig {
    tests: vec![BenchTest::Throughput, BenchTest::BackToBack],
    sizes: vec!["508".parse()?, "imix".parse()?],
    line_rate_mbps: 1000.0,
    ..Default::default()
};
let mut runner = JobTrialRunner::new(capture, open_sink, open_receiver);
let report = run_benchmark(&config, &mut runner, |size, trial| {
    println!("{} {}: {:.2}% lost {}", size.size, trial.test, trial.load_pct, trial.lost)
})?;
println!("{}", report.text());
```

Stateful TCP in code, here with the client and the server on two in-memory
ports (`ferotrx_io::open_port("eth0")` opens a real one):

```rust
use std::sync::Arc;
use ferotrx_core::*;

let program = TcpProgram::from_capture(&Capture::from_path("http.pcap")?, None)?;
let mut client = TcpClientConfig::new(
    TcpEndpoint::new(0, "02:00:00:00:00:01".parse()?, "10.0.0.1".parse()?),
);
client.cps = 100.0;
client.connections = 1000;
let server = TcpServerConfig::new(
    TcpEndpoint::new(1, "02:00:00:00:00:02".parse()?, "10.0.0.2".parse()?).with_ip_count(4),
);
// One template; add more, each with its own port, and weights to mix them.
let web = TcpTemplate::new(Arc::new(program), "10.0.0.2:80".parse()?)
    .with_name("web")
    .with_connect_ips(4);
let engine = TcpEngine::new(TcpConfig {
    templates: vec![web],
    client: Some(client),
    server: Some(server),
    options: TcpOptions::default(),
})?;
let (a, b) = memory_ports();
let job = TcpJob::spawn(engine, vec![Box::new(a), Box::new(b)], TcpRunConfig::default())?;
let stats = job.join()?;
println!("{} connections completed", stats.client.completed);
for t in &stats.templates {
    println!("  {}: {}", t.name, t.client.completed);
}
```

`TcpEngine` does no I/O and reads no clock: it takes received frames and the
time, and returns frames to send, so it can also run on a simulated network
(see `crates/ferotrx-core/tests/tcp.rs`, which puts it behind a simulated
lossy NAT router).

Stateful UDP the same way, here DNS:

```rust
let dns = DnsWorkload::parse(&["www.lab.local AAAA"], &["www.lab.local AAAA fd00::80"])?;
let mut client = UdpClientConfig::new(
    UdpEndpoint::new(0, "02:00:00:00:00:01".parse()?, "10.0.0.1".parse()?),
);
client.rate = 1000.0;
client.transactions = 10_000;
let engine = UdpEngine::new(UdpConfig {
    templates: vec![UdpTemplate::new(UdpApp::Dns(Arc::new(dns)), "10.0.0.2:53".parse()?)],
    client: Some(client),
    server: Some(UdpServerConfig::new(
        UdpEndpoint::new(1, "02:00:00:00:00:02".parse()?, "10.0.0.2".parse()?),
    )),
    options: UdpOptions::default(),
})?;
let (a, b) = memory_ports();
let stats = UdpJob::spawn(engine, vec![Box::new(a), Box::new(b)], TcpRunConfig::default())?.join()?;
println!("{} answered, p99 {:?}", stats.client.answered, stats.client.response_time.percentile(0.99));
```

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
