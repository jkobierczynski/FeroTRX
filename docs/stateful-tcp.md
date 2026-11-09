# Stateful TCP

How to use `ferotrx tcp`. What the engine does on the wire is in
[tcp-engine.md](tcp-engine.md).

## Why stateful

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

## How it works

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
  failed or carried other bytes, so it can gate a test. When the first line
  ends with `N dropped here before they were read`, the capture on this
  machine overflowed (libpcap's buffer, 32 MB per port): those frames reached
  the interface and the retransmits that follow are not network loss. A
  faster backend (`-B af_xdp`) or fewer connections at once avoids it.

* **IPv6.** Give IPv6 addresses (`--client-ip fd00:10::100/64 --client-gw
  fd00:10::1`, `--connect '[fd00:20::50]:80'`; the prefix defaults to /64) and
  the hosts find their next hop with neighbor discovery instead of ARP. Client,
  gateway and servers must all be of one IP version. The MSS is 20 bytes less
  than over IPv4 (1440 by default), so frames stay as long. Captures of IPv6
  sessions work as well as IPv4 ones, and either plays over either. See
  [`examples/lab-tcp-v6.toml`](../examples/lab-tcp-v6.toml).
* **TCP behavior.** Both ends negotiate window scaling, timestamps (with
  PAWS) and SACK, so a connection can keep megabytes in flight on a long path
  and recover from several losses per round trip without a timeout. The
  retransmission timeout follows the measured round-trip time. Congestion
  control is NewReno or CUBIC (`--congestion cubic`, with HyStart++) with
  SACK-based recovery, and `--ecn` turns on ECN; see
  [docs/tcp-engine.md](tcp-engine.md) for what the engine does and does
  not do. `--send-window` and `--receive-window` (e.g. `4M`, the default),
  `--rto`, `--min-rto`, `--syn-retries`, `--max-retries`, `--idle-timeout`,
  and `--no-window-scaling`, `--no-timestamps`, `--no-sack` change it; the
  summary shows timeouts and the most bytes a connection had in flight.

## TCP profiles

A TCP profile holds all of this in a TOML file; see
[`examples/lab-tcp.toml`](../examples/lab-tcp.toml):

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
congestion = "newreno"      # or "cubic"; a [[template]] can have its own
ecn = false                 # ask for ECN (RFC 3168)
verify = true
```

Instead of `pcap`, a session can be written out as `[[message]]` tables
(`from = "client"`, `text = "..."` or `hex = "..."`, plus `port`). Or both
ends can speak an [application protocol](app-protocols.md) instead of
replaying fixed bytes: `app = "http"` with an `[http]` table of requests and
routes, `app = "https"` for the same over TLS, `app = "h2"` or `"h2c"` for
HTTP/2 with an `[http2]` table, `app = "mqtt"`, or `app = "dns"` for DNS
over TCP. Over the
control API, `tcp.start` takes the same profile (`ferotrx ctl tcp-start
lab-tcp.toml --upload -i enp0s3`), and `tcp.stats` reports the counters.

## Inside GTP-U tunnels

In a mobile network the user plane runs inside GTP-U between the base
stations and the user plane function (UPF). TRex runs its stateful traffic
that way, and so can FeroTRX: `[gtpu]` puts the client, the server or both
into tunnels, with a TEID of its own for each client address. It works the
same for `ferotrx tcp`, `ferotrx udp` and every application protocol.

```toml
[client]
ip = "172.16.0.100/24"       # the phones' (inner) addresses
ips = 10
gateway = "172.16.0.1"

[server]
ip = "172.16.1.50/24"
gateway = "172.16.1.1"

[gtpu]
# The base station's end: outer addresses, the first client's TEID, a QoS flow
client = "local=10.9.1.2,remote=10.9.2.2,gateway=10.9.1.1,teid=1000,qfi=9"
# The UPF's end (leave it out to send to a real UPF)
server = "local=10.9.2.2,remote=10.9.1.2,gateway=10.9.2.1,teid=1000,qfi=9"
```

[`examples/lab-gtpu.toml`](../examples/lab-gtpu.toml) runs this through the lab
router.

On the command line: `--client-gtpu SPEC` and `--server-gtpu SPEC`
(`none` turns a profile's off). Each spec is
`local=IP,remote=IP[,gateway=IP][,teid=N][,qfi=N][,vlan=ID][,mac=MAC][,mtu=N]`:

| Key | Meaning |
| --- | --- |
| `local`, `remote` | The tunnel's outer addresses, IPv4 or IPv6 (inner and outer versions can differ) |
| `gateway` | The outer next hop, found by ARP or neighbor discovery; default `remote` |
| `teid` | The first client's TEID (default 1); client N (counting from 0) uses `teid + N` both ways |
| `qfi` | Adds a PDU session container with this QoS flow ID (uplink from the client's end, downlink from the server's) |
| `vlan`, `mac` | Tag and source MAC of the outer frames; the MAC defaults to 02:00 and the last four bytes of `local` |
| `mtu` | The outer link's MTU (default 1500): SYNs through the tunnel get their MSS lowered so segments fit |

The emulated hosts keep their inner addresses and MACs; the port answers
their ARP and neighbor solicitations itself, since a tunnel has no link
layer, and impairments (`--impair`) act on the outer frames, as a bad
link would. Large UDP datagrams are not fragmented: keep them under the
MTU less the tunnel's 36 to 76 bytes. `sudo scripts/tunnel-netns.sh` runs
TCP and DNS inside GTP-U through a router that only knows the outer
addresses, and checks with tshark that each client had its own TEID.

To put the packets of a capture or a stream into GTP-U, VXLAN, GRE and other
tunnels instead, see [tunnel rewrites](replay.md#tunnels).

## Lab script

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

## Templates: many kinds of connections at once

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
[`examples/lab-tcp-mix.toml`](../examples/lab-tcp-mix.toml):

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

## Message timing and fast ports

* **Message timing.** By default each end answers as soon as the other
  end's message is in. `--keep-timing` (`[tcp] keep_timing`) waits the gaps
  the capture shows between messages, and `--think-time 50ms` adds a pause
  before every answer; `--show` lists the gaps.

Sending and receiving goes through libpcap or Npcap by default; `-B af_xdp`
or `-B dpdk` uses the fast ports for higher connection rates (see
[docs/fast-ports.md](fast-ports.md)). More on the engine in
[docs/tcp-engine.md](tcp-engine.md).
