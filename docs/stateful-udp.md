# Stateful UDP and DNS

How to use `ferotrx udp`. What the engine does on the wire is in
[udp-engine.md](udp-engine.md).

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

## Counters and options

The counters per side (and per template) are transactions `sent`,
`answered`, `timed out`, `with error answers` (DNS response codes other than
NOERROR, expected or not), `with other answers than expected`, unmatched
datagrams (late answers, wrong ids, closed ports), requests sent again, and
response times. The command exits with an error if any transaction timed out
or got another answer than expected. Hosts, `--connect`, `--server-ips`,
`--source-ports` and `--concurrency` work as for TCP; `--timeout`,
`--retries`, `--session-timeout`, `--think-time` and `--keep-timing` are
UDP's own. [docs/udp-engine.md](udp-engine.md) has the details.

## UDP profiles

A UDP profile ([`examples/lab-dns.toml`](../examples/lab-dns.toml)):

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
`think_time` ([`examples/lab-udp-mix.toml`](../examples/lab-udp-mix.toml): DNS
from a capture, NTP at its own rate, and a two-round echo with capture
timing). `udp.start` takes the same profile over the control API (`ferotrx
ctl udp-start lab-dns.toml --upload -i enp0s3`), and `udp.stats` reports the
counters with response times.

## Lab script

`sudo scripts/udp-netns.sh` plays 600 lookups through the namespace router,
then runs the DNS server alone and asks it with `dig` (A, AAAA, MX, NXDOMAIN,
SERVFAIL); `LOSS=0.03`, `MIX=1`, `IPV6=1` and `NO_VLAN=1` work as for the TCP
script. CI runs all of them.
