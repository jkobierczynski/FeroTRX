# FeroTRX

FeroTRX is a traffic replay tool written in Rust, inspired by
[Cisco TRex](https://trex-tgn.cisco.com/). It replays pcap and pcapng captures
at a controlled rate on Linux, macOS and Windows, rewrites them on the way
(addresses, ports, VLAN tags), builds packets from scratch, runs several streams
at once from a profile, and its engine is a library you can use from your own programs.

## Status

* **M1, pcap replay:** done.
* **M2, rewriting and multi-stream profiles:** done.
* **M3, packet inspection (`ferotrx-packet`, `ferotrx inspect`):** done.
* **M4, packet building (`ferotrx build`, built packets in profiles):** this release.
* Next: a control API (`ferotrx-ctl`), flow multiplication (field ranges),
  faster Linux backends (AF_XDP, DPDK).

## Crates

| Crate | What it is |
| --- | --- |
| `ferotrx-core` | The core API: captures, rewrites, streams, profiles, pacing and the scheduler. No platform code. |
| `ferotrx-packet` | Packet decoding (layers, fields with byte ranges, checksum checks, summaries) and building. No dependencies. |
| `ferotrx-io` | Packet sinks: network interfaces through libpcap/Npcap, pcap files. |
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

### Profiles

A profile runs several streams at once into one output, each with its own
capture, rate, loops, start delay and rewrites. The scheduler always sends the
packet with the earliest deadline, so paced streams keep their rate and top
speed streams fill the gaps.

```toml
[[stream]]
name = "dns"
pcap = "dns.pcap"            # relative to the profile
rate = "500pps"              # 1000pps, 10kpps, 100mbps, 1gbps, 2x, topspeed
loops = 0                    # 0 = until the run ends
rewrite = ["vlan_push=10", "ip_dst=192.168.20.50"]

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

Packets flow `PacketSource -> Transform... -> Pacer -> PacketSink`. Implement
`PacketSource` to generate packets, `Transform` to change them, and `PacketSink`
to send them anywhere else. `Profile::from_path(...)?.load()?` builds the streams
of a TOML profile.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
