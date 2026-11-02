# FeroTRX

FeroTRX is a traffic replay tool written in Rust, inspired by
[Cisco TRex](https://trex-tgn.cisco.com/). It replays pcap and pcapng captures
at a controlled rate on Linux, macOS and Windows, rewrites them on the way
(addresses, ports, VLAN tags), runs several streams at once from a profile, and
its engine is a library you can use from your own programs.

## Status

* **M1, pcap replay:** done.
* **M2, rewriting and multi-stream profiles:** done.
* **M3, packet inspection (`ferotrx-packet`, `ferotrx inspect`):** this release.
* Next: packet building, a control API (`ferotrx-ctl`), flow multiplication,
  faster Linux backends (AF_XDP, DPDK).

## Crates

| Crate | What it is |
| --- | --- |
| `ferotrx-core` | The core API: captures, rewrites, streams, profiles, pacing and the scheduler. No platform code. |
| `ferotrx-packet` | Packet decoding: layers, fields with byte ranges, checksum checks, summaries. No dependencies. |
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

Packets flow `PacketSource -> Transform... -> Pacer -> PacketSink`. Implement
`PacketSource` to generate packets, `Transform` to change them, and `PacketSink`
to send them anywhere else. `Profile::from_path(...)?.load()?` builds the streams
of a TOML profile.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
