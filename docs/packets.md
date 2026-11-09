# Inspecting and building packets

`ferotrx inspect` shows what is in a capture; `ferotrx build` makes packets from a short text
description, for sending, for a pcap file, or as streams in a profile.

## Inspecting

`ferotrx inspect` decodes a capture: Ethernet, 802.3/LLC with SNAP (and
Cisco CDP, VTP, DTP and PVST+ by name), VLAN and QinQ tags, Linux cooked
captures, ARP, IPv4, IPv6 with extension headers, TCP, UDP, ICMP, ICMPv6,
IGMP (v1 to v3), MLD (v1 and v2) and DNS/mDNS, and names common ports (HTTP,
TLS, SSH, DHCP, NTP, SNMP). It follows tunnels to the packet inside: MPLS
label stacks (with an Ethernet pseudowire's control word), IP in IP (4in4,
6in4, 4in6, 6in6), GRE (checksum, key, sequence; Ethernet over GRE), VXLAN
(UDP 4789), Geneve (UDP 6081, with options) and GTP-U (UDP 2152, with the
PDU session container's QFI). It checks IPv4, TCP, UDP, ICMP, ICMPv6, IGMP
and GRE checksums and the GTP-U length, and flags truncated headers.

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

## Building packets

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
[`examples/packets.txt`](../examples/packets.txt). Without a rate, packets go out
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
| `mpls` | `label` (16), `tc` (or `exp`), `ttl` (64), `s` (bottom of stack: set on the last label by itself). Before `eth`, a pseudowire control word goes first |
| `gre` | `key`, `seq`, `csum` (0; 1 computes the GRE checksum), `proto` (from the next layer: 0x0800, 0x86dd, 0x8847, or 0x6558 before `eth`) |
| `vxlan` | `vni` (1), `flags` (0x08); after `udp`, which then defaults to port 4789; an `eth` comes next |
| `geneve` | `vni`, `proto` (from the next layer), `oam`, `crit`, `opt` (options as hex, a multiple of 4 bytes); UDP port 6081 |
| `gtpu` (or `gtp`) | `teid` (1), `type` (`gpdu`, `echo`, `echo_resp`, `error`, `end` or a number), `seq`, `qfi` (adds a PDU session container), `pdu` (`ul` or `dl`), `len`; UDP port 2152 both ways |
| `llc` | `dsap` (0xaa), `ssap` (0xaa), `ctrl` (3); the `eth` before it gets an 802.3 length instead of a type |
| `snap` | `oui` (0), `pid` (the next layer's ethertype) |
| `igmp` | `type` (`report`, `query`, `leave`, `v3report`, `v3query`), `ver` (2), `mrt` (max response time in 0.1 s, 100), `group` (239.1.1.1), `src` (repeatable; v3 query sources), `rec` (repeatable v3 report records), `s`, `qrv` (2), `qqic` (125), `chksum` |
| `mld` | after `ipv6` (and `hbh(ra=0)`, as the standard asks): `type` (`report`, `query`, `done`, `v2report`, `v2query`), `ver` (1), `delay` (ms, 10000), `group` (ff0e::1), `src`, `rec`, `s`, `qrv`, `qqic`, `chksum` |
| `raw` | `hex=0a0b0c`, `text="..."` (quotes allow `,` `)` and `\"`), `len=N` with `fill` (0) |

Numbers can be decimal or `0x` hex; on/off fields take 1/0, true/false or
yes/no. A packet that starts with `ipv4` or `ipv6` is written with the raw IP
link type instead of Ethernet.

Group records of IGMPv3 and MLDv2 reports are written `TYPE@GROUP[+SOURCE...]`,
where TYPE is `join` (change to exclude mode, no sources), `leave` (change to
include mode), `include`, `exclude`, `to_in`, `to_ex`, `allow`, `block` or the
record type's number.

```sh
# Tunnels: VXLAN, GTP-U with a QoS flow, GRE with a key, two MPLS labels, 6in4
ferotrx build 'eth/ipv4(dst=10.0.0.2)/udp/vxlan(vni=5000)/eth/ipv4/udp(dport=53)/dns(q=example.com)' -v
ferotrx build 'eth/ipv4/udp/gtpu(teid=0x1234,qfi=9,pdu=ul)/ipv4(src=172.16.0.5,dst=8.8.8.8)/icmp' -v
ferotrx build 'eth/ipv4/gre(key=42,csum=1)/eth/ipv4/icmp' 'eth/mpls(label=100,tc=5)/mpls(label=200)/ipv4/udp' 'eth/ipv4/ipv6/icmp'

# Multicast: an IGMPv3 report joining one group and allowing a source of another,
# an MLDv2 report, an IGMPv3 general query
ferotrx build 'eth/ipv4(dst=224.0.0.22,ttl=1)/igmp(rec=join@239.1.2.3,rec=allow@232.1.1.1+10.0.0.9)' \
              'eth/ipv6(hlim=1,dst=ff02::16)/hbh(ra=0)/mld(rec=join@ff3e::1234)' \
              'eth/ipv4/igmp(type=v3query,group=0.0.0.0)' -o mcast.pcap

# Spanning tree BPDU over 802.3/LLC
ferotrx build 'eth(dst=01:80:c2:00:00:00)/llc(dsap=0x42,ssap=0x42)/raw(hex=0000000000)' -v
```

Every tunnel and multicast header the builder makes is checked against
Wireshark's dissectors in CI (`crates/ferotrx-packet/tests/wireshark.rs`),
with checksum validation on. To put packets of a capture or a stream into a
tunnel, or take them out, see [tunnel rewrites](replay.md#tunnels).

## From a capture back to the text form

`ferotrx_packet::import` turns a captured packet into layers of the text
form, ready to edit and build again: Ethernet, VLAN and QinQ tags, ARP,
IPv4, IPv6 (with hop-by-hop and destination options), TCP (with MSS, window
scale and SACK permitted), UDP, ICMP/ICMPv6 echo, LLC/SNAP, MPLS, GRE, VXLAN,
Geneve, GTP-U, IP in IP, IGMP and MLD become fields, the rest a `raw` payload (as `text` when it
is printable, else `hex`). Lengths and checksums are left out so the builder
computes them, which means a packet with correct checksums builds back to
the same bytes. `Imported::notes` lists what could not be carried over. The
[GUI](gui.md) uses it to make streams from captures;
`ferotrx_packet::parse_layers` and `format_layers` split and join the text
form layer by layer without checking fields, for editors.

