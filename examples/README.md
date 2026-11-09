# Examples

Every file here fits the [lab router](../docs/lab-scripts.md#a-standing-lab-router)
as it is: clients on VLAN 10 (192.168.10.0/24, `fd00:10::/64`, gateway `.1`),
servers on VLAN 20 (192.168.20.0/24, `fd00:20::/64`), the router's MAC
`02:00:00:00:00:01`, and its stream receiver 192.168.20.2, which sends routed
streams back on VLAN 20 so `--rx ftrx-lab` counts them. Build it and try one:

```sh
sudo ferotrx lab up                     # until Ctrl-C; or `ferotrx serve --lab` and the GUI
sudo ferotrx tcp -p examples/lab-tcp.toml -i ftrx-lab
ferotrx check examples/*.toml           # every file, without sending
```

`scripts/lab-examples.sh` plays most of them on that router (in CI too), and
runs every `lab-scenario-*.toml`. For your own lab, change the addresses:
each file says which.

## Streams (`ferotrx run`)

| File | What it shows |
| --- | --- |
| [lab-two-vlans.toml](lab-two-vlans.toml) | captures replayed between the VLANs, with rewrites and a start delay |
| [lab-built-packets.toml](lab-built-packets.toml) | packets built from text instead of captures |
| [lab-models.toml](lab-models.toml) | Poisson arrivals, bursts and a load ramp |
| [lab-sequence.toml](lab-sequence.toml) | multi-burst streams, streams that start each other in a loop, rates as a share of the line and on the wire |
| [lab-l3-port.toml](lab-l3-port.toml) | the port's own address: ARP for the router, answers for the port (L3 mode) |
| [lab-tunnels.toml](lab-tunnels.toml) | VXLAN, GTP-U (a TEID per phone), GRE (a key per site) and MPLS, varied per loop |
| [lab-impair.toml](lab-impair.toml) | FeroTRX's own impairments per stream: delay, jitter, burst loss, a shaper, duplicates, corruption |
| [lab-latency.toml](lab-latency.toml) | loss and latency streams with a receiver |

## Stateful TCP and UDP (`ferotrx tcp`, `ferotrx udp`)

| File | What it shows |
| --- | --- |
| [lab-tcp.toml](lab-tcp.toml) | both ends of `http.pcap` through the NAT, byte for byte |
| [lab-tcp-mix.toml](lab-tcp-mix.toml) | several templates by weight, to several servers |
| [lab-tcp-v6.toml](lab-tcp-v6.toml) | the same over IPv6 |
| [lab-tcp-dhcp.toml](lab-tcp-dhcp.toml) | a client that gets its address by DHCP |
| [lab-tcp-impair.toml](lab-tcp-impair.toml) | impairments on the port (`impair`, `impair_rx`), CUBIC and ECN |
| [lab-tcp-fast.toml](lab-tcp-fast.toml) | AF_XDP with four pinned workers (`lab up --queues 4`) |
| [lab-gtpu.toml](lab-gtpu.toml) | TCP inside GTP-U, a TEID per phone (`lab up --no-nat`) |
| [lab-dns.toml](lab-dns.toml) | DNS lookups with a zone of answers and errors |
| [lab-udp-mix.toml](lab-udp-mix.toml) | DNS from a capture, NTP and a written echo, with timing |
| [lab-ntp.toml](lab-ntp.toml) | NTP clients and a server, Poisson arrivals |

## Sessions, users and personas

| File | What it shows |
| --- | --- |
| [lab-sessions.toml](lab-sessions.toml) | 50 users kept online: log-normal session lengths, think times, lifetimes; a capture in rounds |
| [lab-personas.toml](lab-personas.toml) | office, IoT and server personas mixed in one TCP run |
| [lab-personas-udp.toml](lab-personas-udp.toml) | the same personas' UDP side (DNS, NTP) |
| [personas/](personas) | persona files: `office`, `iot`, `voice`, `server` |

## Application protocols

| File | Protocol |
| --- | --- |
| [lab-http.toml](lab-http.toml) | HTTP/1.1 and DNS over TCP |
| [lab-http-checks.toml](lab-http-checks.toml) | HTTP/1.1 with per-request checks of status, headers and bodies |
| [lab-https.toml](lab-https.toml) | HTTPS and DNS over TLS |
| [lab-tls.toml](lab-tls.toml) | TLS handshake load, resumption, SNI |
| [lab-h2.toml](lab-h2.toml) | HTTP/2 over TLS and h2c |
| [lab-h3.toml](lab-h3.toml) | HTTP/3 over QUIC |
| [lab-mqtt.toml](lab-mqtt.toml) | MQTT clients and a broker |
| [lab-ssh.toml](lab-ssh.toml) | SSH clients and servers |
| [lab-sip.toml](lab-sip.toml) | SIP calls with RTP |
| [lab-smb.toml](lab-smb.toml) | SMB 2 and 3 file clients and a server |

## Hosts (`ferotrx host`)

| File | What it shows |
| --- | --- |
| [lab-hosts.toml](lab-hosts.toml) | DHCP, SLAAC, DHCPv6 and multicast groups |
| [lab-dhcp-server.toml](lab-dhcp-server.toml) | DHCP and DHCPv6 servers with a router |
| [lab-prefix-delegation.toml](lab-prefix-delegation.toml) | DHCPv6 prefix delegation to three CPEs, both ends emulated |
| [lab-services.toml](lab-services.toml) | LLDP/CDP, mDNS, 802.1X and IPFIX export |

## Benchmarks and service tests

| File | What it shows |
| --- | --- |
| [bench-rfc2544.toml](bench-rfc2544.toml) | RFC 2544 throughput, latency, frame loss and back-to-back |
| [lab-bench-sweep.toml](lab-bench-sweep.toml) | a sweep of the lab router: medians and spread over repeated trials |
| [y1564.toml](y1564.toml) | a full Y.1564 test (configuration and 15-minute performance) |
| [lab-y1564.toml](lab-y1564.toml) | a short Y.1564 test of the lab router |

## Scenarios (`ferotrx scenario run`)

| File | Router | Checks |
| --- | --- | --- |
| [lab-scenario.toml](lab-scenario.toml) | resets TCP 8080, drops UDP 123 | NAT, firewall, a voice stream |
| [lab-scenario-apps.toml](lab-scenario-apps.toml) | resets TCP 8080 | HTTP, HTTPS, DNS over TCP |
| [lab-scenario-impaired.toml](lab-scenario-impaired.toml) | 2% loss, 20 ms (netem) | recovery by retransmission |
| [lab-scenario-ipv6.toml](lab-scenario-ipv6.toml) | IPv6 without NAT | web, DNS, a stream |
| [lab-scenario-streams.toml](lab-scenario-streams.toml) | as built | bursts and sequences, tunnels, impaired streams |
| [lab-scenario-tunnels.toml](lab-scenario-tunnels.toml) | without NAT | TCP and DNS inside GTP-U |
| [lab-scenario-services.toml](lab-scenario-services.toml) | as built | NTP, TCP over an impaired port, Y.1564 |
| [scenario-nat.toml](scenario-nat.toml) | your own NAT router | regression checks with variables |

## Several machines and shared servers

| File | What it is |
| --- | --- |
| [fleet/](fleet) | a fleet plan: a web server and clients on three agents, started together |
| [server/serve.toml](server/serve.toml) | traffic limits for a shared control server (`serve --config`) |
| [server/tokens.toml](server/tokens.toml) | logins with read, operator and admin roles (`serve --tokens`), for port reservations |
| [../python/examples/reserve_ports.py](../python/examples/reserve_ports.py) | reserve a port, run on it, give it back |
| [ctl-client.py](ctl-client.py) | the control protocol without the Python package |
