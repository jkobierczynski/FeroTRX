# Lab scripts

You do not need a lab of switches and routers to try FeroTRX. For trying
profiles by hand (or from the GUI) there is a [standing lab
router](#a-standing-lab-router); each script in
[`scripts/`](../scripts) builds a small one in Linux network namespaces, with
the kernel as the router, runs FeroTRX through it, checks the results and
removes the lab again. CI runs all of them on every change.

They need Linux, root and a few tools: `ip` (iproute2) everywhere, plus
`iptables` (or iptables-nft), `tc`, `jq`, `dnsmasq`, `ethtool`, `curl` or
`dig` depending on the script. On Debian and Ubuntu: `sudo apt install
iproute2 iptables jq dnsmasq-base ethtool curl dnsutils`.
Each takes the `ferotrx` binary as its first argument (default: a build in
this checkout, else the installed one); arguments after it go to the
`ferotrx` command the script runs.

| Script | What it runs | Options |
| --- | --- | --- |
| `tcp-nat-netns.sh` | `ferotrx tcp` with `examples/http.pcap` through a NAT router between VLANs 10 and 20 on a trunk | `LOSS=0.03`, `MIX=1` (three templates to four servers), `NETEM="..."`, `BDP=1` (long fat pipe), `ECN=1` (a bottleneck that marks ECN; needs `sch_fq_codel`), `IPV6=1`, `NO_VLAN=1`, `LOG_INVALID=1`, `QUEUES=4` (multi-queue veths, for `--workers`) |
| `udp-netns.sh` | `ferotrx udp` DNS lookups through the same kind of router, then `dig` against the DNS server | `LOSS=0.03`, `MIX=1` (DNS, NTP, echo), `IPV6=1`, `NO_VLAN=1`, `QUEUES=4` |
| `app-netns.sh` | `ferotrx tcp` with HTTP and DNS over TCP (`examples/lab-http.toml`) through the router, then `curl` against the emulated web server and the emulated client against `python3 -m http.server` | `LOSS=0.03`, `IPV6=1`, `NO_VLAN=1` |
| `http-netns.sh` | `ferotrx tcp` HTTP/1.1 with response checks (`examples/lab-http-checks.toml`) through the router, then with a server whose answer must fail one check, then the emulated client checking `python3 -m http.server` | `LOSS=0.03`, `IPV6=1`, `NO_VLAN=1` |
| `tls-netns.sh` | `ferotrx tcp` TLS handshake load through the router: new sessions only on three SNI names, 30% resumed over TLS 1.3 and 1.2, HTTPS with new sessions; then `openssl s_time -new`/`-reuse` against the emulated server and the emulated client against `openssl s_server` | `LOSS=0.03`, `IPV6=1`, `NO_VLAN=1` |
| `sip-netns.sh` | `ferotrx udp` SIP calls with RTP (`examples/lab-sip.toml`) through the router, then SIPp's caller and registrations against the emulated server and the emulated phones against SIPp's answering end | `LOSS=0.03`, `IPV6=1` (emulated ends only), `NO_VLAN=1` |
| `smb-netns.sh` | `ferotrx tcp` SMB clients and file server (`examples/lab-smb.toml`: SMB 3.1.1 and 2.1 signed, a read-only share, a wrong password) through the router, then smbclient against the emulated server and the emulated clients against Samba's `smbd` | `LOSS=0.03`, `IPV6=1` (emulated ends only), `NO_VLAN=1` |
| `h3-netns.sh` | `ferotrx udp` HTTP/3 over QUIC (`examples/lab-h3.toml`: a verified certificate, Retry, key updates, a refused ALPN) through the router, then aioquic's client against the emulated server and the emulated clients against aioquic's server | `LOSS=0.03`, `IPV6=1` (emulated ends only), `NO_VLAN=1`, `PYTHON=` |
| `tunnel-netns.sh` | streams into IP in IP, GRE, Ethernet over GRE, VXLAN (one through `encap=`), Geneve, MPLS and 6in4 tunnels the kernel unwraps, each counted by `--rx`; then `ferotrx tcp` and `ferotrx udp` DNS inside GTP-U through a router that only knows the outer addresses, a TEID per client (checked with tshark) | `DURATION=3s` |
| `latency-netns.sh` | a profile with two latency streams and a plain one, through a router with delay and loss | `DELAY=5ms`, `LOSS=0.02`, `DURATION=4s`, `IPV6=1` |
| `link-netns.sh` | `ferotrx run` with the port's own address (`--ip`/`--gateway`) through a router whose MAC it must find, the router's pings answered, a `50%` stream, bursts and a `next` stream; `ferotrx bench` with the same; then `ctl update -m 3`, `pause` and `resume` on a run of `serve`; loss made by the router (network) and by the sending veth (generator) in the right column of the loss report | `IPV6=1` |
| `impair-netns.sh` | `ferotrx impair` between two hosts in namespaces (ping through delay, jitter, loss, an MTU and duplicates), a stream's own `impair` measured by `ferotrx rx`, and a rate limit; no netem needed (see [Impairments](impairments.md)) | |
| `bench-netns.sh` | `ferotrx bench` against a router that forwards 20 Mbit/s through a token bucket | `RATE=20`, `LINE=100`, `DELAY=2ms`, `SIZES="1020 imix"`, `TRIAL=1s`, `SWEEP=1` (`bench --sweep` below the bottleneck: medians, spread, Markdown report) |
| `y1564-netns.sh` | `ferotrx y1564` (voice and data) through a router that polices by DSCP, then again with data's policer below its CIR, which must fail | `STEP=2s`, `PERF=4s`, `LOW=only` or `LOW=no` |
| `hosts-netns.sh` | `ferotrx host` and `ferotrx tcp --client-ip dhcp` against dnsmasq and a bridge with IGMP/MLD snooping; a FeroTRX DHCP server for busybox `udhcpc` and emulated clients | `IPV6=1` (SLAAC, DHCPv6, MLD, router advertisements, a DHCPv6 server for `udhcpc6`) |
| `services-netns.sh` | LLDP/CDP with lldpd, mDNS with dig and avahi, 802.1X with wpa_supplicant and hostapd, IPFIX/NetFlow v9 with tshark | `IPV6=1` (RA MTU/RDNSS/DNSSL with rdisc6, prefix delegation with dhcpcd) |
| `lab-examples.sh` | the control server's lab router (`serve --lab`, `lab.start`), with the examples as they are: `lab-tcp.toml`, `lab-udp-mix.toml`, `lab-built-packets.toml`, `lab-l3-port.toml` (ARP for the router), `lab-bench-sweep.toml`, `lab-prefix-delegation.toml` (with IPv6), then every `lab-scenario-*.toml` on the router it names | `BLOCK=1` (router resets TCP to port 80) |
| `fleet-netns.sh` | `ferotrx fleet run examples/fleet/fleet.toml` on three agents in namespaces (a web server, clients on two agents, a probe received on another agent), captures on two agents collected and merged, then again with one client agent cut off, which must fail | `SPREAD=100`, `KEEP=DIR` |
| `capture-netns.sh` | `ferotrx capture` with BPF filters between two namespaces: to a file (checked by tcpdump), `-w -` into tcpdump, a ring of files, `--direction in`, a capture on a control server read over ctl and fetched, `--capture` next to a run, `inspect -f` (see [capturing](capture.md)) | |
| `scenario-netns.sh` | `examples/scenario-nat.toml`, then the same after breaking the router's firewall, which must show as a regression | `KEEP=DIR` keeps the reports |

```sh
sudo scripts/tcp-nat-netns.sh
sudo LOSS=0.03 MIX=1 scripts/tcp-nat-netns.sh
sudo IPV6=1 scripts/udp-netns.sh
sudo scripts/tcp-nat-netns.sh target/release/ferotrx -B af_xdp   # through the fast ports
sudo QUEUES=4 scripts/tcp-nat-netns.sh -B af_xdp --workers 4 --cps 4000 -n 40000   # on four cores
```

Options after the script name (and the optional path to the binary) go to
`ferotrx`. The header of each script draws its lab and lists every option. What the
results look like, and what each script checks, is in the guide for the
feature: [stateful TCP](stateful-tcp.md#lab-script),
[stateful UDP](stateful-udp.md#lab-script),
[application protocols](app-protocols.md#lab-script),
[loss and latency](loss-latency.md#lab-script),
[benchmarking](benchmarking.md), [Y.1564](y1564.md#lab-script), [fleets](fleet.md#lab-script), [host emulation](host-emulation.md#lab-script)
and [scenarios](scenarios.md#an-example-run).

Things to know:

* The emulated hosts use their own MAC and IP addresses. Do not give them
  addresses of the machine FeroTRX runs on, or its own stack answers with
  resets.
* On veth links, checksum and VLAN offloads hide things from FeroTRX's
  receive side; the scripts turn the relevant ones off on the router's side
  with `ethtool` when it is installed.
* IPv6 needs a kernel with IPv6 enabled, and IPv6 masquerading only happens
  when the kernel has IPv6 NAT; otherwise the router only routes.

## A standing lab router

The scripts build a lab, run one test and remove the lab. To try the lab
examples (`examples/lab-*.toml`) by hand, or from the [GUI](gui.md), build
the same router and keep it:

```text
  this machine                   router (namespace ferotrx-lab)
  ftrx-lab ---- veth trunk ----- rt.10  192.168.10.1/24  fd00:10::1/64
    VLAN 10: clients             rt.20  192.168.20.1/24  fd00:20::1/64
    VLAN 20: servers             forwards, conntrack, masquerades out of rt.20
```

```sh
sudo ferotrx lab up                       # until Ctrl-C
sudo ferotrx udp -p examples/lab-udp-mix.toml -i ftrx-lab
sudo ferotrx tcp -p examples/lab-tcp.toml -i ftrx-lab
sudo ferotrx run examples/lab-two-vlans.toml -i ftrx-lab
```

Every lab example fits it as it is: clients on VLAN 10 with gateway
192.168.10.1, servers on VLAN 20 with gateway 192.168.20.1, the same with
`fd00:10::1` and `fd00:20::1` for IPv6. The router's MAC is
`02:00:00:00:00:01` on both VLANs, the `mac_dst` that the replay examples
(`lab-two-vlans.toml`, `lab-built-packets.toml`) already use. A replayed
stream is routed when it carries that MAC, VLAN 10 and a source in
192.168.10.0/24; for it to leave on VLAN 20, the router needs a neighbor for
the destination, which nothing answers for in a replay. One is always there:
**192.168.20.2** (and `fd00:20::2`) at `02:00:00:00:00:02`, the stream
receiver: send to it and `--rx ftrx-lab` sees the stream come back on VLAN
20, for loss and latency through the router. For another address:
`sudo ip netns exec ferotrx-lab ip neigh replace 192.168.20.50 lladdr 02:00:00:00:00:50 dev rt.20`. The router tracks connections and
drops what conntrack calls INVALID, as a firewall does, and masquerades
towards the servers. Options:

| `ferotrx lab up` | `lab.start` | What the router does |
| --- | --- | --- |
| `--no-ipv6` | `ipv6: false` | IPv4 only |
| `--no-nat` | `nat: false` | routes without masquerading |
| `--loss 0.03` | `loss: 0.03` | drops 3% of what it forwards |
| `--delay "20ms 5ms"` | `delay` | netem delay on both links (`sch_netem`) |
| `--block-tcp 80` | `block_tcp: [80]` | resets TCP to port 80, to see a test fail |
| `--block-udp 53` | `block_udp: [53]` | drops UDP to port 53 |
| `--dhcp` | `dhcp: true` | DHCP on VLAN 10 (.200-.250), with IPv6 also router advertisements and DHCPv6, from dnsmasq: for `examples/lab-tcp-dhcp.toml` and `lab-hosts.toml` |
| `--queues 4` | `queues: 4` | four queues on the link, for `--workers 4 -B af_xdp` |

It needs Linux, root, `ip` and `iptables`, VLAN support (the 8021q module),
and `tc` or `dnsmasq` for those options. `ferotrx lab down` removes a lab
that was left behind.

A control server builds it for its clients when started with `--lab`
(`sudo ferotrx serve --lab`): `lab.start` with the parameters above, `lab.stop`
and `lab.get` (see [remote control](remote-control.md)). The GUI has a
**Lab router** entry under each such server. The server removes the lab when
it stops (Ctrl-C). Labs are off unless `--lab` is given, because they change
the machine's network: a namespace and a link.
