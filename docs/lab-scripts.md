# Lab scripts

You do not need a lab of switches and routers to try FeroTRX. Each script in
[`scripts/`](../scripts) builds a small one in Linux network namespaces, with
the kernel as the router, runs FeroTRX through it, checks the results and
removes the lab again. CI runs all of them on every change.

They need Linux, root and a few tools: `ip` (iproute2) everywhere, plus
`iptables` (or iptables-nft), `tc`, `jq` or `dnsmasq` depending on the
script. On Debian and Ubuntu: `sudo apt install iproute2 iptables jq dnsmasq-base`.
Each takes the `ferotrx` binary as its first argument (default: a build in
this checkout, else the installed one); arguments after it go to the
`ferotrx` command the script runs.

| Script | What it runs | Options |
| --- | --- | --- |
| `tcp-nat-netns.sh` | `ferotrx tcp` with `examples/http.pcap` through a NAT router between VLANs 10 and 20 on a trunk | `LOSS=0.03`, `MIX=1` (three templates to four servers), `NETEM="..."`, `BDP=1` (long fat pipe), `IPV6=1`, `NO_VLAN=1`, `LOG_INVALID=1`, `QUEUES=4` (multi-queue veths, for `--workers`) |
| `udp-netns.sh` | `ferotrx udp` DNS lookups through the same kind of router, then `dig` against the DNS server | `LOSS=0.03`, `MIX=1` (DNS, NTP, echo), `IPV6=1`, `NO_VLAN=1`, `QUEUES=4` |
| `latency-netns.sh` | a profile with two latency streams and a plain one, through a router with delay and loss | `DELAY=5ms`, `LOSS=0.02`, `DURATION=4s`, `IPV6=1` |
| `bench-netns.sh` | `ferotrx bench` against a router that forwards 20 Mbit/s through a token bucket | `RATE=20`, `LINE=100`, `DELAY=2ms`, `SIZES="1020 imix"`, `TRIAL=1s` |
| `hosts-netns.sh` | `ferotrx host` and `ferotrx tcp --client-ip dhcp` against dnsmasq and a bridge with IGMP/MLD snooping | `IPV6=1` (SLAAC, DHCPv6, MLD, router advertisements) |
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
[loss and latency](loss-latency.md#lab-script),
[benchmarking](benchmarking.md), [host emulation](host-emulation.md#lab-script)
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
