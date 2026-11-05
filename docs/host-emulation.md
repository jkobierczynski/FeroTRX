# Host emulation

FeroTRX 0.12.0 (M19) makes its emulated hosts behave on the link like real
ones: they can get their addresses from the lab's DHCP server or router,
announce them, join multicast groups and keep the memberships alive, and one
can act as an IPv6 router for others. Since 0.25.0 (M29) a host can also be
the [DHCP or DHCPv6 server](#dhcp-servers) of its link. It works in two
places:

* **`ferotrx host`** runs hosts on their own, as many as you like, until
  Ctrl-C or a duration: DHCP clients for a DHCP server, group members for a
  snooping switch, a router for devices that autoconfigure, a DHCP server
  for devices that need addresses.
* **`ferotrx tcp` and `ferotrx udp`**: the client or the server of a run can
  get its address by DHCP, SLAAC or DHCPv6 (`ip = "dhcp"`), announce it and
  join groups. The run starts once the address is there.

All of it is sans-IO in `ferotrx-core` (`HostEngine`, `Hosted`), like the
TCP and UDP engines, and runs on every port type (libpcap/Npcap, AF_XDP,
DPDK).

```sh
# 20 DHCP clients on VLAN 10 that join a group, for a minute
sudo ferotrx host -i enp0s3 --vlan 10 -n 20 --ipv4 dhcp --join 239.1.2.3 -d 1m
# dual stack: DHCP and SLAAC, from a profile
sudo ferotrx host examples/lab-hosts.toml -i enp0s3
# a router that advertises fd00:99::/64 every 5 s
sudo ferotrx host -i enp0s3 --ra fd00:99::/64 --ra-interval 5s
# a DHCP server for a segment, 10 minute leases
sudo ferotrx host -i enp0s3 --ipv4 10.88.0.1/24 --dhcp-pool 10.88.0.100-10.88.0.199 \
     --dhcp-router 10.88.0.1 --dhcp-dns 10.88.0.1 --dhcp-lease 10m
# a TCP client with a DHCP address, a static server
sudo ferotrx tcp examples/http.pcap -n 100 --cps 20 \
     --client-iface eth1 --client-ip dhcp --server-iface eth2 --server-ip 10.77.0.20/24
```

`ferotrx host` prints each host when it is ready (or fails), and all of them
at the end:

```text
host 02:dc:00:00:01:01 ready after 0.01 s: ipv4 10.77.0.174/24 via 10.77.0.1 (dhcp from 10.77.0.1, lease 120 s); group 239.1.2.3 (1 reports, 0 frames received)
...
stopped in 14.000 s: 3 of 3 hosts ready, 0 failed; 48 frames sent, 28 taken
  host 02:dc:00:00:01:01 ready after 0.01 s: ipv4 10.77.0.174/24 via 10.77.0.1 (dhcp from 10.77.0.1, lease 120 s); group 239.1.2.3 (8 reports, 3 frames received)
```

It exits with an error if a host failed or was not ready when the run ended.
`--until-ready` ends the run as soon as every host is ready.

## Addresses

### DHCPv4 (`ipv4 = "dhcp"`)

The RFC 2131 client: DISCOVER, OFFER, REQUEST, ACK, broadcast from 0.0.0.0
with the client identifier (type 1 and the MAC), the host name (option 12,
`hostname`, where `{n}` is the host's number) and a parameter request list
(subnet mask, router, DNS servers, lease and renewal times). The host takes
the address, the prefix from the subnet mask (default /24), the first router
as its gateway and the DNS servers. Unanswered messages are sent again after
1, 2, 4, 4 ... seconds (`retry`); after four requests without an answer the
host starts over with a DISCOVER, and a NAK starts it over at once.

While it runs, the host renews at T1 (option 58, default half the lease) with
a unicast REQUEST to the server, through the MAC its ACK came from, and
rebinds at T2 (option 59, default 7/8) with a broadcast. A lease that runs
out stops a TCP or UDP run with an error; a `ferotrx host` host starts over.
At the end of the run each host sends a DHCPRELEASE (`release = false` keeps
the leases). `broadcast = true` sets the broadcast flag, for relays or servers
that cannot answer a client without an address.

### SLAAC (`ipv6 = "slaac"`)

Router solicitations from the link-local address (fe80:: and the EUI-64 of the
MAC) until an advertisement comes; the first /64 prefix marked for
autoconfiguration (A flag) plus the EUI-64 is the address, and the router
that advertised it (if its router lifetime is above zero) the gateway, by its
link-local address. The valid lifetime shows as the lease.

### DHCPv6 (`ipv6 = "dhcpv6"`)

The RFC 8415 client for one address (IA_NA): SOLICIT, ADVERTISE, REQUEST,
REPLY to ff02::1:2 from the link-local address, with a DUID-LL client id;
RENEW at T1, REBIND at T2, RELEASE at the end. DHCPv6 gives no routes, so the
host also sends router solicitations: the gateway and the on-link prefix
length come from the advertisements (an address in an advertised on-link
prefix takes its length, else /64). Without an answer to three solicitations
the host goes on without a gateway.

### Duplicate address detection

IPv6 addresses (SLAAC, DHCPv6 and static) are checked first (RFC 4862): a
neighbor solicitation from :: to the address's solicited-node group, then a
second's wait (`dad_wait`). An advertisement for the address, or someone
else's probe for it, fails the host ("already in use on the link"). `dad =
false` (`--no-dad`) skips the check. The link-local address is used without
one. IPv4 addresses are not probed (no RFC 5227 ARP probes yet).

### Static addresses

`ipv4 = "192.168.10.50/24"` with `gateway`, `ipv6 = "fd00:10::50/64"` with
`gateway6`. With `count`, each host's address is one higher.

## Announcements

`announce = true` (the default for DHCP, SLAAC and DHCPv6 addresses) sends two
gratuitous ARPs (requests for the host's own address, to everyone), or two
unsolicited neighbor advertisements (override set, to ff02::1), a second
apart (`announcements`, `announce_interval`), once the address is set. Switches
learn the MAC's port, and neighbors with `arp_accept` (or any neighbor that
already had an entry) update it.

## Multicast groups

`groups = ["239.1.2.3", "ff15::1234"]` (`--join`): IPv4 groups over IGMP,
IPv6 groups over MLD.

* On joining, two unsolicited reports a second apart: IGMPv3 or MLDv2
  (CHANGE_TO_EXCLUDE {}, to 224.0.0.22 or ff02::16) by default, IGMPv2 or
  MLDv1 reports to the group with `igmp_version`/`mld_version`. IPv4 reports
  go once the host has its IPv4 address, from it; MLD reports from the
  link-local address. All carry the router alert option.
* A general or group query gets a report for each group it asks about after
  a random delay within its maximum response time. A query of an older
  version makes the host answer in that version from then on (the
  compatibility modes of RFC 3376 and 3810, without their timers back).
* IPv6 hosts also report the solicited-node groups of their addresses, as
  real hosts do, so MLD snooping switches forward neighbor solicitations to
  them. These are not listed with the groups. When a `tcp` or `udp` run
  emulates hosts, a static IPv6 client or server gets a host of its own
  for this (its first address only), so it stays reachable through such a
  switch.
* Frames to a joined group are counted per group (`frames received`).
* At the end, an IGMPv2 leave or IGMPv3 CHANGE_TO_INCLUDE {}, an MLD done or
  MLDv2 CHANGE_TO_INCLUDE {} (not with `release = false`).

IGMPv1 is answered too (with v1 reports, and no leave).

## Routers

A host with a `[host.router]` table (`--ra PREFIX`) sends router
advertisements from its link-local address to ff02::1: at start, every
`interval` (default 10 s), and soon after a router solicitation (at most one
a second). They carry its MAC, each prefix as on-link and for
autoconfiguration (valid 1 day, preferred 4 hours), the router `lifetime`
(default 30 min; 0 advertises the prefixes without being a default router),
and the `managed` (M) and `other` (O) flags. At the end it sends a last
advertisement with router lifetime 0, so hosts drop it as their default
router. It answers neighbor solicitations for its link-local address, so
hosts can reach it. It does not route.

## DHCP servers

A host with a static IPv4 address and a `[host.dhcp_server]` table
(`--dhcp-pool FIRST-LAST`) is a DHCP server (RFC 2131, 2132) for its link
and VLAN; a host with a `[host.dhcpv6_server]` table (an IPv6
`--dhcp-pool`) is a DHCPv6 server (RFC 8415, addresses in IA_NA)
([`examples/lab-dhcp-server.toml`](../examples/lab-dhcp-server.toml)):

```toml
[[host]]
mac = "02:dc:00:00:0d:01"
ipv4 = "10.88.0.1/24"         # the server identifier
[host.dhcp_server]
pool = "10.88.0.100-10.88.0.199"
lease = "10m"                 # default 1h; renewal at 1/2, rebinding at 7/8
router = "10.88.0.1"          # default: the host's `gateway`, else none
dns = ["10.88.0.1"]
domain = "lab.test"
reservations = { "02:dc:00:00:0e:07" = "10.88.0.7" }   # inside or outside the pool
# prefix = 24                 # the subnet mask given out; default the host's
[host.dhcpv6_server]
pool = "fd00:88::100-fd00:88::1ff"
lease = "10m"                 # valid and preferred lifetime; T1 1/2, T2 4/5
dns = ["fd00:88::1"]
domain = "lab.test"           # the domain search list
reservations = { "02:dc:00:00:0e:07" = "fd00:88::7" }
rapid_commit = true           # answer a solicit that asks for it at once
prefix = 64                   # the on-link prefix, for confirm messages
[host.router]                 # DHCPv6 clients take the gateway from adverts
prefixes = ["fd00:88::/64"]
managed = true
```

The DHCPv4 server:

* offers a client its reservation, else the address it had (by client
  identifier, else MAC), else the one it asks for if free, else the next
  never leased one, else an expired one; an offer is held for 30 s. The
  server's own address and the router's are never leased. A full pool
  leaves the discover unanswered (counted as `exhausted`).
* acknowledges requests for its offer, init-reboot requests and renewals
  or rebinds of a free or own address, and NAKs the rest (also an address
  of another subnet: it is authoritative). A request for another server's
  offer frees the offer.
* takes releases and declines (a declined address is not leased for 10
  minutes) and answers informs (configuration without a lease).
* answers as RFC 2131 says: to a relay's `giaddr` (port 67), NAKs and
  answers with the broadcast flag to everyone, renewals to `ciaddr`, else
  unicast to the offered address at the client's MAC. Relay agent
  information (option 82) is sent back as it came. All relayed clients get
  the one pool.

The DHCPv6 server answers on its link-local address: solicits with an
advertise (or, with rapid commit, a reply), requests, renews and rebinds
with a reply (an address the client may not keep with lifetimes 0),
releases and declines, confirms (on link or not) and information requests
(DNS and domain only). A full pool gives `NoAddrsAvail`. It joins
ff02::1:2 (all DHCP servers) over MLD, so snooping switches send the
clients' messages its way.

Leases are kept in memory for the run. The clients can be real devices or
the run's own emulated hosts: the engine hands frames between a server and
the other hosts on its port and VLAN itself, since a port does not deliver
what it sends. `ferotrx host` prints the server with its counters, and
each lease, at the end:

```text
  host 02:dc:00:00:0d:01 ready after 0.00 s: ipv4 10.88.0.1/24 (static); dhcp server 10.88.0.100-10.88.0.104 (3 of 5 leased; 3 discovers, 3 offers, 4 acks, 0 naks, 0 releases)
    lease 10.88.0.7 to 02:dc:00:00:0f:01 (kernel-client), 24 s left
```

The same is in `hosts` of the control server's run info (`dhcp_server`,
`dhcpv6_server`) and the Python client's `HostInfo`.

## Answering

On its own, `ferotrx host` answers ARP requests, neighbor solicitations and
pings for its hosts' addresses (and their link-local addresses). In a TCP or
UDP run the engine answers those for the client and server, as before, and
the host emulation only answers for the link-local address.

## In TCP and UDP runs

The client or server table of a TCP or UDP profile takes:

```toml
[client]
ip = "dhcp"                 # or "slaac", "dhcpv6"; or an address as before
mac = "02:dc:00:00:00:01"   # default for a client without an address; a server gets ...:02
vlan = 10
hostname = "ferotrx-client" # DHCP option 12
announce = true             # default: on for dhcp/slaac/dhcpv6, off for a static ip
groups = ["239.1.2.3"]      # of the host's IP version

[hosts]                     # optional: settings of the host emulation
setup_timeout = "30s"
retry = "1s"
igmp_version = 3
mld_version = 2
dad = true
release = true
broadcast = false
```

On the command line: `--client-ip dhcp|slaac|dhcpv6`, `--server-ip ...`,
`--client-join GROUP`, `--server-join GROUP`, `--announce`,
`--setup-timeout`. [`examples/lab-tcp-dhcp.toml`](../examples/lab-tcp-dhcp.toml)
is a TCP profile whose client gets its address by DHCP.

The run goes like this:

1. The hosts get their addresses. A host that does not get one within
   `setup_timeout` stops the run with an error saying what is missing (no
   offer, an offer but no ack, no advertisement with a prefix, a duplicate).
2. The TCP or UDP engine is built with the addresses, prefixes and gateways
   (a gateway given in the profile wins). Templates that connect to the
   server's address connect to the address the server got.
3. The run plays as usual; the hosts renew leases, answer queries and keep
   their groups beside it. Its rates and elapsed time count from step 2; its
   `duration` counts from the start.
4. At the end, leases are released and groups left.

A host that gets its address this way has one address: `ips` must be 1. The
summary and `tcp.stats`/`udp.stats` (`hosts` in the run info) show each host
with its addresses, lease and groups. `ferotrx check` checks the profile
with example addresses (192.0.2.0/24, 2001:db8::/64) in place of the ones it
will get.

## Host profiles

`ferotrx host PROFILE` reads `[[host]]` tables
([`examples/lab-hosts.toml`](../examples/lab-hosts.toml)):

```toml
format = 1
duration = "5m"             # optional; else until Ctrl-C

[options]                   # all optional
setup_timeout = "30s"
retry = "1s"
rate = 20                   # hosts started per second (default: all at once)
igmp_version = 3
mld_version = 2
dad = true
dad_wait = "1s"
release = true
broadcast = false
announcements = 2
announce_interval = "1s"

[[host]]
iface = "enp0s3"            # default: -i
count = 50                  # 50 hosts, MACs counting up
mac = "02:dc:00:00:01:01"   # default: 02:dc:00:00:01:01, then on from the last table
vlan = 10
ipv4 = "dhcp"               # or "ADDRESS/PREFIX" with gateway = "..."
ipv6 = "slaac"              # or "dhcpv6", or "ADDRESS/PREFIX" with gateway6 = "..."
hostname = "lab-{n}"
groups = ["239.1.2.3", "ff15::1234"]
announce = true

[[host]]
mac = "02:dc:00:00:03:01"
[host.router]
prefixes = ["fd00:20::/64"]
interval = "10s"
lifetime = "30m"
managed = false
other = false
```

A host needs at least an address, a group, a router table or a DHCPv6
server table; a host with a DHCP server table is one host (no `count`). The `ferotrx
host` options (`-n`, `--mac`, `--vlan`, `--ipv4`, `--gateway`, `--ipv6`,
`--gateway6`, `--join`, `--announce`, `--hostname`, `--ra` and the `--ra-*`
options, `--dhcp-pool` and the `--dhcp-*` options) make one table instead
of a profile; `--rate`, `--igmp-version`,
`--mld-version`, `--setup-timeout`, `--no-release`, `--no-dad`, `--broadcast`
and `-B` etc. go with either.

## Lab script

`sudo scripts/hosts-netns.sh` builds a bridge with IGMP/MLD snooping and a
fast querier (every 2 s, memberships expire after 5 s without a report) in a
network namespace, with dnsmasq serving DHCP (and with `IPV6=1`, DHCPv6 and
router advertisements). It checks that:

* three DHCP clients get leases (with their host names), answer pings, show
  up in the bridge's snooping table for 239.1.2.3 and are still there after
  several query intervals, count three multicast pings to the group, and
  release their leases at the end;
* a static host's gratuitous ARP makes a neighbor entry on the bridge;
* a TCP client with `--client-ip dhcp` plays 20 connections to a static
  server on another bridge port;
* with `IPV6=1`: two SLAAC hosts and a DHCPv6 host get their addresses and
  answer pings, the MLD group is in the snooping table and stays, a FeroTRX
  router's advertisements give a kernel host in another namespace an
  address and a default route through it, and a TCP client with
  `--client-ip slaac` plays 20 connections;
* a FeroTRX DHCP server on a direct link to another namespace gives busybox
  `udhcpc` its reserved address with subnet, router, DNS, domain and lease
  time, answers its ping, renews and takes its release, and leases to two
  emulated clients of the same run; with `IPV6=1` the same with a DHCPv6
  server, router advertisements and `udhcpc6`.

Extra arguments go to each `ferotrx` command (`-B af_xdp`). CI runs it over
IPv4 and IPv6, with libpcap and AF_XDP.

## Not done yet

ARP probes before using a DHCP address (RFC 5227, DHCPDECLINE), DHCP relay
agent options in the clients, DHCPv6 prefix delegation, rapid commit and
stateless DHCPv6 (information-request) in the clients; for the servers,
pools per relay or subnet, DHCPv6 relay messages, prefix delegation, ping
or ARP checks before an offer, leases that outlive the run, and static
options beyond router, DNS and domain; source-specific multicast (IGMPv3/MLDv2 include
lists), more than one address per dynamic TCP/UDP end, `host.*` methods on
the control server (`tcp.*` and `udp.*` report hosts), and the RFC timers
for leaving a compatibility mode.
