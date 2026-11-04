# Stateful TCP and UDP over AF_XDP and DPDK

FeroTRX 0.11.0 (M18) lets `ferotrx tcp` and `ferotrx udp` send and receive
through AF_XDP or DPDK, as stateless runs could already send. libpcap stays the
default and works everywhere; the fast ports are for higher connection rates.

```sh
sudo ferotrx tcp -p examples/lab-tcp.toml -i enp0s3 -B af_xdp --cps 5000 -n 50000
sudo ferotrx udp -p examples/lab-dns.toml -i enp0s3 -B af_xdp --rate 20000 -n 0 -d 30s
sudo ferotrx tcp -p examples/lab-tcp.toml -B dpdk -i 0000:03:00.0 --dpdk-args '-l 0-1'
```

The options are those of the stateless backends (see the README's "Fast send
backends"): `-B/--backend`, `--xdp-mode`, `--queue`, `--batch` and
`--dpdk-args`. A TCP or UDP profile can set them in an `[output]` table, and
`tcp.start` and `udp.start` on the control server take the same fields
(`backend`, `queue`, `xdp_mode`, `batch`, `dpdk_args`). The line printed at
the start, and `ports` in the control API's run info, say how each interface
was opened, e.g. `af_xdp on enp0s3: 2 queue(s), XDP generic mode, copy, 2 host
MAC(s)`.

## AF_XDP

A stateful run has to receive as well as send, and AF_XDP receives only
what an XDP program hands it. FeroTRX loads a small one itself, with the
`bpf` system call (no libbpf or clang needed):

* The program looks up each frame's destination MAC address in a map of the
  emulated hosts' addresses. Frames for them go to the AF_XDP socket of the
  receive queue they came in on (one socket per queue of the interface).
  Everything else goes on to the kernel, so the machine's own traffic, SSH
  among it, keeps working.
* Broadcasts and multicasts (ARP requests, neighbor solicitations) reach the
  emulated hosts through an AF_PACKET socket that takes only frames with the
  group bit set, filtered in the kernel. The kernel still sees them too.
* Frames are sent on one queue's socket (`--queue`, default 0), in batches
  handed over each time the engine has sent what it had.
* The program is attached with a BPF link, in the driver's XDP mode where
  the driver has one and in the kernel's generic mode otherwise (VirtualBox
  NICs, for example). Generic mode can only copy frames. The link goes away
  with the process, also when it is killed.

Needs Linux 5.9 or newer and root, or `CAP_NET_ADMIN`, `CAP_NET_RAW` and
`CAP_BPF`. Limits:

* One XDP program per interface: a second FeroTRX run, or another XDP
  program, on the same interface fails with a message saying so.
* At most 4096 emulated host MAC addresses per interface. Hosts with address
  ranges (`ips`) share one MAC, so this is rarely a limit.
* NICs that take VLAN tags off in hardware hide them from XDP. For VLAN labs,
  turn that off: `ethtool -K enp0s3 rxvlan off`. Broadcasts come through the
  AF_PACKET socket with their tags put back either way.
* Frames sent through AF_XDP skip the kernel's packet taps, so tcpdump on the
  sending machine does not show them; frames received through it do not show
  either. Capture on the router or the other end.

## DPDK

With `-B dpdk` the interface is a DPDK device, as for stateless runs: a PCI
address bound to a DPDK driver, a virtual device such as
`net_af_packet0,iface=eth0`, or a port number. The port is put in
promiscuous and all-multicast mode, and frames are taken from its first
receive queue, up to 9216 bytes each. DPDK takes the whole NIC, so the
machine's own traffic does not pass on a NIC bound to DPDK.

```sh
sudo ferotrx tcp examples/http.pcap -B dpdk --dpdk-args '--no-huge -m 512 --no-pci -l 0' \
     --client-iface net_af_packet0,iface=c0 --server-iface net_af_packet1,iface=s0 \
     --client-ip 192.168.10.100/24 --client-gw 192.168.10.1 \
     --server-ip 192.168.20.50/24 --server-gw 192.168.20.1 --cps 5000 -n 20000
```

## How fast

One run is one engine on one thread, playing both ends if the profile has
both. With the HTTP session of `examples/http.pcap` (17 frames, 6 KB from
the server per connection), measured in the development sandbox (4 virtual
cores, a veth pair, release build):

| | asked for | pcap | af_xdp |
| --- | --- | --- | --- |
| client and server back to back | 10000 cps | 9996, 499 retransmits | 9989, none |
| | 20000 cps | 7131, 9326 retransmits | 19235, 1530 retransmits |
| through the NAT router of `tcp-nat-netns.sh` | 10000 cps | 8687, 1224 retransmits | 9996, none |

DPDK's af_packet driver did 9991 cps through the router at 10000. At 20000
cps through the router all three fall over, because the router (the
kernel's conntrack and NAT, on the same cores) cannot keep up. The engine
itself, with memory ports in place of interfaces, manages about 25000 cps
of this session (`cargo run --release -p ferotrx-core --example engine_rate
-- 25000`).

A run asked for more than the engine or the path can take collapses rather
than levelling off: replies come late, retransmission timers fire, and the
retransmissions add load. `--concurrency` caps the connections open at once
and keeps a run on its feet.

The engines' timers used to be checked by walking every connection each
millisecond, connections in TIME_WAIT (4 s by default) included, which
limited a run to about 13000 cps. They are now kept in a queue ordered by
time, in both the TCP and the UDP engine.

## Tests

* `af_xdp_port_sends_and_receives` (ferotrx-io, needs root and
  `FEROTRX_TEST_XDP_IFACE` set to one end of a veth pair): a frame to an
  emulated host's MAC arrives through the XDP program, one to another MAC
  does not, a broadcast arrives through the AF_PACKET socket, and 5000
  frames go out, in driver and in generic XDP mode.
* CI runs `scripts/tcp-nat-netns.sh` with `-B af_xdp` on the VLAN trunk,
  without VLANs with 3% loss, over IPv6, with the template mix and at 1000
  cps, and `scripts/udp-netns.sh` with `-B af_xdp`, IPv4 and IPv6. The DPDK
  job runs both scripts through DPDK's af_packet driver. The scripts pass
  extra options on to `ferotrx tcp` and `ferotrx udp`, so any lab run can
  pick a backend the same way:

  ```sh
  sudo scripts/tcp-nat-netns.sh ./target/release/ferotrx -B af_xdp --cps 5000 -n 20000
  ```
