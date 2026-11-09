# Fast send backends: AF_XDP and DPDK

By default packets go out through libpcap, one system call per packet, which
works everywhere. On Windows, Npcap gets them in batches through its send
queue (see `--batch` below and [Windows](windows.md#sending-fast)). On Linux two faster senders sit behind the
same engine; pick one with `--backend` (`-B`):

| Backend | What it is | Needs |
| --- | --- | --- |
| `pcap` (default) | libpcap/Npcap | Linux, macOS or Windows |
| `af_xdp` | AF_XDP socket: packets are copied into shared memory and handed to the kernel in batches. No XDP program is loaded; sending needs none. | Linux 5.4+, root (or `CAP_NET_RAW` + `CAP_NET_ADMIN`) |
| `dpdk` | DPDK user space drivers, packets handed to the NIC in bursts | a build with `--features dpdk`; a NIC bound to `vfio-pci` and hugepages, or a DPDK virtual device |

```sh
ferotrx backends                                                  # what this build has
sudo ferotrx replay capture.pcap -i enp0s3 -B af_xdp -t --loop 0  # AF_XDP, top speed
sudo ferotrx run lab.toml -i enp0s3 -B af_xdp --xdp-mode copy     # force copy mode
sudo ferotrx replay capture.pcap -B dpdk -i 0000:03:00.0 --dpdk-args '-l 0-1' -t
sudo ferotrx replay capture.pcap -B dpdk -i net_af_packet0,iface=enp0s3 \
     --dpdk-args '--no-huge -m 512 --no-pci -l 0' -t              # DPDK without a DPDK NIC
```

Options for `af_xdp` and `dpdk` (and `--batch` for `pcap` on Windows):

* `--xdp-mode auto|copy|zerocopy` (AF_XDP): `auto` tries zero-copy and falls
  back to copy mode. Copy mode (also called SKB or generic mode) works on every
  interface, including VirtualBox and other virtual NICs, veth pairs and
  bridges; zero-copy needs a driver that supports it (i40e, ice, mlx5, ixgbe, ...).
* `--queue N`: the transmit queue (default 0). One AF_XDP socket per queue.
* `--batch N`: packets handed to the kernel or NIC at once (default 64). Paced
  streams are never held back to fill a batch: whatever is queued goes out
  before the engine waits for the next packet's time. With `pcap` it applies on
  Windows only (Npcap's `pcap_sendqueue_transmit`); `--batch 1` sends each
  packet on its own, as before 0.37.
* `--dpdk-args '...'` (DPDK): arguments for DPDK's EAL, such as cores (`-l 0-1`),
  memory (`--no-huge -m 512`) or allowed devices (`-a 0000:03:00.0`). With
  `-B dpdk`, `-i` names a DPDK device: a PCI address, a virtual device such
  as `net_af_packet0,iface=eth0` or `net_pcap0,iface=eth0`, or a port number.

Packets sent through AF_XDP or DPDK skip the kernel's packet taps, so tcpdump
or Wireshark on the sending machine does not show them. Capture on the receiver
or the router, or watch `/sys/class/net/<iface>/statistics/tx_packets`.

Packets can be up to 4096 bytes with either fast backend. The line printed at
the start says what was opened, e.g. `sending with af_xdp on enp0s3 queue 0, copy mode`.

A profile can choose the sender in an `[output]` table; command line flags and
control requests override it value by value:

```toml
[output]
backend = "af_xdp"           # pcap (default), af_xdp or dpdk
xdp_mode = "copy"            # auto (default), copy or zerocopy
queue = 0
batch = 64
dpdk_args = ["--no-huge", "-m", "512"]
workers = 2                  # engine threads (multi-core.md)
cpus = "2-3"                 # pin worker k to the k-th CPU of the list
```

On a VirtualBox VM such as the lab's Debian host, the virtual NIC has no
zero-copy support, so AF_XDP runs in copy mode; it still saves the per-packet
system call of libpcap. On a veth pair here it sends about 1.0 Mpps against
0.66 Mpps for libpcap. Bridged adapters need promiscuous mode "Allow all" as before.

Stateful TCP and UDP runs (`ferotrx tcp`, `ferotrx udp`) take the same
options and `[output]` table, and then receive through AF_XDP or DPDK too:
FeroTRX loads a small XDP program that hands frames for the emulated hosts'
MAC addresses to its AF_XDP sockets and leaves the rest to the kernel. That
roughly doubles to triples the connection rate one run reaches; see
[docs/fast-ports.md](fast-ports.md).

```sh
sudo ferotrx tcp -p examples/lab-tcp.toml -i enp0s3 -B af_xdp --cps 5000 -n 50000
```
