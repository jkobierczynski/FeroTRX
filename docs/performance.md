# Performance

How fast FeroTRX sends, how to measure it so that the numbers mean
something, and the numbers measured so far. Every number here says where it
was measured. **None of them is from a physical NIC yet**: the sandbox this
is built in has veth pairs only, and the lab's VirtualBox VM has a virtual
NIC on a 5GbE host adapter. A table for a physical 10G or faster NIC is left
empty below, with the commands that fill it.

## The method: `ferotrx bench --sweep`

A sweep sends one frame size at one load for a set time, several times,
after a warm-up that is thrown away, and reports for each figure the median
of the trials with their minimum, maximum and spread (max - min in percent
of the median). The figures are frames and bits per second sent (frames,
and on the wire with the 24 bytes of FCS, preamble and gap), frames per
second received, loss, and the trials' latency p50 and p99
([benchmarking.md](benchmarking.md#the-tests)).

```sh
sudo ferotrx bench sweep.toml -i eth1 --rx eth2 --sweep --load 100 \
     -B af_xdp --workers 2 --cpus 2-3 --report sweep.json
```

with a profile such as:

```toml
[benchmark]
packet = "eth(src=02:00:00:00:01:02,dst=02:00:00:00:01:01)/ipv4(src=10.9.1.2,dst=10.9.2.2)/udp(sport=4000,dport=9000)"
vary = ["port_src=4000..4063"]   # 64 flows, so RSS spreads them
tests = ["sweep"]
sizes = [64, 512, 1514]
line_rate = "10gbps"             # the link's speed: load 100 = line rate
trial_duration = "10s"
repetitions = 5
```

The report (`sweep.json`, `sweep.txt` and `sweep.md`) starts with the test
conditions: FeroTRX version, kernel, CPU model and threads, the CPUs the
process may use, workers and the CPUs they were pinned to, the backend with
each worker's queue, each interface's driver, NIC (PCI ids, firmware), link
speed and NUMA node with its CPUs, and the profile with its SHA-256. The
Markdown file is meant to be pasted into an issue or this page as it is.

Rules that make the numbers comparable:

* **Offer more than the sender can do** (`--load 100` with `line_rate` the
  link's speed) to measure the sender; a trial below 97% of the offered rate
  is marked `sender_limited`, and then the figure is the sender's limit on
  that machine. Offer less (below what the device under test forwards) to
  measure the path with the sender out of the way.
* **Pin the workers** (`--cpus`) to CPUs on the NIC's NUMA node
  (`local_cpus` in the report) and keep other work off them. Unpinned
  workers move between cores and the spread grows.
* **One queue per worker** for AF_XDP and DPDK (`ethtool -L IFACE combined N`),
  and as many flows as workers or more, so RSS spreads the frames back.
* **Look at the spread before the median.** A spread of a few percent says
  the setup is steady; tens of percent say something else runs on those
  CPUs, the receiver drops (loss rises with it), or the machine is a VM.
* **The receiver counts too.** `--rx` with libpcap takes one core per
  receiving interface; when loss rises with more workers while `sent/s`
  rises, the receiver is the limit, not the sender (see the sandbox numbers).

## Repeatability

The same profile gives the same packets whatever the number of workers and
from run to run: the same count, the same field values (incrementing,
stepped and seeded random ones) and the same latency sequence numbers; only
the send time in each signature differs. `crates/ferotrx-core/tests/repeatability.rs`
checks this for 1, 2, 3 and 4 workers, for repeated runs, and for a seeded
Poisson model. A random field without a `seed` differs from run to run on
purpose.

Rates over repeated runs are the sweep's spread. CI runs
`SWEEP=1 scripts/bench-netns.sh` (three trials per size below a 20 Mbit/s
bottleneck, two workers pinned to CPUs 0 and 1) and requires the median sent
rate within 5% of the offered rate, the spread of the sent rate under 10%,
and no loss.

## Sandbox numbers (not a NIC)

Measured on 2026-11-08 in the build sandbox: a VM with 4 threads of an
Intel Xeon at 2.30 GHz, Linux 6.18, release build. The sending and receiving
interfaces are the two ends of one veth pair with 4 queues, so "the wire"
is a memory copy in the same kernel, and the receiver (libpcap) runs on the
same 4 threads as the senders. These numbers show the method and the
relative cost of the backends, not what a NIC does.

**The engine alone** (null output: frames built and dropped), 20 million
packets per run, median of 5 runs with min-max, workers pinned to CPUs 0-3:

| Frame | 1 worker | 2 workers | 4 workers |
|---:|---:|---:|---:|
| 64 | 4.94 Mpps (4.59-5.30) | 8.91 Mpps (8.83-10.04) | 7.84 Mpps (7.59-10.42) |
| 512 | 4.96 Mpps (4.46-5.17) | 8.75 Mpps (8.56-9.99) | 17.6 Mpps (16.7-19.6) |
| 1514 | 4.48 Mpps (4.47-5.00) | 8.42 Mpps (8.29-9.42) | 16.4 Mpps (15.7-18.5) |

```sh
ferotrx build 'eth/ipv4(src=10.0.0.1,dst=10.0.0.2)/udp(sport=1,dport=2)/raw(len=22)' -o p64.pcap
ferotrx replay --null p64.pcap -t -l 0 --limit 20000000 --workers 4 --cpus 0-3 --vary port_src=1000..1999
```

The 64-byte run on 4 workers is below 2 workers: the sandbox's 4 threads
are shared with the host, and the run is too short to settle.

**Sweep on the veth pair** (`--sweep --load 100` on a 100 Gbit/s
`line_rate`, so every trial is sender-limited; 3 trials of 2 s after a
warm-up; frames of 64 bytes go out as 70, to hold the signature). Sent
frames per second, median (min-max), then received and loss:

| Backend, workers | 64 (70) | 512 | 1514 |
|---|---:|---:|---:|
| pcap, 1 | 927k (924k-987k), loss 0.26% | 731k (705k-789k), 0.21% | 576k (575k-583k), 0.09% |
| af_xdp copy, 1 | 1.20M (1.20M-1.27M), 0.12% | 840k (838k-902k), 0.05% | 650k (648k-662k), 0.17% |
| af_xdp copy, 2 (CPUs 0-1) | 1.71M (1.60M-1.72M), 10.0% | 1.27M (1.04M-1.38M), 1.9% | 951k (910k-1.02M), 1.4% |
| af_xdp copy, 4 (CPUs 0-3) | 1.84M (1.74M-1.86M), 49.6% | 1.52M (1.30M-1.73M), 47.4% | 1.43M (1.31M-1.57M), 35.0% |
| dpdk af_packet, 1 | 716k (712k-756k), 2.3% | 568k (558k-606k), 3.4% | 467k (443k-491k), 1.9% |
| dpdk af_packet, 2 queues (CPUs 0-1) | 1.54M (1.48M-1.54M), 14.1% | 1.09M (1.07M-1.10M), 26.2% | 854k (847k-864k), 4.6% |

With 1514-byte frames, 4 AF_XDP workers send 17.4 Gbit/s of frames. The
loss with 2 and 4 workers is the receiver: libpcap on the other end of the
veth, on the same CPUs, cannot take it all. DPDK's `net_af_packet` driver
goes through the kernel's packet sockets and is slower than AF_XDP here;
with a NIC bound to `vfio-pci` it skips the kernel.

```sh
ip link add v0 numtxqueues 4 numrxqueues 4 type veth peer name v1 numtxqueues 4 numrxqueues 4
ferotrx bench sweep.toml -i v0 --rx v1 --sweep -B af_xdp --xdp-mode copy --workers 2 --cpus 0-1
ferotrx bench sweep.toml -i net_af_packet0,iface=v0,qpairs=2 --rx v1 --sweep \
    -B dpdk --dpdk-args '--no-huge -m 512 --no-pci -l 0' --workers 2 --cpus 0-1
```

Stateful TCP numbers from the same sandbox are in
[multi-core.md](multi-core.md#how-much-it-helps) and
[fast-ports.md](fast-ports.md#how-fast).

## The lab's VirtualBox VM (to be measured)

The lab machine is a Debian VM in VirtualBox on a Windows host whose NIC is a
Realtek 5GbE. The VM sees a virtual NIC (`enp0s3`, virtio or an emulated
Intel), with one queue unless VirtualBox gives it more, and no zero-copy.
What it can show: the method, the sender limit of a VM, and how much the
VM's stalls widen the spread. It cannot show what FeroTRX does on a physical
NIC, and DPDK there only runs through `net_af_packet`.

The receiving end decides what is measured:

* **Loopback through a second virtual NIC** (two adapters on the same
  internal network, `-i enp0s3 --rx enp0s8`): the VM's own limit, sender
  and receiver together.
* **Through the switch to another machine that sends the frames back**
  (a second host with a bridge or `ferotrx impair -i A -o A`): the VM plus
  the host's 5GbE path.

```sh
sudo ferotrx bench sweep.toml -i enp0s3 --rx enp0s8 --sweep --load 100 --report vm-pcap.json
sudo ferotrx bench sweep.toml -i enp0s3 --rx enp0s8 --sweep --load 100 \
     -B af_xdp --xdp-mode copy --report vm-afxdp.json
```

with `line_rate = "5gbps"` in the profile. The results go here, from the
`.md` reports:

| Backend, workers | 64 | 512 | 1514 | spread |
|---|---:|---:|---:|---:|
| pcap, 1 | | | | |
| af_xdp copy, 1 | | | | |

## A physical NIC (10G or faster; to be measured)

Needs a machine with a 10G (or faster) NIC with several queues, ideally a
second port or machine to receive, and for DPDK the NIC bound to `vfio-pci`
with hugepages. Run the sweep with 1, 2, 4 and 8 workers pinned to the NIC's
NUMA node, for pcap, AF_XDP (zero-copy where the driver has it) and DPDK,
and paste the `.md` reports' tables here:

| Backend, workers | 64 | 512 | 1514 | spread | NIC, driver, CPU |
|---|---:|---:|---:|---:|---|
| pcap, 1 | | | | | |
| af_xdp, 1 / 2 / 4 / 8 | | | | | |
| dpdk, 1 / 2 / 4 / 8 | | | | | |

Line rate at 10 Gbit/s, for sizes without the FCS as FeroTRX counts them:
14.20 Mpps at 64 bytes, 2.33 Mpps at 512 and 0.81 Mpps at 1514 (14.88 Mpps
is the classic figure for 60 bytes, 64 with the FCS).
