# Benchmarking with FeroTRX

`ferotrx bench` measures a device the way RFC 2544 describes: the highest
rate it forwards without loss (throughput), its latency at that rate, its
loss at rates above it (frame loss) and the longest burst at line rate it
takes without loss (back-to-back). It does so for a list of frame sizes, and
for size mixes such as IMIX, and writes a JSON report for scripts and a text
report for people. This page says how it measures, and where the numbers
stop being trustworthy.

```sh
sudo ferotrx bench examples/bench-rfc2544.toml -i eth1 --rx eth2 --report bench.json
# bench.json and bench.txt; override the profile from the command line:
sudo ferotrx bench examples/bench-rfc2544.toml -i eth1 --rx eth2 \
     --tests throughput --size 508 --size imix --trial-duration 60s --repetitions 3
```

`scripts/bench-netns.sh` runs it against a Linux router in a network
namespace whose output is limited to 20 Mbit/s by a token bucket, and checks
that the benchmark finds that limit; CI runs it on every change.

The [desktop GUI](gui.md#benchmarks) runs the same benchmarks on a control
server (`bench.start`, see [remote control](remote-control.md#the-protocol))
and shows every trial as it ends.

## A benchmark profile

```toml
[benchmark]
packet = "eth(src=02:00:00:00:01:02,dst=02:00:00:00:01:01)/ipv4(src=10.9.1.2,dst=10.9.2.2)/udp(sport=4000,dport=9000)"
vary = ["port_src=4000..4255"]
tests = ["throughput", "latency", "frame_loss", "back_to_back"]
sizes = ["rfc2544", "imix"]    # sizes without FCS: 60, 124, ... 1514, and a mix
line_rate = "1gbps"
trial_duration = "10s"
warmup = "2s"
repetitions = 1
loss_threshold = 0.0           # percent
```

The sending port can have an address of its own instead of fixed MACs in
`packet`: `ip` and `gateway` in `[output]` (or `--ip` and `--gateway` on
`ferotrx bench`) find the router's MAC by ARP or neighbor discovery before
the first trial, put it in every frame, and answer the router's ARP and
pings while the benchmark runs (see [the port's own
addresses](replay.md#the-ports-own-addresses-l3-mode)).

## An example report

Through the namespace router of `scripts/bench-netns.sh`, which forwards
20 Mbit/s (a token bucket) with a 25 ms queue, on a 100 Mbit/s line rate:

```text
Throughput (highest load losing at most 0%, searched to 1%):
  size   frame   load %     frames/s     Mbit/s  L1 Mbit/s  note
  1020    1020    20.39         2442      19.93      20.40
  imix   363.7    21.17         6828      19.87      21.18

Frame loss:
  size   load %    offered/s         sent     received   loss %
  1020   100.00        11973        11974         2480   79.288
  1020    80.00         9579         9579         2506   73.839
  ...
Back-to-back (longest burst without loss):
  size   load %     frames      burst  note
  1020   100.00         78     6.51ms
  imix   100.00        312     9.68ms
```

## The setup

```
   ferotrx -i eth1 ──────► device under test ──────► --rx eth2 (ferotrx)
```

FeroTRX sends on one interface and receives on another, usually on the same
machine (then both timestamps come from one clock), or on one interface when
the device sends the frames back on it. The frames are built from the
profile's `packet` (or `packets`, sent in turn), with any `vary` fields
changing from frame to frame, so the device sees many flows; its addresses
must be ones the device forwards to the receiving side. A frame-by-frame
example is `examples/bench-rfc2544.toml`.

## What a trial is

Every measurement is a series of *trials*. A trial:

1. sends the frames at one rate, evenly spaced, for `trial_duration` (or
   until `trial_packets` or a back-to-back burst is sent, whichever comes
   first), each with a 28-byte signature: a flow id of its own for this
   trial, a sequence number and the send time;
2. keeps receiving for `rx_wait` (500 ms) after the last frame, for frames
   still in the device's queues;
3. counts, for that trial's flow only: frames sent, received once, lost
   (sent minus received), duplicated and reordered, and the latency of every
   frame received.

Frames from an earlier trial that arrive late carry another flow id and do
not count. Sending and receiving are opened once for the whole benchmark.

Before the tests of each size, `warmup` sends frames at `warmup_load` (10%)
that are not counted: RFC 2544's learning frames, so that switches learn the
MAC addresses and routers resolve the next hop before anything is measured.

## Rates, loads and sizes

When one thread cannot send fast enough, `--workers N` (or `workers` in
`[output]`) sends each trial from `N` threads, each with its share of the rate,
on its own AF_XDP queue or libpcap handle ([multi-core.md](multi-core.md)).
The receiver still counts one flow; frames from different workers may arrive
slightly out of order.

Rates are given as a **load**: percent of `line_rate`, the speed of the link.
Every frame takes its length plus 24 bytes on the wire (4 bytes of FCS, 8 of
preamble and start delimiter, 12 of inter-frame gap), as RFC 2544 counts. So
at 1 Gbit/s, 100% is 1,488,095 frames per second of 64-byte frames and 81,274
of 1518-byte ones.

**Frame sizes are without the FCS**, as FeroTRX sends and counts them (the
NIC adds it): RFC 2544's 64, 128, 256, 512, 1024, 1280 and 1518 bytes are 60,
124, 252, 508, 1020, 1276 and 1514 here, and `rfc2544` in `sizes` stands for
these seven. Each size is set by cutting or padding the payload, with the IP
and UDP lengths and the checksums fixed.

A size can also be a **mix**: `imix` is 60:7, 590:4, 1514:1 (the simple IMIX,
as TRex sends it), and any `SIZE:WEIGHT,...` list works, e.g.
`"64:7,570:4,1518:1"`. The sizes take turns in proportion to their weights,
spread out evenly (7 small, 4 medium and 1 large frame in every 12, never
seven small ones in a row); add `,random` for random order with the same odds
(`,random,seed=N` repeats the same order). A mix's load uses the average frame
length. The same mixes work outside benchmarks: `sizes = "imix"` in a stream
of a traffic profile, `--sizes imix` on `replay` and `build`.

The report gives every rate three ways: frames per second, Mbit/s of frames
(their bytes, without FCS) and, for throughput, Mbit/s on the wire (with the
24 bytes).

## The tests

**Throughput.** First a trial at `max_load` (100%). If it loses more than
`loss_threshold` percent (0 by default: no loss at all), a binary search
between `min_load` and `max_load` follows: a trial at the middle, which
becomes the new low end if it passes and the new high end if it fails, until
the two are less than `resolution` (0.5% of the line rate) apart or
`max_trials` (20) trials have run. The result is the highest load that
passed, with the send rate measured in that trial. `repetitions` repeats the
whole search; the report has each result and their average.

**Latency.** Trials at the throughput found (or at `latency_load`, or at
`max_load` when throughput is not measured), `repetitions` of them, with the
latency of every received frame merged: minimum, average, p50, p99, p99.9,
maximum and RFC 3550 jitter. RFC 2544 times one tagged frame per two-minute
trial and averages 20 trials; FeroTRX times every frame, which gives the
whole distribution in one trial. Note that the throughput rate is, by
definition, the edge of loss: latency there often includes the device's
queues filling, and a trial can lose a little. `latency_load` measures at a
load you choose instead.

**Frame loss.** Trials at `max_load`, then `frame_loss_step` (10%) lower each
time, until `frame_loss_clean` (2) loads in a row lose nothing, or the load
reaches 0. The report has the loss at each load.

**Back-to-back.** Bursts at `max_load`: first one of `burst_max` frames; if it
loses any, a binary search on the burst length, down to `resolution` percent
of `burst_max`. The result is the longest burst without loss, also given as
the time it lasts at that rate; `at_limit` says the device took `burst_max`
and might take more.

Every trial is in the report too, with what was offered (the rate asked for)
and what was achieved (the rate the sender measured itself sending), the
frames sent and received, the loss and the latency.

## Stop conditions

* `trial_duration` and `trial_packets` end a trial.
* `resolution` and `max_trials` end a search.
* `frame_loss_clean` ends the frame loss test.
* `max_time` ends the whole benchmark between trials, and Ctrl-C ends the
  trial that is running and the benchmark. The report then says `stopped` and
  holds what was measured so far.

## Reports

`--report bench.json` writes the JSON report and `bench.txt` next to it; the
text also goes to the terminal. Both start with the run metadata:

* the FeroTRX version, the start time (UTC) and the command line;
* the operating system, kernel, host name, CPU model and number of threads;
* how frames were sent (`pcap on eth1`, `af_xdp on eth1 queue 0, copy mode`, ...);
* each interface's driver, NIC (PCI ids, bus address, firmware), link speed,
  MTU and MAC address, where the system tells them (Linux; elsewhere the
  name only);
* how timestamps were taken;
* the profile's path and its whole text.

The JSON has `format: "ferotrx-bench-1"`, `info` (the metadata), `config`
(the settings used, after command line overrides), `stopped`, `elapsed_s`
and `sizes`: per size its `throughput`, `latency`, `frame_loss`,
`back_to_back` and `trials`. Latencies are in microseconds.

The loss and latency report of `replay`, `run` and `build` (`--rx ...
--report`) carries the same metadata now, and per stream the offered rate
next to the achieved one.

## Limits of the method

**Timestamps.** The send time is the system clock read just before a frame is
handed to the sender; the receive time is the capture driver's timestamp
(libpcap on Linux and macOS, Npcap on Windows), taken in software when the
kernel received the frame, in microseconds. Neither is a hardware timestamp.
Both include some of the host's own path: the send side the time in the
kernel's or NIC's transmit queue (and, with AF_XDP or DPDK, up to one batch of
the time it waits to fill; paced frames are never held back for that), the
receive side the time until the kernel took the frame in. On the same machine
they still come from one clock, so latency is right to within a few
microseconds on an idle host, worse on a busy one or a VM. Measure the setup
with a cable instead of the device (or the two ends of a veth pair) to see
the floor.

**Clocks.** With the receiver on another machine (`ferotrx rx` there,
`--latency` here; not available for `bench`, which needs both ends), latency
is only as good as the agreement between the two clocks: NTP gets them within
about a millisecond, PTP within microseconds. Frames that seem to arrive
before they were sent are counted (`negative`) and reported as a clock
problem.

**The 28-byte signature.** Every benchmark frame carries the signature at the
end of its payload. In benchmarks (and in streams with `sizes`) it takes the
place of the payload's last 28 bytes, so frames keep their size, unless the
payload is shorter than that: a 60-byte UDP/IPv4 frame (42 bytes of headers)
then grows to 70, and an IPv6 one to 90. The report says so (`grown`, and a
note under the tables) and uses the length really sent for the loads. A
64-byte RFC 2544 run therefore runs at 74 bytes on the wire with UDP over
IPv4. In other streams (`--rx`, `latency = true` without `sizes`) the
signature adds 28 bytes to every frame instead, so frames already at the MTU
no longer fit.

**The sender.** One thread schedules and sends all frames. libpcap reaches a
few hundred thousand frames per second, AF_XDP and DPDK several million; a
VM far less. When the sender falls more than 3% behind the offered rate, the
trial is flagged (`sender_limited`, "sender slow" in the text) and a
throughput built on such a trial measured the sender, not the device. Watch
the achieved rates. Frames are evenly spaced at the rate asked for; a
back-to-back burst at 100% is spaced at line rate, not sent faster. When the
sender is held up (a VM whose virtual CPU is descheduled for a few
milliseconds, a busy host), it then sends the frames that are due at once to
keep the average rate, and that burst can overflow a small buffer in the
device at a load it would otherwise forward: a throughput found on a VM is a
lower bound. Build with `--release`, and on a VM expect lower and less
repeatable results than on bare metal.

**The receiver.** Receiving goes through libpcap or Npcap, one frame at a
time. At high rates it drops frames in the kernel's capture buffer before
FeroTRX sees them, and those count as frames the device lost. Check the
receiver alone first: run the benchmark over a cable or a veth pair, where
nothing should be lost, up to the rates you need. Receiving through AF_XDP
is planned for rates libpcap cannot keep up with.

**One machine.** With sender and receiver on one host, they share its CPUs,
memory and interrupt handling with each other and with everything else that
runs there; give them separate cores, and keep the host quiet.

**Trial length.** RFC 2544 asks for at least 60-second trials in the final
runs; the default here is 10 s, to make a first pass quick. Short trials can
miss loss that only shows when buffers fill slowly, and a device with large
buffers passes a short trial at a rate it cannot sustain. Use
`trial_duration = "60s"` (or `--trial-duration 60s`) for results to publish.
