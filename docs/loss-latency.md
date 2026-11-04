# Loss and latency

Mark a stream with `latency`, or give `--rx`, and every packet it sends
carries a 28-byte signature at the end of its IP payload: a flow id, a
sequence number and the time it left. A receiver on the far side counts what
arrives per flow, like TRex's latency streams and flow statistics: packets
lost, duplicated and reordered, and latency (min, average, p50, p99, p99.9,
max and RFC 3550 jitter). Lengths and checksums are fixed when the signature
is added, and the signature is written so that the checksums stay right when
the sequence number and time are filled in at the last moment, so the packets
pass routers, NAT and firewalls like any other UDP, TCP or ICMP packet.

```sh
# Send on one interface and receive on another (or the same one, when the
# router sends the packets back on it); the table comes at the end.
sudo ferotrx run examples/lab-latency.toml -i enp0s3 --rx enp0s8 -d 60s
sudo ferotrx replay capture.pcap -i enp0s3 --rx enp0s8 --pps 1000 -l 0 -d 30s
sudo ferotrx build 'eth(dst=02:00:00:00:01:01)/ipv4(dst=192.168.20.50)/udp(dport=7)/raw(len=64)' \
     -i enp0s3 --rx enp0s8 --pps 1000 -l 0 -d 30s --report report.json

# Receiver on another machine: there, then here with signatures and no --rx.
sudo ferotrx rx -i enp0s3 -d 70s
sudo ferotrx run examples/lab-latency.toml -i enp0s3 -d 60s --latency
# Or capture on the receiver with tcpdump and read it afterwards:
ferotrx rx --file receiver.pcap
```

A run through the namespace router of `scripts/latency-netns.sh` (routing and
masquerading, with 3% loss), two streams with signatures and one without:

```text
loss and latency:
  name    flow         tx         rx      lost     loss    dup    ooo       min       avg       p99       max    jitter
  voice      1       4001       3887       114   2.849%      0      0     1.3us     5.5us    19.5us    62.0us     0.4us
  bulk       7       8000       7747       253   3.163%      0      0     0.9us     5.8us    34.8us   931.0us     2.1us
  received 12414 frames, 780 without a signature
```

## How it works

* **Which streams.** In a profile, `latency = true` gives a stream its number
  (1 for the first) as flow id, `latency = 7` sets it. With `--rx`, a
  profile that marks no stream gets signatures in all of them; `--latency`
  marks every stream. `replay` and `build` send one stream, flow 1.
* **Loss.** With `--rx`, loss is what the stream sent minus what arrived;
  the receiver keeps going for `--rx-wait` (500 ms) after the last packet for
  those still on their way. On a receiver alone (`ferotrx rx`), it is the gaps
  in the sequence numbers between the first and the highest seen.
  Duplicates are told from late packets over a window of 4096 sequence numbers.
* **Latency** is the receive time, taken by the kernel (libpcap's
  timestamps, microseconds), minus the send time written just before the
  packet is handed to the sender. On one machine both come from the same
  clock. Across machines their clocks must agree (NTP gets them within about
  a millisecond, PTP far closer); packets that seem to arrive before they left
  are counted and reported as a clock problem. Percentiles are kept to within
  12.5%.
* **Size.** Each packet grows by 28 bytes, so packets already at the MTU no
  longer fit; IP fragments get no signature. Frames that are not IP get the
  signature at their end.
* **Receiving.** The receiver opens the interface in promiscuous mode through
  libpcap or Npcap, so the destination needs no listener and its own stack
  ignores the packets; frames this machine sends on the same interface are
  left out. `--report FILE` writes the table as JSON for scripts.
* **Remote control.** `ferotrx ctl start lab -i enp0s3 --rx enp0s8` reports
  loss and latency per stream in `run.stats` and the `stats` notifications,
  and `ferotrx ctl rx-start enp0s3` runs a receiver alone (`rx.*` methods).

## Lab script

`sudo scripts/latency-netns.sh` builds a router in a Linux network namespace,
with masquerading, a delay (`DELAY=5ms` by default, with the kernel's netem)
and loss (`LOSS=0.02`), runs a profile with two latency streams and one
plain one through it, and checks the report against what the router was told
to do. CI runs it with and without loss.
