# The stateful TCP engine

What `ferotrx tcp` does on the wire, and what it does not try to be. The
engine is `ferotrx_core::TcpEngine` (`crates/ferotrx-core/src/tcp/engine.rs`).
It is sans-IO: it gets frames and the time, and returns frames to send, so
the tests run it on simulated links with a simulated clock
(`crates/ferotrx-core/tests/tcp_paths.rs`).

## What it is for

FeroTRX emulates both ends of TCP connections to push realistic, stateful
traffic through routers, NAT and firewalls, and to check that every byte
arrives as it was sent. It behaves like a correct, conventional endpoint so
that middleboxes and real peers accept it, and so that it can keep a long,
fast path full. It is not a reimplementation of a production TCP stack: there
is no tuning for fairness between flows and no attempt to match Linux
segment for segment.

## Options, negotiated in the handshake

Each end offers these in its SYN and uses one only when the other end
offered it too, as RFC 7323 and RFC 2018 require. Each can be turned off in
`[tcp]` of a profile or on the command line.

| Option | Default | What it does |
|---|---|---|
| MSS | 1460 (IPv6: 1440) | The largest segment announced. The smaller of the two ends' values is used. |
| Window scaling (RFC 7323) | on, shift from `receive_window` | Windows larger than 64 KB. Without it, at most 65535 bytes are in flight. |
| Timestamps (RFC 7323) | on | Every segment carries TSval/TSecr (12 bytes, taken from the data so frames keep their size). They give a round-trip sample from every ACK and enable PAWS. |
| SACK (RFC 2018) | on | The receiver reports up to three (four without timestamps) blocks that arrived after a gap; the sender retransmits only the gaps. |

`receive_window` (default 4 MiB) is the window each end announces;
`send_window` (default 4 MiB) is the most each end keeps in flight. The
program reads received bytes at once, so the receive window is always fully
open.

## Receiving

* Data in order is checked against the program and taken.
* Data out of order, inside the window, is checked on arrival and kept as a
  range; it is taken once the gap before it fills. A FIN that arrives ahead
  of missing data is kept until then. Out-of-order data is kept whether or not
  SACK is in use.
* Every segment with data or a FIN gets an ACK at once (no delayed ACKs).
  While ranges are held out of order, the ACK carries SACK blocks, the block
  of the latest segment first.
* **PAWS:** with timestamps, a segment whose TSval is older than the last
  one recorded for an in-order segment is an old duplicate (sequence numbers
  can wrap on fast links) and is dropped; it is counted as `paws_dropped`.

## Sending and congestion control

The engine follows the classic Reno/NewReno rules (RFC 5681, RFC 6582),
with SACK-based loss recovery after RFC 6675:

* **Initial window:** 10 segments (RFC 6928).
* **Slow start:** the congestion window grows by up to one segment per ACK
  until the slow-start threshold, which starts unlimited.
* **Congestion avoidance:** above the threshold, about one segment per round
  trip.
* **Limits:** in flight is at most the smallest of the congestion window, the
  other end's window and `send_window`.
* **Fast retransmit and recovery:** on the third duplicate ACK, the
  threshold and the window become half of what is in flight, and recovery
  lasts until everything sent before the loss is acknowledged.
  * With SACK, every gap below the highest SACKed byte is taken as lost and
    retransmitted once, as far as the window allows; new data follows when
    the gaps are done ("pipe" from RFC 6675, simplified: gaps below the
    highest SACKed byte count as lost, without the three-segment rule).
  * Without SACK, NewReno: the first unacknowledged segment is resent, and
    again after each partial ACK; each duplicate ACK lets one more segment
    out.
* **Retransmission timeout:** RFC 6298. Round-trip times come from
  timestamp echoes, or, without timestamps, from one timed segment at a time
  (Karn: never a retransmitted one). The handshake gives the first sample.
  Before it, the timeout is `rto` (250 ms); after, smoothed RTT plus four
  times its variation, at least `min_rto` (200 ms), at most 8 s. Each
  timeout doubles it.
* **After a timeout:** the threshold becomes half of what was in flight, the
  window one segment, and sending starts again from the first
  unacknowledged byte, skipping what the other end has SACKed.
* **Giving up:** after `syn_retries` (6) retransmissions of a SYN or SYN-ACK,
  `max_retries` (8) of data, or `idle_timeout` (30 s) with nothing received,
  the connection is reset and counted as timed out.

## What it does not do

* No delayed ACKs, Nagle, or pacing of segments within a window: segments
  go out as fast as the windows allow, and the port sends them at line rate.
* No CUBIC, BBR, ECN, or other congestion controllers; no RACK or tail loss
  probes; no D-SACK; no zero-window probing beyond sending one segment when
  nothing is in flight.
* No PMTU discovery: frames are sized by the MSS, and IPv4 sets DF.
* No urgent data, TCP Fast Open, MD5 or TCP-AO, and no simultaneous open.
* The receive window does not shrink: the program reads everything at once.

## Counters

Per side and per template: connections started, established, completed,
reset, timed out and mismatched; payload bytes sent and received;
`retransmits` (all retransmitted segments) and `timeouts` (those after a
retransmission timeout); `paws_dropped`; and `max_in_flight`, the most bytes
one connection had unacknowledged at once, which shows whether window
scaling is filling a long path.

## Tests

* `crates/ferotrx-core/tests/tcp_paths.rs`: a 50 Mbit/s path with 80 ms round
  trip (more than 400 KB in flight with window scaling, at most 65535 without
  it), window limits, option negotiation, SACK against NewReno with several
  losses per window, burst losses at a short queue, reordering, duplicates and
  loss both ways over IPv4 and IPv6, PAWS dropping an old duplicate,
  RTT-based timeouts on a 300 ms path, and per-template rates.
* `scripts/tcp-nat-netns.sh` in CI: `BDP=1` (netem: 50 Mbit/s, 40 ms each
  way) checks more than 64 KB in flight through a real Linux router, and
  `NETEM="delay 5ms reorder 10% 50% duplicate 2% loss 2%"` runs the
  template mix through reordering, duplicates and loss, over IPv4 and IPv6.
