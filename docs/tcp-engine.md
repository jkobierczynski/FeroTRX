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
| ECN (RFC 3168) | off (`ecn = true`, `--ecn`) | Explicit Congestion Notification: see [ECN](#ecn). |

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

## Resets

* A reset ends a connection only when its sequence number is in the receive
  window, so a stray reset from an old connection on the same ports does not;
  in SYN-SENT, only one that acknowledges our SYN.
* A reset never cuts TIME_WAIT short (RFC 1337). The other end may still be
  resending its FIN because our last ACK was lost. A Linux router answers
  with a reset of its own when conntrack finds a packet INVALID (out of the
  window it tracks) and so leaves it addressed to the router; ending
  TIME_WAIT then would make us reset the other end's next FIN.
* In LAST_ACK (the other end closed first, has all our data and only our FIN
  is not acknowledged), a reset counts the connection as completed: it comes
  from an end that has left TIME_WAIT because its last ACK and our resent
  FINs were lost.

## Sending and congestion control

Loss recovery follows the NewReno rules (RFC 5681, RFC 6582), with SACK
after RFC 6675. How much the window grows and how far it backs off is up to
the congestion controller, `congestion` in `[tcp]` or in a `[[template]]`
(`--congestion` on the command line):

| `congestion` | Grows | Backs off to |
|---|---|---|
| `newreno` (default) | Slow start: up to one segment per ACK. Above the threshold: about one segment per round trip. | Half of what is in flight. |
| `cubic` (RFC 9438) | Slow start with HyStart++ (RFC 9406): when the smallest round-trip time of a round grows by an eighth of the last round's (4 to 16 ms), the queue is filling, and slow start slows to a quarter for up to five rounds, then ends, before a loss. Above the threshold: a cubic curve of the time since the last reduction, back to the window before it (W_max) and then beyond, or as fast as Reno would if that is faster. | 70% of the window (of what was in flight when the application did not fill it); with fast convergence, a second reduction below the last maximum remembers less. |

CUBIC grows by time instead of by round trips, so on a long path it gets
back to where it was much faster: on a simulated 100 Mbit/s path with a
200 ms round trip and one segment in 2000 lost, a 32 MB download takes 19 s
with CUBIC and 45 s with NewReno. The controllers are behind a trait,
`ferotrx_core::CongestionController`, that the engine calls on each ACK of
new data, each congestion event and each timeout.

* **Initial window:** 10 segments (RFC 6928).
* **Limits:** in flight is at most the smallest of the congestion window, the
  other end's window and `send_window`.
* **Fast retransmit and recovery:** on the third duplicate ACK, the
  controller sets the threshold and the window, and recovery lasts until
  everything sent before the loss is acknowledged. Duplicate ACKs for what
  was sent before a retransmission timeout start no fast retransmit (RFC
  6582, 4.1).
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
  times its variation, the latter at least `min_rto` (200 ms, as Linux's
  `rto_min`: timestamps measure every ACK, and on a steady path the
  variation shrinks to nothing), at most 8 s. Each timeout doubles it, and
  a fast retransmit restarts it for the segment it resends.
* **After a timeout:** the controller sets the threshold (NewReno: half of
  what was in flight), the window becomes one segment, and sending starts
  again from the first unacknowledged byte, skipping what the other end has
  SACKed.
* **Giving up:** after `syn_retries` (6) retransmissions of a SYN or SYN-ACK,
  `max_retries` (8) of data, or `idle_timeout` (30 s) with nothing received,
  the connection is reset and counted as timed out.

## ECN

With `ecn = true` (`--ecn`), each end asks for Explicit Congestion
Notification (RFC 3168) in the handshake: the SYN carries ECE and CWR, and
a SYN-ACK with ECE alone agrees. Only when both ends agree:

* New data goes out ECN-capable, ECT(0) in the IP header; retransmissions,
  SYNs and pure ACKs never do (RFC 3168, 6.1.5).
* A router whose queue fills (fq_codel, RED or CoDel with `ecn`) marks such
  packets Congestion Experienced instead of dropping them. The receiver
  echoes the mark with ECE on every ACK until a segment with CWR arrives.
* The sender reduces for an ECE as for a loss, through its controller, at
  most once a round trip, and not again for a loss in the same window; the
  next new segment carries CWR. Nothing is retransmitted: nothing was lost.
* A SYN that has to be sent again goes without ECE and CWR, in case a
  middlebox drops them (RFC 3168, 6.1.1.1). A SYN-ACK that agrees to the
  first SYN still sets ECN up, so both ends agree whichever SYN the server
  saw.

The counters show it: `ecn_connections` (connections that agreed),
`ce_marks` (marked segments received) and `ecn_reductions`. `ferotrx tcp`
prints them as `ECN on N, M CE marks received, K reductions for ECN`, and
scenarios can require them (`ce_marks > 0`). Accurate ECN and L4S (ECT(1))
are not done.

## What it does not do

* No delayed ACKs, Nagle, or pacing of segments within a window: segments
  go out as fast as the windows allow, and the port sends them at line rate.
* No BBR, Accurate ECN or L4S; no RACK or tail loss probes; no D-SACK; no
  zero-window probing beyond sending one segment when nothing is in flight.
* No PMTU discovery: frames are sized by the MSS, and IPv4 sets DF.
* No urgent data, TCP Fast Open, MD5 or TCP-AO, and no simultaneous open.
* The receive window does not shrink: the program reads everything at once.

## Ports and rates

The engine sends and receives through ports: libpcap/Npcap by default, or
AF_XDP and DPDK with `-B` ([fast-ports.md](fast-ports.md)). One run is one
engine on one thread, or one engine per worker with `--workers`
([multi-core.md](multi-core.md)). Connection timers (retransmission, idle, TIME_WAIT,
message waits) sit in a queue ordered by time, so connections in TIME_WAIT
cost nothing until theirs ends.

## Counters

Per side and per template: connections started, established, completed,
reset, timed out and mismatched; payload bytes sent and received;
`retransmits` (all retransmitted segments) and `timeouts` (those after a
retransmission timeout); `paws_dropped`; `max_in_flight`, the most bytes
one connection had unacknowledged at once, which shows whether window
scaling is filling a long path; and the ECN counters `ecn_connections`,
`ce_marks` and `ecn_reductions`.

## Tests

* `crates/ferotrx-core/tests/tcp_paths.rs`: a 50 Mbit/s path with 80 ms round
  trip (more than 400 KB in flight with window scaling, at most 65535 without
  it), window limits, option negotiation, SACK against NewReno with several
  losses per window, burst losses at a short queue, reordering, duplicates and
  loss both ways over IPv4 and IPv6, PAWS dropping an old duplicate,
  RTT-based timeouts on a 300 ms path, per-template rates, a reset in
  TIME_WAIT, one after the last ACK and one outside the window; CUBIC
  against NewReno on a long lossy path, ECN through a queue that marks (no
  retransmissions; without ECN the same queue drops), ECN negotiation and
  which segments are ECN-capable, and a template with its own controller.
* `crates/ferotrx-core/src/tcp/cc.rs`: CUBIC's curve (back to W_max in K
  seconds), fast convergence, HyStart++ leaving slow start when delays grow
  and staying in it after a single slow round.
* `scripts/tcp-nat-netns.sh` in CI: `BDP=1` (netem: 50 Mbit/s, 40 ms each
  way) checks more than 64 KB in flight through a real Linux router, and
  `NETEM="delay 5ms reorder 10% 50% duplicate 2% loss 2%"` runs the
  template mix through reordering, duplicates and loss, over IPv4 and IPv6.
  `ECN=1` puts a 20 Mbit/s bottleneck into fq_codel with `ecn` on the
  router: every connection agrees on ECN, the router marks and drops
  nothing, and the server slows down without retransmitting (NewReno over
  IPv4, CUBIC over IPv6); then Linux (cubic, `tcp_ecn=1`) sends to the
  emulated client through it, which echoes the marks.

## Message timing

By default each end sends its next message as soon as the other end's has
arrived. `keep_timing` (`--keep-timing`) makes it wait the gap the capture
shows between the previous message (its last byte, from either end) and this
one (`TcpMessage::delay`; `delay` in a `[[message]]`), and `think_time`
(`--think-time`) adds a pause before every answer to the other end. Gaps are
measured where the capture was taken, so they include the path's delay there.
A gap longer than `idle_timeout` makes the waiting end reset the connection.
