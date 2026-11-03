# The stateful UDP engine

What `ferotrx udp` does on the wire. The engine is `ferotrx_core::UdpEngine`
(`crates/ferotrx-core/src/udp/engine.rs`). Like the TCP engine it is
sans-IO: it gets frames and the time and returns frames to send, so the tests
run it behind a simulated NAT router with a simulated clock
(`crates/ferotrx-core/tests/udp.rs`). The emulated hosts are the same as for
TCP: own MAC and IP addresses, ARP or neighbor discovery, ping.

## Transactions

A transaction is one UDP session: the datagrams of a program, in order, both
ends taking turns. A DNS lookup or an NTP request is two datagrams; a session
replayed from a capture can have more. The client sends first (a server
cannot know of a client before that), so a program that starts with a server
datagram is refused.

* **The client** starts transactions at `rate` per second (shared by weight
  between the templates without their own `rate`), each from the next source
  address and port, so every transaction is a flow of its own for a NAT router
  or firewall. `transactions` and `concurrency` limit them, overall and per
  template, as for TCP connections.
* **The server** opens a session when a datagram that can start a
  transaction arrives on a template's port (a DNS query with a question, an
  NTP client request, or anything for a replay), plays its part, and keeps the
  session for `session_timeout` after its last datagram to answer repeats.
  A different request on the ports of a finished session starts a new
  transaction.

## Matching

Each end checks that a datagram is the one it waits for:

| Template | Client takes a datagram when | Counted as mismatched when |
|---|---|---|
| `replay` | it arrives on the transaction's ports | its bytes differ from the program (`verify`) |
| `dns` | it is a response with the query's transaction id (random per transaction) | the question differs, or the response code differs from the query's expected one |
| `ntp` | it is a server reply (mode 4) whose originate timestamp is the request's transmit timestamp | |

Datagrams that match nothing are counted as `unmatched`: answers after the
transaction gave up or ended, wrong DNS ids or NTP timestamps, datagrams to
ports nobody listens on, requests the server cannot parse. DNS answers with a
response code other than NOERROR, and NTP kiss-o'-death replies, are counted
as `errors` (and still as answered).

## Timeouts and retries

When the client waits for an answer longer than `timeout` (default 1 s), it
sends its last datagram again, up to `retries` times (default 2); then the
transaction times out. The timeout does not back off. The server answers a
repeated request with the answer it sent before (counted in its `retries`),
or ignores it while it still holds the answer back (think time; counted as a
duplicate). An answer that comes again after the transaction moved on, to a
request sent twice, is a duplicate, not an error.

A server session whose client stops halfway (a longer replay) times out after
`session_timeout` and counts as timed out on the server.

## Timing

* `think_time` (in `[udp]`, or per template): how long an end waits after the
  other end's datagram before it sends its own. For DNS and NTP it delays the
  server's answer, so the response times show it.
* `keep_timing`: before each datagram, wait the gap the capture shows
  between it and the previous one (or the `delay` of a `[[message]]`).
  Think time adds to it.

TCP has the same two settings (`[tcp] keep_timing` and `think_time`,
`--keep-timing` and `--think-time`), between the messages of a connection.

## Counters

Per side, overall and per template: `sent` (transactions started), `answered`
(played to the end), `timed_out`, `unmatched`, `mismatched`, `errors`,
`retries`, `duplicates`, `active`, datagrams and payload bytes each way, and
on the client the response time from each request (its first try) to its
answer: min, mean, percentiles and max. `ferotrx udp` exits with an error if
any transaction timed out or was mismatched.

## DNS server

The DNS server is a small authoritative server for the records it has: a
question for a name with records of its type gets them, following CNAMEs (up
to 8); a name with only other types gets an empty NOERROR answer; a name
listed with an error code (`broken.lab.local SERVFAIL`) gets that code; any
other name gets NXDOMAIN. Answers have the AA and RA flags, echo RD and the
question as asked, and use no name compression. Other opcodes get NOTIMP,
queries without exactly one question FORMERR. It does not do EDNS (an OPT
record in the query is ignored), truncation, DNSSEC, or zone transfers.
Record types: A, AAAA, CNAME, NS, PTR, MX, TXT, SRV, and others as raw data
(`\# LENGTH HEX`).

With `app = "dns"` and a `pcap`, the queries come from the capture, each
expecting the response code its captured answer had, and the server's records
and error names come from the captured answers.

## NTP

The client sends NTP version 4 client requests with a unique transmit
timestamp per transaction; the server answers as a stratum 2 server with its
reference ID `FTRX` and timestamps from the system clock at the start of the
run plus the engine's time. It is for load and path testing, not for setting
clocks.

## Limits

* libpcap or Npcap for sending and receiving, as for TCP; no AF_XDP or DPDK.
* No IP fragmentation: a datagram must fit the path's MTU (1472 bytes of
  payload over IPv4 on Ethernet, 1452 over IPv6).
* A real client or server on the other end works for DNS and NTP (the netns
  script asks the emulated DNS server with `dig`); for replays the other end
  must answer exactly as captured.
