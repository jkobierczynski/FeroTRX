# Call quality, jitter and latency

SIP calls (`app = "sip"`, see [Application protocols](app-protocols.md#sip-and-rtp))
carry RTP audio both ways. Each end measures the other end's packets the
way a phone does, measures the round trip with RTCP, and gives every call a
score: the ITU-T G.107 E-model's transmission rating **R** (0 to 100) and
an estimated **MOS** (mean opinion score, 1 to 4.5). TCP runs measure how
long connections take to set up and to bring the first byte.

Streams of stateless traffic (`--rx`) have their own loss, latency and
jitter: see [Loss and latency](loss-latency.md).

## What each call measures

| Measure | How |
|---|---|
| Lost | Sequence numbers between the first and the highest received that never came. |
| Duplicates, reordered | Packets seen before, and packets that came after a later one. |
| Jitter | RFC 3550 interarrival jitter, in the codec's clock, at the end of the call. |
| Late | Packets that came more than `jitter_buffer` (60 ms) after the earliest (relative to their timestamps): a phone's jitter buffer would have played silence instead. They count as lost for the score, not in `lost`. |
| Loss bursts | Runs of lost or late packets, the longest run, and the burst ratio (G.113): 1 for random loss, more when losses come together. |
| Round trip | From RTCP: each end puts the time of the last sender report it got (LSR) and how long it held it (DLSR) in its reception report, and the sender takes both off the time it got the report back (RFC 3550, 6.4.1). It needs no shared clock. |
| Remote view | What the other end's last RTCP reception report says about our packets: lost in all, and its jitter. Real phones and SIPp send these too. |

RTCP goes every `rtcp_interval` (5 s, RFC 3550's minimum; the first after
half of it) and once at the end with BYE. Short calls get at most one
round trip at 5 s; set `rtcp_interval = "1s"` for calls of a few seconds.

## The score

The E-model adds up impairments on a scale where 100 is perfect. FeroTRX
uses G.107's default values for everything it cannot measure (loudness,
room noise, talker echo: as a good handset with echo cancelling), so that
R depends only on the network and the codec:

    R = 93.2 - Id(Ta) - Ie,eff
    Ie,eff = Ie + (95 - Ie) * Ppl / (Ppl / BurstR + Bpl)

* `Ta` is the one-way mouth-to-ear delay: half the round trip, plus the
  jitter buffer, plus one packet time (`ptime`). Without a round trip yet,
  only the last two. `Id` is G.107's delay impairment: almost nothing up to
  100 ms (a little talker echo), then it grows: R is about 86 at 200 ms and
  63 at 400 ms one way.
* `Ppl` is the loss in percent, late packets included, and `BurstR` the
  burst ratio.
* `Ie` and `Bpl` are the codec's equipment impairment and robustness to
  loss (G.113 Appendix I, with packet loss concealment):

| Codec | `Ie` | `Bpl` |
|---|---|---|
| PCMU, PCMA (G.711) | 0 | 25.1 |
| G.722 | 0 | 25.1 (narrowband scale) |
| G.729 | 11 | 19 |
| Opus | 0 | 20 |

  `ie` and `bpl` in the `[sip]` table set other values (for a phone
  without concealment, G.711 is `bpl = 4.3`).

MOS follows from R (G.107 Annex B): R 93.2 is MOS 4.41, the best a
narrowband call gets. G.109 names bands of R, which the reports count calls
in: 90 and up *very satisfied*, 80 *satisfied*, 70 *some dissatisfied*, 60
*many dissatisfied*, 50 *nearly all dissatisfied*, below 50 *not
recommended*.

Some figures, for G.711 with a 60 ms buffer and 20 ms packets:

| Network | R | MOS |
|---|---|---|
| Clean, 1 ms round trip | 91.6 | 4.38 |
| 1% random loss | 88 | 4.3 |
| 5% random loss | 76 | 3.9 |
| 5% loss and 200 ms more round trip | 73 | 3.7 |

The score is a planning estimate, good for comparing networks and catching
regressions. It does not listen to the audio (that is what PESQ and POLQA
do), and wideband codecs (G.722, Opus) are scored on the narrowband scale.

## Settings

In a template's `[sip]` table (both ends):

| Key | Default | Meaning |
|---|---|---|
| `jitter_buffer` | `60ms` | Packets later than this count as late. |
| `rtcp_interval` | `5s` | How often RTCP reports go (at least `100ms`). |
| `ie` | the codec's | The codec's equipment impairment, 0 to 95. |
| `bpl` | the codec's | The codec's packet-loss robustness, 1 to 100. |

```toml
[[template]]
name = "office"
app = "sip"
[template.sip]
call = "bob"
duration = "30s"
codecs = ["PCMU"]
jitter_buffer = "40ms"
rtcp_interval = "1s"
```

## Where it shows

`ferotrx udp` prints each side's calls at the end:

    40 media streams (PCMU x40): 6040 packets sent, 5633 received, 321 lost
    (5.39%), jitter ms avg 0.75 max 2.38, 305 loss bursts (longest 2), RTCP
    160 sent 107 received, round trip ms avg 1.17 max 5.42, 212 of ours lost
    (their RTCP); MOS 3.81 (worst 3.26), R 75.1 (satisfied x9, some
    dissatisfied x24, many dissatisfied x7)

The control API and the Python client have them in `AppCounters.media`:
`late`, `loss_bursts`, `max_burst`, `rtt` (latency counters of the calls'
mean round trips), `remote_lost`, `r_avg`, `r_min`, `mos_avg`, `mos_min` and
`bands` (calls per band, best first). The GUI's run statistics show the
loss, jitter, round trip and scores. The library has every call's
`MediaReport` and their sum, `MediaStats`; `ferotrx_core::app::quality` has
the E-model itself.

Scenario checks on UDP runs (see [Scenarios](scenarios.md)) can require
them; each takes the worse of the two ways:

| Metric | Unit | Meaning |
|---|---|---|
| `mos`, `mos_min` | number | Mean and worst call MOS. |
| `r_factor`, `r_factor_min` | number | Mean and worst call R. |
| `rtt_avg`, `rtt_max` | ms | The calls' round trips, from RTCP. |
| `media_late` | count | Packets too late for the jitter buffer. |
| `media_playout_loss_pct` | % | Lost and late, of those expected. |
| `max_burst` | count | The longest run of lost or late packets. |

```toml
[[check]]
name = "voice through the firewall"
udp = "sip.toml"
require = ["mos >= 4.0", "mos_min >= 3.6", "rtt_avg < 150ms", "media_playout_loss_pct < 1"]
```

## TCP connection times

The client side of a TCP run measures, per connection, the time from its
first SYN to the end of the handshake (`connect`) and to the first byte
from the server (`first byte`, the time to first byte of a web request).
`ferotrx tcp` prints them per side and template:

    connect ms avg 1.02 p99 3.20 max 3.40; first byte ms avg 2.10 p99 5.00 max 5.60

They are `connect_time` and `first_byte` in the control API's and the
Python client's `TcpCounters`, and the scenario metrics
`connect_min`/`_avg`/`_p99`/`_max` and `first_byte_min`/`_avg`/`_p99`/`_max`.
Application protocols add their own `response_*` (request to whole answer).

## In the lab

`scripts/sip-netns.sh` checks that calls through the netns NAT router score
MOS 3.8 or more without loss and have an RTCP round trip; then, where the
kernel has netem, it puts 200 ms of delay and 5% loss on the router's link
to the server and checks that the round trip grows past 190 ms and the
server's calls score below 4.0 and at least 0.3 below the clean calls (about
3.7 on a quiet machine). On a VM, stalls make some packets late for the
jitter buffer: clean calls then score 4.3 rather than 4.38, and impaired
ones nearer 3.3, as a phone on that VM would also suffer.
