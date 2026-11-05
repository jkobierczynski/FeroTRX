//! RTP and RTCP (RFC 3550) for SIP calls, and the SDP (RFC 4566, RFC 3264)
//! that sets them up.

use std::net::IpAddr;
use std::time::Duration;

use crate::app::quality::{self, EModel};
use crate::app::{AppRng, MediaReport};
use crate::LatencyStats;

/// An audio codec: its payload type, clock and bytes per millisecond.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Codec {
    /// As SDP names it: `PCMU`, `opus`.
    pub name: String,
    pub payload_type: u8,
    /// The RTP clock rate.
    pub clock: u32,
    /// The `a=rtpmap` encoding: `PCMU/8000`, `opus/48000/2`.
    pub rtpmap: String,
    /// Payload bytes per 10 ms.
    pub bytes_per_10ms: usize,
}

impl Codec {
    /// PCMU, PCMA, G722, G729 or opus (at 32 kbit/s), any case.
    pub fn named(name: &str) -> Option<Self> {
        let c = |name: &str, pt, clock, rtpmap: &str, b| Codec {
            name: name.into(),
            payload_type: pt,
            clock,
            rtpmap: rtpmap.into(),
            bytes_per_10ms: b,
        };
        Some(match name.to_ascii_uppercase().as_str() {
            "PCMU" | "G711U" => c("PCMU", 0, 8000, "PCMU/8000", 80),
            "PCMA" | "G711A" => c("PCMA", 8, 8000, "PCMA/8000", 80),
            // G.722 samples at 16 kHz but RTP counts 8 kHz (RFC 3551).
            "G722" => c("G722", 9, 8000, "G722/8000", 80),
            "G729" => c("G729", 18, 8000, "G729/8000", 10),
            "OPUS" => c("opus", 111, 48000, "opus/48000/2", 40),
            _ => return None,
        })
    }

    /// The RTP timestamp step of `ptime`.
    fn ticks(&self, ptime: Duration) -> u32 {
        (u128::from(self.clock) * ptime.as_micros() / 1_000_000) as u32
    }

    /// One packet's payload of `ptime`: a 1 kHz tone for G.711 (so a
    /// capture plays as one), a pattern for the others.
    fn payload(&self, ptime: Duration) -> Vec<u8> {
        let n = (self.bytes_per_10ms as u128 * ptime.as_micros() / 10_000).max(1) as usize;
        let tone = |enc: fn(i16) -> u8| -> Vec<u8> {
            (0..n)
                .map(|i| {
                    let x = (2.0 * std::f64::consts::PI * 1000.0 * i as f64 / 8000.0).sin();
                    enc((x * 8000.0) as i16)
                })
                .collect()
        };
        match self.payload_type {
            0 => tone(ulaw),
            8 => tone(alaw),
            _ => (0..n).map(|i| (i * 37 + 11) as u8).collect(),
        }
    }
}

/// G.711 mu-law.
fn ulaw(sample: i16) -> u8 {
    const BIAS: i32 = 0x84;
    let mut s = i32::from(sample);
    let sign = if s < 0 {
        s = -s;
        0x80
    } else {
        0
    };
    let s = (s.min(32635) + BIAS) as u32;
    let exp = (31 - s.leading_zeros()).saturating_sub(7).min(7);
    let mant = (s >> (exp + 3)) & 0x0f;
    !(sign | (exp << 4) as u8 | mant as u8)
}

/// G.711 A-law.
fn alaw(sample: i16) -> u8 {
    let s = i32::from(sample) >> 3;
    let (sign, s) = if s >= 0 { (0x80u8, s) } else { (0, -s - 1) };
    let s = s.min(0xfff) as u32;
    let v = if s < 32 {
        (s >> 1) as u8
    } else {
        let exp = 31 - s.leading_zeros() - 4;
        ((exp << 4) | ((s >> exp) & 0x0f)) as u8
    };
    (sign | v) ^ 0x55
}

/// What an SDP offer or answer says about audio.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sdp {
    pub ip: Option<IpAddr>,
    pub port: u16,
    /// Payload types, in the order given, with their rtpmap encodings
    /// where the SDP has them.
    pub formats: Vec<(u8, Option<String>)>,
}

impl Sdp {
    pub fn parse(body: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(body).ok()?;
        let mut sdp = Sdp {
            ip: None,
            port: 0,
            formats: Vec::new(),
        };
        let mut audio = false;
        let mut seen_m = false;
        for line in text.lines() {
            let line = line.trim();
            if let Some(c) = line.strip_prefix("c=") {
                // Session-level, or the audio section's own.
                if !seen_m || audio {
                    sdp.ip = c.split_whitespace().nth(2).and_then(|a| a.parse().ok());
                }
            } else if let Some(m) = line.strip_prefix("m=") {
                seen_m = true;
                let w: Vec<&str> = m.split_whitespace().collect();
                audio = w.first() == Some(&"audio") && sdp.port == 0;
                if audio {
                    sdp.port = w.get(1)?.split('/').next()?.parse().ok()?;
                    sdp.formats = w[3.min(w.len())..]
                        .iter()
                        .filter_map(|f| f.parse().ok())
                        .map(|pt| (pt, None))
                        .collect();
                }
            } else if let Some(a) = line.strip_prefix("a=rtpmap:") {
                if audio {
                    let (pt, enc) = a.split_once(' ')?;
                    let pt: u8 = pt.parse().ok()?;
                    if let Some(f) = sdp.formats.iter_mut().find(|f| f.0 == pt) {
                        f.1 = Some(enc.trim().to_string());
                    }
                }
            }
        }
        (seen_m && !sdp.formats.is_empty()).then_some(sdp)
    }

    /// The first of `codecs` (in our order: `prefer_ours`, else in the
    /// SDP's) that the SDP has.
    pub fn pick(&self, codecs: &[Codec], prefer_ours: bool) -> Option<Codec> {
        let matches = |c: &Codec, f: &(u8, Option<String>)| match &f.1 {
            Some(enc) => {
                let name = enc.split('/').next().unwrap_or("");
                name.eq_ignore_ascii_case(&c.name)
            }
            // Static payload types need no rtpmap.
            None => f.0 == c.payload_type && f.0 < 96,
        };
        let found = |c: &Codec| {
            self.formats.iter().find(|f| matches(c, f)).map(|f| {
                let mut c = c.clone();
                c.payload_type = f.0;
                c
            })
        };
        if prefer_ours {
            codecs.iter().find_map(found)
        } else {
            self.formats
                .iter()
                .find_map(|f| codecs.iter().find(|c| matches(c, f)))
                .and_then(found)
        }
    }
}

/// An SDP offer (several codecs) or answer (one).
pub fn sdp(ip: IpAddr, port: u16, codecs: &[Codec], ptime: Duration, session: u64) -> Vec<u8> {
    let fam = if ip.is_ipv4() { "IP4" } else { "IP6" };
    let pts: Vec<String> = codecs.iter().map(|c| c.payload_type.to_string()).collect();
    let mut s = format!(
        "v=0\r\no=- {session} {session} IN {fam} {ip}\r\ns=FeroTRX\r\nc=IN {fam} {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP {}\r\n",
        pts.join(" ")
    );
    for c in codecs {
        s.push_str(&format!("a=rtpmap:{} {}\r\n", c.payload_type, c.rtpmap));
    }
    s.push_str(&format!("a=ptime:{}\r\na=sendrecv\r\n", ptime.as_millis()));
    s.into_bytes()
}

/// How a call's media is sent and judged.
#[derive(Clone, Debug, PartialEq)]
pub struct MediaQuality {
    /// The jitter buffer a phone would have: packets that come later than
    /// this after the earliest (relative to their timestamps) count as lost
    /// for the call's score.
    pub jitter_buffer: Duration,
    /// How often RTCP reports go: 5 s by default (RFC 3550's minimum);
    /// the first after half of it, and one at the end.
    pub rtcp_interval: Duration,
    /// The codec's equipment impairment and loss robustness for the
    /// E-model; none: the codec's own (see
    /// [`codec_factors`](crate::app::quality::codec_factors)).
    pub ie: Option<f64>,
    pub bpl: Option<f64>,
}

impl Default for MediaQuality {
    fn default() -> Self {
        Self {
            jitter_buffer: Duration::from_millis(60),
            rtcp_interval: Duration::from_secs(5),
            ie: None,
            bpl: None,
        }
    }
}

/// The packets of one call's audio, both ways.
pub struct Stream {
    pub codec: Codec,
    ptime: Duration,
    quality: MediaQuality,
    ssrc: u32,
    seq: u16,
    ts: u32,
    payload: Vec<u8>,
    /// When the next packet goes; None: not sending.
    next: Option<Duration>,
    next_rtcp: Duration,
    /// Our RTP port (RTCP is the next).
    pub local: u16,
    /// Where RTP goes on the other end; None until known.
    pub remote: Option<u16>,
    remote_rtcp: Option<u16>,
    /// Whether to send before the other end's first packet tells us where
    /// it is (behind NAT, the SDP's port may not be it).
    pub send_early: bool,
    latched: bool,
    cname: String,
    sent: u64,
    octets: u64,
    rtcp_sent: u64,
    rtcp_received: u64,
    rx: Receiver,
    /// The other end's SSRC, from its RTP.
    peer_ssrc: Option<u32>,
    /// The middle 32 bits of the NTP time of the other end's last sender
    /// report, and our wall clock when it came (for LSR and DLSR).
    last_sr: Option<(u32, Duration)>,
    /// Round trips from the other end's reports about our packets.
    rtt: LatencyStats,
    /// What the other end's last report said about our packets: fraction
    /// lost (of 256), lost in all, jitter in RTP ticks.
    their_report: Option<(u8, u64, u32)>,
}

/// Our view of the other end's packets.
#[derive(Default)]
struct Receiver {
    /// The first and highest extended sequence numbers.
    base: Option<u64>,
    max: u64,
    received: u64,
    duplicates: u64,
    reordered: u64,
    /// Which of the last 1024 sequence numbers arrived (bit i: max - i).
    window: [u64; 16],
    /// The same for those that arrived in time for the jitter buffer.
    played: [u64; 16],
    /// RFC 3550 jitter, in RTP clock ticks.
    jitter: f64,
    last_transit: Option<i64>,
    /// The shortest transit (arrival minus timestamp, in ticks) so far: the
    /// packet the jitter buffer plays on time.
    min_transit: Option<i64>,
    /// The jitter buffer, in ticks.
    buffer: i64,
    /// Packets that came after the jitter buffer would have played them.
    late: u64,
    /// Sequence numbers older than the window, whose fate is known.
    done: Pattern,
    /// The first sequence number not in `done`.
    next_done: u64,
}

/// The pattern of losses (lost or late) over sequence numbers whose fate
/// is known: a two-state model of runs, for the burst ratio.
#[derive(Clone, Copy, Default)]
struct Pattern {
    found: u64,
    lost: u64,
    /// Found then lost, and lost then found.
    to_lost: u64,
    to_found: u64,
    /// Runs of losses, the longest, and the current one.
    bursts: u64,
    max_burst: u64,
    run: u64,
    last_lost: Option<bool>,
}

impl Pattern {
    /// Adds `n` numbers in a row, all lost or all found.
    fn add(&mut self, lost: bool, n: u64) {
        if n == 0 {
            return;
        }
        match (self.last_lost, lost) {
            (Some(false), true) => self.to_lost += 1,
            (Some(true), false) => self.to_found += 1,
            _ => {}
        }
        if lost {
            if self.last_lost != Some(true) {
                self.bursts += 1;
                self.run = 0;
            }
            self.run += n;
            self.max_burst = self.max_burst.max(self.run);
            self.lost += n;
        } else {
            self.found += n;
        }
        self.last_lost = Some(lost);
    }

    /// The burst ratio (G.113): 1/(p + q), with p the chance that a found
    /// packet is followed by a lost one and q the reverse; 1 for random
    /// loss and for none.
    fn burst_ratio(&self) -> f64 {
        if self.lost == 0 || self.found == 0 {
            return 1.0;
        }
        let p = self.to_lost as f64 / self.found as f64;
        let q = self.to_found.max(1) as f64 / self.lost as f64;
        (1.0 / (p + q)).max(1.0)
    }
}

fn bit(w: &[u64; 16], back: u64) -> bool {
    back < 1024 && w[(back / 64) as usize] & (1 << (back % 64)) != 0
}

fn set(w: &mut [u64; 16], back: u64) {
    if back < 1024 {
        w[(back / 64) as usize] |= 1 << (back % 64);
    }
}

fn shift(w: &mut [u64; 16], by: u64) {
    if by >= 1024 {
        *w = [0; 16];
        return;
    }
    let (words, bits) = ((by / 64) as usize, by % 64);
    for i in (0..16usize).rev() {
        let src = i.checked_sub(words);
        let lo = src.map_or(0, |s| w[s]);
        let hi = src.and_then(|s| s.checked_sub(1)).map_or(0, |s| w[s]);
        w[i] = if bits == 0 {
            lo
        } else {
            (lo << bits) | (hi >> (64 - bits))
        };
    }
}

impl Receiver {
    fn new(buffer: i64) -> Self {
        Self {
            buffer,
            ..Default::default()
        }
    }

    /// Moves the numbers below `to` into `done`, from the played window as
    /// it is now (numbers below the window were never received).
    fn settle(&self, done: &mut Pattern, from: u64, to: u64) {
        let low = self.max.saturating_sub(1023);
        let mut n = from;
        if n < low.min(to) {
            done.add(true, low.min(to) - n);
            n = low.min(to);
        }
        let top = to.min(self.max + 1);
        while n < top {
            let found = bit(&self.played, self.max - n);
            // A run of the same, in one step.
            let mut m = n + 1;
            while m < top && bit(&self.played, self.max - m) == found {
                m += 1;
            }
            done.add(!found, m - n);
            n = m;
        }
        // Past the highest so far (a jump ahead): never received.
        if n < to {
            done.add(true, to - n);
        }
    }

    fn packet(&mut self, seq: u16, ts: u32, arrival: u64) {
        let ext = match self.base {
            None => {
                let e = u64::from(seq) + (1 << 16);
                self.base = Some(e);
                self.max = e;
                self.next_done = e;
                e
            }
            Some(_) => {
                // The extended number closest to the highest so far.
                let cycle = self.max & !0xffff;
                [cycle.wrapping_sub(1 << 16), cycle, cycle + (1 << 16)]
                    .into_iter()
                    .map(|c| c | u64::from(seq))
                    .min_by_key(|&e| e.abs_diff(self.max))
                    .unwrap_or(self.max)
            }
        };
        if ext < self.next_done {
            // Older than the window: its fate is settled.
            self.duplicates += 1;
            return;
        }
        let transit = arrival as i64 - i64::from(ts);
        let min = self.min_transit.map_or(transit, |m| m.min(transit));
        self.min_transit = Some(min);
        let on_time = transit - min <= self.buffer;
        if ext > self.max {
            // Settle what falls out of the window.
            let low = ext.saturating_sub(1023);
            if low > self.next_done {
                let mut done = self.done;
                self.settle(&mut done, self.next_done, low);
                self.done = done;
                self.next_done = low;
            }
            shift(&mut self.window, ext - self.max);
            shift(&mut self.played, ext - self.max);
            self.max = ext;
        } else if self.received > 0 {
            let back = self.max - ext;
            if bit(&self.window, back) {
                self.duplicates += 1;
                return;
            }
            set(&mut self.window, back);
            if on_time {
                set(&mut self.played, back);
            } else {
                self.late += 1;
            }
            self.reordered += 1;
            self.received += 1;
            return;
        }
        set(&mut self.window, 0);
        if on_time {
            set(&mut self.played, 0);
        } else {
            self.late += 1;
        }
        self.received += 1;
        if let Some(last) = self.last_transit {
            let d = (transit - last).unsigned_abs() as f64;
            self.jitter += (d - self.jitter) / 16.0;
        }
        self.last_transit = Some(transit);
    }

    fn expected(&self) -> u64 {
        self.base.map_or(0, |b| self.max - b + 1)
    }

    fn lost(&self) -> u64 {
        self.expected().saturating_sub(self.received)
    }

    /// The loss pattern of all numbers so far.
    fn pattern(&self) -> Pattern {
        let mut p = self.done;
        if self.base.is_some() {
            self.settle(&mut p, self.next_done, self.max + 1);
        }
        p
    }
}

/// The middle 32 bits of an NTP timestamp: RTCP's LSR clock, 1/65536 s.
fn ntp_mid(wall: Duration) -> u32 {
    (crate::udp::ntp::timestamp(wall) >> 16) as u32
}

impl Stream {
    pub fn new(
        codec: Codec,
        ptime: Duration,
        local: u16,
        rng: &mut AppRng,
        cname: String,
        quality: &MediaQuality,
    ) -> Self {
        let payload = codec.payload(ptime);
        let buffer = (u128::from(codec.clock) * quality.jitter_buffer.as_micros() / 1_000_000)
            .min(i64::MAX as u128) as i64;
        Self {
            ssrc: rng.next_u64() as u32,
            seq: rng.next_u64() as u16,
            ts: rng.next_u64() as u32,
            payload,
            codec,
            ptime,
            quality: quality.clone(),
            next: None,
            next_rtcp: Duration::MAX,
            local,
            remote: None,
            remote_rtcp: None,
            send_early: true,
            latched: false,
            cname,
            sent: 0,
            octets: 0,
            rtcp_sent: 0,
            rtcp_received: 0,
            rx: Receiver::new(buffer),
            peer_ssrc: None,
            last_sr: None,
            rtt: LatencyStats::default(),
            their_report: None,
        }
    }

    /// Where the other end said (in its SDP) it takes RTP.
    pub fn set_remote(&mut self, port: u16) {
        if !self.latched {
            self.remote = Some(port);
            self.remote_rtcp = Some(port.wrapping_add(1));
        }
    }

    /// Starts sending at `now`.
    pub fn start(&mut self, now: Duration) {
        if self.next.is_none() {
            self.next = Some(now);
            self.next_rtcp = now + self.quality.rtcp_interval / 2;
        }
    }

    pub fn sending(&self) -> bool {
        self.next.is_some()
    }

    /// When [`tick`](Self::tick) has something to do.
    pub fn wake(&self) -> Option<Duration> {
        self.next.map(|n| n.min(self.next_rtcp))
    }

    fn may_send(&self) -> bool {
        self.remote.is_some() && (self.send_early || self.latched)
    }

    /// Sends what is due: RTP every ptime (catching up at most a few
    /// packets after a stall), RTCP every `rtcp_interval`. Calls
    /// `send(from, to, data)`.
    pub fn tick(&mut self, now: Duration, wall: Duration, mut send: impl FnMut(u16, u16, Vec<u8>)) {
        let Some(mut next) = self.next else { return };
        let mut n = 0;
        while next <= now && n < 5 {
            if self.may_send() {
                let mut p = Vec::with_capacity(12 + self.payload.len());
                p.extend_from_slice(&[0x80, self.codec.payload_type & 0x7f]);
                p.extend_from_slice(&self.seq.to_be_bytes());
                p.extend_from_slice(&self.ts.to_be_bytes());
                p.extend_from_slice(&self.ssrc.to_be_bytes());
                p.extend_from_slice(&self.payload);
                send(self.local, self.remote.unwrap_or(0), p);
                self.sent += 1;
                self.octets += self.payload.len() as u64;
                self.seq = self.seq.wrapping_add(1);
            }
            // The clock runs on while we wait for the other end.
            self.ts = self.ts.wrapping_add(self.codec.ticks(self.ptime));
            next += self.ptime;
            n += 1;
        }
        if next <= now {
            // Too far behind: skip ahead, as a real sender's clock would.
            let behind = (now - next).as_micros() / self.ptime.as_micros().max(1) + 1;
            next += self.ptime * behind as u32;
            self.ts = self
                .ts
                .wrapping_add(self.codec.ticks(self.ptime).wrapping_mul(behind as u32));
        }
        self.next = Some(next);
        if now >= self.next_rtcp {
            self.next_rtcp = now + self.quality.rtcp_interval;
            if self.may_send() {
                let p = self.rtcp(wall, false);
                send(self.local + 1, self.remote_rtcp.unwrap_or(0), p);
                self.rtcp_sent += 1;
            }
        }
    }

    /// A datagram on our RTP or RTCP port from `from_port`, at engine time
    /// `now` and wall clock `wall`.
    pub fn receive(
        &mut self,
        port: u16,
        from_port: u16,
        data: &[u8],
        now: Duration,
        wall: Duration,
    ) {
        if port == self.local + 1 {
            if data.len() >= 8 && data[0] >> 6 == 2 && (200..=204).contains(&data[1]) {
                self.rtcp_received += 1;
                if !self.latched {
                    self.remote_rtcp = Some(from_port);
                }
                self.read_rtcp(data, wall);
            }
            return;
        }
        if data.len() < 12 || data[0] >> 6 != 2 {
            return;
        }
        // Symmetric RTP: answer where it comes from.
        if !self.latched {
            self.latched = true;
            self.remote = Some(from_port);
            self.remote_rtcp = Some(from_port.wrapping_add(1));
        }
        let seq = u16::from_be_bytes([data[2], data[3]]);
        let ts = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        self.peer_ssrc = Some(u32::from_be_bytes([data[8], data[9], data[10], data[11]]));
        let arrival = (now.as_nanos() * u128::from(self.codec.clock) / 1_000_000_000) as u64;
        self.rx.packet(seq, ts, arrival);
    }

    /// Reads a compound RTCP packet: the other end's sender report (for
    /// our LSR/DLSR) and its reception report about us (the round trip,
    /// and what it saw of our packets).
    fn read_rtcp(&mut self, mut data: &[u8], wall: Duration) {
        while data.len() >= 8 && data[0] >> 6 == 2 {
            let count = usize::from(data[0] & 0x1f);
            let pt = data[1];
            let len = (usize::from(u16::from_be_bytes([data[2], data[3]])) + 1) * 4;
            let Some(p) = data.get(..len) else { return };
            data = &data[len..];
            let blocks = match pt {
                200 if p.len() >= 28 => {
                    let ntp = u64::from_be_bytes(p[8..16].try_into().expect("8 bytes"));
                    self.last_sr = Some(((ntp >> 16) as u32, wall));
                    &p[28..]
                }
                201 => &p[8..],
                _ => continue,
            };
            for b in blocks.chunks(24).take(count) {
                if b.len() < 24 || u32::from_be_bytes([b[0], b[1], b[2], b[3]]) != self.ssrc {
                    continue;
                }
                let lost = u32::from_be_bytes([0, b[5], b[6], b[7]]);
                // 24 bits, signed: duplicates can make it negative.
                let lost = if lost & 0x80_0000 != 0 {
                    0
                } else {
                    u64::from(lost)
                };
                let jitter = u32::from_be_bytes([b[12], b[13], b[14], b[15]]);
                self.their_report = Some((b[4], lost, jitter));
                let lsr = u32::from_be_bytes([b[16], b[17], b[18], b[19]]);
                let dlsr = u32::from_be_bytes([b[20], b[21], b[22], b[23]]);
                if lsr != 0 {
                    let rtt = ntp_mid(wall).wrapping_sub(lsr).wrapping_sub(dlsr);
                    // Less than a minute: else a clock step or garbage.
                    if rtt < 60 << 16 {
                        let d = Duration::from_nanos((u64::from(rtt) * 1_000_000_000) >> 16);
                        self.rtt.record(Some(d));
                    }
                }
            }
        }
    }

    /// RTCP: a sender report (with a reception report once something came)
    /// and SDES CNAME, and BYE at the end.
    fn rtcp(&self, wall: Duration, bye: bool) -> Vec<u8> {
        let mut p = Vec::new();
        let rr = self.rx.received > 0;
        p.push(0x80 | u8::from(rr));
        p.push(200);
        let words: u16 = 6 + if rr { 6 } else { 0 };
        p.extend_from_slice(&words.to_be_bytes());
        p.extend_from_slice(&self.ssrc.to_be_bytes());
        let ntp = crate::udp::ntp::timestamp(wall);
        p.extend_from_slice(&ntp.to_be_bytes());
        p.extend_from_slice(&self.ts.to_be_bytes());
        p.extend_from_slice(&(self.sent as u32).to_be_bytes());
        p.extend_from_slice(&(self.octets as u32).to_be_bytes());
        if rr {
            p.extend_from_slice(&self.peer_ssrc.unwrap_or(0).to_be_bytes());
            let expected = self.rx.expected().max(1);
            let fraction = ((self.rx.lost() * 256) / expected).min(255) as u8;
            let lost = self.rx.lost().min(0x7f_ffff) as u32;
            p.push(fraction);
            p.extend_from_slice(&lost.to_be_bytes()[1..]);
            p.extend_from_slice(&(self.rx.max as u32).to_be_bytes());
            p.extend_from_slice(&(self.rx.jitter as u32).to_be_bytes());
            let (lsr, dlsr) = match self.last_sr {
                Some((lsr, at)) => {
                    let wait = wall.saturating_sub(at);
                    (lsr, ((wait.as_nanos() << 16) / 1_000_000_000) as u32)
                }
                None => (0, 0),
            };
            p.extend_from_slice(&lsr.to_be_bytes());
            p.extend_from_slice(&dlsr.to_be_bytes());
        }
        // SDES: one chunk with the CNAME, padded to a word.
        let cname = self.cname.as_bytes();
        let cname = &cname[..cname.len().min(255)];
        let mut chunk = self.ssrc.to_be_bytes().to_vec();
        chunk.extend_from_slice(&[1, cname.len() as u8]);
        chunk.extend_from_slice(cname);
        chunk.push(0);
        while !chunk.len().is_multiple_of(4) {
            chunk.push(0);
        }
        p.extend_from_slice(&[0x81, 202]);
        p.extend_from_slice(&((chunk.len() / 4) as u16).to_be_bytes());
        p.extend_from_slice(&chunk);
        if bye {
            p.extend_from_slice(&[0x81, 203, 0, 1]);
            p.extend_from_slice(&self.ssrc.to_be_bytes());
        }
        p
    }

    /// Stops sending, sends RTCP BYE and says what the stream carried.
    pub fn stop(&mut self, wall: Duration, mut send: impl FnMut(u16, u16, Vec<u8>)) -> MediaReport {
        if self.next.take().is_some() && self.may_send() {
            let p = self.rtcp(wall, true);
            send(self.local + 1, self.remote_rtcp.unwrap_or(0), p);
            self.rtcp_sent += 1;
        }
        self.report()
    }

    pub fn report(&self) -> MediaReport {
        let clock = f64::from(self.codec.clock);
        let pattern = self.rx.pattern();
        let rtt = self.rtt.mean();
        // Mouth to ear: half the round trip, the jitter buffer, one packet.
        let delay = rtt.unwrap_or_default() / 2 + self.quality.jitter_buffer + self.ptime;
        let expected = self.rx.expected();
        let unplayed = self.rx.lost() + self.rx.late;
        let (ie, bpl) = quality::codec_factors(&self.codec.name);
        let model = EModel {
            delay,
            loss: if expected == 0 {
                0.0
            } else {
                (unplayed as f64 / expected as f64).min(1.0)
            },
            burst_ratio: pattern.burst_ratio(),
            ie: self.quality.ie.unwrap_or(ie),
            bpl: self.quality.bpl.unwrap_or(bpl),
        };
        let scored = self.rx.received > 0;
        MediaReport {
            codec: self.codec.name.clone(),
            packets_sent: self.sent,
            packets_received: self.rx.received,
            lost: self.rx.lost(),
            duplicates: self.rx.duplicates,
            reordered: self.rx.reordered,
            jitter: Duration::from_secs_f64(self.rx.jitter / clock),
            rtcp_sent: self.rtcp_sent,
            rtcp_received: self.rtcp_received,
            late: self.rx.late,
            loss_bursts: pattern.bursts,
            max_burst: pattern.max_burst,
            burst_ratio: pattern.burst_ratio(),
            rtt,
            remote_lost: self.their_report.map(|r| r.1),
            remote_jitter: self
                .their_report
                .map(|r| Duration::from_secs_f64(f64::from(r.2) / clock)),
            delay,
            r_factor: scored.then(|| model.r()),
            mos: scored.then(|| model.mos()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g711_encoders() {
        // Known values: silence and full scale.
        assert_eq!(ulaw(0), 0xff);
        assert_eq!(ulaw(-1), 0x7f);
        assert_eq!(ulaw(32767), 0x80);
        assert_eq!(ulaw(-32768), 0x00);
        assert_eq!(alaw(0), 0xd5);
        assert_eq!(alaw(-8), 0x55);
        assert_eq!(alaw(32767), 0xaa);
        assert_eq!(alaw(-32768), 0x2a);
        let p = Codec::named("pcmu")
            .unwrap()
            .payload(Duration::from_millis(20));
        assert_eq!(p.len(), 160);
        assert_eq!(p[0], 0xff);
        assert_eq!(p[..8], p[8..16]);
        assert_eq!(
            Codec::named("G729")
                .unwrap()
                .payload(Duration::from_millis(20))
                .len(),
            20
        );
        assert!(Codec::named("speex").is_none());
    }

    #[test]
    fn sdp_offer_and_answer() {
        let codecs = [Codec::named("PCMU").unwrap(), Codec::named("opus").unwrap()];
        let offer = sdp(
            "10.0.0.1".parse().unwrap(),
            16384,
            &codecs,
            Duration::from_millis(20),
            7,
        );
        let s = Sdp::parse(&offer).unwrap();
        assert_eq!(s.port, 16384);
        assert_eq!(s.ip, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(s.formats.len(), 2);
        let ours = [Codec::named("opus").unwrap(), Codec::named("PCMA").unwrap()];
        assert_eq!(s.pick(&ours, true).unwrap().name, "opus");
        assert!(s.pick(&[Codec::named("G722").unwrap()], true).is_none());
        // SIPp's offer: a static type without rtpmap, video after audio.
        let sipp = b"v=0\r\no=user1 53655765 2353687637 IN IP4 10.0.0.9\r\ns=-\r\n\
c=IN IP4 10.0.0.9\r\nt=0 0\r\nm=audio 6000 RTP/AVP 0\r\nm=video 6002 RTP/AVP 31\r\n";
        let s = Sdp::parse(sipp).unwrap();
        assert_eq!((s.port, s.formats.len()), (6000, 1));
        assert_eq!(s.pick(&codecs, false).unwrap().name, "PCMU");
        // A dynamic type takes the number the offer gave it.
        let d =
            b"v=0\r\nc=IN IP6 fd00::1\r\nm=audio 4000 RTP/AVP 96\r\na=rtpmap:96 opus/48000/2\r\n";
        let s = Sdp::parse(d).unwrap();
        assert_eq!(s.pick(&codecs, true).unwrap().payload_type, 96);
        assert!(Sdp::parse(b"v=0\r\n").is_none());
    }

    #[test]
    fn receiver_counts_loss_reordering_and_duplicates() {
        let mut r = Receiver::new(1000);
        for (i, seq) in [65530u16, 65531, 65533, 65532, 65532, 65535, 0, 1, 3]
            .into_iter()
            .enumerate()
        {
            r.packet(seq, i as u32 * 160, i as u64 * 160);
        }
        // 65530..=3 is 10 numbers; 65534 and 2 are missing.
        assert_eq!(r.expected(), 10);
        assert_eq!(r.received, 8);
        assert_eq!(r.lost(), 2);
        assert_eq!(r.duplicates, 1);
        assert_eq!(r.reordered, 1);
        assert!(r.jitter < 1.0);
        // A long gap clears the window without counting false duplicates.
        r.packet(3000, 0, 0);
        r.packet(2999, 0, 0);
        assert_eq!(r.duplicates, 1);
        assert_eq!(r.reordered, 2);
    }

    #[test]
    fn stream_paces_and_reports() {
        let mut rng = AppRng::new(1);
        let c = Codec::named("PCMA").unwrap();
        let q = MediaQuality::default();
        let mut a = Stream::new(
            c.clone(),
            Duration::from_millis(20),
            16384,
            &mut rng,
            "a@x".into(),
            &q,
        );
        let mut b = Stream::new(
            c,
            Duration::from_millis(20),
            20000,
            &mut rng,
            "b@x".into(),
            &q,
        );
        a.set_remote(20000);
        a.start(Duration::ZERO);
        let mut wire = Vec::new();
        let mut t = Duration::ZERO;
        while t <= Duration::from_millis(6000) {
            a.tick(t, t, |f, to, d| wire.push((f, to, d)));
            for (f, to, d) in wire.drain(..) {
                assert_eq!(f, if to == 20000 { 16384 } else { 16385 });
                let at = t + Duration::from_millis(3);
                b.receive(to, f, &d, at, at);
            }
            t += Duration::from_millis(10);
        }
        let r = a.stop(t, |_, to, d| b.receive(to, 16385, &d, t, t));
        assert_eq!(r.packets_sent, 301);
        // At 2.5 s (the next would be at 7.5 s), and the BYE.
        assert_eq!(r.rtcp_sent, 2);
        let rb = b.report();
        assert_eq!(rb.packets_received, 301);
        assert_eq!((rb.lost, rb.duplicates, rb.reordered), (0, 0, 0));
        assert_eq!(rb.rtcp_received, 2);
        assert!(rb.jitter < Duration::from_micros(200), "{:?}", rb.jitter);
        assert!(b.latched && b.remote == Some(16384));
    }

    #[test]
    fn loss_pattern_and_burst_ratio() {
        let mut p = Pattern::default();
        // 100 found, a burst of 5 lost, 100 found, one lost, 100 found.
        for (lost, n) in [
            (false, 100),
            (true, 5),
            (false, 100),
            (true, 1),
            (false, 100),
        ] {
            p.add(lost, n);
        }
        assert_eq!((p.lost, p.found, p.bursts, p.max_burst), (6, 300, 2, 5));
        // p = 2/300, q = 2/6: bursty, so more than 1.
        let br = p.burst_ratio();
        assert!((br - 1.0 / (2.0 / 300.0 + 2.0 / 6.0)).abs() < 1e-9, "{br}");
        assert!(br > 2.5);
        // Random single losses are about 1.
        let mut r = Pattern::default();
        for _ in 0..50 {
            r.add(false, 19);
            r.add(true, 1);
        }
        assert!((r.burst_ratio() - 1.0).abs() < 0.1, "{}", r.burst_ratio());
        assert_eq!(Pattern::default().burst_ratio(), 1.0);
    }

    #[test]
    fn receiver_settles_bursts_and_late_packets() {
        // A 20 ms jitter buffer at 8 kHz: 160 ticks.
        let mut r = Receiver::new(160);
        let at = |r: &mut Receiver, seq: u16, extra: u64| {
            let ts = u32::from(seq) * 160;
            r.packet(seq, ts, u64::from(ts) + 400 + extra);
        };
        for seq in 0..2000u16 {
            // Every 100th packet lost, two in a row at 1000.
            if seq % 100 != 50 && seq != 1000 && seq != 1001 {
                // Every 200th comes 30 ms late (240 ticks): past the buffer.
                let extra = if seq % 200 == 7 { 240 } else { 0 };
                at(&mut r, seq, extra);
            }
        }
        assert_eq!(r.expected(), 2000);
        assert_eq!(r.lost(), 22);
        assert_eq!(r.late, 10);
        let p = r.pattern();
        assert_eq!(p.lost + p.found, 2000);
        assert_eq!(p.lost, 32);
        assert_eq!(p.max_burst, 2);
        assert_eq!(p.bursts, 31);
        // The settled part is behind the window.
        assert!(r.next_done > r.base.unwrap());
        // An old packet behind the window is ignored.
        at(&mut r, 3, 0);
        assert_eq!(r.duplicates, 1);
    }

    /// Two streams over a link with `one_way` delay and every `drop`th
    /// packet lost; returns both reports after `secs`.
    fn call(one_way: Duration, drop: usize, secs: u64) -> (MediaReport, MediaReport) {
        let mut rng = AppRng::new(7);
        let q = MediaQuality {
            rtcp_interval: Duration::from_secs(1),
            ..Default::default()
        };
        let c = Codec::named("PCMU").unwrap();
        let ptime = Duration::from_millis(20);
        let mut a = Stream::new(c.clone(), ptime, 10000, &mut rng, "a".into(), &q);
        let mut b = Stream::new(c, ptime, 20000, &mut rng, "b".into(), &q);
        a.set_remote(20000);
        b.set_remote(10000);
        a.start(Duration::ZERO);
        b.start(Duration::ZERO);
        // (arrival, to b?, to port, from port, data)
        let mut wire: Vec<(Duration, bool, u16, u16, Vec<u8>)> = Vec::new();
        let mut n = 0usize;
        let mut t = Duration::ZERO;
        let end = Duration::from_secs(secs);
        while t <= end {
            let mut out = Vec::new();
            a.tick(t, t, |f, to, d| out.push((true, to, f, d)));
            b.tick(t, t, |f, to, d| out.push((false, to, f, d)));
            for (to_b, to, f, d) in out {
                n += 1;
                let rtp = d[1] < 200;
                if !(rtp && drop > 0 && n.is_multiple_of(drop)) {
                    wire.push((t + one_way, to_b, to, f, d));
                }
            }
            wire.sort_by_key(|w| w.0);
            while wire.first().is_some_and(|w| w.0 <= t) {
                let (at, to_b, to, f, d) = wire.remove(0);
                let s = if to_b { &mut b } else { &mut a };
                s.receive(to, f, &d, at, at);
            }
            t += Duration::from_millis(5);
        }
        (a.report(), b.report())
    }

    #[test]
    fn rtcp_measures_the_round_trip_and_scores_the_call() {
        let (a, b) = call(Duration::from_millis(40), 0, 6);
        let rtt = a.rtt.expect("a round trip");
        assert!(
            rtt >= Duration::from_millis(79) && rtt <= Duration::from_millis(86),
            "{rtt:?}"
        );
        assert!(b.rtt.is_some());
        assert_eq!((a.lost, a.late, a.remote_lost), (0, 0, Some(0)));
        // 40 ms + 60 ms buffer + 20 ms packet.
        assert!(
            (a.delay.as_millis() as i64 - 120).abs() <= 3,
            "{:?}",
            a.delay
        );
        let mos = a.mos.unwrap();
        assert!(mos > 4.3, "{mos}");
        assert_eq!(a.burst_ratio, 1.0);
    }

    #[test]
    fn loss_lowers_the_score() {
        let (clean, _) = call(Duration::from_millis(10), 0, 4);
        // Every 10th datagram: 20% of one side's RTP.
        // (Each tick sends one of each, so it is the second side's.)
        let (lossy, other) = call(Duration::from_millis(10), 10, 4);
        assert!(lossy.lost > 10, "{lossy:?}");
        // Its last report, a second before the end.
        let told = other.remote_lost.unwrap();
        assert!(told > 0 && told <= lossy.lost, "{told}");
        let (c, l) = (clean.mos.unwrap(), lossy.mos.unwrap());
        assert!(c - l > 0.8, "{c} {l}");
        assert!(lossy.r_factor.unwrap() < 70.0);
    }
}
