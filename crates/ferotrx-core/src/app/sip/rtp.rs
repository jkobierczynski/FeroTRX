//! RTP and RTCP (RFC 3550) for SIP calls, and the SDP (RFC 4566, RFC 3264)
//! that sets them up.

use std::net::IpAddr;
use std::time::Duration;

use crate::app::{AppRng, MediaReport};

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

/// How RTCP is sent: every 5 s (RFC 3550's minimum; the first after half
/// of it), and once at the end.
const RTCP_INTERVAL: Duration = Duration::from_secs(5);

/// The packets of one call's audio, both ways.
pub struct Stream {
    pub codec: Codec,
    ptime: Duration,
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
}

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
    /// RFC 3550 jitter, in RTP clock ticks.
    jitter: f64,
    last_transit: Option<i64>,
}

impl Receiver {
    fn seen(&mut self, ext: u64) -> bool {
        let back = self.max.saturating_sub(ext);
        if back >= 1024 {
            return true; // too old to tell: count it as a duplicate
        }
        let (w, b) = ((back / 64) as usize, back % 64);
        let was = self.window[w] & (1 << b) != 0;
        self.window[w] |= 1 << b;
        was
    }

    fn shift(&mut self, by: u64) {
        if by >= 1024 {
            self.window = [0; 16];
            return;
        }
        let (words, bits) = ((by / 64) as usize, by % 64);
        for i in (0..16usize).rev() {
            let src = i.checked_sub(words);
            let lo = src.map_or(0, |s| self.window[s]);
            let hi = src
                .and_then(|s| s.checked_sub(1))
                .map_or(0, |s| self.window[s]);
            self.window[i] = if bits == 0 {
                lo
            } else {
                (lo << bits) | (hi >> (64 - bits))
            };
        }
    }

    fn packet(&mut self, seq: u16, ts: u32, arrival: u64) {
        let ext = match self.base {
            None => {
                self.base = Some(u64::from(seq) + (1 << 16));
                self.max = u64::from(seq) + (1 << 16);
                self.max
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
        if ext > self.max {
            self.shift(ext - self.max);
            self.max = ext;
        } else if self.received > 0 {
            if self.seen(ext) {
                self.duplicates += 1;
                return;
            }
            self.reordered += 1;
            self.received += 1;
            return;
        }
        self.seen(ext);
        self.received += 1;
        let transit = arrival as i64 - i64::from(ts);
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
}

impl Stream {
    pub fn new(codec: Codec, ptime: Duration, local: u16, rng: &mut AppRng, cname: String) -> Self {
        let payload = codec.payload(ptime);
        Self {
            ssrc: rng.next_u64() as u32,
            seq: rng.next_u64() as u16,
            ts: rng.next_u64() as u32,
            payload,
            codec,
            ptime,
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
            rx: Receiver::default(),
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
            self.next_rtcp = now + RTCP_INTERVAL / 2;
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
    /// packets after a stall), RTCP every 5 s. Calls `send(from, to, data)`.
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
            self.next_rtcp = now + RTCP_INTERVAL;
            if self.may_send() {
                let p = self.rtcp(wall, false);
                send(self.local + 1, self.remote_rtcp.unwrap_or(0), p);
                self.rtcp_sent += 1;
            }
        }
    }

    /// A datagram on our RTP or RTCP port from `from_port`.
    pub fn receive(&mut self, port: u16, from_port: u16, data: &[u8], now: Duration) {
        if port == self.local + 1 {
            if data.len() >= 8 && data[0] >> 6 == 2 && (200..=204).contains(&data[1]) {
                self.rtcp_received += 1;
                if !self.latched {
                    self.remote_rtcp = Some(from_port);
                }
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
        let arrival = (now.as_nanos() * u128::from(self.codec.clock) / 1_000_000_000) as u64;
        self.rx.packet(seq, ts, arrival);
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
            p.extend_from_slice(&0u32.to_be_bytes()); // their SSRC: not kept
            let expected = self.rx.expected().max(1);
            let fraction = ((self.rx.lost() * 256) / expected).min(255) as u8;
            let lost = self.rx.lost().min(0x7f_ffff) as u32;
            p.push(fraction);
            p.extend_from_slice(&lost.to_be_bytes()[1..]);
            p.extend_from_slice(&(self.rx.max as u32).to_be_bytes());
            p.extend_from_slice(&(self.rx.jitter as u32).to_be_bytes());
            p.extend_from_slice(&[0; 8]); // LSR, DLSR
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
        MediaReport {
            codec: self.codec.name.clone(),
            packets_sent: self.sent,
            packets_received: self.rx.received,
            lost: self.rx.lost(),
            duplicates: self.rx.duplicates,
            reordered: self.rx.reordered,
            jitter: Duration::from_secs_f64(self.rx.jitter / f64::from(self.codec.clock)),
            rtcp_sent: self.rtcp_sent,
            rtcp_received: self.rtcp_received,
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
        let mut r = Receiver::default();
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
        let mut a = Stream::new(
            c.clone(),
            Duration::from_millis(20),
            16384,
            &mut rng,
            "a@x".into(),
        );
        let mut b = Stream::new(c, Duration::from_millis(20), 20000, &mut rng, "b@x".into());
        a.set_remote(20000);
        a.start(Duration::ZERO);
        let mut wire = Vec::new();
        let mut t = Duration::ZERO;
        while t <= Duration::from_millis(6000) {
            a.tick(t, t, |f, to, d| wire.push((f, to, d)));
            for (f, to, d) in wire.drain(..) {
                assert_eq!(f, if to == 20000 { 16384 } else { 16385 });
                b.receive(to, f, &d, t + Duration::from_millis(3));
            }
            t += Duration::from_millis(10);
        }
        let r = a.stop(t, |_, to, d| b.receive(to, 16385, &d, t));
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
}
