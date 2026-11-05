//! QUIC's variable-length integers, frames (RFC 9000 section 19) and
//! transport parameters (section 18).

use std::ops::Range;

/// The largest value a variable-length integer holds.
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// Appends `v` as a variable-length integer, as short as it fits.
pub fn put_varint(out: &mut Vec<u8>, v: u64) {
    debug_assert!(v <= VARINT_MAX);
    if v < 1 << 6 {
        out.push(v as u8);
    } else if v < 1 << 14 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 1 << 30 {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/// The length of `v` as a variable-length integer.
pub fn varint_len(v: u64) -> usize {
    match v {
        v if v < 1 << 6 => 1,
        v if v < 1 << 14 => 2,
        v if v < 1 << 30 => 4,
        _ => 8,
    }
}

/// Reads QUIC's encodings from a buffer.
#[derive(Debug)]
pub struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, at: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.at >= self.b.len()
    }

    pub fn left(&self) -> usize {
        self.b.len().saturating_sub(self.at)
    }

    pub fn pos(&self) -> usize {
        self.at
    }

    pub fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.at)?;
        self.at += 1;
        Some(v)
    }

    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let v = self.b.get(self.at..end)?;
        self.at = end;
        Some(v)
    }

    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.bytes(4)?.try_into().ok()?))
    }

    pub fn varint(&mut self) -> Option<u64> {
        let first = *self.b.get(self.at)?;
        let len = 1usize << (first >> 6);
        let raw = self.bytes(len)?;
        let mut v = u64::from(raw[0] & 0x3f);
        for &x in &raw[1..] {
            v = (v << 8) | u64::from(x);
        }
        Some(v)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let v = &self.b[self.at.min(self.b.len())..];
        self.at = self.b.len();
        v
    }
}

/// An ACK frame's ranges, largest first, and its delay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack {
    /// Acknowledged packet numbers, inclusive ranges from the largest down.
    pub ranges: Vec<(u64, u64)>,
    /// The ack delay field, in units of 2^exponent microseconds.
    pub delay: u64,
}

impl Ack {
    pub fn largest(&self) -> u64 {
        self.ranges.first().map_or(0, |r| r.1)
    }

    pub fn contains(&self, pn: u64) -> bool {
        self.ranges.iter().any(|&(lo, hi)| (lo..=hi).contains(&pn))
    }
}

/// A frame, as far as this implementation reads or writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Padding(usize),
    Ping,
    Ack(Ack),
    ResetStream {
        id: u64,
        code: u64,
        final_size: u64,
    },
    StopSending {
        id: u64,
        code: u64,
    },
    Crypto {
        offset: u64,
        data: Vec<u8>,
    },
    NewToken(Vec<u8>),
    Stream {
        id: u64,
        offset: u64,
        data: Vec<u8>,
        fin: bool,
    },
    MaxData(u64),
    MaxStreamData {
        id: u64,
        max: u64,
    },
    MaxStreams {
        bidi: bool,
        max: u64,
    },
    DataBlocked(u64),
    StreamDataBlocked {
        id: u64,
        max: u64,
    },
    StreamsBlocked {
        bidi: bool,
        max: u64,
    },
    NewConnectionId {
        seq: u64,
        retire_prior_to: u64,
        cid: Vec<u8>,
        token: [u8; 16],
    },
    RetireConnectionId(u64),
    PathChallenge([u8; 8]),
    PathResponse([u8; 8]),
    ConnectionClose {
        /// An application's error (0x1d) rather than a transport error.
        app: bool,
        code: u64,
        frame_type: u64,
        reason: Vec<u8>,
    },
    HandshakeDone,
}

impl Frame {
    /// Not just ACK, PADDING or CONNECTION_CLOSE: the receiver acknowledges it.
    pub fn ack_eliciting(&self) -> bool {
        !matches!(
            self,
            Frame::Padding(_) | Frame::Ack(_) | Frame::ConnectionClose { .. }
        )
    }

    /// Allowed in Initial and Handshake packets.
    pub fn handshake_ok(&self) -> bool {
        matches!(
            self,
            Frame::Padding(_)
                | Frame::Ping
                | Frame::Ack(_)
                | Frame::Crypto { .. }
                | Frame::ConnectionClose { app: false, .. }
        )
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Frame::Padding(n) => out.extend(std::iter::repeat_n(0, *n)),
            Frame::Ping => out.push(0x01),
            Frame::Ack(a) => {
                out.push(0x02);
                let largest = a.largest();
                put_varint(out, largest);
                put_varint(out, a.delay);
                put_varint(out, a.ranges.len() as u64 - 1);
                let (lo, hi) = a.ranges[0];
                put_varint(out, hi - lo);
                let mut prev_lo = lo;
                for &(lo, hi) in &a.ranges[1..] {
                    put_varint(out, prev_lo - hi - 2);
                    put_varint(out, hi - lo);
                    prev_lo = lo;
                }
            }
            Frame::ResetStream {
                id,
                code,
                final_size,
            } => {
                out.push(0x04);
                put_varint(out, *id);
                put_varint(out, *code);
                put_varint(out, *final_size);
            }
            Frame::StopSending { id, code } => {
                out.push(0x05);
                put_varint(out, *id);
                put_varint(out, *code);
            }
            Frame::Crypto { offset, data } => {
                out.push(0x06);
                put_varint(out, *offset);
                put_varint(out, data.len() as u64);
                out.extend_from_slice(data);
            }
            Frame::NewToken(t) => {
                out.push(0x07);
                put_varint(out, t.len() as u64);
                out.extend_from_slice(t);
            }
            Frame::Stream {
                id,
                offset,
                data,
                fin,
            } => {
                // Always with a length, and an offset unless it is 0.
                let mut ty = 0x08 | 0x02;
                if *offset > 0 {
                    ty |= 0x04;
                }
                if *fin {
                    ty |= 0x01;
                }
                out.push(ty);
                put_varint(out, *id);
                if *offset > 0 {
                    put_varint(out, *offset);
                }
                put_varint(out, data.len() as u64);
                out.extend_from_slice(data);
            }
            Frame::MaxData(m) => {
                out.push(0x10);
                put_varint(out, *m);
            }
            Frame::MaxStreamData { id, max } => {
                out.push(0x11);
                put_varint(out, *id);
                put_varint(out, *max);
            }
            Frame::MaxStreams { bidi, max } => {
                out.push(if *bidi { 0x12 } else { 0x13 });
                put_varint(out, *max);
            }
            Frame::DataBlocked(m) => {
                out.push(0x14);
                put_varint(out, *m);
            }
            Frame::StreamDataBlocked { id, max } => {
                out.push(0x15);
                put_varint(out, *id);
                put_varint(out, *max);
            }
            Frame::StreamsBlocked { bidi, max } => {
                out.push(if *bidi { 0x16 } else { 0x17 });
                put_varint(out, *max);
            }
            Frame::NewConnectionId {
                seq,
                retire_prior_to,
                cid,
                token,
            } => {
                out.push(0x18);
                put_varint(out, *seq);
                put_varint(out, *retire_prior_to);
                out.push(cid.len() as u8);
                out.extend_from_slice(cid);
                out.extend_from_slice(token);
            }
            Frame::RetireConnectionId(s) => {
                out.push(0x19);
                put_varint(out, *s);
            }
            Frame::PathChallenge(d) => {
                out.push(0x1a);
                out.extend_from_slice(d);
            }
            Frame::PathResponse(d) => {
                out.push(0x1b);
                out.extend_from_slice(d);
            }
            Frame::ConnectionClose {
                app,
                code,
                frame_type,
                reason,
            } => {
                out.push(if *app { 0x1d } else { 0x1c });
                put_varint(out, *code);
                if !*app {
                    put_varint(out, *frame_type);
                }
                put_varint(out, reason.len() as u64);
                out.extend_from_slice(reason);
            }
            Frame::HandshakeDone => out.push(0x1e),
        }
    }

    /// The encoded length.
    pub fn encoded_len(&self) -> usize {
        let mut v = Vec::new();
        self.encode(&mut v);
        v.len()
    }

    /// The bytes a STREAM frame takes besides its data.
    pub fn stream_overhead(id: u64, offset: u64, len: usize) -> usize {
        1 + varint_len(id)
            + if offset > 0 { varint_len(offset) } else { 0 }
            + varint_len(len as u64)
    }

    /// The bytes a CRYPTO frame takes besides its data.
    pub fn crypto_overhead(offset: u64, len: usize) -> usize {
        1 + varint_len(offset) + varint_len(len as u64)
    }
}

/// Why a packet's frames could not be read: the frame type, for the
/// FRAME_ENCODING_ERROR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadFrame(pub u64);

/// Reads all frames of a packet's payload.
pub fn parse_frames(payload: &[u8]) -> Result<Vec<Frame>, BadFrame> {
    let mut r = Reader::new(payload);
    let mut out = Vec::new();
    while !r.is_empty() {
        let ty = r.varint().ok_or(BadFrame(0))?;
        let f = parse_one(ty, &mut r).ok_or(BadFrame(ty))?;
        // Runs of padding as one frame.
        if let (Frame::Padding(n), Some(Frame::Padding(m))) = (&f, out.last_mut()) {
            *m += n;
            continue;
        }
        out.push(f);
    }
    Ok(out)
}

fn parse_one(ty: u64, r: &mut Reader) -> Option<Frame> {
    Some(match ty {
        0x00 => {
            let mut n = 1;
            while r.b.get(r.at) == Some(&0) {
                r.at += 1;
                n += 1;
            }
            Frame::Padding(n)
        }
        0x01 => Frame::Ping,
        0x02 | 0x03 => {
            let largest = r.varint()?;
            let delay = r.varint()?;
            let count = r.varint()?;
            let first = r.varint()?;
            let mut lo = largest.checked_sub(first)?;
            let mut ranges = vec![(lo, largest)];
            for _ in 0..count {
                let gap = r.varint()?;
                let len = r.varint()?;
                let hi = lo.checked_sub(gap + 2)?;
                lo = hi.checked_sub(len)?;
                ranges.push((lo, hi));
                if ranges.len() > 4096 {
                    return None;
                }
            }
            if ty == 0x03 {
                for _ in 0..3 {
                    r.varint()?;
                }
            }
            Frame::Ack(Ack { ranges, delay })
        }
        0x04 => Frame::ResetStream {
            id: r.varint()?,
            code: r.varint()?,
            final_size: r.varint()?,
        },
        0x05 => Frame::StopSending {
            id: r.varint()?,
            code: r.varint()?,
        },
        0x06 => {
            let offset = r.varint()?;
            let len = r.varint()? as usize;
            Frame::Crypto {
                offset,
                data: r.bytes(len)?.to_vec(),
            }
        }
        0x07 => {
            let len = r.varint()? as usize;
            Frame::NewToken(r.bytes(len)?.to_vec())
        }
        0x08..=0x0f => {
            let id = r.varint()?;
            let offset = if ty & 0x04 != 0 { r.varint()? } else { 0 };
            let data = if ty & 0x02 != 0 {
                let len = r.varint()? as usize;
                r.bytes(len)?
            } else {
                r.rest()
            };
            if offset + data.len() as u64 > VARINT_MAX {
                return None;
            }
            Frame::Stream {
                id,
                offset,
                data: data.to_vec(),
                fin: ty & 0x01 != 0,
            }
        }
        0x10 => Frame::MaxData(r.varint()?),
        0x11 => Frame::MaxStreamData {
            id: r.varint()?,
            max: r.varint()?,
        },
        0x12 | 0x13 => Frame::MaxStreams {
            bidi: ty == 0x12,
            max: r.varint()?,
        },
        0x14 => Frame::DataBlocked(r.varint()?),
        0x15 => Frame::StreamDataBlocked {
            id: r.varint()?,
            max: r.varint()?,
        },
        0x16 | 0x17 => Frame::StreamsBlocked {
            bidi: ty == 0x16,
            max: r.varint()?,
        },
        0x18 => {
            let seq = r.varint()?;
            let retire_prior_to = r.varint()?;
            let len = r.u8()? as usize;
            if !(1..=20).contains(&len) {
                return None;
            }
            let cid = r.bytes(len)?.to_vec();
            let token = r.bytes(16)?.try_into().ok()?;
            Frame::NewConnectionId {
                seq,
                retire_prior_to,
                cid,
                token,
            }
        }
        0x19 => Frame::RetireConnectionId(r.varint()?),
        0x1a => Frame::PathChallenge(r.bytes(8)?.try_into().ok()?),
        0x1b => Frame::PathResponse(r.bytes(8)?.try_into().ok()?),
        0x1c | 0x1d => {
            let code = r.varint()?;
            let frame_type = if ty == 0x1c { r.varint()? } else { 0 };
            let len = r.varint()? as usize;
            Frame::ConnectionClose {
                app: ty == 0x1d,
                code,
                frame_type,
                reason: r.bytes(len)?.to_vec(),
            }
        }
        0x1e => Frame::HandshakeDone,
        _ => return None,
    })
}

/// Transport error codes (RFC 9000 section 20.1).
pub mod code {
    pub const NO_ERROR: u64 = 0x0;
    pub const INTERNAL_ERROR: u64 = 0x1;
    pub const CONNECTION_REFUSED: u64 = 0x2;
    pub const FLOW_CONTROL_ERROR: u64 = 0x3;
    pub const STREAM_LIMIT_ERROR: u64 = 0x4;
    pub const STREAM_STATE_ERROR: u64 = 0x5;
    pub const FINAL_SIZE_ERROR: u64 = 0x6;
    pub const FRAME_ENCODING_ERROR: u64 = 0x7;
    pub const TRANSPORT_PARAMETER_ERROR: u64 = 0x8;
    pub const PROTOCOL_VIOLATION: u64 = 0xa;
    pub const CRYPTO_BUFFER_EXCEEDED: u64 = 0xd;
    /// 0x100 + a TLS alert.
    pub const CRYPTO_ERROR: u64 = 0x100;
}

/// The name of a transport error code.
pub fn error_name(c: u64) -> String {
    use code::*;
    match c {
        NO_ERROR => "NO_ERROR".into(),
        INTERNAL_ERROR => "INTERNAL_ERROR".into(),
        CONNECTION_REFUSED => "CONNECTION_REFUSED".into(),
        FLOW_CONTROL_ERROR => "FLOW_CONTROL_ERROR".into(),
        STREAM_LIMIT_ERROR => "STREAM_LIMIT_ERROR".into(),
        STREAM_STATE_ERROR => "STREAM_STATE_ERROR".into(),
        FINAL_SIZE_ERROR => "FINAL_SIZE_ERROR".into(),
        FRAME_ENCODING_ERROR => "FRAME_ENCODING_ERROR".into(),
        TRANSPORT_PARAMETER_ERROR => "TRANSPORT_PARAMETER_ERROR".into(),
        0x9 => "CONNECTION_ID_LIMIT_ERROR".into(),
        PROTOCOL_VIOLATION => "PROTOCOL_VIOLATION".into(),
        0xb => "INVALID_TOKEN".into(),
        0xc => "APPLICATION_ERROR".into(),
        CRYPTO_BUFFER_EXCEEDED => "CRYPTO_BUFFER_EXCEEDED".into(),
        0xe => "KEY_UPDATE_ERROR".into(),
        0xf => "AEAD_LIMIT_REACHED".into(),
        0x10 => "NO_VIABLE_PATH".into(),
        c if (0x100..0x200).contains(&c) => {
            let alert = match c - 0x100 {
                0x0a => " unexpected_message",
                0x28 => " handshake_failure",
                0x2a => " bad_certificate",
                0x2b => " unsupported_certificate",
                0x2d => " certificate_expired",
                0x2e => " certificate_unknown",
                0x2f => " illegal_parameter",
                0x30 => " unknown_ca",
                0x32 => " decode_error",
                0x33 => " decrypt_error",
                0x46 => " protocol_version",
                0x50 => " internal_error",
                0x6d => " missing_extension",
                0x6e => " unsupported_extension",
                0x70 => " unrecognized_name",
                0x74 => " certificate_required",
                0x78 => " no_application_protocol",
                _ => "",
            };
            format!("CRYPTO_ERROR 0x{:x}{alert}", c - 0x100)
        }
        c => format!("error 0x{c:x}"),
    }
}

/// The transport parameters of one end (RFC 9000 section 18.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    pub original_dcid: Option<Vec<u8>>,
    /// Milliseconds; 0 for none.
    pub max_idle_timeout: u64,
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    /// Milliseconds.
    pub max_ack_delay: u64,
    pub disable_active_migration: bool,
    pub active_connection_id_limit: u64,
    pub initial_scid: Option<Vec<u8>>,
    pub retry_scid: Option<Vec<u8>>,
    pub stateless_reset_token: Option<[u8; 16]>,
}

impl Default for Params {
    /// The defaults of absent parameters.
    fn default() -> Self {
        Self {
            original_dcid: None,
            max_idle_timeout: 0,
            max_udp_payload_size: 65527,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: false,
            active_connection_id_limit: 2,
            initial_scid: None,
            retry_scid: None,
            stateless_reset_token: None,
        }
    }
}

impl Params {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let d = Params::default();
        let mut put = |id: u64, v: &[u8]| {
            put_varint(&mut out, id);
            put_varint(&mut out, v.len() as u64);
            out.extend_from_slice(v);
        };
        let int = |v: u64| {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            b
        };
        if let Some(c) = &self.original_dcid {
            put(0x00, c);
        }
        if self.max_idle_timeout != d.max_idle_timeout {
            put(0x01, &int(self.max_idle_timeout));
        }
        if let Some(t) = &self.stateless_reset_token {
            put(0x02, t);
        }
        if self.max_udp_payload_size != d.max_udp_payload_size {
            put(0x03, &int(self.max_udp_payload_size));
        }
        for (id, v, dv) in [
            (0x04, self.initial_max_data, d.initial_max_data),
            (
                0x05,
                self.initial_max_stream_data_bidi_local,
                d.initial_max_stream_data_bidi_local,
            ),
            (
                0x06,
                self.initial_max_stream_data_bidi_remote,
                d.initial_max_stream_data_bidi_remote,
            ),
            (
                0x07,
                self.initial_max_stream_data_uni,
                d.initial_max_stream_data_uni,
            ),
            (
                0x08,
                self.initial_max_streams_bidi,
                d.initial_max_streams_bidi,
            ),
            (
                0x09,
                self.initial_max_streams_uni,
                d.initial_max_streams_uni,
            ),
            (0x0a, self.ack_delay_exponent, d.ack_delay_exponent),
            (0x0b, self.max_ack_delay, d.max_ack_delay),
            (
                0x0e,
                self.active_connection_id_limit,
                d.active_connection_id_limit,
            ),
        ] {
            if v != dv {
                put(id, &int(v));
            }
        }
        if self.disable_active_migration {
            put(0x0c, &[]);
        }
        if let Some(c) = &self.initial_scid {
            put(0x0f, c);
        }
        if let Some(c) = &self.retry_scid {
            put(0x10, c);
        }
        out
    }

    /// Reads the other end's parameters; `Err` names what is wrong.
    pub fn parse(b: &[u8]) -> Result<Params, String> {
        let mut p = Params::default();
        let mut r = Reader::new(b);
        let mut seen = std::collections::BTreeSet::new();
        while !r.is_empty() {
            let id = r.varint().ok_or("a truncated parameter")?;
            let len = r.varint().ok_or("a truncated parameter")? as usize;
            let v = r.bytes(len).ok_or("a truncated parameter")?;
            if !seen.insert(id) {
                return Err(format!("parameter 0x{id:x} twice"));
            }
            let int = || -> Result<u64, String> {
                let mut r = Reader::new(v);
                let n = r
                    .varint()
                    .ok_or(format!("parameter 0x{id:x} is no number"))?;
                if !r.is_empty() {
                    return Err(format!("parameter 0x{id:x} is too long"));
                }
                Ok(n)
            };
            let cid = || -> Result<Vec<u8>, String> {
                if v.len() > 20 {
                    return Err(format!("connection id parameter 0x{id:x} is too long"));
                }
                Ok(v.to_vec())
            };
            match id {
                0x00 => p.original_dcid = Some(cid()?),
                0x01 => p.max_idle_timeout = int()?,
                0x02 => {
                    p.stateless_reset_token =
                        Some(v.try_into().map_err(|_| "a bad stateless_reset_token")?)
                }
                0x03 => {
                    p.max_udp_payload_size = int()?;
                    if p.max_udp_payload_size < 1200 {
                        return Err("max_udp_payload_size under 1200".into());
                    }
                }
                0x04 => p.initial_max_data = int()?,
                0x05 => p.initial_max_stream_data_bidi_local = int()?,
                0x06 => p.initial_max_stream_data_bidi_remote = int()?,
                0x07 => p.initial_max_stream_data_uni = int()?,
                0x08 => p.initial_max_streams_bidi = int()?,
                0x09 => p.initial_max_streams_uni = int()?,
                0x0a => {
                    p.ack_delay_exponent = int()?;
                    if p.ack_delay_exponent > 20 {
                        return Err("ack_delay_exponent over 20".into());
                    }
                }
                0x0b => {
                    p.max_ack_delay = int()?;
                    if p.max_ack_delay >= 1 << 14 {
                        return Err("max_ack_delay too large".into());
                    }
                }
                0x0c => p.disable_active_migration = true,
                0x0d => {} // preferred_address: we never migrate
                0x0e => {
                    p.active_connection_id_limit = int()?;
                    if p.active_connection_id_limit < 2 {
                        return Err("active_connection_id_limit under 2".into());
                    }
                }
                0x0f => p.initial_scid = Some(cid()?),
                0x10 => p.retry_scid = Some(cid()?),
                _ => {} // unknown and reserved (grease) parameters
            }
        }
        if p.initial_max_streams_bidi > 1 << 60 || p.initial_max_streams_uni > 1 << 60 {
            return Err("a stream limit over 2^60".into());
        }
        Ok(p)
    }
}

/// Received packet numbers or stream bytes, as sorted disjoint ranges.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RangeSet(Vec<Range<u64>>);

impl RangeSet {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn ranges(&self) -> &[Range<u64>] {
        &self.0
    }

    /// Adds `r`; returns whether anything in it was new.
    pub fn insert(&mut self, r: Range<u64>) -> bool {
        if r.is_empty() {
            return false;
        }
        if self.contains_range(&r) {
            return false;
        }
        let mut start = r.start;
        let mut end = r.end;
        let mut out = Vec::with_capacity(self.0.len() + 1);
        let mut placed = false;
        for x in self.0.drain(..) {
            if x.end < start {
                out.push(x);
            } else if x.start > end {
                if !placed {
                    out.push(start..end);
                    placed = true;
                }
                out.push(x);
            } else {
                start = start.min(x.start);
                end = end.max(x.end);
            }
        }
        if !placed {
            out.push(start..end);
        }
        self.0 = out;
        true
    }

    pub fn contains(&self, v: u64) -> bool {
        self.0.iter().any(|x| x.contains(&v))
    }

    pub fn contains_range(&self, r: &Range<u64>) -> bool {
        self.0.iter().any(|x| x.start <= r.start && r.end <= x.end)
    }

    /// Removes everything below `v`.
    pub fn trim_below(&mut self, v: u64) {
        self.0.retain(|x| x.end > v);
        if let Some(first) = self.0.first_mut() {
            first.start = first.start.max(v);
        }
    }

    pub fn max(&self) -> Option<u64> {
        self.0.last().map(|x| x.end - 1)
    }

    /// The end of the run that starts at `from` (`from` when it does not).
    pub fn contiguous_from(&self, from: u64) -> u64 {
        for x in &self.0 {
            if x.start <= from && from < x.end {
                return x.end;
            }
        }
        from
    }

    /// Takes `r` out.
    pub fn remove(&mut self, r: Range<u64>) {
        let mut out = Vec::with_capacity(self.0.len() + 1);
        for x in self.0.drain(..) {
            if x.end <= r.start || x.start >= r.end {
                out.push(x);
                continue;
            }
            if x.start < r.start {
                out.push(x.start..r.start);
            }
            if x.end > r.end {
                out.push(r.end..x.end);
            }
        }
        self.0 = out;
    }

    /// The first range, if any.
    pub fn first(&self) -> Option<Range<u64>> {
        self.0.first().cloned()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_as_in_the_rfc() {
        // RFC 9000 appendix A.1.
        for (bytes, v) in [
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c][..],
                151_288_809_941_952_652,
            ),
            (&[0x9d, 0x7f, 0x3e, 0x7d][..], 494_878_333),
            (&[0x7b, 0xbd][..], 15_293),
            (&[0x25][..], 37),
        ] {
            assert_eq!(Reader::new(bytes).varint(), Some(v));
            let mut out = Vec::new();
            put_varint(&mut out, v);
            assert_eq!(out, bytes);
            assert_eq!(varint_len(v), bytes.len());
        }
        assert_eq!(Reader::new(&[0x40, 0x25]).varint(), Some(37));
        assert_eq!(Reader::new(&[0x40]).varint(), None);
    }

    #[test]
    fn frames_round_trip() {
        let frames = vec![
            Frame::Ping,
            Frame::Ack(Ack {
                ranges: vec![(90, 100), (50, 80), (3, 3)],
                delay: 12,
            }),
            Frame::Crypto {
                offset: 300,
                data: b"hello".to_vec(),
            },
            Frame::Stream {
                id: 4,
                offset: 0,
                data: b"GET".to_vec(),
                fin: true,
            },
            Frame::Stream {
                id: 2,
                offset: 1 << 20,
                data: vec![7; 100],
                fin: false,
            },
            Frame::MaxData(1 << 30),
            Frame::MaxStreamData { id: 8, max: 99 },
            Frame::MaxStreams {
                bidi: false,
                max: 3,
            },
            Frame::NewConnectionId {
                seq: 1,
                retire_prior_to: 0,
                cid: vec![1, 2, 3, 4, 5, 6, 7, 8],
                token: [9; 16],
            },
            Frame::ResetStream {
                id: 0,
                code: 0x10c,
                final_size: 5,
            },
            Frame::StopSending { id: 0, code: 0x10c },
            Frame::PathChallenge([1; 8]),
            Frame::ConnectionClose {
                app: false,
                code: code::PROTOCOL_VIOLATION,
                frame_type: 6,
                reason: b"bad".to_vec(),
            },
            Frame::ConnectionClose {
                app: true,
                code: 0x100,
                frame_type: 0,
                reason: Vec::new(),
            },
            Frame::HandshakeDone,
            Frame::Padding(5),
        ];
        let mut b = Vec::new();
        for f in &frames {
            f.encode(&mut b);
        }
        assert_eq!(parse_frames(&b).unwrap(), frames);
        assert_eq!(parse_frames(&[0x40]), Err(BadFrame(0)));
        assert_eq!(parse_frames(&[0x21]), Err(BadFrame(0x21)));
        let s = Frame::Stream {
            id: 4,
            offset: 70000,
            data: vec![0; 1000],
            fin: false,
        };
        assert_eq!(
            s.encoded_len(),
            Frame::stream_overhead(4, 70000, 1000) + 1000
        );
    }

    #[test]
    fn params_round_trip() {
        let p = Params {
            original_dcid: Some(vec![1; 8]),
            max_idle_timeout: 30_000,
            initial_max_data: 1 << 20,
            initial_max_stream_data_bidi_local: 1 << 18,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 3,
            initial_scid: Some(vec![2; 8]),
            ..Default::default()
        };
        assert_eq!(Params::parse(&p.encode()).unwrap(), p);
        assert!(Params::parse(&[0x03, 0x02, 0x44, 0x00]).is_err()); // payload 1024
        assert!(Params::parse(&[0x01, 0x01, 0x05, 0x01, 0x01, 0x05]).is_err()); // twice
    }

    #[test]
    fn range_sets() {
        let mut s = RangeSet::new();
        assert!(s.insert(10..20));
        assert!(s.insert(30..40));
        assert!(!s.insert(12..15));
        assert!(s.insert(20..30));
        assert_eq!(s.ranges().to_vec(), vec![10..40]);
        assert!(s.insert(0..5));
        assert_eq!(s.contiguous_from(10), 40);
        assert_eq!(s.contiguous_from(5), 5);
        s.remove(15..18);
        assert_eq!(s.ranges(), &[0..5, 10..15, 18..40]);
        s.trim_below(12);
        assert_eq!(s.ranges(), &[12..15, 18..40]);
        assert_eq!(s.max(), Some(39));
    }
}
