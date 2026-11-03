//! NTP as a UDP workload: client requests (mode 3) and server replies (mode 4).

use std::time::Duration;

/// Seconds from 1900 (NTP's era) to 1970 (Unix time).
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

/// NTP timestamp (32.32 fixed point, from 1900) of `unix` time.
pub(crate) fn timestamp(unix: Duration) -> u64 {
    let secs = unix.as_secs() + NTP_UNIX_OFFSET;
    let frac = (u64::from(unix.subsec_nanos()) << 32) / 1_000_000_000;
    (secs << 32) | frac
}

/// A client request whose transmit timestamp is `xmt`; the answer echoes it.
pub(crate) fn request(xmt: u64) -> Vec<u8> {
    let mut m = vec![0u8; 48];
    m[0] = (4 << 3) | 3; // version 4, client
    m[2] = 6; // poll 64 s
    m[3] = 0xec; // precision 2^-20
    m[40..48].copy_from_slice(&xmt.to_be_bytes());
    m
}

/// The server's reply to `req` at `now` (an NTP timestamp), as a stratum 2
/// server; `None` if `req` is not a client request.
pub(crate) fn reply(req: &[u8], now: u64) -> Option<Vec<u8>> {
    if req.len() < 48 || req[0] & 0x07 != 3 {
        return None;
    }
    let version = (req[0] >> 3) & 0x07;
    let mut m = vec![0u8; 48];
    m[0] = (version << 3) | 4;
    m[1] = 2; // stratum
    m[2] = req[2];
    m[3] = 0xec;
    m[4..8].copy_from_slice(&0x0000_0100u32.to_be_bytes()); // root delay ~4 ms
    m[8..12].copy_from_slice(&0x0000_0100u32.to_be_bytes()); // root dispersion
    m[12..16].copy_from_slice(b"FTRX");
    m[16..24].copy_from_slice(&now.to_be_bytes()); // reference
    m[24..32].copy_from_slice(&req[40..48]); // originate = client's transmit
    m[32..40].copy_from_slice(&now.to_be_bytes()); // receive
    m[40..48].copy_from_slice(&now.to_be_bytes()); // transmit
    Some(m)
}

/// What a client makes of a reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NtpCheck {
    /// Not a reply to this request.
    NotOurs,
    /// A server reply; `kiss` is true for a kiss-o'-death (stratum 0).
    Reply { kiss: bool },
}

pub(crate) fn check(reply: &[u8], xmt: u64) -> NtpCheck {
    if reply.len() < 48 || reply[0] & 0x07 != 4 || reply[24..32] != xmt.to_be_bytes() {
        return NtpCheck::NotOurs;
    }
    NtpCheck::Reply {
        kiss: reply[1] == 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_and_reply() {
        let t = timestamp(Duration::from_millis(1_700_000_000_500));
        assert_eq!(t >> 32, 1_700_000_000 + NTP_UNIX_OFFSET);
        assert_eq!(t & 0xffff_ffff, 1 << 31);
        let req = request(t);
        let r = reply(&req, t + 5).unwrap();
        assert_eq!(check(&r, t), NtpCheck::Reply { kiss: false });
        assert_eq!(check(&r, t + 1), NtpCheck::NotOurs);
        assert!(reply(&r, t).is_none());
        assert_eq!(check(&req, t), NtpCheck::NotOurs);
    }
}
