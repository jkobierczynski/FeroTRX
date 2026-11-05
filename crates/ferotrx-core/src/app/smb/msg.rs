//! SMB 2 and 3 messages (MS-SMB2): the transport framing, the 64-byte
//! header, compounds, signing, and the numbers both ends use.

use super::crypto::{aes_cmac, hmac_sha256, kdf};

// ---- commands -------------------------------------------------------------

pub const NEGOTIATE: u16 = 0x00;
pub const SESSION_SETUP: u16 = 0x01;
pub const LOGOFF: u16 = 0x02;
pub const TREE_CONNECT: u16 = 0x03;
pub const TREE_DISCONNECT: u16 = 0x04;
pub const CREATE: u16 = 0x05;
pub const CLOSE: u16 = 0x06;
pub const FLUSH: u16 = 0x07;
pub const READ: u16 = 0x08;
pub const WRITE: u16 = 0x09;
pub const LOCK: u16 = 0x0a;
pub const IOCTL: u16 = 0x0b;
pub const CANCEL: u16 = 0x0c;
pub const ECHO: u16 = 0x0d;
pub const QUERY_DIRECTORY: u16 = 0x0e;
pub const CHANGE_NOTIFY: u16 = 0x0f;
pub const QUERY_INFO: u16 = 0x10;
pub const SET_INFO: u16 = 0x11;
pub const OPLOCK_BREAK: u16 = 0x12;

pub fn command_name(c: u16) -> &'static str {
    match c {
        NEGOTIATE => "NEGOTIATE",
        SESSION_SETUP => "SESSION_SETUP",
        LOGOFF => "LOGOFF",
        TREE_CONNECT => "TREE_CONNECT",
        TREE_DISCONNECT => "TREE_DISCONNECT",
        CREATE => "CREATE",
        CLOSE => "CLOSE",
        FLUSH => "FLUSH",
        READ => "READ",
        WRITE => "WRITE",
        LOCK => "LOCK",
        IOCTL => "IOCTL",
        CANCEL => "CANCEL",
        ECHO => "ECHO",
        QUERY_DIRECTORY => "QUERY_DIRECTORY",
        CHANGE_NOTIFY => "CHANGE_NOTIFY",
        QUERY_INFO => "QUERY_INFO",
        SET_INFO => "SET_INFO",
        OPLOCK_BREAK => "OPLOCK_BREAK",
        _ => "UNKNOWN",
    }
}

// ---- dialects -------------------------------------------------------------

pub const SMB202: u16 = 0x0202;
pub const SMB210: u16 = 0x0210;
pub const SMB300: u16 = 0x0300;
pub const SMB302: u16 = 0x0302;
pub const SMB311: u16 = 0x0311;
/// What an SMB 1 negotiate that offers SMB 2 is answered with.
pub const SMB2_WILDCARD: u16 = 0x02ff;

pub const ALL_DIALECTS: [u16; 5] = [SMB311, SMB302, SMB300, SMB210, SMB202];

pub fn dialect_name(d: u16) -> String {
    match d {
        SMB202 => "2.0.2".into(),
        SMB210 => "2.1".into(),
        SMB300 => "3.0".into(),
        SMB302 => "3.0.2".into(),
        SMB311 => "3.1.1".into(),
        _ => format!("0x{d:04x}"),
    }
}

pub fn parse_dialect(s: &str) -> Option<u16> {
    match s.trim().trim_start_matches(['S', 's', 'M', 'm', 'B', 'b']) {
        "2.0.2" | "2.02" | "202" => Some(SMB202),
        "2.1" | "2.10" | "210" => Some(SMB210),
        "3.0" | "3" | "300" => Some(SMB300),
        "3.0.2" | "3.02" | "302" => Some(SMB302),
        "3.1.1" | "3.11" | "311" => Some(SMB311),
        _ => None,
    }
}

// ---- statuses -------------------------------------------------------------

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_PENDING: u32 = 0x0000_0103;
pub const STATUS_NOTIFY_ENUM_DIR: u32 = 0x0000_010c;
pub const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
pub const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
pub const STATUS_NOT_IMPLEMENTED: u32 = 0xc000_0002;
pub const STATUS_INVALID_INFO_CLASS: u32 = 0xc000_0003;
pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xc000_0004;
pub const STATUS_INVALID_HANDLE: u32 = 0xc000_0008;
pub const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
pub const STATUS_NO_SUCH_FILE: u32 = 0xc000_000f;
pub const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xc000_0010;
pub const STATUS_END_OF_FILE: u32 = 0xc000_0011;
pub const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xc000_0016;
pub const STATUS_ACCESS_DENIED: u32 = 0xc000_0022;
pub const STATUS_OBJECT_NAME_INVALID: u32 = 0xc000_0033;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xc000_0034;
pub const STATUS_OBJECT_NAME_COLLISION: u32 = 0xc000_0035;
pub const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xc000_003a;
pub const STATUS_SHARING_VIOLATION: u32 = 0xc000_0043;
pub const STATUS_DELETE_PENDING: u32 = 0xc000_0056;
pub const STATUS_LOGON_FAILURE: u32 = 0xc000_006d;
pub const STATUS_ACCOUNT_DISABLED: u32 = 0xc000_0072;
pub const STATUS_MEDIA_WRITE_PROTECTED: u32 = 0xc000_00a2;
pub const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xc000_00ba;
pub const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;
pub const STATUS_NETWORK_NAME_DELETED: u32 = 0xc000_00c9;
pub const STATUS_BAD_NETWORK_NAME: u32 = 0xc000_00cc;
pub const STATUS_REQUEST_NOT_ACCEPTED: u32 = 0xc000_00d0;
pub const STATUS_DIRECTORY_NOT_EMPTY: u32 = 0xc000_0101;
pub const STATUS_NOT_A_DIRECTORY: u32 = 0xc000_0103;
pub const STATUS_CANCELLED: u32 = 0xc000_0120;
pub const STATUS_FILE_CLOSED: u32 = 0xc000_0128;
pub const STATUS_FS_DRIVER_REQUIRED: u32 = 0xc000_019c;
pub const STATUS_USER_SESSION_DELETED: u32 = 0xc000_0203;
pub const STATUS_NOT_FOUND: u32 = 0xc000_0225;

const STATUSES: &[(u32, &str)] = &[
    (STATUS_SUCCESS, "SUCCESS"),
    (STATUS_PENDING, "PENDING"),
    (STATUS_NOTIFY_ENUM_DIR, "NOTIFY_ENUM_DIR"),
    (STATUS_BUFFER_OVERFLOW, "BUFFER_OVERFLOW"),
    (STATUS_NO_MORE_FILES, "NO_MORE_FILES"),
    (STATUS_NOT_IMPLEMENTED, "NOT_IMPLEMENTED"),
    (STATUS_INVALID_INFO_CLASS, "INVALID_INFO_CLASS"),
    (STATUS_INFO_LENGTH_MISMATCH, "INFO_LENGTH_MISMATCH"),
    (STATUS_INVALID_HANDLE, "INVALID_HANDLE"),
    (STATUS_INVALID_PARAMETER, "INVALID_PARAMETER"),
    (STATUS_NO_SUCH_FILE, "NO_SUCH_FILE"),
    (STATUS_INVALID_DEVICE_REQUEST, "INVALID_DEVICE_REQUEST"),
    (STATUS_END_OF_FILE, "END_OF_FILE"),
    (STATUS_MORE_PROCESSING_REQUIRED, "MORE_PROCESSING_REQUIRED"),
    (STATUS_ACCESS_DENIED, "ACCESS_DENIED"),
    (STATUS_OBJECT_NAME_INVALID, "OBJECT_NAME_INVALID"),
    (STATUS_OBJECT_NAME_NOT_FOUND, "OBJECT_NAME_NOT_FOUND"),
    (STATUS_OBJECT_NAME_COLLISION, "OBJECT_NAME_COLLISION"),
    (STATUS_OBJECT_PATH_NOT_FOUND, "OBJECT_PATH_NOT_FOUND"),
    (STATUS_SHARING_VIOLATION, "SHARING_VIOLATION"),
    (STATUS_DELETE_PENDING, "DELETE_PENDING"),
    (STATUS_LOGON_FAILURE, "LOGON_FAILURE"),
    (STATUS_ACCOUNT_DISABLED, "ACCOUNT_DISABLED"),
    (STATUS_MEDIA_WRITE_PROTECTED, "MEDIA_WRITE_PROTECTED"),
    (STATUS_FILE_IS_A_DIRECTORY, "FILE_IS_A_DIRECTORY"),
    (STATUS_NOT_SUPPORTED, "NOT_SUPPORTED"),
    (STATUS_NETWORK_NAME_DELETED, "NETWORK_NAME_DELETED"),
    (STATUS_BAD_NETWORK_NAME, "BAD_NETWORK_NAME"),
    (STATUS_REQUEST_NOT_ACCEPTED, "REQUEST_NOT_ACCEPTED"),
    (STATUS_DIRECTORY_NOT_EMPTY, "DIRECTORY_NOT_EMPTY"),
    (STATUS_NOT_A_DIRECTORY, "NOT_A_DIRECTORY"),
    (STATUS_CANCELLED, "CANCELLED"),
    (STATUS_FILE_CLOSED, "FILE_CLOSED"),
    (STATUS_FS_DRIVER_REQUIRED, "FS_DRIVER_REQUIRED"),
    (STATUS_USER_SESSION_DELETED, "USER_SESSION_DELETED"),
    (STATUS_NOT_FOUND, "NOT_FOUND"),
];

/// `STATUS_LOGON_FAILURE`, or the number for one without a name here.
pub fn status_name(s: u32) -> String {
    match STATUSES.iter().find(|(n, _)| *n == s) {
        Some((_, name)) => format!("STATUS_{name}"),
        None => format!("0x{s:08x}"),
    }
}

/// `STATUS_LOGON_FAILURE`, `LOGON_FAILURE`, `logon failure` or a number.
pub fn parse_status(s: &str) -> Option<u32> {
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x") {
        return u32::from_str_radix(h, 16).ok();
    }
    let norm = t.to_uppercase().replace([' ', '-'], "_");
    let norm = norm.strip_prefix("STATUS_").unwrap_or(&norm);
    STATUSES
        .iter()
        .find(|(_, name)| *name == norm)
        .map(|(n, _)| *n)
}

/// A warning or success, not an error.
pub fn is_success(s: u32) -> bool {
    s >> 30 != 3
}

// ---- the header -----------------------------------------------------------

pub const FLAG_RESPONSE: u32 = 0x0000_0001;
pub const FLAG_ASYNC: u32 = 0x0000_0002;
pub const FLAG_RELATED: u32 = 0x0000_0004;
pub const FLAG_SIGNED: u32 = 0x0000_0008;

pub const HEADER_LEN: usize = 64;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub credit_charge: u16,
    /// The status of a response; zero (or the channel sequence) in a request.
    pub status: u32,
    pub command: u16,
    /// Credits asked for (request) or granted (response).
    pub credits: u16,
    pub flags: u32,
    pub next: u32,
    pub message_id: u64,
    /// With `FLAG_ASYNC`: the async id instead of the process and tree ids.
    pub async_id: u64,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: [u8; 16],
}

impl Header {
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(b"\xfeSMB");
        out.extend_from_slice(&64u16.to_le_bytes());
        out.extend_from_slice(&self.credit_charge.to_le_bytes());
        out.extend_from_slice(&self.status.to_le_bytes());
        out.extend_from_slice(&self.command.to_le_bytes());
        out.extend_from_slice(&self.credits.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.next.to_le_bytes());
        out.extend_from_slice(&self.message_id.to_le_bytes());
        if self.flags & FLAG_ASYNC != 0 {
            out.extend_from_slice(&self.async_id.to_le_bytes());
        } else {
            out.extend_from_slice(&0xfeffu32.to_le_bytes()); // process id
            out.extend_from_slice(&self.tree_id.to_le_bytes());
        }
        out.extend_from_slice(&self.session_id.to_le_bytes());
        out.extend_from_slice(&self.signature);
    }

    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < HEADER_LEN || &b[..4] != b"\xfeSMB" {
            return None;
        }
        let r = R(b);
        let flags = r.u32(16)?;
        let (async_id, tree_id) = if flags & FLAG_ASYNC != 0 {
            (r.u64(32)?, 0)
        } else {
            (0, r.u32(36)?)
        };
        Some(Self {
            credit_charge: r.u16(6)?,
            status: r.u32(8)?,
            command: r.u16(12)?,
            credits: r.u16(14)?,
            flags,
            next: r.u32(20)?,
            message_id: r.u64(24)?,
            async_id,
            tree_id,
            session_id: r.u64(40)?,
            signature: b[48..64].try_into().ok()?,
        })
    }

    pub fn is_response(&self) -> bool {
        self.flags & FLAG_RESPONSE != 0
    }
}

/// A message: its header and body, the body built with offsets from the
/// start of the header as SMB counts them.
pub fn message(h: &Header, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(HEADER_LEN + body.len());
    h.write(&mut m);
    m.extend_from_slice(body);
    m
}

/// The error response body.
pub fn error_body() -> Vec<u8> {
    vec![9, 0, 0, 0, 0, 0, 0, 0, 0]
}

// ---- framing --------------------------------------------------------------

/// Direct TCP: a zero byte and a 24-bit length before each message.
pub fn frame(msg: &[u8]) -> Vec<u8> {
    let n = msg.len() as u32;
    let mut out = Vec::with_capacity(4 + msg.len());
    out.push(0);
    out.extend_from_slice(&n.to_be_bytes()[1..]);
    out.extend_from_slice(msg);
    out
}

/// The next whole message in `buf`: its bytes and how much of `buf` it took.
/// `Err` for something that is not Direct TCP SMB.
pub fn deframe(buf: &[u8]) -> Result<Option<(&[u8], usize)>, String> {
    if buf.len() < 4 {
        return Ok(None);
    }
    if buf[0] != 0 {
        // NetBIOS session keep-alive (0x85) is the one other type we take.
        if buf[0] == 0x85 {
            return Ok(Some((&buf[4..4], 4)));
        }
        return Err(format!("not a Direct TCP message (type 0x{:02x})", buf[0]));
    }
    let n = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
    if n > 16 << 20 {
        return Err(format!("message of {n} bytes"));
    }
    if buf.len() < 4 + n {
        return Ok(None);
    }
    Ok(Some((&buf[4..4 + n], 4 + n)))
}

/// The messages of a compound, by their NextCommand offsets.
pub fn split_compound(msg: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = msg;
    while rest.len() >= HEADER_LEN {
        let next = u32::from_le_bytes(rest[20..24].try_into().unwrap()) as usize;
        if next == 0 || next > rest.len() || next < HEADER_LEN {
            out.push(rest);
            break;
        }
        out.push(&rest[..next]);
        rest = &rest[next..];
    }
    out
}

/// Joins messages into a compound: each but the last padded to 8 bytes,
/// with its NextCommand set. Sign each after this, with [`sign`].
pub fn join_compound(parts: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let n = parts.len();
    parts
        .into_iter()
        .enumerate()
        .map(|(i, mut m)| {
            if i + 1 < n {
                while !m.len().is_multiple_of(8) {
                    m.push(0);
                }
                let len = m.len() as u32;
                m[20..24].copy_from_slice(&len.to_le_bytes());
            }
            m
        })
        .collect()
}

// ---- signing --------------------------------------------------------------

/// The key a session signs with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningKey {
    /// SMB 2.0.2 and 2.1: HMAC-SHA256 with the session key.
    HmacSha256([u8; 16]),
    /// SMB 3: AES-128-CMAC with a derived key.
    Cmac([u8; 16]),
}

impl SigningKey {
    /// The signing key of `dialect` from the session key (and, for 3.1.1,
    /// the session's pre-auth integrity hash).
    pub fn derive(dialect: u16, session_key: &[u8; 16], preauth: &[u8; 64]) -> Self {
        match dialect {
            SMB202 | SMB210 => SigningKey::HmacSha256(*session_key),
            SMB311 => SigningKey::Cmac(kdf(session_key, b"SMBSigningKey\0", preauth)),
            _ => SigningKey::Cmac(kdf(session_key, b"SMB2AESCMAC\0", b"SmbSign\0")),
        }
    }

    fn mac(&self, msg: &[u8]) -> [u8; 16] {
        match self {
            SigningKey::HmacSha256(k) => hmac_sha256(k, msg)[..16].try_into().unwrap(),
            SigningKey::Cmac(k) => aes_cmac(k, msg),
        }
    }
}

/// Signs one message (of a compound, after [`join_compound`]) in place.
pub fn sign(msg: &mut [u8], key: &SigningKey) {
    let flags = u32::from_le_bytes(msg[16..20].try_into().unwrap()) | FLAG_SIGNED;
    msg[16..20].copy_from_slice(&flags.to_le_bytes());
    msg[48..64].fill(0);
    let mac = key.mac(msg);
    msg[48..64].copy_from_slice(&mac);
}

/// Whether one message's signature is right.
pub fn verify(msg: &[u8], key: &SigningKey) -> bool {
    if msg.len() < HEADER_LEN {
        return false;
    }
    let mut copy = msg.to_vec();
    copy[48..64].fill(0);
    key.mac(&copy) == msg[48..64]
}

pub fn is_signed(msg: &[u8]) -> bool {
    msg.len() >= HEADER_LEN && msg[16] & FLAG_SIGNED as u8 != 0
}

// ---- reading and writing --------------------------------------------------

/// Reads little-endian numbers at offsets of a message.
#[derive(Clone, Copy)]
pub struct R<'a>(pub &'a [u8]);

impl<'a> R<'a> {
    pub fn u8(&self, at: usize) -> Option<u8> {
        self.0.get(at).copied()
    }
    pub fn u16(&self, at: usize) -> Option<u16> {
        Some(u16::from_le_bytes(self.0.get(at..at + 2)?.try_into().ok()?))
    }
    pub fn u32(&self, at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(self.0.get(at..at + 4)?.try_into().ok()?))
    }
    pub fn u64(&self, at: usize) -> Option<u64> {
        Some(u64::from_le_bytes(self.0.get(at..at + 8)?.try_into().ok()?))
    }
    pub fn bytes(&self, at: usize, n: usize) -> Option<&'a [u8]> {
        self.0.get(at..at.checked_add(n)?)
    }
    /// A buffer an offset (from the start of the message) and a length point at.
    pub fn buffer(&self, off: usize, n: usize) -> Option<&'a [u8]> {
        if n == 0 {
            return Some(&[]);
        }
        self.bytes(off, n)
    }
}

/// Builds a body; offsets of buffers in it count from the header's start.
#[derive(Default)]
pub struct W(pub Vec<u8>);

impl W {
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
    pub fn zeros(&mut self, n: usize) -> &mut Self {
        self.0.resize(self.0.len() + n, 0);
        self
    }
    /// Where the next byte goes, counted from the header's start.
    pub fn offset(&self) -> usize {
        HEADER_LEN + self.0.len()
    }
    pub fn align(&mut self, n: usize) -> &mut Self {
        while !self.offset().is_multiple_of(n) {
            self.0.push(0);
        }
        self
    }
    /// Overwrites a u16 at body position `at`.
    pub fn set_u16(&mut self, at: usize, v: u16) {
        self.0[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    pub fn set_u32(&mut self, at: usize, v: u32) {
        self.0[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
}

/// A file id: persistent and volatile halves.
pub type FileId = [u8; 16];
/// The file id of a related compound request: the one before it opened.
pub const RELATED_FILE: FileId = [0xff; 16];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_frames_compounds_and_signatures() {
        let h = Header {
            command: CREATE,
            credits: 7,
            message_id: 42,
            tree_id: 3,
            session_id: 9,
            ..Header::default()
        };
        let a = message(&h, &[1, 2, 3]);
        assert_eq!(Header::parse(&a), Some(h.clone()));
        let b = message(
            &Header {
                command: CLOSE,
                ..h
            },
            &[4; 10],
        );
        let mut parts = join_compound(vec![a.clone(), b.clone()]);
        let key = SigningKey::Cmac([5; 16]);
        for p in &mut parts {
            sign(p, &key);
        }
        let joined: Vec<u8> = parts.concat();
        let f = frame(&joined);
        let (m, used) = deframe(&f).unwrap().unwrap();
        assert_eq!(used, f.len());
        let split = split_compound(m);
        assert_eq!(split.len(), 2);
        assert_eq!(split[0].len(), 72);
        assert!(split.iter().all(|p| is_signed(p) && verify(p, &key)));
        assert!(!verify(split[1], &SigningKey::HmacSha256([5; 16])));
        assert_eq!(deframe(&f[..10]).unwrap(), None);
    }

    #[test]
    fn names() {
        assert_eq!(status_name(STATUS_LOGON_FAILURE), "STATUS_LOGON_FAILURE");
        assert_eq!(parse_status("logon failure"), Some(STATUS_LOGON_FAILURE));
        assert_eq!(
            parse_status("STATUS_ACCESS_DENIED"),
            Some(STATUS_ACCESS_DENIED)
        );
        assert_eq!(parse_dialect("3.1.1"), Some(SMB311));
        assert_eq!(parse_dialect("SMB2.1"), Some(SMB210));
        assert_eq!(dialect_name(SMB302), "3.0.2");
        assert!(is_success(STATUS_BUFFER_OVERFLOW) && !is_success(STATUS_END_OF_FILE));
    }
}
