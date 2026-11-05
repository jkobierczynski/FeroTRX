//! NTLMv2 authentication (MS-NLMP) in SPNEGO tokens (RFC 4178), as SMB 2
//! and 3 session setup carries them: the client's NEGOTIATE, the server's
//! CHALLENGE with its target information, the client's AUTHENTICATE with
//! the NTLMv2 response and (with key exchange) its encrypted session key.
//!
//! The server leaves the timestamp out of its target information, so
//! clients send no MIC and SPNEGO needs no mechListMIC: the exchange stays
//! the plain three messages.

use super::crypto::{hmac_md5, md4, rc4};

pub const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
pub const REQUEST_TARGET: u32 = 0x0000_0004;
pub const NEGOTIATE_SIGN: u32 = 0x0000_0010;
pub const NEGOTIATE_NTLM: u32 = 0x0000_0200;
pub const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
pub const TARGET_TYPE_SERVER: u32 = 0x0002_0000;
pub const EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
pub const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
pub const NEGOTIATE_VERSION: u32 = 0x0200_0000;
pub const NEGOTIATE_128: u32 = 0x2000_0000;
pub const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
pub const NEGOTIATE_56: u32 = 0x8000_0000;

/// What the client asks for.
pub const CLIENT_FLAGS: u32 = NEGOTIATE_UNICODE
    | REQUEST_TARGET
    | NEGOTIATE_SIGN
    | NEGOTIATE_NTLM
    | NEGOTIATE_ALWAYS_SIGN
    | EXTENDED_SESSIONSECURITY
    | NEGOTIATE_VERSION
    | NEGOTIATE_128
    | NEGOTIATE_KEY_EXCH
    | NEGOTIATE_56;

const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
/// Windows 10 build 19041, NTLM revision 15: what the version field says.
const VERSION: [u8; 8] = [10, 0, 0x61, 0x4a, 0, 0, 0, 15];

pub fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

pub fn from_utf16(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
}

/// NTOWFv2: the key of everything else, from the password.
pub fn ntowfv2(user: &str, password: &str, domain: &str) -> [u8; 16] {
    let nt = md4(&utf16(password));
    let mut who = utf16(&user.to_uppercase());
    who.extend_from_slice(&utf16(domain));
    hmac_md5(&nt, &who)
}

// ---- messages -------------------------------------------------------------

/// A field of a message: its bytes, at an offset in the payload.
struct Fields {
    fixed: Vec<u8>,
    payload: Vec<u8>,
    header_len: usize,
    /// Where each field descriptor is, to fill in its offset.
    pending: Vec<(usize, Vec<u8>)>,
}

impl Fields {
    fn new(kind: u32, header_len: usize) -> Self {
        let mut fixed = SIGNATURE.to_vec();
        fixed.extend_from_slice(&kind.to_le_bytes());
        Self {
            fixed,
            payload: Vec::new(),
            header_len,
            pending: Vec::new(),
        }
    }
    fn field(&mut self, data: Vec<u8>) {
        self.pending.push((self.fixed.len(), data));
        self.fixed.extend_from_slice(&[0; 8]);
    }
    fn raw(&mut self, b: &[u8]) {
        self.fixed.extend_from_slice(b);
    }
    fn finish(mut self) -> Vec<u8> {
        assert_eq!(self.fixed.len(), self.header_len);
        for (at, data) in std::mem::take(&mut self.pending) {
            let off = (self.header_len + self.payload.len()) as u32;
            let n = data.len() as u16;
            self.fixed[at..at + 2].copy_from_slice(&n.to_le_bytes());
            self.fixed[at + 2..at + 4].copy_from_slice(&n.to_le_bytes());
            self.fixed[at + 4..at + 8].copy_from_slice(&off.to_le_bytes());
            self.payload.extend_from_slice(&data);
        }
        self.fixed.extend_from_slice(&self.payload);
        self.fixed
    }
}

fn kind(msg: &[u8]) -> Option<u32> {
    if msg.len() < 12 || &msg[..8] != SIGNATURE {
        return None;
    }
    Some(u32::from_le_bytes(msg[8..12].try_into().ok()?))
}

fn u32_at(msg: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(msg.get(at..at + 4)?.try_into().ok()?))
}

fn field_at(msg: &[u8], at: usize) -> Option<Vec<u8>> {
    let len = u16::from_le_bytes(msg.get(at..at + 2)?.try_into().ok()?) as usize;
    let off = u32_at(msg, at + 4)? as usize;
    if len == 0 {
        return Some(Vec::new());
    }
    msg.get(off..off.checked_add(len)?).map(<[u8]>::to_vec)
}

pub fn negotiate(flags: u32) -> Vec<u8> {
    let mut f = Fields::new(1, 40);
    f.raw(&flags.to_le_bytes());
    f.field(Vec::new()); // domain
    f.field(Vec::new()); // workstation
    f.raw(&VERSION);
    f.finish()
}

pub fn negotiate_flags(msg: &[u8]) -> Option<u32> {
    (kind(msg)? == 1).then(|| u32_at(msg, 12)).flatten()
}

/// The server's CHALLENGE.
#[derive(Clone, Debug, PartialEq)]
pub struct Challenge {
    pub flags: u32,
    pub challenge: [u8; 8],
    pub target_name: String,
    /// AV pairs, ending with MsvAvEOL.
    pub target_info: Vec<u8>,
}

/// One AV pair of target information.
fn av(id: u16, value: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value);
}

/// Target information: NetBIOS and DNS names of the domain and computer.
pub fn target_info(domain: &str, computer: &str, dns_domain: &str) -> Vec<u8> {
    let mut t = Vec::new();
    av(2, &utf16(domain), &mut t);
    av(1, &utf16(computer), &mut t);
    av(4, &utf16(dns_domain), &mut t);
    let dns_computer = if dns_domain.is_empty() {
        computer.to_lowercase()
    } else {
        format!("{}.{dns_domain}", computer.to_lowercase())
    };
    av(3, &utf16(&dns_computer), &mut t);
    av(0, &[], &mut t);
    t
}

/// The value of AV pair `id`.
pub fn av_get(info: &[u8], id: u16) -> Option<&[u8]> {
    let mut i = 0;
    while i + 4 <= info.len() {
        let t = u16::from_le_bytes([info[i], info[i + 1]]);
        let n = u16::from_le_bytes([info[i + 2], info[i + 3]]) as usize;
        if t == 0 {
            return None;
        }
        let v = info.get(i + 4..i + 4 + n)?;
        if t == id {
            return Some(v);
        }
        i += 4 + n;
    }
    None
}

impl Challenge {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut f = Fields::new(2, 56);
        f.field(utf16(&self.target_name));
        f.raw(&self.flags.to_le_bytes());
        f.raw(&self.challenge);
        f.raw(&[0; 8]);
        f.field(self.target_info.clone());
        f.raw(&VERSION);
        f.finish()
    }

    pub fn parse(msg: &[u8]) -> Option<Self> {
        if kind(msg)? != 2 {
            return None;
        }
        Some(Self {
            target_name: from_utf16(&field_at(msg, 12)?),
            flags: u32_at(msg, 20)?,
            challenge: msg.get(24..32)?.try_into().ok()?,
            target_info: field_at(msg, 40).unwrap_or_default(),
        })
    }
}

/// The client's AUTHENTICATE.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Authenticate {
    pub flags: u32,
    pub lm: Vec<u8>,
    pub nt: Vec<u8>,
    pub domain: String,
    pub user: String,
    pub workstation: String,
    pub session_key: Vec<u8>,
}

impl Authenticate {
    pub fn to_bytes(&self) -> Vec<u8> {
        // With the version and a MIC field (zero: no MIC is claimed).
        let mut f = Fields::new(3, 88);
        f.field(self.lm.clone());
        f.field(self.nt.clone());
        f.field(utf16(&self.domain));
        f.field(utf16(&self.user));
        f.field(utf16(&self.workstation));
        f.field(self.session_key.clone());
        f.raw(&self.flags.to_le_bytes());
        f.raw(&VERSION);
        f.raw(&[0; 16]);
        f.finish()
    }

    pub fn parse(msg: &[u8]) -> Option<Self> {
        if kind(msg)? != 3 {
            return None;
        }
        Some(Self {
            lm: field_at(msg, 12)?,
            nt: field_at(msg, 20)?,
            domain: from_utf16(&field_at(msg, 28)?),
            user: from_utf16(&field_at(msg, 36)?),
            workstation: from_utf16(&field_at(msg, 44)?),
            session_key: field_at(msg, 52).unwrap_or_default(),
            flags: u32_at(msg, 60)?,
        })
    }

    /// No user and no response: an anonymous (null) session.
    pub fn anonymous(&self) -> bool {
        self.user.is_empty() && self.nt.is_empty()
    }
}

/// Windows time: 100 ns since 1601, from time since 1970.
pub fn filetime(since_1970: std::time::Duration) -> u64 {
    (since_1970.as_nanos() / 100) as u64 + 116_444_736_000_000_000
}

/// The client's answer to `ch`, and the session key both ends then share.
#[allow(clippy::too_many_arguments)]
pub fn authenticate(
    ch: &Challenge,
    user: &str,
    password: &str,
    domain: &str,
    workstation: &str,
    client_challenge: [u8; 8],
    now: u64,
    random_key: [u8; 16],
) -> (Authenticate, [u8; 16]) {
    let key = ntowfv2(user, password, domain);
    let ts = av_get(&ch.target_info, 7)
        .and_then(|v| v.try_into().ok())
        .map(u64::from_le_bytes);
    let mut temp = vec![1, 1, 0, 0, 0, 0, 0, 0];
    temp.extend_from_slice(&ts.unwrap_or(now).to_le_bytes());
    temp.extend_from_slice(&client_challenge);
    temp.extend_from_slice(&[0; 4]);
    temp.extend_from_slice(&ch.target_info);
    temp.extend_from_slice(&[0; 4]);
    let mut d = ch.challenge.to_vec();
    d.extend_from_slice(&temp);
    let proof = hmac_md5(&key, &d);
    let mut nt = proof.to_vec();
    nt.extend_from_slice(&temp);
    let lm = if ts.is_some() {
        vec![0; 24]
    } else {
        let mut d = ch.challenge.to_vec();
        d.extend_from_slice(&client_challenge);
        let mut lm = hmac_md5(&key, &d).to_vec();
        lm.extend_from_slice(&client_challenge);
        lm
    };
    let base = hmac_md5(&key, &proof);
    let flags = CLIENT_FLAGS & ch.flags | NEGOTIATE_UNICODE;
    let (exported, enc) = if flags & NEGOTIATE_KEY_EXCH != 0 {
        (random_key, rc4(&base, &random_key))
    } else {
        (base, Vec::new())
    };
    (
        Authenticate {
            flags,
            lm,
            nt,
            domain: domain.to_string(),
            user: user.to_string(),
            workstation: workstation.to_string(),
            session_key: enc,
        },
        exported,
    )
}

/// The server's check of an NTLMv2 answer with the user's password: the
/// session key when it is right.
pub fn verify(a: &Authenticate, challenge: &[u8; 8], password: &str) -> Option<[u8; 16]> {
    if a.nt.len() < 16 + 28 {
        return None; // not NTLMv2
    }
    let (proof, temp) = a.nt.split_at(16);
    // As the client wrote the domain, else without one or in capitals.
    let domains = [a.domain.clone(), String::new(), a.domain.to_uppercase()];
    let base = domains.iter().find_map(|domain| {
        let key = ntowfv2(&a.user, password, domain);
        let mut d = challenge.to_vec();
        d.extend_from_slice(temp);
        (hmac_md5(&key, &d) == proof).then(|| hmac_md5(&key, proof))
    })?;
    if a.flags & NEGOTIATE_KEY_EXCH != 0 && a.session_key.len() == 16 {
        Some(rc4(&base, &a.session_key).try_into().ok()?)
    } else {
        Some(base)
    }
}

// ---- SPNEGO ---------------------------------------------------------------

/// 1.3.6.1.5.5.2
const SPNEGO_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
/// 1.3.6.1.4.1.311.2.2.10
pub const NTLMSSP_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

pub const ACCEPT_COMPLETED: u8 = 0;
pub const ACCEPT_INCOMPLETE: u8 = 1;
pub const REJECT: u8 = 2;

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}

/// The NegTokenInit the server offers in its NEGOTIATE response, or the
/// client's first token (with `token`, its NTLM NEGOTIATE).
pub fn init(token: Option<&[u8]>) -> Vec<u8> {
    let mechs = tlv(0xa0, &tlv(0x30, &tlv(0x06, NTLMSSP_OID)));
    let mut body = mechs;
    if let Some(t) = token {
        body.extend(tlv(0xa2, &tlv(0x04, t)));
    }
    let mut inner = tlv(0x06, SPNEGO_OID);
    inner.extend(tlv(0xa0, &tlv(0x30, &body)));
    tlv(0x60, &inner)
}

/// A NegTokenResp.
pub fn resp(state: Option<u8>, mech: bool, token: Option<&[u8]>) -> Vec<u8> {
    let mut body = Vec::new();
    if let Some(s) = state {
        body.extend(tlv(0xa0, &tlv(0x0a, &[s])));
    }
    if mech {
        body.extend(tlv(0xa1, &tlv(0x06, NTLMSSP_OID)));
    }
    if let Some(t) = token {
        body.extend(tlv(0xa2, &tlv(0x04, t)));
    }
    tlv(0xa1, &tlv(0x30, &body))
}

/// A DER element at the start of `b`: tag, content, rest.
fn read(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let l = *b.get(1)?;
    let (n, start) = if l < 0x80 {
        (l as usize, 2)
    } else {
        let k = (l & 0x7f) as usize;
        if k == 0 || k > 4 {
            return None;
        }
        let mut n = 0usize;
        for &x in b.get(2..2 + k)? {
            n = n << 8 | x as usize;
        }
        (n, 2 + k)
    };
    let content = b.get(start..start.checked_add(n)?)?;
    Some((tag, content, &b[start + n..]))
}

/// What a SPNEGO token says.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Token {
    pub state: Option<u8>,
    pub mechs: Vec<Vec<u8>>,
    /// The NTLM message inside.
    pub inner: Option<Vec<u8>>,
}

impl Token {
    pub fn offers_ntlm(&self) -> bool {
        self.mechs.is_empty() || self.mechs.iter().any(|m| m == NTLMSSP_OID)
    }
}

/// Reads a NegTokenInit, a NegTokenResp, or a bare NTLM message.
pub fn parse(b: &[u8]) -> Option<Token> {
    if b.starts_with(SIGNATURE) {
        return Some(Token {
            inner: Some(b.to_vec()),
            ..Token::default()
        });
    }
    let (tag, content, _) = read(b)?;
    let seq = match tag {
        0x60 => {
            let (t, _oid, rest) = read(content)?;
            if t != 0x06 {
                return None;
            }
            let (t, c, _) = read(rest)?;
            if t != 0xa0 {
                return None;
            }
            c
        }
        0xa1 => content,
        _ => return None,
    };
    let (t, mut fields, _) = read(seq)?;
    if t != 0x30 {
        return None;
    }
    let mut tok = Token::default();
    while !fields.is_empty() {
        let (t, c, rest) = read(fields)?;
        fields = rest;
        let inner = read(c).map(|(_, x, _)| x);
        match (tag, t) {
            (0x60, 0xa0) => {
                let (_, mut list, _) = read(c)?;
                while !list.is_empty() {
                    let (_, oid, rest) = read(list)?;
                    tok.mechs.push(oid.to_vec());
                    list = rest;
                }
            }
            (0x60, 0xa2) | (0xa1, 0xa2) => tok.inner = inner.map(<[u8]>::to_vec),
            (0xa1, 0xa0) => tok.state = inner.and_then(|x| x.first().copied()),
            (0xa1, 0xa1) => tok.mechs.push(inner?.to_vec()),
            _ => {}
        }
    }
    Some(tok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntowfv2_and_response_match_ms_nlmp() {
        // MS-NLMP 4.2.4: User, Password, Domain, server and client challenge.
        let key = ntowfv2("User", "Password", "Domain");
        assert_eq!(
            key,
            [
                0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0,
                0x2e, 0x3f
            ]
        );
        let mut info = Vec::new();
        av(2, &utf16("Domain"), &mut info);
        av(1, &utf16("Server"), &mut info);
        av(0, &[], &mut info);
        let ch = Challenge {
            flags: 0xe28a_8233,
            challenge: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            target_name: "Domain".into(),
            target_info: info,
        };
        let (a, _) = authenticate(
            &ch, "User", "Password", "Domain", "COMPUTER", [0xaa; 8], 0, [0x55; 16],
        );
        // NTProofStr from the spec.
        assert_eq!(
            &a.nt[..16],
            &[
                0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96, 0xaa, 0xbc, 0x92, 0x7b, 0xeb, 0xef,
                0x6a, 0x1c
            ]
        );
        // The encrypted session key from the spec.
        assert_eq!(
            a.session_key,
            vec![
                0xc5, 0xda, 0xd2, 0x54, 0x4f, 0xc9, 0x79, 0x90, 0x94, 0xce, 0x1c, 0xe9, 0x0b, 0xc9,
                0xd0, 0x3e
            ]
        );
        // The server agrees, and gets the same key.
        let back = Authenticate::parse(&a.to_bytes()).unwrap();
        assert_eq!(back, a);
        assert_eq!(verify(&back, &ch.challenge, "Password"), Some([0x55; 16]));
        assert_eq!(verify(&back, &ch.challenge, "password"), None);
    }

    #[test]
    fn spnego_round_trips() {
        let n = negotiate(CLIENT_FLAGS);
        assert_eq!(negotiate_flags(&n), Some(CLIENT_FLAGS));
        let t = parse(&init(Some(&n))).unwrap();
        assert!(t.offers_ntlm());
        assert_eq!(t.inner.as_deref(), Some(&n[..]));
        let offer = parse(&init(None)).unwrap();
        assert_eq!(offer.mechs, vec![NTLMSSP_OID.to_vec()]);
        let big = vec![7u8; 300];
        let r = parse(&resp(Some(ACCEPT_INCOMPLETE), true, Some(&big))).unwrap();
        assert_eq!(r.state, Some(ACCEPT_INCOMPLETE));
        assert_eq!(r.inner, Some(big));
        let ch = Challenge {
            flags: 1,
            challenge: [9; 8],
            target_name: "LAB".into(),
            target_info: target_info("LAB", "FEROTRX", "lab.local"),
        };
        assert_eq!(Challenge::parse(&ch.to_bytes()), Some(ch.clone()));
        assert_eq!(av_get(&ch.target_info, 1), Some(&utf16("FEROTRX")[..]));
    }
}
