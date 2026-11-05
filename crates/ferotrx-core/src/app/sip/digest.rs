//! Digest authentication (RFC 3261 section 22, RFC 7616, RFC 8760): MD5
//! and SHA-256, with and without `qop=auth`.

use std::fmt::Write as _;

/// The hash a digest challenge names.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Algorithm {
    #[default]
    Md5,
    Sha256,
}

impl Algorithm {
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Md5 => "MD5",
            Algorithm::Sha256 => "SHA-256",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "MD5" => Some(Algorithm::Md5),
            "SHA-256" | "SHA256" => Some(Algorithm::Sha256),
            _ => None,
        }
    }

    /// The lowercase hex of the hash of `data`.
    pub fn hex(self, data: &str) -> String {
        let d = match self {
            Algorithm::Md5 => md5(data.as_bytes()).to_vec(),
            Algorithm::Sha256 => sha256(data.as_bytes()).to_vec(),
        };
        let mut s = String::with_capacity(d.len() * 2);
        for b in d {
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

/// A `WWW-Authenticate` or `Proxy-Authenticate` challenge.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Challenge {
    pub realm: String,
    pub nonce: String,
    pub opaque: Option<String>,
    pub algorithm: Algorithm,
    /// `qop="auth"` was offered.
    pub qop_auth: bool,
}

impl Challenge {
    /// Reads a `Digest ...` header value; None for other schemes or
    /// algorithms this does not do.
    pub fn parse(value: &str) -> Option<Self> {
        let rest = strip_scheme(value)?;
        let mut c = Challenge::default();
        let mut nonce = None;
        for (k, v) in params(rest) {
            match k.to_ascii_lowercase().as_str() {
                "realm" => c.realm = v,
                "nonce" => nonce = Some(v),
                "opaque" => c.opaque = Some(v),
                "algorithm" => c.algorithm = Algorithm::from_name(&v)?,
                "qop" => c.qop_auth = v.split(',').any(|q| q.trim() == "auth"),
                _ => {}
            }
        }
        c.nonce = nonce?;
        Some(c)
    }

    /// The header value for a server's challenge.
    pub fn header(&self) -> String {
        let mut s = format!(
            "Digest realm=\"{}\", nonce=\"{}\", algorithm={}",
            self.realm,
            self.nonce,
            self.algorithm.name()
        );
        if self.qop_auth {
            s.push_str(", qop=\"auth\"");
        }
        if let Some(o) = &self.opaque {
            let _ = write!(s, ", opaque=\"{o}\"");
        }
        s
    }

    /// The `Authorization` value answering this challenge.
    pub fn answer(
        &self,
        user: &str,
        password: &str,
        method: &str,
        uri: &str,
        cnonce: &str,
    ) -> String {
        let nc = "00000001";
        let a = self.algorithm;
        let ha1 = a.hex(&format!("{user}:{}:{password}", self.realm));
        let ha2 = a.hex(&format!("{method}:{uri}"));
        let response = if self.qop_auth {
            a.hex(&format!("{ha1}:{}:{nc}:{cnonce}:auth:{ha2}", self.nonce))
        } else {
            a.hex(&format!("{ha1}:{}:{ha2}", self.nonce))
        };
        let mut s = format!(
            "Digest username=\"{user}\", realm=\"{}\", nonce=\"{}\", uri=\"{uri}\", \
             response=\"{response}\", algorithm={}",
            self.realm,
            self.nonce,
            a.name()
        );
        if self.qop_auth {
            let _ = write!(s, ", qop=auth, nc={nc}, cnonce=\"{cnonce}\"");
        }
        if let Some(o) = &self.opaque {
            let _ = write!(s, ", opaque=\"{o}\"");
        }
        s
    }
}

/// An `Authorization` or `Proxy-Authorization` header, as a server reads it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    pub realm: String,
    pub nonce: String,
    pub uri: String,
    pub response: String,
    pub algorithm: Algorithm,
    pub qop: Option<String>,
    pub nc: Option<String>,
    pub cnonce: Option<String>,
}

impl Credentials {
    pub fn parse(value: &str) -> Option<Self> {
        let rest = strip_scheme(value)?;
        let mut c = Credentials::default();
        for (k, v) in params(rest) {
            match k.to_ascii_lowercase().as_str() {
                "username" => c.username = v,
                "realm" => c.realm = v,
                "nonce" => c.nonce = v,
                "uri" => c.uri = v,
                "response" => c.response = v.to_ascii_lowercase(),
                "algorithm" => c.algorithm = Algorithm::from_name(&v)?,
                "qop" => c.qop = Some(v),
                "nc" => c.nc = Some(v),
                "cnonce" => c.cnonce = Some(v),
                _ => {}
            }
        }
        (!c.username.is_empty() && !c.response.is_empty()).then_some(c)
    }

    /// Whether the response is right for `password` and `method`.
    pub fn check(&self, password: &str, method: &str) -> bool {
        let a = self.algorithm;
        let ha1 = a.hex(&format!("{}:{}:{password}", self.username, self.realm));
        let ha2 = a.hex(&format!("{method}:{}", self.uri));
        let want = match (&self.qop, &self.nc, &self.cnonce) {
            (Some(q), Some(nc), Some(cn)) => {
                a.hex(&format!("{ha1}:{}:{nc}:{cn}:{q}:{ha2}", self.nonce))
            }
            (None, _, _) => a.hex(&format!("{ha1}:{}:{ha2}", self.nonce)),
            _ => return false,
        };
        want == self.response
    }
}

fn strip_scheme(value: &str) -> Option<&str> {
    let v = value.trim_start();
    let (scheme, rest) = v.split_at(v.find(char::is_whitespace)?);
    scheme.eq_ignore_ascii_case("digest").then_some(rest)
}

/// `k=v, k="v, w"` pairs.
fn params(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && (b[i] == b',' || b[i].is_ascii_whitespace()) {
            i += 1;
        }
        let k0 = i;
        while i < b.len() && b[i] != b'=' && b[i] != b',' {
            i += 1;
        }
        let key = s[k0..i].trim().to_string();
        if i >= b.len() || b[i] != b'=' {
            continue;
        }
        i += 1;
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let value = if i < b.len() && b[i] == b'"' {
            i += 1;
            let mut v = String::new();
            while i < b.len() && b[i] != b'"' {
                if b[i] == b'\\' && i + 1 < b.len() {
                    i += 1;
                }
                v.push(b[i] as char);
                i += 1;
            }
            i += 1;
            v
        } else {
            let v0 = i;
            while i < b.len() && b[i] != b',' {
                i += 1;
            }
            s[v0..i].trim().to_string()
        };
        if !key.is_empty() {
            out.push((key, value));
        }
    }
    out
}

/// MD5 (RFC 1321), which SIP digest still uses most.
pub fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: [u32; 64] =
        std::array::from_fn(|i| ((i as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32);
    let mut h: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64).wrapping_mul(8)).to_le_bytes());
    for chunk in msg.chunks(64) {
        let m: [u32; 16] = std::array::from_fn(|i| {
            u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().expect("4 bytes"))
        });
        let [mut a, mut b, mut c, mut d] = h;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
    }
    let mut out = [0u8; 16];
    for (i, w) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// SHA-256 (FIPS 180-4), for `algorithm=SHA-256` (RFC 8760).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64).wrapping_mul(8)).to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [
                t1.wrapping_add(t2),
                v[0],
                v[1],
                v[2],
                v[3].wrapping_add(t1),
                v[4],
                v[5],
                v[6],
            ];
        }
        for (a, b) in h.iter_mut().zip(v) {
            *a = a.wrapping_add(b);
        }
    }
    let mut out = [0u8; 32];
    for (i, w) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes() {
        assert_eq!(Algorithm::Md5.hex(""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            Algorithm::Md5.hex("The quick brown fox jumps over the lazy dog"),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
        let long = "a".repeat(1000);
        assert_eq!(
            Algorithm::Md5.hex(&long),
            "cabe45dcc9ae5b66ba86600cca6b8ba8"
        );
        assert_eq!(
            Algorithm::Sha256.hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            Algorithm::Sha256.hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn rfc2617_example() {
        // RFC 2617 section 3.5 (HTTP, but the same computation).
        let c = Challenge {
            realm: "testrealm@host.com".into(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".into(),
            opaque: Some("5ccc069c403ebaf9f0171e9517f40e41".into()),
            algorithm: Algorithm::Md5,
            qop_auth: true,
        };
        let a = c.answer(
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            "0a4f113b",
        );
        assert!(
            a.contains("response=\"6629fae49393a05397450978507c4ef1\""),
            "{a}"
        );
        let cred = Credentials::parse(&a).unwrap();
        assert!(cred.check("Circle Of Life", "GET"));
        assert!(!cred.check("circle of life", "GET"));
        assert!(!cred.check("Circle Of Life", "POST"));
        let back = Challenge::parse(&c.header()).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn without_qop_and_sha256() {
        for alg in [Algorithm::Md5, Algorithm::Sha256] {
            let c = Challenge {
                realm: "lab".into(),
                nonce: "abc".into(),
                algorithm: alg,
                ..Default::default()
            };
            let a = c.answer("alice", "pw", "REGISTER", "sip:lab", "x");
            let cred = Credentials::parse(&a).unwrap();
            assert_eq!(cred.algorithm, alg);
            assert!(cred.qop.is_none());
            assert!(cred.check("pw", "REGISTER"));
        }
        assert!(Challenge::parse("Basic realm=\"x\"").is_none());
        assert!(Challenge::parse("Digest realm=\"x\"").is_none());
        let c = Challenge::parse(
            "Digest realm=\"asterisk\",nonce=\"1a2b\",qop=\"auth,auth-int\",algorithm=md5",
        )
        .unwrap();
        assert!(c.qop_auth);
        assert_eq!(c.realm, "asterisk");
    }
}
