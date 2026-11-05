//! Ed25519 keys as SSH uses them: public key blobs, signatures, OpenSSH
//! key files and fingerprints.

use std::fmt;
use std::sync::Arc;

use ring::rand::SystemRandom;
use ring::signature::{self as sig, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

use super::wire::{Reader, Writer};
use crate::{Error, Result};

pub(crate) const ED25519: &str = "ssh-ed25519";

/// An Ed25519 key pair: a server's host key or a client's login key.
///
/// Generate one with [`SshKey::generate`], or read an unencrypted OpenSSH
/// key file (`ssh-keygen -t ed25519 -N ''`) with [`SshKey::from_openssh`].
#[derive(Clone)]
pub struct SshKey {
    pair: Arc<Ed25519KeyPair>,
}

impl SshKey {
    /// A new random key.
    pub fn generate() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("the system random source works");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("a key ring just made");
        Self {
            pair: Arc::new(pair),
        }
    }

    /// Reads an OpenSSH private key file (`-----BEGIN OPENSSH PRIVATE
    /// KEY-----`) holding one unencrypted Ed25519 key.
    pub fn from_openssh(text: &str) -> Result<Self> {
        let bad = |m: &str| Error::Profile(format!("SSH key: {m}"));
        let begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
        let end = "-----END OPENSSH PRIVATE KEY-----";
        let a = text
            .find(begin)
            .ok_or_else(|| bad("not an OpenSSH private key (ssh-keygen -t ed25519 makes one)"))?;
        let b = text[a..].find(end).ok_or_else(|| bad("no END line"))? + a;
        let body: String = text[a + begin.len()..b]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let raw = base64_decode(&body).ok_or_else(|| bad("bad base64"))?;
        let magic = b"openssh-key-v1\0";
        let rest = raw
            .strip_prefix(&magic[..])
            .ok_or_else(|| bad("not openssh-key-v1"))?;
        let mut r = Reader::new(rest);
        let cipher = r.str().ok_or_else(|| bad("truncated"))?;
        if cipher != "none" {
            return Err(bad(
                "the key is encrypted; make one without a passphrase (ssh-keygen -N '')",
            ));
        }
        r.string().ok_or_else(|| bad("truncated"))?; // kdf name
        r.string().ok_or_else(|| bad("truncated"))?; // kdf options
        if r.u32() != Some(1) {
            return Err(bad("the file must hold exactly one key"));
        }
        r.string().ok_or_else(|| bad("truncated"))?; // public key
        let private = r.string().ok_or_else(|| bad("truncated"))?;
        let mut p = Reader::new(private);
        let (c1, c2) = (p.u32(), p.u32());
        if c1.is_none() || c1 != c2 {
            return Err(bad("damaged private section"));
        }
        let kind = p.str().ok_or_else(|| bad("truncated"))?;
        if kind != ED25519 {
            return Err(bad(&format!("a `{kind}` key; only ssh-ed25519 keys work")));
        }
        let public = p.string().ok_or_else(|| bad("truncated"))?;
        let secret = p.string().ok_or_else(|| bad("truncated"))?;
        if public.len() != 32 || secret.len() != 64 {
            return Err(bad("damaged Ed25519 key"));
        }
        let pair = Ed25519KeyPair::from_seed_and_public_key(&secret[..32], public)
            .map_err(|e| bad(&format!("{e}")))?;
        Ok(Self {
            pair: Arc::new(pair),
        })
    }

    /// The public key blob: string "ssh-ed25519", string key.
    pub fn public_blob(&self) -> Vec<u8> {
        public_blob(self.pair.public_key().as_ref())
    }

    /// The public key as an `authorized_keys` line, without a comment.
    pub fn public_line(&self) -> String {
        format!("{ED25519} {}", base64_encode(&self.public_blob(), true))
    }

    /// `SHA256:...`, as `ssh-keygen -l` prints it.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public_blob())
    }

    /// A signature blob: string "ssh-ed25519", string signature.
    pub(crate) fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.str(ED25519);
        w.string(self.pair.sign(msg).as_ref());
        w.into_inner()
    }
}

impl fmt::Debug for SshKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SshKey({})", self.fingerprint())
    }
}

impl PartialEq for SshKey {
    fn eq(&self, other: &Self) -> bool {
        self.public_blob() == other.public_blob()
    }
}

pub(crate) fn public_blob(key: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.str(ED25519);
    w.string(key);
    w.into_inner()
}

/// `SHA256:` and the unpadded base64 of the blob's SHA-256.
pub fn fingerprint(blob: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, blob);
    format!("SHA256:{}", base64_encode(d.as_ref(), false))
}

/// Checks a signature blob over `msg` with a public key blob.
pub(crate) fn verify(key_blob: &[u8], sig_blob: &[u8], msg: &[u8]) -> bool {
    let mut k = Reader::new(key_blob);
    let (Some(ED25519), Some(key)) = (k.str(), k.string()) else {
        return false;
    };
    let mut s = Reader::new(sig_blob);
    let (Some(ED25519), Some(sig)) = (s.str(), s.string()) else {
        return false;
    };
    UnparsedPublicKey::new(&sig::ED25519, key)
        .verify(msg, sig)
        .is_ok()
}

/// Reads a public key line (`ssh-ed25519 AAAA... comment`, as in
/// `authorized_keys` or a `.pub` file) into its blob.
pub fn parse_public_line(line: &str) -> Result<Vec<u8>> {
    let mut w = line.split_whitespace();
    let (kind, data) = (w.next(), w.next());
    let bad = || Error::Profile(format!("`{line}` is not an ssh-ed25519 public key"));
    if kind != Some(ED25519) {
        return Err(bad());
    }
    let blob = base64_decode(data.ok_or_else(bad)?).ok_or_else(bad)?;
    let mut r = Reader::new(&blob);
    match (r.str(), r.string()) {
        (Some(ED25519), Some(k)) if k.len() == 32 => Ok(blob),
        _ => Err(bad()),
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn base64_encode(data: &[u8], pad: bool) -> String {
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        let out = c.len() + 1;
        for i in 0..4 {
            if i < out {
                s.push(B64[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else if pad {
                s.push('=');
            }
        }
    }
    s
}

pub(crate) fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes() {
        let v = B64.iter().position(|&b| b == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Made with `ssh-keygen -t ed25519 -N '' -C test`.
    const KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB85sb/ExjktjMX/kKm/tIbOuafRn5ZW/dLgwWfP+oU0QAAAJCM7d0KjO3d
CgAAAAtzc2gtZWQyNTUxOQAAACB85sb/ExjktjMX/kKm/tIbOuafRn5ZW/dLgwWfP+oU0Q
AAAECWJVgrr8MXMKlECbgnywlBJI1uy+dAxcIcq3VmDeU4MHzmxv8TGOS2Mxf+Qqb+0hs6
5p9Gfllb90uDBZ8/6hTRAAAACHRlc3RAa2V5AQIDBAU=
-----END OPENSSH PRIVATE KEY-----
";
    const PUB: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHzmxv8TGOS2Mxf+Qqb+0hs65p9Gfllb90uDBZ8/6hTR test@key";
    const FINGERPRINT: &str = "SHA256:Qurk5CcVhyZNVDVSIgmZQptqtLjIdT/idOGwxxht2sQ";

    #[test]
    fn base64_round_trips() {
        for n in 0..20 {
            let d: Vec<u8> = (0..n).map(|i| (i * 37) as u8).collect();
            assert_eq!(base64_decode(&base64_encode(&d, true)).unwrap(), d);
            assert_eq!(base64_decode(&base64_encode(&d, false)).unwrap(), d);
        }
        assert_eq!(base64_encode(b"foob", true), "Zm9vYg==");
        assert_eq!(base64_encode(b"foob", false), "Zm9vYg");
        assert!(base64_decode("a*b").is_none());
    }

    #[test]
    fn reads_openssh_keys_and_signs() {
        let k = SshKey::from_openssh(KEY).unwrap();
        assert_eq!(k.public_blob(), parse_public_line(PUB).unwrap());
        assert_eq!(format!("{} test@key", k.public_line()), PUB);
        let sig = k.sign(b"hello");
        assert!(verify(&k.public_blob(), &sig, b"hello"));
        assert!(!verify(&k.public_blob(), &sig, b"hellO"));
        let other = SshKey::generate();
        assert!(!verify(&other.public_blob(), &sig, b"hello"));
        assert_eq!(k.fingerprint(), FINGERPRINT);
        assert!(SshKey::from_openssh("nope").is_err());
        assert!(parse_public_line("ssh-rsa AAAA").is_err());
    }
}
