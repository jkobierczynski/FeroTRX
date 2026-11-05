//! The SSH transport layer (RFC 4253): version exchange, binary packets,
//! curve25519-sha256 key exchange (RFC 8731) with an ssh-ed25519 host key,
//! and the AEAD ciphers chacha20-poly1305@openssh.com and
//! aes128/256-gcm@openssh.com. Re-keying works in both directions.

use ring::aead::{self, chacha20_poly1305_openssh as chacha, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::digest::{self, SHA256};
use ring::rand::{SecureRandom, SystemRandom};

use super::keys::{self, SshKey, ED25519};
use super::wire::{Reader, Writer};
use crate::app::AppCx;

pub(crate) const DISCONNECT: u8 = 1;
const IGNORE: u8 = 2;
const UNIMPLEMENTED: u8 = 3;
const DEBUG: u8 = 4;
const KEXINIT: u8 = 20;
const NEWKEYS: u8 = 21;
const KEX_ECDH_INIT: u8 = 30;
const KEX_ECDH_REPLY: u8 = 31;

/// Disconnect reasons (RFC 4253 section 11.1).
pub(crate) const PROTOCOL_ERROR: u32 = 2;
pub(crate) const KEY_EXCHANGE_FAILED: u32 = 3;
pub(crate) const HOST_KEY_NOT_VERIFIABLE: u32 = 9;
pub(crate) const BY_APPLICATION: u32 = 11;
pub(crate) const NO_MORE_AUTH_METHODS: u32 = 14;
pub(crate) const SERVICE_NOT_AVAILABLE: u32 = 7;

/// The key exchange methods, best first.
pub const KEX_METHODS: &[&str] = &["curve25519-sha256", "curve25519-sha256@libssh.org"];
/// The ciphers, best first.
pub const CIPHERS: &[&str] = &[
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
];
/// Listed for peers that want a MAC to agree on; the AEAD ciphers use none.
const MACS: &[&str] = &["hmac-sha2-256", "hmac-sha2-512"];

/// The longest packet taken (OpenSSH's own limit).
const MAX_PACKET: usize = 256 * 1024;
const MAX_VERSION_LINES: usize = 50;

/// What the transport hands up.
#[derive(Debug)]
pub(crate) enum Event {
    /// A message for the layers above (user authentication, connection).
    Packet(Vec<u8>),
    /// A key exchange ended: `first` for the one that made the session.
    KexDone { first: bool },
    /// The peer said goodbye.
    Disconnect(u32, String),
}

/// A failure: the reason to put in our DISCONNECT, and what went wrong.
pub(crate) type Failure = (u32, String);

enum Seal {
    Plain,
    ChaCha(Box<chacha::SealingKey>),
    Gcm(Box<LessSafeKey>, [u8; 12]),
}

enum Open {
    Plain,
    ChaCha(Box<chacha::OpeningKey>),
    Gcm(Box<LessSafeKey>, [u8; 12]),
}

/// What both KEXINITs agreed on.
#[derive(Clone, Debug)]
struct Agreed {
    kex: String,
    cipher_out: String,
    cipher_in: String,
}

pub(crate) struct Transport {
    server: bool,
    own_version: Vec<u8>,
    peer_version: Option<Vec<u8>>,
    version_lines: usize,
    ciphers: Vec<String>,
    host_key: Option<SshKey>,
    fingerprint: Option<String>,
    rx: Vec<u8>,
    seq_in: u32,
    seq_out: u32,
    seal: Seal,
    open: Open,
    next_seal: Option<Seal>,
    next_open: Option<Open>,
    own_kexinit: Option<Vec<u8>>,
    peer_kexinit: Option<Vec<u8>>,
    agreed: Option<Agreed>,
    ephemeral: Option<EphemeralPrivateKey>,
    client_q: Vec<u8>,
    sent_newkeys: bool,
    got_newkeys: bool,
    skip_guess: bool,
    session_id: Option<Vec<u8>>,
    kex_count: u32,
    held: Vec<Vec<u8>>,
    /// The peer sent DISCONNECT (or we did): nothing more goes out.
    leaving: bool,
    /// What goes out at the end of a [`feed`](Self::feed).
    deferred: Option<Vec<u8>>,
    rng: SystemRandom,
    /// Key exchange, host key and cipher of the last key exchange.
    pub negotiated: String,
    /// The server's host key fingerprint (client side, once known).
    pub peer_fingerprint: Option<String>,
    /// Payload bytes both ways since the last key exchange.
    pub bytes: u64,
}

impl Transport {
    /// `version` is the whole identification line without CRLF
    /// (`SSH-2.0-FeroTRX_0.20.0`); a server has a host key, a client may
    /// expect a host key `fingerprint`.
    pub fn new(
        server: bool,
        version: &str,
        ciphers: &[String],
        host_key: Option<SshKey>,
        fingerprint: Option<String>,
    ) -> Self {
        Self {
            server,
            own_version: version.as_bytes().to_vec(),
            peer_version: None,
            version_lines: 0,
            ciphers: ciphers.to_vec(),
            host_key,
            fingerprint,
            rx: Vec::new(),
            seq_in: 0,
            seq_out: 0,
            seal: Seal::Plain,
            open: Open::Plain,
            next_seal: None,
            next_open: None,
            own_kexinit: None,
            peer_kexinit: None,
            agreed: None,
            ephemeral: None,
            client_q: Vec::new(),
            sent_newkeys: false,
            got_newkeys: false,
            skip_guess: false,
            session_id: None,
            kex_count: 0,
            held: Vec::new(),
            leaving: false,
            deferred: None,
            rng: SystemRandom::new(),
            negotiated: String::new(),
            peer_fingerprint: None,
            bytes: 0,
        }
    }

    pub fn session_id(&self) -> Option<&[u8]> {
        self.session_id.as_deref()
    }

    /// The peer's identification line, once it came.
    #[cfg(test)]
    pub fn peer_version(&self) -> Option<String> {
        self.peer_version
            .as_ref()
            .map(|v| String::from_utf8_lossy(v).into_owned())
    }

    /// A key exchange is going on.
    pub fn kexing(&self) -> bool {
        self.own_kexinit.is_some() || self.peer_kexinit.is_some()
    }

    /// Sends our identification line and KEXINIT.
    pub fn start(&mut self, cx: &mut AppCx) {
        let mut line = self.own_version.clone();
        line.extend_from_slice(b"\r\n");
        cx.send(line);
        self.send_kexinit(cx);
    }

    /// Starts a new key exchange, unless one is going on.
    pub fn rekey(&mut self, cx: &mut AppCx) {
        if !self.kexing() && self.session_id.is_some() {
            self.send_kexinit(cx);
        }
    }

    /// Sends a message of the layers above; during a key exchange it waits
    /// for the new keys.
    pub fn send(&mut self, payload: Vec<u8>, cx: &mut AppCx) {
        let transport = matches!(payload.first(), Some(1..=49));
        if self.own_kexinit.is_some() && !self.sent_newkeys && !transport {
            self.held.push(payload);
        } else {
            self.send_raw(&payload, cx);
        }
    }

    pub fn disconnect(&mut self, reason: u32, text: &str, cx: &mut AppCx) {
        let mut w = Writer::msg(DISCONNECT);
        w.u32(reason).str(text).str("");
        self.send_raw(&w.into_inner(), cx);
        self.leaving = true;
    }

    fn send_kexinit(&mut self, cx: &mut AppCx) {
        let mut cookie = [0u8; 16];
        let _ = self.rng.fill(&mut cookie);
        let names = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let mut w = Writer::msg(KEXINIT);
        w.raw(&cookie)
            .names(&names(KEX_METHODS))
            .names(&names(&[ED25519]))
            .names(&self.ciphers)
            .names(&self.ciphers)
            .names(&names(MACS))
            .names(&names(MACS))
            .names(&names(&["none"]))
            .names(&names(&["none"]))
            .str("")
            .str("")
            .bool(false)
            .u32(0);
        let p = w.into_inner();
        self.send_raw(&p, cx);
        self.own_kexinit = Some(p);
    }

    fn send_raw(&mut self, payload: &[u8], cx: &mut AppCx) {
        if self.leaving {
            return;
        }
        let (block, aead) = match self.seal {
            Seal::Plain => (8, false),
            Seal::ChaCha(_) => (8, true),
            Seal::Gcm(..) => (16, true),
        };
        let base = 1 + payload.len() + if aead { 0 } else { 4 };
        let mut pad = block - base % block;
        if pad < 4 {
            pad += block;
        }
        let len = 1 + payload.len() + pad;
        let mut buf = Vec::with_capacity(4 + len + 16);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
        buf.push(pad as u8);
        buf.extend_from_slice(payload);
        buf.resize(4 + len, 0);
        match &mut self.seal {
            Seal::Plain => {}
            Seal::ChaCha(k) => {
                let mut tag = [0u8; 16];
                k.seal_in_place(self.seq_out, &mut buf, &mut tag);
                buf.extend_from_slice(&tag);
            }
            Seal::Gcm(k, iv) => {
                let (head, body) = buf.split_at_mut(4);
                let tag = k
                    .seal_in_place_separate_tag(
                        Nonce::assume_unique_for_key(*iv),
                        Aad::from(&*head),
                        body,
                    )
                    .expect("SSH packets are far below AES-GCM's limit");
                buf.extend_from_slice(tag.as_ref());
                next_iv(iv);
            }
        }
        self.seq_out = self.seq_out.wrapping_add(1);
        self.bytes += payload.len() as u64;
        match self.deferred.as_mut() {
            Some(d) => d.extend_from_slice(&buf),
            None => cx.send(buf),
        }
    }

    /// Takes received bytes and returns what they hold.
    ///
    /// What the key exchange answers goes out once all of `data` is read,
    /// and not at all if it held a DISCONNECT: a peer that says goodbye has
    /// closed (or is closing) its socket, and an answer would only come back
    /// as a TCP reset. OpenSSH sends DISCONNECT right after its key share
    /// when a key exchange it started is no longer needed.
    pub fn feed(&mut self, data: &[u8], cx: &mut AppCx) -> Result<Vec<Event>, Failure> {
        self.deferred = Some(Vec::new());
        let r = self.read(data, cx);
        let out = self.deferred.take().unwrap_or_default();
        if !self.leaving && !out.is_empty() {
            cx.send(out);
        }
        r
    }

    fn read(&mut self, data: &[u8], cx: &mut AppCx) -> Result<Vec<Event>, Failure> {
        self.rx.extend_from_slice(data);
        let mut out = Vec::new();
        while self.peer_version.is_none() {
            let Some(nl) = self.rx.iter().position(|&b| b == b'\n') else {
                if self.rx.len() > 8192 {
                    return Err((PROTOCOL_ERROR, "no SSH identification line".into()));
                }
                return Ok(out);
            };
            let mut line: Vec<u8> = self.rx.drain(..=nl).collect();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.starts_with(b"SSH-") {
                if !(line.starts_with(b"SSH-2.0-") || line.starts_with(b"SSH-1.99-")) {
                    return Err((
                        PROTOCOL_ERROR,
                        format!(
                            "the peer speaks {}, not SSH 2",
                            String::from_utf8_lossy(&line)
                        ),
                    ));
                }
                self.peer_version = Some(line);
            } else {
                // Lines before the version are allowed (a server's banner).
                self.version_lines += 1;
                if self.version_lines > MAX_VERSION_LINES {
                    return Err((PROTOCOL_ERROR, "no SSH identification line".into()));
                }
            }
        }
        while let Some(p) = self.next_packet()? {
            self.bytes += p.len() as u64;
            self.handle(p, cx, &mut out)?;
        }
        Ok(out)
    }

    fn next_packet(&mut self) -> Result<Option<Vec<u8>>, Failure> {
        let bad_len = |n: usize| (PROTOCOL_ERROR, format!("bad packet length {n}"));
        if self.rx.len() < 4 {
            return Ok(None);
        }
        let head: [u8; 4] = self.rx[..4].try_into().unwrap();
        let plain_head = match &self.open {
            Open::ChaCha(k) => k.decrypt_packet_length(self.seq_in, head),
            _ => head,
        };
        let len = u32::from_be_bytes(plain_head) as usize;
        if !(5..=MAX_PACKET).contains(&len) {
            return Err(bad_len(len));
        }
        let tag = if matches!(self.open, Open::Plain) {
            0
        } else {
            16
        };
        let total = 4 + len + tag;
        if self.rx.len() < total {
            return Ok(None);
        }
        let bad_mac = || (PROTOCOL_ERROR, "a packet failed its integrity check".into());
        let body: Vec<u8> = match &mut self.open {
            Open::Plain => self.rx[4..total].to_vec(),
            Open::ChaCha(k) => {
                let mut buf = self.rx[..4 + len].to_vec();
                let t: [u8; 16] = self.rx[4 + len..total].try_into().unwrap();
                k.open_in_place(self.seq_in, &mut buf, &t)
                    .map_err(|_| bad_mac())?;
                buf.drain(..4);
                buf
            }
            Open::Gcm(k, iv) => {
                if !len.is_multiple_of(16) {
                    return Err(bad_len(len));
                }
                let mut buf = self.rx[4..total].to_vec();
                let n = k
                    .open_in_place(Nonce::assume_unique_for_key(*iv), Aad::from(head), &mut buf)
                    .map_err(|_| bad_mac())?
                    .len();
                buf.truncate(n);
                next_iv(iv);
                buf
            }
        };
        self.rx.drain(..total);
        self.seq_in = self.seq_in.wrapping_add(1);
        let pad = body[0] as usize;
        if pad + 1 >= body.len() {
            return Err((PROTOCOL_ERROR, "a packet without payload".into()));
        }
        Ok(Some(body[1..body.len() - pad].to_vec()))
    }

    fn handle(&mut self, p: Vec<u8>, cx: &mut AppCx, out: &mut Vec<Event>) -> Result<(), Failure> {
        let malformed = |what: &str| (PROTOCOL_ERROR, format!("malformed {what}"));
        match p[0] {
            DISCONNECT => {
                let mut r = Reader::new(&p[1..]);
                let code = r.u32().unwrap_or(0);
                let text = r.str().unwrap_or("").to_string();
                self.leaving = true;
                out.push(Event::Disconnect(code, text));
            }
            IGNORE | DEBUG | UNIMPLEMENTED => {}
            KEXINIT => {
                if self.peer_kexinit.is_some() {
                    return Err((PROTOCOL_ERROR, "a second KEXINIT".into()));
                }
                if self.own_kexinit.is_none() {
                    self.send_kexinit(cx);
                }
                self.peer_kexinit = Some(p);
                self.agree()?;
                if !self.server {
                    let eph = EphemeralPrivateKey::generate(&X25519, &self.rng)
                        .map_err(|_| (KEY_EXCHANGE_FAILED, "no random numbers".to_string()))?;
                    let q = eph.compute_public_key().map_err(|_| {
                        (KEY_EXCHANGE_FAILED, "no curve25519 public key".to_string())
                    })?;
                    self.ephemeral = Some(eph);
                    self.client_q = q.as_ref().to_vec();
                    let mut w = Writer::msg(KEX_ECDH_INIT);
                    w.string(q.as_ref());
                    self.send_raw(&w.into_inner(), cx);
                }
            }
            KEX_ECDH_INIT if self.server && self.agreed.is_some() => {
                if std::mem::take(&mut self.skip_guess) {
                    return Ok(());
                }
                let q_c = Reader::new(&p[1..])
                    .string()
                    .ok_or_else(|| malformed("KEX_ECDH_INIT"))?
                    .to_vec();
                let eph = EphemeralPrivateKey::generate(&X25519, &self.rng)
                    .map_err(|_| (KEY_EXCHANGE_FAILED, "no random numbers".to_string()))?;
                let q_s = eph
                    .compute_public_key()
                    .map_err(|_| (KEY_EXCHANGE_FAILED, "no curve25519 public key".to_string()))?;
                let k =
                    agreement::agree_ephemeral(eph, &UnparsedPublicKey::new(&X25519, &q_c), |k| {
                        k.to_vec()
                    })
                    .map_err(|_| {
                        (
                            KEY_EXCHANGE_FAILED,
                            "a bad curve25519 public key".to_string(),
                        )
                    })?;
                let host = self.host_key.clone().expect("a server has a host key");
                let k_s = host.public_blob();
                let h = self.exchange_hash(&k_s, &q_c, q_s.as_ref(), &k);
                let mut w = Writer::msg(KEX_ECDH_REPLY);
                w.string(&k_s).string(q_s.as_ref()).string(&host.sign(&h));
                self.send_raw(&w.into_inner(), cx);
                self.new_keys(&k, &h, cx, out);
            }
            KEX_ECDH_REPLY if !self.server && self.ephemeral.is_some() => {
                let mut r = Reader::new(&p[1..]);
                let (Some(k_s), Some(q_s), Some(sig)) = (r.string(), r.string(), r.string()) else {
                    return Err(malformed("KEX_ECDH_REPLY"));
                };
                let eph = self.ephemeral.take().unwrap();
                let k =
                    agreement::agree_ephemeral(eph, &UnparsedPublicKey::new(&X25519, q_s), |k| {
                        k.to_vec()
                    })
                    .map_err(|_| {
                        (
                            KEY_EXCHANGE_FAILED,
                            "a bad curve25519 public key".to_string(),
                        )
                    })?;
                let q_c = std::mem::take(&mut self.client_q);
                let h = self.exchange_hash(k_s, &q_c, q_s, &k);
                if !keys::verify(k_s, sig, &h) {
                    return Err((
                        KEY_EXCHANGE_FAILED,
                        "the server's host key signature does not verify".into(),
                    ));
                }
                let fp = keys::fingerprint(k_s);
                if let Some(want) = &self.fingerprint {
                    if *want != fp {
                        return Err((
                            HOST_KEY_NOT_VERIFIABLE,
                            format!("host key {fp}, expected {want}"),
                        ));
                    }
                }
                self.peer_fingerprint = Some(fp);
                self.new_keys(&k, &h, cx, out);
            }
            NEWKEYS if self.next_open.is_some() => {
                self.open = self.next_open.take().unwrap();
                self.got_newkeys = true;
                self.kex_finished(out);
            }
            k if (KEXINIT..=49).contains(&k) => {
                return Err((
                    PROTOCOL_ERROR,
                    format!("unexpected key exchange message {}", p[0]),
                ))
            }
            _ if self.session_id.is_none() => {
                return Err((
                    PROTOCOL_ERROR,
                    format!("message {} before the key exchange", p[0]),
                ))
            }
            _ => out.push(Event::Packet(p)),
        }
        Ok(())
    }
}

impl Transport {
    /// Agrees on the algorithms from both KEXINITs: the first of the
    /// client's lists that the server has.
    fn agree(&mut self) -> Result<(), Failure> {
        let bad = || (PROTOCOL_ERROR, "malformed KEXINIT".to_string());
        let peer = self.peer_kexinit.as_ref().unwrap();
        let mut r = Reader::new(peer.get(17..).ok_or_else(bad)?);
        let lists: Vec<Vec<String>> = (0..10)
            .map(|_| r.names())
            .collect::<Option<_>>()
            .ok_or_else(bad)?;
        let follows = r.bool().ok_or_else(bad)?;
        let server = self.server;
        let pick = |own: &[String], peer: &[String], what: &str| -> Result<String, Failure> {
            let (c, s) = if server { (peer, own) } else { (own, peer) };
            c.iter().find(|a| s.contains(a)).cloned().ok_or_else(|| {
                (
                    KEY_EXCHANGE_FAILED,
                    format!(
                        "no {what} in common: ours {}, theirs {}",
                        own.join(","),
                        peer.join(",")
                    ),
                )
            })
        };
        let names = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let kex = pick(&names(KEX_METHODS), &lists[0], "key exchange method")?;
        let host = pick(&names(&[ED25519]), &lists[1], "host key type")?;
        let c2s = pick(&self.ciphers, &lists[2], "cipher")?;
        let s2c = pick(&self.ciphers, &lists[3], "cipher")?;
        pick(&names(&["none"]), &lists[6], "compression")?;
        pick(&names(&["none"]), &lists[7], "compression")?;
        if follows && (lists[0].first() != Some(&kex) || lists[1].first() != Some(&host)) {
            // The peer guessed wrong: its first key exchange packet is void.
            self.skip_guess = true;
        }
        self.negotiated = if c2s == s2c {
            format!("{kex} {host} {c2s}")
        } else {
            format!("{kex} {host} {c2s}/{s2c}")
        };
        let (cipher_out, cipher_in) = if server { (s2c, c2s) } else { (c2s, s2c) };
        self.agreed = Some(Agreed {
            kex,
            cipher_out,
            cipher_in,
        });
        Ok(())
    }

    fn exchange_hash(&self, k_s: &[u8], q_c: &[u8], q_s: &[u8], k: &[u8]) -> Vec<u8> {
        let own_v = &self.own_version;
        let peer_v = self.peer_version.as_deref().unwrap_or_default();
        let own_i = self.own_kexinit.as_deref().unwrap_or_default();
        let peer_i = self.peer_kexinit.as_deref().unwrap_or_default();
        let (v_c, v_s, i_c, i_s) = if self.server {
            (peer_v, &own_v[..], peer_i, own_i)
        } else {
            (&own_v[..], peer_v, own_i, peer_i)
        };
        let mut w = Writer::new();
        w.string(v_c)
            .string(v_s)
            .string(i_c)
            .string(i_s)
            .string(k_s)
            .string(q_c)
            .string(q_s)
            .mpint(k);
        digest::digest(&SHA256, &w.into_inner()).as_ref().to_vec()
    }

    /// Makes the keys, sends NEWKEYS and from then on encrypts.
    fn new_keys(&mut self, k: &[u8], h: &[u8], cx: &mut AppCx, out: &mut Vec<Event>) {
        if self.session_id.is_none() {
            self.session_id = Some(h.to_vec());
        }
        let sid = self.session_id.clone().unwrap();
        let a = self.agreed.clone().expect("agreed before the keys");
        let _ = &a.kex;
        let ((iv_out, key_out), (iv_in, key_in)) = if self.server {
            ((b'B', b'D'), (b'A', b'C'))
        } else {
            ((b'A', b'C'), (b'B', b'D'))
        };
        let d = |letter: u8, len: usize| derive(k, h, &sid, letter, len);
        let (iv_len, key_len) = sizes(&a.cipher_out);
        self.next_seal = Some(seal(
            &a.cipher_out,
            &d(iv_out, iv_len),
            &d(key_out, key_len),
        ));
        let (iv_len, key_len) = sizes(&a.cipher_in);
        self.next_open = Some(open(&a.cipher_in, &d(iv_in, iv_len), &d(key_in, key_len)));
        self.send_raw(&[NEWKEYS], cx);
        self.seal = self.next_seal.take().unwrap();
        self.sent_newkeys = true;
        for p in std::mem::take(&mut self.held) {
            self.send_raw(&p, cx);
        }
        self.kex_finished(out);
    }

    fn kex_finished(&mut self, out: &mut Vec<Event>) {
        if !(self.sent_newkeys && self.got_newkeys) {
            return;
        }
        self.own_kexinit = None;
        self.peer_kexinit = None;
        self.agreed = None;
        self.sent_newkeys = false;
        self.got_newkeys = false;
        self.bytes = 0;
        self.kex_count += 1;
        out.push(Event::KexDone {
            first: self.kex_count == 1,
        });
    }
}

/// IV and key lengths of a cipher.
fn sizes(cipher: &str) -> (usize, usize) {
    match cipher {
        "chacha20-poly1305@openssh.com" => (0, chacha::KEY_LEN),
        "aes256-gcm@openssh.com" => (12, 32),
        _ => (12, 16),
    }
}

fn gcm_key(cipher: &str, key: &[u8]) -> Box<LessSafeKey> {
    let alg = if cipher == "aes256-gcm@openssh.com" {
        &aead::AES_256_GCM
    } else {
        &aead::AES_128_GCM
    };
    Box::new(LessSafeKey::new(
        UnboundKey::new(alg, key).expect("the key has the cipher's length"),
    ))
}

fn seal(cipher: &str, iv: &[u8], key: &[u8]) -> Seal {
    if cipher.starts_with("chacha20") {
        Seal::ChaCha(Box::new(chacha::SealingKey::new(key.try_into().unwrap())))
    } else {
        Seal::Gcm(gcm_key(cipher, key), iv.try_into().unwrap())
    }
}

fn open(cipher: &str, iv: &[u8], key: &[u8]) -> Open {
    if cipher.starts_with("chacha20") {
        Open::ChaCha(Box::new(chacha::OpeningKey::new(key.try_into().unwrap())))
    } else {
        Open::Gcm(gcm_key(cipher, key), iv.try_into().unwrap())
    }
}

/// The GCM invocation counter: the IV's last 8 bytes, plus one per packet.
fn next_iv(iv: &mut [u8; 12]) {
    let n = u64::from_be_bytes(iv[4..].try_into().unwrap()).wrapping_add(1);
    iv[4..].copy_from_slice(&n.to_be_bytes());
}

/// RFC 4253 section 7.2: HASH(K || H || letter || session_id), extended
/// with HASH(K || H || so far) to `len` bytes.
fn derive(k: &[u8], h: &[u8], sid: &[u8], letter: u8, len: usize) -> Vec<u8> {
    let mut kw = Writer::new();
    kw.mpint(k);
    let k = kw.into_inner();
    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(&k);
    ctx.update(h);
    ctx.update(&[letter]);
    ctx.update(sid);
    let mut out = ctx.finish().as_ref().to_vec();
    while out.len() < len {
        let mut ctx = digest::Context::new(&SHA256);
        ctx.update(&k);
        ctx.update(h);
        ctx.update(&out);
        out.extend_from_slice(ctx.finish().as_ref());
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn pair(ciphers: &[&str]) -> (Transport, Transport) {
        let c: Vec<String> = ciphers.iter().map(|s| s.to_string()).collect();
        let host = SshKey::generate();
        let fp = host.fingerprint();
        (
            Transport::new(false, "SSH-2.0-client", &c, None, Some(fp)),
            Transport::new(true, "SSH-2.0-server", &c, Some(host), None),
        )
    }

    /// Hands bytes between the two in pieces of `piece` until both are
    /// quiet; returns what each received.
    fn shuttle(
        c: &mut Transport,
        s: &mut Transport,
        mut to_s: Vec<u8>,
        mut to_c: Vec<u8>,
        piece: usize,
    ) -> Result<(Vec<Event>, Vec<Event>), Failure> {
        let (mut ce, mut se) = (Vec::new(), Vec::new());
        while !(to_s.is_empty() && to_c.is_empty()) {
            for chunk in std::mem::take(&mut to_s).chunks(piece) {
                let mut x = AppCx::new(Duration::ZERO, Duration::ZERO);
                se.extend(s.feed(chunk, &mut x)?);
                to_c.extend(x.take_sends().concat());
            }
            for chunk in std::mem::take(&mut to_c).chunks(piece) {
                let mut x = AppCx::new(Duration::ZERO, Duration::ZERO);
                ce.extend(c.feed(chunk, &mut x)?);
                to_s.extend(x.take_sends().concat());
            }
        }
        Ok((ce, se))
    }

    fn started(t: &mut Transport) -> Vec<u8> {
        let mut x = AppCx::new(Duration::ZERO, Duration::ZERO);
        t.start(&mut x);
        x.take_sends().concat()
    }

    fn sent(t: &mut Transport, p: &[u8]) -> Vec<u8> {
        let mut x = AppCx::new(Duration::ZERO, Duration::ZERO);
        t.send(p.to_vec(), &mut x);
        x.take_sends().concat()
    }

    fn packets(e: &[Event]) -> Vec<Vec<u8>> {
        e.iter()
            .filter_map(|e| match e {
                Event::Packet(p) => Some(p.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn handshakes_and_carries_messages_with_every_cipher() {
        for cipher in CIPHERS {
            for piece in [1, 7, 100_000] {
                let (mut c, mut s) = pair(&[cipher]);
                let (to_s, to_c) = (started(&mut c), started(&mut s));
                // The server's banner line comes before its version.
                let to_c = [b"hello there\r\n".to_vec(), to_c].concat();
                let (ce, se) = shuttle(&mut c, &mut s, to_s, to_c, piece).unwrap();
                assert!(matches!(ce[..], [Event::KexDone { first: true }]), "{ce:?}");
                assert!(matches!(se[..], [Event::KexDone { first: true }]));
                assert_eq!(c.session_id(), s.session_id());
                assert!(c.negotiated.ends_with(cipher), "{}", c.negotiated);
                assert_eq!(s.peer_version().unwrap(), "SSH-2.0-client");
                for n in [0usize, 1, 15, 16, 17, 5000] {
                    let p: Vec<u8> = std::iter::once(90).chain((0..n).map(|i| i as u8)).collect();
                    let a = sent(&mut c, &p);
                    let b = sent(&mut s, &p);
                    let (ce, se) = shuttle(&mut c, &mut s, a, b, piece).unwrap();
                    assert_eq!(packets(&se), std::slice::from_ref(&p));
                    assert_eq!(packets(&ce), [p]);
                }
            }
        }
    }

    #[test]
    fn rekeys_while_messages_wait() {
        let (mut c, mut s) = pair(&["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"]);
        let (to_s, to_c) = (started(&mut c), started(&mut s));
        shuttle(&mut c, &mut s, to_s, to_c, 1000).unwrap();
        let sid = c.session_id().unwrap().to_vec();
        for who in 0..2 {
            let (a, b) = if who == 0 {
                (&mut c, &mut s)
            } else {
                (&mut s, &mut c)
            };
            let mut x = AppCx::new(Duration::ZERO, Duration::ZERO);
            a.rekey(&mut x);
            assert!(a.kexing());
            // Held until the new keys: it must come after the exchange.
            a.send(vec![94, 1, 2, 3], &mut x);
            let out = x.take_sends().concat();
            let (ae, be) = if who == 0 {
                shuttle(a, b, out, Vec::new(), 50).unwrap()
            } else {
                let (x, y) = shuttle(b, a, Vec::new(), out, 50).unwrap();
                (y, x)
            };
            assert!(
                matches!(ae[..], [Event::KexDone { first: false }]),
                "{ae:?}"
            );
            assert!(matches!(be[0], Event::KexDone { first: false }));
            assert_eq!(packets(&be), [vec![94, 1, 2, 3]]);
            assert!(!a.kexing() && !b.kexing());
        }
        assert_eq!(c.session_id().unwrap(), sid);
    }

    #[test]
    fn answers_nothing_once_the_peer_says_goodbye() {
        let (mut c, mut s) = pair(CIPHERS);
        let (to_s, to_c) = (started(&mut c), started(&mut s));
        shuttle(&mut c, &mut s, to_s, to_c, 1000).unwrap();
        // The client starts a key exchange, gets the server's KEXINIT,
        // sends its key share and at once DISCONNECT, as OpenSSH does.
        let mut x = AppCx::default();
        c.rekey(&mut x);
        let mut y = AppCx::default();
        s.feed(&x.take_sends().concat(), &mut y).unwrap();
        let mut x = AppCx::default();
        c.feed(&y.take_sends().concat(), &mut x).unwrap();
        c.disconnect(BY_APPLICATION, "bye", &mut x);
        let mut y = AppCx::default();
        let e = s.feed(&x.take_sends().concat(), &mut y).unwrap();
        assert!(
            matches!(e[..], [Event::Disconnect(BY_APPLICATION, _)]),
            "{e:?}"
        );
        assert!(
            y.take_sends().is_empty(),
            "the server answered a leaving client"
        );
        let mut y = AppCx::default();
        s.send(vec![94, 1], &mut y);
        assert!(y.take_sends().is_empty());
    }

    #[test]
    fn refuses_bad_peers() {
        // No cipher in common.
        let (mut c, _) = pair(&["aes128-gcm@openssh.com"]);
        let (_, mut s) = pair(&["chacha20-poly1305@openssh.com"]);
        let (to_s, to_c) = (started(&mut c), started(&mut s));
        let e = shuttle(&mut c, &mut s, to_s, to_c, 1000).unwrap_err();
        assert_eq!(e.0, KEY_EXCHANGE_FAILED);
        assert!(e.1.contains("cipher"), "{}", e.1);
        // A host key other than the one expected.
        let (mut c, mut s) = pair(CIPHERS);
        c.fingerprint = Some("SHA256:nope".into());
        let (to_s, to_c) = (started(&mut c), started(&mut s));
        let e = shuttle(&mut c, &mut s, to_s, to_c, 1000).unwrap_err();
        assert_eq!(e.0, HOST_KEY_NOT_VERIFIABLE);
        // SSH 1, and a damaged packet.
        let (mut c, mut s) = pair(CIPHERS);
        let mut x = AppCx::default();
        assert!(s.feed(b"SSH-1.5-old\r\n", &mut x).is_err());
        let (to_s, to_c) = (started(&mut c), started(&mut s));
        let mut s2 = s;
        shuttle(&mut c, &mut s2, to_s, to_c, 1000).unwrap();
        let mut p = sent(&mut c, &[94, 1, 2]);
        p[6] ^= 1;
        assert!(s2.feed(&p, &mut x).unwrap_err().1.contains("integrity"));
        // Application messages before the key exchange.
        let (_, mut s) = pair(CIPHERS);
        let mut plain = Transport::new(false, "SSH-2.0-x", &[], None, None);
        let mut p = b"SSH-2.0-x\r\n".to_vec();
        p.extend(sent(&mut plain, &[50, 0]));
        assert!(s.feed(&p, &mut x).unwrap_err().1.contains("before"));
    }

    #[test]
    fn derives_keys_as_rfc_4253_says() {
        let k = [0x80u8, 1];
        let d = derive(&k, b"H", b"S", b'A', 40);
        let mut first = digest::Context::new(&SHA256);
        first.update(&[0, 0, 0, 3, 0, 0x80, 1]);
        first.update(b"HAS");
        let f = first.finish();
        assert_eq!(&d[..32], f.as_ref());
        let mut next = digest::Context::new(&SHA256);
        next.update(&[0, 0, 0, 3, 0, 0x80, 1]);
        next.update(b"H");
        next.update(f.as_ref());
        assert_eq!(&d[32..], &next.finish().as_ref()[..8]);
        let mut iv = [0u8; 12];
        iv[11] = 0xff;
        next_iv(&mut iv);
        assert_eq!(iv[10..], [1, 0]);
    }
}
