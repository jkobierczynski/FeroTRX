//! The cryptography SMB needs, without dependencies: MD4 (the NT password
//! hash), HMAC-MD5 and RC4 (NTLMv2), HMAC-SHA256 (SMB 2.x signing and the
//! SP800-108 key derivation of SMB 3), SHA-512 (the SMB 3.1.1 pre-auth
//! integrity hash) and AES-128-CMAC (SMB 3 signing).
//!
//! These are for a lab traffic generator: correct, tested against the
//! published vectors, but not hardened (no constant-time guarantees).

use crate::app::sip::digest::{md5, sha256};

// ---- MD4 (RFC 1320) -------------------------------------------------------

pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut h: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_le_bytes());
    for block in msg.chunks(64) {
        let mut x = [0u32; 16];
        for (i, w) in x.iter_mut().enumerate() {
            *w = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let [mut a, mut b, mut c, mut d] = h;
        let f = |x: u32, y: u32, z: u32| (x & y) | (!x & z);
        let g = |x: u32, y: u32, z: u32| (x & y) | (x & z) | (y & z);
        let hh = |x: u32, y: u32, z: u32| x ^ y ^ z;
        for &i in &[0usize, 4, 8, 12] {
            a = a.wrapping_add(f(b, c, d)).wrapping_add(x[i]).rotate_left(3);
            d = d
                .wrapping_add(f(a, b, c))
                .wrapping_add(x[i + 1])
                .rotate_left(7);
            c = c
                .wrapping_add(f(d, a, b))
                .wrapping_add(x[i + 2])
                .rotate_left(11);
            b = b
                .wrapping_add(f(c, d, a))
                .wrapping_add(x[i + 3])
                .rotate_left(19);
        }
        const K2: u32 = 0x5a82_7999;
        for &i in &[0usize, 1, 2, 3] {
            a = a
                .wrapping_add(g(b, c, d))
                .wrapping_add(x[i])
                .wrapping_add(K2)
                .rotate_left(3);
            d = d
                .wrapping_add(g(a, b, c))
                .wrapping_add(x[i + 4])
                .wrapping_add(K2)
                .rotate_left(5);
            c = c
                .wrapping_add(g(d, a, b))
                .wrapping_add(x[i + 8])
                .wrapping_add(K2)
                .rotate_left(9);
            b = b
                .wrapping_add(g(c, d, a))
                .wrapping_add(x[i + 12])
                .wrapping_add(K2)
                .rotate_left(13);
        }
        const K3: u32 = 0x6ed9_eba1;
        for &i in &[0usize, 2, 1, 3] {
            a = a
                .wrapping_add(hh(b, c, d))
                .wrapping_add(x[i])
                .wrapping_add(K3)
                .rotate_left(3);
            d = d
                .wrapping_add(hh(a, b, c))
                .wrapping_add(x[i + 8])
                .wrapping_add(K3)
                .rotate_left(9);
            c = c
                .wrapping_add(hh(d, a, b))
                .wrapping_add(x[i + 4])
                .wrapping_add(K3)
                .rotate_left(11);
            b = b
                .wrapping_add(hh(c, d, a))
                .wrapping_add(x[i + 12])
                .wrapping_add(K3)
                .rotate_left(15);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
    }
    let mut out = [0u8; 16];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

// ---- SHA-512 (FIPS 180-4) -------------------------------------------------

const K512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    let mut msg = data.to_vec();
    let bits = (data.len() as u128).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 128 != 112 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for block in msg.chunks(128) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..80 {
            let [a, b, c, d, e, f, g, hh] = v;
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K512[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            v = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
        }
        for (x, y) in h.iter_mut().zip(v) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 64];
    for (i, v) in h.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&v.to_be_bytes());
    }
    out
}

// ---- HMAC (RFC 2104) ------------------------------------------------------

fn hmac(hash: impl Fn(&[u8]) -> Vec<u8>, block: usize, key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut k = if key.len() > block {
        hash(key)
    } else {
        key.to_vec()
    };
    k.resize(block, 0);
    let mut inner: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    inner.extend_from_slice(data);
    let mut outer: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    outer.extend_from_slice(&hash(&inner));
    hash(&outer)
}

pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    hmac(|d| md5(d).to_vec(), 64, key, data).try_into().unwrap()
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    hmac(|d| sha256(d).to_vec(), 64, key, data)
        .try_into()
        .unwrap()
}

// ---- RC4 ------------------------------------------------------------------

pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    data.iter()
        .map(|b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            b ^ s[s[i as usize].wrapping_add(s[j as usize]) as usize]
        })
        .collect()
}

// ---- AES-128 (FIPS 197), encryption only ----------------------------------

const SBOX: [u8; 256] = {
    // Built at compile time from the multiplicative inverse in GF(2^8).
    let mut sbox = [0u8; 256];
    let mut p: u8 = 1;
    let mut q: u8 = 1;
    loop {
        // p * 3
        p = p ^ (p << 1) ^ (if p & 0x80 != 0 { 0x1b } else { 0 });
        // q / 3
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        if q & 0x80 != 0 {
            q ^= 0x09;
        }
        let x = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4);
        sbox[p as usize] = x ^ 0x63;
        if p == 1 {
            break;
        }
    }
    sbox[0] = 0x63;
    sbox
};

fn xtime(b: u8) -> u8 {
    (b << 1) ^ if b & 0x80 != 0 { 0x1b } else { 0 }
}

/// The round tables: S-box and MixColumns at once, one per byte position.
const TE: [[u32; 256]; 4] = {
    let mut t = [[0u32; 256]; 4];
    let mut i = 0;
    while i < 256 {
        let s = SBOX[i];
        let s2 = (s << 1) ^ if s & 0x80 != 0 { 0x1b } else { 0 };
        let s3 = s2 ^ s;
        let w = (s2 as u32) << 24 | (s as u32) << 16 | (s as u32) << 8 | s3 as u32;
        t[0][i] = w;
        t[1][i] = w.rotate_right(8);
        t[2][i] = w.rotate_right(16);
        t[3][i] = w.rotate_right(24);
        i += 1;
    }
    t
};

pub struct Aes128 {
    rk: [u32; 44],
}

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Self {
        let mut w = [0u32; 44];
        for i in 0..4 {
            w[i] = u32::from_be_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let mut rcon = 1u8;
        for i in 4..44 {
            let mut t = w[i - 1];
            if i % 4 == 0 {
                let b = t.rotate_left(8).to_be_bytes();
                t = u32::from_be_bytes([
                    SBOX[b[0] as usize] ^ rcon,
                    SBOX[b[1] as usize],
                    SBOX[b[2] as usize],
                    SBOX[b[3] as usize],
                ]);
                rcon = xtime(rcon);
            }
            w[i] = w[i - 4] ^ t;
        }
        Self { rk: w }
    }

    pub fn encrypt(&self, block: &[u8; 16]) -> [u8; 16] {
        let rk = &self.rk;
        let col = |i: usize| u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        let mut s = [
            col(0) ^ rk[0],
            col(1) ^ rk[1],
            col(2) ^ rk[2],
            col(3) ^ rk[3],
        ];
        let b = |x: u32, n: u32| ((x >> n) & 0xff) as usize;
        for round in 1..10 {
            let k = &rk[round * 4..round * 4 + 4];
            s = [
                TE[0][b(s[0], 24)]
                    ^ TE[1][b(s[1], 16)]
                    ^ TE[2][b(s[2], 8)]
                    ^ TE[3][b(s[3], 0)]
                    ^ k[0],
                TE[0][b(s[1], 24)]
                    ^ TE[1][b(s[2], 16)]
                    ^ TE[2][b(s[3], 8)]
                    ^ TE[3][b(s[0], 0)]
                    ^ k[1],
                TE[0][b(s[2], 24)]
                    ^ TE[1][b(s[3], 16)]
                    ^ TE[2][b(s[0], 8)]
                    ^ TE[3][b(s[1], 0)]
                    ^ k[2],
                TE[0][b(s[3], 24)]
                    ^ TE[1][b(s[0], 16)]
                    ^ TE[2][b(s[1], 8)]
                    ^ TE[3][b(s[2], 0)]
                    ^ k[3],
            ];
        }
        let mut out = [0u8; 16];
        for c in 0..4 {
            let v = u32::from_be_bytes([
                SBOX[b(s[c], 24)],
                SBOX[b(s[(c + 1) % 4], 16)],
                SBOX[b(s[(c + 2) % 4], 8)],
                SBOX[b(s[(c + 3) % 4], 0)],
            ]) ^ rk[40 + c];
            out[c * 4..c * 4 + 4].copy_from_slice(&v.to_be_bytes());
        }
        out
    }
}

fn xor16(a: &mut [u8; 16], b: &[u8; 16]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= y;
    }
}

// ---- AES-CMAC (RFC 4493) --------------------------------------------------

fn dbl(b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    for i in (0..16).rev() {
        out[i] = (b[i] << 1) | carry;
        carry = b[i] >> 7;
    }
    if carry != 0 {
        out[15] ^= 0x87;
    }
    out
}

pub fn aes_cmac(key: &[u8; 16], msg: &[u8]) -> [u8; 16] {
    let aes = Aes128::new(key);
    let l = aes.encrypt(&[0u8; 16]);
    let k1 = dbl(&l);
    let k2 = dbl(&k1);
    let n = msg.len().div_ceil(16).max(1);
    let complete = !msg.is_empty() && msg.len().is_multiple_of(16);
    let mut x = [0u8; 16];
    for i in 0..n {
        let mut block = [0u8; 16];
        let chunk = &msg[(i * 16).min(msg.len())..((i + 1) * 16).min(msg.len())];
        block[..chunk.len()].copy_from_slice(chunk);
        if i == n - 1 {
            if complete {
                xor16(&mut block, &k1);
            } else {
                block[chunk.len()] = 0x80;
                xor16(&mut block, &k2);
            }
        }
        xor16(&mut x, &block);
        x = aes.encrypt(&x);
    }
    x
}

// ---- SP800-108 counter mode KDF with HMAC-SHA256 (SMB 3) ------------------

/// The 128-bit key SMB 3 derives from the session key: `label` and
/// `context` without their terminating zero (it is added here).
pub fn kdf(key: &[u8], label: &[u8], context: &[u8]) -> [u8; 16] {
    let mut d = 1u32.to_be_bytes().to_vec();
    d.extend_from_slice(label);
    d.push(0);
    d.extend_from_slice(context);
    d.extend_from_slice(&128u32.to_be_bytes());
    hmac_sha256(key, &d)[..16].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn md4_vectors() {
        assert_eq!(hex(&md4(b"")), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(hex(&md4(b"abc")), "a448017aaf21d8525fc10ae87aa6729d");
        assert_eq!(
            hex(&md4(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )),
            "e33b4ddc9c38f2199c3e7b164fcc0536"
        );
    }

    #[test]
    fn sha512_vectors() {
        assert_eq!(
            hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        let long = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        assert_eq!(
            hex(&sha512(long)),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
             501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        );
    }

    #[test]
    fn hmac_vectors() {
        assert_eq!(
            hex(&hmac_md5(&[0x0b; 16], b"Hi There")),
            "9294727a3638bb1c13f48ef8158bfc9d"
        );
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_md5(b"Jefe", b"what do ya want for nothing?")),
            "750c783e6ab0b503eaa86e310a5db738"
        );
    }

    #[test]
    fn rc4_vector() {
        assert_eq!(hex(&rc4(b"Key", b"Plaintext")), "bbf316e8d940af0ad3");
    }

    #[test]
    fn aes_and_cmac_vectors() {
        let key: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let pt: [u8; 16] = unhex("00112233445566778899aabbccddeeff")
            .try_into()
            .unwrap();
        assert_eq!(
            hex(&Aes128::new(&key).encrypt(&pt)),
            "69c4e0d86a7b0430d8cdb78070b4c55a"
        );
        let k: [u8; 16] = unhex("2b7e151628aed2a6abf7158809cf4f3c")
            .try_into()
            .unwrap();
        assert_eq!(hex(&aes_cmac(&k, b"")), "bb1d6929e95937287fa37d129b756746");
        let m = unhex(
            "6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
             30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710",
        );
        assert_eq!(
            hex(&aes_cmac(&k, &m[..16])),
            "070a16b46b4d4144f79bdd9dd04a287c"
        );
        assert_eq!(
            hex(&aes_cmac(&k, &m[..40])),
            "dfa66747de9ae63030ca32611497c827"
        );
        assert_eq!(hex(&aes_cmac(&k, &m)), "51f0bebf7e3b9d92fc49741779363cfe");
    }
}

#[cfg(test)]
mod speed {
    #[test]
    #[ignore]
    fn cmac_and_hmac_speed() {
        let data = vec![7u8; 1 << 20];
        let t = std::time::Instant::now();
        let _ = super::aes_cmac(&[1; 16], &data);
        eprintln!("CMAC 1 MiB: {:?}", t.elapsed());
        let t = std::time::Instant::now();
        let _ = super::hmac_sha256(&[1; 16], &data);
        eprintln!("HMAC-SHA256 1 MiB: {:?}", t.elapsed());
    }
}
