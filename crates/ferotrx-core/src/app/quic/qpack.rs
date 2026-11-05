//! QPACK (RFC 9204) with the static table only: the encoder never inserts
//! into a dynamic table, and the decoder allows none (capacity 0, which our
//! SETTINGS say), so field sections never block.

use super::super::http2::hpack::{huffman_decode, huffman_encode, huffman_len};

/// The static table (RFC 9204 appendix A).
pub const STATIC: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/// Appends an integer with an `n`-bit prefix, the high bits of the first
/// byte from `flags`.
fn put_int(out: &mut Vec<u8>, flags: u8, n: u32, mut v: u64) {
    let max = (1u64 << n) - 1;
    if v < max {
        out.push(flags | v as u8);
        return;
    }
    out.push(flags | max as u8);
    v -= max;
    while v >= 128 {
        out.push((v % 128) as u8 | 0x80);
        v /= 128;
    }
    out.push(v as u8);
}

fn get_int(b: &[u8], at: &mut usize, n: u32) -> Result<u64, String> {
    let max = (1u64 << n) - 1;
    let first = *b.get(*at).ok_or("a truncated integer")?;
    *at += 1;
    let mut v = u64::from(first) & max;
    if v < max {
        return Ok(v);
    }
    let mut shift = 0;
    loop {
        let x = *b.get(*at).ok_or("a truncated integer")?;
        *at += 1;
        if shift > 56 {
            return Err("an integer too large".into());
        }
        v += u64::from(x & 0x7f) << shift;
        shift += 7;
        if x & 0x80 == 0 {
            return Ok(v);
        }
    }
}

/// A string literal: `flags` (above the H bit), Huffman when shorter, with
/// an `n`-bit length prefix (the H bit is the one above it).
fn put_str(out: &mut Vec<u8>, flags: u8, n: u32, s: &str, huffman: bool) {
    let h_bit = 1u8 << n;
    if huffman && huffman_len(s.as_bytes()) < s.len() {
        let h = huffman_encode(s.as_bytes());
        put_int(out, flags | h_bit, n, h.len() as u64);
        out.extend_from_slice(&h);
    } else {
        put_int(out, flags, n, s.len() as u64);
        out.extend_from_slice(s.as_bytes());
    }
}

fn get_str(b: &[u8], at: &mut usize, n: u32) -> Result<String, String> {
    let huffman = b.get(*at).is_some_and(|&x| x & (1 << n) != 0);
    let len = get_int(b, at, n)? as usize;
    let end = at.checked_add(len).ok_or("a bad length")?;
    let raw = b.get(*at..end).ok_or("a truncated string")?;
    *at = end;
    let bytes = if huffman {
        huffman_decode(raw)?
    } else {
        raw.to_vec()
    };
    String::from_utf8(bytes).map_err(|_| "a field that is not UTF-8".into())
}

/// A field section, with references to the static table only.
pub fn encode<'a>(fields: impl IntoIterator<Item = (&'a str, &'a str)>, huffman: bool) -> Vec<u8> {
    // Required Insert Count 0, Base 0.
    let mut out = vec![0, 0];
    for (name, value) in fields {
        if let Some(i) = STATIC.iter().position(|&(n, v)| n == name && v == value) {
            // Indexed field line, static.
            put_int(&mut out, 0xc0, 6, i as u64);
        } else if let Some(i) = STATIC.iter().position(|&(n, _)| n == name) {
            // Literal with a static name reference.
            put_int(&mut out, 0x50, 4, i as u64);
            put_str(&mut out, 0, 7, value, huffman);
        } else {
            // Literal with a literal name.
            put_str(&mut out, 0x20, 3, name, huffman);
            put_str(&mut out, 0, 7, value, huffman);
        }
    }
    out
}

/// The fields of a section; an error for references to a dynamic table,
/// which we never allow.
pub fn decode(b: &[u8]) -> Result<Vec<(String, String)>, String> {
    let mut at = 0;
    let ric = get_int(b, &mut at, 8)?;
    if ric != 0 {
        return Err("a reference to the dynamic table (whose capacity is 0)".into());
    }
    get_int(b, &mut at, 7)?; // delta base
    let mut out = Vec::new();
    let stat = |i: u64| -> Result<(&str, &str), String> {
        STATIC
            .get(i as usize)
            .copied()
            .ok_or_else(|| format!("static index {i} out of range"))
    };
    while at < b.len() {
        let x = b[at];
        if x & 0x80 != 0 {
            if x & 0x40 == 0 {
                return Err("a dynamic table reference".into());
            }
            let (n, v) = stat(get_int(b, &mut at, 6)?)?;
            out.push((n.to_string(), v.to_string()));
        } else if x & 0x40 != 0 {
            if x & 0x10 == 0 {
                return Err("a dynamic table name reference".into());
            }
            let (n, _) = stat(get_int(b, &mut at, 4)?)?;
            let v = get_str(b, &mut at, 7)?;
            out.push((n.to_string(), v));
        } else if x & 0x20 != 0 {
            let n = get_str(b, &mut at, 3)?;
            let v = get_str(b, &mut at, 7)?;
            if n.bytes().any(|c| c.is_ascii_uppercase()) {
                return Err(format!("an uppercase field name `{n}`"));
            }
            out.push((n, v));
        } else {
            return Err("a post-base reference to the dynamic table".into());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_sections_round_trip() {
        let fields = [
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "www.lab.example"),
            (":path", "/index.html"),
            ("user-agent", "FeroTRX"),
            ("x-custom", "a value"),
            (":status", "200"),
            ("content-length", "1234567"),
        ];
        for huffman in [false, true] {
            let b = encode(fields.iter().copied(), huffman);
            let d = decode(&b).unwrap();
            let want: Vec<(String, String)> = fields
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect();
            assert_eq!(d, want);
        }
        // `:method GET` is static entry 17: 0xc0 | 17.
        assert_eq!(encode([(":method", "GET")], false), [0, 0, 0xd1]);
        // `:path /index.html`: a static name reference (1) and a literal.
        let b = encode([(":path", "/x")], false);
        assert_eq!(b, [0, 0, 0x51, 2, b'/', b'x']);
        assert!(decode(&[1, 0]).is_err());
        assert!(decode(&[0, 0, 0x80]).is_err());
        assert!(decode(&[0, 0, 0xff, 0x7f]).is_err());
    }

    #[test]
    fn the_static_table() {
        assert_eq!(STATIC[0], (":authority", ""));
        assert_eq!(STATIC[17], (":method", "GET"));
        assert_eq!(STATIC[25], (":status", "200"));
        assert_eq!(STATIC[63], (":status", "100"));
        assert_eq!(STATIC[98], ("x-frame-options", "sameorigin"));
    }
}
