//! HPACK (RFC 7541): the header compression of HTTP/2.
//!
//! An [`Encoder`] and a [`Decoder`] with the static table, a dynamic table
//! of their own size, integers with prefixes, and strings raw or Huffman
//! coded. The encoder indexes what it sends (as browsers do), except values
//! that should not be kept, and tells the other end when its table shrinks.

use std::collections::VecDeque;
use std::sync::OnceLock;

use super::tables::{HUFFMAN, STATIC};

/// What a header field costs in a table: name, value and 32 (RFC 7541 4.1).
fn entry_size(name: &str, value: &str) -> usize {
    name.len() + value.len() + 32
}

/// A dynamic table: newest entry first.
#[derive(Clone, Debug)]
struct Table {
    entries: VecDeque<(String, String)>,
    size: usize,
    max: usize,
}

impl Table {
    fn new(max: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            max,
        }
    }

    fn set_max(&mut self, max: usize) {
        self.max = max;
        self.evict(0);
    }

    fn evict(&mut self, room: usize) {
        while self.size + room > self.max {
            match self.entries.pop_back() {
                Some((n, v)) => self.size -= entry_size(&n, &v),
                None => break,
            }
        }
    }

    fn insert(&mut self, name: &str, value: &str) {
        let s = entry_size(name, value);
        if s > self.max {
            // Too big for the table: it empties it (RFC 7541 4.4).
            self.entries.clear();
            self.size = 0;
            return;
        }
        self.evict(s);
        self.entries
            .push_front((name.to_string(), value.to_string()));
        self.size += s;
    }

    /// Entry `index` of the static and then this table, from 1.
    fn get(&self, index: usize) -> Option<(&str, &str)> {
        match index {
            0 => None,
            i if i <= STATIC.len() => Some(STATIC[i - 1]),
            i => self
                .entries
                .get(i - STATIC.len() - 1)
                .map(|(n, v)| (n.as_str(), v.as_str())),
        }
    }

    /// The best index for a field: one with the same name and value, or
    /// failing that one with the same name (`false`).
    fn find(&self, name: &str, value: &str) -> Option<(usize, bool)> {
        let mut by_name = None;
        let all = STATIC
            .iter()
            .copied()
            .chain(self.entries.iter().map(|(n, v)| (n.as_str(), v.as_str())));
        for (i, (n, v)) in all.enumerate() {
            if n == name {
                if v == value {
                    return Some((i + 1, true));
                }
                by_name.get_or_insert(i + 1);
            }
        }
        by_name.map(|i| (i, false))
    }
}

// ----- integers and strings -----

/// Appends `v` with an `n`-bit prefix; `first` holds the bits above it.
pub(super) fn put_int(out: &mut Vec<u8>, first: u8, n: u8, mut v: usize) {
    let max = (1usize << n) - 1;
    if v < max {
        out.push(first | v as u8);
        return;
    }
    out.push(first | max as u8);
    v -= max;
    while v >= 128 {
        out.push((v % 128) as u8 | 0x80);
        v /= 128;
    }
    out.push(v as u8);
}

/// Reads an integer with an `n`-bit prefix at `b[*at]`.
pub(super) fn get_int(b: &[u8], at: &mut usize, n: u8) -> Result<usize, String> {
    let max = (1usize << n) - 1;
    let first = *b.get(*at).ok_or("a header block cut short")?;
    *at += 1;
    let mut v = usize::from(first) & max;
    if v < max {
        return Ok(v);
    }
    let mut shift = 0u32;
    loop {
        let byte = *b.get(*at).ok_or("a header block cut short")?;
        *at += 1;
        if shift > 28 {
            return Err("an HPACK integer too large".into());
        }
        v += usize::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok(v);
        }
    }
}

/// The length of `s` Huffman coded, in bytes.
pub fn huffman_len(s: &[u8]) -> usize {
    let bits: usize = s
        .iter()
        .map(|&c| usize::from(HUFFMAN[usize::from(c)].1))
        .sum();
    bits.div_ceil(8)
}

/// `s` Huffman coded, padded with ones.
pub fn huffman_encode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(huffman_len(s));
    let (mut acc, mut n) = (0u64, 0u32);
    for &c in s {
        let (code, bits) = HUFFMAN[usize::from(c)];
        acc = acc << bits | u64::from(code);
        n += u32::from(bits);
        while n >= 8 {
            n -= 8;
            out.push((acc >> n) as u8);
        }
        acc &= (1 << n) - 1;
    }
    if n > 0 {
        out.push((acc << (8 - n) | ((1 << (8 - n)) - 1)) as u8);
    }
    out
}

/// A node of the decoding tree: children by bit, or a symbol.
#[derive(Clone, Copy)]
enum Node {
    Branch([u16; 2]),
    Leaf(u16),
}

fn tree() -> &'static [Node] {
    static TREE: OnceLock<Vec<Node>> = OnceLock::new();
    TREE.get_or_init(|| {
        let mut t = vec![Node::Branch([0, 0])];
        for (sym, &(code, bits)) in HUFFMAN.iter().enumerate() {
            let mut at = 0usize;
            for i in (0..bits).rev() {
                let bit = ((code >> i) & 1) as usize;
                let Node::Branch(kids) = t[at] else {
                    unreachable!("HPACK codes are prefix-free")
                };
                if i == 0 {
                    let leaf = t.len() as u16;
                    t.push(Node::Leaf(sym as u16));
                    if let Node::Branch(k) = &mut t[at] {
                        k[bit] = leaf;
                    }
                    break;
                }
                at = if kids[bit] == 0 {
                    let n = t.len() as u16;
                    t.push(Node::Branch([0, 0]));
                    if let Node::Branch(k) = &mut t[at] {
                        k[bit] = n;
                    }
                    usize::from(n)
                } else {
                    usize::from(kids[bit])
                };
            }
        }
        t
    })
}

/// Decodes a Huffman coded string; padding must be the start of EOS (all
/// ones, under 8 bits).
pub fn huffman_decode(b: &[u8]) -> Result<Vec<u8>, String> {
    let t = tree();
    let mut out = Vec::with_capacity(b.len() * 8 / 5);
    let (mut at, mut depth, mut ones) = (0usize, 0u32, true);
    for &byte in b {
        for i in (0..8).rev() {
            let bit = usize::from((byte >> i) & 1);
            let Node::Branch(kids) = t[at] else {
                unreachable!()
            };
            depth += 1;
            ones &= bit == 1;
            match t[usize::from(kids[bit])] {
                Node::Leaf(256) => return Err("EOS in a Huffman string".into()),
                Node::Leaf(sym) => {
                    out.push(sym as u8);
                    (at, depth, ones) = (0, 0, true);
                }
                Node::Branch(_) => at = usize::from(kids[bit]),
            }
        }
    }
    if depth > 7 || !ones {
        return Err("bad Huffman padding".into());
    }
    Ok(out)
}

fn put_string(out: &mut Vec<u8>, s: &str, huffman: bool) {
    if huffman && huffman_len(s.as_bytes()) < s.len() {
        let h = huffman_encode(s.as_bytes());
        put_int(out, 0x80, 7, h.len());
        out.extend_from_slice(&h);
    } else {
        put_int(out, 0, 7, s.len());
        out.extend_from_slice(s.as_bytes());
    }
}

fn get_string(b: &[u8], at: &mut usize) -> Result<String, String> {
    let huffman = b.get(*at).is_some_and(|&x| x & 0x80 != 0);
    let n = get_int(b, at, 7)?;
    let end = at.checked_add(n).filter(|&e| e <= b.len());
    let Some(end) = end else {
        return Err("a header string cut short".into());
    };
    let raw = &b[*at..end];
    *at = end;
    let bytes = if huffman {
        huffman_decode(raw)?
    } else {
        raw.to_vec()
    };
    String::from_utf8(bytes).map_err(|_| "a header that is not UTF-8".into())
}

// ----- encoder and decoder -----

/// Header names whose values are not put in tables (RFC 7541 7.1.3).
fn sensitive(name: &str) -> bool {
    matches!(
        name,
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie"
    )
}

/// Encodes header blocks.
#[derive(Clone, Debug)]
pub struct Encoder {
    table: Table,
    /// The most this end lets its table be (its own setting).
    cap: usize,
    huffman: bool,
    /// Size updates to signal at the start of the next block: the smallest
    /// since the last block, then the new size.
    updates: Option<(usize, usize)>,
}

impl Encoder {
    /// An encoder whose table is at most `cap` bytes (and at most 4096 until
    /// the other end says otherwise), Huffman coding strings if `huffman`.
    pub fn new(cap: usize, huffman: bool) -> Self {
        let mut e = Self {
            table: Table::new(4096),
            cap,
            huffman,
            updates: None,
        };
        e.peer_limit(4096);
        e
    }

    /// The other end's `SETTINGS_HEADER_TABLE_SIZE`.
    pub fn peer_limit(&mut self, limit: usize) {
        let size = limit.min(self.cap);
        if size == self.table.max {
            return;
        }
        let low = self.updates.map_or(size, |(l, _)| l.min(size));
        self.updates = Some((low.min(self.table.max), size));
        self.table.set_max(size);
    }

    /// The header block for `fields` (names in lower case).
    pub fn encode<'a>(&mut self, fields: impl IntoIterator<Item = (&'a str, &'a str)>) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some((low, size)) = self.updates.take() {
            if low < size {
                put_int(&mut out, 0x20, 5, low);
            }
            put_int(&mut out, 0x20, 5, size);
        }
        for (name, value) in fields {
            match self.table.find(name, value) {
                Some((i, true)) => put_int(&mut out, 0x80, 7, i),
                found => {
                    let name_index = found.map_or(0, |(i, _)| i);
                    if sensitive(name) {
                        put_int(&mut out, 0x10, 4, name_index);
                    } else {
                        put_int(&mut out, 0x40, 6, name_index);
                    }
                    if name_index == 0 {
                        put_string(&mut out, name, self.huffman);
                    }
                    put_string(&mut out, value, self.huffman);
                    if !sensitive(name) {
                        self.table.insert(name, value);
                    }
                }
            }
        }
        out
    }

    /// Entries in the dynamic table.
    pub fn table_len(&self) -> usize {
        self.table.entries.len()
    }
}

/// Decodes header blocks.
#[derive(Clone, Debug)]
pub struct Decoder {
    table: Table,
    /// What this end allows (its `SETTINGS_HEADER_TABLE_SIZE`).
    limit: usize,
}

impl Decoder {
    /// A decoder whose end allows a table of `limit` bytes. The table is
    /// 4096 bytes until the other end, having seen the setting, says
    /// otherwise; it may not grow past the larger of the two.
    pub fn new(limit: usize) -> Self {
        Self {
            table: Table::new(4096),
            limit: limit.max(4096),
        }
    }

    /// The fields of a header block, in order.
    pub fn decode(&mut self, b: &[u8]) -> Result<Vec<(String, String)>, String> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < b.len() {
            let first = b[at];
            if first & 0x80 != 0 {
                let i = get_int(b, &mut at, 7)?;
                let (n, v) = self
                    .table
                    .get(i)
                    .ok_or_else(|| format!("HPACK index {i} not in the tables"))?;
                out.push((n.to_string(), v.to_string()));
            } else if first & 0xe0 == 0x20 {
                if !out.is_empty() {
                    return Err("an HPACK table size update after a header".into());
                }
                let size = get_int(b, &mut at, 5)?;
                if size > self.limit {
                    return Err(format!(
                        "an HPACK table of {size} bytes, over the {} allowed",
                        self.limit
                    ));
                }
                self.table.set_max(size);
            } else {
                let (n, index) = if first & 0xc0 == 0x40 {
                    (6, true)
                } else {
                    (4, false)
                };
                let i = get_int(b, &mut at, n)?;
                let name = if i == 0 {
                    get_string(b, &mut at)?
                } else {
                    self.table
                        .get(i)
                        .ok_or_else(|| format!("HPACK index {i} not in the tables"))?
                        .0
                        .to_string()
                };
                let value = get_string(b, &mut at)?;
                if index {
                    self.table.insert(&name, &value);
                }
                out.push((name, value));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn integers_as_in_the_rfc() {
        // C.1.1, C.1.2, C.1.3
        let mut v = Vec::new();
        put_int(&mut v, 0, 5, 10);
        assert_eq!(v, [10]);
        v.clear();
        put_int(&mut v, 0, 5, 1337);
        assert_eq!(v, [31, 154, 10]);
        let mut at = 0;
        assert_eq!(get_int(&v, &mut at, 5).unwrap(), 1337);
        v.clear();
        put_int(&mut v, 0, 8, 42);
        assert_eq!(v, [42]);
        assert!(get_int(&[0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f], &mut 0, 5).is_err());
    }

    #[test]
    fn huffman_as_in_the_rfc() {
        let www = hex("f1e3 c2e5 f23a 6ba0 ab90 f4ff");
        assert_eq!(huffman_encode(b"www.example.com"), www);
        assert_eq!(huffman_decode(&www).unwrap(), b"www.example.com");
        let date = "Mon, 21 Oct 2013 20:13:21 GMT";
        let h = hex("d07a be94 1054 d444 a820 0595 040b 8166 e082 a62d 1bff");
        assert_eq!(huffman_encode(date.as_bytes()), h);
        assert_eq!(huffman_decode(&h).unwrap(), date.as_bytes());
        // Every byte value round trips.
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(huffman_decode(&huffman_encode(&all)).unwrap(), all);
        // Padding of a whole byte, or not ones, is refused.
        assert!(huffman_decode(&[0xff]).is_err());
        assert!(huffman_decode(&hex("f1e3 c2e5 f23a 6ba0 ab90 f4fe")).is_err());
    }

    #[test]
    fn requests_as_in_the_rfc() {
        // C.4: three requests with Huffman coding, one decoder.
        let mut d = Decoder::new(4096);
        let b1 = hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff");
        let f = d.decode(&b1).unwrap();
        assert_eq!(
            f,
            [
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com")
            ]
            .map(|(a, b)| (a.to_string(), b.to_string()))
        );
        let b2 = hex("8286 84be 5886 a8eb 1064 9cbf");
        let f = d.decode(&b2).unwrap();
        assert_eq!(f[4], ("cache-control".into(), "no-cache".into()));
        let b3 = hex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf");
        let f = d.decode(&b3).unwrap();
        assert_eq!(f[4], ("custom-key".into(), "custom-value".into()));
        assert_eq!(d.table.size, 164);

        // Our encoder writes the same bytes for them.
        let mut e = Encoder::new(4096, true);
        let r1 = [
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
        ];
        assert_eq!(e.encode(r1), b1);
        let mut r2 = r1.to_vec();
        r2.push(("cache-control", "no-cache"));
        assert_eq!(e.encode(r2), b2);
    }

    #[test]
    fn responses_evict_and_size_updates() {
        // C.6: responses with a 256-byte table.
        let mut d = Decoder::new(256);
        let mut e = Encoder::new(256, true);
        e.peer_limit(256);
        let r1 = [
            (":status", "302"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("location", "https://www.example.com"),
        ];
        let b = e.encode(r1);
        // Starts with the size update to 256 (0x3f 0xe1 0x01).
        assert_eq!(&b[..3], [0x3f, 0xe1, 0x01]);
        assert_eq!(d.decode(&b).unwrap().len(), 4);
        let r2 = [
            (":status", "307"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("location", "https://www.example.com"),
        ];
        let b = e.encode(r2);
        assert_eq!(d.decode(&b).unwrap()[0].1, "307");
        assert_eq!(d.table.entries.len(), 4);
        assert_eq!(e.table_len(), 4);
        // A sensitive value stays out of the tables.
        let b = e.encode([("authorization", "secret")]);
        assert_eq!(d.decode(&b).unwrap()[0].1, "secret");
        assert_eq!(e.table_len(), 4);
        // A shrink to 0 and back: both updates go out, the table empties.
        e.peer_limit(0);
        e.peer_limit(256);
        let b = e.encode([("x-a", "1")]);
        assert_eq!(&b[..2], [0x20, 0x3f]);
        assert_eq!(d.decode(&b).unwrap()[0].0, "x-a");
        assert_eq!(d.table.entries.len(), 1);
        // More than the decoder allows is refused.
        let mut small = Decoder::new(100);
        assert!(small.decode(&[0x3f, 0xe1, 0x01]).is_ok());
        let mut big = Vec::new();
        put_int(&mut big, 0x20, 5, 5000);
        assert!(small.decode(&big).is_err());
        assert!(d.decode(&[0xff, 0x7f]).is_err());
    }
}
