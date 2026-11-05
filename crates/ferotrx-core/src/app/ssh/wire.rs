//! SSH's data types (RFC 4251 section 5).

pub(crate) struct Writer(Vec<u8>);

impl Writer {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn msg(kind: u8) -> Self {
        Self(vec![kind])
    }

    pub fn byte(&mut self, b: u8) -> &mut Self {
        self.0.push(b);
        self
    }

    pub fn bool(&mut self, b: bool) -> &mut Self {
        self.byte(u8::from(b))
    }

    pub fn u32(&mut self, n: u32) -> &mut Self {
        self.0.extend_from_slice(&n.to_be_bytes());
        self
    }

    pub fn string(&mut self, s: &[u8]) -> &mut Self {
        self.u32(s.len() as u32);
        self.0.extend_from_slice(s);
        self
    }

    pub fn str(&mut self, s: &str) -> &mut Self {
        self.string(s.as_bytes())
    }

    pub fn names(&mut self, names: &[String]) -> &mut Self {
        self.str(&names.join(","))
    }

    /// An unsigned big-endian number as an mpint.
    pub fn mpint(&mut self, n: &[u8]) -> &mut Self {
        let start = n.iter().position(|&b| b != 0).unwrap_or(n.len());
        let n = &n[start..];
        if n.first().is_some_and(|&b| b & 0x80 != 0) {
            self.u32(n.len() as u32 + 1);
            self.0.push(0);
            self.0.extend_from_slice(n);
        } else {
            self.string(n);
        }
        self
    }

    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

pub(crate) struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b }
    }

    pub fn byte(&mut self) -> Option<u8> {
        let (&x, rest) = self.b.split_first()?;
        self.b = rest;
        Some(x)
    }

    pub fn bool(&mut self) -> Option<bool> {
        self.byte().map(|b| b != 0)
    }

    pub fn u32(&mut self) -> Option<u32> {
        let (x, rest) = self.b.split_first_chunk::<4>()?;
        self.b = rest;
        Some(u32::from_be_bytes(*x))
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.b.len() < n {
            return None;
        }
        let (x, rest) = self.b.split_at(n);
        self.b = rest;
        Some(x)
    }

    pub fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    pub fn str(&mut self) -> Option<&'a str> {
        std::str::from_utf8(self.string()?).ok()
    }

    pub fn names(&mut self) -> Option<Vec<String>> {
        let s = self.str()?;
        Some(
            s.split(',')
                .filter(|n| !n.is_empty())
                .map(str::to_string)
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mpints_and_strings() {
        let mut w = Writer::new();
        w.mpint(&[0, 0, 0x7f]).mpint(&[0x80, 1]).mpint(&[0, 0]);
        assert_eq!(
            w.into_inner(),
            [0, 0, 0, 1, 0x7f, 0, 0, 0, 3, 0, 0x80, 1, 0, 0, 0, 0]
        );
        let mut w = Writer::msg(20);
        w.str("ab")
            .names(&["x".into(), "y".into()])
            .bool(true)
            .u32(7);
        let b = w.into_inner();
        let mut r = Reader::new(&b);
        assert_eq!(r.byte(), Some(20));
        assert_eq!(r.str(), Some("ab"));
        assert_eq!(r.names().unwrap(), ["x", "y"]);
        assert_eq!(r.bool(), Some(true));
        assert_eq!(r.u32(), Some(7));
        assert_eq!(r.byte(), None);
        assert_eq!(Reader::new(&[0, 0, 0, 9, 1]).string(), None);
    }
}
