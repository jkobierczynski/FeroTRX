//! SIP messages (RFC 3261 section 7): parsing and building.

use std::fmt::Write as _;

/// A request or a response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Start {
    Request { method: String, uri: String },
    Response { code: u16, reason: String },
}

/// A SIP message: the start line, the headers in order, the body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Msg {
    pub start: Start,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// The full name of a compact header form.
fn full_name(n: &str) -> &str {
    match n {
        "v" | "V" => "Via",
        "f" | "F" => "From",
        "t" | "T" => "To",
        "i" | "I" => "Call-ID",
        "m" | "M" => "Contact",
        "l" | "L" => "Content-Length",
        "c" | "C" => "Content-Type",
        "k" | "K" => "Supported",
        "s" | "S" => "Subject",
        "e" | "E" => "Content-Encoding",
        _ => n,
    }
}

/// The reason phrase of the status codes FeroTRX sends.
pub fn reason(code: u16) -> &'static str {
    match code {
        100 => "Trying",
        180 => "Ringing",
        183 => "Session Progress",
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        480 => "Temporarily Unavailable",
        481 => "Call/Transaction Does Not Exist",
        486 => "Busy Here",
        487 => "Request Terminated",
        488 => "Not Acceptable Here",
        500 => "Server Internal Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        600 => "Busy Everywhere",
        603 => "Decline",
        _ => "Unknown",
    }
}

impl Msg {
    pub fn request(method: &str, uri: &str) -> Self {
        Self {
            start: Start::Request {
                method: method.into(),
                uri: uri.into(),
            },
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn response(code: u16) -> Self {
        Self {
            start: Start::Response {
                code,
                reason: reason(code).into(),
            },
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Parses one datagram; None if it is not SIP 2.0.
    pub fn parse(data: &[u8]) -> Option<Self> {
        // Keep-alives (CRLF) and other padding before the start line.
        let start = data.iter().position(|b| !b.is_ascii_whitespace())?;
        let data = &data[start..];
        let end = find(data, b"\r\n\r\n")
            .map(|i| (i, i + 4))
            .or_else(|| find(data, b"\n\n").map(|i| (i, i + 2)))?;
        let head = std::str::from_utf8(&data[..end.0]).ok()?;
        let mut lines: Vec<String> = Vec::new();
        for l in head.split('\n') {
            let l = l.trim_end_matches('\r');
            // Folded lines continue the header before.
            match lines.last_mut() {
                Some(last) if l.starts_with([' ', '\t']) => {
                    last.push(' ');
                    last.push_str(l.trim());
                }
                _ => lines.push(l.to_string()),
            }
        }
        let first = lines.first()?.as_str();
        let start = if let Some(rest) = first.strip_prefix("SIP/2.0 ") {
            let (code, reason) = rest.split_once(' ').unwrap_or((rest, ""));
            let code: u16 = code.parse().ok()?;
            if !(100..700).contains(&code) {
                return None;
            }
            Start::Response {
                code,
                reason: reason.into(),
            }
        } else {
            let mut w = first.split(' ');
            let (method, uri, version) = (w.next()?, w.next()?, w.next()?);
            if version != "SIP/2.0" || w.next().is_some() || method.is_empty() {
                return None;
            }
            Start::Request {
                method: method.into(),
                uri: uri.into(),
            }
        };
        let mut headers = Vec::new();
        for l in &lines[1..] {
            let (n, v) = l.split_once(':')?;
            headers.push((full_name(n.trim()).to_string(), v.trim().to_string()));
        }
        let mut msg = Self {
            start,
            headers,
            body: Vec::new(),
        };
        let rest = &data[end.1..];
        let len = match msg.get("Content-Length") {
            Some(l) => l.parse::<usize>().ok()?,
            None => rest.len(),
        };
        msg.body = rest.get(..len)?.to_vec();
        Some(msg)
    }

    /// The first header called `name` (any case).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Every value of header `name`, comma-separated lists split (for Via,
    /// Record-Route, Route).
    pub fn get_all(&self, name: &str) -> Vec<String> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .flat_map(|(_, v)| split_list(v))
            .collect()
    }

    pub fn header(&mut self, name: &str, value: impl Into<String>) -> &mut Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Copies header `name` (each of them) from `other`.
    pub fn copy(&mut self, other: &Msg, name: &str) -> &mut Self {
        for (n, v) in &other.headers {
            if n.eq_ignore_ascii_case(name) {
                self.headers.push((name.into(), v.clone()));
            }
        }
        self
    }

    pub fn set_body(&mut self, content_type: &str, body: Vec<u8>) -> &mut Self {
        self.header("Content-Type", content_type);
        self.body = body;
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut s = match &self.start {
            Start::Request { method, uri } => format!("{method} {uri} SIP/2.0\r\n"),
            Start::Response { code, reason } => format!("SIP/2.0 {code} {reason}\r\n"),
        };
        for (n, v) in &self.headers {
            if !n.eq_ignore_ascii_case("Content-Length") {
                let _ = write!(s, "{n}: {v}\r\n");
            }
        }
        let _ = write!(s, "Content-Length: {}\r\n\r\n", self.body.len());
        let mut out = s.into_bytes();
        out.extend_from_slice(&self.body);
        out
    }

    pub fn method(&self) -> Option<&str> {
        match &self.start {
            Start::Request { method, .. } => Some(method),
            Start::Response { .. } => None,
        }
    }

    pub fn code(&self) -> Option<u16> {
        match &self.start {
            Start::Response { code, .. } => Some(*code),
            Start::Request { .. } => None,
        }
    }

    pub fn call_id(&self) -> Option<&str> {
        self.get("Call-ID")
    }

    /// The CSeq number and method.
    pub fn cseq(&self) -> Option<(u32, &str)> {
        let v = self.get("CSeq")?;
        let (n, m) = v.split_once(char::is_whitespace)?;
        Some((n.trim().parse().ok()?, m.trim()))
    }

    /// The top Via's branch.
    pub fn branch(&self) -> Option<String> {
        let via = self.get_all("Via").into_iter().next()?;
        param(&via, "branch")
    }

    /// The tag of the From or To header.
    pub fn tag(&self, header: &str) -> Option<String> {
        param(self.get(header)?, "tag")
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Splits a header value at commas outside of quotes and angle brackets.
pub fn split_list(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (mut quoted, mut angle, mut cur) = (false, false, String::new());
    for c in v.chars() {
        match c {
            '"' => quoted = !quoted,
            '<' if !quoted => angle = true,
            '>' if !quoted => angle = false,
            ',' if !quoted && !angle => {
                out.push(cur.trim().to_string());
                cur.clear();
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// A `;name=value` parameter of a header value (outside of `<...>`); an
/// empty string for a parameter without a value.
pub fn param(v: &str, name: &str) -> Option<String> {
    let after = match v.rfind('>') {
        Some(i) => &v[i + 1..],
        None => v,
    };
    after.split(';').skip(1).find_map(|p| {
        let (k, val) = p.split_once('=').unwrap_or((p, ""));
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| val.trim().trim_matches('"').to_string())
    })
}

/// The URI of a name-addr (`"Bob" <sip:bob@lab>;tag=1`) or addr-spec.
pub fn uri_of(v: &str) -> String {
    match (v.find('<'), v.find('>')) {
        (Some(a), Some(b)) if a < b => v[a + 1..b].to_string(),
        _ => v.split(';').next().unwrap_or(v).trim().to_string(),
    }
}

/// The user part of a SIP URI: `bob` of `sip:bob@lab.local`.
pub fn uri_user(uri: &str) -> Option<&str> {
    let rest = uri
        .strip_prefix("sip:")
        .or_else(|| uri.strip_prefix("sips:"))?;
    let (user, _) = rest.split_once('@')?;
    Some(user.split(';').next().unwrap_or(user))
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITE: &str = "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
v: SIP/2.0/UDP proxy;branch=z9hG4bKother\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
i: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:alice@pc33.atlanta.com>\r\n\
Subject: a long\r\n folded line\r\n\
Content-Type: application/sdp\r\n\
l: 4\r\n\r\nv=0\r\nextra";

    #[test]
    fn parses_requests() {
        let m = Msg::parse(INVITE.as_bytes()).unwrap();
        assert_eq!(m.method(), Some("INVITE"));
        assert_eq!(m.call_id(), Some("a84b4c76e66710@pc33.atlanta.com"));
        assert_eq!(m.cseq(), Some((314159, "INVITE")));
        assert_eq!(m.branch().as_deref(), Some("z9hG4bK776asdhds"));
        assert_eq!(m.get_all("via").len(), 2);
        assert_eq!(m.tag("From").as_deref(), Some("1928301774"));
        assert_eq!(m.tag("To"), None);
        assert_eq!(m.get("Subject"), Some("a long folded line"));
        assert_eq!(m.body, b"v=0\r");
        assert_eq!(uri_of(m.get("To").unwrap()), "sip:bob@biloxi.com");
        assert_eq!(uri_user("sip:bob@biloxi.com"), Some("bob"));
        let again = Msg::parse(&m.to_bytes()).unwrap();
        assert_eq!(again, m);
    }

    #[test]
    fn parses_responses_and_rejects_others() {
        let mut r = Msg::response(486);
        r.header(
            "Via",
            "SIP/2.0/UDP a;branch=z9hG4bK1;rport=5060;received=10.0.0.1",
        )
        .header("CSeq", "2 INVITE");
        let m = Msg::parse(&r.to_bytes()).unwrap();
        assert_eq!(m.code(), Some(486));
        assert_eq!(m.cseq(), Some((2, "INVITE")));
        assert_eq!(
            param(m.get("Via").unwrap(), "rport").as_deref(),
            Some("5060")
        );
        assert!(Msg::parse(b"\r\n\r\n").is_none());
        assert!(Msg::parse(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(Msg::parse(b"SIP/2.0 99 x\r\n\r\n").is_none());
        assert!(Msg::parse(b"OPTIONS sip:x SIP/2.0\r\nContent-Length: 9\r\n\r\nshort").is_none());
        assert_eq!(
            split_list("<sip:a;lr>, \"x, y\" <sip:b>"),
            ["<sip:a;lr>", "\"x, y\" <sip:b>"]
        );
    }
}
