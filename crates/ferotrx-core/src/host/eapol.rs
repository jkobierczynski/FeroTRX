//! 802.1X port authentication (EAPOL, IEEE 802.1X-2010) with EAP-MD5
//! (RFC 3748): a supplicant that authenticates the host before it uses the
//! link, and an authenticator role to test supplicants against.

use std::time::Duration;

use super::Me;
use crate::app::sip::digest::md5;
use crate::tcp::wire::{pad, push_link};
use crate::{Error, MacAddr, Result};

/// The port access entity group address.
pub(crate) const PAE_MAC: MacAddr = MacAddr([0x01, 0x80, 0xc2, 0x00, 0x00, 0x03]);
pub(crate) const ETHERTYPE_EAPOL: u16 = 0x888e;

const EAPOL_PACKET: u8 = 0;
const EAPOL_START: u8 = 1;
const EAPOL_LOGOFF: u8 = 2;

const EAP_REQUEST: u8 = 1;
const EAP_RESPONSE: u8 = 2;
const EAP_SUCCESS: u8 = 3;
const EAP_FAILURE: u8 = 4;

const TYPE_IDENTITY: u8 = 1;
const TYPE_NAK: u8 = 3;
const TYPE_MD5: u8 = 4;

/// EAPOL-Starts sent before the supplicant gives up waiting (802.1X maxStart).
const MAX_START: u32 = 3;

/// A host's 802.1X supplicant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dot1xConfig {
    pub identity: String,
    /// For EAP-MD5.
    pub password: String,
    /// Send an EAPOL-Logoff at the end (default on).
    pub logoff: bool,
    /// Wait for an authenticator (default on); off, the host goes on
    /// unauthenticated after three unanswered EAPOL-Starts, like a
    /// supplicant on a port without 802.1X.
    pub required: bool,
}

impl Dot1xConfig {
    pub fn new(identity: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            identity: identity.into(),
            password: password.into(),
            logoff: true,
            required: true,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.identity.is_empty() || self.identity.len() > 253 {
            return Err(Error::Host(
                "dot1x: the identity must be 1-253 bytes".into(),
            ));
        }
        Ok(())
    }
}

/// Where a supplicant is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Dot1xState {
    /// Sending EAPOL-Starts, no authenticator heard yet.
    #[default]
    Connecting,
    /// In an EAP exchange.
    Authenticating,
    /// EAP-Success: the port is open.
    Authorized,
    /// EAP-Failure.
    Refused,
    /// No authenticator answered three EAPOL-Starts and `required` is
    /// off: the host goes on unauthenticated.
    NoAuthenticator,
}

impl std::fmt::Display for Dot1xState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Dot1xState::Connecting => "connecting",
            Dot1xState::Authenticating => "authenticating",
            Dot1xState::Authorized => "authorized",
            Dot1xState::Refused => "refused",
            Dot1xState::NoAuthenticator => "no authenticator",
        })
    }
}

/// What a supplicant did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dot1xStatus {
    pub state: Dot1xState,
    pub identity: String,
    /// The authenticator's MAC, once heard.
    pub authenticator: Option<MacAddr>,
    /// The EAP method used, e.g. `MD5`.
    pub method: Option<String>,
    pub starts: u64,
    /// EAP responses sent.
    pub responses: u64,
    pub successes: u64,
    pub failures: u64,
    /// From the first EAPOL-Start to EAP-Success.
    pub auth_time: Option<Duration>,
}

/// What an EAPOL frame did to a supplicant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Event {
    Authorized,
    Refused,
}

/// One host's supplicant.
#[derive(Debug)]
pub(crate) struct Supplicant {
    cfg: Dot1xConfig,
    status: Dot1xStatus,
    began: Option<Duration>,
    next_start: Duration,
    interval: Duration,
    /// Give up waiting for an authenticator (and fail) after the starts.
    strict: bool,
}

fn eapol(me: &Me, dst: MacAddr, kind: u8, body: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(64);
    push_link(&mut f, dst, me.mac, me.vlan, ETHERTYPE_EAPOL);
    f.push(2); // 802.1X-2004
    f.push(kind);
    f.extend_from_slice(&(body.len() as u16).to_be_bytes());
    f.extend_from_slice(body);
    pad(f)
}

fn eap(code: u8, id: u8, kind: Option<u8>, data: &[u8]) -> Vec<u8> {
    let len = 4 + usize::from(kind.is_some()) + data.len();
    let mut p = vec![code, id];
    p.extend_from_slice(&(len as u16).to_be_bytes());
    if let Some(t) = kind {
        p.push(t);
    }
    p.extend_from_slice(data);
    p
}

/// An EAPOL frame: its type and EAP packet (code, id, type, data).
struct Eapol<'a> {
    kind: u8,
    code: u8,
    id: u8,
    eap_type: Option<u8>,
    data: &'a [u8],
}

fn parse(p: &[u8]) -> Option<Eapol<'_>> {
    if p.len() < 4 {
        return None;
    }
    let kind = p[1];
    let len = usize::from(u16::from_be_bytes([p[2], p[3]]));
    let body = p.get(4..4 + len)?;
    if kind != EAPOL_PACKET {
        return Some(Eapol {
            kind,
            code: 0,
            id: 0,
            eap_type: None,
            data: &[],
        });
    }
    if body.len() < 4 {
        return None;
    }
    let elen = usize::from(u16::from_be_bytes([body[2], body[3]]));
    let e = body.get(..elen)?;
    let (eap_type, data) = if elen > 4 {
        (Some(e[4]), &e[5..])
    } else {
        (None, &e[4..])
    };
    Some(Eapol {
        kind,
        code: e[0],
        id: e[1],
        eap_type,
        data,
    })
}

/// The EAP-MD5 response value: MD5 of the id, the password and the challenge.
fn md5_value(id: u8, password: &str, challenge: &[u8]) -> [u8; 16] {
    let mut b = vec![id];
    b.extend_from_slice(password.as_bytes());
    b.extend_from_slice(challenge);
    md5(&b)
}

impl Supplicant {
    pub fn new(cfg: Dot1xConfig, retry: Duration) -> Self {
        let strict = cfg.required;
        Self {
            status: Dot1xStatus {
                identity: cfg.identity.clone(),
                ..Dot1xStatus::default()
            },
            cfg,
            began: None,
            next_start: Duration::MAX,
            interval: retry,
            strict,
        }
    }

    pub fn authorized(&self) -> bool {
        matches!(
            self.status.state,
            Dot1xState::Authorized | Dot1xState::NoAuthenticator
        )
    }

    #[cfg(test)]
    pub fn refused(&self) -> bool {
        self.status.state == Dot1xState::Refused
    }

    pub fn begin(&mut self, now: Duration) {
        self.began = Some(now);
        self.next_start = now;
    }

    pub fn next_wake(&self) -> Duration {
        match self.status.state {
            Dot1xState::Connecting => self.next_start,
            _ => Duration::MAX,
        }
    }

    /// EAPOL-Starts while no authenticator answered; after `MAX_START` the
    /// host goes on unauthenticated, unless `strict`.
    pub fn poll(&mut self, me: &Me, now: Duration, out: &mut Vec<Vec<u8>>) -> Option<Event> {
        if self.status.state != Dot1xState::Connecting || now < self.next_start {
            return None;
        }
        if self.status.starts >= u64::from(MAX_START) && !self.strict {
            self.status.state = Dot1xState::NoAuthenticator;
            self.next_start = Duration::MAX;
            return Some(Event::Authorized);
        }
        self.status.starts += 1;
        self.next_start = now + self.interval;
        self.interval = (self.interval * 2).min(Duration::from_secs(30));
        out.push(eapol(me, PAE_MAC, EAPOL_START, &[]));
        None
    }

    /// Takes an EAPOL frame from `src`; answers go to `out`.
    pub fn take(
        &mut self,
        me: &Me,
        src: MacAddr,
        payload: &[u8],
        now: Duration,
        out: &mut Vec<Vec<u8>>,
    ) -> Option<Event> {
        let p = parse(payload)?;
        if p.kind != EAPOL_PACKET {
            return None;
        }
        match p.code {
            EAP_REQUEST => {
                if self.status.state == Dot1xState::Refused {
                    return None;
                }
                let restarted = self.status.state != Dot1xState::Authenticating;
                self.status.authenticator = Some(src);
                if restarted && self.authorized() {
                    // Reauthentication: the port stays open meanwhile.
                } else {
                    self.status.state = Dot1xState::Authenticating;
                }
                let reply = match p.eap_type {
                    Some(TYPE_IDENTITY) => eap(
                        EAP_RESPONSE,
                        p.id,
                        Some(TYPE_IDENTITY),
                        self.cfg.identity.as_bytes(),
                    ),
                    Some(TYPE_MD5) => {
                        let n = usize::from(*p.data.first()?);
                        let challenge = p.data.get(1..1 + n)?;
                        self.status.method = Some("MD5".into());
                        let mut v = vec![16];
                        v.extend_from_slice(&md5_value(p.id, &self.cfg.password, challenge));
                        v.extend_from_slice(self.cfg.identity.as_bytes());
                        eap(EAP_RESPONSE, p.id, Some(TYPE_MD5), &v)
                    }
                    // Notification: acknowledge.
                    Some(2) => eap(EAP_RESPONSE, p.id, Some(2), &[]),
                    // Another method: ask for MD5 (a legacy Nak).
                    Some(_) => eap(EAP_RESPONSE, p.id, Some(TYPE_NAK), &[TYPE_MD5]),
                    None => return None,
                };
                self.status.responses += 1;
                out.push(eapol(me, PAE_MAC, EAPOL_PACKET, &reply));
                None
            }
            EAP_SUCCESS => {
                if self.status.state == Dot1xState::Authorized {
                    return None;
                }
                self.status.successes += 1;
                self.status.state = Dot1xState::Authorized;
                self.status.authenticator = Some(src);
                self.status.auth_time = self.began.map(|b| now.saturating_sub(b));
                Some(Event::Authorized)
            }
            EAP_FAILURE => {
                if self.status.state == Dot1xState::Refused {
                    return None;
                }
                self.status.failures += 1;
                self.status.state = Dot1xState::Refused;
                self.status.authenticator = Some(src);
                Some(Event::Refused)
            }
            _ => None,
        }
    }

    /// An EAPOL-Logoff, when the host stops.
    pub fn logoff(&self, me: &Me) -> Option<Vec<u8>> {
        (self.cfg.logoff && self.status.state == Dot1xState::Authorized)
            .then(|| eapol(me, PAE_MAC, EAPOL_LOGOFF, &[]))
    }

    pub fn status(&self) -> Dot1xStatus {
        self.status.clone()
    }
}

/// A host's 802.1X authenticator role: EAP-MD5 against its user list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatorConfig {
    /// Identities and passwords.
    pub users: Vec<(String, String)>,
}

/// A supplicant an authenticator role dealt with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dot1xSession {
    pub mac: MacAddr,
    pub identity: Option<String>,
    /// `authenticating`, `authorized`, `refused` or `logged off`.
    pub state: String,
}

/// What an authenticator role did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthenticatorStatus {
    pub sessions: Vec<Dot1xSession>,
    pub starts: u64,
    pub successes: u64,
    pub failures: u64,
    pub logoffs: u64,
}

#[derive(Debug)]
struct Pending {
    id: u8,
    challenge: [u8; 16],
}

/// One host's authenticator role.
#[derive(Debug)]
pub(crate) struct Authenticator {
    cfg: AuthenticatorConfig,
    status: AuthenticatorStatus,
    pending: Vec<Option<Pending>>,
    next_id: u8,
    rng: u64,
}

impl Authenticator {
    pub fn new(cfg: AuthenticatorConfig, seed: u64) -> Self {
        Self {
            cfg,
            status: AuthenticatorStatus::default(),
            pending: Vec::new(),
            next_id: 1,
            rng: seed | 1,
        }
    }

    fn rand(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn session(&mut self, mac: MacAddr) -> usize {
        match self.status.sessions.iter().position(|s| s.mac == mac) {
            Some(i) => i,
            None => {
                self.status.sessions.push(Dot1xSession {
                    mac,
                    identity: None,
                    state: "authenticating".into(),
                });
                self.pending.push(None);
                self.status.sessions.len() - 1
            }
        }
    }

    fn id(&mut self) -> u8 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }

    /// Takes an EAPOL frame from supplicant `src`; answers go to `out`.
    pub fn take(&mut self, me: &Me, src: MacAddr, payload: &[u8], out: &mut Vec<Vec<u8>>) {
        let Some(p) = parse(payload) else { return };
        let i = self.session(src);
        let send = |out: &mut Vec<Vec<u8>>, body: Vec<u8>| {
            out.push(eapol(me, src, EAPOL_PACKET, &body));
        };
        match (p.kind, p.code, p.eap_type) {
            (EAPOL_START, _, _) => {
                self.status.starts += 1;
                self.status.sessions[i].state = "authenticating".into();
                let id = self.id();
                self.pending[i] = None;
                send(out, eap(EAP_REQUEST, id, Some(TYPE_IDENTITY), &[]));
            }
            (EAPOL_LOGOFF, _, _) => {
                self.status.logoffs += 1;
                self.status.sessions[i].state = "logged off".into();
            }
            (EAPOL_PACKET, EAP_RESPONSE, Some(TYPE_IDENTITY)) => {
                let identity = String::from_utf8_lossy(p.data).into_owned();
                self.status.sessions[i].identity = Some(identity);
                let id = self.id();
                let mut challenge = [0u8; 16];
                let a = self.rand().to_be_bytes();
                let b = self.rand().to_be_bytes();
                challenge[..8].copy_from_slice(&a);
                challenge[8..].copy_from_slice(&b);
                self.pending[i] = Some(Pending { id, challenge });
                let mut v = vec![16];
                v.extend_from_slice(&challenge);
                send(out, eap(EAP_REQUEST, id, Some(TYPE_MD5), &v));
            }
            (EAPOL_PACKET, EAP_RESPONSE, Some(t)) => {
                let ok = match (t, self.pending[i].take()) {
                    (TYPE_MD5, Some(pend)) if pend.id == p.id => {
                        let identity = self.status.sessions[i].identity.clone().unwrap_or_default();
                        let value = p.data.get(1..17);
                        self.cfg
                            .users
                            .iter()
                            .find(|(u, _)| *u == identity)
                            .is_some_and(|(_, pw)| {
                                value == Some(&md5_value(pend.id, pw, &pend.challenge)[..])
                            })
                    }
                    // A Nak or anything else: only MD5 is offered.
                    _ => false,
                };
                let code = if ok {
                    self.status.successes += 1;
                    self.status.sessions[i].state = "authorized".into();
                    EAP_SUCCESS
                } else {
                    self.status.failures += 1;
                    self.status.sessions[i].state = "refused".into();
                    EAP_FAILURE
                };
                send(out, eap(code, p.id, None, &[]));
            }
            _ => {}
        }
    }

    pub fn status(&self) -> AuthenticatorStatus {
        self.status.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::wire::parse_link;

    fn me(n: u8) -> Me {
        Me {
            mac: MacAddr([2, 0xdc, 0, 0, 1, n]),
            vlan: None,
            hostname: None,
            ip4: None,
            gateway4: None,
            ip6: None,
            gateway6: None,
            ll: None,
        }
    }

    /// Runs a supplicant against an authenticator until neither sends.
    fn exchange(sup: &mut Supplicant, auth: &mut Authenticator) -> Option<Event> {
        let (s, a) = (me(1), me(2));
        let mut to_auth = Vec::new();
        sup.begin(Duration::ZERO);
        sup.poll(&s, Duration::ZERO, &mut to_auth);
        let mut event = None;
        for _ in 0..10 {
            let mut to_sup = Vec::new();
            for f in to_auth.drain(..) {
                let l = parse_link(&f).unwrap();
                assert_eq!(l.ethertype, ETHERTYPE_EAPOL);
                auth.take(&a, l.src, &f[l.payload..], &mut to_sup);
            }
            for f in to_sup {
                let l = parse_link(&f).unwrap();
                assert_eq!(l.dst, s.mac);
                if let Some(e) = sup.take(
                    &s,
                    l.src,
                    &f[l.payload..],
                    Duration::from_millis(5),
                    &mut to_auth,
                ) {
                    event = Some(e);
                }
            }
        }
        event
    }

    #[test]
    fn md5_against_the_authenticator_role() {
        let users = vec![("alice".to_string(), "secret".to_string())];
        let mut auth = Authenticator::new(AuthenticatorConfig { users }, 7);
        let mut sup = Supplicant::new(Dot1xConfig::new("alice", "secret"), Duration::from_secs(1));
        assert_eq!(exchange(&mut sup, &mut auth), Some(Event::Authorized));
        let s = sup.status();
        assert_eq!(s.state, Dot1xState::Authorized);
        assert_eq!(s.method.as_deref(), Some("MD5"));
        assert_eq!(s.responses, 2);
        assert_eq!(s.auth_time, Some(Duration::from_millis(5)));
        assert!(sup.logoff(&me(1)).is_some());
        let a = auth.status();
        assert_eq!(a.successes, 1);
        assert_eq!(a.sessions[0].identity.as_deref(), Some("alice"));

        let mut sup = Supplicant::new(Dot1xConfig::new("alice", "wrong"), Duration::from_secs(1));
        assert_eq!(exchange(&mut sup, &mut auth), Some(Event::Refused));
        assert!(sup.refused());
        assert_eq!(auth.status().failures, 1);
    }

    #[test]
    fn rfc_3748_md5_value() {
        // The value is MD5 over id, secret and challenge (as in CHAP).
        let v = md5_value(1, "secret", &[0u8; 16]);
        let mut b = vec![1];
        b.extend_from_slice(b"secret");
        b.extend_from_slice(&[0u8; 16]);
        assert_eq!(v, md5(&b));
    }

    #[test]
    fn no_authenticator_lets_the_host_on() {
        let mut cfg = Dot1xConfig::new("bob", "x");
        cfg.required = false;
        let mut sup = Supplicant::new(cfg, Duration::from_secs(1));
        sup.begin(Duration::ZERO);
        let mut out = Vec::new();
        let mut now = Duration::ZERO;
        let mut event = None;
        while event.is_none() && now < Duration::from_secs(60) {
            event = sup.poll(&me(1), now, &mut out);
            now += Duration::from_millis(100);
        }
        assert_eq!(event, Some(Event::Authorized));
        assert_eq!(out.len(), 3);
        assert_eq!(sup.status().state, Dot1xState::NoAuthenticator);
    }
}
