//! TLS for the control server and client (rustls), client certificates,
//! and a small certificate authority for labs ([`LabPki`]).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName, UnixTime,
};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{ClientCertVerifierBuilder, WebPkiClientVerifier};
use rustls::RootCertStore;

use crate::protocol::Role;

/// Error setting up TLS: a file that cannot be read, PEM that does not
/// parse, a certificate rustls refuses.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TlsError(String);

impl TlsError {
    fn new(msg: impl std::fmt::Display) -> Self {
        Self(msg.to_string())
    }

    pub(crate) fn from_rustls(e: &rustls::Error) -> Self {
        Self(format!("TLS: {e}"))
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn read(path: &Path) -> Result<Vec<u8>, TlsError> {
    std::fs::read(path).map_err(|e| TlsError(format!("cannot read {}: {e}", path.display())))
}

fn certs(pem: &[u8], what: &str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let list = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError(format!("{what}: {e}")))?;
    if list.is_empty() {
        return Err(TlsError(format!("{what}: no certificate in it")));
    }
    Ok(list)
}

fn key(pem: &[u8], what: &str) -> Result<PrivateKeyDer<'static>, TlsError> {
    PrivateKeyDer::from_pem_slice(pem).map_err(|e| TlsError(format!("{what}: {e}")))
}

fn roots(cas: &[CertificateDer<'static>], what: &str) -> Result<RootCertStore, TlsError> {
    let mut store = RootCertStore::empty();
    for c in cas {
        store
            .add(c.clone())
            .map_err(|e| TlsError(format!("{what}: {e}")))?;
    }
    Ok(store)
}

/// The server's side of TLS: its certificate and key, and the certificate
/// authorities whose client certificates log in, each with a role.
#[derive(Clone)]
pub struct ServerTls {
    chain: Vec<CertificateDer<'static>>,
    key: Arc<PrivateKeyDer<'static>>,
    client_cas: Vec<(Role, Vec<CertificateDer<'static>>)>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    denied: HashSet<String>,
}

impl std::fmt::Debug for ServerTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerTls")
            .field("certificates", &self.chain.len())
            .field(
                "client_cas",
                &self.client_cas.iter().map(|(r, _)| *r).collect::<Vec<_>>(),
            )
            .field("crls", &self.crls.len())
            .field("denied", &self.denied.len())
            .finish_non_exhaustive()
    }
}

impl ServerTls {
    /// A certificate chain (the server's certificate first) and its private
    /// key, both PEM.
    pub fn from_pem(chain: &[u8], key_pem: &[u8]) -> Result<Self, TlsError> {
        Ok(Self {
            chain: certs(chain, "server certificate")?,
            key: Arc::new(key(key_pem, "server key")?),
            client_cas: Vec::new(),
            crls: Vec::new(),
            denied: HashSet::new(),
        })
    }

    pub fn from_files(chain: &Path, key: &Path) -> Result<Self, TlsError> {
        Self::from_pem(&read(chain)?, &read(key)?)
            .map_err(|e| TlsError(format!("{} / {}: {e}", chain.display(), key.display())))
    }

    /// Clients with a certificate from this authority (PEM, one or more
    /// certificates) log in with `role`. When one authority is given for
    /// both roles, operator wins.
    pub fn with_client_ca(mut self, role: Role, ca_pem: &[u8]) -> Result<Self, TlsError> {
        let cas = certs(ca_pem, "client CA")?;
        roots(&cas, "client CA")?;
        self.client_cas.push((role, cas));
        Ok(self)
    }

    pub fn with_client_ca_file(self, role: Role, path: &Path) -> Result<Self, TlsError> {
        self.with_client_ca(role, &read(path)?)
            .map_err(|e| TlsError(format!("{}: {e}", path.display())))
    }

    /// True when client certificates can log in.
    pub fn verifies_clients(&self) -> bool {
        !self.client_cas.is_empty()
    }

    /// Refuses client certificates this certificate revocation list (PEM,
    /// one or more, or DER) names. Certificates from an authority without a
    /// list are not checked.
    pub fn with_crl(mut self, data: &[u8]) -> Result<Self, TlsError> {
        if data.windows(10).any(|w| w == b"-----BEGIN") {
            let list = CertificateRevocationListDer::pem_slice_iter(data)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| TlsError(format!("CRL: {e}")))?;
            if list.is_empty() {
                return Err(TlsError::new("CRL: no X509 CRL in it"));
            }
            self.crls.extend(list);
        } else {
            self.crls
                .push(CertificateRevocationListDer::from(data.to_vec()));
        }
        Ok(self)
    }

    pub fn with_crl_file(self, path: &Path) -> Result<Self, TlsError> {
        self.with_crl(&read(path)?)
            .map_err(|e| TlsError(format!("{}: {e}", path.display())))
    }

    /// Refuses the client certificate with this SHA-256 fingerprint (hex,
    /// colons allowed), as `server.info`'s audit log names certificates.
    pub fn deny(mut self, sha256: &str) -> Result<Self, TlsError> {
        let fp: String = sha256
            .chars()
            .filter(|c| *c != ':')
            .collect::<String>()
            .to_ascii_lowercase();
        if fp.len() != 64 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(TlsError(format!(
                "'{sha256}' is not a SHA-256 certificate fingerprint (64 hex digits)"
            )));
        }
        self.denied.insert(fp);
        Ok(self)
    }

    /// Refuses the client certificates a file lists: one SHA-256
    /// fingerprint per line, anything after it on the line and lines
    /// starting with `#` ignored.
    pub fn with_deny_file(mut self, path: &Path) -> Result<Self, TlsError> {
        let text = String::from_utf8(read(path)?)
            .map_err(|_| TlsError(format!("{}: not text", path.display())))?;
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            let Some(fp) = line.split_whitespace().next() else {
                continue;
            };
            self = self
                .deny(fp)
                .map_err(|e| TlsError(format!("{} line {}: {e}", path.display(), n + 1)))?;
        }
        Ok(self)
    }

    /// Revocation lists given.
    pub fn crl_count(&self) -> usize {
        self.crls.len()
    }

    /// Certificate fingerprints refused.
    pub fn denied_count(&self) -> usize {
        self.denied.len()
    }

    /// When the server's certificate expires, in seconds since 1970.
    pub fn expires(&self) -> Option<i64> {
        cert_fields(self.chain.first()?)?.not_after
    }

    /// The rustls configuration. With `cert_optional`, clients without a
    /// certificate may connect (and log in with a token).
    pub(crate) fn build(&self, cert_optional: bool) -> Result<TlsSetup, TlsError> {
        let provider = provider();
        let mut verifiers = Vec::new();
        let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(TlsError::new)?;
        let config = if self.client_cas.is_empty() {
            builder.with_no_client_auth()
        } else {
            let mut all = RootCertStore::empty();
            let mut order: Vec<&(Role, Vec<CertificateDer<'static>>)> =
                self.client_cas.iter().collect();
            // Operator first, so a certificate both authorities accept gets operator.
            order.sort_by_key(|(r, _)| std::cmp::Reverse(*r));
            for (role, cas) in order {
                let store = roots(cas, "client CA")?;
                for c in cas {
                    all.add(c.clone()).map_err(TlsError::new)?;
                }
                let b =
                    WebPkiClientVerifier::builder_with_provider(Arc::new(store), provider.clone());
                let v = self.revoking(b).build().map_err(crl_error)?;
                verifiers.push((*role, v));
            }
            let mut b = self.revoking(WebPkiClientVerifier::builder_with_provider(
                Arc::new(all),
                provider,
            ));
            if cert_optional {
                b = b.allow_unauthenticated();
            }
            builder.with_client_cert_verifier(b.build().map_err(crl_error)?)
        };
        let mut config = config
            .with_single_cert(self.chain.clone(), self.key.clone_key())
            .map_err(|e| TlsError(format!("server certificate and key: {e}")))?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        Ok(TlsSetup {
            config: Arc::new(config),
            verifiers,
            denied: self.denied.clone(),
            expires: self.expires(),
        })
    }

    fn revoking(&self, b: ClientCertVerifierBuilder) -> ClientCertVerifierBuilder {
        if self.crls.is_empty() {
            return b;
        }
        // The lab's chains are CA -> certificate; an authority without a list
        // (say the read-only one, before anything was revoked) is not checked.
        b.with_crls(self.crls.iter().cloned())
            .only_check_end_entity_revocation()
            .allow_unknown_revocation_status()
    }
}

fn crl_error(e: rustls::server::VerifierBuilderError) -> TlsError {
    TlsError(format!("client CAs and CRLs: {e}"))
}

/// ALPN protocol name: the control protocol, one JSON-RPC object per line.
const ALPN: &[u8] = b"ferotrx-ctl";

pub(crate) struct TlsSetup {
    pub config: Arc<rustls::ServerConfig>,
    verifiers: Vec<(Role, Arc<dyn ClientCertVerifier>)>,
    denied: HashSet<String>,
    /// When the server's certificate expires (seconds since 1970).
    pub expires: Option<i64>,
}

impl TlsSetup {
    /// True when the certificate with this fingerprint is refused.
    pub fn is_denied(&self, sha256: &str) -> bool {
        self.denied.contains(sha256)
    }

    /// The role a verified client chain gives.
    pub fn role_of(&self, chain: &[CertificateDer<'static>]) -> Option<Role> {
        let (end, rest) = chain.split_first()?;
        let now = UnixTime::now();
        self.verifiers
            .iter()
            .find(|(_, v)| v.verify_client_cert(end, rest, now).is_ok())
            .map(|(r, _)| *r)
    }
}

/// The client's side of TLS: the authority that signed the server's
/// certificate, and optionally a client certificate to log in with.
#[derive(Clone)]
pub struct ClientTls {
    roots: Arc<RootCertStore>,
    cert: Option<(Vec<CertificateDer<'static>>, Arc<PrivateKeyDer<'static>>)>,
    server_name: Option<String>,
}

impl std::fmt::Debug for ClientTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientTls")
            .field("client_cert", &self.cert.is_some())
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl ClientTls {
    /// Trusts server certificates from this authority (PEM).
    pub fn from_ca_pem(ca: &[u8]) -> Result<Self, TlsError> {
        Ok(Self {
            roots: Arc::new(roots(&certs(ca, "CA")?, "CA")?),
            cert: None,
            server_name: None,
        })
    }

    pub fn from_ca_file(path: &Path) -> Result<Self, TlsError> {
        Self::from_ca_pem(&read(path)?).map_err(|e| TlsError(format!("{}: {e}", path.display())))
    }

    /// Logs in with this client certificate (chain, PEM) and key.
    pub fn with_client_cert(mut self, chain: &[u8], key_pem: &[u8]) -> Result<Self, TlsError> {
        self.cert = Some((
            certs(chain, "client certificate")?,
            Arc::new(key(key_pem, "client key")?),
        ));
        Ok(self)
    }

    pub fn with_client_cert_files(self, chain: &Path, key: &Path) -> Result<Self, TlsError> {
        self.with_client_cert(&read(chain)?, &read(key)?)
            .map_err(|e| TlsError(format!("{} / {}: {e}", chain.display(), key.display())))
    }

    /// Checks the server's certificate for this name instead of the host
    /// the client connects to.
    pub fn with_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = Some(name.into());
        self
    }

    pub(crate) fn connection(&self, host: &str) -> Result<rustls::ClientConnection, TlsError> {
        let b = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(TlsError::new)?
            .with_root_certificates(self.roots.clone());
        let mut config = match &self.cert {
            Some((chain, key)) => b
                .with_client_auth_cert(chain.clone(), key.clone_key())
                .map_err(|e| TlsError(format!("client certificate and key: {e}")))?,
            None => b.with_no_client_auth(),
        };
        config.alpn_protocols = vec![ALPN.to_vec()];
        let name = self.server_name.as_deref().unwrap_or(host);
        let name = name.trim_start_matches('[').trim_end_matches(']');
        let server_name = ServerName::try_from(name.to_string())
            .map_err(|_| TlsError(format!("'{name}' is not a host name or address")))?;
        rustls::ClientConnection::new(Arc::new(config), server_name).map_err(TlsError::new)
    }
}

/// SHA-256 of a certificate, in hex: how the audit log names a certificate.
pub fn fingerprint(der: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, der);
    d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// The parts of a certificate the server and [`LabPki`] look at.
pub(crate) struct CertFields<'a> {
    /// The serial number's bytes, as encoded.
    pub serial: &'a [u8],
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    /// The end of its validity, seconds since 1970.
    pub not_after: Option<i64>,
}

pub(crate) fn cert_fields(der: &[u8]) -> Option<CertFields<'_>> {
    // Certificate ::= SEQUENCE { tbsCertificate, ... }
    let (_, cert, _) = tlv(der)?;
    let (_, mut tbs, _) = tlv(cert)?;
    // tbsCertificate: [0] version (optional), serial, signature, issuer, validity, subject
    let (tag, _, rest) = tlv(tbs)?;
    if tag == 0xa0 {
        tbs = rest;
    }
    let (_, serial, rest) = tlv(tbs)?;
    let (_, _signature, rest) = tlv(rest)?;
    let (_, issuer, rest) = tlv(rest)?;
    let (_, validity, rest) = tlv(rest)?;
    let (_, subject, _) = tlv(rest)?;
    let (_, _, after) = tlv(validity)?;
    let (tag, t, _) = tlv(after)?;
    Some(CertFields {
        serial,
        issuer,
        subject,
        not_after: der_time(tag, t),
    })
}

/// The subject common name of a certificate (DER), if it has one.
pub fn common_name(der: &[u8]) -> Option<String> {
    // Name ::= SEQUENCE OF SET OF SEQUENCE { type OID, value }
    let mut rdns = cert_fields(der)?.subject;
    while !rdns.is_empty() {
        let (_, set, rest) = tlv(rdns)?;
        rdns = rest;
        let mut atvs = set;
        while !atvs.is_empty() {
            let (_, atv, rest) = tlv(atvs)?;
            atvs = rest;
            let (otag, oid, value) = tlv(atv)?;
            if otag == 0x06 && oid == [0x55, 0x04, 0x03] {
                let (_, v, _) = tlv(value)?;
                return Some(String::from_utf8_lossy(v).into_owned());
            }
        }
    }
    None
}

/// UTCTime (tag 0x17, YYMMDDHHMMSSZ) or GeneralizedTime (0x18,
/// YYYYMMDDHHMMSSZ) as seconds since 1970.
fn der_time(tag: u8, v: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(v).ok()?.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 if s.len() == 12 => {
            let yy: i64 = s.get(..2)?.parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &s[2..])
        }
        0x18 if s.len() == 14 => (s.get(..4)?.parse().ok()?, &s[4..]),
        _ => return None,
    };
    let n = |i: usize| -> Option<i64> { rest.get(i..i + 2)?.parse().ok() };
    let days = days_from_civil(year, n(0)?, n(2)?);
    Some(days * 86_400 + n(4)? * 3600 + n(6)? * 60 + n(8)?)
}

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The civil date of days since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, u8, u8) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m as u8, d as u8)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The day `days` from today (negative: before), at midnight UTC, as
/// [`rcgen::date_time_ymd`] takes it.
fn ymd(days: i64) -> (i32, u8, u8) {
    let (y, m, d) = civil_from_days(now_secs().div_euclid(86_400) + days);
    (y as i32, m, d)
}

macro_rules! day {
    ($days:expr) => {{
        let (y, m, d) = ymd($days);
        rcgen::date_time_ymd(y, m, d)
    }};
}

/// Seconds since 1970 as `YYYY-MM-DD`.
#[cfg(test)]
pub(crate) fn date_of(secs: i64) -> String {
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// The revoked certificates of a CRL (DER): serial and revocation time.
fn crl_entries(der: &[u8]) -> Option<Vec<(Vec<u8>, i64)>> {
    // CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signature }
    let (_, list, _) = tlv(der)?;
    let (_, mut tbs, _) = tlv(list)?;
    // version (optional), signature, issuer, thisUpdate, nextUpdate (optional),
    // revokedCertificates (optional), [0] extensions
    if tbs.first() == Some(&0x02) {
        tbs = tlv(tbs)?.2;
    }
    for _ in 0..3 {
        tbs = tlv(tbs)?.2;
    }
    if matches!(tbs.first(), Some(0x17 | 0x18)) {
        tbs = tlv(tbs)?.2;
    }
    let mut out = Vec::new();
    if tbs.first() == Some(&0x30) {
        let (_, mut entries, _) = tlv(tbs)?;
        while !entries.is_empty() {
            let (_, entry, rest) = tlv(entries)?;
            entries = rest;
            let (_, serial, rest) = tlv(entry)?;
            let (tag, t, _) = tlv(rest)?;
            out.push((serial.to_vec(), der_time(tag, t)?));
        }
    }
    Some(out)
}

/// One DER tag-length-value: (tag, value, what follows).
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let first = *b.get(1)?;
    let (len, head) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = head.checked_add(len)?;
    Some((tag, b.get(head..end)?, b.get(end..)?))
}

/// A small certificate authority for a lab: one CA for the server and the
/// operator clients, one for read-only clients, kept as PEM files in a
/// directory. `ferotrx certs` uses it.
///
/// | File | What |
/// | --- | --- |
/// | `ca.pem`, `ca-key.pem` | signs the server certificate and operator client certificates |
/// | `read-ca.pem`, `read-ca-key.pem` | signs read-only client certificates |
/// | `server.pem`, `server-key.pem` | the server's certificate |
/// | `NAME.pem`, `NAME-key.pem` | a client certificate, common name NAME |
/// | `crl.pem`, `read-crl.pem` | certificates each CA revoked ([`revoke`](LabPki::revoke)), empty at first |
///
/// Certificates are valid for a year unless [`with_days`](LabPki::with_days)
/// says otherwise; the CAs for ten years.
///
/// The server takes `server.pem`, `server-key.pem`, `ca.pem` as operator
/// client CA and `read-ca.pem` as read-only client CA; clients take
/// `ca.pem` to check the server and their own certificate and key.
pub struct LabPki {
    dir: PathBuf,
    /// Validity of the certificates issued, in days from today.
    from: i64,
    to: i64,
}

/// How long [`LabPki`] certificates are valid unless set otherwise.
pub const LAB_CERT_DAYS: u32 = 365;
/// How long [`LabPki`]'s certificate authorities are valid.
pub const LAB_CA_DAYS: u32 = 3650;

/// What [`LabPki`] wrote.
#[derive(Debug, Default)]
pub struct Issued {
    pub files: Vec<PathBuf>,
}

impl LabPki {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            from: -1,
            to: i64::from(LAB_CERT_DAYS),
        }
    }

    /// Certificates issued from now on are valid for `days` days.
    pub fn with_days(mut self, days: u32) -> Self {
        self.to = i64::from(days.max(1));
        self
    }

    /// Certificates valid from `from` to `to` days from today, for tests
    /// of expired ones.
    #[cfg(test)]
    fn with_window(mut self, from: i64, to: i64) -> Self {
        (self.from, self.to) = (from, to);
        self
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path(&self, file: &str) -> PathBuf {
        self.dir.join(file)
    }

    /// Issues the server's certificate for `hosts` (names or addresses the
    /// clients connect to; the first is the common name) and for `localhost`,
    /// `127.0.0.1` and `::1`, replacing any old one.
    pub fn issue_server(&self, hosts: &[String]) -> Result<Issued, TlsError> {
        if hosts.is_empty() {
            return Err(TlsError::new(
                "the server certificate needs at least one host name or address",
            ));
        }
        let mut names = hosts.to_vec();
        for local in ["localhost", "127.0.0.1", "::1"] {
            if !names.iter().any(|n| n == local) {
                names.push(local.to_string());
            }
        }
        let mut out = Issued::default();
        let mut p = rcgen::CertificateParams::new(names).map_err(TlsError::new)?;
        p.distinguished_name
            .push(rcgen::DnType::CommonName, hosts[0].clone());
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        self.issue(Role::Operator, p, "server", &mut out)?;
        Ok(out)
    }

    /// Issues a client certificate with common name `name` for `role`.
    pub fn issue_client(&self, name: &str, role: Role) -> Result<Issued, TlsError> {
        let ok = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c))
            && !name.starts_with('.');
        if !ok || ["ca", "read-ca", "server", "crl", "read-crl"].contains(&name) {
            return Err(TlsError(format!(
                "'{name}' cannot be a client name (letters, digits, - _ . @; not ca, read-ca, server, crl or read-crl)"
            )));
        }
        let mut out = Issued::default();
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(TlsError::new)?;
        p.distinguished_name
            .push(rcgen::DnType::CommonName, name.to_string());
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        self.issue(role, p, name, &mut out)?;
        Ok(out)
    }

    fn issue(
        &self,
        role: Role,
        mut params: rcgen::CertificateParams,
        file: &str,
        out: &mut Issued,
    ) -> Result<(), TlsError> {
        let ca_key = self.ca(role, out)?;
        // An empty revocation list from the start, so a server can be
        // given `--crl` before anything is revoked.
        if !self.path(crl_file(role)).exists() {
            self.write_crl(role, &[], out)?;
        }
        let ca_key = rcgen::KeyPair::from_pem(&ca_key).map_err(TlsError::new)?;
        // The CA's own parameters again: same subject, same key, so the
        // issuer name and key identifier match its certificate.
        let issuer = rcgen::Issuer::new(ca_params(role)?, ca_key);
        // From yesterday, for clocks a little behind.
        params.not_before = day!(self.from);
        params.not_after = day!(self.to);
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        let key = rcgen::KeyPair::generate().map_err(TlsError::new)?;
        let cert = params.signed_by(&key, &issuer).map_err(TlsError::new)?;
        self.write(&format!("{file}.pem"), &cert.pem(), false, out)?;
        self.write(&format!("{file}-key.pem"), &key.serialize_pem(), true, out)?;
        Ok(())
    }

    /// The key of the CA for `role` (PEM), the CA made if it is not there yet.
    fn ca(&self, role: Role, out: &mut Issued) -> Result<String, TlsError> {
        let stem = ca_stem(role);
        let cert_path = self.path(&format!("{stem}.pem"));
        let key_path = self.path(&format!("{stem}-key.pem"));
        if cert_path.exists() {
            return std::fs::read_to_string(&key_path)
                .map_err(|e| TlsError(format!("{}: {e}", key_path.display())));
        }
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| TlsError(format!("{}: {e}", self.dir.display())))?;
        let key = rcgen::KeyPair::generate().map_err(TlsError::new)?;
        let cert = ca_params(role)?.self_signed(&key).map_err(TlsError::new)?;
        let key = key.serialize_pem();
        self.write(&format!("{stem}.pem"), &cert.pem(), false, out)?;
        self.write(&format!("{stem}-key.pem"), &key, true, out)?;
        Ok(key)
    }

    /// Revokes the certificate `NAME.pem`: adds it to the revocation list
    /// of the CA that issued it (`crl.pem` or `read-crl.pem`), which a
    /// server given that list with `--crl` (and reloaded) then refuses.
    /// Revoke before issuing a new certificate under the same name, which
    /// replaces `NAME.pem`.
    pub fn revoke(&self, name: &str) -> Result<Issued, TlsError> {
        let path = self.path(&format!("{name}.pem"));
        let pem = read(&path)?;
        let der = certs(&pem, name)?.remove(0);
        let f = cert_fields(&der)
            .ok_or_else(|| TlsError(format!("{}: cannot read the certificate", path.display())))?;
        let mut role = None;
        for r in [Role::Operator, Role::Read] {
            let ca = self.path(&format!("{}.pem", ca_stem(r)));
            if let Ok(pem) = read(&ca) {
                let ca = certs(&pem, "CA")?.remove(0);
                if cert_fields(&ca).is_some_and(|c| c.subject == f.issuer) {
                    role = Some(r);
                    break;
                }
            }
        }
        let role = role.ok_or_else(|| {
            TlsError(format!(
                "{}: not issued by this directory's CAs",
                path.display()
            ))
        })?;
        let crl_path = self.path(crl_file(role));
        let mut entries = match std::fs::read(&crl_path) {
            Ok(pem) => {
                let der = CertificateRevocationListDer::pem_slice_iter(&pem)
                    .next()
                    .ok_or_else(|| TlsError(format!("{}: no CRL in it", crl_path.display())))?
                    .map_err(|e| TlsError(format!("{}: {e}", crl_path.display())))?;
                crl_entries(&der)
                    .ok_or_else(|| TlsError(format!("{}: cannot read it", crl_path.display())))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(TlsError(format!("{}: {e}", crl_path.display()))),
        };
        let serial = f.serial.to_vec();
        if !entries.iter().any(|(s, _)| *s == serial) {
            entries.push((serial, now_secs()));
        }
        let mut out = Issued::default();
        self.write_crl(role, &entries, &mut out)?;
        Ok(out)
    }

    /// Writes the revocation list of the CA for `role`, signed by it.
    fn write_crl(
        &self,
        role: Role,
        entries: &[(Vec<u8>, i64)],
        out: &mut Issued,
    ) -> Result<(), TlsError> {
        let revoked = entries
            .iter()
            .map(|(serial, when)| {
                let (y, m, d) = civil_from_days(when.div_euclid(86_400));
                rcgen::RevokedCertParams {
                    serial_number: rcgen::SerialNumber::from_slice(strip_zeros(serial)),
                    revocation_time: rcgen::date_time_ymd(y as i32, m, d),
                    reason_code: None,
                    invalidity_date: None,
                }
            })
            .collect();
        let params = rcgen::CertificateRevocationListParams {
            this_update: day!(-1),
            next_update: day!(i64::from(LAB_CERT_DAYS)),
            crl_number: rcgen::SerialNumber::from(now_secs() as u64),
            issuing_distribution_point: None,
            revoked_certs: revoked,
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        let ca_key = self.ca(role, out)?;
        let ca_key = rcgen::KeyPair::from_pem(&ca_key).map_err(TlsError::new)?;
        let issuer = rcgen::Issuer::new(ca_params(role)?, ca_key);
        let crl = params.signed_by(&issuer).map_err(TlsError::new)?;
        let text = crl.pem().map_err(TlsError::new)?;
        self.write(crl_file(role), &text, false, out)
    }

    fn write(
        &self,
        file: &str,
        text: &str,
        secret: bool,
        out: &mut Issued,
    ) -> Result<(), TlsError> {
        let path = self.path(file);
        let fail = |e: std::io::Error| TlsError(format!("cannot write {}: {e}", path.display()));
        let _ = std::fs::remove_file(&path);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        if secret {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        #[cfg(not(unix))]
        let _ = secret;
        use std::io::Write;
        opts.open(&path)
            .and_then(|mut f| f.write_all(text.as_bytes()))
            .map_err(fail)?;
        out.files.push(path);
        Ok(())
    }
}

/// The revocation list of the CA for `role`.
pub fn crl_file(role: Role) -> &'static str {
    match role {
        Role::Operator => "crl.pem",
        Role::Read => "read-crl.pem",
    }
}

/// An integer's bytes without the leading zero DER adds to keep it positive.
fn strip_zeros(b: &[u8]) -> &[u8] {
    let n = b.iter().take_while(|x| **x == 0).count();
    &b[n.min(b.len().saturating_sub(1))..]
}

fn ca_stem(role: Role) -> &'static str {
    match role {
        Role::Operator => "ca",
        Role::Read => "read-ca",
    }
}

fn ca_params(role: Role) -> Result<rcgen::CertificateParams, TlsError> {
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(TlsError::new)?;
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    p.distinguished_name.push(
        rcgen::DnType::CommonName,
        match role {
            Role::Operator => "FeroTRX lab CA",
            Role::Read => "FeroTRX lab read-only CA",
        },
    );
    p.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    p.not_before = day!(-1);
    p.not_after = day!(i64::from(LAB_CA_DAYS));
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_certificates_with_their_names() {
        let dir = std::env::temp_dir().join(format!("ferotrx-pki-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let pki = LabPki::new(&dir);
        let first = pki
            .issue_server(&["lab1".into(), "127.0.0.1".into()])
            .unwrap();
        assert_eq!(first.files.len(), 5); // ca, ca-key, crl, server, server-key
        let again = pki.issue_client("alice", Role::Operator).unwrap();
        assert_eq!(again.files.len(), 2); // the CA is reused
        pki.issue_client("dash", Role::Read).unwrap();
        assert!(pki.issue_client("../x", Role::Read).is_err());
        assert!(pki.issue_client("server", Role::Read).is_err());

        let pem = std::fs::read(pki.path("alice.pem")).unwrap();
        let der = certs(&pem, "alice").unwrap();
        assert_eq!(common_name(&der[0]).as_deref(), Some("alice"));
        let pem = std::fs::read(pki.path("server.pem")).unwrap();
        assert_eq!(
            common_name(&certs(&pem, "server").unwrap()[0]).as_deref(),
            Some("lab1")
        );
        assert_eq!(fingerprint(b"").len(), 64);

        let tls = ServerTls::from_files(&pki.path("server.pem"), &pki.path("server-key.pem"))
            .unwrap()
            .with_client_ca_file(Role::Operator, &pki.path("ca.pem"))
            .unwrap()
            .with_client_ca_file(Role::Read, &pki.path("read-ca.pem"))
            .unwrap();
        let setup = tls.build(false).unwrap();
        let chain =
            |n: &str| certs(&std::fs::read(pki.path(&format!("{n}.pem"))).unwrap(), n).unwrap();
        assert_eq!(setup.role_of(&chain("alice")), Some(Role::Operator));
        assert_eq!(setup.role_of(&chain("dash")), Some(Role::Read));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(pki.path("alice-key.pem"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_revoked_and_refused_certificates_give_no_role() {
        let dir = std::env::temp_dir().join(format!("ferotrx-pki-rev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let pki = LabPki::new(&dir);
        pki.issue_server(&["127.0.0.1".into()]).unwrap();
        pki.issue_client("alice", Role::Operator).unwrap();
        pki.issue_client("bob", Role::Operator).unwrap();
        LabPki::new(&dir)
            .with_window(-30, -2)
            .issue_client("old", Role::Operator)
            .unwrap();
        let chain =
            |n: &str| certs(&std::fs::read(pki.path(&format!("{n}.pem"))).unwrap(), n).unwrap();
        let tls = || {
            ServerTls::from_files(&pki.path("server.pem"), &pki.path("server-key.pem"))
                .unwrap()
                .with_client_ca_file(Role::Operator, &pki.path("ca.pem"))
                .unwrap()
        };
        let setup = tls().build(false).unwrap();
        assert_eq!(setup.role_of(&chain("alice")), Some(Role::Operator));
        assert_eq!(setup.role_of(&chain("old")), None, "an expired certificate");
        let days = (setup.expires.unwrap() - now_secs()) / 86_400;
        assert!((364..=365).contains(&days), "{days} days");
        assert!(date_of(setup.expires.unwrap()).len() == 10);

        pki.revoke("alice").unwrap();
        pki.revoke("alice").unwrap(); // twice is once
        let setup = tls()
            .with_crl_file(&pki.path("crl.pem"))
            .unwrap()
            .deny(&fingerprint(&chain("bob")[0]).to_uppercase())
            .unwrap()
            .build(true)
            .unwrap();
        assert_eq!(
            setup.role_of(&chain("alice")),
            None,
            "a revoked certificate"
        );
        assert_eq!(setup.role_of(&chain("bob")), Some(Role::Operator));
        assert!(setup.is_denied(&fingerprint(&chain("bob")[0])));
        let der = CertificateRevocationListDer::pem_slice_iter(
            &std::fs::read(pki.path("crl.pem")).unwrap(),
        )
        .next()
        .unwrap()
        .unwrap();
        assert_eq!(crl_entries(&der).unwrap().len(), 1);
        assert!(pki.revoke("nobody").is_err());
        assert!(
            ServerTls::from_files(&pki.path("server.pem"), &pki.path("server-key.pem"))
                .unwrap()
                .deny("abc")
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn der_times_and_dates() {
        assert_eq!(der_time(0x17, b"700101000000Z"), Some(0));
        assert_eq!(der_time(0x18, b"20261108000000Z"), Some(1_794_096_000));
        assert_eq!(der_time(0x17, b"491231235959Z"), Some(2_524_607_999));
        assert_eq!(date_of(1_794_096_000), "2026-11-08");
        assert_eq!(der_time(0x17, b"7001010000Z"), None);
    }
}
