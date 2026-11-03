//! TLS for the control server and client (rustls), client certificates,
//! and a small certificate authority for labs ([`LabPki`]).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::WebPkiClientVerifier;
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
}

impl std::fmt::Debug for ServerTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerTls")
            .field("certificates", &self.chain.len())
            .field(
                "client_cas",
                &self.client_cas.iter().map(|(r, _)| *r).collect::<Vec<_>>(),
            )
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
                let v =
                    WebPkiClientVerifier::builder_with_provider(Arc::new(store), provider.clone())
                        .build()
                        .map_err(TlsError::new)?;
                verifiers.push((*role, v));
            }
            let mut b = WebPkiClientVerifier::builder_with_provider(Arc::new(all), provider);
            if cert_optional {
                b = b.allow_unauthenticated();
            }
            builder.with_client_cert_verifier(b.build().map_err(TlsError::new)?)
        };
        let mut config = config
            .with_single_cert(self.chain.clone(), self.key.clone_key())
            .map_err(|e| TlsError(format!("server certificate and key: {e}")))?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        Ok(TlsSetup {
            config: Arc::new(config),
            verifiers,
        })
    }
}

/// ALPN protocol name: the control protocol, one JSON-RPC object per line.
const ALPN: &[u8] = b"ferotrx-ctl";

pub(crate) struct TlsSetup {
    pub config: Arc<rustls::ServerConfig>,
    verifiers: Vec<(Role, Arc<dyn ClientCertVerifier>)>,
}

impl TlsSetup {
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

/// The subject common name of a certificate (DER), if it has one.
pub fn common_name(der: &[u8]) -> Option<String> {
    // Certificate ::= SEQUENCE { tbsCertificate, ... }
    let (_, cert, _) = tlv(der)?;
    let (_, mut tbs, _) = tlv(cert)?;
    // tbsCertificate: [0] version (optional), serial, signature, issuer, validity, subject
    let (tag, _, rest) = tlv(tbs)?;
    if tag == 0xa0 {
        tbs = rest;
    }
    // Skip serial, signature, issuer and validity.
    for _ in 0..4 {
        tbs = tlv(tbs)?.2;
    }
    let (_, subject, _) = tlv(tbs)?;
    // Name ::= SEQUENCE OF SET OF SEQUENCE { type OID, value }
    let mut rdns = subject;
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
///
/// The server takes `server.pem`, `server-key.pem`, `ca.pem` as operator
/// client CA and `read-ca.pem` as read-only client CA; clients take
/// `ca.pem` to check the server and their own certificate and key.
pub struct LabPki {
    dir: PathBuf,
}

/// What [`LabPki`] wrote.
#[derive(Debug, Default)]
pub struct Issued {
    pub files: Vec<PathBuf>,
}

impl LabPki {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
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
        if !ok || ["ca", "read-ca", "server"].contains(&name) {
            return Err(TlsError(format!(
                "'{name}' cannot be a client name (letters, digits, - _ . @; not ca, read-ca or server)"
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
        let ca_key = rcgen::KeyPair::from_pem(&ca_key).map_err(TlsError::new)?;
        // The CA's own parameters again: same subject, same key, so the
        // issuer name and key identifier match its certificate.
        let issuer = rcgen::Issuer::new(ca_params(role)?, ca_key);
        params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);
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
    p.not_before = rcgen::date_time_ymd(2025, 1, 1);
    p.not_after = rcgen::date_time_ymd(2035, 1, 1);
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
        assert_eq!(first.files.len(), 4); // ca, ca-key, server, server-key
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
}
