use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::audit::AuditLog;
use crate::auth::Token;
use crate::controller::{parse, to_value};
use crate::ports::{Who, ANONYMOUS};
use crate::protocol::*;
use crate::tls::{common_name, fingerprint, ServerTls, TlsSetup};
use crate::Controller;

/// Longest request line the server accepts unless set otherwise (a profile
/// sent as TOML text included).
pub const MAX_LINE: usize = 4 * 1024 * 1024;

const DEFAULT_INTERVAL: Duration = Duration::from_millis(1000);
const MIN_INTERVAL: Duration = Duration::from_millis(50);
/// How often a waiting connection wakes up to check its timeouts.
const TICK: Duration = Duration::from_millis(500);
/// A client that does not read its answers for this long is dropped.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Wrong tokens a connection may send before it is closed.
const MAX_AUTH_FAILURES: u32 = 5;
/// Pause after a wrong token, against guessing.
#[cfg(not(feature = "fuzzing"))]
const AUTH_FAILURE_DELAY: Duration = Duration::from_millis(500);
/// Fuzz builds try thousands of logins a second.
#[cfg(feature = "fuzzing")]
const AUTH_FAILURE_DELAY: Duration = Duration::ZERO;
/// The window wrong tokens are counted in, per address and in total.
const FAILURE_WINDOW: Duration = Duration::from_secs(60);

/// How the control server lets clients in, and its limits.
///
/// With no tokens and no client certificate authorities, every connection
/// may do everything; the server then refuses to listen on anything but a
/// loopback address unless `insecure` is set. Beyond loopback it also
/// refuses tokens without TLS (they would travel in clear text) unless
/// `allow_cleartext_tokens` is set, and a controller with
/// [`FilePolicy::unrestricted`](crate::FilePolicy::unrestricted) unless
/// `unrestricted_files` is set.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Tokens clients log in with (`auth`), each with its role.
    pub tokens: Vec<Token>,
    /// TLS: the server's certificate, and client certificate authorities.
    pub tls: Option<ServerTls>,
    /// Listen on a non-loopback address without any login.
    pub insecure: bool,
    /// Accept tokens without TLS on a non-loopback address. Anyone who can
    /// watch the network can then copy a token and log in with it; only for
    /// an isolated lab network.
    pub allow_cleartext_tokens: bool,
    /// Listen on a non-loopback address although the controller lets
    /// clients name any file the process can open.
    pub unrestricted_files: bool,
    /// `stats` subscriptions one connection may run at once.
    pub max_subscriptions: usize,
    /// `stats` subscriptions all connections together may run at once.
    pub max_total_subscriptions: usize,
    /// Connections that have not logged in yet, at once (when login is
    /// required). They count towards `max_connections` too; this keeps
    /// clients without a token from taking every slot.
    pub max_unauthenticated: usize,
    /// Wrong tokens one address may send in a minute, over all its
    /// connections; after that its logins are refused unchecked until the
    /// minute has passed.
    pub max_login_failures_per_ip: u32,
    /// Wrong tokens all addresses together may send in a minute.
    pub max_login_failures: u32,
    /// Refuse operator calls while the audit log cannot be written.
    pub audit_required: bool,
    /// Connections open at once; more are turned away.
    pub max_connections: usize,
    /// Longest request line, in bytes.
    pub max_request: usize,
    /// A connection that sends no request for this long, and has no
    /// `stats` subscription running, is closed.
    pub idle_timeout: Option<Duration>,
    /// When login is required, a connection that has not logged in after
    /// this long is closed.
    pub login_timeout: Duration,
    /// Where logins, refusals and changes are recorded.
    pub audit: Option<AuditLog>,
    /// Reads tokens, certificates, revocation lists and refused
    /// fingerprints again for `server.reload` (and `ferotrx serve`'s
    /// SIGHUP); without it the server cannot reload.
    pub reload: Option<Reloader>,
}

/// What logs in to a server, as a [`Reloader`] reads it again.
#[derive(Clone, Debug, Default)]
pub struct Credentials {
    pub tokens: Vec<Token>,
    pub tls: Option<ServerTls>,
}

/// Reads a server's [`Credentials`] again (from the files it was started
/// with): `server.reload` and [`ReloadHandle::reload`] call it.
#[derive(Clone)]
pub struct Reloader(Arc<dyn Fn() -> Result<Credentials, String> + Send + Sync>);

impl Reloader {
    pub fn new(f: impl Fn() -> Result<Credentials, String> + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }
}

impl std::fmt::Debug for Reloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Reloader")
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            tokens: Vec::new(),
            tls: None,
            insecure: false,
            allow_cleartext_tokens: false,
            unrestricted_files: false,
            max_subscriptions: 16,
            max_total_subscriptions: 256,
            max_unauthenticated: 16,
            max_login_failures_per_ip: 20,
            max_login_failures: 200,
            audit_required: false,
            max_connections: 64,
            max_request: MAX_LINE,
            idle_timeout: Some(Duration::from_secs(300)),
            login_timeout: Duration::from_secs(10),
            audit: None,
            reload: None,
        }
    }
}

impl ServerConfig {
    /// True when connections must log in.
    pub fn login_required(&self) -> bool {
        !self.tokens.is_empty() || self.tls.as_ref().is_some_and(ServerTls::verifies_clients)
    }
}

/// The control server: JSON-RPC 2.0 over TCP (or TLS), one JSON object per line.
///
/// Each connection gets its own thread, so a client waiting on `run.stop` or
/// reading `stats` notifications does not hold up the others.
pub struct Server {
    listener: TcpListener,
    controller: Arc<Controller>,
    shared: Arc<Shared>,
}

/// The logins in force; [`Shared::reload`] replaces them.
struct Creds {
    tokens: Vec<Token>,
    tls: Option<TlsSetup>,
}

struct Shared {
    creds: RwLock<Arc<Creds>>,
    /// Counts reloads, so connections see that they must check their
    /// logins again.
    generation: AtomicU64,
    reload: Option<Reloader>,
    tls_on: bool,
    login_required: bool,
    max_connections: usize,
    max_request: usize,
    idle_timeout: Option<Duration>,
    login_timeout: Duration,
    audit: Option<AuditLog>,
    audit_required: bool,
    max_subscriptions: usize,
    max_total_subscriptions: usize,
    max_unauthenticated: usize,
    max_login_failures_per_ip: u32,
    max_login_failures: u32,
    open: AtomicUsize,
    /// Connections that have not logged in yet.
    unauthenticated: AtomicUsize,
    /// `stats` subscriptions running.
    subscriptions: AtomicUsize,
    /// Wrong tokens of the last minute, oldest first, by address.
    failures: Mutex<VecDeque<(Instant, Option<IpAddr>)>>,
    next_conn: AtomicU64,
}

impl Shared {
    fn creds(&self) -> Arc<Creds> {
        self.creds
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Reads the logins again; connections whose certificate or token is
    /// no longer accepted are closed when they next wake (within a second).
    fn reload(&self, by: Map<String, Value>) -> Result<ReloadInfo, String> {
        let outcome = self.try_reload();
        let mut m = by;
        match &outcome {
            Ok(r) => {
                m.insert("ok".into(), true.into());
                m.insert("tokens".into(), r.tokens.into());
                m.insert("crls".into(), r.crls.into());
                m.insert("denied_certs".into(), r.denied_certs.into());
            }
            Err(e) => {
                m.insert("ok".into(), false.into());
                m.insert("error".into(), e.clone().into());
            }
        }
        self.audit("reload", Value::Object(m));
        outcome
    }

    fn try_reload(&self) -> Result<ReloadInfo, String> {
        let reload = self
            .reload
            .as_ref()
            .ok_or("this server was not started from files it can read again")?;
        let c = (reload.0)()?;
        if c.tls.is_some() != self.tls_on {
            return Err(if self.tls_on {
                "the reloaded settings have no TLS; restart the server to turn it off".into()
            } else {
                "the reloaded settings have TLS; restart the server to turn it on".into()
            });
        }
        let login = !c.tokens.is_empty() || c.tls.as_ref().is_some_and(ServerTls::verifies_clients);
        if login != self.login_required {
            return Err(if login {
                "the reloaded settings need logins and this server started without; restart it"
                    .into()
            } else {
                "the reloaded settings have no token and no client CA: nobody could log in".into()
            });
        }
        let info = ReloadInfo {
            tokens: c.tokens.len(),
            crls: c.tls.as_ref().map_or(0, ServerTls::crl_count),
            denied_certs: c.tls.as_ref().map_or(0, ServerTls::denied_count),
            certificate_expires: c.tls.as_ref().and_then(ServerTls::expires).map(expiry),
        };
        let tls = c
            .tls
            .as_ref()
            .map(|t| t.build(!c.tokens.is_empty()))
            .transpose()
            .map_err(|e| e.to_string())?;
        *self
            .creds
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(Creds {
            tokens: c.tokens,
            tls,
        });
        self.generation.fetch_add(1, Ordering::SeqCst);
        Ok(info)
    }

    fn audit(&self, event: &str, fields: Value) {
        if let (Some(log), Value::Object(m)) = (&self.audit, fields) {
            log.record(event, m);
        }
    }

    /// Why a token login from `ip` must be refused unchecked now, if it must.
    fn throttled(&self, ip: Option<IpAddr>) -> Option<&'static str> {
        let mut f = lock(&self.failures);
        let now = Instant::now();
        while f
            .front()
            .is_some_and(|(t, _)| now.duration_since(*t) >= FAILURE_WINDOW)
        {
            f.pop_front();
        }
        if f.len() >= self.max_login_failures as usize {
            return Some("too many failed logins on this server; try again in a minute");
        }
        let from_here = f.iter().filter(|(_, a)| *a == ip).count();
        (from_here >= self.max_login_failures_per_ip as usize)
            .then_some("too many failed logins from this address; try again in a minute")
    }

    fn login_failed(&self, ip: Option<IpAddr>) {
        lock(&self.failures).push_back((Instant::now(), ip));
    }

    /// Refuses a connection before it starts: the reason goes to the audit
    /// log and, without TLS, to the client.
    fn refuse(&self, stream: &TcpStream, peer: &str, reason: &str) {
        self.audit("refused", json!({"peer": peer, "reason": reason}));
        if !self.tls_on {
            let err = RpcError::new(RpcError::FAILED, reason);
            let mut s = stream;
            let _ = s.set_write_timeout(Some(Duration::from_secs(1)));
            if let Ok(mut line) = serde_json::to_vec(&Response::new(Value::Null, Err(err))) {
                line.push(b'\n');
                let _ = s.write_all(&line);
            }
        }
    }
}

impl Server {
    /// Listens on `addr`. With a `token`, every connection must send `auth`
    /// with it before anything but `server.info`, and may then do everything;
    /// without TLS that works on loopback addresses only.
    /// See [`with_config`](Server::with_config) for roles, TLS and limits.
    pub fn bind(
        addr: impl ToSocketAddrs,
        controller: Controller,
        token: Option<String>,
    ) -> io::Result<Server> {
        let config = ServerConfig {
            tokens: token
                .into_iter()
                .map(|t| Token::new("token", Role::Operator, t))
                .collect(),
            ..Default::default()
        };
        Self::with_config(addr, controller, config)
    }

    /// Listens on `addr` with logins, TLS and limits from `config`.
    ///
    /// Fails with [`io::ErrorKind::PermissionDenied`] for a non-loopback
    /// address when `config` has no way to log in and is not `insecure`,
    /// when it has tokens but no TLS and not `allow_cleartext_tokens`, or
    /// when the controller's file policy is unrestricted and `config` is not
    /// `unrestricted_files`.
    pub fn with_config(
        addr: impl ToSocketAddrs,
        mut controller: Controller,
        config: ServerConfig,
    ) -> io::Result<Server> {
        let login_required = config.login_required();
        let listener = TcpListener::bind(addr)?;
        let local = listener.local_addr()?;
        let remote = !local.ip().is_loopback();
        let refuse = |why: String| Err(io::Error::new(io::ErrorKind::PermissionDenied, why));
        if remote && !login_required && !config.insecure {
            return refuse(format!(
                "refusing to listen on {local} without a token or client certificates: \
                 anyone who reaches it could send traffic from this machine \
                 (`ferotrx serve --insecure`, or ServerConfig::insecure, does it anyway)"
            ));
        }
        let cleartext = remote && !config.tokens.is_empty() && config.tls.is_none();
        if cleartext && !config.allow_cleartext_tokens {
            return refuse(format!(
                "refusing tokens without TLS on {local}: anyone who can watch the network \
                 could copy a token and log in with it. Give --tls-cert and --tls-key \
                 (`ferotrx certs` makes them), listen on 127.0.0.1, or, on an isolated lab \
                 network, --allow-cleartext-token (ServerConfig::allow_cleartext_tokens)"
            ));
        }
        if remote && controller.file_policy().is_unrestricted() && !config.unrestricted_files {
            return refuse(format!(
                "refusing to listen on {local} with an unrestricted file policy: clients \
                 could read and write any file this process can. Give the controller \
                 FilePolicy::dirs, or set ServerConfig::unrestricted_files"
            ));
        }
        if config.audit_required && config.audit.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit_required needs an audit log",
            ));
        }
        let tls = config
            .tls
            .as_ref()
            .map(|t| t.build(!config.tokens.is_empty()))
            .transpose()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        controller.set_auth_required(login_required);
        controller.set_audit(config.audit.clone());
        // Captures on this server leave its own control traffic out.
        controller.set_ctl_port(local.port());
        let tls_on = tls.is_some();
        let shared = Arc::new(Shared {
            creds: RwLock::new(Arc::new(Creds {
                tokens: config.tokens,
                tls,
            })),
            generation: AtomicU64::new(0),
            reload: config.reload,
            tls_on,
            login_required,
            max_connections: config.max_connections.max(1),
            max_request: config.max_request.max(1024),
            idle_timeout: config.idle_timeout,
            login_timeout: config.login_timeout,
            audit: config.audit,
            audit_required: config.audit_required,
            max_subscriptions: config.max_subscriptions,
            max_total_subscriptions: config.max_total_subscriptions,
            max_unauthenticated: config.max_unauthenticated.max(1),
            max_login_failures_per_ip: config.max_login_failures_per_ip.max(1),
            max_login_failures: config.max_login_failures.max(1),
            open: AtomicUsize::new(0),
            unauthenticated: AtomicUsize::new(0),
            subscriptions: AtomicUsize::new(0),
            failures: Mutex::default(),
            next_conn: AtomicU64::new(1),
        });
        if cleartext {
            shared.audit("cleartext_tokens", json!({"listen": local.to_string()}));
        }
        Ok(Server {
            listener,
            controller: Arc::new(controller),
            shared,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn controller(&self) -> &Arc<Controller> {
        &self.controller
    }

    /// True when connections are encrypted.
    pub fn tls(&self) -> bool {
        self.shared.tls_on
    }

    /// Reads tokens, certificates, revocation lists and refused
    /// fingerprints again (see [`ServerConfig::reload`]).
    pub fn reload(&self) -> Result<ReloadInfo, String> {
        self.reload_handle().reload()
    }

    /// Something that reloads this server from another thread while
    /// [`serve`](Server::serve) runs, e.g. on a signal.
    pub fn reload_handle(&self) -> ReloadHandle {
        ReloadHandle(self.shared.clone())
    }

    /// Accepts connections for ever.
    pub fn serve(&self) -> io::Result<()> {
        for conn in self.listener.incoming() {
            let stream = match conn {
                Ok(s) => s,
                // A client that went away before we accepted it, or a full fd table:
                // keep serving the others.
                Err(_) => continue,
            };
            let peer = stream
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_default();
            let shared = self.shared.clone();
            if shared.open.fetch_add(1, Ordering::SeqCst) >= shared.max_connections {
                shared.open.fetch_sub(1, Ordering::SeqCst);
                shared.refuse(&stream, &peer, "too many connections");
                continue;
            }
            let pending = shared.login_required;
            if pending
                && shared.unauthenticated.fetch_add(1, Ordering::SeqCst)
                    >= shared.max_unauthenticated
            {
                shared.unauthenticated.fetch_sub(1, Ordering::SeqCst);
                shared.open.fetch_sub(1, Ordering::SeqCst);
                shared.refuse(&stream, &peer, "too many connections waiting to log in");
                continue;
            }
            let controller = self.controller.clone();
            let spawned = std::thread::Builder::new()
                .name("ferotrx-ctl-conn".into())
                .spawn(move || {
                    let _guard = OpenGuard(shared.clone());
                    match Connection::new(stream, peer, controller, shared.clone()) {
                        Ok(c) => c.run(),
                        Err(_) if pending => {
                            shared.unauthenticated.fetch_sub(1, Ordering::SeqCst);
                        }
                        Err(_) => {}
                    }
                });
            if spawned.is_err() {
                self.shared.open.fetch_sub(1, Ordering::SeqCst);
                if pending {
                    self.shared.unauthenticated.fetch_sub(1, Ordering::SeqCst);
                }
            }
        }
        Ok(())
    }

    /// Runs [`serve`](Server::serve) on a new thread, e.g. inside a program or test.
    pub fn spawn(self) -> io::Result<SocketAddr> {
        let addr = self.local_addr()?;
        std::thread::Builder::new()
            .name("ferotrx-ctl-accept".into())
            .spawn(move || self.serve())?;
        Ok(addr)
    }
}

/// Reloads a running [`Server`]'s logins ([`Server::reload_handle`]).
#[derive(Clone)]
pub struct ReloadHandle(Arc<Shared>);

impl ReloadHandle {
    /// As `server.reload`; the audit log records it as by `signal`.
    pub fn reload(&self) -> Result<ReloadInfo, String> {
        let mut by = Map::new();
        by.insert("by".into(), "signal".into());
        self.0.reload(by)
    }
}

/// An expiry time as `server.info` and `server.reload` give it.
fn expiry(secs: i64) -> String {
    crate::audit::rfc3339(secs, 0)
}

struct OpenGuard(Arc<Shared>);

impl Drop for OpenGuard {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::SeqCst);
    }
}

// ----- the wire: plain TCP or TLS, written from several threads -----

/// The sending side of a connection, shared by the connection's thread and
/// its `stats` publishers. For TLS the rustls state sits behind the same
/// lock, and the reader takes it only for a moment, never while it waits
/// for the network.
enum Wire {
    Plain(Mutex<TcpStream>),
    Tls(Box<Mutex<TlsWire>>),
}

struct TlsWire {
    conn: rustls::ServerConnection,
    sock: TcpStream,
}

impl TlsWire {
    fn flush(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            self.conn.write_tls(&mut self.sock)?;
        }
        self.sock.flush()
    }
}

type Writer = Arc<Wire>;

impl Wire {
    fn send(&self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Wire::Plain(s) => {
                let mut s = lock(s);
                s.write_all(bytes)?;
                s.flush()
            }
            Wire::Tls(t) => {
                let mut t = lock(t);
                // rustls buffers at most 64 KiB of plaintext before it is
                // written out, so a large reply (file.get, capture.read)
                // goes in pieces.
                let mut rest = bytes;
                while !rest.is_empty() {
                    let n = t.conn.writer().write(rest)?;
                    if n == 0 {
                        t.flush()?;
                        continue;
                    }
                    rest = &rest[n..];
                }
                t.flush()
            }
        }
    }

    fn close(&self) {
        match self {
            Wire::Plain(s) => {
                let _ = lock(s).shutdown(Shutdown::Both);
            }
            Wire::Tls(t) => {
                let mut t = lock(t);
                t.conn.send_close_notify();
                let _ = t.flush();
                let _ = t.sock.shutdown(Shutdown::Both);
            }
        }
    }

    /// The client's certificate chain, once the TLS handshake is done.
    fn peer_certificates(&self) -> Option<Vec<rustls::pki_types::CertificateDer<'static>>> {
        match self {
            Wire::Plain(_) => None,
            Wire::Tls(t) => {
                let t = lock(t);
                if t.conn.is_handshaking() {
                    return None;
                }
                Some(
                    t.conn
                        .peer_certificates()
                        .map(|c| c.iter().map(|c| c.clone().into_owned()).collect())
                        .unwrap_or_default(),
                )
            }
        }
    }
}

/// Reads plain text from the wire.
struct WireReader {
    sock: TcpStream,
    wire: Writer,
    pending: Vec<u8>,
    start: usize,
    eof: bool,
}

impl Read for WireReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let Wire::Tls(t) = &*self.wire else {
            return self.sock.read(out);
        };
        loop {
            {
                let mut t = lock(t);
                match t.conn.reader().read(out) {
                    Ok(n) => return Ok(n),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                    Err(e) => return Err(e),
                }
                if self.start < self.pending.len() || self.eof {
                    let mut rest = &self.pending[self.start..];
                    let n = t.conn.read_tls(&mut rest)?;
                    self.start += n;
                    let processed = t.conn.process_new_packets();
                    // Handshake messages, session tickets, or the alert for an error.
                    let flushed = t.flush();
                    if let Err(e) = processed {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, TlsFailure(e)));
                    }
                    flushed?;
                    if self.eof && n == 0 {
                        return Ok(0);
                    }
                    continue;
                }
            }
            self.pending.resize(16 * 1024, 0);
            self.start = 0;
            match self.sock.read(&mut self.pending) {
                Ok(0) => {
                    self.pending.clear();
                    self.eof = true;
                }
                Ok(n) => self.pending.truncate(n),
                Err(e) => {
                    self.pending.clear();
                    return Err(e);
                }
            }
        }
    }
}

/// A TLS error from the client's side of the handshake or record layer.
#[derive(Debug)]
struct TlsFailure(rustls::Error);

impl std::fmt::Display for TlsFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TLS: {}", self.0)
    }
}

impl std::error::Error for TlsFailure {}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

// ----- one connection -----

struct Connection {
    id: u64,
    peer: String,
    peer_ip: Option<IpAddr>,
    /// Counted in `Shared::unauthenticated` until the first login.
    pending_login: bool,
    reader: BufReader<WireReader>,
    writer: Writer,
    controller: Arc<Controller>,
    shared: Arc<Shared>,
    role: Option<Role>,
    user: Option<String>,
    /// The role and name the client certificate gave, if any.
    cert_login: Option<(Role, String)>,
    cert_checked: bool,
    /// The client certificate chain, checked again after a reload.
    cert_chain: Option<Vec<rustls::pki_types::CertificateDer<'static>>>,
    /// The token this connection logged in with, checked again after a
    /// reload.
    token: Option<String>,
    /// The reload this connection last checked its logins against.
    generation: u64,
    auth_failures: u32,
    opened: Instant,
    last_request: Instant,
    subs: HashMap<u64, Arc<AtomicBool>>,
    next_sub: u64,
    /// The user whose session counts this connection.
    session_user: Option<String>,
}

/// What to do after a request.
enum Next {
    Continue,
    Close(&'static str),
}

impl Connection {
    fn new(
        stream: TcpStream,
        peer: String,
        controller: Arc<Controller>,
        shared: Arc<Shared>,
    ) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(TICK))?;
        stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
        let creds = shared.creds();
        let wire = match &creds.tls {
            None => Wire::Plain(Mutex::new(stream.try_clone()?)),
            Some(tls) => Wire::Tls(Box::new(Mutex::new(TlsWire {
                conn: rustls::ServerConnection::new(tls.config.clone())
                    .map_err(io::Error::other)?,
                sock: stream.try_clone()?,
            }))),
        };
        let writer = Arc::new(wire);
        let open = !shared.login_required;
        let now = Instant::now();
        let peer_ip = stream.peer_addr().ok().map(|a| a.ip());
        Ok(Self {
            id: shared.next_conn.fetch_add(1, Ordering::Relaxed),
            peer,
            peer_ip,
            pending_login: !open,
            reader: BufReader::new(WireReader {
                sock: stream,
                wire: writer.clone(),
                pending: Vec::new(),
                start: 0,
                eof: false,
            }),
            writer,
            controller,
            role: open.then_some(Role::Operator),
            user: None,
            cert_login: None,
            cert_checked: !shared.tls_on,
            cert_chain: None,
            token: None,
            generation: shared.generation.load(Ordering::SeqCst),
            shared,
            auth_failures: 0,
            opened: now,
            last_request: now,
            subs: HashMap::new(),
            next_sub: 1,
            session_user: None,
        })
    }

    /// Who the connection is, for the audit log.
    fn who(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("conn".into(), self.id.into());
        m.insert("peer".into(), self.peer.clone().into());
        if let Some(u) = &self.user {
            m.insert("user".into(), u.clone().into());
        }
        if let Some(r) = self.role {
            m.insert("role".into(), r.as_str().into());
        }
        m
    }

    /// Who the connection works for, for reservations and run owners.
    fn caller(&self) -> Who {
        Who {
            user: self.user.clone().unwrap_or_else(|| ANONYMOUS.into()),
            role: self.role,
            may_override: self.role == Some(Role::Admin) || !self.shared.login_required,
        }
    }

    /// Counts the connection in its user's session, moving it when its
    /// login changed.
    fn sync_session(&mut self) {
        let now = self
            .role
            .map(|_| self.user.clone().unwrap_or_else(|| ANONYMOUS.into()));
        let ports = self.controller.ports();
        if now != self.session_user {
            if let Some(old) = self.session_user.take() {
                ports.disconnected(&old);
            }
            if let Some(new) = &now {
                ports.connected(new, self.role);
            }
            self.session_user = now;
        } else if let Some(user) = &now {
            ports.seen(user);
        }
    }

    /// `session.name`: on a server without logins, the name this
    /// connection's reservations and runs go under.
    fn name_session(&mut self, params: Value) -> Result<Value, RpcError> {
        let p: SessionNameParams = parse(params)?;
        if self.shared.login_required {
            return Err(RpcError::forbidden(
                "this server names you by your login (token or certificate)",
            ));
        }
        let name = p.user.trim();
        let ok = !name.is_empty()
            && name.len() <= 64
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c));
        if !ok {
            return Err(RpcError::invalid_params(
                "a user name is 1 to 64 letters, digits, - _ . or @",
            ));
        }
        self.user = Some(name.to_string());
        self.sync_session();
        self.audit("session_name", json!({}));
        to_value(self.controller.ports().session(name))
    }

    fn audit(&self, event: &str, extra: Value) {
        if self.shared.audit.is_none() {
            return;
        }
        let mut m = self.who();
        if let Value::Object(e) = extra {
            m.extend(e);
        }
        self.shared.audit(event, Value::Object(m));
    }

    fn run(mut self) {
        self.audit("connect", json!({"tls": self.shared.tls_on}));
        let reason = match self.serve() {
            Ok(reason) => reason.to_string(),
            Err(e) => {
                if let Some(t) = e.get_ref().and_then(|e| e.downcast_ref::<TlsFailure>()) {
                    self.audit("tls_error", json!({"error": t.0.to_string()}));
                    "TLS error".to_string()
                } else {
                    format!("error: {e}")
                }
            }
        };
        for cancel in self.subs.values() {
            end_subscription(cancel, &self.shared);
        }
        if self.pending_login {
            self.shared.unauthenticated.fetch_sub(1, Ordering::SeqCst);
        }
        if let Some(user) = self.session_user.take() {
            self.controller.ports().disconnected(&user);
        }
        self.writer.close();
        self.audit("disconnect", json!({"reason": reason}));
    }

    fn serve(&mut self) -> io::Result<&'static str> {
        let max = self.shared.max_request;
        let mut line = Vec::new();
        loop {
            let limit = (max + 1).saturating_sub(line.len()) as u64;
            let read = (&mut self.reader).take(limit).read_until(b'\n', &mut line);
            if !self.cert_checked {
                if let Some(reason) = self.check_certificate()? {
                    return Ok(reason);
                }
            }
            if let Some(reason) = self.recheck()? {
                return Ok(reason);
            }
            match read {
                Ok(0) if line.is_empty() => return Ok("closed by the client"),
                Ok(0) => {}
                Ok(_) if line.len() <= max && !line.ends_with(b"\n") => {
                    // The end of the input, or a short read before a timeout: wait
                    // for the rest unless it was the end.
                    continue;
                }
                Ok(_) => {}
                Err(e) if is_timeout(&e) => {
                    if let Some(reason) = self.timed_out() {
                        return Ok(reason);
                    }
                    continue;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
            if line.len() > max {
                let err = RpcError::new(RpcError::INVALID_REQUEST, "request line too long");
                send(&self.writer, &Response::new(Value::Null, Err(err)))?;
                return Ok("request line too long");
            }
            self.last_request = Instant::now();
            let text = String::from_utf8_lossy(&line).into_owned();
            line.clear();
            let text = text.trim();
            if !text.is_empty() {
                if let Next::Close(reason) = self.handle_line(text)? {
                    return Ok(reason);
                }
            }
        }
    }

    /// Why the connection should close now, if it should.
    fn timed_out(&self) -> Option<&'static str> {
        if self.role.is_none() && self.opened.elapsed() >= self.shared.login_timeout {
            return Some("no login in time");
        }
        let watching = self.subs.values().any(|c| !c.load(Ordering::Relaxed));
        match self.shared.idle_timeout {
            Some(t) if !watching && self.last_request.elapsed() >= t => Some("idle"),
            _ => None,
        }
    }

    /// Logs in with the client certificate once the handshake is done.
    /// A refused fingerprint closes the connection: the reason is returned.
    fn check_certificate(&mut self) -> io::Result<Option<&'static str>> {
        let Some(chain) = self.writer.peer_certificates() else {
            return Ok(None);
        };
        self.cert_checked = true;
        let Some(end) = chain.first() else {
            return Ok(None);
        };
        let creds = self.shared.creds();
        let fp = fingerprint(end);
        if creds.tls.as_ref().is_some_and(|t| t.is_denied(&fp)) {
            self.audit("denied_cert", json!({"cert_sha256": fp}));
            self.goodbye("this client certificate is no longer accepted")?;
            return Ok(Some("certificate denied"));
        }
        let role = creds.tls.as_ref().and_then(|t| t.role_of(&chain));
        let name = common_name(end).unwrap_or_else(|| format!("cert:{}", &fp[..16]));
        let Some(role) = role else {
            return Ok(None);
        };
        self.cert_login = Some((role, name.clone()));
        self.cert_chain = Some(chain);
        self.role = Some(role);
        self.user = Some(name);
        self.logged_in();
        self.sync_session();
        self.audit("login", json!({"by": "certificate", "cert_sha256": fp}));
        Ok(None)
    }

    /// After a reload: checks the certificate and token this connection
    /// logged in with against the new settings. One no longer accepted
    /// closes the connection: the reason is returned.
    fn recheck(&mut self) -> io::Result<Option<&'static str>> {
        let generation = self.shared.generation.load(Ordering::SeqCst);
        if generation == self.generation {
            return Ok(None);
        }
        self.generation = generation;
        let creds = self.shared.creds();
        if let (Some((_, name)), Some(chain)) = (self.cert_login.clone(), &self.cert_chain) {
            let fp = fingerprint(&chain[0]);
            let tls = creds.tls.as_ref();
            let denied = tls.is_some_and(|t| t.is_denied(&fp));
            let role = tls.and_then(|t| t.role_of(chain)).filter(|_| !denied);
            let Some(role) = role else {
                let event = if denied {
                    "denied_cert"
                } else {
                    "revoked_cert"
                };
                self.audit(event, json!({"cert_sha256": fp}));
                self.goodbye("this client certificate is no longer accepted")?;
                return Ok(Some("certificate revoked"));
            };
            self.cert_login = Some((role, name.clone()));
            if self.token.is_none() {
                self.role = Some(role);
                self.user = Some(name);
            }
        }
        if let Some(secret) = &self.token {
            match creds.tokens.iter().find(|t| t.matches(secret)) {
                Some(t) => {
                    self.role = Some(t.role);
                    self.user = Some(t.name.clone());
                }
                None => {
                    self.audit("token_withdrawn", json!({}));
                    self.goodbye("this token is no longer accepted")?;
                    return Ok(Some("token withdrawn"));
                }
            }
        }
        Ok(None)
    }

    /// Tells the client why the connection closes.
    fn goodbye(&self, why: &str) -> io::Result<()> {
        send(
            &self.writer,
            &Response::new(Value::Null, Err(RpcError::forbidden(why))),
        )
    }

    /// The first login frees the connection's place among those waiting.
    fn logged_in(&mut self) {
        if self.pending_login {
            self.pending_login = false;
            self.shared.unauthenticated.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// With `audit_required`: why an operator call must be refused now.
    fn audit_unavailable(&self, method: &str) -> Option<RpcError> {
        let log = self.shared.audit.as_ref()?;
        if !self.shared.audit_required || log.ok() {
            return None;
        }
        // Try to write the refusal: if that works, the log is back.
        self.audit("audit_refused", json!({"method": method}));
        (!log.ok()).then(|| {
            RpcError::forbidden(
                "the audit log cannot be written, and this server refuses changes without it \
                 (--audit-required)",
            )
        })
    }

    fn handle_line(&mut self, text: &str) -> io::Result<Next> {
        let value: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => {
                let err = RpcError::new(RpcError::PARSE_ERROR, format!("not JSON: {e}"));
                send(&self.writer, &Response::new(Value::Null, Err(err)))?;
                return Ok(Next::Continue);
            }
        };
        let id_of = |v: &Value| v.get("id").cloned().unwrap_or(Value::Null);
        let req: Request = match serde_json::from_value(value.clone()) {
            Ok(r) if value.is_object() => r,
            _ => {
                let err = RpcError::new(
                    RpcError::INVALID_REQUEST,
                    "expected a JSON-RPC 2.0 request object (batches are not supported)",
                );
                send(&self.writer, &Response::new(id_of(&value), Err(err)))?;
                return Ok(Next::Continue);
            }
        };
        if req.jsonrpc != "2.0" {
            let err = RpcError::new(RpcError::INVALID_REQUEST, "jsonrpc must be \"2.0\"");
            send(&self.writer, &Response::new(id_of(&value), Err(err)))?;
            return Ok(Next::Continue);
        }

        let need = Role::required_for(&req.method);
        let allowed = match (need, self.role) {
            (None, _) => Ok(()),
            (Some(_), None) => Err(RpcError::new(
                RpcError::UNAUTHORIZED,
                "log in first: send auth with a token, or connect with a client certificate",
            )),
            (Some(need), Some(have)) if have < need => {
                self.audit("denied", json!({"method": req.method}));
                Err(RpcError::forbidden(format!(
                    "{} needs the {need} role; this login is {have}",
                    req.method
                )))
            }
            _ => Ok(()),
        };
        let mut next = Next::Continue;
        let outcome = match allowed {
            Err(e) => Err(e),
            Ok(()) => match req.method.as_str() {
                "auth" => {
                    let r = self.auth(req.params);
                    if r.is_err() {
                        self.auth_failures += 1;
                        std::thread::sleep(AUTH_FAILURE_DELAY);
                        if self.auth_failures >= MAX_AUTH_FAILURES {
                            next = Next::Close("too many failed logins");
                        }
                    }
                    r
                }
                "server.info" => {
                    let mut info = self.controller.info();
                    info.tls = self.shared.tls_on;
                    info.certificate_expires = self
                        .shared
                        .creds()
                        .tls
                        .as_ref()
                        .and_then(|t| t.expires)
                        .map(expiry);
                    info.role = self.role;
                    info.user = self.user.clone();
                    info.connections = Some(self.shared.open.load(Ordering::Relaxed));
                    info.subscriptions = Some(self.shared.subscriptions.load(Ordering::Relaxed));
                    info.audit = self.shared.audit.as_ref().map(|log| {
                        let mut h = log.health();
                        h.required = self.shared.audit_required;
                        Box::new(h)
                    });
                    to_value(info)
                }
                "stats.subscribe" => {
                    // The response must go out before the first notification.
                    self.subscribe(req.params, req.id)?;
                    return Ok(Next::Continue);
                }
                "stats.unsubscribe" => self.unsubscribe(req.params),
                "server.reload" => self
                    .shared
                    .reload(self.who())
                    .map_err(RpcError::failed)
                    .and_then(to_value),
                method if need == Some(Role::Operator) => {
                    if let Some(e) = self.audit_unavailable(method) {
                        if let Some(id) = req.id {
                            send(&self.writer, &Response::new(id, Err(e)))?;
                        }
                        return Ok(Next::Continue);
                    }
                    let logged = audit_params(&req.params);
                    let r = self.controller.call_as(&self.caller(), method, req.params);
                    // Reading frames is polled many times a second: the
                    // capture's start, stop and files are what the log keeps.
                    if self.shared.audit.is_some() && method != "capture.read" {
                        let mut extra =
                            json!({"method": method, "params": logged, "ok": r.is_ok()});
                        match &r {
                            Ok(v) => {
                                if let Some(id) = v.get("id") {
                                    extra["id"] = id.clone();
                                }
                            }
                            Err(e) => extra["error"] = e.message.clone().into(),
                        }
                        self.audit("call", extra);
                        if let Some(limit) = r.as_ref().err().and_then(crate::refused_limit) {
                            let e = r.as_ref().unwrap_err();
                            self.audit(
                                "limit_refused",
                                json!({"method": method, "limit": limit, "error": e.message}),
                            );
                        }
                    }
                    r
                }
                "session.name" => self.name_session(req.params),
                method => self.controller.call_as(&self.caller(), method, req.params),
            },
        };
        self.sync_session();
        if let Some(id) = req.id {
            send(&self.writer, &Response::new(id, outcome))?;
        }
        Ok(next)
    }

    fn auth(&mut self, params: Value) -> Result<Value, RpcError> {
        let p: AuthParams = parse(params)?;
        if !self.shared.login_required {
            return Ok(Value::Bool(true));
        }
        if let Some(why) = self.shared.throttled(self.peer_ip) {
            self.audit("login_throttled", json!({"reason": why}));
            return Err(RpcError::limit(why));
        }
        // Check every token, so the time taken does not tell which one is close.
        let creds = self.shared.creds();
        let mut found = None;
        for t in &creds.tokens {
            if t.matches(&p.token) && found.is_none() {
                found = Some(t);
            }
        }
        match found {
            Some(t) => {
                self.role = Some(t.role);
                self.user = Some(t.name.clone());
                self.token = Some(p.token.clone());
                self.logged_in();
                self.audit("login", json!({"by": "token"}));
                Ok(Value::Bool(true))
            }
            None => {
                // A wrong token ends a token login; a certificate login stays.
                self.token = None;
                match &self.cert_login {
                    Some((role, name)) => {
                        self.role = Some(*role);
                        self.user = Some(name.clone());
                    }
                    None => {
                        self.role = None;
                        self.user = None;
                    }
                }
                self.shared.login_failed(self.peer_ip);
                self.audit("login_failed", json!({"by": "token"}));
                Err(RpcError::new(RpcError::UNAUTHORIZED, "wrong token"))
            }
        }
    }

    fn subscribe(&mut self, params: Value, id: Option<Value>) -> io::Result<()> {
        let p: SubscribeParams = match parse(params) {
            Ok(p) => p,
            Err(e) => return reply(&self.writer, id, Err(e)),
        };
        if let Some(run) = p.id {
            if let Err(e) = self.controller.run(run) {
                return reply(&self.writer, id, Err(e));
            }
        }
        let interval = p
            .interval_ms
            .map_or(DEFAULT_INTERVAL, Duration::from_millis)
            .max(MIN_INTERVAL);
        // Subscriptions that ended by themselves (their run ended, or a write
        // failed) no longer count.
        self.subs.retain(|_, c| !c.load(Ordering::Relaxed));
        if self.subs.len() >= self.shared.max_subscriptions {
            let e = RpcError::limit(format!(
                "this connection already runs {} stats subscriptions, the most it may",
                self.subs.len()
            ));
            return reply(&self.writer, id, Err(e));
        }
        let total = &self.shared.subscriptions;
        if total.fetch_add(1, Ordering::SeqCst) >= self.shared.max_total_subscriptions {
            total.fetch_sub(1, Ordering::SeqCst);
            let e = RpcError::limit("the server runs as many stats subscriptions as it may");
            return reply(&self.writer, id, Err(e));
        }
        let sub = self.next_sub;
        self.next_sub += 1;
        let cancel = Arc::new(AtomicBool::new(false));
        self.subs.insert(sub, cancel.clone());
        if let Err(e) = reply(
            &self.writer,
            id,
            to_value(Subscription { subscription: sub }),
        ) {
            end_subscription(&cancel, &self.shared);
            return Err(e);
        }

        let writer = self.writer.clone();
        let controller = self.controller.clone();
        let shared = self.shared.clone();
        let spawned = std::thread::Builder::new()
            .name("ferotrx-ctl-stats".into())
            .spawn(move || {
                publish(sub, p.id, interval, &cancel, &controller, &writer);
                // Marks the subscription as over, for the idle timeout.
                end_subscription(&cancel, &shared);
            });
        if let Err(e) = spawned {
            if let Some(cancel) = self.subs.remove(&sub) {
                end_subscription(&cancel, &self.shared);
            }
            return Err(e);
        }
        Ok(())
    }

    fn unsubscribe(&mut self, params: Value) -> Result<Value, RpcError> {
        let p: Subscription = parse(params)?;
        match self.subs.remove(&p.subscription) {
            Some(cancel) => {
                end_subscription(&cancel, &self.shared);
                Ok(Value::Bool(true))
            }
            None => Err(RpcError::not_found(format!(
                "no subscription {}",
                p.subscription
            ))),
        }
    }
}

/// Ends a subscription: its publisher stops at its next check, and it stops
/// counting towards the server's limit (once, whoever ends it first).
fn end_subscription(cancel: &AtomicBool, shared: &Shared) {
    if !cancel.swap(true, Ordering::SeqCst) {
        shared.subscriptions.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Parameters as the audit log shows them: profile text by its size.
fn audit_params(params: &Value) -> Value {
    let mut p = params.clone();
    if let Some(Value::String(text)) = p.get("toml") {
        let bytes = text.len();
        p["toml"] = json!({ "bytes": bytes });
    }
    // A file's bytes (file.put): only how many.
    if let Some(Value::String(data)) = p.get("data") {
        let bytes = data.len() / 4 * 3;
        p["data"] = json!({ "bytes": bytes });
    }
    p
}

/// Sends `stats` notifications every `interval` until cancelled, the
/// connection breaks, or (for one run) the run ends.
fn publish(
    sub: u64,
    run: Option<u64>,
    interval: Duration,
    cancel: &AtomicBool,
    controller: &Controller,
    writer: &Writer,
) {
    let notify = |info, last| {
        let update = StatsUpdate {
            subscription: sub,
            run: info,
            last,
        };
        let params = serde_json::to_value(update).unwrap_or(Value::Null);
        send(writer, &Notification::new("stats", params))
    };
    // Runs that had already ended when the subscription started are not reported.
    let mut done: HashSet<u64> = controller
        .runs()
        .into_iter()
        .filter(|r| !r.state.is_running())
        .map(|r| r.id)
        .collect();
    let mut next = Instant::now();
    loop {
        // Sleep in short steps so unsubscribing takes effect quickly.
        while Instant::now() < next {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep((next - Instant::now()).min(Duration::from_millis(20)));
        }
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        next += interval;
        match run {
            Some(id) => {
                let Ok(info) = controller.run(id) else {
                    return; // the run was removed
                };
                let last = !info.state.is_running();
                if notify(info, last).is_err() || last {
                    return;
                }
            }
            None => {
                // Every run that is running, and one last update for each run
                // that ended since the subscription started.
                for info in controller.runs() {
                    if done.contains(&info.id) {
                        continue;
                    }
                    let last = !info.state.is_running();
                    if last {
                        done.insert(info.id);
                    }
                    if notify(info, last).is_err() {
                        return;
                    }
                }
            }
        }
    }
}

fn reply(writer: &Writer, id: Option<Value>, outcome: Result<Value, RpcError>) -> io::Result<()> {
    match id {
        Some(id) => send(writer, &Response::new(id, outcome)),
        None => Ok(()),
    }
}

fn send(writer: &Writer, msg: &impl Serialize) -> io::Result<()> {
    let mut line = serde_json::to_vec(msg).map_err(io::Error::other)?;
    line.push(b'\n');
    writer.send(&line)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
