//! SSH-2: a client that logs in and runs commands, and a server that
//! answers them.
//!
//! Both ends speak the real protocol, so OpenSSH works against either:
//! the version exchange, curve25519-sha256 key exchange with an
//! ssh-ed25519 host key, the ciphers chacha20-poly1305@openssh.com,
//! aes256-gcm@openssh.com and aes128-gcm@openssh.com, re-keying, user
//! authentication by password or Ed25519 public key (RFC 4252), and
//! session channels with flow control (RFC 4254).
//!
//! The client of each connection logs in (public key first if it has one,
//! then password), then runs its share of the commands, one session
//! channel each: `exec`, the command's input (if any) and EOF, then it
//! reads stdout and stderr up to the exit status and the channel's close.
//! A finished command is a transaction labelled `exit N`, as expected when
//! the status (and, if the profile says, the size of the output) is the
//! one the profile asks for. When all have run it sends DISCONNECT and
//! closes. With `rekey_after`, it starts a new key exchange after that
//! many bytes.
//!
//! The server checks logins against its `users` and `authorized_keys`
//! (accepting any when there are none), and runs commands from its routes
//! or a few built-ins: `echo`, `true`, `false`, `exit N`, `cat` (echoes its
//! input), `cat > /dev/null` (swallows it), `head -c SIZE /dev/zero`,
//! `whoami` and `hostname`. Others fail with exit status 127. A `shell`
//! request gets a small line-by-line shell running the same commands,
//! with echo and CR LF when a pty was asked for.
//!
//! Logins are transactions too: `auth password`, `auth publickey`, or
//! `auth refused`; a finished key exchange is a handshake, and a later one
//! a `rekey` transaction.

mod keys;
mod transport;
mod wire;

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

pub use keys::{fingerprint, parse_public_line, SshKey};
pub use transport::{CIPHERS, KEX_METHODS};

use self::transport::{Event, Transport};
use self::wire::{Reader, Writer};
use super::{
    AppCx, AppHandshake, AppProtocol, AppRole, AppSession, AppTransaction, Receive, SessionInit,
    Transport as Carrier,
};
use crate::{Error, Result};

const SERVICE_REQUEST: u8 = 5;
const SERVICE_ACCEPT: u8 = 6;
const EXT_INFO: u8 = 7;
const USERAUTH_REQUEST: u8 = 50;
const USERAUTH_FAILURE: u8 = 51;
const USERAUTH_SUCCESS: u8 = 52;
const USERAUTH_BANNER: u8 = 53;
const USERAUTH_PK_OK: u8 = 60;
const GLOBAL_REQUEST: u8 = 80;
const REQUEST_SUCCESS: u8 = 81;
const REQUEST_FAILURE: u8 = 82;
const CHANNEL_OPEN: u8 = 90;
const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
const CHANNEL_OPEN_FAILURE: u8 = 92;
const CHANNEL_WINDOW_ADJUST: u8 = 93;
const CHANNEL_DATA: u8 = 94;
const CHANNEL_EXTENDED_DATA: u8 = 95;
const CHANNEL_EOF: u8 = 96;
const CHANNEL_CLOSE: u8 = 97;
const CHANNEL_REQUEST: u8 = 98;
const CHANNEL_SUCCESS: u8 = 99;
const CHANNEL_FAILURE: u8 = 100;

const USERAUTH: &str = "ssh-userauth";
const CONNECTION: &str = "ssh-connection";
/// The largest data packet a channel takes.
const MAX_DATA: u32 = 32 * 1024;

/// A command the client runs.
#[derive(Clone, Debug, PartialEq)]
pub struct SshCommand {
    /// The command line, as `ssh HOST COMMAND` sends it.
    pub run: String,
    /// What it sends on the command's standard input, then EOF.
    pub input: Input,
    /// The exit status expected.
    pub exit: u32,
    /// The stdout size expected, if it matters.
    pub output_size: Option<u64>,
}

impl SshCommand {
    pub fn new(run: impl Into<String>) -> Self {
        Self {
            run: run.into(),
            input: Input::Bytes(Arc::from(&[][..])),
            exit: 0,
            output_size: None,
        }
    }
}

/// Bytes to send: given, or a number of filler bytes.
#[derive(Clone, Debug, PartialEq)]
pub enum Input {
    Bytes(Arc<[u8]>),
    Filler(u64),
    Zeros(u64),
}

impl Input {
    fn len(&self) -> u64 {
        match self {
            Input::Bytes(b) => b.len() as u64,
            Input::Filler(n) | Input::Zeros(n) => *n,
        }
    }
}

/// The client part.
#[derive(Clone, Debug, PartialEq)]
pub struct SshClient {
    pub user: String,
    pub password: Option<String>,
    /// Log in with this key (tried before the password).
    pub key: Option<SshKey>,
    pub commands: Vec<SshCommand>,
    /// Commands per connection, taken in turn from `commands`.
    pub per_connection: u32,
    /// The server's host key fingerprint (`SHA256:...`), if it must be it.
    pub fingerprint: Option<String>,
    /// `failure`: the login (or key exchange) must fail.
    pub expect: Option<String>,
    /// Start a new key exchange after this many bytes.
    pub rekey_after: Option<u64>,
    /// The receive window of each channel.
    pub window: u32,
}

impl Default for SshClient {
    fn default() -> Self {
        Self {
            user: "lab".into(),
            password: Some("lab".into()),
            key: None,
            commands: vec![SshCommand::new("echo hello")],
            per_connection: 1,
            fingerprint: None,
            expect: None,
            rekey_after: None,
            window: 2 * 1024 * 1024,
        }
    }
}

impl SshClient {
    fn expects_failure(&self) -> bool {
        self.expect.as_deref() == Some("failure")
    }
}

/// What the server answers to a command.
#[derive(Clone, Debug, PartialEq)]
pub struct SshRoute {
    /// The command line; a trailing `*` matches any rest.
    pub command: String,
    pub output: Input,
    pub stderr: Arc<[u8]>,
    pub exit: u32,
    /// Waits this long before answering.
    pub delay: Duration,
}

impl SshRoute {
    pub fn new(command: impl Into<String>, output: impl Into<Vec<u8>>) -> Self {
        Self {
            command: command.into(),
            output: Input::Bytes(output.into().into()),
            stderr: Arc::from(&[][..]),
            exit: 0,
            delay: Duration::ZERO,
        }
    }

    fn matches(&self, cmd: &str) -> bool {
        match self.command.strip_suffix('*') {
            Some(prefix) => cmd.starts_with(prefix),
            None => cmd == self.command,
        }
    }
}

/// The server part.
#[derive(Clone, Debug, PartialEq)]
pub struct SshServer {
    pub host_key: SshKey,
    /// User names and passwords; empty takes any password.
    pub users: BTreeMap<String, String>,
    /// Public key blobs that may log in; empty takes any key.
    pub authorized_keys: Vec<Vec<u8>>,
    /// Sent before the login.
    pub banner: Option<String>,
    pub routes: Vec<SshRoute>,
    /// Failed logins before the server disconnects.
    pub max_auth_tries: u32,
    /// What `hostname` prints.
    pub hostname: String,
}

impl Default for SshServer {
    fn default() -> Self {
        Self {
            host_key: SshKey::generate(),
            users: BTreeMap::new(),
            authorized_keys: Vec::new(),
            banner: None,
            routes: Vec::new(),
            max_auth_tries: 6,
            hostname: "ferotrx".into(),
        }
    }
}

/// SSH client and server; see the [module](self) docs.
#[derive(Clone, Debug, PartialEq)]
pub struct Ssh {
    pub client: SshClient,
    pub server: SshServer,
    /// The ciphers, best first: a subset of [`CIPHERS`].
    pub ciphers: Vec<String>,
    /// The software version after `SSH-2.0-`.
    pub version: String,
}

impl Default for Ssh {
    fn default() -> Self {
        Self {
            client: SshClient::default(),
            server: SshServer::default(),
            ciphers: CIPHERS.iter().map(|s| s.to_string()).collect(),
            version: format!("FeroTRX_{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

impl Ssh {
    fn line(&self) -> String {
        format!("SSH-2.0-{}", self.version)
    }
}

impl AppProtocol for Ssh {
    fn name(&self) -> &str {
        "ssh"
    }

    fn describe(&self) -> String {
        let c = &self.client;
        let mut s = format!(
            "SSH-2.0: {} command(s), {} per connection, user {}",
            c.commands.len(),
            c.per_connection,
            c.user
        );
        match (&c.key, &c.password) {
            (Some(_), Some(_)) => s += " (key, password)",
            (Some(_), None) => s += " (key)",
            (None, Some(_)) => s += " (password)",
            (None, None) => s += " (no login)",
        }
        if let Some(n) = c.rekey_after {
            s += &format!(", rekey every {n} bytes");
        }
        s += &format!("; host key {}", self.server.host_key.fingerprint());
        if !self.server.routes.is_empty() {
            s += &format!(", {} route(s)", self.server.routes.len());
        }
        if !self.server.users.is_empty() {
            s += &format!(", {} user(s)", self.server.users.len());
        }
        if !self.server.authorized_keys.is_empty() {
            s += &format!(", {} key(s)", self.server.authorized_keys.len());
        }
        s
    }

    fn default_port(&self) -> u16 {
        22
    }

    fn supports(&self, transport: Carrier) -> bool {
        transport == Carrier::Stream
    }

    fn validate(&self, role: AppRole, _transport: Carrier) -> Result<()> {
        if self.ciphers.is_empty() {
            return Err(Error::Profile("SSH: no ciphers".into()));
        }
        for c in &self.ciphers {
            if !CIPHERS.contains(&c.as_str()) {
                return Err(Error::Profile(format!(
                    "SSH: unknown cipher `{c}`; known: {}",
                    CIPHERS.join(", ")
                )));
            }
        }
        if role == AppRole::Client {
            let c = &self.client;
            if c.per_connection > 0 && c.commands.is_empty() {
                return Err(Error::Profile("SSH: no commands to run".into()));
            }
            if let Some(e) = &c.expect {
                if e != "failure" && e != "success" {
                    return Err(Error::Profile(format!(
                        "SSH: expect is `success` or `failure`, not `{e}`"
                    )));
                }
            }
            if c.window < MAX_DATA {
                return Err(Error::Profile(format!(
                    "SSH: window must be at least {MAX_DATA}"
                )));
            }
        }
        Ok(())
    }

    fn session(&self, init: &SessionInit) -> Box<dyn AppSession> {
        let cfg = Arc::new(self.clone());
        match init.role {
            AppRole::Client => Box::new(ClientSession::new(cfg, init.index)),
            AppRole::Server => Box::new(ServerSession::new(cfg)),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Bytes queued for a channel.
#[derive(Default)]
struct Queue(VecDeque<Input>);

impl Queue {
    fn push(&mut self, i: Input) {
        if i.len() > 0 {
            self.0.push_back(i);
        }
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Up to `max` bytes.
    fn take(&mut self, max: usize) -> Vec<u8> {
        let mut out = Vec::new();
        while out.len() < max {
            let Some(front) = self.0.front_mut() else {
                break;
            };
            let room = max - out.len();
            match front {
                Input::Bytes(b) => {
                    let n = room.min(b.len());
                    out.extend_from_slice(&b[..n]);
                    if n == b.len() {
                        self.0.pop_front();
                    } else {
                        *b = Arc::from(&b[n..]);
                    }
                }
                Input::Filler(left) | Input::Zeros(left) => {
                    let n = (room as u64).min(*left);
                    *left -= n;
                    let done = *left == 0;
                    if matches!(front, Input::Zeros(_)) {
                        out.resize(out.len() + n as usize, 0);
                    } else {
                        out.extend(super::filler(n as usize));
                    }
                    if done {
                        self.0.pop_front();
                    }
                }
            }
        }
        out
    }
}

/// One side of a channel's flow control.
struct Flow {
    /// The peer's number for the channel.
    peer: u32,
    /// What the peer still takes.
    peer_window: u64,
    peer_max: u32,
    /// What we still take, and the window we give.
    window: u32,
    full: u32,
}

impl Flow {
    fn new(peer: u32, peer_window: u32, peer_max: u32, full: u32) -> Self {
        Self {
            peer,
            peer_window: u64::from(peer_window),
            peer_max: peer_max.clamp(1, MAX_DATA),
            window: full,
            full,
        }
    }

    /// Counts received data; tops the window up when half is used.
    fn received(&mut self, n: usize, t: &mut Transport, cx: &mut AppCx) {
        self.window = self.window.saturating_sub(n as u32);
        if self.window < self.full / 2 {
            let mut w = Writer::msg(CHANNEL_WINDOW_ADJUST);
            w.u32(self.peer).u32(self.full - self.window);
            t.send(w.into_inner(), cx);
            self.window = self.full;
        }
    }

    /// Sends what the window lets out of `q` as data (`ext` 1: stderr).
    fn drain(&mut self, q: &mut Queue, ext: Option<u32>, t: &mut Transport, cx: &mut AppCx) {
        while !q.is_empty() && self.peer_window > 0 {
            let n = (self.peer_max as u64).min(self.peer_window) as usize;
            let data = q.take(n);
            self.peer_window -= data.len() as u64;
            let mut w = match ext {
                None => Writer::msg(CHANNEL_DATA),
                Some(_) => Writer::msg(CHANNEL_EXTENDED_DATA),
            };
            w.u32(self.peer);
            if let Some(code) = ext {
                w.u32(code);
            }
            w.string(&data);
            t.send(w.into_inner(), cx);
        }
    }
}

fn simple(t: &mut Transport, kind: u8, peer: u32, cx: &mut AppCx) {
    let mut w = Writer::msg(kind);
    w.u32(peer);
    t.send(w.into_inner(), cx);
}

/// The client's part of a channel.
struct ClientChan {
    id: u32,
    cmd: SshCommand,
    flow: Option<Flow>,
    input: Queue,
    started: Duration,
    stdout: u64,
    stderr: u64,
    exit: Option<String>,
    status: Option<u32>,
    running: bool,
    sent_eof: bool,
    sent_close: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Kex,
    Service,
    Auth,
    Run,
    Done,
}

struct ClientSession {
    cfg: Arc<Ssh>,
    t: Transport,
    index: u64,
    start: Duration,
    phase: Phase,
    tried_key: bool,
    tried_password: bool,
    method: &'static str,
    ran: u32,
    next_id: u32,
    chan: Option<ClientChan>,
}

impl ClientSession {
    fn new(cfg: Arc<Ssh>, index: u64) -> Self {
        let t = Transport::new(
            false,
            &cfg.line(),
            &cfg.ciphers,
            None,
            cfg.client.fingerprint.clone(),
        );
        Self {
            cfg,
            t,
            index,
            start: Duration::ZERO,
            phase: Phase::Kex,
            tried_key: false,
            tried_password: false,
            method: "none",
            ran: 0,
            next_id: 0,
            chan: None,
        }
    }

    fn fail(&mut self, cx: &mut AppCx, (code, what): transport::Failure) {
        let expected = self.cfg.client.expects_failure();
        if self.phase == Phase::Kex {
            cx.handshake(AppHandshake {
                label: format!("failed: {what}"),
                succeeded: false,
                expected,
                resumed: false,
                time: Some(cx.now().saturating_sub(self.start)),
            });
        } else if !expected {
            cx.protocol_error(what.clone());
        }
        self.t.disconnect(code, &what, cx);
        self.phase = Phase::Done;
        cx.close();
    }

    fn finish(&mut self, cx: &mut AppCx) {
        if self.phase != Phase::Done {
            self.t
                .disconnect(transport::BY_APPLICATION, "disconnected by user", cx);
            self.phase = Phase::Done;
        }
        cx.close();
    }

    fn try_login(&mut self, methods: Option<&[String]>, cx: &mut AppCx) -> bool {
        let allows = |m: &str| methods.is_none_or(|l| l.iter().any(|x| x == m));
        let c = &self.cfg.client;
        let sid = self.t.session_id().unwrap_or_default().to_vec();
        let mut w = Writer::msg(USERAUTH_REQUEST);
        w.str(&c.user).str(CONNECTION);
        if let Some(key) = c
            .key
            .as_ref()
            .filter(|_| !self.tried_key && allows("publickey"))
        {
            self.tried_key = true;
            self.method = "publickey";
            let blob = key.public_blob();
            let mut signed = Writer::new();
            signed
                .string(&sid)
                .byte(USERAUTH_REQUEST)
                .str(&c.user)
                .str(CONNECTION)
                .str("publickey")
                .bool(true)
                .str(keys::ED25519)
                .string(&blob);
            let sig = key.sign(&signed.into_inner());
            w.str("publickey")
                .bool(true)
                .str(keys::ED25519)
                .string(&blob)
                .string(&sig);
        } else if let Some(pw) = c
            .password
            .as_ref()
            .filter(|_| !self.tried_password && allows("password"))
        {
            self.tried_password = true;
            self.method = "password";
            w.str("password").bool(false).str(pw);
        } else if methods.is_none() {
            self.method = "none";
            w.str("none");
        } else {
            return false;
        }
        self.t.send(w.into_inner(), cx);
        true
    }

    fn next_command(&mut self, cx: &mut AppCx) {
        let c = &self.cfg.client;
        if self.ran >= c.per_connection {
            self.finish(cx);
            return;
        }
        let k = (self.index * u64::from(c.per_connection) + u64::from(self.ran)) as usize
            % c.commands.len();
        let cmd = c.commands[k].clone();
        self.ran += 1;
        let id = self.next_id;
        self.next_id += 1;
        let mut w = Writer::msg(CHANNEL_OPEN);
        w.str("session").u32(id).u32(c.window).u32(MAX_DATA);
        self.t.send(w.into_inner(), cx);
        let mut input = Queue::default();
        input.push(cmd.input.clone());
        self.chan = Some(ClientChan {
            id,
            cmd,
            flow: None,
            input,
            started: cx.now(),
            stdout: 0,
            stderr: 0,
            exit: None,
            status: None,
            running: false,
            sent_eof: false,
            sent_close: false,
        });
    }

    fn pump(&mut self, cx: &mut AppCx) {
        let Some(ch) = self.chan.as_mut() else {
            return;
        };
        let Some(flow) = ch.flow.as_mut() else {
            return;
        };
        if !ch.running || ch.sent_close {
            return;
        }
        flow.drain(&mut ch.input, None, &mut self.t, cx);
        if ch.input.is_empty() && !ch.sent_eof {
            ch.sent_eof = true;
            simple(&mut self.t, CHANNEL_EOF, flow.peer, cx);
        }
    }

    /// The channel closed: count the command and go on.
    fn closed(&mut self, cx: &mut AppCx) {
        let Some(ch) = self.chan.take() else {
            return;
        };
        if !ch.sent_close {
            if let Some(f) = &ch.flow {
                simple(&mut self.t, CHANNEL_CLOSE, f.peer, cx);
            }
        }
        let label = ch.exit.clone().unwrap_or_else(|| "no exit status".into());
        let size_ok = ch.cmd.output_size.is_none_or(|n| n == ch.stdout);
        let ok = ch.status == Some(ch.cmd.exit) && size_ok;
        if !size_ok {
            cx.protocol_error(format!(
                "`{}`: {} bytes of output, expected {}",
                ch.cmd.run,
                ch.stdout,
                ch.cmd.output_size.unwrap_or(0)
            ));
        }
        cx.transaction(
            AppTransaction::new(label, ok)
                .with_error(ch.status != Some(0))
                .with_response_time(cx.now().saturating_sub(ch.started)),
        );
        self.next_command(cx);
    }

    fn take(&mut self, p: &[u8], cx: &mut AppCx) -> std::result::Result<(), transport::Failure> {
        let malformed = || {
            (
                transport::PROTOCOL_ERROR,
                format!("malformed message {}", p[0]),
            )
        };
        let mut r = Reader::new(&p[1..]);
        match p[0] {
            SERVICE_ACCEPT if self.phase == Phase::Service => {
                self.phase = Phase::Auth;
                self.try_login(None, cx);
            }
            USERAUTH_BANNER | USERAUTH_PK_OK | EXT_INFO => {}
            USERAUTH_FAILURE if self.phase == Phase::Auth => {
                let methods = r.names().ok_or_else(malformed)?;
                if !self.try_login(Some(&methods), cx) {
                    let ok = self.cfg.client.expects_failure();
                    cx.transaction(AppTransaction::new("auth refused", ok).with_error(true));
                    self.finish(cx);
                }
            }
            USERAUTH_SUCCESS if self.phase == Phase::Auth => {
                let ok = !self.cfg.client.expects_failure();
                cx.transaction(AppTransaction::new(format!("auth {}", self.method), ok));
                if !ok {
                    self.finish(cx);
                } else {
                    self.phase = Phase::Run;
                    self.next_command(cx);
                }
            }
            GLOBAL_REQUEST => {
                let _name = r.str().ok_or_else(malformed)?;
                if r.bool() == Some(true) {
                    self.t.send(vec![REQUEST_FAILURE], cx);
                }
            }
            REQUEST_SUCCESS | REQUEST_FAILURE => {}
            CHANNEL_OPEN => {
                // The server may not open channels to us.
                let _kind = r.str().ok_or_else(malformed)?;
                let peer = r.u32().ok_or_else(malformed)?;
                let mut w = Writer::msg(CHANNEL_OPEN_FAILURE);
                w.u32(peer).u32(1).str("not taken").str("");
                self.t.send(w.into_inner(), cx);
            }
            _ if self.phase == Phase::Run
                && (CHANNEL_OPEN_CONFIRMATION..=CHANNEL_FAILURE).contains(&p[0]) =>
            {
                let id = r.u32().ok_or_else(malformed)?;
                let Some(ch) = self.chan.as_mut().filter(|c| c.id == id) else {
                    return Ok(()); // a channel we closed
                };
                let full = self.cfg.client.window;
                match p[0] {
                    CHANNEL_OPEN_CONFIRMATION => {
                        let (peer, win, max) = (r.u32(), r.u32(), r.u32());
                        let (Some(peer), Some(win), Some(max)) = (peer, win, max) else {
                            return Err(malformed());
                        };
                        ch.flow = Some(Flow::new(peer, win, max, full));
                        let mut w = Writer::msg(CHANNEL_REQUEST);
                        w.u32(peer).str("exec").bool(true).str(&ch.cmd.run);
                        self.t.send(w.into_inner(), cx);
                    }
                    CHANNEL_OPEN_FAILURE => {
                        let code = r.u32().unwrap_or(0);
                        let text = r.str().unwrap_or("").to_string();
                        cx.protocol_error(format!("channel refused ({code}): {text}"));
                        self.chan = None;
                        cx.transaction(
                            AppTransaction::new("channel refused", false).with_error(true),
                        );
                        self.next_command(cx);
                    }
                    CHANNEL_SUCCESS => {
                        ch.running = true;
                        self.pump(cx);
                    }
                    CHANNEL_FAILURE => {
                        cx.protocol_error(format!("`{}`: exec refused", ch.cmd.run));
                        ch.exit = Some("exec refused".into());
                        if let Some(f) = &ch.flow {
                            ch.sent_close = true;
                            simple(&mut self.t, CHANNEL_CLOSE, f.peer, cx);
                        }
                    }
                    CHANNEL_WINDOW_ADJUST => {
                        let n = r.u32().ok_or_else(malformed)?;
                        if let Some(f) = ch.flow.as_mut() {
                            f.peer_window += u64::from(n);
                        }
                        self.pump(cx);
                    }
                    CHANNEL_DATA | CHANNEL_EXTENDED_DATA => {
                        let ext = if p[0] == CHANNEL_EXTENDED_DATA {
                            r.u32()
                        } else {
                            None
                        };
                        let data = r.string().ok_or_else(malformed)?;
                        if ext.is_some() {
                            ch.stderr += data.len() as u64;
                        } else {
                            ch.stdout += data.len() as u64;
                        }
                        if let Some(f) = ch.flow.as_mut() {
                            f.received(data.len(), &mut self.t, cx);
                        }
                    }
                    CHANNEL_EOF => {}
                    CHANNEL_REQUEST => {
                        let kind = r.str().ok_or_else(malformed)?;
                        let want = r.bool().ok_or_else(malformed)?;
                        match kind {
                            "exit-status" => {
                                let n = r.u32().ok_or_else(malformed)?;
                                ch.status = Some(n);
                                ch.exit = Some(format!("exit {n}"));
                            }
                            "exit-signal" => {
                                let sig = r.str().unwrap_or("?");
                                ch.exit = Some(format!("signal {sig}"));
                            }
                            _ => {}
                        }
                        if want {
                            if let Some(f) = &ch.flow {
                                simple(&mut self.t, CHANNEL_FAILURE, f.peer, cx);
                            }
                        }
                    }
                    CHANNEL_CLOSE => self.closed(cx),
                    _ => {}
                }
            }
            CHANNEL_OPEN_CONFIRMATION..=CHANNEL_FAILURE => {}
            _ => {
                return Err((
                    transport::PROTOCOL_ERROR,
                    format!("unexpected message {}", p[0]),
                ));
            }
        }
        Ok(())
    }

    fn events(&mut self, events: Vec<Event>, cx: &mut AppCx) {
        for e in events {
            if self.phase == Phase::Done {
                return;
            }
            match e {
                Event::KexDone { first: true } => {
                    cx.handshake(AppHandshake {
                        label: self.t.negotiated.clone(),
                        succeeded: true,
                        expected: true,
                        resumed: false,
                        time: Some(cx.now().saturating_sub(self.start)),
                    });
                    self.phase = Phase::Service;
                    let mut w = Writer::msg(SERVICE_REQUEST);
                    w.str(USERAUTH);
                    self.t.send(w.into_inner(), cx);
                }
                Event::KexDone { first: false } => {
                    cx.transaction(AppTransaction::new("rekey", true));
                }
                Event::Disconnect(code, text) => {
                    cx.goodbye();
                    if !self.cfg.client.expects_failure() {
                        cx.protocol_error(format!("the server disconnected ({code}): {text}"));
                    }
                    self.phase = Phase::Done;
                    cx.close();
                }
                Event::Packet(p) => {
                    if let Err(f) = self.take(&p, cx) {
                        self.fail(cx, f);
                    }
                }
            }
        }
        if let Some(n) = self.cfg.client.rekey_after {
            if self.phase == Phase::Run && self.t.bytes >= n {
                self.t.rekey(cx);
            }
        }
    }
}

impl AppSession for ClientSession {
    fn start(&mut self, cx: &mut AppCx) {
        self.start = cx.now();
        self.t.start(cx);
    }

    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        if self.phase == Phase::Done {
            return Receive::Taken;
        }
        match self.t.feed(data, cx) {
            Ok(events) => self.events(events, cx),
            Err(f) => self.fail(cx, f),
        }
        Receive::Taken
    }

    fn peer_closed(&mut self, cx: &mut AppCx) {
        if self.phase != Phase::Done {
            let what = match self.phase {
                Phase::Kex => "during the key exchange",
                Phase::Service | Phase::Auth => "during the login",
                _ => "while commands ran",
            };
            if !self.cfg.client.expects_failure() || self.phase == Phase::Run {
                cx.protocol_error(format!("the server closed the connection {what}"));
            }
            self.phase = Phase::Done;
        }
        cx.close();
    }
}

/// What a command does with its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sink {
    Ignore,
    Echo,
    Swallow,
}

/// How the server answers a command line.
struct Answer {
    out: Input,
    err: Vec<u8>,
    exit: u32,
    delay: Duration,
    sink: Sink,
}

impl Answer {
    fn text(out: impl Into<Vec<u8>>, exit: u32) -> Self {
        Self {
            out: Input::Bytes(out.into().into()),
            err: Vec::new(),
            exit,
            delay: Duration::ZERO,
            sink: Sink::Ignore,
        }
    }
}

fn unquote(s: &str) -> &str {
    let s = s.trim();
    for q in ['"', '\''] {
        if s.len() >= 2 && s.starts_with(q) && s.ends_with(q) {
            return &s[1..s.len() - 1];
        }
    }
    s
}

fn answer(cfg: &Ssh, user: &str, line: &str) -> Answer {
    let line = line.trim();
    if let Some(r) = cfg.server.routes.iter().find(|r| r.matches(line)) {
        return Answer {
            out: r.output.clone(),
            err: r.stderr.to_vec(),
            exit: r.exit,
            delay: r.delay,
            sink: Sink::Ignore,
        };
    }
    let (word, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
    let rest = rest.trim();
    match word {
        "true" | ":" => Answer::text("", 0),
        "false" => Answer::text("", 1),
        "exit" => Answer::text("", rest.parse().unwrap_or(0)),
        "echo" => Answer::text(format!("{}\n", unquote(rest)), 0),
        "whoami" => Answer::text(format!("{user}\n"), 0),
        "hostname" => Answer::text(format!("{}\n", cfg.server.hostname), 0),
        "cat" if rest.is_empty() => Answer {
            sink: Sink::Echo,
            ..Answer::text("", 0)
        },
        "cat" if rest.replace(' ', "") == ">/dev/null" => Answer {
            sink: Sink::Swallow,
            ..Answer::text("", 0)
        },
        "head" => {
            let w: Vec<&str> = rest.split_whitespace().collect();
            match w[..] {
                ["-c", n, "/dev/zero"] => match crate::parse_size(n) {
                    Ok(n) => Answer {
                        out: Input::Zeros(n),
                        ..Answer::text("", 0)
                    },
                    Err(_) => Answer {
                        err: format!("head: invalid number of bytes: '{n}'\n").into_bytes(),
                        ..Answer::text("", 1)
                    },
                },
                _ => not_found(line),
            }
        }
        _ => not_found(line),
    }
}

fn not_found(line: &str) -> Answer {
    let word = line.split_whitespace().next().unwrap_or("");
    Answer {
        err: format!("sh: 1: {word}: not found\n").into_bytes(),
        ..Answer::text("", 127)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Idle,
    Exec,
    Shell,
}

/// The server's part of a channel.
struct ServerChan {
    flow: Flow,
    pty: bool,
    mode: Mode,
    sink: Sink,
    out: Queue,
    err: Queue,
    /// The exit status, once the command is done.
    exit: Option<u32>,
    /// The status to give when the input ends (`cat`).
    at_eof: Option<u32>,
    /// An answer waiting for its delay.
    due: Option<(Duration, Answer)>,
    line: Vec<u8>,
    peer_eof: bool,
    ended: bool,
}

impl ServerChan {
    fn new(flow: Flow) -> Self {
        Self {
            flow,
            pty: false,
            mode: Mode::Idle,
            sink: Sink::Ignore,
            out: Queue::default(),
            err: Queue::default(),
            exit: None,
            at_eof: None,
            due: None,
            line: Vec::new(),
            peer_eof: false,
            ended: false,
        }
    }

    fn apply(&mut self, a: Answer) {
        self.out.push(a.out);
        self.err.push(Input::Bytes(a.err.into()));
        self.sink = a.sink;
        if a.sink == Sink::Ignore || self.peer_eof {
            self.exit = Some(a.exit);
        } else {
            self.at_eof = Some(a.exit);
        }
    }

    /// Text for a terminal: LF becomes CR LF with a pty.
    fn term(&self, b: &[u8]) -> Input {
        if !self.pty {
            return Input::Bytes(b.into());
        }
        let mut v = Vec::with_capacity(b.len() + 8);
        for &c in b {
            if c == b'\n' {
                v.push(b'\r');
            }
            v.push(c);
        }
        Input::Bytes(v.into())
    }

    fn prompt(&mut self) {
        self.out.push(Input::Bytes(Arc::from(&b"$ "[..])));
    }

    /// Typed bytes for the shell: echoed with a pty, run line by line.
    fn shell_input(&mut self, data: &[u8], cfg: &Ssh, user: &str) {
        for &b in data {
            if self.exit.is_some() {
                return;
            }
            match b {
                b'\r' | b'\n' if self.pty || b == b'\n' => {
                    if self.pty {
                        self.out.push(Input::Bytes(Arc::from(&b"\r\n"[..])));
                    }
                    let line =
                        String::from_utf8_lossy(&std::mem::take(&mut self.line)).into_owned();
                    self.run_line(line.trim(), cfg, user);
                }
                b'\r' => {}
                0x7f | 0x08 if self.pty => {
                    if self.line.pop().is_some() {
                        self.out.push(Input::Bytes(Arc::from(&b"\x08 \x08"[..])));
                    }
                }
                0x03 if self.pty => {
                    self.line.clear();
                    self.out.push(Input::Bytes(Arc::from(&b"^C\r\n"[..])));
                    self.prompt();
                }
                0x04 if self.pty && self.line.is_empty() => self.exit = Some(0),
                _ => {
                    self.line.push(b);
                    if self.pty {
                        self.out.push(Input::Bytes(Arc::from(&[b][..])));
                    }
                }
            }
        }
    }

    fn run_line(&mut self, line: &str, cfg: &Ssh, user: &str) {
        if line.is_empty() {
            self.prompt();
            return;
        }
        let a = answer(cfg, user, line);
        if line == "exit" || line.starts_with("exit ") {
            self.exit = Some(a.exit);
            return;
        }
        if a.sink != Sink::Ignore {
            let e = self.term(b"this shell runs only commands without input\n");
            self.err.push(e);
        } else {
            match &a.out {
                Input::Bytes(b) => {
                    let o = self.term(b);
                    self.out.push(o);
                }
                other => self.out.push(other.clone()),
            }
            let e = self.term(&a.err);
            self.err.push(e);
        }
        self.prompt();
    }
}

struct ServerSession {
    cfg: Arc<Ssh>,
    t: Transport,
    start: Duration,
    kexed: bool,
    user: Option<String>,
    failures: u32,
    banner_sent: bool,
    chans: BTreeMap<u32, ServerChan>,
    next_id: u32,
    done: bool,
}

impl ServerSession {
    fn new(cfg: Arc<Ssh>) -> Self {
        let t = Transport::new(
            true,
            &cfg.line(),
            &cfg.ciphers,
            Some(cfg.server.host_key.clone()),
            None,
        );
        Self {
            cfg,
            t,
            start: Duration::ZERO,
            kexed: false,
            user: None,
            failures: 0,
            banner_sent: false,
            chans: BTreeMap::new(),
            next_id: 0,
            done: false,
        }
    }

    fn fail(&mut self, cx: &mut AppCx, (code, what): transport::Failure) {
        if !self.kexed {
            cx.handshake(AppHandshake {
                label: format!("failed: {what}"),
                succeeded: false,
                expected: false,
                resumed: false,
                time: Some(cx.now().saturating_sub(self.start)),
            });
        }
        cx.protocol_error(what.clone());
        self.t.disconnect(code, &what, cx);
        self.done = true;
        cx.close();
    }

    fn login(&mut self, r: &mut Reader, cx: &mut AppCx) -> Option<()> {
        let user = r.str()?.to_string();
        let _service = r.str()?;
        let method = r.str()?.to_string();
        if self.user.is_some() {
            return Some(()); // already in: ignored (RFC 4252 section 5.1)
        }
        if !self.banner_sent {
            self.banner_sent = true;
            if let Some(b) = &self.cfg.server.banner {
                let mut w = Writer::msg(USERAUTH_BANNER);
                w.str(b).str("");
                self.t.send(w.into_inner(), cx);
            }
        }
        let s = &self.cfg.server;
        // None: not an attempt; Some(ok): one.
        let attempt = match method.as_str() {
            "password" => {
                let _change = r.bool()?;
                let pw = r.str()?;
                Some(s.users.is_empty() || s.users.get(&user).is_some_and(|p| p == pw))
            }
            "publickey" => {
                let signed = r.bool()?;
                let alg = r.str()?.to_string();
                let blob = r.string()?.to_vec();
                let known = alg == keys::ED25519
                    && (s.authorized_keys.is_empty() || s.authorized_keys.contains(&blob));
                if known && !signed {
                    let mut w = Writer::msg(USERAUTH_PK_OK);
                    w.str(&alg).string(&blob);
                    self.t.send(w.into_inner(), cx);
                    return Some(());
                }
                if !signed {
                    None
                } else {
                    let sig = r.string()?;
                    let mut data = Writer::new();
                    data.string(self.t.session_id().unwrap_or_default())
                        .byte(USERAUTH_REQUEST)
                        .str(&user)
                        .str(CONNECTION)
                        .str("publickey")
                        .bool(true)
                        .str(&alg)
                        .string(&blob);
                    Some(known && keys::verify(&blob, sig, &data.into_inner()))
                }
            }
            _ => None,
        };
        match attempt {
            Some(true) => {
                cx.transaction(AppTransaction::new(format!("auth {method}"), true));
                self.user = Some(user);
                self.t.send(vec![USERAUTH_SUCCESS], cx);
            }
            Some(false) => {
                cx.transaction(AppTransaction::new("auth refused", true).with_error(true));
                self.failures += 1;
                if self.failures >= s.max_auth_tries {
                    self.t.disconnect(
                        transport::NO_MORE_AUTH_METHODS,
                        "too many authentication failures",
                        cx,
                    );
                    self.done = true;
                    cx.close();
                    return Some(());
                }
                self.refuse(cx);
            }
            None => self.refuse(cx),
        }
        Some(())
    }

    fn refuse(&mut self, cx: &mut AppCx) {
        let mut w = Writer::msg(USERAUTH_FAILURE);
        w.str("publickey,password").bool(false);
        self.t.send(w.into_inner(), cx);
    }

    fn pump(&mut self, id: u32, cx: &mut AppCx) {
        let Some(ch) = self.chans.get_mut(&id) else {
            return;
        };
        if ch.ended {
            return;
        }
        ch.flow.drain(&mut ch.out, None, &mut self.t, cx);
        ch.flow.drain(&mut ch.err, Some(1), &mut self.t, cx);
        if let (true, Some(n)) = (ch.out.is_empty() && ch.err.is_empty(), ch.exit) {
            let peer = ch.flow.peer;
            let mut w = Writer::msg(CHANNEL_REQUEST);
            w.u32(peer).str("exit-status").bool(false).u32(n);
            self.t.send(w.into_inner(), cx);
            simple(&mut self.t, CHANNEL_EOF, peer, cx);
            simple(&mut self.t, CHANNEL_CLOSE, peer, cx);
            ch.ended = true;
            let label = if ch.mode == Mode::Shell {
                format!("shell exit {n}")
            } else {
                format!("exit {n}")
            };
            cx.transaction(AppTransaction::new(label, true).with_error(n != 0));
        }
    }

    fn channel_request(&mut self, id: u32, r: &mut Reader, cx: &mut AppCx) -> Option<()> {
        let kind = r.str()?.to_string();
        let want = r.bool()?;
        let cfg = self.cfg.clone();
        let user = self.user.clone().unwrap_or_default();
        let ch = self.chans.get_mut(&id)?;
        let ok = match kind.as_str() {
            "pty-req" => {
                ch.pty = true;
                true
            }
            "env" | "window-change" | "signal" | "eow@openssh.com" => true,
            "exec" if ch.mode == Mode::Idle => {
                let cmd = String::from_utf8_lossy(r.string()?).into_owned();
                ch.mode = Mode::Exec;
                let a = answer(&cfg, &user, &cmd);
                if a.delay.is_zero() {
                    ch.apply(a);
                } else {
                    let at = cx.now() + a.delay;
                    ch.due = Some((at, a));
                    cx.wake_at(at);
                }
                true
            }
            "shell" if ch.mode == Mode::Idle => {
                ch.mode = Mode::Shell;
                ch.prompt();
                true
            }
            _ => false,
        };
        let peer = ch.flow.peer;
        if want {
            simple(
                &mut self.t,
                if ok { CHANNEL_SUCCESS } else { CHANNEL_FAILURE },
                peer,
                cx,
            );
        }
        self.pump(id, cx);
        Some(())
    }

    fn take(&mut self, p: &[u8], cx: &mut AppCx) -> std::result::Result<(), transport::Failure> {
        let malformed = || {
            (
                transport::PROTOCOL_ERROR,
                format!("malformed message {}", p[0]),
            )
        };
        let mut r = Reader::new(&p[1..]);
        match p[0] {
            SERVICE_REQUEST => {
                let name = r.str().ok_or_else(malformed)?;
                if name != USERAUTH {
                    return Err((
                        transport::SERVICE_NOT_AVAILABLE,
                        format!("service `{name}` asked before the login"),
                    ));
                }
                let mut w = Writer::msg(SERVICE_ACCEPT);
                w.str(USERAUTH);
                self.t.send(w.into_inner(), cx);
            }
            USERAUTH_REQUEST => self.login(&mut r, cx).ok_or_else(malformed)?,
            EXT_INFO => {}
            _ if self.user.is_none() => {
                return Err((
                    transport::PROTOCOL_ERROR,
                    format!("message {} before the login", p[0]),
                ))
            }
            GLOBAL_REQUEST => {
                let _name = r.str().ok_or_else(malformed)?;
                if r.bool() == Some(true) {
                    self.t.send(vec![REQUEST_FAILURE], cx);
                }
            }
            CHANNEL_OPEN => {
                let kind = r.str().ok_or_else(malformed)?.to_string();
                let (peer, win, max) = (r.u32(), r.u32(), r.u32());
                let (Some(peer), Some(win), Some(max)) = (peer, win, max) else {
                    return Err(malformed());
                };
                if kind != "session" {
                    let mut w = Writer::msg(CHANNEL_OPEN_FAILURE);
                    w.u32(peer)
                        .u32(3)
                        .str(&format!("`{kind}` channels are not taken"))
                        .str("");
                    self.t.send(w.into_inner(), cx);
                    return Ok(());
                }
                let id = self.next_id;
                self.next_id += 1;
                let full = 2 * 1024 * 1024;
                self.chans
                    .insert(id, ServerChan::new(Flow::new(peer, win, max, full)));
                let mut w = Writer::msg(CHANNEL_OPEN_CONFIRMATION);
                w.u32(peer).u32(id).u32(full).u32(MAX_DATA);
                self.t.send(w.into_inner(), cx);
            }
            CHANNEL_WINDOW_ADJUST..=CHANNEL_FAILURE => {
                let id = r.u32().ok_or_else(malformed)?;
                if !self.chans.contains_key(&id) {
                    return Ok(());
                }
                match p[0] {
                    CHANNEL_REQUEST => {
                        self.channel_request(id, &mut r, cx).ok_or_else(malformed)?
                    }
                    CHANNEL_CLOSE => {
                        let ch = self.chans.remove(&id).unwrap();
                        if !ch.ended {
                            simple(&mut self.t, CHANNEL_CLOSE, ch.flow.peer, cx);
                        }
                    }
                    kind => {
                        let cfg = self.cfg.clone();
                        let user = self.user.clone().unwrap_or_default();
                        let ch = self.chans.get_mut(&id).unwrap();
                        match kind {
                            CHANNEL_WINDOW_ADJUST => {
                                ch.flow.peer_window += u64::from(r.u32().ok_or_else(malformed)?);
                            }
                            CHANNEL_DATA | CHANNEL_EXTENDED_DATA => {
                                if kind == CHANNEL_EXTENDED_DATA {
                                    r.u32().ok_or_else(malformed)?;
                                }
                                let data = r.string().ok_or_else(malformed)?;
                                ch.flow.received(data.len(), &mut self.t, cx);
                                match (ch.mode, kind) {
                                    (Mode::Shell, CHANNEL_DATA) => {
                                        ch.shell_input(data, &cfg, &user)
                                    }
                                    (Mode::Exec, CHANNEL_DATA) if ch.sink == Sink::Echo => {
                                        ch.out.push(Input::Bytes(data.into()))
                                    }
                                    _ => {}
                                }
                            }
                            CHANNEL_EOF => {
                                ch.peer_eof = true;
                                if ch.mode == Mode::Shell {
                                    ch.exit.get_or_insert(0);
                                } else if let Some(n) = ch.at_eof.take() {
                                    ch.exit = Some(n);
                                }
                            }
                            _ => {}
                        }
                        self.pump(id, cx);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn events(&mut self, events: Vec<Event>, cx: &mut AppCx) {
        for e in events {
            if self.done {
                return;
            }
            match e {
                Event::KexDone { first: true } => {
                    self.kexed = true;
                    cx.handshake(AppHandshake {
                        label: self.t.negotiated.clone(),
                        succeeded: true,
                        expected: true,
                        resumed: false,
                        time: Some(cx.now().saturating_sub(self.start)),
                    });
                }
                Event::KexDone { first: false } => {
                    cx.transaction(AppTransaction::new("rekey", true));
                }
                Event::Disconnect(code, text) => {
                    cx.goodbye();
                    if code != transport::BY_APPLICATION && code != transport::NO_MORE_AUTH_METHODS
                    {
                        cx.protocol_error(format!("the client disconnected ({code}): {text}"));
                    }
                    self.done = true;
                    cx.close();
                }
                Event::Packet(p) => {
                    if let Err(f) = self.take(&p, cx) {
                        self.fail(cx, f);
                    }
                }
            }
        }
    }
}

impl AppSession for ServerSession {
    fn start(&mut self, cx: &mut AppCx) {
        self.start = cx.now();
        self.t.start(cx);
    }

    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        if self.done {
            return Receive::Taken;
        }
        match self.t.feed(data, cx) {
            Ok(events) => self.events(events, cx),
            Err(f) => self.fail(cx, f),
        }
        Receive::Taken
    }

    fn peer_closed(&mut self, cx: &mut AppCx) {
        self.done = true;
        cx.close();
    }

    fn timer(&mut self, cx: &mut AppCx) {
        let now = cx.now();
        let mut next: Option<Duration> = None;
        let ids: Vec<u32> = self.chans.keys().copied().collect();
        for id in ids {
            let ch = self.chans.get_mut(&id).unwrap();
            match ch.due.as_ref().map(|d| d.0) {
                Some(at) if at <= now => {
                    let (_, a) = ch.due.take().unwrap();
                    ch.apply(a);
                    self.pump(id, cx);
                }
                Some(at) => next = Some(next.map_or(at, |n| n.min(at))),
                None => {}
            }
        }
        if let Some(at) = next {
            cx.wake_at(at);
        }
    }
}

#[cfg(feature = "profile")]
mod raw {
    use std::collections::BTreeMap;

    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(untagged)]
    pub enum Size {
        N(u64),
        S(String),
    }

    impl Size {
        pub fn bytes(&self) -> crate::Result<u64> {
            match self {
                Size::N(n) => Ok(*n),
                Size::S(s) => crate::parse_size(s),
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    pub enum Keys {
        File(String),
        Lines(Vec<String>),
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Ssh {
        pub user: Option<String>,
        pub password: Option<String>,
        pub key: Option<String>,
        #[serde(default)]
        pub commands: Vec<String>,
        #[serde(default)]
        pub command: Vec<Command>,
        pub per_connection: Option<u32>,
        pub fingerprint: Option<String>,
        pub expect: Option<String>,
        pub rekey_after: Option<Size>,
        pub window: Option<Size>,
        pub ciphers: Option<Vec<String>>,
        pub version: Option<String>,
        #[serde(default)]
        pub users: BTreeMap<String, String>,
        pub authorized_keys: Option<Keys>,
        pub host_key: Option<String>,
        pub banner: Option<String>,
        #[serde(default)]
        pub route: Vec<Route>,
        pub max_auth_tries: Option<u32>,
        pub hostname: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Command {
        pub run: String,
        pub input: Option<String>,
        pub input_size: Option<Size>,
        pub exit: Option<u32>,
        pub output_size: Option<Size>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Route {
        pub command: String,
        pub output: Option<String>,
        pub output_size: Option<Size>,
        pub stderr: Option<String>,
        pub exit: Option<u32>,
        pub delay: Option<String>,
    }
}

/// Reads an `[ssh]` table; key files are found from `base_dir`.
#[cfg(feature = "profile")]
pub fn parse(t: &toml::Table, base_dir: &std::path::Path) -> Result<Ssh> {
    let r: raw::Ssh = super::registry::table_into(t)?;
    let read = |what: &str, path: &str| -> Result<String> {
        let p = base_dir.join(path);
        std::fs::read_to_string(&p)
            .map_err(|e| Error::Profile(format!("{what} {}: {e}", p.display())))
    };
    let mut ssh = Ssh::default();
    let c = &mut ssh.client;
    if let Some(u) = r.user {
        c.user = u;
    }
    c.key = match r.key.as_deref() {
        None => None,
        Some("generate") => Some(SshKey::generate()),
        Some(path) => Some(SshKey::from_openssh(&read("key", path)?)?),
    };
    c.password = match r.password {
        Some(p) => Some(p),
        None if c.key.is_some() => None,
        None => c.password.take(),
    };
    let mut commands: Vec<SshCommand> = r.commands.into_iter().map(SshCommand::new).collect();
    for x in r.command {
        let mut cmd = SshCommand::new(x.run);
        cmd.input = match (x.input, x.input_size) {
            (Some(i), None) => Input::Bytes(i.into_bytes().into()),
            (None, Some(n)) => Input::Filler(n.bytes()?),
            (None, None) => cmd.input,
            _ => {
                return Err(Error::Profile(
                    "give a command `input` or `input_size`, not both".into(),
                ))
            }
        };
        cmd.exit = x.exit.unwrap_or(0);
        cmd.output_size = x.output_size.map(|s| s.bytes()).transpose()?;
        commands.push(cmd);
    }
    if !commands.is_empty() {
        c.commands = commands;
    }
    c.per_connection = r.per_connection.unwrap_or(c.commands.len() as u32);
    c.fingerprint = r.fingerprint;
    c.expect = r.expect.map(|e| e.to_ascii_lowercase());
    c.rekey_after = r.rekey_after.map(|s| s.bytes()).transpose()?;
    if let Some(w) = r.window {
        c.window = u32::try_from(w.bytes()?)
            .map_err(|_| Error::Profile("SSH: window is at most 4G - 1".into()))?;
    }
    if let Some(cs) = r.ciphers {
        ssh.ciphers = cs;
    }
    if let Some(v) = r.version {
        ssh.version = v.strip_prefix("SSH-2.0-").unwrap_or(&v).to_string();
        if ssh.version.is_empty() || ssh.version.contains([' ', '\r', '\n']) {
            return Err(Error::Profile(
                "SSH: version is one word, e.g. OpenSSH_9.6".into(),
            ));
        }
    }
    let s = &mut ssh.server;
    s.users = r.users;
    s.authorized_keys = match r.authorized_keys {
        None => Vec::new(),
        Some(raw::Keys::Lines(l)) => l
            .iter()
            .map(|l| parse_public_line(l))
            .collect::<Result<_>>()?,
        Some(raw::Keys::File(path)) => read("authorized_keys", &path)?
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(parse_public_line)
            .collect::<Result<_>>()?,
    };
    if let Some(path) = r.host_key.as_deref().filter(|p| *p != "generate") {
        s.host_key = SshKey::from_openssh(&read("host_key", path)?)?;
    }
    s.banner = r.banner;
    if let Some(n) = r.max_auth_tries {
        s.max_auth_tries = n.max(1);
    }
    if let Some(h) = r.hostname {
        s.hostname = h;
    }
    for x in r.route {
        let mut route = SshRoute::new(x.command, Vec::new());
        route.output = match (x.output, x.output_size) {
            (Some(o), None) => Input::Bytes(o.into_bytes().into()),
            (None, Some(n)) => Input::Filler(n.bytes()?),
            (None, None) => route.output,
            _ => {
                return Err(Error::Profile(
                    "give a route `output` or `output_size`, not both".into(),
                ))
            }
        };
        route.stderr = x.stderr.unwrap_or_default().into_bytes().into();
        route.exit = x.exit.unwrap_or(0);
        if let Some(d) = x.delay {
            route.delay = crate::parse_duration(&d)?;
        }
        s.routes.push(route);
    }
    ssh.validate(AppRole::Client, Carrier::Stream)?;
    ssh.validate(AppRole::Server, Carrier::Stream)?;
    Ok(ssh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn init(role: AppRole, index: u64) -> SessionInit {
        let a: SocketAddr = "10.0.0.1:40000".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:22".parse().unwrap();
        SessionInit {
            role,
            transport: Carrier::Stream,
            index,
            seed: 1,
            local: a,
            remote: b,
        }
    }

    /// Plays a client and a server session, handing bytes over in pieces
    /// of `piece` bytes and firing timers, until both are quiet; then
    /// tells each the other closed.
    fn play(s: &Ssh, index: u64, piece: usize) -> (AppCx, AppCx) {
        let app = super::super::App::new(s.clone());
        let mut c = app.session(&init(AppRole::Client, index));
        let mut sv = app.session(&init(AppRole::Server, index));
        let (mut cc, mut sc) = (AppCx::default(), AppCx::default());
        let mut now = Duration::ZERO;
        let mut x = AppCx::new(now, now);
        c.start(&mut x);
        let mut to_s = x.take_sends().concat();
        let (mut c_closed, mut s_closed) = (x.wants_close(), false);
        cc.absorb(x);
        let mut x = AppCx::new(now, now);
        sv.start(&mut x);
        let mut to_c = x.take_sends().concat();
        sc.absorb(x);
        let mut s_wake: Option<Duration> = None;
        for _ in 0..10_000_000 {
            if to_s.is_empty() && to_c.is_empty() {
                match s_wake.take() {
                    Some(w) => {
                        now = now.max(w);
                        let mut y = AppCx::new(now, now);
                        sv.timer(&mut y);
                        to_c.extend(y.take_sends().concat());
                        s_wake = y.wake();
                        sc.absorb(y);
                        continue;
                    }
                    None => break,
                }
            }
            for chunk in std::mem::take(&mut to_s).chunks(piece) {
                let mut y = AppCx::new(now, now);
                sv.receive(chunk, &mut y);
                to_c.extend(y.take_sends().concat());
                s_wake = y.wake().or(s_wake);
                s_closed |= y.wants_close();
                sc.absorb(y);
            }
            for chunk in std::mem::take(&mut to_c).chunks(piece) {
                let mut y = AppCx::new(now, now);
                c.receive(chunk, &mut y);
                to_s.extend(y.take_sends().concat());
                c_closed |= y.wants_close();
                cc.absorb(y);
            }
        }
        assert!(c_closed, "the client did not finish");
        let mut y = AppCx::new(now, now);
        if !s_closed {
            sv.peer_closed(&mut y);
            sc.absorb(y);
        }
        let mut y = AppCx::new(now, now);
        c.peer_closed(&mut y);
        cc.absorb(y);
        (cc, sc)
    }

    fn labels(cx: &AppCx) -> Vec<String> {
        cx.transactions().iter().map(|t| t.label.clone()).collect()
    }

    fn cmd(run: &str, exit: u32) -> SshCommand {
        SshCommand {
            exit,
            ..SshCommand::new(run)
        }
    }

    #[test]
    fn logs_in_and_runs_commands() {
        let mut s = Ssh::default();
        s.client.commands = vec![
            cmd("echo hello", 0),
            cmd("false", 1),
            cmd("exit 3", 3),
            cmd("nope", 127),
            SshCommand {
                output_size: Some(300_000),
                ..cmd("head -c 300000 /dev/zero", 0)
            },
            SshCommand {
                input: Input::Filler(100_000),
                output_size: Some(100_000),
                ..cmd("cat", 0)
            },
            SshCommand {
                input: Input::Filler(5_000_000),
                output_size: Some(0),
                ..cmd("cat > /dev/null", 0)
            },
        ];
        s.client.per_connection = 7;
        s.server.users.insert("lab".into(), "lab".into());
        for piece in [1, 9, 1500, 1 << 20] {
            if piece == 1 {
                // Byte by byte is slow: fewer commands.
                let mut t = s.clone();
                t.client.commands.truncate(4);
                t.client.per_connection = 4;
                let (cc, sc) = play(&t, 0, piece);
                assert!(cc.all_ok(), "{:?} {:?}", cc.protocol_errors(), labels(&cc));
                assert_eq!(labels(&cc).len(), 5);
                assert!(sc.all_ok(), "{:?}", sc.protocol_errors());
                continue;
            }
            let (cc, sc) = play(&s, 0, piece);
            assert!(cc.all_ok(), "{:?} {:?}", cc.protocol_errors(), labels(&cc));
            assert!(sc.all_ok(), "{:?}", sc.protocol_errors());
            assert_eq!(
                labels(&cc),
                [
                    "auth password",
                    "exit 0",
                    "exit 1",
                    "exit 3",
                    "exit 127",
                    "exit 0",
                    "exit 0",
                    "exit 0"
                ]
            );
            assert_eq!(labels(&sc), labels(&cc));
            assert!(cc.handshakes()[0].succeeded);
            assert!(cc.handshakes()[0]
                .label
                .starts_with("curve25519-sha256 ssh-ed25519 chacha20"));
            assert!(cc.transactions()[1].response_time.is_some());
        }
    }

    #[test]
    fn keys_passwords_and_refusals() {
        let key = SshKey::generate();
        let mut s = Ssh::default();
        s.client.key = Some(key.clone());
        s.client.password = None;
        s.server.authorized_keys = vec![key.public_blob()];
        let (cc, sc) = play(&s, 0, 4096);
        assert!(cc.all_ok() && sc.all_ok(), "{:?}", cc.protocol_errors());
        assert_eq!(labels(&cc)[0], "auth publickey");
        // An unknown key falls back to the password.
        s.client.key = Some(SshKey::generate());
        s.client.password = Some("pw".into());
        let (cc, sc) = play(&s, 0, 4096);
        assert!(cc.all_ok(), "{:?}", cc.protocol_errors());
        assert_eq!(labels(&cc)[0], "auth password");
        assert_eq!(labels(&sc)[..2], ["auth refused", "auth password"]);
        // A wrong password, expected to fail.
        s.client.key = None;
        s.server.users.insert("lab".into(), "right".into());
        s.client.expect = Some("failure".into());
        let (cc, sc) = play(&s, 0, 4096);
        assert!(cc.all_ok(), "{:?} {:?}", cc.protocol_errors(), labels(&cc));
        assert_eq!(labels(&cc), ["auth refused"]);
        assert_eq!(labels(&sc), ["auth refused"]);
        // Not expected to fail.
        s.client.expect = None;
        let (cc, _) = play(&s, 0, 4096);
        assert!(!cc.all_ok());
        // Expected to fail, but it works.
        s.client.password = Some("right".into());
        s.client.expect = Some("failure".into());
        let (cc, _) = play(&s, 0, 4096);
        assert!(!cc.all_ok());
        // The host key fingerprint.
        s.client.expect = None;
        s.client.fingerprint = Some(s.server.host_key.fingerprint());
        assert!(play(&s, 0, 4096).0.all_ok());
        s.client.fingerprint = Some("SHA256:other".into());
        let (cc, _) = play(&s, 0, 4096);
        assert!(!cc.handshakes()[0].succeeded);
        assert!(!cc.all_ok());
    }

    #[test]
    fn routes_delays_ciphers_and_rekeys() {
        let mut s = Ssh::default();
        let mut slow = SshRoute::new("uptime", "up 3 days\n");
        slow.delay = Duration::from_millis(30);
        let mut big = SshRoute::new("backup *", "");
        big.output = Input::Filler(3_000_000);
        big.stderr = Arc::from(&b"warning\n"[..]);
        big.exit = 2;
        s.server.routes = vec![slow, big];
        s.client.commands = vec![
            SshCommand {
                output_size: Some(10),
                ..cmd("uptime", 0)
            },
            SshCommand {
                output_size: Some(3_000_000),
                ..cmd("backup /home", 2)
            },
        ];
        s.client.per_connection = 6;
        s.client.rekey_after = Some(1_000_000);
        for c in CIPHERS {
            s.ciphers = vec![c.to_string()];
            let (cc, sc) = play(&s, 0, 64 * 1024);
            assert!(
                cc.all_ok(),
                "{c}: {:?} {:?}",
                cc.protocol_errors(),
                labels(&cc)
            );
            assert!(sc.all_ok(), "{:?}", sc.protocol_errors());
            let l = labels(&cc);
            assert!(l.iter().filter(|x| *x == "rekey").count() >= 3, "{l:?}");
            assert_eq!(l.iter().filter(|x| *x == "exit 2").count(), 3);
            let up = cc
                .transactions()
                .iter()
                .find(|t| t.label == "exit 0")
                .unwrap();
            assert!(up.response_time.unwrap() >= Duration::from_millis(30));
            assert!(cc.handshakes()[0].label.ends_with(*c));
        }
    }

    /// Plays raw client bytes into a server session; returns its output.
    fn server_out(
        sv: &mut Box<dyn AppSession>,
        t: &mut Transport,
        p: Vec<u8>,
        sc: &mut AppCx,
    ) -> Vec<Vec<u8>> {
        let mut x = AppCx::default();
        t.send(p, &mut x);
        let mut y = AppCx::default();
        sv.receive(&x.take_sends().concat(), &mut y);
        let out = y.take_sends().concat();
        sc.absorb(y);
        let mut z = AppCx::default();
        t.feed(&out, &mut z)
            .unwrap()
            .into_iter()
            .filter_map(|e| match e {
                Event::Packet(p) => Some(p),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_shell_with_a_pty() {
        let s = Ssh::default();
        let app = super::super::App::new(s.clone());
        let mut sv = app.session(&init(AppRole::Server, 0));
        let mut t = Transport::new(false, "SSH-2.0-test", &s.ciphers, None, None);
        let mut sc = AppCx::default();
        let (mut x, mut y) = (AppCx::default(), AppCx::default());
        t.start(&mut x);
        sv.start(&mut y);
        let mut to_s = x.take_sends().concat();
        let mut to_c = y.take_sends().concat();
        while !(to_s.is_empty() && to_c.is_empty()) {
            let mut y = AppCx::default();
            sv.receive(&std::mem::take(&mut to_s), &mut y);
            to_c.extend(y.take_sends().concat());
            let mut x = AppCx::default();
            t.feed(&std::mem::take(&mut to_c), &mut x).unwrap();
            to_s.extend(x.take_sends().concat());
        }
        let msg = |f: &dyn Fn(&mut Writer)| {
            let mut w = Writer::new();
            f(&mut w);
            w.into_inner()
        };
        let p = msg(&|w| {
            w.byte(SERVICE_REQUEST).str(USERAUTH);
        });
        assert_eq!(
            server_out(&mut sv, &mut t, p, &mut sc)[0][0],
            SERVICE_ACCEPT
        );
        // A channel before the login is refused.
        let open = msg(&|w| {
            w.byte(CHANNEL_OPEN)
                .str("session")
                .u32(7)
                .u32(1 << 20)
                .u32(MAX_DATA);
        });
        let p = msg(&|w| {
            w.byte(USERAUTH_REQUEST)
                .str("lab")
                .str(CONNECTION)
                .str("password")
                .bool(false)
                .str("x");
        });
        assert_eq!(
            server_out(&mut sv, &mut t, p, &mut sc)[0],
            [USERAUTH_SUCCESS]
        );
        let r = server_out(&mut sv, &mut t, open, &mut sc);
        assert_eq!(r[0][0], CHANNEL_OPEN_CONFIRMATION);
        let p = msg(&|w| {
            w.byte(CHANNEL_REQUEST)
                .u32(0)
                .str("pty-req")
                .bool(true)
                .str("xterm")
                .u32(80)
                .u32(24)
                .u32(0)
                .u32(0)
                .str("");
        });
        assert_eq!(
            server_out(&mut sv, &mut t, p, &mut sc)[0],
            [CHANNEL_SUCCESS, 0, 0, 0, 7]
        );
        let p = msg(&|w| {
            w.byte(CHANNEL_REQUEST).u32(0).str("shell").bool(true);
        });
        let r = server_out(&mut sv, &mut t, p, &mut sc);
        assert_eq!(r[0][0], CHANNEL_SUCCESS);
        let data = |r: &[Vec<u8>]| -> Vec<u8> {
            r.iter()
                .filter(|p| p[0] == CHANNEL_DATA || p[0] == CHANNEL_EXTENDED_DATA)
                .flat_map(|p| {
                    let mut rd = Reader::new(&p[5..]);
                    if p[0] == CHANNEL_EXTENDED_DATA {
                        rd.u32();
                    }
                    rd.string().unwrap().to_vec()
                })
                .collect()
        };
        assert_eq!(data(&r), b"$ ");
        let typed = |s: &[u8]| {
            let s = s.to_vec();
            msg(&move |w| {
                w.byte(CHANNEL_DATA).u32(0).string(&s);
            })
        };
        let r = server_out(&mut sv, &mut t, typed(b"echo hix\x7f\r"), &mut sc);
        assert_eq!(data(&r), b"echo hix\x08 \x08\r\nhi\r\n$ ");
        let r = server_out(&mut sv, &mut t, typed(b"whoami\rexit 4\r"), &mut sc);
        assert_eq!(data(&r), b"whoami\r\nlab\r\n$ exit 4\r\n");
        let kinds: Vec<u8> = r.iter().map(|p| p[0]).collect();
        assert!(kinds.ends_with(&[CHANNEL_REQUEST, CHANNEL_EOF, CHANNEL_CLOSE]));
        assert_eq!(labels(&sc), ["auth password", "shell exit 4"]);
    }

    #[cfg(feature = "profile")]
    #[test]
    fn reads_profiles() {
        let dir = std::env::temp_dir().join(format!("ferotrx-ssh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let k = SshKey::generate();
        std::fs::write(
            dir.join("keys"),
            format!("# lab\n{} lab@x\n", k.public_line()),
        )
        .unwrap();
        let t: toml::Table = r#"
            user = "root"
            password = "pw"
            commands = ["uptime", "echo hi"]
            per_connection = 4
            rekey_after = "1M"
            ciphers = ["aes128-gcm@openssh.com"]
            version = "OpenSSH_9.6"
            users = { root = "pw" }
            authorized_keys = "keys"
            banner = "lab only"
            [[command]]
            run = "cat"
            input_size = "64K"
            output_size = "64K"
            [[route]]
            command = "uptime"
            output = "up\n"
            delay = "5ms"
        "#
        .parse()
        .unwrap();
        let s = parse(&t, &dir).unwrap();
        assert_eq!(s.client.commands.len(), 3);
        assert_eq!(s.client.commands[2].input, Input::Filler(65536));
        assert_eq!(s.client.per_connection, 4);
        assert_eq!(s.client.rekey_after, Some(1 << 20));
        assert_eq!(s.line(), "SSH-2.0-OpenSSH_9.6");
        assert_eq!(s.server.authorized_keys, [k.public_blob()]);
        assert_eq!(s.server.routes[0].delay, Duration::from_millis(5));
        assert!(s
            .describe()
            .contains("3 command(s), 4 per connection, user root"));
        for bad in [
            r#"ciphers = ["3des-cbc"]"#,
            r#"expect = "maybe""#,
            r#"key = "missing""#,
            r#"authorized_keys = ["ssh-rsa AAAA"]"#,
            r#"bogus = 1"#,
            r#"version = "a b""#,
        ] {
            let t: toml::Table = bad.parse().unwrap();
            assert!(parse(&t, &dir).is_err(), "{bad}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
