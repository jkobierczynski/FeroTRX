//! The SMB client of one connection; see the [module](super) docs.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use super::msg::*;
use super::ntlm::{self, Challenge};
use super::server::chain;
use super::{OpKind, Signing, Smb, SmbOp};
use crate::app::{AppCx, AppHandshake, AppRng, AppSession, AppTransaction, Receive, SessionInit};

const CAP_LARGE_MTU: u32 = 0x04;
const READ_ACCESS: u32 = 0x0012_0089;
const WRITE_ACCESS: u32 = 0x0012_019f;
const DIR_ACCESS: u32 = 0x0010_0081;
const DELETE_ACCESS: u32 = 0x0011_0080;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Negotiate,
    Login1,
    Login2,
    Tree,
    Ops,
    TreeDisconnect,
    Logoff,
    Done,
}

/// What an operation waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Create,
    Io,
    Close,
}

struct Op {
    op: SmbOp,
    path: String,
    phase: Phase,
    started: Duration,
    file: FileId,
    /// The file's size (read) or what to write.
    size: u64,
    /// Bytes asked for or sent so far, and answered.
    next: u64,
    done: u64,
    in_flight: usize,
    entries: usize,
    /// How it ended, if it failed.
    status: u32,
    wrong_data: bool,
}

pub struct Client {
    cfg: Arc<Smb>,
    index: u64,
    rng: AppRng,
    server: String,
    buf: Vec<u8>,
    stage: Stage,
    asked: Duration,
    /// When the stage began (negotiate, login, tree connect, logoff).
    since: Duration,
    connected: Duration,
    last_rx: Duration,
    message_id: u64,
    credits: u64,
    /// Requests in flight: their command, and the offset of a read.
    pending: BTreeMap<u64, (u16, u64)>,
    dialect: u16,
    large_mtu: bool,
    max_read: u32,
    max_write: u32,
    server_requires_signing: bool,
    preauth: [u8; 64],
    session_id: u64,
    exported: [u8; 16],
    key: Option<SigningKey>,
    sign: bool,
    negotiate_msg: Vec<u8>,
    tree_id: u32,
    ops: VecDeque<SmbOp>,
    op: Option<Op>,
    /// What this connection wrote, by path in lower case: their sizes.
    written: BTreeMap<String, u64>,
    login_label: String,
}

impl Client {
    pub fn new(cfg: Arc<Smb>, init: &SessionInit) -> Self {
        let ops = cfg.client.ops.iter().cloned().collect();
        Self {
            index: init.index,
            rng: AppRng::new(init.seed ^ 0x534d_4243),
            server: init.remote.ip().to_string(),
            cfg,
            buf: Vec::new(),
            stage: Stage::Negotiate,
            asked: Duration::ZERO,
            since: Duration::ZERO,
            connected: Duration::ZERO,
            last_rx: Duration::ZERO,
            message_id: 0,
            credits: 1,
            pending: BTreeMap::new(),
            dialect: 0,
            large_mtu: false,
            max_read: 65536,
            max_write: 65536,
            server_requires_signing: false,
            preauth: [0; 64],
            session_id: 0,
            exported: [0; 16],
            key: None,
            sign: false,
            negotiate_msg: Vec::new(),
            tree_id: 0,
            ops,
            op: None,
            written: BTreeMap::new(),
            login_label: String::new(),
        }
    }

    fn charge(&self, len: usize) -> u16 {
        if self.large_mtu && self.dialect >= SMB210 {
            len.div_ceil(65536).max(1) as u16
        } else {
            1
        }
    }

    /// Sends one request: the message bytes it sent.
    fn send(&mut self, cx: &mut AppCx, command: u16, body: Vec<u8>, charge: u16) -> Vec<u8> {
        let h = Header {
            credit_charge: if self.dialect == SMB202 || self.dialect == 0 {
                0
            } else {
                charge
            },
            command,
            credits: 256,
            message_id: self.message_id,
            tree_id: self.tree_id,
            session_id: self.session_id,
            ..Header::default()
        };
        self.pending.insert(self.message_id, (command, 0));
        self.message_id += u64::from(charge.max(1));
        self.credits = self.credits.saturating_sub(u64::from(charge.max(1)));
        let mut m = message(&h, &body);
        // 3.1.1 signs every tree connect of a session with a key.
        let must = command == TREE_CONNECT && self.dialect == SMB311;
        if (self.sign || must) && command != NEGOTIATE && command != SESSION_SETUP {
            if let Some(k) = &self.key {
                sign(&mut m, k);
            }
        }
        cx.send(frame(&m));
        self.asked = cx.now();
        self.wake(cx);
        m
    }

    fn wake(&self, cx: &mut AppCx) {
        if self.stage != Stage::Done {
            cx.wake_at(self.asked.max(self.last_rx) + self.cfg.client.wait);
        }
    }

    fn record(&self, cx: &mut AppCx, label: String, ok: bool, error: bool, since: Duration) {
        cx.transaction(
            AppTransaction::new(label, ok)
                .with_error(error)
                .with_response_time(cx.now().saturating_sub(since)),
        );
    }

    fn finish(&mut self, cx: &mut AppCx) {
        self.stage = Stage::Done;
        cx.close();
    }

    // ---- the steps --------------------------------------------------------

    fn negotiate(&mut self, cx: &mut AppCx) {
        let c = &self.cfg.client;
        let dialects = c.dialects.clone();
        let mut guid = [0u8; 16];
        self.rng.fill(&mut guid);
        let mut w = W::default();
        let security = 1 | if c.signing == Signing::Required { 2 } else { 0 };
        let caps = if dialects.iter().any(|d| *d >= SMB210) {
            CAP_LARGE_MTU
        } else {
            0
        };
        w.u16(36)
            .u16(dialects.len() as u16)
            .u16(security)
            .u16(0)
            .u32(caps)
            .bytes(&guid);
        let ctx_at = w.0.len();
        w.u32(0).u16(0).u16(0);
        for d in &dialects {
            w.u16(*d);
        }
        if dialects.contains(&SMB311) {
            w.align(8);
            let off = w.offset() as u32;
            w.set_u32(ctx_at, off);
            w.set_u16(ctx_at + 4, 1);
            let mut salt = [0u8; 32];
            self.rng.fill(&mut salt);
            w.u16(1).u16(38).u32(0).u16(1).u16(32).u16(1).bytes(&salt);
        }
        self.since = cx.now();
        let m = self.send(cx, NEGOTIATE, w.0, 1);
        self.preauth = chain(&[0; 64], &m);
        self.stage = Stage::Negotiate;
    }

    fn setup(&mut self, cx: &mut AppCx, token: Vec<u8>) {
        let mut w = W::default();
        let security = 1 | if self.cfg.client.signing == Signing::Required {
            2
        } else {
            0
        };
        w.u16(25)
            .u8(0)
            .u8(security)
            .u32(0)
            .u32(0)
            .u16(0x58)
            .u16(token.len() as u16)
            .u64(0)
            .bytes(&token);
        let m = self.send(cx, SESSION_SETUP, w.0, 1);
        if self.dialect == SMB311 {
            self.preauth = chain(&self.preauth, &m);
        }
    }

    fn tree_connect(&mut self, cx: &mut AppCx) {
        let path = ntlm::utf16(&format!("\\\\{}\\{}", self.server, self.cfg.client.share));
        let mut w = W::default();
        w.u16(9)
            .u16(0)
            .u16(0x48)
            .u16(path.len() as u16)
            .bytes(&path);
        self.stage = Stage::Tree;
        self.since = cx.now();
        self.send(cx, TREE_CONNECT, w.0, 1);
    }

    fn create(&mut self, cx: &mut AppCx, path: &str, access: u32, disposition: u32, options: u32) {
        let name = ntlm::utf16(path);
        let mut w = W::default();
        w.u16(57)
            .u8(0)
            .u8(0)
            .u32(2)
            .u64(0)
            .u64(0)
            .u32(access)
            .u32(0)
            .u32(7)
            .u32(disposition)
            .u32(options)
            .u16(0x78)
            .u16(name.len() as u16)
            .u32(0)
            .u32(0);
        if name.is_empty() {
            w.u8(0);
        } else {
            w.bytes(&name);
        }
        self.send(cx, CREATE, w.0, 1);
    }

    fn close_file(&mut self, cx: &mut AppCx, f: FileId) {
        let mut w = W::default();
        w.u16(24).u16(0).u32(0).bytes(&f);
        self.send(cx, CLOSE, w.0, 1);
    }

    /// Starts the next operation, or ends the connection after the last.
    fn next_op(&mut self, cx: &mut AppCx) {
        let Some(op) = self.ops.pop_front() else {
            self.stage = Stage::TreeDisconnect;
            self.send(cx, TREE_DISCONNECT, vec![4, 0, 0, 0], 1);
            return;
        };
        self.stage = Stage::Ops;
        let path = op.path.replace("{n}", &self.index.to_string());
        let size = match op.kind {
            OpKind::Write(n) => n,
            _ => 0,
        };
        let (access, disposition, options) = match op.kind {
            OpKind::Write(_) => (WRITE_ACCESS, 5, 0x40),
            OpKind::Read => (READ_ACCESS, 1, 0x40),
            OpKind::List => (DIR_ACCESS, 1, 0x01),
            OpKind::Delete => (DELETE_ACCESS, 1, 0x1040),
            OpKind::Mkdir => (DIR_ACCESS, 2, 0x01),
            OpKind::Rmdir => (DELETE_ACCESS, 1, 0x1001),
        };
        self.op = Some(Op {
            op,
            path: path.clone(),
            phase: Phase::Create,
            started: cx.now(),
            file: [0; 16],
            size,
            next: 0,
            done: 0,
            in_flight: 0,
            entries: 0,
            status: STATUS_SUCCESS,
            wrong_data: false,
        });
        self.create(cx, &path, access, disposition, options);
    }

    /// Sends the reads, writes or directory queries the window allows.
    fn pump(&mut self, cx: &mut AppCx) {
        let window = self.cfg.client.window;
        loop {
            let Some(op) = self.op.as_ref() else { return };
            if op.phase != Phase::Io {
                return;
            }
            match op.op.kind {
                OpKind::Write(_) | OpKind::Read => {
                    if op.next >= op.size || op.in_flight >= window {
                        break;
                    }
                    let write = matches!(op.op.kind, OpKind::Write(_));
                    let limit = if write { self.max_write } else { self.max_read };
                    let chunk =
                        u64::from(self.cfg.client.chunk.min(limit)).min(op.size - op.next) as usize;
                    let charge = self.charge(chunk);
                    if self.credits < u64::from(charge) && op.in_flight > 0 {
                        break;
                    }
                    let (file, offset, path) = (op.file, op.next, op.path.clone());
                    let mut w = W::default();
                    if write {
                        w.u16(49)
                            .u16(0x70)
                            .u32(chunk as u32)
                            .u64(offset)
                            .bytes(&file)
                            .u32(0)
                            .u32(0)
                            .u16(0)
                            .u16(0)
                            .u32(0)
                            .bytes(&Smb::content(&path, offset, chunk));
                        self.send(cx, WRITE, w.0, charge);
                    } else {
                        let id = self.message_id;
                        w.u16(49)
                            .u8(0x50)
                            .u8(0)
                            .u32(chunk as u32)
                            .u64(offset)
                            .bytes(&file)
                            .u32(0)
                            .u32(0)
                            .u32(0)
                            .u16(0)
                            .u16(0)
                            .u8(0);
                        self.send(cx, READ, w.0, charge);
                        if let Some(p) = self.pending.get_mut(&id) {
                            p.1 = offset;
                        }
                    }
                    let op = self.op.as_mut().unwrap();
                    op.next += chunk as u64;
                    op.in_flight += 1;
                }
                OpKind::List => {
                    if op.in_flight > 0 {
                        break;
                    }
                    let restart = op.next == 0;
                    let file = op.file;
                    let pattern = ntlm::utf16("*");
                    let mut w = W::default();
                    w.u16(33)
                        .u8(37)
                        .u8(if restart { 1 } else { 0 })
                        .u32(0)
                        .bytes(&file)
                        .u16(0x60)
                        .u16(pattern.len() as u16)
                        .u32(65536)
                        .bytes(&pattern);
                    self.send(cx, QUERY_DIRECTORY, w.0, 1);
                    let op = self.op.as_mut().unwrap();
                    op.next += 1;
                    op.in_flight += 1;
                }
                _ => break,
            }
        }
        let op = self.op.as_mut().unwrap();
        if op.in_flight == 0 && op.next >= op.size && op.op.kind != OpKind::List {
            op.phase = Phase::Close;
            let f = op.file;
            self.close_file(cx, f);
        }
    }

    /// The operation is over: its transaction, and the next one.
    fn end_op(&mut self, cx: &mut AppCx) {
        let Some(op) = self.op.take() else { return };
        let name = op.op.kind.name();
        let ok_status = op.status == op.op.expect.unwrap_or(STATUS_SUCCESS);
        let label = if op.wrong_data {
            format!("{name} wrong data")
        } else if op.status == STATUS_SUCCESS {
            name.to_string()
        } else {
            format!("{name} {}", status_name(op.status))
        };
        let ok = ok_status && !op.wrong_data;
        self.record(
            cx,
            label,
            ok,
            op.status != STATUS_SUCCESS || op.wrong_data,
            op.started,
        );
        if op.status == STATUS_SUCCESS {
            match op.op.kind {
                OpKind::Write(n) => {
                    self.written.insert(op.path.to_lowercase(), n);
                }
                OpKind::Delete => {
                    self.written.remove(&op.path.to_lowercase());
                }
                _ => {}
            }
        }
        self.next_op(cx);
    }

    /// The operation failed with `status`: closes what it opened, if anything.
    fn fail_op(&mut self, cx: &mut AppCx, status: u32) {
        let Some(op) = self.op.as_mut() else { return };
        if op.status == STATUS_SUCCESS {
            op.status = status;
        }
        if op.phase == Phase::Io {
            op.next = op.size; // send no more
            if op.in_flight == 0 {
                op.phase = Phase::Close;
                let f = op.file;
                self.close_file(cx, f);
            }
        } else {
            self.end_op(cx);
        }
    }

    // ---- answers ------------------------------------------------------------

    fn response(&mut self, msg: &[u8], cx: &mut AppCx) {
        let Some(h) = Header::parse(msg) else {
            cx.protocol_error("an answer without an SMB 2 header");
            return self.finish(cx);
        };
        if h.flags & FLAG_ASYNC != 0 && h.status == STATUS_PENDING {
            self.credits += u64::from(h.credits);
            return; // the real answer follows
        }
        let Some((command, read_at)) = self.pending.remove(&h.message_id) else {
            cx.protocol_error(format!(
                "an answer to message {} we did not send",
                h.message_id
            ));
            return;
        };
        self.credits += u64::from(h.credits);
        if command != h.command {
            cx.protocol_error(format!(
                "{} answered with {}",
                command_name(command),
                command_name(h.command)
            ));
        }
        // Signatures: check what is signed, and what has to be.
        if is_signed(msg) {
            let key = if command == SESSION_SETUP && h.status == STATUS_SUCCESS {
                self.final_key()
            } else {
                self.key
            };
            if let Some(k) = key {
                if !verify(msg, &k) {
                    cx.protocol_error(format!("{}: bad signature", command_name(command)));
                }
            }
        } else if self.sign
            && self.key.is_some()
            && command != SESSION_SETUP
            && is_success(h.status)
        {
            cx.protocol_error(format!("{}: answer not signed", command_name(command)));
        }
        let r = R(msg);
        let b = HEADER_LEN;
        match command {
            NEGOTIATE => self.on_negotiate(&h, msg, cx),
            SESSION_SETUP => self.on_setup(&h, msg, cx),
            TREE_CONNECT => {
                if h.status == STATUS_SUCCESS {
                    self.tree_id = h.tree_id;
                    self.record(cx, "tree connect".into(), true, false, self.since);
                    self.next_op(cx);
                } else {
                    self.refused(cx, "tree connect", h.status);
                }
            }
            CREATE => {
                let Some(op) = self.op.as_mut() else { return };
                if h.status != STATUS_SUCCESS {
                    return self.fail_op(cx, h.status);
                }
                op.file = r
                    .bytes(b + 64, 16)
                    .and_then(|f| f.try_into().ok())
                    .unwrap_or([0; 16]);
                match op.op.kind {
                    OpKind::Read => {
                        op.size = r.u64(b + 48).unwrap_or(0);
                        op.phase = Phase::Io;
                    }
                    OpKind::Write(_) | OpKind::List => op.phase = Phase::Io,
                    _ => {
                        op.phase = Phase::Close;
                        let f = op.file;
                        self.close_file(cx, f);
                        return;
                    }
                }
                self.pump(cx);
            }
            READ | WRITE | QUERY_DIRECTORY => {
                let Some(op) = self.op.as_mut() else { return };
                op.in_flight = op.in_flight.saturating_sub(1);
                match (command, h.status) {
                    (READ, STATUS_SUCCESS) => {
                        let off = r.u8(b + 2).unwrap_or(0) as usize;
                        let len = r.u32(b + 4).unwrap_or(0) as usize;
                        let data = r.buffer(off, len).unwrap_or(&[]);
                        let at = read_at;
                        if self.written.contains_key(&op.path.to_lowercase())
                            && data != Smb::content(&op.path, at, data.len()).as_slice()
                        {
                            op.wrong_data = true;
                        }
                        op.done += data.len() as u64;
                        if data.is_empty() {
                            op.next = op.size;
                        }
                    }
                    (READ, STATUS_END_OF_FILE) => op.next = op.size,
                    (WRITE, STATUS_SUCCESS) => {
                        op.done += u64::from(r.u32(b + 4).unwrap_or(0));
                    }
                    (QUERY_DIRECTORY, STATUS_SUCCESS) => {
                        op.entries += count_entries(&r, b);
                    }
                    (QUERY_DIRECTORY, STATUS_NO_MORE_FILES | STATUS_NO_SUCH_FILE) => {
                        op.phase = Phase::Close;
                        let f = op.file;
                        self.close_file(cx, f);
                        return;
                    }
                    (_, s) => return self.fail_op(cx, s),
                }
                let op = self.op.as_mut().unwrap();
                if op.status != STATUS_SUCCESS {
                    if op.in_flight == 0 {
                        op.phase = Phase::Close;
                        let f = op.file;
                        self.close_file(cx, f);
                    }
                    return;
                }
                self.pump(cx);
            }
            CLOSE => {
                if h.status != STATUS_SUCCESS {
                    if let Some(op) = self.op.as_mut() {
                        if op.status == STATUS_SUCCESS {
                            op.status = h.status;
                        }
                    }
                }
                self.end_op(cx);
            }
            TREE_DISCONNECT => {
                self.stage = Stage::Logoff;
                self.since = cx.now();
                self.send(cx, LOGOFF, vec![4, 0, 0, 0], 1);
            }
            LOGOFF => {
                self.record(
                    cx,
                    "logoff".into(),
                    h.status == STATUS_SUCCESS,
                    false,
                    self.since,
                );
                self.finish(cx);
            }
            _ => {}
        }
    }

    fn on_negotiate(&mut self, h: &Header, msg: &[u8], cx: &mut AppCx) {
        let r = R(msg);
        let b = HEADER_LEN;
        if h.status != STATUS_SUCCESS {
            return self.refused(cx, "negotiate", h.status);
        }
        self.dialect = r.u16(b + 4).unwrap_or(0);
        if !self.cfg.client.dialects.contains(&self.dialect) {
            cx.protocol_error(format!(
                "the server chose dialect {}, which was not offered",
                dialect_name(self.dialect)
            ));
            return self.finish(cx);
        }
        if self.dialect == SMB311 {
            self.preauth = chain(&self.preauth, msg);
        }
        let security = r.u16(b + 2).unwrap_or(0);
        self.server_requires_signing = security & 2 != 0;
        let caps = r.u32(b + 24).unwrap_or(0);
        self.large_mtu = caps & CAP_LARGE_MTU != 0;
        let cap = if self.large_mtu { 8 << 20 } else { 65536 };
        self.max_read = r.u32(b + 32).unwrap_or(65536).min(cap);
        self.max_write = r.u32(b + 36).unwrap_or(65536).min(cap);
        let off = r.u16(b + 56).unwrap_or(0) as usize;
        let len = r.u16(b + 58).unwrap_or(0) as usize;
        if let Some(t) = r.buffer(off, len).filter(|t| !t.is_empty()) {
            if !ntlm::parse(t).is_some_and(|t| t.offers_ntlm()) {
                cx.protocol_error("the server does not offer NTLM");
            }
        }
        let name = dialect_name(self.dialect);
        self.record(cx, format!("negotiate {name}"), true, false, self.since);
        self.negotiate_msg = ntlm::negotiate(ntlm::CLIENT_FLAGS);
        self.stage = Stage::Login1;
        self.since = cx.now();
        let t = ntlm::init(Some(&self.negotiate_msg.clone()));
        self.setup(cx, t);
    }

    fn final_key(&self) -> Option<SigningKey> {
        (self.exported != [0; 16])
            .then(|| SigningKey::derive(self.dialect, &self.exported, &self.preauth))
    }

    fn on_setup(&mut self, h: &Header, msg: &[u8], cx: &mut AppCx) {
        let r = R(msg);
        let b = HEADER_LEN;
        let off = r.u16(b + 4).unwrap_or(0) as usize;
        let len = r.u16(b + 6).unwrap_or(0) as usize;
        let token = r.buffer(off, len).and_then(ntlm::parse);
        match (self.stage, h.status) {
            (Stage::Login1, STATUS_MORE_PROCESSING_REQUIRED) => {
                if self.dialect == SMB311 {
                    self.preauth = chain(&self.preauth, msg);
                }
                self.session_id = h.session_id;
                let Some(ch) = token
                    .and_then(|t| t.inner)
                    .and_then(|i| Challenge::parse(&i))
                else {
                    cx.protocol_error("SESSION_SETUP: no NTLM CHALLENGE");
                    return self.finish(cx);
                };
                let c = &self.cfg.client;
                let mut cc = [0u8; 8];
                self.rng.fill(&mut cc);
                let mut rk = [0u8; 16];
                self.rng.fill(&mut rk);
                let (auth, key) = if c.user.is_empty() {
                    let a = ntlm::Authenticate {
                        flags: ntlm::CLIENT_FLAGS & ch.flags & !ntlm::NEGOTIATE_KEY_EXCH
                            | ntlm::NEGOTIATE_UNICODE,
                        lm: vec![0],
                        ..Default::default()
                    };
                    (a, [0u8; 16])
                } else {
                    ntlm::authenticate(
                        &ch,
                        &c.user,
                        &c.password,
                        &c.domain,
                        &c.workstation,
                        cc,
                        ntlm::filetime(cx.wall()),
                        rk,
                    )
                };
                self.exported = key;
                self.stage = Stage::Login2;
                let t = ntlm::resp(None, false, Some(&auth.to_bytes()));
                self.setup(cx, t);
            }
            (Stage::Login2, STATUS_SUCCESS) => {
                let flags = r.u16(b + 2).unwrap_or(0);
                let guest = flags & 3 != 0;
                if flags & 4 != 0 {
                    cx.protocol_error("the server requires encryption, which is not supported");
                    return self.refused(cx, "login", STATUS_ACCESS_DENIED);
                }
                if !guest {
                    self.key = self.final_key();
                }
                let c = &self.cfg.client;
                self.sign = !guest
                    && self.key.is_some()
                    && match c.signing {
                        Signing::Required => true,
                        Signing::Auto => self.server_requires_signing,
                        Signing::Off => false,
                    };
                self.login_label = if flags & 2 != 0 {
                    "login anonymous".into()
                } else if guest {
                    "login guest".into()
                } else {
                    "login".into()
                };
                let ok = c.expect.is_none();
                let label = self.login_label.clone();
                self.record(cx, label, ok, false, self.since);
                let how = if self.sign {
                    match self.key {
                        Some(SigningKey::Cmac(_)) => "signed AES-CMAC",
                        _ => "signed HMAC-SHA256",
                    }
                } else if guest {
                    "guest"
                } else {
                    "unsigned"
                };
                cx.handshake(AppHandshake {
                    label: format!("SMB {} {how}", dialect_name(self.dialect)),
                    succeeded: true,
                    expected: ok,
                    resumed: false,
                    time: Some(cx.now().saturating_sub(self.connected)),
                });
                if !ok {
                    return self.finish(cx);
                }
                self.tree_connect(cx);
            }
            (_, s) => self.refused(cx, "login", s),
        }
    }

    /// The login or tree connect failed: as expected or not, the end.
    fn refused(&mut self, cx: &mut AppCx, what: &str, status: u32) {
        let ok = self.cfg.client.expect == Some(status);
        self.record(
            cx,
            format!("{what} {}", status_name(status)),
            ok,
            true,
            self.since,
        );
        if what == "login" {
            cx.handshake(AppHandshake {
                label: format!("failed: {}", status_name(status)),
                succeeded: false,
                expected: ok,
                resumed: false,
                time: Some(cx.now().saturating_sub(self.connected)),
            });
        }
        self.finish(cx);
    }
}

fn count_entries(r: &R, b: usize) -> usize {
    let off = r.u16(b + 2).unwrap_or(0) as usize;
    let len = r.u32(b + 4).unwrap_or(0) as usize;
    let Some(buf) = r.buffer(off, len) else {
        return 0;
    };
    let e = R(buf);
    let mut at = 0;
    let mut n = 0;
    while at + 104 <= buf.len() {
        let name_len = e.u32(at + 60).unwrap_or(0) as usize;
        let name = e
            .bytes(at + 104, name_len)
            .map(ntlm::from_utf16)
            .unwrap_or_default();
        if name != "." && name != ".." {
            n += 1;
        }
        let next = e.u32(at).unwrap_or(0) as usize;
        if next == 0 {
            break;
        }
        at += next;
    }
    n
}

impl AppSession for Client {
    fn start(&mut self, cx: &mut AppCx) {
        self.asked = cx.now();
        self.connected = cx.now();
        self.negotiate(cx);
    }

    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        self.last_rx = cx.now();
        self.buf.extend_from_slice(data);
        loop {
            if self.stage == Stage::Done {
                self.buf.clear();
                break;
            }
            match deframe(&self.buf) {
                Ok(Some((msg, used))) => {
                    let msg = msg.to_vec();
                    self.buf.drain(..used);
                    for part in split_compound(&msg) {
                        self.response(part, cx);
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    cx.protocol_error(e);
                    self.finish(cx);
                }
            }
        }
        self.wake(cx);
        Receive::Taken
    }

    fn peer_closed(&mut self, cx: &mut AppCx) {
        if self.stage != Stage::Done {
            let what = match self.stage {
                Stage::Negotiate => "negotiate",
                Stage::Login1 | Stage::Login2 => "login",
                Stage::Tree => "tree connect",
                Stage::Ops => self.op.as_ref().map_or("operation", |o| o.op.kind.name()),
                _ => "logoff",
            };
            self.record(cx, format!("{what} closed"), false, true, self.since);
        }
        self.finish(cx);
    }

    fn timer(&mut self, cx: &mut AppCx) {
        if self.stage == Stage::Done {
            return;
        }
        if cx.now() >= self.asked.max(self.last_rx) + self.cfg.client.wait {
            let what = match self.stage {
                Stage::Negotiate => "negotiate",
                Stage::Login1 | Stage::Login2 => "login",
                Stage::Tree => "tree connect",
                Stage::Ops => self.op.as_ref().map_or("operation", |o| o.op.kind.name()),
                _ => "logoff",
            };
            self.record(cx, format!("{what} timeout"), false, true, self.since);
            self.finish(cx);
        } else {
            self.wake(cx);
        }
    }
}
