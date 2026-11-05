//! The SMB server: negotiates, logs users in with NTLMv2 (or as guests),
//! connects trees to its shares, and serves files and directories from the
//! in-memory store: create, read, write, close, flush, directory listings,
//! file and volume information, renames and deletes. It signs what it
//! sends when the client signs, or when it requires signing.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::crypto::sha512;
use super::msg::*;
use super::ntlm::{self, Authenticate, Challenge};
use super::store::{self, Node, Share};
use super::{Smb, Store};
use crate::app::{AppCx, AppRng, AppSession, AppTransaction, Receive};

// Create dispositions and options.
const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;
const FILE_DIRECTORY_FILE: u32 = 0x01;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_DELETE_ON_CLOSE: u32 = 0x1000;

/// Access bits that change something.
const WRITE_ACCESS: u32 = 0x0000_0002 // FILE_WRITE_DATA
    | 0x0000_0004 // FILE_APPEND_DATA
    | 0x0000_0010 // FILE_WRITE_EA
    | 0x0000_0100 // FILE_WRITE_ATTRIBUTES
    | 0x0001_0000 // DELETE
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE

const CAP_LARGE_MTU: u32 = 0x04;

const FSCTL_VALIDATE_NEGOTIATE_INFO: u32 = 0x0014_0204;

struct Sess {
    /// Set while the login waits for the AUTHENTICATE.
    challenge: Option<[u8; 8]>,
    ready: bool,
    user: String,
    key: Option<SigningKey>,
    /// A guest or anonymous session: nothing to sign with.
    guest: bool,
    preauth: [u8; 64],
    trees: BTreeMap<u32, String>,
}

struct Open {
    session: u64,
    tree: u32,
    share: String,
    key: String,
    dir: bool,
    delete_on_close: bool,
    /// A directory listing in progress: the entries and how far it got.
    listing: Option<(Vec<Entry>, usize)>,
}

#[derive(Clone)]
struct Entry {
    name: String,
    node: Node,
}

/// What a request gets.
struct Reply {
    status: u32,
    body: Vec<u8>,
    session_id: u64,
    tree_id: u32,
    /// The file it opened, for related requests after it.
    file: Option<FileId>,
    /// No answer at all (CANCEL).
    none: bool,
}

impl Reply {
    fn ok(body: Vec<u8>) -> Self {
        Self {
            status: STATUS_SUCCESS,
            body,
            session_id: 0,
            tree_id: 0,
            file: None,
            none: false,
        }
    }
    fn err(status: u32) -> Self {
        Self {
            status,
            body: error_body(),
            ..Self::ok(Vec::new())
        }
    }
}

pub struct Server {
    cfg: Arc<Smb>,
    rng: AppRng,
    buf: Vec<u8>,
    dialect: Option<u16>,
    client_guid: [u8; 16],
    client_caps: u32,
    client_security: u16,
    guid: [u8; 16],
    preauth: [u8; 64],
    sessions: BTreeMap<u64, Sess>,
    opens: BTreeMap<u64, Open>,
    next_id: u64,
    failed: bool,
}

fn fid(id: u64) -> FileId {
    let mut f = [0u8; 16];
    f[..8].copy_from_slice(&id.to_le_bytes());
    f[8..].copy_from_slice(&id.to_le_bytes());
    f
}

fn fid_num(f: &FileId) -> u64 {
    u64::from_le_bytes(f[8..].try_into().unwrap())
}

impl Server {
    pub fn new(cfg: Arc<Smb>, seed: u64) -> Self {
        let mut rng = AppRng::new(seed ^ 0x5342_5356);
        let mut guid = [0u8; 16];
        rng.fill(&mut guid);
        Self {
            cfg,
            rng,
            buf: Vec::new(),
            dialect: None,
            client_guid: [0; 16],
            client_caps: 0,
            client_security: 0,
            guid,
            preauth: [0; 64],
            sessions: BTreeMap::new(),
            opens: BTreeMap::new(),
            next_id: 0,
            failed: false,
        }
    }

    fn id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.cfg.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn security_mode(&self) -> u16 {
        1 | if self.cfg.server.require_signing {
            2
        } else {
            0
        }
    }

    /// One message from the client, maybe a compound: the answer to send.
    fn message(&mut self, msg: &[u8], cx: &mut AppCx) -> Option<Vec<u8>> {
        if msg.starts_with(b"\xffSMB") {
            cx.protocol_error("SMB 1 is not supported");
            self.failed = true;
            return None;
        }
        let parts = split_compound(msg);
        let mut replies: Vec<(Vec<u8>, Option<SigningKey>)> = Vec::new();
        let (mut last_session, mut last_tree, mut last_file) = (0u64, 0u32, None::<FileId>);
        let mut last_status = STATUS_SUCCESS;
        for part in parts {
            let Some(mut h) = Header::parse(part) else {
                cx.protocol_error("a message without an SMB 2 header");
                self.failed = true;
                return None;
            };
            let related = h.flags & FLAG_RELATED != 0;
            if related {
                if h.session_id == u64::MAX || h.session_id == 0 {
                    h.session_id = last_session;
                }
                if h.tree_id == u32::MAX || h.tree_id == 0 {
                    h.tree_id = last_tree;
                }
            }
            let signed = is_signed(part);
            // LOGOFF ends the session, but its answer is signed with its key.
            let before = self
                .sessions
                .get(&h.session_id)
                .filter(|s| s.ready)
                .and_then(|s| s.key);
            let mut reply = if related && !is_success(last_status) {
                Reply::err(last_status)
            } else {
                self.checked(&h, part, signed, related.then_some(last_file).flatten(), cx)
            };
            if reply.none {
                continue;
            }
            let session_id = if reply.session_id != 0 {
                reply.session_id
            } else {
                h.session_id
            };
            let tree_id = if reply.tree_id != 0 {
                reply.tree_id
            } else {
                h.tree_id
            };
            last_session = session_id;
            last_tree = tree_id;
            if reply.file.is_some() {
                last_file = reply.file;
            }
            last_status = reply.status;
            self.count(&h, reply.status, cx);
            let rh = Header {
                credit_charge: h.credit_charge,
                status: reply.status,
                command: h.command,
                credits: h.credits.clamp(1, 512),
                flags: FLAG_RESPONSE | (h.flags & FLAG_RELATED),
                message_id: h.message_id,
                tree_id,
                session_id,
                ..Header::default()
            };
            let bytes = message(&rh, &std::mem::take(&mut reply.body));
            // Sign when the client signed, when signing is required, and
            // the end of every login that has a key.
            let key = self.sessions.get(&session_id).and_then(|s| {
                let final_login = h.command == SESSION_SETUP && reply.status == STATUS_SUCCESS;
                let sign = signed || final_login || self.cfg.server.require_signing;
                s.key.filter(|_| sign && s.ready)
            });
            let key = key.or(before
                .filter(|_| h.command == LOGOFF && (signed || self.cfg.server.require_signing)));
            replies.push((bytes, key));
            // The 3.1.1 pre-auth hash covers the login until its last answer.
            if self.dialect == Some(SMB311) {
                if h.command == NEGOTIATE {
                    self.preauth = chain(&self.preauth, &replies.last().unwrap().0);
                }
                if h.command == SESSION_SETUP && reply.status == STATUS_MORE_PROCESSING_REQUIRED {
                    if let Some(s) = self.sessions.get_mut(&session_id) {
                        s.preauth = chain(&s.preauth, &replies.last().unwrap().0);
                    }
                }
            }
        }
        if replies.is_empty() {
            return None;
        }
        let keys: Vec<Option<SigningKey>> = replies.iter().map(|r| r.1).collect();
        let mut joined = join_compound(replies.into_iter().map(|r| r.0).collect());
        for (m, k) in joined.iter_mut().zip(keys) {
            if let Some(k) = k {
                sign(m, &k);
            }
        }
        Some(frame(&joined.concat()))
    }

    fn count(&self, h: &Header, status: u32, cx: &mut AppCx) {
        let normal = matches!(
            status,
            STATUS_SUCCESS
                | STATUS_MORE_PROCESSING_REQUIRED
                | STATUS_END_OF_FILE
                | STATUS_NO_MORE_FILES
                | STATUS_BUFFER_OVERFLOW
        );
        if h.command == SESSION_SETUP && status == STATUS_MORE_PROCESSING_REQUIRED {
            return; // half a login
        }
        let label = if normal {
            command_name(h.command).to_string()
        } else {
            format!("{} {}", command_name(h.command), status_name(status))
        };
        cx.transaction(AppTransaction::new(label, true).with_error(!normal));
    }

    /// Checks the session and signature, then handles the request.
    fn checked(
        &mut self,
        h: &Header,
        msg: &[u8],
        signed: bool,
        last_file: Option<FileId>,
        cx: &mut AppCx,
    ) -> Reply {
        if h.command != NEGOTIATE && self.dialect.is_none() {
            return Reply::err(STATUS_INVALID_PARAMETER);
        }
        if !matches!(h.command, NEGOTIATE | SESSION_SETUP | ECHO | CANCEL) {
            let Some(s) = self.sessions.get(&h.session_id).filter(|s| s.ready) else {
                return Reply::err(STATUS_USER_SESSION_DELETED);
            };
            if signed {
                if let Some(k) = &s.key {
                    if !verify(msg, k) {
                        cx.protocol_error(format!("{}: bad signature", command_name(h.command)));
                        return Reply::err(STATUS_ACCESS_DENIED);
                    }
                }
            } else if s.key.is_some()
                && (self.cfg.server.require_signing
                    || (h.command == TREE_CONNECT && self.dialect == Some(SMB311)))
            {
                // 3.1.1 asks for a signed tree connect whenever it can be.
                return Reply::err(STATUS_ACCESS_DENIED);
            }
            if !matches!(h.command, TREE_CONNECT | LOGOFF) && !s.trees.contains_key(&h.tree_id) {
                return Reply::err(STATUS_NETWORK_NAME_DELETED);
            }
        }
        let r = R(msg);
        let file = |at: usize| -> Option<FileId> {
            let f: FileId = r.bytes(at, 16)?.try_into().ok()?;
            Some(if f == RELATED_FILE { last_file? } else { f })
        };
        match h.command {
            NEGOTIATE => self.negotiate(msg, cx),
            SESSION_SETUP => self.session_setup(h, msg, cx),
            LOGOFF => {
                self.sessions.remove(&h.session_id);
                self.opens.retain(|_, o| o.session != h.session_id);
                Reply::ok(vec![4, 0, 0, 0])
            }
            TREE_CONNECT => self.tree_connect(h, msg),
            TREE_DISCONNECT => {
                if let Some(s) = self.sessions.get_mut(&h.session_id) {
                    s.trees.remove(&h.tree_id);
                }
                let (sid, tid) = (h.session_id, h.tree_id);
                self.opens
                    .retain(|_, o| !(o.session == sid && o.tree == tid));
                Reply::ok(vec![4, 0, 0, 0])
            }
            CREATE => self.create(h, msg, cx),
            CLOSE => match file(HEADER_LEN + 8) {
                Some(f) => self.close(h, &f, r.u16(HEADER_LEN + 2).unwrap_or(0)),
                None => Reply::err(STATUS_INVALID_PARAMETER),
            },
            FLUSH => match file(HEADER_LEN + 8).and_then(|f| self.open_of(h, &f)) {
                Some(_) => Reply::ok(vec![4, 0, 0, 0]),
                None => Reply::err(STATUS_FILE_CLOSED),
            },
            READ => match file(HEADER_LEN + 16) {
                Some(f) => self.read(h, &f, msg),
                None => Reply::err(STATUS_INVALID_PARAMETER),
            },
            WRITE => match file(HEADER_LEN + 16) {
                Some(f) => self.write(h, &f, msg, cx),
                None => Reply::err(STATUS_INVALID_PARAMETER),
            },
            LOCK => Reply::ok(vec![4, 0, 0, 0]),
            IOCTL => self.ioctl(msg),
            CANCEL => Reply {
                none: true,
                ..Reply::ok(Vec::new())
            },
            ECHO => Reply::ok(vec![4, 0, 0, 0]),
            QUERY_DIRECTORY => match file(HEADER_LEN + 8) {
                Some(f) => self.query_directory(h, &f, msg),
                None => Reply::err(STATUS_INVALID_PARAMETER),
            },
            QUERY_INFO => match file(HEADER_LEN + 24) {
                Some(f) => self.query_info(h, &f, msg),
                None => Reply::err(STATUS_INVALID_PARAMETER),
            },
            SET_INFO => match file(HEADER_LEN + 16) {
                Some(f) => self.set_info(h, &f, msg, cx),
                None => Reply::err(STATUS_INVALID_PARAMETER),
            },
            CHANGE_NOTIFY | OPLOCK_BREAK => Reply::err(STATUS_NOT_SUPPORTED),
            _ => Reply::err(STATUS_INVALID_PARAMETER),
        }
    }

    // ---- negotiate and login ---------------------------------------------

    fn negotiate(&mut self, msg: &[u8], cx: &mut AppCx) -> Reply {
        let r = R(msg);
        let b = HEADER_LEN;
        let n = r.u16(b + 2).unwrap_or(0) as usize;
        self.client_security = r.u16(b + 4).unwrap_or(0);
        self.client_caps = r.u32(b + 8).unwrap_or(0);
        if let Some(g) = r.bytes(b + 12, 16) {
            self.client_guid.copy_from_slice(g);
        }
        let offered: Vec<u16> = (0..n).filter_map(|i| r.u16(b + 36 + 2 * i)).collect();
        let Some(dialect) = self
            .cfg
            .server
            .dialects
            .iter()
            .copied()
            .filter(|d| offered.contains(d))
            .max()
        else {
            cx.protocol_error(format!(
                "no common dialect: the client offers {}",
                offered
                    .iter()
                    .map(|d| dialect_name(*d))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            return Reply::err(STATUS_NOT_SUPPORTED);
        };
        self.dialect = Some(dialect);
        if dialect == SMB311 {
            self.preauth = chain(&[0; 64], msg);
        }
        // The client's negotiate contexts (3.1.1): which signing algorithm.
        let mut signing_ctx = false;
        if dialect == SMB311 {
            let off = r.u32(b + 28).unwrap_or(0) as usize;
            let count = r.u16(b + 32).unwrap_or(0);
            let mut at = off;
            for _ in 0..count {
                let (Some(t), Some(len)) = (r.u16(at), r.u16(at + 2)) else {
                    break;
                };
                if t == 8 {
                    signing_ctx = true;
                }
                at = (at + 8 + len as usize).next_multiple_of(8);
            }
        }
        let caps = if dialect >= SMB210 { CAP_LARGE_MTU } else { 0 };
        let max = self.cfg.server.max_io;
        let token = ntlm::init(None);
        let mut w = W::default();
        w.u16(65)
            .u16(self.security_mode())
            .u16(dialect)
            .u16(if dialect == SMB311 {
                1 + u16::from(signing_ctx)
            } else {
                0
            })
            .bytes(&self.guid)
            .u32(caps)
            .u32(max)
            .u32(max)
            .u32(max)
            .u64(ntlm::filetime(cx.wall()))
            .u64(0);
        let sec_at = w.0.len();
        w.u16(0).u16(token.len() as u16).u32(0);
        w.set_u16(sec_at, w.offset() as u16);
        w.bytes(&token);
        if dialect == SMB311 {
            w.align(8);
            let ctx_at = w.offset() as u32;
            w.set_u32(sec_at + 4, ctx_at);
            let mut salt = [0u8; 32];
            self.rng.fill(&mut salt);
            // Pre-auth integrity: SHA-512 and a salt.
            w.u16(1).u16(38).u32(0).u16(1).u16(32).u16(1).bytes(&salt);
            if signing_ctx {
                w.align(8);
                // Signing: AES-CMAC.
                w.u16(8).u16(4).u32(0).u16(1).u16(1);
            }
        }
        Reply::ok(w.0)
    }

    fn session_setup(&mut self, h: &Header, msg: &[u8], cx: &mut AppCx) -> Reply {
        let r = R(msg);
        let b = HEADER_LEN;
        let off = r.u16(b + 12).unwrap_or(0) as usize;
        let len = r.u16(b + 14).unwrap_or(0) as usize;
        let Some(token) = r.buffer(off, len).and_then(ntlm::parse) else {
            cx.protocol_error("SESSION_SETUP: no SPNEGO token");
            return Reply::err(STATUS_INVALID_PARAMETER);
        };
        let inner = token.inner.clone().unwrap_or_default();
        let id = if h.session_id == 0 {
            let id = self.id() | 0x0000_1000_0000_0000;
            self.sessions.insert(
                id,
                Sess {
                    challenge: None,
                    ready: false,
                    user: String::new(),
                    key: None,
                    guest: false,
                    preauth: self.preauth,
                    trees: BTreeMap::new(),
                },
            );
            id
        } else if self.sessions.contains_key(&h.session_id) {
            h.session_id
        } else {
            return Reply::err(STATUS_USER_SESSION_DELETED);
        };
        let dialect = self.dialect.unwrap_or(SMB202);
        if dialect == SMB311 {
            if let Some(s) = self.sessions.get_mut(&id) {
                s.preauth = chain(&s.preauth, msg);
            }
        }
        if let Some(flags) = ntlm::negotiate_flags(&inner) {
            let mut challenge = [0u8; 8];
            self.rng.fill(&mut challenge);
            let srv = &self.cfg.server;
            let ch = Challenge {
                flags: (flags & ntlm::CLIENT_FLAGS)
                    | ntlm::NEGOTIATE_UNICODE
                    | ntlm::NEGOTIATE_NTLM
                    | ntlm::NEGOTIATE_TARGET_INFO
                    | ntlm::TARGET_TYPE_SERVER
                    | ntlm::REQUEST_TARGET,
                challenge,
                target_name: srv.name.clone(),
                target_info: ntlm::target_info(&srv.domain, &srv.name, &srv.dns_domain),
            };
            if let Some(s) = self.sessions.get_mut(&id) {
                s.challenge = Some(challenge);
            }
            let t = ntlm::resp(Some(ntlm::ACCEPT_INCOMPLETE), true, Some(&ch.to_bytes()));
            return Reply {
                status: STATUS_MORE_PROCESSING_REQUIRED,
                session_id: id,
                ..Reply::ok(setup_body(0, &t))
            };
        }
        let Some(a) = Authenticate::parse(&inner) else {
            cx.protocol_error("SESSION_SETUP: neither NTLM NEGOTIATE nor AUTHENTICATE");
            self.sessions.remove(&id);
            return Reply::err(STATUS_INVALID_PARAMETER);
        };
        let Some(challenge) = self.sessions.get(&id).and_then(|s| s.challenge) else {
            return Reply::err(STATUS_INVALID_PARAMETER);
        };
        let srv = &self.cfg.server;
        let password = srv
            .users
            .iter()
            .find(|(u, _)| u.eq_ignore_ascii_case(&a.user))
            .map(|(_, p)| p.clone());
        let (key, guest) = match password {
            Some(p) => match ntlm::verify(&a, &challenge, &p) {
                Some(k) => (Some(k), false),
                None => {
                    self.sessions.remove(&id);
                    return Reply {
                        session_id: id,
                        ..Reply::err(STATUS_LOGON_FAILURE)
                    };
                }
            },
            // Anyone, without a password check, when there are no users;
            // else anonymous or unknown users only as guests, if allowed.
            None if srv.users.is_empty() || srv.guest => (None, true),
            None => {
                self.sessions.remove(&id);
                return Reply {
                    session_id: id,
                    ..Reply::err(STATUS_LOGON_FAILURE)
                };
            }
        };
        let anonymous = a.anonymous();
        let s = self.sessions.get_mut(&id).unwrap();
        s.challenge = None;
        s.ready = true;
        s.user = a.user.clone();
        s.guest = guest;
        s.key = key.map(|k| SigningKey::derive(dialect, &k, &s.preauth));
        let flags = if anonymous {
            2
        } else if guest {
            1
        } else {
            0
        };
        let t = ntlm::resp(Some(ntlm::ACCEPT_COMPLETED), false, None);
        Reply {
            session_id: id,
            ..Reply::ok(setup_body(flags, &t))
        }
    }

    fn tree_connect(&mut self, h: &Header, msg: &[u8]) -> Reply {
        let r = R(msg);
        let off = r.u16(HEADER_LEN + 4).unwrap_or(0) as usize;
        let len = r.u16(HEADER_LEN + 6).unwrap_or(0) as usize;
        let path = ntlm::from_utf16(r.buffer(off, len).unwrap_or(&[]));
        let name = path.rsplit('\\').next().unwrap_or("").to_lowercase();
        let ipc = name == "ipc$";
        if !ipc && !self.store().shares.contains_key(&name) {
            return Reply::err(STATUS_BAD_NETWORK_NAME);
        }
        let tree = self.id() as u32;
        if let Some(s) = self.sessions.get_mut(&h.session_id) {
            s.trees.insert(tree, name.clone());
        }
        let read_only = self.store().shares.get(&name).is_some_and(|s| s.read_only);
        let access: u32 = if ipc || read_only {
            0x0012_0089 // read, read attributes and EAs, synchronize
        } else {
            0x001f_01ff // all
        };
        let mut w = W::default();
        w.u16(16)
            .u8(if ipc { 2 } else { 1 })
            .u8(0)
            .u32(0x0000_0030) // no caching of documents
            .u32(0)
            .u32(access);
        Reply {
            tree_id: tree,
            ..Reply::ok(w.0)
        }
    }

    // ---- files ------------------------------------------------------------

    fn share_of(&self, h: &Header) -> Option<String> {
        self.sessions
            .get(&h.session_id)?
            .trees
            .get(&h.tree_id)
            .cloned()
    }

    fn open_of(&self, h: &Header, f: &FileId) -> Option<&Open> {
        self.opens
            .get(&fid_num(f))
            .filter(|o| o.session == h.session_id)
    }

    fn create(&mut self, h: &Header, msg: &[u8], cx: &mut AppCx) -> Reply {
        let r = R(msg);
        let b = HEADER_LEN;
        let access = r.u32(b + 24).unwrap_or(0);
        let disposition = r.u32(b + 36).unwrap_or(FILE_OPEN);
        let options = r.u32(b + 40).unwrap_or(0);
        let off = r.u16(b + 44).unwrap_or(0) as usize;
        let len = r.u16(b + 46).unwrap_or(0) as usize;
        let name = ntlm::from_utf16(r.buffer(off, len).unwrap_or(&[]));
        let Some(share) = self.share_of(h) else {
            return Reply::err(STATUS_NETWORK_NAME_DELETED);
        };
        if share == "ipc$" {
            return Reply::err(STATUS_NOT_SUPPORTED);
        }
        let key = match store::key(&name) {
            Ok(k) => k,
            Err(e) => return Reply::err(e),
        };
        let now = ntlm::filetime(cx.wall());
        let new_id = self.id();
        let cfg = self.cfg.clone();
        let mut guard = cfg.store.lock().unwrap_or_else(|e| e.into_inner());
        let st = &mut *guard;
        let next_id = &mut st.next_id;
        let Some(sh) = st.shares.get_mut(&share) else {
            return Reply::err(STATUS_NETWORK_NAME_DELETED);
        };
        let wants_write = access & WRITE_ACCESS != 0 || options & FILE_DELETE_ON_CLOSE != 0;
        let want_dir = options & FILE_DIRECTORY_FILE != 0;
        let exists = sh.get(&key).cloned();
        let action;
        match (&exists, disposition) {
            (Some(n), _) if want_dir && !n.dir => return Reply::err(STATUS_NOT_A_DIRECTORY),
            (Some(n), _) if options & FILE_NON_DIRECTORY_FILE != 0 && n.dir => {
                return Reply::err(STATUS_FILE_IS_A_DIRECTORY)
            }
            (Some(_), FILE_CREATE) => return Reply::err(STATUS_OBJECT_NAME_COLLISION),
            (Some(n), FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF) if !n.dir => {
                if sh.read_only {
                    return Reply::err(STATUS_ACCESS_DENIED);
                }
                let n = sh.get_mut(&key).unwrap();
                n.data.clear();
                n.written = now;
                action = if disposition == FILE_SUPERSEDE { 0 } else { 3 };
            }
            (Some(_), _) => {
                if sh.read_only && wants_write {
                    return Reply::err(STATUS_ACCESS_DENIED);
                }
                action = 1;
            }
            (None, FILE_OPEN | FILE_OVERWRITE) => {
                let parent_ok = key
                    .rsplit_once('\\')
                    .is_none_or(|(p, _)| sh.get(p).is_some_and(|n| n.dir));
                return Reply::err(if parent_ok {
                    STATUS_OBJECT_NAME_NOT_FOUND
                } else {
                    STATUS_OBJECT_PATH_NOT_FOUND
                });
            }
            (None, _) => {
                if sh.read_only {
                    return Reply::err(STATUS_ACCESS_DENIED);
                }
                *next_id += 1;
                if let Err(e) = sh.create(&name, want_dir, now, *next_id) {
                    return Reply::err(e);
                }
                action = 2;
            }
        }
        let read_only = sh.read_only;
        let node = sh.get(&key).cloned().unwrap();
        let mut delete_on_close = false;
        if options & FILE_DELETE_ON_CLOSE != 0 {
            if read_only {
                return Reply::err(STATUS_ACCESS_DENIED);
            }
            delete_on_close = true;
        }
        drop(guard);
        self.opens.insert(
            new_id,
            Open {
                session: h.session_id,
                tree: h.tree_id,
                share,
                key,
                dir: node.dir,
                delete_on_close,
                listing: None,
            },
        );
        let mut w = W::default();
        w.u16(89).u8(0).u8(0).u32(action);
        times(&mut w, &node);
        w.u64(node.allocation())
            .u64(node.size())
            .u32(node.attributes(read_only))
            .u32(0)
            .bytes(&fid(new_id))
            .u32(0)
            .u32(0);
        Reply {
            file: Some(fid(new_id)),
            ..Reply::ok(w.0)
        }
    }

    fn close(&mut self, h: &Header, f: &FileId, flags: u16) -> Reply {
        let n = fid_num(f);
        if self.open_of(h, f).is_none() {
            return Reply::err(STATUS_FILE_CLOSED);
        }
        let o = self.opens.remove(&n).unwrap();
        let mut st = self.store();
        let mut w = W::default();
        w.u16(60).u16(flags).u32(0);
        let node = st.shares.get(&o.share).and_then(|s| s.get(&o.key)).cloned();
        match (&node, flags & 1 != 0) {
            (Some(node), true) => {
                times(&mut w, node);
                w.u64(node.allocation())
                    .u64(node.size())
                    .u32(node.attributes(false));
            }
            _ => {
                w.zeros(52);
            }
        }
        if o.delete_on_close {
            let still_open = self
                .opens
                .values()
                .any(|x| x.share == o.share && x.key == o.key);
            if !still_open {
                if let Some(sh) = st.shares.get_mut(&o.share) {
                    let _ = sh.remove(&o.key);
                }
            }
        }
        Reply::ok(w.0)
    }

    fn read(&mut self, h: &Header, f: &FileId, msg: &[u8]) -> Reply {
        let r = R(msg);
        let b = HEADER_LEN;
        let len = r.u32(b + 4).unwrap_or(0) as usize;
        let offset = r.u64(b + 8).unwrap_or(0) as usize;
        let min = r.u32(b + 32).unwrap_or(0) as usize;
        let Some(o) = self.open_of(h, f) else {
            return Reply::err(STATUS_FILE_CLOSED);
        };
        if o.dir {
            return Reply::err(STATUS_INVALID_DEVICE_REQUEST);
        }
        if len > self.cfg.server.max_io as usize {
            return Reply::err(STATUS_INVALID_PARAMETER);
        }
        let st = self.store();
        let Some(node) = st.shares.get(&o.share).and_then(|s| s.get(&o.key)) else {
            return Reply::err(STATUS_FILE_CLOSED);
        };
        if offset >= node.data.len() {
            return Reply::err(STATUS_END_OF_FILE);
        }
        let data = &node.data[offset..(offset + len).min(node.data.len())];
        if data.len() < min {
            return Reply::err(STATUS_END_OF_FILE);
        }
        let mut w = W::default();
        w.u16(17)
            .u8(0x50)
            .u8(0)
            .u32(data.len() as u32)
            .u32(0)
            .u32(0);
        w.bytes(data);
        Reply::ok(w.0)
    }

    fn write(&mut self, h: &Header, f: &FileId, msg: &[u8], cx: &mut AppCx) -> Reply {
        let r = R(msg);
        let b = HEADER_LEN;
        let off = r.u16(b + 2).unwrap_or(0) as usize;
        let len = r.u32(b + 4).unwrap_or(0) as usize;
        let offset = r.u64(b + 8).unwrap_or(0) as usize;
        let Some(data) = r.buffer(off, len) else {
            return Reply::err(STATUS_INVALID_PARAMETER);
        };
        let Some(o) = self.open_of(h, f) else {
            return Reply::err(STATUS_FILE_CLOSED);
        };
        if o.dir {
            return Reply::err(STATUS_INVALID_DEVICE_REQUEST);
        }
        let (share, key) = (o.share.clone(), o.key.clone());
        let now = ntlm::filetime(cx.wall());
        let mut st = self.store();
        let Some(sh) = st.shares.get_mut(&share) else {
            return Reply::err(STATUS_FILE_CLOSED);
        };
        if sh.read_only {
            return Reply::err(STATUS_ACCESS_DENIED);
        }
        let Some(node) = sh.get_mut(&key) else {
            return Reply::err(STATUS_FILE_CLOSED);
        };
        if node.data.len() < offset + data.len() {
            node.data.resize(offset + data.len(), 0);
        }
        node.data[offset..offset + data.len()].copy_from_slice(data);
        node.written = now;
        let mut w = W::default();
        w.u16(17)
            .u16(0)
            .u32(data.len() as u32)
            .u32(0)
            .u16(0)
            .u16(0)
            .u8(0);
        Reply::ok(w.0)
    }

    fn query_directory(&mut self, h: &Header, f: &FileId, msg: &[u8]) -> Reply {
        let r = R(msg);
        let b = HEADER_LEN;
        let class = r.u8(b + 2).unwrap_or(0);
        let flags = r.u8(b + 3).unwrap_or(0);
        let off = r.u16(b + 24).unwrap_or(0) as usize;
        let len = r.u16(b + 26).unwrap_or(0) as usize;
        let max = r.u32(b + 28).unwrap_or(0) as usize;
        let pattern = ntlm::from_utf16(r.buffer(off, len).unwrap_or(&[]));
        if !matches!(class, 1 | 2 | 3 | 12 | 37 | 38) {
            return Reply::err(STATUS_INVALID_INFO_CLASS);
        }
        let n = fid_num(f);
        let Some(o) = self.open_of(h, f) else {
            return Reply::err(STATUS_FILE_CLOSED);
        };
        if !o.dir {
            return Reply::err(STATUS_INVALID_PARAMETER);
        }
        let restart = flags & 0x11 != 0 || o.listing.is_none();
        if restart {
            let st = self.store();
            let Some(sh) = st.shares.get(&o.share) else {
                return Reply::err(STATUS_FILE_CLOSED);
            };
            let me = sh.get(&o.key).cloned();
            let up = o.key.rsplit_once('\\').map_or("", |(p, _)| p).to_string();
            let mut list = Vec::new();
            if let Some(me) = me {
                let parent = sh.get(&up).cloned().unwrap_or_else(|| me.clone());
                for (name, node) in [(".", me), ("..", parent)] {
                    if store::matches(&pattern, name) {
                        list.push(Entry {
                            name: name.into(),
                            node,
                        });
                    }
                }
            }
            for c in sh.children(&o.key) {
                if store::matches(&pattern, &c.name) {
                    list.push(Entry {
                        name: c.name.clone(),
                        node: c.clone(),
                    });
                }
            }
            drop(st);
            let o = self.opens.get_mut(&n).unwrap();
            let empty = list.is_empty();
            o.listing = Some((list, 0));
            if empty {
                return Reply::err(STATUS_NO_SUCH_FILE);
            }
        }
        let read_only = self.share_read_only(h);
        let o = self.opens.get_mut(&n).unwrap();
        let (list, at) = o.listing.as_mut().unwrap();
        if *at >= list.len() {
            return Reply::err(STATUS_NO_MORE_FILES);
        }
        let mut out: Vec<u8> = Vec::new();
        let mut last_start = 0;
        let single = flags & 0x02 != 0;
        while *at < list.len() {
            let e = dir_entry(class, &list[*at], read_only);
            let start = out.len().next_multiple_of(8);
            if start + e.len() > max {
                break;
            }
            out.resize(start, 0);
            if !out.is_empty() || start > 0 {
                let next = (start - last_start) as u32;
                out[last_start..last_start + 4].copy_from_slice(&next.to_le_bytes());
            }
            last_start = start;
            out.extend_from_slice(&e);
            *at += 1;
            if single {
                break;
            }
        }
        if out.is_empty() {
            return Reply::err(STATUS_INFO_LENGTH_MISMATCH);
        }
        let mut w = W::default();
        w.u16(9).u16(0x48).u32(out.len() as u32).bytes(&out);
        Reply::ok(w.0)
    }

    fn share_read_only(&self, h: &Header) -> bool {
        self.share_of(h)
            .and_then(|s| self.store().shares.get(&s).map(|x| x.read_only))
            .unwrap_or(false)
    }

    fn query_info(&mut self, h: &Header, f: &FileId, msg: &[u8]) -> Reply {
        let r = R(msg);
        let b = HEADER_LEN;
        let kind = r.u8(b + 2).unwrap_or(0);
        let class = r.u8(b + 3).unwrap_or(0);
        let max = r.u32(b + 4).unwrap_or(0) as usize;
        let Some(o) = self.open_of(h, f) else {
            return Reply::err(STATUS_FILE_CLOSED);
        };
        let st = self.store();
        let Some(sh) = st.shares.get(&o.share) else {
            return Reply::err(STATUS_FILE_CLOSED);
        };
        let Some(node) = sh.get(&o.key) else {
            return Reply::err(STATUS_FILE_CLOSED);
        };
        let out = match kind {
            1 => file_info(class, node, &o.key, sh.read_only, o.delete_on_close),
            2 => fs_info(class, sh, &self.cfg.server.name),
            _ => None,
        };
        let Some(mut out) = out else {
            return Reply::err(if kind == 1 || kind == 2 {
                STATUS_INVALID_INFO_CLASS
            } else {
                STATUS_NOT_SUPPORTED
            });
        };
        let mut status = STATUS_SUCCESS;
        if out.len() > max {
            out.truncate(max);
            status = STATUS_BUFFER_OVERFLOW;
        }
        let mut w = W::default();
        w.u16(9).u16(0x48).u32(out.len() as u32).bytes(&out);
        Reply {
            status,
            ..Reply::ok(w.0)
        }
    }

    fn set_info(&mut self, h: &Header, f: &FileId, msg: &[u8], cx: &mut AppCx) -> Reply {
        let r = R(msg);
        let b = HEADER_LEN;
        let kind = r.u8(b + 2).unwrap_or(0);
        let class = r.u8(b + 3).unwrap_or(0);
        let len = r.u32(b + 4).unwrap_or(0) as usize;
        let off = r.u16(b + 8).unwrap_or(0) as usize;
        let data = r.buffer(off, len).unwrap_or(&[]);
        let n = fid_num(f);
        let Some(o) = self.open_of(h, f) else {
            return Reply::err(STATUS_FILE_CLOSED);
        };
        if kind != 1 {
            return Reply::err(STATUS_NOT_SUPPORTED);
        }
        let (share, key) = (o.share.clone(), o.key.clone());
        let now = ntlm::filetime(cx.wall());
        let mut st = self.store();
        let Some(sh) = st.shares.get_mut(&share) else {
            return Reply::err(STATUS_FILE_CLOSED);
        };
        if sh.read_only && class != 4 {
            return Reply::err(STATUS_ACCESS_DENIED);
        }
        let d = R(data);
        match class {
            // Basic: times and attributes, taken but not kept.
            4 => {}
            // Rename.
            10 => {
                let replace = d.u8(0).unwrap_or(0) != 0;
                let nlen = d.u32(16).unwrap_or(0) as usize;
                let to = ntlm::from_utf16(d.bytes(20, nlen).unwrap_or(&[]));
                match sh.rename(&key, to.trim_start_matches('\\'), replace) {
                    Ok(k) => {
                        drop(st);
                        if let Some(o) = self.opens.get_mut(&n) {
                            o.key = k;
                        }
                        return Reply::ok(vec![2, 0]);
                    }
                    Err(e) => return Reply::err(e),
                }
            }
            // Disposition (and its extended form): delete on close.
            13 | 64 => {
                let delete = if class == 13 {
                    d.u8(0).unwrap_or(0) != 0
                } else {
                    d.u32(0).unwrap_or(0) & 1 != 0
                };
                if delete {
                    match sh.is_empty_dir_or_file(&key) {
                        Ok(true) => {}
                        Ok(false) => return Reply::err(STATUS_DIRECTORY_NOT_EMPTY),
                        Err(e) => return Reply::err(e),
                    }
                    if key.is_empty() {
                        return Reply::err(STATUS_ACCESS_DENIED);
                    }
                }
                drop(st);
                if let Some(o) = self.opens.get_mut(&n) {
                    o.delete_on_close = delete;
                }
                return Reply::ok(vec![2, 0]);
            }
            // Allocation: nothing to do.
            19 => {}
            // End of file.
            20 => {
                let size = d.u64(0).unwrap_or(0) as usize;
                if let Some(node) = sh.get_mut(&key) {
                    if node.dir {
                        return Reply::err(STATUS_INVALID_PARAMETER);
                    }
                    node.data.resize(size, 0);
                    node.written = now;
                }
            }
            _ => return Reply::err(STATUS_NOT_SUPPORTED),
        }
        Reply::ok(vec![2, 0])
    }

    fn ioctl(&mut self, msg: &[u8]) -> Reply {
        let r = R(msg);
        let b = HEADER_LEN;
        let code = r.u32(b + 4).unwrap_or(0);
        if code != FSCTL_VALIDATE_NEGOTIATE_INFO {
            return Reply::err(if code == 0x0006_0194 || code == 0x0006_01b0 {
                STATUS_FS_DRIVER_REQUIRED // no DFS
            } else {
                STATUS_NOT_SUPPORTED
            });
        }
        let mut out = W::default();
        out.u32(if self.dialect >= Some(SMB210) {
            CAP_LARGE_MTU
        } else {
            0
        })
        .bytes(&self.guid)
        .u16(self.security_mode())
        .u16(self.dialect.unwrap_or(0));
        let mut w = W::default();
        w.u16(49).u16(0).u32(code).bytes(&[0xff; 16]);
        let at = w.offset() as u32 + 24;
        w.u32(at)
            .u32(0)
            .u32(at)
            .u32(out.0.len() as u32)
            .u32(0)
            .u32(0);
        w.bytes(&out.0);
        Reply::ok(w.0)
    }
}

/// The pre-auth integrity hash after `msg`.
pub fn chain(h: &[u8; 64], msg: &[u8]) -> [u8; 64] {
    let mut d = h.to_vec();
    d.extend_from_slice(msg);
    sha512(&d)
}

fn setup_body(flags: u16, token: &[u8]) -> Vec<u8> {
    let mut w = W::default();
    w.u16(9)
        .u16(flags)
        .u16(0x48)
        .u16(token.len() as u16)
        .bytes(token);
    w.0
}

fn times(w: &mut W, n: &Node) {
    w.u64(n.created)
        .u64(n.written)
        .u64(n.written)
        .u64(n.written);
}

fn dir_entry(class: u8, e: &Entry, read_only: bool) -> Vec<u8> {
    let n = &e.node;
    let name = ntlm::utf16(&e.name);
    let mut w = W::default();
    w.u32(0).u32(0);
    if class == 12 {
        w.u32(name.len() as u32).bytes(&name);
        return w.0;
    }
    times(&mut w, n);
    w.u64(n.size())
        .u64(n.allocation())
        .u32(n.attributes(read_only))
        .u32(name.len() as u32);
    match class {
        1 => {}
        2 => {
            w.u32(0);
        }
        3 | 37 => {
            w.u32(0).u8(0).u8(0).zeros(24);
            if class == 37 {
                w.u16(0).u64(n.id);
            }
        }
        38 => {
            w.u32(0).u32(0).u64(n.id);
        }
        _ => {}
    }
    w.bytes(&name);
    w.0
}

fn file_info(class: u8, n: &Node, key: &str, ro: bool, delete: bool) -> Option<Vec<u8>> {
    let mut w = W::default();
    let basic = |w: &mut W| {
        times(w, n);
        w.u32(n.attributes(ro)).u32(0);
    };
    let standard = |w: &mut W| {
        w.u64(n.allocation())
            .u64(n.size())
            .u32(1)
            .u8(u8::from(delete))
            .u8(u8::from(n.dir))
            .u16(0);
    };
    match class {
        4 => basic(&mut w),
        5 => standard(&mut w),
        6 => {
            w.u64(n.id);
        }
        7 => {
            w.u32(0);
        }
        8 => {
            w.u32(if ro { 0x0012_0089 } else { 0x001f_01ff });
        }
        14 => {
            w.u64(0);
        }
        16 | 17 => {
            w.u32(0);
        }
        18 => {
            basic(&mut w);
            standard(&mut w);
            w.u64(n.id)
                .u32(0)
                .u32(if ro { 0x0012_0089 } else { 0x001f_01ff })
                .u64(0)
                .u32(0)
                .u32(0);
            let name = ntlm::utf16(&format!("\\{key}"));
            w.u32(name.len() as u32).bytes(&name);
        }
        22 => {
            if !n.dir {
                let s = ntlm::utf16("::$DATA");
                w.u32(0)
                    .u32(s.len() as u32)
                    .u64(n.size())
                    .u64(n.allocation())
                    .bytes(&s);
            }
        }
        34 => {
            times(&mut w, n);
            w.u64(n.allocation())
                .u64(n.size())
                .u32(n.attributes(ro))
                .u32(0);
        }
        35 => {
            w.u32(n.attributes(ro)).u32(0);
        }
        _ => return None,
    }
    Some(w.0)
}

fn fs_info(class: u8, sh: &Share, server: &str) -> Option<Vec<u8>> {
    // A volume of 64 GiB in 4 KiB clusters, less what the share holds.
    const UNITS: u64 = 16 << 20;
    let free = UNITS.saturating_sub(sh.used().div_ceil(4096));
    let mut w = W::default();
    match class {
        1 => {
            let label = ntlm::utf16(&sh.name);
            let serial = sh
                .name
                .bytes()
                .fold(0x4645_524fu32, |a, b| a.rotate_left(5) ^ u32::from(b));
            w.u64(sh.get("").map_or(0, |r| r.created))
                .u32(serial)
                .u32(label.len() as u32)
                .u8(0)
                .u8(0)
                .bytes(&label);
        }
        3 => {
            w.u64(UNITS).u64(free).u32(8).u32(512);
        }
        4 => {
            w.u32(7).u32(0x20); // disk; remote
        }
        5 => {
            let fs = ntlm::utf16("NTFS");
            w.u32(0x0000_0007).u32(255).u32(fs.len() as u32).bytes(&fs);
        }
        7 => {
            w.u64(UNITS).u64(free).u64(free).u32(8).u32(512);
        }
        8 => {
            w.zeros(64);
        }
        11 => {
            w.u32(512).u32(512).u32(512).u32(512).u32(0x3).u32(0).u32(0);
        }
        _ => {
            let _ = server;
            return None;
        }
    }
    Some(w.0)
}

impl AppSession for Server {
    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        self.cfg.ensure_store(cx.wall());
        self.buf.extend_from_slice(data);
        loop {
            if self.failed {
                self.buf.clear();
                cx.close();
                break;
            }
            match deframe(&self.buf) {
                Ok(Some((msg, used))) => {
                    let msg = msg.to_vec();
                    self.buf.drain(..used);
                    if msg.is_empty() {
                        continue; // keep-alive
                    }
                    if let Some(out) = self.message(&msg, cx) {
                        cx.send(out);
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    cx.protocol_error(e);
                    self.failed = true;
                }
            }
        }
        Receive::Taken
    }

    fn peer_closed(&mut self, cx: &mut AppCx) {
        cx.close();
    }
}
