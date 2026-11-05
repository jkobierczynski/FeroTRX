//! SMB 2 and 3 (MS-SMB2) over TCP port 445: file clients and a file server.
//!
//! Each client connection negotiates a dialect (2.0.2 up to 3.1.1, with
//! the 3.1.1 pre-auth integrity hash), logs in with NTLMv2 in SPNEGO (or
//! anonymously), connects to a share, plays its operations (`write`,
//! `read`, `list`, `delete`, `mkdir`, `rmdir`, each a CREATE, the reads,
//! writes or directory queries, and a CLOSE), then disconnects the tree
//! and logs off. Reads and writes go in chunks with several in flight.
//! It signs (HMAC-SHA256 for 2.x, AES-CMAC for 3.x) when the server
//! requires it or `signing = "required"`, and checks what the server
//! signs. A read of a file the connection wrote checks the bytes.
//!
//! The server takes the same dialects and logins (its `users`, or anyone
//! as a guest when it has none), and serves shares from memory: the files
//! of `files` in each, and whatever clients write, shared by all its
//! connections. It answers the requests smbclient and Windows send for
//! files and directories, file and volume information, renames and
//! deletes, and validates negotiation (FSCTL_VALIDATE_NEGOTIATE_INFO).
//!
//! Transactions: the client's `negotiate 3.1.1`, `login` (`login guest`,
//! `login anonymous`), `tree connect`, each operation by its name, and
//! `logoff`; a refusal adds its status (`login STATUS_LOGON_FAILURE`).
//! The server counts each request by its command (`CREATE`, `READ`).
//!
//! Not here: encryption, SMB 1, Kerberos, leases and oplocks, named pipes.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::{AppProtocol, AppRole, AppSession, SessionInit, Transport};
use crate::{Error, Result};

mod client;
pub mod crypto;
pub mod msg;
pub mod ntlm;
mod server;
pub mod store;

pub use msg::{dialect_name, parse_dialect, parse_status, status_name};

/// When a client signs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Signing {
    /// When the server requires it (the client) or the client signs (the
    /// server).
    #[default]
    Auto,
    /// Always (the client), or refuse what is not signed (the server).
    Required,
    /// Never, even when the server requires it (to test that it refuses).
    Off,
}

impl std::str::FromStr for Signing {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" | "if_required" | "default" => Ok(Signing::Auto),
            "required" | "on" | "always" | "mandatory" => Ok(Signing::Required),
            "off" | "never" | "disabled" => Ok(Signing::Off),
            _ => Err(Error::Profile(format!(
                "signing `{s}`: use auto, required or off"
            ))),
        }
    }
}

/// What an operation does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpKind {
    /// Creates or overwrites a file of this many bytes.
    Write(u64),
    Read,
    List,
    Delete,
    Mkdir,
    Rmdir,
}

impl OpKind {
    pub fn name(&self) -> &'static str {
        match self {
            OpKind::Write(_) => "write",
            OpKind::Read => "read",
            OpKind::List => "list",
            OpKind::Delete => "delete",
            OpKind::Mkdir => "mkdir",
            OpKind::Rmdir => "rmdir",
        }
    }
}

/// One operation of a client: `write upload-{n}.bin 256K`, `read
/// readme.txt`, `list docs`, `delete upload-{n}.bin`, `mkdir d`, `rmdir d`;
/// `... expect STATUS` for one that should fail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmbOp {
    pub kind: OpKind,
    /// In the share; `{n}` is the connection's number.
    pub path: String,
    /// The status it should end with, when not success.
    pub expect: Option<u32>,
}

impl std::str::FromStr for SmbOp {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let (main, expect) = match s.split_once(" expect ") {
            Some((m, e)) => (
                m,
                Some(parse_status(e).ok_or_else(|| {
                    Error::Profile(format!("`{s}`: unknown status `{}`", e.trim()))
                })?),
            ),
            None => (s, None),
        };
        let w: Vec<&str> = main.split_whitespace().collect();
        let bad = || {
            Error::Profile(format!(
                "SMB operation `{s}`: write PATH SIZE, read PATH, list [DIR], delete PATH, \
                 mkdir DIR or rmdir DIR, optionally followed by `expect STATUS`"
            ))
        };
        let (kind, path) = match w.as_slice() {
            ["write", p, size] => (OpKind::Write(crate::parse_size(size)?), *p),
            ["write", p] => (OpKind::Write(64 << 10), *p),
            ["read", p] => (OpKind::Read, *p),
            ["list"] => (OpKind::List, ""),
            ["list", p] => (OpKind::List, *p),
            ["delete" | "rm" | "del", p] => (OpKind::Delete, *p),
            ["mkdir" | "md", p] => (OpKind::Mkdir, *p),
            ["rmdir" | "rd", p] => (OpKind::Rmdir, *p),
            _ => return Err(bad()),
        };
        Ok(Self {
            kind,
            path: path.trim_matches(['\\', '/']).replace('/', "\\"),
            expect,
        })
    }
}

/// The client part.
#[derive(Clone, Debug, PartialEq)]
pub struct SmbClient {
    /// Empty for an anonymous login.
    pub user: String,
    pub password: String,
    pub domain: String,
    pub workstation: String,
    pub share: String,
    /// Offered, best first.
    pub dialects: Vec<u16>,
    pub signing: Signing,
    pub ops: Vec<SmbOp>,
    /// The size of each read and write (at most what the server allows).
    pub chunk: u32,
    /// Reads or writes in flight at once.
    pub window: usize,
    /// How long to wait for an answer.
    pub wait: Duration,
    /// The status the login or tree connect should fail with.
    pub expect: Option<u32>,
}

impl Default for SmbClient {
    fn default() -> Self {
        Self {
            user: "guest".into(),
            password: String::new(),
            domain: "WORKGROUP".into(),
            workstation: "FEROTRX".into(),
            share: "lab".into(),
            dialects: msg::ALL_DIALECTS.to_vec(),
            signing: Signing::Auto,
            ops: vec![
                "write ferotrx-{n}.bin 64K".parse().unwrap(),
                "read ferotrx-{n}.bin".parse().unwrap(),
                "list".parse().unwrap(),
                "delete ferotrx-{n}.bin".parse().unwrap(),
            ],
            chunk: 64 << 10,
            window: 4,
            wait: Duration::from_secs(30),
            expect: None,
        }
    }
}

/// A share of the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareConfig {
    pub name: String,
    pub read_only: bool,
}

/// The server part.
#[derive(Clone, Debug, PartialEq)]
pub struct SmbServer {
    /// User names and passwords; none: anyone, as a guest.
    pub users: BTreeMap<String, String>,
    /// With users: also take unknown users and anonymous logins, as guests.
    pub guest: bool,
    pub shares: Vec<ShareConfig>,
    /// Files in every share at the start, with their sizes.
    pub files: Vec<(String, u64)>,
    /// Accepted; the best one both offer is used.
    pub dialects: Vec<u16>,
    pub require_signing: bool,
    /// The NetBIOS names of the server and its domain, and a DNS domain.
    pub name: String,
    pub domain: String,
    pub dns_domain: String,
    /// The largest read and write.
    pub max_io: u32,
}

impl Default for SmbServer {
    fn default() -> Self {
        Self {
            users: BTreeMap::new(),
            guest: false,
            shares: vec![ShareConfig {
                name: "lab".into(),
                read_only: false,
            }],
            files: vec![("readme.txt".into(), 4096)],
            dialects: msg::ALL_DIALECTS.to_vec(),
            require_signing: false,
            name: "FEROTRX".into(),
            domain: "WORKGROUP".into(),
            dns_domain: String::new(),
            max_io: 1 << 20,
        }
    }
}

/// The server's shares, shared by all its connections.
#[derive(Debug, Default)]
pub struct Store {
    pub shares: BTreeMap<String, store::Share>,
    pub next_id: u64,
    ready: bool,
}

/// SMB client and server; see the [module](self) docs.
#[derive(Clone, Debug, Default)]
pub struct Smb {
    pub client: SmbClient,
    pub server: SmbServer,
    store: Arc<Mutex<Store>>,
}

impl Smb {
    pub fn new(client: SmbClient, server: SmbServer) -> Self {
        Self {
            client,
            server,
            store: Arc::default(),
        }
    }

    /// Fills the shares on first use, with the time of day as file times.
    fn ensure_store(&self, wall: Duration) {
        let mut st = self.store.lock().unwrap_or_else(|e| e.into_inner());
        if st.ready {
            return;
        }
        st.ready = true;
        let now = ntlm::filetime(wall);
        for s in &self.server.shares {
            st.next_id += 1;
            let mut share = store::Share::new(&s.name, s.read_only, now, st.next_id);
            let mut id = st.next_id;
            for (path, size) in &self.server.files {
                share.put(path, super::filler(*size as usize), now, &mut id);
            }
            st.next_id = id;
            st.shares.insert(s.name.to_lowercase(), share);
        }
    }

    /// Bytes a client writes to `path` from `offset`, and checks reads by.
    pub fn content(path: &str, offset: u64, len: usize) -> Vec<u8> {
        let seed = path.to_lowercase().bytes().fold(0x811c_9dc5u32, |h, b| {
            (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
        });
        (0..len as u64)
            .map(|i| {
                let x = (offset + i) as u32;
                (x.wrapping_mul(0x9e37_79b1) ^ seed).rotate_left(x % 13 + 3) as u8
            })
            .collect()
    }
}

impl AppProtocol for Smb {
    fn name(&self) -> &str {
        "smb"
    }

    fn describe(&self) -> String {
        let c = &self.client;
        let who = if c.user.is_empty() {
            "anonymous".to_string()
        } else {
            c.user.clone()
        };
        let mut s = format!(
            "SMB {}: {who} on {}, {} operation(s)",
            dialect_name(c.dialects.iter().copied().max().unwrap_or(msg::SMB311)),
            c.share,
            c.ops.len()
        );
        if c.signing == Signing::Required {
            s += ", signed";
        }
        let srv = &self.server;
        let shares: Vec<String> = srv
            .shares
            .iter()
            .map(|x| {
                if x.read_only {
                    format!("{} (read only)", x.name)
                } else {
                    x.name.clone()
                }
            })
            .collect();
        s += &format!("; server shares {}", shares.join(", "));
        if !srv.users.is_empty() {
            s += &format!(", {} user(s)", srv.users.len());
        }
        if srv.require_signing {
            s += ", signing required";
        }
        s
    }

    fn default_port(&self) -> u16 {
        445
    }

    fn supports(&self, transport: Transport) -> bool {
        transport == Transport::Stream
    }

    fn validate(&self, role: AppRole, _transport: Transport) -> Result<()> {
        match role {
            AppRole::Client => {
                if self.client.dialects.is_empty() {
                    return Err(Error::Profile("SMB: no dialects to offer".into()));
                }
                if self.client.chunk == 0 || self.client.window == 0 {
                    return Err(Error::Profile(
                        "SMB: chunk and window are at least 1".into(),
                    ));
                }
            }
            AppRole::Server => {
                if self.server.dialects.is_empty() || self.server.shares.is_empty() {
                    return Err(Error::Profile(
                        "SMB: the server needs dialects and a share".into(),
                    ));
                }
                if self.server.max_io < 4096 {
                    return Err(Error::Profile("SMB: max_io is at least 4K".into()));
                }
            }
        }
        Ok(())
    }

    fn session(&self, init: &SessionInit) -> Box<dyn AppSession> {
        let cfg = Arc::new(self.clone());
        match init.role {
            AppRole::Client => Box::new(client::Client::new(cfg, init)),
            AppRole::Server => Box::new(server::Server::new(cfg, init.seed)),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
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

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Smb {
        pub user: Option<String>,
        pub password: Option<String>,
        pub domain: Option<String>,
        pub workstation: Option<String>,
        pub share: Option<String>,
        pub dialects: Option<Vec<String>>,
        pub signing: Option<String>,
        pub ops: Option<Vec<String>>,
        pub chunk: Option<Size>,
        pub window: Option<usize>,
        pub wait: Option<String>,
        pub expect: Option<String>,
        pub users: Option<BTreeMap<String, String>>,
        pub guest: Option<bool>,
        pub shares: Option<Vec<String>>,
        #[serde(default)]
        pub read_only: Vec<String>,
        pub files: Option<BTreeMap<String, Size>>,
        pub name: Option<String>,
        pub workgroup: Option<String>,
        pub dns_domain: Option<String>,
        pub max_io: Option<Size>,
    }
}

#[cfg(feature = "profile")]
fn size(s: raw::Size) -> Result<u64> {
    match s {
        raw::Size::N(n) => Ok(n),
        raw::Size::S(s) => crate::parse_size(&s),
    }
}

#[cfg(feature = "profile")]
fn dialects(list: Vec<String>) -> Result<Vec<u16>> {
    list.iter()
        .map(|d| {
            parse_dialect(d).ok_or_else(|| {
                Error::Profile(format!(
                    "SMB dialect `{d}`: use 2.0.2, 2.1, 3.0, 3.0.2 or 3.1.1"
                ))
            })
        })
        .collect()
}

/// Reads an `[smb]` table.
#[cfg(feature = "profile")]
pub fn parse(t: &toml::Table) -> Result<Smb> {
    let r: raw::Smb = super::registry::table_into(t)?;
    let mut c = SmbClient::default();
    if let Some(u) = r.user {
        c.user = u;
    }
    if let Some(p) = r.password {
        c.password = p;
    }
    if let Some(d) = r.domain {
        c.domain = d;
    }
    if let Some(w) = r.workstation {
        c.workstation = w;
    }
    if let Some(s) = r.share {
        c.share = s;
    }
    let mut s = SmbServer::default();
    if let Some(d) = r.dialects {
        c.dialects = dialects(d)?;
        s.dialects = c.dialects.clone();
    }
    if let Some(g) = r.signing {
        c.signing = g.parse()?;
        s.require_signing = c.signing == Signing::Required;
    }
    if let Some(ops) = r.ops {
        c.ops = ops.iter().map(|o| o.parse()).collect::<Result<_>>()?;
    }
    if let Some(ch) = r.chunk {
        c.chunk =
            u32::try_from(size(ch)?).map_err(|_| Error::Profile("SMB: chunk is too big".into()))?;
    }
    if let Some(w) = r.window {
        c.window = w;
    }
    if let Some(w) = r.wait {
        c.wait = crate::parse_duration(&w)?;
    }
    if let Some(e) = r.expect {
        c.expect =
            Some(parse_status(&e).ok_or_else(|| Error::Profile(format!("unknown status `{e}`")))?);
    }
    if let Some(u) = r.users {
        s.users = u;
    }
    if let Some(g) = r.guest {
        s.guest = g;
    }
    if let Some(sh) = r.shares {
        s.shares = sh
            .into_iter()
            .map(|name| ShareConfig {
                read_only: r.read_only.iter().any(|x| x.eq_ignore_ascii_case(&name)),
                name,
            })
            .collect();
    } else {
        for x in &mut s.shares {
            x.read_only = r.read_only.iter().any(|y| y.eq_ignore_ascii_case(&x.name));
        }
    }
    if let Some(f) = r.files {
        s.files = f
            .into_iter()
            .map(|(k, v)| Ok((k, size(v)?)))
            .collect::<Result<_>>()?;
    }
    if let Some(n) = r.name {
        s.name = n;
    }
    if let Some(w) = r.workgroup {
        s.domain = w;
    }
    if let Some(d) = r.dns_domain {
        s.dns_domain = d;
    }
    if let Some(m) = r.max_io {
        s.max_io =
            u32::try_from(size(m)?).map_err(|_| Error::Profile("SMB: max_io is too big".into()))?;
    }
    let smb = Smb::new(c, s);
    smb.validate(AppRole::Client, Transport::Stream)?;
    smb.validate(AppRole::Server, Transport::Stream)?;
    Ok(smb)
}

#[cfg(test)]
mod tests;
