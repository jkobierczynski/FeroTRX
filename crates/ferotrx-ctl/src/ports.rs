//! Port reservations and sessions per user.
//!
//! Several people can share one FeroTRX server. Each user (a token's name,
//! a client certificate's common name, or on a server without logins the
//! name given with `session.name`) has a session: the connections logged
//! in as that user, the ports the user reserved with `ports.acquire`, and
//! the user's runs.
//!
//! A run may only send on a port that no other user reserved and that no
//! other user's run sends on now. With `require_acquire` (`ferotrx serve
//! --require-acquire`) it may only send on ports its user acquired. Ports
//! stay reserved across reconnects until `ports.release`; an admin takes
//! them over with `force`, which stops the runs of others that send on them.
//! Receiving (`rx.start`, `capture.start`, a run's `rx`) needs no
//! reservation: listening does not disturb anyone.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use serde_json::json;

use crate::protocol::{PortInfo, PortRun, Role, RpcError, SessionInfo};

/// The user of connections that did not log in or name themselves.
pub const ANONYMOUS: &str = "anonymous";

/// Kinds of runs whose owner is recorded, and that `*.stop` and friends
/// check against it.
pub(crate) const KINDS: &[&str] = &[
    "run", "tcp", "udp", "rx", "scenario", "bench", "y1564", "capture",
];

/// How many finished runs' owners are remembered.
const MAX_OWNERS: usize = 8192;

/// How long a forced `ports.acquire` waits for the runs it stopped.
const FORCE_WAIT: Duration = Duration::from_secs(10);

/// Who calls the controller.
#[derive(Clone, Debug)]
pub struct Who {
    pub user: String,
    pub role: Option<Role>,
    /// May take ports and runs from other users: an admin, or anyone on a
    /// server without logins (which cannot tell users apart for sure).
    pub may_override: bool,
}

impl Who {
    /// Calls made on the controller directly, not through a connection.
    pub fn local() -> Self {
        Self {
            user: ANONYMOUS.into(),
            role: Some(Role::Admin),
            may_override: true,
        }
    }
}

thread_local! {
    static CALLER: RefCell<Option<Who>> = const { RefCell::new(None) };
}

/// Who the controller works for on this thread now.
pub(crate) fn caller() -> Who {
    CALLER
        .with(|c| c.borrow().clone())
        .unwrap_or_else(Who::local)
}

/// Runs `f` on behalf of `who`.
pub(crate) fn as_caller<R>(who: &Who, f: impl FnOnce() -> R) -> R {
    struct Reset(Option<Who>);
    impl Drop for Reset {
        fn drop(&mut self) {
            let old = self.0.take();
            CALLER.with(|c| *c.borrow_mut() = old);
        }
    }
    let old = CALLER.with(|c| c.borrow_mut().replace(who.clone()));
    let _reset = Reset(old);
    f()
}

type RunningFn = dyn Fn() -> bool + Send + Sync;
type StopFn = dyn Fn() + Send + Sync;

/// Reservations, the runs that send on ports, and the sessions.
#[derive(Default)]
pub(crate) struct Ports {
    inner: Mutex<Inner>,
    pub require_acquire: bool,
}

#[derive(Default)]
struct Inner {
    held: BTreeMap<String, Hold>,
    leases: Vec<Lease>,
    /// (kind, id) -> who started it.
    owners: BTreeMap<(String, u64), String>,
    sessions: BTreeMap<String, Session>,
}

struct Hold {
    owner: String,
    since: SystemTime,
    note: Option<String>,
}

/// A run that sends on ports while it goes.
struct Lease {
    owner: String,
    kind: &'static str,
    id: u64,
    ports: Vec<String>,
    running: Arc<RunningFn>,
    stop: Arc<StopFn>,
}

impl Lease {
    fn info(&self) -> PortRun {
        PortRun {
            kind: self.kind.into(),
            id: self.id,
            owner: self.owner.clone(),
            ports: self.ports.clone(),
        }
    }
}

struct Session {
    role: Option<Role>,
    connections: usize,
    since: SystemTime,
    last_seen: SystemTime,
}

fn secs(t: SystemTime) -> f64 {
    ferotrx_core::unix_seconds(t)
}

/// A refusal that names the port, who has it and why.
fn refused(message: String, port: &str, owner: Option<&str>, reason: &str) -> RpcError {
    let mut e = RpcError::forbidden(message);
    e.data = Some(json!({"port": port, "owner": owner, "reason": reason}));
    e
}

/// The port a refusal names, and why (`reserved`, `in_use`,
/// `not_acquired`, `not_owner`).
pub fn refused_port(e: &RpcError) -> Option<(&str, &str)> {
    if e.code != RpcError::FORBIDDEN {
        return None;
    }
    let d = e.data.as_ref()?;
    Some((d.get("port")?.as_str()?, d.get("reason")?.as_str()?))
}

/// One name per port: on Windows, an adapter's name ("Ethernet 2") or
/// `{GUID}` becomes its Npcap device, so both spellings are the same port.
pub(crate) fn canonical(name: &str) -> String {
    #[cfg(windows)]
    {
        ferotrx_io::windows::resolve(name.trim())
    }
    #[cfg(not(windows))]
    {
        name.trim().to_string()
    }
}

fn canonical_all(names: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for n in names {
        let c = canonical(n);
        if !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

/// `since` and `last_seen` as UTC text, `YYYY-MM-DDTHH:MM:SS.000Z`.
pub fn utc_text(secs: f64) -> String {
    crate::audit::rfc3339(secs as i64, 0)
}

/// "run 3", "tcp run 4".
pub fn run_name(kind: &str, id: u64) -> String {
    if kind == "run" {
        format!("run {id}")
    } else {
        format!("{kind} run {id}")
    }
}

const OVERRIDE_HINT: &str = "an admin can take it with ports.acquire and force";

impl Ports {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether `who` may start a run that sends on `ports`.
    pub fn check_send(&self, who: &Who, ports: &[String]) -> Result<(), RpcError> {
        let ports = &canonical_all(ports);
        let mut g = self.lock();
        g.leases.retain(|l| (l.running)());
        for p in ports {
            match g.held.get(p) {
                Some(h) if h.owner != who.user => {
                    let note = h
                        .note
                        .as_ref()
                        .map(|n| format!(" ({n})"))
                        .unwrap_or_default();
                    return Err(refused(
                        format!(
                            "port {p} is reserved by {}{note}: ask them to release it; \
                             {OVERRIDE_HINT}",
                            h.owner
                        ),
                        p,
                        Some(&h.owner),
                        "reserved",
                    ));
                }
                None if self.require_acquire => {
                    return Err(refused(
                        format!(
                            "this server sends only on acquired ports: acquire {p} first \
                             (ports.acquire, `ferotrx ctl acquire {p}`)"
                        ),
                        p,
                        None,
                        "not_acquired",
                    ));
                }
                _ => {}
            }
            if let Some(l) = g
                .leases
                .iter()
                .find(|l| l.owner != who.user && l.ports.contains(p))
            {
                return Err(refused(
                    format!(
                        "{}'s {} sends on {p} now: wait for it to end, or ask them to \
                         stop it; {OVERRIDE_HINT}",
                        l.owner,
                        run_name(l.kind, l.id)
                    ),
                    p,
                    Some(&l.owner),
                    "in_use",
                ));
            }
        }
        Ok(())
    }

    /// Notes that `owner`'s run sends on `ports` while `running` says so.
    pub fn lease(
        &self,
        owner: &str,
        kind: &'static str,
        id: u64,
        ports: Vec<String>,
        running: Arc<RunningFn>,
        stop: Arc<StopFn>,
    ) {
        let ports = canonical_all(&ports);
        let mut g = self.lock();
        g.leases.retain(|l| (l.running)());
        if !ports.is_empty() {
            g.leases.push(Lease {
                owner: owner.into(),
                kind,
                id,
                ports,
                running,
                stop,
            });
        }
    }

    /// Remembers who started run `id` of `kind`.
    pub fn record_owner(&self, kind: &str, id: u64, owner: &str) {
        let mut g = self.lock();
        g.owners.insert((kind.into(), id), owner.into());
        while g.owners.len() > MAX_OWNERS {
            let Some(first) = g.owners.keys().next().cloned() else {
                break;
            };
            g.owners.remove(&first);
        }
    }

    /// Whether `who` may stop, change or remove run `id` of `kind`.
    pub fn check_owner(&self, who: &Who, kind: &str, id: u64) -> Result<(), RpcError> {
        let g = self.lock();
        match g.owners.get(&(kind.to_string(), id)) {
            Some(owner) if *owner != who.user && !who.may_override => {
                let mut e = RpcError::forbidden(format!(
                    "{} belongs to {owner}: only they or an admin may change it",
                    run_name(kind, id)
                ));
                e.data = Some(json!({"owner": owner, "reason": "not_owner"}));
                Err(e)
            }
            _ => Ok(()),
        }
    }

    /// Reserves `ports` for `who`: all or none.
    pub fn acquire(
        &self,
        who: &Who,
        ports: &[String],
        force: bool,
        note: Option<String>,
    ) -> Result<Vec<PortInfo>, RpcError> {
        let ports = &canonical_all(ports);
        if ports.is_empty() {
            return Err(RpcError::invalid_params("name the ports to acquire"));
        }
        if force && !who.may_override {
            return Err(RpcError::forbidden(
                "taking ports from other users (force) needs the admin role",
            ));
        }
        let stopping: Vec<Lease> = {
            let mut g = self.lock();
            g.leases.retain(|l| (l.running)());
            let mut stopping = Vec::new();
            for p in ports {
                if let Some(h) = g.held.get(p).filter(|h| h.owner != who.user) {
                    if !force {
                        return Err(refused(
                            format!("port {p} is reserved by {}; {OVERRIDE_HINT}", h.owner),
                            p,
                            Some(&h.owner),
                            "reserved",
                        ));
                    }
                }
                for l in g
                    .leases
                    .iter()
                    .filter(|l| l.owner != who.user && l.ports.contains(p))
                {
                    if !force {
                        return Err(refused(
                            format!(
                                "{}'s {} sends on {p} now; {OVERRIDE_HINT}",
                                l.owner,
                                run_name(l.kind, l.id)
                            ),
                            p,
                            Some(&l.owner),
                            "in_use",
                        ));
                    }
                    if !stopping
                        .iter()
                        .any(|s: &Lease| s.kind == l.kind && s.id == l.id)
                    {
                        stopping.push(Lease {
                            owner: l.owner.clone(),
                            kind: l.kind,
                            id: l.id,
                            ports: l.ports.clone(),
                            running: l.running.clone(),
                            stop: l.stop.clone(),
                        });
                    }
                }
            }
            let now = SystemTime::now();
            for p in ports {
                let keep = g
                    .held
                    .get(p)
                    .filter(|h| h.owner == who.user)
                    .map(|h| h.since);
                g.held.insert(
                    p.clone(),
                    Hold {
                        owner: who.user.clone(),
                        since: keep.unwrap_or(now),
                        note: note.clone(),
                    },
                );
            }
            stopping
        };
        // The ports are ours now, so nobody else starts on them; stop what
        // still sends there and wait for it.
        for l in &stopping {
            (l.stop)();
        }
        let deadline = Instant::now() + FORCE_WAIT;
        while stopping.iter().any(|l| (l.running)()) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let all = self.list();
        Ok(all
            .into_iter()
            .filter(|p| ports.contains(&p.name))
            .collect())
    }

    /// Gives `ports` (or all of `who`'s, when empty) back; returns those
    /// released.
    pub fn release(
        &self,
        who: &Who,
        ports: &[String],
        force: bool,
    ) -> Result<Vec<String>, RpcError> {
        if force && !who.may_override {
            return Err(RpcError::forbidden(
                "releasing other users' ports (force) needs the admin role",
            ));
        }
        let ports = &canonical_all(ports);
        let mut g = self.lock();
        if ports.is_empty() {
            let mine: Vec<String> = g
                .held
                .iter()
                .filter(|(_, h)| h.owner == who.user)
                .map(|(p, _)| p.clone())
                .collect();
            for p in &mine {
                g.held.remove(p);
            }
            return Ok(mine);
        }
        for p in ports {
            match g.held.get(p) {
                None => {
                    return Err(RpcError::not_found(format!("port {p} is not reserved")));
                }
                Some(h) if h.owner != who.user && !force => {
                    return Err(refused(
                        format!("port {p} is reserved by {}, not by you", h.owner),
                        p,
                        Some(&h.owner),
                        "not_owner",
                    ));
                }
                _ => {}
            }
        }
        for p in ports {
            g.held.remove(p);
        }
        Ok(ports.to_vec())
    }

    /// Ports that are reserved or that runs send on now.
    pub fn list(&self) -> Vec<PortInfo> {
        let mut g = self.lock();
        g.leases.retain(|l| (l.running)());
        let mut out: BTreeMap<String, PortInfo> = BTreeMap::new();
        for (p, h) in &g.held {
            out.insert(
                p.clone(),
                PortInfo {
                    name: p.clone(),
                    owner: Some(h.owner.clone()),
                    since: Some(secs(h.since)),
                    note: h.note.clone(),
                    runs: Vec::new(),
                },
            );
        }
        for l in &g.leases {
            for p in &l.ports {
                out.entry(p.clone())
                    .or_insert_with(|| PortInfo {
                        name: p.clone(),
                        ..Default::default()
                    })
                    .runs
                    .push(l.info());
            }
        }
        out.into_values().collect()
    }

    /// A connection logged in as `user`.
    pub fn connected(&self, user: &str, role: Option<Role>) {
        let mut g = self.lock();
        let now = SystemTime::now();
        let s = g.sessions.entry(user.into()).or_insert(Session {
            role,
            connections: 0,
            since: now,
            last_seen: now,
        });
        if s.connections == 0 {
            s.since = now;
        }
        s.connections += 1;
        s.role = role.max(s.role);
        s.last_seen = now;
    }

    /// A connection of `user` closed or changed its user.
    pub fn disconnected(&self, user: &str) {
        let mut g = self.lock();
        if let Some(s) = g.sessions.get_mut(user) {
            s.connections = s.connections.saturating_sub(1);
            s.last_seen = SystemTime::now();
            if s.connections == 0 {
                s.role = None;
            }
        }
    }

    /// `user` asked something.
    pub fn seen(&self, user: &str) {
        if let Some(s) = self.lock().sessions.get_mut(user) {
            s.last_seen = SystemTime::now();
        }
    }

    fn session_of(g: &Inner, user: &str) -> SessionInfo {
        let s = g.sessions.get(user);
        SessionInfo {
            user: user.into(),
            role: s.and_then(|s| s.role),
            connections: s.map_or(0, |s| s.connections),
            ports: g
                .held
                .iter()
                .filter(|(_, h)| h.owner == user)
                .map(|(p, _)| p.clone())
                .collect(),
            runs: g
                .leases
                .iter()
                .filter(|l| l.owner == user)
                .map(Lease::info)
                .collect(),
            since: s.map(|s| secs(s.since)),
            last_seen: s.map(|s| secs(s.last_seen)),
        }
    }

    /// `user`'s session.
    pub fn session(&self, user: &str) -> SessionInfo {
        let mut g = self.lock();
        g.leases.retain(|l| (l.running)());
        Self::session_of(&g, user)
    }

    /// Every user with a connection, a reserved port or a run that sends;
    /// sessions with none of them are forgotten.
    pub fn sessions(&self) -> Vec<SessionInfo> {
        let mut g = self.lock();
        g.leases.retain(|l| (l.running)());
        let mut users: Vec<String> = g.sessions.keys().cloned().collect();
        users.extend(g.held.values().map(|h| h.owner.clone()));
        users.extend(g.leases.iter().map(|l| l.owner.clone()));
        users.sort();
        users.dedup();
        let out: Vec<SessionInfo> = users
            .iter()
            .map(|u| Self::session_of(&g, u))
            .filter(|s| s.connections > 0 || !s.ports.is_empty() || !s.runs.is_empty())
            .collect();
        g.sessions.retain(|u, _| out.iter().any(|s| &s.user == u));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn who(user: &str, admin: bool) -> Who {
        Who {
            user: user.into(),
            role: Some(if admin { Role::Admin } else { Role::Operator }),
            may_override: admin,
        }
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn reservations_keep_others_off() {
        let ports = Ports::default();
        let (alice, bob) = (who("alice", false), who("bob", false));
        ports
            .acquire(&alice, &names(&["eth1"]), false, Some("soak".into()))
            .unwrap();
        assert!(ports.check_send(&alice, &names(&["eth1"])).is_ok());
        let e = ports.check_send(&bob, &names(&["eth1"])).unwrap_err();
        assert_eq!(refused_port(&e), Some(("eth1", "reserved")));
        assert!(e.message.contains("alice") && e.message.contains("soak"));
        assert!(ports.check_send(&bob, &names(&["eth2"])).is_ok());
        assert!(ports
            .acquire(&bob, &names(&["eth2", "eth1"]), false, None)
            .is_err());
        // All or none: eth2 was not taken either.
        assert!(ports.list().iter().all(|p| p.name != "eth2"));
        assert!(ports.release(&bob, &names(&["eth1"]), false).is_err());
        assert!(ports.release(&bob, &names(&["eth1"]), true).is_err());
        assert_eq!(ports.release(&alice, &[], false).unwrap(), names(&["eth1"]));
        assert!(ports.check_send(&bob, &names(&["eth1"])).is_ok());
    }

    #[test]
    fn running_runs_hold_their_ports() {
        let ports = Ports::default();
        let (alice, bob, root) = (who("alice", false), who("bob", false), who("root", true));
        let going = Arc::new(AtomicBool::new(true));
        let (g1, g2) = (going.clone(), going.clone());
        ports.lease(
            "alice",
            "tcp",
            7,
            names(&["eth1", "eth2"]),
            Arc::new(move || g1.load(Ordering::SeqCst)),
            Arc::new(move || g2.store(false, Ordering::SeqCst)),
        );
        let e = ports.check_send(&bob, &names(&["eth2"])).unwrap_err();
        assert_eq!(refused_port(&e), Some(("eth2", "in_use")));
        assert!(e.message.contains("tcp run 7"));
        assert!(ports.check_send(&alice, &names(&["eth2"])).is_ok());
        assert!(ports.acquire(&bob, &names(&["eth1"]), false, None).is_err());
        assert!(ports.acquire(&bob, &names(&["eth1"]), true, None).is_err());
        assert_eq!(ports.session("alice").runs.len(), 1);
        // An admin takes the port: alice's run stops.
        let got = ports.acquire(&root, &names(&["eth1"]), true, None).unwrap();
        assert_eq!(got[0].owner.as_deref(), Some("root"));
        assert!(!going.load(Ordering::SeqCst));
        assert!(ports.check_send(&bob, &names(&["eth2"])).is_ok());
        assert!(ports.session("alice").runs.is_empty());
    }

    #[test]
    fn strict_servers_need_acquired_ports() {
        let ports = Ports {
            require_acquire: true,
            ..Default::default()
        };
        let alice = who("alice", false);
        let e = ports.check_send(&alice, &names(&["eth1"])).unwrap_err();
        assert_eq!(refused_port(&e), Some(("eth1", "not_acquired")));
        ports
            .acquire(&alice, &names(&["eth1"]), false, None)
            .unwrap();
        assert!(ports.check_send(&alice, &names(&["eth1"])).is_ok());
    }

    #[test]
    fn runs_belong_to_who_started_them() {
        let ports = Ports::default();
        ports.record_owner("run", 3, "alice");
        assert!(ports.check_owner(&who("alice", false), "run", 3).is_ok());
        assert!(ports.check_owner(&who("bob", false), "run", 3).is_err());
        assert!(ports.check_owner(&who("root", true), "run", 3).is_ok());
        assert!(ports.check_owner(&who("bob", false), "run", 4).is_ok());
    }

    #[test]
    fn sessions_count_connections_and_outlive_them_while_ports_are_held() {
        let ports = Ports::default();
        ports.connected("alice", Some(Role::Operator));
        ports.connected("alice", Some(Role::Read));
        ports.connected("bob", Some(Role::Read));
        ports
            .acquire(&who("alice", false), &names(&["eth1"]), false, None)
            .unwrap();
        let s = ports.session("alice");
        assert_eq!((s.connections, s.role), (2, Some(Role::Operator)));
        ports.disconnected("alice");
        ports.disconnected("alice");
        ports.disconnected("bob");
        let all = ports.sessions();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].user, "alice");
        assert_eq!(all[0].connections, 0);
        assert_eq!(all[0].ports, names(&["eth1"]));
    }

    #[test]
    fn the_caller_is_per_thread() {
        assert_eq!(caller().user, ANONYMOUS);
        let alice = who("alice", false);
        let inner = as_caller(&alice, || {
            let here = caller().user;
            let other = std::thread::spawn(|| caller().user).join().unwrap();
            (here, other)
        });
        assert_eq!(inner, ("alice".to_string(), ANONYMOUS.to_string()));
        assert_eq!(caller().user, ANONYMOUS);
    }
}
