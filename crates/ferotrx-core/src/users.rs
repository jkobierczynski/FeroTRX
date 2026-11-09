//! Concurrent users: a number of emulated users kept alive, each opening
//! one session after another with a think time between them, and leaving
//! after a lifetime of their own (a new user takes the place).
//!
//! The engines (TCP and UDP) ask [`Users::due`] which users want a new
//! session now, open one for each, say so with [`Users::busy`], and tell
//! [`Users::ended`] when a user's session is over. Each user keeps one
//! client address for its whole life, as a real host would.

use std::time::Duration;

use crate::{Dist, DistRng};

/// One kind of user: how many are online at once, how long they pause
/// between sessions and how long they stay. A persona brings one.
#[derive(Clone, Debug, PartialEq)]
pub struct UserGroup {
    /// For reports: the persona's name, or `users`.
    pub name: String,
    /// Users online at once.
    pub users: u32,
    /// The pause between the end of a user's session and its next one.
    pub think: Dist,
    /// How long a user stays before it leaves (and a new one comes);
    /// `None`: for the whole run.
    pub lifetime: Option<Dist>,
    /// Users that arrive per second at the start, until all are online;
    /// `None`: all at once.
    pub arrival: Option<f64>,
}

impl UserGroup {
    pub fn new(name: impl Into<String>, users: u32) -> Self {
        Self {
            name: name.into(),
            users,
            think: Dist::zero(),
            lifetime: None,
            arrival: None,
        }
    }

    pub(crate) fn validate(&self) -> crate::Result<()> {
        if self.users == 0 {
            return Err(crate::Error::Profile(format!(
                "users '{}': give at least 1 user",
                self.name
            )));
        }
        if let Some(r) = self.arrival {
            if !(r.is_finite() && r > 0.0) {
                return Err(crate::Error::Profile(format!(
                    "users '{}': the arrival rate must be above 0",
                    self.name
                )));
            }
        }
        Ok(())
    }
}

impl std::fmt::Display for UserGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} user(s) '{}'", self.users, self.name)?;
        if !self.think.is_zero() {
            write!(f, ", think {}", self.think)?;
        }
        if let Some(l) = &self.lifetime {
            write!(f, ", stay {l}")?;
        }
        if let Some(r) = self.arrival {
            write!(f, ", arriving {r}/s")?;
        }
        Ok(())
    }
}

/// A profile's `[users]` table (and a persona's `[user]` table, without
/// `count`).
#[cfg(feature = "profile")]
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawUsers {
    pub count: Option<u32>,
    pub think: Option<crate::dist::DistText>,
    pub lifetime: Option<crate::dist::DistText>,
    pub arrival: Option<f64>,
}

#[cfg(feature = "profile")]
impl RawUsers {
    /// The group, named `name`; `count` comes from here or from `users`.
    pub(crate) fn group(&self, name: &str, users: Option<u32>) -> crate::Result<UserGroup> {
        use crate::Quantity;
        let count = users.or(self.count).ok_or_else(|| {
            crate::Error::Profile(format!(
                "users '{name}': give `count`, the users online at once"
            ))
        })?;
        let mut g = UserGroup::new(name, count);
        if let Some(t) = &self.think {
            g.think = t.parse(Quantity::Time)?;
        }
        g.lifetime = self
            .lifetime
            .as_ref()
            .map(|l| l.parse(Quantity::Time))
            .transpose()?;
        g.arrival = self.arrival;
        g.validate()?;
        Ok(g)
    }

    /// Overrides from a `[[persona]]` entry over the persona's own.
    pub(crate) fn over(mut self, o: &RawUsers) -> Self {
        if o.think.is_some() {
            self.think = o.think.clone();
        }
        if o.lifetime.is_some() {
            self.lifetime = o.lifetime.clone();
        }
        if o.arrival.is_some() {
            self.arrival = o.arrival;
        }
        self
    }
}

/// Checks that the templates, as (name, group, weight, own rate), fit the
/// groups: each group makes sessions of at least one template, and the
/// templates of a group have no rate of their own.
pub(crate) fn check_groups<'a>(
    groups: &[UserGroup],
    templates: impl Iterator<Item = (&'a str, Option<usize>, u32, bool)>,
) -> crate::Result<()> {
    let mut used = vec![false; groups.len()];
    for g in groups {
        g.validate()?;
    }
    for (name, group, weight, rate) in templates {
        let Some(g) = group else { continue };
        if g >= groups.len() {
            return Err(crate::Error::Profile(format!(
                "template {name}: users group {g} does not exist ({} groups)",
                groups.len()
            )));
        }
        if rate {
            return Err(crate::Error::Profile(format!(
                "template {name}: its users open its sessions, so it takes no rate of its own"
            )));
        }
        used[g] |= weight > 0;
    }
    if let Some(i) = used.iter().position(|u| !u) {
        return Err(crate::Error::Profile(format!(
            "users '{}': no template with a weight above 0 for them to use",
            groups[i].name
        )));
    }
    Ok(())
}

/// Counters of the users of a run (all groups together, or one group).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct UserStats {
    pub name: String,
    /// Users online now.
    pub online: u64,
    /// Users that came, the first ones included.
    pub arrived: u64,
    /// Users that left after their lifetime.
    pub departed: u64,
    /// Sessions users started.
    pub sessions: u64,
    /// Sessions per user that left (how much a user did).
    pub sessions_per_user: crate::CountStats,
    /// How long users that left stayed.
    pub lifetime: crate::LatencyStats,
    /// The think times drawn between sessions.
    pub think: crate::LatencyStats,
}

impl UserStats {
    pub fn merge(&mut self, o: &UserStats) {
        self.online += o.online;
        self.arrived += o.arrived;
        self.departed += o.departed;
        self.sessions += o.sessions;
        self.sessions_per_user.merge(&o.sessions_per_user);
        self.lifetime.merge(&o.lifetime);
        self.think.merge(&o.think);
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    /// Will open a session at this time.
    Ready(Duration),
    /// A session is open.
    Busy,
}

#[derive(Clone, Debug)]
struct Slot {
    group: usize,
    /// The client address (index into the client's addresses).
    address: u64,
    state: State,
    came: Duration,
    leaves: Option<Duration>,
    sessions: u64,
}

/// The users of a run.
#[derive(Clone, Debug)]
pub(crate) struct Users {
    groups: Vec<UserGroup>,
    slots: Vec<Slot>,
    rng: DistRng,
    /// The next client address a new user gets.
    next_address: u64,
    started: bool,
    /// Per group, then all together at the end.
    stats: Vec<UserStats>,
}

impl Users {
    pub(crate) fn new(groups: Vec<UserGroup>, seed: u64) -> Self {
        let mut stats: Vec<UserStats> = groups
            .iter()
            .map(|g| UserStats {
                name: g.name.clone(),
                ..Default::default()
            })
            .collect();
        stats.push(UserStats {
            name: "all".into(),
            ..Default::default()
        });
        Self {
            groups,
            slots: Vec::new(),
            rng: DistRng::new(seed),
            next_address: 0,
            started: false,
            stats,
        }
    }

    /// Users get client addresses from `n` on.
    pub(crate) fn first_address(mut self, n: u64) -> Self {
        self.next_address = n;
        self
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    fn count(&mut self, group: usize, f: impl Fn(&mut UserStats)) {
        f(&mut self.stats[group]);
        let all = self.stats.len() - 1;
        f(&mut self.stats[all]);
    }

    fn arrive(&mut self, group: usize, at: Duration) -> Slot {
        let leaves = self.groups[group]
            .lifetime
            .map(|l| at.saturating_add(l.sample_time(&mut self.rng)));
        let address = self.next_address;
        self.next_address += 1;
        self.count(group, |s| {
            s.arrived += 1;
            s.online += 1;
        });
        Slot {
            group,
            address,
            state: State::Ready(at),
            came: at,
            leaves,
            sessions: 0,
        }
    }

    /// Brings the first users, at `now` (spread by the arrival rate).
    pub(crate) fn start(&mut self, now: Duration) {
        if self.started {
            return;
        }
        self.started = true;
        for g in 0..self.groups.len() {
            let (n, rate) = (self.groups[g].users, self.groups[g].arrival);
            for k in 0..n {
                let at = match rate {
                    Some(r) => now.saturating_add(
                        Duration::try_from_secs_f64(f64::from(k) / r)
                            .unwrap_or(crate::dist::MAX_TIME)
                            .min(crate::dist::MAX_TIME),
                    ),
                    None => now,
                };
                let slot = self.arrive(g, at);
                self.slots.push(slot);
            }
        }
    }

    /// The users that want a session now: (user, group, client address).
    pub(crate) fn due(&self, now: Duration) -> Vec<(usize, usize, u64)> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, s)| matches!(s.state, State::Ready(t) if t <= now))
            .map(|(i, s)| (i, s.group, s.address))
            .collect()
    }

    /// When the next user wants a session, if one waits.
    pub(crate) fn next_due(&self) -> Option<Duration> {
        self.slots
            .iter()
            .filter_map(|s| match s.state {
                State::Ready(t) => Some(t),
                State::Busy => None,
            })
            .min()
    }

    /// User `i` opened a session.
    pub(crate) fn busy(&mut self, i: usize) {
        let g = self.slots[i].group;
        self.slots[i].state = State::Busy;
        self.slots[i].sessions += 1;
        self.count(g, |s| s.sessions += 1);
    }

    /// User `i` could not open a session now (no free address or port, a
    /// limit): it tries again a little later.
    pub(crate) fn retry(&mut self, i: usize, at: Duration) {
        self.slots[i].state = State::Ready(at);
    }

    /// User `i`'s session ended at `now`: it thinks, or leaves and a new
    /// user takes its place.
    pub(crate) fn ended(&mut self, i: usize, now: Duration) {
        let Some(slot) = self.slots.get(i) else {
            return;
        };
        let g = slot.group;
        if slot.leaves.is_some_and(|t| now >= t) {
            let (stayed, sessions) = (now.saturating_sub(slot.came), slot.sessions);
            self.count(g, |s| {
                s.departed += 1;
                s.online = s.online.saturating_sub(1);
                s.sessions_per_user.record(sessions);
                s.lifetime.record(Some(stayed));
            });
            let fresh = self.arrive(g, now);
            self.slots[i] = fresh;
            return;
        }
        let think = self.groups[g].think.sample_time(&mut self.rng);
        self.count(g, |s| s.think.record(Some(think)));
        self.slots[i].state = State::Ready(now.saturating_add(think));
    }

    /// Per group, then all together.
    pub(crate) fn stats(&self) -> &[UserStats] {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Quantity;

    #[test]
    fn users_think_leave_and_are_replaced() {
        let mut g = UserGroup::new("office", 3);
        g.think = Dist::time(Duration::from_secs(2));
        g.lifetime = Some(Dist::time(Duration::from_secs(5)));
        let mut u = Users::new(vec![g], 1);
        u.start(Duration::ZERO);
        let due = u.due(Duration::ZERO);
        assert_eq!(due.len(), 3);
        assert_eq!(
            due.iter().map(|d| d.2).collect::<Vec<_>>(),
            [0, 1, 2],
            "one address per user"
        );
        for (i, _, _) in due {
            u.busy(i);
        }
        assert!(u.due(Duration::from_secs(1)).is_empty());
        u.ended(0, Duration::from_secs(1));
        assert!(u.due(Duration::from_secs(2)).is_empty());
        assert_eq!(u.due(Duration::from_secs(3)).len(), 1);
        // After its lifetime the user leaves; a new one, with a new address,
        // is due at once.
        u.busy(0);
        u.ended(0, Duration::from_secs(6));
        let due = u.due(Duration::from_secs(6));
        assert_eq!(due, [(0, 0, 3)]);
        let all = &u.stats()[1];
        assert_eq!((all.arrived, all.departed, all.online), (4, 1, 3));
        assert_eq!(all.sessions_per_user.mean(), Some(2.0));
    }

    #[test]
    fn arrivals_are_spread() {
        let mut g = UserGroup::new("iot", 10);
        g.arrival = Some(5.0);
        g.think = Dist::parse(Quantity::Time, "exp(1s)").unwrap();
        let mut u = Users::new(vec![g], 1);
        u.start(Duration::ZERO);
        assert_eq!(u.due(Duration::ZERO).len(), 1);
        assert_eq!(u.due(Duration::from_millis(999)).len(), 5);
        assert_eq!(u.next_due(), Some(Duration::ZERO));
    }
}
