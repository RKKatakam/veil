//! What a regional cache knows of access epochs, and how fresh it is
//! (`docs/HUB.md` §13.18; design: `phase-2-thin-clients.md` §4.4).
//!
//! The cache serves under a grant only if the server confirmed, at most
//! [`STALE`] ago, that the grant's project epoch and its device's person
//! epoch are still the ones the grant carries. It asks about every key it
//! has seen in a grant for the last [`TRACK_FOR`], every [`POLL`] (and at
//! once when a new key appears), through `POST /v1/cache/epochs`
//! (`super::feed`).
//!
//! **The bound.** A key's confirmation is the time its poll was *sent*: the
//! server's answer reflects every access change committed before that. An
//! access change committed at time R is in every poll sent after R, so the
//! cache serves under the grant it voided only while its latest confirmation
//! predates R, that is, until R + [`STALE`] at the latest; with polls every
//! second it stops within about a second and the poll's round trip. A cache
//! that cannot read the feed stops serving from its store [`STALE`] after
//! its last answer and passes every request to the server (fail closed),
//! public grants included: a policy change can make a public folder private.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use veil_core::hub::grant::{GrantBody, GRANT_TTL_MS, REQUEST_SKEW_MS};

/// How often the cache polls the feed.
pub const POLL: Duration = Duration::from_secs(1);
/// How old a confirmation may be for the cache to serve under it: the
/// owner's bound for removal at caches (`VISIBILITY.md`, "Read grants").
pub const STALE: Duration = Duration::from_secs(5);
/// How long a key is polled for after a grant last named it: a grant's
/// lifetime and the clock skew a request may have.
pub const TRACK_FOR: Duration = Duration::from_millis((GRANT_TTL_MS + REQUEST_SKEW_MS) as u64);
/// Most projects, and most devices, polled for; a grant naming one past it
/// is passed to the server.
pub const MAX_KEYS: usize = 100_000;

#[derive(Debug)]
struct Key {
    /// The current epoch, as last confirmed; `None`: no grant of it holds
    /// (left out of the answer).
    current: Option<i64>,
    /// When the poll that confirmed it was sent.
    confirmed: Option<Instant>,
    used: Instant,
}

#[derive(Default)]
struct Inner {
    grant_key: Option<String>,
    projects: HashMap<String, Key>,
    devices: HashMap<String, Key>,
}

/// The keys of one poll, and when it was sent.
pub struct Asked {
    pub sent: Instant,
    pub projects: Vec<String>,
    pub devices: Vec<String>,
}

#[derive(Default)]
pub struct Tracker {
    inner: Mutex<Inner>,
    /// A new key appeared: poll now.
    pub wake: tokio::sync::Notify,
}

/// Note `name` as used now; whether its confirmed epoch, fresh at `now`,
/// is `want`. A key not yet known is added (up to [`MAX_KEYS`]) and
/// `*new` set.
fn holds(keys: &mut HashMap<String, Key>, name: &str, want: i64, now: Instant, new: &mut bool) -> bool {
    if let Some(k) = keys.get_mut(name) {
        k.used = now;
        return k.current == Some(want) && k.confirmed.is_some_and(|c| now.saturating_duration_since(c) <= STALE);
    }
    if keys.len() < MAX_KEYS {
        keys.insert(name.to_string(), Key { current: None, confirmed: None, used: now });
        *new = true;
    }
    false
}

impl Tracker {
    /// The server's grant key, once a poll has named it.
    pub fn grant_key(&self) -> Option<String> {
        self.inner.lock().unwrap().grant_key.clone()
    }

    /// May the cache serve under a grant with `body`'s epochs at `now`:
    /// were both confirmed current at most [`STALE`] ago? A grant of
    /// anyone on Earth names no device; its person epoch is 0. Notes the
    /// keys for polling either way.
    pub fn current(&self, body: &GrantBody, now: Instant) -> bool {
        let mut new = false;
        let ok = {
            let mut g = self.inner.lock().unwrap();
            let project = holds(&mut g.projects, &body.project, body.epoch, now, &mut new);
            let person = match &body.device {
                Some(d) => holds(&mut g.devices, d, body.person_epoch, now, &mut new),
                None => body.person_epoch == 0,
            };
            project && person
        };
        if new {
            self.wake.notify_one();
        }
        ok
    }

    /// The keys to poll at `now`, after dropping those no grant named for
    /// [`TRACK_FOR`].
    pub fn to_ask(&self, now: Instant) -> Asked {
        let mut g = self.inner.lock().unwrap();
        let live = |k: &Key| now.saturating_duration_since(k.used) <= TRACK_FOR;
        g.projects.retain(|_, k| live(k));
        g.devices.retain(|_, k| live(k));
        Asked {
            sent: now,
            projects: g.projects.keys().cloned().collect(),
            devices: g.devices.keys().cloned().collect(),
        }
    }

    /// Record the server's answer to the poll `asked`: every key asked is
    /// confirmed at its send time, with the epoch answered or none.
    pub fn apply(&self, asked: &Asked, answer: &super::feed::FeedAnswer) {
        let mut g = self.inner.lock().unwrap();
        g.grant_key = Some(answer.grant_key.clone());
        let set = |keys: &mut HashMap<String, Key>, names: &[String], answered: &std::collections::BTreeMap<String, i64>| {
            for n in names {
                if let Some(k) = keys.get_mut(n) {
                    // Polls run one at a time; never move a confirmation back.
                    if k.confirmed.is_none_or(|c| c <= asked.sent) {
                        k.current = answered.get(n).copied();
                        k.confirmed = Some(asked.sent);
                    }
                }
            }
        };
        set(&mut g.projects, &asked.projects, &answer.projects);
        set(&mut g.devices, &asked.devices, &answer.devices);
    }

    /// How many keys it polls for (projects, devices).
    pub fn len(&self) -> (usize, usize) {
        let g = self.inner.lock().unwrap();
        (g.projects.len(), g.devices.len())
    }
}

#[cfg(test)]
mod tests {
    use super::{super::feed::FeedAnswer, *};
    use veil_core::ObjectId;

    fn body(project: &str, device: Option<&str>, epoch: i64, person_epoch: i64) -> GrantBody {
        GrantBody {
            project: project.into(),
            device: device.map(str::to_string),
            root: ObjectId([1; 32]),
            epoch,
            person_epoch,
            expires: i64::MAX,
        }
    }

    fn answer(projects: &[(&str, i64)], devices: &[(&str, i64)]) -> FeedAnswer {
        FeedAnswer {
            grant_key: "k".into(),
            projects: projects.iter().map(|(n, e)| (n.to_string(), *e)).collect(),
            devices: devices.iter().map(|(n, e)| (n.to_string(), *e)).collect(),
        }
    }

    #[test]
    fn a_grant_holds_only_while_both_epochs_are_confirmed_and_fresh() {
        let t = Tracker::default();
        let t0 = Instant::now();
        let b = body("acme", Some("dev"), 7, 9);
        // Unknown keys: never served, and noted for the next poll.
        assert!(!t.current(&b, t0));
        let asked = t.to_ask(t0);
        assert_eq!((asked.projects.clone(), asked.devices.clone()), (vec!["acme".to_string()], vec!["dev".to_string()]));
        t.apply(&asked, &answer(&[("acme", 7)], &[("dev", 9)]));
        assert!(t.current(&b, t0 + Duration::from_secs(1)));
        assert!(t.current(&b, t0 + STALE), "fresh up to the bound");
        assert!(!t.current(&b, t0 + STALE + Duration::from_millis(1)), "stale after it: fail closed");
        // Another epoch than the grant's, newer or older, of either key.
        for (e, pe) in [(8, 9), (6, 9), (7, 8), (7, 0), (0, 9)] {
            assert!(!t.current(&body("acme", Some("dev"), e, pe), t0), "{e} {pe}");
        }
        // A removal: the next poll answers another person epoch, or leaves
        // the device (or the project) out.
        let a2 = t.to_ask(t0 + Duration::from_secs(1));
        t.apply(&a2, &answer(&[("acme", 7)], &[]));
        assert!(!t.current(&b, t0 + Duration::from_secs(1)));
        let a3 = t.to_ask(t0 + Duration::from_secs(2));
        t.apply(&a3, &answer(&[], &[("dev", 9)]));
        assert!(!t.current(&b, t0 + Duration::from_secs(2)));
        // An answer to an older poll never overrides a newer one.
        let old = Asked { sent: t0, projects: vec!["acme".into()], devices: vec!["dev".into()] };
        t.apply(&old, &answer(&[("acme", 7)], &[("dev", 9)]));
        assert!(!t.current(&b, t0 + Duration::from_secs(2)));
        // Anyone on Earth: no device, person epoch 0 only.
        let a4 = t.to_ask(t0 + Duration::from_secs(3));
        t.apply(&a4, &answer(&[("acme", 7)], &[]));
        assert!(t.current(&body("acme", None, 7, 0), t0 + Duration::from_secs(3)));
        assert!(!t.current(&body("acme", None, 7, 9), t0 + Duration::from_secs(3)));
    }

    #[test]
    fn keys_are_dropped_when_no_grant_names_them_and_bounded() {
        let t = Tracker::default();
        let t0 = Instant::now();
        t.current(&body("a", Some("d"), 1, 1), t0);
        assert_eq!(t.len(), (1, 1));
        t.to_ask(t0 + TRACK_FOR);
        assert_eq!(t.len(), (1, 1));
        t.to_ask(t0 + TRACK_FOR + Duration::from_millis(1));
        assert_eq!(t.len(), (0, 0));
        for i in 0..MAX_KEYS + 10 {
            t.current(&body(&format!("p{i}"), None, 1, 0), t0);
        }
        assert_eq!(t.len().0, MAX_KEYS);
        // A key past the bound is never served from the store.
        let a = t.to_ask(t0);
        t.apply(&a, &answer(&[(&format!("p{}", MAX_KEYS + 5), 1)], &[]));
        assert!(!t.current(&body(&format!("p{}", MAX_KEYS + 5), None, 1, 0), t0));
    }
}
