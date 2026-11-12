//! Early back-pressure on a branch's landing queue (BUG-1955; `docs/HUB.md`
//! §13.32, item 6).
//!
//! A landing service lands what it can; past that, its queue grows. Until
//! this, nothing told a submitter: its request waited out the server's 30 s
//! ([`crate::landing::WAIT`]), answered `queued`, the agent submitted again,
//! and the service went on landing changes nobody waited for.
//!
//! Now a submit is refused **before any work is done for it** when more
//! landings would land before it than the service takes at a time
//! ([`MAX_BRANCH_WAITING`]), or than it lands within [`MAX_QUEUE_WAIT`] at
//! the rate it is landing now. The answer is `503 queue_full` with
//! `retry_after_ms`: how long the service needs for what is over the bound
//! (at least [`RETRY_MIN`]).
//!
//! **"Before it" follows the service's own order** ([`super::landing::fair_batch`]:
//! round robin over people, then over each person's sessions), so the
//! bound is each submitter's fair share of the queue and one person's flood
//! never has another person's landing refused: a person with nothing
//! waiting has at most one landing of each other person before theirs
//! ([`ahead`]).
//!
//! What waits is read from the database (every server's submits are in it),
//! at most once every [`REFRESH`] for a branch, in one statement; between
//! two reads a server adds its own admitted submits. The service's rate is
//! the count of entries it served, which it keeps in its lease row
//! (`landing_leases.served`, migration 37) in the batch's own transaction.
//! Nothing here is a guarantee of the exact bounds (those are
//! [`super::landing::admit_queue`]'s slots): it sheds load early, and may
//! admit a few more than the bound between two reads.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::{error::Result, landing::MAX_BATCH, Hub};

/// Most landings that may be due to land before a new one on a branch: 32
/// batches. Above a person's own bound ([`super::landing::MAX_PERSON_OUTSTANDING`]),
/// so one person alone meets only that one.
pub const MAX_BRANCH_WAITING: usize = 32 * MAX_BATCH;
/// The longest a new landing may be due to wait in the queue, at the rate
/// the service lands now: a third of what its request waits
/// ([`crate::landing::WAIT`]).
pub const MAX_QUEUE_WAIT: Duration = Duration::from_secs(10);
/// The shortest and longest wait a refusal asks for.
pub const RETRY_MIN: Duration = Duration::from_secs(1);
pub const RETRY_MAX: Duration = Duration::from_secs(5);
/// How long what was read of a branch's queue is used.
const REFRESH: Duration = Duration::from_millis(100);
/// The service's rate is taken over about this long, and from readings at
/// least [`RATE_MIN_MS`] apart.
const RATE_OVER_MS: i64 = 2_000;
const RATE_MIN_MS: i64 = 400;
/// A branch nobody submitted to for this long is forgotten.
const FORGET: Duration = Duration::from_secs(60);

/// The landings waiting on a branch, by person and session (as the
/// service's order names a session: `QueuedEntry::session_key`).
#[derive(Default, Clone, Debug)]
pub struct Waiting {
    by: HashMap<i64, HashMap<String, usize>>,
}

impl Waiting {
    pub fn add(&mut self, person: i64, session: &str, n: usize) {
        *self.by.entry(person).or_default().entry(session.to_string()).or_default() += n;
    }

    /// How many landings land before a new one of `person`'s `session`, in
    /// the service's order: of the person's own, every session's up to one
    /// more than this session has (round robin over sessions); of each
    /// other person's, up to one more than that (round robin over people).
    pub fn ahead(&self, person: i64, session: &str) -> usize {
        let mine = self.by.get(&person);
        let in_session = mine.and_then(|s| s.get(session)).copied().unwrap_or(0);
        let own: usize = mine.map_or(0, |s| s.iter().map(|(k, n)| if k == session { *n } else { (*n).min(in_session + 1) }).sum());
        let others: usize = self.by.iter().filter(|(p, _)| **p != person).map(|(_, s)| s.values().sum::<usize>().min(own + 1)).sum();
        own + others
    }
}

/// Whether a landing with `ahead` landings before it is refused, at `rate`
/// entries a second served now (`None`: not known, or nothing is being
/// served) and a bound of `max` landings: how long to wait before
/// submitting again.
pub fn refuse(ahead: usize, rate: Option<f64>, max: usize) -> Option<Duration> {
    let rate = rate.filter(|r| *r > 0.0);
    // The rate is the service's capacity only while it has more than it
    // takes at once: a short queue is never refused for a slow moment.
    let in_time = rate.map_or(usize::MAX, |r| ((r * MAX_QUEUE_WAIT.as_secs_f64()) as usize).max(2 * MAX_BATCH));
    let bound = max.min(in_time);
    if ahead < bound {
        return None;
    }
    let over = (ahead + 1 - bound) as f64;
    Some(match rate {
        Some(r) => Duration::from_secs_f64((over / r).clamp(RETRY_MIN.as_secs_f64(), RETRY_MAX.as_secs_f64())),
        None => RETRY_MIN,
    })
}

/// What one server knows of a branch's queue.
#[derive(Default)]
struct Gauge {
    read: Option<Instant>,
    waiting: Waiting,
    /// `(the database's clock in ms, entries served so far)`, oldest first.
    served: VecDeque<(i64, i64)>,
}

impl Gauge {
    fn fresh(&self) -> bool {
        self.read.is_some_and(|t| t.elapsed() < REFRESH)
    }

    /// Entries a second the service served over the last readings.
    fn rate(&self) -> Option<f64> {
        let (now, served) = *self.served.back()?;
        let (then, before) = *self.served.iter().find(|(t, _)| now - t <= RATE_OVER_MS)?;
        (now - then >= RATE_MIN_MS && served >= before).then(|| (served - before) as f64 * 1000.0 / (now - then) as f64)
    }
}

type Branch = (i64, String);

/// Every branch's gauge on this server.
#[derive(Default)]
pub struct Gauges {
    by: Mutex<HashMap<Branch, Arc<(Mutex<Gauge>, tokio::sync::Mutex<()>)>>>,
}

/// A refused submit: what to say, and when to come back.
pub struct Refused {
    pub message: String,
    pub wait: Duration,
}

impl Refused {
    pub fn response(&self) -> axum::response::Response {
        super::refuse(axum::http::StatusCode::SERVICE_UNAVAILABLE, "queue_full", &self.message, Some(self.wait), false)
    }
}

/// Is a new landing of `person`'s `session` onto `branch` refused for now
/// (see the module)? Asked before anything is done for the submit; one
/// admitted is counted here at once.
pub async fn admit(hub: &Hub, project: i64, branch: &str, who: &crate::landing::Submitter) -> Result<Option<Refused>> {
    // The session as the service's order has it (`QueuedEntry::session_key`).
    let person = who.person.id;
    let session = match super::landing::session_of(who) {
        "" => who.person.device_key.as_str(),
        s => s,
    };
    let key: Branch = (project, branch.to_string());
    let gauge = {
        let mut by = hub.landing.pressure.by.lock().unwrap();
        if by.len() > 1024 {
            by.retain(|_, g| g.0.lock().unwrap().read.is_some_and(|t| t.elapsed() < FORGET));
        }
        by.entry(key).or_default().clone()
    };
    if !gauge.0.lock().unwrap().fresh() {
        // One reader at a time; the others use what it read.
        let _reading = gauge.1.lock().await;
        if !gauge.0.lock().unwrap().fresh() {
            let rows: Vec<(i64, String, i64, i64)> = sqlx::query_as(
                "SELECT person_id, CASE WHEN session = '' THEN device_key ELSE session END, COUNT(*)::BIGINT, 0::BIGINT FROM landing_queue \
                 WHERE project_id = $1 AND branch = $2 AND state IN ('queued', 'merging') GROUP BY 1, 2 \
                 UNION ALL \
                 SELECT -1, '', COALESCE((SELECT served FROM landing_leases WHERE project_id = $1 AND branch = $2), 0), \
                 (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
            )
            .bind(project)
            .bind(branch)
            .fetch_all(&hub.db)
            .await?;
            let mut g = gauge.0.lock().unwrap();
            g.waiting = Waiting::default();
            for (person, session, n, now) in rows {
                if now == 0 {
                    g.waiting.add(person, &session, n.max(0) as usize);
                    continue;
                }
                while g.served.front().is_some_and(|(t, _)| now - t > 2 * RATE_OVER_MS) {
                    g.served.pop_front();
                }
                g.served.push_back((now, n));
            }
            g.read = Some(Instant::now());
        }
    }
    let mut g = gauge.0.lock().unwrap();
    let ahead = g.waiting.ahead(person, session);
    match refuse(ahead, g.rate(), hub.limits.settings.max_branch_waiting.max(1)) {
        None => {
            g.waiting.add(person, session, 1);
            Ok(None)
        }
        Some(wait) => {
            hub.landing.stats.queue_full.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(Some(Refused {
                message: format!("the landing queue of '{branch}' is full (landings are arriving faster than they land); try again in a few seconds"),
                wait,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn waiting(rows: &[(i64, &str, usize)]) -> Waiting {
        let mut w = Waiting::default();
        for (p, s, n) in rows {
            w.add(*p, s, *n);
        }
        w
    }

    /// What is before a new landing follows the service's order: one
    /// person's flood counts once a round for everyone else, and one
    /// session's flood once a round for the person's other sessions.
    #[test]
    fn ahead_is_the_fair_position() {
        // Nothing waits.
        assert_eq!(Waiting::default().ahead(1, ""), 0);
        // One person alone: their own.
        assert_eq!(waiting(&[(1, "", 40)]).ahead(1, ""), 40);
        // Behind a flood of 1,000 of one person: someone else's first
        // landing has one before it, their second two.
        let w = waiting(&[(1, "", 1000)]);
        assert_eq!(w.ahead(2, ""), 1);
        assert_eq!(waiting(&[(1, "", 1000), (2, "", 1)]).ahead(2, ""), 3);
        // The flooder has everyone's before theirs.
        assert_eq!(waiting(&[(1, "", 1000), (2, "", 5), (3, "", 7)]).ahead(1, ""), 1012);
        // A hundred people with 20 each: 2,000 before the next of any, 100
        // before a newcomer's.
        let rows: Vec<(i64, &str, usize)> = (1..=100).map(|p| (p, "", 20)).collect();
        assert_eq!(waiting(&rows).ahead(7, ""), 20 + 99 * 20);
        assert_eq!(waiting(&rows).ahead(500, ""), 100);
        // Sessions of one person: a new session's first landing has one of
        // the flooding session's before it.
        let w = waiting(&[(1, "a", 100), (1, "b", 2)]);
        assert_eq!(w.ahead(1, "c"), 2);
        assert_eq!(w.ahead(1, "b"), 2 + 3);
        assert_eq!(w.ahead(1, "a"), 102);
        // And then one of each other person's more than that.
        assert_eq!(waiting(&[(1, "a", 100), (1, "b", 2), (2, "", 50)]).ahead(1, "c"), 2 + 3);
    }

    /// The position agrees with the batches the service takes: the entries
    /// that land before a new one in `fair_batch`'s order.
    #[test]
    fn ahead_bounds_what_fair_batches_land_first() {
        use crate::limits::landing::{fair_batch, QueuedEntry};
        #[derive(Clone)]
        struct Item(i64, i64, String);
        impl QueuedEntry for Item {
            fn seq(&self) -> i64 {
                self.0
            }
            fn person_id(&self) -> i64 {
                self.1
            }
            fn session_key(&self) -> &str {
                &self.2
            }
        }
        // A seeded mix of people and sessions, in arrival order.
        let mut state = 0x9e3779b97f4a7c15u64;
        let mut next = |n: u64| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) % n
        };
        for _ in 0..200 {
            let queue: Vec<Item> = (0..next(300)).map(|i| Item(i as i64, 1 + next(5) as i64, format!("s{}", next(3)))).collect();
            let (person, session) = (1 + next(6) as i64, format!("s{}", next(4)));
            let mut w = Waiting::default();
            for q in &queue {
                w.add(q.1, &q.2, 1);
            }
            let mut all = queue.clone();
            all.push(Item(i64::MAX, person, session.clone()));
            let order = fair_batch(all, &Default::default(), usize::MAX);
            let before = order.iter().position(|q| q.0 == i64::MAX).expect("the new entry is in the order");
            assert!(before <= w.ahead(person, &session), "{before} land first, {} counted", w.ahead(person, &session));
        }
    }

    #[test]
    fn a_submit_is_refused_past_the_bound_with_the_time_the_service_needs() {
        // Below the bound: admitted, whatever the rate.
        assert_eq!(refuse(2047, None, 2048), None);
        assert_eq!(refuse(2047, Some(1000.0), 2048), None);
        // At the bound: refused; a second by default, the time for what is
        // over at the service's rate otherwise, within the limits.
        assert_eq!(refuse(2048, None, 2048), Some(RETRY_MIN));
        assert_eq!(refuse(2048, Some(1000.0), 2048), Some(RETRY_MIN));
        assert_eq!(refuse(5048, Some(1000.0), 2048), Some(Duration::from_secs_f64(3.001)));
        assert_eq!(refuse(50_000, Some(1000.0), 2048), Some(RETRY_MAX));
        // A slow service: what it lands in ten seconds, never less than two
        // batches (a rate measured while it had little to do is no bound).
        assert_eq!(refuse(499, Some(50.0), 2048), None);
        assert_eq!(refuse(500, Some(50.0), 2048), Some(RETRY_MIN));
        assert_eq!(refuse(700, Some(50.0), 2048), Some(Duration::from_secs_f64(201.0 / 50.0)));
        assert_eq!(refuse(127, Some(1.0), 2048), None);
        assert_eq!(refuse(128, Some(1.0), 2048), Some(RETRY_MIN));
        // A service that lands nothing (its lease held elsewhere, a branch
        // held): the count alone.
        assert_eq!(refuse(1500, Some(0.0), 2048), None);
        assert_eq!(refuse(2048, Some(0.0), 2048), Some(RETRY_MIN));
    }

    #[test]
    fn the_rate_is_what_was_served_over_the_last_readings() {
        let mut g = Gauge::default();
        assert_eq!(g.rate(), None);
        g.served.push_back((10_000, 500));
        assert_eq!(g.rate(), None);
        // Too close together to say.
        g.served.push_back((10_100, 600));
        assert_eq!(g.rate(), None);
        g.served.push_back((10_500, 1000));
        assert_eq!(g.rate(), Some(1000.0));
        // Over the last two seconds only.
        g.served.push_back((13_000, 1500));
        g.served.push_back((14_000, 3500));
        assert_eq!(g.rate(), Some(2000.0));
    }
}
