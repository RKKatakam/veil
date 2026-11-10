//! Limits on the landing service (milestone S24, part B; `docs/HUB.md`
//! §13.32; `docs/design/server/phase-4-agent-scale.md` §4.11):
//!
//! * **Outstanding landings per agent session and per person**
//!   ([`admit_queue`]): each agent session may have at most
//!   [`MAX_SESSION_OUTSTANDING`] (100) queued landings waiting at once, and
//!   each person at most [`MAX_PERSON_OUTSTANDING`] (1,000, ten times an
//!   agent session's). Checked inside the submit's database transaction
//!   under the person's row lock (`SELECT id FROM people WHERE id = $1 FOR
//!   UPDATE`), so the bound holds across every server sharing the database,
//!   and a refused submit rolls back the whole transaction (nothing
//!   half-lands). The refusal is `429 rate_limited` with `retry_after_ms`
//!   and names nothing outside the caller's own session or person bound.
//! * **Each submitter's fair share of a batch** ([`fair_batch`]): a batch
//!   takes queued landings in two-level round-robin order — first across
//!   people (`person_id`), then across each person's sessions (`session`, or
//!   `device_key` for a person's own session), with FIFO order (`created_at,
//!   seq`) within each session. One person's or one session's flood never
//!   delays another person's landing beyond its fair share.

use std::collections::{HashMap, HashSet, VecDeque};

use axum::http::StatusCode;
use sqlx::PgConnection;

use crate::{
    error::{Error, Result},
    landing::{encode_stack, Queued, Submitter},
    limits::Settings,
};

/// Default cap on queued landings waiting at once for one agent session
/// (design §4.11).
pub const MAX_SESSION_OUTSTANDING: usize = 100;
/// Default cap on queued landings waiting at once for one person (ten times
/// [`MAX_SESSION_OUTSTANDING`]).
pub const MAX_PERSON_OUTSTANDING: usize = 10 * MAX_SESSION_OUTSTANDING;
/// Suggested retry wait when a caller's landing queue is full.
const RETRY_AFTER_MS: u64 = 1_000;

/// The bounds in effect for the current request's server (set by
/// [`super::admit`]; defaults outside a request).
pub fn bounds() -> (usize, usize) {
    super::BOUNDS
        .try_with(|b| b.get())
        .unwrap_or((MAX_SESSION_OUTSTANDING, MAX_PERSON_OUTSTANDING))
}

/// The session key stored in `landing_queue.session` for `who`: the stored
/// session hash for an agent session, empty for a person's own session.
pub fn session_of(who: &Submitter) -> &str {
    who.person.agent.as_ref().map_or("", |a| a.session.as_str())
}

/// Check `who`'s outstanding-landing bounds and insert `q` into
/// `landing_queue` in the caller's transaction.
///
/// Locking the submitter's row in `people` serializes concurrent submissions
/// by the same person across all servers sharing the database, without
/// blocking any other person's landings.
pub async fn admit_queue(c: &mut PgConnection, project: i64, who: &Submitter, q: &Queued) -> Result<()> {
    let (max_session, max_person) = bounds();
    let session = session_of(who);
    let _: Option<i64> = sqlx::query_scalar("SELECT id FROM people WHERE id = $1 FOR UPDATE")
        .bind(who.person.id)
        .fetch_optional(&mut *c)
        .await?;
    let (person_queued, session_queued): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE session = $3) FROM landing_queue \
         WHERE project_id = $1 AND person_id = $2 AND state = 'queued'",
    )
    .bind(project)
    .bind(who.person.id)
    .bind(session)
    .fetch_one(&mut *c)
    .await?;
    if !session.is_empty() && session_queued as usize >= max_session {
        return Err(Error::rate_limited(
            format!(
                "this agent session already has {max_session} landings waiting in the queue; \
                 wait for them to finish before submitting more"
            ),
            RETRY_AFTER_MS,
        ));
    }
    if person_queued as usize >= max_person {
        return Err(Error::rate_limited(
            format!(
                "you already have {max_person} landings waiting in the queue; \
                 wait for them to finish before submitting more"
            ),
            RETRY_AFTER_MS,
        ));
    }
    sqlx::query(
        "INSERT INTO landing_queue (project_id, branch, ticket, person_id, person_name, device_key, session, stack, lineage, person_epoch, \
         project_epoch, state, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'queued', \
         (extract(epoch FROM clock_timestamp()) * 1000000)::BIGINT)",
    )
    .bind(project)
    .bind(&q.branch)
    .bind(&q.ticket)
    .bind(who.person.id)
    .bind(&who.person.name)
    .bind(&who.person.device_key)
    .bind(session)
    .bind(encode_stack(&q.stack))
    .bind(q.lineage)
    .bind(who.epochs.person)
    .bind(who.epochs.project.map_or(0, |(_, e)| e))
    .execute(&mut *c)
    .await?;
    Ok(())
}

/// A queued row's identity for fair-share scheduling.
pub trait QueuedEntry {
    fn seq(&self) -> i64;
    fn person_id(&self) -> i64;
    /// The session key (`landing_queue.session` when non-empty, else
    /// `device_key`).
    fn session_key(&self) -> &str;
}

/// Select up to `limit` entries from `rows` (already ordered by
/// `created_at, seq`) in two-level round-robin order:
/// 1. Round-robin over people (`person_id`), ordered by each person's
///    earliest queued entry;
/// 2. Within each person, round-robin over their active sessions
///    (`session_key`), ordered by each session's earliest queued entry;
/// 3. Within each session, FIFO (`created_at, seq`).
///
/// Entries whose `seq` is in `exclude` (already in flight) are skipped.
pub fn fair_batch<T: QueuedEntry>(rows: Vec<T>, exclude: &HashSet<i64>, limit: usize) -> Vec<T> {
    if limit == 0 || rows.is_empty() {
        return Vec::new();
    }
    struct PersonQueue<T> {
        session_order: VecDeque<String>,
        sessions: HashMap<String, VecDeque<T>>,
    }
    let mut people_order: VecDeque<i64> = VecDeque::new();
    let mut people: HashMap<i64, PersonQueue<T>> = HashMap::new();
    for row in rows {
        if exclude.contains(&row.seq()) {
            continue;
        }
        let pid = row.person_id();
        let skey = row.session_key().to_string();
        let pq = people.entry(pid).or_insert_with(|| {
            people_order.push_back(pid);
            PersonQueue {
                session_order: VecDeque::new(),
                sessions: HashMap::new(),
            }
        });
        let sq = pq.sessions.entry(skey.clone()).or_insert_with(|| {
            pq.session_order.push_back(skey);
            VecDeque::new()
        });
        sq.push_back(row);
    }
    let mut out = Vec::with_capacity(limit.min(people.len().saturating_mul(2)));
    while out.len() < limit && !people_order.is_empty() {
        let pid = people_order.pop_front().unwrap();
        let Some(pq) = people.get_mut(&pid) else { continue };
        while let Some(skey) = pq.session_order.pop_front() {
            if let Some(sq) = pq.sessions.get_mut(&skey) {
                if let Some(item) = sq.pop_front() {
                    out.push(item);
                    if !sq.is_empty() {
                        pq.session_order.push_back(skey);
                    } else {
                        pq.sessions.remove(&skey);
                    }
                    break;
                }
            }
        }
        if !pq.session_order.is_empty() {
            people_order.push_back(pid);
        } else {
            people.remove(&pid);
        }
    }
    out
}

/// Settings helper for bounds.
pub fn settings_bounds(s: &Settings) -> (usize, usize) {
    (s.max_session_outstanding.max(1), s.max_person_outstanding.max(1))
}

/// Whether an error is a `429 rate_limited` refusal.
pub fn is_rate_limited(e: &Error) -> bool {
    matches!(e, Error::Api { status, .. } if *status == StatusCode::TOO_MANY_REQUESTS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct Item {
        seq: i64,
        person: i64,
        session: &'static str,
    }

    impl QueuedEntry for Item {
        fn seq(&self) -> i64 {
            self.seq
        }
        fn person_id(&self) -> i64 {
            self.person
        }
        fn session_key(&self) -> &str {
            self.session
        }
    }

    #[test]
    fn fair_batch_round_robins_over_people_then_sessions() {
        let mut rows = Vec::new();
        for i in 1..=4 {
            rows.push(Item { seq: i, person: 1, session: "s1" });
        }
        for i in 5..=6 {
            rows.push(Item { seq: i, person: 1, session: "s2" });
        }
        rows.push(Item { seq: 7, person: 2, session: "d2" });
        let picked = fair_batch(rows, &HashSet::new(), 10);
        let seqs: Vec<i64> = picked.iter().map(|x| x.seq).collect();
        // Turn 1: person 1 (s1: seq 1), person 2 (d2: seq 7)
        // Turn 2+: person 1 alternates s2 (seq 5), s1 (seq 2), s2 (seq 6), s1 (seq 3), s1 (seq 4)
        assert_eq!(seqs, vec![1, 7, 5, 2, 6, 3, 4]);
    }
}
