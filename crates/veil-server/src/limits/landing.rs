//! Limits on the landing service (milestone S24, part B; `docs/HUB.md`
//! §13.32; `docs/design/server/phase-4-agent-scale.md` §4.11):
//!
//! * **Outstanding landings per agent session and per person**
//!   ([`admit_queue`]): each agent session may have at most
//!   [`MAX_SESSION_OUTSTANDING`] (100) queued landings waiting at once, and
//!   each person at most [`MAX_PERSON_OUTSTANDING`] (1,000, ten times an
//!   agent session's). Each waiting landing holds one of its person's slots
//!   and one of its session's (`landing_queue.person_slot`, `session_slot`),
//!   and a unique index on each is the bound: it is exact across every
//!   server sharing the database, and no submit waits for another of the
//!   same person (BUG-1940: the person's row was locked for the whole of the
//!   submit's transaction). A refused submit rolls back the whole
//!   transaction (nothing half-lands). The refusal is `429 rate_limited`
//!   with `retry_after_ms` and names nothing outside the caller's own
//!   session or person bound.
//! * **Each submitter's fair share of a batch** ([`fair_batch`]): a batch
//!   takes queued landings in two-level round-robin order — first across
//!   people (`person_id`), then across each person's sessions (`session`, or
//!   `device_key` for a person's own session), with FIFO order (`created_at,
//!   seq`) within each session. One person's or one session's flood never
//!   delays another person's landing beyond its fair share.
//! * **A batch is chosen from a bounded read of the queue** ([`pick_batch`],
//!   BUG-1941): the queue is read in its order, [`PICK_CHUNK`] rows at a
//!   time, leaving out the people and sessions no further row of which can
//!   be in the batch ([`FairPick`]), until no row not yet read can be. The
//!   batch is the one [`fair_batch`] takes from the whole queue.

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
    super::request_bounds().unwrap_or((MAX_SESSION_OUTSTANDING, MAX_PERSON_OUTSTANDING))
}

/// The session key stored in `landing_queue.session` for `who`: the stored
/// session hash for an agent session, empty for a person's own session.
pub fn session_of(who: &Submitter) -> &str {
    who.person.agent.as_ref().map_or("", |a| a.session.as_str())
}

/// How many times a submit takes another slot after losing one to a submit
/// of the same person that committed first. Each loss is a landing of that
/// person queued meanwhile, so the bounds end it long before.
const ADMIT_TRIES: usize = 64;

/// A slot below `max` that none of `taken` holds, chosen at random so that
/// submits in flight at the same instant seldom choose the same one.
fn free_slot(taken: &[i32], max: usize) -> Option<i32> {
    let taken: HashSet<i32> = taken.iter().copied().collect();
    let free: Vec<i32> = (0..max.min(i32::MAX as usize) as i32).filter(|s| !taken.contains(s)).collect();
    if free.is_empty() {
        return None;
    }
    let r = u64::from_le_bytes(veil_core::crypto::random_bytes::<8>());
    Some(free[(r % free.len() as u64) as usize])
}

/// Check `who`'s outstanding-landing bounds and insert `q` into
/// `landing_queue` in the caller's transaction.
///
/// The row takes a free slot of the person and, from an agent session, of
/// the session; the unique indexes on the slots of waiting rows
/// (`landing_queue_person_slot`, `landing_queue_session_slot`) are the
/// bounds, exact across all servers sharing the database. Nothing is locked
/// that another submit of the same person needs, so they do not wait for
/// one another (BUG-1940); two that choose the same slot at the same instant
/// are decided by the index, and the one that lost takes another.
pub async fn admit_queue(c: &mut PgConnection, project: i64, who: &Submitter, q: &Queued) -> Result<()> {
    let (max_session, max_person) = bounds();
    let session = session_of(who);
    for _ in 0..ADMIT_TRIES {
        let (person_queued, session_queued, person_slots, session_slots): (i64, i64, Vec<i32>, Vec<i32>) = sqlx::query_as(
            "SELECT COUNT(*), COUNT(*) FILTER (WHERE session = $3), \
             COALESCE(ARRAY_AGG(person_slot) FILTER (WHERE person_slot IS NOT NULL), '{}'), \
             COALESCE(ARRAY_AGG(session_slot) FILTER (WHERE session = $3 AND session_slot IS NOT NULL), '{}') \
             FROM landing_queue WHERE project_id = $1 AND person_id = $2 AND state IN ('queued', 'merging')",
        )
        .bind(project)
        .bind(who.person.id)
        .bind(session)
        .fetch_one(&mut *c)
        .await?;
        let session_slot = if session.is_empty() {
            None
        } else {
            match free_slot(&session_slots, max_session).filter(|_| (session_queued as usize) < max_session) {
                Some(s) => Some(s),
                None => {
                    return Err(Error::rate_limited(
                        format!(
                            "this agent session already has {max_session} landings waiting in the queue; \
                             wait for them to finish before submitting more"
                        ),
                        RETRY_AFTER_MS,
                    ))
                }
            }
        };
        let Some(person_slot) = free_slot(&person_slots, max_person).filter(|_| (person_queued as usize) < max_person) else {
            return Err(Error::rate_limited(
                format!(
                    "you already have {max_person} landings waiting in the queue; \
                     wait for them to finish before submitting more"
                ),
                RETRY_AFTER_MS,
            ));
        };
        // `ON CONFLICT DO NOTHING`: a submit of the same person in flight
        // holds the slot. This one waits only if that one has not committed
        // yet, and then reads the slots again.
        let inserted = sqlx::query(
            "INSERT INTO landing_queue (project_id, branch, ticket, person_id, person_name, device_key, session, stack, lineage, person_epoch, \
             project_epoch, agent_session, person_slot, session_slot, state, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'queued', \
             (extract(epoch FROM clock_timestamp()) * 1000000)::BIGINT) ON CONFLICT DO NOTHING",
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
        .bind(who.person.agent.as_ref().map(|a| a.session_hash.as_str()))
        .bind(person_slot)
        .bind(session_slot)
        .execute(&mut *c)
        .await?
        .rows_affected();
        if inserted == 1 {
            return Ok(());
        }
    }
    Err(Error::busy())
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

/// What the next read of the queue leaves out ([`FairPick::add`]): no
/// further row of these can be in the batch.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Skip {
    /// People (`person_id`).
    pub people: Vec<i64>,
    /// Sessions of the other people ([`session_id`]).
    pub sessions: Vec<String>,
}

/// A session's name in [`Skip::sessions`]: its person and its session key.
/// `pick_batch`'s statement writes the same.
pub fn session_id(person: i64, session_key: &str) -> String {
    format!("{person}/{session_key}")
}

/// Chooses the batch [`fair_batch`] takes from a whole queue from a bounded
/// read of it (BUG-1941): the queue's rows are added in its order, a chunk
/// at a time, and after each chunk [`FairPick::add`] says which people and
/// sessions the next read leaves out, or that no row not yet read can be in
/// the batch.
///
/// Why leaving them out is exact: in round-robin order a row comes no
/// earlier when rows are added to the queue behind it. So if the next row a
/// session (a person's next session, the next person) could have would not
/// be among the first `limit` of the rows read so far with it added, no
/// later row of it is in the batch either, whatever else the queue holds.
pub struct FairPick<T> {
    limit: usize,
    rows: Vec<T>,
}

impl<T: QueuedEntry> FairPick<T> {
    pub fn new(limit: usize) -> Self {
        FairPick { limit, rows: Vec::new() }
    }

    /// Add the queue's next rows (in its order; none of what the last
    /// [`Skip`] left out). `None`: no row not yet read can be in the batch.
    /// `Some`: read on, leaving these out.
    pub fn add(&mut self, rows: Vec<T>) -> Option<Skip> {
        self.rows.extend(rows);
        // Each person's sessions and how many rows each has, in the order
        // they first appear.
        let mut people: Vec<(i64, Vec<(&str, usize)>)> = Vec::new();
        let mut person_at: HashMap<i64, usize> = HashMap::new();
        let mut session_at: HashMap<(i64, &str), usize> = HashMap::new();
        for r in &self.rows {
            let p = *person_at.entry(r.person_id()).or_insert_with(|| {
                people.push((r.person_id(), Vec::new()));
                people.len() - 1
            });
            let sessions = &mut people[p].1;
            let s = *session_at.entry((r.person_id(), r.session_key())).or_insert_with(|| {
                sessions.push((r.session_key(), 0));
                sessions.len() - 1
            });
            sessions[s].1 += 1;
        }
        let totals: Vec<usize> = people.iter().map(|(_, ss)| ss.iter().map(|s| s.1).sum()).collect();
        // Where person `p`'s `j`th row (from 1) comes in round-robin order
        // (from 0): after the first `j - 1` rows of everyone, and the `j`th
        // of those ahead of `p`.
        let place = |p: usize, j: usize| -> usize {
            totals.iter().map(|n| (*n).min(j - 1)).sum::<usize>() + totals[..p].iter().filter(|n| **n >= j).count()
        };
        let mut skip = Skip::default();
        // A person not seen yet comes after the first row of each one seen.
        let mut open = people.len() < self.limit;
        for (p, (person, sessions)) in people.iter().enumerate() {
            // A session of `p` not seen yet: after the first row of each
            // one seen.
            let mut person_open = place(p, sessions.len() + 1) < self.limit;
            let mut closed = Vec::new();
            for (s, (key, m)) in sessions.iter().enumerate() {
                // The session's next row: `p`'s row after the first `m` of
                // each of its sessions, and the next of those ahead of it.
                let j = sessions.iter().map(|x| x.1.min(*m)).sum::<usize>() + sessions[..s].iter().filter(|x| x.1 > *m).count() + 1;
                if place(p, j) < self.limit {
                    person_open = true;
                } else {
                    closed.push(session_id(*person, key));
                }
            }
            if person_open {
                open = true;
                skip.sessions.extend(closed);
            } else {
                skip.people.push(*person);
            }
        }
        open.then_some(skip)
    }

    /// The batch, in its order.
    pub fn finish(self) -> Vec<T> {
        fair_batch(self.rows, &HashSet::new(), self.limit)
    }
}

/// How many rows of the queue one statement of [`pick_batch`] reads.
pub const PICK_CHUNK: usize = 256;

/// A queued row as [`pick_batch`] reads it.
#[derive(Debug)]
pub struct Ready {
    pub seq: i64,
    pub ticket: String,
    pub person_id: i64,
    pub person_name: String,
    pub device_key: String,
    pub session: String,
    /// As stored (`landing::decode_stack`).
    pub stack: String,
    pub lineage: i64,
    pub person_epoch: i64,
    pub project_epoch: i64,
    pub merges: i64,
    pub agent_session: Option<String>,
    /// One of the server's own reverts (S20, `priority > 0`).
    pub revert: bool,
    pub created_at: i64,
}

impl QueuedEntry for Ready {
    fn seq(&self) -> i64 {
        self.seq
    }
    fn person_id(&self) -> i64 {
        self.person_id
    }
    fn session_key(&self) -> &str {
        if self.session.is_empty() {
            &self.device_key
        } else {
            &self.session
        }
    }
}

/// A batch, and what choosing it read.
#[derive(Debug)]
pub struct Picked {
    pub rows: Vec<Ready>,
    /// Statements made, and the rows they returned.
    pub statements: usize,
    pub read: usize,
}

const READY_COLUMNS: &str = "seq, ticket, person_id, person_name, device_key, session, stack, lineage, person_epoch, project_epoch, merges, \
     agent_session, priority > 0 AS revert, created_at";

type ReadyRow = (i64, String, i64, String, String, String, String, i64, i64, i64, i64, Option<String>, bool, i64);

fn ready_rows(rows: Vec<ReadyRow>) -> Vec<Ready> {
    rows.into_iter()
        .map(|(seq, ticket, person_id, person_name, device_key, session, stack, lineage, person_epoch, project_epoch, merges, agent_session, revert, created_at)| Ready {
            seq,
            ticket,
            person_id,
            person_name,
            device_key,
            session,
            stack,
            lineage,
            person_epoch,
            project_epoch,
            merges,
            agent_session,
            revert,
            created_at,
        })
        .collect()
}

/// The next batch of `branch`'s queue, at most `limit` rows, leaving out
/// `exclude` (rows being committed): the server's reverts first (S20,
/// `priority > 0`, in their order, never held back by fair sharing), then
/// the rest in fair-share order ([`fair_batch`]).
///
/// What it reads does not grow with the queue (BUG-1941): each statement
/// reads [`PICK_CHUNK`] rows in the queue's order through its index
/// (`landing_queue_ready`), and [`FairPick`] ends the reading as soon as no
/// later row can be in the batch. With `limit` people or more at the head
/// of the queue that is one statement. Behind fewer it reads on past the
/// rows of those it has seen, of which each person has at most their bound
/// ([`admit_queue`]).
pub async fn pick_batch(c: &mut PgConnection, project: i64, branch: &str, exclude: &HashSet<i64>, limit: usize) -> Result<Picked> {
    let exclude: Vec<i64> = exclude.iter().copied().collect();
    let first = ready_rows(
        sqlx::query_as(&format!(
            "SELECT {READY_COLUMNS} FROM landing_queue WHERE project_id = $1 AND branch = $2 AND state = 'queued' AND seq <> ALL($3) \
             ORDER BY priority DESC, created_at, seq LIMIT $4"
        ))
        .bind(project)
        .bind(branch)
        .bind(&exclude)
        .bind(PICK_CHUNK as i64)
        .fetch_all(&mut *c)
        .await?,
    );
    let (mut statements, mut read) = (1, first.len());
    let mut more = first.len() == PICK_CHUNK;
    // The rows that are not reverts are read on from the last one read (from
    // their first, if the chunk was all reverts).
    let mut after = first.last().map(|r| if r.revert { (i64::MIN, i64::MIN) } else { (r.created_at, r.seq) });
    let (mut rows, rest): (Vec<Ready>, Vec<Ready>) = first.into_iter().partition(|r| r.revert);
    rows.truncate(limit);
    let mut pick = FairPick::new(limit - rows.len());
    let mut skip = pick.add(rest);
    while let (true, Some(s), Some((at, seq))) = (more, &skip, after) {
        // `created_at >= $5` is the index's range; the rest of the row
        // comparison only drops the rows of that microsecond already read.
        let next = ready_rows(
            sqlx::query_as(&format!(
                "SELECT {READY_COLUMNS} FROM landing_queue WHERE project_id = $1 AND branch = $2 AND state = 'queued' AND priority = 0 \
                 AND created_at >= $5 AND (created_at > $5 OR seq > $6) AND seq <> ALL($3) AND person_id <> ALL($7) \
                 AND person_id::TEXT || '/' || CASE WHEN session <> '' THEN session ELSE device_key END <> ALL($8) \
                 ORDER BY created_at, seq LIMIT $4"
            ))
            .bind(project)
            .bind(branch)
            .bind(&exclude)
            .bind(PICK_CHUNK as i64)
            .bind(at)
            .bind(seq)
            .bind(&s.people)
            .bind(&s.sessions)
            .fetch_all(&mut *c)
            .await?,
        );
        statements += 1;
        read += next.len();
        more = next.len() == PICK_CHUNK;
        after = next.last().map(|r| (r.created_at, r.seq));
        skip = pick.add(next);
    }
    rows.extend(pick.finish());
    Ok(Picked { rows, statements, read })
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
