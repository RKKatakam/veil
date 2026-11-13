//! The `[review]` rules in force on the default branch: a state recorded at
//! each landing (BUG-1279, review cycle 3; `docs/HUB.md` §13.24).
//!
//! * **The state** of a landed tip is `file` (its `.veilrules` parsed), or
//!   `absent` (no file: the defaults, a deletion being an admin's change like
//!   any other), or `strict` (every risk needs one person's approval).
//! * **Recorded in the landing's transaction** ([`record_landing`], called by
//!   the push and by commits through the API after the branch's
//!   compare-and-swap): the branch row's lock orders landings, so states
//!   follow landing order exactly, across servers.
//! * **A file that does not parse** keeps the state recorded at the tip the
//!   branch moved from, when the move is a fast-forward from it; otherwise
//!   (a forced move, a new branch, no state recorded there) `strict`, until
//!   a landing with a valid file or none records one. No history is walked
//!   and no older file's text is ever used.
//! * **A reader** ([`rules_in_force`]) reads the tip and the record in one
//!   statement and applies the state recorded at the tip. A record behind
//!   the tip (the branch moved without a landing) is brought up to it by a
//!   compare-and-swap on the tip read with it: to the tip's own file (or
//!   its absence), or, for a broken file, to the recorded state only if the
//!   record's tip is an ancestor of the tip. A read never writes `strict`
//!   (BUG-1322).

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use veil_core::{
    object::{EntryKind, Object},
    ObjectId,
};

use super::{
    revision::entry_at,
    rules::{Review, RULES_FILE},
};
use crate::{
    error::{Error, Result},
    perm::Viewer,
    query::graph::{blocking, ensure, G},
    sync::Source,
    Hub,
};

/// The largest `.veilrules` read.
const MAX_RULES: u64 = 64 << 10;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum RulesState {
    File { text: String },
    Absent,
    Strict,
}

/// A tip's `.veilrules` as found.
#[derive(Clone, Debug)]
pub enum RulesFile {
    Valid(String),
    Absent,
    /// It does not parse: the strict rules with why (for admins).
    Broken(Review),
}

/// The `.veilrules` at the root of `tree`.
pub fn file_at(src: &Source, tree: ObjectId) -> Result<RulesFile> {
    let Some(e) = entry_at(src, tree, RULES_FILE)? else { return Ok(RulesFile::Absent) };
    let broken = |why: &str| RulesFile::Broken(Review::strict(why.into()));
    if e.kind != EntryKind::File || !e.visibility.is_public() || e.size > MAX_RULES {
        return Ok(broken("not a plain file of at most 64 KiB"));
    }
    let Ok(Object::Blob(b)) = Object::decode(&src.raw(&e.id)?) else { return Ok(broken("not a plain file of at most 64 KiB")) };
    let r = Review::parse(Some(&b));
    Ok(match (r.broken, String::from_utf8(b)) {
        (false, Ok(text)) => RulesFile::Valid(text),
        (true, _) => RulesFile::Broken(r),
        (false, Err(_)) => broken("not UTF-8"),
    })
}

/// The state a landing records: from its file, or (broken) the state at the
/// tip it moved from, `prev`, which is `None` unless the move is a
/// fast-forward from a tip with a recorded state.
pub fn next_state(file: &RulesFile, prev: Option<&RulesState>) -> RulesState {
    match file {
        RulesFile::Valid(t) => RulesState::File { text: t.clone() },
        RulesFile::Absent => RulesState::Absent,
        RulesFile::Broken(_) => prev.cloned().unwrap_or(RulesState::Strict),
    }
}

/// The rules a tip whose file is `file` and whose state is `state` has.
pub fn review_of(file: &RulesFile, state: &RulesState) -> Review {
    match file {
        RulesFile::Valid(t) => Review::parse(Some(t.as_bytes())),
        RulesFile::Absent => Review::default(),
        RulesFile::Broken(why) => {
            let mut r = match state {
                RulesState::File { text } => Review::parse(Some(text.as_bytes())),
                RulesState::Absent => Review::default(),
                RulesState::Strict => Review::strict(String::new()),
            };
            r.warnings = why.warnings.clone();
            r.warnings.push(match state {
                RulesState::Strict => "until it is fixed, every PR needs one person's approval".into(),
                _ => format!("until it is fixed, the rules recorded at the last landing apply ({RULES_FILE} or its absence)"),
            });
            r.broken = true;
            r
        }
    }
}

fn state_json(s: &RulesState) -> String {
    serde_json::to_string(s).expect("plain")
}

/// What a landing on the default branch brings: its old and new tip, the
/// new tip's file, and whether the move is a fast-forward from the old one.
#[derive(Clone, Debug)]
pub struct Landing {
    pub old: Option<ObjectId>,
    pub new: ObjectId,
    pub file: RulesFile,
    pub fast_forward: bool,
}

/// The state `l` records over the record `row` read, and whether that can
/// change the rules a landing on another branch was judged under (BUG-2061):
/// unless the record was at the tip the branch moves from and keeps its
/// state, the rules may change. (With the same state, a file that turns
/// valid or absent keeps what it requires and only loses a broken file's
/// warnings.)
fn next_record(row: &Option<(String, String)>, l: &Landing) -> (RulesState, bool) {
    let recorded: Option<RulesState> = match (row, l.old) {
        (Some((checked, state)), Some(old)) if *checked == old.hex() => serde_json::from_str(state).ok(),
        _ => None,
    };
    let prev = if l.fast_forward { recorded.as_ref() } else { None };
    let state = next_state(&l.file, prev);
    let changes = recorded.as_ref() != Some(&state);
    (state, changes)
}

/// Whether recording `l` can change the review rules (see `next_record`),
/// read before the landing's transaction takes the review gate: by the
/// default branch's own batch, which must know which way to take it
/// (`prs::close_review_gate` or `prs::review_gate::share_review_gate`) before it reads
/// the rules again. Its branch row's lock keeps the record where it is
/// until it records.
pub async fn changes_rules(c: &mut sqlx::PgConnection, project: i64, l: &Landing) -> Result<bool> {
    let row: Option<(String, String)> = sqlx::query_as("SELECT checked, state FROM pr_review_rules WHERE project_id = $1")
        .bind(project)
        .fetch_optional(&mut *c)
        .await?;
    Ok(next_record(&row, l).1)
}

/// Record the state a landing brings, in the landing's transaction, after
/// the branch's compare-and-swap (which holds the branch row's lock, so
/// landings record in their order). Answers whether the rules may have
/// changed: the caller then takes the review gate exclusively
/// (`prs::close_review_gate`) once it holds every branch row it moves, so
/// that a batch on another branch either reads the new rules or commits
/// before this landing does (BUG-2061).
pub async fn record_landing(c: &mut sqlx::PgConnection, project: i64, l: &Landing) -> Result<bool> {
    let row: Option<(String, String)> = sqlx::query_as("SELECT checked, state FROM pr_review_rules WHERE project_id = $1 FOR UPDATE")
        .bind(project)
        .fetch_optional(&mut *c)
        .await?;
    let (state, changes) = next_record(&row, l);
    sqlx::query(
        "INSERT INTO pr_review_rules (project_id, checked, state) VALUES ($1, $2, $3) \
         ON CONFLICT (project_id) DO UPDATE SET checked = EXCLUDED.checked, state = EXCLUDED.state",
    )
    .bind(project)
    .bind(l.new.hex())
    .bind(state_json(&state))
    .execute(&mut *c)
    .await?;
    Ok(changes)
}

/// The `[review]` rules in force at the tip of `branch` (the default
/// branch), bringing a record that is behind the tip up to it.
pub async fn rules_in_force(hub: &Arc<Hub>, project: &crate::perm::Project, branch: &str) -> Result<Review> {
    let gc_epoch = crate::pack_gc::read_gc_epoch(hub, project.id).await?;
    // The tip and the record in one statement (BUG-1322): a landing writes
    // both in one transaction, so this is a state some landing left.
    type Row = (String, Option<String>, Option<String>);
    let row: Option<Row> = sqlx::query_as(
        "SELECT b.target, r.checked, r.state FROM branches b LEFT JOIN pr_review_rules r ON r.project_id = b.project_id \
         WHERE b.project_id = $1 AND b.name = $2",
    )
    .bind(project.id)
    .bind(branch)
    .fetch_optional(&hub.db)
    .await?;
    let Some((tip, checked, state)) = row else { return Ok(Review::default()) };
    let Ok(tip) = ObjectId::from_hex(&tip) else { return Ok(Review::default()) };
    let recorded = match (checked, state) {
        (Some(c), Some(s)) => Some((c.clone(), ObjectId::from_hex(&c).ok(), serde_json::from_str::<RulesState>(&s).ok())),
        _ => None,
    };
    let file = blocking(hub, project.id, move |cx| file_at(&cx.src, cx.src.snapshot(&tip)?.tree)).await?;
    match &recorded {
        Some((_, Some(checked), Some(state))) if *checked == tip => return Ok(review_of(&file, state)),
        _ => {}
    }
    // Behind the tip (the branch moved without a landing): the rule of a
    // landing, from the record read with the tip. A broken file keeps the
    // recorded state only if the record's tip is an ancestor of the tip
    // (a fast-forward); a valid file, or none, is the tip's own state. The
    // write is a compare-and-swap on the record's tip as read, and a read
    // never writes `strict` (BUG-1322): a broken file with no state to keep
    // is answered strict, and the record left as it is.
    let prev = match (&recorded, &file) {
        (Some((_, Some(checked), Some(state))), RulesFile::Broken(_)) if ancestor(hub, project, *checked, tip).await? => Some(state.clone()),
        _ => None,
    };
    let state = next_state(&file, prev.as_ref());
    if state != RulesState::Strict {
        match write_record_at(hub, project.id, gc_epoch, recorded.as_ref().map(|r| r.0.as_str()), tip, &state).await {
            Ok(_) => {}
            Err(e) if crate::pack_gc::is_gc_epoch_changed(&e) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(review_of(&file, &state))
}

/// Bring the record from the tip it was read at (`read`, `None`: no record)
/// to `tip` with `state`: a compare-and-swap on the record's tip, so a
/// server that read it before another moved it writes nothing. Answers
/// whether it wrote.
pub async fn write_record(hub: &Hub, project: i64, read: Option<&str>, tip: ObjectId, state: &RulesState) -> Result<bool> {
    let gc_epoch = crate::pack_gc::read_gc_epoch(hub, project).await?;
    write_record_at(hub, project, gc_epoch, read, tip, state).await
}

async fn write_record_at(hub: &Hub, project: i64, gc_epoch: i64, read: Option<&str>, tip: ObjectId, state: &RulesState) -> Result<bool> {
    let read = read.map(str::to_string);
    let state_str = state_json(state);
    let tip_hex = tip.hex();
    let n = crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
        let read = read.clone();
        let state_str = state_str.clone();
        let tip_hex = tip_hex.clone();
        Box::pin(async move {
            crate::pack_gc::guard_root_write(&mut *c, project, gc_epoch).await?;
            let rows = match &read {
                Some(checked) => sqlx::query("UPDATE pr_review_rules SET checked = $2, state = $3 WHERE project_id = $1 AND checked = $4")
                    .bind(project)
                    .bind(&tip_hex)
                    .bind(&state_str)
                    .bind(checked)
                    .execute(&mut *c)
                    .await?
                    .rows_affected(),
                None => sqlx::query("INSERT INTO pr_review_rules (project_id, checked, state) VALUES ($1, $2, $3) ON CONFLICT (project_id) DO NOTHING")
                    .bind(project)
                    .bind(&tip_hex)
                    .bind(&state_str)
                    .execute(&mut *c)
                    .await?
                    .rows_affected(),
            };
            Ok(rows)
        })
    })
    .await?;
    Ok(n == 1)
}

/// Is real snapshot `a` an ancestor of `b` (or `b`)? One question of the
/// real graph; a snapshot it cannot place answers no.
async fn ancestor(hub: &Arc<Hub>, project: &crate::perm::Project, a: ObjectId, b: ObjectId) -> Result<bool> {
    if a == b {
        return Ok(true);
    }
    let admin = Viewer { admin: true, ..Viewer::default() };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    if ensure(hub, project, &admin, &[a, b], Some(deadline)).await.is_err() {
        return Ok(false);
    }
    blocking(hub, project.id, move |cx| {
        let g = G::new(cx, "admin", Some(deadline));
        g.is_ancestor(a, b).map_err(|e: Error| e)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prs::rules::Risk;

    fn valid(n: u32) -> RulesFile {
        RulesFile::Valid(format!("[review]\nnormal = {{ approvals = {n} }}\n"))
    }

    fn broken() -> RulesFile {
        RulesFile::Broken(Review::parse(Some(b"[review\n")))
    }

    /// The state a run of landings records, each a fast-forward (`true`)
    /// or a forced move, and what normal risk needs after each.
    fn run(landings: &[(RulesFile, bool)]) -> Vec<u32> {
        let mut state: Option<RulesState> = None;
        landings
            .iter()
            .map(|(file, ff)| {
                let prev = if *ff { state.as_ref() } else { None };
                let s = next_state(file, prev);
                let n = review_of(file, &s).need(Risk::Normal).approvals;
                state = Some(s);
                n
            })
            .collect()
    }

    #[test]
    fn a_broken_file_keeps_the_state_of_the_landing_before_it() {
        // Valid 3, broken, broken: 3 throughout.
        assert_eq!(run(&[(valid(3), true), (broken(), true), (broken(), true)]), [3, 3, 3]);
        // A deletion counts: the defaults, then broken keeps the defaults,
        // never the deleted file's 0.
        assert_eq!(run(&[(valid(0), true), (RulesFile::Absent, true), (broken(), true)]), [0, 1, 1]);
        // A forced move with a broken file: strict until a valid landing.
        assert_eq!(run(&[(valid(3), true), (broken(), false), (broken(), true), (valid(2), true)]), [3, 1, 1, 2]);
        // A first landing that is broken: strict.
        assert_eq!(run(&[(broken(), true)]), [1]);
        let strict = review_of(&broken(), &RulesState::Strict);
        assert!(strict.broken && strict.need(Risk::Low).approvals == 1 && strict.need(Risk::Low).people_only);
    }
}
