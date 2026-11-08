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
//! * **A reader** ([`rules_in_force`]) applies the state recorded at the
//!   tip; a record behind the tip (the branch moved without a landing) is
//!   brought up to it by the same rule, a compare-and-swap on the record's
//!   tip, so a slow server never moves it back.

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

/// Record the state a landing brings, in the landing's transaction, after
/// the branch's compare-and-swap (which holds the branch row's lock, so
/// landings record in their order).
pub async fn record_landing(c: &mut sqlx::PgConnection, project: i64, l: &Landing) -> Result<()> {
    let row: Option<(String, String)> = sqlx::query_as("SELECT checked, state FROM pr_review_rules WHERE project_id = $1 FOR UPDATE")
        .bind(project)
        .fetch_optional(&mut *c)
        .await?;
    let prev: Option<RulesState> = match (&row, l.old, l.fast_forward) {
        (Some((checked, state)), Some(old), true) if *checked == old.hex() => serde_json::from_str(state).ok(),
        _ => None,
    };
    let state = next_state(&l.file, prev.as_ref());
    sqlx::query(
        "INSERT INTO pr_review_rules (project_id, checked, state) VALUES ($1, $2, $3) \
         ON CONFLICT (project_id) DO UPDATE SET checked = EXCLUDED.checked, state = EXCLUDED.state",
    )
    .bind(project)
    .bind(l.new.hex())
    .bind(state_json(&state))
    .execute(&mut *c)
    .await?;
    Ok(())
}

/// The `[review]` rules in force at the tip of `branch` (the default
/// branch), bringing a record that is behind the tip up to it.
pub async fn rules_in_force(hub: &Arc<Hub>, project: &crate::perm::Project, branch: &str) -> Result<Review> {
    let tip: Option<String> = sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = $2")
        .bind(project.id)
        .bind(branch)
        .fetch_optional(&hub.db)
        .await?;
    let Some(tip) = tip.and_then(|t| ObjectId::from_hex(&t).ok()) else { return Ok(Review::default()) };
    let file = blocking(hub, project.id, move |cx| file_at(&cx.src, cx.src.snapshot(&tip)?.tree)).await?;
    let row: Option<(String, String)> = sqlx::query_as("SELECT checked, state FROM pr_review_rules WHERE project_id = $1")
        .bind(project.id)
        .fetch_optional(&hub.db)
        .await?;
    let recorded = row.as_ref().and_then(|(c, s)| Some((ObjectId::from_hex(c).ok()?, serde_json::from_str::<RulesState>(s).ok()?)));
    if let Some((checked, state)) = &recorded {
        if *checked == tip {
            return Ok(review_of(&file, state));
        }
    }
    // Behind the tip: the same rule as a landing, from the recorded tip.
    let prev = match &recorded {
        Some((checked, state)) if ancestor(hub, project, *checked, tip).await? => Some(state.clone()),
        _ => None,
    };
    let state = next_state(&file, prev.as_ref());
    write_record(hub, project.id, row.as_ref().map(|r| r.0.as_str()), tip, &state).await?;
    Ok(review_of(&file, &state))
}

/// Bring the record from the tip it was read at (`read`, `None`: no record)
/// to `tip` with `state`: a compare-and-swap on the record's tip, so a
/// server that read it before another moved it writes nothing. Answers
/// whether it wrote.
pub async fn write_record(hub: &Hub, project: i64, read: Option<&str>, tip: ObjectId, state: &RulesState) -> Result<bool> {
    let n = match read {
        Some(checked) => sqlx::query("UPDATE pr_review_rules SET checked = $2, state = $3 WHERE project_id = $1 AND checked = $4")
            .bind(project)
            .bind(tip.hex())
            .bind(state_json(state))
            .bind(checked)
            .execute(&hub.db)
            .await?
            .rows_affected(),
        None => sqlx::query("INSERT INTO pr_review_rules (project_id, checked, state) VALUES ($1, $2, $3) ON CONFLICT (project_id) DO NOTHING")
            .bind(project)
            .bind(tip.hex())
            .bind(state_json(state))
            .execute(&hub.db)
            .await?
            .rows_affected(),
    };
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
