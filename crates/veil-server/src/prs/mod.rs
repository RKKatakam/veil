//! PRs and review (milestone S21; `docs/HUB.md` §13.24; phase-4 design
//! §4.9). PRs, their titles, bodies, threads and reviews are **plain text
//! behind the server's permissions**, never encrypted
//! (`docs/VISIBILITY.md`).
//!
//! | Route (`/v1/projects/{p}/prs…`) | |
//! |---|---|
//! | `GET prs?state=&q=&n=&after=` | the PRs the caller may see, newest first, with their count; `q` searches titles and bodies |
//! | `POST prs {head, onto?, title, body?}` | a PR for the stack of changes from `onto`'s tip (the default branch) to `head` |
//! | `GET prs/{id}` | the PR, its revisions (the caller's snapshot ids), its review gate |
//! | `GET prs/{id}/diff?revision=&change=&stat=` | a revision's diff, or one change's: S13's diff on the caller's projected history |
//! | `POST prs/{id}/revisions {head}` | a new revision (the author or an admin) |
//! | `POST prs/{id}/close` | close it (the author or an admin) |
//! | `GET|POST prs/{id}/threads`, `POST prs/{id}/threads/{t}` | threads, anchored to lines (`threads`); replies; resolve |
//! | `POST prs/{id}/reviews {patch, verdict, body?, signature}` | a device-signed verdict on the current patch (`review`) |
//! | `POST prs/{id}/land` | the review gate; submitting to the landing service comes with S17 |
//!
//! **Who sees a PR** ([`class`]): exactly the people who can read every
//! path any of its revisions touched. For anyone else it does not exist:
//! not in lists, counts or search, and every route answers "no such PR
//! that you can see", the answer for an id nobody made, by the same code
//! path. PR ids are random (`pr-` and 8 hex digits), so no gap in a
//! sequence counts hidden PRs.
//!
//! **What a viewer is shown** is computed on their projected history
//! (`docs/HUB.md` §13.4, S13's `query`): snapshot ids are theirs (a
//! projection, or the real snapshot where it is the same), diffs are S13's
//! diffs between them, and a change of the stack that is not in their
//! history (it changed only an empty folder they are not shown) is left
//! out. **Revisions are numbered per viewer:** consecutive revisions with
//! the same base and head in their history (a rebase over changes of
//! folders they cannot see) are one revision to them, so nothing hidden
//! makes a revision appear; for the same reason lists are ordered by
//! creation, and no "updated" time is shown. Everything else (title, body,
//! risk, file count, patch, threads, reviews) is about paths they may
//! read.

pub mod class;
pub mod embargo;
pub mod review_gate;
pub mod review;
pub mod revision;
pub mod rules;
pub mod state;
pub mod threads;

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use veil_core::{
    crypto::domains::SIG_CONTEXT_HUB_PR_REVIEW,
    hub::pr::{review_message, valid_pr_id, VERDICTS},
    identity::verify_signature,
    ObjectId,
};

use self::{
    revision::{Computed, StackChange},
    rules::{classify, FileChange, Review, Risk},
    threads::{Anchor, AnchorRequest, At},
};
use crate::{
    auth::Caller,
    db::{transaction, Isolation},
    error::{Error, Result},
    perm::Viewer,
    query::{
        self,
        graph::{blocking, ensure, G},
        Ask, Limits,
    },
    Hub, HubState,
};

/// The longest title, in characters.
pub const MAX_TITLE: usize = 300;
/// The largest body, comment or review text, in bytes.
pub const MAX_TEXT: usize = 64 << 10;
/// The most revisions a PR may have.
pub const MAX_REVISIONS: i32 = 100;
/// The most threads a PR may have, and comments a thread.
pub const MAX_THREADS: i64 = 1_000;
pub const MAX_COMMENTS: i64 = 500;
/// The most PRs a list page holds.
pub const MAX_PAGE: i64 = 200;
/// How long the work of one PR request may take.
const DEADLINE: Duration = Duration::from_secs(10);

fn no_pr() -> Error {
    Error::not_found("no such PR that you can see")
}

/// A PR's row.
#[derive(Clone, Debug)]
pub struct PrRow {
    pub id: String,
    pub target: String,
    pub author: i64,
    pub author_name: String,
    pub title: String,
    pub body: String,
    pub state: String,
    pub revision: i32,
    pub created_at: i64,
    pub updated_at: i64,
    pub embargo: String,
    pub land_at_release: bool,
}

/// One revision's row. `risk` and `reasons` are the revision's files rated
/// under the rules whose key is `rules_key` ([`Review::risk_key`]): a cache,
/// which `rated` brings to the rules in force (BUG-1424).
#[derive(Clone, Debug)]
pub struct RevRow {
    pub n: i32,
    pub base: ObjectId,
    pub head: ObjectId,
    pub changes: Vec<StackChange>,
    pub patch: String,
    pub risk: String,
    pub reasons: Vec<String>,
    pub rules_key: String,
    pub files: i32,
    pub pushed_by: i64,
    pub at: i64,
}

fn hex_id(s: &str) -> Result<ObjectId> {
    ObjectId::from_hex(s).map_err(|e| Error::Other(anyhow::anyhow!("a stored id: {e}")))
}

/// The caller's view of the project.
async fn open(hub: &Hub, project: &str, caller: &Caller) -> Result<Ask> {
    Ask::open(hub, project, caller).await
}

/// The PR `id` if the caller may see it; otherwise, and for an id nobody
/// made, "no such PR" (one statement either way). Every PR's class is
/// computed under the current access lines first.
pub async fn visible(hub: &Hub, ask: &Ask, id: &str) -> Result<PrRow> {
    class::reclassify(hub, &ask.project).await?;
    if !valid_pr_id(id) {
        return Err(no_pr());
    }
    type Row = (String, i64, String, String, String, String, i32, i64, i64, String, bool, String, String);
    let row: Option<Row> = sqlx::query_as(
        "SELECT p.target, p.author, pe.name, p.title, p.body, p.state, p.revision, p.created_at, p.updated_at, \
                p.embargo, p.land_at_release, c.lines, c.embargo \
         FROM prs p JOIN pr_classes c ON c.project_id = p.project_id AND c.class_id = p.class_id JOIN people pe ON pe.id = p.author \
         WHERE p.project_id = $1 AND p.id = $2 AND p.policy_key = $3",
    )
    .bind(ask.project.id)
    .bind(id)
    .bind(class::policy_key(&ask.project.policy))
    .fetch_optional(&hub.db)
    .await?;
    let Some((target, author, author_name, title, body, state, revision, created_at, updated_at, pr_embargo, land_at_release, lines, class_embargo)) = row else {
        return Err(no_pr());
    };
    let lines: BTreeSet<String> = serde_json::from_str(&lines).unwrap_or_else(|_| BTreeSet::from([String::new()]));
    let vis_emb = if class_embargo.is_empty() && pr_embargo.is_empty() {
        std::collections::HashSet::new()
    } else {
        embargo::visible_embargoes(hub, &ask.project, &ask.viewer).await?
    };
    let view = ask.project.view(&ask.viewer);
    if !class::satisfies_with_embargoes(&view, &lines, &class_embargo, &vis_emb)
        || (!pr_embargo.is_empty() && !vis_emb.contains(&pr_embargo))
    {
        return Err(no_pr());
    }
    if ask.viewer.only.is_some() {
        let paths = review::paths_of(hub, ask.project.id, id).await?;
        if paths.iter().any(|p| !ask.viewer.within_narrowing(p)) {
            return Err(no_pr());
        }
    }
    Ok(PrRow {
        id: id.to_string(),
        target,
        author,
        author_name,
        title,
        body,
        state,
        revision,
        created_at,
        updated_at,
        embargo: pr_embargo,
        land_at_release,
    })
}

/// The PR's revisions, with their risk as last rated (see [`rated`]).
async fn revisions(hub: &Hub, project: i64, pr: &str) -> Result<Vec<RevRow>> {
    type Row = (i32, String, String, String, String, String, String, String, i32, i64, i64);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT n, base, head, changes, patch, risk, reasons, rules_key, files_count, pushed_by, at FROM pr_revisions WHERE project_id = $1 AND pr = $2 ORDER BY n",
    )
    .bind(project)
    .bind(pr)
    .fetch_all(&hub.db)
    .await?;
    rows.into_iter()
        .map(|(n, base, head, changes, patch, risk, reasons, rules_key, files, pushed_by, at)| {
            Ok(RevRow {
                n,
                base: hex_id(&base)?,
                head: hex_id(&head)?,
                changes: serde_json::from_str(&changes).map_err(|e| Error::Other(e.into()))?,
                patch,
                risk,
                reasons: serde_json::from_str(&reasons).unwrap_or_default(),
                rules_key,
                files,
                pushed_by,
                at,
            })
        })
        .collect()
}

/// Rate revisions `which` of `pr` (each with the key its stored class was
/// rated under) under `rules`, the rules in force (BUG-1424): the files of
/// every revision whose key differs are read and classified again, and
/// the cache is replaced (only while it still holds what was read: two
/// raters under different rules never overwrite each other's newer
/// rating). Answers, per revision in `which`, the risk and its reasons.
async fn rate(hub: &Hub, project: i64, pr: &str, which: &[(i32, String, Vec<String>, String)], rules: &Review) -> Result<Vec<(Risk, Vec<String>)>> {
    let key = rules.risk_key();
    let stale: Vec<i32> = which.iter().filter(|(_, _, _, k)| *k != key).map(|(n, ..)| *n).collect();
    let mut fresh: HashMap<i32, (Risk, Vec<String>)> = HashMap::new();
    if !stale.is_empty() {
        let rows: Vec<(i32, String, String)> = sqlx::query_as("SELECT n, files, rules_key FROM pr_revisions WHERE project_id = $1 AND pr = $2 AND n = ANY($3)")
            .bind(project)
            .bind(pr)
            .bind(&stale)
            .fetch_all(&hub.db)
            .await?;
        for (n, files, was) in rows {
            let files: Vec<FileChange> = serde_json::from_str(&files).map_err(|e| Error::Other(e.into()))?;
            let (risk, reasons) = classify(&files, rules);
            sqlx::query("UPDATE pr_revisions SET risk = $1, reasons = $2, rules_key = $3 WHERE project_id = $4 AND pr = $5 AND n = $6 AND rules_key = $7")
                .bind(risk.name())
                .bind(serde_json::to_string(&reasons).expect("strings"))
                .bind(&key)
                .bind(project)
                .bind(pr)
                .bind(n)
                .bind(&was)
                .execute(&hub.db)
                .await?;
            fresh.insert(n, (risk, reasons));
        }
    }
    Ok(which
        .iter()
        .map(|(n, risk, reasons, _)| fresh.remove(n).unwrap_or_else(|| (Risk::parse(risk), reasons.clone())))
        .collect())
}

/// The PR's revisions, every one rated under `rules` (the rules in force).
async fn rated(hub: &Hub, project: i64, pr: &str, rules: &Review) -> Result<Vec<RevRow>> {
    let mut revs = revisions(hub, project, pr).await?;
    let which: Vec<_> = revs.iter().map(|r| (r.n, r.risk.clone(), r.reasons.clone(), r.rules_key.clone())).collect();
    for (r, (risk, reasons)) in revs.iter_mut().zip(rate(hub, project, pr, &which, rules).await?) {
        r.risk = risk.name().to_string();
        r.reasons = reasons;
        r.rules_key = rules.risk_key();
    }
    Ok(revs)
}

/// The review gate of `pr` now: the rules in force on the default branch,
/// its revisions rated under them, and the gate of the current one. The
/// one function every answer about readiness goes through, and S17's
/// landing will (BUG-1424).
pub async fn gate(hub: &Arc<Hub>, ask: &Ask, pr: &PrRow) -> Result<(Vec<RevRow>, review::Gate)> {
    let rules = rules(hub, ask).await?;
    let revs = rated(hub, ask.project.id, &pr.id, &rules).await?;
    let current = revs.iter().find(|r| r.n == pr.revision).ok_or_else(|| Error::Other(anyhow::anyhow!("the PR's revision is missing")))?;
    let cids = revert_identities(hub, ask.project.id, &current.changes).await?;
    let rev_twice = crate::bisect::any_reverted_twice(hub, ask.project.id, &cids).await?;
    let gate = review::gate(hub, &ask.project, &ask.viewer, pr, &current.patch, Risk::parse(&current.risk), &rules, rev_twice).await?;
    Ok((revs, gate))
}

async fn names(hub: &Hub, ids: &[i64]) -> Result<HashMap<i64, String>> {
    let rows: Vec<(i64, String)> = sqlx::query_as("SELECT id, name FROM people WHERE id = ANY($1)").bind(ids).fetch_all(&hub.db).await?;
    Ok(rows.into_iter().collect())
}


/// The real tip of `branch`, if it exists and is not a hidden embargo line.
async fn tip(hub: &Hub, project: i64, branch: &str) -> Result<Option<ObjectId>> {
    let t: Option<String> = sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = $2 AND hidden_for_embargo IS NULL")
        .bind(project)
        .bind(branch)
        .fetch_optional(&hub.db)
        .await?;
    t.map(|t| hex_id(&t)).transpose()
}

/// The review rules of the default branch's tip.
async fn rules(hub: &Arc<Hub>, ask: &Ask) -> Result<Review> {
    state::rules_in_force(hub, &ask.project, &ask.project.default_branch).await
}

/// The review rules in force at the tip of `default_branch`: the state
/// recorded at the last landing (`state`, BUG-1279), brought up to the tip
/// if the branch moved without a landing.
pub async fn rules_of_project(hub: &Arc<Hub>, project: i64, default_branch: &str) -> Result<Review> {
    let name: Option<String> = sqlx::query_scalar("SELECT name FROM projects WHERE id = $1").bind(project).fetch_optional(&hub.db).await?;
    let Some(name) = name else { return Ok(Review::default()) };
    let p = crate::perm::load_project(&mut *hub.db.acquire().await?, &name).await?.ok_or_else(|| Error::not_found("no such project"))?;
    state::rules_in_force(hub, &p, default_branch).await
}

/// After a landing that moved `branches` of `project` (the derive workers):
/// a landing records its rules state in its own transaction
/// (`state::record_landing`); this only brings up a record that is behind
/// the tip (a move that recorded nothing).
pub async fn landed(hub: &Arc<Hub>, project: i64, branches: &[String]) -> Result<()> {
    let default: Option<String> = sqlx::query_scalar("SELECT default_branch FROM projects WHERE id = $1").bind(project).fetch_optional(&hub.db).await?;
    match default {
        Some(d) if branches.contains(&d) => rules_of_project(hub, project, &d).await.map(|_| ()),
        _ => Ok(()),
    }
}

/// Mark `pr` landed at `revision`, where it is open at that revision and no
/// embargo holds it (an embargo's release marks its own PRs): in the
/// transaction that lands it (the landing batch's, BUG-1924) or that finds
/// its changes on the target already. Whether it was marked here.
pub(crate) async fn mark_landed(c: &mut sqlx::PgConnection, project: i64, pr: &str, revision: i32, now: i64) -> Result<bool> {
    let n = sqlx::query(
        "UPDATE prs SET state = 'landed', updated_at = $1 WHERE project_id = $2 AND id = $3 AND state = 'open' AND revision = $4 AND embargo = ''",
    )
    .bind(now)
    .bind(project)
    .bind(pr)
    .bind(revision)
    .execute(&mut *c)
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// The landing service's hook for a landed entry of a PR (BUG-1924), after
/// the batch that marked it committed, whether or not the request that
/// queued it still waits: the event (when that batch `marked` it), and its
/// source branch deleted (BUG-1885). Best effort: a branch it leaves is
/// deleted by anyone who may write.
pub(crate) async fn pr_landed(hub: &Arc<Hub>, project: i64, pr: &str, revision: i32, actor: i64, marked: bool) {
    if marked {
        crate::events::emit_pr(hub, project, pr, "pr.landed").await;
    }
    let r: Result<()> = async {
        let name: Option<String> = sqlx::query_scalar("SELECT name FROM projects WHERE id = $1").bind(project).fetch_optional(&hub.db).await?;
        let Some(name) = name else { return Ok(()) };
        let Some(p) = crate::perm::load_project(&mut *hub.db.acquire().await?, &name).await? else { return Ok(()) };
        crate::branches::delete_landed_pr_branch(hub, &p, pr, revision, actor).await
    }
    .await;
    if let Err(e) = r {
        eprintln!("veil-server: deleting the source branch of landed PR {pr} of project {project}: {e:?}");
    }
}

fn admin() -> Viewer {
    Viewer {
        admin: true,
        ..Viewer::default()
    }
}

/// Compute the revision of `head` (real) onto `onto` (real), on the real
/// history.
async fn compute(hub: &Arc<Hub>, ask: &Ask, head: ObjectId, onto: ObjectId) -> Result<Computed> {
    let deadline = Instant::now() + DEADLINE;
    ensure(hub, &ask.project, &admin(), &[head, onto], Some(deadline)).await?;
    let rules = rules(hub, ask).await?;
    let r = blocking(hub, ask.project.id, move |cx| {
        let g = G::new(cx, "admin", Some(deadline));
        revision::compute(cx, &g, head, onto, &rules)
    })
    .await;
    match r {
        // The stack's refusals name its changes and count its paths, as the
        // server has them: only admins (who see all of it) are told which;
        // anyone else gets the one refusal `readable_by` gives.
        Err(Error::Api { code: "bad_request", message, .. }) if !ask.viewer.admin && !message.starts_with(revision::NOTHING_TO_REVIEW) => Err(not_a_pr()),
        r => r,
    }
}

/// The one refusal of a stack to anyone but an admin (whatever the reason:
/// a merge, a change twice, too many changes or paths, a path they cannot
/// see), so a refusal says nothing of the part they cannot see.
fn not_a_pr() -> Error {
    Error::forbidden(format!(
        "this cannot be a PR of yours: a PR is a stack of at most {} changes with one parent each, touching at most {} paths, \
         every one of them a file you can see; ask someone with access to the rest to open it",
        revision::MAX_STACK,
        revision::MAX_PATHS
    ))
}

fn signed_in(caller: &Caller) -> Result<&crate::auth::Person> {
    caller.not_runner()
}

/// Writes need a person of the project (and never a CI runner session, S19).
fn participant(ask: &Ask, caller: &Caller) -> Result<i64> {
    let p = caller.not_runner()?;
    if !ask.project.participant(&ask.viewer) {
        return Err(Error::forbidden("only the project's people may do that"));
    }
    Ok(p.id)
}

fn check_text(what: &str, s: &str, max: usize) -> Result<()> {
    if s.len() > max {
        return Err(Error::bad_request(format!("{what} is longer than {max} bytes")));
    }
    if s.chars().any(|c| c.is_control() && c != '\n' && c != '\t' && c != '\r') {
        return Err(Error::bad_request(format!("{what} holds control characters")));
    }
    Ok(())
}

fn check_title(t: &str) -> Result<String> {
    let t = t.trim();
    if t.is_empty() || t.chars().count() > MAX_TITLE || t.contains('\n') {
        return Err(Error::bad_request(format!("a title is one line of 1 to {MAX_TITLE} characters")));
    }
    check_text("the title", t, MAX_TEXT)?;
    Ok(t.to_string())
}

/// The touched paths must all be readable by whoever makes the revision:
/// otherwise they could not see their own PR. Like a push's merge across
/// hidden folders (`docs/HUB.md` §13.4), this says only that the stack, as
/// the server has it, holds something they cannot see.
fn readable_by(ask: &Ask, touched: &BTreeSet<String>) -> Result<()> {
    let lines = class::lines_of(&ask.project.policy, touched.iter().map(String::as_str));
    if !class::satisfies(&ask.project.view(&ask.viewer), &lines, "") {
        return Err(not_a_pr());
    }
    Ok(())
}

fn random_id() -> String {
    format!("pr-{}", hex::encode(veil_core::crypto::random_bytes::<4>()))
}

/// Write a new revision's rows (and the PR's paths and class) in `c`.
async fn write_revision(c: &mut sqlx::PgConnection, project: i64, pr: &str, n: i32, r: &Computed, by: i64, at: i64) -> Result<()> {
    sqlx::query(
        "INSERT INTO pr_revisions (project_id, pr, n, base, head, changes, patch, files, risk, reasons, rules_key, files_count, pushed_by, at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(project)
    .bind(pr)
    .bind(n)
    .bind(r.base.hex())
    .bind(r.head.hex())
    .bind(serde_json::to_string(&r.changes).expect("strings"))
    .bind(&r.patch)
    .bind(serde_json::to_string(&r.files).expect("strings"))
    .bind(r.risk.name())
    .bind(serde_json::to_string(&r.reasons).expect("strings"))
    .bind(&r.rules_key)
    .bind(r.files.len() as i32)
    .bind(by)
    .bind(at)
    .execute(&mut *c)
    .await?;
    let paths: Vec<String> = r.touched.iter().cloned().collect();
    sqlx::query("INSERT INTO pr_paths (project_id, pr, path) SELECT $1, $2, p FROM UNNEST($3::text[]) AS p ON CONFLICT DO NOTHING")
        .bind(project)
        .bind(pr)
        .bind(&paths)
        .execute(&mut *c)
        .await?;
    Ok(())
}

// ---- answers ------------------------------------------------------------------

/// The viewer's ids of `reals` (their projections), in one fill.
async fn projected(hub: &Arc<Hub>, ask: &Ask, embargo: &str, reals: &[ObjectId]) -> Result<HashMap<ObjectId, ObjectId>> {
    if !embargo.is_empty() {
        return embargo::projected(hub, ask, embargo, reals).await;
    }
    let ps = ensure(hub, &ask.project, &ask.viewer, reals, Some(Instant::now() + DEADLINE)).await?;
    Ok(reals.iter().copied().zip(ps).collect())
}

/// A revision's changes as the viewer is shown them: each in their history,
/// with their snapshot id (a change their history has no version of is
/// left out).
fn changes_json(r: &RevRow, p: &HashMap<ObjectId, ObjectId>) -> Vec<Value> {
    r.changes
        .iter()
        .filter(|c| p[&c.snapshot_id()] != p[&c.parent_id()])
        .map(|c| json!({ "change_id": c.change, "snapshot_id": p[&c.snapshot_id()].hex() }))
        .collect()
}

/// The viewer's number of each revision (by index in `revs`): a revision
/// whose base and head are, in their history, those of the one before is
/// the same revision to them.
fn viewer_numbers(revs: &[RevRow], p: &HashMap<ObjectId, ObjectId>) -> Vec<i32> {
    let mut out = Vec::with_capacity(revs.len());
    let mut n = 0;
    for (i, r) in revs.iter().enumerate() {
        let same = i > 0 && p[&revs[i - 1].base] == p[&r.base] && p[&revs[i - 1].head] == p[&r.head];
        if !same {
            n += 1;
        }
        out.push(n);
    }
    out
}

/// Every real snapshot the revisions name.
fn reals_of(revs: &[RevRow]) -> Vec<ObjectId> {
    let mut reals: Vec<ObjectId> = Vec::new();
    for r in revs {
        reals.extend([r.base, r.head]);
        for c in &r.changes {
            reals.extend([c.snapshot_id(), c.parent_id()]);
        }
    }
    reals.sort();
    reals.dedup();
    reals
}

/// The PR's revisions, the viewer's ids of every snapshot they name, and
/// the viewer's number of each.
async fn viewer_revisions(hub: &Arc<Hub>, ask: &Ask, pr: &str, embargo: &str) -> Result<(Vec<RevRow>, HashMap<ObjectId, ObjectId>, HashMap<i32, i32>)> {
    let revs = revisions(hub, ask.project.id, pr).await?;
    numbered(hub, ask, embargo, revs).await
}

/// `revs` with the viewer's ids of every snapshot they name, and the
/// viewer's number of each.
async fn numbered(hub: &Arc<Hub>, ask: &Ask, embargo: &str, revs: Vec<RevRow>) -> Result<(Vec<RevRow>, HashMap<ObjectId, ObjectId>, HashMap<i32, i32>)> {
    let p = projected(hub, ask, embargo, &reals_of(&revs)).await?;
    let numbers = viewer_numbers(&revs, &p);
    let map = revs.iter().zip(&numbers).map(|(r, v)| (r.n, *v)).collect();
    Ok((revs, p, map))
}

/// The PR as `ask`'s viewer sees it.
pub async fn pr_json(hub: &Arc<Hub>, ask: &Ask, pr: &PrRow) -> Result<Value> {
    let (revs, gate) = gate(hub, ask, pr).await?;
    let (revs, p, vn) = numbered(hub, ask, &pr.embargo, revs).await?;
    let ppl = names(hub, &revs.iter().map(|r| r.pushed_by).collect::<Vec<_>>()).await?;
    let current = revs.iter().find(|r| r.n == pr.revision).ok_or_else(|| Error::Other(anyhow::anyhow!("the PR's revision is missing")))?;
    let mut review = gate.json();
    for r in review["reviews"].as_array_mut().into_iter().flatten() {
        let real = r["revision"].as_i64().unwrap_or(0) as i32;
        r["revision"] = json!(vn.get(&real));
    }
    let threads: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pr_threads WHERE project_id = $1 AND pr = $2 AND state = 'open'")
        .bind(ask.project.id)
        .bind(&pr.id)
        .fetch_one(&hub.db)
        .await?;
    let current_head_proj = p[&current.head];
    let mut current_reals = vec![current.head];
    for r in &revs {
        if p[&r.head] == current_head_proj && !current_reals.contains(&r.head) {
            current_reals.push(r.head);
        }
    }
    let checks = crate::ci::checks_for(hub, &ask.project, &ask.viewer, current_head_proj, &current_reals).await?;
    // One entry per revision as the viewer numbers them: the first real
    // revision of each run (the later ones are the same to them).
    let mut shown = Vec::new();
    let mut last = 0;
    for r in &revs {
        if vn[&r.n] == last {
            continue;
        }
        last = vn[&r.n];
        shown.push(json!({
            "n": last,
            "base": p[&r.base].hex(),
            "head": p[&r.head].hex(),
            "changes": changes_json(r, &p),
            "patch": r.patch,
            "risk": r.risk,
            "files": r.files,
            "pushed_by": ppl.get(&r.pushed_by),
            "at": r.at,
        }));
    }
    let mut out = json!({
        "schema": "veil.pr/1",
        "id": pr.id,
        "title": pr.title,
        "body": pr.body,
        "author": pr.author_name,
        "target": pr.target,
        "state": pr.state,
        "risk": current.risk,
        "reasons": current.reasons,
        "revision": vn[&pr.revision],
        "patch": current.patch,
        "files": current.files,
        "created_at": pr.created_at,
        "open_threads": threads,
        "review": review,
        "checks": checks,
        "revisions": shown,
        "policy_version": ask.policy_version,
    });
    if !pr.embargo.is_empty() {
        out["embargo"] = json!(pr.embargo);
        out["land_at_release"] = json!(pr.land_at_release);
    }
    Ok(out)
}

// ---- operations (the routes call these; the tests call them directly) ------------

#[derive(Clone, Debug, Default, Deserialize)]
pub struct CreatePr {
    pub head: String,
    pub onto: Option<String>,
    pub title: String,
    pub body: Option<String>,
}

pub async fn create(hub: &Arc<Hub>, ask: &Ask, caller: &Caller, q: CreatePr) -> Result<Value> {
    let _ = participant(ask, caller)?;
    create_with(hub, ask, caller, q, false).await
}

pub async fn create_with(hub: &Arc<Hub>, ask: &Ask, caller: &Caller, q: CreatePr, land_at_release: bool) -> Result<Value> {
    let me = participant(ask, caller)?;
    let title = check_title(&q.title)?;
    let body = q.body.unwrap_or_default();
    check_text("the body", &body, MAX_TEXT)?;
    let gc_epoch = crate::pack_gc::read_gc_epoch(hub, ask.project.id).await?;
    let onto = q.onto.unwrap_or_else(|| ask.project.default_branch.clone());
    let deadline = Instant::now() + DEADLINE;
    // The target is a branch, named as the caller names it.
    let (onto_tip, onto_emb) = embargo::resolve_onto(hub, ask, &onto, deadline).await?;
    let (head, head_emb) = embargo::resolve_head(hub, ask, &q.head, deadline).await?;
    let pr_embargo = embargo::combine_embargo(ask, head_emb, onto_emb.clone())?;
    if land_at_release && pr_embargo.is_empty() {
        return Err(Error::bad_request("land_at_release applies only to an embargoed PR"));
    }
    // The branch landing deletes (BUG-1885). An embargoed PR has none: its
    // head is the embargo's line, which only the release removes.
    let source_branch = if pr_embargo.is_empty() {
        crate::branches::source_of_pr(hub, ask.project.id, &q.head, &onto, head).await?
    } else {
        None
    };
    let r = if pr_embargo.is_empty() {
        compute(hub, ask, head, onto_tip).await?
    } else {
        let rules = rules(hub, ask).await?;
        embargo::compute(hub, ask, head, onto_tip, onto_emb.is_some(), &pr_embargo, rules).await?
    };
    readable_by(ask, &r.touched)?;
    if ask.viewer.only.is_some() && r.touched.iter().any(|p| !ask.viewer.within_narrowing(p)) {
        return Err(crate::sync::agent_refusal(crate::sync::NARROWED_MOVE));
    }
    if ask.viewer.agent && r.touched.iter().any(|p| veil_core::hub::agent::decides_access(p)) {
        return Err(crate::sync::agent_refusal(crate::sync::AGENT_ACCESS_MOVE));
    }
    let key = class::policy_key(&ask.project.policy);
    let lines = class::lines_of(&ask.project.policy, r.touched.iter().map(String::as_str));
    let (project, r, pr_emb) = (ask.project.id, Arc::new(r), pr_embargo.clone());
    let mut made = None;
    for _ in 0..5 {
        let id = random_id();
        let now = veil_core::now_millis();
        let (r, key, lines, title, body, onto, pr_emb, src_b, id2) = (
            r.clone(),
            key.clone(),
            lines.clone(),
            title.clone(),
            body.clone(),
            onto.clone(),
            pr_emb.clone(),
            source_branch.clone(),
            id.clone(),
        );
        let fresh = transaction(&hub.db, Isolation::ReadCommitted, move |c| {
            let (r, key, lines, title, body, onto, pr_emb, src_b, id) = (
                r.clone(),
                key.clone(),
                lines.clone(),
                title.clone(),
                body.clone(),
                onto.clone(),
                pr_emb.clone(),
                src_b.clone(),
                id2.clone(),
            );
            Box::pin(async move {
                crate::pack_gc::guard_root_write(&mut *c, project, gc_epoch).await?;
                if !pr_emb.is_empty() {
                    let locked = sqlx::query(
                        "UPDATE embargo_lines SET has_pr = TRUE WHERE project_id = $1 AND embargo_id = $2 AND released_at IS NULL",
                    )
                    .bind(project)
                    .bind(&pr_emb)
                    .execute(&mut *c)
                    .await?
                    .rows_affected();
                    if locked == 0 {
                        return Err(Error::conflict("the embargo has already been released; open an ordinary PR"));
                    }
                }
                let class = class::put_class_for(&mut *c, project, &key, &lines, &pr_emb).await?;
                let inserted = sqlx::query(
                    "INSERT INTO prs (project_id, id, class_id, policy_key, target, author, title, body, state, revision, created_at, updated_at, embargo, land_at_release, source_branch) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'open', 1, $9, $9, $10, $11, $12) ON CONFLICT (project_id, id) DO NOTHING",
                )
                .bind(project)
                .bind(&id)
                .bind(&class)
                .bind(&key)
                .bind(&onto)
                .bind(me)
                .bind(&title)
                .bind(&body)
                .bind(now)
                .bind(&pr_emb)
                .bind(land_at_release && !pr_emb.is_empty())
                .bind(&src_b)
                .execute(&mut *c)
                .await?
                .rows_affected();
                if inserted == 0 {
                    return Ok(false);
                }
                write_revision(&mut *c, project, &id, 1, &r, me, now).await?;
                Ok(true)
            })
        })
        .await?;
        if fresh {
            made = Some(id);
            break;
        }
    }
    let id = made.ok_or_else(|| Error::Other(anyhow::anyhow!("no free PR id after 5 tries")))?;
    crate::events::emit_pr(hub, ask.project.id, &id, "pr.opened").await;
    let pr = visible(hub, ask, &id).await?;
    pr_json(hub, ask, &pr).await
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ListParams {
    pub state: Option<String>,
    pub q: Option<String>,
    pub n: Option<i64>,
    pub after: Option<String>,
}

/// The PRs the viewer may see, newest first by creation: only rows of
/// classes they satisfy are read.
pub async fn list(hub: &Arc<Hub>, ask: &Ask, q: ListParams) -> Result<Value> {
    let state = q.state.unwrap_or_else(|| "open".into());
    if !matches!(state.as_str(), "open" | "closed" | "landed" | "all") {
        return Err(Error::bad_request("state is open, closed, landed or all"));
    }
    let state = if state == "all" { String::new() } else { state };
    let search = q.q.unwrap_or_default();
    if search.chars().count() > 200 {
        return Err(Error::bad_request("a search is at most 200 characters"));
    }
    let like = if search.is_empty() {
        String::new()
    } else {
        format!("%{}%", search.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"))
    };
    let n = q.n.unwrap_or(50).clamp(1, MAX_PAGE);
    let (after_at, after_id) = match q.after.as_deref() {
        None => (None, String::new()),
        Some(a) => {
            let (t, id) = a.split_once(':').ok_or_else(|| Error::bad_request("invalid cursor"))?;
            let t: i64 = t.parse().map_err(|_| Error::bad_request("invalid cursor"))?;
            if !valid_pr_id(id) {
                return Err(Error::bad_request("invalid cursor"));
            }
            (Some(t), id.to_string())
        }
    };
    class::reclassify(hub, &ask.project).await?;
    let classes = class::satisfied(hub, &ask.project, &ask.viewer).await?;
    let states: Vec<String> = if state.is_empty() { vec!["open".into(), "closed".into(), "landed".into()] } else { vec![state] };
    let narrowed = ask.viewer.only.is_some();
    let only: Vec<String> = ask.viewer.only.as_deref().cloned().unwrap_or_default();
    // Each PR's current revision's risk as last rated, with the key of the
    // rules it was rated under: rated again under the rules in force where
    // they differ (BUG-1424).
    type Row = (String, String, String, String, String, String, i64, i32, String, String, String, bool);
    let (rows, count): (Vec<Row>, i64) = if like.is_empty() {
        // Newest first without sorting the classes' PRs: one ordered scan
        // of `prs_by_class` per (class, state), at most a page each, merged.
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT p.id, p.title, pe.name, p.state, r.risk, p.target, p.created_at, p.revision, r.reasons, r.rules_key, p.embargo, p.land_at_release \
             FROM UNNEST($2::text[]) AS c(class_id) CROSS JOIN UNNEST($3::text[]) AS s(state), \
             LATERAL (SELECT * FROM prs q WHERE q.project_id = $1 AND q.class_id = c.class_id AND q.state = s.state \
                      AND ($4::BIGINT IS NULL OR q.created_at < $4 OR (q.created_at = $4 AND q.id < $5)) \
                      AND (NOT $7 OR NOT EXISTS (SELECT 1 FROM pr_paths pp WHERE pp.project_id = q.project_id AND pp.pr = q.id \
                           AND NOT EXISTS (SELECT 1 FROM UNNEST($8::text[]) AS o(p) WHERE pp.path = o.p OR LEFT(pp.path, CHAR_LENGTH(o.p) + 1) = o.p || '/'))) \
                      ORDER BY q.created_at DESC, q.id DESC LIMIT $6) p \
             JOIN pr_revisions r ON r.project_id = p.project_id AND r.pr = p.id AND r.n = p.revision \
             JOIN people pe ON pe.id = p.author \
             ORDER BY p.created_at DESC, p.id DESC LIMIT $6",
        )
        .bind(ask.project.id)
        .bind(&classes)
        .bind(&states)
        .bind(after_at)
        .bind(&after_id)
        .bind(n + 1)
        .bind(narrowed)
        .bind(&only)
        .fetch_all(&hub.db)
        .await?;
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM prs q WHERE q.project_id = $1 AND q.class_id = ANY($2) AND q.state = ANY($3) \
             AND (NOT $4 OR NOT EXISTS (SELECT 1 FROM pr_paths pp WHERE pp.project_id = q.project_id AND pp.pr = q.id \
                  AND NOT EXISTS (SELECT 1 FROM UNNEST($5::text[]) AS o(p) WHERE pp.path = o.p OR LEFT(pp.path, CHAR_LENGTH(o.p) + 1) = o.p || '/')))",
        )
        .bind(ask.project.id)
        .bind(&classes)
        .bind(&states)
        .bind(narrowed)
        .bind(&only)
        .fetch_one(&hub.db)
        .await?;
        (rows, count)
    } else {
        // A search reads every PR of the satisfied classes once: the page
        // and the count from one scan.
        type Counted = (String, String, String, String, String, String, i64, i32, String, String, String, bool, i64);
        let rows: Vec<Counted> = sqlx::query_as(
            "SELECT p.id, p.title, pe.name, p.state, r.risk, p.target, p.created_at, p.revision, r.reasons, r.rules_key, p.embargo, p.land_at_release, p.total FROM ( \
                 SELECT q.*, COUNT(*) OVER () AS total, \
                        ($4::BIGINT IS NULL OR q.created_at < $4 OR (q.created_at = $4 AND q.id < $5)) AS after_cursor \
                 FROM prs q WHERE q.project_id = $1 AND q.class_id = ANY($2) AND q.state = ANY($3) \
                 AND (q.title ILIKE $7 OR q.body ILIKE $7) \
                 AND (NOT $8 OR NOT EXISTS (SELECT 1 FROM pr_paths pp WHERE pp.project_id = q.project_id AND pp.pr = q.id \
                      AND NOT EXISTS (SELECT 1 FROM UNNEST($9::text[]) AS o(p) WHERE pp.path = o.p OR LEFT(pp.path, CHAR_LENGTH(o.p) + 1) = o.p || '/')))) p \
             JOIN pr_revisions r ON r.project_id = p.project_id AND r.pr = p.id AND r.n = p.revision \
             JOIN people pe ON pe.id = p.author WHERE p.after_cursor \
             ORDER BY p.created_at DESC, p.id DESC LIMIT $6",
        )
        .bind(ask.project.id)
        .bind(&classes)
        .bind(&states)
        .bind(after_at)
        .bind(&after_id)
        .bind(n + 1)
        .bind(&like)
        .bind(narrowed)
        .bind(&only)
        .fetch_all(&hub.db)
        .await?;
        let count = match rows.first() {
            Some(r) => r.12,
            // An empty page (past the end) still counts every match.
            None => sqlx::query_scalar(
                "SELECT COUNT(*) FROM prs q WHERE q.project_id = $1 AND q.class_id = ANY($2) AND q.state = ANY($3) AND (q.title ILIKE $4 OR q.body ILIKE $4) \
                 AND (NOT $5 OR NOT EXISTS (SELECT 1 FROM pr_paths pp WHERE pp.project_id = q.project_id AND pp.pr = q.id \
                      AND NOT EXISTS (SELECT 1 FROM UNNEST($6::text[]) AS o(p) WHERE pp.path = o.p OR LEFT(pp.path, CHAR_LENGTH(o.p) + 1) = o.p || '/')))",
            )
            .bind(ask.project.id)
            .bind(&classes)
            .bind(&states)
            .bind(&like)
            .bind(narrowed)
            .bind(&only)
            .fetch_one(&hub.db)
            .await?,
        };
        (rows.into_iter().map(|r| (r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7, r.8, r.9, r.10, r.11)).collect(), count)
    };
    let more = rows.len() as i64 > n;
    let rows = &rows[..rows.len().min(n as usize)];
    let next = more.then(|| rows.last().map(|r| format!("{}:{}", r.6, r.0))).flatten();
    let rules = rules(hub, ask).await?;
    let mut risks = Vec::with_capacity(rows.len());
    for (id, _, _, _, risk, _, _, revision, reasons, rules_key, ..) in rows {
        let which = [(*revision, risk.clone(), serde_json::from_str(reasons).unwrap_or_default(), rules_key.clone())];
        risks.push(rate(hub, ask.project.id, id, &which, &rules).await?.remove(0).0);
    }
    Ok(json!({
        "schema": "veil.prs/1",
        "count": count,
        "prs": rows.iter().zip(&risks).map(|((id, title, author, state, _, target, created_at, _, _, _, embargo, land_at_release), risk)| {
            let mut item = json!({
                "id": id, "title": title, "author": author, "state": state, "risk": risk.name(),
                "target": target, "created_at": created_at,
            });
            if !embargo.is_empty() {
                item["embargo"] = json!(embargo);
                item["land_at_release"] = json!(land_at_release);
            }
            item
        }).collect::<Vec<_>>(),
        "next": next,
        "policy_version": ask.policy_version,
    }))
}

pub async fn show(hub: &Arc<Hub>, ask: &Ask, id: &str) -> Result<Value> {
    let pr = visible(hub, ask, id).await?;
    pr_json(hub, ask, &pr).await
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PrDiffParams {
    pub revision: Option<i32>,
    pub change: Option<String>,
    pub stat: Option<bool>,
}

/// A revision's diff (base to head), or one change's (its parent to it), as
/// S13 computes it on the viewer's projected history.
pub async fn diff(hub: &Arc<Hub>, ask: &Ask, id: &str, q: PrDiffParams) -> Result<Value> {
    let pr = visible(hub, ask, id).await?;
    let (revs, _, vn) = viewer_revisions(hub, ask, &pr.id, &pr.embargo).await?;
    // The viewer's number: the first real revision of that run.
    let n = q.revision.unwrap_or(vn[&pr.revision]);
    let r = revs.into_iter().find(|r| vn[&r.n] == n).ok_or_else(|| Error::not_found("no such revision of this PR"))?;
    let (from, to) = match &q.change {
        None => (r.base, r.head),
        Some(c) => {
            let c = r.changes.iter().find(|x| x.change == *c).ok_or_else(|| Error::not_found("no such change in this revision of the PR"))?;
            (c.parent_id(), c.snapshot_id())
        }
    };
    let p = projected(hub, ask, &pr.embargo, &[from, to]).await?;
    let mut v = if !pr.embargo.is_empty() {
        embargo::diff(hub, ask, from, to, p[&from], p[&to], q.stat).await?
    } else {
        query::diff_pr(hub, ask, p[&from], p[&to], q.stat, Limits::default()).await?
    };
    v["pr"] = json!(pr.id);
    v["revision"] = json!(n);
    Ok(v)
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RevisionRequest {
    pub head: String,
}

/// May the caller change the PR (a new revision, closing it)?
fn owner_or_admin(ask: &Ask, me: i64, pr: &PrRow) -> Result<()> {
    if pr.author != me && !ask.viewer.admin {
        return Err(Error::forbidden("only the PR's author or an admin may do that"));
    }
    if pr.state != "open" {
        return Err(Error::conflict(format!("the PR is {}", pr.state)));
    }
    Ok(())
}

type ThreadRow = (String, Option<String>, Option<String>);

pub async fn add_revision(hub: &Arc<Hub>, ask: &Ask, caller: &Caller, id: &str, q: RevisionRequest) -> Result<Value> {
    let me = participant(ask, caller)?;
    let pr = visible(hub, ask, id).await?;
    owner_or_admin(ask, me, &pr)?;
    if pr.revision >= MAX_REVISIONS {
        return Err(Error::bad_request(format!("a PR has at most {MAX_REVISIONS} revisions; open a new one")));
    }
    let gc_epoch = crate::pack_gc::read_gc_epoch(hub, ask.project.id).await?;
    let deadline = Instant::now() + DEADLINE;
    let (head, head_emb) = embargo::resolve_head(hub, ask, &q.head, deadline).await?;
    // An embargoed PR never has a source branch to delete (BUG-1885).
    let source_branch = if pr.embargo.is_empty() {
        crate::branches::source_of_pr(hub, ask.project.id, &q.head, &pr.target, head).await?
    } else {
        None
    };
    // The target as the caller sees it (never a withheld one), then its tip.
    let (onto, onto_emb) = embargo::resolve_onto(hub, ask, &pr.target, deadline)
        .await
        .map_err(|_| Error::conflict(format!("the target {} no longer exists", pr.target)))?;
    if pr.embargo.is_empty() {
        if head_emb.is_some() || onto_emb.is_some() {
            return Err(Error::conflict("an ordinary PR cannot be updated to an embargoed revision; open an embargoed PR"));
        }
    } else {
        for e in [&head_emb, &onto_emb].into_iter().flatten() {
            if e != &pr.embargo {
                return Err(if ask.viewer.admin {
                    Error::bad_request("a PR belongs to at most one embargo")
                } else {
                    not_a_pr()
                });
            }
        }
    }
    let r = if pr.embargo.is_empty() {
        compute(hub, ask, head, onto).await?
    } else {
        let rules = rules(hub, ask).await?;
        embargo::compute(hub, ask, head, onto, onto_emb.is_some(), &pr.embargo, rules).await?
    };
    let (revs, _, vn) = viewer_revisions(hub, ask, &pr.id, &pr.embargo).await?;
    let current = revs.iter().find(|x| x.n == pr.revision).cloned().ok_or_else(|| Error::Other(anyhow::anyhow!("the PR's revision is missing")))?;
    // The same revision to the caller (BUG-1254): named by their number,
    // and refused, as a revision only hidden content tells apart would be
    // shown to them as this one anyway.
    let p = projected(hub, ask, &pr.embargo, &[current.base, current.head, r.base, r.head]).await?;
    if p[&current.head] == p[&r.head] && p[&current.base] == p[&r.base] {
        return Err(Error::bad_request(format!("that is revision {} already", vn[&pr.revision])));
    }
    // What the PR touches is the union over every revision.
    let mut all: BTreeSet<String> = review::paths_of(hub, ask.project.id, &pr.id).await?.into_iter().collect();
    all.extend(r.touched.iter().cloned());
    // Visibility first, then the bound (the union's size counts paths the
    // caller may not see).
    readable_by(ask, &all)?;
    if ask.viewer.only.is_some() && all.iter().any(|p| !ask.viewer.within_narrowing(p)) {
        return Err(crate::sync::agent_refusal(crate::sync::NARROWED_MOVE));
    }
    if ask.viewer.agent && r.touched.iter().any(|p| veil_core::hub::agent::decides_access(p)) {
        return Err(crate::sync::agent_refusal(crate::sync::AGENT_ACCESS_MOVE));
    }
    if all.len() > revision::MAX_PATHS {
        return Err(Error::bad_request(format!("a PR touches at most {} paths over all its revisions; open a new one", revision::MAX_PATHS)));
    }
    // Carry every positioned anchor to the new revision.
    let threads: Vec<ThreadRow> = sqlx::query_as("SELECT id, anchor, now_at FROM pr_threads WHERE project_id = $1 AND pr = $2 AND now_at IS NOT NULL ORDER BY created_at, id")
        .bind(ask.project.id)
        .bind(&pr.id)
        .fetch_all(&hub.db)
        .await?;
    let n = pr.revision + 1;
    let (old_stack, new_stack) = (current.changes.clone(), r.changes.clone());
    let moved: Vec<(String, Option<String>)> = blocking(hub, ask.project.id, move |cx| {
        let anchors: Vec<(String, Anchor, At)> = threads
            .into_iter()
            .filter_map(|(tid, anchor, now)| Some((tid, serde_json::from_str(&anchor?).ok()?, serde_json::from_str(&now?).ok()?)))
            .collect();
        let moved = threads::carry_all(cx, anchors, &old_stack, &new_stack, n as u32, deadline)?;
        Ok(moved.into_iter().map(|(t, at)| (t, at.map(|x| serde_json::to_string(&x).expect("numbers")))).collect())
    })
    .await?;
    let key = class::policy_key(&ask.project.policy);
    let lines = class::lines_of(&ask.project.policy, all.iter().map(String::as_str));
    let (project, prid, pr_emb, r, old_rev) = (ask.project.id, pr.id.clone(), pr.embargo.clone(), Arc::new(r), pr.revision);
    let now = veil_core::now_millis();
    let ok = transaction(&hub.db, Isolation::ReadCommitted, move |c| {
        let (key, lines, prid, pr_emb, r, moved, src_b) =
            (key.clone(), lines.clone(), prid.clone(), pr_emb.clone(), r.clone(), moved.clone(), source_branch.clone());
        Box::pin(async move {
            crate::pack_gc::guard_root_write(&mut *c, project, gc_epoch).await?;
            close_review_gate(&mut *c, project).await?;
            let class = class::put_class_for(&mut *c, project, &key, &lines, &pr_emb).await?;
            // The compare-and-swap: two new revisions at once, one wins.
            let moved_on = sqlx::query(
                "UPDATE prs SET revision = $1, class_id = $2, policy_key = $3, updated_at = $4, source_branch = COALESCE($9, source_branch) \
                 WHERE project_id = $5 AND id = $6 AND revision = $7 AND embargo = $8 AND state = 'open'",
            )
            .bind(n)
            .bind(&class)
            .bind(&key)
            .bind(now)
            .bind(project)
            .bind(&prid)
            .bind(old_rev)
            .bind(&pr_emb)
            .bind(&src_b)
            .execute(&mut *c)
            .await?
            .rows_affected();
            if moved_on == 0 {
                return Ok(false);
            }
            write_revision(&mut *c, project, &prid, n, &r, me, now).await?;
            for (tid, at) in &moved {
                sqlx::query("UPDATE pr_threads SET now_at = $1 WHERE project_id = $2 AND pr = $3 AND id = $4")
                    .bind(at)
                    .bind(project)
                    .bind(&prid)
                    .bind(tid)
                    .execute(&mut *c)
                    .await?;
            }
            Ok(true)
        })
    })
    .await?;
    if !ok {
        return Err(Error::conflict("the PR changed meanwhile; look at it again (`vl pr show`)"));
    }
    crate::events::emit_pr(hub, ask.project.id, &pr.id, "pr.revision").await;
    show(hub, ask, id).await
}

pub async fn close(hub: &Arc<Hub>, ask: &Ask, caller: &Caller, id: &str) -> Result<Value> {
    let me = participant(ask, caller)?;
    let pr = visible(hub, ask, id).await?;
    owner_or_admin(ask, me, &pr)?;
    let (project, prid, now) = (ask.project.id, pr.id.clone(), veil_core::now_millis());
    // A closed PR's approvals count no more: the review gate, ordered
    // against every landing batch (BUG-2111).
    let n = transaction(&hub.db, Isolation::ReadCommitted, move |c| {
        let prid = prid.clone();
        Box::pin(async move {
            close_review_gate(&mut *c, project).await?;
            Ok(sqlx::query("UPDATE prs SET state = 'closed', updated_at = $1 WHERE project_id = $2 AND id = $3 AND state = 'open'")
                .bind(now)
                .bind(project)
                .bind(&prid)
                .execute(&mut *c)
                .await?
                .rows_affected())
        })
    })
    .await?;
    if n > 0 {
        crate::events::emit_pr(hub, ask.project.id, &pr.id, "pr.closed").await;
    }
    show(hub, ask, id).await
}

// ---- threads -------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize)]
pub struct NewThread {
    pub body: String,
    pub anchor: Option<AnchorRequest>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ThreadUpdate {
    pub body: Option<String>,
    pub state: Option<String>,
}

fn random_short() -> String {
    hex::encode(veil_core::crypto::random_bytes::<6>())
}

/// About the most bytes of comment text one answer holds (BUG-1253); one
/// comment is at most [`MAX_TEXT`], and an answer always holds at least one.
pub const ANSWER_BYTES: usize = 1 << 20;
/// Threads a listing page holds at most, and comments shown with each.
pub const THREADS_PAGE: i64 = 100;
pub const COMMENTS_SHOWN: i64 = 20;
/// Comments a thread's page holds at most.
pub const COMMENTS_PAGE: i64 = 500;

/// `"<time>:<id>"`, the cursor of threads and comments.
fn cursor(s: Option<&str>) -> Result<(i64, String)> {
    let Some(s) = s else { return Ok((i64::MIN, String::new())) };
    let bad = || Error::bad_request("invalid cursor");
    let (t, id) = s.split_once(':').ok_or_else(bad)?;
    if id.len() != 12 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad());
    }
    Ok((t.parse().map_err(|_| bad())?, id.to_string()))
}

type ThreadMeta = (String, Option<String>, Option<String>, String, i64, i64);
/// A comment without its body: (thread, id, author, at, bytes).
type CommentMeta = (String, String, i64, i64, i64);

/// The bodies of the chosen comments (thread, id), read only once chosen.
async fn comment_bodies(hub: &Hub, project: i64, pr: &str, chosen: &[(String, String)]) -> Result<HashMap<(String, String), String>> {
    if chosen.is_empty() {
        return Ok(HashMap::new());
    }
    let (threads, ids): (Vec<String>, Vec<String>) = chosen.iter().cloned().unzip();
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT c.thread, c.id, c.body FROM UNNEST($3::text[], $4::text[]) AS w(thread, id) \
         JOIN pr_comments c ON c.project_id = $1 AND c.pr = $2 AND c.thread = w.thread AND c.id = w.id",
    )
    .bind(project)
    .bind(pr)
    .bind(&threads)
    .bind(&ids)
    .fetch_all(&hub.db)
    .await?;
    Ok(rows.into_iter().map(|(t, i, b)| ((t, i), b)).collect())
}

fn comment_value(c: &CommentMeta, bodies: &HashMap<(String, String), String>, ppl: &HashMap<i64, String>) -> Value {
    json!({ "id": c.1, "author": ppl.get(&c.2), "body": bodies.get(&(c.0.clone(), c.1.clone())), "at": c.3 })
}

/// A thread as the viewer is shown it, with `comments` (and the cursor of
/// the rest, if any).
fn thread_value(t: &ThreadMeta, comments: Vec<Value>, more: Option<String>, ppl: &HashMap<i64, String>, vn: &HashMap<i32, i32>) -> Value {
    let (tid, anchor, now, state, author, created_at) = t;
    let a: Option<Anchor> = anchor.as_deref().and_then(|a| serde_json::from_str(a).ok());
    let at: Option<At> = now.as_deref().and_then(|a| serde_json::from_str(a).ok());
    let at = at.map(|a| json!({ "revision": vn.get(&(a.revision as i32)), "start": a.start, "end": a.end }));
    json!({
        "id": tid,
        "state": state,
        "author": ppl.get(author),
        "created_at": created_at,
        "outdated": a.is_some() && at.is_none(),
        "anchor": a.map(|a| json!({ "revision": vn.get(&(a.revision as i32)), "change_id": a.change, "path": a.path, "side": a.side, "start": a.start, "end": a.end })),
        "now": at,
        "comments": comments,
        "comments_next": more,
    })
}

async fn people_of(hub: &Hub, ts: &[ThreadMeta], cs: &[CommentMeta]) -> Result<HashMap<i64, String>> {
    let mut people: Vec<i64> = ts.iter().map(|t| t.4).chain(cs.iter().map(|c| c.2)).collect();
    people.sort();
    people.dedup();
    names(hub, &people).await
}

/// A page of the PR's threads, oldest first, each with its first comments,
/// within [`ANSWER_BYTES`] of comment text (BUG-1253): `next` names the
/// rest of the threads, and a thread's `comments_next` the rest of its
/// comments (`thread_json`).
pub async fn threads_json(hub: &Arc<Hub>, ask: &Ask, id: &str, after: Option<&str>) -> Result<Value> {
    let (after_at, after_id) = cursor(after)?;
    let pr = visible(hub, ask, id).await?;
    let (_, _, vn) = viewer_revisions(hub, ask, &pr.id, &pr.embargo).await?;
    let ts: Vec<ThreadMeta> = sqlx::query_as(
        "SELECT id, anchor, now_at, state, author, created_at FROM pr_threads WHERE project_id = $1 AND pr = $2 \
         AND (created_at > $3 OR (created_at = $3 AND id > $4)) ORDER BY created_at, id LIMIT $5",
    )
    .bind(ask.project.id)
    .bind(&pr.id)
    .bind(after_at)
    .bind(&after_id)
    .bind(THREADS_PAGE + 1)
    .fetch_all(&hub.db)
    .await?;
    let more_threads = ts.len() as i64 > THREADS_PAGE;
    let ts = &ts[..ts.len().min(THREADS_PAGE as usize)];
    let ids: Vec<String> = ts.iter().map(|t| t.0.clone()).collect();
    // Each thread's first comments and one more (to know there are more),
    // without their bodies: the sizes decide which fit, then only those
    // bodies are read (BUG-1258).
    let metas: Vec<CommentMeta> = sqlx::query_as(
        "SELECT t.id, c.id, c.author, c.at, c.size FROM UNNEST($3::text[]) AS t(id), \
         LATERAL (SELECT id, author, at, octet_length(body)::BIGINT AS size FROM pr_comments \
                  WHERE project_id = $1 AND pr = $2 AND thread = t.id ORDER BY at, id LIMIT $4) c",
    )
    .bind(ask.project.id)
    .bind(&pr.id)
    .bind(&ids)
    .bind(COMMENTS_SHOWN + 1)
    .fetch_all(&hub.db)
    .await?;
    let mut by_thread: HashMap<&str, Vec<&CommentMeta>> = HashMap::new();
    for c in &metas {
        by_thread.entry(c.0.as_str()).or_default().push(c);
    }
    for v in by_thread.values_mut() {
        v.sort_by(|a, b| (a.3, &a.1).cmp(&(b.3, &b.1)));
    }
    // Choose within the bytes, in the answer's order.
    type Planned<'a> = (&'a ThreadMeta, Vec<&'a CommentMeta>, Option<String>);
    let mut chosen: Vec<(String, String)> = Vec::new();
    let mut plan: Vec<Planned> = Vec::new();
    let (mut bytes, mut next): (usize, Option<String>) = (0, None);
    for t in ts {
        if bytes >= ANSWER_BYTES && !plan.is_empty() {
            next = plan.last().map(|(t, _, _)| format!("{}:{}", t.5, t.0));
            break;
        }
        let mine = by_thread.remove(t.0.as_str()).unwrap_or_default();
        let (mut shown, mut more) = (Vec::new(), None);
        for (i, c) in mine.iter().enumerate() {
            if i as i64 == COMMENTS_SHOWN || (bytes >= ANSWER_BYTES && !shown.is_empty()) {
                more = shown.last().map(|c: &&CommentMeta| format!("{}:{}", c.3, c.1));
                break;
            }
            bytes += c.4 as usize + 64;
            chosen.push((c.0.clone(), c.1.clone()));
            shown.push(*c);
        }
        plan.push((t, shown, more));
    }
    let bodies = comment_bodies(hub, ask.project.id, &pr.id, &chosen).await?;
    let ppl = people_of(hub, ts, &metas).await?;
    let mut out = Vec::new();
    for (t, shown, more) in plan {
        let comments = shown.iter().map(|c| comment_value(c, &bodies, &ppl)).collect();
        out.push(thread_value(t, comments, more, &ppl, &vn));
    }
    if next.is_none() && more_threads {
        next = ts.last().map(|t| format!("{}:{}", t.5, t.0));
    }
    Ok(json!({ "schema": "veil.pr.threads/2", "pr": pr.id, "revision": vn[&pr.revision], "threads": out, "next": next }))
}

/// One thread with a page of its comments from `after`, within
/// [`ANSWER_BYTES`].
pub async fn thread_json(hub: &Arc<Hub>, ask: &Ask, id: &str, thread: &str, after: Option<&str>) -> Result<Value> {
    let (after_at, after_id) = cursor(after)?;
    let pr = visible(hub, ask, id).await?;
    if thread.len() != 12 || !thread.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::not_found("no such thread in this PR"));
    }
    let (_, _, vn) = viewer_revisions(hub, ask, &pr.id, &pr.embargo).await?;
    let t: Option<ThreadMeta> =
        sqlx::query_as("SELECT id, anchor, now_at, state, author, created_at FROM pr_threads WHERE project_id = $1 AND pr = $2 AND id = $3")
            .bind(ask.project.id)
            .bind(&pr.id)
            .bind(thread)
            .fetch_optional(&hub.db)
            .await?;
    let t = t.ok_or_else(|| Error::not_found("no such thread in this PR"))?;
    // Sizes first; only the bodies that fit are read (BUG-1258).
    let cs: Vec<CommentMeta> = sqlx::query_as(
        "SELECT thread, id, author, at, octet_length(body)::BIGINT FROM pr_comments WHERE project_id = $1 AND pr = $2 AND thread = $3 \
         AND (at > $4 OR (at = $4 AND id > $5)) ORDER BY at, id LIMIT $6",
    )
    .bind(ask.project.id)
    .bind(&pr.id)
    .bind(thread)
    .bind(after_at)
    .bind(&after_id)
    .bind(COMMENTS_PAGE + 1)
    .fetch_all(&hub.db)
    .await?;
    let ppl = people_of(hub, std::slice::from_ref(&t), &cs).await?;
    let (mut picked, mut bytes, mut more) = (Vec::new(), 0usize, None);
    for (i, c) in cs.iter().enumerate() {
        if i as i64 == COMMENTS_PAGE || (bytes >= ANSWER_BYTES && !picked.is_empty()) {
            more = picked.last().map(|c: &&CommentMeta| format!("{}:{}", c.3, c.1));
            break;
        }
        bytes += c.4 as usize + 64;
        picked.push(c);
    }
    let chosen: Vec<(String, String)> = picked.iter().map(|c| (c.0.clone(), c.1.clone())).collect();
    let bodies = comment_bodies(hub, ask.project.id, &pr.id, &chosen).await?;
    let shown = picked.iter().map(|c| comment_value(c, &bodies, &ppl)).collect();
    let mut v = thread_value(&t, shown, more, &ppl, &vn);
    v["schema"] = json!("veil.pr.thread/1");
    v["pr"] = json!(pr.id);
    Ok(v)
}

pub async fn new_thread(hub: &Arc<Hub>, ask: &Ask, caller: &Caller, id: &str, q: NewThread) -> Result<Value> {
    let me = participant(ask, caller)?;
    let pr = visible(hub, ask, id).await?;
    check_text("a comment", &q.body, MAX_TEXT)?;
    if q.body.trim().is_empty() {
        return Err(Error::bad_request("a comment needs a body"));
    }
    let (anchor, at) = match q.anchor {
        None => (None, None),
        Some(a) => {
            ask.file_path(Some(&a.path))?;
            let revs = revisions(hub, ask.project.id, &pr.id).await?;
            let current = revs.into_iter().find(|r| r.n == pr.revision).ok_or_else(|| Error::Other(anyhow::anyhow!("the PR's revision is missing")))?;
            let n = pr.revision as u32;
            let stack = current.changes.clone();
            let a = blocking(hub, ask.project.id, move |cx| threads::anchor(cx, n, &stack, &a)).await?;
            let at = At { revision: n, start: a.start, end: a.end };
            (Some(serde_json::to_string(&a).expect("plain")), Some(serde_json::to_string(&at).expect("numbers")))
        }
    };
    let (project, prid, body, tid, cid) = (ask.project.id, pr.id.clone(), q.body.clone(), random_short(), random_short());
    let tid_out = tid.clone();
    let now = veil_core::now_millis();
    let made = transaction(&hub.db, Isolation::ReadCommitted, move |c| {
        let (prid, body, tid, cid, anchor, at) = (prid.clone(), body.clone(), tid.clone(), cid.clone(), anchor.clone(), at.clone());
        Box::pin(async move {
            // Bounded per PR; the lock on the PR's row orders thread
            // creation, so the count holds.
            sqlx::query("SELECT id FROM prs WHERE project_id = $1 AND id = $2 FOR UPDATE").bind(project).bind(&prid).execute(&mut *c).await?;
            let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pr_threads WHERE project_id = $1 AND pr = $2")
                .bind(project)
                .bind(&prid)
                .fetch_one(&mut *c)
                .await?;
            if n >= MAX_THREADS {
                return Ok(false);
            }
            sqlx::query("INSERT INTO pr_threads (project_id, pr, id, anchor, now_at, state, author, created_at) VALUES ($1, $2, $3, $4, $5, 'open', $6, $7)")
                .bind(project)
                .bind(&prid)
                .bind(&tid)
                .bind(&anchor)
                .bind(&at)
                .bind(me)
                .bind(now)
                .execute(&mut *c)
                .await?;
            sqlx::query("INSERT INTO pr_comments (project_id, pr, thread, id, author, body, at) VALUES ($1, $2, $3, $4, $5, $6, $7)")
                .bind(project)
                .bind(&prid)
                .bind(&tid)
                .bind(&cid)
                .bind(me)
                .bind(&body)
                .bind(now)
                .execute(&mut *c)
                .await?;
            Ok(true)
        })
    })
    .await?;
    if !made {
        return Err(Error::bad_request(format!("a PR has at most {MAX_THREADS} threads")));
    }
    crate::events::emit_pr(hub, ask.project.id, &pr.id, "pr.comment").await;
    thread_json(hub, ask, id, &tid_out, None).await
}

pub async fn update_thread(hub: &Arc<Hub>, ask: &Ask, caller: &Caller, id: &str, thread: &str, q: ThreadUpdate) -> Result<Value> {
    let me = participant(ask, caller)?;
    let pr = visible(hub, ask, id).await?;
    if thread.len() != 12 || !thread.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::not_found("no such thread in this PR"));
    }
    if let Some(b) = &q.body {
        check_text("a comment", b, MAX_TEXT)?;
        if b.trim().is_empty() {
            return Err(Error::bad_request("a comment needs a body"));
        }
    }
    let state = match q.state.as_deref() {
        None => None,
        Some(s @ ("open" | "resolved")) => Some(s.to_string()),
        Some(_) => return Err(Error::bad_request("a thread's state is open or resolved")),
    };
    if q.body.is_none() && state.is_none() {
        return Err(Error::bad_request("reply with a body, or set the state"));
    }
    let has_body = q.body.is_some();
    let (project, prid, tid, body, cid) = (ask.project.id, pr.id.clone(), thread.to_string(), q.body.clone(), random_short());
    let now = veil_core::now_millis();
    let found = transaction(&hub.db, Isolation::ReadCommitted, move |c| {
        let (prid, tid, body, cid, state) = (prid.clone(), tid.clone(), body.clone(), cid.clone(), state.clone());
        Box::pin(async move {
            let t: Option<String> = sqlx::query_scalar("SELECT id FROM pr_threads WHERE project_id = $1 AND pr = $2 AND id = $3 FOR UPDATE")
                .bind(project)
                .bind(&prid)
                .bind(&tid)
                .fetch_optional(&mut *c)
                .await?;
            if t.is_none() {
                return Ok(Some(false));
            }
            if let Some(body) = &body {
                let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pr_comments WHERE project_id = $1 AND pr = $2 AND thread = $3")
                    .bind(project)
                    .bind(&prid)
                    .bind(&tid)
                    .fetch_one(&mut *c)
                    .await?;
                if n >= MAX_COMMENTS {
                    return Ok(None);
                }
                sqlx::query("INSERT INTO pr_comments (project_id, pr, thread, id, author, body, at) VALUES ($1, $2, $3, $4, $5, $6, $7)")
                    .bind(project)
                    .bind(&prid)
                    .bind(&tid)
                    .bind(&cid)
                    .bind(me)
                    .bind(body)
                    .bind(now)
                    .execute(&mut *c)
                    .await?;
            }
            if let Some(s) = &state {
                sqlx::query("UPDATE pr_threads SET state = $1 WHERE project_id = $2 AND pr = $3 AND id = $4")
                    .bind(s)
                    .bind(project)
                    .bind(&prid)
                    .bind(&tid)
                    .execute(&mut *c)
                    .await?;
            }
            Ok(Some(true))
        })
    })
    .await?;
    match found {
        Some(true) => {
            if has_body {
                crate::events::emit_pr(hub, ask.project.id, &pr.id, "pr.comment").await;
            }
            thread_json(hub, ask, id, thread, None).await
        }
        Some(false) => Err(Error::not_found("no such thread in this PR")),
        None => Err(Error::bad_request(format!("a thread has at most {MAX_COMMENTS} comments"))),
    }
}

// ---- reviews and landing -----------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ReviewRequest {
    /// The current revision's patch, as the reviewer was shown it.
    pub patch: String,
    pub verdict: String,
    pub body: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

pub async fn add_review(hub: &Arc<Hub>, ask: &Ask, caller: &Caller, id: &str, q: ReviewRequest) -> Result<Value> {
    let me = participant(ask, caller)?;
    let person = signed_in(caller)?;
    let pr = visible(hub, ask, id).await?;
    if pr.state != "open" {
        return Err(Error::conflict(format!("the PR is {}", pr.state)));
    }
    if !VERDICTS.contains(&q.verdict.as_str()) {
        return Err(Error::bad_request("a verdict is approve or request-changes"));
    }
    let agent = caller.agent().is_some() || ask.viewer.agent;
    if agent && q.verdict == "approve" {
        return Err(crate::sync::agent_refusal(
            "an agent session never approves a PR: review and approve from a person's session",
        ));
    }
    if pr.author == me {
        return Err(Error::forbidden("you wrote this PR: someone else reviews it"));
    }
    let body = q.body.unwrap_or_default();
    check_text("a review", &body, MAX_TEXT)?;
    let paths = review::paths_of(hub, ask.project.id, &pr.id).await?;
    if !review::writes_all(&ask.project, &ask.viewer, &paths) {
        return Err(Error::forbidden("only people who may write every file of this PR review it"));
    }
    let revs = revisions(hub, ask.project.id, &pr.id).await?;
    let current = revs.into_iter().find(|r| r.n == pr.revision).ok_or_else(|| Error::Other(anyhow::anyhow!("the PR's files changed since you looked at it: look at it again")))?;
    if q.patch != current.patch {
        return Err(Error::conflict("the PR's files changed since you looked at it: look at it again"));
    }
    let recorded_sig: String = match q.signature.as_deref().filter(|s| !s.is_empty()) {
        Some(sig) => {
            let msg = review_message(&ask.project.name, &pr.id, &current.patch, &q.verdict);
            if !verify_signature(&person.device_key, SIG_CONTEXT_HUB_PR_REVIEW, &msg, sig) {
                return Err(Error::unauthorized("the review's signature is not this device's over this revision"));
            }
            sig.to_string()
        }
        None => {
            if !caller.is_web() {
                return Err(Error::unauthorized("a review outside the web client must be signed by this device"));
            }
            caller.person_only()?;
            "web-session".to_string()
        }
    };
    let stored = review::put_verdict(hub, ask.project.id, &pr.id, pr.revision, me, &q.verdict, &current.patch, agent, &person.device_key, &recorded_sig, &body, true).await?;
    if !stored {
        return Err(Error::conflict("the PR changed meanwhile: look at it again"));
    }
    crate::events::emit_pr(hub, ask.project.id, &pr.id, "pr.review").await;
    if !pr.embargo.is_empty() && q.verdict == "approve" {
        crate::embargo::try_release_waiting(hub, ask.project.id, &pr.embargo).await;
    }
    show(hub, ask, id).await
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct DismissRequest {
    /// The reviewer, by name.
    pub person: String,
}

/// An admin dismisses a reviewer's requests for changes (BUG-1259).
pub async fn dismiss(hub: &Arc<Hub>, ask: &Ask, caller: &Caller, id: &str, q: DismissRequest) -> Result<Value> {
    caller.not_runner()?;
    caller.person_only()?;
    participant(ask, caller)?;
    let pr = visible(hub, ask, id).await?;
    if !ask.viewer.admin {
        return Err(Error::forbidden("only an admin dismisses a request for changes"));
    }
    let person: Option<i64> = sqlx::query_scalar("SELECT id FROM people WHERE name = $1").bind(&q.person).fetch_optional(&hub.db).await?;
    let person = person.ok_or_else(|| Error::not_found("no such person"))?;
    if review::dismiss(hub, ask.project.id, &pr, person).await? == 0 {
        return Err(Error::not_found(format!("{} has no request for changes on this PR", q.person)));
    }
    crate::embargo::try_release_waiting_in_project(hub, ask.project.id).await;
    show(hub, ask, id).await
}

pub async fn dismiss_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, id)): Path<(String, String)>,
    Json(q): Json<DismissRequest>,
) -> Result<Json<Value>> {
    let ask = open(&hub, &p, &caller).await?;
    Ok(Json(dismiss(&hub, &ask, &caller, &id, q).await?))
}

/// Paths touched by `stack` when applied onto its entries' bases.
pub async fn stack_touched_paths(
    hub: &Arc<Hub>,
    project_id: i64,
    stack: &[crate::landing::Entry],
    staged: Option<Arc<crate::sync::Staged>>,
) -> Result<Vec<String>> {
    if stack.is_empty() {
        return Ok(Vec::new());
    }
    let entries = stack.to_vec();
    crate::sync::blocking_staged(hub, project_id, staged, move |src| {
        let mut touched = BTreeSet::new();
        for e in &entries {
            let s = src.snapshot(&e.id)?;
            let parent = if s.parents.get(1..).is_some_and(|o| o.contains(&e.base)) {
                e.base
            } else {
                s.parents.first().copied().unwrap_or_else(crate::sync::root_snapshot_id)
            };
            let ptree = src.snapshot(&parent)?.tree;
            let (leaves, dirs) = crate::derive::changes::diff(src, ptree, s.tree)?;
            for c in &leaves {
                touched.insert(c.path.clone());
            }
            touched.extend(dirs.into_iter().filter(|d| !d.is_empty()));
        }
        Ok(touched.into_iter().collect())
    })
    .await
}

/// Diff summary of a landing stack for the review rules' check (`BUG-1880`).
#[derive(Clone, Debug)]
pub struct StackReviewDiff {
    pub touched: BTreeSet<String>,
    pub files: Vec<rules::FileChange>,
    pub patch: String,
    /// What "reverted twice" counts the stack's entries by (BUG-1884,
    /// BUG-1921): each one's change id, and what its edits are whatever
    /// change id carries them ([`edits_id`]).
    pub changes: Vec<String>,
}

/// What a change's edits are, whatever change id it is given (BUG-1921):
/// a hash of the leaves its tree differs at from its base's (each path,
/// with the entry before and after), in a domain of its own. The same edit
/// made again as a new change has the same one; a rebased version whose
/// files differ has another, and is known by its change id. `None` for a
/// change with no edits.
fn edits_id_of(leaves: &[veil_core::hub::project::Change]) -> Option<String> {
    if leaves.is_empty() {
        return None;
    }
    let mut h = blake3::Hasher::new_derive_key("veil 2026 hub change edits v1");
    h.update(&(leaves.len() as u64).to_le_bytes());
    for c in leaves {
        h.update(&(c.path.len() as u64).to_le_bytes());
        h.update(c.path.as_bytes());
        revision::entry_bytes(&mut h, c.old.as_ref());
        revision::entry_bytes(&mut h, c.new.as_ref());
    }
    Some(format!("edits:{}", h.finalize().to_hex()))
}

/// `edits_id_of`: the edits of `snapshot` against `parent`.
pub fn edits_id(src: &crate::sync::Source, snapshot: ObjectId, parent: ObjectId) -> Result<Option<String>> {
    let (leaves, _) = crate::derive::changes::diff(src, src.snapshot(&parent)?.tree, src.snapshot(&snapshot)?.tree)?;
    Ok(edits_id_of(&leaves))
}

/// What "reverted twice" counts the changes of a PR's revision by: their
/// change ids and their edits ([`edits_id`]).
pub(crate) async fn revert_identities(hub: &Arc<Hub>, project: i64, changes: &[StackChange]) -> Result<Vec<String>> {
    let stack = changes.to_vec();
    crate::sync::blocking(hub, project, move |src| {
        let mut ids = Vec::with_capacity(stack.len() * 2);
        for c in &stack {
            ids.push(c.change.clone());
            ids.extend(edits_id(src, c.snapshot_id(), c.parent_id())?);
        }
        Ok(ids)
    })
    .await
}

/// Compute [`StackReviewDiff`] for `stack` from `src`.
pub fn stack_review_diff(src: &crate::sync::Source, stack: &[crate::landing::Entry]) -> Result<StackReviewDiff> {
    let mut changes = Vec::with_capacity(stack.len());
    let mut touched = BTreeSet::new();
    let mut files: std::collections::BTreeMap<String, rules::FileChange> = std::collections::BTreeMap::new();
    let mut patch = blake3::Hasher::new_derive_key("veil 2026 hub pr patch v1");
    for e in stack {
        let s = src.snapshot(&e.id)?;
        changes.push(s.change_id.to_string());
        let parent = if s.parents.get(1..).is_some_and(|o| o.contains(&e.base)) {
            e.base
        } else {
            s.parents.first().copied().unwrap_or_else(crate::sync::root_snapshot_id)
        };
        let ptree = src.snapshot(&parent)?.tree;
        let (leaves, dirs) = crate::derive::changes::diff(src, ptree, s.tree)?;
        changes.extend(edits_id_of(&leaves));
        if !leaves.is_empty() {
            patch.update(&s.change_id.0);
            patch.update(&(leaves.len() as u64).to_le_bytes());
        }
        for c in &leaves {
            patch.update(&(c.path.len() as u64).to_le_bytes());
            patch.update(c.path.as_bytes());
            revision::entry_bytes(&mut patch, c.old.as_ref());
            revision::entry_bytes(&mut patch, c.new.as_ref());
            let secret = [&c.old, &c.new].iter().any(|e| e.as_ref().is_some_and(|e| !e.visibility.is_public()));
            let executable = c.new.as_ref().is_some_and(|e| e.executable);
            let regular = [&c.old, &c.new].iter().all(|e| e.as_ref().is_none_or(|e| e.kind == veil_core::object::EntryKind::File));
            let f = files.entry(c.path.clone()).or_insert(rules::FileChange {
                path: c.path.clone(),
                secret,
                executable,
                regular,
            });
            f.secret |= secret;
            f.executable |= executable;
            f.regular &= regular;
            touched.insert(c.path.clone());
        }
        touched.extend(dirs.into_iter().filter(|d| !d.is_empty()));
    }
    Ok(StackReviewDiff {
        touched,
        files: files.into_values().collect(),
        patch: patch.finalize().to_hex().to_string(),
        changes,
    })
}

/// Snapshot of the default branch's protection set and review rules prepared for
/// a landing batch (`BUG-1880`).
#[derive(Clone, Debug)]
pub struct BranchReviewContext {
    pub default_branch: String,
    pub default_tip: Option<ObjectId>,
    pub default_file: state::RulesFile,
    pub protected: std::collections::BTreeSet<String>,
    pub rules: Review,
}

pub async fn branch_review_context(
    hub: &Arc<Hub>,
    project: &crate::perm::Project,
    branch: &str,
    on_tip: Option<ObjectId>,
    pending: Arc<HashMap<ObjectId, bytes::Bytes>>,
) -> Result<BranchReviewContext> {
    let db_default_tip = tip(hub, project.id, &project.default_branch).await?;
    let default_tip = if branch == project.default_branch {
        on_tip
    } else {
        db_default_tip
    };
    let pid = project.id;
    let rt = tokio::runtime::Handle::current();
    let (protected, default_file) = tokio::task::spawn_blocking({
        let hub = hub.clone();
        move || {
            let src = crate::sync::Source {
                hub,
                project: pid,
                rt,
                pending: (*pending).clone(),
                staged: None,
            };
            let protected = crate::landing::protected(&src, default_tip)?;
            let file = match default_tip {
                Some(t) => state::file_at(&src, src.snapshot(&t)?.tree)?,
                None => state::RulesFile::Absent,
            };
            Ok::<_, Error>((protected, file))
        }
    })
    .await
    .map_err(|e| Error::Other(e.into()))??;
    let rules = match &default_file {
        state::RulesFile::Valid(t) => Review::parse(Some(t.as_bytes())),
        state::RulesFile::Absent => Review::default(),
        state::RulesFile::Broken(_) if default_tip == db_default_tip => {
            state::rules_in_force(hub, project, &project.default_branch).await?
        }
        state::RulesFile::Broken(_) => {
            let row: Option<(String, String)> = sqlx::query_as(
                "SELECT checked, state FROM pr_review_rules WHERE project_id = $1",
            )
            .bind(project.id)
            .fetch_optional(&hub.db)
            .await?;
            let st = match (row, db_default_tip) {
                (Some((checked, state_str)), Some(dbt)) if checked == dbt.hex() => {
                    serde_json::from_str(&state_str).unwrap_or(state::RulesState::Strict)
                }
                _ => state::RulesState::Strict,
            };
            state::review_of(&default_file, &st)
        }
    };
    Ok(BranchReviewContext {
        default_branch: project.default_branch.clone(),
        default_tip,
        default_file,
        protected,
        rules,
    })
}

/// Verify inside a batch's commit transaction that the default branch's review
/// rules have not changed since [`branch_review_context`] ran (`BUG-1880`).
pub async fn rules_unchanged_in_tx(
    c: &mut sqlx::PgConnection,
    project_id: i64,
    branch: &str,
    old_tip: Option<ObjectId>,
    ctx: &BranchReviewContext,
) -> Result<bool> {
    let tip = if branch == ctx.default_branch {
        old_tip
    } else {
        let cur: Option<String> = sqlx::query_scalar(
            "SELECT target FROM branches WHERE project_id = $1 AND name = $2 AND hidden_for_embargo IS NULL",
        )
        .bind(project_id)
        .bind(&ctx.default_branch)
        .fetch_optional(&mut *c)
        .await?;
        if cur != ctx.default_tip.map(|t| t.hex()) {
            return Ok(false);
        }
        ctx.default_tip
    };
    let live_rules = match tip {
        None => Review::default(),
        Some(t) => {
            let row: Option<(String, String)> = sqlx::query_as(
                "SELECT checked, state FROM pr_review_rules WHERE project_id = $1",
            )
            .bind(project_id)
            .fetch_optional(&mut *c)
            .await?;
            let st = match row {
                Some((checked, state_str)) if checked == t.hex() => {
                    serde_json::from_str(&state_str).unwrap_or(state::RulesState::Strict)
                }
                _ => state::next_state(&ctx.default_file, None),
            };
            state::review_of(&ctx.default_file, &st)
        }
    };
    Ok(live_rules == ctx.rules)
}

/// Every refusal of a landing under the review rules starts with this.
pub const NOT_READY: &str = "not ready to land:";

/// Evaluate the review rules for a landing on `c` (usable both in
/// `Service::prepare` and inside `Service::commit`'s single transaction,
/// `BUG-1880`), the one rule every route that lands meets (S17 + S21,
/// `docs/HUB.md` §13.24: push, `POST …/land`, API commit with land,
/// `POST …/prs/{id}/land`, an embargo's release): a protected branch's
/// (`branch_protected`), and on any branch a person's approval of a change
/// the server reverted twice (BUG-1884; the reverts as recorded:
/// `bisect::settle_queued_reverts` comes first). On an unprotected branch
/// with no such change there is nothing to meet.
///
/// A landing of a PR (`ReviewClaim::Pr`) meets that PR's gate at the revision
/// it was submitted at. Any other: if an open PR on `branch` has the stack's
/// patch as its current revision (and covers its paths), its gate decides;
/// for an embargo's release (`ReviewClaim::Embargo`), a PR of that embargo
/// may carry the approvals (BUG-1861). Otherwise the stack is rated directly
/// under `rules` with 0 approvals.
///
/// Returns `Ok(Ok(matched_pr))` when ready, or `Ok(Err(message))` with the
/// refusal message the submit route gives.
#[allow(clippy::too_many_arguments)]
pub async fn verify_landing_review(
    c: &mut sqlx::PgConnection,
    project: &crate::perm::Project,
    viewer: &Viewer,
    branch: &str,
    diff: &StackReviewDiff,
    rules: &Review,
    claim: Option<&crate::landing::ReviewClaim>,
    branch_protected: bool,
) -> Result<std::result::Result<Option<String>, String>> {
    let rev_twice = crate::bisect::any_reverted_twice_conn(&mut *c, project.id, &diff.changes).await?;
    if !branch_protected && !rev_twice {
        return Ok(Ok(None));
    }
    if let Some(crate::landing::ReviewClaim::Pr { id, revision: req_rev, patch: req_patch }) = claim {
        type Row = (String, i64, String, String, String, String, i32, i64, i64, String, bool, Option<String>, Option<String>);
        let row: Option<Row> = sqlx::query_as(
            "SELECT p.target, p.author, pe.name, p.title, p.body, p.state, p.revision, p.created_at, p.updated_at, p.embargo, p.land_at_release, r.patch, r.files \
             FROM prs p JOIN people pe ON pe.id = p.author \
             LEFT JOIN pr_revisions r ON r.project_id = p.project_id AND r.pr = p.id AND r.n = p.revision \
             WHERE p.project_id = $1 AND p.id = $2",
        )
        .bind(project.id)
        .bind(id)
        .fetch_optional(&mut *c)
        .await?;
        let Some((target, author, author_name, title, body, state_str, cur_rev, created_at, updated_at, embargo, land_at_release, cur_patch, cur_files)) = row
        else {
            return Ok(Err(format!("{NOT_READY} the PR no longer exists")));
        };
        let pr = PrRow {
            id: id.clone(),
            target,
            author,
            author_name,
            title,
            body,
            state: state_str,
            revision: cur_rev,
            created_at,
            updated_at,
            embargo,
            land_at_release,
        };
        if pr.state == "open" && (cur_rev != *req_rev || cur_patch.as_deref() != Some(req_patch.as_str())) {
            return Ok(Err(format!("{NOT_READY} a new revision was pushed to the PR")));
        }
        let pr_files: Vec<FileChange> = match cur_files {
            Some(f) => serde_json::from_str(&f).map_err(|e| Error::Other(e.into()))?,
            None => diff.files.clone(),
        };
        let (pr_risk, _) = classify(&pr_files, rules);
        let patch_ref = cur_patch.as_deref().unwrap_or(req_patch.as_str());
        let g = review::gate_conn(&mut *c, project, viewer, &pr, patch_ref, pr_risk, rules, rev_twice, false).await?;
        return if g.ready {
            Ok(Ok(Some(pr.id)))
        } else {
            Ok(Err(format!("{NOT_READY} {}", g.reasons.join("; "))))
        };
    }

    let (effective_patch, embargo_id) = match claim {
        Some(crate::landing::ReviewClaim::Patch { patch }) => (patch.as_str(), None),
        Some(crate::landing::ReviewClaim::Embargo { embargo, patch }) => (patch.as_str(), Some(embargo.as_str())),
        _ => (diff.patch.as_str(), None),
    };
    let (risk, _) = classify(&diff.files, rules);

    type Cand = (String, i64, String, String, String, i32, i64, i64, String, bool, String);
    let cands: Vec<Cand> = sqlx::query_as(
        "SELECT p.id, p.author, pe.name, p.title, p.body, p.revision, p.created_at, p.updated_at, p.embargo, p.land_at_release, r.files \
         FROM prs p JOIN pr_revisions r ON r.project_id = p.project_id AND r.pr = p.id AND r.n = p.revision \
         JOIN people pe ON pe.id = p.author \
         WHERE p.project_id = $1 AND p.target = $2 AND p.state = 'open' \
           AND (p.embargo = '' OR ($4::text IS NOT NULL AND p.embargo = $4)) \
           AND r.patch = $3 \
         ORDER BY p.updated_at DESC, p.id DESC",
    )
    .bind(project.id)
    .bind(branch)
    .bind(effective_patch)
    .bind(embargo_id)
    .fetch_all(&mut *c)
    .await?;
    let mut not_ready_reasons: Option<Vec<String>> = None;
    for (id, author, author_name, title, body, revision, created_at, updated_at, pr_embargo, land_at_release, rev_files_json) in cands {
        let pr_paths: BTreeSet<String> = review::paths_of_conn(&mut *c, project.id, &id).await?.into_iter().collect();
        if !diff.touched.is_subset(&pr_paths) {
            continue;
        }
        let pr = PrRow {
            id: id.clone(),
            target: branch.to_string(),
            author,
            author_name,
            title,
            body,
            state: "open".into(),
            revision,
            created_at,
            updated_at,
            embargo: pr_embargo,
            land_at_release,
        };
        let rev_files: Vec<FileChange> = serde_json::from_str(&rev_files_json).map_err(|e| Error::Other(e.into()))?;
        let (pr_risk, _) = classify(&rev_files, rules);
        let gate = review::gate_conn(&mut *c, project, viewer, &pr, effective_patch, pr_risk, rules, rev_twice, false).await?;
        if gate.ready {
            return Ok(Ok(Some(pr.id)));
        }
        if not_ready_reasons.is_none() {
            not_ready_reasons = Some(gate.reasons);
        }
    }
    if let Some(reasons) = not_ready_reasons {
        return Ok(Err(format!("{NOT_READY} {}", reasons.join("; "))));
    }
    let risk = if rev_twice { Risk::High } else { risk };
    let mut need = if branch_protected {
        rules.need(risk)
    } else {
        rules::Need { approvals: 1, people_only: true }
    };
    if rev_twice {
        need.approvals = need.approvals.max(1);
        need.people_only = true;
    }
    let paths: Vec<String> = diff.touched.iter().cloned().collect();
    let held: Vec<String> = if branch_protected {
        review::holds_for_pr_conn(&mut *c, project.id, embargo_id.unwrap_or(""), &paths)
            .await?
            .into_iter()
            .map(|(_, n, _)| n)
            .collect()
    } else {
        Vec::new()
    };
    if need.approvals == 0 && held.is_empty() {
        return Ok(Ok(None));
    }
    let mut reasons: Vec<String> = if !branch_protected {
        Vec::new()
    } else if project.view(viewer).admin {
        rules.warnings.clone()
    } else if rules.warnings.is_empty() {
        Vec::new()
    } else {
        vec![format!("the project's review rules ({}) need an admin's attention", rules::RULES_FILE)]
    };
    if need.approvals > 0 {
        if rev_twice {
            reasons.push(review::REVERTED_TWICE_REASON.to_string());
        } else {
            reasons.push(format!(
                "{} risk needs {} approval{}{}; it has 0",
                risk.name(),
                need.approvals,
                if need.approvals == 1 { "" } else { "s" },
                if need.people_only { " from people (not agents)" } else { "" },
            ));
        }
    }
    for h in &held {
        reasons.push(format!("{h} asked for changes"));
    }
    Ok(Err(format!("{NOT_READY} {}", reasons.join("; "))))
}

pub(crate) use self::review_gate::close_review_gate;

/// One entry of a landing batch, for [`verify_landing_reviews`]: what
/// [`verify_landing_review`] is asked of it.
pub struct LandingReview<'a> {
    pub project: &'a crate::perm::Project,
    pub viewer: &'a Viewer,
    pub diff: &'a StackReviewDiff,
    pub claim: Option<&'a crate::landing::ReviewClaim>,
}

/// [`verify_landing_review`] for every entry of a landing batch onto
/// `branch` of `project`, with the same answers, in a number of statements
/// that does not grow with the batch (BUG-1942: the batch asked for each
/// entry in turn, three statements each, in its commit transaction too).
///
/// Three statements read, for all the entries at once, what could make an
/// entry's answer anything but "nothing to meet": a change of it the server
/// reverted twice, an open PR on `branch` whose current revision is its
/// patch, a reviewer's hold on a path it touches. An entry none of them
/// names, with no PR or embargo of its own (`ReviewClaim`) and a risk that
/// needs no approval, is ready, as [`verify_landing_review`] would find from
/// the same rows. Any other entry is asked alone, there.
///
/// `reverted_twice`: whether the project has a change the server reverted
/// twice at all (`bisect::has_reverted_twice`, which the batch's
/// transaction checks again). `asks` counts the statements for the whole
/// batch and the entries asked alone (`landing::Stats::review_asks`).
#[allow(clippy::too_many_arguments)]
pub async fn verify_landing_reviews(
    c: &mut sqlx::PgConnection,
    project: i64,
    branch: &str,
    rules: &Review,
    items: &[LandingReview<'_>],
    branch_protected: bool,
    reverted_twice: bool,
    asks: &std::sync::atomic::AtomicU64,
) -> Result<Vec<std::result::Result<Option<String>, String>>> {
    let count = |n: u64| asks.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    if items.is_empty() || (!branch_protected && !reverted_twice) {
        return Ok(items.iter().map(|_| Ok(None)).collect());
    }
    // Asked alone: an entry with a change reverted twice,
    let mut alone: Vec<bool> = vec![false; items.len()];
    if reverted_twice {
        let ids: Vec<String> = items.iter().flat_map(|i| i.diff.changes.iter().cloned()).collect();
        count(1);
        let twice = crate::bisect::reverted_twice_among(&mut *c, project, &ids).await?;
        for (i, item) in items.iter().enumerate() {
            alone[i] = item.diff.changes.iter().any(|k| twice.contains(k));
        }
    }
    if branch_protected {
        // one that lands a PR or releases an embargo,
        for (i, item) in items.iter().enumerate() {
            alone[i] |= matches!(item.claim, Some(crate::landing::ReviewClaim::Pr { .. } | crate::landing::ReviewClaim::Embargo { .. }));
        }
        let patch_of = |item: &LandingReview<'_>| match item.claim {
            Some(crate::landing::ReviewClaim::Patch { patch }) => patch.clone(),
            _ => item.diff.patch.clone(),
        };
        // one whose patch is an open PR's current revision,
        let patches: Vec<String> = items.iter().zip(&alone).filter(|(_, a)| !**a).map(|(i, _)| patch_of(i)).collect();
        if !patches.is_empty() {
            count(1);
            let with_pr: HashSet<String> = sqlx::query_scalar(
                "SELECT DISTINCT r.patch FROM prs p JOIN pr_revisions r ON r.project_id = p.project_id AND r.pr = p.id AND r.n = p.revision \
                 WHERE p.project_id = $1 AND p.target = $2 AND p.state = 'open' AND r.patch = ANY($3)",
            )
            .bind(project)
            .bind(branch)
            .bind(&patches)
            .fetch_all(&mut *c)
            .await?
            .into_iter()
            .collect();
            for (i, item) in items.iter().enumerate() {
                alone[i] |= with_pr.contains(&patch_of(item));
            }
        }
        // one that touches a path a reviewer holds,
        let paths: Vec<String> = {
            let all: BTreeSet<&String> = items.iter().zip(&alone).filter(|(_, a)| !**a).flat_map(|(i, _)| i.diff.touched.iter()).collect();
            all.into_iter().cloned().collect()
        };
        if !paths.is_empty() {
            count(1);
            let held: HashSet<String> = sqlx::query_scalar("SELECT DISTINCT path FROM pr_holds WHERE project_id = $1 AND path = ANY($2)")
                .bind(project)
                .bind(&paths)
                .fetch_all(&mut *c)
                .await?
                .into_iter()
                .collect();
            if !held.is_empty() {
                for (i, item) in items.iter().enumerate() {
                    alone[i] |= item.diff.touched.iter().any(|p| held.contains(p));
                }
            }
        }
        // and one whose risk needs an approval (it has none: no PR).
        for (i, item) in items.iter().enumerate() {
            alone[i] = alone[i] || rules.need(classify(&item.diff.files, rules).0).approvals > 0;
        }
    }
    let mut out = Vec::with_capacity(items.len());
    for (item, alone) in items.iter().zip(alone) {
        out.push(if alone {
            count(1);
            verify_landing_review(&mut *c, item.project, item.viewer, branch, item.diff, rules, item.claim, branch_protected).await?
        } else {
            Ok(None)
        });
    }
    Ok(out)
}

/// Check the review rules in force for a landing `stack` onto `branch`
/// ([`verify_landing_review`]) when a route submits it: `Err` (`not_ready`)
/// with the refusal, or what the landing batch checks again in its own
/// transaction (BUG-1880), kept on the stack's first entry.
pub async fn check_landing_review(
    hub: &Arc<Hub>,
    project: &crate::perm::Project,
    viewer: &Viewer,
    branch: &str,
    stack: &[crate::landing::Entry],
    staged: Option<Arc<crate::sync::Staged>>,
    branch_protected: bool,
) -> Result<Option<crate::landing::ReviewClaim>> {
    check_landing_review_for_embargo(hub, project, viewer, branch, stack, staged, branch_protected, None).await
}

/// [`check_landing_review`] for an embargo's release: a PR of that embargo
/// may carry the approvals (BUG-1861), at submit and in the batch alike.
#[allow(clippy::too_many_arguments)]
pub async fn check_landing_review_for_embargo(
    hub: &Arc<Hub>,
    project: &crate::perm::Project,
    viewer: &Viewer,
    branch: &str,
    stack: &[crate::landing::Entry],
    staged: Option<Arc<crate::sync::Staged>>,
    branch_protected: bool,
    embargo_id: Option<&str>,
) -> Result<Option<crate::landing::ReviewClaim>> {
    if stack.is_empty() {
        return Ok(None);
    }
    let rules = state::rules_in_force(hub, project, &project.default_branch).await?;
    let entries = stack.to_vec();
    let diff = crate::sync::blocking_staged(hub, project.id, staged, move |src| stack_review_diff(src, &entries)).await?;
    crate::bisect::settle_queued_reverts(hub, project.id).await?;
    // An embargo's release always says whose PRs count; any other landing
    // names its patch where the branch's rules were met.
    let claim = match embargo_id {
        Some(e) => Some(crate::landing::ReviewClaim::Embargo { embargo: e.to_string(), patch: diff.patch.clone() }),
        None if branch_protected => Some(crate::landing::ReviewClaim::Patch { patch: diff.patch.clone() }),
        None => None,
    };
    let mut c = hub.db.acquire().await?;
    match verify_landing_review(&mut c, project, viewer, branch, &diff, &rules, claim.as_ref(), branch_protected).await? {
        Ok(_) => Ok(claim),
        Err(msg) => Err(Error::new(StatusCode::CONFLICT, "not_ready", msg)),
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct LandPr {
    pub at_release: Option<bool>,
}

/// Land `pr` through the landing service (S17), after checking its review
/// gate (S21) and S11's agent rules (`landing::agent_stack`).
pub async fn land(hub: &Arc<Hub>, ask: &Ask, caller: &Caller, id: &str) -> Result<Value> {
    let _ = participant(ask, caller)?;
    land_with(hub, ask, caller, id, LandPr::default()).await
}

pub async fn land_with(hub: &Arc<Hub>, ask: &Ask, caller: &Caller, id: &str, q: LandPr) -> Result<Value> {
    let me = participant(ask, caller)?;
    let person = signed_in(caller)?.clone();
    let gc_epoch = crate::pack_gc::read_gc_epoch(hub, ask.project.id).await?;
    let pr = visible(hub, ask, id).await?;
    if !pr.embargo.is_empty() {
        return embargo::land_embargoed(hub, ask, me, &pr, q.at_release).await;
    }
    if q.at_release.is_some() {
        return Err(Error::bad_request("at_release applies only to an embargoed PR"));
    }
    let paths = review::paths_of(hub, ask.project.id, &pr.id).await?;
    if pr.author != me && !review::writes_all(&ask.project, &ask.viewer, &paths) {
        return Err(Error::forbidden("only the author, or someone who may write every file of this PR, lands it"));
    }
    let (revs, g) = gate(hub, ask, &pr).await?;
    if !g.ready {
        return Err(Error::new(StatusCode::CONFLICT, "not_ready", format!("not ready to land: {}", g.reasons.join("; "))));
    }
    let current = revs.iter().find(|r| r.n == pr.revision).ok_or_else(|| Error::Other(anyhow::anyhow!("the PR's revision is missing")))?;
    let mut judged = match crate::landing::stack(hub, &ask.project, &ask.viewer, &pr.target, current.head, &HashMap::new(), None).await? {
        Ok(s) if !s.branch => return Err(Error::conflict(format!("the target {} no longer exists", pr.target))),
        Ok(s) => s,
        Err(why) => return Err(Error::bad_request(why)),
    };
    crate::landing::agent_stack(hub, &ask.project, &ask.viewer, &pr.target, &judged, current.head, false, None).await?;
    // Re-check the PR and its gate right before queueing so a revision,
    // access, rule, or hold change during stack computation is never missed.
    let pr_now = visible(hub, ask, id).await?;
    if pr_now.state == "open" && pr_now.revision != pr.revision {
        return Err(Error::new(StatusCode::CONFLICT, "not_ready", "not ready to land: a new revision was pushed to the PR"));
    }
    let (_, g) = gate(hub, ask, &pr_now).await?;
    if !g.ready {
        return Err(Error::new(StatusCode::CONFLICT, "not_ready", format!("not ready to land: {}", g.reasons.join("; "))));
    }
    if judged.stack.is_empty() {
        let now = veil_core::now_millis();
        let n = sqlx::query("UPDATE prs SET state = 'landed', updated_at = $1 WHERE project_id = $2 AND id = $3 AND state = 'open' AND revision = $4")
            .bind(now)
            .bind(ask.project.id)
            .bind(&pr.id)
            .bind(pr.revision)
            .execute(&hub.db)
            .await?
            .rows_affected();
        if n > 0 {
            crate::events::emit_pr(hub, ask.project.id, &pr.id, "pr.landed").await;
        }
        let _ = crate::branches::delete_landed_pr_branch(hub, &ask.project, &pr.id, pr.revision, me).await;
        return show(hub, ask, id).await;
    }
    if let Some(first) = judged.stack.first_mut() {
        first.review = Some(crate::landing::ReviewClaim::Pr {
            id: pr.id.clone(),
            revision: pr.revision,
            patch: current.patch.clone(),
        });
    }
    let who = crate::landing::Submitter {
        person,
        epochs: caller.epochs,
    };
    let q = crate::landing::Queued {
        ticket: crate::landing::ticket(),
        branch: pr.target.clone(),
        stack: judged.stack,
        lineage: judged.lineage,
        skipped: Arc::new(std::sync::Mutex::new(judged.skipped)),
    };
    let w = hub.landing.register(&q.ticket);
    let pid = ask.project.id;
    let q2 = q.clone();
    let who2 = who.clone();
    let r = transaction(&hub.db, Isolation::ReadCommitted, move |c| {
        let (q, who) = (q2.clone(), who2.clone());
        Box::pin(async move {
            crate::pack_gc::guard_root_write(&mut *c, pid, gc_epoch).await?;
            crate::landing::insert(&mut *c, pid, &who, &q).await
        })
    })
    .await;
    if let Err(e) = r {
        crate::landing::abandon(hub, w);
        return Err(e);
    }
    crate::landing::ensure(hub, ask.project.id, &q.branch);
    let deadline = tokio::time::Instant::now() + crate::landing::WAIT;
    let r = crate::landing::wait(hub, ask.project.id, me, &q.branch, w, deadline).await?;
    let mut r = crate::landing::seen(hub, &ask.project, &ask.viewer, r).await?;
    let skipped = q.skipped.lock().unwrap().clone();
    r.warnings.extend(crate::landing::skipped_warnings(hub, ask.project.id, &q.branch, &skipped).await?);
    use veil_core::hub::land::LandState;
    match r.state {
        // The batch that landed it marked the PR and cleans its source
        // branch (`mark_landed`, `pr_landed`: BUG-1924); the request only
        // reports, as it does for a landing that outlasts its wait.
        LandState::Landed | LandState::Queued => {
            let mut v = show(hub, ask, id).await?;
            v["landing"] = serde_json::to_value(&r).unwrap_or_default();
            Ok(v)
        }
        LandState::Conflict => {
            let msg = r.message.clone().unwrap_or_else(|| {
                format!(
                    "conflict: {} changed on '{}' since this PR's base; rebase it onto '{}' and update the PR",
                    r.paths.join(", "),
                    pr.target,
                    pr.target
                )
            });
            Err(Error::new(StatusCode::CONFLICT, "conflict", msg))
        }
        LandState::Rejected => {
            let msg = r.message.unwrap_or_else(|| "landing rejected".into());
            if msg.starts_with(NOT_READY) {
                Err(Error::new(StatusCode::CONFLICT, "not_ready", msg))
            } else {
                Err(Error::bad_request(msg))
            }
        }
    }
}

// ---- routes ------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize)]
pub struct CreatePrRoute {
    #[serde(flatten)]
    pub inner: CreatePr,
    #[serde(default)]
    pub land_at_release: bool,
}

pub async fn list_route(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Query(q): Query<ListParams>) -> Result<Json<Value>> {
    let ask = open(&hub, &p, &caller).await?;
    Ok(Json(list(&hub, &ask, q).await?))
}

pub async fn create_route(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Json(q): Json<CreatePrRoute>) -> Result<Json<Value>> {
    let ask = open(&hub, &p, &caller).await?;
    Ok(Json(create_with(&hub, &ask, &caller, q.inner, q.land_at_release).await?))
}

pub async fn show_route(State(hub): State<HubState>, caller: Caller, Path((p, id)): Path<(String, String)>) -> Result<Json<Value>> {
    let ask = open(&hub, &p, &caller).await?;
    Ok(Json(show(&hub, &ask, &id).await?))
}

pub async fn diff_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, id)): Path<(String, String)>,
    Query(q): Query<PrDiffParams>,
) -> Result<Json<Value>> {
    let ask = open(&hub, &p, &caller).await?;
    Ok(Json(diff(&hub, &ask, &id, q).await?))
}

pub async fn revision_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, id)): Path<(String, String)>,
    Json(q): Json<RevisionRequest>,
) -> Result<Json<Value>> {
    let ask = open(&hub, &p, &caller).await?;
    Ok(Json(add_revision(&hub, &ask, &caller, &id, q).await?))
}

pub async fn close_route(State(hub): State<HubState>, caller: Caller, Path((p, id)): Path<(String, String)>) -> Result<Json<Value>> {
    let ask = open(&hub, &p, &caller).await?;
    Ok(Json(close(&hub, &ask, &caller, &id).await?))
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct After {
    pub after: Option<String>,
}

pub async fn threads_route(State(hub): State<HubState>, caller: Caller, Path((p, id)): Path<(String, String)>, Query(q): Query<After>) -> Result<Json<Value>> {
    let ask = open(&hub, &p, &caller).await?;
    Ok(Json(threads_json(&hub, &ask, &id, q.after.as_deref()).await?))
}

pub async fn thread_get_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, id, t)): Path<(String, String, String)>,
    Query(q): Query<After>,
) -> Result<Json<Value>> {
    let ask = open(&hub, &p, &caller).await?;
    Ok(Json(thread_json(&hub, &ask, &id, &t, q.after.as_deref()).await?))
}

pub async fn new_thread_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, id)): Path<(String, String)>,
    Json(q): Json<NewThread>,
) -> Result<Json<Value>> {
    let ask = open(&hub, &p, &caller).await?;
    Ok(Json(new_thread(&hub, &ask, &caller, &id, q).await?))
}

pub async fn thread_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, id, t)): Path<(String, String, String)>,
    Json(q): Json<ThreadUpdate>,
) -> Result<Json<Value>> {
    let ask = open(&hub, &p, &caller).await?;
    Ok(Json(update_thread(&hub, &ask, &caller, &id, &t, q).await?))
}

pub async fn review_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, id)): Path<(String, String)>,
    Json(q): Json<ReviewRequest>,
) -> Result<Json<Value>> {
    let ask = open(&hub, &p, &caller).await?;
    Ok(Json(add_review(&hub, &ask, &caller, &id, q).await?))
}

pub async fn land_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, id)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> Result<Json<Value>> {
    let ask = open(&hub, &p, &caller).await?;
    let q = if body.iter().all(|b| b.is_ascii_whitespace()) {
        LandPr::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| Error::bad_request(format!("invalid JSON: {e}")))?
    };
    Ok(Json(land_with(&hub, &ask, &caller, &id, q).await?))
}
