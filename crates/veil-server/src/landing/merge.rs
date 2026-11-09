//! Content merge workers, re-queue and conflict reports for the landing
//! service (milestone S18; `docs/HUB.md` §13.30;
//! `docs/design/server/phase-4-agent-scale.md` §4.3, §5).
//!
//! When a queued change's edited paths changed on the branch's tip since its
//! base ([`super::edits::fast_path`] is `Some`), the landing service checks
//! whether the change can be merged by content:
//!
//! * Up to [`MAX_MERGES`] (3) clean content merges are attempted per queued
//!   submission. A change that still overlaps after [`MAX_MERGES`] merges is
//!   answered `conflict`.
//! * A merge worker runs on a bounded pool ([`MAX_WORKERS`]) and tries a
//!   three-way content merge (`veil_core::textmerge::merge` or
//!   `veil_core::attributes::union_merge` per `.veilattributes`) on each
//!   overlapping path when both sides are plain-text `Public` files that the
//!   submitter may read and write.
//! * **Guarantee 1:** Before a merged snapshot can re-queue or land, the
//!   worker verifies that the submitter sees every edit of the original and
//!   merged change whole (`Class::Whole`) under both the project's current
//!   access epochs and the tip's `.veilpolicy`, and runs the push checks
//!   (`sync::complete`) on the new parent.
//! * **Guarantee 2:** When a merge cannot be done cleanly, the worker builds
//!   a conflict report (`onto`, `base`, `paths`, `conflicts`, `landed_since`)
//!   that names nothing hidden from the submitter; any conflict involving a
//!   path the submitter cannot read is reported solely as
//!   [`HIDDEN_CONFLICT`] (`"conflicts with changes you can't see"`), never by
//!   path.
//! * **Guarantee 3:** Clean merges atomically transition their queue row
//!   `merging -> queued` with `merges = merges + 1` and record the original
//!   submitted snapshot in `predecessors`, so a re-queued change lands at
//!   most once.

use std::{
    collections::HashMap,
    sync::{atomic::Ordering, Arc},
};

use bytes::Bytes;
use tokio::sync::Semaphore;
use veil_core::{
    attributes::{AttrSource, Attrs, MergeAttr, ATTRIBUTES_FILE, MAX_FILE},
    hub::{
        access::{AccessPolicy, View},
        land::{ConflictPath, LandResult, LandState},
        project::Change,
    },
    object::{EntryKind, Object, Snapshot, TreeEntry, Visibility},
    policy::POLICY_FILE,
    secrets::looks_binary,
    vpath::VPath,
    ChangeId, ObjectId,
};

use super::{edits, rules::RULES_FILE, Entry};
use crate::{
    auth::{Caller, Person},
    caches::Epochs,
    error::{Error, Result},
    perm::{Project, Viewer},
    sync::{self, Source},
    Hub,
};

/// Most times one submission is content-merged and re-queued before an
/// overlap is answered `conflict`.
pub const MAX_MERGES: u32 = 3;

/// Most merge workers running at once on one server.
pub const MAX_WORKERS: usize = 8;

/// The sole message when a conflict involves a path the receiver cannot read.
pub const HIDDEN_CONFLICT: &str = "conflicts with changes you can't see";

/// Bounded pool of merge workers on this server.
pub struct Workers {
    sem: Arc<Semaphore>,
}

impl Default for Workers {
    fn default() -> Self {
        Workers {
            sem: Arc::new(Semaphore::new(MAX_WORKERS)),
        }
    }
}

/// Details of a conflict on a branch tip (real snapshot IDs, projected for
/// the viewer by `landing::seen`).
#[derive(Clone, Debug)]
pub struct ConflictReport {
    pub paths: Vec<String>,
    pub onto: ObjectId,
    pub base: ObjectId,
    pub conflicts: Vec<ConflictPath>,
    pub landed_since: Vec<ObjectId>,
    pub hidden: bool,
    pub merges: u32,
    pub change_id: Option<ChangeId>,
}

impl ConflictReport {
    pub fn into_result(self, ticket: &str, branch: &str) -> LandResult {
        let message = if self.hidden {
            Some(HIDDEN_CONFLICT.to_string())
        } else {
            Some(format!(
                "a path this change edits changed on '{branch}' since its base: get the branch's new tip, redo the change on it, and land it again"
            ))
        };
        LandResult {
            ticket: ticket.to_string(),
            state: LandState::Conflict,
            change_id: self.change_id,
            landed: Vec::new(),
            message,
            paths: if self.hidden { Vec::new() } else { self.paths },
            onto: Some(self.onto),
            base: Some(self.base),
            conflicts: if self.hidden { Vec::new() } else { self.conflicts },
            landed_since: self.landed_since,
            merges: self.merges,
            warnings: Vec::new(),
        }
    }
}

/// A queue row claimed for content merging by a merge worker.
#[derive(Clone)]
pub struct Job {
    pub project: i64,
    pub project_name: String,
    pub branch: String,
    pub seq: i64,
    pub ticket: String,
    pub person: Person,
    pub stack: Vec<Entry>,
    pub lineage: i64,
    pub merges: u32,
    pub tip: ObjectId,
}

/// Read `.veilattributes` from a real tree `tree` in `src`, restricted to
/// public regular files that `view` may read.
struct ServerAttrSource<'a> {
    src: &'a Source,
    tree: ObjectId,
    view: &'a View<'a>,
}

impl AttrSource for ServerAttrSource<'_> {
    fn read_attributes(&self, dir: &VPath) -> std::result::Result<Option<Vec<u8>>, String> {
        let rel = if dir.is_root() {
            ATTRIBUTES_FILE.to_string()
        } else {
            format!("{}/{ATTRIBUTES_FILE}", dir.as_str())
        };
        if !dir.is_root() && !self.view.read(&rel) {
            return Ok(None);
        }
        let e = match sync::entry_at(self.src, &self.tree, &rel) {
            Ok(Some(e)) => e,
            Ok(None) => return Ok(None),
            Err(e) => return Err(format!("{e:?}")),
        };
        if e.kind != EntryKind::File || e.visibility != Visibility::Public {
            return Ok(None);
        }
        if e.size > MAX_FILE as u64 {
            return Err(format!("it is larger than {} KiB", MAX_FILE >> 10));
        }
        match self.src.raw(&e.id).and_then(|r| Object::decode(&r)) {
            Ok(Object::Blob(b)) if b.len() <= MAX_FILE => Ok(Some(b)),
            Ok(Object::Blob(_)) => Err(format!("it is larger than {} KiB", MAX_FILE >> 10)),
            Ok(_) => Ok(None),
            Err(e) => Err(format!("{e:?}")),
        }
    }
}

/// Do paths `a` and `b` overlap (the same path, or one inside the other)?
fn paths_overlap(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let (short, long) = if a.len() < b.len() { (a, b) } else { (b, a) };
    long.starts_with(short) && long.as_bytes().get(short.len()) == Some(&b'/')
}

/// Build a visibility-safe [`ConflictReport`] for an entry whose `set` (made
/// on `base_snap` with tree `parent_tree`) conflicts with `tip_snap` (tree
/// `chain_tree`).
#[allow(clippy::too_many_arguments)]
pub fn build_conflict(
    src: &Source,
    view: &View<'_>,
    base_snap: ObjectId,
    parent_tree: ObjectId,
    tip_snap: ObjectId,
    chain_tree: ObjectId,
    set: &[Change],
    merges: u32,
    change_id: Option<ChangeId>,
) -> Result<ConflictReport> {
    let main_edits = edits::edit_set(src, chain_tree, parent_tree)?;
    let mut paths = Vec::new();
    let mut conflicts = Vec::new();
    let mut overlapping_edits = Vec::new();
    let mut hidden = false;

    for c in set {
        if edits::fast_path(src, parent_tree, chain_tree, std::slice::from_ref(c))?.is_none() {
            continue;
        }
        overlapping_edits.push(c.clone());
        if !view.read(&c.path) {
            hidden = true;
            continue;
        }
        let main_touching: Vec<&Change> = main_edits.iter().filter(|m| paths_overlap(&c.path, &m.path)).collect();
        if main_touching.iter().any(|m| !view.read(&m.path)) {
            hidden = true;
            continue;
        }
        let leaf_id = |e: Option<TreeEntry>| -> Option<ObjectId> {
            e.filter(|x| x.kind != EntryKind::Dir && x.visibility == Visibility::Public).map(|x| x.id)
        };
        let base_id = leaf_id(sync::entry_at(src, &parent_tree, &c.path)?);
        let main_id = leaf_id(sync::entry_at(src, &chain_tree, &c.path)?);
        let yours_id = leaf_id(c.new.clone());
        paths.push(c.path.clone());
        conflicts.push(ConflictPath {
            path: c.path.clone(),
            base: base_id,
            main: main_id,
            yours: yours_id,
        });
    }

    if paths.is_empty() && !hidden {
        // Blocked by a folder/file collision detected during `edits::apply`.
        for c in set {
            if !view.read(&c.path) || main_edits.iter().any(|m| paths_overlap(&c.path, &m.path) && !view.read(&m.path)) {
                hidden = true;
            } else {
                paths.push(c.path.clone());
            }
        }
    }

    let landed_since = if hidden {
        Vec::new()
    } else {
        collect_landed_since(src, view, base_snap, tip_snap, &overlapping_edits)?
    };

    Ok(ConflictReport {
        paths,
        onto: tip_snap,
        base: base_snap,
        conflicts,
        landed_since,
        hidden,
        merges,
        change_id,
    })
}

/// Walk the first-parent chain from `tip` down to `base` (at most 256 steps)
/// and return the snapshots (oldest first) that touched at least one of the
/// `overlapping` edits and have at least one edit readable by `view`.
/// (`landing::seen` projects these for the viewer and drops any that
/// collapsed.)
fn collect_landed_since(
    src: &Source,
    view: &View<'_>,
    base: ObjectId,
    tip: ObjectId,
    overlapping: &[Change],
) -> Result<Vec<ObjectId>> {
    if base == tip {
        return Ok(Vec::new());
    }
    let root = sync::root_snapshot_id();
    let mut chain = Vec::new();
    let mut cur = tip;
    for _ in 0..256 {
        if cur == base || cur == root {
            break;
        }
        let Ok(s) = src.snapshot(&cur) else { break };
        let parent = s.parents.first().copied().unwrap_or(root);
        chain.push((cur, s.tree, parent));
        cur = parent;
    }
    chain.reverse();
    let mut out = Vec::new();
    for (id, tree, parent) in chain {
        let Ok(ps) = src.snapshot(&parent) else {
            continue;
        };
        let step_edits = edits::edit_set(src, tree, ps.tree)?;
        if !step_edits.iter().any(|c| view.read(&c.path)) {
            continue;
        }
        if overlapping.is_empty() || edits::fast_path(src, ps.tree, tree, overlapping)?.is_some() {
            out.push(id);
        }
    }
    Ok(out)
}

/// Quick check during batch build: can this overlapping entry possibly be
/// content-merged by a merge worker?
///
/// Returns `Ok(true)` if a merge worker should be spawned for it, or
/// `Ok(false)` if it is definitely a conflict (e.g. `merges >= MAX_MERGES`,
/// a merge commit, touches policy/rules, has a hidden conflict, or an
/// overlapping path is not a plain-text `Public` file on both sides).
#[allow(clippy::too_many_arguments)]
pub fn can_merge(
    src: &Source,
    view: &View<'_>,
    merges: u32,
    snaps: &[Arc<Snapshot>],
    sets: &[Vec<Change>],
    base_trees: &[ObjectId],
    chain_tree: ObjectId,
) -> Result<bool> {
    if merges >= MAX_MERGES {
        return Ok(false);
    }
    for ((s, set), parent_tree) in snaps.iter().zip(sets).zip(base_trees) {
        if s.parents.len() > 1 {
            return Ok(false);
        }
        if set.iter().any(|c| c.path == POLICY_FILE || c.path == RULES_FILE || !view.read(&c.path) || !view.write(&c.path)) {
            return Ok(false);
        }
        if edits::fast_path(src, *parent_tree, chain_tree, set)?.is_none() {
            continue;
        }
        let main_edits = edits::edit_set(src, chain_tree, *parent_tree)?;
        let attrs = Attrs::with_source(
            Box::new(ServerAttrSource {
                src,
                tree: chain_tree,
                view,
            }),
            None,
        );
        for c in set {
            if edits::fast_path(src, *parent_tree, chain_tree, std::slice::from_ref(c))?.is_none() {
                continue;
            }
            if main_edits.iter().any(|m| paths_overlap(&c.path, &m.path) && !view.read(&m.path)) {
                return Ok(false);
            }
            let Some(te) = &c.new else { return Ok(false) };
            let Some(oe) = sync::entry_at(src, &chain_tree, &c.path)? else { return Ok(false) };
            let be = sync::entry_at(src, parent_tree, &c.path)?;
            if !can_merge_entries(src, &attrs, &c.path, be.as_ref(), &oe, te)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn can_merge_entries(
    src: &Source,
    attrs: &Attrs<'_>,
    path: &str,
    be: Option<&TreeEntry>,
    oe: &TreeEntry,
    te: &TreeEntry,
) -> Result<bool> {
    if oe.kind != EntryKind::File || te.kind != EntryKind::File {
        return Ok(false);
    }
    if oe.visibility != Visibility::Public || te.visibility != Visibility::Public {
        return Ok(false);
    }
    if let Some(b) = be {
        if b.kind != EntryKind::File || b.visibility != Visibility::Public {
            return Ok(false);
        }
    }
    let Ok(vp) = VPath::new(path) else { return Ok(false) };
    let how = attrs.for_path(&vp).merge;
    if how == MergeAttr::Binary {
        return Ok(false);
    }
    let read_blob = |e: &TreeEntry| -> Result<Option<Vec<u8>>> {
        Ok(match Object::decode(&src.raw(&e.id)?)? {
            Object::Blob(b) => Some(b),
            _ => None,
        })
    };
    let Some(ours) = read_blob(oe)? else { return Ok(false) };
    let Some(theirs) = read_blob(te)? else { return Ok(false) };
    let base = match be {
        Some(b) => match read_blob(b)? {
            Some(d) => d,
            None => return Ok(false),
        },
        None => Vec::new(),
    };
    if looks_binary(&base) || looks_binary(&ours) || looks_binary(&theirs) {
        return Ok(false);
    }
    if ours == theirs {
        return Ok(true);
    }
    if how == MergeAttr::Union {
        return Ok(true);
    }
    // Without a common base file, two different newly added files conflict
    // unless `merge=union` is set.
    if be.is_none() {
        return Ok(false);
    }
    Ok(veil_core::textmerge::merge(&base, &ours, &theirs, 7, veil_core::textmerge::Style::Diff3).is_ok())
}

/// Spawn a merge worker for `job`.
pub fn spawn(hub: &Arc<Hub>, job: Job) {
    let hub = hub.clone();
    tokio::spawn(async move {
        let _permit = hub.landing.merges.sem.clone().acquire_owned().await.ok();
        if let Err(e) = run_worker(&hub, job).await {
            eprintln!("veil-server: merge worker failed: {e:?}");
        }
    });
}

enum WorkerOutcome {
    Requeued {
        stack: Vec<Entry>,
        objects: Vec<(ObjectId, Bytes)>,
        snapshots: Vec<ObjectId>,
        origins: Vec<(ObjectId, ObjectId)>,
        onto: ObjectId,
        change_id: Option<ChangeId>,
    },
    Conflict(ConflictReport),
    Rejected(String, Option<ChangeId>),
}

async fn run_worker(hub: &Arc<Hub>, job: Job) -> Result<()> {
    // 1. Re-open the project and viewer as the submitter is *now* (current
    //    access epochs), so revoked access is caught before any merge lands.
    let epochs_rows: Vec<(i64, i64, i64)> = sqlx::query_as(
        "SELECT project_id, person_id, epoch FROM access_epochs WHERE (project_id = 0 AND person_id = $1) OR (project_id = $2 AND person_id = 0)",
    )
    .bind(job.person.id)
    .bind(job.project)
    .fetch_all(&hub.db)
    .await?;
    let person_epoch = epochs_rows.iter().find(|e| e.0 == 0 && e.1 == job.person.id).map_or(0, |e| e.2);
    let project_epoch = epochs_rows.iter().find(|e| e.0 == job.project).map_or(0, |e| e.2);
    let caller = Caller {
        person: Some(job.person.clone()),
        epochs: Epochs {
            person: person_epoch,
            project: Some((job.project, project_epoch)),
        },
    };
    let who = match crate::perm::open(hub, &job.project_name, &caller).await {
        Ok((p, v)) if p.participant(&v) => Ok((Arc::new(p), v)),
        Ok(_) | Err(Error::Api { code: "not_found", .. }) => Err("you are no longer in this project".to_string()),
        Err(Error::Api { message, code: "forbidden", .. }) => Err(message),
        Err(e) => return Err(e),
    };

    // Read the current tip and lineage of the branch from the database.
    let branch_row: Option<(String, i64)> =
        sqlx::query_as("SELECT target, lineage FROM branches WHERE project_id = $1 AND name = $2")
            .bind(job.project)
            .bind(&job.branch)
            .fetch_optional(&hub.db)
            .await?;

    let outcome = match (who, branch_row) {
        (Err(why), _) => WorkerOutcome::Rejected(why, None),
        (_, None) => WorkerOutcome::Rejected(format!("there is no branch '{}'", job.branch), None),
        (Ok((project, viewer)), Some((tip_hex, lineage))) => {
            if lineage != job.lineage {
                WorkerOutcome::Rejected(
                    "the branch was reset since this change was submitted (a forced push, or deleted and made again): submit it again".into(),
                    None,
                )
            } else {
                let tip = ObjectId::from_hex(&tip_hex).map_err(|e| Error::Other(e.into()))?;
                let h = hub.clone();
                let j = job.clone();
                let rt = tokio::runtime::Handle::current();
                tokio::task::spawn_blocking(move || merge_stack(h, rt, project, viewer, j, tip))
                    .await
                    .map_err(|e| Error::Other(e.into()))??
            }
        }
    };

    match outcome {
        WorkerOutcome::Requeued {
            stack,
            objects,
            snapshots,
            origins,
            onto,
            change_id,
        } => {
            sync::put_all(hub, job.project, objects).await?;
            let snap_hex: Vec<String> = snapshots.iter().map(ObjectId::hex).collect();
            let orig_real: Vec<String> = origins.iter().map(|(r, _)| r.hex()).collect();
            let orig_src: Vec<String> = origins.iter().map(|(_, o)| o.hex()).collect();
            let encoded = super::encode_stack(&stack);
            let pid = job.project;
            let branch = job.branch.clone();
            let seq = job.seq;
            let max_merges = i64::from(MAX_MERGES);
            let new_merges: Option<i64> = crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
                let (snap_hex, orig_real, orig_src, encoded, branch) = (
                    snap_hex.clone(),
                    orig_real.clone(),
                    orig_src.clone(),
                    encoded.clone(),
                    branch.clone(),
                );
                Box::pin(async move {
                    if !snap_hex.is_empty() {
                        sqlx::query("INSERT INTO snapshots (project_id, id) SELECT $1, unnest($2::TEXT[]) ON CONFLICT DO NOTHING")
                            .bind(pid)
                            .bind(&snap_hex)
                            .execute(&mut *c)
                            .await?;
                    }
                    if !orig_real.is_empty() {
                        sqlx::query(
                            "INSERT INTO origins (project_id, real_id, origin_id) \
                             SELECT $1, r, o FROM unnest($2::TEXT[], $3::TEXT[]) AS v(r, o) ON CONFLICT DO NOTHING",
                        )
                        .bind(pid)
                        .bind(&orig_real)
                        .bind(&orig_src)
                        .execute(&mut *c)
                        .await?;
                    }
                    let m: Option<i64> = sqlx::query_scalar(
                        "UPDATE landing_queue SET state = 'queued', stack = $4, merges = merges + 1, \
                         created_at = (extract(epoch FROM clock_timestamp()) * 1000000)::BIGINT \
                         WHERE project_id = $1 AND branch = $2 AND seq = $3 AND state = 'merging' AND merges < $5 \
                         RETURNING merges",
                    )
                    .bind(pid)
                    .bind(&branch)
                    .bind(seq)
                    .bind(&encoded)
                    .bind(max_merges)
                    .fetch_optional(&mut *c)
                    .await?;
                    Ok(m)
                })
            })
            .await?;

            for s in &snapshots {
                hub.caches.put_committed(job.project, s);
            }
            if let Some(m) = new_merges {
                let mut r = super::queued(&job.ticket);
                r.change_id = change_id;
                r.onto = Some(onto);
                r.merges = m as u32;
                crate::events::emit_ticket(
                    hub,
                    job.project,
                    &job.branch,
                    job.person.id,
                    "land.requeued",
                    "requeued",
                    r,
                )
                .await;
                super::ensure(hub, job.project, &job.branch);
            }
        }
        WorkerOutcome::Conflict(report) => {
            let res = report.into_result(&job.ticket, &job.branch);
            finish_terminal(hub, &job, "conflict", "land.conflict", res).await?;
        }
        WorkerOutcome::Rejected(why, cid) => {
            let mut res = super::queued(&job.ticket);
            res.state = LandState::Rejected;
            res.change_id = cid;
            res.message = Some(why);
            res.merges = job.merges;
            finish_terminal(hub, &job, "rejected", "land.rejected", res).await?;
        }
    }
    Ok(())
}

async fn finish_terminal(
    hub: &Arc<Hub>,
    job: &Job,
    state_str: &str,
    event_name: &str,
    res: LandResult,
) -> Result<()> {
    let text = serde_json::to_string(&res).unwrap_or_default();
    let n = sqlx::query(
        "UPDATE landing_queue SET state = $4, result = $5, done_at = $6 \
         WHERE project_id = $1 AND branch = $2 AND seq = $3 AND state = 'merging'",
    )
    .bind(job.project)
    .bind(&job.branch)
    .bind(job.seq)
    .bind(state_str)
    .bind(&text)
    .bind(veil_core::now_millis())
    .execute(&hub.db)
    .await?
    .rows_affected();
    if n == 1 {
        match res.state {
            LandState::Conflict => {
                hub.landing.stats.conflicts.fetch_add(1, Ordering::Relaxed);
            }
            LandState::Rejected => {
                hub.landing.stats.rejected.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        crate::events::emit_ticket(
            hub,
            job.project,
            &job.branch,
            job.person.id,
            event_name,
            state_str,
            res.clone(),
        )
        .await;
        hub.landing.resolve([(job.ticket.clone(), res)]);
    }
    Ok(())
}

/// Perform the three-way content merge of `job.stack` onto `tip`, verifying
/// whole-change visibility (Guarantee 1) and `sync::complete` on the new
/// parents.
fn merge_stack(
    hub: Arc<Hub>,
    rt: tokio::runtime::Handle,
    project: Arc<Project>,
    viewer: Viewer,
    job: Job,
    tip: ObjectId,
) -> Result<WorkerOutcome> {
    let mut src = Source {
        hub: hub.clone(),
        project: job.project,
        rt,
        pending: HashMap::new(),
    };
    let view = project.view(&viewer);
    let tip_tree = src.snapshot(&tip)?.tree;
    let tip_policy = AccessPolicy::parse(&sync::policy_text(&src, &tip_tree)?);
    let tip_project = Project {
        id: project.id,
        name: project.name.clone(),
        default_branch: project.default_branch.clone(),
        policy: tip_policy,
        policy_text: String::new(),
        bindings: project.bindings.clone(),
    };
    let tip_view = tip_project.view(&viewer);

    let snaps: Vec<Arc<Snapshot>> = job.stack.iter().map(|e| src.snapshot(&e.id)).collect::<veil_core::Result<_>>()?;
    let last_cid = snaps.last().map(|s| s.change_id);

    if job.merges >= MAX_MERGES {
        let e = &job.stack[0];
        let s = &snaps[0];
        let against = if s.parents.get(1..).is_some_and(|o| o.contains(&e.base)) { e.base } else { s.parents[0] };
        let parent_tree = src.snapshot(&against)?.tree;
        let set = edits::edit_set(&src, s.tree, parent_tree)?;
        let report = build_conflict(&src, &view, against, parent_tree, tip, tip_tree, &set, job.merges, last_cid)?;
        return Ok(WorkerOutcome::Conflict(report));
    }

    let mut chain = tip;
    let mut chain_tree = tip_tree;
    let mut new_stack = Vec::with_capacity(job.stack.len());
    let mut objects: Vec<(ObjectId, Bytes)> = Vec::new();
    let mut snapshots: Vec<ObjectId> = Vec::new();
    let mut origins: Vec<(ObjectId, ObjectId)> = Vec::new();

    for (e, s) in job.stack.iter().zip(&snaps) {
        let sid = e.id;
        let against = if s.parents.get(1..).is_some_and(|o| o.contains(&e.base)) { e.base } else { s.parents[0] };
        let parent_tree = src.snapshot(&against)?.tree;
        let set = edits::edit_set(&src, s.tree, parent_tree)?;

        // Guarantee 1: A merge never lands anything its submitter couldn't
        // see whole. Every edit of the change must be readable and writable
        // by the submitter under both current permissions and the tip's
        // policy; a hidden edit is refused without naming its path.
        if !viewer.admin {
            if set.iter().any(|c| !view.read(&c.path) || !tip_view.read(&c.path)) {
                return Ok(WorkerOutcome::Rejected(
                    "your access changed since this change was submitted, and it holds edits you cannot see: make it again".into(),
                    last_cid,
                ));
            }
            if let Some(c) = set.iter().find(|c| !view.write(&c.path) || !tip_view.write(&c.path)) {
                return Ok(WorkerOutcome::Rejected(format!("you may not write '{}'", c.path), last_cid));
            }
        }
        if s.parents.len() > 1 {
            return Ok(WorkerOutcome::Rejected(
                "a merge lands only on the tip it was made on: merge the branch's new tip and land again".into(),
                last_cid,
            ));
        }

        let mut merged_set = Vec::with_capacity(set.len());
        if edits::fast_path(&src, parent_tree, chain_tree, &set)?.is_none() {
            merged_set = set.clone();
        } else {
            let main_edits = edits::edit_set(&src, chain_tree, parent_tree)?;
            let mut new_blobs = Vec::new();
            {
                let attrs = Attrs::with_source(
                    Box::new(ServerAttrSource {
                        src: &src,
                        tree: chain_tree,
                        view: &view,
                    }),
                    None,
                );
                for c in &set {
                    if edits::fast_path(&src, parent_tree, chain_tree, std::slice::from_ref(c))?.is_none() {
                        merged_set.push(c.clone());
                        continue;
                    }
                    if main_edits.iter().any(|m| paths_overlap(&c.path, &m.path) && (!view.read(&m.path) || !tip_view.read(&m.path))) {
                        let report = build_conflict(&src, &view, against, parent_tree, chain, chain_tree, &set, job.merges, last_cid)?;
                        return Ok(WorkerOutcome::Conflict(report));
                    }
                    let Some(te) = &c.new else {
                        let report = build_conflict(&src, &view, against, parent_tree, chain, chain_tree, &set, job.merges, last_cid)?;
                        return Ok(WorkerOutcome::Conflict(report));
                    };
                    let Some(oe) = sync::entry_at(&src, &chain_tree, &c.path)? else {
                        let report = build_conflict(&src, &view, against, parent_tree, chain, chain_tree, &set, job.merges, last_cid)?;
                        return Ok(WorkerOutcome::Conflict(report));
                    };
                    let be = sync::entry_at(&src, &parent_tree, &c.path)?;
                    match merge_entry_bytes(&src, &attrs, &c.path, be.as_ref(), &oe, te)? {
                        Some((merged_entry, blob_raw)) => {
                            if let Some((bid, braw)) = blob_raw {
                                new_blobs.push((bid, braw));
                            }
                            merged_set.push(Change {
                                path: c.path.clone(),
                                old: Some(oe),
                                new: Some(merged_entry),
                            });
                        }
                        None => {
                            let report = build_conflict(&src, &view, against, parent_tree, chain, chain_tree, &set, job.merges, last_cid)?;
                            return Ok(WorkerOutcome::Conflict(report));
                        }
                    }
                }
            }
            for (bid, braw) in new_blobs {
                src.pending.insert(bid, braw.clone());
                objects.push((bid, braw));
            }
        }

        let mut made = HashMap::new();
        let tree = match edits::apply(&src, chain_tree, &merged_set, &mut made)? {
            Ok(t) => t,
            Err(_) => {
                let report = build_conflict(&src, &view, against, parent_tree, chain, chain_tree, &set, job.merges, last_cid)?;
                return Ok(WorkerOutcome::Conflict(report));
            }
        };
        for (id, (raw, _)) in made {
            let b = Bytes::from(raw);
            src.pending.insert(id, b.clone());
            objects.push((id, b));
        }

        // The landing check on the merged edit set.
        let actual_diff = edits::edit_set(&src, tree, chain_tree)?;
        if !edits::same_edits(&actual_diff, &merged_set) {
            return Ok(WorkerOutcome::Rejected(
                "the server could not merge this change: its landing check failed".into(),
                last_cid,
            ));
        }
        // Guarantee 1: verify that the submitter sees the resulting diff whole.
        if !viewer.admin && actual_diff.iter().any(|c| !view.read(&c.path) || !view.write(&c.path) || !tip_view.read(&c.path) || !tip_view.write(&c.path)) {
            return Ok(WorkerOutcome::Rejected(
                "your access changed since this change was submitted, and it no longer lands as it was made: make it again".into(),
                last_cid,
            ));
        }

        let mut preds = vec![sid];
        if job.merges > 0 {
            for p in &s.predecessors {
                if !preds.contains(p) {
                    preds.push(*p);
                }
            }
        }
        let parents = vec![chain];
        let mut n = Snapshot {
            parents: parents.clone(),
            change_id: s.change_id,
            tree,
            description: s.description.clone(),
            author: s.author.clone(),
            timestamp: s.timestamp,
            predecessors: preds,
            conflicts: vec![],
            embargo: None,
            signature: None,
        };
        n.sign(&hub.identity);
        let raw = Bytes::from(Object::Snapshot(n.clone()).encode());
        let id = ObjectId::hash(&raw);
        src.pending.insert(id, raw.clone());
        objects.push((id, raw));
        snapshots.push(id);
        origins.push((id, sid));

        // Full push check (`sync::complete`) on the new parent so secret scan,
        // session narrowing and graft equivalence hold on the merged snapshot.
        if let Err(why) = super::service::recheck_merged(&mut src, &project, &viewer, &n, &parents, &merged_set, &hub.identity)? {
            return Ok(WorkerOutcome::Rejected(why, last_cid));
        }

        new_stack.push(Entry::plain(id, chain));
        chain = id;
        chain_tree = tree;
    }

    Ok(WorkerOutcome::Requeued {
        stack: new_stack,
        objects,
        snapshots,
        origins,
        onto: tip,
        change_id: last_cid,
    })
}

type MergedEntry = (TreeEntry, Option<(ObjectId, Bytes)>);

fn merge_entry_bytes(
    src: &Source,
    attrs: &Attrs<'_>,
    path: &str,
    be: Option<&TreeEntry>,
    oe: &TreeEntry,
    te: &TreeEntry,
) -> Result<Option<MergedEntry>> {
    if oe.kind != EntryKind::File || te.kind != EntryKind::File {
        return Ok(None);
    }
    if oe.visibility != Visibility::Public || te.visibility != Visibility::Public {
        return Ok(None);
    }
    if let Some(b) = be {
        if b.kind != EntryKind::File || b.visibility != Visibility::Public {
            return Ok(None);
        }
    }
    let Ok(vp) = VPath::new(path) else { return Ok(None) };
    let how = attrs.for_path(&vp).merge;
    if how == MergeAttr::Binary {
        return Ok(None);
    }
    let read_blob = |e: &TreeEntry| -> Result<Option<Vec<u8>>> {
        Ok(match Object::decode(&src.raw(&e.id)?)? {
            Object::Blob(b) => Some(b),
            _ => None,
        })
    };
    let Some(ours) = read_blob(oe)? else { return Ok(None) };
    let Some(theirs) = read_blob(te)? else { return Ok(None) };
    let base = match be {
        Some(b) => match read_blob(b)? {
            Some(d) => d,
            None => return Ok(None),
        },
        None => Vec::new(),
    };
    if looks_binary(&base) || looks_binary(&ours) || looks_binary(&theirs) {
        return Ok(None);
    }
    let executable = if be.is_some_and(|b| b.executable == oe.executable) {
        te.executable
    } else {
        oe.executable
    };
    if ours == theirs {
        return Ok(Some((
            TreeEntry {
                executable,
                ..oe.clone()
            },
            None,
        )));
    }
    let merged = if how == MergeAttr::Union {
        veil_core::attributes::union_merge(&base, &ours, &theirs)
    } else {
        if be.is_none() {
            return Ok(None);
        }
        match veil_core::textmerge::merge(&base, &ours, &theirs, 7, veil_core::textmerge::Style::Diff3) {
            Ok(m) => m,
            Err(_) => return Ok(None),
        }
    };
    let raw = Bytes::from(Object::Blob(merged.clone()).encode());
    let id = ObjectId::hash(&raw);
    Ok(Some((
        TreeEntry {
            name: oe.name.clone(),
            kind: EntryKind::File,
            id,
            size: merged.len() as u64,
            executable,
            visibility: Visibility::Public,
        },
        Some((id, raw)),
    )))
}
