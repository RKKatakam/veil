//! Commits through the API (`docs/HUB.md` §13.13; phase 2 §5.5):
//! `POST /v1/projects/{p}/changes`.
//!
//! A caller sends edits on top of a snapshot it may see (`base`, a
//! projected id). The server:
//!
//! 1. applies the edits to the caller's projection of `base`, as the
//!    caller's own `vl` would have built the tree it pushes;
//! 2. runs **the push's own checks** on it (`sync::complete`): the graft
//!    onto the full tree (nothing the caller cannot see is touched), write
//!    access for every edited path, access lines changed only by admins,
//!    closure, personal keys refused, secrets only as ciphertext, and the
//!    secret scan of every new plain-text file (check 9);
//! 3. signs the full snapshot with its key, and works out the caller's
//!    projection of it (`sync::project_one`);
//! 4. stores the objects, then writes everything in **one database
//!    commit**: the snapshot row, the caller's projection memo, the change
//!    ref, the audit row and, with `onto`, the one-row compare-and-swap of
//!    the branch (and an admin's policy acceptance on the default branch).
//!
//! **Inline text is never stored before the checks pass**: it is read from
//! memory ([`Source::pending`]) until then, so a refused plain-text secret
//! never reaches the object store.
//!
//! **`onto` with `"rebase"`**: when the branch's tip is not `base`, the
//! edits are applied to the tip instead, if the entry at every edited path
//! (and whether each folder above it is a folder) is the same in `base`
//! and in the tip; the branch moves only if it is still at that tip (the
//! compare-and-swap); a lost race tries again, up to [`MAX_REBASES`]
//! times. The change is its edits: its diff against its parent is always
//! exactly them.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use bytes::Bytes;
use veil_core::{
    hub::{
        access::AccessPolicy,
        changes::{BranchOutcome, ChangeRequest, ChangeResult, Expected, Status, MAX_EDITS, MAX_INLINE_TEXT, MAX_REBASES},
        project::{Node, Projector, TreeSource},
    },
    object::{validate_entry_name, EntryKind, Object, Snapshot, Text, Tree, TreeEncoding, TreeEntry, Visibility},
    tree::MAX_TREE_DEPTH,
    ChangeId, ObjectId,
};

use crate::{
    auth::Person,
    error::{Error, Result},
    perm::{Project, Viewer},
    sync::{self, Source},
    Hub,
};

/// Longest path one edit may name, in bytes.
const MAX_PATH: usize = 4096;

/// One edit, checked: the path's components, and the new content (`None`:
/// delete).
#[derive(Clone)]
struct Edit {
    path: String,
    parts: Vec<String>,
    put: Option<Content>,
}

#[derive(Clone)]
enum Content {
    /// Inline text, made into a blob (held in memory until the checks pass).
    Made(ObjectId, u64, bool),
    /// An uploaded object (or the one at that path in `base`).
    Object(ObjectId, bool),
}

fn bad(m: impl Into<String>) -> Error {
    Error::bad_request(m)
}

/// Check the request's shape and limits, and make the inline blobs.
fn validate(req: &ChangeRequest, pending: &mut HashMap<ObjectId, Bytes>) -> Result<Vec<Edit>> {
    if req.edits.is_empty() {
        return Err(bad("a change needs at least one edit"));
    }
    if req.edits.len() > MAX_EDITS {
        return Err(bad(format!("at most {MAX_EDITS} edits per change; upload larger changes with `vl push`")));
    }
    let inline: usize = req.edits.iter().filter_map(|e| e.put.as_ref()?.text.as_ref().map(String::len)).sum();
    if inline > MAX_INLINE_TEXT {
        return Err(bad(format!(
            "at most {} MiB of inline text per change; upload larger files as objects first",
            MAX_INLINE_TEXT >> 20
        )));
    }
    if let Some(o) = &req.onto {
        veil_core::commands::validate_tag_name(&o.branch).map_err(|_| bad(format!("invalid branch name {:?}", o.branch)))?;
    }
    let mut out = Vec::with_capacity(req.edits.len());
    let mut paths = HashSet::new();
    for e in &req.edits {
        let p = &e.path;
        if p.is_empty() || p.len() > MAX_PATH || p.starts_with('/') || p.ends_with('/') {
            return Err(bad("an edit's path is a file path from the project root (no leading or trailing '/')"));
        }
        if veil_core::vpath::nfc(p) != p.as_str() {
            return Err(bad(format!("'{p}' is not in Unicode normal form C")));
        }
        let parts: Vec<String> = p.split('/').map(str::to_string).collect();
        if parts.len() > MAX_TREE_DEPTH {
            return Err(bad(format!("'{p}' is nested deeper than {MAX_TREE_DEPTH} folders")));
        }
        for part in &parts {
            validate_entry_name(part).map_err(|_| bad(format!("'{p}' is not a valid path")))?;
        }
        if !paths.insert(p.clone()) {
            return Err(bad(format!("two edits of '{p}'")));
        }
        let put = match (&e.put, e.delete) {
            (Some(_), true) | (None, false) => return Err(bad(format!("'{p}': an edit is either a put or a delete"))),
            (None, true) => None,
            (Some(put), false) => Some(match (&put.object, &put.text) {
                (Some(id), None) => Content::Object(*id, put.executable),
                (None, Some(text)) => {
                    let raw = Object::Blob(text.as_bytes().to_vec()).encode();
                    let id = ObjectId::hash(&raw);
                    pending.insert(id, Bytes::from(raw));
                    Content::Made(id, text.len() as u64, put.executable)
                }
                _ => return Err(bad(format!("'{p}': a put has either an object or text"))),
            }),
        };
        out.push(Edit { path: p.clone(), parts, put });
    }
    // A file and something below it cannot both be edited. By components,
    // a path sorts right before everything below it.
    out.sort_by(|a, b| a.parts.cmp(&b.parts));
    for w in out.windows(2) {
        if w[1].parts.starts_with(&w[0].parts) {
            return Err(bad(format!("'{}' and '{}' are both edited: one is a folder of the other", w[0].path, w[1].path)));
        }
    }
    Ok(out)
}

/// A tree and its encoding: one the projector made, or a stored one.
fn load(src: &Source, pr: &Projector, id: &ObjectId) -> Result<(Arc<Tree>, TreeEncoding)> {
    if let Some(raw) = pr.created_raw(id) {
        let enc = Object::tree_encoding(raw).unwrap_or(TreeEncoding::Binary);
        let t = pr.tree(id)?.ok_or_else(|| Error::Other(anyhow::anyhow!("a projected tree is not a tree")))?;
        return Ok((t, enc));
    }
    match src.node(id)? {
        Node::Tree(t, enc) => Ok((t, enc)),
        Node::Leaf => Err(Error::Other(anyhow::anyhow!("a folder entry names something else"))),
    }
}

/// Apply `edits` (sorted, below `dir`, `depth` components already
/// consumed) to `tree`; the new tree, `None` when it is left empty. New
/// trees go to `made`.
fn apply(
    src: &Source,
    pr: &Projector,
    entries: &HashMap<String, TreeEntry>,
    made: &mut HashMap<ObjectId, Bytes>,
    tree: Option<ObjectId>,
    edits: &[&Edit],
    depth: usize,
) -> Result<Option<ObjectId>> {
    let (mut t, enc) = match tree {
        Some(id) => {
            let (t, enc) = load(src, pr, &id)?;
            ((*t).clone(), enc)
        }
        None => (Tree::default(), TreeEncoding::Binary),
    };
    let mut i = 0;
    while i < edits.len() {
        let name = &edits[i].parts[depth];
        let mut j = i;
        while j < edits.len() && edits[j].parts[depth] == *name {
            j += 1;
        }
        let here = t.get(name).cloned();
        let e = edits[i];
        if e.parts.len() == depth + 1 {
            // The edit names this entry (no other edit is below it).
            if here.as_ref().is_some_and(|h| h.kind == EntryKind::Dir) {
                return Err(bad(format!("'{}' is a folder: edit its files", e.path)));
            }
            match &e.put {
                None if here.is_none() => return Err(bad(format!("nothing at '{}' to delete", e.path))),
                None => {
                    t.remove(name);
                }
                Some(_) => {
                    t.remove(name);
                    t.insert(TreeEntry {
                        name: name.clone(),
                        ..entries[&e.path].clone()
                    });
                }
            }
        } else {
            let sub = match &here {
                Some(h) if h.kind == EntryKind::Dir => Some(h.id),
                Some(_) => return Err(bad(format!("'{}' is a file, not a folder", e.parts[..=depth].join("/")))),
                None => None,
            };
            match apply(src, pr, entries, made, sub, &edits[i..j], depth + 1)? {
                Some(id) => {
                    t.remove(name);
                    t.insert(TreeEntry::dir(name, id));
                }
                None => {
                    t.remove(name);
                }
            }
        }
        i = j;
    }
    if t.entries.is_empty() && depth > 0 {
        return Ok(None);
    }
    let raw = Object::Tree(t).encode_with(enc);
    let id = ObjectId::hash(&raw);
    made.insert(id, Bytes::from(raw));
    Ok(Some(id))
}

/// The new entries of the puts: kind, size and label from the object
/// itself (labels are claims, objects are authority). An object the caller
/// did not upload, and that is not the entry at that path in `base`, gets
/// the answer a missing object gets, before anything reads it: a change
/// never confirms a guess of a hidden object (BUG-824's rule for pushes).
fn entries(src: &Source, edits: &[Edit], uploaded: &HashSet<ObjectId>, base_tree: &ObjectId) -> Result<HashMap<String, TreeEntry>> {
    let mut out = HashMap::new();
    for e in edits {
        let entry = match &e.put {
            None => continue,
            Some(Content::Made(id, size, executable)) => TreeEntry {
                name: String::new(),
                kind: EntryKind::File,
                id: *id,
                size: *size,
                executable: *executable,
                visibility: Visibility::Public,
                fallback: None,
            },
            Some(Content::Object(id, executable)) => {
                let at_base = sync::entry_at(src, base_tree, &e.path)?.is_some_and(|b| b.id == *id);
                if !uploaded.contains(id) && !at_base {
                    return Err(veil_core::VeilError::Missing(*id).into());
                }
                let raw = src.raw(id)?;
                let (size, visibility) = match Object::sealed_scope(&raw) {
                    // The scope a secret is sealed under, without its key
                    // generation (`team#…`), as `vl` labels it.
                    Some(label) => (0, Visibility::Cloaked { scope: label.split('#').next().unwrap_or_default().to_string() }),
                    None if Object::is_blob_raw(&raw) => match Object::decode(&raw)? {
                        Object::Blob(b) => (b.len() as u64, Visibility::Public),
                        _ => unreachable!("a blob's encoding"),
                    },
                    None => return Err(bad(format!("'{}': the object is not a file's content", e.path))),
                };
                TreeEntry {
                    name: String::new(),
                    kind: EntryKind::File,
                    id: *id,
                    size,
                    executable: *executable,
                    visibility,
                    fallback: None,
                }
            }
        };
        out.insert(e.path.clone(), entry);
    }
    Ok(out)
}

/// Walk `parts` down tree `root` (a real tree, read as it is, or one `pr`
/// projected; `pr` projects nothing itself): the
/// folders on the way (the root's id first, then each folder's, as far as
/// they are folders) and the entry at the end.
fn walk(pr: &Projector, root: ObjectId, parts: &[String]) -> Result<(Vec<ObjectId>, Option<TreeEntry>)> {
    let mut dirs = vec![root];
    let mut cur = root;
    for (i, part) in parts.iter().enumerate() {
        let Some(t) = pr.tree(&cur)? else { return Ok((dirs, None)) };
        let Some(e) = t.get(part) else { return Ok((dirs, None)) };
        if i + 1 == parts.len() {
            return Ok((dirs, Some(e.clone())));
        }
        if e.kind != EntryKind::Dir {
            return Ok((dirs, None));
        }
        cur = e.id;
        dirs.push(cur);
    }
    Ok((dirs, None))
}

/// May edits made on real tree `a` be applied to real tree `b`: as the
/// caller sees them (`pr`), the same entry at every edited path, and each
/// folder above it a folder in both or in neither? (On the caller's view
/// only: whether to rebase never tells them about what they cannot see.)
fn unchanged(pr: &mut Projector, a: &ObjectId, b: &ObjectId, edits: &[Edit]) -> Result<bool> {
    let (a, b) = (pr.root(*a)?, pr.root(*b)?);
    for e in edits {
        let (da, ea) = walk(pr, a, &e.parts)?;
        let (db, eb) = walk(pr, b, &e.parts)?;
        if ea != eb || da.len() != db.len() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The caller's projected tree of real snapshot `parent` with the edits
/// applied: the tree their own `vl` would push.
struct Shaped {
    tree: ObjectId,
    made: HashMap<ObjectId, Bytes>,
    entries: HashMap<String, TreeEntry>,
}

/// What one attempt built.
struct Built {
    real: ObjectId,
    /// The objects to store (blobs, the trees of the full snapshot this
    /// change made, the snapshot, the caller's projection of it).
    store: Vec<(ObjectId, Bytes)>,
    mine: ObjectId,
    /// The policy text the default branch's move accepts (an admin's).
    accept: Option<String>,
}

/// Everything the attempts share.
struct Plan {
    project: Project,
    viewer: Viewer,
    edits: Vec<Edit>,
    uploaded: HashSet<ObjectId>,
    pending: HashMap<ObjectId, Bytes>,
    change_id: ChangeId,
    description: String,
    author: String,
    timestamp: i64,
    predecessors: Vec<ObjectId>,
    ppredecessors: Vec<ObjectId>,
    base_tree: ObjectId,
    /// The branch `onto` names, if it is the default branch.
    default_branch: bool,
}

/// Build the change on real snapshot `parent` (which the caller sees as
/// `pparent`), with every check a push gets.
async fn build(hub: &Arc<Hub>, plan: &Arc<Plan>, parent: ObjectId, pparent: ObjectId) -> Result<Built> {
    // The caller's tree, as their `vl` would push it.
    let p = plan.clone();
    let shaped = sync::blocking_with(hub, plan.project.id, plan.pending.clone(), move |src| {
        let view = p.project.view(&p.viewer);
        let mut pr = Projector::new(src, &view);
        let ptree = pr.root(src.snapshot(&parent)?.tree)?;
        let entries = entries(src, &p.edits, &p.uploaded, &p.base_tree)?;
        let mut made = HashMap::new();
        let edits: Vec<&Edit> = p.edits.iter().collect();
        let tree = apply(src, &pr, &entries, &mut made, Some(ptree), &edits, 0)?.expect("the root is never absent");
        Ok(Shaped { tree, made, entries })
    })
    .await?;
    // The push's checks on it, then the caller's projection.
    let mut overlay = plan.pending.clone();
    overlay.extend(shaped.made.iter().map(|(k, v)| (*k, v.clone())));
    let (p, hub2) = (plan.clone(), hub.clone());
    sync::blocking_with(hub, plan.project.id, overlay, move |src| {
        let project = &p.project;
        let mut n = Snapshot {
            parents: vec![parent],
            change_id: p.change_id,
            tree: shaped.tree,
            description: Text::Plain(p.description.clone()),
            author: p.author.clone(),
            timestamp: p.timestamp,
            predecessors: p.predecessors.clone(),
            conflicts: vec![],
            cloak: None,
            embargo: None,
            signature: None,
        };
        n.sign(&hub2.identity);
        let mut known = p.uploaded.clone();
        known.extend(src.pending.keys().copied());
        let c = sync::complete(src, project, &p.viewer, &known, &n, &[parent], &hub2.identity)?;
        let (real, raw) = match c.raw {
            Some(raw) => match Object::decode(&raw)? {
                Object::Snapshot(s) => (s, raw),
                _ => unreachable!("complete makes snapshots"),
            },
            None => {
                let raw = Bytes::from(Object::Snapshot(n.clone()).encode());
                (n, raw)
            }
        };
        let view = project.view(&p.viewer);
        let (mine, mine_raw) = sync::project_one(src, &view, c.real, &real, vec![pparent], p.ppredecessors.clone(), None, &hub2.identity)?;
        // What the full tree holds of what this change made: the blobs, and
        // the trees of the caller's that are the full tree's (all of them
        // for someone who sees everything there; the graft stored its own).
        let mut store: Vec<(ObjectId, Bytes)> = Vec::new();
        let mut seen = HashSet::new();
        for e in &p.edits {
            if let Some(entry) = shaped.entries.get(&e.path) {
                if let Some(raw) = p.pending.get(&entry.id) {
                    if seen.insert(entry.id) {
                        store.push((entry.id, raw.clone()));
                    }
                }
            }
            for d in walk(&Projector::new(src, &view), real.tree, &e.parts)?.0 {
                if let Some(raw) = shaped.made.get(&d) {
                    if seen.insert(d) {
                        store.push((d, raw.clone()));
                    }
                }
            }
        }
        store.push((c.real, raw));
        if let Some(r) = mine_raw {
            store.push((mine, r));
        }
        let accept = match p.default_branch {
            true => {
                let text = sync::policy_text(src, &real.tree)?;
                match AccessPolicy::parse(&text).same_rules(&p.project.policy) {
                    true => None,
                    false if p.viewer.admin => Some(text),
                    false => return Err(Error::forbidden("only admins may change who has access (the default branch's .veilpolicy)")),
                }
            }
            false => None,
        };
        Ok(Built { real: c.real, store, mine, accept })
    })
    .await
}

/// Store `objects`, several at once.
async fn store_all(hub: &Arc<Hub>, project: i64, objects: Vec<(ObjectId, Bytes)>) -> Result<()> {
    let mut set = tokio::task::JoinSet::new();
    for (id, raw) in objects {
        let objects = hub.objects.clone();
        set.spawn(async move { objects.put(project, &id, raw).await });
    }
    while let Some(r) = set.join_next().await {
        r.map_err(|e| Error::Other(e.into()))??;
    }
    Ok(())
}

/// The branch move of one attempt: `(branch, its real tip now)`, and
/// whether to keep the change when the tip moved meanwhile (else the
/// transaction is rolled back, to try again on the new tip).
struct Move {
    branch: String,
    cur: ObjectId,
    keep_on_loss: bool,
}

/// The one database commit of a change: its snapshot row, the caller's
/// projection, the change ref, the audit row and, with `mv`, the branch's
/// compare-and-swap (and an admin's policy). `Ok(Some(moved))` with a
/// move, `Ok(None)` without; `Err(conflict)` when the tip moved and the
/// change is not kept.
async fn commit(hub: &Arc<Hub>, plan: &Arc<Plan>, built: &Built, person: i64, mv: Option<Move>) -> Result<Option<bool>> {
    let pid = plan.project.id;
    let view_key = (!plan.viewer.admin).then(|| plan.project.view(&plan.viewer).key());
    let (real, mine, cid, accept) = (built.real.hex(), built.mine.hex(), plan.change_id.to_string(), built.accept.clone());
    let mv = mv.map(|m| (m.branch, m.cur.hex(), m.keep_on_loss));
    crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
        let (real, mine, cid, accept, mv, view_key) = (real.clone(), mine.clone(), cid.clone(), accept.clone(), mv.clone(), view_key.clone());
        Box::pin(async move {
            let now = veil_core::now_millis();
            let mut moved = None;
            if let Some((branch, cur, keep)) = &mv {
                let rows = sqlx::query("UPDATE branches SET target = $1 WHERE project_id = $2 AND name = $3 AND target = $4")
                    .bind(&real)
                    .bind(pid)
                    .bind(branch)
                    .bind(cur)
                    .execute(&mut *c)
                    .await?
                    .rows_affected();
                if rows != 1 && !keep {
                    return Err(Error::conflict(format!("branch '{branch}' moved")));
                }
                moved = Some(rows == 1);
                if let (1, Some(text)) = (rows, &accept) {
                    crate::perm::accept_policy(&mut *c, pid, text).await?;
                }
            }
            sqlx::query("INSERT INTO snapshots (project_id, id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                .bind(pid)
                .bind(&real)
                .execute(&mut *c)
                .await?;
            if let Some(key) = &view_key {
                sqlx::query(
                    "INSERT INTO projections (project_id, view_key, real_id, projected_id, created_at) VALUES ($1, $2, $3, $4, $5) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(pid)
                .bind(key)
                .bind(&real)
                .bind(&mine)
                .bind(now)
                .execute(&mut *c)
                .await?;
            }
            // Only its creator makes new revisions of a change.
            let rows = sqlx::query(
                "INSERT INTO change_refs (project_id, change_id, snapshot, created_by, created_at) VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (project_id, change_id) DO UPDATE SET snapshot = EXCLUDED.snapshot WHERE change_refs.created_by = EXCLUDED.created_by",
            )
            .bind(pid)
            .bind(&cid)
            .bind(&real)
            .bind(person)
            .bind(now)
            .execute(&mut *c)
            .await?
            .rows_affected();
            if rows != 1 {
                return Err(Error::not_found(format!("no change {cid} of yours")));
            }
            let what = match (&mv, moved) {
                (Some((b, _, _)), Some(true)) => format!("change {cid}, onto {b}"),
                _ => format!("change {cid}"),
            };
            sqlx::query("INSERT INTO audit_log (project_id, at, actor, action, details) VALUES ($1, $2, $3, $4, $5)")
                .bind(pid)
                .bind(now)
                .bind(person)
                .bind("change")
                .bind(&what)
                .execute(&mut *c)
                .await?;
            Ok(moved)
        })
    })
    .await
}

/// The real tip of `branch`, if it exists.
async fn tip(hub: &Hub, project: i64, branch: &str) -> Result<Option<ObjectId>> {
    let t: Option<String> = sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = $2")
        .bind(project)
        .bind(branch)
        .fetch_optional(&hub.db)
        .await?;
    t.map(|t| ObjectId::from_hex(&t).map_err(|e| Error::Other(e.into()))).transpose()
}

/// The real snapshot the caller means by `base`: the branch's tip if they
/// see it as `base`, else the newest real snapshot that is `base` for
/// them. Anything else is not found, as for every snapshot they may not
/// see (a real id of a snapshot they see only part of included).
async fn resolve_base(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, base: ObjectId, cur: Option<ObjectId>) -> Result<ObjectId> {
    if base == sync::root_snapshot_id() {
        return Ok(base);
    }
    if let Some(c) = cur {
        if sync::projected(hub, project, viewer, c).await? == base {
            return Ok(c);
        }
    }
    // A projection many hidden-only changes share stands for each of them;
    // the newest few are enough (they differ only in what the caller
    // cannot see).
    for r in sync::resolve(hub, project.id, &base).await?.into_iter().take(16) {
        if sync::projected(hub, project, viewer, r).await? == base {
            return Ok(r);
        }
    }
    Err(Error::not_found(format!("no snapshot {} that you can see", base.short())))
}

/// `POST /v1/projects/{p}/changes`.
pub async fn create(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, person: &Person, req: ChangeRequest) -> Result<ChangeResult> {
    if !project.participant(viewer) {
        return Err(Error::forbidden("you are not in this project"));
    }
    let mut pending = HashMap::new();
    let edits = validate(&req, &mut pending)?;
    let onto = req.onto.clone();
    let mut cur = match &onto {
        Some(o) => Some(tip(hub, project.id, &o.branch).await?.ok_or_else(|| bad(format!("no branch '{}'", o.branch)))?),
        None => None,
    };
    let base_real = resolve_base(hub, project, viewer, req.base, cur).await?;
    // A new revision of one of the caller's own changes, or a new change.
    let (change_id, predecessors) = match req.change_id {
        Some(cid) => {
            let row: Option<(String, i64)> = sqlx::query_as("SELECT snapshot, created_by FROM change_refs WHERE project_id = $1 AND change_id = $2")
                .bind(project.id)
                .bind(cid.to_string())
                .fetch_optional(&hub.db)
                .await?;
            match row {
                Some((s, by)) if by == person.id => (cid, vec![ObjectId::from_hex(&s).map_err(|e| Error::Other(e.into()))?]),
                _ => return Err(Error::not_found(format!("no change {cid} of yours"))),
            }
        }
        None => (ChangeId::random(), vec![]),
    };
    let mut ppredecessors = Vec::new();
    for p in &predecessors {
        ppredecessors.push(sync::projected(hub, project, viewer, *p).await?);
    }
    let base_tree = {
        let b = base_real;
        sync::blocking(hub, project.id, move |src| Ok(src.snapshot(&b)?.tree)).await?
    };
    let plan = Arc::new(Plan {
        project: project.clone(),
        viewer: viewer.clone(),
        uploaded: sync::receipted(hub, project.id, person.id, &req.receipts),
        pending,
        change_id,
        description: req.description.clone(),
        author: person.name.clone(),
        timestamp: veil_core::now_millis(),
        predecessors,
        ppredecessors,
        base_tree,
        default_branch: onto.as_ref().is_some_and(|o| o.branch == project.default_branch),
        edits,
    });

    // The branch move, when asked: refused at once if the tip is not what
    // the caller expected or the move is not a fast-forward (the change is
    // still made and kept on its ref).
    let mut rejected: Option<String> = None;
    if let (Some(o), Some(c)) = (&onto, cur) {
        if let Expected::Tip(t) = o.expected {
            if sync::projected(hub, project, viewer, c).await? != t {
                rejected = Some("the branch has moved since you last saw it".into());
            } else if c != base_real && !sync::is_ancestor(hub, project.id, c, base_real).await? {
                rejected = Some("not a fast-forward: the change is not on top of the branch".into());
            }
        }
    }
    let rebase = onto.as_ref().is_some_and(|o| o.expected == Expected::Rebase);
    let (mut parent, mut pparent) = (base_real, req.base);
    let mut rebased = 0u32;
    let mut attempts = 0u32;
    let (built, moved) = loop {
        attempts += 1;
        if let (true, None, Some(c)) = (rebase, &rejected, cur) {
            if c != parent {
                let (bt, b) = (plan.base_tree, plan.clone());
                let ok = sync::blocking(hub, project.id, move |src| {
                    let ct = src.snapshot(&c)?.tree;
                    let view = b.project.view(&b.viewer);
                    unchanged(&mut Projector::new(src, &view), &bt, &ct, &b.edits)
                })
                .await?;
                match ok {
                    true => {
                        parent = c;
                        pparent = sync::projected(hub, project, viewer, c).await?;
                        rebased += 1;
                    }
                    false => rejected = Some("the branch moved, and a path this change edits changed there since its base".into()),
                }
            }
        }
        let built = build(hub, &plan, parent, pparent).await?;
        store_all(hub, project.id, built.store.clone()).await?;
        let mv = match (&onto, cur, &rejected) {
            (Some(o), Some(c), None) => Some(Move {
                branch: o.branch.clone(),
                cur: c,
                // A tip that moves away and back must not keep it trying.
                keep_on_loss: !rebase || rebased >= MAX_REBASES || attempts > MAX_REBASES,
            }),
            _ => None,
        };
        match commit(hub, &plan, &built, person.id, mv).await {
            Ok(m) => break (built, m),
            // The tip moved during the request: try again on the new one.
            Err(Error::Api { code: "conflict", .. }) => {
                cur = tip(hub, project.id, &onto.as_ref().expect("a move").branch).await?;
                if cur.is_none() {
                    rejected = Some("the branch was deleted".into());
                }
            }
            Err(e) => return Err(e),
        }
    };
    let mut warnings = Vec::new();
    let branch = match onto {
        None => None,
        Some(o) => {
            let landed = moved == Some(true);
            if moved == Some(false) {
                rejected = Some("the branch moved during the request".into());
            }
            let tip_seen = match landed {
                true => Some(built.mine),
                false => match tip(hub, project.id, &o.branch).await? {
                    Some(t) => Some(sync::projected(hub, project, viewer, t).await?),
                    None => None,
                },
            };
            if landed && built.accept.is_some() {
                let p = crate::perm::load_project(&mut *hub.db.acquire().await?, &project.name)
                    .await?
                    .ok_or_else(|| Error::not_found("project"))?;
                warnings = crate::perm::accepted_listing(&p);
            }
            Some(BranchOutcome {
                branch: o.branch,
                status: if landed { Status::Ok } else { Status::Rejected },
                message: if landed { None } else { rejected },
                tip: tip_seen,
                rebased,
            })
        }
    };
    Ok(ChangeResult {
        change_id,
        snapshot: built.mine,
        branch,
        warnings,
    })
}
