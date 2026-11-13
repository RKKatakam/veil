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
    auth::Caller,
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
        // The tree's own limit: at most `MAX_TREE_DEPTH` folders above a file.
        if parts.len() > MAX_TREE_DEPTH + 1 {
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
/// did not upload, and that is not the entry at that path in **their view**
/// of `base` (`pbase`, projected by `pr`), gets the answer a missing object
/// gets, before anything reads it: a change never confirms a guess of a
/// hidden object or of a hidden file's content (BUG-824's rule for pushes;
/// BUG-1050).
fn entries(src: &Source, pr: &Projector, edits: &[Edit], uploaded: &HashSet<ObjectId>, pbase: ObjectId) -> Result<HashMap<String, TreeEntry>> {
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
            },
            Some(Content::Object(id, executable)) => {
                let at_base = walk(pr, pbase, &e.parts)?.1.is_some_and(|b| b.id == *id);
                if !uploaded.contains(id) && !at_base {
                    return Err(veil_core::VeilError::Missing(*id).into());
                }
                let raw = src.raw(id)?;
                let (size, visibility) = match Object::sealed_scope(&raw) {
                    // The scope a secret is sealed under, without its key
                    // generation (`team#…`), as `vl` labels it.
                    // Its stored length: the server cannot know the
                    // plaintext's, and a recorded size bounds reads (BUG-1087).
                    Some(label) => (raw.len() as u64, Visibility::Cloaked { scope: label.split('#').next().unwrap_or_default().to_string() }),
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
pub(crate) fn walk(pr: &Projector, root: ObjectId, parts: &[String]) -> Result<(Vec<ObjectId>, Option<TreeEntry>)> {
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
    /// The default branch's new access lines (its `.veilpolicy`), when they
    /// are not the accepted ones: accepted only if the branch moves, and
    /// only from an admin.
    accept: Option<String>,
    /// The default branch's new `.veilpolicy` text when only non-access lines
    /// changed.
    policy_text_update: Option<String>,
    /// The branch rules (`.veilrules`) of the full tree, to compare with the
    /// default branch's tip's (BUG-1102).
    rules: Option<TreeEntry>,
    /// The new tip's `.veilrules`, for a move of the default branch (S21:
    /// the review rules state its landing records, `prs::state`).
    rules_file: Option<crate::prs::state::RulesFile>,
}

/// Who asks, as of one attempt: the project with its accepted policy and
/// the caller's view, read again after every lost race (BUG-1051).
struct Who {
    project: Project,
    viewer: Viewer,
}

/// Everything the attempts share.
struct Plan {
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
    /// An agent session's attribution (`docs/HUB.md` §13.27): the server
    /// stamps it from the session's record; the request has no field for
    /// one, so a caller can never set or forge it.
    agent: Option<veil_core::object::Attribution>,
}

/// Build the change on real snapshot `parent` (which the caller sees as
/// `pparent`), with every check a push gets.
async fn build(hub: &Arc<Hub>, plan: &Arc<Plan>, who: &Arc<Who>, parent: ObjectId, pparent: ObjectId) -> Result<Built> {
    // The caller's tree, as their `vl` would push it.
    let (p, w) = (plan.clone(), who.clone());
    let t_sh = std::time::Instant::now();
    let shaped = sync::blocking_with(hub, w.project.id, plan.pending.clone(), move |src| {
        let view = w.project.view(&w.viewer);
        let mut pr = Projector::new(src, &view);
        let ptree = pr.root(src.snapshot(&parent)?.tree)?;
        let pbase = pr.root(p.base_tree)?;
        let entries = entries(src, &pr, &p.edits, &p.uploaded, pbase)?;
        let mut made = HashMap::new();
        let edits: Vec<&Edit> = p.edits.iter().collect();
        let tree = apply(src, &pr, &entries, &mut made, Some(ptree), &edits, 0)?.expect("the root is never absent");
        Ok(Shaped { tree, made, entries })
    })
    .await?;
    crate::landing::prof(&hub.landing.stats.p_b_shape_us, t_sh);
    // The push's checks on it, then the caller's projection.
    let mut overlay = plan.pending.clone();
    overlay.extend(shaped.made.iter().map(|(k, v)| (*k, v.clone())));
    let (p, w, hub2) = (plan.clone(), who.clone(), hub.clone());
    // The trees the push's checks graft are held, not stored as they are
    // made (BUG-2362: each was written alone, two waits on a local store's
    // journal apiece, 7 to 11 ms of a landing's submit while it held its
    // project's gate): they are stored with the change's other objects,
    // all at once, before anything reads them from the store.
    let held = sync::Staged::held();
    sync::blocking_in(hub, who.project.id, overlay, Some(held.clone()), move |src| {
        let n = Snapshot {
            parents: vec![parent],
            change_id: p.change_id,
            tree: shaped.tree,
            description: Text::Plain(p.description.clone()),
            author: p.author.clone(),
            timestamp: p.timestamp,
            predecessors: p.predecessors.clone(),
            conflicts: vec![],
            embargo: None,
            agent: p.agent.clone(),
            abandoned: None,
            attempts: vec![],
            signature: None,
        };
        let mut known = p.uploaded.clone();
        known.extend(src.pending.keys().copied());
        let t_cs = std::time::Instant::now();
        let (real_id, real, raw) = complete_signed(src, &w, &known, n, parent, &hub2.identity)?;
        crate::landing::prof(&hub2.landing.stats.p_b_complete_us, t_cs);
        let t_po = std::time::Instant::now();
        let view = w.project.view(&w.viewer);
        let (mine, mine_raw) = sync::project_one(src, &view, real_id, &real, vec![pparent], p.ppredecessors.clone(), vec![], None, &hub2.identity)?;
        crate::landing::prof(&hub2.landing.stats.p_b_project_us, t_po);
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
        for (id, raw) in held.made() {
            if seen.insert(id) {
                store.push((id, raw));
            }
        }
        store.push((real_id, raw));
        if let Some(r) = mine_raw {
            store.push((mine, r));
        }
        // Access lines are judged against the parent by the push's checks
        // (`complete`); a move of the default branch accepts its lines,
        // which `create` allows only for an admin's move (BUG-1051).
        let (accept, policy_text_update) = match p.default_branch {
            true => {
                let text = sync::policy_text(src, &real.tree)?;
                if !AccessPolicy::parse(&text).same_rules(&w.project.policy) {
                    (Some(text), None)
                } else if text != w.project.policy_text {
                    (None, Some(text))
                } else {
                    (None, None)
                }
            }
            false => (None, None),
        };
        let rules = sync::entry_at(src, &real.tree, crate::landing::rules::RULES_FILE)?;
        let rules_file = match p.default_branch {
            true => Some(crate::prs::state::file_at(src, real.tree)?),
            false => None,
        };
        Ok(Built { real: real_id, store, mine, accept, policy_text_update, rules, rules_file })
    })
    .await
}

/// [`sync::complete`] for snapshot `n` (signed here by the server) on real
/// parent `parent`: the full snapshot, its id and encoding.
fn complete_signed(src: &Source, who: &Who, known: &HashSet<ObjectId>, mut n: Snapshot, parent: ObjectId, identity: &veil_core::Identity) -> Result<(ObjectId, Snapshot, Bytes)> {
    n.sign(identity);
    // A change made again keeps its attempts (real ids already).
    let attempts = n.attempts.clone();
    let c = sync::complete(src, &who.project, &who.viewer, known, &n, &[parent], &attempts, identity, &mut sync::PushRows::default())?;
    Ok(match c.raw {
        Some(raw) => match Object::decode(&raw)? {
            Object::Snapshot(s) => (c.real, s, raw),
            _ => unreachable!("complete makes snapshots"),
        },
        None => {
            let raw = Bytes::from(Object::Snapshot(n.clone()).encode());
            (c.real, n, raw)
        }
    })
}

/// The caller's own unlanded changes `chain` (real, oldest first, made
/// through this API: they change only paths their maker sees), made again
/// on real tip `onto`, which the caller sees exactly as the parent of the
/// oldest (only changes they cannot see came between). Each is the
/// caller's view of it grafted onto the new parent, with the push's checks;
/// the caller's projection of each is unchanged, so whether anything they
/// cannot see landed never shows (BUG-1054). `(new, old, mine)` for each.
async fn restack(hub: &Arc<Hub>, who: &Arc<Who>, chain: Vec<ObjectId>, onto: ObjectId) -> Result<(Vec<(ObjectId, ObjectId, ObjectId)>, Vec<(ObjectId, Bytes)>)> {
    let mut rows = Vec::new();
    let mut store = Vec::new();
    let mut parent = onto;
    for old in chain {
        let mine = sync::projected(hub, &who.project, &who.viewer, old).await?;
        // The caller's view of it (trees the projector made, held in
        // memory), and the objects it introduced: known, as they are
        // already the caller's (their own change, checked when it was made).
        let w = who.clone();
        let (n, overlay, known) = sync::blocking(hub, who.project.id, move |src| {
            let s = src.snapshot(&old)?;
            let old_parent = src.snapshot(&s.parents[0])?;
            let policy = AccessPolicy::default();
            let everything = veil_core::hub::access::View::admin(&policy);
            let mut diff = veil_core::hub::project::Graft::new(src, &everything);
            diff.root(s.tree, Some(old_parent.tree))?;
            let mut known = HashSet::new();
            for c in &diff.changes {
                if let Some(e) = &c.new {
                    known.extend(sync::named_ids(src, e)?);
                }
            }
            let view = w.project.view(&w.viewer);
            let mut pr = Projector::new(src, &view);
            let tree = pr.root(s.tree)?;
            // The folders of the caller's view on the way to each path the
            // change made (a new folder, or one they see whole: real trees
            // of theirs), as known as its files (BUG-1056).
            for c in &diff.changes {
                let parts: Vec<String> = c.path.split('/').map(str::to_string).collect();
                known.extend(walk(&pr, tree, &parts)?.0);
            }
            let overlay: HashMap<ObjectId, Bytes> = pr.created.iter().map(|(id, (_, raw))| (*id, Bytes::from(raw.clone()))).collect();
            known.extend(overlay.keys().copied());
            let n = Snapshot {
                parents: vec![parent],
                tree,
                signature: None,
                ..(*s).clone()
            };
            Ok((n, overlay, known))
        })
        .await?;
        let (w, hub2) = (who.clone(), hub.clone());
        let (id, raw) = sync::blocking_with(hub, who.project.id, overlay, move |src| {
            let (id, real, raw) = complete_signed(src, &w, &known, n, parent, &hub2.identity)?;
            // The caller sees it exactly as before (the same id).
            let view = w.project.view(&w.viewer);
            let pm = src.snapshot(&mine)?;
            let (again, _) = sync::project_one(src, &view, id, &real, pm.parents.clone(), pm.predecessors.clone(), pm.attempts.clone(), None, &hub2.identity)?;
            if again != mine {
                return Err(Error::Other(anyhow::anyhow!("a change made again on the tip would show differently")));
            }
            Ok((id, raw))
        })
        .await?;
        store.push((id, raw));
        rows.push((id, old, mine));
        parent = id;
    }
    Ok((rows, store))
}

/// The branch move of one attempt: `(branch, its real tip now)`, and
/// whether to keep the change when the tip moved meanwhile (else the
/// transaction is rolled back, to try again on the new tip).
struct Move {
    branch: String,
    cur: ObjectId,
    /// The change's parent: `cur`, the caller's changes restacked on it, or
    /// a stack of the caller's own held changes made on `cur` itself, which
    /// the move brings onto the branch with the change (BUG-1922).
    below: ObjectId,
    keep_on_loss: bool,
}

/// The one database commit of a change: its snapshot row, the caller's
/// projection, the change ref, the audit row and, with `mv`, the branch's
/// compare-and-swap (and an admin's policy) and the notice that drops every
/// server's tips (`caches`, S4), with the rows of the caller's changes
/// `restacked` under it. `Ok(Some(moved))` with a move,
/// `Ok(None)` without; `Err(conflict)` when the tip moved and the change is
/// not kept.
#[allow(clippy::too_many_arguments)]
async fn commit(
    hub: &Arc<Hub>,
    plan: &Arc<Plan>,
    who: &Who,
    built: &Built,
    restacked: &[(ObjectId, ObjectId, ObjectId)],
    person: i64,
    gc_epoch: i64,
    mv: Option<Move>,
    land: Option<&(crate::landing::Submitter, crate::landing::Queued)>,
    base_embargo: Option<&str>,
) -> Result<Option<bool>> {
    let pid = who.project.id;
    // A landing: the change (and what it stacks on: `landing::stack`) joins
    // the queue in this same commit.
    let land = land.cloned();
    let base_embargo = base_embargo.map(str::to_string);
    let view_key = (!who.viewer.admin).then(|| who.project.view(&who.viewer).key());
    let mut snaps: Vec<(String, String)> = restacked.iter().map(|(n, _, m)| (n.hex(), m.hex())).collect();
    snaps.push((built.real.hex(), built.mine.hex()));
    let moved_refs: Vec<(String, String)> = restacked.iter().map(|(n, o, _)| (n.hex(), o.hex())).collect();
    let (real, cid, accept, policy_text_update) = (built.real.hex(), plan.change_id.to_string(), built.accept.clone(), built.policy_text_update.clone());
    let (agent_session, narrowed) = (who.viewer.agent || who.viewer.only.is_some(), who.viewer.only.is_some());
    let expected_prev = plan.predecessors.first().map(ObjectId::hex);
    // A change onto the tip is a fast-forward from it.
    let rules_landing = match (&built.rules_file, &mv) {
        (Some(file), Some(m)) => Some(crate::prs::state::Landing { old: Some(m.cur), new: built.real, file: file.clone(), fast_forward: true }),
        _ => None,
    };
    // The held snapshots the move reaches first: the change's parent, when
    // it is neither the tip nor one of the changes restacked here.
    let below: Vec<ObjectId> = mv.iter().filter(|m| m.below != m.cur && !restacked.iter().any(|(n, _, _)| *n == m.below)).map(|m| m.below).collect();
    let moved_from = mv.as_ref().map(|m| m.cur);
    let mv = mv.map(|m| (m.branch, m.cur.hex(), m.keep_on_loss));
    let notify = hub.caches.notices.load(std::sync::atomic::Ordering::SeqCst);
    let committed: Vec<ObjectId> = restacked.iter().map(|(n, _, _)| *n).chain(std::iter::once(built.real)).collect();
    // What a move puts on the branch, by change id and author
    // (`landed_changes`, BUG-1522, BUG-1527): the caller's restacked changes
    // and this one, and the held changes below it that the move brings
    // (BUG-1922: a stack made on the tip itself), read as a push's
    // fast-forward reads them (`landing::reached`). Where they cannot all
    // be read, the move turns the branch's `changes_recorded` off, in the
    // lineage they were read under.
    let (mut recorded, mut read_under): (bool, Option<i64>) = (true, None);
    let on_branch: (Vec<String>, Vec<i64>, Vec<String>) = match &mv {
        None => (Vec::new(), Vec::new(), Vec::new()),
        Some((branch, _, _)) => {
            let ids = committed.clone();
            let mut cs: Vec<String> = sync::blocking(hub, pid, move |src| {
                ids.iter().take(ids.len() - 1).map(|n| Ok(src.snapshot(n)?.change_id.to_string())).collect::<Result<Vec<_>>>()
            })
            .await?;
            cs.push(cid.clone());
            let mut aus = vec![person; cs.len()];
            let mut ls: Vec<String> = committed.iter().map(ObjectId::hex).collect();
            if !below.is_empty() {
                match crate::landing::reached(hub, pid, branch, below, moved_from).await? {
                    Some((lineage, (c2, a2, l2))) => {
                        cs.extend(c2);
                        aus.extend(a2);
                        ls.extend(l2);
                        read_under = Some(lineage);
                    }
                    None => recorded = false,
                }
            }
            (cs, aus, ls)
        }
    };
    let r = crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
        let (real, cid, accept, policy_text_update, mv, view_key, snaps, moved_refs, land, on_branch, expected_prev, base_embargo) = (
            real.clone(),
            cid.clone(),
            accept.clone(),
            policy_text_update.clone(),
            mv.clone(),
            view_key.clone(),
            snaps.clone(),
            moved_refs.clone(),
            land.clone(),
            on_branch.clone(),
            expected_prev.clone(),
            base_embargo.clone(),
        );
        let rules_landing = rules_landing.clone();
        Box::pin(async move {
            crate::pack_gc::guard_root_write(&mut *c, pid, gc_epoch).await?;
            if let Some((w, q)) = &land {
                crate::landing::insert(&mut *c, pid, w, q).await?;
            }
            let now = veil_core::now_millis();
            let mut moved = None;
            if let Some((branch, cur, keep)) = &mv {
                let lineage: Option<i64> =
                    sqlx::query_scalar(
                        "UPDATE branches SET target = $1, changes_recorded = changes_recorded AND $5 AND ($6::BIGINT IS NULL OR lineage = $6) \
                         WHERE project_id = $2 AND name = $3 AND target = $4 RETURNING lineage",
                    )
                        .bind(&real)
                        .bind(pid)
                        .bind(branch)
                        .bind(cur)
                        .bind(recorded)
                        .bind(read_under)
                        .fetch_optional(&mut *c)
                        .await?;
                let rows = u64::from(lineage.is_some());
                if rows != 1 && !keep {
                    return Err(Error::conflict(format!("branch '{branch}' moved")));
                }
                if let Some(lineage) = lineage {
                    crate::landing::record_changes(&mut *c, pid, branch, lineage, &on_branch.0, &on_branch.1, &on_branch.2).await?;
                }
                moved = Some(rows == 1);
                let mut gate = false;
                if rows == 1 && (accept.is_some() || policy_text_update.is_some()) {
                    // A new access policy (an approval counts while its
                    // reviewer may write the PR's paths: BUG-2111): the
                    // review gate, exclusively, before the project's row
                    // (lock order, BUG-2130).
                    crate::prs::close_review_gate(&mut *c, pid).await?;
                    if let Some(text) = &accept {
                        crate::perm::accept_policy(&mut *c, pid, text).await?;
                    } else if let Some(text) = &policy_text_update {
                        sqlx::query("UPDATE projects SET policy_text = $1 WHERE id = $2")
                            .bind(text)
                            .bind(pid)
                            .execute(&mut *c)
                            .await?;
                    }
                }
                if let (1, Some(l)) = (rows, &rules_landing) {
                    gate = crate::prs::state::record_landing(&mut *c, pid, l).await?;
                }
                if gate {
                    // New review rules (BUG-2061): the review gate,
                    // exclusively, after the branch row (again, if the
                    // policy took it).
                    crate::prs::close_review_gate(&mut *c, pid).await?;
                }
            }
            let mut memos = Vec::new();
            for (snap, mine) in &snaps {
                sqlx::query("INSERT INTO snapshots (project_id, id, author) VALUES ($1, $2, $3) ON CONFLICT (project_id, id) DO UPDATE SET author = EXCLUDED.author WHERE snapshots.author = 0")
                    .bind(pid)
                    .bind(snap)
                    .bind(person)
                    .execute(&mut *c)
                    .await?;
                if let Some(eid) = &base_embargo {
                    for s_id in [snap.as_str(), mine.as_str()] {
                        sqlx::query("INSERT INTO embargo_snapshots (project_id, snapshot, embargo_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
                            .bind(pid)
                            .bind(s_id)
                            .bind(eid)
                            .execute(&mut *c)
                            .await?;
                    }
                }
                if let Some(key) = &view_key {
                    let n = sqlx::query(
                        // The caller's own changes: in their history (never collapsed).
                        "INSERT INTO projections (project_id, view_key, real_id, projected_id, created_at, collapsed) VALUES ($1, $2, $3, $4, $5, false) \
                         ON CONFLICT DO NOTHING",
                    )
                    .bind(pid)
                    .bind(key)
                    .bind(snap)
                    .bind(mine)
                    .bind(now)
                    .execute(&mut *c)
                    .await?
                    .rows_affected();
                    // Cached once committed, if it is the row stored.
                    if n == 1 {
                        memos.push((key.clone(), snap.clone(), mine.clone()));
                    }
                }
            }
            // The caller's changes made again under this one keep their refs.
            for (new, old) in &moved_refs {
                sqlx::query("UPDATE change_refs SET snapshot = $1 WHERE project_id = $2 AND snapshot = $3 AND created_by = $4")
                    .bind(new)
                    .bind(pid)
                    .bind(old)
                    .bind(person)
                    .execute(&mut *c)
                    .await?;
            }
            // Only its creator makes new revisions of a change; an agent or
            // narrowed session also binds the exact snapshot `resolve_change`
            // verified so a concurrent out-of-scope update is never clobbered.
            if agent_session {
                if let Some(prev) = &expected_prev {
                    let cur_expected = moved_refs
                        .iter()
                        .find(|(_, o)| o == prev)
                        .map_or(prev.as_str(), |(n, _)| n.as_str());
                    let rows = sqlx::query(
                        "UPDATE change_refs SET snapshot = $1 WHERE project_id = $2 AND change_id = $3 AND created_by = $4 AND snapshot = $5",
                    )
                    .bind(&real)
                    .bind(pid)
                    .bind(&cid)
                    .bind(person)
                    .bind(cur_expected)
                    .execute(&mut *c)
                    .await?
                    .rows_affected();
                    if rows != 1 {
                        return if narrowed {
                            Err(sync::agent_refusal(sync::NARROWED_WRITE))
                        } else {
                            Err(Error::conflict(format!("change {cid} moved while this request ran; try again")))
                        };
                    }
                } else {
                    let rows = sqlx::query(
                        "INSERT INTO change_refs (project_id, change_id, snapshot, created_by, created_at) VALUES ($1, $2, $3, $4, $5) \
                         ON CONFLICT (project_id, change_id) DO NOTHING",
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
                        return if narrowed {
                            Err(sync::agent_refusal(sync::NARROWED_WRITE))
                        } else {
                            Err(Error::not_found(format!("no change {cid} of yours")))
                        };
                    }
                }
            } else {
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
            // Delivered at commit, to every server: drop your tips.
            if notify && moved == Some(true) {
                sqlx::query("SELECT pg_notify($1, $2)")
                    .bind(crate::caches::TIPS_CHANNEL)
                    .bind(pid.to_string())
                    .execute(&mut *c)
                    .await?;
            }
            Ok((moved, memos))
        })
    })
    .await?;
    let (r, memos) = r;
    for id in &committed {
        hub.caches.put_committed(pid, id);
    }
    for (k, real, mine) in memos {
        if let (Ok(real), Ok(mine)) = (ObjectId::from_hex(&real), ObjectId::from_hex(&mine)) {
            hub.caches.put_memo(pid, &k, &real, &mine);
        }
    }
    if r == Some(true) {
        hub.caches.tips_changed(pid);
    }
    Ok(r)
}

/// The real tip of `branch`, if it exists.
async fn tip(hub: &Hub, project: i64, branch: &str) -> Result<Option<ObjectId>> {
    let t: Option<String> =
        sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = $2 AND hidden_for_embargo IS NULL")
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
async fn resolve_base(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, mut base: ObjectId, onto: Option<&str>, landing: bool) -> Result<ObjectId> {
    if base == ObjectId([0; 32]) {
        let branch = onto.unwrap_or(&project.default_branch);
        if let Some(tested) = crate::ci::tested_for(hub, project, viewer, branch).await? {
            base = tested;
        } else if let Some(t) = tip(hub, project.id, branch).await? {
            if crate::embargo::is_withheld_from_viewer(hub, project, viewer, &t).await? {
                return Err(Error::not_found(format!("no branch '{branch}' that you can see")));
            }
            base = sync::projected(hub, project, viewer, t).await?;
        } else {
            return Err(Error::not_found(format!("no branch '{branch}' that you can see")));
        }
    }
    // As a push resolves its parents (one function: BUG-1520): the branch
    // the change goes to first, then the default branch.
    let branches: Vec<&str> = onto.into_iter().collect();
    match sync::resolve_for(hub, project, viewer, &base, &branches, landing).await? {
        Some(r) => Ok(r),
        None => Err(Error::not_found(format!("no snapshot {} that you can see", base.short()))),
    }
}

/// Resolve an existing `change_id` (`change_refs`) for a revision rewrite. An
/// agent session may resolve or rewrite a change only when its existing
/// snapshot lies within the session's narrowing (`within_narrowing`) and
/// touches no access or review file (`decides_access`); outside its narrowing,
/// the refusal is identical whether or not the change exists (BUG-1784).
async fn resolve_change(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    person_id: i64,
    cid: ChangeId,
) -> Result<(ChangeId, Vec<ObjectId>)> {
    let row: Option<(String, i64)> =
        sqlx::query_as("SELECT snapshot, created_by FROM change_refs WHERE project_id = $1 AND change_id = $2")
            .bind(project.id)
            .bind(cid.to_string())
            .fetch_optional(&hub.db)
            .await?;
    let narrowed = viewer.only.is_some();
    let Some((s_hex, by)) = row else {
        return if narrowed {
            Err(sync::agent_refusal(sync::NARROWED_WRITE))
        } else {
            Err(Error::not_found(format!("no change {cid} of yours")))
        };
    };
    if by != person_id {
        return if narrowed {
            Err(sync::agent_refusal(sync::NARROWED_WRITE))
        } else {
            Err(Error::not_found(format!("no change {cid} of yours")))
        };
    }
    let prev = ObjectId::from_hex(&s_hex).map_err(|e| Error::Other(e.into()))?;
    if crate::embargo::is_withheld_from_viewer(hub, project, viewer, &prev).await? {
        return if narrowed {
            Err(sync::agent_refusal(sync::NARROWED_WRITE))
        } else {
            Err(Error::not_found(format!("no change {cid} of yours")))
        };
    }
    if viewer.agent || narrowed {
        let v = viewer.clone();
        sync::blocking(hub, project.id, move |src| {
            let s = src.snapshot(&prev)?;
            let policy = AccessPolicy::default();
            let everything = veil_core::hub::access::View::admin(&policy);
            let parent_trees: Vec<Option<ObjectId>> = if s.parents.is_empty() {
                vec![None]
            } else {
                s.parents
                    .iter()
                    .map(|p| Ok(Some(src.snapshot(p)?.tree)))
                    .collect::<Result<Vec<_>>>()?
            };
            for pt in parent_trees {
                let mut diff = veil_core::hub::project::Graft::new(src, &everything);
                diff.root(s.tree, pt)?;
                if diff.changes.iter().any(|c| !v.within_narrowing(&c.path)) {
                    return Err(sync::agent_refusal(sync::NARROWED_WRITE));
                }
                if v.agent {
                    if let Some(c) = diff.changes.iter().find(|c| veil_core::hub::agent::decides_access(&c.path)) {
                        return Err(sync::agent_refusal(&format!(
                            "an agent session never changes '{}', which decides access or review",
                            c.path
                        )));
                    }
                }
            }
            Ok(())
        })
        .await?;
    }
    Ok((cid, vec![prev]))
}

/// Most of the caller's own unlanded changes a change may be stacked on
/// for an `expected` move.
const MAX_STACK: usize = 64;

/// For an `expected` move whose `base` is not the tip `t` (as the caller
/// sees it): the caller's own unlanded changes from `t` up to `base`
/// (real, oldest first), and the real snapshot the oldest is on. `Err`
/// (a reason to reject the move) when `base` is not such a stack on `t`,
/// or one of the changes writes a path the caller may no longer write (so
/// that making them again through the caller's view, [`restack`], never
/// loses an edit). Decided on what the caller sees only (their change
/// refs, their projections, their access), never on what came between in
/// the real history (BUG-1054).
async fn stack_on(hub: &Arc<Hub>, who: &Arc<Who>, person: i64, base_real: ObjectId, t: ObjectId) -> Result<std::result::Result<(Vec<ObjectId>, ObjectId), String>> {
    let mut chain = Vec::new();
    let mut r = base_real;
    for _ in 0..=MAX_STACK {
        if sync::projected(hub, &who.project, &who.viewer, r).await? == t {
            chain.reverse();
            let (w, c2) = (who.clone(), chain.clone());
            let blocked = sync::blocking(hub, who.project.id, move |src| {
                let view = w.project.view(&w.viewer);
                let policy = AccessPolicy::default();
                let everything = veil_core::hub::access::View::admin(&policy);
                for s in &c2 {
                    let s = src.snapshot(s)?;
                    let mut diff = veil_core::hub::project::Graft::new(src, &everything);
                    diff.root(s.tree, Some(src.snapshot(&s.parents[0])?.tree))?;
                    if let Some(c) = diff.changes.iter().find(|c| !view.write(&c.path)) {
                        // A narrowed session is told nothing of what lies
                        // outside its paths (BUG-1378).
                        if !view.within_narrowing(&c.path) {
                            return Ok(Some(sync::NARROWED_MOVE.to_string()));
                        }
                        return Ok(Some(format!("a change of yours below this one writes '{}', which you may no longer write", c.path)));
                    }
                }
                Ok(None)
            })
            .await?;
            return Ok(match blocked {
                Some(why) => Err(why),
                None => Ok((chain, r)),
            });
        }
        let mine: Option<String> = sqlx::query_scalar("SELECT change_id FROM change_refs WHERE project_id = $1 AND snapshot = $2 AND created_by = $3")
            .bind(who.project.id)
            .bind(r.hex())
            .bind(person)
            .fetch_optional(&hub.db)
            .await?;
        if mine.is_none() || chain.len() == MAX_STACK {
            return Ok(Err(NOT_ON_TIP.into()));
        }
        chain.push(r);
        let s = r;
        r = sync::blocking(hub, who.project.id, move |src| Ok(src.snapshot(&s)?.parents[0])).await?;
    }
    Ok(Err(NOT_ON_TIP.into()))
}

const NOT_ON_TIP: &str = "not a fast-forward: the change is not on the branch's tip, or on your own unlanded changes on it";

/// `POST /v1/projects/{p}/changes`.
pub async fn create(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, caller: &Caller, req: ChangeRequest) -> Result<ChangeResult> {
    create_with(hub, project, viewer, caller, req, None).await
}

/// [`create`]; with `land`, the change (made on `base`, never moving a
/// branch) also joins the landing queue in its one commit (`landing`).
pub(crate) async fn create_with(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    caller: &Caller,
    req: ChangeRequest,
    mut land: Option<(crate::landing::Submitter, crate::landing::Queued)>,
) -> Result<ChangeResult> {
    let person = caller.not_runner()?.clone();
    if land.is_some() && req.onto.is_some() {
        return Err(bad("a landing names its branch once (`onto` of the landing)"));
    }
    if !project.participant(viewer) {
        return Err(Error::forbidden("you are not in this project"));
    }
    let mut pending = HashMap::new();
    let edits = validate(&req, &mut pending)?;
    // A narrowed session edits nothing outside its paths, and learns nothing
    // there: not even whether a path exists (BUG-1392).
    if req.edits.iter().any(|e| !viewer.within_narrowing(&e.path)) {
        return Err(sync::agent_refusal(sync::NARROWED_WRITE));
    }
    let st = &hub.landing.stats;
    let t_c = std::time::Instant::now();
    let gc_epoch = crate::pack_gc::read_gc_epoch(hub, project.id).await?;
    // Uploads are staged (S28): read into memory with what the change makes,
    // stored only once every check passed (BUG-930).
    // Held decoded under the server-wide bound while the commit runs
    // (BUG-1156).
    let (uploaded, staged, _held) = sync::take_uploads(hub, project.id, person.id, &req.receipts).await?;
    pending.extend(staged);
    let onto = req.onto.clone();
    let mut who = Arc::new(Who {
        project: project.clone(),
        viewer: viewer.clone(),
    });
    let mut cur = match &onto {
        Some(o) => Some(tip(hub, project.id, &o.branch).await?.ok_or_else(|| bad(format!("no branch '{}'", o.branch)))?),
        None => None,
    };
    let target = onto.as_ref().map(|o| o.branch.clone()).or_else(|| land.as_ref().map(|(_, q)| q.branch.clone()));
    let base_real = resolve_base(hub, project, viewer, req.base, target.as_deref(), land.is_some()).await?;
    let base_eids = crate::embargo::active_embargoes_of(hub, project.id, &[base_real], &HashMap::new(), None).await?;
    for eid in &base_eids {
        if !crate::embargo::can_see(hub, project, viewer, eid).await? {
            return Err(Error::not_found(format!("no snapshot {} that you can see", req.base.short())));
        }
    }
    if base_eids.len() > 1 {
        return Err(bad("a change cannot build on multiple active embargoes"));
    }
    let base_embargo: Option<String> = base_eids.into_iter().next();
    if let (Some(eid), Some((_, q))) = (&base_embargo, &land) {
        if veil_core::embargo::embargo_id_of_branch(&q.branch) != Some(eid.as_str()) {
            return Err(bad(format!("cannot land work built on unreleased embargo {eid} onto '{}'", q.branch)));
        }
    }
    crate::landing::prof(&st.p_c_base_us, t_c);
    let base_proj = if req.base == ObjectId([0; 32]) {
        sync::projected(hub, project, viewer, base_real).await?
    } else {
        req.base
    };
    // A new revision of one of the caller's own changes, or a new change.
    let (change_id, predecessors) = match req.change_id {
        Some(cid) => resolve_change(hub, project, viewer, person.id, cid).await?,
        None => (ChangeId::random(), vec![]),
    };
    let mut ppredecessors = Vec::new();
    for p in &predecessors {
        ppredecessors.push(sync::projected(hub, project, viewer, *p).await?);
    }
    let base_tree = {
        let b = base_real;
        let base = sync::blocking(hub, project.id, move |src| Ok(src.snapshot(&b)?)).await?;
        // Attempts never enter ancestry (`Snapshot::abandoned`).
        if base.abandoned.is_some() {
            return Err(bad("the base is an abandoned attempt: nothing is built on it"));
        }
        base.tree
    };
    let plan = Arc::new(Plan {
        uploaded,
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
        agent: caller.agent().map(|a| a.attribution.clone()),
    });

    // The branch move, when asked: refused at once if the tip is not what
    // the caller expected, or the change is not on it (directly, or on a
    // stack of the caller's own unlanded changes on it); the change is
    // still made and kept on its ref. All judged on the caller's view.
    let mut rejected: Option<String> = None;
    if let (Some(eid), Some(o)) = (&base_embargo, &onto) {
        if veil_core::embargo::embargo_id_of_branch(&o.branch) != Some(eid.as_str()) {
            rejected = Some(format!("cannot put work built on unreleased embargo {eid} onto '{}'", o.branch));
        }
    }
    // Only the landing service moves a protected branch (S17).
    if let (None, Some(o)) = (&rejected, &onto) {
        let default_tip = tip(hub, project.id, &project.default_branch).await?;
        let protected = sync::blocking(hub, project.id, move |src| crate::landing::protected(src, default_tip)).await?;
        if protected.contains(&o.branch) {
            rejected = Some(format!("'{}' is protected: land the change instead (`vl land`, `POST …/land`)", o.branch));
        }
    }
    let (mut parent, mut pparent) = (base_real, base_proj);
    let mut restacked = Vec::new();
    if let (None, Some(o), Some(c)) = (&rejected, &onto, cur) {
        if let Expected::Tip(t) = o.expected {
            if sync::projected(hub, project, viewer, c).await? != t {
                rejected = Some("the branch has moved since you last saw it".into());
            } else if c != base_real {
                match stack_on(hub, &who, person.id, base_real, t).await? {
                    Err(why) => rejected = Some(why),
                    // The changes it is on were made on the tip itself.
                    Ok((_, fork)) if fork == c => {}
                    // Only changes the caller cannot see came between: make
                    // theirs again on the tip.
                    Ok((chain, _)) => {
                        let (rows, objects) = restack(hub, &who, chain, c).await?;
                        // Stored now: the change is built on them.
                        sync::put_all(hub, project.id, objects).await?;
                        parent = rows.last().map(|r| r.0).unwrap_or(c);
                        restacked = rows;
                    }
                }
            }
        }
    }
    let rebase = onto.as_ref().is_some_and(|o| o.expected == Expected::Rebase);
    let mut rebased = 0u32;
    let mut attempts = 0u32;
    let (built, moved) = loop {
        attempts += 1;
        if let (true, None, Some(c)) = (rebase, &rejected, cur) {
            if c != parent {
                let (bt, b, w) = (plan.base_tree, plan.clone(), who.clone());
                let ok = sync::blocking(hub, project.id, move |src| {
                    let ct = src.snapshot(&c)?.tree;
                    let view = w.project.view(&w.viewer);
                    unchanged(&mut Projector::new(src, &view), &bt, &ct, &b.edits)
                })
                .await?;
                match ok {
                    true => {
                        parent = c;
                        pparent = sync::projected(hub, &who.project, &who.viewer, c).await?;
                        rebased += 1;
                    }
                    false => rejected = Some("the branch moved, and a path this change edits changed there since its base".into()),
                }
            }
        }
        let t_b = std::time::Instant::now();
        let built = build(hub, &plan, &who, parent, pparent).await?;
        crate::landing::prof(&st.p_c_build_us, t_b);
        // The one rule of every tip an agent session sets (`sync::agent_tip`):
        // for a narrowed one, anything outside its paths first (a stack of
        // its person's own changes may hold more); then the files that decide
        // access or review, whoever changed them. Before every other answer.
        let tip_refused = match (&onto, cur, &rejected) {
            (Some(o), Some(c), None) => {
                // What the change made is stored only after: read it from here.
                let made: HashMap<ObjectId, Bytes> = built.store.iter().cloned().collect();
                sync::agent_tip_of(hub, &who.project, &who.viewer, &o.branch, Some(c), built.real, made).await?
            }
            _ => None,
        };
        // Stored before anything reads them (a landing's stack may).
        let t_p = std::time::Instant::now();
        sync::put_all(hub, project.id, built.store.clone()).await?;
        crate::landing::prof(&st.p_c_put_us, t_p);
        let t_s = std::time::Instant::now();
        // A landing of edits: the stack is the submitter's history from the
        // branch up to this one, as for a pushed snapshot (BUG-1112).
        if let Some((_, q)) = land.as_mut() {
            let fresh = HashMap::from([(built.real, (vec![parent], person.id))]);
            let judged = match crate::landing::stack(hub, &who.project, &who.viewer, &q.branch, built.real, &fresh, None).await? {
                Ok(j) if j.branch => j,
                // No branch: the service answers so (unless `agent_stack`
                // refuses creating the default branch first).
                Ok(j) => crate::landing::Judged {
                    stack: vec![crate::landing::Entry::plain(built.real, parent)],
                    ..j
                },
                Err(why) => return Err(bad(why)),
            };
            // S11's agent rule (`agent_stack`) on the stack's edits before the
            // landing is queued (BUG-1636).
            crate::landing::agent_stack(hub, &who.project, &who.viewer, &q.branch, &judged, built.real, false, None).await?;
            *q.skipped.lock().unwrap() = judged.skipped;
            (q.stack, q.lineage) = (judged.stack, judged.lineage);
            if q.stack.is_empty() {
                let skipped = q.skipped.lock().unwrap().clone();
                let mut msg = "nothing to land: this change is on the branch already".to_string();
                let named = crate::landing::skipped_warnings(hub, project.id, &q.branch, &skipped).await?;
                if !named.is_empty() {
                    msg = format!("{msg}; {}", named.join("; "));
                }
                return Err(bad(msg));
            }
            let default_tip = tip(hub, project.id, &project.default_branch).await?;
            let protected = sync::blocking(hub, project.id, move |src| crate::landing::protected(src, default_tip)).await?;
            let claim = crate::prs::check_landing_review(
                hub,
                &who.project,
                &who.viewer,
                &q.branch,
                &q.stack,
                None,
                protected.contains(&q.branch),
            )
            .await?;
            if let (Some(first), Some(claim)) = (q.stack.first_mut(), claim) {
                first.review = Some(claim);
            }
        }
        crate::landing::prof(&st.p_c_stack_us, t_s);
        // The branch rules: a move of the default branch changes them only
        // for an admin, judged against its tip (BUG-1102).
        let rules_moved = match cur {
            Some(c) if plan.default_branch && !who.viewer.admin && rejected.is_none() => {
                let tip = sync::blocking(hub, project.id, move |src| sync::entry_at(src, &src.snapshot(&c)?.tree, crate::landing::rules::RULES_FILE)).await?;
                match (&built.rules, &tip) {
                    (None, None) => false,
                    (Some(a), Some(b)) => !a.same_content(b),
                    _ => true,
                }
            }
            _ => false,
        };
        if let (None, Some(o), Some(c), None) = (&land, &onto, cur, &rejected) {
            if crate::bisect::branch_has_reverted_twice(hub, project.id, &o.branch).await? {
                let stack = [crate::landing::Entry::plain(built.real, c)];
                if let Err(Error::Api { message, .. }) =
                    crate::prs::check_landing_review(hub, &who.project, &who.viewer, &o.branch, &stack, None, false).await
                {
                    rejected = Some(message);
                }
            }
        }
        let mv = match (&onto, cur, &rejected) {
            (Some(_), Some(_), None) if tip_refused.is_some() => {
                rejected = Some(match tip_refused {
                    Some(sync::AgentTip::Narrowed) => sync::NARROWED_MOVE.into(),
                    _ => sync::AGENT_ACCESS_MOVE.into(),
                });
                None
            }
            // A change of who has access moves the default branch only for
            // an admin (the push's rule), never for an agent session
            // (BUG-1377); anyone else's change is kept.
            (Some(_), Some(_), None) if built.accept.is_some() && (!who.viewer.admin || who.viewer.agent) => {
                rejected = Some(match who.viewer.agent {
                    true => "an agent session never changes who has access (the default branch's .veilpolicy)".into(),
                    false => "only admins may change who has access (the default branch's .veilpolicy)".into(),
                });
                None
            }
            (Some(_), Some(_), None) if rules_moved => {
                rejected = Some("only admins may change the branch rules (.veilrules)".into());
                None
            }
            (Some(o), Some(c), None) => match if c != parent || attempts > 1 {
                // An API commit always adds to the branch: landed work it
                // stands on is no write on a branch other than the default.
                let landed = match plan.default_branch {
                    true => None,
                    false => tip(hub, project.id, &project.default_branch).await?,
                };
                sync::branch_move_write_refusal(hub, &who.project, &who.viewer, Some(c), built.real, landed, &mut sync::PushRows::default(), None).await?
            } else {
                None
            } {
                Some(msg) => {
                    rejected = Some(msg);
                    None
                }
                None => Some(Move {
                    branch: o.branch.clone(),
                    cur: c,
                    below: parent,
                    // A tip that moves away and back must not keep it trying.
                    keep_on_loss: !rebase || rebased >= MAX_REBASES || attempts > MAX_REBASES,
                }),
            },
            _ => None,
        };
        let t_m = std::time::Instant::now();
        let committed = commit(hub, &plan, &who, &built, &restacked, person.id, gc_epoch, mv, land.as_ref(), base_embargo.as_deref()).await;
        crate::landing::prof(&st.p_c_commit_us, t_m);
        match committed {
            Ok(m) => break (built, m),
            // The tip moved during the request: try again on the new one,
            // with the access as it is now (BUG-1051).
            Err(Error::Api { code: "conflict", .. }) => {
                cur = tip(hub, project.id, &onto.as_ref().expect("a move").branch).await?;
                if cur.is_none() {
                    rejected = Some("the branch was deleted".into());
                }
                // The access now: epochs read again, then the caches
                // checked against them (S4), so a removal, a bar or a
                // policy change since the request began applies here.
                let now = crate::auth::Caller {
                    person: caller.person.clone(),
                    epochs: crate::caches::read_epochs(&hub.db, caller.person.as_ref().map_or(0, |p| p.id), Some(project.id)).await?,
                };
                let (project, viewer) = crate::perm::open(hub, &project.name, &now).await?;
                if !project.participant(&viewer) {
                    return Err(Error::forbidden("you are not in this project"));
                }
                who = Arc::new(Who { project, viewer });
            }
            Err(e) => return Err(e),
        }
    };
    let mut warnings = Vec::new();
    let branch = match onto {
        None => None,
        Some(o) => {
            let landed = moved == Some(true);
            if landed {
                // Derived history data for the branch, in the background,
                // as after a push (S12).
                crate::derive::landed(hub, project.id, vec![o.branch.clone()]);
            }
            if moved == Some(false) {
                rejected = Some("the branch moved during the request".into());
            }
            let tip_seen = match landed {
                true => Some(built.mine),
                false => match tip(hub, project.id, &o.branch).await? {
                    Some(t) => Some(sync::projected(hub, &who.project, &who.viewer, t).await?),
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
