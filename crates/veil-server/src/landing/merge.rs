//! Content merges and conflict reports for the landing service
//! (milestone S18; `docs/HUB.md` §13.30;
//! `docs/design/server/phase-4-agent-scale.md` §4.3, §5).
//!
//! When a change's edited paths changed on the branch since its base
//! ([`super::edits::fast_path`] is `Some`), the landing batch merges it by
//! content onto the running tip, in the queue's order (`merge_onto`):
//!
//! * A change that merges cleanly onto what landed before it lands; one
//!   that does not is answered `conflict`, never one that merges cleanly
//!   (BUG-1956: until then a merge was made by a worker off the batch and
//!   the change queued again at the back, at most three times, and more
//!   than about four clean overlaps of one file at once were answered
//!   `conflict`).
//! * A path is merged (`veil_core::textmerge::merge`, or
//!   `veil_core::attributes::union_merge` per `.veilattributes`) only when
//!   both sides are plain-text `Public` files within
//!   [`MAX_MERGE_FILE_BYTES`] that the submitter may read and write, and
//!   what changed it on the branch is visible to them whole.
//! * **Guarantee 1:** A merged change lands only after the push's checks
//!   (`sync::complete`) on its new parent, as its submitter is now, as
//!   every landing that needs them (`service::recheck`).
//! * **Guarantee 2:** When a merge cannot be done cleanly, the conflict
//!   report (`onto`, `base`, `paths`, `conflicts`, `landed_since`) names
//!   nothing hidden from the submitter; any conflict involving a path the
//!   submitter cannot read is reported solely as [`HIDDEN_CONFLICT`]
//!   (`"conflicts with changes you can't see"`), never by path.
//! * Rows a server before BUG-1956's fix left `merging` are queued again
//!   when their claim expires (`landing::resume`, BUG-1883).

use bytes::Bytes;
use veil_core::{
    attributes::{AttrSource, Attrs, MergeAttr, ATTRIBUTES_FILE, MAX_FILE},
    hub::{
        access::View,
        land::{ConflictPath, LandResult, LandState},
        project::Change,
    },
    object::{EntryKind, Object, TreeEntry, Visibility},
    policy::POLICY_FILE,
    secrets::looks_binary,
    vpath::VPath,
    ChangeId, ObjectId,
};

use super::{edits, rules::RULES_FILE};
use crate::{
    error::Result,
    sync::{self, Source},
};

/// Largest plain-text file (in bytes) that the server content-merges; above
/// this, an overlapping edit is answered `conflict` so the client merges it.
pub const MAX_MERGE_FILE_BYTES: u64 = 1 << 20;

/// The sole message when a conflict involves a path the receiver cannot read.
pub const HIDDEN_CONFLICT: &str = "conflicts with changes you can't see";

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
    pub too_large: bool,
    pub merges: u32,
    pub change_id: Option<ChangeId>,
}

impl ConflictReport {
    pub fn into_result(self, ticket: &str, branch: &str) -> LandResult {
        let message = if self.hidden {
            Some(HIDDEN_CONFLICT.to_string())
        } else if self.too_large {
            Some(format!(
                "a path this change edits changed on '{branch}' since its base and is too large to merge on the server (over {} MiB): get the branch's new tip, redo the change on it, and land it again",
                MAX_MERGE_FILE_BYTES >> 20
            ))
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
        if !self.view.read(&rel) {
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
    // What the branch changed since the base, where the change edits: read
    // per path (`edits::touching`), never the branch's whole edit set
    // (every folder anyone landed in since, BUG-1955).
    let main_touching = |path: &str| edits::touching(src, chain_tree, parent_tree, path);
    let mut paths = Vec::new();
    let mut conflicts = Vec::new();
    let mut overlapping_edits = Vec::new();
    let mut hidden = false;
    let mut too_large = false;
    let can_see = |p: &str| view.read(p) && view.within_narrowing(p);

    for c in set {
        if edits::fast_path(src, parent_tree, chain_tree, std::slice::from_ref(c))?.is_none() {
            continue;
        }
        overlapping_edits.push(c.clone());
        if !can_see(&c.path) {
            hidden = true;
            continue;
        }
        if main_touching(&c.path)?.iter().any(|m| !can_see(&m.path)) {
            hidden = true;
            continue;
        }
        let be = sync::entry_at(src, &parent_tree, &c.path)?;
        let oe = sync::entry_at(src, &chain_tree, &c.path)?;
        let te = c.new.clone();
        if let (Some(oe), Some(te)) = (&oe, &te) {
            if oe.kind == EntryKind::File
                && te.kind == EntryKind::File
                && oe.visibility == Visibility::Public
                && te.visibility == Visibility::Public
                && be.as_ref().is_none_or(|b| b.kind == EntryKind::File && b.visibility == Visibility::Public)
                && (oe.size > MAX_MERGE_FILE_BYTES
                    || te.size > MAX_MERGE_FILE_BYTES
                    || be.as_ref().is_some_and(|b| b.size > MAX_MERGE_FILE_BYTES))
            {
                too_large = true;
            }
        }
        let leaf_id = |e: Option<TreeEntry>| -> Option<ObjectId> {
            e.filter(|x| x.kind != EntryKind::Dir && x.visibility == Visibility::Public).map(|x| x.id)
        };
        let base_id = leaf_id(be);
        let main_id = leaf_id(oe);
        let yours_id = leaf_id(te);
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
            if !can_see(&c.path) || main_touching(&c.path)?.iter().any(|m| !can_see(&m.path)) {
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
        too_large: too_large && !hidden,
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
        // Did the step touch an overlapping edit? Asked first: it reads the
        // edits' own folders, and few steps did; the step's whole edit set
        // only then (BUG-1955: 256 edit sets for every conflict).
        if !overlapping.is_empty() && edits::fast_path(src, ps.tree, tree, overlapping)?.is_none() {
            continue;
        }
        let step_edits = edits::edit_set(src, tree, ps.tree)?;
        if step_edits.iter().any(|c| view.read(&c.path) && view.within_narrowing(&c.path)) {
            out.push(id);
        }
    }
    Ok(out)
}

fn can_merge_entries(
    attrs: &Attrs<'_>,
    path: &str,
    be: Option<&TreeEntry>,
    oe: &TreeEntry,
    te: &TreeEntry,
) -> bool {
    if oe.kind != EntryKind::File || te.kind != EntryKind::File {
        return false;
    }
    if oe.visibility != Visibility::Public || te.visibility != Visibility::Public {
        return false;
    }
    if oe.size > MAX_MERGE_FILE_BYTES || te.size > MAX_MERGE_FILE_BYTES {
        return false;
    }
    if let Some(b) = be {
        if b.kind != EntryKind::File || b.visibility != Visibility::Public || b.size > MAX_MERGE_FILE_BYTES {
            return false;
        }
    }
    let Ok(vp) = VPath::new(path) else { return false };
    let how = attrs.for_path(&vp).merge;
    if how == MergeAttr::Binary {
        return false;
    }
    if oe.id == te.id {
        return true;
    }
    if how == MergeAttr::Union {
        return true;
    }
    // Without a common base file, two different newly added files conflict
    // unless `merge=union` is set.
    be.is_some()
}

/// A change merged onto a tip by [`merge_onto`].
pub(super) struct Merged {
    /// Its edits onto the tip: the merged ones where the tip changed.
    pub set: Vec<Change>,
    /// The merged files' blobs.
    pub blobs: Vec<(ObjectId, Bytes)>,
    /// The bytes of the three versions of the files merged.
    pub read: usize,
}

/// Merge the edits `set` of a change, made on `parent_tree`, onto the tree
/// `chain_tree` that changed some of their paths since: `None` when it
/// cannot be merged cleanly (a conflict), which is when it is a merge
/// snapshot (`parents` of more than one), changes what decides access or
/// review, holds a path `view` may not read or write, overlaps a change
/// of the tip's at a path `view` does not see whole, or a path's three
/// versions do not merge cleanly ([`merge_entry_bytes`]).
pub(super) fn merge_onto(
    src: &Source,
    view: &View<'_>,
    parents: usize,
    set: &[Change],
    parent_tree: ObjectId,
    chain_tree: ObjectId,
) -> Result<Option<Merged>> {
    if parents > 1 {
        return Ok(None);
    }
    if set.iter().any(|c| {
        veil_core::hub::agent::decides_access(&c.path)
            || c.path == POLICY_FILE
            || c.path == RULES_FILE
            || !view.read(&c.path)
            || !view.write(&c.path)
    }) {
        return Ok(None);
    }
    let attrs = Attrs::with_source(Box::new(ServerAttrSource { src, tree: chain_tree, view }), None);
    let mut out = Merged { set: Vec::with_capacity(set.len()), blobs: Vec::new(), read: 0 };
    for c in set {
        if edits::fast_path(src, parent_tree, chain_tree, std::slice::from_ref(c))?.is_none() {
            out.set.push(c.clone());
            continue;
        }
        if edits::touching(src, chain_tree, parent_tree, &c.path)?
            .iter()
            .any(|m| !view.read(&m.path) || !view.within_narrowing(&m.path))
        {
            return Ok(None);
        }
        let Some(te) = &c.new else { return Ok(None) };
        let Some(oe) = sync::entry_at(src, &chain_tree, &c.path)? else { return Ok(None) };
        let be = sync::entry_at(src, &parent_tree, &c.path)?;
        out.read += (oe.size + te.size + be.as_ref().map_or(0, |b| b.size)) as usize;
        let Some((merged, blob)) = merge_entry_bytes(src, &attrs, &c.path, be.as_ref(), &oe, te)? else { return Ok(None) };
        out.blobs.extend(blob);
        out.set.push(Change { path: c.path.clone(), old: Some(oe), new: Some(merged) });
    }
    Ok(Some(out))
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
    if !can_merge_entries(attrs, path, be, oe, te) {
        return Ok(None);
    }
    let Ok(vp) = VPath::new(path) else { return Ok(None) };
    let how = attrs.for_path(&vp).merge;
    let read_blob = |e: &TreeEntry| -> Result<Option<Vec<u8>>> {
        Ok(match Object::decode(&src.raw(&e.id)?)? {
            Object::Blob(b) if b.len() as u64 <= MAX_MERGE_FILE_BYTES => Some(b),
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
    let size = merged.len() as u64;
    let raw = Bytes::from(Object::Blob(merged).encode());
    let id = ObjectId::hash(&raw);
    Ok(Some((
        TreeEntry {
            name: oe.name.clone(),
            kind: EntryKind::File,
            id,
            size,
            executable,
            visibility: Visibility::Public,
        },
        Some((id, raw)),
    )))
}
