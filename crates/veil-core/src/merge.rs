//! Three-way tree merge. Works at the tree level (identical subtrees are
//! resolved by id without reading content) and falls back to line-based
//! diff3 for files changed on both sides.
//!
//! Visibility never widens: a file merged from a sealed side stays sealed
//! (ours' sealing if ours is sealed, else theirs'), whichever side "ours"
//! happens to be. Nor does it move: when the two sides are sealed under
//! different scopes, nothing merged is sealed for either; the side that
//! kept the base's scope (else ours) is kept as it is, and the file is a
//! conflict (BUG-123). This matters for auto-rebase, where "ours" is the new
//! (possibly public) parent and "theirs" the (possibly cloaked) child.
//! Conflict markers show the base's version only where its audience is the
//! result's (BUG-126).
//!
//! Trees under an unreleased embargo (see [`crate::embargo`]) stay under it:
//! the result is re-wrapped under the same embargo, with the merge of the
//! inputs' public views as its fallback. Merging them needs the embargo key,
//! and trees under two different unreleased embargoes are never merged
//! (embargoes cannot overlap in Veil 1.0).

use std::{collections::BTreeSet, sync::Arc};

use crate::{
    builder::{verify_sealing, Sealing},
    conflict::{Merge, Term},
    embargo::{overlap_error, public_view, unreleased_wrapper, wrap},
    error::{Result, VeilError},
    id::ObjectId,
    object::{ConflictTerm, EntryKind, Tree, TreeEntry, Visibility},
    secrets::looks_binary,
    store::ObjectStore,
    tree::MAX_TREE_DEPTH,
    vpath::VPath,
};

#[derive(Debug, Clone)]
pub struct MergeOutcome {
    pub tree: ObjectId,
    pub conflicts: Vec<VPath>,
}

/// How conflicts are resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// A real merge: conflicts are recorded, with markers in text files.
    Merge,
    /// Building a virtual merge base: whatever conflicts takes the base's
    /// version (a conflicting text hunk the base's lines), nothing is
    /// recorded. Two later versions that disagree on it then both differ
    /// from the virtual base and conflict.
    VirtualBase,
}

/// Three-way merge of trees. In a repository of format 4 or later, files
/// that do not merge become conflict entries ([`crate::conflict`]); below
/// format 4, and for trees under an unreleased embargo, they get conflict
/// markers in their content, as before.
pub fn merge_trees(store: &ObjectStore, base: Option<ObjectId>, ours: ObjectId, theirs: ObjectId) -> Result<MergeOutcome> {
    let markers = store.format() < crate::object::CONFLICT_REPO_FORMAT;
    merge_trees_in(store, base, ours, theirs, Mode::Merge, markers)
}

/// [`merge_trees`] that writes conflicts as markers in the file whatever
/// the repository format (a merge about to be put under an embargo: sealed
/// trees never hold conflict entries). Conflict entries met on the way are
/// replaced by their marker files.
pub fn merge_trees_with_markers(store: &ObjectStore, base: Option<ObjectId>, ours: ObjectId, theirs: ObjectId) -> Result<MergeOutcome> {
    merge_trees_in(store, base, ours, theirs, Mode::Merge, true)
}

/// The virtual merge base of two merge bases `ours` and `theirs` (whose
/// own merge base is `base`), for a criss-cross merge (see
/// [`crate::repo::Repo::merge_base_tree`]). What the two bases disagree on
/// is left as `base` has it, so neither base's version of it is taken
/// silently (BUG-244). Markers in the virtual base, as Git writes them,
/// would line up with one side's resolution in a line diff and let it win.
pub fn virtual_merge_base(store: &ObjectStore, base: Option<ObjectId>, ours: ObjectId, theirs: ObjectId) -> Result<ObjectId> {
    let markers = store.format() < crate::object::CONFLICT_REPO_FORMAT;
    Ok(merge_trees_in(store, base, ours, theirs, Mode::VirtualBase, markers)?.tree)
}

fn merge_trees_in(store: &ObjectStore, base: Option<ObjectId>, ours: ObjectId, theirs: ObjectId, mode: Mode, markers: bool) -> Result<MergeOutcome> {
    if ours == theirs || Some(theirs) == base {
        return Ok(MergeOutcome { tree: ours, conflicts: vec![] });
    }
    if Some(ours) == base {
        return Ok(MergeOutcome { tree: theirs, conflicts: vec![] });
    }
    let mut wrapped: Option<crate::embargo::EmbargoWrapper> = None;
    for id in [Some(ours), Some(theirs), base].into_iter().flatten() {
        if let Some(w) = unreleased_wrapper(store, &id)? {
            if !store.keys.has(&w.key_label()) {
                return Err(VeilError::Policy(format!(
                    "cannot merge: part of this history is under unreleased embargo {} and you do not hold its key",
                    w.embargo
                )));
            }
            // Embargoes never overlap (Veil 1.0): combining two lines under
            // different unreleased embargoes would nest one inside the other.
            match &wrapped {
                Some(first) if first.embargo != w.embargo => return Err(overlap_error(&first.embargo, &w.embargo)),
                Some(_) => {}
                None => wrapped = Some(w),
            }
        }
    }
    // Trees under an embargo never hold conflict entries.
    let markers = markers || wrapped.is_some();
    let full = merge_resolved(store, base, ours, theirs, mode, markers)?;
    let Some(w) = wrapped else {
        return Ok(full);
    };
    // What readers without the key see: the same merge of what they see.
    let pv = |id: ObjectId| public_view(store, &id);
    let (pb, po, pt) = (base.map(pv).transpose()?, pv(ours)?, pv(theirs)?);
    let fallback = match merge_resolved(store, pb, po, pt, mode, markers) {
        Ok(m) => m.tree,
        Err(_) => po,
    };
    Ok(MergeOutcome {
        tree: wrap(store, &w.embargo, &full.tree, &fallback)?,
        conflicts: full.conflicts,
    })
}

fn merge_resolved(store: &ObjectStore, base: Option<ObjectId>, ours: ObjectId, theirs: ObjectId, mode: Mode, markers: bool) -> Result<MergeOutcome> {
    if ours == theirs || Some(theirs) == base {
        return Ok(MergeOutcome { tree: ours, conflicts: vec![] });
    }
    if Some(ours) == base {
        return Ok(MergeOutcome { tree: theirs, conflicts: vec![] });
    }
    let b = base.map(|id| store.tree(&id)).transpose()?;
    let o = store.tree(&ours)?;
    let t = store.tree(&theirs)?;
    let mut conflicts = Vec::new();
    let tree = match merge_dir(store, b, Some((o, ours)), Some((t, theirs)), mode, markers, &mut conflicts)? {
        Some(id) => id,
        None => store.empty_tree()?,
    };
    Ok(MergeOutcome { tree, conflicts })
}

fn same(a: Option<&TreeEntry>, b: Option<&TreeEntry>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => x.same_content(y),
        _ => false,
    }
}

fn subtree(store: &ObjectStore, e: Option<&TreeEntry>) -> Result<Option<(Arc<Tree>, ObjectId)>> {
    match e {
        Some(e) if e.kind == EntryKind::Dir => Ok(Some((store.tree(&e.id)?, e.id))),
        _ => Ok(None),
    }
}

fn read_for_merge(store: &ObjectStore, e: &TreeEntry, path: &VPath) -> Result<Vec<u8>> {
    // A cloaked entry's fallback is its last public version, not its
    // content: merging that would silently revert the sealed edit.
    let read = match e.visibility {
        Visibility::Cloaked { .. } => store.read_blob(&e.id),
        _ => store.read_entry(e),
    };
    read.map_err(|err| match err {
        VeilError::Redacted { scope } => VeilError::Policy(format!(
            "cannot merge {path}: it is cloaked under scope '{scope}' and you do not hold the key"
        )),
        other => other,
    })
}

/// One directory being merged.
struct MergeFrame {
    dir: VPath,
    b: Option<Arc<Tree>>,
    o: Option<(Arc<Tree>, ObjectId)>,
    t: Option<(Arc<Tree>, ObjectId)>,
    names: Vec<String>,
    next: usize,
    out: Tree,
    /// Name of the entry whose subdirectory is being merged on top of this
    /// frame.
    waiting: Option<String>,
}

impl MergeFrame {
    fn new(dir: VPath, b: Option<Arc<Tree>>, o: Option<(Arc<Tree>, ObjectId)>, t: Option<(Arc<Tree>, ObjectId)>) -> Self {
        let mut names = BTreeSet::new();
        for tree in [b.as_deref(), o.as_ref().map(|x| &*x.0), t.as_ref().map(|x| &*x.0)].into_iter().flatten() {
            names.extend(tree.entries.iter().map(|e| e.name.clone()));
        }
        MergeFrame {
            dir,
            b,
            o,
            t,
            names: names.into_iter().collect(),
            next: 0,
            out: Tree::default(),
            waiting: None,
        }
    }

    /// Store the merged directory. A result equal to one side reuses that
    /// side's id (no re-encoding, so a format-1 tree keeps its id).
    fn finish(self, store: &ObjectStore) -> Result<Option<ObjectId>> {
        if self.out.is_empty() {
            return Ok(None);
        }
        for (tree, id) in [&self.o, &self.t].into_iter().flatten() {
            if **tree == self.out {
                return Ok(Some(*id));
            }
        }
        Ok(Some(store.put_tree(&self.out)?))
    }
}

/// Three-way merge of directories. Iterative: tree depth comes from
/// `.veil/` and remotes and is not trusted.
fn merge_dir(
    store: &ObjectStore,
    b: Option<Arc<Tree>>,
    o: Option<(Arc<Tree>, ObjectId)>,
    t: Option<(Arc<Tree>, ObjectId)>,
    mode: Mode,
    markers: bool,
    conflicts: &mut Vec<VPath>,
) -> Result<Option<ObjectId>> {
    let mut stack = vec![MergeFrame::new(VPath::root(), b, o, t)];
    let mut result: Option<Option<ObjectId>> = None;
    loop {
        let depth = stack.len();
        let f = stack.last_mut().expect("stack is never empty here");
        if let Some(name) = f.waiting.take() {
            if let Some(id) = result.take().expect("a finished subdirectory") {
                f.out.insert(TreeEntry::dir(&name, id));
            }
        }
        let Some(name) = f.names.get(f.next).cloned() else {
            let done = stack.pop().expect("checked");
            let id = done.finish(store)?;
            if stack.is_empty() {
                return Ok(id);
            }
            result = Some(id);
            continue;
        };
        f.next += 1;
        let path = f.dir.join(&name);
        let mut be = f.b.as_ref().and_then(|x| x.get(&name)).cloned();
        let mut oe = f.o.as_ref().and_then(|x| x.0.get(&name)).cloned();
        let mut te = f.t.as_ref().and_then(|x| x.0.get(&name)).cloned();
        if !markers {
            // A copy of a conflict as a public reader sees it (the Git
            // export's marker file, which a Git commit then edits) stands
            // for that conflict, so the edit applies to the conflict.
            for side in [&oe, &te] {
                if let (Some(b), Some(c)) = (&be, side) {
                    if b.kind == EntryKind::File && c.kind == EntryKind::Conflict && crate::conflict::publicly_renders_as(store, c, b)? {
                        be = Some(TreeEntry {
                            name: b.name.clone(),
                            ..c.clone()
                        });
                        break;
                    }
                }
            }
        }
        if markers && !(same(oe.as_ref(), te.as_ref()) || same(be.as_ref(), te.as_ref()) || same(be.as_ref(), oe.as_ref())) {
            // Where something must be merged, a conflict entry becomes the
            // file of markers a reader sees (no conflict entries here).
            for e in [&mut be, &mut oe, &mut te] {
                if let Some(c) = e.as_ref().filter(|c| c.kind == EntryKind::Conflict) {
                    *e = Some(crate::conflict::as_marker_file(store, c, &path)?);
                }
            }
        }
        let (be, oe, te) = (be.as_ref(), oe.as_ref(), te.as_ref());
        let mut aside = None;
        let pick = if same(oe, te) || same(be, te) {
            oe.cloned()
        } else if same(be, oe) {
            te.cloned()
        } else {
            let kinds: Vec<EntryKind> = [oe, te].into_iter().flatten().map(|e| e.kind).collect();
            // Two directories (or two files) merge as such, whatever the base
            // was: a base of the other kind counts as absent.
            if kinds == [EntryKind::Dir, EntryKind::Dir] {
                if depth >= MAX_TREE_DEPTH {
                    return Err(VeilError::Corrupt(
                        path.to_string(),
                        format!("directory nesting exceeds {MAX_TREE_DEPTH} levels"),
                    ));
                }
                let (bs, os, ts) = (subtree(store, be)?.map(|x| x.0), subtree(store, oe)?, subtree(store, te)?);
                f.waiting = Some(name);
                stack.push(MergeFrame::new(path, bs, os, ts));
                continue;
            } else if !markers && !kinds.contains(&EntryKind::Dir) && (kinds.contains(&EntryKind::Conflict) || mode == Mode::Merge) {
                // Conflicts as data (format 4): files, absent files and
                // conflicts merge algebraically, then by content.
                merge_terms(store, &path, &name, be, oe, te, mode, conflicts)?
            } else if let (Some(oe), Some(te), [EntryKind::File, EntryKind::File]) = (oe, te, kinds.as_slice()) {
                let be = be.filter(|e| e.kind == EntryKind::File);
                Some(merge_file(store, &path, be, oe, te, mode, conflicts)?)
            } else if mode == Mode::VirtualBase {
                // Modify/delete or file/directory: the base's version.
                be.cloned()
            } else if let (Some(oe), Some(te)) = (oe, te) {
                // File/directory conflict (BUG-243): both sides survive. The
                // directory keeps the name; the file moves aside to
                // `<name>~ours` or `<name>~theirs` (the side it came from).
                // Both paths are recorded as conflicted.
                let (dir, file, side) = if oe.kind == EntryKind::Dir {
                    (oe, te, "theirs")
                } else {
                    (te, oe, "ours")
                };
                let moved = aside_name(f, &name, side);
                conflicts.push(path.clone());
                conflicts.push(f.dir.join(&moved));
                aside = Some(TreeEntry {
                    name: moved,
                    ..file.clone()
                });
                Some(dir.clone())
            } else {
                // modify/delete conflict: keep the modified side and flag it.
                conflicts.push(path.clone());
                oe.or(te).cloned()
            }
        };
        for e in pick.into_iter().chain(aside) {
            f.out.insert(e);
        }
    }
}

/// Merge the versions at `path` as a [`Merge`] (repository format 4):
/// each input may be a file, a conflict or nothing (a directory in the base
/// counts as nothing). Flattened and simplified first, so a conflict whose
/// change the other side already holds resolves, then merged by content
/// ([`resolve_by_content`]); what still conflicts is stored as a conflict
/// entry and reported in `conflicts`. In a virtual merge base, what
/// conflicts takes the base's version instead (nothing is recorded).
#[allow(clippy::too_many_arguments)]
fn merge_terms(
    store: &ObjectStore,
    path: &VPath,
    name: &str,
    be: Option<&TreeEntry>,
    oe: Option<&TreeEntry>,
    te: Option<&TreeEntry>,
    mode: Mode,
    conflicts: &mut Vec<VPath>,
) -> Result<Option<TreeEntry>> {
    let be = be.filter(|e| e.kind != EntryKind::Dir);
    let m = Merge::three_way(Merge::of_entry(store, be)?, Merge::of_entry(store, oe)?, Merge::of_entry(store, te)?).simplify();
    if let Some(t) = m.trivial() {
        return Ok(t.map(|t| t.entry(name)));
    }
    if let Some(e) = resolve_by_content(store, path, name, &m)? {
        return Ok(Some(e));
    }
    if mode == Mode::VirtualBase {
        return Ok(be.cloned());
    }
    // The versions are recorded as they really are sealed (BUG-103): a
    // forged label is not carried into the conflict.
    let relabel = |t: &Term| -> Result<Term> {
        let Some(t) = t else { return Ok(None) };
        Ok(Some(match verify_sealing(store, &t.entry(name))? {
            Sealing::Relabelled(actual) => ConflictTerm {
                visibility: actual,
                ..t.clone()
            },
            _ => t.clone(),
        }))
    };
    let m = Merge {
        adds: m.adds.iter().map(relabel).collect::<Result<_>>()?,
        removes: m.removes.iter().map(relabel).collect::<Result<_>>()?,
    }
    .simplify();
    if let Some(t) = m.trivial() {
        return Ok(t.map(|t| t.entry(name)));
    }
    conflicts.push(path.clone());
    crate::conflict::entry_for(store, name, m)
}

/// The file `m` merges to by content, if it does: every version present,
/// readable and text, and each further side merging cleanly (diff3) into
/// the result so far against its base. Its audience is the merged
/// audience of the sides, as for any merged file (never wider than either,
/// never moved between scopes). `None`: a real conflict.
fn resolve_by_content(store: &ObjectStore, path: &VPath, name: &str, m: &Merge) -> Result<Option<TreeEntry>> {
    if m.adds.iter().any(Option::is_none) || (m.adds.len() > 2 && m.removes.iter().any(Option::is_none)) {
        return Ok(None);
    }
    let entry = |t: &Term| t.as_ref().map(|t| t.entry(name));
    let mut acc = entry(&m.adds[0]).expect("present");
    for i in 1..m.adds.len() {
        let base = entry(&m.removes[i - 1]);
        let side = entry(&m.adds[i]).expect("present");
        let mut found = Vec::new();
        let merged = merge_file_content(store, path, base.as_ref(), &acc, &side, &mut found)?;
        match merged {
            Some(e) if found.is_empty() => acc = e,
            _ => return Ok(None),
        }
    }
    acc.executable = crate::conflict::merged_executable(m);
    Ok(Some(acc))
}

/// diff3 of `ours` and `theirs` where each conflicting hunk takes the
/// `base`'s lines (for a virtual merge base, see [`Mode::VirtualBase`]).
fn merge_keeping_base(base: &[u8], ours: &[u8], theirs: &[u8]) -> Vec<u8> {
    // Markers long enough to appear in none of the inputs, so the
    // conflict blocks can be cut out of the output unambiguously, even
    // where a section without a final newline runs into the next marker.
    let longest_run = [base, ours, theirs]
        .iter()
        .flat_map(|x| x.chunk_by(|a, b| a == b))
        .filter(|run| matches!(run[0], b'<' | b'|' | b'=' | b'>'))
        .map(|run| run.len())
        .max()
        .unwrap_or(0);
    let n = longest_run.max(63) + 1;
    let marker = |c: u8, label: &[u8]| {
        let mut m = vec![c; n];
        m.extend_from_slice(label);
        m.push(b'\n');
        m
    };
    let (start, orig, mid, end) = (marker(b'<', b" ours"), marker(b'|', b" original"), marker(b'=', b""), marker(b'>', b" theirs"));
    let merged = match diffy::MergeOptions::new()
        .set_conflict_marker_length(n)
        .set_conflict_style(diffy::ConflictStyle::Diff3)
        .merge_bytes(base, ours, theirs)
    {
        Ok(m) => return m,
        Err(m) => m,
    };
    let mut out = Vec::with_capacity(merged.len());
    let mut rest = merged.as_slice();
    while let Some(i) = find(rest, &start) {
        out.extend_from_slice(&rest[..i]);
        rest = &rest[i + start.len()..];
        let (Some(o), Some(m)) = (find(rest, &orig), find(rest, &mid)) else { break };
        let base_part = &rest[o + orig.len()..m];
        out.extend_from_slice(base_part);
        rest = &rest[m + mid.len()..];
        let Some(e) = find(rest, &end) else { break };
        rest = &rest[e + end.len()..];
    }
    out.extend_from_slice(rest);
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    memchr::memmem::find(hay, needle)
}

/// A name for the file side of a file/directory conflict on `name`:
/// `<name>~<side>`, or `<name>~<side>~2`, … if that name is taken in any
/// input of the directory being merged or in its result so far.
fn aside_name(f: &MergeFrame, name: &str, side: &str) -> String {
    let taken = |n: &str| {
        f.out.get(n).is_some()
            || f.b.as_ref().is_some_and(|t| t.get(n).is_some())
            || [&f.o, &f.t].into_iter().flatten().any(|(t, _)| t.get(n).is_some())
    };
    let mut candidate = format!("{name}~{side}");
    let mut n = 2;
    while taken(&candidate) {
        candidate = format!("{name}~{side}~{n}");
        n += 1;
    }
    candidate
}

/// The clean content merge of two file versions (format 4): `Some` with
/// the merged file, or `None` (and the path in `conflicts`) when the two
/// do not merge. No markers are ever written.
fn merge_file_content(
    store: &ObjectStore,
    path: &VPath,
    be: Option<&TreeEntry>,
    oe: &TreeEntry,
    te: &TreeEntry,
    conflicts: &mut Vec<VPath>,
) -> Result<Option<TreeEntry>> {
    let base = match be.filter(|e| e.kind == EntryKind::File) {
        Some(e) => read_for_merge(store, e, path)?,
        None => Vec::new(),
    };
    let ours = read_for_merge(store, oe, path)?;
    let theirs = read_for_merge(store, te, path)?;
    let executable = if be.is_some_and(|b| b.executable == oe.executable) {
        te.executable
    } else {
        oe.executable
    };
    if let Some(keep) = audience_clash(store, be, oe, te)? {
        if ours == theirs {
            return Ok(Some(TreeEntry { executable, ..keep }));
        }
        conflicts.push(path.clone());
        return Ok(None);
    }
    if ours == theirs {
        return Ok(Some(TreeEntry { executable, ..oe.clone() }));
    }
    let (oe, te) = (&checked(store, oe, path)?, &checked(store, te, path)?);
    if looks_binary(&ours) || looks_binary(&theirs) || looks_binary(&base) {
        conflicts.push(path.clone());
        return Ok(None);
    }
    let merged = match diffy::merge_bytes(&base, &ours, &theirs) {
        Ok(m) => m,
        Err(_) => {
            conflicts.push(path.clone());
            return Ok(None);
        }
    };
    let (visibility, fallback) = merged_visibility(store, oe, te);
    let id = store.store_file(&merged, &visibility)?;
    Ok(Some(TreeEntry {
        name: oe.name.clone(),
        kind: EntryKind::File,
        id,
        size: merged.len() as u64,
        executable,
        visibility,
        fallback,
    }))
}

/// The three-way merge of two file versions that records a conflict as
/// markers in the content (repository formats 1 to 3, trees under an
/// embargo, and virtual merge bases).
fn merge_file(
    store: &ObjectStore,
    path: &VPath,
    be: Option<&TreeEntry>,
    oe: &TreeEntry,
    te: &TreeEntry,
    mode: Mode,
    conflicts: &mut Vec<VPath>,
) -> Result<TreeEntry> {
    let base = match be.filter(|e| e.kind == EntryKind::File) {
        Some(e) => read_for_merge(store, e, path)?,
        None => Vec::new(),
    };
    let ours = read_for_merge(store, oe, path)?;
    let theirs = read_for_merge(store, te, path)?;
    let executable = if be.is_some_and(|b| b.executable == oe.executable) {
        te.executable
    } else {
        oe.executable
    };
    // Sealed for two different scopes: no merged content may be sealed for
    // either audience, since that would show one scope's content to the
    // other's members (BUG-123). One side is kept as it is.
    if let Some(keep) = audience_clash(store, be, oe, te)? {
        if ours == theirs {
            return Ok(TreeEntry { executable, ..keep });
        }
        conflicts.push(path.clone());
        return Ok(keep);
    }
    if ours == theirs {
        return Ok(TreeEntry { executable, ..oe.clone() });
    }
    // The merged content is new: its audience is decided on what both
    // sides' objects really are sealed for, never on their labels alone
    // (BUG-103: a forged `cloaked:embargo/<released>` or `cloaked:<scope of
    // the attacker's>` label on one side would re-key it).
    let (oe, te) = (&checked(store, oe, path)?, &checked(store, te, path)?);
    let (visibility, fallback) = merged_visibility(store, oe, te);
    // The base's text may appear in the result only where its audience is
    // the result's (BUG-126): a base sealed for a scope never shows in a
    // public result, or in one sealed for another audience.
    let base_ok = base_shown(store, be, &visibility)?;
    let style = match base_ok {
        true => diffy::ConflictStyle::Diff3,
        false => diffy::ConflictStyle::Merge,
    };
    let merged = if mode == Mode::VirtualBase {
        // A virtual base keeps the base's version where the two merge
        // bases disagree, and is sealed as they are: where the base's
        // audience is not theirs, it keeps nothing there instead
        // (BUG-127), so the base's text is never stored for a wider or
        // other audience, and the two later versions still both differ
        // from the virtual base there and conflict.
        let kept: &[u8] = if base_ok { &base } else { &[] };
        if looks_binary(&ours) || looks_binary(&theirs) || looks_binary(&base) {
            kept.to_vec()
        } else {
            merge_keeping_base(kept, &ours, &theirs)
        }
    } else if looks_binary(&ours) || looks_binary(&theirs) || looks_binary(&base) {
        conflicts.push(path.clone());
        ours
    } else {
        match diffy::MergeOptions::new().set_conflict_style(style).merge_bytes(&base, &ours, &theirs) {
            Ok(m) => m,
            Err(m) => {
                conflicts.push(path.clone());
                m
            }
        }
    };
    let id = store.store_file(&merged, &visibility)?;
    Ok(TreeEntry {
        name: oe.name.clone(),
        kind: EntryKind::File,
        id,
        size: merged.len() as u64,
        executable,
        visibility,
        fallback,
    })
}

/// The visibility `e`'s object really has (BUG-103), if it can be checked.
fn verified_visibility(store: &ObjectStore, e: &TreeEntry) -> Result<Option<Visibility>> {
    Ok(match verify_sealing(store, e)? {
        Sealing::Verified => Some(e.visibility.clone()),
        Sealing::Relabelled(actual) => Some(actual),
        Sealing::Unverifiable => None,
    })
}

/// Whether the text of the base `be` may appear in a merged file sealed as
/// `result`, as the "original" section of its conflict markers (BUG-126):
/// when the base is public (or under a released embargo), or (verifiably)
/// sealed exactly as the result is. Otherwise the conflict shows only the
/// two sides. A clean merge never holds lines of the base that neither side
/// has, so only the markers are concerned.
fn base_shown(store: &ObjectStore, be: Option<&TreeEntry>, result: &Visibility) -> Result<bool> {
    let Some(b) = be.filter(|e| e.kind == EntryKind::File) else {
        return Ok(true);
    };
    Ok(match verified_visibility(store, b)? {
        Some(Visibility::Public) => true,
        Some(Visibility::Embargoed { embargo }) if store.keys.embargo_released(&embargo) => true,
        Some(v) => v == *result,
        None => false,
    })
}

/// If `oe` and `te` are (really) sealed under two different scopes, the
/// side to keep, unchanged, under its real label: the one whose scope is
/// the base's (the other side moved the file to another audience, and its
/// content goes nowhere), else ours. Neither scope can be called narrower:
/// membership is not ordered and changes. `None`: no such clash.
fn audience_clash(store: &ObjectStore, be: Option<&TreeEntry>, oe: &TreeEntry, te: &TreeEntry) -> Result<Option<TreeEntry>> {
    let scope = |e: &TreeEntry| -> Result<Option<Visibility>> {
        Ok(verified_visibility(store, e)?.filter(|v| matches!(v, Visibility::Cloaked { .. })))
    };
    let (Some(so), Some(st)) = (scope(oe)?, scope(te)?) else {
        return Ok(None);
    };
    if so == st {
        return Ok(None);
    }
    let sb = match be.filter(|b| b.kind == EntryKind::File) {
        Some(b) => scope(b)?,
        None => None,
    };
    let (keep, vis) = if sb.as_ref() == Some(&st) { (te, st) } else { (oe, so) };
    Ok(Some(TreeEntry {
        visibility: vis,
        ..keep.clone()
    }))
}

/// The visibility of a file merged from `oe` and `te`: never wider than
/// either side. Ours' sealing wins if ours is sealed; otherwise theirs'.
/// An embargoed result taken from theirs shows ours (public) as fallback.
/// A cloaked result from a side that is a sealed edit of a public file
/// (it has a fallback) shows the other side's public version as its
/// fallback if there is one (the newest public version), else the
/// sealed side's own.
///
/// A scope's sealing beats an embargo's (the release would publish the
/// scope's content), and a released embargo counts as public: its key is
/// public, so nothing new is ever sealed under it.
fn merged_visibility(store: &ObjectStore, oe: &TreeEntry, te: &TreeEntry) -> (Visibility, Option<ObjectId>) {
    let public_other = |sealed: &TreeEntry, other: &TreeEntry| match (sealed.fallback, other.visibility.is_public() && other.fallback.is_none()) {
        (Some(_), true) => Some(other.id),
        (fb, _) => fb,
    };
    let rank = |e: &TreeEntry| match &e.visibility {
        Visibility::Cloaked { .. } => 2,
        Visibility::Embargoed { embargo } if !store.keys.embargo_released(embargo) => 1,
        _ => 0,
    };
    let ours_wins = rank(oe) >= rank(te);
    let (sealed, other) = if ours_wins { (oe, te) } else { (te, oe) };
    match rank(sealed) {
        2 => (sealed.visibility.clone(), public_other(sealed, other)),
        // An embargoed result shows ours (its fallback, or ours itself when
        // public) to readers without the key.
        1 if ours_wins => (oe.visibility.clone(), oe.fallback),
        1 if oe.visibility.is_public() => (te.visibility.clone(), Some(oe.id)),
        1 => (te.visibility.clone(), te.fallback),
        _ => (Visibility::Public, None),
    }
}

/// `e` with the visibility its object really has (BUG-103). A sealed label
/// whose object is sealed under no audience (`local`, not a scope) is
/// refused: merging would seal the result on the label's word.
fn checked(store: &ObjectStore, e: &TreeEntry, path: &VPath) -> Result<TreeEntry> {
    match verify_sealing(store, e)? {
        Sealing::Verified => Ok(e.clone()),
        Sealing::Relabelled(actual) => Ok(TreeEntry {
            visibility: actual,
            ..e.clone()
        }),
        Sealing::Unverifiable if e.visibility.is_public() => Ok(e.clone()),
        Sealing::Unverifiable => Err(VeilError::Policy(format!(
            "cannot merge {path}: it is labelled {} but its sealing cannot be verified",
            e.visibility.label()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::merge_keeping_base;

    #[test]
    fn conflicting_hunks_take_the_base() {
        let base = b"1\n2\n3\n4\n5\n";
        let ours = b"ONE\n2\nB\n4\n5\n";
        let theirs = b"1\n2\nC\n4\nFIVE\n";
        assert_eq!(merge_keeping_base(base, ours, theirs), b"ONE\n2\n3\n4\nFIVE\n");
    }

    #[test]
    fn a_clean_merge_is_the_merge() {
        assert_eq!(merge_keeping_base(b"1\n2\n3\n", b"A\n2\n3\n", b"1\n2\nC\n"), b"A\n2\nC\n");
    }

    #[test]
    fn missing_final_newlines_and_marker_like_content() {
        let markers = "<<<<<<< ours\n=======\n>>>>>>> theirs\n";
        let base = format!("{markers}last");
        let ours = format!("{markers}left");
        let theirs = format!("{markers}right");
        assert_eq!(merge_keeping_base(base.as_bytes(), ours.as_bytes(), theirs.as_bytes()), base.as_bytes());
        // Long runs of marker characters in the content get longer markers.
        let run = "=".repeat(200);
        let base = format!("{run}\nx\n");
        let ours = format!("{run}\ny\n");
        let theirs = format!("{run}\nz\n");
        assert_eq!(merge_keeping_base(base.as_bytes(), ours.as_bytes(), theirs.as_bytes()), base.as_bytes());
    }

    #[test]
    fn no_base_drops_the_conflicting_hunk() {
        assert_eq!(merge_keeping_base(b"", b"a\n", b"b\n"), b"");
    }
}
