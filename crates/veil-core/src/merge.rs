//! Three-way tree merge. Works at the tree level (identical subtrees are
//! resolved by id without reading content) and falls back to line-based
//! diff3 for files changed on both sides.
//!
//! Visibility never widens: a file merged from a sealed side stays sealed
//! (ours' sealing if ours is sealed, else theirs'), whichever side "ours"
//! happens to be. This matters for auto-rebase, where "ours" is the new
//! (possibly public) parent and "theirs" the (possibly cloaked) child.
//!
//! Trees under an unreleased embargo (see [`crate::embargo`]) stay under it:
//! the result is re-wrapped under the same embargo, with the merge of the
//! inputs' public views as its fallback. Merging them needs the embargo key,
//! and trees under two different unreleased embargoes are never merged
//! (embargoes cannot overlap in Veil 1.0).

use std::{collections::BTreeSet, sync::Arc};

use crate::{
    builder::{verify_sealing, Sealing},
    embargo::{overlap_error, public_view, unreleased_wrapper, wrap},
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Tree, TreeEntry, Visibility},
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

pub fn merge_trees(store: &ObjectStore, base: Option<ObjectId>, ours: ObjectId, theirs: ObjectId) -> Result<MergeOutcome> {
    merge_trees_in(store, base, ours, theirs, Mode::Merge)
}

/// The virtual merge base of two merge bases `ours` and `theirs` (whose
/// own merge base is `base`), for a criss-cross merge (see
/// [`crate::repo::Repo::merge_base_tree`]). What the two bases disagree on
/// is left as `base` has it, so neither base's version of it is taken
/// silently (BUG-244). Markers in the virtual base, as Git writes them,
/// would line up with one side's resolution in a line diff and let it win.
pub fn virtual_merge_base(store: &ObjectStore, base: Option<ObjectId>, ours: ObjectId, theirs: ObjectId) -> Result<ObjectId> {
    Ok(merge_trees_in(store, base, ours, theirs, Mode::VirtualBase)?.tree)
}

fn merge_trees_in(store: &ObjectStore, base: Option<ObjectId>, ours: ObjectId, theirs: ObjectId, mode: Mode) -> Result<MergeOutcome> {
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
    let full = merge_resolved(store, base, ours, theirs, mode)?;
    let Some(w) = wrapped else {
        return Ok(full);
    };
    // What readers without the key see: the same merge of what they see.
    let pv = |id: ObjectId| public_view(store, &id);
    let (pb, po, pt) = (base.map(pv).transpose()?, pv(ours)?, pv(theirs)?);
    let fallback = match merge_resolved(store, pb, po, pt, mode) {
        Ok(m) => m.tree,
        Err(_) => po,
    };
    Ok(MergeOutcome {
        tree: wrap(store, &w.embargo, &full.tree, &fallback)?,
        conflicts: full.conflicts,
    })
}

fn merge_resolved(store: &ObjectStore, base: Option<ObjectId>, ours: ObjectId, theirs: ObjectId, mode: Mode) -> Result<MergeOutcome> {
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
    let tree = match merge_dir(store, b, Some((o, ours)), Some((t, theirs)), mode, &mut conflicts)? {
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
        let be = f.b.as_ref().and_then(|x| x.get(&name));
        let oe = f.o.as_ref().and_then(|x| x.0.get(&name));
        let te = f.t.as_ref().and_then(|x| x.0.get(&name));
        let path = f.dir.join(&name);
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
    if ours == theirs {
        return Ok(TreeEntry { executable, ..oe.clone() });
    }
    let merged = if mode == Mode::VirtualBase {
        if looks_binary(&ours) || looks_binary(&theirs) || looks_binary(&base) {
            base
        } else {
            merge_keeping_base(&base, &ours, &theirs)
        }
    } else if looks_binary(&ours) || looks_binary(&theirs) || looks_binary(&base) {
        conflicts.push(path.clone());
        ours
    } else {
        match diffy::merge_bytes(&base, &ours, &theirs) {
            Ok(m) => m,
            Err(m) => {
                conflicts.push(path.clone());
                m
            }
        }
    };
    // The merged content is new: its audience is decided on what both
    // sides' objects really are sealed for, never on their labels alone
    // (BUG-103: a forged `cloaked:embargo/<released>` or `cloaked:<scope of
    // the attacker's>` label on one side would re-key it).
    let (oe, te) = (&checked(store, oe, path)?, &checked(store, te, path)?);
    let (visibility, fallback) = merged_visibility(store, oe, te);
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
