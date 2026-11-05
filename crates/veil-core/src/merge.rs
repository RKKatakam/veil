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
//! Renames are followed (see [`FollowedRename`]): when one side renamed a
//! file and the other edited it, the edit is merged at the new path instead
//! of being a modify/delete conflict. Pairs are found by
//! [`crate::rename::detect`] as a public mirror reads the trees, and only
//! between versions of the same (verified) audience, so the result never
//! depends on the merger's keys and never moves content between audiences.
//!
//! How a file's content merges follows `.veilattributes` (feature 7), read
//! from `ours`: `-merge` / `binary` make it a whole-file conflict,
//! `merge=union` keeps both sides' lines, and `merge=<name>` runs a driver
//! only if this device defines one ([`crate::attributes::DeviceDrivers`]).
//! A driver gets the base only where its audience is the result's (as
//! conflict markers do, BUG-126), never runs where two scopes clash, and
//! its output is sealed as any merged content is.
//!
//! Trees under an unreleased embargo (see [`crate::embargo`]) stay under it:
//! the result is re-wrapped under the same embargo, with the merge of the
//! inputs' public views as its fallback. Merging them needs the embargo key,
//! and trees under two different unreleased embargoes are never merged
//! (embargoes cannot overlap in Veil 1.0).

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::Arc,
};

use crate::{
    attributes::{Attrs, MergeAttr},
    blame::Reader,
    builder::{verify_sealing, Sealing},
    conflict::{Merge, Term},
    embargo::{overlap_error, public_view, unreleased_wrapper, wrap},
    error::{Result, VeilError},
    id::ObjectId,
    object::{ConflictTerm, EntryKind, Tree, TreeEntry, Visibility},
    rename::{Pair, RenameOptions},
    secrets::looks_binary,
    store::ObjectStore,
    tree::{lookup, TreeChange, MAX_TREE_DEPTH},
    vpath::VPath,
};

#[derive(Debug, Clone)]
pub struct MergeOutcome {
    pub tree: ObjectId,
    pub conflicts: Vec<VPath>,
    /// Renames the merge followed, for this reader's report only: never
    /// stored (threat review 1 of `docs/design/git-parity/2-renames.md`).
    pub renames: Vec<FollowedRename>,
}

impl MergeOutcome {
    /// A merge that needed no work: `tree`, nothing conflicted or renamed.
    pub fn clean(tree: ObjectId) -> MergeOutcome {
        MergeOutcome { tree, conflicts: vec![], renames: vec![] }
    }
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
        return Ok(MergeOutcome::clean(ours));
    }
    if Some(ours) == base {
        return Ok(MergeOutcome::clean(theirs));
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
        renames: full.renames,
    })
}

fn merge_resolved(store: &ObjectStore, base: Option<ObjectId>, ours: ObjectId, theirs: ObjectId, mode: Mode, markers: bool) -> Result<MergeOutcome> {
    if ours == theirs || Some(theirs) == base {
        return Ok(MergeOutcome::clean(ours));
    }
    if Some(ours) == base {
        return Ok(MergeOutcome::clean(theirs));
    }
    // Renames first: the trees with each followed rename applied to the
    // side (and base) that did not make it.
    let plan = match base {
        Some(b) => follow_renames(store, b, ours, theirs)?,
        None => RenamePlan::none(base, ours, theirs),
    };
    let b = plan.base.map(|id| store.tree(&id)).transpose()?;
    let o = store.tree(&plan.ours)?;
    let t = store.tree(&plan.theirs)?;
    let mut conflicts = Vec::new();
    // Attributes of the path the content merges at: `ours` with the
    // followed renames applied (a renamed file merges at its new path), as
    // the merged file's audience reads them (BUG-705).
    let attrs = MergeAttrs::new(store, plan.ours);
    let tree = match merge_dir(store, b, Some((o, plan.ours)), Some((t, plan.theirs)), mode, markers, &mut conflicts, &attrs)? {
        Some(id) => id,
        None => store.empty_tree()?,
    };
    let (tree, renames) = finish_renames(store, tree, plan.renames, mode, markers, &mut conflicts)?;
    Ok(MergeOutcome { tree, conflicts, renames })
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
#[allow(clippy::too_many_arguments)]
fn merge_dir(
    store: &ObjectStore,
    b: Option<Arc<Tree>>,
    o: Option<(Arc<Tree>, ObjectId)>,
    t: Option<(Arc<Tree>, ObjectId)>,
    mode: Mode,
    markers: bool,
    conflicts: &mut Vec<VPath>,
    attrs: &MergeAttrs<'_>,
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
            // A copy of a conflict as a public reader sees it (its marker
            // file, which a later change then edits) stands for that
            // conflict, so the edit applies to the conflict.
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
                merge_terms(store, &path, &name, be, oe, te, mode, conflicts, attrs)?
            } else if let (Some(oe), Some(te), [EntryKind::File, EntryKind::File]) = (oe, te, kinds.as_slice()) {
                let be = be.filter(|e| e.kind == EntryKind::File);
                Some(merge_file(store, &path, be, oe, te, mode, conflicts, attrs)?)
            } else if mode == Mode::VirtualBase {
                // Modify/delete or file/directory: the base's version.
                be.cloned()
            } else if oe.is_some_and(|e| e.kind != EntryKind::Dir) && te.is_some_and(|e| e.kind != EntryKind::Dir) {
                // Two different versions where one is a symlink
                // (format 5) and no conflict entry can be recorded here:
                // our side as it is, flagged. A link target never becomes
                // a file of markers.
                conflicts.push(path.clone());
                oe.cloned()
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
    attrs: &MergeAttrs<'_>,
) -> Result<Option<TreeEntry>> {
    let be = be.filter(|e| e.kind != EntryKind::Dir);
    let m = Merge::three_way(Merge::of_entry(store, be)?, Merge::of_entry(store, oe)?, Merge::of_entry(store, te)?).simplify();
    if let Some(t) = m.trivial() {
        return Ok(t.map(|t| t.entry(name)));
    }
    if let Some(e) = resolve_by_content(store, path, name, &m, attrs, mode)? {
        return Ok(Some(e));
    }
    if mode == Mode::VirtualBase {
        return Ok(be.cloned());
    }
    // The versions are recorded as they really are sealed (BUG-103): a
    // forged label is not carried into the conflict.
    let relabel = |t: &Term| relabelled(store, t, name);
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

/// `t` with the visibility its object really has (BUG-103).
fn relabelled(store: &ObjectStore, t: &Term, name: &str) -> Result<Term> {
    let Some(t) = t else { return Ok(None) };
    Ok(Some(match verify_sealing(store, &t.entry(name))? {
        Sealing::Relabelled(actual) => ConflictTerm {
            visibility: actual,
            ..t.clone()
        },
        _ => t.clone(),
    }))
}

/// The file `m` merges to by content, if it does: every version present,
/// readable and text, and each further side merging cleanly (diff3) into
/// the result so far against its base. Its audience is the merged
/// audience of the sides, as for any merged file (never wider than either,
/// never moved between scopes). `None`: a real conflict.
fn resolve_by_content(store: &ObjectStore, path: &VPath, name: &str, m: &Merge, attrs: &MergeAttrs<'_>, mode: Mode) -> Result<Option<TreeEntry>> {
    if m.adds.iter().any(Option::is_none) || (m.adds.len() > 2 && m.removes.iter().any(Option::is_none)) {
        return Ok(None);
    }
    // Link targets are never merged line by line: two
    // different ones are a conflict (format 5).
    if m.adds.iter().chain(&m.removes).flatten().any(|t| t.kind != crate::object::TermKind::File) {
        return Ok(None);
    }
    let entry = |t: &Term| t.as_ref().map(|t| t.entry(name));
    let mut acc = entry(&m.adds[0]).expect("present");
    for i in 1..m.adds.len() {
        let base = entry(&m.removes[i - 1]);
        let side = entry(&m.adds[i]).expect("present");
        let mut found = Vec::new();
        let merged = merge_file_content(store, path, base.as_ref(), &acc, &side, &mut found, attrs, mode)?;
        match merged {
            Some(e) if found.is_empty() => acc = e,
            _ => return Ok(None),
        }
    }
    acc.executable = crate::conflict::merged_executable(m);
    Ok(Some(acc))
}

/// Git's (and diffy's default) conflict marker length.
const MARKER_LEN: usize = 7;

/// The attributes a merge reads (from ours), one set per audience of the
/// merged files (BUG-705): a file merged for audience `V` is shaped only by
/// `.veilattributes` content `V` can read ([`Attrs::for_audience`]), so a
/// sealed `merge=union` never decides a public result, and a member and a
/// non-member merging the same public files get the same tree.
struct MergeAttrs<'a> {
    store: &'a ObjectStore,
    tree: ObjectId,
    by_audience: std::cell::RefCell<Vec<(Visibility, Arc<Attrs<'a>>)>>,
}

impl<'a> MergeAttrs<'a> {
    fn new(store: &'a ObjectStore, tree: ObjectId) -> Self {
        MergeAttrs { store, tree, by_audience: Default::default() }
    }

    /// The attributes for a result sealed as `audience`.
    fn for_audience(&self, audience: &Visibility) -> Arc<Attrs<'a>> {
        let audience = match audience {
            Visibility::Embargoed { embargo } if self.store.keys.embargo_released(embargo) => Visibility::Public,
            v => v.clone(),
        };
        let mut by = self.by_audience.borrow_mut();
        if let Some((_, a)) = by.iter().find(|(v, _)| *v == audience) {
            return a.clone();
        }
        let a = Arc::new(Attrs::for_audience(self.store, self.tree, audience.clone()));
        by.push((audience, a.clone()));
        a
    }
}

/// How the content at `path`, merged for `audience`, merges, as
/// `.veilattributes` (read from ours, as `audience` reads it) says, with
/// named drivers resolved against this device's definitions (see
/// [`crate::attributes::merge_strategy`]). A virtual merge base only
/// tells whole-file merges from line merges: no driver runs for it.
fn strategy(store: &ObjectStore, attrs: &MergeAttrs<'_>, audience: &Visibility, path: &VPath, mode: Mode) -> MergeAttr {
    match crate::attributes::merge_strategy(store, &attrs.for_audience(audience), path) {
        MergeAttr::Union | MergeAttr::Driver(_) if mode == Mode::VirtualBase => MergeAttr::Text,
        m => m,
    }
}

/// The content merge of `base`, `ours` and `theirs` by `how` (when it is
/// not the built-in line merge): `Some(Ok(merged))` clean, `Some(Err(()))`
/// a whole-file conflict, `None` for the built-in line merge. The base is
/// given (to a driver, or to the union) only when `base_ok` (its audience
/// is the result's): otherwise an empty file stands in for it.
fn attribute_merge(store: &ObjectStore, path: &VPath, how: &MergeAttr, base: &[u8], ours: &[u8], theirs: &[u8], base_ok: bool) -> Option<Result<Vec<u8>, ()>> {
    let base: &[u8] = if base_ok { base } else { &[] };
    match how {
        MergeAttr::Text => None,
        MergeAttr::Binary => Some(Err(())),
        MergeAttr::Union if looks_binary(ours) || looks_binary(theirs) || looks_binary(base) => Some(Err(())),
        MergeAttr::Union => Some(Ok(crate::attributes::union_merge(base, ours, theirs))),
        MergeAttr::Driver(name) => {
            let d = store.device_drivers()?;
            let input = crate::attributes::DriverInput { path, base, ours, theirs };
            Some(match d.merge(name, &input) {
                crate::attributes::DriverMerge::Clean(m) => Ok(m),
                crate::attributes::DriverMerge::Conflict => Err(()),
            })
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
    let merged = match crate::textmerge::merge(base, ours, theirs, n, crate::textmerge::Style::Diff3) {
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
#[allow(clippy::too_many_arguments)]
fn merge_file_content(
    store: &ObjectStore,
    path: &VPath,
    be: Option<&TreeEntry>,
    oe: &TreeEntry,
    te: &TreeEntry,
    conflicts: &mut Vec<VPath>,
    attrs: &MergeAttrs<'_>,
    mode: Mode,
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
    let (visibility, fallback) = merged_visibility(store, oe, te);
    let base_ok = base_shown(store, be, &visibility)?;
    let how = strategy(store, attrs, &visibility, path, mode);
    let merged = match content_merge(store, path, &how, &base, &ours, &theirs, base_ok, crate::textmerge::Style::Diff3) {
        Ok(m) => m,
        Err(_) => {
            conflicts.push(path.clone());
            return Ok(None);
        }
    };
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
#[allow(clippy::too_many_arguments)]
fn merge_file(
    store: &ObjectStore,
    path: &VPath,
    be: Option<&TreeEntry>,
    oe: &TreeEntry,
    te: &TreeEntry,
    mode: Mode,
    conflicts: &mut Vec<VPath>,
    attrs: &MergeAttrs<'_>,
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
        true => crate::textmerge::Style::Diff3,
        false => crate::textmerge::Style::Merge,
    };
    let how = strategy(store, attrs, &visibility, path, mode);
    let merged = if mode == Mode::VirtualBase {
        // A virtual base keeps the base's version where the two merge
        // bases disagree, and is sealed as they are: where the base's
        // audience is not theirs, it keeps nothing there instead
        // (BUG-127), so the base's text is never stored for a wider or
        // other audience, and the two later versions still both differ
        // from the virtual base there and conflict. No driver runs here.
        let kept: &[u8] = if base_ok { &base } else { &[] };
        if how == MergeAttr::Binary || looks_binary(&ours) || looks_binary(&theirs) || looks_binary(&base) {
            kept.to_vec()
        } else {
            merge_keeping_base(kept, &ours, &theirs)
        }
    } else {
        match content_merge(store, path, &how, &base, &ours, &theirs, base_ok, style) {
            Ok(m) => m,
            // Markers in the content.
            Err(Some(m)) => {
                conflicts.push(path.clone());
                m
            }
            // A whole-file conflict: ours, flagged.
            Err(None) => {
                conflicts.push(path.clone());
                ours
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

/// The content merge of one file's three readable versions at `path`, by
/// `how` (what `.veilattributes` asks for, see [`strategy`]): `Ok` when
/// clean, `Err(Some(markers))` for a line conflict (see
/// [`crate::textmerge::merge`]), `Err(None)` for a whole-file conflict
/// (`binary` / `-merge`, binary-looking content, a driver's conflict).
///
/// The seam for per-path merge drivers. The built-in diff3's clean result
/// never holds a line of the base that neither side has; a union or a
/// driver can output anything it is given, so it is given the base only
/// when `base_ok` ([`base_shown`] against the result's visibility, BUG-126)
/// and an empty one otherwise (design 7, threat review 6).
#[allow(clippy::too_many_arguments)]
fn content_merge(
    store: &ObjectStore,
    path: &VPath,
    how: &MergeAttr,
    base: &[u8],
    ours: &[u8],
    theirs: &[u8],
    base_ok: bool,
    style: crate::textmerge::Style,
) -> std::result::Result<Vec<u8>, Option<Vec<u8>>> {
    if let Some(r) = attribute_merge(store, path, how, base, ours, theirs, base_ok) {
        return r.map_err(|()| None);
    }
    if looks_binary(ours) || looks_binary(theirs) || looks_binary(base) {
        return Err(None);
    }
    crate::textmerge::merge(base, ours, theirs, MARKER_LEN, style).map_err(Some)
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

// ---- rename-aware merging ------------------------------------------------------
//
// Before the directory walk, renames are detected base → ours and base →
// theirs ([`crate::rename::detect`]) and each one the other side cares about
// is applied to the trees that did not make it, so the walk merges the
// versions of a file at one path. The pairing only decides *which* entries
// are combined; their audiences are decided by the content merge itself
// (`merged_visibility`, `audience_clash`, BUG-123/126), exactly as for a
// file that was not renamed (threat review 2 of
// `docs/design/git-parity/2-renames.md`).

/// Which side of a merge renamed a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameSide {
    Ours,
    Theirs,
    Both,
}

/// What a merge did with a rename it detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenameMerge {
    /// One side renamed the file and the other edited it: the edit was
    /// merged at the new path.
    Followed,
    /// Both sides renamed it to the same path: the two versions were merged
    /// there.
    Both,
    /// One side renamed it, the other deleted it: a conflict at the new
    /// path (the renamed version against no file).
    RenameDelete,
    /// The sides renamed it to two different paths (`to` is ours, `other`
    /// theirs): a conflict at both, each holding its side's version against
    /// no file, so either name can be kept with `vl resolve`.
    RenameRename { other: VPath },
}

/// A rename a merge followed. Reported to this reader only; never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FollowedRename {
    pub from: VPath,
    pub to: VPath,
    /// Similarity in percent (100: the same object).
    pub score: u8,
    pub side: RenameSide,
    pub how: RenameMerge,
    /// The result at `to` is sealed for this audience: it stays sealed at
    /// its new path, whatever the policy says there; only `vl expose`
    /// publishes it.
    pub sealed: Option<Visibility>,
}

/// Is rename following on in merges? On unless `VEIL_MERGE_RENAMES=0`
/// (an escape hatch for one release; any other value, or none, means on).
pub fn merge_renames_enabled() -> bool {
    !matches!(std::env::var_os("VEIL_MERGE_RENAMES"), Some(v) if v == "0")
}

/// The trees a merge walks after renames were applied, and what was done.
struct RenamePlan {
    base: Option<ObjectId>,
    ours: ObjectId,
    theirs: ObjectId,
    renames: Vec<PlannedRename>,
}

impl RenamePlan {
    fn none(base: Option<ObjectId>, ours: ObjectId, theirs: ObjectId) -> RenamePlan {
        RenamePlan { base, ours, theirs, renames: vec![] }
    }
}

/// One rename the plan uses, with the versions a conflict would record.
struct PlannedRename {
    r: FollowedRename,
    /// The base's version (at `from`).
    base: TreeEntry,
    /// The renamed version(s): ours (at `to`) and theirs (at `to`, or at
    /// `other` for rename/rename).
    ours: Option<TreeEntry>,
    theirs: Option<TreeEntry>,
}

/// The renames of `changes` (base → one side) a merge may follow: real
/// renames (not copies) between versions of the same kind and the same
/// verified audience. Detection reads as a public mirror does
/// ([`Reader::Public`]): the inexact pass only reads plaintext, sealed
/// content pairs by exact object id only (an equality every reader of the
/// trees already sees), so the pairing never depends on the merger's keys
/// and never reads what the merger cannot (threat review 5).
fn side_renames(store: &ObjectStore, changes: &[TreeChange]) -> Result<BTreeMap<VPath, Pair>> {
    let mut out = BTreeMap::new();
    let d = crate::rename::detect(store, changes, Reader::Public, &RenameOptions::default())?;
    for p in d.pairs {
        if !p.copy && same_audience(store, &p.old, &p.new)? {
            out.insert(p.from.clone(), p);
        }
    }
    Ok(out)
}

/// May `a` and `b` be paired: the same kind and the same audience, checked
/// on their objects (labels are claims, BUG-103)? A conflict pairs only
/// with the same conflict object.
fn same_audience(store: &ObjectStore, a: &TreeEntry, b: &TreeEntry) -> Result<bool> {
    if a.kind != b.kind {
        return Ok(false);
    }
    if a.kind == EntryKind::Conflict {
        return Ok(a.id == b.id);
    }
    if a.kind != EntryKind::File {
        return Ok(false);
    }
    Ok(match (verified_visibility(store, a)?, verified_visibility(store, b)?) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    })
}

/// Does `cx` (base → one side) hold a rename the other side (`other`, the
/// paths it changed) could care about: a deleted file the other side
/// changed, and an added file? Most merges have none, and detection is
/// skipped.
fn may_matter(cx: &[TreeChange], other: &HashSet<&VPath>) -> bool {
    let deleted = cx.iter().any(|c| c.new.is_none() && c.old.as_ref().is_some_and(|e| e.kind.is_file_like()) && other.contains(&c.path));
    deleted && cx.iter().any(|c| c.old.is_none() && c.new.as_ref().is_some_and(|e| e.kind.is_file_like()))
}

/// Detect the renames each side made and apply those the other side cares
/// about (see [`RenameMerge`]). Unchanged trees when following is off, or
/// nothing applies. A rename whose new path is taken on the other side
/// (rename/add), or cannot be placed there (a file where a directory is
/// needed), is not followed: the merge does what it did before.
fn follow_renames(store: &ObjectStore, base: ObjectId, ours: ObjectId, theirs: ObjectId) -> Result<RenamePlan> {
    let mut plan = RenamePlan::none(Some(base), ours, theirs);
    if !merge_renames_enabled() {
        return Ok(plan);
    }
    let co = crate::tree::diff_trees(store, Some(&base), Some(&ours))?;
    let ct = crate::tree::diff_trees(store, Some(&base), Some(&theirs))?;
    let (po, pt) = {
        let touched_o: HashSet<&VPath> = co.iter().map(|c| &c.path).collect();
        let touched_t: HashSet<&VPath> = ct.iter().map(|c| &c.path).collect();
        let po = if may_matter(&co, &touched_t) { side_renames(store, &co)? } else { BTreeMap::new() };
        let pt = if may_matter(&ct, &touched_o) { side_renames(store, &ct)? } else { BTreeMap::new() };
        (po, pt)
    };
    if po.is_empty() && pt.is_empty() {
        return Ok(plan);
    }
    let froms: BTreeSet<&VPath> = po.keys().chain(pt.keys()).collect();
    let mut claimed: HashSet<VPath> = HashSet::new();
    let (mut b, mut o, mut t) = (base, ours, theirs);
    for from in froms {
        let rename = |p: &Pair, side, how| FollowedRename {
            from: p.from.clone(),
            to: p.to.clone(),
            score: p.score,
            side,
            how,
            sealed: None,
        };
        match (po.get(from), pt.get(from)) {
            (Some(x), Some(y)) if x.to == y.to => {
                // Both renamed it the same way: merge the two versions there.
                if claimed.contains(&x.to) {
                    continue;
                }
                let Some(nb) = move_entry(store, &b, from, &x.to, &x.old)? else { continue };
                b = nb;
                claimed.insert(x.to.clone());
                plan.renames.push(PlannedRename {
                    r: FollowedRename { score: x.score.min(y.score), ..rename(x, RenameSide::Both, RenameMerge::Both) },
                    base: x.old.clone(),
                    ours: Some(x.new.clone()),
                    theirs: Some(y.new.clone()),
                });
            }
            (Some(x), Some(y)) => {
                // rename/rename to two names: each keeps its name; a
                // conflict at both (see `finish_renames`).
                if claimed.contains(&x.to) || claimed.contains(&y.to) {
                    continue;
                }
                claimed.insert(x.to.clone());
                claimed.insert(y.to.clone());
                plan.renames.push(PlannedRename {
                    r: rename(x, RenameSide::Both, RenameMerge::RenameRename { other: y.to.clone() }),
                    base: x.old.clone(),
                    ours: Some(x.new.clone()),
                    theirs: Some(y.new.clone()),
                });
            }
            (Some(p), None) | (None, Some(p)) => {
                let side = if po.contains_key(from) { RenameSide::Ours } else { RenameSide::Theirs };
                if claimed.contains(&p.to) {
                    continue;
                }
                let other = if side == RenameSide::Ours { t } else { o };
                if lookup(store, &other, &p.to)?.is_some() {
                    // rename/add: the other side has its own file there.
                    continue;
                }
                let (ours_v, theirs_v) = match side {
                    RenameSide::Ours => (Some(p.new.clone()), None),
                    _ => (None, Some(p.new.clone())),
                };
                match lookup(store, &other, from)? {
                    // The other side left the file alone: the rename is
                    // merged as it is (deleted at `from`, added at `to`).
                    Some(e) if e.same_content(&p.old) => continue,
                    Some(e) if e.kind == EntryKind::Dir => continue,
                    Some(e) => {
                        // Edited on the other side: the edit follows.
                        let Some(nb) = move_entry(store, &b, from, &p.to, &p.old)? else { continue };
                        let Some(nother) = move_entry(store, &other, from, &p.to, &e)? else { continue };
                        b = nb;
                        match side {
                            RenameSide::Ours => t = nother,
                            _ => o = nother,
                        }
                        claimed.insert(p.to.clone());
                        plan.renames.push(PlannedRename {
                            r: rename(p, side, RenameMerge::Followed),
                            base: p.old.clone(),
                            ours: ours_v,
                            theirs: theirs_v,
                        });
                    }
                    None => {
                        claimed.insert(p.to.clone());
                        plan.renames.push(PlannedRename {
                            r: rename(p, side, RenameMerge::RenameDelete),
                            base: p.old.clone(),
                            ours: ours_v,
                            theirs: theirs_v,
                        });
                    }
                }
            }
            (None, None) => {}
        }
    }
    plan.base = Some(b);
    plan.ours = o;
    plan.theirs = t;
    Ok(plan)
}

/// After the walk: record rename/delete and rename/rename as conflicts (a
/// real merge only; a virtual merge base records nothing, and below format
/// 4 the files stay as they are and are flagged), and note which followed
/// renames are sealed at their new path.
fn finish_renames(
    store: &ObjectStore,
    mut tree: ObjectId,
    planned: Vec<PlannedRename>,
    mode: Mode,
    markers: bool,
    conflicts: &mut Vec<VPath>,
) -> Result<(ObjectId, Vec<FollowedRename>)> {
    let mut out = Vec::with_capacity(planned.len());
    for p in planned {
        let mut r = p.r;
        if mode == Mode::Merge {
            // (path, the version found there, ours' and theirs' versions)
            let sites: Vec<(VPath, &TreeEntry, Option<&TreeEntry>, Option<&TreeEntry>)> = match (&r.how, &p.ours, &p.theirs) {
                (RenameMerge::RenameDelete, Some(oe), None) => vec![(r.to.clone(), oe, Some(oe), None)],
                (RenameMerge::RenameDelete, None, Some(te)) => vec![(r.to.clone(), te, None, Some(te))],
                (RenameMerge::RenameRename { other }, Some(oe), Some(te)) => {
                    vec![(r.to.clone(), oe, Some(oe), None), (other.clone(), te, None, Some(te))]
                }
                _ => vec![],
            };
            for (path, expect, oe, te) in sites {
                // Only where the walk left the renamed version as it was.
                if !lookup(store, &tree, &path)?.is_some_and(|e| e.same_content(expect)) {
                    continue;
                }
                if !markers {
                    let name = path.file_name().to_string();
                    let m = Merge::three_way(Merge::of_entry(store, Some(&p.base))?, Merge::of_entry(store, oe)?, Merge::of_entry(store, te)?);
                    let m = Merge {
                        adds: m.adds.iter().map(|x| relabelled(store, x, &name)).collect::<Result<_>>()?,
                        removes: m.removes.iter().map(|x| relabelled(store, x, &name)).collect::<Result<_>>()?,
                    };
                    let Some(c) = m.into_conflict()? else { continue };
                    let entry = TreeEntry::conflict(&name, store.put_conflict(&c)?);
                    tree = crate::conflict::set_entry(store, &tree, &path, Some(entry))?;
                }
                if !conflicts.contains(&path) {
                    conflicts.push(path);
                }
            }
        }
        if let Some(e) = lookup(store, &tree, &r.to)?.filter(|e| e.kind == EntryKind::File) {
            r.sealed = match verified_visibility(store, &e)? {
                Some(Visibility::Public) | None => None,
                Some(Visibility::Embargoed { embargo }) if store.keys.embargo_released(&embargo) => None,
                Some(v) => Some(v),
            };
        }
        out.push(r);
    }
    Ok((tree, out))
}

/// For `vl merge`, after it re-derived audiences
/// ([`crate::embargo::normalize_tree`]): a file whose edit followed a rename
/// and that the merge left sealed keeps its sealed entry from `merged` at
/// its new path, even where the policy would publish the merged-in line's
/// files (or quarantine them): the rename put it there, not the line being
/// merged, and only `vl expose` publishes it. Such paths leave
/// `declassified` and `quarantined`, and `warnings` says why.
pub fn keep_followed_sealed(
    store: &ObjectStore,
    mut tree: ObjectId,
    merged: ObjectId,
    renames: &[FollowedRename],
    declassified: &mut Vec<VPath>,
    quarantined: &mut Vec<(VPath, Vec<crate::secrets::Finding>)>,
    warnings: &mut Vec<String>,
) -> Result<ObjectId> {
    for r in renames {
        let Some(vis) = &r.sealed else { continue };
        let was_declassified = declassified.contains(&r.to);
        let was_quarantined = quarantined.iter().any(|(p, _)| *p == r.to);
        if !was_declassified && !was_quarantined {
            continue;
        }
        declassified.retain(|p| *p != r.to);
        quarantined.retain(|(p, _)| *p != r.to);
        let Some(sealed) = lookup(store, &merged, &r.to)? else { continue };
        let now = lookup(store, &tree, &r.to)?;
        if now.as_ref() != Some(&sealed) && unreleased_wrapper(store, &tree)?.is_none() {
            tree = crate::conflict::set_entry(store, &tree, &r.to, Some(sealed))?;
        }
        warnings.push(format!(
            "{} followed the rename of {} and stays sealed ({}) at its new path; `vl expose {}` publishes it",
            r.to,
            r.from,
            vis.label(),
            r.to
        ));
    }
    Ok(tree)
}

/// `tree` with `entry` moved from `from` to `to` (directories created as
/// needed, emptied ones removed). `None` when `to` is taken or a component
/// of it is not a directory: the rename cannot be applied there.
fn move_entry(store: &ObjectStore, tree: &ObjectId, from: &VPath, to: &VPath, entry: &TreeEntry) -> Result<Option<ObjectId>> {
    let Some(t) = put_at(store, tree, from, None)? else { return Ok(None) };
    put_at(store, &t, to, Some(entry.clone()))
}

/// `root` with `entry` at `path` (`None` removes it). Missing directories
/// are created; one left empty disappears. `None` when a component of
/// `path` is not a directory, or (adding) `path` is taken. Iterative.
fn put_at(store: &ObjectStore, root: &ObjectId, path: &VPath, entry: Option<TreeEntry>) -> Result<Option<ObjectId>> {
    let comps: Vec<&str> = path.components().collect();
    let Some((last, dirs)) = comps.split_last() else { return Ok(None) };
    let mut chain: Vec<Tree> = vec![(*store.tree(root)?).clone()];
    for d in dirs {
        let next = match chain.last().expect("non-empty").get(d) {
            Some(e) if e.kind == EntryKind::Dir => (*store.tree(&e.id)?).clone(),
            Some(_) => return Ok(None),
            None if entry.is_some() => Tree::default(),
            None => return Ok(Some(*root)),
        };
        chain.push(next);
    }
    let mut leaf = chain.pop().expect("non-empty");
    match entry {
        Some(_) if leaf.get(last).is_some() => return Ok(None),
        Some(e) => leaf.insert(TreeEntry {
            name: last.to_string(),
            ..e
        }),
        None => {
            leaf.remove(last);
        }
    }
    let mut child: Option<ObjectId> = (!leaf.is_empty()).then(|| store.put_tree(&leaf)).transpose()?;
    for (mut t, name) in chain.into_iter().rev().zip(dirs.iter().rev()) {
        match child {
            Some(id) => t.insert(TreeEntry::dir(name, id)),
            None => {
                t.remove(name);
            }
        }
        child = (!t.is_empty()).then(|| store.put_tree(&t)).transpose()?;
    }
    Ok(Some(match child {
        Some(id) => id,
        None => store.empty_tree()?,
    }))
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
