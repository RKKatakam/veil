//! Choosing part of a change: the files, hunks and executable-bit changes
//! `vl split` and `vl squash` move (ARCHITECTURE §5, "Shaping history").
//!
//! A change is listed as **units** ([`Unit`]): one per changed file, or one
//! per file/directory swap (a file replaced by a directory of the same name,
//! or the reverse, is one unit: its halves cannot be taken apart). Each unit
//! is either **text**, whose hunks ([`crate::hunks`]) and executable-bit
//! change can be chosen one by one, or **whole**, taken or left as it is
//! ([`Whole`] says why). From a [`Selection`], [`halves`] builds two trees
//! on the change's base: the base with what was chosen, and the base with
//! the rest.
//!
//! **Audiences** (ARCHITECTURE §4 rule 5). Choosing never changes who can
//! read anything:
//!
//! * a whole unit's halves are its entries exactly as recorded (same
//!   object, same sealing, same fallback): no content is read or sealed;
//! * a text unit is offered by hunk only when this reader can read both
//!   versions (a version it cannot read makes the file whole: a reader
//!   cannot choose lines it cannot see), when both labels are verified
//!   against their objects (`builder::verify_sealing`), when neither is
//!   under an embargo, and when the new version's audience holds the old
//!   one's (the old one public, or sealed exactly as the new one). A file in
//!   between holds lines of both versions; it is sealed exactly as the new
//!   version (its scope, and its fallback: the last public version, so the
//!   public fallback rules still hold). Lines of a version sealed for `s`
//!   therefore never end up in a file readable by anyone outside `s`.
//!   A version moved to a wider or another audience (an exposure, a
//!   re-key) is whole;
//! * a half that comes out equal to one of the versions is that version's
//!   entry itself, so a file is never resealed when nothing in it changed;
//! * conflicts (format 4 entries, and older marker conflicts listed on the
//!   snapshot) are whole, and so is `.veilpolicy` (a policy in between,
//!   never written by anyone, would decide audiences).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::{
    builder::{verify_sealing, Sealing},
    error::{Result, VeilError},
    hunks::{apply, diff_text, BlockId, TextDiff},
    id::ObjectId,
    object::{EntryKind, Tree, TreeEntry, Visibility},
    policy::POLICY_FILE,
    secrets::looks_binary,
    store::ObjectStore,
    tree::{diff_trees, TreeChange, MAX_TREE_DEPTH},
    vpath::VPath,
};

/// Why a unit can only be taken whole.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Whole {
    /// A file is replaced by a directory, or the reverse.
    TypeChange,
    /// Binary content (a NUL byte) on either side.
    Binary,
    /// Not UTF-8 text.
    NotText,
    /// A version this reader cannot read: sealed for this scope.
    Unreadable(String),
    /// A version whose content is not in this repository (withheld by a
    /// public remote, or removed).
    Missing,
    /// A file in between would be sealed for this scope, and this reader
    /// holds no current key for it (a revoked member reading an older key
    /// generation).
    NoSealingKey(String),
    /// An unresolved conflict on either side.
    Conflict,
    /// Under an embargo.
    Embargoed,
    /// The versions have different audiences (exposed, cloaked or
    /// re-keyed by this change).
    Audience,
    /// A label that does not match its object.
    Unverified,
    /// The policy file.
    Policy,
    /// Only the executable bit changes.
    ModeOnly,
    /// An empty file added or deleted.
    Empty,
}

impl Whole {
    /// The machine-readable reason (`--json`).
    pub fn word(&self) -> &'static str {
        match self {
            Whole::TypeChange => "type_change",
            Whole::Binary => "binary",
            Whole::NotText => "not_text",
            Whole::Unreadable(_) => "unreadable",
            Whole::Missing => "missing",
            Whole::NoSealingKey(_) => "no_sealing_key",
            Whole::Conflict => "conflict",
            Whole::Embargoed => "embargoed",
            Whole::Audience => "audience",
            Whole::Unverified => "unverified",
            Whole::Policy => "policy",
            Whole::ModeOnly => "mode_only",
            Whole::Empty => "empty",
        }
    }

    /// Why, for people.
    pub fn why(&self) -> String {
        match self {
            Whole::TypeChange => "a file and a directory swap places".into(),
            Whole::Binary => "binary".into(),
            Whole::NotText => "not UTF-8 text".into(),
            Whole::Unreadable(s) => format!("sealed for '{s}', which you cannot read"),
            Whole::Missing => "its content is not in this repository".into(),
            Whole::NoSealingKey(s) => format!("you hold no current key of '{s}' to seal a part of it"),
            Whole::Conflict => "conflicted (a conflict moves whole; resolve it to split it)".into(),
            Whole::Embargoed => "under an embargo".into(),
            Whole::Audience => "its audience changes in this change".into(),
            Whole::Unverified => "its visibility label does not match its content".into(),
            Whole::Policy => "the visibility policy".into(),
            Whole::ModeOnly => "executable bit only".into(),
            Whole::Empty => "empty file".into(),
        }
    }
}

/// How a unit can be chosen.
#[derive(Clone, Debug)]
pub enum Content {
    /// Not looked at yet ([`classify`]): it can be taken whole.
    Pending,
    Whole(Whole),
    Text(TextUnit),
}

/// A text file whose hunks can be chosen.
#[derive(Clone, Debug)]
pub struct TextUnit {
    pub old: String,
    pub new: String,
    pub diff: TextDiff,
    /// The executable bit changes too (`(old, new)`): a choice of its own.
    pub mode: Option<(bool, bool)>,
}

/// One changed file (or file/directory swap) of a change.
#[derive(Clone, Debug)]
pub struct Unit {
    /// The file, or for a swap the name both kinds share.
    pub path: VPath,
    /// The file-level changes it covers (one, except for a swap), in
    /// [`diff_trees`] order.
    pub changes: Vec<TreeChange>,
    pub content: Content,
}

impl Unit {
    /// `A`, `D` or `M`, as `vl status` shows the unit's own path (a swap is
    /// `M`).
    pub fn status(&self) -> char {
        match self.changes.as_slice() {
            [c] => c.status(),
            _ => 'M',
        }
    }

    /// The text unit, if its hunks can be chosen.
    pub fn text(&self) -> Option<&TextUnit> {
        match &self.content {
            Content::Text(t) => Some(t),
            Content::Whole(_) | Content::Pending => None,
        }
    }

    /// Every choice the unit offers, taken.
    pub fn everything(&self) -> Pick {
        match &self.content {
            Content::Whole(_) | Content::Pending => Pick { whole: true, ..Pick::default() },
            Content::Text(t) => Pick { whole: false, mode: t.mode.is_some(), blocks: t.diff.all_blocks() },
        }
    }

    /// Does `pick` take everything this unit changes?
    pub fn is_all(&self, pick: &Pick) -> bool {
        pick.whole || (!self.is_none(pick) && *pick == self.everything())
    }

    /// Does `pick` take nothing?
    pub fn is_none(&self, pick: &Pick) -> bool {
        !pick.whole && !pick.mode && pick.blocks.is_empty()
    }
}

/// What is chosen of one unit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pick {
    /// The whole unit (any kind).
    pub whole: bool,
    /// The executable-bit change of a text unit.
    pub mode: bool,
    /// Blocks of a text unit.
    pub blocks: BTreeSet<BlockId>,
}

/// What is chosen, by unit path. Units not named are left.
pub type Selection = BTreeMap<VPath, Pick>;

/// The file-level changes from `from` to `to`, as units, without reading
/// any content (every unit [`Content::Pending`], or whole for a
/// file/directory swap; see [`classify`]). Trees under an embargo wrapper are refused.
pub fn units(store: &ObjectStore, from: &ObjectId, to: &ObjectId) -> Result<Vec<Unit>> {
    for t in [from, to] {
        if crate::embargo::wrapper_of(store, t)?.is_some() {
            return Err(VeilError::Policy(
                "this change is under an embargo: it can only be squashed whole (`vl squash` with no paths)".into(),
            ));
        }
    }
    let changes = diff_trees(store, Some(from), Some(to))?;
    let file_paths: BTreeSet<VPath> = changes.iter().map(|c| c.path.clone()).collect();
    // The highest changed path that is a proper ancestor of `p`: `p` is
    // part of that file/directory swap.
    let swap_of = |p: &VPath| -> Option<VPath> {
        let mut cur = p.parent();
        let mut found = None;
        while let Some(a) = cur {
            if a.is_root() {
                break;
            }
            if file_paths.contains(&a) {
                found = Some(a.clone());
            }
            cur = a.parent();
        }
        found
    };
    let mut out: Vec<Unit> = Vec::new();
    let mut index: HashMap<VPath, usize> = HashMap::new();
    for c in changes {
        let key = swap_of(&c.path).unwrap_or_else(|| c.path.clone());
        match index.get(&key) {
            Some(&i) => {
                out[i].changes.push(c);
                out[i].content = Content::Whole(Whole::TypeChange);
            }
            None => {
                index.insert(key.clone(), out.len());
                out.push(Unit { path: key, changes: vec![c], content: Content::Pending });
            }
        }
    }
    for u in &mut out {
        if u.changes.len() > 1 || u.changes[0].path != u.path {
            u.content = Content::Whole(Whole::TypeChange);
        }
    }
    Ok(out)
}

/// Decide how `unit` can be chosen, reading its versions if needed (see
/// the module documentation). `conflicted` lists the paths the change
/// records as conflicted (marker conflicts of older formats).
pub fn classify(store: &ObjectStore, unit: &mut Unit, conflicted: &[String]) -> Result<()> {
    if matches!(unit.content, Content::Whole(Whole::TypeChange)) {
        return Ok(());
    }
    unit.content = classify_change(store, &unit.changes[0], conflicted)?;
    Ok(())
}

fn classify_change(store: &ObjectStore, c: &TreeChange, conflicted: &[String]) -> Result<Content> {
    let whole = |w| Ok(Content::Whole(w));
    if c.path.as_str() == POLICY_FILE {
        return whole(Whole::Policy);
    }
    let sides = [c.old.as_ref(), c.new.as_ref()];
    if sides.iter().flatten().any(|e| e.kind == EntryKind::Conflict) || conflicted.iter().any(|p| p == c.path.as_str()) {
        return whole(Whole::Conflict);
    }
    if sides.iter().flatten().any(|e| matches!(e.visibility, Visibility::Embargoed { .. })) {
        return whole(Whole::Embargoed);
    }
    for e in sides.iter().flatten() {
        if !matches!(verify_sealing(store, e)?, Sealing::Verified) {
            return whole(Whole::Unverified);
        }
    }
    if let (Some(o), Some(n)) = (&c.old, &c.new) {
        if !(o.visibility.is_public() || o.visibility == n.visibility) {
            return whole(Whole::Audience);
        }
    }
    // The object itself, never a fallback: the lines chosen must be the
    // version's own.
    let read = |e: Option<&TreeEntry>| -> Result<Result<Vec<u8>, Whole>> {
        let Some(e) = e else { return Ok(Ok(Vec::new())) };
        match store.read_blob(&e.id) {
            Ok(d) => Ok(Ok(d)),
            Err(err) if err.is_not_found() || matches!(err, VeilError::Missing(_)) => Ok(Err(Whole::Missing)),
            Err(err) if err.is_unreadable() => match e.visibility.key_scope() {
                Some(scope) => Ok(Err(Whole::Unreadable(scope))),
                None => Ok(Err(Whole::Missing)),
            },
            Err(err) => Err(err),
        }
    };
    let (old, new) = match (read(c.old.as_ref())?, read(c.new.as_ref())?) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(w), _) | (_, Err(w)) => return whole(w),
    };
    if looks_binary(&old) || looks_binary(&new) {
        return whole(Whole::Binary);
    }
    let (Ok(old), Ok(new)) = (String::from_utf8(old), String::from_utf8(new)) else {
        return whole(Whole::NotText);
    };
    // A file in between is sealed as the new version (the old one, for a
    // deletion): this reader must be able to seal for that scope now.
    if let Some(Visibility::Cloaked { scope }) = c.new.as_ref().or(c.old.as_ref()).map(|e| &e.visibility) {
        if store.keys.sealing_key(scope).is_err() {
            return whole(Whole::NoSealingKey(scope.clone()));
        }
    }
    let mode = match (&c.old, &c.new) {
        (Some(o), Some(n)) if o.executable != n.executable => Some((o.executable, n.executable)),
        _ => None,
    };
    let diff = diff_text(&old, &new);
    if diff.is_empty() {
        return whole(if mode.is_some() { Whole::ModeOnly } else { Whole::Empty });
    }
    Ok(Content::Text(TextUnit { old, new, diff, mode }))
}

/// The two halves of a change from `base`: the base with what `sel`
/// chooses, and the base with the rest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Halves {
    pub chosen: ObjectId,
    pub rest: ObjectId,
    /// Something is chosen.
    pub any: bool,
    /// Everything is chosen (`rest` is the base).
    pub all: bool,
}

/// Build the [`Halves`] of the change from `base` to `tree` that `units`
/// lists. `sel` should come from [`select`] (or a picker) over `units`. When
/// everything (or nothing) is chosen, the halves are `tree` and `base`
/// themselves.
pub fn halves(store: &ObjectStore, base: &ObjectId, tree: &ObjectId, units: &[Unit], sel: &Selection) -> Result<Halves> {
    let none = Pick::default();
    let picks: Vec<&Pick> = units.iter().map(|u| sel.get(&u.path).unwrap_or(&none)).collect();
    let any = units.iter().zip(&picks).any(|(u, p)| !u.is_none(p));
    let all = units.iter().zip(&picks).all(|(u, p)| u.is_all(p));
    if all {
        return Ok(Halves { chosen: *tree, rest: *base, any: !units.is_empty(), all: true });
    }
    if !any {
        return Ok(Halves { chosen: *base, rest: *tree, any: false, all: false });
    }
    let (mut chosen, mut rest) = (Vec::new(), Vec::new());
    for (u, pick) in units.iter().zip(picks) {
        let (to_chosen, to_rest) = if u.is_all(pick) {
            (true, false)
        } else if u.is_none(pick) {
            (false, true)
        } else {
            let t = u.text().expect("a partial pick is of a text unit");
            let c = &u.changes[0];
            let complement: BTreeSet<BlockId> = t.diff.all_blocks().difference(&pick.blocks).copied().collect();
            chosen.push((c.path.clone(), part(store, c, t, &pick.blocks, pick.mode)?));
            rest.push((c.path.clone(), part(store, c, t, &complement, t.mode.is_some() && !pick.mode)?));
            continue;
        };
        for c in &u.changes {
            if to_chosen {
                chosen.push((c.path.clone(), c.new.clone()));
            }
            if to_rest {
                rest.push((c.path.clone(), c.new.clone()));
            }
        }
    }
    Ok(Halves { chosen: edit_tree(store, base, chosen)?, rest: edit_tree(store, base, rest)?, any, all })
}

/// The file between the two versions of `c` that has `blocks` (and the
/// executable-bit change if `mode`) applied to the old one; `None` for no
/// file.
fn part(store: &ObjectStore, c: &TreeChange, t: &TextUnit, blocks: &BTreeSet<BlockId>, mode: bool) -> Result<Option<TreeEntry>> {
    let data = apply(&t.old, &t.diff, |id| blocks.contains(&id));
    let n_blocks = t.diff.all_blocks().len();
    let (template, executable) = match (&c.old, &c.new) {
        (None, Some(_)) if blocks.is_empty() => return Ok(None),
        (None, Some(n)) => (n, n.executable),
        (Some(_), None) if blocks.len() == n_blocks => return Ok(None),
        (Some(o), None) => (o, o.executable),
        (Some(o), Some(n)) => (n, if mode { n.executable } else { o.executable }),
        (None, None) => return Ok(None),
    };
    // Equal to a version: that version's entry (its object, its sealing).
    for (e, text) in [(&c.old, &t.old), (&c.new, &t.new)] {
        if let Some(e) = e {
            if data == *text {
                return Ok(Some(TreeEntry { executable, ..e.clone() }));
            }
        }
    }
    // Lines of both versions, sealed exactly as the new one (`classify`
    // allowed this only where that audience holds the old one's).
    let id = store.store_file(data.as_bytes(), &template.visibility)?;
    Ok(Some(TreeEntry {
        name: template.name.clone(),
        kind: EntryKind::File,
        id,
        size: data.len() as u64,
        executable,
        visibility: template.visibility.clone(),
        fallback: template.fallback,
    }))
}

/// `tree` with each path set to its entry (removed for `None`; directories
/// are created as needed, and left empty, removed).
pub fn edit_tree(store: &ObjectStore, tree: &ObjectId, edits: Vec<(VPath, Option<TreeEntry>)>) -> Result<ObjectId> {
    let mut list = Vec::with_capacity(edits.len());
    for (p, e) in edits {
        let comps: Vec<String> = p.components().map(str::to_string).collect();
        if comps.is_empty() || comps.len() > MAX_TREE_DEPTH {
            return Err(VeilError::InvalidPath(p.to_string()));
        }
        list.push((comps, e));
    }
    match edit_dir(store, Some(tree), &list)? {
        Some(id) => Ok(id),
        None => store.empty_tree(),
    }
}

type Edit = (Vec<String>, Option<TreeEntry>);

fn edit_dir(store: &ObjectStore, dir: Option<&ObjectId>, edits: &[Edit]) -> Result<Option<ObjectId>> {
    let mut t: Tree = match dir {
        Some(id) => (*store.tree(id)?).clone(),
        None => Tree::default(),
    };
    // Per child name: the entry set at that name itself, and the edits
    // below it.
    let mut by_name: BTreeMap<&str, (Option<&Option<TreeEntry>>, Vec<Edit>)> = BTreeMap::new();
    for (comps, e) in edits {
        let slot = by_name.entry(comps[0].as_str()).or_default();
        if comps.len() == 1 {
            slot.0 = Some(e);
        } else {
            slot.1.push((comps[1..].to_vec(), e.clone()));
        }
    }
    for (name, (direct, nested)) in by_name {
        let current = t.get(name).cloned();
        if nested.is_empty() {
            match direct.cloned().flatten() {
                Some(e) => t.insert(TreeEntry { name: name.to_string(), ..e }),
                None => {
                    t.remove(name);
                }
            }
            continue;
        }
        let sub = current.as_ref().filter(|e| e.kind == EntryKind::Dir).map(|e| e.id);
        let file = direct.cloned().flatten().filter(|e| e.kind != EntryKind::Dir);
        match edit_dir(store, sub.as_ref(), &nested)? {
            Some(id) if file.is_none() => t.insert(TreeEntry::dir(name, id)),
            Some(_) => return Err(VeilError::repo(format!("cannot place both a file and a directory at '{name}'"))),
            None => match file {
                Some(e) => t.insert(TreeEntry { name: name.to_string(), ..e }),
                None => {
                    t.remove(name);
                }
            },
        }
    }
    if t.is_empty() {
        return Ok(None);
    }
    Ok(Some(store.put_tree(&t)?))
}

/// A path the caller names, with the hunks it chooses (`None`: all of it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spec {
    pub path: VPath,
    pub hunks: Option<Vec<HunkRef>>,
}

/// One choice inside a file: hunk `N` (1-based), block `M` of hunk `N`
/// (`N.M`), or the executable-bit change (`mode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HunkRef {
    Hunk(usize),
    Block(usize, usize),
    Mode,
}

impl HunkRef {
    /// Parse `3`, `3.1` or `mode`.
    pub fn parse(s: &str) -> Result<HunkRef> {
        let s = s.trim();
        let bad = || VeilError::repo(format!("'{s}' is not a hunk: use N (hunk N, from 1), N.M (block M of hunk N) or `mode`"));
        if s == "mode" {
            return Ok(HunkRef::Mode);
        }
        let num = |x: &str| x.parse::<usize>().ok().filter(|n| *n >= 1).ok_or_else(bad);
        match s.split_once('.') {
            Some((h, b)) => Ok(HunkRef::Block(num(h)?, num(b)?)),
            None => Ok(HunkRef::Hunk(num(s)?)),
        }
    }
}

impl std::fmt::Display for HunkRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HunkRef::Hunk(h) => write!(f, "{h}"),
            HunkRef::Block(h, b) => write!(f, "{h}.{b}"),
            HunkRef::Mode => write!(f, "mode"),
        }
    }
}

/// Turn what the caller named into a [`Selection`] over `units`. A path
/// with no hunks takes every unit at or below it (a directory names all
/// its files); a path with hunks must be one text unit. Anything that
/// names nothing, or a hunk a unit does not have, is an error, so a script
/// never splits differently from what it asked.
pub fn select(units: &[Unit], specs: &[Spec]) -> Result<Selection> {
    let mut sel = Selection::new();
    for s in specs {
        let Some(hunks) = &s.hunks else {
            let mut found = false;
            for u in units.iter().filter(|u| u.path.starts_with(&s.path)) {
                sel.insert(u.path.clone(), Pick { whole: true, ..Pick::default() });
                found = true;
            }
            if !found {
                // Inside a file/directory swap: only the swap as a whole.
                if let Some(u) = units.iter().find(|u| s.path.starts_with(&u.path)) {
                    return Err(VeilError::repo(format!(
                        "{} is part of a file/directory swap at {}: choose {} as a whole",
                        s.path, u.path, u.path
                    )));
                }
                return Err(VeilError::NotFound(format!("changes at {} in this change", display(&s.path))));
            }
            continue;
        };
        let Some(u) = units.iter().find(|u| u.path == s.path) else {
            return Err(VeilError::NotFound(format!("a changed file {} in this change", display(&s.path))));
        };
        let t = match &u.content {
            Content::Text(t) => t,
            Content::Pending => return Err(VeilError::repo(format!("{}: its hunks were not read", u.path))),
            Content::Whole(w) => {
                return Err(VeilError::repo(format!("{} cannot be split by hunk ({}): name it without hunks to take it whole", u.path, w.why())))
            }
        };
        let pick = sel.entry(u.path.clone()).or_default();
        if pick.whole {
            continue;
        }
        for h in hunks {
            let missing = || VeilError::repo(format!("{} has no hunk {h} (it has {} hunks)", u.path, t.diff.hunks.len()));
            match *h {
                HunkRef::Mode if t.mode.is_some() => pick.mode = true,
                HunkRef::Mode => return Err(VeilError::repo(format!("{}: its executable bit does not change", u.path))),
                HunkRef::Hunk(n) => {
                    let hunk = t.diff.hunks.get(n - 1).ok_or_else(missing)?;
                    pick.blocks.extend((0..hunk.blocks.len()).map(|b| (n - 1, b)));
                }
                HunkRef::Block(n, m) => {
                    let hunk = t.diff.hunks.get(n - 1).ok_or_else(missing)?;
                    if m > hunk.blocks.len() {
                        return Err(VeilError::repo(format!("{}: hunk {n} has no block {m} (it has {})", u.path, hunk.blocks.len())));
                    }
                    pick.blocks.insert((n - 1, m - 1));
                }
            }
        }
    }
    Ok(sel)
}

fn display(p: &VPath) -> String {
    if p.is_root() {
        "the repository root".into()
    } else {
        p.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hunk_refs_parse() {
        assert_eq!(HunkRef::parse("3").unwrap(), HunkRef::Hunk(3));
        assert_eq!(HunkRef::parse(" 2.1").unwrap(), HunkRef::Block(2, 1));
        assert_eq!(HunkRef::parse("mode").unwrap(), HunkRef::Mode);
        for bad in ["0", "1.0", "x", "", "1.", ".2", "-1"] {
            assert!(HunkRef::parse(bad).is_err(), "{bad}");
        }
    }
}
