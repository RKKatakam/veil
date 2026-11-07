//! `vl blame`: line attribution through history, reading every version as
//! this reader may see it ([`readable_version`]).
//!
//! # Reading as a reader
//!
//! Every history read tool (blame, `vl grep`, the `-S`/`-G` log filters,
//! inexact rename detection) reads file content through one function,
//! [`readable_version`]. It never hands a sealed object to the decrypter
//! unless the envelope's label (bound to the ciphertext) names a key this
//! reader holds, and it never returns ciphertext:
//!
//! * [`Readable::Plain`]: public content, or a sealed secret file this
//!   reader opens (with [`Reader::Public`], plaintext only: what a public
//!   mirror holds);
//! * [`Readable::Redacted`]: nothing, and why.
//!
//! # The walk
//!
//! Lines of the file at the starting snapshot are open until attributed.
//! Snapshots are visited in topological order, children before parents
//! ([`Repo::topo_children_first`]), each once, with every line its children
//! passed it (threat review 5: no snapshot is visited twice, whatever the
//! timestamps say). A snapshot's version is compared
//! with each parent's in order; a line the parent holds moves to the first
//! parent that holds it, the rest are attributed to the snapshot. A parent
//! whose readable version is identical (same object, or same bytes) takes
//! every open line without a diff. A parent whose version is
//! redacted stops the lines it might hold: they are reported unattributed
//! ("history sealed for …"), never guessed.
//!
//! # Limits
//!
//! Each diff is bounded as in [`crate::textmerge`] (BUG-484): past its work
//! limit the differing middle is attributed whole to the snapshot, and the
//! result says [`Blame::coarse`]. The walk stops after
//! [`BlameOptions::max_changes`] visits or when its work passes
//! [`BlameOptions::work_budget`]; lines still open are reported
//! unattributed. Work is what each step really cost: the lines read and
//! compared, plus each diff's search (`D²` for `D` differing lines, the
//! whole [`textmerge::work_limit`] for a diff past it). A single diff is
//! bounded, so the budget is overshot by at most one.

use std::{
    cmp::Ordering,
    collections::{BinaryHeap, HashMap},
    sync::Arc,
};

use crate::{
    builder::object_visibility,
    conflict::{self, Audience},
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Object, Text, TreeEntry, Visibility},
    rename::{self, RenameOptions},
    repo::Repo,
    store::ObjectStore,
    textmerge,
    tree::{diff_trees, lookup},
    vpath::VPath,
};

// ---- reading as a reader ---------------------------------------------------------

/// Whose eyes a history tool reads with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Reader {
    /// This repository's keychain: whatever its keys open.
    #[default]
    Me,
    /// A public mirror: plaintext objects, and no history an unreleased
    /// embargo withholds (the `--public` view).
    Public,
}

/// A file entry as one reader may read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Readable {
    /// The entry's own content. `id` is the object read (for a conflict,
    /// the blob id of its materialisation); `visibility` is what that
    /// object proves (labels are claims, BUG-482): `Public` for plaintext.
    Plain { id: ObjectId, data: Vec<u8>, visibility: Visibility },
    /// Nothing this reader may see.
    Redacted(Hidden),
}

impl Readable {
    /// The bytes read, unless redacted.
    pub fn data(&self) -> Option<&[u8]> {
        match self {
            Readable::Plain { data, .. } => Some(data),
            Readable::Redacted(_) => None,
        }
    }

    /// The object read, unless redacted. Equal ids mean equal content.
    pub fn id(&self) -> Option<ObjectId> {
        match self {
            Readable::Plain { id, .. } => Some(*id),
            Readable::Redacted(_) => None,
        }
    }

    pub fn is_plain(&self) -> bool {
        matches!(self, Readable::Plain { .. })
    }
}

/// Why a version is not readable, and for whom it is (labels are public
/// metadata; never the content).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hidden {
    pub reason: HiddenReason,
    /// Who can read it: what the object proves when it is present, the
    /// entry's label otherwise.
    pub visibility: Visibility,
}

/// The words of [`crate::store`]'s callers (`vl ls`, `vl diff`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenReason {
    /// Sealed for a scope this reader holds no key for.
    NoKey,
    /// Sealed, and absent here: a public remote never delivered it.
    Withheld,
    /// Sealed, and the reader is [`Reader::Public`].
    PublicView,
    /// A public object absent from the store (damage, not a redaction).
    Missing,
    /// Not a file (a directory, or an entry kind this build reads no
    /// content of).
    NotAFile,
}

impl HiddenReason {
    pub fn as_str(self) -> &'static str {
        match self {
            HiddenReason::NoKey => "no_key",
            HiddenReason::Withheld => "withheld",
            HiddenReason::PublicView => "public_view",
            HiddenReason::Missing => "missing",
            HiddenReason::NotAFile => "not_a_file",
        }
    }
}

/// What the readers did, for tests and reports: no content, no ids.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadStats {
    /// Sealed objects opened (the label named a key this reader holds).
    pub sealed_opened: u64,
    /// Sealed objects left closed after the label check (no key, or the
    /// public view).
    pub sealed_skipped: u64,
    /// Opens the keychain refused although the label check passed (a
    /// damaged envelope). Never expected.
    pub open_failed: u64,
}

impl ReadStats {
    pub fn add(&mut self, o: &ReadStats) {
        self.sealed_opened += o.sealed_opened;
        self.sealed_skipped += o.sealed_skipped;
        self.open_failed += o.open_failed;
    }
}

/// A description as a public mirror reads it (descriptions are plain
/// text). For `--public` views.
pub fn public_description(_store: &ObjectStore, t: &Text) -> Option<String> {
    Some(t.as_str().to_string())
}

/// File entry `e` as `reader` may read it (see the module docs).
pub fn readable_version(store: &ObjectStore, e: &TreeEntry, reader: Reader) -> Result<Readable> {
    readable_version_counted(store, e, reader, &mut ReadStats::default())
}

/// [`readable_version`], counting what it opened in `stats`.
pub fn readable_version_counted(store: &ObjectStore, e: &TreeEntry, reader: Reader, stats: &mut ReadStats) -> Result<Readable> {
    match e.kind {
        EntryKind::File => {
            if let Some((data, visibility)) = open_readable(store, &e.id, reader, stats)? {
                return Ok(Readable::Plain { id: e.id, data, visibility });
            }
            Ok(Readable::Redacted(hidden(store, e, reader)))
        }
        EntryKind::Conflict => {
            // The file with markers this reader is shown: versions it cannot
            // read are left out by the materialisation itself.
            let audience = match reader {
                Reader::Me => Audience::Reader,
                Reader::Public => Audience::Public,
            };
            match conflict::materialize_entry(store, e, audience) {
                Ok(m) => Ok(Readable::Plain { id: Object::blob_id(&m.content), data: m.content, visibility: m.visibility }),
                Err(err) if err.is_unreadable() || err.is_not_found() => Ok(Readable::Redacted(hidden(store, e, reader))),
                Err(err) => Err(err),
            }
        }
        _ => Ok(Readable::Redacted(Hidden { reason: HiddenReason::NotAFile, visibility: e.visibility.clone() })),
    }
}

/// The plaintext of object `id` and what it proves about its audience, if
/// `reader` may open it; `None` otherwise. A sealed object is opened only
/// after its label names a key this reader holds.
fn open_readable(store: &ObjectStore, id: &ObjectId, reader: Reader, stats: &mut ReadStats) -> Result<Option<(Vec<u8>, Visibility)>> {
    let raw = match store.get_raw(id) {
        Ok(r) => r,
        Err(err) if err.is_unreadable() || err.is_not_found() => return Ok(None),
        Err(err) => return Err(err),
    };
    if Object::is_blob_raw(&raw) {
        return match Object::decode(&raw)? {
            Object::Blob(b) => Ok(Some((b, Visibility::Public))),
            o => Err(VeilError::Corrupt(id.hex(), format!("expected blob, found {}", o.kind_name()))),
        };
    }
    let Some(label) = Object::sealed_scope(&raw) else {
        // Neither a blob nor a sealed object: not file content.
        return Ok(None);
    };
    drop(raw);
    // A public reader never opens a sealed (secret) file.
    let allowed = reader == Reader::Me && store.keys.has(&label);
    if !allowed {
        stats.sealed_skipped += 1;
        return Ok(None);
    }
    stats.sealed_opened += 1;
    match store.read_blob(id) {
        Ok(data) => {
            let vis = object_visibility(&store.get_raw(id)?).unwrap_or(Visibility::Cloaked { scope: label });
            Ok(Some((data, vis)))
        }
        Err(err) if err.is_unreadable() => {
            stats.open_failed += 1;
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn hidden(store: &ObjectStore, e: &TreeEntry, reader: Reader) -> Hidden {
    let raw = store.get_raw(&e.id).ok();
    let visibility = raw.as_deref().and_then(object_visibility).unwrap_or_else(|| e.visibility.clone());
    let label_held = raw.as_deref().and_then(Object::sealed_scope).is_some_and(|l| store.keys.has(&l));
    let reason = match (&raw, &visibility) {
        (None, Visibility::Public) => HiddenReason::Missing,
        (None, _) => HiddenReason::Withheld,
        (Some(_), _) if reader == Reader::Public && label_held => HiddenReason::PublicView,
        (Some(_), _) => HiddenReason::NoKey,
    };
    Hidden { reason, visibility }
}

// ---- line mapping ------------------------------------------------------------------

/// Byte ranges of the lines of `data`, as diffy splits them (each with its
/// `\n`; a last line without one is a line too).
pub(crate) fn line_ranges(data: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = 0;
    for l in data.split_inclusive(|b| *b == b'\n') {
        out.push((start, start + l.len()));
        start += l.len();
    }
    out
}

/// Where each line of `new` comes from in `old` (`None`: not there), and
/// whether the diff was past its work limit (then only the lines both
/// share at the start and at the end are mapped).
pub(crate) fn map_lines(old: &[u8], new: &[u8], new_lines: usize) -> (Vec<Option<u32>>, bool) {
    let mut map: Vec<Option<u32>> = vec![None; new_lines];
    if !textmerge::fits(old, new) {
        let a: Vec<&[u8]> = old.split_inclusive(|b| *b == b'\n').collect();
        let b: Vec<&[u8]> = new.split_inclusive(|b| *b == b'\n').collect();
        let p = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
        let s = a[p..].iter().rev().zip(b[p..].iter().rev()).take_while(|(x, y)| x == y).count();
        for (i, m) in map.iter_mut().enumerate().take(p) {
            *m = Some(i as u32);
        }
        for k in 0..s {
            map[b.len() - 1 - k] = Some((a.len() - 1 - k) as u32);
        }
        return (map, true);
    }
    let patch = diffy::DiffOptions::new().set_context_len(0).create_patch_bytes(old, new);
    // Lines outside hunks are equal, in order.
    let (mut oi, mut ni) = (0usize, 0usize);
    for h in patch.hunks() {
        let ostart = if !h.old_range().is_empty() { h.old_range().start() - 1 } else { h.old_range().start() };
        let nstart = if !h.new_range().is_empty() { h.new_range().start() - 1 } else { h.new_range().start() };
        while ni < nstart && ni < new_lines {
            map[ni] = Some(oi as u32);
            ni += 1;
            oi += 1;
        }
        oi = ostart;
        for l in h.lines() {
            match l {
                diffy::Line::Context(_) => {
                    if ni < new_lines {
                        map[ni] = Some(oi as u32);
                    }
                    ni += 1;
                    oi += 1;
                }
                diffy::Line::Delete(_) => oi += 1,
                diffy::Line::Insert(_) => ni += 1,
            }
        }
    }
    while ni < new_lines {
        map[ni] = Some(oi as u32);
        ni += 1;
        oi += 1;
    }
    (map, false)
}

// ---- blame -------------------------------------------------------------------------

/// Default for [`BlameOptions::max_changes`].
pub const DEFAULT_MAX_CHANGES: usize = 100_000;
/// Default for [`BlameOptions::work_budget`]: about 2 s of the worst case
/// (every step a diff past its work limit) in a release build, and some
/// ten thousand steps of ordinary edits to a 20 000-line file. (Threat
/// review 4 asks for lines × snapshots ≤ 2³²; this is tighter, because
/// it also counts the diffs.)
pub const DEFAULT_WORK_BUDGET: u64 = 1 << 29;

#[derive(Clone, Debug)]
pub struct BlameOptions {
    pub reader: Reader,
    /// Follow the file across renames ([`rename::detect`] where the path
    /// first appears).
    pub follow: bool,
    /// Visits of a snapshot allowed before the walk stops.
    pub max_changes: usize,
    /// Work allowed: lines read and compared, plus the worst-case cost of
    /// each line diff ([`textmerge::work_limit`]).
    pub work_budget: u64,
    /// Only these lines (1-based, inclusive) of the file are attributed.
    pub lines: Option<(usize, usize)>,
    /// Rename detection for `follow`.
    pub renames: RenameOptions,
}

impl Default for BlameOptions {
    fn default() -> Self {
        BlameOptions {
            reader: Reader::Me,
            follow: false,
            max_changes: DEFAULT_MAX_CHANGES,
            work_budget: DEFAULT_WORK_BUDGET,
            lines: None,
            renames: RenameOptions::default(),
        }
    }
}

/// Why a line has no change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unattributed {
    /// The version it would move to cannot be read by this reader.
    Sealed(Visibility),
    /// [`BlameOptions::max_changes`] was reached.
    MaxChanges,
    /// [`BlameOptions::work_budget`] was spent.
    Budget,
}

impl Unattributed {
    pub fn as_str(&self) -> &'static str {
        match self {
            Unattributed::Sealed(_) => "sealed",
            Unattributed::MaxChanges => "max_changes",
            Unattributed::Budget => "budget",
        }
    }
}

/// Where a line comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The snapshot that introduced the line, and the file's path there.
    Snapshot { id: ObjectId, path: VPath },
    Unattributed(Unattributed),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlameLine {
    /// 1-based, in the file at the starting snapshot.
    pub number: usize,
    /// The line, with its line break.
    pub text: Vec<u8>,
    pub origin: Origin,
}

/// Why the walk stopped before every line was attributed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    MaxChanges,
    Budget,
}

#[derive(Clone, Debug)]
pub struct Blame {
    pub path: VPath,
    pub rev: ObjectId,
    pub lines: Vec<BlameLine>,
    /// Some diff was past its work limit: a differing middle was attributed
    /// whole.
    pub coarse: bool,
    pub stopped: Option<Stop>,
    /// Snapshot visits.
    pub visited: usize,
    pub stats: ReadStats,
}

impl Blame {
    pub fn unattributed(&self) -> usize {
        self.lines.iter().filter(|l| matches!(l.origin, Origin::Unattributed(_))).count()
    }
}

/// A file version being walked.
struct Version {
    id: ObjectId,
    data: Vec<u8>,
    lines: Vec<(usize, usize)>,
}

impl Version {
    fn new(id: ObjectId, data: Vec<u8>) -> Arc<Version> {
        let lines = line_ranges(&data);
        Arc::new(Version { id, data, lines })
    }
}

/// Open lines waiting at a snapshot: (line of the result, line of this
/// version).
struct Pending {
    lines: Vec<(u32, u32)>,
    version: Arc<Version>,
}

/// A snapshot (and the file's name there) waiting to be visited; the
/// heap pops the lowest topological rank (children first) first.
#[derive(PartialEq, Eq)]
struct Queued {
    rank: usize,
    id: ObjectId,
    path: VPath,
}

impl Ord for Queued {
    fn cmp(&self, o: &Self) -> Ordering {
        o.rank.cmp(&self.rank).then_with(|| o.path.as_str().cmp(self.path.as_str()))
    }
}

impl PartialOrd for Queued {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

/// Topological ranks (children first, as [`Repo::topo_children_first`]
/// numbers them), produced only as far as they are asked for.
struct LazyRank<'r> {
    iter: crate::graph_index::TopoIter<'r>,
    ranks: HashMap<ObjectId, usize>,
}

impl LazyRank<'_> {
    fn of(&mut self, id: &ObjectId) -> Result<Option<usize>> {
        while !self.ranks.contains_key(id) {
            match self.iter.next() {
                Some(next) => {
                    let n = self.ranks.len();
                    self.ranks.insert(next?, n);
                }
                None => break,
            }
        }
        Ok(self.ranks.get(id).copied())
    }
}

/// The version of the file at `path` in `tree` this reader reads, `None`
/// when there is no file there; `Err(Hidden)` when it is redacted.
fn version_at(store: &ObjectStore, tree: &ObjectId, path: &VPath, reader: Reader, stats: &mut ReadStats) -> Result<Option<std::result::Result<Arc<Version>, Hidden>>> {
    let e = match lookup(store, tree, path) {
        Ok(Some(e)) if e.kind != EntryKind::Dir => e,
        Ok(_) => return Ok(None),
        // A directory on the way this reader cannot open.
        Err(err) if err.is_unreadable() => {
            return Ok(Some(Err(Hidden { reason: HiddenReason::NoKey, visibility: Visibility::Public })))
        }
        Err(err) => return Err(err),
    };
    Ok(Some(match readable_version_counted(store, &e, reader, stats)? {
        Readable::Plain { id, data, .. } => Ok(Version::new(id, data)),
        Readable::Redacted(h) => Err(h),
    }))
}

/// Attribute each line of the file `path` at snapshot `rev`.
pub fn blame(repo: &Repo, rev: &ObjectId, path: &VPath, o: &BlameOptions) -> Result<Blame> {
    // A public mirror lacks what an unreleased embargo withholds (BUG-991):
    // no push sends it before the release. A revision it has holds none of
    // it in its history, so only the revision itself is checked.
    if o.reader == Reader::Public && crate::remote::embargo_blocks(repo, &[*rev])?[0].is_some() {
        return Err(VeilError::Policy(format!(
            "{} is not public: an unreleased embargo withholds it, and a public mirror does not have it before the release",
            rev.short()
        )));
    }
    let store = repo.store();
    let mut stats = ReadStats::default();
    let top = repo.snapshot(rev)?;
    let entry = match lookup(store, &top.tree, path)? {
        Some(e) if e.kind.is_file_like() => e,
        Some(_) => return Err(VeilError::NotFound(format!("{path} is a directory in {}", rev.short()))),
        None => return Err(VeilError::NotFound(format!("{path} does not exist in {}", rev.short()))),
    };
    let version = match readable_version_counted(store, &entry, o.reader, &mut stats)? {
        Readable::Plain { id, data, .. } => Version::new(id, data),
        Readable::Redacted(h) => return Err(VeilError::Redacted { scope: h.visibility.label() }),
    };
    let total = version.lines.len();
    let (from, to) = match o.lines {
        Some((a, b)) => (a.max(1).min(total + 1) - 1, b.min(total)),
        None => (0, total),
    };
    let mut origins: Vec<Option<Origin>> = vec![None; total];
    let mut result = Blame { path: path.clone(), rev: *rev, lines: Vec::new(), coarse: false, stopped: None, visited: 0, stats };
    let mut heap: BinaryHeap<Queued> = BinaryHeap::new();
    let mut pending: HashMap<(ObjectId, VPath), Pending> = HashMap::new();
    let open: Vec<(u32, u32)> = (from..to.max(from)).map(|i| (i as u32, i as u32)).collect();
    // Children before parents: every line a snapshot will receive has
    // arrived by the time it is popped.
    // Ranks come lazily, as far down as the walk goes (the history index).
    let mut rank = LazyRank { iter: repo.held().topo_iter([*rev]), ranks: HashMap::new() };
    if !open.is_empty() {
        pending.insert((*rev, path.clone()), Pending { lines: open, version: version.clone() });
        heap.push(Queued { rank: 0, id: *rev, path: path.clone() });
    }
    let mut work: u64 = 0;
    let budget = o.work_budget;
    'walk: while let Some(q) = heap.pop() {
        let Some(pend) = pending.remove(&(q.id, q.path.clone())) else { continue };
        if result.visited >= o.max_changes {
            result.stopped = Some(Stop::MaxChanges);
            pending.insert((q.id, q.path.clone()), pend);
            break;
        }
        result.visited += 1;
        work = work.saturating_add(pend.lines.len() as u64);
        let snap = repo.snapshot(&q.id)?;
        let cur = pend.version;
        let mut open = pend.lines;
        for parent in &snap.parents {
            if open.is_empty() {
                break;
            }
            // A parent withheld here (an unreleased embargo on a public
            // clone) is not part of this replica's history.
            let Some(ps) = repo.exact().snapshot(parent)? else { continue };
            let Some(prank) = rank.of(parent)? else { continue };
            let mut ppath = q.path.clone();
            let mut pv = match pending.get(&(*parent, ppath.clone())) {
                Some(p) => Some(Ok(p.version.clone())),
                None => version_at(store, &ps.tree, &ppath, o.reader, &mut result.stats)?,
            };
            if pv.is_none() && o.follow {
                // Where did the file come from? Renames in this step only.
                let changes = diff_trees(store, Some(&ps.tree), Some(&snap.tree))?;
                if changes.iter().any(|c| c.path == q.path && c.old.is_none()) {
                    let d = rename::detect(store, &changes, o.reader, &o.renames)?;
                    result.stats.add(&d.stats);
                    if let Some(pair) = d.pairs.iter().find(|p| p.to == q.path && !p.copy) {
                        ppath = pair.from.clone();
                        pv = match pending.get(&(*parent, ppath.clone())) {
                            Some(p) => Some(Ok(p.version.clone())),
                            None => version_at(store, &ps.tree, &ppath, o.reader, &mut result.stats)?,
                        };
                    }
                }
            }
            let pver = match pv {
                None => continue,
                Some(Err(h)) => {
                    // The parent may hold these lines; this reader cannot
                    // tell. Never guessed.
                    for (fin, _) in open.drain(..) {
                        origins[fin as usize] = Some(Origin::Unattributed(Unattributed::Sealed(h.visibility.clone())));
                    }
                    break;
                }
                Some(Ok(v)) => v,
            };
            let passed: Vec<(u32, u32)> = if pver.id == cur.id || pver.data == cur.data {
                std::mem::take(&mut open)
            } else {
                if work >= budget {
                    result.stopped = Some(Stop::Budget);
                    pending.insert((q.id, q.path.clone()), Pending { lines: open, version: cur });
                    break 'walk;
                }
                let lines = (pver.lines.len() + cur.lines.len()) as u64;
                let (map, coarse) = map_lines(&pver.data, &cur.data, cur.lines.len());
                // What the diff cost: past its limit the whole limit was
                // spent measuring; within it, about D² for D edits.
                let search = if coarse {
                    textmerge::work_limit(lines as usize)
                } else {
                    let kept = map.iter().filter(|m| m.is_some()).count() as u64;
                    let d = lines.saturating_sub(2 * kept);
                    d.saturating_mul(d)
                };
                work = work.saturating_add(lines).saturating_add(search);
                result.coarse |= coarse;
                let mut passed = Vec::new();
                open.retain(|&(fin, local)| match map.get(local as usize).copied().flatten() {
                    Some(old) => {
                        passed.push((fin, old));
                        false
                    }
                    None => true,
                });
                passed
            };
            if passed.is_empty() {
                continue;
            }
            match pending.get_mut(&(*parent, ppath.clone())) {
                Some(p) => p.lines.extend(passed),
                None => {
                    pending.insert((*parent, ppath.clone()), Pending { lines: passed, version: pver });
                    heap.push(Queued { rank: prank, id: *parent, path: ppath });
                }
            }
        }
        for (fin, _) in open {
            origins[fin as usize] = Some(Origin::Snapshot { id: q.id, path: q.path.clone() });
        }
    }
    let why = match result.stopped {
        Some(Stop::Budget) => Unattributed::Budget,
        _ => Unattributed::MaxChanges,
    };
    for p in pending.into_values() {
        for (fin, _) in p.lines {
            origins[fin as usize].get_or_insert(Origin::Unattributed(why.clone()));
        }
    }
    for (i, origin) in origins.into_iter().enumerate().take(to).skip(from) {
        let (a, b) = version.lines[i];
        result.lines.push(BlameLine {
            number: i + 1,
            text: version.data[a..b].to_vec(),
            origin: origin.unwrap_or(Origin::Unattributed(why.clone())),
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapped(old: &str, new: &str) -> Vec<Option<u32>> {
        let n = line_ranges(new.as_bytes()).len();
        map_lines(old.as_bytes(), new.as_bytes(), n).0
    }

    #[test]
    fn lines_map_through_the_diff() {
        assert_eq!(mapped("a\nb\nc\n", "a\nb\nc\n"), vec![Some(0), Some(1), Some(2)]);
        assert_eq!(mapped("a\nb\nc\n", "a\nX\nc\n"), vec![Some(0), None, Some(2)]);
        assert_eq!(mapped("a\nb\nc\n", "z\na\nb\nc\n"), vec![None, Some(0), Some(1), Some(2)]);
        assert_eq!(mapped("a\nb\nc\n", "a\nc\n"), vec![Some(0), Some(2)]);
        assert_eq!(mapped("a\nb\n", "a\nb\nc"), vec![Some(0), Some(1), None]);
        assert_eq!(mapped("", "a\nb\n"), vec![None, None]);
        assert_eq!(mapped("a\nb\n", ""), Vec::<Option<u32>>::new());
        assert_eq!(mapped("a\nb", "a\nb\n"), vec![Some(0), None]);
        // Several hunks.
        assert_eq!(mapped("1\n2\n3\n4\n5\n6\n", "1\nX\n3\n4\nY\n6\nZ\n"), vec![Some(0), None, Some(2), Some(3), None, Some(5), None]);
    }

    /// Every mapped line is equal to the line it maps to, and the mapping
    /// is increasing (a property of any diff), on random edits.
    #[test]
    fn mapping_is_a_monotone_matching_of_equal_lines() {
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..300 {
            let n = (rnd() % 30) as usize;
            let old: Vec<String> = (0..n).map(|_| format!("{}\n", rnd() % 6)).collect();
            let m = (rnd() % 30) as usize;
            let new: Vec<String> = (0..m).map(|_| format!("{}\n", rnd() % 6)).collect();
            let (o, nw) = (old.concat(), new.concat());
            let map = mapped(&o, &nw);
            assert_eq!(map.len(), m);
            let mut last: Option<u32> = None;
            for (i, x) in map.iter().enumerate() {
                if let Some(x) = x {
                    assert_eq!(old[*x as usize], new[i], "{o:?} → {nw:?}: {map:?}");
                    assert!(last.is_none_or(|l| *x > l), "{map:?}");
                    last = Some(*x);
                }
            }
        }
    }
}
