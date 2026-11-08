//! Rename and copy detection (computed, never stored): exact and inexact
//! passes within limits, on what this reader can read.
//!
//! Renames are never recorded in snapshots, trees or operations; they exist
//! only in this reader's output. Detection runs on the changes between two trees as
//! [`crate::tree::diff_trees`] lists them.
//!
//! 1. **Exact pass** (linear): a deleted and an added entry of the same
//!    kind and the same object id. Sealed objects pair only with the same
//!    sealed id: deterministic sealing makes that equal content, an
//!    equality every reader of the trees can already see. A conflict pairs
//!    only with an equal conflict id (threat review 9). Empty files never
//!    pair (every empty file is "the same").
//! 2. **Inexact pass**, only on files this reader reads as
//!    [`Readable::Plain`] (never ciphertext): similarity
//!    is Git's span hash (chunks of a line, at most 64 bytes, hashed and
//!    weighed by their bytes; score = shared bytes / larger size). It runs
//!    only while `sources × destinations ≤ limit²`, each file is at most
//!    [`MAX_INEXACT_FILE`], at most [`RenameOptions::budget`] bytes are
//!    read and hashed, and the comparisons' work is bounded too
//!    ([`COMPARE_BUDGET`]). Past any limit no inexact pair is reported and
//!    [`Detected::truncated`] says so: the result is exact pairs only, as
//!    with Git's `diff.renameLimit`.
//! 3. With [`RenameOptions::copies`], the sources also include the old
//!    sides of modified files, and with [`detect_with_sources`] the
//!    unchanged files of the old tree.
//!
//! Each destination gets at most one source, assigned greedily by score,
//! then by path; a deleted source is renamed once and may then only be
//! copied. The output is linear in the number of changes.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::{
    blame::{readable_version_counted, ReadStats, Readable, Reader},
    error::Result,
    id::ObjectId,
    object::{EntryKind, Object, TreeEntry},
    store::ObjectStore,
    tree::{walk_files_hiding, TreeChange},
    vpath::VPath,
};

/// Default similarity threshold, in percent (Git's `-M`).
pub const DEFAULT_THRESHOLD: u8 = 50;
/// Default bound on the inexact pass: `sources × destinations ≤ limit²`.
pub const DEFAULT_LIMIT: usize = 1000;
/// Default bound on the bytes the inexact pass reads and hashes.
pub const DEFAULT_BUDGET: u64 = 1 << 30;
/// Largest file the inexact pass reads.
pub const MAX_INEXACT_FILE: u64 = 16 << 20;
/// Bound on the inexact pass's comparisons: chunk-list entries merged,
/// summed over every pair compared.
pub const COMPARE_BUDGET: u64 = 1 << 28;
/// Longest chunk hashed as one span.
const SPAN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenameOptions {
    /// Also detect copies.
    pub copies: bool,
    /// Similarity, in percent, a pair needs.
    pub threshold: u8,
    /// `sources × destinations ≤ limit²` for the inexact pass.
    pub limit: usize,
    /// Bytes the inexact pass may read and hash.
    pub budget: u64,
}

impl Default for RenameOptions {
    fn default() -> Self {
        RenameOptions { copies: false, threshold: DEFAULT_THRESHOLD, limit: DEFAULT_LIMIT, budget: DEFAULT_BUDGET }
    }
}

/// One detected rename or copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pair {
    pub from: VPath,
    pub to: VPath,
    /// Similarity in percent (100 for an exact pair).
    pub score: u8,
    /// A copy: the source is still there (or was already renamed).
    pub copy: bool,
    /// The source entry and the destination entry.
    pub old: TreeEntry,
    pub new: TreeEntry,
}

/// One line of a diff after detection: a change as it was, or a pair in
/// the place of its destination's addition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    Change(TreeChange),
    Pair(Pair),
}

#[derive(Clone, Debug, Default)]
pub struct Detected {
    pub pairs: Vec<Pair>,
    /// The changes no pair took (a renamed file's deletion and addition
    /// are gone; a copy's source change stays).
    pub changes: Vec<TreeChange>,
    /// Some limit stopped the inexact pass: only exact pairs are reported.
    pub truncated: bool,
    pub stats: ReadStats,
    /// For [`Detected::items`]: per input change, `Some(i)` when it is the
    /// destination of `pairs[i]`, and whether it was kept in `changes`.
    order: Vec<(Option<usize>, bool)>,
}

impl Detected {
    /// Every change and pair in the order of the input changes, each pair
    /// where its destination was added.
    pub fn items(&self) -> Vec<Item> {
        let mut changes = self.changes.iter();
        let mut out = Vec::with_capacity(self.order.len());
        for (pair, kept) in &self.order {
            if let Some(i) = pair {
                out.push(Item::Pair(self.pairs[*i].clone()));
            } else if *kept {
                if let Some(c) = changes.next() {
                    out.push(Item::Change(c.clone()));
                }
            }
        }
        out
    }
}

/// The empty file's id: never a rename (every empty file would pair).
fn empty_blob() -> ObjectId {
    Object::blob_id(b"")
}

/// A possible source.
struct Source {
    path: VPath,
    entry: TreeEntry,
    /// Deleted in the change set: may be renamed (once).
    deleted: bool,
    /// Index into the input changes (deleted sources only).
    change: Option<usize>,
}

/// Detect renames (and copies) among `changes` (from `from` to `to`),
/// reading as `reader`. In a thin clone, what the inexact pass reads is
/// asked for at its path in `from` or `to` (BUG-1506).
pub fn detect(store: &ObjectStore, from: Option<&ObjectId>, to: Option<&ObjectId>, changes: &[TreeChange], reader: Reader, o: &RenameOptions) -> Result<Detected> {
    detect_in(store, (from, to), false, changes, reader, o)
}

/// [`detect`]; with copies on and `old_tree` given, the unchanged files of
/// `old_tree` are copy sources too.
pub fn detect_with_sources(
    store: &ObjectStore,
    old_tree: Option<&ObjectId>,
    new_tree: Option<&ObjectId>,
    changes: &[TreeChange],
    reader: Reader,
    o: &RenameOptions,
) -> Result<Detected> {
    detect_in(store, (old_tree, new_tree), true, changes, reader, o)
}

fn detect_in(
    store: &ObjectStore,
    (from, to): (Option<&ObjectId>, Option<&ObjectId>),
    unchanged_sources: bool,
    changes: &[TreeChange],
    reader: Reader,
    o: &RenameOptions,
) -> Result<Detected> {
    let old_tree = from.filter(|_| unchanged_sources);
    let mut sources: Vec<Source> = Vec::new();
    let mut dests: Vec<usize> = Vec::new();
    for (i, c) in changes.iter().enumerate() {
        match (&c.old, &c.new) {
            (Some(e), None) if e.kind.is_file_like() => {
                sources.push(Source { path: c.path.clone(), entry: e.clone(), deleted: true, change: Some(i) })
            }
            (None, Some(e)) if e.kind.is_file_like() => dests.push(i),
            (Some(e), Some(_)) if o.copies && e.kind.is_file_like() => {
                sources.push(Source { path: c.path.clone(), entry: e.clone(), deleted: false, change: None })
            }
            _ => {}
        }
    }
    let mut d = Detected::default();
    if dests.is_empty() || (sources.is_empty() && !(o.copies && old_tree.is_some())) {
        d.changes = changes.to_vec();
        d.order = changes.iter().map(|_| (None, true)).collect();
        return Ok(d);
    }
    if o.copies {
        if let Some(t) = old_tree {
            let changed: HashSet<&VPath> = changes.iter().map(|c| &c.path).collect();
            for (p, e) in walk_files_hiding(store, t)?.0 {
                if !changed.contains(&p) {
                    sources.push(Source { path: p, entry: e, deleted: false, change: None });
                }
            }
        }
    }
    let empty = empty_blob();
    // dest change index → (source index, score, a rename rather than a copy)
    let mut assigned: HashMap<usize, (usize, u8, bool)> = HashMap::new();
    let mut renamed: HashSet<usize> = HashSet::new();

    // ---- exact pass --------------------------------------------------------------
    #[derive(Default)]
    struct Bucket {
        by_name: HashMap<String, VecDeque<usize>>,
        deleted: VecDeque<usize>,
        any: Option<usize>,
        any_by_name: HashMap<String, usize>,
    }
    let mut buckets: HashMap<(u8, ObjectId), Bucket> = HashMap::new();
    let kind_tag = |k: EntryKind| -> u8 {
        match k {
            EntryKind::File => 0,
            EntryKind::Conflict => 1,
            _ => 2,
        }
    };
    for (si, s) in sources.iter().enumerate() {
        if s.entry.id == empty {
            continue;
        }
        let b = buckets.entry((kind_tag(s.entry.kind), s.entry.id)).or_default();
        b.any.get_or_insert(si);
        b.any_by_name.entry(s.path.file_name().to_string()).or_insert(si);
        if s.deleted {
            b.deleted.push_back(si);
            b.by_name.entry(s.path.file_name().to_string()).or_default().push_back(si);
        }
    }
    for &di in &dests {
        let e = changes[di].new.as_ref().expect("an addition");
        if e.id == empty {
            continue;
        }
        let Some(b) = buckets.get_mut(&(kind_tag(e.kind), e.id)) else { continue };
        let name = changes[di].path.file_name();
        // A deleted source of the same name, then any deleted source, not
        // renamed yet.
        let mut pick = None;
        if let Some(q) = b.by_name.get_mut(name) {
            while let Some(si) = q.pop_front() {
                if !renamed.contains(&si) {
                    pick = Some(si);
                    break;
                }
            }
        }
        if pick.is_none() {
            while let Some(si) = b.deleted.pop_front() {
                if !renamed.contains(&si) {
                    pick = Some(si);
                    break;
                }
            }
        }
        match pick {
            Some(si) => {
                renamed.insert(si);
                assigned.insert(di, (si, 100, true));
            }
            None if o.copies => {
                let si = b.any_by_name.get(name).copied().or(b.any).expect("a bucket has a source");
                assigned.insert(di, (si, 100, false));
            }
            None => {}
        }
    }

    // ---- inexact pass ------------------------------------------------------------
    let open_dests: Vec<usize> = dests
        .iter()
        .copied()
        .filter(|di| !assigned.contains_key(di) && changes[*di].new.as_ref().is_some_and(|e| e.kind == EntryKind::File && e.id != empty))
        .collect();
    let open_sources: Vec<usize> = (0..sources.len())
        .filter(|si| {
            let s = &sources[*si];
            s.entry.kind == EntryKind::File && s.entry.id != empty && (o.copies || (s.deleted && !renamed.contains(si)))
        })
        .collect();
    if !open_dests.is_empty() && !open_sources.is_empty() {
        let limit = (o.limit as u128).pow(2);
        if (open_dests.len() as u128) * (open_sources.len() as u128) > limit {
            d.truncated = true;
        } else {
            prefetch_inexact(store, (from, to), &sources, &open_sources, changes, &open_dests, o)?;
            match inexact(store, &sources, &open_sources, changes, &open_dests, reader, o, &mut d.stats)? {
                None => d.truncated = true,
                Some(mut cands) => {
                    // Best score first, then by destination and source path.
                    cands.sort_by(|a, b| {
                        b.0.cmp(&a.0)
                            .then_with(|| changes[a.1].path.as_str().cmp(changes[b.1].path.as_str()))
                            .then_with(|| sources[a.2].path.as_str().cmp(sources[b.2].path.as_str()))
                    });
                    for (score, di, si) in cands {
                        if assigned.contains_key(&di) {
                            continue;
                        }
                        let s = &sources[si];
                        if s.deleted && !renamed.contains(&si) {
                            renamed.insert(si);
                            assigned.insert(di, (si, score, true));
                        } else if o.copies {
                            assigned.insert(di, (si, score, false));
                        }
                    }
                }
            }
        }
    }

    // ---- result --------------------------------------------------------------------
    // A deleted source renamed away no longer shows as deleted.
    let consumed: HashSet<usize> = renamed.iter().filter_map(|si| sources[*si].change).collect();
    let mut pair_at: HashMap<usize, usize> = HashMap::new();
    let mut dest_order: Vec<usize> = assigned.keys().copied().collect();
    dest_order.sort_unstable();
    for di in dest_order {
        let (si, score, rename) = assigned[&di];
        let s = &sources[si];
        let copy = !rename;
        pair_at.insert(di, d.pairs.len());
        d.pairs.push(Pair {
            from: s.path.clone(),
            to: changes[di].path.clone(),
            score,
            copy,
            old: s.entry.clone(),
            new: changes[di].new.clone().expect("an addition"),
        });
    }
    for (i, c) in changes.iter().enumerate() {
        if let Some(p) = pair_at.get(&i) {
            d.order.push((Some(*p), false));
        } else if consumed.contains(&i) {
            d.order.push((None, false));
        } else {
            d.changes.push(c.clone());
            d.order.push((None, true));
        }
    }
    Ok(d)
}

/// Span-hash summary of a file: (hash, bytes) sorted by hash, and its size.
struct Spans {
    spans: Vec<(u32, u32)>,
    size: u64,
}

fn spans(data: &[u8]) -> Spans {
    let mut v: Vec<(u32, u32)> = Vec::new();
    let mut start = 0;
    while start < data.len() {
        let end = data[start..]
            .iter()
            .take(SPAN)
            .position(|b| *b == b'\n')
            .map_or((start + SPAN).min(data.len()), |i| start + i + 1);
        // FNV-1a, 32 bits.
        let mut h: u32 = 0x811c_9dc5;
        for b in &data[start..end] {
            h ^= u32::from(*b);
            h = h.wrapping_mul(0x0100_0193);
        }
        v.push((h, (end - start) as u32));
        start = end;
    }
    v.sort_unstable_by_key(|x| x.0);
    let mut out: Vec<(u32, u32)> = Vec::with_capacity(v.len());
    for (h, n) in v {
        match out.last_mut() {
            Some(last) if last.0 == h => last.1 = last.1.saturating_add(n),
            _ => out.push((h, n)),
        }
    }
    Spans { spans: out, size: data.len() as u64 }
}

/// Similarity in percent: bytes in shared spans over the larger size.
fn similarity(a: &Spans, b: &Spans) -> u8 {
    let max = a.size.max(b.size);
    if max == 0 {
        return 100;
    }
    let (mut i, mut j, mut common) = (0, 0, 0u64);
    while i < a.spans.len() && j < b.spans.len() {
        let (ha, na) = a.spans[i];
        let (hb, nb) = b.spans[j];
        match ha.cmp(&hb) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                common += u64::from(na.min(nb));
                i += 1;
                j += 1;
            }
        }
    }
    ((common * 100) / max).min(100) as u8
}

/// Read a file for the inexact pass: plain content only, within the size
/// cap. `None` for anything else.
fn read_plain(store: &ObjectStore, e: &TreeEntry, reader: Reader, stats: &mut ReadStats) -> Result<Option<Vec<u8>>> {
    if e.size > MAX_INEXACT_FILE {
        return Ok(None);
    }
    Ok(match readable_version_counted(store, e, reader, stats)? {
        Readable::Plain { data, .. } if data.len() as u64 <= MAX_INEXACT_FILE => Some(data),
        _ => None,
    })
}

/// In a thin clone, what [`inexact`] reads (in its order, within its
/// budget), each at its own path: sources in `from`, destinations in `to`.
fn prefetch_inexact(
    store: &ObjectStore,
    (from, to): (Option<&ObjectId>, Option<&ObjectId>),
    sources: &[Source],
    open_sources: &[usize],
    changes: &[TreeChange],
    open_dests: &[usize],
    o: &RenameOptions,
) -> Result<()> {
    if !store.may_fetch() {
        return Ok(());
    }
    let mut left = o.budget;
    let mut within = |e: &TreeEntry| {
        let take = e.size <= MAX_INEXACT_FILE && e.size <= left;
        if take {
            left -= e.size;
        }
        take
    };
    let src: Vec<(&VPath, &TreeEntry)> = open_sources.iter().map(|&si| (&sources[si].path, &sources[si].entry)).filter(|(_, e)| within(e)).collect();
    let dst: Vec<(&VPath, &TreeEntry)> = open_dests
        .iter()
        .filter_map(|&di| changes[di].new.as_ref().map(|e| (&changes[di].path, e)))
        .filter(|(_, e)| within(e))
        .collect();
    if let Some(f) = from {
        crate::tree::prefetch_files(store, f, src)?;
    }
    if let Some(t) = to {
        crate::tree::prefetch_files(store, t, dst)?;
    }
    Ok(())
}

/// The inexact candidates `(score, dest change, source)`, or `None` when a
/// limit stopped the pass.
#[allow(clippy::too_many_arguments)]
fn inexact(
    store: &ObjectStore,
    sources: &[Source],
    open_sources: &[usize],
    changes: &[TreeChange],
    open_dests: &[usize],
    reader: Reader,
    o: &RenameOptions,
    stats: &mut ReadStats,
) -> Result<Option<Vec<(u8, usize, usize)>>> {
    let mut read: u64 = 0;
    let mut load = |e: &TreeEntry, stats: &mut ReadStats| -> Result<std::result::Result<Option<Spans>, ()>> {
        if read.saturating_add(e.size) > o.budget {
            return Ok(Err(()));
        }
        let Some(data) = read_plain(store, e, reader, stats)? else { return Ok(Ok(None)) };
        read = read.saturating_add(data.len() as u64);
        if read > o.budget {
            return Ok(Err(()));
        }
        Ok(Ok(Some(spans(&data))))
    };
    let mut src: Vec<(usize, Spans)> = Vec::new();
    for &si in open_sources {
        match load(&sources[si].entry, stats)? {
            Err(()) => return Ok(None),
            Ok(Some(s)) => src.push((si, s)),
            Ok(None) => {}
        }
    }
    let mut dst: Vec<(usize, Spans)> = Vec::new();
    for &di in open_dests {
        match load(changes[di].new.as_ref().expect("an addition"), stats)? {
            Err(()) => return Ok(None),
            Ok(Some(s)) => dst.push((di, s)),
            Ok(None) => {}
        }
    }
    // The comparisons' work, bounded before any is done.
    let src_work: u64 = src.iter().map(|(_, s)| s.spans.len() as u64).sum();
    let dst_work: u64 = dst.iter().map(|(_, s)| s.spans.len() as u64).sum();
    let work = src_work.saturating_mul(dst.len() as u64).saturating_add(dst_work.saturating_mul(src.len() as u64));
    if work > COMPARE_BUDGET {
        return Ok(None);
    }
    let threshold = u64::from(o.threshold);
    let mut out = Vec::new();
    for (di, ds) in &dst {
        for (si, ss) in &src {
            // The score cannot reach the threshold when the sizes differ
            // too much.
            let (lo, hi) = (ds.size.min(ss.size), ds.size.max(ss.size));
            if hi > 0 && lo * 100 < threshold * hi {
                continue;
            }
            let score = similarity(ss, ds);
            if u64::from(score) >= threshold && score > 0 {
                out.push((score, *di, *si));
            }
        }
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_split_at_lines_and_at_64_bytes() {
        let s = spans(b"a\nb\na\n");
        assert_eq!(s.size, 6);
        assert_eq!(s.spans.len(), 2, "two distinct spans, `a\\n` weighs 4");
        assert!(s.spans.iter().any(|x| x.1 == 4));
        let long = vec![b'x'; 200];
        let s = spans(&long);
        // 64 + 64 + 64 + 8: three equal chunks and one short one.
        assert_eq!(s.spans.iter().map(|x| x.1).sum::<u32>(), 200);
        assert_eq!(s.spans.len(), 2);
    }

    #[test]
    fn similarity_is_shared_bytes_over_the_larger_size() {
        let a = spans(b"one\ntwo\nthree\nfour\n");
        assert_eq!(similarity(&a, &a), 100);
        let b = spans(b"one\ntwo\nthree\nFOUR\n");
        assert_eq!(similarity(&a, &b), 73, "14 of 19 bytes");
        let c = spans(b"nothing in common here\n");
        assert_eq!(similarity(&a, &c), 0);
    }
}
