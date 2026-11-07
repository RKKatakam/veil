//! The history index: each snapshot's **generation**, kept as a
//! device-local cache so that graph queries stop at the part of the
//! history they need instead of reading all of it
//! (`docs/design/scale/3-history-index.md`).
//!
//! The generation is a *corrected commit date* (Git's generation v2): the
//! larger of the snapshot's own timestamp (milliseconds, at least 0) and 1
//! plus the largest generation of its parents present in the store. Along
//! every parent edge it strictly decreases, so a walk looking for `a` below
//! `b` can stop at every snapshot whose generation is below `a`'s: none of
//! that snapshot's ancestors can be `a`. That is the only property the walks
//! rely on, and it holds whatever timestamps authors chose: a timestamp in
//! the future or the past only makes some walk read more, never answer
//! wrongly. Following timestamps, walks stop at what is older than what
//! they look for, which a plain topological level cannot do for an old
//! branch or an old tag.
//!
//! A second derived fact rides along: whether a snapshot or any ancestor
//! has `embargo` set ([`FLAG_EMBARGO_LINE`]), so that the embargo checks
//! skip every line that does not build on an embargoed merge.
//!
//! **What the index trusts.** Walks read every snapshot they visit from the
//! store, and take its parents from the object, never from the index. The
//! index supplies only generations (to stop early), change ids (to find
//! candidates for a change-id prefix, confirmed against the store) and one
//! flag (`embargo` set, to find embargoed merges without walking). Its bytes
//! are a function of plaintext snapshot fields alone, so they say nothing a
//! reader without keys could not compute from the store.
//!
//! **A parent that arrives later.** A parent that is not in the store (the
//! withheld fix of an unreleased embargo on a public clone, or history not
//! pulled yet) is not part of the graph, and the child's generation ignores
//! it. If that parent arrives later, it may have a larger generation than
//! its indexed child, which would break the property above. Every layer
//! therefore lists the parents that were missing when its entries were
//! computed, and the index is dropped and rebuilt as soon as one of them is
//! present (checked when the index is opened, after every commit, and on
//! [`crate::Repo::reload`]).
//!
//! **Files** (`.veil/index/graph/`), never synced, never copied out of
//! `.veil/` by any command:
//!
//! ```text
//! L-<epoch>-<lo>-<hi>.vcg   a layer holding the entries appended in slots lo..=hi
//! E-<epoch>                 an empty marker: layers of older epochs are void
//! ```
//!
//! A layer is created with `create_new_unsynced` (exclusive, never
//! synced: a power loss can leave it missing, empty or torn, which its
//! checksum catches), so appenders never overwrite one another: an appender that loses a slot reads the winner's layer and
//! tries the next slot. Readers use the newest epoch, and take its longest
//! layer starting at slot 0, then the longest starting right after it, and
//! so on. Small layers are merged geometrically into larger ones, which are
//! preferred by the same rule; the merged-away files are removed
//! afterwards. Every entry's parents are in the same layer or an earlier
//! one. Dropping the index (a layer that fails its checksum or bounds
//! checks, or a missing parent that arrived) creates the next epoch's marker
//! before removing the old layers, so a layer appended concurrently from
//! the old ones is never mixed into the new chain. Entries are then
//! computed again from the store: the index is never required.
//!
//! Layer encoding (integers little-endian):
//!
//! ```text
//! "VEILCG01" | count u32 | missing u32
//! | ids [count × 32], ascending
//! | records [count × (generation u64 | change id [16] | flags u8)]
//! | missing parents [missing × 32]
//! | BLAKE3 of everything before
//! ```

use std::{
    collections::{BinaryHeap, HashMap, HashSet},
    sync::{Arc, Mutex, MutexGuard},
};

use crate::{
    error::{Result, VeilError},
    id::{ChangeId, ObjectId},
    object::Snapshot,
    repo::Repo,
    vfs::StorageBackend,
    vpath::VPath,
};

const MAGIC: &[u8; 8] = b"VEILCG01";
const DIR: &str = ".veil/index/graph";
const HEADER: usize = 8 + 4 + 4;
const REC: usize = 8 + 16 + 1;
/// Flag: the snapshot's `embargo` field is set.
pub const FLAG_EMBARGO: u8 = 1;
/// Flag: the snapshot or one of its ancestors in the store has [`FLAG_EMBARGO`].
pub const FLAG_EMBARGO_LINE: u8 = 2;

/// A generation (see the module docs).
pub type Gen = u64;
/// Fresh entries a read-only command persists without waiting for a commit.
const PERSIST_BATCH: usize = 256;
/// Layers above this count on the chain are merged even when not geometric.
const MAX_LAYERS: usize = 24;

/// One index entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub generation: Gen,
    pub change_id: ChangeId,
    pub flags: u8,
}

/// A loaded layer: its slots and its encoded bytes.
struct Layer {
    lo: u64,
    hi: u64,
    name: String,
    data: Vec<u8>,
    count: usize,
    missing: usize,
}

impl Layer {
    fn parse(name: String, lo: u64, hi: u64, data: Vec<u8>) -> Option<Layer> {
        if data.len() < HEADER + 32 || &data[..8] != MAGIC {
            return None;
        }
        let count = u32::from_le_bytes(data[8..12].try_into().ok()?) as usize;
        let missing = u32::from_le_bytes(data[12..16].try_into().ok()?) as usize;
        let body = count.checked_mul(32 + REC)?.checked_add(missing.checked_mul(32)?)?;
        if data.len() != HEADER.checked_add(body)?.checked_add(32)? {
            return None;
        }
        let (content, sum) = data.split_at(data.len() - 32);
        if blake3::hash(content).as_bytes() != sum {
            return None;
        }
        let layer = Layer { lo, hi, name, data, count, missing };
        // Ids strictly ascending: binary search relies on it.
        if (1..count).any(|i| layer.id(i - 1) >= layer.id(i)) {
            return None;
        }
        Some(layer)
    }

    fn id(&self, i: usize) -> ObjectId {
        let at = HEADER + i * 32;
        ObjectId(self.data[at..at + 32].try_into().unwrap())
    }

    fn entry(&self, i: usize) -> Entry {
        let at = HEADER + self.count * 32 + i * REC;
        let r = &self.data[at..at + REC];
        Entry {
            generation: u64::from_le_bytes(r[..8].try_into().unwrap()),
            change_id: ChangeId(r[8..24].try_into().unwrap()),
            flags: r[24],
        }
    }

    fn missing_parent(&self, i: usize) -> ObjectId {
        let at = HEADER + self.count * (32 + REC) + i * 32;
        ObjectId(self.data[at..at + 32].try_into().unwrap())
    }

    fn find(&self, id: &ObjectId) -> Option<Entry> {
        let (mut lo, mut hi) = (0usize, self.count);
        while lo < hi {
            let mid = (lo + hi) / 2;
            match self.id(mid).cmp(id) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(self.entry(mid)),
            }
        }
        None
    }

    fn encode(entries: &mut [(ObjectId, Entry)], missing: &[ObjectId]) -> Vec<u8> {
        entries.sort_by_key(|e| e.0);
        let mut out = Vec::with_capacity(HEADER + entries.len() * (32 + REC) + missing.len() * 32 + 32);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        out.extend_from_slice(&(missing.len() as u32).to_le_bytes());
        for (id, _) in entries.iter() {
            out.extend_from_slice(&id.0);
        }
        for (_, e) in entries.iter() {
            out.extend_from_slice(&e.generation.to_le_bytes());
            out.extend_from_slice(&e.change_id.0);
            out.push(e.flags);
        }
        for m in missing {
            out.extend_from_slice(&m.0);
        }
        let sum = blake3::hash(&out);
        out.extend_from_slice(sum.as_bytes());
        out
    }
}

#[derive(Default)]
struct State {
    loaded: bool,
    /// The epoch the layers belong to, and new ones are written in.
    epoch: u64,
    layers: Vec<Layer>,
    /// The next free slot (one past the last loaded layer's `hi`).
    end: u64,
    /// Entries computed in this process.
    mem: HashMap<ObjectId, Entry>,
    /// Those of `mem` not in a persisted layer, in the order computed.
    fresh: Vec<ObjectId>,
    /// Parents found missing while computing `fresh`.
    fresh_missing: HashSet<ObjectId>,
    /// Missing parents listed by the loaded layers, and by `fresh`.
    missing: HashSet<ObjectId>,
}

impl State {
    fn get(&self, id: &ObjectId) -> Option<Entry> {
        if let Some(e) = self.mem.get(id) {
            return Some(*e);
        }
        self.layers.iter().rev().find_map(|l| l.find(id))
    }

    fn reset(&mut self, epoch: u64) {
        *self = State {
            loaded: true,
            epoch,
            ..State::default()
        };
    }
}

/// The history index of one repository (see the module docs). Shared by
/// every query of a [`Repo`]; entries computed by one query serve the next.
pub struct GraphIndex {
    backend: Arc<dyn StorageBackend>,
    /// Whether layers are read and written (local repositories with a
    /// working copy). Otherwise entries live in memory only.
    persist: bool,
    state: Mutex<State>,
}

impl std::fmt::Debug for GraphIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GraphIndex").field("persist", &self.persist).finish()
    }
}

fn dir() -> VPath {
    VPath::new(DIR).unwrap()
}

fn layer_name(epoch: u64, lo: u64, hi: u64) -> String {
    format!("L-{epoch}-{lo}-{hi}.vcg")
}

fn marker_name(epoch: u64) -> String {
    format!("E-{epoch}")
}

/// A file of the index directory.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum File {
    Layer { epoch: u64, lo: u64, hi: u64, name: String },
    Marker { epoch: u64, name: String },
}

impl File {
    fn parse(name: &str) -> Option<File> {
        // Canonical spellings only (no leading zeros or signs), so one
        // layer has one name.
        if let Some(rest) = name.strip_prefix("E-") {
            let epoch: u64 = rest.parse().ok()?;
            return (marker_name(epoch) == name).then(|| File::Marker { epoch, name: name.to_string() });
        }
        let rest = name.strip_prefix("L-")?.strip_suffix(".vcg")?;
        let mut parts = rest.split('-');
        let (epoch, lo, hi): (u64, u64, u64) = (parts.next()?.parse().ok()?, parts.next()?.parse().ok()?, parts.next()?.parse().ok()?);
        (parts.next().is_none() && layer_name(epoch, lo, hi) == name && lo <= hi).then(|| File::Layer {
            epoch,
            lo,
            hi,
            name: name.to_string(),
        })
    }

    fn epoch(&self) -> u64 {
        match self {
            File::Layer { epoch, .. } | File::Marker { epoch, .. } => *epoch,
        }
    }

    fn name(&self) -> &str {
        match self {
            File::Layer { name, .. } | File::Marker { name, .. } => name,
        }
    }
}

/// Has the store any of `ids` as a snapshot (a missing parent arrived)?
fn any_arrived(repo: &Repo, ids: &HashSet<ObjectId>) -> bool {
    ids.iter().any(|id| repo.store().has(id))
}

impl GraphIndex {
    pub(crate) fn new(backend: Arc<dyn StorageBackend>, persist: bool) -> GraphIndex {
        GraphIndex {
            backend,
            persist,
            state: Mutex::new(State::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The files of `.veil/index/graph/`, and the current epoch (the
    /// newest named by any of them).
    fn list(&self) -> (Vec<File>, u64) {
        let Ok(entries) = self.backend.list_dir(&dir()) else { return (Vec::new(), 0) };
        let mut out: Vec<File> = entries.into_iter().filter_map(|e| File::parse(&e.name)).collect();
        out.sort();
        let epoch = out.iter().map(File::epoch).max().unwrap_or(0);
        (out, epoch)
    }

    /// The chain of `epoch`: from slot `from`, the longest layer starting at
    /// each next slot. `None` if a layer could not be read or parsed.
    fn read_chain(&self, files: &[File], epoch: u64, from: u64) -> Option<Vec<Layer>> {
        let mut out = Vec::new();
        let mut next = from;
        loop {
            let best = files
                .iter()
                .filter_map(|f| match f {
                    File::Layer { epoch: e, lo, hi, name } if *e == epoch && *lo == next => Some((*hi, name)),
                    _ => None,
                })
                .max();
            let Some((hi, name)) = best else { break };
            let data = self.backend.read_opt(&dir().join(name)).ok()??;
            out.push(Layer::parse(name.clone(), next, hi, data)?);
            next = hi + 1;
        }
        Some(out)
    }

    /// Void the index: create the next epoch's marker, then remove every
    /// older file. Returns the new epoch.
    fn discard_files(&self) -> u64 {
        let (files, epoch) = self.list();
        let next = epoch + 1;
        let _ = self.backend.create_dir_all(&dir());
        let created = self.backend.create_new(&dir().join(&marker_name(next)), b"").is_ok();
        if created {
            self.remove_older(&files, next);
        }
        next
    }

    /// Remove the files of epochs before `epoch` (best effort).
    fn remove_older(&self, files: &[File], epoch: u64) {
        for f in files.iter().filter(|f| f.epoch() < epoch) {
            let _ = self.backend.remove_file(&dir().join(f.name()));
        }
    }

    fn ensure_loaded(&self, repo: &Repo, st: &mut State) {
        if st.loaded {
            return;
        }
        st.reset(0);
        if !self.persist {
            return;
        }
        // A merge may remove files between the listing and the reads: one
        // retry, then void the index (entries are computed again).
        for attempt in 0..2 {
            let (files, epoch) = self.list();
            match self.read_chain(&files, epoch, 0) {
                Some(layers) => {
                    st.epoch = epoch;
                    st.end = layers.last().map_or(0, |l| l.hi + 1);
                    for l in &layers {
                        for i in 0..l.missing {
                            st.missing.insert(l.missing_parent(i));
                        }
                    }
                    st.layers = layers;
                    break;
                }
                None if attempt == 0 => continue,
                None => {
                    let epoch = self.discard_files();
                    st.reset(epoch);
                }
            }
        }
        if any_arrived(repo, &st.missing) {
            self.void(st);
        }
    }

    /// Drop every entry, in memory and on disk.
    fn void(&self, st: &mut State) {
        let epoch = match self.persist {
            true => self.discard_files(),
            false => 0,
        };
        st.reset(epoch);
    }

    /// Re-check, after the store may have gained snapshots (a commit, a
    /// pull, another process), that no parent the index took as missing
    /// has arrived. If one has, the index is dropped and rebuilt.
    pub fn revalidate(&self, repo: &Repo) {
        let mut st = self.lock();
        if st.loaded && any_arrived(repo, &st.missing) {
            self.void(&mut st);
        }
    }

    /// Run `f` with the index loaded.
    fn with<R>(&self, repo: &Repo, f: impl FnOnce(&mut Walker<'_>) -> Result<R>) -> Result<R> {
        let mut st = self.lock();
        self.ensure_loaded(repo, &mut st);
        let mut w = Walker { repo, st: &mut st };
        let out = f(&mut w)?;
        if st.fresh.len() >= PERSIST_BATCH {
            self.persist_locked(&mut st);
        }
        Ok(out)
    }

    /// Write the entries computed in this process as a new layer. Best
    /// effort: on any failure they stay in memory, and another process
    /// computes them again.
    pub fn persist(&self, repo: &Repo) {
        let mut st = self.lock();
        if !st.loaded {
            return;
        }
        if any_arrived(repo, &st.missing) {
            self.void(&mut st);
            return;
        }
        self.persist_locked(&mut st);
    }

    fn persist_locked(&self, st: &mut State) {
        if !self.persist || st.fresh.is_empty() {
            return;
        }
        if self.backend.create_dir_all(&dir()).is_err() {
            return;
        }
        for _ in 0..4 {
            // Entries another appender has persisted meanwhile are dropped.
            let fresh: Vec<ObjectId> = st.fresh.iter().copied().filter(|id| !st.layers.iter().any(|l| l.find(id).is_some())).collect();
            if fresh.is_empty() {
                st.fresh.clear();
                st.fresh_missing.clear();
                return;
            }
            let mut entries: Vec<(ObjectId, Entry)> = fresh.iter().map(|id| (*id, st.mem[id])).collect();
            let mut missing: Vec<ObjectId> = st.fresh_missing.iter().copied().collect();
            missing.sort();
            let data = Layer::encode(&mut entries, &missing);
            let (lo, hi) = (st.end, st.end);
            let name = layer_name(st.epoch, lo, hi);
            let path = dir().join(&name);
            match self.backend.create_new_unsynced(&path, &data) {
                Ok(true) => {
                    let Some(layer) = Layer::parse(name, lo, hi, data) else { return };
                    st.layers.push(layer);
                    st.end = hi + 1;
                    st.fresh.clear();
                    st.fresh_missing.clear();
                    self.compact(st);
                    return;
                }
                Ok(false) => {
                    // Lost the slot: read the layers others appended, then
                    // try the slot after them.
                    let (files, epoch) = self.list();
                    if epoch != st.epoch {
                        return;
                    }
                    match self.read_chain(&files, epoch, st.end) {
                        Some(more) if !more.is_empty() => {
                            for l in &more {
                                for i in 0..l.missing {
                                    st.missing.insert(l.missing_parent(i));
                                }
                            }
                            st.end = more.last().unwrap().hi + 1;
                            st.layers.extend(more);
                        }
                        _ => return,
                    }
                }
                Err(_) => return,
            }
        }
    }

    /// Merge the newest layers while the one below is less than twice as
    /// large as the one above (or the chain is too long), so the chain stays
    /// logarithmic. The rule is followed on the counts first, so that what
    /// it merges is written as one layer, not once per step. The merged
    /// layer is created first, then the parts are removed; readers prefer
    /// the merged one either way.
    fn compact(&self, st: &mut State) {
        let n = st.layers.len();
        // How many of the newest layers end up merged into one.
        let (mut k, mut top) = (1, st.layers.last().map_or(0, |l| l.count));
        while k < n {
            let below = st.layers[n - 1 - k].count;
            if below >= 2 * top && n - k < MAX_LAYERS {
                break;
            }
            top += below;
            k += 1;
        }
        if k > 1 {
            let parts = &st.layers[n - k..];
            let (lo, hi) = (parts[0].lo, parts[k - 1].hi);
            let mut entries: Vec<(ObjectId, Entry)> = Vec::with_capacity(top);
            let mut missing: Vec<ObjectId> = Vec::new();
            for l in parts {
                entries.extend((0..l.count).map(|i| (l.id(i), l.entry(i))));
                missing.extend((0..l.missing).map(|i| l.missing_parent(i)));
            }
            missing.sort();
            missing.dedup();
            let data = Layer::encode(&mut entries, &missing);
            let name = layer_name(st.epoch, lo, hi);
            if self.backend.create_new_unsynced(&dir().join(&name), &data).is_err() {
                return;
            }
            let Some(merged) = Layer::parse(name.clone(), lo, hi, data) else { return };
            let parts: Vec<String> = parts.iter().map(|l| l.name.clone()).collect();
            st.layers.truncate(n - k);
            st.layers.push(merged);
            for part in parts {
                if part != name {
                    let _ = self.backend.remove_file(&dir().join(&part));
                }
            }
        }
        if st.layers.len() < 2 {
            // Leftovers of voided epochs.
            let (files, _) = self.list();
            self.remove_older(&files, st.epoch);
        }
    }

    // ---- queries --------------------------------------------------------

    /// The generation of snapshot `id`; `None` if the store does not hold it.
    pub fn generation(&self, repo: &Repo, id: &ObjectId) -> Result<Option<Gen>> {
        Ok(self.entry(repo, id)?.map(|e| e.generation))
    }

    /// The entry of snapshot `id`; `None` if the store does not hold it.
    pub fn entry(&self, repo: &Repo, id: &ObjectId) -> Result<Option<Entry>> {
        self.with(repo, |w| w.entry(id))
    }

    /// Is `a` an ancestor of (or equal to) `b`?
    pub fn is_ancestor(&self, repo: &Repo, a: &ObjectId, b: &ObjectId) -> Result<bool> {
        if a == b {
            return Ok(true);
        }
        let set: HashSet<ObjectId> = [*a].into_iter().collect();
        Ok(!self.reachable_among(repo, [*b], &set)?.is_empty())
    }

    /// Which of `candidates` are reachable from `roots` (themselves
    /// included)? One walk, which stops below the lowest candidate.
    pub fn reachable_among(
        &self,
        repo: &Repo,
        roots: impl IntoIterator<Item = ObjectId>,
        candidates: &HashSet<ObjectId>,
    ) -> Result<HashSet<ObjectId>> {
        self.with(repo, |w| {
            let mut floor = Gen::MAX;
            let mut wanted = HashSet::new();
            for c in candidates {
                if let Some(e) = w.entry(c)? {
                    floor = floor.min(e.generation);
                    wanted.insert(*c);
                }
            }
            let mut found = HashSet::new();
            if wanted.is_empty() {
                return Ok(found);
            }
            let mut seen = HashSet::new();
            let mut stack: Vec<ObjectId> = roots.into_iter().collect();
            while let Some(id) = stack.pop() {
                if !seen.insert(id) {
                    continue;
                }
                let Some(e) = w.entry(&id)? else { continue };
                if e.generation < floor {
                    continue;
                }
                if wanted.contains(&id) {
                    found.insert(id);
                    if found.len() == wanted.len() {
                        break;
                    }
                }
                if e.generation == floor {
                    continue;
                }
                let Some(s) = w.snapshot(&id)? else { continue };
                stack.extend(s.parents.iter().filter(|p| !seen.contains(*p)).copied());
            }
            Ok(found)
        })
    }

    /// The snapshots with [`FLAG_EMBARGO`] reachable from `roots`. The walk
    /// reads only lines that build on one ([`FLAG_EMBARGO_LINE`]): with no
    /// embargo in the history, nothing past the roots.
    pub fn embargoed_among(&self, repo: &Repo, roots: impl IntoIterator<Item = ObjectId>) -> Result<HashSet<ObjectId>> {
        self.with(repo, |w| {
            let mut found = HashSet::new();
            let mut seen = HashSet::new();
            let mut stack: Vec<ObjectId> = roots.into_iter().collect();
            while let Some(id) = stack.pop() {
                if !seen.insert(id) {
                    continue;
                }
                let Some(e) = w.entry(&id)? else { continue };
                if e.flags & FLAG_EMBARGO_LINE == 0 {
                    continue;
                }
                if e.flags & FLAG_EMBARGO != 0 {
                    found.insert(id);
                }
                let Some(s) = w.snapshot(&id)? else { continue };
                stack.extend(s.parents.iter().filter(|p| !seen.contains(*p)).copied());
            }
            Ok(found)
        })
    }

    /// Every snapshot reachable from `roots` whose generation is at least
    /// `floor`, with its snapshot. The walk stops below `floor`.
    pub fn down_to(
        &self,
        repo: &Repo,
        roots: impl IntoIterator<Item = ObjectId>,
        floor: Gen,
    ) -> Result<HashMap<ObjectId, (Gen, Arc<Snapshot>)>> {
        self.with(repo, |w| {
            let mut out: HashMap<ObjectId, (Gen, Arc<Snapshot>)> = HashMap::new();
            let mut seen = HashSet::new();
            let mut stack: Vec<ObjectId> = roots.into_iter().collect();
            while let Some(id) = stack.pop() {
                if !seen.insert(id) {
                    continue;
                }
                let Some(e) = w.entry(&id)? else { continue };
                if e.generation < floor {
                    continue;
                }
                let Some(s) = w.snapshot(&id)? else { continue };
                stack.extend(s.parents.iter().filter(|p| !seen.contains(*p)).copied());
                out.insert(id, (e.generation, s));
            }
            Ok(out)
        })
    }

    /// The snapshots reachable from `include` and not from `exclude`
    /// (Git's `exclude..include`). Walks by generation, highest first, and
    /// stops once everything left is reachable from `exclude`.
    pub fn range(&self, repo: &Repo, include: &[ObjectId], exclude: &[ObjectId]) -> Result<HashSet<ObjectId>> {
        const INC: u8 = 1;
        const EXC: u8 = 2;
        self.with(repo, |w| {
            let mut flags: HashMap<ObjectId, u8> = HashMap::new();
            let mut heap: BinaryHeap<(Gen, ObjectId)> = BinaryHeap::new();
            // Queued nodes not (yet) known to be reachable from `exclude`.
            let mut live = 0usize;
            let mut queued: HashSet<ObjectId> = HashSet::new();
            let mark = |w: &mut Walker<'_>, flags: &mut HashMap<ObjectId, u8>, heap: &mut BinaryHeap<(Gen, ObjectId)>, queued: &mut HashSet<ObjectId>, live: &mut usize, id: ObjectId, f: u8| -> Result<()> {
                let Some(e) = w.entry(&id)? else { return Ok(()) };
                let old = flags.get(&id).copied();
                let new = old.unwrap_or(0) | f;
                if old == Some(new) {
                    return Ok(());
                }
                flags.insert(id, new);
                match old {
                    None => {
                        heap.push((e.generation, id));
                        queued.insert(id);
                        if new & EXC == 0 {
                            *live += 1;
                        }
                    }
                    Some(o) if queued.contains(&id) && o & EXC == 0 && new & EXC != 0 => *live -= 1,
                    _ => {}
                }
                Ok(())
            };
            for id in exclude {
                mark(w, &mut flags, &mut heap, &mut queued, &mut live, *id, EXC)?;
            }
            for id in include {
                mark(w, &mut flags, &mut heap, &mut queued, &mut live, *id, INC)?;
            }
            let mut out = HashSet::new();
            while live > 0 {
                let Some((_, id)) = heap.pop() else { break };
                if !queued.remove(&id) {
                    continue;
                }
                let f = flags[&id];
                if f & EXC == 0 {
                    live -= 1;
                    out.insert(id);
                }
                let Some(s) = w.snapshot(&id)? else { continue };
                for p in &s.parents {
                    mark(w, &mut flags, &mut heap, &mut queued, &mut live, *p, f)?;
                }
            }
            Ok(out)
        })
    }

    /// The merge bases of `a` and `b`: their common ancestors that are not
    /// an ancestor of another common ancestor. Unordered.
    pub fn merge_bases(&self, repo: &Repo, a: &[ObjectId], b: &[ObjectId]) -> Result<Vec<ObjectId>> {
        const A: u8 = 1;
        const B: u8 = 2;
        const STALE: u8 = 4;
        self.with(repo, |w| {
            let mut flags: HashMap<ObjectId, u8> = HashMap::new();
            let mut heap: BinaryHeap<(Gen, ObjectId)> = BinaryHeap::new();
            let mut done: HashSet<ObjectId> = HashSet::new();
            let push = |w: &mut Walker<'_>, flags: &mut HashMap<ObjectId, u8>, heap: &mut BinaryHeap<(Gen, ObjectId)>, id: ObjectId, f: u8| -> Result<()> {
                let Some(e) = w.entry(&id)? else { return Ok(()) };
                let old = flags.get(&id).copied();
                let new = old.unwrap_or(0) | f;
                if old != Some(new) {
                    flags.insert(id, new);
                    heap.push((e.generation, id));
                }
                Ok(())
            };
            for id in a {
                push(w, &mut flags, &mut heap, *id, A)?;
            }
            for id in b {
                push(w, &mut flags, &mut heap, *id, B)?;
            }
            let mut bases = Vec::new();
            loop {
                // Stop once every queued node is below a common ancestor.
                if heap.iter().all(|(_, id)| flags[id] & STALE != 0 || done.contains(id)) {
                    break;
                }
                let Some((_, id)) = heap.pop() else { break };
                if !done.insert(id) {
                    continue;
                }
                let mut f = flags[&id];
                if f & (A | B) == A | B && f & STALE == 0 {
                    bases.push(id);
                    f |= STALE;
                }
                let Some(s) = w.snapshot(&id)? else { continue };
                for p in &s.parents {
                    if !done.contains(p) {
                        push(w, &mut flags, &mut heap, *p, f)?;
                    }
                }
            }
            // Nodes are taken highest generation first, so every common
            // ancestor above a node has passed its stale mark down before
            // the node is taken: no base found is below another.
            Ok(bases)
        })
    }

    /// Indexed snapshots reachable from `roots`, after indexing everything
    /// reachable from them: each with its entry. For change-id lookups and
    /// embargo flags; the caller confirms what it uses against the store.
    pub fn entries_matching(
        &self,
        repo: &Repo,
        roots: impl IntoIterator<Item = ObjectId>,
        mut keep: impl FnMut(&ObjectId, &Entry) -> bool,
    ) -> Result<Vec<ObjectId>> {
        self.with(repo, |w| {
            for r in roots {
                w.entry(&r)?;
            }
            let mut out = Vec::new();
            for (id, e) in &w.st.mem {
                if keep(id, e) {
                    out.push(*id);
                }
            }
            for l in &w.st.layers {
                for i in 0..l.count {
                    let (id, e) = (l.id(i), l.entry(i));
                    if !w.st.mem.contains_key(&id) && keep(&id, &e) {
                        out.push(id);
                    }
                }
            }
            out.sort();
            out.dedup();
            Ok(out)
        })
    }

    /// Snapshots reachable from `roots`, children before parents, newest
    /// first among unrelated snapshots: exactly the order of
    /// [`crate::repo::Held::topo_children_first`], produced lazily (an incremental
    /// topological walk, as Git's `--topo-order` since 2.20).
    pub fn topo_iter<'r>(&'r self, repo: &'r Repo, roots: impl IntoIterator<Item = ObjectId>) -> TopoIter<'r> {
        TopoIter {
            index: self,
            repo,
            roots: Some(roots.into_iter().collect()),
            unexamined: Vec::new(),
            explore: BinaryHeap::new(),
            indegree: HashMap::new(),
            ready: BinaryHeap::new(),
            queued: HashSet::new(),
            nodes: HashMap::new(),
            failed: false,
        }
    }
}

/// Computes missing entries on demand while a query runs.
struct Walker<'a> {
    repo: &'a Repo,
    st: &'a mut State,
}

impl Walker<'_> {
    fn snapshot(&mut self, id: &ObjectId) -> Result<Option<Arc<Snapshot>>> {
        self.repo.held().snapshot(id)
    }

    /// The entry of `id`, computing it (and every unindexed ancestor) from
    /// the store if needed; `None` if the store does not hold `id`.
    fn entry(&mut self, id: &ObjectId) -> Result<Option<Entry>> {
        if let Some(e) = self.st.get(id) {
            return Ok(Some(e));
        }
        // Post-order over the unindexed ancestors, iterative.
        let mut pending: HashMap<ObjectId, Arc<Snapshot>> = HashMap::new();
        let mut stack = vec![(*id, false)];
        while let Some((x, expanded)) = stack.pop() {
            if self.st.get(&x).is_some() {
                continue;
            }
            if !expanded {
                if pending.contains_key(&x) {
                    continue;
                }
                let Some(s) = self.repo.held().snapshot(&x)? else { continue };
                stack.push((x, true));
                for p in &s.parents {
                    if self.st.get(p).is_none() && !pending.contains_key(p) {
                        stack.push((*p, false));
                    }
                }
                pending.insert(x, s);
                continue;
            }
            let s = pending.remove(&x).expect("expanded snapshots are pending");
            let mut above: Gen = 0;
            let mut flags = if s.embargo.is_some() { FLAG_EMBARGO | FLAG_EMBARGO_LINE } else { 0 };
            for p in &s.parents {
                match self.st.get(p) {
                    Some(e) => {
                        above = above.max(e.generation);
                        flags |= e.flags & FLAG_EMBARGO_LINE;
                    }
                    None => {
                        self.st.missing.insert(*p);
                        self.st.fresh_missing.insert(*p);
                    }
                }
            }
            let above = above.checked_add(1).filter(|g| *g < Gen::MAX).ok_or_else(|| {
                VeilError::Unsupported("the history is deeper than the index supports".into())
            })?;
            let e = Entry {
                generation: above.max(s.timestamp.max(0) as Gen),
                change_id: s.change_id,
                flags,
            };
            self.st.mem.insert(x, e);
            self.st.fresh.push(x);
        }
        Ok(self.st.get(id))
    }
}

/// See [`GraphIndex::topo_iter`].
///
/// Kahn's algorithm, newest first among the snapshots whose children are
/// all emitted, made lazy two ways. A node's count of children is complete
/// once every node of a larger generation is explored, so exploration goes
/// only as deep as the next node to emit. And a root (which no emitted node
/// will free) is examined only once its timestamp could be the next one
/// emitted: an old tag costs nothing until the walk reaches its time.
pub struct TopoIter<'r> {
    index: &'r GraphIndex,
    repo: &'r Repo,
    roots: Option<Vec<ObjectId>>,
    /// Roots not examined yet, oldest first (the newest is popped).
    unexamined: Vec<(i64, ObjectId)>,
    /// Nodes to explore (count their parents' children), highest generation first.
    explore: BinaryHeap<(Gen, ObjectId)>,
    /// Children counted so far, per discovered node.
    indegree: HashMap<ObjectId, usize>,
    /// Nodes whose children are all emitted, newest first.
    ready: BinaryHeap<(i64, ObjectId)>,
    /// Nodes ever put in `ready`.
    queued: HashSet<ObjectId>,
    /// Discovered nodes: generation and snapshot.
    nodes: HashMap<ObjectId, (Gen, Arc<Snapshot>)>,
    failed: bool,
}

impl TopoIter<'_> {
    fn discover(&mut self, w: &mut Walker<'_>, id: ObjectId) -> Result<bool> {
        if self.nodes.contains_key(&id) {
            return Ok(true);
        }
        let Some(e) = w.entry(&id)? else { return Ok(false) };
        let Some(s) = w.snapshot(&id)? else { return Ok(false) };
        self.nodes.insert(id, (e.generation, s));
        self.indegree.insert(id, 0);
        self.explore.push((e.generation, id));
        Ok(true)
    }

    /// Explore every discovered node of generation `>= floor` (count it
    /// as a child of each of its parents, discovering them). Afterwards the
    /// count of every node of generation `< floor` whose children all have
    /// generation `>= floor` is complete: in particular, of every node of
    /// generation `floor - 1`.
    fn explore_to(&mut self, w: &mut Walker<'_>, floor: Gen) -> Result<()> {
        while let Some(&(g, id)) = self.explore.peek() {
            if g < floor {
                break;
            }
            self.explore.pop();
            let parents = self.nodes[&id].1.parents.clone();
            for p in parents {
                if self.discover(w, p)? {
                    *self.indegree.get_mut(&p).unwrap() += 1;
                }
            }
        }
        Ok(())
    }

    /// Queue `id` if its count is complete and zero.
    fn settle(&mut self, w: &mut Walker<'_>, id: ObjectId) -> Result<()> {
        if self.queued.contains(&id) {
            return Ok(());
        }
        let g = self.nodes[&id].0;
        self.explore_to(w, g + 1)?;
        if self.indegree[&id] == 0 {
            self.queued.insert(id);
            self.ready.push((self.nodes[&id].1.timestamp, id));
        }
        Ok(())
    }

    fn step(&mut self) -> Result<Option<ObjectId>> {
        let (index, repo) = (self.index, self.repo);
        index.with(repo, |w| {
            if let Some(roots) = self.roots.take() {
                for r in roots {
                    if self.discover(w, r)? {
                        self.unexamined.push((self.nodes[&r].1.timestamp, r));
                    }
                }
                self.unexamined.sort();
                self.unexamined.dedup();
            }
            // A root newer than the best ready node might be ready itself.
            while let Some(&key) = self.unexamined.last() {
                if self.ready.peek().is_some_and(|top| *top > key) {
                    break;
                }
                self.unexamined.pop();
                self.settle(w, key.1)?;
            }
            let Some((_, id)) = self.ready.pop() else { return Ok(None) };
            // Explored itself, so its parents are discovered and counted.
            self.explore_to(w, self.nodes[&id].0)?;
            let parents = self.nodes[&id].1.parents.clone();
            for p in parents {
                if !self.nodes.contains_key(&p) {
                    continue;
                }
                let c = self.indegree.get_mut(&p).unwrap();
                *c -= 1;
                if *c == 0 {
                    // Every child of `p` has a larger generation: once
                    // those are explored, its count is final.
                    self.settle(w, p)?;
                }
            }
            Ok(Some(id))
        })
    }
}

impl Iterator for TopoIter<'_> {
    type Item = Result<ObjectId>;

    fn next(&mut self) -> Option<Result<ObjectId>> {
        if self.failed {
            return None;
        }
        match self.step() {
            Ok(Some(id)) => Some(Ok(id)),
            Ok(None) => None,
            Err(e) => {
                self.failed = true;
                Some(Err(e))
            }
        }
    }
}
