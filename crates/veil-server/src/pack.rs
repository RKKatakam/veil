//! Packs (S28, `docs/design/server/storage-and-cost.md` §7, `docs/HUB.md`
//! §13.20): many objects of a project in one storage object, so a push
//! costs one storage write instead of one per object.
//!
//! **Layout** (one storage object, `p/<project>/pack/<name>`, `name` 32
//! random hex digits; never edited in place):
//!
//! ```text
//! "veilpack3\n"                    10 bytes
//! count u32be
//! index: count × (id 32 ‖ offset u64be ‖ len u32be), sorted by id, ids distinct
//! entries: each object's id (32 bytes), the length of its encoding
//!          (u32be), then its encoding (S27: `v…` or `z…`); a slot spans
//!          all three
//! ```
//!
//! The index is at the front, so one read of the first [`FIRST_READ`]
//! bytes holds it for most packs, without knowing the pack's length. An
//! entry is read with a range request, and **every read checks the id and
//! the length the entry starts with against its slot** ([`entry`]) before
//! any byte of it is used, a ranged one too: the id ties the slot's start
//! to the object, the length its end, so a wrong slot (a damaged index, a
//! merger's mistake, a boundary moved between neighbours) is an error,
//! never another object's bytes (BUG-1154, BUG-1394, BUG-1497). Whole reads
//! are also decoded and checked against the id like any object
//! (`store::Objects`). A pack is self-describing: S29 merges packs by
//! reading their indexes and copying entries into a new pack, and drops an
//! object by writing a pack without it (`storage-and-cost.md` §8).
//! `veilpack2` (entries without their length, never merged: S28 before its
//! cycle 4) is not a pack to this reader.
//!
//! **States** (the `packs` table, migration 13), one row per pack:
//! * *staged* (0): an upload's pack, recorded with its uploader **before**
//!   it is written, so the database knows every upload in storage; read by
//!   nobody but a push or API commit of that person whose receipts name it;
//! * *listed* (1): its objects are the project's, set in the transaction of
//!   the push that lands it (a push's own pack is inserted there);
//! * *discarded* (2): refused; its storage object is deleted after the row
//!   says so. A staged row turns listed or discarded once, whichever comes
//!   first (the row is locked by the update), so a listed pack is never
//!   deleted and a discarded one is never listed.
//!
//! **Lookups.** Each server keeps, per project, the indexes of the listed
//! packs it has read ([`Packs`]), bounded by bytes across projects
//! ([`LOOKUP_BUDGET`]); past it an index is unloaded, and a lookup that
//! needs it reads it again. A miss there and among loose objects reads the
//! project's listing again (one statement) and the indexes of packs it
//! does not know. **Every other index held in memory** (one being read, a
//! push's staged uploads', the staged-index cache's) holds a share of one
//! server-wide bound ([`INDEXES_HELD`], [`Held`]) while it is held, taken
//! before it is read (BUG-1496).

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use veil_core::{cache::LruCache, ObjectId};

use crate::store::BlobStore;

/// A pack's first bytes.
pub const MAGIC: &[u8; 10] = b"veilpack3\n";
/// The magic and the count.
const HEAD: usize = MAGIC.len() + 4;
/// One index entry: id, offset, length.
const ENTRY: usize = 32 + 8 + 4;
/// The id each entry starts with.
const ID_LEN: u64 = 32;
/// What each entry starts with: its id and the length of its encoding.
pub const ENTRY_HEAD: u64 = ID_LEN + 4;
/// What a reader asks for first: the head and, up to about 1,500 objects,
/// the whole index.
pub const FIRST_READ: u64 = 64 << 10;
/// Most objects one pack holds (its index is at most 11 MiB on disk, 12 MiB
/// in memory, and 27 MiB while read and parsed: BUG-1621).
pub const MAX_OBJECTS: usize = 256 << 10;

/// Pack states in the `packs` table.
pub const STAGED: i16 = 0;
pub const LISTED: i16 = 1;
pub const DISCARDED: i16 = 2;

/// The storage key of pack `name` of `project`.
pub fn key(project: i64, name: &str) -> String {
    format!("p/{project}/pack/{name}")
}

fn project_of_key(key: &str) -> Option<i64> {
    key.strip_prefix("p/")?.split('/').next()?.parse().ok()
}

/// A fresh pack name: 128 random bits, in lowercase hex.
pub fn new_name() -> String {
    hex::encode(veil_core::crypto::random_bytes::<16>())
}

/// Is `s` a pack name ([`new_name`]'s form)?
pub fn valid_name(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Where an object's entry (its id, its encoding's length, then its
/// encoding) sits in its pack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub offset: u64,
    pub len: u32,
}

impl Slot {
    /// The last byte (inclusive), for a range read.
    pub fn last(&self) -> u64 {
        self.offset + u64::from(self.len.max(1)) - 1
    }

    /// The length of the object's encoding (the entry without its head).
    pub fn encoding_len(&self) -> u64 {
        u64::from(self.len).saturating_sub(ENTRY_HEAD)
    }
}

/// The encoding in `bytes`, an entry's first bytes read from slot `s`
/// (at most the slot), once the entry's head is checked against the slot:
/// the id it starts with is `id` (the slot's start is the object's entry),
/// and the length it states is the slot's (the slot ends where the entry
/// does). A slot that is not exactly the object's entry is an error, never
/// another object's bytes (BUG-1154, BUG-1497).
pub fn entry<'a>(id: &ObjectId, s: Slot, bytes: &'a [u8]) -> Result<&'a [u8]> {
    let head = ENTRY_HEAD as usize;
    if bytes.len() < head || bytes[..ID_LEN as usize] != id.0 {
        bail!("pack entry for {} holds another object", id.short());
    }
    let stated = u32::from_be_bytes(bytes[ID_LEN as usize..head].try_into().expect("4 bytes"));
    if u64::from(stated) != s.encoding_len() || bytes.len() as u64 > u64::from(s.len) {
        bail!("pack entry for {} does not fill its slot", id.short());
    }
    Ok(&bytes[head..])
}

/// A pack's index: sorted by id, ids distinct.
#[derive(Debug, Default)]
pub struct Index {
    entries: Vec<(ObjectId, Slot)>,
}

impl Index {
    pub fn get(&self, id: &ObjectId) -> Option<Slot> {
        self.entries.binary_search_by(|(e, _)| e.cmp(id)).ok().map(|i| self.entries[i].1)
    }

    pub fn iter(&self) -> impl Iterator<Item = &(ObjectId, Slot)> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// About the memory it holds.
    pub fn weight(&self) -> usize {
        Self::weight_of(self.entries.capacity())
    }

    /// [`Index::weight`] of an index of `count` slots.
    pub fn weight_of(count: usize) -> usize {
        64 + count * std::mem::size_of::<(ObjectId, Slot)>()
    }

    /// Memory held while reading and parsing an index of `count` slots
    /// (BUG-1621): its bytes, the parsed index and the parse's working copy.
    pub fn read_weight_of(count: usize) -> usize {
        HEAD + count * ENTRY + Self::weight_of(count) + count * std::mem::size_of::<Slot>()
    }

    /// Memory held for the index while laying out a pack of `count` objects
    /// (BUG-1621): the pack's index bytes and the parsed index.
    pub fn write_weight_of(count: usize) -> usize {
        HEAD + count * ENTRY + Self::weight_of(count)
    }
}

/// Lay out a pack of the encodings `objects` (the first of each id kept),
/// in the order given; its index. Deduplicates in place using the sorted
/// index entries so no separate `HashSet` or second object vector is held
/// alongside the index (BUG-1621).
pub fn build(mut objects: Vec<(ObjectId, Bytes)>) -> Result<(Bytes, Index)> {
    let mut entries = Vec::with_capacity(objects.len());
    let mut at = (HEAD + objects.len() * ENTRY) as u64;
    for (id, b) in &objects {
        let len = u32::try_from(ENTRY_HEAD as usize + b.len()).map_err(|_| anyhow!("an object of 4 GiB or more cannot be packed"))?;
        entries.push((*id, Slot { offset: at, len }));
        at += u64::from(len);
    }
    entries.sort_unstable_by_key(|(id, s)| (*id, s.offset));
    if entries.windows(2).any(|w| w[0].0 == w[1].0) {
        entries.dedup_by_key(|(id, _)| *id);
        entries.sort_unstable_by_key(|(_, s)| s.offset);
        let mut cur = (HEAD + objects.len() * ENTRY) as u64;
        let mut keep = entries.iter();
        let mut next_off = keep.next().map(|(_, s)| s.offset);
        objects.retain(|(_, b)| {
            let off = cur;
            cur += ENTRY_HEAD + b.len() as u64;
            if next_off == Some(off) {
                next_off = keep.next().map(|(_, s)| s.offset);
                true
            } else {
                false
            }
        });
        let mut at = (HEAD + entries.len() * ENTRY) as u64;
        for (_, s) in &mut entries {
            s.offset = at;
            at += u64::from(s.len);
        }
        entries.sort_unstable_by_key(|(id, _)| *id);
    }
    if objects.len() > MAX_OBJECTS {
        bail!("at most {MAX_OBJECTS} objects per pack");
    }
    let head = HEAD + objects.len() * ENTRY;
    let total = head + objects.iter().map(|(_, b)| ENTRY_HEAD as usize + b.len()).sum::<usize>();
    let mut out = BytesMut::with_capacity(total);
    out.put_slice(MAGIC);
    out.put_u32(entries.len() as u32);
    for (id, s) in &entries {
        out.put_slice(&id.0);
        out.put_u64(s.offset);
        out.put_u32(s.len);
    }
    for (id, b) in objects {
        out.put_slice(&id.0);
        out.put_u32(b.len() as u32);
        out.put_slice(&b);
    }
    debug_assert_eq!(out.len(), total);
    Ok((out.freeze(), Index { entries }))
}

/// How many bytes at a pack's start hold its head and index, from its
/// first bytes (at least the magic and the count).
pub fn head_len(first: &[u8]) -> Result<u64> {
    if first.len() < HEAD || &first[..MAGIC.len()] != MAGIC {
        bail!("not a pack");
    }
    let count = u32::from_be_bytes(first[MAGIC.len()..HEAD].try_into().expect("4 bytes")) as usize;
    if count > MAX_OBJECTS {
        bail!("a pack's index names {count} objects, more than {MAX_OBJECTS}");
    }
    Ok((HEAD + count * ENTRY) as u64)
}

fn parse_entry(e: &[u8; ENTRY], hl: u64, size: Option<u64>) -> Result<(ObjectId, Slot)> {
    let id = ObjectId(e[..32].try_into().expect("32 bytes"));
    let offset = u64::from_be_bytes(e[32..40].try_into().expect("8 bytes"));
    let len = u32::from_be_bytes(e[40..44].try_into().expect("4 bytes"));
    let end = offset.checked_add(u64::from(len)).ok_or_else(|| anyhow!("a pack slot past the end"))?;
    if offset < hl || u64::from(len) <= ENTRY_HEAD || size.is_some_and(|s| end > s) {
        bail!("a pack slot outside its entries");
    }
    Ok((id, Slot { offset, len }))
}

/// The index from a pack's first bytes (at least [`head_len`] of them),
/// checked: ids sorted and distinct, every slot long enough for its entry's
/// head and one byte, the slots tiling the entries from the index's end,
/// and, when the pack's length `size` is known, ending at it. (Where each
/// entry really ends is checked by every read of it: [`entry`].)
pub fn parse_index(first: &[u8], size: Option<u64>) -> Result<Index> {
    let hl = head_len(first)? as usize;
    if first.len() < hl {
        bail!("a pack's index is cut short");
    }
    let mut entries = Vec::with_capacity((hl - HEAD) / ENTRY);
    for e in first[HEAD..hl].as_chunks::<ENTRY>().0 {
        let (id, slot) = parse_entry(e, hl as u64, size)?;
        if entries.last().is_some_and(|(last, _): &(ObjectId, Slot)| *last >= id) {
            bail!("a pack's index is not sorted");
        }
        entries.push((id, slot));
    }
    // The slots tile the entries exactly, in offset order: each starts where
    // the one before ends, the first at the index's end, the last at the
    // pack's end when it is known (BUG-1394). That two neighbours' boundary
    // is where the first entry ends is checked by reading it: the length
    // each entry states (BUG-1497).
    let mut by_offset: Vec<Slot> = entries.iter().map(|(_, s)| *s).collect();
    by_offset.sort_unstable_by_key(|s| s.offset);
    let mut at = hl as u64;
    for s in &by_offset {
        if s.offset != at {
            bail!("a pack's slots do not tile its entries");
        }
        at = s.offset + u64::from(s.len);
    }
    if size.is_some_and(|size| size != at) {
        bail!("a pack's slots do not reach its end");
    }
    Ok(Index { entries })
}

/// Bytes of pack indexes one server holds in memory outside its lookup
/// maps (BUG-1496), for every request together: indexes being read
/// (`Packs::refresh`, `Packs::find_paged`), what a push or API commit reads
/// of its staged uploads' indexes (`Packs::staged_slots`: it bisects by
/// range and keeps only the slots its receipts name, BUG-1620), the index
/// of a pack being written, and the staged-index cache's
/// ([`STAGED_INDEXES`] of it at most). Each takes its share before it reads
/// or builds the index, and holds it while the index is held ([`Held`]).
/// A lookup's index joins the lookup maps once read (bounded by
/// [`LOOKUP_BUDGET`]).
pub const INDEXES_HELD: usize = 96 << 20;
/// What the staged-index cache may hold of [`INDEXES_HELD`].
pub const STAGED_INDEXES: usize = 32 << 20;
/// How long a request waits for its share of [`INDEXES_HELD`] before it is
/// answered [`IndexesFull`] (`warming`: try again).
const INDEX_WAIT: Duration = Duration::from_secs(10);

/// No share of [`INDEXES_HELD`] came free in time: the request is answered
/// `busy` (503, try again), never with an index held outside the bound.
#[derive(Debug)]
pub struct IndexesFull;

impl std::fmt::Display for IndexesFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the server holds as many pack indexes as it may; try again in a few seconds")
    }
}

impl std::error::Error for IndexesFull {}

/// Is `e` (or what it wraps, an I/O error's inner chain included) [`IndexesFull`]?
pub fn indexes_full(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.is::<IndexesFull>()
            || c.downcast_ref::<std::io::Error>().and_then(|io| io.get_ref()).is_some_and(|i| {
                let mut cur: &(dyn std::error::Error + 'static) = i;
                loop {
                    if cur.is::<IndexesFull>() {
                        return true;
                    }
                    match cur.source() {
                        Some(s) => cur = s,
                        None => return false,
                    }
                }
            })
    })
}

#[derive(Default)]
struct BoundState {
    held: HashMap<i64, usize>,
    waiting: HashMap<i64, usize>,
    last_large: Option<i64>,
}

/// A server-wide bound on bytes of indexes held ([`INDEXES_HELD`]), with a
/// fair share per project (BUG-1620) and no clamping below what a holder
/// actually allocates (BUG-1621).
#[derive(Clone)]
pub struct Bound {
    sem: Arc<tokio::sync::Semaphore>,
    state: Arc<Mutex<BoundState>>,
    notify: Arc<tokio::sync::Notify>,
    /// The largest share one holder may take (what the staged-index cache
    /// leaves of [`INDEXES_HELD`]).
    most: usize,
    wait: Duration,
}

impl Bound {
    pub fn new(total: usize) -> Bound {
        Bound {
            sem: Arc::new(tokio::sync::Semaphore::new(total)),
            state: Arc::new(Mutex::new(BoundState::default())),
            notify: Arc::new(tokio::sync::Notify::new()),
            most: total,
            wait: INDEX_WAIT,
        }
    }

    fn permits(&self, bytes: u64) -> u32 {
        bytes.max(1).min(u32::MAX as u64) as u32
    }

    /// A share of `bytes`, not tied to one project.
    pub async fn take(&self, bytes: u64) -> Result<Share> {
        self.take_for(None, bytes).await
    }

    /// A share of `bytes` for `project`, waiting at most this bound's wait
    /// (only by a holder of none, so holders never wait on one another in a
    /// cycle). One project holds at most a quarter of `most` across
    /// concurrent shares, or one larger share alone (up to `most`, yielding
    /// after one when another project waits: BUG-1620); a share past `most`
    /// is refused (BUG-1621).
    pub async fn take_for(&self, project: Option<i64>, bytes: u64) -> Result<Share> {
        let want = self.permits(bytes) as usize;
        if want > self.most {
            return Err(anyhow::Error::new(IndexesFull));
        }
        struct Waiting<'a> {
            project: Option<i64>,
            state: &'a Mutex<BoundState>,
            registered: bool,
        }
        impl Drop for Waiting<'_> {
            fn drop(&mut self) {
                if self.registered {
                    if let Some(p) = self.project {
                        let mut s = self.state.lock().unwrap();
                        if let Some(w) = s.waiting.get_mut(&p) {
                            *w = w.saturating_sub(1);
                            if *w == 0 {
                                s.waiting.remove(&p);
                            }
                        }
                    }
                }
            }
        }
        let quarter = (self.most / 4).max(1);
        let deadline = tokio::time::Instant::now() + self.wait;
        let mut guard = Waiting { project, state: &self.state, registered: false };
        loop {
            let notified = self.notify.notified();
            {
                let mut s = self.state.lock().unwrap();
                let can_take = match project {
                    None => true,
                    Some(p) => {
                        let cur = s.held.get(&p).copied().unwrap_or(0);
                        let other_waiting = s.waiting.iter().any(|(k, v)| *k != p && *v > 0);
                        cur + want <= quarter || (cur == 0 && (!other_waiting || s.last_large != Some(p)))
                    }
                };
                if can_take {
                    if let Ok(permit) = self.sem.clone().try_acquire_many_owned(want as u32) {
                        if let Some(p) = project {
                            *s.held.entry(p).or_default() += want;
                            if want > quarter || s.last_large != Some(p) {
                                s.last_large = None;
                            }
                            if want > quarter {
                                s.last_large = Some(p);
                            }
                        }
                        return Ok(Share {
                            permit: Some(permit),
                            project,
                            state: self.state.clone(),
                            notify: self.notify.clone(),
                        });
                    }
                    if !guard.registered {
                        if let Some(p) = project {
                            *s.waiting.entry(p).or_default() += 1;
                        }
                        guard.registered = true;
                    }
                } else if guard.registered {
                    if let Some(p) = project {
                        if let Some(w) = s.waiting.get_mut(&p) {
                            *w = w.saturating_sub(1);
                            if *w == 0 {
                                s.waiting.remove(&p);
                            }
                        }
                    }
                    guard.registered = false;
                }
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(anyhow::Error::new(IndexesFull));
            }
            let sleep_for = (deadline - now).min(Duration::from_millis(5));
            let _ = tokio::time::timeout(sleep_for, notified).await;
        }
    }

    /// The same bound, for a holder that does not wait.
    fn now(&self) -> Bound {
        Bound { wait: Duration::ZERO, ..self.clone() }
    }

    /// Bytes not held now.
    pub fn available(&self) -> usize {
        self.sem.available_permits()
    }
}

/// A share of a [`Bound`], given back when dropped.
pub struct Share {
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    project: Option<i64>,
    state: Arc<Mutex<BoundState>>,
    notify: Arc<tokio::sync::Notify>,
}

impl Share {
    /// Give back what is held beyond `bytes`.
    fn keep(&mut self, bytes: usize) {
        let Some(permit) = &mut self.permit else { return };
        let n = permit.num_permits();
        let keep = bytes.max(1);
        if n > keep {
            let give_back = n - keep;
            if let Some(p) = self.project {
                let mut s = self.state.lock().unwrap();
                if let Some(cur) = s.held.get_mut(&p) {
                    *cur = cur.saturating_sub(give_back);
                    if *cur == 0 {
                        s.held.remove(&p);
                    }
                }
            }
            drop(permit.split(give_back));
            self.notify.notify_waiters();
        }
    }

    /// Detach this share from its project's active quota when the index
    /// enters the server-wide staged-index cache (which has its own
    /// [`STAGED_INDEXES`] share of [`INDEXES_HELD`]) or once a landing
    /// push's split pack is written and recorded.
    fn unproject(&mut self) {
        if let Some(p) = self.project.take() {
            let n = self.permit.as_ref().map_or(0, |p| p.num_permits());
            let mut s = self.state.lock().unwrap();
            if let Some(cur) = s.held.get_mut(&p) {
                *cur = cur.saturating_sub(n);
                if *cur == 0 {
                    s.held.remove(&p);
                }
            }
            drop(s);
            self.notify.notify_waiters();
        }
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        let n = self.permit.as_ref().map_or(0, |p| p.num_permits());
        if let Some(p) = self.project.take() {
            let mut s = self.state.lock().unwrap();
            if let Some(cur) = s.held.get_mut(&p) {
                *cur = cur.saturating_sub(n);
                if *cur == 0 {
                    s.held.remove(&p);
                }
            }
        }
        drop(self.permit.take());
        self.notify.notify_waiters();
    }
}

/// An index held in memory with its share of the server's bound on
/// indexes (BUG-1496): the share goes back when the last holder drops it.
pub struct Held {
    pub index: Arc<Index>,
    /// The pack's length.
    pub size: u64,
    _share: Share,
}

impl Held {
    pub(crate) fn new(index: Arc<Index>, size: u64, mut share: Share) -> Held {
        share.keep(index.weight());
        Held { index, size, _share: share }
    }

    pub(crate) fn unproject(&mut self) {
        self._share.unproject();
    }
}

/// Read the index of the pack at `key` (one read for most packs, two for a
/// large index), holding a share of `bound` (BUG-1496, BUG-1621) taken
/// before the first [`FIRST_READ`] bytes are read, then resized for the
/// index bytes, the parsed index and the parse's working copy of the slots;
/// kept, once parsed, for the index alone.
pub async fn read_index(store: &dyn BlobStore, key: &str, bound: &Bound) -> Result<Option<Held>> {
    let project = project_of_key(key);
    let first_share = bound.take_for(project, FIRST_READ.min(bound.most as u64)).await?;
    let Some((first, size)) = store.get_range(key, 0, FIRST_READ - 1).await? else { return Ok(None) };
    let hl = head_len(&first).with_context(|| format!("reading pack {key}"))?;
    let count = (hl as usize - HEAD) / ENTRY;
    let need = Index::read_weight_of(count) as u64;
    let whole = (first.len() as u64) >= hl;
    let first = if whole { Some(first) } else { None };
    let share = if need <= FIRST_READ.min(bound.most as u64) {
        first_share
    } else {
        drop(first_share);
        bound.take_for(project, need).await?
    };
    let first = match first {
        Some(b) => b,
        None => match store.get_range(key, 0, hl - 1).await? {
            Some((b, _)) => b,
            None => return Ok(None),
        },
    };
    let index = parse_index(&first, Some(size)).with_context(|| format!("reading pack {key}"))?;
    drop(first);
    Ok(Some(Held::new(Arc::new(index), size, share)))
}

/// The lookup structures' own memory: a project's entry, and each listed
/// pack it names (its name and bookkeeping); a loaded index weighs
/// [`Index::weight`] (its entries, exactly: 48 bytes a slot).
const PROJECT_WEIGHT: usize = 512;
const PACK_WEIGHT: usize = 128;
/// The lookup structures of all projects, together, by their real memory.
/// Past it, the indexes used least recently are unloaded, those of the
/// project in use too (BUG-1395, BUG-1396): a lookup that needs an unloaded
/// index reads it again from storage ([`Packs::find_paged`]), so a project of
/// any size always reads; then the entries of projects used least
/// recently, never the one in use.
pub const LOOKUP_BUDGET: usize = 128 << 20;

/// One listed pack of a project: its index while loaded, and when it was
/// last searched.
struct Listed {
    name: Arc<str>,
    index: Option<Arc<Index>>,
    used: AtomicU64,
}

#[derive(Default)]
struct Map {
    /// The project's listing was read at least once.
    loaded: bool,
    names: HashSet<Arc<str>>,
    /// Oldest first.
    packs: Vec<Listed>,
}

impl Map {
    fn weight(&self) -> usize {
        PROJECT_WEIGHT + self.packs.len() * PACK_WEIGHT + self.packs.iter().filter_map(|l| l.index.as_ref()).map(|i| i.weight()).sum::<usize>()
    }
}

struct ProjectPacks {
    /// Serialises listings; when the last one began.
    listing: tokio::sync::Mutex<Option<Instant>>,
    map: RwLock<Map>,
    used: AtomicU64,
}

/// What a lookup found.
pub enum Found {
    At(Arc<str>, Slot),
    /// In no pack this server knows of.
    Absent,
    /// In no loaded index, and some are unloaded ([`Packs::find_paged`]).
    Paged,
    /// The project's listing was never read here.
    Unloaded,
}

/// The uploads a person staged on this server recently, newest first, per
/// project (a push that lost a race uploads the same objects again: they
/// get the receipts of the pack that holds them, BUG-1157); in a bounded
/// cache (BUG-1396).
const RECENT_UPLOADS: usize = 8;
const RECENT_BUDGET: usize = 1 << 20;

/// A person's recent staged packs in a project, newest first.
type Recent = VecDeque<Arc<str>>;

/// Every project's listed packs, as this server knows them, and the packs
/// staged here.
pub struct Packs {
    db: Option<sqlx::PgPool>,
    projects: Mutex<HashMap<i64, Arc<ProjectPacks>>>,
    /// [`LOOKUP_BUDGET`] (smaller in tests).
    budget: usize,
    tick: AtomicU64,
    /// [`INDEXES_HELD`]: every index held outside the lookup maps.
    bound: Bound,
    /// Indexes and lengths of packs staged recently, by name (a push on the
    /// server that took the upload reads them without a storage read), each
    /// holding its share of `bound`; `None` once discarded here.
    staged: LruCache<Option<Arc<Held>>>,
    recent: LruCache<Recent>,
}

fn name_key(project: i64, name: &str) -> ObjectId {
    let mut h = blake3::Hasher::new();
    h.update(b"pack");
    h.update(&project.to_le_bytes());
    h.update(name.as_bytes());
    ObjectId(*h.finalize().as_bytes())
}

fn person_key(project: i64, person: i64) -> ObjectId {
    let mut h = blake3::Hasher::new();
    h.update(b"recent uploads");
    h.update(&project.to_le_bytes());
    h.update(&person.to_le_bytes());
    ObjectId(*h.finalize().as_bytes())
}

/// What a push or API commit keeps of a staged pack's index (BUG-1496):
/// how many objects it holds, its length, and the slots of the objects its
/// receipts name.
pub struct StagedSlots {
    pub objects: usize,
    pub size: u64,
    pub slots: Vec<(ObjectId, Slot)>,
}

impl Packs {
    pub fn new(db: Option<sqlx::PgPool>) -> Packs {
        Packs {
            db,
            projects: Mutex::new(HashMap::new()),
            budget: LOOKUP_BUDGET,
            tick: AtomicU64::new(0),
            // One holder takes at most what the staged-index cache leaves,
            // so a share for any index can always come free.
            bound: Bound { most: INDEXES_HELD - STAGED_INDEXES, ..Bound::new(INDEXES_HELD) },
            staged: LruCache::new(STAGED_INDEXES),
            recent: LruCache::new(RECENT_BUDGET),
        }
    }

    /// The server's bound on indexes held outside the lookup maps.
    pub fn bound(&self) -> &Bound {
        &self.bound
    }

    fn now(&self) -> u64 {
        self.tick.fetch_add(1, Ordering::Relaxed)
    }

    fn project(&self, project: i64) -> Arc<ProjectPacks> {
        let mut g = self.projects.lock().unwrap();
        let fresh = !g.contains_key(&project);
        let p = g
            .entry(project)
            .or_insert_with(|| {
                Arc::new(ProjectPacks {
                    listing: tokio::sync::Mutex::new(None),
                    map: RwLock::new(Map::default()),
                    used: AtomicU64::new(0),
                })
            })
            .clone();
        p.used.store(self.now(), Ordering::Relaxed);
        if fresh {
            Self::evict(&mut g, project, self.budget);
        }
        p
    }

    /// Where object `id` of `project` is, among the indexes this server
    /// has loaded (newest pack first).
    pub fn find(&self, project: i64, id: &ObjectId) -> Found {
        self.find_in(&self.project(project), id)
    }

    fn find_in(&self, p: &ProjectPacks, id: &ObjectId) -> Found {
        let m = p.map.read().unwrap();
        let mut paged = false;
        for l in m.packs.iter().rev() {
            match &l.index {
                Some(index) => {
                    if let Some(s) = index.get(id) {
                        l.used.store(self.now(), Ordering::Relaxed);
                        return Found::At(l.name.clone(), s);
                    }
                }
                None => paged = true,
            }
        }
        match (m.loaded, paged) {
            (false, _) => Found::Unloaded,
            (true, true) => Found::Paged,
            (true, false) => Found::Absent,
        }
    }

    /// Where object `id` of `project` is stored in a listed pack: in the
    /// indexes this server holds; or (`again`, after a miss everywhere
    /// since `since`) in one listed since, or one whose index it unloaded
    /// past its budget, read again from storage. One project entry serves
    /// the whole lookup, so an eviction of the project's entry meanwhile
    /// (another project's lookup) never empties it (BUG-1495's class).
    pub async fn locate(&self, store: &Arc<dyn BlobStore>, project: i64, id: &ObjectId, again: bool, since: Instant, reads: &AtomicU64) -> Result<Option<(Arc<str>, Slot)>> {
        let p = self.project(project);
        match self.find_in(&p, id) {
            Found::At(n, s) => return Ok(Some((n, s))),
            Found::Absent | Found::Paged if !again => return Ok(None),
            _ => {}
        }
        self.refresh_in(&p, store, project, since, reads).await?;
        self.find_paged_in(&p, store, project, id, reads).await
    }

    /// [`Packs::find`] in every listed pack of `project` this server knows:
    /// the loaded indexes are searched and the unloaded ones named **under
    /// one read of the map**, then those are read again from storage, one
    /// at a time, newest first, each loaded as it is read (BUG-1495: a
    /// lookup that only searched the indexes unloaded when it began missed
    /// one another lookup paged in meanwhile). So whatever pages in or out
    /// concurrently, every pack is searched: loaded ones then, unloaded
    /// ones from storage.
    pub async fn find_paged(&self, store: &Arc<dyn BlobStore>, project: i64, id: &ObjectId, reads: &AtomicU64) -> Result<Option<(Arc<str>, Slot)>> {
        self.find_paged_in(&self.project(project), store, project, id, reads).await
    }

    async fn find_paged_in(&self, p: &Arc<ProjectPacks>, store: &Arc<dyn BlobStore>, project: i64, id: &ObjectId, reads: &AtomicU64) -> Result<Option<(Arc<str>, Slot)>> {
        let unloaded: Vec<Arc<str>> = {
            let m = p.map.read().unwrap();
            let mut unloaded = Vec::new();
            for l in m.packs.iter().rev() {
                match &l.index {
                    Some(index) => {
                        if let Some(s) = index.get(id) {
                            l.used.store(self.now(), Ordering::Relaxed);
                            return Ok(Some((l.name.clone(), s)));
                        }
                    }
                    None => unloaded.push(l.name.clone()),
                }
            }
            unloaded
        };
        for name in unloaded {
            reads.fetch_add(1, Ordering::Relaxed);
            // Held under its share of the bound while it is read and
            // searched; then the lookup maps' (BUG-1496). If another server
            // merged and deleted `name` after its grace period (S29), forget
            // it here and keep searching.
            let Some(held) = read_index(&**store, &key(project, &name), &self.bound).await? else {
                self.forget(project, std::slice::from_ref(&name));
                continue;
            };
            let slot = held.index.get(id);
            self.load(p, project, &name, &held.index);
            if let Some(s) = slot {
                return Ok(Some((name, s)));
            }
        }
        Ok(None)
    }

    /// Load `index`, just read, as pack `name`'s in `p`'s map, if `p` is
    /// still the project's entry (an entry evicted meanwhile is only this
    /// lookup's: what it holds is not loaded into it).
    fn load(&self, p: &Arc<ProjectPacks>, project: i64, name: &str, index: &Arc<Index>) {
        if !self.projects.lock().unwrap().get(&project).is_some_and(|q| Arc::ptr_eq(q, p)) {
            return;
        }
        {
            let mut m = p.map.write().unwrap();
            if let Some(l) = m.packs.iter_mut().find(|l| &*l.name == name) {
                if l.index.is_none() {
                    l.index = Some(index.clone());
                }
                l.used.store(self.now(), Ordering::Relaxed);
            }
        }
        self.evict_now(project);
    }

    /// Add listed packs to `project`'s map (an index `None`: unloaded, read
    /// when a lookup needs it).
    fn add(&self, project: i64, packs: Vec<(Arc<str>, Option<Arc<Index>>)>, loaded: bool) {
        let p = self.project(project);
        {
            let mut m = p.map.write().unwrap();
            for (name, index) in packs {
                if !m.names.insert(name.clone()) {
                    continue;
                }
                m.packs.push(Listed { name, index, used: AtomicU64::new(self.now()) });
            }
            m.loaded |= loaded;
        }
        self.evict_now(project);
    }

    /// Drop packs `names` from `project`'s in-memory lookup map (S29: packs
    /// a merge or garbage-collection pass replaced and turned discarded).
    pub fn forget(&self, project: i64, names: &[Arc<str>]) {
        if names.is_empty() {
            return;
        }
        for n in names {
            self.staged.insert(name_key(project, n), None, 64);
        }
        let Some(p) = self.projects.lock().unwrap().get(&project).cloned() else {
            return;
        };
        let mut m = p.map.write().unwrap();
        for n in names {
            m.names.remove(n);
        }
        let Map { names, packs, .. } = &mut *m;
        packs.retain(|l| names.contains(&l.name));
    }

    /// Drop `project`'s cached pack listing when a cross-server GC epoch
    /// changes so the next lookup refreshes `LISTED` packs from the database.
    pub fn invalidate_project(&self, project: i64) {
        if self.db.is_some() {
            self.projects.lock().unwrap().remove(&project);
        }
    }

    fn evict_now(&self, project: i64) {
        let mut g = self.projects.lock().unwrap();
        Self::evict(&mut g, project, self.budget);
    }

    /// Fit every project's lookup structures in `budget`, by their real
    /// memory, read from the maps themselves under the projects' lock (so
    /// an add racing an eviction is never counted twice or lost): first
    /// unload the indexes used least recently, of any project; then drop
    /// the entries of projects used least recently, never `keep`'s (the
    /// one in use: its listing stays, so its lookups read what they need
    /// from storage, BUG-1395).
    fn evict(g: &mut HashMap<i64, Arc<ProjectPacks>>, keep: i64, budget: usize) {
        let mut total: usize = g.values().map(|p| p.map.read().unwrap().weight()).sum();
        if total <= budget {
            return;
        }
        let mut loaded: Vec<(u64, i64, Arc<str>)> = Vec::new();
        for (k, p) in g.iter() {
            for l in p.map.read().unwrap().packs.iter().filter(|l| l.index.is_some()) {
                loaded.push((l.used.load(Ordering::Relaxed), *k, l.name.clone()));
            }
        }
        loaded.sort();
        for (_, k, name) in loaded {
            if total <= budget {
                return;
            }
            let p = &g[&k];
            let mut m = p.map.write().unwrap();
            if let Some(l) = m.packs.iter_mut().find(|l| l.name == name) {
                if let Some(i) = l.index.take() {
                    total -= i.weight();
                }
            }
        }
        let mut by_use: Vec<(u64, i64)> = g.iter().filter(|(k, _)| **k != keep).map(|(k, p)| (p.used.load(Ordering::Relaxed), *k)).collect();
        by_use.sort();
        for (_, k) in by_use {
            if total <= budget {
                break;
            }
            if let Some(p) = g.remove(&k) {
                total -= p.map.read().unwrap().weight();
            }
        }
    }

    /// Read `project`'s listing again, and the indexes of the packs this
    /// server does not know, unless a listing began after `since` (it
    /// holds every pack listed before then).
    pub async fn refresh(&self, store: &Arc<dyn BlobStore>, project: i64, since: Instant, reads: &AtomicU64) -> Result<()> {
        self.refresh_in(&self.project(project), store, project, since, reads).await
    }

    async fn refresh_in(&self, p: &Arc<ProjectPacks>, store: &Arc<dyn BlobStore>, project: i64, since: Instant, reads: &AtomicU64) -> Result<()> {
        let mut last = p.listing.lock().await;
        if last.is_some_and(|t| t >= since) {
            return Ok(());
        }
        let began = Instant::now();
        let Some(db) = &self.db else {
            p.map.write().unwrap().loaded = true;
            *last = Some(began);
            return Ok(());
        };
        let rows: Vec<String> = sqlx::query_scalar("SELECT name FROM packs WHERE project_id = $1 AND state = $2 ORDER BY created_at, name")
            .bind(project)
            .bind(LISTED)
            .fetch_all(db)
            .await?;
        {
            let mut m = p.map.write().unwrap();
            let current: HashSet<Arc<str>> = rows.iter().map(|n| Arc::<str>::from(n.as_str())).collect();
            m.names.retain(|n| current.contains(n));
            m.packs.retain(|l| current.contains(&l.name));
        }
        self.load_listed(p, store, project, rows, reads).await?;
        *last = Some(began);
        Ok(())
    }

    /// Join packs `names` (listed, oldest first) to `p`'s map and mark its
    /// listing read: each one this server does not know is entered
    /// unloaded, then its index is read (16 at once, each under its share of
    /// the bound, taken without waiting) and **loaded as it is read**, so no
    /// more is held than the lookup budget and the bound allow (BUG-1496:
    /// all of them were collected before any was added). An index the bound
    /// has no room for now stays unloaded, for a lookup to read.
    async fn load_listed(&self, p: &Arc<ProjectPacks>, store: &Arc<dyn BlobStore>, project: i64, names: Vec<String>, reads: &AtomicU64) -> Result<()> {
        let new: Vec<Arc<str>> = {
            let mut m = p.map.write().unwrap();
            let mut new = Vec::new();
            for n in names {
                let n: Arc<str> = n.into();
                if m.names.insert(n.clone()) {
                    m.packs.push(Listed { name: n.clone(), index: None, used: AtomicU64::new(self.now()) });
                    new.push(n);
                }
            }
            new
        };
        let bound = self.bound.now();
        let mut set = tokio::task::JoinSet::new();
        let mut it = new.into_iter();
        loop {
            while set.len() < 16 {
                let Some(name) = it.next() else { break };
                let (k, store, bound) = (key(project, &name), store.clone(), bound.clone());
                reads.fetch_add(1, Ordering::Relaxed);
                set.spawn(async move { (name, read_index(&*store, &k, &bound).await) });
            }
            match set.join_next().await {
                Some(Ok((name, Ok(Some(held))))) => self.load(p, project, &name, &held.index),
                Some(Ok((name, Ok(None)))) => self.forget(project, &[name]),
                // The rest stay unloaded (the tasks still running stop).
                Some(Ok((_, Err(e)))) if indexes_full(&e) => break,
                Some(Ok((_, Err(e)))) => return Err(e),
                Some(Err(e)) => return Err(e.into()),
                None => break,
            }
        }
        p.map.write().unwrap().loaded = true;
        Ok(())
    }

    /// Packs this server listed in a transaction that committed (an index
    /// `None`: loaded when a lookup needs it).
    pub fn listed(&self, project: i64, packs: Vec<(Arc<str>, Option<Arc<Index>>)>) {
        // Only into a map that is loaded: an unloaded one reads the whole
        // listing when first used. Without a database, what this process
        // lists is the listing.
        let loaded = self.db.is_none() || self.project(project).map.read().unwrap().loaded;
        if loaded {
            self.add(project, packs, self.db.is_none());
        }
    }

    /// [`Packs::listed`], with every index in hand.
    pub fn listed_here(&self, project: i64, packs: Vec<(Arc<str>, Arc<Index>)>) {
        self.listed(project, packs.into_iter().map(|(n, i)| (n, Some(i))).collect());
    }

    /// Record staged pack `name` of `project`, uploaded by `person`, before
    /// it is written: the database knows every upload in storage.
    pub async fn record_staged(&self, project: i64, person: i64, name: &str, size: u64, objects: usize) -> Result<()> {
        self.record_staged_by(project, Some(person), name, size, objects).await
    }

    /// Record staged pack `name` of `project` (`person` `None`: written by
    /// a merge or garbage-collection pass, S29) before it is written.
    pub async fn record_staged_by(&self, project: i64, person: Option<i64>, name: &str, size: u64, objects: usize) -> Result<()> {
        let Some(db) = &self.db else { return Ok(()) };
        sqlx::query("INSERT INTO packs (project_id, name, state, person_id, size, objects, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)")
            .bind(project)
            .bind(name)
            .bind(STAGED)
            .bind(person)
            .bind(size as i64)
            .bind(objects as i64)
            .bind(veil_core::now_millis())
            .execute(db)
            .await?;
        Ok(())
    }

    /// Remember the index of a pack staged here, by `person`, with its
    /// share of the bound (given back when the cache drops it, or now if
    /// the cache does not keep it).
    pub fn staged_here(&self, project: i64, person: i64, name: &Arc<str>, mut held: Held) {
        held.unproject();
        let w = held.index.weight();
        self.staged.insert(name_key(project, name), Some(Arc::new(held)), w);
        let k = person_key(project, person);
        let mut q = self.recent.get(&k).unwrap_or_default();
        q.push_front(name.clone());
        q.truncate(RECENT_UPLOADS);
        let w = 96 + q.len() * 48;
        self.recent.insert(k, q, w);
    }

    /// The index of pack `name` of `project` if the staged-index cache
    /// holds it (a listed upload's, for the lookup maps).
    pub fn staged_cached(&self, project: i64, name: &str) -> Option<Arc<Index>> {
        self.staged.get(&name_key(project, name)).flatten().map(|h| h.index.clone())
    }

    /// A pack `person` staged here recently that holds every one of `ids`
    /// and is still staged or listed (asked of the database): an upload of
    /// those objects again gets its receipts instead of a new pack.
    pub async fn staged_holding(&self, project: i64, person: i64, ids: &[ObjectId]) -> Result<Option<Arc<str>>> {
        let names: Vec<Arc<str>> = self.recent.get(&person_key(project, person)).map(|q| q.into_iter().collect()).unwrap_or_default();
        for name in names {
            let Some(Some(held)) = self.staged.get(&name_key(project, &name)) else { continue };
            if !ids.iter().all(|id| held.index.get(id).is_some()) {
                continue;
            }
            if self.usable(project, person, std::slice::from_ref(&name)).await?.contains(&name) {
                return Ok(Some(name));
            }
        }
        Ok(None)
    }

    /// Of packs `names`, those `person` uploaded that are staged or listed
    /// now (not discarded): the only uploads a receipt may name.
    pub async fn usable(&self, project: i64, person: i64, names: &[Arc<str>]) -> Result<HashSet<Arc<str>>> {
        let Some(db) = &self.db else { return Ok(names.iter().cloned().collect()) };
        if names.is_empty() {
            return Ok(HashSet::new());
        }
        let asked: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM packs WHERE project_id = $1 AND name = ANY($2) AND person_id = $3 AND state IN ($4, $5)",
        )
        .bind(project)
        .bind(&asked)
        .bind(person)
        .bind(STAGED)
        .bind(LISTED)
        .fetch_all(db)
        .await?;
        let rows: HashSet<String> = rows.into_iter().collect();
        Ok(names.iter().filter(|n| rows.contains(&***n)).cloned().collect())
    }

    /// The index and length of staged pack `name`, with its share of the
    /// bound: from the staged-index cache, or read under a share of its own;
    /// `None` if it is not in the store (discarded).
    pub async fn staged_index(&self, store: &dyn BlobStore, project: i64, name: &str) -> Result<Option<Arc<Held>>> {
        if let Some(i) = self.staged.get(&name_key(project, name)) {
            return Ok(i);
        }
        Ok(read_index(store, &key(project, name), &self.bound).await?.map(Arc::new))
    }

    /// What a push or API commit keeps of staged pack `name` (BUG-1496,
    /// BUG-1620): its object count, its length and the slots of `ids` in it.
    /// If the staged-index cache holds the index, it is searched there;
    /// otherwise the sorted index on disk is bisected with ranged reads of
    /// at most [`FIRST_READ`] bytes, under a [`FIRST_READ`] share of the
    /// bound, never reading or holding the whole index. `None` if the pack
    /// is not in the store (discarded).
    pub async fn staged_slots(&self, store: &dyn BlobStore, project: i64, name: &str, ids: &[ObjectId]) -> Result<Option<StagedSlots>> {
        if let Some(cached) = self.staged.get(&name_key(project, name)) {
            let Some(held) = cached else { return Ok(None) };
            let slots = ids.iter().filter_map(|id| Some((*id, held.index.get(id)?))).collect();
            return Ok(Some(StagedSlots { objects: held.index.len(), size: held.size, slots }));
        }
        let _share = self.bound.take_for(Some(project), FIRST_READ.min(self.bound.most as u64)).await?;
        let k = key(project, name);
        let Some((first, size)) = store.get_range(&k, 0, FIRST_READ - 1).await? else { return Ok(None) };
        let hl = head_len(&first).with_context(|| format!("reading pack {k}"))?;
        if size < hl {
            bail!("a pack's index is cut short");
        }
        let count = (hl as usize - HEAD) / ENTRY;
        let in_first = ((first.len().min(hl as usize) - HEAD) / ENTRY).min(count);
        if in_first == count {
            let idx = parse_index(&first, Some(size)).with_context(|| format!("reading pack {k}"))?;
            drop(first);
            let slots = ids.iter().filter_map(|id| Some((*id, idx.get(id)?))).collect();
            return Ok(Some(StagedSlots { objects: count, size, slots }));
        }
        if ids.is_empty() {
            return Ok(Some(StagedSlots { objects: count, size, slots: Vec::new() }));
        }
        let mut wanted: Vec<ObjectId> = ids.to_vec();
        wanted.sort_unstable();
        wanted.dedup();
        let mut found: HashMap<ObjectId, Slot> = HashMap::with_capacity(wanted.len());
        let last_first = lookup_slice(&first[HEAD..HEAD + in_first * ENTRY], hl, size, None, None, &wanted, &mut found)
            .with_context(|| format!("reading pack {k}"))?;
        drop(first);
        let rem_start = match last_first {
            Some(last_id) => wanted.partition_point(|id| *id <= last_id),
            None => 0,
        };
        if rem_start < wanted.len() {
            bisect_slots(store, &k, hl, size, in_first, count, last_first, None, &wanted[rem_start..], &mut found)
                .await
                .with_context(|| format!("reading pack {k}"))?;
        }
        let slots = ids.iter().filter_map(|id| Some((*id, *found.get(id)?))).collect();
        Ok(Some(StagedSlots { objects: count, size, slots }))
    }

    /// Discard staged packs `names` of `project`: the row turns discarded
    /// first (so no push can list them after), then the storage objects
    /// go, **every one tried** whatever another's delete answers (BUG-1498;
    /// the first error is returned once all were tried). A pack already
    /// listed is left as it is. A discarded row whose pack is still stored
    /// (a failed delete, a server stopped in between) is S29's job's to
    /// delete (`storage-and-cost.md` §8).
    pub async fn discard(&self, store: &dyn BlobStore, project: i64, names: &[Arc<str>]) -> Result<()> {
        if names.is_empty() {
            return Ok(());
        }
        for n in names {
            self.staged.insert(name_key(project, n), None, 64);
        }
        let gone: Vec<String> = match &self.db {
            Some(db) => {
                let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
                sqlx::query_scalar(
                    "UPDATE packs SET state = $3, discarded_at = $5 WHERE project_id = $1 AND name = ANY($2) AND state = $4 RETURNING name",
                )
                .bind(project)
                .bind(&names)
                .bind(DISCARDED)
                .bind(STAGED)
                .bind(veil_core::now_millis())
                .fetch_all(db)
                .await?
            }
            None => names.iter().map(|n| n.to_string()).collect(),
        };
        let (mut first, mut failed) = (None, 0);
        for n in &gone {
            if let Err(e) = store.delete(&key(project, n)).await {
                failed += 1;
                first.get_or_insert(e);
            }
        }
        match first {
            Some(e) => Err(e.context(format!("{failed} of {} discarded packs of project {project} are still stored", gone.len()))),
            None => Ok(()),
        }
    }
}

const WINDOW_ENTRIES: usize = (FIRST_READ as usize) / ENTRY;

/// Validate a contiguous slice of index entries against `hl` and `size`, and
/// record any entries whose object id is in sorted `wanted` into `found`.
/// Returns the last entry's `(end_offset, id)`.
fn lookup_slice(
    slice: &[u8],
    hl: u64,
    size: u64,
    prev_id: Option<ObjectId>,
    next_id: Option<ObjectId>,
    wanted: &[ObjectId],
    found: &mut HashMap<ObjectId, Slot>,
) -> Result<Option<ObjectId>> {
    ensure!(slice.len().is_multiple_of(ENTRY), "pack index slice is not a whole number of entries");
    let mut prev = prev_id;
    let mut last = None;
    for chunk in slice.as_chunks::<ENTRY>().0 {
        let (id, slot) = parse_entry(chunk, hl, Some(size))?;
        if let Some(p) = prev {
            ensure!(id > p, "a pack's index is not sorted");
        }
        if wanted.binary_search(&id).is_ok() {
            found.insert(id, slot);
        }
        prev = Some(id);
        last = Some(id);
    }
    if let (Some(last_id), Some(n)) = (last, next_id) {
        ensure!(last_id < n, "a pack's index is not sorted");
    }
    Ok(last)
}

type BisectStep<'a> = (usize, usize, Option<ObjectId>, Option<ObjectId>, &'a [ObjectId]);

/// Find `wanted` (sorted, deduplicated) in entries `lo..hi` of a pack index in
/// `store` by bisecting with ranged reads of at most [`WINDOW_ENTRIES`]
/// entries (within one [`FIRST_READ`] buffer).
#[allow(clippy::too_many_arguments)]
async fn bisect_slots(
    store: &dyn BlobStore,
    key: &str,
    hl: u64,
    size: u64,
    lo: usize,
    hi: usize,
    prev_before_lo: Option<ObjectId>,
    next_after_hi: Option<ObjectId>,
    wanted: &[ObjectId],
    found: &mut HashMap<ObjectId, Slot>,
) -> Result<()> {
    let mut work: Vec<BisectStep<'_>> = vec![(lo, hi, prev_before_lo, next_after_hi, wanted)];
    while let Some((lo, hi, prev_lo, next_hi, sub)) = work.pop() {
        if lo >= hi || sub.is_empty() {
            continue;
        }
        let span = hi - lo;
        let (w_lo, w_hi) = if span <= WINDOW_ENTRIES {
            (lo, hi)
        } else {
            let half = WINDOW_ENTRIES / 2;
            let w_lo = (lo + span / 2).saturating_sub(half).max(lo);
            let w_hi = (w_lo + WINDOW_ENTRIES).min(hi);
            (w_lo, w_hi)
        };
        let start = HEAD as u64 + (w_lo * ENTRY) as u64;
        let want_bytes = (w_hi - w_lo) * ENTRY;
        let end = start + want_bytes as u64 - 1;
        let (bytes, total) = store.get_range(key, start, end).await?.context("pack vanished while bisecting its index")?;
        ensure!(total == size && bytes.len() == want_bytes, "pack index truncated at {start}..={end}");
        let first_id = ObjectId(bytes[..32].try_into().unwrap());
        if let Some(p) = prev_lo {
            ensure!(first_id > p, "pack index is not sorted");
        }
        if let Some(n) = next_hi {
            ensure!(first_id < n, "pack index is not sorted");
        }
        let last_id = lookup_slice(
            &bytes,
            hl,
            size,
            if w_lo == lo { prev_lo } else { None },
            if w_hi == hi { next_hi } else { None },
            sub,
            found,
        )?
        .expect("window is non-empty");
        if let Some(n) = next_hi {
            ensure!(last_id < n, "pack index is not sorted");
        }
        if w_hi < hi {
            let right_start = sub.partition_point(|id| *id <= last_id);
            if right_start < sub.len() {
                work.push((w_hi, hi, Some(last_id), next_hi, &sub[right_start..]));
            }
        }
        if w_lo > lo {
            let left_end = sub.partition_point(|id| *id < first_id);
            if left_end > 0 {
                work.push((lo, w_lo, prev_lo, Some(first_id), &sub[..left_end]));
            }
        }
    }
    ensure!(wanted.iter().all(|id| found.contains_key(id)), "a pack's index is not sorted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(s: &str) -> (ObjectId, Bytes) {
        let raw = format!("veil:blob\n{s}");
        (ObjectId::hash(raw.as_bytes()), Bytes::from(raw))
    }

    #[test]
    fn a_pack_round_trips_through_its_index() {
        let objects: Vec<_> = (0..300).map(|i| obj(&format!("object {i}"))).collect();
        let mut with_dup = objects.clone();
        with_dup.push(objects[7].clone());
        let (pack, index) = build(with_dup).unwrap();
        assert_eq!(index.len(), 300);
        let parsed = parse_index(&pack, Some(pack.len() as u64)).unwrap();
        for (id, raw) in &objects {
            let s = parsed.get(id).unwrap();
            assert_eq!(index.get(id), Some(s));
            let bytes = &pack[s.offset as usize..=s.last() as usize];
            assert_eq!(entry(id, s, bytes).unwrap(), &raw[..]);
            assert_eq!(s.encoding_len(), raw.len() as u64);
            // Another object's entry is refused, whole or in part; so is a
            // slot that does not end where the entry says it does (BUG-1497).
            let other = objects.iter().find(|(o, _)| o != id).unwrap().0;
            assert!(entry(&other, s, bytes).is_err() && entry(id, s, &bytes[..10]).is_err());
            let longer = Slot { len: s.len + 1, ..s };
            let shorter = Slot { len: s.len - 1, ..s };
            assert!(entry(id, longer, bytes).is_err() && entry(id, shorter, bytes).is_err(), "a slot of another length than the entry states");
        }
        assert!(parsed.get(&ObjectId::hash(b"absent")).is_none());
        assert_eq!(head_len(&pack[..HEAD]).unwrap(), (HEAD + 300 * ENTRY) as u64);
        // An empty pack is a valid pack.
        let (empty, i) = build(vec![]).unwrap();
        assert!(i.is_empty() && parse_index(&empty, Some(empty.len() as u64)).unwrap().is_empty());
    }

    /// A damaged or hostile index is refused, never read past its bytes.
    #[test]
    fn malformed_indexes_are_refused() {
        let (pack, _) = build(vec![obj("a"), obj("b")]).unwrap();
        let size = Some(pack.len() as u64);
        assert!(parse_index(&pack[..HEAD + ENTRY], size).is_err(), "cut short");
        assert!(parse_index(b"veilpack1\n\0\0\0\0", None).is_err(), "another magic");
        let mut huge = pack.to_vec();
        huge[MAGIC.len()..HEAD].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(head_len(&huge).is_err(), "a count past the limit");
        let mut unsorted = pack.to_vec();
        let (a, b) = (HEAD, HEAD + ENTRY);
        let first: Vec<u8> = unsorted[a..b].to_vec();
        unsorted.copy_within(b..b + ENTRY, a);
        unsorted[b..b + ENTRY].copy_from_slice(&first);
        assert!(parse_index(&unsorted, size).is_err(), "unsorted");
        let mut past = pack.to_vec();
        past[HEAD + 32..HEAD + 40].copy_from_slice(&(pack.len() as u64).to_be_bytes());
        assert!(parse_index(&past, size).is_err(), "a slot past the end");
        let mut inside = pack.to_vec();
        inside[HEAD + 32..HEAD + 40].copy_from_slice(&0u64.to_be_bytes());
        assert!(parse_index(&inside, size).is_err(), "a slot over the index");
        let mut overflow = pack.to_vec();
        overflow[HEAD + 32..HEAD + 40].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(parse_index(&overflow, None).is_err(), "an offset that overflows");
        let mut short = pack.to_vec();
        short[HEAD + 40..HEAD + 44].copy_from_slice(&(ENTRY_HEAD as u32).to_be_bytes());
        assert!(parse_index(&short, size).is_err(), "a slot with room for its entry's head only");
        assert!(parse_index(b"veilpack2\n\0\0\0\0", None).is_err(), "a pack before cycle 4 (entries without their length) is not a pack");
        assert!(valid_name(&new_name()) && !valid_name("../x") && !valid_name(&"A".repeat(32)));
    }

    fn total(packs: &Packs) -> usize {
        packs.projects.lock().unwrap().values().map(|p| p.map.read().unwrap().weight()).sum()
    }

    /// The lookup structures stay within their budget, every project's
    /// entry counted; the project in use keeps its entry.
    #[test]
    fn lookup_maps_are_bounded_by_bytes() {
        let budget = 1 << 20;
        let packs = Packs { budget, ..Packs::new(None) };
        let index = |n: usize, salt: usize| {
            let objects: Vec<_> = (0..n).map(|i| obj(&format!("{salt} {i}"))).collect();
            Arc::new(build(objects).unwrap().1)
        };
        let per = budget / 48 / 3;
        for p in 0..5 {
            packs.listed_here(p, vec![(Arc::from(new_name()), index(per, p as usize))]);
            assert!(total(&packs) <= budget, "{} bytes after project {p}", total(&packs));
            assert!(packs.projects.lock().unwrap().contains_key(&p), "the project in use is kept");
            assert!(matches!(packs.find(p, &obj(&format!("{p} 7")).0), Found::At(..)), "the index just used is loaded");
        }
        // Many projects touched once: bounded too.
        for p in 100..100 + (budget / PROJECT_WEIGHT) as i64 + 10 {
            let _ = packs.find(p, &ObjectId::hash(b"x"));
        }
        assert!(total(&packs) <= budget);
    }

    /// BUG-1395 (S28 cycle 2, fixed): a project whose lookup structures
    /// alone pass the budget lost its map as it was filled, so its packed
    /// objects read as missing. Now its indexes are unloaded past the budget
    /// (its listing kept), and a lookup reads them again from storage
    /// (`Packs::find_paged`): every object of a project of any size is
    /// found. Here with a budget of 1 MiB and a pack's index of more.
    #[tokio::test]
    async fn bug_1395_a_project_past_the_lookup_budget_still_finds_its_objects() {
        let budget = 1 << 20;
        let packs = Packs { budget, ..Packs::new(None) };
        let n = budget / 48 + 100;
        let objects: Vec<_> = (0..n).map(|i| obj(&format!("big {i}"))).collect();
        let probe = objects[n / 2].0;
        let (bytes, index) = build(objects).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn BlobStore> = Arc::new(crate::store::FsStore::new(dir.path()));
        let name: Arc<str> = Arc::from(new_name());
        store.put(&key(7, &name), bytes).await.unwrap();
        // `refresh`, with the listing a database answered.
        packs.add(7, vec![(name.clone(), Some(Arc::new(index)))], true);
        assert!(total(&packs) <= budget, "within the budget: {}", total(&packs));
        assert!(packs.projects.lock().unwrap().contains_key(&7), "the project in use keeps its listing");
        // `Objects::in_pack`, right after: found, from storage if need be.
        let reads = AtomicU64::new(0);
        let found = match packs.find(7, &probe) {
            Found::At(n, s) => Some((n, s)),
            Found::Paged => packs.find_paged(&store, 7, &probe, &reads).await.unwrap(),
            Found::Absent | Found::Unloaded => None,
        };
        let (n2, s) = found.expect("an object of a listed pack of a project past the budget is found");
        assert_eq!(n2, name);
        let (b, _) = store.get_range(&key(7, &name), s.offset, s.last()).await.unwrap().unwrap();
        assert!(entry(&probe, s, &b).is_ok());
        // An object it does not hold: absent, not an error.
        let missing = ObjectId::hash(b"not in the pack");
        if matches!(packs.find(7, &missing), Found::Paged) {
            assert!(packs.find_paged(&store, 7, &missing, &reads).await.unwrap().is_none());
        }
    }

    /// BUG-1495 (S28 cycle 3 review): `Objects::in_pack` asks
    /// [`Packs::find`] (the loaded indexes) and then, on `Paged`,
    /// [`Packs::find_paged`], which searches only the indexes unloaded **when
    /// it starts**. Nothing holds the map between the two: a lookup of the
    /// same project that pages the object's index in between (a clone's
    /// concurrent reads past the budget do) makes it loaded, so neither call
    /// searches it, and an object of a listed pack reads as missing. Here
    /// the two lookups are interleaved by hand, as two tasks can be. Fixed
    /// (cycle 4): `find_paged` searches the loaded indexes and names the
    /// unloaded ones under one read of the map, so together they cover every
    /// listed pack, whatever pages in or out between the two calls.
    #[tokio::test]
    async fn bug_1495_a_lookup_racing_a_page_in_still_finds_its_object() {
        let budget = 1 << 20;
        let packs = Packs { budget, ..Packs::new(None) };
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn BlobStore> = Arc::new(crate::store::FsStore::new(dir.path()));
        // Three packs of 8,000 objects (384 KiB of index each): two fit.
        let mut names = Vec::new();
        let mut members = Vec::new();
        for k in 0..3 {
            let objects: Vec<_> = (0..8_000).map(|i| obj(&format!("pack {k} object {i}"))).collect();
            members.push((objects[0].0, objects[1].0));
            let (bytes, index) = build(objects).unwrap();
            let name: Arc<str> = Arc::from(new_name());
            store.put(&key(7, &name), bytes).await.unwrap();
            packs.listed_here(7, vec![(name.clone(), Arc::new(index))]);
            names.push(name);
        }
        assert!(total(&packs) <= budget, "within the budget: {}", total(&packs));
        let (target, neighbour) = members[0];
        // Task A: its object's pack (the oldest) is unloaded.
        assert!(matches!(packs.find(7, &target), Found::Paged), "the first pack's index is unloaded past the budget");
        // Task B, in between: pages the same pack in, for another object of it.
        let reads = AtomicU64::new(0);
        let b = packs.find_paged(&store, 7, &neighbour, &reads).await.unwrap();
        assert_eq!(b.map(|(n, _)| n), Some(names[0].clone()), "task B finds its object in the first pack");
        // Task A goes on: `find_paged`, as `in_pack` calls it on `Paged`.
        let a = packs.find_paged(&store, 7, &target, &reads).await.unwrap();
        assert_eq!(a.map(|(n, _)| n), Some(names[0].clone()), "an object of a listed pack read as missing");
    }

    /// BUG-1498 (S28 cycle 3 review): `Packs::discard` turns the rows
    /// discarded, then deletes the packs one by one and stops at the first
    /// delete that fails (a store error past its retries), so the packs after
    /// it stay in storage, discarded, with nothing to delete them: S29's job
    /// is documented (`HUB.md` §13.20) to remove staged rows' packs, not
    /// discarded ones'. What a refused push uploaded (a plain-text secret,
    /// BUG-930) then stays stored. A server stopped between the update and
    /// the deletes leaves the same. Fixed (cycle 4): every delete is tried,
    /// and S29's sweep removes discarded rows' packs
    /// (`storage-and-cost.md` §8).
    #[tokio::test]
    async fn bug_1498_a_failed_delete_leaves_no_other_discarded_pack_stored() {
        struct FailsOnce(crate::store::FsStore, std::sync::atomic::AtomicBool);
        #[async_trait::async_trait]
        impl BlobStore for FailsOnce {
            async fn get(&self, key: &str) -> Result<Option<Bytes>> {
                self.0.get(key).await
            }
            async fn put(&self, key: &str, data: Bytes) -> Result<()> {
                self.0.put(key, data).await
            }
            async fn exists(&self, key: &str) -> Result<bool> {
                self.0.exists(key).await
            }
            async fn delete(&self, key: &str) -> Result<()> {
                if !self.1.swap(true, Ordering::SeqCst) {
                    bail!("the store is unreachable");
                }
                self.0.delete(key).await
            }
            async fn list(&self, prefix: &str) -> Result<Vec<String>> {
                self.0.list(prefix).await
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let store = FailsOnce(crate::store::FsStore::new(dir.path()), Default::default());
        let packs = Packs::new(None);
        let names: Vec<Arc<str>> = (0..3).map(|_| Arc::from(new_name())).collect();
        for (i, n) in names.iter().enumerate() {
            store.put(&key(1, n), build(vec![obj(&format!("refused {i}"))]).unwrap().0).await.unwrap();
        }
        let r = packs.discard(&store, 1, &names).await;
        assert!(r.is_err(), "the first delete fails");
        let left = store.list("p/1/pack/").await.unwrap();
        assert_eq!(left.len(), 1, "every other discarded pack is deleted whatever one delete answers: {left:?}");
        assert!(store.1.load(Ordering::SeqCst));
    }

    /// BUG-1396 (S28 cycle 2), the same class: the recent uploads of each
    /// person in each project (`Packs::recent`, for a retry's receipts) are
    /// kept for every pair that ever uploaded on this server, never dropped:
    /// unlike the staged indexes beside them (an `LruCache` of 32 MiB), the
    /// map grows with the server's uptime.
    #[tokio::test]
    async fn bug_1396_recent_uploads_are_bounded() {
        let packs = Packs::new(None);
        let index = Arc::new(build(vec![obj("one")]).unwrap().1);
        for person in 0..200_000 {
            let held = Held::new(index.clone(), 100, packs.bound.take(index.weight() as u64).await.unwrap());
            packs.staged_here(1, person, &Arc::from(new_name()), held);
        }
        assert_eq!(packs.bound.available(), INDEXES_HELD - packs.staged.stats().weight, "the cache's indexes hold their shares, dropped ones gave theirs back");
        let kept = packs.recent.stats().entries;
        assert!(kept <= 10_000, "{kept} people's recent uploads kept, with nothing staged left to name for most");
    }

    /// BUG-1396 (S28 cycle 2): the lookup maps' weight is counted at 80
    /// bytes a slot, but a slot is a 64-byte entry of a `HashMap` whose
    /// table doubles (a power of two of buckets, filled to 7/8 at most):
    /// just past a doubling, a slot takes about 146 bytes. Measured in a
    /// child process (`MALLOC_MMAP_THRESHOLD_` fixed, so freed tables go
    /// back to the system): maps the budget allows of projects of 460,000
    /// packed objects each hold about 1.5 times `LOOKUP_BUDGET`.
    #[test]
    fn bug_1396_lookup_maps_stay_within_their_budget_in_memory() {
        const CHILD: &str = "VEIL_TEST_LOOKUP_MAPS_CHILD";
        const NAME: &str = "pack::tests::bug_1396_lookup_maps_stay_within_their_budget_in_memory";
        if std::env::var_os(CHILD).is_some() {
            let rss = || -> usize {
                let s = std::fs::read_to_string("/proc/self/status").unwrap();
                let l = s.lines().find(|l| l.starts_with("VmRSS:")).unwrap();
                l.split_whitespace().nth(1).unwrap().parse::<usize>().unwrap() << 10
            };
            let packs = Packs::new(None);
            let before = rss();
            for p in 0..6i64 {
                let mut entries: Vec<(ObjectId, Slot)> = (0..460_000u64)
                    .map(|i| (ObjectId::hash(&[p.to_le_bytes(), i.to_le_bytes()].concat()), Slot { offset: 1 << 30, len: 100 }))
                    .collect();
                entries.sort_by_key(|e| e.0);
                packs.listed_here(p, vec![(Arc::from(new_name()), Arc::new(Index { entries }))]);
            }
            let grew = rss().saturating_sub(before);
            let accounted = total(&packs);
            println!("LOOKUP-MAPS projects={} accounted={accounted} grew={grew}", packs.projects.lock().unwrap().len());
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([NAME, "--exact", "--nocapture", "--include-ignored", "--test-threads=1"])
            .env(CHILD, "1")
            .env("MALLOC_MMAP_THRESHOLD_", "131072")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(out.status.success(), "the child failed: {text}{}", String::from_utf8_lossy(&out.stderr));
        let line = text.lines().find_map(|l| l.find("LOOKUP-MAPS").map(|at| &l[at..])).unwrap_or_else(|| panic!("no measurement in {text}"));
        let field = |k: &str| -> usize { line.split_whitespace().find_map(|w| w.strip_prefix(k)).unwrap().parse().unwrap() };
        let (accounted, grew) = (field("accounted="), field("grew="));
        assert!(accounted <= LOOKUP_BUDGET, "{line}");
        assert!(grew <= LOOKUP_BUDGET + (8 << 20), "the lookup maps took {} MiB of memory for a budget of {} MiB ({line})", grew >> 20, LOOKUP_BUDGET >> 20);
    }

    /// BUG-1496 (cycle 4 guarantee): every index held in memory outside
    /// the lookup maps holds a share of one server-wide bound, taken before
    /// it is read: one being read ([`read_index`]), the staged-index
    /// cache's, a push's. Past the bound a read waits for a share and is
    /// then answered [`IndexesFull`] (`warming`), never with an index held
    /// outside it; `refresh` leaves a pack it has no share for unloaded, for
    /// a lookup to read once one is free; a push keeps of a staged index only
    /// the slots its receipts name ([`Packs::staged_slots`]), holding the
    /// index itself only while it is read; and an index the cache drops gives
    /// its share back.
    #[tokio::test]
    async fn indexes_held_outside_the_lookup_maps_share_one_bound() {
        let total = 128 << 10;
        let bound = Bound { most: total, wait: Duration::from_millis(100), ..Bound::new(total) };
        let packs = Packs { bound: bound.clone(), ..Packs::new(None) };
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn BlobStore> = Arc::new(crate::store::FsStore::new(dir.path()));
        // 1,000 objects: an index of 48 KiB, which with the parse's working
        // copy and the bytes read (108 KiB) takes more than half the bound.
        let objects: Vec<_> = (0..1_000).map(|i| obj(&format!("held {i}"))).collect();
        let ids: Vec<ObjectId> = objects.iter().map(|(id, _)| *id).collect();
        let (bytes, _) = build(objects).unwrap();
        let name: Arc<str> = Arc::from(new_name());
        store.put(&key(7, &name), bytes.clone()).await.unwrap();
        let held = read_index(&*store, &key(7, &name), &bound).await.unwrap().unwrap();
        let weight = held.index.weight();
        assert_eq!(bound.available(), total - weight, "an index read holds exactly its weight once parsed");
        // A second read finds no share in time: refused, in about the wait.
        let t = Instant::now();
        let e = read_index(&*store, &key(7, &name), &bound).await.err().expect("no share is free for a second index");
        assert!(indexes_full(&e), "{e:#}");
        assert!(t.elapsed() < Duration::from_secs(5));
        // Kept by the staged-index cache: the share stays with it, and a
        // push reading the index from the cache takes none of its own,
        // keeping only the slots its receipts name.
        packs.staged_here(7, 1, &name, held);
        assert_eq!(bound.available(), total - weight);
        let slots = packs.staged_slots(&*store, 7, &name, &ids[..3]).await.unwrap().unwrap();
        assert_eq!((slots.objects, slots.size, slots.slots.len()), (1_000, bytes.len() as u64, 3));
        assert!(slots.slots.iter().all(|(id, _)| ids[..3].contains(id)));
        assert_eq!(bound.available(), total - weight, "a push holds no index of its own");
        // Dropped by the cache (evicted): its share comes back.
        packs.staged.clear();
        assert_eq!(bound.available(), total, "an index the cache dropped gave its share back");
        // A push reading an index the cache does not hold: read under a
        // share, kept only while the slots are taken.
        let slots = packs.staged_slots(&*store, 7, &name, &ids[..3]).await.unwrap().unwrap();
        assert_eq!((slots.objects, slots.slots.len()), (1_000, 3));
        assert_eq!(bound.available(), total, "the index is not held once the slots are");
        // `refresh` (its listing in hand) while another holder has the whole
        // bound: the pack enters the map unloaded, nothing is read into
        // memory, and a lookup pages it in once a share is free.
        let other = bound.take(total as u64).await.unwrap();
        let p = packs.project(7);
        let reads = AtomicU64::new(0);
        packs.load_listed(&p, &store, 7, vec![name.to_string()], &reads).await.unwrap();
        assert!(matches!(packs.find(7, &ids[0]), Found::Paged), "the pack is listed and unloaded");
        let e = packs.find_paged(&store, 7, &ids[0], &reads).await.expect_err("no share: the lookup is refused (warming)");
        assert!(indexes_full(&e), "{e:#}");
        drop(other);
        let found = packs.find_paged(&store, 7, &ids[0], &reads).await.unwrap();
        assert_eq!(found.map(|(n, _)| n), Some(name.clone()), "found once a share is free");
        assert!(matches!(packs.find(7, &ids[0]), Found::At(..)), "and loaded into the lookup maps");
        assert_eq!(bound.available(), total, "the lookup maps' indexes are bounded by the lookup budget, not the bound");
    }

    /// Objects listed so far in one project: each id and its pack.
    type Known = Arc<Mutex<Vec<(ObjectId, Arc<str>)>>>;

    /// Write pack `k` of `project` (`per` objects) and list it as
    /// `Packs::refresh` does with a listing in hand ([`Packs::load_listed`]);
    /// then make its objects known.
    async fn list_pack(packs: &Packs, store: &Arc<dyn BlobStore>, project: i64, k: usize, per: usize, known: &Known) {
        let objects: Vec<_> = (0..per).map(|i| obj(&format!("project {project} pack {k} object {i}"))).collect();
        let ids: Vec<ObjectId> = objects.iter().map(|(id, _)| *id).collect();
        let (bytes, _) = build(objects).unwrap();
        let name: Arc<str> = Arc::from(new_name());
        store.put(&key(project, &name), bytes).await.unwrap();
        let reads = AtomicU64::new(0);
        packs.load_listed(&packs.project(project), store, project, vec![name.to_string()], &reads).await.unwrap();
        known.lock().unwrap().extend(ids.into_iter().map(|id| (id, name.clone())));
    }

    /// `lookups` lookups of known objects of `project`, each as
    /// `Objects::in_pack` runs one (`again` after a miss): found (in its own
    /// pack, its entry checked), or with `tight` refused for want of a share
    /// of the bound; never answered missing. How many were found, refused.
    async fn look_up_known(packs: Arc<Packs>, store: Arc<dyn BlobStore>, known: Known, project: i64, seed: u64, lookups: usize, tight: bool) -> (usize, usize) {
        let (mut found, mut refused, mut x) = (0, 0, seed);
        let reads = AtomicU64::new(0);
        for _ in 0..lookups {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            let (id, name) = {
                let k = known.lock().unwrap();
                k[(x >> 33) as usize % k.len()].clone()
            };
            let since = Instant::now();
            let r = match packs.locate(&store, project, &id, false, since, &reads).await {
                Ok(None) => packs.locate(&store, project, &id, true, since, &reads).await,
                r => r,
            };
            match r {
                Ok(Some((n, s))) => {
                    assert_eq!(n, name, "found in another pack");
                    let (b, _) = store.get_range(&key(project, &n), s.offset, s.last()).await.unwrap().unwrap();
                    entry(&id, s, &b).expect("the slot found is the object's entry");
                    found += 1;
                }
                Ok(None) => panic!("an object of a listed pack of project {project} answered missing (tight bound: {tight})"),
                Err(e) if tight && indexes_full(&e) => refused += 1,
                Err(e) => panic!("{e:#}"),
            }
            tokio::task::yield_now().await;
        }
        (found, refused)
    }

    /// Review s28r4 (S28 guarantee 2, cycle 4's BUG-1495 fix under load):
    /// no lookup answers "missing" for a stored object, whatever other
    /// lookups page in and out and packs are listed meanwhile. Twelve tasks
    /// look up objects of a project whose indexes never fit the budget
    /// together (about two of ten do: each lookup pages one in and another
    /// out), three look up another project's (paging this one's out), and
    /// one lists new packs (`load_listed`, what `refresh` does with a
    /// listing) while they run, on eight threads. Every lookup finds its
    /// object in its pack. Then the same with the bound on indexes held
    /// outside the maps tight (room to read one index, a short wait): a
    /// lookup finds its object or is refused (`IndexesFull`, 503), never
    /// answers it missing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn s28r4_no_lookup_answers_missing_while_others_page_in_out_and_list() {
        const PER: usize = 2_000;
        const LOOKUPS: usize = 150;
        for tight in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let store: Arc<dyn BlobStore> = Arc::new(crate::store::FsStore::new(dir.path()));
            let budget = 2 * Index::weight_of(PER) + 16 * PACK_WEIGHT + 2 * PROJECT_WEIGHT + 4096;
            let mut packs = Packs { budget, ..Packs::new(None) };
            if tight {
                let total = 300_000;
                packs.bound = Bound { most: total, wait: Duration::from_millis(5), ..Bound::new(total) };
            }
            let packs = Arc::new(packs);
            let (known7, known8): (Known, Known) = Default::default();
            for k in 0..4 {
                list_pack(&packs, &store, 7, k, PER, &known7).await;
            }
            for k in 0..2 {
                list_pack(&packs, &store, 8, k, PER, &known8).await;
            }
            let mut set = tokio::task::JoinSet::new();
            for t in 0..15u64 {
                let (project, known) = if t < 12 { (7, known7.clone()) } else { (8, known8.clone()) };
                set.spawn(look_up_known(packs.clone(), store.clone(), known, project, t + 1, LOOKUPS, tight));
            }
            let lister = {
                let (packs, store, known) = (packs.clone(), store.clone(), known7.clone());
                tokio::spawn(async move {
                    for k in 4..10 {
                        tokio::time::sleep(Duration::from_millis(3)).await;
                        list_pack(&packs, &store, 7, k, PER, &known).await;
                    }
                })
            };
            let (mut found, mut refused) = (0, 0);
            while let Some(r) = set.join_next().await {
                let (f, r) = r.expect("no lookup panicked (none answered missing)");
                found += f;
                refused += r;
            }
            lister.await.unwrap();
            println!("tight bound {tight}: {found} found, {refused} refused");
            assert_eq!(found + refused, 15 * LOOKUPS);
            if tight {
                assert!(found > 0, "some lookups found their objects");
            } else {
                assert_eq!(refused, 0);
                assert!(total(&packs) <= budget, "within the budget: {}", total(&packs));
            }
            assert_eq!(packs.bound.available(), if tight { 300_000 } else { INDEXES_HELD }, "every share given back");
        }
    }

    /// BUG-1620 (review s28r4): the bound on indexes held outside the lookup
    /// maps ([`INDEXES_HELD`]) is one queue for the whole server, first come
    /// first served (a fair semaphore), with no share per project or
    /// person, and a request that waits for it 10 s ([`INDEX_WAIT`]) is
    /// answered 503. So one person's requests can starve every other
    /// project's uploads (`Objects::write_pack`), pushes (`staged_slots`)
    /// and paged lookups (`find_paged`), however small their own index:
    /// - the staged-index cache holds up to 32 MiB of shares, and fills with
    ///   the person's own small uploads (another upload that would evict
    ///   them needs a share first, so cannot);
    /// - a push reads the index of every staged pack its receipts name, 16
    ///   at once (`sync::staging`); an index the cache does not hold (one
    ///   past 32 MiB, about 700,000 objects, never is) is read from storage
    ///   each time, under a share of 64 MiB: all the cache leaves;
    /// - so while such reads queue, every other request waits behind them
    ///   with nothing beside them to take: past 10 s of queued reads (16 a
    ///   push, about a second each on an object store) it is answered 503.
    ///
    /// Fixed (cycle 5): (a) `staged_slots` bisects an uncached staged index
    /// with ranged reads under one `FIRST_READ` (64 KiB) share rather than
    /// reading and parsing the whole index, and (b) `Bound` gives each
    /// project its own fair share so one project's concurrent reads/writes
    /// can never starve another project's.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn bug_1620_one_persons_index_reads_never_starve_another_projects_lookup() {
        struct Slow(crate::store::FsStore);
        #[async_trait::async_trait]
        impl BlobStore for Slow {
            async fn get(&self, key: &str) -> Result<Option<Bytes>> {
                self.0.get(key).await
            }
            async fn put(&self, key: &str, data: Bytes) -> Result<()> {
                self.0.put(key, data).await
            }
            async fn exists(&self, key: &str) -> Result<bool> {
                self.0.exists(key).await
            }
            async fn get_range(&self, key: &str, start: u64, end: u64) -> Result<Option<(Bytes, u64)>> {
                if end >= FIRST_READ {
                    tokio::time::sleep(Duration::from_millis(600)).await;
                }
                self.0.get_range(key, start, end).await
            }
            async fn delete(&self, key: &str) -> Result<()> {
                self.0.delete(key).await
            }
            async fn list(&self, prefix: &str) -> Result<Vec<String>> {
                self.0.list(prefix).await
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn BlobStore> = Arc::new(Slow(crate::store::FsStore::new(dir.path())));
        // The participant's small upload, which the staged-index cache keeps
        // (the cache full: on the server 32 MiB of 96).
        let cached: Vec<_> = (0..5_000).map(|i| obj(&format!("cached {i}"))).collect();
        let cached_name: Arc<str> = Arc::from(new_name());
        let (bytes, index) = build(cached).unwrap();
        let w = index.weight();
        store.put(&key(1, &cached_name), bytes).await.unwrap();
        // The server's proportions: one holder takes at most what the cache
        // leaves (on the server 64 MiB), a wait shorter than a large read.
        let total = 1 << 20;
        let bound = Bound { most: total - w, wait: Duration::from_millis(200), ..Bound::new(total) };
        let packs = Arc::new(Packs { bound, ..Packs::new(None) });
        let held = read_index(&*store, &key(1, &cached_name), &packs.bound).await.unwrap().unwrap();
        packs.staged_here(1, 1, &cached_name, held);
        assert_eq!(packs.bound.available(), total - w, "the cache holds its index's share");
        assert!(packs.staged_cached(1, &cached_name).is_some());
        // The participant's large staged upload: 20,000 objects, an index
        // the cache does not hold.
        let big: Vec<_> = (0..20_000).map(|i| obj(&format!("staged {i}"))).collect();
        let mut sorted_ids: Vec<ObjectId> = big.iter().map(|(id, _)| *id).collect();
        sorted_ids.sort_unstable();
        // Pick an id near the end of the sorted index so bisection must range-read past FIRST_READ,
        // and verify staged_slots finds ids across start, middle, and end.
        let probe = *sorted_ids.last().unwrap();
        let sample = [sorted_ids[0], sorted_ids[sorted_ids.len() / 2], probe];
        let big_name: Arc<str> = Arc::from(new_name());
        store.put(&key(1, &big_name), build(big).unwrap().0).await.unwrap();
        let check = packs.staged_slots(&*store, 1, &big_name, &sample).await.unwrap().unwrap();
        assert_eq!(check.objects, 20_000);
        assert_eq!(check.slots.len(), 3, "start, middle, and end ids found by ranged bisection");
        // Other projects' listed packs of 10 objects, their indexes unloaded.
        let mut wanted = Vec::new();
        for project in 2..5 {
            let small: Vec<_> = (0..10).map(|i| obj(&format!("project {project} object {i}"))).collect();
            let id = small[3].0;
            let name: Arc<str> = Arc::from(new_name());
            store.put(&key(project, &name), build(small).unwrap().0).await.unwrap();
            packs.add(project, vec![(name.clone(), None)], true);
            wanted.push((project, id, name));
        }
        // Success first: with nothing else held, a lookup finds its object.
        let reads = AtomicU64::new(0);
        let (p0, id0, name0) = wanted.remove(0);
        let found = packs.find_paged(&store, p0, &id0, &reads).await.unwrap();
        assert_eq!(found.map(|(n, _)| n), Some(name0), "an idle server finds it");
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut pushes = tokio::task::JoinSet::new();
        for i in 0..4 {
            let (packs, store, stop, name) = (packs.clone(), store.clone(), stop.clone(), big_name.clone());
            pushes.spawn(async move {
                let mut n = 0;
                while !stop.load(Ordering::Relaxed) {
                    // Half run staged_slots, half hold project 1's full fair share via take_for(Some(1), ...)
                    if i < 2 {
                        if let Ok(Some(s)) = packs.staged_slots(&*store, 1, &name, &[probe]).await {
                            assert_eq!(s.slots.len(), 1);
                            n += 1;
                        }
                    } else if let Ok(_s) = packs.bound.take_for(Some(1), (192 << 10) as u64).await {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        n += 1;
                    }
                }
                n
            });
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut answers = Vec::new();
        for (project, id, name) in &wanted {
            let t = Instant::now();
            answers.push((packs.find_paged(&store, *project, id, &reads).await, t.elapsed(), name.clone()));
            // Another project's upload share (`take_for`) and `staged_slots` also succeed immediately.
            let _upload = packs.bound.take_for(Some(*project), Index::write_weight_of(10) as u64).await.expect("other project's upload share is never starved");
        }
        stop.store(true, Ordering::Relaxed);
        let mut read = 0;
        while let Some(n) = pushes.join_next().await {
            read += n.unwrap();
        }
        assert!(read > 0, "the participant's pushes read their staged index");
        for (r, waited, name) in answers {
            let found = r.unwrap_or_else(|e| panic!("another project's lookup of a 10-object pack was refused after {waited:?} ({e:#}), while one project's {read} reads of its staged index held the bound"));
            assert_eq!(found.map(|(n, _)| n), Some(name));
        }
        assert_eq!(packs.bound.available(), total - w, "every share but the cache's given back");
    }

    /// BUG-1621 (review s28r4): a share of the bound on indexes is clamped
    /// at what one holder may take ([`Bound::permits`]: 64 MiB, so that a
    /// share for any index can always come free), but a pack may hold
    /// [`MAX_OBJECTS`] (2^21) objects: reading its index holds 216 MiB (its
    /// 88 MiB of bytes, the parsed 96 MiB and the parse's 32 MiB working
    /// copy) and holding it 96 MiB, under a share of 64 MiB. With the
    /// staged-index cache's 32 MiB that is about 250 MiB of indexes outside
    /// the lookup maps, against `INDEXES_HELD` (96 MiB, `HUB.md` §13.20: "96
    /// MiB for every request together"). Writing a pack is counted short the
    /// same way: `Objects::write_pack` takes a share for the parsed index
    /// only, while `build` also holds the pack's index bytes (44 bytes a
    /// slot). Fixed (cycle 5): `Bound::permits` never clamps a share below
    /// what it holds; `MAX_OBJECTS` is 262,144 (`256 << 10`), whose index
    /// takes 27 MiB to read and parse, 23 MiB to build, and 12 MiB to hold;
    /// `write_pack` takes `Index::write_weight_of`; and `build` deduplicates
    /// in place without a hash set. Measured in a child process against
    /// `INDEXES_HELD` (96 MiB).
    #[tokio::test]
    async fn bug_1621_an_index_held_outside_the_lookup_maps_holds_a_share_of_all_it_holds() {
        const CHILD: &str = "VEIL_TEST_BUG_1621_CHILD";
        const NAME: &str = "pack::tests::bug_1621_an_index_held_outside_the_lookup_maps_holds_a_share_of_all_it_holds";
        if std::env::var_os(CHILD).is_some() {
            let rss = || -> usize {
                let s = std::fs::read_to_string("/proc/self/status").unwrap();
                let l = s.lines().find(|l| l.starts_with("VmRSS:")).unwrap();
                l.split_whitespace().nth(1).unwrap().parse::<usize>().unwrap() << 10
            };
            let dir = tempfile::tempdir().unwrap();
            let store = crate::store::FsStore::new(dir.path());
            for (p, count) in [(1i64, MAX_OBJECTS), (2, MAX_OBJECTS), (3, 140_000), (4, MAX_OBJECTS), (5, MAX_OBJECTS)] {
                let items: Vec<_> = (0..count)
                    .map(|i| {
                        let id = ObjectId::hash(&[p.to_le_bytes(), (i as u64).to_le_bytes()].concat());
                        (id, Bytes::from_static(b"x"))
                    })
                    .collect();
                let (bytes, _) = build(items).unwrap();
                store.put(&key(p, "full"), bytes).await.unwrap();
            }
            let packs = Packs::new(None);
            let before = rss();
            let mut peak = 0usize;
            // Fill the 32 MiB staged-index cache with 3 packs (~31 MiB).
            for p in 1..=3i64 {
                let held = read_index(&store, &key(p, "full"), &packs.bound).await.unwrap().unwrap();
                peak = peak.max(rss().saturating_sub(before));
                packs.staged_here(p, 1, &Arc::from("full"), held);
                peak = peak.max(rss().saturating_sub(before));
            }
            // Read two full MAX_OBJECTS indexes concurrently while the staged-index cache holds ~31 MiB.
            let (k4, k5) = (key(4, "full"), key(5, "full"));
            let (h4, h5) = tokio::join!(
                read_index(&store, &k4, &packs.bound),
                read_index(&store, &k5, &packs.bound),
            );
            let (h4, h5) = (h4.unwrap().unwrap(), h5.unwrap().unwrap());
            peak = peak.max(rss().saturating_sub(before));
            let accounted = INDEXES_HELD - packs.bound.available();
            drop((h4, h5));
            println!("INDEX-BOUND accounted={accounted} peak={peak} staged={}", packs.staged.stats().weight);
            return;
        }
        let total = 96 << 10;
        let bound = Bound { most: 64 << 10, wait: Duration::from_millis(100), ..Bound::new(total) };
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::FsStore::new(dir.path());
        // An oversized index (2,048 objects needs 216 KiB to read > 64 KiB `most`) is refused, never clamped to a smaller share.
        assert!(bound.take(Index::read_weight_of(2_048) as u64).await.is_err(), "a share above `most` is refused, never clamped");
        let n = MAX_OBJECTS >> 10;
        let (bytes, _) = build((0..n).map(|i| obj(&format!("full {i}"))).collect()).unwrap();
        store.put(&key(7, "full"), bytes).await.unwrap();
        let held = read_index(&store, &key(7, "full"), &bound).await.unwrap().expect("the pack is stored");
        assert_eq!(held.index.len(), n, "the index is read");
        let share = total - bound.available();
        assert!(share >= held.index.weight(), "an index of {} bytes held under a share of {share}", held.index.weight());
        drop(held);
        // The server's sizes: read, write, and held shares cover every byte they use.
        let packs = Packs::new(None);
        let n = MAX_OBJECTS;
        let read = Index::read_weight_of(n) as u64;
        let write = Index::write_weight_of(n) as u64;
        let hold = Index::weight_of(n) as u64;
        let (r, w, h) = (
            u64::from(packs.bound.permits(read)),
            u64::from(packs.bound.permits(write)),
            u64::from(packs.bound.permits(hold)),
        );
        assert!(r >= read && w >= write && h >= hold && (r as usize) <= packs.bound.most, "reading the index of a full pack takes a share of {} MiB for {} MiB, writing {} MiB for {} MiB, holding {} MiB for {} MiB", r >> 20, read >> 20, w >> 20, write >> 20, h >> 20, hold >> 20);
        // Measure real peak memory in a child process against `INDEXES_HELD` (96 MiB).
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([NAME, "--exact", "--nocapture", "--include-ignored", "--test-threads=1"])
            .env(CHILD, "1")
            .env("MALLOC_MMAP_THRESHOLD_", "131072")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(out.status.success(), "the child failed: {text}{}", String::from_utf8_lossy(&out.stderr));
        let line = text.lines().find_map(|l| l.find("INDEX-BOUND").map(|at| &l[at..])).unwrap_or_else(|| panic!("no measurement in {text}"));
        println!("{line}");
        let field = |k: &str| -> usize { line.split_whitespace().find_map(|w| w.strip_prefix(k)).unwrap().parse().unwrap() };
        let (accounted, peak) = (field("accounted="), field("peak="));
        assert!(accounted <= INDEXES_HELD, "{line}");
        assert!(peak <= INDEXES_HELD, "indexes outside the lookup maps took {} MiB at peak against the {} MiB bound ({line})", peak >> 20, INDEXES_HELD >> 20);
    }

    /// S28r5 review (guarantees 1 and 3): on a valid pack spanning several
    /// [`FIRST_READ`] windows, `staged_slots` (`lookup_slice` + `bisect_slots`)
    /// returns the exact slots a full `read_index` (`parse_index`) does for
    /// present and absent ids across every window boundary, never returns
    /// another object's slot, never reads a byte at or past `hl` (once the
    /// index is past [`FIRST_READ`]), and concurrent readers and writers across
    /// every path (`read_index`, `find_paged`, `staged_slots`, `write_weight_of`)
    /// stay within [`INDEXES_HELD`].
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn s28r5_bisect_slots_matches_full_read_never_returns_another_slot_or_reads_past_index() {
        struct Guarded {
            inner: crate::store::FsStore,
            hl: AtomicU64,
            max_end: AtomicU64,
        }
        #[async_trait::async_trait]
        impl BlobStore for Guarded {
            async fn get(&self, key: &str) -> Result<Option<Bytes>> {
                panic!("staged_slots must use ranged reads, not get({key})");
            }
            async fn put(&self, key: &str, data: Bytes) -> Result<()> {
                self.inner.put(key, data).await
            }
            async fn exists(&self, key: &str) -> Result<bool> {
                self.inner.exists(key).await
            }
            async fn get_range(&self, key: &str, start: u64, end: u64) -> Result<Option<(Bytes, u64)>> {
                let hl = self.hl.load(Ordering::Relaxed);
                if hl > 0 {
                    assert!(
                        end < hl,
                        "ranged read {start}..={end} read at or past index end hl={hl}"
                    );
                }
                self.max_end.fetch_max(end, Ordering::Relaxed);
                self.inner.get_range(key, start, end).await
            }
            async fn delete(&self, key: &str) -> Result<()> {
                self.inner.delete(key).await
            }
            async fn list(&self, prefix: &str) -> Result<Vec<String>> {
                self.inner.list(prefix).await
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Guarded {
            inner: crate::store::FsStore::new(dir.path()),
            hl: AtomicU64::new(0),
            max_end: AtomicU64::new(0),
        });
        let count = 6_000usize; // > 4 * WINDOW_ENTRIES (1,489), sohl > FIRST_READ
        let items: Vec<_> = (0..count).map(|i| obj(&format!("item-{i}"))).collect();
        let (bytes, full_index) = build(items.clone()).unwrap();
        let hl = head_len(&bytes).unwrap();
        assert!(hl > FIRST_READ, "index ({hl} B) spans multiple FIRST_READ windows");
        store.put(&key(1, "big"), bytes.clone()).await.unwrap();
        store.hl.store(hl, Ordering::Relaxed);

        let mut sorted: Vec<ObjectId> = items.iter().map(|(id, _)| *id).collect();
        sorted.sort_unstable();
        let in_first = ((FIRST_READ as usize) - HEAD) / ENTRY;
        let mut boundary_indices = vec![
            0,
            1,
            in_first - 1,
            in_first,
            in_first + 1,
            in_first + WINDOW_ENTRIES / 2,
            in_first + WINDOW_ENTRIES - 1,
            in_first + WINDOW_ENTRIES,
            count / 2,
            count - 2,
            count - 1,
        ];
        boundary_indices.sort_unstable();
        boundary_indices.dedup();
        let mut query: Vec<ObjectId> = boundary_indices.iter().map(|&i| sorted[i]).collect();
        // Duplicate wanted IDs and reverse order to exercise deduplication and ordering.
        let dup = query[3];
        query.push(dup);
        query.reverse();

        let packs = Arc::new(Packs::new(None));
        let got = packs.staged_slots(&*store, 1, "big", &query).await.unwrap().unwrap();
        assert_eq!(got.objects, count);
        assert_eq!(got.size, bytes.len() as u64);
        assert!(store.max_end.load(Ordering::Relaxed) < hl);
        let expected: Vec<(ObjectId, Slot)> = query.iter().filter_map(|id| Some((*id, full_index.get(id)?))).collect();
        assert_eq!(got.slots, expected, "bisect_slots must return the exact slots a full read does");
        for (id, slot) in &got.slots {
            let raw_entry = entry(id, *slot, &bytes[slot.offset as usize..(slot.offset + u64::from(slot.len)) as usize]).unwrap();
            let orig = &items.iter().find(|(oid, _)| oid == id).unwrap().1;
            assert_eq!(raw_entry, &orig[..], "slot must decode to its own object, never another's");
        }
        // An absent wanted ID in the bisected partition is refused (BUG-1499).
        assert!(packs.staged_slots(&*store, 1, "big", &[ObjectId([0xffu8; 32])]).await.is_err());

        // Also check all 6,000 objects in one call.
        let all = packs.staged_slots(&*store, 1, "big", &sorted).await.unwrap().unwrap();
        assert_eq!(all.slots.len(), count);
        for id in &sorted {
            let s = all.slots.iter().find(|(oid, _)| oid == id).unwrap().1;
            assert_eq!(Some(s), full_index.get(id));
        }

        // Concurrency check across every index-bound path: accounted permits never exceed INDEXES_HELD.
        store.hl.store(0, Ordering::Relaxed);
        let dyn_store: Arc<dyn BlobStore> = store;
        for p in 2..=6i64 {
            dyn_store.put(&key(p, "big"), bytes.clone()).await.unwrap();
            packs.add(p, vec![(Arc::from("big"), None)], true);
        }
        let peak_used = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let present_id = sorted[0];
        let mut tasks = tokio::task::JoinSet::new();
        for t in 0..12usize {
            let (packs, dyn_store, peak_used, q) = (packs.clone(), dyn_store.clone(), peak_used.clone(), query.clone());
            tasks.spawn(async move {
                for round in 0..8usize {
                    let p = ((t + round) % 5 + 2) as i64;
                    match (t + round) % 3 {
                        0 => {
                            let s = packs.staged_slots(&*dyn_store, 1, "big", &q).await.unwrap().unwrap();
                            assert_eq!(s.objects, count);
                        }
                        1 => {
                            let reads = AtomicU64::new(0);
                            let found = packs.find_paged(&dyn_store, p, &present_id, &reads).await.unwrap();
                            assert!(found.is_some());
                        }
                        _ => {
                            let _w = packs.bound.take_for(Some(p), Index::write_weight_of(10_000) as u64).await.unwrap();
                            tokio::task::yield_now().await;
                        }
                    }
                    let used = INDEXES_HELD - packs.bound.available();
                    peak_used.fetch_max(used, Ordering::Relaxed);
                }
            });
        }
        while let Some(r) = tasks.join_next().await {
            r.unwrap();
        }
        assert!(peak_used.load(Ordering::Relaxed) <= INDEXES_HELD);
        assert_eq!(packs.bound.available(), INDEXES_HELD);
    }

    /// BUG-1499 (review s28r5, Guarantee 1): `Packs::staged_slots` (`lookup_slice`
    /// + `bisect_slots`) must return the same answer as a full `read_index`
    /// (`parse_index`) and refuse an index that is unsorted, duplicated, or
    /// does not tile the pack (`hl..size`). Because `lookup_slice` and
    /// `bisect_slots` omit `parse_index`'s tiling check and only inspect the
    /// 64 KiB windows along the binary-search path for `ids`:
    /// 1. an untiled pack (overlapping slots, gaps between slots, or trailing
    ///    unindexed bytes after the last slot) is accepted by `staged_slots`
    ///    even when the whole index fits in the first 64 KiB read, and when all
    ///    its objects are touched by a landing push `sync::packs_to_list` lists
    ///    the damaged staged pack as-is without ever running `parse_index`;
    /// 2. duplicate or unsorted entries outside the bisected windows are
    ///    accepted; and
    /// 3. an out-of-order entry for a wanted object causes `bisect_slots` to
    ///    search the wrong half and return `Ok` with the object silently missing
    ///    from `slots` instead of refusing the unsorted index.
    #[tokio::test]
    async fn bug_1499_staged_slots_refuses_unsorted_duplicated_and_untiled_indexes_like_a_full_read() {
        let dir = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let store = crate::store::FsStore::new(dir.path());
        let packs = Packs::new(None);

        // Success first: on a valid pack, both `read_index` and `staged_slots` succeed and agree.
        let valid_items: Vec<_> = (0..2_000).map(|i| obj(&format!("valid-{i}"))).collect();
        let (valid_bytes, valid_idx) = build(valid_items.clone()).unwrap();
        store.put(&key(1, "valid"), valid_bytes.clone()).await.unwrap();
        let mut sorted_ids: Vec<ObjectId> = valid_items.iter().map(|(id, _)| *id).collect();
        sorted_ids.sort_unstable();
        let probe = *sorted_ids.last().unwrap();
        let full = read_index(&store, &key(1, "valid"), &packs.bound).await.unwrap().unwrap();
        let got = packs.staged_slots(&store, 1, "valid", &[ sorted_ids[0], probe ]).await.unwrap().unwrap();
        assert_eq!(got.slots, vec![(sorted_ids[0], full.index.get(&sorted_ids[0]).unwrap()), (probe, valid_idx.get(&probe).unwrap())]);

        // Case 1: Untiled pack (trailing byte / gap between slots / overlapping slots), even in a small 2-object pack.
        let small_items = vec![obj("small-a"), obj("small-b")];
        let (small_bytes, _) = build(small_items.clone()).unwrap();
        let mut trailing = small_bytes.to_vec();
        trailing.push(0u8); // pack ends 1 byte past the last slot (`at != size`)
        let trailing = Bytes::from(trailing);
        assert!(parse_index(&trailing, Some(trailing.len() as u64)).is_err(), "parse_index refuses a pack whose slots do not tile to size");
        store.put(&key(1, "untiled"), trailing).await.unwrap();
        let untiled_res = packs.staged_slots(&store, 1, "untiled", &[small_items[0].0, small_items[1].0]).await;

        // Case 2: Out-of-order wanted entry in a multi-window pack (`bisect_slots` searches the wrong partition and must refuse, never return `Ok` with the wanted id missing).
        let mut damaged = valid_bytes.to_vec();
        // Swap entries 1,600 and 1,601 (past FIRST_READ = 1,489 entries), making the index unsorted and placing `sorted_ids[1601]` before `sorted_ids[1600]`.
        let e1600 = HEAD + 1600 * ENTRY;
        let e1601 = HEAD + 1601 * ENTRY;
        let (left, right) = damaged.split_at_mut(e1601);
        left[e1600..e1600 + ENTRY].swap_with_slice(&mut right[..ENTRY]);
        let damaged = Bytes::from(damaged);
        assert!(parse_index(&damaged, Some(damaged.len() as u64)).is_err(), "parse_index refuses an unsorted index");
        store.put(&key(1, "unsorted"), damaged.clone()).await.unwrap();
        let missing_wanted_res = packs.staged_slots(&store, 1, "unsorted", &[sorted_ids[1600]]).await;

        // Case 3: When a push touches every object of an uncached staged pack, `sync::packs_to_list` runs `parse_index` on it before listing it as-is.
        let objects = Arc::new(crate::store::Objects::new(Arc::new(crate::store::FsStore::new(dir.path())), 1 << 20));
        let db = crate::db::connect_lazy("postgres://veil@127.0.0.1:9/none", 1).unwrap();
        let hub = Arc::new(crate::Hub {
            db: db.clone(),
            objects,
            trees: LruCache::new(1 << 20),
            identity: veil_core::Identity::generate("hub"),
            receipt_key: [0; 32],
            grants: crate::grant::Grants::load(data.path()).unwrap(),
            cache_token: crate::cache::feed::load_token(data.path()).unwrap(),
            session_ttl_ms: 0,
            certificate: rustls::pki_types::CertificateDer::from(Vec::new()),
            caches: Default::default(),
            derive: crate::derive::Workers::new(db),
            query: Default::default(),
            landing: Default::default(),
            events: Default::default(),
            embargo: Default::default(),
            pack_gc: Default::default(),
            limits: crate::limits::Limits::new(Default::default(), 1),
        });
        let all_slots: Vec<(ObjectId, Slot)> = sorted_ids.iter().map(|id| (*id, valid_idx.get(id).unwrap())).collect();
        let touched: HashSet<ObjectId> = sorted_ids.iter().copied().collect();
        let st_valid = crate::sync::Staged::from_packs(
            vec![(Arc::from("valid"), StagedSlots { objects: valid_items.len(), size: valid_bytes.len() as u64, slots: all_slots.clone() })],
            HashMap::new(),
        );
        let listed_ok = crate::sync::packs_to_list(&hub, 1, 7, &st_valid, &touched, &[], &Mutex::new(Default::default())).await;
        assert_eq!(listed_ok.expect("valid uncached staged pack lists as-is").len(), 1);
        let st_unsorted = crate::sync::Staged::from_packs(
            vec![(Arc::from("unsorted"), StagedSlots { objects: valid_items.len(), size: damaged.len() as u64, slots: all_slots })],
            HashMap::new(),
        );
        let unsorted_res = crate::sync::packs_to_list(&hub, 1, 7, &st_unsorted, &touched, &[], &Mutex::new(Default::default())).await;
        assert!(
            untiled_res.is_err() && missing_wanted_res.is_err() && unsorted_res.is_err(),
            "staged_slots / packs_to_list must refuse untiled and unsorted indexes as a full read would, but returned untiled={:?}, missing_wanted={:?}, unsorted_list={:?}",
            untiled_res.map(|o| o.map(|s| s.slots.len())),
            missing_wanted_res.map(|o| o.map(|s| s.slots.len())),
            unsorted_res.map(|v| v.len()),
        );
    }

    /// BUG-1626 (review s28r7, Guarantee 3): every index the server reads
    /// (`Packs::staged_slots` in both branches, `bisect_slots`) must be
    /// refused iff a full `parse_index` would refuse it, and no wanted object
    /// is ever answered missing while the index holds it, nor present when it
    /// doesn't. Two remaining divergences in `staged_slots` when `in_first < count`:
    /// 1. When `ids` is a subset (or empty) on a multi-window pack (`count > 1,489`),
    ///    `staged_slots` never runs `parse_index` (`pack.rs:1151-1171`), so an
    ///    untiled multi-window index (trailing bytes, gaps, overlapping slots)
    ///    or an index with duplicate/unsorted entries outside the bisected
    ///    64 KiB windows is accepted (`Ok(Some(..))`), whereas `parse_index`
    ///    refuses it (`Err`).
    /// 2. `bisect_slots` ends with `ensure!(wanted.iter().all(|id| found.contains_key(id)), "a pack's index is not sorted")`
    ///    (`pack.rs:1319`), unconditionally refusing any valid sorted multi-window
    ///    pack whenever a wanted ID past `last_first` is simply absent from the
    ///    pack (`Err`), whereas `parse_index` (and `staged_slots` when cached,
    ///    when `in_first == count`, or when the absent ID sorts `<= last_first`)
    ///    succeeds (`Ok(Some(StagedSlots))`) and omits the absent ID from `slots`.
    #[tokio::test]
    #[ignore = "BUG-1626: staged_slots when in_first < count accepts untiled/unsorted/duplicated multi-window indexes that parse_index refuses, and bisect_slots refuses valid sorted indexes when a wanted id is absent"]
    async fn bug_1626_staged_slots_matches_parse_index_on_multi_window_packs_and_absent_ids() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::FsStore::new(dir.path());
        let packs = Packs::new(None);

        // Success first: on a valid multi-window pack (2,000 objects, > FIRST_READ = 1,489 entries),
        // `read_index` (`parse_index`) and `staged_slots` for a present ID both succeed and return the same slot.
        let valid_items: Vec<_> = (0..2_000).map(|i| obj(&format!("valid-1626-{i}"))).collect();
        let (valid_bytes, valid_idx) = build(valid_items.clone()).unwrap();
        store.put(&key(1, "valid"), valid_bytes.clone()).await.unwrap();
        let mut sorted_ids: Vec<ObjectId> = valid_items.iter().map(|(id, _)| *id).collect();
        sorted_ids.sort_unstable();
        let probe = sorted_ids[0];
        let full = read_index(&store, &key(1, "valid"), &packs.bound).await.unwrap().unwrap();
        let got_present = packs.staged_slots(&store, 1, "valid", &[probe]).await.unwrap().unwrap();
        assert_eq!(got_present.slots, vec![(probe, full.index.get(&probe).unwrap())]);
        assert_eq!(got_present.slots[0].1, valid_idx.get(&probe).unwrap());

        // Divergence 1a: Multi-window pack with trailing unindexed byte (untiled: `size != at`).
        // `parse_index` refuses it, but `staged_slots` with `ids = &[probe]` (or `&[]`) accepts it (`Ok(Some(..))`).
        let mut untiled_multi = valid_bytes.to_vec();
        untiled_multi.push(0u8);
        let untiled_multi = Bytes::from(untiled_multi);
        assert!(parse_index(&untiled_multi, Some(untiled_multi.len() as u64)).is_err(), "parse_index refuses untiled multi-window pack");
        store.put(&key(1, "untiled_multi"), untiled_multi).await.unwrap();
        let untiled_subset_res = packs.staged_slots(&store, 1, "untiled_multi", &[probe]).await;
        let untiled_empty_res = packs.staged_slots(&store, 1, "untiled_multi", &[]).await;

        // Divergence 1b: Multi-window pack with unsorted / duplicate entries outside the bisected window (at entries 1,600..1,602)
        // when querying `probe` (`sorted_ids[0]`, in the first window).
        // `parse_index` refuses it, but `staged_slots` accepts it (`Ok(Some(..))`).
        let mut unsorted_outside = valid_bytes.to_vec();
        let e1600 = HEAD + 1600 * ENTRY;
        let e1601 = HEAD + 1601 * ENTRY;
        let (left, right) = unsorted_outside.split_at_mut(e1601);
        left[e1600..e1600 + ENTRY].swap_with_slice(&mut right[..ENTRY]);
        let unsorted_outside = Bytes::from(unsorted_outside);
        assert!(parse_index(&unsorted_outside, Some(unsorted_outside.len() as u64)).is_err(), "parse_index refuses unsorted multi-window pack");
        store.put(&key(1, "unsorted_outside"), unsorted_outside).await.unwrap();
        let unsorted_outside_res = packs.staged_slots(&store, 1, "unsorted_outside", &[probe]).await;

        // Divergence 2: Valid sorted multi-window pack queried with `[probe, absent_high]` where `absent_high` (`[0xff; 32]`)
        // is not in the pack and sorts past `last_first`. `parse_index` succeeds and `valid_idx.get(&absent_high)` is `None`,
        // so `staged_slots` must return `Ok(Some(StagedSlots))` with `slots == [(probe, slot)]`, never `Err`.
        let absent_high = ObjectId([0xffu8; 32]);
        let valid_with_absent_res = packs.staged_slots(&store, 1, "valid", &[probe, absent_high]).await;

        assert!(
            untiled_subset_res.is_err()
                && untiled_empty_res.is_err()
                && unsorted_outside_res.is_err()
                && valid_with_absent_res.as_ref().is_ok_and(|o| o.as_ref().is_some_and(|s| s.slots.len() == 1 && s.slots[0].0 == probe)),
            "staged_slots diverged from parse_index: untiled_subset={:?}, untiled_empty={:?}, unsorted_outside={:?}, valid_with_absent={:?}",
            untiled_subset_res.map(|o| o.map(|s| s.slots.len())),
            untiled_empty_res.map(|o| o.map(|s| s.slots.len())),
            unsorted_outside_res.map(|o| o.map(|s| s.slots.len())),
            valid_with_absent_res.map(|o| o.map(|s| s.slots.len())),
        );
    }

    /// BUG-1623 (review s28r5, Guarantees 2 and 4): `Bound::take_for` has two
    /// flaws in its per-project share and yielding rules:
    /// 1. `s.last_large` is set to `Some(p)` when project `p` takes a share
    ///    above `quarter`, and is never cleared when another project takes a
    ///    share `<= quarter`; meanwhile `s.waiting` counts a project even when
    ///    that project is only waiting on its own `quarter` cap while `self.sem`
    ///    has plenty of free permits. Project 2 holding its own `quarter` with
    ///    one more request of Project 2 waiting on Project 2's own `quarter`
    ///    keeps `other_waiting == true` and `last_large == Some(1)`, starving
    ///    Project 1's next large share for the whole `wait` and answering 503
    ///    `IndexesFull` while 75% of `most` is free.
    /// 2. When a push splits `own` at `MAX_OBJECTS` (`sync::packs_to_list`), it
    ///    holds the first pack's `Held` share (`Index::weight_of(MAX_OBJECTS)` =
    ///    12 MiB, still charged to `s.held[project]` because `put_pack` does
    ///    not call `unproject()`) while calling `put_pack` for the next chunk
    ///    in the same task. Whenever the next chunk needs `> 4 MiB` (>= 45,589
    ///    objects, so `cur + want > quarter` while `cur > 0`), `take_for`
    ///    deadlocks against the caller's own first pack and fails with
    ///    `IndexesFull` (503).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bug_1623_yielding_and_per_project_shares_never_starve_a_large_share_or_split_pack() {
        let bound = Arc::new(Bound {
            most: 64 << 20,
            wait: Duration::from_millis(200),
            ..Bound::new(INDEXES_HELD)
        });
        let quarter = (bound.most / 4) as u64; // 16 MiB
        let large = Index::read_weight_of(MAX_OBJECTS) as u64; // ~27 MiB (> quarter)

        // Success first: Project 1 can take a large share, drop it, and take it again when idle.
        let s1 = bound.take_for(Some(1), large).await.expect("first large share succeeds");
        drop(s1);
        let s2 = bound.take_for(Some(1), large).await.expect("second large share succeeds when no other project waits");
        drop(s2);

        // Route 1: Project 2 holds its own 16 MiB quarter and queues a second request of its own
        // (blocked only by Project 2's own per-project quarter cap, leaving 80 MiB of 96 MiB free).
        let p2_held = bound.take_for(Some(2), quarter).await.expect("project 2 takes its quarter");
        let b_wait = bound.clone();
        let p2_waiter = tokio::spawn(async move {
            // Waits on Project 2's own quarter cap for longer than Project 1's attempt.
            let b_long = Bound { wait: Duration::from_millis(500), ..(*b_wait).clone() };
            let _ = b_long.take_for(Some(2), FIRST_READ).await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Project 1 now asks for a large share (27 MiB out of 80 MiB free).
        let p1_again = bound.take_for(Some(1), large).await.map(drop);
        drop(p2_held);
        let _ = p2_waiter.await;

        // Also Route 1b: Project 2 takes and drops a small share `<= quarter`, clearing `last_large = Some(1)`,
        // so Project 1 can take a large share even while another project truly waits on `sem`.
        let p2_small = bound.take_for(Some(2), FIRST_READ).await.expect("project 2 takes a small share");
        drop(p2_small);
        let f1 = bound.take(32 << 20).await.unwrap();
        let f2 = bound.take((INDEXES_HELD as u64) - (32 << 20) - large).await.unwrap();
        let b_wait2 = bound.clone();
        let p4_waiter = tokio::spawn(async move {
            let b_long = Bound { wait: Duration::from_millis(500), ..(*b_wait2).clone() };
            let _ = b_long.take_for(Some(4), large + 1024).await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let p1_after_other = bound.take_for(Some(1), large).await.map(drop);
        drop((f1, f2));
        let _ = p4_waiter.await;

        // Route 2: Splitting a push's own pack of `MAX_OBJECTS + 50,000` small objects in `sync::packs_to_list`.
        let dir = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let objects = Arc::new(crate::store::Objects::new(Arc::new(crate::store::FsStore::new(dir.path())), 1 << 20));
        let db = crate::db::connect_lazy("postgres://veil@127.0.0.1:9/none", 1).unwrap();
        let hub = Arc::new(crate::Hub {
            db: db.clone(),
            objects: objects.clone(),
            trees: LruCache::new(1 << 20),
            identity: veil_core::Identity::generate("hub"),
            receipt_key: [0; 32],
            grants: crate::grant::Grants::load(data.path()).unwrap(),
            cache_token: crate::cache::feed::load_token(data.path()).unwrap(),
            session_ttl_ms: 0,
            certificate: rustls::pki_types::CertificateDer::from(Vec::new()),
            caches: Default::default(),
            derive: crate::derive::Workers::new(db),
            query: Default::default(),
            landing: Default::default(),
            events: Default::default(),
            embargo: Default::default(),
            pack_gc: Default::default(),
            limits: crate::limits::Limits::new(Default::default(), 1),
        });
        let total_objs = MAX_OBJECTS + 50_000;
        let mut made_map = HashMap::with_capacity(total_objs);
        let mut made_ids = Vec::with_capacity(total_objs);
        for i in 0..total_objs {
            let mut raw = [0u8; 24];
            raw[..10].copy_from_slice(b"veil:blob\n");
            raw[10..18].copy_from_slice(&(i as u64).to_le_bytes());
            let id = ObjectId::hash(&raw);
            made_ids.push(id);
            made_map.insert(id, Bytes::copy_from_slice(&raw));
        }
        let st = crate::sync::Staged::from_packs(Vec::new(), made_map);
        let progress = Mutex::new(crate::sync::Progress::default());
        let split_res = crate::sync::packs_to_list(&hub, 3, 7, &st, &HashSet::new(), &made_ids, &progress).await;
        assert!(
            p1_again.is_ok() && p1_after_other.is_ok() && split_res.is_ok(),
            "Bound::take_for / packs_to_list answered 503 IndexesFull: route1={:?}, route1b={:?}, route2={:?}",
            p1_again.err(),
            p1_after_other.err(),
            split_res.as_ref().err()
        );
        let listed = split_res.unwrap();
        assert_eq!(listed.len(), 2, "MAX_OBJECTS + 50,000 objects split into 2 packs");
        assert_eq!(listed[0].objects + listed[1].objects, total_objs);
        assert!(objects.index_bound().available() < INDEXES_HELD, "listed packs hold their index shares until listed()");
        let for_cache: Vec<_> = listed.into_iter().map(|p| (p.name, p.held.map(|h| h.index))).collect();
        objects.listed(3, for_cache);
        assert_eq!(objects.index_bound().available(), INDEXES_HELD, "all shares released once split packs join the lookup maps");

        // Failure path: if `packs_to_list` fails (e.g. a discarded staged pack named after writing the first pack, or an error during `packs_to_list`), all shares are released when `packs_to_list` returns.
        let mut touched_fail = HashSet::new();
        let missing_id = ObjectId::hash(b"missing-from-store");
        touched_fail.insert(missing_id);
        let st_fail = crate::sync::Staged::from_packs(
            vec![(
                Arc::from("vanished"),
                StagedSlots {
                    objects: 2,
                    size: 200,
                    slots: vec![(missing_id, Slot { offset: HEAD as u64 + 2 * ENTRY as u64, len: 50 })],
                },
            )],
            HashMap::new(),
        );
        let fail_res = crate::sync::packs_to_list(&hub, 3, 7, &st_fail, &touched_fail, &made_ids, &Mutex::new(Default::default())).await;
        assert!(fail_res.is_err(), "packs_to_list fails when a touched staged pack vanished");
        assert_eq!(objects.index_bound().available(), INDEXES_HELD, "all shares released when packs_to_list fails");
    }
}
