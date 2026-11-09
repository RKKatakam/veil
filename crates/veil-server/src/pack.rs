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

use anyhow::{anyhow, bail, Context, Result};
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
/// Most objects one pack holds (its index is at most 88 MiB).
pub const MAX_OBJECTS: usize = 2 << 20;

/// Pack states in the `packs` table.
pub const STAGED: i16 = 0;
pub const LISTED: i16 = 1;
pub const DISCARDED: i16 = 2;

/// The storage key of pack `name` of `project`.
pub fn key(project: i64, name: &str) -> String {
    format!("p/{project}/pack/{name}")
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
    fn weight_of(count: usize) -> usize {
        64 + count * std::mem::size_of::<(ObjectId, Slot)>()
    }
}

/// Lay out a pack of the encodings `objects` (the first of each id kept),
/// in the order given; its index.
pub fn build(objects: Vec<(ObjectId, Bytes)>) -> Result<(Bytes, Index)> {
    let mut seen = HashSet::with_capacity(objects.len());
    let objects: Vec<(ObjectId, Bytes)> = objects.into_iter().filter(|(id, _)| seen.insert(*id)).collect();
    if objects.len() > MAX_OBJECTS {
        bail!("at most {MAX_OBJECTS} objects per pack");
    }
    let head = HEAD + objects.len() * ENTRY;
    let total = head + objects.iter().map(|(_, b)| ENTRY_HEAD as usize + b.len()).sum::<usize>();
    let mut entries = Vec::with_capacity(objects.len());
    let mut at = head as u64;
    for (id, b) in &objects {
        let len = u32::try_from(ENTRY_HEAD as usize + b.len()).map_err(|_| anyhow!("an object of 4 GiB or more cannot be packed"))?;
        entries.push((*id, Slot { offset: at, len }));
        at += u64::from(len);
    }
    entries.sort_unstable_by_key(|a| a.0);
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
        let id = ObjectId(e[..32].try_into().expect("32 bytes"));
        let offset = u64::from_be_bytes(e[32..40].try_into().expect("8 bytes"));
        let len = u32::from_be_bytes(e[40..44].try_into().expect("4 bytes"));
        let end = offset.checked_add(u64::from(len)).ok_or_else(|| anyhow!("a pack slot past the end"))?;
        if offset < hl as u64 || u64::from(len) <= ENTRY_HEAD || size.is_some_and(|s| end > s) {
            bail!("a pack slot outside its entries");
        }
        if entries.last().is_some_and(|(last, _): &(ObjectId, Slot)| *last >= id) {
            bail!("a pack's index is not sorted");
        }
        entries.push((id, Slot { offset, len }));
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
/// of its staged uploads' indexes (`Packs::staged_slots`: it keeps only the
/// slots its receipts name), the index of a pack being written, and the
/// staged-index cache's ([`STAGED_INDEXES`] of it at most). Each takes its
/// share before it reads or builds the index, and holds it while the index
/// is held ([`Held`]); an index larger than what the cache leaves takes
/// all of that. A lookup's index joins the lookup maps once read (bounded
/// by [`LOOKUP_BUDGET`]).
pub const INDEXES_HELD: usize = 96 << 20;
/// What the staged-index cache may hold of [`INDEXES_HELD`].
pub const STAGED_INDEXES: usize = 32 << 20;
/// How long a request waits for its share of [`INDEXES_HELD`] before it is
/// answered [`IndexesFull`] (`warming`: try again).
const INDEX_WAIT: Duration = Duration::from_secs(10);

/// No share of [`INDEXES_HELD`] came free in time: the request is answered
/// `warming` (503, try again), never with an index held outside the bound.
#[derive(Debug)]
pub struct IndexesFull;

impl std::fmt::Display for IndexesFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the server holds as many pack indexes as it may; try again in a few seconds")
    }
}

impl std::error::Error for IndexesFull {}

/// Is `e` (or what it wraps, an I/O error's inner one included) [`IndexesFull`]?
pub fn indexes_full(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.is::<IndexesFull>() || c.downcast_ref::<std::io::Error>().and_then(|io| io.get_ref()).is_some_and(|i| i.is::<IndexesFull>()))
}

/// A server-wide bound on bytes of indexes held ([`INDEXES_HELD`]).
#[derive(Clone)]
pub struct Bound {
    sem: Arc<tokio::sync::Semaphore>,
    /// The largest share one holder takes.
    most: usize,
    wait: Duration,
}

impl Bound {
    pub fn new(total: usize) -> Bound {
        Bound { sem: Arc::new(tokio::sync::Semaphore::new(total)), most: total, wait: INDEX_WAIT }
    }

    fn permits(&self, bytes: u64) -> u32 {
        bytes.clamp(1, self.most as u64) as u32
    }

    /// A share of `bytes`, waiting for it at most this bound's wait (only
    /// by a holder of none, so holders never wait on one another in a cycle).
    pub async fn take(&self, bytes: u64) -> Result<Share> {
        match tokio::time::timeout(self.wait, self.sem.clone().acquire_many_owned(self.permits(bytes))).await {
            Ok(Ok(p)) => Ok(Share(p)),
            _ => Err(anyhow::Error::new(IndexesFull)),
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
pub struct Share(tokio::sync::OwnedSemaphorePermit);

impl Share {
    /// Give back what is held beyond `bytes`.
    fn keep(&mut self, bytes: usize) {
        let n = self.0.num_permits();
        if n > bytes.max(1) {
            drop(self.0.split(n - bytes.max(1)));
        }
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
}

/// Read the index of the pack at `key` (one read for most packs, two for a
/// large index), holding a share of `bound` (BUG-1496) taken before
/// anything sized by the index is read or made: its bytes, the parsed
/// index and the parse's working copy of the slots; kept, once parsed, for
/// the index alone. (Only the first [`FIRST_READ`] bytes, which say how
/// large the index is, are read before.)
pub async fn read_index(store: &dyn BlobStore, key: &str, bound: &Bound) -> Result<Option<Held>> {
    let Some((first, size)) = store.get_range(key, 0, FIRST_READ - 1).await? else { return Ok(None) };
    let hl = head_len(&first).with_context(|| format!("reading pack {key}"))?;
    let count = (hl as usize - HEAD) / ENTRY;
    let share = bound.take(hl + (Index::weight_of(count) + count * std::mem::size_of::<Slot>()) as u64).await?;
    let first = if (first.len() as u64) < hl {
        match store.get_range(key, 0, hl - 1).await? {
            Some((b, _)) => b,
            None => return Ok(None),
        }
    } else {
        first
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
            // searched; then the lookup maps' (BUG-1496).
            let Some(held) = read_index(&**store, &key(project, &name), &self.bound).await? else {
                bail!("listed pack {name} of project {project} is not in the store");
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
                Some(Ok((name, Ok(None)))) => bail!("listed pack {name} of project {project} is not in the store"),
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
    pub fn staged_here(&self, project: i64, person: i64, name: &Arc<str>, held: Held) {
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

    /// What a push or API commit keeps of staged pack `name` (BUG-1496):
    /// its object count, its length and the slots of `ids` in it; the index
    /// itself is held, under its share of the bound, only while it is read.
    /// `None` if the pack is not in the store (discarded).
    pub async fn staged_slots(&self, store: &dyn BlobStore, project: i64, name: &str, ids: &[ObjectId]) -> Result<Option<StagedSlots>> {
        let Some(held) = self.staged_index(store, project, name).await? else { return Ok(None) };
        let slots = ids.iter().filter_map(|id| Some((*id, held.index.get(id)?))).collect();
        Ok(Some(StagedSlots { objects: held.index.len(), size: held.size, slots }))
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
                sqlx::query_scalar("UPDATE packs SET state = $3 WHERE project_id = $1 AND name = ANY($2) AND state = $4 RETURNING name")
                    .bind(project)
                    .bind(&names)
                    .bind(DISCARDED)
                    .bind(STAGED)
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
            assert_eq!(entry(id, bytes).unwrap(), &raw[..]);
            assert_eq!(s.encoding_len(), raw.len() as u64);
            // Another object's entry is refused, whole or in part.
            let other = objects.iter().find(|(o, _)| o != id).unwrap().0;
            assert!(entry(&other, bytes).is_err() && entry(id, &bytes[..10]).is_err());
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
        short[HEAD + 40..HEAD + 44].copy_from_slice(&(ID_LEN as u32).to_be_bytes());
        assert!(parse_index(&short, size).is_err(), "a slot with room for its id only");
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
        packs.add(7, vec![(name.clone(), Arc::new(index))], true);
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
        assert!(entry(&probe, &b).is_ok());
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
    /// the two lookups are interleaved by hand, as two tasks can be.
    #[tokio::test]
    #[ignore = "BUG-1495: a lookup racing another lookup's page-in reads a listed object as missing"]
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
    /// the deletes leaves the same.
    #[tokio::test]
    #[ignore = "BUG-1498: a failed delete stops a discard, and discarded packs left in storage are removed by nothing"]
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
        assert!(left.len() <= 1, "packs discarded but left in storage after one failed delete: {left:?}");
    }

    /// BUG-1396 (S28 cycle 2), the same class: the recent uploads of each
    /// person in each project (`Packs::recent`, for a retry's receipts) are
    /// kept for every pair that ever uploaded on this server, never dropped:
    /// unlike the staged indexes beside them (an `LruCache` of 32 MiB), the
    /// map grows with the server's uptime.
    #[test]
    fn bug_1396_recent_uploads_are_bounded() {
        let packs = Packs::new(None);
        let index = Arc::new(build(vec![obj("one")]).unwrap().1);
        for person in 0..200_000 {
            packs.staged_here(1, person, &Arc::from(new_name()), index.clone(), 100);
        }
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
}
