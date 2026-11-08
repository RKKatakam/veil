//! Packs (S28, `docs/design/server/storage-and-cost.md` §7, `docs/HUB.md`
//! §13.20): many objects of a project in one storage object, so a push
//! costs one storage write instead of one per object.
//!
//! **Layout** (one storage object, `p/<project>/pack/<name>`, `name` 32
//! random hex digits; never edited in place):
//!
//! ```text
//! "veilpack1\n"                    10 bytes
//! count u32be
//! index: count × (id 32 ‖ offset u64be ‖ len u32be), sorted by id, ids distinct
//! entries: each object's encoding (S27: `v…` or `z…`), at its offset
//! ```
//!
//! The index is at the front, so one read of the first [`FIRST_READ`]
//! bytes holds it for most packs, without knowing the pack's length. An
//! entry is read with a range request and decoded and checked against its
//! id like any object (`store::Objects`), so a wrong index entry is an
//! error, never other content. A pack is self-describing: S29 merges packs
//! by reading their indexes and copying entries into a new pack, and drops
//! an object by writing a pack without it (`storage-and-cost.md` §8).
//!
//! **States** (the `packs` table, migration 13): a pack an upload wrote is
//! *staged*: no row, never read by anyone but the push or API commit whose
//! receipts name it. A push that lands *lists* it (a row with `listed`) in
//! its own transaction; a refused one *discards* it (a row without
//! `listed`, then the storage object is deleted). Whichever row is written
//! first wins, by the primary key, so a listed pack is never deleted and a
//! discarded one is never listed.
//!
//! **Lookups.** Each server keeps, per project, the slots of every listed
//! pack it has read the index of ([`Packs`]): object id → pack and slot.
//! A miss there and among loose objects reads the project's listing again
//! (one statement) and the indexes of packs it does not know.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Instant,
};

use anyhow::{anyhow, bail, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use veil_core::{cache::LruCache, ObjectId};

use crate::store::BlobStore;

/// A pack's first bytes.
pub const MAGIC: &[u8; 10] = b"veilpack1\n";
/// The magic and the count.
const HEAD: usize = MAGIC.len() + 4;
/// One index entry: id, offset, length.
const ENTRY: usize = 32 + 8 + 4;
/// What a reader asks for first: the head and, up to about 1,500 objects,
/// the whole index.
pub const FIRST_READ: u64 = 64 << 10;
/// Most objects one pack holds (its index is at most 88 MiB).
pub const MAX_OBJECTS: usize = 2 << 20;

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

/// Where an object's encoding sits in its pack.
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
        64 + self.entries.capacity() * std::mem::size_of::<(ObjectId, Slot)>()
    }
}

/// Lay out a pack of the encodings `objects` (the first of each id kept),
/// in the order given; its index; its length.
pub fn build(objects: Vec<(ObjectId, Bytes)>) -> Result<(Bytes, Index)> {
    let mut seen = HashSet::with_capacity(objects.len());
    let objects: Vec<(ObjectId, Bytes)> = objects.into_iter().filter(|(id, _)| seen.insert(*id)).collect();
    if objects.len() > MAX_OBJECTS {
        bail!("at most {MAX_OBJECTS} objects per pack");
    }
    let head = HEAD + objects.len() * ENTRY;
    let total = head + objects.iter().map(|(_, b)| b.len()).sum::<usize>();
    let mut entries = Vec::with_capacity(objects.len());
    let mut at = head as u64;
    for (id, b) in &objects {
        let len = u32::try_from(b.len()).map_err(|_| anyhow!("an object of 4 GiB or more cannot be packed"))?;
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
    for (_, b) in objects {
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
/// checked: ids sorted and distinct, every slot after the index and, when
/// the pack's length `size` is known, inside it.
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
        if offset < hl as u64 || len == 0 || size.is_some_and(|s| end > s) {
            bail!("a pack slot outside its entries");
        }
        if entries.last().is_some_and(|(last, _): &(ObjectId, Slot)| *last >= id) {
            bail!("a pack's index is not sorted");
        }
        entries.push((id, Slot { offset, len }));
    }
    Ok(Index { entries })
}

/// Read the index of the pack at `key` (one read for most packs, two for a
/// large index); its length.
pub async fn read_index(store: &dyn BlobStore, key: &str) -> Result<Option<(Index, u64)>> {
    let Some((first, size)) = store.get_range(key, 0, FIRST_READ - 1).await? else { return Ok(None) };
    let hl = head_len(&first).with_context(|| format!("reading pack {key}"))?;
    let first = if (first.len() as u64) < hl {
        match store.get_range(key, 0, hl - 1).await? {
            Some((b, _)) => b,
            None => return Ok(None),
        }
    } else {
        first
    };
    Ok(Some((parse_index(&first, Some(size)).with_context(|| format!("reading pack {key}"))?, size)))
}

/// A listed pack's row.
#[derive(Clone, Debug)]
pub struct Row {
    pub name: Arc<str>,
    pub size: u64,
    pub objects: u64,
}

/// About the memory one slot takes in a project's lookup map.
const SLOT_WEIGHT: usize = 80;
/// The lookup maps of all projects, together: projects used least recently
/// are dropped past it (each is read again when next needed).
pub const LOOKUP_BUDGET: usize = 128 << 20;

#[derive(Default)]
struct Map {
    /// The project's listing was read at least once.
    loaded: bool,
    packs: HashSet<Arc<str>>,
    slots: HashMap<ObjectId, (Arc<str>, Slot)>,
}

struct ProjectPacks {
    /// Serialises listings; when the last one began.
    listing: tokio::sync::Mutex<Option<Instant>>,
    map: RwLock<Map>,
    used: Mutex<Instant>,
}

/// What a lookup found.
pub enum Found {
    At(Arc<str>, Slot),
    /// In no pack this server knows of.
    Absent,
    /// The project's listing was never read here.
    Unloaded,
}

/// Every project's listed packs, as this server knows them.
pub struct Packs {
    db: Option<sqlx::PgPool>,
    projects: Mutex<HashMap<i64, Arc<ProjectPacks>>>,
    weight: AtomicUsize,
    /// Indexes and lengths of packs staged recently, by name (a push on the
    /// server that took the upload reads them without a storage read);
    /// `None` once discarded here.
    staged: LruCache<Option<(Arc<Index>, u64)>>,
}

fn name_key(project: i64, name: &str) -> ObjectId {
    let mut h = blake3::Hasher::new();
    h.update(b"pack");
    h.update(&project.to_le_bytes());
    h.update(name.as_bytes());
    ObjectId(*h.finalize().as_bytes())
}

impl Packs {
    pub fn new(db: Option<sqlx::PgPool>) -> Packs {
        Packs {
            db,
            projects: Mutex::new(HashMap::new()),
            weight: AtomicUsize::new(0),
            staged: LruCache::new(32 << 20),
        }
    }

    fn project(&self, project: i64) -> Arc<ProjectPacks> {
        let mut g = self.projects.lock().unwrap();
        let p = g
            .entry(project)
            .or_insert_with(|| {
                Arc::new(ProjectPacks {
                    listing: tokio::sync::Mutex::new(None),
                    map: RwLock::new(Map::default()),
                    used: Mutex::new(Instant::now()),
                })
            })
            .clone();
        *p.used.lock().unwrap() = Instant::now();
        p
    }

    /// Where object `id` of `project` is, as far as this server knows.
    pub fn find(&self, project: i64, id: &ObjectId) -> Found {
        let p = self.project(project);
        let m = p.map.read().unwrap();
        match m.slots.get(id) {
            Some((n, s)) => Found::At(n.clone(), *s),
            None if m.loaded => Found::Absent,
            None => Found::Unloaded,
        }
    }

    /// Add listed packs to `project`'s map.
    fn add(&self, project: i64, packs: Vec<(Arc<str>, Arc<Index>)>, loaded: bool) {
        let p = self.project(project);
        let mut added = 0;
        {
            let mut m = p.map.write().unwrap();
            for (name, index) in packs {
                if !m.packs.insert(name.clone()) {
                    continue;
                }
                for (id, s) in index.iter() {
                    if m.slots.insert(*id, (name.clone(), *s)).is_none() {
                        added += 1;
                    }
                }
            }
            m.loaded |= loaded;
        }
        let total = self.weight.fetch_add(added * SLOT_WEIGHT, Ordering::Relaxed) + added * SLOT_WEIGHT;
        if total > LOOKUP_BUDGET {
            self.evict(project);
        }
    }

    /// Drop the maps of projects used least recently (never `keep`'s)
    /// until the maps fit [`LOOKUP_BUDGET`].
    fn evict(&self, keep: i64) {
        let mut g = self.projects.lock().unwrap();
        let mut by_use: Vec<(Instant, i64)> = g.iter().filter(|(k, _)| **k != keep).map(|(k, p)| (*p.used.lock().unwrap(), *k)).collect();
        by_use.sort();
        for (_, k) in by_use {
            if self.weight.load(Ordering::Relaxed) <= LOOKUP_BUDGET {
                break;
            }
            if let Some(p) = g.remove(&k) {
                let n = p.map.read().unwrap().slots.len();
                self.weight.fetch_sub(n * SLOT_WEIGHT, Ordering::Relaxed);
            }
        }
    }

    /// Read `project`'s listing again, and the indexes of the packs this
    /// server does not know, unless a listing began after `since` (it
    /// holds every pack listed before then).
    pub async fn refresh(&self, store: &Arc<dyn BlobStore>, project: i64, since: Instant, reads: &AtomicU64) -> Result<()> {
        let p = self.project(project);
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
        let rows: Vec<String> = sqlx::query_scalar("SELECT name FROM packs WHERE project_id = $1 AND listed")
            .bind(project)
            .fetch_all(db)
            .await?;
        let new: Vec<String> = {
            let m = p.map.read().unwrap();
            rows.into_iter().filter(|n| !m.packs.contains(n.as_str())).collect()
        };
        let mut got = Vec::new();
        let mut set = tokio::task::JoinSet::new();
        let mut it = new.into_iter();
        loop {
            while set.len() < 16 {
                let Some(name) = it.next() else { break };
                let (k, name): (String, Arc<str>) = (key(project, &name), name.into());
                reads.fetch_add(1, Ordering::Relaxed);
                let store = store.clone();
                set.spawn(async move { (name, read_index(&*store, &k).await) });
            }
            match set.join_next().await {
                Some(Ok((name, Ok(Some((index, _)))))) => got.push((name, Arc::new(index))),
                Some(Ok((name, Ok(None)))) => bail!("listed pack {name} of project {project} is not in the store"),
                Some(Ok((_, Err(e)))) => return Err(e),
                Some(Err(e)) => return Err(e.into()),
                None => break,
            }
        }
        self.add(project, got, true);
        *last = Some(began);
        Ok(())
    }

    /// Packs this server listed in a transaction that committed.
    pub fn listed_here(&self, project: i64, packs: Vec<(Arc<str>, Arc<Index>)>) {
        // Only into a map that is loaded: an unloaded one reads the whole
        // listing when first used. Without a database, what this process
        // lists is the listing.
        let loaded = self.db.is_none() || self.project(project).map.read().unwrap().loaded;
        if loaded {
            self.add(project, packs, self.db.is_none());
        }
    }

    /// Remember the index of a pack staged here.
    pub fn staged_here(&self, project: i64, name: &str, index: Arc<Index>, size: u64) {
        let w = index.weight();
        self.staged.insert(name_key(project, name), Some((index, size)), w);
    }

    /// The index and length of staged pack `name`: from memory, or read.
    pub async fn staged_index(&self, store: &dyn BlobStore, project: i64, name: &str) -> Result<Option<(Arc<Index>, u64)>> {
        if let Some(i) = self.staged.get(&name_key(project, name)) {
            return Ok(i);
        }
        Ok(read_index(store, &key(project, name)).await?.map(|(i, s)| (Arc::new(i), s)))
    }

    /// Discard packs `names` of `project` that no transaction listed: a row
    /// without `listed` first (so no push can list them after), then the
    /// storage objects. A pack already listed is left as it is.
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
                    "INSERT INTO packs (project_id, name, size, objects, listed, created_at) \
                     SELECT $1, n, 0, 0, FALSE, $3 FROM UNNEST($2::text[]) AS t(n) ON CONFLICT DO NOTHING RETURNING name",
                )
                .bind(project)
                .bind(&names)
                .bind(veil_core::now_millis())
                .fetch_all(db)
                .await?
            }
            None => names.iter().map(|n| n.to_string()).collect(),
        };
        for n in gone {
            store.delete(&key(project, &n)).await?;
        }
        Ok(())
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
            assert_eq!(&pack[s.offset as usize..=s.last() as usize], &raw[..]);
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
        assert!(parse_index(b"veilpack2\n\0\0\0\0", None).is_err(), "another magic");
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
        assert!(valid_name(&new_name()) && !valid_name("../x") && !valid_name(&"A".repeat(32)));
    }
}
