//! Packfiles: many objects in one file, located through a sorted index.
//!
//! A pack is a pair of files in `.veil/objects/pack/`, named after the
//! BLAKE3 checksum of the pack data:
//!
//! ```text
//! pack-<hex>.pack   "VEILPAK1" | count u32 | entry* | BLAKE3(everything before)
//!   entry          = kind u8 | raw_len u64 | [base id, 32 bytes — deltas only] | data
//!   kind 0 stored  data is the canonical encoding itself (sealed objects)
//!   kind 1 zstd    data is a zstd frame of the canonical encoding
//!   kind 2 delta   data is a zstd frame compressed with the canonical
//!                  encoding of `base` (in the same pack) as a raw-content
//!                  dictionary
//!
//! pack-<hex>.idx    "VEILIDX1" | count u32 | fanout [256] u32 | ids [count] 32 bytes (sorted)
//!                   | offsets [count] u64 | lengths [count] u64 | pack checksum | BLAKE3(everything before)
//! ```
//!
//! All integers are little-endian. `fanout[b]` is the number of ids whose
//! first byte is `<= b`, so a lookup is one fan-out step plus a binary search
//! over a single bucket.
//!
//! Object ids stay the BLAKE3 of the **uncompressed** canonical encoding;
//! compression is purely a storage detail. Every object read from a pack is
//! re-hashed, so any corruption (flipped bits, truncated files, a wrong delta
//! base) surfaces as [`VeilError::Corrupt`], never as wrong content.
//!
//! The `.pack` file is always written before its `.idx`, and readers only
//! discover packs through `.idx` files, so a reader never sees half a pack.

use std::{
    collections::HashMap,
    io::Read,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock,
    },
};

use crate::{
    cache::LruCache,
    error::{Result, VeilError},
    id::ObjectId,
    object::Object,
    vfs::StorageBackend,
    vpath::VPath,
};

pub const PACK_MAGIC: &[u8; 8] = b"VEILPAK1";
pub const IDX_MAGIC: &[u8; 8] = b"VEILIDX1";

/// A later pack or index version (`VEILPAK2`, `VEILIDX2`, …): written by a
/// newer vl, so "unsupported", not "corrupt".
fn newer_magic(found: &[u8], ours: &[u8; 8]) -> Option<VeilError> {
    let v = *found.get(7)?;
    (found.len() >= 8 && found[..7] == ours[..7] && v.is_ascii_digit() && v > ours[7]).then(|| {
        VeilError::Unsupported(format!(
            "{} version {} needs a newer vl (this is vl {})",
            if ours == PACK_MAGIC { "pack" } else { "pack index" },
            v as char,
            env!("CARGO_PKG_VERSION")
        ))
    })
}

/// Entry kinds reserved for later pack versions.
const RESERVED_KINDS: std::ops::RangeInclusive<u8> = 3..=15;
const HEADER_LEN: usize = 12;
const SUM_LEN: usize = 32;
const FANOUT_LEN: usize = 256 * 4;
const IDX_ENTRY_LEN: usize = 32 + 8 + 8;

/// Longest delta chain the writer produces. Bounds read amplification.
pub const MAX_DELTA_DEPTH: u32 = 10;
/// Longest chain a reader follows before declaring the pack corrupt (also
/// protects against cycles in a damaged pack).
const MAX_READ_CHAIN: usize = 64;
/// Objects larger than this are decompressed by streaming instead of into a
/// pre-sized buffer, so a corrupt length can never trigger a huge allocation.
const BULK_LIMIT: u64 = 64 << 20;
/// Deltas are only tried for objects at least this large.
const MIN_DELTA_SIZE: usize = 64;

pub const DEFAULT_LEVEL: i32 = 3;

/// After this many ranged reads from one pack, a process loads the whole pack
/// into memory (if it is at most [`SLURP_LIMIT`] bytes): bulk readers (log,
/// diff, push, checkout) stop paying several syscalls per object, while
/// short commands still only read the entries they need.
const SLURP_AFTER: usize = 64;
const SLURP_LIMIT: u64 = 256 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryKind {
    Stored = 0,
    Zstd = 1,
    Delta = 2,
}

impl EntryKind {
    fn from_u8(b: u8) -> Option<EntryKind> {
        match b {
            0 => Some(EntryKind::Stored),
            1 => Some(EntryKind::Zstd),
            2 => Some(EntryKind::Delta),
            _ => None,
        }
    }
}

fn corrupt(what: impl Into<String>, msg: impl Into<String>) -> VeilError {
    VeilError::Corrupt(what.into(), msg.into())
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn id_at(b: &[u8], at: usize) -> ObjectId {
    ObjectId(b[at..at + 32].try_into().unwrap())
}

pub fn pack_file(dir: &VPath, name: &str) -> VPath {
    dir.join(&format!("pack-{name}.pack"))
}

pub fn index_file(dir: &VPath, name: &str) -> VPath {
    dir.join(&format!("pack-{name}.idx"))
}

/// Pack name from an index file name (`pack-<64 hex>.idx`).
pub fn name_from_index_file(file: &str) -> Option<&str> {
    let name = file.strip_prefix("pack-")?.strip_suffix(".idx")?;
    (name.len() == 64 && name.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())).then_some(name)
}

// ---- index ------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PackIndex {
    fanout: Vec<u32>,
    ids: Vec<ObjectId>,
    offsets: Vec<u64>,
    lens: Vec<u64>,
    pack_sum: [u8; 32],
}

impl PackIndex {
    fn build(mut entries: Vec<(ObjectId, u64, u64)>, pack_sum: [u8; 32]) -> PackIndex {
        entries.sort_by_key(|e| e.0);
        let mut fanout = vec![0u32; 256];
        for (id, _, _) in &entries {
            fanout[id.0[0] as usize] += 1;
        }
        for b in 1..256 {
            fanout[b] += fanout[b - 1];
        }
        PackIndex {
            fanout,
            ids: entries.iter().map(|e| e.0).collect(),
            offsets: entries.iter().map(|e| e.1).collect(),
            lens: entries.iter().map(|e| e.2).collect(),
            pack_sum,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let n = self.ids.len();
        let mut out = Vec::with_capacity(HEADER_LEN + FANOUT_LEN + n * IDX_ENTRY_LEN + 2 * SUM_LEN);
        out.extend_from_slice(IDX_MAGIC);
        out.extend_from_slice(&(n as u32).to_le_bytes());
        for f in &self.fanout {
            out.extend_from_slice(&f.to_le_bytes());
        }
        for id in &self.ids {
            out.extend_from_slice(&id.0);
        }
        for o in &self.offsets {
            out.extend_from_slice(&o.to_le_bytes());
        }
        for l in &self.lens {
            out.extend_from_slice(&l.to_le_bytes());
        }
        out.extend_from_slice(&self.pack_sum);
        let sum = blake3::hash(&out);
        out.extend_from_slice(sum.as_bytes());
        out
    }

    pub fn decode(raw: &[u8]) -> Result<PackIndex> {
        let bad = |m: &str| corrupt("pack index", m);
        if let Some(e) = newer_magic(raw, IDX_MAGIC) {
            return Err(e);
        }
        if raw.len() < HEADER_LEN + FANOUT_LEN + 2 * SUM_LEN || &raw[..8] != IDX_MAGIC {
            return Err(bad("bad header"));
        }
        let n = u32_at(raw, 8) as usize;
        let expected = n
            .checked_mul(IDX_ENTRY_LEN)
            .and_then(|x| x.checked_add(HEADER_LEN + FANOUT_LEN + 2 * SUM_LEN));
        if expected != Some(raw.len()) {
            return Err(bad("wrong length"));
        }
        let body = raw.len() - SUM_LEN;
        if blake3::hash(&raw[..body]).as_bytes() != &raw[body..] {
            return Err(bad("checksum mismatch"));
        }
        let fanout: Vec<u32> = (0..256).map(|b| u32_at(raw, HEADER_LEN + b * 4)).collect();
        if fanout.windows(2).any(|w| w[0] > w[1]) || fanout[255] as usize != n {
            return Err(bad("inconsistent fan-out table"));
        }
        let ids_at = HEADER_LEN + FANOUT_LEN;
        let offs_at = ids_at + n * 32;
        let lens_at = offs_at + n * 8;
        let sum_at = lens_at + n * 8;
        let ids: Vec<ObjectId> = (0..n).map(|i| id_at(raw, ids_at + i * 32)).collect();
        if ids.windows(2).any(|w| w[0] >= w[1]) {
            return Err(bad("ids are not strictly sorted"));
        }
        for (i, id) in ids.iter().enumerate() {
            let b = id.0[0] as usize;
            let lo = if b == 0 { 0 } else { fanout[b - 1] as usize };
            if i < lo || i >= fanout[b] as usize {
                return Err(bad("fan-out table does not match the ids"));
            }
        }
        Ok(PackIndex {
            fanout,
            ids,
            offsets: (0..n).map(|i| u64_at(raw, offs_at + i * 8)).collect(),
            lens: (0..n).map(|i| u64_at(raw, lens_at + i * 8)).collect(),
            pack_sum: raw[sum_at..sum_at + 32].try_into().unwrap(),
        })
    }

    pub fn find(&self, id: &ObjectId) -> Option<usize> {
        let b = id.0[0] as usize;
        let lo = if b == 0 { 0 } else { self.fanout[b - 1] as usize };
        let hi = self.fanout[b] as usize;
        self.ids[lo..hi].binary_search(id).ok().map(|i| lo + i)
    }

    pub fn ids(&self) -> &[ObjectId] {
        &self.ids
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Hex checksum of the pack data, which is also the pack's name.
    pub fn name(&self) -> String {
        hex::encode(self.pack_sum)
    }
}

// ---- reading ----------------------------------------------------------------

struct Entry {
    kind: EntryKind,
    raw_len: u64,
    base: Option<ObjectId>,
    data: Vec<u8>,
}

/// An opened pack: its parsed index plus the location of its data file.
#[derive(Debug)]
pub struct Pack {
    name: String,
    path: VPath,
    index_path: VPath,
    index: PackIndex,
    size: u64,
    reads: AtomicUsize,
    data: OnceLock<Vec<u8>>,
}

impl Pack {
    /// Open a pack by name, validating the index and cross-checking it against
    /// the pack's header, size and trailing checksum.
    pub fn open(backend: &dyn StorageBackend, dir: &VPath, name: &str) -> Result<Pack> {
        let what = || format!("pack {}", &name[..name.len().min(12)]);
        let index_path = index_file(dir, name);
        let path = pack_file(dir, name);
        let index = PackIndex::decode(&backend.read(&index_path)?).map_err(|e| match e {
            VeilError::Corrupt(_, m) => corrupt(what(), format!("index: {m}")),
            e => e,
        })?;
        if index.name() != name {
            return Err(corrupt(what(), "index belongs to a different pack"));
        }
        let size = match backend.metadata(&path)? {
            Some(m) => m.len,
            None => return Err(corrupt(what(), "pack data file is missing")),
        };
        if size < (HEADER_LEN + SUM_LEN) as u64 {
            return Err(corrupt(what(), "pack data file is truncated"));
        }
        let header = backend.read_range(&path, 0, HEADER_LEN)?;
        if let Some(e) = newer_magic(&header, PACK_MAGIC) {
            return Err(e);
        }
        if &header[..8] != PACK_MAGIC || u32_at(&header, 8) as usize != index.len() {
            return Err(corrupt(what(), "pack header does not match its index"));
        }
        let trailer = backend.read_range(&path, size - SUM_LEN as u64, SUM_LEN)?;
        if trailer[..] != index.pack_sum[..] {
            return Err(corrupt(what(), "pack checksum does not match its index"));
        }
        let data_end = size - SUM_LEN as u64;
        for (o, l) in index.offsets.iter().zip(&index.lens) {
            if *o < HEADER_LEN as u64 || o.checked_add(*l).is_none_or(|end| end > data_end) || *l < 9 {
                return Err(corrupt(what(), "index entry points outside the pack"));
            }
        }
        Ok(Pack {
            name: name.to_string(),
            path,
            index_path,
            index,
            size,
            reads: AtomicUsize::new(0),
            data: OnceLock::new(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn index(&self) -> &PackIndex {
        &self.index
    }

    pub fn contains(&self, id: &ObjectId) -> bool {
        self.index.find(id).is_some()
    }

    /// Bytes on the backend (pack data plus index).
    pub fn disk_size(&self) -> u64 {
        self.size + (HEADER_LEN + FANOUT_LEN + self.index.len() * IDX_ENTRY_LEN + 2 * SUM_LEN) as u64
    }

    pub fn path(&self) -> &VPath {
        &self.path
    }

    pub fn index_path(&self) -> &VPath {
        &self.index_path
    }

    fn what(&self) -> String {
        format!("pack {}", &self.name[..12])
    }

    /// The whole pack, once it has been read often enough to be worth it.
    fn whole(&self, backend: &dyn StorageBackend) -> Result<Option<&[u8]>> {
        if let Some(d) = self.data.get() {
            return Ok(Some(d));
        }
        if self.size > SLURP_LIMIT || self.reads.fetch_add(1, Ordering::Relaxed) < SLURP_AFTER {
            return Ok(None);
        }
        let all = backend.read(&self.path)?;
        if all.len() as u64 != self.size || all[all.len() - SUM_LEN..] != self.index.pack_sum[..] {
            return Err(corrupt(self.what(), "pack changed on disk"));
        }
        Ok(Some(self.data.get_or_init(|| all)))
    }

    fn read_entry(&self, backend: &dyn StorageBackend, i: usize) -> Result<Entry> {
        let len = usize::try_from(self.index.lens[i]).map_err(|_| corrupt(self.what(), "entry too large"))?;
        let offset = self.index.offsets[i];
        let ranged;
        let raw: &[u8] = match self.whole(backend)? {
            Some(all) => &all[offset as usize..offset as usize + len],
            None => {
                ranged = backend.read_range(&self.path, offset, len)?;
                &ranged
            }
        };
        let kind = EntryKind::from_u8(raw[0]).ok_or_else(|| {
            if RESERVED_KINDS.contains(&raw[0]) {
                VeilError::Unsupported(format!(
                    "pack entry kind {} needs a newer vl (this is vl {})",
                    raw[0],
                    env!("CARGO_PKG_VERSION")
                ))
            } else {
                corrupt(self.what(), "unknown entry kind")
            }
        })?;
        let raw_len = u64_at(raw, 1);
        let (base, data_at) = match kind {
            EntryKind::Delta if raw.len() >= 41 => (Some(id_at(raw, 9)), 41),
            EntryKind::Delta => return Err(corrupt(self.what(), "truncated delta entry")),
            _ => (None, 9),
        };
        Ok(Entry {
            kind,
            raw_len,
            base,
            data: raw[data_at..].to_vec(),
        })
    }

    /// The canonical encoding of `id`, or `None` if this pack lacks it.
    /// Delta bases met on the way are cached in `bases`.
    pub fn get(
        &self,
        backend: &dyn StorageBackend,
        id: &ObjectId,
        bases: &LruCache<Arc<Vec<u8>>>,
    ) -> Result<Option<Vec<u8>>> {
        let Some(mut i) = self.index.find(id) else {
            return Ok(None);
        };
        // Walk down the delta chain until a full object or a cached base.
        let mut chain: Vec<(ObjectId, Entry)> = Vec::new();
        let mut cur = *id;
        let mut base: Arc<Vec<u8>> = loop {
            if chain.len() > MAX_READ_CHAIN {
                return Err(corrupt(self.what(), "delta chain too long (cycle?)"));
            }
            if !chain.is_empty() {
                if let Some(b) = bases.get(&cur) {
                    break b;
                }
            }
            let e = self.read_entry(backend, i)?;
            match (e.kind, e.base) {
                (EntryKind::Delta, Some(b)) => {
                    chain.push((cur, e));
                    cur = b;
                    i = self
                        .index
                        .find(&b)
                        .ok_or_else(|| corrupt(self.what(), format!("delta base {} is not in the pack", b.short())))?;
                }
                (EntryKind::Stored, _) => break Arc::new(self.check(&cur, e.raw_len, e.data)?),
                _ => {
                    let raw = decompress(&e.data, e.raw_len, None).map_err(|m| corrupt(cur.hex(), m))?;
                    break Arc::new(self.check(&cur, e.raw_len, raw)?);
                }
            }
        };
        let mut base_id = cur;
        while let Some((oid, e)) = chain.pop() {
            bases.insert(base_id, base.clone(), base.len());
            let raw = decompress(&e.data, e.raw_len, Some(&base)).map_err(|m| corrupt(oid.hex(), m))?;
            base = Arc::new(self.check(&oid, e.raw_len, raw)?);
            base_id = oid;
        }
        Ok(Some(Arc::try_unwrap(base).unwrap_or_else(|a| (*a).clone())))
    }

    fn check(&self, id: &ObjectId, raw_len: u64, raw: Vec<u8>) -> Result<Vec<u8>> {
        if raw.len() as u64 != raw_len || ObjectId::hash(&raw) != *id {
            return Err(corrupt(
                id.hex(),
                format!("content does not match its id (in {})", self.what()),
            ));
        }
        Ok(raw)
    }

    /// Full check: the pack checksum, and every object decodes to its id.
    pub fn verify(&self, backend: &dyn StorageBackend) -> Result<()> {
        let data = backend.read(&self.path)?;
        if data.len() as u64 != self.size || data.len() < SUM_LEN {
            return Err(corrupt(self.what(), "pack changed size"));
        }
        let body = data.len() - SUM_LEN;
        if blake3::hash(&data[..body]).as_bytes()[..] != data[body..] {
            return Err(corrupt(self.what(), "pack checksum mismatch"));
        }
        let bases = LruCache::new(64 << 20);
        for id in self.index.ids() {
            self.get(backend, id, &bases)?;
        }
        Ok(())
    }
}

fn decompress(data: &[u8], raw_len: u64, dict: Option<&[u8]>) -> std::result::Result<Vec<u8>, String> {
    let frame_len = zstd::bulk::Decompressor::upper_bound(data);
    if frame_len.map(|n| n as u64) != Some(raw_len) {
        return Err("compressed frame does not match the recorded length".into());
    }
    let out = if raw_len <= BULK_LIMIT {
        // Creating a zstd context per object dominates small reads; reuse
        // one per thread.
        thread_local! {
            static DCTX: std::cell::RefCell<Option<zstd::bulk::Decompressor<'static>>> =
                const { std::cell::RefCell::new(None) };
        }
        DCTX.with(|cell| -> std::result::Result<Vec<u8>, String> {
            let mut slot = cell.borrow_mut();
            if slot.is_none() {
                *slot = Some(zstd::bulk::Decompressor::new().map_err(|e| e.to_string())?);
            }
            let d = slot.as_mut().unwrap();
            d.set_dictionary(dict.unwrap_or(&[])).map_err(|e| e.to_string())?;
            let out = d.decompress(data, raw_len as usize).map_err(|e| e.to_string());
            if dict.is_some() {
                d.set_dictionary(&[]).map_err(|e| e.to_string())?;
            }
            out
        })?
    } else {
        let mut out = Vec::new();
        let dec = match dict {
            Some(dict) => zstd::stream::read::Decoder::with_dictionary(data, dict),
            None => zstd::stream::read::Decoder::with_buffer(data),
        }
        .map_err(|e| e.to_string())?;
        dec.take(raw_len + 1).read_to_end(&mut out).map_err(|e| e.to_string())?;
        out
    };
    if out.len() as u64 != raw_len {
        return Err("decompressed length does not match the recorded length".into());
    }
    Ok(out)
}

// ---- writing ----------------------------------------------------------------

/// What a pack ended up containing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PackStats {
    pub objects: usize,
    pub stored: usize,
    pub compressed: usize,
    pub deltas: usize,
    /// Sum of canonical (uncompressed) sizes.
    pub raw_bytes: u64,
    /// Size of the pack data file.
    pub pack_bytes: u64,
}

/// Accumulates objects into a pack in memory, then writes it out.
///
/// Objects are written in insertion order; a delta base must have been added
/// before the objects that use it.
pub struct PackBuilder {
    level: i32,
    max_depth: u32,
    buf: Vec<u8>,
    entries: Vec<(ObjectId, u64, u64)>,
    depth: HashMap<ObjectId, u32>,
    plain: zstd::bulk::Compressor<'static>,
    stats: PackStats,
}

impl PackBuilder {
    pub fn new(level: i32) -> Result<PackBuilder> {
        let mut buf = Vec::with_capacity(1 << 20);
        buf.extend_from_slice(PACK_MAGIC);
        buf.extend_from_slice(&0u32.to_le_bytes());
        Ok(PackBuilder {
            level,
            max_depth: MAX_DELTA_DEPTH,
            buf,
            entries: Vec::new(),
            depth: HashMap::new(),
            plain: zstd::bulk::Compressor::new(level).map_err(|e| VeilError::repo(format!("zstd: {e}")))?,
            stats: PackStats::default(),
        })
    }

    pub fn with_max_depth(mut self, depth: u32) -> Self {
        self.max_depth = depth;
        self
    }

    pub fn contains(&self, id: &ObjectId) -> bool {
        self.depth.contains_key(id)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add one object (its canonical encoding). `base` is an optional delta
    /// candidate that is already in this pack; the delta is kept only if it is
    /// smaller than plain compression. Sealed objects are stored as they are:
    /// ciphertext does not compress.
    pub fn add(&mut self, id: ObjectId, raw: &[u8], base: Option<(&ObjectId, &[u8])>) -> Result<()> {
        if self.contains(&id) {
            return Ok(());
        }
        if ObjectId::hash(raw) != id {
            return Err(corrupt(id.hex(), "hash mismatch while packing"));
        }
        let zerr = |e: std::io::Error| VeilError::repo(format!("zstd: {e}"));
        let (kind, data, base_id, depth) = if Object::sealed_scope(raw).is_some() {
            (EntryKind::Stored, raw.to_vec(), None, 0)
        } else {
            let plain = self.plain.compress(raw).map_err(zerr)?;
            let mut best = if plain.len() < raw.len() {
                (EntryKind::Zstd, plain, None, 0)
            } else {
                (EntryKind::Stored, raw.to_vec(), None, 0)
            };
            if let Some((bid, braw)) = base {
                let bdepth = self.depth.get(bid).copied();
                let usable = raw.len() >= MIN_DELTA_SIZE
                    && bdepth.is_some_and(|d| d < self.max_depth)
                    && Object::sealed_scope(braw).is_none();
                if usable {
                    let mut c = zstd::bulk::Compressor::with_dictionary(self.level, braw).map_err(zerr)?;
                    let delta = c.compress(raw).map_err(zerr)?;
                    // Worth a dependency only if clearly smaller.
                    if delta.len() + 32 + delta.len() / 8 < best.1.len() {
                        best = (EntryKind::Delta, delta, Some(*bid), bdepth.unwrap() + 1);
                    }
                }
            }
            best
        };
        let offset = self.buf.len() as u64;
        self.buf.push(kind as u8);
        self.buf.extend_from_slice(&(raw.len() as u64).to_le_bytes());
        if let Some(b) = base_id {
            self.buf.extend_from_slice(&b.0);
        }
        self.buf.extend_from_slice(&data);
        self.entries.push((id, offset, self.buf.len() as u64 - offset));
        self.depth.insert(id, depth);
        self.stats.objects += 1;
        self.stats.raw_bytes += raw.len() as u64;
        match kind {
            EntryKind::Stored => self.stats.stored += 1,
            EntryKind::Zstd => self.stats.compressed += 1,
            EntryKind::Delta => self.stats.deltas += 1,
        }
        Ok(())
    }

    /// Write `pack-<sum>.pack` and then `pack-<sum>.idx` into `dir`. Returns
    /// the pack name, or `None` if no objects were added.
    pub fn finish(mut self, backend: &dyn StorageBackend, dir: &VPath) -> Result<Option<(String, PackStats)>> {
        if self.entries.is_empty() {
            return Ok(None);
        }
        let count = u32::try_from(self.entries.len()).map_err(|_| VeilError::repo("too many objects for one pack"))?;
        self.buf[8..12].copy_from_slice(&count.to_le_bytes());
        let sum = *blake3::hash(&self.buf).as_bytes();
        self.buf.extend_from_slice(&sum);
        let index = PackIndex::build(std::mem::take(&mut self.entries), sum);
        let name = index.name();
        backend.write(&pack_file(dir, &name), &self.buf)?;
        backend.write(&index_file(dir, &name), &index.encode())?;
        self.stats.pack_bytes = self.buf.len() as u64;
        Ok(Some((name, self.stats)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::MemoryBackend;

    fn blob(s: &[u8]) -> (ObjectId, Vec<u8>) {
        let raw = Object::Blob(s.to_vec()).encode();
        (ObjectId::hash(&raw), raw)
    }

    #[test]
    fn index_lookup_and_corruption() {
        let entries: Vec<(ObjectId, u64, u64)> = (0..500u32)
            .map(|i| (ObjectId::hash(&i.to_le_bytes()), 12 + i as u64 * 10, 10))
            .collect();
        let idx = PackIndex::build(entries.clone(), [7; 32]);
        let enc = idx.encode();
        let dec = PackIndex::decode(&enc).unwrap();
        for (id, off, _) in &entries {
            assert_eq!(dec.offsets[dec.find(id).unwrap()], *off);
        }
        assert_eq!(dec.find(&ObjectId([0xab; 32])), None);
        for at in [3, 20, HEADER_LEN + FANOUT_LEN + 5, enc.len() - 40] {
            let mut bad = enc.clone();
            bad[at] ^= 1;
            assert!(PackIndex::decode(&bad).is_err(), "flip at {at} detected");
        }
        assert!(PackIndex::decode(&enc[..enc.len() - 1]).is_err());
    }

    #[test]
    fn deltas_round_trip() {
        let fs = MemoryBackend::new();
        let dir = VPath::new("p").unwrap();
        let base_text: Vec<u8> = (0..4000).flat_map(|i| format!("line {i}\n").into_bytes()).collect();
        let mut edited = base_text.clone();
        edited.extend_from_slice(b"one more line\n");
        let (b_id, b_raw) = blob(&base_text);
        let (e_id, e_raw) = blob(&edited);
        let mut pb = PackBuilder::new(DEFAULT_LEVEL).unwrap();
        pb.add(e_id, &e_raw, None).unwrap();
        pb.add(b_id, &b_raw, Some((&e_id, &e_raw))).unwrap();
        let (name, stats) = pb.finish(&fs, &dir).unwrap().unwrap();
        assert_eq!(stats.deltas, 1);
        let pack = Pack::open(&fs, &dir, &name).unwrap();
        let cache = LruCache::new(1 << 20);
        assert_eq!(pack.get(&fs, &b_id, &cache).unwrap().unwrap(), b_raw);
        assert_eq!(pack.get(&fs, &e_id, &cache).unwrap().unwrap(), e_raw);
        pack.verify(&fs).unwrap();
    }
}
