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
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock,
    },
};

use crate::{
    cache::LruCache,
    error::{Result, VeilError},
    id::ObjectId,
    vfs::StorageBackend,
    vpath::VPath,
};

#[cfg(feature = "zstd")]
use crate::object::Object;

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
/// They are decoded twice: once into a hash (in [`STREAM_CHUNK`]s), and
/// only once that matched the id into memory, so a frame that inflates to
/// gigabytes of anything else costs time but never memory (BUG-490).
const BULK_LIMIT: u64 = 64 << 20;
/// Output buffer of a streamed decode.
const STREAM_CHUNK: usize = 1 << 20;

/// Largest object a pack entry may hold by default: the ceiling one file
/// read from an SFTP remote has (`VEIL_SFTP_MAX_FILE`), and the Veil Hub's
/// object limit. `VEIL_MAX_OBJECT` (bytes, or a `K`/`M`/`G` suffix)
/// overrides it. An entry declaring more is refused before anything is
/// decoded (BUG-490).
pub const DEFAULT_MAX_OBJECT: u64 = 4 << 30;

/// Most entries one pack may hold: far more than any pack vl writes (sync
/// packs close at about 128 MiB, see `remote.rs`), so an index claiming
/// more is damaged or hostile.
pub const MAX_PACK_ENTRIES: usize = 1 << 25;

/// The largest object a pack entry may declare in this process:
/// `VEIL_MAX_OBJECT`, or [`DEFAULT_MAX_OBJECT`] (also when the setting
/// does not parse).
pub fn max_object_size() -> u64 {
    static MAX: OnceLock<u64> = OnceLock::new();
    *MAX.get_or_init(|| {
        std::env::var("VEIL_MAX_OBJECT").ok().and_then(|v| crate::vfs::parse_size(&v)).unwrap_or(DEFAULT_MAX_OBJECT)
    })
}
/// Deltas are only tried for objects at least this large.
#[cfg(feature = "zstd")]
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
        if n > MAX_PACK_ENTRIES {
            return Err(bad(&format!("{n} entries, more than a pack may hold ({MAX_PACK_ENTRIES})")));
        }
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

    /// The size of the pack data file this index describes: its header,
    /// every entry and the checksum (a pack vl writes has no gaps).
    pub fn pack_len(&self) -> u64 {
        let end = self.offsets.iter().zip(&self.lens).map(|(o, l)| o.saturating_add(*l)).max().unwrap_or(HEADER_LEN as u64);
        end.saturating_add(SUM_LEN as u64)
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
    /// Largest object an entry may declare ([`max_object_size`]).
    max_object: u64,
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
            max_object: max_object_size(),
        })
    }

    /// The same pack, refusing entries that declare more than `bytes`
    /// (instead of [`max_object_size`]).
    pub fn with_max_object(mut self, bytes: u64) -> Pack {
        self.max_object = bytes;
        self
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
        if raw_len > self.max_object {
            return Err(corrupt(
                self.what(),
                format!(
                    "an entry declares {raw_len} bytes unpacked, more than the {} bytes an object may have here (VEIL_MAX_OBJECT raises the limit)",
                    self.max_object
                ),
            ));
        }
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
                    let raw = decompress(&e.data, e.raw_len, None, &cur).map_err(|m| corrupt(cur.hex(), m))?;
                    break Arc::new(self.check(&cur, e.raw_len, raw)?);
                }
            }
        };
        let mut base_id = cur;
        while let Some((oid, e)) = chain.pop() {
            bases.insert(base_id, base.clone(), base.len());
            let raw = decompress(&e.data, e.raw_len, Some(&base), &oid).map_err(|m| corrupt(oid.hex(), m))?;
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

/// Decode one zstd frame of exactly `raw_len` bytes (optionally against
/// `dict`) that must hash to `id`. Small objects are decoded into a buffer
/// of their size at once; above [`BULK_LIMIT`] the frame is first streamed
/// into the hash only, and decoded into memory once that matched (BUG-490).
/// Neither pass ever produces more than `raw_len` bytes.
fn decompress(data: &[u8], raw_len: u64, dict: Option<&[u8]>, id: &ObjectId) -> std::result::Result<Vec<u8>, String> {
    if raw_len <= BULK_LIMIT {
        return decompress_bulk(data, raw_len, dict);
    }
    let mut hasher = blake3::Hasher::new();
    stream(data, raw_len, dict, &mut |chunk| {
        hasher.update(chunk);
    })?;
    if hasher.finalize().as_bytes() != &id.0 {
        return Err("content does not match its id".into());
    }
    let limit = usize::try_from(raw_len).map_err(|_| "object too large for this platform".to_string())?;
    let mut out = Vec::with_capacity(limit);
    stream(data, raw_len, dict, &mut |chunk| out.extend_from_slice(chunk))?;
    Ok(out)
}

#[cfg(feature = "zstd")]
fn decompress_bulk(data: &[u8], raw_len: u64, dict: Option<&[u8]>) -> std::result::Result<Vec<u8>, String> {
    let frame_len = zstd::bulk::Decompressor::upper_bound(data);
    if frame_len.map(|n| n as u64) != Some(raw_len) {
        return Err("compressed frame does not match the recorded length".into());
    }
    // Creating a zstd context per object dominates small reads; reuse
    // one per thread. The output buffer is `raw_len` bytes: decoding fails
    // rather than grow it.
    thread_local! {
        static DCTX: std::cell::RefCell<Option<zstd::bulk::Decompressor<'static>>> =
            const { std::cell::RefCell::new(None) };
    }
    let out = DCTX.with(|cell| -> std::result::Result<Vec<u8>, String> {
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
    })?;
    if out.len() as u64 != raw_len {
        return Err("decompressed length does not match the recorded length".into());
    }
    Ok(out)
}

/// Stream the frame's content to `sink` in chunks of at most
/// [`STREAM_CHUNK`] bytes: exactly `raw_len` bytes, or an error as soon as
/// it would be more (or ends short).
#[cfg(feature = "zstd")]
fn stream(data: &[u8], raw_len: u64, dict: Option<&[u8]>, sink: &mut dyn FnMut(&[u8])) -> std::result::Result<(), String> {
    use std::io::Read;
    if zstd::bulk::Decompressor::upper_bound(data).map(|n| n as u64) != Some(raw_len) {
        return Err("compressed frame does not match the recorded length".into());
    }
    let mut dec = match dict {
        Some(dict) => zstd::stream::read::Decoder::with_dictionary(data, dict),
        None => zstd::stream::read::Decoder::with_buffer(data),
    }
    .map_err(|e| e.to_string())?;
    // One frame only: data after it is not this object's.
    dec = dec.single_frame();
    dec.window_log_max(MAX_DELTA_WINDOW_LOG).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; STREAM_CHUNK];
    let mut total = 0u64;
    loop {
        let n = dec.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > raw_len {
            return Err("decompressed length does not match the recorded length".into());
        }
        sink(&buf[..n]);
    }
    if total != raw_len {
        return Err("decompressed length does not match the recorded length".into());
    }
    Ok(())
}

#[cfg(not(feature = "zstd"))]
fn decompress_bulk(data: &[u8], raw_len: u64, dict: Option<&[u8]>) -> std::result::Result<Vec<u8>, String> {
    pure::decompress(data, raw_len, dict)
}

#[cfg(not(feature = "zstd"))]
fn stream(data: &[u8], raw_len: u64, dict: Option<&[u8]>, sink: &mut dyn FnMut(&[u8])) -> std::result::Result<(), String> {
    pure::stream(data, raw_len, dict, sink)
}

// Without the zstd C library, every entry is read with the pure-Rust
// decoder (identical results: the content is re-hashed either way).

/// Reading zstd frames with `ruzstd`, the pure-Rust decoder (no C library:
/// builds without `zstd`, such as WASM). With both features the C library
/// reads, and this is only tested against it.
#[cfg(feature = "ruzstd")]
#[cfg_attr(feature = "zstd", allow(dead_code))]
pub(crate) mod pure {
    use ruzstd::decoding::{BlockDecodingStrategy, Dictionary, FrameDecoder};

    /// The header of a *formatted* zstd dictionary: magic, id 1, entropy
    /// tables and the default repeat offsets 1, 4, 8.
    ///
    /// Delta entries are compressed against their base as a *raw-content*
    /// dictionary (or prefix), which `ruzstd` cannot load directly: it only
    /// parses formatted dictionaries. A formatted dictionary is entropy
    /// tables, the starting repeat offsets and then raw content, so this
    /// header followed by the base is the same history. The tables (cut
    /// from a dictionary trained by `zstd --train`) are never used: a frame
    /// compressed against raw content has no tables to repeat, so its first
    /// block always describes its own, and the repeat offsets are exactly
    /// the ones a raw-content dictionary starts with. Whatever the tables,
    /// a wrong result would fail the re-hash, never return wrong content.
    const DICT_HEADER: [u8; 112] = [
        0x37, 0xa4, 0x30, 0xec, 0x01, 0x00, 0x00, 0x00, 0x14, 0x10, 0xe8, 0x0a, 0xd3, 0x01, 0x00, 0x00, //
        0x00, 0x00, 0xc0, 0x8a, 0x29, 0x49, 0x99, 0x52, 0xda, 0x03, 0x94, 0x42, 0x48, 0xf3, 0x03, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x43, 0x82, 0x16, 0xe5, 0x00, 0x00, 0x04, 0x60, 0x00, 0x00, 0x00, 0xc0, //
        0x00, 0x00, 0xc0, 0x00, 0x80, 0x80, 0x01, 0x22, 0x49, 0x07, 0x00, 0x30, 0x00, 0x00, 0x06, 0x00, //
        0x00, 0x00, 0x00, 0x10, 0x24, 0x71, 0x09, 0x00, 0x00, 0x00, 0x60, 0x01, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0xe4, 0x8b, 0x15, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, //
    ];
    const DICT_ID: u32 = 1;

    /// Largest window accepted: what the writer may use for a delta
    /// (`MAX_DELTA_WINDOW_LOG`), and libzstd's default limit.
    const MAX_WINDOW: u64 = 1 << super::MAX_DELTA_WINDOW_LOG;

    /// Decode one zstd frame of exactly `raw_len` bytes, optionally against
    /// `dict` as raw-content history. Same checks as the libzstd path: the
    /// frame must declare `raw_len`, and decoding stops as soon as the
    /// output would exceed it.
    #[cfg_attr(feature = "zstd", allow(dead_code))]
    pub(crate) fn decompress(data: &[u8], raw_len: u64, dict: Option<&[u8]>) -> std::result::Result<Vec<u8>, String> {
        let limit = usize::try_from(raw_len).map_err(|_| "object too large for this platform".to_string())?;
        let mut out = Vec::with_capacity(limit.min(super::BULK_LIMIT as usize));
        stream(data, raw_len, dict, &mut |chunk| out.extend_from_slice(chunk))?;
        Ok(out)
    }

    /// Stream the frame's content to `sink` in chunks of about
    /// [`super::STREAM_CHUNK`] bytes: exactly `raw_len` bytes, or an error
    /// as soon as it would be more (or ends short). The decoder holds at
    /// most its window ([`MAX_WINDOW`]) besides.
    pub(crate) fn stream(data: &[u8], raw_len: u64, dict: Option<&[u8]>, sink: &mut dyn FnMut(&[u8])) -> std::result::Result<(), String> {
        let mut d = FrameDecoder::new();
        d.set_max_window_size(MAX_WINDOW);
        if let Some(base) = dict {
            let mut formatted = Vec::with_capacity(DICT_HEADER.len() + base.len());
            formatted.extend_from_slice(&DICT_HEADER);
            formatted.extend_from_slice(base);
            let dict = Dictionary::decode_dict(&formatted).map_err(|e| e.to_string())?;
            d.add_dict(dict).map_err(|e| e.to_string())?;
        }
        let mut src = data;
        d.init(&mut src).map_err(|e| e.to_string())?;
        // A frame always records its size (the writer compresses whole
        // buffers); one that does not, or records another, is not ours.
        if d.content_size() != raw_len || (raw_len == 0 && !frame_declares_size(data)) {
            return Err("compressed frame does not match the recorded length".into());
        }
        if dict.is_some() {
            d.force_dict(DICT_ID).map_err(|e| e.to_string())?;
        }
        let too_long = || "decompressed length does not match the recorded length".to_string();
        let mut total = 0u64;
        let mut take = |chunk: Option<Vec<u8>>| -> std::result::Result<(), String> {
            if let Some(chunk) = chunk {
                total += chunk.len() as u64;
                if total > raw_len {
                    return Err(too_long());
                }
                sink(&chunk);
            }
            Ok(())
        };
        loop {
            d.decode_blocks(&mut src, BlockDecodingStrategy::UptoBytes(super::STREAM_CHUNK)).map_err(|e| e.to_string())?;
            take(d.collect())?;
            if d.is_finished() {
                break;
            }
        }
        take(d.collect())?;
        if total != raw_len {
            return Err(too_long());
        }
        Ok(())
    }

    /// Does the frame header carry a content size? (`content_size()` is 0
    /// both for "empty" and for "not recorded".)
    fn frame_declares_size(data: &[u8]) -> bool {
        // Frame_Header_Descriptor: Frame_Content_Size_flag (bits 7-6) and
        // Single_Segment_flag (bit 5); either one means a size is present.
        data.get(4).is_some_and(|fhd| fhd >> 6 != 0 || fhd & 0x20 != 0)
    }
}

// ---- writing ----------------------------------------------------------------

/// Above this much base plus object, a delta is compressed with the base
/// as a *prefix* and long-distance matching (see [`delta_compress`]).
#[cfg(feature = "zstd")]
const LONG_DELTA: usize = 2 << 20;

/// Largest zstd window a delta may use: 2^27 (128 MiB) is the most every
/// zstd decoder accepts by default, so packs stay readable by every vl.
#[cfg_attr(not(feature = "zstd"), allow(dead_code))]
const MAX_DELTA_WINDOW_LOG: u32 = 27;

/// zstd-compress `raw` against `base` (a delta entry; read back with
/// `base` as a raw-content dictionary).
///
/// A dictionary is only indexed as far as the compression level's tables
/// reach: at the default level its matches stop a few MiB back, so for a
/// large file a small edit compressed no better than the file alone
/// (BUG-290). For large inputs the base is therefore referenced as a prefix
/// (what `zstd --patch-from` does): the window is sized to cover base and
/// object (up to [`MAX_DELTA_WINDOW_LOG`]) and long-distance matching finds
/// matches anywhere in it. Decoding is unchanged: a prefix and a raw-content
/// dictionary are the same history to the decoder. Memory stays bounded by
/// the window cap: the long-distance table adds a few MiB per delta being
/// compressed, on top of the base and object already in memory.
#[cfg(feature = "zstd")]
fn delta_compress(level: i32, base: &[u8], raw: &[u8]) -> std::io::Result<Vec<u8>> {
    if base.len() + raw.len() <= LONG_DELTA {
        return zstd::bulk::Compressor::with_dictionary(level, base)?.compress(raw);
    }
    use zstd::zstd_safe::CParameter;
    let zerr = |code: usize| std::io::Error::other(zstd::zstd_safe::get_error_name(code));
    let total = base.len() + raw.len();
    let window_log = (usize::BITS - total.leading_zeros()).clamp(10, MAX_DELTA_WINDOW_LOG);
    let mut c = zstd::bulk::Compressor::new(level)?;
    c.set_parameter(CParameter::WindowLog(window_log))?;
    c.set_parameter(CParameter::EnableLongDistanceMatching(true))?;
    c.context_mut().ref_prefix(base).map_err(zerr)?;
    c.compress(raw)
}

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
///
/// Without the `zstd` feature (WASM builds) every entry is *stored* (kind
/// 0): packs are then larger, but the same format, readable by every vl.
pub struct PackBuilder {
    #[cfg_attr(not(feature = "zstd"), allow(dead_code))]
    level: i32,
    max_depth: u32,
    buf: Vec<u8>,
    entries: Vec<(ObjectId, u64, u64)>,
    depth: HashMap<ObjectId, u32>,
    #[cfg(feature = "zstd")]
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
            #[cfg(feature = "zstd")]
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
        let (kind, data, base_id, depth) = self.encode(raw, base)?;
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

    /// The entry for `raw`: (kind, data, delta base, delta depth).
    #[cfg(feature = "zstd")]
    fn encode(&mut self, raw: &[u8], base: Option<(&ObjectId, &[u8])>) -> Result<(EntryKind, Vec<u8>, Option<ObjectId>, u32)> {
        let zerr = |e: std::io::Error| VeilError::repo(format!("zstd: {e}"));
        if Object::sealed_scope(raw).is_some() {
            return Ok((EntryKind::Stored, raw.to_vec(), None, 0));
        }
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
                let delta = delta_compress(self.level, braw, raw).map_err(zerr)?;
                // Worth a dependency only if clearly smaller.
                if delta.len() + 32 + delta.len() / 8 < best.1.len() {
                    best = (EntryKind::Delta, delta, Some(*bid), bdepth.unwrap() + 1);
                }
            }
        }
        Ok(best)
    }

    /// Without zstd: every entry stored as it is.
    #[cfg(not(feature = "zstd"))]
    fn encode(&mut self, raw: &[u8], _base: Option<(&ObjectId, &[u8])>) -> Result<(EntryKind, Vec<u8>, Option<ObjectId>, u32)> {
        Ok((EntryKind::Stored, raw.to_vec(), None, 0))
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
    use crate::{object::Object, vfs::MemoryBackend};

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

    /// BUG-290: a small edit of a large file is stored as a small delta,
    /// and reads back.
    #[cfg(feature = "zstd")]
    #[test]
    fn large_deltas_are_small() {
        let fs = MemoryBackend::new();
        let dir = VPath::new("p").unwrap();
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let base: Vec<u8> = (0..6 << 20)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect();
        let mut edited = base.clone();
        for b in &mut edited[1000..1064] {
            *b ^= 0x5a;
        }
        let (b_id, b_raw) = blob(&base);
        let (e_id, e_raw) = blob(&edited);
        let mut pb = PackBuilder::new(DEFAULT_LEVEL).unwrap();
        pb.add(b_id, &b_raw, None).unwrap();
        pb.add(e_id, &e_raw, Some((&b_id, &b_raw))).unwrap();
        let (name, stats) = pb.finish(&fs, &dir).unwrap().unwrap();
        assert_eq!(stats.deltas, 1);
        assert!(stats.pack_bytes < (6 << 20) + (64 << 10), "{stats:?}");
        let pack = Pack::open(&fs, &dir, &name).unwrap();
        let cache = LruCache::new(1 << 20);
        assert_eq!(pack.get(&fs, &e_id, &cache).unwrap().unwrap(), e_raw);
        pack.verify(&fs).unwrap();
    }

    #[cfg(feature = "zstd")]
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

    /// Without zstd, a pack holds stored entries only, which every vl reads.
    #[cfg(not(feature = "zstd"))]
    #[test]
    fn without_zstd_every_entry_is_stored() {
        let fs = MemoryBackend::new();
        let dir = VPath::new("p").unwrap();
        let text: Vec<u8> = (0..4000).flat_map(|i| format!("line {i}\n").into_bytes()).collect();
        let (b_id, b_raw) = blob(&text);
        let (e_id, e_raw) = blob(&[&text[..], b"more\n"].concat());
        let mut pb = PackBuilder::new(DEFAULT_LEVEL).unwrap();
        pb.add(b_id, &b_raw, None).unwrap();
        pb.add(e_id, &e_raw, Some((&b_id, &b_raw))).unwrap();
        let (name, stats) = pb.finish(&fs, &dir).unwrap().unwrap();
        assert_eq!((stats.stored, stats.compressed, stats.deltas), (2, 0, 0));
        let pack = Pack::open(&fs, &dir, &name).unwrap();
        let cache = LruCache::new(1 << 20);
        assert_eq!(pack.get(&fs, &e_id, &cache).unwrap().unwrap(), e_raw);
        pack.verify(&fs).unwrap();
    }

    /// The pure-Rust decoder (the WASM build's) against what the zstd C
    /// library writes: plain frames at several levels, dictionary deltas
    /// and prefix deltas with long-distance matching (BUG-290), and every
    /// kind of damage.
    #[cfg(all(feature = "zstd", feature = "ruzstd"))]
    mod pure_decoder {
        use proptest::prelude::*;

        use super::super::{delta_compress, pure, DEFAULT_LEVEL, LONG_DELTA};

        fn noise(n: usize, mut x: u64) -> Vec<u8> {
            (0..n)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    (x >> 24) as u8
                })
                .collect()
        }

        fn text(n: usize) -> Vec<u8> {
            (0..).flat_map(|i| format!("line {i} of the text\n").into_bytes()).take(n).collect()
        }

        fn plain(level: i32, raw: &[u8]) -> Vec<u8> {
            zstd::bulk::Compressor::new(level).unwrap().compress(raw).unwrap()
        }

        #[test]
        fn plain_frames_decode() {
            for raw in [Vec::new(), b"x".to_vec(), text(1000), text(300_000), noise(100_000, 7), text(3 << 20)] {
                for level in [1, DEFAULT_LEVEL, 19] {
                    let z = plain(level, &raw);
                    assert_eq!(pure::decompress(&z, raw.len() as u64, None).unwrap(), raw, "level {level}, {} bytes", raw.len());
                }
            }
        }

        #[test]
        fn dictionary_and_prefix_deltas_decode() {
            // Below LONG_DELTA: the base as a raw-content dictionary.
            let base = text(200_000);
            let mut edited = base.clone();
            edited.splice(5000..5000, b"an inserted line\n".iter().copied());
            edited.truncate(150_000);
            assert!(base.len() + edited.len() <= LONG_DELTA);
            let d = delta_compress(DEFAULT_LEVEL, &base, &edited).unwrap();
            assert!(d.len() < 2000, "a real delta: {}", d.len());
            assert_eq!(pure::decompress(&d, edited.len() as u64, Some(&base)).unwrap(), edited);

            // Above: the base as a prefix, long-distance matching, a window
            // covering both.
            let base = noise(6 << 20, 0x9e37_79b9_7f4a_7c15);
            let mut edited = base.clone();
            for b in &mut edited[1000..1064] {
                *b ^= 0x5a;
            }
            edited.extend_from_slice(&noise(10_000, 3));
            let d = delta_compress(DEFAULT_LEVEL, &base, &edited).unwrap();
            assert!(d.len() < 64 << 10, "a real delta: {}", d.len());
            assert_eq!(pure::decompress(&d, edited.len() as u64, Some(&base)).unwrap(), edited);
        }

        #[test]
        fn damage_is_an_error() {
            let raw = text(50_000);
            let z = plain(DEFAULT_LEVEL, &raw);
            let n = raw.len() as u64;
            assert!(pure::decompress(&z, n + 1, None).is_err(), "wrong recorded length");
            assert!(pure::decompress(&z, n - 1, None).is_err(), "wrong recorded length");
            assert!(pure::decompress(&z[..z.len() / 2], n, None).is_err(), "truncated");
            assert!(pure::decompress(b"not zstd at all", n, None).is_err());
            assert!(pure::decompress(&[], 0, None).is_err());
            // A delta without (or with the wrong) base never yields the content.
            let base = text(100_000);
            let d = delta_compress(DEFAULT_LEVEL, &base, &raw).unwrap();
            assert!(pure::decompress(&d, n, None).map_or(true, |out| out != raw));
            assert!(pure::decompress(&d, n, Some(&noise(100_000, 9))).map_or(true, |out| out != raw));
        }

        /// A zstd frame declaring `size` bytes of RLE blocks (4 bytes per
        /// 128 KiB), producing `size + extra`.
        fn rle_frame(size: u64, extra: u64) -> Vec<u8> {
            let mut f = vec![0x28, 0xb5, 0x2f, 0xfd, 0xc0, 7 << 3];
            f.extend_from_slice(&size.to_le_bytes());
            let mut left = size + extra;
            while left > 0 {
                let n = left.min(128 << 10);
                left -= n;
                let header = (left == 0) as u32 | (1 << 1) | ((n as u32) << 3);
                f.extend_from_slice(&header.to_le_bytes()[..3]);
                f.push(b'A');
            }
            f
        }

        /// BUG-490 in the pure-Rust decoder: a bomb streams in bounded
        /// chunks, stops at the declared size, and one that is not its
        /// object is refused by the hash pass, before anything is kept.
        #[test]
        fn bombs_stream_in_bounded_chunks_and_stop_at_the_declared_size() {
            let size = 96u64 << 20;
            let (mut total, mut largest) = (0u64, 0usize);
            pure::stream(&rle_frame(size, 0), size, None, &mut |c| {
                total += c.len() as u64;
                largest = largest.max(c.len());
            })
            .unwrap();
            assert_eq!(total, size);
            assert!(largest <= 2 * crate::pack::STREAM_CHUNK, "{largest}");
            let mut seen = 0u64;
            assert!(pure::stream(&rle_frame(size, 32 << 20), size, None, &mut |c| seen += c.len() as u64).is_err());
            assert!(seen <= size);
            let err = crate::pack::decompress(&rle_frame(size, 0), size, None, &crate::id::ObjectId([7; 32])).unwrap_err();
            assert!(err.contains("does not match its id"), "{err}");
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            /// Both decoders agree on every delta the writer makes.
            #[test]
            fn deltas_agree(seed in any::<u64>(), len in 64usize..20_000, edits in prop::collection::vec((any::<u16>(), any::<u8>()), 0..20)) {
                let base = if seed % 2 == 0 { text(len) } else { noise(len, seed | 1) };
                let mut edited = base.clone();
                for (at, b) in edits {
                    let at = at as usize % edited.len();
                    edited.insert(at, b);
                }
                let d = delta_compress(DEFAULT_LEVEL, &base, &edited).unwrap();
                prop_assert_eq!(pure::decompress(&d, edited.len() as u64, Some(&base)).unwrap(), edited.clone());
                let z = plain(DEFAULT_LEVEL, &edited);
                prop_assert_eq!(pure::decompress(&z, edited.len() as u64, None).unwrap(), edited);
            }

            /// Damaged frames are errors or (caught by the re-hash) other
            /// bytes, never a panic or a runaway allocation.
            #[test]
            fn damaged_frames_never_panic(seed in any::<u64>(), flips in prop::collection::vec((any::<u32>(), any::<u8>()), 1..8), declared in prop::option::of(0u64..1 << 40)) {
                let raw = if seed % 2 == 0 { text(5000) } else { noise(5000, seed | 1) };
                let base = text(3000);
                let mut z = if seed % 3 == 0 { delta_compress(DEFAULT_LEVEL, &base, &raw).unwrap() } else { plain(DEFAULT_LEVEL, &raw) };
                for (at, x) in flips {
                    let i = at as usize % z.len();
                    z[i] ^= x | 1;
                }
                let n = declared.unwrap_or(raw.len() as u64);
                let _ = pure::decompress(&z, n, (seed % 3 == 0).then_some(&base[..]));
            }

            #[test]
            fn random_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..512), n in 0u64..100_000) {
                let mut framed = vec![0x28, 0xb5, 0x2f, 0xfd];
                framed.extend_from_slice(&data);
                let _ = pure::decompress(&framed, n, None);
                let _ = pure::decompress(&framed, n, Some(b"some base bytes"));
                let _ = pure::decompress(&data, n, None);
            }
        }
    }
}

