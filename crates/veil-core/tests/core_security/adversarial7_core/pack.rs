//! BUG-490: decompression bombs in a pack served by a hostile remote.
//!
//! A pack entry records the size of its object (`raw_len`) and a zstd
//! frame. A few kilobytes of RLE blocks decode to gigabytes, so a remote
//! (or a damaged pack) can make a reader allocate whatever an entry
//! declares before the content is checked against its id. These tests
//! measure the memory a read allocates on its own thread (a counting
//! allocator), with small sizes, so they stay safe even where the reader
//! is unbounded: an unbounded reader fails the assertion after allocating
//! 256 MiB, never the machine.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    time::{Duration, Instant},
};

use veil_core::{
    cache::LruCache,
    id::ObjectId,
    pack::{index_file, pack_file, Pack, PackBuilder, PackIndex, MAX_PACK_ENTRIES},
    vfs::{MemoryBackend, StorageBackend},
    vpath::VPath,
};

// ---- a per-thread peak of live allocations -----------------------------------------

struct Counting;

thread_local! {
    static LIVE: Cell<usize> = const { Cell::new(0) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
}

fn add(n: usize) {
    let _ = LIVE.try_with(|l| {
        let now = l.get() + n;
        l.set(now);
        let _ = PEAK.try_with(|p| p.set(p.get().max(now)));
    });
}

fn sub(n: usize) {
    let _ = LIVE.try_with(|l| l.set(l.get().saturating_sub(n)));
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        add(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        add(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        sub(layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        add(new_size);
        sub(layout.size());
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// `f`'s result and the most memory it held at once on this thread above
/// what was live when it started.
pub(crate) fn peak_of<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let start = LIVE.with(Cell::get);
    PEAK.with(|p| p.set(start));
    let out = f();
    (out, PEAK.with(Cell::get) - start)
}

const MIB: usize = 1 << 20;

/// Bytes live on this thread (the counting allocator's).
pub(crate) fn live() -> usize {
    LIVE.with(Cell::get)
}

// ---- hostile packs ---------------------------------------------------------------

/// A zstd frame declaring `size` bytes, made of RLE blocks (4 bytes per
/// 128 KiB of output): `size` bytes of `byte`, plus `extra` more.
fn rle_frame(size: u64, extra: u64, byte: u8) -> Vec<u8> {
    let mut f = vec![0x28, 0xb5, 0x2f, 0xfd];
    // Frame header: an 8-byte content size, a 128 KiB window.
    f.push(0xc0);
    f.push(7 << 3);
    f.extend_from_slice(&size.to_le_bytes());
    let mut left = size + extra;
    if left == 0 {
        // One empty raw block, last.
        f.extend_from_slice(&[1, 0, 0]);
        return f;
    }
    while left > 0 {
        let n = left.min(128 << 10);
        left -= n;
        let last = (left == 0) as u32;
        let header = last | (1 << 1) | ((n as u32) << 3);
        f.extend_from_slice(&header.to_le_bytes()[..3]);
        f.push(byte);
    }
    f
}

/// Write a pack of `entries` (`id`, kind, declared length, data) and its
/// index under `dir` of `mem`, laid out as `pack.rs` documents; its name.
fn write_pack(mem: &MemoryBackend, dir: &VPath, entries: &[(ObjectId, u8, u64, Vec<u8>)]) -> String {
    let mut pack = b"VEILPAK1".to_vec();
    pack.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    let mut at = Vec::new();
    for (id, kind, raw_len, data) in entries {
        let start = pack.len() as u64;
        pack.push(*kind);
        pack.extend_from_slice(&raw_len.to_le_bytes());
        pack.extend_from_slice(data);
        at.push((*id, start, pack.len() as u64 - start));
    }
    let sum = *blake3::hash(&pack).as_bytes();
    pack.extend_from_slice(&sum);
    at.sort_by_key(|e| e.0);
    let mut idx = b"VEILIDX1".to_vec();
    idx.extend_from_slice(&(at.len() as u32).to_le_bytes());
    for b in 0..256usize {
        let n = at.iter().filter(|e| e.0 .0[0] as usize <= b).count() as u32;
        idx.extend_from_slice(&n.to_le_bytes());
    }
    for e in &at {
        idx.extend_from_slice(&e.0 .0);
    }
    for e in &at {
        idx.extend_from_slice(&e.1.to_le_bytes());
    }
    for e in &at {
        idx.extend_from_slice(&e.2.to_le_bytes());
    }
    idx.extend_from_slice(&sum);
    let isum = *blake3::hash(&idx).as_bytes();
    idx.extend_from_slice(&isum);
    let name = hex::encode(sum);
    mem.write(&pack_file(dir, &name), &pack).unwrap();
    mem.write(&index_file(dir, &name), &idx).unwrap();
    name
}

fn dir() -> VPath {
    VPath::new("p").unwrap()
}

/// A forged id: no content hashes to it.
fn forged() -> ObjectId {
    ObjectId([7; 32])
}

/// BUG-490: an entry whose frame inflates to 256 MiB of something that is
/// not its object is refused without holding it: the content is hashed as
/// it streams, and only kept once it matched. (Unbounded, the reader
/// allocated the whole declared size first, 8 GiB from a 256 KiB frame.)
#[test]
fn a_pack_entry_that_inflates_to_something_else_costs_no_memory() {
    let mem = MemoryBackend::new();
    let size = 256 * MIB as u64;
    let name = write_pack(&mem, &dir(), &[(forged(), 1, size, rle_frame(size, 0, b'A'))]);
    let pack = Pack::open(&mem, &dir(), &name).unwrap();
    let bases = LruCache::new(64 << 20);
    let (got, peak) = peak_of(|| pack.get(&mem, &forged(), &bases));
    let err = got.expect_err("a forged object is never returned");
    assert!(matches!(err, veil_core::error::VeilError::Corrupt(..)), "{err}");
    assert!(peak < 16 * MIB, "reading the entry held {} MiB", peak / MIB);
}

/// BUG-490: an entry declaring more than an object may have
/// (`VEIL_MAX_OBJECT`, 4 GiB by default; here an explicit 1 MiB) is
/// refused before a byte is decoded, whatever its frame holds. The frame
/// here really inflates to 8 GiB.
#[test]
fn a_pack_entry_declaring_more_than_the_limit_is_refused_before_decoding() {
    let mem = MemoryBackend::new();
    let huge = 8u64 << 30;
    let small = 2 * MIB as u64;
    let name = write_pack(&mem, &dir(), &[(forged(), 1, huge, rle_frame(huge, 0, b'A')), (ObjectId([9; 32]), 1, small, rle_frame(small, 0, b'B'))]);
    let bases = LruCache::new(64 << 20);
    // The default limit.
    let pack = Pack::open(&mem, &dir(), &name).unwrap();
    let t = Instant::now();
    let (got, peak) = peak_of(|| pack.get(&mem, &forged(), &bases));
    let err = got.expect_err("8 GiB is over the default limit").to_string();
    assert!(err.contains("VEIL_MAX_OBJECT"), "{err}");
    assert!(peak < MIB, "held {peak} bytes");
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    // An explicit small limit.
    let pack = Pack::open(&mem, &dir(), &name).unwrap().with_max_object(MIB as u64);
    let (got, peak) = peak_of(|| pack.get(&mem, &ObjectId([9; 32]), &bases));
    assert!(got.expect_err("2 MiB is over a 1 MiB limit").to_string().contains("VEIL_MAX_OBJECT"));
    assert!(peak < MIB, "held {peak} bytes");
}

/// BUG-490: a frame that produces more than its entry declares (a second
/// frame, or blocks past the declared size) is cut off at the declared
/// size, for small (one buffer) and large (streamed) entries.
#[test]
fn a_frame_never_produces_more_than_its_entry_declares() {
    let mem = MemoryBackend::new();
    for size in [64 * 1024u64, 80 * MIB as u64] {
        let mut two_frames = rle_frame(size, 0, b'A');
        two_frames.extend_from_slice(&rle_frame(64 * MIB as u64, 0, b'A'));
        let entries = [(forged(), 1, size, rle_frame(size, 64 * MIB as u64, b'A')), (ObjectId([9; 32]), 1, size, two_frames)];
        let name = write_pack(&mem, &dir(), &entries);
        let pack = Pack::open(&mem, &dir(), &name).unwrap();
        let bases = LruCache::new(64 << 20);
        for (id, ..) in &entries {
            let (got, peak) = peak_of(|| pack.get(&mem, id, &bases));
            assert!(got.is_err());
            assert!(peak < (size as usize).min(16 * MIB) + 2 * MIB, "{size}: held {} MiB", peak / MIB);
        }
    }
}

/// Control: real objects past the streaming threshold (64 MiB) and below
/// it read back, through the hash pass and into memory, as do deltas.
#[test]
fn large_honest_objects_still_read_back() {
    let mem = MemoryBackend::new();
    let big: Vec<u8> = (0..70 * MIB).map(|i| (i / 4096) as u8).collect();
    let mut edited = big.clone();
    edited[35 * MIB..35 * MIB + 10].copy_from_slice(b"0123456789");
    let small = b"a small object".repeat(100);
    let ids = [ObjectId::hash(&big), ObjectId::hash(&edited), ObjectId::hash(&small)];
    let mut b = PackBuilder::new(3).unwrap();
    b.add(ids[0], &big, None).unwrap();
    b.add(ids[1], &edited, Some((&ids[0], &big))).unwrap();
    b.add(ids[2], &small, None).unwrap();
    let (name, _) = b.finish(&mem, &dir()).unwrap().unwrap();
    let pack = Pack::open(&mem, &dir(), &name).unwrap();
    let bases = LruCache::new(64 << 20);
    assert!(pack.get(&mem, &ids[0], &bases).unwrap().unwrap() == big);
    assert!(pack.get(&mem, &ids[1], &bases).unwrap().unwrap() == edited);
    assert_eq!(pack.get(&mem, &ids[2], &bases).unwrap().unwrap(), small);
    // Under a limit below their size, they are refused instead.
    let pack = pack.with_max_object(MIB as u64);
    assert!(pack.get(&mem, &ids[0], &bases).is_err());
    assert_eq!(pack.get(&mem, &ids[2], &bases).unwrap().unwrap(), small);
}

/// BUG-490: an index claiming more entries than a pack may hold is
/// refused before anything is allocated for them.
#[test]
fn an_index_with_too_many_entries_is_refused() {
    let mut idx = b"VEILIDX1".to_vec();
    idx.extend_from_slice(&(MAX_PACK_ENTRIES as u32 + 1).to_le_bytes());
    idx.resize(8 + 4 + 256 * 4 + 64, 0);
    let err = PackIndex::decode(&idx).unwrap_err().to_string();
    assert!(err.contains("more than a pack may hold"), "{err}");
}
