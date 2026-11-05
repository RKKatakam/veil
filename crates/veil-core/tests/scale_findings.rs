//! Reproductions of findings from the scale benchmark's baseline
//! (`docs/design/scale/BASELINE.md`, BUG-800 to BUG-809), each ignored
//! while its bug is open.
//!
//! The tests measure this process's RSS, so they never run at once (one
//! lock), and the stores they build are larger than every cache.

use std::sync::{Arc, Mutex};

/// Taken by every test here: another test's allocations would count.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

use veil_core::{
    remote::{self, SyncOptions},
    DiskBackend, Identity, Repo,
};

fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)?.parse().ok()))
        .unwrap_or(0)
}

/// Incompressible bytes, deterministic from `seed`.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut v = Vec::with_capacity(len + 8);
    while v.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.truncate(len);
    v
}

/// BUG-800: a store keeps every pack it has read often whole in memory.
/// `Pack::whole` slurps a pack of up to 256 MiB after 64 reads, and the
/// limit is per pack, so a reader that touches every pack (any history walk:
/// `pull`, `clone`, `gc`, `log`) ends up holding the whole store. At 1 GB the
/// baseline measured `clone` at 1.98 GB RSS and `pull` of one snapshot at
/// 950 MB.
#[test]
#[cfg(target_os = "linux")]
fn reading_every_pack_does_not_hold_the_whole_store_in_memory() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    const PACKS: usize = 4;
    const BLOBS: usize = 150;
    const BLOB: usize = 200 * 1024; // 150 × 200 KiB ≈ 30 MiB per pack
    let tmp = tempfile::tempdir().unwrap();
    let local_dir = tmp.path().join("local");
    let remote_dir = tmp.path().join("remote");
    std::fs::create_dir_all(&local_dir).unwrap();
    std::fs::create_dir_all(&remote_dir).unwrap();
    let id = Identity::generate("bench");
    let mut repo = Repo::init(Arc::new(DiskBackend::new(&local_dir)), Some(id.clone()), "bench").unwrap();
    let mut head = repo.root_id();
    // Each push lands as one pack on the remote.
    for p in 0..PACKS {
        let ws = repo.ephemeral_workspace(head).unwrap();
        for b in 0..BLOBS {
            ws.write(&format!("p{p}/b{b}.bin"), noise((p * BLOBS + b) as u64 + 1, BLOB)).unwrap();
        }
        head = repo.commit_ephemeral(&ws, &format!("pack {p}")).unwrap().0;
        repo.set_tag("main", head, None, false).unwrap();
        remote::push_with(&mut repo, Arc::new(DiskBackend::new(&remote_dir)), false, &[], false, &SyncOptions::default()).unwrap();
    }
    drop(repo);
    let packs = std::fs::read_dir(remote_dir.join(".veil/objects/pack"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".pack"))
        .count();
    assert!(packs >= PACKS, "expected one pack per push, found {packs}");

    let remote = Repo::open(Arc::new(DiskBackend::new(&remote_dir)), None, "reader").unwrap();
    let ids = remote.store().list_objects().unwrap();
    let before = rss_kib();
    let mut total = 0usize;
    for oid in &ids {
        total += remote.store().get_raw(oid).unwrap().len();
    }
    let grown_mib = rss_kib().saturating_sub(before) / 1024;
    let store_mib = (total / (1 << 20)) as u64;
    // Reading objects one at a time needs no more than a pack's worth of
    // buffers: holding the store (≈ 120 MiB here) is the bug.
    assert!(
        grown_mib < store_mib / 2,
        "reading {} objects ({store_mib} MiB in {packs} packs) grew RSS by {grown_mib} MiB",
        ids.len()
    );
}

/// The highest RSS (KiB) while `f` runs, sampled every few milliseconds.
#[cfg(target_os = "linux")]
fn peak_rss_kib<T>(f: impl FnOnce() -> T) -> (T, u64) {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    let (done, peak) = (AtomicBool::new(false), AtomicU64::new(rss_kib()));
    std::thread::scope(|s| {
        s.spawn(|| {
            while !done.load(Ordering::Relaxed) {
                peak.fetch_max(rss_kib(), Ordering::Relaxed);
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        });
        let out = f();
        peak.fetch_max(rss_kib(), Ordering::Relaxed);
        done.store(true, Ordering::Relaxed);
        (out, peak.load(Ordering::Relaxed))
    })
}

/// BUG-800, the write and transfer side: a clone (a pull into an empty
/// repository) of a store several times the caches' size neither
/// downloads the remote's packs into memory (they are spooled to disk)
/// nor builds the packs it writes there (they are streamed). The baseline
/// measured `vl clone` at 1.98 GB RSS for a 1 GB store, then 1.2 GB once
/// reads were bounded.
#[test]
#[cfg(target_os = "linux")]
fn a_clone_of_a_large_store_does_not_hold_it_in_memory() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    const PACKS: usize = 4;
    const BLOBS: usize = 250;
    const BLOB: usize = 200 * 1024; // 4 × 250 × 200 KiB ≈ 195 MiB
    let tmp = tempfile::tempdir().unwrap();
    let (local_dir, remote_dir, clone_dir) = (tmp.path().join("local"), tmp.path().join("remote"), tmp.path().join("clone"));
    for d in [&local_dir, &remote_dir, &clone_dir] {
        std::fs::create_dir_all(d).unwrap();
    }
    let id = Identity::generate("bench");
    let mut repo = Repo::init(Arc::new(DiskBackend::new(&local_dir)), Some(id.clone()), "bench").unwrap();
    let mut head = repo.root_id();
    for p in 0..PACKS {
        let ws = repo.ephemeral_workspace(head).unwrap();
        for b in 0..BLOBS {
            ws.write(&format!("p{p}/b{b}.bin"), noise((p * BLOBS + b) as u64 + 1, BLOB)).unwrap();
        }
        head = repo.commit_ephemeral(&ws, &format!("pack {p}")).unwrap().0;
        repo.set_tag("main", head, None, false).unwrap();
        remote::push_with(&mut repo, Arc::new(DiskBackend::new(&remote_dir)), false, &[], false, &SyncOptions::default()).unwrap();
    }
    drop(repo);
    let store_mib = (PACKS * BLOBS * BLOB) as u64 >> 20;

    let mut clone = Repo::init_for_clone(Arc::new(DiskBackend::new(&clone_dir)), Some(id), "bench").unwrap();
    let before = rss_kib();
    let (report, peak) = peak_rss_kib(|| remote::pull(&mut clone, "origin", Arc::new(DiskBackend::new(&remote_dir))).unwrap());
    let grown_mib = peak.saturating_sub(before) / 1024;
    assert!(report.packs_written >= 1, "{report:?}");
    assert_eq!(clone.view().tags["main"].target, head);
    // What may grow: the last versions kept as delta bases (64 MiB) and a
    // few MiB of buffers. Holding the store (≈ 195 MiB) is the bug.
    assert!(grown_mib < store_mib / 2, "cloning {store_mib} MiB in {PACKS} packs grew peak RSS by {grown_mib} MiB");
    assert!(!clone_dir.join(".veil/objects/incoming/pull").exists(), "the download spool is removed");
}
