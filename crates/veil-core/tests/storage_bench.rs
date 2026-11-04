//! Storage benchmark (ignored by default). Run with:
//!
//! ```sh
//! cargo test --release -p veil-core --test storage_bench -- --ignored --nocapture
//! ```
//!
//! Builds an on-disk repository with a few thousand files and a few hundred
//! snapshots, then measures disk usage and object read times before and
//! after `gc`.

use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use veil_core::{
    gc::{gc, GcOptions},
    tree::walk_files,
    DiskBackend, Identity, ObjectId, Repo,
};

const FILES: usize = 3000;
const COMMITS: usize = 300;
const EDITS_PER_COMMIT: usize = 8;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn source_file(i: usize, rev: usize) -> String {
    let mut s = format!("// module {i}\nuse crate::prelude::*;\n\n");
    for f in 0..(20 + i % 40) {
        s.push_str(&format!(
            "pub fn function_{i}_{f}(x: u64) -> u64 {{\n    let y = x.wrapping_mul({});\n    y ^ (y >> {})\n}}\n\n",
            (i * 31 + f) % 997,
            f % 13 + 1
        ));
    }
    s.push_str(&format!("// revision {rev}\n"));
    s
}

fn disk_usage(dir: &Path) -> (u64, usize) {
    let mut bytes = 0;
    let mut files = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let m = e.metadata().unwrap();
            if m.is_dir() {
                stack.push(e.path());
            } else {
                bytes += m.len();
                files += 1;
            }
        }
    }
    (bytes, files)
}

struct ReadTimes {
    objects: usize,
    all_objects: Duration,
    checkout_files: usize,
    checkout: Duration,
    history_files: usize,
    history: Duration,
}

/// Measured with a freshly opened repository (cold in-process caches).
fn read_times(root: &Path, id: &Identity, head: ObjectId, all: &[ObjectId]) -> ReadTimes {
    let open = || Repo::open(Arc::new(DiskBackend::new(root)), Some(id.clone()), "bench").unwrap();
    let repo = open();
    let t = Instant::now();
    for oid in all {
        repo.store().get_raw(oid).unwrap();
    }
    let all_objects = t.elapsed();

    let repo = open();
    let t = Instant::now();
    let tree = repo.snapshot(&head).unwrap().tree;
    let files = walk_files(repo.store(), &tree).unwrap();
    for (_, e) in &files {
        repo.store().read_entry(e).unwrap();
    }
    let checkout = t.elapsed();

    // One file through the whole history (log -p style).
    let repo = open();
    let t = Instant::now();
    let mut n = 0;
    let mut cur = Some(head);
    while let Some(s) = cur {
        let snap = repo.snapshot(&s).unwrap();
        if let Some(e) = veil_core::tree::lookup(repo.store(), &snap.tree, &veil_core::VPath::new("src/d7/m0007.rs").unwrap()).unwrap() {
            repo.store().read_entry(&e).unwrap();
            n += 1;
        }
        cur = snap.parents.first().copied();
    }
    ReadTimes {
        objects: all.len(),
        all_objects,
        checkout_files: files.len(),
        checkout,
        history_files: n,
        history: t.elapsed(),
    }
}

fn mib(b: u64) -> f64 {
    b as f64 / (1024.0 * 1024.0)
}

fn print_times(label: &str, r: &ReadTimes) {
    println!(
        "  {label:<8} read all {} objects: {:>8.1} ms ({:.2} µs/object) | checkout {} files: {:>7.1} ms | 1 file x {} revisions: {:>6.1} ms",
        r.objects,
        r.all_objects.as_secs_f64() * 1e3,
        r.all_objects.as_secs_f64() * 1e6 / r.objects as f64,
        r.checkout_files,
        r.checkout.as_secs_f64() * 1e3,
        r.history_files,
        r.history.as_secs_f64() * 1e3,
    );
}

#[test]
#[ignore = "benchmark: run with --ignored --nocapture"]
fn storage_benchmark() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let backend = Arc::new(DiskBackend::new(root));
    let id = Identity::generate("bench");
    let mut repo = Repo::init(backend.clone(), Some(id.clone()), "bench").unwrap();
    let mut rng = Rng(42);
    let mut revs = vec![0usize; FILES];
    let path = |i: usize| format!("src/d{}/m{i:04}.rs", i % 40);

    let t = Instant::now();
    let ws = repo.ephemeral_workspace(repo.root_id()).unwrap();
    for (i, rev) in revs.iter().enumerate() {
        ws.write(&path(i), source_file(i, *rev)).unwrap();
    }
    let (mut head, _) = repo.commit_ephemeral(&ws, "initial import").unwrap();
    drop(ws);
    let mut abandoned = 0;
    for c in 0..COMMITS {
        let ws = repo.ephemeral_workspace(head).unwrap();
        for _ in 0..EDITS_PER_COMMIT {
            let i = if rng.below(4) == 0 { 7 } else { rng.below(FILES) };
            revs[i] += 1;
            ws.write(&path(i), source_file(i, revs[i])).unwrap();
        }
        let (s, _) = repo.commit_ephemeral(&ws, &format!("commit {c}")).unwrap();
        // Every tenth commit is a throwaway experiment that gets abandoned.
        if c % 10 == 9 {
            let ws = repo.ephemeral_workspace(s).unwrap();
            let noise: Vec<u8> = (0..20_000).map(|_| rng.next() as u8).collect();
            ws.write("experiment.bin", noise).unwrap();
            let (x, _) = repo.commit_ephemeral(&ws, "experiment").unwrap();
            repo.abandon(x).unwrap();
            abandoned += 1;
        }
        head = s;
    }
    repo.set_tag("main", head, None, false).unwrap();
    println!(
        "\nBuilt {FILES} files, {COMMITS} commits (+{abandoned} abandoned) in {:.1} s",
        t.elapsed().as_secs_f64()
    );

    let objects_dir = root.join(".veil/objects");
    let all_before = repo.store().list_objects().unwrap();
    let (bytes0, files0) = disk_usage(&objects_dir);
    let before = read_times(root, &id, head, &all_before);

    // 1. Pack only (keep the whole op log).
    let t = Instant::now();
    let r1 = gc(&mut repo, &GcOptions::default()).unwrap();
    let gc1 = t.elapsed();
    let (bytes1, files1) = disk_usage(&objects_dir);
    let all1 = repo.store().list_objects().unwrap();
    let packed = read_times(root, &id, head, &all1);

    // 2. Prune ops and delete garbage now.
    let t = Instant::now();
    let r2 = gc(
        &mut repo,
        &GcOptions {
            keep_ops: Some(Duration::ZERO),
            grace: Duration::ZERO,
            ..GcOptions::default()
        },
    )
    .unwrap();
    let gc2 = t.elapsed();
    let (bytes2, files2) = disk_usage(&objects_dir);
    let all2 = repo.store().list_objects().unwrap();
    let pruned = read_times(root, &id, head, &all2);

    // 3. Same, without deltas, for comparison.
    let r3 = gc(&mut repo, &GcOptions { deltas: false, ..GcOptions::default() }).unwrap();
    let (bytes3, _) = disk_usage(&objects_dir);
    let all3 = repo.store().list_objects().unwrap();
    let no_deltas = read_times(root, &id, head, &all3);

    println!("Disk usage of .veil/objects:");
    println!("  loose                    {:>8.2} MiB in {files0} files ({} objects)", mib(bytes0), all_before.len());
    println!(
        "  gc (pack, deltas)        {:>8.2} MiB in {files1} files  [{:.2} s; {} deltas, {} zstd, {} stored]",
        mib(bytes1),
        gc1.as_secs_f64(),
        r1.pack_stats.deltas,
        r1.pack_stats.compressed,
        r1.pack_stats.stored
    );
    println!(
        "  gc --keep-ops-days 0 --prune-now {:>8.2} MiB in {files2} files  [{:.2} s; {} ops pruned, {} objects deleted]",
        mib(bytes2),
        gc2.as_secs_f64(),
        r2.ops_pruned,
        r2.deleted
    );
    println!("  same, without deltas     {:>8.2} MiB ({} zstd)", mib(bytes3), r3.pack_stats.compressed);
    println!(
        "  canonical object bytes   {:>8.2} MiB (sum of uncompressed encodings)",
        mib(r1.pack_stats.raw_bytes)
    );
    println!("Read times (fresh process caches, warm OS page cache):");
    print_times("loose", &before);
    print_times("packed", &packed);
    print_times("pruned", &pruned);
    print_times("no-delta", &no_deltas);
}
