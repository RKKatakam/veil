//! Sync benchmark over local SFTP (ignored by default). Run with:
//!
//! ```sh
//! cargo test --release -p veil-core --test core_bench -- --ignored --nocapture sftp_bench::
//! ```
//!
//! A repository of 3,000 files and 300 snapshots is pushed to, and cloned
//! from, a local OpenSSH `sftp-server`, with an artificial one-way delay in
//! both directions. "full" is the object-by-object walk (`--full`, the
//! pre-pack behaviour); "incremental" is the default. `VEIL_BENCH_RTTS`
//! (milliseconds, comma-separated) picks the round-trip times;
//! `VEIL_BENCH_FULL_MAX_RTT` the largest one the slow full walk runs at.

use crate::sftp_support;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use sftp_support::{connect_with, Shim};
use veil_core::{
    remote::{self, SyncOptions},
    DiskBackend, Identity, ObjectId, Repo, StorageBackend,
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

fn build(repo: &mut Repo) -> (ObjectId, Vec<usize>, Rng) {
    let mut rng = Rng(42);
    let mut revs = vec![0usize; FILES];
    let ws = repo.ephemeral_workspace(repo.root_id()).unwrap();
    for (i, rev) in revs.iter().enumerate() {
        ws.write(&path(i), source_file(i, *rev)).unwrap();
    }
    let (mut head, _) = repo.commit_ephemeral(&ws, "initial import").unwrap();
    drop(ws);
    for c in 0..COMMITS - 1 {
        head = commit(repo, head, &mut revs, &mut rng, c);
    }
    repo.set_tag("main", head, None, false).unwrap();
    (head, revs, rng)
}

fn path(i: usize) -> String {
    format!("src/d{}/m{i:04}.rs", i % 40)
}

fn commit(repo: &mut Repo, head: ObjectId, revs: &mut [usize], rng: &mut Rng, c: usize) -> ObjectId {
    let ws = repo.ephemeral_workspace(head).unwrap();
    for _ in 0..EDITS_PER_COMMIT {
        let i = if rng.below(4) == 0 { 7 } else { rng.below(FILES) };
        revs[i] += 1;
        ws.write(&path(i), source_file(i, revs[i])).unwrap();
    }
    repo.commit_ephemeral(&ws, &format!("commit {c}")).unwrap().0
}

struct Run {
    secs: f64,
    requests: u64,
    sent: u64,
    received: u64,
    objects: usize,
}

fn row(what: &str, rtt: Duration, r: &Run) {
    println!(
        "| {what:<34} | {:>4} ms | {:>8.2} s | {:>8} | {:>7.1} MiB | {:>7.1} MiB | {:>7} |",
        rtt.as_millis(),
        r.secs,
        r.requests,
        r.sent as f64 / (1 << 20) as f64,
        r.received as f64 / (1 << 20) as f64,
        r.objects
    );
}

fn timed(
    server: &std::path::Path,
    dir: &std::path::Path,
    rtt: Duration,
    f: impl FnOnce(Arc<dyn StorageBackend>) -> remote::SyncReport,
) -> Run {
    let shim = Shim {
        delay: rtt / 2,
        cut_after: None,
    };
    let (b, _child) = connect_with(server, dir, shim);
    let b = Arc::new(b);
    let t = Instant::now();
    let rep = f(b.clone());
    let secs = t.elapsed().as_secs_f64();
    let s = b.stats();
    Run {
        secs,
        requests: s.requests,
        sent: s.bytes_sent,
        received: s.bytes_received,
        objects: rep.objects_copied,
    }
}

#[test]
#[ignore = "benchmark: run with --ignored --nocapture"]
fn sftp_sync_benchmark() {
    let Some(server) = sftp_support::server() else { return };
    let rtts: Vec<Duration> = std::env::var("VEIL_BENCH_RTTS")
        .unwrap_or_else(|_| "0,2,50".into())
        .split(',')
        .map(|s| Duration::from_millis(s.trim().parse().unwrap()))
        .collect();
    let full_max = Duration::from_millis(
        std::env::var("VEIL_BENCH_FULL_MAX_RTT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2),
    );

    let tmp = tempfile::tempdir().unwrap();
    let local_dir = tmp.path().join("local");
    std::fs::create_dir_all(&local_dir).unwrap();
    let id = Identity::generate("bench");
    let mut repo = Repo::init(Arc::new(DiskBackend::new(&local_dir)), Some(id.clone()), "bench").unwrap();
    let t = Instant::now();
    let (head, mut revs, mut rng) = build(&mut repo);
    let objects = repo.store().list_objects().unwrap().len();
    println!(
        "\nBuilt {FILES} files, {COMMITS} snapshots, {objects} objects in {:.1} s\n",
        t.elapsed().as_secs_f64()
    );
    println!("| operation                          |     RTT |       time | requests |        sent |    received | objects |");
    println!("|------------------------------------|---------|------------|----------|-------------|-------------|---------|");

    let full = SyncOptions { full: true };
    let inc = SyncOptions::default();
    let mut n = 0;
    for &rtt in &rtts {
        for (label, opts) in [("full", &full), ("incremental", &inc)] {
            if opts.full && rtt > full_max {
                continue;
            }
            n += 1;
            let remote_dir = tmp.path().join(format!("remote{n}"));
            let r = timed(&server, &remote_dir, rtt, |b| {
                remote::push_with(&mut repo, b, false, &[], false, opts).unwrap()
            });
            row(&format!("push, {label} (initial)"), rtt, &r);

            let clone_dir = tmp.path().join(format!("clone{n}"));
            std::fs::create_dir_all(&clone_dir).unwrap();
            let mut clone =
                Repo::init_for_clone(Arc::new(DiskBackend::new(&clone_dir)), Some(id.clone()), "c").unwrap();
            let r = timed(&server, &remote_dir, rtt, |b| {
                remote::pull_with(&mut clone, "origin", b, opts).unwrap()
            });
            row(&format!("clone, {label}"), rtt, &r);
            assert_eq!(clone.view().tags["main"].target, repo.view().tags["main"].target);

            let r = timed(&server, &remote_dir, rtt, |b| {
                remote::push_with(&mut repo, b, false, &[], false, opts).unwrap()
            });
            row(&format!("push, {label} (up to date)"), rtt, &r);

            let tip = repo.view().tags["main"].target;
            let next = commit(&mut repo, tip, &mut revs, &mut rng, 1000 + n);
            repo.set_tag("main", next, None, false).unwrap();
            let r = timed(&server, &remote_dir, rtt, |b| {
                remote::push_with(&mut repo, b, false, &[], false, opts).unwrap()
            });
            row(&format!("push, {label} (1 new snapshot)"), rtt, &r);
            let r = timed(&server, &remote_dir, rtt, |b| {
                remote::pull_with(&mut clone, "origin", b, opts).unwrap()
            });
            row(&format!("pull, {label} (1 new snapshot)"), rtt, &r);
            assert_eq!(clone.view().tags["main"].target, next);
        }
    }
    let _ = head;
}
