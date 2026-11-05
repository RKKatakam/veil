//! gc beside lock-free transactions (BUG-811 and its class): no gc mode,
//! `--prune-now` included, deletes what a live transaction staged,
//! published or will reference. Each test pauses one transaction (a thread
//! named `recorder`) at a chosen point on a gating disk, runs gc with
//! `keep_ops: 0` and grace 0 on another thread, lets the transaction
//! finish, and checks the result is whole.

use crate::adversarial_support;
use crate::oplog_concurrency::{assert_fsck_clean, open};

use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Condvar, Mutex,
    },
    time::Duration,
};

use adversarial_support::*;
use veil_core::{
    gc::{gc, GcOptions, GcReport},
    oplog::{Tag, OP_HEADS_DIR},
    vfs::{DirEntry, Metadata},
    Identity, MemoryBackend, Repo, Result, StorageBackend, VPath,
};

/// Where the recorder stops.
#[derive(Clone, Copy, Debug, PartialEq)]
enum At {
    /// Creating its op head file: its objects are published (renamed into
    /// the store), and nothing names them yet.
    OpHead,
    /// After its first staged object was renamed into the store: the
    /// others are still in staging.
    FirstRename,
    /// At its first staged write: its base view is read, nothing written.
    FirstStage,
}

#[derive(Default)]
struct Flag(Mutex<bool>, Condvar);

impl Flag {
    fn set(&self) {
        *self.0.lock().unwrap() = true;
        self.1.notify_all();
    }
    fn wait(&self) {
        let mut g = self.0.lock().unwrap();
        while !*g {
            g = self.1.wait(g).unwrap();
        }
    }
}

#[derive(Debug)]
struct Pause {
    inner: Arc<MemoryBackend>,
    at: At,
    armed: AtomicBool,
    renames: AtomicUsize,
    reached: Arc<FlagBox>,
    go: Arc<FlagBox>,
}

#[derive(Default)]
struct FlagBox(Flag);

impl std::fmt::Debug for FlagBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("flag")
    }
}

impl Pause {
    fn new(at: At) -> Arc<Pause> {
        Arc::new(Pause {
            inner: Arc::new(MemoryBackend::new()),
            at,
            armed: AtomicBool::new(false),
            renames: AtomicUsize::new(0),
            reached: Default::default(),
            go: Default::default(),
        })
    }

    fn stop_here(&self, at: At) {
        let me = std::thread::current().name() == Some("recorder");
        if me && at == self.at && self.armed.swap(false, Ordering::SeqCst) {
            self.reached.0.set();
            self.go.0.wait();
        }
    }
}

impl StorageBackend for Pause {
    fn kind(&self) -> &'static str {
        "pause"
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        self.inner.read(path)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.inner.write(path, data)
    }
    fn write_unsynced(&self, path: &VPath, data: &[u8]) -> Result<()> {
        if path.as_str().contains("/incoming/tx-") {
            self.stop_here(At::FirstStage);
        }
        self.inner.write_unsynced(path, data)
    }
    fn rename_unsynced(&self, from: &VPath, to: &VPath) -> Result<()> {
        self.inner.rename_unsynced(from, to)?;
        if from.as_str().contains("/incoming/tx-") && self.renames.fetch_add(1, Ordering::SeqCst) == 0 {
            self.stop_here(At::FirstRename);
        }
        Ok(())
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        if path.as_str().starts_with(OP_HEADS_DIR) {
            self.stop_here(At::OpHead);
        }
        self.inner.create_new(path, data)
    }
    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.inner.remove_file(path)
    }
    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        self.inner.remove_dir_all(path)
    }
    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        self.inner.create_dir_all(path)
    }
    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        self.inner.list_dir(path)
    }
    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        self.inner.metadata(path)
    }
    fn set_executable(&self, path: &VPath, x: bool) -> Result<()> {
        self.inner.set_executable(path, x)
    }
}

/// gc as `vl gc --keep-ops-days 0 --prune-now` a minute from now.
fn prune_now() -> GcOptions {
    GcOptions {
        keep_ops: Some(Duration::ZERO),
        grace: Duration::ZERO,
        now: Some(veil_core::now_millis() + 60_000),
        ..GcOptions::default()
    }
}

/// Run `recorder` on a thread named so, stop it at the gate's point, run
/// `meanwhile` and then gc on other threads while it waits, and let it go
/// once gc finished or (with the fence) had time to start waiting for it.
/// Returns what the recorder and gc returned.
fn race<R: Send + 'static>(
    gate: &Arc<Pause>,
    id: &Identity,
    recorder: impl FnOnce(&mut Repo) -> R + Send + 'static,
    meanwhile: impl FnOnce(),
) -> (R, Result<GcReport>) {
    gate.armed.store(true, Ordering::SeqCst);
    let fs: Arc<dyn StorageBackend> = gate.clone();
    let rec = {
        let (fs, id) = (fs.clone(), id.clone());
        std::thread::Builder::new()
            .name("recorder".into())
            .spawn(move || recorder(&mut Repo::open(fs, Some(id.clone()), &id.name).unwrap()))
            .unwrap()
    };
    gate.reached.0.wait();
    meanwhile();
    let g = {
        let (fs, id) = (fs.clone(), id.clone());
        std::thread::spawn(move || gc(&mut Repo::open(fs, Some(id.clone()), &id.name).unwrap(), &prune_now()))
    };
    // Before the fix gc deletes at once; with it, gc waits for the
    // recorder, whatever this wait is.
    let until = std::time::Instant::now() + Duration::from_secs(2);
    while !g.is_finished() && std::time::Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    gate.go.0.set();
    let r = rec.join().unwrap();
    (r, g.join().unwrap())
}

fn new_gated(at: At) -> (Arc<Pause>, Arc<dyn StorageBackend>, Identity) {
    let gate = Pause::new(at);
    let fs: Arc<dyn StorageBackend> = gate.clone();
    let id = Identity::generate("alice");
    let mut init = Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap();
    init.snapshot_workspace(WS, &*fs).unwrap();
    (gate, fs, id)
}

/// The recording (`vl ws exec` and every snapshot do this) is complete and
/// readable, and `fsck` is clean.
fn assert_recorded(fs: &Arc<dyn StorageBackend>, id: &Identity, path: &str, want: &[u8]) {
    let r = Repo::open(fs.clone(), Some(id.clone()), &id.name).unwrap();
    let wc = r.workspace_wc(WS).unwrap();
    assert_eq!(read_at(&r, &wc, path), want);
    assert_fsck_clean(fs.clone(), id, "after gc raced a recording");
}

/// BUG-811: a transaction has renamed its objects into the store and not
/// yet created its op head; `gc --prune-now` takes them for garbage.
#[test]
fn prune_now_never_deletes_what_a_transaction_published_but_not_named() {
    let (gate, fs, id) = new_gated(At::OpHead);
    fs.write(&p("work.txt"), b"recorded work 811-a\n").unwrap();
    let rfs = fs.clone();
    let (out, g) = race(&gate, &id, move |r| r.snapshot_workspace(WS, &*rfs).map(|s| s.changed), || {});
    assert!(out.unwrap());
    g.unwrap();
    assert_recorded(&fs, &id, "work.txt", b"recorded work 811-a\n");
}

/// The same with the staging half renamed: some objects in the store,
/// the rest still staged.
#[test]
fn prune_now_never_deletes_what_a_transaction_is_renaming() {
    let (gate, fs, id) = new_gated(At::FirstRename);
    for i in 0..8 {
        fs.write(&p(&format!("dir{i}/work.txt")), format!("recorded work 811-b {i}\n").as_bytes()).unwrap();
    }
    let rfs = fs.clone();
    let (out, g) = race(&gate, &id, move |r| r.snapshot_workspace(WS, &*rfs).map(|s| s.changed), || {});
    assert!(out.unwrap());
    g.unwrap();
    for i in 0..8 {
        assert_recorded(&fs, &id, &format!("dir{i}/work.txt"), format!("recorded work 811-b {i}\n").as_bytes());
    }
}

/// A transaction reuses an object already in the store that nothing
/// references (a file restored to the content of an abandoned change), so
/// it never writes it: gc must not delete it under the recording.
#[test]
fn prune_now_never_deletes_an_object_a_transaction_reused() {
    let (gate, fs, id) = new_gated(At::OpHead);
    {
        let mut r = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
        let s = commit_files(&mut r, &*fs, &[("old.txt", "an abandoned version 811-c\n")], "experiment");
        r.abandon(s).unwrap();
        fs.remove_file(&p("old.txt")).unwrap();
        r.snapshot_workspace(WS, &*fs).unwrap();
    }
    // Packed, so that deleting it means removing a pack.
    let mut g = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
    gc(&mut g, &GcOptions::default()).unwrap();
    drop(g);
    fs.write(&p("again.txt"), b"an abandoned version 811-c\n").unwrap();
    let rfs = fs.clone();
    let (out, g) = race(&gate, &id, move |r| r.snapshot_workspace(WS, &*rfs).map(|s| s.changed), || {});
    assert!(out.unwrap());
    g.unwrap();
    assert_recorded(&fs, &id, "again.txt", b"an abandoned version 811-c\n");
}

/// A transaction whose base gc prunes while it runs (two commands land on
/// top, and `--keep-ops-days 0` keeps only the heads and their parents):
/// it either records its work whole, or refuses and asks to run it again.
/// The other commands' work is never undone (no merge against nothing).
#[test]
fn a_transaction_whose_base_gc_prunes_records_whole_or_refuses() {
    let (gate, fs, id) = new_gated(At::FirstStage);
    // Tags on a commit the recording does not rewrite (one on the working
    // copy moves with it, and a moved tag wins over a deletion).
    let base = {
        let mut r = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
        let c = commit_files(&mut r, &*fs, &[("base.txt", "base\n")], "base");
        r.set_tag("withdrawn", c, None, false).unwrap();
        c
    };
    fs.write(&p("work.txt"), b"recorded work 811-d\n").unwrap();
    let (mfs, mid) = (fs.clone(), id.clone());
    let rfs = fs.clone();
    let (out, g) = race(
        &gate,
        &id,
        move |r| r.snapshot_workspace(WS, &*rfs).map(|s| s.changed),
        move || {
            let mut other = Repo::open(mfs, Some(mid.clone()), "alice").unwrap();
            other.delete_tag("withdrawn").unwrap();
            other.set_tag("landed", base, None, false).unwrap();
        },
    );
    let g = g.unwrap();
    let r = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
    let tags = &r.view().tags;
    assert!(!tags.contains_key("withdrawn"), "a deleted tag came back: recording {out:?}, gc {g:?}");
    assert!(tags.contains_key("landed"));
    drop(r);
    match out {
        Ok(changed) => {
            assert!(changed);
            assert_recorded(&fs, &id, "work.txt", b"recorded work 811-d\n");
        }
        Err(e) => {
            assert!(e.to_string().contains("run the command again"), "{e}");
            assert_fsck_clean(fs.clone(), &id, "after a refused recording");
        }
    }
}

/// A command that resolved a snapshot from an older view and tags it after
/// gc pruned it (`vl tag set` with a revision read before gc ran): the
/// commit refuses, instead of recording a tag that names nothing.
#[test]
fn a_tag_carried_from_an_older_view_is_checked_at_commit() {
    let (mut repo, fs, id) = new_repo("alice");
    let old = commit_files(&mut repo, &*fs, &[("f", "old 811-e\n")], "old");
    repo.abandon(old).unwrap();
    commit_files(&mut repo, &*fs, &[("f", "new 811-e\n")], "new");
    let mut g = open(&fs, &id);
    gc(&mut g, &prune_now()).unwrap();
    assert!(!repo.store().has(&old), "the test needs the snapshot gone");
    let mut tx = repo.transaction("tag set").unwrap();
    tx.view.tags.insert("stale".into(), Tag::new(old, None));
    let e = tx.commit().unwrap_err();
    assert!(e.to_string().contains("run the command again"), "{e}");
    let r = open(&fs, &id);
    assert!(!r.view().tags.contains_key("stale"));
}

/// gc called on a thread that holds a transaction cannot wait for it: it
/// deletes nothing, at once, and says why.
#[test]
fn gc_on_a_thread_holding_a_transaction_defers_deletion() {
    let (mut repo, fs, id) = new_repo("alice");
    let old = commit_files(&mut repo, &*fs, &[("f", "old 811-f\n")], "old");
    repo.abandon(old).unwrap();
    let mut g = open(&fs, &id);
    let tx = repo.transaction("held").unwrap();
    let started = std::time::Instant::now();
    let r = gc(&mut g, &prune_now()).unwrap();
    assert!(started.elapsed() < Duration::from_secs(3), "gc waited for its own thread");
    assert_eq!(r.deleted, 0);
    assert!(r.deferred.is_some());
    drop(tx);
    assert!(repo.store().has(&old));
    let r = gc(&mut g, &prune_now()).unwrap();
    assert!(r.deleted > 0, "{r:?}");
    assert_fsck_clean(fs.clone(), &id, "after the deferred gc");
}

/// Stress: threads recording, tagging and running `gc --prune-now` on one
/// disk. Every recorded file and tag is there at the end, `fsck` clean.
#[test]
fn prune_now_beside_many_writers_loses_nothing() {
    let (repo, fs, id) = new_repo("alice");
    drop(repo);
    let fs: Arc<dyn StorageBackend> = fs;
    let names: Vec<String> = (0..4).map(|i| format!("agent{i}")).collect();
    {
        let mut r = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
        let wc = r.workspace_wc(WS).unwrap();
        for n in &names {
            r.create_workspace(n, vec![wc], None).unwrap();
        }
    }
    let stop = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::new();
    for n in names.clone() {
        let (fs, id) = (fs.clone(), id.clone());
        threads.push(std::thread::spawn(move || {
            let mut done = Vec::new();
            for k in 0..6 {
                let mut r = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
                let ov = r.workspace_overlay(&n).unwrap();
                let file = format!("{n}-{k}.txt");
                ov.write(&p(&file), format!("{n} work {k}\n").as_bytes()).unwrap();
                match r.snapshot_workspace_with(&n, &ov, Default::default()) {
                    Ok(_) => done.push(file),
                    Err(e) => assert!(e.to_string().contains("run the command again"), "{e}"),
                }
                let wc = r.workspace_wc(&n).unwrap();
                r.set_tag(&format!("{n}-tag-{k}"), wc, None, false).unwrap();
            }
            (n, done)
        }));
    }
    let gcs = {
        let (fs, id, stop) = (fs.clone(), id.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let mut g = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
                gc(&mut g, &prune_now()).unwrap();
            }
        })
    };
    let results: Vec<(String, Vec<String>)> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    stop.store(true, Ordering::SeqCst);
    gcs.join().unwrap();
    let r = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
    for (n, files) in results {
        let wc = r.workspace_wc(&n).unwrap();
        for f in files {
            let want = format!("{n} work {}\n", &f[n.len() + 1..f.len() - 4]);
            assert_eq!(read_at(&r, &wc, &f), want.as_bytes(), "{f}");
        }
        for k in 0..6 {
            assert!(r.view().tags.contains_key(&format!("{n}-tag-{k}")));
        }
    }
    drop(r);
    assert_fsck_clean(fs, &id, "after the stress run");
}
