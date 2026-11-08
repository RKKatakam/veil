//! The lock-free op log (format 6, `docs/design/scale/2-lock-free-oplog.md`):
//! one test per item of its threat review that the engine can show.
//!
//! Concurrency is made deterministic by forking the "disk": two
//! `MemoryBackend` forks of one repository each run a command, as two
//! processes that read the same heads would, and [`land`] then puts what
//! each wrote (objects, operations, head files) on the shared disk. The
//! next `Repo::open` finds two heads and merges them. Real concurrency
//! (threads on one disk) is in the stress tests at the end.

use crate::adversarial_support;

use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use adversarial_support::*;
use veil_core::{
    commands::EmbargoSpec,
    fsck::{fsck, Severity},
    gc::{gc, GcOptions},
    lock::{owner_gone, owner_tag, HostIdentity, LockContext, Owner, ProcEntry, ProcessProbe, ProcessStart, Signal},
    oplog::{Tag, OP_HEADS_DIR},
    remote,
    transaction::Transaction,
    vfs::{DirEntry, Metadata},
    DiskBackend, Identity, MemoryBackend, ObjectId, Repo, Result, StorageBackend, VPath, VeilError,
};

const WS: &str = "default";

/// The head files on `fs`.
pub(crate) fn head_files(fs: &dyn StorageBackend) -> BTreeSet<String> {
    fs.list_dir(&p(OP_HEADS_DIR)).map(|v| v.into_iter().map(|e| e.name).collect()).unwrap_or_default()
}

/// What a "process" that worked on `side` (a fork of `disk` taken when its
/// head files were `heads_at_fork`) wrote, put on `disk`: new objects,
/// operations, metadata and head files, and the head files it removed.
pub(crate) fn land(disk: &MemoryBackend, side: &MemoryBackend, heads_at_fork: &BTreeSet<String>) {
    for f in side.files() {
        let s = f.as_str();
        let shared = [".veil/objects/", ".veil/ops/", ".veil/op_heads/", ".veil/meta/"].iter().any(|d| s.starts_with(d));
        if shared && !s.contains("/incoming/") && !disk.exists(&f).unwrap() {
            disk.write(&f, &side.read(&f).unwrap()).unwrap();
        }
    }
    let now = head_files(side);
    for h in heads_at_fork.difference(&now) {
        disk.remove_file(&p(&format!("{OP_HEADS_DIR}/{h}"))).unwrap();
    }
}

/// Two "processes" on forks of `disk`: run `a` and `b` on their own forks
/// (each opens the repository as it is now), then land both. Returns what
/// each returned.
pub(crate) fn concurrently<A, B>(disk: &Arc<MemoryBackend>, id: &Identity, a: impl FnOnce(&mut Repo) -> A, b: impl FnOnce(&mut Repo) -> B) -> (A, B) {
    let heads = head_files(&**disk);
    let (fa, fb) = (Arc::new(disk.fork()), Arc::new(disk.fork()));
    let ra = a(&mut Repo::open(fa.clone(), Some(id.clone()), &id.name).unwrap());
    let rb = b(&mut Repo::open(fb.clone(), Some(id.clone()), &id.name).unwrap());
    land(disk, &fa, &heads);
    land(disk, &fb, &heads);
    (ra, rb)
}

pub(crate) fn assert_fsck_clean(fs: Arc<dyn StorageBackend>, id: &Identity, what: &str) {
    let r = fsck(fs, Some(id.clone())).unwrap();
    let bad: Vec<String> = r
        .findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Corrupt | Severity::Warning))
        .map(|f| f.to_string())
        .collect();
    assert!(bad.is_empty(), "{what}: {bad:#?}");
}

pub(crate) fn open(fs: &Arc<MemoryBackend>, id: &Identity) -> Repo {
    Repo::open(fs.clone(), Some(id.clone()), &id.name).unwrap()
}

/// The heads of the merged log are one merge operation of `n` parents.
fn assert_merged(repo: &Repo, n: usize) {
    assert_eq!(repo.heads().len(), 1, "settled into one head");
    let op = repo.ops().get(&repo.heads()[0]).unwrap();
    assert_eq!(op.parents.len(), n, "a merge of {n}: {:?}", op.description);
    assert_eq!(op.user, "veil");
}

// ---- threat 1: no lost view update -----------------------------------------------

#[test]
fn concurrent_tag_sets_all_land() {
    let (mut repo, fs, id) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("f", "1\n")], "base");
    drop(repo);
    concurrently(&fs, &id, |r| r.set_tag("from-a", base, false).unwrap(), |r| r.set_tag("from-b", base, false).unwrap());
    let mut r = open(&fs, &id);
    assert!(r.view().tags.contains_key("from-a") && r.view().tags.contains_key("from-b"), "{:?}", r.view().tags.keys());
    assert_merged(&r, 2);
    assert!(r.take_warnings().is_empty());
    assert_fsck_clean(fs.clone(), &id, "after the merge");

    // The same tag moved on both sides: one target wins, the other stays
    // a visible change, and the user is told (once).
    let mut r = open(&fs, &id);
    let ws = r.workspace_wc(WS).unwrap();
    let (x, _) = r.commit_working_copy(WS, "x").unwrap();
    drop(r);
    concurrently(&fs, &id, |r| r.set_tag("main", x, true).unwrap(), |r| r.set_tag("main", ws, true).unwrap());
    let mut r = open(&fs, &id);
    let won = r.view().tags["main"].target;
    let lost = if won == x { ws } else { x };
    assert!(r.exact().visible().unwrap().contains(&lost), "the losing target was dropped");
    let w = r.take_warnings();
    assert!(w.iter().any(|w| w.contains("tag 'main'")), "{w:?}");
    assert!(open(&fs, &id).take_warnings().is_empty(), "warned twice");
}

// ---- threat 2: a child left on a rewritten parent ----------------------------------

#[test]
fn amend_racing_child_rebases_child() {
    let (mut repo, fs, id) = new_repo("alice");
    let x = commit_files(&mut repo, &*fs, &[("f", "1\n")], "x");
    let change = repo.snapshot(&x).unwrap().change_id;
    drop(repo);
    let (x2, side) = concurrently(&fs, &id, |r| r.describe(x, "x, amended").unwrap(), |r| r.create_workspace("side", vec![x]).unwrap());
    let r = open(&fs, &id);
    assert_merged(&r, 2);
    let side_now = r.workspace_wc("side").unwrap();
    assert_ne!(side_now, side, "the child stayed on the rewritten parent");
    assert_eq!(r.snapshot(&side_now).unwrap().parents, vec![x2], "the child is on the amended parent");
    assert_eq!(r.snapshot(&side_now).unwrap().predecessors, vec![side], "evolog of the moved child");
    assert!(!r.exact().visible().unwrap().contains(&x), "the rewritten parent is still visible");
    assert_eq!(r.snapshot(&x2).unwrap().change_id, change);
    assert_fsck_clean(fs.clone(), &id, "after the merge");
}

// ---- threats 3 and 18: an embargo escape through concurrency -----------------------

const FIX_NAMES: [&str; 3] = ["FIXNAME-K7", "FIXBODY-K7", "CHILDBODY-K7"];

/// `v1` (tag `main`); the fix `fix` on it in workspace `fixws`; a child of
/// the fix that edits one of its files. Returns (v1, fix, child).
fn fix_line(repo: &mut Repo, fs: &MemoryBackend) -> (ObjectId, ObjectId, ObjectId) {
    let v1 = commit_files(repo, fs, &[("a.c", "v\n")], "v1");
    repo.set_tag("main", v1, false).unwrap();
    repo.create_workspace("fixws", vec![v1]).unwrap();
    let ov = repo.workspace_overlay("fixws").unwrap();
    ov.write(&p("FIXNAME-K7.c"), b"FIXBODY-K7\n").unwrap();
    repo.snapshot_workspace("fixws", &ov).unwrap();
    let (fix, _) = repo.commit_working_copy("fixws", "the fix").unwrap();
    let ov = repo.workspace_overlay("fixws").unwrap();
    ov.write(&p("FIXNAME-K7.c"), b"FIXBODY-K7 CHILDBODY-K7\n").unwrap();
    repo.snapshot_workspace("fixws", &ov).unwrap();
    let (child, _) = repo.commit_working_copy("fixws", "work on the fix").unwrap();
    (v1, fix, child)
}

#[test]
fn concurrent_rebase_cannot_escape_embargo() {
    let (mut repo, fs, id) = new_repo("alice");
    let (v1, fix, child) = fix_line(&mut repo, &fs);
    drop(repo);
    // A moves the child off the fix (no embargo yet, so allowed); B, at
    // the same time, makes the fix an unreleased embargo, which confines
    // the child (work built on it).
    concurrently(
        &fs,
        &id,
        |r| r.rebase(child, vec![v1]).unwrap(),
        |r| {
            let m = r.merge(WS, v1, vec![fix], "embargoed", Some(EmbargoSpec { scope: "team".into(), until: None })).unwrap();
            r.set_tag("main", m.snapshot, true).unwrap();
            m.snapshot
        },
    );
    let mut r = open(&fs, &id);
    assert_merged(&r, 2);
    let w = r.take_warnings();
    assert!(w.iter().any(|w| w.contains("was not applied") && w.contains("unreleased embargo")), "{w:?}");
    for msg in &w {
        for n in FIX_NAMES {
            assert!(!msg.contains(n), "a warning names the fix: {msg}");
        }
    }
    // The child is back on the fix: nothing of it sits outside the embargo.
    let visible = r.exact().visible().unwrap();
    for s in &visible {
        let snap = r.snapshot(s).unwrap();
        if snap.change_id == r.snapshot(&child).unwrap().change_id {
            assert!(r.is_ancestor(&fix, s).unwrap(), "a copy of the child sits outside the embargo: {}", s.short());
        }
    }
    // Later commands succeed and do not warn again (threat 18).
    let (c, _) = r.commit_working_copy(WS, "later").unwrap();
    r.set_tag("later", c, false).unwrap();
    assert!(open(&fs, &id).take_warnings().is_empty());
    // And a public push carries nothing of the fix.
    let mirror = Arc::new(MemoryBackend::new());
    let mut r = open(&fs, &id);
    remote::push(&mut r, mirror.clone(), true, &[], false).unwrap();
    for n in FIX_NAMES {
        assert!(backend_contains(&*mirror, n.as_bytes()).is_empty(), "{n} reached the public remote");
    }
    assert_fsck_clean(fs.clone(), &id, "after the merge");
}

/// Threat 3 with a chain: the side that moved the child out also amended
/// it afterwards (two rewrites, child → moved → amended). Dropping the
/// first rewrite must take the last replacement back too.
#[test]
fn chained_rewrite_cannot_escape_embargo() {
    let (mut repo, fs, id) = new_repo("alice");
    let (v1, fix, child) = fix_line(&mut repo, &fs);
    let change = repo.snapshot(&child).unwrap().change_id;
    drop(repo);
    concurrently(
        &fs,
        &id,
        |r| {
            let moved = r.rebase(child, vec![v1]).unwrap();
            r.describe(moved, "moved, then amended").unwrap();
        },
        |r| {
            r.merge(WS, v1, vec![fix], "embargoed", Some(EmbargoSpec { scope: "team".into(), until: None })).unwrap();
        },
    );
    let mut r = open(&fs, &id);
    assert!(r.take_warnings().iter().any(|w| w.contains("was not applied")));
    for s in r.exact().visible().unwrap() {
        if r.snapshot(&s).unwrap().change_id == change {
            assert!(r.is_ancestor(&fix, &s).unwrap(), "a copy of the child sits outside the embargo: {}", s.short());
        }
    }
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut r, mirror.clone(), true, &[], false).unwrap();
    for n in FIX_NAMES {
        assert!(backend_contains(&*mirror, n.as_bytes()).is_empty(), "{n} reached the public remote");
    }
    assert_fsck_clean(fs.clone(), &id, "after the merge");
}

// ---- threats 4 and 22: compare-and-swap; a superseded snapshot keeps its objects -----

#[test]
fn expected_wc_cas_supersedes() {
    let (mut repo, fs, id) = new_repo("alice");
    commit_files(&mut repo, &*fs, &[("f", "1\n")], "base");
    let wc = repo.workspace_wc(WS).unwrap();
    let mut other = open(&fs, &id);
    // A transaction that recorded the working copy it started from...
    let mut tx = repo.transaction("record").unwrap();
    tx.expect_wc(WS, wc);
    let blob = tx.repo().store().put(&veil_core::object::Object::Blob(b"staged by the loser".to_vec())).unwrap();
    tx.view.tags.insert("loser".into(), Tag::new(wc));
    // ...loses to an operation that moved it meanwhile.
    other.new_change(WS, vec![wc], "moved").unwrap();
    let err = tx.commit().unwrap_err();
    assert!(Transaction::is_superseded(&err), "{err}");
    // Its objects are published anyway (a stat cache may name them).
    assert!(repo.store().has(&blob), "the superseded transaction's object was discarded");
    let r = open(&fs, &id);
    assert!(!r.view().tags.contains_key("loser"));
    // An unrelated concurrent operation does not supersede it.
    let mut repo = open(&fs, &id);
    let wc = repo.workspace_wc(WS).unwrap();
    let mut tx = repo.transaction("record").unwrap();
    tx.expect_wc(WS, wc);
    tx.view.tags.insert("winner".into(), Tag::new(wc));
    open(&fs, &id).set_tag("unrelated", wc, false).unwrap();
    tx.commit().unwrap();
    let r = open(&fs, &id);
    assert!(r.view().tags.contains_key("winner") && r.view().tags.contains_key("unrelated"));
    assert_fsck_clean(fs.clone(), &id, "after the compare-and-swap");
}

#[test]
fn superseded_snapshot_keeps_objects() {
    let (mut repo, fs, id) = new_repo("alice");
    commit_files(&mut repo, &*fs, &[("f", "1\n")], "base");
    let wc = repo.workspace_wc(WS).unwrap();
    let mut other = open(&fs, &id);
    other.new_change(WS, vec![wc], "moved meanwhile").unwrap();
    // The snapshot finds the workspace moved before it builds: nothing to
    // keep. Moved during the build: what it staged is published.
    fs.write(&p("g"), b"edit\n").unwrap();
    let out = repo
        .snapshot_workspace_with(WS, &*fs, veil_core::workspace::SnapshotOptions { expected_wc: Some(wc), ..Default::default() })
        .unwrap();
    assert!(out.superseded);
    assert_fsck_clean(fs.clone(), &id, "after a superseded snapshot");
}

// ---- threat 5: never adopting an object that may not be durable ---------------------

/// A disk whose next barrier can fail with EIO (Linux semantics: the
/// failed writes read back but never reach the disk), and that can lose
/// power: every write not covered by a successful barrier is torn.
#[derive(Debug, Default)]
struct EioDisk {
    inner: MemoryBackend,
    fail_next: AtomicBool,
    failures: std::sync::atomic::AtomicU64,
    volatile: Mutex<BTreeSet<VPath>>,
    lost: Mutex<BTreeSet<VPath>>,
}

impl EioDisk {
    fn power_loss(&self) {
        let mut gone: Vec<VPath> = std::mem::take(&mut *self.volatile.lock().unwrap()).into_iter().collect();
        gone.extend(std::mem::take(&mut *self.lost.lock().unwrap()));
        for f in gone {
            if self.inner.exists(&f).unwrap() {
                self.inner.write(&f, b"").unwrap();
            }
        }
    }
}

impl StorageBackend for EioDisk {
    fn kind(&self) -> &'static str {
        "eio"
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        self.inner.read(path)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.inner.write(path, data)?;
        self.volatile.lock().unwrap().remove(path);
        self.lost.lock().unwrap().remove(path);
        Ok(())
    }
    fn write_unsynced(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.inner.write(path, data)?;
        self.lost.lock().unwrap().remove(path);
        self.volatile.lock().unwrap().insert(path.clone());
        Ok(())
    }
    fn rename_unsynced(&self, from: &VPath, to: &VPath) -> Result<()> {
        let data = self.inner.read(from)?;
        self.inner.write(to, &data)?;
        self.inner.remove_file(from)?;
        for set in [&self.volatile, &self.lost] {
            let mut s = set.lock().unwrap();
            if s.remove(from) {
                s.insert(to.clone());
            }
        }
        Ok(())
    }
    fn sync_barrier(&self) -> Result<()> {
        let mut v = self.volatile.lock().unwrap();
        if self.fail_next.swap(false, Ordering::SeqCst) {
            self.failures.fetch_add(1, Ordering::SeqCst);
            self.lost.lock().unwrap().extend(std::mem::take(&mut *v));
            return Err(VeilError::Io {
                path: "<disk>".into(),
                source: std::io::Error::other("EIO"),
            });
        }
        v.clear();
        Ok(())
    }
    fn barrier_failures(&self) -> u64 {
        self.failures.load(Ordering::SeqCst)
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.inner.create_new(path, data)
    }
    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.volatile.lock().unwrap().remove(path);
        self.lost.lock().unwrap().remove(path);
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

#[test]
fn eio_barrier_never_adopted() {
    let disk = Arc::new(EioDisk::default());
    let fs: Arc<dyn StorageBackend> = disk.clone();
    let id = Identity::generate("alice");
    Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap();
    let mut a = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
    let mut b = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
    let content = b"shared content, written by both processes\n".to_vec();
    // A and B both build the same snapshot; A's copy is staged first.
    let build = |r: &Repo| {
        let blob = blob(r, &content);
        let tree = raw_tree(r, vec![file("shared.txt", blob)]);
        let s = veil_core::object::Snapshot {
            parents: vec![r.root_id()],
            change_id: veil_core::id::ChangeId([3; 16]),
            description: veil_core::object::Text::Plain("shared".into()),
            author: "alice".into(),
            timestamp: 1,
            ..veil_core::object::Snapshot::root(tree)
        };
        r.store().put_snapshot(&s).unwrap()
    };
    let mut tx_a = a.transaction("A").unwrap();
    let s_a = build(tx_a.repo());
    tx_a.add_head(s_a).unwrap();
    let mut tx_b = b.transaction("B").unwrap();
    let s_b = build(tx_b.repo());
    assert_eq!(s_a, s_b);
    tx_b.add_head(s_b).unwrap();
    tx_b.view.tags.insert("from-b".into(), Tag::new(s_b));
    // A's barrier fails: its objects are void, and nobody adopted them.
    disk.fail_next.store(true, Ordering::SeqCst);
    assert!(tx_a.commit().is_err());
    // On a shared backend value A's failed barrier covered B's writes too:
    // B fails rather than publish them, and its retry writes fresh copies.
    assert!(tx_b.commit().is_err(), "B published writes a failed barrier covered");
    let mut tx_b = b.transaction("B again").unwrap();
    let s_b = build(tx_b.repo());
    tx_b.add_head(s_b).unwrap();
    tx_b.view.tags.insert("from-b".into(), Tag::new(s_b));
    tx_b.commit().unwrap();
    disk.power_loss();
    let r = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
    let s = r.view().tags["from-b"].target;
    assert_eq!(read_at(&r, &s, "shared.txt"), content);
    assert_fsck_clean(fs, &id, "after EIO and a power loss");
}

// ---- threat 7: staging is removed only when its owner is provably gone ---------------

#[derive(Debug)]
struct Probe(Vec<(u32, ProcEntry, Signal)>);

impl ProcessProbe for Probe {
    fn entry(&self, pid: u32) -> ProcEntry {
        self.0.iter().find(|(p, _, _)| *p == pid).map_or(ProcEntry::Absent, |(_, e, _)| e.clone())
    }
    fn signal(&self, pid: u32) -> Signal {
        self.0.iter().find(|(p, _, _)| *p == pid).map_or(Signal::Unknown, |(_, _, s)| *s)
    }
}

#[test]
fn staging_sweep_keeps_live_owners() {
    let me = HostIdentity::simulated("here");
    let now = veil_core::now_millis();
    let present = |start: u64, zombie: bool| ProcEntry::Present {
        zombie: Some(zombie),
        start: Some(ProcessStart { id: start, wall_ms: None }),
    };
    let ctx = LockContext {
        host: Some(me.clone()),
        probe: Arc::new(Probe(vec![
            (101, present(5, true), Signal::Delivered),   // a zombie
            (102, present(9, false), Signal::Delivered),  // pid reused (other start)
            (103, present(7, false), Signal::Delivered),  // alive, same start
            (104, ProcEntry::Absent, Signal::NoProcess),  // gone
            (105, ProcEntry::Unavailable, Signal::Unknown), // cannot tell
        ])),
        boot_ms: Some(now - 60_000),
        ..LockContext::default()
    };
    let other_ns = HostIdentity { host: me.host.clone(), boot: "another pid namespace".into() };
    let cases = [
        (owner_tag(&me, 101, 5, now), true, "a zombie"),
        (owner_tag(&me, 102, 5, now), true, "a reused pid"),
        (owner_tag(&me, 103, 7, now), false, "a live holder"),
        (owner_tag(&me, 104, 7, now), false.then_some(()).is_none(), "a dead pid"),
        (owner_tag(&me, 105, 7, now), false, "a pid that cannot be checked"),
        (owner_tag(&other_ns, 104, 7, now), false, "another namespace of this boot"),
        (owner_tag(&other_ns, 104, 7, now - 3_600_000), true, "the previous boot"),
        (owner_tag(&HostIdentity::simulated("elsewhere"), 104, 7, now - 3_600_000), false, "another host"),
        ("not-a-tag".to_string(), false, "garbage"),
    ];
    for (tag, gone, what) in &cases {
        assert_eq!(owner_gone(tag, &ctx), *gone, "{what}");
    }
    // This process: kept while its owner lives.
    let mine = Owner::with_context(&ctx);
    assert!(!owner_gone(mine.tag(), &ctx));
    let dropped = Owner::with_context(&ctx).tag().to_string();
    assert!(owner_gone(&dropped, &ctx), "a dropped owner of this process");

    // End to end: the sweep removes exactly the dead owners' directories.
    let (repo, fs, _) = new_repo("alice");
    for (i, (tag, _, _)) in cases.iter().enumerate() {
        let kind = if i % 2 == 0 { "tx-" } else { "pull-" };
        fs.write(&p(&format!(".veil/objects/incoming/{kind}{tag}/ab/{}", "c".repeat(62))), b"x").unwrap();
    }
    fs.write(&p(&format!(".veil/objects/incoming/tx-{}/x", mine.tag())), b"x").unwrap();
    fs.write(&p(".veil/objects/incoming/push-something/x"), b"x").unwrap();
    let removed = repo.store().sweep_staging(&ctx).unwrap();
    assert_eq!(removed, cases.iter().filter(|c| c.1).count());
    let left: BTreeSet<String> = fs.list_dir(&p(".veil/objects/incoming")).unwrap().into_iter().map(|e| e.name).collect();
    for (tag, gone, what) in &cases {
        assert_eq!(left.iter().any(|n| n.ends_with(tag.as_str())), !gone, "{what}");
    }
    assert!(left.contains(&format!("tx-{}", mine.tag())) && left.contains("push-something"));
}

// ---- threats 8 and 24: hostile head files -------------------------------------------

#[test]
fn planted_head_fails_open_and_fsck_names_it() {
    let (_, fs, id) = new_repo("alice");
    let planted = ObjectId::hash(b"no such operation");
    fs.write(&p(&format!("{OP_HEADS_DIR}/{}", planted.hex())), b"").unwrap();
    let err = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap_err().to_string();
    assert!(err.contains(&planted.short()) && err.contains("op_heads") && err.contains("fsck"), "{err}");
    let report = fsck(fs.clone(), Some(id.clone())).unwrap();
    let corrupt: Vec<&str> = report.findings.iter().filter(|f| f.severity == Severity::Corrupt).map(|f| f.message.as_str()).collect();
    assert_eq!(corrupt.len(), 1, "{corrupt:?}");
    assert!(corrupt[0].contains(&format!("{OP_HEADS_DIR}/{}", planted.hex())), "{corrupt:?}");
}

#[test]
fn hostile_op_heads_entries_ignored() {
    let (mut repo, fs, id) = new_repo("alice");
    commit_files(&mut repo, &*fs, &[("f", "1\n")], "base");
    let head = repo.heads()[0];
    for junk in ["junk", "..", &head.hex().to_uppercase(), &format!("{}.tmp", head.hex()), &"g".repeat(64)] {
        fs.write(&p(&format!("{OP_HEADS_DIR}/{}", junk.replace('.', "_"))), b"").unwrap();
    }
    // A directory named like a head.
    fs.write(&p(&format!("{OP_HEADS_DIR}/{}/x", ObjectId::hash(b"dir").hex())), b"").unwrap();
    let mut r = open(&fs, &id);
    assert_eq!(r.heads(), [head]);
    r.set_tag("after", head_target(&r), false).unwrap();
    let report = fsck(fs.clone(), Some(id.clone())).unwrap();
    assert!(report.is_ok(), "{:?}", report.findings);
    assert!(report.findings.iter().any(|f| f.message.contains("not a head file")), "{:?}", report.findings);
}

fn head_target(r: &Repo) -> ObjectId {
    r.snapshot(&r.workspace_wc(WS).unwrap()).unwrap().parents[0]
}

// ---- threat 10: merge storms ---------------------------------------------------------

#[test]
fn two_settlers_write_one_merge() {
    let (mut repo, fs, id) = new_repo("alice");
    let x = commit_files(&mut repo, &*fs, &[("f", "1\n")], "x");
    drop(repo);
    // Two heads, one of which rewrote what the other built on, and a
    // workspace whose working copy the other side abandoned: the merge
    // creates snapshots, which must come out the same in both settlers.
    let heads = head_files(&*fs);
    let (fa, fb) = (Arc::new(fs.fork()), Arc::new(fs.fork()));
    open(&fa, &id).describe(x, "x, amended").unwrap();
    let mut b = open(&fb, &id);
    b.create_workspace("side", vec![x]).unwrap();
    b.set_tag("t", x, false).unwrap();
    drop(b);
    land(&fs, &fa, &heads);
    land(&fs, &fb, &heads);
    assert_eq!(head_files(&*fs).len(), 2);
    let ops = |f: &MemoryBackend| f.list_dir(&p(".veil/ops")).unwrap().into_iter().map(|e| e.name).collect::<BTreeSet<_>>();
    let before = ops(&fs);
    // Two processes settle the same heads, each on its own fork.
    let (s1, s2) = (Arc::new(fs.fork()), Arc::new(fs.fork()));
    let m1 = open(&s1, &id).heads()[0];
    let m2 = open(&s2, &id).heads()[0];
    assert_eq!(m1, m2, "two settlers wrote different merges");
    assert_eq!(s1.read(&p(&format!(".veil/ops/{}", m1.hex()))).unwrap(), s2.read(&p(&format!(".veil/ops/{}", m2.hex()))).unwrap());
    let at = head_files(&*fs);
    land(&fs, &s1, &at);
    land(&fs, &s2, &at);
    assert_eq!(ops(&fs).len(), before.len() + 1, "ops/ gained more than one merge");
    assert_eq!(head_files(&*fs).len(), 1);
    assert_fsck_clean(fs.clone(), &id, "after two settlers");
}

// ---- threat 13: ancestry after pruning ------------------------------------------------

#[test]
fn pruned_ancestry_keeps_both_heads() {
    let (mut repo, fs, id) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("f", "1\n")], "base");
    drop(repo);
    concurrently(&fs, &id, |r| r.set_tag("a", base, false).unwrap(), |r| r.set_tag("b", base, false).unwrap());
    // `gc --keep-ops-days` removed the operations linking the two heads.
    let heads: Vec<String> = head_files(&*fs).into_iter().collect();
    let r0 = veil_core::oplog::OpStore::new(fs.clone());
    let mut pruned = Vec::new();
    for h in &heads {
        let op = r0.get(&ObjectId::from_hex(h).unwrap()).unwrap();
        for parent in op.parents {
            pruned.push(parent);
        }
    }
    pruned.sort();
    pruned.dedup();
    veil_core::oplog::record_pruned_ops(&*fs, &pruned).unwrap();
    for x in &pruned {
        fs.remove_file(&p(&format!(".veil/ops/{}", x.hex()))).unwrap();
    }
    let r = open(&fs, &id);
    assert!(r.view().tags.contains_key("a") && r.view().tags.contains_key("b"), "{:?}", r.view().tags.keys());
    assert_merged(&r, 2);
}

// ---- threat 14: a transaction that outlives gc's grace period -----------------------

#[test]
fn long_transaction_survives_gc() {
    let (mut repo, fs, id) = new_repo("alice");
    commit_files(&mut repo, &*fs, &[("f", "1\n")], "base");
    // An object nothing references (left by an abandoned change, say).
    let old = blob(&repo, b"an old version nothing references any more\n");
    let mut tx = repo.transaction("long recording").unwrap();
    let tree = raw_tree(tx.repo(), vec![file("old.txt", old)]);
    let s = raw_snapshot(tx.repo(), vec![tx.repo().root_id()], tree, "long");
    tx.add_head(s).unwrap();
    tx.view.tags.insert("long".into(), Tag::new(s));
    // Two gc runs, more than the grace period apart, while it runs.
    let now = veil_core::now_millis();
    let mut g = open(&fs, &id);
    for t in [now, now + 61 * 60 * 1000] {
        gc(&mut g, &GcOptions { now: Some(t), ..GcOptions::default() }).unwrap();
    }
    tx.backdate(40 * 60 * 1000);
    tx.commit().unwrap();
    let r = open(&fs, &id);
    assert_eq!(read_at(&r, &r.view().tags["long"].target, "old.txt"), b"an old version nothing references any more\n");
    assert_fsck_clean(fs.clone(), &id, "after gc during a long transaction");
}

// ---- threat 16: features that relied on the lock ------------------------------------

#[test]
fn mount_recording_racing_commit() {
    let (mut repo, fs, id) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("f", "1\n")], "base");
    repo.create_workspace("agent", vec![base]).unwrap();
    drop(repo);
    concurrently(
        &fs,
        &id,
        |r| {
            let ov = r.workspace_overlay("agent").unwrap();
            ov.write(&p("agent.txt"), b"agent work\n").unwrap();
            let out = r
                .snapshot_workspace_with(
                    "agent",
                    &ov,
                    veil_core::workspace::SnapshotOptions {
                        description: Some(veil_core::workspace::mount_record_op_description("agent")),
                        ..Default::default()
                    },
                )
                .unwrap();
            assert!(out.changed);
        },
        |r| {
            let fs = MemoryBackend::new();
            commit_files(r, &fs, &[("mine.txt", "mine\n")], "mine");
        },
    );
    let r = open(&fs, &id);
    assert_eq!(read_at(&r, &r.workspace_wc("agent").unwrap(), "agent.txt"), b"agent work\n");
    let parent = r.snapshot(&r.workspace_wc(WS).unwrap()).unwrap().parents[0];
    assert_eq!(read_at(&r, &parent, "mine.txt"), b"mine\n");
}

#[test]
fn exec_recording_racing_rebase_of_base() {
    let (mut repo, fs, id) = new_repo("alice");
    let first = commit_files(&mut repo, &*fs, &[("f", "1\n")], "first");
    let base = commit_files(&mut repo, &*fs, &[("g", "2\n")], "base");
    repo.create_workspace("o", vec![first]).unwrap();
    let ov = repo.workspace_overlay("o").unwrap();
    ov.write(&p("o.txt"), b"other line\n").unwrap();
    repo.snapshot_workspace("o", &ov).unwrap();
    let (other, _) = repo.commit_working_copy("o", "other").unwrap();
    let agent = repo.create_workspace("agent", vec![base]).unwrap();
    // The sandbox was materialised from `agent`; meanwhile its base is
    // rebased (which moves the workspace), so the recording supersedes
    // rather than reverting the rebase, and nothing is lost.
    let mut rebaser = open(&fs, &id);
    let ov = repo.workspace_overlay("agent").unwrap();
    ov.write(&p("work.txt"), b"agent work\n").unwrap();
    rebaser.rebase(base, vec![other]).unwrap();
    let out = repo
        .snapshot_workspace_with("agent", &ov, veil_core::workspace::SnapshotOptions { expected_wc: Some(agent), ..Default::default() })
        .unwrap();
    assert!(out.superseded, "recorded over a moved workspace");
    let r = open(&fs, &id);
    let now = r.workspace_wc("agent").unwrap();
    assert!(r.is_ancestor(&other, &now).unwrap(), "the rebase was reverted");
}

// ---- threat 17: an embargo release next to a concurrent commit ------------------------

#[test]
fn release_undo_with_concurrent_commit() {
    let (mut repo, fs, id) = new_repo("alice");
    let (v1, fix, _) = fix_line(&mut repo, &fs);
    let m = repo.merge(WS, v1, vec![fix], "embargoed", Some(EmbargoSpec { scope: "team".into(), until: None })).unwrap();
    let e = m.embargo.clone().unwrap();
    repo.create_workspace("agent", vec![v1]).unwrap();
    drop(repo);
    // The release changes device-local and shared metadata as well as the
    // log: it runs on the disk itself, the agent's recording on a fork.
    let heads = head_files(&*fs);
    let fb = Arc::new(fs.fork());
    let mut b = open(&fb, &id);
    let ov = b.workspace_overlay("agent").unwrap();
    ov.write(&p("agent.txt"), b"agent work\n").unwrap();
    b.snapshot_workspace("agent", &ov).unwrap();
    drop(b);
    open(&fs, &id).release_embargo(&e).unwrap();
    land(&fs, &fb, &heads);
    let mut r = open(&fs, &id);
    assert!(r.keys().embargo_released(&e));
    let (_, undone) = r.undo_keeping_edits(WS).unwrap();
    assert!(undone.starts_with(veil_core::commands::RELEASE_OP_PREFIX), "{undone}");
    assert!(!r.keys().embargo_released(&e), "undo did not take back the staged release");
    assert_eq!(read_at(&r, &r.workspace_wc("agent").unwrap(), "agent.txt"), b"agent work\n", "the concurrent work was undone");
    let err = r.redo_keeping_edits(WS).unwrap_err().to_string();
    assert!(err.contains("never releases"), "{err}");
}

// ---- threat 19: an undo racing a commit keeps the commit -------------------------------

#[test]
fn undo_racing_commit_keeps_commit() {
    let (mut repo, fs, id) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("f", "1\n")], "base");
    repo.create_workspace("agent", vec![base]).unwrap();
    repo.set_command_workspace(Some(WS.into()));
    let c1 = commit_files(&mut repo, &*fs, &[("mine.txt", "mine\n")], "mine");
    drop(repo);
    concurrently(
        &fs,
        &id,
        |r| {
            r.set_command_workspace(Some(WS.into()));
            let (_, undone) = r.undo_keeping_edits(WS).unwrap();
            assert!(undone.starts_with("commit"), "{undone}");
        },
        |r| {
            r.set_command_workspace(Some("agent".into()));
            let ov = r.workspace_overlay("agent").unwrap();
            ov.write(&p("agent.txt"), b"agent work\n").unwrap();
            r.snapshot_workspace("agent", &ov).unwrap();
            r.commit_working_copy("agent", "agent commit").unwrap();
        },
    );
    let r = open(&fs, &id);
    let wc = r.workspace_wc(WS).unwrap();
    assert!(!r.is_ancestor(&c1, &wc).unwrap(), "the undo was lost");
    let agent_parent = r.snapshot(&r.workspace_wc("agent").unwrap()).unwrap().parents[0];
    assert_eq!(read_at(&r, &agent_parent, "agent.txt"), b"agent work\n", "the agent's commit was undone");
    assert_fsck_clean(fs.clone(), &id, "after the undo and the commit");
}

// ---- threat 23: two pulls at once ------------------------------------------------------

/// A remote whose reads are slow, so that two pulls overlap.
#[derive(Debug)]
struct Slow(Arc<dyn StorageBackend>);

impl StorageBackend for Slow {
    fn kind(&self) -> &'static str {
        "slow"
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        std::thread::sleep(Duration::from_millis(2));
        self.0.read(path)
    }
    fn read_range(&self, path: &VPath, offset: u64, len: usize) -> Result<Vec<u8>> {
        std::thread::sleep(Duration::from_millis(20));
        self.0.read_range(path, offset, len)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.0.write(path, data)
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.0.create_new(path, data)
    }
    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.0.remove_file(path)
    }
    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        self.0.remove_dir_all(path)
    }
    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        self.0.create_dir_all(path)
    }
    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        self.0.list_dir(path)
    }
    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        self.0.metadata(path)
    }
    fn set_executable(&self, path: &VPath, x: bool) -> Result<()> {
        self.0.set_executable(path, x)
    }
}

#[test]
fn two_pulls_at_once() {
    let tmp = tempfile::tempdir().unwrap();
    let id = Identity::generate("alice");
    // A remote with packs (the pull spools them).
    let src_fs = Arc::new(DiskBackend::new(tmp.path().join("src")));
    let mut src = Repo::init(src_fs.clone(), Some(id.clone()), "alice").unwrap();
    for i in 0..300 {
        src_fs.write(&p(&format!("d{}/f{i}.txt", i % 9)), format!("{i} {}\n", "x".repeat(i % 50)).as_bytes()).unwrap();
    }
    let (c, _) = {
        src.snapshot_workspace(WS, &*src_fs).unwrap();
        src.commit_working_copy(WS, "c").unwrap()
    };
    src.set_tag("main", c, false).unwrap();
    let remote_fs: Arc<dyn StorageBackend> = Arc::new(DiskBackend::new(tmp.path().join("remote")));
    remote::push(&mut src, remote_fs.clone(), false, &[], false).unwrap();
    // One clone, two pulls at once (two processes).
    let clone_dir = tmp.path().join("clone");
    Repo::init_for_clone(Arc::new(DiskBackend::new(&clone_dir)), Some(id.clone()), "alice").unwrap();
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let (dir, id, remote_fs) = (clone_dir.clone(), id.clone(), remote_fs.clone());
            std::thread::spawn(move || {
                let mut r = Repo::open(Arc::new(DiskBackend::new(&dir)), Some(id), "alice").unwrap();
                remote::pull(&mut r, "origin", Arc::new(Slow(remote_fs))).map(|_| ())
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap().expect("a pull failed (did the other delete its spool?)");
    }
    let fs: Arc<dyn StorageBackend> = Arc::new(DiskBackend::new(&clone_dir));
    let r = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
    assert_eq!(r.view().remote_tags.get("origin/main"), Some(&c));
    assert_eq!(read_at(&r, &c, "d3/f12.txt"), format!("12 {}\n", "x".repeat(12)).into_bytes());
    let incoming: Vec<String> = std::fs::read_dir(clone_dir.join(".veil/objects/incoming")).map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
    assert!(incoming.is_empty(), "spools or staging left behind: {incoming:?}");
    assert_fsck_clean(fs, &id, "after two pulls");
}

// ---- threat 25: many writers, nothing lost -------------------------------------------

#[test]
fn many_threads_no_lost_operation() {
    let tmp = tempfile::tempdir().unwrap();
    let id = Identity::generate("alice");
    let fs: Arc<dyn StorageBackend> = Arc::new(DiskBackend::new(tmp.path()));
    let mut init = Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap();
    let base = commit_files(&mut init, &*fs, &[("f", "1\n")], "base");
    const THREADS: usize = 8;
    const ROUNDS: usize = 6;
    for t in 0..THREADS {
        init.create_workspace(&format!("w{t}"), vec![base]).unwrap();
    }
    drop(init);
    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let (root, id) = (tmp.path().to_path_buf(), id.clone());
            std::thread::spawn(move || {
                // A handle of its own, as a separate process has.
                let mut r = Repo::open(Arc::new(DiskBackend::new(&root)), Some(id), "alice").unwrap();
                let ws = format!("w{t}");
                r.set_command_workspace(Some(ws.clone()));
                for n in 0..ROUNDS {
                    let ov = r.workspace_overlay(&ws).unwrap();
                    ov.write(&p(&format!("file-{t}")), format!("{n}\n").as_bytes()).unwrap();
                    r.snapshot_workspace(&ws, &ov).unwrap();
                    let wc = r.workspace_wc(&ws).unwrap();
                    r.set_tag(&format!("t{t}-{n}"), wc, false).unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let r1 = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
    for t in 0..THREADS {
        for n in 0..ROUNDS {
            assert!(r1.view().tags.contains_key(&format!("t{t}-{n}")), "tag t{t}-{n} was lost");
        }
        let wc = r1.workspace_wc(&format!("w{t}")).unwrap();
        assert_eq!(read_at(&r1, &wc, &format!("file-{t}")), format!("{}\n", ROUNDS - 1).into_bytes(), "w{t}'s last snapshot was lost");
    }
    assert_eq!(r1.heads().len(), 1);
    // Every reader sees the same, settled view.
    let r2 = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
    assert_eq!(r1.view(), r2.view());
    assert_eq!(r1.heads(), r2.heads());
    let committed = r1.op_log(usize::MAX).unwrap().iter().filter(|(_, op)| !op.is_merge() && op.description.starts_with("set tag")).count();
    assert_eq!(committed, THREADS * ROUNDS, "an operation is missing from the log");
    assert_fsck_clean(fs, &id, "after many writers");
}

// ---- op log merges review (BUG-1295 to 1298 fixes) ---------------------------------

/// Write `f` in workspace `ws` and commit it: (the commit, the new working copy).
fn commit_in(r: &mut Repo, ws: &str, f: &str, body: &str) -> (ObjectId, ObjectId) {
    r.set_command_workspace(Some(ws.into()));
    let ov = r.workspace_overlay(ws).unwrap();
    ov.write(&p(f), body.as_bytes()).unwrap();
    r.snapshot_workspace(ws, &ov).unwrap();
    r.commit_working_copy(ws, f).unwrap()
}

/// Whether the view shows `id`: as a ref, or an ancestor of one.
fn shows(r: &Repo, id: &ObjectId) -> bool {
    r.view().refs().iter().any(|x| x == id || r.is_ancestor(id, x).unwrap())
}

/// Auto-rebase through the new skip rules (BUG-1295): a commit made on
/// `x` in its workspace while another command describes `x` moves onto
/// the described `x`, though both sides moved the workspace (the shared
/// history has no value for it, BUG-1296) and the committing side shows
/// `x`.
#[test]
fn describe_racing_a_commit_on_it_moves_the_commit() {
    let (mut repo, fs, id) = new_repo("alice");
    repo.create_workspace("w", vec![repo.root_id()]).unwrap();
    let (x, _) = commit_in(&mut repo, "w", "x", "1\n");
    drop(repo);
    let (x2, (y, _)) = concurrently(&fs, &id, |r| r.describe(x, "x, amended").unwrap(), |r| commit_in(r, "w", "y", "2\n"));
    let r = open(&fs, &id);
    assert_merged(&r, 2);
    let change = r.snapshot(&y).unwrap().change_id;
    let ys: Vec<ObjectId> = r.visible_snapshots().unwrap().into_iter().filter(|s| r.snapshot(s).unwrap().description.as_str() == "y").collect();
    assert_eq!(ys.len(), 1, "one commit y");
    assert_eq!(r.snapshot(&ys[0]).unwrap().change_id, change);
    assert_eq!(r.snapshot(&ys[0]).unwrap().parents, vec![x2], "y is on the described x");
    assert!(!shows(&r, &x), "the rewritten x is still visible");
}

/// BUG-1299: a rewrite one side recorded and undid makes the merge skip
/// every rewrite of that snapshot, another side's too. `side` holds a
/// child of `x`; A describes `x` and undoes it; B describes `x`
/// concurrently. B's rewrite should move the child (it does on
/// `integration` @ ebabc15c); `merge_plan` keys `undone` by the old
/// snapshot alone, so A's undo cancels B's rewrite: the child stays on
/// `x`, and `x` and B's `x` are both visible.
#[test]
fn bug_1299_an_undone_rewrite_does_not_cancel_another_sides_rewrite() {
    let (mut repo, fs, id) = new_repo("alice");
    repo.create_workspace("w", vec![repo.root_id()]).unwrap();
    let (x, _) = commit_in(&mut repo, "w", "x", "1\n");
    let side = repo.create_workspace("side", vec![x]).unwrap();
    drop(repo);
    let (_, x2) = concurrently(
        &fs,
        &id,
        |r| {
            r.describe(x, "x, by A").unwrap();
            r.undo().unwrap();
            assert_eq!(r.snapshot(&r.workspace_wc("side").unwrap()).unwrap().parents, vec![x], "A's undo put the child back on x");
        },
        |r| r.describe(x, "x, by B").unwrap(),
    );
    let r = open(&fs, &id);
    assert_merged(&r, 2);
    let side_now = r.workspace_wc("side").unwrap();
    assert_eq!(r.snapshot(&side_now).unwrap().change_id, r.snapshot(&side).unwrap().change_id);
    assert_eq!(r.snapshot(&side_now).unwrap().parents, vec![x2], "the child is on B's described x");
    assert!(!shows(&r, &x), "x, which B rewrote, is still visible");
}
