//! Adversarial pass on the lock-free op log (scale stream O): what the
//! threat-review tests in `oplog_concurrency` miss. Each test is the
//! reproduction of a `docs/BUGS.md` row ("Scale round: adversarial pass on
//! stream O").

use crate::adversarial_support;
use crate::oplog_concurrency::{assert_fsck_clean, concurrently, open};

use adversarial_support::*;
use veil_core::{
    oplog::{Operation, Tag, View, OP_HEADS_DIR},
    ObjectId, StorageBackend,
};

/// Write an operation with the given parents, timestamp and view, as a
/// process would publish it, and return its id.
fn put_op(repo: &veil_core::Repo, parents: Vec<ObjectId>, timestamp: i64, view: View, description: &str) -> ObjectId {
    repo.ops()
        .put(&Operation {
            parents,
            timestamp,
            user: "alice".into(),
            description: description.into(),
            view,
            manual_undo: None,
            undo_of: None,
            redo_of: None,
            workspace: None,
            rewritten: Default::default(),
            restore_of: None,
        })
        .unwrap()
}

fn head_file(id: &ObjectId) -> veil_core::VPath {
    p(&format!("{OP_HEADS_DIR}/{}", id.hex()))
}

// ---- an undone rewrite is applied again by the next merge ----------------------------

/// `vl abandon X; vl undo` in one workspace while anything else (here a tag
/// set) lands concurrently: the merge re-applies the undone abandon, and the
/// working copy loses X again.
#[test]
fn undone_abandon_is_not_redone_by_a_concurrent_merge() {
    let (mut repo, fs, id) = new_repo("alice");
    repo.set_command_workspace(Some(WS.into()));
    let base = commit_files(&mut repo, &*fs, &[("f", "1\n")], "base");
    let x = commit_files(&mut repo, &*fs, &[("x.txt", "X-CONTENT-ABANDONED-THEN-RESTORED\n")], "x");
    drop(repo);
    concurrently(
        &fs,
        &id,
        |r| {
            r.set_command_workspace(Some(WS.into()));
            r.abandon(x).unwrap();
            let (_, undone) = r.undo_keeping_edits(WS).unwrap();
            assert!(undone.starts_with("abandon"), "{undone}");
            let wc = r.workspace_wc(WS).unwrap();
            assert!(r.is_ancestor(&x, &wc).unwrap(), "the undo itself restored X");
        },
        |r| r.set_tag("unrelated", base, false).unwrap(),
    );
    let r = open(&fs, &id);
    let wc = r.workspace_wc(WS).unwrap();
    assert!(r.view().tags.contains_key("unrelated"));
    assert!(r.is_ancestor(&x, &wc).unwrap(), "the merge abandoned X again after its abandon was undone");
    assert_eq!(read_at(&r, &wc, "x.txt"), b"X-CONTENT-ABANDONED-THEN-RESTORED\n");
    assert_fsck_clean(fs.clone(), &id, "after the merge");
}

/// The same with an amend (`vl describe`): the undone rewrite comes back,
/// and the working copy moves onto the amended change the user undid.
#[test]
fn undone_amend_is_not_redone_by_a_concurrent_merge() {
    let (mut repo, fs, id) = new_repo("alice");
    repo.set_command_workspace(Some(WS.into()));
    let base = commit_files(&mut repo, &*fs, &[("f", "1\n")], "base");
    let x = commit_files(&mut repo, &*fs, &[("x.txt", "x\n")], "x");
    drop(repo);
    concurrently(
        &fs,
        &id,
        |r| {
            r.set_command_workspace(Some(WS.into()));
            r.describe(x, "x, amended then undone").unwrap();
            r.undo_keeping_edits(WS).unwrap();
            let wc = r.workspace_wc(WS).unwrap();
            assert_eq!(r.snapshot(&wc).unwrap().parents, vec![x], "the undo itself restored X");
        },
        |r| r.set_tag("unrelated", base, false).unwrap(),
    );
    let r = open(&fs, &id);
    let wc = r.workspace_wc(WS).unwrap();
    assert_eq!(r.snapshot(&wc).unwrap().parents, vec![x], "the merge re-applied the undone amend");
}

// ---- the merge base is lost when one side's history spans more than an hour -------

/// A command that ran for over an hour (a long pull, a suspended `vl`)
/// lands beside a line of commands that started right after it did. The
/// ancestry walk gives up an hour below the newest heads, so the merge finds
/// no common operation and merges against an empty view: a tag deleted on
/// one side comes back (and is pushed by the next `vl push`).
#[test]
fn merge_base_is_found_below_the_ancestry_slack() {
    let (mut repo, fs, id) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("f", "1\n")], "base");
    repo.set_tag("withdrawn", base, false).unwrap();
    let h = repo.heads()[0];
    let hop = repo.ops().get(&h).unwrap();
    let t0 = hop.timestamp;
    const HOUR: i64 = 60 * 60 * 1000;
    // One side: a minute after H, the tag is deleted; two hours later,
    // another command.
    let mut v1 = hop.view.clone();
    v1.tags.remove("withdrawn");
    let a1 = put_op(&repo, vec![h], t0 + 60_000, v1.clone(), "delete tag withdrawn");
    let mut v2 = v1.clone();
    v2.tags.insert("a".into(), Tag::new(base));
    let o1 = put_op(&repo, vec![a1], t0 + 2 * HOUR, v2, "set tag a");
    // The other: one long command that started from H.
    let mut v3 = hop.view.clone();
    v3.tags.insert("b".into(), Tag::new(base));
    let o2 = put_op(&repo, vec![h], t0 + 2 * HOUR + 1, v3, "pull from origin");
    drop(repo);
    fs.remove_file(&head_file(&h)).unwrap();
    fs.write(&head_file(&o1), b"").unwrap();
    fs.write(&head_file(&o2), b"").unwrap();
    let r = open(&fs, &id);
    let tags = &r.view().tags;
    assert!(tags.contains_key("a") && tags.contains_key("b"), "{:?}", tags.keys());
    assert!(!tags.contains_key("withdrawn"), "a deleted tag came back: the merge used an empty base");
}

// ---- a merge that fails for a policy reason, forever --------------------------------

/// A side commit in `ws` on top of its working copy: write `files` there,
/// record and commit. Returns the commit.
fn commit_in(r: &mut veil_core::Repo, ws: &str, files: &[(&str, &str)], msg: &str) -> ObjectId {
    let ov = r.workspace_overlay(ws).unwrap();
    for (path, data) in files {
        ov.write(&p(path), data.as_bytes()).unwrap();
    }
    r.snapshot_workspace(ws, &ov).unwrap();
    r.commit_working_copy(ws, msg).unwrap().0
}

/// One side moves change Y onto an embargoed merge (Y joins embargo E1);
/// the other, at the same time, merges a second fix into Y's line under its
/// own embargo E2. Each is allowed on its own view. Merging the two heads
/// must never fail every later command, and neither fix may leave the
/// repository before its release.
#[test]
fn merge_combining_two_embargoes_degrades_instead_of_failing_forever() {
    let (mut repo, fs, id) = new_repo("alice");
    let v1 = commit_files(&mut repo, &*fs, &[("a.c", "v\n")], "v1");
    repo.set_tag("main", v1, false).unwrap();
    for ws in ["rel", "fix1", "fix2"] {
        repo.create_workspace(ws, vec![v1]).unwrap();
    }
    let y = commit_in(&mut repo, "rel", &[("rel.c", "release line\n")], "y");
    let fix1 = commit_in(&mut repo, "fix1", &[("FIXONE-NAME-Q4.c", "FIXONE-BODY-Q4\n")], "fix one");
    let fix2 = commit_in(&mut repo, "fix2", &[("FIXTWO-NAME-Q4.c", "FIXTWO-BODY-Q4\n")], "fix two");
    drop(repo);
    let spec = || Some(veil_core::commands::EmbargoSpec { scope: "team".into(), until: None });
    concurrently(
        &fs,
        &id,
        |r| {
            let m1 = r.merge(WS, v1, vec![fix1], "embargoed one", spec()).unwrap().snapshot;
            r.rebase(y, vec![m1]).unwrap();
        },
        |r| {
            r.merge("rel", y, vec![fix2], "embargoed two", spec()).unwrap();
        },
    );
    let mut r = veil_core::Repo::open(fs.clone(), Some(id.clone()), &id.name).expect("every command fails: the merge of the heads fails");
    let w = r.take_warnings();
    for msg in &w {
        assert!(!msg.contains("FIXONE") && !msg.contains("FIXTWO"), "a warning names a fix: {msg}");
    }
    let (c, _) = r.commit_working_copy(WS, "later").unwrap();
    r.set_tag("later", c, false).unwrap();
    let mirror = std::sync::Arc::new(veil_core::MemoryBackend::new());
    veil_core::remote::push(&mut r, mirror.clone(), true, &[], false).unwrap();
    for n in ["FIXONE-NAME-Q4", "FIXONE-BODY-Q4", "FIXTWO-NAME-Q4", "FIXTWO-BODY-Q4"] {
        assert!(backend_contains(&*mirror, n.as_bytes()).is_empty(), "{n} reached the public remote");
    }
    assert_fsck_clean(fs.clone(), &id, "after the merge");
}

/// The same empty-base merge through pruning: a long command started from
/// operation H; meanwhile two commands landed (a tag deleted, a tag set) and
/// `vl gc --keep-ops-days 0` pruned H (it keeps the heads and their
/// parents only). The long command then publishes an operation whose parent
/// is gone, and the merge has no common operation: the deleted tag returns.
#[test]
fn transaction_whose_base_was_pruned_does_not_merge_against_nothing() {
    let (mut repo, fs, id) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("f", "1\n")], "base");
    repo.set_tag("withdrawn", base, false).unwrap();
    drop(repo);
    let mut long = open(&fs, &id);
    let mut tx = long.transaction("pull from origin").unwrap();
    tx.view.tags.insert("pulled".into(), Tag::new(base));
    {
        let mut other = open(&fs, &id);
        other.delete_tag("withdrawn").unwrap();
        other.set_tag("a", base, false).unwrap();
        let mut g = open(&fs, &id);
        let opts = veil_core::gc::GcOptions {
            keep_ops: Some(std::time::Duration::ZERO),
            // A minute later: every operation is older than the window.
            now: Some(veil_core::now_millis() + 60_000),
            ..Default::default()
        };
        let r = veil_core::gc::gc(&mut g, &opts).unwrap();
        // While `tx` holds its registration, gc's fence waits and defers pruning.
        assert!(r.deferred.is_some(), "{r:?}");
        assert_eq!(r.ops_pruned, 0, "{r:?}");
    }
    let committed = tx.commit().unwrap();
    assert!(committed.is_some());
    drop(long);
    let r = open(&fs, &id);
    let tags = &r.view().tags;
    assert!(!tags.contains_key("withdrawn"), "a deleted tag came back (commit: {committed:?})");
    assert!(tags.contains_key("a") && tags.contains_key("pulled"));

    // And if the base operation actually WAS pruned while a transaction was in
    // flight (e.g. its registration was missing), `recheck` refuses to publish
    // an operation whose parent is gone.
    let mut long2 = open(&fs, &id);
    let mut tx2 = long2.transaction("pull again").unwrap();
    tx2.view.tags.insert("pulled2".into(), Tag::new(base));
    for e in fs.list_dir(&p(".veil/objects/incoming")).unwrap_or_default() {
        if e.name.starts_with(veil_core::maintenance::LIVE_PREFIX) {
            fs.remove_dir_all(&p(&format!(".veil/objects/incoming/{}", e.name))).unwrap();
        }
    }
    {
        let mut other = open(&fs, &id);
        other.set_tag("b", base, false).unwrap();
        other.set_tag("c", base, false).unwrap();
        let (fs2, id2) = (fs.clone(), id.clone());
        let r = std::thread::spawn(move || {
            let mut g = open(&fs2, &id2);
            let opts = veil_core::gc::GcOptions {
                keep_ops: Some(std::time::Duration::ZERO),
                now: Some(veil_core::now_millis() + 120_000),
                ..Default::default()
            };
            veil_core::gc::gc(&mut g, &opts).unwrap()
        })
        .join()
        .unwrap();
        assert!(r.ops_pruned > 0, "{r:?}");
    }
    let e = tx2.commit().unwrap_err();
    assert!(e.to_string().contains("run the command again"), "{e}");
}

// ---- the compare-and-swap of a recording is not atomic -----------------------------

/// A disk that stops one thread (named `recorder-a`) right before it creates
/// an op head file, until released: the gap between a transaction's
/// compare-and-swap check (`recheck`) and its publication.
#[derive(Debug)]
struct PublishGate {
    inner: std::sync::Arc<veil_core::MemoryBackend>,
    armed: std::sync::atomic::AtomicBool,
    at: (std::sync::Mutex<bool>, std::sync::Condvar),
    go: (std::sync::Mutex<bool>, std::sync::Condvar),
}

impl PublishGate {
    fn wait(flag: &(std::sync::Mutex<bool>, std::sync::Condvar)) {
        let mut g = flag.0.lock().unwrap();
        while !*g {
            g = flag.1.wait(g).unwrap();
        }
    }
    fn set(flag: &(std::sync::Mutex<bool>, std::sync::Condvar)) {
        *flag.0.lock().unwrap() = true;
        flag.1.notify_all();
    }
}

impl StorageBackend for PublishGate {
    fn kind(&self) -> &'static str {
        "gate"
    }
    fn read(&self, path: &veil_core::VPath) -> veil_core::Result<Vec<u8>> {
        self.inner.read(path)
    }
    fn write(&self, path: &veil_core::VPath, data: &[u8]) -> veil_core::Result<()> {
        self.inner.write(path, data)
    }
    fn create_new(&self, path: &veil_core::VPath, data: &[u8]) -> veil_core::Result<bool> {
        let me = std::thread::current().name() == Some("recorder-a");
        if me && path.as_str().starts_with(OP_HEADS_DIR) && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            Self::set(&self.at);
            Self::wait(&self.go);
        }
        self.inner.create_new(path, data)
    }
    /// A staged head file renamed into `op_heads/` (format 6): the same
    /// moment as `create_new` above.
    fn rename_unsynced(&self, from: &veil_core::VPath, to: &veil_core::VPath) -> veil_core::Result<()> {
        let me = std::thread::current().name() == Some("recorder-a");
        if me && to.as_str().starts_with(OP_HEADS_DIR) && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            Self::set(&self.at);
            Self::wait(&self.go);
        }
        self.inner.rename_unsynced(from, to)
    }
    fn remove_file(&self, path: &veil_core::VPath) -> veil_core::Result<()> {
        self.inner.remove_file(path)
    }
    fn remove_dir_all(&self, path: &veil_core::VPath) -> veil_core::Result<()> {
        self.inner.remove_dir_all(path)
    }
    fn create_dir_all(&self, path: &veil_core::VPath) -> veil_core::Result<()> {
        self.inner.create_dir_all(path)
    }
    fn list_dir(&self, path: &veil_core::VPath) -> veil_core::Result<Vec<veil_core::vfs::DirEntry>> {
        self.inner.list_dir(path)
    }
    fn metadata(&self, path: &veil_core::VPath) -> veil_core::Result<Option<veil_core::vfs::Metadata>> {
        self.inner.metadata(path)
    }
    fn set_executable(&self, path: &veil_core::VPath, x: bool) -> veil_core::Result<()> {
        self.inner.set_executable(path, x)
    }
}

/// Two recorders of one directory in one process (threads of `vl serve`,
/// an embedder): A scans and passes its compare-and-swap check, then B
/// scans (seeing A's edit and its own), checks and publishes, then A
/// publishes over the workspace B already moved. The merge keeps one
/// working copy and warns: B's edit is out of the workspace (BUG-801's
/// `racing_snapshots_of_one_directory_lose_nothing` fails this way about
/// once in 50 runs under load).
#[test]
fn two_recorders_of_one_workspace_never_both_publish() {
    use std::sync::{atomic::AtomicBool, Arc, Condvar, Mutex};
    let id = veil_core::Identity::generate("alice");
    let gate = Arc::new(PublishGate {
        inner: Arc::new(veil_core::MemoryBackend::new()),
        armed: AtomicBool::new(false),
        at: (Mutex::new(false), Condvar::new()),
        go: (Mutex::new(false), Condvar::new()),
    });
    let fs: Arc<dyn StorageBackend> = gate.clone();
    let mut init = veil_core::Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap();
    init.snapshot_workspace(WS, &*fs).unwrap();
    drop(init);
    gate.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    fs.write(&p("file-a"), b"from A\n").unwrap();
    let a = {
        let (fs, id) = (fs.clone(), id.clone());
        std::thread::Builder::new()
            .name("recorder-a".into())
            .spawn(move || {
                let mut r = veil_core::Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
                r.snapshot_workspace(WS, &*fs).unwrap()
            })
            .unwrap()
    };
    PublishGate::wait(&gate.at);
    fs.write(&p("file-b"), b"from B\n").unwrap();
    let b = {
        let (fs, id) = (fs.clone(), id.clone());
        std::thread::spawn(move || {
            let mut r = veil_core::Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
            r.snapshot_workspace(WS, &*fs).unwrap()
        })
    };
    // B either finishes (it was not held back) or waits for A.
    let t = std::time::Instant::now();
    while !b.is_finished() && t.elapsed() < std::time::Duration::from_secs(2) {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    PublishGate::set(&gate.go);
    a.join().unwrap();
    b.join().unwrap();
    let mut r = veil_core::Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
    let w = r.take_warnings();
    assert!(!w.iter().any(|w| w.contains("moved by concurrent commands")), "both recordings published: {w:?}");
    let wc = r.workspace_wc(WS).unwrap();
    assert_eq!(read_at(&r, &wc, "file-a"), b"from A\n");
    assert_eq!(read_at(&r, &wc, "file-b"), b"from B\n", "B's edit is not in the working copy");
}

/// BUG-942/943 through concurrent operations: one side abandons the
/// embargoed merge (nothing is built on it in its view, so it may), while
/// the other commits a follow-up on the merge. Merging the two heads would
/// rebase the follow-up onto the merge's parents, holding the fix with no
/// embargoed ancestor: the merge drops the abandon instead, and the fix
/// stays withheld.
#[test]
fn a_concurrent_abandon_of_the_embargoed_merge_never_unwithholds_its_fix() {
    let (mut repo, fs, id) = new_repo("alice");
    let v1 = commit_files(&mut repo, &*fs, &[("a.c", "v\n")], "v1");
    repo.set_tag("main", v1, false).unwrap();
    repo.create_workspace("fix", vec![v1]).unwrap();
    let fix = commit_in(&mut repo, "fix", &[("FIX-NAME-Q5.c", "FIX-BODY-Q5\n")], "fix");
    let spec = Some(veil_core::commands::EmbargoSpec { scope: "team".into(), until: None });
    let m = repo.merge(WS, v1, vec![fix], "embargoed", spec).unwrap().snapshot;
    repo.edit(WS, v1).unwrap();
    drop(repo);
    concurrently(
        &fs,
        &id,
        |r| r.abandon(m).unwrap(),
        |r| {
            r.create_workspace("w2", vec![m]).unwrap();
            commit_in(r, "w2", &[("follow.c", "f\n")], "follow-up");
        },
    );
    let mut r = veil_core::Repo::open(fs.clone(), Some(id.clone()), &id.name).unwrap();
    let w2 = r.workspace_wc("w2").unwrap();
    assert!(veil_core::remote::embargo_blocks(&r, &[w2]).unwrap()[0].is_some(), "the follow-up no longer builds on the embargoed merge");
    r.set_tag("later", w2, false).unwrap();
    let mirror = std::sync::Arc::new(veil_core::MemoryBackend::new());
    veil_core::remote::push(&mut r, mirror.clone(), true, &[], false).unwrap();
    for n in ["FIX-NAME-Q5", "FIX-BODY-Q5"] {
        assert!(backend_contains(&*mirror, n.as_bytes()).is_empty(), "{n} reached the public remote");
    }
}
