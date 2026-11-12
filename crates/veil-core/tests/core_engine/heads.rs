//! The heads of the view after a rewrite (`Transaction::drop_ancestor_heads`,
//! BUG-1830, and its cost, BUG-1944): no head is an ancestor of another, and
//! finding that out does not read the history between the newest head and
//! the oldest at every commit.

use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use veil_core::{MemoryBackend, ObjectId, Repo, StorageBackend, VPath};

/// A change with one file of its own on `base`, made without a working copy.
fn change_on(repo: &mut Repo, base: ObjectId, file: &str) -> ObjectId {
    let ws = repo.ephemeral_workspace(base).unwrap();
    ws.write(file, format!("{file}\n")).unwrap();
    repo.commit_ephemeral(&ws, file).unwrap().0
}

/// The heads, but the working copy's change (a head of its own on the
/// root in these tests, which never touch it).
fn heads(repo: &Repo) -> HashSet<ObjectId> {
    let wc = repo.workspace_wc("default").unwrap();
    repo.view().heads.iter().copied().filter(|h| *h != wc).collect()
}

/// The heads that another head descends from, by reading all the history.
fn redundant_heads(repo: &Repo) -> Vec<ObjectId> {
    let heads: HashSet<ObjectId> = repo.view().heads.iter().copied().collect();
    let mut out = Vec::new();
    for h in &heads {
        for other in &heads {
            if other != h && repo.held().ancestors(other).unwrap().contains(h) {
                out.push(*h);
                break;
            }
        }
    }
    out
}

/// Counts the objects read from the store.
#[derive(Debug, Default)]
struct Counting {
    inner: MemoryBackend,
    objects_read: AtomicUsize,
}

impl StorageBackend for Counting {
    fn kind(&self) -> &'static str {
        "memory"
    }
    fn read(&self, path: &VPath) -> veil_core::Result<Vec<u8>> {
        if path.as_str().starts_with(".veil/objects/") {
            self.objects_read.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.read(path)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> veil_core::Result<()> {
        self.inner.write(path, data)
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> veil_core::Result<bool> {
        self.inner.create_new(path, data)
    }
    fn remove_file(&self, path: &VPath) -> veil_core::Result<()> {
        self.inner.remove_file(path)
    }
    fn remove_dir_all(&self, path: &VPath) -> veil_core::Result<()> {
        self.inner.remove_dir_all(path)
    }
    fn create_dir_all(&self, path: &VPath) -> veil_core::Result<()> {
        self.inner.create_dir_all(path)
    }
    fn list_dir(&self, path: &VPath) -> veil_core::Result<Vec<veil_core::vfs::DirEntry>> {
        self.inner.list_dir(path)
    }
    fn metadata(&self, path: &VPath) -> veil_core::Result<Option<veil_core::vfs::Metadata>> {
        self.inner.metadata(path)
    }
    fn set_executable(&self, path: &VPath, executable: bool) -> veil_core::Result<()> {
        self.inner.set_executable(path, executable)
    }
}

/// BUG-1944: a rewrite at the tip of a long line, beside the head of a
/// branch left long ago, does not read the line (it did at every commit:
/// 66 ms of a 165 ms commit at 10,000 snapshots).
#[test]
fn a_rewrite_beside_an_old_head_does_not_read_the_history_between() {
    const LINE: usize = 300;
    let backend = Arc::new(Counting::default());
    let mut repo = Repo::init(backend.clone(), None, "t").unwrap();
    let root = repo.root_id();
    let old = change_on(&mut repo, root, "old.txt");
    let mut tip = root;
    for i in 0..LINE {
        tip = change_on(&mut repo, tip, &format!("f{i}.txt"));
    }
    assert_eq!(heads(&repo), HashSet::from([old, tip]));
    // The first rewrite builds on an operation that rewrote nothing: it
    // reads the range, and leaves heads known not to descend from each other.
    tip = repo.describe(tip, "first").unwrap();
    assert_eq!(heads(&repo), HashSet::from([old, tip]));

    // A new process: nothing is held in memory.
    drop(repo);
    let mut repo = Repo::open(backend.clone(), None, "t").unwrap();
    backend.objects_read.store(0, Ordering::SeqCst);
    let tip = repo.describe(tip, "second").unwrap();
    let read = backend.objects_read.load(Ordering::SeqCst);
    assert_eq!(heads(&repo), HashSet::from([old, tip]));
    assert_eq!(repo.snapshot(&tip).unwrap().description, veil_core::object::Text::Plain("second".into()));
    assert!(read < LINE / 4, "the rewrite read {read} objects: the line of {LINE} snapshots between the old head and the tip");
}

/// A head the transaction makes an ancestor of a new head, by any route,
/// is dropped when the heads it started from are known (the operation
/// before rewrote something) exactly as when they are not.
#[test]
fn an_old_head_under_a_new_one_is_dropped_whatever_the_operation_before_was() {
    for settled in [false, true] {
        let backend: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
        let mut repo = Repo::init(backend, None, "t").unwrap();
        let root = repo.root_id();
        let old = change_on(&mut repo, root, "old.txt");
        let mut other = change_on(&mut repo, root, "other.txt");
        if settled {
            other = repo.describe(other, "other, described").unwrap();
        }
        assert_eq!(heads(&repo), HashSet::from([old, other]), "settled: {settled}");
        // Two snapshots on the old head, not through the transaction (as
        // history that arrives): the second becomes a head, its parent is
        // no head to remove.
        let mut tx = repo.transaction("arrive and rewrite").unwrap();
        let tree = tx.repo().store().empty_tree().unwrap();
        let mut parent = old;
        for i in 0..2i64 {
            parent = tx
                .repo()
                .store()
                .put_snapshot(&veil_core::Snapshot {
                    parents: vec![parent],
                    change_id: veil_core::ChangeId::random(),
                    tree,
                    description: veil_core::object::Text::default(),
                    author: "t".into(),
                    timestamp: veil_core::now_millis() + i,
                    predecessors: vec![],
                    conflicts: vec![],
                    embargo: None,
                    agent: None,
                    abandoned: None,
                    attempts: vec![],
                    signature: None,
                })
                .unwrap();
        }
        tx.add_head(parent).unwrap();
        let mut described = (*tx.repo().snapshot(&other).unwrap()).clone();
        described.description = veil_core::object::Text::Plain("other, again".into());
        let other = tx.rewrite(other, described).unwrap();
        tx.commit().unwrap();
        assert_eq!(heads(&repo), HashSet::from([parent, other]), "settled: {settled}: the old head is under the new one");
        assert!(repo.held().visible().unwrap().contains(&old));
    }
}

/// BUG-1830's case after an operation that rewrote something: the parent a
/// rebase leaves becomes a head only when nothing else descends from it,
/// however far above it the other descendant's head is.
#[test]
fn a_parent_left_by_a_rebase_is_a_head_only_without_other_descendants() {
    let backend: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(backend, None, "t").unwrap();
    let root = repo.root_id();
    let a = change_on(&mut repo, root, "a.txt");
    let b = change_on(&mut repo, a, "b.txt");
    // A line of three above A, beside B.
    let mut line = a;
    for i in 0..3 {
        line = change_on(&mut repo, line, &format!("line{i}.txt"));
    }
    let c = change_on(&mut repo, root, "c.txt");
    let c = repo.describe(c, "c, described").unwrap();
    assert_eq!(heads(&repo), HashSet::from([b, line, c]));

    // B moves away: A is left, and the line still descends from it.
    let b = repo.rebase(b, vec![c]).unwrap();
    assert_eq!(repo.snapshot(&b).unwrap().parents, vec![c]);
    assert_eq!(heads(&repo), HashSet::from([b, line]), "A is under the line's head");
    assert!(repo.held().visible().unwrap().contains(&a));

    // The line's head moves away too (the operation before rewrote B): what
    // it stood on is left with no other descendant, and is a head.
    let under = repo.snapshot(&line).unwrap().parents[0];
    let line = repo.rebase(line, vec![b]).unwrap();
    assert_eq!(repo.snapshot(&line).unwrap().parents, vec![b]);
    assert_eq!(heads(&repo), HashSet::from([line, under]));
    assert!(repo.held().visible().unwrap().contains(&a));
}

/// A head that another already descended from before the transaction (left
/// by an operation that rewrote nothing) is dropped by the next rewrite,
/// as before.
#[test]
fn a_head_left_under_another_by_an_operation_without_rewrites_is_dropped_by_the_next_rewrite() {
    let backend: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(backend, None, "t").unwrap();
    let root = repo.root_id();
    let old = change_on(&mut repo, root, "old.txt");
    let other = change_on(&mut repo, root, "other.txt");
    let mut tx = repo.transaction("arrive").unwrap();
    let tree = tx.repo().store().empty_tree().unwrap();
    let mut parent = old;
    for i in 0..2i64 {
        parent = tx
            .repo()
            .store()
            .put_snapshot(&veil_core::Snapshot {
                parents: vec![parent],
                change_id: veil_core::ChangeId::random(),
                tree,
                description: veil_core::object::Text::default(),
                author: "t".into(),
                timestamp: veil_core::now_millis() + i,
                predecessors: vec![],
                conflicts: vec![],
                embargo: None,
                agent: None,
                abandoned: None,
                attempts: vec![],
                signature: None,
            })
            .unwrap();
    }
    tx.add_head(parent).unwrap();
    tx.commit().unwrap();
    assert_eq!(heads(&repo), HashSet::from([old, other, parent]), "nothing was rewritten: the old head stays");

    let other = repo.describe(other, "other, described").unwrap();
    assert_eq!(heads(&repo), HashSet::from([other, parent]));
    // And the next rewrite, which starts from heads known apart, keeps them.
    let other = repo.describe(other, "other, again").unwrap();
    assert_eq!(heads(&repo), HashSet::from([other, parent]));
}

/// A random walk of new changes, descriptions, rebases and abandons (fixed
/// seeds): after every operation no head is an ancestor of another, and no
/// change left the view but the abandoned ones.
#[test]
fn no_head_descends_from_another_after_any_sequence_of_rewrites() {
    for seed in 1..=40u64 {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut next = |n: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % n as u64) as usize
        };
        let backend: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
        let mut repo = Repo::init(backend, None, "t").unwrap();
        let root = repo.root_id();
        // Changes by change id: what is visible is compared by change, as
        // rewrites replace snapshots.
        let mut live: HashSet<veil_core::ChangeId> = HashSet::new();
        for step in 0..40 {
            let mut visible: Vec<ObjectId> = repo.held().visible().unwrap().into_iter().filter(|id| *id != root).collect();
            visible.sort();
            // The working copy's change is the workspace's: left where it is.
            let wc = repo.workspace_wc("default").unwrap();
            let free: Vec<ObjectId> = visible.iter().copied().filter(|id| *id != wc).collect();
            let what = if free.is_empty() { 0 } else { next(4) };
            match what {
                0 => {
                    let base = if free.is_empty() { root } else { free[next(free.len())] };
                    let id = change_on(&mut repo, base, &format!("s{seed}-{step}.txt"));
                    live.insert(repo.snapshot(&id).unwrap().change_id);
                }
                1 => {
                    let id = free[next(free.len())];
                    repo.describe(id, &format!("described at {step}")).unwrap();
                }
                2 => {
                    let source = free[next(free.len())];
                    // Onto something that does not descend from the source.
                    let dests: Vec<ObjectId> = std::iter::once(root)
                        .chain(free.iter().copied())
                        .filter(|d| !repo.held().ancestors(d).unwrap().contains(&source))
                        .collect();
                    let dest = dests[next(dests.len())];
                    repo.rebase(source, vec![dest]).unwrap();
                }
                _ => {
                    let id = free[next(free.len())];
                    live.remove(&repo.snapshot(&id).unwrap().change_id);
                    repo.abandon(id).unwrap();
                }
            }
            assert_eq!(redundant_heads(&repo), Vec::<ObjectId>::new(), "seed {seed}, step {step} (operation {what}): a head under another head");
            let seen: HashSet<veil_core::ChangeId> =
                repo.held().visible().unwrap().iter().map(|id| repo.snapshot(id).unwrap().change_id).collect();
            for c in &live {
                assert!(seen.contains(c), "seed {seed}, step {step} (operation {what}): change {} left the view", c.short());
            }
        }
    }
}

/// A snapshot on `parents` with the empty tree, as history from elsewhere.
fn foreign(repo: &Repo, parents: Vec<ObjectId>, at: i64) -> veil_core::Snapshot {
    veil_core::Snapshot {
        parents,
        change_id: veil_core::ChangeId([at as u8; 16]),
        tree: repo.store().empty_tree().unwrap(),
        description: veil_core::object::Text::default(),
        author: "t".into(),
        timestamp: 1_700_000_000_000 + at,
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        agent: None,
        abandoned: None,
        attempts: vec![],
        signature: None,
    }
}

/// The review of `clifast` (guarantee 3, "history that arrives later"): two
/// heads that a withheld snapshot stands between (the source of an
/// unreleased embargo: `Held` reads `None` for it) are both heads, rightly,
/// while it is withheld. When it arrives (the release, pulled: no head
/// moves, so no operation need be recorded), the lower head is an ancestor
/// of the upper one, and the next rewrite drops it: `drop_ancestor_heads`
/// read the range at every rewrite. With `settled_heads` the rewrite takes
/// the heads it started from as known apart, because the operation before
/// it rewrote something, and the lower head stays a head at every later
/// rewrite (every `vl commit` is one).
///
/// `settled`: whether a rewrite was recorded while the snapshot was
/// withheld (the heads are then "known apart" when it arrives).
fn heads_after_withheld_history_arrives(settled: bool) -> (HashSet<ObjectId>, HashSet<ObjectId>) {
    let backend: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(backend, None, "t").unwrap();
    let root = repo.root_id();
    let old = change_on(&mut repo, root, "old.txt");
    // A line beside it, whose tip the rewrites below describe: higher than
    // everything else here, as a working copy's change is.
    let mut other = root;
    for i in 0..6 {
        other = change_on(&mut repo, other, &format!("line{i}.txt"));
    }
    // `between` stands on the old head and is withheld: known by its id
    // (what another repository names it) as the parent of `upper`.
    let between = foreign(&repo, vec![old], 1);
    let elsewhere = Repo::init(Arc::new(MemoryBackend::new()), None, "t").unwrap();
    let between_id = elsewhere.store().put_snapshot(&between).unwrap();
    let mut tx = repo.transaction("a pull: the upper snapshot, its parent withheld").unwrap();
    let upper = tx.repo().store().put_snapshot(&foreign(tx.repo(), vec![between_id], 2)).unwrap();
    tx.add_head(upper).unwrap();
    tx.commit().unwrap();
    assert!(repo.held().snapshot(&between_id).unwrap().is_none(), "withheld");
    assert_eq!(heads(&repo), HashSet::from([old, other, upper]));
    if settled {
        other = repo.describe(other, "described while the parent is withheld").unwrap();
        assert_eq!(heads(&repo), HashSet::from([old, other, upper]), "nothing held joins the heads yet");
    }

    // The withheld snapshot arrives; no reference moves.
    assert_eq!(repo.store().put_snapshot(&between).unwrap(), between_id);
    assert!(repo.held().ancestors(&upper).unwrap().contains(&old), "the old head is under the upper one now");

    let other = repo.describe(other, "described after it arrived").unwrap();
    (heads(&repo), HashSet::from([other, upper]))
}

/// The reference: the first rewrite after the history arrived, on an
/// operation that rewrote nothing, drops the head that is now under another.
#[test]
fn a_head_that_arrived_history_puts_under_another_is_dropped_by_the_next_rewrite() {
    let (heads, expected) = heads_after_withheld_history_arrives(false);
    assert_eq!(heads, expected);
}

#[test]
#[ignore = "BUG-1960: a head that history arriving later (a withheld parent, released) puts under another head stays a head at every later rewrite, when the operation before rewrote something"]
fn bug_1960_a_head_that_arrived_history_puts_under_another_is_dropped_after_an_operation_that_rewrote() {
    let (heads, expected) = heads_after_withheld_history_arrives(true);
    assert_eq!(heads, expected, "the old head is an ancestor of the upper head, and still a head");
}
