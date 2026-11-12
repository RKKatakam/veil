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
fn bug_1960_a_head_that_arrived_history_puts_under_another_is_dropped_after_an_operation_that_rewrote() {
    let (heads, expected) = heads_after_withheld_history_arrives(true);
    assert_eq!(heads, expected, "the old head is an ancestor of the upper head, and still a head");
}

/// The heads `old`, `other` and `upper` of [`heads_after_withheld_history_arrives`],
/// settled by a rewrite while the snapshot between `upper` and `old` is
/// withheld: the repository, the three heads, and the withheld snapshot.
fn settled_beside_withheld_history() -> (Repo, [ObjectId; 3], veil_core::Snapshot) {
    let backend: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(backend, None, "t").unwrap();
    let root = repo.root_id();
    let old = change_on(&mut repo, root, "old.txt");
    let mut other = root;
    for i in 0..6 {
        other = change_on(&mut repo, other, &format!("line{i}.txt"));
    }
    let between = foreign(&repo, vec![old], 1);
    let elsewhere = Repo::init(Arc::new(MemoryBackend::new()), None, "t").unwrap();
    let between_id = elsewhere.store().put_snapshot(&between).unwrap();
    let mut tx = repo.transaction("a pull: the upper snapshot, its parent withheld").unwrap();
    let upper = tx.repo().store().put_snapshot(&foreign(tx.repo(), vec![between_id], 2)).unwrap();
    tx.add_head(upper).unwrap();
    tx.commit().unwrap();
    let other = repo.describe(other, "described while the parent is withheld").unwrap();
    assert_eq!(heads(&repo), HashSet::from([old, other, upper]), "nothing held joins the heads yet");
    (repo, [old, other, upper], between)
}

/// BUG-1960, a pull that brings the joining history and rewrites in the
/// same transaction (as `supersede_landed` does): the transaction's own
/// writes are history that arrived since the heads were settled.
#[test]
fn bug_1960_history_that_arrives_in_the_rewriting_transaction_drops_the_head_it_puts_under_another() {
    let (mut repo, [old, other, upper], between) = settled_beside_withheld_history();
    let mut tx = repo.transaction("a pull: the withheld snapshot, and a rewrite").unwrap();
    let between_id = tx.repo().store().put_snapshot(&between).unwrap();
    let mut described = (*tx.repo().snapshot(&other).unwrap()).clone();
    described.description = veil_core::object::Text::Plain("described in the pull".into());
    let other = tx.rewrite(other, described).unwrap();
    tx.commit().unwrap();
    assert!(repo.held().snapshot(&between_id).unwrap().is_some(), "the withheld snapshot arrived");
    assert!(repo.held().ancestors(&upper).unwrap().contains(&old));
    assert_eq!(heads(&repo), HashSet::from([other, upper]), "the old head is under the upper one");
    assert_eq!(redundant_heads(&repo), Vec::<ObjectId>::new());
}

/// BUG-1960, an operation log written before the settled-heads record (an
/// operation that rewrote something, by an older `vl`, or one whose record
/// was lost, torn, or replaced by another operation's): the next rewrite
/// reads the range, and drops a head that arrived history put under
/// another.
#[test]
fn bug_1960_an_operation_without_its_settled_record_is_no_proof_the_heads_are_apart() {
    for how in ["removed", "torn", "another operation's"] {
        let (mut repo, [old, other, upper], between) = settled_beside_withheld_history();
        let backend = repo.backend().clone();
        let record = veil_core::VPath::new(&format!(".veil/index/settled/{}", repo.op_id().hex())).unwrap();
        let written = backend.read_opt(&record).unwrap().expect("the rewrite recorded its heads");
        match how {
            "removed" => backend.remove_file(&record).unwrap(),
            "torn" => backend.write(&record, &written[..written.len() - 1]).unwrap(),
            _ => {
                // A record for an operation since (one that rewrote
                // nothing), whose heads it did not settle.
                let root = repo.root_id();
                let a = change_on(&mut repo, root, "beside.txt");
                assert!(heads(&repo).contains(&a));
            }
        }
        // The record lists the withheld snapshot as missing; with it gone,
        // what joins the heads is not known to have been absent.
        repo.store().put_snapshot(&between).unwrap();
        assert!(repo.held().ancestors(&upper).unwrap().contains(&old), "{how}");
        let other = repo.describe(other, "described after it arrived").unwrap();
        assert!(!heads(&repo).contains(&old), "{how}: the old head is under the upper one, and still a head");
        assert!(heads(&repo).contains(&other) && heads(&repo).contains(&upper), "{how}");
        assert_eq!(redundant_heads(&repo), Vec::<ObjectId>::new(), "{how}");
    }
}

fn xorshift(seed: u64) -> impl FnMut(usize) -> usize {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    move |n: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state % n as u64) as usize
    }
}

/// The review of `clifast` (guarantee 3): `reachable_among_tips` answers
/// as `reachable_among` (the walk before the branch) for any history, any
/// roots and any candidates, whenever the tips it is told are apart (none
/// descends from another) and `under` holds their parents: random
/// histories with merges, fixed seeds.
#[test]
fn reachable_among_tips_answers_as_the_full_walk_for_tips_that_are_apart() {
    let mut compared = 0;
    for seed in 1..=60u64 {
        let mut next = xorshift(seed);
        let backend: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
        let repo = Repo::init(backend, None, "t").unwrap();
        let mut all = vec![repo.root_id()];
        let n = 8 + next(40);
        for i in 0..n {
            let mut parents = vec![all[next(all.len())]];
            // Mostly near the newest (long lines), sometimes anywhere, sometimes a merge.
            if next(3) > 0 {
                parents = vec![all[all.len() - 1 - next(all.len().min(3))]];
            }
            if next(5) == 0 {
                let other = all[next(all.len())];
                if !parents.contains(&other) {
                    parents.push(other);
                }
            }
            all.push(repo.store().put_snapshot(&foreign(&repo, parents, i as i64 + 1)).unwrap());
        }
        let ancestors: Vec<HashSet<ObjectId>> = all.iter().map(|id| repo.held().ancestors(id).unwrap()).collect();
        let at = |id: &ObjectId| all.iter().position(|a| a == id).unwrap();
        for round in 0..30 {
            // Tips that are apart.
            let mut tips: Vec<ObjectId> = Vec::new();
            for _ in 0..next(6) {
                let c = all[next(all.len())];
                if tips.iter().all(|t| !ancestors[at(t)].contains(&c) && !ancestors[at(&c)].contains(t)) {
                    tips.push(c);
                }
            }
            let tips: HashSet<ObjectId> = tips.into_iter().collect();
            let under: HashSet<ObjectId> = tips.iter().flat_map(|t| repo.snapshot(t).unwrap().parents.clone()).collect();
            // Candidates: some of the tips, and anything else.
            let mut candidates: HashSet<ObjectId> = tips.iter().copied().filter(|_| next(3) > 0).collect();
            for _ in 0..next(5) {
                candidates.insert(all[next(all.len())]);
            }
            // Roots: the candidates' parents (as `drop_ancestor_heads` asks), or anything.
            let roots: Vec<ObjectId> = match next(2) {
                0 => candidates.iter().flat_map(|c| repo.snapshot(c).unwrap().parents.clone()).collect(),
                _ => (0..1 + next(4)).map(|_| all[next(all.len())]).collect(),
            };
            let full = repo.held().reachable_among(roots.clone(), &candidates).unwrap();
            let short = repo.held().reachable_among_tips(roots.clone(), &candidates, &tips, &under).unwrap();
            assert_eq!(short, full, "seed {seed}, round {round}: {} snapshots, {} tips, {} candidates", all.len(), tips.len(), candidates.len());
            compared += 1;
        }
    }
    assert_eq!(compared, 60 * 30);
}

/// The review of `clifast` (guarantee 3): a random walk over every kind of
/// operation that moves heads (new changes, merges, descriptions, rebases,
/// squashes, abandons, undo, a restore to any earlier operation, history
/// that arrives above what is held, with and without a rewrite in the same
/// operation, history that arrives below a head (a withheld snapshot
/// released, with no operation or in a rewriting one: BUG-1960), a new process, two processes writing at once and their
/// merge): after every operation that rewrote something and builds on one
/// operation, no head is an ancestor of another, which is what the walk
/// before the branch left (it read every head's whole range at each such
/// operation).
#[test]
fn no_head_descends_from_another_after_a_rewrite_whatever_came_before() {
    let (mut rewrites_checked, mut merges_seen, mut reverts) = (0, 0, 0);
    for seed in 1..=50u64 {
        let mut next = xorshift(seed);
        let backend: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
        let mut repo = Repo::init(backend.clone(), None, "t").unwrap();
        let root = repo.root_id();
        let mut stamp = 0i64;
        // Snapshots withheld (known by id only), released later.
        let elsewhere = Repo::init(Arc::new(MemoryBackend::new()), None, "t").unwrap();
        let mut withheld: Vec<veil_core::Snapshot> = Vec::new();
        for step in 0..60 {
            let wc = repo.workspace_wc("default").unwrap();
            let mut free: Vec<ObjectId> = repo.held().visible().unwrap().into_iter().filter(|id| *id != root && *id != wc).collect();
            // Not one standing on a withheld snapshot (a rewrite of it reads its parent).
            free.retain(|id| repo.snapshot(id).unwrap().parents.iter().all(|p| repo.held().snapshot(p).unwrap().is_some()));
            free.sort();
            let what = if free.len() < 2 { 0 } else { next(16) };
            let pick = |next: &mut dyn FnMut(usize) -> usize| free[next(free.len())];
            match what {
                0 | 1 => {
                    let base = if free.is_empty() || next(6) == 0 { root } else { pick(&mut next) };
                    change_on(&mut repo, base, &format!("s{seed}-{step}.txt"));
                }
                2 => {
                    repo.describe(pick(&mut next), &format!("described at {step}")).unwrap();
                }
                3 => {
                    let source = pick(&mut next);
                    let dests: Vec<ObjectId> = std::iter::once(root)
                        .chain(free.iter().copied())
                        .filter(|d| !repo.held().ancestors(d).unwrap().contains(&source))
                        .collect();
                    repo.rebase(source, vec![dests[next(dests.len())]]).unwrap();
                }
                4 => {
                    repo.abandon(pick(&mut next)).unwrap();
                }
                5 => {
                    // A change with one parent that is neither the root nor the working copy's.
                    let foldable: Vec<ObjectId> = free
                        .iter()
                        .copied()
                        .filter(|id| matches!(repo.snapshot(id).unwrap().parents[..], [p] if p != root && p != wc))
                        .collect();
                    if let Some(id) = foldable.get(next(foldable.len().max(1))) {
                        repo.squash(*id).unwrap();
                    }
                }
                6 => {
                    if repo.ops().get(&repo.op_id()).unwrap().parents.len() == 1 {
                        repo.undo().unwrap();
                    }
                }
                7 => {
                    let log = repo.op_log(1000).unwrap();
                    let (op, _) = &log[next(log.len())];
                    repo.restore_operation(*op).unwrap();
                }
                8 | 9 => {
                    // History that arrives: one or two snapshots on something
                    // held, the upper one a head; with a rewrite in the same
                    // operation (9) or without (8).
                    let mut tx = repo.transaction("arrive").unwrap();
                    let mut parent = if next(4) == 0 { root } else { pick(&mut next) };
                    for _ in 0..1 + next(2) {
                        stamp += 1;
                        parent = tx.repo().store().put_snapshot(&foreign(tx.repo(), vec![parent], 1_000 + stamp)).unwrap();
                    }
                    tx.add_head(parent).unwrap();
                    if what == 9 {
                        let target = pick(&mut next);
                        let mut described = (*tx.repo().snapshot(&target).unwrap()).clone();
                        described.description = veil_core::object::Text::Plain(format!("rewritten at {step}"));
                        tx.rewrite(target, described).unwrap();
                    }
                    tx.commit().unwrap();
                }
                10 => {
                    // A merge of two changes neither of which descends from the other.
                    let a = pick(&mut next);
                    let others: Vec<ObjectId> = free
                        .iter()
                        .copied()
                        .filter(|b| !repo.held().ancestors(b).unwrap().contains(&a) && !repo.held().ancestors(&a).unwrap().contains(b))
                        .collect();
                    if let Some(b) = others.get(next(others.len().max(1))) {
                        let mut tx = repo.transaction("merge").unwrap();
                        tx.new_change(vec![a, *b], "a merge").unwrap();
                        tx.commit().unwrap();
                    }
                }
                11 | 12 => {
                    // `vl undo` and `vl redo`: a 3-way revert of what one
                    // command changed, when there is one to take back.
                    let done = match what {
                        11 => repo.undo_keeping_edits("default"),
                        _ => repo.redo_keeping_edits("default"),
                    };
                    match done {
                        Ok(_) => reverts += 1,
                        Err(e) => {
                            let e = e.to_string();
                            assert!(e.contains("nothing to") || e.contains("cannot undo") || e.contains("cannot redo") || e.contains("merges concurrent"), "seed {seed}, step {step}: {e}");
                        }
                    }
                }
                13 => {
                    // A snapshot on something held, withheld, and one on
                    // it that arrives: a head whose parent is not held.
                    stamp += 1;
                    let between = foreign(&repo, vec![pick(&mut next)], 1_000 + stamp);
                    let between_id = elsewhere.store().put_snapshot(&between).unwrap();
                    let mut tx = repo.transaction("arrive above a withheld snapshot").unwrap();
                    stamp += 1;
                    let upper = tx.repo().store().put_snapshot(&foreign(tx.repo(), vec![between_id], 1_000 + stamp)).unwrap();
                    tx.add_head(upper).unwrap();
                    tx.commit().unwrap();
                    withheld.push(between);
                }
                14 => {
                    // A withheld snapshot released: put in the store with
                    // no operation (a pull that moves no reference), or by
                    // an operation that also rewrites.
                    if !withheld.is_empty() {
                        let between = withheld.remove(next(withheld.len()));
                        if next(2) == 0 {
                            repo.store().put_snapshot(&between).unwrap();
                        } else {
                            let mut tx = repo.transaction("release and rewrite").unwrap();
                            tx.repo().store().put_snapshot(&between).unwrap();
                            let target = pick(&mut next);
                            let mut described = (*tx.repo().snapshot(&target).unwrap()).clone();
                            described.description = veil_core::object::Text::Plain(format!("rewritten at {step}"));
                            tx.rewrite(target, described).unwrap();
                            tx.commit().unwrap();
                        }
                    }
                }
                _ => {
                    // Two processes at once: each describes a change from
                    // the same state (the second in a copy of the
                    // repository, published afterwards); then a new
                    // process, which merges their operations.
                    let (a, b) = (pick(&mut next), pick(&mut next));
                    let fork: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
                    let files = |fs: &dyn StorageBackend| veil_core::vfs::walk_files(fs, &VPath::root(), &|p: &VPath| p.as_str().starts_with(".veil/local")).unwrap();
                    for f in files(&*backend) {
                        fork.write(&f, &backend.read(&f).unwrap()).unwrap();
                    }
                    repo.describe(a, &format!("first at {step}")).unwrap();
                    if a != b {
                        let mut second = Repo::open(fork.clone(), None, "t").unwrap();
                        second.describe(b, &format!("second at {step}")).unwrap();
                        drop(second);
                        for f in files(&*fork) {
                            let s = f.as_str();
                            let new = backend.metadata(&f).unwrap().is_none();
                            if new && (s.starts_with(".veil/objects/") || s.starts_with(".veil/ops/") || s.starts_with(".veil/op_heads/")) {
                                backend.write(&f, &fork.read(&f).unwrap()).unwrap();
                            }
                        }
                    }
                    repo = Repo::open(backend.clone(), None, "t").unwrap();
                }
            }
            if next(7) == 0 {
                repo = Repo::open(backend.clone(), None, "t").unwrap();
            }
            let op = repo.ops().get(&repo.op_id()).unwrap();
            merges_seen += usize::from(op.parents.len() > 1);
            if op.parents.len() == 1 && !op.rewritten.is_empty() {
                rewrites_checked += 1;
                assert_eq!(
                    redundant_heads(&repo),
                    Vec::<ObjectId>::new(),
                    "seed {seed}, step {step} (operation {what}, '{}'): a head under another head after a rewrite",
                    op.description
                );
            }
        }
    }
    assert!(rewrites_checked > 500, "the walk checked {rewrites_checked} rewrites");
    assert!(merges_seen > 20, "the walk merged concurrent operations {merges_seen} times");
    assert!(reverts > 50, "the walk undid or redid {reverts} commands");
}
