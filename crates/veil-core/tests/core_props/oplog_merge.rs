//! Merging concurrent operations (the lock-free op log, format 6): the
//! 3-way merge of views loses no update (threat 1), never widens an
//! audience by dropping a cloak (threat 20), and never tears a release tag
//! from its annotation (threat 21).

use std::{collections::BTreeMap, sync::Arc};

use proptest::prelude::*;
use veil_core::{
    oplog::{merge_views, revert_views, shared_base, Introduced, Tag, View, WorkspaceState, OP_HEADS_DIR},
    Identity, MemoryBackend, ObjectId, Repo, StorageBackend, VPath,
};

fn id(n: u8) -> ObjectId {
    ObjectId([n; 32])
}

fn no_descent(_: &ObjectId, _: &ObjectId) -> bool {
    false
}

#[derive(Clone, Debug)]
enum Edit {
    SetTag(u8, u8),
    DeleteTag(u8),
    MoveWs(u8, u8),
    AddHead(u8),
}

fn edit() -> impl Strategy<Value = Edit> {
    prop_oneof![
        (0..4u8, 1..9u8).prop_map(|(t, x)| Edit::SetTag(t, x)),
        (0..4u8).prop_map(Edit::DeleteTag),
        (0..3u8, 1..9u8).prop_map(|(w, x)| Edit::MoveWs(w, x)),
        (10..20u8).prop_map(Edit::AddHead),
    ]
}

fn base_view() -> View {
    let mut v = View::default();
    v.heads.insert(id(1));
    for t in 0..2u8 {
        v.tags.insert(format!("t{t}"), Tag::new(id(1)));
    }
    for w in 0..3u8 {
        v.workspaces.insert(format!("w{w}"), WorkspaceState { wc: id(2), id: None });
    }
    v
}

fn apply(v: &mut View, edits: &[Edit]) {
    for e in edits {
        match e {
            Edit::SetTag(t, x) => {
                v.tags.insert(format!("t{t}"), Tag::new(id(*x)));
            }
            Edit::DeleteTag(t) => {
                v.tags.remove(&format!("t{t}"));
            }
            Edit::MoveWs(w, x) => {
                v.workspaces.get_mut(&format!("w{w}")).unwrap().wc = id(*x);
            }
            Edit::AddHead(h) => {
                v.heads.insert(id(*h));
            }
        }
    }
}

/// The sequential per-key model: a key one side changed takes that side's
/// value; changed by both, the first side's (a removal loses to a change).
fn model<T: Copy + PartialEq>(base: Option<T>, a: Option<T>, b: Option<T>) -> Option<T> {
    let ca = a != base;
    let cb = b != base;
    match (ca, cb) {
        (false, false) => base,
        (true, false) => a,
        (false, true) => b,
        (true, true) => a.or(b),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

    /// Threat 1: every side's change of a key is in the merged view, unless
    /// the other side changed the same key, in which case one wins and the
    /// loser's target stays visible.
    #[test]
    fn merge_views_matches_sequential_model(ea in prop::collection::vec(edit(), 0..8), eb in prop::collection::vec(edit(), 0..8)) {
        let base = base_view();
        let (mut a, mut b) = (base.clone(), base.clone());
        apply(&mut a, &ea);
        apply(&mut b, &eb);
        let m = merge_views(&base, &[&a, &b], &mut no_descent).view;
        let names: std::collections::BTreeSet<String> = base.tags.keys().chain(a.tags.keys()).chain(b.tags.keys()).cloned().collect();
        for n in names {
            let want = model(base.tags.get(&n).map(|t| t.target), a.tags.get(&n).map(|t| t.target), b.tags.get(&n).map(|t| t.target));
            prop_assert_eq!(m.tags.get(&n).map(|t| t.target), want, "tag {}", n);
            // A losing target stays visible.
            for side in [&a, &b] {
                if let Some(t) = side.tags.get(&n) {
                    if Some(t.target) != want && Some(t) != base.tags.get(&n) {
                        prop_assert!(m.heads.contains(&t.target), "tag {}: the losing target {} was dropped", n, t.target.short());
                    }
                }
            }
        }
        for w in base.workspaces.keys() {
            let want = model(base.workspaces.get(w).map(|s| s.wc), a.workspaces.get(w).map(|s| s.wc), b.workspaces.get(w).map(|s| s.wc));
            prop_assert_eq!(m.workspaces.get(w).map(|s| s.wc), want);
        }
        for h in a.heads.iter().chain(b.heads.iter()).filter(|h| !base.heads.contains(h)) {
            prop_assert!(m.heads.contains(h), "added head dropped");
        }
        // Deterministic, whatever side order the merge sees? The first side
        // wins conflicts: swapping sides may change winners, never drops a
        // change nobody else made.
        let swapped = merge_views(&base, &[&b, &a], &mut no_descent).view;
        for (n, t) in &m.tags {
            if a.tags.get(n) == b.tags.get(n) {
                prop_assert_eq!(swapped.tags.get(n), Some(t));
            }
        }
    }
}

/// Threat 21: a release tag's target and annotation stay one unit.
#[test]
fn release_tag_never_torn() {
    let base = View::default();
    let release = |target: u8, ann: u8| {
        let mut v = View::default();
        v.tags.insert("v1".into(), Tag { target: id(target), annotation: Some(id(ann)) });
        v
    };
    let (a, b) = (release(1, 11), release(2, 12));
    let mut ordinary = View::default();
    ordinary.tags.insert("v1".into(), Tag::new(id(3)));
    for sides in [[&a, &b], [&b, &a], [&a, &ordinary], [&ordinary, &a]] {
        let m = merge_views(&base, &sides, &mut no_descent).view;
        let t = &m.tags["v1"];
        let pair = (t.target, t.annotation);
        assert!(pair == (id(1), Some(id(11))) || pair == (id(2), Some(id(12))), "torn release tag: {t:?}");
    }
    // A move of a tag, merged with its release: the release stays.
    let mut moved = a.clone();
    moved.tags.insert("v1".into(), Tag::new(id(4)));
    let m = merge_views(&a, &[&a, &moved], &mut no_descent).view;
    let t = &m.tags["v1"];
    assert!(t.annotation.is_none() || t.target == id(1), "{t:?}");
}

#[derive(Clone, Debug)]
enum TagCmd {
    Set(u8),
    Delete(u8),
}

fn tag_cmd() -> impl Strategy<Value = TagCmd> {
    prop_oneof![(0..5u8).prop_map(TagCmd::Set), (0..5u8).prop_map(TagCmd::Delete)]
}

fn run_tag(repo: &mut Repo, c: &TagCmd, target: ObjectId) {
    match c {
        TagCmd::Set(t) => repo.set_tag(&format!("t{t}"), target, true).unwrap(),
        TagCmd::Delete(t) => {
            let _ = repo.delete_tag(&format!("t{t}"));
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, failure_persistence: None, ..ProptestConfig::default() })]

    /// Threat 1, through the engine: two sequences of tag commands run
    /// concurrently (on forks of one disk, landed together), then merged
    /// by the next open; each tag ends as the per-key model says.
    #[test]
    fn concurrent_commands_merge_per_key(ca in prop::collection::vec(tag_cmd(), 0..5), cb in prop::collection::vec(tag_cmd(), 0..5)) {
        let fs = Arc::new(MemoryBackend::new());
        let me = Identity::generate("alice");
        let mut repo = Repo::init(fs.clone(), Some(me.clone()), "alice").unwrap();
        let root = repo.root_id();
        let ta = repo.new_change("default", vec![root], "a").unwrap();
        let tb = repo.new_change("default", vec![root], "b").unwrap();
        repo.set_tag("t0", root, true).unwrap();
        let base: BTreeMap<String, ObjectId> = repo.view().tags.iter().map(|(n, t)| (n.clone(), t.target)).collect();
        drop(repo);
        let heads = |f: &MemoryBackend| f.list_dir(&VPath::new(OP_HEADS_DIR).unwrap()).unwrap().into_iter().map(|e| e.name).collect::<Vec<_>>();
        let at = heads(&fs);
        let (fa, fb) = (Arc::new(fs.fork()), Arc::new(fs.fork()));
        let mut ra = Repo::open(fa.clone(), Some(me.clone()), "alice").unwrap();
        for c in &ca { run_tag(&mut ra, c, ta); }
        let va: BTreeMap<String, ObjectId> = ra.view().tags.iter().map(|(n, t)| (n.clone(), t.target)).collect();
        let mut rb = Repo::open(fb.clone(), Some(me.clone()), "alice").unwrap();
        for c in &cb { run_tag(&mut rb, c, tb); }
        let vb: BTreeMap<String, ObjectId> = rb.view().tags.iter().map(|(n, t)| (n.clone(), t.target)).collect();
        drop((ra, rb));
        for side in [&fa, &fb] {
            for f in side.files() {
                let s = f.as_str();
                if (s.starts_with(".veil/objects/") || s.starts_with(".veil/ops/") || s.starts_with(".veil/op_heads/")) && !s.contains("/incoming/") && !fs.exists(&f).unwrap() {
                    fs.write(&f, &side.read(&f).unwrap()).unwrap();
                }
            }
            let now = heads(side);
            for h in &at {
                if !now.contains(h) {
                    fs.remove_file(&VPath::new(&format!("{OP_HEADS_DIR}/{h}")).unwrap()).unwrap();
                }
            }
        }
        let r = Repo::open(fs.clone(), Some(me.clone()), "alice").unwrap();
        let names: std::collections::BTreeSet<&String> = base.keys().chain(va.keys()).chain(vb.keys()).collect();
        for n in names {
            let got = r.view().tags.get(n).map(|t| t.target);
            let (b0, a1, b1) = (base.get(n), va.get(n), vb.get(n));
            match (a1 != b0, b1 != b0) {
                (true, true) if a1 != b1 => {
                    // Both changed it differently: one of them wins, unless
                    // both removed it.
                    prop_assert!(got.as_ref() == a1 || got.as_ref() == b1, "tag {}: {:?} is neither side's", n, got.map(|g| g.short()));
                }
                _ => prop_assert_eq!(got, model(b0.copied(), a1.copied(), b1.copied()), "tag {}", n),
            }
        }
        prop_assert_eq!(r.heads().len(), 1);
    }
}

/// BUG-1031: a workspace's identity goes with the working copy that won: a
/// concurrent move keeps it, and an undo that brings back an earlier
/// workspace of the same name brings back that one's, never the later one's.
#[test]
fn a_workspace_keeps_its_identity_through_merges_and_undo() {
    let first = WorkspaceState::new(id(2));
    let later = WorkspaceState::new(id(5));
    assert!(first.id.is_some() && first.id != later.id, "each workspace gets its own id");
    let mut base = View::default();
    base.workspaces.insert("w".into(), first.clone());
    let mut moved = base.clone();
    moved.workspaces.get_mut("w").unwrap().wc = id(4);
    let m = merge_views(&base, &[&moved, &base], &mut no_descent).view;
    assert_eq!(m.workspaces["w"].id, first.id);
    // Removed, then made again under its name; undoing the removal's
    // successor and the removal brings the first back, with its own id.
    let gone = View::default();
    let mut again = View::default();
    again.workspaces.insert("w".into(), later.clone());
    let back = revert_views(&gone, &base, &again, &mut no_descent).view;
    let w = &back.workspaces["w"];
    assert_eq!((w.wc, &w.id), (first.wc, &first.id), "{w:?}");
}

// ---- BUG-1294: settlers that list different heads --------------------------

/// BUG-1294, the interleaving found: from `p` (w = 2), one writer records
/// w = 3 (`x1`) while another operation (`x2`, newer) leaves w alone. One
/// settler merges them (`a`, w = 3); another merges them with a third
/// head, and the writer commits on that (`b`, w = 4). `a` and `b` share
/// `x1` and `x2`; the newest, `x2`, alone says w = 2, so both sides
/// looked changed and the first side (`a`, the older w = 3) won.
#[test]
fn criss_cross_keeps_the_newer_commit() {
    let ws = |wc: u8| {
        let mut v = base_view();
        v.workspaces.get_mut("w0").unwrap().wc = id(wc);
        v
    };
    let (x1, x2) = (ws(3), ws(2));
    let (a, b) = (ws(3), ws(4));
    // Only `a` reaches the merge `a` (its parents x1, x2); only `b`
    // reaches b's merge of x1, x2 and a third head, and the commit.
    let mut ia = Introduced::default();
    ia.add(&a, &[&x1, &x2]);
    let mut ib = Introduced::default();
    let b_merge = ws(3);
    ib.add(&b_merge, &[&x1, &x2, &base_view()]);
    ib.add(&b, &[&b_merge]);
    let shared = shared_base(&x2, &a, &ia, &b, &ib);
    for sides in [[&a, &b], [&b, &a]] {
        let m = merge_views(&shared, &sides, &mut no_descent);
        assert_eq!(m.view.workspaces["w0"].wc, id(4), "the newer commit wins");
        assert!(m.warnings.is_empty(), "{:?}", m.warnings);
    }
    // Before the fix, against `x2` alone: the first side won.
    assert_eq!(merge_views(&x2, &[&a, &b], &mut no_descent).view.workspaces["w0"].wc, id(3));
    // An undo on one side back to a value the shared history held is a
    // change too: introduced by the undo.
    let undone = ws(2);
    let mut iu = Introduced::default();
    iu.add(&undone, &[&a]);
    let shared = shared_base(&x2, &undone, &iu, &a, &Introduced::default());
    assert_eq!(merge_views(&shared, &[&a, &undone], &mut no_descent).view.workspaces["w0"].wc, id(2));
}

/// A repository on one backend, as one simulated process sees it: a reader
/// copies it (`fork`) when it lists the heads, and what it then writes
/// lands later (`land`), as a slow transaction or settler publishes.
struct Device {
    fs: Arc<dyn StorageBackend>,
    _dir: Option<tempfile::TempDir>,
}

fn op_heads(fs: &dyn StorageBackend) -> Vec<String> {
    fs.list_dir(&VPath::new(OP_HEADS_DIR).unwrap()).unwrap().into_iter().map(|e| e.name).collect()
}

fn repo_files(fs: &dyn StorageBackend) -> Vec<VPath> {
    let skip = |p: &VPath| p.as_str().starts_with(".veil/objects/incoming") || p.as_str().starts_with(".veil/local");
    veil_core::vfs::walk_files(fs, &VPath::root(), &skip).unwrap()
}

impl Device {
    fn new(disk: bool) -> Device {
        match disk {
            true => {
                let d = tempfile::tempdir().unwrap();
                Device { fs: Arc::new(veil_core::DiskBackend::new(d.path())), _dir: Some(d) }
            }
            false => Device { fs: Arc::new(MemoryBackend::new()), _dir: None },
        }
    }

    /// A copy of the repository with only `heads` as its op heads.
    fn fork(&self, heads: &[String]) -> Device {
        let out = Device::new(self._dir.is_some());
        for f in repo_files(&*self.fs) {
            out.fs.write(&f, &self.fs.read(&f).unwrap()).unwrap();
        }
        for h in op_heads(&*out.fs) {
            if !heads.contains(&h) {
                out.fs.remove_file(&VPath::new(&format!("{OP_HEADS_DIR}/{h}")).unwrap()).unwrap();
            }
        }
        out
    }

    /// Publish what `fork` (forked with `heads`) wrote: its operations and
    /// objects, its new heads, and the removal of the heads it merged.
    fn land(&self, fork: &Device, heads: &[String]) {
        for f in repo_files(&*fork.fs) {
            let s = f.as_str();
            if (s.starts_with(".veil/objects/") || s.starts_with(".veil/ops/")) && !self.fs.exists(&f).unwrap() {
                self.fs.write(&f, &fork.fs.read(&f).unwrap()).unwrap();
            }
        }
        let now = op_heads(&*fork.fs);
        for h in &now {
            if !heads.contains(h) {
                self.fs.write(&VPath::new(&format!("{OP_HEADS_DIR}/{h}")).unwrap(), b"").unwrap();
            }
        }
        for h in heads {
            let p = VPath::new(&format!("{OP_HEADS_DIR}/{h}")).unwrap();
            if !now.contains(h) && self.fs.exists(&p).unwrap() {
                self.fs.remove_file(&p).unwrap();
            }
        }
    }
}

fn files_of(repo: &Repo, snapshot: &ObjectId) -> Vec<String> {
    veil_core::tree::walk_files(repo.store(), &repo.snapshot(snapshot).unwrap().tree).unwrap().into_iter().map(|(p, _)| p.to_string()).collect()
}

/// BUG-1294's guarantee, checked over many interleavings: every committed
/// operation's effects are in every later view. Three writers each commit
/// new files in their own workspace and tag each commit; settlers merge
/// random subsets of the heads; every writer and settler publishes after
/// a random delay (others land meanwhile), which makes criss-crosses: two
/// merges of overlapping sets of operations. Each writer finds all its
/// own files in its workspace when it starts, and in the end every tag
/// names a commit holding all its writer's files so far; no merge reports
/// a conflict (each key has one writer).
fn check_merges_keep_every_operation(disk: bool, steps: &[u8]) -> Result<(), TestCaseError> {
    let me = Identity::generate("alice");
    let truth = Device::new(disk);
    {
        let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        let root = repo.root_id();
        for w in 0..3 {
            repo.create_workspace(&format!("w{w}"), vec![root]).unwrap();
        }
    }
    let mut done = [0usize; 3];
    // (fork, the heads it was forked with, the writer it belongs to)
    let mut pending: Vec<(Device, Vec<String>, Option<usize>)> = Vec::new();
    for &b in steps {
        let heads = op_heads(&*truth.fs);
        match b % 3 {
            0 => {
                let w = (b as usize / 3) % 3;
                if done[w] == 3 || pending.iter().any(|p| p.2 == Some(w)) {
                    continue;
                }
                let fork = truth.fork(&heads);
                let mut repo = Repo::open(fork.fs.clone(), Some(me.clone()), "alice").unwrap();
                let ws = format!("w{w}");
                let have = files_of(&repo, &repo.workspace_wc(&ws).unwrap());
                for n in 0..done[w] {
                    prop_assert!(have.contains(&format!("f{w}-{n}")), "{}: {ws} lost f{w}-{n}: {:?}", truth.fs.kind(), have);
                }
                let n = done[w];
                let ov = repo.workspace_overlay(&ws).unwrap();
                ov.write(&VPath::new(&format!("f{w}-{n}")).unwrap(), b"x\n").unwrap();
                repo.snapshot_workspace(&ws, &ov).unwrap();
                let (c, _) = repo.commit_working_copy(&ws, &format!("{ws} {n}")).unwrap();
                repo.set_tag(&format!("c{w}-{n}"), c, true).unwrap();
                // Each key has one writer, and nothing rewrites: a conflict
                // is a merge that took a shared value for a change.
                prop_assert_eq!(repo.take_warnings(), Vec::<String>::new());
                drop(repo);
                done[w] += 1;
                pending.push((fork, heads, Some(w)));
            }
            1 => {
                // A settler that listed some of the heads.
                let pick: Vec<String> = heads.iter().enumerate().filter(|(i, _)| (b >> (2 + i % 6)) & 1 == 1).map(|(_, h)| h.clone()).collect();
                if pick.len() < 2 {
                    continue;
                }
                let fork = truth.fork(&pick);
                let mut repo = Repo::open(fork.fs.clone(), Some(me.clone()), "alice").unwrap();
                prop_assert_eq!(repo.heads().len(), 1, "the settler merged its heads");
                prop_assert_eq!(repo.take_warnings(), Vec::<String>::new());
                drop(repo);
                pending.push((fork, pick, None));
            }
            _ => {
                if !pending.is_empty() {
                    let (fork, heads, _) = pending.remove(b as usize / 3 % pending.len());
                    truth.land(&fork, &heads);
                }
            }
        }
    }
    for (fork, heads, _) in pending.drain(..) {
        truth.land(&fork, &heads);
    }
    let mut repo = Repo::open(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
    prop_assert_eq!(repo.heads().len(), 1);
    prop_assert_eq!(repo.take_warnings(), Vec::<String>::new());
    for (w, &done) in done.iter().enumerate() {
        let have = files_of(&repo, &repo.workspace_wc(&format!("w{w}")).unwrap());
        for n in 0..done {
            prop_assert!(have.contains(&format!("f{w}-{n}")), "{}: w{w} lost f{w}-{n}: {:?}", truth.fs.kind(), have);
            let t = repo.view().tags.get(&format!("c{w}-{n}"));
            prop_assert!(t.is_some(), "{}: tag c{w}-{n} was lost", truth.fs.kind());
            let files = files_of(&repo, &t.unwrap().target);
            for m in 0..=n {
                prop_assert!(files.contains(&format!("f{w}-{m}")), "{}: c{w}-{n} lacks f{w}-{m}: {:?}", truth.fs.kind(), files);
            }
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(256),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// BUG-1294 on the memory backend (256 cases, a few seconds: without
    /// the fix, 7 seeds in 8 and the pinned one fail).
    #[test]
    fn merges_keep_every_operation_memory(steps in prop::collection::vec(any::<u8>(), 10..60)) {
        check_merges_keep_every_operation(false, &steps)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(16),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// BUG-1294 on the disk backend (fewer cases: each syncs; 64 found
    /// it at the pinned seed without the fix).
    #[test]
    fn merges_keep_every_operation_disk(steps in prop::collection::vec(any::<u8>(), 10..60)) {
        check_merges_keep_every_operation(true, &steps)?;
    }
}

// ---- BUG-1294 review: every write survives, for every kind of key ---------

/// One key of a view, as the per-key model sees it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Key {
    Ws(String),
    Tag(String),
    Rtag(String),
    Head(ObjectId),
}

/// A key's value (a workspace's working copy, a tag's target and
/// annotation, a remote tag's target, a head's presence); `None`: absent.
type Val = Option<(ObjectId, Option<ObjectId>)>;

fn keys_of(v: &View) -> BTreeMap<Key, (ObjectId, Option<ObjectId>)> {
    let mut out = BTreeMap::new();
    for (n, w) in &v.workspaces {
        out.insert(Key::Ws(n.clone()), (w.wc, None));
    }
    for (n, t) in &v.tags {
        out.insert(Key::Tag(n.clone()), (t.target, t.annotation));
    }
    for (n, t) in &v.remote_tags {
        out.insert(Key::Rtag(n.clone()), (*t, None));
    }
    for h in &v.heads {
        out.insert(Key::Head(*h), (*h, None));
    }
    out
}

/// What a command wrote: every key whose value it changed.
fn writes(before: &View, after: &View) -> Vec<(Key, Val)> {
    let (b, a) = (keys_of(before), keys_of(after));
    let names: std::collections::BTreeSet<&Key> = b.keys().chain(a.keys()).collect();
    names.into_iter().filter(|k| b.get(k) != a.get(k)).map(|k| (k.clone(), a.get(k).copied())).collect()
}

/// A command as the model records it: when it read the repository (it saw
/// every command landed before), when it landed, and what it wrote.
struct Cmd {
    forked: usize,
    landed: Option<usize>,
    writes: Vec<(Key, Val)>,
    what: String,
    /// The commit it made, a tag target for later commands.
    commit: Option<ObjectId>,
}

/// The per-key model: the values a view that saw the commands landed by
/// now may hold for `key`: those of the writes no later landed write of
/// `key` saw (causal last writer wins; several only for concurrent writes,
/// where a change beats a removal). `None` when nothing wrote the key.
fn allowed(cmds: &[Cmd], key: &Key) -> Option<(Vec<Val>, Vec<usize>)> {
    let landed: Vec<(usize, &Cmd)> = cmds.iter().enumerate().filter(|(_, c)| c.landed.is_some()).collect();
    let mut last: Vec<(Val, usize)> = Vec::new();
    for (i, c) in &landed {
        let Some((_, v)) = c.writes.iter().find(|(k, _)| k == key) else { continue };
        let superseded = landed.iter().any(|(j, d)| j != i && d.writes.iter().any(|(k, _)| k == key) && c.landed.unwrap() < d.forked);
        if !superseded {
            last.push((*v, *i));
        }
    }
    if last.is_empty() {
        return None;
    }
    let mut vals: Vec<Val> = last.iter().map(|(v, _)| *v).collect();
    // A change (or an added head) beats a concurrent removal.
    if vals.iter().any(|v| v.is_some()) {
        vals.retain(|v| v.is_some());
    }
    vals.sort();
    vals.dedup();
    Some((vals, last.iter().map(|(_, i)| *i).collect()))
}

/// Were two landed writes of `key` concurrent, to different values (not
/// a removal)?
fn conflicted(cmds: &[Cmd], key: &Key) -> bool {
    let w: Vec<(&Cmd, Val)> = cmds.iter().filter(|c| c.landed.is_some()).filter_map(|c| c.writes.iter().find(|(k, _)| k == key).map(|(_, v)| (c, *v))).collect();
    w.iter().any(|(c, v)| {
        w.iter().any(|(d, u)| v.is_some() && u.is_some() && v != u && c.landed.unwrap() >= d.forked && d.landed.unwrap() >= c.forked)
    })
}

/// Does `repo`'s view hold, for every key, a value the model allows? A key
/// with a real conflict may hold any value the model allows, each of which
/// must stay visible. Heads: a head the model keeps must stay visible; one
/// it removed may come back only as a written value (a conflict's loser).
fn check_model(cmds: &[Cmd], repo: &Repo, losers: &std::collections::HashSet<ObjectId>, at: &str) -> Result<(), TestCaseError> {
    let view = repo.view();
    let have = keys_of(view);
    let refs = view.refs();
    // The rewrites the op log records (old to its replacements).
    let mut rewrites: std::collections::HashMap<ObjectId, Vec<Vec<ObjectId>>> = Default::default();
    for r in repo.ops().walk(repo.heads()) {
        for (old, new) in r.unwrap().1.rewritten {
            rewrites.entry(old).or_default().push(new);
        }
    }
    // Visible as a ref or below one; or, moved by a concurrent rewrite (an
    // amend, the rebase onto one, BUG-1299), through the rewrites the op
    // log records, followed to a visible snapshot. Not by change id: two
    // concurrent snapshots of one working copy are versions of one change,
    // and a dropped one is lost (BUG-1435).
    let shown = |v: &ObjectId| refs.iter().any(|r| r == v || repo.is_ancestor(v, r).unwrap());
    let visible = |v: &ObjectId| {
        let mut todo = vec![*v];
        let mut seen: std::collections::HashSet<ObjectId> = Default::default();
        while let Some(x) = todo.pop() {
            if !seen.insert(x) || seen.len() > 256 {
                continue;
            }
            if shown(&x) {
                return true;
            }
            todo.extend(rewrites.get(&x).into_iter().flatten().flatten().copied());
        }
        false
    };
    // Rewritten, through one rewrite or several (a merge's rebase, then a
    // `ws remove` of the rebased copy), into nothing: abandoned.
    let abandoned = |v: &ObjectId| {
        let mut todo = vec![*v];
        let mut seen: std::collections::HashSet<ObjectId> = Default::default();
        while let Some(x) = todo.pop() {
            if !seen.insert(x) || seen.len() > 256 {
                continue;
            }
            for n in rewrites.get(&x).into_iter().flatten() {
                if n.is_empty() {
                    return true;
                }
                todo.extend(n.iter().copied());
            }
        }
        false
    };
    // Through the rewrites the op log records, one or several (a describe
    // of what a value is on rebases it, and a later one again).
    let moved = |v: &ObjectId, g: &ObjectId| {
        let mut todo = vec![*v];
        let mut seen: std::collections::HashSet<ObjectId> = Default::default();
        while let Some(x) = todo.pop() {
            if !seen.insert(x) || seen.len() > 256 {
                continue;
            }
            for n in rewrites.get(&x).into_iter().flatten() {
                if n.contains(g) || (n.is_empty() && repo.snapshot(g).unwrap().parents == repo.snapshot(&x).unwrap().parents) {
                    return true;
                }
                todo.extend(n.iter().copied());
            }
        }
        false
    };
    let mut keys: std::collections::BTreeSet<Key> = Default::default();
    for c in cmds.iter().filter(|c| c.landed.is_some()) {
        keys.extend(c.writes.iter().map(|(k, _)| k.clone()));
    }
    for k in keys {
        let Some((vals, by)) = allowed(cmds, &k) else { continue };
        let got = have.get(&k).copied();
        // Two concurrent writes of different values: a real conflict, where
        // the first side wins and the loser stays visible (a later removal
        // that saw only the winner may then remove the key). Every value the
        // model still allows must be visible.
        if !matches!(k, Key::Head(_)) && conflicted(cmds, &k) {
            for v in vals.iter().flatten() {
                // Unless a later undo or op restore that saw it took its head
                // away (of the command that wrote it, or from before it).
                let wrote: Vec<&Cmd> = cmds.iter().filter(|c| c.landed.is_some() && c.writes.iter().any(|(k2, v2)| *k2 == k && *v2 == Some(*v))).collect();
                let reverts = |d: &Cmd| d.what.starts_with("undo") || d.what.starts_with("op restore");
                // (its head, or a head it was below: a workspace on it the
                // revert removed, BUG-1489).
                let below = |h: &ObjectId| *h == v.0 || repo.is_ancestor(&v.0, h).unwrap();
                let dropped = |d: &Cmd| d.writes.iter().any(|(k2, w)| matches!(k2, Key::Head(h) if below(h)) && w.is_none());
                let removed = cmds.iter().any(|d| d.landed.is_some() && reverts(d) && dropped(d) && wrote.iter().all(|c| c.landed.unwrap() < d.forked));
                // Or abandoned by a concurrent command (an empty working
                // copy a `ws remove` dropped): the ref moved onto a new
                // change on its parents, as without a conflict (BUG-1489).
                let followed = refs.iter().any(|r| moved(&v.0, r));
                prop_assert!(matches!(k, Key::Rtag(_)) || removed || visible(&v.0) || followed, "{}: {:?}: {} was dropped in a conflict", at, k, v.0.short());
            }
            continue;
        }
        let ok = match &k {
            // A head the model keeps must stay visible (a head, or below
            // one: a merge drops a head another ref now covers).
            Key::Head(h) if vals.contains(&Some((*h, None))) => got.is_some() || visible(h) || abandoned(h),
            // A head two rewrites replaced differently (a divergent change:
            // nothing follows either, and it stays where it was).
            Key::Head(h) => vals.contains(&got) || losers.contains(h) || rewrites.get(h).is_some_and(|news| news.iter().any(|n| *n != news[0])),
            _ => vals.contains(&got) || vals.iter().flatten().any(|v| got.is_some_and(|g| moved(&v.0, &g.0))),
        };
        let whats: Vec<&str> = by.iter().map(|i| cmds[*i].what.as_str()).collect();
        prop_assert!(ok, "{}: {:?} is {:?}, the model allows {:?} (last written by {:?})", at, k, got.map(|g| g.0.short()), vals.iter().map(|v| v.map(|v| v.0.short())).collect::<Vec<_>>(), whats);
    }
    Ok(())
}

/// A fork not landed yet: the fork, the heads it was forked with, its
/// command (none for a settler), and the workspace slots it holds.
type Pending = (Device, Vec<String>, Option<usize>, Vec<String>);

/// The review's model check of guarantee 1 (BUG-1294 review): `nw`
/// writers, each committing in its own workspace (one recorder per
/// workspace at a time, as the workspace lock keeps it); any command moves
/// and deletes tags (so concurrent tag moves are real conflicts), updates
/// and drops remote tags, creates and removes extra workspaces, and (with
/// `undo`) undoes the last command of a workspace or restores an earlier
/// operation; settlers merge random subsets of the heads; everything
/// publishes after a random delay. Without `aba`, no tag or remote tag is
/// written back to a value it held before (BUG-1296). Every command (and
/// the final view) must see, for every key, the value of the causally last
/// write (a value of one of several concurrent writes, whose losers stay
/// visible). No warning unless two writes of a key were concurrent, and a
/// warning for every conflict still open at the end.
fn check_every_write_survives(disk: bool, nw: usize, undo: bool, aba: bool, steps: &[u16]) -> Result<(), TestCaseError> {
    check_every_write_survives_with(disk, nw, undo, aba, false, steps)
}

/// [`check_every_write_survives`], with `describes`: some tag moves turn
/// into describes of a visible commit, whose rewrite moves the tags on it
/// and rebases what is built on it (working copies), and which settlers
/// record again when they merge it (BUG-2550: a command's rewrite recorded
/// again by a settler was read as the settler's own rebase, and a
/// concurrent move of the same tag or workspace won silently).
fn check_every_write_survives_with(disk: bool, nw: usize, undo: bool, aba: bool, describes: bool, steps: &[u16]) -> Result<(), TestCaseError> {
    let me = Identity::generate("alice");
    let truth = Device::new(disk);
    let mut cmds: Vec<Cmd> = Vec::new();
    let mut commits: Vec<ObjectId>;
    {
        let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        let root = repo.root_id();
        let before = View::default();
        for w in 0..nw {
            repo.create_workspace(&format!("w{w}"), vec![root]).unwrap();
        }
        for t in 0..3 {
            repo.set_tag(&format!("t{t}"), root, true).unwrap();
        }
        cmds.push(Cmd { forked: 0, landed: Some(0), writes: writes(&before, repo.view()), what: "init".into(), commit: None });
        commits = vec![root];
    }
    let mut warnings: Vec<String> = Vec::new();
    let mut losers: std::collections::HashSet<ObjectId> = Default::default();
    let mut files = vec![0usize; nw];
    // Without `aba`, no command writes a tag or remote tag back to a value
    // it held before (BUG-1296): every value a key was written is here.
    let mut used: std::collections::HashMap<Key, std::collections::HashSet<Val>> = Default::default();
    for (k, v) in &cmds[0].writes {
        used.entry(k.clone()).or_default().insert(*v);
    }
    let mut pending: Vec<Pending> = Vec::new();
    for (clock, &b) in steps.iter().enumerate() {
        let clock = clock + 1;
        let heads = op_heads(&*truth.fs);
        let arg = (b / 16) as usize;
        let kind = b % 16;
        if kind >= 12 {
            if kind == 15 {
                let pick: Vec<String> = heads.iter().enumerate().filter(|(i, _)| (arg >> (i % 10)) & 1 == 1).map(|(_, h)| h.clone()).collect();
                if pick.len() < 2 {
                    continue;
                }
                let fork = truth.fork(&pick);
                let mut repo = Repo::open(fork.fs.clone(), Some(me.clone()), "alice").unwrap();
                prop_assert_eq!(repo.heads().len(), 1, "the settler merged its heads");
                warnings.extend(repo.take_warnings());
                drop(repo);
                pending.push((fork, pick, None, Vec::new()));
            } else if !pending.is_empty() {
                let (fork, heads, c, _) = pending.remove(arg % pending.len());
                truth.land(&fork, &heads);
                if let Some(c) = c {
                    cmds[c].landed = Some(clock);
                    commits.extend(cmds[c].commit);
                }
            }
            continue;
        }
        // A command: which workspace slots it holds.
        // Without undo and op restore (see BUG-1295): those turn into
        // more tag moves.
        let kind = match (undo, kind) {
            (false, 10 | 11) => 9,
            (_, k) => k,
        };
        // With `describes`, every other two-tag move is a describe (kind 16).
        let kind = match (describes, kind) {
            (true, 9) if arg.is_multiple_of(2) => 16,
            (_, k) => k,
        };
        let w = arg % nw;
        let x = format!("x{}", arg % 2);
        let slots: Vec<String> = match kind {
            0..=3 | 10 => vec![format!("w{w}")],
            8 => vec![x.clone()],
            // One describe at a time (two concurrent describes of a commit
            // are a divergent change, which the per-key model does not
            // judge; `check_rewrites_followed` does), and none concurrent
            // with a workspace made or removed on what it rebases.
            16 => vec!["describe".to_string(), "x0".to_string(), "x1".to_string()],
            11 => (0..nw).map(|w| format!("w{w}")).chain(["x0".to_string(), "x1".to_string()]).collect(),
            _ => Vec::new(),
        };
        if pending.iter().any(|p| p.3.iter().any(|s| slots.contains(s))) {
            continue;
        }
        let fork = truth.fork(&heads);
        // Each command as its own user: two commands never write the same
        // operation (with `aba`, a tag set to the value it has, from the
        // same head in the same millisecond, would be one operation, and
        // the model would count two commands).
        let mut repo = Repo::open(fork.fs.clone(), Some(me.clone()), &format!("alice-{clock}")).unwrap();
        warnings.extend(repo.take_warnings());
        check_model(&cmds, &repo, &losers, &format!("step {clock} (a command's view)"))?;
        let before = repo.view().clone();
        let tag = format!("t{}", arg % 3);
        // A target for `key`: any commit, or (without `aba`) one the key
        // never had.
        let fresh = |key: Key, n: usize| -> Option<ObjectId> {
            let ok = |c: &ObjectId| aba || !used.get(&key).is_some_and(|u| u.contains(&Some((*c, None))));
            let cands: Vec<ObjectId> = commits.iter().copied().filter(ok).collect();
            (!cands.is_empty()).then(|| cands[n % cands.len()])
        };
        let gone = |key: Key| !aba && used.get(&key).is_some_and(|u| u.contains(&None));
        let what;
        let mut new_commit = None;
        let ok: Result<(), veil_core::VeilError> = match kind {
            0..=3 => {
                let ws = format!("w{w}");
                if !repo.view().workspaces.contains_key(&ws) {
                    // An op restore to before its creation took it away.
                    continue;
                }
                repo.set_command_workspace(Some(ws.clone()));
                let n = files[w];
                files[w] += 1;
                what = format!("commit {ws} {n}");
                let ov = repo.workspace_overlay(&ws).unwrap();
                ov.write(&VPath::new(&format!("f{w}-{n}")).unwrap(), b"x\n").unwrap();
                repo.snapshot_workspace(&ws, &ov).unwrap();
                repo.commit_working_copy(&ws, &format!("{ws} {n}")).map(|(c, _)| new_commit = Some(c))
            }
            4 | 5 => match fresh(Key::Tag(tag.clone()), arg) {
                Some(t) => {
                    what = format!("tag {tag} -> {}", t.short());
                    repo.set_tag(&tag, t, true)
                }
                None => continue,
            },
            6 => {
                what = format!("delete tag {tag}");
                match repo.view().tags.contains_key(&tag) && !gone(Key::Tag(tag.clone())) {
                    true => repo.delete_tag(&tag),
                    false => Err(veil_core::VeilError::repo("no tag")),
                }
            }
            7 => {
                let name = format!("origin/{tag}");
                what = format!("remote tag {name}");
                let drop = arg % 4 == 3;
                let t = fresh(Key::Rtag(name.clone()), arg);
                if (drop && (gone(Key::Rtag(name.clone())) || !repo.view().remote_tags.contains_key(&name))) || (!drop && t.is_none()) {
                    continue;
                }
                let mut tx = repo.transaction("pull").unwrap();
                tx.repository_wide();
                match (drop, t) {
                    (true, _) => {
                        tx.view.remote_tags.remove(&name);
                    }
                    (false, t) => {
                        tx.view.remote_tags.insert(name, t.unwrap());
                    }
                }
                tx.commit().map(|_| ())
            }
            8 => match repo.view().workspaces.contains_key(&x) {
                true => {
                    what = format!("remove workspace {x}");
                    repo.remove_workspace(&x)
                }
                false => {
                    what = format!("create workspace {x}");
                    let t = commits[arg % commits.len()];
                    repo.create_workspace(&x, vec![t]).map(|_| ())
                }
            },
            9 => {
                let other = format!("t{}", (arg + 1) % 3);
                what = format!("tag {tag} and {other}");
                match (fresh(Key::Tag(tag.clone()), arg), fresh(Key::Tag(other.clone()), arg)) {
                    (Some(t), Some(u)) => repo.set_tag(&tag, t, true).and_then(|_| repo.set_tag(&other, u, true)),
                    _ => continue,
                }
            }
            16 => {
                // A visible commit (not a working copy).
                let wcs: Vec<ObjectId> = repo.view().workspaces.values().map(|w| w.wc).collect();
                let visible = repo.exact().visible().unwrap();
                let cands: Vec<ObjectId> = commits.iter().copied().filter(|c| *c != repo.root_id() && !wcs.contains(c) && visible.contains(c)).collect();
                if cands.is_empty() {
                    continue;
                }
                let target = cands[arg % cands.len()];
                what = format!("describe {}", target.short());
                repo.describe(target, &format!("described {clock}")).map(|c| new_commit = Some(c))
            }
            10 => {
                let ws = format!("w{w}");
                repo.set_command_workspace(Some(ws.clone()));
                what = format!("undo in {ws}");
                repo.undo_keeping_edits(&ws).map(|_| ())
            }
            _ => {
                // Restore the view of an operation a few back.
                let back = arg % 5 + 1;
                let target = repo.ops().walk(&[repo.op_id()]).nth(back).map(|r| r.unwrap().0);
                what = format!("op restore {back} back");
                match target {
                    Some(op) => repo.restore_operation_keeping_edits("w0", op).map(|_| ()),
                    None => Err(veil_core::VeilError::repo("no op")),
                }
            }
        };
        if ok.is_err() {
            // Nothing to undo, no tag to delete: nothing ran (the fork is
            // dropped unpublished).
            continue;
        }
        warnings.extend(repo.take_warnings());
        let ws = writes(&before, repo.view());
        for (k, v) in &ws {
            used.entry(k.clone()).or_default().insert(*v);
        }
        drop(repo);
        cmds.push(Cmd { forked: clock, landed: None, writes: ws, what, commit: new_commit });
        pending.push((fork, heads, Some(cmds.len() - 1), slots));
        // A conflict's losing values stay visible as heads.
        for (k, v) in &cmds.last().unwrap().writes {
            if let (Key::Ws(_) | Key::Tag(_), Some((t, _))) = (k, v) {
                losers.insert(*t);
            }
        }
    }
    let end = steps.len() + 1;
    for (fork, heads, c, _) in pending.drain(..) {
        truth.land(&fork, &heads);
        if let Some(c) = c {
            cmds[c].landed = Some(end);
        }
    }
    let mut repo = Repo::open(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
    prop_assert_eq!(repo.heads().len(), 1);
    warnings.extend(repo.take_warnings());
    check_model(&cmds, &repo, &losers, "the final view")?;
    // Guarantee 3: a warning only for a real conflict (two concurrent
    // writes of one workspace or tag, to different values).
    let concurrent = cmds.iter().enumerate().any(|(i, c)| {
        cmds.iter().enumerate().any(|(j, d)| {
            i < j
                && c.landed.unwrap() >= d.forked
                && d.landed.unwrap() >= c.forked
                && c.writes.iter().any(|(k, v)| matches!(k, Key::Ws(_) | Key::Tag(_)) && d.writes.iter().any(|(k2, v2)| k2 == k && v2 != v))
        })
    });
    if !concurrent {
        prop_assert_eq!(&warnings, &Vec::<String>::new(), "a warning without a conflict");
    }
    // And a real conflict that no later write settled is named in a
    // warning.
    let mut keys: std::collections::BTreeSet<Key> = Default::default();
    for c in &cmds {
        keys.extend(c.writes.iter().map(|(k, _)| k.clone()));
    }
    for k in keys {
        let name = match &k {
            Key::Ws(n) => format!("workspace '{n}'"),
            Key::Tag(n) => format!("tag '{n}'"),
            _ => continue,
        };
        // Still two values at the end (no later write settled it).
        let open = allowed(&cmds, &k).is_some_and(|(v, _)| v.iter().flatten().count() > 1);
        if open {
            prop_assert!(warnings.iter().any(|w| w.starts_with(&name)), "{} had concurrent moves and no warning: {:?}", name, warnings);
        }
    }
    Ok(())
}

// ---- op log merges review: auto-rebase through concurrent merges -------------

/// A command of the auto-rebase model: when it read the repository and
/// landed, the operations it wrote, the rewrites they recorded (commits and
/// describes), and the commands it took back (an undo, an op restore).
struct RwCmd {
    forked: usize,
    landed: Option<usize>,
    ops: std::collections::HashSet<ObjectId>,
    /// Each rewrite with the operation that recorded it: (op, old, new).
    rewrites: Vec<(ObjectId, ObjectId, ObjectId)>,
    /// The rewrites an undo or an op restore recorded, as (op, old, new):
    /// the edits recorded since, re-applied on the working copy it
    /// restored (`Repo::undo_keeping_edits`, the restored working copy
    /// rewritten into one holding them), and what that rebased. Rewrites
    /// of a command like any other (BUG-1444: the check knew only those of
    /// commits and describes, and so took a describe concurrent with such
    /// a restore of one snapshot for a rewrite to follow, not for the
    /// divergent change it is). Kept apart from `rewrites`: those also
    /// choose what later commands of an input describe and tag.
    reapplied: Vec<(ObjectId, ObjectId, ObjectId)>,
    /// The operations it took back (an undo the one it undid, an op
    /// restore every one between the restored one and its parents).
    retracts: Vec<ObjectId>,
    /// What it wrote (keys and their values, as the per-key model sees
    /// them).
    writes: Vec<(Key, Val)>,
    what: String,
}

/// The auto-rebase guarantee (BUG-1299's class), in `repo`'s view: a
/// rewrite of a snapshot that a landed command made (a commit of the
/// working copy, a describe, the edits an undo or an op restore re-applied
/// on the working copy it restored) and that no landed undo or op restore took
/// back (undid the command, restored to before it, or, having seen it,
/// showed its old snapshot again) leaves its old snapshot invisible: everything built on it, by
/// commands that never saw the rewrite too, moved onto the replacement.
/// Unless two such rewrites of one snapshot differ (a divergent change:
/// nothing follows either, and it stays visible, with what is below and
/// on it).
fn check_rewrites_followed(cmds: &[RwCmd], repo: &Repo, at: &str) -> Result<(), TestCaseError> {
    // Taken back by an undo or op restore that is itself in force (not
    // taken back by an undo of it).
    fn in_force(cmds: &[RwCmd], r: usize) -> bool {
        !cmds.iter().enumerate().any(|(x, c)| c.landed.is_some() && c.retracts.iter().any(|o| cmds[r].ops.contains(o)) && in_force(cmds, x))
    }
    let retracted = |op: &ObjectId| cmds.iter().enumerate().any(|(r, c)| c.landed.is_some() && c.retracts.contains(op) && in_force(cmds, r));
    // Every rewrite a command recorded: a commit's, a describe's, and an
    // undo's or op restore's (the edits it re-applied).
    fn recorded(c: &RwCmd) -> impl Iterator<Item = &(ObjectId, ObjectId, ObjectId)> {
        c.rewrites.iter().chain(c.reapplied.iter())
    }
    let live: Vec<(usize, (ObjectId, ObjectId))> = cmds
        .iter()
        .enumerate()
        .filter(|(_, c)| c.landed.is_some())
        .flat_map(|(i, c)| recorded(c).filter(|r| !retracted(&r.0)).map(move |r| (i, (r.1, r.2))))
        .collect();
    // Snapshots two concurrent commands rewrote differently: a divergent
    // change, nothing follows either, so they stay where they are, with
    // their ancestors and what is built on them; and a merge does not
    // revisit that when one is taken back later (only a later merge with
    // both still to merge would see it).
    let landed: Vec<(usize, (ObjectId, ObjectId))> =
        cmds.iter().enumerate().filter(|(_, c)| c.landed.is_some()).flat_map(|(i, c)| recorded(c).map(move |r| (i, (r.1, r.2)))).collect();
    let concurrent = |i: usize, j: usize| cmds[i].landed.unwrap() >= cmds[j].forked && cmds[j].landed.unwrap() >= cmds[i].forked;
    // Or two that both still stand (a command that saw the first rewrote
    // the old version again: two versions of one change).
    let mut divergent: std::collections::HashSet<ObjectId> =
        landed.iter().filter(|(i, (o, n))| landed.iter().any(|(j, (o2, n2))| o2 == o && n2 != n && concurrent(*i, *j))).map(|(_, (o, _))| *o).collect();
    divergent.extend(live.iter().filter(|(_, (o, n))| live.iter().any(|(_, (o2, n2))| o2 == o && n2 != n)).map(|(_, (o, _))| *o));
    let at_or_above = |a: &ObjectId, b: &ObjectId| a == b || repo.is_ancestor(a, b).unwrap();
    let have = keys_of(repo.view());
    // What each snapshot was rewritten from (the op log's records, merges'
    // rebases included).
    let mut from: std::collections::HashMap<ObjectId, Vec<ObjectId>> = Default::default();
    for r in repo.ops().walk(repo.heads()) {
        for (o, ns) in r.unwrap().1.rewritten {
            for n in ns {
                from.entry(n).or_default().push(o);
            }
        }
    }
    let earlier = |v: &ObjectId| {
        let mut out = vec![*v];
        let mut i = 0;
        while i < out.len() && out.len() < 64 {
            for o in from.get(&out[i]).into_iter().flatten() {
                if !out.contains(o) {
                    out.push(*o);
                }
            }
            i += 1;
        }
        out
    };
    for (i, (old, new)) in &live {
        // On or below a divergent change: nothing follows it, so what is on
        // it stays too.
        if divergent.iter().any(|d| at_or_above(d, old)) {
            continue;
        }
        // A command that saw the rewrite, or saw it taken back (by an undo
        // or op restore an undo later took back in turn: what it did
        // meanwhile was built on the old version, as it would have been in
        // a sequence of commands).
        let saw = |j: &RwCmd| {
            j.landed.is_some()
                && (cmds[*i].landed.unwrap() < j.forked
                    || cmds.iter().any(|r| r.landed.is_some_and(|l| l < j.forked) && r.retracts.iter().any(|o| cmds[*i].ops.contains(o))))
        };
        let by: Vec<String> = have
            .iter()
            .filter(|(k, v)| !matches!(k, Key::Rtag(_)) && at_or_above(old, &v.0))
            .filter(|(_, v)| !divergent.iter().any(|d| at_or_above(d, &v.0) && at_or_above(old, d)))
            // Set on it by a command that saw the rewrite (a tag on the old
            // version, a workspace on it, an undo's revert): deliberate, and
            // so is what a concurrent rewrite of its ancestors made of it.
            // A conflict's loser stays as a head (BUG-1298), so a written
            // value counts under any key.
            // What such a command set or made, or a rebase made of it.
            .filter(|(k, v)| {
                let versions = earlier(&v.0);
                !cmds.iter().any(|j| {
                    saw(j)
                        && (j.writes.iter().any(|(k2, w)| w.is_some_and(|w| versions.contains(&w.0)) || (k2 == *k && w.is_some_and(|w| at_or_above(old, &w.0))))
                            || recorded(j).any(|(_, _, n)| versions.contains(n)))
                })
            })
            .map(|(k, v)| format!("{k:?}={}", v.0.short()))
            .collect();
        prop_assert!(by.is_empty(), "{}: {} (rewritten into {} by '{}') is still visible, from {:?}", at, old.short(), new.short(), cmds[*i].what, by);
    }
    Ok(())
}


/// The model check of auto-rebase through concurrent merges (op log merges
/// review): `nw` writers commit in their own workspaces, any command
/// describes a visible commit (so a commit lands on a snapshot another
/// command rewrote), and (with `undo`) undoes the last command of a
/// workspace or restores an earlier operation, and describes run
/// concurrently with each other (two describes of one commit make a
/// divergent change, BUG-1403); settlers merge random subsets of the
/// heads; everything publishes after a random delay. Every command's view
/// and the final one satisfy [`check_rewrites_followed`].
fn check_rewrites_follow_through_merges(disk: bool, nw: usize, undo: bool, old_refs: bool, steps: &[u16]) -> Result<(), TestCaseError> {
    check_rewrites_follow_with(disk, nw, undo, old_refs, false, steps)
}

/// [`check_rewrites_follow_through_merges`], with `second_versions`: a
/// describe may pick an old version a landed command rewrote (one a tag or
/// a workspace of `old_refs` shows), which makes a second version of the
/// change (BUG-1488). A separate flag: the describes of the pinned inputs
/// of the other checks keep picking what they picked.
fn check_rewrites_follow_with(disk: bool, nw: usize, undo: bool, old_refs: bool, second_versions: bool, steps: &[u16]) -> Result<(), TestCaseError> {
    let me = Identity::generate("alice");
    let truth = Device::new(disk);
    {
        let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        let root = repo.root_id();
        for w in 0..nw {
            repo.create_workspace(&format!("w{w}"), vec![root]).unwrap();
        }
    }
    let mut cmds: Vec<RwCmd> = Vec::new();
    let mut files = vec![0usize; nw];
    let mut described = 0usize;
    // (fork, heads it was forked with, its command, the slots it holds)
    let mut pending: Vec<Pending> = Vec::new();
    for (clock, &b) in steps.iter().enumerate() {
        let clock = clock + 1;
        let heads = op_heads(&*truth.fs);
        let arg = (b / 16) as usize;
        let kind = b % 16;
        if kind >= 12 {
            if kind == 15 {
                let pick: Vec<String> = heads.iter().enumerate().filter(|(i, _)| (arg >> (i % 10)) & 1 == 1).map(|(_, h)| h.clone()).collect();
                if pick.len() < 2 {
                    continue;
                }
                let fork = truth.fork(&pick);
                let repo = Repo::open(fork.fs.clone(), Some(me.clone()), "alice").unwrap();
                prop_assert_eq!(repo.heads().len(), 1, "the settler merged its heads");
                drop(repo);
                pending.push((fork, pick, None, Vec::new()));
            } else if !pending.is_empty() {
                let (fork, heads, c, _) = pending.remove(arg % pending.len());
                truth.land(&fork, &heads);
                if let Some(c) = c {
                    cmds[c].landed = Some(clock);
                }
            }
            continue;
        }
        let w = arg % nw;
        let ws = format!("w{w}");
        // Without `undo` (BUG-1444), undos and op restores turn into more
        // describes.
        let kind = match (undo, kind) {
            (false, 8..=11) => 4,
            (_, k) => k,
        };
        let slots: Vec<String> = match kind {
            0..=3 | 8 | 9 => vec![ws.clone()],
            10 => (0..nw).map(|w| format!("w{w}")).collect(),
            7 if old_refs => vec![format!("o{}", arg % 2)],
            // Without `undo`, one describe at a time: two concurrent
            // describes of a snapshot make a divergent change.
            4..=7 if !undo => vec!["describe".to_string()],
            _ => Vec::new(),
        };
        if pending.iter().any(|p| p.3.iter().any(|s| slots.contains(s))) {
            continue;
        }
        let fork = truth.fork(&heads);
        let mut repo = Repo::open(fork.fs.clone(), Some(me.clone()), &format!("alice-{clock}")).unwrap();
        check_rewrites_followed(&cmds, &repo, &format!("step {clock} (a command's view)"))?;
        let start = repo.op_id();
        let before = repo.view().clone();
        let what;
        let mut retracts = Vec::new();
        // With `old_refs`, an old version (a snapshot a landed command
        // rewrote) for a tag or a workspace: showing it again undoes
        // nothing (BUG-1434).
        let olds: Vec<ObjectId> = cmds.iter().filter(|c| c.landed.is_some()).flat_map(|c| c.rewrites.iter().map(|r| r.1)).filter(|o| *o != repo.root_id()).collect();
        let kind = match kind {
            6 | 7 if old_refs && olds.is_empty() => 4,
            k => k,
        };
        let ok: Result<(), veil_core::VeilError> = match kind {
            6 if old_refs => {
                let (name, target) = (format!("old{}", arg % 3), olds[arg % olds.len()]);
                what = format!("tag {name} on the old version {}", target.short());
                repo.set_tag(&name, target, true)
            }
            7 if old_refs => {
                let (name, target) = (format!("o{}", arg % 2), olds[arg % olds.len()]);
                if repo.view().workspaces.contains_key(&name) {
                    continue;
                }
                what = format!("workspace {name} on the old version {}", target.short());
                repo.create_workspace(&name, vec![target]).map(|_| ())
            }
            0..=3 => {
                if !repo.view().workspaces.contains_key(&ws) {
                    continue;
                }
                repo.set_command_workspace(Some(ws.clone()));
                let n = files[w];
                files[w] += 1;
                what = format!("commit {ws} {n}");
                let ov = repo.workspace_overlay(&ws).unwrap();
                ov.write(&VPath::new(&format!("f{w}-{n}")).unwrap(), b"x\n").unwrap();
                repo.snapshot_workspace(&ws, &ov).unwrap();
                repo.commit_working_copy(&ws, &format!("{ws} {n}")).map(|_| ())
            }
            4..=7 => {
                // Describe a visible commit (not a working copy), and,
                // without `second_versions`, not an old version a landed
                // command rewrote (a second version of a change, BUG-1488).
                let rewritten: std::collections::HashSet<ObjectId> = match second_versions {
                    true => Default::default(),
                    false => cmds.iter().filter(|c| c.landed.is_some()).flat_map(|c| c.rewrites.iter().map(|r| r.1)).collect(),
                };
                let wcs: Vec<ObjectId> = repo.view().workspaces.values().map(|w| w.wc).chain(rewritten).collect();
                let cands: Vec<ObjectId> = repo
                    .exact()
                    .visible()
                    .unwrap()
                    .into_iter()
                    .filter(|s| *s != repo.root_id() && !wcs.contains(s))
                    .collect();
                if cands.is_empty() {
                    continue;
                }
                let target = cands[arg % cands.len()];
                described += 1;
                what = format!("describe {}", target.short());
                repo.describe(target, &format!("described {clock}")).map(|_| ())
            }
            8 | 9 => {
                repo.set_command_workspace(Some(ws.clone()));
                what = format!("undo in {ws}");
                repo.undo_keeping_edits(&ws).map(|_| ())
            }
            _ => {
                let back = arg % 5 + 1;
                let target = repo.ops().walk(&[repo.op_id()]).nth(back).map(|r| r.unwrap().0);
                what = format!("op restore {back} back");
                match target {
                    Some(op) => {
                        // It takes back every operation its view holds since.
                        retracts = repo.ops().split(&[start], &[op]).unwrap().only_a;
                        repo.restore_operation_keeping_edits("w0", op).map(|_| ())
                    }
                    None => Err(veil_core::VeilError::repo("no op")),
                }
            }
        };
        if ok.is_err() {
            continue;
        }
        // The operations this command wrote (not the merge it opened with).
        let mine = repo.ops().split(&[repo.op_id()], &[start]).unwrap().only_a;
        let (mut rewrites, mut reapplied) = (Vec::new(), Vec::new());
        for id in &mine {
            let op = repo.ops().get(id).unwrap();
            if let Some(u) = op.undo_of {
                retracts.push(u);
            }
            if !op.is_merge() {
                for (old, new) in op.rewritten {
                    if let [n] = new.as_slice() {
                        match kind < 8 {
                            true => rewrites.push((*id, old, *n)),
                            false => reapplied.push((*id, old, *n)),
                        }
                    }
                }
            }
        }
        let writes = writes(&before, repo.view());
        drop(repo);
        cmds.push(RwCmd { forked: clock, landed: None, ops: mine.into_iter().collect(), rewrites, reapplied, retracts, writes, what });
        pending.push((fork, heads, Some(cmds.len() - 1), slots));
    }
    let end = steps.len() + 1;
    for (fork, heads, c, _) in pending.drain(..) {
        truth.land(&fork, &heads);
        if let Some(c) = c {
            cmds[c].landed = Some(end);
        }
    }
    let repo = Repo::open(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
    prop_assert_eq!(repo.heads().len(), 1);
    check_rewrites_followed(&cmds, &repo, "the final view")?;
    let _ = (described, cmds.iter().map(|c| c.forked).max());
    Ok(())
}

/// The range of steps of a model check: `lo..hi`, or `VEIL_PROPS_STEPS`
/// (`120..300` for the long runs of a review).
fn steps(lo: usize, hi: usize) -> std::ops::Range<usize> {
    std::env::var("VEIL_PROPS_STEPS")
        .ok()
        .and_then(|v| v.split_once("..").and_then(|(a, b)| Some(a.parse().ok()?..b.parse().ok()?)))
        .unwrap_or(lo..hi)
}

fn review_cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: review_cases(64), failure_persistence: None, ..ProptestConfig::default() })]

    /// Guarantee 1 of the BUG-1294 review, memory backend, 2 to 5 writers.
    #[test]
    fn every_write_survives_concurrent_merges_memory(nw in 2usize..6, steps in prop::collection::vec(any::<u16>(), steps(20, 120))) {
        check_every_write_survives(false, nw, false, false, &steps)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: review_cases(64), failure_persistence: None, ..ProptestConfig::default() })]

    /// Guarantee 1 and 3 with describes among the commands (BUG-2550):
    /// settlers record a describe's rewrite again when they merge it, and
    /// it moves tags and working copies that other commands move too.
    #[test]
    fn every_write_survives_concurrent_merges_with_describes_memory(nw in 2usize..5, steps in prop::collection::vec(any::<u16>(), steps(20, 120))) {
        check_every_write_survives_with(false, nw, false, false, true, &steps)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: review_cases(8), failure_persistence: None, ..ProptestConfig::default() })]

    /// The same on the disk backend.
    #[test]
    fn every_write_survives_concurrent_merges_disk(nw in 2usize..5, steps in prop::collection::vec(any::<u16>(), steps(20, 80))) {
        check_every_write_survives(true, nw, false, false, &steps)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: review_cases(64), failure_persistence: None, ..ProptestConfig::default() })]

    /// Auto-rebase through concurrent merges (BUG-1299's class), memory
    /// backend.
    #[test]
    fn rewrites_follow_through_concurrent_merges_memory(nw in 2usize..5, steps in prop::collection::vec(any::<u16>(), steps(20, 100))) {
        check_rewrites_follow_through_merges(false, nw, false, false, &steps)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: review_cases(8), failure_persistence: None, ..ProptestConfig::default() })]

    /// The same on the disk backend.
    #[test]
    fn rewrites_follow_through_concurrent_merges_disk(nw in 2usize..4, steps in prop::collection::vec(any::<u16>(), steps(20, 70))) {
        check_rewrites_follow_through_merges(true, nw, false, false, &steps)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: review_cases(64), failure_persistence: None, ..ProptestConfig::default() })]

    /// The same with tags and workspaces set on old versions, without
    /// undoing anything (showing an old snapshot again undoes nothing,
    /// BUG-1434).
    #[test]
    fn rewrites_follow_with_refs_to_old_versions_memory(nw in 2usize..5, steps in prop::collection::vec(any::<u16>(), steps(20, 100))) {
        check_rewrites_follow_through_merges(false, nw, false, true, &steps)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: review_cases(8), failure_persistence: None, ..ProptestConfig::default() })]

    /// The same on the disk backend.
    #[test]
    fn rewrites_follow_with_refs_to_old_versions_disk(nw in 2usize..4, steps in prop::collection::vec(any::<u16>(), steps(20, 70))) {
        check_rewrites_follow_through_merges(true, nw, false, true, &steps)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: review_cases(64), failure_persistence: None, ..ProptestConfig::default() })]

    /// The same, where a describe may also pick an old version a landed
    /// command rewrote: a second version of the change, which with the
    /// first is a divergent change (BUG-1488).
    #[test]
    fn bug_1488_rewrites_follow_with_second_versions_memory(nw in 2usize..5, steps in prop::collection::vec(any::<u16>(), steps(20, 100))) {
        check_rewrites_follow_with(false, nw, false, true, true, &steps)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: review_cases(64), failure_persistence: None, ..ProptestConfig::default() })]

    /// The same with `vl undo` and `vl op restore` among the commands, and
    /// describes concurrent with each other (BUG-1403's reproduction, and
    /// BUG-1444's; BUG-2640 and BUG-2641 fixed the remaining causes).
    #[test]
    fn bug_1444_rewrites_follow_with_undo_restore_and_concurrent_describes(nw in 2usize..5, steps in prop::collection::vec(any::<u16>(), steps(20, 100))) {
        check_rewrites_follow_through_merges(false, nw, true, false, &steps)?;
    }
}

/// BUG-2944: the input GitHub CI's run of the test above shrank to (run
/// 44951820661, 2026-11-21): a change `op restore` rewrote stays visible.
#[test]
#[ignore = "BUG-2944: after `op restore 3 back`, the version it rewrote is still visible from the final view's head"]
fn bug_2944_op_restore_leaves_a_rewritten_version_visible() {
    let steps: Vec<u16> = vec![21874, 56464, 55109, 54244, 44308, 16580, 20507, 6281, 13382, 59506, 13274, 42265, 47245, 4750, 37796, 17177, 64752, 32355, 10352, 9104, 36987, 42920, 62131, 33646, 64817, 19671, 24123, 45587, 33863, 490, 28006, 26579, 37619, 51094, 46213, 61087, 27721, 21739, 57655, 40, 18295, 28977, 47764, 1419, 55337, 19571, 38028, 61193, 41439, 51039, 51210, 60253, 33644, 25014, 16044, 49116, 7938, 3735, 33694, 42058, 38820, 7268, 25464, 39238, 51640, 12364, 6535, 62572, 53055, 15562];
    check_rewrites_follow_through_merges(false, 3, true, false, &steps).unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig { cases: review_cases(64), failure_persistence: None, ..ProptestConfig::default() })]

    /// The model check with `vl undo` and `vl op restore` among the
    /// commands, and writes back to earlier values (memory backend).
    #[test]
    fn bug_1295_every_write_survives_with_undo_and_restore(nw in 2usize..6, steps in prop::collection::vec(any::<u16>(), steps(20, 120))) {
        check_every_write_survives(false, nw, true, true, &steps)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: review_cases(8), failure_persistence: None, ..ProptestConfig::default() })]

    /// The same on the disk backend.
    #[test]
    fn every_write_survives_with_undo_and_restore_disk(nw in 2usize..5, steps in prop::collection::vec(any::<u16>(), steps(20, 80))) {
        check_every_write_survives(true, nw, true, true, &steps)?;
    }
}


/// BUG-1297: the split of two sides' histories ends its walk once everything
/// queued is common. A merge has its newest parent's timestamp, so an
/// operation and a common descendant can share one; when the operation's
/// id sorts first it is walked first, as one side's, and the walk ended
/// before the common descendant marked it common: listed as only `a`'s,
/// its values counted as `a`'s changes (a removal on `b` lost to the
/// stale value) and its rewrites as new to `b`.
#[test]
fn split_lists_no_common_operation_as_one_sides() {
    use veil_core::oplog::{OpStore, Operation};
    let ops = OpStore::new(Arc::new(MemoryBackend::new()));
    let op = |parents: Vec<ObjectId>, timestamp: i64, description: String| Operation {
        parents,
        timestamp,
        user: "alice".into(),
        description,
        view: View::default(),
        manual_undo: None,
        undo_of: None,
        redo_of: None,
        workspace: None,
        rewritten: Default::default(),
        restore_of: None,
    };
    // `p`, and `m` on it with its timestamp, `p`'s id sorting after `m`'s.
    let p = ops.put(&op(vec![], 10, "p".into())).unwrap();
    let m = (0..)
        .map(|n| ops.put(&op(vec![p], 10, format!("m{n}"))).unwrap())
        .find(|m| *m < p)
        .unwrap();
    // `a` reaches `p` and `m`; `b` reaches `m` (so `p` too).
    let a = ops.put(&op(vec![p, m], 20, "a".into())).unwrap();
    let b = ops.put(&op(vec![m], 20, "b".into())).unwrap();
    let split = ops.split(&[a], &[b]).unwrap();
    assert_eq!(split.base, Some(m), "the nearest common operation");
    assert_eq!(split.only_a, vec![a], "{} is common", p.short());
    assert_eq!(split.only_b, vec![b]);
}

/// BUG-1401: the split's walk ends early on timestamps, which presumes a
/// command's operation is never older than its parents. The clamp
/// (`Repo::base_time`) makes that so for new operations, but operations
/// written before it (a clock set back) stay in the log: `n`, written
/// after `o` with the clock set back, is older than its parent. `a`
/// reaches `o` through `m` and `n`; `b` reaches `n`, so `o` is common.
/// The walk reached `o` as `a`'s and ended once only `n` (common, older
/// than every operation walked as one side's) was queued: `o` is listed as
/// `a`'s, and what it introduced counts as `a`'s changes (BUG-1297's
/// symptom).
#[test]
fn bug_1401_split_lists_no_common_operation_as_one_sides_with_older_children() {
    use veil_core::oplog::{OpStore, Operation};
    let ops = OpStore::new(Arc::new(MemoryBackend::new()));
    let op = |parents: Vec<ObjectId>, timestamp: i64, description: &str| Operation {
        parents,
        timestamp,
        user: "alice".into(),
        description: description.into(),
        view: View::default(),
        manual_undo: None,
        undo_of: None,
        redo_of: None,
        workspace: None,
        rewritten: Default::default(),
        restore_of: None,
    };
    let o = ops.put(&op(vec![], 100, "o")).unwrap();
    // The clock set back: `n` is older than its parent.
    let n = ops.put(&op(vec![o], 1, "n")).unwrap();
    let m = ops.put(&op(vec![o], 150, "m")).unwrap();
    let a = ops.put(&op(vec![m, n], 200, "a")).unwrap();
    let b = ops.put(&op(vec![n], 200, "b")).unwrap();
    let split = ops.split(&[a], &[b]).unwrap();
    assert_eq!(split.base, Some(n), "the nearest common operation");
    assert_eq!(split.only_b, vec![b]);
    assert!(!split.only_a.contains(&o), "{} is common (an ancestor of {}): {:?}", o.short(), n.short(), split.only_a.iter().map(|i| i.short()).collect::<Vec<_>>());
    assert_eq!(split.only_a, vec![a, m]);
}

/// BUG-1402: the op log's walk (`vl op log`, the operation `vl undo`
/// undoes) visits newest first by time, then id. Times tie (a merge has its
/// newest parent's, and a clock set back gives every operation its
/// parent's), and the id then decided: an operation came before one that
/// descends from it. And an operation older than its parent (written before
/// times were clamped) came after the parent. The walk must list every
/// operation after all its descendants, whatever the times.
#[test]
fn walk_lists_every_operation_after_its_descendants() {
    use veil_core::oplog::{OpStore, Operation};
    let op = |parents: Vec<ObjectId>, timestamp: i64, description: String| Operation {
        parents,
        timestamp,
        user: "alice".into(),
        description,
        view: View::default(),
        manual_undo: None,
        undo_of: None,
        redo_of: None,
        workspace: None,
        rewritten: Default::default(),
        restore_of: None,
    };
    let mut cases = 0;
    for n in 0..400 {
        let ops = OpStore::new(Arc::new(MemoryBackend::new()));
        // One time for all: `a`, and `p` and `d` on it; `m` merges them.
        let a = ops.put(&op(vec![], 10, format!("a{n}"))).unwrap();
        let p = ops.put(&op(vec![a], 10, format!("p{n}"))).unwrap();
        let d = ops.put(&op(vec![a], 10, format!("d{n}"))).unwrap();
        // An older child: `y` (time 50) on `a`, and `x` (time 5) on `y`.
        let y = ops.put(&op(vec![a], 50, format!("y{n}"))).unwrap();
        let x = ops.put(&op(vec![y], 5, format!("x{n}"))).unwrap();
        let mut parents = vec![p, d, x];
        parents.sort();
        let m = ops.put(&op(parents, 50, format!("m{n}"))).unwrap();
        // The id order that put an ancestor first.
        if a < d.min(p) {
            continue;
        }
        cases += 1;
        let order: Vec<ObjectId> = ops.walk(&[m]).map(|r| r.unwrap().0).collect();
        let at = |id: &ObjectId| order.iter().position(|o| o == id).unwrap();
        assert_eq!(order.len(), 6, "each once");
        for (child, parent) in [(m, p), (m, d), (m, x), (p, a), (d, a), (x, y), (y, a)] {
            assert!(at(&child) < at(&parent), "{} (a child) before {}: {:?}", child.short(), parent.short(), order.iter().map(|o| o.short()).collect::<Vec<_>>());
        }
        if cases == 8 {
            break;
        }
    }
    assert!(cases > 0, "the id order ran");
}

/// BUG-1432 (op log merges review, cycle 2): the walk's order (BUG-1402)
/// on a log written before operation times were clamped. `x` (time 5,
/// the clock set back) is older than its parent `y` (50), `z` is on `x`, and
/// `w` (60), another branch on `y`, is merged with `z` by `m`. The walk
/// reaches `y` from `w` first, with nothing yet saying `x` is below it, and
/// lists `y` (and `a`) before `x` and `z`, which descend from it: `vl undo`
/// in `x`'s workspace, with `w` another workspace's, would undo `y`.
#[test]
#[ignore = "BUG-1432 (closed, won't fix, owner 2026-11-19: only pre-release logs can hold it): on a log written before operation times were clamped, the walk can list an operation before an older descendant reached by a later path"]
fn bug_1432_walk_lists_an_operation_after_an_older_descendant_on_another_branch() {
    use veil_core::oplog::{OpStore, Operation};
    let op = |parents: Vec<ObjectId>, timestamp: i64, description: &str| Operation {
        parents,
        timestamp,
        user: "alice".into(),
        description: description.into(),
        view: View::default(),
        manual_undo: None,
        undo_of: None,
        redo_of: None,
        workspace: None,
        rewritten: Default::default(),
        restore_of: None,
    };
    let ops = OpStore::new(Arc::new(MemoryBackend::new()));
    let a = ops.put(&op(vec![], 1, "a")).unwrap();
    let y = ops.put(&op(vec![a], 50, "y")).unwrap();
    let w = ops.put(&op(vec![y], 60, "w")).unwrap();
    let x = ops.put(&op(vec![y], 5, "x")).unwrap();
    let z = ops.put(&op(vec![x], 6, "z")).unwrap();
    let mut parents = vec![w, z];
    parents.sort();
    let m = ops.put(&op(parents, 60, "m")).unwrap();
    let order: Vec<ObjectId> = ops.walk(&[m]).map(|r| r.unwrap().0).collect();
    let names = |o: &ObjectId| ops.get(o).unwrap().description;
    assert_eq!(order.len(), 6, "each once: {:?}", order.iter().map(names).collect::<Vec<_>>());
    let at = |id: &ObjectId| order.iter().position(|o| o == id).unwrap();
    for (child, parent) in [(m, w), (m, z), (w, y), (z, x), (x, y), (y, a)] {
        assert!(at(&child) < at(&parent), "{} (a child) after {}: {:?}", names(&child), names(&parent), order.iter().map(names).collect::<Vec<_>>());
    }
}

/// BUG-1435 (op log merges review, cycle 2): the model check must see a
/// conflict's loser dropped. A and B snapshot workspace `w` concurrently
/// (`v1`, `v2`, two versions of its working copy, one change); the view
/// below holds B's and has lost A's operation (A's objects are there), as a
/// merge that dropped the loser would leave it. `check_model` counts `v1`
/// visible because `v2`, a version of the same change, is: the correction
/// for values a concurrent rewrite moved (BUG-1299) matches by change id,
/// not by a rewrite the op log records, so it accepts the lost write.
#[test]
fn bug_1435_the_model_check_sees_a_conflicts_loser_dropped() {
    let me = Identity::generate("alice");
    let truth = Device::new(false);
    {
        let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        let root = repo.root_id();
        repo.create_workspace("w", vec![root]).unwrap();
    }
    let heads = op_heads(&*truth.fs);
    let snap = |d: &Device, body: &[u8]| {
        let mut r = Repo::open(d.fs.clone(), Some(me.clone()), "alice").unwrap();
        r.set_command_workspace(Some("w".into()));
        let ov = r.workspace_overlay("w").unwrap();
        ov.write(&VPath::new("f").unwrap(), body).unwrap();
        r.snapshot_workspace("w", &ov).unwrap().snapshot
    };
    let (a, b) = (truth.fork(&heads), truth.fork(&heads));
    let v1 = snap(&a, b"from A\n");
    let v2 = snap(&b, b"from B\n");
    truth.land(&b, &heads);
    for f in repo_files(&*a.fs) {
        if f.as_str().starts_with(".veil/objects/") && !truth.fs.exists(&f).unwrap() {
            truth.fs.write(&f, &a.fs.read(&f).unwrap()).unwrap();
        }
    }
    let repo = Repo::open(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
    assert_eq!(repo.workspace_wc("w").unwrap(), v2, "B's working copy");
    assert!(!repo.view().refs().iter().any(|r| *r == v1 || repo.is_ancestor(&v1, r).unwrap()), "A's working copy is gone from the view");
    assert_eq!(repo.snapshot(&v1).unwrap().change_id, repo.snapshot(&v2).unwrap().change_id, "two versions of one change");
    let w = Key::Ws("w".into());
    let cmds = vec![
        Cmd { forked: 1, landed: Some(3), writes: vec![(w.clone(), Some((v1, None)))], what: "snapshot w (A)".into(), commit: None },
        Cmd { forked: 2, landed: Some(4), writes: vec![(w, Some((v2, None)))], what: "snapshot w (B)".into(), commit: None },
    ];
    assert!(check_model(&cmds, &repo, &Default::default(), "the view").is_err(), "the model check accepted a view that dropped the conflict's loser");
}

/// A backend that counts the operations read (`.veil/ops/`).
#[derive(Debug, Default)]
struct CountingOps {
    inner: MemoryBackend,
    reads: std::sync::atomic::AtomicUsize,
}

impl StorageBackend for CountingOps {
    fn kind(&self) -> &'static str {
        "counting"
    }
    fn read(&self, path: &VPath) -> veil_core::Result<Vec<u8>> {
        if path.as_str().starts_with(".veil/ops/") {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
    fn set_executable(&self, path: &VPath, x: bool) -> veil_core::Result<()> {
        self.inner.set_executable(path, x)
    }
}

/// BUG-1433 (op log merges review, cycle 2): the cost of the op log's walk
/// with one time for many operations. With the clock set back, every
/// operation takes its parent's time (the clamp), until the clock catches
/// up: an hour set back, an hour of operations; a clock once a year ahead,
/// a year. The walk (BUG-1402) gathers every operation of the newest time
/// before it lists the first, so `vl op log -n 5`, `vl undo` and `vl redo`
/// read all of them (2.8 s for 1,000 tag moves in a debug build). The
/// first few should cost a few reads, as before.
#[test]
fn bug_1433_the_first_operations_of_the_walk_cost_a_few_reads_with_one_time() {
    use veil_core::oplog::{OpStore, Operation};
    let backend = Arc::new(CountingOps::default());
    let ops = OpStore::new(backend.clone());
    let mut last: Option<ObjectId> = None;
    for i in 0..500 {
        let op = Operation {
            parents: last.into_iter().collect(),
            timestamp: 10,
            user: "alice".into(),
            description: format!("tag {i}"),
            view: View::default(),
            manual_undo: None,
            undo_of: None,
            redo_of: None,
            workspace: None,
            rewritten: Default::default(),
            restore_of: None,
        };
        last = Some(ops.put(&op).unwrap());
    }
    let head = last.unwrap();
    backend.reads.store(0, std::sync::atomic::Ordering::SeqCst);
    let first: Vec<ObjectId> = ops.walk(&[head]).take(5).map(|r| r.unwrap().0).collect();
    let reads = backend.reads.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(first.len(), 5, "the walk listed five");
    assert_eq!(first[0], head, "newest first");
    assert!(reads <= 20, "the first five of 500 operations of one time read {reads} operations");
}

/// The walk's order on ties that strictly later command times leave: a
/// merge has its newest parent's time. `a` (10), `c` on it (11); `m1`
/// merges `a` and `b` (5), with `a`'s time; `m2` merges `m1` and `c`, with
/// `c`'s. From `m2`, `a` is reached through `c` while `m1`, which descends
/// from it with its time, is still queued: `a` must wait for `m1`.
#[test]
fn walk_lists_a_merge_before_the_parent_whose_time_it_has() {
    use veil_core::oplog::{OpStore, Operation};
    let op = |parents: Vec<ObjectId>, timestamp: i64, description: String| Operation {
        parents,
        timestamp,
        user: "alice".into(),
        description,
        view: View::default(),
        manual_undo: None,
        undo_of: None,
        redo_of: None,
        workspace: None,
        rewritten: Default::default(),
        restore_of: None,
    };
    let mut cases = 0;
    for n in 0..400 {
        let ops = OpStore::new(Arc::new(MemoryBackend::new()));
        let a = ops.put(&op(vec![], 10, format!("a{n}"))).unwrap();
        let b = ops.put(&op(vec![], 5, format!("b{n}"))).unwrap();
        let c = ops.put(&op(vec![a], 11, format!("c{n}"))).unwrap();
        let mut p1 = vec![a, b];
        p1.sort();
        let m1 = ops.put(&op(p1, 10, format!("m1-{n}"))).unwrap();
        let mut p2 = vec![m1, c];
        p2.sort();
        let m2 = ops.put(&op(p2, 11, format!("m2-{n}"))).unwrap();
        // The id order that lists `a` first among the two of time 10.
        if a < m1 {
            continue;
        }
        cases += 1;
        let order: Vec<ObjectId> = ops.walk(&[m2]).map(|r| r.unwrap().0).collect();
        let at = |id: &ObjectId| order.iter().position(|o| o == id).unwrap();
        for (child, parent) in [(m2, m1), (m2, c), (c, a), (m1, a), (m1, b)] {
            assert!(at(&child) < at(&parent), "{} (a child) after {}", child.short(), parent.short());
        }
        if cases == 8 {
            break;
        }
    }
    assert!(cases > 0, "the id order ran");
}

/// BUG-1296: a tag moved away and back (by `vl tag set` or an undo, which
/// the merge counts as a change) concurrently with its deletion. Both
/// sides introduced their value, so the merge compares with the nearest
/// common operation, which holds the moved-back value: that side looks
/// unchanged and the deletion wins, though a change beats a removal.
#[test]
fn bug_1296_a_tag_moved_back_survives_a_concurrent_delete() {
    let me = Identity::generate("alice");
    let truth = Device::new(false);
    let (a, b);
    {
        let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        repo.create_workspace("w", vec![repo.root_id()]).unwrap();
        let ov = repo.workspace_overlay("w").unwrap();
        ov.write(&VPath::new("f").unwrap(), b"x\n").unwrap();
        repo.snapshot_workspace("w", &ov).unwrap();
        a = repo.commit_working_copy("w", "a").unwrap().0;
        b = repo.root_id();
        repo.set_tag("t", a, true).unwrap();
    }
    let heads = op_heads(&*truth.fs);
    let (back, del) = (truth.fork(&heads), truth.fork(&heads));
    {
        let mut repo = Repo::open(back.fs.clone(), Some(me.clone()), "alice").unwrap();
        repo.set_tag("t", b, true).unwrap();
        repo.set_tag("t", a, true).unwrap();
        assert_eq!(repo.view().tags["t"].target, a);
    }
    {
        let mut repo = Repo::open(del.fs.clone(), Some(me.clone()), "alice").unwrap();
        repo.delete_tag("t").unwrap();
        assert!(!repo.view().tags.contains_key("t"));
    }
    truth.land(&back, &heads);
    truth.land(&del, &heads);
    let repo = Repo::open(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
    assert_eq!(repo.heads().len(), 1, "settled");
    assert_eq!(repo.view().tags.get("t").map(|t| t.target), Some(a), "the concurrent move (a change) beats the removal");
}

/// BUG-1298: a conflict's losing target stays visible through the rest of
/// the fold. Two commands move tag `t` (from `z` to `x`, a commit that is
/// a head, and to `y`) while a third restores an operation from before `x`, which
/// drops the head. When the fold merges the two moves first, `x` loses and
/// "stays a visible head" (it already was one); the restore, merged next,
/// dropped that head and the other side kept it unchanged, so the head
/// went: `x` vanished, though the warning said it stays.
#[test]
fn bug_1298_a_conflicts_loser_stays_visible_through_the_fold() {
    let me = Identity::generate("alice");
    let mut hits = 0;
    for _ in 0..200 {
        let truth = Device::new(false);
        let (x, y, before);
        {
            let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
            let root = repo.root_id();
            repo.create_workspace("v", vec![root]).unwrap();
            repo.create_workspace("w", vec![root]).unwrap();
            let commit = |repo: &mut Repo, ws: &str, f: &str| {
                repo.set_command_workspace(Some(ws.into()));
                let ov = repo.workspace_overlay(ws).unwrap();
                ov.write(&VPath::new(f).unwrap(), b"x\n").unwrap();
                repo.snapshot_workspace(ws, &ov).unwrap();
                repo.commit_working_copy(ws, f).unwrap().0
            };
            // `t` on `z` (not on a parent a later commit moves it from).
            y = commit(&mut repo, "v", "y");
            let z = commit(&mut repo, "v", "z");
            repo.set_tag("t", z, true).unwrap();
            before = repo.op_id();
            x = commit(&mut repo, "w", "x");
            assert_eq!(repo.view().tags["t"].target, z);
            repo.remove_workspace("w").unwrap();
            assert!(repo.view().heads.contains(&x), "x is a head");
        }
        let k = op_heads(&*truth.fs);
        let (a, b, r) = (truth.fork(&k), truth.fork(&k), truth.fork(&k));
        let mut ids = Vec::new();
        for (fork, target) in [(&a, x), (&b, y)] {
            let mut repo = Repo::open(fork.fs.clone(), Some(me.clone()), "alice").unwrap();
            repo.set_tag("t", target, true).unwrap();
            assert_eq!(repo.view().tags["t"].target, target);
            ids.push(repo.op_id());
        }
        let rid = {
            let mut repo = Repo::open(r.fs.clone(), Some(me.clone()), "alice").unwrap();
            repo.restore_operation(before).unwrap();
            assert!(!repo.view().heads.contains(&x), "the restore dropped the head");
            repo.op_id()
        };
        // The fold merges the restore last.
        if !ids.iter().all(|i| rid > *i) {
            continue;
        }
        hits += 1;
        for f in [&a, &b, &r] {
            truth.land(f, &k);
        }
        let mut repo = Repo::open(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        assert_eq!(repo.heads().len(), 1, "settled");
        let won = repo.view().tags["t"].target;
        assert!(won == x || won == y, "a move wins");
        let refs = repo.view().refs();
        for c in [x, y] {
            assert!(refs.iter().any(|r| *r == c || repo.is_ancestor(&c, r).unwrap()), "{} stays visible", c.short());
        }
        assert!(repo.take_warnings().iter().any(|w| w.starts_with("tag 't'")), "the conflict is warned of");
        if hits == 3 {
            break;
        }
    }
    assert!(hits > 0, "the interleaving ran");
}

/// BUG-1298's shape as a property (op log merges review, cycle 2, BUG-1435):
/// `n` commands move one tag concurrently, each to its own commit that is a
/// head only (its workspace removed), and `r` op restores to before those
/// commits drop the heads, all merged in one fold of every head, in an
/// order the random ids decide. Every target a move wrote stays visible:
/// the winner as the tag, the losers as heads, though the restores dropped
/// them (they never saw the moves).
fn check_losers_stay_visible_through_the_fold(n: usize, r: usize) -> Result<(), TestCaseError> {
    let me = Identity::generate("alice");
    let truth = Device::new(false);
    let (targets, before);
    {
        let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        let root = repo.root_id();
        // `t` on a commit of its own (a commit moves the tags on its
        // parent, and the targets below are on the root).
        repo.create_workspace("base", vec![root]).unwrap();
        repo.set_command_workspace(Some("base".into()));
        let ov = repo.workspace_overlay("base").unwrap();
        ov.write(&VPath::new("base").unwrap(), b"b\n").unwrap();
        repo.snapshot_workspace("base", &ov).unwrap();
        let (b, _) = repo.commit_working_copy("base", "base").unwrap();
        repo.set_tag("t", b, true).unwrap();
        before = repo.op_id();
        let mut ts = Vec::new();
        for i in 0..n {
            let ws = format!("x{i}");
            repo.create_workspace(&ws, vec![root]).unwrap();
            repo.set_command_workspace(Some(ws.clone()));
            let ov = repo.workspace_overlay(&ws).unwrap();
            ov.write(&VPath::new(&format!("f{i}")).unwrap(), b"x\n").unwrap();
            repo.snapshot_workspace(&ws, &ov).unwrap();
            ts.push(repo.commit_working_copy(&ws, &ws).unwrap().0);
            repo.remove_workspace(&ws).unwrap();
        }
        prop_assert!(ts.iter().all(|t| repo.view().heads.contains(t)), "each target is a head");
        prop_assert_eq!(repo.view().tags["t"].target, b, "t stays on its commit");
        targets = ts;
    }
    let k = op_heads(&*truth.fs);
    let mut forks = Vec::new();
    for t in &targets {
        let f = truth.fork(&k);
        let mut repo = Repo::open(f.fs.clone(), Some(me.clone()), "alice").unwrap();
        repo.set_tag("t", *t, true).unwrap();
        prop_assert_eq!(repo.view().tags["t"].target, *t);
        drop(repo);
        forks.push(f);
    }
    for _ in 0..r {
        let f = truth.fork(&k);
        let mut repo = Repo::open(f.fs.clone(), Some(me.clone()), "alice").unwrap();
        repo.restore_operation(before).unwrap();
        prop_assert!(targets.iter().all(|t| !repo.view().heads.contains(t)), "the restore dropped the heads");
        drop(repo);
        forks.push(f);
    }
    for f in &forks {
        truth.land(f, &k);
    }
    let repo = Repo::open(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
    prop_assert_eq!(repo.heads().len(), 1, "settled");
    prop_assert!(targets.contains(&repo.view().tags["t"].target), "a move wins");
    let refs = repo.view().refs();
    for t in &targets {
        prop_assert!(refs.iter().any(|x| x == t || repo.is_ancestor(t, x).unwrap()), "{} (a move's target) stays visible", t.short());
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: review_cases(32), failure_persistence: None, ..ProptestConfig::default() })]

    /// A conflict's losers stay visible through a fold of three to seven
    /// heads (BUG-1298, BUG-1435).
    #[test]
    fn losers_stay_visible_through_the_fold(n in 2usize..6, r in 1usize..3) {
        check_losers_stay_visible_through_the_fold(n, r)?;
    }
}

/// BUG-1295: `vl undo` of a commit, merged with two other heads, one of
/// which saw the commit and one did not. The fold (in id order) can merge
/// those two first: the commit's rewrite of the working copy into the
/// commit is collected there (that side does not show the old working
/// copy), and then applied to the undo's working copy, which is that old
/// one: the workspace ends on the commit, the undo lost.
#[test]
fn bug_1295_an_undone_commit_stays_undone_through_a_three_way_merge() {
    let me = Identity::generate("alice");
    let mut hits = 0;
    for _ in 0..200 {
        let truth = Device::new(false);
        {
            let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
            repo.create_workspace("w", vec![repo.root_id()]).unwrap();
        }
        let p = op_heads(&*truth.fs);
        // `x`: a command that never saw the commit.
        let x = truth.fork(&p);
        {
            let mut repo = Repo::open(x.fs.clone(), Some(me.clone()), "alice").unwrap();
            repo.set_tag("x", repo.root_id(), true).unwrap();
        }
        {
            let mut repo = Repo::open(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
            repo.set_command_workspace(Some("w".into()));
            let ov = repo.workspace_overlay("w").unwrap();
            ov.write(&VPath::new("f").unwrap(), b"x\n").unwrap();
            repo.snapshot_workspace("w", &ov).unwrap();
            repo.commit_working_copy("w", "c").unwrap();
        }
        let k = op_heads(&*truth.fs);
        // `y` saw the commit; `u` undid it.
        let (y, u) = (truth.fork(&k), truth.fork(&k));
        let (yid, uid, undone);
        {
            let mut repo = Repo::open(y.fs.clone(), Some(me.clone()), "alice").unwrap();
            repo.set_tag("y", repo.root_id(), true).unwrap();
            yid = repo.op_id();
        }
        {
            let mut repo = Repo::open(u.fs.clone(), Some(me.clone()), "alice").unwrap();
            repo.set_command_workspace(Some("w".into()));
            repo.undo_keeping_edits("w").unwrap();
            undone = repo.workspace_wc("w").unwrap();
            uid = repo.op_id();
        }
        let xid = Repo::open(x.fs.clone(), Some(me.clone()), "alice").unwrap().op_id();
        // The fold merges `u` last.
        if !(uid > xid && uid > yid) {
            continue;
        }
        hits += 1;
        truth.land(&x, &p);
        truth.land(&y, &k);
        truth.land(&u, &k);
        let repo = Repo::open(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        assert_eq!(repo.heads().len(), 1, "settled");
        assert_eq!(repo.workspace_wc("w").unwrap(), undone, "the undo of the commit stays undone");
        if hits == 3 {
            break;
        }
    }
    assert!(hits > 0, "the interleaving ran");
}

/// Op log merges review, cycle 3: BUG-1434's class through a rewrite only
/// a merge recorded. A describes `x`; E, concurrently, builds `e` on `x`
/// (its own workspace); the settler's merge rebases `e` onto the new `x`
/// and records `e`'s rewrite. K, who saw that merge, tags the old `e` (a
/// pointer to the old version, nothing undone). F, who saw E but neither
/// A nor the merge, builds `f` on `e` in a workspace of its own. After the
/// last merge F's work sits on the merge's new `e`, not on the old one
/// nor on a second new version of it: showing an old snapshot again is
/// never an undo.
#[test]
fn a_tag_on_the_old_version_of_a_merge_rebased_snapshot_does_not_cancel_its_rebase() {
    let me = Identity::generate("alice");
    let commit = |repo: &mut Repo, ws: &str, file: &str| -> ObjectId {
        repo.set_command_workspace(Some(ws.into()));
        let ov = repo.workspace_overlay(ws).unwrap();
        ov.write(&VPath::new(file).unwrap(), b"x\n").unwrap();
        repo.snapshot_workspace(ws, &ov).unwrap();
        repo.commit_working_copy(ws, file).unwrap().0
    };
    let mut runs = 0;
    for _ in 0..6 {
        let truth = Device::new(false);
        let x = {
            let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
            repo.create_workspace("w", vec![repo.root_id()]).unwrap();
            commit(&mut repo, "w", "x")
        };
        let h0 = op_heads(&*truth.fs);
        let (a, e_dev) = (truth.fork(&h0), truth.fork(&h0));
        let x2 = Repo::open(a.fs.clone(), Some(me.clone()), "alice").unwrap().describe(x, "x, described").unwrap();
        let e = {
            let mut repo = Repo::open(e_dev.fs.clone(), Some(me.clone()), "alice").unwrap();
            repo.create_workspace("e", vec![x]).unwrap();
            commit(&mut repo, "e", "e")
        };
        truth.land(&e_dev, &h0);
        let he = op_heads(&*truth.fs);
        // F saw E only.
        let f_dev = truth.fork(&he);
        let f = {
            let mut repo = Repo::open(f_dev.fs.clone(), Some(me.clone()), "alice").unwrap();
            repo.create_workspace("g", vec![e]).unwrap();
            commit(&mut repo, "g", "f")
        };
        truth.land(&a, &h0);
        // The settler's merge rebases `e` onto `x2` and records it.
        let hae = op_heads(&*truth.fs);
        assert_eq!(hae.len(), 2, "A and E concurrent");
        let s = truth.fork(&hae);
        let e2 = {
            let repo = Repo::open(s.fs.clone(), Some(me.clone()), "alice").unwrap();
            assert_eq!(repo.heads().len(), 1, "the settler merged");
            let merge = repo.ops().get(&repo.op_id()).unwrap();
            assert!(merge.is_merge(), "a merge");
            let e2 = merge.rewritten.get(&e).and_then(|n| n.first().copied()).expect("the merge rebased e");
            assert_eq!(repo.snapshot(&e2).unwrap().parents.clone(), vec![x2], "onto the described x");
            e2
        };
        truth.land(&s, &hae);
        // K saw the merge, and tags the old `e`.
        let hm = op_heads(&*truth.fs);
        let k = truth.fork(&hm);
        Repo::open(k.fs.clone(), Some(me.clone()), "alice").unwrap().set_tag("old", e, true).unwrap();
        truth.land(&k, &hm);
        truth.land(&f_dev, &he);
        let repo = Repo::open(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        assert_eq!(repo.heads().len(), 1, "settled");
        assert_eq!(repo.view().tags["old"].target, e, "the tag stays on the old version");
        let g = repo.workspace_wc("g").unwrap();
        // F's commit, rebased: its parent is the merge's new `e`.
        let f2 = repo.snapshot(&g).unwrap().parents.clone();
        assert_eq!(f2.len(), 1);
        let f2 = f2[0];
        assert_ne!(f2, f, "F's commit moved off the old e");
        assert_eq!(repo.snapshot(&f2).unwrap().parents.clone(), vec![e2], "F's commit sits on the merge's new e ({}), not on another version of it", e2.short());
        runs += 1;
    }
    assert_eq!(runs, 6);
}

/// Op log merges review, cycle 3 (format): an op restore written before
/// `restore_of` existed (by an older `vl`: the restored operation named
/// only in its description) still takes back what it restored past when
/// it is merged. `x` and its child `c` are committed; a describe of `x`
/// rebases `c`; `u` restores the operation before the describe; `e`, who
/// never saw the describe, starts a workspace on `c`. Merged in either
/// order, `e`'s workspace stays on `c`: the describe was taken back, so
/// nothing follows its rewrite, as with a restore that records
/// `restore_of`.
#[test]
fn a_restore_written_before_restore_of_still_takes_back_what_it_restored_past() {
    let me = Identity::generate("alice");
    let commit = |repo: &mut Repo, file: &str| -> ObjectId {
        repo.set_command_workspace(Some("w".into()));
        let ov = repo.workspace_overlay("w").unwrap();
        ov.write(&VPath::new(file).unwrap(), b"x\n").unwrap();
        repo.snapshot_workspace("w", &ov).unwrap();
        repo.commit_working_copy("w", file).unwrap().0
    };
    for legacy in [true, false] {
        let mut orders = std::collections::HashSet::new();
        for _ in 0..40 {
            let truth = Device::new(false);
            let (x, c, before) = {
                let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
                repo.create_workspace("w", vec![repo.root_id()]).unwrap();
                let x = commit(&mut repo, "x");
                let c = commit(&mut repo, "c");
                (x, c, repo.op_id())
            };
            let p = op_heads(&*truth.fs);
            let e = truth.fork(&p);
            let eid = {
                let mut repo = Repo::open(e.fs.clone(), Some(me.clone()), "alice").unwrap();
                repo.create_workspace("e", vec![c]).unwrap();
                repo.op_id()
            };
            {
                let mut repo = Repo::open(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
                repo.describe(x, "x, described").unwrap();
                assert_ne!(repo.snapshot(&repo.workspace_wc("w").unwrap()).unwrap().parents[0], c, "the describe rebased c");
            }
            let k = op_heads(&*truth.fs);
            let u = truth.fork(&k);
            let uid = {
                let mut repo = Repo::open(u.fs.clone(), Some(me.clone()), "alice").unwrap();
                let id = match legacy {
                    true => {
                        let view = repo.ops().get(&before).unwrap().view;
                        let mut tx = repo.transaction(format!("restore to operation {}", before.short())).unwrap();
                        tx.view = view;
                        tx.record_always();
                        tx.commit().unwrap().expect("recorded")
                    }
                    false => repo.restore_operation(before).unwrap(),
                };
                assert_eq!(repo.ops().get(&id).unwrap().restore_of.is_none(), legacy, "written as {} vl writes it", if legacy { "an older" } else { "this" });
                assert_eq!(repo.snapshot(&repo.workspace_wc("w").unwrap()).unwrap().parents.clone(), vec![c], "the restore brought c back");
                id
            };
            orders.insert(uid < eid);
            truth.land(&e, &p);
            truth.land(&u, &k);
            let repo = Repo::open(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
            assert_eq!(repo.heads().len(), 1, "settled");
            let on = repo.snapshot(&repo.workspace_wc("e").unwrap()).unwrap().parents.clone();
            assert_eq!(on, vec![c], "e's workspace stays on c, the describe taken back (legacy {legacy})");
            assert_eq!(repo.snapshot(&repo.workspace_wc("w").unwrap()).unwrap().parents.clone(), vec![c], "w stays restored");
            if orders.len() == 2 {
                break;
            }
        }
        assert_eq!(orders.len(), 2, "both fold orders ran");
    }
}

/// BUG-1488 (op log merges review, cycle 3): a command that saw a
/// rewrite and rewrites the old version again makes a second version of
/// the change; the model check (`check_rewrites_followed`: "two that both
/// still stand") and the merge disagree on what follows. `x` and its child
/// `f` are committed in `w`. C (another process) commits in `w` on `f`.
/// Meanwhile A describes `x` (rebasing `f` into `f1`), tags the old `f`
/// (a pointer to the old version) and describes the old `f` (`f2`, on the
/// old `x`). Both rewrites of `f` stand, and differ: a divergent change,
/// which nothing follows, so C's commit stays on `f`. The merge instead
/// lets A's second describe replace the first (its operation descends
/// from the first's, `Repo::merge_plan`'s `replaced`), and moves C's
/// commit onto `f2`, the copy on the old `x`. With the two rewrites in
/// different steps of the fold (a head between them), the same merge
/// keeps them divergent, so the result depends on the order of the heads:
/// `rewrites_follow_with_refs_to_old_versions_memory` fails about 1 run
/// in 8 of 200 cases. Fixed: two versions that stand and differ are a
/// divergent change however they meet (no "the later one replaces"), and
/// the merge leaves a divergent snapshot where it is, rather than move it
/// through its parent's rewrite into a third version.
#[test]
fn bug_1488_a_second_version_of_a_change_is_divergent_in_the_merge() {
    let me = Identity::generate("alice");
    let commit = |repo: &mut Repo, file: &str| -> ObjectId {
        repo.set_command_workspace(Some("w".into()));
        let ov = repo.workspace_overlay("w").unwrap();
        ov.write(&VPath::new(file).unwrap(), b"x\n").unwrap();
        repo.snapshot_workspace("w", &ov).unwrap();
        repo.commit_working_copy("w", file).unwrap().0
    };
    let truth = Device::new(false);
    let (x, f) = {
        let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        repo.create_workspace("w", vec![repo.root_id()]).unwrap();
        let x = commit(&mut repo, "x");
        (x, commit(&mut repo, "f"))
    };
    let h0 = op_heads(&*truth.fs);
    let c_dev = truth.fork(&h0);
    let c = commit(&mut Repo::open(c_dev.fs.clone(), Some(me.clone()), "alice").unwrap(), "c");
    let (f1, f2) = {
        let mut repo = Repo::open(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        repo.describe(x, "x, described").unwrap();
        let f1: Vec<ObjectId> = repo.exact().visible().unwrap().into_iter().filter(|s| *s != f && repo.snapshot(s).unwrap().description.as_str() == "f").collect();
        assert_eq!(f1.len(), 1, "the describe rebased f once");
        repo.set_tag("old", f, true).unwrap();
        let f2 = repo.describe(f, "f, second version").unwrap();
        assert_eq!(repo.snapshot(&f2).unwrap().parents.clone(), vec![x], "the second version is on the old x");
        (f1[0], f2)
    };
    truth.land(&c_dev, &h0);
    let repo = Repo::open(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
    assert_eq!(repo.heads().len(), 1, "settled");
    assert!(repo.view().refs().iter().any(|r| *r == f1 || repo.is_ancestor(&f1, r).unwrap()), "the first version stays visible");
    assert_eq!(repo.view().tags["old"].target, f2, "the tag on the second version");
    // C's commit, by its description.
    let cs: Vec<ObjectId> = repo.exact().visible().unwrap().into_iter().filter(|s| repo.snapshot(s).unwrap().description.as_str() == "c").collect();
    assert_eq!(cs.len(), 1, "one commit c ({})", c.short());
    let on = repo.snapshot(&cs[0]).unwrap().parents.clone();
    assert_ne!(on, vec![f2], "C's commit followed the second version of f ({}), on the old x", f2.short());
    assert_eq!(on, vec![f], "C's commit stays on f: a divergent change, which nothing follows");
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: review_cases(40),
        failure_persistence: None,
        rng_seed: proptest::test_runner::RngSeed::Fixed(20261108),
        ..ProptestConfig::default()
    })]

    /// BUG-1503: the long runs of the auto-rebase model check (with and
    /// without tags and workspaces on old versions, 120 to 300 steps), at
    /// a pinned seed. The ids within a case are random (identities, change
    /// ids), so the pinned inputs failed some runs, not every one: about 1
    /// to 3 runs in 8 of 300 cases. 40 cases by default;
    /// `PROPTEST_CASES=300` is the long run of a review (about 3 minutes).
    #[test]
    fn bug_1503_rewrites_follow_in_long_runs(nw in 2usize..5, old_refs in any::<bool>(), steps in prop::collection::vec(any::<u16>(), 120..300)) {
        check_rewrites_follow_through_merges(false, nw, false, old_refs, &steps)?;
    }
}

/// BUG-1503, the case the long runs found, shrunk (37 steps, four writers,
/// workspaces on old versions). A writer commits its working copy (`W`
/// becomes the snapshot `I`, described as the commit `C`); concurrently a
/// describe rewrites the commit below (`X` into `X'`); a third command,
/// which saw the commit and not the describe, puts a workspace on the old
/// version `I`. One merge of the commit and the describe rebases `C` onto
/// `X'` (`C'`). The next merge, with the workspace's side, saw that side
/// show `C` where the shared history (older than the commit) did not, took
/// the rebase of `C` for undone ("the side showing `old` brought it back")
/// and dropped it, although that side had made `C`, not restored it. The
/// workspace then followed `I` to the stale `C`, below `X`, and the next
/// merges kept it there for the same reason: `X`, which the describe
/// rewrote, stayed visible under it. The engine was wrong, not the model:
/// a change left on a stale parent. The failure depends on the random ids
/// (which commit the describes pick, the order heads merge in), so the
/// input is replayed: it failed about 1 replay in 12, and must pass every
/// time.
#[test]
fn bug_1503_a_merge_rebase_of_a_commit_made_since_the_shared_history_is_not_taken_for_undone() {
    let steps: Vec<u16> = vec![
        38976, 22496, 50557, 34786, 48366, 19737, 39998, 8773, 41458, 13773, 30999, 37549, 15616, 675,
        59886, 16540, 17868, 55986, 26704, 4418, 64383, 1245, 4366, 50977, 21098, 7692, 61628, 39892,
        11438, 41440, 18067, 21447, 33646, 49770, 22220, 15473, 28086,
    ];
    let mut failed = Vec::new();
    for n in 0..160 {
        if let Err(e) = check_rewrites_follow_through_merges(false, 4, false, true, &steps) {
            failed.push((n, e.to_string()));
        }
    }
    assert!(failed.is_empty(), "{} replays in 160 failed; the first: {:?}", failed.len(), failed.first());
}

/// BUG-1489 (op log merges review, cycle 3): the model check of the
/// every-write guarantee (`check_model`) reported conflict losers dropped
/// that a later command had taken away on purpose, as the engine should.
/// Two concurrent commits each move `t0` (a commit moves the tags on its
/// working copy's parent), so one commit's value loses and stays visible,
/// below a workspace a third command creates on that commit; an op
/// restore that saw both commits restores the other one's view, taking
/// back the losing commit and the workspace. The check accepted a revert
/// only when it removed the loser's own head. (The other shape: an empty
/// working copy restored by an undo, the loser of a conflict, abandoned
/// by a concurrent `ws remove`: the workspace moves onto a new empty
/// change on its parents, which the check accepted without a conflict and
/// not with one.) This input failed 160 replays in 300.
#[test]
fn bug_1489_the_model_check_accepts_a_loser_a_restore_took_back() {
    let steps: Vec<u16> = vec![46400, 64147, 32158, 41390, 43653, 19720, 22388, 35165, 28269, 13147, 7548, 1001];
    for _ in 0..30 {
        check_every_write_survives(false, 2, true, true, &steps).unwrap();
    }
}

/// BUG-1534 (op log merges review, cycle 4): BUG-1444's model check,
/// un-ignored by `d0952e31`, still fails at its default length on fresh
/// seeds (1 copy in 8 of the first round, 8 copies at once, the default
/// 64 cases of 20 to 100 steps), with the default check's restriction for
/// BUG-1488 in place: a described snapshot is still visible below a
/// workspace and a head in a command's view. The input proptest shrank
/// to; the failure depends on more than the input (random identities
/// and change ids), so it is replayed and must pass every time. Traced
/// (BUG-1444): an op restore brings back a working copy that a concurrent
/// commit had snapshotted and committed; the restored ref follows those
/// rewrites to the commit, which no ref of the merged view showed, so the
/// merge's rebase never walked it and left it on a parent a describe had
/// rewritten since (two settlers' rebases of the commit, one made from
/// describes the restore took back, kept it from following either). It
/// failed 14 to 18 replays in 60.
#[test]
fn bug_1534_rewrites_follow_with_undo_restore_and_concurrent_describes_replayed() {
    let steps: Vec<u16> = vec![
        23264, 46812, 38543, 15785, 26640, 15929, 21122, 9261, 54694, 11624, 56747, 56534, 64520, 9806, 37357, 49583, 3432, 36839, 15965, 10860, 60463, 16525, 40514,
        57022, 50747, 3648, 51108, 2397, 57319, 561, 50299, 31356, 13164, 52425, 46111, 27490, 19082, 42794, 41270, 15707, 8779, 520, 21579, 22875, 32337, 53278, 29131,
        31106, 62687, 10664, 17995, 22145, 35556, 2332, 21623, 54787, 31423, 44553, 27785, 63043, 32785, 1767, 15465, 29833, 18441, 41238, 28578, 8449, 33227, 16513,
        13038, 40022, 32886, 18658, 62862, 28749, 14310, 18757, 46398, 33943, 2473, 19285, 27307, 25735, 13289, 40802, 23655, 45396, 30446, 4545, 38151, 30809,
    ];
    let mut failed = Vec::new();
    for n in 0..60 {
        if let Err(e) = check_rewrites_follow_through_merges(false, 3, true, false, &steps) {
            failed.push((n, e.to_string()));
        }
    }
    assert!(failed.is_empty(), "{} replays in 60 failed; the first: {:?}", failed.len(), failed.first());
}

/// BUG-1444: the input its model check shrank to at seed 5 (three writers;
/// no undo or restore takes part in the failure), up to the step that
/// failed: its first 54 steps. A describe's new version follows its
/// parent's rewrite onto a settler's rebased copy that no ref shows any
/// more, on a version a concurrent describe of the line's first commit
/// replaced; the rebase never walked the copy, and the replaced version
/// stayed visible below it
/// (`bug_1444_what_follows_a_rewrite_lands_on_a_current_snapshot` is that
/// shape built by hand). It failed 104 replays in 150; replayed, it must
/// pass every time. (The whole input, 28 steps more, reaches another cause
/// now and then, 5 replays in 1100, at step 80: it is pinned, ignored, as
/// `bug_2641_a_settlers_rebase_an_op_restore_went_back_past_replayed`.)
#[test]
fn bug_1444_rewrites_follow_with_concurrent_describes_replayed() {
    let steps: Vec<u16> = vec![
        12675, 1612, 47070, 57123, 55165, 16163, 44657, 21442, 48616, 10224, 34716, 24770, 33690, 66, 7935, 50658, 60607, 17734, 18538, 62880, 28974, 49248, 22749,
        35142, 22639, 15344, 8869, 57450, 62616, 42820, 57182, 46600, 55180, 45484, 28880, 64079, 39401, 52162, 775, 38990, 31215, 63410, 58254, 28812, 2127, 15756,
        11632, 4398, 49360, 42369, 41814, 33868, 65244, 21467,
    ];
    let mut failed = Vec::new();
    for n in 0..40 {
        if let Err(e) = check_rewrites_follow_through_merges(false, 3, true, false, &steps) {
            failed.push((n, e.to_string()));
        }
    }
    assert!(failed.is_empty(), "{} replays in 40 failed; the first: {:?}", failed.len(), failed.first());
}

/// BUG-1444, one of its two causes, built by hand: what follows a rewrite
/// must land on a current snapshot. `A` is committed in `w`; `B` and `C` on
/// it in `v`. A describe of `A` that saw neither (`A1`) is merged with them
/// by a settler, which rebases `B` (`B'`) and `C` onto `A1`. Meanwhile a
/// describe of `C` that never saw `A1` makes `C2` (on `B`), and a describe
/// of `A1` that never saw `B` makes `A2`. In the last merge the describe's
/// `C2` stands (the settler's rebase of `C` is no version), and `C2`
/// follows its parent's rewrite `B` → `B'`. Nothing shows `B'` any more
/// (the settler's rebased working copy gave way to the describe's), so the
/// rebase never walked it: `B'` stayed on `A1`, which `A2` replaced, and
/// `C2` was put on it, `A1` visible below. The replacement is part of the
/// rebase: `B'` moves onto `A2` first. Run until each of the three heads
/// was merged last (the fold order is by operation id).
#[test]
fn bug_1444_what_follows_a_rewrite_lands_on_a_current_snapshot() {
    let me = Identity::generate("alice");
    let open = |d: &Device| Repo::open(d.fs.clone(), Some(me.clone()), "alice").unwrap();
    let commit = |repo: &mut Repo, ws: &str, file: &str| -> ObjectId {
        repo.set_command_workspace(Some(ws.into()));
        let ov = repo.workspace_overlay(ws).unwrap();
        ov.write(&VPath::new(file).unwrap(), b"x\n").unwrap();
        repo.snapshot_workspace(ws, &ov).unwrap();
        repo.commit_working_copy(ws, file).unwrap().0
    };
    let mut last: std::collections::HashSet<&str> = Default::default();
    for _ in 0..200 {
        let truth = Device::new(false);
        let a = {
            let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
            repo.create_workspace("w", vec![repo.root_id()]).unwrap();
            commit(&mut repo, "w", "a")
        };
        let h0 = op_heads(&*truth.fs);
        // The describe of `a` that never saw `b` and `c`.
        let d1 = truth.fork(&h0);
        let a1 = open(&d1).describe(a, "a1").unwrap();
        let c = {
            let mut repo = open(&truth);
            repo.create_workspace("v", vec![a]).unwrap();
            commit(&mut repo, "v", "b");
            commit(&mut repo, "v", "c")
        };
        let h1 = op_heads(&*truth.fs);
        // The describe of `c` that never saw `a1`.
        let d3 = truth.fork(&h1);
        let (c2, d3_op) = {
            let mut repo = open(&d3);
            let c2 = repo.describe(c, "c2").unwrap();
            (c2, repo.op_id())
        };
        truth.land(&d1, &h0);
        let h2 = op_heads(&*truth.fs);
        assert_eq!(h2.len(), 2, "the commits and the describe of a");
        // The describe of `a1` that never saw `b` and `c`.
        let d1_head: Vec<String> = h2.iter().filter(|h| !h1.contains(h)).cloned().collect();
        assert_eq!(d1_head.len(), 1);
        let d4 = truth.fork(&d1_head);
        let (a2, d4_op) = {
            let mut repo = open(&d4);
            let a2 = repo.describe(a1, "a2").unwrap();
            (a2, repo.op_id())
        };
        // The settler: `b` and `c` onto `a1`.
        let m = truth.fork(&h2);
        let m_op = {
            let repo = open(&m);
            assert_eq!(repo.heads().len(), 1, "the settler merged");
            let merge = repo.ops().get(&repo.op_id()).unwrap();
            let b1 = merge.rewritten.get(&repo.snapshot(&c).unwrap().parents[0]).and_then(|n| n.first().copied()).expect("the settler rebased b");
            assert_eq!(repo.snapshot(&b1).unwrap().parents.clone(), vec![a1], "onto a1");
            repo.op_id()
        };
        truth.land(&m, &h2);
        truth.land(&d3, &h1);
        truth.land(&d4, &d1_head);
        assert_eq!(op_heads(&*truth.fs).len(), 3, "the settler's merge and the two describes");
        let repo = open(&truth);
        assert_eq!(repo.heads().len(), 1, "settled");
        let visible = repo.exact().visible().unwrap();
        let descs: Vec<String> = visible.iter().map(|s| repo.snapshot(s).unwrap().description.as_str().to_string()).collect();
        assert!(visible.contains(&a2), "a2 {} visible: {descs:?}", a2.short());
        assert!(!visible.contains(&a1) && !visible.contains(&a), "an old version of a is still visible: {descs:?}");
        // The described `c`, moved with `b` onto `a2`.
        let cs: Vec<ObjectId> = visible.iter().copied().filter(|s| repo.snapshot(s).unwrap().description.as_str() == "c2").collect();
        assert_eq!(cs.len(), 1, "one c2 ({}): {descs:?}", c2.short());
        let b_now = repo.snapshot(&cs[0]).unwrap().parents[0];
        assert_eq!(repo.snapshot(&b_now).unwrap().description.as_str(), "b");
        assert_eq!(repo.snapshot(&b_now).unwrap().parents.clone(), vec![a2], "b on a2");
        last.insert(match [m_op, d3_op, d4_op].iter().max().unwrap() {
            x if *x == m_op => "the settler",
            x if *x == d3_op => "the describe of c",
            _ => "the describe of a1",
        });
        if last.len() == 3 {
            break;
        }
    }
    assert_eq!(last.len(), 3, "each head merged last once: {last:?}");
}

/// BUG-2640 (found while fixing BUG-1444, by its model check: seed 50, and
/// seed 109 of the long runs, each failing every replay): an undo of an op
/// restore puts back in force the commands the restore took back, and
/// nothing applies their rewrites to what was put on the old snapshots
/// meanwhile. `A` is committed in `w`. A describe of `A` (`A1`) lands; an
/// op restore to before it takes it back (`A` stands again); a commit `C`
/// made on `A` by a command that saw neither lands, and its merge with
/// the restore rightly leaves it on `A`. Then `vl undo` undoes the restore:
/// the describe stands again and its view comes back (`A1`), but `C` stays
/// on `A`, the version the describe replaced, visible below it. Had the
/// restore and its undo not happened, the merge of the commit with the
/// describe would have moved `C` onto `A1`: a restore and its undo must
/// leave the same result.
#[test]
fn bug_2640_an_undo_of_a_restore_reapplies_the_rewrites_it_puts_back_in_force() {
    let me = Identity::generate("alice");
    let open = |d: &Device| Repo::open(d.fs.clone(), Some(me.clone()), "alice").unwrap();
    let commit = |repo: &mut Repo, ws: &str, file: &str| -> ObjectId {
        repo.set_command_workspace(Some(ws.into()));
        let ov = repo.workspace_overlay(ws).unwrap();
        ov.write(&VPath::new(file).unwrap(), b"x\n").unwrap();
        repo.snapshot_workspace(ws, &ov).unwrap();
        repo.commit_working_copy(ws, file).unwrap().0
    };
    let truth = Device::new(false);
    let (a, before) = {
        let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        repo.create_workspace("w", vec![repo.root_id()]).unwrap();
        repo.create_workspace("v", vec![repo.root_id()]).unwrap();
        let a = commit(&mut repo, "w", "a");
        (a, repo.op_id())
    };
    let h0 = op_heads(&*truth.fs);
    // The commit on `a`, by a command that sees neither the describe nor
    // the restore.
    let k = truth.fork(&h0);
    commit(&mut open(&k), "w", "c");
    let a1 = open(&truth).describe(a, "a1").unwrap();
    {
        let mut repo = open(&truth);
        repo.restore_operation(before).unwrap();
        assert!(repo.exact().visible().unwrap().contains(&a), "the restore brought a back");
    }
    let h1 = op_heads(&*truth.fs);
    truth.land(&k, &h0);
    assert_eq!(op_heads(&*truth.fs).len(), 2, "the restore and the commit");
    let _ = h1;
    {
        let mut repo = open(&truth);
        assert_eq!(repo.heads().len(), 1, "settled");
        let c: Vec<ObjectId> = repo.exact().visible().unwrap().into_iter().filter(|s| repo.snapshot(s).unwrap().description.as_str() == "c").collect();
        assert_eq!(c.len(), 1, "one commit c");
        assert_eq!(repo.snapshot(&c[0]).unwrap().parents.clone(), vec![a], "on a: the describe is taken back");
        // Undo the restore (in a workspace that did nothing since).
        repo.set_command_workspace(Some("v".into()));
        let (_, what) = repo.undo_keeping_edits("v").unwrap();
        assert!(what.starts_with("restore to operation"), "the undo undid the restore: {what}");
    }
    let repo = open(&truth);
    let visible = repo.exact().visible().unwrap();
    let descs: Vec<String> = visible.iter().map(|s| repo.snapshot(s).unwrap().description.as_str().to_string()).collect();
    assert!(visible.contains(&a1), "the describe is back in force: {descs:?}");
    assert!(!visible.contains(&a), "the version the describe replaced is still visible: {descs:?}");
    let c: Vec<ObjectId> = visible.iter().copied().filter(|s| repo.snapshot(s).unwrap().description.as_str() == "c").collect();
    assert_eq!(c.len(), 1, "one commit c: {descs:?}");
    assert_eq!(repo.snapshot(&c[0]).unwrap().parents.clone(), vec![a1], "the commit on a1");
}

/// BUG-2640: the input BUG-1444's model check shrank to at seed 50 (23
/// steps, two writers): a describe; an op restore to before it; a commit
/// made on the old version by a command that saw neither, merged with the
/// restore; then `vl undo` of the restore. The describe is in force again
/// and the commit stays on the version it replaced
/// (`bug_2640_an_undo_of_a_restore_reapplies_…` is this, built by hand).
/// It fails every replay, before BUG-1444's fix and after.
#[test]
fn bug_2640_an_undo_of_a_restore_seed_50_replayed() {
    let steps: Vec<u16> = vec![
        57600, 5947, 8063, 57644, 30607, 24192, 60884, 22268, 36740, 8932, 62002, 2987, 57788, 6348, 39405, 61518, 40713, 21894, 8070, 39670, 26613, 51229, 49270,
    ];
    let mut failed = Vec::new();
    for n in 0..10 {
        if let Err(e) = check_rewrites_follow_through_merges(false, 2, true, false, &steps) {
            failed.push((n, e.to_string()));
        }
    }
    assert!(failed.is_empty(), "{} replays in 10 failed; the first: {:?}", failed.len(), failed.first());
}

/// BUG-2640 through a merge: the input BUG-1444's model check shrank to at
/// seed 34 (57 steps, four writers). A describe of `A` lands; an op restore
/// takes it back; a concurrent describe of a commit on `A` is merged while
/// it is taken back, and stays on `A`; a second op restore, to the first
/// describe's operation, takes the first restore back, so that describe
/// stands again. Its command is shared history by then: no step of the
/// merge collects its rewrite, and what was put on `A` stays there. It
/// fails 16 to 18 replays in 40, before BUG-1444's fix and after.
#[test]
fn bug_2640_a_restore_of_a_restore_seed_34_replayed() {
    let steps: Vec<u16> = vec![
        27364, 17703, 51354, 31916, 38464, 41170, 64826, 60689, 19053, 58688, 20633, 27569, 10649, 24256, 44557, 41677, 45797, 55185, 9335, 5971, 31145, 42550, 31717,
        7276, 13012, 63083, 6623, 14053, 16992, 2956, 16860, 49377, 38865, 27157, 53168, 61004, 44283, 61343, 48990, 63942, 21793, 53445, 47387, 59346, 65319, 52957,
        46189, 28075, 65435, 27447, 44417, 56839, 31550, 32491, 2870, 26399, 49992,
    ];
    let mut failed = Vec::new();
    for n in 0..40 {
        if let Err(e) = check_rewrites_follow_through_merges(false, 4, true, false, &steps) {
            failed.push((n, e.to_string()));
        }
    }
    assert!(failed.is_empty(), "{} replays in 40 failed; the first: {:?}", failed.len(), failed.first());
}

/// BUG-2641, cause (c): the whole input BUG-1444's model check shrank to at
/// seed 5 (82 steps, three writers), whose first 54 steps are
/// `bug_1444_rewrites_follow_with_concurrent_describes_replayed`. With
/// BUG-1444's fix it still fails now and then at step 80 (5 replays in
/// 1100; traced on three of them): settlers rebased a described commit `X`
/// (`X'`, a rewrite only merges recorded); op restores then took the view
/// back past those merges, `X` visible again; a describe of `X` lands, and
/// a describe of its child, made by a command that had not seen that
/// describe, lands last, on `X`. The last merge counts the settlers'
/// recorded rebase as a second version of `X` beside the describe's (the
/// op log says an op restore takes back the operations it went back past,
/// and a merge's record is judged by the views instead), calls `X` a
/// divergent change, and leaves the late describe's result on `X`, which
/// the describe replaced. Replayed 300 times here, so that it fails most
/// runs (about 3 in 4).
#[test]
fn bug_2641_a_settlers_rebase_an_op_restore_went_back_past_replayed() {
    let steps: Vec<u16> = vec![
        12675, 1612, 47070, 57123, 55165, 16163, 44657, 21442, 48616, 10224, 34716, 24770, 33690, 66, 7935, 50658, 60607, 17734, 18538, 62880, 28974, 49248, 22749,
        35142, 22639, 15344, 8869, 57450, 62616, 42820, 57182, 46600, 55180, 45484, 28880, 64079, 39401, 52162, 775, 38990, 31215, 63410, 58254, 28812, 2127, 15756,
        11632, 4398, 49360, 42369, 41814, 33868, 65244, 21467, 31837, 45709, 59770, 32663, 47560, 9278, 32908, 45717, 33438, 62534, 1461, 37817, 13934, 55287, 6671,
        32262, 35521, 55142, 21340, 51850, 5331, 22376, 10040, 45448, 10573, 21973, 2000, 29418,
    ];
    let mut failed = Vec::new();
    for n in 0..300 {
        if let Err(e) = check_rewrites_follow_through_merges(false, 3, true, false, &steps) {
            failed.push((n, e.to_string()));
        }
    }
    assert!(failed.is_empty(), "{} replays in 300 failed; the first: {:?}", failed.len(), failed.first());
}

/// BUG-2642 (found by the fresh-seed runs of BUG-1444's fix, seed 5; as
/// often on the engine before it): the every-write model check with `vl
/// undo` and `vl op restore` (`bug_1295_every_write_survives_with_undo_and_
/// restore`, which runs in the default suite at the pinned seed) reports a
/// conflict's losing tag target dropped. The input it shrank to (86 steps,
/// three writers): a losing write settled in an earlier merge had its head
/// dropped because another head covered it, and a late concurrent undo or
/// restore dropped that covering head.
#[test]
fn bug_2642_every_write_survives_with_undo_and_restore_replayed() {
    let steps: Vec<u16> = vec![
        39438, 46179, 13977, 5347, 24046, 6292, 64970, 30544, 13397, 31427, 35815, 59922, 8737, 31656, 39721, 24544, 12840, 6634, 10893, 29748, 2557, 33089, 37837,
        54196, 51187, 43346, 29386, 23386, 53874, 23382, 27948, 4455, 55573, 15444, 11015, 42999, 31369, 31381, 35518, 54789, 40661, 43582, 49445, 43039, 59977,
        22963, 16514, 35358, 56444, 13409, 57453, 43064, 18169, 57752, 17261, 46911, 34575, 54112, 29340, 33762, 18110, 58763, 6829, 15614, 44645, 28325, 50918,
        31018, 60092, 46970, 44895, 61472, 38092, 9040, 11481, 17975, 31384, 29970, 49371, 60078, 19215, 55195, 34185, 45230, 8229, 9004,
    ];
    let mut failed = Vec::new();
    for n in 0..150 {
        if let Err(e) = check_every_write_survives(false, 3, true, true, &steps) {
            failed.push((n, e.to_string()));
        }
    }
    assert!(failed.is_empty(), "{} replays in 150 failed; the first: {:?}", failed.len(), failed.first());
}

/// BUG-2641: the long runs (120 to 300 steps) of BUG-1444's model check
/// still fail on fresh seeds after its fixes and with BUG-2640's cause
/// known: 6 seeds in 16. This is the input of seed 107 (244 steps, two
/// writers): an undo of an op restore putting rewrites back in force
/// (BUG-2640), plus the fold's intermediate view and retracted settlers'
/// rebases (BUG-2641).
#[test]
fn bug_2641_rewrites_follow_with_undo_restore_in_long_runs_replayed() {
    let steps: Vec<u16> = vec![
        33417, 15452, 58658, 19228, 1610, 57910, 14223, 50835, 37183, 61744, 14153, 13786, 1230, 54063, 32812, 40437, 29068, 62093, 21566, 27474, 10962, 18173, 37637,
        60058, 38671, 45702, 10491, 9341, 2111, 23845, 58850, 15853, 35167, 49343, 13819, 26979, 63827, 62, 20515, 32936, 59727, 9577, 4944, 63518, 28188, 49975,
        35600, 3699, 30974, 33755, 55374, 50674, 26741, 62995, 13558, 27664, 33468, 43274, 63652, 59526, 36955, 51381, 12215, 3626, 8023, 63735, 21513, 27951, 55129,
        60311, 58906, 47853, 22686, 4323, 64166, 55680, 6653, 3936, 21851, 42671, 30254, 29911, 11021, 32792, 27769, 63708, 6467, 29885, 19528, 1929, 21932, 26368,
        41894, 44293, 3528, 54503, 21461, 60099, 22153, 17798, 57402, 57143, 6519, 7950, 19235, 10168, 40225, 54197, 61699, 4134, 32242, 56645, 40392, 15854, 59749,
        12361, 19645, 3509, 30522, 9811, 22576, 26154, 18715, 65342, 12663, 2449, 9339, 26642, 49280, 28327, 8779, 38076, 20421, 25190, 22650, 27055, 40707, 35255,
        33875, 56357, 46226, 35075, 25030, 3645, 38480, 20716, 53509, 16545, 43683, 26432, 32845, 43583, 44313, 21511, 45984, 61380, 48258, 16504, 52796, 48456,
        58875, 10606, 61688, 26159, 7797, 53380, 49998, 49610, 33691, 60874, 47103, 9496, 59315, 32497, 2325, 26905, 56055, 34270, 58840, 60493, 27387, 1374, 16656,
        34590, 65066, 32323, 20226, 8587, 12488, 2367, 15815, 5991, 24998, 31620, 25796, 9186, 6095, 38109, 17448, 7847, 51362, 16243, 55897, 5101, 23469, 49318,
        38635, 34406, 19398, 63599, 46645, 64256, 37020, 62207, 22930, 31560, 16971, 146, 29663, 17391, 47992, 52538, 6239, 21016, 27041, 26540, 44186, 18821, 26776,
        17624, 18969, 13551, 8665, 62352, 14209, 5280, 5007, 29780, 29492, 25606, 56642, 42427, 53599, 35995,
    ];
    let mut failed = Vec::new();
    for n in 0..30 {
        if let Err(e) = check_rewrites_follow_through_merges(false, 2, true, false, &steps) {
            failed.push((n, e.to_string()));
        }
    }
    assert!(failed.is_empty(), "{} replays in 30 failed; the first: {:?}", failed.len(), failed.first());
}

/// BUG-2464, the second way: a describe of `X` runs concurrently with a
/// commit on `X` (its new working copy `W1`); a settler merges the two and
/// rebases `C` and `W1` onto `X'` (`W1'`, a rebase only that merge
/// records); meanwhile a command that saw the commit and not the describe
/// snapshots `W1` (`W2`). The final merge has two rewrites of `W1`: the
/// merge's rebase and the snapshot. Taken for a divergent change, nothing
/// followed either: `W1'` stayed visible beside `W2`, two versions of the
/// working copy's change, and the merge warned of a conflict on `w` that
/// is not one (`W1'` counted as a change). A merge's rebase is no change
/// and no version of one: the snapshot's rewrite stands and wins, `W2`
/// moves onto `X'` (with `C`), and `W1'`, the rebase of the head `W1` the
/// snapshot dropped, goes.
#[test]
fn bug_2464_a_merge_rebase_gives_way_to_a_concurrent_snapshot() {
    let me = Identity::generate("alice");
    let open = |d: &Device| Repo::open(d.fs.clone(), Some(me.clone()), "alice").unwrap();
    let write = |repo: &mut Repo, file: &str| {
        repo.set_command_workspace(Some("w".into()));
        let ov = repo.workspace_overlay("w").unwrap();
        ov.write(&VPath::new(file).unwrap(), b"x\n").unwrap();
        repo.snapshot_workspace("w", &ov).unwrap();
    };
    // The describe also rebases the working copy the commit snapshots (a
    // write of `w` by each command), so the settler warns of a conflict and
    // keeps one side's working copy by the order of the operation ids. This
    // reproduction is the order where it keeps the commit's (`W1'`, its
    // rebase); in the other it keeps the describe's rebase of the old one,
    // a write of `w` the later snapshot is concurrent with, and the final
    // merge warns of that real conflict (checked too). Built again with
    // fresh ids until the settler kept the commit's.
    let mut tries = 0;
    let (truth, x2, w1_rebased, m_dev, h2, s_dev, h1) = loop {
        tries += 1;
        assert!(tries <= 64, "the settler kept the describe's working copy 64 times");
        let truth = Device::new(false);
        let x = {
            let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
            repo.create_workspace("w", vec![repo.root_id()]).unwrap();
            write(&mut repo, "x");
            repo.commit_working_copy("w", "x").unwrap().0
        };
        let h0 = op_heads(&*truth.fs);
        // The describe, concurrent with the commit.
        let d_dev = truth.fork(&h0);
        let x2 = open(&d_dev).describe(x, "x, described").unwrap();
        {
            let mut repo = open(&truth);
            write(&mut repo, "c");
            repo.commit_working_copy("w", "c").unwrap();
        }
        let w1 = open(&truth).view().workspaces["w"].wc;
        let h1 = op_heads(&*truth.fs);
        // The command that saw the commit, not the describe.
        let s_dev = truth.fork(&h1);
        {
            let mut repo = open(&s_dev);
            write(&mut repo, "s");
        }
        // A settler merges the commit and the describe, and lands first.
        truth.land(&d_dev, &h0);
        let h2 = op_heads(&*truth.fs);
        assert_eq!(h2.len(), 2, "the commit and the describe");
        let m_dev = truth.fork(&h2);
        let (w1_rebased, kept_commit) = {
            let repo = open(&m_dev);
            assert_eq!(repo.heads().len(), 1, "the settler merged");
            let wc = repo.view().workspaces["w"].wc;
            (wc, repo.snapshot(&wc).unwrap().change_id == repo.snapshot(&w1).unwrap().change_id)
        };
        if !kept_commit {
            // The other order: the settler kept the describe's rebase of the
            // old working copy (`W0'`), a write of `w` the snapshot is
            // concurrent with. A real conflict: a warning, both working
            // copies visible, on the described x.
            truth.land(&m_dev, &h2);
            truth.land(&s_dev, &h1);
            let mut repo = open(&truth);
            assert_eq!(repo.heads().len(), 1, "settled");
            let warnings = repo.take_warnings();
            assert!(warnings.iter().any(|w| w.starts_with("workspace 'w' was moved by concurrent commands")), "a conflict on w: {warnings:?}");
            let visible: Vec<ObjectId> = repo.exact().visible().unwrap();
            assert!(visible.contains(&w1_rebased), "the describe's working copy {} still visible", w1_rebased.short());
            assert!(visible.iter().any(|s| files_of(&repo, s) == vec!["c", "s", "x"]), "the snapshot's working copy still visible");
            let below: Vec<String> = visible.iter().map(|s| repo.snapshot(s).unwrap().description.as_str().to_string()).collect();
            assert!(below.contains(&"x, described".to_string()) && !below.contains(&"x".to_string()), "on the described x ({}): {:?}", x2.short(), below);
            continue;
        }
        assert_ne!(w1_rebased, w1, "the settler rebased the working copy");
        break (truth, x2, w1_rebased, m_dev, h2, s_dev, h1);
    };
    truth.land(&m_dev, &h2);
    truth.land(&s_dev, &h1);
    let mut repo = open(&truth);
    assert_eq!(repo.heads().len(), 1, "settled");
    assert!(repo.take_warnings().is_empty(), "no conflict");
    let wc = repo.view().workspaces["w"].wc;
    assert_eq!(files_of(&repo, &wc), vec!["c", "s", "x"], "the snapshot's working copy");
    let below: Vec<String> = repo.exact().visible().unwrap().into_iter().map(|s| repo.snapshot(&s).unwrap().description.as_str().to_string()).collect();
    assert!(below.contains(&"x, described".to_string()) && !below.contains(&"x".to_string()), "on the described x ({}): {:?}", x2.short(), below);
    // One version of the working copy's change: the rebased copy followed.
    let change = repo.snapshot(&wc).unwrap().change_id;
    let versions: Vec<String> = repo.exact().visible().unwrap().into_iter().filter(|s| repo.snapshot(s).unwrap().change_id == change).map(|s| s.short()).collect();
    assert_eq!(versions, vec![wc.short()], "the rebased copy {} still visible", w1_rebased.short());
}

/// BUG-2466 (found while fixing BUG-2464): a commit `C` (on `X`) runs
/// concurrently with a describe of `X` (`X1`) and a second describe that
/// saw the first (`X1` into `X2`). One settler merges the commit and the
/// first describe (`C` onto `X1`, `C1`); another merges the commit and the
/// second describe, whose history holds the first (`C` onto `X2`, `C2`).
/// Two rebases of `C`, by merges alone: taken for a divergent change,
/// nothing followed either, and `C1` kept `X1` visible below it. The second
/// merge merged everything the first did, so its rebase supersedes: `C`
/// and `C1` follow `C2`. (Judged by the result: `C1`'s parent `X1` is now
/// `X2`, `C2`'s, so the two are one rebase, and `C2`, on it, stands.) (The
/// describes also rebase the working copy the commit snapshots: two
/// commands' rewrites of it, a divergent change, not decided here.)
#[test]
fn bug_2466_the_rebase_of_a_merge_that_merged_more_supersedes() {
    let me = Identity::generate("alice");
    let open = |d: &Device| Repo::open(d.fs.clone(), Some(me.clone()), "alice").unwrap();
    let write = |repo: &mut Repo, file: &str| {
        repo.set_command_workspace(Some("w".into()));
        let ov = repo.workspace_overlay("w").unwrap();
        ov.write(&VPath::new(file).unwrap(), b"x\n").unwrap();
        repo.snapshot_workspace("w", &ov).unwrap();
    };
    let truth = Device::new(false);
    let x = {
        let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        repo.create_workspace("w", vec![repo.root_id()]).unwrap();
        write(&mut repo, "x");
        repo.commit_working_copy("w", "x").unwrap().0
    };
    let h0 = op_heads(&*truth.fs);
    let d1_dev = truth.fork(&h0);
    let x1 = open(&d1_dev).describe(x, "x1").unwrap();
    let k_dev = truth.fork(&h0);
    {
        let mut repo = open(&k_dev);
        write(&mut repo, "c");
        repo.commit_working_copy("w", "c").unwrap();
    }
    truth.land(&d1_dev, &h0);
    let h1 = op_heads(&*truth.fs);
    let d2_dev = truth.fork(&h1);
    open(&d2_dev).describe(x1, "x2").unwrap();
    truth.land(&k_dev, &h0);
    let h2 = op_heads(&*truth.fs);
    assert_eq!(h2.len(), 2, "the first describe and the commit");
    let m1_dev = truth.fork(&h2);
    assert_eq!(open(&m1_dev).heads().len(), 1, "the first settler merged");
    truth.land(&d2_dev, &h1);
    let h3 = op_heads(&*truth.fs);
    assert_eq!(h3.len(), 2, "the second describe and the commit");
    let m2_dev = truth.fork(&h3);
    assert_eq!(open(&m2_dev).heads().len(), 1, "the second settler merged");
    truth.land(&m1_dev, &h2);
    truth.land(&m2_dev, &h3);
    assert_eq!(op_heads(&*truth.fs).len(), 2, "the two settlers' merges");
    let mut repo = open(&truth);
    assert_eq!(repo.heads().len(), 1, "settled");
    let warnings = repo.take_warnings();
    let descs: Vec<String> = repo.exact().visible().unwrap().into_iter().map(|s| repo.snapshot(&s).unwrap().description.as_str().to_string()).collect();
    assert!(descs.contains(&"x2".to_string()), "{descs:?}");
    assert!(!descs.contains(&"x".to_string()) && !descs.contains(&"x1".to_string()), "an old version of x still visible: {descs:?} ({warnings:?})");
    assert_eq!(descs.iter().filter(|d| *d == "c").count(), 1, "one version of the commit: {descs:?}");
    let c: Vec<ObjectId> = repo.exact().visible().unwrap().into_iter().filter(|s| repo.snapshot(s).unwrap().description.as_str() == "c").collect();
    assert_eq!(repo.snapshot(&repo.snapshot(&c[0]).unwrap().parents[0]).unwrap().description.as_str(), "x2", "the commit on x2");
}

/// BUG-2464: the input BUG-1503's long-run check shrank to when it failed
/// once under the whole suite's load (three writers, tags and workspaces on
/// old versions). Not the load: the random ids within a case decide which
/// settler merges what first: 4 to 6 replays in 100 fail. Two ways, both a
/// settler's rebase taken for a change: a value two settlers rebased alike,
/// or one settler's rebase of a working copy onto a describe while the
/// other side committed it, counted as a change that conflicted with the
/// commit (the workspace moved onto the commit, or left on the rebased
/// copy), and that rebase and the commit's rewrite of the same working copy
/// made a divergent change nothing followed, so the old working copy stayed
/// visible on the version the describe replaced. Replayed 100 times (it
/// failed at least once in nearly every run of the unfixed engine), it
/// must pass every time.
#[test]
fn bug_2464_rewrites_follow_in_long_runs_replayed() {
    let steps: Vec<u16> = vec![
        43865, 25173, 53776, 43947, 28641, 31713, 13004, 61295, 31429, 13303, 36445, 26051, 53352, 39121, 50952, 14650, 27771, 35681, 47413, 14012, 4098, 17930,
        61895, 64483, 43151, 26629, 59351, 37198, 46956, 43996, 45557, 31069, 28194, 22747, 50520, 2969, 18661, 46354, 64274, 46954, 60953, 13705, 61706, 15539,
        54169, 62031, 19777, 7836, 14546, 42542, 61108, 41671, 22277, 3480, 33507, 39845, 60242, 36732, 64655, 56747, 50761, 22230, 28607, 30067, 16142, 36787,
        47861, 60663, 19400, 5811, 8522, 40867, 34569, 5785, 2334, 59303, 12882, 32692, 59720, 43783, 28927, 30047, 26336, 57949, 36710, 48480, 108, 18855, 36343,
        18679, 49142, 26539, 58224, 52839, 9535, 59258, 37651, 53663, 4981, 11864, 42327, 59553, 6347, 48191, 31483, 58880, 27797, 18084, 39910, 55301, 52384,
        18402, 11348, 53287, 21920, 60211, 52571, 44770, 11710, 26730, 33259, 23736, 31926, 62726, 37286, 49661, 28863, 35247, 42613, 4761, 33695, 21616, 54186,
        25408, 32778, 4841, 34787, 54331, 20847, 56309, 64769, 59235, 1522, 46695, 4113, 4213, 32694, 62755, 46203, 25764, 15395, 45453, 54598, 12305, 39597, 13251,
        13086, 60797, 44418, 15172, 16065, 1077, 22344, 10766, 54407, 49425, 21153, 13386, 962, 18735, 45805, 48148, 61945, 63424, 21451, 32697, 14465, 904, 4985,
        53126, 17039, 11127, 31627, 32247, 60919, 44009, 63451, 44970,
    ];
    let mut failed = Vec::new();
    for i in 0..100 {
        if let Err(e) = check_rewrites_follow_through_merges(false, 3, false, true, &steps) {
            failed.push((i, e.to_string()));
        }
    }
    assert!(failed.is_empty(), "{} replays in 100 failed; the first: {:?}", failed.len(), failed.first());
}

/// A guard for a fix of BUG-2464: an input of BUG-1503's long-run check
/// (three writers, no refs to old versions) that passes today and that
/// attempts at that fix broke (2 to 37 replays in 160 failed): with the
/// workspaces merged differently, two settlers merged a commit with one
/// describe and with two, and their two rebases of it are taken for a
/// divergent change (BUG-2466). Replayed, it must pass every time.
#[test]
fn bug_2464_guard_two_settlers_rebase_one_commit_replayed() {
    let steps: Vec<u16> = vec![
        9298, 33168, 24058, 11979, 38173, 33704, 57601, 25004, 24807, 64909, 35742, 58067, 8202, 43915, 6728, 32665, 12535, 60130, 13404, 34866, 42224, 2989, 27781,
        18614, 46937, 41191, 50988, 49313, 33363, 13330, 34785, 7199, 22829, 46859, 39981, 24002, 6569, 17727, 38915, 4667, 14417, 18231, 25828, 31805, 65531, 36162,
        41028, 14257, 46532, 1511, 30871, 18963, 42384, 56780, 29840, 196, 42447, 18774, 46122, 6861, 49924, 43960, 48165, 12883, 40784, 6691, 6286, 10287, 4463,
        34738, 32509, 16456, 38084, 24708, 5387, 12677, 31823, 57275, 5582, 12025, 21870, 39681, 60183, 4681, 19328, 23297, 25180, 37683, 64224, 20251, 33463, 3478,
        44411, 54223, 37795, 47541, 15066, 16033, 30703, 48362, 27430, 25314, 30050, 36204, 42021, 44025, 5103, 16592, 34958, 56739, 24329, 18000, 25256, 52427, 3216,
        35218, 30800, 21349, 51303, 45538, 32775, 57599, 40602, 1943, 61475, 33345, 31164, 54331, 24904, 12615, 64596, 22725, 53591, 23058, 15968, 19225, 57368, 44082,
        52678, 47563, 63056, 12930, 25348, 33344, 47256, 60984, 32901, 63299, 30494, 20995, 60049, 52105, 13210, 44093, 30729, 53283, 10615, 17230, 58077, 9580, 12138,
        43744, 49888, 28503, 41359, 43310, 49647, 3620, 7009, 28752, 20179, 62147, 36481, 51831, 54443, 17848, 37693, 48804, 18918, 52822, 36652, 57343, 53926, 54938,
        633, 19588, 48807, 2428, 46676, 25456, 46500, 5077, 28034, 51210, 1170, 23323, 17418, 3933, 1053, 62813, 41357, 45138, 16084, 31502, 46678, 53362, 23124,
        61328, 36740, 56921, 52167, 2018, 58650, 8383, 19771, 48839, 20873, 21213, 14502, 40472, 48332, 51134, 1014, 55539, 51289, 48703, 23509, 39320, 36295, 24757,
        34589, 64825, 28960, 10952, 5623, 29165, 19845, 24621, 24544, 16489, 23175, 1940, 54856, 14540, 49244, 45814, 37546, 28143, 22823, 23452, 59455, 26479, 15779,
        55254, 11192, 23073, 20501, 36288, 22887, 4527, 17457, 58873, 35012, 28459, 23676, 25808, 58229, 14046, 22932, 22041, 53504, 22707, 48098, 52247, 26145, 61848,
        27096, 60854, 46130, 38688, 54764, 51779, 19044, 16446, 48833, 51840, 44599, 23747, 63083, 20688, 10950, 29643, 37100, 20768, 41465, 51306, 39495,
    ];
    let mut failed = Vec::new();
    for i in 0..20 {
        if let Err(e) = check_rewrites_follow_through_merges(false, 3, false, false, &steps) {
            failed.push((i, e.to_string()));
        }
    }
    assert!(failed.is_empty(), "{} replays in 20 failed; the first: {:?}", failed.len(), failed.first());
}

/// A guard for a fix of BUG-2464: an input of the long run of
/// `rewrites_follow_with_refs_to_old_versions_memory` (two writers, tags
/// and workspaces on old versions) that passes today and that an attempt
/// broke (14 replays in 160 failed): it took a describe's rebase of a
/// working copy, from the shared history and recorded again by merges, for
/// a merge's own, and let it give way to a concurrent commit of that
/// working copy; two commands' rewrites, a divergent change. Replayed, it
/// must pass every time.
#[test]
fn bug_2464_guard_a_describe_s_rebase_from_the_shared_history_replayed() {
    let steps: Vec<u16> = vec![
        26924, 1310, 51560, 53233, 3462, 40367, 37372, 36139, 48236, 6871, 29283, 61260, 40674, 14075, 21369, 60301, 15256, 4192, 57718, 33349, 53417, 9061, 35632,
        3632, 31911, 48592, 41838, 24946, 20298, 17748, 19184, 8029, 9076, 3142, 65321, 31267, 10206, 19767, 17511, 61207, 42355, 39062, 33149, 61780, 489, 11070,
        61384, 41096, 28291, 39830, 41740, 43222, 9439, 42982, 63687, 41273, 24496, 18246, 63135, 16364, 13370, 62813, 20759, 48350, 49358, 28756, 52678, 9769, 18819,
        22825, 39177, 47040, 47201, 64207, 48866, 49848, 11951, 6440, 58444, 55071, 65234, 7449, 4118, 26370, 30285, 5877, 28445, 32135, 27221, 51279, 45686, 37346,
        65191, 15835, 8540, 16170, 23048, 20059, 6914, 51390, 11227, 17782, 44925, 26238, 44844, 24233, 52659, 46041, 63004, 13770, 16848, 4950, 63962, 26350, 34571,
        23186, 41118, 7040, 46435, 36843, 12874, 1229, 41169, 49284, 32058, 49346, 2260, 44296, 5042, 24430, 2506, 33438, 38637, 63025, 57976, 45961, 19695, 54581,
        34259, 57034, 40417, 4373, 2291, 61231, 62557, 63084, 12024, 30368, 61082, 47692, 13858, 47986, 5846, 34664, 61189, 34668, 41392, 13082, 11162, 31849, 9050,
        1078, 55953, 25148, 62817, 36428, 23732, 49801, 27745, 34154, 28329, 44262, 47119, 15110, 132, 5437, 42640, 56314, 18374, 56979, 28208, 24306, 51714, 36018,
        43905, 57052, 47439, 13747, 30099, 19749, 12786, 43314, 15250, 35508, 62402, 29228, 20081, 64797, 6162,
    ];
    let mut failed = Vec::new();
    for i in 0..20 {
        if let Err(e) = check_rewrites_follow_through_merges(false, 2, false, true, &steps) {
            failed.push((i, e.to_string()));
        }
    }
    assert!(failed.is_empty(), "{} replays in 20 failed; the first: {:?}", failed.len(), failed.first());
}

/// A guard for a fix of BUG-2464: an input of the long run of
/// `rewrites_follow_with_refs_to_old_versions_memory` (4 writers, tags and
/// workspaces on old versions) that passes today and that the most
/// complete attempt broke (14 and 15 replays in 20 failed): rules that let
/// settlers' rebases give way to other rewrites of a snapshot, and refs on
/// the rebased copies follow, left old versions visible here. Replayed, it
/// must pass every time.
#[test]
fn bug_2464_guard_rebased_copies_left_where_they_are_replayed() {
    let steps: Vec<u16> = vec![
        15285, 16720, 27493, 3823, 34777, 62217, 15319, 54568, 7437, 11373, 24684, 36780, 39077, 10708, 45698, 31526, 52898, 55019, 27081, 32612, 38547, 454, 56051,
        60083, 59055, 14758, 33795, 57653, 2417, 30996, 64160, 38965, 33937, 15352, 45977, 40069, 5670, 14043, 3600, 18064, 52004, 19505, 15466, 26874, 39776, 51864,
        13180, 15312, 1298, 32241, 24708, 33298, 62737, 64190, 6785, 43421, 10687, 4083, 5795, 30396, 62354, 4928, 17365, 32839, 57331, 960, 38394, 49810, 4429,
        32056, 902, 42289, 42976, 53980, 44256, 44286, 63185, 42612, 20470, 38033, 36785, 50271, 1596, 37362, 48246, 59669, 17721, 52420, 23926, 4690, 32718, 26439,
        26292, 18322, 57410, 5348, 21523, 24853, 58153, 26459, 15033, 52187, 15506, 18850, 28294, 13307, 19483, 5436, 15064, 40490, 11995, 50807, 10701, 15922, 13314,
        2881, 38814, 474, 1439, 45004, 16211,
    ];
    let mut failed = Vec::new();
    for i in 0..10 {
        if let Err(e) = check_rewrites_follow_through_merges(false, 4, false, true, &steps) {
            failed.push((i, e.to_string()));
        }
    }
    assert!(failed.is_empty(), "{} replays in 10 failed; the first: {:?}", failed.len(), failed.first());
}

/// BUG-2550 (review of the BUG-2464 fix): a command's rewrite, recorded
/// again by a settler that merged it with an unrelated operation, was read
/// as that settler's own rebase. `C` is a commit only a head shows; one
/// command describes it (`C1`), another, concurrently, too (`C2`); a
/// settler merges the first with an unrelated command whose view still
/// shows `C`. The settler did not make `C1` (its parent did), but `C1`
/// counted as its rebase of `C`, a value of the shared history, moved,
/// which the second describe dropped: `C1` left the heads, and the
/// divergent change kept nothing that showed it. Both versions stay
/// visible.
#[test]
fn bug_2550_a_command_s_rewrite_a_settler_recorded_again_is_no_rebase_of_its() {
    let me = Identity::generate("alice");
    let open = |d: &Device| Repo::open(d.fs.clone(), Some(me.clone()), "alice").unwrap();
    let truth = Device::new(false);
    let c = {
        let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        repo.create_workspace("w", vec![repo.root_id()]).unwrap();
        repo.create_workspace("v", vec![repo.root_id()]).unwrap();
        repo.set_command_workspace(Some("w".into()));
        let ov = repo.workspace_overlay("w").unwrap();
        ov.write(&VPath::new("c").unwrap(), b"c\n").unwrap();
        repo.snapshot_workspace("w", &ov).unwrap();
        let c = repo.commit_working_copy("w", "c").unwrap().0;
        repo.remove_workspace("w").unwrap();
        c
    };
    let h0 = op_heads(&*truth.fs);
    assert_eq!(open(&truth).view().heads.iter().filter(|h| **h == c).count(), 1, "c is a head");
    assert!(!open(&truth).view().workspaces.values().any(|w| w.wc == c), "and no workspace's");
    let d1 = truth.fork(&h0);
    let c1 = open(&d1).describe(c, "c, first").unwrap();
    let d2 = truth.fork(&h0);
    let c2 = open(&d2).describe(c, "c, second").unwrap();
    let b0 = truth.fork(&h0);
    open(&b0).create_workspace("u", vec![open(&b0).root_id()]).unwrap();
    truth.land(&d1, &h0);
    truth.land(&b0, &h0);
    let h1 = op_heads(&*truth.fs);
    assert_eq!(h1.len(), 2, "the first describe and the unrelated command");
    let m = truth.fork(&h1);
    assert_eq!(open(&m).heads().len(), 1, "the settler merged");
    truth.land(&m, &h1);
    truth.land(&d2, &h0);
    let repo = open(&truth);
    assert_eq!(repo.heads().len(), 1, "settled");
    let shown = |s: &ObjectId| repo.view().refs().iter().any(|r| r == s || repo.is_ancestor(s, r).unwrap());
    assert!(shown(&c1), "the first version {} still visible", c1.short());
    assert!(shown(&c2), "the second version {} still visible", c2.short());
}

/// BUG-2550, a working copy: a describe of `@` (`W` into `W'`), merged by a
/// settler with an unrelated command, runs concurrently with a snapshot of
/// `W` elsewhere (`W2`). Two commands moved the workspace: a conflict, with
/// a warning, and both working copies visible. `W'` counted as the
/// settler's rebase of `W`, so the snapshot won silently and `W'` went.
#[test]
fn bug_2550_a_describe_of_the_working_copy_a_settler_recorded_again_still_conflicts() {
    let me = Identity::generate("alice");
    let open = |d: &Device| Repo::open(d.fs.clone(), Some(me.clone()), "alice").unwrap();
    let write = |repo: &mut Repo, file: &str| {
        repo.set_command_workspace(Some("w".into()));
        let ov = repo.workspace_overlay("w").unwrap();
        ov.write(&VPath::new(file).unwrap(), b"x\n").unwrap();
        repo.snapshot_workspace("w", &ov).unwrap();
    };
    let truth = Device::new(false);
    let w = {
        let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        repo.create_workspace("w", vec![repo.root_id()]).unwrap();
        write(&mut repo, "a");
        repo.view().workspaces["w"].wc
    };
    let h0 = op_heads(&*truth.fs);
    let d = truth.fork(&h0);
    let w1 = {
        let mut repo = open(&d);
        repo.set_command_workspace(Some("w".into()));
        repo.describe(w, "w, described").unwrap()
    };
    let s = truth.fork(&h0);
    let w2 = {
        let mut repo = open(&s);
        write(&mut repo, "b");
        repo.view().workspaces["w"].wc
    };
    assert_ne!(w2, w, "the snapshot moved the working copy");
    let b0 = truth.fork(&h0);
    open(&b0).create_workspace("u", vec![open(&b0).root_id()]).unwrap();
    truth.land(&d, &h0);
    truth.land(&b0, &h0);
    let h1 = op_heads(&*truth.fs);
    assert_eq!(h1.len(), 2, "the describe and the unrelated command");
    let m = truth.fork(&h1);
    assert_eq!(open(&m).heads().len(), 1, "the settler merged");
    truth.land(&m, &h1);
    truth.land(&s, &h0);
    let mut repo = open(&truth);
    assert_eq!(repo.heads().len(), 1, "settled");
    let warnings = repo.take_warnings();
    assert!(warnings.iter().any(|x| x.starts_with("workspace 'w' was moved by concurrent commands")), "a conflict on w: {warnings:?}");
    let shown = |s: &ObjectId| repo.view().refs().iter().any(|r| r == s || repo.is_ancestor(s, r).unwrap());
    assert!(shown(&w1), "the described working copy {} still visible", w1.short());
    assert!(shown(&w2), "the snapshot {} still visible", w2.short());
}

/// BUG-2550, a tag: a describe of `X` moves the tag `t` on it to `X'`; a
/// settler merges it with an unrelated command; concurrently a command
/// moves `t` to `Y`. Two commands moved the tag: a conflict, with a
/// warning (guarantee 3). `X'` counted as the settler's rebase of `X`, and
/// `Y` won silently.
#[test]
fn bug_2550_a_tag_a_describe_moved_and_a_settler_recorded_again_still_conflicts() {
    let me = Identity::generate("alice");
    let open = |d: &Device| Repo::open(d.fs.clone(), Some(me.clone()), "alice").unwrap();
    let truth = Device::new(false);
    let (x, y) = {
        let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        repo.create_workspace("w", vec![repo.root_id()]).unwrap();
        repo.set_command_workspace(Some("w".into()));
        let ov = repo.workspace_overlay("w").unwrap();
        ov.write(&VPath::new("x").unwrap(), b"x\n").unwrap();
        repo.snapshot_workspace("w", &ov).unwrap();
        let x = repo.commit_working_copy("w", "x").unwrap().0;
        let ov = repo.workspace_overlay("w").unwrap();
        ov.write(&VPath::new("y").unwrap(), b"y\n").unwrap();
        repo.snapshot_workspace("w", &ov).unwrap();
        let y = repo.commit_working_copy("w", "y").unwrap().0;
        repo.set_tag("t", x, true).unwrap();
        (x, y)
    };
    let h0 = op_heads(&*truth.fs);
    let d = truth.fork(&h0);
    let x1 = open(&d).describe(x, "x, described").unwrap();
    assert_eq!(open(&d).view().tags["t"].target, x1, "the describe moved the tag");
    let t = truth.fork(&h0);
    open(&t).set_tag("t", y, true).unwrap();
    let b0 = truth.fork(&h0);
    open(&b0).create_workspace("u", vec![open(&b0).root_id()]).unwrap();
    truth.land(&d, &h0);
    truth.land(&b0, &h0);
    let h1 = op_heads(&*truth.fs);
    assert_eq!(h1.len(), 2, "the describe and the unrelated command");
    let m = truth.fork(&h1);
    assert_eq!(open(&m).heads().len(), 1, "the settler merged");
    truth.land(&m, &h1);
    truth.land(&t, &h0);
    let mut repo = open(&truth);
    assert_eq!(repo.heads().len(), 1, "settled");
    let warnings = repo.take_warnings();
    assert!(warnings.iter().any(|w| w.starts_with("tag 't' was moved by concurrent commands")), "a conflict on t: {warnings:?}");
    let target = repo.view().tags["t"].target;
    let y_now: Vec<ObjectId> = repo.exact().visible().unwrap().into_iter().filter(|s| repo.snapshot(s).unwrap().description.as_str() == "y").collect();
    assert_eq!(y_now.len(), 1, "one y");
    assert!(target == x1 || target == y_now[0], "the tag on one of the two moves: {}", target.short());
    let shown = |s: &ObjectId| repo.view().refs().iter().any(|r| r == s || repo.is_ancestor(s, r).unwrap());
    assert!(shown(&x1), "the described x {} still visible", x1.short());
}

/// BUG-2640 through a merge, with chained shared-history rewrites and
/// transient application: `A -> A1 -> A2` is taken back by an op restore
/// `R1`; a concurrent commit `C` on `A` merges with `R1` (`M1`) and rightly
/// stays on `A`; a second op restore `R2` (forked from `R1`, concurrent with
/// `M1`) takes `R1` back to `D2`. Merging `M1` and `R2` must keep `C`, move
/// `C` all the way onto `A2`, and not re-record `A -> A1` or `A1 -> A2` on
/// the merge op (so undoing only `D2` afterward cleanly brings `A1` back).
#[test]
fn bug_2640_a_reinstated_rewrite_through_a_merge_follows_chains_and_can_still_be_taken_back() {
    let me = Identity::generate("alice");
    let open = |d: &Device| Repo::open(d.fs.clone(), Some(me.clone()), "alice").unwrap();
    let commit = |repo: &mut Repo, ws: &str, file: &str| -> ObjectId {
        repo.set_command_workspace(Some(ws.into()));
        let ov = repo.workspace_overlay(ws).unwrap();
        ov.write(&VPath::new(file).unwrap(), b"x\n").unwrap();
        repo.snapshot_workspace(ws, &ov).unwrap();
        repo.commit_working_copy(ws, file).unwrap().0
    };
    let truth = Device::new(false);
    let (a, before_d1) = {
        let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        repo.create_workspace("w", vec![repo.root_id()]).unwrap();
        repo.create_workspace("v", vec![repo.root_id()]).unwrap();
        let a = commit(&mut repo, "w", "a");
        (a, repo.op_id())
    };
    let h0 = op_heads(&*truth.fs);
    // Commit `c` on `a`, seeing neither describes nor restores.
    let k = truth.fork(&h0);
    commit(&mut open(&k), "w", "c");
    let (a1, _op_d1) = {
        let mut repo = open(&truth);
        let a1 = repo.describe(a, "a1").unwrap();
        (a1, repo.op_id())
    };
    // Concurrent branch forked at `D1`, committing `d` on `a1`.
    let h_d1 = op_heads(&*truth.fs);
    let branch_d = truth.fork(&h_d1);
    commit(&mut open(&branch_d), "w", "d");
    let (a2, op_d2) = {
        let mut repo = open(&truth);
        let a2 = repo.describe(a1, "a2").unwrap();
        (a2, repo.op_id())
    };
    open(&truth).restore_operation(before_d1).unwrap();
    // Fork `r2` right after `R1`, before `k` lands, and restore `op_d2`
    // (taking `R1` back and reinstating `D1` and `D2`).
    let h_r1 = op_heads(&*truth.fs);
    let r2 = truth.fork(&h_r1);
    open(&r2).restore_operation(op_d2).unwrap();
    // Land `k` onto `R1` and settle `M1`: `c` rightly stays on `a` while `R1` stands.
    truth.land(&k, &h0);
    {
        let repo = open(&truth);
        assert_eq!(repo.heads().len(), 1, "settled M1 with R1");
        let c: Vec<ObjectId> = repo.exact().visible().unwrap().into_iter().filter(|s| repo.snapshot(s).unwrap().description.as_str() == "c").collect();
        assert_eq!(c.len(), 1, "one commit c");
        assert_eq!(repo.snapshot(&c[0]).unwrap().parents.clone(), vec![a], "c stays on a while R1 stands");
    }
    // Now land `r2` (concurrent with `M1`) so reinstating `D1`/`D2` goes through `M2`.
    truth.land(&r2, &h_r1);
    assert_eq!(op_heads(&*truth.fs).len(), 2, "M1 and R2");
    {
        let repo = open(&truth);
        assert_eq!(repo.heads().len(), 1, "merged M1 and R2");
        let visible = repo.exact().visible().unwrap();
        assert!(visible.contains(&a2), "a2 is back in force");
        assert!(!visible.contains(&a), "a is gone");
        assert!(!visible.contains(&a1), "a1 is gone (chained rewrite followed)");
        let c: Vec<ObjectId> = visible.iter().copied().filter(|s| repo.snapshot(s).unwrap().description.as_str() == "c").collect();
        assert_eq!(c.len(), 1, "one commit c");
        assert_eq!(repo.snapshot(&c[0]).unwrap().parents.clone(), vec![a2], "c moved all the way onto a2");
        let merge_op = repo.ops().get(&repo.op_id()).unwrap();
        assert!(merge_op.is_merge(), "top op is the merge");
        assert!(!merge_op.rewritten.contains_key(&a), "shared-history rewrite a->a1 not re-recorded on merge");
        assert!(!merge_op.rewritten.contains_key(&a1), "shared-history rewrite a1->a2 not re-recorded on merge");
    }
    // Now undo ONLY `D2` (not `M2`), then land `branch_d` (committed `d` on
    // `a1`): because `M2` did not re-record `a1 -> a2`, `d` must stay on `a1`.
    open(&truth).undo_operation_keeping_edits("v", op_d2).unwrap();
    truth.land(&branch_d, &h_d1);
    let repo = open(&truth);
    assert_eq!(repo.heads().len(), 1, "settled after undoing D2 and landing branch_d");
    let visible = repo.exact().visible().unwrap();
    assert!(visible.contains(&a1), "a1 stands again after undoing D2");
    let d: Vec<ObjectId> = visible.iter().copied().filter(|s| repo.snapshot(s).unwrap().description.as_str() == "d").collect();
    assert_eq!(d.len(), 1, "one commit d");
    assert_eq!(repo.snapshot(&d[0]).unwrap().parents.clone(), vec![a1], "d stays on a1 because D2 was undone and M2 did not re-record a1->a2");
}

/// BUG-2641, cause (c): a settler's merge rebases `X -> X'` (only a merge
/// records it); an op restore goes back past that merge so `X` stands
/// again; a describe then rewrites `X -> X2`, while a concurrent describe
/// of `Y` (child of `X`, forked before the merge) lands last. The retracted
/// merge's `X -> X'` must not count as a second version of `X` beside `X2`:
/// `Y2` must move onto `X2`.
#[test]
fn bug_2641_a_settlers_rebase_taken_back_by_an_op_restore_does_not_block_a_later_describe() {
    let me = Identity::generate("alice");
    let open = |d: &Device| Repo::open(d.fs.clone(), Some(me.clone()), "alice").unwrap();
    let commit = |repo: &mut Repo, ws: &str, file: &str| -> ObjectId {
        repo.set_command_workspace(Some(ws.into()));
        let ov = repo.workspace_overlay(ws).unwrap();
        ov.write(&VPath::new(file).unwrap(), b"x\n").unwrap();
        repo.snapshot_workspace(ws, &ov).unwrap();
        repo.commit_working_copy(ws, file).unwrap().0
    };
    let truth = Device::new(false);
    let a = {
        let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        repo.create_workspace("w", vec![repo.root_id()]).unwrap();
        commit(&mut repo, "w", "a")
    };
    let h0 = op_heads(&*truth.fs);
    // Side 1: describe `a -> a1`.
    let da = truth.fork(&h0);
    open(&da).describe(a, "a1").unwrap();
    // Side 2: commit `x` on `a`, then `y` on `x`.
    let xy = truth.fork(&h0);
    let (x, y, op_xy) = {
        let mut repo = open(&xy);
        let x = commit(&mut repo, "w", "x");
        let y = commit(&mut repo, "w", "y");
        (x, y, repo.op_id())
    };
    // Late branch forked at `op_xy` (before the settler's merge): describes `y`.
    let dy = xy.fork(&op_heads(&*xy.fs));
    open(&dy).describe(y, "y2").unwrap();
    // Settler merges `da` and `xy`, recording merge-only rebases `x -> x'` and `y -> y'`.
    truth.land(&da, &h0);
    truth.land(&xy, &h0);
    assert_eq!(op_heads(&*truth.fs).len(), 2, "da and xy");
    {
        let repo = open(&truth);
        assert_eq!(repo.heads().len(), 1, "settler merged da and xy");
        let mop = repo.ops().get(&repo.op_id()).unwrap();
        assert!(mop.is_merge() && mop.rewritten.contains_key(&x), "settler recorded merge-only rebase of x");
    }
    // Op restore back to `op_xy` (taking back `da` and the settler's merge),
    // then describe `x -> x2`.
    let x2 = {
        let mut repo = open(&truth);
        repo.restore_operation(op_xy).unwrap();
        assert!(repo.exact().visible().unwrap().contains(&x), "restore brought x back");
        repo.describe(x, "x2").unwrap()
    };
    // Land the late describe of `y` (which sits on `x`).
    truth.land(&dy, &op_heads(&*xy.fs));
    let repo = open(&truth);
    assert_eq!(repo.heads().len(), 1, "settled");
    let visible = repo.exact().visible().unwrap();
    assert!(visible.contains(&x2), "x2 is visible");
    assert!(!visible.contains(&x), "x (replaced by x2, with retracted settler rebase) must not stay visible");
    let y2: Vec<ObjectId> = visible.iter().copied().filter(|s| repo.snapshot(s).unwrap().description.as_str() == "y2").collect();
    assert_eq!(y2.len(), 1, "one y2");
    assert_eq!(repo.snapshot(&y2[0]).unwrap().parents.clone(), vec![x2], "y2 moved onto x2");
}

/// BUG-2642: two concurrent tag writes (`t = X` and `t = Z`) conflict in an
/// earlier merge `M1` that also includes commits `Wx` (on `X`) and `Wz` (on
/// `Z`); `M1` adds the losing tag target to `heads`, then
/// `drop_ancestor_heads` drops it because `Wx`/`Wz` cover it. A concurrent
/// op restore `U` (forked after `Wx`/`Wz`, restoring to before `X`/`Z`)
/// drops `Wx` and `Wz` in `M2`. Neither head of `M2` holds the losing
/// target on `t` or in `heads`, yet the losing write was never retracted or
/// superseded and must stay visible.
#[test]
fn bug_2642_a_conflicts_loser_covered_by_a_head_an_undo_drops_stays_visible() {
    let me = Identity::generate("alice");
    let open = |d: &Device| Repo::open(d.fs.clone(), Some(me.clone()), "alice").unwrap();
    let commit = |repo: &mut Repo, ws: &str, file: &str| -> ObjectId {
        repo.set_command_workspace(Some(ws.into()));
        let ov = repo.workspace_overlay(ws).unwrap();
        ov.write(&VPath::new(file).unwrap(), b"x\n").unwrap();
        repo.snapshot_workspace(ws, &ov).unwrap();
        repo.commit_working_copy(ws, file).unwrap().0
    };
    let truth = Device::new(false);
    let before_xz = {
        let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        let root = repo.root_id();
        repo.create_workspace("w1", vec![root]).unwrap();
        repo.create_workspace("w2", vec![root]).unwrap();
        repo.op_id()
    };
    let (x, z) = {
        let mut repo = open(&truth);
        let x = commit(&mut repo, "w1", "x");
        let z = commit(&mut repo, "w2", "z");
        (x, z)
    };
    let h_xz = op_heads(&*truth.fs);
    // Two concurrent moves of tag `tag1`: one to `x`, one to `z`.
    let bt1 = truth.fork(&h_xz);
    open(&bt1).set_tag("tag1", x, true).unwrap();
    let bt2 = truth.fork(&h_xz);
    open(&bt2).set_tag("tag1", z, true).unwrap();
    // Third branch builds commits `wx` on `x` and `wz` on `z`, covering both.
    let bw = truth.fork(&h_xz);
    {
        let mut repo = open(&bw);
        commit(&mut repo, "w1", "wx");
        commit(&mut repo, "w2", "wz");
    }
    let h_w = op_heads(&*bw.fs);
    // Fourth branch restores to `before_xz` (dropping `x`, `z`, `wx`, `wz`).
    let bu = bw.fork(&h_w);
    open(&bu).restore_operation(before_xz).unwrap();
    // Settler M1 merges `bt1`, `bt2`, `bw`: conflict on `tag1`, losing target
    // covered by `wx`/`wz` and dropped from `M1.view.heads`.
    truth.land(&bt1, &h_xz);
    truth.land(&bt2, &h_xz);
    truth.land(&bw, &h_xz);
    assert_eq!(op_heads(&*truth.fs).len(), 3, "bt1, bt2, bw");
    {
        let repo = open(&truth);
        assert_eq!(repo.heads().len(), 1, "M1 settled");
        assert!(repo.view().tags.contains_key("tag1"), "tag1 present after M1");
    }
    // Land `bu` (concurrent with M1): M2 merges M1 and `bu`.
    truth.land(&bu, &h_w);
    let repo = open(&truth);
    assert_eq!(repo.heads().len(), 1, "M2 settled");
    let visible = repo.exact().visible().unwrap();
    assert!(visible.contains(&x), "x (tag1 candidate) must survive M2");
    assert!(visible.contains(&z), "z (tag1 candidate) must survive M2");
}

/// BUG-2641 (seeds 121 and 123): two independent settlers `S1` and `S2` both
/// make the same merge rebase `X -> X'` (moving `X` onto `A1`). `M1` merges
/// `S1`, `S2`, and a concurrent `describe X -> X2`. A later merge `M2` folds
/// `M1`, a branch `B1` built on `S1`, and a late `describe Y -> Y2` (child of
/// `X`). Because `S1` is in the shared history of `M1` and `B1`, `shared`
/// shows `X'`; `S2`'s `X -> X'` must still be recognized as a merge's rebase
/// (not a second version of `X`), so `X -> X2` stands and `Y2` does not stay
/// on `X`.
#[test]
fn bug_2641_a_settlers_rebase_also_in_shared_history_is_not_a_second_version() {
    let me = Identity::generate("alice");
    let open = |d: &Device| Repo::open(d.fs.clone(), Some(me.clone()), "alice").unwrap();
    let commit = |repo: &mut Repo, ws: &str, file: &str| -> ObjectId {
        repo.set_command_workspace(Some(ws.into()));
        let ov = repo.workspace_overlay(ws).unwrap();
        ov.write(&VPath::new(file).unwrap(), b"x\n").unwrap();
        repo.snapshot_workspace(ws, &ov).unwrap();
        repo.commit_working_copy(ws, file).unwrap().0
    };
    let truth = Device::new(false);
    let a = {
        let mut repo = Repo::init(truth.fs.clone(), Some(me.clone()), "alice").unwrap();
        repo.create_workspace("w", vec![repo.root_id()]).unwrap();
        commit(&mut repo, "w", "a")
    };
    let h0 = op_heads(&*truth.fs);
    // Side 1: describe `a -> a1`.
    let da = truth.fork(&h0);
    open(&da).describe(a, "a1").unwrap();
    // Side 2: commit `x` on `a`, then `y` on `x`.
    let xy = truth.fork(&h0);
    let (x, y) = {
        let mut repo = open(&xy);
        let x = commit(&mut repo, "w", "x");
        let y = commit(&mut repo, "w", "y");
        (x, y)
    };
    let h_xy = op_heads(&*xy.fs);
    // Branches forked at `h_xy`: `dx` describes `x`, `dy` describes `y`,
    // `u1` and `u2` make two distinct settlers `S1` and `S2`.
    let dx = xy.fork(&h_xy);
    open(&dx).describe(x, "x2").unwrap();
    let dy = xy.fork(&h_xy);
    open(&dy).describe(y, "y2").unwrap();
    let u1 = xy.fork(&h_xy);
    open(&u1).create_workspace("u1", vec![open(&u1).root_id()]).unwrap();
    let u2 = xy.fork(&h_xy);
    open(&u2).create_workspace("u2", vec![open(&u2).root_id()]).unwrap();
    // Settler S1 merges `da` and `u1` (which reaches `xy`), creating merge rebase `x -> x'`.
    let s1 = truth.fork(&h0);
    s1.land(&da, &h0);
    s1.land(&u1, &h0);
    let x_prime = {
        let repo = open(&s1);
        assert_eq!(repo.heads().len(), 1, "S1 settled");
        let mop = repo.ops().get(&repo.op_id()).unwrap();
        assert!(mop.is_merge() && mop.rewritten.contains_key(&x), "S1 recorded merge rebase of x");
        mop.rewritten[&x][0]
    };
    let h_s1 = op_heads(&*s1.fs);
    let b1 = s1.fork(&h_s1);
    open(&b1).create_workspace("v1", vec![open(&b1).root_id()]).unwrap();
    // Settler S2 independently merges `da` and `u2`, creating the exact same `x -> x'`.
    let s2 = truth.fork(&h0);
    s2.land(&da, &h0);
    s2.land(&u2, &h0);
    {
        let repo = open(&s2);
        assert_eq!(repo.heads().len(), 1, "S2 settled");
        let mop = repo.ops().get(&repo.op_id()).unwrap();
        assert_eq!(mop.rewritten.get(&x).map(Vec::as_slice), Some(&[x_prime][..]), "S2 made the same merge rebase x -> x'");
    }
    // M1 merges S1, S2, and dx.
    truth.land(&s1, &h0);
    truth.land(&s2, &h0);
    truth.land(&dx, &h0);
    {
        let repo = open(&truth);
        assert_eq!(repo.heads().len(), 1, "M1 settled");
    }
    // Now land `b1` (built on S1) and `dy` (built on x) concurrently with M1 -> M2.
    truth.land(&b1, &h_s1);
    truth.land(&dy, &h_xy);
    let repo = open(&truth);
    assert_eq!(repo.heads().len(), 1, "M2 settled");
    let visible = repo.exact().visible().unwrap();
    assert!(!visible.contains(&x), "old x must not stay visible after M2");
    let y2: Vec<ObjectId> = visible.iter().copied().filter(|s| repo.snapshot(s).unwrap().description.as_str() == "y2").collect();
    assert_eq!(y2.len(), 1, "one y2");
    let y2_parent = repo.snapshot(&y2[0]).unwrap().parents[0];
    assert_eq!(repo.snapshot(&y2_parent).unwrap().description.as_str(), "x2", "y2 moved onto x2 (not left on old x)");
}
