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
    let moved = |v: &ObjectId, g: &ObjectId| {
        rewrites.get(v).is_some_and(|news| {
            news.iter().any(|n| n.contains(g) || (n.is_empty() && repo.snapshot(g).unwrap().parents == repo.snapshot(v).unwrap().parents))
        })
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
            Key::Head(h) if vals.contains(&Some((*h, None))) => got.is_some() || visible(h) || rewrites.get(h).is_some_and(|news| news.iter().any(|n| n.is_empty() || n.iter().any(&visible))),
            Key::Head(h) => vals.contains(&got) || losers.contains(h),
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
        let w = arg % nw;
        let x = format!("x{}", arg % 2);
        let slots: Vec<String> = match kind {
            0..=3 | 10 => vec![format!("w{w}")],
            8 => vec![x.clone()],
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
/// working copy, a describe) and that no landed undo or op restore took
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
    let live: Vec<(usize, (ObjectId, ObjectId))> = cmds
        .iter()
        .enumerate()
        .filter(|(_, c)| c.landed.is_some())
        .flat_map(|(i, c)| c.rewrites.iter().filter(|r| !retracted(&r.0)).map(move |r| (i, (r.1, r.2))))
        .collect();
    // Snapshots two concurrent commands rewrote differently: a divergent
    // change, nothing follows either, so they stay where they are, with
    // their ancestors and what is built on them; and a merge does not
    // revisit that when one is taken back later (only a later merge with
    // both still to merge would see it).
    let landed: Vec<(usize, (ObjectId, ObjectId))> =
        cmds.iter().enumerate().filter(|(_, c)| c.landed.is_some()).flat_map(|(i, c)| c.rewrites.iter().map(move |r| (i, (r.1, r.2)))).collect();
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
                            || j.rewrites.iter().any(|(_, _, n)| versions.contains(n)))
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
                // Describe a visible commit (not a working copy), and not an
                // old version a landed command rewrote: a second version of
                // a change is BUG-1488's, not decided yet.
                let rewritten: std::collections::HashSet<ObjectId> = cmds.iter().filter(|c| c.landed.is_some()).flat_map(|c| c.rewrites.iter().map(|r| r.1)).collect();
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
        let mut rewrites = Vec::new();
        for id in &mine {
            let op = repo.ops().get(id).unwrap();
            if let Some(u) = op.undo_of {
                retracts.push(u);
            }
            if kind < 8 && !op.is_merge() {
                for (old, new) in op.rewritten {
                    if let [n] = new.as_slice() {
                        rewrites.push((*id, old, *n));
                    }
                }
            }
        }
        let writes = writes(&before, repo.view());
        drop(repo);
        cmds.push(RwCmd { forked: clock, landed: None, ops: mine.into_iter().collect(), rewrites, retracts, writes, what });
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

    /// The same with `vl undo` and `vl op restore` among the commands, and
    /// describes concurrent with each other (BUG-1403's reproduction; what
    /// it still finds, now and then, is BUG-1444).
    #[test]
    #[ignore = "BUG-1444: undo, op restore and concurrent describes: the merge and the model still disagree now and then on whether a rewrite stands (25 replays in 60 on fresh seeds)"]
    fn bug_1444_rewrites_follow_with_undo_restore_and_concurrent_describes(nw in 2usize..5, steps in prop::collection::vec(any::<u16>(), steps(20, 100))) {
        check_rewrites_follow_through_merges(false, nw, true, false, &steps)?;
    }
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
#[ignore = "BUG-1432 (a documented residual): on a log written before operation times were clamped, the walk can list an operation before an older descendant reached by a later path"]
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
/// in 8 of 200 cases.
#[test]
#[ignore = "BUG-1488: a second rewrite of an old version by a command that saw the first replaces it in the merge, though both stand (a divergent change)"]
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
        cases: review_cases(300),
        failure_persistence: None,
        rng_seed: proptest::test_runner::RngSeed::Fixed(20261108),
        ..ProptestConfig::default()
    })]

    /// BUG-1503: the long runs of the auto-rebase model check (with and
    /// without tags and workspaces on old versions, 120 to 300 steps), at
    /// a pinned seed. The
    /// ids within a case are random (identities, change ids), so the
    /// pinned inputs fail some runs, not every one: about 3 runs in 8.
    #[test]
    #[ignore = "BUG-1503: the long runs of the auto-rebase model check fail now and then (an old snapshot visible below a head); not traced; about 3 runs in 8 at this seed"]
    fn bug_1503_rewrites_follow_in_long_runs(nw in 2usize..5, old_refs in any::<bool>(), steps in prop::collection::vec(any::<u16>(), 120..300)) {
        check_rewrites_follow_through_merges(false, nw, false, old_refs, &steps)?;
    }
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
/// and change ids), so it is replayed and must pass every time.
#[test]
#[ignore = "BUG-1534: the BUG-1444 model check (undo, op restore, concurrent describes) still fails at its default length on fresh seeds"]
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
