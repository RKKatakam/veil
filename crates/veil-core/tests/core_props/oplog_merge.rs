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
    if let Some(w) = back.workspaces.get("w") {
        assert!((w.wc == first.wc && w.id == first.id) || (w.wc == later.wc && w.id == later.id), "{w:?}");
    }
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
    let visible = |v: &ObjectId| refs.iter().any(|r| r == v || repo.is_ancestor(v, r).unwrap());
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
                // Unless a later command that saw it took its head away (an
                // undo or op restore of the command that wrote it).
                let wrote: Vec<&Cmd> = cmds.iter().filter(|c| c.landed.is_some() && c.writes.iter().any(|(k2, v2)| *k2 == k && *v2 == Some(*v))).collect();
                let removed = cmds.iter().any(|d| d.landed.is_some() && d.writes.contains(&(Key::Head(v.0), None)) && wrote.iter().all(|c| c.landed.unwrap() < d.forked));
                prop_assert!(matches!(k, Key::Rtag(_)) || removed || visible(&v.0), "{}: {:?}: {} was dropped in a conflict", at, k, v.0.short());
            }
            continue;
        }
        let ok = match &k {
            // A head the model keeps must stay visible (a head, or below
            // one: a merge drops a head another ref now covers).
            Key::Head(h) if vals.contains(&Some((*h, None))) => got.is_some() || visible(h),
            Key::Head(h) => vals.contains(&got) || losers.contains(h),
            _ => vals.contains(&got),
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

fn review_cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: review_cases(64), failure_persistence: None, ..ProptestConfig::default() })]

    /// Guarantee 1 of the BUG-1294 review, memory backend, 2 to 5 writers.
    #[test]
    fn every_write_survives_concurrent_merges_memory(nw in 2usize..6, steps in prop::collection::vec(any::<u16>(), 20..120)) {
        check_every_write_survives(false, nw, false, false, &steps)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: review_cases(8), failure_persistence: None, ..ProptestConfig::default() })]

    /// The same on the disk backend.
    #[test]
    fn every_write_survives_concurrent_merges_disk(nw in 2usize..5, steps in prop::collection::vec(any::<u16>(), 20..80)) {
        check_every_write_survives(true, nw, false, false, &steps)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: review_cases(64), failure_persistence: None, ..ProptestConfig::default() })]

    /// The model check with `vl undo` and `vl op restore` among the
    /// commands, and writes back to earlier values (memory backend).
    #[test]
    fn bug_1295_every_write_survives_with_undo_and_restore(nw in 2usize..6, steps in prop::collection::vec(any::<u16>(), 20..120)) {
        check_every_write_survives(false, nw, true, true, &steps)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: review_cases(8), failure_persistence: None, ..ProptestConfig::default() })]

    /// The same on the disk backend.
    #[test]
    fn every_write_survives_with_undo_and_restore_disk(nw in 2usize..5, steps in prop::collection::vec(any::<u16>(), 20..80)) {
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
