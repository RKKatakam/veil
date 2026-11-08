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
