//! Property-based tests.
//!
//! 1. Random sequences of history operations (edit, snapshot, commit,
//!    describe, new, edit, abandon, rebase, squash, merge, undo, op restore,
//!    workspaces, push, pull) checked after every step against invariants:
//!    every visible snapshot is readable, the working copy matches `@`, undo is
//!    an exact inverse, change ids survive rewrites, committed content can
//!    always be recovered from the op log, and pushes round-trip.
//! 2. Model equivalence of `MemoryBackend`, `OverlayBackend` (over empty,
//!    memory and tree-view lower layers) and `DiskBackend` against a simple
//!    reference model.
//!
//! Set `PROPTEST_CASES` to run more cases.

mod adversarial_support;

use std::{
    collections::{BTreeMap, BTreeSet},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::Arc,
};

use adversarial_support::*;
use proptest::prelude::*;
use veil_core::{
    id::ChangeId,
    remote,
    tree::{diff_trees, walk_files},
    vfs::NodeKind,
    DiskBackend, Identity, MemoryBackend, ObjectId, OverlayBackend, Repo, StorageBackend, VPath,
};

fn cfg(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(cases),
        failure_persistence: None,
        max_shrink_iters: 2000,
        ..ProptestConfig::default()
    }
}

// =====================================================================
// 1. History operations
// =====================================================================

const PATHS: &[&str] = &["a.txt", "dir/b.txt", "dir/sub/c.txt", "x", "x/y", "e.txt"];
const CONTENTS: &[&str] = &[
    "",
    "one\n",
    "1\n2\n3\n4\n5\n6\n7\n8\n",
    "1\n2\nTHREE\n4\n5\n6\n7\n8\n",
    "1\n2\n3\n4\n5\n6\n7\nEIGHT\n",
    "\0binary\0",
    "zzz\n",
];

#[derive(Debug, Clone)]
#[allow(clippy::enum_variant_names)]
enum Op {
    Write(usize, usize),
    Remove(usize),
    Commit,
    Describe(usize),
    New(usize),
    NewMerge(usize, usize),
    Edit(usize),
    Abandon(usize),
    Rebase(usize, usize),
    Squash(usize),
    Merge(usize),
    Undo,
    OpRestore(usize),
    WsNew(usize),
    WsWrite(usize, usize, usize),
    Tag(usize),
    Push,
    Pull,
}

fn arb_op() -> impl Strategy<Value = Op> {
    let i = || 0usize..64;
    prop_oneof![
        6 => (0..PATHS.len(), 0..CONTENTS.len()).prop_map(|(p, c)| Op::Write(p, c)),
        2 => (0..PATHS.len()).prop_map(Op::Remove),
        3 => Just(Op::Commit),
        1 => i().prop_map(Op::Describe),
        1 => i().prop_map(Op::New),
        1 => (i(), i()).prop_map(|(a, b)| Op::NewMerge(a, b)),
        1 => i().prop_map(Op::Edit),
        1 => i().prop_map(Op::Abandon),
        1 => (i(), i()).prop_map(|(a, b)| Op::Rebase(a, b)),
        1 => i().prop_map(Op::Squash),
        1 => i().prop_map(Op::Merge),
        2 => Just(Op::Undo),
        1 => i().prop_map(Op::OpRestore),
        1 => i().prop_map(Op::WsNew),
        2 => (i(), 0..PATHS.len(), 0..CONTENTS.len()).prop_map(|(w, p, c)| Op::WsWrite(w, p, c)),
        1 => i().prop_map(Op::Tag),
        1 => Just(Op::Push),
        1 => Just(Op::Pull),
    ]
}

#[allow(clippy::type_complexity)]
struct Harness {
    repo: Repo,
    fs: Arc<MemoryBackend>,
    materialized: ObjectId,
    remote: Arc<MemoryBackend>,
    identity: Identity,
    workspaces: usize,
    /// (op id right after the commit, change id, files of the commit)
    commits: Vec<(ObjectId, ChangeId, Vec<(VPath, Vec<u8>)>)>,
    log: Vec<String>,
    /// Create virtual workspaces cloaked under `team` and check that cloaked
    /// lines of work never hold public entries.
    cloaked: bool,
}

fn files_of(repo: &Repo, snapshot: &ObjectId) -> Vec<(VPath, Vec<u8>)> {
    let tree = repo.snapshot(snapshot).unwrap().tree;
    walk_files(repo.store(), &tree)
        .unwrap()
        .into_iter()
        .map(|(p, e)| {
            let d = veil_core::conflict::read_file_like(repo.store(), &e).unwrap();
            (p, d)
        })
        .collect()
}

impl Harness {
    fn new() -> Harness {
        let fs = Arc::new(MemoryBackend::new());
        let identity = Identity::generate("prop");
        let repo = Repo::init(fs.clone(), Some(identity.clone()), "prop").unwrap();
        let remote = Arc::new(MemoryBackend::new());
        Repo::init_bare(remote.clone()).unwrap();
        let wc = repo.workspace_wc(WS).unwrap();
        let materialized = repo.snapshot(&wc).unwrap().tree;
        Harness {
            repo,
            fs,
            materialized,
            remote,
            identity,
            workspaces: 0,
            commits: vec![],
            log: vec![],
            cloaked: false,
        }
    }

    fn visible(&self, include_root: bool) -> Vec<ObjectId> {
        let mut v = self.repo.visible_snapshots().unwrap();
        if !include_root {
            v.retain(|id| *id != self.repo.root_id());
        }
        v.sort();
        v
    }

    fn pick(&self, i: usize, include_root: bool) -> Option<ObjectId> {
        let v = self.visible(include_root);
        (!v.is_empty()).then(|| v[i % v.len()])
    }

    /// What every `vl` command does first.
    fn auto_snapshot(&mut self) {
        let out = self.repo.snapshot_workspace(WS, &*self.fs).unwrap();
        self.materialized = self.repo.snapshot(&out.snapshot).unwrap().tree;
    }

    /// What every `vl` command does last.
    fn sync_working_copy(&mut self) {
        let wc = self.repo.workspace_wc(WS).unwrap();
        let to = self.repo.snapshot(&wc).unwrap().tree;
        self.repo.checkout_tree(&*self.fs, Some(&self.materialized), &to).unwrap();
        self.materialized = to;
    }

    fn check(&mut self, ctx: &str) {
        // working copy matches @
        let wc = self.repo.workspace_wc(WS).unwrap();
        let s = self.repo.snapshot(&wc).unwrap();
        let (tree, _) = self.repo.build_amending(&*self.fs, &wc, None, None).unwrap();
        assert_eq!(
            tree, s.tree,
            "[{ctx}] working copy does not match @: disk={:?} @={:?}\nlog: {:#?}",
            disk_files(&self.fs),
            files_of(&self.repo, &wc),
            self.log
        );
        // every visible snapshot is readable
        for id in self.visible(true) {
            let snap = self.repo.snapshot(&id).unwrap_or_else(|e| panic!("[{ctx}] {id:?} unreadable: {e}"));
            for (path, e) in walk_files(self.repo.store(), &snap.tree).unwrap() {
                veil_core::conflict::read_file_like(self.repo.store(), &e)
                    .unwrap_or_else(|err| panic!("[{ctx}] {path} in {id:?} unreadable: {err}"));
            }
        }
        if self.cloaked {
            // content *introduced* by a cloaked change must never be public
            for id in self.visible(true) {
                let snap = self.repo.snapshot(&id).unwrap();
                if snap.cloak.is_none() {
                    continue;
                }
                let base = self.repo.parents_tree(&snap.parents).unwrap().tree;
                for c in diff_trees(self.repo.store(), Some(&base), Some(&snap.tree)).unwrap() {
                    if let Some(e) = c.new.as_ref().filter(|e| e.kind == veil_core::EntryKind::Conflict) {
                        // A conflict introduces no content: a public version
                        // in it is one some public line already holds.
                        let public = public_blobs(&self.repo);
                        for t in self.repo.store().conflict(&e.id).unwrap().interleaved().flatten() {
                            assert!(
                                !t.visibility.is_public() || public.contains(&t.id) || c.path.as_str() == ".veilpolicy",
                                "[{ctx}] cloaked change {id:?} introduces a public conflict version at {}\nlog: {:#?}",
                                c.path,
                                self.log
                            );
                        }
                        continue;
                    }
                    if let Some(e) = &c.new {
                        // A sealed edit edited back to the version readers
                        // without the key are shown at that path (the
                        // fallback of the base's sealed entry) introduces
                        // nothing either: they see the same bytes before and
                        // after (BUG-074 records it public again).
                        let shown_before = c
                            .old
                            .as_ref()
                            .filter(|o| matches!(o.visibility, veil_core::object::Visibility::Cloaked { .. }))
                            .and_then(|o| o.fallback)
                            .filter(|_| c.old.as_ref().is_some_and(|o| o.executable == e.executable));
                        assert!(
                            !e.visibility.is_public() || c.path.as_str() == ".veilpolicy" || shown_before == Some(e.id),
                            "[{ctx}] cloaked change {id:?} introduces public content at {}\nlog: {:#?}",
                            c.path,
                            self.log
                        );
                    }
                }
            }
        }
        // workspaces point at visible snapshots
        let vis: BTreeSet<ObjectId> = self.visible(true).into_iter().collect();
        for (name, w) in &self.repo.view().workspaces {
            assert!(vis.contains(&w.wc), "[{ctx}] workspace {name} points at an invisible snapshot");
        }
    }

    fn write_path(&self, path: &str, content: &str) {
        let vp = p(path);
        for anc in vp.ancestors() {
            if self.fs.metadata(&anc).unwrap().is_some_and(|m| m.kind == NodeKind::File) {
                self.fs.remove_file(&anc).unwrap();
            }
        }
        if self.fs.metadata(&vp).unwrap().is_some_and(|m| m.kind == NodeKind::Dir) {
            self.fs.remove_dir_all(&vp).unwrap();
        }
        self.fs.write(&vp, content.as_bytes()).unwrap();
    }

    fn apply(&mut self, op: &Op) {
        self.log.push(format!("{op:?}"));
        self.auto_snapshot();
        self.check(&format!("after auto-snapshot before {op:?}"));
        let view_before = self.repo.view().clone();
        let op_before = self.repo.op_id();
        let result: veil_core::Result<()> = (|| {
            match op {
                Op::Write(pi, c) => self.write_path(PATHS[*pi], CONTENTS[*c]),
                Op::Remove(pi) => {
                    let vp = p(PATHS[*pi]);
                    match self.fs.metadata(&vp)? {
                        Some(m) if m.kind == NodeKind::Dir => self.fs.remove_dir_all(&vp)?,
                        _ => self.fs.remove_file(&vp)?,
                    }
                }
                Op::Commit => {
                    let (c, _) = self.repo.commit_working_copy(WS, "commit")?;
                    let ch = self.repo.snapshot(&c)?.change_id;
                    let files = files_of(&self.repo, &c);
                    self.commits.push((self.repo.op_id(), ch, files));
                }
                Op::Describe(i) => {
                    if let Some(t) = self.pick(*i, false) {
                        let before = self.repo.snapshot(&t)?.change_id;
                        let n = self.repo.describe(t, &format!("described {i}"))?;
                        assert_eq!(self.repo.snapshot(&n)?.change_id, before, "describe changed the change id");
                    }
                }
                Op::New(i) => {
                    if let Some(t) = self.pick(*i, true) {
                        self.repo.new_change(WS, vec![t], "")?;
                    }
                }
                Op::NewMerge(i, j) => {
                    if let (Some(a), Some(b)) = (self.pick(*i, false), self.pick(*j, false)) {
                        if a != b {
                            self.repo.new_change(WS, vec![a, b], "")?;
                        }
                    }
                }
                Op::Edit(i) => {
                    if let Some(t) = self.pick(*i, false) {
                        self.repo.edit(WS, t)?;
                    }
                }
                Op::Abandon(i) => {
                    if let Some(t) = self.pick(*i, false) {
                        self.repo.abandon(t)?;
                    }
                }
                Op::Rebase(i, j) => {
                    if let (Some(s), Some(d)) = (self.pick(*i, false), self.pick(*j, true)) {
                        let before = self.repo.snapshot(&s)?.change_id;
                        let n = self.repo.rebase(s, vec![d])?;
                        assert_eq!(self.repo.snapshot(&n)?.change_id, before, "rebase changed the change id");
                    }
                }
                Op::Squash(i) => {
                    if let Some(t) = self.pick(*i, false) {
                        let parent = self.repo.snapshot(&t)?.parents.first().copied();
                        let pch = parent.map(|p| self.repo.snapshot(&p).map(|s| s.change_id)).transpose()?;
                        let n = self.repo.squash(t)?;
                        assert_eq!(Some(self.repo.snapshot(&n)?.change_id), pch, "squash changed the parent's change id");
                        let child_tree = files_of_tree_of(&self.repo, &n);
                        let _ = child_tree;
                    }
                }
                Op::Merge(i) => {
                    if let Some(t) = self.pick(*i, false) {
                        let wc = self.repo.workspace_wc(WS)?;
                        if t != wc {
                            self.repo.merge(WS, wc, vec![t], "merge", None)?;
                        }
                    }
                }
                Op::Undo => {
                    if self.repo.op_log(2)?.len() > 1 {
                        self.repo.undo()?;
                    }
                }
                Op::OpRestore(i) => {
                    let log = self.repo.op_log(64)?;
                    let (id, _) = &log[i % log.len()];
                    self.repo.restore_operation(*id)?;
                }
                Op::WsNew(i) => {
                    if let Some(t) = self.pick(*i, true) {
                        let cloak = self.cloaked.then(|| "team".to_string());
                        self.repo.create_workspace(&format!("w{}", self.workspaces), vec![t], cloak)?;
                        self.workspaces += 1;
                    }
                }
                Op::WsWrite(w, pi, c) => {
                    let names: Vec<String> = self.repo.view().workspaces.keys().filter(|n| *n != WS).cloned().collect();
                    if !names.is_empty() {
                        let name = &names[w % names.len()];
                        let ov = self.repo.workspace_overlay(name)?;
                        let vp = p(PATHS[*pi]);
                        for anc in vp.ancestors() {
                            if ov.metadata(&anc)?.is_some_and(|m| m.kind == NodeKind::File) {
                                ov.remove_file(&anc)?;
                            }
                        }
                        if ov.metadata(&vp)?.is_some_and(|m| m.kind == NodeKind::Dir) {
                            ov.remove_dir_all(&vp)?;
                        }
                        ov.write(&vp, CONTENTS[*c].as_bytes())?;
                        let out = self.repo.snapshot_workspace(name, &ov)?;
                        let got = self.repo.tree_view(&out.snapshot)?.read(&vp)?;
                        assert_eq!(got, CONTENTS[*c].as_bytes(), "overlay write not recorded");
                    }
                }
                Op::Tag(i) => {
                    if let Some(t) = self.pick(*i, false) {
                        self.repo.set_tag("t", t, None, true)?;
                    }
                }
                Op::Push => {
                    if !self.repo.view().tags.is_empty() {
                        remote::push(&mut self.repo, self.remote.clone(), false, &[], true)?;
                        // round-trip: a fresh clone sees identical content
                        let mut clone = Repo::init_for_clone(
                            Arc::new(MemoryBackend::new()),
                            Some(self.identity.clone()),
                            "clone",
                        )?;
                        remote::pull(&mut clone, "origin", self.remote.clone())?;
                        for (name, tag) in &clone.view().tags {
                            if self.repo.view().tags.get(name).map(|t| t.target) == Some(tag.target) {
                                assert_eq!(files_of(&clone, &tag.target), files_of(&self.repo, &tag.target), "push lost content");
                            }
                        }
                    }
                }
                Op::Pull => {
                    remote::pull(&mut self.repo, "origin", self.remote.clone())?;
                }
            }
            Ok(())
        })();
        self.log.push(format!("  -> {:?}", result.as_ref().err().map(|e| e.to_string())));
        if matches!(op, Op::Write(..) | Op::Remove(_)) {
            self.auto_snapshot(); // the next command records the edit
        } else {
            self.sync_working_copy();
        }
        self.check(&format!("after {op:?}"));

        // Undo must be an exact inverse of any successful operation.
        let is_history_op = !matches!(op, Op::Undo | Op::OpRestore(_) | Op::Write(..) | Op::Remove(_));
        if result.is_ok() && is_history_op && self.repo.op_id() != op_before {
            let view_after = self.repo.view().clone();
            self.repo.undo().unwrap();
            assert_eq!(self.repo.view(), &view_before, "undo of {op:?} is not an exact inverse");
            self.sync_working_copy();
            self.check(&format!("after undo of {op:?}"));
            self.repo.undo().unwrap();
            assert_eq!(self.repo.view(), &view_after, "redo of {op:?} did not restore the view");
            self.sync_working_copy();
            self.check(&format!("after redo of {op:?}"));
        }
    }

    /// No committed content is ever lost: every commit can be recovered by
    /// restoring the operation that created it.
    fn check_commits_recoverable(&mut self) {
        let head = self.repo.op_id();
        for (op, change, files) in self.commits.clone() {
            self.repo.restore_operation(op).unwrap();
            let found = self
                .visible(false)
                .into_iter()
                .filter(|id| self.repo.snapshot(id).unwrap().change_id == change)
                .any(|id| files_of(&self.repo, &id) == files);
            assert!(found, "committed change {change:?} cannot be recovered from the op log");
        }
        self.repo.restore_operation(head).unwrap();
        // every view in the op log only references readable snapshots
        for (id, op) in self.repo.op_log(usize::MAX).unwrap() {
            for r in op.view.refs() {
                assert!(self.repo.snapshot(&r).is_ok(), "op {id:?} references unreadable {r:?}");
            }
        }
    }
}

/// Every plaintext file version held by an uncloaked snapshot in the store.
fn public_blobs(repo: &Repo) -> BTreeSet<ObjectId> {
    let mut out = BTreeSet::new();
    for id in repo.store().list_objects().unwrap() {
        let Ok(s) = repo.store().snapshot(&id) else { continue };
        if s.cloak.is_some() {
            continue;
        }
        for (_, e) in walk_files(repo.store(), &s.tree).unwrap() {
            if e.kind == veil_core::EntryKind::File && e.visibility.is_public() {
                out.insert(e.id);
            }
        }
    }
    out
}

fn files_of_tree_of(repo: &Repo, id: &ObjectId) -> usize {
    files_of(repo, id).len()
}

fn disk_files(fs: &MemoryBackend) -> Vec<String> {
    fs.files()
        .into_iter()
        .filter(|p| !p.as_str().starts_with(".veil"))
        .map(|p| format!("{p}={:?}", String::from_utf8_lossy(&fs.read(&p).unwrap())))
        .collect()
}

fn run_ops(ops: &[Op]) -> Result<(), String> {
    run_ops_with(ops, false)
}

fn run_ops_with(ops: &[Op], cloaked: bool) -> Result<(), String> {
    let r = catch_unwind(AssertUnwindSafe(|| {
        let mut h = Harness::new();
        h.cloaked = cloaked;
        for op in ops {
            h.apply(op);
        }
        h.check_commits_recoverable();
    }));
    r.map_err(|e| {
        e.downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    })
}

proptest! {
    #![proptest_config(cfg(64))]

    #[test]
    fn random_history_operations_preserve_invariants(ops in proptest::collection::vec(arb_op(), 1..30)) {
        let r = run_ops(&ops);
        prop_assert!(r.is_ok(), "{}", r.unwrap_err());
    }
}

proptest! {
    #![proptest_config(cfg(256))]

    /// Same random operations with cloaked virtual workspaces.
    #[test]
    fn cloaked_lines_of_work_never_hold_public_entries(ops in proptest::collection::vec(arb_op(), 1..30)) {
        let r = run_ops_with(&ops, true);
        prop_assert!(r.is_ok(), "{}", r.unwrap_err());
    }
}

// =====================================================================
// 2. Backend model equivalence
// =====================================================================

const FPATHS: &[&str] = &["a", "a/b", "a/b/c", "d", "d/e", "f"];

#[derive(Debug, Clone)]
enum FsOp {
    Write(usize, u8),
    RemoveFile(usize),
    RemoveDirAll(usize),
    CreateDirAll(usize),
    SetExec(usize, bool),
    /// `metadata` / `exists` on a path (never mutates).
    Probe(usize),
}

fn arb_fs_op() -> impl Strategy<Value = FsOp> {
    let i = || 0..FPATHS.len();
    prop_oneof![
        4 => (i(), any::<u8>()).prop_map(|(p, d)| FsOp::Write(p, d)),
        2 => i().prop_map(FsOp::RemoveFile),
        1 => i().prop_map(FsOp::RemoveDirAll),
        1 => i().prop_map(FsOp::CreateDirAll),
        1 => (i(), any::<bool>()).prop_map(|(p, b)| FsOp::SetExec(p, b)),
        1 => i().prop_map(FsOp::Probe),
    ]
}

/// Reference model: files (content, executable) and directories.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Model {
    files: BTreeMap<String, (Vec<u8>, bool)>,
    dirs: BTreeSet<String>,
}

fn ancestors(p: &str) -> Vec<String> {
    VPath::new(p).unwrap().ancestors().into_iter().map(|a| a.as_str().to_string()).collect()
}

impl Model {
    /// `None` = behaviour unspecified by the trait docs (skipped everywhere).
    fn apply(&mut self, op: &FsOp) -> Option<bool> {
        match op {
            FsOp::Write(i, d) => {
                let p = FPATHS[*i];
                if self.dirs.contains(p) || ancestors(p).iter().any(|a| self.files.contains_key(a)) {
                    return Some(false);
                }
                self.dirs.extend(ancestors(p));
                let exec = self.files.get(p).is_some_and(|f| f.1);
                self.files.insert(p.to_string(), (vec![*d; (*d as usize % 5) + 1], exec));
                Some(true)
            }
            FsOp::RemoveFile(i) => {
                let p = FPATHS[*i];
                if self.dirs.contains(p) {
                    return None;
                }
                self.files.remove(p);
                Some(true)
            }
            FsOp::RemoveDirAll(i) => {
                let p = FPATHS[*i];
                if self.files.contains_key(p) {
                    return None;
                }
                let pre = format!("{p}/");
                self.dirs.retain(|d| d != p && !d.starts_with(&pre));
                self.files.retain(|f, _| !f.starts_with(&pre));
                Some(true)
            }
            FsOp::CreateDirAll(i) => {
                let p = FPATHS[*i];
                if self.files.contains_key(p) || ancestors(p).iter().any(|a| self.files.contains_key(a)) {
                    return Some(false);
                }
                self.dirs.extend(ancestors(p));
                self.dirs.insert(p.to_string());
                Some(true)
            }
            FsOp::SetExec(i, b) => {
                let p = FPATHS[*i];
                if self.dirs.contains(p) {
                    return None;
                }
                match self.files.get_mut(p) {
                    Some(f) => {
                        f.1 = *b;
                        Some(true)
                    }
                    None => Some(false),
                }
            }
            // metadata() on any path is Ok; the answer is "exists or not"
            FsOp::Probe(_) => Some(true),
        }
    }
}

fn apply_fs(fs: &dyn StorageBackend, op: &FsOp) -> bool {
    let r = match op {
        FsOp::Write(i, d) => fs.write(&p(FPATHS[*i]), &vec![*d; (*d as usize % 5) + 1]),
        FsOp::RemoveFile(i) => fs.remove_file(&p(FPATHS[*i])),
        FsOp::RemoveDirAll(i) => fs.remove_dir_all(&p(FPATHS[*i])),
        FsOp::CreateDirAll(i) => fs.create_dir_all(&p(FPATHS[*i])),
        FsOp::SetExec(i, b) => fs.set_executable(&p(FPATHS[*i]), *b),
        FsOp::Probe(i) => fs.metadata(&p(FPATHS[*i])).map(|_| ()).and_then(|_| fs.exists(&p(FPATHS[*i])).map(|_| ())),
    };
    r.is_ok()
}

fn observe(fs: &dyn StorageBackend) -> Model {
    let mut m = Model::default();
    let mut stack = vec![VPath::root()];
    while let Some(d) = stack.pop() {
        for e in fs.list_dir(&d).unwrap() {
            let c = d.join(&e.name);
            if c.as_str() == ".veil" {
                continue;
            }
            match e.kind {
                NodeKind::Dir => {
                    m.dirs.insert(c.as_str().to_string());
                    stack.push(c);
                }
                NodeKind::File => {
                    let meta = fs.metadata(&c).unwrap().unwrap();
                    m.files.insert(c.as_str().to_string(), (fs.read(&c).unwrap(), meta.executable));
                }
                NodeKind::Symlink => {}
            }
        }
    }
    m
}

/// Initial content as a list of (path index, byte, exec).
fn arb_initial() -> impl Strategy<Value = Vec<(usize, u8, bool)>> {
    proptest::collection::vec((0..FPATHS.len(), any::<u8>(), any::<bool>()), 0..4)
}

fn seed(fs: &dyn StorageBackend, model: &mut Model, init: &[(usize, u8, bool)]) {
    for (i, d, x) in init {
        let op = FsOp::Write(*i, *d);
        if model.apply(&op) == Some(true) {
            assert!(apply_fs(fs, &op));
            model.apply(&FsOp::SetExec(*i, *x));
            fs.set_executable(&p(FPATHS[*i]), *x).unwrap();
        }
    }
}

fn check_equivalence(name: &str, fs: &dyn StorageBackend, base: Model, ops: &[FsOp]) -> Result<(), String> {
    let mut model = base;
    for (n, op) in ops.iter().enumerate() {
        let mut probe = model.clone();
        let Some(expect) = probe.apply(op) else { continue };
        let got = apply_fs(fs, op);
        if got != expect {
            return Err(format!("{name}: op #{n} {op:?} returned ok={got}, model says ok={expect}; state before: {model:?}"));
        }
        model = probe;
        let seen = observe(fs);
        if seen != model {
            return Err(format!("{name}: after op #{n} {op:?}\n  backend: {seen:?}\n  model:   {model:?}"));
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(cfg(256))]

    #[test]
    fn memory_backend_matches_model(init in arb_initial(), ops in proptest::collection::vec(arb_fs_op(), 1..25)) {
        let fs = MemoryBackend::new();
        let mut m = Model::default();
        seed(&fs, &mut m, &init);
        let r = check_equivalence("memory", &fs, m, &ops);
        prop_assert!(r.is_ok(), "{}", r.unwrap_err());
    }

    #[test]
    fn disk_backend_matches_model(init in arb_initial(), ops in proptest::collection::vec(arb_fs_op(), 1..25)) {
        let tmp = tempfile::tempdir().unwrap();
        let fs = DiskBackend::new(tmp.path());
        let mut m = Model::default();
        seed(&fs, &mut m, &init);
        let r = check_equivalence("disk", &fs, m, &ops);
        prop_assert!(r.is_ok(), "{}", r.unwrap_err());
    }

    #[test]
    fn overlay_over_empty_lower_matches_model(ops in proptest::collection::vec(arb_fs_op(), 1..25)) {
        let fs = OverlayBackend::new(Arc::new(MemoryBackend::new()));
        let r = check_equivalence("overlay/empty", &fs, Model::default(), &ops);
        prop_assert!(r.is_ok(), "{}", r.unwrap_err());
    }

    #[test]
    fn overlay_over_memory_lower_matches_model(init in arb_initial(), ops in proptest::collection::vec(arb_fs_op(), 1..25)) {
        let lower = MemoryBackend::new();
        let mut m = Model::default();
        seed(&lower, &mut m, &init);
        let lower = Arc::new(lower);
        let fs = OverlayBackend::new(lower.clone());
        let before = observe(&*lower);
        let r = check_equivalence("overlay/memory", &fs, m, &ops);
        prop_assert!(r.is_ok(), "{}", r.unwrap_err());
        prop_assert_eq!(observe(&*lower), before, "overlay modified its lower layer");
    }

    /// The ephemeral-workspace configuration: overlay over a snapshot tree.
    #[test]
    fn overlay_over_tree_view_matches_model(init in arb_initial(), ops in proptest::collection::vec(arb_fs_op(), 1..25)) {
        let (mut repo, wc, _) = new_repo("m");
        let mut m = Model::default();
        seed(&*wc, &mut m, &init);
        let s = snap(&mut repo, &*wc);
        let fs = OverlayBackend::new(Arc::new(repo.tree_view(&s).unwrap()));
        // trees do not record empty directories, and drop .veil
        let base = observe(&fs);
        let mut expect = m.clone();
        expect.dirs.retain(|d| base.dirs.contains(d));
        prop_assert_eq!(&base, &expect);
        let r = check_equivalence("overlay/tree", &fs, expect, &ops);
        prop_assert!(r.is_ok(), "{}", r.unwrap_err());
    }
}

// Deterministic reproductions of divergences found by the model tests.

#[test]
fn overlay_does_not_replace_a_lower_file_with_a_directory() {
    let lower = Arc::new(MemoryBackend::from_files([("a", &b"file"[..])]).unwrap());
    let o = OverlayBackend::new(lower);
    let m = MemoryBackend::from_files([("a", &b"file"[..])]).unwrap();
    assert!(m.write(&p("a/b"), b"x").is_err());
    assert!(o.write(&p("a/b"), b"x").is_err(), "overlay replaced file 'a' with a directory");
}

#[test]
fn disk_paths_below_a_file_are_simply_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let d = DiskBackend::new(tmp.path());
    d.write(&p("a"), b"file").unwrap();
    let m = MemoryBackend::from_files([("a", &b"file"[..])]).unwrap();
    for fs in [&d as &dyn StorageBackend, &m] {
        assert_eq!(fs.metadata(&p("a/b")).ok(), Some(None), "{}: metadata", fs.kind());
        assert!(fs.remove_file(&p("a/b")).is_ok(), "{}: remove_file", fs.kind());
        assert!(fs.remove_dir_all(&p("a/b")).is_ok(), "{}: remove_dir_all", fs.kind());
    }
}

/// BUG-128: this sequence (found by `cloaked_lines_of_work_never_hold_public_entries`)
/// sometimes makes a change on a cloaked line record a new *public* file
/// (`dir/sub/c.txt` after the last `WsWrite`). Which changes the indices
/// pick depends on random ids, so it fails in about 1 run in 12; the loop
/// makes a failure near-certain.
#[test]
fn bug128_cloaked_line_records_a_public_file() {
    use Op::*;
    let ops = vec![
        Write(0, 1), WsNew(13), WsWrite(50, 1, 3), Remove(5), Undo, WsWrite(25, 1, 5), Push, Remove(2),
        Write(2, 5), NewMerge(38, 25), Merge(59), Remove(1), Tag(41), WsWrite(44, 4, 4), Write(5, 4),
        WsWrite(50, 0, 1), Rebase(38, 34), Commit, WsWrite(43, 2, 4), Abandon(43), Describe(11), WsNew(51),
        Commit, WsWrite(50, 2, 5),
    ];
    for _ in 0..100 {
        let r = run_ops_with(&ops, true);
        assert!(r.is_ok(), "{}", r.unwrap_err());
    }
}
