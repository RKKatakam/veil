//! Persistent `ws exec` sandboxes at the engine level: incremental sync,
//! vouched stat-cache records and recording must always agree with a plain
//! rebuild from scratch, whatever the workspace and the command did.

use std::{path::Path, sync::Arc, time::Duration};

use proptest::prelude::*;
use veil_core::{
    builder::BuildReport,
    checkout::CheckoutReport,
    sandbox::{self, Manifest, VouchWait},
    statcache::StatCache,
    vfs::SandboxFs,
    workspace::SnapshotOptions,
    Identity, MemoryBackend, ObjectId, Repo, StorageBackend, VPath,
};

const WS: &str = "agent";
const PATHS: &[&str] = &["a", "b", "d/c", "d/e/f", "x.bin"];

fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

fn repo() -> Repo {
    let mut repo = Repo::init(Arc::new(MemoryBackend::new()), Some(Identity::generate("alice")), "alice").unwrap();
    let base = repo.workspace_wc("default").unwrap();
    repo.create_workspace(WS, vec![base], None).unwrap();
    repo
}

fn wc_tree(repo: &Repo) -> ObjectId {
    repo.snapshot(&repo.workspace_wc(WS).unwrap()).unwrap().tree
}

/// One sync, as `vl ws exec` does it.
fn sync(repo: &Repo, fs: &SandboxFs, m: &mut Manifest, cache: &mut StatCache) -> CheckoutReport {
    let tree = wc_tree(repo);
    let r = sandbox::sync(repo, fs, m, &tree, cache).unwrap();
    sandbox::vouch_written(repo.store(), fs, &tree, &r, cache, VouchWait::Always).unwrap();
    r
}

/// What the sandbox holds, built without any cache, relative to `parent`.
fn fresh_build(repo: &Repo, dir: &Path, parent: ObjectId) -> ObjectId {
    let plain = veil_core::DiskBackend::new(dir);
    repo.build_from(&plain, Some(parent), None).unwrap().0
}

#[derive(Clone, Debug)]
enum Op {
    /// Write content `n` (all contents of a path have the same size).
    Write(usize, u8),
    Remove(usize),
    /// Same-size rewrite with the old mtime put back.
    Sneaky(usize, u8),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0..PATHS.len(), 0u8..4).prop_map(|(i, n)| Op::Write(i, n)),
        (0..PATHS.len()).prop_map(Op::Remove),
        (0..PATHS.len(), 0u8..4).prop_map(|(i, n)| Op::Sneaky(i, n)),
    ]
}

fn content(i: usize, n: u8) -> Vec<u8> {
    format!("{}-{n}\n", PATHS[i]).into_bytes()
}

fn apply_command(dir: &Path, ops: &[Op]) {
    for o in ops {
        match *o {
            Op::Write(i, n) => {
                let f = dir.join(PATHS[i]);
                std::fs::create_dir_all(f.parent().unwrap()).unwrap();
                if f.is_dir() {
                    continue;
                }
                std::fs::write(&f, content(i, n)).unwrap();
            }
            Op::Remove(i) => {
                let _ = std::fs::remove_file(dir.join(PATHS[i]));
            }
            Op::Sneaky(i, n) => {
                let f = dir.join(PATHS[i]);
                let Ok(m) = std::fs::metadata(&f) else { continue };
                if !m.is_file() {
                    continue;
                }
                let mtime = m.modified().unwrap();
                std::fs::write(&f, content(i, n)).unwrap();
                std::fs::File::options().write(true).open(&f).unwrap().set_modified(mtime).unwrap();
            }
        }
    }
}

fn apply_workspace(repo: &mut Repo, ops: &[Op]) {
    let overlay = repo.workspace_overlay(WS).unwrap();
    for o in ops {
        match *o {
            Op::Write(i, n) | Op::Sneaky(i, n) => overlay.write(&p(PATHS[i]), &content(i, n)).unwrap(),
            Op::Remove(i) => {
                if overlay.metadata(&p(PATHS[i])).unwrap().is_some() {
                    overlay.remove_file(&p(PATHS[i])).unwrap();
                }
            }
        }
    }
    repo.snapshot_workspace(WS, &overlay).unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    #[test]
    fn incremental_sandboxes_record_exactly_what_a_fresh_build_sees(
        runs in prop::collection::vec((prop::collection::vec(op(), 0..4), prop::collection::vec(op(), 0..5)), 1..5)
    ) {
        let mut repo = repo();
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("files");
        std::fs::create_dir_all(&dir).unwrap();
        let mut m = Manifest::new(WS);
        let mut cache = StatCache::new();
        for (ws_ops, cmd_ops) in runs {
            apply_workspace(&mut repo, &ws_ops);
            let fs = SandboxFs::new(&dir, None, true);
            sync(&repo, &fs, &mut m, &mut cache);
            // The sandbox is exactly the workspace.
            let synced = wc_tree(&repo);
            prop_assert_eq!(fresh_build(&repo, &dir, synced), synced);
            apply_command(&dir, &cmd_ops);
            let expected = fresh_build(&repo, &dir, synced);
            let out = repo
                .snapshot_workspace_with(WS, &fs, SnapshotOptions { cache: Some(&mut cache), ..Default::default() })
                .unwrap();
            prop_assert_eq!(repo.snapshot(&out.snapshot).unwrap().tree, expected);
            m.tree = Some(expected);
        }
    }
}

#[test]
fn vouched_files_are_not_read_back() {
    let mut repo = repo();
    let overlay = repo.workspace_overlay(WS).unwrap();
    for i in 0..50 {
        overlay.write(&p(&format!("src/f{i}.rs")), format!("fn f{i}() {{}}\n").as_bytes()).unwrap();
    }
    repo.snapshot_workspace(WS, &overlay).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let fs = SandboxFs::new(tmp.path(), None, true);
    let mut m = Manifest::new(WS);
    let mut cache = StatCache::new();
    let r = sync(&repo, &fs, &mut m, &mut cache);
    assert_eq!(r.written, 50);
    let out = repo
        .snapshot_workspace_with(WS, &fs, SnapshotOptions { cache: Some(&mut cache), ..Default::default() })
        .unwrap();
    assert!(!out.changed);
    let BuildReport { hashed, cache_hits, .. } = out.report;
    assert_eq!(hashed, 0, "a vouched file was read back");
    assert_eq!(cache_hits, 50);
    // A same-size edit right after is still seen.
    std::thread::sleep(Duration::from_millis(5));
    std::fs::write(tmp.path().join("src/f7.rs"), b"fn g7() {}\n").unwrap();
    let out = repo
        .snapshot_workspace_with(WS, &fs, SnapshotOptions { cache: Some(&mut cache), ..Default::default() })
        .unwrap();
    assert!(out.changed);
    let tree = repo.snapshot(&out.snapshot).unwrap().tree;
    let e = veil_core::tree::lookup(repo.store(), &tree, &p("src/f7.rs")).unwrap().unwrap();
    assert_eq!(repo.store().read_entry(&e).unwrap(), b"fn g7() {}\n");
}

#[test]
fn injection_is_undone_and_copies_are_cleaned() {
    let mut repo = repo();
    let overlay = repo.workspace_overlay(WS).unwrap();
    overlay.write(&p("app.cfg"), b"port = 80\n").unwrap();
    repo.snapshot_workspace(WS, &overlay).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let fs = SandboxFs::new(tmp.path(), None, true);
    let mut m = Manifest::new(WS);
    let mut cache = StatCache::new();
    sync(&repo, &fs, &mut m, &mut cache);
    let synced = wc_tree(&repo);
    // The sandbox's own .env, from an earlier run.
    fs.write(&p(".env"), b"OWN=1\n").unwrap();
    let secret = b"API_TOKEN=Zq81kLm2Np4Rt6Vx8Bz0Cd3F\n".to_vec();
    let inj = sandbox::inject(&fs, &[(".env".into(), secret.clone()), ("nested/key.pem".into(), b"k".to_vec())]).unwrap();
    assert_eq!(inj.paths.len(), 2);
    assert_eq!(fs.read(&p(".env")).unwrap(), secret);
    // The command copies it around.
    std::fs::write(tmp.path().join("leak.txt"), &secret).unwrap();
    let mut cfg = b"port = 80\n".to_vec();
    cfg.extend_from_slice(&secret);
    std::fs::write(tmp.path().join("app.cfg"), &cfg).unwrap();
    std::fs::write(tmp.path().join("ok.txt"), b"fine\n").unwrap();
    let out = repo
        .snapshot_workspace_with(
            WS,
            &fs,
            SnapshotOptions { cache: Some(&mut cache), injected: Some(&inj.secrets), ..Default::default() },
        )
        .unwrap();
    let recorded = repo.snapshot(&out.snapshot).unwrap().tree;
    let c = sandbox::remove_injected(repo.store(), &fs, &synced, &recorded, &inj, &out.report, &mut cache).unwrap();
    assert!(c.failed.is_empty(), "{:?}", c.failed);
    assert_eq!(fs.read(&p(".env")).unwrap(), b"OWN=1\n", "the sandbox's own file is put back");
    assert!(!tmp.path().join("nested").exists(), "injected file (and its directory) removed");
    assert!(!tmp.path().join("leak.txt").exists());
    assert_eq!(fs.read(&p("app.cfg")).unwrap(), b"port = 80\n", "tracked file put back");
    assert_eq!(fs.read(&p("ok.txt")).unwrap(), b"fine\n");
    // Nothing of the secret anywhere in the sandbox.
    for e in walk(tmp.path()) {
        let d = std::fs::read(&e).unwrap();
        assert!(!d.windows(10).any(|w| w == b"Zq81kLm2Np"), "{}", e.display());
    }
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let path = e.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// After a checkout writes a cloaked file (and so invalidates its stat-cache
/// record), every later snapshot reads and decrypts it again: the builder's
/// "unchanged cloaked content keeps its sealing" path returns the parent
/// entry without recording what it verified. A sandbox (or a fresh clone)
/// with many cloaked files pays for them on every run.
#[test]
fn unchanged_cloaked_files_are_cached_after_a_checkout() {
    let mut repo = repo();
    let overlay = repo.workspace_overlay(WS).unwrap();
    overlay.write(&p(".veilpolicy"), b"vault/ cloak team\n").unwrap();
    overlay.write(&p("vault/plan.md"), b"secret plans\n").unwrap();
    repo.snapshot_workspace(WS, &overlay).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let fs = SandboxFs::new(tmp.path(), None, true);
    let mut m = Manifest::new(WS);
    let mut cache = StatCache::new();
    sync(&repo, &fs, &mut m, &mut cache);
    // Let the written files age past the racy window.
    std::thread::sleep(Duration::from_millis(150));
    let mut hashed = Vec::new();
    for _ in 0..3 {
        let out = repo
            .snapshot_workspace_with(WS, &fs, SnapshotOptions { cache: Some(&mut cache), ..Default::default() })
            .unwrap();
        assert!(!out.changed);
        hashed.push(out.report.hashed);
    }
    assert_eq!(hashed[2], 0, "the cloaked file is read on every snapshot: {hashed:?}");
}

// ---- sparse sandboxes -------------------------------------------------------

/// Paths of the sparse property test (no file is another's directory).
/// `g/` is cloaked.
const SPARSE_PATHS: &[&str] = &["a", "b/c", "b/d", "b/e/f", "b/e/g", "g/h", "g/i/j", "k.bin"];
/// Candidate `--only` paths (only those in the workspace's tree are used).
const SPARSE_ONLY: &[&str] = &["a", "b", "b/d", "b/e", "b/e/f", "g", "g/i", "k.bin"];
const SPARSE_POLICY: &[u8] = b"g/ cloak team\n";

use std::collections::BTreeMap;
use veil_core::vfs::{SparseSet, SparseView};

fn sparse_content(i: usize, n: u8) -> Vec<u8> {
    format!("{}={n}\n", SPARSE_PATHS[i]).into_bytes()
}

/// Every file of `tree` with its (decrypted) content.
fn flatten(repo: &Repo, tree: &ObjectId) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![(VPath::root(), *tree)];
    while let Some((dir, id)) = stack.pop() {
        for e in &repo.store().tree(&id).unwrap().entries {
            let p = dir.join(&e.name);
            match e.kind {
                veil_core::object::EntryKind::Dir => stack.push((p, e.id)),
                _ => {
                    out.insert(p.as_str().to_string(), repo.store().read_entry(e).unwrap());
                }
            }
        }
    }
    out
}

/// Every file under `dir` on disk, relative to it.
fn flatten_dir(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    walk(dir)
        .into_iter()
        .map(|f| (f.strip_prefix(dir).unwrap().to_str().unwrap().to_string(), std::fs::read(&f).unwrap()))
        .collect()
}

fn sparse_repo(files: &[(usize, u8)]) -> Repo {
    let mut repo = repo();
    let overlay = repo.workspace_overlay(WS).unwrap();
    overlay.write(&p(".veilpolicy"), SPARSE_POLICY).unwrap();
    for &(i, n) in files {
        overlay.write(&p(SPARSE_PATHS[i]), &sparse_content(i, n)).unwrap();
    }
    repo.snapshot_workspace(WS, &overlay).unwrap();
    repo
}

fn sparse_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0..SPARSE_PATHS.len(), 0u8..4).prop_map(|(i, n)| Op::Write(i, n)),
        (0..SPARSE_PATHS.len()).prop_map(Op::Remove),
        (0..SPARSE_PATHS.len(), 0u8..4).prop_map(|(i, n)| Op::Sneaky(i, n)),
    ]
}

fn apply_sparse_command(dir: &Path, ops: &[Op], model: &mut BTreeMap<String, Vec<u8>>) {
    for o in ops {
        match *o {
            Op::Write(i, n) => {
                let f = dir.join(SPARSE_PATHS[i]);
                std::fs::create_dir_all(f.parent().unwrap()).unwrap();
                std::fs::write(&f, sparse_content(i, n)).unwrap();
                model.insert(SPARSE_PATHS[i].to_string(), sparse_content(i, n));
            }
            Op::Remove(i) => {
                let _ = std::fs::remove_file(dir.join(SPARSE_PATHS[i]));
                model.remove(SPARSE_PATHS[i]);
            }
            Op::Sneaky(i, n) => {
                let f = dir.join(SPARSE_PATHS[i]);
                let Ok(m) = std::fs::metadata(&f) else { continue };
                let mtime = m.modified().unwrap();
                std::fs::write(&f, sparse_content(i, n)).unwrap();
                std::fs::File::options().write(true).open(&f).unwrap().set_modified(mtime).unwrap();
                model.insert(SPARSE_PATHS[i].to_string(), sparse_content(i, n));
            }
        }
    }
}

fn apply_sparse_workspace(repo: &mut Repo, ops: &[Op]) {
    let overlay = repo.workspace_overlay(WS).unwrap();
    for o in ops {
        match *o {
            Op::Write(i, n) | Op::Sneaky(i, n) => overlay.write(&p(SPARSE_PATHS[i]), &sparse_content(i, n)).unwrap(),
            Op::Remove(i) => {
                if overlay.metadata(&p(SPARSE_PATHS[i])).unwrap().is_some() {
                    overlay.remove_file(&p(SPARSE_PATHS[i])).unwrap();
                }
            }
        }
    }
    repo.snapshot_workspace(WS, &overlay).unwrap();
}

/// The `--only` set a run uses: the chosen candidates that the tree has
/// (as the CLI refuses the others); `None` (the whole tree) if none.
fn choose_set(repo: &Repo, tree: &ObjectId, chosen: &[usize]) -> Option<SparseSet> {
    let paths = chosen
        .iter()
        .map(|&i| p(SPARSE_ONLY[i]))
        .filter(|vp| veil_core::tree::lookup(repo.store(), tree, vp).unwrap().is_some());
    SparseSet::new(paths)
}

fn in_set(set: Option<&SparseSet>, path: &str) -> bool {
    set.is_none_or(|s| s.contains(&p(path)))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

    /// Random workspaces, random `--only` sets (changing from run to run)
    /// and random commands writing inside and outside the set: the sandbox
    /// holds exactly the set's files, the recorded tree is the workspace's
    /// with exactly the edits inside the set applied, and what was written
    /// outside is reported and removed.
    #[test]
    fn sparse_sandboxes_record_the_workspace_plus_exactly_the_edits_inside(
        initial in prop::collection::vec((0..SPARSE_PATHS.len(), 0u8..4), 1..8),
        runs in prop::collection::vec(
            (
                prop::collection::vec(sparse_op(), 0..3),
                prop::collection::vec(0..SPARSE_ONLY.len(), 0..3),
                prop::collection::vec(sparse_op(), 0..6),
            ),
            1..5,
        )
    ) {
        let mut repo = sparse_repo(&initial);
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("files");
        std::fs::create_dir_all(&dir).unwrap();
        let mut m = Manifest::new(WS);
        let mut cache = StatCache::new();
        for (ws_ops, chosen, cmd_ops) in runs {
            apply_sparse_workspace(&mut repo, &ws_ops);
            let synced = wc_tree(&repo);
            let set = choose_set(&repo, &synced, &chosen);
            let fs = SandboxFs::new(&dir, None, true);
            let r = sandbox::sync_to(&repo, &fs, &mut m, &synced, set.as_ref(), &mut cache).unwrap();
            sandbox::vouch_written(repo.store(), &fs, &synced, &r, &mut cache, VouchWait::Always).unwrap();
            prop_assert!(r.kept_local.is_empty() && r.obstructed.is_empty(), "{:?}", r);
            // The sandbox holds exactly the set's files.
            let ws = flatten(&repo, &synced);
            let mut model: BTreeMap<String, Vec<u8>> = ws.iter().filter(|(k, _)| in_set(set.as_ref(), k)).map(|(k, v)| (k.clone(), v.clone())).collect();
            prop_assert_eq!(&flatten_dir(&dir), &model);

            apply_sparse_command(&dir, &cmd_ops, &mut model);
            let view = set.as_ref().map(|s| SparseView::new(&fs, repo.store().clone(), synced, s));
            let rec: &dyn StorageBackend = match &view { Some(v) => v, None => &fs };
            let out = repo
                .snapshot_workspace_with(WS, rec, SnapshotOptions { cache: Some(&mut cache), expected_wc: Some(repo.workspace_wc(WS).unwrap()), ..Default::default() })
                .unwrap();
            prop_assert!(!out.superseded);
            let recorded = repo.snapshot(&out.snapshot).unwrap().tree;
            // The workspace, with exactly the edits inside the set.
            let mut expected: BTreeMap<String, Vec<u8>> = ws.iter().filter(|(k, _)| !in_set(set.as_ref(), k)).map(|(k, v)| (k.clone(), v.clone())).collect();
            expected.extend(model.iter().filter(|(k, _)| in_set(set.as_ref(), k)).map(|(k, v)| (k.clone(), v.clone())));
            prop_assert_eq!(&flatten(&repo, &recorded), &expected);
            // Cloaked stays cloaked, inside and out.
            for (path, _) in expected.iter().filter(|(k, _)| k.starts_with("g/")) {
                let e = veil_core::tree::lookup(repo.store(), &recorded, &p(path)).unwrap().unwrap();
                prop_assert!(!e.visibility.is_public(), "{} lost its cloak", path);
            }
            m.tree = Some(recorded);
            if let Some(set) = &set {
                let strays = sandbox::strays(&fs, set, &veil_core::policy::Policy::load(&fs).unwrap()).unwrap();
                let want: Vec<VPath> = model.keys().filter(|k| !set.contains(&p(k))).map(|k| p(k)).collect();
                prop_assert_eq!(&strays, &want);
                prop_assert!(sandbox::remove_strays(&fs, set, &strays, &mut cache).is_empty());
                model.retain(|k, _| set.contains(&p(k)));
            }
            prop_assert_eq!(&flatten_dir(&dir), &model);
        }
    }
}

#[test]
fn a_sparse_run_reuses_everything_outside_the_set_without_reading_it() {
    let mut repo = repo();
    let overlay = repo.workspace_overlay(WS).unwrap();
    for d in 0..20 {
        for i in 0..20 {
            overlay.write(&p(&format!("d{d}/f{i}.rs")), format!("fn f{d}_{i}() {{}}\n").as_bytes()).unwrap();
        }
    }
    repo.snapshot_workspace(WS, &overlay).unwrap();
    let synced = wc_tree(&repo);
    let tmp = tempfile::tempdir().unwrap();
    let fs = SandboxFs::new(tmp.path(), None, true);
    let mut m = Manifest::new(WS);
    let mut cache = StatCache::new();
    let set = SparseSet::new([p("d3")]).unwrap();
    let r = sandbox::sync_to(&repo, &fs, &mut m, &synced, Some(&set), &mut cache).unwrap();
    assert_eq!(r.written, 20, "only the set is written");
    sandbox::vouch_written(repo.store(), &fs, &synced, &r, &mut cache, VouchWait::Always).unwrap();
    std::fs::write(tmp.path().join("d3/f0.rs"), b"edited\n").unwrap();
    let view = SparseView::new(&fs, repo.store().clone(), synced, &set);
    let out = repo
        .snapshot_workspace_with(WS, &view, SnapshotOptions { cache: Some(&mut cache), ..Default::default() })
        .unwrap();
    assert!(out.changed);
    assert_eq!(out.report.hashed, 1, "only the edited file is read");
    let tree = repo.snapshot(&out.snapshot).unwrap().tree;
    assert_eq!(flatten(&repo, &tree).len(), 400);
    m.tree = Some(tree);
    // Widening to the whole tree writes the rest, and leaves the set alone.
    let r = sandbox::sync_to(&repo, &fs, &mut m, &tree, None, &mut cache).unwrap();
    assert_eq!((r.written, r.removed), (380, 0));
    assert_eq!(std::fs::read(tmp.path().join("d3/f0.rs")).unwrap(), b"edited\n");
    // And narrowing removes it again.
    let r = sandbox::sync_to(&repo, &fs, &mut m, &tree, Some(&SparseSet::new([p("d7/f1.rs")]).unwrap()), &mut cache).unwrap();
    assert_eq!((r.written, r.removed), (0, 399));
    assert_eq!(walk(tmp.path()).len(), 1);
}
