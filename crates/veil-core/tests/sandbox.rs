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
#[ignore = "BUG-300: unchanged cloaked files are re-read on every snapshot after a checkout"]
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
