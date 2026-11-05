//! Round 3: a property model of the Git bridge. Interleaved Veil commits
//! (public, cloaked, isolated files) and GitHub commits made with plain
//! `git`, synchronised with `vl git pull` / merge / `vl git push`.
//!
//! Invariants, checked after every synchronisation:
//! * Git never receives cloaked or isolated content (every object of the
//!   bare remote and of the bridge is grepped for every token ever written);
//! * Veil never loses cloaked data (each cloaked file reads back its last
//!   content on `main`);
//! * nothing is silently deleted on either side (after a sync, the public
//!   files of Veil `main` and GitHub `main` are exactly the model's);
//! * export is pinned and deterministic (an immediate re-export writes
//!   nothing and yields the same branches).
//!
//! `PROPTEST_CASES` scales it (default 16: every case runs dozens of `git`
//! processes).

#![cfg(feature = "git")]

use crate::adversarial_support;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use adversarial_support::*;
use proptest::prelude::*;
use veil_core::{git, MemoryBackend, ObjectId, Repo, StorageBackend};

fn git_bytes(dir: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Gita Hub")
        .env("GIT_AUTHOR_EMAIL", "gita@example.com")
        .env("GIT_COMMITTER_NAME", "Gita Hub")
        .env("GIT_COMMITTER_EMAIL", "gita@example.com")
        .args(["-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false"])
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!("git {args:?}: {}", String::from_utf8_lossy(&out.stderr)));
    }
    Ok(out.stdout)
}

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    Ok(String::from_utf8_lossy(&git_bytes(dir, args)?).trim().to_string())
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[derive(Clone, Debug)]
enum Op {
    /// Write (or delete) `pub/f<slot>` or `secrets/f<slot>` in Veil, commit,
    /// move `main`.
    Veil { slot: u8, cloaked: bool, delete: bool },
    /// Write (or delete) `pub/g<slot>` on GitHub, or add a file under
    /// `secrets/` there (Git-side content is public by definition).
    Git { slot: u8, delete: bool, in_secrets: bool },
    /// `vl git pull`, merge if diverged, `vl git push`.
    Sync,
    /// Re-export immediately: must write nothing.
    Reexport,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0u8..3, any::<bool>(), prop::bool::weighted(0.2))
            .prop_map(|(slot, cloaked, delete)| Op::Veil { slot, cloaked, delete }),
        3 => (0u8..3, prop::bool::weighted(0.2), prop::bool::weighted(0.15))
            .prop_map(|(slot, delete, in_secrets)| Op::Git { slot, delete, in_secrets }),
        3 => Just(Op::Sync),
        1 => Just(Op::Reexport),
    ]
}

struct World {
    _tmp: tempfile::TempDir,
    bare: PathBuf,
    bridge: PathBuf,
    work: PathBuf,
    repo: Repo,
    fs: Arc<MemoryBackend>,
    /// The tree `fs` currently reflects.
    fs_tree: ObjectId,
    /// Public files Veil and GitHub should both have after a sync.
    public: BTreeMap<String, String>,
    /// Cloaked files Veil must keep.
    cloaked: BTreeMap<String, String>,
    /// Every cloaked or isolated token ever written: Git must never see one.
    forbidden: Vec<String>,
    n: usize,
    github_dirty: bool,
}

const POLICY: &str = "secrets/ cloak team\n";

impl World {
    fn new() -> Result<World, String> {
        let tmp = tempfile::tempdir().unwrap();
        let bare = tmp.path().join("remote.git");
        git(tmp.path(), &["init", "--bare", "-q", bare.to_str().unwrap()])?;
        let bridge = tmp.path().join("bridge.git");
        let (mut repo, fs, _) = new_repo("alice");
        let isolated = "DB_PASSWORD=ISOLATED-TOKEN-0000\n";
        let c1 = commit_files(&mut repo, &*fs, &[(".veilpolicy", POLICY), ("pub/seed", "seed\n"), (".env", isolated)], "seed");
        repo.set_tag("main", c1, None, false).unwrap();
        git::remote_add(&mut repo, "github", bare.to_str().unwrap()).map_err(|e| e.to_string())?;
        git::push(&mut repo, &bridge, "github", &[], false).map_err(|e| e.to_string())?;
        let work = tmp.path().join("work");
        git(tmp.path(), &["clone", "-q", "-b", "main", bare.to_str().unwrap(), work.to_str().unwrap()])?;
        let wc = repo.workspace_wc(WS).unwrap();
        let fs_tree = repo.snapshot(&wc).unwrap().tree;
        let mut public = BTreeMap::new();
        public.insert("pub/seed".to_string(), "seed\n".to_string());
        Ok(World {
            _tmp: tmp,
            bare,
            bridge,
            work,
            repo,
            fs,
            fs_tree,
            public,
            cloaked: BTreeMap::new(),
            forbidden: vec!["ISOLATED-TOKEN-0000".into()],
            n: 0,
            github_dirty: false,
        })
    }

    fn token(&mut self, kind: &str) -> String {
        self.n += 1;
        format!("{kind}-TOKEN-{:04}", self.n)
    }

    /// Bring `fs` to the working-copy commit (merge and new_change move it).
    fn sync_fs(&mut self) -> Result<(), String> {
        let wc = self.repo.workspace_wc(WS).unwrap();
        let to = self.repo.snapshot(&wc).unwrap().tree;
        if to != self.fs_tree {
            self.repo.checkout_tree(&*self.fs, Some(&self.fs_tree), &to).map_err(|e| e.to_string())?;
            self.fs_tree = to;
        }
        Ok(())
    }

    fn onto_main(&mut self) -> Result<(), String> {
        let main = self.repo.view().tags["main"].target;
        self.repo.new_change(WS, vec![main], "").map_err(|e| e.to_string())?;
        self.sync_fs()
    }

    fn veil(&mut self, slot: u8, cloaked: bool, delete: bool) -> Result<(), String> {
        self.onto_main()?;
        let path = format!("{}/f{slot}", if cloaked { "secrets" } else { "pub" });
        if delete {
            let _ = self.fs.remove_file(&p(&path));
            self.public.remove(&path);
            self.cloaked.remove(&path);
        } else {
            let t = self.token(if cloaked { "CLOAK" } else { "PUBLIC" });
            self.fs.write(&p(&path), format!("{t}\n").as_bytes()).unwrap();
            if cloaked {
                self.forbidden.push(t.clone());
                self.cloaked.insert(path, format!("{t}\n"));
            } else {
                self.public.insert(path, format!("{t}\n"));
            }
        }
        snap(&mut self.repo, &*self.fs);
        let (c, wc) = self.repo.commit_working_copy(WS, "veil edit").map_err(|e| e.to_string())?;
        self.repo.set_tag("main", c, None, false).map_err(|e| e.to_string())?;
        self.fs_tree = self.repo.snapshot(&wc).unwrap().tree;
        Ok(())
    }

    fn github(&mut self, slot: u8, delete: bool, in_secrets: bool) -> Result<(), String> {
        git(&self.work, &["pull", "-q", "--ff-only", "origin", "main"])?;
        let rel = if in_secrets { format!("secrets/g{slot}") } else { format!("pub/g{slot}") };
        let file = self.work.join(&rel);
        if delete {
            if !file.exists() {
                return Ok(());
            }
            std::fs::remove_file(&file).unwrap();
            if !in_secrets {
                self.public.remove(&rel);
            }
        } else {
            let t = self.token("GIT");
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, format!("{t}\n")).unwrap();
            if !in_secrets {
                self.public.insert(rel.clone(), format!("{t}\n"));
            }
        }
        git(&self.work, &["add", "-A"])?;
        git(&self.work, &["commit", "-q", "-m", "github edit"])?;
        git(&self.work, &["push", "-q", "origin", "main"])?;
        self.github_dirty = true;
        Ok(())
    }

    fn sync(&mut self) -> Result<(), String> {
        let rep = git::pull(&mut self.repo, &self.bridge, "github").map_err(|e| format!("pull: {e}"))?;
        if !rep.import.failed.is_empty() {
            return Err(format!("import failed: {:?}", rep.import.failed));
        }
        let main = self.repo.view().tags["main"].target;
        let theirs = self.repo.view().remote_tags["github/main"];
        if !self.repo.is_ancestor(&theirs, &main).unwrap() {
            self.onto_main()?;
            let m = self
                .repo
                .merge(WS, main, vec![theirs], "merge GitHub", None)
                .map_err(|e| format!("merge: {e}"))?;
            if !m.conflicts.is_empty() {
                return Err(format!("unexpected conflicts {:?}", m.conflicts));
            }
            self.repo.set_tag("main", m.snapshot, None, false).unwrap();
            self.sync_fs()?;
        }
        let rep = git::push(&mut self.repo, &self.bridge, "github", &[], false).map_err(|e| format!("push: {e}"))?;
        if let Some((b, s)) = rep.outcome.refs.iter().find(|(_, s)| !s.accepted()) {
            return Err(format!("push of {b} rejected: {s:?}"));
        }
        self.github_dirty = false;
        self.check_synced()
    }

    fn check_no_leak(&self) -> Result<(), String> {
        for dir in [&self.bare, &self.bridge] {
            let objects = git_bytes(dir, &["cat-file", "--batch-all-objects", "--batch"])?;
            for t in &self.forbidden {
                if contains(&objects, t) {
                    return Err(format!("{t} reached {}", dir.display()));
                }
            }
        }
        Ok(())
    }

    fn check_synced(&self) -> Result<(), String> {
        self.check_no_leak()?;
        let main = self.repo.view().tags["main"].target;
        for (path, want) in &self.cloaked {
            let got = file_entry(&self.repo, &main, path)
                .ok_or_else(|| format!("cloaked {path} lost in Veil"))
                .and_then(|e| self.repo.store().read_entry(&e).map_err(|e| e.to_string()))?;
            if got != want.as_bytes() {
                return Err(format!("cloaked {path}: {:?} != {want:?}", String::from_utf8_lossy(&got)));
            }
        }
        // Public files of Veil main.
        let tree = self.repo.snapshot(&main).unwrap().tree;
        let mut veil_pub = BTreeMap::new();
        for (path, e) in veil_core::tree::walk_files(self.repo.store(), &tree).map_err(|e| e.to_string())? {
            if path.as_str().starts_with("pub/") {
                let data = self.repo.store().read_entry(&e).map_err(|e| e.to_string())?;
                veil_pub.insert(path.to_string(), String::from_utf8_lossy(&data).into_owned());
            }
        }
        if veil_pub != self.public {
            return Err(format!("Veil main public files {veil_pub:?} != model {:?}", self.public));
        }
        // Public files of GitHub main.
        let listing = git(&self.bare, &["ls-tree", "-r", "--name-only", "main"])?;
        let mut git_pub = BTreeMap::new();
        for path in listing.lines().filter(|l| l.starts_with("pub/")) {
            let data = git_bytes(&self.bare, &["show", &format!("main:{path}")])?;
            git_pub.insert(path.to_string(), String::from_utf8_lossy(&data).into_owned());
        }
        if git_pub != self.public {
            return Err(format!("GitHub main public files {git_pub:?} != model {:?}", self.public));
        }
        Ok(())
    }

    fn reexport(&mut self) -> Result<(), String> {
        if self.github_dirty {
            return Ok(());
        }
        let mut b = git::GitBridge::open(&self.repo, &self.bridge).map_err(|e| e.to_string())?;
        let before: Vec<_> = b.export(&mut self.repo, &[]).map_err(|e| e.to_string())?.branches;
        let again = b.export(&mut self.repo, &[]).map_err(|e| e.to_string())?;
        if again.written != 0 || again.branches != before {
            return Err(format!("re-export wrote {} commit(s): {:?} -> {:?}", again.written, before, again.branches));
        }
        self.check_no_leak()
    }

    fn apply(&mut self, op: &Op) -> Result<(), String> {
        match *op {
            Op::Veil { slot, cloaked, delete } => self.veil(slot, cloaked, delete),
            Op::Git { slot, delete, in_secrets } => {
                // Veil must sync before GitHub moves again, or the model's
                // concurrent edits of the same slot would conflict.
                self.github(slot, delete, in_secrets)
            }
            Op::Sync => self.sync(),
            Op::Reexport => self.reexport(),
        }
    }
}

fn run(ops: &[Op]) -> Result<(), String> {
    let mut w = World::new()?;
    for (i, op) in ops.iter().enumerate() {
        w.apply(op).map_err(|e| format!("step {i} {op:?}: {e}"))?;
        w.check_no_leak().map_err(|e| format!("step {i} {op:?}: {e}"))?;
    }
    w.sync().map_err(|e| format!("final sync: {e}"))
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(16),
        max_shrink_iters: 200,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn git_round_trips_keep_every_invariant(ops in prop::collection::vec(op(), 1..14)) {
        if let Err(e) = run(&ops) {
            prop_assert!(false, "{e}\nops: {ops:?}");
        }
    }
}
