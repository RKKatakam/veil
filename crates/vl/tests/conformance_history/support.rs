//! Helpers: run the real `vl` binary with an isolated `VEIL_HOME`, and read
//! the resulting repository through `veil-core` to check the graph.

#![allow(dead_code)]

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::Arc,
};

use veil_core::{
    object::{EntryKind, Visibility},
    DiskBackend, Identity, Repo, StorageBackend, VPath,
};

pub const U: &str = "alice";

pub struct Env {
    _tmp: tempfile::TempDir,
    pub root: PathBuf,
}

impl Env {
    pub fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        Env { _tmp: tmp, root }
    }

    pub fn dir(&self, name: &str) -> PathBuf {
        let d = self.root.join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    pub fn home(&self, user: &str) -> PathBuf {
        self.root.join(format!("home-{user}"))
    }

    pub fn cmd(&self, user: &str, cwd: &Path, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_vl"));
        c.args(args)
            .current_dir(cwd)
            .env("VEIL_HOME", self.home(user))
            .env("VEIL_USER", user)
            .env("NO_COLOR", "1")
            .env("TMPDIR", self.dir("tmp"));
        c
    }

    pub fn run(&self, user: &str, cwd: &Path, args: &[&str]) -> Output {
        self.cmd(user, cwd, args).output().unwrap()
    }

    /// A new, empty repository (`vl init`) owned by alice.
    pub fn repo(&self, name: &str) -> R<'_> {
        let dir = self.dir(name);
        let r = R { env: self, dir, user: U.into() };
        r.ok(&["init"]);
        r
    }

    /// The same directory, driven as another user.
    pub fn as_user<'a>(&'a self, dir: &Path, user: &str) -> R<'a> {
        R { env: self, dir: dir.to_path_buf(), user: user.into() }
    }
}

pub fn text(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

/// Exit code set, not 101 (a Rust panic), no panic message.
pub fn exited_cleanly(out: &Output) -> bool {
    out.status.code().is_some_and(|c| c != 101) && !text(out).contains("panicked")
}

/// One repository directory, driven as one user.
pub struct R<'a> {
    pub env: &'a Env,
    pub dir: PathBuf,
    pub user: String,
}

/// What `veil-core` says about one snapshot.
#[derive(Debug, Clone)]
pub struct Snap {
    pub id: String,
    pub change: String,
    pub parents: Vec<String>,
    pub parent_changes: Vec<String>,
    pub conflicts: Vec<String>,
    pub description: Option<String>,
    pub cloak: Option<String>,
    pub embargo: Option<String>,
    pub predecessors: Vec<String>,
    pub tree: String,
}

impl R<'_> {
    pub fn run(&self, args: &[&str]) -> Output {
        self.env.run(&self.user, &self.dir, args)
    }

    /// stdout + stderr; asserts success.
    pub fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        let t = text(&out);
        assert!(out.status.success(), "vl {args:?} failed:\n{t}");
        t
    }

    /// stdout only; asserts success.
    pub fn out(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(out.status.success(), "vl {args:?} failed:\n{}", text(&out));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// stdout + stderr; asserts a clean failure (non-zero, no panic).
    pub fn fails(&self, args: &[&str]) -> String {
        let out = self.run(args);
        let t = text(&out);
        assert!(!out.status.success(), "vl {args:?} unexpectedly succeeded:\n{t}");
        assert!(exited_cleanly(&out), "vl {args:?} crashed:\n{t}");
        t
    }

    pub fn write(&self, rel: &str, content: impl AsRef<[u8]>) {
        let p = self.dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    pub fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.dir.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    pub fn read_bytes(&self, rel: &str) -> Vec<u8> {
        std::fs::read(self.dir.join(rel)).unwrap()
    }

    pub fn exists(&self, rel: &str) -> bool {
        self.dir.join(rel).symlink_metadata().is_ok()
    }

    pub fn rm(&self, rel: &str) {
        let p = self.dir.join(rel);
        if p.is_dir() {
            std::fs::remove_dir_all(p).unwrap();
        } else {
            std::fs::remove_file(p).unwrap();
        }
    }

    pub fn chmod_x(&self, rel: &str, exec: bool) {
        use std::os::unix::fs::PermissionsExt;
        let p = self.dir.join(rel);
        let mode = if exec { 0o755 } else { 0o644 };
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Write files, then `vl commit --no-advance -m msg` (tags stay where
    /// the test put them). Returns the committed change id.
    pub fn commit(&self, msg: &str, files: &[(&str, &str)]) -> String {
        for (p, c) in files {
            self.write(p, c);
        }
        self.ok(&["commit", "--no-advance", "-m", msg]);
        self.snap("@-").change
    }

    pub fn tag(&self, name: &str, rev: &str) {
        self.ok(&["tag", "set", name, "-r", rev, "--allow-backwards"]);
    }

    /// Open the repository through `veil-core` with this user's identity.
    pub fn core(&self) -> Repo {
        let id_path = self.env.home(&self.user).join("identity.json");
        let identity = std::fs::read_to_string(&id_path).ok().map(|s| Identity::from_json(&s).unwrap());
        Repo::open(Arc::new(DiskBackend::new(&self.dir)), identity, &self.user).unwrap()
    }

    /// Open the repository as an outsider who holds no key.
    pub fn core_anon(&self) -> Repo {
        Repo::open(Arc::new(DiskBackend::new(&self.dir)), Some(Identity::generate("anon")), "anon").unwrap()
    }

    pub fn snap(&self, rev: &str) -> Snap {
        let repo = self.core();
        let id = veil_core::revset::resolve(&repo, rev, "default").unwrap_or_else(|e| panic!("{rev}: {e}"));
        snap_of(&repo, &id)
    }

    pub fn try_snap(&self, rev: &str) -> Option<Snap> {
        let repo = self.core();
        let id = veil_core::revset::resolve(&repo, rev, "default").ok()?;
        Some(snap_of(&repo, &id))
    }

    /// Full change id of `rev`.
    pub fn cid(&self, rev: &str) -> String {
        self.snap(rev).change
    }

    /// Full snapshot id of `rev`.
    pub fn sid(&self, rev: &str) -> String {
        self.snap(rev).id
    }

    /// `path → content` of every readable file at `rev` (None: unreadable).
    pub fn tree_files(&self, rev: &str) -> Vec<(String, Option<Vec<u8>>, Visibility, bool)> {
        let repo = self.core();
        let id = veil_core::revset::resolve(&repo, rev, "default").unwrap();
        let s = repo.snapshot(&id).unwrap();
        veil_core::tree::walk_files(repo.store(), &s.tree)
            .unwrap()
            .into_iter()
            .filter(|(_, e)| e.kind == EntryKind::File)
            .map(|(p, e)| (p.to_string(), repo.store().read_entry(&e).ok(), e.visibility.clone(), e.executable))
            .collect()
    }

    pub fn paths(&self, rev: &str) -> Vec<String> {
        self.tree_files(rev).into_iter().map(|f| f.0).collect()
    }

    pub fn cat(&self, rev: &str, path: &str) -> String {
        self.out(&["cat", path, "-r", rev])
    }

    pub fn visibility(&self, rev: &str, path: &str) -> Visibility {
        let repo = self.core();
        let id = veil_core::revset::resolve(&repo, rev, "default").unwrap();
        let s = repo.snapshot(&id).unwrap();
        veil_core::tree::lookup(repo.store(), &s.tree, &VPath::new(path).unwrap())
            .unwrap()
            .unwrap_or_else(|| panic!("{path} not in {rev}"))
            .visibility
    }

    pub fn tag_target(&self, name: &str) -> Option<String> {
        self.core().view().tags.get(name).map(|t| t.target.hex())
    }

    pub fn op_head(&self) -> String {
        self.core().op_id().hex()
    }

    /// Change ids of every visible snapshot (root excluded).
    pub fn visible_changes(&self) -> Vec<String> {
        let repo = self.core();
        let root = repo.root_id();
        repo.visible_snapshots()
            .unwrap()
            .into_iter()
            .filter(|i| *i != root)
            .map(|i| repo.snapshot(&i).unwrap().change_id.display())
            .collect()
    }

    /// Visible snapshot ids, sorted (a fingerprint of the graph).
    pub fn graph(&self) -> Vec<String> {
        let mut v: Vec<String> = self.core().visible_snapshots().unwrap().iter().map(|i| i.hex()).collect();
        v.sort();
        v
    }

    /// Visible snapshots, tags and workspace pointers: everything undo must
    /// restore.
    pub fn state(&self) -> (Vec<String>, Vec<(String, String)>, Vec<(String, String)>) {
        let repo = self.core();
        let view = repo.view();
        let tags = view.tags.iter().map(|(n, t)| (n.clone(), t.target.hex())).collect();
        let wss = view.workspaces.iter().map(|(n, w)| (n.clone(), w.wc.hex())).collect();
        (self.graph(), tags, wss)
    }

    /// Paths under `.veil/` (raw files, and decoded pack entries) whose
    /// bytes contain `needle`. Cloaked content and sealed descriptions are
    /// encrypted at rest, so plaintext that only ever lived in cloaked
    /// files must never show up here.
    pub fn store_contains(&self, needle: &str) -> Vec<String> {
        store_contains(&self.dir, needle.as_bytes())
    }

    /// Every public file content and every plaintext description an
    /// outsider (no keys) can read in any snapshot of the store that
    /// contains `needle`.
    pub fn outsider_reads(&self, needle: &str) -> Vec<String> {
        let repo = self.core_anon();
        let mut hits = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut stack: Vec<_> = repo.visible_snapshots().unwrap();
        // Hidden snapshots too: everything the op log still reaches.
        for (_, op) in repo.op_log(10_000).unwrap() {
            stack.extend(op.view.heads.iter().copied());
            stack.extend(op.view.workspaces.values().map(|w| w.wc));
            stack.extend(op.view.tags.values().map(|t| t.target));
        }
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            let Some(s) = repo.snapshot_opt(&id).unwrap() else { continue };
            stack.extend(s.parents.iter().copied());
            stack.extend(s.predecessors.iter().copied());
            if let veil_core::object::Text::Plain(d) = &s.description {
                if d.contains(needle) {
                    hits.push(format!("description of {}", id.short()));
                }
            }
            let Ok(files) = veil_core::tree::walk_files(repo.store(), &s.tree) else { continue };
            for (p, e) in files {
                if e.kind != EntryKind::File {
                    continue;
                }
                if let Ok(data) = repo.store().read_entry(&e) {
                    if data.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                        hits.push(format!("{p} in {} ({:?})", id.short(), e.visibility));
                    }
                }
            }
        }
        hits
    }
}

pub fn snap_of(repo: &Repo, id: &veil_core::ObjectId) -> Snap {
    let s = repo.snapshot(id).unwrap();
    Snap {
        id: id.hex(),
        change: s.change_id.display(),
        parents: s.parents.iter().map(|p| p.hex()).collect(),
        parent_changes: s
            .parents
            .iter()
            .map(|p| repo.snapshot_opt(p).unwrap().map(|x| x.change_id.display()).unwrap_or_default())
            .collect(),
        conflicts: s.conflicts.clone(),
        description: repo.store().read_text(&s.description),
        cloak: s.cloak.clone(),
        embargo: s.embargo.clone(),
        predecessors: s.predecessors.iter().map(|p| p.hex()).collect(),
        tree: s.tree.hex(),
    }
}

pub fn store_contains(dir: &Path, needle: &[u8]) -> Vec<String> {
    use veil_core::{cache::LruCache, pack};
    let has = |data: &[u8]| data.windows(needle.len()).any(|w| w == needle);
    let fs = DiskBackend::new(dir);
    let mut hits = Vec::new();
    let files = veil_core::vfs::walk_files(&fs, &VPath::new(".veil").unwrap(), &|_| false).unwrap();
    for f in files {
        if let Ok(data) = fs.read(&f) {
            if has(&data) {
                hits.push(f.to_string());
            }
        }
    }
    let pdir = VPath::new(".veil/objects/pack").unwrap();
    if let Ok(entries) = fs.list_dir(&pdir) {
        let bases = LruCache::new(64 << 20);
        for e in entries {
            let Some(name) = pack::name_from_index_file(&e.name) else { continue };
            let p = pack::Pack::open(&fs, &pdir, name).unwrap();
            for id in p.index().ids() {
                if let Some(raw) = p.get(&fs, id, &bases).unwrap() {
                    if has(&raw) {
                        hits.push(format!("{}#{}", e.name, id.short()));
                    }
                }
            }
        }
    }
    hits
}

/// Lines `1\n2\n…n\n`, each prefixed.
pub fn lines(prefix: &str, n: usize) -> String {
    (1..=n).map(|i| format!("{prefix}{i}\n")).collect()
}
