//! Helpers for the adversarial CLI suites: run the real `vl` binary, and build
//! hostile repositories on disk with `veil-core`.

#![allow(dead_code)]

use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use veil_core::{
    id::ChangeId,
    object::{EntryKind, Object, Snapshot, Text, Tree, TreeEntry, Visibility},
    oplog::Tag,
    MemoryBackend, ObjectId, Repo, StorageBackend, VPath,
};

pub struct Env {
    pub tmp: tempfile::TempDir,
    pub root: PathBuf,
}

impl Env {
    pub fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        Env { tmp, root }
    }

    pub fn dir(&self, name: &str) -> PathBuf {
        let d = self.root.join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    pub fn cmd(&self, user: &str, cwd: &Path, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_vl"));
        c.env("VEIL_TEST_PATH_REMOTES", "1").args(args)
            .current_dir(cwd)
            .env("VEIL_HOME", self.root.join(format!("home-{user}")))
            .env("VEIL_USER", user)
            .env("NO_COLOR", "1")
            .env("TMPDIR", self.dir("tmp"));
        c
    }

    pub fn vl(&self, user: &str, cwd: &Path, args: &[&str]) -> Output {
        self.cmd(user, cwd, args).output().unwrap()
    }

    pub fn spawn(&self, user: &str, cwd: &Path, args: &[&str]) -> Child {
        self.cmd(user, cwd, args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    /// stdout + stderr; asserts success.
    pub fn ok(&self, user: &str, cwd: &Path, args: &[&str]) -> String {
        let out = self.vl(user, cwd, args);
        let text = text(&out);
        assert!(out.status.success(), "vl {args:?} failed:\n{text}");
        text
    }

    pub fn stdout(&self, user: &str, cwd: &Path, args: &[&str]) -> String {
        let out = self.vl(user, cwd, args);
        assert!(out.status.success(), "vl {args:?} failed: {}", text(&out));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// A fresh project with one commit tagged `main`.
    pub fn project(&self, user: &str, name: &str, files: &[(&str, &str)]) -> PathBuf {
        let proj = self.dir(name);
        self.ok(user, &proj, &["init"]);
        for (p, c) in files {
            write(&proj, p, c);
        }
        self.ok(user, &proj, &["commit", "-m", "initial"]);
        self.ok(user, &proj, &["tag", "set", "main", "-r", "@-"]);
        proj
    }
}

pub fn text(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

/// Did the process end normally (exit code, no signal, no Rust panic)?
pub fn exited_cleanly(out: &Output) -> bool {
    out.status.code().is_some_and(|c| c != 101) && !text(out).contains("panicked")
}

pub fn write(dir: &Path, rel: &str, content: &str) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

pub fn read(dir: &Path, rel: &str) -> String {
    std::fs::read_to_string(dir.join(rel)).unwrap()
}

pub fn wait_for(timeout: Duration, mut f: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

pub fn vp(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

// ---- hostile remotes ------------------------------------------------------

pub fn file(name: &str, id: ObjectId) -> TreeEntry {
    TreeEntry {
        name: name.into(),
        kind: EntryKind::File,
        id,
        size: 0,
        executable: false,
        visibility: Visibility::Public,
    }
}

pub fn dir(name: &str, id: ObjectId) -> TreeEntry {
    TreeEntry::dir(name, id)
}

pub fn blob(r: &Repo, data: &[u8]) -> ObjectId {
    r.store().put(&Object::Blob(data.to_vec())).unwrap()
}

pub fn raw_tree(r: &Repo, entries: Vec<TreeEntry>) -> ObjectId {
    r.store().put(&Object::Tree(Tree { entries })).unwrap()
}

/// Build a bare repository in memory whose tag `main` points at a snapshot
/// with the tree produced by `build`, then dump it to `dest` on disk.
pub fn evil_remote_on_disk(dest: &Path, description: &str, tags: &[&str], build: impl FnOnce(&Repo) -> ObjectId) {
    let mem = Arc::new(MemoryBackend::new());
    let mut r = Repo::init_bare(mem.clone()).unwrap();
    let tree = build(&r);
    let root = r.root_id();
    let s = r
        .store()
        .put_snapshot(&Snapshot {
            parents: vec![root],
            change_id: ChangeId::random(),
            tree,
            description: Text::Plain(description.into()),
            author: "mallory".into(),
            timestamp: 1,
            predecessors: vec![],
            conflicts: vec![],
            signature: None,
            embargo: None,
        })
        .unwrap();
    let mut tx = r.transaction("evil").unwrap();
    for t in tags {
        tx.view.tags.insert(t.to_string(), Tag::new(s));
    }
    tx.view.heads.insert(s);
    tx.commit().unwrap();
    dump(&mem, dest);
}

/// Copy every file of a memory backend to a host directory (no fsync).
pub fn dump(mem: &MemoryBackend, dest: &Path) {
    for f in mem.files() {
        let p = dest.join(f.as_str());
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, mem.read(&f).unwrap()).unwrap();
    }
}

/// Every path under `dir` (recursive), relative.
pub fn tree_listing(dir: &Path) -> Vec<String> {
    fn go(base: &Path, d: &Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(d).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            out.push(p.strip_prefix(base).unwrap().to_string_lossy().into_owned());
            if e.file_type().unwrap().is_dir() {
                go(base, &p, out);
            }
        }
    }
    let mut out = Vec::new();
    if dir.exists() {
        go(dir, dir, &mut out);
    }
    out.sort();
    out
}
