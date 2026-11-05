//! `vl ws mount` under everything that can happen to it while it serves:
//! random edits in the mount interleaved with grants (files the mount never
//! showed becoming readable), other commands moving the workspace, `vl
//! undo`, and the mount process being killed. The recorded workspace is
//! checked against a model: nothing written is lost, nothing the mount
//! never showed is recorded as deleted (BUG-534), the mount's own
//! recordings are never what `vl undo` undoes (BUG-538), and a crash adds
//! no spurious change (BUG-539). Plus where a mount may be (BUG-535).
//!
//! Every test skips itself where FUSE is not available, mounts only under
//! its temporary directory, and unmounts on drop.

use crate::adversarial_support;

use std::{
    collections::BTreeMap,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use adversarial_support::*;
use proptest::prelude::*;

fn fuse_available() -> bool {
    let dev = std::fs::OpenOptions::new().read(true).write(true).open("/dev/fuse").is_ok();
    let tool = ["fusermount3", "fusermount"]
        .iter()
        .any(|b| Command::new(b).arg("-V").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok());
    if !(dev && tool && cfg!(target_os = "linux") && cfg!(feature = "fuse")) {
        eprintln!("skipping: FUSE is not available here");
        return false;
    }
    true
}

/// Unmounts (lazily) on drop, so a failing test leaves no mount behind.
struct Mounted(PathBuf);

impl Drop for Mounted {
    fn drop(&mut self) {
        for b in ["fusermount3", "fusermount"] {
            if Command::new(b).args(["-u", "-z", "-q"]).arg(&self.0).stderr(Stdio::null()).status().is_ok() {
                break;
            }
        }
    }
}

fn is_mounted(dir: &Path) -> bool {
    let info = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    info.lines().any(|l| l.split(' ').nth(4) == Some(dir.to_str().unwrap()))
}

fn mount_at(env: &Env, user: &str, proj: &Path, ws: &str, mnt: &Path) -> Mounted {
    let out = env.ok(user, proj, &["ws", "mount", ws, mnt.to_str().unwrap()]);
    assert!(out.contains("Mounted workspace"), "{out}");
    assert!(is_mounted(mnt), "not mounted: {out}");
    Mounted(mnt.to_path_buf())
}

fn state_pid(proj: &Path, ws: &str) -> i32 {
    let st: serde_json::Value =
        serde_json::from_slice(&std::fs::read(proj.join(".veil/local/mounts").join(ws).join("state.json")).unwrap()).unwrap();
    st["pid"].as_i64().unwrap() as i32
}

fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 only checks for existence.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Kill the mount process of `ws` (SIGKILL) and wait until it is gone.
fn crash(proj: &Path, ws: &str) {
    let pid = state_pid(proj, ws);
    // SAFETY: kill(2) of the mount process this test started.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    assert!(wait_for(Duration::from_secs(10), || !alive(pid)));
}

/// Paths of revision `rev` (`vl files`).
fn files(env: &Env, user: &str, proj: &Path, rev: &str) -> Vec<String> {
    env.stdout(user, proj, &["files", "-r", rev])
        .lines()
        .filter_map(|l| l.split_whitespace().rfind(|t| *t != "*").map(str::to_string))
        .collect()
}

fn public_key(env: &Env, user: &str) -> String {
    let out = env.ok(user, &env.root, &["identity", "show"]);
    out.lines().find(|l| l.starts_with("public key")).unwrap().split_whitespace().last().unwrap().to_string()
}

/// Every file under `dir` with its content (`dir` relative, `/`-separated).
fn tree(dir: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if e.file_type().unwrap().is_dir() {
                stack.push(p);
            } else {
                let rel = p.strip_prefix(dir).unwrap().to_str().unwrap().to_string();
                out.insert(rel, std::fs::read_to_string(&p).unwrap());
            }
        }
    }
    out
}

const SECRET: &str = "docs/secret.md";
const SECRET_TEXT: &str = "SECRET-PLAN-77\n";

/// Alice's project on a team remote: `docs/secret.md` cloaked for `team`
/// next to public files, `docs/readme.md` in the same directory. Bob clones
/// it before he holds the key and has workspace `work` on `main`.
fn bob_without_the_key(env: &Env) -> (PathBuf, PathBuf) {
    let alice = env.dir("alice");
    write(&alice, "top.txt", "top\n");
    write(&alice, "pub/a.txt", "a\n");
    write(&alice, "pub/b.txt", "b\n");
    write(&alice, "docs/readme.md", "readme\n");
    write(&alice, SECRET, SECRET_TEXT);
    env.ok("alice", &alice, &["init"]);
    env.ok("alice", &alice, &["cloak", SECRET]);
    env.ok("alice", &alice, &["commit", "-m", "initial"]);
    env.ok("alice", &alice, &["tag", "set", "main", "-r", "@-"]);
    let team = env.root.join("team");
    env.ok("alice", &alice, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &alice, &["push"]);
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    let bob = env.root.join("bob");
    env.ok("bob", &bob, &["ws", "new", "work", "-r", "main"]);
    (alice, bob)
}

/// Alice grants Bob `team`; Bob pulls, and his next command has the mount
/// read its tree with the new key.
fn grant(env: &Env, alice: &Path, bob: &Path) {
    let key = public_key(env, "bob");
    env.ok("alice", alice, &["scope", "grant", "team", &key, "--name", "bob"]);
    env.ok("alice", alice, &["push"]);
    env.ok("bob", bob, &["pull"]);
    env.ok("bob", bob, &["status"]);
    // What the kernel cached about the paths that appear (1 s).
    std::thread::sleep(Duration::from_millis(1100));
}

// ---- where a mount may be (BUG-535) -------------------------------------------

/// A repository created around an existing mount (`vl init` in a parent of
/// the mountpoint) never walks into it: the mount is another workspace,
/// cloaked files in plaintext.
#[test]
fn a_repository_around_a_mount_never_records_it() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let secret = env.dir("secret");
    write(&secret, "README.md", "hello\n");
    write(&secret, "internal/plan.md", SECRET_TEXT);
    env.ok("alice", &secret, &["init"]);
    env.ok("alice", &secret, &["cloak", "internal/"]);
    env.ok("alice", &secret, &["commit", "-m", "initial"]);
    env.ok("alice", &secret, &["ws", "new", "view", "-r", "@-"]);
    let outer = env.dir("outer");
    write(&outer, "lib.rs", "pub fn f() {}\n");
    let mnt = outer.join("mnt");
    let _g = mount_at(&env, "alice", &secret, "view", &mnt);
    assert_eq!(read(&mnt, "internal/plan.md"), SECRET_TEXT);
    // Now a repository is made around it.
    env.ok("alice", &outer, &["init"]);
    env.ok("alice", &outer, &["commit", "-m", "first"]);
    let recorded = files(&env, "alice", &outer, "@-");
    assert!(recorded.contains(&"lib.rs".to_string()), "{recorded:?}");
    assert!(!recorded.iter().any(|f| f.starts_with("mnt")), "the enclosing repository recorded the mount: {recorded:?}");
    // And it never writes into the mount (a checkout of another revision).
    env.ok("alice", &outer, &["new", "root()"]);
    assert_eq!(read(&mnt, "internal/plan.md"), SECRET_TEXT);
    let out = env.ok("alice", &secret, &["ws", "unmount", "view"]);
    assert!(!files(&env, "alice", &secret, "view@").is_empty(), "{out}");
}

/// The mountpoint is refused inside any repository: this one, another
/// one, a nested one, at any depth.
#[test]
fn mountpoints_inside_any_repository_are_refused() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "main"]);
    let other = env.project("alice", "other", &[("b.txt", "b\n")]);
    let nested = other.join("vendor/inner");
    std::fs::create_dir_all(&nested).unwrap();
    env.ok("alice", &nested, &["init"]);
    for dir in [other.join("deep/down/mnt"), nested.join("mnt"), proj.join("x")] {
        let out = env.vl("alice", &proj, &["ws", "mount", "agent", dir.to_str().unwrap()]);
        let _g = Mounted(dir.clone());
        assert!(!out.status.success(), "mounted at {}: {}", dir.display(), text(&out));
        assert!(!is_mounted(&dir));
    }
}

// ---- grants and crashes (BUG-534) ---------------------------------------------

/// Bob deletes `docs/` in the mount (he sees `readme.md` only), the mount
/// process dies, he is granted the scope, and the next mount recovers: the
/// file he never saw stays; the one he deleted goes.
#[test]
fn a_deleted_directory_keeps_what_it_never_showed_across_a_crash_and_a_grant() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let (alice, bob) = bob_without_the_key(&env);
    let mnt = env.root.join("mnt");
    let _g = mount_at(&env, "bob", &bob, "work", &mnt);
    assert!(!mnt.join(SECRET).exists());
    std::fs::remove_dir_all(mnt.join("docs")).unwrap();
    crash(&bob, "work");
    grant(&env, &alice, &bob);
    let out = env.ok("bob", &bob, &["ws", "unmount", "work"]);
    let recorded = files(&env, "bob", &bob, "work@");
    assert!(!recorded.contains(&"docs/readme.md".to_string()), "{out}\n{recorded:?}");
    assert!(recorded.contains(&SECRET.to_string()), "the file the mount never showed was recorded as deleted:\n{out}\n{recorded:?}");
    assert_eq!(env.stdout("bob", &bob, &["ws", "cat", "work", SECRET]), SECRET_TEXT);
}

// ---- the property ---------------------------------------------------------------

const PATHS: [&str; 7] = ["top.txt", "pub/a.txt", "pub/b.txt", "pub/new.txt", "docs/readme.md", "docs/new.md", "x/y/z.txt"];

#[derive(Clone, Debug)]
enum Op {
    /// Write `PATHS[i]` in the mount.
    Write(usize, u8),
    /// Delete `PATHS[i]` in the mount (if it shows there).
    Delete(usize),
    /// `rm -rf docs` (true) or `pub` in the mount.
    RmDir(bool),
    /// Bob is granted `team` (once).
    Grant,
    /// Another command writes the workspace (`vl ws write`).
    CliWrite(u8),
    /// Bob commits in the project directory, writes in the mount, and
    /// undoes: the commit is undone, the mount's write stays.
    CommitUndo(u8),
    /// The mount process dies, and the workspace is mounted again.
    Crash,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0..PATHS.len(), any::<u8>()).prop_map(|(i, c)| Op::Write(i, c)),
        2 => (0..PATHS.len()).prop_map(Op::Delete),
        2 => any::<bool>().prop_map(Op::RmDir),
        2 => Just(Op::Grant),
        1 => any::<u8>().prop_map(Op::CliWrite),
        1 => any::<u8>().prop_map(Op::CommitUndo),
        1 => Just(Op::Crash),
    ]
}

struct World {
    env: Env,
    alice: PathBuf,
    bob: PathBuf,
    mnt: PathBuf,
    _g: Mounted,
    /// What the workspace holds (and the mount shows, but the secret
    /// before the grant).
    model: BTreeMap<String, String>,
    granted: bool,
    n: usize,
}

impl World {
    fn new() -> World {
        let env = Env::new();
        let (alice, bob) = bob_without_the_key(&env);
        let mnt = env.root.join("mnt");
        let g = mount_at(&env, "bob", &bob, "work", &mnt);
        let policy = read(&mnt, ".veilpolicy");
        let model = [("top.txt", "top\n"), ("pub/a.txt", "a\n"), ("pub/b.txt", "b\n"), ("docs/readme.md", "readme\n"), (SECRET, SECRET_TEXT)]
            .into_iter()
            .map(|(p, c)| (p.to_string(), c.to_string()))
            .chain([(".veilpolicy".to_string(), policy)])
            .collect();
        World { env, alice, bob, mnt, _g: g, model, granted: false, n: 0 }
    }

    fn shown(&self) -> BTreeMap<String, String> {
        self.model.iter().filter(|(p, _)| self.granted || *p != SECRET).map(|(p, c)| (p.clone(), c.clone())).collect()
    }

    /// Bob's next command (the mount records, and follows the workspace).
    fn settle(&self) {
        self.env.ok("bob", &self.bob, &["status"]);
    }

    fn apply(&mut self, op: &Op) -> Result<(), TestCaseError> {
        self.n += 1;
        match *op {
            Op::Write(i, c) => {
                let path = self.mnt.join(PATHS[i]);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                let content = format!("{c} {}\n", self.n);
                std::fs::write(&path, &content).unwrap();
                self.model.insert(PATHS[i].to_string(), content);
            }
            Op::Delete(i) => {
                if self.model.contains_key(PATHS[i]) {
                    std::fs::remove_file(self.mnt.join(PATHS[i])).unwrap();
                    self.model.remove(PATHS[i]);
                }
            }
            Op::RmDir(docs) => {
                let dir = if docs { "docs/" } else { "pub/" };
                if self.mnt.join(dir).exists() {
                    std::fs::remove_dir_all(self.mnt.join(dir)).unwrap();
                }
                let granted = self.granted;
                self.model.retain(|p, _| !p.starts_with(dir) || (p == SECRET && !granted));
            }
            Op::Grant => {
                if !self.granted {
                    grant(&self.env, &self.alice, &self.bob);
                    self.granted = true;
                }
            }
            Op::CliWrite(c) => {
                let path = format!("cli/{}.txt", self.n);
                let content = format!("cli {c}\n");
                let mut child = self
                    .env
                    .cmd("bob", &self.bob, &["ws", "write", "work", &path])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                child.stdin.take().unwrap().write_all(content.as_bytes()).unwrap();
                let out = child.wait_with_output().unwrap();
                prop_assert!(out.status.success(), "ws write: {}", text(&out));
                self.model.insert(path, content);
                self.settle();
            }
            Op::CommitUndo(c) => {
                let local = format!("local-{}.txt", self.n);
                write(&self.bob, &local, "local\n");
                self.env.ok("bob", &self.bob, &["commit", "-m", &format!("local commit {}", self.n)]);
                let path = format!("undo-{}.txt", self.n);
                let content = format!("mount {c}\n");
                std::fs::write(self.mnt.join(&path), &content).unwrap();
                self.model.insert(path, content);
                let out = self.env.ok("bob", &self.bob, &["undo"]);
                prop_assert!(out.contains("Undid: commit change") && !out.contains("mount"), "undo undid something else:\n{out}");
                self.settle();
            }
            Op::Crash => {
                crash(&self.bob, "work");
                let out = self.env.ok("bob", &self.bob, &["ws", "mount", "work", self.mnt.to_str().unwrap()]);
                prop_assert!(out.contains("Mounted workspace"), "{out}");
            }
        }
        Ok(())
    }

    fn check(self) -> Result<(), TestCaseError> {
        // What the mount shows.
        self.settle();
        std::thread::sleep(Duration::from_millis(1100));
        let shown = tree(&self.mnt);
        prop_assert_eq!(&shown, &self.shown(), "what the mount shows");
        // What the workspace recorded.
        let out = self.env.ok("bob", &self.bob, &["ws", "unmount", "work"]);
        let mut recorded = files(&self.env, "bob", &self.bob, "work@");
        recorded.sort();
        // A path this reader cannot read is listed as `(redacted)`.
        let mut want: Vec<String> =
            self.model.keys().map(|p| if p == SECRET && !self.granted { "(redacted)".to_string() } else { p.clone() }).collect();
        want.sort();
        prop_assert_eq!(&recorded, &want, "what the workspace recorded:\n{}", out);
        for (p, c) in self.shown() {
            let got = self.env.stdout("bob", &self.bob, &["ws", "cat", "work", &p]);
            prop_assert_eq!(&got, &c, "{} in the workspace", p);
        }
        let log = self.env.stdout("bob", &self.bob, &["log", "-n", "200"]);
        prop_assert!(!log.contains("conflicted with a change"), "a spurious conflict change was saved:\n{}", log);
        Ok(())
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("VEIL_MOUNT_PROP_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(6),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn a_mount_under_grants_moves_undo_and_crashes_matches_the_model(ops in prop::collection::vec(op(), 1..10)) {
        if !fuse_available() {
            return Ok(());
        }
        let mut w = World::new();
        for op in &ops {
            w.apply(op)?;
        }
        w.check()?;
    }
}
