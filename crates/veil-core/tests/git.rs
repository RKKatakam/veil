//! Two-way Git interop. Every "Git remote" is a local bare repository and
//! every change made "on GitHub" is made with the plain `git` binary, so the
//! suite runs offline.

#![cfg(feature = "git")]

mod adversarial_support;

use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use adversarial_support::*;
use veil_core::{
    commands::EmbargoSpec,
    git::{self, GitBridge, RefStatus},
    object::Visibility,
    MemoryBackend, ObjectId, Repo, StorageBackend,
};

// ---- helpers -------------------------------------------------------------------

fn git_bytes(dir: &Path, args: &[&str]) -> Vec<u8> {
    let out = Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Gita Hub")
        .env("GIT_AUTHOR_EMAIL", "gita@example.com")
        .env("GIT_COMMITTER_NAME", "Gita Hub")
        .env("GIT_COMMITTER_EMAIL", "gita@example.com")
        .args(["-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", "-c", "advice.detachedHead=false"])
        .args(args)
        .output()
        .expect("git is installed");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn git(dir: &Path, args: &[&str]) -> String {
    String::from_utf8(git_bytes(dir, args)).unwrap().trim().to_string()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Every object of a Git repository (loose and packed), decompressed.
fn all_git_objects(git_dir: &Path) -> Vec<u8> {
    git_bytes(git_dir, &["cat-file", "--batch-all-objects", "--batch"])
}

struct Env {
    tmp: tempfile::TempDir,
    bare: PathBuf,
    bridge: PathBuf,
}

impl Env {
    fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let bare = tmp.path().join("remote.git");
        git(tmp.path(), &["init", "--bare", "-q", bare.to_str().unwrap()]);
        let bridge = tmp.path().join("bridge.git");
        Env { tmp, bare, bridge }
    }

    fn url(&self) -> &str {
        self.bare.to_str().unwrap()
    }

    /// A fresh working clone of the bare remote ("someone on GitHub").
    fn clone_work(&self, name: &str) -> PathBuf {
        let work = self.tmp.path().join(name);
        git(self.tmp.path(), &["clone", "-q", self.url(), work.to_str().unwrap()]);
        work
    }

    fn connect(&self, repo: &mut Repo) {
        git::remote_add(repo, "github", self.url()).unwrap();
    }

    fn push(&self, repo: &mut Repo) -> git::PushReport {
        git::push(repo, &self.bridge, "github", &[], false).unwrap()
    }

    fn remote_head(&self, branch: &str) -> String {
        git(&self.bare, &["rev-parse", &format!("refs/heads/{branch}")])
    }
}

const POLICY: &str = "secrets/ cloak team\n";
const CLOAKED: &str = "CLOAKED-PLAINTEXT-7f3a\n";
const ISOLATED: &str = "DB_PASSWORD=ISOLATED-PLAINTEXT-91c2\n";

/// A project with a public file, a cloaked file and an isolated `.env`,
/// tagged `main`.
fn project() -> (Repo, Arc<MemoryBackend>, ObjectId) {
    let (mut r, fs, _) = new_repo("alice");
    let c1 = commit_files(
        &mut r,
        &*fs,
        &[
            (".veilpolicy", POLICY),
            ("README.md", "hello\n"),
            ("secrets/key.txt", CLOAKED),
            (".env", ISOLATED),
        ],
        "first",
    );
    r.set_tag("main", c1, None, false).unwrap();
    (r, fs, c1)
}

fn tag(repo: &Repo, name: &str) -> ObjectId {
    repo.view().tags[name].target
}

// ---- visibility ------------------------------------------------------------------

#[test]
fn git_sees_only_what_a_public_remote_sees() {
    let env = Env::new();
    let (mut r, _fs, c1) = project();
    // A cloaked line of work on top: its files and description are sealed.
    r.create_workspace("priv", vec![c1], Some("team".into())).unwrap();
    let ov = r.workspace_overlay("priv").unwrap();
    ov.write(&p("plan.md"), b"CLOAKED-LINE-FILE-55aa\n").unwrap();
    let out = r.snapshot_workspace("priv", &ov).unwrap();
    let c2 = r.describe(out.snapshot, "CLOAKED-DESCRIPTION-0b1d").unwrap();
    r.set_tag("main", c2, None, false).unwrap();
    // `a` and `a/b` cannot both be Git branches: one is skipped, not fatal.
    r.set_tag("a", c1, None, false).unwrap();
    r.set_tag("a/b", c1, None, false).unwrap();
    // A cloaked tag is never exported.
    r.set_tag("secret-tag", c1, Some("team".into()), false).unwrap();

    env.connect(&mut r);
    let rep = env.push(&mut r);
    assert!(rep.export.skipped.iter().any(|(t, _)| t == "secret-tag"), "{:?}", rep.export.skipped);
    assert!(rep.export.skipped.iter().any(|(t, _)| t == "a/b"), "{:?}", rep.export.skipped);
    assert!(rep.outcome.refs.contains(&("main".to_string(), RefStatus::Created)));

    for dir in [&env.bare, &env.bridge] {
        let objects = all_git_objects(dir);
        for needle in [
            CLOAKED.trim(),
            "ISOLATED-PLAINTEXT-91c2",
            "CLOAKED-LINE-FILE-55aa",
            "CLOAKED-DESCRIPTION-0b1d",
            "plan.md",
        ] {
            assert!(!contains(&objects, needle.as_bytes()), "{needle} reached {}", dir.display());
        }
        assert!(contains(&objects, b"hello\n"));
        assert!(contains(&objects, b"(description withheld: cloaked)"));
    }
    let refs = git(&env.bare, &["for-each-ref", "--format=%(refname)"]);
    assert_eq!(refs, "refs/heads/a\nrefs/heads/main");
    let files = git(&env.bare, &["ls-tree", "-r", "--name-only", "main"]);
    assert_eq!(files.lines().collect::<Vec<_>>(), vec![".veilpolicy", "README.md"]);
}

#[test]
fn export_is_deterministic_and_carries_the_change_id() {
    let env = Env::new();
    let (mut r, fs, c1) = project();
    let c2 = commit_files(&mut r, &*fs, &[("src/lib.rs", "pub fn f() {}\n")], "second");
    r.set_tag("main", c2, None, false).unwrap();

    let mut b1 = GitBridge::open(&r, &env.bridge).unwrap();
    let e1 = b1.export(&mut r, &[]).unwrap();
    assert_eq!(e1.written, 2);
    let again = b1.export(&mut r, &[]).unwrap();
    assert_eq!(again.written, 0, "an exported snapshot keeps its commit");
    assert_eq!(again.branches, e1.branches);

    // A different bridge (another machine) computes the same commits.
    let other = Repo::open(r.backend().clone(), None, "bob").unwrap();
    let mut other = other;
    let elsewhere = env.tmp.path().join("other.git");
    // Without the mapping, everything is recomputed from scratch.
    let saved = r.backend().read(&p(".veil/git/map")).unwrap();
    r.backend().remove_file(&p(".veil/git/map")).unwrap();
    r.backend().remove_file(&p(".veil/git/cache")).unwrap();
    let e2 = GitBridge::open(&other, &elsewhere).unwrap().export(&mut other, &[]).unwrap();
    r.backend().write(&p(".veil/git/map"), &saved).unwrap();
    assert_eq!(e1.branches, e2.branches);

    let commit = e1.branches[0].1.to_string();
    let raw = git(&env.bridge, &["cat-file", "commit", &commit]);
    let change = r.snapshot(&c2).unwrap().change_id.display();
    assert!(raw.contains(&format!("\nchange-id {change}\n")), "{raw}");
    assert!(raw.contains("author alice <> "), "{raw}");
    let parent = git(&env.bridge, &["rev-parse", &format!("{commit}^")]);
    assert_eq!(b1.snapshot_of(&parent.parse().unwrap()), Some(c1));
    assert_eq!(b1.commit_of(&c2).unwrap().to_string(), commit);
}

#[test]
fn unreleased_embargo_exports_the_fallback_and_withholds_the_fix() {
    let env = Env::new();
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "fn check() -> bool { true }\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "fn check() -> bool { verify_signature() }\n").unwrap();
    ws.write("CVE-2026-0001.md", "details\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "FIX-DESCRIPTION-c0de").unwrap();
    drop(ws);
    let spec = EmbargoSpec {
        scope: "team".into(),
        until: None,
    };
    let res = alice.merge(WS, main, vec![fix], "MERGE-DESCRIPTION-77e1", Some(spec)).unwrap();
    let embargo = res.embargo.unwrap();
    alice.set_tag("main", res.snapshot, None, false).unwrap();
    alice.set_tag("fix", fix, None, false).unwrap();

    env.connect(&mut alice);
    let rep = env.push(&mut alice);
    assert!(rep.export.skipped.iter().any(|(t, _)| t == "fix"), "{:?}", rep.export.skipped);
    let objects = all_git_objects(&env.bare);
    for needle in ["verify_signature", "CVE-2026-0001", "FIX-DESCRIPTION-c0de", "MERGE-DESCRIPTION-77e1"] {
        assert!(!contains(&objects, needle.as_bytes()), "{needle} reached Git before the release");
    }
    let bridge = GitBridge::open(&alice, &env.bridge).unwrap();
    let v1 = bridge.commit_of(&main).unwrap().to_string();
    let merge_commit = env.remote_head("main");
    // The merge shows the pre-merge tree and only its first parent.
    assert_eq!(git(&env.bare, &["rev-parse", &format!("{merge_commit}^@")]), v1);
    assert_eq!(
        git(&env.bare, &["rev-parse", &format!("{merge_commit}^{{tree}}")]),
        git(&env.bare, &["rev-parse", &format!("{v1}^{{tree}}")])
    );
    assert!(git(&env.bare, &["log", "-1", "--format=%B", &merge_commit]).contains("under embargo"));
    drop(bridge);

    // Release: one publication commit on top, a fast-forward.
    alice.release_embargo(&embargo).unwrap();
    let rep = env.push(&mut alice);
    assert_eq!(rep.export.published, 1);
    let main_out = rep.outcome.refs.iter().find(|(b, _)| b == "main").unwrap();
    assert_eq!(main_out.1, RefStatus::FastForward);
    let published = env.remote_head("main");
    git(&env.bare, &["merge-base", "--is-ancestor", &merge_commit, &published]);
    assert!(git(&env.bare, &["show", &format!("{published}:auth.rs")]).contains("verify_signature"));
    let bridge = GitBridge::open(&alice, &env.bridge).unwrap();
    let fix_commit = bridge.commit_of(&fix).unwrap().to_string();
    assert_eq!(
        git(&env.bare, &["rev-parse", &format!("{published}^@")]),
        format!("{merge_commit}\n{fix_commit}")
    );
    assert!(git(&env.bare, &["log", "-1", "--format=%B", &published]).contains("MERGE-DESCRIPTION-77e1"));
    // The fix tag is now exported too, and nothing changes on a re-push.
    assert_eq!(git(&env.bare, &["rev-parse", "refs/heads/fix"]), fix_commit);
    let again = env.push(&mut alice);
    assert_eq!(again.export.written, 0);
}

// ---- round trips -----------------------------------------------------------------

#[test]
fn a_git_commit_on_an_export_keeps_cloaked_files() {
    let env = Env::new();
    let (mut r, _fs, c1) = project();
    env.connect(&mut r);
    env.push(&mut r);

    let work = env.clone_work("work");
    assert!(!work.join("secrets").exists() && !work.join(".env").exists());
    std::fs::write(work.join("README.md"), "hello from GitHub\n").unwrap();
    std::fs::write(work.join("new.txt"), "added in Git\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "edit on GitHub"]);
    git(&work, &["push", "-q", "origin", "main"]);

    let rep = git::pull(&mut r, &env.bridge, "github").unwrap();
    assert_eq!(rep.import.imported, 1, "{rep:?}");
    let s2 = tag(&r, "main");
    let snap = r.snapshot(&s2).unwrap();
    assert_eq!(snap.parents, vec![c1]);
    assert_eq!(snap.author, "Gita Hub <gita@example.com>");
    assert_eq!(r.description(&snap), "edit on GitHub");
    assert_eq!(read_at(&r, &s2, "secrets/key.txt"), CLOAKED.as_bytes());
    assert_eq!(
        file_entry(&r, &s2, "secrets/key.txt").unwrap(),
        file_entry(&r, &c1, "secrets/key.txt").unwrap(),
        "the cloaked entry is carried over untouched"
    );
    assert_eq!(read_at(&r, &s2, "README.md"), b"hello from GitHub\n");
    assert_eq!(read_at(&r, &s2, "new.txt"), b"added in Git\n");
    assert_eq!(r.view().remote_tags["github/main"], s2);

    // Pushing back is a no-op: the imported commit is the truth.
    let rep = env.push(&mut r);
    assert_eq!(rep.export.written, 0);
    assert_eq!(rep.outcome.refs, vec![("main".to_string(), RefStatus::UpToDate)]);
    // Fetching again imports nothing.
    assert_eq!(git::fetch(&mut r, &env.bridge, "github").unwrap().import.imported, 0);
}

#[test]
fn a_merge_made_in_git_keeps_cloaked_files() {
    let env = Env::new();
    let (mut r, _fs, c1) = project();
    env.connect(&mut r);
    env.push(&mut r);

    let work = env.clone_work("work");
    git(&work, &["checkout", "-q", "-b", "feature"]);
    std::fs::write(work.join("feature.txt"), "feature\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "feature"]);
    git(&work, &["checkout", "-q", "main"]);
    std::fs::write(work.join("README.md"), "hello, main\n").unwrap();
    git(&work, &["commit", "-q", "-am", "main edit"]);
    git(&work, &["merge", "-q", "--no-ff", "-m", "merge feature", "feature"]);
    git(&work, &["push", "-q", "origin", "main", "feature"]);

    let rep = git::pull(&mut r, &env.bridge, "github").unwrap();
    assert_eq!(rep.import.imported, 3, "{rep:?}");
    assert!(rep.import.failed.is_empty());
    let m = tag(&r, "main");
    let snap = r.snapshot(&m).unwrap();
    assert_eq!(snap.parents.len(), 2);
    assert!(snap.conflicts.is_empty());
    assert_eq!(read_at(&r, &m, "secrets/key.txt"), CLOAKED.as_bytes());
    assert_eq!(read_at(&r, &m, "feature.txt"), b"feature\n");
    assert_eq!(read_at(&r, &m, "README.md"), b"hello, main\n");
    assert!(r.is_ancestor(&c1, &m).unwrap());
    assert_eq!(read_at(&r, &tag(&r, "feature"), "secrets/key.txt"), CLOAKED.as_bytes());
}

#[test]
fn a_veil_commit_on_an_imported_one_keeps_files_veil_refused() {
    let env = Env::new();
    // A plain Git project, with a committed .env (it happens).
    let work = env.tmp.path().join("upstream");
    git(env.tmp.path(), &["init", "-q", work.to_str().unwrap()]);
    std::fs::write(work.join("a.txt"), "a\n").unwrap();
    std::fs::write(work.join(".env"), ISOLATED).unwrap();
    git(&work, &["add", "-A"]);
    Command::new("git")
        .current_dir(&work)
        .env("GIT_AUTHOR_NAME", "Ada")
        .env("GIT_AUTHOR_EMAIL", "ada@example.com")
        .env("GIT_AUTHOR_DATE", "2020-01-02T03:04:05Z")
        .env("GIT_COMMITTER_NAME", "Ada")
        .env("GIT_COMMITTER_EMAIL", "ada@example.com")
        .args(["-c", "commit.gpgsign=false", "commit", "-q", "-m", "initial"])
        .status()
        .unwrap();
    git(&work, &["push", "-q", env.url(), "HEAD:refs/heads/main"]);
    let initial = git(&work, &["rev-parse", "HEAD"]);

    let (mut r, fs, _) = new_repo("alice");
    let rep = git::import(&mut r, &env.bridge, env.url(), "github").unwrap();
    assert_eq!(rep.import.imported, 1);
    assert!(rep.import.left_in_git.contains_key(".env"), "{:?}", rep.import.left_in_git);
    let s1 = tag(&r, "main");
    let snap = r.snapshot(&s1).unwrap();
    assert_eq!(snap.author, "Ada <ada@example.com>");
    assert_eq!(snap.timestamp, 1_577_934_245_000);
    assert_eq!(r.description(&snap), "initial");
    assert!(file_entry(&r, &s1, ".env").is_none(), "isolated files never enter Veil");
    assert!(!contains(&all_objects(r.backend().as_ref()).concat_bytes(), b"ISOLATED-PLAINTEXT"));

    // Work in Veil on top, push back.
    let ws = r.ephemeral_workspace(s1).unwrap();
    ws.write("b.txt", "b\n").unwrap();
    let (s2, _) = r.commit_ephemeral(&ws, "add b").unwrap();
    drop(ws);
    r.set_tag("main", s2, None, false).unwrap();
    let rep = env.push(&mut r);
    assert_eq!(rep.outcome.refs, vec![("main".to_string(), RefStatus::FastForward)]);
    let head = env.remote_head("main");
    assert_eq!(git(&env.bare, &["rev-parse", &format!("{head}^")]), initial, "imported commits keep their ids");
    let files = git(&env.bare, &["ls-tree", "-r", "--name-only", &head]);
    assert_eq!(files.lines().collect::<Vec<_>>(), vec![".env", "a.txt", "b.txt"], "Veil does not delete what it never recorded");
    let _ = fs;
}

trait Concat {
    fn concat_bytes(&self) -> Vec<u8>;
}
impl Concat for Vec<(String, Vec<u8>)> {
    fn concat_bytes(&self) -> Vec<u8> {
        self.iter().flat_map(|(_, b)| b.clone()).collect()
    }
}

#[test]
fn a_git_force_push_is_reported_and_loses_no_veil_data() {
    let env = Env::new();
    let (mut r, fs, _) = project();
    let c2 = commit_files(&mut r, &*fs, &[("two.txt", "two\n")], "second");
    r.set_tag("main", c2, None, false).unwrap();
    env.connect(&mut r);
    env.push(&mut r);
    let pushed = env.remote_head("main");

    let work = env.clone_work("work");
    git(&work, &["reset", "-q", "--hard", "HEAD~1"]);
    std::fs::write(work.join("other.txt"), "rewritten history\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "rewrite"]);
    git(&work, &["push", "-q", "--force", "origin", "main"]);

    let rep = git::fetch(&mut r, &env.bridge, "github").unwrap();
    assert_eq!(rep.forced.len(), 1, "{rep:?}");
    assert_eq!(rep.forced[0].0, "main");
    assert_eq!(rep.forced[0].1.to_string(), pushed);
    assert_eq!(tag(&r, "main"), c2, "fetch never moves local tags");
    let theirs = r.view().remote_tags["github/main"];
    assert_eq!(read_at(&r, &theirs, "secrets/key.txt"), CLOAKED.as_bytes());

    let rep = git::pull(&mut r, &env.bridge, "github").unwrap();
    assert!(rep.warnings.iter().any(|w| w.contains("diverged")), "{:?}", rep.warnings);
    assert_eq!(tag(&r, "main"), c2);
    assert_eq!(read_at(&r, &c2, "two.txt"), b"two\n");

    // Pushing over it needs --force (with a lease on what we fetched).
    let rep = env.push(&mut r);
    assert!(matches!(rep.outcome.refs[0].1, RefStatus::Rejected(_)), "{:?}", rep.outcome);
    let rep = git::push(&mut r, &env.bridge, "github", &[], true).unwrap();
    assert_eq!(rep.outcome.refs[0].1, RefStatus::Forced);
    assert_eq!(env.remote_head("main"), pushed);
}

#[test]
fn a_git_policy_edit_cannot_declassify_cloaked_files() {
    let env = Env::new();
    let (mut r, _fs, _) = project();
    env.connect(&mut r);
    env.push(&mut r);
    let work = env.clone_work("work");
    std::fs::write(work.join(".veilpolicy"), "secrets/ public!\n").unwrap();
    git(&work, &["commit", "-q", "-am", "expose everything"]);
    git(&work, &["push", "-q", "origin", "main"]);

    let rep = git::pull(&mut r, &env.bridge, "github").unwrap();
    assert!(rep.import.warnings.iter().any(|w| w.contains("kept its policy")), "{:?}", rep.import.warnings);
    let s2 = tag(&r, "main");
    assert_eq!(read_at(&r, &s2, ".veilpolicy"), POLICY.as_bytes());
    assert_eq!(
        file_entry(&r, &s2, "secrets/key.txt").unwrap().visibility,
        Visibility::Cloaked { scope: "team".into() }
    );
}

#[test]
fn a_git_commit_on_an_embargoed_merge_is_held_back_without_the_key() {
    let env = Env::new();
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "v1\n")], "v1");
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "fixed\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    drop(ws);
    let spec = EmbargoSpec {
        scope: "team".into(),
        until: None,
    };
    let res = alice.merge(WS, main, vec![fix], "merge", Some(spec)).unwrap();
    alice.set_tag("main", res.snapshot, None, false).unwrap();
    env.connect(&mut alice);
    env.push(&mut alice);

    let work = env.clone_work("work");
    std::fs::write(work.join("notes.txt"), "added on GitHub\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "edit"]);
    git(&work, &["push", "-q", "origin", "main"]);

    // Bob shares the history but not the embargo key.
    let (mut bob, _, _) = new_repo("bob");
    veil_core::remote::pull(&mut bob, "alice", alice.backend().clone()).unwrap();
    std::fs::create_dir_all(env.tmp.path().join("bob")).unwrap();
    let bob_bridge = env.tmp.path().join("bob").join("bridge.git");
    // Seed bob's mapping by exporting what he can see (same commits).
    git::remote_add(&mut bob, "github", env.url()).unwrap();
    GitBridge::open(&bob, &bob_bridge).unwrap().export(&mut bob, &[]).unwrap();
    let rep = git::pull(&mut bob, &bob_bridge, "github").unwrap();
    assert_eq!(rep.import.failed.len(), 1, "{rep:?}");
    assert!(rep.import.failed[0].1.contains("held back"), "{:?}", rep.import.failed);

    // Alice holds the key: the edit lands on top of the fix, and the
    // result stays under the embargo (Git still sees the pre-merge file).
    let rep = git::pull(&mut alice, &env.bridge, "github").unwrap();
    assert!(rep.import.failed.is_empty(), "{rep:?}");
    let s = tag(&alice, "main");
    assert_eq!(read_at(&alice, &s, "auth.rs"), b"fixed\n");
    assert_eq!(read_at(&alice, &s, "notes.txt"), b"added on GitHub\n");
    let tree = alice.snapshot(&s).unwrap().tree;
    assert!(veil_core::embargo::unreleased_wrapper(alice.store(), &tree).unwrap().is_some());
    assert_eq!(env.push(&mut alice).export.written, 0);
    assert!(!contains(&all_git_objects(&env.bare), b"fixed\n"));
}

/// BUG-200: a Git commit that adds a Veil repository's directory (its
/// `.veil/` included) is imported without it: nothing in a nested
/// repository is recorded, whichever route it comes by.
#[test]
fn a_nested_veil_repository_in_a_git_commit_is_not_imported() {
    let env = Env::new();
    let (mut r, _fs, _) = project();
    env.connect(&mut r);
    env.push(&mut r);
    let work = env.clone_work("work");
    std::fs::create_dir_all(work.join("vendor/lib/.veil")).unwrap();
    std::fs::write(work.join("vendor/lib/.veil/repo.json"), "{}\n").unwrap();
    std::fs::write(work.join("vendor/lib/plan.txt"), "NESTED-PLAINTEXT\n").unwrap();
    std::fs::write(work.join("new.txt"), "added in Git\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "vendor a library"]);
    git(&work, &["push", "-q", "origin", "main"]);

    git::pull(&mut r, &env.bridge, "github").unwrap();
    let s2 = tag(&r, "main");
    assert_eq!(read_at(&r, &s2, "new.txt"), b"added in Git\n");
    assert!(file_entry(&r, &s2, "vendor/lib/plan.txt").is_none(), "a nested repository's file was imported");
    assert!(file_entry(&r, &s2, "vendor").is_none());
}

/// BUG-121 (the Git route): a Git commit whose `.veilpolicy` is a
/// directory is refused with the reason, as a symlinked one is (BUG-058):
/// the pull itself goes ahead, and nothing of that commit is recorded.
#[test]
fn a_git_commit_whose_policy_is_a_directory_is_refused_with_the_reason() {
    let env = Env::new();
    let (mut r, _fs, c1) = project();
    env.connect(&mut r);
    env.push(&mut r);
    let work = env.clone_work("work");
    git(&work, &["rm", "-q", ".veilpolicy"]);
    std::fs::create_dir_all(work.join(".veilpolicy")).unwrap();
    std::fs::write(work.join(".veilpolicy/rules"), "** public!\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "policy as a directory"]);
    git(&work, &["push", "-q", "origin", "main"]);

    let rep = git::pull(&mut r, &env.bridge, "github").expect("the pull is blocked");
    assert_eq!(tag(&r, "main"), c1);
    assert!(format!("{rep:?}").contains(".veilpolicy"), "{rep:?}");
}

// ---- first-class conflicts (format 4) ----------------------------------------------

/// Two lines editing the same line of `notes.md` from `c1`: one public,
/// one on a line cloaked under `team` (when `cloaked`). Their merge (`vl
/// new A B`) holds a conflict entry; tagged `main`.
fn conflicted_main(cloaked: bool) -> (Repo, ObjectId) {
    let (mut r, fs, c1) = project();
    fs.write(&p("notes.md"), b"intro\nline\noutro\n").unwrap();
    let c1b = commit_files(&mut r, &*fs, &[], "notes");
    let _ = c1;
    r.create_workspace("pub", vec![c1b], None).unwrap();
    let o = r.workspace_overlay("pub").unwrap();
    o.write(&p("notes.md"), b"intro\nPUBLIC-SIDE-LINE\noutro\n").unwrap();
    let a = r.snapshot_workspace("pub", &o).unwrap().snapshot;
    r.create_workspace("priv", vec![c1b], cloaked.then(|| "team".to_string())).unwrap();
    let o = r.workspace_overlay("priv").unwrap();
    o.write(&p("notes.md"), b"intro\nCLOAKED-SIDE-LINE-3e1f\noutro\n").unwrap();
    let b = r.snapshot_workspace("priv", &o).unwrap().snapshot;
    r.new_change(WS, vec![a, b], "").unwrap();
    let m = r.workspace_wc(WS).unwrap();
    let e = file_entry(&r, &m, "notes.md").unwrap();
    assert_eq!(e.kind, veil_core::EntryKind::Conflict);
    r.set_tag("main", m, None, true).unwrap();
    (r, m)
}

/// Git sees a conflict as the marker file a public reader is shown: the
/// public side, and a "not shown" line for the side sealed for `team`,
/// whose text never reaches Git.
#[test]
fn a_conflict_exports_as_its_public_markers_without_the_sealed_side() {
    let env = Env::new();
    let (mut r, _) = conflicted_main(true);
    env.connect(&mut r);
    env.push(&mut r);
    for dir in [&env.bare, &env.bridge] {
        let objects = all_git_objects(dir);
        assert!(!contains(&objects, b"CLOAKED-SIDE-LINE-3e1f"), "the sealed side reached {}", dir.display());
    }
    let shown = git(&env.bare, &["show", "main:notes.md"]);
    assert!(shown.contains("<<<<<<<") && shown.contains("PUBLIC-SIDE-LINE"), "{shown}");
    assert!(shown.contains("not shown: this version is not public"), "{shown}");
}

/// A Git commit resolving the exported marker file (every side was public,
/// so Git saw all of it) imports as the resolution of the conflict.
#[test]
fn a_git_resolution_of_an_exported_conflict_resolves_it() {
    let env = Env::new();
    let (mut r, m) = conflicted_main(false);
    env.connect(&mut r);
    env.push(&mut r);
    let work = env.clone_work("work");
    let shown = std::fs::read_to_string(work.join("notes.md")).unwrap();
    assert!(shown.contains("PUBLIC-SIDE-LINE") && shown.contains("CLOAKED-SIDE-LINE-3e1f"), "{shown}");
    std::fs::write(work.join("notes.md"), "intro\nresolved on GitHub\noutro\n").unwrap();
    git(&work, &["commit", "-q", "-am", "resolve"]);
    git(&work, &["push", "-q", "origin", "main"]);
    let rep = git::pull(&mut r, &env.bridge, "github").unwrap();
    assert_eq!(rep.import.imported, 1, "{rep:?}");
    let s = tag(&r, "main");
    assert_eq!(r.snapshot(&s).unwrap().parents, vec![m]);
    let e = file_entry(&r, &s, "notes.md").unwrap();
    assert_eq!(e.kind, veil_core::EntryKind::File, "the conflict is resolved, not widened");
    assert_eq!(read_at(&r, &s, "notes.md"), b"intro\nresolved on GitHub\noutro\n");
    assert!(r.snapshot(&s).unwrap().conflicts.is_empty());
}
