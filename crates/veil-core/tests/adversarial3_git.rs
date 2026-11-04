//! Round 3 adversarial tests: the Git bridge at the library level (export
//! projection, carry-over, import merging, embargo releases). Every "GitHub"
//! is a local bare repository driven with plain `git`.

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
    git::{self, GitBridge},
    MemoryBackend, ObjectId, Repo, StorageBackend,
};

// ---- helpers -------------------------------------------------------------------

pub fn git_bytes(dir: &Path, args: &[&str]) -> Vec<u8> {
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
    assert!(out.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    out.stdout
}

pub fn git(dir: &Path, args: &[&str]) -> String {
    String::from_utf8(git_bytes(dir, args)).unwrap().trim().to_string()
}

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

pub fn all_git_objects(git_dir: &Path) -> Vec<u8> {
    git_bytes(git_dir, &["cat-file", "--batch-all-objects", "--batch"])
}

pub struct Env {
    pub tmp: tempfile::TempDir,
    pub bare: PathBuf,
    pub bridge: PathBuf,
}

impl Default for Env {
    fn default() -> Self {
        Self::new()
    }
}

impl Env {
    pub fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let bare = tmp.path().join("remote.git");
        git(tmp.path(), &["init", "--bare", "-q", bare.to_str().unwrap()]);
        let bridge = tmp.path().join("bridge.git");
        Env { tmp, bare, bridge }
    }
    pub fn url(&self) -> &str {
        self.bare.to_str().unwrap()
    }
    pub fn clone_work(&self, name: &str) -> PathBuf {
        let work = self.tmp.path().join(name);
        if work.exists() {
            git(&work, &["pull", "-q", "--ff-only", "origin", "main"]);
            return work;
        }
        git(self.tmp.path(), &["clone", "-q", "-b", "main", self.url(), work.to_str().unwrap()]);
        work
    }
    pub fn connect(&self, repo: &mut Repo) {
        git::remote_add(repo, "github", self.url()).unwrap();
    }
    pub fn push(&self, repo: &mut Repo) -> git::PushReport {
        git::push(repo, &self.bridge, "github", &[], false).unwrap()
    }
    pub fn pull(&self, repo: &mut Repo) -> git::FetchReport {
        git::pull(repo, &self.bridge, "github").unwrap()
    }
    pub fn show(&self, rev: &str, path: &str) -> String {
        git(&self.bare, &["show", &format!("{rev}:{path}")])
    }
}

fn tag(repo: &Repo, name: &str) -> ObjectId {
    repo.view().tags[name].target
}

/// Move the working copy onto a new change on `rev` and check it out.
fn checkout_onto(repo: &mut Repo, fs: &dyn StorageBackend, rev: ObjectId) {
    let old = repo.snapshot(&repo.workspace_wc(WS).unwrap()).unwrap().tree;
    let wc = repo.new_change(WS, vec![rev], "").unwrap();
    let to = repo.snapshot(&wc).unwrap().tree;
    repo.checkout_tree(fs, Some(&old), &to).unwrap();
}

/// `main` = v1 with a vulnerable `auth.rs`; an embargoed merge of the fix
/// on top, tagged `main` and exported.
fn embargoed_merge_exported() -> (Env, Repo, Arc<MemoryBackend>, String) {
    let env = Env::new();
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "VULNERABLE-v1\n"), ("README", "r1\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "FIXED-v2\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "the fix").unwrap();
    drop(ws);
    let spec = EmbargoSpec {
        scope: "team".into(),
        until: None,
    };
    let before = alice.snapshot(&alice.workspace_wc(WS).unwrap()).unwrap().tree;
    let res = alice.merge(WS, main, vec![fix], "merge fix", Some(spec)).unwrap();
    let embargo = res.embargo.unwrap();
    // `Repo::merge` moves the working copy onto the merge without writing
    // it; check it out, as `vl merge` does. (Left with the pre-fix file,
    // the working copy would be recorded as a revert after the release.)
    let after = alice.snapshot(&alice.workspace_wc(WS).unwrap()).unwrap().tree;
    alice.checkout_tree(&*fs, Some(&before), &after).unwrap();
    alice.set_tag("main", res.snapshot, None, false).unwrap();
    env.connect(&mut alice);
    env.push(&mut alice);
    (env, alice, fs, embargo)
}

/// Commit `files` on GitHub's `main` (clone `work`).
fn github_commit(env: &Env, files: &[(&str, &str)], msg: &str) {
    let work = env.clone_work("work");
    for (path, data) in files {
        std::fs::write(work.join(path), data).unwrap();
    }
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", msg]);
    git(&work, &["push", "-q", "origin", "main"]);
}

/// [`embargoed_merge_exported`], then someone commits on GitHub on top of
/// the (fallback-only) merge commit and the key holder pulls it.
fn embargo_with_a_github_commit_on_top() -> (Env, Repo, Arc<MemoryBackend>, String) {
    let (env, mut alice, fs, embargo) = embargoed_merge_exported();
    github_commit(&env, &[("README", "r2 from GitHub\n")], "readme on GitHub");
    let rep = env.pull(&mut alice);
    assert!(rep.import.failed.is_empty(), "{rep:?}");
    assert_eq!(read_at(&alice, &tag(&alice, "main"), "auth.rs"), b"FIXED-v2\n");
    (env, alice, fs, embargo)
}

// ---- BUG-063: an embargo release never reaches GitHub past an imported commit -----

/// After the release, Veil's `main` holds the fix, but GitHub's `main`
/// still has the vulnerable file: the imported commit on top of the
/// embargoed merge is "the truth" for its snapshot and is never
/// recomputed (`export.rs` `export_snapshot`: `cur.origin == Imported`),
/// and no publication commit is written for it.
#[test]
fn a_released_fix_reaches_github_past_a_github_commit() {
    let (env, mut alice, _fs, embargo) = embargo_with_a_github_commit_on_top();
    alice.release_embargo(&embargo).unwrap();
    let rep = env.push(&mut alice);
    assert!(rep.outcome.refs.iter().all(|(_, s)| s.accepted()), "{:?}", rep.outcome);
    assert_eq!(read_at(&alice, &tag(&alice, "main"), "auth.rs"), b"FIXED-v2\n");
    assert_eq!(
        env.show("main", "auth.rs"),
        "FIXED-v2",
        "Veil main has the released fix, GitHub main does not ({:?})",
        rep.export
    );
}

/// Worse: carry-over (`GitBridge::carry`) then treats the stale Git file as
/// "Git's version of a path Veil did not change", so even the next commit
/// made *in Veil* is exported with the vulnerable file. The import of the
/// next GitHub commit then sees "Git changed auth.rs back"; today only the
/// BUG-050 heuristic (fallback content looks like a stale working copy)
/// keeps that revert out of Veil, so the second assertion guards against
/// the fix of BUG-050 turning this into a silent revert in Veil too.
#[test]
fn a_released_fix_is_not_reverted_by_the_next_github_round_trip() {
    let (env, mut alice, fs, embargo) = embargo_with_a_github_commit_on_top();
    alice.release_embargo(&embargo).unwrap();
    env.push(&mut alice);
    // Alice keeps working on main …
    let m = tag(&alice, "main");
    checkout_onto(&mut alice, &*fs, m);
    let s3 = commit_files(&mut alice, &*fs, &[("NEWS", "released\n")], "news");
    alice.set_tag("main", s3, None, false).unwrap();
    env.push(&mut alice);
    assert_eq!(read_at(&alice, &s3, "auth.rs"), b"FIXED-v2\n");
    assert_eq!(
        env.show("main", "auth.rs"),
        "FIXED-v2",
        "a commit made in Veil, whose tree has the fix, was exported with the vulnerable file"
    );
    // … and someone edits an unrelated file on GitHub.
    let work = env.clone_work("work");
    std::fs::write(work.join("NEWS"), "released, again\n").unwrap();
    git(&work, &["commit", "-q", "-am", "news on GitHub"]);
    git(&work, &["push", "-q", "origin", "main"]);
    env.pull(&mut alice);
    assert_eq!(read_at(&alice, &tag(&alice, "main"), "auth.rs"), b"FIXED-v2\n");
}

// ---- BUG-064: losing the mapping duplicates Veil's own history on the next pull ----

/// The mapping is documented as recomputable ("export is deterministic and
/// import of the same commit yields the same snapshot"). That holds when
/// the next command is an export. When it is a pull, every commit Veil had
/// exported is unmapped, so `import_tips` imports Veil's own commits as
/// new snapshots: a second, parallel copy of the history, without the
/// cloaked files, which `github/main` now points at and `main` has
/// "diverged" from.
#[test]
fn a_lost_mapping_does_not_duplicate_history_on_pull() {
    let env = Env::new();
    let (mut alice, fs, _) = new_repo("alice");
    let c1 = commit_files(
        &mut alice,
        &*fs,
        &[(".veilpolicy", "secrets/ cloak team\n"), ("README", "r1\n"), ("secrets/k", "CLOAKED-77\n")],
        "v1",
    );
    let c2 = commit_files(&mut alice, &*fs, &[("README", "r2\n")], "v2");
    let _ = c1;
    alice.set_tag("main", c2, None, false).unwrap();
    env.connect(&mut alice);
    env.push(&mut alice);

    alice.backend().remove_file(&p(".veil/git/map")).unwrap();
    let _ = alice.backend().remove_file(&p(".veil/git/cache"));
    let rep = env.pull(&mut alice);
    assert_eq!(rep.import.imported, 0, "Veil's own exported commits were imported again: {rep:?}");
    assert_eq!(alice.view().remote_tags["github/main"], c2);
}

// ---- BUG-063, the cases around it -------------------------------------------------

/// A GitHub commit made on the exported embargoed merge *after* the release
/// but before Veil pushed it: its author saw the pre-fix file. Imported
/// against the released tree it would read as "Git reverted the fix"; it
/// is imported against the view its author saw instead.
#[test]
fn a_github_commit_on_the_stale_merge_after_the_release_does_not_revert_the_fix() {
    let (env, mut alice, _fs, embargo) = embargoed_merge_exported();
    alice.release_embargo(&embargo).unwrap();
    github_commit(&env, &[("README", "r2 from GitHub\n")], "readme, after the release");
    let rep = env.pull(&mut alice);
    assert!(rep.import.failed.is_empty(), "{rep:?}");
    let main = tag(&alice, "main");
    assert_eq!(read_at(&alice, &main, "auth.rs"), b"FIXED-v2\n", "the import reverted the fix");
    assert_eq!(read_at(&alice, &main, "README"), b"r2 from GitHub\n");
    let rep = env.push(&mut alice);
    assert!(rep.outcome.refs.iter().all(|(_, s)| s.accepted()), "{:?}", rep.outcome);
    assert_eq!(env.show("main", "auth.rs"), "FIXED-v2");
    assert_eq!(env.show("main", "README"), "r2 from GitHub");
    assert_eq!(env.push(&mut alice).export.written, 0);
}

/// The same, one level further: a GitHub commit on top of the GitHub
/// commit that sat on the merge, made after the release.
#[test]
fn a_github_commit_on_a_stale_github_commit_after_the_release_does_not_revert_the_fix() {
    let (env, mut alice, _fs, embargo) = embargo_with_a_github_commit_on_top();
    alice.release_embargo(&embargo).unwrap();
    github_commit(&env, &[("NEWS", "n1 from GitHub\n")], "news, after the release");
    let rep = env.pull(&mut alice);
    assert!(rep.import.failed.is_empty(), "{rep:?}");
    let main = tag(&alice, "main");
    assert_eq!(read_at(&alice, &main, "auth.rs"), b"FIXED-v2\n", "the import reverted the fix");
    assert_eq!(read_at(&alice, &main, "NEWS"), b"n1 from GitHub\n");
    env.push(&mut alice);
    assert_eq!(env.show("main", "auth.rs"), "FIXED-v2");
    assert_eq!(env.show("main", "NEWS"), "n1 from GitHub");
    assert_eq!(env.show("main", "README"), "r2 from GitHub");
}

/// The publication commit written for a GitHub commit applies only the
/// release: what that commit holds that Veil never recorded (a symlink)
/// stays on GitHub.
#[test]
fn publishing_past_a_github_commit_keeps_what_veil_never_recorded() {
    let (env, mut alice, _fs, embargo) = embargoed_merge_exported();
    let work = env.clone_work("work");
    std::os::unix::fs::symlink("README", work.join("link")).unwrap();
    std::fs::write(work.join("README"), "r2 from GitHub\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "a symlink"]);
    git(&work, &["push", "-q", "origin", "main"]);
    let rep = env.pull(&mut alice);
    assert!(rep.import.left_in_git.contains_key("link"), "{rep:?}");
    alice.release_embargo(&embargo).unwrap();
    let rep = env.push(&mut alice);
    assert!(rep.outcome.refs.iter().all(|(_, s)| s.accepted()), "{:?}", rep.outcome);
    assert_eq!(env.show("main", "auth.rs"), "FIXED-v2");
    let tree = git(&env.bare, &["ls-tree", "main"]);
    assert!(tree.contains("120000") && tree.contains("\tlink"), "{tree}");
}

// ---- BUG-064, the cases around it -------------------------------------------------

/// The mapping is lost after a release was published past a GitHub commit:
/// the exported merge (as pinned before the release), the publication
/// commits and the earlier import are all recognised, nothing is imported
/// twice, and a re-export writes nothing.
#[test]
fn a_lost_mapping_after_a_release_is_recomputed() {
    let (env, mut alice, _fs, embargo) = embargo_with_a_github_commit_on_top();
    alice.release_embargo(&embargo).unwrap();
    env.push(&mut alice);
    let main = tag(&alice, "main");

    alice.backend().remove_file(&p(".veil/git/map")).unwrap();
    let _ = alice.backend().remove_file(&p(".veil/git/cache"));
    let rep = env.pull(&mut alice);
    assert_eq!(rep.import.imported, 0, "{rep:?}");
    assert_eq!(alice.view().remote_tags["github/main"], main);
    let rep = env.push(&mut alice);
    assert_eq!(rep.export.written, 0, "{:?}", rep.export);
    // A GitHub commit made on the merge as pinned (pre-release view) is
    // still imported against that view.
    let work = env.tmp.path().join("late");
    let merge_commit = git(&env.bare, &["rev-parse", "main^1^1"]);
    git(env.tmp.path(), &["clone", "-q", env.url(), work.to_str().unwrap()]);
    git(&work, &["checkout", "-q", "-b", "late", &merge_commit]);
    assert_eq!(std::fs::read_to_string(work.join("auth.rs")).unwrap(), "VULNERABLE-v1\n");
    std::fs::write(work.join("LATE"), "late\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "late"]);
    git(&work, &["push", "-q", "origin", "late"]);
    let rep = env.pull(&mut alice);
    assert_eq!(rep.import.imported, 1, "{rep:?}");
    assert_eq!(read_at(&alice, &tag(&alice, "late"), "auth.rs"), b"FIXED-v2\n");
}

/// Another replica holding the same history (pulled from a Veil remote)
/// recognises the commits Veil exported to GitHub as its own snapshots,
/// without having exported anything itself.
#[test]
fn another_replica_recognises_the_exported_commits() {
    let env = Env::new();
    let (mut alice, fs, _) = new_repo("alice");
    commit_files(
        &mut alice,
        &*fs,
        &[(".veilpolicy", "secrets/ cloak team\n"), ("README", "r1\n"), ("secrets/k", "CLOAKED-77\n")],
        "v1",
    );
    let c2 = commit_files(&mut alice, &*fs, &[("README", "r2\n")], "v2");
    alice.set_tag("main", c2, None, false).unwrap();
    env.connect(&mut alice);
    env.push(&mut alice);
    github_commit(&env, &[("README", "r3 from GitHub\n")], "on GitHub");

    let (mut bob, _, _) = new_repo("bob");
    veil_core::remote::pull(&mut bob, "alice", alice.backend().clone()).unwrap();
    git::remote_add(&mut bob, "github", env.url()).unwrap();
    let bridge = env.tmp.path().join("bob.git");
    let rep = git::pull(&mut bob, &bridge, "github").unwrap();
    assert_eq!(rep.import.imported, 1, "only the GitHub commit is new: {rep:?}");
    let head = bob.view().remote_tags["github/main"];
    assert_eq!(bob.snapshot(&head).unwrap().parents, vec![c2]);
    let bb = GitBridge::open(&bob, &bridge).unwrap();
    assert!(bb.commit_of(&c2).is_some());
}

/// A Jujutsu commit's `change-id` header is still taken when it names no
/// existing change.
#[test]
fn a_change_id_header_naming_a_new_change_is_kept() {
    let env = Env::new();
    let (mut alice, fs, _) = new_repo("alice");
    let c1 = commit_files(&mut alice, &*fs, &[("README", "r1\n")], "v1");
    alice.set_tag("main", c1, None, false).unwrap();
    env.connect(&mut alice);
    env.push(&mut alice);
    let jj = "zyxwvutsrqponmlkzyxwvutsrqponmlk";
    let parent = git(&env.bare, &["rev-parse", "main"]);
    let tree = git(&env.bare, &["rev-parse", "main^{tree}"]);
    let raw = format!(
        "tree {tree}\nparent {parent}\nauthor J <j@example.com> 1 +0000\ncommitter J <j@example.com> 1 +0000\nchange-id {jj}\n\nfrom jj\n"
    );
    let path = env.tmp.path().join("raw-commit");
    std::fs::write(&path, raw).unwrap();
    let c = git(&env.bare, &["hash-object", "-t", "commit", "-w", path.to_str().unwrap()]);
    git(&env.bare, &["update-ref", "refs/heads/jj", &c]);
    env.pull(&mut alice);
    let s = alice.view().remote_tags["github/jj"];
    assert_eq!(alice.snapshot(&s).unwrap().change_id.display(), jj);
}
