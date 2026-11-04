//! Round 3 adversarial tests: the Git bridge (`vl git …`) end to end, with
//! plain `git` playing a hostile GitHub. Offline: the "GitHub" is a local
//! bare repository, and hostile objects are written with
//! `git hash-object --literally`.

mod adversarial_support;

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use adversarial_support::{text, write, Env};

const U: &str = "alice";

/// Run plain `git` with a neutral identity and no system configuration.
fn git(dir: &Path, args: &[&str]) -> String {
    let out = git_cmd(dir).args(args).output().unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn git_cmd(dir: &Path) -> Command {
    let mut c = Command::new("git");
    c.current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Mallory")
        .env("GIT_AUTHOR_EMAIL", "mallory@example.com")
        .env("GIT_COMMITTER_NAME", "Mallory")
        .env("GIT_COMMITTER_EMAIL", "mallory@example.com")
        .args(["-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false"]);
    c
}

/// Write `data` as an object of `kind` without any validation.
fn literal(bare: &Path, kind: &str, data: &[u8]) -> String {
    let mut child = git_cmd(bare)
        .args(["hash-object", "-t", kind, "--literally", "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(data).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// A raw tree from `(mode, name, oid)` entries, in the order given.
fn raw_tree(bare: &Path, entries: &[(&str, &[u8], &str)]) -> String {
    let mut data = Vec::new();
    for (mode, name, oid) in entries {
        data.extend_from_slice(mode.as_bytes());
        data.push(b' ');
        data.extend_from_slice(name);
        data.push(0);
        data.extend_from_slice(&hex::decode(oid).unwrap());
    }
    literal(bare, "tree", &data)
}

fn blob(bare: &Path, data: &str) -> String {
    literal(bare, "blob", data.as_bytes())
}

fn commit_tree(bare: &Path, tree: &str, parents: &[&str], msg: &str) -> String {
    let mut args = vec!["commit-tree", tree, "-m", msg];
    for p in parents {
        args.push("-p");
        args.push(p);
    }
    git(bare, &args)
}

fn all_git_objects(bare: &Path) -> Vec<u8> {
    git_cmd(bare)
        .args(["cat-file", "--batch-all-objects", "--batch"])
        .output()
        .unwrap()
        .stdout
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// A Veil project with one commit tagged `main`, exported to a fresh bare
/// "GitHub" repository as remote `origin`.
fn exported_project(env: &Env, files: &[(&str, &str)]) -> (PathBuf, PathBuf) {
    let bare = env.root.join("github.git");
    git(&env.root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    let proj = env.project(U, "proj", files);
    env.ok(U, &proj, &["git", "remote", "add", "origin", bare.to_str().unwrap()]);
    env.ok(U, &proj, &["git", "push"]);
    (proj, bare)
}

/// A clone of the bare repository's `main`, to commit on "GitHub".
fn github_clone(env: &Env, bare: &Path, name: &str) -> PathBuf {
    let work = env.root.join(name);
    git(&env.root, &["clone", "-q", "-b", "main", bare.to_str().unwrap(), work.to_str().unwrap()]);
    work
}

// ---- BUG-057: a Git-side policy edit publishes isolated files to GitHub ----------

/// A GitHub contributor appends `.env public!` to `.veilpolicy`. The import
/// takes it silently (`guard_policy` only looks at files that are already
/// sealed; isolated files never are), the next snapshot records the local
/// `.env` in plaintext, and the next `vl git push` uploads it to GitHub.
#[test]
fn a_github_policy_edit_cannot_exfiltrate_the_local_dotenv() {
    let env = Env::new();
    let (proj, bare) = exported_project(&env, &[("app.txt", "v1\n")]);
    write(&proj, ".env", "LOCAL_ONLY_CUSTOMER_EXPORT=acme-7731\n");
    env.ok(U, &proj, &["status"]);

    let work = github_clone(&env, &bare, "work");
    let mut policy = std::fs::read_to_string(work.join(".veilpolicy")).unwrap();
    policy.push_str("\n.env public!\n");
    std::fs::write(work.join(".veilpolicy"), policy).unwrap();
    write(&work, "app.txt", "v1 plus a typo fix\n");
    git(&work, &["commit", "-qam", "Fix a typo"]);
    git(&work, &["push", "-q", "origin", "main"]);

    // Alice pulls the contribution, keeps working, and pushes.
    let pulled = env.ok(U, &proj, &["git", "pull"]);
    env.ok(U, &proj, &["new", "main"]);
    write(&proj, "app.txt", "v2\n");
    env.ok(U, &proj, &["commit", "-m", "v2"]);
    env.ok(U, &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok(U, &proj, &["git", "push"]);

    let objects = all_git_objects(&bare);
    assert!(
        !contains(&objects, "acme-7731"),
        "the isolated .env reached GitHub; the pull said only:\n{pulled}"
    );
}

/// Control: an edit that would un-cloak an already cloaked file is refused
/// (this is what `guard_policy` does check).
#[test]
fn control_a_github_policy_edit_cannot_uncloak_a_sealed_file() {
    let env = Env::new();
    let (proj, bare) = exported_project(&env, &[("app.txt", "v1\n")]);
    env.ok(U, &proj, &["cloak", "secrets/"]);
    write(&proj, "secrets/token.txt", "CLOAKED-TOKEN-5150\n");
    env.ok(U, &proj, &["commit", "-m", "cloaked"]);
    env.ok(U, &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok(U, &proj, &["git", "push"]);

    let work = github_clone(&env, &bare, "work");
    let mut policy = std::fs::read_to_string(work.join(".veilpolicy")).unwrap();
    policy.push_str("\nsecrets/ public!\n");
    std::fs::write(work.join(".veilpolicy"), policy).unwrap();
    git(&work, &["commit", "-qam", "open up"]);
    git(&work, &["push", "-q", "origin", "main"]);

    let out = env.ok(U, &proj, &["git", "pull"]);
    assert!(out.contains("Veil kept its policy"), "{out}");
    env.ok(U, &proj, &["new", "main"]);
    env.ok(U, &proj, &["commit", "-m", "more"]);
    env.ok(U, &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok(U, &proj, &["git", "push"]);
    assert!(!contains(&all_git_objects(&bare), "CLOAKED-TOKEN-5150"));
}

// ---- BUG-058: one hostile branch blocks every fetch ----------------------------------

/// A branch whose tree holds `.veilpolicy` as a symlink (or nested deeper
/// than Veil accepts) makes the whole `vl git fetch` fail: no other branch
/// is imported, and the error does not say which branch or commit. Anyone
/// who can push a branch to the GitHub repository can stop every Veil
/// user's fetch. Policy errors are isolated per commit (`import_tips`);
/// any other error aborts the import.
#[test]
fn a_hostile_branch_does_not_block_importing_the_other_branches() {
    let env = Env::new();
    let (proj, bare) = exported_project(&env, &[("app.txt", "v1\n")]);
    let work = github_clone(&env, &bare, "work");
    write(&work, "app.txt", "v2 from GitHub\n");
    git(&work, &["commit", "-qam", "v2"]);
    git(&work, &["push", "-q", "origin", "main"]);

    let b = blob(&bare, "anything\n");
    let tree = raw_tree(&bare, &[("120000", b".veilpolicy", &b), ("100644", b"x.txt", &b)]);
    let evil = commit_tree(&bare, &tree, &[], "symlinked policy");
    git(&bare, &["update-ref", "refs/heads/zz-evil", &evil]);

    let out = env.vl(U, &proj, &["git", "fetch"]);
    let t = text(&out);
    assert!(out.status.success(), "fetch failed because of one hostile branch:\n{t}");
    assert_eq!(env.stdout(U, &proj, &["cat", "app.txt", "-r", "origin/main"]), "v2 from GitHub\n");
}

/// Control: a tree deeper than `MAX_TREE_DEPTH` is cut off by the builder
/// (reported, not fatal), so it does not block the other branches.
#[test]
fn control_a_too_deep_branch_does_not_block_importing_the_other_branches() {
    let env = Env::new();
    let (proj, bare) = exported_project(&env, &[("app.txt", "v1\n")]);
    let work = github_clone(&env, &bare, "work");
    write(&work, "app.txt", "v2 from GitHub\n");
    git(&work, &["commit", "-qam", "v2"]);
    git(&work, &["push", "-q", "origin", "main"]);

    let b = blob(&bare, "deep\n");
    let mut t = raw_tree(&bare, &[("100644", b"leaf", &b)]);
    for _ in 0..1100 {
        t = raw_tree(&bare, &[("40000", b"d", &t)]);
    }
    let evil = commit_tree(&bare, &t, &[], "deep");
    git(&bare, &["update-ref", "refs/heads/zz-deep", &evil]);

    let out = env.vl(U, &proj, &["git", "fetch"]);
    assert!(adversarial_support::exited_cleanly(&out), "{}", text(&out));
    assert!(out.status.success(), "fetch failed because of one hostile branch:\n{}", text(&out));
    assert_eq!(env.stdout(U, &proj, &["cat", "app.txt", "-r", "origin/main"]), "v2 from GitHub\n");
}

// ---- BUG-060: a failed fetch loses the deletion of a branch -------------------------

/// `transport::fetch` prunes the bridge's tracking refs before the import
/// runs; when the import then fails, the Veil transaction (which removes the
/// `<remote>/<branch>` tags of deleted branches) is never committed, and the
/// next fetch no longer sees the branch as deleted. The stale remote tag
/// stays forever.
#[test]
fn a_branch_deleted_during_a_failed_fetch_loses_its_remote_tag() {
    let env = Env::new();
    let (proj, bare) = exported_project(&env, &[("app.txt", "v1\n")]);
    let main = git(&bare, &["rev-parse", "main"]);
    git(&bare, &["update-ref", "refs/heads/feature", &main]);
    env.ok(U, &proj, &["git", "fetch"]);
    assert!(env.stdout(U, &proj, &["tag", "list"]).contains("origin/feature"));

    // `feature` is deleted while a hostile branch makes the fetch fail …
    git(&bare, &["update-ref", "-d", "refs/heads/feature"]);
    let b = blob(&bare, "x\n");
    let tree = raw_tree(&bare, &[("120000", b".veilpolicy", &b)]);
    let evil = commit_tree(&bare, &tree, &[], "symlinked policy");
    git(&bare, &["update-ref", "refs/heads/evil", &evil]);
    let _ = env.vl(U, &proj, &["git", "fetch"]);
    // … then the hostile branch goes away and fetching works again.
    git(&bare, &["update-ref", "-d", "refs/heads/evil"]);
    env.ok(U, &proj, &["git", "fetch"]);

    let tags = env.stdout(U, &proj, &["tag", "list"]);
    assert!(!tags.contains("origin/feature"), "stale remote tag kept:\n{tags}");
}

// ---- BUG-059: GitHub can hijack the names of the user's changes ----------------------

/// Exported commits carry the full change id (`change-id` header). A
/// branch named after it becomes a local tag on `vl git pull`, and tags win
/// over change ids in revsets: `vl new <change>` then checks out the
/// attacker's commit.
#[test]
fn a_branch_named_after_a_change_id_does_not_hijack_it() {
    let env = Env::new();
    let (proj, bare) = exported_project(&env, &[("app.txt", "alice's work\n")]);
    let raw = git(&bare, &["cat-file", "commit", "main"]);
    let cid = raw
        .lines()
        .find_map(|l| l.strip_prefix("change-id "))
        .expect("exported commits carry a change id")
        .to_string();
    let short = &cid[..8];

    let b = blob(&bare, "mallory's payload\n");
    let tree = raw_tree(&bare, &[("100644", b"app.txt", &b)]);
    let evil = commit_tree(&bare, &tree, &[], "innocent");
    git(&bare, &["update-ref", &format!("refs/heads/{short}"), &evil]);
    env.ok(U, &proj, &["git", "pull"]);

    env.ok(U, &proj, &["new", short]);
    assert_eq!(
        std::fs::read_to_string(proj.join("app.txt")).unwrap(),
        "alice's work\n",
        "`vl new {short}` checked out the Git branch named {short}, not the change"
    );
}

/// A commit made on GitHub with a forged `change-id` header equal to an
/// exported change makes that change divergent: the user can no longer
/// address their own change by id.
#[test]
fn a_forged_change_id_header_does_not_break_the_users_change_id() {
    let env = Env::new();
    let (proj, bare) = exported_project(&env, &[("app.txt", "alice's work\n")]);
    let raw = git(&bare, &["cat-file", "commit", "main"]);
    let cid = raw.lines().find_map(|l| l.strip_prefix("change-id ")).unwrap().to_string();
    let tree = git(&bare, &["rev-parse", "main^{tree}"]);
    let forged = format!(
        "tree {tree}\nauthor Mallory <m@example.com> 1 +0000\ncommitter Mallory <m@example.com> 1 +0000\nchange-id {cid}\n\nforged\n"
    );
    let evil = literal(&bare, "commit", forged.as_bytes());
    git(&bare, &["update-ref", "refs/heads/other", &evil]);
    env.ok(U, &proj, &["git", "fetch"]);

    let out = env.vl(U, &proj, &["new", &cid[..8]]);
    assert!(out.status.success(), "{}", text(&out));
}

// ---- BUG-061: credentials in Git URLs are echoed ---------------------------------------

/// `git` itself redacts `user:password@` in its messages; Veil's own error
/// (`transport.rs` "git fetch from {url} failed") prints the token.
#[test]
fn credentials_in_a_git_url_are_not_printed_in_errors() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    env.ok(U, &proj, &["git", "remote", "add", "gh", "https://bob:ghp_S3CRETTOKEN@127.0.0.1:9/x.git"]);
    for args in [&["git", "fetch", "gh"][..], &["git", "push", "gh"][..]] {
        let out = env.vl(U, &proj, args);
        assert!(!out.status.success());
        let t = text(&out);
        assert!(!t.contains("ghp_S3CRETTOKEN"), "vl {args:?} printed the token:\n{t}");
    }
}

// ---- BUG-062: relative Git remote URLs follow the current directory ------------------

/// `vl git remote add origin ../github.git` stores the path as typed, and
/// `git` resolves it against the directory `vl` runs in. From a
/// subdirectory of the project, `vl git push` writes to another repository.
#[test]
fn a_relative_git_remote_is_the_same_repository_from_a_subdirectory() {
    let env = Env::new();
    let bare = env.root.join("github.git");
    git(&env.root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    env.ok(U, &proj, &["git", "remote", "add", "origin", "../github.git"]);
    let sub = proj.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    // What `../github.git` means from `proj/sub`.
    let decoy = proj.join("github.git");
    git(&env.root, &["init", "-q", "--bare", decoy.to_str().unwrap()]);
    env.ok(U, &sub, &["git", "push"]);
    let branches = git(&bare, &["branch", "--list"]);
    assert!(branches.contains("main"), "main went to {} instead of {}", decoy.display(), bare.display());
}

// ---- controls: hostile tree names never reach the working copy ------------------------

/// `.veil`, `.VEIL`, `..` and `.Git` from Git are not recorded and not
/// checked out; nothing is written into `.veil/`. Symlinks and gitlinks
/// are recorded as such (format 5), never as files.
#[test]
fn control_hostile_git_tree_names_are_not_checked_out() {
    let env = Env::new();
    let bare = env.root.join("gh.git");
    git(&env.root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    let b = blob(&bare, "hostile\n");
    let inner = raw_tree(&bare, &[("100644", b"op_head", &b)]);
    let tree = raw_tree(
        &bare,
        &[
            ("40000", b".veil", &inner),
            ("40000", b".VEIL", &inner),
            ("100644", b"..", &b),
            ("40000", b".Git", &inner),
            ("120000", b"link", &b),
            ("160000", b"sub", &b),
            ("100644", b"ok.txt", &b),
            ("107777", b"weird", &b),
        ],
    );
    let c = commit_tree(&bare, &tree, &[], "hostile tree");
    git(&bare, &["update-ref", "refs/heads/main", &c]);
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    let out = env.ok(U, &proj, &["git", "import", bare.to_str().unwrap()]);
    for name in [".veil", ".VEIL", "..", ".Git"] {
        assert!(out.contains(&format!("not recorded {name} ")), "{name}: {out}");
    }
    assert!(!proj.join("link").is_file() && !proj.join("sub").is_file(), "a link was written as a file");
    assert!(proj.join("ok.txt").exists());
    assert!(!proj.join(".VEIL").exists());
    assert!(!proj.join(".veil/op_head").exists() || std::fs::read(proj.join(".veil/op_head")).unwrap() != b"hostile\n");
    env.ok(U, &proj, &["status"]);
}

// ---- follow-ups to the round 3 fixes ---------------------------------------------------

/// BUG-060, the other way in: `git fetch` itself prunes the deleted
/// branch's tracking ref and *then* fails (here a `git` that exits 1 after
/// fetching). Deletions are computed from the remote tags Veil recorded,
/// not from the bridge's refs, so the next fetch still removes the tag.
#[cfg(unix)]
#[test]
fn a_branch_deleted_while_git_fetch_fails_loses_its_remote_tag() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    let (proj, bare) = exported_project(&env, &[("app.txt", "v1\n")]);
    let main = git(&bare, &["rev-parse", "main"]);
    git(&bare, &["update-ref", "refs/heads/feature", &main]);
    env.ok(U, &proj, &["git", "fetch"]);
    assert!(env.stdout(U, &proj, &["tag", "list"]).contains("origin/feature"));

    git(&bare, &["update-ref", "-d", "refs/heads/feature"]);
    let failing = env.root.join("failing-git");
    std::fs::write(&failing, "#!/bin/sh\ngit \"$@\"\necho 'fatal: the network went away' >&2\nexit 1\n").unwrap();
    std::fs::set_permissions(&failing, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = env.cmd(U, &proj, &["git", "fetch"]).env("VEIL_GIT", &failing).output().unwrap();
    assert!(!out.status.success(), "{}", text(&out));

    let out = env.ok(U, &proj, &["git", "fetch"]);
    assert!(out.contains("feature was deleted"), "{out}");
    let tags = env.stdout(U, &proj, &["tag", "list"]);
    assert!(!tags.contains("origin/feature"), "stale remote tag kept:\n{tags}");
}

/// BUG-058: the warning names the branch and the reason.
#[test]
fn a_hostile_branch_is_named_with_the_reason() {
    let env = Env::new();
    let (proj, bare) = exported_project(&env, &[("app.txt", "v1\n")]);
    let b = blob(&bare, "anything\n");
    let tree = raw_tree(&bare, &[("120000", b".veilpolicy", &b)]);
    let evil = commit_tree(&bare, &tree, &[], "symlinked policy");
    git(&bare, &["update-ref", "refs/heads/zz-evil", &evil]);
    let out = env.ok(U, &proj, &["git", "pull"]);
    assert!(out.contains("zz-evil") && out.contains(".veilpolicy is not a regular file"), "{out}");
    assert!(!env.stdout(U, &proj, &["tag", "list"]).contains("zz-evil"));
}

/// BUG-061: `vl git remote add` and `list` do not print the token either.
#[test]
fn credentials_in_a_git_url_are_not_listed() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    let added = env.ok(U, &proj, &["git", "remote", "add", "gh", "https://bob:ghp_S3CRETTOKEN@127.0.0.1:9/x.git"]);
    let listed = env.ok(U, &proj, &["git", "remote", "list"]);
    for t in [&added, &listed] {
        assert!(!t.contains("ghp_S3CRETTOKEN"), "{t}");
    }
    assert!(listed.contains("https://***@127.0.0.1:9/x.git"), "{listed}");
}

/// Round 3 hypothesis: HFS+ spellings of `.git` (an ignorable code point
/// inside it) are refused like `.git` itself, both ways. On a macOS
/// filesystem `.g\u{200C}it` *is* `.git`: a colocated working copy would
/// take what GitHub put there as its repository.
#[test]
fn hfs_spellings_of_dot_git_are_refused_both_ways() {
    let env = Env::new();
    let spelling = ".g\u{200C}it";
    // Veil → Git: not exported.
    let (proj, bare) = exported_project(&env, &[("app.txt", "v1\n")]);
    write(&proj, &format!("{spelling}/config"), "[core]\n\tfsmonitor = evil\n");
    // VCS metadata is never recorded (BUG-076), HFS+ spellings included…
    env.ok(U, &proj, &["commit", "-m", "hfs"]);
    let files = env.stdout(U, &proj, &["files", "-r", "@-"]);
    assert!(!files.contains("config"), "{files}");
    // …unless a `public!` rule names it; then the export still refuses it.
    let policy = std::fs::read_to_string(proj.join(".veilpolicy")).unwrap_or_default();
    write(&proj, ".veilpolicy", &format!("{policy}{spelling}/ public!\n"));
    env.ok(U, &proj, &["commit", "-m", "hfs"]);
    assert!(env.stdout(U, &proj, &["files", "-r", "@-"]).contains("config"));
    env.ok(U, &proj, &["tag", "set", "main", "-r", "@-"]);
    let out = env.ok(U, &proj, &["git", "push"]);
    assert!(out.contains("cannot be represented in Git"), "{out}");
    let names = git(&bare, &["ls-tree", "-r", "--name-only", "-z", "main"]);
    assert!(!names.contains("config"), "{names:?}");

    // Git → Veil: not recorded, not checked out.
    let gh = env.root.join("gh.git");
    git(&env.root, &["init", "-q", "--bare", gh.to_str().unwrap()]);
    let b = blob(&gh, "hostile\n");
    let inner = raw_tree(&gh, &[("100644", b"config", &b)]);
    let mut entries: Vec<(&str, &[u8], &str)> = vec![("40000", spelling.as_bytes(), &inner), ("100644", b"ok.txt", &b)];
    entries.sort_by(|a, b| a.1.cmp(b.1));
    let tree = raw_tree(&gh, &entries);
    let c = commit_tree(&gh, &tree, &[], "hfs");
    git(&gh, &["update-ref", "refs/heads/main", &c]);
    let other = env.dir("other");
    env.ok(U, &other, &["init"]);
    let out = env.ok(U, &other, &["git", "import", gh.to_str().unwrap()]);
    assert!(out.contains("not recorded"), "{out}");
    assert!(other.join("ok.txt").exists());
    assert!(!other.join(spelling).exists());
}
