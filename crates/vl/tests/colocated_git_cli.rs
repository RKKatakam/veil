//! Colocated Git mode (feature 9, stream C) through the real `vl` and
//! `git` binaries: one test per item of the design's threat review
//! (`docs/design/git-parity/9-colocated-git.md`), plus adoption, the
//! commands, and hostile inputs. Every test is offline: remotes are local
//! bare repositories.
//!
//! The core invariant, checked by most of them: the `.git` next to the
//! working copy never receives cloaked, isolated, quarantined or
//! embargo-withheld content (`objects` dumps every loose and packed
//! object), and nothing pushed from it carries any.

mod colocated_support;

use std::path::Path;

use colocated_support::*;

/// `git --version`, printed once per test run (the Git-version matrix:
/// these tests ran with whatever `git` is installed).
fn note_git_version(env: &Env) {
    eprintln!("tested with {}", env.git_ok(&env.root, &["--version"]));
}

fn cloaked_ws(env: &Env, dir: &Path) {
    env.ok(dir, &["ws", "new", "p", "-r", "main", "--cloak", "team"]);
    env.ok(dir, &["ws", "switch", "p"]);
}

// ---- 1. git add -A ------------------------------------------------------------------

#[test]
fn t01_git_add_all_never_stages_new_cloaked_or_isolated_files() {
    let env = Env::new();
    note_git_version(&env);
    let dir = env.project("p");
    // No vl command in between: the policy patterns already exclude them.
    env.write(&dir, "secrets/new.yml", "token: CLOAKMARK-new\n");
    env.write(&dir, ".env", "API=ISOMARK-env\n");
    env.write(&dir, "config/prod.pem", "ISOMARK-pem\n");
    env.write(&dir, "notes.md", "public notes\n");
    env.git_ok(&dir, &["add", "-A"]);
    env.git_ok(&dir, &["commit", "-q", "-m", "git side"]);
    let tree = env.git_ok(&dir, &["ls-tree", "-r", "--name-only", "HEAD"]);
    assert!(tree.contains("notes.md"), "{tree}");
    assert!(!tree.contains("secrets") && !tree.contains(".env") && !tree.contains("prod.pem"), "{tree}");
    assert_clean(&env, &dir.join(".git"), &["CLOAKMARK", "ISOMARK"], "after git add -A");
    // In a cloaked workspace, a new file is not added either (frozen: `*`).
    env.ok(&dir, &["status"]);
    cloaked_ws(&env, &dir);
    env.write(&dir, "plan.md", "CLOAKMARK-plan\n");
    env.git_ok(&dir, &["add", "-A"]);
    assert_eq!(env.git_ok(&dir, &["status", "--porcelain"]), "");
    assert_clean(&env, &dir.join(".git"), &["CLOAKMARK", "ISOMARK"], "after git add -A in a cloaked workspace");
}

// ---- 2. git commit -a of a line-cloaked edit -------------------------------------------

#[test]
fn t02_commit_all_of_a_line_cloaked_edit_commits_nothing() {
    let env = Env::new();
    let dir = env.project("p");
    cloaked_ws(&env, &dir);
    // No vl command after the edit: the index already hides README.md.
    env.write(&dir, "README.md", "hello\nCLOAKMARK-line\n");
    let out = env.git(&dir, &["commit", "-a", "-m", "leak?"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert_eq!(env.git_ok(&dir, &["status", "--porcelain"]), "");
    assert_eq!(env.git_ok(&dir, &["diff"]), "");
    env.ok(&dir, &["status"]);
    let out = env.git(&dir, &["commit", "-a", "-m", "leak?"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert_clean(&env, &dir.join(".git"), &["CLOAKMARK-line"], "after git commit -a");
    let st = env.ok(&dir, &["git", "colocate", "--status"]);
    assert!(st.contains("frozen"), "{st}");
}

// ---- 3. Git silently clears skip-worktree (the command matrix) --------------------------

#[test]
fn t03_git_commands_that_touch_skip_worktree_never_commit_sealed_content() {
    let env = Env::new();
    note_git_version(&env);
    // (command, clears skip-worktree): a command that clears the bit lets a
    // later `git add` / `git commit -a` hash the sealed file into a loose
    // object (local, never committed: the pre-commit guard refuses, and
    // never pushed); `vl git colocate --prune` removes it.
    let cmds: &[(&[&str], bool)] = &[
        (&["update-index", "--really-refresh"], false),
        (&["reset", "--hard"], false),
        (&["checkout", "--", "."], false),
        (&["read-tree", "-mu", "HEAD"], false),
        (&["restore", "--staged", "."], false),
        (&["stash"], false),
        (&["add", "--sparse", "README.md"], false),
        (&["update-index", "--no-skip-worktree", "README.md"], true),
        (&["sparse-checkout", "disable"], true),
    ];
    for (cmd, clears) in cmds {
        let dir = env.project(&format!("m-{}", cmd.join("-").replace(['/', '.'], "_")));
        cloaked_ws(&env, &dir);
        env.write(&dir, "README.md", "hello\nCLOAKMARK-matrix\n");
        env.ok(&dir, &["status"]);
        let _ = env.git(&dir, cmd);
        let _ = env.git(&dir, &["commit", "-a", "-m", "after"]);
        let _ = env.git(&dir, &["add", "-A"]);
        let _ = env.git(&dir, &["commit", "-m", "after add"]);
        let git = dir.join(".git");
        // Never in a commit, whatever the command.
        let log = env.git_ok(&dir, &["log", "--all", "-p", "--format=%H"]);
        assert!(!log.contains("CLOAKMARK"), "git {cmd:?}: committed:\n{log}");
        if !clears {
            assert_clean(&env, &git, &["CLOAKMARK-matrix"], &format!("git {cmd:?} then git commit -a"));
        }
        // The next vl command puts the bits back …
        env.ok(&dir, &["status"]);
        let ls = env.git_ok(&dir, &["ls-files", "-v"]);
        assert!(ls.lines().all(|l| l.starts_with('S')), "git {cmd:?}: skip-worktree not re-asserted:\n{ls}");
        assert_eq!(env.git_ok(&dir, &["status", "--porcelain"]), "", "git {cmd:?}");
        // … and --prune drops what Git hashed meanwhile.
        env.ok(&dir, &["git", "colocate", "--prune"]);
        assert_clean(&env, &git, &["CLOAKMARK-matrix"], &format!("git {cmd:?}, after --prune"));
    }
}

// ---- 4. a deliberate bypass is superseded -------------------------------------------------

#[test]
fn t04_a_forced_add_is_superseded_held_and_never_pushed() {
    let env = Env::new();
    let dir = env.project("p");
    let remote = env.bare("remote.git");
    env.ok(&dir, &["git", "remote", "add", "gh", remote.to_str().unwrap()]);
    env.write(&dir, "secrets/key.yml", "CLOAKMARK-forced\n");
    // The pre-commit guard refuses it …
    env.git_ok(&dir, &["add", "-f", "secrets/key.yml"]);
    let out = env.git(&dir, &["commit", "-m", "forced"]);
    assert!(!out.status.success(), "pre-commit let it through: {}", text(&out));
    assert!(text(&out).contains("secrets/key.yml") && !text(&out).contains("CLOAKMARK"), "{}", text(&out));
    // … so the user bypasses that too.
    env.git_ok(&dir, &["commit", "-q", "--no-verify", "-m", "forced"]);
    let held = env.git_ok(&dir, &["rev-parse", "HEAD"]);
    let st = env.ok(&dir, &["status"]);
    assert!(st.contains("held") && st.contains(&held[..10]), "{st}");
    assert!(!st.contains("CLOAKMARK"), "a message quoted sealed content: {st}");
    // The branch moved off it, to a commit without the file.
    let now = env.git_ok(&dir, &["rev-parse", "refs/heads/main"]);
    assert_ne!(now, held);
    let tree = env.git_ok(&dir, &["ls-tree", "-r", "--name-only", "main"]);
    assert!(!tree.contains("secrets"), "{tree}");
    // Veil's push sends the replacement, never the held commit.
    env.ok(&dir, &["git", "push", "gh"]);
    assert_clean(&env, &remote, &["CLOAKMARK"], "remote after vl git push");
    assert_eq!(env.git_ok(&remote, &["rev-parse", "refs/heads/main"]), now);
    // Listed until pruned.
    let s = env.ok(&dir, &["git", "colocate", "--status"]);
    assert!(s.contains(&held[..10]), "{s}");
    env.ok(&dir, &["git", "colocate", "--prune"]);
    let out = env.git(&dir, &["cat-file", "-e", &held]);
    assert!(!out.status.success(), "the held commit survived --prune");
    assert_clean(&env, &dir.join(".git"), &["CLOAKMARK-forced"], "after --prune");
}

// ---- 5. carry-over never draws from a local commit ---------------------------------------

#[test]
fn t05_later_exports_never_carry_a_local_commits_extra_paths() {
    let env = Env::new();
    let dir = env.project("p");
    let remote = env.bare("remote.git");
    env.ok(&dir, &["git", "remote", "add", "gh", remote.to_str().unwrap()]);
    env.write(&dir, ".env", "ISOMARK-carry\n");
    env.git_ok(&dir, &["add", "-f", ".env"]);
    env.git_ok(&dir, &["commit", "-q", "--no-verify", "-m", "local with .env"]);
    // A Veil commit on top: its export must not carry `.env` over from
    // the local parent.
    env.write(&dir, "more.md", "more\n");
    env.ok(&dir, &["commit", "-m", "veil on top"]);
    let tree = env.git_ok(&dir, &["ls-tree", "-r", "--name-only", "main"]);
    assert!(tree.contains("more.md") && !tree.contains(".env"), "{tree}");
    let log = env.git_ok(&dir, &["log", "--format=%s", "main"]);
    assert!(log.contains("veil on top") && log.contains("local with .env"), "{log}");
    env.ok(&dir, &["git", "push", "gh"]);
    assert_clean(&env, &remote, &["ISOMARK"], "remote after the child's export");
}

// ---- 6. git push from the colocated directory --------------------------------------------

#[test]
fn t06_a_direct_git_push_of_private_content_is_refused() {
    let env = Env::new();
    let dir = env.project("p");
    let remote = env.bare("remote.git");
    env.git_ok(&dir, &["remote", "add", "origin", remote.to_str().unwrap()]);
    // Public work pushes fine.
    env.write(&dir, "a.md", "a\n");
    env.git_ok(&dir, &["add", "a.md"]);
    env.git_ok(&dir, &["commit", "-q", "-m", "public"]);
    env.git_ok(&dir, &["push", "-q", "origin", "main"]);
    // A bypassed secret, pushed before any vl command ran.
    env.write(&dir, "secrets/x.yml", "CLOAKMARK-push\n");
    env.git_ok(&dir, &["add", "-f", "secrets/x.yml"]);
    env.git_ok(&dir, &["commit", "-q", "--no-verify", "-m", "oops"]);
    let oops = env.git_ok(&dir, &["rev-parse", "HEAD"]);
    let out = env.git(&dir, &["push", "origin", &format!("{oops}:refs/heads/main")]);
    assert!(!out.status.success(), "pre-push let it through: {}", text(&out));
    assert!(text(&out).contains("held"), "{}", text(&out));
    assert_clean(&env, &remote, &["CLOAKMARK"], "remote after a refused git push");
    // refs/stash is never pushed either.
    env.write(&dir, "a.md", "changed\n");
    env.git_ok(&dir, &["stash"]);
    let out = env.git(&dir, &["push", "origin", "refs/stash:refs/heads/st"]);
    assert!(!out.status.success(), "{}", text(&out));
    // `--no-verify` is the documented residual hole: Git skips the hook.
    let out = env.git(&dir, &["push", "--no-verify", "origin", &format!("{oops}:refs/heads/leak")]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(contains(&objects(&env, &remote), "CLOAKMARK-push"), "--no-verify is documented as a leak by explicit action");
}

// ---- 7. a Git checkout never records sealed content as public ------------------------------

#[test]
fn t07_git_checkouts_never_record_sealed_edits_as_public() {
    let env = Env::new();
    let dir = env.project("p");
    let mirror = env.dir("mirror");
    env.ok(&dir, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    env.write(&dir, "b.md", "b\n");
    env.ok(&dir, &["commit", "-m", "second"]);
    env.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
    cloaked_ws(&env, &dir);
    env.write(&dir, "README.md", "hello\nCLOAKMARK-checkout\n");
    env.ok(&dir, &["status"]);
    // Frozen: Git refuses checkouts that would change hidden files …
    assert!(!env.git(&dir, &["reset", "-q", "--hard", "HEAD~1"]).status.success());
    assert!(!env.git(&dir, &["checkout", "-q", "--detach", "HEAD~1"]).status.success());
    // … but HEAD itself can move (the index keeps its bits, the disk the
    // edit), and the working copy follows it.
    let (c2, c1) = (env.git_ok(&dir, &["rev-parse", "HEAD"]), env.git_ok(&dir, &["rev-parse", "HEAD~1"]));
    env.git_ok(&dir, &["reset", "-q", "--soft", &c1]);
    let st = env.ok(&dir, &["status"]);
    assert!(st.contains("Followed Git HEAD"), "{st}");
    env.git_ok(&dir, &["reset", "-q", "--soft", &c2]);
    env.ok(&dir, &["status"]);
    env.git_ok(&dir, &["update-ref", "--no-deref", "HEAD", &c1]);
    env.ok(&dir, &["status"]);
    // The sealed edit is still on disk and readable here …
    assert!(std::fs::read_to_string(dir.join("README.md")).unwrap().contains("CLOAKMARK-checkout"));
    // … but no public snapshot and no Git object holds it.
    env.ok(&dir, &["ws", "switch", "default"]);
    env.ok(&dir, &["push", "mirror"]);
    let pushed = std::process::Command::new("grep")
        .args(["-r", "-l", "CLOAKMARK-checkout"])
        .arg(&mirror)
        .output()
        .unwrap();
    assert!(pushed.stdout.is_empty(), "the public mirror holds the sealed edit: {}", text(&pushed));
    assert_clean(&env, &dir.join(".git"), &["CLOAKMARK"], "after following checkouts");
}

#[test]
fn t07b_hidden_edits_follow_a_branch_switch_like_unstaged_ones() {
    let env = Env::new();
    let dir = env.project("p");
    env.git_ok(&dir, &["checkout", "-q", "-b", "feature"]);
    env.write(&dir, "feat.txt", "feat\n");
    env.git_ok(&dir, &["add", "feat.txt"]);
    env.git_ok(&dir, &["commit", "-q", "-m", "feat"]);
    let st = env.ok(&dir, &["status"]);
    assert!(st.contains("Followed Git HEAD"), "{st}");
    env.write(&dir, "secrets/db.yml", "password: CLOAKMARK-edited\n");
    env.git_ok(&dir, &["checkout", "-q", "main"]);
    let st = env.ok(&dir, &["status"]);
    assert!(st.contains("Followed Git HEAD"), "{st}");
    assert!(st.contains("secrets/db.yml"), "the cloaked edit is a change of the new working copy: {st}");
    assert!(!dir.join("feat.txt").exists());
    assert!(std::fs::read_to_string(dir.join("secrets/db.yml")).unwrap().contains("CLOAKMARK-edited"));
    // Veil followed the branches: tag `feature` exists, @ is on main.
    let tags = env.ok(&dir, &["tag", "list"]);
    assert!(tags.contains("feature"), "{tags}");
    assert_clean(&env, &dir.join(".git"), &["CLOAKMARK"], "after a branch switch");
}

// ---- 8. Git overwrites an excluded file ------------------------------------------------------

#[test]
fn t08_an_excluded_file_git_overwrites_is_recoverable() {
    let env = Env::new();
    let dir = env.dir("p");
    env.ok(&dir, &["init", "--colocate", "--experimental"]);
    // Public at first …
    env.write(&dir, "conf/db.yml", "OLDPUBLIC\n");
    env.ok(&dir, &["commit", "-m", "public db"]);
    env.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
    let old = env.git_ok(&dir, &["rev-parse", "HEAD"]);
    // … then cloaked, and edited.
    env.ok(&dir, &["cloak", "conf/db.yml"]);
    env.write(&dir, "conf/db.yml", "CLOAKMARK-member\n");
    env.ok(&dir, &["commit", "-m", "cloak db"]);
    env.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
    let _ = env.git(&dir, &["checkout", "-q", &old]);
    env.ok(&dir, &["status"]);
    let now = std::fs::read_to_string(dir.join("conf/db.yml")).unwrap();
    if !now.contains("CLOAKMARK-member") {
        // Overwritten by Git: history still holds the member's version.
        let cat = env.ok(&dir, &["cat", "conf/db.yml", "-r", "main"]);
        assert!(cat.contains("CLOAKMARK-member"), "{cat}");
    }
    assert_clean(&env, &dir.join(".git"), &["CLOAKMARK"], "after git checkout of an old commit");
}

// ---- 9. concurrent git and vl ------------------------------------------------------------------

#[test]
fn t09_concurrent_git_commits_and_vl_commands_lose_no_commit() {
    let env = Env::new();
    let dir = env.project("p");
    let n: usize = std::env::var("VEIL_RACE_N").ok().and_then(|v| v.parse().ok()).unwrap_or(200);
    let stop = std::sync::atomic::AtomicBool::new(false);
    let commits = std::thread::scope(|s| {
        let vl = s.spawn(|| {
            let mut i = 0;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) && i < n {
                let args: &[&str] = if i % 2 == 0 { &["status"] } else { &["describe", "-m", "wc"] };
                let out = env.vl(&dir, args);
                assert!(!text(&out).contains("panicked"), "{}", text(&out));
                i += 1;
            }
        });
        let mut commits = Vec::new();
        for i in 0..n {
            env.write(&dir, &format!("race/{i}.txt"), &format!("{i}\n"));
            env.git_ok(&dir, &["add", &format!("race/{i}.txt")]);
            let out = env.git(&dir, &["commit", "-q", "-m", &format!("race {i}")]);
            if out.status.success() {
                commits.push(env.git_ok(&dir, &["rev-parse", "HEAD"]));
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        vl.join().unwrap();
        commits
    });
    assert!(commits.len() >= n / 2, "most git commits should succeed ({} of {n})", commits.len());
    env.ok(&dir, &["status"]);
    let all = env.git_ok(&dir, &["rev-list", "--all", "--reflog"]);
    for c in &commits {
        assert!(all.contains(c.as_str()), "git commit {c} is lost");
    }
    let reachable = env.git_ok(&dir, &["rev-list", "--branches"]);
    let last = commits.last().unwrap();
    assert!(reachable.contains(last.as_str()), "the last git commit is not on a branch");
    let fsck = env.git(&dir, &["fsck", "--no-dangling"]);
    assert!(fsck.status.success(), "{}", text(&fsck));
    assert!(dir.join(".git/index").exists() && !dir.join(".git/index.lock").exists());
}

// ---- 10. vl from a Git hook while Git holds index.lock -------------------------------------------

#[test]
fn t10_vl_run_by_a_git_hook_works_without_deadlock() {
    let env = Env::new();
    let dir = env.project("p");
    // A pre-commit framework hook that calls vl (chained before Veil's).
    let hook = dir.join(".git/hooks/pre-commit.veil-chained");
    std::fs::write(&hook, format!("#!/bin/sh\n'{}' status >/dev/null 2>&1 || exit 1\n", env!("CARGO_BIN_EXE_vl"))).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    env.write(&dir, "c.md", "c\n");
    env.git_ok(&dir, &["add", "c.md"]);
    let start = std::time::Instant::now();
    env.git_ok(&dir, &["commit", "-q", "-m", "with hook"]);
    assert!(start.elapsed() < std::time::Duration::from_secs(60));
    // Inside the hook, vl saw the lock and only noted it.
    let st = env.ok(&dir, &["status"]);
    assert!(!st.contains("error"), "{st}");
}

// ---- 11. cloaked descriptions and tag names -------------------------------------------------------

#[test]
fn t11_cloaked_descriptions_and_tag_names_never_reach_git() {
    let env = Env::new();
    let dir = env.project("p");
    cloaked_ws(&env, &dir);
    env.write(&dir, "plan.md", "CLOAKMARK-plan\n");
    env.ok(&dir, &["commit", "-m", "CLOAKMSG-sealed description"]);
    env.ok(&dir, &["tag", "set", "hush-feature", "-r", "@-", "--cloak", "team"]);
    env.ok(&dir, &["status"]);
    env.ok(&dir, &["ws", "switch", "default"]);
    let git = dir.join(".git");
    assert_clean(&env, &git, &["CLOAKMSG", "CLOAKMARK", "hush-feature"], "after a cloaked session");
    let refs = ref_names(&env, &git);
    assert!(!refs.contains("hush-feature"), "{refs}");
}

// ---- 12. embargo key holders ------------------------------------------------------------------------

#[test]
fn t12_an_embargo_key_holder_sees_and_stores_nothing_of_the_fix_in_git() {
    let env = Env::new();
    let dir = env.dir("p");
    env.ok(&dir, &["init", "--colocate", "--experimental"]);
    env.write(&dir, "auth.rs", "fn check() { true }\n");
    env.ok(&dir, &["commit", "-m", "v1"]);
    env.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
    env.ok(&dir, &["ws", "new", "fix", "-r", "main", "--cloak", "team"]);
    env.ok(&dir, &["ws", "switch", "fix"]);
    env.write(&dir, "auth.rs", "fn check() { EMBMARK_verify() }\n");
    env.ok(&dir, &["commit", "-m", "the fix"]);
    env.ok(&dir, &["ws", "switch", "default"]);
    env.ok(&dir, &["merge", "fix@-", "--into", "main", "--embargo", "-m", "Fix CVE"]);
    env.ok(&dir, &["new", "main"]);
    // The key holder has the fix on disk …
    assert!(std::fs::read_to_string(dir.join("auth.rs")).unwrap().contains("EMBMARK"));
    // … and Git shows and stores nothing of it.
    assert_eq!(env.git_ok(&dir, &["status", "--porcelain"]), "");
    assert_eq!(env.git_ok(&dir, &["diff"]), "");
    let _ = env.git(&dir, &["stash", "-u"]);
    assert!(std::fs::read_to_string(dir.join("auth.rs")).unwrap().contains("EMBMARK"));
    let log = env.git_ok(&dir, &["log", "--all", "--format=%B"]);
    assert!(!log.contains("the fix") && !log.contains("Fix CVE"), "{log}");
    assert_clean(&env, &dir.join(".git"), &["EMBMARK"], "in an embargo workspace");
    let st = env.ok(&dir, &["git", "colocate", "--status"]);
    assert!(st.contains("frozen"), "{st}");
}

// ---- 13. git stash -a / git clean -fdx ---------------------------------------------------------------

#[test]
fn t13_stash_all_and_clean_never_take_the_veil_repository_or_reach_a_remote() {
    let env = Env::new();
    let dir = env.project("p");
    let remote = env.bare("remote.git");
    env.ok(&dir, &["git", "remote", "add", "gh", remote.to_str().unwrap()]);
    env.write(&dir, ".env", "ISOMARK-stash\n");
    env.ok(&dir, &["status"]);
    env.git_ok(&dir, &["stash", "-a"]);
    assert!(dir.join(".veil/repo.json").exists(), "git stash -a took .veil");
    env.ok(&dir, &["git", "push", "gh"]);
    assert_clean(&env, &remote, &["ISOMARK", "CLOAKMARK"], "remote after git stash -a");
    env.git_ok(&dir, &["stash", "pop", "-q"]);
    assert!(dir.join(".env").exists());
    // `git clean -fdx` deletes the ignored files (recoverable), never .veil.
    let _ = env.git(&dir, &["clean", "-q", "-f", "-d", "-x"]);
    assert!(dir.join(".veil/repo.json").exists(), "git clean -fdx deleted .veil");
    env.ok(&dir, &["status"]);
    let rec = env.vl(&dir, &["secret", "recover", ".env"]);
    if rec.status.success() {
        assert!(std::fs::read_to_string(dir.join(".env")).unwrap().contains("ISOMARK-stash"));
    }
    let cat = env.ok(&dir, &["cat", "secrets/db.yml", "-r", "main"]);
    assert!(cat.contains("CLOAKMARK-base"), "{cat}");
}

// ---- 14. a hostile .git in a tree ---------------------------------------------------------------------

#[test]
fn t14_a_tree_with_a_dot_git_lookalike_is_refused() {
    let env = Env::new();
    let dir = env.project("p");
    let git = dir.join(".git");
    let g = git.to_str().unwrap();
    // A commit whose tree holds `.GIT/hooks/post-checkout`.
    let blob = {
        let mut c = env.git_cmd(&dir, &["--git-dir", g, "hash-object", "-w", "--stdin"]);
        c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped());
        let mut child = c.spawn().unwrap();
        use std::io::Write;
        child.stdin.take().unwrap().write_all(b"#!/bin/sh\ntouch PWNED\n").unwrap();
        String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap().trim().to_string()
    };
    let mk = |input: String| -> String {
        let mut c = env.git_cmd(&dir, &["--git-dir", g, "mktree"]);
        c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped());
        let mut child = c.spawn().unwrap();
        use std::io::Write;
        child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap().trim().to_string()
    };
    for name in [".GIT", ".git", ".Git"] {
        let hooks = mk(format!("100755 blob {blob}\tpost-checkout\n"));
        let dotgit = mk(format!("040000 tree {hooks}\thooks\n"));
        let root = mk(format!("040000 tree {dotgit}\t{name}\n"));
        let head = env.git_ok(&dir, &["rev-parse", "HEAD"]);
        let commit = env.git_ok(&dir, &["commit-tree", &root, "-p", &head, "-m", "evil"]);
        env.git_ok(&dir, &["update-ref", "refs/heads/evil", &commit]);
        env.ok(&dir, &["status"]);
        let files = env.vl(&dir, &["files", "-r", "evil"]);
        assert!(!text(&files).contains("post-checkout"), "{name}: {}", text(&files));
        let _ = env.vl(&dir, &["new", "evil"]);
        assert!(!dir.join("PWNED").exists());
        let wrote = std::fs::read_dir(&git).unwrap().any(|e| e.unwrap().file_name() == "hooks")
            && std::fs::read_to_string(git.join("hooks/post-checkout")).is_ok_and(|t| t.contains("PWNED"));
        assert!(!wrote, "{name}: a tree wrote .git/hooks");
        env.ok(&dir, &["new", "main"]);
        env.git_ok(&dir, &["update-ref", "-d", "refs/heads/evil"]);
        env.ok(&dir, &["status"]);
    }
}

// ---- 15. core.hooksPath is the user's -----------------------------------------------------------------

#[test]
fn t15_a_user_hooks_path_is_preserved_and_reported() {
    let env = Env::new();
    let dir = env.dir("p");
    env.git_ok(&dir, &["init", "-q"]);
    env.git_ok(&dir, &["config", "core.hooksPath", "my-hooks"]);
    env.write(&dir, "a.md", "a\n");
    env.git_ok(&dir, &["add", "a.md"]);
    env.git_ok(&dir, &["commit", "-q", "-m", "a"]);
    let out = env.ok(&dir, &["init", "--colocate", "--experimental"]);
    assert!(out.contains("core.hooksPath"), "{out}");
    assert_eq!(env.git_ok(&dir, &["config", "--get", "core.hooksPath"]), "my-hooks");
    let st = env.ok(&dir, &["git", "colocate", "--status"]);
    assert!(st.contains("inactive"), "{st}");
}

// ---- 16. policy weakening through Git -------------------------------------------------------------------

#[test]
fn t16_a_git_pull_that_weakens_the_policy_is_held_back() {
    let env = Env::new();
    let dir = env.project("p");
    let remote = env.bare("remote.git");
    env.ok(&dir, &["git", "remote", "add", "gh", remote.to_str().unwrap()]);
    env.ok(&dir, &["git", "push", "gh"]);
    // A teammate weakens .veilpolicy in plain Git.
    let other = env.root.join("other");
    env.git_ok(&env.root, &["clone", "-q", remote.to_str().unwrap(), other.to_str().unwrap()]);
    let mut p = std::fs::read_to_string(other.join(".veilpolicy")).unwrap();
    p.push_str("secrets/ public!\n");
    std::fs::write(other.join(".veilpolicy"), p).unwrap();
    env.git_ok(&other, &["commit", "-q", "-a", "-m", "weaken"]);
    env.git_ok(&other, &["push", "-q", "origin", "main"]);
    env.git_ok(&dir, &["pull", "-q", "--ff-only", remote.to_str().unwrap(), "main"]);
    let st = env.ok(&dir, &["status"]);
    assert!(st.contains("held back") || st.contains("accept") || st.contains("kept its policy"), "{st}");
    // The cloaked file stays cloaked: the pulled policy is incoming, not
    // the member's own edit.
    let ls = env.ok(&dir, &["ls"]);
    assert!(ls.lines().any(|l| l.contains("secrets/db.yml") && l.contains("cloaked")), "{ls}");
    let ex = std::fs::read_to_string(dir.join(".git/info/exclude")).unwrap();
    assert!(ex.contains("[sS][eE][cC][rR][eE][tT][sS]/"), "{ex}");
    env.write(&dir, "secrets/more.yml", "CLOAKMARK-after-pull\n");
    env.git_ok(&dir, &["add", "-A"]);
    let _ = env.git(&dir, &["commit", "-q", "-m", "after pull"]);
    assert_clean(&env, &dir.join(".git"), &["CLOAKMARK"], "after a weakening git pull");
}

// ---- 17. symlinks -----------------------------------------------------------------------------------------

#[test]
fn t17_a_git_side_symlink_never_redirects_a_hidden_checkout() {
    let env = Env::new();
    let dir = env.project("p");
    let outside = env.dir("outside");
    // A Git commit replacing `secrets/` by a link out of the project.
    let g = dir.join(".git");
    let link = {
        let mut c = env.git_cmd(&dir, &["--git-dir", g.to_str().unwrap(), "hash-object", "-w", "--stdin"]);
        c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped());
        let mut child = c.spawn().unwrap();
        use std::io::Write;
        child.stdin.take().unwrap().write_all(outside.to_str().unwrap().as_bytes()).unwrap();
        String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap().trim().to_string()
    };
    let head_tree = env.git_ok(&dir, &["rev-parse", "HEAD^{tree}"]);
    let mut entries = env.git_ok(&dir, &["ls-tree", &head_tree]);
    entries.push_str(&format!("\n120000 blob {link}\tsecrets\n"));
    let mut c = env.git_cmd(&dir, &["mktree"]);
    c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(entries.as_bytes()).unwrap();
    let tree = String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap().trim().to_string();
    let head = env.git_ok(&dir, &["rev-parse", "HEAD"]);
    let commit = env.git_ok(&dir, &["commit-tree", &tree, "-p", &head, "-m", "link"]);
    let _ = env.git(&dir, &["checkout", "-q", &commit]);
    let _ = env.vl(&dir, &["status"]);
    let _ = env.vl(&dir, &["new", "main"]);
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0, "something was written through the link");
    let cat = env.ok(&dir, &["cat", "secrets/db.yml", "-r", "main"]);
    assert!(cat.contains("CLOAKMARK-base"), "{cat}");
}

// ---- 18. uncolocate ---------------------------------------------------------------------------------------

#[test]
fn t18_uncolocate_removes_every_guard_and_keeps_format_5() {
    let env = Env::new();
    let dir = env.dir("p");
    env.git_ok(&dir, &["init", "-q"]);
    std::fs::write(dir.join(".git/hooks/pre-push"), "#!/bin/sh\nexit 0\n").unwrap();
    env.write(&dir, "a.md", "a\n");
    env.git_ok(&dir, &["add", "a.md"]);
    env.git_ok(&dir, &["commit", "-q", "-m", "a"]);
    env.ok(&dir, &["init", "--colocate", "--experimental"]);
    assert!(dir.join(".git/hooks/pre-push.veil-chained").exists());
    assert!(std::fs::read_to_string(dir.join(".git/info/exclude")).unwrap().contains("BEGIN veil"));
    env.ok(&dir, &["git", "uncolocate"]);
    let ex = std::fs::read_to_string(dir.join(".git/info/exclude")).unwrap_or_default();
    assert!(!ex.contains("BEGIN veil"), "{ex}");
    assert_eq!(std::fs::read_to_string(dir.join(".git/hooks/pre-push")).unwrap(), "#!/bin/sh\nexit 0\n");
    assert!(!dir.join(".git/hooks/pre-commit").exists());
    assert!(!dir.join(".veil/.git").exists());
    let ls = env.git_ok(&dir, &["ls-files", "-v"]);
    assert!(!ls.lines().any(|l| l.starts_with('S')), "{ls}");
    let cfg = std::fs::read_to_string(dir.join(".veil/repo.json")).unwrap();
    assert!(cfg.contains("\"format\": 5") && !cfg.contains("colocated"), "{cfg}");
    // vl keeps working, with the bridge back in .veil/git.
    env.ok(&dir, &["status"]);
    env.ok(&dir, &["git", "export"]);
}

// ---- 19. sandboxes are never colocated ---------------------------------------------------------------------

#[test]
fn t19_ws_exec_sandboxes_have_no_git() {
    let env = Env::new();
    let dir = env.project("p");
    env.ok(&dir, &["ws", "new", "agent", "-r", "main"]);
    let out = env.ok(&dir, &["ws", "exec", "agent", "--", "sh", "-c", "ls -a; git rev-parse --git-dir 2>&1 || true"]);
    assert!(!out.lines().any(|l| l.trim() == ".git"), "{out}");
}

// ---- adoption, commands, hostile inputs -------------------------------------------------------------------

#[test]
fn adopting_a_git_checkout_imports_gitignore_and_its_history() {
    let env = Env::new();
    let dir = env.dir("rails");
    env.git_ok(&dir, &["init", "-q"]);
    env.write(&dir, ".gitignore", "config/master.key\n*.tfvars\nlog/\n");
    env.write(&dir, "app.rb", "puts 1\n");
    env.git_ok(&dir, &["add", "-A"]);
    env.git_ok(&dir, &["commit", "-q", "-m", "app"]);
    env.write(&dir, "config/master.key", "ISOMARK-masterkey\n");
    env.write(&dir, "prod.tfvars", "ISOMARK-tfvars\n");
    env.write(&dir, "log/dev.log", "log\n");
    env.write(&dir, "app.rb", "puts 2\n");
    let out = env.ok(&dir, &["init", "--colocate", "--experimental"]);
    assert!(out.contains("master.key") && out.contains("tfvars"), "{out}");
    let policy = std::fs::read_to_string(dir.join(".veilpolicy")).unwrap();
    assert!(policy.contains("/config/master.key ignore"), "{policy}");
    let files = env.ok(&dir, &["files", "-r", "@"]);
    assert!(!files.contains("master.key") && !files.contains("tfvars") && !files.contains("dev.log"), "{files}");
    // HEAD's commit is @-, the uncommitted edit is @'s change.
    let st = env.ok(&dir, &["status"]);
    assert!(st.contains("app.rb"), "{st}");
    let log = env.ok(&dir, &["log"]);
    assert!(log.contains("app"), "{log}");
    assert_eq!(env.git_ok(&dir, &["symbolic-ref", "HEAD"]), "refs/heads/main");
}

#[test]
fn adoption_refuses_what_it_cannot_guard() {
    let env = Env::new();
    // A linked worktree's .git file.
    let main = env.dir("main");
    env.git_ok(&main, &["init", "-q"]);
    env.write(&main, "a", "a\n");
    env.git_ok(&main, &["add", "a"]);
    env.git_ok(&main, &["commit", "-q", "-m", "a"]);
    let wt = env.root.join("wt");
    env.git_ok(&main, &["worktree", "add", "-q", wt.to_str().unwrap()]);
    let out = env.fails(&wt, &["init", "--colocate", "--experimental"]);
    assert!(out.contains("worktree") || out.contains("file"), "{out}");
    assert!(!wt.join(".veil").exists());
    // A Git operation in progress.
    std::fs::write(main.join(".git/MERGE_HEAD"), "0000000000000000000000000000000000000000\n").unwrap();
    let out = env.fails(&main, &["init", "--colocate", "--experimental"]);
    assert!(out.contains("in progress"), "{out}");
    std::fs::remove_file(main.join(".git/MERGE_HEAD")).unwrap();
    // GIT_DIR pointing elsewhere.
    let out = env.vl_cmd(&main, &["init", "--colocate", "--experimental"]).env("GIT_DIR", &wt).output().unwrap();
    assert!(!out.status.success() && text(&out).contains("GIT_DIR"), "{}", text(&out));
    // Without --experimental.
    let fresh = env.dir("fresh");
    let out = env.fails(&fresh, &["init", "--colocate"]);
    assert!(out.contains("experimental"), "{out}");
    assert!(!fresh.join(".veil").exists() && !fresh.join(".git").exists());
    // An existing Veil working copy needs an upgraded format and the flag.
    let v = env.dir("v");
    env.ok(&v, &["init"]);
    let out = env.fails(&v, &["git", "colocate"]);
    assert!(out.contains("experimental"), "{out}");
    env.ok(&v, &["git", "colocate", "--experimental"]);
    let out = env.fails(&v, &["git", "colocate", "--experimental"]);
    assert!(out.contains("already colocated"), "{out}");
}

#[test]
fn colocating_an_existing_veil_repository_migrates_the_bridge() {
    let env = Env::new();
    let dir = env.dir("v");
    let remote = env.bare("remote.git");
    env.ok(&dir, &["init"]);
    env.write(&dir, "README.md", "r\n");
    env.ok(&dir, &["commit", "-m", "one"]);
    env.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
    env.ok(&dir, &["git", "remote", "add", "gh", remote.to_str().unwrap()]);
    env.ok(&dir, &["git", "push", "gh"]);
    env.ok(&dir, &["git", "colocate", "--experimental"]);
    assert!(!env.git_ok(&dir, &["rev-parse", "refs/remotes/gh/main"]).is_empty());
    assert_eq!(env.git_ok(&dir, &["rev-parse", "main"]), env.git_ok(&remote, &["rev-parse", "main"]));
    env.write(&dir, "two.md", "2\n");
    env.ok(&dir, &["commit", "-m", "two"]);
    env.ok(&dir, &["git", "push", "gh"]);
    assert_eq!(env.git_ok(&remote, &["log", "-1", "--format=%s", "main"]), "two");
}

#[test]
fn import_gitignore_adds_rules_once() {
    let env = Env::new();
    let dir = env.dir("g");
    env.git_ok(&dir, &["init", "-q"]);
    env.write(&dir, ".gitignore", "*.secret\n");
    env.write(&dir, "sub/.gitignore", "cache/\n");
    env.write(&dir, "x.secret", "ISOMARK\n");
    env.write(&dir, "sub/cache/a", "a\n");
    env.ok(&dir, &["init"]);
    let out = env.ok(&dir, &["policy", "import-gitignore"]);
    assert!(out.contains("*.secret") && out.contains("/sub/**/cache/"), "{out}");
    let p1 = std::fs::read_to_string(dir.join(".veilpolicy")).unwrap();
    env.ok(&dir, &["policy", "import-gitignore"]);
    assert_eq!(std::fs::read_to_string(dir.join(".veilpolicy")).unwrap(), p1);
    let none = env.dir("none");
    env.ok(&none, &["init"]);
    let out = env.fails(&none, &["policy", "import-gitignore"]);
    assert!(out.contains(".git"), "{out}");
}

#[test]
fn hostile_branch_names_and_refs_are_never_followed_into_trouble() {
    let env = Env::new();
    let dir = env.project("p");
    let head = env.git_ok(&dir, &["rev-parse", "HEAD"]);
    // Names Git allows that are not Veil tag names, or that mimic ours.
    for b in ["a@b", "x--upload-pack", "dir/sub", "\u{e9}t\u{e9}", "veil/tags/x"] {
        let _ = env.git(&dir, &["branch", b, &head]);
    }
    let st = env.ok(&dir, &["status"]);
    assert!(!st.contains("panicked"), "{st}");
    // refs/stash and refs outside heads/tags are never imported as tags.
    env.write(&dir, "README.md", "changed\n");
    env.git_ok(&dir, &["stash"]);
    env.git_ok(&dir, &["update-ref", "refs/notes/evil", &head]);
    env.ok(&dir, &["status"]);
    let tags = env.ok(&dir, &["tag", "list"]);
    assert!(!tags.contains("stash") && !tags.contains("notes"), "{tags}");
    // Garbage on the pre-push hook's stdin is refused, not trusted.
    let mut c = env.vl_cmd(&dir, &["git", "check-push", "origin"]);
    c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(b"refs/heads/main zzz refs/heads/main 000\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success(), "{}", text(&out));
    // A corrupt colocated.json is an error, never a silent reset of the guards.
    std::fs::write(dir.join(".veil/git/colocated.json"), "{ not json").unwrap();
    let out = env.fails(&dir, &["status"]);
    assert!(out.contains("colocated.json"), "{out}");
}

#[test]
fn a_symlinked_or_file_dot_git_is_refused_once_colocated() {
    let env = Env::new();
    let dir = env.project("p");
    let elsewhere = env.root.join("elsewhere.git");
    std::fs::rename(dir.join(".git"), &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, dir.join(".git")).unwrap();
    let out = env.fails(&dir, &["status"]);
    assert!(out.contains("symlink") || out.contains("not a directory"), "{out}");
    std::fs::remove_file(dir.join(".git")).unwrap();
    std::fs::write(dir.join(".git"), format!("gitdir: {}\n", elsewhere.display())).unwrap();
    let out = env.fails(&dir, &["status"]);
    assert!(out.contains("not a directory"), "{out}");
}

#[test]
fn git_operations_in_progress_pause_the_mirror() {
    let env = Env::new();
    let dir = env.project("p");
    let head = env.git_ok(&dir, &["rev-parse", "HEAD"]);
    std::fs::create_dir_all(dir.join(".git/rebase-merge")).unwrap();
    env.write(&dir, "x.md", "x\n");
    env.ok(&dir, &["commit", "-m", "during rebase"]);
    let out = env.ok(&dir, &["status"]);
    assert!(out.contains("in progress"), "{out}");
    // Nothing moved in Git meanwhile.
    assert_eq!(env.git_ok(&dir, &["rev-parse", "HEAD"]), head);
    std::fs::remove_dir_all(dir.join(".git/rebase-merge")).unwrap();
    env.ok(&dir, &["status"]);
    assert_ne!(env.git_ok(&dir, &["rev-parse", "HEAD"]), head);
}

#[test]
fn quarantined_edits_are_hidden_from_git() {
    let env = Env::new();
    let dir = env.project("p");
    // A public file gets a credential: Veil quarantines the edit.
    env.write(&dir, "README.md", "hello\naws_secret_access_key = AKIAIOSFODNN7EXAMPLEQ wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n");
    let st = env.ok(&dir, &["status"]);
    assert!(st.contains("quarantin"), "{st}");
    assert_eq!(env.git_ok(&dir, &["status", "--porcelain"]), "", "Git sees the quarantined edit");
    let out = env.git(&dir, &["commit", "-a", "-m", "leak"]);
    assert!(!out.status.success() || !contains(&objects(&env, &dir.join(".git")), "wJalrXUtnFEMI"), "{}", text(&out));
    assert_clean(&env, &dir.join(".git"), &["wJalrXUtnFEMI"], "after a quarantined edit");
}
