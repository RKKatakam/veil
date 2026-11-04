//! Round trips through the Git bridge, after the scenarios of git's
//! fast-import / fast-export tests (t9300, t9350): authors, merges, empty
//! commits, file modes, odd paths, deletions; and Veil → Git → Veil
//! stability (change ids, no duplicated commits).

use std::path::{Path, PathBuf};

use crate::support::*;

/// A Git history exercising the fast-export scenarios, on `main` and `side`.
fn rich_git_history(env: &Env) -> (PathBuf, PathBuf) {
    let (bare, wc) = git_upstream(env, "gh.git", &[("a.txt", "a\n")]);
    write(&wc, "dir with space/f i le.txt", "s\n");
    write(&wc, "ünïcödé.txt", "u\n");
    write(&wc, "-dash.txt", "d\n");
    write(&wc, "nonl.txt", "no newline");
    write(&wc, "empty", "");
    write_bytes(&wc, "bin.dat", &[0, 159, 146, 150, 0, 10]);
    write(&wc, "run.sh", "#!/bin/sh\necho hi\n");
    set_mode(&wc.join("run.sh"), 0o755);
    git(&wc, &["add", "-A"]);
    git_env(
        &wc,
        &[
            ("GIT_AUTHOR_NAME", "Zoë Ünicode"),
            ("GIT_AUTHOR_EMAIL", "zoe@example.com"),
            ("GIT_AUTHOR_DATE", "1700000000 +0000"),
        ],
        &[
            "commit",
            "-q",
            "-m",
            "odd names\n\nA body paragraph.\n\nSigned-off-by: Zoë <zoe@example.com>",
        ],
    );
    git(
        &wc,
        &["commit", "-q", "--allow-empty", "-m", "an empty commit"],
    );
    git(&wc, &["checkout", "-q", "-b", "side"]);
    write(&wc, "side.txt", "side\n");
    git(&wc, &["add", "-A"]);
    git(&wc, &["commit", "-q", "-m", "side work"]);
    git(&wc, &["checkout", "-q", "main"]);
    git(&wc, &["rm", "-q", "a.txt"]);
    git(&wc, &["commit", "-q", "-m", "delete a"]);
    git(&wc, &["merge", "-q", "--no-ff", "side", "-m", "merge side"]);
    git(&wc, &["push", "-q", "origin", "main", "side"]);
    (bare, wc)
}

fn import(env: &Env, user: &str, name: &str, bare: &Path) -> PathBuf {
    let proj = env.dir(name);
    env.ok(user, &proj, &["init"]);
    env.ok(user, &proj, &["git", "import", bare.to_str().unwrap()]);
    proj
}

/// `(change id, description first line)` of every snapshot `vl log` shows,
/// except the working copy and the root.
fn changes(env: &Env, user: &str, dir: &Path) -> Vec<(String, String)> {
    let log = env.stdout(user, dir, &["--no-snapshot", "log", "-n", "1000"]);
    let lines: Vec<&str> = log.lines().collect();
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let body = l.trim_start_matches(|c: char| "│ ○@◆~─╮╯╭╰├┤ ".contains(c));
        if l.contains("default@") || body.starts_with("zzzzzzzz") {
            continue;
        }
        let Some(change) = body
            .split_whitespace()
            .next()
            .filter(|w| w.len() == 8 && w.chars().all(|c| ('k'..='z').contains(&c)))
        else {
            continue;
        };
        if l.contains('○') || l.contains('◆') || l.contains('@') {
            let desc = lines
                .get(i + 1)
                .map(|d| d.trim_start_matches(|c: char| "│ ".contains(c)).to_string())
                .unwrap_or_default();
            out.push((change.to_string(), desc));
        }
    }
    out.sort();
    out
}

// Scenario from git t9350-fast-export.sh / t9300-fast-import.sh: authors, merges, empty
// commits, file modes, odd paths and deletions survive an import.
#[test]
fn git_import_preserves_the_fast_export_scenarios() {
    let env = Env::new();
    let (bare, _wc) = rich_git_history(&env);
    let proj = import(&env, "alice", "proj", &bare);
    for f in [
        "dir with space/f i le.txt",
        "ünïcödé.txt",
        "-dash.txt",
        "nonl.txt",
        "empty",
        "bin.dat",
        "side.txt",
    ] {
        assert_eq!(
            std::fs::read(proj.join(f)).unwrap(),
            git_cmd(&bare)
                .args(["show", &format!("main:{f}")])
                .output()
                .unwrap()
                .stdout,
            "{f}"
        );
    }
    assert!(!proj.join("a.txt").exists(), "the deletion was imported");
    assert!(is_executable(&proj.join("run.sh")));
    assert!(!is_executable(&proj.join("nonl.txt")));
    let log = env.stdout("alice", &proj, &["log"]);
    assert!(log.contains("Zoë Ünicode <zoe@example.com>"), "{log}");
    assert!(
        log.contains("an empty commit") && log.contains("(empty)"),
        "{log}"
    );
    assert!(log.contains("merges"), "the merge has two parents: {log}");
    let show = env.stdout("alice", &proj, &["show", "main--"]);
    let _ = show;
    let odd = env.stdout("alice", &proj, &["log"]);
    assert!(odd.contains("odd names"), "{odd}");
}

// Scenario from git t9350-fast-export.sh: a full message (body, trailers) survives import.
#[test]
fn a_multi_paragraph_message_survives_import() {
    let env = Env::new();
    let (bare, wc) = rich_git_history(&env);
    let _ = wc;
    let proj = import(&env, "alice", "proj", &bare);
    let commit = git(&bare, &["log", "--format=%H", "--grep=odd names", "main"]);
    let _ = commit;
    // Find the snapshot by its message and show it.
    let log = env.stdout("alice", &proj, &["log"]);
    let change = log
        .lines()
        .zip(log.lines().skip(1))
        .find(|(_, d)| d.contains("odd names"))
        .and_then(|(l, _)| {
            l.split_whitespace()
                .find(|w| w.len() == 8 && w.chars().all(|c| ('k'..='z').contains(&c)))
        })
        .expect("the odd-names change")
        .to_string();
    let show = env.stdout("alice", &proj, &["show", &change]);
    assert!(
        show.contains("A body paragraph.") && show.contains("Signed-off-by: Zoë"),
        "{show}"
    );
}

// Scenario from git t9350-fast-export.sh ("fast-export | fast-import" gives identical
// commits): Git → Veil → Git keeps every commit id.
#[test]
fn git_to_veil_to_git_keeps_every_commit_id() {
    let env = Env::new();
    let (bare, _wc) = rich_git_history(&env);
    let proj = import(&env, "alice", "proj", &bare);
    let other = env.path("other.git");
    git(
        &env.root,
        &["init", "-q", "--bare", other.to_str().unwrap()],
    );
    env.ok(
        "alice",
        &proj,
        &["git", "remote", "add", "other", other.to_str().unwrap()],
    );
    env.ok("alice", &proj, &["git", "push", "other"]);
    for b in ["main", "side"] {
        assert_eq!(
            git(&other, &["rev-parse", b]),
            git(&bare, &["rev-parse", b]),
            "{b}"
        );
    }
    let out = env.ok("alice", &proj, &["git", "push"]);
    assert!(
        out.contains("up to date main") && out.contains("up to date side"),
        "{out}"
    );
}

// Scenario from git t9350-fast-export.sh, Veil → Git: every Veil commit becomes one Git
// commit with the change id header, the author, merges and modes.
#[test]
fn veil_history_exports_with_change_ids_authors_merges_and_modes() {
    let env = Env::new();
    let (proj, bare) =
        veil_with_git_remote(&env, "Alice Doe <alice@example.com>", "proj", "gh.git");
    let u = "Alice Doe <alice@example.com>";
    env.commit(
        u,
        &proj,
        "base",
        &[("a.txt", "a\n"), ("tool.sh", "#!/bin/sh\n")],
    );
    set_mode(&proj.join("tool.sh"), 0o755);
    env.commit(u, &proj, "make it executable", &[]);
    env.ok(u, &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok(u, &proj, &["new", "main"]);
    write(&proj, "s.txt", "s\n");
    env.ok(u, &proj, &["commit", "--no-advance", "-m", "side"]);
    env.ok(u, &proj, &["tag", "set", "side", "-r", "@-"]);
    env.ok(u, &proj, &["new", "main"]);
    env.commit(u, &proj, "main work", &[("m.txt", "m\n")]);
    env.ok(
        u,
        &proj,
        &["merge", "side", "--into", "main", "-m", "merge side"],
    );
    env.ok(u, &proj, &["git", "push"]);
    let parents = git(&bare, &["log", "-1", "--format=%P", "main"]);
    assert_eq!(parents.split_whitespace().count(), 2, "{parents}");
    assert_eq!(
        git(&bare, &["log", "-1", "--format=%an <%ae>", "main"]),
        "Alice Doe <alice@example.com>"
    );
    let raw = git(&bare, &["cat-file", "commit", "main"]);
    assert!(raw.lines().any(|l| l.starts_with("change-id ")), "{raw}");
    let mode = git(&bare, &["ls-tree", "main", "tool.sh"]);
    assert!(mode.starts_with("100755"), "{mode}");
    // The executable bit change is its own commit.
    assert!(git(&bare, &["log", "--format=%s", "main"]).contains("make it executable"));
}

// Scenario from git t9350-fast-export.sh ("empty commits"): an empty Veil commit exports
// as a commit with its parent's tree.
#[test]
fn an_empty_veil_commit_exports_as_an_empty_git_commit() {
    let env = Env::new();
    let (proj, bare) = veil_with_git_remote(&env, "alice", "proj", "gh.git");
    env.commit("alice", &proj, "base", &[("a", "a\n")]);
    env.ok("alice", &proj, &["commit", "-m", "nothing changed"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["git", "push"]);
    assert_eq!(
        git(&bare, &["log", "-1", "--format=%s", "main"]),
        "nothing changed"
    );
    assert_eq!(
        git(&bare, &["rev-parse", "main^{tree}"]),
        git(&bare, &["rev-parse", "main~1^{tree}"])
    );
}

// Scenario from git t9350-fast-export.sh: deletions, a file replaced by a directory and
// back, deep paths, odd names, empty and binary files, Veil → Git.
#[test]
fn deletions_and_type_changes_export_correctly() {
    let env = Env::new();
    let (proj, bare) = veil_with_git_remote(&env, "alice", "proj", "gh.git");
    let deep = format!("{}leaf.txt", "d/".repeat(30));
    env.commit(
        "alice",
        &proj,
        "base",
        &[
            ("x", "file x\n"),
            ("gone.txt", "g\n"),
            (deep.as_str(), "deep\n"),
            ("sp ace/ü.txt", "u\n"),
            ("empty", ""),
        ],
    );
    write_bytes(&proj, "bin", &[0, 1, 2, 0xff]);
    std::fs::remove_file(proj.join("gone.txt")).unwrap();
    std::fs::remove_file(proj.join("x")).unwrap();
    write(&proj, "x/inside.txt", "now a directory\n");
    env.ok("alice", &proj, &["commit", "-m", "x becomes a dir"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["git", "push"]);
    let files = git(&bare, &["ls-tree", "-r", "--name-only", "main"]);
    assert!(!files.contains("gone.txt"), "{files}");
    assert!(
        files.contains("x/inside.txt")
            && files.contains(&deep)
            && files.contains("sp ace/ü.txt")
            && files.contains("empty")
            && files.contains("bin"),
        "{files}"
    );
    assert_eq!(
        git_cmd(&bare)
            .args(["show", "main:bin"])
            .output()
            .unwrap()
            .stdout,
        vec![0, 1, 2, 0xff]
    );
    // And back to a file.
    std::fs::remove_dir_all(proj.join("x")).unwrap();
    write(&proj, "x", "a file again\n");
    env.ok("alice", &proj, &["commit", "-m", "x is a file again"]);
    env.ok("alice", &proj, &["git", "push"]);
    assert_eq!(git(&bare, &["show", "main:x"]), "a file again");
    assert!(
        git(&bare, &["fsck", "--no-progress"]).is_empty()
            || git_ok(&bare, &["fsck", "--no-progress"])
    );
}

// Scenario from git t9300-fast-import.sh: a Git commit replacing a file by a directory imports.
#[test]
fn a_git_file_to_directory_change_imports() {
    let env = Env::new();
    let (bare, wc) = git_upstream(&env, "gh.git", &[("x", "file\n")]);
    let proj = import(&env, "alice", "proj", &bare);
    git(&wc, &["rm", "-q", "x"]);
    write(&wc, "x/y.txt", "dir now\n");
    git_commit_push(&wc, "x becomes a directory");
    env.ok("alice", &proj, &["git", "pull"]);
    assert_eq!(
        env.stdout("alice", &proj, &["cat", "x/y.txt", "-r", "main"]),
        "dir now\n"
    );
    env.ok("alice", &proj, &["rebase", "-d", "main"]);
    assert_eq!(read(&proj, "x/y.txt"), "dir now\n");
}

// Scenario from git t9350-fast-export.sh ("fast-export | fast-import" is idempotent), Veil
// side: Veil → Git → a second Veil repository keeps change ids and descriptions.
#[test]
fn veil_to_git_to_veil_keeps_change_ids() {
    let env = Env::new();
    let (proj, bare) = veil_with_git_remote(&env, "alice", "proj", "gh.git");
    env.commit("alice", &proj, "one", &[("a", "1\n")]);
    env.commit("alice", &proj, "two", &[("a", "2\n")]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["git", "push"]);
    let other = import(&env, "bob", "other", &bare);
    let mine = changes(&env, "alice", &proj);
    let theirs = changes(&env, "bob", &other);
    assert!(!mine.is_empty());
    assert_eq!(mine, theirs, "change ids differ after Veil → Git → Veil");
}

// Veil: deleting the bridge's map rebuilds it; nothing is duplicated in Git.
#[test]
fn a_lost_git_map_is_rebuilt_without_duplicating_commits() {
    let env = Env::new();
    let (proj, bare) = veil_with_git_remote(&env, "alice", "proj", "gh.git");
    env.commit("alice", &proj, "one", &[("a", "1\n")]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["git", "push"]);
    let head = git(&bare, &["rev-parse", "main"]);
    std::fs::remove_file(proj.join(".veil/git/map")).unwrap();
    let _ = std::fs::remove_file(proj.join(".veil/git/cache"));
    let out = env.ok("alice", &proj, &["git", "pull"]);
    assert!(out.contains("Imported 0 commit(s)"), "{out}");
    let out = env.ok("alice", &proj, &["git", "push"]);
    assert!(out.contains("up to date main"), "{out}");
    assert_eq!(git(&bare, &["rev-parse", "main"]), head);
    let n = git(&bare, &["rev-list", "--count", "main"]);
    assert_eq!(n, "1", "one commit (holding `vl init`'s .veilpolicy and a)");
}

// Veil: exports are deterministic — two replicas of the same Veil history export the
// same commits.
#[test]
fn two_replicas_export_the_same_commits() {
    let env = Env::new();
    let (alice, hub) = env.project_with_hub("alice", "alice", "hub", &[("a.txt", "a\n")]);
    env.commit("alice", &alice, "two", &[("a.txt", "a2\n")]);
    env.ok("alice", &alice, &["push"]);
    let bob = env.clone("bob", &hub, "bob");
    let ga = env.path("a.git");
    let gb = env.path("b.git");
    for (who, dir, g) in [("alice", &alice, &ga), ("bob", &bob, &gb)] {
        git(&env.root, &["init", "-q", "--bare", g.to_str().unwrap()]);
        env.ok(
            who,
            dir,
            &["git", "remote", "add", "gh", g.to_str().unwrap()],
        );
        env.ok(who, dir, &["git", "push", "gh", "-t", "main"]);
    }
    assert_eq!(
        git(&ga, &["rev-parse", "main"]),
        git(&gb, &["rev-parse", "main"])
    );
}

// Veil: a second replica pulling Alice's export from GitHub recognises it (same snapshots).
#[test]
fn a_replica_recognises_exports_made_by_another_replica() {
    let env = Env::new();
    let (alice, hub) = env.project_with_hub("alice", "alice", "hub", &[("a.txt", "a\n")]);
    let gh = env.path("gh.git");
    git(&env.root, &["init", "-q", "--bare", gh.to_str().unwrap()]);
    env.ok(
        "alice",
        &alice,
        &["git", "remote", "add", "gh", gh.to_str().unwrap()],
    );
    env.ok("alice", &alice, &["git", "push", "gh"]);
    let bob = env.clone("bob", &hub, "bob");
    env.ok(
        "bob",
        &bob,
        &["git", "remote", "add", "gh", gh.to_str().unwrap()],
    );
    let out = env.ok("bob", &bob, &["git", "pull", "gh"]);
    assert!(out.contains("Imported 0 commit(s)"), "{out}");
    assert_eq!(
        env.tag_target("bob", &bob, "main"),
        env.tag_target("bob", &bob, "gh/main")
    );
}

// Veil + jj test_git_fetch.rs (two clones fetching the same new commits): the same GitHub
// commit imported by two members must be one snapshot, not two divergent copies.
#[test]
#[ignore = "BUG-285: two members importing the same Git commit get two snapshots (same change id); a merge then duplicates it on GitHub"]
fn the_same_github_commit_pulled_by_two_members_is_one_snapshot() {
    let env = Env::new();
    let (bare, wc) = git_upstream(&env, "gh.git", &[("a.txt", "a\n")]);
    let alice = import(&env, "alice", "alice", &bare);
    env.ok("alice", &alice, &["remote", "add", "hub", "../hub"]);
    env.ok("alice", &alice, &["push", "hub"]);
    let bob = env.clone("bob", &env.path("hub"), "bob");
    env.ok(
        "bob",
        &bob,
        &["git", "remote", "add", "gh", bare.to_str().unwrap()],
    );
    env.ok("bob", &bob, &["git", "pull", "gh"]);
    // A commit lands on GitHub; both members `vl git pull` before syncing with each other.
    write(&wc, "b.txt", "from github\n");
    git_commit_push(&wc, "on github");
    env.ok("alice", &alice, &["git", "pull"]);
    env.ok("bob", &bob, &["git", "pull", "gh"]);
    env.ok("alice", &alice, &["push", "hub"]);
    let out = env.ok("bob", &bob, &["pull"]);
    assert!(
        !out.contains("diverged"),
        "the same Git commit diverged: {out}"
    );
    assert_eq!(
        env.tag_target("bob", &bob, "main"),
        env.tag_target("bob", &bob, "origin/main")
    );
}

// Deliberate difference (docs/guide/github.md "Times are exported in UTC"): Git time zones
// are not kept; the instant is.
#[test]
fn author_time_survives_but_the_time_zone_becomes_utc() {
    let env = Env::new();
    let (bare, wc) = git_upstream(&env, "gh.git", &[("a", "a\n")]);
    write(&wc, "b", "b\n");
    git(&wc, &["add", "-A"]);
    git_env(
        &wc,
        &[
            ("GIT_AUTHOR_DATE", "1700000000 +0530"),
            ("GIT_COMMITTER_DATE", "1700000000 +0530"),
        ],
        &["commit", "-q", "-m", "in India"],
    );
    git(&wc, &["push", "-q", "origin", "HEAD:main"]);
    let proj = import(&env, "alice", "proj", &bare);
    env.commit("alice", &proj, "on top", &[("c", "c\n")]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["git", "push"]);
    // The imported commit itself is GitHub's own (unchanged); Veil's new commit is UTC.
    assert_eq!(
        git(
            &bare,
            &["log", "-1", "--format=%ad", "--date=raw", "main~1"]
        ),
        "1700000000 +0530"
    );
    assert!(git(&bare, &["log", "-1", "--format=%ad", "--date=raw", "main"]).ends_with("+0000"));
}

// Veil: a Jujutsu-style change-id header on a Git commit gives the snapshot that change id.
#[test]
fn a_change_id_header_from_git_is_honoured() {
    let env = Env::new();
    let (bare, wc) = git_upstream(&env, "gh.git", &[("a", "a\n")]);
    // Write a commit with a change-id header (as jj does) by hand.
    let tree = git(&wc, &["rev-parse", "HEAD^{tree}"]);
    let parent = git(&wc, &["rev-parse", "HEAD"]);
    let raw = format!(
        "tree {tree}\nparent {parent}\nauthor J J <jj@example.com> 1700000000 +0000\ncommitter J J <jj@example.com> 1700000000 +0000\nchange-id zzzzkkkkzzzzkkkkzzzzkkkkzzzzkkkk\n\nfrom jj\n"
    );
    let path = env.path("commit.raw");
    std::fs::write(&path, raw).unwrap();
    let id = git(
        &wc,
        &["hash-object", "-t", "commit", "-w", path.to_str().unwrap()],
    );
    git(
        &wc,
        &["push", "-q", "origin", &format!("{id}:refs/heads/main")],
    );
    let proj = import(&env, "alice", "proj", &bare);
    let show = env.stdout("alice", &proj, &["show", "main"]);
    assert!(show.contains("zzzzkkkkzzzzkkkkzzzzkkkkzzzzkkkk"), "{show}");
}

// Scenario from git t9350-fast-export.sh ("names with spaces, quotes, backslashes").
#[test]
fn names_with_quotes_and_backslashes_round_trip() {
    let env = Env::new();
    let (proj, bare) = veil_with_git_remote(&env, "alice", "proj", "gh.git");
    for name in [
        "q\"uote.txt",
        "back\\slash.txt",
        "tab\tname.txt",
        "new\nline.txt",
    ] {
        write(&proj, name, "odd\n");
    }
    env.ok("alice", &proj, &["commit", "-m", "odd names"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["git", "push"]);
    let files = git_cmd(&bare)
        .args(["ls-tree", "-r", "-z", "--name-only", "main"])
        .output()
        .unwrap()
        .stdout;
    let names: Vec<String> = files
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    for name in [
        "q\"uote.txt",
        "back\\slash.txt",
        "tab\tname.txt",
        "new\nline.txt",
    ] {
        assert!(
            names.contains(&name.to_string()),
            "{name:?} missing from {names:?}"
        );
    }
    let back = import(&env, "bob", "back", &bare);
    for name in [
        "q\"uote.txt",
        "back\\slash.txt",
        "tab\tname.txt",
        "new\nline.txt",
    ] {
        assert_eq!(read(&back, name), "odd\n", "{name:?}");
    }
}

// Scenario from git t9350-fast-export.sh with NFC and NFD spellings of one name (both
// legal on Linux): both survive, byte for byte.
#[test]
fn nfc_and_nfd_names_round_trip_byte_for_byte() {
    let env = Env::new();
    let (bare, wc) = git_upstream(&env, "gh.git", &[("a", "a\n")]);
    write(&wc, "caf\u{e9}.txt", "nfc\n");
    write(&wc, "cafe\u{301}.txt", "nfd\n");
    git_commit_push(&wc, "two cafés");
    let proj = import(&env, "alice", "proj", &bare);
    assert_eq!(read(&proj, "caf\u{e9}.txt"), "nfc\n");
    assert_eq!(read(&proj, "cafe\u{301}.txt"), "nfd\n");
    let other = env.path("other.git");
    git(
        &env.root,
        &["init", "-q", "--bare", other.to_str().unwrap()],
    );
    env.ok(
        "alice",
        &proj,
        &["git", "remote", "add", "other", other.to_str().unwrap()],
    );
    env.ok("alice", &proj, &["git", "push", "other"]);
    assert_eq!(
        git(&other, &["rev-parse", "main"]),
        git(&bare, &["rev-parse", "main"])
    );
}

// Scenario from git t9300-fast-import.sh: a symlink in Git (pending feature in Veil) is
// reported, stays in Git, and is not deleted by the next Veil push.
#[test]
fn a_git_symlink_is_reported_and_survives_a_veil_push() {
    let env = Env::new();
    let (bare, wc) = git_upstream(&env, "gh.git", &[("target.txt", "t\n")]);
    std::os::unix::fs::symlink("target.txt", wc.join("link")).unwrap();
    git_commit_push(&wc, "a symlink");
    let proj = import(&env, "alice", "proj", &bare);
    assert!(!proj.join("link").exists());
    env.ok("alice", &proj, &["new", "main"]);
    env.commit("alice", &proj, "veil edit", &[("target.txt", "t2\n")]);
    env.ok("alice", &proj, &["git", "push"]);
    let mode = git(&bare, &["ls-tree", "main", "link"]);
    assert!(
        mode.starts_with("120000"),
        "the symlink was dropped from Git: {mode:?}"
    );
}

// Veil: export of a cloaked file's public neighbour edits keeps Git history linear, and a
// re-import of Veil's own export imports nothing (export recognition).
#[test]
fn veil_never_reimports_its_own_exports() {
    let env = Env::new();
    let (proj, _bare) = veil_with_git_remote(&env, "alice", "proj", "gh.git");
    env.ok("alice", &proj, &["cloak", "secrets/"]);
    for i in 0..3 {
        env.commit(
            "alice",
            &proj,
            &format!("c{i}"),
            &[
                ("pub.txt", &format!("{i}\n")),
                ("secrets/s.txt", &format!("s{i}\n")),
            ],
        );
    }
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["git", "push"]);
    let before = changes(&env, "alice", &proj);
    let out = env.ok("alice", &proj, &["git", "pull"]);
    assert!(out.contains("Imported 0 commit(s)"), "{out}");
    assert_eq!(changes(&env, "alice", &proj), before);
}
