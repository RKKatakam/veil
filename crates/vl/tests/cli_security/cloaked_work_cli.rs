//! The tag-advance rule (BUG-075) end to end through the real `vl`
//! binary, and conflicts after a merge (BUG-079, BUG-080, BUG-126).

use crate::adversarial_support;

use std::path::Path;

use adversarial_support::*;

/// Target of tag `name` as `vl tag list` prints it (change id + snapshot).
fn tag_target(env: &Env, dir: &Path, name: &str) -> String {
    env.stdout("alice", dir, &["tag", "list"])
        .lines()
        .find_map(|l| {
            let (n, target) = l.split_once(": ")?;
            (n.split(' ').next() == Some(name)).then(|| target.to_string())
        })
        .unwrap_or_else(|| panic!("no tag {name}"))
}

/// Alice's project: README.md public, tagged `main`.
fn setup(env: &Env) -> std::path::PathBuf {
    env.project("alice", "proj", &[("README.md", "hello\n")])
}

/// BUG-075: the tag-advance rule.
#[test]
fn commit_moves_only_the_tags_its_line_may_move() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    let main0 = tag_target(&env, &proj, "main");

    // The common single-workspace flow: `vl commit` moves main.
    write(&proj, "c.txt", "c\n");
    env.ok("alice", &proj, &["commit", "-m", "public"]);
    let main1 = tag_target(&env, &proj, "main");
    assert_ne!(main1, main0);
    assert!(main1.contains("public"), "{main1}");

    // `--no-advance` keeps every tag where it is.
    write(&proj, "d.txt", "d\n");
    let out = env.ok("alice", &proj, &["commit", "-m", "later", "--no-advance"]);
    assert_eq!(tag_target(&env, &proj, "main"), main1, "{out}");
}

/// Two lines that both edit `a.txt`, merged: the merge records a conflict.
/// Returns the project, with `@` the empty change on top of the merge.
fn conflicted_merge(env: &Env) -> std::path::PathBuf {
    let proj = env.project("alice", "proj", &[("a.txt", "base\n"), ("b.txt", "b\n")]);
    env.ok("alice", &proj, &["ws", "new", "other", "-r", "main"]);
    let mut c = env.cmd("alice", &proj, &["ws", "write", "other", "a.txt"]);
    c.stdin(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(b"theirs\n").unwrap();
    assert!(child.wait().unwrap().success());
    env.ok("alice", &proj, &["describe", "-r", "other@", "-m", "theirs"]);
    write(&proj, "a.txt", "ours\n");
    env.ok("alice", &proj, &["commit", "-m", "ours"]);
    let out = env.ok("alice", &proj, &["merge", "other@", "-m", "merge"]);
    assert!(out.contains("conflicts in: a.txt"), "{out}");
    proj
}

/// BUG-079: `vl status` shows the merge's unresolved conflicts, which are
/// recorded on `@-`, until the file is edited.
#[test]
fn status_shows_the_unresolved_conflicts_of_the_merge_below() {
    let env = Env::new();
    let proj = conflicted_merge(&env);
    let out = env.ok("alice", &proj, &["status"]);
    assert!(out.contains("Unresolved conflicts"), "{out}");
    assert!(out.lines().any(|l| l.trim_start().starts_with("C a.txt")), "{out}");
    assert!(!out.lines().any(|l| l.trim_start().starts_with("C b.txt")), "{out}");
    assert!(out.contains("hint"), "{out}");

    write(&proj, "a.txt", "resolved\n");
    let out = env.ok("alice", &proj, &["status"]);
    assert!(!out.contains("Unresolved conflicts"), "{out}");
}

/// BUG-080: squashing the resolution into the merge clears its conflict;
/// squashing something that leaves the conflict in place keeps it.
#[test]
fn squashing_a_resolution_into_the_merge_clears_the_conflict() {
    let env = Env::new();
    let proj = conflicted_merge(&env);
    // A change that does not touch a.txt: the conflict stays.
    write(&proj, "b.txt", "b2\n");
    env.ok("alice", &proj, &["squash"]);
    let log = env.stdout("alice", &proj, &["log", "-n", "3"]);
    assert!(log.contains("(conflict)"), "{log}");

    write(&proj, "a.txt", "resolved\n");
    env.ok("alice", &proj, &["squash"]);
    let log = env.stdout("alice", &proj, &["log", "-n", "3"]);
    assert!(!log.contains("(conflict)"), "{log}");
    let out = env.ok("alice", &proj, &["status"]);
    assert!(!out.contains("Unresolved conflicts"), "{out}");
}

/// BUG-126: the conflict markers of a merge include the merge base's
/// version (diff3 style). When that version was sealed (a secret file) for a scope and the
/// merged file is public (here both sides exposed it independently, each
/// with its own edit of the same line), the base's text must not reach the
/// public result: not the snapshot, not a public remote.
#[test]
fn a_conflict_never_shows_a_base_sealed_for_another_audience() {
    const BASE: &str = "TEAM-ONLY-BASE-8841";
    let env = Env::new();
    let proj = setup(&env);
    let mirror = env.root.join("mirror");
    env.ok("alice", &proj, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    write(&proj, ".env.notes", &format!("intro\n{BASE}\noutro\n"));
    env.ok("alice", &proj, &["cloak", "--scope", "team", ".env.notes"]);
    env.ok("alice", &proj, &["commit", "-m", "base"]);
    env.ok("alice", &proj, &["ws", "new", "b", "-r", "main"]);

    // Two lines expose the file, each editing the sealed line.
    env.ok("alice", &proj, &["expose", "--force", ".env.notes"]);
    write(&proj, ".env.notes", "intro\nSIDE-A\noutro\n");
    env.ok("alice", &proj, &["commit", "-m", "a"]);
    env.ok("alice", &proj, &["ws", "switch", "b"]);
    assert_eq!(read(&proj, ".env.notes"), format!("intro\n{BASE}\noutro\n"));
    env.ok("alice", &proj, &["expose", "--force", ".env.notes"]);
    write(&proj, ".env.notes", "intro\nSIDE-B\noutro\n");
    env.ok("alice", &proj, &["commit", "-m", "b"]);
    env.ok("alice", &proj, &["ws", "switch", "default"]);

    let out = env.ok("alice", &proj, &["merge", "b@-", "--into", "main", "-m", "merge b"]);
    let merged = env.stdout("alice", &proj, &["cat", ".env.notes", "-r", "main"]);
    assert!(merged.contains("SIDE-A") && merged.contains("SIDE-B") && merged.contains("<<<<<<<"), "{out}\n{merged}");
    assert!(!merged.contains(BASE), "the public conflict shows the sealed base:\n{merged}");

    // Published: a public remote.
    env.ok("alice", &proj, &["push", "mirror", "-t", "main"]);
    env.ok("bob", &env.root, &["clone", mirror.to_str().unwrap(), "bob"]);
    let bob = env.root.join("bob");
    let seen = env.stdout("bob", &bob, &["cat", ".env.notes", "-r", "main"]);
    assert!(seen.contains("SIDE-A") && !seen.contains(BASE), "the public mirror shows:\n{seen}");
}
