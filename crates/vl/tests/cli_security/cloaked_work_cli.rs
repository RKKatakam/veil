//! Cloaked work and the public view, end to end through the real `vl`
//! binary (BUG-074, BUG-075), and conflicts after a merge (BUG-079,
//! BUG-080).
//!
//! * A commit in a cloaked workspace never moves an uncloaked tag, so
//!   cloaked work cannot reach `main` (and with it a public mirror) by
//!   accident.
//! * A public file edited on a cloaked line is sealed with its last public
//!   version as fallback: public remotes and readers without the key keep
//!   seeing that version. "Now sealed" never reads as
//!   "deleted".

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

/// BUG-075, the guide's repro: edit a public file in a cloaked workspace,
/// commit.
#[test]
fn a_commit_in_a_cloaked_workspace_never_moves_main() {
    let env = Env::new();
    let proj = setup(&env);
    let before = tag_target(&env, &proj, "main");

    env.ok("alice", &proj, &["ws", "new", "p", "-r", "main", "--cloak", "team"]);
    env.ok("alice", &proj, &["ws", "switch", "p"]);
    write(&proj, "README.md", "hello\nCLOAKED-EDIT-7731\n");
    let out = env.ok("alice", &proj, &["commit", "-m", "m"]);
    // BUG-075: the cloaked commit leaves `main` alone, and says so.
    assert_eq!(tag_target(&env, &proj, "main"), before, "{out}");
    assert!(out.contains("main") && out.contains("cloaked"), "commit should explain why main stayed:\n{out}");
}

/// BUG-074, public-mirror variant: a clone of a public remote keeps the
/// last public version when `main` moves onto a cloaked edit, and records
/// neither a deletion nor (it cannot read the edit) a revert.
#[test]
fn a_public_mirror_clone_keeps_the_last_public_version_of_a_cloaked_edit() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("README.md", "hello\n"), ("other.txt", "o\n")]);
    let mirror = env.root.join("mirror");
    env.ok("alice", &proj, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    env.ok("alice", &proj, &["push", "mirror", "-t", "main"]);
    env.ok("bob", &env.root, &["clone", mirror.to_str().unwrap(), "bob"]);
    let bob = env.root.join("bob");
    assert_eq!(read(&bob, "README.md"), "hello\n");

    env.ok("alice", &proj, &["ws", "new", "p", "-r", "main", "--cloak", "team"]);
    env.ok("alice", &proj, &["ws", "switch", "p"]);
    write(&proj, "README.md", "hello\nCLOAKED-EDIT-7731\n");
    env.ok("alice", &proj, &["commit", "-m", "m"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "p@-"]);
    env.ok("alice", &proj, &["push", "mirror", "-t", "main"]);

    env.ok("bob", &bob, &["pull"]);
    env.ok("bob", &bob, &["new", "main"]);
    assert_eq!(read(&bob, "README.md"), "hello\n", "the clone lost the file or saw the cloaked edit");
    env.ok("bob", &bob, &["status"]);
    let diff = env.stdout("bob", &bob, &["diff", "--stat"]);
    assert!(!diff.contains("README"), "bob's working copy records a change to README.md:\n{diff}");

    // Bob edits the file he can only see the public version of: the edit
    // cannot be recorded (it would revert Alice's sealed edit), and is
    // neither recorded as a deletion.
    write(&bob, "README.md", "hello from bob\n");
    let out = env.ok("bob", &bob, &["status"]);
    assert!(out.contains("README.md"), "{out}");
    let diff = env.stdout("bob", &bob, &["diff", "--stat"]);
    assert!(!diff.contains("README"), "bob recorded an edit over a sealed file:\n{diff}");
    env.ok("bob", &bob, &["commit", "-m", "bob"]);
    let files = env.stdout("bob", &bob, &["files", "-r", "@-"]);
    assert!(files.contains("README.md"), "{files}");
    // Alice still reads her edit in Bob's commit's tree after he pushes
    // nothing: the entry is hers, unchanged.
}

/// BUG-075: the tag-advance rule.
#[test]
fn commit_moves_only_the_tags_its_line_may_move() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    // A cloaked tag for the same scope as the workspace does follow it.
    env.ok("alice", &proj, &["tag", "set", "fix", "-r", "main", "--cloak", "team"]);
    let main0 = tag_target(&env, &proj, "main");
    env.ok("alice", &proj, &["ws", "new", "p", "-r", "main", "--cloak", "team"]);
    env.ok("alice", &proj, &["ws", "switch", "p"]);
    write(&proj, "b.txt", "b\n");
    let out = env.ok("alice", &proj, &["commit", "-m", "cloaked"]);
    assert_eq!(tag_target(&env, &proj, "main"), main0, "{out}");
    assert_ne!(tag_target(&env, &proj, "fix"), main0, "the cloaked tag should follow the cloaked line:\n{out}");

    // The common single-workspace flow is unchanged: `vl commit` moves main.
    env.ok("alice", &proj, &["ws", "switch", "default"]);
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
/// version (diff3 style). When that version was sealed for a scope and the
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
    write(&proj, "notes.txt", &format!("intro\n{BASE}\noutro\n"));
    env.ok("alice", &proj, &["cloak", "--scope", "team", "notes.txt"]);
    env.ok("alice", &proj, &["commit", "-m", "base"]);
    env.ok("alice", &proj, &["ws", "new", "b", "-r", "main"]);

    // Two lines expose the file, each editing the sealed line.
    env.ok("alice", &proj, &["expose", "notes.txt"]);
    write(&proj, "notes.txt", "intro\nSIDE-A\noutro\n");
    env.ok("alice", &proj, &["commit", "-m", "a"]);
    env.ok("alice", &proj, &["ws", "switch", "b"]);
    assert_eq!(read(&proj, "notes.txt"), format!("intro\n{BASE}\noutro\n"));
    env.ok("alice", &proj, &["expose", "notes.txt"]);
    write(&proj, "notes.txt", "intro\nSIDE-B\noutro\n");
    env.ok("alice", &proj, &["commit", "-m", "b"]);
    env.ok("alice", &proj, &["ws", "switch", "default"]);

    let out = env.ok("alice", &proj, &["merge", "b@-", "--into", "main", "-m", "merge b"]);
    let merged = env.stdout("alice", &proj, &["cat", "notes.txt", "-r", "main"]);
    assert!(merged.contains("SIDE-A") && merged.contains("SIDE-B") && merged.contains("<<<<<<<"), "{out}\n{merged}");
    assert!(!merged.contains(BASE), "the public conflict shows the sealed base:\n{merged}");

    // Published: a public remote.
    env.ok("alice", &proj, &["push", "mirror", "-t", "main"]);
    env.ok("bob", &env.root, &["clone", mirror.to_str().unwrap(), "bob"]);
    let bob = env.root.join("bob");
    let seen = env.stdout("bob", &bob, &["cat", "notes.txt", "-r", "main"]);
    assert!(seen.contains("SIDE-A") && !seen.contains(BASE), "the public mirror shows:\n{seen}");
}
