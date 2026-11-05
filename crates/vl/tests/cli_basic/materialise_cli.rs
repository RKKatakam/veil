//! The working copy remembers what it could not materialise (files hidden
//! for lack of a key, an embargoed merge shown as its pre-merge tree) and
//! fills it in once it becomes readable, instead of recording it as deleted
//! or reverted. Both flows run through the real `vl` binary.

use crate::adversarial_support;

use std::path::Path;

use adversarial_support::*;

fn public_key(env: &Env, user: &str) -> String {
    env.ok(user, &env.root, &["identity", "show"])
        .lines()
        .find(|l| l.starts_with("public key"))
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap()
        .to_string()
}

/// `vl files -r <rev>` paths.
fn files(env: &Env, user: &str, dir: &Path, rev: &str) -> Vec<String> {
    env.stdout(user, dir, &["files", "-r", rev])
        .lines()
        .filter_map(|l| l.rsplit("  ").next().map(|p| p.trim().trim_end_matches(" (redacted)").to_string()))
        .collect()
}

/// What `vl diff` reports for the working-copy change (against its parent).
fn wc_diff(env: &Env, user: &str, dir: &Path) -> String {
    env.stdout(user, dir, &["diff", "--stat"])
}

fn embargo_id(env: &Env, user: &str, dir: &Path) -> String {
    env.stdout(user, dir, &["embargo", "list"])
        .split_whitespace()
        .next()
        .expect("an embargo")
        .to_string()
}

/// Onboarding: Bob clones the team remote before he is granted the scope,
/// then is granted and pulls. The cloaked files appear, and no snapshot
/// along the way records them as deleted.
#[test]
fn cloaked_files_appear_after_a_grant_and_are_never_recorded_as_deleted() {
    let env = Env::new();
    let proj = env.project(
        "alice",
        "proj",
        &[(".veilpolicy", "internal/ cloak team\n"), ("internal/plan.md", "the plan\n"), ("internal/deep/notes.md", "notes\n"), ("README", "hi\n")],
    );
    let team = env.root.join("team");
    env.ok("alice", &proj, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &proj, &["push", "-t", "main"]);

    let out = env.ok("bob", &env.root, &["clone", "team", "bob"]);
    assert!(out.contains("2 cloaked file(s)"), "{out}");
    let bob = env.root.join("bob");
    assert!(!bob.join("internal/plan.md").exists());
    // Bob works meanwhile: the hidden files are carried, not deleted.
    write(&bob, "README", "hi from bob\n");
    env.ok("bob", &bob, &["status"]);
    env.ok("bob", &bob, &["commit", "-m", "bob's readme"]);
    let bob_files = files(&env, "bob", &bob, "@-");
    assert!(bob_files.iter().any(|p| p == "internal/plan.md"), "{bob_files:?}");

    // Granted; Alice pushes the new key ring; Bob pulls.
    let key = public_key(&env, "bob");
    env.ok("alice", &proj, &["scope", "grant", "team", &key, "--name", "bob"]);
    env.ok("alice", &proj, &["push", "-t", "main"]);
    let out = env.ok("bob", &bob, &["pull"]);
    assert_eq!(read(&bob, "internal/plan.md"), "the plan\n", "pull output:\n{out}");
    assert_eq!(read(&bob, "internal/deep/notes.md"), "notes\n");
    assert_eq!(read(&bob, "README"), "hi from bob\n");

    // Nothing recorded as deleted: not by the pull, not by later commands.
    env.ok("bob", &bob, &["status"]);
    let diff = wc_diff(&env, "bob", &bob);
    assert!(!diff.contains("internal"), "the working-copy change touches the cloaked files:\n{diff}");
    let diff = env.stdout("bob", &bob, &["diff", "--stat", "-r", "@-"]);
    assert!(!diff.contains("internal") && diff.contains("README"), "bob's commit:\n{diff}");
    for rev in ["@", "@-"] {
        let f = files(&env, "bob", &bob, rev);
        assert!(
            f.iter().any(|p| p == "internal/plan.md") && f.iter().any(|p| p == "internal/deep/notes.md"),
            "{rev}: {f:?}"
        );
    }
    let checkout = read(&bob, ".veil/local/checkout.json");
    assert!(!checkout.contains("hidden"), "the record still lists hidden files: {checkout}");
}

/// The record survives Bob working while he cannot read, and his own file at
/// a hidden path is never overwritten when access arrives.
#[test]
fn a_local_file_at_a_hidden_path_is_not_overwritten_when_access_arrives() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[(".veilpolicy", "internal/ cloak team\n"), ("internal/plan.md", "the plan\n")]);
    let team = env.root.join("team");
    env.ok("alice", &proj, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &proj, &["push", "-t", "main"]);
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    let bob = env.root.join("bob");
    let key = public_key(&env, "bob");
    env.ok("alice", &proj, &["scope", "grant", "team", &key, "--name", "bob"]);
    env.ok("alice", &proj, &["push", "-t", "main"]);

    // Bob writes his own file there before he pulls, without a command in
    // between (so no snapshot sees it while the entry is unreadable).
    write(&bob, "internal/plan.md", "bob's own plan\n");
    let out = env.ok("bob", &bob, &["pull"]);
    assert_eq!(read(&bob, "internal/plan.md"), "bob's own plan\n", "{out}");
}

/// An embargoed merge checked out without the key shows the pre-merge
/// tree. After the release and a pull, the fix's added file appears and the
/// modified file switches to the released content; nothing is recorded as
/// deleted or reverted.
#[test]
fn an_embargoed_merge_is_filled_in_after_its_release() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("auth.rs", "fn check() -> bool { true }\n"), ("README", "hi\n")]);
    env.ok("alice", &proj, &["ws", "new", "fix", "-r", "main"]);
    env.ok(
        "alice",
        &proj,
        &[
            "ws",
            "exec",
            "fix",
            "-m",
            "fix",
            "--",
            "sh",
            "-c",
            "printf 'fn check() -> bool { verify() }\\n' > auth.rs && mkdir -p src && printf 'fn verify() -> bool { false }\\n' > src/verify.rs",
        ],
    );
    env.ok("alice", &proj, &["merge", "fix@", "--into", "main", "--embargo", "-m", "Fix the auth bypass"]);
    let mirror = env.root.join("mirror");
    env.ok("alice", &proj, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    env.ok("alice", &proj, &["push", "mirror", "-t", "main"]);

    // Carol only reads the public mirror: she sees the pre-merge tree.
    env.ok("carol", &env.root, &["clone", "mirror", "carol"]);
    let carol = env.root.join("carol");
    assert_eq!(read(&carol, "auth.rs"), "fn check() -> bool { true }\n");
    assert!(!carol.join("src/verify.rs").exists());
    write(&carol, "README", "hi from carol\n");
    env.ok("carol", &carol, &["status"]);

    let id = embargo_id(&env, "alice", &proj);
    env.ok("alice", &proj, &["embargo", "release", &id, "--yes"]);
    env.ok("alice", &proj, &["push", "mirror", "-t", "main"]);
    let out = env.ok("carol", &carol, &["pull"]);
    assert_eq!(read(&carol, "auth.rs"), "fn check() -> bool { verify() }\n", "pull output:\n{out}");
    assert_eq!(read(&carol, "src/verify.rs"), "fn verify() -> bool { false }\n");
    assert_eq!(read(&carol, "README"), "hi from carol\n");

    env.ok("carol", &carol, &["status"]);
    let diff = wc_diff(&env, "carol", &carol);
    assert!(
        !diff.contains("auth.rs") && !diff.contains("verify.rs"),
        "the working-copy change reverts or deletes the released fix:\n{diff}"
    );
    let f = files(&env, "carol", &carol, "@");
    assert!(f.iter().any(|p| p == "src/verify.rs"), "{f:?}");
    assert_eq!(env.stdout("carol", &carol, &["cat", "auth.rs", "-r", "@"]), "fn check() -> bool { verify() }\n");
}

/// A local edit made while the embargo hid the fix is kept when the release
/// arrives (and recorded on top of the fix, not as a revert).
#[test]
fn a_local_edit_over_an_embargo_fallback_survives_the_release() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("auth.rs", "v1\n"), ("README", "hi\n")]);
    env.ok("alice", &proj, &["ws", "new", "fix", "-r", "main"]);
    env.ok("alice", &proj, &["ws", "exec", "fix", "-m", "fix", "--", "sh", "-c", "printf 'v2\\n' > auth.rs && printf 'new\\n' > added.rs"]);
    env.ok("alice", &proj, &["merge", "fix@", "--into", "main", "--embargo", "-m", "fix"]);
    let mirror = env.root.join("mirror");
    env.ok("alice", &proj, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    env.ok("alice", &proj, &["push", "mirror", "-t", "main"]);
    env.ok("carol", &env.root, &["clone", "mirror", "carol"]);
    let carol = env.root.join("carol");

    // Carol edits the file the embargo hides: held back with its own message.
    write(&carol, "auth.rs", "carol's v1 edit\n");
    let out = env.ok("carol", &carol, &["status"]);
    assert!(out.contains("not recorded: this line is under embargo"), "{out}");
    assert!(!out.contains("could not cloak"), "{out}");

    let id = embargo_id(&env, "alice", &proj);
    env.ok("alice", &proj, &["embargo", "release", &id, "--yes"]);
    env.ok("alice", &proj, &["push", "mirror", "-t", "main"]);
    env.ok("carol", &carol, &["pull"]);
    assert_eq!(read(&carol, "auth.rs"), "carol's v1 edit\n", "the local edit was overwritten");
    assert_eq!(read(&carol, "added.rs"), "new\n");
    env.ok("carol", &carol, &["status"]);
    assert_eq!(env.stdout("carol", &carol, &["cat", "auth.rs", "-r", "@"]), "carol's v1 edit\n");
    assert!(files(&env, "carol", &carol, "@").iter().any(|p| p == "added.rs"));
}
