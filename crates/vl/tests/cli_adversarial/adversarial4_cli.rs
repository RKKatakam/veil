//! Round 4 adversarial tests through the real `vl` binary: `vl upgrade`
//! and the accepted-policy pin (`vl policy accept`, ARCHITECTURE §4).
//!
//! Every `#[ignore = "BUG-NNN: …"]` test demonstrates a bug listed in
//! `docs/BUGS.md` ("Round 4 findings"); the others are controls.

use crate::adversarial_support;
#[allow(unused_imports)]
#[path = "../../../veil-core/tests/adversarial_support/mod.rs"]
mod core_support;

use std::path::{Path, PathBuf};

use adversarial_support::*;

fn fixture(format: u32) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../veil-core/tests/fixtures/format-{format}"))
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dst = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dst);
        } else {
            std::fs::copy(e.path(), &dst).unwrap();
        }
    }
}

fn format_of(repo: &Path) -> u64 {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(repo.join(".veil/repo.json")).unwrap()).unwrap();
    v["format"].as_u64().unwrap()
}

/// `vl files -r <rev>` as (path, tier label) pairs.
fn recorded(env: &Env, user: &str, proj: &Path, rev: &str) -> Vec<(String, String)> {
    env.stdout(user, proj, &["files", "-r", rev])
        .lines()
        .filter_map(|l| {
            let tier = l.split_whitespace().next()?.to_string();
            let path = l.rsplit("  ").next()?.trim().to_string();
            Some((path, tier))
        })
        .collect()
}

fn tier_of<'a>(files: &'a [(String, String)], path: &str) -> Option<&'a str> {
    files.iter().find(|(p, _)| p.ends_with(path)).map(|(_, t)| t.as_str())
}

fn public_key(env: &Env, user: &str) -> String {
    let out = env.ok(user, &env.root, &["identity", "show"]);
    out.lines()
        .find(|l| l.starts_with("public key"))
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap()
        .to_string()
}

// ---- vl upgrade --remote ---------------------------------------------------

/// `vl upgrade --remote <name>` turns the remote's URL into a local path
/// without asking whether it is an SSH remote (`remote_backend`, which every
/// other command uses, does). For `host:path` or `sftp://host/path` it opens
/// `<project>/host:path` instead: an error at best, and here a decoy
/// repository at that path is "upgraded" and the command reports success,
/// while the real remote stays at format 2 and keeps refusing AES-SIV
/// objects and HPKE rings.
#[test]
fn upgrade_remote_does_not_treat_an_ssh_url_as_a_local_path() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("fx");
    copy_dir(&fixture(2), &root);
    let alice = root.join("alice");
    let home = root.join("home-alice");
    let vl = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_vl"))
            .args(args)
            .current_dir(&alice)
            .env("VEIL_HOME", &home)
            .env("VEIL_USER", "alice")
            .env("NO_COLOR", "1")
            .output()
            .unwrap()
    };
    // An SSH remote whose host does not resolve (nothing can be upgraded).
    let url = "nobody@veil-test.invalid:srv/team.veil";
    let out = vl(&["remote", "add", "build", url]);
    assert!(out.status.success(), "{}", text(&out));
    // A decoy repository where the URL lands when read as a relative path.
    let decoy = alice.join("nobody@veil-test.invalid:srv/team.veil");
    copy_dir(&root.join("team-remote"), &decoy);
    assert_eq!(format_of(&decoy), 2);

    let out = vl(&["upgrade", "--remote", "build"]);
    let said = text(&out);
    assert!(
        !out.status.success() && format_of(&decoy) == 2,
        "`vl upgrade --remote build` ({url}) acted on the local directory {}: success = {}, decoy now at format {}\n{said}",
        decoy.display(),
        out.status.success(),
        format_of(&decoy)
    );
}

// ---- the accepted policy: the member's own edit -----------------------------

/// Bob, alice and a team remote; `.veilpolicy` isolates `notes/private.md`,
/// and Bob has that file locally.
fn team_with_private_notes(env: &Env) -> (PathBuf, PathBuf) {
    let alice = env.dir("alice");
    write(&alice, ".veilpolicy", "notes/private.md isolate\n");
    write(&alice, "README.md", "hello\n");
    env.ok("alice", &alice, &["init"]);
    env.ok("alice", &alice, &["commit", "-m", "v1"]);
    env.ok("alice", &alice, &["tag", "set", "main", "-r", "@-"]);
    let team = env.root.join("team");
    env.ok("alice", &alice, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &alice, &["push"]);
    let bob_key = public_key(env, "bob");
    env.ok("alice", &alice, &["scope", "grant", "team", &bob_key, "--name", "bob"]);
    env.ok("alice", &alice, &["push"]);
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    let bob = env.root.join("bob");
    write(&bob, "notes/private.md", "bob's private notes: salary review, health\n");
    env.ok("bob", &bob, &["status"]);
    (alice, bob)
}

/// Alice publishes a new `.veilpolicy` and Bob checks it out.
fn alice_publishes_policy(env: &Env, alice: &Path, bob: &Path, policy: &str) {
    write(alice, ".veilpolicy", policy);
    env.ok("alice", alice, &["commit", "-m", "policy"]);
    env.ok("alice", alice, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", alice, &["push"]);
    env.ok("bob", bob, &["pull"]);
    env.ok("bob", bob, &["new", "origin/main"]);
    assert_eq!(read(bob, ".veilpolicy"), policy, "the policy reached Bob's working copy");
}

/// Control: Bob edits the policy himself while nothing is pending. He puts
/// a general rule *above* the exception for his file. His whole file is
/// accepted, in his order, so a later policy from Alice that drops the
/// exception is held back.
#[test]
fn a_members_reordered_edit_is_accepted_in_their_order() {
    let env = Env::new();
    let (alice, bob) = team_with_private_notes(&env);
    write(&bob, ".veilpolicy", "notes/** public\nnotes/private.md isolate\n");
    env.ok("bob", &bob, &["commit", "-m", "notes are public, except mine"]);
    assert_eq!(tier_of(&recorded(&env, "bob", &bob, "@-"), "notes/private.md"), None);

    alice_publishes_policy(&env, &alice, &bob, "notes/** public\n");
    let out = env.ok("bob", &bob, &["commit", "-m", "work"]);
    assert_eq!(tier_of(&recorded(&env, "bob", &bob, "@-"), "notes/private.md"), None, "{out}");
}

/// The same edit while a teammate's change is pending (any change Bob has
/// not accepted, here an unrelated `.env public!`). "Exactly his edit" is
/// applied to the accepted policy. It used to be applied by *appending* the
/// rules he added (BUG-073): Bob wrote `notes/** public` above his
/// exception, in the accepted policy it landed below it and overrode it, so
/// the accepted policy said `notes/private.md` is public. When Alice's next
/// policy dropped the exception, Bob's private notes were recorded in
/// plaintext and pushed, with no warning and no `vl policy accept`. Now his
/// rule keeps its place (`policy::fold_edit`).
#[test]
fn a_members_edit_during_a_pending_change_keeps_their_rule_order() {
    let env = Env::new();
    let (alice, bob) = team_with_private_notes(&env);
    // Pending (not accepted by Bob): Alice publishes `.env`.
    alice_publishes_policy(&env, &alice, &bob, "notes/private.md isolate\n.env public!\n");
    let status = env.ok("bob", &bob, &["policy", "show"]);
    assert!(status.contains("notes/private.md"), "{status}");

    // Bob's own edit: a general rule above the exception for his file.
    write(&bob, ".veilpolicy", "notes/** public\nnotes/private.md isolate\n.env public!\n");
    env.ok("bob", &bob, &["commit", "-m", "notes are public, except mine"]);
    assert_eq!(tier_of(&recorded(&env, "bob", &bob, "@-"), "notes/private.md"), None, "control");

    // Alice later drops the exception (it was Bob's file, not hers).
    alice_publishes_policy(&env, &alice, &bob, "notes/** public\n.env public!\n");
    let out = env.ok("bob", &bob, &["commit", "-m", "work"]);
    env.ok("bob", &bob, &["tag", "set", "bob-work", "-r", "@-"]);
    // Only Bob's work: `main` has diverged on the remote, and since the
    // CLI polish wave a push with a rejected tag exits non-zero (BUG-081).
    env.ok("bob", &bob, &["push", "origin", "-t", "bob-work"]);
    let files = recorded(&env, "bob", &bob, "@-");
    let leaked = veil_core_backend_contains(&env.root.join("team"), b"salary review");
    assert!(
        tier_of(&files, "notes/private.md").is_none() && !leaked,
        "Bob's isolated notes/private.md was recorded as {:?} without `vl policy accept` (on the team remote: {leaked})\n{out}",
        tier_of(&files, "notes/private.md")
    );
}

/// Leak check on a repository directory, through the decoded pack contents
/// (`adversarial_support::backend_contains` of the engine's suites).
fn veil_core_backend_contains(dir: &Path, needle: &[u8]) -> bool {
    !core_support::backend_contains(&veil_core::DiskBackend::new(dir), needle).is_empty()
}
