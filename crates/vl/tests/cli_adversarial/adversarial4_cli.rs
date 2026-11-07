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
