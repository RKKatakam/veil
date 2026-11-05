//! Attributes (design 7): a sealed `.veilattributes` and public results.

use std::path::Path;

use super::{
    adversarial_support::{read, write, Env},
    change_id, U,
};

/// Merge two public edits of `log.txt` (one line each, the same line)
/// under a `.veilattributes` holding `attributes`, cloaked for `team` when
/// `cloaked`. Returns the merged working-copy file.
fn merge_under(env: &Env, name: &str, attributes: &str, cloaked: bool) -> String {
    let proj = env.dir(name);
    env.ok(U, &proj, &["init"]);
    write(&proj, "log.txt", "a\nb\nc\n");
    write(&proj, ".veilattributes", attributes);
    if cloaked {
        env.ok(U, &proj, &["cloak", ".veilattributes"]);
    }
    env.ok(U, &proj, &["commit", "-m", "base"]);
    let base = change_id(env, U, &proj, "@-");
    write(&proj, "log.txt", "a\nOURS\nc\n");
    env.ok(U, &proj, &["commit", "-m", "ours"]);
    let ours = change_id(env, U, &proj, "@-");
    env.ok(U, &proj, &["new", &base]);
    write(&proj, "log.txt", "a\nTHEIRS\nc\n");
    env.ok(U, &proj, &["commit", "-m", "theirs"]);
    let theirs = change_id(env, U, &proj, "@-");
    env.ok(U, &proj, &["new", &ours, &theirs]);
    let tier = env.stdout(U, &proj, &["files"]);
    assert!(tier.lines().any(|l| l.starts_with("public") && l.contains(" log.txt")), "{tier}");
    read(Path::new(&proj), "log.txt")
}

/// BUG-705 (the W2 agent's suspicion, proven): the merge of a *public*
/// file depends on a *sealed* `.veilattributes`. A member merges with the
/// cloaked file's `merge=union` (a clean union of both sides, recorded
/// and published as public content); without it the same merge is a
/// conflict. The public result therefore tells every mirror reader
/// something only `team` may read ("log.txt merges by union"), and a
/// non-member merging the same history gets another result. Attributes
/// that decide public content should come only from what that audience
/// can read.
#[test]
fn a_sealed_gitattributes_does_not_decide_a_public_merge() {
    let env = Env::new();
    // Same length, so only the rule differs.
    let with = merge_under(&env, "with", "log.txt merge=union\n", true);
    let without = merge_under(&env, "without", "lag.txt merge=union\n", true);
    assert_eq!(with, without, "the sealed .veilattributes changed the public merge result");
}

/// Control: a public `.veilattributes` is meant to decide it.
#[test]
fn control_a_public_union_attribute_merges_by_union() {
    let env = Env::new();
    let merged = merge_under(&env, "public", "log.txt merge=union\n", false);
    assert_eq!(merged, "a\nOURS\nTHEIRS\nc\n");
}

/// BUG-705, the other audience: a result sealed for `team` is shaped by
/// what `team` reads, so a cloaked `.veilattributes` still decides how a
/// cloaked file merges.
#[test]
fn a_sealed_gitattributes_still_decides_a_merge_sealed_for_its_scope() {
    let env = Env::new();
    let proj = env.dir("cloaked");
    env.ok(U, &proj, &["init"]);
    write(&proj, "log.txt", "a\nb\nc\n");
    write(&proj, ".veilattributes", "log.txt merge=union\n");
    env.ok(U, &proj, &["cloak", ".veilattributes", "log.txt"]);
    env.ok(U, &proj, &["commit", "-m", "base"]);
    let base = change_id(&env, U, &proj, "@-");
    write(&proj, "log.txt", "a\nOURS\nc\n");
    env.ok(U, &proj, &["commit", "-m", "ours"]);
    let ours = change_id(&env, U, &proj, "@-");
    env.ok(U, &proj, &["new", &base]);
    write(&proj, "log.txt", "a\nTHEIRS\nc\n");
    env.ok(U, &proj, &["commit", "-m", "theirs"]);
    let theirs = change_id(&env, U, &proj, "@-");
    env.ok(U, &proj, &["new", &ours, &theirs]);
    let tier = env.stdout(U, &proj, &["files"]);
    assert!(tier.lines().any(|l| !l.starts_with("public") && l.contains(" log.txt")), "{tier}");
    assert_eq!(read(Path::new(&proj), "log.txt"), "a\nOURS\nTHEIRS\nc\n");
}
