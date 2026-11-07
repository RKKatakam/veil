//! Attributes (design 7): a `.veilattributes` and the results it shapes.

use std::path::Path;

use super::{
    adversarial_support::{read, write, Env},
    change_id, U,
};

/// Merge two public edits of `log.txt` (one line each, the same line)
/// under a `.veilattributes` holding `attributes`. Returns the merged
/// working-copy file.
fn merge_under(env: &Env, name: &str, attributes: &str) -> String {
    let proj = env.dir(name);
    env.ok(U, &proj, &["init"]);
    write(&proj, "log.txt", "a\nb\nc\n");
    write(&proj, ".veilattributes", attributes);
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

/// Control: a public `.veilattributes` is meant to decide it.
#[test]
fn control_a_public_union_attribute_merges_by_union() {
    let env = Env::new();
    let merged = merge_under(&env, "public", "log.txt merge=union\n");
    assert_eq!(merged, "a\nOURS\nTHEIRS\nc\n");
}
