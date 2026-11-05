//! Embargo confinement (`veil_core::confinement`, BUG-681) and sealed
//! content on public lines.

use super::{
    adversarial_support::{write, Env},
    change_id, repo_contains, ws_write, U,
};

/// BUG-682 (pinned; found by `adversarial7::rewrites` in fix wave 1): a
/// draft in `@` that no public remote has seen, squashed into the cloaked
/// change `sec@` (sealed content from then on), reaches the public mirror
/// as plaintext with the next push. The sequence is the property test's
/// `[Draft(0,true), Draft(0,false), SquashIntoSealed(false,None),
/// SquashIntoSealed(true,None)]`, with its publish step after each.
#[test]
fn a_draft_squashed_into_a_cloaked_change_stays_off_the_mirror() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "one\ntwo\nthree\n"), ("b.txt", "b\n")]);
    env.ok(U, &proj, &["tag", "set", "base", "-r", "main"]);
    env.ok(U, &proj, &["ws", "new", "sec", "-r", "base", "--cloak", "team"]);
    let mirror = env.root.join("pub");
    env.ok(U, &proj, &["remote", "add", "pub", mirror.to_str().unwrap(), "--public"]);
    let publish = |env: &Env| {
        for (t, r) in [("w1", "@-"), ("w2", "@--"), ("s", "sec@")] {
            let _ = env.vl(U, &proj, &["tag", "set", t, "-r", r, "--allow-backwards"]);
        }
        env.ok(U, &proj, &["push", "pub", "--force"]);
    };
    write(&proj, "a.txt", "one\nDRAFT-0001\nthree\n");
    env.ok(U, &proj, &["commit", "--no-advance", "-m", "draft"]);
    publish(&env);
    write(&proj, "a.txt", "one\nDRAFT-0002\nthree\n");
    publish(&env);
    let _ = env.vl(U, &proj, &["squash", "-r", "@-", "--into", "sec@"]);
    publish(&env);
    assert!(repo_contains(&mirror, b"DRAFT-0002").is_empty(), "control: the draft is not public yet");
    let _ = env.vl(U, &proj, &["squash", "-r", "@", "--into", "sec@"]);
    // The draft is now sealed content of the cloaked change.
    let sec = env.stdout(U, &proj, &["cat", "-r", "sec@", "a.txt"]);
    assert!(sec.contains("DRAFT-0002"), "{sec}");
    let files = env.stdout(U, &proj, &["files", "-r", "sec@"]);
    assert!(files.lines().any(|l| l.starts_with("cloaked:team") && l.ends_with("a.txt")), "{files}");
    publish(&env);
    let hits = repo_contains(&mirror, b"DRAFT-0002");
    assert!(hits.is_empty(), "the draft sealed into sec@ is on the public mirror: {hits:?}");
}

/// BUG-707 (BUG-682's root cause by another command): `vl duplicate` of a
/// public change no remote has seen onto a cloaked line seals what the
/// line introduces (design 1, threat 13), but the sealed entry's fallback
/// (what readers without the key are shown) is the duplicated content
/// itself: `merge::merged_visibility` (`public_other`) takes the public
/// side of the merge as "the newest public version". Pushing the cloaked
/// line publishes the draft in plaintext as that fallback.
#[test]
fn a_draft_duplicated_onto_a_cloaked_line_stays_off_the_mirror() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "1\n2\n3\n4\n5\n6\n7\n8\n9\n")]);
    env.ok(U, &proj, &["ws", "new", "sec", "-r", "main", "--cloak", "team"]);
    ws_write(&env, &proj, "sec", "a.txt", "1\n2\n3\n4\n5\n6\n7\n8\nSEALED-9\n");
    let mirror = env.root.join("pub");
    env.ok(U, &proj, &["remote", "add", "pub", mirror.to_str().unwrap(), "--public"]);
    env.ok(U, &proj, &["tag", "set", "s", "-r", "sec@"]);
    env.ok(U, &proj, &["push", "pub"]);
    // A public draft, committed but never pushed.
    write(&proj, "a.txt", "DRAFT-0001\n2\n3\n4\n5\n6\n7\n8\n9\n");
    env.ok(U, &proj, &["commit", "--no-advance", "-m", "draft"]);
    let draft = change_id(&env, U, &proj, "@-");
    let out = env.ok(U, &proj, &["duplicate", &draft, "-d", "sec@"]);
    // "        as <change> <snapshot> draft"
    let dup = out
        .lines()
        .find_map(|l| l.trim().strip_prefix("as ").and_then(|r| r.split_whitespace().next()).map(str::to_string))
        .unwrap_or_else(|| panic!("no duplicate in: {out}"));
    let files = env.stdout(U, &proj, &["files", "-r", &dup]);
    assert!(files.lines().any(|l| l.starts_with("cloaked:team") && l.ends_with("a.txt")), "{files}");
    env.ok(U, &proj, &["tag", "set", "s2", "-r", &dup]);
    env.ok(U, &proj, &["push", "pub"]);
    let hits = repo_contains(&mirror, b"DRAFT-0001");
    assert!(hits.is_empty(), "the draft the cloaked line took in is on the public mirror: {hits:?}");
}
