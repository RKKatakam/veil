//! Embargo confinement (`veil_core::confinement`, BUG-681) and sealed
//! content on public lines.

use std::process::Command;

use crate::{
    adversarial_support::{text, write, Env},
    change_id, repo_contains, ws_write, U,
};

/// A patch made with Git from `before` to `after` of `vuln.c` (its `index`
/// line names the Git blob of `before`).
fn git_patch(env: &Env, before: &str, after: &str) -> std::path::PathBuf {
    let g = env.dir("git-src");
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .args(["-c", "user.name=Bob", "-c", "user.email=bob@example.com"])
            .args(args)
            .current_dir(&g)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", &g)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        out.stdout
    };
    git(&["init", "-q"]);
    write(&g, "vuln.c", before);
    git(&["add", "vuln.c"]);
    git(&["commit", "-qm", "base"]);
    write(&g, "vuln.c", after);
    git(&["commit", "-qam", "follow-up"]);
    let patch = git(&["format-patch", "-1", "--stdout"]);
    let p = env.root.join("follow.patch");
    std::fs::write(&p, patch).unwrap();
    p
}

/// BUG-706: `vl am --3way` looks for the pre-image a patch's `index` line
/// names in the history of *every* visible head (`patch::Preimages`),
/// the withheld fix of an unreleased embargo included, and records a
/// conflict whose base term is the fix's version, onto any destination:
/// `confinement` (BUG-681) is not consulted. A follow-up patch made on
/// top of the fix (by a co-holder, in Git) and applied with `--3way` to a
/// line outside the embargo therefore copies the fix's `vuln.c` into a
/// public change; the next public push publishes it (sealed under the
/// embargo key: the mirror learns that the embargo changed `vuln.c` and
/// receives the fix's ciphertext before the release, readable by everyone
/// the moment it is released, whatever the destination line says).
#[test]
#[ignore = "BUG-706: vl am --3way takes the embargoed fix's version as a base on a public line (confinement bypass)"]
fn am_three_way_never_copies_the_withheld_fix_onto_a_public_line() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("vuln.c", "int a;\nint b;\n")]);
    let init = change_id(&env, U, &proj, "main");
    env.ok(U, &proj, &["ws", "new", "fix", "-r", "main"]);
    ws_write(&env, &proj, "fix", "vuln.c", "int a;\nint FIXED_LINE;\n");
    env.ok(U, &proj, &["describe", "-r", "fix@", "-m", "fix"]);
    env.ok(U, &proj, &["merge", "fix@", "--into", "main", "--embargo", "-m", "embargoed"]);
    // A public line that is not under the embargo.
    env.ok(U, &proj, &["ws", "new", "other", "-r", &init]);
    let patch = git_patch(&env, "int a;\nint FIXED_LINE;\n", "int a;\nint FOLLOW_UP;\n");
    let am = env.vl(U, &proj, &["am", "--3way", "-d", "other@-", patch.to_str().unwrap()]);
    if !am.status.success() {
        return; // refused: fine
    }
    // "Applied 1 patch(es):\n  <change> <snapshot> follow-up"
    let new = text(&am).lines().find_map(|l| {
        l.split_whitespace().next().filter(|w| w.len() == 8 && w.chars().all(|c| c.is_ascii_lowercase())).map(str::to_string)
    });
    let new = new.unwrap_or_else(|| panic!("no new change in: {}", text(&am)));
    env.ok(U, &proj, &["tag", "set", "followup", "-r", &new]);
    let mirror = env.root.join("mirror");
    env.ok(U, &proj, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    env.ok(U, &proj, &["push", "mirror"]);
    env.ok("carol", &env.root, &["clone", "mirror", "carol"]);
    let carol = env.root.join("carol");
    let list = text(&env.vl("carol", &carol, &["resolve", "--list", "-r", "followup"]));
    assert!(
        !list.contains("embargo"),
        "the public change made by `vl am --3way` carries the embargoed fix's version of vuln.c:\n{list}"
    );
}

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
