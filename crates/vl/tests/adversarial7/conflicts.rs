//! First-class conflicts (format 4) meeting the commands that move content
//! between audiences: `vl squash` into a cloaked change, `vl restore`.

use crate::{
    adversarial_support::{read, write, Env},
    all_files, change_of, publish, sealed_conflict, ws_write, U,
};

// ---- squash into a cloaked change ---------------------------------------------

/// A public change `X` (line 2 = `NEWTEXT-PUBLIC-X`) rebased onto the
/// working-copy change of the cloaked workspace `sec`, which rewrote line 2
/// too when `conflict`; then squashed into it. Returns the project.
fn squash_public_work_into_cloaked_change(env: &Env, conflict: bool) -> std::path::PathBuf {
    let proj = env.project(U, "proj", &[("a.txt", "one\ntwo\nthree\n")]);
    env.ok(U, &proj, &["ws", "new", "sec", "-r", "main", "--cloak", "team"]);
    if conflict {
        ws_write(env, &proj, "sec", "a.txt", "one\nSEALED-Y\nthree\n");
    } else {
        ws_write(env, &proj, "sec", "y.txt", "SEALED-Y\n");
    }
    write(&proj, "a.txt", "one\nNEWTEXT-PUBLIC-X\nthree\n");
    env.ok(U, &proj, &["commit", "--no-advance", "-m", "X"]);
    let x = change_of(env, &proj, "X");
    env.ok(U, &proj, &["rebase", "-s", &x, "-d", "sec@"]);
    let out = env.ok(U, &proj, &["squash", "-r", &x, "--into", "sec@"]);
    assert!(out.contains("Squashed into"), "{out}");
    proj
}

/// Control: `vl squash --help` says "Squashing into a cloaked change seals
/// what it brings for that change's scope", and it does for a file: pushed
/// to a public remote, `NEWTEXT-PUBLIC-X` stays withheld.
#[test]
fn squash_into_a_cloaked_change_seals_a_public_edit() {
    let env = Env::new();
    let proj = squash_public_work_into_cloaked_change(&env, false);
    let files = env.stdout(U, &proj, &["files", "-r", "sec@"]);
    assert!(files.lines().any(|l| l.starts_with("cloaked:team") && l.ends_with("a.txt")), "{files}");
    let carol = publish(&env, &proj, "sec@", "feat");
    assert!(!all_files(&carol).contains("NEWTEXT-PUBLIC-X"));
}

/// The same squash when the moved file is a conflict entry (the rebase made
/// one: "ours" sealed for `team`, "theirs" the public edit). `squash_into`
/// seals what it brings with `embargo::seal_introduced`
/// (`commands.rs:540`), which leaves a conflict entry exactly as it is
/// (`EntryKind::File | EntryKind::Conflict => {}`, `embargo.rs:953`): "none
/// is public content this line introduces". Here it is: the public side is
/// the work being moved into the cloaked change. It stays plaintext in the
/// cloaked change, the conflict object and that side are sent to a public
/// remote, and Carol's checkout of the cloaked change shows it.
#[test]
#[ignore = "BUG-480: squash into a cloaked change leaves a conflict's public side unsealed"]
fn squash_into_a_cloaked_change_seals_the_public_side_of_a_conflict_it_brings() {
    let env = Env::new();
    let proj = squash_public_work_into_cloaked_change(&env, true);
    let list = env.stdout(U, &proj, &["resolve", "--list", "-r", "sec@", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&list).unwrap();
    let versions = v["conflicts"][0]["conflict"]["versions"].as_array().cloned().unwrap_or_default();
    assert!(!versions.is_empty(), "{list}");
    let carol = publish(&env, &proj, "sec@", "feat");
    let seen = all_files(&carol);
    assert!(
        !seen.contains("NEWTEXT-PUBLIC-X"),
        "work squashed into a change cloaked for 'team' is public on the mirror:\n{seen}\nversions in the cloaked change: {versions:?}"
    );
}

// ---- restore -----------------------------------------------------------------------

/// `vl restore --from REV a.txt` where `a.txt` at REV is cloaked for `team`
/// and the working copy's `a.txt` is public. `cmd_restore` (`main.rs:919`)
/// writes the content REV's version materialises to (`checkout::
/// restore_paths`) and then records the directory as an edit of `@`: the
/// file's parent entry is `@`'s public one, so the sealed content is
/// recorded in plaintext, and the next push publishes it. Nothing says so.
/// A restore puts back a recorded *version*; its audience is part of it
/// (as `vl resolve --theirs` keeps a side's sealing).
#[test]
#[ignore = "BUG-481: vl restore --from records a cloaked version's plaintext as public"]
fn restore_from_a_cloaked_version_keeps_it_sealed() {
    let env = Env::new();
    let proj = sealed_conflict(&env);
    env.ok(U, &proj, &["new", "main"]);
    env.ok(U, &proj, &["restore", "--from", "sec@", "a.txt"]);
    assert_eq!(read(&proj, "a.txt"), "one\nSEALED-SIDE-0042\nthree\n");
    let files = env.stdout(U, &proj, &["files"]);
    assert!(
        files.lines().any(|l| l.starts_with("cloaked:team") && l.ends_with("a.txt")),
        "the restored sealed version is recorded as:\n{files}"
    );
}

/// The same with a format-4 conflict: REV's `a.txt` is a conflict whose
/// "theirs" side is sealed for `team`; Alice's materialised copy shows it
/// (the copy is sealed for `team`). Restoring it into a public line records
/// the markers, sealed side included, as a public file: pushed to a public
/// remote, Carol reads `SEALED-SIDE-0042`.
#[test]
#[ignore = "BUG-481: vl restore --from of a conflict records its sealed side as public"]
fn restore_from_a_conflict_does_not_publish_its_sealed_side() {
    let env = Env::new();
    let proj = sealed_conflict(&env);
    env.ok(U, &proj, &["new", "main"]);
    env.ok(U, &proj, &["restore", "--from", "conflicted", "a.txt"]);
    assert!(read(&proj, "a.txt").contains("SEALED-SIDE-0042"));
    env.ok(U, &proj, &["commit", "-m", "restored"]);
    let carol = publish(&env, &proj, "@-", "restored");
    let seen = all_files(&carol);
    assert!(!seen.contains("SEALED-SIDE-0042"), "the sealed side is public on the mirror:\n{seen}");
}

/// Control: checking the conflicted merge out and publishing *it* keeps the
/// sealed side off the mirror (Carol sees a "not shown" line).
#[test]
fn a_published_conflict_shows_its_sealed_side_redacted() {
    let env = Env::new();
    let proj = sealed_conflict(&env);
    let carol = publish(&env, &proj, "conflicted", "conflicted2");
    let seen = read(&carol, "a.txt");
    assert!(seen.contains("PUBLIC") && seen.contains("not shown") && !seen.contains("SEALED-SIDE-0042"), "{seen}");
}

// ---- partial squash into a cloaked parent ------------------------------------------

/// `vl squash a.txt` from a public change into its cloaked parent (the
/// working-copy change of `sec`, cloaked for `team`). The destination seals
/// what it gets (`finish_dest`, `seal_introduced`), but the source keeps its
/// own tree unchanged (`finish_source(…, s.tree)`, `commands.rs:606` and `:614`: "the
/// source's own tree is unchanged (it already held everything)"). That
/// holds only when the destination keeps the moved entries as they are: here
/// the source still holds `a.txt` as the public plaintext on top of the
/// sealed version, so its diff becomes `visibility: cloaked:team → public`,
/// an exposure nobody asked for, and pushing the line publishes what was
/// just moved into the cloaked change.
#[test]
#[ignore = "BUG-483: a partial squash into a cloaked parent leaves the moved file public in the source"]
fn a_file_squashed_into_a_cloaked_parent_does_not_stay_public_in_the_source() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "one\ntwo\nthree\n"), ("b.txt", "b\n")]);
    env.ok(U, &proj, &["ws", "new", "sec", "-r", "main", "--cloak", "team"]);
    ws_write(&env, &proj, "sec", "y.txt", "SEALED-Y\n");
    env.ok(U, &proj, &["new", "sec@"]);
    write(&proj, "a.txt", "one\nMOVE-ME-0043\nthree\n");
    write(&proj, "b.txt", "b2\n");
    let out = env.ok(U, &proj, &["squash", "a.txt"]);
    assert!(out.contains("Moved 1 file"), "{out}");
    let parent = env.stdout(U, &proj, &["files", "-r", "@-"]);
    assert!(parent.lines().any(|l| l.starts_with("cloaked:team") && l.ends_with("a.txt")), "{parent}");
    let diff = env.stdout(U, &proj, &["diff"]);
    assert!(!diff.contains("a.txt"), "the source's own change still touches a.txt after moving it:\n{diff}");
    env.ok(U, &proj, &["commit", "-m", "rest"]);
    let carol = publish(&env, &proj, "@-", "rest");
    assert!(!all_files(&carol).contains("MOVE-ME-0043"), "the squashed file is public on the mirror");
}
