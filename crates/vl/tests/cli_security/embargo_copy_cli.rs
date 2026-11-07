//! BUG-681: no route copies content out of an unreleased embargo's fix (its
//! withheld history, work built on it, or the embargoed line) into a line
//! outside the embargo, where the next public push would publish the fix's
//! file names, and its content when the fix was not cloaked, before the
//! release. Every route, through the binary: `vl restore --from` (with and
//! without paths), `vl squash` (`--into`, partial and whole), `vl rebase`
//! and `vl abandon` that move work off the fix, `vl duplicate` of work built
//! on it, and `vl resolve`
//! (which only ever picks among versions already in the change). Refusals
//! name the change and the embargo, never a file or a description, and
//! record nothing. Inside the embargo every route still works.

#[path = "../cli_conformance/conformance_history/support.rs"]
mod support;

use support::*;

/// Every marker of the fix: its file names, contents and description.
const MARK: &str = "K7";

/// `v1` (tagged `main`), the fix on it (`fix`: two files and a
/// description), merged into `main` under an embargo. Returns the repo and
/// v1's snapshot id.
fn embargoed(env: &Env) -> (R<'_>, String) {
    let r = env.repo("p");
    r.commit("v1", &[("a.c", "v\n")]);
    r.tag("main", "@-");
    let v1 = r.sid("@-")[..16].to_string();
    r.ok(&["new", "main"]);
    r.commit("FIXDESC-K7", &[("FIXNAME-K7.c", "FIXBODY-K7\n"), ("FIX2-K7.c", "FIXBODY-K7 two\n")]);
    r.tag("fix", "@-");
    r.ok(&["merge", "fix", "--into", "main", "--embargo", "-m", "embargoed"]);
    (r, v1)
}

/// A change on the fix (`fixchild`) that edits one of its files and adds
/// one of its own; `@` ends on a new change on v1.
fn with_child(r: &R, v1: &str) {
    r.ok(&["new", "fix"]);
    r.commit("CHILDDESC-K7", &[("child.c", "c\n"), ("FIXNAME-K7.c", "FIXBODY-K7 edited\n")]);
    r.tag("fixchild", "@-");
    r.ok(&["new", v1]);
}

/// A public change `other` on v1, with `@` on a new change on it.
fn other(r: &R, v1: &str) {
    r.ok(&["new", v1]);
    r.commit("other", &[("o.c", "o\n")]);
    r.tag("other", "@-");
}

/// The command fails cleanly with the confinement refusal, names nothing
/// of the fix, and records nothing.
fn refused(r: &R, args: &[&str]) -> String {
    let before = r.op_head();
    let t = r.fails(args);
    assert!(t.contains("unreleased embargo") && t.contains("outside the embargo"), "{args:?}: {t}");
    assert!(!t.contains(MARK), "{args:?} named the fix: {t}");
    assert_eq!(r.op_head(), before, "{args:?} recorded an operation");
    t
}

/// Push every tag to a fresh public remote: none of the fix's names,
/// content or descriptions are there.
fn publishes_nothing(env: &Env, r: &R) {
    let mirror = env.dir("mirror");
    env.run(U, &mirror, &["init", "--bare"]);
    r.ok(&["remote", "add", "pub", mirror.to_str().unwrap(), "--public"]);
    r.ok(&["push", "pub"]);
    for needle in ["FIXNAME-K7", "FIX2-K7", "FIXBODY-K7", "FIXDESC-K7", "CHILDDESC-K7"] {
        assert!(store_contains(&mirror, needle.as_bytes()).is_empty(), "{needle} reached the public remote");
    }
}

#[test]
fn restore_from_the_fix_onto_another_line_is_refused_with_and_without_paths() {
    let env = Env::new();
    let (r, v1) = embargoed(&env);
    with_child(&r, &v1);
    for args in [
        &["restore", "--from", "fix", "FIXNAME-K7.c"][..],
        &["restore", "--from", "fix"],
        &["restore", "--from", "fixchild", "child.c"],
        // The embargoed merge (and the line on top of it): its tree is the
        // fix's, sealed for key holders only.
        &["restore", "--from", "main", "FIXNAME-K7.c"],
        &["restore", "--from", "main"],
    ] {
        refused(&r, args);
    }
    assert!(!r.exists("FIXNAME-K7.c") && !r.exists("child.c"));
    r.ok(&["commit", "-m", "rel"]);
    r.tag("rel", "@-");
    publishes_nothing(&env, &r);
}

#[test]
fn restore_from_the_fix_inside_its_embargo_works() {
    let env = Env::new();
    let (r, v1) = embargoed(&env);
    with_child(&r, &v1);
    // On the fix line: put the fix's version back.
    r.ok(&["new", "fixchild"]);
    r.ok(&["restore", "--from", "fix", "FIXNAME-K7.c"]);
    assert_eq!(r.read("FIXNAME-K7.c"), "FIXBODY-K7\n");
    r.ok(&["commit", "-m", "back"]);
    // From the fix line's first parent (the public v1) too.
    r.ok(&["restore", "--from", &v1]);
    // On the embargoed line, the fix is already there: not this refusal.
    r.ok(&["new", "main"]);
    let t = text(&r.run(&["restore", "--from", "fix", "FIXNAME-K7.c"]));
    assert!(!t.contains("a copy outside the embargo"), "{t}");
    publishes_nothing(&env, &r);
}

#[test]
fn squashing_the_fix_out_of_its_embargo_is_refused() {
    let env = Env::new();
    let (r, v1) = embargoed(&env);
    with_child(&r, &v1);
    other(&r, &v1);
    for args in [
        &["squash", "-r", "fix", "--into", "other", "FIXNAME-K7.c"][..],
        &["squash", "-r", "fix", "--into", "other"],
        &["squash", "-r", "fixchild", "--into", "other", "child.c"],
        // Into the fix's own (public) parent.
        &["squash", "-r", "fix"],
        &["squash", "-r", "fix", "FIXNAME-K7.c"],
    ] {
        refused(&r, args);
    }
    // Inside the embargo: work on the fix folds into the fix.
    r.ok(&["squash", "-r", "fixchild", "child.c"]);
    publishes_nothing(&env, &r);
}

#[test]
fn moving_work_built_on_the_fix_off_its_embargo_is_refused() {
    let env = Env::new();
    let (r, v1) = embargoed(&env);
    with_child(&r, &v1);
    other(&r, &v1);
    for args in [
        &["rebase", "-r", "fixchild", "-d", &v1][..],
        &["rebase", "-s", "fixchild", "-d", "other"],
        // Abandoning the fix would move the work on it onto v1.
        &["abandon", "fix"],
    ] {
        refused(&r, args);
    }
    // No conflict carrying the fix's versions reached the public line, so
    // `vl resolve` has nothing of it to pick there.
    assert!(r.fails(&["resolve", "--ours", "FIXNAME-K7.c"]).contains("no conflict"));
    // Moving the fix itself keeps it withheld (the embargoed merge
    // follows), and so does splitting it.
    r.ok(&["rebase", "-r", "fix", "-d", "other"]);
    r.ok(&["split", "-r", "fix", "FIXNAME-K7.c"]);
    publishes_nothing(&env, &r);
}

#[test]
fn duplicating_work_built_on_the_fix_is_refused() {
    let env = Env::new();
    let (r, v1) = embargoed(&env);
    with_child(&r, &v1);
    for args in [&["duplicate", "fixchild", "-d", &v1][..], &["cherry-pick", "fixchild"]] {
        let t = refused(&r, args);
        assert!(t.contains("withholds"), "{t}");
    }
    // Onto the fix line it is a copy inside the embargo.
    r.ok(&["duplicate", "fixchild", "-d", "fix"]);
    publishes_nothing(&env, &r);
}

#[test]
fn resolving_a_conflict_with_the_fix_inside_its_embargo_works() {
    let env = Env::new();
    let (r, v1) = embargoed(&env);
    with_child(&r, &v1);
    r.ok(&["new", "fix"]);
    r.commit("sibling", &[("FIXNAME-K7.c", "FIXBODY-K7 other edit\n")]);
    r.tag("sibling", "@-");
    r.ok(&["new", "fixchild", "sibling"]);
    assert!(r.ok(&["resolve", "--list"]).contains("FIXNAME-K7.c"));
    r.ok(&["resolve", "--theirs", "FIXNAME-K7.c"]);
    r.ok(&["commit", "-m", "resolved"]);
    r.tag("resolved", "@-");
    publishes_nothing(&env, &r);
}

#[test]
fn cat_reads_the_fix_and_records_nothing() {
    let env = Env::new();
    let (r, v1) = embargoed(&env);
    r.ok(&["new", &v1]);
    let before = r.op_head();
    assert_eq!(r.out(&["cat", "-r", "fix", "FIXNAME-K7.c"]), "FIXBODY-K7\n");
    assert_eq!(r.op_head(), before);
    publishes_nothing(&env, &r);
}

// ---- adversarial pass: simplification part 2 ----------------------------------------

/// BUG-944: the JSON documents say `public` ("Plaintext, sent to every
/// remote you may push it to", docs/reference/json.md "Tier") for the
/// fix's files in the embargoed merge, which no push sends before the
/// release; format 8 dropped the `embargoed` tier and the `embargo` and
/// `cloak` fields under the same `/1` schemas, which the versioning rules
/// forbid. A consumer (CI, an agent) that publishes what Veil calls
/// public publishes the fix.
#[test]
fn json_never_calls_a_file_under_an_unreleased_embargo_public() {
    let env = Env::new();
    let (r, _) = embargoed(&env);
    let doc: serde_json::Value = serde_json::from_str(&r.ok(&["ls", "-r", "main", "--json"])).unwrap();
    assert_eq!(doc["schema"], "veil.ls/2");
    let fix = doc["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["path"] == "FIXNAME-K7.c")
        .expect("the fix is in main")
        .clone();
    assert_ne!(fix["tier"], "public", "a file no push sends before the release is listed as public: {fix}");
}

/// BUG-942, through the binary: `vl squash` of the embargoed merge into
/// the change on top of it (inside the embargo, so allowed) abandons the
/// merge, and nothing withholds the fix any more: the next push publishes
/// it. Before format 8 this squash was refused ("a change under an embargo
/// can only be squashed whole into its parent").
#[test]
fn squashing_the_embargoed_merge_away_publishes_nothing() {
    let env = Env::new();
    let (r, _) = embargoed(&env);
    let merge = r.sid("main");
    r.ok(&["new", "main"]);
    r.commit("follow-up", &[("follow.c", "f\n")]);
    r.tag("main", "@-");
    let out = r.fails(&["squash", "-r", &merge, "--into", "main"]);
    assert!(out.contains("embargoed merge") && out.contains("vl embargo release"), "{out}");
    publishes_nothing(&env, &r);
}

// ---- simplification cycle 2 --------------------------------------------------

/// BUG-990 (pre-existing on `integration` 0fbe207; the class of BUG-942):
/// a rebase of the embargoed merge that keeps its embargo but changes its
/// parents (the fix first, the fix alone, or `main` alone) changes what
/// the embargo withholds: `remote::embargo_withheld` takes the fix to be
/// the history behind the merge's non-first parents, so the fix tag stops
/// being withheld while the embargo is still pending, and the next push
/// publishes the fix.
#[test]
#[ignore = "BUG-990: rebasing the embargoed merge onto other parents un-withholds its fix"]
fn rebasing_the_embargoed_merge_onto_other_parents_publishes_nothing() {
    for dest in [&["fix", "V1"][..], &["fix"], &["V1"]] {
        let env = Env::new();
        let (r, v1) = embargoed(&env);
        let mut args = vec!["rebase", "-r", "main"];
        for d in dest {
            args.extend(["-d", if *d == "V1" { v1.as_str() } else { d }]);
        }
        let _ = r.run(&args);
        assert!(r.ok(&["embargo", "list"]).contains("manual release"), "control: the embargo is still pending");
        publishes_nothing(&env, &r);
    }
}

/// BUG-991 (regression: `integration` 0fbe207 refuses, "cannot be read as
/// the public sees it"): `vl blame --public` annotates the fix's lines in
/// the embargoed `main` as a public mirror sees them, attributed to the
/// fix's change and description, although no push sends any of it before
/// the release.
#[test]
#[ignore = "BUG-991: `vl blame --public` reads an unreleased embargo's history as public"]
fn blame_public_never_shows_an_unreleased_embargo_as_public() {
    let env = Env::new();
    let (r, _) = embargoed(&env);
    let out = text(&r.run(&["blame", "FIXNAME-K7.c", "-r", "main", "--public", "--json"]));
    assert!(!out.contains("FIXBODY-K7") && !out.contains("FIXDESC-K7"), "the public view shows the withheld fix: {out}");
}

/// BUG-992 (the rest of BUG-944): `vl diff --json` and `vl show --json`
/// list the files an unreleased embargo withholds with the visibility
/// `public` and nothing else to say otherwise (format 7 said `embargoed`;
/// the `/2` schemas dropped that kind and added no tier to file diffs).
#[test]
#[ignore = "BUG-992: `vl diff --json` and `vl show --json` call an unreleased embargo's files public"]
fn diff_and_show_json_never_call_a_file_under_an_unreleased_embargo_public() {
    let env = Env::new();
    let (r, v1) = embargoed(&env);
    for args in [&["diff", "--from", v1.as_str(), "--to", "main", "--json"][..], &["diff", "-r", "fix", "--json"], &["show", "fix", "--json"]] {
        let doc: serde_json::Value = serde_json::from_str(&r.ok(args)).unwrap();
        let files = if doc["diff"].is_object() { &doc["diff"]["files"] } else { &doc["files"] };
        let fix = files.as_array().unwrap().iter().find(|f| f["path"] == "FIXNAME-K7.c").unwrap_or_else(|| panic!("{args:?}: {doc}")).clone();
        assert!(
            fix["new"]["visibility"]["kind"] != "public" || fix.get("tier").is_some_and(|t| t != "public"),
            "{args:?}: a file no push sends before the release is public: {fix}"
        );
    }
}
