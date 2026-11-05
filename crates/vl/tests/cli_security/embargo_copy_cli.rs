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
