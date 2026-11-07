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

// ---- simplification cycle 3 --------------------------------------------------

/// BUG-1015 (regression: `t3/b837a04e` 94aba9b refuses, "cannot drop or
/// replace the embargoed merge … is built on it"): `vl squash` of the
/// embargoed merge into the fix rewrites the fix too, so every snapshot the
/// embargo withheld gets a new id. `Transaction::check_withheld` only asks
/// whether the *old* ids are still visible, finds none, and lets it through:
/// the fix (and the follow-up on `main`, now a plain merge holding it) are
/// no longer withheld, and the next push publishes them.
#[test]
fn squashing_the_embargoed_merge_into_the_fix_publishes_nothing() {
    for follow_up in [false, true] {
        let env = Env::new();
        let (r, _) = embargoed(&env);
        let merge = if follow_up {
            r.ok(&["new", "main"]);
            r.commit("follow-up", &[("f.c", "f\n")]);
            r.tag("main", "@-");
            "main-"
        } else {
            "main"
        };
        let _ = r.run(&["squash", "-r", merge, "--into", "fix"]);
        assert!(r.ok(&["embargo", "list"]).contains("manual release"), "control: the embargo is still pending");
        publishes_nothing(&env, &r);
    }
}

/// BUG-1016 (pre-existing on 94aba9b): only the snapshots behind a visible
/// embargoed merge are withheld, not the earlier versions of the same
/// changes. `vl undo --op` of a describe of the fix made before the merge
/// moves the `fix` tag back to the earlier version (a ref-only transaction,
/// which `check_withheld` never sees), and `vl restore --from` an earlier
/// version copies it onto another line (`check_confinement` only knows the
/// withheld ids): either way the next push publishes the fix while its
/// embargo is pending.
#[test]
fn an_earlier_version_of_the_fix_is_withheld_too() {
    for route in ["undo", "restore"] {
        let env = Env::new();
        let r = env.repo("p");
        r.commit("v1", &[("a.c", "v\n")]);
        r.tag("main", "@-");
        let v1 = r.sid("@-")[..16].to_string();
        r.ok(&["new", "main"]);
        r.commit("FIXDESC-K7", &[("FIXNAME-K7.c", "FIXBODY-K7\n")]);
        r.tag("fix", "@-");
        let earlier = r.sid("fix")[..16].to_string();
        r.ok(&["describe", "-r", "fix", "-m", "FIXDESC-K7 reworded"]);
        let describe = r.op_head();
        r.ok(&["merge", "fix", "--into", "main", "--embargo", "-m", "embargoed"]);
        if route == "undo" {
            // The user puts the old description back.
            let _ = r.run(&["undo", "--op", &describe]);
        } else {
            other(&r, &v1);
            r.ok(&["new", "other"]);
            let _ = r.run(&["restore", "--from", &earlier]);
            r.ok(&["commit", "-m", "rel"]);
            r.tag("rel", "@-");
        }
        assert!(r.ok(&["embargo", "list"]).contains("manual release"), "{route}: control: the embargo is still pending");
        publishes_nothing(&env, &r);
    }
}

/// BUG-1017 (pre-existing on 94aba9b): undoing the embargoed merge
/// withdraws its embargo (the documented limitation: the fix line is then an
/// ordinary change, pushed as soon as a tag reaches it), but `vl embargo
/// list` still reports it as pending ("manual release") and the push that
/// then publishes the fix says nothing, so the record tells the member the
/// fix is still withheld.
#[test]
fn a_withdrawn_embargo_is_not_listed_as_pending() {
    let env = Env::new();
    let (r, _) = embargoed(&env);
    r.ok(&["undo"]);
    let list = r.ok(&["embargo", "list"]);
    assert!(!list.contains("manual release") || list.contains("withdrawn"), "nothing withholds the fix, yet: {list}");
}

// ---- the withholding rule, randomized -----------------------------------------

/// Found by the randomized test below (another seed): abandoning the fix
/// rebases the embargoed merge down to one parent, which forgot the fix
/// line; `vl undo --op` of an earlier abandon then brought back work built
/// on the old fix, and nothing withheld it. The fix line includes every
/// earlier version of the merge (`predecessors`), so it stays withheld.
#[test]
fn work_on_an_abandoned_fix_brought_back_by_undo_stays_withheld() {
    let env = Env::new();
    let (r, v1) = embargoed(&env);
    with_child(&r, &v1);
    r.ok(&["abandon", "fixchild"]);
    let abandon = r.op_head();
    r.ok(&["abandon", "fix"]);
    r.ok(&["undo", "--op", &abandon]);
    assert!(r.tag_target("fixchild").is_some(), "control: the work on the old fix is back");
    assert!(!r.ok(&["embargo", "list"]).contains("withdrawn"));
    publishes_nothing(&env, &r);
}

/// A pinned pseudo-random sequence (xorshift64*): the same cases every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn pick<'a>(&mut self, xs: &'a [String]) -> &'a str {
        &xs[(self.next() % xs.len() as u64) as usize]
    }
}

// ---- Simplification cycle 4 ----------------------------------------------------

/// BUG-1040 (pre-existing on 82429c6): the fix squashed into work built on
/// the embargoed merge (allowed: a copy inside the embargo) leaves its
/// content in a change that is withheld only because it descends from the
/// merge. Dropping the merge then (abandoning it, or squashing it into that
/// work) rebases the work onto v1, and no check sees it: no version of a
/// fix-line change is visible any more (`check_withheld` compares only
/// versions), and the confinement check skips an embargo whose merge is
/// gone. `vl embargo list` calls the embargo withdrawn, the push gives no
/// warning, and it publishes the fix.
#[test]
fn the_fix_squashed_into_work_on_the_merge_stays_withheld_when_the_merge_goes() {
    for route in ["abandon", "squash"] {
        let env = Env::new();
        let (r, _) = embargoed(&env);
        r.ok(&["new", "main"]);
        r.commit("follow-up", &[("f.c", "f\n")]);
        r.tag("fu", "@-");
        // Inside the embargo: allowed.
        r.ok(&["squash", "-r", "fix", "--into", "fu"]);
        let _ = match route {
            "abandon" => r.run(&["abandon", "main"]),
            _ => r.run(&["squash", "-r", "main", "--into", "fu"]),
        };
        publishes_nothing(&env, &r);
    }
}

/// BUG-1041 (pre-existing on 82429c6): `vl undo --op` carries "the edits
/// recorded since" the undone operation over to the working copy it
/// restores, as the difference between the working copy that operation
/// left and the current one (`Repo::restore_view_keeping_edits`). When the
/// working copy moved to another change since (`vl edit`, `vl new`), that
/// difference is the other change's whole content: here the fix, 3-way
/// merged into a change on the public line, where `vl status` lists its
/// files as plain additions and the next commit and push publish them. The
/// rewrite keeps the change's parents, so the confinement check never
/// judges it. Plain `vl undo` reaches it too, after an earlier `undo --op`
/// moved the working copy (the randomized test below).
#[test]
fn undo_never_copies_the_change_being_edited_into_another() {
    for route in ["edit", "new"] {
        let env = Env::new();
        let (r, v1) = embargoed(&env);
        with_child(&r, &v1);
        other(&r, &v1);
        r.ok(&["abandon", "other"]);
        let abandon = r.op_head();
        r.ok(&[route, "fixchild"]);
        r.ok(&["undo", "--op", &abandon]);
        // The restored working copy is the empty change on `other` again.
        assert!(!r.exists("FIXNAME-K7.c") && !r.exists("child.c"), "{route}: the fix's files are in the working copy on other");
        r.ok(&["commit", "-m", "work"]);
        publishes_nothing(&env, &r);
    }
}

/// Random sequences of the rewrite and working-copy commands (squash,
/// rebase, describe, undo, redo, restore, tag set, new, edit, split,
/// abandon of one or two changes, duplicate, merge, a commit of a new
/// file) over an embargoed history with work on the fix (`fixchild`) and on
/// the merge (`fu`), on any revision (current names and every snapshot id
/// seen so far, earlier versions included). After each command a push to a
/// public remote publishes nothing of the fix, unless the member withdrew
/// the embargo (its merge undone or abandoned bare): then `vl embargo list`
/// says so, and the push that publishes it warns. Returns how many cases
/// ended withdrawn.
fn random_embargo_cases(seed: u64, cases: usize, steps: usize) -> usize {
    let markers = ["FIXNAME-K7", "FIX2-K7", "FIXBODY-K7", "FIXDESC-K7", "CHILDDESC-K7"];
    let mut rng = Rng(seed);
    let mut withdrawn = 0;
    for case in 0..cases {
        let env = Env::new();
        let (r, v1) = embargoed(&env);
        with_child(&r, &v1);
        r.ok(&["new", "main"]);
        r.commit("follow-up", &[("f.c", "f\n")]);
        r.tag("fu", "@-");
        other(&r, &v1);
        let mirror = env.dir("mirror");
        env.run(U, &mirror, &["init", "--bare"]);
        r.ok(&["remote", "add", "pub", mirror.to_str().unwrap(), "--public"]);
        let mut revs: Vec<String> = ["fix", "main", "main-", "fixchild", "other", "@", "@-", v1.as_str(), "fu"].iter().map(|s| s.to_string()).collect();
        for n in ["fix", "main", "fixchild"] {
            revs.push(r.sid(n)[..16].to_string());
        }
        let mut ops: Vec<String> = vec![r.op_head()];
        let mut log = Vec::new();
        for step in 0..steps {
            let a = rng.pick(&revs).to_string();
            let b = rng.pick(&revs).to_string();
            let n = rng.next();
            let args: Vec<String> = match n % 15 {
                0 if n.is_multiple_of(3) => vec!["squash".into(), "-r".into(), a],
                0 => vec!["squash".into(), "-r".into(), a, "--into".into(), b],
                1 if n.is_multiple_of(3) => vec!["rebase".into(), "-s".into(), a, "-d".into(), b],
                1 if n % 3 == 1 => vec!["rebase".into(), "-r".into(), a, "-d".into(), b.clone(), "-d".into(), rng.pick(&revs).to_string()],
                1 => vec!["rebase".into(), "-r".into(), a, "-d".into(), b],
                2 => vec!["describe".into(), "-r".into(), a, "-m".into(), format!("reworded {step}")],
                3 if n.is_multiple_of(2) => vec!["undo".into()],
                3 => vec!["undo".into(), "--op".into(), rng.pick(&ops).to_string()],
                4 => vec!["restore".into(), "--from".into(), a],
                5 => vec!["tag".into(), "set".into(), ["fix", "main", "rel", "fu"][(n / 10 % 4) as usize].into(), "-r".into(), a],
                6 if n.is_multiple_of(2) => vec!["new".into(), a, b],
                6 => vec!["new".into(), a],
                7 => vec!["split".into(), "-r".into(), a, ["FIXNAME-K7.c", "a.c", "child.c", "f.c"][(n / 10 % 4) as usize].into()],
                8 => vec!["abandon".into(), a],
                9 => vec!["duplicate".into(), a, "-d".into(), b],
                10 => vec!["redo".into()],
                11 => vec!["edit".into(), a],
                12 => vec!["merge".into(), a, "--into".into(), b],
                13 => vec!["abandon".into(), a, b],
                _ => {
                    r.write(&format!("w{step}.c"), "w\n");
                    vec!["commit".into(), "-m".into(), format!("work {step}")]
                }
            };
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            let out = r.run(&argv);
            assert!(exited_cleanly(&out), "seed {seed:#x} case {case}, {argv:?} crashed:\n{}", text(&out));
            log.push(format!("{argv:?} -> {}", if out.status.success() { "ok" } else { "refused" }));
            ops.push(r.op_head());
            for rev in ["fix", "main", "@", "@-", "fixchild", "fu"] {
                if let Some(s) = r.try_snap(rev) {
                    let id = s.id[..16].to_string();
                    if !revs.contains(&id) {
                        revs.push(id);
                    }
                }
            }
            let push = text(&r.run(&["push", "pub"]));
            let leaked: Vec<&str> = markers.iter().copied().filter(|m| !store_contains(&mirror, m.as_bytes()).is_empty()).collect();
            if !leaked.is_empty() {
                let list = r.ok(&["embargo", "list"]);
                assert!(
                    list.contains("withdrawn") && push.contains("withdrawn"),
                    "seed {seed:#x} case {case}: {leaked:?} reached the public remote while the embargo is not withdrawn:\n{}\nembargo list: {list}\npush: {push}",
                    log.join("\n")
                );
                withdrawn += 1;
                break;
            }
        }
    }
    withdrawn
}

/// [`random_embargo_cases`] on a pinned seed.
#[test]
fn random_rewrites_never_push_what_an_unreleased_embargo_withholds() {
    let w = random_embargo_cases(0x5eed_1015_1016_1017, 8, 24);
    println!("{w} of 8 cases ended with the embargo withdrawn");
}

/// The reviewer's pinned seed: case 6 found BUG-1041 (`vl undo --op` after
/// `vl edit fixchild`, then a commit); seed 0xa1b2c3d4e5f60718 found it in
/// case 4 through plain `vl undo`.
#[test]
fn random_rewrites_and_working_copy_commands_never_push_what_an_unreleased_embargo_withholds() {
    random_embargo_cases(0x7777_dead_beef_0001, 7, 24);
    random_embargo_cases(0xa1b2_c3d4_e5f6_0718, 5, 24);
}
