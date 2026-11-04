//! Revision syntax: git t1500-rev-parse, t1505 (last), t1506 diagnosis,
//! t1508 at-combinations, t1511 caret (parents), t1512 disambiguation,
//! t1513 prefixes; jj test_revset_output (the subset Veil has), lib
//! test_id_prefix.

use crate::*;

/// A repository with a linear history `one`, `two`, `three` (`@` on top).
fn linear(env: &Env) -> (R<'_>, [String; 3]) {
    let r = env.repo("p");
    let mut ids = Vec::new();
    for n in ["one", "two", "three"] {
        r.write(&format!("{n}.txt"), format!("{n}\n"));
        ids.push(r.commit(n));
    }
    (r, ids.try_into().unwrap())
}

// Scenario from git t1500-rev-parse.sh / t1511-rev-parse-caret.sh: `@` and
// `X-` chains (Git's HEAD and HEAD^/HEAD~N).
#[test]
fn at_and_parent_suffixes_walk_first_parents() {
    let env = Env::new();
    let (r, [one, two, three]) = linear(&env);
    assert_eq!(r.change("@-"), three);
    assert_eq!(r.change("@--"), two);
    assert_eq!(r.change("@---"), one);
    assert_eq!(r.change(&format!("{three}--")), one);
    assert_eq!(r.snap("@----"), r.snap("root"));
}

// Scenario from git t1506-rev-parse-diagnosis.sh: walking past the root.
#[test]
fn walking_past_the_root_is_an_error() {
    let env = Env::new();
    let (r, _) = linear(&env);
    let err = r.fails(&["show", "@-----"]);
    assert!(err.contains("walks past the root"), "{err}");
    let err = r.fails(&["show", "root-"]);
    assert!(err.contains("walks past the root"), "{err}");
}

// Scenario from git t1506-rev-parse-diagnosis.sh: unknown and empty revisions.
#[test]
fn unknown_and_empty_revisions_fail_cleanly() {
    let env = Env::new();
    let (r, _) = linear(&env);
    for (rev, msg) in [
        ("nosuchtag", "not found"),
        ("", "empty revision"),
        ("-", "empty revision"),
        ("nosuch@", "workspace"),
        ("abc", "not found"),
    ] {
        let err = r.fails(&["show", rev]);
        assert!(err.contains(msg), "{rev:?}: {err}");
    }
    // Every command that takes a revision fails the same way.
    let ops = r.op_count();
    for args in [
        &["new", "nosuchtag"][..],
        &["edit", "nosuchtag"],
        &["diff", "-r", "nosuchtag"],
        &["cat", "-r", "nosuchtag", "one.txt"],
        &["restore", "--from", "nosuchtag"],
        &["files", "-r", "nosuchtag"],
        &["tag", "set", "x", "-r", "nosuchtag"],
        &["describe", "-r", "nosuchtag", "-m", "x"],
    ] {
        let err = r.fails(args);
        assert!(err.contains("not found"), "{args:?}: {err}");
    }
    assert_eq!(r.op_count(), ops, "failed commands record no operation");
}

// Scenario from jj test_revset_output.rs: `root` and `root()` are the root.
#[test]
fn root_spellings() {
    let env = Env::new();
    let (r, _) = linear(&env);
    assert_eq!(r.snap("root"), r.snap("root()"));
    assert_eq!(r.change("root"), "z".repeat(32));
    assert_eq!(r.snap("zzzzzzzz"), r.snap("root"));
}

// Scenario from git t1513-rev-parse-prefix.sh: change-id prefixes of any
// unique length, up to the full id.
#[test]
fn change_id_prefixes_of_any_unique_length() {
    let env = Env::new();
    let (r, [one, ..]) = linear(&env);
    let snap = r.snap(&one);
    for len in [8, 12, 20, 32] {
        assert_eq!(r.snap(&one[..len]), snap, "prefix of length {len}");
    }
}

// Scenario from git t1512-rev-parse-disambiguation.sh: a prefix shared by
// two changes is refused as ambiguous; a longer one resolves.
#[test]
fn ambiguous_change_id_prefix_is_refused() {
    let env = Env::new();
    let r = env.repo("p");
    // Change ids use 16 letters (k–z): among 17 changes two share a first letter.
    let mut ids: Vec<String> = Vec::new();
    for i in 0..17 {
        r.write("f.txt", format!("{i}\n"));
        ids.push(r.commit(&format!("c{i}")));
    }
    ids.push(r.change("@"));
    let (a, b) = ids
        .iter()
        .enumerate()
        .find_map(|(i, a)| ids[i + 1..].iter().find(|b| b[..1] == a[..1]).map(|b| (a.clone(), b.clone())))
        .expect("pigeonhole");
    let common = a.chars().zip(b.chars()).take_while(|(x, y)| x == y).count();
    let err = r.fails(&["show", &a[..common]]);
    assert!(err.contains("ambiguous"), "{err}");
    assert_eq!(r.change(&a[..common + 1]), a);
    assert_eq!(r.change(&b[..common + 1]), b);
}

// Scenario from git t1512-rev-parse-disambiguation.sh: snapshot-id
// prefixes need at least four hex digits.
#[test]
fn snapshot_id_prefixes_need_four_hex_digits() {
    let env = Env::new();
    let (r, [one, ..]) = linear(&env);
    let snap = r.snap(&one);
    assert_eq!(r.snap(&snap[..4]).len(), 64);
    assert_eq!(r.snap(&snap[..8]), snap);
    assert_eq!(r.snap(&snap), snap);
    let err = r.fails(&["show", &snap[..3]]);
    assert!(err.contains("not found"), "{err}");
}

// Scenario from git t1512-rev-parse-disambiguation.sh: hex is
// case-insensitive.
#[test]
fn snapshot_id_prefixes_are_case_insensitive() {
    let env = Env::new();
    let (r, [one, ..]) = linear(&env);
    let snap = r.snap(&one);
    assert_eq!(r.snap(&snap[..10].to_ascii_uppercase()), snap);
}

// Scenario from git t1512-rev-parse-disambiguation.sh "ambiguous 40-hex
// ref" / "ambiguous short sha1 ref": a tag wins over an id prefix
// (documented for Veil).
#[test]
fn a_tag_wins_over_an_id_prefix_that_spells_the_same() {
    let env = Env::new();
    let (r, [one, two, _]) = linear(&env);
    r.ok(&["tag", "set", &two[..6], "-r", one.as_str()]);
    assert_eq!(r.change(&two[..6]), one, "the tag wins");
    assert_eq!(r.change(&two[..7]), two, "a longer prefix is still the change");
    let snap2 = r.snap(&two);
    r.ok(&["tag", "set", &snap2[..8], "-r", one.as_str()]);
    assert_eq!(r.change(&snap2[..8]), one);
}

// Scenario from git t1508-at-combinations.sh: `name@` is another
// workspace's working copy, and suffixes apply to it.
#[test]
fn workspace_at_revisions_and_their_parents() {
    let env = Env::new();
    let (r, [_, two, three]) = linear(&env);
    r.ok(&["ws", "new", "agent", "-r", two.as_str()]);
    assert_eq!(r.change("agent@-"), two);
    assert_eq!(r.change("default@"), r.change("@"));
    assert_eq!(r.change("default@-"), three);
    let err = r.fails(&["show", "ghost@"]);
    assert!(err.contains("ghost"), "{err}");
}

// Scenario from git t1511-rev-parse-caret.sh (`^1` of a merge): `X-` is
// the first parent of a merge.
#[test]
fn parent_suffix_of_a_merge_is_its_first_parent() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    let a = r.commit("a");
    r.ok(&["new", "root"]);
    r.write("b.txt", "b\n");
    let b = r.commit("b");
    r.ok(&["new", a.as_str(), b.as_str()]);
    assert_eq!(r.change("@-"), a);
    r.ok(&["new", b.as_str(), a.as_str()]);
    assert_eq!(r.change("@-"), b);
}

// Scenario from git t1500-rev-parse.sh: surrounding whitespace is trimmed.
#[test]
fn whitespace_around_a_revision_is_ignored() {
    let env = Env::new();
    let (r, [_, _, three]) = linear(&env);
    assert_eq!(r.change(" @- "), three);
}

// Scenario from git t1512-rev-parse-disambiguation.sh (hidden objects):
// an abandoned change is no longer a revision by its change id.
#[test]
fn an_abandoned_change_id_no_longer_resolves() {
    let env = Env::new();
    let (r, [_, two, _]) = linear(&env);
    r.ok(&["abandon", two.as_str()]);
    let err = r.fails(&["show", two.as_str()]);
    assert!(err.contains("not found"), "{err}");
}

// Scenario from git t1505-rev-parse-last.sh / jj test_evolog: the
// snapshot ids `vl evolog` prints for earlier versions of a change are
// the documented way to name "one exact version" (getting-started guide:
// "Use snapshot ids when you mean one exact version (to compare with
// `vl diff --from` …)"), but only visible snapshots resolve by prefix.
#[test]
#[ignore = "BUG-207: snapshot ids that `vl evolog` prints for earlier versions do not resolve as revisions"]
fn evolog_snapshot_ids_resolve_as_revisions() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "v1\n");
    r.ok(&["status"]);
    r.write("a.txt", "v2\n");
    r.commit("two");
    let evolog = r.out(&["evolog", "-r", "@-"]);
    let versions: Vec<&str> = evolog.lines().map(|l| l.split_whitespace().nth(3).unwrap()).collect();
    assert!(versions.len() >= 3, "{evolog}");
    // Every version `vl evolog` lists is a revision; one of them holds v1.
    for id in &versions {
        let out = r.run(&["--no-snapshot", "show", "--stat", id]);
        assert!(out.status.success(), "evolog id {id}: {}", text(&out));
    }
    assert!(versions.iter().any(|id| r.run(&["cat", "-r", id, "a.txt"]).stdout == b"v1\n"), "{evolog}");
}

// Scenario from git t1500-rev-parse.sh `--verify` of a non-snapshot
// object: blob and tree ids are not revisions.
#[test]
fn ids_that_are_not_snapshots_are_not_revisions() {
    let env = Env::new();
    let (r, _) = linear(&env);
    // A 64-hex string that is no object.
    let err = r.fails(&["show", &"ab".repeat(32)]);
    assert!(err.contains("not found"), "{err}");
}

// Scenario from git t1500-rev-parse.sh "--short= truncates": `vl log`
// prints prefixes that resolve.
#[test]
fn ids_printed_by_log_resolve() {
    let env = Env::new();
    let (r, ids) = linear(&env);
    let log = r.out(&["log"]);
    for id in &ids {
        let short = &id[..8];
        assert!(log.contains(short), "{log}");
        assert_eq!(r.change(short), *id);
    }
    for l in log.lines().filter(|l| l.contains(" alice ")) {
        let snap = l.split_whitespace().filter(|w| w.len() == 8 && w.bytes().all(|b| b.is_ascii_hexdigit())).last();
        if let Some(s) = snap {
            r.ok(&["--no-snapshot", "show", "--stat", s]);
        }
    }
}
