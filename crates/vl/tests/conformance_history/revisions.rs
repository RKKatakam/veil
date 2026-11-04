//! Revision expressions: Git t6xxx rev-list / rev-parse (t6101 parents,
//! t6010 merge-base, t6133 rev dwim), mapped to Veil's revisions
//! (`@`, `name@`, tags, id prefixes, `root`, `X-`); jj test_revset*.

use crate::merge::fork;
use crate::support::*;

// Scenario from git t6101-rev-parse-parents.sh: X- walks first parents.
#[test]
fn dash_suffix_walks_first_parents() {
    let env = Env::new();
    let r = env.repo("p");
    let a = r.commit("a", &[("a", "a\n")]);
    let b = r.commit("b", &[("b", "b\n")]);
    assert_eq!(r.cid("@-"), b);
    assert_eq!(r.cid("@--"), a);
    r.tag("t", "@-");
    assert_eq!(r.cid("t-"), a);
    assert_eq!(r.snap("@---").change, "z".repeat(32), "three steps from @ reach the root");
    assert!(r.fails(&["show", "@----"]).contains("past the root"));
}

// Scenario from git t6101-rev-parse-parents.sh: walking past the root is an error.
#[test]
fn walking_past_the_root_fails() {
    let env = Env::new();
    let r = env.repo("p");
    let err = r.fails(&["show", "@--"]);
    assert!(err.contains("past the root"), "{err}");
    r.fails(&["show", "root-"]);
}

// Scenario from git t6101-rev-parse-parents.sh (merge^1): the first parent of a merge is the destination.
#[test]
fn dash_of_a_merge_is_its_first_parent() {
    let env = Env::new();
    let r = fork(&env, &[("k", "k\n")], |r: &R| r.write("l", "l\n"), |r: &R| r.write("r", "r\n"));
    let right = r.cid("right");
    r.ok(&["merge", "left"]);
    assert_eq!(r.cid("@--"), right);
}

// Scenario from git t6133-pathspec-rev-dwim.sh / jj test_revset (prefixes): change-id and snapshot-id prefixes.
#[test]
fn id_prefixes_resolve() {
    let env = Env::new();
    let r = env.repo("p");
    let c = r.commit("a", &[("a", "a\n")]);
    let s = r.sid("@-");
    assert_eq!(r.cid(&c[..12]), c);
    assert_eq!(r.cid(&s[..10]), c);
    assert_eq!(r.cid(&s.to_uppercase()[..10]), c, "hex prefixes are case-insensitive");
    assert_eq!(r.cid(&s), c, "full snapshot id");
    let out = r.out(&["show", &c[..12]]);
    assert!(out.contains(&format!("Change ID : {c}")), "{out}");
}

// Scenario from jj test_revset (short prefixes): fewer than 4 hex digits are not a snapshot prefix.
#[test]
fn short_hex_prefixes_are_not_revisions() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("a", &[("a", "a\n")]);
    let s = r.sid("@-");
    let err = r.fails(&["show", &s[..3]]);
    assert!(err.contains("not found"), "{err}");
}

// Scenario from jj test_revset (ambiguous prefix): a too-short change prefix is ambiguous.
#[test]
fn ambiguous_change_prefix_is_reported() {
    let env = Env::new();
    let r = env.repo("p");
    for i in 0..40 {
        r.commit(&format!("c{i}"), &[("f", &format!("{i}\n"))]);
    }
    let repo = r.core();
    let mut firsts = std::collections::HashMap::new();
    for id in repo.visible_snapshots().unwrap() {
        let c = repo.snapshot(&id).unwrap().change_id.display();
        *firsts.entry(c[..1].to_string()).or_insert(0) += 1;
    }
    let (letter, _) = firsts.iter().find(|(_, n)| **n > 1).expect("40 changes share a first letter");
    let err = r.fails(&["show", letter]);
    assert!(err.contains("ambiguous"), "{err}");
}

// Scenario from jj test_revset (symbol resolution order): a tag wins over a change-id prefix.
#[test]
fn tag_wins_over_a_change_prefix() {
    let env = Env::new();
    let r = env.repo("p");
    let a = r.commit("a", &[("a", "a\n")]);
    let b = r.commit("b", &[("b", "b\n")]);
    // A tag spelled like b's change-id prefix, pointing at a.
    let prefix = &b[..6];
    r.tag(prefix, &a[..8]);
    assert_eq!(r.cid(prefix), a);
}

// Scenario from jj test_revset (root symbol).
#[test]
fn root_has_two_spellings() {
    let env = Env::new();
    let r = env.repo("p");
    assert_eq!(r.sid("root"), r.sid("root()"));
    assert_eq!(r.cid("root"), "z".repeat(32));
}

// Scenario from jj test_revset (working-copy symbols): name@ is another workspace's working copy.
#[test]
fn workspace_at_symbol() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("a", &[("a", "a\n")]);
    r.ok(&["ws", "new", "agent", "-r", "@-"]);
    assert_eq!(r.snap("agent@").parents, vec![r.sid("@-")]);
    assert_eq!(r.sid("default@"), r.sid("@"));
    assert!(r.fails(&["show", "nosuch@"]).contains("nosuch"));
}

// Scenario from git t6133 / jj test_revset: unknown names fail with a clear message.
#[test]
fn unknown_revisions_fail_clearly() {
    let env = Env::new();
    let r = env.repo("p");
    for bad in ["nosuch", "kkkkkkkkkkkkkkkk", "@@", "-", ""] {
        let out = r.run(&["show", bad]);
        assert!(!out.status.success(), "{bad:?} resolved");
        assert!(exited_cleanly(&out), "{bad:?}: {}", text(&out));
    }
}

// Scenario from jj test_revset (hidden commits): an abandoned change's id no longer resolves.
#[test]
fn abandoned_change_id_does_not_resolve() {
    let env = Env::new();
    let r = env.repo("p");
    let a = r.commit("a", &[("a", "a\n")]);
    r.ok(&["abandon", &a[..10]]);
    assert!(r.fails(&["show", &a[..10]]).contains("not found"));
}

// Scenario from git t6000-rev-list-misc.sh (range syntax) / jj revset operators: not in Veil 1.0.
#[test]
fn revset_operators_are_rejected_not_misread() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("a", &[("a", "a\n")]);
    r.commit("b", &[("b", "b\n")]);
    r.tag("main", "@-");
    for expr in ["main..@", "::main", "main|@", "all()", "main~1", "main^"] {
        let out = r.run(&["show", expr]);
        assert!(!out.status.success(), "{expr:?} was accepted:\n{}", text(&out));
        assert!(exited_cleanly(&out));
    }
}

// Scenario from git t6010-merge-base.sh: the merge base is the nearest common ancestor.
#[test]
fn merge_uses_the_nearest_common_ancestor() {
    let env = Env::new();
    let r = env.repo("p");
    let base = lines("l", 9);
    r.commit("old base", &[("f", &base)]);
    // The nearest common ancestor rewrites line 5; both sides then edit other lines.
    let nearer = base.replace("l5\n", "five\n");
    r.commit("nearer base", &[("f", &nearer)]);
    r.tag("nca", "@-");
    r.commit("left", &[("f", &nearer.replace("l1\n", "one\n"))]);
    r.tag("left", "@-");
    r.ok(&["new", "nca"]);
    r.commit("right", &[("f", &nearer.replace("l9\n", "nine\n"))]);
    let out = r.ok(&["merge", "left"]);
    assert!(!out.contains("conflict"), "{out}");
    assert_eq!(r.read("f"), nearer.replace("l1\n", "one\n").replace("l9\n", "nine\n"));
}

// Scenario from Veil tag-name rules: names that would be read as revision syntax are refused.
#[test]
fn tag_names_that_clash_with_revision_syntax_are_refused() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("a", &[("a", "a\n")]);
    for bad in ["release-", "ws@", "root", "a..b", "with space"] {
        let out = r.run(&["tag", "set", bad, "-r", "@-"]);
        assert!(!out.status.success(), "tag {bad:?} accepted");
    }
    r.ok(&["tag", "set", "release-1.0", "-r", "@-"]);
    assert_eq!(r.cid("release-1.0-"), "z".repeat(32), "tag with a dash then a parent step");
}

// Scenario from jj test_revset (remote bookmarks): origin/main names the remote tag after a pull.
#[test]
fn remote_tags_resolve_after_a_pull() {
    let env = Env::new();
    let r = env.repo("p");
    let a = r.commit("a", &[("a", "a\n")]);
    r.tag("main", "@-");
    let remote = env.root.join("remote");
    r.ok(&["remote", "add", "origin", remote.to_str().unwrap()]);
    r.ok(&["push", "origin", "-t", "main"]);
    r.ok(&["pull", "origin"]);
    r.commit("b", &[("b", "b\n")]);
    r.tag("main", "@-");
    assert_eq!(r.cid("origin/main"), a);
    assert_ne!(r.cid("main"), a);
}

// Scenario from guide ("origin/main: where main was on remote origin at the last pull or push").
#[test]
#[ignore = "BUG-248: `vl push` does not record remote tags: `origin/main` is unknown after a push until the next pull"]
fn remote_tags_are_recorded_by_push() {
    let env = Env::new();
    let r = env.repo("p");
    let a = r.commit("a", &[("a", "a\n")]);
    r.tag("main", "@-");
    let remote = env.root.join("remote");
    r.ok(&["remote", "add", "origin", remote.to_str().unwrap()]);
    r.ok(&["push", "origin", "-t", "main"]);
    let s = r.try_snap("origin/main").expect("origin/main does not resolve after `vl push`");
    assert_eq!(s.change, a);
}
