//! Local tags, Veil's branches: git t3200-branch, t3203 (branch output),
//! t3204 (name interpretation), t7004-tag (local tags only); jj
//! test_bookmark_command (local behaviour), test_tag_command.

use super::*;

fn chain(env: &Env) -> (R<'_>, String, String) {
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    let one = r.commit("one");
    r.write("b.txt", "b\n");
    let two = r.commit("two");
    (r, one, two)
}

// Scenario from git t3200-branch.sh "git branch abc should create a branch".
#[test]
fn tag_set_creates_and_list_shows_it() {
    let env = Env::new();
    let (r, one, _) = chain(&env);
    let out = r.ok(&["tag", "set", "abc", "-r", one.as_str()]);
    assert!(out.contains(&format!("Tag abc → {}", &one[..8])), "{out}");
    assert_eq!(r.tags(), vec![("abc".to_string(), one[..8].to_string())]);
}

// Scenario from git t3200 (branch at HEAD by default): `-r` defaults to `@`.
#[test]
fn tag_set_defaults_to_the_working_copy() {
    let env = Env::new();
    let (r, _, _) = chain(&env);
    r.ok(&["tag", "set", "here"]);
    assert_eq!(r.change("here"), r.change("@"));
}

// Scenario from git t3200-branch.sh "git branch -d d/e/f should delete".
#[test]
fn tag_delete_removes_it() {
    let env = Env::new();
    let (r, one, _) = chain(&env);
    r.ok(&["tag", "set", "d/e/f", "-r", one.as_str()]);
    let out = r.ok(&["tag", "delete", "d/e/f"]);
    assert!(out.contains("Deleted tag d/e/f"), "{out}");
    assert!(r.tags().is_empty());
    // The change itself is untouched.
    assert_eq!(r.description(one.as_str()), "one");
}

// Scenario from git t3200-branch.sh "deleting a non-existent branch".
#[test]
fn deleting_an_unknown_tag_fails() {
    let env = Env::new();
    let (r, _, _) = chain(&env);
    let err = r.fails(&["tag", "delete", "nope"]);
    assert!(err.contains("not found: tag 'nope'"), "{err}");
}

// Scenario from git t3200-branch.sh "git branch -f" / "-m": moving forward
// is free, backwards or sideways needs `--allow-backwards`.
#[test]
fn tags_move_forward_freely_but_not_backwards() {
    let env = Env::new();
    let (r, one, two) = chain(&env);
    r.ok(&["tag", "set", "main", "-r", one.as_str()]);
    r.ok(&["tag", "set", "main", "-r", two.as_str()]);
    assert_eq!(r.change("main"), two);
    let err = r.fails(&["tag", "set", "main", "-r", one.as_str()]);
    assert!(err.contains("backwards or sideways"), "{err}");
    assert_eq!(r.change("main"), two);
    r.ok(&["tag", "set", "main", "-r", one.as_str(), "--allow-backwards"]);
    assert_eq!(r.change("main"), one);
    // Sideways: an unrelated line.
    r.ok(&["new", "root"]);
    r.write("x.txt", "x\n");
    let other = r.commit("other line");
    let err = r.fails(&["tag", "set", "main", "-r", other.as_str()]);
    assert!(err.contains("backwards or sideways"), "{err}");
}

// Scenario from git t3200-branch.sh (re-setting a branch to where it is).
#[test]
fn setting_a_tag_to_its_current_target_is_fine() {
    let env = Env::new();
    let (r, one, _) = chain(&env);
    r.ok(&["tag", "set", "main", "-r", one.as_str()]);
    r.ok(&["tag", "set", "main", "-r", one.as_str()]);
    assert_eq!(r.change("main"), one);
}

// Scenario from git t3200-branch.sh / t3204-branch-name-interpretation.sh
// ("git branch with an invalid name"): names that would clash with the
// revision syntax are refused.
#[test]
fn invalid_tag_names_are_refused() {
    let env = Env::new();
    let (r, _, _) = chain(&env);
    for bad in ["", "a b", "@", "x@", "main-", "root", "a..b", "\u{fc}", "a:b", "a~1", "a^", "tab\tname", "new\nline"] {
        let err = r.fails(&["tag", "set", "-r", "@-", "--", bad]);
        assert!(err.contains("invalid tag name"), "{bad:?}: {err}");
    }
    assert!(r.tags().is_empty());
}

// Scenario from git t3200-branch.sh (hierarchical names): `feat` and
// `feat/x` coexist as Veil tags.
#[test]
fn hierarchical_tag_names() {
    let env = Env::new();
    let (r, one, two) = chain(&env);
    r.ok(&["tag", "set", "feat/x", "-r", one.as_str()]);
    r.ok(&["tag", "set", "feat", "-r", two.as_str()]);
    r.ok(&["tag", "set", "v1.0.0", "-r", one.as_str()]);
    assert_eq!(r.change("feat/x"), one);
    assert_eq!(r.change("feat"), two);
    assert_eq!(r.change("v1.0.0-"), r.change("root"), "suffixes apply to tags");
}

// Scenario from git t3203-branch-output.sh: the list is sorted by name.
#[test]
fn tag_list_is_sorted() {
    let env = Env::new();
    let (r, one, _) = chain(&env);
    for t in ["zeta", "alpha", "Mid", "beta/1"] {
        r.ok(&["tag", "set", t, "-r", one.as_str()]);
    }
    let names: Vec<String> = r.tags().into_iter().map(|(n, _)| n).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
}

// Scenario from jj test_bookmark_command.rs: a tag follows its change
// through rewrites (describe, edit).
#[test]
fn a_tag_follows_its_change_through_rewrites() {
    let env = Env::new();
    let (r, one, _) = chain(&env);
    r.ok(&["tag", "set", "keep", "-r", one.as_str()]);
    let snap = r.snap("keep");
    r.ok(&["describe", "-r", "keep", "-m", "renamed"]);
    assert_ne!(r.snap("keep"), snap);
    assert_eq!(r.change("keep"), one);
    r.ok(&["edit", "keep"]);
    r.write("a.txt", "amended\n");
    r.ok(&["status"]);
    assert_eq!(r.cat("a.txt", "keep"), "amended\n");
}

// Scenario from jj test_bookmark_command.rs "abandon a bookmarked
// commit": the tag moves to the parent.
#[test]
fn abandoning_a_tagged_change_moves_the_tag_to_its_parent() {
    let env = Env::new();
    let (r, one, two) = chain(&env);
    r.ok(&["tag", "set", "t", "-r", two.as_str()]);
    r.ok(&["abandon", "t"]);
    assert_eq!(r.change("t"), one);
}

// Scenario from git t3200 (branch at the root / orphan): a tag on root.
#[test]
fn a_tag_on_the_root() {
    let env = Env::new();
    let (r, _, _) = chain(&env);
    r.ok(&["tag", "set", "start", "-r", "root"]);
    assert_eq!(r.snap("start"), r.snap("root"));
}

// Scenario from git t3200 "branch at a hidden commit": an abandoned change
// cannot be tagged by its change id.
#[test]
fn an_abandoned_change_cannot_be_tagged() {
    let env = Env::new();
    let (r, _, two) = chain(&env);
    r.ok(&["abandon", two.as_str()]);
    let err = r.fails(&["tag", "set", "gone", "-r", two.as_str()]);
    assert!(err.contains("not found"), "{err}");
}

// Scenario from git t7004-tag.sh (lightweight tags list) with Veil's
// cloaked tags: the scope is shown in the list.
#[test]
fn a_cloaked_tag_is_marked_in_the_list() {
    let env = Env::new();
    let (r, one, _) = chain(&env);
    r.ok(&["tag", "set", "secret-line", "-r", one.as_str(), "--cloak"]);
    let list = r.out(&["tag", "list"]);
    assert!(list.contains("secret-line [cloaked:team]:"), "{list}");
    // Moving it keeps its cloak.
    r.ok(&["tag", "set", "secret-line", "-r", "@-"]);
    assert!(r.out(&["tag", "list"]).contains("secret-line [cloaked:team]:"));
}

// Scenario from git t7004-tag.sh (invalid tag options) with Veil's scopes:
// a cloaked tag must name a scope that exists and that you can use, as
// `vl cloak --scope` and `vl ws new --cloak` require; reserved names
// (`local`, `embargo/…`) and malformed ones are refused.
#[test]
fn a_cloaked_tag_needs_a_valid_scope() {
    let env = Env::new();
    let (r, one, _) = chain(&env);
    for bad in ["tema", "local", "embargo/x", "../x", "UPPER", ""] {
        let out = r.run(&["tag", "set", "t", "-r", one.as_str(), &format!("--cloak={bad}")]);
        assert!(!out.status.success(), "--cloak={bad:?} accepted: {}", text(&out));
    }
}

// Scenario from git t3200 "git branch -m" (rename): no rename command;
// set the new name, delete the old one.
#[test]
fn renaming_a_tag_by_set_and_delete() {
    let env = Env::new();
    let (r, one, _) = chain(&env);
    r.ok(&["tag", "set", "old", "-r", one.as_str()]);
    r.ok(&["tag", "set", "new", "-r", "old"]);
    r.ok(&["tag", "delete", "old"]);
    assert_eq!(r.tags(), vec![("new".to_string(), one[..8].to_string())]);
}

// Scenario from git t3200-branch.sh (deleting the checked-out branch):
// deleting the tag at `@` is fine; the working copy is untouched.
#[test]
fn deleting_the_tag_at_the_working_copy() {
    let env = Env::new();
    let (r, _, _) = chain(&env);
    r.write("wip.txt", "w\n");
    r.ok(&["tag", "set", "here"]);
    r.ok(&["tag", "delete", "here"]);
    assert_eq!(r.read("wip.txt"), "w\n");
    assert!(r.changes().contains(&"A wip.txt".to_string()));
}

// Scenario from git t3204-branch-name-interpretation.sh: names with dots
// and dashes, and a name that starts with a dash after `--`.
#[test]
fn unusual_but_legal_tag_names() {
    let env = Env::new();
    let (r, one, _) = chain(&env);
    for n in ["v1.2.3-rc.1", "release_2026", "-dash", "UPPER", "a/b/c/d"] {
        r.ok(&["tag", "set", "-r", one.as_str(), "--", n]);
        assert_eq!(r.change(n), one, "{n}");
    }
    r.ok(&["tag", "delete", "--", "-dash"]);
    assert!(!r.tags().iter().any(|(n, _)| n == "-dash"));
}
