//! Git's stash, done the Veil way (the guide: `git stash` / `git stash pop`
//! is `vl new @-` / `vl edit <change>`): git t3903-stash, t3905
//! (include-untracked), t3907 (show), t3908 (stash in worktree).

use super::*;

fn dirty(env: &Env) -> (R<'_>, String) {
    let r = env.repo("p");
    r.write("a.txt", "a1\n");
    let base = r.commit("base");
    r.write("a.txt", "a2 wip\n");
    r.write("new.txt", "untracked in Git terms\n");
    (r, base)
}

// Scenario from git t3903-stash.sh "stash some dirty working directory".
#[test]
fn new_on_the_parent_sets_work_aside() {
    let env = Env::new();
    let (r, base) = dirty(&env);
    let wip = r.change("@");
    r.ok(&["new", "@-"]);
    assert_eq!(r.change("@-"), base);
    assert_eq!(r.read("a.txt"), "a1\n");
    assert!(!r.exists("new.txt"), "new files go along (git stash -u)");
    assert!(r.changes().is_empty());
    assert_eq!(r.cat("a.txt", wip.as_str()), "a2 wip\n");
    assert_eq!(r.cat("new.txt", wip.as_str()), "untracked in Git terms\n");
}

// Scenario from git t3903-stash.sh "apply stashed changes" / "pop".
#[test]
fn edit_brings_the_work_back() {
    let env = Env::new();
    let (r, _) = dirty(&env);
    let wip = r.change("@");
    r.ok(&["describe", "-m", "stash: wip"]);
    r.ok(&["new", "@-"]);
    r.write("hotfix.txt", "fix\n");
    r.commit("hotfix");
    r.ok(&["edit", wip.as_str()]);
    assert_eq!(r.read("a.txt"), "a2 wip\n");
    assert_eq!(r.read("new.txt"), "untracked in Git terms\n");
    assert!(!r.exists("hotfix.txt"), "the hotfix is on another line");
}

// Scenario from git t3903-stash.sh "stash list" / t3907 "stash show".
#[test]
fn set_aside_work_is_listed_and_shown() {
    let env = Env::new();
    let (r, _) = dirty(&env);
    let wip = r.change("@");
    r.ok(&["describe", "-m", "stash: wip"]);
    r.ok(&["new", "@-"]);
    assert!(r.out(&["log"]).contains("stash: wip"));
    let show = r.out(&["show", "--stat", wip.as_str()]);
    assert!(show.contains("M a.txt") && show.contains("A new.txt"), "{show}");
}

// Scenario from git t3903-stash.sh "drop".
#[test]
fn abandon_drops_set_aside_work() {
    let env = Env::new();
    let (r, _) = dirty(&env);
    let wip = r.change("@");
    r.ok(&["describe", "-m", "stash: wip"]);
    r.ok(&["new", "@-"]);
    r.ok(&["abandon", wip.as_str()]);
    assert!(!r.out(&["log"]).contains("stash: wip"));
    assert_eq!(r.read("a.txt"), "a1\n");
}

// Scenario from git t3905-stash-include-untracked.sh "ignored files are
// not stashed": ignored and isolated files stay on disk.
#[test]
fn ignored_and_isolated_files_stay_on_disk() {
    let env = Env::new();
    let (r, _) = dirty(&env);
    r.write("target/build.o", "o\n");
    r.write(".netrc", DOTENV);
    r.ok(&["new", "@-"]);
    assert_eq!(r.read("target/build.o"), "o\n");
    assert_eq!(r.read(".netrc"), DOTENV);
}

// Scenario from git t3903-stash.sh with a quarantined edit: it is never
// recorded, so it stays on disk instead of being set aside.
#[test]
fn a_quarantined_edit_stays_on_disk() {
    let env = Env::new();
    let (r, _) = dirty(&env);
    r.write("cfg.js", LEAKY);
    r.quarantined(&["new", "@-"]);
    assert_eq!(r.read("cfg.js"), LEAKY);
}

// Scenario from git t3903-stash.sh "stash an added file then pop on top of
// new work": the set-aside change can be moved onto the new parent.
#[test]
fn set_aside_work_combines_with_new_work_in_a_merge() {
    let env = Env::new();
    let (r, _) = dirty(&env);
    let wip = r.change("@");
    r.ok(&["new", "@-"]);
    r.write("other.txt", "o\n");
    let other = r.commit("other work");
    r.ok(&["new", other.as_str(), wip.as_str()]);
    assert_eq!(r.read("a.txt"), "a2 wip\n");
    assert_eq!(r.read("other.txt"), "o\n");
    assert_eq!(r.read("new.txt"), "untracked in Git terms\n");
}
