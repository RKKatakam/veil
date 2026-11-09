//! Virtual workspaces (`vl ws`), Veil's worktrees: git t2400-worktree-add,
//! t2401 (prune), t2402 (list), t2403 (move), t2406 (repair), t2407
//! (heads), t3908 (stash in worktree); jj test_workspaces; lib
//! test_workspace.

use super::*;

fn based(env: &Env) -> (R<'_>, String) {
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    let base = r.commit("base");
    (r, base)
}

fn ws_lines(r: &R) -> Vec<String> {
    r.out(&["ws", "list"]).lines().map(String::from).collect()
}

// Scenario from git t2400-worktree-add.sh "add": a workspace is created
// on the parents of `@` (like a fresh checkout), and no directory appears.
#[test]
fn ws_new_creates_a_virtual_workspace_on_the_parents_of_at() {
    let env = Env::new();
    let (r, base) = based(&env);
    let before = r.disk();
    let out = r.ok(&["ws", "new", "agent"]);
    assert!(out.contains("Created virtual workspace agent"), "{out}");
    assert!(out.contains("no directory was created"), "{out}");
    assert_eq!(r.disk(), before);
    assert!(!env.root.join("agent").exists());
    assert_eq!(r.change("agent@-"), base);
    assert!(r.out(&["log"]).contains("agent@"));
}

// Scenario from git t2400-worktree-add.sh "add <path> <commit>".
#[test]
fn ws_new_on_a_given_revision() {
    let env = Env::new();
    let (r, base) = based(&env);
    r.write("b.txt", "b\n");
    r.commit("two");
    r.ok(&["ws", "new", "old", "-r", base.as_str()]);
    assert_eq!(r.change("old@-"), base);
    assert!(r.run(&["ws", "cat", "old", "b.txt"]).status.code() == Some(1));
    assert_eq!(r.out(&["ws", "cat", "old", "a.txt"]), "a\n");
}

// Scenario from git t2402-worktree-list.sh: the attached workspace is marked.
#[test]
fn ws_list_marks_the_attached_workspace() {
    let env = Env::new();
    let (r, _) = based(&env);
    r.ok(&["ws", "new", "agent"]);
    let l = ws_lines(&r);
    assert_eq!(l.len(), 2, "{l:?}");
    assert!(l.iter().any(|x| x.starts_with("* default:")), "{l:?}");
    assert!(l.iter().any(|x| x.starts_with("  agent:")), "{l:?}");
    r.ok(&["ws", "switch", "agent"]);
    let l = ws_lines(&r);
    assert!(l.iter().any(|x| x.starts_with("* agent:")), "{l:?}");
}

// Scenario from git t2400-worktree-add.sh "add refuses to checkout locked
// branch" / existing path: duplicate and malformed names are refused.
#[test]
fn ws_new_refuses_duplicate_and_malformed_names() {
    let env = Env::new();
    let (r, _) = based(&env);
    r.ok(&["ws", "new", "agent"]);
    let err = r.fails(&["ws", "new", "agent"]);
    assert!(err.contains("already exists"), "{err}");
    let err = r.fails(&["ws", "new", "default"]);
    assert!(err.contains("already exists"), "{err}");
    let long = "w".repeat(65);
    for bad in ["", "has space", "a/b", "../x", "x@", "ü", long.as_str()] {
        let err = r.fails(&["ws", "new", bad]);
        assert!(err.contains("invalid workspace name"), "{bad:?}: {err}");
    }
    assert_eq!(ws_lines(&r).len(), 2);
}

// Scenario from jj test_workspaces.rs: switching records the current
// workspace's files first, replaces them, and switching back restores them.
#[test]
fn ws_switch_swaps_the_files_and_keeps_both_sides() {
    let env = Env::new();
    let (r, _) = based(&env);
    r.ok(&["ws", "new", "agent"]);
    r.write("default-only.txt", "d\n");
    r.ok(&["ws", "switch", "agent"]);
    assert!(!r.exists("default-only.txt"));
    assert_eq!(r.read("a.txt"), "a\n");
    r.write("agent-only.txt", "g\n");
    r.ok(&["ws", "switch", "default"]);
    assert_eq!(r.read("default-only.txt"), "d\n");
    assert!(!r.exists("agent-only.txt"));
    assert_eq!(r.out(&["ws", "cat", "agent", "agent-only.txt"]), "g\n");
}

// Scenario from git t2400 (switching to what is already checked out).
#[test]
fn ws_switch_to_the_attached_workspace_changes_nothing() {
    let env = Env::new();
    let (r, _) = based(&env);
    r.write("wip.txt", "w\n");
    let out = r.run(&["ws", "switch", "default"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(r.read("wip.txt"), "w\n");
    assert!(r.changes().contains(&"A wip.txt".to_string()));
}

// Scenario from git t2403-worktree-move.sh / t2400 (unknown worktree).
#[test]
fn ws_switch_to_an_unknown_workspace_fails_and_changes_nothing() {
    let env = Env::new();
    let (r, _) = based(&env);
    r.write("wip.txt", "w\n");
    let before = r.disk();
    let err = r.fails(&["ws", "switch", "ghost"]);
    assert!(err.contains("ghost"), "{err}");
    assert_eq!(r.disk(), before);
}

// Scenario from git t2401-worktree-prune.sh / jj test_workspaces.rs
// "forget": removing a workspace keeps its change in history.
#[test]
fn ws_rm_removes_the_workspace_but_keeps_its_change() {
    let env = Env::new();
    let (r, _) = based(&env);
    r.ok(&["ws", "new", "agent"]);
    r.ws_write("agent", "notes.md", "agent notes\n");
    let change = r.change("agent@");
    r.ok(&["ws", "rm", "agent"]);
    assert_eq!(ws_lines(&r).len(), 1);
    assert_eq!(r.cat("notes.md", &change), "agent notes\n");
    let err = r.fails(&["ws", "rm", "agent"]);
    assert!(err.contains("not found"), "{err}");
}

// Scenario from git t2401 (cannot remove the main worktree).
#[test]
fn ws_rm_of_the_attached_workspace_is_refused() {
    let env = Env::new();
    let (r, _) = based(&env);
    let err = r.fails(&["ws", "rm", "default"]);
    assert!(err.contains("switch away first"), "{err}");
    assert_eq!(ws_lines(&r).len(), 1);
}

// Scenario from jj test_workspaces.rs: creating and removing workspaces
// are operations that `vl undo` reverts.
#[test]
fn undo_reverts_ws_new_and_ws_rm() {
    let env = Env::new();
    let (r, _) = based(&env);
    r.ok(&["ws", "new", "agent"]);
    r.ok(&["undo"]);
    assert_eq!(ws_lines(&r).len(), 1);
    r.ok(&["ws", "new", "agent"]);
    r.ok(&["ws", "rm", "agent"]);
    r.ok(&["undo"]);
    assert_eq!(ws_lines(&r).len(), 2);
}

// Scenario from git t2400-worktree-add.sh (work in the other tree): `vl ws
// exec` runs a command in a sandbox with the workspace's files and
// records what it leaves; the project directory is untouched.
#[test]
fn ws_exec_records_the_result_and_leaves_the_project_alone() {
    let env = Env::new();
    let (r, _) = based(&env);
    r.ok(&["ws", "new", "agent"]);
    let before = r.disk();
    let out = r.run(&["ws", "exec", "agent", "-m", "agent: notes", "--", "sh", "-c", "cat a.txt; echo n > notes.md; rm a.txt"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(stdout_of(&out), "a\n", "stdout belongs to the command");
    assert_eq!(r.disk(), before);
    assert_eq!(r.description("agent@"), "agent: notes");
    let paths = r.paths("agent@");
    assert_eq!(paths, vec!["notes.md"]);
    // The sandbox is gone.
    let leftovers: Vec<_> = std::fs::read_dir(env.root.join("tmp")).unwrap().flatten().collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

// Scenario from jj test_workspaces.rs (command failure): the result is
// recorded whatever the exit status, and `vl` exits with it.
#[test]
fn ws_exec_propagates_the_exit_status_and_still_records() {
    let env = Env::new();
    let (r, _) = based(&env);
    r.ok(&["ws", "new", "agent"]);
    let out = r.run(&["ws", "exec", "agent", "--", "sh", "-c", "echo partial > out.txt; exit 7"]);
    assert_eq!(out.status.code(), Some(7), "{}", text(&out));
    assert_eq!(r.out(&["ws", "cat", "agent", "out.txt"]), "partial\n");
}

// Scenario from git t2400 (the main worktree's own work): exec into the
// attached workspace is refused.
#[test]
fn ws_exec_into_the_attached_workspace_is_refused() {
    let env = Env::new();
    let (r, _) = based(&env);
    let err = r.fails(&["ws", "exec", "default", "--", "true"]);
    assert!(err.contains("just run the command"), "{err}");
    let err = r.fails(&["ws", "exec", "--", "true"]);
    assert!(err.contains("--ephemeral"), "{err}");
}

// Scenario from git t2400 (no repository metadata in the sandbox): the
// command cannot reach the repository from inside it.
#[test]
fn ws_exec_sandbox_has_no_repository_metadata() {
    let env = Env::new();
    let (r, _) = based(&env);
    r.ok(&["ws", "new", "agent"]);
    let out = r.run(&["ws", "exec", "agent", "--", "sh", "-c", "test ! -e .veil"]);
    assert!(out.status.success(), "{}", text(&out));
}

// Scenario from jj test_workspaces.rs with Veil's invariants: an isolated
// file is not copied into the sandbox, and one written there is not
// recorded.
#[test]
fn ws_exec_applies_the_policy_to_what_the_command_writes() {
    let env = Env::new();
    let (r, _) = based(&env);
    r.write(".netrc", DOTENV);
    r.ok(&["ws", "new", "agent"]);
    let out = r.run(&["ws", "exec", "agent", "--", "sh", "-c", &format!("test ! -e .netrc && printf '%s' '{}' > .netrc && echo built > out.txt", DOTENV.trim())]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(r.paths("agent@"), vec!["a.txt", "out.txt"]);
    assert!(!contains_bytes(&all_bytes(&r.path(".veil/objects")), "Xk29vLq8sPz"));
}

// Scenario from jj test_workspaces.rs / Veil guide: a one-shot ephemeral
// run on a revision records a new change on top of it, in no workspace.
#[test]
fn ws_exec_ephemeral_records_a_new_change_on_the_revision() {
    let env = Env::new();
    let (r, base) = based(&env);
    let out = r.run(&["ws", "exec", "--ephemeral", "-r", base.as_str(), "-m", "codegen", "--", "sh", "-c", "echo gen > gen.txt"]);
    assert!(out.status.success(), "{}", text(&out));
    let t = text(&out);
    let id = t
        .lines()
        .find_map(|l| l.strip_prefix("Recorded "))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("{t}"))
        .to_string();
    assert_eq!(r.change(&format!("{id}-")), base);
    assert_eq!(r.cat("gen.txt", &id), "gen\n");
    assert_eq!(ws_lines(&r).len(), 1, "no workspace was created");
    assert!(!r.exists("gen.txt"));
}

// Scenario from jj test_workspaces.rs (writing to another workspace
// without a checkout): `vl ws write` and `vl ws cat`.
#[test]
fn ws_write_and_cat_without_a_checkout() {
    let env = Env::new();
    let (r, _) = based(&env);
    r.ok(&["ws", "new", "agent"]);
    r.ws_write("agent", "deep/dir/x.txt", "written\n");
    assert_eq!(r.out(&["ws", "cat", "agent", "deep/dir/x.txt"]), "written\n");
    assert!(!r.exists("deep"));
    let err = r.fails(&["ws", "cat", "agent", "nope.txt"]);
    assert!(err.contains("not found"), "{err}");
    let err = r.fails(&["ws", "write", "agent", "../escape"]);
    assert!(err.contains("escapes"), "{err}");
    let err = r.fails(&["ws", "write", "default", "x.txt"]);
    assert!(err.contains("edit the file directly"), "{err}");
}

// Scenario from jj test_workspaces.rs "stale working copy": another
// workspace rewrites the change this directory has checked out; the next
// command brings the directory up to date without losing local edits.
#[test]
fn a_working_copy_rewritten_from_another_workspace_is_updated() {
    let env = Env::new();
    let (r, _) = based(&env);
    r.ok(&["ws", "new", "agent"]);
    // Both workspaces now share one change.
    r.ok(&["edit", "agent@"]);
    r.write("mine.txt", "local edit\n");
    r.ok(&["status"]);
    r.ws_write("agent", "theirs.txt", "from agent\n");
    r.write("mine.txt", "local edit 2\n");
    r.ok(&["status"]);
    assert_eq!(r.read("theirs.txt"), "from agent\n");
    assert_eq!(r.read("mine.txt"), "local edit 2\n");
    assert_eq!(r.cat("mine.txt", "@"), "local edit 2\n");
}

// Scenario from git t3908-stash-in-worktree.sh / the guide: committing in
// another workspace moves the tags at its parent, as in `default`.
#[test]
fn commit_in_a_switched_workspace_moves_the_tag_at_its_parent() {
    let env = Env::new();
    let (r, base) = based(&env);
    r.ok(&["tag", "set", "main", "-r", base.as_str()]);
    r.ok(&["ws", "new", "agent"]);
    r.ok(&["ws", "switch", "agent"]);
    r.write("feature.txt", "f\n");
    let c = r.commit("feature");
    assert_eq!(r.change("main"), c);
}

// Scenario from git t2407-worktree-heads.sh: two workspaces on one base
// work independently, and each one's commits stay in its own line.
#[test]
fn two_workspaces_on_one_base_are_independent() {
    let env = Env::new();
    let (r, base) = based(&env);
    r.ok(&["ws", "new", "one", "-r", base.as_str()]);
    r.ok(&["ws", "new", "two", "-r", base.as_str()]);
    r.ok(&["ws", "exec", "one", "--", "sh", "-c", "echo 1 > a.txt"]);
    r.ok(&["ws", "exec", "two", "--", "sh", "-c", "echo 2 > a.txt"]);
    assert_eq!(r.out(&["ws", "cat", "one", "a.txt"]), "1\n");
    assert_eq!(r.out(&["ws", "cat", "two", "a.txt"]), "2\n");
    assert_eq!(r.read("a.txt"), "a\n");
    assert_eq!(r.change("one@-"), base);
    assert_eq!(r.change("two@-"), base);
}

// Scenario from git t2406-worktree-repair.sh: the directory's attachment
// record is lost; commands still open the repository (default workspace).
#[test]
fn a_missing_checkout_record_is_survivable() {
    let env = Env::new();
    let (r, _) = based(&env);
    r.write("wip.txt", "w\n");
    r.ok(&["status"]);
    let rec = r.path(".veil/local/checkout.json");
    assert!(rec.exists(), "control: the attachment record is {}", rec.display());
    std::fs::remove_file(&rec).unwrap();
    let out = r.run(&["status"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(r.read("wip.txt"), "w\n");
}
