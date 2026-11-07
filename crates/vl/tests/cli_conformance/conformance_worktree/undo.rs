//! The operation log, `vl undo` and `vl op restore`: jj
//! test_undo_redo_commands, test_operations, test_op_restore_command,
//! test_op_revert_command, test_concurrent_operations; lib
//! test_operations; git reflog-style recovery (t1410 is plumbing; the
//! everyday part is "undo what I just did").

use super::*;

fn two_commits(env: &Env) -> (R<'_>, String, String) {
    let r = env.repo("p");
    r.write("a.txt", "1\n");
    let one = r.commit("one");
    r.write("a.txt", "2\n");
    let two = r.commit("two");
    (r, one, two)
}

// Scenario from jj test_undo_redo_commands.rs "undo a commit". `vl
// commit` records the directory and commits in one operation (owner,
// 2026-11-06): undo takes back both, so the edits the commit recorded leave
// the working copy too, and `vl redo` brings them back.
#[test]
fn undo_of_a_commit_reopens_the_change() {
    let env = Env::new();
    let (r, one, two) = two_commits(&env);
    let ops = r.out(&["op", "log", "-n", "2"]);
    assert!(ops.contains("commit change") && !ops.contains("snapshot working copy"), "one operation per commit:\n{ops}");
    let out = r.ok(&["undo"]);
    assert!(out.contains(&format!("Undid: commit change {}", &two[..8])), "{out}");
    assert_eq!(r.change("@"), two);
    assert_eq!(r.change("@-"), one);
    assert_eq!(r.read("a.txt"), "1\n");
    assert_eq!(r.description("@"), "(no description set)");
    r.ok(&["redo"]);
    assert_eq!(r.read("a.txt"), "2\n");
    assert_eq!(r.description("@-"), "two");
}

// Scenario from the guide ("Both keep the files on disk that you had not
// recorded yet") / jj test_undo_redo_commands.rs.
#[test]
fn undo_keeps_unrecorded_edits() {
    let env = Env::new();
    let (r, _, _) = two_commits(&env);
    r.write("new-work.txt", "do not lose me\n");
    r.write("b.txt", "3\n");
    r.ok(&["undo"]);
    assert_eq!(r.read("new-work.txt"), "do not lose me\n");
    assert_eq!(r.read("b.txt"), "3\n");
}

// Scenario from jj test_undo_redo_commands.rs "undo twice": the guide
// says "Run it again to go further back" (BUG-206).
#[test]
fn undo_again_goes_further_back() {
    let env = Env::new();
    let (r, one, two) = two_commits(&env);
    r.ok(&["undo"]); // undo "commit two": @ is `two`, reopened
    r.ok(&["undo"]); // further back: undo the snapshot / "commit one"
    assert_ne!(r.change("@-"), two, "the second undo re-applied the commit it should step past");
    let log = r.out(&["log"]);
    // Description lines only: a random change id can contain "two".
    assert!(!log.lines().any(|l| l.trim_start_matches(['│', ' ']).trim_end() == "two"), "{log}");
    let _ = one;
}

// Scenario from jj test_undo_redo_commands.rs "redo": `vl redo` takes the
// undos back, newest first, and stops when there are none left.
#[test]
fn redo_takes_back_successive_undos() {
    let env = Env::new();
    let (r, one, two) = two_commits(&env);
    let log_after = r.out(&["log"]);
    r.ok(&["undo"]);
    r.ok(&["undo"]);
    assert_eq!(r.description("@"), "(no description set)");
    let out = r.ok(&["redo"]);
    assert!(out.contains(&format!("Redid: commit change {}", &one[..8])), "{out}");
    assert_eq!(r.change("@-"), one);
    let out = r.ok(&["redo"]);
    assert!(out.contains(&format!("Redid: commit change {}", &two[..8])), "{out}");
    assert_eq!(r.change("@-"), two);
    assert_eq!(r.out(&["log"]), log_after);
    let err = r.fails(&["redo"]);
    assert!(err.contains("nothing to redo"), "{err}");
}

// Scenario from jj test_undo_redo_commands.rs: a new command after an undo
// clears what could be redone; edits made in between do not.
#[test]
fn a_new_command_clears_the_redo_stack_but_edits_do_not() {
    let env = Env::new();
    let (r, _, two) = two_commits(&env);
    r.ok(&["undo"]);
    r.write("wip.txt", "unsaved\n");
    r.ok(&["status"]); // records the edit: not a command
    r.ok(&["redo"]);
    assert_eq!(r.change("@-"), two);
    assert_eq!(r.read("wip.txt"), "unsaved\n", "redo keeps unrecorded edits");
    r.ok(&["undo"]);
    r.ok(&["describe", "-m", "something new"]);
    let err = r.fails(&["redo"]);
    assert!(err.contains("nothing to redo"), "{err}");
}

// Undo and redo of `vl ws switch` move the project directory back and
// forth; repeated undo then continues before the switch.
#[test]
fn undo_and_redo_of_a_workspace_switch() {
    let env = Env::new();
    let (r, _, _) = two_commits(&env);
    r.ok(&["ws", "new", "w"]);
    r.ok(&["ws", "switch", "w"]);
    r.write("in-w.txt", "w edit\n");
    let out = r.ok(&["undo"]);
    assert!(out.contains("Undid: switch the project directory from workspace 'default' to 'w'"), "{out}");
    assert!(!r.path("in-w.txt").exists());
    let out = r.ok(&["redo"]);
    assert!(out.contains("Redid: switch the project directory from workspace 'default' to 'w'"), "{out}");
    assert_eq!(r.read("in-w.txt"), "w edit\n");
    r.ok(&["undo"]);
    // Further back: the creation of `w`, which holds a recorded edit.
    let err = r.fails(&["undo"]);
    assert!(err.contains("workspace 'w'") && err.contains("Nothing was changed"), "{err}");
    assert_eq!(r.out(&["ws", "cat", "w", "in-w.txt"]), "w edit\n");
}

// Scenario from jj test_undo_redo_commands.rs: nothing to undo in a fresh
// repository.
#[test]
fn undo_in_a_fresh_repository_has_nothing_to_undo() {
    let env = Env::new();
    let r = env.repo("p");
    let err = r.fails(&["undo"]);
    assert!(err.contains("nothing to undo"), "{err}");
    assert!(r.path(".veilpolicy").exists());
}

// Scenario from jj test_operations.rs "op log": newest first, `-n`.
#[test]
fn op_log_lists_operations_newest_first() {
    let env = Env::new();
    let (r, _, two) = two_commits(&env);
    let log = r.out(&["op", "log"]);
    let first = log.lines().next().unwrap();
    assert!(first.contains(&format!("commit change {}", &two[..8])), "{log}");
    assert!(log.lines().last().unwrap().contains("initialize repository"), "{log}");
    assert_eq!(r.out(&["op", "log", "-n", "2"]).lines().count(), 2);
    assert!(r.out(&["op", "log", "-n", "0"]).is_empty());
    for l in log.lines() {
        let id = l.split_whitespace().next().unwrap();
        assert_eq!(id.len(), 8, "{l}");
        assert!(l.contains(" alice "), "{l}");
    }
}

// Scenario from jj test_operations.rs: automatic snapshots are operations;
// a command with nothing to record adds none.
#[test]
fn snapshots_are_operations_but_idle_commands_add_none() {
    let env = Env::new();
    let (r, _, _) = two_commits(&env);
    let n = r.op_count();
    r.ok(&["status"]);
    r.ok(&["log"]);
    r.ok(&["files"]);
    assert_eq!(r.op_count(), n, "nothing changed, nothing recorded");
    r.write("b.txt", "b\n");
    r.ok(&["status"]);
    assert_eq!(r.op_count(), n + 1);
    assert!(r.out(&["op", "log", "-n", "1"]).contains("snapshot working copy of 'default'"));
}

// Scenario from jj test_global_opts.rs "--ignore-working-copy": with
// `--no-snapshot`, edits are not recorded.
#[test]
fn no_snapshot_does_not_record_the_disk() {
    let env = Env::new();
    let (r, _, _) = two_commits(&env);
    let n = r.op_count();
    r.write("b.txt", "b\n");
    let st = r.out(&["--no-snapshot", "status"]);
    assert!(st.contains("The working copy has no changes."), "{st}");
    assert_eq!(r.op_count(), n);
    assert!(r.status().contains("A b.txt"));
}

// Scenario from jj test_op_restore_command.rs: restore to an earlier
// operation by id prefix; edits since are kept.
#[test]
fn op_restore_returns_to_an_earlier_state_keeping_edits() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "1\n");
    let one = r.commit("one");
    r.ok(&["tag", "set", "t1", "-r", one.as_str()]);
    let op = r.out(&["op", "log", "-n", "1"]).split_whitespace().next().unwrap().to_string();
    r.write("a.txt", "2\n");
    r.commit("two");
    r.ok(&["tag", "delete", "t1"]);
    r.write("wip.txt", "wip\n");
    let out = r.ok(&["op", "restore", &op[..6]]);
    assert!(out.contains(&format!("Restored to operation {}", &op[..8])), "{out}");
    assert_eq!(r.change("t1"), one);
    assert_eq!(r.read("a.txt"), "1\n");
    assert_eq!(r.read("wip.txt"), "wip\n");
    // Description lines only: a random change id can contain "two" (BUG-1127).
    let log = r.out(&["log"]);
    assert!(!log.lines().any(|l| l.trim_start_matches(['│', ' ']).trim_end() == "two"), "{log}");
}

// Scenario from jj test_op_restore_command.rs: op restore is itself an
// operation, and undoable.
#[test]
fn op_restore_is_undoable() {
    let env = Env::new();
    let (r, _, two) = two_commits(&env);
    let init = r.out(&["op", "log"]).lines().last().unwrap().split_whitespace().next().unwrap().to_string();
    r.ok(&["op", "restore", init.as_str()]);
    let log = r.out(&["log"]);
    assert!(!log.lines().any(|l| l.trim_start_matches(['│', ' ']).trim_end() == "two"), "{log}");
    r.ok(&["undo"]);
    assert_eq!(r.change("@-"), two);
}

// Scenario from jj test_op_restore_command.rs (bad operation ids).
#[test]
fn op_restore_with_a_bad_id_fails_and_changes_nothing() {
    let env = Env::new();
    let (r, _, _) = two_commits(&env);
    let n = r.op_count();
    let err = r.fails(&["op", "restore", "zzzz"]);
    assert!(err.contains("no operation matches"), "{err}");
    let err = r.fails(&["op", "restore", ""]);
    assert!(err.contains("ambiguous"), "{err}");
    assert_eq!(r.op_count(), n);
}

// Scenario from jj test_undo_redo_commands.rs: undo of tag changes.
#[test]
fn undo_of_tag_set_and_delete() {
    let env = Env::new();
    let (r, one, _) = two_commits(&env);
    r.ok(&["tag", "set", "main", "-r", one.as_str()]);
    r.ok(&["undo"]);
    assert!(r.tags().is_empty());
    r.ok(&["tag", "set", "main", "-r", one.as_str()]);
    r.ok(&["tag", "delete", "main"]);
    r.ok(&["undo"]);
    assert_eq!(r.change("main"), one);
}

// Scenario from jj test_undo_redo_commands.rs: undo of describe.
#[test]
fn undo_of_describe() {
    let env = Env::new();
    let (r, one, _) = two_commits(&env);
    r.ok(&["describe", "-r", one.as_str(), "-m", "renamed"]);
    assert_eq!(r.description(one.as_str()), "renamed");
    r.ok(&["undo"]);
    assert_eq!(r.description(one.as_str()), "one");
}

// Scenario from jj test_abandon_command.rs + undo: abandoning the working
// copy discards its files; undo brings them back.
#[test]
fn undo_of_abandon_brings_the_files_back() {
    let env = Env::new();
    let (r, _, two) = two_commits(&env);
    r.write("wip.txt", "wip\n");
    let wc = r.change("@");
    r.ok(&["abandon"]);
    assert!(!r.exists("wip.txt"));
    assert_eq!(r.change("@-"), two);
    r.ok(&["undo"]);
    assert_eq!(r.change("@"), wc);
    assert_eq!(r.read("wip.txt"), "wip\n");
}

// Scenario from jj test_undo_redo_commands.rs: undo of `vl new` / `vl edit`.
#[test]
fn undo_of_new_and_edit_returns_to_the_previous_working_copy() {
    let env = Env::new();
    let (r, one, _) = two_commits(&env);
    r.write("wip.txt", "wip\n");
    let wc = r.change("@");
    r.ok(&["new", one.as_str()]);
    assert!(!r.exists("wip.txt"));
    r.ok(&["undo"]);
    assert_eq!(r.change("@"), wc);
    assert_eq!(r.read("wip.txt"), "wip\n");
    r.ok(&["edit", one.as_str()]);
    assert_eq!(r.read("a.txt"), "1\n");
    r.ok(&["undo"]);
    assert_eq!(r.change("@"), wc);
    assert_eq!(r.read("a.txt"), "2\n");
}

// Scenario from jj test_concurrent_operations.rs: concurrent commands in
// one repository are serialised; every one is recorded and nothing is lost.
#[test]
fn concurrent_commands_are_serialised() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("base.txt", "b\n");
    r.commit("base");
    let n = r.op_count();
    let kids: Vec<_> = (0..6)
        .map(|i| {
            r.cmd(&["tag", "set", &format!("t{i}"), "-r", "@-"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for k in kids {
        let out = k.wait_with_output().unwrap();
        assert!(out.status.success(), "{}", text(&out));
    }
    assert_eq!(r.tags().len(), 6);
    assert!(r.op_count() >= n + 6);
}

// Scenario from jj test_concurrent_operations.rs with commits racing on
// the same working copy: every file ends up recorded exactly once.
#[test]
fn concurrent_commits_lose_no_file() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("base.txt", "b\n");
    r.commit("base");
    let kids: Vec<_> = (0..4)
        .map(|i| {
            r.write(&format!("f{i}.txt"), format!("{i}\n"));
            r.cmd(&["commit", "-m", &format!("c{i}")])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for k in kids {
        let out = k.wait_with_output().unwrap();
        assert!(out.status.success(), "{}", text(&out));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut rev = "@".to_string();
    while r.snap(&rev) != r.snap("root") {
        for p in r.paths(&rev) {
            seen.insert(p);
        }
        rev.push('-');
    }
    for i in 0..4 {
        assert!(seen.contains(&format!("f{i}.txt")), "{seen:?}");
        assert_eq!(r.read(&format!("f{i}.txt")), format!("{i}\n"));
    }
}

// Scenario from jj test_operations.rs: `vl undo` after an automatic
// snapshot undoes the last *command*, not the snapshot.
#[test]
fn undo_skips_the_automatic_snapshot() {
    let env = Env::new();
    let (r, _, two) = two_commits(&env);
    r.write("x.txt", "x\n");
    r.ok(&["status"]); // records x.txt as an automatic snapshot
    let out = r.ok(&["undo"]);
    assert!(out.contains("commit change"), "{out}");
    assert_eq!(r.change("@"), two);
    assert_eq!(r.read("x.txt"), "x\n");
}
