//! `vl gc`: reachability, the grace period for recent unreachable objects,
//! op-log pruning, and safety next to other commands.

use std::path::{Path, PathBuf};

use super::support::*;

fn gc(env: &Env, dir: &Path, args: &[&str]) -> String {
    let mut a = vec!["gc"];
    a.extend_from_slice(args);
    env.ok("alice", dir, &a)
}

/// `N pending deletion` / `N deleted` from gc's summary line.
fn count(out: &str, what: &str) -> usize {
    let line = out
        .lines()
        .find(|l| l.starts_with("Objects:"))
        .unwrap_or_else(|| panic!("{out}"));
    line.split(',')
        .find(|p| p.trim().ends_with(what))
        .and_then(|p| p.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no '{what}' in {line}"))
}

fn with_abandoned_work(env: &Env) -> PathBuf {
    let proj = env.project("alice", "proj", &[("keep.txt", "kept\n")]);
    write(&proj, "experiment.txt", "abandoned experiment 9090\n");
    env.ok("alice", &proj, &["commit", "-m", "experiment"]);
    env.ok("alice", &proj, &["abandon", "@-"]);
    proj
}

// Scenario from git t6500-gc.sh: "gc empty repository".
#[test]
fn gc_of_an_empty_repository() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    let out = gc(&env, &proj, &[]);
    assert_eq!(count(&out, "deleted"), 0, "{out}");
    env.ok("alice", &proj, &["fsck"]);
    env.ok("alice", &proj, &["status"]);
}

// Scenario from git t6500-gc.sh: "gc --gobbledegook" (bad options exit 2 with usage).
#[test]
fn gc_with_bad_options_fails_with_usage() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    for args in [
        vec!["gc", "--gobbledegook"],
        vec!["gc", "--grace-minutes", "soon"],
        vec!["gc", "--keep-ops-days", "-1"],
        vec!["gc", "--level", "x"],
    ] {
        let (code, out) = env.code("alice", &proj, &args);
        assert_eq!(code, 2, "{args:?}: {out}");
    }
}

// Scenario from git t5304-prune.sh / jj test_gc.rs: reachable history survives gc, everything packed.
#[test]
fn gc_keeps_all_reachable_history_and_packs_it() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "v0\n")]);
    for i in 1..6 {
        env.commit(
            "alice",
            &proj,
            &format!("v{i}"),
            &[("a.txt", &format!("v{i}\n"))],
        );
    }
    gc(&env, &proj, &["--prune-now"]);
    assert!(
        loose_objects(&proj).is_empty(),
        "{:?}",
        loose_objects(&proj)
    );
    assert_eq!(packs(&proj).len(), 1);
    for i in 0..6 {
        let rev = format!("main{}", "-".repeat(5 - i));
        assert_eq!(
            env.stdout("alice", &proj, &["cat", "a.txt", "-r", &rev]),
            format!("v{i}\n")
        );
    }
    env.ok("alice", &proj, &["fsck"]);
}

// Scenario from git t5304-prune.sh: "prune --expire" / "gc: implicit prune --expire" — recent
// unreachable objects are kept for the grace period.
#[test]
fn unreachable_objects_wait_out_the_grace_period() {
    let env = Env::new();
    let proj = with_abandoned_work(&env);
    let out = gc(&env, &proj, &["--keep-ops-days", "0"]);
    let pending = count(&out, "pending deletion");
    assert!(pending > 0, "{out}");
    assert_eq!(count(&out, "deleted"), 0, "{out}");
    // A second run within the grace period deletes nothing either.
    let out = gc(&env, &proj, &[]);
    assert_eq!(count(&out, "deleted"), 0, "{out}");
    assert!(count(&out, "pending deletion") >= pending, "{out}");
    // A zero grace period on a later run deletes them.
    let out = gc(&env, &proj, &["--grace-minutes", "0"]);
    assert!(count(&out, "deleted") >= pending, "{out}");
    assert_eq!(count(&out, "pending deletion"), 0, "{out}");
    env.ok("alice", &proj, &["fsck"]);
}

// Scenario from git t5304-prune.sh: "prune: prune unreachable heads" right away with --prune-now.
#[test]
fn prune_now_deletes_unreachable_objects_at_once() {
    let env = Env::new();
    let proj = with_abandoned_work(&env);
    // The current operation and its parent are always kept: move two operations on.
    env.commit("alice", &proj, "later", &[("later.txt", "later\n")]);
    env.commit("alice", &proj, "later still", &[("later2.txt", "later\n")]);
    let out = gc(&env, &proj, &["--keep-ops-days", "0", "--prune-now"]);
    assert!(count(&out, "deleted") > 0, "{out}");
    assert!(!contains(
        &everything_in(&proj),
        "abandoned experiment 9090"
    ));
    assert_eq!(
        env.stdout("alice", &proj, &["cat", "keep.txt", "-r", "main"]),
        "kept\n"
    );
}

// Scenario from git t5304-prune.sh: "gc --prune=never" — with the whole op log kept
// (the default), nothing an operation saw is deleted, abandoned work included.
#[test]
fn abandoned_work_survives_gc_while_the_op_log_keeps_it() {
    let env = Env::new();
    let proj = with_abandoned_work(&env);
    let out = gc(&env, &proj, &["--prune-now"]);
    assert_eq!(count(&out, "deleted"), 0, "{out}");
    assert!(contains(&everything_in(&proj), "abandoned experiment 9090"));
    // Undo the abandon: the experiment is back.
    env.ok("alice", &proj, &["undo"]);
    let log = env.stdout("alice", &proj, &["log"]);
    assert!(log.contains("experiment"), "{log}");
}

// Scenario from jj test_gc.rs / test_operations.rs: undo keeps working after op-log pruning
// (the current operation and its parent are kept).
#[test]
fn undo_works_after_op_log_pruning() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    env.commit("alice", &proj, "b", &[("b", "b\n")]);
    env.commit("alice", &proj, "c", &[("c", "c\n")]);
    gc(&env, &proj, &["--keep-ops-days", "0", "--prune-now"]);
    env.ok("alice", &proj, &["undo"]);
    let log = env.stdout("alice", &proj, &["log"]);
    assert!(log.contains("b") && log.contains("initial"), "{log}");
    // A second undo goes further back (BUG-247), into the pruned operations:
    // it refuses, saying why, and changes nothing; redo still works.
    let out = env.fails("alice", &proj, &["undo"]);
    assert!(out.contains("pruned"), "{out}");
    env.ok("alice", &proj, &["redo"]);
    let log = env.stdout("alice", &proj, &["log"]);
    assert!(log.lines().any(|l| l.trim_start_matches(['│', ' ']).trim_end() == "c"), "{log}");
    env.ok("alice", &proj, &["op", "log"]);
    env.ok("alice", &proj, &["fsck"]);
}

// Scenario from git t6500-gc.sh: gc twice is idempotent.
#[test]
fn gc_twice_is_idempotent() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    gc(&env, &proj, &["--prune-now"]);
    let first = listing(&proj.join(".veil/objects"));
    let out = gc(&env, &proj, &["--prune-now"]);
    assert_eq!(count(&out, "deleted"), 0, "{out}");
    let second = listing(&proj.join(".veil/objects"));
    assert_eq!(first.len(), second.len(), "{first:?} vs {second:?}");
}

// Scenario from git t5304-prune.sh: remote-tracking refs are roots (Veil: remote tags).
#[test]
fn gc_keeps_what_only_a_remote_tag_reaches() {
    let env = Env::new();
    let (alice, hub) = env.project_with_hub("alice", "alice", "hub", &[("a.txt", "a\n")]);
    let bob = env.clone("bob", &hub, "bob");
    env.commit(
        "alice",
        &alice,
        "remote only",
        &[("r.txt", "only on origin/main\n")],
    );
    env.ok("alice", &alice, &["push"]);
    env.ok("bob", &bob, &["pull"]);
    env.ok("bob", &bob, &["tag", "delete", "main"]);
    env.ok("bob", &bob, &["gc", "--keep-ops-days", "0", "--prune-now"]);
    assert_eq!(
        env.stdout("bob", &bob, &["cat", "r.txt", "-r", "origin/main"]),
        "only on origin/main\n"
    );
    env.ok("bob", &bob, &["fsck"]);
}

// Scenario from git t5304-prune.sh: "prune: handle HEAD in multiple worktrees" (Veil: workspaces).
#[test]
fn gc_keeps_every_workspace_and_its_unrecorded_base() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "main"]);
    env.ok(
        "alice",
        &proj,
        &[
            "ws",
            "exec",
            "agent",
            "-m",
            "agent work",
            "--",
            "sh",
            "-c",
            "echo agent-only > agent.txt",
        ],
    );
    gc(&env, &proj, &["--keep-ops-days", "0", "--prune-now"]);
    assert_eq!(
        env.stdout("alice", &proj, &["ws", "cat", "agent", "agent.txt"]),
        "agent-only\n"
    );
    env.ok("alice", &proj, &["fsck"]);
}

// Veil: gc keeps cloaked content, and a non-member's gc keeps what it cannot read.
#[test]
fn gc_keeps_cloaked_content_and_content_it_cannot_read() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["cloak", "secrets/.env.s"]);
    write(&proj, "secrets/.env.s", "sealed\n");
    write(&proj, "p.txt", "public\n");
    env.ok("alice", &proj, &["commit", "-m", "c"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["remote", "add", "origin", "../hub"]);
    env.ok("alice", &proj, &["push"]);
    gc(&env, &proj, &["--keep-ops-days", "0", "--prune-now"]);
    assert_eq!(
        env.stdout("alice", &proj, &["cat", "secrets/.env.s", "-r", "main"]),
        "sealed\n"
    );
    let bob = env.clone("bob", &env.path("hub"), "bob");
    env.ok("bob", &bob, &["gc", "--keep-ops-days", "0", "--prune-now"]);
    env.ok("bob", &bob, &["fsck"]);
    let key = env.pubkey("bob");
    env.ok(
        "alice",
        &proj,
        &["scope", "grant", "team", &key, "--name", "bob"],
    );
    env.ok("alice", &proj, &["push"]);
    env.ok("bob", &bob, &["pull"]);
    assert_eq!(
        read(&bob, "secrets/.env.s"),
        "sealed\n",
        "gc deleted the ciphertext Bob could not read yet"
    );
}

// Scenario from git t6500-gc.sh: "background auto gc respects lock" — gc next to running commands.
// BUG-811: under load (12 copies at once) this lost a recorded tree about
// one run in three, before gc deleted only under its fence.
#[test]
fn gc_concurrent_with_commits_loses_nothing() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    let ws: Vec<String> = (0..3).map(|i| format!("w{i}")).collect();
    for w in &ws {
        env.ok("alice", &proj, &["ws", "new", w, "-r", "main"]);
    }
    let mut children = Vec::new();
    for (i, w) in ws.iter().enumerate() {
        let script = format!("echo work-{i} > work-{i}.txt");
        children.push(env.spawn(
            "alice",
            &proj,
            &[
                "ws",
                "exec",
                w,
                "-m",
                &format!("work {i}"),
                "--",
                "sh",
                "-c",
                &script,
            ],
        ));
        children.push(env.spawn(
            "alice",
            &proj,
            &["gc", "--keep-ops-days", "0", "--prune-now"],
        ));
    }
    for c in children {
        let out = c.wait_with_output().unwrap();
        assert!(exited_cleanly(&out), "{}", text(&out));
        // With the lock-free op log, `gc --keep-ops-days 0 --prune-now` can
        // prune the operation a running `ws exec` started from (BUG-804):
        // that command refuses to record and keeps its output in the
        // sandbox, which is never a loss. Anything else must succeed.
        assert!(
            out.status.success() || text(&out).contains("locked") || text(&out).contains("run the command again"),
            "{}",
            text(&out)
        );
    }
    // Record what a refused `ws exec` kept in its sandbox.
    for w in &ws {
        env.ok("alice", &proj, &["ws", "exec", w, "--record-only"]);
    }
    let (code, out) = env.code("alice", &proj, &["fsck"]);
    assert_eq!(code, 0, "{out}");
    for (i, w) in ws.iter().enumerate() {
        let got = env.vl("alice", &proj, &["ws", "cat", w, &format!("work-{i}.txt")]);
        assert!(got.status.success(), "work of {w} lost: {}", text(&got));
    }
}

// Veil (BUG-811's class, scale stream G2): `gc --keep-ops-days 0
// --prune-now` on both sides beside every kind of writer at once: a commit,
// two `ws exec` recordings, a push, and a pull with its own gc. Each command
// succeeds or asks to be run again; nothing recorded is lost, and `fsck` is
// clean on both sides. Run it under load (many copies at once).
#[test]
fn gc_beside_commits_pushes_pulls_and_ws_exec_loses_nothing() {
    let env = Env::new();
    let (alice, hub) = env.project_with_hub("alice", "alice", "hub", &[("a.txt", "a\n")]);
    let bob = env.clone("bob", &hub, "bob");
    for w in ["agent0", "agent1"] {
        env.ok("alice", &alice, &["ws", "new", w, "-r", "main"]);
    }
    write(&alice, "mine.txt", "alice's work\n");
    let gc = ["gc", "--keep-ops-days", "0", "--prune-now"];
    let mut children = vec![
        env.spawn("alice", &alice, &["ws", "exec", "agent0", "-m", "agent 0", "--", "sh", "-c", "echo zero > zero.txt"]),
        env.spawn("alice", &alice, &gc),
        env.spawn("alice", &alice, &["commit", "-m", "mine"]),
        env.spawn("alice", &alice, &["ws", "exec", "agent1", "-m", "agent 1", "--", "sh", "-c", "echo one > one.txt"]),
        env.spawn("alice", &alice, &["push"]),
        env.spawn("bob", &bob, &["pull"]),
        env.spawn("bob", &bob, &gc),
        env.spawn("alice", &alice, &gc),
    ];
    for c in children.drain(..) {
        let out = c.wait_with_output().unwrap();
        assert!(exited_cleanly(&out), "{}", text(&out));
        assert!(
            out.status.success() || text(&out).contains("locked") || text(&out).contains("run the command again"),
            "{}",
            text(&out)
        );
    }
    for w in ["agent0", "agent1"] {
        env.ok("alice", &alice, &["ws", "exec", w, "--record-only"]);
    }
    let _ = env.vl("alice", &alice, &["commit", "-m", "mine"]);
    env.ok("alice", &alice, &["push"]);
    env.ok("bob", &bob, &["pull"]);
    for (dir, who) in [(&alice, "alice"), (&bob, "bob")] {
        let (code, out) = env.code(who, dir, &["fsck"]);
        assert_eq!(code, 0, "{who}: {out}");
    }
    assert_eq!(read(&alice, "mine.txt"), "alice's work\n");
    assert!(env.ok("alice", &alice, &["log"]).contains("mine"));
    for (w, f, c) in [("agent0", "zero.txt", "zero\n"), ("agent1", "one.txt", "one\n")] {
        assert_eq!(env.stdout("alice", &alice, &["ws", "cat", w, f]), c, "work of {w} lost");
    }
    assert_eq!(env.stdout("bob", &bob, &["cat", "a.txt", "-r", "main"]), "a\n");
}

// Veil: gc on a clone, then push and pull keep working (packed objects travel).
#[test]
fn push_and_pull_work_after_gc_on_both_sides() {
    let env = Env::new();
    let (alice, hub) = env.project_with_hub("alice", "alice", "hub", &[("a.txt", "a\n")]);
    let bob = env.clone("bob", &hub, "bob");
    gc(&env, &alice, &["--prune-now"]);
    env.ok("bob", &bob, &["gc", "--prune-now"]);
    env.commit("alice", &alice, "after gc", &[("a.txt", "after gc\n")]);
    env.ok("alice", &alice, &["push"]);
    env.ok("bob", &bob, &["pull"]);
    assert_eq!(
        env.stdout("bob", &bob, &["cat", "a.txt", "-r", "main"]),
        "after gc\n"
    );
    env.commit("bob", &bob, "bob after gc", &[("b.txt", "b\n")]);
    let _ = env.vl("bob", &bob, &["rebase", "-d", "main"]);
    env.ok("bob", &bob, &["fsck"]);
}

// Scenario from git t6500-gc.sh: gc --level / --no-deltas produce a usable repository.
#[test]
fn gc_compression_options_keep_the_repository_usable() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", &"line\n".repeat(1000))]);
    env.commit("alice", &proj, "two", &[("a.txt", &"line\n".repeat(1001))]);
    gc(&env, &proj, &["--level", "19"]);
    gc(&env, &proj, &["--no-deltas", "--level", "1"]);
    assert_eq!(
        env.stdout("alice", &proj, &["cat", "a.txt", "-r", "main-"]),
        "line\n".repeat(1000)
    );
    env.ok("alice", &proj, &["fsck"]);
}

// Scenario from git t5304-prune.sh: a damaged history makes gc refuse to delete anything.
#[test]
fn gc_deletes_nothing_when_history_cannot_be_read() {
    let env = Env::new();
    let proj = with_abandoned_work(&env);
    // A tree on the way (the root tree of `main`, which names keep.txt).
    let f = loose_objects(&proj)
        .into_iter()
        .find(|p| {
            let b = std::fs::read(p).unwrap();
            b.starts_with(b"veil:tree")
                && contains(&b, "keep.txt")
                && !contains(&b, "experiment.txt")
        })
        .expect("main's root tree");
    std::fs::remove_file(&f).unwrap();
    let before = listing(&proj.join(".veil/objects")).len();
    let out = env.vl(
        "alice",
        &proj,
        &["--no-snapshot", "gc", "--keep-ops-days", "0", "--prune-now"],
    );
    let t = text(&out);
    assert!(exited_cleanly(&out), "{t}");
    if out.status.success() {
        assert_eq!(count(&t, "deleted"), 0, "{t}");
    }
    assert!(
        contains(&everything_in(&proj), "abandoned experiment 9090"),
        "deleted although history is damaged ({before} files before): {t}"
    );
}
