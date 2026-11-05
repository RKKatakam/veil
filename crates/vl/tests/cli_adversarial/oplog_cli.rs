//! The lock-free op log from the command line (format 6,
//! `docs/design/scale/2-lock-free-oplog.md`): real `vl` processes, at once.

use std::collections::BTreeSet;

use crate::adversarial_support::*;
use veil_core::ObjectId;

fn heads(proj: &std::path::Path) -> BTreeSet<String> {
    std::fs::read_dir(proj.join(".veil/op_heads")).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()
}

/// Threat 8: a head file naming a missing operation fails every command
/// with the `fsck` hint, and `vl fsck` names exactly that file.
#[test]
fn planted_head_status_fails_with_fsck_hint() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    let planted = ObjectId::hash(b"planted").hex();
    write(&proj, &format!(".veil/op_heads/{planted}"), "");
    let out = env.vl("alice", &proj, &["status"]);
    assert!(!out.status.success());
    let t = text(&out);
    assert!(t.contains("fsck") && t.contains(&planted[..12]), "{t}");
    let out = env.vl("alice", &proj, &["fsck"]);
    let t = text(&out);
    assert!(!out.status.success() && t.contains(&format!(".veil/op_heads/{planted}")), "{t}");
}

/// Threats 11 and 12: `vl undo` in the project directory never takes back
/// an agent's work in its own workspace; `vl op restore` to before it
/// refuses without `--force` and lists the agent's operations.
#[test]
fn op_restore_refuses_over_other_workspace() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    env.ok("alice", &proj, &["ws", "new", "agent"]);
    write(&proj, "mine.txt", "mine\n");
    env.ok("alice", &proj, &["commit", "-m", "mine"]);
    let before = env.stdout("alice", &proj, &["op", "log", "--json"]);
    let before: serde_json::Value = serde_json::from_str(&before).unwrap();
    let target = before["operations"][0]["op_id"].as_str().unwrap().to_string();
    // The agent works in its own workspace.
    env.ok("alice", &proj, &["ws", "exec", "agent", "--", "sh", "-c", "echo agent > agent.txt"]);
    let log = env.stdout("alice", &proj, &["op", "log", "--json"]);
    assert!(log.contains("\"workspace\":\"agent\""), "{log}");
    // Undo here undoes my commit, not the agent's work.
    let out = env.ok("alice", &proj, &["undo"]);
    assert!(out.contains("Undid: commit"), "{out}");
    assert_eq!(env.stdout("alice", &proj, &["cat", "-r", "agent@", "agent.txt"]), "agent\n");
    env.ok("alice", &proj, &["redo"]);
    // Restoring a view from before the agent's work refuses...
    let out = env.vl("alice", &proj, &["op", "restore", &target[..12]]);
    let t = text(&out);
    assert!(!out.status.success() && t.contains("workspace 'agent'") && t.contains("--force"), "{t}");
    assert_eq!(env.stdout("alice", &proj, &["cat", "-r", "agent@", "agent.txt"]), "agent\n");
    // ...and with `--force` restores it (the agent's work stays in the log).
    env.ok("alice", &proj, &["op", "restore", &target[..12], "--force"]);
    assert!(!env.vl("alice", &proj, &["cat", "-r", "agent@", "agent.txt"]).status.success());
    // `vl undo --op` undoes a single operation, keeping later ones.
    env.ok("alice", &proj, &["undo"]);
    assert_eq!(env.stdout("alice", &proj, &["cat", "-r", "agent@", "agent.txt"]), "agent\n");
    // `vl op heads` lists the one head.
    let h = env.stdout("alice", &proj, &["op", "heads", "--json"]);
    let h: serde_json::Value = serde_json::from_str(&h).unwrap();
    assert_eq!(h["operations"].as_array().unwrap().len(), 1, "{h}");
}

/// Threat 4: eight `vl status` loops in one project directory while files
/// change. No edit is lost, no stray side change appears, the final working
/// copy equals the disk, and nothing waited on `.veil/lock`.
#[test]
fn concurrent_status_loops_lose_nothing() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    let changes_before = env.stdout("alice", &proj, &["log", "--json"]).matches("\"change_id\"").count();
    let rounds: Vec<usize> = std::thread::scope(|s| {
        let loops: Vec<_> = (0..8)
            .map(|i| {
                let (env, proj) = (&env, &proj);
                s.spawn(move || {
                    for n in 0..6 {
                        write(proj, &format!("loop-{i}.txt"), &format!("{n}\n"));
                        let out = env.vl("alice", proj, &["status"]);
                        assert!(out.status.success(), "loop {i}: {}", text(&out));
                    }
                    6
                })
            })
            .collect();
        loops.into_iter().map(|l| l.join().unwrap()).collect()
    });
    assert!(!proj.join(".veil/lock").exists());
    // The last snapshot holds what the disk holds.
    let st = env.stdout("alice", &proj, &["status"]);
    for (i, n) in rounds.iter().enumerate() {
        assert_eq!(env.stdout("alice", &proj, &["cat", &format!("loop-{i}.txt")]), format!("{}\n", n - 1), "loop {i}'s last edit is not recorded: {st}");
    }
    // No stray side change ("recovered working-copy edits").
    let all = env.stdout("alice", &proj, &["log", "--json"]);
    assert_eq!(all.matches("\"change_id\"").count(), changes_before, "a side change appeared: {all}");
    assert_eq!(heads(&proj).len(), 1);
    env.ok("alice", &proj, &["fsck"]);
}

/// Threat 25: many `vl` processes on one repository at once, each in its
/// own workspace: every tag lands, one head after settling, `fsck` clean,
/// and no `vl` failed or waited for `.veil/lock`.
#[test]
fn many_processes_no_lost_operation() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    const N: usize = 6;
    for i in 0..N {
        env.ok("alice", &proj, &["ws", "new", &format!("w{i}")]);
    }
    std::thread::scope(|s| {
        for i in 0..N {
            let (env, proj) = (&env, &proj);
            s.spawn(move || {
                for n in 0..3 {
                    let out = env.vl(
                        "alice",
                        proj,
                        &["ws", "exec", &format!("w{i}"), "-m", &format!("w{i} {n}"), "--", "sh", "-c", &format!("echo {n} > f{i}.txt")],
                    );
                    assert!(out.status.success(), "w{i} {n}: {}", text(&out));
                    let out = env.vl("alice", proj, &["tag", "set", &format!("w{i}-{n}"), "-r", &format!("w{i}@"), "--allow-backwards"]);
                    assert!(out.status.success(), "tag w{i}-{n}: {}", text(&out));
                }
            });
        }
    });
    let tags = env.stdout("alice", &proj, &["tag", "list"]);
    for i in 0..N {
        for n in 0..3 {
            assert!(tags.contains(&format!("w{i}-{n}")), "tag w{i}-{n} was lost:\n{tags}");
        }
        assert_eq!(env.stdout("alice", &proj, &["cat", "-r", &format!("w{i}@"), &format!("f{i}.txt")]), "2\n");
    }
    assert_eq!(heads(&proj).len(), 1);
    assert!(!proj.join(".veil/lock").exists());
    env.ok("alice", &proj, &["fsck"]);
}
