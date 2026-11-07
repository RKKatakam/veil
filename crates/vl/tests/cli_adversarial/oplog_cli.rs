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


// ---- the directory's state, judged under its lock (BUG-1084, BUG-1010) ----
//
// The test plays the other `vl`: it holds a workspace's working-copy lock
// (`lock::WcLock`, an `flock`), lets a real `vl` read the repository and
// block on that lock, changes what the other `vl` would have changed, and
// lets it go. Waiting for the block is read from `/proc/locks` (Linux).

/// Take workspace `ws`'s working-copy lock, as another recorder holds it.
#[cfg(target_os = "linux")]
fn hold_wc_lock(proj: &std::path::Path, ws: &str) -> std::fs::File {
    let dir = proj.join(".veil/local/wc");
    std::fs::create_dir_all(&dir).unwrap();
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join(format!("ws-{ws}.lock"))).unwrap();
    use std::os::unix::io::AsRawFd;
    // SAFETY: a valid descriptor we own; `flock` only takes a lock (the one
    // `lock::WcLock` takes).
    assert_eq!(unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) }, 0);
    f
}

/// Wait until a process blocks on the lock `held`, or `child` exits
/// (`false`: it never waited for the lock).
#[cfg(target_os = "linux")]
fn blocks_on(held: &std::fs::File, child: &mut std::process::Child) -> bool {
    use std::os::unix::fs::MetadataExt;
    let needle = format!(":{} ", held.metadata().unwrap().ino());
    let mut waiting = false;
    wait_for(std::time::Duration::from_secs(60), || {
        waiting = std::fs::read_to_string("/proc/locks").unwrap_or_default().lines().any(|l| l.contains("->") && l.contains(&needle));
        waiting || child.try_wait().unwrap().is_some()
    });
    waiting
}

/// Replace op head files `from` with `to` (keeping any other head).
#[cfg(target_os = "linux")]
fn swap_heads(proj: &std::path::Path, from: &BTreeSet<String>, to: &BTreeSet<String>) {
    for h in from.difference(to) {
        std::fs::remove_file(proj.join(".veil/op_heads").join(h)).unwrap();
    }
    for h in to.difference(from) {
        write(proj, &format!(".veil/op_heads/{h}"), "");
    }
}

#[cfg(target_os = "linux")]
fn changes(env: &Env, proj: &std::path::Path) -> usize {
    env.stdout("alice", proj, &["log", "--json"]).matches("\"change_id\"").count()
}

/// BUG-1084, BUG-1010: a `vl status` read the op heads just before another
/// `vl status` published its snapshot, and the checkout record just after
/// that one rewrote it, then waited for the working-copy lock. It judged
/// the directory against the older view: "stale", so it saved the
/// directory as a "recovered working-copy edits" side change and checked
/// out the older `@`, removing from disk the edit the other one had just
/// recorded and the one made since.
#[cfg(target_os = "linux")]
#[test]
fn bug_1084_a_recorder_judges_the_directory_under_its_lock() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    env.ok("alice", &proj, &["status"]);
    let n = changes(&env, &proj);
    let before = heads(&proj);
    // The other `vl status`: its snapshot and its checkout record.
    write(&proj, "x.txt", "1\n");
    env.ok("alice", &proj, &["status"]);
    let after = heads(&proj);
    // This one reads the heads from before it, the record from after.
    let lock = hold_wc_lock(&proj, "default");
    swap_heads(&proj, &after, &before);
    let mut child = env.spawn("alice", &proj, &["status"]);
    let blocked = blocks_on(&lock, &mut child);
    swap_heads(&proj, &before, &after);
    write(&proj, "y.txt", "2\n");
    drop(lock);
    let out = child.wait_with_output().unwrap();
    let t = text(&out);
    assert!(blocked && out.status.success(), "{t}");
    assert!(!t.contains("stale"), "nothing was stale: {t}");
    assert_eq!(read(&proj, "x.txt"), "1\n", "a recorded edit was taken out of the directory: {t}");
    assert_eq!(read(&proj, "y.txt"), "2\n", "a new edit was taken out of the directory: {t}");
    assert_eq!(env.stdout("alice", &proj, &["cat", "-r", "@", "y.txt"]), "2\n");
    assert_eq!(changes(&env, &proj), n, "a side change appeared");
    env.ok("alice", &proj, &["fsck"]);
}

/// BUG-1120: `vl ws write` read the workspace's `@` before it took the
/// workspace's lock, so a write that landed while it waited was reverted
/// by its snapshot (built on the older `@`).
#[cfg(target_os = "linux")]
#[test]
fn bug_1120_ws_write_keeps_a_write_that_landed_while_it_waited() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    env.ok("alice", &proj, &["ws", "new", "agent"]);
    env.ok("alice", &proj, &["status"]);
    let ws_write = |name: &str, data: &str| {
        let mut c = env.cmd("alice", &proj, &["ws", "write", "agent", name]);
        c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let mut child = c.spawn().unwrap();
        use std::io::Write;
        child.stdin.take().unwrap().write_all(data.as_bytes()).unwrap();
        child
    };
    let before = heads(&proj);
    let out = ws_write("b.txt", "b\n").wait_with_output().unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let after = heads(&proj);
    let lock = hold_wc_lock(&proj, "agent");
    swap_heads(&proj, &after, &before);
    let mut child = ws_write("a.txt", "a\n");
    let blocked = blocks_on(&lock, &mut child);
    swap_heads(&proj, &before, &after);
    drop(lock);
    let out = child.wait_with_output().unwrap();
    assert!(blocked && out.status.success(), "{}", text(&out));
    assert_eq!(env.stdout("alice", &proj, &["cat", "-r", "agent@", "a.txt"]), "a\n");
    assert_eq!(env.stdout("alice", &proj, &["cat", "-r", "agent@", "b.txt"]), "b\n", "the other write was reverted");
}

/// BUG-1121: the project directory's lock is its workspace's, and `vl ws
/// switch` took only the one it moved to. Moving the directory, it did not
/// wait for a `vl status` recording it into the workspace it was leaving
/// (which would record the half-moved files there, BUG-113's class).
#[cfg(target_os = "linux")]
#[test]
fn bug_1121_ws_switch_waits_for_a_recorder_of_the_workspace_it_leaves() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    env.ok("alice", &proj, &["ws", "new", "other"]);
    env.ok("alice", &proj, &["status"]);
    // A `vl status` is recording the directory into 'default'.
    let lock = hold_wc_lock(&proj, "default");
    let mut child = env.spawn("alice", &proj, &["--no-snapshot", "ws", "switch", "other"]);
    let blocked = blocks_on(&lock, &mut child);
    drop(lock);
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", text(&out));
    assert!(blocked, "the switch moved the directory while it was being recorded");
}

/// BUG-1121: a recorder never touches a directory another `vl` is moving
/// to another workspace: it waits for that workspace's lock instead of
/// "finishing" the live move itself (or recording half-moved files).
#[cfg(target_os = "linux")]
#[test]
fn bug_1121_a_recorder_waits_for_a_live_move_of_the_directory() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    env.ok("alice", &proj, &["ws", "new", "other"]);
    env.ok("alice", &proj, &["status"]);
    // `vl ws switch other` is moving the directory: it holds 'other''s lock
    // and the record says the move is under way.
    let lock = hold_wc_lock(&proj, "other");
    let record = read(&proj, ".veil/local/checkout.json");
    let mut v: serde_json::Value = serde_json::from_str(&record).unwrap();
    assert!(v.get("pending").is_none_or(|p| p.is_null()), "{record}");
    let other: serde_json::Value = serde_json::from_str(&env.stdout("alice", &proj, &["log", "-r", "other@", "--json"])).unwrap();
    let snapshot = other["entries"][0]["snapshot_id"].clone();
    v["pending"] = serde_json::json!({"workspace": "other", "snapshot": snapshot});
    write(&proj, ".veil/local/checkout.json", &v.to_string());
    let mut child = env.spawn("alice", &proj, &["status"]);
    let blocked = blocks_on(&lock, &mut child);
    // The move ends.
    v["workspace"] = "other".into();
    v["snapshot"] = snapshot;
    v.as_object_mut().unwrap().remove("pending");
    write(&proj, ".veil/local/checkout.json", &v.to_string());
    drop(lock);
    let out = child.wait_with_output().unwrap();
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(blocked && !t.contains("interrupted move"), "a live move was finished by another command: {t}");
}
