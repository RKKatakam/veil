//! Adversarial CLI tests: concurrent `vl` processes, `kill -9` mid-command,
//! stale locks, and the `ws exec` sandbox.

mod adversarial_support;

use std::{
    io::Write as _,
    time::{Duration, Instant},
};

use adversarial_support::*;

fn many_files(dir: &std::path::Path, n: usize, tag: &str) {
    for i in 0..n {
        write(dir, &format!("d{}/f{i}.txt", i % 50), &format!("{tag} {i}\n{}\n", "x".repeat(200)));
    }
}

// ---- concurrency ----------------------------------------------------------------

#[test]
fn concurrent_vl_processes_do_not_corrupt_the_repository() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    let n = 8;
    let children: Vec<_> = (0..n)
        .map(|i| {
            let args: Vec<String> = match i % 3 {
                0 => vec!["new".into(), "-m".into(), format!("new-{i}")],
                1 => vec!["describe".into(), "-r".into(), "main".into(), "-m".into(), format!("desc-{i}")],
                _ => vec!["status".into()],
            };
            let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            env.spawn("alice", &proj, &a)
        })
        .collect();
    let outs: Vec<_> = children.into_iter().map(|c| c.wait_with_output().unwrap()).collect();
    for o in &outs {
        assert!(exited_cleanly(o), "{}", text(o));
        assert!(o.status.success() || text(o).contains("locked"), "{}", text(o));
    }
    // repository is still fully usable and consistent
    env.ok("alice", &proj, &["status"]);
    let log = env.ok("alice", &proj, &["log"]);
    let ops = env.ok("alice", &proj, &["op", "log", "-n", "1000"]);
    for (i, o) in outs.iter().enumerate() {
        if o.status.success() && i % 3 == 0 {
            assert!(log.contains(&format!("new-{i}")) || ops.contains("new change"), "lost `vl new` #{i}");
        }
    }
    assert!(!log.contains("recovered working-copy edits"), "spurious recovery change:\n{log}");
    assert_eq!(read(&proj, "a.txt"), "a\n");
}

#[test]
fn concurrent_snapshots_of_a_changing_tree_lose_nothing() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("seed", "s\n")]);
    let mut children = Vec::new();
    for i in 0..6 {
        write(&proj, &format!("file-{i}.txt"), &format!("content {i}\n"));
        children.push(env.spawn("alice", &proj, &["status"]));
    }
    for c in children {
        let o = c.wait_with_output().unwrap();
        assert!(exited_cleanly(&o), "{}", text(&o));
    }
    env.ok("alice", &proj, &["commit", "-m", "all"]);
    let files = env.stdout("alice", &proj, &["files", "-r", "@-"]);
    for i in 0..6 {
        assert!(files.contains(&format!("file-{i}.txt")), "file-{i}.txt missing:\n{files}");
    }
}

// ---- kill -9 ---------------------------------------------------------------------

/// Kill `vl` at random points while it snapshots and commits a large tree;
/// after each crash the repository must reopen, and no data may be lost.
#[test]
fn kill_9_mid_command_never_corrupts_the_repository() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("keep.txt", "keep\n")]);
    for round in 0..6 {
        many_files(&proj, 400, &format!("round{round}"));
        let mut child = env.spawn("alice", &proj, &["commit", "-m", &format!("round {round}")]);
        std::thread::sleep(Duration::from_millis(20 + 37 * round as u64));
        let _ = child.kill(); // SIGKILL
        let _ = child.wait();
        // a crash may leave a fresh lock behind (see BUG-026); clear it
        let _ = std::fs::remove_file(proj.join(".veil/lock"));
        let st = env.vl("alice", &proj, &["status"]);
        assert!(st.status.success(), "round {round}: repo unusable after kill -9:\n{}", text(&st));
        env.ok("alice", &proj, &["log"]);
        env.ok("alice", &proj, &["op", "log"]);
        assert_eq!(read(&proj, "keep.txt"), "keep\n");
        assert!(read(&proj, "d0/f0.txt").starts_with(&format!("round{round} 0")), "working copy lost edits");
    }
    env.ok("alice", &proj, &["commit", "-m", "final"]);
    let cat = env.stdout("alice", &proj, &["cat", "d7/f7.txt", "-r", "@-"]);
    assert!(cat.starts_with("round5 7"), "{cat}");
}

/// A process killed while holding the repository lock blocks every later
/// command for two minutes.
#[test]
#[ignore = "BUG-026: a lock left by a crashed process blocks every command for 2 minutes (no PID liveness check)"]
fn repository_is_usable_right_after_a_crash_while_locked() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    many_files(&proj, 3000, "v1");
    env.ok("alice", &proj, &["status"]);
    let mut caught = false;
    for attempt in 0..30 {
        many_files(&proj, 3000, &format!("v{}", attempt + 2));
        let mut child = env.spawn("alice", &proj, &["status"]);
        // the lock is held while the tree is being built
        let held = wait_for(Duration::from_secs(5), || proj.join(".veil/lock").exists());
        let _ = child.kill();
        let _ = child.wait();
        if held && proj.join(".veil/lock").exists() {
            caught = true;
            break;
        }
    }
    assert!(caught, "could not kill vl while it held the lock");
    let start = Instant::now();
    let out = env.vl("alice", &proj, &["status"]);
    assert!(
        out.status.success() && start.elapsed() < Duration::from_secs(5),
        "after {:?}: {}",
        start.elapsed(),
        text(&out)
    );
}

#[test]
fn interrupted_write_leftovers_are_not_snapshotted() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("src/main.rs", "fn main() {}\n")]);
    // exactly what DiskBackend::write leaves behind if killed before rename
    write(&proj, "src/.main.rs.vltmp1a2b3c4d", "fn main() { half");
    env.ok("alice", &proj, &["commit", "-m", "next"]);
    let files = env.stdout("alice", &proj, &["files", "-r", "@-"]);
    assert!(!files.contains("vltmp"), "crash debris recorded in history:\n{files}");
}

// ---- stale locks ---------------------------------------------------------------------

#[test]
fn an_old_stale_lock_is_recovered_automatically() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    let old = veil_core::now_millis() - 10 * 60 * 1000;
    std::fs::write(proj.join(".veil/lock"), format!("12345 {old}")).unwrap();
    env.ok("alice", &proj, &["status"]);
    env.ok("alice", &proj, &["describe", "-m", "after stale lock"]);
}

// ---- ws exec sandbox ---------------------------------------------------------------------

fn sandbox_project(env: &Env) -> std::path::PathBuf {
    let proj = env.project("alice", "proj", &[("app.py", "print('hi')\n")]);
    write(&proj, ".env", "API_TOKEN=super-secret-isolated-value\n");
    write(&proj, "secrets/db.txt", "cloaked-db-password\n");
    env.ok("alice", &proj, &["cloak", "secrets/"]);
    env.ok("alice", &proj, &["commit", "-m", "with secrets"]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "@-"]);
    proj
}

#[test]
fn ws_exec_sandbox_is_private_to_the_user() {
    let env = Env::new();
    let proj = sandbox_project(&env);
    let out = env.stdout(
        "alice",
        &proj,
        &["ws", "exec", "agent", "--with-isolated", "--", "sh", "-c", "stat -c '%a %n' . .env secrets secrets/db.txt"],
    );
    for line in out.lines() {
        let mode = u32::from_str_radix(line.split_whitespace().next().unwrap(), 8).unwrap();
        assert_eq!(mode & 0o077, 0, "sandbox entry readable by other users: {line}");
    }
}

#[test]
fn killed_ws_exec_leaves_no_plaintext_behind() {
    let env = Env::new();
    let proj = sandbox_project(&env);
    let pidfile = env.root.join("child.pid");
    let script = format!("echo $$ > {}; exec sleep 30", pidfile.display());
    let mut child = env.spawn("alice", &proj, &["ws", "exec", "agent", "--with-isolated", "--", "sh", "-c", &script]);
    assert!(wait_for(Duration::from_secs(20), || pidfile.exists()), "sandbox command never started");
    let _ = child.kill();
    let _ = child.wait();
    if let Ok(pid) = std::fs::read_to_string(&pidfile) {
        let _ = std::process::Command::new("kill").args(["-9", pid.trim()]).status();
    }
    let leftovers: Vec<String> = tree_listing(&env.root.join("tmp"))
        .into_iter()
        .filter(|p| p.ends_with(".env") || p.ends_with("db.txt"))
        .collect();
    assert!(leftovers.is_empty(), "secrets left on disk after crash: {leftovers:?}");
}

#[test]
fn ws_exec_cleans_up_and_never_records_isolated_files() {
    let env = Env::new();
    let proj = sandbox_project(&env);
    let o = env.vl(
        "alice",
        &proj,
        &["ws", "exec", "agent", "--with-isolated", "-m", "agent run", "--", "sh", "-c", "echo new > out.txt; false"],
    );
    assert_eq!(o.status.code(), Some(1), "exit code of the sandboxed command is propagated: {}", text(&o));
    assert!(tree_listing(&env.root.join("tmp")).is_empty(), "sandbox not removed");
    let files = env.stdout("alice", &proj, &["files", "-r", "agent@"]);
    assert!(files.contains("out.txt"));
    assert!(!files.lines().any(|l| l.ends_with(" .env")), "isolated file recorded:\n{files}");
    let cat = env.vl("alice", &proj, &["ws", "cat", "agent", "out.txt"]);
    assert_eq!(String::from_utf8_lossy(&cat.stdout), "new\n");
}

#[test]
fn ws_write_from_stdin_records_into_the_virtual_workspace_only() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    env.ok("alice", &proj, &["ws", "new", "agent"]);
    let mut c = env
        .cmd("alice", &proj, &["ws", "write", "agent", "notes/n.txt"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(b"from stdin\n").unwrap();
    let o = c.wait_with_output().unwrap();
    assert!(o.status.success(), "{}", text(&o));
    assert!(!proj.join("notes").exists());
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "notes/n.txt"]), "from stdin\n");
}

/// `--with-isolated` hands `.env` to the sandboxed command; anything the
/// command writes is recorded. A tool (or a prompt-injected agent) that copies
/// the secret into a tracked file publishes it: nothing compares recorded
/// content with the isolated values the engine itself injected.
#[test]
fn ws_exec_cannot_launder_isolated_secrets_into_history() {
    let env = Env::new();
    let proj = sandbox_project(&env);
    let o = env.vl(
        "alice",
        &proj,
        &["ws", "exec", "agent", "--with-isolated", "-m", "agent run", "--", "sh", "-c", "cp .env config.txt"],
    );
    assert!(o.status.success(), "{}", text(&o));
    let cat = env.vl("alice", &proj, &["ws", "cat", "agent", "config.txt"]);
    assert!(
        !String::from_utf8_lossy(&cat.stdout).contains("super-secret-isolated-value"),
        "isolated secret recorded in the agent workspace's history"
    );
}
