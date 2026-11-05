//! Adversarial CLI tests: concurrent `vl` processes, `kill -9` mid-command,
//! stale locks, and the `ws exec` sandbox.

use crate::adversarial_support;

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

/// A process killed while holding the repository lock blocked every later
/// command for two minutes. From format 6 a recording takes no repository
/// lock: it stages its objects in its own directory. A process killed
/// while staging blocks nothing, its staging directory is removed by the
/// next command (its pid is provably gone), and the repository stays
/// consistent.
#[test]
fn repository_is_usable_right_after_a_crash_while_locked() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    many_files(&proj, 3000, "v1");
    env.ok("alice", &proj, &["status"]);
    let incoming = proj.join(".veil/objects/incoming");
    let staging = || -> Vec<String> {
        std::fs::read_dir(&incoming).map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.starts_with("tx-")).collect()).unwrap_or_default()
    };
    let mut caught = false;
    for attempt in 0..30 {
        many_files(&proj, 3000, &format!("v{}", attempt + 2));
        let mut child = env.spawn("alice", &proj, &["status"]);
        // objects are staged while the tree is being built
        let held = wait_for(Duration::from_secs(5), || !staging().is_empty() && proj.join(".veil/objects/incoming").read_dir().is_ok_and(|d| d.flatten().any(|e| e.path().read_dir().is_ok_and(|mut f| f.next().is_some()))));
        let _ = child.kill();
        let _ = child.wait();
        if held && !staging().is_empty() {
            caught = true;
            break;
        }
    }
    assert!(caught, "could not kill vl while it staged objects");
    assert!(!proj.join(".veil/lock").exists(), "a recording took the repository lock");
    let start = Instant::now();
    let out = env.vl("alice", &proj, &["status"]);
    assert!(
        out.status.success() && start.elapsed() < Duration::from_secs(5),
        "after {:?}: {}",
        start.elapsed(),
        text(&out)
    );
    assert!(staging().is_empty(), "the dead process's staging was not removed: {:?}", staging());
    env.ok("alice", &proj, &["fsck"]);
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

// ---- kill -9 during a push -------------------------------------------------------

/// Objects `vl push --dry-run` plans for remote `origin`.
fn planned_objects(env: &Env, proj: &std::path::Path) -> u64 {
    let out = env.stdout("alice", proj, &["push", "origin", "--dry-run", "--json"]);
    let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
    doc["remotes"][0]["objects"].as_u64().unwrap()
}

/// "Pushed N object(s)" of a push's output.
fn pushed_objects(out: &str) -> u64 {
    let line = out.lines().find(|l| l.starts_with("Pushed ")).unwrap_or_else(|| panic!("{out}"));
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

/// `main` in the repository at `dir` (a project or a bare remote).
fn main_of(dir: &std::path::Path, bare: bool) -> veil_core::ObjectId {
    use veil_core::{DiskBackend, Repo};
    let fs = std::sync::Arc::new(DiskBackend::new(dir));
    let r = match bare {
        true => Repo::open_remote(fs).unwrap(),
        false => Repo::open(fs, None, "check").unwrap(),
    };
    r.view().tags["main"].target
}

/// The remote as it is on disk: no damage, and `main` at `old` or `new`
/// (a push is published whole or not at all).
fn remote_consistent(remote: &std::path::Path, old: veil_core::ObjectId, new: veil_core::ObjectId, ctx: &str) {
    use veil_core::{fsck, DiskBackend, StorageBackend};
    let fs: std::sync::Arc<dyn StorageBackend> = std::sync::Arc::new(DiskBackend::new(remote));
    let bad: Vec<String> = fsck::fsck(fs, None)
        .unwrap()
        .findings
        .iter()
        .filter(|f| matches!(f.severity, fsck::Severity::Corrupt | fsck::Severity::Warning))
        .map(|f| f.to_string())
        .collect();
    assert!(bad.is_empty(), "{ctx}: {bad:#?}");
    let at = main_of(remote, true);
    assert!(at == old || at == new, "{ctx}: main at {}", at.short());
}

/// `kill -9` of `vl push` at many points of its upload (staged packs of
/// 8 KiB): the remote never shows a partial push, and each next `vl push`
/// resumes, sending only what was not staged yet; the last one completes.
#[test]
fn kill_9_mid_push_never_publishes_part_of_it_and_the_next_push_resumes() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("keep.txt", "keep\n")]);
    let remote = env.dir("hub");
    env.ok("alice", &proj, &["remote", "add", "origin", remote.to_str().unwrap()]);
    env.ok("alice", &proj, &["push", "origin"]);
    let old = main_of(&remote, true);
    for i in 0..1500 {
        let body: String = (0..12).map(|j| format!("{:016x}", (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ (j as u64).wrapping_mul(0xc2b2_ae3d_27d4_eb4f))).collect();
        write(&proj, &format!("d{}/f{i}.txt", i % 40), &format!("{body}\n"));
    }
    env.ok("alice", &proj, &["commit", "-m", "big"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-", "--allow-backwards"]);
    let new = main_of(&proj, false);
    let total = planned_objects(&env, &proj);
    assert!(total > 1500, "control: {total} objects to send");

    // Packs the journal lists as staged.
    let journal = proj.join(".veil/local/push");
    let staged = || -> usize {
        let Ok(mut d) = std::fs::read_dir(&journal) else { return 0 };
        let Some(Ok(f)) = d.next() else { return 0 };
        let Ok(raw) = std::fs::read(f.path()) else { return 0 };
        serde_json::from_slice::<serde_json::Value>(&raw).map_or(0, |v| v["staged"].as_array().map_or(0, Vec::len))
    };
    let mut killed = 0;
    for round in 0..6usize {
        let before = staged();
        let mut child = env.cmd("alice", &proj, &["push", "origin"]).env("VEIL_PUSH_CHUNK", "8K").stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        // Kill it once it has staged a few more packs (a different number
        // each round), or at once if it already finished.
        let deadline = Instant::now() + Duration::from_secs(20);
        while staged() < before + 1 + round % 3 && child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        let _ = child.kill(); // SIGKILL
        let out = child.wait_with_output().unwrap();
        killed += usize::from(!out.status.success());
        remote_consistent(&remote, old, new, &format!("killed in round {round}"));
    }
    assert!(killed >= 3, "only {killed} pushes were actually killed");
    let out = env.cmd("alice", &proj, &["push", "origin"]).env("VEIL_PUSH_CHUNK", "8K").output().unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let sent = pushed_objects(&text(&out));
    assert!(sent < total, "the last push sent all {total} objects again: nothing was resumed");
    remote_consistent(&remote, old, new, "after the resumed push");
    assert_eq!(main_of(&remote, true), new);
    assert!(
        std::fs::read_dir(proj.join(".veil/local/push")).map_or(true, |mut d| d.next().is_none()),
        "the push journal is removed once the push is published"
    );
    let clone = env.root.join("clone");
    env.ok("bob", &env.root, &["clone", remote.to_str().unwrap(), clone.to_str().unwrap()]);
    assert_eq!(read(&clone, "d7/f7.txt"), read(&proj, "d7/f7.txt"));
}

/// `vl push --no-resume` ignores what an interrupted push staged.
#[test]
fn push_no_resume_sends_everything_again() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("keep.txt", "keep\n")]);
    let remote = env.dir("hub");
    env.ok("alice", &proj, &["remote", "add", "origin", remote.to_str().unwrap()]);
    env.ok("alice", &proj, &["push", "origin"]);
    for i in 0..1500 {
        let body: String = (0..12).map(|j| format!("{:016x}", (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ (j as u64).wrapping_mul(0xc2b2_ae3d_27d4_eb4f))).collect();
        write(&proj, &format!("d{}/f{i}.txt", i % 40), &format!("{body}\n"));
    }
    env.ok("alice", &proj, &["commit", "-m", "big"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-", "--allow-backwards"]);
    let total = planned_objects(&env, &proj);
    let journal = proj.join(".veil/local/push");
    let mut staged = false;
    for round in 0..10u64 {
        let mut child = env.cmd("alice", &proj, &["push", "origin"]).env("VEIL_PUSH_CHUNK", "8K").stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        wait_for(Duration::from_secs(5), || std::fs::read_dir(&journal).is_ok_and(|mut d| d.next().is_some()));
        std::thread::sleep(Duration::from_millis(10 * round));
        let _ = child.kill();
        let out = child.wait_with_output().unwrap();
        if !out.status.success() && std::fs::read_dir(&journal).is_ok_and(|mut d| d.next().is_some()) {
            staged = true;
            break;
        }
    }
    assert!(staged, "could not interrupt a push after it staged something");
    let out = env.ok("alice", &proj, &["push", "origin", "--no-resume"]);
    assert_eq!(pushed_objects(&out), total, "{out}");
}
