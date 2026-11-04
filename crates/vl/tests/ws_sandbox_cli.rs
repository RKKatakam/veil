//! Persistent `vl ws exec` sandboxes: kept between runs, synced
//! incrementally, recorded exactly, safe under concurrency, crashes and
//! injected secrets.

mod adversarial_support;

use std::{
    io::Write as _,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use adversarial_support::*;

fn files_dir(proj: &Path, ws: &str) -> PathBuf {
    proj.join(".veil/local/sandboxes").join(ws).join("files")
}

fn project(env: &Env) -> PathBuf {
    let proj = env.project("alice", "proj", &[("a.txt", "a\n"), ("src/lib.rs", "pub fn f() {}\n"), ("gone.txt", "g\n")]);
    write(&proj, ".env", "API_TOKEN=super-secret-isolated-value\n");
    env.ok("alice", &proj, &["commit", "-m", "env"]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "@-"]);
    proj
}

fn exec(env: &Env, proj: &Path, args: &[&str]) -> String {
    let mut all = vec!["ws", "exec", "agent"];
    all.extend_from_slice(args);
    env.ok("alice", proj, &all)
}

fn ws_write(env: &Env, proj: &Path, ws: &str, path: &str, data: &str) {
    let mut c = env
        .cmd("alice", proj, &["ws", "write", ws, path])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(data.as_bytes()).unwrap();
    let o = c.wait_with_output().unwrap();
    assert!(o.status.success(), "{}", text(&o));
}

fn paths(env: &Env, proj: &Path, rev: &str) -> Vec<String> {
    env.stdout("alice", proj, &["files", "-r", rev])
        .lines()
        .filter_map(|l| l.split_whitespace().rfind(|t| *t != "*").map(str::to_string))
        .collect()
}

fn ino(p: &Path) -> u64 {
    std::fs::metadata(p).unwrap().ino()
}

#[test]
fn the_sandbox_persists_and_keeps_unrecorded_build_output() {
    let env = Env::new();
    let proj = project(&env);
    let out = exec(&env, &proj, &["--", "sh", "-c", "pwd; mkdir -p target && echo obj > target/out.o"]);
    let dir = files_dir(&proj, "agent");
    assert!(out.contains(dir.to_str().unwrap()), "{out}");
    assert_eq!(read(&dir, "target/out.o"), "obj\n");
    let before = ino(&dir.join("src/lib.rs"));
    // The second run finds the build output and rewrites nothing.
    let out = exec(&env, &proj, &["--", "sh", "-c", "cat target/out.o"]);
    assert!(out.contains("obj"), "{out}");
    assert!(!out.contains("synced sandbox"), "nothing changed, nothing written: {out}");
    assert_eq!(ino(&dir.join("src/lib.rs")), before, "an unchanged file was rewritten");
    assert!(!paths(&env, &proj, "agent@").iter().any(|p| p.starts_with("target")));
    // The sandbox is private.
    for d in [proj.join(".veil/local/sandboxes"), proj.join(".veil/local/sandboxes/agent"), dir.clone()] {
        assert_eq!(std::fs::metadata(&d).unwrap().mode() & 0o077, 0, "{}", d.display());
    }
    // Nothing in $TMPDIR.
    assert!(tree_listing(&env.root.join("tmp")).is_empty());
}

#[test]
fn a_run_rewrites_only_what_the_workspace_changed() {
    let env = Env::new();
    let proj = project(&env);
    exec(&env, &proj, &["--", "true"]);
    let dir = files_dir(&proj, "agent");
    let untouched = ino(&dir.join("src/lib.rs"));
    ws_write(&env, &proj, "agent", "a.txt", "changed elsewhere\n");
    ws_write(&env, &proj, "agent", "new/n.txt", "n\n");
    let out = exec(&env, &proj, &["--", "sh", "-c", "cat a.txt new/n.txt"]);
    assert!(out.contains("changed elsewhere\nn\n"), "{out}");
    assert!(out.contains("synced sandbox: 2 files written, 0 removed"), "{out}");
    assert_eq!(ino(&dir.join("src/lib.rs")), untouched);
}

#[test]
fn edits_creations_and_deletions_are_recorded_exactly() {
    let env = Env::new();
    let proj = project(&env);
    exec(&env, &proj, &["--", "true"]);
    exec(
        &env,
        &proj,
        &["-m", "agent work", "--", "sh", "-c", "echo b >> a.txt; mkdir -p d && echo n > d/new.txt; rm gone.txt; chmod +x src/lib.rs"],
    );
    let p = paths(&env, &proj, "agent@");
    assert_eq!(p, vec![".veilpolicy", "a.txt", "d/new.txt", "src/lib.rs"], "{p:?}");
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "a.txt"]), "a\nb\n");
    // A same-size rewrite whose mtime is put back (stat stamps alone would
    // miss it: the inode change time and the racy window catch it).
    exec(&env, &proj, &["--", "sh", "-c", "printf 'a\\nb\\n' > .ref; touch -r a.txt .ref; printf 'x\\ny\\n' > a.txt; touch -r .ref a.txt; rm .ref"]);
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "a.txt"]), "x\ny\n");
    // And it survives the next run unchanged.
    exec(&env, &proj, &["--", "true"]);
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "a.txt"]), "x\ny\n");
    assert_eq!(read(&files_dir(&proj, "agent"), "a.txt"), "x\ny\n");
}

#[test]
fn files_edited_right_after_the_sync_are_not_missed() {
    // The command starts within the racy window of the files checkout just
    // wrote; same-size edits must still be recorded.
    let env = Env::new();
    let proj = project(&env);
    for i in 0..5 {
        let body = format!("v{i}\n");
        ws_write(&env, &proj, "agent", "a.txt", &body);
        exec(&env, &proj, &["--", "sh", "-c", &format!("printf 'w{i}\\n' > a.txt")]);
        assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "a.txt"]), format!("w{i}\n"));
    }
}

#[test]
fn injected_secrets_are_taken_out_after_the_run() {
    let env = Env::new();
    let proj = project(&env);
    let dir = files_dir(&proj, "agent");
    // The sandbox's own .env (written by an earlier run) is put back after
    // an injected run.
    exec(&env, &proj, &["--", "sh", "-c", "echo LOCAL=1 > .env"]);
    let out = exec(
        &env,
        &proj,
        &["--with-isolated", "--", "sh", "-c", "cat .env; cp .env leak.txt; cat .env >> a.txt; mkdir -p deep && cp .env deep/copy; echo fine > fine.txt"],
    );
    assert!(out.contains("super-secret-isolated-value"), "the command saw the secret: {out}");
    assert_eq!(read(&dir, ".env"), "LOCAL=1\n");
    assert!(!dir.join("leak.txt").exists(), "copy of the secret left in the sandbox");
    assert!(!dir.join("deep").exists(), "copy of the secret left in the sandbox");
    assert_eq!(read(&dir, "a.txt"), "a\n", "the tracked file is put back");
    assert_eq!(read(&dir, "fine.txt"), "fine\n");
    let all = String::from_utf8_lossy(&std::process::Command::new("grep").arg("-r").arg("super-secret").arg(proj.join(".veil/local/sandboxes")).output().unwrap().stdout).into_owned();
    assert!(all.is_empty(), "secret left under the sandbox: {all}");
    // The next run, without the guard, records none of it.
    exec(&env, &proj, &["--", "true"]);
    let p = paths(&env, &proj, "agent@");
    assert!(p.contains(&"fine.txt".to_string()) && !p.iter().any(|p| p.contains("leak") || p.contains("deep")), "{p:?}");
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "a.txt"]), "a\n");
}

/// `kill -9` of `vl` during an injected run: the reaper takes the injected
/// file out again, and deletes nothing else (BUG-550: what the command
/// left is its output, and the next run records it first).
#[test]
fn the_reaper_takes_injected_files_out_of_a_run_that_was_killed() {
    let env = Env::new();
    let proj = project(&env);
    exec(&env, &proj, &["--", "sh", "-c", "mkdir -p target; echo o > target/o"]);
    let pidfile = env.root.join("child.pid");
    let script = format!("echo $$ > {}; exec sleep 30", pidfile.display());
    let mut child = env.spawn("alice", &proj, &["ws", "exec", "agent", "--with-isolated", "--", "sh", "-c", &script]);
    assert!(wait_for(Duration::from_secs(20), || pidfile.exists()), "never started");
    let _ = child.kill();
    let _ = child.wait();
    if let Ok(pid) = std::fs::read_to_string(&pidfile) {
        let _ = std::process::Command::new("kill").args(["-9", pid.trim()]).status();
    }
    let dir = files_dir(&proj, "agent");
    assert!(wait_for(Duration::from_secs(10), || !dir.join(".env").exists()), "injected secret left after kill -9");
    // The next run records what the killed one left (nothing new here),
    // keeps the build output and works.
    let out = exec(&env, &proj, &["--", "sh", "-c", "test -e target/o && cat a.txt"]);
    assert!(out.contains("Recording the output of an earlier run") && out.contains("a\n"), "{out}");
}

#[test]
fn an_unfinished_run_found_by_the_next_one_means_a_rebuild() {
    let env = Env::new();
    let proj = project(&env);
    exec(&env, &proj, &["--", "sh", "-c", "echo half > half.txt; mkdir -p target; echo o > target/o"]);
    // As if the run died with its reaper: the marker is still set.
    let mpath = proj.join(".veil/local/sandboxes/agent/manifest.json");
    let mut m: serde_json::Value = serde_json::from_slice(&std::fs::read(&mpath).unwrap()).unwrap();
    m["running"] = "deadbeef".into();
    std::fs::write(&mpath, serde_json::to_vec(&m).unwrap()).unwrap();
    std::fs::write(files_dir(&proj, "agent").join("debris.txt"), "partial write of a dead run\n").unwrap();
    let out = exec(&env, &proj, &["--", "sh", "-c", "ls"]);
    assert!(out.contains("Rebuilding the sandbox of workspace agent: the previous run did not finish"), "{out}");
    assert!(!out.contains("debris.txt") && !out.contains("target"), "{out}");
    assert!(!paths(&env, &proj, "agent@").contains(&"debris.txt".to_string()));
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "half.txt"]), "half\n", "recorded work kept");
}

#[test]
fn a_corrupt_manifest_or_a_replaced_files_directory_means_a_rebuild() {
    let env = Env::new();
    let proj = project(&env);
    exec(&env, &proj, &["--", "true"]);
    std::fs::write(proj.join(".veil/local/sandboxes/agent/manifest.json"), "{not json").unwrap();
    let out = exec(&env, &proj, &["--", "cat", "a.txt"]);
    assert!(out.contains("Rebuilding") && out.contains("a\n"), "{out}");
    // The files directory replaced by a symlink to somewhere else: never
    // written through.
    let outside = env.dir("outside");
    write(&outside, "keep.txt", "mine\n");
    let dir = files_dir(&proj, "agent");
    std::fs::remove_dir_all(&dir).unwrap();
    std::os::unix::fs::symlink(&outside, &dir).unwrap();
    let out = exec(&env, &proj, &["--", "cat", "a.txt"]);
    assert!(out.contains("Rebuilding") && out.contains("a\n"), "{out}");
    assert_eq!(tree_listing(&outside), vec!["keep.txt"]);
    assert!(std::fs::symlink_metadata(&dir).unwrap().is_dir());
}

#[test]
fn two_runs_in_one_workspace_take_turns() {
    let env = Env::new();
    let proj = project(&env);
    exec(&env, &proj, &["--", "true"]);
    let script = "n=$(cat count 2>/dev/null || echo 0); sleep 1; echo $((n+1)) > count";
    let a = env.spawn("alice", &proj, &["ws", "exec", "agent", "--", "sh", "-c", script]);
    std::thread::sleep(Duration::from_millis(300));
    let b = env.spawn("alice", &proj, &["ws", "exec", "agent", "--", "sh", "-c", script]);
    let (oa, ob) = (a.wait_with_output().unwrap(), b.wait_with_output().unwrap());
    assert!(oa.status.success() && ob.status.success(), "{}\n{}", text(&oa), text(&ob));
    assert!(text(&ob).contains("waiting:") || text(&oa).contains("waiting:"), "{}\n{}", text(&oa), text(&ob));
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "count"]), "2\n", "runs overlapped");
}

#[test]
fn ctrl_c_stops_the_command_and_vl_records_what_it_left() {
    let env = Env::new();
    let proj = project(&env);
    let started = env.root.join("started");
    let script = format!("echo partial > p.txt; touch {}; exec sleep 30", started.display());
    let child = {
        use std::os::unix::process::CommandExt;
        env.cmd("alice", &proj, &["ws", "exec", "agent", "--", "sh", "-c", &script])
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    assert!(wait_for(Duration::from_secs(20), || started.exists()));
    // The terminal's Ctrl-C goes to the whole foreground process group.
    // SAFETY: signals our own child's process group.
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGINT);
    }
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(130), "{}", text(&out));
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "p.txt"]), "partial\n");
    assert!(files_dir(&proj, "agent").join("p.txt").exists(), "sandbox kept");
}

#[test]
fn the_command_cannot_reach_the_project_through_vl_or_git() {
    let env = Env::new();
    let proj = project(&env);
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    std::process::Command::new("git").arg("init").arg("-q").current_dir(&proj).status().ok();
    let vl = env!("CARGO_BIN_EXE_vl");
    let o = env.vl(
        "alice",
        &proj,
        &["ws", "exec", "agent", "--", "sh", "-c", &format!("'{vl}' status; echo vl=$?; git rev-parse --show-toplevel; echo git=$?")],
    );
    let t = text(&o);
    assert!(t.contains("no Veil repository found"), "{t}");
    assert!(!t.contains("vl=0"), "{t}");
    if !t.contains("git: not found") {
        assert!(!t.contains("git=0"), "git found the project's repository: {t}");
    }
}

#[test]
fn a_workspace_moved_during_the_run_keeps_both_results() {
    let env = Env::new();
    let proj = project(&env);
    exec(&env, &proj, &["--", "true"]);
    let started = env.root.join("started");
    let script = format!("touch {}; sleep 2; echo run > run.txt", started.display());
    let child = env.spawn("alice", &proj, &["ws", "exec", "agent", "-m", "agent run", "--", "sh", "-c", &script]);
    assert!(wait_for(Duration::from_secs(20), || started.exists()));
    ws_write(&env, &proj, "agent", "meanwhile.txt", "m\n");
    let out = child.wait_with_output().unwrap();
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("moved while the command ran"), "{t}");
    let p = paths(&env, &proj, "agent@");
    assert!(p.contains(&"meanwhile.txt".to_string()) && !p.contains(&"run.txt".to_string()), "{p:?}");
    // The saved change holds the run's result.
    let id = t
        .lines()
        .find_map(|l| l.strip_prefix("Saved "))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("{t}"))
        .to_string();
    assert!(paths(&env, &proj, &id).contains(&"run.txt".to_string()));
    let log = env.stdout("alice", &proj, &["log", "-n", "50"]);
    assert!(log.contains("agent run"), "{log}");
    // The next run is in the workspace again.
    let o = exec(&env, &proj, &["--", "sh", "-c", "ls"]);
    assert!(o.contains("meanwhile.txt") && !o.contains("run.txt"), "{o}");
}

#[test]
fn ws_rm_removes_the_sandbox_but_not_quarantined_work_without_force() {
    let env = Env::new();
    let proj = project(&env);
    exec(&env, &proj, &["--", "sh", "-c", "echo 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' > creds.txt"]);
    let dir = proj.join(".veil/local/sandboxes/agent");
    assert!(dir.join("files/creds.txt").exists(), "quarantined work stays in the sandbox");
    let o = env.vl("alice", &proj, &["ws", "rm", "agent"]);
    assert!(!o.status.success() && text(&o).contains("creds.txt") && text(&o).contains("--force"), "{}", text(&o));
    assert!(dir.exists());
    let out = env.ok("alice", &proj, &["ws", "rm", "--force", "agent"]);
    assert!(out.contains("and its sandbox"), "{out}");
    assert!(!dir.exists());
}

#[test]
fn ws_rm_is_refused_while_a_run_is_in_progress() {
    let env = Env::new();
    let proj = project(&env);
    let started = env.root.join("started");
    let script = format!("touch {}; sleep 2", started.display());
    let child = env.spawn("alice", &proj, &["ws", "exec", "agent", "--", "sh", "-c", &script]);
    assert!(wait_for(Duration::from_secs(20), || started.exists()));
    let o = env.vl("alice", &proj, &["ws", "rm", "agent"]);
    assert!(!o.status.success() && text(&o).contains("is running"), "{}", text(&o));
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", text(&out));
    env.ok("alice", &proj, &["ws", "rm", "agent"]);
    assert!(!proj.join(".veil/local/sandboxes/agent").exists());
}

#[test]
fn doctor_reports_sandboxes_of_removed_workspaces() {
    let env = Env::new();
    let proj = project(&env);
    exec(&env, &proj, &["--", "true"]);
    let orphan = proj.join(".veil/local/sandboxes/ghost/files");
    std::fs::create_dir_all(&orphan).unwrap();
    let out = text(&env.vl("alice", &proj, &["doctor"]));
    assert!(out.contains("1 `ws exec` sandbox(es) in .veil/local/sandboxes"), "{out}");
    assert!(out.contains("ghost") && out.contains("no longer exists"), "{out}");
}

#[test]
fn ws_exec_of_dot_named_workspaces_stays_inside_the_sandboxes_directory() {
    let env = Env::new();
    let proj = project(&env);
    env.ok("alice", &proj, &["ws", "new", ".."]);
    let o = env.ok("alice", &proj, &["ws", "exec", "..", "--", "sh", "-c", "pwd; echo x > x.txt"]);
    assert!(o.contains("sandboxes/%2e%2e/files"), "{o}");
    assert!(!proj.join(".veil/local/files").exists());
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "..", "x.txt"]), "x\n");
}
