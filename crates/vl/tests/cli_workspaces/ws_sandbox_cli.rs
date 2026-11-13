//! Persistent `vl ws exec` sandboxes: kept between runs, synced
//! incrementally, recorded exactly, safe under concurrency, crashes and
//! injected secrets.

use crate::adversarial_support;

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
    write(&proj, ".netrc", "API_TOKEN=super-secret-isolated-value\n");
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
    // The sandbox's own .netrc (written by an earlier run) is put back after
    // an injected run.
    exec(&env, &proj, &["--", "sh", "-c", "echo LOCAL=1 > .netrc"]);
    let out = exec(
        &env,
        &proj,
        &["--with-isolated", "--", "sh", "-c", "cat .netrc; cp .netrc leak.txt; cat .netrc >> a.txt; mkdir -p deep && cp .netrc deep/copy; echo fine > fine.txt"],
    );
    assert!(out.contains("super-secret-isolated-value"), "the command saw the secret: {out}");
    assert_eq!(read(&dir, ".netrc"), "LOCAL=1\n");
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
    // Confined, the command sees only the sandbox: it says it started
    // there, and the confinement stops it when `vl` dies.
    let started = files_dir(&proj, "agent").join(".started");
    let mut child = env.spawn("alice", &proj, &["ws", "exec", "agent", "--with-isolated", "--", "sh", "-c", "touch .started; exec sleep 30"]);
    assert!(wait_for(Duration::from_secs(20), || started.exists()), "never started");
    let _ = std::fs::remove_file(&started);
    let _ = child.kill();
    let _ = child.wait();
    let dir = files_dir(&proj, "agent");
    assert!(wait_for(Duration::from_secs(10), || !dir.join(".netrc").exists()), "injected secret left after kill -9");
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
    let started = files_dir(&proj, "agent").join(".started");
    let script = "echo partial > p.txt; touch .started; exec sleep 30";
    let child = {
        use std::os::unix::process::CommandExt;
        env.cmd("alice", &proj, &["ws", "exec", "agent", "--", "sh", "-c", script])
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    assert!(wait_for(Duration::from_secs(20), || started.exists()));
    let _ = std::fs::remove_file(&started);
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
    // Confined (Linux), `vl` must be allowed in to be run at all.
    let script = format!("'{vl}' status; echo vl=$?; git rev-parse --show-toplevel; echo git=$?");
    let mut args = vec!["ws", "exec", "agent"];
    if cfg!(target_os = "linux") {
        args.extend(["--allow", vl]);
    }
    args.extend(["--", "sh", "-c", &script]);
    // Without the workspace socket, `vl` finds no repository; with it
    // (milestone S8) it runs on the sandbox's own workspace, through the
    // `vl` outside, never on the project directory.
    let unset = args.iter().map(|a| a.replace(&format!("'{vl}' status"), &format!("env -u VEIL_WORKSPACE_SOCKET '{vl}' status"))).collect::<Vec<_>>();
    let unset: Vec<&str> = unset.iter().map(String::as_str).collect();
    let o = env.vl("alice", &proj, &unset);
    assert!(o.status.success(), "{}", text(&o));
    let t = text(&o);
    assert!(t.contains("no Veil repository found"), "{t}");
    assert!(!t.contains("vl=0"), "{t}");
    let o = env.vl("alice", &proj, &args);
    let t = text(&o);
    assert!(o.status.success() && t.contains("vl=0") && t.contains("Workspace    : agent"), "{t}");
    if !t.contains("git: not found") {
        assert!(!t.contains("git=0"), "git found the project's repository: {t}");
    }
}

#[test]
fn a_workspace_moved_during_the_run_keeps_both_results() {
    let env = Env::new();
    let proj = project(&env);
    exec(&env, &proj, &["--", "true"]);
    let started = files_dir(&proj, "agent").join(".started");
    let script = "touch .started; sleep 2; echo run > run.txt";
    let child = env.spawn("alice", &proj, &["ws", "exec", "agent", "-m", "agent run", "--", "sh", "-c", script]);
    assert!(wait_for(Duration::from_secs(20), || started.exists()));
    let _ = std::fs::remove_file(&started);
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
    env.quarantined("alice", &proj, &["ws", "exec", "agent", "--", "sh", "-c", "echo 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' > creds.txt"]);
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
    let started = files_dir(&proj, "agent").join(".started");
    let child = env.spawn("alice", &proj, &["ws", "exec", "agent", "--", "sh", "-c", "touch .started; sleep 2"]);
    assert!(wait_for(Duration::from_secs(20), || started.exists()));
    let _ = std::fs::remove_file(&started);
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
    let out = env.ok("alice", &proj, &["doctor"]);
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

// BUG-2171: a `vl ws exec` whose command succeeded but whose recording left
// a file out as a secret exits 3, as `vl commit` does (BUG-2140), naming
// the file; with --ephemeral the file is moved out of the throwaway
// directory first, never deleted. The command's own failure keeps its
// status, with the same message.
const LEAK: &str = "echo \"const key = 'AKIAIOSFODNN7EXAMPLE';\" > cfg.js";
const LEFT_OUT: &str = "  cfg.js (aws-access-key-id at line 1; never recorded)";

fn recorded_id(out: &str) -> String {
    out.lines()
        .find_map(|l| l.strip_prefix("Recorded "))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("no Recorded line:\n{out}"))
        .to_string()
}

/// The one `cfg.js` an `--ephemeral` run kept, and its directory.
fn kept_file(proj: &Path) -> PathBuf {
    let dirs: Vec<PathBuf> = std::fs::read_dir(proj.join(".veil/local/ephemeral-kept")).unwrap().map(|e| e.unwrap().path()).collect();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    dirs[0].join("cfg.js")
}

#[test]
fn bug_2171_ws_exec_that_quarantines_an_output_file_exits_3() {
    let env = Env::new();
    let proj = project(&env);
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--", "sh", "-c", LEAK]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(3), "{t}");
    assert!(t.contains("error: recorded, but without 1 quarantined file (it looks like a secret):"), "{t}");
    assert!(t.contains(LEFT_OUT), "{t}");
    assert!(t.contains("vl ws switch agent") && t.contains("Exit status 3 until then"), "{t}");
    // The file stays in the sandbox, where the message says, and in no snapshot.
    let files = files_dir(&proj, "agent");
    assert!(t.contains(&files.display().to_string()), "{t}");
    assert!(read(&files, "cfg.js").contains("AKIAIOSFODNN7EXAMPLE"));
    let o = env.vl("alice", &proj, &["ws", "cat", "agent", "cfg.js"]);
    assert!(!o.status.success(), "cfg.js was recorded:\n{}", text(&o));

    // A failing command keeps its own status; the message is printed all the same.
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--", "sh", "-c", "exit 7"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(7), "{t}");
    assert!(t.contains(LEFT_OUT), "{t}");
    assert!(!t.contains("Exit status 3"), "{t}");

    // Isolated in that workspace, the file is kept on purpose: exit 0.
    env.ok("alice", &proj, &["ws", "switch", "agent"]);
    env.ok("alice", &proj, &["isolate", "cfg.js"]);
    env.ok("alice", &proj, &["ws", "switch", "default"]);
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--", "true"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(!t.contains("quarantined file"), "{t}");
    assert!(read(&files, "cfg.js").contains("AKIAIOSFODNN7EXAMPLE"));
}

#[test]
fn ephemeral_ws_exec_keeps_a_quarantined_file_and_exits_3() {
    let env = Env::new();
    let proj = project(&env);
    let leak = format!("{LEAK}; chmod 640 cfg.js; echo ok > ok.txt");
    let out = env.vl("alice", &proj, &["ws", "exec", "--ephemeral", "-r", "@-", "--", "sh", "-c", &leak]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(3), "{t}");
    assert!(t.contains("error: recorded, but without 1 quarantined file (it looks like a secret):"), "{t}");
    assert!(t.contains(LEFT_OUT), "{t}");
    assert!(!t.contains("Exit status 3"), "{t}");
    // Kept where the message says, with its permissions.
    let kept = kept_file(&proj);
    assert!(t.contains(&kept.parent().unwrap().display().to_string()), "{t}");
    assert_eq!(std::fs::read_to_string(&kept).unwrap(), "const key = 'AKIAIOSFODNN7EXAMPLE';\n");
    assert_eq!(std::fs::metadata(&kept).unwrap().mode() & 0o777, 0o640);
    assert_eq!(std::fs::metadata(kept.parent().unwrap()).unwrap().mode() & 0o777, 0o700);

    // The change has the rest, not the file; neither does a push of it.
    let id = recorded_id(&t);
    assert_eq!(env.stdout("alice", &proj, &["cat", "-r", &id, "ok.txt"]), "ok\n");
    let o = env.vl("alice", &proj, &["cat", "-r", &id, "cfg.js"]);
    assert!(!o.status.success(), "cfg.js was recorded:\n{}", text(&o));
    // The main working copy holds no quarantined file: its own commands exit 0.
    let st = env.ok("alice", &proj, &["status"]);
    assert!(!st.contains("cfg.js"), "{st}");
    env.ok("alice", &proj, &["tag", "set", "main", "-r", &id]);
    let remote = env.dir("remote");
    env.ok("alice", &proj, &["remote", "add", "origin", remote.to_str().unwrap()]);
    env.ok("alice", &proj, &["push", "origin"]);
    env.ok("bob", &env.root, &["clone", "remote", "bob"]);
    let bob = env.root.join("bob");
    assert_eq!(read(&bob, "ok.txt"), "ok\n");
    assert!(!bob.join("cfg.js").exists());
    assert!(!env.ok("bob", &bob, &["files", "-r", "main"]).contains("cfg.js"));
    // `vl doctor` lists the kept directory.
    let d = env.vl("alice", &proj, &["doctor"]);
    assert!(text(&d).contains(&kept.parent().unwrap().display().to_string()), "{}", text(&d));
}

#[test]
fn ephemeral_ws_exec_whose_command_fails_keeps_its_status_and_the_file() {
    let env = Env::new();
    let proj = project(&env);
    let leak = format!("{LEAK}; exit 7");
    let out = env.vl("alice", &proj, &["ws", "exec", "--ephemeral", "--", "sh", "-c", &leak]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(7), "{t}");
    assert!(t.contains(LEFT_OUT), "{t}");
    assert!(std::fs::read_to_string(kept_file(&proj)).unwrap().contains("AKIAIOSFODNN7EXAMPLE"));
}

/// A throwaway directory on another filesystem than the project (`/tmp` is
/// often a tmpfs): the file is copied out, at its path and with its mode,
/// into private directories, before the throwaway directory goes.
#[cfg(target_os = "linux")]
#[test]
fn ephemeral_ws_exec_keeps_a_quarantined_file_across_filesystems() {
    let env = Env::new();
    let proj = project(&env);
    let tmp = tempfile::tempdir_in("/dev/shm").expect("a /dev/shm to put the throwaway directory on");
    assert_ne!(std::fs::metadata(tmp.path()).unwrap().dev(), std::fs::metadata(&proj).unwrap().dev(), "not another filesystem");
    let leak = "mkdir -p deep/er && echo \"const key = 'AKIAIOSFODNN7EXAMPLE';\" > deep/er/cfg.js && chmod 604 deep/er/cfg.js";
    let out = env.cmd("alice", &proj, &["ws", "exec", "--ephemeral", "--", "sh", "-c", leak]).env("TMPDIR", tmp.path()).output().unwrap();
    let t = text(&out);
    assert_eq!(out.status.code(), Some(3), "{t}");
    assert!(t.contains("  deep/er/cfg.js (aws-access-key-id at line 1; never recorded)"), "{t}");
    assert!(!t.contains("lost with it"), "{t}");
    let dirs: Vec<PathBuf> = std::fs::read_dir(proj.join(".veil/local/ephemeral-kept")).unwrap().map(|e| e.unwrap().path()).collect();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    let kept = dirs[0].join("deep/er/cfg.js");
    assert_eq!(std::fs::read_to_string(&kept).unwrap(), "const key = 'AKIAIOSFODNN7EXAMPLE';\n");
    assert_eq!(std::fs::metadata(&kept).unwrap().mode() & 0o7777, 0o604);
    for d in [dirs[0].clone(), dirs[0].join("deep"), dirs[0].join("deep/er")] {
        assert_eq!(std::fs::metadata(&d).unwrap().mode() & 0o777, 0o700, "{}", d.display());
    }
    // The throwaway directory is gone.
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}

/// A step after the recording that fails (here: listing what the command
/// wrote outside `--only src`, in a directory it made unreadable) fails
/// the run, but the file the recording left out is kept and named all the
/// same, not deleted with the throwaway directory.
#[test]
fn ephemeral_ws_exec_that_fails_after_recording_still_keeps_the_file() {
    let env = Env::new();
    let proj = project(&env);
    let leak = "echo \"const key = 'AKIAIOSFODNN7EXAMPLE';\" > src/cfg.js && mkdir shut && chmod 000 shut";
    let out = env.vl("alice", &proj, &["ws", "exec", "--ephemeral", "--only", "src", "--", "sh", "-c", leak]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("  src/cfg.js (aws-access-key-id at line 1; never recorded)"), "{t}");
    let dirs: Vec<PathBuf> = std::fs::read_dir(proj.join(".veil/local/ephemeral-kept")).unwrap().map(|e| e.unwrap().path()).collect();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    assert!(t.contains(&dirs[0].display().to_string()), "{t}");
    assert_eq!(std::fs::read_to_string(dirs[0].join("src/cfg.js")).unwrap(), "const key = 'AKIAIOSFODNN7EXAMPLE';\n");
}

#[test]
#[ignore = "BUG-2200: an --ephemeral --only run fails after recording when the command left an unreadable directory outside the set"]
fn bug_2200_an_unreadable_directory_outside_the_set_does_not_fail_a_recorded_ephemeral_run() {
    let env = Env::new();
    let proj = project(&env);
    let out = env.vl("alice", &proj, &["ws", "exec", "--ephemeral", "--only", "src", "--", "sh", "-c", "echo ok > src/ok.txt && mkdir shut && chmod 000 shut"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    let id = recorded_id(&t);
    assert_eq!(env.stdout("alice", &proj, &["cat", "-r", &id, "src/ok.txt"]), "ok\n");
}
