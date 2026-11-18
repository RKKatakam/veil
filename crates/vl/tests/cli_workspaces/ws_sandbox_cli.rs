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

/// A run that left an unreadable directory outside `--only src` beside a
/// file the recording left out: the run is recorded (BUG-2200; this step
/// failed it before), exits 3 for the file, and the file is kept and named,
/// not deleted with the throwaway directory (BUG-2171: it is moved out
/// before any later step).
#[test]
fn ephemeral_ws_exec_with_an_unreadable_directory_outside_the_set_still_keeps_the_file() {
    let env = Env::new();
    let proj = project(&env);
    let leak = "echo \"const key = 'AKIAIOSFODNN7EXAMPLE';\" > src/cfg.js && mkdir shut && chmod 000 shut";
    let out = env.vl("alice", &proj, &["ws", "exec", "--ephemeral", "--only", "src", "--", "sh", "-c", leak]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(3), "{t}");
    assert!(t.contains("Recorded "), "{t}");
    assert!(t.contains("  src/cfg.js (aws-access-key-id at line 1; never recorded)"), "{t}");
    let dirs: Vec<PathBuf> = std::fs::read_dir(proj.join(".veil/local/ephemeral-kept")).unwrap().map(|e| e.unwrap().path()).collect();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    assert!(t.contains(&dirs[0].display().to_string()), "{t}");
    assert_eq!(std::fs::read_to_string(dirs[0].join("src/cfg.js")).unwrap(), "const key = 'AKIAIOSFODNN7EXAMPLE';\n");
}

/// A step after the recording that fails fails the run, but the file the
/// recording left out is kept and named all the same, not deleted with the
/// throwaway directory (BUG-2171: it is moved out before any later step).
/// The step: an unconfined command, given the isolated files, shuts the
/// project's own vault of them, which `vl` reads again after the recording
/// to tell them from what the command wrote outside `--only`. (A confined
/// command cannot make a later step fail any more: BUG-2200.)
#[test]
fn ephemeral_ws_exec_that_fails_after_recording_still_keeps_the_file() {
    let env = Env::new();
    let proj = project(&env);
    let vault = proj.join(".veil/local/vault.sealed");
    assert!(vault.is_file(), "the project has an isolated file");
    let leak = format!("echo \"const key = 'AKIAIOSFODNN7EXAMPLE';\" > src/cfg.js && chmod 000 '{}'", vault.display());
    let out = env.vl("alice", &proj, &["ws", "exec", "--ephemeral", "--unconfined", "--with-isolated", "--only", "src", "--", "sh", "-c", &leak]);
    std::fs::set_permissions(&vault, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("vault.sealed: Permission denied"), "{t}");
    assert!(t.contains("  src/cfg.js (aws-access-key-id at line 1; never recorded)"), "{t}");
    let dirs: Vec<PathBuf> = std::fs::read_dir(proj.join(".veil/local/ephemeral-kept")).unwrap().map(|e| e.unwrap().path()).collect();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    assert!(t.contains(&dirs[0].display().to_string()), "{t}");
    assert_eq!(std::fs::read_to_string(dirs[0].join("src/cfg.js")).unwrap(), "const key = 'AKIAIOSFODNN7EXAMPLE';\n");
}

/// BUG-2200: a directory the command made unreadable outside the `--only`
/// set is named in a warning, as a recording names one inside it; the run,
/// already recorded, does not fail on it, and the throwaway directory goes.
#[test]
fn bug_2200_an_unreadable_directory_outside_the_set_does_not_fail_a_recorded_ephemeral_run() {
    let env = Env::new();
    let proj = project(&env);
    let cmd = "echo ok > src/ok.txt && echo stray > notes.txt && mkdir shut && echo in > shut/f && chmod 000 shut";
    let out = env.vl("alice", &proj, &["ws", "exec", "--ephemeral", "--only", "src", "--", "sh", "-c", cmd]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    let id = recorded_id(&t);
    assert_eq!(env.stdout("alice", &proj, &["cat", "-r", &id, "src/ok.txt"]), "ok\n");
    // What could be listed is named as before; what could not, by its directory.
    assert!(t.contains("not recorded: 1 file(s) written outside --only src: notes.txt"), "{t}");
    assert!(
        t.contains("cannot list shut (Permission denied (os error 13)): whatever the command wrote there, outside --only src, is not recorded and goes with the throwaway directory"),
        "{t}"
    );
    assert!(!paths(&env, &proj, &id).iter().any(|p| p.starts_with("shut") || p == "notes.txt"));
    assert!(tree_listing(&env.root.join("tmp")).is_empty(), "the throwaway directory is gone");
}

/// BUG-2200, a persistent sandbox (the same step after its recording): the
/// run is recorded, and the sandbox takes the next `--only` run too. What
/// the command left in the directory it made unlistable is its output
/// outside its paths: it could not be removed then, and is, as written
/// outside `--only`, by the first `--only` run that can list it, so no
/// later run takes it for the workspace's.
#[test]
fn bug_2200_an_unreadable_directory_outside_the_set_does_not_fail_a_persistent_sandbox() {
    let env = Env::new();
    let proj = project(&env);
    let dir = files_dir(&proj, "agent");
    let cannot = "cannot list shut (Permission denied (os error 13)): whatever the command wrote there, outside --only src, is not recorded and stays in the sandbox";
    let cmd = "echo one > src/one.txt && mkdir shut && echo work > shut/f && chmod 000 shut";
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src", "--", "sh", "-c", cmd]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("Recorded ") && t.contains(cannot), "{t}");
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "src/one.txt"]), "one\n");
    // The next run starts, is recorded, and says so again.
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src", "--", "sh", "-c", "echo two > src/two.txt && echo stray > notes.txt"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("Recorded ") && t.contains(cannot), "{t}");
    assert!(t.contains("not recorded: 1 file(s) written outside --only src (removed from the sandbox): notes.txt"), "{t}");
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "src/two.txt"]), "two\n");
    // A run that opens the directory: what the first command left there
    // goes with what this one wrote outside the paths.
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src", "--", "sh", "-c", "chmod 755 shut && echo new > new.txt"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(!t.contains("cannot list") && !t.contains("did not write"), "{t}");
    assert!(t.contains("not recorded: 2 file(s) written outside --only src (removed from the sandbox): new.txt, shut/f"), "{t}");
    assert!(!dir.join("shut").exists() && !dir.join("new.txt").exists());
    // A run of the whole tree finds nothing of it to record.
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--", "true"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(!paths(&env, &proj, "agent@").iter().any(|p| p.starts_with("shut") || p == "new.txt" || p == "notes.txt"));
}

/// BUG-2200: the same when the directory is opened between two runs (by
/// hand, here): the listing before the next command does not take what a
/// command left there for files the sandbox held before.
#[test]
fn bug_2200_what_a_command_left_in_a_directory_it_shut_is_removed_once_listable() {
    let env = Env::new();
    let proj = project(&env);
    let dir = files_dir(&proj, "agent");
    let cmd = "echo one > src/one.txt && mkdir -p shut/deep && echo work > shut/deep/f && chmod 000 shut";
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src", "--", "sh", "-c", cmd]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    std::fs::set_permissions(dir.join("shut"), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src", "--", "true"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("not recorded: 1 file(s) written outside --only src (removed from the sandbox): shut/deep/f"), "{t}");
    assert!(!t.contains("did not write"), "{t}");
    assert!(!dir.join("shut").exists());
}

/// BUG-2200: what an `--only` run's command left in a directory it shut
/// cannot be removed after that run. A run of the whole tree would record
/// it as the workspace's if its command opened the directory: it does not
/// start while the directory is there, and says how to go on. After an
/// `--only` run that can list the directory (which removes what was
/// written there) it runs, and records none of it.
#[test]
fn bug_2200_a_whole_tree_run_never_records_what_an_only_run_left_in_a_shut_directory() {
    let env = Env::new();
    let proj = project(&env);
    let dir = files_dir(&proj, "agent");
    let cmd = "echo one > src/one.txt && mkdir shut && echo stray > shut/f && chmod 000 shut";
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src", "--", "sh", "-c", cmd]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let whole = ["ws", "exec", "agent", "--", "sh", "-c", "chmod 755 shut; echo ran > ran.txt"];
    let out = env.vl("alice", &proj, &whole);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("holds shut, which a command of an earlier `--only src` run made unlistable"), "{t}");
    assert!(t.contains(&format!("`chmod u+rwx {}`", dir.join("shut").display())) && t.contains("`vl ws exec agent --only src -- true`"), "{t}");
    assert!(!t.contains("running sh") && !dir.join("ran.txt").exists(), "the command ran: {t}");
    assert!(!paths(&env, &proj, "agent@").iter().any(|p| p.starts_with("shut")));
    // As the message says.
    std::fs::set_permissions(dir.join("shut"), std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src", "--", "true"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("not recorded: 1 file(s) written outside --only src (removed from the sandbox): shut/f"), "{t}");
    let out = env.vl("alice", &proj, &whole);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    let recorded = paths(&env, &proj, "agent@");
    assert!(recorded.contains(&"src/one.txt".to_string()) && recorded.contains(&"ran.txt".to_string()), "{recorded:?}");
    assert!(!recorded.iter().any(|p| p.starts_with("shut")), "recorded: {recorded:?}");
}

/// BUG-2200: deleting the directory is the other way on: a run of the
/// whole tree then starts.
#[test]
fn bug_2200_a_whole_tree_run_starts_once_the_shut_directory_is_deleted() {
    let env = Env::new();
    let proj = project(&env);
    let dir = files_dir(&proj, "agent");
    let cmd = "mkdir shut && echo stray > shut/f && chmod 000 shut";
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src", "--", "sh", "-c", cmd]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    std::fs::set_permissions(dir.join("shut"), std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    std::fs::remove_dir_all(dir.join("shut")).unwrap();
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--", "sh", "-c", "echo ran > ran.txt"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(paths(&env, &proj, "agent@").contains(&"ran.txt".to_string()));
}

/// BUG-2200: the refusal looks at what the run's paths reach, not only at
/// whether they hold the whole directory. The tree has `docs/api/`; an
/// `--only src` run's command writes `docs/api/x.md` and shuts `docs`. A
/// run with `--only src docs/api` would take `x.md` for the workspace's
/// (it is inside its paths): it does not start. After a run with the
/// earlier paths, which removes it, it does, and records none of it.
#[test]
fn bug_2200_a_run_whose_paths_reach_into_a_shut_directory_never_records_what_was_left_there() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("src/lib.rs", "pub fn f() {}\n"), ("docs/api/index.md", "index\n"), ("docs/guide.md", "guide\n")]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "main"]);
    let dir = files_dir(&proj, "agent");
    let cmd = "mkdir -p docs/api && echo x > docs/api/x.md && chmod 000 docs";
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src", "--", "sh", "-c", cmd]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("cannot list docs (Permission denied (os error 13))"), "{t}");
    // Opened by hand.
    std::fs::set_permissions(dir.join("docs"), std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    for only in [&["src", "docs/api"][..], &["docs/api/index.md"], &["docs"]] {
        let mut args = vec!["ws", "exec", "agent", "--only"];
        args.extend_from_slice(only);
        args.extend_from_slice(&["--", "sh", "-c", "echo ran > src/ran.txt"]);
        let out = env.vl("alice", &proj, &args);
        let t = text(&out);
        assert_eq!(out.status.code(), Some(1), "--only {only:?}: {t}");
        assert!(t.contains("holds docs, which a command of an earlier `--only src` run made unlistable"), "{t}");
        assert!(t.contains("`vl ws exec agent --only src -- true`"), "{t}");
        assert!(!t.contains("running sh") && !dir.join("src/ran.txt").exists(), "the command ran: {t}");
    }
    assert!(!paths(&env, &proj, "agent@").iter().any(|p| p == "docs/api/x.md"));
    // The way on: the earlier paths once more, then the wider run.
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src", "--", "true"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("not recorded: 1 file(s) written outside --only src (removed from the sandbox): docs/api/x.md"), "{t}");
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src", "docs/api", "--", "sh", "-c", "echo more >> docs/api/index.md"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    let recorded = paths(&env, &proj, "agent@");
    assert!(!recorded.iter().any(|p| p == "docs/api/x.md"), "{recorded:?}");
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "docs/api/index.md"]), "index\nmore\n");
}

/// BUG-2200: a command that shuts a directory on the way to its own paths
/// (`a`, with `--only a/src`) does not lock its paths out: once `a` can be
/// listed, a run with the same paths starts (what it holds below `a` was
/// that run's own), and removes what the command wrote in `a` outside
/// them; a run of more of `a`, or of less (BUG-2651), waits for that.
#[test]
fn bug_2200_a_directory_shut_on_the_way_to_the_paths_does_not_refuse_those_paths() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a/src/lib.rs", "pub fn f() {}\n"), ("a/src/deep/m.rs", "// m\n"), ("a/README.md", "a\n"), ("b.txt", "b\n")]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "main"]);
    let dir = files_dir(&proj, "agent");
    let cmd = "echo one > a/src/one.rs && echo stray > a/stray.txt && chmod 000 a";
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "a/src", "--", "sh", "-c", cmd]);
    let t = text(&out);
    // (Nothing of `a/src` could be read either: nothing to record yet.)
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("cannot list a (Permission denied (os error 13))"), "{t}");
    std::fs::set_permissions(dir.join("a"), std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    // More of `a` than that run held: refused.
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "a", "--", "true"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("holds a, which a command of an earlier `--only a/src` run made unlistable"), "{t}");
    // The same paths: it starts.
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "a/src", "--", "true"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(!dir.join("a/stray.txt").exists(), "{t}");
    let recorded = paths(&env, &proj, "agent@");
    assert!(recorded.contains(&"a/src/one.rs".to_string()) && !recorded.iter().any(|p| p == "a/stray.txt"), "{recorded:?}");
    // And then less of `a`, and all of it.
    for only in ["a/src/deep", "a"] {
        let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", only, "--", "true"]);
        assert_eq!(out.status.code(), Some(0), "--only {only}: {}", text(&out));
    }
    assert!(!paths(&env, &proj, "agent@").iter().any(|p| p == "a/stray.txt"));
}

/// The project of BUG-2651's tests, after an `--only a/src` run whose
/// command shut `a`: the sandbox remembers `a` with the paths `a/src`.
/// `open`: `a` is then opened again by hand.
fn bug_2651_project(env: &Env, open: bool) -> (PathBuf, PathBuf) {
    let proj = env.project("alice", "proj", &[("a/src/lib.rs", "pub fn f() {}\n"), ("a/src/deep/m.rs", "// m\n"), ("a/README.md", "a\n"), ("b.txt", "b\n")]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "main"]);
    let dir = files_dir(&proj, "agent");
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "a/src", "--", "sh", "-c", "chmod 000 a"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    if open {
        chmod(&dir.join("a"), 0o700);
    }
    (proj, dir)
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode)).unwrap();
}

/// A run refused because of a shut directory: exit 1, the directory and
/// the paths of the run that shut it named, and the command not run. The
/// command the message gives as the way on, as written.
fn refused_for(out: &std::process::Output, dir: &str, was: &str) -> String {
    let t = text(out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains(&format!("holds {dir}, which a command of an earlier `--only {was}` run made unlistable")), "{t}");
    assert!(!t.contains("running "), "the command ran: {t}");
    t.split('`').find(|c| c.starts_with("vl ws exec ")).unwrap_or_else(|| panic!("no command in: {t}")).to_string()
}

/// Run `given` (a command a message gave, starting with `vl`) through a
/// shell, as a person pasting it would.
fn run_as_written(env: &Env, proj: &Path, given: &str) -> std::process::Output {
    let rest = given.strip_prefix("vl ").unwrap_or_else(|| panic!("not a vl command: {given}"));
    let mut c = std::process::Command::new("sh");
    c.arg("-c").arg(format!("exec \"$VL_UNDER_TEST\" {rest}")).current_dir(proj).env("VL_UNDER_TEST", env!("CARGO_BIN_EXE_vl"));
    for (k, v) in env.cmd("alice", proj, &[]).get_envs() {
        if let Some(v) = v {
            c.env(k, v);
        }
    }
    c.output().unwrap()
}

/// BUG-2651, the first reproduction. A shut directory carried forward kept
/// the paths of the first run that shut it, though a narrower run could
/// write there: with `a` opened by hand, `--only a/src/deep` wrote
/// `a/src/y.rs`, outside its own paths, and shut `a` again, and the
/// `--only a/src` run the refusal itself suggested recorded the file.
/// Beside a shut directory only a run with exactly its entry's paths at
/// or below it starts: the narrower run waits for the cleaning run. Once
/// it runs, and shuts `a` again, the directory is its own, and the run
/// with its paths removes what it wrote outside them. `a/src/y.rs` is
/// never recorded.
#[test]
fn bug_2651_a_narrower_run_that_shuts_the_directory_again_does_not_get_its_strays_recorded() {
    let env = Env::new();
    let (proj, dir) = bug_2651_project(&env, true);
    let narrow = ["ws", "exec", "agent", "--only", "a/src/deep", "--", "sh", "-c", "echo y > a/src/y.rs && chmod 000 a"];
    let given = refused_for(&env.vl("alice", &proj, &narrow), "a", "a/src");
    assert_eq!(given, "vl ws exec agent --only a/src -- true");
    assert!(!dir.join("a/src/y.rs").exists());
    let out = run_as_written(&env, &proj, &given);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    // Now the narrower run starts; its command writes outside its paths
    // and shuts `a`, which is then that run's.
    let out = env.vl("alice", &proj, &narrow);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("running sh") && t.contains("cannot list a (Permission denied (os error 13))"), "{t}");
    chmod(&dir.join("a"), 0o700);
    let given = refused_for(&env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "a/src", "--", "true"]), "a", "a/src/deep");
    assert_eq!(given, "vl ws exec agent --only a/src/deep -- true");
    let out = run_as_written(&env, &proj, &given);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("not recorded: 1 file(s) written outside --only a/src/deep (removed from the sandbox): a/src/y.rs"), "{t}");
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "a/src", "--", "true"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let recorded = paths(&env, &proj, "agent@");
    assert!(recorded.contains(&"a/src/lib.rs".to_string()), "{recorded:?}");
    assert!(!recorded.iter().any(|p| p == "a/src/y.rs"), "a/src/y.rs, written outside --only a/src/deep, was recorded: {recorded:?}");
}

/// BUG-2651, its second form: the narrower run shuts `a/src` itself, a
/// directory the first run held whole. The way on a refusal gives was that
/// same refused run, a loop. Now each refusal names the paths of the run
/// that shut the directory in its way, and that command starts.
#[test]
fn bug_2651_the_way_on_the_refusal_gives_is_not_refused_itself() {
    let env = Env::new();
    let (proj, dir) = bug_2651_project(&env, true);
    let narrow = ["ws", "exec", "agent", "--only", "a/src/deep", "--", "sh", "-c", "echo y > a/src/y.rs && chmod 000 a/src"];
    let given = refused_for(&env.vl("alice", &proj, &narrow), "a", "a/src");
    let out = run_as_written(&env, &proj, &given);
    assert_eq!(out.status.code(), Some(0), "the way on is refused: {}", text(&out));
    let out = env.vl("alice", &proj, &narrow);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("running sh") && t.contains("cannot list a/src (Permission denied (os error 13))"), "{t}");
    chmod(&dir.join("a/src"), 0o700);
    // `--only a/src` holds the shut directory whole: refused, and the way on
    // is the narrower run's paths, which starts and removes its stray.
    let given = refused_for(&env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "a/src", "--", "true"]), "a/src", "a/src/deep");
    assert_eq!(given, "vl ws exec agent --only a/src/deep -- true");
    let out = run_as_written(&env, &proj, &given);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "the way on is refused: {t}");
    assert!(!dir.join("a/src/y.rs").exists(), "{t}");
    // And then the wider run starts, with nothing of it to record.
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "a/src", "--", "true"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "the way on is refused: {t}");
    assert!(!paths(&env, &proj, "agent@").iter().any(|p| p == "a/src/y.rs"));
}

/// BUG-2651, the third route (review of its first fix): with `a` still
/// shut, a run whose paths name the same files by other paths (`--only
/// a/src/deep a/src/lib.rs` for `a/src`) has nothing to sync, so it
/// started; its command, which owns the directory, opened it, wrote
/// `a/src/y.rs` outside its paths and shut it again, unseen, and the entry
/// kept `a/src`: the next `--only a/src` run recorded the file. No run
/// with other paths at or below the directory starts, whatever files they
/// name: not that one, not a narrower one, not one beside it that drops
/// them; and nothing is pending for `--record-only` to record.
#[test]
fn bug_2651_no_run_with_other_paths_below_a_shut_directory_starts() {
    let env = Env::new();
    let (proj, dir) = bug_2651_project(&env, false);
    let reopen = "chmod 700 a; echo y > a/src/y.rs; chmod 000 a; echo ran > b.txt";
    for only in [&["a/src/deep", "a/src/lib.rs"][..], &["a/src/deep"], &["a/src/lib.rs"], &["b.txt"], &["a/src/deep", "b.txt"], &["a"]] {
        let mut args = vec!["ws", "exec", "agent", "--only"];
        args.extend_from_slice(only);
        args.extend_from_slice(&["--", "sh", "-c", reopen]);
        let given = refused_for(&env.vl("alice", &proj, &args), "a", "a/src");
        assert_eq!(given, "vl ws exec agent --only a/src -- true", "--only {only:?}");
    }
    refused_for(&env.vl("alice", &proj, &["ws", "exec", "agent", "--", "sh", "-c", reopen]), "a", "a/src");
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--record-only"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("Nothing to record"), "{t}");
    chmod(&dir.join("a"), 0o700);
    assert!(!dir.join("a/src/y.rs").exists() && !dir.join("b.txt").exists());
    // The way on, then the run with other paths: `y.rs` is its stray now.
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "a/src", "--", "true"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "a/src/deep", "a/src/lib.rs", "--", "sh", "-c", "echo y > a/src/y.rs"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("(removed from the sandbox): a/src/y.rs"), "{t}");
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "a/src", "--", "true"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(!paths(&env, &proj, "agent@").iter().any(|p| p == "a/src/y.rs"));
}

/// BUG-2651: a run with the entry's own paths starts beside the directory,
/// shut or not. What its command writes inside them is its output,
/// recorded once the directory can be read; what it writes there outside
/// them is removed then. The entry keeps its paths throughout.
#[test]
fn bug_2651_a_run_with_the_same_paths_starts_beside_the_shut_directory() {
    let env = Env::new();
    let (proj, dir) = bug_2651_project(&env, false);
    let shut = |proj: &Path| -> serde_json::Value {
        let m: serde_json::Value = serde_json::from_slice(&std::fs::read(proj.join(".veil/local/sandboxes/agent/manifest.json")).unwrap()).unwrap();
        m["shut_by_command"].clone()
    };
    assert_eq!(shut(&proj), serde_json::json!([{"dir": "a", "only": ["a/src"]}]));
    let reopen = "chmod 700 a; echo y > a/src/y.rs; echo z > a/z.txt; chmod 000 a";
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "a/src", "--", "sh", "-c", reopen]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("running sh") && t.contains("cannot list a (Permission denied (os error 13))"), "{t}");
    assert_eq!(shut(&proj), serde_json::json!([{"dir": "a", "only": ["a/src"]}]));
    chmod(&dir.join("a"), 0o700);
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "a/src", "--", "true"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("not recorded: 1 file(s) written outside --only a/src (removed from the sandbox): a/z.txt"), "{t}");
    assert_eq!(shut(&proj), serde_json::Value::Null);
    let recorded = paths(&env, &proj, "agent@");
    assert!(recorded.contains(&"a/src/y.rs".to_string()) && !recorded.iter().any(|p| p == "a/z.txt"), "{recorded:?}");
}

/// BUG-2651: a shut directory that is on no run's way (`shut`, beside
/// `src`) refuses no run that leaves it alone, narrower or not, and keeps
/// the paths of the run that shut it.
#[test]
fn bug_2651_a_directory_that_stayed_shut_keeps_the_paths_of_the_run_that_shut_it() {
    let env = Env::new();
    let proj = project(&env);
    let dir = files_dir(&proj, "agent");
    let shut = |proj: &Path| -> serde_json::Value {
        let m: serde_json::Value = serde_json::from_slice(&std::fs::read(proj.join(".veil/local/sandboxes/agent/manifest.json")).unwrap()).unwrap();
        m["shut_by_command"].clone()
    };
    let cmd = "mkdir shut && echo stray > shut/f && chmod 000 shut";
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src", "--", "sh", "-c", cmd]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(shut(&proj), serde_json::json!([{"dir": "shut", "only": ["src"]}]));
    // A narrower run beside it, which leaves it shut.
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src/lib.rs", "--", "sh", "-c", "echo x >> src/lib.rs"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("cannot list shut (Permission denied (os error 13))"), "{t}");
    assert_eq!(shut(&proj), serde_json::json!([{"dir": "shut", "only": ["src"]}]));
    // Opened by hand: any run beside it removes what the first command left.
    chmod(&dir.join("shut"), 0o700);
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src/lib.rs", "--", "true"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("not recorded: 1 file(s) written outside --only src/lib.rs (removed from the sandbox): shut/f"), "{t}");
    assert_eq!(shut(&proj), serde_json::Value::Null);
}

/// BUG-2651: no run takes a shut directory over, so nothing a person or
/// the run that shut it left inside that run's paths is ever removed as a
/// narrower run's stray. A file written by hand in `a/src`, and the first
/// run's own output there that could not be recorded while `a` was shut,
/// stay through the refusal and are recorded by the run with those paths.
#[test]
fn bug_2651_files_inside_the_shutting_runs_paths_are_never_removed_as_a_narrower_runs() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a/src/lib.rs", "pub fn f() {}\n"), ("a/src/deep/m.rs", "// m\n")]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "main"]);
    let dir = files_dir(&proj, "agent");
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "a/src", "--", "sh", "-c", "echo one > a/src/one.rs && chmod 000 a"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    chmod(&dir.join("a"), 0o700);
    std::fs::write(dir.join("a/src/hand.rs"), "a person's notes\n").unwrap();
    let narrow = ["ws", "exec", "agent", "--only", "a/src/deep", "--", "sh", "-c", "chmod 000 a"];
    let given = refused_for(&env.vl("alice", &proj, &narrow), "a", "a/src");
    assert_eq!(read(&dir, "a/src/hand.rs"), "a person's notes\n");
    assert_eq!(read(&dir, "a/src/one.rs"), "one\n");
    let out = run_as_written(&env, &proj, &given);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(!t.contains("written outside"), "{t}");
    let recorded = paths(&env, &proj, "agent@");
    assert!(recorded.contains(&"a/src/hand.rs".to_string()) && recorded.contains(&"a/src/one.rs".to_string()), "{recorded:?}");
}

/// BUG-2651: the command a refusal gives as the way on runs as written,
/// with several paths (given as `--only` takes them, not as a list with
/// commas) and with paths a shell would split (quoted).
#[test]
fn bug_2651_the_refusals_command_runs_as_written_with_several_paths() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("src/lib.rs", "pub fn f() {}\n"), ("my docs/it's here/index.md", "index\n"), ("b.txt", "b\n")]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "main"]);
    let dir = files_dir(&proj, "agent");
    let cmd = "mkdir 'shut dir' && echo stray > 'shut dir/f' && chmod 000 'shut dir'";
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src", "my docs/it's here", "--", "sh", "-c", cmd]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--", "true"]);
    let t = text(&out);
    let given = refused_for(&out, "shut dir", r"'my docs/it'\''s here' src");
    assert_eq!(given, r"vl ws exec agent --only 'my docs/it'\''s here' src -- true");
    // The `chmod` it gives, as written too.
    let hint = t.split('`').find(|c| c.starts_with("chmod u+rwx ")).unwrap_or_else(|| panic!("no chmod in: {t}"));
    assert_eq!(hint, format!("chmod u+rwx '{}'", dir.join("shut dir").display()));
    assert!(std::process::Command::new("sh").arg("-c").arg(hint).status().unwrap().success());
    let out = run_as_written(&env, &proj, &given);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("(removed from the sandbox): shut dir/f"), "{t}");
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--", "true"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(!paths(&env, &proj, "agent@").iter().any(|p| p.starts_with("shut")));
}

/// BUG-2200: a rebuild of the sandbox (here: after a run that died) keeps
/// the files outside the paths as work to bring over, but not what a
/// command left in a directory it shut: that was to be removed, and no
/// later run finds it.
#[test]
fn bug_2200_a_rebuild_does_not_bring_over_what_a_command_left_in_a_shut_directory() {
    let env = Env::new();
    let proj = project(&env);
    let dir = files_dir(&proj, "agent");
    let cmd = "mkdir shut && echo stray > shut/f && chmod 000 shut";
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src", "--", "sh", "-c", cmd]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    std::fs::set_permissions(dir.join("shut"), std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    // A file put beside it by hand is work; one put into it is named with
    // what the command left there. Then, as if a run died.
    std::fs::write(dir.join("mine.txt"), "by hand\n").unwrap();
    std::fs::write(dir.join("shut/note.txt"), "by hand, in the shut directory\n").unwrap();
    let mpath = proj.join(".veil/local/sandboxes/agent/manifest.json");
    let mut m: serde_json::Value = serde_json::from_slice(&std::fs::read(&mpath).unwrap()).unwrap();
    assert_eq!(m["shut_by_command"], serde_json::json!([{"dir": "shut", "only": ["src"]}]));
    m["running"] = "deadbeef".into();
    std::fs::write(&mpath, serde_json::to_vec(&m).unwrap()).unwrap();
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--", "true"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("Rebuilding the sandbox of workspace agent: the previous run did not finish"), "{t}");
    // Named, as a run names what it removes.
    assert!(
        t.contains("not recorded: 2 file(s) in a directory a command had made unlistable outside its --only paths (not brought over to the rebuilt sandbox): shut/f, shut/note.txt"),
        "{t}"
    );
    assert_eq!(read(&dir, "mine.txt"), "by hand\n");
    assert!(!dir.join("shut").exists(), "{t}");
    assert!(!paths(&env, &proj, "agent@").iter().any(|p| p.starts_with("shut")));
}

/// BUG-2200: a directory nobody's command shut (unlistable before any
/// command ran: made so by hand) keeps what it holds. Once listable, its
/// files are files the command did not write: kept, never removed.
#[test]
fn bug_2200_a_directory_unlistable_before_any_command_keeps_what_it_holds() {
    let env = Env::new();
    let proj = project(&env);
    let dir = files_dir(&proj, "agent");
    // The sandbox exists, with `src` only.
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src", "--", "true"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    // By hand: work in a directory, shut.
    std::fs::create_dir(dir.join("mine")).unwrap();
    std::fs::write(dir.join("mine/notes.txt"), "by hand\n").unwrap();
    std::fs::set_permissions(dir.join("mine"), std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
    // A run that leaves it shut, then one that opens it.
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src", "--", "sh", "-c", "echo two > src/two.txt"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("Recorded ") && t.contains("cannot list mine (Permission denied (os error 13))"), "{t}");
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "src", "--", "sh", "-c", "chmod 755 mine"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("that the command did not write (kept; a run whose paths hold them records them): mine/notes.txt"), "{t}");
    assert_eq!(read(&dir, "mine/notes.txt"), "by hand\n");
}

fn extract_between<'a>(haystack: &'a str, before: &str, after: &str) -> &'a str {
    let rest = haystack.split_once(before).unwrap_or_else(|| panic!("missing {before:?} in:\n{haystack}")).1;
    rest.split_once(after).unwrap_or_else(|| panic!("missing {after:?} in:\n{haystack}")).0
}

fn run_chmod_as_written(cwd: &Path, chmod_cmd: &str) {
    assert!(chmod_cmd.starts_with("chmod u+rwx "), "unexpected chmod command: {chmod_cmd}");
    let out = std::process::Command::new("sh").arg("-c").arg(chmod_cmd).current_dir(cwd).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "chmod failed ({chmod_cmd}): {}", text(&out));
}

/// BUG-2652: the commands the shut-directory refusal gives (`chmod` and `vl
/// ws exec`) run as written through a shell in every case where names hold
/// printable UTF-8: `--only` paths starting with `-` (first or after `+x`
/// where `-m` would otherwise become `--message`), `=` (expanded by zsh if
/// unquoted), shell metacharacters (`$()`, backticks, `;`, quotes), runs
/// invoked from a subdirectory (including the `--only` directory itself) or
/// from outside the repository with `-R`, and workspace names starting with
/// `-` (`-`, `-agent`, `--ephemeral`).
#[test]
fn bug_2652_the_refusals_command_runs_as_written_for_hyphens_metacharacters_and_subdirectories() {
    let env = Env::new();
    let sentinel = env.root.join("INJECTED");
    let inj_sub = format!("$(touch {})", sentinel.display());
    let inj_bt = "`touch INJECTED`";
    let proj = env.project(
        "alice",
        "proj",
        &[
            ("-d/src/lib.rs", "pub fn f() {}\n"),
            ("+x/a.txt", "x\n"),
            ("-m/b.txt", "m\n"),
            ("=true/c.txt", "eq\n"),
            (&format!("{inj_sub}/d.txt"), "sub\n"),
            (&format!("{inj_bt}/e.txt"), "bt\n"),
            ("sub/deep/here.txt", "here\n"),
        ],
    );
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "main"]);

    // (1) Leading `-` (`-d/src`), `+x` then `-m` (must not set `-m` message),
    // `=true` (must be quoted for zsh), and shell command-substitution names.
    let shut_cmd = "mkdir -- -shut && echo stray > -shut/f && chmod 000 -- -shut";
    let out = env.vl(
        "alice",
        &proj,
        &[
            "ws",
            "exec",
            "agent",
            "--only",
            "./-d/src",
            "+x",
            "./-m",
            "=true",
            &inj_sub,
            inj_bt,
            "--",
            "sh",
            "-c",
            shut_cmd,
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));

    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--", "true"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    let chmod_cmd = extract_between(&t, "Make the directory listable (`", "`) and run `");
    let vl_cmd = extract_between(&t, "`) and run `", "`, which removes");
    assert!(vl_cmd.contains("'='") || vl_cmd.contains("'=true'"), "=true must be quoted for zsh: {vl_cmd}");
    run_chmod_as_written(&proj, chmod_cmd);
    let out = run_as_written(&env, &proj, vl_cmd);
    let rt = text(&out);
    assert_eq!(out.status.code(), Some(0), "{vl_cmd}\n{rt}");
    assert!(rt.contains("(removed from the sandbox): -shut/f"), "{rt}");
    assert!(!sentinel.exists() && !proj.join("INJECTED").exists(), "shell syntax injected!");

    // (2) Invoked from a subdirectory (`sub/deep`), from inside the `--only`
    // directory itself (`-d/src`), and from outside the repository (`-R`).
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "./-d/src", "--", "sh", "-c", shut_cmd]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));

    for (cwd, extra_args) in [
        (proj.join("sub/deep"), &[][..]),
        (proj.join("-d/src"), &[][..]),
        (env.root.clone(), &["-R", proj.to_str().unwrap()][..]),
    ] {
        let mut args: Vec<&str> = extra_args.to_vec();
        args.extend_from_slice(&["ws", "exec", "agent", "--", "true"]);
        let out = env.vl("alice", &cwd, &args);
        let t = text(&out);
        assert_eq!(out.status.code(), Some(1), "cwd={}: {t}", cwd.display());
        let chmod_cmd = extract_between(&t, "Make the directory listable (`", "`) and run `");
        let vl_cmd = extract_between(&t, "`) and run `", "`, which removes");
        run_chmod_as_written(&cwd, chmod_cmd);
        let out = run_as_written(&env, &cwd, vl_cmd);
        assert_eq!(out.status.code(), Some(0), "cwd={}, cmd={vl_cmd}:\n{}", cwd.display(), text(&out));
        // Re-shut for the next `cwd` case.
        let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "./-d/src", "--", "sh", "-c", shut_cmd]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    }
    // Clean up `agent`.
    chmod(&files_dir(&proj, "agent").join("-shut"), 0o700);
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "./-d/src", "--", "true"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));

    // (3) Workspace names starting with `-`: `-`, `-agent`, and `--ephemeral`
    // (must never inject `--ephemeral` or flags).
    for ws in ["-", "-agent", "--ephemeral"] {
        env.ok("alice", &proj, &["ws", "new", "-r", "main", "--", ws]);
        let ws_flag = format!("--workspace={ws}");
        let out = env.vl("alice", &proj, &["ws", "exec", &ws_flag, "--only", "./-d/src", "--", "sh", "-c", shut_cmd]);
        assert_eq!(out.status.code(), Some(0), "ws={ws}: {}", text(&out));

        let out = env.vl("alice", &proj, &["ws", "exec", &ws_flag, "--", "true"]);
        let t = text(&out);
        assert_eq!(out.status.code(), Some(1), "ws={ws}: {t}");
        let chmod_cmd = extract_between(&t, "Make the directory listable (`", "`) and run `");
        let vl_cmd = extract_between(&t, "`) and run `", "`, which removes");
        run_chmod_as_written(&proj, chmod_cmd);
        let out = run_as_written(&env, &proj, vl_cmd);
        let rt = text(&out);
        assert_eq!(out.status.code(), Some(0), "ws={ws}, cmd={vl_cmd}:\n{rt}");
        assert!(rt.contains("(removed from the sandbox): -shut/f"), "ws={ws}: {rt}");
    }
}

/// BUG-2652: when the shut directory or an `--only` path holds control or
/// bidirectional characters (which `safe()` escapes), no runnable command
/// naming a wrong path is printed, and raw control/bidi bytes never reach
/// stderr; the message explains why instead.
#[test]
fn bug_2652_control_or_bidi_characters_never_print_a_wrong_command_to_paste() {
    let env = Env::new();
    let tab_dir = "x\ty";
    let bidi_dir = "rtl\u{202e}txt";
    let proj = env.project(
        "alice",
        "proj",
        &[
            (&format!("{tab_dir}/src/lib.rs"), "pub fn f() {}\n"),
            (&format!("{bidi_dir}/lib.rs"), "pub fn g() {}\n"),
            ("plain/lib.rs", "pub fn h() {}\n"),
        ],
    );
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "main"]);
    let dir = files_dir(&proj, "agent");

    // Case A: `--only` path contains a tab (`\t`), shut directory is plain.
    let tab_only = format!("{tab_dir}/src");
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", &tab_only, "--", "sh", "-c", "mkdir shut && chmod 000 shut"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--", "true"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(!t.contains('\t'), "raw tab leaked to stderr: {t:?}");
    assert!(t.contains(r"x\ty/src"), "escaped path missing: {t}");
    assert!(!t.contains("chmod u+rwx "), "printed a runnable chmod command alongside escaped path: {t}");
    assert!(!t.contains("-- true`"), "printed a runnable vl ws exec command naming escaped path: {t}");
    assert!(t.contains("control") || t.contains("escaped"), "did not explain why no command is printed: {t}");
    chmod(&dir.join("shut"), 0o700);
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", &tab_only, "--", "true"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));

    // Case B: shut directory itself contains a bidi override (`\u{202e}`).
    let cmd = format!("mkdir '{bidi_dir}_shut' && chmod 000 '{bidi_dir}_shut'");
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "plain", "--", "sh", "-c", &cmd]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--", "true"]);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(!t.contains('\u{202e}'), "raw bidi char leaked to stderr: {t:?}");
    assert!(t.contains(r"\u{202e}"), "escaped bidi char missing: {t}");
    assert!(!t.contains("chmod u+rwx "), "printed a runnable chmod naming escaped dir: {t}");
    assert!(!t.contains("-- true`"), "printed a runnable vl ws exec alongside escaped dir: {t}");
    chmod(&dir.join(format!("{bidi_dir}_shut")), 0o700);
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--only", "plain", "--", "true"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
}

#[cfg(target_os = "linux")]
#[test]
fn bug_2650_exec_beside_a_large_sealed_file_keeps_memory_bounded_and_quarantines_copies() {
    let env = Env::new();
    let proj = env.dir("proj");
    write(&proj, "README.md", "hello\n");
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let mut plan = String::with_capacity(4 << 20);
    while plan.len() < (4 << 20) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        plan.push_str(&format!("{x:016x}"));
    }
    write(&proj, "internal/.env.plan", &plan);
    drop(plan);
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["cloak", "internal/.env.plan"]);
    env.ok("alice", &proj, &["commit", "-m", "initial"]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "@-"]);

    // First run materialises the sandbox; second run edits README.md beside the
    // 4 MiB sealed file. Measure the second run's whole-tree ru_maxrss (before
    // BUG-2650's fix: > 900 MiB).
    exec(&env, &proj, &["--", "true"]);
    let child = env
        .cmd("alice", &proj, &["ws", "exec", "agent", "--", "sh", "-c", "echo edited > README.md"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut status: libc::c_int = 0;
    let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
    let waited = unsafe { libc::wait4(child.id() as libc::pid_t, &mut status, 0, &mut rusage) };
    assert_eq!(waited, child.id() as libc::pid_t);
    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "status={status}");
    let peak_mib = rusage.ru_maxrss / 1024;
    assert!(
        peak_mib < 192,
        "vl ws exec beside a 4 MiB sealed file used {peak_mib} MiB peak RSS"
    );
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "README.md"]), "edited\n");

    // Copying the 4 MiB sealed secret into a plain file is still quarantined
    // and scrubbed out of the sandbox.
    let leak = env.vl("alice", &proj, &["ws", "exec", "agent", "--", "sh", "-c", "cp internal/.env.plan leak.txt"]);
    let leak_out = text(&leak);
    assert!(leak.status.success(), "{leak_out}");
    assert!(leak_out.contains("leak.txt quarantined") && leak_out.contains("cleaned leak.txt"), "{leak_out}");
    assert!(!paths(&env, &proj, "agent@").iter().any(|p| p == "leak.txt"));
    assert!(!files_dir(&proj, "agent").join("leak.txt").exists());

    // Above MAX_GUARD_BYTES (16 MiB), both persistent and ephemeral `vl ws exec`
    // fail closed before running the command rather than skipping or weakening
    // the guard.
    let big = "a".repeat((16 << 20) + 1024);
    write(&proj, "internal/.env.plan", &big);
    drop(big);
    env.ok("alice", &proj, &["commit", "-m", "oversize"]);
    env.ok("alice", &proj, &["ws", "new", "over", "-r", "@-"]);
    let marker = proj.join(".scratch-ran");
    let run_cmd = format!("touch '{}'", marker.display());
    for args in [
        vec!["ws", "exec", "over", "--", "sh", "-c", run_cmd.as_str()],
        vec!["ws", "exec", "--ephemeral", "-r", "@-", "--", "sh", "-c", run_cmd.as_str()],
    ] {
        let out = env.vl("alice", &proj, &args);
        let t = text(&out);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {t}");
        assert!(t.contains("16 MiB limit") && t.contains("internal/.env.plan"), "{args:?}: {t}");
        assert!(!marker.exists(), "command ran despite oversized guard: {args:?}");
    }
}
