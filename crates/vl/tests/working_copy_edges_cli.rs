//! End-to-end checks for the working copy and the `ws exec` sandbox: undo
//! with uncommitted edits, symlinks in the way of a checkout, unreadable
//! files, and sandbox hygiene (private, swept after crashes, nothing
//! laundered into history, stdout left to the command).

mod adversarial_support;

use adversarial_support::*;

fn is_root() -> bool {
    std::process::Command::new("id").arg("-u").output().map(|o| o.stdout.starts_with(b"0\n")).unwrap_or(false)
}

// ---- undo ------------------------------------------------------------------

#[test]
fn undo_reverts_the_command_not_the_edits() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a1\n")]);
    // a command that changes files: commit an edit, then move back to the
    // initial commit (`commit` advances `main`, hence `@--`)
    write(&proj, "a.txt", "a2\n");
    env.ok("alice", &proj, &["commit", "-m", "a2"]);
    env.ok("alice", &proj, &["new", "@--"]);
    assert_eq!(read(&proj, "a.txt"), "a1\n");
    // edits, recorded by an unrelated command *and* by `undo` itself
    write(&proj, "wip.txt", "work\n");
    env.ok("alice", &proj, &["status"]);
    write(&proj, "wip2.txt", "more work\n");
    let out = env.ok("alice", &proj, &["undo"]);
    assert!(out.contains("Undid: new change"), "{out}");
    assert_eq!(read(&proj, "a.txt"), "a2\n", "the undone `vl new` is reverted");
    assert_eq!(read(&proj, "wip.txt"), "work\n");
    assert_eq!(read(&proj, "wip2.txt"), "more work\n");
    let files = env.stdout("alice", &proj, &["files"]);
    assert!(files.contains("wip.txt") && files.contains("wip2.txt"), "{files}");
}

#[test]
fn op_restore_keeps_edits() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    let ops = env.stdout("alice", &proj, &["op", "log", "-n", "1"]);
    let id = ops.split_whitespace().next().unwrap().to_string();
    env.ok("alice", &proj, &["describe", "-m", "later"]);
    write(&proj, "wip.txt", "work\n");
    env.ok("alice", &proj, &["op", "restore", &id]);
    assert_eq!(read(&proj, "wip.txt"), "work\n");
}

// ---- symlinks -------------------------------------------------------------

#[test]
fn a_symlink_in_the_way_is_reported_and_not_recorded_as_a_deletion() {
    let env = Env::new();
    let shared = env.dir("shared-vendor");
    let alice = env.project("alice", "alice", &[("a.txt", "a\n")]);
    write(&alice, "vendor/postinstall.sh", "#!/bin/sh\n");
    env.ok("alice", &alice, &["commit", "-m", "add vendor"]);
    env.ok("alice", &alice, &["tag", "set", "main", "-r", "@-"]);
    let remote = env.dir("remote");
    env.ok("alice", &alice, &["remote", "add", "origin", remote.to_str().unwrap()]);
    env.ok("alice", &alice, &["push", "origin"]);

    let bob = env.project("bob", "bob", &[("b.txt", "b\n")]);
    std::os::unix::fs::symlink(&shared, bob.join("vendor")).unwrap();
    env.ok("bob", &bob, &["remote", "add", "origin", remote.to_str().unwrap()]);
    env.ok("bob", &bob, &["pull", "origin"]);
    let out = env.ok("bob", &bob, &["new", "origin/main"]);
    assert!(out.contains("skipped vendor/postinstall.sh"), "{out}");
    assert!(std::fs::read_dir(&shared).unwrap().next().is_none(), "wrote into the link target");
    let st = env.ok("bob", &bob, &["status"]);
    assert!(st.contains("symlink"), "{st}");
    let diff = env.stdout("bob", &bob, &["diff"]);
    assert!(!diff.contains("postinstall"), "recorded as a deletion:\n{diff}");
}

#[test]
fn restore_never_writes_through_a_symlink() {
    let env = Env::new();
    let shared = env.dir("shared");
    let proj = env.project("alice", "proj", &[("vendor/x", "v1\n")]);
    write(&proj, "vendor/x", "v2\n");
    env.ok("alice", &proj, &["commit", "-m", "v2"]);
    std::fs::remove_dir_all(proj.join("vendor")).unwrap();
    std::os::unix::fs::symlink(&shared, proj.join("vendor")).unwrap();
    let out = env.ok("alice", &proj, &["restore", "vendor", "--from", "@--"]);
    assert!(out.contains("skipped vendor/x"), "{out}");
    assert!(std::fs::read_dir(&shared).unwrap().next().is_none(), "restore wrote through the link");
}

// ---- unreadable files ---------------------------------------------------------

#[test]
fn an_unreadable_file_is_warned_about_and_keeps_its_recorded_version() {
    use std::os::unix::fs::PermissionsExt;
    if is_root() {
        return;
    }
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("data.bin", "v1\n")]);
    write(&proj, "data.bin", "v2\n");
    std::fs::set_permissions(proj.join("data.bin"), std::fs::Permissions::from_mode(0o000)).unwrap();
    let out = env.vl("alice", &proj, &["commit", "-m", "while locked"]);
    std::fs::set_permissions(proj.join("data.bin"), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("skipped data.bin: cannot read it"), "{}", text(&out));
    assert_eq!(env.stdout("alice", &proj, &["cat", "data.bin", "-r", "@-"]), "v1\n", "not recorded as deleted");
    env.ok("alice", &proj, &["commit", "-m", "readable again"]);
    assert_eq!(env.stdout("alice", &proj, &["cat", "data.bin", "-r", "@-"]), "v2\n");
}

// ---- ws exec sandbox -------------------------------------------------------------

fn sandbox_project(env: &Env) -> std::path::PathBuf {
    let proj = env.project("alice", "proj", &[("app.py", "print('hi')\n")]);
    write(&proj, ".env", "API_TOKEN=super-secret-isolated-value\nPORT=3000\n");
    env.ok("alice", &proj, &["commit", "-m", "with .env"]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "@-"]);
    proj
}

#[test]
fn ephemeral_exec_cannot_launder_isolated_secrets_either() {
    let env = Env::new();
    let proj = sandbox_project(&env);
    let o = env.vl(
        "alice",
        &proj,
        &["ws", "exec", "--ephemeral", "-r", "@-", "--with-isolated", "-m", "eph", "--", "sh", "-c", "grep TOKEN .env | cut -d= -f2 > leaked.txt; echo ok > fine.txt"],
    );
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("leaked.txt"), "a quarantine warning names the file: {}", text(&o));
    let all = text(&o);
    let rev = all
        .lines()
        .find_map(|l| l.strip_prefix("Recorded "))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("no Recorded line:\n{all}"))
        .to_string();
    assert_eq!(env.stdout("alice", &proj, &["cat", "fine.txt", "-r", &rev]), "ok\n");
    let files = env.stdout("alice", &proj, &["files", "-r", &rev]);
    assert!(!files.contains("leaked.txt"), "secret recorded:\n{files}");
}

#[test]
fn ws_exec_stdout_belongs_to_the_command() {
    let env = Env::new();
    let proj = sandbox_project(&env);
    let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--", "echo", "only this"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "only this\n");
}

#[test]
fn stale_sandboxes_of_dead_processes_are_swept() {
    let env = Env::new();
    let proj = sandbox_project(&env);
    let tmp = env.dir("tmp");
    // a pid that is certainly gone, and one that is certainly alive (ours)
    let mut child = std::process::Command::new("true").spawn().unwrap();
    let dead = child.id();
    child.wait().unwrap();
    let stale = tmp.join(format!("veil-ws-agent-{dead}-0badf00d"));
    let live = tmp.join(format!("veil-ws-agent-{}-0badf00d", std::process::id()));
    let unrelated = tmp.join(format!("other-{dead}"));
    for d in [&stale, &live, &unrelated] {
        write(d, ".env", "API_TOKEN=leftover\n");
    }
    env.ok("alice", &proj, &["ws", "exec", "agent", "--", "true"]);
    assert!(!stale.exists(), "stale sandbox with secrets left behind");
    assert!(live.exists(), "a live process's sandbox was removed");
    assert!(unrelated.exists(), "removed something that is not a sandbox");
}
