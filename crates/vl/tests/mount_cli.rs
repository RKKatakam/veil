//! `vl ws mount` with the real kernel: reads, writes, creates, deletes,
//! renames, the executable bit, cloaked files for a member and a non-member,
//! recording on unmount and before other commands, the workspace moving
//! under the mount, crash recovery, and the refusals.
//!
//! Every test is skipped (and says so) where FUSE cannot be used: no
//! `/dev/fuse`, no `fusermount3`/`fusermount`, or a `vl` built without the
//! `fuse` feature. CI does not need FUSE.

mod adversarial_support;

use std::{
    io::Write as _,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use adversarial_support::*;

fn fuse_available() -> bool {
    let dev = std::fs::OpenOptions::new().read(true).write(true).open("/dev/fuse").is_ok();
    let tool = ["fusermount3", "fusermount"]
        .iter()
        .any(|b| Command::new(b).arg("-V").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok());
    if !(dev && tool && cfg!(target_os = "linux") && cfg!(feature = "fuse")) {
        eprintln!("skipping: FUSE is not available here (/dev/fuse, fusermount3 and a vl built with the `fuse` feature are needed)");
        return false;
    }
    true
}

/// Unmounts (lazily) on drop, so a failing test leaves no mount behind.
struct Mounted(PathBuf);

impl Drop for Mounted {
    fn drop(&mut self) {
        for b in ["fusermount3", "fusermount"] {
            if Command::new(b).args(["-u", "-z", "-q"]).arg(&self.0).stderr(Stdio::null()).status().is_ok() {
                break;
            }
        }
    }
}

fn is_mounted(dir: &Path) -> bool {
    let info = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    info.lines().any(|l| l.split(' ').nth(4) == Some(dir.to_str().unwrap()))
}

fn mount(env: &Env, user: &str, proj: &Path, ws: &str) -> (PathBuf, Mounted) {
    let mnt = env.root.join(format!("mnt-{user}-{ws}"));
    let out = env.ok(user, proj, &["ws", "mount", ws, mnt.to_str().unwrap()]);
    assert!(out.contains("Mounted workspace"), "{out}");
    assert!(is_mounted(&mnt), "not mounted: {out}");
    (mnt.clone(), Mounted(mnt))
}

fn ws_write(env: &Env, user: &str, proj: &Path, args: &[&str], data: &str) -> String {
    let mut c = env.cmd(user, proj, args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    c.stdin.take().unwrap().write_all(data.as_bytes()).unwrap();
    let o = c.wait_with_output().unwrap();
    assert!(o.status.success(), "{}", text(&o));
    text(&o)
}

fn files(env: &Env, user: &str, proj: &Path, rev: &str) -> Vec<String> {
    env.stdout(user, proj, &["files", "-r", rev])
        .lines()
        .filter_map(|l| l.split_whitespace().rfind(|t| *t != "*").map(str::to_string))
        .collect()
}

fn project(env: &Env) -> PathBuf {
    let proj = env.project("alice", "proj", &[("a.txt", "a\n"), ("src/lib.rs", "pub fn f() {}\n"), ("gone.txt", "g\n")]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "main"]);
    proj
}

fn state_pid(proj: &Path, ws: &str) -> i32 {
    let st: serde_json::Value =
        serde_json::from_slice(&std::fs::read(proj.join(".veil/local/mounts").join(ws).join("state.json")).unwrap()).unwrap();
    st["pid"].as_i64().unwrap() as i32
}

#[test]
fn reads_writes_and_unmount_records_through_the_policy() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let proj = project(&env);
    let (mnt, _guard) = mount(&env, "alice", &proj, "agent");

    // Reads.
    assert_eq!(read(&mnt, "a.txt"), "a\n");
    assert_eq!(read(&mnt, "src/lib.rs"), "pub fn f() {}\n");
    // Write, create, delete, rename, mkdir, chmod +x, truncate.
    std::fs::write(mnt.join("a.txt"), "edited\n").unwrap();
    std::fs::write(mnt.join("new.txt"), "new\n").unwrap();
    std::fs::remove_file(mnt.join("gone.txt")).unwrap();
    std::fs::rename(mnt.join("src"), mnt.join("lib")).unwrap();
    std::fs::create_dir_all(mnt.join("deep/er")).unwrap();
    std::fs::write(mnt.join("deep/er/x.txt"), "x\n").unwrap();
    std::fs::write(mnt.join("run.sh"), "#!/bin/sh\necho ran-in-mount\n").unwrap();
    std::fs::set_permissions(mnt.join("run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = Command::new(mnt.join("run.sh")).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ran-in-mount\n");
    let f = std::fs::OpenOptions::new().write(true).open(mnt.join("new.txt")).unwrap();
    f.set_len(2).unwrap();
    drop(f);
    // Isolated and quarantined files stay local.
    std::fs::write(mnt.join(".env"), "API_TOKEN=isolated-value-9f8e7d6c\n").unwrap();
    std::fs::write(mnt.join("leak.txt"), "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n").unwrap();
    // Private to the owner.
    assert_eq!(std::fs::metadata(&mnt).unwrap().permissions().mode() & 0o077, 0);
    assert_eq!(std::fs::metadata(mnt.join("a.txt")).unwrap().permissions().mode() & 0o777, 0o600);
    // No `.veil` can be made in the mount.
    assert!(std::fs::create_dir(mnt.join(".veil")).is_err());
    // Symlinks are refused (Veil records none).
    assert!(std::os::unix::fs::symlink("a.txt", mnt.join("link")).is_err());

    // Another command records the mount first.
    let diff = env.ok("alice", &proj, &["diff", "-r", "agent@", "--stat"]);
    assert!(diff.contains("a.txt") && diff.contains("lib/lib.rs") && diff.contains("gone.txt"), "{diff}");
    assert!(diff.contains(".env is isolated") && diff.contains("leak.txt quarantined"), "{diff}");

    let out = env.ok("alice", &proj, &["ws", "unmount", "agent"]);
    assert!(out.contains("Unmounted workspace agent"), "{out}");
    assert!(!is_mounted(&mnt));
    let recorded = files(&env, "alice", &proj, "agent@");
    for p in ["a.txt", "new.txt", "lib/lib.rs", "deep/er/x.txt", "run.sh"] {
        assert!(recorded.contains(&p.to_string()), "{p} missing from {recorded:?}");
    }
    for p in ["gone.txt", "src/lib.rs", ".env", "leak.txt"] {
        assert!(!recorded.contains(&p.to_string()), "{p} in {recorded:?}");
    }
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "a.txt"]), "edited\n");
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "new.txt"]), "ne");
    assert!(env.stdout("alice", &proj, &["files", "-r", "agent@"]).lines().any(|l| l.ends_with("run.sh *")), "exec bit lost");
    // What was not recorded is kept for the next mount, and only there.
    assert!(out.contains("kept 2 file(s)"), "{out}");
    let (mnt, _guard2) = mount(&env, "alice", &proj, "agent");
    assert_eq!(read(&mnt, ".env"), "API_TOKEN=isolated-value-9f8e7d6c\n");
    assert!(mnt.join("leak.txt").exists());
    assert!(!proj.join(".env").exists() && !proj.join("leak.txt").exists());
    env.ok("alice", &proj, &["ws", "unmount", "agent"]);
    // `vl ws rm` wants --force for them.
    let o = env.vl("alice", &proj, &["ws", "rm", "agent"]);
    assert!(!o.status.success() && text(&o).contains("--force"), "{}", text(&o));
    env.ok("alice", &proj, &["ws", "rm", "--force", "agent"]);
    assert!(!proj.join(".veil/local/mounts/agent").exists());
}

#[test]
fn the_mount_follows_the_workspace_and_keeps_conflicting_edits() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let proj = project(&env);
    let (mnt, _guard) = mount(&env, "alice", &proj, "agent");
    // `vl ws write` while mounted: the mount shows it within a second.
    ws_write(&env, "alice", &proj, &["ws", "write", "agent", "other.txt"], "from ws write\n");
    assert!(wait_for(Duration::from_secs(10), || std::fs::read_to_string(mnt.join("other.txt")).is_ok_and(|s| s == "from ws write\n")));

    // Both sides change a.txt without recording in between: the mount's
    // version is saved as a change of its own, nothing is lost.
    std::fs::write(mnt.join("a.txt"), "mount side\n").unwrap();
    std::fs::write(mnt.join("untouched.txt"), "kept\n").unwrap();
    ws_write(&env, "alice", &proj, &["--no-snapshot", "ws", "write", "agent", "a.txt"], "other side\n");
    assert!(wait_for(Duration::from_secs(10), || read(&mnt, "a.txt") == "other side\n"), "{}", read(&mnt, "a.txt"));
    assert_eq!(read(&mnt, "untouched.txt"), "kept\n", "edits elsewhere stay");
    let log_path = proj.join(".veil/local/mounts/agent/log");
    assert!(wait_for(Duration::from_secs(10), || std::fs::read_to_string(&log_path).unwrap().contains("saved as change")));
    let log = std::fs::read_to_string(&log_path).unwrap();
    let change = log
        .split("saved as change ")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .unwrap_or_else(|| panic!("no saved change in the log:\n{log}"));
    assert_eq!(env.stdout("alice", &proj, &["cat", "a.txt", "-r", change]), "mount side\n");

    // A commit in the workspace from elsewhere: the mount follows it.
    env.ok("alice", &proj, &["describe", "-r", "agent@", "-m", "agent work"]);
    std::fs::write(mnt.join("later.txt"), "later\n").unwrap();
    env.ok("alice", &proj, &["ws", "unmount", "agent"]);
    let recorded = files(&env, "alice", &proj, "agent@");
    assert!(recorded.contains(&"later.txt".into()) && recorded.contains(&"untouched.txt".into()), "{recorded:?}");
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "a.txt"]), "other side\n");
}

#[test]
fn a_killed_mount_loses_nothing() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let proj = project(&env);
    let (mnt, _guard) = mount(&env, "alice", &proj, "agent");
    std::fs::write(mnt.join("crash.txt"), "survives\n").unwrap();
    std::fs::remove_file(mnt.join("gone.txt")).unwrap();
    std::fs::write(mnt.join(".env"), "TOKEN=local-only-abcdef123456\n").unwrap();
    // SAFETY: plain kill(2).
    unsafe { libc::kill(state_pid(&proj, "agent"), libc::SIGKILL) };
    assert!(wait_for(Duration::from_secs(5), || std::fs::read_dir(&mnt).is_err()), "the dead mount still answers");
    let doctor = text(&env.vl("alice", &proj, &["doctor"]));
    assert!(doctor.contains("lost its process"), "{doctor}");
    // A switch to it is refused while the dead mount is not cleaned up.
    let o = env.vl("alice", &proj, &["ws", "switch", "agent"]);
    assert!(!o.status.success(), "{}", text(&o));

    let out = env.ok("alice", &proj, &["ws", "unmount", "agent"]);
    assert!(out.contains("Recovered the mount"), "{out}");
    assert!(!is_mounted(&mnt));
    let recorded = files(&env, "alice", &proj, "agent@");
    assert!(recorded.contains(&"crash.txt".into()) && !recorded.contains(&"gone.txt".into()), "{recorded:?}");
    assert!(!recorded.contains(&".env".into()));
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "crash.txt"]), "survives\n");

    // Killed again, and mounted again without an unmount in between: the
    // new mount picks the overlay up.
    let (mnt, _g2) = mount(&env, "alice", &proj, "agent");
    assert_eq!(read(&mnt, ".env"), "TOKEN=local-only-abcdef123456\n");
    std::fs::write(mnt.join("second.txt"), "2\n").unwrap();
    unsafe { libc::kill(state_pid(&proj, "agent"), libc::SIGKILL) };
    assert!(wait_for(Duration::from_secs(5), || std::fs::read_dir(&mnt).is_err()));
    let (mnt, _g3) = mount(&env, "alice", &proj, "agent");
    assert_eq!(read(&mnt, "second.txt"), "2\n");
    env.ok("alice", &proj, &["ws", "unmount", "agent"]);
    assert!(files(&env, "alice", &proj, "agent@").contains(&"second.txt".into()));
}

#[test]
fn cloaked_files_as_a_member_and_as_a_non_member() {
    if !fuse_available() {
        return;
    }
    const CLOAKED: &str = "CLOAKED-PLAN-71c3";
    const EMBARGOED: &str = "EMBARGOED-FIX-55e1";
    let env = Env::new();
    let alice = env.dir("alice");
    write(&alice, "README.md", "hello\n");
    write(&alice, "internal/plan.md", &format!("{CLOAKED}\n"));
    env.ok("alice", &alice, &["init"]);
    env.ok("alice", &alice, &["cloak", "internal/"]);
    env.ok("alice", &alice, &["commit", "-m", "initial"]);
    env.ok("alice", &alice, &["tag", "set", "main", "-r", "@-"]);
    // An ordinary line next to it (its own snapshot, so the embargoed
    // merge below does not move it).
    write(&alice, "other.txt", "o\n");
    env.ok("alice", &alice, &["commit", "--no-advance", "-m", "other"]);
    env.ok("alice", &alice, &["tag", "set", "base1", "-r", "@-"]);
    // An embargoed fix of README.md on main: readers without the key see
    // the previous version.
    env.ok("alice", &alice, &["ws", "new", "fix", "-r", "main"]);
    ws_write(&env, "alice", &alice, &["ws", "write", "fix", "README.md"], &format!("hello\n{EMBARGOED}\n"));
    env.ok("alice", &alice, &["describe", "-r", "fix@", "-m", "fix"]);
    env.ok("alice", &alice, &["merge", "fix@", "--into", "main", "--embargo", "-m", "embargoed merge"]);
    let team = env.root.join("team");
    env.ok("alice", &alice, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &alice, &["push"]);
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    let bob = env.root.join("bob");

    // Alice (a member, holding the embargo key) sees both.
    env.ok("alice", &alice, &["ws", "new", "view", "-r", "main"]);
    let (am, _ga) = mount(&env, "alice", &alice, "view");
    assert_eq!(read(&am, "internal/plan.md"), format!("{CLOAKED}\n"));
    assert!(read(&am, "README.md").contains(EMBARGOED));
    // An edit of a cloaked file is recorded sealed.
    std::fs::write(am.join("internal/plan.md"), format!("{CLOAKED} v2\n")).unwrap();
    env.ok("alice", &alice, &["ws", "unmount", "view"]);
    let ls = env.stdout("alice", &alice, &["ls", "-r", "view@"]);
    assert!(ls.lines().any(|l| l.contains("internal/plan.md") && l.starts_with("cloaked:team")), "{ls}");

    // Bob (no key) sees what his checkout shows: no internal/, the
    // pre-embargo README.md, and no plaintext anywhere.
    env.ok("bob", &bob, &["ws", "new", "view", "-r", "main"]);
    let (bm, _gb) = mount(&env, "bob", &bob, "view");
    assert_eq!(read(&bm, "README.md"), "hello\n");
    assert_eq!(std::fs::metadata(bm.join("README.md")).unwrap().len(), 6, "the fallback's size");
    assert!(!bm.join("internal").exists(), "a directory holding only unreadable files shows");
    assert!(!bm.join("internal/plan.md").exists());
    assert!(std::fs::read(bm.join("internal/plan.md")).is_err());
    let mut seen = String::new();
    for e in walk(&bm) {
        seen.push_str(&e.display().to_string());
        seen.push_str(&String::from_utf8_lossy(&std::fs::read(&e).unwrap()));
    }
    assert!(!seen.contains(CLOAKED) && !seen.contains(EMBARGOED), "{seen}");
    // On the embargoed line Bob's edit is held back (as `vl ws write`
    // holds it back): it stays in the mount, unrecorded.
    std::fs::write(bm.join("notes.txt"), "bob\n").unwrap();
    let out = env.ok("bob", &bob, &["ws", "unmount", "view"]);
    assert!(out.contains("notes.txt held back") && out.contains("kept 1 file(s)"), "{out}");
    assert!(!files(&env, "bob", &bob, "view@").contains(&"notes.txt".into()));
    // Next to the hidden file on an ordinary line it is recorded, and the
    // hidden file is carried, not deleted.
    env.ok("bob", &bob, &["ws", "new", "work", "-r", "base1"]);
    let (bm, _gw) = mount(&env, "bob", &bob, "work");
    assert!(!bm.join("internal").exists());
    std::fs::write(bm.join("notes.txt"), "bob\n").unwrap();
    let out = env.ok("bob", &bob, &["ws", "unmount", "work"]);
    let ls = env.stdout("bob", &bob, &["ls", "-r", "work@"]);
    assert!(ls.contains("notes.txt") && ls.contains("internal/plan.md"), "{out}\n{ls}");
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

#[test]
fn foreground_mounts_unmount_on_a_signal_and_from_outside() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let proj = project(&env);
    let mnt = env.root.join("fg");
    let mut child = env.spawn("alice", &proj, &["ws", "mount", "--foreground", "agent", mnt.to_str().unwrap()]);
    let _guard = Mounted(mnt.clone());
    assert!(wait_for(Duration::from_secs(10), || is_mounted(&mnt)));
    std::fs::write(mnt.join("fg.txt"), "fg\n").unwrap();
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let status = child.wait().unwrap();
    assert!(status.success() && !is_mounted(&mnt), "{status:?}");
    assert!(files(&env, "alice", &proj, "agent@").contains(&"fg.txt".into()));

    // Unmounted by `fusermount -u`: still recorded.
    let (mnt, _g2) = mount(&env, "alice", &proj, "agent");
    std::fs::write(mnt.join("outside.txt"), "o\n").unwrap();
    let ok = ["fusermount3", "fusermount"].iter().any(|b| Command::new(b).arg("-u").arg(&mnt).status().is_ok_and(|s| s.success()));
    assert!(ok);
    assert!(wait_for(Duration::from_secs(10), || !proj.join(".veil/local/mounts/agent").exists()));
    assert!(files(&env, "alice", &proj, "agent@").contains(&"outside.txt".into()));
}

#[test]
fn refusals() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let proj = project(&env);
    let fails = |args: &[&str], what: &str| {
        let o = env.vl("alice", &proj, args);
        assert!(!o.status.success() && text(&o).contains(what), "vl {args:?}: {}", text(&o));
    };
    let outside = env.root.join("m");
    fails(&["ws", "mount", "default", outside.to_str().unwrap()], "attached to the project directory");
    fails(&["ws", "mount", "agent", proj.join("inside").to_str().unwrap()], "inside the project directory");
    fails(&["ws", "mount", "nope", outside.to_str().unwrap()], "nope");
    std::fs::create_dir_all(env.root.join("full")).unwrap();
    write(&env.root.join("full"), "f", "x");
    fails(&["ws", "mount", "agent", env.root.join("full").to_str().unwrap()], "not empty");
    fails(&["ws", "unmount", "agent"], "not mounted");
    let (mnt, _guard) = mount(&env, "alice", &proj, "agent");
    fails(&["ws", "mount", "agent", env.root.join("m2").to_str().unwrap()], "already mounted");
    fails(&["ws", "switch", "agent"], "is mounted at");
    fails(&["ws", "rm", "agent"], "is mounted at");
    // A busy mount is not unmounted (and its edits are recorded anyway).
    std::fs::write(mnt.join("busy.txt"), "b\n").unwrap();
    let busy = std::fs::File::open(mnt.join("busy.txt")).unwrap();
    let o = env.vl("alice", &proj, &["ws", "unmount", "agent"]);
    assert!(!o.status.success() && text(&o).contains("busy"), "{}", text(&o));
    assert!(is_mounted(&mnt));
    assert!(files(&env, "alice", &proj, "agent@").contains(&"busy.txt".into()));
    drop(busy);
    env.ok("alice", &proj, &["ws", "unmount", "agent"]);
    assert!(!is_mounted(&mnt));
}

/// A file the mount holds a quarantined (never recorded) version of, changed
/// in the workspace by another command: the mount's version is not in the
/// saved change, so it must stay in the mount, not be dropped.
#[test]
fn a_quarantined_edit_survives_the_workspace_moving() {
    if !fuse_available() {
        return;
    }
    const LEAK: &str = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";
    let env = Env::new();
    let proj = project(&env);
    let (mnt, _guard) = mount(&env, "alice", &proj, "agent");
    std::fs::write(mnt.join("a.txt"), LEAK).unwrap();
    std::fs::write(mnt.join("b.txt"), "plain edit\n").unwrap();
    ws_write(&env, "alice", &proj, &["--no-snapshot", "ws", "write", "agent", "a.txt"], "theirs\n");
    ws_write(&env, "alice", &proj, &["--no-snapshot", "ws", "write", "agent", "b.txt"], "theirs too\n");
    let log_path = proj.join(".veil/local/mounts/agent/log");
    assert!(
        wait_for(Duration::from_secs(10), || std::fs::read_to_string(&log_path).unwrap().contains("keeps showing its own")),
        "{}",
        std::fs::read_to_string(&log_path).unwrap()
    );
    assert_eq!(read(&mnt, "a.txt"), LEAK, "the quarantined version was dropped");
    assert!(wait_for(Duration::from_secs(10), || read(&mnt, "b.txt") == "theirs too\n"));
    env.ok("alice", &proj, &["ws", "unmount", "agent"]);
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "a.txt"]), "theirs\n");
    // Never recorded anywhere.
    let all = env.stdout("alice", &proj, &["log", "-n", "50"]);
    assert!(!all.contains("wJalrXUtnFEMI"), "{all}");
    let upper = proj.join(".veil/local/mounts/agent/upper/a.txt");
    assert_eq!(std::fs::read_to_string(upper).unwrap(), LEAK, "kept for the next mount");
}
