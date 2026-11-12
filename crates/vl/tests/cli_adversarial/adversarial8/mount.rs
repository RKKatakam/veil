//! `vl ws mount` / `vl ws unmount` (FUSE) with the real kernel. Every test
//! skips itself where FUSE is not available, mounts only under the test's
//! temporary directory (`$TMPDIR`), and unmounts on drop.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use super::{
    adversarial_support::{read, text, wait_for, write, Env},
    public_key, ws_write, U,
};

fn fuse_available() -> bool {
    let dev = std::fs::OpenOptions::new().read(true).write(true).open("/dev/fuse").is_ok();
    let tool = ["fusermount3", "fusermount"]
        .iter()
        .any(|b| Command::new(b).arg("-V").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok());
    if !(dev && tool && cfg!(target_os = "linux") && cfg!(feature = "fuse")) {
        eprintln!("skipping: FUSE is not available here");
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

/// Paths of revision `rev` (`vl files`).
fn files(env: &Env, user: &str, proj: &Path, rev: &str) -> Vec<String> {
    env.stdout(user, proj, &["files", "-r", rev])
        .lines()
        .filter_map(|l| l.split_whitespace().rfind(|t| *t != "*").map(str::to_string))
        .collect()
}


const CLOAKED: &str = "CLOAKED-PLAN-9d41";

/// Alice's project (`internal/.env.plan` cloaked for `team`) on a team
/// remote, cloned by Bob before he holds the key; Bob has workspace `work`
/// on `main`.
fn bob_without_the_key(env: &Env) -> (PathBuf, PathBuf) {
    let alice = env.dir("alice");
    write(&alice, "README.md", "hello\n");
    write(&alice, "internal/.env.plan", &format!("{CLOAKED}\n"));
    env.ok(U, &alice, &["init"]);
    env.ok(U, &alice, &["cloak", "internal/.env.plan"]);
    env.ok(U, &alice, &["commit", "-m", "initial"]);
    env.ok(U, &alice, &["tag", "set", "main", "-r", "@-"]);
    let team = env.root.join("team");
    env.ok(U, &alice, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok(U, &alice, &["push"]);
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    let bob = env.root.join("bob");
    env.ok("bob", &bob, &["ws", "new", "work", "-r", "main"]);
    (alice, bob)
}

// ---- readability changing under a live mount --------------------------------

/// Bob mounts a workspace while he cannot read `internal/.env.plan`, is then
/// granted the scope and pulls (the onboarding flow). A checkout fills the
/// file in; the mount keeps the reader view it started with, and its next
/// recording (of an unrelated edit) records the now-readable file it never
/// showed as **deleted**: the mount records without a materialisation
/// record, so the builder takes "readable and absent" for a deletion.
#[test]
fn a_grant_during_a_mount_never_deletes_the_files_it_never_showed() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let (alice, bob) = bob_without_the_key(&env);
    let (mnt, _g) = mount(&env, "bob", &bob, "work");
    assert!(!mnt.join("internal").exists());

    let key = public_key(&env, "bob");
    env.ok(U, &alice, &["scope", "grant", "team", &key, "--name", "bob"]);
    env.ok(U, &alice, &["push"]);
    env.ok("bob", &bob, &["pull"]);
    // An unrelated edit in the mount, then the recording.
    std::fs::write(mnt.join("notes.txt"), "bob\n").unwrap();
    let out = env.ok("bob", &bob, &["ws", "unmount", "work"]);
    let recorded = files(&env, "bob", &bob, "work@");
    assert!(recorded.contains(&"notes.txt".to_string()), "{out}");
    assert!(
        recorded.contains(&"internal/.env.plan".to_string()),
        "the mount recorded the cloaked file Bob was just granted as deleted:\n{out}\n{recorded:?}"
    );
}

/// Control: a checkout of the same flow (the project directory) keeps the
/// granted file.
#[test]
fn control_a_grant_in_the_project_directory_fills_the_file_in() {
    let env = Env::new();
    let (alice, bob) = bob_without_the_key(&env);
    let key = public_key(&env, "bob");
    env.ok(U, &alice, &["scope", "grant", "team", &key, "--name", "bob"]);
    env.ok(U, &alice, &["push"]);
    env.ok("bob", &bob, &["pull"]);
    assert_eq!(read(&bob, "internal/.env.plan"), format!("{CLOAKED}\n"));
    write(&bob, "notes.txt", "bob\n");
    env.ok("bob", &bob, &["status"]);
    assert!(files(&env, "bob", &bob, "@").contains(&"internal/.env.plan".to_string()));
}

fn state_pid(proj: &Path, ws: &str) -> i32 {
    let st: serde_json::Value =
        serde_json::from_slice(&std::fs::read(proj.join(".veil/local/mounts").join(ws).join("state.json")).unwrap()).unwrap();
    st["pid"].as_i64().unwrap() as i32
}

fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 only checks for existence.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// A project with `b.txt` and a workspace `agent` on `main`.
fn agent_project(env: &Env) -> PathBuf {
    let proj = env.project(U, "proj", &[("a.txt", "a\n"), ("b.txt", "line1\nline2\n")]);
    env.ok(U, &proj, &["ws", "new", "agent", "-r", "main"]);
    proj
}

// ---- the mount following the workspace ---------------------------------------

/// A file held open in the mount with writes not yet flushed (an editor or
/// agent between `write` and `close`) when another command changes it. Both
/// changed it since the last recording, so by the documented rule the
/// mount's version is saved as a change of its own and the mount shows the
/// workspace's. But the overlap check only looks at the upper layer on
/// disk, the dirty buffer is persisted afterwards (`switch_lower`), and the
/// mount's version silently shadows (then overwrites) the other command's
/// change.
/// (Control: holds today; the dirty buffer reaches the overlap check.)
#[test]
fn control_an_open_dirty_file_does_not_silently_overwrite_a_concurrent_change() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let proj = agent_project(&env);
    let (mnt, _g) = mount(&env, U, &proj, "agent");
    let mut f = std::fs::OpenOptions::new().write(true).open(mnt.join("b.txt")).unwrap();
    std::io::Write::write_all(&mut f, b"MOUNT").unwrap();
    // Another command rewrites b.txt (without asking the mount to record).
    let mut c = env.cmd(U, &proj, &["--no-snapshot", "ws", "write", "agent", "b.txt"]);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), b"THEIRS\n").unwrap();
    assert!(child.wait_with_output().unwrap().status.success());
    // Let the mount follow (it looks every second).
    std::thread::sleep(Duration::from_secs(3));
    drop(f);
    let log = std::fs::read_to_string(proj.join(".veil/local/mounts/agent/log")).unwrap_or_default();
    let out = env.ok(U, &proj, &["ws", "unmount", "agent"]);
    let now = env.stdout(U, &proj, &["ws", "cat", "agent", "b.txt"]);
    assert_eq!(
        now, "THEIRS\n",
        "the other command's change was silently overwritten by the mount's open file (no conflict saved):\nlog: {log}\n{out}"
    );
}

/// Control: the same edit, closed before the other command runs, is saved
/// as a change of its own and the workspace keeps the other change.
#[test]
fn control_a_closed_edit_overlapping_a_concurrent_change_is_saved() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let proj = agent_project(&env);
    let (mnt, _g) = mount(&env, U, &proj, "agent");
    std::fs::write(mnt.join("b.txt"), "MOUNT\n").unwrap();
    let mut c = env.cmd(U, &proj, &["--no-snapshot", "ws", "write", "agent", "b.txt"]);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), b"THEIRS\n").unwrap();
    assert!(child.wait_with_output().unwrap().status.success());
    let log_path = proj.join(".veil/local/mounts/agent/log");
    assert!(wait_for(Duration::from_secs(10), || std::fs::read_to_string(&log_path)
        .unwrap_or_default()
        .contains("was saved as change")));
    env.ok(U, &proj, &["ws", "unmount", "agent"]);
    assert_eq!(env.stdout(U, &proj, &["ws", "cat", "agent", "b.txt"]), "THEIRS\n");
}

// ---- denial of service --------------------------------------------------------

/// `truncate -s 1T` on a file in the mount (sparse files are ordinary:
/// databases, disk images, `fallocate`-style tools): `setattr` resizes the
/// in-memory buffer to the full size, the allocation fails and the serving
/// process aborts. The mount is gone (`ENOTCONN`), and every other file
/// open there loses what was written to it and not yet closed.
#[test]
fn a_huge_truncate_does_not_kill_the_mount() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let proj = agent_project(&env);
    let (mnt, _g) = mount(&env, U, &proj, "agent");
    let pid = state_pid(&proj, "agent");
    // An open file with unsaved work.
    let mut open = std::fs::OpenOptions::new().write(true).open(mnt.join("a.txt")).unwrap();
    std::io::Write::write_all(&mut open, b"unsaved work\n").unwrap();
    let big = std::fs::File::create(mnt.join("sparse.img")).unwrap();
    let r = big.set_len(1 << 40);
    drop(big);
    std::thread::sleep(Duration::from_millis(500));
    let alive_now = alive(pid);
    let close = std::io::Write::flush(&mut open).and_then(|_| open.sync_all());
    drop(open);
    assert!(alive_now, "the mount process died on a 1 TiB truncate (set_len: {r:?})");
    assert!(close.is_ok(), "{close:?}");
    env.ok(U, &proj, &["ws", "unmount", "agent"]);
}

/// The same through `pwrite` at a 1 TiB offset.
#[test]
fn a_write_at_a_huge_offset_does_not_kill_the_mount() {
    if !fuse_available() {
        return;
    }
    use std::os::unix::fs::FileExt;
    let env = Env::new();
    let proj = agent_project(&env);
    let (mnt, _g) = mount(&env, U, &proj, "agent");
    let pid = state_pid(&proj, "agent");
    let f = std::fs::File::create(mnt.join("sparse.bin")).unwrap();
    let r = f.write_at(b"x", 1 << 40);
    drop(f);
    std::thread::sleep(Duration::from_millis(500));
    assert!(alive(pid), "the mount process died on a write at 1 TiB ({r:?})");
    env.ok(U, &proj, &["ws", "unmount", "agent"]);
}

/// A kernel-reported memory figure of process `pid` (`VmHWM`: peak RSS;
/// `VmRSS`: now), in KiB.
fn vm_kib(pid: i32, field: &str) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    status
        .lines()
        .find_map(|l| l.strip_prefix(field))
        .and_then(|v| v.trim_start_matches(':').split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("no {field} in /proc/{pid}/status"))
}

/// BUG-561: a sparse file in the mount (a 2 GiB `truncate`, then a small
/// write near its end, through the same handle and through another one)
/// lives on disk, in the overlay's upper file: the serving process's
/// memory does not grow with it, and the file reads back as written.
#[test]
fn a_sparse_file_in_the_mount_costs_no_memory() {
    if !fuse_available() {
        return;
    }
    use std::os::unix::fs::FileExt;
    const SIZE: u64 = 2 << 30;
    let env = Env::new();
    let proj = agent_project(&env);
    let (mnt, _g) = mount(&env, U, &proj, "agent");
    let pid = state_pid(&proj, "agent");
    let before = vm_kib(pid, "VmRSS");
    // The kernel splits writes; the file system only ever sees small ones.
    let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(mnt.join("sparse.img")).unwrap();
    f.set_len(SIZE).unwrap();
    f.write_all_at(b"tail", SIZE - 4).unwrap();
    f.write_all_at(b"head", 0).unwrap();
    f.sync_all().unwrap();
    drop(f);
    let g = std::fs::OpenOptions::new().read(true).write(true).open(mnt.join("sparse.img")).unwrap();
    g.write_all_at(b"middle", SIZE / 2).unwrap();
    drop(g);
    // An existing file truncated by path, too.
    std::fs::OpenOptions::new().write(true).open(mnt.join("a.txt")).unwrap().set_len(SIZE).unwrap();
    let peak = vm_kib(pid, "VmHWM");
    let grown = peak.saturating_sub(before);
    let r = std::fs::File::open(mnt.join("sparse.img")).unwrap();
    assert_eq!(r.metadata().unwrap().len(), SIZE);
    let mut buf = [0u8; 6];
    r.read_exact_at(&mut buf[..4], 0).unwrap();
    assert_eq!(&buf[..4], b"head");
    r.read_exact_at(&mut buf, SIZE / 2).unwrap();
    assert_eq!(&buf, b"middle");
    r.read_exact_at(&mut buf[..4], SIZE - 4).unwrap();
    assert_eq!(&buf[..4], b"tail");
    r.read_exact_at(&mut buf[..4], 4096).unwrap();
    assert_eq!(&buf[..4], &[0; 4]);
    drop(r);
    assert!(grown < 256 * 1024, "the mount process grew by {grown} KiB (peak {peak} KiB, before {before} KiB) for sparse files");
    assert_eq!(std::fs::metadata(mnt.join("a.txt")).unwrap().len(), SIZE);
    // Not recorded: a 2 GiB object would be read into memory by the builder.
    std::fs::remove_file(mnt.join("sparse.img")).unwrap();
    std::fs::write(mnt.join("a.txt"), "a\n").unwrap();
    env.ok(U, &proj, &["ws", "unmount", "agent"]);
}

// ---- what a non-member can read -----------------------------------------------

/// A conflict whose "theirs" side is sealed for `team` (a secret file,
/// exposed with `--force` on the other side), published to a public remote
/// and mounted by Carol (no key): she must see the redacted materialisation
/// only, with a size that matches what a read returns.
#[test]
fn a_sealed_conflict_side_never_reaches_a_non_member_through_the_mount() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let proj = env.project(U, "proj", &[("README", "hi\n")]);
    write(&proj, ".env.app", "one\ntwo\nthree\n");
    env.ok(U, &proj, &["cloak", ".env.app"]);
    env.ok(U, &proj, &["commit", "-m", "sealed"]);
    env.ok(U, &proj, &["ws", "new", "sec", "-r", "main"]);
    ws_write(&env, &proj, "sec", ".env.app", "one\nSEALED-SIDE-0042\nthree\n");
    env.ok(U, &proj, &["expose", "--force", ".env.app"]);
    write(&proj, ".env.app", "one\nPUBLIC\nthree\n");
    env.ok(U, &proj, &["commit", "--no-advance", "-m", "public"]);
    env.ok(U, &proj, &["new", "@-", "sec@", "-m", "conflicted"]);
    env.ok(U, &proj, &["tag", "set", "conflicted", "-r", "@"]);
    let pubdir = env.root.join("pub");
    env.ok(U, &proj, &["remote", "add", "pub", pubdir.to_str().unwrap(), "--public"]);
    env.ok(U, &proj, &["push", "pub", "-t", "conflicted"]);
    env.ok("carol", &env.root, &["clone", pubdir.to_str().unwrap(), "carol"]);
    let carol = env.root.join("carol");
    env.ok("carol", &carol, &["ws", "new", "view", "-r", "conflicted"]);
    let (mnt, _g) = mount(&env, "carol", &carol, "view");
    let data = std::fs::read(mnt.join(".env.app")).unwrap();
    let shown = String::from_utf8_lossy(&data).into_owned();
    assert!(!shown.contains("SEALED-SIDE"), "{shown}");
    assert!(shown.contains("PUBLIC"), "{shown}");
    assert_eq!(std::fs::metadata(mnt.join(".env.app")).unwrap().len(), data.len() as u64, "{shown}");
    for (p, c) in super::walk(&mnt).iter().filter_map(|p| std::fs::read(mnt.join(p)).ok().map(|c| (p.clone(), c))) {
        assert!(!String::from_utf8_lossy(&c).contains("SEALED-SIDE"), "{p:?}");
    }
    env.ok("carol", &carol, &["ws", "unmount", "view"]);
}

// ---- where the mount may be ---------------------------------------------------

/// The mountpoint is refused inside the project directory ("every snapshot
/// would walk into the mount"), but not inside *another* Veil project.
/// That project's next command snapshots its directory, walks into the
/// mount and records the mounted workspace, cloaked plaintext included, as
/// its own public files; its next push publishes them.
#[test]
fn a_mount_inside_another_project_is_never_recorded_by_it() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let secret = env.dir("secret");
    write(&secret, "README.md", "hello\n");
    write(&secret, "internal/.env.plan", &format!("{CLOAKED}\n"));
    env.ok(U, &secret, &["init"]);
    env.ok(U, &secret, &["cloak", "internal/.env.plan"]);
    env.ok(U, &secret, &["commit", "-m", "initial"]);
    env.ok(U, &secret, &["ws", "new", "view", "-r", "@-"]);
    // An unrelated, public project of the same user.
    let oss = env.project(U, "oss", &[("lib.rs", "pub fn f() {}\n")]);
    let mnt = oss.join("scratch-mount");
    let out = env.vl(U, &secret, &["ws", "mount", "view", mnt.to_str().unwrap()]);
    let _g = Mounted(mnt.clone());
    // Refused: the correct outcome.
    assert!(!out.status.success() && text(&out).contains("is inside the Veil repository"), "{}", text(&out));
    env.ok(U, &oss, &["status"]);
    assert!(super::cat(&env, U, &oss, "@", "scratch-mount/internal/.env.plan").is_none(), "the public project recorded a file under the refused mount");
}

/// `readdir` answers by index into a listing recomputed for every request,
/// so a directory read while its entries are deleted skips entries (the
/// offsets shift under the reader). `std::fs::remove_dir_all` (cargo
/// clean, most Rust tools) deletes while it reads and fails with "Directory
/// not empty" on a directory of a few thousand files; a lazy delete loop
/// leaves a third of them (ext4 and tmpfs: none). Renaming while listing
/// can likewise visit an entry twice.
#[test]
fn deleting_while_listing_skips_nothing() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let proj = agent_project(&env);
    let (mnt, _g) = mount(&env, U, &proj, "agent");
    std::fs::create_dir(mnt.join("many")).unwrap();
    for i in 0..3000 {
        let f = format!("many/file-{i:05}.txt");
        std::fs::write(mnt.join(&f), "x").unwrap_or_else(|e| panic!("writing {f} through the mount: {e}"));
    }
    let r = std::fs::remove_dir_all(mnt.join("many"));
    // What is left, by name (BUG-1983: a failure on a loaded machine kept
    // no more than the summary).
    let left: Vec<String> = match std::fs::read_dir(mnt.join("many")) {
        Ok(d) => d.map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()).unwrap_or_else(|e| format!("<{e}>"))).collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => vec![format!("<listing failed: {e}>")],
    };
    env.ok(U, &proj, &["ws", "unmount", "agent"]);
    let shown: Vec<&String> = left.iter().take(20).collect();
    assert!(r.is_ok() && left.is_empty(), "remove_dir_all: {r:?}; {} entries left: {shown:?}", left.len());
}

/// `vl undo` while the mount holds new work: `Ctx::open` first has the
/// mount record it (the record-before-snapshot hook), as the operation
/// "snapshot working copy of 'agent'", and undo then undoes exactly that
/// operation. The agent's file vanishes from the mount and the workspace,
/// and the commit the user meant to undo stays. For the project directory
/// undo skips the automatic snapshot and keeps the edits (BUG-116).
#[test]
fn undo_never_throws_away_the_mounts_new_work() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let proj = agent_project(&env);
    let (mnt, _g) = mount(&env, U, &proj, "agent");
    write(&proj, "c.txt", "c\n");
    env.ok(U, &proj, &["commit", "-m", "project commit"]);
    std::fs::write(mnt.join("work.txt"), "agent work\n").unwrap();
    let out = env.ok(U, &proj, &["undo"]);
    std::thread::sleep(Duration::from_secs(3));
    let shown = std::fs::read_to_string(mnt.join("work.txt")).ok();
    env.ok(U, &proj, &["ws", "unmount", "agent"]);
    let kept = env.vl(U, &proj, &["ws", "cat", "agent", "work.txt"]);
    assert_eq!(shown.as_deref(), Some("agent work\n"), "the mount's work vanished: {out}");
    assert!(kept.status.success(), "{out}\n{}", text(&kept));
    assert!(!out.contains("snapshot working copy of 'agent'"), "{out}");
}

/// A crash of the mount process between the recording's transaction and
/// the durable write of the new `base` to `state.json` (simulated: the
/// process is killed after a recording, `base` is set back to what it was
/// and the upper layer holds the recorded file again, as before
/// `reconcile`).
/// Recovery then sees the workspace "moved" by its own recording, finds
/// the overlay overlapping it, and saves the same edits again as a spurious
/// conflict change ("they conflicted with a change to the workspace").
#[test]
fn recovery_after_a_crash_mid_recording_saves_no_spurious_change() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let proj = agent_project(&env);
    let (mnt, _g) = mount(&env, U, &proj, "agent");
    let state_path = proj.join(".veil/local/mounts/agent/state.json");
    let before: serde_json::Value = serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    std::fs::write(mnt.join("work.txt"), "agent work\n").unwrap();
    env.ok(U, &proj, &["status"]); // the mount records work.txt
    let pid = state_pid(&proj, "agent");
    // SAFETY: kill(2) of the mount process this test started.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    assert!(wait_for(Duration::from_secs(10), || !alive(pid)));
    let mut st: serde_json::Value = serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    assert_ne!(st["base"], before["base"], "the recording moved the base");
    st["base"] = before["base"].clone();
    std::fs::write(&state_path, serde_json::to_vec_pretty(&st).unwrap()).unwrap();
    // ...and the overlay as it was before `reconcile` trimmed it.
    std::fs::write(proj.join(".veil/local/mounts/agent/upper/work.txt"), "agent work\n").unwrap();
    let out = env.ok(U, &proj, &["ws", "unmount", "agent"]);
    let log = env.stdout(U, &proj, &["log", "-n", "100"]);
    assert_eq!(env.stdout(U, &proj, &["ws", "cat", "agent", "work.txt"]), "agent work\n");
    assert!(!log.contains("conflicted with a change"), "a spurious conflict change was saved:\n{out}\n{log}");
}

/// Control: renames of open files keep POSIX semantics (the open file
/// follows its rename; a file renamed over keeps its readers' content).
#[test]
fn control_renames_of_open_files() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let proj = agent_project(&env);
    let (mnt, _g) = mount(&env, U, &proj, "agent");
    let mut f = std::fs::OpenOptions::new().append(true).open(mnt.join("a.txt")).unwrap();
    std::io::Write::write_all(&mut f, b"one\n").unwrap();
    std::fs::rename(mnt.join("a.txt"), mnt.join("moved.txt")).unwrap();
    std::io::Write::write_all(&mut f, b"two\n").unwrap();
    drop(f);
    assert_eq!(read(&mnt, "moved.txt"), "a\none\ntwo\n");
    assert!(!mnt.join("a.txt").exists());
    let reader = std::fs::File::open(mnt.join("b.txt")).unwrap();
    std::fs::write(mnt.join("tmp"), "replaced\n").unwrap();
    std::fs::rename(mnt.join("tmp"), mnt.join("b.txt")).unwrap();
    let mut old = String::new();
    std::io::Read::read_to_string(&mut &reader, &mut old).unwrap();
    drop(reader);
    assert_eq!(old, "line1\nline2\n");
    assert_eq!(read(&mnt, "b.txt"), "replaced\n");
    env.ok(U, &proj, &["ws", "unmount", "agent"]);
    assert_eq!(env.stdout(U, &proj, &["ws", "cat", "agent", "moved.txt"]), "a\none\ntwo\n");
    assert_eq!(env.stdout(U, &proj, &["ws", "cat", "agent", "b.txt"]), "replaced\n");
}

/// Control: the mount is private (no `allow_other`, `default_permissions`,
/// `nosuid`, `nodev`; files `0600`) and refuses `.veil` in any case.
#[test]
fn control_mount_options_and_reserved_names() {
    if !fuse_available() {
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    let proj = agent_project(&env);
    let (mnt, _g) = mount(&env, U, &proj, "agent");
    let info = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    let line = info.lines().find(|l| l.split(' ').nth(4) == Some(mnt.to_str().unwrap())).unwrap().to_string();
    assert!(line.contains("nosuid") && line.contains("nodev") && line.contains("default_permissions"), "{line}");
    assert!(!line.contains("allow_other"), "{line}");
    assert_eq!(std::fs::metadata(mnt.join("a.txt")).unwrap().permissions().mode() & 0o777, 0o600);
    for bad in [".veil", ".VEIL", ".Veil"] {
        assert!(std::fs::create_dir(mnt.join(bad)).is_err(), "{bad}");
        assert!(std::fs::write(mnt.join(bad), "x").is_err(), "{bad}");
        assert!(std::fs::rename(mnt.join("a.txt"), mnt.join(bad)).is_err(), "{bad}");
    }
    // Format 5 records symlinks: the mount creates one as it is (the
    // kernel, never the mount, resolves it).
    std::os::unix::fs::symlink("/etc/passwd", mnt.join("l")).unwrap();
    assert_eq!(std::fs::read_link(mnt.join("l")).unwrap(), std::path::PathBuf::from("/etc/passwd"));
    assert!(std::fs::hard_link(mnt.join("a.txt"), mnt.join("h")).is_err());
    env.ok(U, &proj, &["ws", "unmount", "agent"]);
}
