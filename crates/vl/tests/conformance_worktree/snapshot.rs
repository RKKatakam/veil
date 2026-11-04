//! The automatic snapshot itself: jj test_working_copy, lib
//! test_local_working_copy, test_local_working_copy_concurrent,
//! test_local_working_copy_executable_bit; git t0010 (racy), t7516
//! (races), t0005 (signals), t2009 (stat info).

use crate::*;
use std::time::{Duration, Instant};

// Scenario from jj test_local_working_copy.rs "snapshot special file":
// FIFOs (and symlinks, a pending feature) are skipped, not followed.
#[cfg(unix)]
#[test]
fn fifos_and_symlinks_are_not_recorded_or_followed() {
    let env = Env::new();
    let r = env.repo("p");
    let fifo = r.path("pipe");
    let made = std::process::Command::new("mkfifo").arg(&fifo).status().is_ok_and(|s| s.success());
    std::os::unix::fs::symlink("/etc/hostname", r.path("link")).unwrap();
    r.write("real.txt", "r\n");
    let out = r.run(&["status"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(r.paths("@"), vec!["real.txt"]);
    if made {
        assert!(fifo.exists());
    }
    assert!(r.path("link").symlink_metadata().unwrap().file_type().is_symlink());
}

// Scenario from jj test_local_working_copy.rs (unreadable directory): its
// last recorded content is kept, with a warning; nothing is deleted.
#[cfg(unix)]
#[test]
fn an_unreadable_directory_keeps_its_recorded_content() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("locked/s.txt", "s\n");
    r.commit("one");
    r.chmod("locked", 0o000);
    if std::fs::read_dir(r.path("locked")).is_ok() {
        r.chmod("locked", 0o755);
        return; // root
    }
    let out = r.run(&["status"]);
    r.chmod("locked", 0o755);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("cannot read it"), "{}", text(&out));
    assert_eq!(r.paths("@"), vec!["locked/s.txt"]);
}

// Scenario from git t0005-signals.sh / jj test_local_working_copy.rs
// (interrupted snapshot): `kill -9` during a large snapshot leaves the
// repository usable, and the next command records the file.
#[cfg(unix)]
#[test]
fn a_killed_snapshot_leaves_the_repository_usable() {
    let env = Env::new();
    let r = env.repo("p");
    let big: Vec<u8> = (0..40_000_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    r.write("big.bin", &big);
    let mut child = r.cmd(&["commit", "-m", "big"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
    std::thread::sleep(Duration::from_millis(60));
    let _ = child.kill();
    let _ = child.wait();
    let out = r.run(&["status"]);
    assert!(out.status.success(), "{}", text(&out));
    let mut rev = "@".to_string();
    let mut found = false;
    while r.snap(&rev) != r.snap("root") {
        if r.paths(&rev).contains(&"big.bin".to_string()) {
            found = true;
            break;
        }
        rev.push('-');
    }
    assert!(found, "big.bin is recorded somewhere on the line");
    assert_eq!(r.run(&["cat", "-r", rev.as_str(), "big.bin"]).stdout.len(), big.len());
    let fsck = r.run(&["fsck"]);
    assert!(fsck.status.success(), "{}", text(&fsck));
}

// Scenario from jj test_local_working_copy.rs "large file": a 64 MiB file
// is recorded and checked out intact.
#[test]
fn a_large_file_round_trips() {
    let env = Env::new();
    let r = env.repo("p");
    let big: Vec<u8> = (0..64u32 << 20).map(|i| (i % 253) as u8).collect();
    r.write("big.bin", &big);
    let c = r.commit("big");
    r.ok(&["new", "root"]);
    assert!(!r.exists("big.bin"));
    r.ok(&["new", c.as_str()]);
    assert!(r.read_bytes("big.bin") == big);
}

// Scenario from jj test_working_copy.rs: repeated snapshots of an
// unchanged tree are cheap and record nothing.
#[test]
fn unchanged_snapshots_are_cheap() {
    let env = Env::new();
    let r = env.repo("p");
    for i in 0..300 {
        r.write(&format!("d{}/f{i}", i % 7), "x\n");
    }
    r.commit("many");
    let snap = r.snap("@");
    let t = Instant::now();
    for _ in 0..5 {
        r.ok(&["status"]);
    }
    assert_eq!(r.snap("@"), snap);
    assert!(t.elapsed() < Duration::from_secs(20), "{:?}", t.elapsed());
}

// Scenario from jj test_local_working_copy.rs "file changed to directory
// and back" within one change, across snapshots.
#[test]
fn a_path_changes_kind_between_snapshots() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("x", "file\n");
    r.ok(&["status"]);
    r.rm("x");
    r.write("x/y", "dir\n");
    assert_eq!(r.paths("@"), vec!["x/y"]);
    r.rm("x");
    r.write("x", "file again\n");
    assert_eq!(r.paths("@"), vec!["x"]);
    assert_eq!(r.cat("x", "@"), "file again\n");
}

// Scenario from jj test_local_working_copy_executable_bit.rs: toggling
// only the mode is a change, and toggling back is none.
#[cfg(unix)]
#[test]
fn toggling_the_executable_bit_and_back() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("s", "#!/bin/sh\n");
    r.commit("one");
    r.chmod("s", 0o755);
    assert_eq!(r.changes(), vec!["M s"]);
    r.chmod("s", 0o644);
    assert!(r.changes().is_empty());
    // Only the user-executable bit matters, like Git.
    r.chmod("s", 0o664);
    assert!(r.changes().is_empty());
}

// Scenario from jj test_local_working_copy.rs (crash debris): interrupted
// atomic writes are never recorded.
#[test]
fn temporary_files_of_interrupted_writes_are_not_recorded() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    r.write(".a.txt.vltmp1a2b3c4d", "half written\n");
    assert_eq!(r.paths("@"), vec!["a.txt"]);
}

// Scenario from jj test_working_copy.rs (`vl watch`): continuous
// snapshots record edits without another command.
#[test]
fn watch_records_edits_as_they_happen() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base");
    let mut w = r
        .cmd(&["watch", "--interval-ms", "50"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    r.write("watched.txt", "w\n");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seen = false;
    while Instant::now() < deadline {
        if r.out(&["--no-snapshot", "files"]).contains("watched.txt") {
            seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = w.kill();
    let _ = w.wait();
    assert!(seen, "vl watch recorded the new file");
}

// Scenario from git t0010-racy-git.sh with a whole tree rewritten in the
// same second as the snapshot.
#[test]
fn a_tree_rewritten_right_after_a_snapshot_is_noticed() {
    let env = Env::new();
    let r = env.repo("p");
    for i in 0..20 {
        r.write(&format!("f{i}"), "aaaa\n");
    }
    r.commit("one");
    for i in 0..20 {
        r.write(&format!("f{i}"), "bbbb\n");
    }
    assert_eq!(r.changes().len(), 20);
}

// Scenario from jj test_local_working_copy_concurrent.rs: a checkout in
// one process while another snapshots does not corrupt anything.
#[test]
fn concurrent_checkout_and_snapshot() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "1\n");
    let one = r.commit("one");
    r.write("a.txt", "2\n");
    r.commit("two");
    let kids: Vec<_> = (0..6)
        .map(|i| {
            let args: Vec<String> = if i % 2 == 0 { vec!["new".into(), one.clone()] } else { vec!["status".into()] };
            r.cmd(&args).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap()
        })
        .collect();
    for k in kids {
        let out = k.wait_with_output().unwrap();
        assert!(clean_exit(&out), "{}", text(&out));
    }
    let out = r.run(&["status"]);
    assert!(out.status.success(), "{}", text(&out));
    let fsck = r.run(&["fsck"]);
    assert!(fsck.status.success(), "{}", text(&fsck));
    assert_eq!(r.read("a.txt"), r.cat("a.txt", "@"));
}
