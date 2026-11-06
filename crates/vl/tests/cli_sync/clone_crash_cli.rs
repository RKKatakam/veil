//! BUG-830: a `vl clone` killed during its checkout.

use std::{
    path::Path,
    process::{Command, Output, Stdio},
};

fn vl(home: &Path, cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vl"))
        .args(args)
        .current_dir(cwd)
        .env("VEIL_HOME", home)
        .env("VEIL_USER", "alice")
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

fn ok(home: &Path, cwd: &Path, args: &[&str]) -> String {
    let out = vl(home, cwd, args);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "vl {args:?} failed:\n{text}");
    text
}

/// Did the checkout into `dst` start: is anything there besides `.veil`?
fn checkout_started(dst: &Path) -> bool {
    std::fs::read_dir(dst).is_ok_and(|d| d.flatten().any(|e| e.file_name() != ".veil"))
}

/// A clone writes `.veil/` (the objects, the new change), then checks the
/// files out. Killed during the checkout (here: `kill -9` as soon as its
/// first file or directory appears), it must leave a journal, so the next
/// command finishes the checkout instead of recording every file not yet
/// written as deleted. Every attempt checks that (safety); an attempt whose
/// clone finished before the kill landed proves nothing and is repeated.
#[test]
fn a_clone_killed_during_its_checkout_never_records_deletions() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, src) = (tmp.path().join("home"), tmp.path().join("src"));
    let mut files = Vec::new();
    for d in 0..40 {
        std::fs::create_dir_all(src.join(format!("d{d:02}"))).unwrap();
        for i in 0..100 {
            let p = format!("d{d:02}/f{i:03}.txt");
            std::fs::write(src.join(&p), format!("{p}\n")).unwrap();
            files.push(p);
        }
    }
    ok(&home, &src, &["init"]);
    ok(&home, &src, &["commit", "-m", "import"]);
    ok(&home, &src, &["tag", "set", "main", "-r", "@-"]);
    let mut interrupted = 0;
    for attempt in 0..8 {
        let dst = tmp.path().join(format!("dst{attempt}"));
        let mut child = Command::new(env!("CARGO_BIN_EXE_vl"))
            .args(["clone", src.to_str().unwrap(), dst.to_str().unwrap()])
            .current_dir(tmp.path())
            .env("VEIL_HOME", &home)
            .env("VEIL_USER", "alice")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while child.try_wait().unwrap().is_none() && !checkout_started(&dst) {
            assert!(std::time::Instant::now() < deadline, "the clone neither started its checkout nor ended");
        }
        let _ = child.kill();
        let finished = child.wait().unwrap().success();
        if finished {
            continue;
        }
        interrupted += 1;
        // Safety: nothing is recorded as deleted, and every file is there.
        let status = ok(&home, &dst, &["status"]);
        assert!(
            !status.lines().any(|l| l.trim_start().starts_with("D ")),
            "attempt {attempt}: files the clone had not written yet were recorded as deleted:\n{status}"
        );
        for p in &files {
            assert_eq!(std::fs::read_to_string(dst.join(p)).ok().as_deref(), Some(format!("{p}\n").as_str()), "attempt {attempt}: {p}");
        }
        let log = ok(&home, &dst, &["log"]);
        assert!(!log.contains("recovered"), "{log}");
        if interrupted >= 2 {
            break;
        }
    }
    assert!(interrupted > 0, "no clone was interrupted during its checkout (each finished first)");
}
