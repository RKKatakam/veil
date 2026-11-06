//! BUG-819: a `vl clone` killed during its checkout.

use std::{
    path::Path,
    process::{Command, Output},
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

/// A clone writes `.veil/` (the objects, the new change), checks the files
/// out, and only then saves `checkout.json`. Killed during the checkout, it
/// leaves `.veil/`, no record and some of the files. The next command takes
/// the directory for one that holds its change, and records every file
/// not yet written as deleted. The state after the kill is made here by
/// hand: a complete clone without its record and without one directory.
#[test]
#[ignore = "BUG-819: a clone killed during its checkout has no journal; the next command records the unwritten files as deleted"]
fn a_clone_killed_during_its_checkout_never_records_deletions() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, src) = (tmp.path().join("home"), tmp.path().join("src"));
    for d in ["a", "b"] {
        std::fs::create_dir_all(src.join(d)).unwrap();
        for i in 0..3 {
            std::fs::write(src.join(d).join(format!("f{i}.txt")), format!("{d} {i}\n")).unwrap();
        }
    }
    ok(&home, &src, &["init"]);
    ok(&home, &src, &["commit", "-m", "import"]);
    ok(&home, &src, &["tag", "set", "main", "-r", "@-"]);
    let dst = tmp.path().join("dst");
    ok(&home, tmp.path(), &["clone", src.to_str().unwrap(), dst.to_str().unwrap()]);
    std::fs::remove_file(dst.join(".veil/local/checkout.json")).unwrap();
    std::fs::remove_dir_all(dst.join("b")).unwrap();
    let status = ok(&home, &dst, &["status"]);
    assert!(!status.contains("D b/"), "the files the clone had not written yet were recorded as deleted:\n{status}");
}
