//! `vl fsck` against real on-disk repositories.

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn vl(home: &Path, cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vl"))
        .env("VEIL_TEST_PATH_REMOTES", "1")
        .args(args)
        .current_dir(cwd)
        .env("VEIL_HOME", home)
        .env("VEIL_USER", "alice")
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn ok(home: &Path, cwd: &Path, args: &[&str]) -> String {
    let o = vl(home, cwd, args);
    assert!(o.status.success(), "vl {args:?} failed:\n{}", text(&o));
    text(&o)
}

/// Every loose object file of the repository.
fn objects(repo: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for d in std::fs::read_dir(repo.join(".veil/objects")).unwrap() {
        let d = d.unwrap().path();
        if d.is_dir() {
            for f in std::fs::read_dir(&d).unwrap() {
                out.push(f.unwrap().path());
            }
        }
    }
    out.sort();
    out
}

fn setup() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(repo.join("secrets")).unwrap();
    std::fs::write(repo.join("a.txt"), "hello\n").unwrap();
    std::fs::write(repo.join("secrets/.env.prod"), "password: hunter2\n").unwrap();
    ok(&home, &repo, &["init"]);
    ok(&home, &repo, &["cloak", "secrets/.env.prod"]);
    ok(&home, &repo, &["commit", "-m", "one"]);
    std::fs::write(repo.join("a.txt"), "hello again\n").unwrap();
    ok(&home, &repo, &["commit", "-m", "two"]);
    (tmp, home, repo)
}

#[test]
fn fsck_passes_on_a_healthy_repository_and_writes_nothing() {
    let (_tmp, home, repo) = setup();
    std::fs::write(repo.join("a.txt"), "unsnapshotted edit\n").unwrap();
    let before = objects(&repo);
    let heads = || {
        let mut v: Vec<String> = std::fs::read_dir(repo.join(".veil/op_heads")).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    };
    let head = heads();
    let out = ok(&home, &repo, &["fsck"]);
    assert!(out.contains("No corruption found"), "{out}");
    assert_eq!(objects(&repo), before, "fsck does not snapshot");
    assert_eq!(heads(), head);
}

#[test]
fn fsck_fails_on_a_damaged_object() {
    let (_tmp, home, repo) = setup();
    for f in objects(&repo) {
        let mut raw = std::fs::read(&f).unwrap();
        raw.push(b'!');
        std::fs::write(&f, raw).unwrap();
    }
    let o = vl(&home, &repo, &["fsck"]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(text(&o).contains("does not match its hash"), "{}", text(&o));
}

#[test]
fn fsck_fails_on_a_missing_object_and_a_broken_op_head() {
    let (_tmp, home, repo) = setup();
    let f = objects(&repo).into_iter().next().unwrap();
    std::fs::remove_file(f).unwrap();
    std::fs::write(repo.join(".veil/op_head"), "garbage").unwrap();
    // Ordinary commands cannot open the repository any more; fsck can.
    assert!(!vl(&home, &repo, &["status"]).status.success());
    let o = vl(&home, &repo, &["fsck", "--verbose"]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    let t = text(&o);
    assert!(t.contains("op_head"), "{t}");
}
