//! `vl upgrade` on a copy of a golden fixture
//! (`crates/veil-core/tests/fixtures`).

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn fixture(format: u32) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../veil-core/tests/fixtures/format-{format}"))
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dst = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dst);
        } else {
            std::fs::copy(e.path(), &dst).unwrap();
        }
    }
}

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

fn ok(o: &Output) -> String {
    assert!(
        o.status.success(),
        "failed: {}\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn format_of(repo: &Path) -> u64 {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(repo.join(".veil/repo.json")).unwrap()).unwrap();
    v["format"].as_u64().unwrap()
}

fn err(o: &Output) -> String {
    assert!(!o.status.success(), "unexpectedly succeeded: {}", String::from_utf8_lossy(&o.stdout));
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Every file under `dir`, with its bytes.
fn snapshot_dir(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_dir() {
            snapshot_dir(&e.path(), out);
        } else {
            out.push((e.path(), std::fs::read(e.path()).unwrap()));
        }
    }
    out.sort();
}

/// The format-7 fixture holds what format 8 removed (cloaked folders, tags
/// and lines of work, sealed descriptions, embargo keys): this vl refuses
/// to open it, and `vl upgrade` refuses it, naming each thing and changing
/// nothing.
#[test]
fn upgrade_from_the_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("fx");
    copy_dir(&fixture(7), &root);
    let (home, alice) = (root.join("home-alice"), root.join("alice"));
    let mut before = Vec::new();
    snapshot_dir(&root, &mut before);

    let e = err(&vl(&home, &alice, &["cat", "README.md", "-r", "main"]));
    assert!(e.contains("format 7") && e.contains("vl upgrade"), "{e}");
    let dry = vl(&home, &alice, &["upgrade", "--dry-run"]);
    let dry = String::from_utf8_lossy(&dry.stdout).into_owned();
    assert!(dry.contains(&format!("Would upgrade this repository from format 7 to format {}", veil_core::repo::REPO_FORMAT)), "{dry}");
    assert!(dry.contains("The upgrade would be refused"), "{dry}");
    let e = err(&vl(&home, &alice, &["upgrade"]));
    assert!(e.contains("upgrade refused") && e.contains("Nothing was changed"), "{e}");
    for thing in ["tag 'team-only': cloaked", "workspace 'fix-a': cloaked", "an encrypted description", "its record holds an embargo key", "secrets/notes.txt: encrypted (cloaked:team), and not a secret file"] {
        assert!(e.contains(thing), "{thing:?} not named: {e}");
    }
    assert_eq!(format_of(&alice), 7);
    let mut after = Vec::new();
    snapshot_dir(&root, &mut after);
    assert!(before == after, "a refused upgrade changed files");
}

#[test]
fn new_identities_have_independent_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let out = ok(&vl(&home, tmp.path(), &["identity", "new", "--name", "zoe"]));
    assert!(out.contains("Created identity zoe"), "{out}");
    let show = ok(&vl(&home, tmp.path(), &["identity", "show"]));
    assert!(!show.contains("legacy"), "{show}");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(home.join("identity.json")).unwrap()).unwrap();
    assert_eq!(v["format"], 2);
    assert!(v.get("secret").is_none() && v.get("signing_secret").is_some());
}
