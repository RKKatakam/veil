//! `vl upgrade` and format handling of `vl clone`, on a copy of the
//! format-1 golden fixture (`crates/veil-core/tests/fixtures`).

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

#[test]
fn upgrade_from_the_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("fx");
    copy_dir(&fixture(1), &root);
    let (home, alice) = (root.join("home-alice"), root.join("alice"));

    // A format-1 repository works without upgrading.
    assert!(ok(&vl(&home, &alice, &["cat", "secrets/notes.txt", "-r", "main"])).contains("team-only notes v2"));
    let dry = ok(&vl(&home, &alice, &["upgrade", "--dry-run"]));
    assert!(
        dry.contains("Would upgrade this repository from format 1 to format 2"),
        "{dry}"
    );
    assert_eq!(format_of(&alice), 1);

    let out = ok(&vl(&home, &alice, &["upgrade"]));
    assert!(
        out.contains("Upgraded this repository from format 1 to format 2"),
        "{out}"
    );
    assert_eq!(format_of(&alice), 2);
    assert!(ok(&vl(&home, &alice, &["upgrade"])).contains("already at format 2"));
    ok(&vl(&home, &alice, &["fsck"]));

    // New commits are binary; the format-1 remote refuses them until upgraded.
    std::fs::write(alice.join("after.txt"), "after\n").unwrap();
    ok(&vl(&home, &alice, &["commit", "-m", "after upgrade"]));
    ok(&vl(
        &home,
        &alice,
        &["tag", "set", "main", "-r", "@-", "--allow-backwards"],
    ));
    let push = vl(&home, &alice, &["push", "origin"]);
    assert!(!push.status.success());
    assert!(
        String::from_utf8_lossy(&push.stderr).contains("vl upgrade --remote"),
        "{push:?}"
    );
    let up = ok(&vl(&home, &alice, &["upgrade", "--remote", "origin"]));
    assert!(up.contains("Upgraded remote 'origin'"), "{up}");
    ok(&vl(&home, &alice, &["push", "origin"]));
    assert_eq!(format_of(&root.join("team-remote")), 2);
}

#[test]
fn clone_keeps_the_format_of_its_source() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("fx");
    copy_dir(&fixture(1), &root);
    let home = root.join("home-bob");
    let dest = tmp.path().join("bob-clone");
    ok(&vl(
        &home,
        tmp.path(),
        &[
            "clone",
            root.join("team-remote").to_str().unwrap(),
            dest.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        format_of(&dest),
        1,
        "a clone of a format-1 remote must stay pushable to it"
    );
    assert!(ok(&vl(&home, &dest, &["cat", "secrets/notes.txt", "-r", "main"])).contains("team-only notes v2"));
    std::fs::write(dest.join("bob.txt"), "bob\n").unwrap();
    ok(&vl(&home, &dest, &["commit", "-m", "bob"]));
    ok(&vl(
        &home,
        &dest,
        &["tag", "set", "main", "-r", "@-", "--allow-backwards"],
    ));
    ok(&vl(&home, &dest, &["push", "origin"]));
    ok(&vl(&home, &dest, &["fsck"]));
}
