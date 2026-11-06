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

/// Upgrade the fixture's path remote at `dir` structurally (no identity),
/// as `vl upgrade --remote` did before path remotes were removed.
fn upgrade_remote(dir: &Path) {
    let backend = std::sync::Arc::new(veil_core::DiskBackend::new(dir));
    veil_core::upgrade::upgrade(backend, None, &veil_core::upgrade::UpgradeOptions::default()).unwrap();
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
        dry.contains("Would upgrade this repository from format 1 to format 6"),
        "{dry}"
    );
    assert_eq!(format_of(&alice), 1);

    let out = ok(&vl(&home, &alice, &["upgrade"]));
    assert!(
        out.contains("Upgraded this repository from format 1 to format 6"),
        "{out}"
    );
    assert!(out.contains("scope 'team': new key generation 3"), "{out}");
    assert_eq!(format_of(&alice), 6);
    assert!(ok(&vl(&home, &alice, &["upgrade"])).contains("already at format 6"));
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
        String::from_utf8_lossy(&push.stderr).contains("vl upgrade"),
        "{push:?}"
    );
    upgrade_remote(&root.join("team-remote"));
    ok(&vl(&home, &alice, &["push", "origin"]));
    assert_eq!(format_of(&root.join("team-remote")), 6);
}

#[test]
fn upgrade_from_format_2_moves_keys_to_hpke_from_the_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("fx");
    copy_dir(&fixture(2), &root);
    let (home, alice) = (root.join("home-alice"), root.join("alice"));
    let show = ok(&vl(&home, &alice, &["identity", "show"]));
    assert!(show.contains("legacy: derived from the encryption key"), "{show}");

    let out = ok(&vl(&home, &alice, &["upgrade"]));
    assert!(out.contains("from format 2 to format 6"), "{out}");
    assert!(out.contains("3:hpke-ring-keys"), "{out}");
    assert!(out.contains("nothing is re-sealed"), "{out}");
    assert!(ok(&vl(&home, &alice, &["cat", "secrets/notes.txt", "-r", "main"])).contains("team-only notes v2"));
    ok(&vl(&home, &alice, &["fsck"]));

    std::fs::write(alice.join("secrets/notes.txt"), "notes after the upgrade\n").unwrap();
    ok(&vl(&home, &alice, &["commit", "-m", "after upgrade"]));
    ok(&vl(&home, &alice, &["tag", "set", "main", "-r", "@-", "--allow-backwards"]));
    // The format-2 remote refuses AES-SIV objects and the HPKE ring.
    let push = vl(&home, &alice, &["push", "origin"]);
    assert!(!push.status.success());
    assert!(String::from_utf8_lossy(&push.stderr).contains("vl upgrade"), "{push:?}");
    assert_eq!(format_of(&root.join("team-remote")), 2);
    upgrade_remote(&root.join("team-remote"));
    ok(&vl(&home, &alice, &["push", "origin"]));

    // Bob (a member, legacy identity) clones the upgraded remote and reads it.
    let bob_home = root.join("home-bob");
    let dest = tmp.path().join("bob-clone");
    ok(&vl(&bob_home, tmp.path(), &["clone", root.join("team-remote").to_str().unwrap(), dest.to_str().unwrap()]));
    assert_eq!(format_of(&dest), 6);
    assert!(ok(&vl(&bob_home, &dest, &["cat", "secrets/notes.txt", "-r", "main"])).contains("notes after the upgrade"));
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
