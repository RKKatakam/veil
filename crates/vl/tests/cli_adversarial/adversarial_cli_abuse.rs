//! Adversarial CLI tests: hostile arguments and revsets, odd files (huge,
//! binary, deep, Unicode, case-colliding, symlinks, permissions), empty
//! repositories, subdirectories and `-R`, and data-loss scenarios.

use crate::adversarial_support;

use std::{os::unix::fs::PermissionsExt, path::Path};

use adversarial_support::*;

// ---- arguments and revsets ---------------------------------------------------------

#[test]
fn hostile_revsets_never_panic() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    let long = "k".repeat(10_000);
    let dashes = format!("@{}", "-".repeat(5_000));
    let revs: Vec<&str> = vec![
        "", "-", "--", "@@", "@-@", "root-", "root--", "zzzzzzzz", "kkkk", "0000", "ffff", "@ ", " @", "main@",
        "nope@", "origin/", "/", "../..", "ü@", "🦀", "@\n-", &long, &dashes, "root()", "root(", "deadbeef-",
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        "0000000000000000000000000000000000000000000000000000000000000000",
    ];
    for r in &revs {
        for cmd in [&["show", r][..], &["log", "-n", "1"], &["diff", "-r", r], &["files", "-r", r], &["edit", r], &["new", r], &["rebase", "-s", r, "-d", "@"], &["squash", "-r", r], &["abandon", r], &["describe", "-r", r, "-m", "x"], &["tag", "set", "t", "-r", r]] {
            let out = env.vl("alice", &proj, cmd);
            assert!(exited_cleanly(&out), "vl {cmd:?} crashed:\n{}", text(&out));
        }
    }
    env.ok("alice", &proj, &["status"]);
}

#[test]
fn hostile_names_and_arguments_are_rejected_cleanly() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    let cases: Vec<Vec<&str>> = vec![
        vec!["ws", "new", ""],
        vec!["ws", "new", "../escape"],
        vec!["ws", "new", "a/b"],
        vec!["ws", "new", "default"],
        vec!["ws", "rm", "default"],
        vec!["ws", "switch", "nope"],
        vec!["ws", "cat", "default", "../../etc/passwd"],
        vec!["ws", "cat", "nope", "a.txt"],
        vec!["ws", "exec", "default", "--", "true"],
        vec!["ws", "exec", "--", "true"],
        vec!["tag", "set", "", "-r", "@-"],
        vec!["tag", "set", "a b", "-r", "@-"],
        vec!["tag", "set", "root", "-r", "@-"],
        vec!["tag", "set", "x-", "-r", "@-"],
        vec!["tag", "set", "../../x", "-r", "@-"],
        vec!["tag", "delete", "nope"],
        vec!["cat", ""],
        vec!["cat", "../../../etc/passwd"],
        vec!["cat", "/etc/passwd"],
        vec!["cat", ".veil/repo.json"],
        vec!["restore", "../../outside"],
        vec!["op", "restore", ""],
        vec!["op", "restore", "zzzz"],
        vec!["embargo", "release", "nope"],
        vec!["scope", "create", "local"],
        vec!["scope", "create", "embargo-x"],
        vec!["scope", "create", "../x"],
        vec!["scope", "create", "UPPER"],
        vec!["scope", "grant", "team", "veil1zz"],
        vec!["scope", "grant", "nope", "veil1aa"],
        vec!["scope", "revoke", "team", "garbage"],
        vec!["cloak", "x", "--scope", "nope"],
        vec!["remote", "rm", "nope"],
        vec!["push", "nope"],
        vec!["pull", "nope"],
        vec!["secret", "get", "nope"],
        vec!["secret", "rm", "nope"],
        vec!["merge"],
        vec!["merge", "@", "--into", "@"],
        vec!["merge", "main", "--until", "garbage"],
        vec!["merge", "main", "--until", "+5x"],
        vec!["rebase", "-s", "@", "-d", "@"],
        vec!["rebase", "-s", "root", "-d", "@"],
        vec!["squash", "-r", "root"],
        vec!["abandon", "root"],
        vec!["edit", "root"],
        vec!["log", "-n", "0"],
        vec!["run", "--", "/nonexistent-binary"],
        vec!["policy", "check", "../../x"],
    ];
    for args in &cases {
        let out = env.vl("alice", &proj, args);
        assert!(exited_cleanly(&out), "vl {args:?} crashed:\n{}", text(&out));
    }
    // nothing above escaped the project or broke it
    env.ok("alice", &proj, &["status"]);
    env.ok("alice", &proj, &["log"]);
    assert_eq!(read(&proj, "a.txt"), "a\n");
}

/// Scope and embargo names typed by the user reach `VPath::new(..).unwrap()`.
#[test]
fn path_like_scope_and_embargo_names_do_not_panic() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    let pk = format!("veil1{}", "11".repeat(32));
    for args in [
        vec!["embargo", "release", "../../x"],
        vec!["scope", "grant", "../x", pk.as_str()],
        vec!["scope", "revoke", "../x", pk.as_str()],
        vec!["cloak", "x", "--scope", "../x"],
    ] {
        let out = env.vl("alice", &proj, &args);
        assert!(exited_cleanly(&out), "vl {args:?} crashed:\n{}", text(&out));
    }
}

#[test]
fn embargo_deadline_overflow_is_rejected() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    env.ok("alice", &proj, &["new", "main", "-m", "fix"]);
    write(&proj, "a.txt", "fixed\n");
    env.ok("alice", &proj, &["tag", "set", "fix", "-r", "@"]);
    let out = env.vl("alice", &proj, &["merge", "fix", "--into", "main", "--embargo", "--until", "+213503955787d"]);
    assert!(exited_cleanly(&out), "{}", text(&out));
    let list = env.ok("alice", &proj, &["embargo", "list"]);
    assert!(!list.contains("released"), "embargo released immediately:\n{list}");
}

// ---- empty repositories ------------------------------------------------------------

#[test]
fn empty_repository_commands_behave() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    for args in [
        &["status"][..],
        &["log"],
        &["show"],
        &["show", "root"],
        &["diff"],
        &["diff", "-r", "root"],
        &["files"],
        &["files", "-r", "root"],
        &["evolog"],
        &["op", "log"],
        &["tag", "list"],
        &["ws", "list"],
        &["scope", "list"],
        &["embargo", "list"],
        &["policy", "show"],
        &["scan"],
        &["commit", "-m", "empty"],
        &["new", "root"],
    ] {
        let out = env.vl("alice", &proj, args);
        assert!(exited_cleanly(&out) && out.status.success(), "vl {args:?}:\n{}", text(&out));
    }
    for _ in 0..6 {
        let out = env.vl("alice", &proj, &["undo"]);
        assert!(exited_cleanly(&out), "{}", text(&out));
    }
    env.ok("alice", &proj, &["status"]);
}

#[test]
fn bare_remote_and_odd_repository_paths_fail_cleanly() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    let remote = env.dir("remote");
    env.ok("alice", &proj, &["remote", "add", "origin", remote.to_str().unwrap()]);
    env.ok("alice", &proj, &["push", "origin"]);
    let file = env.root.join("plain-file");
    std::fs::write(&file, "x").unwrap();
    let elsewhere = env.dir("elsewhere");
    for r in [
        remote.to_str().unwrap(),
        file.to_str().unwrap(),
        "/nonexistent/x",
        proj.join(".veil").to_str().unwrap(),
        proj.join(".veil/objects").to_str().unwrap(),
    ] {
        let out = env.vl("alice", &elsewhere, &["-R", r, "status"]);
        assert!(exited_cleanly(&out), "-R {r}: {}", text(&out));
    }
    // -R into .veil resolves to the enclosing repository
    let st = env.ok("alice", &elsewhere, &["-R", proj.join(".veil").to_str().unwrap(), "status"]);
    assert!(st.contains("Working copy"), "{st}");
}

// ---- odd files ------------------------------------------------------------------------

fn roundtrip_via_clone(env: &Env, proj: &Path, name: &str) -> std::path::PathBuf {
    let remote = env.dir(&format!("{name}-remote"));
    env.ok("alice", proj, &["remote", "add", "origin", remote.to_str().unwrap()]);
    env.ok("alice", proj, &["push", "origin"]);
    let work = env.dir(&format!("{name}-work"));
    env.ok("alice", &work, &["clone", remote.to_str().unwrap(), "dest"]);
    work.join("dest")
}

#[test]
fn huge_and_binary_files_roundtrip_exactly() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    let big: Vec<u8> = (0..24 * 1024 * 1024u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8 | 1).collect();
    let binary: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
    std::fs::write(proj.join("big.bin"), &big).unwrap();
    std::fs::write(proj.join("all-bytes.bin"), &binary).unwrap();
    std::fs::write(proj.join("empty"), b"").unwrap();
    env.ok("alice", &proj, &["commit", "-m", "big"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    let out = env.vl("alice", &proj, &["cat", "all-bytes.bin", "-r", "@-"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(out.stdout, binary);
    let dest = roundtrip_via_clone(&env, &proj, "big");
    assert_eq!(std::fs::read(dest.join("big.bin")).unwrap(), big);
    assert_eq!(std::fs::read(dest.join("all-bytes.bin")).unwrap(), binary);
    assert_eq!(std::fs::read(dest.join("empty")).unwrap(), b"");
}

#[test]
fn deep_unicode_and_case_colliding_paths_roundtrip() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    let deep = (0..120).map(|i| format!("d{i}")).collect::<Vec<_>>().join("/") + "/leaf.txt";
    let names = [
        deep.as_str(),
        "Ünïcödé/ファイル.txt",
        "emoji-🦀.rs",
        "with space.txt",
        "-rf",
        "--help",
        "README.md",
        "readme.md",
        "ReadMe.MD",
        "tab\there",
        "new\nline",
        "back\\slash",
        "e\u{301}.txt",
        "\u{e9}.txt",
    ];
    for (i, n) in names.iter().enumerate() {
        write(&proj, n, &format!("content {i}\n"));
    }
    env.ok("alice", &proj, &["commit", "-m", "odd names"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    let dest = roundtrip_via_clone(&env, &proj, "names");
    for (i, n) in names.iter().enumerate() {
        assert_eq!(read(&dest, n), format!("content {i}\n"), "{n:?}");
    }
    let st = env.ok("alice", &dest, &["status"]);
    assert!(st.contains("no changes"), "clone is dirty:\n{st}");
}

#[test]
fn symlinks_are_never_followed_when_snapshotting() {
    let env = Env::new();
    let outside = env.dir("outside");
    std::fs::write(outside.join("id_ed25519_copy"), "OUTSIDE-SECRET\n").unwrap();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    std::os::unix::fs::symlink(outside.join("id_ed25519_copy"), proj.join("notes.txt")).unwrap();
    std::os::unix::fs::symlink(&outside, proj.join("vendor")).unwrap();
    std::os::unix::fs::symlink("/", proj.join("rootfs")).unwrap();
    std::os::unix::fs::symlink(proj.join("loop"), proj.join("loop")).unwrap();
    env.ok("alice", &proj, &["commit", "-m", "links"]);
    // Format 5 records the links themselves: their targets, never what
    // they point at.
    let files = env.stdout("alice", &proj, &["files", "-r", "@-"]);
    assert!(files.contains("notes.txt") && files.contains("vendor") && files.contains("rootfs"), "{files}");
    let target = env.stdout("alice", &proj, &["cat", "-r", "@-", "notes.txt"]);
    assert_eq!(target, outside.join("id_ed25519_copy").to_str().unwrap());
    fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() => out.extend(walk(&p)),
                Ok(t) if t.is_file() => out.push(p),
                _ => {}
            }
        }
        out
    }
    for d in walk(&proj.join(".veil")) {
        if let Ok(data) = std::fs::read(&d) {
            assert!(!String::from_utf8_lossy(&data).contains("OUTSIDE-SECRET"), "{} holds the link's target content", d.display());
        }
    }
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-", "--allow-backwards"]);
    let dest = roundtrip_via_clone(&env, &proj, "links");
    for (name, target) in [("notes.txt", outside.join("id_ed25519_copy")), ("vendor", outside.clone()), ("rootfs", "/".into())] {
        assert_eq!(std::fs::read_link(dest.join(name)).unwrap(), target, "{name}");
    }
}

/// The victim has an (untracked, invisible to Veil) symlinked directory, e.g.
/// `vendor -> /shared/vendor`. A pulled tree containing `vendor/x` is written
/// *through* the link, outside the working copy.
#[test]
fn checkout_never_writes_through_a_symlinked_directory() {
    let env = Env::new();
    let shared = env.dir("shared-vendor");
    let alice = env.project("alice", "alice", &[("a.txt", "a\n")]);
    write(&alice, "vendor/postinstall.sh", "#!/bin/sh\necho owned\n");
    env.ok("alice", &alice, &["commit", "-m", "add vendor"]);
    env.ok("alice", &alice, &["tag", "set", "main", "-r", "@-"]);
    let remote = env.dir("remote");
    env.ok("alice", &alice, &["remote", "add", "origin", remote.to_str().unwrap()]);
    env.ok("alice", &alice, &["push", "origin"]);

    let bob = env.project("bob", "bob", &[("b.txt", "b\n")]);
    std::os::unix::fs::symlink(&shared, bob.join("vendor")).unwrap();
    env.ok("bob", &bob, &["remote", "add", "origin", remote.to_str().unwrap()]);
    env.ok("bob", &bob, &["pull", "origin"]);
    let out = env.vl("bob", &bob, &["new", "origin/main"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(!shared.join("postinstall.sh").exists(), "checkout wrote into {}", shared.display());
}

#[test]
fn read_only_files_and_directories_do_not_corrupt_state() {
    let env = Env::new();
    if unsafe_is_root() {
        return;
    }
    let proj = env.project("alice", "proj", &[("ro.txt", "v1\n"), ("dir/f.txt", "v1\n")]);
    let v1 = snapshot_of(&env, &proj, "@-"); // `vl commit` advances tags, so pin by id
    std::fs::set_permissions(proj.join("ro.txt"), std::fs::Permissions::from_mode(0o444)).unwrap();
    write_ro(&proj.join("ro.txt"), "v2\n");
    env.ok("alice", &proj, &["commit", "-m", "v2"]);
    env.ok("alice", &proj, &["new", &v1]);
    assert_eq!(read(&proj, "ro.txt"), "v1\n", "read-only file restored through atomic rename");
    // a read-only directory makes checkout fail; it must fail cleanly and recover
    write(&proj, "dir/f.txt", "v3\n");
    env.ok("alice", &proj, &["commit", "-m", "v3"]);
    std::fs::set_permissions(proj.join("dir"), std::fs::Permissions::from_mode(0o555)).unwrap();
    let out = env.vl("alice", &proj, &["new", &v1]);
    assert!(out.status.success() && text(&out).contains("failed dir/f.txt"), "{}", text(&out));
    std::fs::set_permissions(proj.join("dir"), std::fs::Permissions::from_mode(0o755)).unwrap();
    env.ok("alice", &proj, &["status"]);
    env.ok("alice", &proj, &["new", &v1]);
    assert_eq!(read(&proj, "dir/f.txt"), "v1\n");
    let log = env.ok("alice", &proj, &["log"]);
    assert!(log.contains("v3"), "committed work lost:\n{log}");
}

fn snapshot_of(env: &Env, proj: &Path, rev: &str) -> String {
    let show = env.stdout("alice", proj, &["show", rev]);
    show.lines()
        .find_map(|l| l.strip_prefix("Snapshot  : "))
        .unwrap_or_else(|| panic!("no snapshot line in:\n{show}"))
        .trim()
        .to_string()
}

fn write_ro(p: &Path, content: &str) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(p, content).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o444)).unwrap();
}

fn unsafe_is_root() -> bool {
    std::process::Command::new("id").arg("-u").output().map(|o| o.stdout.starts_with(b"0\n")).unwrap_or(false)
}

#[test]
fn an_unreadable_file_does_not_brick_the_cli() {
    let env = Env::new();
    if unsafe_is_root() {
        return;
    }
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    write(&proj, "locked.bin", "x");
    std::fs::set_permissions(proj.join("locked.bin"), std::fs::Permissions::from_mode(0o000)).unwrap();
    let ign = env.vl("alice", &proj, &["ignore", "locked.bin"]);
    let st = env.vl("alice", &proj, &["status"]);
    std::fs::set_permissions(proj.join("locked.bin"), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(ign.status.success(), "cannot even ignore the file: {}", text(&ign));
    assert!(st.status.success(), "{}", text(&st));
}

#[test]
fn non_utf8_file_names_are_not_silently_dropped() {
    use std::os::unix::ffi::OsStrExt;
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    let name = std::ffi::OsStr::from_bytes(b"report-\xff\xfe.csv");
    std::fs::write(proj.join(name), "important data\n").unwrap();
    let out = env.ok("alice", &proj, &["commit", "-m", "add report"]);
    let files = env.stdout("alice", &proj, &["files", "-r", "@-"]);
    assert!(
        files.contains("report-") || out.to_lowercase().contains("utf-8") || out.contains("skipp"),
        "file silently not recorded and no warning:\n{out}\n{files}"
    );
}

#[test]
fn running_from_a_subdirectory_uses_repository_relative_paths() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("src/lib.rs", "v1\n"), ("README", "r\n")]);
    let sub = proj.join("src");
    write(&proj, "src/lib.rs", "v2\n");
    assert_eq!(env.stdout("alice", &sub, &["cat", "lib.rs", "-r", "main"]), "v1\n");
    assert_eq!(env.stdout("alice", &sub, &["cat", "../README", "-r", "main"]), "r\n");
    env.ok("alice", &sub, &["restore", "lib.rs", "--from", "main"]);
    assert_eq!(read(&proj, "src/lib.rs"), "v1\n");
    let out = env.vl("alice", &sub, &["cat", "../../outside", "-r", "main"]);
    assert!(exited_cleanly(&out) && !out.status.success());
}

// ---- data loss --------------------------------------------------------------------------

/// The user edits a tracked file and accidentally adds a credential. The file
/// is quarantined: the working-copy change records it as *deleted*. Moving to
/// another change (`vl new main`) then overwrites the edited file with the old
/// version, and the next snapshot drops it from the vault: the edit is gone.
#[test]
fn quarantined_edits_are_never_lost() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("config.js", "const a = 1;\n")]);
    let edit = "const a = 2;\n// lots of work\nconst k = \"AKIAIOSFODNN7EXAMPLE\";\n";
    write(&proj, "config.js", edit);
    let st = env.ok("alice", &proj, &["status"]);
    assert!(st.contains("quarantined"), "{st}");
    env.ok("alice", &proj, &["new", "main"]);
    env.ok("alice", &proj, &["status"]);
    let on_disk = read(&proj, "config.js");
    let in_vault = {
        let fs = std::sync::Arc::new(veil_core::DiskBackend::new(&proj));
        let id = veil_core::Identity::from_json(&std::fs::read_to_string(env.root.join("home-alice/identity.json")).unwrap()).unwrap();
        let repo = veil_core::Repo::open(fs, Some(id), "alice").unwrap();
        repo.vault_load().unwrap().files.contains_key("config.js")
    };
    assert!(on_disk == edit || in_vault, "the quarantined edit is gone (disk: {on_disk:?}, vault: {in_vault})");
}

/// `vl undo` right after editing undoes the auto-snapshot of those edits and
/// deletes them from disk (recoverable only through the op log).
#[test]
fn undo_does_not_discard_uncommitted_edits() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    env.ok("alice", &proj, &["describe", "-r", "@", "-m", "an operation to undo"]);
    write(&proj, "new-work.txt", "an hour of work\n");
    env.ok("alice", &proj, &["undo"]);
    assert!(proj.join("new-work.txt").exists(), "`vl undo` deleted uncommitted work from disk");
}

// ---- visibility commands ------------------------------------------------------------------

/// Next.js-style names (`[id].tsx`) and other glob metacharacters: `vl cloak`
/// writes the name as a glob, so the literal file is not matched and stays
/// public while the CLI reports it as cloaked.
#[test]
fn cloaking_a_file_with_glob_metacharacters_cloaks_that_file() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    write(&proj, "config[prod].pem", "prod creds: correct-horse\n");
    write(&proj, "notes{1}.txt", "private\n");
    write(&proj, "app/[id]/token?.pem", "t\n");
    let msg = env.ok("alice", &proj, &["cloak", "config[prod].pem", "app/[id]/token?.pem"]);
    assert!(msg.contains("Added rule"));
    env.ok("alice", &proj, &["isolate", "notes{1}.txt"]);
    env.ok("alice", &proj, &["commit", "-m", "c"]);
    let files = env.stdout("alice", &proj, &["files", "-r", "@-"]);
    assert!(files.contains("config[prod].pem") && files.contains("app/[id]/token?.pem"), "{files}");
    let mut matched = 0;
    for line in files.lines() {
        if line.contains("config[prod]") || line.contains("token?") {
            assert!(line.starts_with("cloaked"), "told it was cloaked, recorded as: {line}");
            matched += 1;
        }
        assert!(!line.contains("notes{1}"), "told it was isolated, recorded as: {line}");
    }
    assert_eq!(matched, 2, "{files}");
}

#[test]
fn rotating_the_identity_does_not_brick_the_repository() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    write(&proj, ".env", "X=1\n");
    env.ok("alice", &proj, &["status"]);
    env.ok("alice", &proj, &["identity", "new", "--force"]);
    let out = env.vl("alice", &proj, &["status"]);
    assert!(out.status.success(), "{}", text(&out));
}
