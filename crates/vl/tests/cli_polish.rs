//! CLI polish: `vl clone` cleans up after itself on failure, concurrent
//! `vl remote add` never loses a remote, and working-copy warnings escape
//! the file names they quote.

mod adversarial_support;

use adversarial_support::*;

#[test]
fn a_failed_clone_removes_the_directory_it_created() {
    let env = Env::new();
    let not_a_repo = env.dir("not-a-repo");
    write(&not_a_repo, "file.txt", "x\n");
    let out = env.vl("bob", &env.root, &["clone", "not-a-repo", "dest"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(!env.root.join("dest").exists(), "a half-created clone was left behind");

    // An empty directory that already existed is kept, and left empty.
    let existing = env.dir("existing");
    let out = env.vl("bob", &env.root, &["clone", "not-a-repo", "existing"]);
    assert!(!out.status.success());
    assert!(existing.is_dir());
    assert_eq!(std::fs::read_dir(&existing).unwrap().count(), 0, "debris left in {}", existing.display());
}

#[test]
fn concurrent_remote_adds_are_all_kept() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    const N: usize = 8;
    let children: Vec<_> = (0..N)
        .map(|i| {
            let url = env.root.join(format!("remote-{i}"));
            env.spawn("alice", &proj, &["--no-snapshot", "remote", "add", &format!("r{i}"), url.to_str().unwrap()])
        })
        .collect();
    for c in children {
        let out = c.wait_with_output().unwrap();
        assert!(out.status.success(), "{}", text(&out));
    }
    let list = env.stdout("alice", &proj, &["remote", "list"]);
    for i in 0..N {
        assert!(list.contains(&format!("r{i} ")), "remote r{i} was lost:\n{list}");
    }
}

/// File names come from the working copy: a name carrying terminal escape
/// sequences must be shown escaped in the symlink and unreadable warnings.
#[cfg(unix)]
#[test]
fn working_copy_warnings_escape_file_names() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    let evil = "a\x1b]0;pwned\x07.txt";
    let locked = "b\x1b[2J.txt";
    let proj = env.project("alice", "proj", &[(evil, "x\n"), (locked, "y\n")]);
    std::fs::remove_file(proj.join(evil)).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", proj.join(evil)).unwrap();
    std::fs::set_permissions(proj.join(locked), std::fs::Permissions::from_mode(0o000)).unwrap();
    let unreadable = std::fs::read(proj.join(locked)).is_err(); // false when run as root
    let out = env.vl("alice", &proj, &["status"]);
    std::fs::set_permissions(proj.join(locked), std::fs::Permissions::from_mode(0o644)).unwrap();
    let all = text(&out);
    assert!(out.status.success(), "{all}");
    assert!(!all.contains('\x1b') && !all.contains('\x07'), "raw control characters in the output: {all:?}");
    assert!(all.contains("a\\x1b]0;pwned\\x07.txt is tracked but is now a symlink"), "{all}");
    if unreadable {
        assert!(all.contains("skipped b\\x1b[2J.txt: cannot read it"), "{all}");
    }
}
