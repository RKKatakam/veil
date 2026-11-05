//! Listing and reading the files of a snapshot (`vl files`, `vl cat`):
//! git t3000–t3013 (ls-files), t3020 (error-unmatch), t3060 (with-tree),
//! t3100–t3105 (ls-tree); jj test_file_list_command, test_file_show_command,
//! test_file_chmod_command (via the disk), test_file_track_untrack_commands.

use super::*;

// Scenario from git t3004-ls-files-basic.sh: every file, sorted, with its
// visibility and size.
#[test]
fn files_lists_every_file_sorted_with_visibility_and_size() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("b.txt", "bb\n");
    r.write("a/z.txt", "z\n");
    r.write("a.txt", "");
    let files = r.files("@");
    let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
    // Tree order: each directory's entries by name (`a` before `a.txt`).
    assert_eq!(paths, vec![".veilpolicy", "a/z.txt", "a.txt", "b.txt"]);
    let b = files.iter().find(|f| f.path == "b.txt").unwrap();
    assert_eq!((b.vis.as_str(), b.size), ("public", 3));
    assert_eq!(files.iter().find(|f| f.path == "a.txt").unwrap().size, 0);
}

// Scenario from git t3060-ls-files-with-tree.sh / t3100-ls-tree-restrict.sh:
// another revision's files, and the root's (none).
#[test]
fn files_of_other_revisions() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("one.txt", "1\n");
    let one = r.commit("one");
    r.rm("one.txt");
    r.write("two.txt", "2\n");
    r.commit("two");
    assert_eq!(r.paths(one.as_str()), vec!["one.txt"]);
    assert_eq!(r.paths("@-"), vec!["two.txt"]);
    assert!(r.out(&["files", "-r", "root"]).is_empty());
}

// Scenario from git t3004-ls-files-basic.sh "ls-files in an empty repo".
#[test]
fn files_of_a_fresh_repository_lists_only_the_policy() {
    let env = Env::new();
    let r = env.repo("p");
    let files = r.files("@");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, ".veilpolicy");
}

// Scenario from jj test_file_chmod_command.rs (Veil has no `file chmod`;
// the disk's mode is recorded): the executable flag is listed.
#[cfg(unix)]
#[test]
fn files_marks_executables() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("run.sh", "#!/bin/sh\n");
    r.write("data.txt", "d\n");
    r.chmod("run.sh", 0o755);
    let files = r.files("@");
    assert!(files.iter().any(|f| f.path == "run.sh" && f.exec));
    assert!(files.iter().any(|f| f.path == "data.txt" && !f.exec));
}

// Scenario from git t3010-ls-files-killed-modified.sh: `vl files` lists
// what is recorded; files kept out (ignored, isolated, quarantined) are
// not in the list.
#[test]
fn files_lists_only_what_is_recorded() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("ok.txt", "ok\n");
    r.write(".env", DOTENV);
    r.write("leak.js", LEAKY);
    r.write("target/x.o", "o\n");
    assert_eq!(r.paths("@"), vec!["ok.txt"]);
}

// Scenario from git t3100-ls-tree-restrict.sh with Veil's tiers: a cloaked
// file is listed with its scope.
#[test]
fn files_shows_cloaked_files_with_their_scope() {
    let env = Env::new();
    let r = env.repo("p");
    r.ok(&["cloak", "secrets/"]);
    r.write("secrets/plan.txt", SECRET_PLAN);
    let f = r.files("@").into_iter().find(|f| f.path == "secrets/plan.txt").unwrap();
    assert_eq!(f.vis, "cloaked:team");
    assert!(!f.redacted, "the member can read it");
    assert_eq!(r.cat("secrets/plan.txt", "@"), SECRET_PLAN);
}

// Scenario from jj test_file_show_command.rs: `vl cat` prints the bytes
// exactly (binary, no trailing newline, empty).
#[test]
fn cat_prints_the_exact_bytes() {
    let env = Env::new();
    let r = env.repo("p");
    let bin: Vec<u8> = (0..=255u8).collect();
    r.write("bin", &bin);
    r.write("nonl", "no newline");
    r.write("empty", "");
    r.commit("bytes");
    assert_eq!(r.run(&["cat", "-r", "@-", "bin"]).stdout, bin);
    assert_eq!(r.cat("nonl", "@-"), "no newline");
    let out = r.run(&["cat", "-r", "@-", "empty"]);
    assert!(out.status.success() && out.stdout.is_empty());
}

// Scenario from git t3020-ls-files-error-unmatch.sh / jj
// test_file_show_command.rs "no such path".
#[test]
fn cat_of_a_missing_path_fails() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    r.commit("one");
    let err = r.fails(&["cat", "-r", "@-", "nope.txt"]);
    assert!(err.contains("nope.txt does not exist in"), "{err}");
    let err = r.fails(&["cat", "-r", "root", "a.txt"]);
    assert!(err.contains("does not exist"), "{err}");
}

// Scenario from jj test_file_show_command.rs "show a directory" (an
// error, not a crash) / git `cat-file` of a tree: a directory is not a
// file; the message must not claim the repository is corrupt.
#[test]
fn cat_of_a_directory_is_a_clear_error() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("dir/f.txt", "x\n");
    r.commit("one");
    for p in ["dir", ".", ""] {
        let err = r.fails(&["cat", "-r", "@-", p]);
        assert!(!err.contains("corrupt"), "{p:?}: {err}");
    }
    r.ok(&["ws", "new", "w", "-r", "@-"]);
    let err = r.fails(&["ws", "cat", "w", "dir"]);
    assert!(!err.contains("corrupt"), "ws cat: {err}");
    // And the repository is fine.
    let fsck = r.ok(&["fsck"]);
    assert!(fsck.contains("No corruption found"), "{fsck}");
}

// Scenario from git t3005-ls-files-relative.sh: `vl cat` takes paths
// relative to the current directory.
#[test]
fn cat_paths_are_relative_to_the_current_directory() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("sub/f.txt", "sub file\n");
    r.write("top.txt", "top\n");
    r.commit("one");
    let out = r.run_in("sub", &["cat", "-r", "@-", "f.txt"]);
    assert_eq!(stdout_of(&out), "sub file\n", "{}", text(&out));
    let out = r.run_in("sub", &["cat", "-r", "@-", "../top.txt"]);
    assert_eq!(stdout_of(&out), "top\n", "{}", text(&out));
}

// Scenario from git t3002-ls-files-dashpath.sh: a path starting with a dash.
#[test]
fn files_and_cat_with_dash_paths() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("-foo", "dash\n");
    assert!(r.paths("@").contains(&"-foo".to_string()));
    assert_eq!(r.out(&["cat", "--", "-foo"]), "dash\n");
}

// Scenario from jj test_file_show_command.rs: `vl cat` defaults to `@`
// and reads what is recorded, after snapshotting the disk.
#[test]
fn cat_defaults_to_the_working_copy() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "v1\n");
    r.commit("one");
    r.write("a.txt", "v2\n");
    assert_eq!(r.out(&["cat", "a.txt"]), "v2\n");
    assert_eq!(r.out(&["cat", "-r", "@-", "a.txt"]), "v1\n");
}

// Scenario from git t3100–t3105 (ls-tree of a large tree): sizes are byte
// counts, also for a multi-megabyte file.
#[test]
fn sizes_are_exact_for_large_files() {
    let env = Env::new();
    let r = env.repo("p");
    let big: Vec<u8> = (0..3_000_000u32).map(|i| (i * 7 % 251) as u8).collect();
    r.write("big.bin", &big);
    let f = r.files("@").into_iter().find(|f| f.path == "big.bin").unwrap();
    assert_eq!(f.size, big.len() as u64);
    assert_eq!(r.run(&["cat", "big.bin"]).stdout, big);
}

// Scenario from jj test_file_list_command.rs with a non-member: cloaked
// files are listed as redacted and cannot be printed.
#[test]
fn files_and_cat_for_a_non_member() {
    let env = Env::new();
    let r = env.repo("alice");
    r.ok(&["cloak", "secrets/"]);
    r.write("secrets/plan.txt", SECRET_PLAN);
    r.write("pub.txt", "public\n");
    r.commit("one");
    r.ok(&["tag", "set", "main", "-r", "@-"]);
    let remote = env.root.join("remote");
    r.ok(&["remote", "add", "origin", remote.to_str().unwrap()]);
    r.ok(&["push", "origin"]);
    let bob_dir = env.root.join("bob");
    let out = env.run_as("bob", &env.root, &["clone", remote.to_str().unwrap(), bob_dir.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out));
    let bob = env.as_user("bob", &bob_dir);
    let f = bob.files("main").into_iter().find(|f| f.path == "secrets/plan.txt").unwrap();
    assert!(f.redacted, "{f:?}");
    let err = bob.fails(&["cat", "-r", "main", "secrets/plan.txt"]);
    assert!(err.contains("cloaked under scope 'team'"), "{err}");
    assert!(!err.contains(SECRET_PLAN));
    assert_eq!(bob.cat("pub.txt", "main"), "public\n");
}
