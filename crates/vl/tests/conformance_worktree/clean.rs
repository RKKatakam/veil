//! Git's `clean`: git t7300-clean (t7301 interactive is not applicable).
//! Veil has no untracked files, so "clean" is `vl restore` for recorded
//! additions; ignored and isolated files are never removed by any command.

use crate::*;

// Scenario from git t7300-clean.sh "git clean" / "git clean -d": new files
// and new directories are dropped by restoring from the parent.
#[test]
fn restore_drops_new_files_and_directories() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("src/keep.rs", "k\n");
    r.commit("one");
    r.write("src/scratch.rs", "s\n");
    r.write("newdir/deep/x.txt", "x\n");
    r.ok(&["restore"]);
    assert_eq!(r.disk_files(), vec!["src/keep.rs"]);
}

// Scenario from git t7300-clean.sh "git clean with prefix" / pathspec.
#[test]
fn restore_of_a_directory_drops_only_new_files_there() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a/keep", "k\n");
    r.commit("one");
    r.write("a/new", "n\n");
    r.write("b/new", "n\n");
    r.ok(&["restore", "a"]);
    assert!(!r.exists("a/new"));
    assert_eq!(r.read("b/new"), "n\n");
}

// Scenario from git t7300-clean.sh "git clean -x" / "-X": there is no
// Veil command that deletes ignored files; restore and checkouts keep them.
#[test]
fn ignored_files_are_never_cleaned() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("target/debug/app", "binary\n");
    r.write("node_modules/m/index.js", "m\n");
    r.write("x.txt", "x\n");
    r.commit("one");
    // (Not `restore --from root` of everything: that deletes .veilpolicy,
    // whose rules are what ignores target/.)
    r.ok(&["restore", "--from", "root", "x.txt"]);
    r.ok(&["new", "root"]);
    assert_eq!(r.read("target/debug/app"), "binary\n");
    assert_eq!(r.read("node_modules/m/index.js"), "m\n");
}

// Scenario from git t7300-clean.sh with Veil's local-only files: isolated
// files survive every "cleaning" operation and stay in the vault.
#[test]
fn isolated_files_are_never_cleaned() {
    let env = Env::new();
    let r = env.repo("p");
    r.write(".env", DOTENV);
    r.write("id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n");
    r.write("a.txt", "a\n");
    r.commit("one");
    r.ok(&["restore", "--from", "root"]);
    r.ok(&["new", "root"]);
    r.ok(&["abandon"]);
    assert_eq!(r.read(".env"), DOTENV);
    assert!(r.exists("id_ed25519"));
}

// Scenario from git t7300-clean.sh "clean removes empty directories" (-d).
#[test]
fn restore_removes_the_new_directories_it_empties() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("keep", "k\n");
    r.commit("one");
    r.write("newdir/a/b/c.txt", "c\n");
    r.ok(&["restore"]);
    assert!(!r.exists("newdir"), "{:?}", r.disk());
}
