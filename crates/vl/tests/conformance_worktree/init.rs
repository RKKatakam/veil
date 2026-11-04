//! `vl init` and repository discovery (git t0001, t1500/t1501/t1504/t1515
//! discovery parts, t2300; jj test_init, test_root, test_global_opts).

use crate::*;

// Scenario from git t0001-init.sh: plain init in the current directory.
#[test]
fn init_creates_the_repository_and_a_default_policy() {
    let env = Env::new();
    let r = env.bare_dir("p");
    let out = r.ok(&["init"]);
    assert!(out.contains("Initialized Veil repository in"), "{out}");
    assert!(r.path(".veil").is_dir());
    assert!(r.read(".veilpolicy").contains("target/"), "default policy ignores target/");
    // The fresh repository: one change on the root, recording the policy.
    assert_eq!(r.changes(), Vec::<String>::new());
    assert!(r.status().contains("A .veilpolicy"));
    let log = r.out(&["log"]);
    assert!(log.contains("root()"), "{log}");
    assert_eq!(r.snap("root"), r.snap("@-"));
}

// Scenario from git t0001-init.sh: init creates a new (deep) directory.
#[test]
fn init_creates_missing_deep_directories() {
    let env = Env::new();
    let r = env.bare_dir("base");
    r.ok(&["init", "a/b/c/d"]);
    assert!(r.path("a/b/c/d/.veil").is_dir());
    assert!(r.path("a/b/c/d/.veilpolicy").is_file());
    // `base` itself is not a repository.
    assert!(!r.path(".veil").exists());
}

// Scenario from git t0001-init.sh: a relative path argument.
#[test]
fn init_with_a_relative_path_outside_the_current_directory() {
    let env = Env::new();
    let r = env.bare_dir("here");
    r.ok(&["init", "../there"]);
    assert!(env.root.join("there/.veil").is_dir());
    assert!(!r.path(".veil").exists());
}

// Scenario from git t0001-init.sh "reinit": Veil refuses instead of
// re-initialising, and changes nothing.
#[test]
fn reinit_is_refused_and_changes_nothing() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    r.commit("one");
    let ops = r.op_count();
    let policy = r.read(".veilpolicy");
    let err = r.fails(&["init"]);
    assert!(err.contains("already exists"), "{err}");
    assert_eq!(r.op_count(), ops);
    assert_eq!(r.read(".veilpolicy"), policy);
    assert_eq!(r.paths("@-"), vec!["a.txt"]);
}

// Scenario from git t0001-init.sh "init notices EEXIST": the target is a file.
#[test]
fn init_on_a_regular_file_fails_cleanly() {
    let env = Env::new();
    let r = env.bare_dir("p");
    r.write("file", "x");
    r.fails(&["init", "file"]);
    assert_eq!(r.read("file"), "x");
}

// Scenario from git t0001-init.sh "init notices EPERM".
#[cfg(unix)]
#[test]
fn init_in_an_unwritable_directory_fails_and_leaves_nothing() {
    let env = Env::new();
    let r = env.bare_dir("ro");
    r.chmod(".", 0o555);
    let out = r.run(&["init"]);
    r.chmod(".", 0o755);
    if out.status.success() {
        // Running as root: permissions do not apply.
        return;
    }
    assert!(clean_exit(&out), "{}", text(&out));
    assert!(!r.path(".veil").exists(), "no half-made repository");
}

// Scenario from jj test_init.rs: init keeps a policy file already present
// (e.g. a checkout that ships one) and records existing files.
#[test]
fn init_keeps_an_existing_policy_and_records_existing_files() {
    let env = Env::new();
    let r = env.bare_dir("p");
    r.write(".veilpolicy", "*.log ignore\n");
    r.write("src/main.rs", "fn main() {}\n");
    r.write("debug.log", "noise\n");
    let out = r.ok(&["init"]);
    assert!(out.contains("recorded   2 files"), "{out}");
    assert_eq!(r.read(".veilpolicy"), "*.log ignore\n");
    assert_eq!(r.paths("@"), vec!["src/main.rs"]);
}

// Scenario from git t0001-init.sh (plain init over existing content), with
// Veil's invariant: secrets present at init are never recorded.
#[test]
fn init_lists_existing_secrets_as_local_only() {
    let env = Env::new();
    let r = env.bare_dir("p");
    r.write(".env", DOTENV);
    r.write("deploy/id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn\n-----END OPENSSH PRIVATE KEY-----\n");
    r.write("app.py", "print('hi')\n");
    let out = r.ok(&["init"]);
    assert!(out.contains("local-only"), "{out}");
    assert!(out.contains(".env"), "{out}");
    assert_eq!(r.paths("@"), vec!["app.py"]);
    assert!(!contains_bytes(&all_bytes(&r.path(".veil/objects")), "Xk29vLq8sPz"));
}

// Scenario from git t0001-init.sh with a Git checkout: `.git` is never recorded.
#[test]
fn init_in_a_git_checkout_does_not_record_dot_git() {
    let env = Env::new();
    let r = env.bare_dir("p");
    r.write(".git/HEAD", "ref: refs/heads/main\n");
    r.write(".git/config", "[core]\n");
    r.write("README", "hi\n");
    r.ok(&["init"]);
    assert_eq!(r.paths("@"), vec!["README"]);
}

// Scenario from git t0001-init.sh "plain nested": a repository inside a
// repository is independent; commands in it act on it alone.
#[test]
fn nested_repository_is_independent_of_the_outer_one() {
    let env = Env::new();
    let outer = env.repo("outer");
    outer.write("o.txt", "outer\n");
    outer.commit("outer one");
    let inner = env.bare_dir("outer/inner");
    inner.ok(&["init"]);
    inner.write("i.txt", "inner\n");
    inner.commit("inner one");
    assert_eq!(inner.paths("@-"), vec!["i.txt"]);
    assert!(inner.out(&["log"]).contains("inner one"));
    assert!(!inner.out(&["log"]).contains("outer one"));
}

// Scenario from git t0001-init.sh "plain nested" (Git records an embedded
// repository as a gitlink, never its files), with Veil's invariant: a file
// the inner repository cloaks is plaintext on disk, and the outer
// repository must not record it in public.
#[test]
#[ignore = "BUG-200: an enclosing repository records a nested Veil repository's working files, cloaked ones as public plaintext"]
fn outer_repository_does_not_record_a_nested_repositorys_cloaked_files() {
    let env = Env::new();
    let outer = env.repo("outer");
    outer.commit("outer");
    let inner = env.bare_dir("outer/inner");
    inner.ok(&["init"]);
    inner.ok(&["cloak", "secrets/"]);
    inner.write("secrets/plan.txt", SECRET_PLAN);
    inner.commit("inner");
    assert_eq!(inner.files("@-").iter().find(|f| f.path == "secrets/plan.txt").unwrap().vis, "cloaked:team");
    outer.ok(&["status"]);
    let leaked: Vec<FileLine> = outer.files("@").into_iter().filter(|f| f.path.starts_with("inner/")).collect();
    assert!(
        leaked.iter().all(|f| f.path != "inner/secrets/plan.txt" || f.vis != "public"),
        "the inner repository's cloaked file is recorded in public by the outer one: {leaked:?}"
    );
}

// Scenario from git t1500-rev-parse.sh "--show-toplevel from subdir" and
// t2300-cd-to-toplevel.sh: commands work from any subdirectory.
#[test]
fn commands_find_the_repository_from_a_deep_subdirectory() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a/b/c/f.txt", "x\n");
    let out = r.run_in("a/b/c", &["commit", "-m", "from deep"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(r.paths("@-"), vec!["a/b/c/f.txt"]);
}

// Scenario from git t1500-rev-parse.sh "--show-toplevel from inside .git".
#[test]
fn commands_work_from_inside_the_metadata_directory() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("f.txt", "x\n");
    let out = r.run_in(".veil", &["status"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(stdout_of(&out).contains("A f.txt"));
    // Nothing under .veil was recorded.
    assert_eq!(r.paths("@"), vec!["f.txt"]);
}

// Scenario from git t1515-rev-parse-outside-repo.sh / t1517-outside-repo.sh.
#[test]
fn repository_commands_outside_a_repository_fail_with_a_hint() {
    let env = Env::new();
    let r = env.bare_dir("nowhere");
    for args in [&["status"][..], &["log"], &["commit", "-m", "x"], &["files"], &["undo"], &["ws", "list"]] {
        let err = r.fails(args);
        assert!(err.contains("no Veil repository found"), "{args:?}: {err}");
        assert!(err.contains("vl init"), "{args:?}: {err}");
    }
    assert!(!r.path(".veil").exists());
}

// Scenario from git t0056-git-C.sh / jj test_global_opts.rs (`-R`).
#[test]
fn repository_option_works_from_anywhere() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("sub/f.txt", "x\n");
    let elsewhere = env.dir("elsewhere");
    let p = r.dir.to_str().unwrap();
    let out = env.run_as("alice", &elsewhere, &["-R", p, "commit", "-m", "remote control"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(r.paths("@-"), vec!["sub/f.txt"]);
    // A subdirectory of a repository is accepted too.
    let sub = r.path("sub");
    let out = env.run_as("alice", &elsewhere, &["-R", sub.to_str().unwrap(), "log", "-n", "1"]);
    assert!(out.status.success(), "{}", text(&out));
    // A path that is no repository fails cleanly.
    let out = env.run_as("alice", &elsewhere, &["-R", env.root.join("missing").to_str().unwrap(), "status"]);
    assert!(!out.status.success() && clean_exit(&out), "{}", text(&out));
}

// Scenario from git t1504-ceiling-dirs.sh: discovery stops at the first
// repository going upwards (the nearest one wins).
#[test]
fn discovery_uses_the_nearest_enclosing_repository() {
    let env = Env::new();
    let outer = env.repo("outer");
    let inner = env.bare_dir("outer/a/inner");
    inner.ok(&["init"]);
    inner.write("deep/x.txt", "x\n");
    let out = inner.run_in("deep", &["commit", "-m", "inner commit"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(inner.out(&["log"]).contains("inner commit"));
    assert!(!outer.out(&["log"]).contains("inner commit"));
}

// Scenario from jj test_init.rs: the first command creates the identity.
#[test]
fn first_use_creates_an_identity_with_private_permissions() {
    let env = Env::new();
    let r = env.bare_dir("p");
    let out = r.ok(&["init"]);
    assert!(out.contains("Created new identity for 'alice'"), "{out}");
    let id = env.root.join("home-alice/identity.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&id).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // A second repository reuses it.
    let r2 = env.bare_dir("q");
    let out = r2.ok(&["init"]);
    assert!(!out.contains("Created new identity"), "{out}");
}

// Scenario from git t0001-init.sh "init in long base path".
#[test]
fn init_and_commit_in_a_long_base_path() {
    let env = Env::new();
    let long: String = (0..12).map(|i| format!("segment-number-{i:02}-of-a-long-path/")).collect();
    let r = env.bare_dir(&long);
    r.ok(&["init"]);
    r.write("f.txt", "x\n");
    r.commit("long");
    assert_eq!(r.paths("@-"), vec!["f.txt"]);
}

// Scenario from jj test_root.rs: the root snapshot is empty and cannot be
// edited or described.
#[test]
fn the_root_snapshot_is_empty_and_immutable() {
    let env = Env::new();
    let r = env.repo("p");
    assert!(r.out(&["files", "-r", "root"]).is_empty());
    let err = r.fails(&["edit", "root"]);
    assert!(err.contains("root"), "{err}");
    r.fails(&["describe", "-r", "root", "-m", "nope"]);
    r.fails(&["abandon", "root"]);
    assert_eq!(r.change("root"), "z".repeat(32));
}
