//! `vl clone` from path remotes: destinations, failures and cleanup, empty
//! repositories, which tag the working copy starts on.

use super::support::*;

// Scenario from git t5601-clone.sh: "clone" of a repository with history.
#[test]
fn clone_copies_history_tags_and_files_and_sets_origin() {
    let env = Env::new();
    let (proj, hub) = env.project_with_hub(
        "alice",
        "proj",
        "hub",
        &[("a.txt", "a\n"), ("d/b.txt", "b\n")],
    );
    env.commit("alice", &proj, "second", &[("a.txt", "a2\n")]);
    env.ok("alice", &proj, &["push"]);
    let copy = env.clone("bob", &hub, "copy");
    assert_eq!(read(&copy, "a.txt"), "a2\n");
    assert_eq!(read(&copy, "d/b.txt"), "b\n");
    let log = env.stdout("bob", &copy, &["log"]);
    assert!(log.contains("second") && log.contains("initial"), "{log}");
    let tags = env.tags("bob", &copy);
    assert_eq!(tags, vec!["main".to_string(), "origin/main".to_string()]);
    let remotes = env.stdout("bob", &copy, &["remote", "list"]);
    assert!(
        remotes.starts_with("origin") && remotes.contains("team"),
        "{remotes}"
    );
    assert!(
        remotes.contains(hub.to_str().unwrap()),
        "the clone stores the absolute source path: {remotes}"
    );
    // The working copy is a new, empty change on main.
    let st = env.ok("bob", &copy, &["status"]);
    assert!(st.contains("no changes"), "{st}");
}

// Scenario from git t5603-clone-dirname.sh: the default directory is the source's last path component.
#[test]
fn clone_without_a_destination_uses_the_last_path_component() {
    let env = Env::new();
    let (_proj, _hub) = env.project_with_hub("alice", "proj", "srv/team-repo", &[("a", "a\n")]);
    let work = env.dir("work");
    let out = env.ok("bob", &work, &["clone", "../srv/team-repo"]);
    assert!(out.contains("Cloned"), "{out}");
    assert_eq!(read(&work.join("team-repo"), "a"), "a\n");
    // A trailing slash names the same directory.
    let work2 = env.dir("work2");
    env.ok("bob", &work2, &["clone", "../srv/team-repo/"]);
    assert!(work2.join("team-repo/a").exists());
}

// Scenario from git t5603-clone-dirname.sh: `.git` suffixes are stripped; Veil keeps
// the component as is (deliberate: documented as "the source's last path component").
#[test]
fn clone_keeps_a_dot_veil_suffix_in_the_default_directory_name() {
    let env = Env::new();
    let (_proj, _hub) = env.project_with_hub("alice", "proj", "proj.veil", &[("a", "a\n")]);
    let work = env.dir("work");
    env.ok("bob", &work, &["clone", "../proj.veil"]);
    assert!(work.join("proj.veil/a").exists());
}

// Scenario from git t5600-clone-fail-cleanup.sh: "clone of non-existent source should fail"
// and "failed clone should not leave a directory".
#[test]
fn clone_of_a_missing_source_fails_and_leaves_nothing() {
    let env = Env::new();
    let out = env.fails("bob", &env.root, &["clone", "does-not-exist", "dest"]);
    assert!(out.contains("not found"), "{out}");
    assert!(!env.path("dest").exists());
}

// Scenario from git t5605-clone-local.sh: "cloning non-git directory fails".
#[test]
fn clone_of_a_directory_that_is_not_a_repository_fails_and_leaves_nothing() {
    let env = Env::new();
    let plain = env.dir("plain");
    write(&plain, "x.txt", "x\n");
    let out = env.fails("bob", &env.root, &["clone", "plain", "dest"]);
    assert!(out.contains("Veil repository"), "{out}");
    assert!(!env.path("dest").exists());
    assert_eq!(listing(&plain), vec!["x.txt"], "the source is untouched");
}

// Scenario from git t5600-clone-fail-cleanup.sh: "failed clone into empty leaves directory".
#[test]
fn a_failed_clone_into_an_existing_empty_directory_leaves_it_empty() {
    let env = Env::new();
    let dest = env.dir("dest");
    env.fails("bob", &env.root, &["clone", "does-not-exist", "dest"]);
    assert!(dest.exists() && listing(&dest).is_empty());
    // A source that fails half way (a corrupt object) cleans up too.
    let (proj, hub) = env.project_with_hub(
        "alice",
        "proj",
        "hub",
        &[("big.txt", &"payload ".repeat(400))],
    );
    let _ = proj;
    let corrupt = env.path("corrupt");
    copy_dir(&hub, &corrupt);
    let pack = packs(&corrupt).pop().expect("a pack");
    let len = std::fs::metadata(&pack).unwrap().len() as isize;
    flip_byte(&pack, len / 2);
    env.fails("bob", &env.root, &["clone", "corrupt", "dest"]);
    assert!(
        dest.exists() && listing(&dest).is_empty(),
        "{:?}",
        listing(&dest)
    );
}

// Scenario from git t5601-clone.sh: cloning into a non-empty directory fails without touching it.
#[test]
fn clone_into_a_non_empty_directory_is_refused_and_leaves_it_alone() {
    let env = Env::new();
    let (_proj, hub) = env.project_with_hub("alice", "proj", "hub", &[("a", "a\n")]);
    let dest = env.dir("dest");
    write(&dest, "mine.txt", "keep me\n");
    let out = env.fails("bob", &env.root, &["clone", hub.to_str().unwrap(), "dest"]);
    assert!(out.contains("not empty"), "{out}");
    assert_eq!(listing(&dest), vec!["mine.txt"]);
    assert_eq!(read(&dest, "mine.txt"), "keep me\n");
}

// Scenario from git t5601-clone.sh: clone into an existing empty directory works.
#[test]
fn clone_into_an_existing_empty_directory_works() {
    let env = Env::new();
    let (_proj, hub) = env.project_with_hub("alice", "proj", "hub", &[("a", "a\n")]);
    let dest = env.dir("dest");
    env.ok(
        "bob",
        &env.root,
        &["clone", hub.to_str().unwrap(), dest.to_str().unwrap()],
    );
    assert_eq!(read(&dest, "a"), "a\n");
}

// Scenario from git t5605-clone-local.sh: "clone empty repository" and
// "clone empty repository, and then push should not segfault".
#[test]
fn clone_of_an_empty_repository_then_push_back() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["remote", "add", "origin", "../hub"]);
    let out = env.ok("alice", &proj, &["push"]);
    assert!(out.contains("Pushed 0 object(s)"), "{out}");
    let copy = env.clone("bob", &env.path("hub"), "copy");
    let out = env.stdout("bob", &copy, &["log"]);
    assert!(out.contains("root()"), "{out}");
    assert!(env.tags("bob", &copy).is_empty());
    env.commit("bob", &copy, "first from the clone", &[("b.txt", "b\n")]);
    env.ok("bob", &copy, &["tag", "set", "main", "-r", "@-"]);
    let out = env.ok("bob", &copy, &["push"]);
    assert!(out.contains("pushed main"), "{out}");
    env.ok("alice", &proj, &["pull"]);
    assert_eq!(
        env.stdout("alice", &proj, &["cat", "b.txt", "-r", "main"]),
        "b\n"
    );
}

// Scenario from git t5609-clone-branch.sh: "vanilla clone chooses HEAD"; Veil picks main,
// then trunk, then master, then the first tag.
#[test]
fn clone_starts_on_main_then_trunk_then_master_then_the_first_tag() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["remote", "add", "origin", "../hub"]);
    let make = |tag: &str, file: &str| {
        env.ok("alice", &proj, &["new", "root"]);
        write(&proj, file, &format!("{tag}\n"));
        env.ok("alice", &proj, &["commit", "-m", tag]);
        env.ok("alice", &proj, &["tag", "set", tag, "-r", "@-"]);
    };
    make("alpha", "alpha.txt");
    make("master", "master.txt");
    env.ok("alice", &proj, &["push"]);
    let c1 = env.clone("bob", &env.path("hub"), "c1");
    assert!(
        c1.join("master.txt").exists() && !c1.join("alpha.txt").exists(),
        "{:?}",
        listing(&c1)
    );
    make("trunk", "trunk.txt");
    env.ok("alice", &proj, &["push"]);
    let c2 = env.clone("bob", &env.path("hub"), "c2");
    assert!(
        c2.join("trunk.txt").exists() && !c2.join("master.txt").exists(),
        "{:?}",
        listing(&c2)
    );
    make("main", "main.txt");
    env.ok("alice", &proj, &["push"]);
    let c3 = env.clone("bob", &env.path("hub"), "c3");
    assert!(
        c3.join("main.txt").exists() && !c3.join("trunk.txt").exists(),
        "{:?}",
        listing(&c3)
    );
}

// Scenario from git t5609-clone-branch.sh: a repository without the usual names starts on its first tag.
#[test]
fn clone_of_a_repository_without_main_starts_on_its_first_tag() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    write(&proj, "r.txt", "release\n");
    env.ok("alice", &proj, &["commit", "-m", "release"]);
    env.ok("alice", &proj, &["tag", "set", "release-1", "-r", "@-"]);
    env.ok("alice", &proj, &["remote", "add", "origin", "../hub"]);
    env.ok("alice", &proj, &["push"]);
    let c = env.clone("bob", &env.path("hub"), "c");
    assert_eq!(read(&c, "r.txt"), "release\n");
}

// Scenario from git t5605-clone-local.sh: cloning a non-bare repository (with a working copy).
#[test]
fn clone_of_a_repository_with_a_working_copy() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    write(&proj, "wip.txt", "not tagged\n");
    let c = env.clone("bob", &proj, "c");
    assert_eq!(read(&c, "a"), "a\n");
    assert!(!c.join("wip.txt").exists(), "only tagged history travels");
    // Alice's directory is unaffected by being cloned.
    assert_eq!(read(&proj, "wip.txt"), "not tagged\n");
    env.ok("alice", &proj, &["status"]);
}

// Scenario from jj test_git_clone.rs: the clone is an independent repository (fsck, commit, gc).
#[test]
fn a_clone_is_complete_and_independent_of_its_source() {
    let env = Env::new();
    let (_proj, hub) = env.project_with_hub("alice", "proj", "hub", &[("a", "a\n")]);
    let c = env.clone("bob", &hub, "c");
    std::fs::remove_dir_all(&hub).unwrap();
    let out = env.ok("bob", &c, &["fsck"]);
    assert!(out.contains("No corruption found"), "{out}");
    assert_eq!(env.stdout("bob", &c, &["cat", "a", "-r", "main"]), "a\n");
    env.commit("bob", &c, "offline", &[("b", "b\n")]);
    env.ok("bob", &c, &["gc", "--prune-now"]);
    env.ok("bob", &c, &["fsck"]);
    let out = env.fails("bob", &c, &["pull"]);
    assert!(
        out.contains("not found") || out.contains("No such file"),
        "{out}"
    );
}

// Scenario from git t5601-clone.sh: special characters in file names survive a clone.
#[test]
fn clone_preserves_odd_names_modes_and_bytes() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    write(&proj, "with space.txt", "s\n");
    write(&proj, "-leading-dash", "d\n");
    write(&proj, "ünïcödé/naïve.txt", "u\n");
    write(&proj, "empty", "");
    write(&proj, "nonl", "no newline");
    write_bytes(&proj, "bin.dat", &[0u8, 1, 2, 255, 0, 10, 13]);
    write(&proj, &format!("{}leaf", "deep/".repeat(39)), "x");
    write(&proj, "run.sh", "#!/bin/sh\n");
    set_mode(&proj.join("run.sh"), 0o755);
    env.ok("alice", &proj, &["commit", "-m", "odd"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["remote", "add", "origin", "../hub"]);
    env.ok("alice", &proj, &["push"]);
    let c = env.clone("bob", &env.path("hub"), "c");
    for f in [
        "with space.txt",
        "-leading-dash",
        "ünïcödé/naïve.txt",
        "empty",
        "nonl",
        "bin.dat",
        "run.sh",
    ] {
        assert_eq!(
            std::fs::read(c.join(f)).unwrap(),
            std::fs::read(proj.join(f)).unwrap(),
            "{f}"
        );
    }
    assert!(is_executable(&c.join("run.sh")));
    assert!(!is_executable(&c.join("nonl")));
    let deep: Vec<String> = listing(&c)
        .into_iter()
        .filter(|p| p.starts_with("deep/"))
        .collect();
    assert_eq!(deep.len(), 1);
    assert_eq!(deep[0].matches('/').count(), 39);
}

// Scenario from git t5601-clone.sh: cloning a repository whose source path has spaces and Unicode.
#[test]
fn clone_from_a_source_path_with_spaces_and_unicode() {
    let env = Env::new();
    let (_proj, hub) = env.project_with_hub("alice", "proj", "my hub ünï", &[("a", "a\n")]);
    let c = env.clone("bob", &hub, "dest with space");
    assert_eq!(read(&c, "a"), "a\n");
    env.commit("bob", &c, "b", &[("b", "b\n")]);
    env.ok("bob", &c, &["push"]);
}

// Scenario from git t5601-clone.sh: clone a clone (a chain of remotes).
#[test]
fn clone_of_a_clone_has_the_same_snapshot_ids() {
    let env = Env::new();
    let (proj, hub) = env.project_with_hub("alice", "proj", "hub", &[("a", "a\n")]);
    let c1 = env.clone("bob", &hub, "c1");
    let c2 = env.clone("carol", &c1, "c2");
    let want = env.tag_target("alice", &proj, "main").unwrap();
    assert_eq!(env.tag_target("bob", &c1, "main").unwrap(), want);
    assert_eq!(env.tag_target("carol", &c2, "main").unwrap(), want);
    // c2's origin is c1, not the hub.
    assert!(env.stdout("carol", &c2, &["remote", "list"]).contains("c1"));
}

// Scenario from jj test_git_clone.rs ("clone with a cloaked file, no key"): the clone shows
// the cloaked file as redacted and fills it in after a grant.
#[test]
fn clone_before_a_grant_gets_redactions_then_the_file_after_grant_and_pull() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["cloak", "secrets/"]);
    write(&proj, "secrets/notes.md", "internal notes\n");
    write(&proj, "README", "hi\n");
    env.ok("alice", &proj, &["commit", "-m", "c"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["remote", "add", "origin", "../hub"]);
    env.ok("alice", &proj, &["push"]);
    let c = env.clone("bob", &env.path("hub"), "c");
    assert!(!c.join("secrets/notes.md").exists());
    let st = env.ok("bob", &c, &["status"]);
    assert!(st.contains("secrets/notes.md"), "{st}");
    let key = env.pubkey("bob");
    env.ok(
        "alice",
        &proj,
        &["scope", "grant", "team", &key, "--name", "bob"],
    );
    env.ok("alice", &proj, &["push"]);
    let out = env.ok("bob", &c, &["pull"]);
    assert!(out.contains("Filled in 1 file"), "{out}");
    assert_eq!(read(&c, "secrets/notes.md"), "internal notes\n");
}
