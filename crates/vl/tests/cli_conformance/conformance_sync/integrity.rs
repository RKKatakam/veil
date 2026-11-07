//! `vl fsck`, corruption of Veil's CAS (local and remote), repair with
//! `--full`, and interrupted transfers (kill -9).

use std::{path::PathBuf, time::Duration};

use super::support::*;

fn repo_with_history(env: &Env) -> PathBuf {
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    write(&proj, "a.txt", "first version of a\n");
    write(&proj, "dir/b.txt", "bee\n");
    env.ok("alice", &proj, &["commit", "-m", "one"]);
    write(&proj, "a.txt", "second version of a\n");
    env.ok("alice", &proj, &["commit", "-m", "two"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    proj
}

fn fsck(env: &Env, dir: &std::path::Path) -> (i32, String) {
    env.code("alice", dir, &["--no-snapshot", "fsck"])
}

// Scenario from git t1450-fsck.sh: "setup" / a fresh, empty repository is clean.
#[test]
fn fsck_of_a_fresh_repository_is_clean() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    let (code, out) = fsck(&env, &proj);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("No corruption found"), "{out}");
}

// Scenario from git t1450-fsck.sh: "object with hash mismatch".
#[test]
fn fsck_reports_a_loose_object_whose_content_does_not_match_its_hash() {
    let env = Env::new();
    let proj = repo_with_history(&env);
    let f = loose_object_containing(&proj, "first version of a").expect("loose blob");
    flip_byte(&f, -2);
    let (code, out) = fsck(&env, &proj);
    assert_eq!(code, 1, "{out}");
    let id = format!(
        "{}{}",
        f.parent().unwrap().file_name().unwrap().to_string_lossy(),
        f.file_name().unwrap().to_string_lossy()
    );
    assert!(
        out.contains("does not match its hash") && out.contains(&id),
        "{out}"
    );
}

// Scenario from git t1450-fsck.sh: "missing blob" referenced by an old commit.
#[test]
fn fsck_reports_a_missing_object_of_old_history() {
    let env = Env::new();
    let proj = repo_with_history(&env);
    let f = loose_object_containing(&proj, "first version of a").unwrap();
    std::fs::remove_file(&f).unwrap();
    let (code, out) = fsck(&env, &proj);
    assert_eq!(code, 1, "{out}");
    assert!(out.to_lowercase().contains("missing"), "{out}");
    // The current version is still readable.
    assert_eq!(
        env.stdout(
            "alice",
            &proj,
            &["--no-snapshot", "cat", "a.txt", "-r", "main"]
        ),
        "second version of a\n"
    );
}

// Scenario from git t1450-fsck.sh: "zero-length object" / truncated object file.
#[test]
fn fsck_reports_an_empty_object_file() {
    let env = Env::new();
    let proj = repo_with_history(&env);
    let f = loose_object_containing(&proj, "bee").unwrap();
    truncate_file(&f, 0);
    let (code, out) = fsck(&env, &proj);
    assert_eq!(code, 1, "{out}");
}

// Scenario from git t1450-fsck.sh: "fsck notices broken commit" (a damaged snapshot).
#[test]
fn fsck_reports_a_damaged_snapshot() {
    let env = Env::new();
    let proj = repo_with_history(&env);
    let f = loose_objects(&proj)
        .into_iter()
        .find(|p| {
            std::fs::read(p).unwrap().starts_with(b"veil:snap")
                && contains(&std::fs::read(p).unwrap(), "\"one\"")
        })
        .expect("the snapshot of `one`");
    let raw = String::from_utf8(std::fs::read(&f).unwrap()).unwrap();
    std::fs::write(&f, raw.replace("\"one\"", "\"0ne\"")).unwrap();
    let (code, out) = fsck(&env, &proj);
    assert_eq!(code, 1, "{out}");
}

// Scenario from git t1450-fsck.sh: "fsck notices garbage files" (reported, not an error).
#[test]
fn fsck_notes_garbage_files_in_the_object_store() {
    let env = Env::new();
    let proj = repo_with_history(&env);
    write(&proj, ".veil/objects/ab/not-an-object", "junk");
    let (code, out) = env.code("alice", &proj, &["--no-snapshot", "fsck", "-v"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("unexpected entry .veil/objects/ab/not-an-object"),
        "{out}"
    );
}

// Scenario from git t1450-fsck.sh: a broken operation log (Veil's refs) is corruption.
#[test]
fn fsck_reports_a_damaged_operation() {
    let env = Env::new();
    let proj = repo_with_history(&env);
    let ops: Vec<String> = listing(&proj.join(".veil/ops"));
    let first = proj.join(".veil/ops").join(&ops[0]);
    std::fs::write(&first, "garbage").unwrap();
    let (code, out) = fsck(&env, &proj);
    assert_eq!(code, 1, "{out}");
}

// Scenario from git t1450-fsck.sh: damaged metadata (Veil: a key ring) is corruption.
#[test]
fn fsck_reports_a_damaged_key_ring() {
    let env = Env::new();
    let proj = repo_with_history(&env);
    std::fs::write(
        proj.join(".veil/meta/keyrings/team.json"),
        "{\"garbage\": 1}",
    )
    .unwrap();
    let (code, out) = fsck(&env, &proj);
    assert_eq!(code, 1, "{out}");
}

// Scenario from git t1450-fsck.sh: fsck changes nothing.
#[test]
fn fsck_writes_nothing_even_with_unrecorded_edits() {
    let env = Env::new();
    let proj = repo_with_history(&env);
    write(&proj, "a.txt", "unrecorded\n");
    let before = listing(&proj.join(".veil"));
    env.ok("alice", &proj, &["fsck"]);
    // The listing includes the operation heads (`op_heads/`).
    assert_eq!(listing(&proj.join(".veil")), before);
}

// Scenario from git t1450-fsck.sh: "fsck reports dangling objects" (not an error).
#[test]
fn fsck_counts_unreachable_objects_after_gc_packed_them() {
    let env = Env::new();
    let proj = repo_with_history(&env);
    env.ok("alice", &proj, &["abandon", "main"]);
    let out = env.ok("alice", &proj, &["gc", "--keep-ops-days", "0"]);
    assert!(
        !out.contains(" 0 pending deletion"),
        "gc kept some unreachable objects: {out}"
    );
    let (code, out) = fsck(&env, &proj);
    assert_eq!(code, 0, "{out}");
    assert!(
        !out.contains("; 0 unreachable)"),
        "fsck sees no unreachable object although gc kept them: {out}"
    );
}

// Scenario from git t1450-fsck.sh / t5303-pack-corruption-resilience.sh: a damaged pack.
#[test]
fn fsck_reports_a_damaged_pack() {
    let env = Env::new();
    let proj = repo_with_history(&env);
    env.ok("alice", &proj, &["gc"]);
    let pack = packs(&proj).pop().unwrap();
    let len = std::fs::metadata(&pack).unwrap().len();
    truncate_file(&pack, len / 2);
    let (code, out) = fsck(&env, &proj);
    assert_eq!(code, 1, "{out}");
}

// Scenario from git t1450-fsck.sh: `fsck` outside a repository fails cleanly.
#[test]
fn fsck_outside_a_repository_fails() {
    let env = Env::new();
    let nowhere = env.dir("nowhere");
    env.fails("alice", &nowhere, &["fsck"]);
}

// Veil: a damaged local object is detected by push and never sent.
#[test]
fn a_corrupt_local_object_is_detected_by_push_and_not_sent() {
    let env = Env::new();
    let (alice, hub) = env.project_with_hub("alice", "alice", "hub", &[("a.txt", "a\n")]);
    write(&alice, "new.txt", &"fresh payload 777 ".repeat(30));
    env.ok("alice", &alice, &["commit", "-m", "new"]);
    let f = loose_object_containing(&alice, "fresh payload 777").unwrap();
    flip_byte(&f, -3);
    let out = env.fails("alice", &alice, &["--no-snapshot", "push"]);
    assert!(out.contains("corrupt"), "{out}");
    let (code, out) = env.code("alice", &env.root, &["fsck", "-R", hub.to_str().unwrap()]);
    assert_eq!(code, 0, "{out}");
    assert!(!open_repo(&hub)
        .view()
        .tags
        .values()
        .any(|t| t.target.short() == env.tag_target("alice", &alice, "main").unwrap()));
}

// Veil: a remote whose operation head is garbage fails pull cleanly and changes nothing.
#[test]
fn a_remote_with_a_broken_op_head_fails_pull_cleanly() {
    let env = Env::new();
    let (alice, hub) = env.project_with_hub("alice", "alice", "hub", &[("a.txt", "a\n")]);
    let bob = env.clone("bob", &hub, "bob");
    let _ = alice;
    std::fs::write(hub.join(".veil/op_head"), "garbage").unwrap();
    let ops = op_count(&bob);
    env.fails("bob", &bob, &["--no-snapshot", "pull"]);
    assert_eq!(op_count(&bob), ops);
    env.fails(
        "carol",
        &env.root,
        &["clone", hub.to_str().unwrap(), "carol"],
    );
    assert!(!env.path("carol").exists());
}

// Scenario from git t5600 (transport failure cleanup) + interrupted transfer: kill -9 during a
// push leaves a remote that fsck accepts and the next push completes.
#[test]
fn a_push_killed_midway_leaves_a_consistent_remote() {
    let env = Env::new();
    let (alice, hub) = env.project_with_hub("alice", "alice", "hub", &[("a.txt", "a\n")]);
    for i in 0..12 {
        write_bytes(&alice, &format!("bulk/f{i}.bin"), &noise(400_000, i + 1));
    }
    env.ok("alice", &alice, &["commit", "-m", "bulk"]);
    for delay in [5u64, 30, 120] {
        let mut child = env.spawn("alice", &alice, &["--no-snapshot", "push"]);
        std::thread::sleep(Duration::from_millis(delay));
        let _ = child.kill();
        let _ = child.wait();
        let (code, out) = env.code("alice", &env.root, &["fsck", "-R", hub.to_str().unwrap()]);
        assert_eq!(code, 0, "after kill at {delay} ms: {out}");
    }
    env.ok("alice", &alice, &["push"]);
    let bob = env.clone("bob", &hub, "bob");
    assert_eq!(
        std::fs::read(bob.join("bulk/f3.bin")).unwrap(),
        noise(400_000, 4)
    );
}

// Interrupted transfer: kill -9 during a pull leaves a consistent local repository.
#[test]
fn a_pull_killed_midway_leaves_a_consistent_repository() {
    let env = Env::new();
    let (alice, hub) = env.project_with_hub("alice", "alice", "hub", &[("a.txt", "a\n")]);
    let bob = env.clone("bob", &hub, "bob");
    for i in 0..12 {
        write_bytes(&alice, &format!("bulk/f{i}.bin"), &noise(400_000, 100 + i));
    }
    env.ok("alice", &alice, &["commit", "-m", "bulk"]);
    env.ok("alice", &alice, &["push"]);
    for delay in [5u64, 40, 150] {
        let mut child = env.spawn("bob", &bob, &["--no-snapshot", "pull"]);
        std::thread::sleep(Duration::from_millis(delay));
        let _ = child.kill();
        let _ = child.wait();
        let (code, out) = env.code("bob", &bob, &["--no-snapshot", "fsck"]);
        assert_eq!(code, 0, "after kill at {delay} ms: {out}");
    }
    env.ok("bob", &bob, &["pull"]);
    env.ok("bob", &bob, &["rebase", "-d", "main"]);
    assert_eq!(
        std::fs::read(bob.join("bulk/f0.bin")).unwrap(),
        noise(400_000, 100)
    );
}

// Interrupted clone: kill -9 mid-clone, then a fresh clone into the same place works.
#[test]
fn a_clone_killed_midway_can_be_redone() {
    let env = Env::new();
    let (alice, hub) = env.project_with_hub("alice", "alice", "hub", &[("a.txt", "a\n")]);
    for i in 0..10 {
        write_bytes(&alice, &format!("bulk/f{i}.bin"), &noise(400_000, 200 + i));
    }
    env.ok("alice", &alice, &["commit", "-m", "bulk"]);
    env.ok("alice", &alice, &["push"]);
    let dest = env.path("bob");
    let mut child = env.spawn(
        "bob",
        &env.root,
        &["clone", hub.to_str().unwrap(), dest.to_str().unwrap()],
    );
    std::thread::sleep(Duration::from_millis(60));
    let _ = child.kill();
    let _ = child.wait();
    if dest.exists() {
        std::fs::remove_dir_all(&dest).unwrap();
    }
    env.clone("bob", &hub, "bob");
    assert_eq!(
        std::fs::read(dest.join("bulk/f9.bin")).unwrap(),
        noise(400_000, 209)
    );
    let (code, out) = env.code("bob", &dest, &["fsck"]);
    assert_eq!(code, 0, "{out}");
}

// Veil: `fsck -R` checks a bare remote, and is read-only there too.
#[test]
fn fsck_dash_r_checks_a_remote_without_writing_to_it() {
    let env = Env::new();
    let (_alice, hub) = env.project_with_hub("alice", "alice", "hub", &[("a.txt", "a\n")]);
    let before = listing(&hub);
    let out = env.ok("bob", &env.root, &["fsck", "-R", hub.to_str().unwrap()]);
    assert!(out.contains("No corruption found"), "{out}");
    assert_eq!(listing(&hub), before);
}
