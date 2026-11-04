//! Large files and many files (git t1050-large.sh) through commit, push,
//! clone, pull, gc, fsck and the Git bridge.

use std::path::Path;

use crate::support::*;

const MIB: usize = 1024 * 1024;

fn dir_size(dir: &Path) -> u64 {
    listing(dir)
        .iter()
        .map(|f| std::fs::metadata(dir.join(f)).map(|m| m.len()).unwrap_or(0))
        .sum()
}

// Scenario from git t1050-large.sh: "add a large file or two", "checkout a large file",
// "cat-file a large file", "fsck large blobs".
#[test]
fn a_large_binary_file_round_trips_through_push_clone_and_cat() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    let big = noise(5 * MIB, 7);
    write_bytes(&proj, "assets/big.bin", &big);
    write_bytes(&proj, "assets/big2.bin", &noise(2 * MIB, 8));
    env.ok("alice", &proj, &["commit", "-m", "large"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    let out = env.vl("alice", &proj, &["cat", "assets/big.bin", "-r", "main"]);
    assert!(out.status.success());
    assert_eq!(out.stdout, big, "cat of a large file");
    env.ok("alice", &proj, &["remote", "add", "origin", "../hub"]);
    env.ok("alice", &proj, &["push"]);
    let bob = env.clone("bob", &env.path("hub"), "bob");
    assert_eq!(std::fs::read(bob.join("assets/big.bin")).unwrap(), big);
    let files = env.stdout("bob", &bob, &["files", "-r", "main"]);
    assert!(files.contains(&(5 * MIB).to_string()), "{files}");
    env.ok("bob", &bob, &["fsck"]);
}

/// Two versions of a `size`-byte incompressible file differing in 64 bytes,
/// pushed, cloned, gc'd. Returns the clone's object storage after gc.
fn two_versions_after_gc(size: usize) -> u64 {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    let mut big = noise(size, 11);
    write_bytes(&proj, "big.bin", &big);
    env.ok("alice", &proj, &["commit", "-m", "v1"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["remote", "add", "origin", "../hub"]);
    env.ok("alice", &proj, &["push"]);
    big[size / 2..size / 2 + 64].copy_from_slice(&[b'Z'; 64]);
    write_bytes(&proj, "big.bin", &big);
    env.ok("alice", &proj, &["commit", "-m", "v2"]);
    env.ok("alice", &proj, &["push"]);
    let bob = env.clone("bob", &env.path("hub"), "bob");
    assert_eq!(std::fs::read(bob.join("big.bin")).unwrap(), big);
    env.ok("bob", &bob, &["gc", "--prune-now"]);
    assert_eq!(
        env.vl("bob", &bob, &["cat", "big.bin", "-r", "main-"])
            .stdout,
        noise(size, 11)
    );
    env.ok("bob", &bob, &["fsck"]);
    dir_size(&bob.join(".veil/objects"))
}

// Scenario from git t1050-large.sh: "repack" — gc stores a small edit of a file as a delta
// (Veil: deltas between versions of a path). Deltas against what the remote already
// holds (thin packs) are not done in 1.0 (docs/BACKLOG.md: chunking).
#[test]
fn gc_stores_a_small_edit_of_a_one_mib_file_as_a_delta() {
    let packed = two_versions_after_gc(MIB);
    assert!(
        packed < (MIB + MIB / 2) as u64,
        "two versions of a 1 MiB file take {packed} bytes after gc"
    );
}

// Same, above zstd's default window: the dictionary delta silently stops working.
#[test]
fn gc_stores_a_small_edit_of_a_four_mib_file_as_a_delta() {
    let packed = two_versions_after_gc(4 * MIB);
    assert!(
        packed < 6 * MIB as u64,
        "two versions of a 4 MiB file take {packed} bytes after gc"
    );
}

// Scenario from git t1050-large.sh: "diff --stat" / "diff --raw" on large binary files.
#[test]
fn diff_of_a_large_binary_file_does_not_dump_it() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    write_bytes(&proj, "big.bin", &noise(3 * MIB, 3));
    env.ok("alice", &proj, &["commit", "-m", "v1"]);
    write_bytes(&proj, "big.bin", &noise(3 * MIB, 4));
    let out = env.vl("alice", &proj, &["diff"]);
    assert!(out.status.success());
    assert!(
        out.stdout.len() < 64 * 1024,
        "diff printed {} bytes for a binary file",
        out.stdout.len()
    );
    let stat = env.ok("alice", &proj, &["diff", "--stat"]);
    assert!(stat.contains("big.bin"), "{stat}");
}

// Veil: a credential far into a large public file is still caught and never pushed.
#[test]
fn a_secret_deep_inside_a_large_file_is_quarantined() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    let mut body = "// generated\n".repeat(3 * MIB / 13).into_bytes();
    body.extend_from_slice(b"const k = \"AKIAZ7QXN4PL2WVR8TQM\";\nconst s = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY9\";\n");
    write_bytes(&proj, "gen/bundle.js", &body);
    let out = env.ok("alice", &proj, &["commit", "-m", "bundle"]);
    assert!(out.contains("quarantined"), "{out}");
    env.ok("alice", &proj, &["remote", "add", "origin", "../hub"]);
    env.ok("alice", &proj, &["push"]);
    assert_absent(
        &env.path("hub"),
        "AKIAZ7QXN4PL2WVR8TQM",
        "secret deep in a large file",
    );
}

// Scenario from git t1050-large.sh: many files (scale of a real tree) push and clone.
#[test]
fn two_thousand_small_files_push_and_clone() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    for i in 0..2000 {
        write(
            &proj,
            &format!("src/m{:02}/f{i}.txt", i % 40),
            &format!("file {i}\n"),
        );
    }
    env.ok("alice", &proj, &["commit", "-m", "many"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["remote", "add", "origin", "../hub"]);
    env.ok("alice", &proj, &["push"]);
    let bob = env.clone("bob", &env.path("hub"), "bob");
    let got = listing(&bob.join("src"));
    assert_eq!(got.len(), 2000);
    assert_eq!(read(&bob, "src/m07/f1047.txt"), "file 1047\n");
    // One more file: the next pull is incremental.
    env.commit("alice", &proj, "one more", &[("src/m00/new.txt", "new\n")]);
    env.ok("alice", &proj, &["push"]);
    let out = env.ok("bob", &bob, &["pull"]);
    assert!(
        out.contains("Pulled 5 object(s)"),
        "snapshot, three trees and a blob: {out}"
    );
}

// Scenario from git t1050-large.sh via the Git bridge: a large binary imported from Git and
// exported back is byte-identical (same blob id in Git).
#[test]
fn a_large_file_round_trips_through_the_git_bridge() {
    let env = Env::new();
    let (bare, wc) = git_upstream(&env, "gh.git", &[("README", "r\n")]);
    write_bytes(&wc, "big.bin", &noise(3 * MIB, 21));
    git_commit_push(&wc, "big");
    let blob = git(&bare, &["rev-parse", "main:big.bin"]);
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["git", "import", bare.to_str().unwrap()]);
    assert_eq!(
        std::fs::read(proj.join("big.bin")).unwrap(),
        noise(3 * MIB, 21)
    );
    // Export to a second, empty Git remote: same blob.
    let other = env.path("other.git");
    git(
        &env.root,
        &["init", "-q", "--bare", other.to_str().unwrap()],
    );
    env.ok(
        "alice",
        &proj,
        &["git", "remote", "add", "other", other.to_str().unwrap()],
    );
    env.ok("alice", &proj, &["git", "push", "other"]);
    assert_eq!(git(&other, &["rev-parse", "main:big.bin"]), blob);
}

// Scenario from git t1050-large.sh: an empty file, then a large one at the same path, then empty again.
#[test]
fn a_file_that_grows_large_and_shrinks_to_empty() {
    let env = Env::new();
    let (alice, hub) = env.project_with_hub("alice", "alice", "hub", &[("f.bin", "")]);
    let bob = env.clone("bob", &hub, "bob");
    write_bytes(&alice, "f.bin", &noise(2 * MIB, 5));
    env.ok("alice", &alice, &["commit", "-m", "grow"]);
    write(&alice, "f.bin", "");
    env.ok("alice", &alice, &["commit", "-m", "shrink"]);
    env.ok("alice", &alice, &["push"]);
    env.ok("bob", &bob, &["pull"]);
    assert_eq!(
        env.vl("bob", &bob, &["cat", "f.bin", "-r", "main-"]).stdout,
        noise(2 * MIB, 5)
    );
    assert_eq!(
        env.vl("bob", &bob, &["cat", "f.bin", "-r", "main"]).stdout,
        Vec::<u8>::new()
    );
}
