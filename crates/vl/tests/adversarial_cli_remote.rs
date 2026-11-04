//! Adversarial CLI tests: `vl clone` / `vl pull` from hostile repositories.

mod adversarial_support;

use std::path::Path;

use adversarial_support::*;

#[test]
#[ignore = "BUG-001: tree entry names are not validated; `vl clone` of a hostile remote writes outside the destination"]
fn clone_cannot_write_outside_the_destination() {
    let env = Env::new();
    let remote = env.dir("remote");
    evil_remote_on_disk(&remote, "innocent", &["main"], |r| {
        let payload = blob(r, b"#!/bin/sh\necho owned\n");
        let inner = raw_tree(r, vec![file("PWNED.sh", payload)]);
        let up = raw_tree(r, vec![dir("..", inner)]);
        raw_tree(r, vec![dir("..", up), file("README", blob(r, b"hi\n"))])
    });
    let work = env.dir("work");
    let out = env.vl("victim", &work, &["clone", remote.to_str().unwrap(), "dest"]);
    let escaped: Vec<String> = tree_listing(&env.root)
        .into_iter()
        .filter(|p| p.ends_with("PWNED.sh"))
        .collect();
    assert!(escaped.is_empty(), "clone wrote {escaped:?} outside work/dest\n{}", text(&out));
}

#[test]
#[ignore = "BUG-001: tree entry names are not validated; `vl pull` + `vl new` writes outside the working copy"]
fn pull_and_new_cannot_write_outside_the_working_copy() {
    let env = Env::new();
    let proj = env.project("victim", "proj", &[("a.txt", "a\n")]);
    let remote = env.dir("remote");
    evil_remote_on_disk(&remote, "update", &["upstream"], |r| {
        let inner = raw_tree(r, vec![file("victim-home-file", blob(r, b"clobbered\n"))]);
        raw_tree(r, vec![dir("..", inner)])
    });
    env.ok("victim", &proj, &["remote", "add", "origin", remote.to_str().unwrap()]);
    env.vl("victim", &proj, &["pull", "origin"]);
    env.vl("victim", &proj, &["new", "upstream"]);
    assert!(!env.root.join("victim-home-file").exists(), "checkout escaped the project directory");
}

#[test]
#[ignore = "BUG-002: checkout writes tree entries named '.veil', so a remote can replace key rings, config and op log"]
fn clone_cannot_overwrite_repository_metadata() {
    let env = Env::new();
    let remote = env.dir("remote");
    evil_remote_on_disk(&remote, "innocent", &["main"], |r| {
        let cfg = blob(r, br#"{"format":1,"repo_id":"0000","remotes":{"origin":{"url":"/tmp/attacker-controlled","public":false}}}"#);
        raw_tree(r, vec![dir(".veil", raw_tree(r, vec![file("repo.json", cfg)])), file("README", blob(r, b"hi\n"))])
    });
    let work = env.dir("work");
    let out = env.vl("victim", &work, &["clone", remote.to_str().unwrap(), "dest"]);
    let cfg = std::fs::read_to_string(work.join("dest/.veil/repo.json")).unwrap_or_default();
    assert!(!cfg.contains("attacker-controlled"), "remote rewrote .veil/repo.json:\n{cfg}\n{}", text(&out));
    let remotes = env.vl("victim", &work.join("dest"), &["remote", "list"]);
    assert!(!text(&remotes).contains("attacker"), "{}", text(&remotes));
}

#[test]
#[ignore = "BUG-027: recursive tree walks (Transfer::copy, diff_trees, checkout) overflow the stack on deeply nested hostile trees"]
fn deeply_nested_remote_tree_does_not_crash_clone() {
    let env = Env::new();
    let remote = env.dir("remote");
    evil_remote_on_disk(&remote, "deep", &["main"], |r| {
        let mut t = raw_tree(r, vec![file("leaf", blob(r, b"x"))]);
        for _ in 0..60_000 {
            t = raw_tree(r, vec![dir("d", t)]);
        }
        t
    });
    let work = env.dir("work");
    let out = env.vl("victim", &work, &["clone", remote.to_str().unwrap(), "dest"]);
    assert!(
        out.status.code().is_some(),
        "vl was killed by a signal ({:?}): {}",
        out.status,
        text(&out).lines().last().unwrap_or("")
    );
}

#[test]
#[ignore = "BUG-028: remote-controlled tag names, descriptions and authors are printed raw; terminal escape sequences are injected"]
fn remote_metadata_cannot_inject_terminal_escapes() {
    let env = Env::new();
    let remote = env.dir("remote");
    evil_remote_on_disk(
        &remote,
        "fix typo\x1b]0;owned-title\x07\x1b[2J\x1b]8;;https://evil.example\x07click\x1b]8;;\x07",
        &["main", "v1\x1b[1A\x1b[2Kfake-line"],
        |r| raw_tree(r, vec![file("README", blob(r, b"hi\n"))]),
    );
    let work = env.dir("work");
    let mut outputs = vec![env.vl("victim", &work, &["clone", remote.to_str().unwrap(), "dest"])];
    let dest = work.join("dest");
    for args in [&["log"][..], &["tag", "list"], &["show", "main"], &["pull", "origin"]] {
        outputs.push(env.vl("victim", &dest, args));
    }
    for o in &outputs {
        assert!(!text(o).contains('\x1b'), "raw ESC from the remote reached the terminal:\n{:?}", text(o));
    }
}

#[test]
fn clone_of_a_tampered_remote_fails_cleanly_and_leaves_no_partial_tags() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "honest\n")]);
    let remote = env.dir("remote");
    env.ok("alice", &proj, &["remote", "add", "origin", remote.to_str().unwrap()]);
    env.ok("alice", &proj, &["push", "origin"]);
    // flip a byte in every blob object on the remote
    for f in tree_listing(&remote.join(".veil/objects")) {
        let p = remote.join(".veil/objects").join(&f);
        if p.is_file() {
            let mut b = std::fs::read(&p).unwrap();
            if b.starts_with(b"veil:blob\n") {
                let n = b.len() - 1;
                b[n] ^= 1;
                std::fs::write(&p, b).unwrap();
            }
        }
    }
    let work = env.dir("work");
    let out = env.vl("bob", &work, &["clone", remote.to_str().unwrap(), "dest"]);
    assert!(exited_cleanly(&out), "{}", text(&out));
    assert!(!out.status.success(), "clone of tampered objects succeeded");
}

#[test]
fn clone_of_a_non_repository_fails_cleanly() {
    let env = Env::new();
    let empty = env.dir("empty");
    let work = env.dir("work");
    for src in [empty.to_str().unwrap(), "/nonexistent/path", "/dev/null"] {
        let out = env.vl("bob", &work, &["clone", src, "dest"]);
        assert!(exited_cleanly(&out) && !out.status.success(), "{src}: {}", text(&out));
    }
    let out = env.vl("bob", &work, &["clone", empty.to_str().unwrap(), "../../../../tmp"]);
    assert!(exited_cleanly(&out), "{}", text(&out));
}

#[test]
fn public_push_withholds_cloaked_files_and_isolated_secrets() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    write(&proj, ".env", "DB=postgres://ISOLATED-SECRET\n");
    write(&proj, "secrets/k.txt", "CLOAKED-SECRET\n");
    write(&proj, "pub.txt", "public\n");
    env.ok("alice", &proj, &["cloak", "secrets/"]);
    env.ok("alice", &proj, &["commit", "-m", "c"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    let mirror = env.dir("mirror");
    env.ok("alice", &proj, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    env.ok("alice", &proj, &["push", "mirror"]);
    for f in tree_listing(&mirror) {
        let p = mirror.join(&f);
        if p.is_file() {
            let b = std::fs::read(&p).unwrap();
            for needle in [&b"ISOLATED-SECRET"[..], b"CLOAKED-SECRET"] {
                assert!(!b.windows(needle.len()).any(|w| w == needle), "{f} leaks {}", String::from_utf8_lossy(needle));
            }
        }
    }
    let work = env.dir("work");
    env.ok("bob", &work, &["clone", mirror.to_str().unwrap(), "dest"]);
    assert!(!Path::new(&work.join("dest/.env")).exists());
    assert!(!Path::new(&work.join("dest/secrets/k.txt")).exists());
    assert_eq!(read(&work.join("dest"), "pub.txt"), "public\n");
}

