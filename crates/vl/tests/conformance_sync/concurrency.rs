//! Concurrent pushes and pulls against one remote, and concurrent commands
//! in one repository (jj test_concurrent_operations.rs, test_bad_locking.rs).

use std::path::PathBuf;

use crate::support::*;

fn clones(env: &Env, n: usize) -> (PathBuf, Vec<PathBuf>) {
    let (_alice, hub) = env.project_with_hub("alice", "alice", "hub", &[("a.txt", "a\n")]);
    let cs = (0..n)
        .map(|i| env.clone(&format!("u{i}"), &hub, &format!("c{i}")))
        .collect();
    (hub, cs)
}

// Scenario from jj test_concurrent_operations.rs: several clients push different tags at once.
#[test]
fn concurrent_pushes_of_different_tags_all_land() {
    let env = Env::new();
    let (hub, cs) = clones(&env, 5);
    for (i, c) in cs.iter().enumerate() {
        let u = format!("u{i}");
        env.ok(&u, c, &["new", "main"]);
        env.commit(
            &u,
            c,
            &format!("work {i}"),
            &[(&format!("w{i}.txt"), &format!("{i}\n"))],
        );
        env.ok(
            &u,
            c,
            &[
                "tag",
                "set",
                &format!("topic-{i}"),
                "-r",
                "@-",
                "--allow-backwards",
            ],
        );
    }
    let kids: Vec<_> = cs
        .iter()
        .enumerate()
        .map(|(i, c)| {
            env.spawn(
                &format!("u{i}"),
                c,
                &["--no-snapshot", "push", "-t", &format!("topic-{i}")],
            )
        })
        .collect();
    let mut failed = Vec::new();
    for (i, k) in kids.into_iter().enumerate() {
        let out = k.wait_with_output().unwrap();
        assert!(exited_cleanly(&out), "{}", text(&out));
        if !out.status.success() {
            failed.push(i);
        }
    }
    // A lock timeout is acceptable; a retry must then succeed.
    for i in failed {
        env.ok(
            &format!("u{i}"),
            &cs[i],
            &["push", "-t", &format!("topic-{i}")],
        );
    }
    let tags = open_repo(&hub).view().tags.clone();
    for i in 0..5 {
        assert!(
            tags.contains_key(&format!("topic-{i}")),
            "topic-{i} lost: {:?}",
            tags.keys()
        );
    }
    let (code, out) = env.code("alice", &env.root, &["fsck", "-R", hub.to_str().unwrap()]);
    assert_eq!(code, 0, "{out}");
}

// Scenario from jj test_concurrent_operations.rs / git t5516: concurrent pushes of the same
// tag from diverged clones: one wins, the others are rejected, nothing is corrupted.
#[test]
fn concurrent_pushes_of_the_same_tag_have_one_winner() {
    let env = Env::new();
    let (hub, cs) = clones(&env, 4);
    for (i, c) in cs.iter().enumerate() {
        env.commit(
            &format!("u{i}"),
            c,
            &format!("race {i}"),
            &[("race.txt", &format!("{i}\n"))],
        );
    }
    let kids: Vec<_> = cs
        .iter()
        .enumerate()
        .map(|(i, c)| env.spawn(&format!("u{i}"), c, &["--no-snapshot", "push"]))
        .collect();
    let outs: Vec<_> = kids
        .into_iter()
        .map(|k| k.wait_with_output().unwrap())
        .collect();
    let winners: Vec<usize> = outs
        .iter()
        .enumerate()
        .filter(|(_, o)| text(o).contains("pushed main"))
        .map(|(i, _)| i)
        .collect();
    for o in &outs {
        assert!(exited_cleanly(o), "{}", text(o));
    }
    assert_eq!(
        winners.len(),
        1,
        "{:?}",
        outs.iter().map(text).collect::<Vec<_>>()
    );
    let w = winners[0];
    let remote_main = open_repo(&hub).view().tags["main"].target.short();
    assert_eq!(
        Some(remote_main),
        env.tag_target(&format!("u{w}"), &cs[w], "main")
    );
    let (code, out) = env.code("alice", &env.root, &["fsck", "-R", hub.to_str().unwrap()]);
    assert_eq!(code, 0, "{out}");
}

// Scenario from jj test_concurrent_operations.rs: pull while another client pushes.
#[test]
fn pulls_concurrent_with_pushes_see_a_consistent_state() {
    let env = Env::new();
    let (hub, cs) = clones(&env, 3);
    let pusher = &cs[0];
    for i in 0..4 {
        write_bytes(pusher, &format!("p{i}.bin"), &noise(50_000, i));
        env.ok("u0", pusher, &["commit", "-m", &format!("p{i}")]);
    }
    let push = env.spawn("u0", pusher, &["--no-snapshot", "push"]);
    let pulls: Vec<_> = (1..3)
        .map(|i| env.spawn(&format!("u{i}"), &cs[i], &["--no-snapshot", "pull"]))
        .collect();
    let out = push.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", text(&out));
    for (i, p) in pulls.into_iter().enumerate() {
        let out = p.wait_with_output().unwrap();
        assert!(exited_cleanly(&out), "{}", text(&out));
        let c = &cs[i + 1];
        let u = format!("u{}", i + 1);
        let (code, f) = env.code(&u, c, &["--no-snapshot", "fsck"]);
        assert_eq!(code, 0, "{f}");
        env.ok(&u, c, &["pull"]);
        assert_eq!(
            env.tag_target(&u, c, "main"),
            env.tag_target("u0", pusher, "main")
        );
    }
    let (code, out) = env.code("alice", &env.root, &["fsck", "-R", hub.to_str().unwrap()]);
    assert_eq!(code, 0, "{out}");
}

// Scenario from jj test_concurrent_operations.rs: two pulls into the same repository at once.
#[test]
fn two_concurrent_pulls_into_one_repository() {
    let env = Env::new();
    let (alice, hub) = env.project_with_hub("alice", "alice", "hub", &[("a.txt", "a\n")]);
    let bob = env.clone("bob", &hub, "bob");
    env.commit("alice", &alice, "two", &[("a.txt", "two\n")]);
    env.ok("alice", &alice, &["push"]);
    let kids: Vec<_> = (0..3)
        .map(|_| env.spawn("bob", &bob, &["--no-snapshot", "pull"]))
        .collect();
    for k in kids {
        let out = k.wait_with_output().unwrap();
        assert!(exited_cleanly(&out), "{}", text(&out));
        assert!(
            out.status.success() || text(&out).contains("locked"),
            "{}",
            text(&out)
        );
    }
    assert_eq!(
        env.tag_target("bob", &bob, "main"),
        env.tag_target("alice", &alice, "main")
    );
    env.ok("bob", &bob, &["fsck"]);
    let ops = env.stdout("bob", &bob, &["op", "log", "-n", "100"]);
    assert!(ops.contains("pull from origin"), "{ops}");
}

// Scenario from jj test_concurrent_operations.rs: a push concurrent with local commits.
#[test]
fn push_concurrent_with_local_commits() {
    let env = Env::new();
    let (alice, hub) = env.project_with_hub("alice", "alice", "hub", &[("a.txt", "a\n")]);
    env.commit("alice", &alice, "pushed", &[("p.txt", "p\n")]);
    env.ok("alice", &alice, &["ws", "new", "side", "-r", "main"]);
    let push = env.spawn("alice", &alice, &["--no-snapshot", "push"]);
    let exec = env.spawn(
        "alice",
        &alice,
        &[
            "ws",
            "exec",
            "side",
            "-m",
            "meanwhile",
            "--",
            "sh",
            "-c",
            "echo m > m.txt",
        ],
    );
    for k in [push, exec] {
        let out = k.wait_with_output().unwrap();
        assert!(out.status.success(), "{}", text(&out));
    }
    assert_eq!(
        env.stdout("alice", &alice, &["ws", "cat", "side", "m.txt"]),
        "m\n"
    );
    assert_eq!(
        open_repo(&hub).view().tags["main"].target.short(),
        env.tag_target("alice", &alice, "main").unwrap()
    );
    env.ok("alice", &alice, &["fsck"]);
}

// Scenario from jj test_bad_locking.rs: a leftover lock of a dead process on a path remote is
// taken over by the next push.
#[test]
fn a_push_killed_while_holding_the_remote_lock_does_not_block_the_next() {
    let env = Env::new();
    let (alice, hub) = env.project_with_hub("alice", "alice", "hub", &[("a.txt", "a\n")]);
    for i in 0..8 {
        write_bytes(&alice, &format!("b{i}.bin"), &noise(500_000, 50 + i));
    }
    env.ok("alice", &alice, &["commit", "-m", "bulk"]);
    let mut k = env.spawn("alice", &alice, &["--no-snapshot", "push"]);
    // Wait for the remote lock to appear (or the push to finish), then kill.
    wait_for(std::time::Duration::from_secs(10), || {
        hub.join(".veil/lock").exists() || k.try_wait().unwrap().is_some()
    });
    let _ = k.kill();
    let _ = k.wait();
    let start = std::time::Instant::now();
    env.ok("alice", &alice, &["push"]);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(20),
        "took {:?}",
        start.elapsed()
    );
    assert!(!hub.join(".veil/lock").exists());
    let bob = env.clone("bob", &hub, "bob");
    assert_eq!(
        std::fs::read(bob.join("b7.bin")).unwrap(),
        noise(500_000, 57)
    );
}

// Known race (docs/BACKLOG.md, "concurrent first pushes to an empty remote"): the loser may
// fail, but cleanly, and a retry succeeds.
#[test]
fn concurrent_first_pushes_to_an_empty_remote_end_consistent() {
    let env = Env::new();
    let projs: Vec<PathBuf> = (0..3)
        .map(|i| {
            env.project(
                &format!("u{i}"),
                &format!("p{i}"),
                &[(&format!("f{i}"), "x\n")],
            )
        })
        .collect();
    let hub = env.path("fresh-hub");
    for (i, p) in projs.iter().enumerate() {
        let u = format!("u{i}");
        env.ok(&u, p, &["tag", "set", &format!("t{i}"), "-r", "main"]);
        env.ok(&u, p, &["remote", "add", "origin", hub.to_str().unwrap()]);
    }
    let kids: Vec<_> = projs
        .iter()
        .enumerate()
        .map(|(i, p)| {
            env.spawn(
                &format!("u{i}"),
                p,
                &["--no-snapshot", "push", "-t", &format!("t{i}")],
            )
        })
        .collect();
    let outs: Vec<_> = kids
        .into_iter()
        .map(|k| k.wait_with_output().unwrap())
        .collect();
    for (i, o) in outs.iter().enumerate() {
        assert!(exited_cleanly(o), "{}", text(o));
        if !o.status.success() {
            env.ok(
                &format!("u{i}"),
                &projs[i],
                &["push", "-t", &format!("t{i}")],
            );
        }
    }
    let tags = open_repo(&hub).view().tags.clone();
    for i in 0..3 {
        assert!(tags.contains_key(&format!("t{i}")), "{:?}", tags.keys());
    }
    let (code, out) = env.code("u0", &env.root, &["fsck", "-R", hub.to_str().unwrap()]);
    assert_eq!(code, 0, "{out}");
}
