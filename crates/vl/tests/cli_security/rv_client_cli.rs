//! Whole-codebase review, client area (`rv-client`, 2026-11-10): the
//! reproductions of BUG-1840 to BUG-1849 that concern keys, secrets at rest
//! and what `vl` prints. Each test states the guarantee, asserts that its
//! action succeeded, then checks the guarantee.

use crate::adversarial_support;

use std::{os::unix::fs::PermissionsExt, process::Command};

use adversarial_support::*;

/// `c`, run under `umask MASK` (the usual `022`, whatever the test runner's is).
fn with_umask(c: &Command, mask: &str) -> Command {
    let mut sh = Command::new("sh");
    sh.arg("-c").arg(format!("umask {mask}; exec \"$0\" \"$@\"")).arg(c.get_program()).args(c.get_args());
    for (k, v) in c.get_envs() {
        match v {
            Some(v) => sh.env(k, v),
            None => sh.env_remove(k),
        };
    }
    if let Some(d) = c.get_current_dir() {
        sh.current_dir(d);
    }
    sh
}

/// `docs/VISIBILITY.md`: secrets are "decrypted only on the devices of
/// people who have access to them"; `docs/ARCHITECTURE.md`, "Threat model":
/// "the network, and other OS users on the same machine" are not trusted.
/// `vl` keeps every other plain copy of a secret owner-only (sandboxes
/// `0700`/`0600`, the Veil home, the daemon's store).
///
/// A checkout decrypts a sealed `.env` into the working copy. Under the
/// usual umask (`022`) the plain text must not be readable by other users
/// of the machine.
#[test]
fn bug_1843_a_checked_out_secret_is_readable_by_its_owner_only() {
    const SECRET: &str = "Xk29vLq8sPzQw7LmTr4Bn6Yc";
    let env = Env::new();
    let proj = env.project(
        "alice",
        "proj",
        &[("a.txt", "a\n"), ("billing/.env", &format!("API_KEY={SECRET}\n"))],
    );
    let base_policy = std::fs::read_to_string(proj.join(".veilpolicy")).unwrap();
    write(&proj, ".veilpolicy", &format!("{base_policy}\n.env.example public!\n"));
    env.ok("alice", &proj, &["policy", "accept"]);
    write(&proj, ".env.example", "API_KEY=placeholder\n");
    env.ok("alice", &proj, &["commit", "-m", "public example"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    let ls = env.ok("alice", &proj, &["ls", "-r", "main"]);
    assert!(ls.lines().any(|l| l.contains("cloaked") && l.ends_with("billing/.env")), "billing/.env is a sealed secret:\n{ls}");

    // Alice's second clone (she holds the key), under the usual umask.
    let dest = env.root.join("clone");
    let clone = env.cmd("alice", &env.root, &["clone", proj.to_str().unwrap(), dest.to_str().unwrap()]);
    let out = with_umask(&clone, "022").output().unwrap();
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(read(&dest, "billing/.env"), format!("API_KEY={SECRET}\n"), "the clone decrypted the secret");
    // The umask is the one asked for: ordinary public files are 0644.
    let mode = |rel: &str| std::fs::metadata(dest.join(rel)).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode("a.txt"), 0o644, "an ordinary file follows the umask");
    assert_eq!(mode(".env.example"), 0o644, "a public .env.example follows the umask");

    assert_eq!(
        mode("billing/.env"),
        0o600,
        "the decrypted secret billing/.env is mode {:o}: other users of this machine can read it",
        mode("billing/.env")
    );

    // Executable sealed secrets become 0700 (not 0755), and a file that was
    // previously 0644 when public becomes 0600 once sealed and checked out.
    write(&proj, "billing/.env.run", &format!("#!/bin/sh\nexport KEY={SECRET}\n"));
    std::fs::set_permissions(proj.join("billing/.env.run"), std::fs::Permissions::from_mode(0o755)).unwrap();
    write(&proj, ".veilpolicy", &format!("{base_policy}\nbilling/.env.run cloak\n.env.example cloak\n"));
    env.ok("alice", &proj, &["policy", "accept"]);
    write(&proj, ".env.example", &format!("API_KEY={SECRET}\n"));
    env.ok("alice", &proj, &["commit", "-m", "seal executable and existing"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);

    env.ok("alice", &dest, &["pull"]);
    let co = env.cmd("alice", &dest, &["new", "origin/main"]);
    let out = with_umask(&co, "002").output().unwrap();
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(mode("billing/.env.run"), 0o700, "executable decrypted secret must be 0700");
    assert_eq!(mode(".env.example"), 0o600, "newly sealed secret replacing a 0644 file must be 0600");

    // `vl secret recover` restores an isolated secret owner-only (0600), even under umask 002.
    write(&dest, "server.pem", &format!("-----BEGIN PRIVATE KEY-----\n{SECRET}\n-----END PRIVATE KEY-----\n"));
    env.ok("alice", &dest, &["isolate", "server.pem"]);
    env.ok("alice", &dest, &["status"]);
    std::fs::remove_file(dest.join("server.pem")).unwrap();
    let recover = env.cmd("alice", &dest, &["secret", "recover", "server.pem"]);
    let out = with_umask(&recover, "002").output().unwrap();
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(mode("server.pem"), 0o600, "recovered isolated secret must be 0600");
}
