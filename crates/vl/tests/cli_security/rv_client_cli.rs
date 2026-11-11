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
#[ignore = "BUG-1843: a checkout writes a decrypted secret file with the umask's mode (0644): other OS users read it"]
fn bug_1843_a_checked_out_secret_is_readable_by_its_owner_only() {
    const SECRET: &str = "Xk29vLq8sPzQw7LmTr4Bn6Yc";
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n"), ("billing/.env", &format!("API_KEY={SECRET}\n"))]);
    let ls = env.ok("alice", &proj, &["ls", "-r", "main"]);
    assert!(ls.lines().any(|l| l.contains("cloaked") && l.ends_with("billing/.env")), "billing/.env is a sealed secret:\n{ls}");

    // Alice's second clone (she holds the key), under the usual umask.
    let dest = env.root.join("clone");
    let clone = env.cmd("alice", &env.root, &["clone", proj.to_str().unwrap(), dest.to_str().unwrap()]);
    let out = with_umask(&clone, "022").output().unwrap();
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(read(&dest, "billing/.env"), format!("API_KEY={SECRET}\n"), "the clone decrypted the secret");
    // The umask is the one asked for: an ordinary file is 0644.
    let mode = |rel: &str| std::fs::metadata(dest.join(rel)).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode("a.txt"), 0o644, "an ordinary file follows the umask");

    assert_eq!(
        mode("billing/.env") & 0o077,
        0,
        "the decrypted secret billing/.env is mode {:o}: other users of this machine can read it",
        mode("billing/.env")
    );
}
