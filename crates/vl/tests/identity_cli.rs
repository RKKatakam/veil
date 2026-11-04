//! Replacing the identity (`vl identity new --force`) and the local vault,
//! whose key is derived from the identity (BUG-027).

mod adversarial_support;

use adversarial_support::*;

fn project_with_vault(env: &Env, name: &str) -> std::path::PathBuf {
    let proj = env.project("alice", name, &[("a.txt", "a\n")]);
    write(&proj, ".env", "X=1\n");
    env.ok("alice", &proj, &["status"]);
    env.ok("alice", &proj, &["secret", "set", "TOKEN", &format!("t-{name}")]);
    proj
}

#[test]
fn replacing_the_identity_keeps_vaults_recoverable() {
    let env = Env::new();
    let here = project_with_vault(&env, "here");
    let other = project_with_vault(&env, "other");

    // Run inside `here`: its vault is re-keyed on the spot.
    let out = env.ok("alice", &here, &["identity", "new", "--force"]);
    assert!(out.contains("Re-keyed the local vault"), "{out}");
    assert_eq!(env.stdout("alice", &here, &["secret", "get", "TOKEN"]).trim(), "t-here");

    // The replaced identity is kept, owner-only.
    let retired: Vec<_> = std::fs::read_dir(env.root.join("home-alice/retired"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(retired.len(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&retired[0]).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "retired identity is private ({mode:o})");
    }

    // `other` keeps working; only the vault's content is out of reach, with
    // a message saying what to do.
    env.ok("alice", &other, &["status"]);
    env.ok("alice", &other, &["log"]);
    let out = env.vl("alice", &other, &["secret", "get", "TOKEN"]);
    assert!(!out.status.success() && text(&out).contains("recover-vault"), "{}", text(&out));
    // Nothing overwrites the old vault meanwhile.
    write(&other, ".env", "X=2\n");
    env.ok("alice", &other, &["status"]);
    assert!(!env.vl("alice", &other, &["secret", "set", "NEW", "v"]).status.success());

    let out = env.ok("alice", &other, &["identity", "recover-vault"]);
    assert!(out.contains("Re-keyed"), "{out}");
    assert_eq!(env.stdout("alice", &other, &["secret", "get", "TOKEN"]).trim(), "t-other");
    env.ok("alice", &other, &["status"]);
    let out = env.ok("alice", &other, &["identity", "recover-vault"]);
    assert!(out.contains("nothing to do"), "{out}");
}

#[test]
fn a_vault_without_its_identity_never_bricks_the_repository() {
    let env = Env::new();
    let proj = project_with_vault(&env, "proj");
    env.ok("alice", &proj, &["identity", "new", "--force"]);
    // Re-keyed already; simulate a vault sealed by an identity that is gone
    // for good: replace the identity again from outside the repository and
    // delete everything it retired.
    env.ok("alice", &env.root, &["identity", "new", "--force"]);
    std::fs::remove_dir_all(env.root.join("home-alice/retired")).unwrap();

    for args in [&["status"][..], &["log"], &["commit", "-m", "still works"], &["files"]] {
        env.ok("alice", &proj, args);
    }
    let out = env.vl("alice", &proj, &["identity", "recover-vault"]);
    assert!(!out.status.success() && text(&out).contains("none of 0"), "{}", text(&out));
    let out = env.vl("alice", &proj, &["secret", "list"]);
    assert!(!out.status.success() && text(&out).contains("sealed by"), "{}", text(&out));
    // The documented way out: delete the vault and start over.
    std::fs::remove_file(proj.join(".veil/local/vault.sealed")).unwrap();
    env.ok("alice", &proj, &["secret", "set", "K", "v"]);
    assert_eq!(env.stdout("alice", &proj, &["secret", "get", "K"]).trim(), "v");
}
