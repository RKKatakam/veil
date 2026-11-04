//! The synced team vault (`vl secret --scope`, `vl run`), through the real
//! binary.

use std::path::{Path, PathBuf};

use crate::{
    adversarial_support::{text, Env},
    public_key, vl_stdin,
};

/// Alice's project (with `scripts/env.sh`, a file any teammate could have
/// committed) and a team remote `origin`; Bob granted `team` with his full
/// key and cloned; Alice alone in scope `prod`, whose team vault holds
/// `PROD_DB_PASSWORD`.
fn setup(env: &Env) -> (PathBuf, PathBuf) {
    let proj = env.project(
        "alice",
        "proj",
        &[("README", "hi\n"), ("scripts/env.sh", "echo \"EXFIL:$PROD_DB_PASSWORD\" >&2\n")],
    );
    let team = env.root.join("team");
    env.ok("alice", &proj, &["remote", "add", "origin", team.to_str().unwrap()]);
    let bob = public_key(env, "bob");
    env.ok("alice", &proj, &["scope", "grant", "team", &bob, "--name", "bob"]);
    env.ok("alice", &proj, &["scope", "create", "prod"]);
    env.ok("alice", &proj, &["secret", "set", "--scope", "prod", "PROD_DB_PASSWORD", "prod-canary-6b1f"]);
    env.ok("alice", &proj, &["push"]);
    let bob_dir = env.root.join("bob");
    env.ok("bob", &env.root, &["clone", team.to_str().unwrap(), bob_dir.to_str().unwrap()]);
    (proj, bob_dir)
}

fn bob_sets(env: &Env, bob: &Path, name: &str, value: &str) {
    let out = vl_stdin(env, "bob", bob, &["secret", "set", "--scope", "team", name], value.as_bytes());
    assert!(out.status.success(), "{}", text(&out));
}

// ---- BUG-520: team-vault entries control the loader and the shell ----------

/// Control: an ordinary team secret reaches the command.
#[test]
fn run_injects_an_ordinary_team_secret() {
    let env = Env::new();
    let (proj, bob) = setup(&env);
    bob_sets(&env, &bob, "STAGING_URL", "https://staging.example");
    env.ok("bob", &bob, &["push"]);
    env.ok("alice", &proj, &["pull"]);
    let out = env.vl("alice", &proj, &["run", "--scope", "team", "--", "/bin/sh", "-c", "printf %s \"$STAGING_URL\""]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "https://staging.example", "{}", text(&out));
}

/// Bob, a member of `team` only, stores `BASH_ENV` (and `PATH`,
/// `LD_PRELOAD`) in the team vault. `vl run` loads every scope Alice
/// belongs to by default and lets the team vault override her
/// environment, so her `vl run -- bash …` sources a script of Bob's choice
/// with `prod`'s secrets in its environment: a member of one scope reads
/// another scope's team vault, and runs code on every teammate's machine.
/// Variables that decide what code runs (`BASH_ENV`, `ENV`, `PATH`,
/// `LD_*`, `DYLD_*`, `NODE_OPTIONS`, …) must not come from a team vault.
#[test]
fn a_team_member_cannot_take_over_vl_run_through_loader_variables() {
    let env = Env::new();
    let (proj, bob) = setup(&env);
    bob_sets(&env, &bob, "BASH_ENV", "scripts/env.sh");
    bob_sets(&env, &bob, "LD_PRELOAD", "/tmp/bob-evil-preload.so");
    bob_sets(&env, &bob, "PATH", "/tmp/bob-evil-bin");
    env.ok("bob", &bob, &["push"]);
    env.ok("alice", &proj, &["pull"]);
    let out = env.vl("alice", &proj, &["run", "--", "/bin/bash", "-c", "printf '%s|%s' \"$LD_PRELOAD\" \"$PATH\""]);
    let all = text(&out);
    assert!(
        !all.contains("EXFIL:prod-canary-6b1f"),
        "Bob's BASH_ENV script ran inside Alice's `vl run` and read scope prod's secret:\n{all}"
    );
    assert!(!all.contains("bob-evil"), "Bob's LD_PRELOAD / PATH reached Alice's command:\n{all}");
    // Even with both scopes loaded on purpose (explicitly, or as this
    // device's default), the team vault never sets those variables, and
    // says so.
    for args in [
        &["run", "--scope", "team", "--scope", "prod", "--"][..],
        &["run", "--scope", "team", "--scope", "prod", "--remember", "--"][..],
        &["run", "--"][..],
    ] {
        let mut args = args.to_vec();
        args.extend(["/bin/bash", "-c", "printf '%s|%s|%s' \"$LD_PRELOAD\" \"$PATH\" \"${PROD_DB_PASSWORD:+prod-loaded}\""]);
        let out = env.vl("alice", &proj, &args);
        let all = text(&out);
        assert!(out.status.success(), "{all}");
        assert!(String::from_utf8_lossy(&out.stdout).ends_with("|prod-loaded"), "{all}");
        assert!(!all.contains("EXFIL:prod-canary-6b1f") && !all.contains("bob-evil"), "{args:?}:\n{all}");
        assert!(all.contains("not setting BASH_ENV, LD_PRELOAD, PATH"), "{all}");
    }
}

// ---- BUG-523: one member's large entries break every member's vl run -------

/// Bob stores 40 entries of 64 000 bytes each (each within the documented
/// 64 KiB limit; there is no limit on their number or total). Every
/// teammate's plain `vl run -- CMD` (which loads every scope) then fails
/// with "Argument list too long", with no hint which scope or entry is to
/// blame, or that `--scope` / `--local-only` avoids it.
///
/// Since the fix a scope holds at most 256 KiB in all, so Bob's fifth
/// entry is refused (the original test stored all 40, which the fix
/// forbids), and the command runs with every scope loaded. `vl run`'s own
/// size report is unit-tested in `team_secret.rs` (`too_big…`).
#[test]
fn many_large_entries_do_not_break_everyones_vl_run() {
    let env = Env::new();
    let (proj, bob) = setup(&env);
    let value = "x".repeat(64_000);
    for i in 0..4 {
        bob_sets(&env, &bob, &format!("BLOB_{i:02}"), &value);
    }
    let out = vl_stdin(&env, "bob", &bob, &["secret", "set", "--scope", "team", "BLOB_04"], value.as_bytes());
    assert!(!out.status.success() && text(&out).contains("KiB"), "{}", text(&out));
    env.ok("bob", &bob, &["push"]);
    env.ok("alice", &proj, &["pull"]);
    let out = env.vl("alice", &proj, &["run", "--scope", "team", "--scope", "prod", "--", "/bin/sh", "-c", "echo ran"]);
    let all = text(&out);
    // Where the system takes less (a 2 MiB stack limit lowers ARG_MAX to
    // 512 KiB on Linux), three full scopes are too much: `vl run` names the
    // scopes and their entries instead of passing on E2BIG.
    if cfg!(target_os = "linux") {
        env.ok("alice", &proj, &["scope", "create", "ops"]);
        for (scope, i) in [("prod", 0), ("prod", 1), ("prod", 2), ("prod", 3), ("ops", 0), ("ops", 1), ("ops", 2), ("ops", 3)] {
            let out = vl_stdin(&env, "alice", &proj, &["secret", "set", "--scope", scope, &format!("{}_{i}", scope.to_uppercase())], value.as_bytes());
            assert!(out.status.success(), "{}", text(&out));
        }
        let small = std::process::Command::new("/bin/sh")
            .args(["-c", "ulimit -s 2048 && exec \"$0\" \"$@\"", env!("CARGO_BIN_EXE_vl")])
            .args(["run", "--scope", "team", "--scope", "prod", "--scope", "ops", "--", "/bin/sh", "-c", "echo ran"])
            .envs(env.cmd("alice", &proj, &[]).get_envs().filter_map(|(k, v)| Some((k, v?))))
            .current_dir(&proj)
            .output()
            .unwrap();
        let t = text(&small);
        assert!(
            !small.status.success() && t.contains("scope 'team' adds") && t.contains("BLOB_0") && t.contains("scope 'prod'")
                && t.contains("--local-only"),
            "{t}"
        );
    }
    let explained = all.contains("'team'") && all.contains("--scope");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("ran") || explained,
        "Alice's `vl run` neither ran the command nor said which scope is too big:\n{}",
        &all[..all.len().min(400)]
    );
}
