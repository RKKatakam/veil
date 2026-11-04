//! Veil-specific variants of the everyday scenarios above: the same
//! commands with an isolated `.env`, a quarantined credential and a cloaked
//! file. Whatever the command, plaintext secrets never reach a snapshot,
//! the object store, or output for someone who may not read them.

use crate::*;

fn objects(r: &R) -> Vec<u8> {
    all_bytes(&r.path(".veil"))
}

const DB_PASSWORD: &str = "Xk29vLq8sPz";

/// A repository with `.env` (isolated), `secrets/plan.txt` (cloaked) and a
/// public file, committed once.
fn protected(env: &Env) -> (R<'_>, String) {
    let r = env.repo("p");
    r.ok(&["cloak", "secrets/"]);
    r.write(".env", DOTENV);
    r.write("secrets/plan.txt", SECRET_PLAN);
    r.write("app.py", "print('hi')\n");
    let c = r.commit("protected");
    (r, c)
}

fn assert_no_plaintext(r: &R, what: &str) {
    let o = objects(r);
    assert!(!contains_bytes(&o, DB_PASSWORD), "{what}: the .env value is stored in plaintext under .veil");
    assert!(!contains_bytes(&o, SECRET_PLAN), "{what}: the cloaked text is stored in plaintext under .veil");
}

// Scenario from git t3700-add.sh / t7501 with Veil's tiers: commit stores
// the cloaked file sealed and the isolated one not at all.
#[test]
fn commit_never_stores_isolated_or_cloaked_plaintext() {
    let env = Env::new();
    let (r, c) = protected(&env);
    assert_eq!(r.paths(c.as_str()), vec!["app.py", "secrets/plan.txt"]);
    assert_no_plaintext(&r, "after commit");
}

// Scenario from git t7201-co.sh / jj test_edit_command.rs across a
// checkout round trip: the isolated file stays on disk, the cloaked file
// comes back, nothing leaks.
#[test]
fn checkout_round_trips_keep_protection() {
    let env = Env::new();
    let (r, c) = protected(&env);
    r.ok(&["new", "root"]);
    assert_eq!(r.read(".env"), DOTENV, "isolated files are never removed");
    assert!(!r.exists("secrets/plan.txt"));
    r.ok(&["new", c.as_str()]);
    assert_eq!(r.read("secrets/plan.txt"), SECRET_PLAN);
    r.ok(&["edit", c.as_str()]);
    assert_no_plaintext(&r, "after checkouts");
}

// Scenario from git t2070-restore.sh / t7104 with Veil's tiers.
#[test]
fn restore_keeps_isolated_files_and_cloaked_ones_sealed() {
    let env = Env::new();
    let (r, _) = protected(&env);
    r.write("secrets/plan.txt", "edited plan\n");
    r.ok(&["restore"]);
    assert_eq!(r.read("secrets/plan.txt"), SECRET_PLAN);
    r.ok(&["restore", "--from", "root", ".env"]);
    assert_eq!(r.read(".env"), DOTENV, "restore never touches an isolated file");
    assert_no_plaintext(&r, "after restore");
}

// Scenario from jj test_undo_redo_commands.rs with Veil's tiers: undo and
// op restore never bring an isolated file into a snapshot.
#[test]
fn undo_and_op_restore_never_record_isolated_files() {
    let env = Env::new();
    let (r, _) = protected(&env);
    r.ok(&["undo"]);
    r.ok(&["undo"]);
    let first = r.out(&["op", "log"]).lines().last().unwrap().split_whitespace().next().unwrap().to_string();
    r.ok(&["op", "restore", first.as_str()]);
    r.ok(&["status"]);
    assert!(!r.paths("@").contains(&".env".to_string()));
    assert_eq!(r.read(".env"), DOTENV);
    assert_no_plaintext(&r, "after undo/op restore");
}

// Scenario from git t7508-status.sh / t4000-diff (output) with Veil's
// tiers: no everyday command prints the isolated value or a quarantined
// credential.
#[test]
fn everyday_output_never_prints_secret_values() {
    let env = Env::new();
    let (r, _) = protected(&env);
    r.write("cfg.js", LEAKY);
    for args in [
        &["status"][..],
        &["log"],
        &["diff"],
        &["diff", "-r", "@-"],
        &["show", "@-"],
        &["files"],
        &["op", "log"],
        &["policy", "check", ".env", "cfg.js"],
    ] {
        let out = r.ok(args);
        assert!(!out.contains(DB_PASSWORD), "{args:?} printed the .env value");
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "{args:?} printed the quarantined key");
    }
}

// Scenario from git t7001-mv.sh / t3700 with a copy of `.env` under
// another name: the scanner quarantines it.
#[test]
fn a_copy_of_the_env_file_under_another_name_is_quarantined() {
    let env = Env::new();
    let (r, _) = protected(&env);
    std::fs::copy(r.path(".env"), r.path("env-backup.txt")).unwrap();
    let st = r.status();
    assert!(st.contains("Q env-backup.txt"), "{st}");
    r.commit("after copy");
    assert!(!r.paths("@-").contains(&"env-backup.txt".to_string()));
    assert_no_plaintext(&r, "after copying .env");
}

// Scenario from git t0008-ignores.sh (editor files) with Veil's rule that
// editor and backup artefacts of a protected file take its protection.
#[test]
fn editor_artefacts_of_protected_files_keep_their_protection() {
    let env = Env::new();
    let (r, _) = protected(&env);
    r.write(".env.swp", DOTENV);
    r.write(".env~", DOTENV);
    r.write(".env.bak", DOTENV);
    r.write("secrets/plan.txt.orig", SECRET_PLAN);
    r.write("secrets/.plan.txt.swp", SECRET_PLAN);
    r.ok(&["status"]);
    let files = r.files("@");
    assert!(!files.iter().any(|f| f.path.starts_with(".env")), "{files:?}");
    if let Some(f) = files.iter().find(|f| f.path == "secrets/plan.txt.orig") {
        assert_eq!(f.vis, "cloaked:team");
    }
    assert_no_plaintext(&r, "after editor artefacts");
}

// Scenario from git t0050-filesystem.sh (case) with Veil's built-in secret
// rules, which ignore case.
#[test]
fn secret_names_in_any_case_and_at_any_depth_are_isolated() {
    let env = Env::new();
    let r = env.repo("p");
    for p in [".ENV", "config/.env", "deep/er/.Env.production", "keys/server.PEM", "home/.ssh/id_ed25519"] {
        r.write(p, DOTENV);
    }
    r.write("ok.txt", "ok\n");
    assert_eq!(r.paths("@"), vec!["ok.txt"]);
    assert_no_plaintext(&r, "case variants");
}

// Scenario from git t2400 (worktree) with Veil's isolation: `ws exec
// --with-isolated` gives the command `.env`, and a copy it writes is
// quarantined.
#[test]
fn ws_exec_with_isolated_quarantines_copies_of_injected_secrets() {
    let env = Env::new();
    let (r, _) = protected(&env);
    r.ok(&["ws", "new", "agent"]);
    let out = r.run(&["ws", "exec", "agent", "--with-isolated", "--", "sh", "-c", "test -f .env && cp .env leaked.txt"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("leaked.txt quarantined"), "{}", text(&out));
    assert!(!r.paths("agent@").iter().any(|p| p == "leaked.txt" || p == ".env"));
    assert_no_plaintext(&r, "after ws exec");
}

// Scenario from jj test_workspaces.rs with a cloaked workspace: what the
// sandbox records there is cloaked.
#[test]
fn ws_exec_in_a_cloaked_workspace_records_cloaked_files() {
    let env = Env::new();
    let (r, _) = protected(&env);
    r.ok(&["ws", "new", "fix", "--cloak"]);
    let out = r.run(&["ws", "exec", "fix", "--", "sh", "-c", &format!("echo '{SECRET_PLAN} v2' > fix.txt")]);
    assert!(out.status.success(), "{}", text(&out));
    let f = r.files("fix@").into_iter().find(|f| f.path == "fix.txt").unwrap();
    assert_eq!(f.vis, "cloaked:team");
    assert_no_plaintext(&r, "cloaked ws exec");
}

// Scenario from git t3600-rm.sh / jj test_file_track_untrack with a
// non-member: an edit to a cloaked file they cannot seal is kept local
// and never recorded in plaintext.
#[test]
fn a_non_members_edit_of_a_cloaked_file_is_kept_local() {
    let env = Env::new();
    let (r, c) = protected(&env);
    r.ok(&["tag", "set", "main", "-r", "@-"]);
    let remote = env.root.join("remote");
    r.ok(&["remote", "add", "origin", remote.to_str().unwrap()]);
    r.ok(&["push", "origin"]);
    let bob_dir = env.root.join("bob");
    let out = env.run_as("bob", &env.root, &["clone", remote.to_str().unwrap(), bob_dir.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out));
    let bob = env.as_user("bob", &bob_dir);
    let st = bob.status();
    assert!(st.contains("R secrets/plan.txt"), "{st}");
    assert!(!bob.exists("secrets/plan.txt"));
    bob.write("secrets/plan.txt", "bob's guess\n");
    let st = bob.status();
    assert!(st.contains("could not cloak secrets/plan.txt"), "{st}");
    bob.commit("bob");
    let o = all_bytes(&bob_dir.join(".veil"));
    assert!(!contains_bytes(&o, "bob's guess"), "the non-member's edit was stored in plaintext");
    assert!(!contains_bytes(&o, SECRET_PLAN));
    // bob's restore cannot write what he cannot read, and does not crash.
    let out = bob.run(&["restore", "--from", c.as_str(), "secrets/plan.txt"]);
    assert!(clean_exit(&out), "{}", text(&out));
    let diff = bob.ok(&["diff", "-r", c.as_str()]);
    assert!(!diff.contains(SECRET_PLAN) && diff.contains("content hidden"), "{diff}");
}

// Scenario from git t7004-tag.sh with Veil's cloaked tags: a tag cloaked
// for the team is never sent to a public remote.
#[test]
fn a_cloaked_tag_stays_off_a_public_remote() {
    let env = Env::new();
    let (r, c) = protected(&env);
    r.ok(&["tag", "set", "main", "-r", c.as_str()]);
    r.ok(&["tag", "set", "secret-line", "-r", c.as_str(), "--cloak"]);
    let mirror = env.root.join("mirror");
    r.ok(&["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    r.ok(&["push", "mirror"]);
    let o = all_bytes(&mirror);
    assert!(!contains_bytes(&o, "secret-line"), "the cloaked tag reached the public remote");
    assert!(!contains_bytes(&o, SECRET_PLAN));
    assert!(!contains_bytes(&o, DB_PASSWORD));
}
