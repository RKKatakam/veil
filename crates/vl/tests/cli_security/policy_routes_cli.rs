//! Every route by which a `.veilpolicy` from someone else reaches the
//! working copy goes through the accepted-policy pin (BUG-101), and what is
//! at `.veilpolicy` (missing, a symlink, unreadable, a directory) never
//! makes a snapshot less protected than the pin (BUG-106, BUG-107).
//!
//! Each route test starts from the same state: Alice's project has an
//! isolated `.netrc` and is pushed to `hub`; Mallory pushes a `.veilpolicy`
//! that says `.netrc public!`; Alice pulls. After the route, `.netrc` must
//! still be off the record until Alice runs `vl policy accept`.

use crate::adversarial_support;

use std::path::Path;

use adversarial_support::{read, text, write, Env};

const U: &str = "alice";
const SECRET: &str = "DB_PASSWORD=hunter2hunter2\n";

/// Alice's project (`.netrc` isolated, `main` pushed to `hub`) after
/// `vl pull` of Mallory's `.netrc public!` on `main`.
fn pulled_hostile_policy(env: &Env) -> std::path::PathBuf {
    let hub = env.dir("hub");
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, ".netrc", SECRET);
    write(&proj, "a.txt", "a\n");
    env.ok(U, &proj, &["commit", "-m", "initial"]);
    env.ok(U, &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok(U, &proj, &["tag", "set", "before", "-r", "@-"]);
    env.ok(U, &proj, &["remote", "add", "origin", hub.to_str().unwrap()]);
    env.ok(U, &proj, &["push"]);
    let m = env.root.join("m");
    env.ok("mallory", &env.root, &["clone", hub.to_str().unwrap(), "m"]);
    let policy = read(&m, ".veilpolicy") + ".netrc public!\n";
    write(&m, ".veilpolicy", &policy);
    write(&m, "b.txt", "b\n");
    env.ok("mallory", &m, &["commit", "-m", "add b"]);
    env.ok("mallory", &m, &["push"]);
    env.ok(U, &proj, &["pull"]);
    proj
}

/// `.netrc` is not recorded in the working copy, nor in a commit of it.
fn assert_env_off_the_record(env: &Env, proj: &Path, route: &str) {
    assert_eq!(read(proj, ".netrc"), SECRET, "{route}: the local .netrc is gone");
    let status = env.ok(U, proj, &["status"]);
    let files = env.stdout(U, proj, &["files"]);
    assert!(
        !files.lines().any(|l| l.ends_with(" .netrc")) && !status.contains("A .netrc"),
        "{route}: the pulled policy published .netrc without `vl policy accept`:\n{status}\n{files}"
    );
    assert!(status.contains("policy accept"), "{route}: nothing says the policy is held back:\n{status}");
    let p = env.stdout(U, proj, &["policy", "check", ".netrc"]);
    assert!(p.contains("isolated") && p.contains("not yet accepted"), "{route}: {p}");
}

/// And `vl policy accept` is what moves it (the pin is not stuck).
fn assert_accept_moves_it(env: &Env, proj: &Path) {
    env.ok(U, proj, &["policy", "accept"]);
    let files = env.stdout(U, proj, &["files"]);
    assert!(files.lines().any(|l| l.ends_with(" .netrc")), "{files}");
}

#[test]
fn restore_from_a_revision_holds_its_policy_back() {
    let env = Env::new();
    let proj = pulled_hostile_policy(&env);
    env.ok(U, &proj, &["restore", "--from", "origin/main"]);
    assert_env_off_the_record(&env, &proj, "restore --from");
    assert_accept_moves_it(&env, &proj);
}

#[test]
fn restoring_only_the_policy_file_holds_it_back() {
    let env = Env::new();
    let proj = pulled_hostile_policy(&env);
    env.ok(U, &proj, &["restore", ".veilpolicy", "--from", "origin/main"]);
    assert_env_off_the_record(&env, &proj, "restore .veilpolicy --from");
}

/// A restore that does not touch `.veilpolicy` keeps the member's own edit
/// of it theirs (`--no-snapshot`: the edit is not recorded before).
#[test]
fn restore_of_other_paths_keeps_the_members_own_policy_edit() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n"), ("b.txt", "b\n")]);
    write(&proj, ".netrc", SECRET);
    env.ok(U, &proj, &["status"]);
    let policy = read(&proj, ".veilpolicy") + ".netrc public!\n";
    write(&proj, ".veilpolicy", &policy);
    write(&proj, "a.txt", "changed\n");
    env.ok(U, &proj, &["--no-snapshot", "restore", "a.txt"]);
    let files = env.stdout(U, &proj, &["files"]);
    assert!(files.lines().any(|l| l.ends_with(" .netrc")), "the member's own edit was not applied:\n{files}");
}

#[test]
fn new_on_a_pulled_revision_holds_its_policy_back() {
    let env = Env::new();
    let proj = pulled_hostile_policy(&env);
    env.ok(U, &proj, &["new", "main"]);
    assert_env_off_the_record(&env, &proj, "new main");
    assert_accept_moves_it(&env, &proj);
}

#[test]
fn edit_of_a_pulled_revision_holds_its_policy_back() {
    let env = Env::new();
    let proj = pulled_hostile_policy(&env);
    env.ok(U, &proj, &["edit", "main"]);
    assert_env_off_the_record(&env, &proj, "edit main");
}

#[test]
fn switching_to_a_workspace_on_a_pulled_revision_holds_its_policy_back() {
    let env = Env::new();
    let proj = pulled_hostile_policy(&env);
    env.ok(U, &proj, &["ws", "new", "agent", "-r", "main"]);
    env.ok(U, &proj, &["ws", "switch", "agent"]);
    assert_env_off_the_record(&env, &proj, "ws switch");
}

#[test]
fn undo_back_onto_a_pulled_policy_holds_it_back() {
    let env = Env::new();
    let proj = pulled_hostile_policy(&env);
    env.ok(U, &proj, &["new", "main"]);
    env.ok(U, &proj, &["new", "before"]);
    env.ok(U, &proj, &["undo"]);
    assert!(read(&proj, ".veilpolicy").contains(".netrc public!"), "control: undo is back on main");
    assert_env_off_the_record(&env, &proj, "undo");
}

#[test]
fn op_restore_onto_a_pulled_policy_holds_it_back() {
    let env = Env::new();
    let proj = pulled_hostile_policy(&env);
    env.ok(U, &proj, &["new", "main"]);
    let log = env.stdout(U, &proj, &["op", "log", "-n", "1"]);
    let op = log.split_whitespace().next().unwrap().to_string();
    env.ok(U, &proj, &["new", "before"]);
    env.ok(U, &proj, &["op", "restore", &op]);
    assert!(read(&proj, ".veilpolicy").contains(".netrc public!"), "control: op restore is back on main");
    assert_env_off_the_record(&env, &proj, "op restore");
}

#[test]
fn merging_a_pulled_policy_holds_it_back() {
    let env = Env::new();
    let proj = pulled_hostile_policy(&env);
    write(&proj, "c.txt", "c\n");
    env.ok(U, &proj, &["commit", "-m", "c"]);
    env.ok(U, &proj, &["merge", "main", "-m", "merge main"]);
    assert_env_off_the_record(&env, &proj, "merge");
}

// ---- what is at .veilpolicy ---------------------------------------------------------

/// A project with `secrets/ cloak team` and one cloaked file.
fn cloaked_project(env: &Env) -> std::path::PathBuf {
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, ".veilpolicy", "secrets/ cloak team\n");
    write(&proj, "secrets/db.yml", "password: hunter2hunter2\n");
    write(&proj, ".netrc", SECRET);
    write(&proj, "README", "hi\n");
    env.ok(U, &proj, &["commit", "-m", "initial"]);
    proj
}

fn assert_still_protected(env: &Env, proj: &Path, what: &str) -> String {
    write(proj, "secrets/new.yml", "token: Xk9mQ2vL7pR4wZt8\n");
    let status = env.ok(U, proj, &["status"]);
    let files = env.stdout(U, proj, &["files"]);
    for l in files.lines().filter(|l| l.contains("secrets/")) {
        assert!(l.starts_with("cloaked:team"), "{what}: the policy stopped applying:\n{status}\n{files}");
    }
    assert!(files.contains("secrets/new.yml"), "{what}: {files}");
    assert!(!files.lines().any(|l| l.ends_with(" .netrc")), "{what}: {files}");
    status
}

/// Deleting `.veilpolicy` is not an edit that lifts every rule.
#[test]
fn a_deleted_policy_file_does_not_lift_protection() {
    let env = Env::new();
    let proj = cloaked_project(&env);
    std::fs::remove_file(proj.join(".veilpolicy")).unwrap();
    let status = assert_still_protected(&env, &proj, "deleted");
    assert!(status.contains(".veilpolicy is missing"), "{status}");
    // `vl cloak` starts from the recorded version, not from nothing.
    env.ok(U, &proj, &["cloak", "more/"]);
    let policy = read(&proj, ".veilpolicy");
    assert!(policy.contains("secrets/ cloak team") && policy.contains("more/"), "{policy}");
    assert_still_protected(&env, &proj, "after vl cloak");
}

/// A symlink is followed: a change in its target that adds protection
/// applies, one that weakens it waits for `vl policy accept`.
#[test]
fn a_symlinked_policy_is_followed_but_never_taken_as_the_members_edit() {
    let env = Env::new();
    let proj = cloaked_project(&env);
    let shared = env.root.join("shared.veilpolicy");
    std::fs::rename(proj.join(".veilpolicy"), &shared).unwrap();
    std::os::unix::fs::symlink(&shared, proj.join(".veilpolicy")).unwrap();
    let status = assert_still_protected(&env, &proj, "symlinked");
    assert!(status.contains("is a symlink"), "{status}");
    assert!(!status.contains("Veil never follows it"), "the old, wrong message: {status}");
    // Strengthening applies at once.
    std::fs::write(&shared, "secrets/ cloak team\nnotes/ isolate\n").unwrap();
    write(&proj, "notes/n.txt", "n\n");
    let files = env.stdout(U, &proj, &["files"]);
    assert!(!files.contains("notes/n.txt"), "{files}");
    // Weakening the shared file (someone else's monorepo pull) is held back.
    std::fs::write(&shared, "secrets/ public\n").unwrap();
    assert_still_protected(&env, &proj, "weakened target");
    // `vl cloak` refuses to write over the link.
    let out = env.vl(U, &proj, &["cloak", "x/"]);
    assert!(!out.status.success() && text(&out).contains("symlink"), "{}", text(&out));
    assert!(std::fs::symlink_metadata(proj.join(".veilpolicy")).unwrap().file_type().is_symlink());
    // An explicit accept reads through the link.
    let accepted = env.ok(U, &proj, &["policy", "accept"]);
    assert!(accepted.contains("secrets/db.yml: cloak team → public"), "{accepted}");
    // The fixture (`password: hunter2hunter2`) is a secret to scanner v4, so
    // the now-public file is quarantined and history keeps the cloaked
    // version; either way it is no longer under the old rule.
    let status = env.ok(U, &proj, &["status"]);
    let files = env.stdout(U, &proj, &["files"]);
    assert!(
        files.lines().any(|l| l.starts_with("public") && l.contains("secrets/db.yml"))
            || status.contains("Q secrets/db.yml"),
        "{status}\n{files}"
    );
}

#[test]
fn a_dangling_or_looping_symlinked_policy_falls_back_to_the_pin() {
    let env = Env::new();
    let proj = cloaked_project(&env);
    std::fs::remove_file(proj.join(".veilpolicy")).unwrap();
    std::os::unix::fs::symlink(proj.join("nowhere"), proj.join(".veilpolicy")).unwrap();
    let status = assert_still_protected(&env, &proj, "dangling");
    assert!(status.contains("cannot read .veilpolicy"), "{status}");
    std::fs::remove_file(proj.join(".veilpolicy")).unwrap();
    std::os::unix::fs::symlink(proj.join(".veilpolicy"), proj.join(".veilpolicy")).unwrap();
    assert_still_protected(&env, &proj, "looping");
    // Accepting "no policy" for a file that cannot be read is refused.
    let out = env.vl(U, &proj, &["policy", "accept"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert_still_protected(&env, &proj, "after a refused accept");
}

#[test]
fn an_unreadable_policy_falls_back_to_the_pin() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    let proj = cloaked_project(&env);
    let p = proj.join(".veilpolicy");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&p).is_ok() {
        return; // running as root: permissions do not apply
    }
    let status = assert_still_protected(&env, &proj, "unreadable");
    let out = env.vl(U, &proj, &["policy", "accept"]);
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(status.contains("cannot read .veilpolicy"), "{status}");
    assert!(!out.status.success(), "{}", text(&out));
}

#[test]
fn a_directory_named_veilpolicy_falls_back_to_the_pin() {
    let env = Env::new();
    let proj = cloaked_project(&env);
    std::fs::remove_file(proj.join(".veilpolicy")).unwrap();
    std::fs::create_dir(proj.join(".veilpolicy")).unwrap();
    assert_still_protected(&env, &proj, "directory");
}

/// Control: the member's own edit by hand still applies at once.
#[test]
fn the_members_own_edit_still_applies() {
    let env = Env::new();
    let proj = cloaked_project(&env);
    let policy = read(&proj, ".veilpolicy") + ".netrc public!\n";
    write(&proj, ".veilpolicy", &policy);
    let files = env.stdout(U, &proj, &["files"]);
    assert!(files.lines().any(|l| l.ends_with(" .netrc")), "{files}");
}

/// A symlink planted by a hostile Git checkout (`vl init` in CI) to a file
/// that is not a policy is not parsed, so none of its lines are echoed in
/// warnings; the policy falls back as for an unreadable one.
#[test]
fn a_symlink_to_a_file_not_named_like_a_policy_is_not_read() {
    let env = Env::new();
    let co = env.dir("checkout");
    let creds = env.root.join("credentials");
    std::fs::write(&creds, "aws_secret_access_key SECRETSECRETSECRET\n").unwrap();
    std::os::unix::fs::symlink(&creds, co.join(".veilpolicy")).unwrap();
    write(&co, "a.txt", "a\n");
    let out = env.ok("ci", &co, &["init"]) + &env.ok("ci", &co, &["status"]);
    assert!(!out.contains("SECRETSECRET"), "{out}");
    assert!(out.contains("cannot read .veilpolicy"), "{out}");
    let pin = std::fs::read_to_string(co.join(".veil/local/accepted-policy")).unwrap_or_default();
    assert!(!pin.contains("SECRETSECRET"), "{pin}");
}
