//! Veil-specific: what public and team remotes may receive. Every check
//! reads every object of the remote (decompressed) and every metadata file.

use std::path::{Path, PathBuf};

use super::support::*;

const CLOAKED: &str = "CLOAKED-PLAINTEXT-7781";
/// The sealed secret file.
const PLAN: &str = "secrets/.env.plan";
const ISOLATED: &str = "DB_PASSWORD=isolated-9931";
const KEYFILE: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH PRIVATE KEY-----\n";

/// A repository with a cloaked secret file, isolated files, and a public
/// file.
fn secretive(env: &Env) -> PathBuf {
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["cloak", PLAN]);
    write(&proj, PLAN, &format!("{CLOAKED}\n"));
    write(&proj, "app.txt", "public app\n");
    write(&proj, ".netrc", &format!("{ISOLATED}\n"));
    write(
        &proj,
        "config/prod.pem",
        &format!("{ISOLATED}-prod\n"),
    );
    write(&proj, "keys/id_rsa", KEYFILE);
    env.ok("alice", &proj, &["commit", "-m", "public start"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    proj
}

fn push_to(env: &Env, proj: &Path, name: &str, public: bool) -> PathBuf {
    let dir = env.path(name);
    let mut args = vec!["remote", "add", name, dir.to_str().unwrap()];
    if public {
        args.push("--public");
    }
    env.ok("alice", proj, &args);
    env.ok("alice", proj, &["push", name]);
    dir
}

// Veil: a public remote never receives cloaked (secret-file) content, isolated files or key
// rings (README "Team remotes and public remotes").
#[test]
fn a_public_remote_receives_none_of_the_protected_content() {
    let env = Env::new();
    let proj = secretive(&env);
    let mirror = push_to(&env, &proj, "mirror", true);
    for (needle, what) in [
        (CLOAKED, "cloaked file"),
        (ISOLATED, "isolated .netrc"),
        ("BEGIN OPENSSH PRIVATE KEY", "isolated key"),
    ] {
        assert_absent(&mirror, needle, what);
    }
    assert!(
        keyrings(&mirror).is_empty(),
        "key rings on a public remote: {:?}",
        keyrings(&mirror)
    );
    let remote = open_repo(&mirror);
    assert!(remote.view().tags.contains_key("main"));
    assert!(
        contains(&everything_in(&mirror), "public app"),
        "control: the public file is there"
    );
}

// Veil: a team remote stores cloaked content as ciphertext only, and never isolated files.
#[test]
fn a_team_remote_holds_ciphertext_and_key_rings_but_no_plaintext() {
    let env = Env::new();
    let proj = secretive(&env);
    let hub = push_to(&env, &proj, "origin", false);
    assert_absent(&hub, CLOAKED, "cloaked file on a team remote");
    assert_absent(&hub, ISOLATED, "isolated .netrc on a team remote");
    assert_absent(
        &hub,
        "BEGIN OPENSSH PRIVATE KEY",
        "isolated key on a team remote",
    );
    assert!(!keyrings(&hub).is_empty());
    // A member clone reads everything back.
    let key = env.pubkey("bob");
    env.ok(
        "alice",
        &proj,
        &["scope", "grant", "team", &key, "--name", "bob"],
    );
    env.ok("alice", &proj, &["push"]);
    let bob = env.clone("bob", &hub, "bob");
    assert_eq!(read(&bob, PLAN), format!("{CLOAKED}\n"));
    assert!(!bob.join(".netrc").exists() && !bob.join("keys/id_rsa").exists());
}

// Veil: a non-member clone of a team remote learns none of the cloaked plaintext.
#[test]
fn a_non_member_clone_of_a_team_remote_learns_no_plaintext() {
    let env = Env::new();
    let proj = secretive(&env);
    let hub = push_to(&env, &proj, "origin", false);
    let eve = env.clone("eve", &hub, "eve");
    assert!(!eve.join(PLAN).exists());
    assert_absent(&eve, CLOAKED, "non-member clone");
    let out = env.ok("eve", &eve, &["show", "main"]);
    assert!(!out.contains(CLOAKED), "{out}");
}

// Veil: `--force` to a public remote is still filtered.
#[test]
fn force_push_to_a_public_remote_is_still_filtered() {
    let env = Env::new();
    let proj = secretive(&env);
    let mirror = push_to(&env, &proj, "mirror", true);
    env.ok("alice", &proj, &["push", "mirror", "--force"]);
    assert_absent(&mirror, CLOAKED, "forced full push");
    assert!(keyrings(&mirror).is_empty());
}

// Veil: a public mirror's clone (no keys, redacted entries) commits and pushes to the team
// remote without deleting the cloaked files it never saw.
#[test]
fn work_from_a_public_mirror_clone_does_not_delete_cloaked_files_on_the_team_remote() {
    let env = Env::new();
    let proj = secretive(&env);
    let hub = push_to(&env, &proj, "origin", false);
    let mirror = push_to(&env, &proj, "mirror", true);
    let carol = env.clone("carol", &mirror, "carol");
    assert!(!carol.join(PLAN).exists());
    env.commit(
        "carol",
        &carol,
        "carol's fix",
        &[("app.txt", "carol's app\n")],
    );
    env.ok(
        "carol",
        &carol,
        &["remote", "add", "team", hub.to_str().unwrap()],
    );
    let out = env.ok("carol", &carol, &["push", "team"]);
    assert!(out.contains("pushed main"), "{out}");
    env.ok("alice", &proj, &["pull"]);
    assert_eq!(
        env.stdout("alice", &proj, &["cat", PLAN, "-r", "main"]),
        format!("{CLOAKED}\n")
    );
    assert_eq!(
        env.stdout("alice", &proj, &["cat", "app.txt", "-r", "main"]),
        "carol's app\n"
    );
}

// Veil: pulling back from one's own public mirror changes nothing and loses nothing.
#[test]
fn pulling_from_the_public_mirror_loses_no_cloaked_content() {
    let env = Env::new();
    let proj = secretive(&env);
    let _mirror = push_to(&env, &proj, "mirror", true);
    let before = env.tag_target("alice", &proj, "main");
    env.ok("alice", &proj, &["pull", "mirror"]);
    assert_eq!(env.tag_target("alice", &proj, "main"), before);
    assert_eq!(
        env.stdout("alice", &proj, &["cat", PLAN, "-r", "main"]),
        format!("{CLOAKED}\n")
    );
    env.ok("alice", &proj, &["fsck"]);
}

// Veil: a remote first used as a team remote, then re-added as public, warns about the
// key rings already there (documented) and sends no more.
#[test]
fn a_public_remote_with_key_rings_from_earlier_warns() {
    let env = Env::new();
    let proj = secretive(&env);
    let dir = push_to(&env, &proj, "was-team", false);
    assert!(!keyrings(&dir).is_empty());
    env.ok("alice", &proj, &["remote", "rm", "was-team"]);
    env.ok(
        "alice",
        &proj,
        &[
            "remote",
            "add",
            "now-public",
            dir.to_str().unwrap(),
            "--public",
        ],
    );
    let out = env.ok("alice", &proj, &["push", "now-public"]);
    assert!(
        out.to_lowercase().contains("ring"),
        "no warning about the rings already there: {out}"
    );
}

// Veil: history from before a secret file was cloaked stays public (documented: it was
// exposed with `--force`), but the new version does not reach the mirror.
#[test]
fn cloaking_later_keeps_old_versions_public_and_new_ones_private() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    write(&proj, "deploy.pem", "old public notes 1111\n");
    env.ok("alice", &proj, &["expose", "--force", "deploy.pem"]);
    env.ok("alice", &proj, &["commit", "-m", "public"]);
    env.ok("alice", &proj, &["cloak", "deploy.pem"]);
    write(&proj, "deploy.pem", "new private notes 2222\n");
    env.ok("alice", &proj, &["commit", "-m", "now private"]);
    let mirror = push_to(&env, &proj, "mirror", true);
    let all = everything_in(&mirror);
    assert!(
        contains(&all, "old public notes 1111"),
        "documented: earlier history stays public"
    );
    assert!(!contains(&all, "new private notes 2222"));
}

// Veil: a quarantined file (the scanner flags a credential) never reaches any remote.
#[test]
fn a_quarantined_file_reaches_no_remote() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    write(&proj, "cfg.js", "const k = \"AKIAZ7QXN4PL2WVR8TQM\";\nconst s = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY9\";\n");
    let out = env.quarantined("alice", &proj, &["commit", "-m", "with a leak"]);
    assert!(out.contains("  cfg.js ("), "{out}");
    // Each push exits 3 while `cfg.js` stays quarantined (BUG-2140).
    let (hub, mirror) = (env.path("origin"), env.path("mirror"));
    env.ok("alice", &proj, &["remote", "add", "origin", hub.to_str().unwrap()]);
    env.ok("alice", &proj, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    env.quarantined("alice", &proj, &["push", "origin"]);
    env.quarantined("alice", &proj, &["push", "mirror"]);
    for d in [&hub, &mirror] {
        assert_absent(d, "AKIAZ7QXN4PL2WVR8TQM", "quarantined credential");
    }
}

/// Alice's project with an embargoed fix merged into main.
fn embargoed(env: &Env) -> PathBuf {
    let proj = before_the_fix(env);
    merge_the_fix(env, &proj);
    proj
}

/// Alice's project, before the fix.
fn before_the_fix(env: &Env) -> PathBuf {
    env.project(
        "alice",
        "proj",
        &[
            ("auth.rs", "fn check() -> bool { true }\n"),
            ("README", "hi\n"),
        ],
    )
}

/// The fix, on workspace `fix`, merged into main under an embargo.
fn merge_the_fix(env: &Env, proj: &Path) {
    let proj = proj.to_path_buf();
    env.ok("alice", &proj, &["ws", "new", "fix", "-r", "main"]);
    env.ok(
        "alice",
        &proj,
        &[
            "ws",
            "exec",
            "fix",
            "-m",
            "fix line 4471",
            "--",
            "sh",
            "-c",
            "printf 'EMBARGOED-FIX-4471\\n' > auth.rs && printf 'NEW-FILE-4471\\n' > verify.rs",
        ],
    );
    env.ok(
        "alice",
        &proj,
        &[
            "merge",
            "fix@",
            "--into",
            "main",
            "--embargo",
            "-m",
            "Fix CVE 4471",
        ],
    );
}

fn embargo_id(env: &Env, proj: &Path) -> String {
    env.stdout("alice", proj, &["embargo", "list"])
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

// Veil: an unreleased embargo's merge and the history it brings in reach neither the public
// mirror nor a team remote; after release both receive it, same ids.
#[test]
fn an_unreleased_embargo_reaches_no_remote_and_the_release_keeps_snapshot_ids() {
    let env = Env::new();
    let proj = embargoed(&env);
    let mirror = push_to(&env, &proj, "mirror", true);
    let hub = push_to(&env, &proj, "origin", false);
    for d in [&mirror, &hub] {
        for needle in [
            "EMBARGOED-FIX-4471",
            "NEW-FILE-4471",
            "fix line 4471",
            "Fix CVE 4471",
        ] {
            assert_absent(d, needle, "unreleased embargo");
        }
    }
    assert!(!open_repo(&mirror).view().tags.contains_key("main"), "the embargoed main reached the mirror");
    let main_here = open_repo(&proj).view().tags["main"].target;
    let id = embargo_id(&env, &proj);
    env.ok("alice", &proj, &["embargo", "release", &id, "--yes"]);
    env.ok("alice", &proj, &["push", "mirror"]);
    let all = everything_in(&mirror);
    assert!(
        contains(&all, "EMBARGOED-FIX-4471") && contains(&all, "fix line 4471"),
        "the release was not published"
    );
    assert_eq!(
        open_repo(&mirror).view().tags["main"].target,
        main_here,
        "same snapshot id after release"
    );
    let carol = env.clone("carol", &mirror, "carol");
    assert_eq!(read(&carol, "auth.rs"), "EMBARGOED-FIX-4471\n");
    env.ok("carol", &carol, &["fsck"]);
}

// Veil: a tag on the embargoed fix itself is skipped by a push of all tags (not a failure).
#[test]
fn a_tag_on_the_embargoed_fix_is_skipped_by_push() {
    let env = Env::new();
    let proj = embargoed(&env);
    env.ok("alice", &proj, &["tag", "set", "fix-tag", "-r", "fix@"]);
    let mirror = env.path("mirror");
    env.ok(
        "alice",
        &proj,
        &[
            "remote",
            "add",
            "mirror",
            mirror.to_str().unwrap(),
            "--public",
        ],
    );
    let (code, out) = env.code("alice", &proj, &["push", "mirror"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("skipped fix-tag"), "{out}");
    assert!(!open_repo(&mirror).view().tags.contains_key("fix-tag"));
    assert_absent(&mirror, "EMBARGOED-FIX-4471", "tag on the fix");
    let (code, out) = env.code("alice", &proj, &["push", "mirror", "-t", "fix-tag"]);
    assert_ne!(code, 0, "naming a held-back tag fails: {out}");
}

// Veil: a clone of the mirror made before the release has the pre-merge tree; after the
// release and a pull its work moves onto the fix and records nothing as deleted.
#[test]
fn a_mirror_clone_from_before_the_release_catches_up() {
    let env = Env::new();
    let proj = before_the_fix(&env);
    let mirror = push_to(&env, &proj, "mirror", true);
    merge_the_fix(&env, &proj);
    let out = env.ok("alice", &proj, &["push", "mirror"]);
    assert!(out.contains("skipped main"), "{out}");
    let carol = env.clone("carol", &mirror, "carol");
    assert_eq!(read(&carol, "auth.rs"), "fn check() -> bool { true }\n");
    assert!(!carol.join("verify.rs").exists());
    assert_absent(&mirror, "EMBARGOED-FIX-4471", "before the release");
    let id = embargo_id(&env, &proj);
    env.ok("alice", &proj, &["embargo", "release", &id, "--yes"]);
    env.ok("alice", &proj, &["push", "mirror"]);
    env.ok("carol", &carol, &["pull"]);
    env.ok("carol", &carol, &["rebase", "-s", "@", "-d", "main"]);
    assert_eq!(read(&carol, "verify.rs"), "NEW-FILE-4471\n");
    let diff = env.ok("carol", &carol, &["diff"]);
    assert!(!diff.contains("auth.rs"), "{diff}");
}
