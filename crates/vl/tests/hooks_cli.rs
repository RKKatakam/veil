//! Hooks (feature 5a of the Git-parity round) through the real binary: one
//! test per point of the threat review in
//! `docs/design/git-parity/5-hooks-submodules-signed-tags.md`, plus the
//! hostile inputs of every new surface (`.veilhooks`, the trust record,
//! `VEIL_HOOK_TIMEOUT`, the environment, `PATH`, signals).

mod adversarial_support;

use std::{
    io::{BufRead, BufReader, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use adversarial_support::{read, text, wait_for, write, Env};

const U: &str = "alice";

fn vl_bin() -> &'static str {
    env!("CARGO_BIN_EXE_vl")
}

/// An executable shell script.
fn script(dir: &Path, rel: &str, body: &str) {
    write(dir, rel, &format!("#!/bin/sh\n{body}\n"));
    let p = dir.join(rel);
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A marker file outside the project (a hook writing inside it would edit
/// the working copy, which refuses the commit).
fn marker(env: &Env, name: &str) -> PathBuf {
    env.root.join("markers").join(name)
}

fn marked(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

/// A project whose `.veilhooks` runs `scripts/lint.sh` before each commit;
/// the script appends `ran` to the marker `lint`.
fn project(env: &Env) -> PathBuf {
    std::fs::create_dir_all(env.root.join("markers")).unwrap();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    let m = marker(env, "lint");
    script(&proj, "scripts/lint.sh", &format!("echo ran >> '{}'", m.display()));
    write(&proj, ".veilhooks", "[pre-commit]\nrun = [\"sh\", \"scripts/lint.sh\"]\n");
    env.ok(U, &proj, &["commit", "-m", "hooks", "--no-verify"]);
    proj
}

fn trust(env: &Env, proj: &Path) {
    env.ok(U, proj, &["hooks", "trust", "--yes"]);
}

fn head_op(env: &Env, proj: &Path) -> String {
    let log = env.stdout(U, proj, &["op", "log", "-n", "1", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&log).unwrap();
    v["operations"][0]["op_id"].as_str().unwrap().to_string()
}

/// The description of `rev`.
fn description(env: &Env, proj: &Path, rev: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(&env.stdout(U, proj, &["show", rev, "--json"])).unwrap();
    v["description"].as_str().unwrap_or_default().to_string()
}

// ---- 1. code execution from a teammate's push -----------------------------------------------

#[test]
fn untrusted_veilhooks_never_run_and_every_command_warns() {
    let env = Env::new();
    let proj = project(&env);
    let m = marker(&env, "lint");
    write(&proj, "a.txt", "b\n");
    let out = env.ok(U, &proj, &["commit", "-m", "x"]);
    assert!(out.contains("has not trusted") && out.contains("vl hooks show") && out.contains("vl hooks trust"), "{out}");
    assert_eq!(marked(&m), "", "an untrusted hook ran");
    let show = env.ok(U, &proj, &["hooks", "show"]);
    assert!(show.contains("not trusted on this device") && show.contains("scripts/lint.sh"), "{show}");
    // describe of @ would run it too: it warns as well.
    let out = env.ok(U, &proj, &["describe", "-m", "y"]);
    assert!(out.contains("has not trusted"), "{out}");
    assert_eq!(marked(&m), "");
}

#[test]
fn trusted_hooks_run_and_any_change_untrusts_them() {
    let env = Env::new();
    let proj = project(&env);
    let m = marker(&env, "lint");
    trust(&env, &proj);
    assert!(proj.join(".veil/local/hooks-trust.json").is_file());
    let mode = std::fs::metadata(proj.join(".veil/local/hooks-trust.json")).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    env.ok(U, &proj, &["commit", "-m", "one"]);
    assert_eq!(marked(&m), "ran\n");

    // The script changes (and is committed, as a pull would bring it).
    script(&proj, "scripts/lint.sh", &format!("echo changed >> '{}'", m.display()));
    env.ok(U, &proj, &["commit", "-m", "edit lint", "--no-verify"]);
    let out = env.ok(U, &proj, &["commit", "-m", "two"]);
    assert!(out.contains("changed since you trusted it") && out.contains("scripts/lint.sh") && out.contains("by change"), "{out}");
    assert_eq!(marked(&m), "ran\n", "a changed script ran");
    let show = env.ok(U, &proj, &["hooks", "show"]);
    assert!(show.contains("changed since you trusted them") && show.contains("changed since trusted"), "{show}");

    // Trusted again, it runs.
    trust(&env, &proj);
    env.ok(U, &proj, &["commit", "-m", "three"]);
    assert_eq!(marked(&m), "ran\nchanged\n");

    // `.veilhooks` itself changes: untrusted.
    write(&proj, ".veilhooks", "[pre-commit]\nrun = [\"sh\", \"scripts/lint.sh\", \"extra\"]\n");
    let out = env.ok(U, &proj, &["commit", "-m", "four"]);
    assert!(out.contains("changed since you trusted it (.veilhooks"), "{out}");
    assert_eq!(marked(&m), "ran\nchanged\n");

    // An argument that named nothing at trust time and names a file now
    // untrusts the command too.
    trust(&env, &proj);
    write(&proj, "extra", "surprise\n");
    let out = env.ok(U, &proj, &["commit", "-m", "five"]);
    assert!(out.contains("changed since you trusted it (extra"), "{out}");
    assert_eq!(marked(&m), "ran\nchanged\n");
}

#[test]
fn a_teammates_push_never_runs_code_on_this_device() {
    let env = Env::new();
    let alice = project(&env);
    let m = marker(&env, "lint");
    let evil = marker(&env, "evil");
    trust(&env, &alice);
    env.ok(U, &alice, &["tag", "set", "main", "-r", "@-"]);
    let team = env.root.join("team");
    env.ok(U, &alice, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok(U, &alice, &["push"]);

    // Bob never trusted anything: his commits run nothing, and the trust
    // record did not travel.
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    let bob = env.root.join("bob");
    assert!(!bob.join(".veil/local/hooks-trust.json").exists(), "the trust record was synced");
    script(&bob, "scripts/lint.sh", &format!("echo pwned >> '{}'", evil.display()));
    let out = env.ok("bob", &bob, &["commit", "-m", "innocent"]);
    assert!(out.contains("has not trusted"), "{out}");
    env.ok("bob", &bob, &["tag", "set", "main", "-r", "@-"]);
    env.ok("bob", &bob, &["push"]);
    assert_eq!(marked(&evil), "");

    // Alice pulls and works on top of it: the hook is untrusted now.
    env.ok(U, &alice, &["pull"]);
    env.ok(U, &alice, &["new", "main"]);
    assert!(read(&alice, "scripts/lint.sh").contains("pwned"));
    write(&alice, "a.txt", "more\n");
    let out = env.ok(U, &alice, &["commit", "-m", "after pull"]);
    assert!(out.contains("changed since you trusted it") && out.contains("scripts/lint.sh"), "{out}");
    assert_eq!(marked(&evil), "", "a teammate's script ran");
    assert_eq!(marked(&m), "");
}

#[test]
fn a_git_import_brings_no_hooks_and_cannot_write_the_veil_directory() {
    if Command::new("git").arg("--version").output().is_err() {
        return;
    }
    let env = Env::new();
    std::fs::create_dir_all(env.root.join("markers")).unwrap();
    let evil = marker(&env, "evil");
    let g = env.dir("gitrepo");
    let git = |args: &[&str]| {
        let o = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@e", "-c", "init.defaultBranch=main"])
            .args(args)
            .current_dir(&g)
            .output()
            .unwrap();
        assert!(o.status.success(), "git {args:?}: {}", text(&o));
    };
    git(&["init", "-q"]);
    script(&g, "scripts/lint.sh", &format!("echo pwned >> '{}'", evil.display()));
    write(&g, ".veilhooks", "[pre-commit]\nrun = [\"sh\", \"scripts/lint.sh\"]\n");
    script(&g, ".veil/hooks/pre-commit", &format!("echo local-pwned >> '{}'", evil.display()));
    git(&["add", "-A", "-f"]);
    git(&["commit", "-q", "-m", "hooks"]);
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    let _ = env.vl(U, &proj, &["git", "import", g.to_str().unwrap()]);
    assert!(proj.join(".veilhooks").is_file() && proj.join("scripts/lint.sh").is_file(), "the import brought nothing");
    assert!(!proj.join(".veil/hooks/pre-commit").exists(), "a Git import wrote a device-local hook");
    write(&proj, "x.txt", "x\n");
    let out = env.vl(U, &proj, &["commit", "-m", "x"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(marked(&evil), "", "imported content ran code");
}

// ---- 2. time of check to time of use -------------------------------------------------------

#[test]
fn only_trusted_bytes_ever_run_while_the_script_is_swapped() {
    let env = Env::new();
    let proj = project(&env);
    let m = marker(&env, "race");
    let good = format!("#!/bin/sh\necho trusted >> '{}'\n", m.display());
    let bad = format!("#!/bin/sh\necho SWAPPED >> '{}'\n", m.display());
    write(&proj, "scripts/lint.sh", &good);
    write(&proj, ".veilhooks", "[pre-commit]\nrun = [\"sh\", \"scripts/lint.sh\"]\n[pre-push]\nrun = [\"scripts/lint.sh\"]\n");
    std::fs::set_permissions(proj.join("scripts/lint.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    env.ok(U, &proj, &["commit", "-m", "race setup", "--no-verify"]);
    let team = env.root.join("team");
    env.ok(U, &proj, &["remote", "add", "origin", team.to_str().unwrap()]);
    trust(&env, &proj);
    let stop = Arc::new(AtomicBool::new(false));
    let swapper = {
        let stop = stop.clone();
        let path = proj.join("scripts/lint.sh");
        let tmp = proj.join("scripts/.swap");
        std::thread::spawn(move || {
            let mut flip = false;
            while !stop.load(Ordering::Relaxed) {
                // Atomic swaps (rename) and torn writes, both.
                let body = if flip { &bad } else { &good };
                if flip {
                    std::fs::write(&path, body).ok();
                } else {
                    std::fs::write(&tmp, body).ok();
                    std::fs::rename(&tmp, &path).ok();
                }
                flip = !flip;
                std::thread::sleep(Duration::from_micros(300));
            }
            std::fs::write(&path, &good).ok();
        })
    };
    // Each commit may be refused (the swap was recorded, or the script
    // changed between the trust check and the copy) or go through; either
    // way only the trusted bytes may run. Go on until they did run a few
    // times, so the race was really run.
    let started = Instant::now();
    let mut i = 0;
    while marked(&m).matches("trusted").count() < 3 && started.elapsed() < Duration::from_secs(120) {
        let _ = env.vl(U, &proj, &["commit", "-m", &format!("r{i}")]);
        // The pre-push command runs the script itself (exec of the copy).
        let _ = env.vl(U, &proj, &["push"]);
        i += 1;
    }
    stop.store(true, Ordering::Relaxed);
    swapper.join().unwrap();
    let log = marked(&m);
    assert!(!log.contains("SWAPPED"), "swapped bytes ran:\n{log}");
    assert!(log.contains("trusted"), "the trusted script never ran in {i} commits");
}

// ---- 3. indirect execution -----------------------------------------------------------------

#[test]
fn build_tools_need_explicit_indirect_trust_and_their_files_are_pinned() {
    let env = Env::new();
    let proj = project(&env);
    write(&proj, "Makefile", "lint:\n\ttrue\n");
    write(&proj, ".veilhooks", "[pre-commit]\nrun = [\"make\", \"lint\"]\n");
    env.ok(U, &proj, &["commit", "-m", "make", "--no-verify"]);
    let out = env.vl(U, &proj, &["hooks", "trust", "--yes"]);
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("--i-understand-indirect") && t.contains("Makefile"), "{t}");
    assert!(!proj.join(".veil/local/hooks-trust.json").exists());
    env.ok(U, &proj, &["hooks", "trust", "--yes", "--i-understand-indirect"]);
    let show = env.ok(U, &proj, &["hooks", "show"]);
    assert!(show.contains("runs a build tool") && show.contains("Makefile"), "{show}");
    // The Makefile changes: the hook is untrusted.
    write(&proj, "Makefile", "lint:\n\ttouch /tmp/pwned-by-make\n");
    let out = env.ok(U, &proj, &["commit", "-m", "x"]);
    assert!(out.contains("changed since you trusted it") && out.contains("Makefile"), "{out}");
}

// ---- 4. hook input never leaks sealed content ----------------------------------------------

/// A pre-push hook that saves its argv and stdin outside the project.
fn capture_push(env: &Env, proj: &Path) -> (PathBuf, PathBuf) {
    let argv = marker(env, "push-argv");
    let input = marker(env, "push-stdin");
    script(
        proj,
        ".veil/hooks/pre-push",
        &format!("printf '%s\\n' \"$@\" > '{}'\ncat > '{}'", argv.display(), input.display()),
    );
    (argv, input)
}

#[test]
fn pre_push_input_never_names_cloaked_tags_or_withheld_history_on_a_public_remote() {
    let env = Env::new();
    std::fs::create_dir_all(env.root.join("markers")).unwrap();
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, "auth.rs", "fn check() { true }\n");
    env.ok(U, &proj, &["commit", "-m", "v1"]);
    env.ok(U, &proj, &["tag", "set", "main", "-r", "@-"]);
    let mirror = env.dir("mirror");
    env.ok(U, &proj, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    env.ok(U, &proj, &["push", "mirror"]);
    // An embargoed fix merged into main, and a cloaked tag.
    env.ok(U, &proj, &["ws", "new", "fix", "-r", "main", "--cloak", "team"]);
    let mut c = env.cmd(U, &proj, &["ws", "write", "fix", "auth.rs"]);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"fn check() { verify_secretfix() }\n").unwrap();
    assert!(child.wait_with_output().unwrap().status.success());
    env.ok(U, &proj, &["merge", "fix@", "--into", "main", "--embargo", "-m", "Fix CVE"]);
    env.ok(U, &proj, &["tag", "set", "cloakedtagname", "-r", "fix@", "--cloak", "team"]);
    env.ok(U, &proj, &["tag", "set", "public-feature", "-r", "main"]);
    let plan: serde_json::Value = serde_json::from_str(&env.stdout(U, &proj, &["push", "mirror", "--dry-run", "--json"])).unwrap();
    let withheld: Vec<String> = plan["remotes"][0]["withheld_snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["snapshot_id"].as_str().unwrap().to_string())
        .collect();
    let fix_id: serde_json::Value = serde_json::from_str(&env.stdout(U, &proj, &["show", "fix@", "--json"])).unwrap();
    let fix_id = fix_id["snapshot_id"].as_str().map(String::from);

    let (argv, input) = capture_push(&env, &proj);
    env.ok(U, &proj, &["push", "mirror"]);
    let args = marked(&argv);
    assert_eq!(args, format!("mirror\n{}\npublic\n", mirror.display()), "{args}");
    let stdin = marked(&input);
    assert!(stdin.contains("public-feature "), "{stdin}");
    assert!(!stdin.contains("cloakedtagname"), "a cloaked tag reached a public pre-push hook:\n{stdin}");
    assert!(!stdin.contains("secretfix") && !stdin.contains("Fix CVE"), "{stdin}");
    for w in withheld.iter().chain(fix_id.iter()) {
        assert!(!stdin.contains(w.as_str()), "withheld snapshot {w} reached the hook:\n{stdin}");
    }
    for line in stdin.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        assert_eq!(f.len(), 3, "{line}");
        assert!(f[1].len() == 64 && (f[2] == "0" || f[2].len() == 64), "{line}");
    }

    // A team remote is told about the cloaked tag (its members may see it).
    let team = env.dir("teamremote");
    env.ok(U, &proj, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok(U, &proj, &["push", "origin"]);
    assert!(marked(&argv).ends_with("team\n"));
    assert!(marked(&input).contains("cloakedtagname "), "{}", marked(&input));
}

#[test]
fn git_push_pre_push_input_names_exported_commits_only_and_redacts_the_url() {
    if Command::new("git").arg("--version").output().is_err() {
        return;
    }
    let env = Env::new();
    std::fs::create_dir_all(env.root.join("markers")).unwrap();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    env.ok(U, &proj, &["tag", "set", "cloakedtagname", "-r", "@-", "--cloak", "team"]);
    let bare = env.dir("bare.git");
    assert!(Command::new("git").args(["init", "-q", "--bare"]).arg(&bare).status().unwrap().success());
    env.ok(U, &proj, &["git", "remote", "add", "gh", bare.to_str().unwrap()]);
    let (argv, input) = capture_push(&env, &proj);
    env.ok(U, &proj, &["git", "push", "gh"]);
    assert_eq!(marked(&argv), format!("gh\n{}\ngit\n", bare.display()));
    let stdin = marked(&input);
    assert!(!stdin.contains("cloakedtagname"), "{stdin}");
    let line = stdin.lines().find(|l| l.starts_with("main ")).unwrap_or_else(|| panic!("{stdin}"));
    let f: Vec<&str> = line.split(' ').collect();
    assert_eq!(f.len(), 4, "{line}");
    let head = Command::new("git").args(["--git-dir", bare.to_str().unwrap(), "rev-parse", "main"]).output().unwrap();
    assert_eq!(f[3], String::from_utf8_lossy(&head.stdout).trim(), "{line}");

    // Credentials in a Git URL never reach the hook; a failing hook stops
    // the push before anything is sent.
    env.ok(U, &proj, &["git", "remote", "add", "creds", "https://bob:s3cr3t-token@127.0.0.1:9/x.git"]);
    script(&proj, ".veil/hooks/pre-push", &format!("printf '%s\\n' \"$@\" > '{}'\nexit 3", argv.display()));
    let out = env.vl(U, &proj, &["git", "push", "creds"]);
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("pre-push hook") && t.contains("exit status 3") && t.contains("nothing was pushed"), "{t}");
    let a = marked(&argv);
    assert!(a.contains("***") && !a.contains("s3cr3t-token"), "{a}");
}

/// BUG-641: `vl git push` tells `pre-push` about the Git tags it pushes, in
/// Git's own format (`refs/tags/<name> <local> refs/tags/<name> <remote>`),
/// including a tag-only push and a tag deletion, and never about a cloaked
/// release tag or one an unreleased embargo holds back.
#[test]
fn git_push_pre_push_input_lists_git_tags_in_gits_format() {
    if Command::new("git").arg("--version").output().is_err() {
        return;
    }
    let env = Env::new();
    std::fs::create_dir_all(env.root.join("markers")).unwrap();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    let bare = env.dir("bare.git");
    assert!(Command::new("git").args(["init", "-q", "--bare"]).arg(&bare).status().unwrap().success());
    env.ok(U, &proj, &["git", "remote", "add", "gh", bare.to_str().unwrap()]);
    let git_ref = |r: &str| {
        let o = Command::new("git").args(["--git-dir", bare.to_str().unwrap(), "rev-parse", r]).output().unwrap();
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    };
    let zeros = "0".repeat(40);
    env.ok(U, &proj, &["tag", "set", "v1.0", "-r", "@-", "-a", "-m", "Release 1.0"]);
    env.ok(U, &proj, &["tag", "set", "v-cloaked-rel", "-r", "@-", "-a", "-m", "team notes", "--cloak"]);
    let (_, input) = capture_push(&env, &proj);
    env.ok(U, &proj, &["git", "push", "gh"]);
    let stdin = marked(&input);
    let line = format!("refs/tags/v1.0 {} refs/tags/v1.0 {zeros}", git_ref("refs/tags/v1.0"));
    assert!(stdin.lines().any(|l| l == line), "{line} missing from:\n{stdin}");
    assert!(stdin.lines().any(|l| l.starts_with("main ")), "{stdin}");
    assert!(!stdin.contains("v-cloaked-rel"), "a cloaked release tag reached the hook:\n{stdin}");

    // A tag-only push: the hook sees the tag, and no branch.
    env.ok(U, &proj, &["tag", "set", "v1.1", "-r", "@-", "-a", "-m", "Release 1.1"]);
    env.ok(U, &proj, &["git", "push", "gh", "--tag", "v1.1"]);
    let stdin = marked(&input);
    assert_eq!(stdin, format!("refs/tags/v1.1 {} refs/tags/v1.1 {zeros}\n", git_ref("refs/tags/v1.1")), "{stdin}");

    // Pushed again, a tag the remote already holds names what it holds.
    env.ok(U, &proj, &["git", "push", "gh", "--tag", "v1.1"]);
    let held = git_ref("refs/tags/v1.1");
    assert_eq!(marked(&input), format!("refs/tags/v1.1 {held} refs/tags/v1.1 {held}\n"));

    // A release tag an unreleased embargo holds back is never named.
    env.ok(U, &proj, &["new", "main"]);
    write(&proj, "fix.txt", "the fix\n");
    env.ok(U, &proj, &["commit", "--no-advance", "-m", "fix"]);
    env.ok(U, &proj, &["tag", "set", "fix-line", "-r", "@-", "--cloak", "team"]);
    env.ok(U, &proj, &["merge", "fix-line", "--into", "main", "--embargo", "-m", "Fix CVE"]);
    env.ok(U, &proj, &["tag", "set", "v2.0-held", "-r", "main", "-a", "-m", "Release 2.0"]);
    let out = env.ok(U, &proj, &["git", "push", "gh"]);
    assert!(out.contains("skipped v2.0-held"), "{out}");
    let stdin = marked(&input);
    assert!(!stdin.contains("v2.0-held") && !stdin.contains("fix-line"), "{stdin}");
    let out = env.vl(U, &proj, &["git", "push", "gh", "--tag", "v2.0-held"]);
    assert!(!out.status.success() && text(&out).contains("skipped v2.0-held"), "{}", text(&out));
    assert_eq!(marked(&input), "", "a held-back tag reached the hook");

    // A tag deletion, alone: Git's `(delete)` line, naming what the remote held.
    let old = git_ref("refs/tags/v1.0");
    env.ok(U, &proj, &["tag", "delete", "v1.0"]);
    env.ok(U, &proj, &["git", "push", "gh", "--delete-tag", "v1.0"]);
    assert_eq!(marked(&input), format!("(delete) {zeros} refs/tags/v1.0 {old}\n"));
}

#[test]
fn a_failing_or_tag_moving_pre_push_hook_stops_the_push() {
    let env = Env::new();
    std::fs::create_dir_all(env.root.join("markers")).unwrap();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    let team = env.dir("team");
    env.ok(U, &proj, &["remote", "add", "origin", team.to_str().unwrap()]);
    script(&proj, ".veil/hooks/pre-push", "exit 1");
    let out = env.vl(U, &proj, &["push"]);
    assert!(!out.status.success() && text(&out).contains("nothing was pushed"), "{}", text(&out));
    assert!(!team.join(".veil").exists(), "a refused push created the remote");
    script(
        &proj,
        ".veil/hooks/pre-push",
        &format!("'{}' tag set other -r @- >/dev/null 2>&1; cat >/dev/null", vl_bin()),
    );
    let out = env.vl(U, &proj, &["push"]);
    assert!(!out.status.success() && text(&out).contains("tags changed while the pre-push hook ran"), "{}", text(&out));
    assert!(!team.join(".veil").exists());
    // `--no-verify` skips it.
    env.ok(U, &proj, &["push", "--no-verify"]);
    assert!(team.join(".veil").exists());
}

// ---- 5. environment ------------------------------------------------------------------------

#[test]
fn the_hook_environment_is_scrubbed() {
    let env = Env::new();
    let proj = project(&env);
    let dump = marker(&env, "env");
    script(&proj, ".veil/hooks/pre-commit", &format!("env > '{}'", dump.display()));
    env.ok(U, &proj, &["secret", "set", "API_TOKEN", "vault-canary-1234"]);
    let path = format!(".:{}:{}:{}", proj.display(), proj.join("scripts").display(), std::env::var("PATH").unwrap());
    let out = env
        .cmd(U, &proj, &["commit", "-m", "x"])
        .env("MY_SECRET", "env-canary-5678")
        .env("VEIL_TEAM_KEY", "veil-canary-9012")
        .env("VEIL_SSH", "ssh-canary")
        .env("GIT_DIR", "/git-canary")
        .env("AWS_SECRET_ACCESS_KEY", "aws-canary")
        .env("PATH", &path)
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let e = marked(&dump);
    for canary in ["env-canary", "veil-canary", "ssh-canary", "git-canary", "aws-canary", "vault-canary", "VEIL_USER", "NO_COLOR"] {
        assert!(!e.contains(canary), "{canary} reached the hook:\n{e}");
    }
    assert!(e.contains("VEIL_HOOK=pre-commit") && e.contains("VEIL_SNAPSHOT=") && e.contains("VEIL_WORKSPACE=default"), "{e}");
    assert!(e.contains("LC_ALL=C"), "{e}");
    let hook_path = e.lines().find_map(|l| l.strip_prefix("PATH=")).unwrap();
    for entry in hook_path.split(':') {
        assert!(entry.starts_with('/') && !entry.starts_with(proj.to_str().unwrap()), "PATH entry {entry:?}: {hook_path}");
    }

    // Under `vl run`, the vault's secrets are in vl's environment; the
    // hook still does not get them.
    std::fs::remove_file(&dump).unwrap();
    write(&proj, "a.txt", "under run\n");
    env.ok(U, &proj, &["run", "--", vl_bin(), "commit", "-m", "under run"]);
    let e = marked(&dump);
    assert!(e.contains("VEIL_HOOK=pre-commit"), "{e}");
    assert!(!e.contains("vault-canary") && !e.contains("API_TOKEN"), "a vault secret reached the hook:\n{e}");
}

#[test]
fn a_repository_file_never_becomes_a_command_by_path_lookup() {
    let env = Env::new();
    let proj = project(&env);
    let evil = marker(&env, "evil");
    // `.veilhooks` names a bare program; the project has an executable of
    // that name, and PATH reaches it through `.` and an absolute entry.
    script(&proj, "linter", &format!("echo pwned >> '{}'", evil.display()));
    write(&proj, ".veilhooks", "[pre-commit]\nrun = [\"linter\"]\n");
    env.ok(U, &proj, &["commit", "-m", "x", "--no-verify"]);
    trust(&env, &proj);
    for path in [".".to_string(), proj.display().to_string(), String::new()] {
        let out = env.cmd(U, &proj, &["commit", "-m", "y"]).env("PATH", format!("{path}:/usr/bin:/bin")).output().unwrap();
        let t = text(&out);
        assert!(!out.status.success(), "{t}");
        assert!(t.contains("not found on PATH"), "{t}");
        assert_eq!(marked(&evil), "", "PATH={path:?} ran a repository file");
    }
}

// ---- 6. deadlocks and lost operations ------------------------------------------------------

#[test]
fn a_hook_that_edits_files_or_runs_vl_refuses_the_commit_and_loses_nothing() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    // `vl status` inside the hook neither deadlocks nor refuses anything.
    script(&proj, ".veil/hooks/pre-commit", &format!("'{}' status >/dev/null", vl_bin()));
    write(&proj, "a.txt", "work\n");
    let started = Instant::now();
    env.ok(U, &proj, &["commit", "-m", "with status"]);
    assert!(started.elapsed() < Duration::from_secs(60));
    assert!(description(&env, &proj, "@-").contains("with status"));

    script(
        &proj,
        ".veil/hooks/pre-commit",
        &format!("'{}' describe -m from-hook >/dev/null 2>&1\necho hook-edit > a.txt", vl_bin()),
    );
    write(&proj, "a.txt", "precious\n");
    let before = head_op(&env, &proj);
    let out = env.vl(U, &proj, &["commit", "-m", "mine"]);
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("changed while the pre-commit hooks ran") && t.contains("nothing was lost"), "{t}");
    assert_ne!(head_op(&env, &proj), before);
    // Nothing committed; the hook's edit and description are in @.
    assert!(!description(&env, &proj, "@-").contains("mine"));
    assert_eq!(env.stdout(U, &proj, &["cat", "a.txt"]), "hook-edit\n");
    assert!(description(&env, &proj, "@").contains("from-hook"));
    // The edit the user made before is in history (the op log).
    let ops = env.stdout(U, &proj, &["op", "log"]);
    assert!(ops.contains("snapshot"), "{ops}");
    // A hook that only edits files refuses the commit too.
    script(&proj, ".veil/hooks/pre-commit", "echo again >> a.txt");
    let out = env.vl(U, &proj, &["commit", "-m", "mine"]);
    assert!(!out.status.success() && text(&out).contains("hook edited files"), "{}", text(&out));
    assert_eq!(read(&proj, "a.txt"), "hook-edit\nagain\n");
}

// ---- 7. vl serve ---------------------------------------------------------------------------

struct Server(std::process::Child);

impl Drop for Server {
    fn drop(&mut self) {
        // SAFETY: signals our own child.
        unsafe { libc::kill(self.0.id() as i32, libc::SIGTERM) };
        let _ = self.0.wait();
    }
}

fn rpc(sock: &Path, method: &str, params: serde_json::Value) -> serde_json::Value {
    let mut s = UnixStream::connect(sock).unwrap();
    let req = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    s.write_all(format!("{req}\n").as_bytes()).unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

#[test]
fn serve_commit_runs_the_same_hooks_and_keeps_their_output_out_of_the_reply() {
    let env = Env::new();
    let proj = project(&env);
    let m = marker(&env, "lint");
    script(&proj, "scripts/lint.sh", &format!("echo STDOUT-CANARY\necho STDERR-CANARY >&2\necho ran >> '{}'", m.display()));
    env.ok(U, &proj, &["commit", "-m", "loud", "--no-verify"]);
    let errlog = env.root.join("serve.err");
    let child = env
        .cmd(U, &proj, &["serve", "--local"])
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&errlog).unwrap())
        .spawn()
        .unwrap();
    let server = Server(child);
    let sock = proj.join(".veil/local/sock");
    assert!(wait_for(Duration::from_secs(20), || UnixStream::connect(&sock).is_ok()));

    // Untrusted: the commit goes through, the hook does not run.
    write(&proj, "a.txt", "via serve\n");
    let r = rpc(&sock, "commit", serde_json::json!({"message": "untrusted"}));
    assert!(r["result"].is_object(), "{r}");
    assert_eq!(marked(&m), "");
    // There is no method to trust hooks.
    let r = rpc(&sock, "hooks.trust", serde_json::json!({}));
    assert!(r["error"].is_object(), "{r}");

    trust(&env, &proj);
    let r = rpc(&sock, "commit", serde_json::json!({"message": "trusted"}));
    let reply = r.to_string();
    assert!(r["result"].is_object(), "{reply}");
    assert_eq!(marked(&m), "ran\n");
    assert!(!reply.contains("CANARY"), "hook output reached the reply: {reply}");
    // `vl serve --call` prints the reply on stdout: no hook output there.
    let out = env.vl(U, &proj, &["serve", "--call", "commit", r#"{"message": "via call"}"#]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("CANARY"));
    assert_eq!(marked(&m), "ran\nran\n");
    // A failing hook: an error reply, nothing committed, no output in it.
    script(&proj, "scripts/lint.sh", "echo STDOUT-CANARY\nexit 1");
    trust(&env, &proj);
    let r = rpc(&sock, "commit", serde_json::json!({"message": "fails"}));
    let reply = r.to_string();
    assert!(r["error"].is_object() && reply.contains("pre-commit hook") && !reply.contains("CANARY"), "{reply}");
    // ...unless `no_verify`.
    let r = rpc(&sock, "commit", serde_json::json!({"message": "skips", "no_verify": true}));
    assert!(r["result"].is_object(), "{r}");
    drop(server);
    assert!(read(&env.root, "serve.err").contains("STDOUT-CANARY"), "hook output should go to the server's stderr");
}

// ---- 8. denial of service ------------------------------------------------------------------

/// Is `pid` running (a zombie waiting for a reaper is not)?
fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 only checks.
    if unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(s) => s.rsplit(')').next().and_then(|r| r.split_whitespace().next()) != Some("Z"),
        Err(_) => true,
    }
}

#[test]
fn a_hook_that_never_exits_is_killed_with_its_process_group() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    std::fs::create_dir_all(env.root.join("markers")).unwrap();
    let pids = marker(&env, "pids");
    script(&proj, ".veil/hooks/pre-commit", &format!("sleep 1000 &\necho $! > '{}'\nwait", pids.display()));
    let started = Instant::now();
    let out = env.cmd(U, &proj, &["commit", "-m", "x"]).env("VEIL_HOOK_TIMEOUT", "1").output().unwrap();
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("did not finish within 1s") && t.contains("VEIL_HOOK_TIMEOUT"), "{t}");
    assert!(started.elapsed() < Duration::from_secs(30));
    let pid: i32 = marked(&pids).trim().parse().unwrap();
    assert!(wait_for(Duration::from_secs(5), || !alive(pid)), "the hook's child {pid} outlived it");
    assert_ne!(description(&env, &proj, "@-"), "x");
}

#[test]
fn hostile_hook_timeouts_are_refused_before_anything_runs() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    std::fs::create_dir_all(env.root.join("markers")).unwrap();
    let m = marker(&env, "ran");
    script(&proj, ".veil/hooks/pre-commit", &format!("echo ran >> '{}'", m.display()));
    for bad in ["abc", "0", "-1", "1.5", "99999999999999999999", "", " "] {
        let out = env.cmd(U, &proj, &["commit", "-m", "x"]).env("VEIL_HOOK_TIMEOUT", bad).output().unwrap();
        let t = text(&out);
        assert_eq!(out.status.code(), Some(1), "{bad:?}: {t}");
        assert!(t.contains("VEIL_HOOK_TIMEOUT") && !t.contains("panicked"), "{bad:?}: {t}");
    }
    assert_eq!(marked(&m), "");
}

#[test]
fn ctrl_c_reaches_the_hook_and_stops_the_command() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    std::fs::create_dir_all(env.root.join("markers")).unwrap();
    let pids = marker(&env, "pids");
    script(&proj, ".veil/hooks/pre-commit", &format!("echo $$ > '{}'\nsleep 1000 &\nwait", pids.display()));
    let mut child = env.cmd(U, &proj, &["commit", "-m", "x"]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    assert!(wait_for(Duration::from_secs(20), || !marked(&pids).is_empty()));
    let hook: i32 = marked(&pids).trim().parse().unwrap();
    // SAFETY: signals our own child.
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let started = Instant::now();
    let st = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        assert!(started.elapsed() < Duration::from_secs(20), "vl did not stop on SIGINT");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(!st.success());
    assert!(wait_for(Duration::from_secs(5), || !alive(hook)), "the hook survived Ctrl-C");
}

// ---- 9. sandboxes --------------------------------------------------------------------------

#[test]
fn sandboxes_never_run_hooks() {
    let env = Env::new();
    let proj = project(&env);
    let m = marker(&env, "lint");
    let local = marker(&env, "local");
    script(&proj, ".veil/hooks/pre-commit", &format!("echo local >> '{}'", local.display()));
    trust(&env, &proj);
    env.ok(U, &proj, &["ws", "new", "agent"]);
    let out = env.ok(
        U,
        &proj,
        &["ws", "exec", "agent", "-m", "agent work", "--", "sh", "-c", &format!("echo hi > out.txt; '{}' commit -m inner || true", vl_bin())],
    );
    let _ = out;
    assert_eq!(marked(&m), "", "a sandbox ran a repository hook");
    assert_eq!(marked(&local), "", "a sandbox ran a device-local hook");
    assert_eq!(env.ok(U, &proj, &["ws", "cat", "agent", "out.txt"]), "hi\n");
    // An untrusted `.veilhooks` written inside the sandbox does not run
    // when the project commits.
    env.ok(
        U,
        &proj,
        &["ws", "exec", "agent", "-m", "hooks", "--", "sh", "-c", "printf '[pre-commit]\\nrun = [\"sh\", \"evil.sh\"]\\n' > .veilhooks"],
    );
    env.ok(U, &proj, &["ws", "switch", "agent"]);
    let out = env.ok(U, &proj, &["commit", "-m", "from agent"]);
    assert!(out.contains("changed since you trusted it (.veilhooks"), "{out}");
}

// ---- the rest of the surface ---------------------------------------------------------------

#[test]
fn device_local_hooks_run_without_trust_and_no_verify_skips_every_hook() {
    let env = Env::new();
    let proj = project(&env);
    let m = marker(&env, "lint");
    let local = marker(&env, "local");
    let global = marker(&env, "global");
    trust(&env, &proj);
    script(&proj, ".veil/hooks/pre-commit", &format!("echo local >> '{}'", local.display()));
    script(&env.root.join(format!("home-{U}")), "hooks/pre-commit", &format!("echo global >> '{}'", global.display()));
    env.ok(U, &proj, &["commit", "-m", "one"]);
    assert_eq!((marked(&global), marked(&local), marked(&m)), ("global\n".into(), "local\n".into(), "ran\n".into()));
    env.ok(U, &proj, &["commit", "-m", "two", "--no-verify"]);
    env.ok(U, &proj, &["describe", "-m", "three", "--no-verify"]);
    assert_eq!(marked(&m), "ran\n");
    assert_eq!(marked(&local), "local\n");
    // Not executable: skipped, with a warning.
    std::fs::set_permissions(proj.join(".veil/hooks/pre-commit"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = env.ok(U, &proj, &["commit", "-m", "four"]);
    assert!(out.contains("is not executable"), "{out}");
    assert_eq!(marked(&local), "local\n");
    // A failing local hook aborts.
    script(&proj, ".veil/hooks/pre-commit", "exit 7");
    let before = head_op(&env, &proj);
    let out = env.vl(U, &proj, &["commit", "-m", "five"]);
    let t = text(&out);
    assert!(!out.status.success() && t.contains("exit status 7") && t.contains("--no-verify"), "{t}");
    assert_eq!(head_op(&env, &proj), before, "a refused commit recorded an operation");
}

#[test]
fn describe_of_the_working_copy_runs_pre_commit_and_others_do_not() {
    let env = Env::new();
    let proj = project(&env);
    let m = marker(&env, "lint");
    trust(&env, &proj);
    env.ok(U, &proj, &["describe", "-r", "@-", "-m", "older"]);
    assert_eq!(marked(&m), "");
    env.ok(U, &proj, &["describe", "-m", "current"]);
    assert_eq!(marked(&m), "ran\n");
}

#[test]
fn commit_msg_edits_the_message_through_a_private_file() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    std::fs::create_dir_all(env.root.join("markers")).unwrap();
    let perms = marker(&env, "perms");
    script(
        &proj,
        ".veil/hooks/commit-msg",
        &format!(
            "case \"$1\" in *'/.veil/local/tmp/'*) ;; *) exit 9 ;; esac\n\
             if [ \"$(uname)\" = Darwin ]; then stat -f %Lp \"$1\"; else stat -c %a \"$1\"; fi > '{}'\n\
             printf '\\nSigned-off-by: alice\\n' >> \"$1\"",
            perms.display()
        ),
    );
    env.ok(U, &proj, &["commit", "-m", "subject"]);
    assert_eq!(marked(&perms).trim(), "600");
    let shown = description(&env, &proj, "@-");
    assert!(shown.contains("subject") && shown.contains("Signed-off-by: alice"), "{shown}");
    assert!(std::fs::read_dir(proj.join(".veil/local/tmp")).unwrap().next().is_none(), "the message file was left behind");
    // A failing commit-msg hook aborts; a NUL in the edited message is refused.
    script(&proj, ".veil/hooks/commit-msg", "exit 1");
    assert!(!env.vl(U, &proj, &["commit", "-m", "no"]).status.success());
    script(&proj, ".veil/hooks/commit-msg", "printf 'a\\000b' > \"$1\"");
    let out = env.vl(U, &proj, &["commit", "-m", "nul"]);
    assert!(!out.status.success() && text(&out).contains("NUL"), "{}", text(&out));
    // A hook that swaps the file for a symbolic link is refused.
    script(&proj, ".veil/hooks/commit-msg", "rm \"$1\"; ln -s /etc/passwd \"$1\"");
    let out = env.vl(U, &proj, &["commit", "-m", "link"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(!description(&env, &proj, "@-").contains("root:"));
}

#[test]
fn post_checkout_gets_old_and_new_and_never_fails_the_command() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    std::fs::create_dir_all(env.root.join("markers")).unwrap();
    let m = marker(&env, "checkout");
    script(&proj, ".veil/hooks/post-checkout", &format!("echo \"$1 $2\" >> '{}'\nexit 1", m.display()));
    let out = env.ok(U, &proj, &["new", "-m", "next"]);
    assert!(out.contains("post-checkout hook") && out.contains("exit status 1"), "{out}");
    let line = marked(&m);
    let ids: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(ids.len(), 2, "{line}");
    assert!(ids[0].len() == 64 && ids[1].len() == 64 && ids[0] != ids[1], "{line}");
    env.ok(U, &proj, &["edit", "@-"]);
    env.ok(U, &proj, &["ws", "new", "other"]);
    env.ok(U, &proj, &["ws", "switch", "other"]);
    assert_eq!(marked(&m).lines().count(), 3, "{}", marked(&m));
    // Commands that do not move the working copy run nothing.
    env.ok(U, &proj, &["status"]);
    assert_eq!(marked(&m).lines().count(), 3);
}

#[test]
fn hostile_veilhooks_files_run_nothing() {
    let env = Env::new();
    let proj = project(&env);
    let m = marker(&env, "lint");
    trust(&env, &proj);
    type Case<'a> = (&'a str, Box<dyn Fn() + 'a>);
    let cases: Vec<Case> = vec![
        ("invalid TOML", Box::new(|| write(&proj, ".veilhooks", "[pre-commit\nrun = ["))),
        ("unknown hook", Box::new(|| write(&proj, ".veilhooks", "[post-merge]\nrun = [\"sh\", \"scripts/lint.sh\"]\n"))),
        ("too large", Box::new(|| write(&proj, ".veilhooks", &format!("# {}\n[pre-commit]\nrun = [\"sh\", \"scripts/lint.sh\"]\n", "x".repeat(70_000))))),
        (
            "deep nesting",
            Box::new(|| write(&proj, ".veilhooks", &format!("[pre-commit]\nrun = {}{}\n", "[".repeat(10_000), "]".repeat(10_000)))),
        ),
        ("not UTF-8", Box::new(|| std::fs::write(proj.join(".veilhooks"), b"[pre-commit]\nrun = [\"\xff\"]\n").unwrap())),
        (
            "symbolic link",
            Box::new(|| {
                let target = env.root.join("elsewhere.toml");
                std::fs::write(&target, "[pre-commit]\nrun = [\"sh\", \"scripts/lint.sh\"]\n").unwrap();
                std::os::unix::fs::symlink(&target, proj.join(".veilhooks")).unwrap();
            }),
        ),
        (
            "escaping script",
            Box::new(|| write(&proj, ".veilhooks", "[pre-commit]\nrun = [\"../escape.sh\"]\n")),
        ),
    ];
    for (what, make) in cases {
        let _ = std::fs::remove_file(proj.join(".veilhooks"));
        make();
        let out = env.vl(U, &proj, &["commit", "-m", what]);
        let t = text(&out);
        assert!(out.status.success() && !t.contains("panicked"), "{what}: {t}");
        assert!(t.contains("warning:"), "{what}: no warning: {t}");
        assert_eq!(marked(&m), "", "{what}: a hook ran");
        assert!(!env.vl(U, &proj, &["hooks", "trust", "--yes"]).status.success(), "{what}: trusted");
    }
    // A script that is a symbolic link out of the project cannot be trusted.
    let _ = std::fs::remove_file(proj.join(".veilhooks"));
    write(&proj, ".veilhooks", "[pre-commit]\nrun = [\"sh\", \"scripts/linked.sh\"]\n");
    std::os::unix::fs::symlink("/bin/true", proj.join("scripts/linked.sh")).unwrap();
    let out = env.vl(U, &proj, &["hooks", "trust", "--yes"]);
    assert!(!out.status.success() && text(&out).contains("not a regular file"), "{}", text(&out));
    // An absolute argument inside the project is refused at run time.
    std::fs::remove_file(proj.join("scripts/linked.sh")).unwrap();
    write(&proj, ".veilhooks", &format!("[pre-commit]\nrun = [\"sh\", \"{}\"]\n", proj.join("scripts/lint.sh").display()));
    trust(&env, &proj);
    let out = env.vl(U, &proj, &["commit", "-m", "abs"]);
    assert!(!out.status.success() && text(&out).contains("relative path"), "{}", text(&out));
    assert_eq!(marked(&m), "");
}

#[test]
fn trust_needs_a_terminal_or_yes_and_never_comes_from_a_hook() {
    let env = Env::new();
    let proj = project(&env);
    let out = env.cmd(U, &proj, &["hooks", "trust"]).stdin(Stdio::null()).output().unwrap();
    let t = text(&out);
    assert!(!out.status.success() && t.contains("--yes"), "{t}");
    assert!(!proj.join(".veil/local/hooks-trust.json").exists());
    let out = env.cmd(U, &proj, &["hooks", "trust", "--yes"]).env("VEIL_HOOK", "pre-commit").output().unwrap();
    assert!(!out.status.success() && text(&out).contains("a hook cannot trust hooks"), "{}", text(&out));
    assert!(!proj.join(".veil/local/hooks-trust.json").exists());
    // A damaged trust record trusts nothing (and says so).
    std::fs::write(proj.join(".veil/local/hooks-trust.json"), "{not json").unwrap();
    let out = env.ok(U, &proj, &["commit", "-m", "x"]);
    assert!(out.contains("damaged"), "{out}");
    assert_eq!(marked(&marker(&env, "lint")), "");
    // A forged record for other digests trusts nothing either.
    std::fs::write(
        proj.join(".veil/local/hooks-trust.json"),
        format!(r#"{{"version":1,"veilhooks":"{}","trusted":[]}}"#, "0".repeat(64)),
    )
    .unwrap();
    let out = env.ok(U, &proj, &["commit", "-m", "y"]);
    assert!(out.contains("changed since you trusted it"), "{out}");
    assert_eq!(marked(&marker(&env, "lint")), "");
}
