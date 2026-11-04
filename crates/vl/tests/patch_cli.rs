//! `vl format-patch` and `vl am` through the real binary: round trips
//! (Veil → Veil, Veil → `git am`), the public view as the Git export's own
//! (differential against `git format-patch` on the bridge), and the threat
//! review of `docs/design/git-parity/4-patches.md`.

mod adversarial_support;

use std::{
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use adversarial_support::{text, write, Env};
use proptest::prelude::*;

const U: &str = "Alice <alice@example.com>";
const B: &str = "Bob <bob@example.com>";

fn git_out(dir: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", dir)
        .env("GIT_AUTHOR_NAME", "Gita Hub")
        .env("GIT_AUTHOR_EMAIL", "gita@example.com")
        .env("GIT_COMMITTER_NAME", "Gita Hub")
        .env("GIT_COMMITTER_EMAIL", "gita@example.com")
        .args(["-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"])
        .args(args)
        .output()
        .unwrap()
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = git_out(dir, args);
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `vl args` with `input` on standard input.
fn vl_stdin(env: &Env, user: &str, cwd: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut c = env.cmd(user, cwd, args);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn ws_write(env: &Env, proj: &Path, ws: &str, path: &str, content: &str) {
    let out = vl_stdin(env, U, proj, &["ws", "write", ws, path], content.as_bytes());
    assert!(out.status.success(), "ws write: {}", text(&out));
}

fn head_op(env: &Env, proj: &Path) -> String {
    let log: serde_json::Value = serde_json::from_str(&env.stdout(U, proj, &["op", "log", "-n", "1", "--json"])).unwrap();
    log["operations"][0]["op_id"].as_str().unwrap().to_string()
}

/// Every marker that must never leave Alice's device in a public patch.
const SECRETS: &[&str] = &["SEALED-TOKEN-0101", "ISOLATED-VALUE-0202", "SEALED-LINE-0303", "SEALED-DESC-0404", "token.txt"];

/// Alice's project: `main` (initial), then `v2` with a cloaked file and an
/// isolated `.env`, then a cloaked line `sec` on top with a sealed edit of
/// a public file and a sealed description.
fn project(env: &Env) -> PathBuf {
    let proj = env.project(U, "proj", &[("README", "hello\n"), ("app.txt", "v1\n")]);
    env.ok(U, &proj, &["cloak", "secrets/"]);
    write(&proj, "secrets/token.txt", "SEALED-TOKEN-0101\n");
    write(&proj, ".env", "API_KEY=ISOLATED-VALUE-0202\n");
    write(&proj, "app.txt", "v1\nv2\n");
    env.ok(U, &proj, &["commit", "--no-advance", "-m", "v2 with secrets\n\nThe body of v2."]);
    env.ok(U, &proj, &["tag", "set", "v2", "-r", "@-"]);
    env.ok(U, &proj, &["ws", "new", "sec", "-r", "v2", "--cloak", "team"]);
    ws_write(env, &proj, "sec", "app.txt", "v1\nv2\nSEALED-LINE-0303\n");
    env.ok(U, &proj, &["describe", "-r", "sec@", "-m", "SEALED-DESC-0404"]);
    proj
}

fn assert_clean(what: &str, bytes: &[u8]) {
    let s = String::from_utf8_lossy(bytes);
    for m in SECRETS {
        assert!(!s.contains(m), "{what} holds {m}:\n{s}");
    }
}

#[test]
fn public_patches_never_carry_sealed_or_isolated_content() {
    let env = Env::new();
    let proj = project(&env);
    let out = env.vl(U, &proj, &["format-patch", "::sec@", "--stdout"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_clean("the mbox", &out.stdout);
    assert_clean("stderr", &out.stderr);
    let mbox = String::from_utf8_lossy(&out.stdout);
    assert!(mbox.contains("Subject: [PATCH 3/3] (description withheld: cloaked)"), "{mbox}");
    assert!(mbox.contains("+v2\n") && mbox.contains("Subject: [PATCH 2/3] v2 with secrets"), "{mbox}");
    // The sealed line's patch shows nothing (the public view did not change).
    assert!(String::from_utf8_lossy(&out.stderr).contains("shows no file change"), "{}", text(&out));
    // Files too, and the cover letter.
    let dir = env.dir("out");
    let out = env.vl(U, &proj, &["format-patch", "::sec@", "-o", dir.to_str().unwrap(), "--cover-letter"]);
    assert!(out.status.success(), "{}", text(&out));
    let mut names: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    assert_eq!(
        names,
        ["0000-cover-letter.patch", "0001-initial.patch", "0002-v2-with-secrets.patch", "0003-description-withheld-cloaked.patch"]
    );
    for n in &names {
        assert_clean(n, &std::fs::read(dir.join(n)).unwrap());
    }
    let cover = std::fs::read_to_string(dir.join("0000-cover-letter.patch")).unwrap();
    assert!(cover.contains("Subject: [PATCH 0/3] *** SUBJECT HERE ***") && cover.contains("Alice (3):"), "{cover}");
}

#[test]
fn round_trip_into_another_repository_and_into_git_am() {
    let env = Env::new();
    let proj = project(&env);
    let mbox = env.stdout(U, &proj, &["format-patch", "main..v2", "--stdout"]).into_bytes();
    // Bob starts from the same public content as `main`.
    let bob = env.dir("bob");
    env.ok(B, &bob, &["init"]);
    write(&bob, "README", "hello\n");
    write(&bob, "app.txt", "v1\n");
    env.ok(B, &bob, &["commit", "-m", "initial"]);
    let out = vl_stdin(&env, B, &bob, &["am", "-"], &mbox);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("Applied 1 patch(es)"), "{}", text(&out));
    assert_eq!(std::fs::read_to_string(bob.join("app.txt")).unwrap(), "v1\nv2\n");
    assert!(!bob.join("secrets").exists() && !bob.join(".env").exists());
    let show = env.stdout(B, &bob, &["show", "@-"]);
    assert!(show.contains("v2 with secrets") && show.contains("The body of v2."), "{show}");
    // Author spoofing (point 17): the patch's author is a claim, the
    // signature is Bob's.
    assert!(show.contains("Author    : Alice <alice@example.com>"), "{show}");
    assert!(show.contains("signed by Bob <bob@example.com>") && show.contains("author Alice"), "{show}");
    // `vl undo` takes it back.
    env.ok(B, &bob, &["undo"]);
    assert_eq!(std::fs::read_to_string(bob.join("app.txt")).unwrap(), "v1\n");
    assert!(!env.stdout(B, &bob, &["log"]).contains("v2 with secrets"));

    // `git am` takes Veil's output too, from the root.
    let all = env.dir("all");
    let out = env.vl(U, &proj, &["format-patch", "::v2", "-o", all.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out));
    let g = env.dir("g");
    git(&g, &["init", "-q"]);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&all).unwrap().map(|e| e.unwrap().path()).collect();
    files.sort();
    let mut args = vec!["am", "-q"];
    args.extend(files.iter().map(|f| f.to_str().unwrap()));
    git(&g, &args);
    assert_eq!(std::fs::read_to_string(g.join("app.txt")).unwrap(), "v1\nv2\n");
    assert_eq!(git(&g, &["log", "--format=%an <%ae>|%s"]), "Alice <alice@example.com>|v2 with secrets\nAlice <alice@example.com>|initial");
    assert!(!g.join("secrets").exists() && !g.join(".env").exists());
}

/// Points 1 and 5: the public view is the Git export's. `git format-patch`
/// run on the bridge's export gives the same mails (headers, files, `index`
/// blob ids), and `git am` of Veil's patches rebuilds the exported tree.
#[test]
fn public_patches_match_git_format_patch_of_the_git_export() {
    let env = Env::new();
    let proj = project(&env);
    write(&proj, "app.txt", "v1\nv2\nv3\n");
    write(&proj, "tool.sh", "#!/bin/sh\necho hi\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(proj.join("tool.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::remove_file(proj.join("README")).unwrap();
    env.ok(U, &proj, &["commit", "-m", "v3"]);
    env.ok(U, &proj, &["tag", "set", "main", "-r", "@-", "--allow-backwards"]);
    let bare = env.root.join("github.git");
    git(&env.root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    env.ok(U, &proj, &["git", "remote", "add", "origin", bare.to_str().unwrap()]);
    env.ok(U, &proj, &["git", "push"]);
    let clone = env.root.join("clone");
    git(&env.root, &["clone", "-q", bare.to_str().unwrap(), clone.to_str().unwrap()]);
    let gp = env.dir("gp");
    git(&clone, &["format-patch", "-q", "--full-index", "--no-renames", "--root", "main", "-o", gp.to_str().unwrap()]);
    let vp = env.dir("vp");
    env.ok(U, &proj, &["format-patch", "::main", "-o", vp.to_str().unwrap()]);
    let list = |d: &Path| {
        let mut v: Vec<PathBuf> = std::fs::read_dir(d).unwrap().map(|e| e.unwrap().path()).collect();
        v.sort();
        v
    };
    let (gs, vs) = (list(&gp), list(&vp));
    assert_eq!(gs.len(), 3);
    assert_eq!(vs.len(), 3);
    let key_lines = |s: &str| -> Vec<String> {
        s.lines()
            .filter(|l| {
                l.starts_with("From ")
                    || l.starts_with("From: ")
                    || l.starts_with("Date: ")
                    || l.starts_with("Subject: ")
                    || l.starts_with("diff --git ")
                    || l.starts_with("index ")
                    || l.starts_with("new file mode ")
                    || l.starts_with("deleted file mode ")
                    || l.starts_with("old mode ")
                    || l.starts_with("new mode ")
            })
            .map(str::to_string)
            .collect()
    };
    for (g, v) in gs.iter().zip(&vs) {
        let (gt, vt) = (std::fs::read_to_string(g).unwrap(), std::fs::read_to_string(v).unwrap());
        assert_eq!(key_lines(&gt), key_lines(&vt), "\n--- git:\n{gt}\n--- vl:\n{vt}");
        assert_eq!(g.file_name(), v.file_name());
        assert_clean("vl's patch", vt.as_bytes());
    }
    // An `index` id is the Git blob id of the projected content.
    let v2 = std::fs::read_to_string(&vs[1]).unwrap();
    let blob = git(&clone, &["rev-parse", "main~1:app.txt"]);
    assert!(v2.contains(&format!("..{blob} 100644")), "{v2}");
    // Applied by git, Veil's patches rebuild exactly the exported tree.
    let e = env.dir("e");
    git(&e, &["init", "-q"]);
    let mut args = vec!["am", "-q"];
    args.extend(vs.iter().map(|f| f.to_str().unwrap()));
    git(&e, &args);
    assert_eq!(git(&e, &["rev-parse", "HEAD^{tree}"]), git(&clone, &["rev-parse", "main^{tree}"]));
}

/// Point 2: a range holding the withheld fix of an unreleased embargo is
/// refused before anything is written.
#[test]
fn embargo_withheld_history_is_refused_and_nothing_is_written() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("auth.rs", "fn check() { true }\n")]);
    env.ok(U, &proj, &["ws", "new", "fix", "-r", "main", "--cloak", "team"]);
    ws_write(&env, &proj, "fix", "auth.rs", "fn check() { verify_signature_secretfix() }\n");
    env.ok(U, &proj, &["describe", "-r", "fix@", "-m", "the fix"]);
    env.ok(U, &proj, &["merge", "fix@", "--into", "main", "--embargo", "-m", "Fix CVE"]);
    let id = env.stdout(U, &proj, &["embargo", "list"]).split_whitespace().next().unwrap().to_string();
    let out_dir = env.dir("out");
    for args in [
        vec!["format-patch", "::fix@", "-o", out_dir.to_str().unwrap()],
        vec!["format-patch", "fix@", "--stdout"],
        vec!["format-patch", "::fix@", "--audience", "me", "--stdout", "--yes"],
    ] {
        let out = env.vl(U, &proj, &args);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", text(&out));
        let t = text(&out);
        assert!(t.contains(&format!("withheld history of unreleased embargo {id}")), "{t}");
        assert!(!t.contains("secretfix"), "{t}");
        assert!(out.stdout.is_empty());
    }
    assert_eq!(std::fs::read_dir(&out_dir).unwrap().count(), 0, "a partial series was left behind");
    // Its author may export it for themself, naming the embargo.
    let out = env.vl(U, &proj, &["format-patch", "fix@", "--audience", "me", "--include-embargoed", &id, "--stdout", "--yes"]);
    assert!(out.status.success(), "{}", text(&out));
    let mbox = String::from_utf8_lossy(&out.stdout);
    assert!(mbox.contains("verify_signature_secretfix") && mbox.contains("X-Veil-Audience: team"), "{mbox}");
}

/// Point 3: `--audience me` is never the default, cannot be abbreviated,
/// and needs `--yes` to go anywhere but a terminal.
#[test]
fn audience_me_needs_yes_on_a_pipe_and_says_what_it_includes() {
    let env = Env::new();
    let proj = project(&env);
    let out = env.vl(U, &proj, &["format-patch", "v2", "--audience", "me", "--stdout"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(out.stdout.is_empty());
    assert!(text(&out).contains("add --yes"), "{}", text(&out));
    let out = env.vl(U, &proj, &["format-patch", "v2", "--aud", "me", "--stdout"]);
    assert_eq!(out.status.code(), Some(2), "an abbreviated --audience must not be accepted");
    let out = env.vl(U, &proj, &["format-patch", "v2", "--audience", "me", "--stdout", "--yes"]);
    assert!(out.status.success(), "{}", text(&out));
    let mbox = String::from_utf8_lossy(&out.stdout);
    assert!(mbox.contains("SEALED-TOKEN-0101") && mbox.contains("X-Veil-Audience: team"), "{mbox}");
    assert!(!mbox.contains("ISOLATED-VALUE-0202"), "isolated content is never in the graph: {mbox}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("scope 'team'"), "{}", text(&out));
    // The sealed description, for `me`.
    let out = env.vl(U, &proj, &["format-patch", "sec@", "--audience", "me", "--stdout", "--yes"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("SEALED-DESC-0404"), "{}", text(&out));
    let out = env.vl(U, &proj, &["format-patch", "v2", "--include-embargoed", "e1", "--stdout"]);
    assert_eq!(out.status.code(), Some(1));
}

/// Point 4: moving a cloaked file to a public path never shows its
/// cloaked name in a public patch.
#[test]
fn a_moved_cloaked_file_never_shows_its_cloaked_name() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("README", "hello\n")]);
    env.ok(U, &proj, &["cloak", "secrets/"]);
    write(&proj, "secrets/payroll-2026.txt", "salaries\nmore\nlines\n");
    env.ok(U, &proj, &["commit", "-m", "payroll"]);
    std::fs::create_dir_all(proj.join("public")).unwrap();
    std::fs::rename(proj.join("secrets/payroll-2026.txt"), proj.join("public/payroll.txt")).unwrap();
    env.ok(U, &proj, &["commit", "-m", "move"]);
    let out = env.vl(U, &proj, &["format-patch", "@-", "--stdout", "-M"]);
    assert!(out.status.success(), "{}", text(&out));
    let mbox = String::from_utf8_lossy(&out.stdout);
    assert!(!mbox.contains("rename") && !mbox.contains("payroll-2026") && !mbox.contains("secrets/"), "{mbox}");
    assert!(text(&out).contains("rename detection is not available yet"), "{}", text(&out));
}

/// Point 6: a conflict with a sealed side shows only the public side.
#[test]
fn a_conflict_with_a_sealed_side_shows_no_sealed_text() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "one\ntwo\nthree\n")]);
    env.ok(U, &proj, &["ws", "new", "sec", "-r", "main", "--cloak", "team"]);
    ws_write(&env, &proj, "sec", "a.txt", "one\nSEALED-SIDE-0042\nthree\n");
    write(&proj, "a.txt", "one\nPUBLIC\nthree\n");
    env.ok(U, &proj, &["commit", "--no-advance", "-m", "public"]);
    env.ok(U, &proj, &["rebase", "-s", "sec@", "-d", "@-"]);
    let ls = env.stdout(U, &proj, &["resolve", "--list", "-r", "sec@"]);
    assert!(ls.contains("a.txt"), "no conflict was made: {ls}");
    for audience in [&["--stdout"][..], &["--stdout", "--audience", "public"][..]] {
        let mut args = vec!["format-patch", "::sec@"];
        args.extend_from_slice(audience);
        let out = env.vl(U, &proj, &args);
        assert!(out.status.success(), "{}", text(&out));
        assert!(!String::from_utf8_lossy(&out.stdout).contains("SEALED-SIDE-0042"), "{}", String::from_utf8_lossy(&out.stdout));
    }
}

// ---- import ----------------------------------------------------------------

fn mail(subject: &str, diff: &str) -> String {
    format!(
        "From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\n\
         From: Mallory <mallory@example.com>\nDate: Wed, 4 Nov 2026 10:00:00 +0000\nSubject: [PATCH] {subject}\n\n---\n{diff}-- \n2.43.0\n\n"
    )
}

/// `vl am` of `mbox` fails (exit 1), records nothing, and prints no raw
/// control character.
fn refused(env: &Env, proj: &Path, mbox: &str, what: &str) -> String {
    let before = head_op(env, proj);
    let out = vl_stdin(env, U, proj, &["am", "-"], mbox.as_bytes());
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains(what), "expected '{what}' in: {t}");
    assert!(!t.contains('\u{1b}') && !t.contains("panicked"), "{t:?}");
    assert_eq!(head_op(env, proj), before, "an operation was recorded: {t}");
    t
}

/// Points 7, 8, 13, 14, 16: hostile patches through the CLI.
#[test]
fn hostile_patches_are_refused_and_nothing_is_written_outside() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "one\ntwo\nthree\n")]);
    let new_file = |path: &str| format!("diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+pwned\n");
    for (path, why) in [
        ("../../evil.txt", "'..'"),
        ("x/../../../evil.txt", "'..'"),
        (".veil/repo.json", "Veil's own metadata"),
        (".git/hooks/pre-commit", ".git metadata"),
        (".GIT/config", ".git metadata"),
    ] {
        refused(&env, &proj, &mail("p", &new_file(path)), why);
    }
    refused(&env, &proj, &mail("p", "diff --git \"a//etc/evil\" \"b//etc/evil\"\nnew file mode 100644\n"), "absolute");
    assert!(!env.root.join("evil.txt").exists() && !proj.join(".git").exists());
    // Header injection (point 13).
    let esc = mail("x", &new_file("ok.txt")).replace("Subject: [PATCH] x", "Subject: =?UTF-8?B?G10yOzE=?=");
    refused(&env, &proj, &esc, "control character");
    // Symlink, then write through it (point 8).
    let link = format!(
        "{}{}",
        mail("link", "diff --git a/link b/link\nnew file mode 120000\nindex 0000000..1111111\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+../../home-u/.ssh\n\\ No newline at end of file\n"),
        mail("write", &new_file("link/authorized_keys")),
    );
    refused(&env, &proj, &link, "symlinks (mode 120000) cannot be applied yet");
    assert!(!proj.join("link").exists() && !env.root.join("home-u").exists());
    // Mode tricks (point 14).
    refused(&env, &proj, &mail("sub", "diff --git a/sub b/sub\nnew file mode 160000\n"), "submodules");
    refused(&env, &proj, &mail("m", "diff --git a/nope b/nope\nold mode 100644\nnew mode 100755\n"), "nope does not exist");
    refused(&env, &proj, &mail("pol", "diff --git a/.veilpolicy b/.veilpolicy\nold mode 100644\nnew mode 120000\n"), "symlinks");
    // CRLF context against LF content (point 16).
    let crlf = mail("crlf", "diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ -1,3 +1,3 @@\n one\r\n-two\r\n+TWO\r\n three\r\n");
    refused(&env, &proj, &crlf, "does not apply");
    // A decompression bomb (point 12) is refused at once.
    let mut bomb = mail("bomb", "diff --git a/x.bin b/x.bin\nGIT binary patch\nliteral 17179869184\n");
    bomb.insert_str(bomb.len() - 12, &"zcmV?d00001zcmV?d00001zcmV?d00001\n".repeat(300));
    let t = std::time::Instant::now();
    refused(&env, &proj, &bomb, "declares 17179869184 bytes");
    assert!(t.elapsed() < std::time::Duration::from_secs(5), "{:?}", t.elapsed());
    // Plain binary sections are refused, naming the file.
    refused(&env, &proj, &mail("bin", "diff --git a/x.bin b/x.bin\nnew file mode 100644\nBinary files /dev/null and b/x.bin differ\n"), "x.bin: binary patches cannot be applied yet");
    assert_eq!(std::fs::read_to_string(proj.join("a.txt")).unwrap(), "one\ntwo\nthree\n");
}

/// Points 9 and 10 through the CLI: a policy weakening waits as `P`, a
/// public Git push carries none of the cloaked content, and a patch with a
/// secret is refused naming the patch and the rule.
#[test]
fn policy_weakening_waits_and_secrets_are_refused() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "one\n")]);
    env.ok(U, &proj, &["cloak", "secrets/"]);
    write(&proj, "secrets/old.txt", "SEALED-OLD-0505\n");
    env.ok(U, &proj, &["commit", "-m", "secrets"]);
    let policy = std::fs::read_to_string(proj.join(".veilpolicy")).unwrap();
    let n = policy.lines().count();
    let rule = policy.lines().last().unwrap().to_string();
    assert!(rule.starts_with("secrets/"), "{rule}");
    let weaken = mail(
        "open up",
        &format!(
            "diff --git a/.veilpolicy b/.veilpolicy\n--- a/.veilpolicy\n+++ b/.veilpolicy\n@@ -{n} +{n} @@\n-{rule}\n+secrets/ public!\n\
             diff --git a/secrets/new.txt b/secrets/new.txt\nnew file mode 100644\n--- /dev/null\n+++ b/secrets/new.txt\n@@ -0,0 +1 @@\n+SEALED-NEW-0606\n"
        ),
    );
    let out = vl_stdin(&env, U, &proj, &["am", "-"], weaken.as_bytes());
    assert!(out.status.success(), "{}", text(&out));
    let status = env.stdout(U, &proj, &["status"]);
    assert!(status.contains("P secrets/new.txt") && status.contains("P secrets/old.txt"), "{status}");
    env.ok(U, &proj, &["tag", "set", "main", "-r", "@-", "--allow-backwards"]);
    let bare = env.root.join("pub.git");
    git(&env.root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    env.ok(U, &proj, &["git", "remote", "add", "origin", bare.to_str().unwrap()]);
    env.ok(U, &proj, &["git", "push"]);
    let objects = git_out(&bare, &["cat-file", "--batch-all-objects", "--batch"]).stdout;
    let objects = String::from_utf8_lossy(&objects);
    assert!(objects.contains("secrets/ public!"), "the policy edit itself is public");
    assert!(!objects.contains("SEALED-NEW-0606") && !objects.contains("SEALED-OLD-0505"));
    // A secret (point 10).
    let creds = mail("creds", "diff --git a/config.yml b/config.yml\nnew file mode 100644\n--- /dev/null\n+++ b/config.yml\n@@ -0,0 +1 @@\n+aws_key: AKIAIOSFODNN7EXAMPLE\n");
    let t = refused(&env, &proj, &creds, "patch 1/1 (creds): config.yml quarantined (aws");
    assert!(!t.contains("AKIAIOSFODNN7EXAMPLE"), "{t}");
    assert!(!proj.join("config.yml").exists());
}

#[test]
fn input_from_a_file_a_directory_and_a_plain_diff_on_stdin() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "one\ntwo\nthree\n")]);
    let dir = env.dir("series");
    write(&dir, "0001-x.patch", &mail("first", "diff --git a/b.txt b/b.txt\nnew file mode 100644\n--- /dev/null\n+++ b/b.txt\n@@ -0,0 +1 @@\n+b\n"));
    write(&dir, "0002-y.patch", &mail("second", "diff --git a/b.txt b/b.txt\n--- a/b.txt\n+++ b/b.txt\n@@ -1 +1 @@\n-b\n+B\n"));
    write(&dir, ".hidden", "not a patch");
    let out = env.vl(U, &proj, &["am", dir.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(std::fs::read_to_string(proj.join("b.txt")).unwrap(), "B\n");
    let log = env.stdout(U, &proj, &["log"]);
    assert!(log.find("second").unwrap() < log.find("first").unwrap(), "{log}");
    let file = dir.join("0001-x.patch");
    env.ok(U, &proj, &["undo"]);
    env.ok(U, &proj, &["am", file.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(proj.join("b.txt")).unwrap(), "b\n");
    // A plain diff, as `diff -u` writes it.
    let plain = "--- a/a.txt\t2026-11-04\n+++ b/a.txt\t2026-11-04\n@@ -1,3 +1,3 @@\n one\n-two\n+2\n three\n";
    let out = vl_stdin(&env, U, &proj, &["am", "-", "--signoff"], plain.as_bytes());
    assert!(out.status.success(), "{}", text(&out));
    let show = env.stdout(U, &proj, &["show", "@-"]);
    assert!(show.contains("Apply a patch from standard input") && show.contains("Signed-off-by: Alice <alice@example.com>"), "{show}");
    assert!(show.contains(&format!("Author    : {U}")), "{show}");
}

/// Point 15: `vl am` racing `vl commit` from another process: no edit is
/// lost, and every applied patch is in the history.
#[test]
fn am_racing_commits_loses_nothing() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    let rounds = 6;
    for i in 0..rounds {
        write(&env.root, &format!("p{i}.patch"), &mail(&format!("patch {i}"), &format!("diff --git a/p{i}.txt b/p{i}.txt\nnew file mode 100644\n--- /dev/null\n+++ b/p{i}.txt\n@@ -0,0 +1 @@\n+P{i}\n")));
    }
    std::thread::scope(|s| {
        let committer = s.spawn(|| {
            for i in 0..rounds {
                write(&proj, &format!("e{i}.txt"), &format!("E{i}\n"));
                let out = env.vl(U, &proj, &["commit", "-m", &format!("edit {i}")]);
                assert!(out.status.success(), "{}", text(&out));
            }
        });
        for i in 0..rounds {
            let patch = env.root.join(format!("p{i}.patch"));
            let out = env.vl(U, &proj, &["am", patch.to_str().unwrap()]);
            assert!(out.status.success(), "{}", text(&out));
        }
        committer.join().unwrap();
    });
    env.ok(U, &proj, &["status"]);
    let files = env.stdout(U, &proj, &["files", "-r", "@"]);
    for i in 0..rounds {
        assert!(files.contains(&format!("e{i}.txt")), "edit {i} lost:\n{files}");
        assert!(files.contains(&format!("p{i}.txt")), "patch {i} lost:\n{files}");
        assert_eq!(std::fs::read_to_string(proj.join(format!("e{i}.txt"))).unwrap(), format!("E{i}\n"));
    }
}

// ---- the confidentiality property ------------------------------------------

#[derive(Clone, Debug)]
enum Op {
    /// Edit the public file (marker `PUBLIC-n`).
    Public(u8),
    /// Write cloaked file `secrets/s{x % 3}.txt` (marker `SEALED-n`).
    Cloaked(u8),
    /// Write the isolated `.env` (marker `ISOLATED-n`).
    Isolated(u8),
    /// The cloaked line `sec` edits the public file and its (sealed)
    /// description (marker `SEALED-n`).
    SealedLine(u8),
    /// Move a cloaked file to a public path: the member declassifies its
    /// current content (path-based policy), so its marker leaves the set.
    MoveOut,
    /// Commit the working copy.
    Commit,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => any::<u8>().prop_map(Op::Public),
        3 => any::<u8>().prop_map(Op::Cloaked),
        1 => any::<u8>().prop_map(Op::Isolated),
        2 => any::<u8>().prop_map(Op::SealedLine),
        1 => Just(Op::MoveOut),
        3 => Just(Op::Commit),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 6, ..ProptestConfig::default() })]

    /// After any sequence of edits to public, cloaked, isolated and
    /// cloaked-line content, the public patches of the whole history (their
    /// stderr included), and a Veil repository that `vl am`s them (its
    /// output, log JSON and files), hold no sealed or isolated marker.
    #[test]
    fn public_patches_hold_no_sealed_marker(ops in proptest::collection::vec(op(), 1..10)) {
        let env = Env::new();
        let proj = env.project(U, "proj", &[("pub.txt", "start\n")]);
        env.ok(U, &proj, &["cloak", "secrets/"]);
        env.ok(U, &proj, &["ws", "new", "sec", "-r", "main", "--cloak", "team"]);
        let mut sealed: Vec<String> = Vec::new();
        let mut current: [Option<String>; 3] = Default::default();
        for (n, o) in ops.iter().enumerate() {
            match o {
                Op::Public(x) => write(&proj, "pub.txt", &format!("PUBLIC-{n}-{x}\n")),
                Op::Cloaked(x) => {
                    let m = format!("SEALED-{n}-{x}");
                    let i = (x % 3) as usize;
                    write(&proj, &format!("secrets/s{i}.txt"), &format!("{m}\n"));
                    sealed.push(m.clone());
                    current[i] = Some(m);
                }
                Op::Isolated(x) => {
                    let m = format!("ISOLATED-{n}-{x}");
                    write(&proj, ".env", &format!("K={m}\n"));
                    sealed.push(m);
                }
                Op::SealedLine(x) => {
                    let m = format!("SEALED-{n}-{x}");
                    ws_write(&env, &proj, "sec", "pub.txt", &format!("{m}\n"));
                    env.ok(U, &proj, &["describe", "-r", "sec@", "-m", &format!("DESC-{m}")]);
                    sealed.push(m);
                }
                Op::MoveOut => {
                    if let Some(i) = (0..3).find(|i| current[*i].is_some()) {
                        std::fs::create_dir_all(proj.join("moved")).unwrap();
                        std::fs::rename(proj.join(format!("secrets/s{i}.txt")), proj.join(format!("moved/m{n}.txt"))).unwrap();
                        let m = current[i].take().unwrap();
                        sealed.retain(|s| *s != m);
                    }
                }
                Op::Commit => {
                    env.ok(U, &proj, &["commit", "-m", &format!("commit {n}")]);
                }
            }
        }
        env.ok(U, &proj, &["commit", "-m", "last"]);
        for (k, range) in ["::@-", "::sec@"].into_iter().enumerate() {
            let out = env.vl(U, &proj, &["format-patch", range, "--stdout"]);
            prop_assert!(out.status.success(), "{}", text(&out));
            let all = text(&out);
            for m in &sealed {
                prop_assert!(!all.contains(m.as_str()), "{} holds {}:\n{}", range, m, all);
            }
            // Into a fresh repository, through `vl am`.
            let bob = env.dir(&format!("bob{k}"));
            env.ok(B, &bob, &["init"]);
            std::fs::remove_file(bob.join(".veilpolicy")).unwrap();
            env.ok(B, &bob, &["commit", "-m", "empty"]);
            env.ok(B, &bob, &["policy", "accept"]);
            let am = vl_stdin(&env, B, &bob, &["am", "-"], &out.stdout);
            prop_assert!(am.status.success(), "{}", text(&am));
            let log = env.vl(B, &bob, &["log", "--json"]);
            let mut seen = format!("{}{}", text(&am), text(&log));
            for f in adversarial_support::tree_listing(&bob).iter().filter(|f| !f.starts_with(".veil")) {
                if bob.join(f).is_file() {
                    seen.push_str(&String::from_utf8_lossy(&std::fs::read(bob.join(f)).unwrap()));
                }
            }
            for m in &sealed {
                prop_assert!(!seen.contains(m.as_str()), "Bob's repository holds {}:\n{}", m, seen);
            }
        }
    }
}

/// BUG-640: `vl git export` in a repository that has never talked to Git
/// fails, because the bridge creates its bare repository but not the
/// `.veil/git/` directory around it (`git/mod.rs`, `open_git`). `vl
/// format-patch` creates the directory itself.
#[test]
#[ignore = "BUG-640: vl git export fails before .veil/git exists"]
fn bug_640_git_export_in_a_fresh_repository() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    env.ok(U, &proj, &["git", "export"]);
}

/// `VEIL_MAX_OBJECT` bounds what a patch may write (and what a binary
/// section may declare), like every other object.
#[test]
fn veil_max_object_bounds_what_a_patch_writes() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    let lines: String = (0..64).map(|i| format!("+line {i:04} of a file larger than one kibibyte\n")).collect();
    let big = mail("big", &format!("diff --git a/big.txt b/big.txt\nnew file mode 100644\n--- /dev/null\n+++ b/big.txt\n@@ -0,0 +1,64 @@\n{lines}"));
    let mut c = env.cmd(U, &proj, &["am", "-"]);
    c.env("VEIL_MAX_OBJECT", "1K").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    child.stdin.take().unwrap().write_all(big.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("VEIL_MAX_OBJECT"), "{}", text(&out));
    assert!(!proj.join("big.txt").exists());
    // Without the limit, the same patch applies.
    let out = vl_stdin(&env, U, &proj, &["am", "-"], big.as_bytes());
    assert!(out.status.success(), "{}", text(&out));
}

/// A `vl am` killed part way through a long series leaves either nothing
/// or the whole series (one transaction), and a sound repository.
#[test]
fn a_killed_am_leaves_all_or_nothing() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    let n = 400;
    let series: String = (0..n)
        .map(|i| mail(&format!("k{i}"), &format!("diff --git a/k{i}.txt b/k{i}.txt\nnew file mode 100644\n--- /dev/null\n+++ b/k{i}.txt\n@@ -0,0 +1 @@\n+K{i}\n")))
        .collect();
    let file = env.root.join("series.mbox");
    std::fs::write(&file, series).unwrap();
    for delay in [50u64, 200, 600] {
        let mut child = env.spawn(U, &proj, &["am", file.to_str().unwrap()]);
        std::thread::sleep(std::time::Duration::from_millis(delay));
        let _ = child.kill();
        let _ = child.wait();
        let log = env.stdout(U, &proj, &["log", "-n", "1000"]);
        let applied = (0..n).filter(|i| log.contains(&format!("k{i}\n"))).count();
        assert!(applied == 0 || applied == n, "a killed `vl am` left {applied} of {n} patches");
        let fsck = env.vl(U, &proj, &["fsck"]);
        assert!(fsck.status.success(), "{}", text(&fsck));
        if applied == n {
            env.ok(U, &proj, &["undo"]);
        }
    }
}
