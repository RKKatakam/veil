//! `vl format-patch` and `vl am`, phase 2, through the real binary: rename
//! and copy detection (`-M`, `-C`), symlinks, submodules, type changes and
//! `GIT binary patch` data, differential against Git in both directions
//! (`vl format-patch` → `git am`, `git format-patch` → `vl am`);
//! confidentiality of rename pairs and binary content; the hostile
//! link-then-write series on a real disk; `--3way`.

mod adversarial_support;

use std::{
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use adversarial_support::{text, write, Env};

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
        .args(["-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", "-c", "core.symlinks=true"])
        .args(args)
        .output()
        .unwrap()
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = git_out(dir, args);
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn vl_stdin(env: &Env, user: &str, cwd: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut c = env.cmd(user, cwd, args);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn head_op(env: &Env, proj: &Path) -> String {
    let log: serde_json::Value = serde_json::from_str(&env.stdout(U, proj, &["op", "log", "-n", "1", "--json"])).unwrap();
    log["operations"][0]["op_id"].as_str().unwrap().to_string()
}

fn mail(subject: &str, diff: &str) -> String {
    format!(
        "From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\nFrom: Mallory <m@example.com>\n\
         Date: Wed, 4 Nov 2026 10:00:00 +0000\nSubject: [PATCH] {subject}\n\n---\n{diff}-- \n2.43.0\n\n"
    )
}

fn list(d: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(d).unwrap().map(|e| e.unwrap().path()).collect();
    v.sort();
    v
}

fn noise(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

fn symlink(target: &str, at: &Path) {
    std::os::unix::fs::symlink(target, at).unwrap();
}

const PIN: &str = "1234567890123456789012345678901234567890";
const LONG: &str = "line01\nline02\nline03\nline04\nline05\nline06\nline07\nline08\nline09\nline10\n";

/// Alice's history, one commit per shape phase 2 adds:
/// 1. text, an executable, a symlink, a binary file;
/// 2. an inexact rename into a directory, a copy of a changed file, an
///    exact symlink rename, a binary delta, a symlink turned into a file;
/// 3. a submodule pin (added by `vl am`, the only way a pin enters here
///    without a clone), a file turned into a symlink, a binary deletion.
fn history(env: &Env) -> PathBuf {
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, "a.txt", LONG);
    write(&proj, "b.txt", "shared\ncontent\nhere\nfor\ncopies\n");
    write(&proj, "tool.sh", "#!/bin/sh\necho hi\n");
    std::fs::set_permissions(proj.join("tool.sh"), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    symlink("a.txt", &proj.join("lnk"));
    symlink("b.txt", &proj.join("t"));
    std::fs::write(proj.join("img.bin"), noise(6000, 7)).unwrap();
    env.ok(U, &proj, &["commit", "-m", "initial"]);

    std::fs::create_dir_all(proj.join("docs")).unwrap();
    std::fs::remove_file(proj.join("a.txt")).unwrap();
    write(&proj, "docs/a.txt", &LONG.replace("line10", "LINE10"));
    write(&proj, "b2.txt", "shared\ncontent\nhere\nfor\ncopies\n");
    write(&proj, "b.txt", "shared\ncontent\nhere\nfor\ncopies\nand more\n");
    std::fs::rename(proj.join("lnk"), proj.join("lnk2")).unwrap();
    let mut img = noise(6000, 7);
    img[10] ^= 0x55;
    img.extend_from_slice(b"\x00appended");
    std::fs::write(proj.join("img.bin"), img).unwrap();
    std::fs::remove_file(proj.join("t")).unwrap();
    write(&proj, "t", "a file now\n");
    env.ok(U, &proj, &["commit", "-m", "renames and copies"]);

    let sub = mail(
        "pin",
        &format!("diff --git a/vendor/lib b/vendor/lib\nnew file mode 160000\nindex 0000000..1234567\n--- /dev/null\n+++ b/vendor/lib\n@@ -0,0 +1 @@\n+Subproject commit {PIN}\n"),
    );
    let out = vl_stdin(env, U, &proj, &["am", "-"], sub.as_bytes());
    assert!(out.status.success(), "{}", text(&out));
    std::fs::remove_file(proj.join("tool.sh")).unwrap();
    symlink("b.txt", &proj.join("tool.sh"));
    std::fs::remove_file(proj.join("img.bin")).unwrap();
    env.ok(U, &proj, &["commit", "-m", "type changes"]);
    env.ok(U, &proj, &["tag", "set", "main", "-r", "@-"]);
    proj
}

/// The lines both writers must agree on: headers, file sections, rename
/// and copy lines, the diffstat and its summary, and text hunks (binary
/// data is compressed differently by each zlib; it is checked by applying).
fn key_lines(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_binary = false;
    for l in s.lines() {
        if l == "GIT binary patch" {
            in_binary = true;
        } else if l.starts_with("diff --git ") || l == "-- " {
            in_binary = false;
        }
        if in_binary && !(l.starts_with("literal ") || l.starts_with("delta ") || l == "GIT binary patch") {
            continue;
        }
        let keep = l.starts_with("From: ")
            || l.starts_with("Subject: ")
            || l.starts_with("diff --git ")
            || l.starts_with("index ")
            || l.starts_with("new file mode ")
            || l.starts_with("deleted file mode ")
            || l.starts_with("old mode ")
            || l.starts_with("new mode ")
            || l.starts_with("similarity index ")
            || l.starts_with("rename ")
            || l.starts_with("copy ")
            || l.starts_with("--- ")
            || l.starts_with("+++ ")
            || l.starts_with("@@ ")
            || l == "GIT binary patch"
            || l.starts_with(' ') && (l.contains(" | ") || l.contains(" changed") || l.contains(" mode ") || l.starts_with(" rename ") || l.starts_with(" copy "))
            || (l.starts_with('+') || l.starts_with('-')) && !l.starts_with("---") && !l.starts_with("+++");
        // Literal sizes match; the choice of a delta and its size depend on
        // the delta encoder.
        if l.starts_with("delta ") {
            out.push("delta".into());
        } else if keep || l.starts_with("literal ") {
            out.push(l.to_string());
        }
    }
    out
}

/// Phase 2 against Git, both ways: `vl format-patch -C --binary` shows
/// what `git format-patch -M -C --binary --full-index` shows of the Git
/// export (the same sections, rename and copy lines, similarity, modes,
/// `index` ids and diffstat); `git am` of Veil's patches rebuilds the
/// exported tree exactly; `vl am` of Git's patches rebuilds it too (its
/// own Git export has the same tree id).
#[test]
fn renames_copies_links_submodules_and_binary_match_git_both_ways() {
    let env = Env::new();
    let proj = history(&env);
    let bare = env.root.join("github.git");
    git(&env.root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    env.ok(U, &proj, &["git", "remote", "add", "origin", bare.to_str().unwrap()]);
    env.ok(U, &proj, &["git", "push"]);
    let clone = env.root.join("clone");
    git(&env.root, &["clone", "-q", "--no-checkout", bare.to_str().unwrap(), clone.to_str().unwrap()]);
    let gp = env.dir("gp");
    git(&clone, &["format-patch", "-q", "-M", "-C", "--binary", "--full-index", "--root", "origin/main", "-o", gp.to_str().unwrap()]);
    let vp = env.dir("vp");
    env.ok(U, &proj, &["format-patch", "::main", "-C", "--binary", "-o", vp.to_str().unwrap()]);
    let (gs, vs) = (list(&gp), list(&vp));
    assert_eq!(gs.len(), 4);
    assert_eq!(vs.len(), 4);
    for (g, v) in gs.iter().zip(&vs) {
        let (gt, vt) = (std::fs::read_to_string(g).unwrap(), std::fs::read_to_string(v).unwrap());
        assert_eq!(key_lines(&gt), key_lines(&vt), "\n--- git:\n{gt}\n--- vl:\n{vt}");
        assert_eq!(g.file_name(), v.file_name());
    }
    let second = std::fs::read_to_string(&vs[1]).unwrap();
    for want in [
        "rename from a.txt\nrename to docs/a.txt\n",
        "copy from b.txt\ncopy to b2.txt\n",
        "rename from lnk\nrename to lnk2\n",
        "GIT binary patch\ndelta ",
        "deleted file mode 120000",
        " {a.txt => docs/a.txt}",
    ] {
        assert!(second.contains(want) || want.starts_with(" {") && second.contains(" a.txt => docs/a.txt"), "{want:?} in:\n{second}");
    }
    let fourth = std::fs::read_to_string(&vs[3]).unwrap();
    assert!(fourth.contains(&format!("+Subproject commit {PIN}\n")) || std::fs::read_to_string(&vs[2]).unwrap().contains(&format!("+Subproject commit {PIN}\n")));

    // Veil → Git: `git am` rebuilds the exported tree.
    let e = env.dir("e");
    git(&e, &["init", "-q"]);
    let mut args = vec!["am", "-q"];
    args.extend(vs.iter().map(|f| f.to_str().unwrap()));
    git(&e, &args);
    assert_eq!(git(&e, &["rev-parse", "HEAD^{tree}"]), git(&clone, &["rev-parse", "origin/main^{tree}"]));
    assert_eq!(std::fs::read_link(e.join("lnk2")).unwrap(), Path::new("a.txt"));
    assert_eq!(git(&e, &["ls-tree", "HEAD", "vendor/lib"]), format!("160000 commit {PIN}\tvendor/lib"));

    // Git → Veil: Bob applies Git's series to an empty history; his own
    // Git export of the result has the very same tree.
    let bob = env.dir("bob");
    env.ok(B, &bob, &["init"]);
    std::fs::remove_file(bob.join(".veilpolicy")).unwrap();
    env.ok(B, &bob, &["commit", "-m", "empty"]);
    env.ok(B, &bob, &["policy", "accept"]);
    let out = env.vl(B, &bob, &["am", gp.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("Applied 4 patch(es)"), "{}", text(&out));
    assert_eq!(std::fs::read_link(bob.join("lnk2")).unwrap(), Path::new("a.txt"));
    assert_eq!(std::fs::read_link(bob.join("tool.sh")).unwrap(), Path::new("b.txt"));
    assert!(!bob.join("img.bin").exists());
    assert!(std::fs::metadata(bob.join("vendor/lib")).unwrap().is_dir(), "a submodule is checked out as an empty directory");
    assert_eq!(std::fs::read_dir(bob.join("vendor/lib")).unwrap().count(), 0, "nothing is fetched");
    env.ok(B, &bob, &["tag", "set", "main", "-r", "@-"]);
    let bare2 = env.root.join("bob.git");
    git(&env.root, &["init", "-q", "--bare", bare2.to_str().unwrap()]);
    env.ok(B, &bob, &["git", "remote", "add", "origin", bare2.to_str().unwrap()]);
    env.ok(B, &bob, &["git", "push"]);
    assert_eq!(git(&bare2, &["rev-parse", "main^{tree}"]), git(&clone, &["rev-parse", "origin/main^{tree}"]));
}

/// Threat review point 4 with `-M` and `-C`, and binary content: rename
/// and copy pairs are found on the public sides only, so a cloaked source
/// never shows as `rename from`/`copy from`, and its content never appears
/// as a binary literal or delta; a public binary file does.
#[test]
fn rename_pairs_and_binary_data_never_carry_sealed_content() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("README", "hello\n")]);
    env.ok(U, &proj, &["cloak", "secrets/"]);
    write(&proj, "secrets/plan-2026.txt", "SEALED-PLAN-1\nline two\nline three\nline four\n");
    let mut sealed_bin = b"SEALED-BIN-2\x00".to_vec();
    sealed_bin.extend(noise(2000, 3));
    std::fs::write(proj.join("secrets/blob.bin"), &sealed_bin).unwrap();
    write(&proj, "secrets/notes.txt", "SEALED-NOTES-3\nshared line\nshared line 2\n");
    env.ok(U, &proj, &["commit", "-m", "secrets"]);
    // A cloaked file replaced by a similar public one (an exact move stays
    // sealed: protection follows content), a copy of a cloaked file to a
    // public one, and a public binary file next to a sealed one.
    std::fs::remove_file(proj.join("secrets/plan-2026.txt")).unwrap();
    write(&proj, "public/plan.txt", "PUBLIC-PLAN\nline two\nline three\nline four\n");
    write(&proj, "public/notes-copy.txt", "public now\nshared line\nshared line 2\n");
    write(&proj, "secrets/notes.txt", "SEALED-NOTES-3\nshared line\nshared line 2\nmore\n");
    let mut sealed_bin2 = sealed_bin.clone();
    sealed_bin2.extend_from_slice(b"SEALED-BIN-TAIL");
    std::fs::write(proj.join("secrets/blob.bin"), &sealed_bin2).unwrap();
    let mut public_bin = vec![0u8];
    public_bin.extend(noise(499, 11));
    std::fs::write(proj.join("public.bin"), public_bin).unwrap();
    env.ok(U, &proj, &["commit", "-m", "move out"]);

    let out = env.vl(U, &proj, &["format-patch", "@-", "--stdout", "-C", "--binary"]);
    assert!(out.status.success(), "{}", text(&out));
    let mbox = String::from_utf8_lossy(&out.stdout);
    for leak in ["rename", "copy from", "plan-2026", "secrets/", "SEALED-", "blob.bin", "notes.txt\n"] {
        assert!(!mbox.contains(leak), "{leak} in:\n{mbox}");
    }
    assert!(mbox.contains("new file mode 100644\nindex 0000000000000000000000000000000000000000.."), "{mbox}");
    assert!(mbox.contains("+++ b/public/plan.txt"), "{mbox}");
    assert!(mbox.contains("diff --git a/public.bin b/public.bin\nnew file mode 100644\n") && mbox.contains("GIT binary patch\nliteral 500\n"), "{mbox}");
    assert!(!String::from_utf8_lossy(&out.stderr).contains("secrets/"), "{}", text(&out));

    // `--audience me`: the pairs this reader sees, but a sealed binary file
    // is never written as binary data.
    let out = env.vl(U, &proj, &["format-patch", "@-", "--stdout", "-C", "--binary", "--audience", "me", "--yes"]);
    assert!(out.status.success(), "{}", text(&out));
    let mbox = String::from_utf8_lossy(&out.stdout);
    assert!(mbox.contains("rename from secrets/plan-2026.txt"), "{mbox}");
    assert!(mbox.contains("Binary files a/secrets/blob.bin and b/secrets/blob.bin differ"), "{mbox}");
    let blob_section = mbox.split("diff --git a/secrets/blob.bin").nth(1).unwrap().split("diff --git").next().unwrap();
    assert!(!blob_section.contains("GIT binary patch") && !blob_section.contains("literal"), "{blob_section}");
    assert!(text(&out).contains("secrets/blob.bin: sealed binary content is never written as a binary patch"), "{}", text(&out));
}

fn refused(env: &Env, proj: &Path, mbox: &str, what: &str) -> String {
    let before = head_op(env, proj);
    let out = vl_stdin(env, U, proj, &["am", "-"], mbox.as_bytes());
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains(what), "expected '{what}' in: {t}");
    assert!(!t.contains("panicked"), "{t:?}");
    assert_eq!(head_op(env, proj), before, "an operation was recorded: {t}");
    t
}

/// Point 8 on a real disk: a series that adds a link to a directory
/// outside the repository and then writes below it is refused as a whole,
/// in every shape; nothing appears outside the repository, and the link
/// is never created. A link alone is recorded as a link (with a warning),
/// and checking it out writes nothing through it.
#[test]
fn a_hostile_link_then_write_series_writes_nothing_outside() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "one\n")]);
    let outside = env.dir("outside");
    let target = outside.to_str().unwrap().to_string();
    let link = format!(
        "diff --git a/link b/link\nnew file mode 120000\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+{target}\n\\ No newline at end of file\n"
    );
    let rel_link = "diff --git a/up b/up\nnew file mode 120000\n--- /dev/null\n+++ b/up\n@@ -0,0 +1 @@\n+../outside\n\\ No newline at end of file\n";
    let below = |l: &str| format!("diff --git a/{l}/authorized_keys b/{l}/authorized_keys\nnew file mode 100644\n--- /dev/null\n+++ b/{l}/authorized_keys\n@@ -0,0 +1 @@\n+ssh-ed25519 AAAA mallory\n");
    refused(&env, &proj, &format!("{}{}", mail("link", &link), mail("write", &below("link"))), "link is not a directory");
    refused(&env, &proj, &mail("both", &format!("{link}{}", below("link"))), "the same patch makes link a symlink");
    refused(&env, &proj, &mail("both", &format!("{}{link}", below("link"))), "the same patch makes link a symlink");
    refused(&env, &proj, &format!("{}{}", mail("up", rel_link), mail("write", &below("up"))), "up is not a directory");
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    assert!(std::fs::symlink_metadata(proj.join("link")).is_err() && std::fs::symlink_metadata(proj.join("up")).is_err());

    // The links alone: recorded and checked out as links, with warnings.
    let out = vl_stdin(&env, U, &proj, &["am", "-"], format!("{}{}", mail("link", &link), mail("up", rel_link)).as_bytes());
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("symlink link points outside the repository"), "{}", text(&out));
    assert_eq!(std::fs::read_link(proj.join("link")).unwrap(), Path::new(&target));
    // A later write below it, by patch, still fails; by hand it is the
    // user's own business, and a snapshot records the link, not the file.
    refused(&env, &proj, &mail("write", &below("link")), "link is not a directory");
    env.ok(U, &proj, &["new"]);
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
}

/// `vl am --3way`: a hunk whose context moved on merges with the version
/// the patch was made from; a real conflict is recorded in the new change
/// and shown in the working copy, and the command says so.
#[test]
fn three_way_through_the_cli() {
    let env = Env::new();
    let base = "1\n2\n3\n4\n5\n6\n7\n8\n9\n";
    let proj = env.project(U, "proj", &[("f.txt", base)]);
    write(&proj, "f.txt", &base.replace("5\n", "FIVE\n"));
    env.ok(U, &proj, &["commit", "-m", "theirs"]);
    let theirs = env.stdout(U, &proj, &["format-patch", "@-", "--stdout"]);
    env.ok(U, &proj, &["new", "main"]);
    write(&proj, "f.txt", &base.replace("2\n", "TWO\n"));
    env.ok(U, &proj, &["commit", "-m", "context moved"]);
    let out = vl_stdin(&env, U, &proj, &["am", "-"], theirs.as_bytes());
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let out = vl_stdin(&env, U, &proj, &["am", "--3way", "-"], theirs.as_bytes());
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("f.txt merged three ways"), "{}", text(&out));
    assert_eq!(std::fs::read_to_string(proj.join("f.txt")).unwrap(), base.replace("2\n", "TWO\n").replace("5\n", "FIVE\n"));

    write(&proj, "f.txt", &base.replace("2\n", "TWO\n").replace("5\n", "CINQ\n"));
    env.ok(U, &proj, &["commit", "-m", "ours"]);
    let other = theirs.replace("+FIVE", "+FUENF");
    let out = vl_stdin(&env, U, &proj, &["am", "-3", "-"], other.as_bytes());
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("f.txt has a conflict"), "{}", text(&out));
    let f = std::fs::read_to_string(proj.join("f.txt")).unwrap();
    assert!(f.contains("<<<<<<<") && f.contains("CINQ") && f.contains("FUENF"), "{f}");
    assert!(env.stdout(U, &proj, &["status"]).contains("C f.txt"));
}

/// The CLI's own guards: `-M=N` takes a percentage, `--binary` needs no
/// confirmation for the public view.
#[test]
fn flags_are_checked() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    let out = env.vl(U, &proj, &["format-patch", "main", "--stdout", "--find-renames=101"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let out = env.vl(U, &proj, &["format-patch", "main", "--stdout", "-M=90", "-C", "--binary"]);
    assert!(out.status.success(), "{}", text(&out));
}
