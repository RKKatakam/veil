//! Feature 7 through the real `vl` binary: `vl attr check`, `vl
//! renormalize` (explicit, undoable), device-local diff and merge drivers
//! (a teammate's content never defines a command), textconv in `vl diff`
//! but never in `vl format-patch`, and the Git export with `eol=crlf`
//! (threat review of `docs/design/git-parity/7-attributes-line-endings.md`,
//! points 5, 7 and 8; the engine side is in
//! `crates/veil-core/tests/attributes.rs`).

mod adversarial_support;

use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use adversarial_support::*;

const U: &str = "alice";

fn git(dir: &Path, args: &[&str]) -> Vec<u8> {
    let out = Command::new("git")
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
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    out.stdout
}

fn write_bytes(dir: &Path, rel: &str, data: &[u8]) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

fn ws_write(env: &Env, proj: &Path, ws: &str, path: &str, content: &str) {
    let mut c = env.cmd(U, proj, &["ws", "write", ws, path]);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    child.stdin.take().unwrap().write_all(content.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "ws write: {}", text(&out));
}

/// `a.txt` edited on two lines of work that conflict as text: `main`
/// (ours) and workspace `other` (theirs); returns the output of `vl merge`.
fn conflicting_merge(env: &Env, proj: &Path) -> String {
    env.ok(U, proj, &["ws", "new", "other", "-r", "main"]);
    ws_write(env, proj, "other", "a.txt", "one\nTHEIRS\nthree\n");
    write(proj, "a.txt", "one\nOURS\nthree\n");
    env.ok(U, proj, &["commit", "-m", "ours"]);
    env.ok(U, proj, &["merge", "other@", "-m", "merge"])
}

// ---- vl attr check ------------------------------------------------------------------------

#[test]
fn attr_check_shows_attributes_effects_and_what_is_not_supported() {
    let env = Env::new();
    let proj = env.project(
        U,
        "proj",
        &[
            (".gitattributes", "* text=auto\n*.bat eol=crlf\n*.png binary\n*.bin filter=lfs diff=lfs merge=lfs -text\n"),
            ("docs/.gitattributes", "*.md linguist-documentation export-ignore\n"),
            ("README", "hi\n"),
        ],
    );
    let out = env.ok(U, &proj, &["attr", "check", "run.bat", "i.png", "big.bin", "docs/x.md"]);
    assert!(out.contains("run.bat: eol: crlf"), "{out}");
    assert!(out.contains("line endings: auto-crlf"), "{out}");
    assert!(out.contains("i.png: binary: set") && out.contains("i.png: diff: unset"), "{out}");
    assert!(out.contains("merge: binary"), "{out}");
    assert!(out.contains("big.bin: filter: lfs") && out.contains("not supported by Veil"), "{out}");
    assert!(out.contains("`filter` is not supported by Veil"), "the filter warning: {out}");
    assert!(out.contains("docs/x.md: linguist-documentation: set"), "{out}");
    let doc: serde_json::Value = serde_json::from_str(&env.stdout(U, &proj, &["attr", "check", "big.bin", "run.bat", "--json"])).unwrap();
    assert_eq!(doc["schema"], "veil.attr-check/1");
    let big = &doc["paths"][0];
    assert_eq!(big["path"], "big.bin");
    assert_eq!(big["line_endings"], "none");
    assert!(big["diff"].as_str().unwrap().contains("not defined on this device"), "{big}");
    let unsupported: Vec<&str> = big["unsupported"].as_array().unwrap().iter().map(|u| u["name"].as_str().unwrap()).collect();
    assert_eq!(unsupported, vec!["filter"]);
    assert_eq!(doc["paths"][1]["line_endings"], "auto-crlf");
    // Hostile path arguments are refused, never read outside.
    let out = env.vl(U, &proj, &["attr", "check", "../../etc/passwd"]);
    assert!(!out.status.success() && text(&out).contains("escapes"), "{}", text(&out));
}

// ---- vl renormalize -----------------------------------------------------------------------

#[test]
fn renormalize_is_explicit_and_undone_by_undo() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write_bytes(&proj, "a.txt", b"one\r\ntwo\r\n");
    write_bytes(&proj, "b.txt", b"x\r\n");
    write_bytes(&proj, "mixed.txt", b"x\r\ny\n");
    env.ok(U, &proj, &["commit", "-m", "crlf"]);
    // The attributes change: nothing is re-recorded, status says so.
    write(&proj, ".gitattributes", "*.txt text\n");
    let st = env.stdout(U, &proj, &["status"]);
    assert!(st.contains("2 file(s) would change line endings") && st.contains("vl renormalize"), "{st}");
    let js: serde_json::Value = serde_json::from_str(&env.stdout(U, &proj, &["status", "--json"])).unwrap();
    assert_eq!(js["renormalizable"], serde_json::json!(["a.txt", "b.txt"]));
    let changes: Vec<&str> = js["changes"].as_array().unwrap().iter().map(|c| c["path"].as_str().unwrap()).collect();
    assert_eq!(changes, vec![".gitattributes"], "only the attributes file changed");
    // Renormalize one path, then the rest.
    let out = env.ok(U, &proj, &["renormalize", "a.txt"]);
    assert!(out.contains("Renormalized a.txt") && !out.contains("b.txt"), "{out}");
    assert_eq!(env.stdout(U, &proj, &["cat", "a.txt"]), "one\ntwo\n");
    assert_eq!(std::fs::read(proj.join("a.txt")).unwrap(), b"one\r\ntwo\r\n", "the working copy is not rewritten");
    let out = env.ok(U, &proj, &["renormalize"]);
    assert!(out.contains("Renormalized b.txt") && out.contains("mixed.txt: its line endings are mixed"), "{out}");
    assert_eq!(env.stdout(U, &proj, &["cat", "mixed.txt"]), "x\r\ny\n", "a lossy conversion never happens");
    let out = env.ok(U, &proj, &["renormalize"]);
    assert!(out.contains("Nothing to renormalize"), "{out}");
    // `vl undo` reverts it (one operation per renormalize).
    env.ok(U, &proj, &["undo"]);
    env.ok(U, &proj, &["undo"]);
    assert_eq!(env.stdout(U, &proj, &["cat", "a.txt"]), "one\r\ntwo\r\n");
    assert_eq!(env.stdout(U, &proj, &["cat", "b.txt"]), "x\r\n");
    assert_eq!(std::fs::read(proj.join("a.txt")).unwrap(), b"one\r\ntwo\r\n");
    let st = env.stdout(U, &proj, &["status"]);
    assert!(st.contains("2 file(s) would change line endings"), "{st}");
}

#[test]
fn a_lossy_conversion_warns_and_records_the_bytes() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[(".gitattributes", "* text\n")]);
    write_bytes(&proj, "m.txt", b"a\r\nb\nc\r\n");
    let out = env.ok(U, &proj, &["status"]);
    assert!(out.contains("m.txt: its line endings are mixed (CRLF and LF); recorded unchanged"), "{out}");
    assert_eq!(env.stdout(U, &proj, &["cat", "m.txt"]).as_bytes(), b"a\r\nb\nc\r\n");
    write_bytes(&proj, "n.txt", b"a\r\nb\r\n");
    env.ok(U, &proj, &["status"]);
    assert_eq!(env.stdout(U, &proj, &["cat", "n.txt"]), "a\nb\n");
}

// ---- drivers: a teammate's content never defines a command --------------------------------

#[test]
fn a_teammates_attributes_and_config_never_run_a_command() {
    let env = Env::new();
    let marker = env.root.join("PWNED");
    let m = marker.to_str().unwrap();
    let cfg = format!("[merge.pwn]\ncommand = [\"/bin/sh\", \"-c\", \"touch {m}\"]\n[diff.pwn]\ntextconv = [\"/bin/sh\", \"-c\", \"touch {m}\"]\n");
    let proj = env.project(
        U,
        "proj",
        &[
            (".gitattributes", "* merge=pwn diff=pwn\n"),
            ("config.toml", &cfg),
            (".veil.toml", &cfg),
            ("veil/local/config.toml", &cfg),
            ("a.txt", "one\ntwo\nthree\n"),
        ],
    );
    let out = conflicting_merge(&env, &proj);
    assert!(out.contains("conflicts in: a.txt"), "the built-in text merge ran: {out}");
    assert!(out.contains("merge driver 'pwn', which this device does not define"), "{out}");
    let diff = env.ok(U, &proj, &["diff", "--from", "root()", "--to", "other@"]);
    assert!(diff.contains("diff driver 'pwn', which this device does not define"), "{diff}");
    assert!(!marker.exists(), "a command named by the repository ran");
}

#[test]
fn a_device_local_merge_driver_runs_confined() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[(".gitattributes", "a.txt merge=both\n"), ("a.txt", "one\ntwo\nthree\n")]);
    write(
        &proj,
        ".veil/local/config.toml",
        "[merge.both]\ncommand = [\"/bin/sh\", \"-c\", \"cat \\\"$1\\\" >> \\\"$2\\\" && test -z \\\"$VEIL_SECRET_ENV\\\"\", \"sh\", \"%B\", \"%A\"]\n",
    );
    let mut c = env.cmd(U, &proj, &["status"]);
    c.env("VEIL_SECRET_ENV", "leak");
    assert!(c.output().unwrap().status.success());
    let out = conflicting_merge(&env, &proj);
    assert!(!out.contains("conflicts in"), "the driver merged it: {out}");
    let merged = env.stdout(U, &proj, &["cat", "a.txt", "-r", "@-"]);
    assert_eq!(merged, "one\nOURS\nthree\none\nTHEIRS\nthree\n");
    let tmp = proj.join(".veil/local/tmp");
    assert!(std::fs::read_dir(&tmp).map_or(true, |mut d| d.next().is_none()), "the driver's files are removed");
}

#[test]
fn a_driver_program_inside_the_project_never_runs() {
    let env = Env::new();
    let marker = env.root.join("RAN");
    let proj = env.project(U, "proj", &[(".gitattributes", "a.txt merge=mine\n"), ("a.txt", "one\ntwo\nthree\n")]);
    let script = proj.join("tools/merge.sh");
    write(&proj, "tools/merge.sh", &format!("#!/bin/sh\ntouch {}\n", marker.display()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    write(&proj, ".veil/local/config.toml", &format!("[merge.mine]\ncommand = [\"{}\", \"%O\", \"%A\", \"%B\"]\n", script.display()));
    let out = conflicting_merge(&env, &proj);
    assert!(out.contains("inside the project") && out.contains("conflicts in: a.txt"), "{out}");
    assert!(!marker.exists());
}

// ---- textconv: in `vl diff`, never in `vl format-patch` -----------------------------------

#[test]
fn textconv_shapes_vl_diff_but_never_a_patch() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[(".gitattributes", "*.txt diff=up\nblob.dat -diff\n"), ("a.txt", "hello\n"), ("blob.dat", "v1\n")]);
    write(&proj, ".veil/local/config.toml", "[diff.up]\ntextconv = [\"tr\", \"a-z\", \"A-Z\"]\n");
    write(&proj, "a.txt", "hello\nworld\n");
    write(&proj, "blob.dat", "v2\n");
    env.ok(U, &proj, &["commit", "-m", "two"]);
    env.ok(U, &proj, &["tag", "set", "main", "-r", "@-"]);
    let diff = env.stdout(U, &proj, &["diff", "-r", "@-"]);
    assert!(diff.contains("+WORLD"), "the textconv's output is diffed: {diff}");
    assert!(diff.contains("binary content differs"), "-diff shows binary: {diff}");
    let json: serde_json::Value = serde_json::from_str(&env.stdout(U, &proj, &["diff", "-r", "@-", "--json"])).unwrap();
    let blob = json["files"].as_array().unwrap().iter().find(|f| f["path"] == "blob.dat").unwrap();
    assert_eq!(blob["content"]["binary"], true);
    let patch = env.stdout(U, &proj, &["format-patch", "@-", "--stdout"]);
    assert!(patch.contains("+world") && !patch.contains("WORLD"), "never a textconv: {patch}");
    assert!(patch.contains("Binary files a/blob.dat and b/blob.dat differ"), "{patch}");
    // The same as `git format-patch` of the Git export.
    let bare = env.root.join("github.git");
    git(&env.root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    env.ok(U, &proj, &["git", "remote", "add", "origin", bare.to_str().unwrap()]);
    env.ok(U, &proj, &["git", "push"]);
    let clone = env.root.join("clone");
    git(&env.root, &["clone", "-q", bare.to_str().unwrap(), clone.to_str().unwrap()]);
    let gp = String::from_utf8(git(&clone, &["format-patch", "-1", "--stdout", "--full-index", "--no-renames", "--no-binary", "main"])).unwrap();
    let body = |s: &str| -> Vec<String> {
        s.lines()
            .skip_while(|l| !l.starts_with("diff --git"))
            .take_while(|l| *l != "-- ")
            .map(str::to_string)
            .collect()
    };
    assert_eq!(body(&patch), body(&gp), "\n--- vl:\n{patch}\n--- git:\n{gp}");
}

// ---- the Git export -----------------------------------------------------------------------

#[test]
fn an_eol_crlf_export_is_clean_in_a_git_clone() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, ".gitattributes", "*.txt text eol=crlf\n");
    write_bytes(&proj, "a.txt", b"one\r\ntwo\r\n");
    write_bytes(&proj, "old.dat", b"kept\r\nas is\r\n");
    env.ok(U, &proj, &["commit", "-m", "first"]);
    env.ok(U, &proj, &["tag", "set", "main", "-r", "@-"]);
    assert_eq!(env.stdout(U, &proj, &["cat", "a.txt"]), "one\ntwo\n");
    let bare = env.root.join("github.git");
    git(&env.root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    env.ok(U, &proj, &["git", "remote", "add", "origin", bare.to_str().unwrap()]);
    env.ok(U, &proj, &["git", "push"]);
    let clone = env.root.join("clone");
    git(&env.root, &["clone", "-q", bare.to_str().unwrap(), clone.to_str().unwrap()]);
    // The blobs are the recorded bytes (export never converts) …
    assert_eq!(git(&clone, &["cat-file", "blob", "HEAD:a.txt"]), b"one\ntwo\n");
    assert_eq!(git(&clone, &["cat-file", "blob", "HEAD:old.dat"]), b"kept\r\nas is\r\n");
    // … Git converts them as Veil does, and sees no change.
    assert_eq!(std::fs::read(clone.join("a.txt")).unwrap(), b"one\r\ntwo\r\n");
    assert!(git(&clone, &["status", "--porcelain"]).is_empty());
}

// ---- confidentiality ----------------------------------------------------------------------

#[test]
fn a_sealed_gitattributes_never_shapes_or_reaches_a_public_patch() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "hello\n")]);
    env.ok(U, &proj, &["cloak", ".gitattributes"]);
    write(&proj, ".gitattributes", "a.txt -diff merge=SEALED-DRIVER-7781\n");
    env.ok(U, &proj, &["commit", "-m", "attrs"]);
    write(&proj, "a.txt", "hello\nworld\n");
    env.ok(U, &proj, &["commit", "-m", "edit"]);
    // Alice (a member) sees her attributes.
    assert!(env.stdout(U, &proj, &["diff", "-r", "@-"]).contains("binary content differs"));
    // The public patch is the projection's: no sealed attribute decides
    // how it looks, and none of its text is in it.
    let patch = env.stdout(U, &proj, &["format-patch", "@-", "--stdout"]);
    assert!(patch.contains("+world"), "{patch}");
    assert!(!patch.contains("SEALED-DRIVER-7781") && !patch.contains("-diff"), "{patch}");
    // Nor any JSON a public reader gets: `vl attr check --json` reads the
    // member's own working copy only.
    let out = env.ok(U, &proj, &["format-patch", "::@-", "--stdout"]);
    assert!(!out.contains("SEALED-DRIVER-7781"), "{out}");
}

#[test]
fn hostile_driver_configuration_is_reported_and_ignored() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[(".gitattributes", "*.txt diff=x merge=y\n"), ("a.txt", "hi\n")]);
    for cfg in [
        "[merge.y]\ncommand = \"not an array\"\n",
        "[merge.y]\ncommand = []\n[diff.x]\ntextconv = [1, 2]\n",
        "this is = = not toml\n",
        "[merge.y]\ncommand = [\"a\\u0000b\"]\n",
    ] {
        write(&proj, ".veil/local/config.toml", cfg);
        let doc: serde_json::Value = serde_json::from_str(&env.stdout(U, &proj, &["attr", "check", "a.txt", "--json"])).unwrap();
        assert!(!doc["warnings"].as_array().unwrap().is_empty(), "{cfg}: {doc}");
        assert!(doc["paths"][0]["merge"].as_str().unwrap().contains("not defined"), "{cfg}: {doc}");
        env.ok(U, &proj, &["status"]);
    }
    // A huge or non-regular file is ignored too.
    write(&proj, ".veil/local/config.toml", &"#".repeat(2 << 20));
    let out = env.ok(U, &proj, &["attr", "check", "a.txt"]);
    assert!(out.contains("not a regular file under 1 MiB"), "{out}");
    std::fs::remove_file(proj.join(".veil/local/config.toml")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc/passwd", proj.join(".veil/local/config.toml")).unwrap();
    let out = env.ok(U, &proj, &["attr", "check", "a.txt"]);
    assert!(out.contains("not a regular file"), "{out}");
}

#[test]
fn a_renamed_no_diff_file_is_binary_in_a_patch_and_a_link_never_is() {
    let env = Env::new();
    let body: String = (0..12).map(|i| format!("row {i} of the data file\n")).collect();
    let proj = env.project(U, "proj", &[(".gitattributes", "*.dat -diff\n* -diff\n"), ("a.dat", &body)]);
    std::fs::rename(proj.join("a.dat"), proj.join("b.dat")).unwrap();
    std::fs::write(proj.join("b.dat"), format!("{body}one more\n")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("b.dat", proj.join("link")).unwrap();
    env.ok(U, &proj, &["commit", "-m", "move"]);
    let patch = env.stdout(U, &proj, &["format-patch", "@-", "-M", "--stdout"]);
    assert!(patch.contains("rename from a.dat") && patch.contains("rename to b.dat"), "{patch}");
    assert!(patch.contains("Binary files a/a.dat and b/b.dat differ"), "{patch}");
    // `* -diff` covers the symlink too, but only regular files are binary.
    #[cfg(unix)]
    assert!(!patch.contains("Binary files /dev/null and b/link differ") && patch.contains("+b.dat"), "{patch}");
}
