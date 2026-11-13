//! End-to-end working-copy behaviour through the real `vl` binary:
//! quarantined edits and the stat cache.

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Env {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Env {
    fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        Env { _tmp: tmp, root }
    }

    fn dir(&self, name: &str) -> PathBuf {
        let d = self.root.join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn vl(&self, cwd: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vl"))
            .env("VEIL_TEST_PATH_REMOTES", "1")
            .args(args)
            .current_dir(cwd)
            .env("VEIL_HOME", self.root.join("home"))
            .env("VEIL_USER", "alice")
            .env("NO_COLOR", "1")
            .output()
            .unwrap()
    }

    /// stdout + stderr of a successful run.
    fn ok(&self, cwd: &Path, args: &[&str]) -> String {
        let out = self.vl(cwd, args);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "vl {args:?} failed:\n{text}");
        text
    }

    fn stdout(&self, cwd: &Path, args: &[&str]) -> String {
        let out = self.vl(cwd, args);
        assert!(
            out.status.success(),
            "vl {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

fn write(dir: &Path, rel: &str, content: &str) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

fn read(dir: &Path, rel: &str) -> String {
    std::fs::read_to_string(dir.join(rel)).unwrap()
}

fn files(env: &Env, proj: &Path, rev: &str) -> Vec<String> {
    env.stdout(proj, &["files", "-r", rev])
        .lines()
        .filter_map(|l| l.split_whitespace().last().map(String::from))
        .collect()
}

const CLEAN: &str = "const key = process.env.KEY;\n";
const LEAKY: &str = "const key = 'AKIAIOSFODNN7EXAMPLE';\n";

#[test]
fn quarantined_edits_keep_history_and_survive_checkouts() {
    let env = Env::new();
    let proj = env.dir("proj");
    write(&proj, "cfg.js", CLEAN);
    write(&proj, "main.rs", "fn main() {}\n");
    env.ok(&proj, &["init"]);
    env.ok(&proj, &["commit", "-m", "v1"]);

    // Case 1: a tracked file gains a secret. History keeps v1; no deletion.
    write(&proj, "cfg.js", LEAKY);
    // Case 2: a never-tracked file with a secret stays out of the tree.
    write(&proj, "leak.js", LEAKY);
    let st = env.ok(&proj, &["status"]);
    assert!(
        st.contains("The working copy has no changes."),
        "no deletion recorded:\n{st}"
    );
    assert!(
        st.contains("Q cfg.js [quarantined]  (aws-access-key-id; edit held back; history keeps the previous version)"),
        "{st}"
    );
    assert!(st.contains("Q leak.js [quarantined]  (aws-access-key-id; never recorded)"), "{st}");
    assert!(
        st.contains("history keeps the previous version"),
        "warning explains it:\n{st}"
    );
    assert_eq!(files(&env, &proj, "@"), vec![".veilpolicy", "cfg.js", "main.rs"]);
    assert_eq!(env.stdout(&proj, &["cat", "cfg.js", "-r", "@"]), CLEAN);

    // Checking out a tree without the file must not delete the local edit...
    // (Exit 3: `cfg.js` and `leak.js` stay quarantined, BUG-2140.)
    let out = env.vl(&proj, &["new", "root"]);
    assert_eq!(out.status.code(), Some(3), "{}", String::from_utf8_lossy(&out.stderr));
    let out = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.contains("kept cfg.js"), "{out}");
    assert_eq!(read(&proj, "cfg.js"), LEAKY);
    assert!(!proj.join("main.rs").exists(), "everything else is checked out");
    // ...and neither must checking out one that has it (from a tree that does not).
    let out = env.ok(&proj, &["undo"]);
    assert!(out.contains("kept cfg.js"), "{out}");
    assert_eq!(read(&proj, "cfg.js"), LEAKY);
    assert_eq!(read(&proj, "main.rs"), "fn main() {}\n");
    let st = env.ok(&proj, &["status"]);
    assert!(st.contains("history keeps the previous version"), "{st}");
    assert_eq!(files(&env, &proj, "@"), vec![".veilpolicy", "cfg.js", "main.rs"]);

    // `vl restore` discards the quarantined edit.
    env.ok(&proj, &["restore", "cfg.js"]);
    assert_eq!(read(&proj, "cfg.js"), CLEAN);
    let st = env.ok(&proj, &["status"]);
    assert!(!st.contains("Q cfg.js"), "{st}");
    assert!(st.contains("Q leak.js"), "{st}");
}

#[test]
fn same_size_edits_are_seen_with_a_warm_cache() {
    let env = Env::new();
    let proj = env.dir("proj");
    write(&proj, "a.txt", "v0\n");
    write(&proj, "b/c.txt", "c\n");
    env.ok(&proj, &["init"]);
    env.ok(&proj, &["commit", "-m", "base"]);
    env.ok(&proj, &["status"]);
    assert!(proj.join(".veil/local/statcache/default.cache").is_file());
    for i in 1..=5 {
        // Same size as before, rewritten immediately after the last command.
        write(&proj, "a.txt", &format!("v{i}\n"));
        let st = env.ok(&proj, &["status"]);
        assert!(st.contains("M a.txt"), "edit {i} missed:\n{st}");
        assert_eq!(env.stdout(&proj, &["cat", "a.txt", "-r", "@"]), format!("v{i}\n"));
    }
    // Switching workspaces keeps the directory and its cache consistent.
    env.ok(&proj, &["ws", "new", "other", "-r", "@-"]);
    env.ok(&proj, &["ws", "switch", "other"]);
    assert_eq!(read(&proj, "a.txt"), "v0\n");
    write(&proj, "a.txt", "w1\n");
    assert!(env.ok(&proj, &["status"]).contains("M a.txt"));
    env.ok(&proj, &["ws", "switch", "default"]);
    assert_eq!(read(&proj, "a.txt"), "v5\n");
    assert!(proj.join(".veil/local/statcache/other.cache").is_file());
}

/// BUG-757: `vl restore` of a cloaked file (a `.env.*`, under `init`'s
/// `cloak rule`) whose directory was deleted (by `rm -r`, `git clean`) put
/// the file back, then failed with `not found`: the restored entry was set
/// into a tree that no longer had its directory.
#[test]
fn restoring_a_cloaked_file_into_a_deleted_directory_works() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok(&proj, &["init"]);
    write(&proj, "secrets/deep/.env.db", "password: hunter2\n");
    write(&proj, "plain/f.txt", "plain\n");
    env.ok(&proj, &["commit", "-m", "v1"]);
    std::fs::remove_dir_all(proj.join("secrets")).unwrap();
    std::fs::remove_dir_all(proj.join("plain")).unwrap();
    let out = env.ok(&proj, &["restore", "secrets/deep/.env.db"]);
    assert!(out.contains("Restored 1 path(s)"), "{out}");
    assert_eq!(read(&proj, "secrets/deep/.env.db"), "password: hunter2\n");
    env.ok(&proj, &["restore", "plain/f.txt"]);
    assert_eq!(read(&proj, "plain/f.txt"), "plain\n");
    let st = env.ok(&proj, &["status"]);
    assert!(st.contains("no changes"), "{st}");
    let ls = env.stdout(&proj, &["ls", "-r", "@"]);
    assert!(ls.lines().any(|l| l.starts_with("cloaked") && l.ends_with("secrets/deep/.env.db")), "{ls}");
}

// ---- S7: the Veil daemon's file watcher (`docs/HUB.md` §13.33) ----------------

#[cfg(unix)]
mod s7_watcher {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    impl Env {
        fn vl_env(&self, cwd: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_vl"));
            cmd.env("VEIL_TEST_PATH_REMOTES", "1")
                .args(args)
                .current_dir(cwd)
                .env("VEIL_HOME", self.root.join("home"))
                .env("VEIL_USER", "alice")
                .env("NO_COLOR", "1");
            for &(k, v) in extra_env {
                cmd.env(k, v);
            }
            cmd.output().unwrap()
        }

        fn ok_env(&self, cwd: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> String {
            let out = self.vl_env(cwd, args, extra_env);
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(out.status.success(), "vl {args:?} failed:\n{text}");
            text
        }
    }

    impl Drop for Env {
        fn drop(&mut self) {
            // Stop any daemon started inside this test's VEIL_HOME so no background
            // process lingers after the test TempDir is removed.
            if self.root.join("home/daemon").exists() {
                let _ = self.vl(&self.root, &["daemon", "stop"]);
            }
        }
    }

    fn checkout_token(proj: &Path) -> Option<String> {
        let raw = std::fs::read(proj.join(".veil/local/checkout.json")).ok()?;
        let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
        v.get("watch")?.get("token")?.as_str().map(String::from)
    }

    /// Compare a watched working copy `watched` against a reference `scanned`
    /// (where `watch = false` forces a full scan on every command). Both must
    /// produce identical `vl status --json` and `vl files -r @` outputs and
    /// identical tree content.
    fn assert_same_as_scan(env: &Env, watched: &Path, scanned: &Path) {
        let st_w = env.stdout(watched, &["status", "--json"]);
        let st_s = env.stdout(scanned, &["status", "--json"]);
        let vw: serde_json::Value = serde_json::from_str(&st_w).unwrap();
        let vs: serde_json::Value = serde_json::from_str(&st_s).unwrap();
        assert_eq!(vw["changes"], vs["changes"], "watched vs scanned changes differ:\nwatched: {st_w}\nscanned: {st_s}");
        assert_eq!(vw["quarantined"], vs["quarantined"], "quarantined differ");
        assert_eq!(vw["isolated"], vs["isolated"], "isolated differ");
        assert_eq!(vw["unreadable"], vs["unreadable"], "unreadable differ");
        let ls_w: serde_json::Value = serde_json::from_str(&env.stdout(watched, &["ls", "--json", "-r", "@"])).unwrap();
        let ls_s: serde_json::Value = serde_json::from_str(&env.stdout(scanned, &["ls", "--json", "-r", "@"])).unwrap();
        assert_eq!(ls_w["entries"], ls_s["entries"], "tracked tree entries differ:\nwatched: {ls_w}\nscanned: {ls_s}");
        if let Some(arr) = ls_w["entries"].as_array() {
            for item in arr {
                if item["kind"].as_str() == Some("file") && item["recorded"].as_bool() == Some(true) {
                    if let Some(path) = item["path"].as_str() {
                        assert_eq!(
                            env.stdout(watched, &["cat", path, "-r", "@"]),
                            env.stdout(scanned, &["cat", path, "-r", "@"]),
                            "content of {path} differs between watched and scanned"
                        );
                    }
                }
            }
        }
    }

    /// Guarantee 1: `vl status` and `vl commit` give the exact same answer with
    /// the watcher as with a full scan across edits, adds, deletes, renames,
    /// mode changes, new deep subdirectories, files changed in the racy window
    /// right before/during a commit, and changes made while the daemon was down,
    /// restarting, or handed a foreign/corrupt token.
    #[test]
    fn s7_g1_status_and_commit_with_watcher_match_full_scan_across_all_changes_and_restarts() {
        let env = Env::new();
        let w = env.dir("watched");
        let s = env.dir("scanned");

        let both = |op: &dyn Fn(&Path)| {
            op(&w);
            op(&s);
        };

        both(&|p| {
            write(p, "src/lib.rs", "pub fn a() -> u32 { 1 }\n");
            write(p, "src/sub/mod.rs", "pub mod inner;\n");
            write(p, "src/sub/inner.rs", "pub fn x() {}\n");
            write(p, "docs/readme.md", "# hello\n");
            write(p, "scripts/run.sh", "#!/bin/sh\necho hi\n");
        });
        env.ok(&w, &["init"]);
        env.ok(&s, &["init"]);
        // Disable the watcher on `scanned` via `.veil/local/config.toml` so it
        // always performs a full scan.
        write(&s, ".veil/local/config.toml", "watch = false\n");

        env.ok(&w, &["commit", "-m", "initial"]);
        env.ok(&s, &["commit", "-m", "initial"]);

        // First status registers the working copy with the daemon and records a token.
        assert_same_as_scan(&env, &w, &s);
        let tok1 = checkout_token(&w).expect("watcher recorded a token in watched repo");
        assert!(checkout_token(&s).is_none(), "watch = false must not record a watch token");

        // Second status on unchanged working copy uses the watcher plan and advances/keeps token.
        assert_same_as_scan(&env, &w, &s);
        assert!(checkout_token(&w).is_some());

        let dst = env.ok(&w, &["daemon", "status"]);
        assert!(dst.contains("watching  1 working cop(ies)"), "daemon status shows watched wc:\n{dst}");

        // 1. Edit a file (including same-size edit in the racy window).
        both(&|p| write(p, "src/lib.rs", "pub fn a() -> u32 { 2 }\n"));
        assert_same_as_scan(&env, &w, &s);

        // 2. Add a file in an existing directory and in a brand-new nested directory tree.
        both(&|p| {
            write(p, "src/added.rs", "pub const NEW: usize = 1;\n");
            write(p, "src/new_dir/deep/leaf.rs", "pub fn deep() {}\n");
        });
        assert_same_as_scan(&env, &w, &s);

        // 3. Delete a file and a whole directory subtree.
        both(&|p| {
            std::fs::remove_file(p.join("docs/readme.md")).unwrap();
            std::fs::remove_dir_all(p.join("src/sub")).unwrap();
        });
        assert_same_as_scan(&env, &w, &s);

        // 4. Rename a file and rename a directory.
        both(&|p| {
            std::fs::rename(p.join("src/added.rs"), p.join("src/renamed.rs")).unwrap();
            std::fs::rename(p.join("src/new_dir"), p.join("src/moved_dir")).unwrap();
        });
        assert_same_as_scan(&env, &w, &s);

        // 5. Mode change (executable bit toggled).
        both(&|p| {
            let sh = p.join("scripts/run.sh");
            std::fs::set_permissions(&sh, std::fs::Permissions::from_mode(0o755)).unwrap();
        });
        assert_same_as_scan(&env, &w, &s);

        // Commit all these changes and verify commit tree matches scan.
        env.ok(&w, &["commit", "-m", "batch 1"]);
        env.ok(&s, &["commit", "-m", "batch 1"]);
        assert_same_as_scan(&env, &w, &s);

        // 6. Immediate edit + commit in the same millisecond / racy window.
        both(&|p| write(p, "src/moved_dir/deep/leaf.rs", "pub fn deep() { /* edited */ }\n"));
        env.ok(&w, &["commit", "-m", "racy commit"]);
        env.ok(&s, &["commit", "-m", "racy commit"]);
        assert_same_as_scan(&env, &w, &s);

        // 7. Tamper with the token in checkout.json (foreign / bogus token):
        // the daemon cannot vouch for it, so `vl` falls back to scanning and never misses an edit.
        let co_path = w.join(".veil/local/checkout.json");
        let mut co: serde_json::Value = serde_json::from_slice(&std::fs::read(&co_path).unwrap()).unwrap();
        co["watch"]["token"] = serde_json::json!("deadbeef:99999999");
        std::fs::write(&co_path, serde_json::to_vec(&co).unwrap()).unwrap();
        both(&|p| write(p, "src/lib.rs", "pub fn a() -> u32 { 3 }\n"));
        assert_same_as_scan(&env, &w, &s);
        let tok_after_tamper = checkout_token(&w).expect("fresh token issued after rescan");
        assert_ne!(tok_after_tamper, "deadbeef:99999999");

        // 8. Stop and restart the daemon while edits happen (changes made while daemon is down).
        env.ok(&w, &["daemon", "stop"]);
        both(&|p| {
            write(p, "src/while_down.rs", "pub fn down() {}\n");
            std::fs::remove_file(p.join("src/renamed.rs")).unwrap();
        });
        // While stopped, `vl status` still works and matches scan.
        assert_same_as_scan(&env, &w, &s);
        // Restart the daemon; the old token from `tok1` is from a previous daemon instance,
        // so it must rescan and catch edits made before `daemon start`.
        env.ok(&w, &["daemon", "start"]);
        both(&|p| write(p, "src/after_restart.rs", "pub fn restart() {}\n"));
        assert_same_as_scan(&env, &w, &s);
        env.ok(&w, &["commit", "-m", "after restart"]);
        env.ok(&s, &["commit", "-m", "after restart"]);
        assert_same_as_scan(&env, &w, &s);

        // 9. Editing `.veilpolicy` or `.veilattributes` forces a full rescan so
        // reclassification across untouched directories is never missed.
        both(&|p| {
            write(p, "build/out.bin", "artifact\n");
        });
        assert_same_as_scan(&env, &w, &s);
        both(&|p| {
            let mut pol = read(p, ".veilpolicy");
            pol.push_str("\nbuild/ ignore\n");
            write(p, ".veilpolicy", &pol);
        });
        assert_same_as_scan(&env, &w, &s);
        let ls_w = env.stdout(&w, &["ls", "--all"]);
        let ls_s = env.stdout(&s, &["ls", "--all"]);
        assert_eq!(ls_w, ls_s, "`vl ls --all` with watcher matches full scan");
        let _ = tok1;
    }

    /// The review of `clifast` (guarantee 1): a walk of edits (same size, in
    /// the same instant as the command), creations, deletions, renames of
    /// files and directories, mode changes, a file replaced by a directory
    /// and the reverse, in directories whose names share prefixes; with the
    /// daemon stopped and started, and the stat cache file deleted,
    /// truncated, corrupted or put back from an earlier command (stale).
    /// After every step `vl status` and the recorded tree of the watched
    /// working copy are those of one that scans with the watcher off, and
    /// `vl commit` records the same.
    #[test]
    fn clifast_review_status_and_commit_with_the_watcher_match_a_full_scan_over_a_walk_of_changes() {
        for seed in [1u64, 2, 3] {
            let env = Env::new();
            let w = env.dir("watched");
            let s = env.dir("scanned");
            let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            let mut next = |n: usize| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state % n as u64) as usize
            };
            for p in [&w, &s] {
                write(p, "a/f", "one\n");
                write(p, "a/b/f", "two\n");
                write(p, "a/b2/f", "three\n");
                write(p, "top", "four\n");
                env.ok(p, &["init"]);
            }
            write(&s, ".veil/local/config.toml", "watch = false\n");
            env.ok(&w, &["commit", "-m", "initial"]);
            env.ok(&s, &["commit", "-m", "initial"]);
            let same = |at: &str| {
                let st = |p: &Path| -> serde_json::Value { serde_json::from_str(&env.stdout(p, &["status", "--json"])).unwrap() };
                let (vw, vs) = (st(&w), st(&s));
                assert_eq!(vw["changes"], vs["changes"], "seed {seed}, {at}: `vl status` with the watcher against a full scan");
                let ls = |p: &Path| -> serde_json::Value { serde_json::from_str(&env.stdout(p, &["ls", "--json", "-r", "@"])).unwrap() };
                let (lw, lsc) = (ls(&w), ls(&s));
                assert_eq!(lw["entries"], lsc["entries"], "seed {seed}, {at}: the recorded tree with the watcher against a full scan");
            };
            same("start");
            assert!(checkout_token(&w).is_some(), "the watcher is on");
            const DIRS: &[&str] = &["", "a", "a/b", "a/b2", "a/b.x", "a/b/c", "a.d", "ab", "z é"];
            const NAMES: &[&str] = &["f", "f2", "f.txt", "a", "b", "b2", "é ü"];
            let files = |root: &Path| -> Vec<String> {
                fn go(root: &Path, dir: &Path, out: &mut Vec<String>) {
                    let mut names: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap()).collect();
                    names.sort_by_key(|e| e.file_name());
                    for e in names {
                        let name = e.file_name().to_string_lossy().to_string();
                        if name.starts_with(".veil") {
                            continue;
                        }
                        match e.file_type().unwrap().is_dir() {
                            true => go(root, &e.path(), out),
                            false => out.push(e.path().strip_prefix(root).unwrap().to_string_lossy().to_string()),
                        }
                    }
                }
                let mut out = Vec::new();
                go(root, root, &mut out);
                out
            };
            let mut kept_cache: Option<Vec<u8>> = None;
            let cache = w.join(".veil/local/statcache/default.cache");
            for step in 0..28 {
                let existing = files(&w);
                assert_eq!(existing, files(&s), "the two working copies hold the same files");
                let what = if existing.len() < 3 { 0 } else { next(12) };
                let dir = DIRS[next(DIRS.len())];
                let name = NAMES[next(NAMES.len())];
                let target = if dir.is_empty() { name.to_string() } else { format!("{dir}/{name}") };
                let pick = existing.get(next(existing.len().max(1))).cloned().unwrap_or_default();
                let text = format!("{seed} {step} {}\n", next(1000));
                for p in [&w, &s] {
                    let clear = |path: &Path| {
                        // Whatever stands in the way of a file at `path` goes.
                        let mut up = path.parent();
                        while let Some(d) = up.filter(|d| d.starts_with(p) && *d != p.as_path()) {
                            if d.is_file() {
                                std::fs::remove_file(d).unwrap();
                            }
                            up = d.parent();
                        }
                        if path.is_dir() {
                            std::fs::remove_dir_all(path).unwrap();
                        }
                    };
                    match what {
                        0..=2 => {
                            clear(&p.join(&target));
                            write(p, &target, &text);
                        }
                        3 | 4 => {
                            // The same size, written at once.
                            let old = read(p, &pick);
                            let mut new = old.clone().into_bytes();
                            new[0] = if new[0] == b'x' { b'y' } else { b'x' };
                            std::fs::write(p.join(&pick), new).unwrap();
                        }
                        5 => std::fs::remove_file(p.join(&pick)).unwrap(),
                        6 => {
                            // A directory removed with what it holds.
                            if let Some((d, _)) = pick.split_once('/') {
                                std::fs::remove_dir_all(p.join(d)).unwrap();
                            }
                        }
                        7 => {
                            let mode = if std::fs::metadata(p.join(&pick)).unwrap().permissions().mode() & 0o100 != 0 { 0o644 } else { 0o755 };
                            std::fs::set_permissions(p.join(&pick), std::fs::Permissions::from_mode(mode)).unwrap();
                        }
                        8 => {
                            // A file renamed.
                            if pick != target && !p.join(&target).starts_with(p.join(&pick)) {
                                clear(&p.join(&target));
                                if p.join(&pick).is_file() {
                                    std::fs::create_dir_all(p.join(&target).parent().unwrap()).unwrap();
                                    std::fs::rename(p.join(&pick), p.join(&target)).unwrap();
                                }
                            }
                        }
                        9 => {
                            // A directory renamed, to a name that shares its prefix.
                            if let Some((d, _)) = pick.split_once('/') {
                                let to = format!("{d}{}", step % 3);
                                if !p.join(&to).exists() {
                                    std::fs::rename(p.join(d), p.join(&to)).unwrap();
                                }
                            }
                        }
                        10 => {
                            // A file replaced by a directory of its name.
                            std::fs::remove_file(p.join(&pick)).unwrap();
                            write(p, &format!("{pick}/inside"), &text);
                        }
                        _ => {
                            // A directory replaced by a file of its name.
                            if let Some((d, _)) = pick.split_once('/') {
                                std::fs::remove_dir_all(p.join(d)).unwrap();
                                write(p, d, &text);
                            }
                        }
                    }
                }
                // Between two commands: the daemon, and the cache file.
                let between = next(12);
                match between {
                    // The change is made while the daemon is running, and it
                    // is stopped before the command; or it is restarted.
                    0 => {
                        env.ok(&w, &["daemon", "stop"]);
                    }
                    1 => {
                        env.ok(&w, &["daemon", "stop"]);
                        env.ok(&w, &["daemon", "start"]);
                    }
                    2 => {
                        let _ = std::fs::remove_file(&cache);
                    }
                    3 => {
                        if let Ok(raw) = std::fs::read(&cache) {
                            std::fs::write(&cache, &raw[..raw.len() / 2]).unwrap();
                        }
                    }
                    4 => {
                        if let Ok(mut raw) = std::fs::read(&cache) {
                            let at = raw.len() / 2;
                            raw[at] ^= 0x20;
                            std::fs::write(&cache, raw).unwrap();
                        }
                    }
                    5 => kept_cache = std::fs::read(&cache).ok(),
                    6 => {
                        if let Some(old) = &kept_cache {
                            std::fs::write(&cache, old).unwrap();
                        }
                    }
                    _ => {}
                }
                // A record made within 100 ms of a file's last change vouches
                // for nothing: some commands come later, so that the next
                // ones find records they use.
                if next(3) == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(130));
                }
                same(&format!("step {step} (change {what})"));
                if between == 0 {
                    env.ok(&w, &["daemon", "start"]);
                }
                if next(4) == 0 {
                    same(&format!("step {step}, again"));
                }
                if next(5) == 0 {
                    env.ok(&w, &["commit", "-m", &format!("step {step}")]);
                    env.ok(&s, &["commit", "-m", &format!("step {step}")]);
                    same(&format!("step {step}, committed"));
                }
            }
            same("the end");
            same("the end, again");
            assert!(checkout_token(&w).is_some(), "seed {seed}: the watcher is still on");
            let status = env.ok(&w, &["daemon", "status"]);
            assert!(status.contains("watching  1 working cop(ies)"), "seed {seed}: {status}");
        }
    }

    /// Guarantee 2: The watcher never reads or reports anything outside the
    /// working copy, never follows symlinks (to files or directories) out of
    /// it, and never descends into nested `.veil` repositories.
    #[test]
    fn s7_g2_watcher_never_follows_symlinks_or_escapes_working_copy() {
        let env = Env::new();
        let outside = env.dir("outside_secret");
        write(&outside, "secret.txt", "TOP_SECRET_OUTSIDE_REPO\n");
        write(&outside, "sub/inner.txt", "INNER_OUTSIDE\n");

        let w = env.dir("watched");
        let s = env.dir("scanned");
        write(&w, "a.txt", "hello\n");
        write(&s, "a.txt", "hello\n");
        env.ok(&w, &["init"]);
        env.ok(&s, &["init"]);
        write(&s, ".veil/local/config.toml", "watch = false\n");
        env.ok(&w, &["commit", "-m", "base"]);
        env.ok(&s, &["commit", "-m", "base"]);
        assert_same_as_scan(&env, &w, &s);
        assert!(checkout_token(&w).is_some());

        // Create symlinks pointing to outside directory and outside file.
        for p in [&w, &s] {
            std::os::unix::fs::symlink(&outside, p.join("escape_dir")).unwrap();
            std::os::unix::fs::symlink(outside.join("secret.txt"), p.join("escape_file")).unwrap();
        }
        assert_same_as_scan(&env, &w, &s);

        // Mutating files inside `outside` must NOT affect the watched working copy
        // or leak outside filenames/contents into status or daemon state.
        write(&outside, "secret.txt", "MODIFIED_OUTSIDE\n");
        write(&outside, "new_outside.txt", "NEW_OUTSIDE\n");
        assert_same_as_scan(&env, &w, &s);

        let st = env.ok(&w, &["status"]);
        assert!(!st.contains("TOP_SECRET_OUTSIDE_REPO") && !st.contains("new_outside.txt"), "{st}");

        // Replacing a real watched subdirectory with a symlink to `outside`:
        // the watcher must drop the watch and never watch `outside`.
        for p in [&w, &s] {
            write(p, "real_sub/f.txt", "inside\n");
        }
        assert_same_as_scan(&env, &w, &s);
        for p in [&w, &s] {
            std::fs::remove_dir_all(p.join("real_sub")).unwrap();
            std::os::unix::fs::symlink(&outside, p.join("real_sub")).unwrap();
        }
        write(&outside, "after_swap.txt", "SWAP\n");
        assert_same_as_scan(&env, &w, &s);

        // A nested Veil repository inside the working copy is never descended into by the watcher.
        let nested_w = w.join("nested_repo");
        let nested_s = s.join("nested_repo");
        std::fs::create_dir_all(&nested_w).unwrap();
        std::fs::create_dir_all(&nested_s).unwrap();
        write(&nested_w, "inside_nested.txt", "nested\n");
        write(&nested_s, "inside_nested.txt", "nested\n");
        env.ok(&nested_w, &["init"]);
        env.ok(&nested_s, &["init"]);
        assert_same_as_scan(&env, &w, &s);
    }

    /// Guarantee 3: Watched directories and dirty paths per working copy are
    /// bounded. When a bound is exceeded, the daemon drops the working copy's
    /// watches, `vl` warns that it is falling back to a full scan, and `vl
    /// status` / `vl commit` still produce the exact same result as a scan.
    #[test]
    fn s7_g3_watcher_bounds_fall_back_to_scanning_and_warn() {
        let env = Env::new();
        let w = env.dir("watched");
        let s = env.dir("scanned");
        for i in 0..6 {
            write(&w, &format!("d{i}/f.txt"), &format!("v{i}\n"));
            write(&s, &format!("d{i}/f.txt"), &format!("v{i}\n"));
        }
        env.ok(&w, &["init"]);
        env.ok(&s, &["init"]);
        write(&s, ".veil/local/config.toml", "watch = false\n");
        env.ok(&w, &["commit", "-m", "base"]);
        env.ok(&s, &["commit", "-m", "base"]);

        // 1. Exceed max_dirs bound (6 directories in tree: root + d0..d5 = 7 dirs > max_dirs=3).
        let out = env.ok_env(&w, &["status"], &[("VEIL_WATCH_MAX_DIRS", "3")]);
        assert!(
            out.contains("directory bound (3 directories) was reached") && out.contains("falling back to a full scan"),
            "expected directory-bound fallback warning:\n{out}"
        );
        assert!(checkout_token(&w).is_none(), "no token when directory bound is exceeded");

        // Edit a file while bound is exceeded: still detected by fallback scan!
        write(&w, "d2/f.txt", "changed under dir bound\n");
        write(&s, "d2/f.txt", "changed under dir bound\n");
        let out2 = env.ok_env(&w, &["status"], &[("VEIL_WATCH_MAX_DIRS", "3")]);
        assert!(out2.contains("M d2/f.txt"), "{out2}");
        assert_same_as_scan(&env, &w, &s);

        // 2. Raise max_dirs and test max_dirty_paths bound (via `.veil/local/config.toml`).
        write(&w, ".veil/local/config.toml", "[watch]\nmax_dirs = 100\nmax_dirty_paths = 2\n");
        let out_arm = env.ok(&w, &["status"]);
        assert!( !out_arm.contains("falling back"), "{out_arm}");
        assert!(checkout_token(&w).is_some(), "armed with max_dirs = 100");

        // Dirty 4 distinct directories (> max_dirty_paths = 2).
        for i in 0..4 {
            write(&w, &format!("d{i}/f.txt"), &format!("burst {i}\n"));
            write(&s, &format!("d{i}/f.txt"), &format!("burst {i}\n"));
        }
        let out_dirty = env.ok(&w, &["status"]);
        assert!(
            out_dirty.contains("dirty-path bound (2 paths") && out_dirty.contains("falling back to a full scan"),
            "expected dirty-path bound fallback warning:\n{out_dirty}"
        );
        assert!(checkout_token(&w).is_none(), "overflow clears token");
        assert_same_as_scan(&env, &w, &s);
    }

    /// Guarantee 4: The watcher is off when the daemon is stopped (`vl daemon
    /// stop`) or when `watch = false` is set in `.veil/local/config.toml`, and
    /// `vl` works identically without it (and never auto-starts a stopped daemon).
    #[test]
    fn s7_g4_watcher_is_off_when_daemon_stopped_or_disabled_in_config() {
        let env = Env::new();
        let proj = env.dir("proj");
        write(&proj, "a.txt", "v0\n");
        env.ok(&proj, &["init"]);
        env.ok(&proj, &["commit", "-m", "v0"]);

        // Turn the daemon off with `vl daemon stop`.
        let stop = env.ok(&proj, &["daemon", "stop"]);
        assert!(stop.contains("the Veil daemon is stopped and stays off"), "{stop}");

        // Run status and commit while daemon is off: must NOT start the daemon.
        write(&proj, "a.txt", "v1\n");
        let st = env.ok(&proj, &["status"]);
        assert!(st.contains("M a.txt"), "{st}");
        assert!(checkout_token(&proj).is_none(), "no watch token when daemon is off");

        let dst = env.ok(&proj, &["daemon", "status"]);
        assert!(dst.contains("Veil daemon: off"), "daemon stayed off:\n{dst}");

        let doc = env.ok(&proj, &["doctor"]);
        assert!(doc.contains("Veil daemon is off"), "doctor reports daemon is off:\n{doc}");

        env.ok(&proj, &["commit", "-m", "v1"]);
        assert_eq!(env.stdout(&proj, &["cat", "a.txt", "-r", "@"]), "v1\n");

        // Turn the daemon back on: now `vl status` uses it and `vl doctor` reports it.
        env.ok(&proj, &["daemon", "start"]);
        env.ok(&proj, &["status"]);
        assert!(checkout_token(&proj).is_some(), "watch token recorded after daemon start");
        let doc_on = env.ok(&proj, &["doctor"]);
        assert!(doc_on.contains("Veil daemon running") && doc_on.contains("watching 1 working cop(ies)"), "{doc_on}");
    }

    /// Guarantee 5: Secret files (`.env`, `.env.*`, keys) and quarantined leaks
    /// in plain files are sealed / held back on commit with the watcher active
    /// just as with a full scan.
    #[test]
    fn s7_g5_secrets_are_sealed_and_leaks_quarantined_with_watcher() {
        let env = Env::new();
        let w = env.dir("watched");
        let s = env.dir("scanned");

        for p in [&w, &s] {
            write(p, "src/app.rs", "pub fn app() {}\n");
            write(p, "config/.env.prod", "DB_PASS=super_secret_value_1\n");
        }
        env.ok(&w, &["init"]);
        env.ok(&s, &["init"]);
        write(&s, ".veil/local/config.toml", "watch = false\n");
        env.ok(&w, &["commit", "-m", "v1"]);
        env.ok(&s, &["commit", "-m", "v1"]);

        // Arm the watcher.
        assert_same_as_scan(&env, &w, &s);
        assert!(checkout_token(&w).is_some());

        // Edit the secret `.env.prod` and add another secret file `config/.env.staging`,
        // while also introducing a secret leak into a public file `src/app.rs`.
        for p in [&w, &s] {
            write(p, "config/.env.prod", "DB_PASS=rotated_secret_value_2\n");
            write(p, "config/.env.staging", "STAGE_TOKEN=stage_secret_3\n");
            write(p, "src/app.rs", LEAKY);
        }

        // Both status and commit must quarantine `src/app.rs` and seal both `.env.*` files.
        assert_same_as_scan(&env, &w, &s);
        let st = env.ok(&w, &["status"]);
        assert!(st.contains("Q src/app.rs [quarantined]"), "leaky edit quarantined:\n{st}");

        // Committed without the leaky edit: exit 3 (BUG-2140).
        for p in [&w, &s] {
            let out = env.vl(p, &["commit", "-m", "rotate secrets"]);
            assert_eq!(out.status.code(), Some(3), "{}", String::from_utf8_lossy(&out.stderr));
            assert!(String::from_utf8_lossy(&out.stderr).contains("  src/app.rs (aws-access-key-id at line 1; edit held back)"));
        }
        assert_same_as_scan(&env, &w, &s);

        // Verify that the committed `.env.prod` and `.env.staging` are sealed (`cloaked`)
        // in the snapshot tree, and that `src/app.rs` kept its clean v1 content.
        let ls = env.stdout(&w, &["ls", "-r", "@-"]);
        assert!(ls.lines().any(|l| l.starts_with("cloaked") && l.ends_with("config/.env.prod")), "sealed .env.prod:\n{ls}");
        assert!(ls.lines().any(|l| l.starts_with("cloaked") && l.ends_with("config/.env.staging")), "sealed .env.staging:\n{ls}");
        assert_eq!(env.stdout(&w, &["cat", "config/.env.prod", "-r", "@-"]), "DB_PASS=rotated_secret_value_2\n");
        assert_eq!(env.stdout(&w, &["cat", "src/app.rs", "-r", "@-"]), "pub fn app() {}\n");

        // Verify no plaintext secret exists anywhere in loose/packed object bytes on disk.
        for entry in std::fs::read_dir(w.join(".veil/objects")).unwrap().flatten() {
            if entry.path().is_dir() {
                for sub in std::fs::read_dir(entry.path()).unwrap().flatten() {
                    if let Ok(bytes) = std::fs::read(sub.path()) {
                        let text = String::from_utf8_lossy(&bytes);
                        assert!(!text.contains("rotated_secret_value_2"), "plaintext secret in object {:?}", sub.path());
                        assert!(!text.contains("stage_secret_3"), "plaintext secret in object {:?}", sub.path());
                        assert!(!text.contains("AKIAIOSFODNN7EXAMPLE"), "quarantined leak in object {:?}", sub.path());
                    }
                }
            }
        }
    }

    /// Hostile input test: relative paths, non-repository directories, `.veil`
    /// symlinked to another repository, system directories owned by root (`/`,
    /// `/etc`), and malformed/huge tokens on the daemon's `watch` request are
    /// cleanly refused (`known: false`, `token: None`) and never crash the
    /// daemon or leak anything outside the user's working copy.
    #[test]
    fn s7_hostile_watch_inputs_never_escape_or_crash_daemon() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        let env = Env::new();
        let proj = env.dir("proj");
        write(&proj, "a.txt", "ok\n");
        env.ok(&proj, &["init"]);
        env.ok(&proj, &["commit", "-m", "v0"]);
        env.ok(&proj, &["status"]);
        assert!(checkout_token(&proj).is_some());

        let sock = env.root.join("home/daemon/sock");
        let ask_watch = |req: serde_json::Value| -> serde_json::Value {
            let mut s = UnixStream::connect(&sock).expect("connect to daemon sock");
            s.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            let mut body = vec![1u8]; // PROTOCOL = 1
            body.extend_from_slice(&serde_json::to_vec(&req).unwrap());
            let mut msg = vec![b'Q'];
            msg.extend_from_slice(&(body.len() as u32).to_be_bytes());
            msg.extend_from_slice(&body);
            s.write_all(&msg).unwrap();
            loop {
                let mut head = [0u8; 5];
                s.read_exact(&mut head).unwrap();
                let len = u32::from_be_bytes(head[1..].try_into().unwrap()) as usize;
                let mut payload = vec![0u8; len];
                s.read_exact(&mut payload).unwrap();
                if head[0] == b'E' {
                    let end: serde_json::Value = serde_json::from_slice(&payload).unwrap();
                    return end["body"].clone();
                }
            }
        };

        // 1. Relative root path.
        let r = ask_watch(serde_json::json!({ "op": "watch", "root": "relative/path" }));
        assert_eq!(r["known"], false);
        assert!(r["token"].is_null());

        // 2. Root owned by another user (`/etc`) or without `.veil/repo.json`.
        let r = ask_watch(serde_json::json!({ "op": "watch", "root": "/etc" }));
        assert_eq!(r["known"], false);
        assert!(r["token"].is_null());

        let plain_dir = env.dir("not_a_repo");
        let r = ask_watch(serde_json::json!({ "op": "watch", "root": plain_dir }));
        assert_eq!(r["known"], false);
        assert!(r["token"].is_null());

        // 3. Directory where `.veil` is a symlink to a real repository's `.veil`.
        let fake_repo = env.dir("fake_repo");
        std::os::unix::fs::symlink(proj.join(".veil"), fake_repo.join(".veil")).unwrap();
        let r = ask_watch(serde_json::json!({ "op": "watch", "root": fake_repo }));
        assert_eq!(r["known"], false);
        assert!(r["token"].is_null(), "symlinked .veil must be refused by O_NOFOLLOW");

        // 4. Malformed tokens and zero bounds on a valid working copy.
        for bad_tok in ["", ":", "nothex:123", "123:notnum", "123:-1", &"a".repeat(8192)] {
            let r = ask_watch(serde_json::json!({
                "op": "watch",
                "root": proj,
                "token": bad_tok,
                "max_dirs": 0,
                "max_dirty_paths": 0,
            }));
            assert_eq!(r["known"], false, "bad token {bad_tok:?} must not be trusted");
        }

        // Daemon is still healthy and serves `proj`.
        write(&proj, "a.txt", "still works\n");
        let st = env.ok(&proj, &["status"]);
        assert!(st.contains("M a.txt"), "{st}");
    }
}


