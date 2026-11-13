//! Sparse `vl ws exec --only` sandboxes: they hold only the given paths,
//! record everything else as the workspace has it, never record what the
//! command writes elsewhere, and change their set incrementally.

use crate::adversarial_support;

use std::{
    io::Write as _,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use adversarial_support::*;

fn files_dir(proj: &Path) -> PathBuf {
    proj.join(".veil/local/sandboxes/agent/files")
}

fn project(env: &Env) -> PathBuf {
    let proj = env.project(
        "alice",
        "proj",
        &[
            ("README.md", "readme\n"),
            ("src/lib.rs", "pub fn f() {}\n"),
            ("src/util/mod.rs", "pub fn u() {}\n"),
            ("tests/t.rs", "#[test] fn t() {}\n"),
            ("docs/guide.md", "guide\n"),
            ("secret/.env.plan", "the plan\n"),
        ],
    );
    let policy = std::fs::read_to_string(proj.join(".veilpolicy")).unwrap();
    write(&proj, ".veilpolicy", &format!("{policy}secret/.env.plan cloak team\n"));
    write(&proj, ".netrc", "API_TOKEN=super-secret-isolated-value\n");
    env.ok("alice", &proj, &["commit", "-m", "base"]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "@-"]);
    proj
}

fn exec(env: &Env, proj: &Path, args: &[&str]) -> String {
    let mut all = vec!["ws", "exec", "agent"];
    all.extend_from_slice(args);
    env.ok("alice", proj, &all)
}

/// `vl files -r REV` as `(tier, path)`.
fn files(env: &Env, proj: &Path, rev: &str) -> Vec<(String, String)> {
    env.stdout("alice", proj, &["files", "-r", rev])
        .lines()
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            Some((t.first()?.to_string(), t.last()?.to_string()))
        })
        .collect()
}

fn paths(env: &Env, proj: &Path, rev: &str) -> Vec<String> {
    files(env, proj, rev).into_iter().map(|(_, p)| p).collect()
}

fn on_disk(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = walk(dir).iter().map(|p| p.strip_prefix(dir).unwrap().to_str().unwrap().to_string()).collect();
    out.sort();
    out
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if e.file_type().unwrap().is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

fn ino(p: &Path) -> u64 {
    std::fs::metadata(p).unwrap().ino()
}

#[test]
fn a_sparse_sandbox_holds_only_its_paths_and_records_only_edits_inside_them() {
    let env = Env::new();
    let proj = project(&env);
    let all_before = files(&env, &proj, "agent@");
    let out = exec(
        &env,
        &proj,
        &[
            "--only",
            "src/",
            "tests/t.rs",
            "-m",
            "sparse work",
            "--",
            "sh",
            "-c",
            "find . -type f | LC_ALL=C sort; echo 'pub fn g() {}' >> src/lib.rs; echo n > src/new.rs; rm src/util/mod.rs; rm tests/t.rs; \
             echo hacked > README.md; mkdir -p docs && echo x > docs/extra.md; echo n > notes.txt; mkdir -p target && echo o > target/out.o",
        ],
    );
    let listed: Vec<&str> = out.lines().filter(|l| l.starts_with("./")).collect();
    assert_eq!(listed, ["./.veilpolicy", "./src/lib.rs", "./src/util/mod.rs", "./tests/t.rs"], "{out}");
    assert!(out.contains("sparse: sandbox holds src, tests/t.rs"), "{out}");
    assert!(
        out.contains("not recorded: 3 file(s) written outside --only src, tests/t.rs (removed from the sandbox): README.md, docs/extra.md, notes.txt"),
        "{out}"
    );
    // Inside: the edit, the new file and both deletions. Outside: exactly
    // as before, cloaked files included.
    let now = files(&env, &proj, "agent@");
    let mut want: Vec<(String, String)> = all_before
        .iter()
        .filter(|(_, p)| p != "src/util/mod.rs" && p != "tests/t.rs")
        .cloned()
        .collect();
    want.push(("public".into(), "src/new.rs".into()));
    want.sort_by(|a, b| a.1.cmp(&b.1));
    assert_eq!(now, want);
    assert!(now.contains(&("cloaked:team".into(), "secret/.env.plan".into())), "{now:?}");
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "README.md"]), "readme\n");
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "src/lib.rs"]), "pub fn f() {}\npub fn g() {}\n");
    // The strays are gone from the sandbox; ignored build output stays.
    assert_eq!(on_disk(&files_dir(&proj)), [".veilpolicy", "src/lib.rs", "src/new.rs", "target/out.o"]);
    let log = env.stdout("alice", &proj, &["log", "-n", "5"]);
    assert!(log.contains("sparse work"), "{log}");
}

#[test]
fn a_different_set_changes_the_sandbox_incrementally() {
    let env = Env::new();
    let proj = project(&env);
    let dir = files_dir(&proj);
    exec(&env, &proj, &["--only", "src", "--", "sh", "-c", "mkdir -p target && echo o > target/o"]);
    let lib = ino(&dir.join("src/lib.rs"));
    // Widen: only tests is written, src is left alone.
    let out = exec(&env, &proj, &["--only", "src", "tests", "--", "true"]);
    assert!(out.contains("synced sandbox: 1 files written, 0 removed"), "{out}");
    assert_eq!(ino(&dir.join("src/lib.rs")), lib);
    // The same set again: nothing to do, nothing said.
    let out = exec(&env, &proj, &["--only", "tests", "src/", "--", "true"]);
    assert!(!out.contains("synced") && !out.contains("sparse:"), "{out}");
    // The whole tree.
    let out = exec(&env, &proj, &["--", "true"]);
    assert!(out.contains("sparse: sandbox holds the whole tree"), "{out}");
    assert!(dir.join("docs/guide.md").exists() && dir.join("secret/.env.plan").exists());
    assert_eq!(ino(&dir.join("src/lib.rs")), lib);
    // Narrow to one file: everything else goes, build output stays.
    let out = exec(&env, &proj, &["--only", "docs/guide.md", "--", "true"]);
    assert!(out.contains("0 files written, 5 removed"), "{out}");
    assert_eq!(on_disk(&dir), [".veilpolicy", "docs/guide.md", "target/o"]);
    // Nothing was recorded by any of it.
    assert_eq!(paths(&env, &proj, "agent@"), paths(&env, &proj, "@-"));
}

#[test]
fn only_paths_follow_the_cli_path_rules() {
    let env = Env::new();
    let proj = project(&env);
    let err = |args: &[&str], cwd: &Path| {
        let mut all = vec!["ws", "exec", "agent", "--only"];
        all.extend_from_slice(args);
        all.extend_from_slice(&["--", "true"]);
        let o = env.vl("alice", cwd, &all);
        assert!(!o.status.success(), "{args:?} was accepted: {}", text(&o));
        text(&o)
    };
    assert!(err(&["nope"], &proj).contains("there is no file or directory nope in workspace 'agent'"));
    assert!(err(&["src", "../elsewhere"], &proj).contains("escapes the repository"));
    assert!(err(&["/etc"], &proj).contains("escapes the repository"));
    // A nested repository is never part of the tree.
    let nested = proj.join("vendor/inner");
    std::fs::create_dir_all(&nested).unwrap();
    env.ok("alice", &nested, &["init"]);
    write(&nested, "x.txt", "x\n");
    env.ok("alice", &proj, &["status"]);
    assert!(err(&["vendor/inner"], &proj).contains("no file or directory vendor/inner"));
    // Nothing was created by a refused run.
    assert!(!proj.join(".veil/local/sandboxes/agent/manifest.json").exists());
    // Relative to the current directory; an absolute path inside the
    // repository is fine; overlapping paths are fine.
    let sub = proj.join("src");
    let abs = proj.join("tests");
    let out = env.ok(
        "alice",
        &sub,
        &["ws", "exec", "agent", "--only", "util", ".", abs.to_str().unwrap(), "lib.rs", "--", "sh", "-c", "find . -type f | LC_ALL=C sort"],
    );
    assert!(out.contains("sparse: sandbox holds src, tests"), "{out}");
    // The repository's root is the whole tree.
    let out = env.ok("alice", &sub, &["ws", "exec", "agent", "--only", "..", "--", "true"]);
    assert!(out.contains("sandbox holds the whole tree"), "{out}");
}

#[test]
fn a_policy_edit_in_a_sparse_run_reclassifies_files_outside_it() {
    let env = Env::new();
    let proj = project(&env);
    exec(&env, &proj, &["--only", "src", "--", "sh", "-c", "echo 'docs/ isolate' >> .veilpolicy"]);
    let now = files(&env, &proj, "agent@");
    assert!(!now.iter().any(|(_, p)| p == "docs/guide.md"), "{now:?}");
    assert!(now.contains(&("cloaked:team".into(), "secret/.env.plan".into())), "{now:?}");
    assert_eq!(now.len(), 6, "{now:?}");
}

#[test]
fn isolated_files_are_injected_everywhere_and_copies_outside_are_not_recorded() {
    let env = Env::new();
    let proj = project(&env);
    let dir = files_dir(&proj);
    let out = exec(
        &env,
        &proj,
        &["--only", "src", "--with-isolated", "--", "sh", "-c", "cat .netrc; cp .netrc leak.txt; cp .netrc src/leak.rs; echo ok > src/ok.rs"],
    );
    assert!(out.contains("super-secret-isolated-value"), "the root .netrc was injected: {out}");
    assert!(out.contains("leak.txt") && out.contains("not recorded"), "{out}");
    let p = paths(&env, &proj, "agent@");
    assert!(p.contains(&"src/ok.rs".to_string()) && !p.iter().any(|p| p.contains("leak") || p == ".netrc"), "{p:?}");
    let all = String::from_utf8_lossy(
        &std::process::Command::new("grep")
            .arg("-r")
            .arg("super-secret")
            .arg(proj.join(".veil/local/sandboxes"))
            .output()
            .unwrap()
            .stdout,
    )
    .into_owned();
    assert!(all.is_empty(), "secret left under the sandbox: {all}");
    assert_eq!(on_disk(&dir), [".veilpolicy", "src/lib.rs", "src/ok.rs", "src/util/mod.rs"]);
}

#[test]
fn a_workspace_moved_during_a_sparse_run_keeps_both_results_and_everything_else() {
    let env = Env::new();
    let proj = project(&env);
    exec(&env, &proj, &["--only", "src", "--", "true"]);
    let started = files_dir(&proj).join(".started");
    let script = "touch .started; sleep 2; echo run > src/run.rs";
    let child = env.spawn("alice", &proj, &["ws", "exec", "agent", "--only", "src", "-m", "agent run", "--", "sh", "-c", script]);
    assert!(wait_for(Duration::from_secs(20), || started.exists()));
    let _ = std::fs::remove_file(&started);
    let mut w = env
        .cmd("alice", &proj, &["ws", "write", "agent", "docs/meanwhile.md"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    w.stdin.take().unwrap().write_all(b"m\n").unwrap();
    assert!(w.wait_with_output().unwrap().status.success());
    let out = child.wait_with_output().unwrap();
    let t = text(&out);
    assert!(out.status.success() && t.contains("moved while the command ran"), "{t}");
    let p = paths(&env, &proj, "agent@");
    assert!(p.contains(&"docs/meanwhile.md".to_string()) && !p.contains(&"src/run.rs".to_string()), "{p:?}");
    let id = t
        .lines()
        .find_map(|l| l.strip_prefix("Saved "))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("{t}"))
        .to_string();
    // The saved change is the start plus the run: nothing outside src lost.
    let saved = paths(&env, &proj, &id);
    let mut want = paths(&env, &proj, "@-");
    want.push("src/run.rs".into());
    want.sort();
    assert_eq!(saved, want);
    // The next run is in the workspace again.
    let o = exec(&env, &proj, &["--only", "src", "docs", "--", "sh", "-c", "find . -type f | LC_ALL=C sort"]);
    assert!(o.contains("docs/meanwhile.md") && !o.contains("run.rs"), "{o}");
}

#[test]
fn ephemeral_runs_can_be_sparse() {
    let env = Env::new();
    let proj = project(&env);
    let out = env.ok(
        "alice",
        &proj,
        &["ws", "exec", "--ephemeral", "-r", "@-", "--only", "docs", "--", "sh", "-c", "find . -type f | LC_ALL=C sort; echo more >> docs/guide.md; echo x > top.txt"],
    );
    let listed: Vec<&str> = out.lines().filter(|l| l.starts_with("./")).collect();
    assert_eq!(listed, ["./.veilpolicy", "./docs/guide.md"], "{out}");
    assert!(out.contains("not recorded: 1 file(s) written outside --only docs: top.txt"), "{out}");
    let id = out
        .lines()
        .find_map(|l| l.strip_prefix("Recorded "))
        .and_then(|l| l.split_whitespace().next())
        .unwrap()
        .to_string();
    assert_eq!(paths(&env, &proj, &id), paths(&env, &proj, "@-"));
    assert_eq!(env.stdout("alice", &proj, &["cat", "-r", &id, "docs/guide.md"]), "guide\nmore\n");
    let o = env.vl("alice", &proj, &["ws", "exec", "--ephemeral", "--only", "missing", "--", "true"]);
    assert!(!o.status.success() && text(&o).contains("no file or directory missing"), "{}", text(&o));
}

#[test]
fn quarantined_work_outside_a_narrower_set_is_kept_and_guarded() {
    let env = Env::new();
    let proj = project(&env);
    env.quarantined("alice", &proj, &["ws", "exec", "agent", "--", "sh", "-c", "echo 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' > docs/creds.txt"]);
    let dir = files_dir(&proj);
    assert!(dir.join("docs/creds.txt").exists());
    exec(&env, &proj, &["--only", "src", "--", "true"]);
    assert!(dir.join("docs/creds.txt").exists(), "quarantined work was removed");
    let o = env.vl("alice", &proj, &["ws", "rm", "agent"]);
    assert!(!o.status.success() && text(&o).contains("docs/creds.txt"), "{}", text(&o));
    // Back to the whole tree: still quarantined (exit 3), still there.
    env.quarantined("alice", &proj, &["ws", "exec", "agent", "--", "true"]);
    assert!(dir.join("docs/creds.txt").exists());
    assert!(!paths(&env, &proj, "agent@").contains(&"docs/creds.txt".to_string()));
}

#[test]
fn a_hand_edit_a_narrower_set_leaves_outside_is_kept_until_a_run_records_it() {
    let env = Env::new();
    let proj = project(&env);
    let dir = files_dir(&proj);
    exec(&env, &proj, &["--", "true"]);
    // Edited by hand between runs, then the set narrows past it.
    write(&dir, "docs/guide.md", "edited by hand\n");
    write(&dir, "docs/mine.md", "mine\n");
    let out = exec(&env, &proj, &["--only", "src", "--", "sh", "-c", "echo x > stray.txt"]);
    assert!(out.contains("not recorded: 1 file(s) written outside --only src (removed from the sandbox): stray.txt"), "{out}");
    assert!(out.contains("that the command did not write (kept") && out.contains("docs/guide.md, docs/mine.md"), "{out}");
    assert_eq!(read(&dir, "docs/guide.md"), "edited by hand\n");
    assert!(!dir.join("stray.txt").exists());
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "docs/guide.md"]), "guide\n");
    // A run whose paths hold them records them.
    exec(&env, &proj, &["--only", "docs", "--", "true"]);
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "docs/guide.md"]), "edited by hand\n");
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "docs/mine.md"]), "mine\n");
}
