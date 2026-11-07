//! Reproductions of CLI findings from the scale benchmark's baseline
//! (`docs/design/scale/BASELINE.md`, BUG-800 to BUG-809). Ignored until
//! fixed: each fails today.

use std::{
    path::Path,
    process::{Command, Stdio},
};

fn vl(home: &Path, cwd: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_vl"));
    c.env("VEIL_TEST_PATH_REMOTES", "1").args(args)
        .current_dir(cwd)
        .env("VEIL_HOME", home)
        .env("VEIL_USER", "bench")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    c
}

/// BUG-801: concurrent commands fail instead of queueing. Every `vl`
/// command records the working copy first, and holds `.veil/lock` while it
/// scans the whole project directory (`Repo::snapshot_workspace_with` opens
/// its transaction before `build_tree_cached`). A contender gives up after
/// 15 s (`LockOptions::default().wait`), so once enough commands queue up
/// (agents in their own workspaces, editors, `vl watch`) they fail with
/// "repository is locked". The baseline's 64-agent profile on the 1 GB
/// repository failed 194 of 640 iterations this way.
#[test]
fn many_concurrent_commands_all_succeed() {
    const FILES: usize = 20_000;
    const PROCS: usize = 64;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let repo = tmp.path().join("repo");
    for i in 0..FILES {
        let d = repo.join(format!("src/m{:03}", i % 200));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(format!("f{i}.rs")), format!("pub fn f{i}() -> u64 {{ {i} }}\n")).unwrap();
    }
    assert!(vl(&home, &repo, &["init"]).status().unwrap().success());
    // Read-only in intent: each still records (a clean) working copy.
    let children: Vec<_> = (0..PROCS).map(|_| vl(&home, &repo, &["status"]).spawn().unwrap()).collect();
    let mut failed = Vec::new();
    for c in children {
        let out = c.wait_with_output().unwrap();
        if !out.status.success() {
            failed.push(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
    }
    assert!(failed.is_empty(), "{} of {PROCS} concurrent `vl status` failed, e.g. {:?}", failed.len(), failed.first());
}
