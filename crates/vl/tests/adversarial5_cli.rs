//! Round-5 adversarial tests through the real `vl` binary.
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the secure behaviour and
//! currently fails; see `docs/BUGS.md` ("Round 5 findings").

mod adversarial_support;

use std::{
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

use adversarial_support::{text, write, Env};

const U: &str = "alice";

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Mallory")
        .env("GIT_AUTHOR_EMAIL", "mallory@example.com")
        .env("GIT_COMMITTER_NAME", "Mallory")
        .env("GIT_COMMITTER_EMAIL", "mallory@example.com")
        .args(["-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false"])
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A "GitHub" repository with one commit on `main`, imported into a fresh
/// Veil project; then a contributor pushes branch `contrib` adding
/// `fixtures/data.txt` with `content`. Returns how long `vl git fetch`
/// took, or `None` if it was still running after `limit` (it is killed).
fn fetch_time_with_file(content: &str, limit: Duration) -> Option<Duration> {
    let env = Env::new();
    let gh = env.dir("github");
    git(&gh, &["init", "-q"]);
    write(&gh, "README.md", "# project\n");
    git(&gh, &["add", "."]);
    git(&gh, &["commit", "-q", "-m", "initial"]);
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    env.ok(U, &proj, &["git", "import", gh.to_str().unwrap()]);

    git(&gh, &["checkout", "-q", "-b", "contrib"]);
    write(&gh, "fixtures/data.txt", content);
    git(&gh, &["add", "."]);
    git(&gh, &["commit", "-q", "-m", "add test fixture"]);

    let started = Instant::now();
    let mut child = env.spawn(U, &proj, &["git", "fetch"]);
    while started.elapsed() < limit {
        if let Some(status) = child.try_wait().unwrap() {
            let out = child.wait_with_output().unwrap();
            assert!(status.success(), "vl git fetch failed: {}", text(&out));
            return Some(started.elapsed());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// Control: a 128 KiB fixture of ordinary text is fetched in moments.
#[test]
fn fetching_a_branch_with_an_ordinary_fixture_is_quick() {
    let content = "token = compute(x)\n".repeat((128 << 10) / 19);
    assert!(fetch_time_with_file(&content, Duration::from_secs(30)).is_some());
}

/// BUG-090 through the Git bridge: every file a Git commit adds is
/// secret-scanned on import (the commit goes through the builder's policy
/// gate), so anyone who can push a branch to the team's GitHub repository
/// can stall `vl git fetch` / `vl git pull` for every member: 128 KiB of
/// `xgithub_pat_` repeated takes minutes, 1 MiB hours. The fetch holds the
/// repository lock throughout, so every other `vl` command fails with
/// "locked" meanwhile.
#[test]
#[ignore = "BUG-090: a pushed Git branch with a crafted file stalls vl git fetch (quadratic scanner)"]
fn fetching_a_branch_with_a_crafted_fixture_is_quick() {
    let content = "xgithub_pat_".repeat((128 << 10) / 12);
    let took = fetch_time_with_file(&content, Duration::from_secs(30));
    assert!(took.is_some(), "vl git fetch was still running after 30 s (killed)");
}
