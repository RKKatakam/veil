//! Round-9 adversarial tests (Opus) of colocated Git mode, through the real
//! `vl` and `git` binaries. Each test builds a scratch repository in its
//! temporary directory, reproduces one finding and asserts the safe
//! outcome. Every `#[ignore = "BUG-NNN: …"]` test fails today; see
//! `docs/BUGS.md` ("Round 9 findings"). Tests without `ignore` are
//! controls. Every test skips when `git` is not installed.

#![allow(dead_code)]

#[path = "../colocated_support/mod.rs"]
mod colocated_support;

use std::path::{Path, PathBuf};

pub use colocated_support::*;

mod policy_injection;
mod hookspath;
mod bundle;
mod branches;
mod switch_race;
mod stash;
mod clean;
mod adopt;
mod uncolocate;
mod prune;
mod gitignore_negation;
mod dot_veil_file;

/// Is `git` installed? Every test returns early without it.
pub fn have_git() -> bool {
    std::process::Command::new("git").arg("--version").output().is_ok_and(|o| o.status.success())
}

#[macro_export]
macro_rules! need_git {
    () => {
        if !$crate::have_git() {
            eprintln!("skipped: git is not installed");
            return;
        }
    };
}

/// Switch `dir` to a new workspace `c` cloaked for `team`, on `main`.
pub fn cloaked_ws(env: &Env, dir: &Path) {
    env.ok(dir, &["ws", "new", "c", "-r", "main", "--cloak", "team"]);
    env.ok(dir, &["ws", "switch", "c"]);
}

/// A bare Git remote for `dir`'s `main` (Git's `origin`, tracked; Veil's
/// `gh`) and a second clone of it, standing for an upstream contributor.
pub fn upstream(env: &Env, dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let remote = env.bare(&format!("{name}-remote.git"));
    let r = remote.to_str().unwrap();
    env.git_ok(dir, &["remote", "add", "origin", r]);
    env.git_ok(dir, &["push", "-q", "-u", "origin", "main"]);
    env.ok(dir, &["git", "remote", "add", "gh", r]);
    let other = env.root.join(format!("{name}-contributor"));
    env.git_ok(&env.root, &["clone", "-q", r, other.to_str().unwrap()]);
    (remote, other)
}

/// The contributor commits `files` (path, content) and pushes `main`.
pub fn contributor_pushes(env: &Env, clone: &Path, files: &[(&str, &str)]) {
    for (p, t) in files {
        env.write(clone, p, t);
        env.git_ok(clone, &["add", "-f", p]);
    }
    env.git_ok(clone, &["commit", "-q", "-m", "contribution"]);
    env.git_ok(clone, &["push", "-q", "origin", "main"]);
}
