//! Records the git commit `vl` was built from, for `vl --version`.
//!
//! `VL_GIT_COMMIT` overrides it (builds from a source tarball, packagers);
//! without git or a repository it is `unknown`.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    (out.status.success() && !s.is_empty()).then(|| s.to_string())
}

fn main() {
    println!("cargo:rerun-if-env-changed=VL_GIT_COMMIT");
    let commit = std::env::var("VL_GIT_COMMIT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            let hash = git(&["rev-parse", "--short=12", "HEAD"])?;
            let dirty = git(&["status", "--porcelain", "--untracked-files=no"]).is_some();
            Some(if dirty { format!("{hash}-dirty") } else { hash })
        })
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=VL_GIT_COMMIT={commit}");
    // Rebuild when HEAD moves (works in worktrees, where .git is a file).
    for path in ["HEAD", "index"] {
        if let Some(p) = git(&["rev-parse", "--git-path", path]) {
            println!("cargo:rerun-if-changed={p}");
        }
    }
    if let Some(r) = git(&["symbolic-ref", "-q", "HEAD"]) {
        if let Some(p) = git(&["rev-parse", "--git-path", &r]) {
            println!("cargo:rerun-if-changed={p}");
        }
    }
    println!(
        "cargo:rustc-env=VL_TARGET={}",
        std::env::var("TARGET").unwrap_or_else(|_| "unknown".into())
    );
}
