//! Network transport: the system `git` binary.
//!
//! `gix` has no push, and `git2`/libgit2 would bring its own credential and
//! SSH stack. Running `git` (as Jujutsu does) reuses exactly what the user
//! already set up: credential helpers (osxkeychain, libsecret, `gh auth`),
//! `~/.ssh/config`, the SSH agent, `insteadOf` rules, proxies. Only the
//! bridge repository is passed with `--git-dir`; refspecs are explicit, so
//! nothing depends on remotes configured in Git itself.

use std::{
    path::Path,
    process::{Command, Stdio},
};

use super::map::GitOid;
use crate::error::{Result, VeilError};

fn git(git_dir: &Path) -> Command {
    let bin = std::env::var_os("VEIL_GIT").unwrap_or_else(|| "git".into());
    let mut c = Command::new(bin);
    // Variables that would point git at another repository.
    for v in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
        "GIT_COMMON_DIR",
    ] {
        c.env_remove(v);
    }
    c.arg("--git-dir").arg(git_dir);
    // Objects Veil exported may be referenced only through its mapping:
    // never let a fetch garbage-collect them.
    c.args(["-c", "gc.auto=0", "-c", "maintenance.auto=false"]);
    c.stdin(Stdio::inherit());
    c
}

fn run(mut c: Command, what: &str) -> Result<std::process::Output> {
    c.stdout(Stdio::piped()).stderr(Stdio::piped());
    c.output().map_err(|e| {
        VeilError::repo(format!(
            "could not run git for {what}: {e} (is git installed? set VEIL_GIT to its path)"
        ))
    })
}

/// URLs are passed to `git` as arguments: refuse anything it could read as
/// an option.
pub(crate) fn validate_url(url: &str) -> Result<()> {
    if url.is_empty() || url.starts_with('-') || url.contains(['\n', '\0']) {
        return Err(VeilError::repo(format!("invalid Git URL {url:?}")));
    }
    Ok(())
}

/// Fetch every branch of `url` into `refs/remotes/<remote>/*`, following
/// force-pushes and deletions (they are reported by the caller).
pub(crate) fn fetch(git_dir: &Path, url: &str, remote: &str) -> Result<()> {
    validate_url(url)?;
    let mut c = git(git_dir);
    c.args(["fetch", "--no-tags", "--prune", "--quiet", "--no-write-fetch-head", "--"])
        .arg(url)
        .arg(format!("+refs/heads/*:refs/remotes/{remote}/*"));
    let out = run(c, "fetch")?;
    if !out.status.success() {
        return Err(VeilError::repo(format!(
            "git fetch from {url} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct PushRef {
    pub branch: String,
    pub commit: GitOid,
    pub force: bool,
    /// What we last saw on the remote (for `--force-with-lease`).
    pub lease: Option<GitOid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefStatus {
    Created,
    FastForward,
    Forced,
    UpToDate,
    Rejected(String),
}

impl RefStatus {
    pub fn accepted(&self) -> bool {
        !matches!(self, RefStatus::Rejected(_))
    }
}

#[derive(Debug, Default)]
pub struct PushOutcome {
    pub refs: Vec<(String, RefStatus)>,
}

/// Push each update as `<commit>:refs/heads/<branch>` in one `git push`.
pub(crate) fn push(git_dir: &Path, url: &str, updates: &[PushRef]) -> Result<PushOutcome> {
    validate_url(url)?;
    if updates.is_empty() {
        return Ok(PushOutcome::default());
    }
    let mut c = git(git_dir);
    c.args(["push", "--porcelain"]);
    for u in updates.iter().filter(|u| u.force) {
        match u.lease {
            Some(l) => c.arg(format!("--force-with-lease=refs/heads/{}:{l}", u.branch)),
            None => c.arg(format!("--force-with-lease=refs/heads/{}:", u.branch)),
        };
    }
    c.arg("--").arg(url);
    for u in updates {
        c.arg(format!("{}:refs/heads/{}", u.commit, u.branch));
    }
    let out = run(c, "push")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut outcome = PushOutcome::default();
    for line in stdout.lines() {
        // <flag> \t <from>:<to> \t <summary>
        let mut parts = line.splitn(3, '\t');
        let (Some(flag), Some(refs), summary) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let Some(branch) = refs.split_once(':').and_then(|(_, to)| to.strip_prefix("refs/heads/")) else {
            continue;
        };
        let summary = summary.unwrap_or("").trim().to_string();
        let status = match flag {
            "*" => RefStatus::Created,
            " " => RefStatus::FastForward,
            "+" => RefStatus::Forced,
            "=" => RefStatus::UpToDate,
            _ => RefStatus::Rejected(if summary.is_empty() { "rejected".into() } else { summary }),
        };
        outcome.refs.push((branch.to_string(), status));
    }
    if outcome.refs.is_empty() && !out.status.success() {
        return Err(VeilError::repo(format!(
            "git push to {url} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(outcome)
}
