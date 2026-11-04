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
    let mut bin = std::path::PathBuf::from(std::env::var_os("VEIL_GIT").unwrap_or_else(|| "git".into()));
    // `git` runs in the bridge directory (below): a relative `$VEIL_GIT`
    // path means what it means here.
    if bin.is_relative() && bin.components().count() > 1 {
        if let Ok(cwd) = std::env::current_dir() {
            bin = cwd.join(bin);
        }
    }
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
    // Never the caller's directory: nothing may depend on where `vl` runs.
    match git_dir.canonicalize() {
        Ok(abs) => {
            c.arg("--git-dir").arg(&abs).current_dir(&abs);
        }
        Err(_) => {
            c.arg("--git-dir").arg(git_dir);
        }
    }
    // Objects Veil exported may be referenced only through its mapping:
    // never let a fetch garbage-collect them.
    c.args(["-c", "gc.auto=0", "-c", "maintenance.auto=false"]);
    // A remote URL never runs a command (`ext::`, whatever the user's
    // configuration allows), and the bridge runs no hooks.
    c.args(["-c", "protocol.ext.allow=never", "-c", "protocol.fd.allow=never"]);
    c.args(["-c", "core.hooksPath=/dev/null"]);
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

/// The credentials part of `url` that must never be printed: the whole
/// `user[:password]` of an `http(s)://` URL (a token is often passed as
/// the user name), the password of any other `scheme://user:password@`.
fn secret_of(url: &str) -> Option<&str> {
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let userinfo = &rest[..rest[..end].rfind('@')?];
    let web = matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https");
    match userinfo.split_once(':') {
        _ if web => Some(userinfo),
        Some((_, password)) => Some(password),
        None => None,
    }
    .filter(|s| !s.is_empty())
}

/// `url` with any credentials it embeds (`https://user:token@host/…`)
/// replaced by `***`, for messages and listings.
pub fn redact_url(url: &str) -> String {
    redact_in(url, url)
}

/// `text` with the credentials of `url` replaced by `***` wherever they
/// occur (in `git`'s own messages too).
pub(crate) fn redact_in(text: &str, url: &str) -> String {
    match secret_of(url) {
        Some(secret) => text.replace(secret, "***"),
        None => text.to_string(),
    }
}

/// URLs are passed to `git` as arguments: refuse anything it could read as
/// an option.
pub(crate) fn validate_url(url: &str) -> Result<()> {
    if url.is_empty() || url.starts_with('-') || url.contains(['\n', '\0']) {
        return Err(VeilError::repo(format!("invalid Git URL {:?}", redact_url(url))));
    }
    Ok(())
}

/// `git`'s error output as one line, credentials redacted: the CLI shows
/// control characters escaped, so its newlines would read as a literal
/// `\n` (BUG-292).
fn git_stderr(stderr: &[u8], url: &str) -> String {
    let text = String::from_utf8_lossy(stderr);
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    redact_in(&lines.join("; "), url)
}

/// Fetch every branch of `url` into `refs/remotes/<remote>/*`, following
/// force-pushes and deletions (they are reported by the caller). With
/// `tags`, the remote's tags go to `refs/veil/tags/<remote>/*`, a namespace
/// of their own (a branch `tags/x` cannot collide with tag `x`); Git's
/// `--prune` drops the ones deleted remotely there, and a moved tag is
/// followed there too: the caller compares with what it recorded.
pub(crate) fn fetch(git_dir: &Path, url: &str, remote: &str, tags: bool) -> Result<()> {
    validate_url(url)?;
    let mut c = git(git_dir);
    c.args(["fetch", "--no-tags", "--prune", "--quiet", "--no-write-fetch-head", "--"])
        .arg(url)
        .arg(format!("+refs/heads/*:refs/remotes/{remote}/*"));
    if tags {
        c.arg(format!("+refs/tags/*:{}*", tag_tracking_prefix(remote)));
    }
    let out = run(c, "fetch")?;
    if !out.status.success() {
        return Err(VeilError::repo(format!(
            "git fetch from {} failed: {}",
            redact_url(url),
            git_stderr(&out.stderr, url)
        )));
    }
    Ok(())
}

/// Where the bridge keeps the tags last fetched from (or pushed to) Git
/// remote `remote`.
pub(crate) fn tag_tracking_prefix(remote: &str) -> String {
    format!("refs/veil/tags/{remote}/")
}

#[derive(Debug, Clone)]
pub(crate) struct PushRef {
    /// The branch name, or the tag name for a tag (`tag: true`).
    pub branch: String,
    /// `refs/tags/<branch>` rather than `refs/heads/<branch>`.
    pub tag: bool,
    /// `None` deletes the branch.
    pub commit: Option<GitOid>,
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
    Deleted,
    Rejected(String),
}

impl RefStatus {
    pub fn accepted(&self) -> bool {
        !matches!(self, RefStatus::Rejected(_))
    }
}

#[derive(Debug, Default)]
pub struct PushOutcome {
    /// Branches.
    pub refs: Vec<(String, RefStatus)>,
    /// Git tags (`refs/tags/<name>`).
    pub tags: Vec<(String, RefStatus)>,
}

/// Push each update as `<commit>:refs/heads/<branch>` in one `git push`.
pub(crate) fn push(git_dir: &Path, url: &str, updates: &[PushRef]) -> Result<PushOutcome> {
    validate_url(url)?;
    if updates.is_empty() {
        return Ok(PushOutcome::default());
    }
    let mut c = git(git_dir);
    c.args(["push", "--porcelain"]);
    // A forced update is leased (`--force-with-lease`), and so is a
    // deletion unless forced: it must not delete commits pushed since the
    // last fetch.
    let leased = |u: &&PushRef| match u.commit {
        Some(_) => u.force,
        None => !u.force,
    };
    let full = |u: &PushRef| format!("refs/{}/{}", if u.tag { "tags" } else { "heads" }, u.branch);
    for u in updates.iter().filter(leased) {
        match u.lease {
            Some(l) => c.arg(format!("--force-with-lease={}:{l}", full(u))),
            None => c.arg(format!("--force-with-lease={}:", full(u))),
        };
    }
    c.arg("--").arg(url);
    // Never a `+` refspec: a forced update goes through its lease only.
    for u in updates {
        match u.commit {
            Some(commit) => c.arg(format!("{commit}:{}", full(u))),
            None => c.arg(format!(":{}", full(u))),
        };
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
        let Some(to) = refs.split_once(':').map(|(_, to)| to) else { continue };
        let (branch, tag) = match (to.strip_prefix("refs/heads/"), to.strip_prefix("refs/tags/")) {
            (Some(b), _) => (b, false),
            (_, Some(t)) => (t, true),
            _ => continue,
        };
        let summary = redact_in(summary.unwrap_or("").trim(), url);
        let status = match flag {
            "*" => RefStatus::Created,
            " " => RefStatus::FastForward,
            "+" => RefStatus::Forced,
            "=" => RefStatus::UpToDate,
            "-" => RefStatus::Deleted,
            _ if tag && summary.contains("already exists") => RefStatus::Rejected("tag exists with another target".into()),
            _ => RefStatus::Rejected(if summary.is_empty() { "rejected".into() } else { summary }),
        };
        match tag {
            true => outcome.tags.push((branch.to_string(), status)),
            false => outcome.refs.push((branch.to_string(), status)),
        }
    }
    if outcome.refs.is_empty() && outcome.tags.is_empty() && !out.status.success() {
        return Err(VeilError::repo(format!(
            "git push to {} failed: {}",
            redact_url(url),
            git_stderr(&out.stderr, url)
        )));
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_redacted() {
        assert_eq!(redact_url("https://bob:ghp_x@h:9/x.git"), "https://***@h:9/x.git");
        assert_eq!(redact_url("https://ghp_x@github.com/o/r"), "https://***@github.com/o/r");
        assert_eq!(redact_url("ssh://git:pw@host/r"), "ssh://git:***@host/r");
        assert_eq!(redact_url("ssh://git@host/r"), "ssh://git@host/r");
        assert_eq!(redact_url("git@github.com:o/r.git"), "git@github.com:o/r.git");
        assert_eq!(redact_url("https://host/a@b"), "https://host/a@b");
        assert_eq!(
            redact_in("fatal: could not reach https://bob:ghp_x@h/", "https://bob:ghp_x@h/"),
            "fatal: could not reach https://***@h/"
        );
    }
}
