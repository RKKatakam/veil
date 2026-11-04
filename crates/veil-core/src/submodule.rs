//! Submodules (Git gitlinks, repository format 5): `.gitmodules` parsing,
//! name, path and URL validation, and the system-`git` runner behind `vl
//! submodule` (feature 5b of the Git-parity round,
//! `docs/design/git-parity/5-hooks-submodules-signed-tags.md`).
//!
//! # Model
//!
//! A gitlink tree entry pins a commit of another Git repository at a path
//! (`EntryKind::Gitlink`, its blob `"<hex commit>\n"`). Veil never records
//! anything below it, never reads the inner `.git` to follow its `HEAD`
//! (the pin changes only with [`set_pin`] or a Git import), and never
//! updates a submodule on its own (not on pull, not on checkout).
//!
//! # Code execution
//!
//! A `.gitmodules` file arrives with a teammate's push or a Git import:
//! hostile input. Its URLs and names have been Git's own code-execution
//! bugs (CVE-2017-1000117 option-like URLs, CVE-2018-11235 `../` names
//! writing hooks into `.git/modules`, `ext::` helpers). Here:
//!
//! * only `path` and `url` are read: `update = !command`, `branch` and
//!   every other key are ignored;
//! * a URL must be `https://`, `ssh://`, `git://` or scp-like
//!   `host:path` with a host that cannot read as an option; local paths
//!   and `file://` only with `allow_local`; `ext::`, `fd::` and every
//!   other `<helper>::` form, `http://`, option-like values and control
//!   characters are refused ([`validate_url`]);
//! * `git` also gets `GIT_ALLOW_PROTOCOL` with the same allowlist and
//!   `protocol.file.allow=never` (unless `allow_local`), so its own
//!   redirects and nested lookups cannot widen it, and runs with hooks
//!   disabled, `--` before the URL, and never `--recurse-submodules`;
//! * the name is checked as Git's `check_submodule_name` does (no `..`
//!   component) and only ever used hashed: the clone's Git directory is
//!   `.veil/local/submodules/<hash of the name>/`, never `.git/modules`;
//! * the path must be a gitlink of the tree, inside the working copy,
//!   reached through no symlink, and never `.git` or `.veil`.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Object, Snapshot, TreeEntry, Visibility},
    repo::Repo,
    store::ObjectStore,
    vpath::VPath,
};

/// The file naming each submodule's URL.
pub const GITMODULES: &str = ".gitmodules";

/// Largest `.gitmodules` read.
const MAX_GITMODULES: usize = 1 << 20;

/// One `[submodule "name"]` section of `.gitmodules`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submodule {
    pub name: String,
    /// The `path` value (unvalidated; see [`validate_path`]).
    pub path: Option<String>,
    /// The `url` value (unvalidated; see [`validate_url`]).
    pub url: Option<String>,
}

fn io_err(path: &Path, source: std::io::Error) -> VeilError {
    VeilError::Io {
        path: path.display().to_string(),
        source,
    }
}

fn sm_err(m: impl Into<String>) -> VeilError {
    VeilError::Policy(m.into())
}

/// Parse `.gitmodules` with gix's configuration parser (no includes are
/// followed). Only `path` and `url` are read.
pub fn parse_gitmodules(data: &[u8]) -> Result<Vec<Submodule>> {
    if data.len() > MAX_GITMODULES {
        return Err(sm_err(format!("{GITMODULES} is over {MAX_GITMODULES} bytes")));
    }
    let file = gix::config::File::from_bytes_no_includes(
        data,
        gix::config::file::Metadata::api(),
        gix::config::file::init::Options::default(),
    )
    .map_err(|e| sm_err(format!("{GITMODULES} cannot be parsed: {e}")))?;
    let mut out: Vec<Submodule> = Vec::new();
    let Some(sections) = file.sections_by_name("submodule") else {
        return Ok(out);
    };
    for s in sections {
        let Some(name) = s.header().subsection_name() else { continue };
        let name = String::from_utf8_lossy(name).into_owned();
        let get = |k: &str| s.value(k).map(|v| String::from_utf8_lossy(&v).into_owned());
        let (path, url) = (get("path"), get("url"));
        // Git: a later section of the same name extends the earlier one.
        match out.iter_mut().find(|x| x.name == name) {
            Some(x) => {
                x.path = path.or(x.path.take());
                x.url = url.or(x.url.take());
            }
            None => out.push(Submodule { name, path, url }),
        }
    }
    Ok(out)
}

/// Git's `check_submodule_name`: non-empty, no `..` component (with `/` or
/// `\` as separators). Control characters are refused too (names are
/// printed).
pub fn validate_name(name: &str) -> Result<()> {
    if gix::validate::submodule::name(name.as_bytes().into()).is_err() || name.chars().any(char::is_control) {
        return Err(sm_err(format!(
            "submodule name {:?} is refused: empty, a '..' component, or control characters",
            name.escape_debug().to_string()
        )));
    }
    Ok(())
}

/// A submodule path: a valid repository path, not the root, with no
/// component that is a spelling of `.git` or `.veil`.
pub fn validate_path(path: &str) -> Result<VPath> {
    if path.starts_with('/') || path.contains('\\') {
        return Err(sm_err(format!("submodule path {path:?} must be relative to the project root")));
    }
    let p = VPath::new(path.trim_end_matches('/')).map_err(|_| sm_err(format!("submodule path {path:?} is not a valid path")))?;
    if p.is_root() {
        return Err(sm_err("a submodule cannot be the project root"));
    }
    for c in p.components() {
        if crate::policy::vcs_metadata_name(c).is_some() || crate::object::is_reserved_name(c) {
            return Err(sm_err(format!("submodule path {path:?} goes through {c:?}")));
        }
    }
    Ok(p)
}

/// Is `url` a local path for `git` (no `scheme://`, no scp-style
/// `host:`)?
fn is_local(url: &str) -> bool {
    if url.contains("://") {
        return false;
    }
    match url.find(':') {
        Some(colon) => url.find('/').is_some_and(|slash| slash < colon),
        None => true,
    }
}

/// Is `url` relative to the superproject's remote (`./x`, `../x`)?
pub fn is_relative(url: &str) -> bool {
    url.starts_with("./") || url.starts_with("../")
}

/// Check a submodule URL before it reaches `git` (see the module docs).
pub fn validate_url(url: &str, allow_local: bool) -> Result<()> {
    let shown = crate::git::redact_url(url).escape_debug().to_string();
    let refuse = |why: &str| Err(sm_err(format!("submodule URL \"{shown}\" is refused: {why}")));
    if url.is_empty() {
        return refuse("it is empty");
    }
    if url.starts_with('-') {
        return refuse("it reads as a command-line option");
    }
    if url.chars().any(|c| c.is_control()) {
        return refuse("it holds control characters");
    }
    if let Some((scheme, rest)) = url.split_once("://") {
        if scheme.contains("::") {
            return refuse("remote helpers (`<helper>::…`) are never run");
        }
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
        return match scheme.to_ascii_lowercase().as_str() {
            "https" | "ssh" | "git" | "git+ssh" | "ssh+git" => {
                if host.is_empty() || host.starts_with('-') {
                    refuse("its host is empty or reads as an option")
                } else {
                    Ok(())
                }
            }
            "file" if allow_local => Ok(()),
            "file" => refuse("local repositories need --allow-local"),
            "http" => refuse("plain http is not allowed (use https)"),
            _ => refuse("only https, ssh and git URLs are allowed"),
        };
    }
    if url.contains("::") {
        return refuse("remote helpers (`<helper>::…`) are never run");
    }
    if is_local(url) {
        return match allow_local {
            true => Ok(()),
            false => refuse("local repositories need --allow-local"),
        };
    }
    // scp-like `[user@]host:path`.
    let host = url.split(':').next().unwrap_or("");
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    if host.is_empty() || host.starts_with('-') {
        return refuse("its host is empty or reads as an option");
    }
    Ok(())
}

/// Resolve a relative submodule URL (`../lib.git`) against the
/// superproject's remote URL `base`, as Git does.
pub fn resolve_relative(url: &str, base: &str) -> Option<String> {
    let mut base = base.trim_end_matches('/').to_string();
    // Never cut into `scheme://host`.
    let floor = base.find("://").map_or(0, |i| i + 3);
    let mut rest = url;
    loop {
        if let Some(r) = rest.strip_prefix("./") {
            rest = r;
        } else if let Some(r) = rest.strip_prefix("../") {
            rest = r;
            let cut = base.rfind(['/', ':']).filter(|c| *c >= floor)?;
            if base.as_bytes()[cut] == b':' {
                // scp-like `host:path`: up to the host.
                base.truncate(cut + 1);
            } else {
                base.truncate(cut);
            }
        } else {
            break;
        }
    }
    if base.len() <= floor {
        return None;
    }
    if base.ends_with(':') {
        return Some(format!("{base}{rest}"));
    }
    Some(format!("{base}/{rest}"))
}

/// A pinned commit: what a gitlink's content `"<hex>\n"` names.
pub fn parse_pin(data: &[u8]) -> Option<String> {
    let hex = data.strip_suffix(b"\n")?;
    if !matches!(hex.len(), 40 | 64) || !hex.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    Some(String::from_utf8(hex.to_vec()).unwrap())
}

/// A commit id as `vl submodule set` takes it: 40 or 64 hex digits
/// (lowercased).
pub fn parse_commit_arg(s: &str) -> Result<String> {
    let s = s.trim().to_ascii_lowercase();
    if !matches!(s.len(), 40 | 64) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(sm_err(format!(
            "{:?} is not a full Git commit id (40 hex digits)",
            s.escape_debug().to_string()
        )));
    }
    Ok(s)
}

/// A gitlink of a tree.
#[derive(Clone, Debug)]
pub struct Gitlink {
    pub path: VPath,
    pub entry: TreeEntry,
    /// The pinned commit, `None` if this reader cannot open it (sealed for
    /// a scope it is not in) or it is malformed.
    pub commit: Option<String>,
}

/// Every gitlink of tree `tree`, in path order.
pub fn gitlinks(store: &ObjectStore, tree: &ObjectId) -> Result<Vec<Gitlink>> {
    let mut out = Vec::new();
    let mut stack = vec![(VPath::root(), *tree, 0usize)];
    while let Some((dir, id, depth)) = stack.pop() {
        if depth > crate::tree::MAX_TREE_DEPTH {
            continue;
        }
        let t = match store.tree(&id) {
            Ok(t) => t,
            Err(e) if e.is_unreadable() => continue,
            Err(e) => return Err(e),
        };
        for e in &t.entries {
            let path = dir.join(&e.name);
            match e.kind {
                EntryKind::Dir => stack.push((path, e.id, depth + 1)),
                EntryKind::Gitlink => {
                    let commit = store.read_entry(e).ok().and_then(|b| parse_pin(&b));
                    out.push(Gitlink {
                        path,
                        entry: e.clone(),
                        commit,
                    });
                }
                _ => {}
            }
        }
    }
    out.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    Ok(out)
}

/// The `.gitmodules` of tree `tree` (empty if absent or not a readable
/// regular file).
pub fn gitmodules_of(store: &ObjectStore, tree: &ObjectId) -> Result<Vec<Submodule>> {
    let Some(e) = crate::tree::lookup(store, tree, &VPath::new(GITMODULES)?)? else {
        return Ok(Vec::new());
    };
    if e.kind != EntryKind::File {
        return Err(sm_err(format!("{GITMODULES} is not a regular file; it is not read")));
    }
    match store.read_entry(&e) {
        Ok(b) => parse_gitmodules(&b),
        Err(err) if err.is_unreadable() => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

/// Pin the gitlink at `path` of workspace `ws`'s working-copy change to
/// `commit` (`vl submodule set`, `vl submodule add`). A new gitlink is
/// classified by the policy like a file (public, or sealed for a cloaked
/// path; an isolated or ignored path is refused); an existing one keeps its
/// audience. Returns the previous pin.
pub fn set_pin(repo: &mut Repo, ws: &str, path: &VPath, commit: &str, create: bool) -> Result<Option<String>> {
    if repo.format() < crate::object::GIT_PARITY_REPO_FORMAT {
        return Err(VeilError::Unsupported(format!(
            "submodules need repository format {}; this one is at format {}: upgrade it with `vl upgrade`",
            crate::object::GIT_PARITY_REPO_FORMAT,
            repo.format()
        )));
    }
    validate_path(path.as_str())?;
    parse_commit_arg(commit)?;
    let wc = repo.workspace_wc(ws)?;
    let s = repo.snapshot(&wc)?;
    let store = repo.store().clone();
    let current = crate::tree::lookup(&store, &s.tree, path)?;
    let content = format!("{commit}\n").into_bytes();
    let (vis, old) = match &current {
        Some(e) if e.kind == EntryKind::Gitlink => (e.visibility.clone(), store.read_entry(e).ok().and_then(|b| parse_pin(&b))),
        Some(e) => {
            return Err(sm_err(format!(
                "{path} is a {} here, not a submodule{}",
                e.kind.name(),
                if create { "; move it away first" } else { "" }
            )))
        }
        None if !create => return Err(sm_err(format!("{path} is not a submodule (add one with `vl submodule add`)"))),
        None => {
            let policy = match crate::tree::lookup(&store, &s.tree, &VPath::new(crate::policy::POLICY_FILE)?)? {
                Some(e) if e.kind == EntryKind::File => match store.read_entry(&e) {
                    Ok(b) => crate::policy::Policy::parse(&String::from_utf8_lossy(&b)),
                    Err(_) => crate::policy::Policy::builtin(),
                },
                _ => crate::policy::Policy::builtin(),
            };
            match policy.classify(path, false).tier {
                crate::policy::Tier::Public => (Visibility::Public, None),
                crate::policy::Tier::Cloaked(scope) => (Visibility::Cloaked { scope }, None),
                crate::policy::Tier::Isolated | crate::policy::Tier::Ignored => {
                    return Err(sm_err(format!(
                        "{path} is isolated or ignored by the policy; Veil cannot record a submodule there"
                    )))
                }
            }
        }
    };
    if old.as_deref() == Some(commit) {
        return Ok(old);
    }
    let id = store.store_file(&content, &vis)?;
    let entry = TreeEntry {
        name: path.file_name().to_string(),
        kind: EntryKind::Gitlink,
        id,
        size: content.len() as u64,
        executable: false,
        visibility: vis,
        fallback: None,
    };
    let tree = crate::selection::edit_tree(&store, &s.tree, vec![(path.clone(), Some(entry))])?;
    let mut tx = repo.transaction(format!("submodule set {path}"))?;
    let ns = Snapshot { tree, ..(*s).clone() };
    let nid = tx.rewrite(wc, ns)?;
    tx.set_workspace_wc(ws, nid)?;
    tx.commit()?;
    Ok(old)
}

/// Is `id` the blob of a gitlink naming `commit`?
pub fn is_pin_blob(id: &ObjectId, commit: &str) -> bool {
    *id == Object::blob_id(format!("{commit}\n").as_bytes())
}

// ---- running git ---------------------------------------------------------------

/// How [`update`] and [`clone_new`] run `git`.
#[derive(Clone, Debug, Default)]
pub struct GitRunner {
    /// Allow local paths and `file://` URLs.
    pub allow_local: bool,
}

impl GitRunner {
    fn command(&self) -> Command {
        let bin = std::env::var_os("VEIL_GIT").unwrap_or_else(|| "git".into());
        let mut c = Command::new(bin);
        for v in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_NAMESPACE",
            "GIT_COMMON_DIR",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_COUNT",
        ] {
            c.env_remove(v);
        }
        let protocols = if self.allow_local { "https:ssh:git:file" } else { "https:ssh:git" };
        c.env("GIT_ALLOW_PROTOCOL", protocols);
        c.env("GIT_PROTOCOL_FROM_USER", "0");
        c.args(["-c", "protocol.ext.allow=never", "-c", "protocol.fd.allow=never"]);
        c.args(["-c", if self.allow_local { "protocol.file.allow=always" } else { "protocol.file.allow=never" }]);
        c.args(["-c", "core.hooksPath=/dev/null", "-c", "submodule.recurse=false", "-c", "core.fsmonitor=false"]);
        c.args(["-c", "advice.detachedHead=false", "-c", "gc.auto=0"]);
        c.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        c
    }

    fn run(&self, mut c: Command, what: &str, url: &str) -> Result<String> {
        let out = c.output().map_err(|e| {
            VeilError::repo(format!("could not run git for {what}: {e} (is git installed? set VEIL_GIT to its path)"))
        })?;
        if !out.status.success() {
            let text = String::from_utf8_lossy(&out.stderr);
            let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
            let msg = crate::git::redact_in_text(&lines.join("; "), url);
            return Err(VeilError::repo(format!("git {what} failed: {msg}")));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn git_in(&self, git_dir: &Path, work: Option<&Path>) -> Command {
        let mut c = self.command();
        c.arg("--git-dir").arg(git_dir);
        if let Some(w) = work {
            c.arg("--work-tree").arg(w);
        }
        c.current_dir(git_dir);
        c
    }

    fn has_commit(&self, git_dir: &Path, commit: &str) -> bool {
        let mut c = self.git_in(git_dir, None);
        c.args(["cat-file", "-e", &format!("{commit}^{{commit}}")]);
        c.output().is_ok_and(|o| o.status.success())
    }
}

/// Where the Git directory of submodule `name` lives:
/// `.veil/local/submodules/<hash of the name>` (never `.git/modules`).
pub fn local_git_dir(project_root: &Path, name: &str) -> PathBuf {
    let h = blake3::hash(name.as_bytes());
    project_root
        .join(crate::repo::VEIL_DIR)
        .join("local")
        .join("submodules")
        .join(&h.to_hex()[..32])
}

/// The submodule work tree at `path` below `project_root`, refusing a path
/// reached through a symlink (a link planted at `vendor` must not send the
/// clone elsewhere).
fn work_tree(project_root: &Path, path: &VPath) -> Result<PathBuf> {
    let mut cur = project_root.to_path_buf();
    for c in path.components() {
        cur.push(c);
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(sm_err(format!("{path} goes through a symlink ({}); refused", cur.display())))
            }
            Ok(m) if !m.is_dir() => return Err(sm_err(format!("{} is not a directory", cur.display()))),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_err(&cur, e)),
        }
    }
    Ok(cur)
}

/// What [`update`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// Cloned and checked out.
    Cloned,
    /// Fetched (the commit was missing) and checked out.
    Fetched,
    /// Checked out a commit already present.
    CheckedOut,
    /// Already at the pinned commit.
    UpToDate,
}

/// The commit checked out in the submodule work tree at `path`, read
/// with gix (no configuration of that repository is executed or obeyed).
pub fn checked_out(project_root: &Path, name: Option<&str>, path: &VPath) -> Option<String> {
    let work = work_tree(project_root, path).ok()?;
    let git_dir = match name.map(|n| local_git_dir(project_root, n)).filter(|d| d.is_dir()) {
        Some(d) => d,
        None => {
            let dot = work.join(".git");
            let m = std::fs::symlink_metadata(&dot).ok()?;
            if m.is_dir() {
                dot
            } else if m.is_file() {
                let text = std::fs::read_to_string(&dot).ok()?;
                let p = PathBuf::from(text.strip_prefix("gitdir:")?.trim());
                if p.is_absolute() {
                    p
                } else {
                    work.join(p)
                }
            } else {
                return None;
            }
        }
    };
    let repo = gix::open_opts(&git_dir, gix::open::Options::isolated()).ok()?;
    Some(repo.head_id().ok()?.detach().to_string())
}

/// Clone or fetch submodule `name` from `url` into `path` (below
/// `project_root`) and check out `commit`, detached. The URL must already
/// have passed [`validate_url`] (checked again here). A non-empty
/// directory that is not this submodule's work tree is never touched.
pub fn update(runner: &GitRunner, project_root: &Path, name: &str, path: &VPath, url: &str, commit: &str) -> Result<UpdateOutcome> {
    validate_name(name)?;
    validate_url(url, runner.allow_local)?;
    // A hostile tree may hold a gitlink at `x/.git`: never a place to clone.
    validate_path(path.as_str())?;
    parse_commit_arg(commit)?;
    let work = work_tree(project_root, path)?;
    let git_dir = local_git_dir(project_root, name);
    let dot_git = work.join(".git");
    let mut outcome = UpdateOutcome::CheckedOut;
    if !git_dir.is_dir() {
        // A fresh clone needs an empty (or absent) directory: never mix
        // a clone into files someone put there.
        if let Ok(mut rd) = std::fs::read_dir(&work) {
            if rd.next().is_some() {
                return Err(sm_err(format!(
                    "{path} is not empty and is not a submodule Veil cloned; move its files away first"
                )));
            }
        }
        std::fs::create_dir_all(git_dir.parent().unwrap()).map_err(|e| io_err(&git_dir, e))?;
        let mut c = runner.command();
        c.current_dir(project_root);
        c.args(["clone", "--no-checkout", "--quiet", "--separate-git-dir"])
            .arg(&git_dir)
            .arg("--")
            .arg(url)
            .arg(&work);
        if let Err(e) = runner.run(c, "clone", url) {
            let _ = std::fs::remove_dir_all(&git_dir);
            return Err(e);
        }
        outcome = UpdateOutcome::Cloned;
    } else if std::fs::symlink_metadata(&dot_git).is_err() {
        std::fs::create_dir_all(&work).map_err(|e| io_err(&work, e))?;
        std::fs::write(&dot_git, format!("gitdir: {}\n", git_dir.display())).map_err(|e| io_err(&dot_git, e))?;
    }
    if checked_out(project_root, Some(name), path).as_deref() == Some(commit) && outcome != UpdateOutcome::Cloned {
        return Ok(UpdateOutcome::UpToDate);
    }
    if !runner.has_commit(&git_dir, commit) {
        let mut c = runner.git_in(&git_dir, None);
        c.args(["fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "--"])
            .arg(url)
            .arg("+refs/heads/*:refs/remotes/origin/*");
        runner.run(c, "fetch", url)?;
        if !runner.has_commit(&git_dir, commit) {
            let mut c = runner.git_in(&git_dir, None);
            c.args(["fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "--"]).arg(url).arg(commit);
            runner.run(c, "fetch", url)?;
        }
        if outcome != UpdateOutcome::Cloned {
            outcome = UpdateOutcome::Fetched;
        }
    }
    let mut c = runner.git_in(&git_dir, Some(&work));
    c.args(["checkout", "--quiet", "--detach", commit, "--"]);
    runner.run(c, "checkout", url)?;
    Ok(outcome)
}

/// Clone `url` into `path` for `vl submodule add` and return the commit
/// checked out (the remote's default branch).
pub fn clone_new(runner: &GitRunner, project_root: &Path, name: &str, path: &VPath, url: &str) -> Result<String> {
    validate_name(name)?;
    validate_url(url, runner.allow_local)?;
    validate_path(path.as_str())?;
    let work = work_tree(project_root, path)?;
    let git_dir = local_git_dir(project_root, name);
    if git_dir.exists() {
        return Err(sm_err(format!(
            "a submodule named {name:?} was cloned here before ({}); remove that directory or pick another path",
            git_dir.display()
        )));
    }
    if let Ok(mut rd) = std::fs::read_dir(&work) {
        if rd.next().is_some() {
            return Err(sm_err(format!("{path} exists and is not empty")));
        }
    }
    std::fs::create_dir_all(git_dir.parent().unwrap()).map_err(|e| io_err(&git_dir, e))?;
    let mut c = runner.command();
    c.current_dir(project_root);
    c.args(["clone", "--quiet", "--no-recurse-submodules", "--separate-git-dir"])
        .arg(&git_dir)
        .arg("--")
        .arg(url)
        .arg(&work);
    if let Err(e) = runner.run(c, "clone", url) {
        let _ = std::fs::remove_dir_all(&git_dir);
        return Err(e);
    }
    let mut c = runner.git_in(&git_dir, None);
    c.args(["rev-parse", "--verify", "HEAD^{commit}"]);
    let head = runner.run(c, "rev-parse", url)?;
    parse_commit_arg(&head)
}

/// The `.gitmodules` text with a section for `name` at `path` from `url`
/// appended (`vl submodule add`). Refuses a name or path already listed.
pub fn add_section(existing: &str, name: &str, path: &VPath, url: &str) -> Result<String> {
    for s in parse_gitmodules(existing.as_bytes())? {
        if s.name == name || s.path.as_deref() == Some(path.as_str()) {
            return Err(sm_err(format!("{GITMODULES} already has a submodule named {name:?} or at {path}")));
        }
    }
    let quote = |v: &str| -> Result<String> {
        if v.chars().any(|c| c.is_control()) {
            return Err(sm_err("control characters cannot be written to .gitmodules"));
        }
        Ok(format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\"")))
    };
    let mut out = existing.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!(
        "[submodule {}]\n\tpath = {}\n\turl = {}\n",
        quote(name)?,
        quote(path.as_str())?,
        quote(url)?
    ));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gitmodules_and_ignores_commands() {
        let text = b"[submodule \"lib\"]\n\tpath = vendor/lib\n\turl = https://example.com/lib.git\n\tupdate = !touch /tmp/pwned\n[submodule \"x\"]\n\tpath = x\n";
        let s = parse_gitmodules(text).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].name, "lib");
        assert_eq!(s[0].path.as_deref(), Some("vendor/lib"));
        assert_eq!(s[0].url.as_deref(), Some("https://example.com/lib.git"));
        assert_eq!(s[1].url, None);
        assert!(parse_gitmodules(b"[submodule \"a\"\n path").is_err() || parse_gitmodules(b"[submodule \"a\"\n path").unwrap().is_empty());
    }

    #[test]
    fn hostile_urls_are_refused() {
        for url in [
            "--upload-pack=touch /tmp/x",
            "-oProxyCommand=touch /tmp/x:repo",
            "ext::sh -c touch% /tmp/x",
            "fd::17",
            "file:///home/u/private-repo",
            "/home/u/private-repo",
            "../../private",
            "https://example.com/a\nurl=ext::sh",
            "ssh://-oProxyCommand=touch%20x/repo",
            "http://example.com/x.git",
            "foo::bar",
            "transport::https://x",
            "",
            "https://evil\u{1b}]8;;x",
        ] {
            assert!(validate_url(url, false).is_err(), "{url:?} accepted");
        }
        for url in ["https://github.com/o/r.git", "ssh://git@host/r", "git@github.com:o/r.git", "git://host/r"] {
            validate_url(url, false).unwrap();
        }
        validate_url("file:///srv/r.git", true).unwrap();
        validate_url("/srv/r.git", true).unwrap();
        assert!(validate_url("ext::sh -c x", true).is_err());
        assert!(validate_url("--upload-pack=x", true).is_err());
    }

    #[test]
    fn hostile_names_and_paths_are_refused() {
        for n in ["../../../.veil/hooks", "..", "a/../b", "a\\..\\b", "", "x\ny"] {
            assert!(validate_name(n).is_err(), "{n:?}");
        }
        validate_name("vendor/lib").unwrap();
        for p in [".git", "a/.git/hooks", ".veil/local", "a/.GIT", "../x", "/etc", ""] {
            assert!(validate_path(p).is_err(), "{p:?}");
        }
        assert_eq!(validate_path("vendor/lib/").unwrap().as_str(), "vendor/lib");
        // The Git directory is a hash of the name: no name escapes it.
        let d = local_git_dir(Path::new("/p"), "../../../.veil/hooks");
        assert!(d.starts_with("/p/.veil/local/submodules"));
        assert_eq!(d.components().count(), Path::new("/p/.veil/local/submodules/x").components().count());
    }

    #[test]
    fn update_refuses_hostile_paths_and_commits_before_running_git() {
        let runner = GitRunner { allow_local: true };
        let root = Path::new("/nonexistent-veil-test-root");
        let c = "a".repeat(40);
        for bad in ["x/.git", ".GIT", "a/.git/hooks"] {
            let p = VPath::new(bad).unwrap();
            let err = update(&runner, root, "n", &p, "https://h/x.git", &c).unwrap_err();
            assert!(err.to_string().contains("goes through"), "{bad}: {err}");
        }
        let p = VPath::new("x").unwrap();
        assert!(update(&runner, root, "n", &p, "https://h/x.git", "--orphan").is_err());
    }

    #[test]
    fn relative_urls_resolve_like_git() {
        assert_eq!(resolve_relative("../lib.git", "https://github.com/o/app.git").as_deref(), Some("https://github.com/o/lib.git"));
        assert_eq!(resolve_relative("./sub", "https://h/o/app").as_deref(), Some("https://h/o/app/sub"));
        assert_eq!(resolve_relative("../lib.git", "git@github.com:o/app.git").as_deref(), Some("git@github.com:o/lib.git"));
        assert_eq!(resolve_relative("../../lib.git", "git@github.com:o/app.git").as_deref(), Some("git@github.com:lib.git"));
    }

    #[test]
    fn pins_and_sections() {
        let c = "a".repeat(40);
        assert_eq!(parse_pin(format!("{c}\n").as_bytes()), Some(c.clone()));
        assert_eq!(parse_pin(c.as_bytes()), None);
        assert_eq!(parse_pin(b"zz\n"), None);
        assert!(parse_commit_arg("abc").is_err());
        assert_eq!(parse_commit_arg(&"A".repeat(40)).unwrap(), "a".repeat(40));
        let p = VPath::new("vendor/lib").unwrap();
        let text = add_section("", "lib", &p, "https://h/lib.git").unwrap();
        let s = parse_gitmodules(text.as_bytes()).unwrap();
        assert_eq!(s[0].path.as_deref(), Some("vendor/lib"));
        assert!(add_section(&text, "lib", &p, "https://h/x").is_err());
        assert!(add_section("", "a\"b", &p, "https://h/x\nurl=ext::x").is_err());
    }
}
