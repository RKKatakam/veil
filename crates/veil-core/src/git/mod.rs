//! Two-way Git interop: import Git history, and bridge Veil tags to the
//! branches of a Git remote (GitHub, GitLab, any Git server).
//!
//! # Layout
//!
//! ```text
//! .veil/git/repo.git     bare Git repository (gix): exported and fetched objects
//!   refs/heads/<tag>          what Veil last exported for a tag
//!   refs/remotes/<r>/<b>      branches of Git remote <r> as last fetched or pushed
//! .veil/git/map          commit ↔ snapshot mapping (see `map`)
//! .veil/git/cache        conversion caches (safe to delete)
//! .veil/git/remotes.json Git remotes: name → URL
//! ```
//!
//! # Visibility
//!
//! Git sees exactly what a **public** Veil remote sees (the *public
//! projection*, `project.rs`, for trees). Snapshots are selected with the public push's own rules
//! (`remote::embargo_withheld`, `remote::push_closure`): cloaked tags are
//! never exported, the merged-in history of an unreleased embargoed merge is
//! withheld (the merge's extra parents are dropped from the Git commit), and
//! a tag that would publish withheld history is skipped. Descriptions sealed
//! for a scope become a fixed placeholder.
//!
//! # Determinism
//!
//! A snapshot's commit is a function of the snapshot, the commits of its
//! parents and the visibility state: author and committer are the
//! snapshot's author and timestamp (UTC), the change id is stored in a
//! `change-id` header (as Jujutsu does), and nothing else varies. Once
//! exported, a snapshot keeps its commit (the mapping pins it), so Git
//! history is append-only from Veil's side: when an embargo is released,
//! a *publication* commit on top of the pinned one brings in the released
//! tree and the fix's history. The same holds for a commit made in Git on
//! top of an embargoed merge (it shows the pre-fix files): the mapping
//! records which embargoes were unreleased in each commit's view, and a
//! Git commit made on such a view is imported against it, so the pre-fix
//! files it shows never read as a revert of the fix.
//!
//! The mapping can be lost: an exported commit met in Git without one is
//! recognised by exporting its snapshot again (same commit id), never by
//! its `change-id` header alone, which anyone can write. A header naming
//! an existing change is not taken.
//!
//! # Round trips
//!
//! A Git commit made on top of an exported commit lacks every file Git never
//! saw. Import therefore applies the commit as a three-way merge onto the
//! parent's real Veil tree: `base` = the parent's public projection (what
//! Git saw), `ours` = the parent's Veil tree, `theirs` = the Git commit
//! built through the policy gate (the builder: isolation, secret scanning,
//! cloaking). Cloaked, isolated-by-Veil and embargoed entries are carried
//! over untouched; Git's edits apply; nothing sealed is ever widened. The
//! reverse holds for export: paths Git has but Veil never recorded
//! (quarantined or isolated files that were committed to Git, symlinks,
//! submodules) are carried over from the parent commit.
//!
//! # Transport
//!
//! Objects are read and written with `gix`. Network fetch and push run the
//! system `git` binary (`$VEIL_GIT`, default `git`), like Jujutsu does, so
//! the user's credential helpers, SSH configuration and agent, proxies and
//! `insteadOf` rules all apply unchanged.

pub mod colocate;
mod export;
mod import;
mod index;
pub mod map;
mod project;
mod transport;

use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
};

pub use export::ExportReport;
// The public projection's readers, for `vl format-patch` (`crate::patch`):
// one projection function for every export.
pub(crate) use export::split_author;
pub(crate) use project::{public_open, public_text, Public, Veil, CLOAKED_DESCRIPTION};
pub use import::ImportReport;
pub use map::{GitMap, GitOid, Origin};
pub use transport::{redact_url, PushOutcome, RefStatus};

use crate::{
    commands::validate_tag_name,
    error::{Result, VeilError},
    id::ObjectId,
    oplog::Tag,
    repo::Repo,
    revset::RevisionNames,
    vfs::StorageBackend,
    vpath::VPath,
};

pub(crate) fn gerr(e: impl std::fmt::Display) -> VeilError {
    VeilError::Repo(format!("git: {e}"))
}

/// Where the bridge repository lives below a project directory.
pub fn default_git_dir(project_root: &Path) -> PathBuf {
    project_root.join(".veil").join("git").join("repo.git")
}

/// The bare Git repository Veil exchanges objects through, with the
/// mapping and caches.
pub struct GitBridge {
    pub(crate) git: gix::Repository,
    git_dir: PathBuf,
    pub(crate) map: GitMap,
    pub(crate) cache: map::Cache,
    /// Projections of this run that the cache cannot keep, for `veil`.
    pub(crate) run_projected: HashMap<ObjectId, project::Projection>,
    /// Embargoes projections treat as unreleased (see `project::Veil`).
    pub(crate) veil: project::Veil,
    pub(crate) warnings: Vec<String>,
}

impl std::fmt::Debug for GitBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GitBridge({})", self.git_dir.display())
    }
}

fn open_git(dir: &Path) -> Result<gix::Repository> {
    // Isolated: the user's Git configuration must not change how objects
    // are written (or refuse to open a directory it does not own).
    let opts = gix::open::Options::isolated();
    match gix::open_opts(dir, opts.clone()) {
        Ok(r) => Ok(r),
        Err(_) => {
            gix::init_bare(dir).map_err(gerr)?;
            gix::open_opts(dir, opts).map_err(gerr)
        }
    }
}

impl GitBridge {
    pub fn open(repo: &Repo, git_dir: impl AsRef<Path>) -> Result<GitBridge> {
        let git_dir = git_dir.as_ref().to_path_buf();
        Ok(GitBridge {
            git: open_git(&git_dir)?,
            map: GitMap::load(&**repo.backend())?,
            cache: map::Cache::load(&**repo.backend()),
            git_dir,
            run_projected: HashMap::new(),
            veil: project::Veil::default(),
            warnings: Vec::new(),
        })
    }

    pub fn git_dir(&self) -> &Path {
        &self.git_dir
    }

    pub fn map(&self) -> &GitMap {
        &self.map
    }

    /// Re-open the Git repository (after `git` changed it on disk).
    fn reopen(&mut self) -> Result<()> {
        self.git = open_git(&self.git_dir)?;
        Ok(())
    }

    pub(crate) fn save(&mut self, backend: &dyn StorageBackend) -> Result<()> {
        self.map.save(backend)?;
        self.cache.save(backend);
        Ok(())
    }

    /// The commit currently representing `snapshot` in Git, if any.
    pub fn commit_of(&self, snapshot: &ObjectId) -> Option<GitOid> {
        self.map
            .current
            .get(snapshot)
            .map(|c| c.commit)
            .filter(|c| self.has_object(c))
    }

    /// The snapshot that `commit` was imported as or exported from.
    pub fn snapshot_of(&self, commit: &GitOid) -> Option<ObjectId> {
        self.map.commits.get(commit).copied()
    }

    // ---- objects ---------------------------------------------------------

    pub(crate) fn has_object(&self, oid: &GitOid) -> bool {
        matches!(self.git.try_find_object(*oid), Ok(Some(_)))
    }

    fn find(&self, oid: &GitOid, kind: gix::objs::Kind) -> Result<Vec<u8>> {
        let obj = self.git.find_object(*oid).map_err(gerr)?;
        if obj.kind != kind {
            return Err(gerr(format!("object {oid} is a {}, expected a {kind}", obj.kind)));
        }
        Ok(obj.data.clone())
    }

    pub fn read_commit(&self, oid: &GitOid) -> Result<gix::objs::Commit> {
        let data = self.find(oid, gix::objs::Kind::Commit)?;
        let commit = gix::objs::CommitRef::from_bytes(&data, gix::hash::Kind::Sha1)
            .map_err(gerr)?
            .into_owned()
            .map_err(gerr)?;
        Ok(commit)
    }

    pub fn read_tree(&self, oid: &GitOid) -> Result<gix::objs::Tree> {
        if *oid == empty_tree_oid() {
            return Ok(gix::objs::Tree::empty());
        }
        let data = self.find(oid, gix::objs::Kind::Tree)?;
        Ok(gix::objs::TreeRef::from_bytes(&data, gix::hash::Kind::Sha1)
            .map_err(gerr)?
            .into_owned())
    }

    pub fn read_blob(&self, oid: &GitOid) -> Result<Vec<u8>> {
        self.find(oid, gix::objs::Kind::Blob)
    }

    pub(crate) fn write_blob(&self, data: &[u8]) -> Result<GitOid> {
        Ok(self.git.write_blob(data).map_err(gerr)?.detach())
    }

    pub(crate) fn write_tree(&self, tree: gix::objs::Tree) -> Result<GitOid> {
        Ok(self.git.write_object(&tree).map_err(gerr)?.detach())
    }

    pub(crate) fn write_commit(&self, commit: &gix::objs::Commit) -> Result<GitOid> {
        Ok(self.git.write_object(commit).map_err(gerr)?.detach())
    }

    // ---- refs ------------------------------------------------------------

    pub fn get_ref(&self, name: &str) -> Result<Option<GitOid>> {
        Ok(self
            .git
            .try_find_reference(name)
            .map_err(gerr)?
            .and_then(|r| r.try_id().map(|id| id.detach())))
    }

    pub(crate) fn set_ref(&self, name: &str, oid: GitOid) -> Result<()> {
        self.git
            .reference(name, oid, gix::refs::transaction::PreviousValue::Any, "veil")
            .map_err(gerr)?;
        Ok(())
    }

    pub(crate) fn delete_ref(&self, name: &str) -> Result<()> {
        if let Some(r) = self.git.try_find_reference(name).map_err(gerr)? {
            r.delete().map_err(gerr)?;
        }
        Ok(())
    }

    /// Every direct reference below `prefix` (e.g. `refs/remotes/github/`),
    /// keyed by the rest of its name.
    pub fn refs_under(&self, prefix: &str) -> Result<BTreeMap<String, GitOid>> {
        let mut out = BTreeMap::new();
        let platform = self.git.references().map_err(gerr)?;
        for r in platform.all().map_err(gerr)? {
            let r = r.map_err(gerr)?;
            let name = r.name().as_bstr().to_string();
            if let (Some(rest), Some(id)) = (name.strip_prefix(prefix), r.try_id()) {
                out.insert(rest.to_string(), id.detach());
            }
        }
        Ok(out)
    }
}

pub(crate) fn empty_tree_oid() -> GitOid {
    GitOid::empty_tree(gix::hash::Kind::Sha1)
}

// ---- Git remotes -------------------------------------------------------------

fn remotes_path() -> VPath {
    VPath::new(".veil/git/remotes.json").unwrap()
}

/// Configured Git remotes: name → URL.
pub fn remotes(repo: &Repo) -> Result<BTreeMap<String, String>> {
    match repo.backend().read_opt(&remotes_path())? {
        Some(raw) => Ok(serde_json::from_slice(&raw)?),
        None => Ok(BTreeMap::new()),
    }
}

fn save_remotes(repo: &Repo, r: &BTreeMap<String, String>) -> Result<()> {
    repo.backend().write(&remotes_path(), &serde_json::to_vec_pretty(r)?)
}

/// Check a Git remote name: it becomes part of ref names and of Veil
/// remote-tag names (`<remote>/<branch>`). The same rule as for Veil
/// remotes ([`crate::remote::validate_remote_name`]).
pub fn validate_remote_name(name: &str) -> Result<()> {
    crate::remote::validate_remote_name(name)
}

/// Is `url` a local path to `git` (not `scheme://…` nor scp-style
/// `host:path`)?
pub(crate) fn is_local_path(url: &str) -> bool {
    if url.contains("://") {
        return false;
    }
    match url.find(':') {
        Some(colon) => url.find('/').is_some_and(|slash| slash < colon),
        None => true,
    }
}

/// `url` as it should be stored for a Git remote: a relative local path is
/// made absolute against `cwd` (the directory the user typed it in), so
/// that the remote is the same repository whichever directory `vl` later
/// runs in. Other URLs are returned unchanged.
pub fn absolute_git_url(url: &str, cwd: &Path) -> String {
    if !is_local_path(url) || Path::new(url).is_absolute() {
        return url.to_string();
    }
    let joined = cwd.join(url);
    if let Ok(p) = joined.canonicalize() {
        return p.to_string_lossy().into_owned();
    }
    // Not there yet: normalise `.` and `..` lexically.
    let mut out = PathBuf::new();
    for c in joined.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            c => out.push(c),
        }
    }
    out.to_string_lossy().into_owned()
}

/// Add Git remote `name` for `url`. A local path must be absolute (see
/// [`absolute_git_url`]): `git` would resolve a relative one against
/// whatever directory it runs in.
pub fn remote_add(repo: &mut Repo, name: &str, url: &str) -> Result<()> {
    validate_remote_name(name)?;
    transport::validate_url(url)?;
    if is_local_path(url) && !Path::new(url).is_absolute() {
        return Err(VeilError::repo(format!(
            "Git remote path {url:?} is relative; give an absolute path"
        )));
    }
    if crate::repo::read_config(&**repo.backend())?.remotes.contains_key(name) {
        return Err(VeilError::repo(format!(
            "'{name}' is already the name of a Veil remote; Git remotes share its `{name}/<branch>` names, pick another"
        )));
    }
    let _lock = crate::lock::RepoLock::acquire_reentrant(repo.backend().clone())?;
    let mut r = remotes(repo)?;
    if r.contains_key(name) {
        return Err(VeilError::AlreadyExists(format!("Git remote '{name}'")));
    }
    r.insert(name.to_string(), url.to_string());
    save_remotes(repo, &r)
}

/// Remove Git remote `name`: its remote tags `<name>/*` and the bridge's
/// tracking refs first, in one operation, then the remote itself, so that
/// an interruption leaves the remote configured (a retry finishes the
/// job), never remote tags of a remote that is gone (BUG-291).
pub fn remote_remove(repo: &mut Repo, git_dir: &Path, name: &str) -> Result<()> {
    let url = remotes(repo)?
        .get(name)
        .cloned()
        .ok_or_else(|| VeilError::NotFound(format!("Git remote '{name}'")))?;
    let mut tx = repo.transaction(format!("remove Git remote {name}"))?;
    let prefix = format!("{name}/");
    tx.view.remote_tags.retain(|k, _| !k.starts_with(&prefix));
    tx.manual_undo(format!(
        "Git remotes live in .veil/git/remotes.json, outside the operation log; add it back with \
         `vl git remote add {name} {}` (its remote tags come back with the next fetch)",
        redact_url(&url)
    ));
    drop_tracking_refs(tx.repo(), git_dir, name)?;
    tx.commit()?;
    forget_remote(repo, name)
}

/// Delete the bridge's `refs/remotes/<name>/*` (a cache of what was last
/// fetched; nothing else refers to it).
fn drop_tracking_refs(repo: &Repo, git_dir: &Path, name: &str) -> Result<()> {
    if !git_dir.exists() {
        return Ok(());
    }
    let bridge = GitBridge::open(repo, git_dir)?;
    for b in bridge.refs_under(&format!("refs/remotes/{name}/"))?.keys() {
        bridge.delete_ref(&format!("refs/remotes/{name}/{b}"))?;
    }
    Ok(())
}

/// Remove `name` from `.veil/git/remotes.json` (under the repository lock).
fn forget_remote(repo: &Repo, name: &str) -> Result<()> {
    let _lock = crate::lock::RepoLock::acquire(repo.backend().clone())?;
    let mut r = remotes(repo)?;
    if r.remove(name).is_some() {
        save_remotes(repo, &r)?;
    }
    Ok(())
}

/// The URL of Git remote `name`. A relative local path (stored by an
/// older version) is taken relative to the project directory when the
/// bridge has the standard layout (`<project>/.veil/git/repo.git`).
fn remote_url(repo: &Repo, git_dir: &Path, name: &str) -> Result<String> {
    let url = remotes(repo)?.get(name).cloned().ok_or_else(|| {
        VeilError::NotFound(format!(
            "Git remote '{name}' (add one with `vl git remote add {name} <url>`)"
        ))
    })?;
    if is_local_path(&url) && !Path::new(&url).is_absolute() {
        let standard = git_dir.ends_with(Path::new(".veil").join("git").join("repo.git"));
        if let Some(project) = git_dir.ancestors().nth(3).filter(|_| standard) {
            return Ok(absolute_git_url(&url, project));
        }
    }
    Ok(url)
}

// ---- fetch / pull ------------------------------------------------------------

#[derive(Debug, Default)]
pub struct FetchReport {
    pub import: ImportReport,
    /// `<remote>/<branch>` → snapshot, as recorded in the view.
    pub branches: Vec<(String, ObjectId)>,
    /// Branches rewritten on the Git side (force-push): (branch, old, new).
    /// Veil keeps the history they dropped.
    pub forced: Vec<(String, GitOid, GitOid)>,
    /// Branches deleted on the Git side (their remote tags are removed).
    pub deleted: Vec<String>,
    /// Local tags created or fast-forwarded (pull only).
    pub tags_updated: Vec<(String, ObjectId)>,
    pub warnings: Vec<String>,
}

/// `vl git fetch`: download a Git remote's branches and import new commits.
/// Records `<remote>/<branch>` remote tags; local tags are not moved.
pub fn fetch(repo: &mut Repo, git_dir: &Path, remote: &str) -> Result<FetchReport> {
    fetch_inner(repo, git_dir, remote, false)
}

/// `vl git pull`: [`fetch`], then create or fast-forward local tags like
/// `vl pull` does. A tag that has diverged from its branch is left alone
/// with a warning.
pub fn pull(repo: &mut Repo, git_dir: &Path, remote: &str) -> Result<FetchReport> {
    fetch_inner(repo, git_dir, remote, true)
}

/// `vl git import`: add `remote` for `url` (or reuse it if it already
/// points there) and pull every branch.
pub fn import(repo: &mut Repo, git_dir: &Path, url: &str, remote: &str) -> Result<FetchReport> {
    match remotes(repo)?.get(remote) {
        Some(u) if u == url => {}
        Some(u) => {
            return Err(VeilError::repo(format!(
                "Git remote '{remote}' already points at {}; choose another name with --remote",
                redact_url(u)
            )))
        }
        None => {
            remote_add(repo, remote, url)?;
            // A failed first import (a typo in the URL, a network error)
            // takes back the remote it added, so that a retry with the
            // right URL is not refused (BUG-292). Nothing else was recorded:
            // the pull's transaction never committed.
            return pull(repo, git_dir, remote).inspect_err(|_| {
                let _ = drop_tracking_refs(repo, git_dir, remote);
                let _ = forget_remote(repo, remote);
            });
        }
    }
    pull(repo, git_dir, remote)
}

fn fetch_inner(repo: &mut Repo, git_dir: &Path, remote: &str, update_tags: bool) -> Result<FetchReport> {
    let url = remote_url(repo, git_dir, remote)?;
    let mut bridge = GitBridge::open(repo, git_dir)?;
    let prefix = format!("refs/remotes/{remote}/");
    let before = bridge.refs_under(&prefix)?;
    transport::fetch(git_dir, &url, remote)?;
    bridge.reopen()?;
    let after = bridge.refs_under(&prefix)?;

    let mut report = FetchReport::default();
    let mut tx = repo.transaction(format!("git fetch from {remote}"))?;
    // What Veil last recorded for each branch. The bridge's tracking refs
    // cannot tell: `git fetch` has already moved them (and pruned deleted
    // branches), even if a previous import then failed.
    let tag_prefix = format!("{remote}/");
    let recorded: BTreeMap<String, ObjectId> = tx
        .view
        .remote_tags
        .iter()
        .filter_map(|(k, v)| k.strip_prefix(&tag_prefix).map(|b| (b.to_string(), *v)))
        .collect();
    let tips: Vec<GitOid> = after.values().copied().collect();
    report.import = bridge.import_tips(&mut tx, &tips)?;
    // Tags deleted here stay deleted while their branch has not moved
    // (`remote::deleted_tags`, BUG-280).
    let (stay_deleted, recreated) = if update_tags {
        let imported: Vec<(String, ObjectId)> = after
            .iter()
            .filter_map(|(b, oid)| bridge.snapshot_of(oid).map(|sid| (b.clone(), sid)))
            .collect();
        crate::remote::tags_staying_deleted(&tx, &imported)?
    } else {
        Default::default()
    };
    for name in recreated {
        report.warnings.push(format!(
            "tag '{name}', deleted here, has new commits on Git branch {remote}/{name}: it is back. \
             Delete it again, or delete the branch too with `vl git push {remote} --delete {name}`"
        ));
    }
    let mut revisions = RevisionNames::default();
    for (branch, oid) in &after {
        let name = format!("{remote}/{branch}");
        if validate_tag_name(branch).is_err() || validate_tag_name(&name).is_err() {
            report
                .warnings
                .push(format!("skipped Git branch {branch:?}: not a valid Veil tag name"));
            continue;
        }
        let Some(sid) = bridge.snapshot_of(oid) else {
            let why = report
                .import
                .failed
                .iter()
                .find(|(c, _)| c == oid)
                .map(|(_, why)| why.clone())
                .unwrap_or_else(|| "not imported".into());
            report.warnings.push(format!(
                "Git branch '{branch}' ({}) was not imported: {why}; the other branches were",
                short(oid)
            ));
            continue;
        };
        if let Some(old_sid) = recorded.get(branch).filter(|o| **o != sid) {
            if !tx.repo().is_ancestor(old_sid, &sid)? {
                let old = before
                    .get(branch)
                    .copied()
                    .or_else(|| bridge.commit_of(old_sid))
                    .unwrap_or_else(|| GitOid::null(gix::hash::Kind::Sha1));
                report.forced.push((branch.clone(), old, *oid));
            }
        }
        tx.view.remote_tags.insert(name.clone(), sid);
        report.branches.push((name, sid));
        if update_tags && !(stay_deleted.contains(branch) && !tx.view.tags.contains_key(branch)) {
            update_tag(&mut tx, remote, branch, sid, &mut revisions, &mut report)?;
        }
    }
    for branch in recorded.keys().filter(|b| !after.contains_key(*b)) {
        tx.view.remote_tags.remove(&format!("{remote}/{branch}"));
        report.deleted.push(branch.clone());
    }
    report.warnings.append(&mut bridge.warnings);
    bridge.save(&**tx.repo().backend())?;
    tx.commit()?;
    Ok(report)
}

/// Create or fast-forward local tag `branch` to `sid` (as `remote::pull`).
/// A new tag is not created if its name would shadow one of this
/// repository's change ids or snapshot ids: anyone who can push a branch
/// named after a published change id could otherwise redirect `vl new
/// <change>` to their commit. `<remote>/<branch>` still names it.
fn update_tag(
    tx: &mut crate::transaction::Transaction<'_>,
    remote: &str,
    branch: &str,
    sid: ObjectId,
    revisions: &mut RevisionNames,
    report: &mut FetchReport,
) -> Result<()> {
    match tx.view.tags.get(branch).cloned() {
        None => {
            if revisions.shadows(tx.repo(), || tx.repo().view().refs(), branch)? {
                report.warnings.push(format!(
                    "no local tag created for Git branch '{branch}': the name is also a change or snapshot id of this repository; use {remote}/{branch}"
                ));
                return Ok(());
            }
            tx.view.tags.insert(branch.to_string(), Tag { target: sid, cloak: None });
            report.tags_updated.push((branch.to_string(), sid));
        }
        Some(t) if t.target == sid => {}
        Some(t) => {
            if tx.repo().is_ancestor(&t.target, &sid)? {
                tx.view.tags.insert(
                    branch.to_string(),
                    Tag {
                        target: sid,
                        cloak: t.cloak,
                    },
                );
                report.tags_updated.push((branch.to_string(), sid));
            } else if !tx.repo().is_ancestor(&sid, &t.target)? {
                report.warnings.push(format!(
                    "tag '{branch}' has diverged from Git branch {remote}/{branch}; nothing was lost on either side. Merge with `vl merge {remote}/{branch}`, then `vl git push {remote}`"
                ));
            }
        }
    }
    Ok(())
}

// ---- push --------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct PushReport {
    pub export: ExportReport,
    pub outcome: PushOutcome,
}

/// `vl git push`: export tags (all by default) as branches and push them.
/// Without `force` a branch that moved on the Git side is rejected (fetch
/// and merge first); with `force` it is overwritten, but only if it still
/// holds what was last fetched (`--force-with-lease`).
pub fn push(repo: &mut Repo, git_dir: &Path, remote: &str, only_tags: &[String], force: bool) -> Result<PushReport> {
    push_with_deletions(repo, git_dir, remote, only_tags, force, &[])
}

/// [`push`], also deleting the branches `delete` on the remote (`vl git
/// push --delete`, BUG-280); their tags must already be deleted here
/// (`vl tag delete`). When no tag is named, only the deletions are pushed.
/// A deletion is leased like a forced push: it is rejected if the branch
/// has moved since it was last fetched (`force` deletes it regardless).
/// The branch's remote tag goes too; local tags deleted here stay deleted
/// on the next pull (`remote::deleted_tags`).
pub fn push_with_deletions(
    repo: &mut Repo,
    git_dir: &Path,
    remote: &str,
    only_tags: &[String],
    force: bool,
    delete: &[String],
) -> Result<PushReport> {
    for d in delete {
        if repo.view().tags.contains_key(d) {
            return Err(VeilError::repo(format!(
                "tag '{d}' still exists here; delete it first with `vl tag delete {d}` (a later `vl git push` would push it again)"
            )));
        }
        validate_tag_name(d)?;
    }
    let url = remote_url(repo, git_dir, remote)?;
    let mut bridge = GitBridge::open(repo, git_dir)?;
    let export = if delete.is_empty() || !only_tags.is_empty() {
        bridge.export(repo, only_tags)?
    } else {
        ExportReport::default()
    };
    let mut updates = Vec::new();
    for (branch, commit) in &export.branches {
        let tracking = format!("refs/remotes/{remote}/{branch}");
        updates.push(transport::PushRef {
            branch: branch.clone(),
            commit: Some(*commit),
            force,
            lease: bridge.get_ref(&tracking)?,
        });
    }
    for d in delete {
        let tracking = format!("refs/remotes/{remote}/{d}");
        updates.push(transport::PushRef {
            branch: d.clone(),
            commit: None,
            force,
            lease: bridge.get_ref(&tracking)?,
        });
    }
    let outcome = transport::push(git_dir, &url, &updates)?;
    bridge.reopen()?;
    // Record what the remote now holds.
    let mut tx = repo.transaction(format!("git push to {remote}"))?;
    for (branch, status) in &outcome.refs {
        if !status.accepted() {
            continue;
        }
        let Some(u) = updates.iter().find(|u| &u.branch == branch) else { continue };
        let Some(commit) = u.commit else {
            bridge.delete_ref(&format!("refs/remotes/{remote}/{branch}"))?;
            tx.view.remote_tags.remove(&format!("{remote}/{branch}"));
            continue;
        };
        bridge.set_ref(&format!("refs/remotes/{remote}/{branch}"), commit)?;
        if let Some(sid) = bridge.snapshot_of(&commit) {
            tx.view.remote_tags.insert(format!("{remote}/{branch}"), sid);
        }
    }
    tx.commit()?;
    Ok(PushReport { export, outcome })
}

pub(crate) fn short(oid: &GitOid) -> String {
    oid.to_hex_with_len(10).to_string()
}
