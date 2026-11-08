//! CLI session: locate the repository, load the identity, auto-snapshot the
//! working copy, and keep the project directory in sync with the view.
//!
//! The session owns the project directory's stat cache
//! (`.veil/local/statcache/<workspace>.cache`). It is loaded once, used by
//! every snapshot and checkout of the session, and saved only when it changed.
//!
//! It also keeps the record of what the directory was materialised from
//! (`checkout.json`, [`Materialised`]): files left out because they were
//! unreadable. Every command fills in whatever has become readable since,
//! before it snapshots and again when it finishes, so a grant is never
//! recorded as a
//! deletion or a revert.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{anyhow, bail, Context, Result};
use veil_core::{
    builder::BuildReport,
    checkout::{CheckoutReport, Materialised},
    workspace::SnapshotOptions,
    policy::POLICY_FILE,
    repo::{DEFAULT_WORKSPACE, VEIL_DIR},
    revset,
    statcache::{cache_path, StatCache},
    tree::lookup,
    DiskBackend, Identity, ObjectId, Repo, StorageBackend, VPath,
};

use crate::render::{self, safe, warn, warn_untrusted};

pub fn veil_home() -> PathBuf {
    if let Some(h) = std::env::var_os("VEIL_HOME") {
        return PathBuf::from(h);
    }
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(x).join("veil");
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".config").join("veil")
}

pub fn identity_path() -> PathBuf {
    veil_home().join("identity.json")
}

pub fn default_user_name() -> String {
    std::env::var("VEIL_USER")
        .or_else(|_| std::env::var("USER"))
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "anonymous".into())
}

/// Write the identity (private keys) to [`identity_path`]: never readable
/// by anyone else, not even briefly (BUG-112), and never half-written.
/// The content goes to a fresh temp file created with mode `0600`, is
/// synced, and is renamed over the old file; a new `$VEIL_HOME` is created
/// owner-only.
pub fn write_identity(id: &Identity) -> Result<()> {
    store_identity(id, true).map(|_| ())
}

/// Store `id` as [`identity_path`] only if no identity is there yet, as
/// [`write_identity`] does but without ever replacing one: the synced temp
/// file is hard-linked into place, which fails if another process got there
/// first (BUG-360). `false`: an identity already existed, nothing changed.
pub fn create_identity(id: &Identity) -> Result<bool> {
    store_identity(id, false)
}

fn store_identity(id: &Identity, replace: bool) -> Result<bool> {
    use std::io::Write;
    let path = identity_path();
    let dir = path.parent().unwrap();
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir).with_context(|| format!("creating {}", dir.display()))?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(".identity.json.{}.{nanos:08x}.tmp", std::process::id()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let written = (|| -> std::io::Result<bool> {
        let mut f = opts.open(&tmp)?;
        f.write_all(id.to_json().as_bytes())?;
        f.sync_all()?;
        drop(f);
        if replace {
            std::fs::rename(&tmp, &path)?;
        } else {
            let linked = match std::fs::hard_link(&tmp, &path) {
                Ok(()) => true,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
                // A filesystem without hard links: claim the name with an
                // exclusive create instead (the content follows by rename,
                // so a reader only ever sees an empty file, never half of
                // one, and `load_identity` waits that out).
                Err(_) => match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
                    Ok(_) => {
                        std::fs::rename(&tmp, &path)?;
                        true
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
                    Err(e) => return Err(e),
                },
            };
            let _ = std::fs::remove_file(&tmp);
            if !linked {
                return Ok(false);
            }
        }
        #[cfg(unix)]
        std::fs::File::open(dir)?.sync_all()?;
        Ok(true)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written.with_context(|| format!("writing {}", path.display()))
}

/// Load the identity, creating one on first use. Several processes
/// starting at once on a fresh `$VEIL_HOME` agree on one identity: the
/// first to store its own wins, the others load that one (BUG-360).
pub fn load_identity() -> Result<Identity> {
    let path = identity_path();
    if path.exists() {
        return read_identity(&path);
    }
    let id = Identity::generate(&default_user_name());
    if !create_identity(&id)? {
        return read_identity(&path);
    }
    eprintln!(
        "{} new identity for '{}' at {}",
        render::green("Created"),
        id.name,
        path.display()
    );
    Ok(id)
}

/// Read the identity file. An empty one is another process's identity
/// being put in place (see [`create_identity`]): wait for it briefly.
fn read_identity(path: &Path) -> Result<Identity> {
    for attempt in 0.. {
        let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        if !s.is_empty() || attempt == 50 {
            return Ok(Identity::from_json(&s)?);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    unreachable!()
}

pub fn user_for(id: &Identity) -> String {
    std::env::var("VEIL_USER").unwrap_or_else(|_| id.name.clone())
}

pub use veil_core::working_copy::CheckoutState;

pub fn checkout_path() -> VPath {
    CheckoutState::path()
}

pub struct Ctx {
    pub root: PathBuf,
    pub fs: Arc<DiskBackend>,
    pub repo: Repo,
    pub ws: String,
    checkout: CheckoutState,
    pub report: BuildReport,
    /// Stat cache of the project directory (it follows the directory when
    /// another workspace is attached).
    cache: StatCache,
    /// A bare repository (a path remote an older `vl push` created): no workspace, no
    /// working copy. Only commands that read history, and `gc`, run here
    /// (BUG-284); nothing is snapshotted or checked out.
    pub bare: bool,
    /// The working copy before [`Ctx::commit`] recorded the directory and
    /// moved `@` in one operation: what [`Ctx::finish`] reports the move
    /// from (the directory already holds the new `@`).
    committed_from: Option<ObjectId>,
    /// The command runs for a workspace the project directory is not
    /// attached to: a `vl` inside a `vl ws exec` sandbox, through the
    /// workspace socket ([`Ctx::open_for_workspace`]). It never records,
    /// moves or attaches the project directory.
    pub detached: bool,
}

/// Written by `vl clone` before it fetches anything, removed once its
/// checkout is done (BUG-837). A clone killed before its checkout started
/// holds part of the project's history and none of its files: commands
/// refuse it instead of showing an empty project. Once the checkout's
/// journal exists everything was fetched, and the journal finishes the
/// checkout (BUG-830).
pub const CLONE_INCOMPLETE: &str = ".veil/local/clone-incomplete";

/// Mark `fs` as a clone that has not finished ([`CLONE_INCOMPLETE`]).
pub fn mark_clone_incomplete(fs: &DiskBackend) -> Result<()> {
    fs.write(&VPath::new(CLONE_INCOMPLETE)?, b"vl clone did not finish\n")?;
    Ok(())
}

/// The clone in `fs` finished ([`CLONE_INCOMPLETE`]).
pub fn mark_clone_complete(fs: &DiskBackend) -> Result<()> {
    fs.remove_file(&VPath::new(CLONE_INCOMPLETE)?)?;
    Ok(())
}

/// Refuse a clone killed before it fetched everything (see
/// [`CLONE_INCOMPLETE`]).
fn check_clone_finished(root: &Path) -> Result<()> {
    if !root.join(CLONE_INCOMPLETE).exists() {
        return Ok(());
    }
    if root.join(veil_core::working_copy::CHECKOUT_STATE_PATH).exists() {
        // Everything was fetched; the checkout's journal finishes it.
        let _ = std::fs::remove_file(root.join(CLONE_INCOMPLETE));
        return Ok(());
    }
    bail!(
        "{} is a clone that was interrupted before it fetched the project: remove it and clone again",
        root.display()
    )
}

pub fn find_root(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start);
    while let Some(d) = cur {
        if d.join(VEIL_DIR).join("repo.json").is_file() {
            return Some(d.to_path_buf());
        }
        // Never from inside a `vl ws exec` sandbox
        // (`.veil/local/sandboxes/<ws>/files`): `vl` run by the command
        // there must not act on the project directory above it.
        if veil_core::sandbox::is_sandboxes_dir(d) {
            return None;
        }
        cur = d.parent();
    }
    None
}

pub fn save_checkout(fs: &DiskBackend, st: &CheckoutState) -> Result<()> {
    st.save(fs)?;
    Ok(())
}

/// How long `vl watch` leaves a working copy that another command moved
/// alone before recovering it itself (that command may still be checking
/// it out; see [`Ctx::behind`]).
pub const WATCH_YIELD: std::time::Duration = std::time::Duration::from_secs(10);

/// The checkout record of the directory, or a fresh one for `default`.
fn load_state(fs: &DiskBackend, repo: &Repo) -> Result<CheckoutState> {
    Ok(match CheckoutState::load(fs)? {
        Some(st) => st,
        None => CheckoutState::new(DEFAULT_WORKSPACE, repo.workspace_wc(DEFAULT_WORKSPACE)?, Materialised::default()),
    })
}

/// The workspace the directory belongs to, or another one if that one was
/// removed.
fn attached_workspace(repo: &Repo, st: &CheckoutState) -> Result<String> {
    let ws = st.attached().to_string();
    if repo.view().workspaces.contains_key(&ws) {
        return Ok(ws);
    }
    let fallback = repo
        .view()
        .workspaces
        .keys()
        .next()
        .cloned()
        .ok_or_else(|| anyhow!("repository has no workspaces"))?;
    warn_untrusted(&format!("workspace '{ws}' no longer exists; attaching to '{fallback}'"));
    Ok(fallback)
}

/// How many times [`Ctx::record`] looks at the working copy before giving
/// up because other commands keep moving it.
const RECORD_ATTEMPTS: u32 = 10;

/// The pause before look `attempt` (from 1) of [`Ctx::record`]: 5 ms
/// doubling, at most 200 ms, plus up to half again of jitter so that
/// processes that lost together do not look again together.
fn record_backoff(attempt: u32) -> std::time::Duration {
    let base = (5u64 << attempt.saturating_sub(1).min(6)).min(200);
    let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos() as u64);
    let jitter = (seed ^ u64::from(std::process::id())) % (base / 2 + 1);
    std::time::Duration::from_millis(base + jitter)
}

impl Ctx {
    pub fn open(repo_arg: Option<&Path>, snapshot: bool) -> Result<Ctx> {
        let start = match repo_arg {
            Some(p) => p.to_path_buf(),
            None => std::env::current_dir()?,
        };
        let root = find_root(&start).ok_or_else(|| anyhow!("no Veil repository found in {} or its parents (run `vl init`)", start.display()))?;
        check_clone_finished(&root)?;
        // The stat cache of the workspace the directory is attached to
        // (most of opening a large working copy) is read meanwhile; used
        // only if that is the workspace the session attaches to.
        let early_cache = {
            let root = root.clone();
            std::thread::Builder::new()
                .name("veil-statcache".into())
                .spawn(move || {
                    let fs = DiskBackend::new(&root);
                    let ws = match CheckoutState::load(&fs).ok()? {
                        Some(st) => st.attached().to_string(),
                        None => DEFAULT_WORKSPACE.to_string(),
                    };
                    veil_core::workspace::validate_workspace_name(&ws).ok()?;
                    Some((StatCache::load(&fs, &cache_path(&ws)), ws))
                })
                .ok()
        };
        if snapshot {
            // The snapshot may scan changed files: the scanner's rules
            // compile on another thread meanwhile, as do the policy's.
            veil_core::secrets::prepare();
            veil_core::policy::prepare();
            // What was written in mounted workspaces is recorded first, as
            // the project directory is below.
            crate::mount::record_live(&root);
        }
        let identity = load_identity()?;
        let user = user_for(&identity);
        let fs = Arc::new(DiskBackend::new(&root));
        let mut repo = Repo::open(fs.clone(), Some(identity.clone()), &user)?;
        // A thin clone reads what it has not fetched from its server.
        crate::thin::attach(&repo, &identity);
        // A clone of a server project trusts only the key rings of the
        // project fingerprint this device confirmed, before anything seals
        // (BUG-845). (A repository that will create its project, at its first
        // push, records none until then.)
        if let Some(Ok(url)) = repo.config().remotes.get("origin").and_then(|r| crate::hub::HubUrl::parse(&r.url)) {
            if repo.keys().anchor().is_none() {
                if let Some(a) = crate::hub::anchor_for(&url.authority, &url.project)? {
                    repo.keys().set_anchor(&a)?;
                }
            }
        }
        // This device's diff and merge drivers (`.veilattributes` only names them).
        crate::attr_cmd::register(&repo, &root);
        if repo.view().workspaces.is_empty() {
            let checkout = CheckoutState::new(DEFAULT_WORKSPACE, repo.root_id(), Materialised::default());
            return Ok(Ctx {
                root,
                cache: StatCache::default(),
                fs,
                repo,
                ws: DEFAULT_WORKSPACE.to_string(),
                checkout,
                report: BuildReport::default(),
                bare: true,
                committed_from: None,
                detached: false,
            });
        }
        let checkout = load_state(&fs, &repo)?;
        let ws = attached_workspace(&repo, &checkout)?;
        // The operations of this command are for the attached workspace
        // (`vl undo` there undoes them; format 6).
        repo.set_command_workspace(Some(ws.clone()));
        let cache = match early_cache.and_then(|h| h.join().ok().flatten()) {
            Some((cache, read_for)) if read_for == ws => cache,
            _ => StatCache::load(&*fs, &cache_path(&ws)),
        };
        let mut ctx = Ctx {
            root,
            fs,
            repo,
            ws,
            checkout,
            report: BuildReport::default(),
            cache,
            bare: false,
            committed_from: None,
            detached: false,
        };
        if snapshot {
            ctx.snapshot()?;
        }
        Ok(ctx)
    }

    /// The repository at `root`, for a command of workspace `ws` (the
    /// workspace socket, `crate::ws_socket`): what its mounts hold is
    /// recorded first, as for any command, and `@` is `ws`'s working-copy
    /// change. The project directory is left as it is: never recorded,
    /// moved or attached to `ws`.
    pub fn open_for_workspace(root: &Path, ws: &str) -> Result<Ctx> {
        crate::mount::record_live(root);
        let mut ctx = Ctx::open(Some(root), false)?;
        if ctx.bare {
            bail!("{} is a bare repository: it has no workspaces", ctx.root.display());
        }
        ctx.repo.workspace_wc(ws)?;
        ctx.ws = ws.to_string();
        ctx.repo.set_command_workspace(Some(ctx.ws.clone()));
        ctx.detached = true;
        Ok(ctx)
    }

    /// The project directory's stat cache (what its files hold, as far as
    /// the last snapshot verified).
    pub fn stat_cache(&self) -> &StatCache {
        &self.cache
    }

    /// The record of what the working copy was materialised from.
    pub fn materialised(&self) -> &veil_core::checkout::Materialised {
        &self.checkout.materialised
    }

    /// The working copy's change moved to its person's current view, which
    /// no longer names `paths` (BUG-1509): recorded before the working copy
    /// follows, so what it holds there stays the person's, never recorded.
    pub fn mark_lost(&mut self, paths: &[(VPath, Option<ObjectId>)]) -> Result<()> {
        if paths.is_empty() {
            return Ok(());
        }
        self.checkout.materialised.mark_lost(paths.iter().cloned());
        save_checkout(&self.fs, &self.checkout)
    }

    pub fn wc(&self) -> Result<ObjectId> {
        if self.bare {
            return Err(anyhow!("this is a bare repository (an old path remote): it has no working copy"));
        }
        Ok(self.repo.workspace_wc(&self.ws)?)
    }

    pub fn rev(&self, spec: &str) -> Result<ObjectId> {
        // A thin clone: a full snapshot id it does not hold is asked of the
        // server, and a walk that reaches beyond what it holds goes on
        // through the server's history pages.
        if self.repo.is_partial() {
            if let Ok(id) = veil_core::ObjectId::from_hex(spec.trim().trim_end_matches('-')) {
                if !self.repo.store().has(&id) {
                    self.repo.deepen(&[id], 1)?;
                }
            }
        }
        // (`main-` names a parent the clone may not hold yet: reading it
        // fetches it, `Exact::snapshot`.)
        // Names a thin clone's held history cannot decide are asked of the
        // server (`revset::server_names`); no paging here.
        Ok(revset::resolve(&self.repo, spec, &self.ws)?)
    }

    /// Record the project directory into the attached workspace.
    pub fn snapshot(&mut self) -> Result<()> {
        self.record(None, false, &[])
    }

    /// Record the project directory as operation `description`: for commands
    /// that edit the working copy themselves (`vl expose`, `vl restore`, …),
    /// so that `vl undo` reverts them instead of skipping them as the
    /// user's uncommitted edits.
    pub fn snapshot_as(&mut self, description: String) -> Result<()> {
        self.record(Some(description), false, &[])
    }

    /// Record the project directory as operation `description` after `vl
    /// restore` wrote the versions `carried`
    /// into the directory: those files are recorded as the entries they
    /// were written from (their sealing, or the conflict as it was), not as
    /// edits of `@`'s (BUG-481). With `policy_incoming`, the command wrote
    /// `.veilpolicy` from another revision: it is guarded by the accepted
    /// policy like any incoming change, never taken as the member's edit.
    pub fn snapshot_restored(&mut self, description: String, policy_incoming: bool, carried: &[(VPath, veil_core::TreeEntry)]) -> Result<()> {
        self.record(Some(description), policy_incoming, carried)
    }

    /// `vl commit`: record the project directory and commit it as one
    /// operation (one transaction; `vl undo` takes back both). If the
    /// directory was stale, its recovery is recorded first and the commit
    /// is its own operation.
    pub fn commit(&mut self, message: &str, advance: bool) -> Result<veil_core::commands::CommitResult> {
        if !self.bare {
            veil_core::secrets::prepare();
            crate::mount::record_live(&self.root);
            let mut committed = None;
            let before = self.wc()?;
            self.record_into(None, false, &[], Some((message, advance)), &mut committed)?;
            if let Some(r) = committed {
                self.committed_from = Some(before);
                return Ok(r);
            }
        }
        let ws = self.ws.clone();
        Ok(self.repo.commit(&ws, message, advance)?)
    }

    fn record(&mut self, description: Option<String>, policy_incoming: bool, carried: &[(VPath, veil_core::TreeEntry)]) -> Result<()> {
        self.record_into(description, policy_incoming, carried, None, &mut None)
    }

    /// [`Ctx::record`], committing what it records when `commit` is given
    /// (the result in `committed`, unless the directory was stale).
    fn record_into(
        &mut self,
        description: Option<String>,
        policy_incoming: bool,
        carried: &[(VPath, veil_core::TreeEntry)],
        commit: Option<(&str, bool)>,
        committed: &mut Option<veil_core::commands::CommitResult>,
    ) -> Result<()> {
        // A detached command records nothing of the directory: its
        // workspace's files were recorded before it ran (mounts, the
        // sandbox's).
        if self.detached {
            if let Some((message, advance)) = commit {
                let ws = self.ws.clone();
                *committed = Some(self.repo.commit(&ws, message, advance)?);
            }
            return Ok(());
        }
        // One recorder of this directory at a time (the lock-free op log
        // has no repository lock to serialise them), judging it by what it
        // holds now (BUG-1084).
        let _wc = self.lock_dir(None)?;
        // A copy of a secret share this device would now seal for the
        // folder's people never enters history (docs/HUB.md §13.17).
        crate::share_cmd::hold_back_received(self);
        // A move of the directory that a previous command started and did
        // not finish (killed, disk full): finish it before recording
        // anything, or the half-moved directory would be recorded as the
        // edit of the workspace it was leaving.
        self.resume()?;
        // Another process may move the workspace between our look at it and
        // the snapshot's transaction; the snapshot then records nothing, and
        // we look again (the directory is stale now). Each look loses only
        // to a command that did move it, so with several `vl` running here
        // at once (an editor, a script, a hook) a few looks can lose in a
        // row: up to RECORD_ATTEMPTS, backing off (5 ms doubling to 200 ms,
        // with jitter, about 1 s in all) so that the racers spread out.
        for attempt in 0..RECORD_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(record_backoff(attempt));
            }
            if self.record_once(description.clone(), policy_incoming, carried, commit, committed)? {
                return Ok(());
            }
            // The process that moved it also recorded what the directory
            // now holds: read that too, or the directory would be judged
            // against the snapshot it held before, look stale, and have
            // its newest edits moved out of it (BUG-362).
            self.refresh()?;
            self.resume()?;
        }
        bail!("the working copy keeps moving under this command (another `vl` is running here?); try again")
    }

    /// One attempt of [`Ctx::record`]; `false` if the workspace moved
    /// before the snapshot could be recorded.
    fn record_once(
        &mut self,
        description: Option<String>,
        policy_incoming: bool,
        carried: &[(VPath, veil_core::TreeEntry)],
        commit: Option<(&str, bool)>,
        committed: &mut Option<veil_core::commands::CommitResult>,
    ) -> Result<bool> {
        let view_wc = self.wc()?;
        let disk = self.fs.clone();
        let fs: &dyn StorageBackend = &*disk;
        // Whatever became readable since the directory was materialised
        // (a grant, an embargo release) is filled in first; otherwise the
        // snapshot would record it as deleted, or reverted to the fallback.
        self.fill_in()?;
        let mut stale = self.checkout.workspace != self.ws
            || (self.checkout.snapshot != view_wc && self.repo.store().has(&self.checkout.snapshot));
        // The repository moved on, but everything it changed is already in
        // the directory: another command recorded this very directory (a
        // snapshot), or moved `@` to the same tree (`commit`, `new`), and
        // has not rewritten the checkout record yet. The directory is not
        // behind; edits made since belong in `@`, on disk, not in a side
        // change taken out of the directory (BUG-361, BUG-362).
        if stale && self.directory_holds(view_wc)? {
            self.checkout.snapshot = view_wc;
            save_checkout(&self.fs, &self.checkout)?;
            stale = false;
        }
        if stale {
            // The directory reflects `checkout.snapshot`, but the repository
            // moved on (undo, another process, removed workspace). Preserve
            // any local edits as their own change, then catch up.
            let base = self.checkout.snapshot;
            let base_snap = self.repo.snapshot(&base)?;
            let target_tree = self.repo.snapshot(&view_wc)?.tree;
            // A thin clone fetches the catch-up's move first. If it cannot
            // (a full cache, a lost server), the directory stays as it is
            // and nothing is recorded, so `status`, `undo`, `op restore`
            // and `partial limit` still run (BUG-1146); a command that
            // would record the directory as a commit stops instead.
            if let Err(e) = self.repo.store().prefetch_diff(Some(&base_snap.tree), &target_tree) {
                if commit.is_some() {
                    return Err(anyhow::Error::from(e).context(
                        "the working copy is behind `@` and cannot be brought up to it; run `vl undo`, or raise the cache's bound with `vl partial limit SIZE`",
                    ));
                }
                warn(&format!(
                    "the working copy stays as it is: moving it to `@` needs what this thin clone cannot fetch now ({e}). \
                     Nothing in it was recorded; run `vl undo` to go back, or `vl partial limit SIZE` and run any command"
                ));
                return Ok(true);
            }
            // What a command put back (`vl restore`) is judged against the
            // entries it was written from, as in the ordinary snapshot
            // below: a sealed version restored stays sealed (BUG-492).
            let (tree, report) = self.repo.build_amending_carried(
                fs,
                &base,
                Some(&mut self.cache),
                Some(&self.checkout.materialised),
                carried,
            )?;
            // The snapshot the directory now holds: what it was checked out
            // from, the edits saved on top of it, or already the target.
            let mut holds = base;
            if tree == target_tree {
                // Directory already matches (e.g. interrupted after checkout).
                holds = view_wc;
            } else if tree != base_snap.tree {
                let (saved, _) = self.repo.commit_fs_as_child_with(
                    base,
                    fs,
                    "recovered working-copy edits",
                    None,
                    Some(&self.checkout.materialised),
                    carried,
                    false,
                )?;
                let s = self.repo.snapshot(&saved)?;
                holds = saved;
                warn(&format!(
                    "the working copy was stale; your edits were saved as change {}",
                    s.change_id.short()
                ));
            }
            print_working_copy_warnings(&report);
            self.report = report;
            // Journalled like any move: a crash half way is finished by the
            // next command instead of being saved as another "recovery".
            self.checkout.snapshot = holds;
            let ws = self.ws.clone();
            let co = self
                .repo
                .move_working_copy(fs, &mut self.checkout, &ws, view_wc, Some(&mut self.cache))?;
            print_kept_local(&co.kept_local);
            print_blocked(&co.blocked);
            print_obstructed(&co.obstructed);
            print_nested(&co.nested);
            print_failed(&co.failed);
            print_checkout_warnings(&co.warnings);
            self.save_cache();
            return Ok(true);
        }
        let out = self.repo.snapshot_workspace_with(
            &self.ws,
            fs,
            SnapshotOptions {
                cache: Some(&mut self.cache),
                materialised: Some(&self.checkout.materialised),
                description,
                policy_incoming,
                expected_wc: Some(view_wc),
                carried,
                commit,
                ..Default::default()
            },
        )?;
        if out.superseded {
            return Ok(false);
        }
        *committed = out.committed;
        self.save_cache();
        self.repo.capture_local_files(fs, &out.report)?;
        render::print_build_warnings(&out.report);
        print_working_copy_warnings(&out.report);
        self.report = out.report;
        if self.checkout.snapshot != out.snapshot {
            self.checkout.snapshot = out.snapshot;
            save_checkout(&self.fs, &self.checkout)?;
        }
        Ok(true)
    }

    /// Record the project directory as operation `description`, with line
    /// endings as `line_endings` says (`vl renormalize`). Under the lock, as
    /// every recording (BUG-1125); a directory another command moved since
    /// this one started is not renormalized.
    pub fn snapshot_with_line_endings(&mut self, description: String, line_endings: veil_core::builder::LineEndings<'_>) -> Result<BuildReport> {
        let _wc = self.lock_dir(None)?;
        self.resume()?;
        if self.behind()? {
            bail!("the working copy moved while this command ran (another `vl` is running here?); try again");
        }
        let view_wc = self.wc()?;
        let disk = self.fs.clone();
        let fs: &dyn StorageBackend = &*disk;
        let out = self.repo.snapshot_workspace_with(
            &self.ws,
            fs,
            SnapshotOptions {
                cache: Some(&mut self.cache),
                materialised: Some(&self.checkout.materialised),
                description: Some(description),
                expected_wc: Some(view_wc),
                line_endings,
                ..Default::default()
            },
        )?;
        if out.superseded {
            bail!("the working copy moved while this command ran (another `vl` is running here?); try again");
        }
        self.save_cache();
        self.repo.capture_local_files(fs, &out.report)?;
        if self.checkout.snapshot != out.snapshot {
            self.checkout.snapshot = out.snapshot;
            save_checkout(&self.fs, &self.checkout)?;
        }
        Ok(out.report)
    }

    /// Does the directory already hold every change from the snapshot it
    /// was last recorded at to `target`, the attached workspace's `@`?
    fn directory_holds(&mut self, target: ObjectId) -> Result<bool> {
        if self.checkout.workspace != self.ws || self.checkout.pending.is_some() {
            return Ok(false);
        }
        let base = self.repo.snapshot(&self.checkout.snapshot)?;
        let to = self.repo.snapshot(&target)?.tree;
        if base.tree == to {
            return Ok(true);
        }
        let disk = self.fs.clone();
        let (now, _) = self.repo.build_from_recorded(
            &*disk,
            Some(base.tree),
            Some(&mut self.cache),
            Some(&self.checkout.materialised),
        )?;
        let store = self.repo.store();
        for c in veil_core::tree::diff_trees(store, Some(&base.tree), Some(&to))? {
            if lookup(store, &now, &c.path)? != c.new {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Finish a move of the directory that was interrupted (see
    /// [`veil_core::working_copy`]).
    fn resume(&mut self) -> Result<()> {
        if self.checkout.pending.is_none() {
            return Ok(());
        }
        let target = self.checkout.attached().to_string();
        if let Some(r) = self
            .repo
            .resume_working_copy(&*self.fs, &mut self.checkout, Some(&mut self.cache))?
        {
            eprintln!(
                "{} the interrupted move of the working copy to workspace '{}'",
                render::green("Finished"),
                safe(&target)
            );
            if r.written + r.removed > 0 {
                eprintln!("Updated {} files, removed {}", r.written, r.removed);
            }
            print_kept_local(&r.kept_local);
            print_blocked(&r.blocked);
            print_obstructed(&r.obstructed);
            print_nested(&r.nested);
            print_failed(&r.failed);
            print_checkout_warnings(&r.warnings);
        }
        self.save_cache();
        Ok(())
    }

    /// Re-read the view and the directory's checkout record: another `vl`
    /// command may have moved the working copy since this session started
    /// (`vl watch` runs for hours).
    pub fn refresh(&mut self) -> Result<()> {
        self.repo.reload()?;
        self.checkout = load_state(&self.fs, &self.repo)?;
        let ws = attached_workspace(&self.repo, &self.checkout)?;
        if ws != self.ws {
            self.cache = StatCache::load(&*self.fs, &cache_path(&ws));
            self.repo.set_command_workspace(Some(ws.clone()));
            self.ws = ws;
        }
        Ok(())
    }

    /// Is the directory behind the repository: is a move of it unfinished,
    /// or does the attached workspace point elsewhere than what was last
    /// materialised? Right after another command moved the working copy,
    /// that command may still be checking it out.
    pub fn behind(&self) -> Result<bool> {
        let view_wc = self.wc()?;
        Ok(self.checkout.pending.is_some()
            || self.checkout.workspace != self.ws
            || (self.checkout.snapshot != view_wc && self.repo.store().has(&self.checkout.snapshot)))
    }

    /// Materialise what was unreadable when the directory was checked out
    /// and is readable now (see [`Materialised::fill_in`]). Local edits are
    /// never overwritten.
    fn fill_in(&mut self) -> Result<()> {
        if self.checkout.materialised.is_empty() || !self.repo.store().has(&self.checkout.snapshot) {
            return Ok(());
        }
        let tree = self.repo.snapshot(&self.checkout.snapshot)?.tree;
        let mut record = self.checkout.materialised.clone();
        let co = self
            .repo
            .fill_in_materialised(&*self.fs, &tree, &mut record, Some(&mut self.cache))?;
        if record != self.checkout.materialised {
            self.checkout.materialised = record;
            save_checkout(&self.fs, &self.checkout)?;
            self.save_cache();
        }
        print_filled_in(&co);
        Ok(())
    }

    /// Lock the project directory for recording or checkout
    /// ([`veil_core::lock::WcLock`]: the lock of the workspace it is
    /// attached to, and of `to`, a workspace this command moves it to), then
    /// read again what it holds and where the workspace points
    /// ([`Ctx::refresh`]). Read before the lock, both may predate another
    /// `vl` that recorded or moved the directory while this one waited: the
    /// directory then looked stale, and its edits were moved into a side
    /// change and out of it (BUG-1084). If the directory was attached
    /// elsewhere meanwhile, that workspace is locked instead (BUG-1121).
    ///
    /// A command that writes into the directory itself (`vl restore`, the
    /// policy commands) holds it from before it reads the directory until
    /// its closing snapshot (BUG-1125); the lock is re-entrant within a
    /// process.
    pub fn lock_dir(&mut self, to: Option<&str>) -> Result<Vec<veil_core::lock::WcLock>> {
        if self.bare {
            return Ok(Vec::new());
        }
        for _ in 0..RECORD_ATTEMPTS {
            let attached = self.ws.clone();
            let mut names = vec![attached.as_str()];
            names.extend(to);
            // One order for every process, so two never wait for each other.
            names.sort_unstable();
            names.dedup();
            let state = veil_core::repo::state_dir(&self.root);
            let locks = names
                .iter()
                .map(|ws| veil_core::lock::WcLock::acquire(&state, ws))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            self.refresh()?;
            if self.ws == attached {
                return Ok(locks);
            }
        }
        bail!("the working copy keeps moving under this command (another `vl` is running here?); try again")
    }

    /// Print what merges of concurrent operations decided (once: only the
    /// process that wrote the merge prints it).
    pub fn print_merge_warnings(&mut self) {
        for w in self.repo.take_warnings() {
            warn(&w);
        }
    }

    /// The snapshots this command's view of the project directory names
    /// (the checkout pointer as it read it): `vl gc` keeps them, as this
    /// command reads them when it finishes, even if another command moved
    /// the directory meanwhile.
    pub fn checkout_roots(&self) -> Vec<veil_core::ObjectId> {
        std::iter::once(self.checkout.snapshot).chain(self.checkout.pending.as_ref().map(|p| p.snapshot)).collect()
    }

    /// Bring the project directory in line with the attached workspace.
    pub fn finish(&mut self) -> Result<()> {
        self.print_merge_warnings();
        if self.bare || self.detached {
            return Ok(());
        }
        // A workspace this command attached the directory to (`vl ws
        // switch`, undoing one) is where it goes; otherwise it follows what
        // its record says now, under the lock.
        let to = (self.ws != self.checkout.attached()).then(|| std::mem::replace(&mut self.ws, self.checkout.attached().to_string()));
        let _wc = self.lock_dir(to.as_deref())?;
        // The re-read may have merged heads that landed meanwhile: only the
        // process that writes a merge says what it decided (BUG-1126).
        self.print_merge_warnings();
        if let Some(ws) = to {
            self.attach(&ws)?;
        }
        if self.checkout.pending.is_some() {
            self.resume()?;
        }
        let target = self.wc()?;
        if self.committed_from.take().is_some_and(|f| f != target) {
            eprintln!("Working copy now at: {}", render::one_line(&self.repo, &target));
        }
        let moved = target != self.checkout.snapshot || self.checkout.workspace != self.ws;
        if !moved && self.checkout.materialised.is_empty() {
            return Ok(());
        }
        if !moved {
            // Same snapshot, but this command may have made more of it
            // readable (`vl pull` brought a grant, `vl embargo release`).
            return self.fill_in();
        }
        let from = self.repo.snapshot(&self.checkout.snapshot)?.tree;
        let to_snap = self.repo.snapshot(&target)?;
        // A thin clone: a move this command could not fetch for (left by an
        // earlier one; every move this command published was fetched ahead
        // before it was) leaves the directory as it is (BUG-1146).
        if let Err(e) = self.repo.store().prefetch_diff(Some(&from), &to_snap.tree) {
            warn(&format!(
                "the working copy stays as it is: moving it to `@` needs what this thin clone cannot fetch now ({e}). \
                 Run `vl undo` to go back, or `vl partial limit SIZE` and run any command"
            ));
            return Ok(());
        }
        let previous = self.checkout.snapshot;
        let needs_checkout = from != to_snap.tree || !self.checkout.materialised.is_empty();
        // Journalled: a crash half way is finished by the next command.
        let ws = self.ws.clone();
        let r = self
            .repo
            .move_working_copy(&*self.fs, &mut self.checkout, &ws, target, Some(&mut self.cache))?;
        let report = needs_checkout.then_some(r);
        self.save_cache();
        if let Some(r) = report {
            if r.written + r.removed > 0 {
                eprintln!("Updated {} files, removed {}", r.written, r.removed);
            }
            for p in &r.redacted {
                let e = lookup(self.repo.store(), &to_snap.tree, p)?;
                // A folder the server refuses (BUG-1508): its path only.
                if e.as_ref().is_some_and(|e| e.kind == veil_core::EntryKind::Dir) {
                    eprintln!(
                        "  {} {} (you no longer have access to this folder; left out of the working copy, kept in history)",
                        render::yellow("redacted"),
                        safe(&crate::api::hidden_dir(p))
                    );
                    continue;
                }
                let why = e.and_then(|e| render::hidden_reason(&self.repo, &e));
                eprintln!(
                    "  {} {} ({}; left out of the working copy)",
                    render::yellow("redacted"),
                    safe(p.as_str()),
                    why.unwrap_or_else(|| "no key".into())
                );
            }
            for p in &r.protected {
                eprintln!(
                    "  {} {} (local-only file kept as is)",
                    render::yellow("protected"),
                    safe(p.as_str())
                );
            }
            print_kept_local(&r.kept_local);
            print_blocked(&r.blocked);
            print_obstructed(&r.obstructed);
            print_nested(&r.nested);
            print_failed(&r.failed);
            print_checkout_warnings(&r.warnings);
        }
        // A `.veilpolicy` that arrived with this checkout: say now (not at
        // the next snapshot) which local files keep their protection.
        let policy_of = |t: &ObjectId| lookup(self.repo.store(), t, &VPath::new(POLICY_FILE).expect("valid"));
        if policy_of(&from)? != policy_of(&to_snap.tree)? {
            render::print_policy_held_back(&self.repo.policy_held_back(&*self.fs)?, false);
        }
        if previous != target {
            eprintln!("Working copy now at: {}", render::one_line(&self.repo, &target));
        }
        Ok(())
    }

    /// `vl restore`: bring the paths `wanted` selects from `from` (the tree
    /// the working copy was just snapshotted as) to `to`, through
    /// checkout's rules ([`veil_core::checkout::restore_paths`]), keeping
    /// the record of what was materialised and the stat cache in step. The
    /// caller records the result with a snapshot.
    pub fn restore(&mut self, from: &ObjectId, to: &ObjectId, wanted: &dyn Fn(&VPath) -> bool) -> Result<CheckoutReport> {
        let mut record = self.checkout.materialised.clone();
        let r = veil_core::checkout::restore_paths(self.repo.store(), &*self.fs, from, to, wanted, &mut record, Some(&mut self.cache))?;
        if record != self.checkout.materialised {
            self.checkout.materialised = record;
            save_checkout(&self.fs, &self.checkout)?;
        }
        self.save_cache();
        for p in &r.redacted {
            eprintln!("  {} {} (unreadable here; not restored)", render::yellow("redacted"), safe(p.as_str()));
        }
        print_kept_local(&r.kept_local);
        print_blocked(&r.blocked);
        print_obstructed(&r.obstructed);
        print_nested(&r.nested);
        print_failed(&r.failed);
        print_checkout_warnings(&r.warnings);
        Ok(r)
    }

    /// Persist the stat cache if it changed. It is only an accelerator, so
    /// failing to write it is a warning, not an error.
    fn save_cache(&mut self) {
        if let Err(e) = self.cache.save(&*self.fs, &cache_path(&self.ws)) {
            warn(&format!("could not save the stat cache: {e}"));
        }
    }

    pub fn attach(&mut self, ws: &str) -> Result<()> {
        if !self.repo.view().workspaces.contains_key(ws) {
            bail!("no workspace named '{ws}'");
        }
        self.ws = ws.to_string();
        self.repo.set_command_workspace(Some(self.ws.clone()));
        Ok(())
    }

    /// Convert a user path to a repository path: relative to the current
    /// directory when that is inside the repository, otherwise (`-R` from
    /// elsewhere) relative to the repository's root. An absolute path, or a
    /// relative one that climbs out with `..`, must lie inside the
    /// repository: anything else is refused, never taken as a path of the
    /// repository's own (BUG-204). `\` is an ordinary character in a name
    /// on Linux and macOS.
    pub fn repo_path(&self, user: &str) -> Result<VPath> {
        let cwd = std::env::current_dir()?;
        let mut roots = vec![normalize(&self.root)];
        if let Ok(c) = std::fs::canonicalize(&self.root) {
            if c != roots[0] {
                roots.push(c);
            }
        }
        let inside = |p: &Path| roots.iter().find_map(|r| p.strip_prefix(r).ok().map(Path::to_path_buf));
        // The same path with symlinks resolved, as far as it exists.
        let resolved = |p: &Path| -> Option<PathBuf> {
            let mut tail = Vec::new();
            let mut cur = p.to_path_buf();
            loop {
                if let Ok(c) = std::fs::canonicalize(&cur) {
                    return Some(tail.iter().rev().fold(c, |acc: PathBuf, n: &std::ffi::OsString| acc.join(n)));
                }
                tail.push(cur.file_name()?.to_os_string());
                cur = cur.parent()?.to_path_buf();
            }
        };
        let given = Path::new(user);
        let abs = if given.is_absolute() {
            normalize(given)
        } else if inside(&normalize(&cwd)).is_some() {
            normalize(&cwd.join(given))
        } else {
            normalize(&roots[0].join(given))
        };
        let outside = || anyhow!("'{user}' escapes the repository: it is outside {}", self.root.display());
        let rel = match inside(&abs) {
            Some(rel) => rel,
            None => resolved(&abs).and_then(|r| inside(&r)).ok_or_else(outside)?,
        };
        let rel = rel.to_str().ok_or_else(outside)?;
        Ok(VPath::new(rel)?)
    }
}

/// Things in the working copy a snapshot could not record. Never fatal, never
/// silent. Paths and reasons come from the working copy (or a tree), so they
/// are escaped.
pub fn print_working_copy_warnings(r: &BuildReport) {
    for (p, why) in &r.unreadable {
        warn_untrusted(&format!(
            "skipped {p}: cannot read it ({why}); its last recorded version, if any, is kept. Fix its permissions or `vl ignore {p}`"
        ));
    }
    for name in &r.unrepresentable {
        warn_untrusted(&format!(
            "skipped {name}: the file name is not valid UTF-8, so Veil cannot record it. Rename it to keep it under version control"
        ));
    }
    // A symlinked `.veilpolicy` is followed: its policy warning says so.
    for p in r.shadowed.iter().filter(|p| p.as_str() != POLICY_FILE) {
        warn_untrusted(&format!(
            "{p} is tracked but is now a symlink or special file; Veil never follows it and keeps the recorded version \
             (repositories in format 5 record symlinks: `vl upgrade`)"
        ));
    }
    for (p, why) in &r.link_warnings {
        warn_untrusted(&format!("symlink {p} {why}"));
    }
    for (p, why) in &r.line_endings {
        warn_untrusted(&format!("{p}: {why}"));
    }
    for (a, b) in &r.name_collisions {
        warn_untrusted(&format!(
            "{a} and {b} differ only in case or Unicode normalisation; a checkout on a case-insensitive \
             filesystem (macOS by default) will refuse this snapshot. Rename one of them"
        ));
    }
}

/// Report files that became readable and were materialised.
fn print_filled_in(r: &CheckoutReport) {
    if r.written + r.removed > 0 {
        eprintln!(
            "{} {} file(s) that became readable (a key arrived), removed {}",
            render::green("Filled in"),
            r.written,
            r.removed
        );
    }
    print_kept_local(&r.kept_local);
    print_blocked(&r.blocked);
    print_obstructed(&r.obstructed);
    print_nested(&r.nested);
    print_failed(&r.failed);
    print_checkout_warnings(&r.warnings);
}

/// Everything a checkout left alone or could not do (`vl ws exec`'s sync of
/// its sandbox reports through this).
pub fn print_checkout_problems(r: &CheckoutReport) {
    print_kept_local(&r.kept_local);
    print_blocked(&r.blocked);
    print_obstructed(&r.obstructed);
    print_nested(&r.nested);
    print_failed(&r.failed);
    print_checkout_warnings(&r.warnings);
}

/// Paths checkout left alone because they lie in a nested repository
/// (grouped by repository).
fn print_nested(paths: &[(VPath, VPath)]) {
    let mut by_repo: std::collections::BTreeMap<&VPath, usize> = Default::default();
    for (_, repo) in paths {
        *by_repo.entry(repo).or_default() += 1;
    }
    for (repo, n) in by_repo {
        eprintln!(
            "  {} {}/ (a Veil repository of its own, which this one never records; {n} path(s) of the snapshot below it were \
             neither written nor removed)",
            render::yellow("kept"),
            safe(repo.as_str())
        );
    }
}

/// Paths the filesystem refused to write or remove (one bad name never
/// stops a checkout).
pub fn print_failed(paths: &[(VPath, String)]) {
    for (p, why) in paths {
        eprintln!(
            "  {} {} ({}; left out of the working copy and kept in history as it is; every command tries again. \
             Rename it where it can be checked out)",
            render::red("failed"),
            safe(p.as_str()),
            safe(why)
        );
    }
}

/// Problems that did not stop a checkout (an unreadable `.veilpolicy` in the
/// target, BUG-121). They come from history someone else wrote.
fn print_checkout_warnings(warnings: &[String]) {
    for w in warnings {
        warn_untrusted(w);
    }
}

/// Paths checkout did not write because something it did not write is in
/// the way (grouped by obstacle). The obstacle is the user's: kept as is.
fn print_obstructed(paths: &[(VPath, VPath)]) {
    let mut by_obstacle: std::collections::BTreeMap<&VPath, Vec<&VPath>> = Default::default();
    for (p, obstacle) in paths {
        by_obstacle.entry(obstacle).or_default().push(p);
    }
    for (obstacle, ps) in by_obstacle {
        let what = if ps.len() == 1 && ps[0] == obstacle {
            format!(
                "{}/ holds files that are in no snapshot (isolated, ignored or untracked), so the snapshot's file {} was not written",
                safe(obstacle.as_str()),
                safe(obstacle.as_str())
            )
        } else {
            let shown: Vec<String> = ps.iter().take(3).map(|p| safe(p.as_str()).into_owned()).collect();
            let more = if ps.len() > 3 { format!(" and {} more", ps.len() - 3) } else { String::new() };
            format!(
                "{} is a file that is in no snapshot, so the snapshot's {}{more} below it {} not written",
                safe(obstacle.as_str()),
                shown.join(", "),
                if ps.len() == 1 { "was" } else { "were" }
            )
        };
        eprintln!(
            "  {} {} ({what}; the next snapshot records the working copy as it is. To take the snapshot's version, \
             move {} out of the way and run `vl restore`)",
            render::yellow("kept"),
            safe(obstacle.as_str()),
            safe(obstacle.as_str())
        );
    }
}

fn print_blocked(paths: &[VPath]) {
    for p in paths {
        eprintln!(
            "  {} {} (a symlink or special file is in the way; Veil never writes through or over it)",
            render::yellow("skipped"),
            safe(p.as_str())
        );
    }
}

fn print_kept_local(paths: &[VPath]) {
    for p in paths {
        eprintln!(
            "  {} {} (local edit not in history, e.g. quarantined; left as is instead of being overwritten)",
            render::yellow("kept"),
            safe(p.as_str())
        );
    }
}

fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            c => out.push(c),
        }
    }
    out
}
