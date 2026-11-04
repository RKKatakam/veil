//! Colocated Git mode: `vl init --colocate`, `vl git colocate`,
//! `vl git uncolocate`, `vl git check-push` (the `pre-push` and
//! `pre-commit` guards) and `vl policy import-gitignore`, plus the session
//! hooks [`open_session`] and [`finish_session`] that `Ctx` calls around
//! every command.
//!
//! Feature 9 of the Git-parity round (`docs/design/git-parity/9-colocated-git.md`).
//! **Experimental**: `--experimental` is required until a dedicated
//! adversarial pass is clean. The engine side is `veil_core::git::colocate`;
//! this module adds what needs the command line: following a Git checkout
//! with the working copy (snapshots, the hidden-part checkout), the Git
//! hooks, and the commands.
//!
//! The hooks Veil installs into `.git/hooks` are device-local, written by
//! `vl` with fixed content (they run `vl git check-push` and nothing from
//! the repository), like the device-local hooks of `hooks.rs`; a hook
//! already there is kept and called first (`<name>.veil-chained`).

use std::{
    collections::{BTreeSet, HashSet},
    io::Read,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use veil_core::{
    git::{
        colocate::{self, FollowLock, Head, PushLine, State},
        index, GitBridge,
    },
    policy::POLICY_FILE,
    policy_gitignore,
    repo::Colocated,
    ObjectId, VPath,
};

use crate::{
    ctx::Ctx,
    render::{bold, cyan, dim, green, red, safe, warn, warn_untrusted, yellow},
};

/// The guide page every refusal and warning points at.
const GUIDE: &str = "docs/guide/colocated-git.md";

/// `vl init --colocate`.
#[derive(Args, Debug, Clone, Copy, Default)]
pub struct InitColocateArgs {
    /// Create (or adopt) a real `.git` beside the working copy, kept in step
    /// with Veil (experimental: needs `--experimental`).
    #[arg(long)]
    pub colocate: bool,
    /// Accept that colocated Git mode is experimental.
    #[arg(long, requires = "colocate")]
    pub experimental: bool,
}

/// `vl git colocate [--experimental] [--status | --prune]`.
#[derive(Args, Debug)]
pub struct ColocateArgs {
    /// Required while colocated mode is experimental.
    #[arg(long)]
    pub experimental: bool,
    /// Report the guards instead: exclude block, skip-worktree count, held
    /// local commits, Git version, `pre-push` hook.
    #[arg(long, conflicts_with = "prune")]
    pub status: bool,
    /// Expire the reflogs of superseded local commits and run
    /// `git gc --prune=now` (every unreachable reflog entry of `.git` is
    /// expired).
    #[arg(long)]
    pub prune: bool,
}

/// `vl git uncolocate`.
#[derive(Args, Debug)]
pub struct UncolocateArgs {}

/// `vl git check-push [REMOTE [URL]]`: Git's `pre-push` hook arguments; the
/// refs to push are read from standard input, as Git gives them.
#[derive(Args, Debug)]
pub struct CheckPushArgs {
    /// Name of the Git remote being pushed to.
    pub remote: Option<String>,
    /// URL of the Git remote being pushed to.
    pub url: Option<String>,
    /// Check what `git commit` is about to commit instead (the `pre-commit`
    /// guard; reads `$GIT_INDEX_FILE`).
    #[arg(long, hide = true)]
    pub pre_commit: bool,
}

/// `vl policy import-gitignore`.
#[derive(Args, Debug)]
pub struct ImportGitignoreArgs {}

/// What the follow at the start of a command saw (see [`open_session`]).
#[derive(Debug)]
pub struct Session {
    pub git_dir: PathBuf,
    /// `HEAD` as the follow left it; `None`: neither `HEAD` nor the index
    /// is written by this command (not followed, or `HEAD` could not be).
    pub expected_head: Option<Head>,
    /// The follow ran (and a snapshot follows): the full mirror may run.
    pub followed: bool,
    /// A Git operation in progress: only the excludes are written.
    pub in_progress: Option<&'static str>,
    /// Mirror at all (`vl git check-push` does not: it runs inside Git).
    pub mirror: bool,
}

// ---- session -------------------------------------------------------------------------------

/// The `.git` of a colocated project must be a real directory: never a
/// gitfile (a linked worktree or submodule), never a symlink.
fn check_git_dir(git_dir: &Path) -> Result<()> {
    let m = std::fs::symlink_metadata(git_dir)
        .with_context(|| format!("the colocated Git directory {} is missing (`vl git uncolocate` stops colocation)", git_dir.display()))?;
    if !m.is_dir() {
        bail!(
            "{} is not a directory (a gitfile or a symlink); colocated mode refuses it. See {GUIDE}",
            git_dir.display()
        );
    }
    Ok(())
}

fn env_points_elsewhere() -> Option<&'static str> {
    ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"]
        .into_iter()
        .find(|v| std::env::var_os(v).is_some_and(|x| !x.is_empty()))
}

/// Start of every command (`Ctx::open`): when the directory is colocated,
/// follow what Git did since the last command (with `snapshot`), and
/// remember what was seen for [`finish_session`].
pub fn open_session(ctx: &mut Ctx, snapshot: bool) -> Result<()> {
    if ctx.bare {
        return Ok(());
    }
    let Some(git_dir) = colocate::colocated_git_dir(&ctx.root) else {
        return Ok(());
    };
    check_git_dir(&git_dir)?;
    let mut session = Session {
        git_dir,
        expected_head: None,
        followed: false,
        in_progress: None,
        mirror: true,
    };
    if let Some(op) = colocate::operation_in_progress(&session.git_dir) {
        // Inside a Git hook (`git commit` holds index.lock), or a rebase:
        // the command works as usual; nothing is followed or mirrored.
        eprintln!(
            "{} Git operation in progress ({op}); Veil mirrors into .git when it ends",
            dim("note:")
        );
        session.in_progress = Some(op);
        ctx.git = Some(session);
        return Ok(());
    }
    if snapshot {
        let _lock = FollowLock::acquire(&ctx.root)?;
        follow(ctx, &mut session)?;
    }
    ctx.git = Some(session);
    Ok(())
}

/// End of every command (`Ctx::finish`): mirror into `.git` and write the
/// exclude block, before control returns to the user.
pub fn finish_session(ctx: &mut Ctx) -> Result<()> {
    let Some(session) = ctx.git.take() else { return Ok(()) };
    if !session.mirror {
        return Ok(());
    }
    let _lock = FollowLock::acquire(&ctx.root)?;
    let mut state = State::load(&**ctx.repo.backend())?;
    if session.followed {
        state.local_only = ctx
            .report
            .local_only()
            .into_iter()
            .map(|p| p.as_str().to_string())
            .chain(ctx.report.policy_held_back.iter().map(|h| h.path.as_str().to_string()))
            .collect();
    }
    let policy = ctx.repo.effective_policy(&*ctx.fs)?;
    let literal = colocate::literal_paths(&policy, state.local_only.iter().cloned());
    let mut frozen = state.frozen;
    if session.in_progress.is_none() && session.followed {
        let mut bridge = GitBridge::open(&ctx.repo, &session.git_dir)?;
        let local_only = state.local_only.clone();
        let ws = ctx.ws.clone();
        let r = bridge.mirror(&mut ctx.repo, &mut state, &ws, session.expected_head.as_ref(), &local_only)?;
        frozen = r.frozen;
        for w in &r.warnings {
            warn_untrusted(w);
        }
        for n in &r.notes {
            eprintln!("{} {}", dim("note:"), safe(n));
        }
    }
    colocate::write_exclude(&session.git_dir, &colocate::exclude_block(&policy, &literal, frozen))?;
    state.save(&**ctx.repo.backend())?;
    Ok(())
}

/// The follow (see `veil_core::git::colocate`): local commits, then
/// `HEAD`.
fn follow(ctx: &mut Ctx, session: &mut Session) -> Result<()> {
    let mut state = State::load(&**ctx.repo.backend())?;
    let mut bridge = GitBridge::open(&ctx.repo, &session.git_dir)?;
    let r = bridge.follow_local(&mut ctx.repo, &mut state)?;
    print_follow(&r);
    let head = bridge.head()?;
    let last = state
        .last_head
        .as_deref()
        .and_then(|h| veil_core::git::GitOid::from_hex(h.as_bytes()).ok());
    let mut expected = Some(head.clone());
    if let Some(h) = head.commit.filter(|h| Some(*h) != last) {
        match bridge.snapshot_of(&h) {
            Some(target) => follow_head(ctx, &bridge, &state, target, &h)?,
            None => {
                let why = r
                    .failed
                    .iter()
                    .find(|(c, _)| *c == h)
                    .map(|(_, w)| w.clone())
                    .unwrap_or_else(|| "not imported".into());
                warn_untrusted(&format!(
                    "Git HEAD ({}) could not be imported ({why}); the working copy stays where it is and Veil leaves HEAD alone",
                    h.to_hex_with_len(10)
                ));
                expected = None;
            }
        }
    }
    if expected.is_some() {
        state.last_head = head.commit.map(|c| c.to_string());
        state.last_head_ref = head.symbolic.clone();
    }
    state.save(&**ctx.repo.backend())?;
    session.expected_head = expected;
    session.followed = true;
    Ok(())
}

fn print_follow(r: &colocate::FollowReport) {
    if r.imported > 0 {
        eprintln!("{} {} commit(s) from the colocated .git", green("Imported"), r.imported);
    }
    for (old, new, why) in &r.superseded {
        eprintln!(
            "  {} local Git commit {} {} (Veil keeps it private); replaced by {} on its branch",
            red("held"),
            old.to_hex_with_len(10),
            safe(why),
            new.to_hex_with_len(10)
        );
    }
    if !r.superseded.is_empty() {
        eprintln!(
            "{} the held commit(s) stay in .git until `vl git colocate --prune`; `git push` refuses them",
            yellow("note:")
        );
    }
    for (tag, sid) in &r.tags_moved {
        match sid {
            Some(s) => eprintln!("  {} tag {} → {} (follows its Git branch)", dim("moved"), cyan(&safe(tag)), s.short()),
            None => eprintln!("  {} tag {} (its Git branch was deleted)", dim("deleted"), cyan(&safe(tag))),
        }
    }
    for (tag, old) in &r.kept_heads {
        warn_untrusted(&format!(
            "Git branch {tag} was rewritten; Veil's previous {} stays visible (nothing Git could not see is dropped)",
            old.short()
        ));
    }
    for w in &r.warnings {
        warn_untrusted(w);
    }
}

/// The paths Git manages now: stage-0 entries without skip-worktree that
/// Veil did not hide (`state`), whose entry in `target` is plain public
/// content. Git wrote those itself on checkout; everything else is
/// Veil's to move.
fn managed_paths(ctx: &Ctx, bridge: &GitBridge, state: &State, target: &ObjectId) -> Result<HashSet<String>> {
    let Some(entries) = index::read(&index::index_path(bridge.git_dir()))? else {
        return Ok(HashSet::new());
    };
    let mut ours: HashSet<String> = state.skip.iter().cloned().collect();
    if state.frozen {
        if let Some(h) = state.index_head.as_deref().and_then(|h| veil_core::git::GitOid::from_hex(h.as_bytes()).ok()) {
            if let Ok(c) = bridge.read_commit(&h) {
                ours.extend(bridge.flatten_tree(&c.tree)?.keys().map(|p| colocate::escape_git_path(p)));
            }
        }
    }
    let public = colocate::public_plain(&ctx.repo, &ctx.repo.snapshot(target)?.tree);
    Ok(entries
        .into_iter()
        .filter(|e| e.stage == 0 && !e.skip_worktree && e.mode != 0o040000)
        .filter(|e| public.contains(&e.path))
        .filter_map(|e| String::from_utf8(e.path).ok())
        .filter(|p| !ours.contains(p))
        .collect())
}

/// `HEAD` moved in Git (a `git checkout`, `git commit`, `git reset`): the
/// working copy follows it to `target` (step 3 of the follow).
fn follow_head(ctx: &mut Ctx, bridge: &GitBridge, state: &State, target: ObjectId, commit: &veil_core::git::GitOid) -> Result<()> {
    let old = ctx.wc()?;
    let old_snap = ctx.repo.snapshot(&old)?;
    if old == target || old_snap.parents == [target] {
        return Ok(());
    }
    let managed = managed_paths(ctx, bridge, state, &target)?;
    // 1. What the hidden files hold now goes into the old change first.
    if managed.is_empty() {
        ctx.snapshot()?;
    } else {
        let store = ctx.repo.store().clone();
        let mut hidden: BTreeSet<VPath> = BTreeSet::new();
        for t in [old_snap.tree, ctx.repo.snapshot(&target)?.tree] {
            for (p, _) in veil_core::tree::walk_files(&store, &t)? {
                if !managed.contains(p.as_str()) {
                    hidden.insert(p);
                }
            }
        }
        if let Some(set) = veil_core::vfs::SparseSet::new(hidden) {
            ctx.snapshot_only(&set)?;
        }
    }
    let old = ctx.wc()?;
    // 2–3. A new change on the target, with the hidden part moved by Veil.
    let ws = ctx.ws.clone();
    let plan = colocate::plan_head_move(&ctx.repo, &ws, old, target, &managed)?;
    let old_tree = ctx.repo.snapshot(&old)?.tree;
    let (new, kept) = colocate::apply_head_move(&mut ctx.repo, &ws, old, target, &plan)?;
    if !plan.write.is_empty() {
        let write = plan.write.clone();
        ctx.restore(&old_tree, &plan.tree, &|p: &VPath| write.contains(p))?;
    }
    ctx.set_materialised_snapshot(new)?;
    let change = ctx.repo.snapshot(&new)?.change_id;
    eprintln!(
        "{} Git HEAD to {}: the working copy is now change {} on it",
        green("Followed"),
        commit.to_hex_with_len(10),
        change.short()
    );
    if kept {
        let c = ctx.repo.snapshot(&old)?.change_id;
        eprintln!("  {} the previous working-copy change {} stays as it was", dim("kept"), c.short());
    }
    for p in &plan.conflicts {
        eprintln!(
            "  {} {} (changed here and in the checked-out commit; your version stays in the previous change)",
            yellow("kept"),
            safe(p.as_str())
        );
    }
    Ok(())
}

// ---- hooks ---------------------------------------------------------------------------------

const HOOK_MARK: &str = "# veil colocated guard (generated by `vl git colocate`)";
const CHAINED: &str = ".veil-chained";

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The script Veil installs as `.git/hooks/<name>`: run the chained hook
/// first (same arguments and input), then the guard. A missing `vl`
/// refuses (fail closed).
fn hook_script(name: &str, vl: &Path) -> String {
    let check = match name {
        "pre-push" => "\"$VL\" -R \"$ROOT\" git check-push \"$@\"",
        _ => "\"$VL\" --no-snapshot -R \"$ROOT\" git check-push --pre-commit",
    };
    format!(
        "#!/bin/sh\n{HOOK_MARK}\n\
         # Refuses a Git {name} that would let content Veil keeps private into Git.\n\
         # Removed by `vl git uncolocate`; see {GUIDE}.\n\
         VL={vl}\n\
         HOOKS=$(cd \"$(dirname \"$0\")\" && pwd)\n\
         ROOT=$(cd \"$HOOKS/../..\" && pwd)\n\
         input=$(cat)\n\
         if [ -x \"$HOOKS/{name}{CHAINED}\" ]; then\n\
         \tprintf '%s\\n' \"$input\" | \"$HOOKS/{name}{CHAINED}\" \"$@\" || exit $?\n\
         fi\n\
         if [ ! -x \"$VL\" ]; then\n\
         \tVL=$(command -v vl) || {{ echo \"veil: vl not found; refusing ({name} guard of colocated mode)\" >&2; exit 1; }}\n\
         fi\n\
         printf '%s\\n' \"$input\" | {check}\n",
        vl = sh_quote(&vl.to_string_lossy()),
    )
}

const HOOK_NAMES: [&str; 2] = ["pre-push", "pre-commit"];

/// `core.hooksPath`, if the user set one (Git then ignores `.git/hooks`).
fn hooks_path_config(git_dir: &Path) -> Option<String> {
    let out = git_cmd(git_dir).args(["config", "--get", "core.hooksPath"]).output().ok()?;
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !v.is_empty()).then_some(v)
}

fn git_cmd(git_dir: &Path) -> Command {
    let mut c = Command::new(std::env::var_os("VEIL_GIT").unwrap_or_else(|| "git".into()));
    for v in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY"] {
        c.env_remove(v);
    }
    c.arg("--git-dir").arg(git_dir);
    c.stdin(Stdio::null());
    c
}

fn run_git(mut c: Command, what: &str) -> Result<String> {
    let out = c.output().with_context(|| format!("running git for {what} (is git installed? set VEIL_GIT)"))?;
    if !out.status.success() {
        bail!("git {what} failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Install the guards into `git_dir/hooks`. Returns warnings.
fn install_hooks(git_dir: &Path) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    let vl = std::env::current_exe().context("locating the vl binary for the Git hooks")?;
    let dir = git_dir.join("hooks");
    std::fs::create_dir_all(&dir)?;
    for name in HOOK_NAMES {
        let path = dir.join(name);
        let chained = dir.join(format!("{name}{CHAINED}"));
        let ours = std::fs::read_to_string(&path).is_ok_and(|t| t.contains(HOOK_MARK));
        if std::fs::symlink_metadata(&path).is_ok() && !ours {
            if std::fs::symlink_metadata(&chained).is_ok() {
                warnings.push(format!(
                    "{} and {} both exist; the guard was not installed as {name} (see `vl git colocate --status`)",
                    path.display(),
                    chained.display()
                ));
                continue;
            }
            std::fs::rename(&path, &chained)?;
        }
        write_executable(&path, &hook_script(name, &vl))?;
    }
    if let Some(p) = hooks_path_config(git_dir) {
        warnings.push(format!(
            "core.hooksPath is set ({p}): Git runs hooks from there, so Veil's pre-push and pre-commit guards do not run. \
             Call `vl git check-push` from your own pre-push hook"
        ));
    }
    Ok(warnings)
}

fn write_executable(path: &Path, text: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = path.with_extension("veil-tmp");
    let _ = std::fs::remove_file(&tmp);
    std::fs::write(&tmp, text)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn uninstall_hooks(git_dir: &Path) -> Result<()> {
    let dir = git_dir.join("hooks");
    for name in HOOK_NAMES {
        let path = dir.join(name);
        if std::fs::read_to_string(&path).is_ok_and(|t| t.contains(HOOK_MARK)) {
            std::fs::remove_file(&path)?;
        }
        let chained = dir.join(format!("{name}{CHAINED}"));
        if std::fs::symlink_metadata(&chained).is_ok() && std::fs::symlink_metadata(&path).is_err() {
            std::fs::rename(&chained, &path)?;
        }
    }
    Ok(())
}

/// Each guard hook: installed by Veil, and exactly as Veil wrote it.
fn hooks_intact(git_dir: &Path) -> Vec<(&'static str, bool, bool)> {
    let vl = std::env::current_exe().unwrap_or_default();
    HOOK_NAMES
        .iter()
        .map(|n| {
            let text = std::fs::read_to_string(git_dir.join("hooks").join(n)).unwrap_or_default();
            (*n, text.contains(HOOK_MARK), text == hook_script(n, &vl))
        })
        .collect()
}

// ---- vl init --colocate / vl git colocate --------------------------------------------------

fn require_experimental(yes: bool) -> Result<()> {
    if !yes {
        bail!(
            "colocated Git mode is experimental: a real .git beside cloaked files is guarded, but not yet through a \
             dedicated adversarial pass. Read {GUIDE}, then add --experimental"
        );
    }
    Ok(())
}

/// Why the Git checkout at `root` cannot be adopted, if it cannot.
fn refuse_adoption(root: &Path) -> Result<()> {
    let git = root.join(".git");
    let m = std::fs::symlink_metadata(&git)?;
    if m.file_type().is_symlink() {
        bail!(".git is a symlink; colocated mode refuses it");
    }
    if !m.is_dir() {
        bail!(".git is a file (a linked worktree or a submodule); colocated mode needs the repository's own .git directory");
    }
    if let Some(op) = colocate::operation_in_progress(&git) {
        bail!("a Git operation is in progress ({op}); finish or abort it first");
    }
    colocate::check_adoptable(&git)?;
    let wt = git_cmd(&git).args(["config", "--get", "core.worktree"]).output()?;
    if wt.status.success() && !wt.stdout.is_empty() {
        bail!("the Git repository sets core.worktree; colocated mode refuses it");
    }
    Ok(())
}

/// `vl init --colocate [PATH]`: a new Veil repository with a `.git`, or
/// the adoption of an existing Git checkout.
pub fn init_colocate(path: Option<&Path>, args: &InitColocateArgs) -> Result<ExitCode> {
    require_experimental(args.experimental)?;
    if let Some(v) = env_points_elsewhere() {
        bail!("{v} is set; colocated mode refuses to run with Git pointed elsewhere (unset it)");
    }
    let root = match path {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir()?,
    };
    std::fs::create_dir_all(&root)?;
    let root = root.canonicalize()?;
    if root.join(".veil").exists() {
        bail!(
            "{} is already a Veil repository; colocate it with `vl git colocate --experimental`",
            root.display()
        );
    }
    let adopt = std::fs::symlink_metadata(root.join(".git")).is_ok();
    if adopt {
        refuse_adoption(&root)?;
        // Before the first snapshot: what `.gitignore` ignores is ignored
        // by Veil too, so it is never recorded just because Veil did not
        // read `.gitignore`.
        let found = policy_gitignore::import_gitignore(&root, &root.join(".git"))?;
        if !found.is_empty() {
            let policy = root.join(POLICY_FILE);
            if std::fs::symlink_metadata(&policy).is_ok_and(|m| !m.is_file()) {
                bail!("{POLICY_FILE} is not a regular file; cannot add the .gitignore rules to it");
            }
            let mut text = std::fs::read_to_string(&policy).unwrap_or_else(|_| crate::DEFAULT_POLICY.to_string());
            append_rules(&mut text, &found);
            std::fs::write(&policy, text)?;
            print_imported(&found);
        }
    } else {
        colocate::init_git(&root)?;
    }
    crate::cmd_init(Some(&root))?;
    let mut ctx = Ctx::open(Some(&root), true)?;
    colocate_now(&mut ctx, adopt)?;
    ctx.finish()?;
    Ok(ExitCode::SUCCESS)
}

/// Append one `ignore` rule per pattern to policy `text`, skipping rules it
/// already has.
fn append_rules(text: &mut String, found: &[policy_gitignore::ImportedPattern]) {
    let have: HashSet<String> = text.lines().map(|l| l.split('#').next().unwrap_or("").trim().to_string()).collect();
    let mut added = String::new();
    for f in found {
        let line = format!("{} ignore", f.pattern);
        if have.contains(&line) {
            continue;
        }
        added.push_str(&format!("{line}    # from {}\n", f.source.replace('\n', " ")));
    }
    if added.is_empty() {
        return;
    }
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str("\n# Imported from .gitignore (`vl policy import-gitignore`)\n");
    text.push_str(&added);
}

fn print_imported(found: &[policy_gitignore::ImportedPattern]) {
    for f in found {
        eprintln!(
            "  {} {} ignore  {}",
            green("added"),
            safe(&f.pattern),
            dim(&format!("(from {}; ignores {})", safe(&f.source), safe(&f.example)))
        );
    }
}

/// Colocate the working copy of `ctx` (see `vl git colocate`).
fn colocate_now(ctx: &mut Ctx, adopt: bool) -> Result<()> {
    if ctx.repo.format() < veil_core::object::GIT_PARITY_REPO_FORMAT {
        bail!(
            "colocated mode needs repository format {} (this one is {}): run `vl upgrade` first",
            veil_core::object::GIT_PARITY_REPO_FORMAT,
            ctx.repo.format()
        );
    }
    if ctx.repo.config().colocated.is_some() {
        bail!("this working copy is already colocated (`vl git colocate --status` shows its guards)");
    }
    let root = ctx.root.clone();
    let git_dir = root.join(".git");
    if std::fs::symlink_metadata(&git_dir).is_err() {
        colocate::init_git(&root)?;
    } else {
        refuse_adoption(&root)?;
    }
    // The old bridge's remote-tracking refs (and their objects) come along:
    // a local fetch, no network.
    let bridge_dir = root.join(".veil").join("git").join("repo.git");
    if bridge_dir.is_dir() {
        let mut c = git_cmd(&git_dir);
        c.args(["-c", "gc.auto=0", "-c", "core.hooksPath=/dev/null", "fetch", "--quiet", "--no-tags", "--no-write-fetch-head"])
            .arg(&bridge_dir)
            .args(["+refs/remotes/*:refs/remotes/*", "+refs/veil/*:refs/veil/*"]);
        run_git(c, "fetch from the bridge")?;
    }
    for (k, v) in [("core.autocrlf", "false"), ("sparse.expectFilesOutsideOfPatterns", "true")] {
        let mut c = git_cmd(&git_dir);
        c.args(["config", k, v]);
        run_git(c, "config")?;
    }
    colocate::guard_veil_dir(&root)?;
    ctx.repo.update_config(|c| {
        c.colocated = Some(Colocated { git_dir: ".git".into() });
        Ok(())
    })?;
    let mut state = State::load(&**ctx.repo.backend())?;
    let warnings = install_hooks(&git_dir)?;
    state.hooks_installed = true;
    for w in warnings {
        warn(&w);
    }
    // Git's branches come in (local commits with the local-origin rule).
    let mut bridge = GitBridge::open(&ctx.repo, &git_dir)?;
    let r = bridge.follow_local(&mut ctx.repo, &mut state)?;
    print_follow(&r);
    let head = bridge.head()?;
    if adopt {
        if let Some(h) = head.commit {
            match bridge.snapshot_of(&h) {
                Some(sid) => {
                    let ws = ctx.ws.clone();
                    let new = colocate::reparent_working_copy(&mut ctx.repo, &ws, sid)?;
                    ctx.set_materialised_snapshot(new)?;
                    eprintln!(
                        "{} the working copy is a change on Git's HEAD ({}); uncommitted Git edits are its changes",
                        green("Adopted"),
                        h.to_hex_with_len(10)
                    );
                }
                None => warn("Git's HEAD could not be imported; the working copy stays on the root"),
            }
        }
    }
    let head = bridge.head()?;
    state.last_head = head.commit.map(|c| c.to_string());
    state.last_head_ref = head.symbolic.clone();
    state.save(&**ctx.repo.backend())?;
    ctx.snapshot()?;
    ctx.git = Some(Session {
        git_dir: git_dir.clone(),
        expected_head: Some(head),
        followed: true,
        in_progress: None,
        mirror: true,
    });
    eprintln!(
        "{} {} with Veil ({}). Git sees the public view only; see {GUIDE}",
        green("Colocated"),
        bold(&git_dir.display().to_string()),
        yellow("experimental")
    );
    Ok(())
}

/// `vl git colocate [--status | --prune]`.
pub fn colocate(ctx: &mut Ctx, args: &ColocateArgs) -> Result<ExitCode> {
    if args.status {
        return status(ctx);
    }
    if args.prune {
        return prune(ctx);
    }
    require_experimental(args.experimental)?;
    if let Some(v) = env_points_elsewhere() {
        bail!("{v} is set; colocated mode refuses to run with Git pointed elsewhere (unset it)");
    }
    let adopt = std::fs::symlink_metadata(ctx.root.join(".git")).is_ok();
    if adopt {
        refuse_adoption(&ctx.root)?;
        let found = policy_gitignore::import_gitignore(&ctx.root, &ctx.root.join(".git"))?;
        if !found.is_empty() {
            add_policy_rules(ctx, &found)?;
        }
    }
    colocate_now(ctx, adopt)?;
    Ok(ExitCode::SUCCESS)
}

fn colocated_dir(ctx: &Ctx) -> Result<PathBuf> {
    colocate::colocated_git_dir(&ctx.root)
        .ok_or_else(|| anyhow!("this working copy is not colocated with Git (`vl git colocate --experimental`)"))
}

fn status(ctx: &mut Ctx) -> Result<ExitCode> {
    let git_dir = colocated_dir(ctx)?;
    let state = State::load(&**ctx.repo.backend())?;
    let version = run_git({
        let mut c = git_cmd(&git_dir);
        c.arg("--version");
        c
    }, "--version")
    .unwrap_or_else(|e| format!("unavailable ({e})"));
    println!("{}  {}", bold("git dir"), git_dir.display());
    println!("{}  {}", bold("git"), version.trim());
    match colocate::current_exclude_block(&git_dir) {
        Some(b) => println!("{}  info/exclude block present ({} lines)", bold("excludes"), b.lines().count().saturating_sub(2)),
        None => println!("{}  {} (written by the next command)", bold("excludes"), red("missing")),
    }
    let entries = index::read(&index::index_path(&git_dir)).ok().flatten().unwrap_or_default();
    let skip = entries.iter().filter(|e| e.skip_worktree).count();
    println!("{}  {} of {} index entries skip-worktree", bold("index"), skip, entries.len());
    if state.frozen {
        println!(
            "{}  {} ({})",
            bold("mode"),
            yellow("frozen"),
            safe(state.frozen_reason.as_deref().unwrap_or("cloaked or embargoed work"))
        );
    } else {
        println!("{}  normal", bold("mode"));
    }
    for (name, installed, intact) in hooks_intact(&git_dir) {
        let what = match (installed, intact) {
            (true, true) => green("installed"),
            (true, false) => yellow("installed (differs from what this vl writes; rerun `vl git colocate --experimental`)"),
            (false, _) => red("missing"),
        };
        println!("{}  {name}: {what}", bold("hook"));
    }
    if let Some(p) = hooks_path_config(&git_dir) {
        println!("{}  {} core.hooksPath={p}: the guards do not run", bold("hook"), red("inactive"));
    }
    if state.held.is_empty() {
        println!("{}  none", bold("held"));
    }
    for h in &state.held {
        let gone = !git_cmd(&git_dir).args(["cat-file", "-e", &h.commit]).status().is_ok_and(|s| s.success());
        println!(
            "{}  {} {}{}",
            bold("held"),
            &h.commit[..h.commit.len().min(10)],
            safe(&h.reason),
            if gone { dim(" (pruned)") } else { String::new() }
        );
    }
    if git_cmd(&git_dir).args(["rev-parse", "-q", "--verify", "refs/stash"]).status().is_ok_and(|s| s.success()) {
        println!(
            "{}  refs/stash exists: `git stash -a` stores ignored files (cloaked or isolated plaintext) in .git; it is never pushed",
            bold("stash")
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn prune(ctx: &mut Ctx) -> Result<ExitCode> {
    let git_dir = colocated_dir(ctx)?;
    let mut state = State::load(&**ctx.repo.backend())?;
    let mut c = git_cmd(&git_dir);
    c.args(["reflog", "expire", "--expire=now", "--expire-unreachable=now", "--all"]);
    run_git(c, "reflog expire")?;
    let mut c = git_cmd(&git_dir);
    c.args(["-c", "core.hooksPath=/dev/null", "gc", "--prune=now", "--quiet"]);
    run_git(c, "gc")?;
    let before = state.held.len();
    state
        .held
        .retain(|h| git_cmd(&git_dir).args(["cat-file", "-e", &h.commit]).status().is_ok_and(|s| s.success()));
    state.save(&**ctx.repo.backend())?;
    println!("Pruned {} held commit(s) from .git", before - state.held.len());
    for h in &state.held {
        println!(
            "  {} {} is still referenced (a branch, tag or stash names it); delete that, then prune again",
            yellow("kept"),
            &h.commit[..h.commit.len().min(10)]
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// `vl git uncolocate`.
pub fn uncolocate(ctx: &mut Ctx, _args: &UncolocateArgs) -> Result<ExitCode> {
    let git_dir = colocated_dir(ctx)?;
    ctx.git = None;
    let state = State::load(&**ctx.repo.backend())?;
    // The bridge goes back to .veil/git/repo.git, with what was fetched.
    let bridge_dir = ctx.root.join(".veil").join("git").join("repo.git");
    if !bridge_dir.exists() {
        std::fs::create_dir_all(&bridge_dir)?;
        run_git(
            {
                let mut c = Command::new(std::env::var_os("VEIL_GIT").unwrap_or_else(|| "git".into()));
                c.args(["init", "--quiet", "--bare"]).arg(&bridge_dir).stdin(Stdio::null());
                c
            },
            "init",
        )?;
    }
    let mut c = git_cmd(&bridge_dir);
    c.args(["-c", "gc.auto=0", "-c", "core.hooksPath=/dev/null", "fetch", "--quiet", "--no-tags", "--no-write-fetch-head"])
        .arg(&git_dir)
        .args(["+refs/remotes/*:refs/remotes/*", "+refs/veil/*:refs/veil/*"]);
    run_git(c, "fetch into the bridge")?;
    ctx.repo.update_config(|c| {
        c.colocated = None;
        Ok(())
    })?;
    colocate::remove_exclude(&git_dir)?;
    uninstall_hooks(&git_dir)?;
    let mut revealed = 0;
    if let Some(entries) = index::read(&index::index_path(&git_dir))? {
        revealed = entries.iter().filter(|e| e.skip_worktree).count();
        let list: Vec<index::NewEntry> = entries
            .iter()
            .filter(|e| e.stage == 0)
            .map(|e| index::NewEntry {
                path: e.path.clone(),
                mode: e.mode,
                oid: e.oid,
                skip_worktree: false,
            })
            .collect();
        if !index::write(&git_dir, &list)? {
            warn("the Git index is locked; its skip-worktree bits were left as they are");
        }
    }
    colocate::unguard_veil_dir(&ctx.root)?;
    State::remove(&**ctx.repo.backend())?;
    println!("Stopped colocation: {} is a plain Git repository again", git_dir.display());
    if revealed > 0 {
        warn(&format!(
            "{revealed} file(s) Veil hid from Git now show in `git status`; some hold content Veil keeps private \
             (cloaked, embargoed): do not `git add` them"
        ));
    }
    if !state.held.is_empty() {
        warn(&format!(
            "{} held commit(s) are still in .git; `git gc --prune=now` after expiring reflogs removes them",
            state.held.len()
        ));
    }
    Ok(ExitCode::SUCCESS)
}

// ---- gates ---------------------------------------------------------------------------------

/// `vl git check-push`: the `pre-push` (and, with `--pre-commit`, the
/// `pre-commit`) guard.
pub fn check_push(ctx: &mut Ctx, args: &CheckPushArgs) -> Result<ExitCode> {
    let git_dir = colocated_dir(ctx)?;
    if let Some(s) = ctx.git.as_mut() {
        s.mirror = false;
    }
    let state = State::load(&**ctx.repo.backend())?;
    let bridge = GitBridge::open(&ctx.repo, &git_dir)?;
    let refused = if args.pre_commit {
        let staged = index::read_staged(&git_dir)?.unwrap_or_default();
        let policy = ctx.repo.effective_policy(&*ctx.fs)?;
        bridge.check_staged(&state, &policy, &staged)?
    } else {
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input)?;
        let mut lines = Vec::new();
        for l in input.lines().filter(|l| !l.trim().is_empty()) {
            lines.push(PushLine::parse(l)?);
        }
        bridge.check_push(&state, &lines)?
    };
    if refused.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    let what = if args.pre_commit { "commit" } else { "push" };
    eprintln!("{} Veil refuses this Git {what} (colocated guard):", red("error:"));
    for r in &refused {
        eprintln!("  {}", safe(r));
    }
    if args.pre_commit {
        eprintln!("{} commit with `vl commit` instead; see {GUIDE}", yellow("hint:"));
    } else {
        let remote = args.remote.as_deref().map(|r| format!(" {}", safe(r))).unwrap_or_default();
        eprintln!(
            "{} `vl git push{remote}` pushes Veil's public view. `git push --no-verify` skips this check and can publish private content",
            yellow("hint:")
        );
    }
    Ok(ExitCode::FAILURE)
}

// ---- vl policy import-gitignore ------------------------------------------------------------

fn add_policy_rules(ctx: &mut Ctx, found: &[policy_gitignore::ImportedPattern]) -> Result<()> {
    let p = VPath::new(POLICY_FILE)?;
    if std::fs::symlink_metadata(ctx.root.join(POLICY_FILE)).is_ok_and(|m| !m.is_file()) {
        bail!("{POLICY_FILE} is not a regular file; cannot add the .gitignore rules to it");
    }
    let mut text = match veil_core::StorageBackend::read_opt(&*ctx.fs, &p)? {
        Some(b) => String::from_utf8(b).map_err(|_| anyhow!("{POLICY_FILE} is not UTF-8"))?,
        None => crate::DEFAULT_POLICY.to_string(),
    };
    let before = text.clone();
    append_rules(&mut text, found);
    if text != before {
        veil_core::StorageBackend::write(&*ctx.fs, &p, text.as_bytes())?;
        print_imported(found);
        ctx.snapshot_as("import .gitignore patterns into .veilpolicy".into())?;
        let recorded: Vec<String> = found
            .iter()
            .filter(|f| {
                VPath::new(&f.example)
                    .ok()
                    .and_then(|vp| veil_core::tree::lookup(ctx.repo.store(), &ctx.repo.snapshot(&ctx.wc().ok()?).ok()?.tree, &vp).ok().flatten())
                    .is_some()
            })
            .map(|f| f.example.clone())
            .collect();
        for r in recorded {
            warn_untrusted(&format!(
                "{r} was already recorded before its .gitignore rule was imported; `vl untrack` or `vl rm --cached` it if it must not be in history"
            ));
        }
    }
    Ok(())
}

/// `vl policy import-gitignore`.
pub fn import_gitignore(ctx: &mut Ctx, _args: &ImportGitignoreArgs) -> Result<()> {
    let git_dir = ctx.root.join(".git");
    if !std::fs::symlink_metadata(&git_dir).is_ok_and(|m| m.is_dir()) {
        bail!("no .git directory in {}; import-gitignore reads Git's view of the files here", ctx.root.display());
    }
    let found = policy_gitignore::import_gitignore(&ctx.root, &git_dir)?;
    if found.is_empty() {
        println!("No .gitignore pattern ignores a file here; nothing to add");
        return Ok(());
    }
    add_policy_rules(ctx, &found)?;
    Ok(())
}

/// `vl status` in a colocated directory: the held local commits, until
/// `vl git colocate --prune`.
pub fn status_notes(ctx: &Ctx) {
    if colocate::colocated_git_dir(&ctx.root).is_none() {
        return;
    }
    let Ok(state) = State::load(&**ctx.repo.backend()) else { return };
    for h in &state.held {
        eprintln!(
            "{} local Git commit {} is held ({}); `vl git colocate --prune` removes it from .git",
            yellow("held:"),
            &h.commit[..h.commit.len().min(10)],
            safe(&h.reason)
        );
    }
    if state.frozen {
        eprintln!(
            "{} Git commits are frozen here ({}): Git sees no edit; commit with vl",
            dim("note:"),
            safe(state.frozen_reason.as_deref().unwrap_or("cloaked or embargoed work"))
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_scripts_quote_the_vl_path() {
        let s = hook_script("pre-push", Path::new("/opt/it's here/vl"));
        assert!(s.contains("VL='/opt/it'\\''s here/vl'"), "{s}");
        assert!(s.contains(HOOK_MARK));
        assert!(s.contains("git check-push \"$@\""));
        let c = hook_script("pre-commit", Path::new("/x/vl"));
        assert!(c.contains("--pre-commit"));
    }

    #[test]
    fn imported_rules_are_appended_once() {
        let f = vec![policy_gitignore::ImportedPattern {
            pattern: "master.key".into(),
            source: ".gitignore:1".into(),
            example: "config/master.key".into(),
        }];
        let mut t = "target/ ignore\n".to_string();
        append_rules(&mut t, &f);
        assert!(t.contains("master.key ignore    # from .gitignore:1"));
        let again = t.clone();
        append_rules(&mut t, &f);
        assert_eq!(t, again);
    }
}
