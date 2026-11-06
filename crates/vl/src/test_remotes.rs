//! **A test fixture, not a product feature:** path remotes for `vl`'s own
//! test suites, compiled into debug builds only and active only with
//! `VEIL_TEST_PATH_REMOTES` set. Users sync through the Veil server
//! (`docs/OVERVIEW.md`); release builds have none of this.
//!
//! Many CLI tests check what a second person's client does with what it
//! received: a non-member's history tools, a public mirror's clone, a
//! policy held back after a pull, a mount under a key grant. The Veil
//! server refuses cloaked lines and embargoes in S1, so those tests move
//! repositories with the engine's in-process transfer instead
//! (`veil_core::remote::push`/`pull`): `vl remote add NAME PATH [--public]`,
//! `vl clone PATH [DEST]`, `vl push [NAME] [-t TAG]… [--force]` and
//! `vl pull [NAME]`, as the path remotes before the server did.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use anyhow::{anyhow, bail, Context, Result};
use veil_core::{
    remote,
    repo::{RemoteConfig, DEFAULT_WORKSPACE},
    tree::lookup,
    DiskBackend, Identity, ObjectId, Repo, StorageBackend, VPath,
};

use crate::{
    ctx::{self, load_identity, user_for, Ctx},
    hooks, hub,
    render::*,
};

/// The fixture is on (`VEIL_TEST_PATH_REMOTES`).
pub fn enabled() -> bool {
    std::env::var_os("VEIL_TEST_PATH_REMOTES").is_some()
}

/// Remote `name` is a path remote of the fixture.
pub fn is_path_remote(ctx: &Ctx, name: &str) -> bool {
    enabled() && ctx.repo.config().remotes.get(name).is_some_and(|r| hub::HubUrl::parse(&r.url).is_none())
}

/// `vl remote add NAME PATH [--public]`.
pub fn add(ctx: &mut Ctx, name: &str, path: &str, public: bool) -> Result<()> {
    remote::add_remote(&mut ctx.repo, name, path)?;
    if public {
        ctx.repo.update_config(|c| {
            if let Some(r) = c.remotes.get_mut(name) {
                r.public = true;
            }
            Ok(())
        })?;
    }
    println!("Added {} remote {} → {}", if public { "public" } else { "team" }, safe(name), safe(path));
    Ok(())
}

fn backend_of(ctx: &Ctx, name: &str) -> Result<(Arc<dyn StorageBackend>, RemoteConfig)> {
    let r = ctx.repo.config().remotes.get(name).cloned().ok_or_else(|| anyhow!("no remote named '{name}'"))?;
    let path = PathBuf::from(&r.url);
    let path = if path.is_absolute() { path } else { ctx.root.join(path) };
    Ok((Arc::new(DiskBackend::new(path)), r))
}

/// `vl clone PATH [DEST]`.
pub fn clone(source: &str, dest: Option<&Path>) -> Result<ExitCode> {
    let path = Path::new(source).canonicalize().with_context(|| format!("remote {source} not found"))?;
    let shown = path.display().to_string();
    let dest = match dest {
        Some(d) => d.to_path_buf(),
        None => PathBuf::from(path.file_name().ok_or_else(|| anyhow!("cannot derive a directory name"))?),
    };
    clone_into(Arc::new(DiskBackend::new(&path)), shown.clone(), shown, &dest)
}

/// After a push of `only` (all if empty), record every pushed tag the
/// remote holds at our target as `<remote>/<tag>`, as a pull does
/// (BUG-248). One operation, only if anything changed.
fn record_pushed_tags(local: &mut Repo, remote_name: &str, backend: Arc<dyn StorageBackend>, only: &[String]) -> Result<()> {
    let there = Repo::open_remote(backend)?.view().tags.clone();
    let view = local.view();
    let wanted: Vec<(String, ObjectId)> = view
        .tags
        .iter()
        .filter(|(n, _)| only.is_empty() || only.contains(*n))
        .filter(|(n, t)| there.get(*n).is_some_and(|r| r.target == t.target))
        .filter(|(n, t)| view.remote_tags.get(&format!("{remote_name}/{n}")) != Some(&t.target))
        .map(|(n, t)| (n.clone(), t.target))
        .collect();
    if wanted.is_empty() {
        return Ok(());
    }
    let mut tx = local.transaction(format!("push to {remote_name}"))?;
    tx.repository_wide();
    for (t, id) in wanted {
        tx.view.remote_tags.insert(format!("{remote_name}/{t}"), id);
    }
    tx.commit()?;
    Ok(())
}

/// Clone the repository on `backend` (configured as `origin` → `url`) into
/// `dest`. On failure, whatever the clone created is removed: the whole
/// destination if it did not exist, otherwise its contents (it was empty).
fn clone_into(backend: Arc<dyn StorageBackend>, url: String, shown: String, dest: &Path) -> Result<ExitCode> {
    if dest.exists() && std::fs::read_dir(dest)?.next().is_some() {
        bail!("destination {} is not empty", dest.display());
    }
    let created = !dest.exists();
    std::fs::create_dir_all(dest)?;
    let dest = dest.canonicalize()?;
    let result = clone_populate(backend, url, shown, &dest);
    if result.is_err() {
        let cleaned = if created {
            std::fs::remove_dir_all(&dest)
        } else {
            empty_dir(&dest)
        };
        if let Err(e) = cleaned {
            warn(&format!("could not remove the partial clone in {}: {e}", dest.display()));
        }
    }
    result
}

/// Remove everything inside `dir` (not following symlinks).
fn empty_dir(dir: &Path) -> std::io::Result<()> {
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        if e.file_type()?.is_dir() {
            std::fs::remove_dir_all(e.path())?;
        } else {
            std::fs::remove_file(e.path())?;
        }
    }
    Ok(())
}

fn clone_populate(backend: Arc<dyn StorageBackend>, url: String, shown: String, dest: &Path) -> Result<ExitCode> {
    let identity = load_identity()?;
    let fs = Arc::new(DiskBackend::new(dest));
    // Same format as the source, so that what the clone writes can be
    // pushed back and read by everyone who reads the source.
    let source_config = veil_core::repo::read_config(&*backend)?;
    source_config.check_supported()?;
    ctx::mark_clone_incomplete(&fs)?;
    let mut repo = Repo::init_for_clone_at(fs.clone(), Some(identity.clone()), &user_for(&identity), source_config.format)?;
    let mut config = repo.config().clone();
    config.remotes.insert("origin".into(), RemoteConfig { url, public: false, only: None });
    repo.save_config(config)?;
    let report = remote::pull(&mut repo, "origin", backend)?;
    for w in &report.warnings {
        warn_untrusted(w);
    }
    let target = ["main", "trunk", "master"]
        .iter()
        .find_map(|t| repo.view().tags.get(*t).map(|t| t.target))
        .or_else(|| repo.view().tags.values().next().map(|t| t.target))
        .unwrap_or(repo.root_id());
    let wc = repo.new_change(DEFAULT_WORKSPACE, vec![target], "")?;
    let to = repo.snapshot(&wc)?.tree;
    // Journalled (BUG-830). The record remembers what could not be
    // materialised (no key yet, an unreleased embargo), so it is filled in
    // once it becomes readable instead of being recorded as deleted.
    let (state, co) = repo.check_out_new(&*fs, DEFAULT_WORKSPACE, wc, None)?;
    ctx::mark_clone_complete(&fs)?;
    let hidden_by_embargo = state.materialised.view().is_some();
    println!(
        "Cloned {} into {} ({} objects, {} files)",
        safe(&shown),
        dest.display(),
        report.objects_copied,
        co.written
    );
    print_clone_redactions(&repo, &to, &co.redacted, &identity);
    if hidden_by_embargo {
        println!(
            "  {} an embargoed merge is not readable to you yet; you see its pre-merge content until it is released.",
            yellow("note:")
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// After a clone: explain the cloaked files left out of the working copy
/// (`redacted`, paths in `tree`).
/// A team remote delivers them sealed (a grant and a pull make them
/// readable); a public remote never delivers them at all.
/// After a clone: explain the cloaked files left out of the working copy
/// (`redacted`, paths in `tree`).
/// A team remote delivers them sealed (a grant and a pull make them
/// readable); a public remote never delivers them at all.
fn print_clone_redactions(repo: &Repo, tree: &veil_core::ObjectId, redacted: &[VPath], identity: &Identity) {
    use veil_core::object::Visibility;
    let (mut sealed, mut withheld) = (0, 0);
    let mut scopes = std::collections::BTreeSet::new();
    for p in redacted {
        // Embargoed content has a note of its own (below).
        let Ok(Some(e)) = lookup(repo.store(), tree, p) else {
            continue;
        };
        let Visibility::Cloaked { scope } = &e.visibility else {
            continue;
        };
        scopes.insert(safe(scope).into_owned());
        if repo.store().has(&e.id) {
            sealed += 1;
        } else {
            withheld += 1;
        }
    }
    let scopes: Vec<String> = scopes.into_iter().collect();
    let scope = scopes.first().cloned().unwrap_or_default();
    let named = format!(" (scope {})", scopes.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(", "));
    if sealed > 0 {
        println!(
            "  {} {sealed} cloaked file(s){named} you hold no key for. Share your public key ({}) with a member\n  and ask them to run `vl scope grant {scope} <key>` and push. They appear here on your next `vl pull` after that.",
            yellow("note:"),
            identity.public_id()
        );
    }
    if withheld > 0 {
        println!(
            "  {} {withheld} cloaked file(s){named} withheld: this is a public remote, and public remotes never deliver\n  cloaked content. To read them, ask a member to grant you (`vl scope grant {scope} <key>`; your key is in\n  `vl identity show`), then clone or pull from a team remote.",
            yellow("note:"),
        );
    }
}

pub fn push(ctx: &mut Ctx, name: &str, tags: &[String], force: bool, verify: &hooks::NoVerifyArgs) -> Result<ExitCode> {
    let (backend, cfg) = backend_of(ctx, name)?;
    hooks::before_push(ctx, verify, name, &cfg.url, tags)?;
    let r = remote::push(&mut ctx.repo, backend.clone(), cfg.public, tags, force)?;
    record_pushed_tags(&mut ctx.repo, name, backend, tags)?;
    for (t, id) in &r.tags_updated {
        println!("  {} {} → {}", green("pushed"), cyan(&safe(t)), id.short());
    }
    let mut rejected = Vec::new();
    let mut withheld = Vec::new();
    for (t, why) in &r.tags_skipped {
        if r.tags_rejected.contains(t) {
            let why = match why.starts_with("release tag") {
                true => safe(why).into_owned(),
                false => "remote has diverged: not a fast-forward".to_string(),
            };
            println!("  {} {} ({why})", red("rejected"), safe(t));
            rejected.push(t.clone());
        } else {
            println!("  {} {} ({})", yellow("skipped"), safe(t), safe(why));
            if tags.contains(t) {
                withheld.push(t.clone());
            }
        }
    }
    for w in &r.warnings {
        warn_untrusted(w);
    }
    for e in &r.releases_published {
        println!(
            "  {} embargo {} (its key is in the pushed record now; the release can no longer be undone)",
            green("published"),
            safe(e)
        );
    }
    println!(
        "Pushed {} object(s) to {}{name}{}",
        r.objects_copied,
        if cfg.public { "public remote " } else { "" },
        if r.redacted > 0 {
            format!("; {} cloaked/embargoed object(s) withheld", r.redacted)
        } else {
            String::new()
        }
    );
    let first = rejected.first().map(|t| safe(t).into_owned()).unwrap_or_default();
    let fix = format!(
        "{name} has changes you don't have. Run `vl pull {name}`, `vl merge {name}/{first}`, and push again (or `vl push --force` to overwrite them)"
    );
    Ok(push_status(&rejected, &fix, &withheld))
}

/// Exit status of a push that did not send every tag it was asked to:
/// failure if the remote rejected any (`rejected`, with `fix` saying what
/// to do), or if a tag named on the command line was held back. Tags held
/// back by design from an all-tags push (cloaked tags on a public remote,
/// unreleased embargoes) do not fail it: a script tells "nothing to do"
/// (0) from "partially rejected" (1) by the status alone.
fn push_status(rejected: &[String], fix: &str, withheld: &[String]) -> ExitCode {
    let list = |tags: &[String]| tags.iter().map(|t| safe(t).into_owned()).collect::<Vec<_>>().join(", ");
    if !rejected.is_empty() {
        eprintln!(
            "{} {} {} rejected ({}): {fix}",
            red("error:"),
            rejected.len(),
            if rejected.len() == 1 { "tag was" } else { "tags were" },
            list(rejected)
        );
    }
    if !withheld.is_empty() {
        eprintln!(
            "{} requested {} not pushed: {} (see `skipped` above)",
            red("error:"),
            if withheld.len() == 1 { "tag was" } else { "tags were" },
            list(withheld)
        );
    }
    if rejected.is_empty() && withheld.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

pub fn pull(ctx: &mut Ctx, name: &str) -> Result<()> {
    let (backend, _) = backend_of(ctx, name)?;
    let r = remote::pull(&mut ctx.repo, name, backend)?;
    for (t, id) in &r.tags_updated {
        println!("  {} {} → {}", green("updated"), cyan(&safe(t)), id.short());
    }
    for t in &r.remote_tags_removed {
        println!("  {} {} (gone from {name})", yellow("pruned"), safe(t));
    }
    for (t, local, theirs) in &r.release_tags_kept {
        warn_untrusted(&format!(
            "{name} moved release tag {t} from {} to {}; your release tag {t} stays at {} (release tags never move; compare with `vl diff --from {t} --to {name}/{t}`, take theirs with `vl tag set {t} -r {name}/{t} --force`)",
            local.short(),
            theirs.short(),
            local.short()
        ));
    }
    for t in &r.tags_kept_deleted {
        println!(
            "  {} {} (deleted here; still on {name})",
            dim("kept deleted"),
            safe(t)
        );
    }
    for w in &r.warnings {
        warn_untrusted(w);
    }
    println!("Pulled {} object(s) from {name}", r.objects_copied);
    Ok(())
}
