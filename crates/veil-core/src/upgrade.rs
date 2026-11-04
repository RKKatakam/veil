//! `vl upgrade`: explicit, crash-safe, resumable repository migrations.
//!
//! A repository is read and written at the format in `.veil/repo.json`
//! ([`crate::repo::REPO_FORMAT`] lists them). Every format this build knows is
//! read *and keeps being written in its own encoding*, so nothing changes
//! until the owner runs `vl upgrade` (see `docs/FORMAT.md`, "Migrations").
//!
//! An upgrade runs under the repository lock and keeps a journal in
//! `.veil/upgrade.json`:
//!
//! 1. **verify**: `fsck` the repository; any corruption stops the upgrade
//!    before anything is written (unless forced), and a census counts the
//!    trees in each encoding;
//! 2. one **step per format transition** (`1 → 2` has none: existing
//!    objects keep their bytes and ids, only what is written from now on
//!    changes);
//! 3. **set-format**: write `repo.json` with the new format, atomically.
//!    This is the commit point: before it the repository is entirely the old
//!    format, after it entirely the new one;
//! 4. remove the journal.
//!
//! Each finished step is recorded in the journal before the next starts, so a
//! crashed upgrade resumes where it stopped (`vl upgrade` again). Old data is
//! never removed by an upgrade. A dry run takes no lock and writes nothing.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{
    error::{Result, VeilError},
    fsck::{fsck, Severity},
    identity::Identity,
    lock::RepoLock,
    now_millis,
    object::{Object, TreeEncoding},
    repo::{check_format_supported, min_vl_for_format, read_config, write_config, REPO_FORMAT},
    store::ObjectStore,
    vfs::StorageBackend,
    vpath::VPath,
};

/// The upgrade journal (present only while an upgrade is unfinished).
pub const JOURNAL_PATH: &str = ".veil/upgrade.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Journal {
    from: u32,
    to: u32,
    started: i64,
    /// Steps finished so far, in order.
    done: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct UpgradeOptions {
    /// Report what would happen; take no lock, write nothing.
    pub dry_run: bool,
    /// Target format (default: the newest this build writes).
    pub to: u32,
    /// Upgrade even if `fsck` reports corruption.
    pub force: bool,
}

impl Default for UpgradeOptions {
    fn default() -> Self {
        UpgradeOptions {
            dry_run: false,
            to: REPO_FORMAT,
            force: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct UpgradeReport {
    pub from: u32,
    pub to: u32,
    pub dry_run: bool,
    /// Nothing to do: already at the target format.
    pub up_to_date: bool,
    /// An interrupted upgrade was found and continued.
    pub resumed: bool,
    /// Steps run (or, in a dry run, that would run), in order.
    pub steps: Vec<String>,
    /// Plaintext tree objects per encoding (sealed trees are not counted).
    pub trees_json: usize,
    pub trees_binary: usize,
    pub objects: usize,
    /// Corruption `fsck` found (the upgrade refuses to run unless forced).
    pub corrupt: Vec<String>,
    /// What the upgrade means for this repository and its users.
    pub notes: Vec<String>,
}

fn journal_path() -> VPath {
    VPath::new(JOURNAL_PATH).expect("static path")
}

fn read_journal(backend: &dyn StorageBackend) -> Result<Option<Journal>> {
    match backend.read_opt(&journal_path())? {
        None => Ok(None),
        Some(raw) => serde_json::from_slice(&raw)
            .map(Some)
            .map_err(|e| VeilError::Corrupt(JOURNAL_PATH.into(), format!("cannot be parsed: {e}"))),
    }
}

fn write_journal(backend: &dyn StorageBackend, j: &Journal) -> Result<()> {
    backend.write(&journal_path(), &serde_json::to_vec_pretty(j)?)
}

/// Data-transforming steps for the transition `from → from + 1` (each must
/// be idempotent: a resumed upgrade may run a step that was interrupted).
fn transition_steps(from: u32) -> Vec<&'static str> {
    match from {
        // Binary trees: nothing to rewrite. Existing JSON trees keep their
        // bytes and ids (and with them every snapshot id and signature).
        1 => vec![],
        _ => vec![],
    }
}

fn notes_for(from: u32, to: u32, report: &UpgradeReport) -> Vec<String> {
    let mut notes = Vec::new();
    if from < 2 && to >= 2 {
        notes.push(format!(
            "{} existing JSON tree(s) keep their bytes and ids, so snapshot ids, change ids and signatures do not change; \
             new and changed directories are written as binary trees",
            report.trees_json
        ));
        notes.push(format!(
            "vl releases older than {} cannot read the repository afterwards",
            min_vl_for_format(2)
        ));
        notes.push(
            "a remote still at format 1 refuses binary trees: upgrade it with `vl upgrade --remote <name>` \
             once everyone who uses it has upgraded vl; pulling from format-1 remotes keeps working"
                .into(),
        );
    }
    notes
}

/// Upgrade the repository on `backend` (a project or a bare remote) to
/// `opts.to`. `identity` lets the verification open sealed objects.
pub fn upgrade(backend: Arc<dyn StorageBackend>, identity: Option<Identity>, opts: &UpgradeOptions) -> Result<UpgradeReport> {
    check_format_supported(opts.to)?;
    let _lock = if opts.dry_run {
        None
    } else {
        Some(RepoLock::acquire(backend.clone())?)
    };
    let mut config = read_config(&*backend)?;
    config.check_supported()?;
    let journal = read_journal(&*backend)?;
    let mut report = UpgradeReport {
        from: journal.as_ref().map_or(config.format, |j| j.from),
        to: journal.as_ref().map_or(opts.to, |j| j.to),
        dry_run: opts.dry_run,
        resumed: journal.is_some(),
        ..Default::default()
    };
    if report.to < config.format {
        return Err(VeilError::repo(format!(
            "this repository is at format {}; downgrading to format {} is not supported",
            config.format, report.to
        )));
    }
    if config.format == report.to && journal.is_none() {
        report.up_to_date = true;
        return Ok(report);
    }

    let mut plan: Vec<String> = vec!["verify".into()];
    for f in report.from..report.to {
        plan.extend(transition_steps(f).into_iter().map(|s| format!("{f}->{}:{s}", f + 1)));
    }
    plan.push("set-format".into());

    let mut j = journal.unwrap_or(Journal {
        from: report.from,
        to: report.to,
        started: now_millis(),
        done: Vec::new(),
    });
    if !opts.dry_run && j.done.is_empty() {
        write_journal(&*backend, &j)?;
    }
    for step in plan {
        // set-format is the commit point; it may have happened before a
        // crash that left the journal behind.
        let finished = j.done.contains(&step) || (step == "set-format" && config.format == report.to);
        if finished {
            continue;
        }
        if step == "verify" {
            census(&backend, &mut report)?;
            let fsck = fsck(backend.clone(), identity.clone())?;
            report.corrupt = fsck
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Corrupt)
                .map(|f| f.message.clone())
                .collect();
            if !report.corrupt.is_empty() && !opts.force && !opts.dry_run {
                return Err(VeilError::repo(format!(
                    "upgrade refused: `vl fsck` reports {} problem(s), first: {}. Nothing was changed; \
                     repair the repository (or pass --force)",
                    report.corrupt.len(),
                    report.corrupt[0]
                )));
            }
        }
        report.steps.push(step.clone());
        if opts.dry_run {
            continue;
        }
        if step == "set-format" {
            config.format = report.to;
            config.min_vl = (report.to > 1).then(|| min_vl_for_format(report.to).to_string());
            write_config(&*backend, &config)?;
        }
        j.done.push(step);
        write_journal(&*backend, &j)?;
    }
    if report.trees_json + report.trees_binary == 0 && report.objects == 0 {
        // Resumed after verification: the census was not repeated.
        census(&backend, &mut report)?;
    }
    report.notes = notes_for(report.from, report.to, &report);
    if !opts.dry_run {
        backend.remove_file(&journal_path())?;
    }
    Ok(report)
}

/// Count objects and plaintext trees by encoding.
fn census(backend: &Arc<dyn StorageBackend>, report: &mut UpgradeReport) -> Result<()> {
    let keys = Arc::new(crate::keychain::Keychain::new(backend.clone(), None, String::new()));
    let store = ObjectStore::new(backend.clone(), VPath::new(".veil/objects")?, keys);
    report.objects = 0;
    report.trees_json = 0;
    report.trees_binary = 0;
    for id in store.list_objects()? {
        report.objects += 1;
        // Without gc freshening: a dry run writes nothing.
        let Ok(raw) = store.read_raw(&id) else { continue };
        match Object::tree_encoding(&raw) {
            Some(TreeEncoding::Json) => report.trees_json += 1,
            Some(TreeEncoding::Binary) => report.trees_binary += 1,
            None => {}
        }
    }
    Ok(())
}
