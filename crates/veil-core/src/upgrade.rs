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
//! 2. one **step per format transition** (`1 → 2` and `2 → 3` have none:
//!    existing objects keep their bytes and ids, only what is written from
//!    now on changes);
//! 3. **set-format**: write `repo.json` with the new format, atomically.
//!    This is the commit point: before it the repository is entirely the old
//!    format, after it entirely the new one;
//! 4. steps that need the new format (`3:hpke-ring-keys`: move every scope
//!    this identity administers to HPKE key wrapping by appending a signed
//!    rotation to its ring, see [`Keychain::migrate_to_hpke`]);
//! 5. remove the journal.
//!
//! `3:hpke-ring-keys` is also run on its own, whenever it is pending, in a
//! repository that is already at format 3 (BUG-071): a fresh clone of an
//! upgraded remote, or a clone a non-admin upgraded, still holds rings whose
//! current key was wrapped with the legacy box, and their admin is told to
//! run `vl upgrade`. A scope the step cannot rotate (a member no key can be
//! wrapped to is skipped, BUG-070; anything else) is reported in a note and
//! never blocks the upgrade after its commit point.
//!
//! **Sealed history is not re-sealed** by `2 → 3`: re-sealing would change
//! object ids, and with them every tree, snapshot id and signature above
//! them. Objects sealed before the upgrade stay in the legacy construction
//! (readable forever); new objects are sealed with AES-SIV. See
//! `docs/CRYPTO.md`, "Migration".
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
    keychain::{HpkeMigration, Keychain, HPKE_REPO_FORMAT},
    lock::RepoLock,
    now_millis,
    object::{Object, TreeEncoding},
    oplog::{OP_HEADS_DIR, OP_HEADS_REPO_FORMAT, OP_HEAD_FILE},
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
    /// What the steps did (e.g. which key rings were re-keyed).
    step_notes: Vec<String>,
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
        // AES-SIV and HPKE: nothing to rewrite either (old sealed objects
        // keep their bytes, ids and the legacy construction).
        2 => vec![],
        // First-class conflicts: nothing to rewrite. Conflicts recorded
        // before the upgrade stay as they are (markers in the file, the
        // path listed on the snapshot): rewriting them would change the
        // ids and signatures of every snapshot above them. Merges made
        // after the upgrade record conflicts as conflict entries.
        3 => vec![],
        // Symlinks and annotated tags: nothing to rewrite. Links recorded before the upgrade
        // stayed unrecorded (a format-4 snapshot never holds one), so no
        // object, id or signature changes.
        4 => vec![],
        // The lock-free op log: a head file for the current `op_head`,
        // before the commit point (format-5 readers ignore `op_heads/`).
        5 => vec!["op-heads"],
        // Ring format 4 (invites and shares): nothing to rewrite. Rings
        // already stored keep their format until a change needs format 4.
        6 => vec![],
        _ => vec![],
    }
}

/// Steps that run after the commit point, in the new format (each must be
/// idempotent). Named `<format>:<step>`.
fn post_commit_steps(from: u32, to: u32) -> Vec<String> {
    let mut out = Vec::new();
    if from < HPKE_REPO_FORMAT && to >= HPKE_REPO_FORMAT {
        out.push(format!("{HPKE_REPO_FORMAT}:hpke-ring-keys"));
    }
    if from < OP_HEADS_REPO_FORMAT && to >= OP_HEADS_REPO_FORMAT {
        out.push(format!("{OP_HEADS_REPO_FORMAT}:remove-op-head"));
    }
    out
}

/// The head file of `op_head`'s operation (idempotent).
fn op_heads_step(backend: &Arc<dyn StorageBackend>) -> Result<()> {
    let Some(raw) = backend.read_opt(&VPath::new(OP_HEAD_FILE)?)? else {
        return Ok(()); // already moved (a resumed upgrade)
    };
    let head = crate::id::ObjectId::from_hex(String::from_utf8_lossy(&raw).trim())
        .map_err(|_| VeilError::Corrupt(OP_HEAD_FILE.into(), "does not contain an operation id".into()))?;
    backend.create_new(&VPath::new(&format!("{OP_HEADS_DIR}/{}", head.hex()))?, b"")?;
    Ok(())
}

/// `6:remove-op-head`: after the commit point, `op_head` is not written any
/// more. Its operation gets a head file first (it may have moved since the
/// first step, if the upgrade was interrupted in between), then it is
/// removed, with the fixed pull spool of format 5 (now one per pull).
fn remove_op_head_step(backend: &Arc<dyn StorageBackend>) -> Result<()> {
    op_heads_step(backend)?;
    backend.remove_file(&VPath::new(OP_HEAD_FILE)?)?;
    backend.remove_dir_all(&VPath::new(".veil/objects/incoming/pull")?)
}

/// `3:hpke-ring-keys`: rotate every ring this identity may change whose
/// current key was wrapped with the legacy sealed box. Returns notes.
fn hpke_ring_keys(backend: &Arc<dyn StorageBackend>, identity: Option<&Identity>, repo_id: &str) -> Result<Vec<String>> {
    let Some(identity) = identity else {
        return Ok(vec![
            "key rings were not re-keyed here (no identity: a remote is upgraded structurally); \
             they move to HPKE when an admin who has upgraded their clone pushes (in a clone that is already \
             at format 3, `vl upgrade` still moves the admin's rings)"
                .into(),
        ]);
    };
    let keys = Keychain::new(backend.clone(), Some(identity.clone()), repo_id.to_string());
    keys.set_format(HPKE_REPO_FORMAT);
    let mut notes = Vec::new();
    for ring in keys.rings()? {
        let scope = ring.scope.clone();
        let outcome = match keys.migrate_to_hpke(&scope) {
            Ok(o) => o,
            // The disk failing is not the scope's fault: stop, and resume.
            Err(e @ (VeilError::Io { .. } | VeilError::Locked(_))) => return Err(e),
            // Past the commit point a scope must never block the upgrade
            // (BUG-070): report it; `vl upgrade` retries the step.
            Err(e) => {
                notes.push(format!(
                    "scope '{scope}': its key could not be moved to HPKE ({e}); fix that and run `vl upgrade` again"
                ));
                continue;
            }
        };
        match outcome {
            HpkeMigration::AlreadyHpke => {}
            HpkeMigration::Rotated(g) => {
                notes.push(format!(
                    "scope '{scope}': new key generation {g}, wrapped to every member with HPKE; \
                     earlier generations stay reachable (and stay under the legacy key wrapping already published)"
                ));
                for (id, name) in keys.unreachable_members(&scope) {
                    notes.push(format!(
                        "scope '{scope}': member {name} ({id}) has an invalid (low-order) key and received no key; \
                         revoke it with `vl scope revoke {scope} {id}`"
                    ));
                }
            }
            HpkeMigration::NotAdmin => notes.push(format!(
                "scope '{scope}': its key is still wrapped with the legacy construction; \
                 an admin should run `vl upgrade` (or `vl scope rotate {scope}`) in an upgraded clone"
            )),
            HpkeMigration::Unverifiable(e) => {
                notes.push(format!("scope '{scope}': key ring does not verify ({e}); left unchanged"))
            }
        }
    }
    Ok(notes)
}

fn notes_for(from: u32, to: u32, report: &UpgradeReport) -> Vec<String> {
    let mut notes = Vec::new();
    if from < HPKE_REPO_FORMAT && to >= HPKE_REPO_FORMAT {
        notes.push(
            "new content is sealed with AES-SIV and scope keys are wrapped with HPKE; existing sealed objects \
             keep the legacy construction, their bytes and their ids (nothing is re-sealed), so snapshot ids \
             and signatures do not change"
                .into(),
        );
        notes.push(
            "a member's clone at format 1 or 2 refuses AES-SIV objects and HPKE key rings: it cannot pull them \
             until it is upgraded (`vl upgrade` there)"
                .into(),
        );
    }
    if from < crate::object::CONFLICT_REPO_FORMAT && to >= crate::object::CONFLICT_REPO_FORMAT {
        notes.push(
            "merges now record conflicts as data (conflict entries; `vl resolve`); conflicts recorded before \
             the upgrade stay as they are, as markers in their files, and are resolved by editing them"
                .into(),
        );
        notes.push(
            "a clone still at format 3 refuses conflict entries: it cannot pull a change that holds an \
             unresolved conflict until it is upgraded (`vl upgrade` there)"
                .into(),
        );
    }
    if from < crate::object::GIT_PARITY_REPO_FORMAT && to >= crate::object::GIT_PARITY_REPO_FORMAT {
        notes.push(
            "the repository may now record symlinks and annotated (signed) tags; nothing recorded before the \
             upgrade changes"
                .into(),
        );
        notes.push(
            "a clone still at format 4 refuses symlinks and annotated tags until it is upgraded (`vl upgrade` \
             there); vl releases that only know format 4 refuse this repository"
                .into(),
        );
    }
    if from < OP_HEADS_REPO_FORMAT && to >= OP_HEADS_REPO_FORMAT {
        notes.push(
            "commands no longer wait for each other: each records its operation without the repository lock, \
             and concurrent operations are merged; `vl undo` undoes the last command of the workspace it runs in; \
             nothing recorded before the upgrade changes"
                .into(),
        );
        notes.push(format!(
            "vl releases that only know format 5 refuse this repository (vl {} or later reads it)",
            min_vl_for_format(OP_HEADS_REPO_FORMAT)
        ));
    }
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
            "a clone still at format 1 refuses binary trees until it is upgraded (`vl upgrade` there)"
                .into(),
        );
    }
    notes
}

/// Upgrade the repository on `backend` (a project or a bare remote) to
/// `opts.to`. `identity` lets the verification open sealed objects.
pub fn upgrade(
    backend: Arc<dyn StorageBackend>,
    identity: Option<Identity>,
    opts: &UpgradeOptions,
) -> Result<UpgradeReport> {
    check_format_supported(opts.to)?;
    // The gc lease first (threat 10 of the maintenance design): no gc or
    // background maintenance runs while the format changes under it.
    let _lease = match opts.dry_run {
        true => None,
        false => Some(crate::maintenance::GcLease::acquire(&backend, true)?.ok_or_else(|| {
            VeilError::Locked("`vl gc` is running on this repository; run the upgrade again once it is done".into())
        })?),
    };
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
        // BUG-071: the ring step is not tied to the format transition. It is
        // pending whenever a ring's current key still has legacy wraps.
        let keys = Keychain::new(backend.clone(), identity.clone(), config.repo_id.clone());
        keys.set_format(config.format);
        let pending = if config.format >= HPKE_REPO_FORMAT {
            keys.hpke_migration_pending()?
        } else {
            Vec::new()
        };
        let step = format!("{HPKE_REPO_FORMAT}:hpke-ring-keys");
        if !pending.iter().any(|(_, mine)| *mine) {
            report.up_to_date = true;
            report.notes = pending
                .iter()
                .map(|(scope, _)| {
                    format!(
                        "scope '{scope}': its key is still wrapped with the legacy construction; \
                         an admin of the scope should run `vl upgrade` (or `vl scope rotate {scope}`)"
                    )
                })
                .collect();
            return Ok(report);
        }
        report.steps.push(step);
        if !opts.dry_run {
            // Idempotent, and each rotation is atomic: no journal needed.
            report.notes = hpke_ring_keys(&backend, identity.as_ref(), &config.repo_id)?;
        }
        census(&backend, &mut report)?;
        return Ok(report);
    }

    let mut plan: Vec<String> = vec!["verify".into()];
    for f in report.from..report.to {
        plan.extend(transition_steps(f).into_iter().map(|s| format!("{f}->{}:{s}", f + 1)));
    }
    plan.push("set-format".into());
    plan.extend(post_commit_steps(report.from, report.to));
    // From format 3 on (3 → 4): the ring step is not tied to the 2 → 3
    // transition (BUG-071); run it too when one of this identity's rings
    // still needs it, as `vl upgrade` at the newest format would.
    let ring_step = format!("{HPKE_REPO_FORMAT}:hpke-ring-keys");
    if report.from >= HPKE_REPO_FORMAT && !plan.contains(&ring_step) && identity.is_some() {
        let keys = Keychain::new(backend.clone(), identity.clone(), config.repo_id.clone());
        keys.set_format(config.format);
        if keys.hpke_migration_pending()?.iter().any(|(_, mine)| *mine) || journal.as_ref().is_some_and(|j| j.done.iter().any(|d| d == &ring_step)) {
            plan.push(ring_step);
        }
    }

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
        if step.ends_with(":hpke-ring-keys") {
            let notes = hpke_ring_keys(&backend, identity.as_ref(), &config.repo_id)?;
            report.step_notes.extend(notes);
        }
        if step.ends_with(":op-heads") {
            op_heads_step(&backend)?;
        }
        if step.ends_with(":remove-op-head") {
            remove_op_head_step(&backend)?;
        }
        j.done.push(step);
        write_journal(&*backend, &j)?;
    }
    if report.trees_json + report.trees_binary == 0 && report.objects == 0 {
        // Resumed after verification: the census was not repeated.
        census(&backend, &mut report)?;
    }
    report.notes = notes_for(report.from, report.to, &report);
    report.notes.append(&mut report.step_notes);
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
