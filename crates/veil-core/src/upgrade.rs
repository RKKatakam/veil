//! `vl upgrade`: explicit, crash-safe, resumable repository migrations.
//!
//! A repository is read and written at the format in `.veil/repo.json`
//! ([`crate::repo::REPO_FORMAT`] lists them). This build opens format 8
//! only; `vl upgrade` brings formats 6 and 7 to it (formats 1 to 5 are no
//! longer read: an earlier vl upgrades them to 7 first). See
//! `docs/FORMAT.md`, "Migrations".
//!
//! An upgrade runs under the repository lock and keeps a journal in
//! `.veil/upgrade.json`:
//!
//! 1. **verify**: check that the repository holds nothing that only the
//!    removed encryption of non-secret content wrote ([`removed_content`]:
//!    encrypted descriptions and tag messages, cloaked tags and lines of
//!    work, encrypted embargoes and folders, encrypted files that are not
//!    secret files). Anything found stops the upgrade before anything is
//!    written, and every path, snapshot, tag or record is named: nothing
//!    is ever dropped silently. Then `fsck` the repository; any corruption
//!    stops the upgrade too (unless forced), and a census counts the trees
//!    in each encoding;
//! 2. **set-format**: write `repo.json` with the new format, atomically.
//!    This is the commit point: before it the repository is entirely the old
//!    format, after it entirely the new one. `6 → 7` and `7 → 8` rewrite
//!    nothing: every object keeps its bytes and id;
//! 3. `3:hpke-ring-keys`, when one of this identity's rings still has a
//!    legacy key wrap (BUG-071: a clone of an upgraded remote, or one a
//!    non-admin upgraded): move every scope this identity administers to
//!    HPKE key wrapping by appending a signed rotation to its ring (see
//!    [`Keychain::migrate_to_hpke`]). A scope the step cannot rotate (a
//!    member no key can be wrapped to is skipped, BUG-070; anything else)
//!    is reported in a note and never blocks the upgrade after its commit
//!    point. It also runs on its own in a repository already at format 8;
//! 4. remove the journal.
//!
//! **Removed content is not converted.** Opening it would mean re-writing
//! the objects that hold it, which changes their ids and with them every
//! tree, snapshot id and signature above them: the whole history. A
//! repository that holds it is refused, with the list.
//!
//! Each finished step is recorded in the journal before the next starts, so a
//! crashed upgrade resumes where it stopped (`vl upgrade` again). Old data is
//! never removed by an upgrade. A dry run takes no lock and writes nothing.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::Arc,
};

use serde::{Deserialize, Serialize};

use crate::{
    error::{Result, VeilError},
    fsck::{fsck, Severity},
    id::ObjectId,
    identity::Identity,
    keychain::{HpkeMigration, Keychain, HPKE_REPO_FORMAT},
    lock::RepoLock,
    now_millis,
    object::{EntryKind, Object, TreeEncoding, Visibility},
    repo::{check_format_upgradable, min_vl_for_format, read_config, write_config, REPO_FORMAT},
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
    /// What only the removed encryption of non-secret content wrote
    /// ([`removed_content`]): the upgrade refuses to run while any is left.
    pub removed: Vec<String>,
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

fn notes_for(from: u32, to: u32) -> Vec<String> {
    let mut notes = Vec::new();
    if from < REPO_FORMAT && to >= REPO_FORMAT {
        notes.push(
            "only secret files are encrypted from now on (`docs/VISIBILITY.md`): descriptions, tags, embargoes \
             and folders are plain text behind the server's permissions; nothing recorded before the upgrade \
             changes"
                .into(),
        );
        notes.push(format!(
            "vl releases older than {} refuse this repository, and this vl refuses clones still at format 6 or 7 \
             until they are upgraded (`vl upgrade` there)",
            min_vl_for_format(REPO_FORMAT)
        ));
    }
    notes
}

/// The refusal of an upgrade of a repository holding `removed`
/// ([`removed_content`]), naming each thing.
fn removed_refusal(removed: &[String]) -> VeilError {
    let n = removed.len();
    let mut list: Vec<String> = removed.iter().take(MAX_REMOVED_LISTED).cloned().collect();
    if n > MAX_REMOVED_LISTED {
        list.push(format!("… and {} more", n - MAX_REMOVED_LISTED));
    }
    // One line: the CLI prints errors escaped (a path here is untrusted).
    VeilError::repo(format!(
        "upgrade refused: this repository holds {n} thing(s) encrypted by features vl no longer has \
         (only secret files are encrypted from format {REPO_FORMAT} on), and converting them would \
         rewrite its whole history. Nothing was changed. Found: {}. Keep using the vl that wrote it \
         (format 7 or earlier), or start a new repository from a checkout of the files",
        list.join("; ")
    ))
}

/// Most findings [`removed_content`] names one by one.
const MAX_REMOVED_LISTED: usize = 50;

/// What the repository on `backend` holds that only the removed encryption
/// of non-secret content wrote (formats 7 and earlier), one line each:
/// snapshots with an encrypted description or on a cloaked line of work,
/// annotated tags whose message is encrypted, trees with encrypted
/// directories, embargoed entries or fallback versions, encrypted files that
/// are not secret files (`policy::names_secret`), cloaked tags and
/// workspaces in any retained operation's view, and embargo records that
/// hold an embargo key. Nothing is decrypted: labels and structure name it.
pub fn removed_content(backend: &Arc<dyn StorageBackend>) -> Result<Vec<String>> {
    let keys = Arc::new(Keychain::new(backend.clone(), None, String::new()));
    let store = ObjectStore::new(backend.clone(), VPath::new(".veil/objects")?, keys);
    store.set_freshening(false);
    let mut found: BTreeSet<String> = BTreeSet::new();
    // Every snapshot: its parents and its tree.
    let mut snapshots: HashMap<ObjectId, (Vec<ObjectId>, ObjectId)> = HashMap::new();
    for id in store.list_objects()? {
        let Ok(raw) = store.read_raw(&id) else { continue };
        if Object::is_snapshot_raw(&raw) {
            let payload = &raw[b"veil:snap\n".len()..];
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) else { continue };
            if v.get("cloak").is_some_and(|c| !c.is_null()) {
                found.insert(format!("snapshot {}: on a cloaked line of work", id.short()));
            }
            if v.get("description").and_then(|d| d.get("sealed")).is_some() {
                found.insert(format!("snapshot {}: an encrypted description", id.short()));
            }
            if let Some(t) = v.get("tree").and_then(|t| serde_json::from_value(t.clone()).ok()) {
                let parents = v.get("parents").and_then(|p| serde_json::from_value(p.clone()).ok()).unwrap_or_default();
                snapshots.insert(id, (parents, t));
            }
        } else if raw.starts_with(crate::object::ATAG_TAG) {
            if let Err(e) = Object::decode(&raw) {
                found.insert(format!("annotated tag {}: its message cannot be read here ({e})", id.short()));
            }
        }
    }
    // The trees. A sealed file at a path no built-in secret rule names is
    // what format 8 itself writes when it descends from a secret: a secret
    // renamed (protection follows content across a rename), or edited at
    // its new path (sealed content keeps its audience). Anything else
    // sealed there (a file under a cloaked folder, a cloaked line's edit),
    // and a conflict side sealed the same way, only the removed
    // encryption wrote. So snapshots are visited parents first, and a
    // sealed entry is a secret's when its path names a secret, when its
    // object was a secret's anywhere before, when a parent held a
    // secret's sealed entry at the same path, or when a parent's secret of
    // the same scope left its path in this snapshot (a rename and an edit
    // at once).
    let mut sealed_of: HashMap<ObjectId, Vec<SealedEntry>> = HashMap::new();
    let mut secret_ids: HashSet<ObjectId> = HashSet::new();
    let mut secret_paths: HashMap<ObjectId, HashMap<String, String>> = HashMap::new();
    for id in parents_first(&snapshots) {
        let (parents, tree) = &snapshots[&id];
        let entries = sealed_entries(&store, *tree, &mut sealed_of, &mut found)?;
        let here: HashSet<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        let before: Vec<&HashMap<String, String>> = parents.iter().filter_map(|p| secret_paths.get(p)).collect();
        let mut mine: HashMap<String, String> = HashMap::new();
        for e in &entries {
            let secret = crate::policy::sealed_secret::<std::convert::Infallible>(
                &e.path,
                &e.scope,
                secret_ids.contains(&e.id),
                |path| Ok(before.iter().any(|b| b.contains_key(path))),
                |scope| Ok(before.iter().any(|b| b.iter().any(|(p, s)| s == scope && !here.contains(p.as_str())))),
            )
            .unwrap_or_else(|never| match never {});
            if secret {
                secret_ids.insert(e.id);
                mine.insert(e.path.clone(), e.scope.clone());
            } else {
                found.insert(format!(
                    "{}{}: encrypted (cloaked:{}), and not a secret file",
                    e.path,
                    if e.conflict_side { " (a conflict side)" } else { "" },
                    e.scope
                ));
            }
        }
        secret_paths.insert(id, mine);
    }
        // Every retained operation's view (an undo restores any of them).
    let ops = VPath::new(".veil/ops")?;
    if backend.exists(&ops)? {
        for f in backend.list_dir(&ops)? {
            let Ok(raw) = backend.read(&ops.join(&f.name)) else { continue };
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(&raw) else { continue };
            for (what, key) in [("tag", "tags"), ("workspace", "workspaces")] {
                let Some(m) = v.get("view").and_then(|v| v.get(key)).and_then(|m| m.as_object()) else { continue };
                for (name, item) in m {
                    if item.get("cloak").is_some_and(|c| !c.is_null()) {
                        found.insert(format!("{what} '{name}': cloaked"));
                    }
                }
            }
        }
    }
    let embargoes = VPath::new(".veil/meta/embargoes")?;
    if backend.exists(&embargoes)? {
        for f in backend.list_dir(&embargoes)? {
            let Some(id) = f.name.strip_suffix(".json") else { continue };
            let Ok(raw) = backend.read(&embargoes.join(&f.name)) else { continue };
            if crate::keychain::check_embargo_format(&raw).is_err() {
                found.insert(format!("embargo {id}: its record holds an embargo key"));
            }
        }
    }
    Ok(found.into_iter().collect())
}

/// Upgrade the repository on `backend` (a project or a bare remote) to
/// `opts.to`. `identity` lets the verification open sealed objects.
pub fn upgrade(
    backend: Arc<dyn StorageBackend>,
    identity: Option<Identity>,
    opts: &UpgradeOptions,
) -> Result<UpgradeReport> {
    check_format_upgradable(opts.to)?;
    // Before any lock is taken (a lock leaves its file): a format this
    // build does not read, or a repository it would refuse, is left exactly
    // as it was. The check is repeated under the lock.
    let config = read_config(&*backend)?;
    check_format_upgradable(config.format)?;
    if !opts.dry_run && config.format < REPO_FORMAT {
        let removed = removed_content(&backend)?;
        if !removed.is_empty() {
            return Err(removed_refusal(&removed));
        }
    }
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
    check_format_upgradable(config.format)?;
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

    // `6 → 7` and `7 → 8` rewrite nothing (see the module docs).
    let mut plan: Vec<String> = vec!["verify".into(), "set-format".into()];
    // The ring step is not tied to a format transition (BUG-071); run it
    // too when one of this identity's rings still needs it, as `vl upgrade`
    // at the newest format would.
    let ring_step = format!("{HPKE_REPO_FORMAT}:hpke-ring-keys");
    if identity.is_some() {
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
            // First: `fsck` would report what the removed features wrote
            // as damage, without saying what it is.
            if report.from < REPO_FORMAT {
                report.removed = removed_content(&backend)?;
            }
            if !report.removed.is_empty() && !opts.dry_run {
                if j.done.is_empty() {
                    backend.remove_file(&journal_path())?;
                }
                return Err(removed_refusal(&report.removed));
            }
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
        j.done.push(step);
        write_journal(&*backend, &j)?;
    }
    if report.trees_json + report.trees_binary == 0 && report.objects == 0 {
        // Resumed after verification: the census was not repeated.
        census(&backend, &mut report)?;
    }
    report.notes = notes_for(report.from, report.to);
    if opts.dry_run && !report.removed.is_empty() {
        report.notes.insert(
            0,
            format!(
                "the upgrade would be refused: {} thing(s) here are encrypted by features vl no longer has (only secret \
                 files are encrypted from format {REPO_FORMAT} on): {}",
                report.removed.len(),
                report.removed.iter().take(MAX_REMOVED_LISTED).cloned().collect::<Vec<_>>().join("; ")
            ),
        );
    }
    report.notes.append(&mut report.step_notes);
    if !opts.dry_run {
        backend.remove_file(&journal_path())?;
    }
    Ok(report)
}

/// A sealed file, symlink or conflict side of a tree, at `path`.
#[derive(Clone)]
struct SealedEntry {
    path: String,
    scope: String,
    id: ObjectId,
    conflict_side: bool,
}

/// The sealed entries of tree `tree` (paths relative to it), each tree
/// object read once (`memo`). What cannot be read as format 8 reads it
/// (an encrypted directory, an embargoed entry, a fallback version, a
/// conflict that does not decode) goes to `found`, named by its path.
fn sealed_entries(
    store: &ObjectStore,
    tree: ObjectId,
    memo: &mut HashMap<ObjectId, Vec<SealedEntry>>,
    found: &mut BTreeSet<String>,
) -> Result<Vec<SealedEntry>> {
    // Iterative, parents after children: (tree, its path, children done).
    let mut stack: Vec<(ObjectId, String, bool)> = vec![(tree, String::new(), false)];
    let mut dirs: HashMap<ObjectId, Vec<(String, ObjectId)>> = HashMap::new();
    let mut owns: HashMap<ObjectId, Vec<SealedEntry>> = HashMap::new();
    while let Some((id, dir, done)) = stack.pop() {
        if memo.contains_key(&id) || (!done && owns.contains_key(&id)) {
            continue;
        }
        let shown = if dir.is_empty() { "/".to_string() } else { format!("{dir}/") };
        if done {
            let mut out = Vec::new();
            for (name, sub) in dirs.remove(&id).unwrap_or_default() {
                for e in memo.get(&sub).into_iter().flatten() {
                    out.push(SealedEntry { path: format!("{name}/{}", e.path), ..e.clone() });
                }
            }
            out.extend(owns.remove(&id).unwrap_or_default());
            memo.insert(id, out);
            continue;
        }
        let Ok(raw) = store.read_raw(&id) else {
            memo.insert(id, Vec::new());
            continue;
        };
        let tree = match Object::decode(&raw) {
            Ok(Object::Tree(t)) => t,
            Ok(Object::Sealed(_)) => {
                found.insert(format!("{shown}: an encrypted directory"));
                memo.insert(id, Vec::new());
                continue;
            }
            Ok(_) => {
                memo.insert(id, Vec::new());
                continue;
            }
            Err(e) => {
                found.insert(format!("{shown}: {e}"));
                memo.insert(id, Vec::new());
                continue;
            }
        };
        let mut own = Vec::new();
        let mut subdirs = Vec::new();
        for e in &tree.entries {
            let path = if dir.is_empty() { e.name.clone() } else { format!("{dir}/{}", e.name) };
            match e.kind {
                EntryKind::Dir => subdirs.push((e.name.clone(), e.id, path)),
                EntryKind::File | EntryKind::Symlink => {
                    if let Visibility::Cloaked { scope } = &e.visibility {
                        own.push(SealedEntry { path: e.name.clone(), scope: scope.clone(), id: e.id, conflict_side: false });
                    }
                }
                EntryKind::Conflict => match store.get_raw(&e.id).and_then(|r| Object::decode(&r)) {
                    Ok(Object::Conflict(c)) => {
                        for t in c.interleaved().flatten() {
                            if let Visibility::Cloaked { scope } = &t.visibility {
                                own.push(SealedEntry { path: e.name.clone(), scope: scope.clone(), id: t.id, conflict_side: true });
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        found.insert(format!("{path}: {err}"));
                    }
                },
            }
        }
        // Paths are relative to this tree (its parent prefixes them):
        // children first, then this tree again to combine them.
        stack.push((id, dir.clone(), true));
        let mut names = Vec::new();
        for (name, sub, path) in subdirs {
            names.push((name, sub));
            if !memo.contains_key(&sub) {
                stack.push((sub, path, false));
            }
        }
        dirs.insert(id, names);
        owns.insert(id, own);
    }
    Ok(memo.get(&tree).cloned().unwrap_or_default())
}

/// Snapshot ids, every snapshot after the parents among them.
fn parents_first(snapshots: &HashMap<ObjectId, (Vec<ObjectId>, ObjectId)>) -> Vec<ObjectId> {
    let mut out = Vec::new();
    let mut done: HashSet<ObjectId> = HashSet::new();
    let mut ids: Vec<ObjectId> = snapshots.keys().copied().collect();
    ids.sort();
    for start in ids {
        let mut stack = vec![(start, false)];
        while let Some((id, expanded)) = stack.pop() {
            if done.contains(&id) {
                continue;
            }
            if expanded {
                done.insert(id);
                out.push(id);
                continue;
            }
            stack.push((id, true));
            for p in snapshots.get(&id).map(|(p, _)| p.as_slice()).unwrap_or(&[]) {
                if snapshots.contains_key(p) && !done.contains(p) {
                    stack.push((*p, false));
                }
            }
        }
    }
    out
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
