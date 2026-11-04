//! Snapshotting: turn any `StorageBackend` into a tree, applying policy.
//!
//! This is where the engine enforces visibility:
//!
//! * `ignored` paths are skipped;
//! * `isolated` paths (and every built-in secret like `.env`) are reported
//!   back to the caller and **never** written to the CAS;
//! * `cloaked` paths, and every file of a cloaked line of work, are sealed
//!   under their scope key;
//! * public files are secret-scanned and quarantined on a hit. A quarantined
//!   file that was already tracked keeps its previous (safe) entry, so the
//!   local edit is held back instead of being recorded as a deletion;
//! * embargoed entries stay embargoed until released;
//! * entries this reader cannot see (no key, or stripped by a public remote)
//!   are carried over untouched instead of being treated as deletions.
//!
//! With a [`StatCache`] the builder skips reading files whose stat data is
//! unchanged, using content facts recorded on an earlier run. Classification
//! still runs for every path, every time.

use std::collections::HashSet;

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Object, Tree, TreeEntry, Visibility},
    policy::{Policy, Tier, POLICY_FILE},
    secrets::{self, Finding},
    statcache::{CacheKey, CacheRun, StatCache},
    store::ObjectStore,
    vfs::{Metadata, NodeKind, StorageBackend},
    vpath::VPath,
};

pub struct BuildOptions<'a> {
    pub policy: &'a Policy,
    /// Tree of the snapshot being amended (enables reuse and carry-over).
    pub parent_tree: Option<ObjectId>,
    /// Cloak every public file under this scope (cloaked line of work).
    pub cloak: Option<&'a str>,
}

#[derive(Debug, Default, Clone)]
pub struct BuildReport {
    /// Files kept local-only by policy.
    pub isolated: Vec<VPath>,
    /// Public files that contained secrets and were held back.
    pub quarantined: Vec<(VPath, Vec<Finding>)>,
    /// The subset of `quarantined` that was already tracked: the tree keeps
    /// the previous (safe) version, and the local edit stays unrecorded.
    pub quarantine_kept: Vec<VPath>,
    /// Built-in secrets a policy rule tried (and failed) to make public.
    pub blocked_exposures: Vec<VPath>,
    /// Files that should have been cloaked but no key was available.
    pub cloak_failures: Vec<(VPath, String)>,
    /// Entries carried over because this reader cannot materialise them.
    pub carried: Vec<VPath>,
    pub ignored: usize,
    pub files: usize,
    /// Files whose content was read (and hashed) during this build.
    pub hashed: usize,
    /// Files whose entry came from the stat cache without reading them.
    pub cache_hits: usize,
    pub policy_warnings: Vec<String>,
}

impl BuildReport {
    /// Paths that exist locally but are not in the tree.
    pub fn local_only(&self) -> Vec<VPath> {
        let mut v: Vec<VPath> = self.isolated.clone();
        v.extend(self.quarantined.iter().map(|(p, _)| p.clone()));
        v.extend(self.cloak_failures.iter().map(|(p, _)| p.clone()));
        v.sort();
        v.dedup();
        v
    }
}

struct Builder<'a> {
    store: &'a ObjectStore,
    fs: &'a dyn StorageBackend,
    opts: &'a BuildOptions<'a>,
    use_hints: bool,
    /// `.veilpolicy` differs from the parent's: content that is unchanged
    /// since the parent must still be re-scanned, because the parent may
    /// have been built under rules (e.g. `public!`) that no longer apply.
    policy_changed: bool,
    /// The parent's policy, when `policy_changed`: only a path whose
    /// classification *this* snapshot's policy edit changed may leave the
    /// audience it is sealed for (see `file_entry`).
    parent_policy: Option<Policy>,
    cache: Option<CacheRun>,
    report: BuildReport,
}

/// Build a tree from `fs`, returning its id and a report.
pub fn build_tree(store: &ObjectStore, fs: &dyn StorageBackend, opts: &BuildOptions) -> Result<(ObjectId, BuildReport)> {
    build_tree_cached(store, fs, opts, None)
}

/// [`build_tree`] with a stat cache for `fs`. The cache is consulted and
/// updated in place (it is only used if `fs` has a [`StatClock`]).
///
/// [`StatClock`]: crate::vfs::StatClock
pub fn build_tree_cached(
    store: &ObjectStore,
    fs: &dyn StorageBackend,
    opts: &BuildOptions,
    cache: Option<&mut StatCache>,
) -> Result<(ObjectId, BuildReport)> {
    let parent = opts.parent_tree.map(|t| store.tree(&t)).transpose()?;
    // Hints (reuse of unchanged subtrees by id) are only valid if the policy
    // is unchanged, otherwise reclassification could be skipped.
    let policy_path = VPath::new(POLICY_FILE)?;
    let parent_policy = parent.as_ref().and_then(|t| t.get(POLICY_FILE)).map(|e| e.id);
    let use_hints = match (fs.known_id(&policy_path), parent_policy) {
        (Some(h), Some(p)) => h == p,
        (None, None) => !fs.exists(&policy_path)?,
        _ => false,
    };
    let policy_changed = !use_hints
        && match (fs.read_opt(&policy_path)?, parent_policy) {
            (Some(now), Some(p)) => !store.matches_encoding(&p, &now)?,
            (None, None) => false,
            _ => true,
        };
    // The cache only works on backends whose stamps can be trusted. The
    // clock is read before any file is stat'ed (see `statcache`).
    let mut cache = cache;
    let run = match (cache.as_deref_mut(), fs.stat_clock()) {
        (Some(c), Some(clock)) => Some(c.begin_run(CacheKey::compute(fs, &store.keys, clock)?, clock)),
        _ => None,
    };
    let parent_policy = match parent.as_ref().and_then(|t| t.get(POLICY_FILE)) {
        Some(e) if policy_changed => match store.read_entry(e) {
            Ok(b) => Some(Policy::parse(&String::from_utf8_lossy(&b))),
            Err(err) if err.is_unreadable() => None,
            Err(err) => return Err(err),
        },
        None if policy_changed => Some(Policy::builtin()),
        _ => None,
    };
    let mut b = Builder {
        store,
        fs,
        opts,
        use_hints,
        policy_changed,
        parent_policy,
        cache: run,
        report: BuildReport {
            policy_warnings: opts.policy.warnings.clone(),
            ..Default::default()
        },
    };
    let root_parent = parent.as_deref().zip(opts.parent_tree);
    let id = match b.build_dir(&VPath::root(), root_parent)? {
        Some(id) => id,
        None => store.empty_tree()?,
    };
    let id = b.keep_embargo(id)?;
    if let (Some(c), Some(run)) = (cache, b.cache.take()) {
        c.end_run(run);
    }
    Ok((id, b.report))
}

impl Builder<'_> {
    /// A line under an unreleased embargo stays under it. A key holder's new
    /// tree is re-wrapped under the same embargo (readers without the key
    /// keep seeing the pre-merge tree). A reader without the key only sees
    /// that pre-merge tree, so recording edits on top of it would silently
    /// revert the hidden change for everyone else: such edits are held back
    /// (reported as cloak failures) until the embargo is released.
    fn keep_embargo(&mut self, id: ObjectId) -> Result<ObjectId> {
        let Some(parent) = self.opts.parent_tree.filter(|p| *p != id) else {
            return Ok(id);
        };
        let Some(w) = crate::embargo::unreleased_wrapper(self.store, &parent)? else {
            return Ok(id);
        };
        if self.store.keys.has(&w.key_label()) {
            return crate::embargo::wrap(self.store, &w.embargo, &id, &w.fallback);
        }
        for c in crate::tree::diff_trees(self.store, Some(&parent), Some(&id))? {
            self.report.cloak_failures.push((
                c.path,
                format!(
                    "held back: embargo {} hides this line's current content from you; edits are recorded after its release",
                    w.embargo
                ),
            ));
        }
        Ok(parent)
    }

    /// `parent` is the parent's tree for `dir` and its id.
    fn build_dir(&mut self, dir: &VPath, parent: Option<(&Tree, ObjectId)>) -> Result<Option<ObjectId>> {
        let parent_id = parent.map(|(_, id)| id);
        let parent = parent.map(|(t, _)| t);
        let mut out = Tree::default();
        let mut seen = HashSet::new();
        for child in self.fs.list_dir(dir)? {
            if dir.is_root() && child.name == ".veil" {
                continue;
            }
            seen.insert(child.name.clone());
            let path = dir.join(&child.name);
            let parent_entry = parent.and_then(|t| t.get(&child.name));
            match child.kind {
                NodeKind::Dir => {
                    let class = self.opts.policy.classify(&path, true);
                    if class.tier == Tier::Ignored {
                        self.report.ignored += 1;
                        continue;
                    }
                    if let Some(pe) = parent_entry.filter(|e| e.kind == EntryKind::Dir) {
                        if self.use_hints && self.fs.known_id(&path) == Some(pe.id) {
                            out.insert(pe.clone());
                            continue;
                        }
                    }
                    let sub = match parent_entry.filter(|e| e.kind == EntryKind::Dir) {
                        Some(e) => Some((self.store.tree(&e.id)?, e.id)),
                        None => None,
                    };
                    if let Some(id) = self.build_dir(&path, sub.as_ref().map(|(t, id)| (&**t, *id)))? {
                        out.insert(TreeEntry::dir(&child.name, id));
                    }
                }
                NodeKind::File => {
                    if let Some(e) = self.file_entry(&path, &child.name, parent_entry)? {
                        self.report.files += 1;
                        out.insert(e);
                    }
                }
            }
        }
        // Entries we could never have materialised are not deletions.
        if let Some(p) = parent {
            for e in &p.entries {
                if !seen.contains(&e.name) {
                    if let Some(c) = self.carry_unreadable(e, &dir.join(&e.name))? {
                        out.insert(c);
                    }
                }
            }
        }
        if out.is_empty() {
            return Ok(None);
        }
        // Unchanged directory: same entries, same id, already stored. Skips
        // encoding, hashing and the existence check for most directories.
        if let (Some(p), Some(id)) = (parent, parent_id) {
            if *p == out {
                return Ok(Some(id));
            }
        }
        Ok(Some(self.store.put_tree(&out)?))
    }

    fn carry_unreadable(&mut self, e: &TreeEntry, path: &VPath) -> Result<Option<TreeEntry>> {
        match e.kind {
            EntryKind::File => {
                if self.store.entry_readable(e) {
                    Ok(None)
                } else {
                    self.report.carried.push(path.clone());
                    Ok(Some(e.clone()))
                }
            }
            EntryKind::Dir => {
                let Ok(tree) = self.store.tree(&e.id) else {
                    self.report.carried.push(path.clone());
                    return Ok(Some(e.clone()));
                };
                let mut kept = Tree::default();
                for c in &tree.entries {
                    if let Some(k) = self.carry_unreadable(c, &path.join(&c.name))? {
                        kept.insert(k);
                    }
                }
                if kept.is_empty() {
                    return Ok(None);
                }
                Ok(Some(TreeEntry::dir(&e.name, self.store.put_tree(&kept)?)))
            }
        }
    }

    fn file_entry(&mut self, path: &VPath, name: &str, parent_entry: Option<&TreeEntry>) -> Result<Option<TreeEntry>> {
        let parent_file = parent_entry.filter(|e| e.kind == EntryKind::File);
        let class = self.opts.policy.classify(path, false);
        if class.blocked_exposure {
            self.report.blocked_exposures.push(path.clone());
        }
        let mut desired = match &class.tier {
            Tier::Ignored => {
                self.report.ignored += 1;
                return Ok(None);
            }
            Tier::Isolated => {
                self.report.isolated.push(path.clone());
                return Ok(None);
            }
            Tier::Public => Visibility::Public,
            Tier::Cloaked(s) => Visibility::Cloaked { scope: s.clone() },
        };
        if let (Some(scope), Visibility::Public) = (self.opts.cloak, &desired) {
            if path.as_str() != POLICY_FILE {
                desired = Visibility::Cloaked {
                    scope: scope.to_string(),
                };
            }
        }
        // Sealed content keeps its audience. Neither a change of workspace
        // (`vl new <cloaked change>`), nor a rebase, nor a policy that arrived
        // by merge may re-key it or make it public: only an edit of
        // `.veilpolicy` in this very snapshot that reclassifies the path
        // (`vl expose`, `vl cloak --scope`) is a deliberate decision to.
        if let Some(pe) = parent_file.filter(|pe| matches!(pe.visibility, Visibility::Cloaked { .. })) {
            if desired != pe.visibility {
                let reclassified = self
                    .parent_policy
                    .as_ref()
                    .is_some_and(|old| old.classify(path, false) != class);
                if !reclassified {
                    desired = pe.visibility.clone();
                }
            }
        }

        // Fast path: overlay/tree-view says the file is byte-identical.
        if let Some(pe) = parent_file {
            if self.use_hints && self.fs.known_id(path) == Some(pe.id) {
                return Ok(Some(pe.clone()));
            }
        }

        let meta = self.fs.metadata(path)?;
        let executable = meta.as_ref().is_some_and(|m| m.executable);
        // Embargoed entries depend on the parent entry and on embargo state,
        // not only on content: always take the slow path for them.
        let parent_embargoed = parent_file.is_some_and(|pe| matches!(pe.visibility, Visibility::Embargoed { .. }));
        if let (Some(m), false) = (&meta, parent_embargoed) {
            if let Some(e) = self.cached_entry(path, name, m, &desired, class.allow_secrets, parent_file)? {
                return Ok(Some(e));
            }
        }

        let data = self.fs.read(path)?;
        self.report.hashed += 1;
        let content = Object::blob_id(&data);

        // Embargoes are sticky until released.
        let mut fallback = None;
        if let Some(pe) = parent_file {
            if let Visibility::Embargoed { embargo } = &pe.visibility {
                if self.store.keys.embargo_released(embargo) {
                    // Released: unchanged content keeps its (now readable)
                    // entry instead of showing up as a spurious edit.
                    if pe.executable == executable && self.store.matches_encoding(&pe.id, &data)? {
                        return Ok(Some(pe.clone()));
                    }
                    // Still the fallback this reader was shown before the
                    // release: not an edit, and recording it would revert the
                    // fix. (The working copy is stale until checked out again.)
                    if let Some(fb) = pe.fallback {
                        if pe.executable == executable && self.store.matches_encoding(&fb, &data)? {
                            return Ok(Some(TreeEntry {
                                name: name.to_string(),
                                ..pe.clone()
                            }));
                        }
                    }
                } else {
                    if self.store.keys.has(&format!("embargo/{embargo}")) {
                        desired = pe.visibility.clone();
                        fallback = pe.fallback;
                    } else if let Some(fb) = pe.fallback {
                        if self.store.matches_encoding(&fb, &data)? {
                            // We were shown the fallback and did not touch it.
                            return Ok(Some(TreeEntry {
                                name: name.to_string(),
                                ..pe.clone()
                            }));
                        }
                    }
                }
            }
        }

        // A cloaked line of work seals what it *introduces*. A file left
        // exactly as its public parent had it is already public; keep the
        // entry (as the overlay fast path above does) rather than sealing a
        // copy of public bytes.
        if let Some(pe) = parent_file {
            if self.opts.cloak.is_some()
                && class.tier == Tier::Public
                && pe.visibility.is_public()
                && pe.id == content
                && pe.executable == executable
                && !self.policy_changed
            {
                return Ok(Some(pe.clone()));
            }
        }

        let mut scanned_clean = false;
        if desired.is_public() {
            if let Some(pe) = parent_file {
                if !self.policy_changed && pe.id == content && pe.visibility.is_public() && pe.executable == executable {
                    self.learn(path, meta.as_ref(), content, false, None, parent_embargoed);
                    return Ok(Some(pe.clone())); // unchanged; scanned before
                }
            }
            if !class.allow_secrets {
                let findings = secrets::scan(&data);
                if !findings.is_empty() {
                    self.report.quarantined.push((path.clone(), findings));
                    // Hold the edit back, but do not record a deletion: keep
                    // the previously tracked version if it is itself safe.
                    if let Some(pe) = parent_file {
                        if self.previous_is_safe(pe)? {
                            self.report.quarantine_kept.push(path.clone());
                            return Ok(Some(pe.clone()));
                        }
                    }
                    return Ok(None);
                }
                scanned_clean = true;
            }
        }

        // Unchanged cloaked content keeps its sealing (and key generation),
        // so a key rotation does not show every cloaked file as modified.
        if let Some(pe) = parent_file {
            if !desired.is_public()
                && pe.visibility == desired
                && pe.fallback == fallback
                && pe.executable == executable
                && self.store.matches_encoding(&pe.id, &data)?
            {
                return Ok(Some(TreeEntry {
                    name: name.to_string(),
                    ..pe.clone()
                }));
            }
        }

        let id = match self.store.store_file(&data, &desired) {
            Ok(id) => id,
            Err(VeilError::Redacted { scope }) => {
                self.report
                    .cloak_failures
                    .push((path.clone(), format!("no key for scope '{scope}'")));
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        if fallback.is_none() {
            let sealed = match &desired {
                Visibility::Cloaked { scope } => Some((scope.clone(), id)),
                _ => None,
            };
            self.learn(path, meta.as_ref(), content, scanned_clean, sealed, parent_embargoed);
        }
        Ok(Some(TreeEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            id,
            size: data.len() as u64,
            executable,
            visibility: desired,
            fallback,
        }))
    }

    /// Record content facts for a file that was just read.
    fn learn(
        &mut self,
        path: &VPath,
        meta: Option<&Metadata>,
        content: ObjectId,
        scanned_clean: bool,
        sealed: Option<(String, ObjectId)>,
        parent_embargoed: bool,
    ) {
        if let (Some(run), Some(m), false) = (self.cache.as_mut(), meta, parent_embargoed) {
            run.learn(path, m, content, scanned_clean, sealed);
        }
    }

    /// The entry for an unchanged file, built from cached content facts
    /// instead of reading it. `None` means "read the file".
    fn cached_entry(
        &mut self,
        path: &VPath,
        name: &str,
        meta: &Metadata,
        desired: &Visibility,
        allow_secrets: bool,
        parent_file: Option<&TreeEntry>,
    ) -> Result<Option<TreeEntry>> {
        let Some(rec) = self.cache.as_ref().and_then(|c| c.trusted(path, meta)).cloned() else {
            return Ok(None);
        };
        let same_as_parent = |id: &ObjectId| {
            parent_file.filter(|pe| pe.id == *id && pe.visibility == *desired && pe.executable == meta.executable && pe.fallback.is_none())
        };
        let entry = match desired {
            Visibility::Public => {
                let id = rec.content;
                match same_as_parent(&id) {
                    // Same rule as the uncached path: unchanged public content
                    // was scanned when it entered the parent.
                    Some(pe) if !self.policy_changed => Some(pe.clone()),
                    _ if (allow_secrets || rec.scanned_clean) && self.store.has(&id) => Some(self.fresh_entry(name, id, meta, desired)),
                    _ => None,
                }
            }
            Visibility::Cloaked { scope } => match &rec.sealed {
                Some((s, id)) if s == scope && self.store.keys.has(scope) => match same_as_parent(id) {
                    Some(pe) => Some(pe.clone()),
                    None if self.store.has(id) => Some(self.fresh_entry(name, *id, meta, desired)),
                    None => None,
                },
                _ => None,
            },
            Visibility::Embargoed { .. } => None,
        };
        if entry.is_some() {
            self.report.cache_hits += 1;
            if let Some(run) = self.cache.as_mut() {
                run.keep(path, rec);
            }
        }
        Ok(entry)
    }

    fn fresh_entry(&self, name: &str, id: ObjectId, meta: &Metadata, visibility: &Visibility) -> TreeEntry {
        TreeEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            id,
            size: meta.len,
            executable: meta.executable,
            visibility: visibility.clone(),
            fallback: None,
        }
    }

    /// May a quarantined file keep its previous entry? Encrypted entries
    /// are safe by construction. A public one is re-scanned: it may have
    /// been recorded under a rule (e.g. `public!`) that no longer applies,
    /// and must not be carried into a new snapshot if it holds a secret.
    fn previous_is_safe(&self, pe: &TreeEntry) -> Result<bool> {
        if !pe.visibility.is_public() || pe.fallback.is_some() {
            return Ok(true);
        }
        match self.store.read_entry(pe) {
            Ok(old) => Ok(secrets::scan(&old).is_empty()),
            Err(e) if e.is_unreadable() => Ok(false),
            Err(e) => Err(e),
        }
    }
}
