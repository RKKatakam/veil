//! Snapshotting: turn any `StorageBackend` into a tree, applying policy.
//!
//! This is where the engine enforces visibility:
//!
//! * `ignored` paths are skipped;
//! * `isolated` paths (and every built-in secret like `.env`) are reported
//!   back to the caller and **never** written to the CAS;
//! * `cloaked` paths, and every file of a cloaked line of work, are sealed
//!   under their scope key;
//! * public files are secret-scanned and quarantined on a hit;
//! * embargoed entries stay embargoed until released;
//! * entries this reader cannot see (no key, or stripped by a public remote)
//!   are carried over untouched instead of being treated as deletions.

use std::collections::HashSet;

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Object, Tree, TreeEntry, Visibility},
    policy::{Policy, Tier, POLICY_FILE},
    secrets::{self, Finding},
    store::ObjectStore,
    vfs::{NodeKind, StorageBackend},
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
    /// Built-in secrets a policy rule tried (and failed) to make public.
    pub blocked_exposures: Vec<VPath>,
    /// Files that should have been cloaked but no key was available.
    pub cloak_failures: Vec<(VPath, String)>,
    /// Entries carried over because this reader cannot materialise them.
    pub carried: Vec<VPath>,
    pub ignored: usize,
    pub files: usize,
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
    report: BuildReport,
}

/// Build a tree from `fs`, returning its id and a report.
pub fn build_tree(store: &ObjectStore, fs: &dyn StorageBackend, opts: &BuildOptions) -> Result<(ObjectId, BuildReport)> {
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
    let mut b = Builder {
        store,
        fs,
        opts,
        use_hints,
        report: BuildReport {
            policy_warnings: opts.policy.warnings.clone(),
            ..Default::default()
        },
    };
    let id = match b.build_dir(&VPath::root(), parent.as_deref())? {
        Some(id) => id,
        None => store.empty_tree()?,
    };
    Ok((id, b.report))
}

impl Builder<'_> {
    fn build_dir(&mut self, dir: &VPath, parent: Option<&Tree>) -> Result<Option<ObjectId>> {
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
                        Some(e) => Some(self.store.tree(&e.id)?),
                        None => None,
                    };
                    if let Some(id) = self.build_dir(&path, sub.as_deref())? {
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

        // Fast path: overlay/tree-view says the file is byte-identical.
        if let Some(pe) = parent_file {
            if self.use_hints && self.fs.known_id(path) == Some(pe.id) {
                return Ok(Some(pe.clone()));
            }
        }

        let meta = self.fs.metadata(path)?;
        let executable = meta.is_some_and(|m| m.executable);
        let data = self.fs.read(path)?;

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

        if desired.is_public() {
            let id = Object::blob_id(&data);
            if let Some(pe) = parent_file {
                if pe.id == id && pe.visibility.is_public() && pe.executable == executable {
                    return Ok(Some(pe.clone())); // unchanged; scanned before
                }
            }
            if !class.allow_secrets {
                let findings = secrets::scan(&data);
                if !findings.is_empty() {
                    self.report.quarantined.push((path.clone(), findings));
                    return Ok(None);
                }
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
}
