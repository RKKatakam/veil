//! Synchronisation between repositories (any two `StorageBackend`s).
//!
//! Visibility is enforced *in the transfer itself*:
//!
//! | content                         | team remote | public remote |
//! |---------------------------------|-------------|---------------|
//! | public objects                  | ✓           | ✓             |
//! | cloaked objects (ciphertext)    | ✓           | ✗ redacted    |
//! | unreleased embargoed objects    | ✓           | ✗ (fallback ✓)|
//! | released embargoed objects      | ✓           | ✓             |
//! | cloaked tags                    | ✓           | ✗             |
//! | key rings / embargo records     | ✓           | ✓ (encrypted, signed) |
//! | isolated files, vault, `local`  | never — not in the graph at all |
//!
//! Redacted tree entries keep their names and ids, so a later push to a
//! team remote or a key grant fills them in without any history rewrite.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::{
    commands::validate_tag_name,
    error::{Result, VeilError},
    id::ObjectId,
    keychain::{Keychain, RingMerge, LOCAL_SCOPE},
    object::{EntryKind, Object},
    oplog::Tag,
    repo::{is_repo, Repo},
    store::ObjectStore,
    tree::MAX_TREE_DEPTH,
    vfs::StorageBackend,
};

#[derive(Debug, Default, Clone)]
pub struct SyncReport {
    pub objects_copied: usize,
    pub redacted: usize,
    pub missing: usize,
    pub tags_updated: Vec<(String, ObjectId)>,
    pub tags_skipped: Vec<(String, String)>,
    pub warnings: Vec<String>,
}

struct Transfer<'a> {
    src: &'a ObjectStore,
    dst: &'a ObjectStore,
    src_keys: &'a Keychain,
    public: bool,
    seen: HashSet<ObjectId>,
    /// Tree height of every object copied so far (0 for non-trees).
    heights: HashMap<ObjectId, usize>,
    report: SyncReport,
}

impl Transfer<'_> {
    fn allowed(&self, raw: &[u8]) -> bool {
        match Object::sealed_scope(raw) {
            None => true,
            Some(scope) if scope == LOCAL_SCOPE => false,
            Some(_) if !self.public => true,
            Some(scope) => match scope.strip_prefix("embargo/") {
                Some(id) => self.src_keys.embargo_released(id),
                None => false,
            },
        }
    }

    /// Copy one object and everything it references (not snapshot parents).
    ///
    /// The walk is iterative (the remote controls the depth) and rejects
    /// trees nested deeper than [`MAX_TREE_DEPTH`]. Depth is measured as
    /// each tree's *height* (longest chain of trees below it, memoised per
    /// id), because content-addressed trees are shared: the same subtree
    /// may first be met shallowly and later deep inside another tree.
    fn copy(&mut self, root: ObjectId) -> Result<()> {
        struct Frame {
            id: ObjectId,
            is_tree: bool,
            children: Vec<ObjectId>,
            next: usize,
            height: usize,
        }
        let mut stack: Vec<Frame> = Vec::new();
        let mut trees_on_stack = 0usize;
        let mut pending = Some(root);
        loop {
            if let Some(id) = pending.take() {
                if let Some(frame) = self.enter(id)? {
                    if frame.0 {
                        trees_on_stack += 1;
                        if trees_on_stack > MAX_TREE_DEPTH {
                            return Err(too_deep(root));
                        }
                    }
                    stack.push(Frame {
                        id,
                        is_tree: frame.0,
                        children: frame.1,
                        next: 0,
                        height: 0,
                    });
                } else if let Some(top) = stack.last_mut() {
                    let h = self.heights.get(&id).copied().unwrap_or(0);
                    top.height = top.height.max(h);
                }
            }
            let Some(top) = stack.last_mut() else {
                return Ok(());
            };
            if let Some(child) = top.children.get(top.next) {
                top.next += 1;
                pending = Some(*child);
                continue;
            }
            let done = stack.pop().unwrap();
            let height = done.height + usize::from(done.is_tree);
            if done.is_tree {
                trees_on_stack -= 1;
                if height > MAX_TREE_DEPTH {
                    return Err(too_deep(root));
                }
            }
            self.heights.insert(done.id, height);
            if let Some(parent) = stack.last_mut() {
                parent.height = parent.height.max(height);
            }
        }
    }

    /// Fetch, check and store one object. Returns `None` if there is
    /// nothing to descend into (already seen, missing or redacted), else
    /// whether it is a tree and the ids it references.
    fn enter(&mut self, id: ObjectId) -> Result<Option<(bool, Vec<ObjectId>)>> {
        if !self.seen.insert(id) {
            return Ok(None);
        }
        // `get_raw` verifies the content against `id`.
        let raw = match self.src.get_raw(&id) {
            Ok(r) => r,
            Err(VeilError::Missing(_)) => {
                self.report.missing += 1;
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        if !self.allowed(&raw) {
            self.report.redacted += 1;
            return Ok(None);
        }
        // Decoding validates structure: canonical trees with safe names.
        let obj = Object::decode(&raw)?;
        if self.dst.put_raw(&id, &raw)? {
            self.report.objects_copied += 1;
        }
        Ok(Some(match obj {
            Object::Snapshot(s) => {
                if s.signature_valid() == Some(false) {
                    self.report
                        .warnings
                        .push(format!("snapshot {} carries an invalid signature", id.short()));
                }
                (false, vec![s.tree])
            }
            Object::Tree(t) => {
                let mut children = Vec::with_capacity(t.entries.len());
                for e in &t.entries {
                    children.push(e.id);
                    if let (EntryKind::File, Some(fb)) = (e.kind, e.fallback) {
                        children.push(fb);
                    }
                }
                (true, children)
            }
            Object::Blob(_) | Object::Sealed(_) => (false, Vec::new()),
        }))
    }
}

fn too_deep(root: ObjectId) -> VeilError {
    VeilError::Corrupt(
        root.hex(),
        format!("directory nesting exceeds {MAX_TREE_DEPTH} levels; refusing hostile tree"),
    )
}

fn ancestors_in(store: &ObjectStore, tips: &[ObjectId]) -> Result<Vec<ObjectId>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut stack: Vec<ObjectId> = tips.to_vec();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        match store.snapshot(&id) {
            Ok(s) => stack.extend(s.parents.iter().copied()),
            Err(VeilError::Missing(_)) => continue,
            Err(e) => return Err(e),
        }
        out.push(id);
    }
    Ok(out)
}

/// Merge key rings and embargo records from `src` into `dst`.
///
/// Nothing is merged as a union any more: each ring is a signed, hash-chained
/// log that only ever fast-forwards (see [`Keychain::merge_ring`]), so a
/// revocation cannot be undone by syncing with a replica that still lists
/// the member. Rings are merged before embargo records because the records'
/// signatures are checked against ring membership. Runs inside the
/// destination's transaction: each merge is a read-modify-write under its
/// lock (the keychain takes it reentrantly).
fn sync_meta(src: &Keychain, dst: &Keychain, warnings: &mut Vec<String>) -> Result<()> {
    for ring in src.rings()? {
        if let RingMerge::Rejected(w) = dst.merge_ring(&ring)? {
            warnings.push(w);
        }
    }
    for rec in src.embargoes()? {
        if let Some(w) = dst.merge_embargo(&rec)? {
            warnings.push(w);
        }
    }
    dst.invalidate();
    Ok(())
}

/// Push tags (all by default) and their history to `remote`.
pub fn push(
    local: &mut Repo,
    remote_backend: Arc<dyn StorageBackend>,
    public: bool,
    only_tags: &[String],
    force: bool,
) -> Result<SyncReport> {
    let mut remote = if is_repo(&*remote_backend) {
        Repo::open(remote_backend, None, "remote")?
    } else {
        Repo::init_bare(remote_backend)?
    };
    let mut report = SyncReport::default();
    let mut selected: Vec<(String, Tag)> = Vec::new();
    for (name, tag) in &local.view().tags {
        if !only_tags.is_empty() && !only_tags.contains(name) {
            continue;
        }
        if public && tag.cloak.is_some() {
            report
                .tags_skipped
                .push((name.clone(), "cloaked tag is never pushed to a public remote".into()));
            continue;
        }
        selected.push((name.clone(), tag.clone()));
    }
    for t in only_tags {
        if !local.view().tags.contains_key(t) {
            return Err(VeilError::NotFound(format!("tag '{t}'")));
        }
    }
    let tips: Vec<ObjectId> = selected.iter().map(|(_, t)| t.target).collect();
    // Objects and metadata are copied under the remote's lock: metadata
    // merges are read-modify-writes, and objects go through the
    // transaction's durability barrier.
    let mut tx = remote.transaction(format!("push from {}", local.repo_id()))?;
    let mut xfer = Transfer {
        src: local.store(),
        dst: tx.repo().store(),
        src_keys: local.keys(),
        public,
        seen: HashSet::new(),
        heights: HashMap::new(),
        report,
    };
    for id in ancestors_in(local.store(), &tips)? {
        xfer.copy(id)?;
    }
    let mut report = xfer.report;
    sync_meta(local.keys(), tx.repo().keys(), &mut report.warnings)?;
    for (name, tag) in selected {
        if let Some(existing) = tx.view.tags.get(&name) {
            if existing.target == tag.target {
                continue;
            }
            if !force && !tx.repo().is_ancestor(&existing.target, &tag.target)? {
                report
                    .tags_skipped
                    .push((name, "remote has diverged (non-fast-forward; use --force)".into()));
                continue;
            }
        }
        tx.add_head(tag.target)?;
        let cloak = if public { None } else { tag.cloak };
        tx.view.tags.insert(
            name.clone(),
            Tag {
                target: tag.target,
                cloak,
            },
        );
        report.tags_updated.push((name, tag.target));
    }
    tx.commit()?;
    Ok(report)
}

/// Why `target` cannot be the target of a tag, if it cannot.
fn unusable_target(store: &ObjectStore, target: &ObjectId) -> Result<Option<&'static str>> {
    match store.snapshot(target) {
        Ok(_) => Ok(None),
        Err(VeilError::Missing(_)) => Ok(Some("is missing")),
        Err(VeilError::Corrupt(..)) | Err(VeilError::Json(_)) => Ok(Some("is not a valid snapshot")),
        Err(e) if e.is_unreadable() => Ok(Some("is not readable")),
        Err(e) => Err(e),
    }
}

/// Fetch every tag from `remote`, record them as `<remote_name>/<tag>`, and
/// create or fast-forward local tags.
pub fn pull(local: &mut Repo, remote_name: &str, remote_backend: Arc<dyn StorageBackend>) -> Result<SyncReport> {
    if !is_repo(&*remote_backend) {
        return Err(VeilError::NotFound(format!("Veil repository at remote '{remote_name}'")));
    }
    let remote = Repo::open(remote_backend, None, "remote")?;
    let tags: Vec<(String, Tag)> = remote.view().tags.clone().into_iter().collect();
    // Only snapshot targets are fetched; tags on anything else (missing,
    // a tree, a blob) are skipped with a warning below.
    let mut tips = Vec::new();
    for (_, t) in &tags {
        match remote.store().get(&t.target) {
            Ok(Object::Snapshot(_)) => tips.push(t.target),
            Ok(_) | Err(VeilError::Missing(_)) => {}
            Err(e) => return Err(e),
        }
    }
    // Under the local lock, like push (see there).
    let mut tx = local.transaction(format!("pull from {remote_name}"))?;
    let mut xfer = Transfer {
        src: remote.store(),
        dst: tx.repo().store(),
        src_keys: remote.keys(),
        public: false,
        seen: HashSet::new(),
        heights: HashMap::new(),
        report: SyncReport::default(),
    };
    for id in ancestors_in(remote.store(), &tips)? {
        xfer.copy(id)?;
    }
    let mut report = xfer.report;
    sync_meta(remote.keys(), tx.repo().keys(), &mut report.warnings)?;
    tx.repo().keys().invalidate();
    for (name, tag) in tags {
        // Tag names and targets come from the remote: a name may carry
        // terminal escapes or path tricks, and a target may be missing or
        // not a snapshot, which would break every later graph query.
        if validate_tag_name(&name).is_err() {
            report
                .warnings
                .push(format!("skipped remote tag {name:?}: invalid tag name"));
            continue;
        }
        if let Some(why) = unusable_target(tx.repo().store(), &tag.target)? {
            report
                .warnings
                .push(format!("skipped remote tag '{name}': target {} {why}", tag.target.short()));
            continue;
        }
        tx.view.remote_tags.insert(format!("{remote_name}/{name}"), tag.target);
        match tx.view.tags.get(&name).cloned() {
            None => {
                tx.view.tags.insert(name.clone(), tag.clone());
                report.tags_updated.push((name, tag.target));
            }
            Some(existing) if existing.target == tag.target => {}
            Some(existing) => {
                if tx.repo().is_ancestor(&existing.target, &tag.target)? {
                    tx.view.tags.insert(
                        name.clone(),
                        Tag {
                            target: tag.target,
                            cloak: existing.cloak,
                        },
                    );
                    report.tags_updated.push((name, tag.target));
                } else if !tx.repo().is_ancestor(&tag.target, &existing.target)? {
                    report.warnings.push(format!(
                        "tag '{name}' has diverged from {remote_name}/{name}; merge with `vl merge {remote_name}/{name}`"
                    ));
                }
            }
        }
    }
    tx.commit()?;
    Ok(report)
}
