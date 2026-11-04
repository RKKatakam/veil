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
//! | merged-in history of an unreleased embargoed merge | cloaked part only | ✗ |
//! | cloaked tags                    | ✓           | ✗             |
//! | key rings / embargo records     | ✓           | ✓ (encrypted, signed) |
//! | isolated files, vault, `local`  | never — not in the graph at all |
//!
//! Redacted tree entries keep their names and ids, so a later push to a
//! team remote or a key grant fills them in without any history rewrite.
//!
//! An unreleased embargoed merge reaches a remote with its extra parents
//! *redacted*: the snapshots only those parents reach (the fix, and how it
//! was made) stay local until the embargo is released, and a tag that would
//! publish them by another route (a tag on the fix, a commit building on
//! it) is skipped with a reason. Graph walks treat a missing parent as
//! absent, so clones of such a remote work normally; the next push after
//! the release fills the parents in, with unchanged snapshot ids.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    keychain::{Keychain, RingMerge, LOCAL_SCOPE},
    object::Object,
    oplog::Tag,
    repo::{is_repo, Repo},
    store::ObjectStore,
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
    fn copy(&mut self, id: ObjectId) -> Result<()> {
        if !self.seen.insert(id) {
            return Ok(());
        }
        let raw = match self.src.get_raw(&id) {
            Ok(r) => r,
            Err(VeilError::Missing(_)) => {
                self.report.missing += 1;
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        if !self.allowed(&raw) {
            self.report.redacted += 1;
            return Ok(());
        }
        let obj = Object::decode(&raw)?;
        if !self.dst.has(&id) {
            self.dst.put_raw(&id, &raw)?;
            self.report.objects_copied += 1;
        }
        match obj {
            Object::Snapshot(s) => {
                if s.signature_valid() == Some(false) {
                    self.report
                        .warnings
                        .push(format!("snapshot {} carries an invalid signature", id.short()));
                }
                self.copy(s.tree)?
            }
            Object::Tree(t) => {
                for e in &t.entries {
                    self.copy(e.id)?;
                    // File fallbacks, and the pre-merge tree of an embargo
                    // wrapper's marker entry.
                    if let Some(fb) = e.fallback {
                        self.copy(fb)?;
                    }
                }
            }
            Object::Blob(_) | Object::Sealed(_) => {}
        }
        Ok(())
    }
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

/// History that must not leave this repository yet: for every unreleased
/// embargoed merge in the local graph, the snapshots reachable only through
/// its merged-in (non-first) parents — the fix itself, and how it was made.
/// Maps each to the embargo that withholds it.
///
/// A public remote receives none of it before release. A team remote may
/// receive the cloaked part (its content and descriptions are sealed for
/// the scope); plaintext snapshots are withheld there too, because team
/// remotes are also read by people outside the embargo's scope.
fn embargo_withheld(local: &Repo, public: bool) -> Result<HashMap<ObjectId, String>> {
    let mut out = HashMap::new();
    for id in local.visible_snapshots()? {
        let s = local.snapshot(&id)?;
        let Some(e) = &s.embargo else { continue };
        if s.parents.len() < 2 || local.keys().embargo_released(e) {
            continue;
        }
        let mainline = local.ancestors(&s.parents[0])?;
        for p in &s.parents[1..] {
            for a in local.ancestors(p)? {
                if mainline.contains(&a) || out.contains_key(&a) {
                    continue;
                }
                let Some(snap) = local.snapshot_opt(&a)? else { continue };
                if public || snap.cloak.is_none() {
                    out.insert(a, e.clone());
                }
            }
        }
    }
    Ok(out)
}

/// The snapshots to send for `tips`: every ancestor, except the withheld
/// merged-in history of unreleased embargoed merges (those merges reach the
/// remote with their extra parents redacted). Fails with a reason if the
/// tips reach withheld history any other way, i.e. some snapshot *builds
/// on* the embargoed fix and would publish it.
fn push_closure(
    store: &ObjectStore,
    keys: &Keychain,
    tips: &[ObjectId],
    withheld: &HashMap<ObjectId, String>,
) -> Result<Result<Vec<ObjectId>, String>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut stack: Vec<ObjectId> = tips.to_vec();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        if let Some(e) = withheld.get(&id) {
            return Ok(Err(format!(
                "{} is part of the history merged under unreleased embargo {e}; it is pushed when the embargo is released",
                id.short()
            )));
        }
        let s = match store.snapshot(&id) {
            Ok(s) => s,
            Err(VeilError::Missing(_)) => continue,
            Err(e) => return Err(e),
        };
        let embargoed_merge = s.embargo.as_deref().is_some_and(|e| !keys.embargo_released(e));
        for (i, p) in s.parents.iter().enumerate() {
            match withheld.get(p) {
                None => stack.push(*p),
                Some(_) if embargoed_merge && i > 0 => {} // redacted parent
                Some(e) => {
                    return Ok(Err(format!(
                        "snapshot {} builds on {}, which is withheld by unreleased embargo {e}; release the embargo first",
                        id.short(),
                        p.short()
                    )))
                }
            }
        }
        out.push(id);
    }
    Ok(Ok(out))
}

/// Merge key rings and embargo records from `src` into `dst`.
///
/// Nothing is merged as a union any more: each ring is a signed, hash-chained
/// log that only ever fast-forwards (see [`Keychain::merge_ring`]), so a
/// revocation cannot be undone by syncing with a replica that still lists
/// the member. Rings are merged before embargo records because the records'
/// signatures are checked against ring membership.
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
    // The merged-in history of an unreleased embargoed merge stays here, and
    // so does any tag that would publish it by another route.
    let withheld = embargo_withheld(local, public)?;
    let mut sendable = Vec::new();
    for (name, tag) in selected {
        match push_closure(local.store(), local.keys(), &[tag.target], &withheld)? {
            Ok(_) => sendable.push((name, tag)),
            Err(why) => report.tags_skipped.push((name, why)),
        }
    }
    let selected = sendable;
    let tips: Vec<ObjectId> = selected.iter().map(|(_, t)| t.target).collect();
    let ids = push_closure(local.store(), local.keys(), &tips, &withheld)?
        .map_err(|why| VeilError::repo(format!("push: {why}")))?;
    let mut xfer = Transfer {
        src: local.store(),
        dst: remote.store(),
        src_keys: local.keys(),
        public,
        seen: HashSet::new(),
        report,
    };
    for id in ids {
        xfer.copy(id)?;
    }
    let mut report = xfer.report;
    sync_meta(local.keys(), remote.keys(), &mut report.warnings)?;

    let mut tx = remote.transaction(format!("push from {}", local.repo_id()))?;
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

/// Fetch every tag from `remote`, record them as `<remote_name>/<tag>`, and
/// create or fast-forward local tags.
pub fn pull(local: &mut Repo, remote_name: &str, remote_backend: Arc<dyn StorageBackend>) -> Result<SyncReport> {
    if !is_repo(&*remote_backend) {
        return Err(VeilError::NotFound(format!("Veil repository at remote '{remote_name}'")));
    }
    let remote = Repo::open(remote_backend, None, "remote")?;
    let tags: Vec<(String, Tag)> = remote.view().tags.clone().into_iter().collect();
    let tips: Vec<ObjectId> = tags.iter().map(|(_, t)| t.target).collect();
    let mut xfer = Transfer {
        src: remote.store(),
        dst: local.store(),
        src_keys: remote.keys(),
        public: false,
        seen: HashSet::new(),
        report: SyncReport::default(),
    };
    for id in ancestors_in(remote.store(), &tips)? {
        xfer.copy(id)?;
    }
    let mut report = xfer.report;
    sync_meta(remote.keys(), local.keys(), &mut report.warnings)?;
    local.keys().invalidate();

    let mut tx = local.transaction(format!("pull from {remote_name}"))?;
    for (name, tag) in tags {
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
