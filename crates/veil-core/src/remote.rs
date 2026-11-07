//! Synchronisation between repositories (any two `StorageBackend`s).
//!
//! Visibility is enforced *in the transfer itself*:
//!
//! | content                         | team receiver | public receiver |
//! |---------------------------------|---------------|-----------------|
//! | plain objects                   | ✓             | ✓               |
//! | sealed secrets (ciphertext)     | ✓             | ✗ redacted      |
//! | an unreleased embargoed merge, its fix, and anything built on them | ✗ | ✗ |
//! | annotated tag objects (`veil:atag`, format 5) | ✓ with their tag | ✓ with their tag |
//! | key rings (secrets only)        | ✓             | ✗ (they name the members) |
//! | embargo records                 | ✓             | ✓ (plain)       |
//! | team vault (`vl secret --scope`) | ✓ (sealed, signed records) | ✗ |
//! | isolated files, vault, `local`  | never — not in the graph at all |
//!
//! Only secret files are ever encrypted. Redacted tree entries keep their
//! names and ids, so a later transfer to a team receiver or a key grant
//! fills them in without any history rewrite. A tag that would publish
//! embargoed history (a tag on the fix, a commit building on it) is skipped
//! with a reason until the release.
//!
//! # Who uses it
//!
//! Users sync through the Veil server only (`docs/OVERVIEW.md`): `vl`'s
//! server client (`crates/vl/src/hub.rs`) uses [`Incoming`] to write what
//! the server sends and [`apply_remote_tags`] to record its branches. The
//! repository-to-repository [`push`] and [`pull`] here are the engine's
//! in-process transfer: the tests use it, with in-memory or local stores,
//! to check the visibility filters above, and nothing reaches it from the
//! command line (path and SFTP remotes were removed with the
//! simplification pass).
//!
//! * **Push** runs under the receiver's lock: it decides the tags against
//!   the receiver's view, walks the pushed history object by object
//!   through the filters (`allowed`, canonical decoding, tree depth),
//!   writes what the receiver lacks, then the operation.
//! * **Pull** walks the sender's history the same way, under the local
//!   lock, and records the sender's tags ([`apply_remote_tags`]).
//! * Both re-verify the receiver's copies (`put_raw`), so a damaged object
//!   is repaired and a crash leftover (a snapshot without its trees) is
//!   completed.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::{
    cache::LruCache,
    commands::validate_tag_name,
    error::{Result, VeilError},
    id::ObjectId,
    keychain::{Keychain, RingMerge, LOCAL_SCOPE},
    object::Object,
    oplog::Tag,
    pack::{PackWriter, DEFAULT_LEVEL},
    repo::{is_repo, Repo},
    store::ObjectStore,
    tree::MAX_TREE_DEPTH,
    vfs::StorageBackend,
    vpath::VPath,
};

#[derive(Debug, Default, Clone)]
pub struct SyncReport {
    pub objects_copied: usize,
    pub redacted: usize,
    pub missing: usize,
    pub tags_updated: Vec<(String, ObjectId)>,
    pub tags_skipped: Vec<(String, String)>,
    /// The tags of `tags_skipped` that the remote refused: it holds a
    /// version that is not an ancestor of ours (push without `force`).
    /// The others were held back by design (a cloaked tag on a public
    /// remote, an unreleased embargo).
    pub tags_rejected: Vec<String>,
    pub warnings: Vec<String>,
    /// Packs written on the receiving side ([`Incoming`]).
    pub packs_written: usize,
    /// Embargo releases staged here that this push published (written into
    /// their records and sent): from now on they cannot be taken back.
    pub releases_published: Vec<String>,
    /// Remote tags `<remote>/<tag>` removed because the remote no longer
    /// has the tag (pull).
    pub remote_tags_removed: Vec<String>,
    /// Local tags that a pull did not recreate: deleted here, and not
    /// moved on the remote since ([`deleted_tags`]).
    pub tags_kept_deleted: Vec<String>,
    /// Pull: local release tags (annotated) the remote holds at another
    /// target, as (tag, local target, remote target). Release tags never
    /// move on a pull; the remote's target is `<remote>/<tag>`.
    pub release_tags_kept: Vec<(String, ObjectId, ObjectId)>,
}

/// A pack holding at most about this much (uncompressed) data is written
/// before the next one is started.
const PACK_LIMIT: u64 = 128 << 20;

/// What the last versions kept as delta bases may hold together (BUG-800:
/// one per path, for the whole pack, used to be kept).
const LAST_VERSIONS: usize = 64 << 20;

/// Bytes of objects [`PackSink`] encodes at a time.
const BATCH_BYTES: usize = 4 << 20;

/// Collects objects into packs in the store's pack directory. Below
/// `threshold` objects they are written as loose objects instead, so a
/// small pull does not leave a tiny pack behind.
struct PackSink<'a> {
    /// The destination store: decides what its repository format may hold
    /// (packs bypass `put_raw`, so the check happens here).
    dest: &'a ObjectStore,
    backend: &'a dyn StorageBackend,
    dir: VPath,
    threshold: usize,
    pending: Vec<(ObjectId, Vec<u8>, String)>,
    /// The pack being streamed (BUG-800: it used to be built in memory).
    builder: Option<PackWriter<'a>>,
    builder_bytes: u64,
    /// Objects waiting to be encoded into `builder`, a few MiB at a time:
    /// those with no earlier version at their path are compressed on
    /// several threads ([`PackSink::encode_batch`]).
    batch: Vec<(ObjectId, Vec<u8>, String)>,
    batch_bytes: usize,
    /// The last object packed at each path (by the path's hash), the
    /// delta base for the next version found there; least recently used
    /// out past [`LAST_VERSIONS`].
    last: LruCache<(ObjectId, Arc<Vec<u8>>)>,
    packs: usize,
    /// A pack is closed once it holds this much (uncompressed).
    limit: u64,
}

impl<'a> PackSink<'a> {
    fn new(dest: &'a ObjectStore, threshold: usize) -> Self {
        PackSink {
            dest,
            backend: &**dest.backend(),
            dir: dest.pack_dir(),
            threshold,
            pending: Vec::new(),
            builder: None,
            builder_bytes: 0,
            batch: Vec::new(),
            batch_bytes: 0,
            last: LruCache::new(LAST_VERSIONS),
            packs: 0,
            limit: PACK_LIMIT,
        }
    }

    fn put(&mut self, id: ObjectId, raw: Vec<u8>, path: &str) -> Result<bool> {
        // A format-1 repository must never receive binary trees.
        self.dest.check_storable(&raw)?;
        if self.builder.is_none() && self.pending.len() < self.threshold {
            self.pending.push((id, raw, path.to_string()));
            return Ok(true);
        }
        for (id, raw, path) in std::mem::take(&mut self.pending) {
            self.pack(id, raw, path)?;
        }
        self.pack(id, raw, path.to_string())?;
        Ok(true)
    }

    fn pack(&mut self, id: ObjectId, raw: Vec<u8>, path: String) -> Result<()> {
        if self.builder.is_none() {
            self.builder = Some(PackWriter::new(self.backend.create_stream(&self.dir, true)?, DEFAULT_LEVEL)?);
        }
        self.batch_bytes += raw.len();
        self.batch.push((id, raw, path));
        // Encoded by the time the pack reaches its limit, so packs close
        // where they did object by object.
        if self.batch_bytes >= BATCH_BYTES || self.builder_bytes + self.batch_bytes as u64 >= self.limit {
            self.encode_batch()?;
        }
        Ok(())
    }

    /// Encode the waiting objects into the pack, in order. An object with
    /// an earlier version at its path (packed already, or earlier in the
    /// batch) is a delta candidate, encoded here; the others are
    /// compressed on several threads first.
    fn encode_batch(&mut self) -> Result<()> {
        let batch = std::mem::take(&mut self.batch);
        self.batch_bytes = 0;
        let Some(builder) = self.builder.as_mut() else { return Ok(()) };
        let mut keys = HashSet::new();
        let (mut plain, mut plain_keys, mut later) = (Vec::new(), Vec::new(), Vec::new());
        for (id, raw, path) in batch {
            let key = ObjectId::hash(path.as_bytes());
            if self.last.get(&key).is_some() || !keys.insert(key) {
                later.push((id, raw, key));
            } else {
                plain.push((id, raw));
                plain_keys.push(key);
            }
        }
        let threads = match cfg!(feature = "os") {
            true => std::thread::available_parallelism().map_or(1, |n| n.get()).min(8),
            false => 1,
        };
        let entries = crate::pack::encode_entries(&plain, DEFAULT_LEVEL, threads)?;
        for (((id, raw), e), key) in plain.into_iter().zip(&entries).zip(plain_keys) {
            if !builder.add_entry(id, e)? {
                builder.add(id, &raw, None)?;
            }
            self.builder_bytes += raw.len() as u64;
            let weight = raw.len();
            self.last.insert(key, (id, Arc::new(raw)), weight);
        }
        for (id, raw, key) in later {
            let base = self
                .last
                .get(&key)
                .filter(|(bid, braw)| builder.contains(bid) && Object::is_blob_raw(braw) == Object::is_blob_raw(&raw));
            builder.add(id, &raw, base.as_ref().map(|(bid, braw)| (bid, &braw[..])))?;
            self.builder_bytes += raw.len() as u64;
            let weight = raw.len();
            self.last.insert(key, (id, Arc::new(raw)), weight);
        }
        if self.builder_bytes >= self.limit {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if !self.batch.is_empty() {
            // Encoding the batch may close the pack itself (at the limit).
            return self.encode_batch().and_then(|()| self.flush());
        }
        if let Some(b) = self.builder.take() {
            // `finish` publishes the pack (durably), then its index, after
            // a barrier, durably. A crash before the index leaves a pack
            // nobody finds; the index is never torn.
            if b.finish(&PackWrites(self.backend, self.dest), &self.dir)?.is_some() {
                self.packs += 1;
            }
        }
        self.builder_bytes = 0;
        self.last.clear();
        Ok(())
    }

    fn finish(mut self, report: &mut SyncReport) -> Result<()> {
        if self.builder.is_none() {
            for (id, raw, _) in std::mem::take(&mut self.pending) {
                self.dest.put_raw(&id, &raw)?;
            }
        }
        self.flush()?;
        report.packs_written += self.packs;
        Ok(())
    }
}

/// The backend as `PackWriter::finish` sees it: an index is written only
/// after a barrier, durably. The barrier is the destination store's, which
/// voids its own unsynced objects if it fails. (The pack itself is a
/// durable stream of the backend.)
#[derive(Debug)]
struct PackWrites<'a>(&'a dyn StorageBackend, &'a ObjectStore);

impl StorageBackend for PackWrites<'_> {
    fn kind(&self) -> &'static str {
        self.0.kind()
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        self.0.read(path)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        if path.as_str().ends_with(".idx") {
            self.1.sync_barrier()?;
            self.0.write(path, data)
        } else {
            self.0.write_unsynced(path, data)
        }
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.0.create_new(path, data)
    }
    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.0.remove_file(path)
    }
    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        self.0.remove_dir_all(path)
    }
    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        self.0.create_dir_all(path)
    }
    fn list_dir(&self, path: &VPath) -> Result<Vec<crate::vfs::DirEntry>> {
        self.0.list_dir(path)
    }
    fn metadata(&self, path: &VPath) -> Result<Option<crate::vfs::Metadata>> {
        self.0.metadata(path)
    }
    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()> {
        self.0.set_executable(path, executable)
    }
}

/// One walk from a store to another: every object is fetched (and checked
/// against its id), filtered by [`Transfer::allowed`], decoded (canonical
/// trees with safe names) and written with `put_raw`, which re-verifies a
/// copy the receiver already has.
struct Transfer<'a> {
    src: &'a ObjectStore,
    dst: &'a ObjectStore,
    public: bool,
    seen: HashSet<ObjectId>,
    /// Tree height of every object copied so far (0 for non-trees).
    heights: HashMap<ObjectId, usize>,
    report: SyncReport,
}

impl Transfer<'_> {
    fn allowed(&self, raw: &[u8]) -> bool {
        // A sealed secret goes to team receivers only, never under `local`.
        match Object::sealed_scope(raw) {
            None => true,
            Some(scope) if scope == LOCAL_SCOPE => false,
            Some(_) => !self.public,
        }
    }

    /// Copy one object and everything it references (not snapshot parents).
    ///
    /// The walk is iterative (the sender controls the depth) and rejects
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
                if let Some((is_tree, children)) = self.enter(id)? {
                    if is_tree {
                        trees_on_stack += 1;
                        if trees_on_stack > MAX_TREE_DEPTH {
                            return Err(too_deep(root));
                        }
                    }
                    stack.push(Frame {
                        id,
                        is_tree,
                        children,
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
        // The store verifies the content against `id`.
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
                }
                (true, children)
            }
            // Every version a conflict names: each is checked like any
            // object (`allowed`), so a public receiver never gets a sealed
            // side, only the conflict naming it.
            Object::Conflict(c) => (false, c.referenced_ids()),
            // An annotated tag is sent with its tag ([`copy_annotations`]),
            // whose target went through the tag checks; nothing below it
            // is reached through it.
            Object::Blob(_) | Object::Sealed(_) | Object::Atag(_) => (false, Vec::new()),
        }))
    }
}

fn too_deep(root: ObjectId) -> VeilError {
    VeilError::Corrupt(
        root.hex(),
        format!("directory nesting exceeds {MAX_TREE_DEPTH} levels; refusing hostile tree"),
    )
}

pub(crate) fn ancestors_in(store: &ObjectStore, tips: &[ObjectId]) -> Result<Vec<ObjectId>> {
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

/// The snapshots that unreleased embargo `embargo` withholds from a
/// public remote (its fix history): what releasing it publishes, beside
/// the merge's content.
pub fn withheld_by_embargo(local: &Repo, embargo: &str) -> Result<Vec<ObjectId>> {
    let mut out: Vec<ObjectId> = embargo_withheld(local)?
        .into_iter()
        .filter(|(_, e)| e == embargo)
        .map(|(id, _)| id)
        .collect();
    out.sort();
    Ok(out)
}

/// History that must not leave this repository yet: for every unreleased
/// embargoed merge in the local graph, the merge itself and the snapshots
/// reachable only through its merged-in (non-first) parents (the fix, and
/// how it was made). Maps each to the embargo that withholds it.
/// Embargoes are not encrypted, so no receiver gets any of it before the
/// release, and a snapshot that builds on it is refused too
/// ([`push_closure`]).
pub(crate) fn embargo_withheld(local: &Repo) -> Result<HashMap<ObjectId, String>> {
    let mut out = HashMap::new();
    for id in local.visible_embargoed()? {
        let s = local.snapshot(&id)?;
        let Some(e) = &s.embargo else { continue };
        if local.keys().embargo_released(e) {
            continue;
        }
        out.entry(id).or_insert_with(|| e.clone());
        if s.parents.len() < 2 {
            continue;
        }
        for a in local.graph().range(local, &s.parents[1..], &s.parents[..1])? {
            out.entry(a).or_insert_with(|| e.clone());
        }
    }
    Ok(out)
}

/// For each of `targets` (tags another route, such as the Veil server's
/// push, is about to send): why it may not be sent because it would publish
/// history an unreleased embargo withholds (`None`: it may). Nothing of
/// such history may leave the repository, by any route.
pub fn embargo_blocks(local: &Repo, targets: &[ObjectId]) -> Result<Vec<Option<String>>> {
    let withheld = embargo_withheld(local)?;
    if withheld.is_empty() {
        return Ok(vec![None; targets.len()]);
    }
    targets
        .iter()
        .map(|t| Ok(push_closure(local.store(), &[*t], &withheld)?.err()))
        .collect()
}

/// For a snapshot no push may send yet (an unreleased embargo withholds
/// it, or it builds on withheld history): the nearest snapshot down its
/// first parents that a push does send, whose files are already
/// published. `None` for a snapshot a push sends. What the snapshot holds
/// beyond that one is under the embargo (`vl ls`'s tier `embargoed`).
pub fn embargo_base(local: &Repo, id: &ObjectId) -> Result<Option<ObjectId>> {
    let withheld = embargo_withheld(local)?;
    if withheld.is_empty() || push_closure(local.store(), &[*id], &withheld)?.is_ok() {
        return Ok(None);
    }
    let mut x = *id;
    loop {
        let Some(s) = local.snapshot_opt(&x)? else { return Ok(Some(local.root_id())) };
        let Some(p) = s.parents.first().copied() else { return Ok(Some(local.root_id())) };
        if push_closure(local.store(), &[p], &withheld)?.is_ok() {
            return Ok(Some(p));
        }
        x = p;
    }
}

/// The snapshots to send for `tips`: every ancestor. Fails with a reason
/// if the tips reach history an unreleased embargo withholds (the
/// embargoed merge, its fix, or anything built on them).
pub(crate) fn push_closure(
    store: &ObjectStore,
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
        for p in &s.parents {
            match withheld.get(p) {
                None => stack.push(*p),
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

// ---- what a push sends ----------------------------------------------------------

/// Merge key rings and embargo records from `src` into `dst`.
///
/// Nothing is merged as a union any more: each ring is a signed, hash-chained
/// log that only ever fast-forwards (see [`Keychain::merge_ring`]), so a
/// revocation cannot be undone by syncing with a replica that still lists
/// the member. Embargo records are plain ([`Keychain::merge_embargo`]).
/// Runs inside the destination's transaction: each merge is a
/// read-modify-write under its lock (the keychain takes it reentrantly).
///
/// A public destination gets no rings (they name every member, BUG-077),
/// only embargo records. Rings an earlier vl pushed there are left
/// alone (removing them would lock members out of a team remote that was
/// added as public by mistake), with a warning.
///
/// Team-vault records follow the rings: team destinations only, checked
/// against the destination's (just merged) ring ([`crate::team_vault`]).
/// `local` is the keychain holding this identity (the source on push, the
/// destination on pull); `pulling` turns on warnings about records that are
/// refused or will not count.
fn sync_meta(src: &Keychain, dst: &Keychain, public: bool, pulling: bool, warnings: &mut Vec<String>) -> Result<()> {
    if public {
        let records = crate::team_vault::record_count(&**dst.backend())?;
        if records > 0 {
            warnings.push(format!(
                "this public remote holds {records} team-vault record(s) (encrypted), which vl never pushes to \
                 public remotes. If it really is public, delete .veil/meta/vault/ there"
            ));
        }
        let left = dst.rings()?.len();
        if left > 0 {
            warnings.push(format!(
                "this public remote holds {left} key ring(s), pushed by an earlier vl, that name the members of \
                 their scopes; vl no longer pushes rings to public remotes. If it really is public, delete \
                 .veil/meta/keyrings/ there"
            ));
        }
    } else {
        for ring in src.rings()? {
            if let RingMerge::Rejected(w) = dst.merge_ring(&ring)? {
                warnings.push(w);
            }
        }
        dst.invalidate();
        let local = if pulling { dst } else { src };
        crate::team_vault::sync(src, dst, local, pulling, warnings)?;
    }
    for rec in src.embargoes()? {
        if let Some(w) = dst.merge_embargo(&rec)? {
            warnings.push(w);
        }
    }
    dst.invalidate();
    Ok(())
}

// ---- remotes -----------------------------------------------------------------

/// Check a remote name: it becomes the first component of the remote tags
/// `<remote>/<tag>`. ASCII letters,
/// digits, `-`, `_` and `.`; not empty, no leading `-` or `.`, no `..`, not
/// ending in `.lock` (BUG-286). A `/` would make `origin/main/<tag>`
/// collide with remote `origin`'s tag `main/<tag>`.
pub fn validate_remote_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && !name.starts_with(['-', '.'])
        && !name.ends_with(".lock")
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !name.contains("..");
    if ok {
        Ok(())
    } else {
        Err(VeilError::repo(format!(
            "invalid remote name {name:?}: use letters, digits, '-', '_' and '.' (not first), as in `origin`"
        )))
    }
}

/// Add remote `name` for `url` (`vl remote add`: a Veil server project).
/// Refuses an invalid name and an existing remote.
pub fn add_remote(repo: &mut Repo, name: &str, url: &str) -> Result<()> {
    validate_remote_name(name)?;
    // Under the repository lock (`update_config`): a concurrent `vl remote
    // add` must not be lost to this read-modify-write of repo.json.
    repo.update_config(|config| {
        if config.remotes.contains_key(name) {
            return Err(VeilError::repo(format!("remote '{name}' already exists")));
        }
        config.remotes.insert(
            name.to_string(),
            crate::repo::RemoteConfig {
                url: url.to_string(),
                public: false,
                only: None,
            },
        );
        Ok(())
    })?;
    repo.record_outside_view(
        format!("add remote {name}"),
        format!("remotes live in .veil/repo.json, outside the operation log; run `vl remote rm {name}`"),
    )?;
    Ok(())
}

/// Remove Veil remote `name` and its remote tags `<name>/*` (`vl remote
/// rm`, BUG-282). The remote tags go first, in one operation; the remote
/// itself last, so that an interruption leaves the remote configured (a
/// retry finishes the job), never remote tags of a remote that is gone.
pub fn remove_remote(repo: &mut Repo, name: &str) -> Result<crate::repo::RemoteConfig> {
    let removed = crate::repo::read_config(&**repo.backend())?
        .remotes
        .get(name)
        .cloned()
        .ok_or_else(|| VeilError::repo(format!("no remote named '{name}'")))?;
    let mut tx = repo.transaction(format!("remove remote {name}"))?;
    tx.repository_wide();
    let prefix = format!("{name}/");
    tx.view.remote_tags.retain(|k, _| !k.starts_with(&prefix));
    tx.manual_undo(format!(
        "remotes live in .veil/repo.json, outside the operation log; add it back with `vl remote add {name} {}` \
         (its remote tags come back with the next pull)",
        removed.url
    ));
    tx.commit()?;
    repo.update_config(|config| {
        config.remotes.remove(name);
        Ok(())
    })?;
    Ok(removed)
}

// ---- tag deletion ---------------------------------------------------------------

/// Where [`deleted_tags`] are recorded: repository-local, outside the view
/// and the operation log, so no repository format changes (an older vl
/// ignores the file and never rewrites it).
fn deleted_tags_path() -> VPath {
    VPath::new(".veil/local/deleted_tags.json").expect("valid path")
}

/// Tags deleted in this repository with `vl tag delete`: name → the
/// snapshot it named then.
///
/// A pull creates a local tag for every remote tag it has no local tag
/// for. Without this record the next pull would bring a deleted tag right
/// back (BUG-280). With it, a pull leaves the tag deleted as long as the
/// remote's tag is still where it was (or behind it): the deletion is the
/// newer decision. Once somebody moves the tag on the remote to work this
/// repository has not seen, the pull recreates it and says so: new work is
/// never hidden by an old deletion. Like jj's remote-bookmark tracking, the
/// remote tag `<remote>/<tag>` itself always shows what the remote holds.
///
/// An entry is dropped once the tag exists here again (set again, or
/// brought back by `vl undo`) and a pull sees it, or when a pull recreates
/// it.
pub fn deleted_tags(backend: &dyn StorageBackend) -> Result<std::collections::BTreeMap<String, ObjectId>> {
    match backend.read_opt(&deleted_tags_path())? {
        Some(raw) => serde_json::from_slice(&raw).map_err(|e| {
            VeilError::repo(format!(
                "{} is damaged ({e}); delete it (tags deleted here may then come back with the next pull)",
                deleted_tags_path()
            ))
        }),
        None => Ok(Default::default()),
    }
}

fn save_deleted_tags(backend: &dyn StorageBackend, map: &std::collections::BTreeMap<String, ObjectId>) -> Result<()> {
    if map.is_empty() {
        if backend.exists(&deleted_tags_path())? {
            backend.remove_file(&deleted_tags_path())?;
        }
        return Ok(());
    }
    backend.write(&deleted_tags_path(), &serde_json::to_vec_pretty(map)?)
}

/// Record that tag `name`, naming `target`, was deleted here (see
/// [`deleted_tags`]). Called under the repository lock.
pub(crate) fn record_tag_deletion(backend: &dyn StorageBackend, name: &str, target: ObjectId) -> Result<()> {
    let mut map = deleted_tags(backend)?;
    map.insert(name.to_string(), target);
    save_deleted_tags(backend, &map)
}

/// What a pull does about a remote tag `name` (at `remote_target`) that
/// has no local tag: `true` to leave it deleted here (see
/// [`deleted_tags`]). Drops the record when the remote moved past it.
fn stays_deleted(
    repo: &Repo,
    deleted: &mut std::collections::BTreeMap<String, ObjectId>,
    name: &str,
    remote_target: &ObjectId,
) -> Result<bool> {
    let Some(was) = deleted.get(name) else { return Ok(false) };
    if repo.is_ancestor(remote_target, was)? {
        return Ok(true);
    }
    deleted.remove(name);
    Ok(false)
}

/// Apply the pull rules of [`deleted_tags`] for `remote_tags` (name →
/// target, as the remote has them) in transaction `tx`: returns the names
/// that stay deleted, and those deleted here that the pull recreates
/// because the remote moved past the deletion; saves the updated record.
/// Also drops entries for tags that exist here again.
pub(crate) fn tags_staying_deleted(
    tx: &crate::transaction::Transaction<'_>,
    remote_tags: &[(String, ObjectId)],
) -> Result<(HashSet<String>, Vec<String>)> {
    let backend = tx.repo().backend().clone();
    let mut deleted = deleted_tags(&*backend)?;
    let mut stay = HashSet::new();
    let mut recreated = Vec::new();
    if deleted.is_empty() {
        return Ok((stay, recreated));
    }
    let before = deleted.clone();
    deleted.retain(|name, _| !tx.view.tags.contains_key(name));
    for (name, target) in remote_tags {
        if tx.view.tags.contains_key(name) || !deleted.contains_key(name) {
            continue;
        }
        if stays_deleted(tx.repo(), &mut deleted, name, target)? {
            stay.insert(name.clone());
        } else {
            recreated.push(name.clone());
        }
    }
    if deleted != before {
        save_deleted_tags(&*backend, &deleted)?;
    }
    Ok((stay, recreated))
}

/// Push tags (all by default) and their history to the repository on
/// `remote_backend` (created if the directory is new or empty), under its
/// lock. `public`: the receiver is public (no cloaked content or tags, no
/// unreleased embargoes, no key rings). A tag the receiver holds elsewhere
/// is rejected unless it is a fast-forward or `force`; a release tag
/// (annotated) is never moved there.
pub fn push(
    local: &mut Repo,
    remote_backend: Arc<dyn StorageBackend>,
    public: bool,
    only_tags: &[String],
    force: bool,
) -> Result<SyncReport> {
    let mut remote = open_or_init_remote(&remote_backend)?;
    let mut tx = remote.transaction(format!("push from {}", local.repo_id()))?;
    // Releases staged by `vl embargo release` become permanent before the
    // withheld history is decided: an undo cannot take one back between
    // that decision and the upload (BUG-807).
    let releases_published = local.keys().publish_staged_releases()?;
    let mut report = SyncReport::default();
    let (sendable, withheld) = sendable_tags(local, only_tags, &mut report)?;
    let selected = accepted_tags(local, sendable, &tx.view.tags, force, &mut report)?;
    let tips: Vec<ObjectId> = selected.iter().map(|(_, t)| t.target).collect();
    let ids = push_closure(local.store(), &tips, &withheld)?
        .map_err(|why| VeilError::repo(format!("push: {why}")))?;
    {
        let dst = tx.repo().store().clone();
        let mut xfer = Transfer {
            src: local.store(),
            dst: &dst,
            public,
            seen: HashSet::new(),
            heights: HashMap::new(),
            report,
        };
        for id in ids {
            xfer.copy(id)?;
        }
        report = xfer.report;
    }
    report.releases_published = releases_published;
    let annotations: Vec<ObjectId> = selected.iter().filter_map(|(_, t)| t.annotation).collect();
    copy_annotations(local.store(), tx.repo().store(), &annotations)?;
    sync_meta(local.keys(), tx.repo().keys(), public, false, &mut report.warnings)?;
    for (name, tag) in selected {
        // A push never strips the annotation the remote's tag has for the
        // same target (a clone that has not received it yet).
        let existing = tx.view.tags.get(&name).cloned();
        let annotation = tag
            .annotation
            .or(existing.as_ref().filter(|e| e.target == tag.target).and_then(|e| e.annotation));
        if existing.as_ref().is_some_and(|e| e.target == tag.target && e.annotation == annotation) {
            continue;
        }
        for p in &local.snapshot(&tag.target)?.parents {
            tx.view.heads.remove(p);
        }
        tx.view.heads.insert(tag.target);
        tx.view.tags.insert(name.clone(), Tag { target: tag.target, annotation });
        report.tags_updated.push((name, tag.target));
    }
    tx.commit()?;
    Ok(report)
}

/// The tags a push of `only_tags` (all if empty) may send, before the
/// remote is consulted, and the embargo-withheld history. Tags that would
/// publish withheld history are recorded in `report.tags_skipped` with the reason.
#[allow(clippy::type_complexity)]
fn sendable_tags(
    local: &Repo,
    only_tags: &[String],
    report: &mut SyncReport,
) -> Result<(Vec<(String, Tag)>, HashMap<ObjectId, String>)> {
    let mut selected: Vec<(String, Tag)> = Vec::new();
    for (name, tag) in &local.view().tags {
        if !only_tags.is_empty() && !only_tags.contains(name) {
            continue;
        }
        if let Some(why) = annotation_problem(local.store(), name, tag)? {
            report.tags_skipped.push((name.clone(), why));
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
    let withheld = embargo_withheld(local)?;
    let mut sendable = Vec::new();
    for (name, tag) in selected {
        match push_closure(local.store(), &[tag.target], &withheld)? {
            Ok(_) => sendable.push((name, tag)),
            Err(why) => report.tags_skipped.push((name, why)),
        }
    }
    Ok((sendable, withheld))
}

/// Why the tag `name` may not be pushed because of its annotation (format
/// 5), if it may not: the atag is missing or not an atag, names another tag
/// or target (a transplanted or re-targeted annotation, which would
/// publish a release tag the signer never made).
fn annotation_problem(store: &ObjectStore, name: &str, tag: &Tag) -> Result<Option<String>> {
    let Some(a) = tag.annotation else { return Ok(None) };
    let atag = match store.get(&a) {
        Ok(Object::Atag(atag)) => atag,
        Ok(other) => return Ok(Some(format!("its annotation {} is a {}, not an annotated tag", a.short(), other.kind_name()))),
        Err(VeilError::Missing(_)) => return Ok(Some(format!("its annotation {} is missing", a.short()))),
        Err(VeilError::Corrupt(..) | VeilError::Json(_)) => {
            return Ok(Some(format!("its annotation {} is damaged", a.short())))
        }
        Err(e) => return Err(e),
    };
    if atag.name != name || atag.target != tag.target {
        return Ok(Some(format!(
            "its annotation {} belongs to another tag or target ({})",
            a.short(),
            atag.verify(name, &tag.target).describe()
        )));
    }
    Ok(None)
}

/// Copy the annotated tag objects `ids` (format 5) from `src` to `dst`
/// with `put_raw`, so a destination below format 5 refuses them with the
/// upgrade hint.
fn copy_annotations(src: &ObjectStore, dst: &ObjectStore, ids: &[ObjectId]) -> Result<usize> {
    let mut copied = 0;
    for id in ids {
        if dst.has(id) {
            continue;
        }
        let raw = src.get_raw(id)?;
        match Object::decode(&raw)? {
            Object::Atag(_) => {}
            other => {
                return Err(VeilError::Corrupt(
                    id.hex(),
                    format!("expected an annotated tag, found a {}", other.kind_name()),
                ))
            }
        }
        if dst.put_raw(id, &raw)? {
            copied += 1;
        }
    }
    Ok(copied)
}

/// Fetch the annotation `id` of the remote tag `name → target` from
/// `remote` into `local`, checking it on the way: hash, canonical atag,
/// and the same name and target as the tag (a hostile remote cannot
/// transplant a signed annotation onto another tag). `Ok(None)` with a
/// warning in `warnings` when the annotation is not usable; the tag is
/// then received without it.
fn fetch_annotation(
    local: &ObjectStore,
    remote: &ObjectStore,
    name: &str,
    tag: &Tag,
    warnings: &mut Vec<String>,
) -> Result<Option<ObjectId>> {
    let Some(id) = tag.annotation else { return Ok(None) };
    let raw = match local.get_raw(&id) {
        Ok(raw) => raw,
        Err(VeilError::Missing(_)) => match remote.get_raw(&id) {
            Ok(raw) => raw,
            Err(VeilError::Missing(_)) => {
                warnings.push(format!("remote tag '{name}': its annotation {} is missing; received without it", id.short()));
                return Ok(None);
            }
            Err(e) => return Err(e),
        },
        Err(e) => return Err(e),
    };
    if ObjectId::hash(&raw) != id {
        warnings.push(format!("remote tag '{name}': its annotation {} is damaged; received without it", id.short()));
        return Ok(None);
    }
    let atag = match Object::decode(&raw) {
        Ok(Object::Atag(a)) => a,
        Ok(_) | Err(VeilError::Corrupt(..)) | Err(VeilError::Json(_)) => {
            warnings.push(format!("remote tag '{name}': its annotation {} is not a valid annotated tag; received without it", id.short()));
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    if atag.name != name || atag.target != tag.target {
        warnings.push(format!(
            "remote tag '{name}': its annotation {} belongs to another tag or target; received without it",
            id.short()
        ));
        return Ok(None);
    }
    local.put_raw(&id, &raw)?;
    Ok(Some(id))
}

/// Of `sendable`, the tags the remote (holding `remote_tags`) takes; the
/// others are rejected (non-fast-forward without `force`) in `report`.
/// Decided before anything is sent: the history of a rejected tag is not
/// copied (BUG-288).
fn accepted_tags(
    local: &Repo,
    sendable: Vec<(String, Tag)>,
    remote_tags: &std::collections::BTreeMap<String, Tag>,
    force: bool,
    report: &mut SyncReport,
) -> Result<Vec<(String, Tag)>> {
    let mut accepted = Vec::new();
    for (name, tag) in sendable {
        if let Some(existing) = remote_tags.get(&name) {
            // A release tag (annotated, on either side) is never moved on
            // the remote (BUG-710), even forward.
            let release = existing.annotation.is_some() || tag.annotation.is_some();
            if existing.target != tag.target && release {
                report.tags_rejected.push(name.clone());
                report.tags_skipped.push((
                    name,
                    format!("release tag: the remote's is at {}; a release is never replaced", existing.target.short()),
                ));
                continue;
            }
            if existing.target != tag.target && !force && !local.is_ancestor(&existing.target, &tag.target)? {
                report.tags_rejected.push(name.clone());
                report
                    .tags_skipped
                    .push((name, "remote has diverged (non-fast-forward; use --force)".into()));
                continue;
            }
        }
        accepted.push((name, tag));
    }
    Ok(accepted)
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

/// Open the repository a push goes to, creating an empty bare one first if
/// there is none.
///
/// Initialisation happens under the remote's lock, re-checked once the
/// lock is held: when several first pushes reach an empty remote at once,
/// one initialises it and the others find a repository and push to it
/// normally (BUG-120). Without the lock the losers failed with
/// "already exists", or, worse, a late loser could reset `op_head` to its
/// own empty view after the winner had already pushed. An error while
/// checking (a flaky connection) is an error, never a reason to initialise
/// over what may be an existing repository.
fn open_or_init_remote(backend: &Arc<dyn StorageBackend>) -> Result<Repo> {
    let config = crate::repo::config_path();
    if backend.exists(&config)? {
        return Repo::open_remote(backend.clone());
    }
    refuse_foreign_directory(&**backend)?;
    let lock = crate::lock::RepoLock::acquire(backend.clone())?;
    let repo = if backend.exists(&config)? {
        Repo::open_remote(backend.clone())
    } else {
        Repo::init_bare(backend.clone())
    };
    drop(lock);
    match repo {
        // Initialised meanwhile by a client that did not take the lock
        // (an older version): push to it like to any other repository.
        Err(VeilError::AlreadyExists(_)) => Repo::open_remote(backend.clone()),
        r => r,
    }
}

/// A push creates a repository only where there is nothing yet: a missing
/// or empty directory (or one holding only a `.veil/` an interrupted first
/// push left). Anything else is somebody's files, most likely a typo in the
/// remote's URL (`../proj` for `../proj.veil`), and turning it into a bare
/// repository would break every `vl` command run there (BUG-283).
pub(crate) fn refuse_foreign_directory(backend: &dyn StorageBackend) -> Result<()> {
    let listing = match backend.list_dir_full(&VPath::root()) {
        Ok(listing) => listing,
        Err(e) if e.is_not_found() => return Ok(()),
        Err(e) => return Err(e),
    };
    let foreign: Vec<&str> = listing
        .entries
        .iter()
        .map(|e| e.name.as_str())
        .chain(listing.special.iter().map(String::as_str))
        .chain(listing.unrepresentable.iter().map(String::as_str))
        .filter(|n| *n != crate::repo::VEIL_DIR)
        .collect();
    if foreign.is_empty() {
        return Ok(());
    }
    Err(VeilError::repo(format!(
        "the remote is a directory that is not empty and not a Veil repository (it holds {}{}); \
         a push only creates a repository in a new or empty directory. Check the remote's URL (`vl remote list`)",
        foreign.iter().take(3).map(|n| format!("'{n}'")).collect::<Vec<_>>().join(", "),
        if foreign.len() > 3 { ", …" } else { "" }
    )))
}

/// Fetch every tag from the repository on `remote_backend`, record them as
/// `<remote_name>/<tag>`, and create or fast-forward local tags. Under the
/// local lock; every object of the sender's tagged history is walked and
/// checked.
pub fn pull(local: &mut Repo, remote_name: &str, remote_backend: Arc<dyn StorageBackend>) -> Result<SyncReport> {
    if !is_repo(&*remote_backend) {
        return Err(VeilError::NotFound(format!("Veil repository at remote '{remote_name}'")));
    }
    let remote = Repo::open_remote(remote_backend.clone())?;
    let tags: Vec<(String, Tag)> = remote.view().tags.clone().into_iter().collect();
    let mut tx = local.transaction(format!("pull from {remote_name}"))?;
    tx.repository_wide();
    // Only snapshot targets are fetched; tags on anything else (missing, a
    // tree, a blob) are skipped with a warning by `apply_remote_tags`.
    let mut tips = Vec::new();
    for (_, t) in &tags {
        match remote.store().get(&t.target) {
            Ok(Object::Snapshot(_)) => tips.push(t.target),
            Ok(_) | Err(VeilError::Missing(_)) => {}
            Err(e) => return Err(e),
        }
    }
    let mut xfer = Transfer {
        src: remote.store(),
        dst: tx.repo().store(),
        public: false,
        seen: HashSet::new(),
        heights: HashMap::new(),
        report: SyncReport::default(),
    };
    for id in ancestors_in(remote.store(), &tips)? {
        xfer.copy(id)?;
    }
    let mut report = xfer.report;
    sync_meta(remote.keys(), tx.repo().keys(), false, true, &mut report.warnings)?;
    tx.repo().keys().invalidate();
    apply_remote_tags(&mut tx, remote_name, tags, Some(remote.store()), &mut report)?;
    tx.commit()?;
    Ok(report)
}

/// Objects received from the Veil server, written into a local store as a
/// pull writes them: loose while few, then streamed into packs, each
/// checked against what the store's repository format may hold. They are
/// readable once [`Incoming::finish`] returns.
pub struct Incoming<'a> {
    store: &'a Arc<ObjectStore>,
    sink: PackSink<'a>,
    report: SyncReport,
}

impl<'a> Incoming<'a> {
    pub fn new(store: &'a Arc<ObjectStore>) -> Incoming<'a> {
        Incoming {
            store,
            // A pack from 16 objects: one fsync instead of one, and a
            // rename and a directory, per object (a clone of one directory
            // brings a hundred).
            sink: PackSink::new(store, 16),
            report: SyncReport::default(),
        }
    }

    /// Write object `id` (already checked against its id) found at `path`.
    pub fn put(&mut self, id: ObjectId, raw: Vec<u8>, path: &str) -> Result<bool> {
        self.sink.put(id, raw, path)
    }

    /// Publish what was written; returns the packs written.
    pub fn finish(mut self) -> Result<usize> {
        self.sink.finish(&mut self.report)?;
        self.store.reload_packs()?;
        Ok(self.report.packs_written)
    }
}

/// Record a remote's tags after their objects are in the local store
/// (the second half of [`pull`], and of the server client's pull): set `<remote>/<tag>`, prune remote
/// tags the remote no longer has, and create or fast-forward local tags,
/// with every check a pull makes (names, targets, shadowing, release
/// tags, divergence). `remote_store`: where annotated tag objects are
/// read from (`None`: the remote has none, as the Veil server in S1).
pub fn apply_remote_tags(
    tx: &mut crate::transaction::Transaction<'_>,
    remote_name: &str,
    tags: Vec<(String, Tag)>,
    remote_store: Option<&ObjectStore>,
    report: &mut SyncReport,
) -> Result<()> {
    // Change and snapshot ids a new local tag must not shadow: those of
    // local history and of everything this pull brings in (a teammate's
    // change, tagged after its id by someone else, BUG-105).
    let mut revisions = crate::revset::RevisionNames::default();
    let mut incoming = Vec::new();
    for (_, tag) in &tags {
        if unusable_target(tx.repo().store(), &tag.target)?.is_none() {
            incoming.push(tag.target);
        }
    }
    // Remote tags of tags the remote no longer has are pruned (as Git's
    // `fetch --prune` and jj do). A local tag of that name is kept: a
    // teammate's deletion never deletes your tag (BUG-280).
    let prefix = format!("{remote_name}/");
    let on_remote: HashSet<&str> = tags.iter().map(|(n, _)| n.as_str()).collect();
    let gone: Vec<String> = tx
        .view
        .remote_tags
        .keys()
        .filter(|k| k.strip_prefix(&prefix).is_some_and(|t| !on_remote.contains(t)))
        .cloned()
        .collect();
    for key in gone {
        tx.view.remote_tags.remove(&key);
        let name = &key[prefix.len()..];
        if tx.view.tags.contains_key(name) {
            report.warnings.push(format!(
                "tag '{name}' was deleted on {remote_name}; your tag '{name}' is kept. Delete it with \
                 `vl tag delete {name}`, or the next `vl push {remote_name}` publishes it again"
            ));
        }
        report.remote_tags_removed.push(key);
    }
    let usable: Vec<(String, ObjectId)> = tags
        .iter()
        .filter(|(_, t)| incoming.contains(&t.target))
        .map(|(n, t)| (n.clone(), t.target))
        .collect();
    let (stay_deleted, recreated) = tags_staying_deleted(tx, &usable)?;
    for name in recreated {
        report.warnings.push(format!(
            "tag '{name}', deleted here, has moved on {remote_name} to work you had not seen: it is back. \
             Delete it again, or delete it there too with `vl push {remote_name} --delete {name}`"
        ));
    }
    for (name, mut tag) in tags {
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
        // Its annotation (format 5), checked against the tag.
        tag.annotation = match remote_store {
            Some(remote) => fetch_annotation(tx.repo().store(), remote, &name, &tag, &mut report.warnings)?,
            None => None,
        };
        tx.view.remote_tags.insert(format!("{remote_name}/{name}"), tag.target);
        match tx.view.tags.get(&name).cloned() {
            None if stay_deleted.contains(&name) => report.tags_kept_deleted.push(name),
            None => {
                let refs = || {
                    let mut r = tx.view.refs();
                    r.extend(incoming.iter().copied());
                    r
                };
                if revisions.shadows(tx.repo(), refs, &name)? {
                    report.warnings.push(format!(
                        "no local tag created for remote tag '{name}': the name is also a change or snapshot id of this repository; use {remote_name}/{name}"
                    ));
                    continue;
                }
                tx.view.tags.insert(name.clone(), tag.clone());
                report.tags_updated.push((name, tag.target));
            }
            Some(existing) if existing.target == tag.target => {
                // The remote's annotation for the same target, if this tag
                // has none yet.
                if existing.annotation.is_none() && tag.annotation.is_some() {
                    tx.view.tags.insert(
                        name.clone(),
                        Tag {
                            annotation: tag.annotation,
                            ..existing
                        },
                    );
                }
            }
            // A release tag (annotated, format 5) is immutable: a remote
            // that holds it elsewhere (a teammate's `--force`, or a hostile
            // remote) never moves the local one, nor swaps its annotation.
            // The remote's target is recorded as `<remote>/<name>` above.
            Some(existing) if existing.annotation.is_some() => {
                report.release_tags_kept.push((name, existing.target, tag.target));
            }
            Some(existing) => {
                if tx.repo().is_ancestor(&existing.target, &tag.target)? {
                    tx.view.tags.insert(
                        name.clone(),
                        Tag { target: tag.target, annotation: tag.annotation },
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
    Ok(())
}
