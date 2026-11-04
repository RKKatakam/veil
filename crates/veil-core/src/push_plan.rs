//! `vl push --dry-run`: exactly what a push would send, computed without
//! writing anything to the remote.
//!
//! The plan is the push itself, stopped short of writing: the same tag
//! selection (`remote::sendable_tags`, `remote::accepted_tags`), the
//! same embargo-withheld history and push closure, and the same incremental
//! transfer (`remote::push_incremental`) with its visibility filter. Only
//! the sink differs: objects are recorded and packed into a backend that
//! drops them, so the counts, the ids and the pack size are those of the
//! real push (a property test compares them).
//!
//! The remote is only read: it is opened through [`ReadOnly`], which turns
//! every write into an error, and no lock is taken (the real push reads the
//! same view under its lock; a push by someone else in between changes the
//! plan the way it would change the push).
//!
//! For a **public** remote the plan also says which files would become
//! public there for the first time, and which are withheld, and why
//! ([`PublicFiles`]). Both are computed the way a reader of that remote
//! sees the trees: cloaked entries redacted (or their last public version,
//! for a file edited on a cloaked line), unreleased embargo wrappers
//! replaced by their pre-merge tree. Paths under an embargo only appear for
//! a reader holding its key; others get one line per snapshot.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::Arc,
};

use crate::{
    embargo::wrapper_parts,
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Tree, Visibility},
    remote::{self, PlanRecord, PlannedObject, SyncReport},
    repo::Repo,
    store::ObjectStore,
    tree::{diff_trees, MAX_TREE_DEPTH},
    vfs::{DirEntry, DirListing, MemoryBackend, Metadata, NameFolding, StatClock, StorageBackend},
    vpath::VPath,
};

/// What `vl push --dry-run` reports for one remote.
#[derive(Clone, Debug, Default)]
pub struct PushPlan {
    /// The remote is public (no cloaked content, tags or key rings).
    pub public: bool,
    /// No repository there yet: the push would create one.
    pub creates_remote: bool,
    pub tags: Vec<PlannedTag>,
    /// Snapshots that would be sent, in transfer order.
    pub snapshots: Vec<ObjectId>,
    /// Every object that would be sent (snapshots included), in order.
    pub objects: Vec<PlannedObject>,
    /// Bytes of the packs the push would write (compressed, with deltas):
    /// what `vl push` reports as sent.
    pub pack_bytes: u64,
    /// Objects the visibility filter would hold back (cloaked or embargoed
    /// content on a public remote).
    pub redacted: usize,
    /// History that stays here: snapshots reachable from the pushed tags
    /// only through an unreleased embargo, with that embargo.
    pub withheld_snapshots: Vec<(ObjectId, String)>,
    /// Embargo releases staged here that the push would publish.
    pub releases: Vec<String>,
    /// Public remotes only.
    pub files: Option<PublicFiles>,
    pub warnings: Vec<String>,
}

impl PushPlan {
    /// Sum of the objects' canonical encodings (before packing).
    pub fn object_bytes(&self) -> u64 {
        self.objects.iter().map(|o| o.bytes).sum()
    }

    /// Nothing to send and no tag to move.
    pub fn is_noop(&self) -> bool {
        self.objects.is_empty()
            && self
                .tags
                .iter()
                .all(|t| !matches!(t.action, TagAction::Create | TagAction::Update))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagAction {
    /// The remote has no tag of that name.
    Create,
    /// Fast-forward (or `--force`).
    Update,
    /// The remote's tag is at the same snapshot already.
    Unchanged,
    /// The remote's tag diverged (non-fast-forward without `--force`).
    Rejected,
    /// Held back by design: a cloaked tag on a public remote, or a tag that
    /// would publish history withheld by an unreleased embargo.
    Skipped,
}

impl TagAction {
    pub fn word(&self) -> &'static str {
        match self {
            TagAction::Create => "create",
            TagAction::Update => "update",
            TagAction::Unchanged => "unchanged",
            TagAction::Rejected => "rejected",
            TagAction::Skipped => "skipped",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PlannedTag {
    pub name: String,
    pub action: TagAction,
    /// The local target.
    pub target: ObjectId,
    /// What the remote's tag points at now, if it has one.
    pub remote: Option<ObjectId>,
    /// Why a tag is rejected or skipped.
    pub reason: Option<String>,
    /// Scope of a cloaked tag.
    pub cloak: Option<String>,
}

/// Files of the pushed history as a public remote's readers would see them.
#[derive(Clone, Debug, Default)]
pub struct PublicFiles {
    /// Content that would become public there, by path.
    pub published: Vec<PublishedFile>,
    /// Files whose (new) content stays withheld, by path.
    pub withheld: Vec<WithheldFile>,
    /// Snapshots whose tree is under an unreleased embargo this reader
    /// holds no key for: the remote sees their pre-merge tree, and which
    /// files the embargo changes cannot be listed here.
    pub embargoed_trees: Vec<(ObjectId, String)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Exposure {
    /// The path was never public on the remote.
    New,
    /// The path was on the remote, but withheld (cloaked or embargoed);
    /// its content becomes public now.
    Exposed,
    /// Already public there; new content.
    Modified,
}

impl Exposure {
    pub fn word(&self) -> &'static str {
        match self {
            Exposure::New => "new",
            Exposure::Exposed => "exposed",
            Exposure::Modified => "modified",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PublishedFile {
    pub path: VPath,
    pub exposure: Exposure,
    /// Size of the version published (unknown for the last public version
    /// of a file edited on a cloaked line).
    pub size: Option<u64>,
    /// Published from a released embargo.
    pub released_embargo: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WithheldReason {
    /// Cloaked for a scope: public remotes never receive it.
    Cloaked { scope: String },
    /// Edited on a cloaked line: the remote keeps showing its last public
    /// version.
    CloakedEdit { scope: String },
    /// Under an unreleased embargo: the remote shows the pre-merge version.
    Embargoed { embargo: String },
}

impl WithheldReason {
    pub fn text(&self) -> String {
        match self {
            WithheldReason::Cloaked { scope } => format!("cloaked:{scope}; public remotes never receive it"),
            WithheldReason::CloakedEdit { scope } => {
                format!("cloaked:{scope}; edited on a cloaked line, the remote keeps its last public version")
            }
            WithheldReason::Embargoed { embargo } => {
                format!("embargo {embargo}; not released, the remote shows the pre-merge version")
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct WithheldFile {
    pub path: VPath,
    pub reason: WithheldReason,
}

// ---- the read-only remote ----------------------------------------------------------

/// A backend that reads through to `0` and refuses every write: what a dry
/// run opens the remote with, so nothing it does can change the remote.
#[derive(Debug)]
pub struct ReadOnly(pub Arc<dyn StorageBackend>);

fn refused(path: &VPath) -> VeilError {
    VeilError::repo(format!("dry run: refusing to write '{path}' on the remote"))
}

impl StorageBackend for ReadOnly {
    fn kind(&self) -> &'static str {
        self.0.kind()
    }
    fn is_network(&self) -> bool {
        self.0.is_network()
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        self.0.read(path)
    }
    fn write(&self, path: &VPath, _: &[u8]) -> Result<()> {
        Err(refused(path))
    }
    fn write_unsynced(&self, path: &VPath, _: &[u8]) -> Result<()> {
        Err(refused(path))
    }
    fn sync_barrier(&self) -> Result<()> {
        Ok(())
    }
    fn create_new(&self, path: &VPath, _: &[u8]) -> Result<bool> {
        Err(refused(path))
    }
    fn remove_file(&self, path: &VPath) -> Result<()> {
        Err(refused(path))
    }
    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        Err(refused(path))
    }
    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        Err(refused(path))
    }
    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        self.0.list_dir(path)
    }
    fn list_dir_full(&self, path: &VPath) -> Result<DirListing> {
        self.0.list_dir_full(path)
    }
    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        self.0.metadata(path)
    }
    fn set_executable(&self, path: &VPath, _: bool) -> Result<()> {
        Err(refused(path))
    }
    fn stat_clock(&self) -> Option<StatClock> {
        self.0.stat_clock()
    }
    fn name_folding(&self) -> NameFolding {
        self.0.name_folding()
    }
    fn exists(&self, path: &VPath) -> Result<bool> {
        self.0.exists(path)
    }
    fn special_at(&self, path: &VPath) -> Result<Option<&'static str>> {
        self.0.special_at(path)
    }
    fn read_range(&self, path: &VPath, offset: u64, len: usize) -> Result<Vec<u8>> {
        self.0.read_range(path, offset, len)
    }
}

// ---- the plan ------------------------------------------------------------------------

/// What `remote::push` of `only_tags` (all if empty) to `remote_backend`
/// would do, without doing it. Fails where the push would fail before
/// sending anything (a missing tag, a foreign directory, a tag that builds
/// on withheld history).
pub fn plan_push(
    local: &Repo,
    remote_backend: Arc<dyn StorageBackend>,
    public: bool,
    only_tags: &[String],
    force: bool,
) -> Result<PushPlan> {
    let ro: Arc<dyn StorageBackend> = Arc::new(ReadOnly(remote_backend));
    let creates_remote = !ro.exists(&crate::repo::config_path())?;
    let remote = if creates_remote {
        remote::refuse_foreign_directory(&*ro)?;
        // What the push would create: an empty bare repository.
        Repo::init_bare(Arc::new(MemoryBackend::new()))?
    } else {
        Repo::open(ro, None, "remote")?
    };
    let mut report = SyncReport::default();
    let (sendable, withheld) = remote::sendable_tags(local, public, only_tags, &mut report)?;
    let view = remote.view();
    let accepted = remote::accepted_tags(local, sendable, &view.tags, force, &mut report)?;
    let tips: Vec<ObjectId> = accepted.iter().map(|(_, t)| t.target).collect();
    let ids = remote::push_closure(local.store(), local.keys(), &tips, &withheld)?
        .map_err(|why| VeilError::repo(format!("push: {why}")))?;
    let mut rec = PlanRecord::default();
    let report = remote::push_incremental(local, &view.refs(), remote.store(), ids, public, report, Some(&mut rec))?;

    let mut tags = Vec::new();
    for (name, tag) in &accepted {
        let there = view.tags.get(name).map(|t| t.target);
        let action = match there {
            Some(t) if t == tag.target => TagAction::Unchanged,
            Some(_) => TagAction::Update,
            None => TagAction::Create,
        };
        tags.push(PlannedTag {
            name: name.clone(),
            action,
            target: tag.target,
            remote: there,
            reason: None,
            cloak: if public { None } else { tag.cloak.clone() },
        });
    }
    for (name, why) in &report.tags_skipped {
        let tag = &local.view().tags[name];
        tags.push(PlannedTag {
            name: name.clone(),
            action: if report.tags_rejected.contains(name) { TagAction::Rejected } else { TagAction::Skipped },
            target: tag.target,
            remote: view.tags.get(name).map(|t| t.target),
            reason: Some(why.clone()),
            cloak: tag.cloak.clone(),
        });
    }
    tags.sort_by(|a, b| a.name.cmp(&b.name));

    let mut withheld_snapshots: Vec<(ObjectId, String)> = remote::ancestors_in(local.store(), &tips)?
        .into_iter()
        .filter_map(|id| withheld.get(&id).map(|e| (id, e.clone())))
        .collect();
    withheld_snapshots.sort();

    let objects = rec.objects.into_inner();
    let files = if public {
        let sent: HashSet<ObjectId> = objects.iter().map(|o| o.id).collect();
        // Before the push the remote's readers see the releases its records
        // carry; after it, every release this repository knows.
        let remote_released = |e: &str| remote.keys().embargo_released(e);
        Some(public_files(local, &remote_released, &rec.known_snapshots, &rec.sent_snapshots, &sent)?)
    } else {
        None
    };
    let releases = local.keys().staged_releases()?.into_iter().map(|(id, _)| id).collect();
    Ok(PushPlan {
        public,
        creates_remote,
        tags,
        snapshots: rec.sent_snapshots,
        objects,
        pack_bytes: report.bytes_transferred,
        redacted: report.redacted,
        withheld_snapshots,
        releases,
        files,
        warnings: report.warnings,
    })
}

// ---- files as a public remote's readers see them -------------------------------------

/// A file entry as a public reader sees it.
enum Seen {
    /// Readable content `id` (plaintext, or sealed under a released
    /// embargo), of `size` bytes if known.
    Public { id: ObjectId, size: Option<u64>, released: Option<String> },
    Withheld(WithheldReason),
}

/// Whether a public reader can read embargo `e`'s content.
type Released<'a> = &'a dyn Fn(&str) -> bool;

/// Labels are claims (BUG-482): the push sends an object by what it is
/// (`remote.rs`, a plaintext blob goes to a public remote whatever its
/// label says), so a sealed label is checked against its object
/// ([`crate::builder::verify_sealing`]) before it is believed. A public
/// label is taken as it is: if its object is in fact sealed, the push
/// withholds it and the plan only overstates what is published, never
/// the reverse.
fn seen_as_public(store: &ObjectStore, released: Released, e: &crate::object::TreeEntry) -> (Option<Seen>, Option<Seen>) {
    let vis = match &e.visibility {
        Visibility::Public => Visibility::Public,
        claimed => match crate::builder::verify_sealing(store, e) {
            Ok(crate::builder::Sealing::Relabelled(actual)) => actual,
            _ => claimed.clone(),
        },
    };
    match &vis {
        Visibility::Public => (Some(Seen::Public { id: e.id, size: Some(e.size), released: None }), None),
        Visibility::Embargoed { embargo } if released(embargo) => {
            (Some(Seen::Public { id: e.id, size: Some(e.size), released: Some(embargo.clone()) }), None)
        }
        Visibility::Embargoed { embargo } => match e.fallback {
            // The pre-merge version is what the remote shows.
            Some(fb) => (
                Some(Seen::Public { id: fb, size: None, released: None }),
                Some(Seen::Withheld(WithheldReason::Embargoed { embargo: embargo.clone() })),
            ),
            None => (None, Some(Seen::Withheld(WithheldReason::Embargoed { embargo: embargo.clone() }))),
        },
        Visibility::Cloaked { scope } => match e.fallback {
            Some(fb) => (
                Some(Seen::Public { id: fb, size: None, released: None }),
                Some(Seen::Withheld(WithheldReason::CloakedEdit { scope: scope.clone() })),
            ),
            None => (None, Some(Seen::Withheld(WithheldReason::Cloaked { scope: scope.clone() }))),
        },
    }
}

/// The tree a public reader sees for `id`: unreleased embargo wrappers
/// resolve to their fallback, released ones to the merged tree. `None` if
/// it cannot be read here (a public clone missing withheld content).
fn public_tree(store: &ObjectStore, released: Released, id: &ObjectId) -> Result<Option<(ObjectId, Arc<Tree>)>> {
    let mut id = *id;
    for _ in 0..MAX_TREE_DEPTH {
        let t = match store.tree_object(&id) {
            Ok(t) => t,
            Err(e) if e.is_unreadable() || matches!(e, VeilError::Missing(_) | VeilError::Corrupt(..) | VeilError::Json(_)) => {
                return Ok(None)
            }
            Err(e) => return Err(e),
        };
        match wrapper_parts(&t) {
            None => return Ok(Some((id, t))),
            Some(w) if released(&w.embargo) => match store.tree_object(&w.inner) {
                Ok(_) => id = w.inner,
                Err(e) if e.is_unreadable() || matches!(e, VeilError::Missing(_)) => id = w.fallback,
                Err(e) => return Err(e),
            },
            Some(w) => id = w.fallback,
        }
    }
    Ok(None)
}

/// Every file of the trees of `snaps` as a public reader sees it, each
/// (tree, directory) pair once. `skip` says which pairs not to enter.
fn walk_public(
    local: &Repo,
    released: Released,
    snaps: &[ObjectId],
    seen: &mut HashSet<(ObjectId, VPath)>,
    skip: &HashSet<(ObjectId, VPath)>,
    mut visit: impl FnMut(&VPath, &crate::object::TreeEntry),
) -> Result<()> {
    let store = local.store();
    let mut stack: Vec<(ObjectId, VPath, usize)> = Vec::new();
    for s in snaps {
        match local.snapshot_opt(s)? {
            Some(s) => stack.push((s.tree, VPath::root(), 0)),
            None => continue,
        }
        while let Some((id, dir, depth)) = stack.pop() {
            if depth > MAX_TREE_DEPTH {
                continue;
            }
            // Keyed by the tree the reader sees: a wrapper resolves
            // differently before and after its release.
            let Some((id, t)) = public_tree(store, released, &id)? else { continue };
            if skip.contains(&(id, dir.clone())) || !seen.insert((id, dir.clone())) {
                continue;
            }
            for e in &t.entries {
                let p = dir.join(&e.name);
                match e.kind {
                    EntryKind::Dir => stack.push((e.id, p, depth + 1)),
                    // A symlink target or gitlink pointer is sent or
                    // withheld like file content.
                    EntryKind::File | EntryKind::Symlink | EntryKind::Gitlink => visit(&p, e),
                    // Each version as a file: the plan shows what of it is
                    // sent and what is withheld.
                    EntryKind::Conflict => {
                        if let Ok(c) = store.conflict(&e.id) {
                            for t in c.interleaved().flatten() {
                                visit(&p, &t.entry(&e.name));
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn public_files(
    local: &Repo,
    remote_released: Released,
    known: &HashSet<ObjectId>,
    sent_snaps: &[ObjectId],
    sent: &HashSet<ObjectId>,
) -> Result<PublicFiles> {
    // What the remote shows already, over all of its history.
    let mut base_public: HashSet<VPath> = HashSet::new();
    let mut base_withheld: HashSet<VPath> = HashSet::new();
    let mut base_withheld_ids: HashSet<(VPath, ObjectId)> = HashSet::new();
    let mut base_pairs = HashSet::new();
    let mut known_list: Vec<ObjectId> = known.iter().copied().collect();
    known_list.sort();
    walk_public(local, remote_released, &known_list, &mut base_pairs, &HashSet::new(), |p, e| {
        let (shown, held) = seen_as_public(local.store(), remote_released, e);
        if shown.is_some() {
            base_public.insert(p.clone());
        }
        if held.is_some() {
            base_withheld.insert(p.clone());
            base_withheld_ids.insert((p.clone(), e.id));
        }
    })?;

    // What the pushed snapshots add. A (tree, directory) pair the remote
    // already shows holds nothing new.
    let mut published: BTreeMap<VPath, (Option<u64>, Option<String>)> = BTreeMap::new();
    let mut withheld: BTreeMap<VPath, WithheldReason> = BTreeMap::new();
    let mut pairs = HashSet::new();
    // Pushed snapshots, and those already there whose tree is under an
    // embargo released since (the push sends what it held back then).
    let local_released = |e: &str| local.keys().embargo_released(e);
    let mut walk: Vec<ObjectId> = sent_snaps.to_vec();
    for s in &known_list {
        let Some(snap) = local.snapshot_opt(s)? else { continue };
        if let Ok(t) = local.store().tree_object(&snap.tree) {
            if wrapper_parts(&t).is_some_and(|w| local_released(&w.embargo) && !remote_released(&w.embargo)) {
                walk.push(*s);
            }
        }
    }
    walk_public(local, &local_released, &walk, &mut pairs, &base_pairs, |p, e| {
        let (shown, held) = seen_as_public(local.store(), &local_released, e);
        if let Some(Seen::Public { id, size, released }) = shown {
            // Walked newest first: the first version met is the latest.
            if sent.contains(&id) || !base_public.contains(p) {
                published.entry(p.clone()).or_insert((size, released));
            }
        }
        if let Some(Seen::Withheld(why)) = held {
            if !base_withheld_ids.contains(&(p.clone(), e.id)) {
                withheld.entry(p.clone()).or_insert(why);
            }
        }
    })?;

    let cloaked_in_push: HashSet<VPath> = withheld.keys().cloned().collect();

    // Embargoed trees: the files they change, if this reader holds the key.
    let mut embargoed_trees = Vec::new();
    let store = local.store();
    let mut listed: BTreeSet<VPath> = BTreeSet::new();
    for s in sent_snaps {
        let Some(snap) = local.snapshot_opt(s)? else { continue };
        let w = match store.tree_object(&snap.tree) {
            Ok(t) => wrapper_parts(&t),
            Err(_) => None,
        };
        let Some(w) = w.filter(|w| !store.keys.embargo_released(&w.embargo)) else { continue };
        if !store.keys.has(&w.key_label()) {
            embargoed_trees.push((*s, w.embargo.clone()));
            continue;
        }
        for c in diff_trees(store, Some(&w.fallback), Some(&snap.tree))? {
            if listed.insert(c.path.clone()) {
                withheld
                    .entry(c.path)
                    .or_insert_with(|| WithheldReason::Embargoed { embargo: w.embargo.clone() });
            }
        }
    }
    embargoed_trees.sort();
    embargoed_trees.dedup_by(|a, b| a.1 == b.1);

    // Exposed: withheld on the remote before, or in an older version this
    // push sends (cloaked, then exposed). A file whose embargoed edit is
    // withheld while its pre-merge version goes out is simply new there.
    let mut ever_withheld: HashSet<&VPath> = base_withheld.iter().collect();
    ever_withheld.extend(&cloaked_in_push);
    let published = published
        .into_iter()
        .map(|(path, (size, released))| {
            let exposure = if base_public.contains(&path) {
                Exposure::Modified
            } else if ever_withheld.contains(&path) {
                Exposure::Exposed
            } else {
                Exposure::New
            };
            PublishedFile { path, exposure, size, released_embargo: released }
        })
        .collect();
    let withheld = withheld.into_iter().map(|(path, reason)| WithheldFile { path, reason }).collect();
    Ok(PublicFiles { published, withheld, embargoed_trees })
}

