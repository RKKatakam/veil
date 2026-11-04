//! Repository integrity checker (`vl fsck`).
//!
//! The checker never writes and does not need [`Repo::open`] to succeed, so
//! it can diagnose a repository whose operation head is damaged. It checks:
//!
//! 1. **Objects.** Every object, reachable or not, is re-hashed and decoded.
//!    Sealed objects whose scope key we hold are opened and their content
//!    decoded too.
//! 2. **Reachability.** From the current view and from the view of every
//!    retained operation: snapshot → parents, tree → entries and embargo
//!    fallbacks. A missing object is classified by the visibility of the
//!    entry that references it. Content of cloaked or embargoed entries is
//!    legitimately absent from clones of public remotes (and from team
//!    members who were not sent it): **redacted (expected)**. A missing
//!    public file, tree or snapshot is **corrupt**.
//! 3. **Shared metadata.** Key rings and embargo records parse and are
//!    filed under their own name.
//! 4. **Operation log.** Every operation matches its id and parses, every
//!    parent exists, and the head points at an existing operation.
//!
//! State an interrupted command leaves behind (an operation that never became
//! the head, unreachable objects, temp files, a leftover lock) is reported
//! as a note: it is harmless and the repository works normally. That
//! includes unreachable objects torn by a power loss while a lock was held
//! (see [`recover_interrupted_writes`]), as long as that lock is still there.
//!
//! [`recover_interrupted_writes`] is the one function here that writes: the
//! lock runs it when it takes over from a crashed holder.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    fmt,
    sync::Arc,
};

use crate::{
    error::Result,
    id::ObjectId,
    identity::{parse_public_key, Identity},
    keychain::{EmbargoRecord, KeyRing, Keychain},
    lock::{RepoLock, STEAL_PATH},
    now_millis,
    object::{EntryKind, Object, Text, TreeEntry, Visibility},
    oplog::Operation,
    repo::{Repo, RepoConfig},
    store::ObjectStore,
    tree::MAX_TREE_DEPTH,
    vfs::{NodeKind, StorageBackend},
    vpath::VPath,
};

/// How bad a finding is. Only [`Severity::Corrupt`] makes a check fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Data is damaged or missing where it must exist.
    Corrupt,
    /// Suspicious but not necessarily damage; the repository still works.
    Warning,
    /// Content this repository was never meant to receive.
    Redacted,
    /// Harmless leftovers of interrupted commands.
    Note,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Corrupt => "corrupt",
            Severity::Warning => "warning",
            Severity::Redacted => "redacted (expected)",
            Severity::Note => "note",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.severity.label(), self.message)
    }
}

#[derive(Clone, Debug, Default)]
pub struct FsckReport {
    /// Distinct objects whose hash and encoding were verified.
    pub objects_checked: usize,
    pub objects_unreachable: usize,
    pub snapshots: usize,
    pub trees: usize,
    pub files: usize,
    pub operations: usize,
    pub keyrings: usize,
    pub embargoes: usize,
    /// Sealed objects present but not openable by this identity (normal for
    /// non-members; not a finding).
    pub sealed_unreadable: usize,
    pub findings: Vec<Finding>,
}

impl FsckReport {
    /// True when nothing is corrupt.
    pub fn is_ok(&self) -> bool {
        self.count(Severity::Corrupt) == 0
    }

    pub fn count(&self, s: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == s).count()
    }

    pub fn of(&self, s: Severity) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(move |f| f.severity == s)
    }
}

/// Check the repository a `Repo` was opened on, with its identity's keys.
/// Files modified this long before the crashed holder took its lock, by
/// its wall clock, are still checked by [`recover_interrupted_writes`]
/// (wall-clock adjustments, and another host's clock).
const RECOVERY_MARGIN_MS: i64 = 60 * 60 * 1000;

/// The same for a window known on the backend's own stamp clock (only
/// steps of that clock between the acquisition and the writes matter).
const STAMP_MARGIN_MS: i64 = 5 * 60 * 1000;

/// Which loose objects a crashed lock holder may have written unsynced:
/// those modified since it took the lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryWindow {
    /// When the holder took the lock, on the backend's stat clock (see
    /// [`StorageBackend::stat_clock`]; the lock file's own stamp).
    Stamp(i64),
    /// When the holder took the lock, by its wall clock (ms since the
    /// epoch). Used on backends with wall-clock stamps, with a generous
    /// margin.
    Wall(i64),
    /// Unknown: every loose object.
    All,
}

impl RecoveryWindow {
    /// The stamp (on `backend`'s stat clock) before which a file cannot
    /// have been written by the crashed holder; `None`: check every file.
    fn cutoff(self, backend: &dyn StorageBackend) -> Option<i64> {
        let clock = backend.stat_clock()?;
        match self {
            // A generation counter never steps back: no margin.
            RecoveryWindow::Stamp(s) if clock.exact => Some(s),
            RecoveryWindow::Stamp(s) => Some(s.saturating_sub(STAMP_MARGIN_MS.saturating_mul(1_000_000))),
            RecoveryWindow::Wall(ms) if !clock.exact => {
                Some(ms.saturating_sub(RECOVERY_MARGIN_MS).saturating_mul(1_000_000))
            }
            RecoveryWindow::Wall(_) | RecoveryWindow::All => None,
        }
    }
}

/// Clean up after a lock holder that died, run by the new holder under the
/// lock before anything else touches the repository.
///
/// Transactions write objects *unsynced* and make them durable with one
/// barrier before writing the operation (see
/// [`StorageBackend::write_unsynced`]). A holder that dies before its
/// barrier (or whose barrier failed) can leave loose objects that
///
/// * are intact but not yet durable (the process died, the OS did not):
///   they are rewritten (a new file, so a page the kernel marked clean
///   after a failed write-back is not trusted) and synced, because a later
///   transaction may reuse them instead of writing its own copy; or
/// * are empty or truncated (the machine lost power): they are removed, so
///   that nobody mistakes them for the object they are named after.
///
/// Neither kind can be referenced by an operation: the operation is only
/// written after the barrier. Only files modified within `window` are read
/// (fanout directories not modified since are skipped without listing
/// them). The lock records the holder's acquisition on the backend's own
/// stamp clock, so on disk this is the dead holder's writes plus five
/// minutes; without a usable stamp, every loose object is read. Returns
/// the number of objects removed.
pub fn recover_interrupted_writes(backend: &dyn StorageBackend, window: RecoveryWindow) -> Result<usize> {
    let root = vpath(".veil/objects");
    if !backend.exists(&root)? {
        return Ok(0);
    }
    let cutoff = window.cutoff(backend);
    let before = |m: &crate::vfs::Metadata, cut: i64| {
        let old = |t: Option<i64>| t.is_some_and(|t| t < cut);
        old(m.mtime) && (m.ctime.is_none() || old(m.ctime))
    };
    let mut removed = 0;
    for d in backend.list_dir(&root)? {
        if !is_fanout(&d) {
            continue;
        }
        let dir = root.join(&d.name);
        // Writing a loose object (temp file, rename) changes its
        // directory: an older directory holds nothing to recover.
        if let Some(cut) = cutoff {
            if backend.metadata(&dir)?.is_some_and(|m| before(&m, cut)) {
                continue;
            }
        }
        for f in backend.list_dir(&dir)? {
            let Some(id) = loose_id(&d.name, &f) else { continue };
            let path = dir.join(&f.name);
            if let Some(cut) = cutoff {
                let Some(m) = backend.metadata(&path)? else { continue };
                if before(&m, cut) {
                    continue;
                }
            }
            let Some(raw) = backend.read_opt(&path)? else { continue };
            if ObjectId::hash(&raw) == id {
                backend.write_unsynced(&path, &raw)?;
            } else {
                backend.remove_file(&path)?;
                removed += 1;
            }
        }
    }
    backend.sync_barrier()?;
    Ok(removed)
}

fn is_fanout(d: &crate::vfs::DirEntry) -> bool {
    d.kind == NodeKind::Dir && d.name.len() == 2 && d.name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The id a loose object file `<fanout>/<name>` is filed under, if it is one.
fn loose_id(fanout: &str, f: &crate::vfs::DirEntry) -> Option<ObjectId> {
    if f.kind != NodeKind::File || is_temp(&f.name) {
        return None;
    }
    let hex = format!("{fanout}{}", f.name);
    ObjectId::from_hex(&hex).ok().filter(|id| id.hex() == hex)
}

pub fn fsck_repo(repo: &Repo) -> Result<FsckReport> {
    fsck(repo.backend().clone(), repo.identity().cloned())
}

/// Check the repository stored on `backend`. `identity` is used to open
/// sealed objects; without it, sealed content is only checked structurally.
pub fn fsck(backend: Arc<dyn StorageBackend>, identity: Option<Identity>) -> Result<FsckReport> {
    let mut report = FsckReport::default();
    let config = backend.read(&vpath(".veil/repo.json"))?;
    let (repo_id, format) = match serde_json::from_slice::<RepoConfig>(&config) {
        Ok(c) => (c.repo_id, c.format),
        Err(e) => {
            report.findings.push(Finding {
                severity: Severity::Corrupt,
                message: format!(".veil/repo.json cannot be parsed: {e}"),
            });
            (String::new(), crate::repo::REPO_FORMAT)
        }
    };
    if let Err(e) = crate::repo::check_format_supported(format) {
        report.findings.push(Finding {
            severity: Severity::Corrupt,
            message: e.to_string(),
        });
    }
    let keys = Arc::new(Keychain::new(backend.clone(), identity, repo_id));
    let store = ObjectStore::new(backend.clone(), vpath(".veil/objects"), keys.clone());
    store.set_format(format);
    // Read-only: looking at gc-pending objects must not write keep markers
    // or loose copies (that would also rescue garbage from the next gc).
    store.set_freshening(false);
    let mut c = Checker {
        backend,
        store,
        keys,
        report,
        verified: HashSet::new(),
        seen_snapshots: HashSet::new(),
        seen_trees: HashSet::new(),
        seen_blobs: HashSet::new(),
        missing: BTreeMap::new(),
        embargoes: BTreeMap::new(),
        unknown_embargoes: BTreeSet::new(),
        missing_predecessors: 0,
        temp_files: 0,
        torn: 0,
    };
    c.check_meta()?;
    let roots = c.check_ops()?;
    c.walk_snapshots(roots);
    c.scan_loose_objects()?;
    c.finish()?;
    let mut report = c.report;
    report.findings.sort_by_key(|f| f.severity);
    Ok(report)
}

fn vpath(s: &str) -> VPath {
    VPath::new(s).expect("static path")
}

fn is_temp(name: &str) -> bool {
    name.starts_with('.') && name.contains(".vltmp")
}

// Short-lived, never stored: boxing the object would only add allocations.
#[allow(clippy::large_enum_variant)]
enum Load {
    Obj(Object),
    Missing,
    Bad,
}

struct Checker {
    backend: Arc<dyn StorageBackend>,
    store: ObjectStore,
    keys: Arc<Keychain>,
    report: FsckReport,
    /// Objects whose hash and encoding were checked (good or bad).
    verified: HashSet<ObjectId>,
    seen_snapshots: HashSet<ObjectId>,
    seen_trees: HashSet<ObjectId>,
    seen_blobs: HashSet<ObjectId>,
    /// Missing objects with the most severe classification seen so far.
    missing: BTreeMap<ObjectId, (Severity, String)>,
    /// Embargo id → released.
    embargoes: BTreeMap<String, bool>,
    unknown_embargoes: BTreeSet<String>,
    missing_predecessors: usize,
    temp_files: usize,
    /// Unreachable objects that fail their hash while a lock is left over.
    torn: usize,
}

impl Checker {
    fn push(&mut self, severity: Severity, message: impl Into<String>) {
        self.report.findings.push(Finding {
            severity,
            message: message.into(),
        });
    }

    fn list(&self, dir: &str) -> Result<Vec<crate::vfs::DirEntry>> {
        let d = vpath(dir);
        if !self.backend.exists(&d)? {
            return Ok(vec![]);
        }
        self.backend.list_dir(&d)
    }

    // ---- objects ------------------------------------------------------------

    /// Mark `id` as verified; true the first time.
    fn first_visit(&mut self, id: &ObjectId) -> bool {
        let first = self.verified.insert(*id);
        self.report.objects_checked += usize::from(first);
        first
    }

    /// Read, re-hash and decode one object. Damage is reported once per id.
    fn load(&mut self, id: &ObjectId) -> Load {
        let raw = match self.store.get_raw(id) {
            Ok(raw) => raw,
            Err(e) if e.is_unreadable() => return Load::Missing,
            Err(e) => {
                if self.first_visit(id) {
                    self.push(Severity::Corrupt, format!("object {id}: cannot be read: {e}"));
                }
                return Load::Bad;
            }
        };
        let first = self.first_visit(id);
        if ObjectId::hash(&raw) != *id {
            if first {
                self.push(
                    Severity::Corrupt,
                    format!("object {id}: content does not match its hash"),
                );
            }
            return Load::Bad;
        }
        if let Some(enc) = Object::tree_encoding(&raw) {
            if first && enc.min_repo_format() > self.store.format() {
                self.push(
                    Severity::Corrupt,
                    format!(
                        "object {id}: a format-{} tree in a format-{} repository (older vl cannot read it)",
                        enc.min_repo_format(),
                        self.store.format()
                    ),
                );
            }
        }
        match Object::decode(&raw) {
            Ok(o) => Load::Obj(o),
            Err(e) => {
                if first {
                    self.push(Severity::Corrupt, format!("object {id}: cannot be decoded: {e}"));
                }
                Load::Bad
            }
        }
    }

    /// Peel sealed layers we hold keys for. `None` if unreadable (reported
    /// as appropriate).
    fn unseal(&mut self, id: &ObjectId, mut obj: Object, what: &str) -> Option<Object> {
        while let Object::Sealed(env) = obj {
            let Some(key) = self.keys.key(&env.scope) else {
                self.report.sealed_unreadable += 1;
                return None;
            };
            let plain = match env.open(&key) {
                Ok(p) => p,
                Err(_) => {
                    self.push(
                        Severity::Warning,
                        format!(
                            "{what}: object {} does not open with this repository's '{}' key \
                             (tampered, or sealed by an unrelated scope of the same name)",
                            id.short(),
                            env.scope
                        ),
                    );
                    return None;
                }
            };
            obj = match Object::decode(&plain) {
                Ok(o) => o,
                Err(e) => {
                    self.push(
                        Severity::Corrupt,
                        format!("{what}: sealed object {} decrypts to garbage: {e}", id.short()),
                    );
                    return None;
                }
            };
        }
        Some(obj)
    }

    fn note_missing(&mut self, id: ObjectId, severity: Severity, message: String) {
        match self.missing.get(&id) {
            Some((s, _)) if *s <= severity => {}
            _ => {
                self.missing.insert(id, (severity, message));
            }
        }
    }

    // ---- graph ----------------------------------------------------------------

    fn walk_snapshots(&mut self, roots: Vec<(ObjectId, String)>) {
        // The flag marks a parent a public remote withholds: the merged-in
        // side of an embargoed merge, until the embargo is released.
        let mut stack: Vec<(ObjectId, String, bool)> = roots.into_iter().rev().map(|(id, from)| (id, from, false)).collect();
        while let Some((id, from, withheld)) = stack.pop() {
            if !self.seen_snapshots.insert(id) {
                continue;
            }
            let s = match self.load(&id) {
                Load::Obj(Object::Snapshot(s)) => s,
                Load::Obj(o) => {
                    self.push(
                        Severity::Corrupt,
                        format!("{from} refers to {id} as a snapshot, but it is a {}", o.kind_name()),
                    );
                    continue;
                }
                Load::Missing if withheld => {
                    self.note_missing(
                        id,
                        Severity::Redacted,
                        format!("snapshot {id} (merged by {from}) is withheld until its embargo is released"),
                    );
                    continue;
                }
                Load::Missing => {
                    self.note_missing(
                        id,
                        Severity::Corrupt,
                        format!("snapshot {id} (referenced by {from}) is missing"),
                    );
                    continue;
                }
                Load::Bad => continue,
            };
            self.report.snapshots += 1;
            let me = format!("snapshot {}", id.short());
            let embargoed = s
                .embargo
                .as_ref()
                .is_some_and(|e| !self.embargoes.get(e).copied().unwrap_or(false));
            for (i, p) in s.parents.iter().enumerate().rev() {
                stack.push((*p, me.clone(), embargoed && i > 0));
            }
            for p in &s.predecessors {
                if !self.store.has(p) {
                    self.missing_predecessors += 1;
                }
            }
            if let Some(e) = &s.embargo {
                self.check_embargo_known(e);
            }
            if let Text::Sealed(env) = &s.description {
                if self.keys.has(&env.scope) && self.store.read_text(&s.description).is_none() {
                    self.push(
                        Severity::Warning,
                        format!("{me}: sealed description does not open with the '{}' key", env.scope),
                    );
                }
            }
            self.check_tree(s.tree, &format!("{me}:/"), false);
        }
    }

    /// Check the tree `id` and everything below it. Iterative: the depth of
    /// a tampered `.veil/` is unbounded, so nesting beyond
    /// [`MAX_TREE_DEPTH`] is reported instead of followed.
    fn check_tree(&mut self, id: ObjectId, path: &str, redactable: bool) {
        let mut stack = vec![(id, path.to_string(), redactable, 0usize)];
        while let Some((id, path, redactable, depth)) = stack.pop() {
            if depth > MAX_TREE_DEPTH {
                self.push(
                    Severity::Corrupt,
                    format!("directory {path}: nesting exceeds {MAX_TREE_DEPTH} levels; not followed"),
                );
                continue;
            }
            let children = self.check_tree_node(id, &path, redactable);
            // Reverse, so that entries are visited in tree order.
            stack.extend(children.into_iter().rev().map(|(id, p, r)| (id, p, r, depth + 1)));
        }
    }

    /// Check one tree node; returns the trees below it still to visit.
    fn check_tree_node(&mut self, id: ObjectId, path: &str, redactable: bool) -> Vec<(ObjectId, String, bool)> {
        let mut next = Vec::new();
        if !self.seen_trees.insert(id) {
            return next;
        }
        let obj = match self.load(&id) {
            Load::Obj(o) => o,
            Load::Missing => {
                let sev = if redactable {
                    Severity::Redacted
                } else {
                    Severity::Corrupt
                };
                self.note_missing(id, sev, format!("directory {path}: tree {id} is missing"));
                return next;
            }
            Load::Bad => return next,
        };
        let tree = match self.unseal(&id, obj, path) {
            Some(Object::Tree(t)) => t,
            Some(o) => {
                self.push(
                    Severity::Corrupt,
                    format!(
                        "directory {path}: {} should be a tree but is a {}",
                        id.short(),
                        o.kind_name()
                    ),
                );
                return next;
            }
            None => return next,
        };
        self.report.trees += 1;
        // An embargo wrapper: its sealed side (withheld until release) and
        // its fallback, plus the listed objects only the sealed side reaches.
        if let Some(w) = crate::embargo::wrapper_parts(&tree) {
            self.check_embargo_known(&w.embargo);
            next.push((w.inner, format!("{path} (under embargo {})", w.embargo), true));
            next.push((w.fallback, path.to_string(), false));
            return next;
        }
        let mut prev: Option<&str> = None;
        for e in &tree.entries {
            let bad_name = e.name.is_empty() || e.name == "." || e.name == ".." || e.name.contains(['/', '\0']);
            if bad_name {
                self.push(
                    Severity::Corrupt,
                    format!(
                        "directory {path}: tree {} has an invalid entry name {:?}",
                        id.short(),
                        e.name
                    ),
                );
                continue;
            }
            if prev.is_some_and(|p| p >= e.name.as_str()) {
                self.push(
                    Severity::Corrupt,
                    format!(
                        "directory {path}: tree {} entries are not sorted and unique",
                        id.short()
                    ),
                );
            }
            prev = Some(&e.name);
        }
        for e in &tree.entries {
            if e.name.is_empty() || e.name.contains('/') {
                continue;
            }
            let child = if path.ends_with('/') {
                format!("{path}{}", e.name)
            } else {
                format!("{path}/{}", e.name)
            };
            match e.kind {
                EntryKind::Dir => next.push((e.id, child, !e.visibility.is_public())),
                EntryKind::File => self.check_file(e, &child),
            }
        }
        next
    }

    fn check_embargo_known(&mut self, embargo: &str) {
        if !self.embargoes.contains_key(embargo) && self.unknown_embargoes.insert(embargo.to_string()) {
            self.push(
                Severity::Warning,
                format!("embargo {embargo} is used in the history but has no record; its content is unreadable"),
            );
        }
    }

    fn check_file(&mut self, e: &TreeEntry, path: &str) {
        self.report.files += 1;
        let (missing_as, why) = match &e.visibility {
            Visibility::Public => (Severity::Corrupt, String::new()),
            Visibility::Cloaked { scope } => (
                Severity::Redacted,
                format!(" (cloaked under '{scope}': withheld from public remotes)"),
            ),
            Visibility::Embargoed { embargo } => {
                self.check_embargo_known(embargo);
                let released = self.embargoes.get(embargo).copied().unwrap_or(false);
                let why = if released {
                    format!(" (embargo {embargo} was released; pull again to receive it)")
                } else {
                    format!(" (under embargo {embargo})")
                };
                (Severity::Redacted, why)
            }
        };
        let label = format!("file {path}");
        self.check_blob(e.id, &label, missing_as, &why, Some(e.visibility.key_scope()));
        if let Some(fb) = e.fallback {
            // The pre-merge version may itself have been cloaked and withheld,
            // which this entry cannot tell; hence only a warning.
            self.check_blob(
                fb,
                &format!("{label} (embargo fallback)"),
                Severity::Warning,
                " (withheld if the pre-merge file was cloaked)",
                None,
            );
        }
    }

    /// `expected_scope`: `Some(None)` = must be plaintext, `Some(Some(s))` =
    /// must be sealed under `s`, `None` = not checked.
    fn check_blob(
        &mut self,
        id: ObjectId,
        label: &str,
        missing_as: Severity,
        why: &str,
        expected_scope: Option<Option<String>>,
    ) {
        if !self.seen_blobs.insert(id) {
            // Already verified; a missing object may need a stricter class.
            if self.missing.contains_key(&id) {
                self.note_missing(id, missing_as, format!("{label}: content {id} is missing{why}"));
            }
            return;
        }
        let obj = match self.load(&id) {
            Load::Obj(o) => o,
            Load::Missing => {
                self.note_missing(id, missing_as, format!("{label}: content {id} is missing{why}"));
                return;
            }
            Load::Bad => return,
        };
        // Envelope labels may carry a key generation (`team#<key-id>`); the
        // entry's visibility names only the scope.
        let actual_scope = match &obj {
            Object::Sealed(env) => Some(crate::keychain::split_label(&env.scope).0.to_string()),
            _ => None,
        };
        if let Some(expected) = expected_scope {
            if expected != actual_scope {
                let show = |s: &Option<String>| {
                    s.as_deref()
                        .map_or("plaintext".to_string(), |s| format!("sealed under '{s}'"))
                };
                self.push(
                    Severity::Warning,
                    format!(
                        "{label}: entry says {} but object {} is {}",
                        show(&expected),
                        id.short(),
                        show(&actual_scope)
                    ),
                );
            }
        }
        match self.unseal(&id, obj, label) {
            Some(Object::Blob(_)) | None => {}
            Some(o) => self.push(
                Severity::Corrupt,
                format!(
                    "{label}: {} should be file content but is a {}",
                    id.short(),
                    o.kind_name()
                ),
            ),
        }
    }

    // ---- loose objects ---------------------------------------------------------

    /// Verify every loose object file, including unreachable ones. Unknown
    /// directories (e.g. packs owned by another layer) are skipped.
    fn scan_loose_objects(&mut self) -> Result<()> {
        // A leftover lock means its holder may have died before its sync
        // barrier: unreachable objects it wrote may be torn, and the next
        // holder removes them (see `recover_interrupted_writes`).
        let interrupted = RepoLock::holder(&*self.backend)?.is_some();
        for d in self.list(".veil/objects")? {
            if !is_fanout(&d) {
                continue;
            }
            for f in self.backend.list_dir(&vpath(".veil/objects").join(&d.name))? {
                if is_temp(&f.name) {
                    self.temp_files += 1;
                    continue;
                }
                let Some(id) = loose_id(&d.name, &f) else {
                    self.push(
                        Severity::Note,
                        format!("unexpected entry .veil/objects/{}/{}", d.name, f.name),
                    );
                    continue;
                };
                if self.verified.contains(&id) {
                    continue;
                }
                if interrupted {
                    let path = vpath(".veil/objects").join(&d.name).join(&f.name);
                    if let Some(raw) = self.backend.read_opt(&path)? {
                        if ObjectId::hash(&raw) != id {
                            self.first_visit(&id);
                            self.torn += 1;
                            continue;
                        }
                    }
                }
                self.report.objects_unreachable += 1;
                if let Load::Missing = self.load(&id) {
                    self.report.objects_unreachable -= 1;
                }
            }
        }
        Ok(())
    }

    // ---- metadata ----------------------------------------------------------------

    fn check_meta(&mut self) -> Result<()> {
        for e in self.list(".veil/meta/keyrings")? {
            let path = format!(".veil/meta/keyrings/{}", e.name);
            let Some(scope) = e.name.strip_suffix(".json").filter(|_| e.kind == NodeKind::File) else {
                if is_temp(&e.name) {
                    self.temp_files += 1;
                } else {
                    self.push(Severity::Note, format!("unexpected entry {path}"));
                }
                continue;
            };
            self.report.keyrings += 1;
            let raw = self.backend.read(&vpath(&path))?;
            match serde_json::from_slice::<KeyRing>(&raw) {
                Err(err) => self.push(Severity::Corrupt, format!("key ring {path} cannot be parsed: {err}")),
                Ok(ring) => {
                    if ring.scope != scope {
                        self.push(
                            Severity::Corrupt,
                            format!(
                                "key ring {path} is filed as '{scope}' but is for scope '{}'",
                                ring.scope
                            ),
                        );
                    }
                    for (member, m) in &ring.members {
                        let bad_wrap = m.wrapped.sealed.scope != format!("wrap:{}", ring.scope);
                        if parse_public_key(member).is_err() || bad_wrap {
                            self.push(
                                Severity::Corrupt,
                                format!("key ring {path}: member {member} is malformed"),
                            );
                        }
                    }
                }
            }
        }
        for e in self.list(".veil/meta/embargoes")? {
            let path = format!(".veil/meta/embargoes/{}", e.name);
            let Some(id) = e.name.strip_suffix(".json").filter(|_| e.kind == NodeKind::File) else {
                if is_temp(&e.name) {
                    self.temp_files += 1;
                } else {
                    self.push(Severity::Note, format!("unexpected entry {path}"));
                }
                continue;
            };
            self.report.embargoes += 1;
            let raw = self.backend.read(&vpath(&path))?;
            match serde_json::from_slice::<EmbargoRecord>(&raw) {
                Err(err) => self.push(
                    Severity::Corrupt,
                    format!("embargo record {path} cannot be parsed: {err}"),
                ),
                Ok(rec) => {
                    if rec.id != id {
                        self.push(
                            Severity::Corrupt,
                            format!(
                                "embargo record {path} is filed as '{id}' but is for embargo '{}'",
                                rec.id
                            ),
                        );
                    }
                    if let Some(k) = &rec.released_key {
                        if crate::crypto::parse_key_hex(k).is_err() {
                            self.push(
                                Severity::Corrupt,
                                format!("embargo record {path}: released key is malformed"),
                            );
                        }
                    }
                    self.embargoes.insert(rec.id.clone(), rec.is_released());
                }
            }
        }
        Ok(())
    }

    // ---- operation log -------------------------------------------------------------

    /// Check the op log and return the snapshot roots to walk: the current
    /// view first, then the views of all other retained operations.
    fn check_ops(&mut self) -> Result<Vec<(ObjectId, String)>> {
        let mut ops: BTreeMap<ObjectId, Operation> = BTreeMap::new();
        let mut damaged: BTreeSet<ObjectId> = BTreeSet::new();
        for e in self.list(".veil/ops")? {
            if is_temp(&e.name) {
                self.temp_files += 1;
                continue;
            }
            let id = match ObjectId::from_hex(&e.name) {
                Ok(id) if e.kind == NodeKind::File && id.hex() == e.name => id,
                _ => {
                    self.push(Severity::Note, format!("unexpected entry .veil/ops/{}", e.name));
                    continue;
                }
            };
            let raw = self.backend.read(&vpath(".veil/ops").join(&e.name))?;
            if ObjectId::hash(&raw) != id {
                self.push(
                    Severity::Corrupt,
                    format!("operation {}: content does not match its id", id.short()),
                );
                damaged.insert(id);
                continue;
            }
            match serde_json::from_slice::<Operation>(&raw) {
                Ok(op) => {
                    ops.insert(id, op);
                }
                Err(err) => {
                    self.push(
                        Severity::Corrupt,
                        format!("operation {}: cannot be parsed: {err}", id.short()),
                    );
                    damaged.insert(id);
                }
            }
        }
        self.report.operations = ops.len() + damaged.len();

        let head = match self.backend.read_opt(&vpath(".veil/op_head"))? {
            None => {
                self.push(Severity::Corrupt, ".veil/op_head is missing");
                None
            }
            Some(raw) => match ObjectId::from_hex(String::from_utf8_lossy(&raw).trim()) {
                Err(_) => {
                    self.push(Severity::Corrupt, ".veil/op_head does not contain an operation id");
                    None
                }
                Ok(h) if ops.contains_key(&h) => Some(h),
                Ok(h) => {
                    if !damaged.contains(&h) {
                        self.push(
                            Severity::Corrupt,
                            format!(".veil/op_head points to missing operation {}", h.short()),
                        );
                    }
                    None
                }
            },
        };

        let pruned = crate::oplog::pruned_ops(&*self.backend).unwrap_or_default();
        for (id, op) in &ops {
            for p in &op.parents {
                if pruned.contains(p) {
                    self.push(
                        Severity::Note,
                        format!("operation {}: parent operation {} was pruned by gc", id.short(), p.short()),
                    );
                    continue;
                }
                if !ops.contains_key(p) && !damaged.contains(p) {
                    let msg = format!("operation {}: parent operation {} is missing", id.short(), p.short());
                    self.report.findings.push(Finding {
                        severity: Severity::Corrupt,
                        message: msg,
                    });
                }
            }
        }

        // Operations the head cannot reach never took effect (a crash between
        // writing an operation and moving the head) or were superseded.
        let mut reachable = BTreeSet::new();
        let mut queue: VecDeque<ObjectId> = head.into_iter().collect();
        while let Some(id) = queue.pop_front() {
            if reachable.insert(id) {
                if let Some(op) = ops.get(&id) {
                    queue.extend(op.parents.iter().copied());
                }
            }
        }
        if head.is_some() {
            let dangling: Vec<String> = ops
                .keys()
                .filter(|id| !reachable.contains(*id))
                .map(|id| id.short())
                .collect();
            if !dangling.is_empty() {
                self.push(
                    Severity::Note,
                    format!(
                        "{} operation(s) not reachable from the head (e.g. an interrupted transaction): {}",
                        dangling.len(),
                        dangling.join(", ")
                    ),
                );
            }
        }

        let mut roots = Vec::new();
        if let Some(h) = head {
            roots.extend(
                ops[&h]
                    .view
                    .refs()
                    .into_iter()
                    .map(|r| (r, "the current view".to_string())),
            );
        }
        for (id, op) in &ops {
            if Some(*id) != head {
                roots.extend(
                    op.view
                        .refs()
                        .into_iter()
                        .map(|r| (r, format!("operation {}", id.short()))),
                );
            }
        }
        Ok(roots)
    }

    fn finish(&mut self) -> Result<()> {
        for (_, (severity, message)) in std::mem::take(&mut self.missing) {
            self.push(severity, message);
        }
        if self.missing_predecessors > 0 {
            self.push(
                Severity::Note,
                format!(
                    "{} predecessor snapshot(s) of the evolution log are not present (normal after clone or pull)",
                    self.missing_predecessors
                ),
            );
        }
        if self.report.objects_unreachable > 0 {
            self.push(
                Severity::Note,
                format!(
                    "{} unreachable object(s) (rewritten history or interrupted commands; harmless)",
                    self.report.objects_unreachable
                ),
            );
        }
        if self.torn > 0 {
            self.push(
                Severity::Note,
                format!(
                    "{} unreachable object(s) torn by an interrupted write; the next command removes them",
                    self.torn
                ),
            );
        }
        if self.temp_files > 0 {
            self.push(
                Severity::Note,
                format!("{} leftover temporary file(s) from interrupted writes", self.temp_files),
            );
        }
        if let Some(holder) = RepoLock::holder(&*self.backend)? {
            let state = if holder.lease_expired(now_millis()) {
                "expired"
            } else {
                "active"
            };
            self.push(
                Severity::Note,
                format!("repository lock present ({state}), held by {}", holder.describe()),
            );
        }
        if self.backend.exists(&vpath(STEAL_PATH))? {
            self.push(
                Severity::Note,
                format!("{STEAL_PATH} present (an interrupted lock takeover)"),
            );
        }
        Ok(())
    }
}
