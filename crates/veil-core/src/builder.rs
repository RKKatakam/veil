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
//!
//! The working copy is untrusted ground, so nothing in it can fail a build
//! or slip through silently:
//!
//! * crash leftovers of interrupted writes (`.name.vltmpXXXXXXXX`) are
//!   skipped;
//! * an unreadable file or directory keeps its previous entry (or stays out
//!   if it was never tracked) and is reported;
//! * names that are not valid UTF-8 cannot be recorded and are reported;
//! * a tracked path that became a symlink (or socket, device…) is never
//!   followed: its tracked entry is kept and reported.
//!
//! On a backend that folds names ([`StorageBackend::name_folding`], e.g. a
//! macOS volume) a name that is an alias of the parent's entry (another case,
//! or HFS+ handing back NFD for a name checked out in NFC) keeps the parent's
//! spelling, and new names are recorded in NFC. Directories whose entries
//! would collide on such a filesystem are reported on every backend
//! ([`BuildReport::name_collisions`]), so a Linux user learns before a macOS
//! teammate's checkout refuses the snapshot.
//!
//! With [`InjectedSecrets`] (the isolated files a `ws exec` sandbox was given)
//! any new content that contains one of those values is quarantined, so a
//! command cannot launder an injected secret into history under another name.

use std::collections::{HashMap, HashSet};

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Object, Tree, TreeEntry, Visibility},
    policy::{Policy, Tier, POLICY_FILE},
    secrets::{self, Finding},
    statcache::{CacheKey, CacheRun, StatCache},
    store::ObjectStore,
    vfs::{is_temp_name, DirListing, Metadata, NodeKind, StorageBackend},
    vpath::{NameFolding, VPath},
};

pub struct BuildOptions<'a> {
    pub policy: &'a Policy,
    /// Tree of the snapshot being amended (enables reuse and carry-over).
    pub parent_tree: Option<ObjectId>,
    /// Cloak every public file under this scope (cloaked line of work).
    pub cloak: Option<&'a str>,
    /// Secret content the engine handed to whoever wrote `fs` (the isolated
    /// files injected into a sandbox). New content containing any of it is
    /// quarantined, whatever its path and tier.
    pub injected: Option<&'a InjectedSecrets>,
    /// Re-scan unchanged public files (normally trusted because they were
    /// scanned when they entered the parent). Set once after the secret
    /// scanner's rules change, so files an older scanner let through are
    /// caught. Also disables reuse hints for that build.
    pub rescan: bool,
}

/// Rule name of a [`Finding`] for content copied from an injected secret.
pub const INJECTED_RULE: &str = "injected-isolated-secret";

/// Values the engine injected from the vault (isolated files such as
/// `.env`, keys, quarantined files) into a sandbox. Built from the files'
/// contents: every `KEY=value` / `key: value` value that looks like a secret
/// (at least 8 characters, and either 20+ characters or a mix of character
/// classes, so `localhost`, `production` or `3000` never match), plus the
/// whole content and every whitespace-free line of 24+ characters (key
/// material, bare tokens).
#[derive(Debug, Default, Clone)]
pub struct InjectedSecrets {
    /// (needle, the injected file it came from)
    needles: Vec<(Vec<u8>, String)>,
    matcher: Option<regex::bytes::Regex>,
}

impl InjectedSecrets {
    pub fn from_files<'a>(files: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> InjectedSecrets {
        let mut needles: Vec<(Vec<u8>, String)> = Vec::new();
        let mut add = |v: &str, src: &str| {
            let v = v.trim();
            if secret_like(v) && !needles.iter().any(|(n, _)| n == v.as_bytes()) {
                needles.push((v.as_bytes().to_vec(), src.to_string()));
            }
        };
        for (src, data) in files {
            let text = String::from_utf8_lossy(data);
            if text.trim().len() >= LONG_NEEDLE {
                add(&text, src);
            }
            for line in text.lines() {
                // Whole lines only when long and unbroken (key material,
                // tokens), not ordinary `MODE=production` or code lines.
                let line_t = line.trim();
                if line_t.len() >= LONG_NEEDLE && !line_t.contains(char::is_whitespace) {
                    add(line_t, src);
                }
                if let Some(v) = assignment_value(line) {
                    add(v, src);
                }
            }
        }
        // Longest first, so the leftmost match reports the most specific value.
        needles.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        let matcher = (!needles.is_empty())
            .then(|| {
                let alts: Vec<String> = needles
                    .iter()
                    .map(|(n, _)| regex::escape(std::str::from_utf8(n).expect("needles are UTF-8")))
                    .collect();
                regex::bytes::RegexBuilder::new(&alts.join("|"))
                    .size_limit(256 << 20)
                    .dfa_size_limit(64 << 20)
                    .build()
                    .ok()
            })
            .flatten();
        InjectedSecrets { needles, matcher }
    }

    pub fn is_empty(&self) -> bool {
        self.needles.is_empty()
    }

    /// The first injected value contained in `data`, as a printable finding.
    pub fn find(&self, data: &[u8]) -> Option<Finding> {
        let (start, needle) = match &self.matcher {
            Some(re) => {
                let m = re.find(data)?;
                (m.start(), self.needles.iter().find(|(n, _)| n == m.as_bytes())?)
            }
            // Pattern too large for the regex engine: plain substring search.
            None => self.needles.iter().find_map(|n| {
                data.windows(n.0.len()).position(|w| w == n.0.as_slice()).map(|i| (i, n))
            })?,
        };
        Some(Finding {
            rule: INJECTED_RULE,
            line: data[..start].iter().filter(|&&b| b == b'\n').count() + 1,
            excerpt: format!("content of {} injected into the sandbox", needle.1),
        })
    }
}

/// Minimum length of whole-file and whole-line needles.
const LONG_NEEDLE: usize = 24;

/// Long enough, and not a plain word or number.
fn secret_like(v: &str) -> bool {
    if v.len() < 8 || v.contains('\u{fffd}') {
        return false;
    }
    let classes = [
        v.bytes().any(|b| b.is_ascii_lowercase()),
        v.bytes().any(|b| b.is_ascii_uppercase()),
        v.bytes().any(|b| b.is_ascii_digit()),
        v.bytes().any(|b| !b.is_ascii_alphanumeric()),
    ];
    v.len() >= 20 || classes.iter().filter(|&&c| c).count() >= 2
}

/// `value` of `KEY=value`, `export KEY="value"` or `key: value`.
fn assignment_value(line: &str) -> Option<&str> {
    let line = line.trim();
    let line = line.strip_prefix("export ").unwrap_or(line);
    let at = line.find(['=', ':'])?;
    let key = line[..at].trim();
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')) {
        return None;
    }
    let v = line[at + 1..].trim();
    let v = v
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| v.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(v);
    Some(v)
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
    /// Files or directories that could not be read (e.g. permission
    /// denied), with the reason. A tracked one keeps its previous entry; an
    /// untracked one is left out. Never fatal.
    pub unreadable: Vec<(VPath, String)>,
    /// Entries whose names are not valid UTF-8 (escaped for display, with
    /// their directory). They cannot be recorded.
    pub unrepresentable: Vec<String>,
    /// Tracked paths that are now a symlink or another special file. Veil
    /// never follows them; the tracked entry is kept unchanged.
    pub shadowed: Vec<VPath>,
    /// Pairs of recorded paths that differ only in case or Unicode
    /// normalisation, at least one of them new in this snapshot. Valid
    /// here, but a checkout on a case-insensitive filesystem (macOS by
    /// default) refuses the snapshot.
    pub name_collisions: Vec<(VPath, VPath)>,
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
    /// Re-scan unchanged public content (scanner rules changed since this
    /// device last scanned). Affects secret scanning only, never visibility.
    rescan: bool,
    cache: Option<CacheRun>,
    report: BuildReport,
    /// How `fs` compares names (read once per build).
    folding: NameFolding,
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
    let use_hints = use_hints && !opts.rescan;
    let policy_changed = match (fs.read_opt(&policy_path)?, parent_policy) {
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
        rescan: opts.rescan,
        cache: run,
        report: BuildReport {
            policy_warnings: opts.policy.warnings.clone(),
            ..Default::default()
        },
        folding: fs.name_folding(),
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
        let listing = match self.fs.list_dir_full(dir) {
            Ok(l) if self.folding.folds() => self.canonical_names(dir, l, parent),
            Ok(l) => l,
            // Vanished while we were building: a deletion like any other.
            Err(e) if e.is_not_found() && !dir.is_root() => return Ok(None),
            // Unreadable (e.g. permission denied): keep what was tracked.
            Err(VeilError::Io { source, .. }) if !dir.is_root() => {
                self.report.unreadable.push((dir.clone(), source.to_string()));
                return Ok(parent_id);
            }
            Err(e) => return Err(e),
        };
        for name in &listing.unrepresentable {
            self.report.unrepresentable.push(match dir.is_root() {
                true => name.clone(),
                false => format!("{dir}/{name}"),
            });
        }
        let mut out = Tree::default();
        let mut seen = HashSet::new();
        // A tracked path that is now a symlink (or socket, device…) is never
        // followed, and is not a deletion either: keep the tracked entry.
        for name in &listing.special {
            if let Some(pe) = parent.and_then(|t| t.get(name)) {
                let path = dir.join(name);
                let tier = self.opts.policy.classify(&path, pe.kind == EntryKind::Dir).tier;
                if matches!(tier, Tier::Ignored | Tier::Isolated) {
                    continue; // no longer tracked by policy anyway
                }
                seen.insert(name.clone());
                self.report.shadowed.push(path);
                out.insert(pe.clone());
            }
        }
        for child in listing.entries {
            // `.veil` is reserved at every depth (trees containing it are
            // refused on decode), like Git's `.git` in nested repositories.
            if crate::object::is_reserved_name(&child.name) {
                continue;
            }
            // Crash debris of an interrupted atomic write, never content.
            if child.kind == NodeKind::File && is_temp_name(&child.name) {
                self.report.ignored += 1;
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
        self.report_collisions(dir, &out, parent);
        Ok(Some(self.store.put_tree(&out)?))
    }

    /// Rewrite the names of a listing from a name-folding backend to the
    /// spelling to record: the parent's entry when the name is an alias of
    /// it (unless an entry with that exact name is listed too), otherwise
    /// [`NameFolding::record`] (NFC on macOS). A substituted name is only
    /// used if the backend really resolves it, so a wrongly reported
    /// folding can never make a file look deleted.
    fn canonical_names(&self, dir: &VPath, mut listing: DirListing, parent: Option<&Tree>) -> DirListing {
        let folding = self.folding;
        let tracked: HashMap<std::borrow::Cow<'_, str>, &str> = parent
            .map(|t| t.entries.iter().map(|e| (folding.key(&e.name), e.name.as_str())).collect())
            .unwrap_or_default();
        let listed: HashSet<String> = listing
            .entries
            .iter()
            .map(|e| e.name.clone())
            .chain(listing.special.iter().cloned())
            .collect();
        let mut used = HashSet::new();
        // `verify`: special entries (symlinks…) report no metadata, so they
        // are only matched to a tracked alias, never checked.
        let mut canonical = |name: &str, verify: bool| -> String {
            if parent.is_some_and(|t| t.get(name).is_some()) {
                used.insert(name.to_string());
                return name.to_string();
            }
            let want = match tracked.get(&folding.key(name)) {
                Some(&p) if !listed.contains(p) => p.to_string(),
                _ => folding.record(name).into_owned(),
            };
            if want == name
                || listed.contains(&want)
                || used.contains(&want)
                || (verify && !matches!(self.fs.metadata(&dir.join(&want)), Ok(Some(_))))
            {
                used.insert(name.to_string());
                return name.to_string();
            }
            used.insert(want.clone());
            want
        };
        for e in &mut listing.entries {
            e.name = canonical(&e.name, true);
        }
        for n in &mut listing.special {
            *n = canonical(n, false);
        }
        listing.entries.sort_by(|a, b| a.name.cmp(&b.name));
        listing.special.sort();
        listing
    }

    /// Record pairs of entries of `out` that a macOS volume would store as
    /// one, when at least one of them is new relative to `parent`.
    fn report_collisions(&mut self, dir: &VPath, out: &Tree, parent: Option<&Tree>) {
        if out.entries.len() < 2 || out.entries.iter().all(|e| e.name.is_ascii() && !e.name.bytes().any(|b| b.is_ascii_uppercase())) {
            return;
        }
        let mut first: HashMap<std::borrow::Cow<'_, str>, &str> = HashMap::new();
        for e in &out.entries {
            if let Some(other) = first.insert(NameFolding::MACOS.key(&e.name), &e.name) {
                let old = |n: &str| parent.is_some_and(|t| t.get(n).is_some());
                if !(old(other) && old(&e.name)) {
                    self.report.name_collisions.push((dir.join(other), dir.join(&e.name)));
                }
            }
        }
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

    /// A working-copy file could not be stat'ed or read. Vanished meanwhile:
    /// a deletion. Unreadable (e.g. permission denied): a tracked file keeps
    /// its previous entry, an untracked one stays out; both are reported.
    /// Errors of the store are never swallowed here.
    fn unreadable(&mut self, path: &VPath, e: VeilError, parent_file: Option<&TreeEntry>) -> Result<Option<TreeEntry>> {
        match e {
            e if e.is_not_found() => Ok(None),
            VeilError::Io { source, .. } => {
                self.report.unreadable.push((path.clone(), source.to_string()));
                Ok(parent_file.cloned())
            }
            e => Err(e),
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

        let meta = match self.fs.metadata(path) {
            Ok(m) => m,
            Err(e) => return self.unreadable(path, e, parent_file),
        };
        let executable = meta.as_ref().is_some_and(|m| m.executable);
        // Embargoed entries depend on the parent entry and on embargo state,
        // not only on content: always take the slow path for them.
        let parent_embargoed = parent_file.is_some_and(|pe| matches!(pe.visibility, Visibility::Embargoed { .. }));
        // With injected secrets every changed file must be read and checked.
        let cacheable = !parent_embargoed && self.opts.injected.is_none();
        if let (Some(m), true) = (&meta, cacheable) {
            if let Some(e) = self.cached_entry(path, name, m, &desired, class.allow_secrets, parent_file)? {
                return Ok(Some(e));
            }
        }

        let data = match self.fs.read(path) {
            Ok(d) => d,
            Err(e) => return self.unreadable(path, e, parent_file),
        };
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

        // Content the engine injected (e.g. `.env` in a sandbox) never
        // enters history under another name, whatever the tier. Unchanged
        // tracked content predates the injection and is left alone.
        if let Some(inj) = self.opts.injected {
            let unchanged = match parent_file {
                Some(pe) => pe.executable == executable && self.store.matches_encoding(&pe.id, &data)?,
                None => false,
            };
            if !unchanged {
                if let Some(f) = inj.find(&data) {
                    return self.quarantine(path, vec![f], parent_file);
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
                if !self.policy_changed && !self.rescan && pe.id == content && pe.visibility.is_public() && pe.executable == executable {
                    self.learn(path, meta.as_ref(), content, false, None, parent_embargoed);
                    return Ok(Some(pe.clone())); // unchanged; scanned before
                }
            }
            if !class.allow_secrets {
                let findings = secrets::scan(&data);
                if !findings.is_empty() {
                    return self.quarantine(path, findings, parent_file);
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

    /// Hold the edit back, but do not record a deletion: keep the previously
    /// tracked version if it is itself safe.
    fn quarantine(&mut self, path: &VPath, findings: Vec<Finding>, parent_file: Option<&TreeEntry>) -> Result<Option<TreeEntry>> {
        self.report.quarantined.push((path.clone(), findings));
        if let Some(pe) = parent_file {
            if self.previous_is_safe(pe)? {
                self.report.quarantine_kept.push(path.clone());
                return Ok(Some(pe.clone()));
            }
        }
        Ok(None)
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
                    Some(pe) if !self.policy_changed && !self.rescan => Some(pe.clone()),
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
