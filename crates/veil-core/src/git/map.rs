//! The commit ↔ snapshot mapping and the conversion caches, stored under
//! `.veil/git/` on the repository's backend.
//!
//! ```text
//! .veil/git/map     veil-git-map 2
//!                   c <commit> <snapshot> <veiled>         every pair ever made
//!                   s <snapshot> <commit> <origin> <pending>
//!                                                          the commit that currently
//!                                                          represents the snapshot
//!                   t <git tag ref value> <atag>           a release tag (format 5): the
//!                                                          Git tag object (or, for a
//!                                                          lightweight tag, the commit)
//!                                                          and the annotated tag object
//! .veil/git/cache   veil-git-cache 1                       (safe to delete)
//!                   p <veil tree> <public veil tree | ->   public projection
//!                   t <public veil tree> <git tree>        conversion
//!                   b <veil file object> <git blob>
//!                   g <git blob> <veil blob id>            content identity (import hints)
//! ```
//!
//! `origin` is `import` (the commit came from Git: it is the truth for that
//! snapshot), `export` (computed from the snapshot) or `publish` (written
//! after an embargo release on top of an earlier one). `veiled` (and the
//! current commit's `pending`, the same set) lists the embargoes that were
//! unreleased in the view the commit shows (`-` if none): an exported
//! commit pinned while they held, or a Git commit made on top of such a
//! view. Only such commits are ever recomputed, when one of them is
//! released, and a Git commit made on top of one is imported against that
//! older view (what its author saw), so it never reads as a revert.
//!
//! Everything here can be recomputed: export is deterministic, an exported
//! commit found in Git without a mapping is recognised by exporting its
//! snapshot again, and importing the same commit yields the same snapshot.
//! A mapped object that has gone missing (Veil gc, Git gc) is simply
//! treated as unmapped. Format 1 (no `veiled` field) is still read.

use std::collections::{BTreeSet, HashMap};

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    vfs::StorageBackend,
    vpath::VPath,
};

pub type GitOid = gix::ObjectId;

const MAP_HEADER: &str = "veil-git-map 2";
const MAP_HEADER_V1: &str = "veil-git-map 1";
/// Bump when the projection or conversion rules change: cached results
/// computed by older rules are then discarded.
const CACHE_HEADER: &str = "veil-git-cache 1";

pub(crate) fn map_path() -> VPath {
    VPath::new(".veil/git/map").unwrap()
}

fn cache_path() -> VPath {
    VPath::new(".veil/git/cache").unwrap()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Imported from Git: the commit is the truth for this snapshot.
    Imported,
    /// Computed from the snapshot by export.
    Exported,
    /// Written on top of an earlier export once an embargo was released.
    Published,
}

impl Origin {
    fn as_str(self) -> &'static str {
        match self {
            Origin::Imported => "import",
            Origin::Exported => "export",
            Origin::Published => "publish",
        }
    }

    fn parse(s: &str) -> Option<Origin> {
        Some(match s {
            "import" => Origin::Imported,
            "export" => Origin::Exported,
            "publish" => Origin::Published,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Current {
    pub commit: GitOid,
    pub origin: Origin,
    /// Unreleased embargoes that shaped this commit (export only).
    pub pending: BTreeSet<String>,
}

#[derive(Debug, Default)]
pub struct GitMap {
    /// Every commit we imported or wrote → its snapshot.
    pub commits: HashMap<GitOid, ObjectId>,
    /// Snapshot → the commit that currently represents it in Git.
    pub current: HashMap<ObjectId, Current>,
    /// Commit → the embargoes unreleased in the view it shows (only
    /// non-empty sets are kept).
    pub veiled: HashMap<GitOid, BTreeSet<String>>,
    /// Release tags (format 5): what `refs/tags/<name>` holds in Git (a
    /// tag object, or the commit of a lightweight tag) → the atag it was
    /// imported as or exported from. Recomputable: export is deterministic
    /// and import recognises Veil's own tag objects.
    pub tags: HashMap<GitOid, ObjectId>,
    dirty: bool,
}

fn parse_oid(s: &str) -> Option<GitOid> {
    GitOid::from_hex(s.as_bytes()).ok()
}

fn parse_id(s: &str) -> Option<ObjectId> {
    ObjectId::from_hex(s).ok()
}

fn parse_set(s: &str) -> BTreeSet<String> {
    match s {
        "-" => BTreeSet::new(),
        p => p.split(',').map(str::to_string).collect(),
    }
}

fn format_set(s: &BTreeSet<String>) -> String {
    if s.is_empty() {
        "-".to_string()
    } else {
        s.iter().cloned().collect::<Vec<_>>().join(",")
    }
}

impl GitMap {
    pub fn load(backend: &dyn StorageBackend) -> Result<GitMap> {
        let mut map = GitMap::default();
        let Some(raw) = backend.read_opt(&map_path())? else {
            return Ok(map);
        };
        let text = String::from_utf8_lossy(&raw);
        let corrupt = |n: usize| VeilError::Corrupt(".veil/git/map".into(), format!("unreadable line {n}"));
        let mut lines = text.lines().enumerate();
        let v1 = match lines.next() {
            Some((_, MAP_HEADER)) => false,
            Some((_, MAP_HEADER_V1)) => true,
            _ => return Err(VeilError::Corrupt(".veil/git/map".into(), "unknown format".into())),
        };
        for (n, line) in lines {
            let f: Vec<&str> = line.split(' ').collect();
            match f.as_slice() {
                ["c", c, s] if v1 => {
                    let (c, s) = (parse_oid(c).ok_or_else(|| corrupt(n + 1))?, parse_id(s).ok_or_else(|| corrupt(n + 1))?);
                    map.commits.insert(c, s);
                }
                ["c", c, s, veiled] if !v1 => {
                    let (c, s) = (parse_oid(c).ok_or_else(|| corrupt(n + 1))?, parse_id(s).ok_or_else(|| corrupt(n + 1))?);
                    map.commits.insert(c, s);
                    let veiled = parse_set(veiled);
                    if !veiled.is_empty() {
                        map.veiled.insert(c, veiled);
                    }
                }
                ["t", g, a] if !v1 => {
                    let g = parse_oid(g).ok_or_else(|| corrupt(n + 1))?;
                    let a = parse_id(a).ok_or_else(|| corrupt(n + 1))?;
                    map.tags.insert(g, a);
                }
                ["s", s, c, origin, pending] => {
                    let s = parse_id(s).ok_or_else(|| corrupt(n + 1))?;
                    let commit = parse_oid(c).ok_or_else(|| corrupt(n + 1))?;
                    let origin = Origin::parse(origin).ok_or_else(|| corrupt(n + 1))?;
                    let pending = parse_set(pending);
                    map.current.insert(s, Current { commit, origin, pending });
                }
                [""] => {}
                _ => return Err(corrupt(n + 1)),
            }
        }
        // Format 1 kept the set for current commits only.
        for cur in map.current.values() {
            if !cur.pending.is_empty() {
                map.veiled.entry(cur.commit).or_insert_with(|| cur.pending.clone());
            }
        }
        map.dirty = v1;
        Ok(map)
    }

    pub fn save(&mut self, backend: &dyn StorageBackend) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let mut out = String::with_capacity(64 + 140 * (self.commits.len() + self.current.len()));
        out.push_str(MAP_HEADER);
        out.push('\n');
        let mut commits: Vec<_> = self.commits.iter().collect();
        commits.sort();
        let none = BTreeSet::new();
        for (c, s) in commits {
            let veiled = format_set(self.veiled.get(c).unwrap_or(&none));
            out.push_str(&format!("c {c} {} {veiled}\n", s.hex()));
        }
        let mut current: Vec<_> = self.current.iter().collect();
        current.sort_by_key(|(s, _)| **s);
        for (s, cur) in current {
            let pending = format_set(&cur.pending);
            out.push_str(&format!("s {} {} {} {pending}\n", s.hex(), cur.commit, cur.origin.as_str()));
        }
        let mut tags: Vec<_> = self.tags.iter().collect();
        tags.sort();
        for (g, a) in tags {
            out.push_str(&format!("t {g} {}\n", a.hex()));
        }
        backend.write(&map_path(), out.as_bytes())?;
        self.dirty = false;
        Ok(())
    }

    /// Make `current` the commit representing `snapshot`.
    pub fn record(&mut self, snapshot: ObjectId, current: Current) {
        self.record_commit(current.commit, snapshot, current.pending.clone());
        self.current.insert(snapshot, current);
    }

    /// Record that `commit` corresponds to `snapshot` and shows a view in
    /// which the embargoes `veiled` were unreleased.
    pub fn record_commit(&mut self, commit: GitOid, snapshot: ObjectId, veiled: BTreeSet<String>) {
        self.commits.insert(commit, snapshot);
        if veiled.is_empty() {
            self.veiled.remove(&commit);
        } else {
            self.veiled.insert(commit, veiled);
        }
        self.dirty = true;
    }

    /// Record that `commit` (imported) corresponds to `snapshot`. The
    /// snapshot's current commit is set only if it has none.
    pub fn record_import(&mut self, commit: GitOid, snapshot: ObjectId, veiled: BTreeSet<String>) {
        self.record_commit(commit, snapshot, veiled.clone());
        self.current.entry(snapshot).or_insert(Current {
            commit,
            origin: Origin::Imported,
            pending: veiled,
        });
    }

    /// Record a commit found in Git to be Veil's own (exported or
    /// published by another replica, or before the mapping was lost). It
    /// becomes the snapshot's current commit if the snapshot has none, or
    /// if it is a publication on top of the current one (`replaces`).
    pub fn record_found(
        &mut self,
        commit: GitOid,
        snapshot: ObjectId,
        origin: Origin,
        veiled: BTreeSet<String>,
        replaces: Option<GitOid>,
    ) {
        self.record_commit(commit, snapshot, veiled.clone());
        let keep = match self.current.get(&snapshot) {
            None => false,
            Some(cur) => origin != Origin::Published || Some(cur.commit) != replaces,
        };
        if !keep {
            self.current.insert(
                snapshot,
                Current {
                    commit,
                    origin,
                    pending: veiled,
                },
            );
        }
    }

    /// Record that Git ref value `git` (a tag object, or a lightweight
    /// tag's commit) is the release tag `atag`.
    pub fn record_tag(&mut self, git: GitOid, atag: ObjectId) {
        if self.tags.insert(git, atag) != Some(atag) {
            self.dirty = true;
        }
    }

    /// The embargoes unreleased in the view `commit` shows.
    pub fn veiled(&self, commit: &GitOid) -> BTreeSet<String> {
        self.veiled.get(commit).cloned().unwrap_or_default()
    }

    pub fn forget_current(&mut self, snapshot: &ObjectId) {
        if self.current.remove(snapshot).is_some() {
            self.dirty = true;
        }
    }

    pub fn forget_commit(&mut self, commit: &GitOid) {
        self.veiled.remove(commit);
        if self.commits.remove(commit).is_some() {
            self.dirty = true;
        }
    }
}

/// Memoised conversions (see the module docs). Only results that depend on
/// nothing but object content are kept: a projection shaped by an
/// unreleased embargo, or by an object missing from this replica, is
/// recomputed every time.
#[derive(Debug, Default)]
pub struct Cache {
    /// Veil tree → its public projection (`None`: nothing public).
    pub projected: HashMap<ObjectId, Option<ObjectId>>,
    /// Public Veil tree → Git tree.
    pub trees: HashMap<ObjectId, GitOid>,
    /// Veil file object (plain or released-sealed) → Git blob.
    pub blobs: HashMap<ObjectId, GitOid>,
    /// Git blob → id of the plain Veil blob with the same content.
    pub contents: HashMap<GitOid, ObjectId>,
    dirty: bool,
}

impl Cache {
    pub fn load(backend: &dyn StorageBackend) -> Cache {
        let mut c = Cache::default();
        let Ok(Some(raw)) = backend.read_opt(&cache_path()) else {
            return c;
        };
        let text = String::from_utf8_lossy(&raw);
        let mut lines = text.lines();
        if lines.next() != Some(CACHE_HEADER) {
            return c;
        }
        for line in lines {
            let f: Vec<&str> = line.split(' ').collect();
            // A damaged cache is only a slower run: skip what does not parse.
            match f.as_slice() {
                ["p", v, "-"] => {
                    if let Some(v) = parse_id(v) {
                        c.projected.insert(v, None);
                    }
                }
                ["p", v, p] => {
                    if let (Some(v), Some(p)) = (parse_id(v), parse_id(p)) {
                        c.projected.insert(v, Some(p));
                    }
                }
                ["t", v, g] => {
                    if let (Some(v), Some(g)) = (parse_id(v), parse_oid(g)) {
                        c.trees.insert(v, g);
                    }
                }
                ["b", v, g] => {
                    if let (Some(v), Some(g)) = (parse_id(v), parse_oid(g)) {
                        c.blobs.insert(v, g);
                    }
                }
                ["g", g, v] => {
                    if let (Some(g), Some(v)) = (parse_oid(g), parse_id(v)) {
                        c.contents.insert(g, v);
                    }
                }
                _ => {}
            }
        }
        c
    }

    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Best effort: the cache only accelerates.
    pub fn save(&mut self, backend: &dyn StorageBackend) {
        if !self.dirty {
            return;
        }
        let mut out = String::new();
        out.push_str(CACHE_HEADER);
        out.push('\n');
        let mut lines: Vec<String> = Vec::new();
        for (v, p) in &self.projected {
            lines.push(match p {
                Some(p) => format!("p {} {}", v.hex(), p.hex()),
                None => format!("p {} -", v.hex()),
            });
        }
        for (v, g) in &self.trees {
            lines.push(format!("t {} {g}", v.hex()));
        }
        for (v, g) in &self.blobs {
            lines.push(format!("b {} {g}", v.hex()));
        }
        for (g, v) in &self.contents {
            lines.push(format!("g {g} {}", v.hex()));
        }
        lines.sort();
        for l in lines {
            out.push_str(&l);
            out.push('\n');
        }
        if backend.write(&cache_path(), out.as_bytes()).is_ok() {
            self.dirty = false;
        }
    }
}
