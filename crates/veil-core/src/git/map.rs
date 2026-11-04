//! The commit ↔ snapshot mapping and the conversion caches, stored under
//! `.veil/git/` on the repository's backend.
//!
//! ```text
//! .veil/git/map     veil-git-map 1
//!                   c <commit> <snapshot>                  every pair ever made
//!                   s <snapshot> <commit> <origin> <pending>
//!                                                          the commit that currently
//!                                                          represents the snapshot
//! .veil/git/cache   veil-git-cache 1                       (safe to delete)
//!                   p <veil tree> <public veil tree | ->   public projection
//!                   t <public veil tree> <git tree>        conversion
//!                   b <veil file object> <git blob>
//!                   g <git blob> <veil blob id>            content identity (import hints)
//! ```
//!
//! `origin` is `import` (the commit came from Git: it is the truth for that
//! snapshot), `export` (computed from the snapshot) or `publish` (written
//! after an embargo release on top of an earlier export). `pending` lists
//! the unreleased embargoes that shaped an exported commit (`-` if none):
//! only such commits are ever recomputed, when one of them is released.
//!
//! Everything here can be recomputed: export is deterministic and import of
//! the same commit yields the same snapshot id. A mapped object that has
//! gone missing (Veil gc, Git gc) is simply treated as unmapped.

use std::collections::{BTreeSet, HashMap};

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    vfs::StorageBackend,
    vpath::VPath,
};

pub type GitOid = gix::ObjectId;

const MAP_HEADER: &str = "veil-git-map 1";
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
    dirty: bool,
}

fn parse_oid(s: &str) -> Option<GitOid> {
    GitOid::from_hex(s.as_bytes()).ok()
}

fn parse_id(s: &str) -> Option<ObjectId> {
    ObjectId::from_hex(s).ok()
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
        match lines.next() {
            Some((_, MAP_HEADER)) => {}
            _ => return Err(VeilError::Corrupt(".veil/git/map".into(), "unknown format".into())),
        }
        for (n, line) in lines {
            let f: Vec<&str> = line.split(' ').collect();
            match f.as_slice() {
                ["c", c, s] => {
                    let (c, s) = (parse_oid(c).ok_or_else(|| corrupt(n + 1))?, parse_id(s).ok_or_else(|| corrupt(n + 1))?);
                    map.commits.insert(c, s);
                }
                ["s", s, c, origin, pending] => {
                    let s = parse_id(s).ok_or_else(|| corrupt(n + 1))?;
                    let commit = parse_oid(c).ok_or_else(|| corrupt(n + 1))?;
                    let origin = Origin::parse(origin).ok_or_else(|| corrupt(n + 1))?;
                    let pending = match *pending {
                        "-" => BTreeSet::new(),
                        p => p.split(',').map(str::to_string).collect(),
                    };
                    map.current.insert(s, Current { commit, origin, pending });
                }
                [""] => {}
                _ => return Err(corrupt(n + 1)),
            }
        }
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
        for (c, s) in commits {
            out.push_str(&format!("c {c} {}\n", s.hex()));
        }
        let mut current: Vec<_> = self.current.iter().collect();
        current.sort_by_key(|(s, _)| **s);
        for (s, cur) in current {
            let pending = if cur.pending.is_empty() {
                "-".to_string()
            } else {
                cur.pending.iter().cloned().collect::<Vec<_>>().join(",")
            };
            out.push_str(&format!("s {} {} {} {pending}\n", s.hex(), cur.commit, cur.origin.as_str()));
        }
        backend.write(&map_path(), out.as_bytes())?;
        self.dirty = false;
        Ok(())
    }

    pub fn record(&mut self, snapshot: ObjectId, current: Current) {
        self.commits.insert(current.commit, snapshot);
        self.current.insert(snapshot, current);
        self.dirty = true;
    }

    /// Record that `commit` (imported) corresponds to `snapshot`. The
    /// snapshot's current commit is set only if it has none.
    pub fn record_import(&mut self, commit: GitOid, snapshot: ObjectId) {
        self.commits.insert(commit, snapshot);
        self.current.entry(snapshot).or_insert(Current {
            commit,
            origin: Origin::Imported,
            pending: BTreeSet::new(),
        });
        self.dirty = true;
    }

    pub fn forget_current(&mut self, snapshot: &ObjectId) {
        if self.current.remove(snapshot).is_some() {
            self.dirty = true;
        }
    }

    pub fn forget_commit(&mut self, commit: &GitOid) {
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
