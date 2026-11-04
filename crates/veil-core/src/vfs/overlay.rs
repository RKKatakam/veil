use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
};

use super::{walk_files, DirEntry, MemoryBackend, Metadata, NodeKind, StorageBackend};
use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    vpath::VPath,
};

/// Copy-on-write layer over an immutable lower backend.
///
/// Reads fall through to `lower` unless the path was written (lives in the
/// in-memory `upper`) or deleted (recorded as a whiteout). The lower layer is
/// never modified, so many overlays can share one base snapshot — this is how
/// Veil spins up agent workspaces in microseconds without copying files.
///
/// The upper layer is a [`MemoryBackend`] by default; [`OverlayBackend::with_upper`]
/// takes any backend instead (a `vl ws mount` keeps its upper layer on disk,
/// so edits survive a crash of the mount).
#[derive(Debug)]
pub struct OverlayBackend {
    lower: Arc<dyn StorageBackend>,
    upper: Arc<dyn StorageBackend>,
    whiteouts: RwLock<BTreeSet<VPath>>,
}

/// Summary of what an overlay changed relative to its lower layer.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OverlayChanges {
    pub written: Vec<VPath>,
    pub removed: Vec<VPath>,
}

impl OverlayBackend {
    pub fn new(lower: Arc<dyn StorageBackend>) -> Self {
        Self::with_upper(lower, Arc::new(MemoryBackend::new()), [])
    }

    /// An overlay whose upper layer is `upper` (which must not be written
    /// by anyone else meanwhile) and whose lower layer is already hidden at
    /// `whiteouts`: reopening an overlay that was persisted.
    pub fn with_upper(
        lower: Arc<dyn StorageBackend>,
        upper: Arc<dyn StorageBackend>,
        whiteouts: impl IntoIterator<Item = VPath>,
    ) -> Self {
        OverlayBackend {
            lower,
            upper,
            whiteouts: RwLock::new(whiteouts.into_iter().collect()),
        }
    }

    pub fn lower(&self) -> &Arc<dyn StorageBackend> {
        &self.lower
    }

    /// The upper (written) layer.
    pub fn upper(&self) -> &Arc<dyn StorageBackend> {
        &self.upper
    }

    /// The paths hidden from the lower layer (each hides its subtree).
    pub fn whiteouts(&self) -> Vec<VPath> {
        self.whiteouts.read().unwrap().iter().cloned().collect()
    }

    /// Is `path` hidden from the lower layer, by a whiteout on it or on
    /// one of its ancestors?
    pub fn is_whited_out(&self, path: &VPath) -> bool {
        self.hidden(path)
    }

    /// Stop hiding the lower layer at `path` (only that whiteout; one on an
    /// ancestor still hides it).
    pub fn remove_whiteout(&self, path: &VPath) -> bool {
        self.whiteouts.write().unwrap().remove(path)
    }

    pub fn changes(&self) -> OverlayChanges {
        OverlayChanges {
            written: walk_files(&*self.upper, &VPath::root(), &|_| false).unwrap_or_default(),
            removed: self.whiteouts.read().unwrap().iter().cloned().collect(),
        }
    }

    /// Does the upper layer hold `path` or anything below it?
    fn upper_has_any_under(&self, path: &VPath) -> bool {
        if path.is_root() {
            return self.upper.list_dir(path).is_ok_and(|l| !l.is_empty());
        }
        self.upper.metadata(path).is_ok_and(|m| m.is_some())
    }

    /// Is `path` hidden from the lower layer by a whiteout on it or an ancestor?
    fn hidden(&self, path: &VPath) -> bool {
        let w = self.whiteouts.read().unwrap();
        if w.is_empty() {
            return false;
        }
        w.contains(path) || path.ancestors().iter().any(|a| w.contains(a))
    }

    fn whiteout_under(&self, path: &VPath) -> bool {
        let w = self.whiteouts.read().unwrap();
        if path.is_root() {
            return !w.is_empty();
        }
        let prefix = path.child_prefix();
        w.contains(path)
            || w
                .range(VPath::from_raw(prefix.clone())..)
                .next()
                .is_some_and(|k| k.as_str().starts_with(&prefix))
    }

    fn lower_meta(&self, path: &VPath) -> Result<Option<Metadata>> {
        if self.hidden(path) {
            return Ok(None);
        }
        self.lower.metadata(path)
    }

    /// Make sure every ancestor of `path` can be a directory in the merged
    /// view. A *file* in the way is an error, exactly as on every other
    /// backend: silently whiting it out would delete it from the snapshot
    /// (e.g. an agent's `mkdir -p a` where `a` is a file).
    fn check_parents(&self, path: &VPath) -> Result<()> {
        for anc in path.ancestors() {
            let kind = match self.upper.metadata(&anc)? {
                Some(m) => Some(m.kind),
                None => self.lower_meta(&anc)?.map(|m| m.kind),
            };
            if kind == Some(NodeKind::File) {
                return Err(VeilError::InvalidPath(format!("{anc} is a file, not a directory")));
            }
        }
        Ok(())
    }
}

impl StorageBackend for OverlayBackend {
    fn kind(&self) -> &'static str {
        "overlay"
    }

    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        if let Some(m) = self.upper.metadata(path)? {
            if m.kind == NodeKind::File {
                return self.upper.read(path);
            }
        }
        if self.hidden(path) {
            return Err(VeilError::NotFound(path.to_string()));
        }
        self.lower.read(path)
    }

    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        if self.upper.metadata(path)?.is_some_and(|m| m.kind == NodeKind::Dir) && !path.is_root() {
            return Err(VeilError::InvalidPath(format!("{path} is a directory")));
        }
        let lower = self.lower_meta(path)?;
        if lower.as_ref().is_some_and(|m| m.kind == NodeKind::Dir) {
            return Err(VeilError::InvalidPath(format!("{path} is a directory")));
        }
        self.check_parents(path)?;
        let existed_upper = self.upper.metadata(path)?.is_some();
        self.upper.write(path, data)?;
        // Preserve the executable bit of a lower-layer file being replaced.
        if !existed_upper {
            if let Some(m) = lower {
                if m.executable {
                    self.upper.set_executable(path, true)?;
                }
            }
        }
        Ok(())
    }

    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        if self.metadata(path)?.is_some() {
            return Ok(false);
        }
        self.write(path, data)?;
        Ok(true)
    }

    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.upper.remove_file(path)?;
        if self.lower_meta(path)?.is_some() {
            self.whiteouts.write().unwrap().insert(path.clone());
        }
        Ok(())
    }

    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        self.upper.remove_dir_all(path)?;
        if self.lower_meta(path)?.is_some() {
            self.whiteouts.write().unwrap().insert(path.clone());
        }
        Ok(())
    }

    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        if path.is_root() {
            return Ok(());
        }
        self.check_parents(path)?;
        if self.upper.metadata(path)?.is_none() && self.lower_meta(path)?.is_some_and(|m| m.kind == NodeKind::File) {
            return Err(VeilError::InvalidPath(format!("{path} is a file")));
        }
        self.upper.create_dir_all(path)
    }

    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        match self.metadata(path)? {
            None => return Err(VeilError::NotFound(path.to_string())),
            Some(m) if m.kind == NodeKind::File => {
                return Err(VeilError::InvalidPath(format!("{path} is not a directory")))
            }
            _ => {}
        }
        let mut merged: BTreeMap<String, NodeKind> = BTreeMap::new();
        if self.upper.metadata(path)?.is_some_and(|m| m.kind == NodeKind::Dir) {
            for e in self.upper.list_dir(path)? {
                merged.insert(e.name, e.kind);
            }
        }
        if self.lower_meta(path)?.is_some_and(|m| m.kind == NodeKind::Dir) {
            let w = self.whiteouts.read().unwrap();
            for e in self.lower.list_dir(path)? {
                if !w.contains(&path.join(&e.name)) {
                    merged.entry(e.name).or_insert(e.kind);
                }
            }
        }
        Ok(merged.into_iter().map(|(name, kind)| DirEntry { name, kind }).collect())
    }

    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        let m = if path.is_root() {
            self.upper.metadata(path)?
        } else {
            match self.upper.metadata(path)? {
                Some(m) => Some(m),
                None => self.lower_meta(path)?,
            }
        };
        // Upper and lower stamps come from unrelated clocks, so the merged
        // view reports none (and `stat_clock` stays `None`): overlays rely on
        // `known_id` hints instead of a stat cache.
        Ok(m.map(|m| Metadata::unstamped(m.kind, m.len, m.executable)))
    }

    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()> {
        if self.upper.metadata(path)?.is_none() {
            // copy up
            let data = self.read(path)?;
            self.check_parents(path)?;
            self.upper.write(path, &data)?;
        }
        self.upper.set_executable(path, executable)
    }

    fn known_id(&self, path: &VPath) -> Option<ObjectId> {
        if self.upper_has_any_under(path) || self.whiteout_under(path) || self.hidden(path) {
            return None;
        }
        self.lower.known_id(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> VPath {
        VPath::new(s).unwrap()
    }

    #[test]
    fn copy_on_write() {
        let lower = Arc::new(
            MemoryBackend::from_files([("a/x", &b"1"[..]), ("a/y", b"2"), ("b", b"3")]).unwrap(),
        );
        let o = OverlayBackend::new(lower.clone());
        o.write(&p("a/x"), b"changed").unwrap();
        o.remove_file(&p("a/y")).unwrap();
        o.write(&p("c/new"), b"4").unwrap();
        assert_eq!(o.read(&p("a/x")).unwrap(), b"changed");
        assert!(o.read(&p("a/y")).is_err());
        assert_eq!(lower.read(&p("a/y")).unwrap(), b"2", "lower untouched");
        let root: Vec<_> = o.list_dir(&VPath::root()).unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(root, vec!["a", "b", "c"]);
        let a: Vec<_> = o.list_dir(&p("a")).unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(a, vec!["x"]);

        // a lower file is never silently replaced by a directory (as on
        // every other backend); remove it first to make the swap explicit
        assert!(o.write(&p("b/inner"), b"5").is_err());
        assert!(o.create_dir_all(&p("b")).is_err());
        assert!(o.create_dir_all(&p("b/inner")).is_err());
        assert_eq!(o.read(&p("b")).unwrap(), b"3", "the file survives");
        o.remove_file(&p("b")).unwrap();
        o.write(&p("b/inner"), b"5").unwrap();
        assert_eq!(o.metadata(&p("b")).unwrap().unwrap().kind, NodeKind::Dir);
        assert_eq!(o.read(&p("b/inner")).unwrap(), b"5");

        // whiteout a dir then recreate a file inside it: old siblings stay hidden
        o.remove_dir_all(&p("a")).unwrap();
        o.write(&p("a/z"), b"6").unwrap();
        let a: Vec<_> = o.list_dir(&p("a")).unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(a, vec!["z"]);
    }
}
