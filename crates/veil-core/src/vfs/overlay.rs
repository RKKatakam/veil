use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
};

use super::{DirEntry, MemoryBackend, Metadata, NodeKind, StorageBackend};
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
#[derive(Debug)]
pub struct OverlayBackend {
    lower: Arc<dyn StorageBackend>,
    upper: MemoryBackend,
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
        OverlayBackend {
            lower,
            upper: MemoryBackend::new(),
            whiteouts: RwLock::new(BTreeSet::new()),
        }
    }

    pub fn lower(&self) -> &Arc<dyn StorageBackend> {
        &self.lower
    }

    pub fn changes(&self) -> OverlayChanges {
        OverlayChanges {
            written: self.upper.files(),
            removed: self.whiteouts.read().unwrap().iter().cloned().collect(),
        }
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
    /// view: lower-layer *files* in the way get whited out.
    fn prepare_parents(&self, path: &VPath) -> Result<()> {
        for anc in path.ancestors() {
            if self.upper.metadata(&anc)?.is_some() {
                continue;
            }
            if let Some(m) = self.lower_meta(&anc)? {
                if m.kind == NodeKind::File {
                    self.whiteouts.write().unwrap().insert(anc.clone());
                }
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
        self.prepare_parents(path)?;
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
        self.prepare_parents(path)?;
        if let Some(m) = self.lower_meta(path)? {
            if m.kind == NodeKind::File {
                self.whiteouts.write().unwrap().insert(path.clone());
            }
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
            self.prepare_parents(path)?;
            self.upper.write(path, &data)?;
        }
        self.upper.set_executable(path, executable)
    }

    fn known_id(&self, path: &VPath) -> Option<ObjectId> {
        if self.upper.has_any_under(path) || self.whiteout_under(path) || self.hidden(path) {
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

        // replace a lower file with a directory
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
