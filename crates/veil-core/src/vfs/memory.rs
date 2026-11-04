use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
};

use super::{DirEntry, Metadata, NodeKind, StatClock, StorageBackend};
use crate::{
    error::{Result, VeilError},
    vpath::VPath,
};

#[derive(Debug, Clone)]
enum Node {
    /// `stamp` is the write generation that last touched the file.
    File { data: Arc<Vec<u8>>, executable: bool, stamp: u64 },
    Dir,
    /// A symlink: never followed, never written through.
    Link { target: Arc<Vec<u8>>, stamp: u64 },
}

/// A pure in-memory file tree. Cloning file contents is avoided by sharing
/// `Arc` buffers; [`MemoryBackend::fork`] produces an independent copy in
/// O(n) pointer copies.
///
/// Every file write takes a fresh value from a monotonic generation counter
/// and reports it as `Metadata::mtime`, so stat caches work in memory with
/// no racy window.
#[derive(Debug, Default)]
pub struct MemoryBackend {
    nodes: RwLock<BTreeMap<VPath, Node>>,
    generation: AtomicU64,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Convenience constructor for tests and fixtures.
    pub fn from_files<'a>(files: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> Result<Self> {
        let m = Self::new();
        for (p, d) in files {
            m.write(&VPath::new(p)?, d)?;
        }
        Ok(m)
    }

    /// Independent copy sharing file buffers.
    pub fn fork(&self) -> Self {
        MemoryBackend {
            nodes: RwLock::new(self.nodes.read().unwrap().clone()),
            generation: AtomicU64::new(self.generation.load(Ordering::SeqCst)),
        }
    }

    /// A new, strictly larger write generation.
    fn next_stamp(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// All file paths currently stored.
    pub fn files(&self) -> Vec<VPath> {
        self.nodes
            .read()
            .unwrap()
            .iter()
            .filter(|(_, n)| matches!(n, Node::File { .. }))
            .map(|(p, _)| p.clone())
            .collect()
    }

    /// True if `path` itself or anything below it is stored here.
    pub fn has_any_under(&self, path: &VPath) -> bool {
        let nodes = self.nodes.read().unwrap();
        if path.is_root() {
            return !nodes.is_empty();
        }
        nodes.contains_key(path) || Self::descendants(&nodes, path).next().is_some()
    }

    /// Strict descendants of `path`, in order.
    fn descendants<'a>(
        nodes: &'a BTreeMap<VPath, Node>,
        path: &VPath,
    ) -> impl Iterator<Item = (&'a VPath, &'a Node)> + 'a {
        let prefix = path.child_prefix();
        nodes
            .range(VPath::from_raw(prefix.clone())..)
            .take_while(move |(k, _)| k.as_str().starts_with(&prefix))
    }

    fn ensure_parents(nodes: &mut BTreeMap<VPath, Node>, path: &VPath) -> Result<()> {
        for anc in path.ancestors() {
            match nodes.get(&anc) {
                Some(Node::File { .. }) => {
                    return Err(VeilError::InvalidPath(format!("{anc} is a file, not a directory")))
                }
                Some(Node::Link { .. }) => {
                    return Err(VeilError::InvalidPath(format!("refusing to write below {anc}: it is a symbolic link")))
                }
                Some(Node::Dir) => {}
                None => {
                    nodes.insert(anc, Node::Dir);
                }
            }
        }
        Ok(())
    }

    fn keys_under(nodes: &BTreeMap<VPath, Node>, path: &VPath) -> Vec<VPath> {
        let mut out: Vec<VPath> = Self::descendants(nodes, path).map(|(k, _)| k.clone()).collect();
        if nodes.contains_key(path) {
            out.push(path.clone());
        }
        out
    }
}

impl StorageBackend for MemoryBackend {
    fn kind(&self) -> &'static str {
        "memory"
    }

    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        match self.nodes.read().unwrap().get(path) {
            Some(Node::File { data, .. }) => Ok(data.as_ref().clone()),
            Some(Node::Dir) => Err(VeilError::InvalidPath(format!("{path} is a directory"))),
            // Never followed (as on disk).
            Some(Node::Link { .. }) | None => Err(VeilError::NotFound(path.to_string())),
        }
    }

    fn read_link(&self, path: &VPath) -> Result<Vec<u8>> {
        match self.nodes.read().unwrap().get(path) {
            Some(Node::Link { target, .. }) => Ok(target.as_ref().clone()),
            Some(_) => Err(VeilError::InvalidPath(format!("{path} is not a symlink"))),
            None => Err(VeilError::NotFound(path.to_string())),
        }
    }

    fn write_link(&self, path: &VPath, target: &[u8]) -> Result<()> {
        super::check_link_target(target)?;
        if path.is_root() {
            return Err(VeilError::InvalidPath("cannot write to the root".into()));
        }
        let mut nodes = self.nodes.write().unwrap();
        Self::ensure_parents(&mut nodes, path)?;
        if let Some(Node::Dir) = nodes.get(path) {
            return Err(VeilError::InvalidPath(format!("{path} is a directory")));
        }
        nodes.insert(
            path.clone(),
            Node::Link {
                target: Arc::new(target.to_vec()),
                stamp: self.next_stamp(),
            },
        );
        Ok(())
    }

    fn supports_links(&self) -> bool {
        true
    }

    fn read_range(&self, path: &VPath, offset: u64, len: usize) -> Result<Vec<u8>> {
        match self.nodes.read().unwrap().get(path) {
            Some(Node::File { data, .. }) => super::slice_range(path, data, offset, len).map(<[u8]>::to_vec),
            Some(Node::Dir) => Err(VeilError::InvalidPath(format!("{path} is a directory"))),
            Some(Node::Link { .. }) | None => Err(VeilError::NotFound(path.to_string())),
        }
    }

    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        if path.is_root() {
            return Err(VeilError::InvalidPath("cannot write to the root".into()));
        }
        let mut nodes = self.nodes.write().unwrap();
        Self::ensure_parents(&mut nodes, path)?;
        let executable = match nodes.get(path) {
            Some(Node::Dir) => return Err(VeilError::InvalidPath(format!("{path} is a directory"))),
            Some(Node::File { executable, .. }) => *executable,
            // Replaced (never written through).
            Some(Node::Link { .. }) | None => false,
        };
        nodes.insert(
            path.clone(),
            Node::File {
                data: Arc::new(data.to_vec()),
                executable,
                stamp: self.next_stamp(),
            },
        );
        Ok(())
    }

    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        let mut nodes = self.nodes.write().unwrap();
        if nodes.contains_key(path) {
            return Ok(false);
        }
        Self::ensure_parents(&mut nodes, path)?;
        nodes.insert(
            path.clone(),
            Node::File {
                data: Arc::new(data.to_vec()),
                executable: false,
                stamp: self.next_stamp(),
            },
        );
        Ok(true)
    }

    fn remove_file(&self, path: &VPath) -> Result<()> {
        let mut nodes = self.nodes.write().unwrap();
        if let Some(Node::File { .. } | Node::Link { .. }) = nodes.get(path) {
            nodes.remove(path);
        }
        Ok(())
    }

    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        let mut nodes = self.nodes.write().unwrap();
        for k in Self::keys_under(&nodes, path) {
            nodes.remove(&k);
        }
        Ok(())
    }

    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        if path.is_root() {
            return Ok(());
        }
        let mut nodes = self.nodes.write().unwrap();
        Self::ensure_parents(&mut nodes, path)?;
        match nodes.get(path) {
            Some(Node::File { .. }) => Err(VeilError::InvalidPath(format!("{path} is a file"))),
            Some(Node::Link { .. }) => Err(VeilError::InvalidPath(format!("{path} is a symlink"))),
            Some(Node::Dir) => Ok(()),
            None => {
                nodes.insert(path.clone(), Node::Dir);
                Ok(())
            }
        }
    }

    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        let nodes = self.nodes.read().unwrap();
        if !path.is_root() {
            match nodes.get(path) {
                Some(Node::Dir) => {}
                Some(Node::File { .. } | Node::Link { .. }) => {
                    return Err(VeilError::InvalidPath(format!("{path} is not a directory")))
                }
                None => return Err(VeilError::NotFound(path.to_string())),
            }
        }
        let prefix_len = path.child_prefix().len();
        let mut out = Vec::new();
        for (k, n) in Self::descendants(&nodes, path) {
            let rest = &k.as_str()[prefix_len..];
            if rest.is_empty() || rest.contains('/') {
                continue;
            }
            out.push(DirEntry {
                name: rest.to_string(),
                kind: match n {
                    Node::File { .. } => NodeKind::File,
                    Node::Dir => NodeKind::Dir,
                    Node::Link { .. } => NodeKind::Symlink,
                },
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        if path.is_root() {
            return Ok(Some(Metadata::unstamped(NodeKind::Dir, 0, false)));
        }
        Ok(self.nodes.read().unwrap().get(path).map(|n| match n {
            Node::File {
                data,
                executable,
                stamp,
            } => Metadata {
                kind: NodeKind::File,
                len: data.len() as u64,
                executable: *executable,
                mtime: i64::try_from(*stamp).ok(),
                ctime: None,
                inode: None,
            },
            Node::Dir => Metadata::unstamped(NodeKind::Dir, 0, false),
            Node::Link { target, stamp } => Metadata {
                kind: NodeKind::Symlink,
                len: target.len() as u64,
                executable: false,
                mtime: i64::try_from(*stamp).ok(),
                ctime: None,
                inode: None,
            },
        }))
    }

    fn stat_clock(&self) -> Option<StatClock> {
        Some(StatClock {
            now: i64::try_from(self.generation.load(Ordering::SeqCst)).ok()?,
            exact: true,
        })
    }

    fn set_executable(&self, path: &VPath, exec: bool) -> Result<()> {
        match self.nodes.write().unwrap().get_mut(path) {
            Some(Node::File { executable, stamp, .. }) => {
                if *executable != exec {
                    *executable = exec;
                    *stamp = self.next_stamp();
                }
                Ok(())
            }
            Some(Node::Dir) => Err(VeilError::InvalidPath(format!("{path} is a directory"))),
            Some(Node::Link { .. }) => Err(VeilError::InvalidPath(format!("{path} is a symlink"))),
            None => Err(VeilError::NotFound(path.to_string())),
        }
    }

    fn special_at(&self, path: &VPath) -> Result<Option<&'static str>> {
        Ok(matches!(self.nodes.read().unwrap().get(path), Some(Node::Link { .. })).then_some("a symlink"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> VPath {
        VPath::new(s).unwrap()
    }

    #[test]
    fn basic_tree() {
        let m = MemoryBackend::new();
        m.write(&p("a/b/c.txt"), b"hi").unwrap();
        m.write(&p("a/d.txt"), b"yo").unwrap();
        m.write(&p("a-b"), b"x").unwrap();
        m.write(&p("a0"), b"x").unwrap();
        let names: Vec<_> = m.list_dir(&p("a")).unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(names, vec!["b", "d.txt"]);
        let root: Vec<_> = m.list_dir(&VPath::root()).unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(root, vec!["a", "a-b", "a0"]);
        m.remove_dir_all(&p("a")).unwrap();
        assert!(!m.exists(&p("a/b/c.txt")).unwrap());
        assert!(m.exists(&p("a-b")).unwrap());
        assert!(m.write(&p("a0/x"), b"").is_err());
    }
}
