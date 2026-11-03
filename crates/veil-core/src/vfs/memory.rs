use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use super::{DirEntry, Metadata, NodeKind, StorageBackend};
use crate::{
    error::{Result, VeilError},
    vpath::VPath,
};

#[derive(Debug, Clone)]
enum Node {
    File { data: Arc<Vec<u8>>, executable: bool },
    Dir,
}

/// A pure in-memory file tree. Cloning file contents is avoided by sharing
/// `Arc` buffers; [`MemoryBackend::fork`] produces an independent copy in
/// O(n) pointer copies.
#[derive(Debug, Default)]
pub struct MemoryBackend {
    nodes: RwLock<BTreeMap<VPath, Node>>,
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
        }
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
            None => Err(VeilError::NotFound(path.to_string())),
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
            None => false,
        };
        nodes.insert(
            path.clone(),
            Node::File {
                data: Arc::new(data.to_vec()),
                executable,
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
            },
        );
        Ok(true)
    }

    fn remove_file(&self, path: &VPath) -> Result<()> {
        let mut nodes = self.nodes.write().unwrap();
        if let Some(Node::File { .. }) = nodes.get(path) {
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
                Some(Node::File { .. }) => {
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
                },
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        if path.is_root() {
            return Ok(Some(Metadata {
                kind: NodeKind::Dir,
                len: 0,
                executable: false,
            }));
        }
        Ok(self.nodes.read().unwrap().get(path).map(|n| match n {
            Node::File { data, executable } => Metadata {
                kind: NodeKind::File,
                len: data.len() as u64,
                executable: *executable,
            },
            Node::Dir => Metadata {
                kind: NodeKind::Dir,
                len: 0,
                executable: false,
            },
        }))
    }

    fn set_executable(&self, path: &VPath, exec: bool) -> Result<()> {
        match self.nodes.write().unwrap().get_mut(path) {
            Some(Node::File { executable, .. }) => {
                *executable = exec;
                Ok(())
            }
            Some(Node::Dir) => Err(VeilError::InvalidPath(format!("{path} is a directory"))),
            None => Err(VeilError::NotFound(path.to_string())),
        }
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
