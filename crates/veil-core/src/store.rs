//! Content-addressable store with transparent decryption of sealed nodes.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, RwLock},
};

use crate::{
    crypto::Envelope,
    error::{Result, VeilError},
    id::ObjectId,
    keychain::Keychain,
    object::{EntryKind, Object, Snapshot, Text, Tree, TreeEntry, Visibility},
    vfs::StorageBackend,
    vpath::VPath,
};

pub struct ObjectStore {
    backend: Arc<dyn StorageBackend>,
    root: VPath,
    pub keys: Arc<Keychain>,
    trees: RwLock<HashMap<ObjectId, Arc<Tree>>>,
    snapshots: RwLock<HashMap<ObjectId, Arc<Snapshot>>>,
}

impl fmt::Debug for ObjectStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectStore({} at {})", self.backend.kind(), self.root)
    }
}

impl ObjectStore {
    pub fn new(backend: Arc<dyn StorageBackend>, root: VPath, keys: Arc<Keychain>) -> Self {
        ObjectStore {
            backend,
            root,
            keys,
            trees: RwLock::new(HashMap::new()),
            snapshots: RwLock::new(HashMap::new()),
        }
    }

    fn path(&self, id: &ObjectId) -> VPath {
        let h = id.hex();
        self.root.join(&h[..2]).join(&h[2..])
    }

    pub fn has(&self, id: &ObjectId) -> bool {
        self.backend.exists(&self.path(id)).unwrap_or(false)
    }

    pub fn get_raw(&self, id: &ObjectId) -> Result<Vec<u8>> {
        match self.backend.read(&self.path(id)) {
            Ok(b) => Ok(b),
            Err(e) if e.is_not_found() => Err(VeilError::Missing(*id)),
            Err(e) => Err(e),
        }
    }

    /// Insert an already-encoded object, verifying its address.
    pub fn put_raw(&self, id: &ObjectId, raw: &[u8]) -> Result<()> {
        if ObjectId::hash(raw) != *id {
            return Err(VeilError::Corrupt(id.hex(), "hash mismatch".into()));
        }
        if !self.has(id) {
            self.backend.write(&self.path(id), raw)?;
        }
        Ok(())
    }

    pub fn put(&self, obj: &Object) -> Result<ObjectId> {
        let raw = obj.encode();
        let id = ObjectId::hash(&raw);
        if !self.has(&id) {
            self.backend.write(&self.path(&id), &raw)?;
        }
        Ok(id)
    }

    /// Decode without decrypting.
    pub fn get(&self, id: &ObjectId) -> Result<Object> {
        Object::decode(&self.get_raw(id)?)
    }

    /// Decode and peel any sealed layers using the keychain.
    pub fn open(&self, id: &ObjectId) -> Result<Object> {
        let mut obj = self.get(id)?;
        while let Object::Sealed(env) = obj {
            let key = self.keys.require(&env.scope)?;
            let plain = env.open(&key).map_err(|_| VeilError::Redacted {
                scope: env.scope.clone(),
            })?;
            obj = Object::decode(&plain)?;
        }
        Ok(obj)
    }

    pub fn tree(&self, id: &ObjectId) -> Result<Arc<Tree>> {
        if let Some(t) = self.trees.read().unwrap().get(id) {
            return Ok(t.clone());
        }
        let t = match self.open(id)? {
            Object::Tree(t) => Arc::new(t),
            o => return Err(VeilError::Corrupt(id.hex(), format!("expected tree, found {}", o.kind_name()))),
        };
        self.trees.write().unwrap().insert(*id, t.clone());
        Ok(t)
    }

    pub fn put_tree(&self, t: &Tree) -> Result<ObjectId> {
        self.put(&Object::Tree(t.clone()))
    }

    pub fn empty_tree(&self) -> Result<ObjectId> {
        self.put_tree(&Tree::default())
    }

    pub fn snapshot(&self, id: &ObjectId) -> Result<Arc<Snapshot>> {
        if let Some(s) = self.snapshots.read().unwrap().get(id) {
            return Ok(s.clone());
        }
        let s = match self.get(id)? {
            Object::Snapshot(s) => Arc::new(s),
            o => {
                return Err(VeilError::Corrupt(
                    id.hex(),
                    format!("expected snapshot, found {}", o.kind_name()),
                ))
            }
        };
        self.snapshots.write().unwrap().insert(*id, s.clone());
        Ok(s)
    }

    pub fn put_snapshot(&self, s: &Snapshot) -> Result<ObjectId> {
        self.put(&Object::Snapshot(s.clone()))
    }

    /// Seal `inner` under `scope` (deterministically, for dedup). A bare
    /// scope name seals under its current key generation (`scope#key-id`);
    /// a label that already names a generation is used as is.
    pub fn seal(&self, inner: &Object, scope: &str) -> Result<Object> {
        let (label, key) = self.keys.sealing_key(scope)?;
        Ok(Object::Sealed(Envelope::seal(&key, &label, &inner.encode(), true)?))
    }

    /// Store file content with the given visibility, returning its id.
    pub fn store_file(&self, data: &[u8], vis: &Visibility) -> Result<ObjectId> {
        let blob = Object::Blob(data.to_vec());
        match vis.key_scope() {
            None => self.put(&blob),
            Some(scope) => self.put(&self.seal(&blob, &scope)?),
        }
    }

    pub fn read_blob(&self, id: &ObjectId) -> Result<Vec<u8>> {
        match self.open(id)? {
            Object::Blob(b) => Ok(b),
            o => Err(VeilError::Corrupt(id.hex(), format!("expected blob, found {}", o.kind_name()))),
        }
    }

    /// Read a file entry, falling back to the embargo fallback when the
    /// primary content is unreadable.
    pub fn read_entry(&self, e: &TreeEntry) -> Result<Vec<u8>> {
        match self.read_blob(&e.id) {
            Err(err) if err.is_unreadable() => match &e.fallback {
                Some(fb) => self.read_blob(fb),
                None => Err(err),
            },
            r => r,
        }
    }

    fn id_readable(&self, id: &ObjectId) -> bool {
        match self.get_raw(id) {
            Ok(raw) => match Object::sealed_scope(&raw) {
                Some(scope) => self.keys.has(&scope),
                None => true,
            },
            Err(_) => false,
        }
    }

    /// Can this reader materialise the entry?
    pub fn entry_readable(&self, e: &TreeEntry) -> bool {
        match e.kind {
            EntryKind::Dir => self.has(&e.id),
            EntryKind::File => self.id_readable(&e.id) || e.fallback.is_some_and(|f| self.id_readable(&f)),
        }
    }

    /// Would `data` encode to exactly `reference` (same plaintext, same
    /// sealing scope)? Used to recognise unchanged fallback content.
    pub fn matches_encoding(&self, reference: &ObjectId, data: &[u8]) -> Result<bool> {
        let raw = match self.get_raw(reference) {
            Ok(r) => r,
            Err(e) if e.is_unreadable() => return Ok(false),
            Err(e) => return Err(e),
        };
        if Object::is_blob_raw(&raw) {
            return Ok(Object::blob_id(data) == *reference);
        }
        match Object::sealed_scope(&raw) {
            Some(label) if self.keys.has(&label) => {
                // Re-seal under the reference's exact label (generation).
                let key = self.keys.require(&label)?;
                let sealed = Object::Sealed(Envelope::seal(&key, &label, &Object::Blob(data.to_vec()).encode(), true)?);
                Ok(ObjectId::hash(&sealed.encode()) == *reference)
            }
            _ => Ok(false),
        }
    }

    pub fn make_text(&self, text: &str, cloak: Option<&str>) -> Result<Text> {
        match cloak {
            None => Ok(Text::Plain(text.to_string())),
            Some(scope) => {
                let (label, key) = self.keys.sealing_key(scope)?;
                Ok(Text::Sealed(Envelope::seal(&key, &label, text.as_bytes(), false)?))
            }
        }
    }

    /// Plaintext of a description, or `None` if cloaked and unreadable.
    pub fn read_text(&self, t: &Text) -> Option<String> {
        match t {
            Text::Plain(s) => Some(s.clone()),
            Text::Sealed(env) => {
                let key = self.keys.key(&env.scope)?;
                String::from_utf8(env.open(&key).ok()?).ok()
            }
        }
    }
}
