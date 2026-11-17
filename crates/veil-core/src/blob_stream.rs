//! A large file's content, copied out of the store without holding it
//! whole in memory (milestone S8, BUG-1368): a mount spills a large open
//! file this way.
//!
//! Objects of more than 1 MiB are written loose (`store.rs`, `TX_BUFFER_OBJECT`),
//! and a loose object is its canonical encoding as it is: a blob's is
//! `veil:blob\n` and the content. [`ObjectStore::copy_loose_blob`] streams
//! that file, a piece at a time, hashing everything it reads; only once the
//! whole file matches the object's id is the copy good. Anything else (a
//! packed object, a sealed secret, a conflict) is `None`: read it whole, as
//! before.
//!
//! Whether a reader can open a large file at all is told by the first
//! bytes of its object, loose or packed ([`ObjectStore::kind_by_head`],
//! BUG-1461): a mount's `stat` reads no more.

use std::io::{Read, Write};

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    store::ObjectStore,
};

/// The piece read and written at a time.
const PIECE: usize = 1 << 20;
const BLOB_TAG: &[u8] = b"veil:blob\n";

/// The bytes [`ObjectStore::kind_by_head`] looks at: the tag of an object
/// and, of a sealed one, its scope's name.
const HEAD: usize = 512;

/// What the first bytes of an object say of it ([`ObjectStore::kind_by_head`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadKind {
    /// Not sealed: every reader opens it.
    Plain,
    /// A sealed secret: whether this reader holds the key of its scope.
    Sealed(bool),
}

fn io(path: &std::path::Path, source: std::io::Error) -> VeilError {
    VeilError::Io { path: path.display().to_string(), source }
}

impl ObjectStore {
    /// Can this reader open object `id`, told by the first bytes of its
    /// copy here without reading it whole: of its loose object, or of its
    /// entry in a pack (a ranged read and the first block of its frame,
    /// BUG-1461), in this store's own files or a thin clone's cache? What
    /// [`ObjectStore::entry_readable`] answers for a file it reads whole.
    /// `None` when no copy here tells (none here, an object staged by a
    /// transaction, a delta whose first bytes are not its base's first):
    /// decide the full way then. A visibility decision only: every read
    /// still checks the whole object against its id.
    pub fn kind_by_head(&self, id: &ObjectId) -> Option<HeadKind> {
        let stores: Vec<&ObjectStore> = std::iter::once(self).chain(self.cache().map(|c| &**c)).collect();
        let (len, head) = stores.into_iter().find_map(|store| store.loose_head(id).or_else(|| store.packed_head(id, HEAD)))?;
        Some(match crate::object::Object::sealed_scope_of_head(&head, head.len() as u64 == len)? {
            Some(scope) => HeadKind::Sealed(self.keys.has(&scope)),
            None => HeadKind::Plain,
        })
    }

    /// The length of the loose object of `id` in this store's own files,
    /// and its first bytes.
    fn loose_head(&self, id: &ObjectId) -> Option<(u64, Vec<u8>)> {
        let f = std::fs::File::open(self.backend().local_path(&self.loose_path(id))?).ok()?;
        let len = f.metadata().ok()?.len();
        let mut head = Vec::with_capacity(HEAD);
        f.take(HEAD as u64).read_to_end(&mut head).ok()?;
        Some((len, head))
    }

    /// Copy the content of blob `id` to `out`, from its loose object in
    /// this store's own files or a thin clone's cache, a piece at a time,
    /// checked against `id` as it goes: its length, or `None` when no
    /// loose blob of it is here (read it whole). On a mismatch (a torn or
    /// changed file) the copy is an error: whatever was written to `out`
    /// is not the content.
    pub fn copy_loose_blob(&self, id: &ObjectId, out: &mut impl Write) -> Result<Option<u64>> {
        let stores: Vec<&ObjectStore> = std::iter::once(self).chain(self.cache().map(|c| &**c)).collect();
        for store in stores {
            let Some(path) = store.backend().local_path(&store.loose_path(id)) else { continue };
            let mut f = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(io(&path, e)),
            };
            let mut hasher = blake3::Hasher::new();
            let mut head = [0u8; BLOB_TAG.len()];
            if f.read_exact(&mut head).is_err() || head != BLOB_TAG {
                return Ok(None);
            }
            hasher.update(&head);
            let mut buf = vec![0u8; PIECE];
            let mut len = 0u64;
            loop {
                let n = f.read(&mut buf).map_err(|e| io(&path, e))?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                out.write_all(&buf[..n]).map_err(|e| io(&path, e))?;
                len += n as u64;
            }
            if ObjectId(*hasher.finalize().as_bytes()) != *id {
                return Err(VeilError::Corrupt(id.hex(), "a loose object does not match its id".into()));
            }
            return Ok(Some(len));
        }
        Ok(None)
    }
}
