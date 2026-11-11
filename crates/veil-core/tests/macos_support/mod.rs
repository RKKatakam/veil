//! Test-only simulation of macOS filesystem name semantics over
//! `MemoryBackend`, so the engine's behaviour on APFS and HFS+ can be
//! tested on Linux.
//!
//! * [`FoldingBackend::apfs`]: case-insensitive, case-preserving,
//!   normalisation-insensitive and normalisation-preserving (a default APFS
//!   volume). A name is stored exactly as first created; every alias (other
//!   case, other Unicode normalisation form) resolves to it.
//! * [`FoldingBackend::hfs_plus`]: the same, except that new names are
//!   stored decomposed (NFD), so a listing hands back NFD whatever was
//!   written, and HFS+-ignorable code points are ignored when looking up.
//!
//! Writing through an alias of an existing entry keeps the stored name, as
//! writing into an existing file does on macOS.

#![allow(dead_code)]

use unicode_normalization::UnicodeNormalization;
use veil_core::{
    vfs::{DirEntry, Metadata, NameFolding, StatClock},
    MemoryBackend, ObjectId, Result, StorageBackend, VPath,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flavor {
    Apfs,
    HfsPlus,
}

#[derive(Debug)]
pub struct FoldingBackend {
    inner: MemoryBackend,
    flavor: Flavor,
}

impl FoldingBackend {
    pub fn apfs() -> Self {
        FoldingBackend {
            inner: MemoryBackend::new(),
            flavor: Flavor::Apfs,
        }
    }

    pub fn hfs_plus() -> Self {
        FoldingBackend {
            inner: MemoryBackend::new(),
            flavor: Flavor::HfsPlus,
        }
    }

    pub fn flavor(&self) -> Flavor {
        self.flavor
    }

    /// The names exactly as stored (what a directory listing returns).
    pub fn inner(&self) -> &MemoryBackend {
        &self.inner
    }

    fn stored_form(&self, name: &str) -> String {
        match self.flavor {
            Flavor::Apfs => name.to_string(),
            Flavor::HfsPlus => name.nfd().collect(),
        }
    }

    /// Map `path` to the stored spelling of every existing component; the
    /// first missing component and everything below it get the spelling a
    /// create would store.
    fn resolve(&self, path: &VPath) -> VPath {
        let mut cur = VPath::root();
        let mut exists = true;
        for comp in path.components() {
            let found = if exists {
                let key = NameFolding::MACOS.key(comp);
                self.inner
                    .list_dir(&cur)
                    .ok()
                    .and_then(|entries| entries.into_iter().find(|e| NameFolding::MACOS.key(&e.name) == key))
                    .map(|e| e.name)
            } else {
                None
            };
            cur = match found {
                Some(name) => cur.join(&name),
                None => {
                    exists = false;
                    cur.join(&self.stored_form(comp))
                }
            };
        }
        cur
    }
}

impl StorageBackend for FoldingBackend {
    fn kind(&self) -> &'static str {
        match self.flavor {
            Flavor::Apfs => "apfs-sim",
            Flavor::HfsPlus => "hfs+-sim",
        }
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        self.inner.read(&self.resolve(path))
    }
    fn read_range(&self, path: &VPath, offset: u64, len: usize) -> Result<Vec<u8>> {
        self.inner.read_range(&self.resolve(path), offset, len)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.inner.write(&self.resolve(path), data)
    }
    fn write_secret(&self, path: &VPath, data: &[u8], executable: bool) -> Result<()> {
        self.inner.write_secret(&self.resolve(path), data, executable)
    }
    fn write_unsynced(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.inner.write_unsynced(&self.resolve(path), data)
    }
    fn write_secret_unsynced(&self, path: &VPath, data: &[u8], executable: bool) -> Result<()> {
        self.inner.write_secret_unsynced(&self.resolve(path), data, executable)
    }
    fn sync_barrier(&self) -> Result<()> {
        self.inner.sync_barrier()
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.inner.create_new(&self.resolve(path), data)
    }
    fn create_new_secret(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.inner.create_new_secret(&self.resolve(path), data)
    }
    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.inner.remove_file(&self.resolve(path))
    }
    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        self.inner.remove_dir_all(&self.resolve(path))
    }
    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        self.inner.create_dir_all(&self.resolve(path))
    }
    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        self.inner.list_dir(&self.resolve(path))
    }
    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        self.inner.metadata(&self.resolve(path))
    }
    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()> {
        self.inner.set_executable(&self.resolve(path), executable)
    }
    fn known_id(&self, path: &VPath) -> Option<ObjectId> {
        self.inner.known_id(&self.resolve(path))
    }
    fn stat_clock(&self) -> Option<StatClock> {
        self.inner.stat_clock()
    }
    fn name_folding(&self) -> NameFolding {
        NameFolding::MACOS
    }
}
