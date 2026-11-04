//! Shared helpers for the adversarial test suites (`adversarial_*.rs`).
//!
//! Everything here builds hostile inputs *through the public API only*: raw
//! objects are written straight into a backend, trees are assembled entry by
//! entry (no sorting, no validation), and "remotes" are bare repositories
//! whose view we edit by hand.

#![allow(dead_code)]

use std::sync::Arc;

use veil_core::{
    id::ChangeId,
    object::{EntryKind, Object, Snapshot, Text, Tree, TreeEntry, Visibility},
    oplog::Tag,
    tree::lookup,
    Identity, MemoryBackend, ObjectId, Repo, StorageBackend, VPath,
};

pub const WS: &str = "default";

pub fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

pub fn new_repo(name: &str) -> (Repo, Arc<MemoryBackend>, Identity) {
    let fs = Arc::new(MemoryBackend::new());
    let id = Identity::generate(name);
    let repo = Repo::init(fs.clone(), Some(id.clone()), name).unwrap();
    (repo, fs, id)
}

pub fn repo_for(name: &str, id: &Identity) -> (Repo, Arc<MemoryBackend>) {
    let fs = Arc::new(MemoryBackend::new());
    let repo = Repo::init(fs.clone(), Some(id.clone()), name).unwrap();
    (repo, fs)
}

pub fn snap(repo: &mut Repo, fs: &dyn StorageBackend) -> ObjectId {
    repo.snapshot_workspace(WS, fs).unwrap().snapshot
}

pub fn file_entry(repo: &Repo, rev: &ObjectId, path: &str) -> Option<TreeEntry> {
    let tree = repo.snapshot(rev).unwrap().tree;
    lookup(repo.store(), &tree, &p(path)).unwrap()
}

pub fn read_at(repo: &Repo, rev: &ObjectId, path: &str) -> Vec<u8> {
    let e = file_entry(repo, rev, path).unwrap_or_else(|| panic!("{path} missing"));
    repo.store().read_entry(&e).unwrap()
}

/// Commit `files` on top of the current working copy and return the commit.
pub fn commit_files(repo: &mut Repo, fs: &dyn StorageBackend, files: &[(&str, &str)], msg: &str) -> ObjectId {
    for (path, data) in files {
        fs.write(&p(path), data.as_bytes()).unwrap();
    }
    snap(repo, fs);
    repo.commit_working_copy(WS, msg).unwrap().0
}

/// Every raw object stored in a backend's CAS, as `(id, bytes)`.
pub fn all_objects(backend: &dyn StorageBackend) -> Vec<(String, Vec<u8>)> {
    let root = p(".veil/objects");
    let mut out = Vec::new();
    if !backend.exists(&root).unwrap() {
        return out;
    }
    for d in backend.list_dir(&root).unwrap() {
        let dir = root.join(&d.name);
        for f in backend.list_dir(&dir).unwrap() {
            let data = backend.read(&dir.join(&f.name)).unwrap();
            out.push((format!("{}{}", d.name, f.name), data));
        }
    }
    out
}

/// True if `needle` appears anywhere in the backend (objects, ops, meta...).
pub fn backend_contains(backend: &dyn StorageBackend, needle: &[u8]) -> Vec<String> {
    let files = veil_core::vfs::walk_files(backend, &VPath::root(), &|_| false).unwrap();
    files
        .into_iter()
        .filter(|f| {
            let data = backend.read(f).unwrap();
            data.windows(needle.len()).any(|w| w == needle)
        })
        .map(|f| f.to_string())
        .collect()
}

// ---- hostile object construction ---------------------------------------

pub fn file(name: &str, id: ObjectId) -> TreeEntry {
    TreeEntry {
        name: name.to_string(),
        kind: EntryKind::File,
        id,
        size: 0,
        executable: false,
        visibility: Visibility::Public,
        fallback: None,
    }
}

pub fn dir(name: &str, id: ObjectId) -> TreeEntry {
    TreeEntry::dir(name, id)
}

/// Store a tree exactly as given (no sorting, no dedup, no validation).
pub fn raw_tree(repo: &Repo, entries: Vec<TreeEntry>) -> ObjectId {
    repo.store().put(&Object::Tree(Tree { entries })).unwrap()
}

pub fn blob(repo: &Repo, data: &[u8]) -> ObjectId {
    repo.store().put(&Object::Blob(data.to_vec())).unwrap()
}

pub fn raw_snapshot(repo: &Repo, parents: Vec<ObjectId>, tree: ObjectId, desc: &str) -> ObjectId {
    repo.store()
        .put_snapshot(&Snapshot {
            parents,
            change_id: ChangeId::random(),
            tree,
            description: Text::Plain(desc.to_string()),
            author: "mallory".into(),
            timestamp: 1,
            predecessors: vec![],
            conflicts: vec![],
            cloak: None,
            signature: None,
            embargo: None,
        })
        .unwrap()
}

/// A bare "remote" repository whose tag `main` points at a snapshot whose
/// tree is built by `build`.
pub fn evil_remote(build: impl FnOnce(&Repo) -> ObjectId) -> (Arc<MemoryBackend>, ObjectId) {
    let backend = Arc::new(MemoryBackend::new());
    let mut remote = Repo::init_bare(backend.clone()).unwrap();
    let tree = build(&remote);
    let root = remote.root_id();
    let s = raw_snapshot(&remote, vec![root], tree, "totally normal commit");
    set_remote_tag(&mut remote, "main", s);
    (backend, s)
}

pub fn set_remote_tag(remote: &mut Repo, name: &str, target: ObjectId) {
    let mut tx = remote.transaction("evil").unwrap();
    tx.view.tags.insert(name.to_string(), Tag { target, cloak: None });
    tx.view.heads.insert(target);
    tx.commit().unwrap();
}

/// Write a raw object file at the path for `id` without any verification.
pub fn plant_raw_object(backend: &dyn StorageBackend, id: &ObjectId, raw: &[u8]) {
    let h = id.hex();
    backend
        .write(&p(&format!(".veil/objects/{}/{}", &h[..2], &h[2..])), raw)
        .unwrap();
}

/// Pull `main` from `remote` and move the working copy onto it, checking the
/// result out onto `wc`.
pub fn pull_and_checkout(victim: &mut Repo, wc: &dyn StorageBackend, remote: Arc<dyn StorageBackend>) -> veil_core::Result<()> {
    veil_core::remote::pull(victim, "origin", remote)?;
    let main = victim.view().tags["main"].target;
    let old = victim.snapshot(&victim.workspace_wc(WS)?)?.tree;
    let wc_id = victim.new_change(WS, vec![main], "")?;
    let to = victim.snapshot(&wc_id)?.tree;
    victim.checkout_tree(wc, Some(&old), &to)?;
    Ok(())
}
