//! Directory listings fetched ahead of a snapshot's walk, on other threads.
//!
//! A snapshot lists every directory of the working copy and stats every
//! file in it ([`DirListing::stats`]); on a disk that is about a
//! microsecond a file, most of a large working copy's snapshot. The walk
//! (`builder::Builder::build_dir`) is depth first and does everything else
//! in order on one thread; [`Prefetch`]'s workers list the directories
//! breadth first meanwhile, classify their files against the policy
//! (a pure function of the policy and the path), and load each one's tree
//! from the parent snapshot (the object store's cache keeps it for the
//! walk).
//!
//! **Nothing the walk decides changes.** It takes a directory's listing
//! from here when a worker has made it, waits for it while a worker is
//! making it, and otherwise lists the directory itself, as before. A
//! listing is one observation of the directory, made after the stat
//! cache's clock reading (the workers start after the cache run begins),
//! and before any file in it is read: what the walk would have seen had
//! it listed the directory a moment earlier. Workers do not descend where
//! the walk does not (ignored directories, nested repositories, reserved
//! names, beyond the depth limit); a listing the walk never asks for is
//! only wasted work, one it asks for and no worker made it makes itself.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Condvar, Mutex},
};

use crate::{
    error::Result,
    id::ObjectId,
    object::{is_reserved_name, EntryKind, Tree},
    policy::{Classification, Policy, Tier},
    store::ObjectStore,
    tree::MAX_TREE_DEPTH,
    vfs::{holds_repository, DirListing, NodeKind, StorageBackend},
    vpath::VPath,
};

/// Files (as the stat cache counted them last time) per worker; a small
/// working copy is not worth a thread.
pub(crate) const FILES_PER_WORKER: usize = 250;
/// At most this many workers (as checkout's staging threads: a few
/// directories at a time keep the disk busy; more only contend).
pub(crate) const MAX_WORKERS: usize = 7;

/// How many workers to start for a working copy of about `files` files.
pub(crate) fn workers_for(files: usize) -> usize {
    (files / FILES_PER_WORKER).min(MAX_WORKERS)
}

/// A directory's listing and, when a worker made it, the classification of
/// each of its files and symlinks (`None` for directories), by entry.
pub(crate) type Listed = (DirListing, Vec<Option<Classification>>);

enum Slot {
    /// Waiting for a worker.
    Queued,
    /// A worker is listing it.
    Listing,
    Listed(Result<Listed>),
    /// The walk took it (or listed it itself).
    Taken,
}

/// Calls [`Prefetch::finish`] when dropped.
pub(crate) struct Stopper<'p, 'a>(&'p Prefetch<'a>);

impl Drop for Stopper<'_, '_> {
    fn drop(&mut self) {
        self.0.finish();
    }
}

#[derive(Default)]
struct State {
    /// Directories to list, with their tree in the parent snapshot (if
    /// any) and their depth.
    queue: VecDeque<(VPath, Option<ObjectId>, usize)>,
    slots: HashMap<VPath, Slot>,
    /// The walk is over: workers stop.
    done: bool,
}

pub(crate) struct Prefetch<'a> {
    fs: &'a dyn StorageBackend,
    store: &'a ObjectStore,
    policy: &'a Policy,
    state: Mutex<State>,
    changed: Condvar,
}

impl<'a> Prefetch<'a> {
    /// Start from the root, whose tree in the parent snapshot is `root`.
    pub(crate) fn new(fs: &'a dyn StorageBackend, store: &'a ObjectStore, policy: &'a Policy, root: Option<ObjectId>) -> Prefetch<'a> {
        let mut state = State::default();
        state.queue.push_back((VPath::root(), root, 0));
        state.slots.insert(VPath::root(), Slot::Queued);
        Prefetch {
            fs,
            store,
            policy,
            state: Mutex::new(state),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A worker: list what is queued until the walk is over.
    pub(crate) fn work(&self) {
        let mut st = self.lock();
        loop {
            if st.done {
                return;
            }
            let Some((dir, tree, depth)) = st.queue.pop_front() else {
                st = self.changed.wait(st).unwrap_or_else(|e| e.into_inner());
                continue;
            };
            if !matches!(st.slots.get(&dir), Some(Slot::Queued)) {
                continue;
            }
            st.slots.insert(dir.clone(), Slot::Listing);
            drop(st);
            let listing = self.fs.list_dir_full(&dir);
            // Loaded for the walk (the store caches it); a failure here is
            // the walk's to report when it loads it.
            let tree = tree.and_then(|id| self.store.tree(&id).ok());
            if let Ok(l) = &listing {
                let mut st = self.lock();
                self.queue_children(&mut st, &dir, l, tree.as_deref(), depth);
                self.changed.notify_all();
            }
            let listed = listing.map(|l| {
                let classes = l
                    .entries
                    .iter()
                    .map(|e| match e.kind {
                        NodeKind::File => Some(self.policy.classify(&dir.join(&e.name), false)),
                        NodeKind::Symlink => Some(self.policy.classify_link(&dir.join(&e.name))),
                        NodeKind::Dir => None,
                    })
                    .collect();
                (l, classes)
            });
            st = self.lock();
            st.slots.insert(dir, Slot::Listed(listed));
            self.changed.notify_all();
        }
    }

    /// The listing of `dir` (whose tree in the parent snapshot is `tree`),
    /// from a worker or made now.
    pub(crate) fn list(&self, dir: &VPath, tree: Option<&Tree>) -> Result<Listed> {
        let depth = match dir.is_root() {
            true => 0,
            false => dir.as_str().split('/').count(),
        };
        let mut st = self.lock();
        loop {
            match st.slots.insert(dir.clone(), Slot::Taken) {
                Some(Slot::Listed(l)) => return l,
                Some(Slot::Listing) => {
                    st.slots.insert(dir.clone(), Slot::Listing);
                    st = self.changed.wait(st).unwrap_or_else(|e| e.into_inner());
                }
                // Not reached by the workers yet: listed here, as without
                // them; its subdirectories are theirs.
                _ => {
                    drop(st);
                    let listing = self.fs.list_dir_full(dir);
                    if let Ok(l) = &listing {
                        let mut st = self.lock();
                        self.queue_children(&mut st, dir, l, tree, depth);
                        self.changed.notify_all();
                    }
                    return listing.map(|l| (l, Vec::new()));
                }
            }
        }
    }

    /// The walk is over (or failed): the workers stop after what they are
    /// listing.
    pub(crate) fn finish(&self) {
        self.lock().done = true;
        self.changed.notify_all();
    }

    /// [`Prefetch::finish`] when the returned guard is dropped.
    pub(crate) fn stopper(&self) -> Stopper<'_, 'a> {
        Stopper(self)
    }

    /// Queue the subdirectories of `dir` the walk will descend into.
    fn queue_children(&self, st: &mut State, dir: &VPath, listing: &DirListing, tree: Option<&Tree>, depth: usize) {
        // A nested repository is left out as a whole; the depth limit is
        // reported, not walked.
        if (!dir.is_root() && holds_repository(listing)) || depth + 1 >= MAX_TREE_DEPTH {
            return;
        }
        for e in listing.entries.iter().filter(|e| e.kind == NodeKind::Dir && !is_reserved_name(&e.name)) {
            let path = dir.join(&e.name);
            if st.slots.contains_key(&path) || self.policy.classify(&path, true).tier == Tier::Ignored {
                continue;
            }
            let sub = tree.and_then(|t| t.get(&e.name)).filter(|t| t.kind == EntryKind::Dir).map(|t| t.id);
            st.slots.insert(path.clone(), Slot::Queued);
            st.queue.push_back((path, sub, depth + 1));
        }
    }
}
