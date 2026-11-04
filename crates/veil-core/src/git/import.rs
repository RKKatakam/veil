//! Git commits → snapshots, with carry-over of everything Git never saw.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::{Arc, Mutex},
};

use super::{export::CHANGE_ID_HEADER, gerr, map::GitOid, short, GitBridge};
use crate::{
    builder::{build_tree, BuildOptions},
    embargo::policy_rekeys,
    error::{Result, VeilError},
    id::{ChangeId, ObjectId},
    merge::merge_trees,
    object::{validate_entry_name, EntryKind, Object, Snapshot, Text, Tree},
    policy::{Policy, POLICY_FILE},
    store::ObjectStore,
    transaction::Transaction,
    vfs::{DirEntry, DirListing, Metadata, NodeKind, StorageBackend},
    vpath::VPath,
};

#[derive(Debug, Default)]
pub struct ImportReport {
    /// Commits imported as new snapshots.
    pub imported: usize,
    /// Paths present in Git that Veil did not record, with the reason
    /// (isolated, quarantined, no key to cloak, not representable). They
    /// stay in Git: export carries them over.
    pub left_in_git: BTreeMap<String, String>,
    /// Commits that could not be imported (and their descendants).
    pub failed: Vec<(GitOid, String)>,
    /// Imported commits whose snapshot records conflicts.
    pub conflicts: Vec<(GitOid, Vec<String>)>,
    pub warnings: Vec<String>,
}

/// The change id of an imported commit: its `change-id` header (Jujutsu,
/// or an earlier Veil export), else one derived from the commit id, so
/// that importing the same commit twice gives the same snapshot.
fn change_id_of(oid: &GitOid, commit: &gix::objs::Commit) -> ChangeId {
    let header = commit
        .extra_headers
        .iter()
        .find(|(k, _)| k == CHANGE_ID_HEADER)
        .and_then(|(_, v)| std::str::from_utf8(v).ok())
        .and_then(|v| ChangeId::parse(v.trim()).ok())
        .filter(|c| *c != ChangeId::ROOT);
    header.unwrap_or_else(|| {
        let h = blake3::derive_key("veil 2026 git change-id v1", oid.as_bytes());
        ChangeId(h[..16].try_into().unwrap())
    })
}

fn author_of(commit: &gix::objs::Commit) -> (String, i64) {
    let a = &commit.author;
    let name = a.name.to_string();
    let email = a.email.to_string();
    let who = if email.is_empty() {
        name.trim().to_string()
    } else {
        format!("{} <{}>", name.trim(), email.trim())
    };
    (who, a.time.seconds.saturating_mul(1000))
}

impl GitBridge {
    /// Import every commit reachable from `tips` that is not mapped yet,
    /// parents first. A commit that cannot be imported (its parent is under
    /// an embargo whose key we lack) is reported, together with its
    /// descendants; nothing is half-imported.
    pub(crate) fn import_tips(&mut self, tx: &mut Transaction<'_>, tips: &[GitOid]) -> Result<ImportReport> {
        let mut report = ImportReport::default();
        let mut todo: HashMap<GitOid, gix::objs::Commit> = HashMap::new();
        let mut stack: Vec<GitOid> = tips.to_vec();
        while let Some(c) = stack.pop() {
            if todo.contains_key(&c) || self.mapped(tx, &c)?.is_some() {
                continue;
            }
            let commit = self.read_commit(&c)?;
            stack.extend(commit.parents.iter().copied());
            todo.insert(c, commit);
        }
        // Parents first (Kahn), oldest first among the ready ones.
        let mut pending_parents: HashMap<GitOid, usize> = HashMap::new();
        let mut children: HashMap<GitOid, Vec<GitOid>> = HashMap::new();
        for (c, commit) in &todo {
            let mut n = 0;
            for p in commit.parents.iter().collect::<BTreeSet<_>>() {
                if todo.contains_key(p) {
                    n += 1;
                    children.entry(*p).or_default().push(*c);
                }
            }
            pending_parents.insert(*c, n);
        }
        let key = |c: &GitOid| (todo[c].committer.time.seconds, *c);
        let mut ready: BTreeSet<(i64, GitOid)> =
            pending_parents.iter().filter(|(_, n)| **n == 0).map(|(c, _)| key(c)).collect();
        let mut failed: HashSet<GitOid> = HashSet::new();
        while let Some(k) = ready.pop_first() {
            let c = k.1;
            let commit = &todo[&c];
            if let Some(p) = commit.parents.iter().find(|p| failed.contains(*p)) {
                failed.insert(c);
                report.failed.push((c, format!("its parent {} was not imported", short(p))));
            } else {
                match self.import_one(tx, &c, commit, &mut report) {
                    Ok(()) => report.imported += 1,
                    Err(VeilError::Policy(why)) => {
                        failed.insert(c);
                        report.failed.push((c, why));
                    }
                    Err(e) => return Err(e),
                }
            }
            for ch in children.get(&c).into_iter().flatten() {
                let n = pending_parents.get_mut(ch).unwrap();
                *n -= 1;
                if *n == 0 {
                    ready.insert(key(ch));
                }
            }
        }
        report.warnings.append(&mut self.warnings);
        Ok(report)
    }

    /// The snapshot `commit` maps to, if that snapshot is still present.
    fn mapped(&mut self, tx: &Transaction<'_>, commit: &GitOid) -> Result<Option<ObjectId>> {
        let Some(sid) = self.map.commits.get(commit).copied() else {
            return Ok(None);
        };
        if tx.repo().snapshot_opt(&sid)?.is_some() {
            return Ok(Some(sid));
        }
        // Collected by `vl gc`: import it again (same result).
        self.map.forget_commit(commit);
        Ok(None)
    }

    fn import_one(
        &mut self,
        tx: &mut Transaction<'_>,
        oid: &GitOid,
        commit: &gix::objs::Commit,
        report: &mut ImportReport,
    ) -> Result<()> {
        let store = tx.repo().store().clone();
        let mut parents: Vec<ObjectId> = Vec::new();
        for p in &commit.parents {
            let sid = self
                .mapped(tx, p)?
                .ok_or_else(|| VeilError::repo(format!("git import: parent {} of {} is not mapped", short(p), short(oid))))?;
            if !parents.contains(&sid) {
                parents.push(sid);
            }
        }
        if parents.is_empty() {
            parents.push(tx.repo().root_id());
        }
        let held = |e: VeilError| match e {
            VeilError::Policy(why) => VeilError::Policy(format!("held back: {why}")),
            e => e,
        };
        // What Veil holds for the parents (with everything Git never saw) …
        let outcome = tx.repo().parents_tree(&parents).map_err(held)?;
        let ours = outcome.tree;
        // … what Git saw of it …
        let base = match self.project(&store, &ours)?.tree {
            Some(t) => t,
            None => store.empty_tree()?,
        };
        // … and the Git commit, through the policy gate.
        let hints = self.import_hints(&store, &base, &commit.tree)?;
        let fs = GitTreeFs::new(self.git.clone(), commit.tree, hints);
        let policy = Policy::load(&fs)?;
        let (theirs, build) = build_tree(
            &store,
            &fs,
            &BuildOptions {
                policy: &policy,
                parent_tree: Some(base),
                cloak: None,
                injected: None,
                rescan: false,
                materialised: None,
            },
        )?;
        for (g, v) in fs.learned.into_inner().unwrap() {
            self.cache.contents.insert(g, v);
            self.cache.mark_dirty();
        }
        for p in &build.isolated {
            report.left_in_git.insert(p.to_string(), "isolated by policy".into());
        }
        for (p, f) in &build.quarantined {
            let rule = f.first().map(|f| f.rule).unwrap_or("secret");
            report.left_in_git.insert(p.to_string(), format!("quarantined ({rule})"));
        }
        for (p, why) in &build.cloak_failures {
            report.left_in_git.insert(p.to_string(), why.clone());
        }
        for (p, embargo) in &build.held_back {
            report
                .left_in_git
                .insert(p.to_string(), format!("held back: embargo {embargo} hides this line's current content"));
        }
        for p in build.unrepresentable.iter().chain(fs.special.into_inner().unwrap().iter()) {
            report.left_in_git.insert(p.clone(), "not representable in Veil".into());
        }
        let theirs = self.guard_policy(&store, oid, &ours, &base, theirs, report)?;
        let merged = merge_trees(&store, Some(base), ours, theirs).map_err(held)?;
        let mut conflicts: BTreeSet<String> = outcome.conflicts.iter().map(|p| p.to_string()).collect();
        conflicts.extend(merged.conflicts.iter().map(|p| p.to_string()));
        if !conflicts.is_empty() {
            report.conflicts.push((*oid, conflicts.iter().cloned().collect()));
        }
        let (author, timestamp) = author_of(commit);
        let text = String::from_utf8_lossy(&commit.message);
        let snap = Snapshot {
            parents,
            change_id: change_id_of(oid, commit),
            tree: merged.tree,
            description: Text::Plain(text.trim_end_matches('\n').to_string()),
            author,
            timestamp,
            predecessors: vec![],
            conflicts: conflicts.into_iter().collect(),
            cloak: None,
            embargo: None,
            signature: None,
        };
        let sid = tx.write_snapshot(&snap)?;
        self.map.record_import(*oid, sid);
        Ok(())
    }

    /// A Git commit may edit `.veilpolicy` like any file. An edit that would
    /// move sealed files to another audience (`secrets/ cloak team` →
    /// `public!`) is not taken, exactly as `vl merge` refuses it: the
    /// Veil-side policy is kept and the import warns.
    fn guard_policy(
        &mut self,
        store: &ObjectStore,
        oid: &GitOid,
        ours: &ObjectId,
        base: &ObjectId,
        theirs: ObjectId,
        report: &mut ImportReport,
    ) -> Result<ObjectId> {
        let t = store.tree_object(&theirs)?;
        let b = store.tree(base)?;
        let (te, be) = (t.get(POLICY_FILE), b.get(POLICY_FILE));
        if te.map(|e| e.id) == be.map(|e| e.id) {
            return Ok(theirs);
        }
        let read = |e: Option<&crate::object::TreeEntry>| -> Result<Policy> {
            Ok(match e {
                Some(e) => match store.read_entry(e) {
                    Ok(b) => Policy::parse(&String::from_utf8_lossy(&b)),
                    Err(err) if err.is_unreadable() => Policy::builtin(),
                    Err(err) => return Err(err),
                },
                None => Policy::builtin(),
            })
        };
        let ours_tree = store.tree(ours)?;
        let old = read(ours_tree.get(POLICY_FILE))?;
        let new = read(te)?;
        if policy_rekeys(store, ours, &old, &new, None)?.is_empty() {
            return Ok(theirs);
        }
        report.warnings.push(format!(
            "Git commit {} edits .veilpolicy so that sealed files would change audience; Veil kept its policy (edit it in Veil to apply)",
            short(oid)
        ));
        let mut kept: Tree = (*t).clone();
        match be {
            Some(e) => kept.insert(e.clone()),
            None => {
                kept.remove(POLICY_FILE);
            }
        }
        store.put_tree(&kept)
    }

    /// Reuse hints for the builder: paths whose Git content is known to be
    /// exactly what the base (public Veil tree) holds there.
    fn import_hints(&mut self, store: &ObjectStore, base: &ObjectId, git_tree: &GitOid) -> Result<HashMap<VPath, ObjectId>> {
        let mut hints = HashMap::new();
        let mut stack = vec![(VPath::root(), *base, *git_tree)];
        while let Some((dir, vt, gt)) = stack.pop() {
            let vtree = store.tree(&vt)?;
            let gtree = self.read_tree(&gt)?;
            let gmap: HashMap<&[u8], &gix::objs::tree::Entry> =
                gtree.entries.iter().map(|e| (e.filename.as_slice(), e)).collect();
            for e in &vtree.entries {
                let Some(g) = gmap.get(e.name.as_bytes()) else { continue };
                let path = dir.join(&e.name);
                match e.kind {
                    EntryKind::Dir if g.mode.is_tree() => {
                        if self.git_tree(store, &e.id)? == g.oid {
                            hints.insert(path, e.id);
                        } else {
                            stack.push((path, e.id, g.oid));
                        }
                    }
                    EntryKind::File if g.mode.is_blob() && g.mode.is_executable() == e.executable => {
                        if let Some(v) = self.cache.contents.get(&g.oid) {
                            hints.insert(path, *v);
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(hints)
    }
}

// ---- a Git tree as a read-only StorageBackend ---------------------------------

#[derive(Debug)]
struct GitDir {
    entries: BTreeMap<String, (gix::objs::tree::EntryKind, GitOid)>,
    bad: Vec<String>,
}

/// Read-only view of a Git tree, so that the builder (the policy gate)
/// decides what of a Git commit enters the store.
struct GitTreeFs {
    git: Mutex<gix::Repository>,
    root: GitOid,
    dirs: Mutex<HashMap<GitOid, Arc<GitDir>>>,
    hints: HashMap<VPath, ObjectId>,
    /// Git blob → plain Veil blob id, for every blob read.
    learned: Mutex<Vec<(GitOid, ObjectId)>>,
    /// Symlinks and submodules met (Veil cannot record them).
    special: Mutex<BTreeSet<String>>,
}

impl std::fmt::Debug for GitTreeFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GitTreeFs({})", self.root)
    }
}

fn invalid(path: &VPath, why: &str) -> VeilError {
    VeilError::InvalidPath(format!("{path} {why}"))
}

impl GitTreeFs {
    fn new(git: gix::Repository, root: GitOid, hints: HashMap<VPath, ObjectId>) -> GitTreeFs {
        GitTreeFs {
            git: Mutex::new(git),
            root,
            dirs: Mutex::new(HashMap::new()),
            hints,
            learned: Mutex::new(Vec::new()),
            special: Mutex::new(BTreeSet::new()),
        }
    }

    fn object(&self, oid: &GitOid, kind: gix::objs::Kind) -> Result<Vec<u8>> {
        let git = self.git.lock().unwrap();
        let obj = git.find_object(*oid).map_err(gerr)?;
        if obj.kind != kind {
            return Err(gerr(format!("object {oid} is a {}, expected a {kind}", obj.kind)));
        }
        Ok(obj.data.clone())
    }

    fn dir(&self, oid: &GitOid) -> Result<Arc<GitDir>> {
        if let Some(d) = self.dirs.lock().unwrap().get(oid) {
            return Ok(d.clone());
        }
        let tree = if *oid == super::empty_tree_oid() {
            gix::objs::Tree::empty()
        } else {
            let data = self.object(oid, gix::objs::Kind::Tree)?;
            gix::objs::TreeRef::from_bytes(&data, gix::hash::Kind::Sha1)
                .map_err(gerr)?
                .into_owned()
        };
        let mut d = GitDir {
            entries: BTreeMap::new(),
            bad: Vec::new(),
        };
        for e in tree.entries {
            match String::from_utf8(e.filename.to_vec()) {
                Ok(name) if validate_entry_name(&name).is_ok() && !name.eq_ignore_ascii_case(".git") => {
                    d.entries.insert(name, (e.mode.kind(), e.oid));
                }
                Ok(name) => d.bad.push(name.escape_debug().to_string()),
                Err(_) => d.bad.push(e.filename.to_string().escape_debug().to_string()),
            }
        }
        let d = Arc::new(d);
        self.dirs.lock().unwrap().insert(*oid, d.clone());
        Ok(d)
    }

    fn resolve(&self, path: &VPath) -> Result<Option<(gix::objs::tree::EntryKind, GitOid)>> {
        let mut cur = (gix::objs::tree::EntryKind::Tree, self.root);
        for c in path.components() {
            if cur.0 != gix::objs::tree::EntryKind::Tree {
                return Ok(None);
            }
            match self.dir(&cur.1)?.entries.get(c) {
                Some(e) => cur = *e,
                None => return Ok(None),
            }
        }
        Ok(Some(cur))
    }
}

impl StorageBackend for GitTreeFs {
    fn kind(&self) -> &'static str {
        "git"
    }

    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        use gix::objs::tree::EntryKind as K;
        match self.resolve(path)? {
            Some((K::Blob | K::BlobExecutable, oid)) => {
                let data = self.object(&oid, gix::objs::Kind::Blob)?;
                self.learned.lock().unwrap().push((oid, Object::blob_id(&data)));
                Ok(data)
            }
            Some(_) => Err(invalid(path, "is not a regular file")),
            None => Err(VeilError::NotFound(path.to_string())),
        }
    }

    fn write(&self, _: &VPath, _: &[u8]) -> Result<()> {
        Err(VeilError::ReadOnly)
    }
    fn create_new(&self, _: &VPath, _: &[u8]) -> Result<bool> {
        Err(VeilError::ReadOnly)
    }
    fn remove_file(&self, _: &VPath) -> Result<()> {
        Err(VeilError::ReadOnly)
    }
    fn remove_dir_all(&self, _: &VPath) -> Result<()> {
        Err(VeilError::ReadOnly)
    }
    fn create_dir_all(&self, _: &VPath) -> Result<()> {
        Err(VeilError::ReadOnly)
    }
    fn set_executable(&self, _: &VPath, _: bool) -> Result<()> {
        Err(VeilError::ReadOnly)
    }

    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        Ok(self.list_dir_full(path)?.entries)
    }

    fn list_dir_full(&self, path: &VPath) -> Result<DirListing> {
        use gix::objs::tree::EntryKind as K;
        let oid = match self.resolve(path)? {
            Some((K::Tree, oid)) => oid,
            Some(_) => return Err(invalid(path, "is not a directory")),
            None => return Err(VeilError::NotFound(path.to_string())),
        };
        let d = self.dir(&oid)?;
        let mut out = DirListing::default();
        for (name, (kind, _)) in &d.entries {
            match kind {
                K::Tree => out.entries.push(DirEntry {
                    name: name.clone(),
                    kind: NodeKind::Dir,
                }),
                K::Blob | K::BlobExecutable => out.entries.push(DirEntry {
                    name: name.clone(),
                    kind: NodeKind::File,
                }),
                K::Link | K::Commit => {
                    self.special.lock().unwrap().insert(path.join(name).to_string());
                    out.special.push(name.clone());
                }
            }
        }
        for b in &d.bad {
            out.unrepresentable.push(if path.is_root() { b.clone() } else { format!("{path}/{b}") });
        }
        Ok(out)
    }

    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        use gix::objs::tree::EntryKind as K;
        Ok(match self.resolve(path)? {
            Some((K::Tree, _)) => Some(Metadata::unstamped(NodeKind::Dir, 0, false)),
            Some((K::Blob, _)) => Some(Metadata::unstamped(NodeKind::File, 0, false)),
            Some((K::BlobExecutable, _)) => Some(Metadata::unstamped(NodeKind::File, 0, true)),
            _ => None,
        })
    }

    fn known_id(&self, path: &VPath) -> Option<ObjectId> {
        self.hints.get(path).copied()
    }
}
