//! Git commits → snapshots, with carry-over of everything Git never saw.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::{Arc, Mutex},
};

use super::{
    export::CHANGE_ID_HEADER,
    gerr,
    map::{GitOid, Origin},
    project::{gitlink_content, is_git_dir_name, public_open, public_text, Public, Veil},
    short, GitBridge,
};
use crate::{
    builder::{build_tree, BuildOptions},
    embargo::policy_rekeys,
    error::{Result, VeilError},
    id::{ChangeId, ObjectId},
    merge::merge_trees,
    object::{validate_entry_name, EntryKind, Object, Snapshot, Text, Tree, TreeEntry, Visibility, GIT_PARITY_REPO_FORMAT},
    policy::{Policy, Tier, POLICY_FILE},
    repo::Repo,
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

/// The change id a `change-id` header claims (Jujutsu, or a Veil export).
fn header_change_id(commit: &gix::objs::Commit) -> Option<ChangeId> {
    commit
        .extra_headers
        .iter()
        .find(|(k, _)| k == CHANGE_ID_HEADER)
        .and_then(|(_, v)| std::str::from_utf8(v).ok())
        .and_then(|v| ChangeId::parse(v.trim()).ok())
        .filter(|c| *c != ChangeId::ROOT)
}

/// The change id of a Git commit whose header cannot be trusted (or that
/// has none): derived from the commit id, so importing the same commit
/// twice gives the same change, and nothing else can claim it.
fn derived_change_id(oid: &GitOid) -> ChangeId {
    let h = blake3::derive_key(crate::crypto::domains::GIT_CHANGE_ID, oid.as_bytes());
    ChangeId(h[..16].try_into().unwrap())
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

/// Errors that are about this machine, not about the Git data: they abort
/// the whole import. Anything else (a hostile tree, an unreadable commit, a
/// policy refusal) fails only the commit concerned and its descendants.
fn is_fatal(e: &VeilError) -> bool {
    matches!(e, VeilError::Io { .. } | VeilError::Locked(_) | VeilError::ReadOnly)
}

/// Visible snapshots by change id, built on first use during one import.
#[derive(Default)]
struct ChangeIndex(Option<HashMap<ChangeId, Vec<ObjectId>>>);

impl ChangeIndex {
    fn get(&mut self, repo: &Repo, c: &ChangeId) -> Result<Vec<ObjectId>> {
        if self.0.is_none() {
            let mut m: HashMap<ChangeId, Vec<ObjectId>> = HashMap::new();
            for id in repo.visible_snapshots()? {
                m.entry(repo.snapshot(&id)?.change_id).or_default().push(id);
            }
            self.0 = Some(m);
        }
        Ok(self.0.as_ref().unwrap().get(c).cloned().unwrap_or_default())
    }

    fn add(&mut self, c: ChangeId, id: ObjectId) {
        if let Some(m) = &mut self.0 {
            m.entry(c).or_default().push(id);
        }
    }
}

/// Every subset of `items` (at most 2^4 of them; beyond that, only the
/// empty set and the whole), smallest first.
fn subsets(items: &[String]) -> Vec<BTreeSet<String>> {
    if items.len() > 4 {
        return vec![BTreeSet::new(), items.iter().cloned().collect()];
    }
    let mut out: Vec<BTreeSet<String>> = (0..1u32 << items.len())
        .map(|m| (0..items.len()).filter(|i| m & (1 << i) != 0).map(|i| items[i].clone()).collect())
        .collect();
    out.sort_by_key(|s| s.len());
    out
}

/// The symlinks and gitlinks below a Git tree: (path, kind, oid).
pub(crate) type GitLinks = Arc<Vec<(String, gix::objs::tree::EntryKind, GitOid)>>;

/// Where the commits the bridge imports come from (`GitBridge::import_tips`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportOrigin {
    /// Fetched from a Git remote: everything Veil holds that Git never saw
    /// is carried over.
    Remote,
    /// Made in a colocated `.git` on this machine (stream C).
    Local,
}

/// What [`GitBridge::import_one`] did with a commit.
enum Imported {
    New,
    /// Already in Veil: Veil's own export, or an earlier import of it.
    Known,
}

impl GitBridge {
    /// Import every commit reachable from `tips` that is not mapped yet,
    /// parents first. A commit that cannot be imported (a hostile or
    /// unreadable tree, its parent under an embargo whose key we lack, …) is
    /// reported with the reason, together with its descendants; the other
    /// commits are imported, and nothing is half-imported.
    pub(crate) fn import_tips(&mut self, tx: &mut Transaction<'_>, tips: &[GitOid], origin: ImportOrigin) -> Result<ImportReport> {
        // Only commits fetched from a Git remote are imported today; the
        // colocated mode (stream C) gives `Local` its carry-over rule.
        let ImportOrigin::Remote = origin else {
            return Err(VeilError::Unsupported("importing local Git commits is not implemented yet".into()));
        };
        let mut report = ImportReport::default();
        let mut index = ChangeIndex::default();
        // Failed commits → the root cause.
        let mut failed: HashMap<GitOid, String> = HashMap::new();
        let mut todo: HashMap<GitOid, gix::objs::Commit> = HashMap::new();
        let mut stack: Vec<GitOid> = tips.to_vec();
        while let Some(c) = stack.pop() {
            if todo.contains_key(&c) || failed.contains_key(&c) || self.mapped(tx, &c)?.is_some() {
                continue;
            }
            match self.read_commit(&c) {
                Ok(commit) => {
                    stack.extend(commit.parents.iter().copied());
                    todo.insert(c, commit);
                }
                Err(e) if is_fatal(&e) => return Err(e),
                Err(e) => {
                    report.failed.push((c, e.to_string()));
                    failed.insert(c, e.to_string());
                }
            }
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
        while let Some(k) = ready.pop_first() {
            let c = k.1;
            let commit = &todo[&c];
            if let Some(p) = commit.parents.iter().find(|p| failed.contains_key(*p)) {
                let root = failed[p].clone();
                report
                    .failed
                    .push((c, format!("its parent {} was not imported ({root})", short(p))));
                failed.insert(c, root);
            } else {
                match self.import_one(tx, &c, commit, &mut report, &mut index) {
                    Ok(Imported::New) => report.imported += 1,
                    Ok(Imported::Known) => {}
                    Err(e) if is_fatal(&e) => return Err(e),
                    Err(e) => {
                        let why = match e {
                            VeilError::Policy(why) => why,
                            e => e.to_string(),
                        };
                        report.failed.push((c, why.clone()));
                        failed.insert(c, why);
                    }
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

    /// Is `commit` a commit Veil itself exported (or published), whose
    /// mapping was lost or never made on this machine (another replica
    /// exported it)? Recognised by exporting the candidate snapshot again
    /// and comparing commit ids, so nothing but the exact commit matches: a
    /// `change-id` header alone proves nothing. `git_parents` are the
    /// snapshots of the commit's Git parents, in order. Returns the
    /// snapshot, the origin, and the embargoes veiled in the commit's view.
    fn recognise_export(
        &mut self,
        repo: &Repo,
        oid: &GitOid,
        commit: &gix::objs::Commit,
        git_parents: &[ObjectId],
        index: &mut ChangeIndex,
    ) -> Result<Option<(ObjectId, Origin, BTreeSet<String>)>> {
        let distinct = commit.parents.iter().collect::<HashSet<_>>().len() == commit.parents.len();
        if !distinct {
            return Ok(None);
        }
        if let Some(h) = header_change_id(commit) {
            for cand in index.get(repo, &h)? {
                let s = repo.snapshot(&cand)?;
                if !git_parents.iter().all(|p| s.parents.contains(p)) {
                    continue;
                }
                let first = commit.parents.first().map(|c| (git_parents[0], *c));
                let parents: Vec<GitOid> = commit.parents.to_vec();
                // As exported now, then as exported before releases that
                // shaped it.
                let (c, pending) = self.with_veil(Veil::default(), |b| b.fresh_commit(repo, &s, first, parents.clone()))?;
                if Self::commit_id(&c)? == *oid {
                    return Ok(Some((cand, Origin::Exported, pending)));
                }
                for veil in self.released_veils(repo, &s, first.map(|f| f.0))? {
                    let (c, pending) = self.with_veil(veil, |b| b.fresh_commit(repo, &s, first, parents.clone()))?;
                    if Self::commit_id(&c)? == *oid {
                        return Ok(Some((cand, Origin::Exported, pending)));
                    }
                }
            }
            return Ok(None);
        }
        // A publication commit: on top of a commit whose view a release
        // has changed since.
        let Some(c0) = commit.parents.first() else { return Ok(None) };
        let old_veiled = self.map.veiled(c0);
        let released: Vec<String> = old_veiled
            .iter()
            .filter(|e| repo.keys().embargo_released(e))
            .cloned()
            .collect();
        if released.is_empty() {
            return Ok(None);
        }
        let sid = git_parents[0];
        let s = repo.snapshot(&sid)?;
        if !git_parents[1..].iter().all(|p| s.parents.contains(p)) {
            return Ok(None);
        }
        let oc = self.read_commit(c0)?;
        let still: BTreeSet<String> = old_veiled.iter().filter(|e| !released.contains(e)).cloned().collect();
        for kept in subsets(&released) {
            if kept.len() == released.len() {
                continue;
            }
            let mut set = still.clone();
            set.extend(kept);
            let extra = commit.parents[1..].to_vec();
            let (c, pending) = self.with_veil(Veil::of(set), |b| {
                b.publication_commit(repo, &s, *c0, &oc, &old_veiled, extra, BTreeSet::new())
            })?;
            if let Some(c) = c {
                if Self::commit_id(&c)? == *oid {
                    return Ok(Some((sid, Origin::Published, pending)));
                }
            }
        }
        Ok(None)
    }

    /// Veils to try when re-exporting `s` as it was exported before some
    /// release: every combination of the released embargoes that shape its
    /// view (or its first parent's), none-veiled excluded.
    fn released_veils(&mut self, repo: &Repo, s: &Snapshot, first: Option<ObjectId>) -> Result<Vec<Veil>> {
        if !repo.keys().embargoes()?.iter().any(|r| repo.keys().embargo_released(&r.id)) {
            return Ok(Vec::new());
        }
        let store = repo.store().clone();
        let mut shaping = self.with_veil(Veil::all(), |b| {
            let mut p = b.project(&store, &s.tree)?.pending;
            if let Some(f) = first {
                p.extend(b.project(&store, &repo.snapshot(&f)?.tree)?.pending);
            }
            p.extend(public_text(&store, &b.veil, &s.description).1);
            Ok(p)
        })?;
        shaping.extend(s.embargo.clone());
        let released: Vec<String> = shaping.into_iter().filter(|e| repo.keys().embargo_released(e)).collect();
        Ok(subsets(&released)
            .into_iter()
            .filter(|v| !v.is_empty())
            .map(Veil::of)
            .collect())
    }

    fn import_one(
        &mut self,
        tx: &mut Transaction<'_>,
        oid: &GitOid,
        commit: &gix::objs::Commit,
        report: &mut ImportReport,
        index: &mut ChangeIndex,
    ) -> Result<Imported> {
        let store = tx.repo().store().clone();
        let mut git_parents: Vec<ObjectId> = Vec::new();
        for p in &commit.parents {
            let sid = self
                .mapped(tx, p)?
                .ok_or_else(|| VeilError::repo(format!("git import: parent {} of {} is not mapped", short(p), short(oid))))?;
            git_parents.push(sid);
        }
        // Veil's own commit, exported here or by another replica.
        if let Some((sid, origin, veiled)) = self.recognise_export(tx.repo(), oid, commit, &git_parents, index)? {
            self.map.record_found(*oid, sid, origin, veiled, commit.parents.first().copied());
            return Ok(Imported::Known);
        }
        let mut parents: Vec<ObjectId> = Vec::new();
        for sid in git_parents {
            if !parents.contains(&sid) {
                parents.push(sid);
            }
        }
        if parents.is_empty() {
            parents.push(tx.repo().root_id());
        }
        let (author, timestamp) = author_of(commit);
        let text = String::from_utf8_lossy(&commit.message).trim_end_matches('\n').to_string();
        let same_commit = |s: &Snapshot| {
            s.parents == parents && s.author == author && s.timestamp == timestamp && s.description == Text::Plain(text.clone())
        };
        // What this commit's author saw of its parents: the view their
        // commits show. After an embargo release, a commit made on top of
        // the pre-release view (the merge as exported before, or a Git
        // commit made on it) still shows the pre-fix files: against the
        // released tree they would read as a revert of the fix.
        let mut veil = Veil::default();
        for p in &commit.parents {
            veil.set.extend(self.map.veiled(p));
        }
        // An earlier import of this very commit (its mapping was lost): the
        // derived change id is a function of the commit id.
        let derived = derived_change_id(oid);
        for x in index.get(tx.repo(), &derived)? {
            let s = tx.repo().snapshot(&x)?;
            if same_commit(&s) {
                let veiled = self.with_veil(veil.clone(), |b| b.project(&store, &s.tree))?.pending;
                self.map.record_import(*oid, x, veiled);
                return Ok(Imported::Known);
            }
        }
        let held = |e: VeilError| match e {
            VeilError::Policy(why) => VeilError::Policy(format!("held back: {why}")),
            e => e,
        };
        // What Veil holds for the parents (with everything Git never saw) …
        let outcome = tx.repo().parents_tree(&parents).map_err(held)?;
        let ours = outcome.tree;
        // … what Git saw of it …
        let base = match self.with_veil(veil.clone(), |b| b.project(&store, &ours))?.tree {
            Some(t) => t,
            None => store.empty_tree()?,
        };
        // … and the Git commit, through the policy gate.
        let hints = self.import_hints(&store, &base, &commit.tree)?;
        let fs = GitTreeFs::new(self.git.clone(), commit.tree, hints);
        // A Git commit whose `.veilpolicy` is not a regular file is
        // refused, and its branch named with the reason (BUG-058); other
        // branches import as usual.
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
                line_base: None,
                // Git blobs (and patched recorded bytes) are recorded as
                // they are: line endings are a working-copy matter.
                line_endings: crate::builder::LineEndings::Off,
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
        let links = store.format() >= GIT_PARITY_REPO_FORMAT;
        let special = fs.special.into_inner().unwrap();
        for p in build.unrepresentable.iter().chain(special.iter().filter(|_| !links)) {
            report.left_in_git.insert(p.clone(), "not representable in Veil".into());
        }
        // Format 5: Git's symlinks and submodules, through the same gate.
        let theirs = if links {
            self.import_links(&store, &policy, &commit.tree, theirs, report)?
        } else {
            theirs
        };
        let theirs = self.guard_policy(&store, oid, &ours, &base, theirs, report)?;
        let merged = merge_trees(&store, Some(base), ours, theirs).map_err(held)?;
        let mut conflicts: BTreeSet<String> = outcome.conflicts.iter().map(|p| p.to_string()).collect();
        conflicts.extend(merged.conflicts.iter().map(|p| p.to_string()));
        // The embargoes unreleased in the view this commit shows.
        let veiled = self.with_veil(veil, |b| b.project(&store, &merged.tree))?.pending;
        // A `change-id` header is taken only if no visible change has that
        // id: a commit from Git must never make one of the user's changes
        // divergent (a forged header), and Veil's own commits were
        // recognised above.
        let change_id = match header_change_id(commit) {
            Some(h) => {
                let holders = index.get(tx.repo(), &h)?;
                for x in &holders {
                    let s = tx.repo().snapshot(x)?;
                    if same_commit(&s) && s.tree == merged.tree {
                        // Imported before (the mapping was lost).
                        self.map.record_import(*oid, *x, veiled);
                        return Ok(Imported::Known);
                    }
                }
                if holders.is_empty() {
                    h
                } else {
                    report.warnings.push(format!(
                        "Git commit {} claims change id {} of an existing change; imported as a change of its own",
                        short(oid),
                        h.short()
                    ));
                    derived
                }
            }
            None => derived,
        };
        if !conflicts.is_empty() {
            report.conflicts.push((*oid, conflicts.iter().cloned().collect()));
        }
        let snap = Snapshot {
            parents,
            change_id,
            tree: merged.tree,
            description: Text::Plain(text),
            author,
            timestamp,
            predecessors: vec![],
            conflicts: conflicts.into_iter().collect(),
            cloak: None,
            embargo: None,
            signature: None,
        };
        // Unsigned, so that the snapshot is a function of the Git commit
        // and what Veil holds for its parents: every member who imports the
        // same commit gets the same snapshot id (BUG-285). A signature
        // would say who imported it, and two members' imports would then
        // be two divergent copies of one change.
        let sid = tx.write_unsigned_snapshot(&snap)?;
        index.add(change_id, sid);
        self.map.record_import(*oid, sid, veiled);
        Ok(Imported::New)
    }

    /// Format 5: the symlinks (mode `120000`) and submodules (`160000`) of
    /// Git tree `git_tree`, recorded in `theirs` (the builder's tree of the
    /// commit, which never reads them). Each is classified by its own path
    /// like a file: ignored and isolated ones stay in Git, a cloaked one is
    /// sealed under its scope (its target can name private paths), and a
    /// public symlink's target is secret-scanned (`https://u:token@…`).
    /// Link entries the builder carried from the parent are replaced by
    /// what Git holds now: Git is the truth for this commit.
    fn import_links(
        &mut self,
        store: &ObjectStore,
        policy: &Policy,
        git_tree: &GitOid,
        theirs: ObjectId,
        report: &mut ImportReport,
    ) -> Result<ObjectId> {
        let mut carried: BTreeMap<String, TreeEntry> = BTreeMap::new();
        self.veil_links(store, &theirs, &mut String::new(), &mut carried, 0)?;
        let found = self.git_links(git_tree, 0)?;
        if carried.is_empty() && found.is_empty() {
            return Ok(theirs);
        }
        let mut edits: BTreeMap<String, Option<TreeEntry>> = carried.keys().map(|p| (p.clone(), None)).collect();
        'links: for (path, kind, oid) in found.iter() {
            let Ok(vp) = VPath::new(path) else {
                report.left_in_git.insert(path.clone(), "not representable in Veil".into());
                continue;
            };
            // Below an ignored or isolated directory, or ignored or
            // isolated itself: never recorded, as for files.
            let mut dir = vp.parent();
            while let Some(d) = dir.filter(|d| !d.is_root()) {
                if matches!(policy.classify(&d, true).tier, Tier::Ignored | Tier::Isolated) {
                    continue 'links;
                }
                dir = d.parent();
            }
            let class = policy.classify(&vp, false);
            let scope = match &class.tier {
                Tier::Ignored => continue,
                Tier::Isolated => {
                    report.left_in_git.insert(path.clone(), "isolated by policy".into());
                    continue;
                }
                Tier::Cloaked(s) => Some(s.clone()),
                Tier::Public => None,
            };
            let (ekind, content) = match kind {
                gix::objs::tree::EntryKind::Commit => (EntryKind::Gitlink, gitlink_content(oid)),
                _ => {
                    // A symlink: its target is the blob, read with a size
                    // check first (a hostile remote can send anything).
                    let target = match self.link_target(oid) {
                        Ok(t) => t,
                        Err(why) => {
                            report.left_in_git.insert(path.clone(), why);
                            continue;
                        }
                    };
                    if vp.file_name().eq_ignore_ascii_case(".gitmodules") {
                        report
                            .left_in_git
                            .insert(path.clone(), "a symlinked .gitmodules is refused (as Git does)".into());
                        continue;
                    }
                    if scope.is_none() && !class.allow_secrets {
                        let findings = crate::secrets::scan(&target);
                        if let Some(f) = findings.first() {
                            report.left_in_git.insert(path.clone(), format!("quarantined ({})", f.rule));
                            continue;
                        }
                    }
                    (EntryKind::Symlink, target)
                }
            };
            // The parent's entry, if it holds exactly this: kept as it is
            // (a sealed one keeps its sealing).
            if let Some(c) = carried.get(path) {
                let same = c.kind == ekind
                    && match &scope {
                        None => c.visibility.is_public() && c.id == Object::blob_id(&content),
                        Some(s) => {
                            c.visibility == (Visibility::Cloaked { scope: s.clone() })
                                && store.matches_encoding(&c.id, &content).unwrap_or(false)
                        }
                    };
                if same {
                    edits.remove(path);
                    continue;
                }
            }
            let vis = match &scope {
                None => Visibility::Public,
                Some(s) => Visibility::Cloaked { scope: s.clone() },
            };
            let id = match store.store_file(&content, &vis) {
                Ok(id) => id,
                Err(VeilError::Redacted { scope }) => {
                    report.left_in_git.insert(path.clone(), format!("no key for scope '{scope}'"));
                    continue;
                }
                Err(e) => return Err(e),
            };
            let entry = TreeEntry {
                name: vp.file_name().to_string(),
                kind: ekind,
                id,
                size: content.len() as u64,
                executable: false,
                visibility: vis,
                fallback: None,
            };
            edits.insert(path.clone(), Some(entry));
        }
        if edits.is_empty() {
            return Ok(theirs);
        }
        let edits: Vec<(VPath, Option<TreeEntry>)> = edits
            .into_iter()
            .map(|(p, e)| Ok((VPath::new(&p)?, e)))
            .collect::<Result<_>>()?;
        crate::selection::edit_tree(store, &theirs, edits)
    }

    /// The target bytes of the Git symlink blob `oid`, or why it cannot be
    /// a Veil symlink: over 4 KiB (`PATH_MAX`), empty, holding a NUL, or not
    /// UTF-8.
    fn link_target(&self, oid: &GitOid) -> std::result::Result<Vec<u8>, String> {
        const MAX_TARGET: usize = 4096;
        let header = self.git.find_header(*oid).map_err(|e| format!("unreadable symlink: {e}"))?;
        if header.kind() != gix::objs::Kind::Blob {
            return Err("a symlink that is not a blob".into());
        }
        if header.size() > MAX_TARGET as u64 {
            return Err(format!("symlink target over {MAX_TARGET} bytes"));
        }
        let data = self.read_blob(oid).map_err(|e| e.to_string())?;
        if data.is_empty() || data.contains(&0) {
            return Err("symlink target is empty or holds a NUL".into());
        }
        if std::str::from_utf8(&data).is_err() {
            return Err("not representable in Veil (symlink target is not UTF-8)".into());
        }
        Ok(data)
    }

    /// Every symlink and gitlink below Veil tree `id` (`prefix` is its
    /// path), collected into `out`.
    fn veil_links(
        &mut self,
        store: &ObjectStore,
        id: &ObjectId,
        prefix: &mut String,
        out: &mut BTreeMap<String, TreeEntry>,
        depth: usize,
    ) -> Result<()> {
        if depth > crate::tree::MAX_TREE_DEPTH {
            return Ok(());
        }
        if self.no_links.contains(id) {
            return Ok(());
        }
        let tree = match public_open(store, &Veil::default(), id)? {
            Public::Visible { obj: Object::Tree(t), .. } => t,
            // A sealed or embargo-wrapped directory: the builder's tree of
            // a Git commit never holds one, only carried parent content.
            _ => return Ok(()),
        };
        let before = out.len();
        for e in &tree.entries {
            let len = prefix.len();
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(&e.name);
            match e.kind {
                EntryKind::Dir => self.veil_links(store, &e.id, prefix, out, depth + 1)?,
                EntryKind::Symlink | EntryKind::Gitlink => {
                    out.insert(prefix.clone(), e.clone());
                }
                _ => {}
            }
            prefix.truncate(len);
        }
        if out.len() == before {
            self.no_links.insert(*id);
        }
        Ok(())
    }

    /// Every symlink and gitlink of Git tree `oid` the builder could have
    /// reached (valid names, not below `.git` spellings or a nested Veil
    /// repository), as (path, kind, oid). Memoised per tree for the run.
    fn git_links(&mut self, oid: &GitOid, depth: usize) -> Result<GitLinks> {
        use gix::objs::tree::EntryKind as K;
        if let Some(v) = self.git_link_memo.get(oid) {
            return Ok(v.clone());
        }
        let mut out = Vec::new();
        if depth <= crate::tree::MAX_TREE_DEPTH {
            let tree = self.read_tree(oid)?;
            let nested = depth > 0
                && tree
                    .entries
                    .iter()
                    .any(|e| e.mode.is_tree() && crate::object::is_reserved_name(&String::from_utf8_lossy(&e.filename)));
            if !nested {
                for e in &tree.entries {
                    let Ok(name) = std::str::from_utf8(&e.filename) else { continue };
                    if validate_entry_name(name).is_err() || is_git_dir_name(name) {
                        continue;
                    }
                    match e.mode.kind() {
                        K::Tree => {
                            for (p, k, o) in self.git_links(&e.oid, depth + 1)?.iter() {
                                out.push((format!("{name}/{p}"), *k, *o));
                            }
                        }
                        k @ (K::Link | K::Commit) => out.push((name.to_string(), k, e.oid)),
                        K::Blob | K::BlobExecutable => {}
                    }
                }
            }
        }
        let out = Arc::new(out);
        self.git_link_memo.insert(*oid, out.clone());
        Ok(out)
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
                Some(e) if e.kind != crate::object::EntryKind::File => Policy::builtin(),
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
    /// The directory holds a `.veil` directory: a Veil repository of its
    /// own, which the builder leaves out as a whole (BUG-200).
    nested: bool,
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
            nested: false,
        };
        for e in tree.entries {
            // Still listed as not representable (below): at the root that
            // is all it is; anywhere else the directory is left out whole.
            if e.mode.is_tree() && crate::object::is_reserved_name(&String::from_utf8_lossy(&e.filename)) {
                d.nested = true;
            }
            match String::from_utf8(e.filename.to_vec()) {
                Ok(name) if validate_entry_name(&name).is_ok() && !is_git_dir_name(&name) => {
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
        if d.nested {
            // Never listed as a directory: nothing may be read below it.
            out.special.push(crate::repo::VEIL_DIR.to_string());
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
