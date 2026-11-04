//! Snapshots → Git commits (see the module docs of [`super`]).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use super::{
    empty_tree_oid,
    map::{Current, GitOid, Origin},
    project::public_text,
    GitBridge,
};
use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    oplog::Tag,
    remote::{embargo_withheld, push_closure},
    repo::Repo,
};

/// Header carrying the Veil change id (the name Jujutsu uses).
pub const CHANGE_ID_HEADER: &str = "change-id";

#[derive(Debug, Default)]
pub struct ExportReport {
    /// Tag → commit for every exported tag (also written to
    /// `refs/heads/<tag>` in the bridge repository).
    pub branches: Vec<(String, GitOid)>,
    /// Tags not exported, with the reason.
    pub skipped: Vec<(String, String)>,
    /// New commits written (including publication commits).
    pub written: usize,
    /// Publication commits written because an embargo was released.
    pub published: usize,
    pub warnings: Vec<String>,
}

/// `Name <email>` → (name, email); anything else is a bare name. Characters
/// Git cannot carry in a signature are dropped.
pub(crate) fn split_author(author: &str) -> (String, String) {
    let clean = |s: &str| -> String {
        s.chars()
            .filter(|c| !matches!(c, '<' | '>' | '\n' | '\r' | '\0'))
            .collect::<String>()
            .trim()
            .to_string()
    };
    if let Some(rest) = author.trim().strip_suffix('>') {
        if let Some(i) = rest.rfind('<') {
            return (clean(&rest[..i]), clean(&rest[i + 1..]));
        }
    }
    (clean(author), String::new())
}

fn signature(author: &str, millis: i64) -> gix::actor::Signature {
    let (name, email) = split_author(author);
    gix::actor::Signature {
        name: if name.is_empty() { "unknown".into() } else { name.into() },
        email: email.into(),
        time: gix::date::Time {
            seconds: millis.div_euclid(1000),
            offset: 0,
        },
    }
}

fn message(text: &str) -> String {
    let t = text.trim_end_matches('\n');
    if t.is_empty() {
        String::new()
    } else {
        format!("{t}\n")
    }
}

impl GitBridge {
    /// Export tags (all by default) and the history a public remote would
    /// receive. Holds the repository lock throughout; records nothing in
    /// the operation log.
    pub fn export(&mut self, repo: &mut Repo, only_tags: &[String]) -> Result<ExportReport> {
        let tx = repo.transaction("git export")?;
        let report = self.export_in(tx.repo(), only_tags)?;
        self.save(&**tx.repo().backend())?;
        tx.commit()?;
        Ok(report)
    }

    fn export_in(&mut self, repo: &Repo, only_tags: &[String]) -> Result<ExportReport> {
        let mut report = ExportReport::default();
        for t in only_tags {
            if !repo.view().tags.contains_key(t) {
                return Err(VeilError::NotFound(format!("tag '{t}'")));
            }
        }
        let root = repo.root_id();
        let withheld = embargo_withheld(repo, true)?;
        let mut selected: Vec<(String, Tag)> = Vec::new();
        for (name, tag) in &repo.view().tags {
            if !only_tags.is_empty() && !only_tags.contains(name) {
                continue;
            }
            if tag.cloak.is_some() {
                report
                    .skipped
                    .push((name.clone(), "cloaked tag is never exported to Git".into()));
                continue;
            }
            if tag.target == root {
                report.skipped.push((name.clone(), "points at the root".into()));
                continue;
            }
            if gix::refs::FullName::try_from(format!("refs/heads/{name}")).is_err() {
                report.skipped.push((name.clone(), "not a valid Git branch name".into()));
                continue;
            }
            match push_closure(repo.store(), repo.keys(), &[tag.target], &withheld)? {
                Ok(_) => selected.push((name.clone(), tag.clone())),
                Err(why) => report.skipped.push((name.clone(), why)),
            }
        }
        let tips: Vec<ObjectId> = selected.iter().map(|(_, t)| t.target).collect();
        let closure: HashSet<ObjectId> = push_closure(repo.store(), repo.keys(), &tips, &withheld)?
            .map_err(|why| VeilError::repo(format!("git export: {why}")))?
            .into_iter()
            .collect();
        let order = repo.topo_children_first(tips.iter().copied())?;
        for sid in order.into_iter().rev().filter(|s| closure.contains(s)) {
            self.export_snapshot(repo, sid, &withheld, &mut report)?;
        }
        for (name, tag) in selected {
            let Some(commit) = self.commit_of(&tag.target) else {
                report.skipped.push((name, "nothing to export".into()));
                continue;
            };
            self.set_ref(&format!("refs/heads/{name}"), commit)?;
            report.branches.push((name, commit));
        }
        report.warnings.append(&mut self.warnings);
        report.warnings.sort();
        report.warnings.dedup();
        Ok(report)
    }

    /// The Git tree of snapshot tree `tree` as a public reader sees it,
    /// and the unreleased embargoes that shaped it.
    fn public_git_tree(&mut self, repo: &Repo, tree: &ObjectId) -> Result<(GitOid, BTreeSet<String>)> {
        let p = self.project(repo.store(), tree)?;
        let oid = match p.tree {
            Some(t) => self.git_tree(repo.store(), &t)?,
            None => self.write_tree(gix::objs::Tree::empty())?,
        };
        Ok((oid, p.pending))
    }

    fn export_snapshot(
        &mut self,
        repo: &Repo,
        sid: ObjectId,
        withheld: &HashMap<ObjectId, String>,
        report: &mut ExportReport,
    ) -> Result<()> {
        if sid == repo.root_id() {
            return Ok(());
        }
        let mut old = None;
        if let Some(cur) = self.map.current.get(&sid).cloned() {
            if self.has_object(&cur.commit) {
                // Commits that came from Git are the truth for their
                // snapshot. Exported ones stay pinned unless an embargo that
                // shaped them has been released since.
                if cur.origin == Origin::Imported || !cur.pending.iter().any(|e| repo.keys().embargo_released(e)) {
                    return Ok(());
                }
                old = Some(cur);
            } else {
                self.map.forget_current(&sid);
            }
        }
        let s = repo.snapshot(&sid)?;
        let mut pending = BTreeSet::new();
        // Parents as Git sees them: withheld (redacted) and absent ones are
        // dropped; the root is not a commit.
        let mut parents: Vec<GitOid> = Vec::new();
        let mut first: Option<(ObjectId, GitOid)> = None;
        for p in &s.parents {
            if *p == repo.root_id() {
                continue;
            }
            if let Some(e) = withheld.get(p) {
                pending.insert(e.clone());
                continue;
            }
            let Some(c) = self.commit_of(p) else { continue };
            if first.is_none() {
                first = Some((*p, c));
            }
            if !parents.contains(&c) {
                parents.push(c);
            }
        }
        let (theirs, tree_pending) = self.public_git_tree(repo, &s.tree)?;
        pending.extend(tree_pending);
        // Paths Git has but Veil never recorded (committed to Git while
        // isolated or quarantined in Veil, symlinks, submodules) survive.
        let tree = match first {
            None => theirs,
            Some((p, pc)) => {
                let ours = self.read_commit(&pc)?.tree;
                let (base, _) = self.public_git_tree(repo, &repo.snapshot(&p)?.tree)?;
                self.carry(Some(base), Some(ours), Some(theirs))?.unwrap_or_else(empty_tree_oid)
            }
        };
        let (text, text_pending) = public_text(repo.store(), &s.description);
        pending.extend(text_pending);
        let sig = signature(&s.author, s.timestamp);

        let (commit, origin) = match old {
            None => (
                gix::objs::Commit {
                    tree,
                    parents: parents.into_iter().collect(),
                    author: sig.clone(),
                    committer: sig,
                    encoding: None,
                    message: message(&text).into(),
                    extra_headers: vec![(CHANGE_ID_HEADER.into(), s.change_id.display().into())],
                },
                Origin::Exported,
            ),
            Some(old) => {
                let oc = self.read_commit(&old.commit)?;
                if oc.tree == tree && parents.iter().all(|p| oc.parents.contains(p)) {
                    // The release changed nothing Git can see.
                    self.map.record(
                        sid,
                        Current {
                            commit: old.commit,
                            origin: old.origin,
                            pending,
                        },
                    );
                    return Ok(());
                }
                let released: Vec<&String> = old.pending.iter().filter(|e| !pending.contains(*e)).collect();
                let mut ps = vec![old.commit];
                ps.extend(parents.into_iter().filter(|p| !oc.parents.contains(p) && *p != old.commit));
                let body = format!(
                    "{}\n(Published by Veil: released from embargo {}.)",
                    message(&text),
                    released.iter().map(|e| e.as_str()).collect::<Vec<_>>().join(", ")
                );
                report.published += 1;
                (
                    gix::objs::Commit {
                        tree,
                        parents: ps.into_iter().collect(),
                        author: sig.clone(),
                        committer: sig,
                        encoding: None,
                        message: message(&body).into(),
                        extra_headers: vec![],
                    },
                    Origin::Published,
                )
            }
        };
        let oid = self.write_commit(&commit)?;
        report.written += 1;
        self.map.record(sid, Current { commit: oid, origin, pending });
        Ok(())
    }

    /// Three-way carry-over of Git trees: Veil's change (`base` → `theirs`)
    /// applied to Git's state (`ours`), path by path. Paths Veil did not
    /// change keep Git's version; paths Veil changed take Veil's (a
    /// deletion included).
    pub(crate) fn carry(&self, b: Option<GitOid>, o: Option<GitOid>, t: Option<GitOid>) -> Result<Option<GitOid>> {
        let norm = |x: Option<GitOid>| x.filter(|x| *x != empty_tree_oid());
        let (b, o, t) = (norm(b), norm(o), norm(t));
        if o == b || o == t {
            return Ok(t);
        }
        if t == b {
            return Ok(o);
        }
        type Entries = BTreeMap<Vec<u8>, gix::objs::tree::Entry>;
        let load = |x: Option<GitOid>| -> Result<Entries> {
            Ok(match x {
                Some(x) => self
                    .read_tree(&x)?
                    .entries
                    .into_iter()
                    .map(|e| (e.filename.to_vec(), e))
                    .collect(),
                None => BTreeMap::new(),
            })
        };
        let (be, oe, te) = (load(b)?, load(o)?, load(t)?);
        let names: BTreeSet<&Vec<u8>> = be.keys().chain(oe.keys()).chain(te.keys()).collect();
        let same = |x: Option<&gix::objs::tree::Entry>, y: Option<&gix::objs::tree::Entry>| match (x, y) {
            (None, None) => true,
            (Some(x), Some(y)) => x.mode == y.mode && x.oid == y.oid,
            _ => false,
        };
        let tree_or_none = |x: Option<&gix::objs::tree::Entry>| x.is_none_or(|e| e.mode.is_tree());
        let mut out = Vec::new();
        for name in names {
            let (bx, ox, tx) = (be.get(name), oe.get(name), te.get(name));
            let pick = if same(tx, bx) {
                ox.cloned()
            } else if same(ox, bx) {
                tx.cloned()
            } else if ox.is_some() && tree_or_none(bx) && tree_or_none(ox) && tree_or_none(tx) {
                self.carry(bx.map(|e| e.oid), ox.map(|e| e.oid), tx.map(|e| e.oid))?
                    .map(|oid| gix::objs::tree::Entry {
                        mode: gix::objs::tree::EntryKind::Tree.into(),
                        filename: name.as_slice().into(),
                        oid,
                    })
            } else {
                tx.cloned()
            };
            out.extend(pick);
        }
        if out.is_empty() {
            return Ok(None);
        }
        out.sort();
        Ok(Some(self.write_tree(gix::objs::Tree { entries: out })?))
    }
}
