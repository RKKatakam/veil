//! Git tags ↔ release tags (repository format 5; feature 8 of the
//! Git-parity round, `docs/design/git-parity/8-bridge-tags.md`).
//!
//! A Veil tag with an annotation (`veil:atag`) is a **release tag**,
//! exported as `refs/tags/<name>` (`export.rs`); every other tag stays a
//! branch. Fetched Git tags are recorded per remote in
//! `View::remote_release_tags`, apart from the branches in `remote_tags`,
//! and a pull creates the local release tag only where none exists. Git
//! tags are immutable, so are release tags: nothing here ever moves a
//! local one, and a remote that moved one is reported (a supply-chain
//! warning), not followed.

use std::collections::{BTreeMap, HashSet};

use super::{map::GitOid, FetchReport, GitBridge};
use crate::{
    error::Result,
    id::ObjectId,
    object::Text,
    oplog::Tag,
    revset::RevisionNames,
    tag_object::{Atag, AtagKind, GitTagOrigin, MAX_GIT_TAG_RAW, MAX_TAGGER, MAX_TAG_MESSAGE},
    transaction::Transaction,
};

/// Deepest chain of tag objects followed (a tag of a tag of …).
pub(crate) const MAX_PEEL: usize = 8;

/// A fetched Git tag, peeled to its commit.
#[derive(Debug, Clone)]
pub(crate) struct Peeled {
    pub commit: GitOid,
    /// The outermost tag object (its id and raw bytes) for an annotated
    /// tag; `None` for a lightweight tag (the ref names the commit).
    pub object: Option<(GitOid, Vec<u8>)>,
    /// The tag object names the commit directly (no tag of a tag), so its
    /// raw bytes can be re-exported as they are.
    pub direct: bool,
}

/// What [`GitBridge::record_release_tags`] works from.
pub(crate) struct TagFetch<'a> {
    pub remote: &'a str,
    pub pull: bool,
    pub prune: bool,
    /// Tags were fetched (not `--no-tags`).
    pub fetched: bool,
    pub branches: &'a BTreeMap<String, GitOid>,
    pub tags_before: &'a BTreeMap<String, GitOid>,
    pub tags_after: &'a BTreeMap<String, GitOid>,
}

fn clean_tagger(name: &str, email: &str) -> String {
    let who = if email.is_empty() {
        name.trim().to_string()
    } else {
        format!("{} <{}>", name.trim(), email.trim())
    };
    who.chars().filter(|c| !c.is_control()).take(MAX_TAGGER).collect()
}

impl GitBridge {
    /// Peel Git ref value `oid` to a commit, through at most [`MAX_PEEL`]
    /// tag objects. `Err` names why the tag is skipped: a tag of a tree, a
    /// blob or a missing object, a chain too deep, or a tag object over
    /// the size limit (checked from the object header, before reading).
    pub(crate) fn peel_tag(&self, oid: &GitOid) -> Result<std::result::Result<Peeled, String>> {
        use gix::objs::Kind;
        let mut cur = *oid;
        let mut object: Option<(GitOid, Vec<u8>)> = None;
        for depth in 0..=MAX_PEEL {
            let header = match self.git.find_header(cur) {
                Ok(h) => h,
                Err(_) => return Ok(Err(format!("it names {}, which is missing", super::short(&cur)))),
            };
            match header.kind() {
                Kind::Commit => {
                    return Ok(Ok(Peeled {
                        commit: cur,
                        direct: depth <= 1,
                        object,
                    }))
                }
                Kind::Tag if depth == MAX_PEEL => break,
                Kind::Tag => {
                    if header.size() > MAX_GIT_TAG_RAW as u64 {
                        return Ok(Err(format!("its tag object is over {MAX_GIT_TAG_RAW} bytes")));
                    }
                    let data = self.find(&cur, Kind::Tag)?;
                    let target = match gix::objs::TagRef::from_bytes(&data, gix::hash::Kind::Sha1) {
                        Ok(t) => t.target(),
                        Err(_) => return Ok(Err("its tag object cannot be parsed".into())),
                    };
                    if object.is_none() {
                        object = Some((cur, data));
                    }
                    cur = target;
                }
                Kind::Tree => return Ok(Err("it points at a tree, not a commit".into())),
                Kind::Blob => return Ok(Err("it points at a blob, not a commit".into())),
            }
        }
        Ok(Err(format!("its chain of tag objects is deeper than {MAX_PEEL}")))
    }

    /// The atag a fetched Git tag `name` (peeled `p`, its commit imported
    /// as `sid`) becomes. Deterministic: two members who fetch the same tag
    /// get the same atag. `Err`: why it is skipped.
    fn atag_of_git_tag(&self, name: &str, sid: ObjectId, p: &Peeled) -> Result<std::result::Result<Atag, String>> {
        let Some((toid, raw)) = &p.object else {
            let time = self.read_commit(&p.commit)?.committer.time.seconds;
            return Ok(Ok(Atag {
                name: name.to_string(),
                target: sid,
                kind: AtagKind::LightweightGit,
                message: Text::Plain(String::new()),
                tagger: String::new(),
                timestamp: time.saturating_mul(1000),
                signature: None,
                git: None,
            }));
        };
        let t = match gix::objs::TagRef::from_bytes(raw, gix::hash::Kind::Sha1) {
            Ok(t) => t,
            Err(_) => return Ok(Err("its tag object cannot be parsed".into())),
        };
        if t.message.len() > MAX_TAG_MESSAGE {
            return Ok(Err(format!("its message is over {MAX_TAG_MESSAGE} bytes")));
        }
        let (tagger, seconds) = match t.tagger() {
            Ok(Some(sig)) => (
                clean_tagger(&sig.name.to_string(), &sig.email.to_string()),
                sig.time().map(|t| t.seconds).unwrap_or(0),
            ),
            _ => (String::new(), 0),
        };
        let message = String::from_utf8_lossy(t.message).trim_end_matches('\n').to_string();
        Ok(Ok(Atag {
            name: name.to_string(),
            target: sid,
            kind: AtagKind::Annotated,
            message: Text::Plain(message),
            tagger,
            timestamp: seconds.saturating_mul(1000),
            signature: None,
            git: p.direct.then(|| GitTagOrigin {
                oid: toid.to_string(),
                raw: hex::encode(raw),
            }),
        }))
    }

    /// The atag Git ref value `git` (on commit `commit`, snapshot `sid`)
    /// already is, if Veil knows it: from the map, or by exporting the
    /// local release tag of that name again (the map can be lost; a
    /// fetched tag equal to Veil's own export is never imported twice).
    fn known_atag(&self, tx: &Transaction<'_>, name: &str, git: &GitOid, commit: GitOid, sid: ObjectId) -> Option<ObjectId> {
        let store = tx.repo().store();
        let fits = |a: &ObjectId| store.atag(a).is_ok_and(|t| t.name == name && t.target == sid);
        if let Some(a) = self.map.tags.get(git).filter(|a| fits(a)) {
            return Some(*a);
        }
        let local = tx.view.tags.get(name)?.annotation?;
        let atag = store.atag(&local).ok()?;
        if atag.target != sid {
            return None;
        }
        let value = match self.release_tag_object(&atag, commit).ok()? {
            None => commit,
            Some((kind, data)) => gix::objs::compute_hash(gix::hash::Kind::Sha1, kind, &data).ok()?,
        };
        (value == *git).then_some(local)
    }

    /// Record the fetched tags `peeled` (see [`super::fetch_with`]).
    pub(crate) fn record_release_tags(
        &mut self,
        tx: &mut Transaction<'_>,
        ctx: &TagFetch<'_>,
        peeled: Vec<(String, GitOid, Peeled)>,
        revisions: &mut RevisionNames,
        report: &mut FetchReport,
    ) -> Result<()> {
        let remote = ctx.remote;
        let mut resolved: Vec<(String, ObjectId, ObjectId)> = Vec::new();
        for (name, git, p) in peeled {
            let Some(sid) = self.snapshot_of(&p.commit) else {
                let why = report
                    .import
                    .failed
                    .iter()
                    .find(|(c, _)| *c == p.commit)
                    .map(|(_, w)| w.clone())
                    .unwrap_or_else(|| "not imported".into());
                report
                    .tags_skipped
                    .push((name, format!("its commit {} was not imported: {why}", super::short(&p.commit))));
                continue;
            };
            let atag_id = match self.known_atag(tx, &name, &git, p.commit, sid) {
                Some(a) => a,
                None => match self.atag_of_git_tag(&name, sid, &p)? {
                    Ok(a) => tx.repo().store().put_atag(&a)?,
                    Err(why) => {
                        report.tags_skipped.push((name, why));
                        continue;
                    }
                },
            };
            self.map.record_tag(git, atag_id);
            resolved.push((name, sid, atag_id));
        }
        // Snapshots only a tag names stay visible.
        let mut visible: Option<HashSet<ObjectId>> = None;
        for (name, sid, atag_id) in &resolved {
            let key = format!("{remote}/{name}");
            let prev = tx.view.remote_release_tags.get(&key).copied();
            if prev == Some(*atag_id) {
                continue;
            }
            if let Some(old) = prev.and_then(|p| tx.repo().store().atag(&p).ok()) {
                if old.target != *sid {
                    report.tags_moved.push((name.clone(), old.target, *sid));
                }
            }
            tx.view.remote_release_tags.insert(key.clone(), *atag_id);
            report.release_tags.push((key, *atag_id));
            if visible.is_none() {
                let mut v = HashSet::new();
                for r in tx.view.refs() {
                    v.extend(tx.repo().ancestors(&r)?);
                }
                visible = Some(v);
            }
            if !visible.as_ref().unwrap().contains(sid) {
                tx.add_head(*sid)?;
                visible.as_mut().unwrap().extend(tx.repo().ancestors(sid)?);
            }
        }
        // Tags the remote deleted.
        if ctx.fetched {
            let prefix = format!("{remote}/");
            let recorded: Vec<String> = tx
                .view
                .remote_release_tags
                .keys()
                .filter_map(|k| k.strip_prefix(&prefix).map(str::to_string))
                .filter(|n| !ctx.tags_after.contains_key(n))
                .collect();
            for name in recorded {
                if ctx.prune {
                    tx.view.remote_release_tags.remove(&format!("{remote}/{name}"));
                    report.tags_pruned.push(name);
                } else if ctx.tags_before.contains_key(&name) {
                    report.tags_deleted.push(name);
                }
            }
        }
        if !ctx.pull {
            return Ok(());
        }
        // Local release tags: created where absent, never moved.
        let pairs: Vec<(String, ObjectId)> = resolved
            .iter()
            .filter(|(n, ..)| !ctx.branches.contains_key(n))
            .map(|(n, s, _)| (n.clone(), *s))
            .collect();
        let (stay_deleted, _) = crate::remote::tags_staying_deleted(tx, &pairs)?;
        for (name, sid, atag_id) in resolved {
            match tx.view.tags.get(&name).cloned() {
                None => {
                    if stay_deleted.contains(&name) {
                        continue;
                    }
                    if revisions.shadows(tx.repo(), || tx.repo().view().refs(), &name)? {
                        report.warnings.push(format!(
                            "no local tag created for Git tag '{name}': the name is also a change or snapshot id of this repository; use {remote}/{name}"
                        ));
                        continue;
                    }
                    tx.view.tags.insert(
                        name.clone(),
                        Tag {
                            target: sid,
                            cloak: None,
                            annotation: Some(atag_id),
                        },
                    );
                    report.release_tags_created.push((name, sid));
                }
                Some(t) if t.annotation == Some(atag_id) => {}
                Some(t) if t.annotation.is_some() => {
                    if t.target != sid {
                        report.release_tags_kept.push((name, t.target, sid));
                    }
                }
                Some(_) if ctx.branches.contains_key(&name) => report.warnings.push(format!(
                    "{remote} has both a branch and a tag named '{name}': local tag '{name}' follows the branch; the Git tag is recorded as {remote}/{name} (`vl tag list`)"
                )),
                Some(_) => report.warnings.push(format!(
                    "Git tag '{name}' is not a local release tag: a plain tag of that name exists here; the Git tag is recorded as {remote}/{name}"
                )),
            }
        }
        Ok(())
    }
}
