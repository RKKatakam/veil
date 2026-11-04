//! Revision expressions.
//!
//! ```text
//! @            working copy of the current workspace
//! name@        working copy of workspace `name`
//! root         the universal root snapshot
//! main         a tag;  origin/main  a remote tag
//! kxqz…        change-id prefix (letters k–z)
//! 3f9a…        snapshot-id prefix (hex)
//! X-  X--      first parent, grandparent, …
//! ```
//!
//! Tags are resolved before change ids, so a tag must never be named after
//! a change: `vl pull` and `vl git pull` do not create a local tag whose
//! name is a change-id or snapshot-id prefix of the repository
//! (`RevisionNames`, BUG-059 and BUG-105).
//!
//! A change id matching several visible snapshots is *divergent*. Change
//! ids are not secret (every reader of a remote sees them), so anyone who
//! can push may publish a snapshot carrying someone else's change id. When
//! exactly one of a change's snapshots is local history (reachable from
//! this repository's own heads or working copies) and the others are only
//! reachable through tags, the change resolves to the local one: a pushed
//! snapshot can make a change id point nowhere new (BUG-105). The others
//! keep their snapshot ids and tags.

use crate::{
    error::{Result, VeilError},
    id::{ChangeId, ObjectId},
    repo::Repo,
};

pub fn resolve(repo: &Repo, spec: &str, current_ws: &str) -> Result<ObjectId> {
    let spec = spec.trim();
    let base = spec.trim_end_matches('-');
    let up = spec.len() - base.len();
    if base.is_empty() {
        return Err(VeilError::Revset(format!("empty revision '{spec}'")));
    }
    let mut id = resolve_base(repo, base, current_ws)?;
    for _ in 0..up {
        let s = repo.snapshot(&id)?;
        id = *s
            .parents
            .first()
            .ok_or_else(|| VeilError::Revset(format!("'{spec}' walks past the root")))?;
    }
    Ok(id)
}

fn resolve_base(repo: &Repo, base: &str, ws: &str) -> Result<ObjectId> {
    let view = repo.view();
    if base == "@" {
        return repo.workspace_wc(ws);
    }
    if base == "root" || base == "root()" {
        return Ok(repo.root_id());
    }
    if let Some(name) = base.strip_suffix('@') {
        return repo.workspace_wc(name);
    }
    if let Some(t) = view.tags.get(base) {
        return Ok(t.target);
    }
    if let Some(t) = view.remote_tags.get(base) {
        return Ok(*t);
    }
    if base.len() == 64 {
        if let Ok(id) = ObjectId::from_hex(base) {
            // Only snapshots are revisions (not blobs or trees).
            if repo.store().has(&id) && repo.snapshot(&id).is_ok() {
                return Ok(id);
            }
        }
    }
    let visible = repo.visible_snapshots()?;
    if let Some(hex) = ChangeId::reverse_hex_to_hex(base) {
        let mut matches: Vec<(ObjectId, ChangeId)> = Vec::new();
        for id in &visible {
            let s = repo.snapshot(id)?;
            if hex::encode(s.change_id.0).starts_with(&hex) {
                matches.push((*id, s.change_id));
            }
        }
        let mut changes: Vec<ChangeId> = matches.iter().map(|m| m.1).collect();
        changes.sort();
        changes.dedup();
        if changes.len() == 1 && matches.len() > 1 {
            let local = local_history(repo)?;
            let mine: Vec<ObjectId> = matches.iter().map(|m| m.0).filter(|id| local.contains(id)).collect();
            if let [one] = mine.as_slice() {
                return Ok(*one);
            }
        }
        match changes.len() {
            0 => {}
            1 if matches.len() == 1 => return Ok(matches[0].0),
            1 => {
                return Err(VeilError::Revset(format!(
                    "change '{base}' is divergent ({} visible snapshots); use a snapshot id",
                    matches.len()
                )))
            }
            _ => return Err(VeilError::Revset(format!("change id prefix '{base}' is ambiguous"))),
        }
    }
    if base.len() >= 4 && base.bytes().all(|b| b.is_ascii_hexdigit()) {
        let lower = base.to_ascii_lowercase();
        let found: Vec<ObjectId> = visible.into_iter().filter(|id| id.hex().starts_with(&lower)).collect();
        match found.as_slice() {
            [one] => return Ok(*one),
            [] => {}
            _ => return Err(VeilError::Revset(format!("snapshot id prefix '{base}' is ambiguous"))),
        }
    }
    Err(VeilError::Revset(format!("revision '{base}' not found")))
}

/// Snapshots reachable from this repository's own heads and working copies,
/// as opposed to those only reachable through tags and remote tags (which
/// `pull` records, and anyone who can push to the remote can set).
fn local_history(repo: &Repo) -> Result<std::collections::HashSet<ObjectId>> {
    let view = repo.view();
    let roots: Vec<ObjectId> = view
        .heads
        .iter()
        .copied()
        .chain(view.workspaces.values().map(|w| w.wc))
        .collect();
    Ok(repo.topo_children_first(roots)?.into_iter().collect())
}

/// Change ids and snapshot ids of the snapshots reachable from a set of
/// refs, to keep tags created from a remote's names (`vl pull`,
/// `vl git pull`) from shadowing them in revsets: anyone who can push a
/// tag or branch named after a published change id could otherwise
/// redirect `vl edit <change>` to their snapshot. Built on first use.
#[derive(Default)]
pub(crate) struct RevisionNames(Option<Vec<(String, String)>>);

impl RevisionNames {
    /// Would `name`, as a tag, hide a change id or snapshot id prefix of a
    /// snapshot reachable from `refs` (tags are resolved first)? `refs` is
    /// only read on the first call.
    pub(crate) fn shadows(&mut self, repo: &Repo, refs: impl FnOnce() -> Vec<ObjectId>, name: &str) -> Result<bool> {
        let change = ChangeId::reverse_hex_to_hex(name);
        let snapshot = (name.len() >= 4 && name.bytes().all(|b| b.is_ascii_hexdigit())).then(|| name.to_ascii_lowercase());
        if change.is_none() && snapshot.is_none() {
            return Ok(false);
        }
        if self.0.is_none() {
            let mut v = Vec::new();
            for id in repo.topo_children_first(refs())? {
                v.push((hex::encode(repo.snapshot(&id)?.change_id.0), id.hex()));
            }
            self.0 = Some(v);
        }
        let ids = self.0.as_ref().unwrap();
        Ok(ids.iter().any(|(c, s)| {
            change.as_ref().is_some_and(|h| c.starts_with(h.as_str())) || snapshot.as_ref().is_some_and(|h| s.starts_with(h.as_str()))
        }))
    }
}
