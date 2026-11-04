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
