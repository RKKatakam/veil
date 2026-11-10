//! Revision expressions.
//!
//! ```text
//! @            working copy of the current workspace
//! name@        working copy of workspace `name`
//! root         the universal root snapshot
//! main         a tag;  origin/main  a remote tag
//! kxqz…        change-id prefix (letters k–z)
//! 3f9a…        snapshot-id prefix (hex): visible snapshots first, then
//!              hidden ones the op log or an evolution log reaches
//! X-  X--      first parent, grandparent, …
//! ```
//!
//! Sets of snapshots ([`resolve_set`], `vl log -r`, `vl bisect`),
//! children before parents:
//!
//! ```text
//! X            just X
//! ::B          B and all its ancestors (the root included)
//! A..B         ancestors of B (B included) that are not ancestors of A
//! ..B          root()..B
//! A..          visible snapshots that are not ancestors of A
//! agent(PAT)   visible snapshots whose agent attribution matches PAT
//!              (the name exactly, or a glob: `claude-*`)
//! ```
//!
//! Tag names never contain `..` or `:` (`commands::validate_tag_name`), so
//! the operators are unambiguous.
//!
//! Tags are resolved before change ids, so a tag must never be named after
//! a change: `vl pull` does not create a local tag whose
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

use std::collections::HashSet;

use crate::{
    error::{Result, VeilError},
    id::{ChangeId, ObjectId},
    repo::Repo,
};

/// The snapshots `spec` names (see the module docs), children before
/// parents, newest first among unrelated snapshots. Snapshots withheld here
/// (an unreleased embargo on a public clone) are not part of the set.
pub fn resolve_set(repo: &Repo, spec: &str, current_ws: &str) -> Result<Vec<ObjectId>> {
    let spec = spec.trim();
    if let Some(pattern) = spec.strip_prefix("agent(").and_then(|r| r.strip_suffix(')')) {
        let m = agent_matcher(pattern)?;
        // As a full clone answers: a thin clone pages in what it lacks.
        let all = repo.exact().topo_children_first(repo.view().refs())?;
        let mut out = Vec::new();
        for id in all {
            let s = repo.snapshot(&id)?;
            if agent_matches(&s, &m) {
                out.push(id);
            }
        }
        return Ok(out);
    }
    if let Some(b) = spec.strip_prefix("::") {
        let b = resolve(repo, nonempty(b, spec)?, current_ws)?;
        return repo.exact().topo_children_first([b]);
    }
    let Some((a, b)) = spec.split_once("..") else {
        return Ok(vec![resolve(repo, spec, current_ws)?]);
    };
    if b.contains("..") {
        return Err(VeilError::Revset(format!("'{spec}': one `..` per range")));
    }
    let exclude: Vec<ObjectId> = match a.trim() {
        "" => vec![repo.root_id()],
        a => vec![resolve(repo, a, current_ws)?],
    };
    let heads: Vec<ObjectId> = match b.trim() {
        "" => repo.view().refs().into_iter().collect(),
        b => vec![resolve(repo, b, current_ws)?],
    };
    // The range itself, exactly (a thin clone pages in what it reaches and
    // no more), in the held order (everything in it is held by then).
    let set = repo.exact().range(&heads, &exclude)?;
    Ok(repo.held().topo_children_first(heads)?.into_iter().filter(|id| set.contains(id)).collect())
}

/// Longest pattern `agent(PATTERN)` and `vl log --agent` take.
pub const MAX_AGENT_PATTERN: usize = 256;

/// The matcher of `agent(PATTERN)`: a glob (`*`, `?`, `[…]`; no regular
/// expressions), at most [`MAX_AGENT_PATTERN`] bytes.
pub fn agent_matcher(pattern: &str) -> Result<globset::GlobMatcher> {
    let pattern = pattern.trim();
    if pattern.is_empty() || pattern.len() > MAX_AGENT_PATTERN {
        return Err(VeilError::Revset(format!(
            "agent(PATTERN) takes a name or glob of 1 to {MAX_AGENT_PATTERN} bytes"
        )));
    }
    globset::GlobBuilder::new(pattern)
        .literal_separator(false)
        .build()
        .map(|g| g.compile_matcher())
        .map_err(|e| VeilError::Revset(format!("agent({pattern:?}): {}", e.kind())))
}

/// Does snapshot `s` carry an attribution whose agent `m` matches?
pub fn agent_matches(s: &crate::object::Snapshot, m: &globset::GlobMatcher) -> bool {
    s.agent.as_ref().is_some_and(|a| m.is_match(&a.agent))
}

fn nonempty<'a>(s: &'a str, spec: &str) -> Result<&'a str> {
    match s.trim() {
        "" => Err(VeilError::Revset(format!("'{spec}' names no revision"))),
        s => Ok(s),
    }
}

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
    if let Some(branch) = base.strip_suffix("@tested") {
        if !branch.is_empty() {
            if let Some(t) = view.remote_tags.get(&format!("origin/{branch}@tested")) {
                return Ok(*t);
            }
            if let Some((_, t)) = view.remote_tags.iter().find(|(k, _)| k.ends_with(&format!("/{branch}@tested"))) {
                return Ok(*t);
            }
            return Err(VeilError::Revset(format!("branch '{branch}' has no tested snapshot yet")));
        }
    }
    // Release tags (format 5): `tag:<name>` names a release tag.
    if let Some(rest) = base.strip_prefix("tag:") {
        return match view.tags.get(rest).filter(|t| t.annotation.is_some()) {
            Some(t) => Ok(t.target),
            None => Err(VeilError::Revset(format!("no release tag '{rest}'"))),
        };
    }
    if base.len() == 64 {
        if let Ok(id) = ObjectId::from_hex(base) {
            // Only snapshots are revisions (not blobs or trees).
            if repo.store().has(&id) && repo.snapshot(&id).is_ok() {
                return Ok(id);
            }
        }
    }
    // Candidates come from the history index; only their visibility is
    // walked for, never all history.
    let visible_matching = |keep: &dyn Fn(&ObjectId, &ChangeId) -> bool| -> Result<Vec<ObjectId>> {
        let found: HashSet<ObjectId> =
            repo.held().entries_matching(view.refs(), |id, e| keep(id, &e.change_id))?.into_iter().collect();
        // Held: a thin clone adds the server's answer (`server_names`).
        let mut v: Vec<ObjectId> = repo.held().visible_among(&found)?.into_iter().collect();
        v.sort();
        Ok(v)
    };
    if let Some(hex) = ChangeId::reverse_hex_to_hex(base) {
        let mut matches: Vec<(ObjectId, ChangeId)> = Vec::new();
        let mut ids = visible_matching(&|_, c| hex_starts_with(&c.0, &hex))?;
        // A thin clone: and the server's matches beyond what it holds.
        if let Some(r) = server_names(repo, base)? {
            for id in r.changes {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
        for id in ids {
            matches.push((id, repo.snapshot(&id)?.change_id));
        }
        let mut changes: Vec<ChangeId> = matches.iter().map(|m| m.1).collect();
        changes.sort();
        changes.dedup();
        if changes.len() == 1 && matches.len() > 1 {
            let mut mine: Vec<ObjectId> = Vec::new();
            for m in &matches {
                if in_local_history(repo, &m.0)? {
                    mine.push(m.0);
                }
            }
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
        let mut found = visible_matching(&|id, _| hex_starts_with(&id.0, &lower))?;
        if let Some(r) = server_names(repo, &lower)? {
            for id in r.snapshots {
                if !found.contains(&id) {
                    found.push(id);
                }
            }
            found.sort();
        }
        match found.as_slice() {
            [one] => return Ok(*one),
            [] => {}
            _ => return Err(VeilError::Revset(format!("snapshot id prefix '{base}' is ambiguous"))),
        }
        // An earlier version of a change (`vl evolog`), or a snapshot an
        // undone operation made: hidden, but recorded (BUG-207).
        match recorded_snapshots_with_prefix(repo, &lower)?.as_slice() {
            [one] => return Ok(*one),
            [] => {}
            _ => return Err(VeilError::Revset(format!("snapshot id prefix '{base}' is ambiguous"))),
        }
    }
    Err(VeilError::Revset(format!("revision '{base}' not found")))
}

/// In a thin clone, the server's answer for id prefix `prefix` (a change id
/// as written, or snapshot id digits) over this person's history, each
/// snapshot it names held (fetched alone, a page of one): what held history
/// cannot decide (`docs/HUB.md` §13.21, "Revised: names and fetching";
/// BUG-1261, 1266). One request; a name that matches nothing fetches
/// nothing. `None` in any other repository, or from a server older than
/// protocol revision 5.
pub(crate) fn server_names(repo: &Repo, prefix: &str) -> Result<Option<crate::hub::wire::Resolved>> {
    let store = repo.store();
    if !store.is_partial() || !store.may_fetch() {
        return Ok(None);
    }
    let Some(promisor) = store.promisor() else {
        return Err(VeilError::Unavailable(
            "this thin clone cannot tell what an id names without its server, and this command has no connection to it".into(),
        ));
    };
    // Counted from the server's branches and this clone's own refs, as a
    // full clone holds what they reach (BUG-1319).
    let from = repo.server_roots(false)?.map(|(f, _)| f).unwrap_or_default();
    let Some(r) = promisor.resolve(prefix, &from)? else { return Ok(None) };
    for id in r.snapshots.iter().chain(&r.changes) {
        if !store.has(id) {
            repo.deepen(&[*id], 1)?;
        }
    }
    Ok(Some(r))
}

/// Does the lowercase hex spelling of `bytes` start with `prefix`?
fn hex_starts_with(bytes: &[u8], prefix: &str) -> bool {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    prefix.len() <= bytes.len() * 2
        && prefix.bytes().enumerate().all(|(i, c)| {
            let b = bytes[i / 2];
            let nibble = if i % 2 == 0 { b >> 4 } else { b & 15 };
            DIGITS[nibble as usize] == c
        })
}

/// The snapshots in the store whose id starts with `prefix` (lowercase hex)
/// and that the repository has recorded: reachable, through parents and
/// predecessors (the evolution log), from the view of some operation still
/// in the operation log. Hidden snapshots are revisions too, by snapshot id
/// only (a change id names the visible version), so that the ids `vl
/// evolog` and `vl op log` lead to can be shown, diffed and restored from.
/// Only called once the visible snapshots had no match.
fn recorded_snapshots_with_prefix(repo: &Repo, prefix: &str) -> Result<Vec<ObjectId>> {
    let store = repo.store();
    let mut candidates: Vec<ObjectId> = Vec::new();
    // Loose objects live in `<root>/<first two hex digits>/<the rest>`.
    if let Ok(files) = store.backend().list_dir(&store.root().join(&prefix[..2])) {
        for f in files {
            if let Ok(id) = ObjectId::from_hex(&format!("{}{}", &prefix[..2], f.name)) {
                candidates.push(id);
            }
        }
    }
    for p in store.packs()? {
        candidates.extend(p.index().ids().iter().filter(|id| id.hex().starts_with(prefix)));
    }
    candidates.retain(|id| id.hex().starts_with(prefix));
    candidates.sort();
    candidates.dedup();
    // Held reads only: a hidden version is this repository's own, held,
    // and a walk of every view must page in nothing (BUG-1267).
    candidates.retain(|id| matches!(repo.held().snapshot(id), Ok(Some(_))));
    if candidates.is_empty() {
        return Ok(candidates);
    }
    // Walk from every recorded view until each candidate is found (or
    // everything recorded was seen).
    let mut wanted: std::collections::HashSet<ObjectId> = candidates.iter().copied().collect();
    let mut found = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut stack: Vec<ObjectId> = Vec::new();
    for (_, op) in repo.op_log(usize::MAX)? {
        stack.extend(op.view.refs());
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            if wanted.remove(&id) {
                found.push(id);
                if wanted.is_empty() {
                    return Ok(found);
                }
            }
            // Objects stripped by a public remote, or sealed for a scope
            // this reader lacks, end the walk there.
            if let Ok(Some(s)) = repo.held().snapshot(&id) {
                stack.extend(s.parents.iter().chain(&s.predecessors).copied());
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Is `id` reachable from this repository's own heads and working copies,
/// as opposed to only through tags and remote tags (which `pull` records,
/// and anyone who can push to the remote can set)? Exactly: in a thin
/// clone the history below its own work may not be held (BUG-1319: work on
/// versions a rewrite elsewhere left off the branches); the walk stops at
/// `id`'s generation, so only that range is paged in.
fn in_local_history(repo: &Repo, id: &ObjectId) -> Result<bool> {
    let view = repo.view();
    let roots: Vec<ObjectId> = view
        .heads
        .iter()
        .copied()
        .chain(view.workspaces.values().map(|w| w.wc))
        .collect();
    let Some(g) = repo.exact().generation(id)? else { return Ok(false) };
    Ok(repo.exact().down_to(roots, g)?.contains_key(id))
}

/// Change ids and snapshot ids of the snapshots reachable from a set of
/// refs, to keep tags created from a remote's names (`vl pull`) from
/// shadowing them in revsets: anyone who can push a tag named after a published change id could otherwise
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
            // What is held (this clone's own work among it), and below, in a
            // thin clone, the server's answer for the rest (BUG-1261).
            let mut v = Vec::new();
            for id in repo.held().topo_children_first(refs())? {
                let Some(s) = repo.held().snapshot(&id)? else { continue };
                v.push((hex::encode(s.change_id.0), id.hex()));
            }
            self.0 = Some(v);
        }
        let ids = self.0.as_ref().unwrap();
        if ids.iter().any(|(c, s)| {
            change.as_ref().is_some_and(|h| c.starts_with(h.as_str())) || snapshot.as_ref().is_some_and(|h| s.starts_with(h.as_str()))
        }) {
            return Ok(true);
        }
        Ok(server_names(repo, &name.to_ascii_lowercase())?.is_some_and(|r| !r.snapshots.is_empty() || !r.changes.is_empty() || r.more))
    }
}
