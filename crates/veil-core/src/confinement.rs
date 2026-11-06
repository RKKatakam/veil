//! Which unreleased embargo a snapshot belongs to, for the routes that copy
//! content from one revision into another (BUG-681).
//!
//! An unreleased embargo keeps two kinds of snapshot in this repository
//! (`remote::embargo_withheld`, `remote::push_closure`):
//! * its **withheld history**: the embargoed merge, the fix, and how it was
//!   made;
//! * snapshots that **build on** that history: a push refuses them until
//!   the release, so they are part of the fix line too.
//!
//! A snapshot of either is *confined* to the embargo. Copying content out
//! of a confined snapshot into one that is not would publish the fix
//! before the release, so every copy route refuses it: `vl restore --from`,
//! `vl squash` (`--into`), `vl duplicate`/`vl cherry-pick`, and any rewrite
//! that moves a confined change onto parents outside the embargo
//! (`vl rebase`, `vl abandon` of the fix, ...), which
//! [`crate::transaction::Transaction::commit`] checks. Refusals name the
//! change and the embargo, never a file or a description.

use std::collections::HashMap;

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    repo::Repo,
};

/// The confinement of snapshots in one repository state (its current view).
/// Built once per command; queries are memoised.
pub struct Confinement {
    /// Withheld history, by embargo (public-remote rules: the widest).
    withheld: HashMap<ObjectId, String>,
    /// Snapshots already judged by their history (not their tree).
    memo: HashMap<ObjectId, Option<String>>,
    /// The lowest generation of the withheld history: nothing below it
    /// builds on withheld history.
    floor: crate::graph_index::Gen,
}

/// The unreleased embargoes whose embargoed merge (or a rewrite of it) is
/// in `repo`'s current view. An embargo whose merge was abandoned (or undone) confines
/// nothing any more: its fix is back to the state before the merge.
pub fn active_embargoes(repo: &Repo) -> Result<std::collections::HashSet<String>> {
    let mut out = std::collections::HashSet::new();
    for id in repo.visible_embargoed()? {
        let s = repo.snapshot(&id)?;
        if let Some(e) = &s.embargo {
            // A merge rewritten down to one parent (its fix abandoned)
            // still holds the fix in its tree: still active.
            if !repo.keys().embargo_released(e) {
                out.insert(e.clone());
            }
        }
    }
    Ok(out)
}

impl Confinement {
    /// The confinement of `repo`'s current view.
    pub fn new(repo: &Repo) -> Result<Confinement> {
        let withheld = crate::remote::embargo_withheld(repo)?;
        let mut floor = crate::graph_index::Gen::MAX;
        for id in withheld.keys() {
            if let Some(g) = repo.graph().generation(repo, id)? {
                floor = floor.min(g);
            }
        }
        Ok(Confinement {
            withheld,
            memo: HashMap::new(),
            floor,
        })
    }

    /// The unreleased embargo `id` is confined to, if any.
    pub fn of(&mut self, repo: &Repo, id: &ObjectId) -> Result<Option<String>> {
        if self.withheld.is_empty() {
            return Ok(None);
        }
        self.history(repo, id)
    }

    /// By history: withheld, or building on withheld history, which is what
    /// a push refuses. Iterative.
    pub fn of_history(&mut self, repo: &Repo, id: &ObjectId) -> Result<Option<String>> {
        if self.withheld.is_empty() {
            return Ok(None);
        }
        self.history(repo, id)
    }

    fn history(&mut self, repo: &Repo, id: &ObjectId) -> Result<Option<String>> {
        let mut stack = vec![(*id, false)];
        while let Some((x, expanded)) = stack.pop() {
            if self.memo.contains_key(&x) {
                continue;
            }
            if let Some(e) = self.withheld.get(&x) {
                self.memo.insert(x, Some(e.clone()));
                continue;
            }
            // Below every withheld snapshot: its ancestors are all below too.
            if repo.graph().generation(repo, &x)?.is_none_or(|g| g < self.floor) {
                self.memo.insert(x, None);
                continue;
            }
            let Some(s) = repo.snapshot_opt(&x)? else {
                self.memo.insert(x, None);
                continue;
            };
            let parents = &s.parents[..];
            if !expanded {
                stack.push((x, true));
                stack.extend(parents.iter().filter(|p| !self.memo.contains_key(*p)).map(|p| (*p, false)));
            } else {
                let found = parents.iter().find_map(|p| self.memo.get(p).cloned().flatten());
                self.memo.insert(x, found);
            }
        }
        Ok(self.memo.get(id).cloned().flatten())
    }

    /// Refuse copying content of `sources` into a change on `dest` (the
    /// snapshots the copy lands in, or the parents it is made on) unless
    /// every destination is confined to the same embargo as the source.
    /// `what` starts the message: `"cannot restore from"`.
    pub fn check_copy(&mut self, repo: &Repo, what: &str, sources: &[ObjectId], dest: &[ObjectId]) -> Result<()> {
        for src in sources {
            let Some(e) = self.of(repo, src)? else { continue };
            for d in dest {
                if self.of(repo, d)?.as_deref() != Some(e.as_str()) {
                    return Err(copy_refusal(what, src, &e));
                }
            }
        }
        Ok(())
    }
}

/// The refusal for copying confined content out of embargo `e`. Names the
/// change and the embargo only.
pub fn copy_refusal(what: &str, src: &ObjectId, e: &str) -> VeilError {
    VeilError::Policy(format!(
        "{what} {}: it is part of unreleased embargo {e} (the fix, work built on it, or the embargoed line), and a copy outside the embargo would publish the fix before the release; copy it into a change inside the embargo, or release the embargo first (`vl embargo release {e}`)",
        src.short()
    ))
}
