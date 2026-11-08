//! Which unreleased embargo a snapshot belongs to, for the routes that copy
//! content from one revision into another (BUG-681).
//!
//! An unreleased embargo keeps two kinds of snapshot in this repository
//! (`remote::Withheld`, the one rule):
//! * every **version** of a change of its fix line (the embargoed merge,
//!   the fix, and how it was made), whatever its snapshot id;
//! * snapshots that **descend** from one: a push refuses them until the
//!   release, so they are part of the fix line too.
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
    /// What the view withholds (`remote::Withheld`, the one rule).
    withheld: crate::remote::Withheld,
    memo: HashMap<ObjectId, Option<String>>,
}

/// The unreleased embargoes whose embargoed merge (or a rewrite of it) is
/// in `repo`'s current view. An embargo whose merge was abandoned (or undone) confines
/// nothing any more: its fix is back to the state before the merge.
pub fn active_embargoes(repo: &Repo) -> Result<std::collections::HashSet<String>> {
    let mut out = std::collections::HashSet::new();
    for id in repo.exact().visible_embargoed()? {
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
        Ok(Confinement { withheld: crate::remote::embargo_withheld(repo)?, memo: HashMap::new() })
    }

    /// The unreleased embargo `id` is confined to, if any: it is a version
    /// of a change the embargo withholds, or descends from one.
    pub fn of(&mut self, repo: &Repo, id: &ObjectId) -> Result<Option<String>> {
        if self.withheld.is_empty() {
            return Ok(None);
        }
        if let Some(e) = self.memo.get(id) {
            return Ok(e.clone());
        }
        let e = self.withheld.of_snapshot(repo, id)?;
        self.memo.insert(*id, e.clone());
        Ok(e)
    }

    /// [`Confinement::of`] (by history, not by tree).
    pub fn of_history(&mut self, repo: &Repo, id: &ObjectId) -> Result<Option<String>> {
        self.of(repo, id)
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
