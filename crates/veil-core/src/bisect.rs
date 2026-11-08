//! `vl bisect`: the pure graph functions (candidates, next step, verdict).
//!
//! The candidates are the ancestors of the bad snapshot (itself included)
//! that are not ancestors of any good one, as in Git: merges need no
//! special case, the set is the whole DAG difference. The next snapshot to
//! test is the candidate that splits the rest most evenly (the number of
//! candidates among its ancestors closest to half), ties broken by id so
//! the choice is deterministic. The root is never a candidate (its tree is
//! empty), and neither is a snapshot this replica does not hold (withheld
//! by an unreleased embargo).
//!
//! Counting each candidate's ancestors exactly costs a walk per candidate;
//! past [`EXACT_LIMIT`] candidates the count is taken by summing over
//! parents in topological order, which is exact on linear history and an
//! overestimate across merges (the step is then less even, never wrong).

use std::collections::{HashMap, HashSet};

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    repo::Repo,
};

/// Candidate sets up to this size have their ancestor counts computed
/// exactly (`n²` work at most).
pub const EXACT_LIMIT: usize = 2048;

/// What to do next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Test this snapshot. `remaining` candidates are left (the bad one
    /// included), about `steps` more tests.
    Test { candidate: ObjectId, remaining: usize, steps: u32 },
    /// The first bad snapshot.
    Found(ObjectId),
    /// Only skipped snapshots are left: the first bad one is `bad` or one
    /// of `skipped`.
    Undecided { bad: ObjectId, skipped: Vec<ObjectId> },
}

/// The verdict of `bisect run`'s command, from its exit code (Git's rule).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Good,
    Bad,
    Skip,
    /// Stop bisecting (the command was killed, or exited above 127).
    Abort,
}

/// 0 good, 125 skip, 1–127 bad, anything else aborts.
pub fn verdict(code: i32) -> Verdict {
    match code {
        0 => Verdict::Good,
        125 => Verdict::Skip,
        1..=127 => Verdict::Bad,
        _ => Verdict::Abort,
    }
}

/// The candidates for `bad` given `good`: children before parents.
///
/// Exact (a full clone's answer, BUG-1262): the history index's range from
/// `bad` down to the good snapshots, so a thin clone pages in only the
/// range it searches; in the held order (all of it is held by then).
pub fn candidates(repo: &Repo, bad: &ObjectId, good: &[ObjectId]) -> Result<Vec<ObjectId>> {
    for g in good {
        if repo.is_ancestor(bad, g)? {
            return Err(VeilError::Revset(format!(
                "the bad snapshot {} is an ancestor of (or is) a good one: nothing to search",
                bad.short()
            )));
        }
    }
    let mut exclude = good.to_vec();
    exclude.push(repo.root_id());
    let set = repo.exact().range(&[*bad], &exclude)?;
    Ok(repo.held().topo_children_first([*bad])?.into_iter().filter(|id| set.contains(id)).collect())
}

/// How many of `set` each member of `set` has among its ancestors (itself
/// included). `order` is `set` children first.
fn ancestor_counts(repo: &Repo, order: &[ObjectId]) -> Result<HashMap<ObjectId, usize>> {
    let set: HashSet<ObjectId> = order.iter().copied().collect();
    let mut parents: HashMap<ObjectId, Vec<ObjectId>> = HashMap::new();
    for id in order {
        let s = repo.snapshot(id)?;
        parents.insert(*id, s.parents.iter().copied().filter(|p| set.contains(p)).collect());
    }
    let mut counts = HashMap::new();
    if order.len() <= EXACT_LIMIT {
        for id in order {
            let mut seen: HashSet<ObjectId> = HashSet::new();
            let mut stack = vec![*id];
            while let Some(x) = stack.pop() {
                if seen.insert(x) {
                    stack.extend(parents[&x].iter().copied());
                }
            }
            counts.insert(*id, seen.len());
        }
    } else {
        for id in order.iter().rev() {
            let n: usize = 1 + parents[id].iter().map(|p| counts[p]).sum::<usize>();
            counts.insert(*id, n.min(order.len()));
        }
    }
    Ok(counts)
}

/// The next step for `bad`, `good` and `skip`.
pub fn next(repo: &Repo, bad: &ObjectId, good: &[ObjectId], skip: &[ObjectId]) -> Result<Step> {
    let c = candidates(repo, bad, good)?;
    if c.len() <= 1 {
        return Ok(Step::Found(*bad));
    }
    let skip: HashSet<&ObjectId> = skip.iter().collect();
    let counts = ancestor_counts(repo, &c)?;
    let n = c.len();
    let best = c
        .iter()
        .filter(|id| *id != bad && !skip.contains(id))
        .map(|id| {
            let a = counts[id];
            (a.min(n - a), *id)
        })
        // Most even split; then the smallest id.
        .max_by(|x, y| x.0.cmp(&y.0).then_with(|| y.1.cmp(&x.1)));
    match best {
        Some((_, candidate)) => Ok(Step::Test { candidate, remaining: n, steps: usize::BITS - (n - 1).leading_zeros() }),
        None => {
            let mut skipped: Vec<ObjectId> = c.iter().filter(|id| *id != bad).copied().collect();
            skipped.sort();
            Ok(Step::Undecided { bad: *bad, skipped })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_map_as_in_git() {
        assert_eq!(verdict(0), Verdict::Good);
        assert_eq!(verdict(1), Verdict::Bad);
        assert_eq!(verdict(124), Verdict::Bad);
        assert_eq!(verdict(125), Verdict::Skip);
        assert_eq!(verdict(126), Verdict::Bad);
        assert_eq!(verdict(127), Verdict::Bad);
        assert_eq!(verdict(128), Verdict::Abort);
        assert_eq!(verdict(255), Verdict::Abort);
        assert_eq!(verdict(-1), Verdict::Abort);
    }
}
