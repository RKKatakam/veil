//! The commit graph (phase-3 design §3.2): per snapshot, its generation,
//! first-parent depth, parents, change id, embargo flags and a first-parent
//! jump table, so that ancestry, merge bases and "the first-parent ancestor
//! at depth d" read tens of rows, not the history.
//!
//! * **Generation** is the client's corrected commit date
//!   (`veil_core::graph_index`): the larger of the snapshot's timestamp (at
//!   least 0) and 1 plus its parents' largest generation. It strictly
//!   decreases along every parent edge, which is all the walks rely on; a
//!   hostile timestamp only lengthens a walk (timestamps are clamped to
//!   [`MAX_STAMP`], so the sum never overflows: BUG-866). **It is never shown to a
//!   viewer:** hidden snapshots take part in it, so it is not the same in a
//!   viewer's projected history (S13 orders answers by something else).
//! * **Depth** counts first parents down to the universal root (depth 0).
//! * **Jump table** (`skip`): the first parent, then the first-parent
//!   ancestors at the largest multiple of 16, 256 and 4096 below the
//!   snapshot's depth. Each comes from the first parent's row alone (O(1)
//!   per landing), and [`Graph::at_depth`] reaches any depth in at most
//!   15 steps per level plus one per 4096.

use std::{
    collections::{BinaryHeap, HashMap, HashSet},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use veil_core::{object::Snapshot, ObjectId};

use super::Cx;
use crate::{error::Result, sync::root_snapshot_id};

/// The snapshot carries an embargo (`embargo` set).
pub const FLAG_EMBARGO: i32 = 1;
/// The snapshot or one of its ancestors carries an embargo: its changes are
/// not indexed or listed until release (design §6, row 8).
pub const FLAG_EMBARGO_LINE: i32 = 2;

/// The largest timestamp a generation takes from a snapshot (about 73
/// million years in milliseconds): far above any real clock, and far
/// enough below `i64::MAX` that no history can count up to it. The
/// clients' value too (`veil_core::graph_index::generation`, BUG-1316).
pub use veil_core::graph_index::MAX_STAMP;

/// The jump-table levels after the first parent.
const LEVELS: [i64; 3] = [16, 256, 4096];

/// One snapshot's row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphRow {
    pub generation: i64,
    pub depth: i64,
    pub parents: Vec<ObjectId>,
    pub change_id: String,
    pub flags: i32,
    /// `[first parent, at multiple of 16, of 256, of 4096]`; empty for the root.
    pub skip: Vec<ObjectId>,
    /// The changed-paths value ([`super::changes::Changed`]), as stored.
    pub changed: Option<String>,
}

impl GraphRow {
    /// The universal root: depth and generation 0.
    pub fn root() -> GraphRow {
        GraphRow {
            generation: 0,
            depth: 0,
            parents: Vec::new(),
            change_id: hex::encode([0u8; 16]),
            flags: 0,
            skip: Vec::new(),
            changed: Some(super::changes::NONE.into()),
        }
    }

    /// The row of `s`, whose parents' rows are `parents` (in order).
    pub fn compute(s: &Snapshot, parents: &[(ObjectId, Arc<GraphRow>)]) -> GraphRow {
        // The timestamp is the author's choice (BUG-866): clamped, so that
        // 1 plus a parent's generation never overflows, and generations
        // strictly decrease along every edge whatever was pushed.
        // `veil_core`'s one arithmetic, the clients' too (BUG-1316).
        let generation = veil_core::graph_index::generation(s.timestamp, parents.iter().map(|(_, p)| p.generation as u64)) as i64;
        let mut flags = if s.embargo.is_some() { FLAG_EMBARGO | FLAG_EMBARGO_LINE } else { 0 };
        for (_, p) in parents {
            flags |= p.flags & FLAG_EMBARGO_LINE;
        }
        let (skip, depth) = match parents.first() {
            None => (Vec::new(), 0),
            Some((p0, p)) => {
                let mut skip = vec![*p0];
                for (i, level) in LEVELS.iter().enumerate() {
                    // The first parent is at depth `p.depth`: the ancestor at
                    // the multiple of `level` below our depth is the first
                    // parent itself when it sits on one, else its own.
                    let at = if p.depth % level == 0 { *p0 } else { p.skip.get(i + 1).copied().unwrap_or(*p0) };
                    skip.push(at);
                }
                (skip, p.depth.saturating_add(1))
            }
        };
        GraphRow {
            generation,
            depth,
            parents: parents.iter().map(|(id, _)| *id).collect(),
            change_id: hex::encode(s.change_id.0),
            flags,
            skip,
            changed: None,
        }
    }
}

/// Graph reads for one project: pending rows of the running batch, then
/// the process-wide cache, then the database.
pub struct Graph<'a> {
    pub cx: &'a Cx,
    pub pending: HashMap<ObjectId, Arc<GraphRow>>,
}

impl<'a> Graph<'a> {
    pub fn new(cx: &'a Cx) -> Graph<'a> {
        Graph { cx, pending: HashMap::new() }
    }

    /// The derived row of `id`, if there is one.
    pub fn row(&self, id: &ObjectId) -> Result<Option<Arc<GraphRow>>> {
        if *id == root_snapshot_id() {
            return Ok(Some(Arc::new(GraphRow::root())));
        }
        if let Some(r) = self.pending.get(id) {
            return Ok(Some(r.clone()));
        }
        self.cx.stored_row(id)
    }

    /// The row of `id`, which must be derived.
    pub fn get(&self, id: &ObjectId) -> Result<Arc<GraphRow>> {
        self.row(id)?
            .ok_or_else(|| crate::error::Error::Other(anyhow::anyhow!("snapshot {} is not derived yet", id.short())))
    }

    /// The first-parent ancestor of `x` (or `x`) at depth `d`; `None` when
    /// `d` is deeper than `x`.
    pub fn at_depth(&self, x: ObjectId, d: i64) -> Result<Option<ObjectId>> {
        let mut x = x;
        let mut row = self.get(&x)?;
        if d > row.depth || d < 0 {
            return Ok(None);
        }
        while row.depth > d {
            let mut next = row.skip[0];
            for i in (1..row.skip.len()).rev() {
                let r = self.get(&row.skip[i])?;
                if r.depth >= d {
                    next = row.skip[i];
                    break;
                }
            }
            x = next;
            row = self.get(&x)?;
        }
        Ok(Some(x))
    }

    /// Is `a` an ancestor of `b`, or `b` itself? The walk stops below
    /// `a`'s generation; first parents are tried first through the jump
    /// table.
    pub fn is_ancestor(&self, a: ObjectId, b: ObjectId) -> Result<bool> {
        if a == b {
            return Ok(true);
        }
        let ra = self.get(&a)?;
        if self.at_depth(b, ra.depth)? == Some(a) {
            return Ok(true);
        }
        let mut seen = HashSet::new();
        let mut stack = vec![b];
        while let Some(x) = stack.pop() {
            if x == a {
                return Ok(true);
            }
            if !seen.insert(x) {
                continue;
            }
            for p in &self.get(&x)?.parents {
                if self.get(p)?.generation >= ra.generation {
                    stack.push(*p);
                }
            }
        }
        Ok(false)
    }

    /// The best common ancestors of `a` and `b` (none an ancestor of
    /// another), sorted by id: paint-down by generation, as the client's
    /// `GraphIndex::merge_bases`.
    pub fn merge_bases(&self, a: ObjectId, b: ObjectId) -> Result<Vec<ObjectId>> {
        // One side below the other (a branch behind `main`): no paint-down
        // through everything between them.
        if self.is_ancestor(a, b)? {
            return Ok(vec![a]);
        }
        if self.is_ancestor(b, a)? {
            return Ok(vec![b]);
        }
        let mut paint = Paint::default();
        paint.push(self, a, A)?;
        paint.push(self, b, B)?;
        let mut found = Vec::new();
        // Until every snapshot still queued is below a common ancestor.
        while paint.live > 0 {
            let Some((_, x)) = paint.heap.pop() else { break };
            paint.popped(x);
            let mut f = paint.flags[&x];
            if f & (A | B) == A | B && f & STALE == 0 {
                found.push(x);
                f |= STALE;
                paint.set(x, f);
            }
            for p in self.get(&x)?.parents.clone() {
                let pf = paint.flags.get(&p).copied().unwrap_or(0);
                if pf & f != f {
                    paint.set(p, pf | f);
                    paint.push(self, p, 0)?;
                }
            }
        }
        reduce(self, found)
    }
}

const A: u8 = 1;
const B: u8 = 2;
const STALE: u8 = 4;

/// The paint-down queue: by generation, counting the queued snapshots
/// that are not below a common ancestor yet (`live`).
#[derive(Default)]
struct Paint {
    heap: BinaryHeap<(i64, ObjectId)>,
    flags: HashMap<ObjectId, u8>,
    queued: HashMap<ObjectId, usize>,
    live: usize,
}

impl Paint {
    fn stale(&self, x: &ObjectId) -> bool {
        self.flags.get(x).copied().unwrap_or(0) & STALE != 0
    }

    fn push(&mut self, g: &Graph, x: ObjectId, with: u8) -> Result<()> {
        if with != 0 {
            let f = self.flags.get(&x).copied().unwrap_or(0) | with;
            self.set(x, f);
        }
        let q = self.queued.entry(x).or_default();
        if *q == 0 && self.flags.get(&x).copied().unwrap_or(0) & STALE == 0 {
            self.live += 1;
        }
        *self.queued.get_mut(&x).unwrap() += 1;
        self.heap.push((g.get(&x)?.generation, x));
        Ok(())
    }

    fn popped(&mut self, x: ObjectId) {
        let q = self.queued.get_mut(&x).unwrap();
        *q -= 1;
        if *q == 0 && !self.stale(&x) {
            self.live -= 1;
        }
    }

    fn set(&mut self, x: ObjectId, f: u8) {
        let queued = self.queued.get(&x).copied().unwrap_or(0) > 0;
        if queued && !self.stale(&x) && f & STALE != 0 {
            self.live -= 1;
        }
        self.flags.insert(x, f);
    }
}

/// `ids` without any that is an ancestor of another, sorted, deduplicated.
pub fn reduce(g: &Graph, mut ids: Vec<ObjectId>) -> Result<Vec<ObjectId>> {
    ids.sort();
    ids.dedup();
    let mut out = Vec::new();
    for (i, x) in ids.iter().enumerate() {
        let mut below = false;
        for (j, y) in ids.iter().enumerate() {
            if i != j && g.is_ancestor(*x, *y)? {
                below = true;
                break;
            }
        }
        if !below {
            out.push(*x);
        }
    }
    Ok(out)
}
