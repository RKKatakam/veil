//! Derived data as one viewer may see it: the internal reads that S13's
//! query routes will serve from. Every answer is in **real** snapshot ids;
//! mapping them to the viewer's projected ids (`sync::projected`) is the
//! query layer's last step. A viewer's answer depends only on what they may
//! read, so it equals the answer computed on a project holding only their
//! projected history (the projection-equivalence test,
//! `tests/server_hub/derived.rs`).
//!
//! * [`Reader::visible`] decides, from the lists and the graph alone,
//!   exactly what `sync::projected` decides: whether a snapshot is in the
//!   viewer's history or collapses into its first parent.
//! * [`Reader::changes`] is the viewer's part of a change: sides they may
//!   not read are left out (an entry they cannot see is "absent"), and an
//!   added file's sources are only those they may read.
//! * [`Reader::merge_bases`] answers on the viewer's projected graph.
//!
//! **Not yet timing-safe** (design §6, row 4, for S13): `visible` and `rep`
//! walk hidden snapshots between visible ones, and `changes` decodes the
//! whole changed-paths object of a mixed change. Answers never depend on
//! hidden data; their cost does.

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
};

use veil_core::{hub::access::View, hub::project::Change, ObjectId};

use super::{
    changes::{self, PathChange, NONE, WITHHELD},
    graph::{reduce, Graph},
    lines::Lines,
};
use crate::{error::Result, sync::root_snapshot_id};

/// One viewer's reads of one project's derived data.
pub struct Reader<'a> {
    pub g: &'a Graph<'a>,
    pub view: &'a View<'a>,
    /// The lists the viewer may read.
    pub keys: Vec<String>,
    visible: RefCell<HashMap<ObjectId, bool>>,
    /// Snapshots already walked, and where the walk went from them: a
    /// snapshot whose representative is that one's ([`Reader::known_rep`]).
    reps: RefCell<HashMap<ObjectId, ObjectId>>,
    listed: RefCell<HashMap<ObjectId, bool>>,
    /// Steps taken: snapshots walked and list lookups ([`Reader::work`]).
    work: Cell<u64>,
}

/// What deciding one snapshot's visibility needs: nothing more, or another
/// snapshot's visibility first.
enum Step {
    Done(bool),
    Need(ObjectId),
}

impl<'a> Reader<'a> {
    /// `lines` and `view` must be of the same (accepted) policy.
    pub fn new(g: &'a Graph<'a>, lines: &Lines, view: &'a View<'a>) -> Reader<'a> {
        Reader {
            g,
            view,
            keys: lines.readable(view),
            visible: RefCell::new(HashMap::new()),
            reps: RefCell::new(HashMap::new()),
            listed: RefCell::new(HashMap::new()),
            work: Cell::new(0),
        }
    }

    /// The steps this reader has taken (snapshots walked, list lookups):
    /// what its answers cost, whatever the database's speed.
    pub fn work(&self) -> u64 {
        self.work.get()
    }

    /// Is `id` on one of the viewer's lists (did it change something they
    /// may read)?
    pub fn listed(&self, id: &ObjectId) -> Result<bool> {
        self.work.set(self.work.get() + 1);
        let row = self.g.get(id)?;
        let cx = self.g.cx;
        let pool = &cx.hub().db;
        let hex = id.hex();
        let n: i64 = cx.db(|| {
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM rule_history WHERE project_id = $1 AND line_key = ANY($2) AND generation = $3 AND snapshot = $4",
            )
            .bind(cx.project())
            .bind(&self.keys)
            .bind(row.generation)
            .bind(&hex)
            .fetch_one(pool)
        })?;
        Ok(n > 0)
    }

    /// Every snapshot on the viewer's lists, deduplicated (unordered: real
    /// generations depend on hidden snapshots, so S13 orders a log by what
    /// the viewer sees).
    pub fn listed_all(&self) -> Result<Vec<ObjectId>> {
        let cx = self.g.cx;
        let pool = &cx.hub().db;
        let rows: Vec<String> = cx.db(|| {
            sqlx::query_scalar("SELECT DISTINCT snapshot FROM rule_history WHERE project_id = $1 AND line_key = ANY($2)")
                .bind(cx.project())
                .bind(&self.keys)
                .fetch_all(pool)
        })?;
        let mut out: Vec<ObjectId> = rows.iter().filter_map(|s| ObjectId::from_hex(s).ok()).collect();
        out.sort();
        Ok(out)
    }

    /// Is `id` in the viewer's history, or does it collapse into its first
    /// parent (`docs/HUB.md` §13.4)? A change with one parent is in it when
    /// it changed something the viewer may read, or nothing at all (its
    /// tree is its parent's); a merge also when its parents are different
    /// snapshots for the viewer.
    ///
    /// Iterative (BUG-869): a merge needs its parents' representatives,
    /// which need older merges' visibility; those wait on an explicit
    /// stack, never on the thread's, whatever the history holds.
    pub fn visible(&self, id: &ObjectId) -> Result<bool> {
        let mut stack = vec![*id];
        while let Some(&x) = stack.last() {
            if self.decided(&x).is_some() {
                stack.pop();
                continue;
            }
            match self.step(&x)? {
                Step::Done(v) => {
                    self.visible.borrow_mut().insert(x, v);
                    stack.pop();
                }
                Step::Need(y) => stack.push(y),
            }
        }
        Ok(self.decided(id).unwrap())
    }

    fn decided(&self, id: &ObjectId) -> Option<bool> {
        if *id == root_snapshot_id() {
            return Some(true);
        }
        self.visible.borrow().get(id).copied()
    }

    /// Decide `x` from what is decided already, or name what it needs.
    fn step(&self, x: &ObjectId) -> Result<Step> {
        if let Some(v) = self.simple(x)? {
            return Ok(Step::Done(v));
        }
        let row = self.g.get(x)?;
        let first = match self.known_rep(&row.parents[0])? {
            Ok(r) => r,
            Err(need) => return Ok(Step::Need(need)),
        };
        let mut other = false;
        for p in &row.parents[1..] {
            match self.known_rep(p)? {
                Ok(r) => other |= r != first,
                Err(need) => return Ok(Step::Need(need)),
            }
        }
        Ok(Step::Done(other))
    }

    /// The visibility of `x` when it needs no other snapshot's: withheld,
    /// on a list, or one parent. `None` for a merge not on a list.
    fn simple(&self, x: &ObjectId) -> Result<Option<bool>> {
        let row = self.g.get(x)?;
        if row.changed.as_deref() == Some(WITHHELD) {
            // An embargo line is withheld until its release (S22).
            return Ok(Some(false));
        }
        let cached = self.listed.borrow().get(x).copied();
        let listed = match cached {
            Some(l) => l,
            None => {
                let l = self.listed(x)?;
                self.listed.borrow_mut().insert(*x, l);
                l
            }
        };
        if listed {
            return Ok(Some(true));
        }
        match row.parents.len() {
            0 => Ok(Some(false)),
            1 => Ok(Some(row.changed.as_deref() == Some(NONE))),
            _ => Ok(None),
        }
    }

    /// The representative of `id`, or the first merge on its first-parent
    /// line whose visibility is not decided yet. One-parent snapshots are
    /// decided as they are reached, and everything walked is left pointing
    /// at where the walk ended (`reps`: "its representative is that one's"),
    /// so no snapshot is walked twice (BUG-980): a run of `k` hidden changes
    /// costs `k`, whatever merges sit on it.
    fn known_rep(&self, id: &ObjectId) -> Result<std::result::Result<ObjectId, ObjectId>> {
        let mut walked = Vec::new();
        let mut x = *id;
        let out = loop {
            self.work.set(self.work.get() + 1);
            let pointer = self.reps.borrow().get(&x).copied();
            if let Some(t) = pointer {
                walked.push(x);
                x = t;
                continue;
            }
            let v = match self.decided(&x) {
                Some(v) => Some(v),
                None => {
                    let v = self.simple(&x)?;
                    if let Some(v) = v {
                        self.visible.borrow_mut().insert(x, v);
                    }
                    v
                }
            };
            match v {
                Some(true) => break Ok(x),
                Some(false) => {
                    walked.push(x);
                    x = self.g.get(&x)?.parents[0];
                }
                None => break Err(x),
            }
        };
        let end = match out {
            Ok(r) | Err(r) => r,
        };
        let mut reps = self.reps.borrow_mut();
        for w in walked {
            if w != end {
                reps.insert(w, end);
            }
        }
        Ok(out)
    }

    /// The snapshot of the viewer's history that `id` stands for: `id`, or
    /// the nearest first-parent ancestor in their history.
    pub fn rep(&self, id: &ObjectId) -> Result<ObjectId> {
        loop {
            match self.known_rep(id)? {
                Ok(r) => return Ok(r),
                Err(need) => {
                    self.visible(&need)?;
                }
            }
        }
    }

    /// The best common ancestors of `a` and `b` in the viewer's history.
    pub fn merge_bases(&self, a: ObjectId, b: ObjectId) -> Result<Vec<ObjectId>> {
        let mut reps = Vec::new();
        for m in self.g.merge_bases(a, b)? {
            reps.push(self.rep(&m)?);
        }
        reduce(self.g, reps)
    }

    /// The viewer's part of `id`'s changed paths; `None` when the snapshot
    /// changed too many paths to list (or is withheld): walk the trees.
    pub fn changes(&self, id: &ObjectId) -> Result<Option<Vec<PathChange>>> {
        let row = self.g.get(id)?;
        let Some(all) = self.g.cx.changed(row.changed.as_deref().unwrap_or(NONE))? else {
            return Ok(None);
        };
        let side = |path: &str, e: &Option<veil_core::TreeEntry>| e.clone().filter(|e| Lines::side_visible(self.view, path, e));
        let mut mine: Vec<PathChange> = Vec::new();
        for pc in &all.paths {
            let (old, new) = (side(&pc.path, &pc.old), side(&pc.path, &pc.new));
            if old.is_none() && new.is_none() {
                continue;
            }
            mine.push(PathChange {
                path: pc.path.clone(),
                from: Vec::new(),
                capped: false,
                old,
                new,
                prev: pc.prev.clone(),
            });
        }
        // Sources: the readable ones among those stored, unless the stored
        // list may lack some (capped, or similarity skipped for the whole
        // change): then computed on the viewer's part, as a project holding
        // only that part would.
        let recompute = !all.similar || all.paths.iter().any(|p| p.capped);
        if recompute {
            let part: Vec<Change> = mine
                .iter()
                .map(|p| Change {
                    path: p.path.clone(),
                    old: p.old.clone(),
                    new: p.new.clone(),
                })
                .collect();
            let (from, capped, _) = changes::sources(&self.g.cx.src, &part)?;
            for ((p, f), c) in mine.iter_mut().zip(from).zip(capped) {
                p.from = f;
                p.capped = c;
            }
        } else {
            let readable_source = |path: &str| mine.iter().any(|p| p.path == path && p.old.is_some());
            let stored: HashMap<&str, &PathChange> = all.paths.iter().map(|p| (p.path.as_str(), p)).collect();
            let picks: Vec<Vec<changes::From>> = mine
                .iter()
                .map(|p| {
                    if p.old.is_some() || p.new.is_none() {
                        return Vec::new();
                    }
                    stored[p.path.as_str()].from.iter().filter(|f| readable_source(&f.path)).cloned().collect()
                })
                .collect();
            for (p, f) in mine.iter_mut().zip(picks) {
                p.from = f;
            }
        }
        Ok(Some(mine))
    }
}
