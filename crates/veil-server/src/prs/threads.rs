//! Threads anchored to lines across revisions (`docs/HUB.md` §7.3).
//!
//! * An anchor names, on one revision, a change of the stack (by change
//!   id), a file that change changed, a side (`old`: the change's parent,
//!   `new`: the change), lines `start..=end` (1-based), and the BLAKE3 hash
//!   of those lines (`context`).
//! * **On each new revision** an open anchor moves to the same change id's
//!   new snapshot: as it is when the file on that side is the same object;
//!   otherwise through the diff of the two versions (lines inside a changed
//!   block do not map), and only if the hash of the lines it lands on is
//!   still `context`. Otherwise the thread is **outdated** (shown, with no
//!   position, from then on).
//! * Anchors name only change ids, paths the change changed and line
//!   numbers: everything a viewer of the PR may read, never a snapshot id.

use serde::{Deserialize, Serialize};

use super::revision::{change_files, entry_at, text_of, StackChange};
use crate::{
    derive::Cx,
    error::{Error, Result},
};

/// The most lines one anchor covers.
pub const MAX_ANCHOR_LINES: u32 = 1_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnchorRequest {
    pub change: Option<String>,
    pub path: String,
    #[serde(default)]
    pub side: Option<String>,
    pub start: u32,
    pub end: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Anchor {
    pub revision: u32,
    pub change: String,
    pub path: String,
    pub side: String,
    pub start: u32,
    pub end: u32,
    pub context: String,
}

/// Where an anchor is on the current revision.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct At {
    pub revision: u32,
    pub start: u32,
    pub end: u32,
}

fn context_of(lines: &[&str]) -> String {
    let mut h = blake3::Hasher::new_derive_key("veil 2026 hub pr anchor v1");
    for l in lines {
        h.update(&(l.len() as u64).to_le_bytes());
        h.update(l.as_bytes());
    }
    hex::encode(&h.finalize().as_bytes()[..16])
}

/// The text a side of a change holds at `path`, if it is text.
fn side_text(cx: &Cx, c: &StackChange, side: &str, path: &str) -> Result<Option<(veil_core::ObjectId, String)>> {
    let snap = if side == "old" { c.parent_id() } else { c.snapshot_id() };
    let tree = cx.src.snapshot(&snap)?.tree;
    let Some(e) = entry_at(&cx.src, tree, path)? else { return Ok(None) };
    Ok(text_of(cx, &e)?.map(|t| (e.id, t)))
}

/// Check an anchor a viewer of the PR asked for, on revision `revision`
/// whose stack is `stack`.
pub fn anchor(cx: &Cx, revision: u32, stack: &[StackChange], a: &AnchorRequest) -> Result<Anchor> {
    let bad = |m: &str| Error::bad_request(m.to_string());
    let c = match &a.change {
        Some(id) => stack.iter().find(|c| c.change == *id).ok_or_else(|| bad("no such change in this revision of the PR"))?,
        // The top change that changed the file.
        None => {
            let mut found = None;
            for c in stack.iter().rev() {
                if change_files(cx, c)?.iter().any(|f| f.path == a.path) {
                    found = Some(c);
                    break;
                }
            }
            found.ok_or_else(|| bad("no change of this PR changes that path"))?
        }
    };
    if !change_files(cx, c)?.iter().any(|f| f.path == a.path) {
        return Err(bad("that change does not change that path: anchor to a file the change changed"));
    }
    let side = a.side.clone().unwrap_or_else(|| "new".into());
    if side != "old" && side != "new" {
        return Err(bad("side is `old` or `new`"));
    }
    let end = a.end.unwrap_or(a.start);
    if a.start == 0 || end < a.start || end - a.start >= MAX_ANCHOR_LINES {
        return Err(bad("lines are 1-based, start ≤ end, at most 1,000 of them"));
    }
    let (_, text) = side_text(cx, c, &side, &a.path)?.ok_or_else(|| bad("that side of the file is not text the server can show (absent, binary, a secret or over 1 MiB)"))?;
    let lines = veil_core::hunks::lines(&text);
    if end as usize > lines.len() {
        return Err(bad(&format!("that side of the file has {} lines", lines.len())));
    }
    Ok(Anchor {
        revision,
        change: c.change.clone(),
        path: a.path.clone(),
        side,
        start: a.start,
        end,
        context: context_of(&lines[a.start as usize - 1..end as usize]),
    })
}

/// The most bytes of file text one new revision reads to carry its
/// threads (both sides of each file, once): past it, the remaining files'
/// threads are outdated, in a fixed order (BUG-1255).
pub const CARRY_BUDGET: u64 = 64 << 20;

/// One file side's two versions, as carrying needs them (BUG-1258): the
/// diff's block positions only, and the new text with where each line
/// starts. About 4 bytes a line beside the text; one file is held at a
/// time.
struct Versions {
    same: bool,
    blocks: Vec<(usize, usize, usize, usize)>,
    text: String,
    starts: Vec<u32>,
}

impl Versions {
    /// New lines `s..=e` (0-based), with their line breaks.
    fn lines(&self, s: usize, e: usize) -> Vec<&str> {
        (s..=e)
            .map(|i| {
                let from = self.starts[i] as usize;
                let to = self.starts.get(i + 1).map_or(self.text.len(), |x| *x as usize);
                &self.text[from..to]
            })
            .collect()
    }
}

/// Where each anchor (thread id, anchor, its place now on stack `old`) is
/// on the next revision's stack `new` (numbered `revision`); `None`:
/// outdated. Each (change, side, path) is read and diffed once (BUG-1255),
/// one at a time (BUG-1258), within [`CARRY_BUDGET`] bytes read, in the
/// order of each file's first thread; the deadline is checked between
/// files.
pub fn carry_all(
    cx: &Cx,
    anchors: Vec<(String, Anchor, At)>,
    old: &[StackChange],
    new: &[StackChange],
    revision: u32,
    deadline: std::time::Instant,
) -> Result<Vec<(String, Option<At>)>> {
    type Key = (String, String, String);
    let mut order: Vec<Key> = Vec::new();
    let mut groups: std::collections::HashMap<Key, Vec<(String, Anchor, At)>> = std::collections::HashMap::new();
    for x in anchors {
        let k = (x.1.change.clone(), x.1.side.clone(), x.1.path.clone());
        if !groups.contains_key(&k) {
            order.push(k.clone());
        }
        groups.entry(k).or_default().push(x);
    }
    let mut budget = CARRY_BUDGET;
    let mut out = Vec::new();
    for k in order {
        if std::time::Instant::now() > deadline {
            return Err(crate::query::graph::too_slow());
        }
        let v = match (old.iter().find(|c| c.change == k.0), new.iter().find(|c| c.change == k.0)) {
            (Some(oc), Some(nc)) => versions(cx, oc, nc, &k.1, &k.2, &mut budget)?,
            _ => None,
        };
        for (tid, a, now) in groups.remove(&k).unwrap_or_default() {
            let at = match &v {
                None => None,
                Some(v) if v.same => Some(At { revision, ..now }),
                Some(v) => moved(v, &a, now, revision),
            };
            out.push((tid, at));
        }
        // `v` (this file's text and positions) is dropped here.
    }
    Ok(out)
}

/// The two versions of a file side, within `budget`; `None` if either is
/// absent or not text, or the budget is spent.
fn versions(cx: &Cx, oc: &StackChange, nc: &StackChange, side: &str, path: &str, budget: &mut u64) -> Result<Option<Versions>> {
    let side_entry = |c: &StackChange| -> Result<Option<veil_core::object::TreeEntry>> {
        let snap = if side == "old" { c.parent_id() } else { c.snapshot_id() };
        entry_at(&cx.src, cx.src.snapshot(&snap)?.tree, path)
    };
    let (Some(o), Some(n)) = (side_entry(oc)?, side_entry(nc)?) else { return Ok(None) };
    if o.id == n.id {
        return Ok(Some(Versions { same: true, blocks: Vec::new(), text: String::new(), starts: Vec::new() }));
    }
    if o.size + n.size > *budget {
        *budget = 0;
        return Ok(None);
    }
    *budget -= o.size + n.size;
    let (Some(ot), Some(nt)) = (text_of(cx, &o)?, text_of(cx, &n)?) else { return Ok(None) };
    let blocks = veil_core::hunks::blocks(&ot, &nt);
    drop(ot);
    let mut starts = vec![0u32];
    starts.extend(nt.match_indices('\n').map(|(i, _)| i as u32 + 1).filter(|i| (*i as usize) < nt.len()));
    if nt.is_empty() {
        starts.clear();
    }
    Ok(Some(Versions { same: false, blocks, text: nt, starts }))
}

/// 0-based old line `l` through `blocks`, if it is not inside a changed
/// block.
fn map_line(blocks: &[(usize, usize, usize, usize)], l: usize) -> Option<usize> {
    let mut delta: isize = 0;
    for &(old_at, old_len, new_at, new_len) in blocks {
        if l < old_at {
            break;
        }
        if l < old_at + old_len {
            return None;
        }
        delta = (new_at + new_len) as isize - (old_at + old_len) as isize;
    }
    Some((l as isize + delta) as usize)
}

/// Anchor `a` at `now` through `v`, if its lines map whole and still hash
/// to its context.
fn moved(v: &Versions, a: &Anchor, now: At, revision: u32) -> Option<At> {
    let (s, e) = (now.start as usize - 1, now.end as usize - 1);
    let (ns, ne) = (map_line(&v.blocks, s)?, map_line(&v.blocks, e)?);
    if ne < ns || ne - ns != e - s || ne >= v.starts.len() {
        return None;
    }
    (context_of(&v.lines(ns, ne)) == a.context).then_some(At {
        revision,
        start: ns as u32 + 1,
        end: ne as u32 + 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapped(old: &str, new: &str, l: usize) -> Option<usize> {
        map_line(&veil_core::hunks::blocks(old, new), l)
    }

    #[test]
    fn lines_map_through_edits() {
        let old = "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\n";
        // Two lines inserted at the top: everything moves down by two.
        let new = format!("x\ny\n{old}");
        for l in 0..12 {
            assert_eq!(mapped(old, &new, l), Some(l + 2));
        }
        // A line changed in the middle: it does not map; the rest does.
        let new = old.replace("f\n", "F\n");
        assert_eq!(mapped(old, &new, 5), None);
        assert_eq!(mapped(old, &new, 4), Some(4));
        assert_eq!(mapped(old, &new, 6), Some(6));
        // Lines deleted above: moved up.
        let new = old.replacen("a\nb\nc\n", "", 1);
        assert_eq!(mapped(old, &new, 10), Some(7));
        assert_eq!(mapped(old, &new, 1), None);
        // Inserted below: unchanged.
        let new = format!("{old}m\n");
        assert_eq!(mapped(old, &new, 3), Some(3));
    }
}
