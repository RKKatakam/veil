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

/// 0-based old line `l` through `d`, if it is not inside a changed block.
fn map_line(d: &veil_core::hunks::TextDiff, l: usize) -> Option<usize> {
    let mut delta: isize = 0;
    for h in &d.hunks {
        for b in &h.blocks {
            if l < b.old_at {
                return Some((l as isize + delta) as usize);
            }
            if l < b.old_at + b.old_len {
                return None;
            }
            delta = (b.new_at + b.added.len()) as isize - (b.old_at + b.old_len) as isize;
        }
    }
    Some((l as isize + delta) as usize)
}

/// Where anchor `a`, at `now` on stack `old`, is on the next revision's
/// stack `new` (numbered `revision`); `None`: outdated.
pub fn carry(cx: &Cx, a: &Anchor, now: At, old: &[StackChange], new: &[StackChange], revision: u32) -> Result<Option<At>> {
    let (Some(oc), Some(nc)) = (old.iter().find(|c| c.change == a.change), new.iter().find(|c| c.change == a.change)) else {
        return Ok(None);
    };
    let (Some((oid, otext)), Some((nid, ntext))) = (side_text(cx, oc, &a.side, &a.path)?, side_text(cx, nc, &a.side, &a.path)?) else {
        return Ok(None);
    };
    if oid == nid {
        return Ok(Some(At { revision, ..now }));
    }
    let d = veil_core::hunks::diff_text(&otext, &ntext);
    let (s, e) = (now.start as usize - 1, now.end as usize - 1);
    let (Some(ns), Some(ne)) = (map_line(&d, s), map_line(&d, e)) else { return Ok(None) };
    let lines = veil_core::hunks::lines(&ntext);
    if ne < ns || ne - ns != e - s || ne >= lines.len() || context_of(&lines[ns..=ne]) != a.context {
        return Ok(None);
    }
    Ok(Some(At {
        revision,
        start: ns as u32 + 1,
        end: ne as u32 + 1,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapped(old: &str, new: &str, l: usize) -> Option<usize> {
        map_line(&veil_core::hunks::diff_text(old, new), l)
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
