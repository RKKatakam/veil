//! Diff hunks of one text file, and the file with a chosen subset of them
//! applied: the pure logic under `vl split -i` and `vl squash -i`
//! (`crate::selection` does the trees, sealing and audiences).
//!
//! **Hunks** are exactly the hunks `vl diff` shows (and `vl diff --json`
//! lists, in the same order): `diffy`'s unified diff with three lines of
//! context. A script can therefore read the numbers it selects from
//! `vl diff -r REV --json`.
//!
//! **Blocks.** A hunk holds one or more runs of changed lines separated by
//! unchanged ones (two edits closer than seven lines share a hunk). Each run
//! is a [`Block`], the smallest unit that can be chosen: `s` in the picker
//! splits a hunk into its blocks, as `git add -p` does, and a spec names
//! block `M` of hunk `N` as `N.M`.
//!
//! **Applying** a set of blocks replaces, in the old text, the lines each
//! chosen block removes by the lines it adds, and keeps every other line as
//! it is, byte for byte (line breaks, `\r`, a last line without a break).
//! Choosing every block gives the new text exactly, choosing none the old
//! text, and the blocks a selection leaves out, applied on their own, are
//! the rest of the change: [`apply`] of a set and of its complement are the
//! two halves of a split.

use std::collections::BTreeSet;

/// What a line of a hunk is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineKind {
    Context,
    Removed,
    Added,
}

impl LineKind {
    /// The unified-diff prefix: ` `, `-` or `+`.
    pub fn prefix(self) -> char {
        match self {
            LineKind::Context => ' ',
            LineKind::Removed => '-',
            LineKind::Added => '+',
        }
    }
}

/// One line of a hunk, with its line break (none for a last line without
/// one).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub kind: LineKind,
    pub text: String,
}

/// A run of changed lines inside a hunk: the smallest unit a selection can
/// take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// 0-based index, in the old text, of the first line it replaces (where
    /// it inserts, if it removes nothing).
    pub old_at: usize,
    /// How many old lines it removes.
    pub old_len: usize,
    /// 0-based index, in the new text, of the first line it adds.
    pub new_at: usize,
    /// The lines it adds, with their line breaks.
    pub added: Vec<String>,
    /// Its lines in [`Hunk::lines`]: `lines[first..end]`.
    pub first: usize,
    pub end: usize,
}

/// One hunk, as `vl diff` shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hunk {
    /// The `@@ -old_start,old_lines +new_start,new_lines @@` header
    /// (1-based, as in a unified diff and in `vl diff --json`).
    pub old_start: usize,
    pub old_lines: usize,
    pub new_start: usize,
    pub new_lines: usize,
    pub lines: Vec<Line>,
    /// Its runs of changed lines, in order (at least one).
    pub blocks: Vec<Block>,
}

/// The hunks between two versions of a text file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TextDiff {
    pub hunks: Vec<Hunk>,
}

/// A block, named by its hunk and its place in the hunk (both 0-based).
pub type BlockId = (usize, usize);

impl TextDiff {
    /// Every block, in order.
    pub fn all_blocks(&self) -> BTreeSet<BlockId> {
        self.hunks
            .iter()
            .enumerate()
            .flat_map(|(h, hunk)| (0..hunk.blocks.len()).map(move |b| (h, b)))
            .collect()
    }

    /// No hunks: the two texts are equal.
    pub fn is_empty(&self) -> bool {
        self.hunks.is_empty()
    }
}

/// The lines of `text`, each with its line break (`\n`, so `\r\n` keeps
/// its `\r`); a last line without one is a line too. This is how `diffy`
/// splits lines, so block positions index into it.
pub fn lines(text: &str) -> Vec<&str> {
    text.split_inclusive('\n').collect()
}

/// The hunks from `old` to `new` (see the module documentation).
pub fn diff_text(old: &str, new: &str) -> TextDiff {
    // Bounded (BUG-484): past the work limit, one hunk replaces the
    // differing middle.
    let mut scratch = String::new();
    let patch = crate::textmerge::create_patch(old, new, &mut scratch);
    let hunks = patch
        .hunks()
        .iter()
        .map(|h| {
            let (or, nr) = (h.old_range(), h.new_range());
            // diffy's ranges are 1-based, except that an empty range names
            // the 0-based position it sits at.
            let mut old_idx = if !or.is_empty() { or.start() - 1 } else { or.start() };
            let mut new_idx = if !nr.is_empty() { nr.start() - 1 } else { nr.start() };
            let mut lines = Vec::with_capacity(h.lines().len());
            let mut blocks: Vec<Block> = Vec::new();
            let mut open: Option<Block> = None;
            for (i, l) in h.lines().iter().enumerate() {
                let (kind, text) = match l {
                    diffy::Line::Context(s) => (LineKind::Context, *s),
                    diffy::Line::Delete(s) => (LineKind::Removed, *s),
                    diffy::Line::Insert(s) => (LineKind::Added, *s),
                };
                lines.push(Line { kind, text: text.to_string() });
                if kind == LineKind::Context {
                    if let Some(b) = open.take() {
                        blocks.push(b);
                    }
                    old_idx += 1;
                    new_idx += 1;
                    continue;
                }
                let b = open.get_or_insert_with(|| Block {
                    old_at: old_idx,
                    old_len: 0,
                    new_at: new_idx,
                    added: Vec::new(),
                    first: i,
                    end: i,
                });
                b.end = i + 1;
                match kind {
                    LineKind::Removed => {
                        b.old_len += 1;
                        old_idx += 1;
                    }
                    _ => {
                        b.added.push(text.to_string());
                        new_idx += 1;
                    }
                }
            }
            blocks.extend(open);
            Hunk {
                old_start: or.start(),
                old_lines: or.len(),
                new_start: nr.start(),
                new_lines: nr.len(),
                lines,
                blocks,
            }
        })
        .collect();
    TextDiff { hunks }
}

/// `old` with the blocks `take` chooses applied (see the module
/// documentation). `diff` must be [`diff_text`] of `old` and some new text.
pub fn apply(old: &str, diff: &TextDiff, take: impl Fn(BlockId) -> bool) -> String {
    let old_lines = lines(old);
    let mut out = String::with_capacity(old.len());
    let mut at = 0;
    for (h, hunk) in diff.hunks.iter().enumerate() {
        for (b, block) in hunk.blocks.iter().enumerate() {
            let start = block.old_at.min(old_lines.len());
            for l in &old_lines[at.min(start)..start] {
                out.push_str(l);
            }
            let end = (block.old_at + block.old_len).min(old_lines.len());
            if take((h, b)) {
                for l in &block.added {
                    out.push_str(l);
                }
            } else {
                for l in &old_lines[start..end] {
                    out.push_str(l);
                }
            }
            at = end;
        }
    }
    for l in &old_lines[at.min(old_lines.len())..] {
        out.push_str(l);
    }
    out
}

/// The lines to show for block `b` of `hunk` on its own (`s` in the
/// picker): the block with up to three lines of context on each side, and
/// its `@@` header.
pub fn block_view(hunk: &Hunk, b: usize) -> (String, &[Line]) {
    let block = &hunk.blocks[b];
    let ctx = |i: usize| hunk.lines.get(i).is_some_and(|l| l.kind == LineKind::Context);
    let mut start = block.first;
    while start > 0 && block.first - start < 3 && ctx(start - 1) {
        start -= 1;
    }
    let mut end = block.end;
    while end < hunk.lines.len() && end - block.end < 3 && ctx(end) {
        end += 1;
    }
    let before = block.first - start;
    let shown = &hunk.lines[start..end];
    let old_n = shown.iter().filter(|l| l.kind != LineKind::Added).count();
    let new_n = shown.iter().filter(|l| l.kind != LineKind::Removed).count();
    let old_s = block.old_at - before;
    let new_s = block.new_at - before;
    let one = |s: usize, n: usize| if n > 0 { s + 1 } else { s };
    (format!("@@ -{},{} +{},{} @@", one(old_s, old_n), old_n, one(new_s, new_n), new_n), shown)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(d: &TextDiff) -> impl Fn(BlockId) -> bool + '_ {
        let s = d.all_blocks();
        move |id| s.contains(&id)
    }

    #[test]
    fn hunks_match_vl_diff_and_split_into_blocks() {
        let old = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20\n";
        let new = "1\nTWO\n3\n4\n5\nSIX\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20\nextra\n";
        let d = diff_text(old, new);
        assert_eq!(d.hunks.len(), 2, "the edits at 2 and 6 share a hunk; the append is its own");
        assert_eq!(d.hunks[0].blocks.len(), 2);
        assert_eq!(d.hunks[1].blocks.len(), 1);
        let p = diffy::create_patch(old, new);
        for (h, ph) in d.hunks.iter().zip(p.hunks()) {
            assert_eq!((h.old_start, h.old_lines), (ph.old_range().start(), ph.old_range().len()));
            assert_eq!((h.new_start, h.new_lines), (ph.new_range().start(), ph.new_range().len()));
        }
        assert_eq!(apply(old, &d, all(&d)), new);
        assert_eq!(apply(old, &d, |_| false), old);
        assert_eq!(apply(old, &d, |id| id == (0, 1)), old.replacen("\n6\n", "\nSIX\n", 1));
        assert_eq!(apply(old, &d, |id| id.0 == 1), format!("{old}extra\n"));
        let (header, lines) = block_view(&d.hunks[0], 1);
        assert_eq!(header, "@@ -3,7 +3,7 @@");
        assert_eq!(lines.iter().filter(|l| l.kind != LineKind::Context).count(), 2);
    }

    #[test]
    fn line_breaks_survive_exactly() {
        for (old, new) in [
            ("a\r\nb\r\n", "a\r\nB\r\n"),
            ("a\nb", "a\nb\n"),
            ("a\nb\n", "a\nb"),
            ("", "x"),
            ("x", ""),
            ("x\ny", "y\nx"),
        ] {
            let d = diff_text(old, new);
            assert_eq!(apply(old, &d, all(&d)), new, "{old:?} → {new:?}");
            assert_eq!(apply(old, &d, |_| false), old);
        }
    }
}
