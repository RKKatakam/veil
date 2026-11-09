//! Line diffs and three-way merges of text with a bounded cost (BUG-484).
//!
//! `diffy`'s Myers diff costs `O((N + M) · D)` for `D` differing lines and
//! has no limit: two rewritten 10,000-line versions of a file took 25 s
//! to render as a conflict, on every command that looked at it, and a
//! hostile remote could push one. Every diff and three-way merge of the
//! engine goes through here instead:
//!
//! * First the cost is measured: [`fits`] runs diffy's own algorithm (the
//!   same divide-and-conquer middle-snake search, step for step) with a
//!   work counter, and gives up past [`work_limit`] steps, which is linear
//!   in the input ([`WORK_PER_LINE`] per line plus [`WORK_BASE`]).
//! * Within the limit, diffy does the diff or merge: the output is exactly
//!   what it always was.
//! * Past it, the text is not compared line by line: a merge becomes one
//!   conflict holding both sides (and the base) whole, between the lines
//!   all three versions share at the start and the end; a two-way diff
//!   becomes one hunk replacing everything between the lines both share
//!   at the start and the end. Both are correct (a conflict is never
//!   wrong, and the hunk applies); they are only coarser.
//!
//! The whole cost is therefore linear in the size of the input, whatever
//! the input: the measurement is bounded by the limit, diffy then does the
//! same steps again, and the fallbacks are single passes.

use std::collections::HashMap;

/// Work allowed for one diff, independent of its size: small files are
/// always compared line by line (two fully rewritten 1,000-line files are
/// about 1.1 million steps).
pub const WORK_BASE: u64 = 4 << 20;
/// Work allowed per line of the two texts compared, on top of
/// [`WORK_BASE`]. Myers's search spends about `D² / 2` steps on `D`
/// differences, so a file of `L` lines may differ in about
/// `√(2 · WORK_PER_LINE · L)` lines before the fallback: some 2,500 for a
/// 10,000-line file, 5,000 for 40,000 lines.
pub const WORK_PER_LINE: u64 = 128;
/// Most separate edits a diff may have: diffy's compaction moves edits
/// within one vector, which costs up to the square of their number.
pub const MAX_EDITS: usize = 8192;

/// The work limit for comparing texts of `lines` lines in all.
pub fn work_limit(lines: usize) -> u64 {
    WORK_BASE.saturating_add(WORK_PER_LINE.saturating_mul(lines as u64))
}

/// Lines as diffy splits them: each with its `\n`; a last line without
/// one is a line too.
fn lines(text: &[u8]) -> impl Iterator<Item = &[u8]> {
    text.split_inclusive(|b| *b == b'\n')
}

/// Each text's lines as ids, equal lines getting equal ids.
fn classify<'a, const N: usize>(texts: [&'a [u8]; N]) -> [Vec<u32>; N] {
    let mut ids: HashMap<&'a [u8], u32> = HashMap::new();
    texts.map(|t| {
        lines(t)
            .map(|l| {
                let next = ids.len() as u32;
                *ids.entry(l).or_insert(next)
            })
            .collect()
    })
}

/// A work counter: `false` once the limit is passed.
struct Work {
    left: u64,
    edits: usize,
}

impl Work {
    fn spend(&mut self, n: u64) -> bool {
        match self.left.checked_sub(n) {
            Some(l) => {
                self.left = l;
                true
            }
            None => false,
        }
    }
}

fn common_prefix(a: &[u32], b: &[u32]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

fn common_suffix(a: &[u32], b: &[u32]) -> usize {
    a.iter().rev().zip(b.iter().rev()).take_while(|(x, y)| x == y).count()
}

/// Furthest-reaching x per diagonal `k` (`-max..=max`).
struct V {
    offset: isize,
    v: Vec<usize>,
}

impl V {
    fn new(max_d: usize) -> V {
        V { offset: max_d as isize, v: vec![0; 2 * max_d + 2] }
    }
    fn get(&self, k: isize) -> usize {
        self.v[(k + self.offset) as usize]
    }
    fn set(&mut self, k: isize, x: usize) {
        self.v[(k + self.offset) as usize] = x;
    }
}

fn max_d(n: usize, m: usize) -> usize {
    (n + m).div_ceil(2) + 1
}

/// diffy's middle snake (`diffy::diff::myers::find_middle_snake`), with
/// every diagonal step and every line compared counted: the start of the
/// middle snake of an optimal path, `None` past the limit.
fn middle_snake(a: &[u32], b: &[u32], vf: &mut V, vb: &mut V, work: &mut Work) -> Option<(usize, usize)> {
    let (n, m) = (a.len(), b.len());
    let delta = n as isize - m as isize;
    let odd = delta & 1 == 1;
    vf.set(1, 0);
    vb.set(1, 0);
    for d in 0..max_d(n, m) as isize {
        if !work.spend(2 * d as u64 + 2) {
            return None;
        }
        for k in (-d..=d).rev().step_by(2) {
            let mut x = if k == -d || (k != d && vf.get(k - 1) < vf.get(k + 1)) { vf.get(k + 1) } else { vf.get(k - 1) + 1 };
            let y = (x as isize - k) as usize;
            let (x0, y0) = (x, y);
            if x <= n && y <= m {
                let adv = common_prefix(&a[x..], &b[y..]);
                if !work.spend(adv as u64) {
                    return None;
                }
                x += adv;
            }
            vf.set(k, x);
            if odd && (k - delta).abs() < d && vf.get(k) + vb.get(-(k - delta)) >= n {
                return Some((x0, y0));
            }
        }
        for k in (-d..=d).rev().step_by(2) {
            let mut x = if k == -d || (k != d && vb.get(k - 1) < vb.get(k + 1)) { vb.get(k + 1) } else { vb.get(k - 1) + 1 };
            let y = (x as isize - k) as usize;
            if x < n && y < m {
                let adv = common_suffix(&a[..n - x], &b[..m - y]);
                if !work.spend(adv as u64) {
                    return None;
                }
                x += adv;
            }
            vb.set(k, x);
            if !odd && (k - delta).abs() <= d && vb.get(k) + vf.get(-(k - delta)) >= n {
                return Some((n - x, m - (x as isize - k) as usize));
            }
        }
    }
    // Unreachable for a correct search; treat as "too costly".
    None
}

/// diffy's divide and conquer (`diffy::diff::myers::conquer`), counted.
fn conquer(a: &[u32], b: &[u32], vf: &mut V, vb: &mut V, work: &mut Work) -> bool {
    let mut stack = vec![(a, b)];
    while let Some((a, b)) = stack.pop() {
        let p = common_prefix(a, b);
        let (a, b) = (&a[p..], &b[p..]);
        let s = common_suffix(a, b);
        let (a, b) = (&a[..a.len() - s], &b[..b.len() - s]);
        if !work.spend((p + s) as u64 + 1) {
            return false;
        }
        if a.is_empty() || b.is_empty() {
            if !a.is_empty() || !b.is_empty() {
                work.edits += 1;
                if work.edits > MAX_EDITS {
                    return false;
                }
            }
            continue;
        }
        let Some((x, y)) = middle_snake(a, b, vf, vb, work) else { return false };
        stack.push((&a[x..], &b[y..]));
        stack.push((&a[..x], &b[..y]));
    }
    true
}

/// Can diffy diff these line sequences within the work limit?
fn ids_fit(a: &[u32], b: &[u32], limit: u64) -> bool {
    let p = common_prefix(a, b);
    let (a, b) = (&a[p..], &b[p..]);
    let s = common_suffix(a, b);
    let (a, b) = (&a[..a.len() - s], &b[..b.len() - s]);
    if a.is_empty() || b.is_empty() {
        return true;
    }
    // A line kept by an edit script is in both texts, so at least the
    // difference of the two texts' line counts, line by line, is deleted
    // or inserted. The search spends about `D² / 4` steps finding the
    // middle of a script of `D` edits: past the limit, no need to try.
    let mut count = vec![0i64; a.iter().chain(b).max().map_or(0, |m| *m as usize + 1)];
    for x in a {
        count[*x as usize] += 1;
    }
    for x in b {
        count[*x as usize] -= 1;
    }
    let at_least: u64 = count.iter().map(|c| c.unsigned_abs()).sum();
    if at_least.saturating_mul(at_least) / 4 > limit {
        return false;
    }
    let md = max_d(a.len(), b.len());
    let (mut vf, mut vb) = (V::new(md), V::new(md));
    let mut work = Work { left: limit, edits: 0 };
    conquer(a, b, &mut vf, &mut vb, &mut work)
}

/// Does a line diff of `old` and `new` fit in the work limit (so diffy may
/// compute it)?
pub fn fits(old: &[u8], new: &[u8]) -> bool {
    fits_within(old, new, None)
}

/// [`fits`] of two texts that share `lines - lines(old_mid) -
/// lines(new_mid)` lines at their start and end, given only what lies
/// between (`old_mid`, `new_mid`) and the texts' line count in all
/// (`lines`): the search skips shared lines anyway, and its limit counts
/// them. The same answer, without reading the shared lines (blame's
/// `map_lines`).
pub fn fits_middle(old_mid: &[u8], new_mid: &[u8], lines: usize) -> bool {
    if old_mid == new_mid {
        return true;
    }
    let [a, b] = classify([old_mid, new_mid]);
    ids_fit(&a, &b, work_limit(lines))
}

fn fits_within(old: &[u8], new: &[u8], limit: Option<u64>) -> bool {
    if old == new {
        return true;
    }
    let [a, b] = classify([old, new]);
    ids_fit(&a, &b, limit.unwrap_or_else(|| work_limit(a.len() + b.len())))
}

/// The conflict style of [`merge`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    /// `<<<<<<< ours`, `||||||| original`, `=======`, `>>>>>>> theirs`.
    Diff3,
    /// No base section.
    Merge,
}

/// The three-way merge of `ours` and `theirs` from `base`: `Ok` with the
/// clean result, or `Err` with the result holding conflict markers of
/// `marker_len` characters (diffy's `MergeOptions::merge_bytes`, in
/// bounded time: see the module documentation).
pub fn merge(base: &[u8], ours: &[u8], theirs: &[u8], marker_len: usize, style: Style) -> Result<Vec<u8>, Vec<u8>> {
    merge_within(base, ours, theirs, marker_len, style, None)
}

fn merge_within(base: &[u8], ours: &[u8], theirs: &[u8], marker_len: usize, style: Style, limit: Option<u64>) -> Result<Vec<u8>, Vec<u8>> {
    let [b, o, t] = classify([base, ours, theirs]);
    let fit = |x: &[u32]| ids_fit(&b, x, limit.unwrap_or_else(|| work_limit(b.len() + x.len())));
    if fit(&o) && fit(&t) {
        let diffy_style = match style {
            Style::Diff3 => diffy::ConflictStyle::Diff3,
            Style::Merge => diffy::ConflictStyle::Merge,
        };
        return diffy::MergeOptions::new().set_conflict_marker_length(marker_len).set_conflict_style(diffy_style).merge_bytes(base, ours, theirs);
    }
    // Too costly to compare: what diffy's cleanup would conclude for one
    // conflict spanning everything.
    if ours == theirs || base == theirs {
        return Ok(ours.to_vec());
    }
    if base == ours {
        return Ok(theirs.to_vec());
    }
    Err(whole_conflict(base, ours, theirs, [&b, &o, &t], marker_len, style))
}

/// One conflict between the lines all three versions share at the start
/// and at the end, laid out as diffy lays out a conflict.
fn whole_conflict(base: &[u8], ours: &[u8], theirs: &[u8], ids: [&[u32]; 3], marker_len: usize, style: Style) -> Vec<u8> {
    let [b, o, t] = ids;
    let shortest = b.len().min(o.len()).min(t.len());
    let p = (0..shortest).take_while(|&i| b[i] == o[i] && b[i] == t[i]).count();
    let s = (0..shortest - p)
        .take_while(|&i| {
            let (x, y, z) = (b[b.len() - 1 - i], o[o.len() - 1 - i], t[t.len() - 1 - i]);
            x == y && x == z
        })
        .count();
    // Byte ranges of lines `p .. len - s` of each text.
    let middle = |text: &'_ [u8], n: usize| -> (usize, usize) {
        let mut start = 0;
        let mut end = text.len();
        for (i, l) in lines(text).enumerate() {
            if i < p {
                start += l.len();
            }
        }
        for (i, l) in lines(text).enumerate() {
            if i >= n - s {
                end -= l.len();
            }
        }
        (start, end)
    };
    let (bm, om, tm) = (middle(base, b.len()), middle(ours, o.len()), middle(theirs, t.len()));
    let mut out = Vec::with_capacity(base.len() + ours.len() + theirs.len() + 4 * (marker_len + 10));
    let marker = |out: &mut Vec<u8>, c: u8, label: &[u8]| {
        out.extend(std::iter::repeat_n(c, marker_len));
        if !label.is_empty() {
            out.push(b' ');
            out.extend_from_slice(label);
        }
        out.push(b'\n');
    };
    out.extend_from_slice(&ours[..om.0]);
    marker(&mut out, b'<', b"ours");
    out.extend_from_slice(&ours[om.0..om.1]);
    if style == Style::Diff3 {
        marker(&mut out, b'|', b"original");
        out.extend_from_slice(&base[bm.0..bm.1]);
    }
    marker(&mut out, b'=', b"");
    out.extend_from_slice(&theirs[tm.0..tm.1]);
    marker(&mut out, b'>', b"theirs");
    out.extend_from_slice(&ours[om.1..]);
    out
}

/// `diffy::create_patch(old, new)` in bounded time. Past the work limit,
/// one hunk replaces every line between those both texts share at the
/// start and at the end (with diffy's three lines of context). The patch
/// borrows from `old`, `new` or `scratch`.
pub fn create_patch<'a>(old: &'a str, new: &'a str, scratch: &'a mut String) -> diffy::Patch<'a, str> {
    create_patch_within(old, new, scratch, None)
}

fn create_patch_within<'a>(old: &'a str, new: &'a str, scratch: &'a mut String, limit: Option<u64>) -> diffy::Patch<'a, str> {
    if fits_within(old.as_bytes(), new.as_bytes(), limit) {
        return diffy::create_patch(old, new);
    }
    let a: Vec<&str> = old.split_inclusive('\n').collect();
    let b: Vec<&str> = new.split_inclusive('\n').collect();
    let p = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let s = a[p..].iter().rev().zip(b[p..].iter().rev()).take_while(|(x, y)| x == y).count();
    const CONTEXT: usize = 3;
    let from = p.saturating_sub(CONTEXT);
    let (a_to, b_to) = ((a.len() - s + CONTEXT).min(a.len()), (b.len() - s + CONTEXT).min(b.len()));
    let range = |start: usize, len: usize| match len {
        0 => format!("{start},0"),
        1 => format!("{}", start + 1),
        _ => format!("{},{len}", start + 1),
    };
    let mut text = String::with_capacity(old.len() + new.len() + 64);
    text.push_str("--- original\n+++ modified\n");
    // 1-based, except that an empty range (an empty text) names
    // position 0, as diffy writes it.
    text.push_str(&format!("@@ -{} +{} @@\n", range(from, a_to - from), range(from, b_to - from)));
    let line = |text: &mut String, sign: char, l: &str| {
        text.push(sign);
        text.push_str(l);
        if !l.ends_with('\n') {
            text.push_str("\n\\ No newline at end of file\n");
        }
    };
    for l in &a[from..p] {
        line(&mut text, ' ', l);
    }
    for l in &a[p..a.len() - s] {
        line(&mut text, '-', l);
    }
    for l in &b[p..b.len() - s] {
        line(&mut text, '+', l);
    }
    for l in &a[a.len() - s..a_to] {
        line(&mut text, ' ', l);
    }
    *scratch = text;
    let scratch: &'a String = scratch;
    // The text is well formed by construction; should diffy ever refuse
    // it, the exact (unbounded) diff is still correct.
    diffy::Patch::from_str(scratch).unwrap_or_else(|_| diffy::create_patch(old, new))
}

/// The union merge of `ours` and `theirs` from `base` (`.veilattributes`
/// `merge=union`): the line merge, where each conflicting hunk takes ours'
/// lines followed by theirs'. Never fails, and never holds a line only the
/// base has (the base's section of a conflict is dropped).
pub fn merge_union(base: &[u8], ours: &[u8], theirs: &[u8]) -> Vec<u8> {
    // Markers long enough to appear in no input, so the conflict blocks can
    // be cut out unambiguously (as `merge::merge_keeping_base` does).
    let longest_run = [base, ours, theirs]
        .iter()
        .flat_map(|x| x.chunk_by(|a, b| a == b))
        .filter(|run| matches!(run[0], b'<' | b'=' | b'>'))
        .map(|run| run.len())
        .max()
        .unwrap_or(0);
    let n = longest_run.max(63) + 1;
    let marker = |c: u8, label: &[u8]| {
        let mut m = vec![c; n];
        m.extend_from_slice(label);
        m.push(b'\n');
        m
    };
    let (start, mid, end) = (marker(b'<', b" ours"), marker(b'=', b""), marker(b'>', b" theirs"));
    let merged = match merge(base, ours, theirs, n, Style::Merge) {
        Ok(m) => return m,
        Err(m) => m,
    };
    let find = |hay: &[u8], needle: &[u8]| memchr::memmem::find(hay, needle);
    let mut out = Vec::with_capacity(merged.len());
    let mut rest = merged.as_slice();
    while let Some(i) = find(rest, &start) {
        out.extend_from_slice(&rest[..i]);
        rest = &rest[i + start.len()..];
        let Some(m) = find(rest, &mid) else { break };
        out.extend_from_slice(&rest[..m]);
        rest = &rest[m + mid.len()..];
        let Some(e) = find(rest, &end) else { break };
        out.extend_from_slice(&rest[..e]);
        rest = &rest[e + end.len()..];
    }
    out.extend_from_slice(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(prefix: &str, n: usize) -> String {
        (0..n).map(|i| format!("{prefix} line {i}\n")).collect()
    }

    #[test]
    fn within_the_limit_the_merge_is_diffys() {
        let base = "a\nb\nc\nd\ne\n";
        let ours = "a\nB\nc\nd\ne\n";
        let theirs = "a\nb\nc\nD\ne\n";
        assert_eq!(merge(base.as_bytes(), ours.as_bytes(), theirs.as_bytes(), 7, Style::Diff3), diffy::merge_bytes(base.as_bytes(), ours.as_bytes(), theirs.as_bytes()));
        let theirs = "a\nX\nc\nd\ne\n";
        let m = merge(base.as_bytes(), ours.as_bytes(), theirs.as_bytes(), 7, Style::Diff3);
        assert_eq!(m, diffy::merge_bytes(base.as_bytes(), ours.as_bytes(), theirs.as_bytes()));
        assert!(m.is_err());
    }

    /// The fallback's layout is diffy's for one conflict over the middle.
    #[test]
    fn past_the_limit_one_conflict_holds_every_side_whole() {
        let base = format!("top\n{}bottom\n", text("base", 50));
        let ours = format!("top\n{}bottom\n", text("ours", 50));
        let theirs = format!("top\n{}bottom", text("theirs", 40));
        for style in [Style::Diff3, Style::Merge] {
            let got = merge_within(base.as_bytes(), ours.as_bytes(), theirs.as_bytes(), 9, style, Some(10)).unwrap_err();
            let want = diffy::MergeOptions::new()
                .set_conflict_marker_length(9)
                .set_conflict_style(if style == Style::Diff3 { diffy::ConflictStyle::Diff3 } else { diffy::ConflictStyle::Merge })
                .merge_bytes(base.as_bytes(), ours.as_bytes(), theirs.as_bytes())
                .unwrap_err();
            assert_eq!(String::from_utf8_lossy(&got), String::from_utf8_lossy(&want));
        }
        // Trivial merges stay clean.
        let (b, o) = (base.as_bytes(), ours.as_bytes());
        assert_eq!(merge_within(b, o, o, 7, Style::Diff3, Some(1)), Ok(o.to_vec()));
        assert_eq!(merge_within(b, b, o, 7, Style::Diff3, Some(1)), Ok(o.to_vec()));
        assert_eq!(merge_within(b, o, b, 7, Style::Diff3, Some(1)), Ok(o.to_vec()));
        assert_eq!(merge_within(b"", b"", b"", 7, Style::Diff3, Some(1)), Ok(Vec::new()));
        // No line in common.
        let got = merge_within(b"x\n", b"y", b"z\n", 7, Style::Diff3, Some(1)).unwrap_err();
        assert_eq!(got, b"<<<<<<< ours\ny||||||| original\nx\n=======\nz\n>>>>>>> theirs\n");
    }

    /// The fallback hunk is the one diffy finds where no line in the
    /// middle is shared, and applies like any other.
    #[test]
    fn past_the_limit_one_hunk_replaces_the_middle() {
        let cases = [
            (format!("{}{}{}", text("top", 5), text("old", 20), text("end", 5)), format!("{}{}{}", text("top", 5), text("new", 10), text("end", 5))),
            (text("old", 3), text("new", 2)),
            (String::new(), text("new", 2)),
            (text("old", 2), String::new()),
            ("a\nb".to_string(), "a\nc".to_string()),
            ("a\nb\n".to_string(), "a\nb".to_string()),
            (format!("{}x\n", text("top", 1)), format!("{}y\n", text("top", 1))),
        ];
        for (old, new) in cases {
            let mut scratch = String::new();
            let got = create_patch_within(&old, &new, &mut scratch, Some(0));
            assert_eq!(diffy::apply(&old, &got).unwrap(), new, "{old:?} → {new:?}\n{got}");
            let want = diffy::create_patch(&old, &new);
            let ranges = |p: &diffy::Patch<'_, str>| {
                p.hunks().iter().map(|h| (h.old_range().start(), h.old_range().len(), h.new_range().start(), h.new_range().len())).collect::<Vec<_>>()
            };
            assert_eq!(ranges(&got), ranges(&want), "{old:?} → {new:?}\n{got}\n{want}");
        }
    }

    #[test]
    fn the_measurement_agrees_with_the_cost() {
        // Small and near-equal texts always fit; full rewrites of large
        // ones do not.
        assert!(fits(text("a", 500).as_bytes(), text("b", 500).as_bytes()));
        let mut edited = text("a", 20_000);
        edited.insert_str(0, "new first line\n");
        assert!(fits(text("a", 20_000).as_bytes(), edited.as_bytes()));
        assert!(!fits(text("a", 20_000).as_bytes(), text("b", 20_000).as_bytes()));
    }
}
