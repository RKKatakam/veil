//! `vl blame`: line attribution through history, reading every version as
//! this reader may see it ([`readable_version`]).
//!
//! # Reading as a reader
//!
//! Every history read tool (blame, `vl grep`, the `-S`/`-G` log filters,
//! inexact rename detection) reads file content through one function,
//! [`readable_version`]. It never hands a sealed object to the decrypter
//! unless the envelope's label (bound to the ciphertext) names a key this
//! reader holds, and it never returns ciphertext:
//!
//! * [`Readable::Plain`]: public content, or a sealed secret file this
//!   reader opens (with [`Reader::Public`], plaintext only: what a public
//!   mirror holds);
//! * [`Readable::Redacted`]: nothing, and why.
//!
//! # The walk
//!
//! Lines of the file at the starting snapshot are open until attributed.
//! Snapshots are visited in topological order, children before parents
//! ([`crate::repo::Held::topo_children_first`]), each once, with every line its children
//! passed it (threat review 5: no snapshot is visited twice, whatever the
//! timestamps say). A snapshot's version is compared
//! with each parent's in order; a line the parent holds moves to the first
//! parent that holds it, the rest are attributed to the snapshot. A parent
//! whose readable version is identical (same object, or same bytes) takes
//! every open line without a diff. A parent whose version is
//! redacted stops the lines it might hold: they are reported unattributed
//! ("history sealed for …"), never guessed.
//!
//! # Limits
//!
//! Each diff is bounded as in [`crate::textmerge`] (BUG-484): past its work
//! limit the differing middle is attributed whole to the snapshot, and the
//! result says [`Blame::coarse`]. The walk stops after
//! [`BlameOptions::max_changes`] visits or when its work passes
//! [`BlameOptions::work_budget`]; lines still open are reported
//! unattributed. Work is what each step really cost: the lines read and
//! compared, plus each diff's search (`D²` for `D` differing lines, the
//! whole [`textmerge::work_limit`] for a diff past it). A single diff is
//! bounded, so the budget is overshot by at most one.

use std::{
    cmp::Ordering,
    collections::{BinaryHeap, HashMap},
    sync::Arc,
};

use crate::{
    builder::object_visibility,
    conflict::{self, Audience},
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Object, Text, TreeEntry, Visibility},
    rename::{self, RenameOptions},
    repo::Repo,
    store::ObjectStore,
    textmerge,
    tree::{diff_trees_hiding, lookup_to_read},
    vpath::VPath,
};

// ---- reading as a reader ---------------------------------------------------------

/// Whose eyes a history tool reads with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Reader {
    /// This repository's keychain: whatever its keys open.
    #[default]
    Me,
    /// A public mirror: plaintext objects, and no history an unreleased
    /// embargo withholds (the `--public` view).
    Public,
}

/// A file entry as one reader may read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Readable {
    /// The entry's own content. `id` is the object read (for a conflict,
    /// the blob id of its materialisation); `visibility` is what that
    /// object proves (labels are claims, BUG-482): `Public` for plaintext.
    Plain { id: ObjectId, data: Vec<u8>, visibility: Visibility },
    /// Nothing this reader may see.
    Redacted(Hidden),
}

impl Readable {
    /// The bytes read, unless redacted.
    pub fn data(&self) -> Option<&[u8]> {
        match self {
            Readable::Plain { data, .. } => Some(data),
            Readable::Redacted(_) => None,
        }
    }

    /// The object read, unless redacted. Equal ids mean equal content.
    pub fn id(&self) -> Option<ObjectId> {
        match self {
            Readable::Plain { id, .. } => Some(*id),
            Readable::Redacted(_) => None,
        }
    }

    pub fn is_plain(&self) -> bool {
        matches!(self, Readable::Plain { .. })
    }
}

/// Why a version is not readable, and for whom it is (labels are public
/// metadata; never the content).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hidden {
    pub reason: HiddenReason,
    /// Who can read it: what the object proves when it is present, the
    /// entry's label otherwise.
    pub visibility: Visibility,
}

/// The words of [`crate::store`]'s callers (`vl ls`, `vl diff`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenReason {
    /// Sealed for a scope this reader holds no key for.
    NoKey,
    /// Sealed, and absent here: a public remote never delivered it.
    Withheld,
    /// Sealed, and the reader is [`Reader::Public`].
    PublicView,
    /// A public object absent from the store (damage, not a redaction).
    Missing,
    /// Not a file (a directory, or an entry kind this build reads no
    /// content of).
    NotAFile,
}

impl HiddenReason {
    pub fn as_str(self) -> &'static str {
        match self {
            HiddenReason::NoKey => "no_key",
            HiddenReason::Withheld => "withheld",
            HiddenReason::PublicView => "public_view",
            HiddenReason::Missing => "missing",
            HiddenReason::NotAFile => "not_a_file",
        }
    }
}

/// What the readers did, for tests and reports: no content, no ids.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadStats {
    /// Sealed objects opened (the label named a key this reader holds).
    pub sealed_opened: u64,
    /// Sealed objects left closed after the label check (no key, or the
    /// public view).
    pub sealed_skipped: u64,
    /// Opens the keychain refused although the label check passed (a
    /// damaged envelope). Never expected.
    pub open_failed: u64,
}

impl ReadStats {
    pub fn add(&mut self, o: &ReadStats) {
        self.sealed_opened += o.sealed_opened;
        self.sealed_skipped += o.sealed_skipped;
        self.open_failed += o.open_failed;
    }
}

/// A description as a public mirror reads it (descriptions are plain
/// text). For `--public` views.
pub fn public_description(_store: &ObjectStore, t: &Text) -> Option<String> {
    Some(t.as_str().to_string())
}

/// File entry `e` as `reader` may read it (see the module docs).
pub fn readable_version(store: &ObjectStore, e: &TreeEntry, reader: Reader) -> Result<Readable> {
    readable_version_counted(store, e, reader, &mut ReadStats::default())
}

/// [`readable_version`], counting what it opened in `stats`.
pub fn readable_version_counted(store: &ObjectStore, e: &TreeEntry, reader: Reader, stats: &mut ReadStats) -> Result<Readable> {
    match e.kind {
        EntryKind::File => {
            if let Some((data, visibility)) = open_readable(store, &e.id, reader, stats)? {
                return Ok(Readable::Plain { id: e.id, data, visibility });
            }
            Ok(Readable::Redacted(hidden(store, e, reader)))
        }
        EntryKind::Conflict => {
            // The file with markers this reader is shown: versions it cannot
            // read are left out by the materialisation itself.
            let audience = match reader {
                Reader::Me => Audience::Reader,
                Reader::Public => Audience::Public,
            };
            match conflict::materialize_entry(store, e, audience) {
                Ok(m) => Ok(Readable::Plain { id: Object::blob_id(&m.content), data: m.content, visibility: m.visibility }),
                Err(err) if err.is_unreadable() || err.is_not_found() => Ok(Readable::Redacted(hidden(store, e, reader))),
                Err(err) => Err(err),
            }
        }
        _ => Ok(Readable::Redacted(Hidden { reason: HiddenReason::NotAFile, visibility: e.visibility.clone() })),
    }
}

/// The plaintext of object `id` and what it proves about its audience, if
/// `reader` may open it; `None` otherwise. A sealed object is opened only
/// after its label names a key this reader holds.
fn open_readable(store: &ObjectStore, id: &ObjectId, reader: Reader, stats: &mut ReadStats) -> Result<Option<(Vec<u8>, Visibility)>> {
    let raw = match store.get_raw(id) {
        Ok(r) => r,
        Err(err) if err.is_unreadable() || err.is_not_found() => return Ok(None),
        Err(err) => return Err(err),
    };
    if Object::is_blob_raw(&raw) {
        return match Object::decode(&raw)? {
            Object::Blob(b) => Ok(Some((b, Visibility::Public))),
            o => Err(VeilError::Corrupt(id.hex(), format!("expected blob, found {}", o.kind_name()))),
        };
    }
    let Some(label) = Object::sealed_scope(&raw) else {
        // Neither a blob nor a sealed object: not file content.
        return Ok(None);
    };
    drop(raw);
    // A public reader never opens a sealed (secret) file.
    let allowed = reader == Reader::Me && store.keys.has(&label);
    if !allowed {
        stats.sealed_skipped += 1;
        return Ok(None);
    }
    stats.sealed_opened += 1;
    match store.read_blob(id) {
        Ok(data) => {
            let vis = object_visibility(&store.get_raw(id)?).unwrap_or(Visibility::Cloaked { scope: label });
            Ok(Some((data, vis)))
        }
        Err(err) if err.is_unreadable() => {
            stats.open_failed += 1;
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn hidden(store: &ObjectStore, e: &TreeEntry, reader: Reader) -> Hidden {
    let raw = store.get_raw(&e.id).ok();
    let visibility = raw.as_deref().and_then(object_visibility).unwrap_or_else(|| e.visibility.clone());
    let label_held = raw.as_deref().and_then(Object::sealed_scope).is_some_and(|l| store.keys.has(&l));
    let reason = match (&raw, &visibility) {
        (None, Visibility::Public) => HiddenReason::Missing,
        (None, _) => HiddenReason::Withheld,
        (Some(_), _) if reader == Reader::Public && label_held => HiddenReason::PublicView,
        (Some(_), _) => HiddenReason::NoKey,
    };
    Hidden { reason, visibility }
}

// ---- line mapping ------------------------------------------------------------------

/// Byte ranges of the lines of `data`, as diffy splits them (each with its
/// `\n`; a last line without one is a line too).
pub fn line_ranges(data: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::with_capacity(data.len() / 32 + 1);
    let mut start = 0;
    let mut i = 0;
    let len = data.len();
    while i + 8 <= len {
        let chunk = u64::from_le_bytes(data[i..i + 8].try_into().unwrap());
        let x = chunk ^ 0x0a0a_0a0a_0a0a_0a0au64;
        let mut mask = x.wrapping_sub(0x0101_0101_0101_0101u64) & !x & 0x8080_8080_8080_8080u64;
        while mask != 0 {
            let byte_pos = i + (mask.trailing_zeros() as usize >> 3);
            out.push((start, byte_pos + 1));
            start = byte_pos + 1;
            mask &= mask - 1;
        }
        i += 8;
    }
    while i < len {
        if data[i] == b'\n' {
            out.push((start, i + 1));
            start = i + 1;
        }
        i += 1;
    }
    if start < len {
        out.push((start, len));
    }
    out
}

/// Checks that `data` contains no NUL byte (`0x00`) and is valid UTF-8, and
/// returns its [`line_ranges`], in a single 64-bit word pass when `data` is
/// pure non-NUL ASCII (falling back to `std::str::from_utf8` only when a high
/// bit is present).
pub fn plain_text_line_ranges(data: &[u8]) -> Option<Vec<(usize, usize)>> {
    let mut out = Vec::with_capacity(data.len() / 32 + 1);
    let mut start = 0;
    let mut i = 0;
    let len = data.len();
    let mut non_ascii = false;
    while i + 8 <= len {
        let chunk = u64::from_le_bytes(data[i..i + 8].try_into().unwrap());
        let nul = chunk.wrapping_sub(0x0101_0101_0101_0101u64) & !chunk & 0x8080_8080_8080_8080u64;
        if nul != 0 {
            return None;
        }
        if (chunk & 0x8080_8080_8080_8080u64) != 0 {
            non_ascii = true;
        }
        let x = chunk ^ 0x0a0a_0a0a_0a0a_0a0au64;
        let mut mask = x.wrapping_sub(0x0101_0101_0101_0101u64) & !x & 0x8080_8080_8080_8080u64;
        while mask != 0 {
            let byte_pos = i + (mask.trailing_zeros() as usize >> 3);
            out.push((start, byte_pos + 1));
            start = byte_pos + 1;
            mask &= mask - 1;
        }
        i += 8;
    }
    while i < len {
        let b = data[i];
        if b == 0 {
            return None;
        }
        if b >= 0x80 {
            non_ascii = true;
        }
        if b == b'\n' {
            out.push((start, i + 1));
            start = i + 1;
        }
        i += 1;
    }
    if non_ascii && std::str::from_utf8(data).is_err() {
        return None;
    }
    if start < len {
        out.push((start, len));
    }
    Some(out)
}

/// Binary search `lines` for the first index `i` where `lines[i].1 > target_end`
/// (equivalent to `lines.partition_point(|&(_, b)| b <= target_end)` without closure call overhead).
#[inline(always)]
fn bsearch_end_le(lines: &[(usize, usize)], target_end: usize) -> usize {
    let mut lo = 0usize;
    let mut hi = lines.len();
    while lo < hi {
        let mid = lo + ((hi - lo) >> 1);
        if lines[mid].1 <= target_end {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// Binary search `lines` for the first index `i` where `lines[i].0 >= target_start`
/// (equivalent to `lines.partition_point(|&(a, _)| a < target_start)` without closure call overhead).
#[inline(always)]
fn bsearch_start_lt(lines: &[(usize, usize)], target_start: usize) -> usize {
    let mut lo = 0usize;
    let mut hi = lines.len();
    while lo < hi {
        let mid = lo + ((hi - lo) >> 1);
        if lines[mid].0 < target_start {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// Like [`plain_text_line_ranges`], but when `data` shares long unchanged spans
/// with an already-validated plain-text `parent`, reuses `parent_lines` for
/// the unchanged spans via `extend_from_slice` and scans only the differing
/// lines for NUL, UTF-8, and line boundaries.
pub fn plain_text_line_ranges_from_parent(
    data: &[u8],
    parent: &[u8],
    parent_lines: &[(usize, usize)],
) -> Option<Vec<(usize, usize)>> {
    if data.len() < 4096 || parent_lines.len() < 64 {
        return plain_text_line_ranges(data);
    }
    let eq_pre = common_prefix_len(parent, data);
    let mut p_lines = bsearch_end_le(parent_lines, eq_pre);
    if p_lines > 0 {
        let (_, b) = parent_lines[p_lines - 1];
        if parent[b - 1] != b'\n' {
            p_lines -= 1;
        }
    }
    let pre_byte = if p_lines > 0 { parent_lines[p_lines - 1].1 } else { 0 };
    let eq_suf = common_suffix_len(&parent[pre_byte..], &data[pre_byte..]);
    let parent_suf_start = parent.len() - eq_suf;
    let mut s_idx = p_lines + bsearch_start_lt(&parent_lines[p_lines..], parent_suf_start);
    while s_idx < parent_lines.len() {
        // Where that line of the shared end starts in `data`: a line of
        // `data` only at its start or after a newline (BUG-1893: taken for
        // one at the start of `parent`, whatever `data` had before it; and
        // the byte before the start of `data` was read).
        let at = data.len() - (parent.len() - parent_lines[s_idx].0);
        if at == 0 || data[at - 1] == b'\n' {
            break;
        }
        s_idx += 1;
    }
    let s_lines = parent_lines.len() - s_idx;
    let suf_len_bytes = if s_lines > 0 {
        parent.len() - parent_lines[s_idx].0
    } else {
        0
    };
    let mid_end = data.len() - suf_len_bytes;
    let parent_mid_end = parent.len() - suf_len_bytes;
    // Only lines in `parent_lines[..safe_end]` that end with `\n` can be copied piecewise.
    let mut safe_end = s_idx;
    if safe_end > 0 && parent[parent_lines[safe_end - 1].1 - 1] != b'\n' {
        safe_end -= 1;
    }
    let mut out = Vec::with_capacity(parent_lines.len() + 8);
    out.extend_from_slice(&parent_lines[..p_lines]);
    let mut cur_byte = pre_byte;
    let mut cur_p = p_lines;
    while cur_byte < mid_end {
        if cur_p < safe_end {
            let (pa, _) = parent_lines[cur_p];
            let eq = common_prefix_len(&parent[pa..parent_mid_end], &data[cur_byte..mid_end]);
            if eq > 0 {
                let k = bsearch_end_le(&parent_lines[cur_p..safe_end], pa + eq);
                if k > 0 {
                    let matched_bytes = parent_lines[cur_p + k - 1].1 - pa;
                    let delta = cur_byte as isize - pa as isize;
                    if delta == 0 {
                        out.extend_from_slice(&parent_lines[cur_p..cur_p + k]);
                    } else {
                        let base_out = out.len();
                        out.extend_from_slice(&parent_lines[cur_p..cur_p + k]);
                        for (a, b) in &mut out[base_out..] {
                            *a = (*a as isize + delta) as usize;
                            *b = (*b as isize + delta) as usize;
                        }
                    }
                    cur_byte += matched_bytes;
                    cur_p += k;
                    continue;
                }
            }
        }
        let line_end = match memchr::memchr(b'\n', &data[cur_byte..mid_end]) {
            Some(pos) => cur_byte + pos + 1,
            None => mid_end,
        };
        let line_slice = &data[cur_byte..line_end];
        if memchr::memchr(0, line_slice).is_some() || std::str::from_utf8(line_slice).is_err() {
            return None;
        }
        out.push((cur_byte, line_end));
        cur_byte = line_end;
        if cur_p < safe_end {
            cur_p += 1;
        }
    }
    if s_lines > 0 {
        let delta = data.len() as isize - parent.len() as isize;
        if delta == 0 {
            out.extend_from_slice(&parent_lines[s_idx..]);
        } else {
            let cur_len = out.len();
            out.extend_from_slice(&parent_lines[s_idx..]);
            for (a, b) in &mut out[cur_len..] {
                *a = (*a as isize + delta) as usize;
                *b = (*b as isize + delta) as usize;
            }
        }
    }
    Some(out)
}

/// Where each line of `new` comes from in `old` (`None`: not there), and
/// whether the diff was past its work limit (then only the lines both
/// share at the start and at the end are mapped). The server's blame
/// (`veil-server`, `derive::blame`) maps lines with it too, so both
/// attribute a line alike.
///
/// The lines both texts share at the start and at the end are mapped
/// before the diff, which then sees only the rest (most edits change a few
/// lines of a long file). The answer is the diff's of the whole texts: the
/// trimmed start and end stop at a line that occurs nowhere in the rest,
/// so the diff's compaction, which slides an edit only past lines equal to
/// its own, could not have moved an edit into them (`trimming_keeps_the_diff`).
pub fn map_lines(old: &[u8], new: &[u8], new_lines: usize) -> (Vec<Option<u32>>, bool) {
    let mut map: Vec<Option<u32>> = vec![None; new_lines];
    let a: Vec<&[u8]> = old.split_inclusive(|b| *b == b'\n').collect();
    let b: Vec<&[u8]> = new.split_inclusive(|b| *b == b'\n').collect();
    if b.len() != new_lines {
        let coarse = !textmerge::fits(old, new);
        return if coarse { (ends_map(&a, &b, new_lines), true) } else { (diff_map(old, new, new_lines), false) };
    }
    let p0 = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let s0 = a[p0..].iter().rev().zip(b[p0..].iter().rev()).take_while(|(x, y)| x == y).count();
    let bytes = |l: &[&[u8]]| l.iter().map(|x| x.len()).sum::<usize>();
    let middle = |p: usize, s: usize| {
        let (oa, ob) = (bytes(&a[..p]), old.len() - bytes(&a[a.len() - s..]));
        let (na, nb) = (bytes(&b[..p]), new.len() - bytes(&b[b.len() - s..]));
        (&old[oa..ob], &new[na..nb])
    };
    let (om, nm) = middle(p0, s0);
    if !textmerge::fits_middle(om, nm, a.len() + b.len()) {
        return (ends_map(&a, &b, new_lines), true);
    }
    let (p, s) = trimmed(&a, &b, p0, s0);
    let (om, nm) = middle(p, s);
    let mid = diff_map(om, nm, b.len() - p - s);
    for (i, m) in map.iter_mut().enumerate().take(p) {
        *m = Some(i as u32);
    }
    for (i, m) in mid.into_iter().enumerate() {
        map[p + i] = m.map(|j| j + p as u32);
    }
    for k in 0..s {
        map[b.len() - 1 - k] = Some((a.len() - 1 - k) as u32);
    }
    (map, false)
}

/// Length of the longest common byte prefix of `a` and `b`, using `==` on
/// slices (`memcmp`) so even unoptimized builds scan at C speed.
fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    let min_len = a.len().min(b.len());
    let mut lo = 0usize;
    let mut step = 64usize;
    while lo + step <= min_len && a[lo..lo + step] == b[lo..lo + step] {
        lo += step;
        step *= 2;
    }
    let mut hi = (lo + step).min(min_len);
    while hi - lo > 16 {
        let mid = lo + (hi - lo) / 2;
        if a[lo..mid] == b[lo..mid] {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    while lo < hi && a[lo] == b[lo] {
        lo += 1;
    }
    lo
}

/// Length of the longest common byte suffix of `a` and `b`, using `==` on
/// slices (`memcmp`).
fn common_suffix_len(a: &[u8], b: &[u8]) -> usize {
    let min_len = a.len().min(b.len());
    let mut lo = 0usize;
    let mut step = 64usize;
    while lo + step <= min_len && a[a.len() - (lo + step)..a.len() - lo] == b[b.len() - (lo + step)..b.len() - lo] {
        lo += step;
        step *= 2;
    }
    let mut hi = (lo + step).min(min_len);
    while hi - lo > 16 {
        let mid = lo + (hi - lo) / 2;
        if a[a.len() - mid..a.len() - lo] == b[b.len() - mid..b.len() - lo] {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    while lo < hi && a[a.len() - 1 - lo] == b[b.len() - 1 - lo] {
        lo += 1;
    }
    lo
}

/// The lines at which `old` and `new` differ, if [`map_lines`] maps every
/// other line of `new` to the line of `old` at its own place and these to
/// nothing: both texts have as many lines, they differ at 1 to 8 of them,
/// and the diff of the whole texts could not have paired or moved a line
/// otherwise. `None` if that is not known (then [`map_lines_trimmed`]
/// answers).
///
/// The diff is of the lines from the first to the last that differ: the
/// lines before and after them are mapped in place if the one at each edge
/// occurs nowhere between (`trimmed`). Between, the lines that differ are
/// none of the other text's lines, so only the unchanged ones can pair, all
/// of them in one way, and no edit has a line equal to its own to slide
/// past (BUG-1893: lines that differ were compared only with each other
/// and their neighbours, so a changed line equal to an unchanged one
/// further on could pair with it in the diff, and not here).
pub fn isolated_replacements(old: &[u8], old_lines: &[(usize, usize)], new: &[u8], new_lines: &[(usize, usize)]) -> Option<Vec<usize>> {
    let n = new_lines.len();
    let m = old_lines.len();
    if m != n || n == 0 {
        return None;
    }
    let mut diffs = Vec::with_capacity(8);
    let mut cur = 0;
    while cur < n {
        let (oa, ob) = old_lines[cur];
        let (na, nb) = new_lines[cur];
        if ob - oa == nb - na && old[oa..ob] == new[na..nb] {
            let eq = common_prefix_len(&old[oa..], &new[na..]);
            let target_byte = oa + eq;
            let mut jump = bsearch_end_le(&old_lines[cur..], target_byte).max(1);
            // Lines within the shared bytes are shared, but for `old`'s last
            // line if it has no newline: `new`'s may go on (BUG-1893).
            if jump > 1 {
                let ((oa, ob), (na, nb)) = (old_lines[cur + jump - 1], new_lines[cur + jump - 1]);
                if ob - oa != nb - na {
                    jump -= 1;
                }
            }
            cur += jump;
        } else {
            if diffs.len() >= 8 {
                return None;
            }
            diffs.push(cur);
            cur += 1;
        }
    }
    if diffs.is_empty() {
        return Some(diffs);
    }
    let old_line = |i: usize| &old[old_lines[i].0..old_lines[i].1];
    let new_line = |i: usize| &new[new_lines[i].0..new_lines[i].1];
    let (first, last) = (diffs[0], diffs[diffs.len() - 1]);
    // The lines that differ, of both texts: none of `old`'s is one of `new`'s.
    let mut apart: Vec<&[u8]> = Vec::with_capacity(2 * diffs.len() + 2);
    for &d in &diffs {
        let ol = old_line(d);
        if diffs.iter().any(|&d2| ol == new_line(d2)) {
            return None;
        }
        apart.push(ol);
        apart.push(new_line(d));
    }
    // The line before the first and the one after the last are none of them,
    for edge in [first.checked_sub(1), (last + 1 < n).then_some(last + 1)].into_iter().flatten() {
        let el = old_line(edge);
        if apart[..2 * diffs.len()].contains(&el) {
            return None;
        }
        apart.push(el);
    }
    // and no unchanged line between is any of those (few end as one does).
    let end = |l: &[u8]| l.last_chunk::<8>().map(|c| u64::from_le_bytes(*c));
    let ends: Vec<Option<u64>> = apart.iter().map(|l| end(l)).collect();
    let mut next = 1;
    for i in first + 1..last {
        if i == diffs[next] {
            next += 1;
        } else if ends.contains(&end(old_line(i))) && apart.contains(&old_line(i)) {
            return None;
        }
    }
    Some(diffs)
}

/// [`map_lines`] returning `(prefix_len, mid_map, suffix_len, coarse)` without
/// allocating an `n`-element vector for the unchanged prefix and suffix.
pub fn map_lines_trimmed(old: &[u8], old_lines: &[(usize, usize)], new: &[u8], new_lines: &[(usize, usize)]) -> (usize, Vec<Option<u32>>, usize, bool) {
    let n = new_lines.len();
    let m = old_lines.len();
    if n == 0 || m == 0 {
        return (0, vec![None; n], 0, false);
    }
    let min_len = m.min(n);
    // Find first differing byte between `old` and `new`, then binary search `old_lines` for the line containing it.
    let eq_prefix_bytes = common_prefix_len(old, new);
    let mut p0 = old_lines[..min_len].partition_point(|&(_, b)| b <= eq_prefix_bytes);
    // The lines of `old` that end within the shared bytes are `new`'s too,
    // but for `old`'s last line if it has no newline: every byte of it starts
    // a line of `new` that may go on, with its newline or more (BUG-1893).
    if p0 > 0 && new_lines[p0 - 1].1 != old_lines[p0 - 1].1 {
        p0 -= 1;
    }
    while p0 < min_len {
        let (oa, ob) = old_lines[p0];
        let (na, nb) = new_lines[p0];
        if ob - oa != nb - na || old[oa..ob] != new[na..nb] {
            break;
        }
        p0 += 1;
    }
    let prefix_end_byte = old_lines.get(p0).map_or(old.len(), |r| r.0);
    let new_prefix_end_byte = new_lines.get(p0).map_or(new.len(), |r| r.0);
    let eq_suffix_bytes = common_suffix_len(&old[prefix_end_byte..], &new[new_prefix_end_byte..]);
    let old_suf_start = old.len() - eq_suffix_bytes;
    let new_suf_start = new.len() - eq_suffix_bytes;
    let s_guess = if eq_suffix_bytes == 0 {
        0
    } else {
        let idx = old_lines[p0..].partition_point(|&(a, _)| a < old_suf_start);
        m - (p0 + idx)
    };
    let mut s0 = s_guess.min(min_len - p0);
    // Verify the boundary line of `s0` in case `eq_suffix_bytes` started mid-line.
    while s0 > 0 {
        let (oa, _) = old_lines[m - s0];
        let (na, _) = new_lines[n - s0];
        if oa < old_suf_start || na < new_suf_start {
            s0 -= 1;
        } else {
            break;
        }
    }
    while s0 < min_len - p0 {
        let (oa, ob) = old_lines[m - 1 - s0];
        let (na, nb) = new_lines[n - 1 - s0];
        if ob - oa != nb - na || old[oa..ob] != new[na..nb] {
            break;
        }
        s0 += 1;
    }
    let middle = |p: usize, s: usize| {
        let oa = old_lines.get(p).map_or(old.len(), |r| r.0);
        let ob = if s == 0 { old.len() } else { old_lines[m - s].0 };
        let na = new_lines.get(p).map_or(new.len(), |r| r.0);
        let nb = if s == 0 { new.len() } else { new_lines[n - s].0 };
        (&old[oa.min(ob)..ob], &new[na.min(nb)..nb])
    };
    let (om, nm) = middle(p0, s0);
    if !textmerge::fits_middle(om, nm, m + n) {
        return (p0, vec![None; n - p0 - s0], s0, true);
    }
    let (mut p, mut s) = (p0, s0);
    loop {
        let mut moved = false;
        if p > 0 {
            let (ea, eb) = old_lines[p - 1];
            let edge = &old[ea..eb];
            let elen = edge.len();
            let in_old = p < m - s
                && memchr::memmem::find(&old[old_lines[p].0..old_lines[m - s - 1].1], edge).is_some()
                && old_lines[p..m - s].iter().any(|&(a, b)| b - a == elen && &old[a..b] == edge);
            let in_new = !in_old
                && p < n - s
                && memchr::memmem::find(&new[new_lines[p].0..new_lines[n - s - 1].1], edge).is_some()
                && new_lines[p..n - s].iter().any(|&(a, b)| b - a == elen && &new[a..b] == edge);
            if in_old || in_new {
                p -= 1;
                moved = true;
            }
        }
        if s > 0 {
            let (ea, eb) = old_lines[m - s];
            let edge = &old[ea..eb];
            let elen = edge.len();
            let in_old = p < m - s
                && memchr::memmem::find(&old[old_lines[p].0..old_lines[m - s - 1].1], edge).is_some()
                && old_lines[p..m - s].iter().any(|&(a, b)| b - a == elen && &old[a..b] == edge);
            let in_new = !in_old
                && p < n - s
                && memchr::memmem::find(&new[new_lines[p].0..new_lines[n - s - 1].1], edge).is_some()
                && new_lines[p..n - s].iter().any(|&(a, b)| b - a == elen && &new[a..b] == edge);
            if in_old || in_new {
                s -= 1;
                moved = true;
            }
        }
        if !moved {
            break;
        }
    }
    let (om, nm) = middle(p, s);
    let mut mid = diff_map(om, nm, n - p - s);
    for j in mid.iter_mut().flatten() {
        *j += p as u32;
    }
    (p, mid, s, false)
}

/// [`map_lines`] when both texts' line ranges (`old_lines`, `new_lines`) are
/// already known.
pub fn map_lines_ranged(old: &[u8], old_lines: &[(usize, usize)], new: &[u8], new_lines: &[(usize, usize)]) -> (Vec<Option<u32>>, bool) {
    let n = new_lines.len();
    let m = old_lines.len();
    let (p, mid, s, coarse) = map_lines_trimmed(old, old_lines, new, new_lines);
    let mut map: Vec<Option<u32>> = vec![None; n];
    for (i, slot) in map.iter_mut().enumerate().take(p) {
        *slot = Some(i as u32);
    }
    for (i, v) in mid.into_iter().enumerate() {
        map[p + i] = v;
    }
    for k in 0..s {
        map[n - 1 - k] = Some((m - 1 - k) as u32);
    }
    (map, coarse)
}

/// Past the diff's work limit: only the lines both texts share at the
/// start and at the end are mapped.
fn ends_map(a: &[&[u8]], b: &[&[u8]], new_lines: usize) -> Vec<Option<u32>> {
    let mut map: Vec<Option<u32>> = vec![None; new_lines];
    let p = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let s = a[p..].iter().rev().zip(b[p..].iter().rev()).take_while(|(x, y)| x == y).count();
    for (i, m) in map.iter_mut().enumerate().take(p.min(new_lines)) {
        *m = Some(i as u32);
    }
    for k in 0..s {
        if let Some(m) = map.get_mut(b.len() - 1 - k) {
            *m = Some((a.len() - 1 - k) as u32);
        }
    }
    map
}

/// Of the lines `a` and `b` share at the start (`p`) and, of the rest, at
/// the end (`s`), how many to map before the diff: each cut back until the line at its edge occurs nowhere in the
/// lines between: no edit of the diff can slide past it.
fn trimmed(a: &[&[u8]], b: &[&[u8]], p: usize, s: usize) -> (usize, usize) {
    let (mut p, mut s) = (p, s);
    let mut rest: std::collections::HashSet<&[u8]> = a[p..a.len() - s].iter().chain(&b[p..b.len() - s]).copied().collect();
    loop {
        let mut moved = false;
        if p > 0 && rest.contains(a[p - 1]) {
            p -= 1;
            rest.insert(a[p]);
            moved = true;
        }
        if s > 0 && rest.contains(a[a.len() - s]) {
            rest.insert(a[a.len() - s]);
            s -= 1;
            moved = true;
        }
        if !moved {
            return (p, s);
        }
    }
}

/// [`map_lines`] by the diff of the whole texts (within its work limit).
fn diff_map(old: &[u8], new: &[u8], new_lines: usize) -> Vec<Option<u32>> {
    let mut map: Vec<Option<u32>> = vec![None; new_lines];
    let patch = diffy::DiffOptions::new().set_context_len(0).create_patch_bytes(old, new);
    // Lines outside hunks are equal, in order.
    let (mut oi, mut ni) = (0usize, 0usize);
    for h in patch.hunks() {
        let ostart = if !h.old_range().is_empty() { h.old_range().start() - 1 } else { h.old_range().start() };
        let nstart = if !h.new_range().is_empty() { h.new_range().start() - 1 } else { h.new_range().start() };
        while ni < nstart && ni < new_lines {
            map[ni] = Some(oi as u32);
            ni += 1;
            oi += 1;
        }
        oi = ostart;
        for l in h.lines() {
            match l {
                diffy::Line::Context(_) => {
                    if ni < new_lines {
                        map[ni] = Some(oi as u32);
                    }
                    ni += 1;
                    oi += 1;
                }
                diffy::Line::Delete(_) => oi += 1,
                diffy::Line::Insert(_) => ni += 1,
            }
        }
    }
    while ni < new_lines {
        map[ni] = Some(oi as u32);
        ni += 1;
        oi += 1;
    }
    map
}


/// What one [`map_lines`] cost, in the work units of
/// [`BlameOptions::work_budget`]: the lines read, plus the diff's search
/// (past its limit the whole limit was spent measuring; within it, about
/// `D²` for `D` differing lines).
pub fn map_cost(old_lines: usize, map: &[Option<u32>], coarse: bool) -> u64 {
    let lines = (old_lines + map.len()) as u64;
    let search = if coarse {
        textmerge::work_limit(lines as usize)
    } else {
        let kept = map.iter().filter(|m| m.is_some()).count() as u64;
        let d = lines.saturating_sub(2 * kept);
        d.saturating_mul(d)
    };
    lines.saturating_add(search)
}

// ---- blame -------------------------------------------------------------------------

/// Default for [`BlameOptions::max_changes`].
pub const DEFAULT_MAX_CHANGES: usize = 100_000;
/// Default for [`BlameOptions::work_budget`]: about 2 s of the worst case
/// (every step a diff past its work limit) in a release build, and some
/// ten thousand steps of ordinary edits to a 20 000-line file. (Threat
/// review 4 asks for lines × snapshots ≤ 2³²; this is tighter, because
/// it also counts the diffs.)
pub const DEFAULT_WORK_BUDGET: u64 = 1 << 29;

#[derive(Clone, Debug)]
pub struct BlameOptions {
    pub reader: Reader,
    /// Follow the file across renames ([`rename::detect`] where the path
    /// first appears).
    pub follow: bool,
    /// Visits of a snapshot allowed before the walk stops.
    pub max_changes: usize,
    /// Work allowed: lines read and compared, plus the worst-case cost of
    /// each line diff ([`textmerge::work_limit`]).
    pub work_budget: u64,
    /// Only these lines (1-based, inclusive) of the file are attributed.
    pub lines: Option<(usize, usize)>,
    /// Rename detection for `follow`.
    pub renames: RenameOptions,
    /// Restrict tree reads and rename detection to this sparse set (for a
    /// `--only` sandbox's workspace socket).
    pub within: Option<crate::vfs::SparseSet>,
}

impl Default for BlameOptions {
    fn default() -> Self {
        BlameOptions {
            reader: Reader::Me,
            follow: false,
            max_changes: DEFAULT_MAX_CHANGES,
            work_budget: DEFAULT_WORK_BUDGET,
            lines: None,
            renames: RenameOptions::default(),
            within: None,
        }
    }
}

/// Why a line has no change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unattributed {
    /// The version it would move to cannot be read by this reader.
    Sealed(Visibility),
    /// [`BlameOptions::max_changes`] was reached.
    MaxChanges,
    /// [`BlameOptions::work_budget`] was spent.
    Budget,
}

impl Unattributed {
    pub fn as_str(&self) -> &'static str {
        match self {
            Unattributed::Sealed(_) => "sealed",
            Unattributed::MaxChanges => "max_changes",
            Unattributed::Budget => "budget",
        }
    }
}

/// Where a line comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The snapshot that introduced the line, and the file's path there.
    Snapshot { id: ObjectId, path: VPath },
    Unattributed(Unattributed),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlameLine {
    /// 1-based, in the file at the starting snapshot.
    pub number: usize,
    /// The line, with its line break.
    pub text: Vec<u8>,
    pub origin: Origin,
}

/// Why the walk stopped before every line was attributed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    MaxChanges,
    Budget,
}

#[derive(Clone, Debug)]
pub struct Blame {
    pub path: VPath,
    pub rev: ObjectId,
    pub lines: Vec<BlameLine>,
    /// Some diff was past its work limit: a differing middle was attributed
    /// whole.
    pub coarse: bool,
    pub stopped: Option<Stop>,
    /// Snapshot visits.
    pub visited: usize,
    pub stats: ReadStats,
}

impl Blame {
    pub fn unattributed(&self) -> usize {
        self.lines.iter().filter(|l| matches!(l.origin, Origin::Unattributed(_))).count()
    }
}

/// A file version being walked.
struct Version {
    id: ObjectId,
    data: Vec<u8>,
    lines: Vec<(usize, usize)>,
}

impl Version {
    fn new(id: ObjectId, data: Vec<u8>) -> Arc<Version> {
        let lines = line_ranges(&data);
        Arc::new(Version { id, data, lines })
    }
}

/// Open lines waiting at a snapshot: (line of the result, line of this
/// version).
struct Pending {
    lines: Vec<(u32, u32)>,
    version: Arc<Version>,
}

/// A snapshot (and the file's name there) waiting to be visited; the
/// heap pops the lowest topological rank (children first) first.
#[derive(PartialEq, Eq)]
struct Queued {
    rank: usize,
    id: ObjectId,
    path: VPath,
}

impl Ord for Queued {
    fn cmp(&self, o: &Self) -> Ordering {
        o.rank.cmp(&self.rank).then_with(|| o.path.as_str().cmp(self.path.as_str()))
    }
}

impl PartialOrd for Queued {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

/// Topological ranks (children first, as [`crate::repo::Held::topo_children_first`]
/// numbers them), produced only as far as they are asked for.
struct LazyRank<'r> {
    iter: crate::graph_index::TopoIter<'r>,
    ranks: HashMap<ObjectId, usize>,
}

impl LazyRank<'_> {
    fn of(&mut self, id: &ObjectId) -> Result<Option<usize>> {
        while !self.ranks.contains_key(id) {
            match self.iter.next() {
                Some(next) => {
                    let n = self.ranks.len();
                    self.ranks.insert(next?, n);
                }
                None => break,
            }
        }
        Ok(self.ranks.get(id).copied())
    }
}

/// The version of the file at `path` in `tree` this reader reads, `None`
/// when there is no file there; `Err(Hidden)` when it is redacted.
fn version_at(store: &ObjectStore, tree: &ObjectId, path: &VPath, reader: Reader, stats: &mut ReadStats) -> Result<Option<std::result::Result<Arc<Version>, Hidden>>> {
    let e = match lookup_to_read(store, tree, path) {
        Ok(Some(e)) if e.kind != EntryKind::Dir => e,
        Ok(_) => return Ok(None),
        // A directory on the way this reader cannot open.
        Err(err) if err.is_unreadable() => {
            return Ok(Some(Err(Hidden { reason: HiddenReason::NoKey, visibility: Visibility::Public })))
        }
        Err(err) => return Err(err),
    };
    Ok(Some(match readable_version_counted(store, &e, reader, stats)? {
        Readable::Plain { id, data, .. } => Ok(Version::new(id, data)),
        Readable::Redacted(h) => Err(h),
    }))
}

/// Attribute each line of the file `path` at snapshot `rev`.
pub fn blame(repo: &Repo, rev: &ObjectId, path: &VPath, o: &BlameOptions) -> Result<Blame> {
    // A public mirror lacks what an unreleased embargo withholds (BUG-991):
    // no push sends it before the release. A revision it has holds none of
    // it in its history, so only the revision itself is checked.
    if o.reader == Reader::Public && crate::remote::embargo_blocks(repo, &[*rev])?[0].is_some() {
        return Err(VeilError::Policy(format!(
            "{} is not public: an unreleased embargo withholds it, and a public mirror does not have it before the release",
            rev.short()
        )));
    }
    let store = repo.store();
    let restrict = |tree: ObjectId| -> Result<ObjectId> {
        match &o.within {
            Some(set) => crate::vfs::restrict(store, &tree, set),
            None => Ok(tree),
        }
    };
    let mut stats = ReadStats::default();
    let top = repo.snapshot(rev)?;
    let top_tree = restrict(top.tree)?;
    let entry = match lookup_to_read(store, &top_tree, path)? {
        Some(e) if e.kind.is_file_like() => e,
        Some(_) => return Err(VeilError::NotFound(format!("{path} is a directory in {}", rev.short()))),
        None => return Err(VeilError::NotFound(format!("{path} does not exist in {}", rev.short()))),
    };
    let version = match readable_version_counted(store, &entry, o.reader, &mut stats)? {
        Readable::Plain { id, data, .. } => Version::new(id, data),
        Readable::Redacted(h) => return Err(VeilError::Redacted { scope: h.visibility.label() }),
    };
    let total = version.lines.len();
    let (from, to) = match o.lines {
        Some((a, b)) => (a.max(1).min(total + 1) - 1, b.min(total)),
        None => (0, total),
    };
    let mut origins: Vec<Option<Origin>> = vec![None; total];
    let mut result = Blame { path: path.clone(), rev: *rev, lines: Vec::new(), coarse: false, stopped: None, visited: 0, stats };
    let mut heap: BinaryHeap<Queued> = BinaryHeap::new();
    let mut pending: HashMap<(ObjectId, VPath), Pending> = HashMap::new();
    let open: Vec<(u32, u32)> = (from..to.max(from)).map(|i| (i as u32, i as u32)).collect();
    // Children before parents: every line a snapshot will receive has
    // arrived by the time it is popped.
    // Ranks come lazily, as far down as the walk goes (the history index).
    let mut rank = LazyRank { iter: repo.held().topo_iter([*rev]), ranks: HashMap::new() };
    if !open.is_empty() {
        pending.insert((*rev, path.clone()), Pending { lines: open, version: version.clone() });
        heap.push(Queued { rank: 0, id: *rev, path: path.clone() });
    }
    let mut work: u64 = 0;
    let budget = o.work_budget;
    'walk: while let Some(q) = heap.pop() {
        let Some(pend) = pending.remove(&(q.id, q.path.clone())) else { continue };
        if result.visited >= o.max_changes {
            result.stopped = Some(Stop::MaxChanges);
            pending.insert((q.id, q.path.clone()), pend);
            break;
        }
        result.visited += 1;
        work = work.saturating_add(pend.lines.len() as u64);
        let snap = repo.snapshot(&q.id)?;
        let cur = pend.version;
        let mut open = pend.lines;
        for parent in &snap.parents {
            if open.is_empty() {
                break;
            }
            // A parent withheld here (an unreleased embargo on a public
            // clone) is not part of this replica's history.
            let Some(ps) = repo.exact().snapshot(parent)? else { continue };
            let Some(prank) = rank.of(parent)? else { continue };
            let ps_tree = restrict(ps.tree)?;
            let mut ppath = q.path.clone();
            let mut pv = match pending.get(&(*parent, ppath.clone())) {
                Some(p) => Some(Ok(p.version.clone())),
                None => version_at(store, &ps_tree, &ppath, o.reader, &mut result.stats)?,
            };
            if pv.is_none() && o.follow {
                // Where did the file come from? Renames in this step only.
                let snap_tree = restrict(snap.tree)?;
                let (changes, _) = diff_trees_hiding(store, Some(&ps_tree), Some(&snap_tree))?;
                if changes.iter().any(|c| c.path == q.path && c.old.is_none()) {
                    let d = rename::detect(store, Some(&ps_tree), Some(&snap_tree), &changes, o.reader, &o.renames)?;
                    result.stats.add(&d.stats);
                    if let Some(pair) = d.pairs.iter().find(|p| p.to == q.path && !p.copy) {
                        ppath = pair.from.clone();
                        pv = match pending.get(&(*parent, ppath.clone())) {
                            Some(p) => Some(Ok(p.version.clone())),
                            None => version_at(store, &ps_tree, &ppath, o.reader, &mut result.stats)?,
                        };
                    }
                }
            }
            let pver = match pv {
                None => continue,
                Some(Err(h)) => {
                    // The parent may hold these lines; this reader cannot
                    // tell. Never guessed.
                    for (fin, _) in open.drain(..) {
                        origins[fin as usize] = Some(Origin::Unattributed(Unattributed::Sealed(h.visibility.clone())));
                    }
                    break;
                }
                Some(Ok(v)) => v,
            };
            let passed: Vec<(u32, u32)> = if pver.id == cur.id || pver.data == cur.data {
                std::mem::take(&mut open)
            } else {
                if work >= budget {
                    result.stopped = Some(Stop::Budget);
                    pending.insert((q.id, q.path.clone()), Pending { lines: open, version: cur });
                    break 'walk;
                }
                let (map, coarse) = map_lines(&pver.data, &cur.data, cur.lines.len());
                work = work.saturating_add(map_cost(pver.lines.len(), &map, coarse));
                result.coarse |= coarse;
                let mut passed = Vec::new();
                open.retain(|&(fin, local)| match map.get(local as usize).copied().flatten() {
                    Some(old) => {
                        passed.push((fin, old));
                        false
                    }
                    None => true,
                });
                passed
            };
            if passed.is_empty() {
                continue;
            }
            match pending.get_mut(&(*parent, ppath.clone())) {
                Some(p) => p.lines.extend(passed),
                None => {
                    pending.insert((*parent, ppath.clone()), Pending { lines: passed, version: pver });
                    heap.push(Queued { rank: prank, id: *parent, path: ppath });
                }
            }
        }
        for (fin, _) in open {
            origins[fin as usize] = Some(Origin::Snapshot { id: q.id, path: q.path.clone() });
        }
    }
    let why = match result.stopped {
        Some(Stop::Budget) => Unattributed::Budget,
        _ => Unattributed::MaxChanges,
    };
    for p in pending.into_values() {
        for (fin, _) in p.lines {
            origins[fin as usize].get_or_insert(Origin::Unattributed(why.clone()));
        }
    }
    for (i, origin) in origins.into_iter().enumerate().take(to).skip(from) {
        let (a, b) = version.lines[i];
        result.lines.push(BlameLine {
            number: i + 1,
            text: version.data[a..b].to_vec(),
            origin: origin.unwrap_or(Origin::Unattributed(why.clone())),
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapped(old: &str, new: &str) -> Vec<Option<u32>> {
        let n = line_ranges(new.as_bytes()).len();
        map_lines(old.as_bytes(), new.as_bytes(), n).0
    }

    #[test]
    fn lines_map_through_the_diff() {
        assert_eq!(mapped("a\nb\nc\n", "a\nb\nc\n"), vec![Some(0), Some(1), Some(2)]);
        assert_eq!(mapped("a\nb\nc\n", "a\nX\nc\n"), vec![Some(0), None, Some(2)]);
        assert_eq!(mapped("a\nb\nc\n", "z\na\nb\nc\n"), vec![None, Some(0), Some(1), Some(2)]);
        assert_eq!(mapped("a\nb\nc\n", "a\nc\n"), vec![Some(0), Some(2)]);
        assert_eq!(mapped("a\nb\n", "a\nb\nc"), vec![Some(0), Some(1), None]);
        assert_eq!(mapped("", "a\nb\n"), vec![None, None]);
        assert_eq!(mapped("a\nb\n", ""), Vec::<Option<u32>>::new());
        assert_eq!(mapped("a\nb", "a\nb\n"), vec![Some(0), None]);
        // Several hunks.
        assert_eq!(mapped("1\n2\n3\n4\n5\n6\n", "1\nX\n3\n4\nY\n6\nZ\n"), vec![Some(0), None, Some(2), Some(3), None, Some(5), None]);
    }

    /// Trimming the shared start and end gives exactly the diff of the
    /// whole texts, on texts of few distinct lines (where edits can slide).
    #[test]
    fn trimming_keeps_the_diff() {
        let mut seed = 0x2545f4914f6cdd1du64;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for case in 0..20_000 {
            let alphabet = 1 + rnd() % 4;
            let n = (rnd() % 40) as usize;
            let old: Vec<String> = (0..n).map(|_| format!("{}\n", rnd() % alphabet)).collect();
            let mut new = old.clone();
            for _ in 0..1 + rnd() % 3 {
                let at = (rnd() as usize) % (new.len() + 1);
                match rnd() % 3 {
                    0 => new.insert(at, format!("{}\n", rnd() % alphabet)),
                    1 if at < new.len() => {
                        new.remove(at);
                    }
                    _ if at < new.len() => new[at] = format!("{}\n", rnd() % (alphabet + 1)),
                    _ => {}
                }
            }
            let (mut o, mut nw) = (old.concat(), new.concat());
            if case % 7 == 0 {
                o.pop();
            }
            if case % 5 == 0 {
                nw.pop();
            }
            let lines = line_ranges(nw.as_bytes()).len();
            let whole = diff_map(o.as_bytes(), nw.as_bytes(), lines);
            assert!(textmerge::fits(o.as_bytes(), nw.as_bytes()));
            assert_eq!(map_lines(o.as_bytes(), nw.as_bytes(), lines), (whole, false), "{o:?} -> {nw:?}");
        }
    }

    /// Whether a diff is past its work limit is decided as on the whole
    /// texts (`textmerge::fits`), on both sides of the limit.
    #[test]
    fn coarse_decision_matches_the_whole_texts() {
        let (mut seen_coarse, mut seen_fine) = (false, false);
        for k in [10usize, 300, 2_000, 4_000, 8_000, 16_000] {
            let shared: String = (0..2_000).map(|i| format!("shared {i}\n")).collect();
            let old = format!("{shared}{}{shared}", (0..k).map(|i| format!("old {i}\n")).collect::<String>());
            let new = format!("{shared}{}{shared}", (0..k).map(|i| format!("new {i}\n")).collect::<String>());
            let lines = line_ranges(new.as_bytes()).len();
            let (map, coarse) = map_lines(old.as_bytes(), new.as_bytes(), lines);
            assert_eq!(coarse, !textmerge::fits(old.as_bytes(), new.as_bytes()), "{k}");
            assert_eq!(map.iter().filter(|m| m.is_some()).count(), 4_000, "{k}");
            seen_coarse |= coarse;
            seen_fine |= !coarse;
        }
        assert!(seen_coarse && seen_fine);
    }

    /// Every mapped line is equal to the line it maps to, and the mapping
    /// is increasing (a property of any diff), on random edits.
    #[test]
    fn mapping_is_a_monotone_matching_of_equal_lines() {
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..300 {
            let n = (rnd() % 30) as usize;
            let old: Vec<String> = (0..n).map(|_| format!("{}\n", rnd() % 6)).collect();
            let m = (rnd() % 30) as usize;
            let new: Vec<String> = (0..m).map(|_| format!("{}\n", rnd() % 6)).collect();
            let (o, nw) = (old.concat(), new.concat());
            let map = mapped(&o, &nw);
            assert_eq!(map.len(), m);
            let mut last: Option<u32> = None;
            for (i, x) in map.iter().enumerate() {
                if let Some(x) = x {
                    assert_eq!(old[*x as usize], new[i], "{o:?} → {nw:?}: {map:?}");
                    assert!(last.is_none_or(|l| *x > l), "{map:?}");
                    last = Some(*x);
                }
            }
        }
    }

    /// The maps the server's blame uses ([`map_lines_ranged`] over
    /// [`map_lines_trimmed`], and [`isolated_replacements`] where it
    /// answers) say what [`map_lines`] says of `old` and `new`. Returns the
    /// lines `isolated_replacements` answered with, if it did.
    fn ranged_maps_agree(old: &str, new: &str) -> Option<usize> {
        let (o, w) = (old.as_bytes(), new.as_bytes());
        let (ol, nl) = (line_ranges(o), line_ranges(w));
        let want = map_lines(o, w, nl.len());
        assert_eq!(map_lines_ranged(o, &ol, w, &nl), want, "map_lines_ranged, {old:?} -> {new:?}");
        let d = isolated_replacements(o, &ol, w, &nl)?;
        let map: Vec<Option<u32>> = (0..nl.len()).map(|i| (!d.contains(&i)).then_some(i as u32)).collect();
        assert_eq!((map, false), want, "isolated_replacements {d:?}, {old:?} -> {new:?}");
        Some(d.len())
    }

    /// BUG-1893: a last line without its newline is not the line that has
    /// one (or goes on), though every byte of it starts the new text. The
    /// server's maps took it for a shared line, so its blame gave such a
    /// line to the change before the one that ended or extended it, and a
    /// thin clone (answered by the server) disagreed with a full one.
    #[test]
    fn bug_1893_a_last_line_without_its_newline_is_not_the_line_with_one() {
        let ranged = |old: &str, new: &str| {
            let (o, w) = (old.as_bytes(), new.as_bytes());
            map_lines_ranged(o, &line_ranges(o), w, &line_ranges(w)).0
        };
        let isolated = |old: &str, new: &str| {
            let (o, w) = (old.as_bytes(), new.as_bytes());
            isolated_replacements(o, &line_ranges(o), w, &line_ranges(w))
        };
        // The test project's file: a newline, then a second line.
        assert_eq!(mapped("MARK", "MARK\nsecond line\n"), vec![None, None]);
        assert_eq!(ranged("MARK", "MARK\nsecond line\n"), vec![None, None]);
        assert_eq!(ranged("a\nb", "a\nb\nc\n"), vec![Some(0), None, None]);
        assert_eq!(ranged("a\nb", "a\nbc\nd\n"), vec![Some(0), None, None]);
        // As many lines after as before: only the newline added, or the
        // last line longer.
        assert_eq!(mapped("a\nb", "a\nb\n"), vec![Some(0), None]);
        assert_eq!(ranged("a\nb", "a\nb\n"), vec![Some(0), None]);
        assert_eq!(isolated("a\nb", "a\nb\n"), Some(vec![1]));
        assert_eq!(isolated("a\nb", "a\nbc"), Some(vec![1]));
        assert_eq!(isolated("a", "a\n"), Some(vec![0]));
        // The newline removed, and unchanged texts.
        assert_eq!(ranged("a\nb\n", "a\nb"), vec![Some(0), None]);
        assert_eq!(isolated("a\nb\n", "a\nb"), Some(vec![1]));
        assert_eq!(ranged("a\nb", "a\nb"), vec![Some(0), Some(1)]);
        assert_eq!(isolated("a\nb", "a\nb"), Some(vec![]));
        for (old, new) in [("MARK", "MARK\nsecond line\n"), ("a\nb", "a\nb\n"), ("a\nb", "a\nbc"), ("a\nb\n", "a\nb"), ("a", "a\n"), ("a", "ab"), ("x\na", "a")] {
            ranged_maps_agree(old, new);
        }
        // Texts of as many lines, few of them distinct, that differ at a
        // few: where `isolated_replacements` answers, with and without a
        // last newline. (A changed line equal to an unchanged one further
        // on, "x\ny\nb\n" -> "b\nz\nb\n", was the other way it disagreed.)
        ranged_maps_agree("x\ny\nb\n", "b\nz\nb\n");
        let mut seed = 0x1893_0b5e_55ed_c0deu64;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as usize
        };
        const LINES: [&str; 8] = ["a", "b", "c", "d", "e", "f", "g", "h"];
        let (mut one, mut several) = (0, 0);
        for case in 0..60_000u32 {
            let k = 2 + rnd() % 5;
            let old: Vec<&str> = (0..1 + rnd() % 14).map(|_| LINES[rnd() % k]).collect();
            let mut new = old.clone();
            for _ in 0..1 + rnd() % 4 {
                let at = rnd() % new.len();
                new[at] = LINES[rnd() % (k + 2)];
            }
            let (mut old, mut new) = (old.join("\n") + "\n", new.join("\n") + "\n");
            if case.is_multiple_of(5) {
                old.pop();
            }
            if case.is_multiple_of(3) {
                new.pop();
            }
            match ranged_maps_agree(&old, &new) {
                Some(1) => one += 1,
                Some(n) if n > 1 => several += 1,
                _ => {}
            }
        }
        assert!(one > 1_000 && several > 1_000, "isolated_replacements answered: {one} times with one line, {several} with several");
    }

    /// BUG-1893's class, for the lines themselves: line ranges reused from
    /// a parent version ([`plain_text_line_ranges_from_parent`], the
    /// server's blame jobs) are the text's own, whether or not either text
    /// ends with a newline, on long texts of repeated lines (it reuses
    /// nothing below 4,096 bytes or 64 lines).
    #[test]
    fn bug_1893_line_ranges_reused_from_a_parent_are_the_texts_own() {
        let mut seed = 0x1893_11e5_0f7e_47a1u64;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as usize
        };
        // A first line removed (the byte before the text's start was read:
        // a panic), and one with something put before it (taken for the
        // parent's first line, and what was put before it for a line).
        let rest = "a line of fifty bytes or thereabouts, to be long\n".repeat(100);
        let parent = format!("the first line\n{rest}");
        let own = |data: &str| assert_eq!(plain_text_line_ranges_from_parent(data.as_bytes(), parent.as_bytes(), &line_ranges(parent.as_bytes())), Some(line_ranges(data.as_bytes())), "{:?}…", &data[..30]);
        own(&rest);
        own(&format!("// {parent}"));
        own(&format!("first\n{parent}"));
        own(&format!("{parent}last"));
        own(parent.trim_end());
        let mut reused = 0;
        for case in 0..3_000u32 {
            let k = 2 + rnd() % 30;
            let line = |r: usize| format!("{}\n", "line of some length ".repeat(1 + r % k % 4) + &(r % k).to_string());
            let mut lines: Vec<String> = (0..64 + rnd() % 200).map(|_| line(rnd())).collect();
            let mut parent = lines.concat();
            if case.is_multiple_of(3) {
                parent.pop();
            }
            for _ in 0..rnd() % 4 {
                let at = rnd() % lines.len();
                match rnd() % 4 {
                    0 => lines.insert(at, line(rnd())),
                    1 => drop(lines.remove(at)),
                    2 => lines[at] = line(rnd()),
                    _ => {
                        let within = rnd() % lines[at].len();
                        lines[at].insert(within, 'x');
                    }
                }
            }
            let mut data = lines.concat();
            match case % 7 {
                0 => drop(data.pop()),
                1 => data.push_str("more"),
                2 => data.truncate(rnd() % (data.len() + 1)),
                3 => data = format!("{parent}\n"),
                4 => data = format!("{parent}{}", &line(rnd())[..3]),
                _ => {}
            }
            let got = plain_text_line_ranges_from_parent(data.as_bytes(), parent.as_bytes(), &line_ranges(parent.as_bytes()));
            assert_eq!(got, Some(line_ranges(data.as_bytes())), "case {case}");
            assert_eq!(got, plain_text_line_ranges(data.as_bytes()), "case {case}");
            reused += usize::from(data.len() >= 4096);
        }
        assert!(reused > 2_000, "{reused} texts long enough to reuse a parent's lines");
    }

    /// S14 cycle 2 (review): `map_lines` with its trimmed ends answers
    /// exactly what it answered before the trim (the diff of the whole
    /// texts within the work limit, the shared ends past it), on
    /// adversarially repetitive texts: few distinct lines, runs of the
    /// edge lines inside the middle, CRLF and bare CR, empty texts, a last
    /// line without its newline; and on texts straddling the work limit,
    /// where the coarse decision must equal `textmerge::fits` on the whole.
    #[test]
    fn s14c2_trimmed_map_lines_equals_the_whole_texts_diff() {
        fn reference(old: &[u8], new: &[u8], n: usize) -> (Vec<Option<u32>>, bool) {
            let a: Vec<&[u8]> = old.split_inclusive(|b| *b == b'\n').collect();
            let b: Vec<&[u8]> = new.split_inclusive(|b| *b == b'\n').collect();
            if !textmerge::fits(old, new) {
                (ends_map(&a, &b, n), true)
            } else {
                (diff_map(old, new, n), false)
            }
        }
        let mut seed = 0x51c2_7a3d_9e01_44b5u64;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        const TOKENS: [&str; 9] = ["a\n", "b\n", "a\r\n", "\n", "\r\n", "a", "a\r", "e\n", "e\r\n"];
        let mut cases = 0;
        for case in 0..40_000u64 {
            let k = 1 + (rnd() % TOKENS.len() as u64) as usize;
            let tok = |r: u64| TOKENS[(r % k as u64) as usize];
            let edge = tok(rnd()).to_string();
            let mid = |rnd: &mut dyn FnMut() -> u64| -> String {
                let n = (rnd() % 12) as usize;
                (0..n).map(|_| if rnd().is_multiple_of(3) { edge.clone() } else { tok(rnd()).to_string() }).collect()
            };
            let (pre, suf) = (edge.repeat((rnd() % 6) as usize), edge.repeat((rnd() % 6) as usize));
            let base = format!("{pre}{}{suf}", mid(&mut rnd));
            let mut old = base.clone();
            let mut new = match rnd() % 4 {
                0 => format!("{pre}{}{suf}", mid(&mut rnd)),
                1 => String::new(),
                _ => {
                    // Edits of the base: blocks of the edge line or tokens,
                    // inserted, deleted or replaced anywhere.
                    let mut v: Vec<String> = base.split_inclusive('\n').map(str::to_string).collect();
                    for _ in 0..1 + rnd() % 3 {
                        let at = (rnd() as usize) % (v.len() + 1);
                        let block: Vec<String> = (0..1 + rnd() % 3).map(|_| if rnd().is_multiple_of(2) { edge.clone() } else { tok(rnd()).to_string() }).collect();
                        match rnd() % 3 {
                            0 => {
                                v.splice(at..at, block);
                            }
                            1 if at < v.len() => {
                                let end = (at + 1 + (rnd() as usize) % 3).min(v.len());
                                v.drain(at..end);
                            }
                            _ if at < v.len() => v[at] = block.concat(),
                            _ => {}
                        }
                    }
                    v.concat()
                }
            };
            if case.is_multiple_of(11) {
                old.clear();
            }
            if case.is_multiple_of(7) {
                new.pop();
            }
            if case.is_multiple_of(13) {
                old.pop();
            }
            let n = line_ranges(new.as_bytes()).len();
            assert_eq!(map_lines(old.as_bytes(), new.as_bytes(), n), reference(old.as_bytes(), new.as_bytes(), n), "{old:?} -> {new:?}");
            ranged_maps_agree(&old, &new);
            cases += 1;
        }
        // Around the work limit: shared ends of repeated edge lines (which
        // also occur in the middle, so the trim is cut back) around middles
        // of two lines in random order, whose diff costs about the square
        // of their length; the length straddles where `fits` flips.
        let (mut coarse, mut fine) = (0, 0);
        for len in (1_000..9_000).step_by(500) {
            for ends in [3usize, 2_000] {
                let pick = |r: u64| if r.is_multiple_of(2) { "x\n" } else { "e\n" };
                let o: String = (0..len).map(|_| pick(rnd())).collect();
                let w: String = (0..len).map(|_| pick(rnd())).collect();
                let e = "e\n".repeat(ends);
                let (old, new) = (format!("{e}{o}{e}"), format!("{e}{w}y{e}"));
                let n = line_ranges(new.as_bytes()).len();
                let got = map_lines(old.as_bytes(), new.as_bytes(), n);
                let want = reference(old.as_bytes(), new.as_bytes(), n);
                assert_eq!(got.1, want.1, "coarse decision, {len} lines in the middle, {ends} at each end");
                assert!(got == want, "mapping, {len} lines in the middle, {ends} at each end");
                let (ol, nl) = (line_ranges(old.as_bytes()), line_ranges(new.as_bytes()));
                assert!(map_lines_ranged(old.as_bytes(), &ol, new.as_bytes(), &nl) == want, "ranged mapping, {len} lines in the middle, {ends} at each end");
                if got.1 {
                    coarse += 1;
                } else {
                    fine += 1;
                }
                cases += 1;
            }
        }
        assert!(coarse > 0 && fine > 0, "both sides of the limit: {coarse} coarse, {fine} fine");
        assert!(cases > 40_000);
    }
}
