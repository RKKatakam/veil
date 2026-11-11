//! Blame values (milestone S14; phase-3 design §3.1, §3.6): who introduced
//! each line of one version of a file, computed **from the blames of the
//! versions it came from and one line diff each**, and stored as one
//! object per version (`veil-derived blame 1` then JSON), addressed by its
//! hash.
//!
//! A version is named by the snapshot that introduced it (the one whose
//! change against its first parent set the file's entry) and the file's
//! path there. Its blame is a function of that snapshot's history alone,
//! so it is computed once and kept ([`step`] is the function; the query
//! API walks the versions and memoises: `query::files`). The server
//! computes it on a viewer's **projected** history only (snapshots and
//! paths the viewer sees), so no origin ever names a hidden change or path.
//!
//! A line moves to the first parent version that holds it, through
//! [`veil_core::blame::map_lines`] (the diff `vl blame` uses), and takes
//! that version's origin for its line there; a line no parent holds is
//! the version's own. A parent whose version is not plain text (absent,
//! a secret, binary, too large) holds no line.

use std::{collections::HashMap, sync::Arc};

use serde::{Deserialize, Serialize};
use veil_core::{blame::line_ranges, ObjectId};

use crate::error::{Error, Result};

const MAGIC: &[u8] = b"veil-derived blame 2\n";

/// One version's blame, in memory: for each line, the index of its origin
/// in `origins` and its line number there (from 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blame {
    /// 1 + the largest of its parent versions' (1 for a version with none
    /// it came from): which versions are kept as checkpoints.
    pub vd: u64,
    /// Some diff on the way was past its work limit (its differing middle
    /// was attributed whole), as `vl blame` says.
    pub coarse: bool,
    /// Distinct origins: the snapshot that introduced a line, the file's
    /// path there (interned: shared by every blame of a job), and what an
    /// answer shows of that snapshot.
    pub origins: Vec<Origin>,
    pub lines: Vec<(u32, u32)>,
}

/// An origin: snapshot, path, and what an answer shows of the snapshot.
pub type Origin = (ObjectId, Arc<str>, Arc<Meta>);

/// What a blame answer shows of a change its lines name, kept with the
/// blame so that an answer reads nothing else (the viewer's projected
/// snapshot: their change id, author, date and generation, and the first
/// line of the description, as the viewer's log shows them).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    #[serde(rename = "c")]
    pub change_id: String,
    #[serde(rename = "a")]
    pub author: String,
    #[serde(rename = "t")]
    pub timestamp: i64,
    #[serde(rename = "s")]
    pub summary: String,
    #[serde(rename = "g")]
    pub generation: i64,
}

/// Most bytes of a change's author and summary kept (cut at a character).
pub const MAX_AUTHOR: usize = 128;
pub const MAX_SUMMARY: usize = 160;

/// `s`'s first line, control characters as spaces, at most `max` bytes.
pub fn first_line(s: &str, max: usize) -> String {
    let line = s.lines().next().unwrap_or("");
    let mut out = String::new();
    for c in line.chars() {
        let c = if c.is_control() { ' ' } else { c };
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    out
}

impl Meta {
    pub fn of(s: &veil_core::object::Snapshot, generation: i64) -> Meta {
        Meta {
            change_id: s.change_id.to_string(),
            author: first_line(&s.author, MAX_AUTHOR),
            timestamp: s.timestamp,
            summary: first_line(s.description.as_str(), MAX_SUMMARY),
            generation,
        }
    }

    /// Decode only the metadata fields needed by blame from a trusted
    /// canonical `veil:snap\n` payload, skipping parents, tree, and signature
    /// hex decoding.
    pub fn from_raw_snapshot(raw: &[u8], generation: i64) -> Option<Meta> {
        #[derive(Deserialize)]
        struct RawSnap {
            change_id: String,
            description: veil_core::object::Text,
            author: String,
            timestamp: i64,
        }
        let body = raw.strip_prefix(b"veil:snap\n")?;
        let s: RawSnap = serde_json::from_slice(body).ok()?;
        Some(Meta {
            change_id: s.change_id,
            author: first_line(&s.author, MAX_AUTHOR),
            timestamp: s.timestamp,
            summary: first_line(s.description.as_str(), MAX_SUMMARY),
            generation,
        })
    }
}

/// The stored form: runs of lines with one origin and consecutive lines
/// there, `[count, origin, first line]`; each origin's path by its key
/// (the paths are stored once per project, beside: BUG-1217), so a kept
/// blame takes at most [`MAX_BYTES_PER_LINE`] a line, plus a little.
#[derive(Serialize, Deserialize)]
struct Stored {
    vd: u64,
    coarse: bool,
    origins: Vec<(ObjectId, String)>,
    ranges: Vec<[u32; 3]>,
    /// What an answer shows of each snapshot the origins name, by id.
    changes: Vec<(ObjectId, Meta)>,
}

/// Most bytes a kept blame takes per line of its version (an origin, 64 hex
/// digits and a 32-digit path key with their JSON, and a range), and per
/// change its lines name (its id and [`Meta`], author and summary at most
/// [`MAX_AUTHOR`] and [`MAX_SUMMARY`] bytes, their JSON escapes at most
/// doubling them), past [`BASE_BYTES`]: the header and the JSON of an
/// empty blame, at most 101 bytes with the largest depth (BUG-1219: it was
/// stated as 64, and an empty file's kept blame took 82).
pub const MAX_BYTES_PER_LINE: usize = 128;
pub const MAX_BYTES_PER_CHANGE: usize = 768;
pub const BASE_BYTES: usize = 128;

fn write_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 64];
    for (i, &b) in bytes.iter().enumerate() {
        buf[2 * i] = HEX[(b >> 4) as usize];
        buf[2 * i + 1] = HEX[(b & 0xf) as usize];
    }
    out.push_str(std::str::from_utf8(&buf[..bytes.len() * 2]).unwrap());
}

fn write_u64(out: &mut String, mut v: u64) {
    if v == 0 {
        out.push('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 20;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    out.push_str(std::str::from_utf8(&buf[i..]).unwrap());
}

fn write_i64(out: &mut String, v: i64) {
    if v < 0 {
        out.push('-');
        write_u64(out, v.unsigned_abs());
    } else {
        write_u64(out, v as u64);
    }
}

fn write_json_str(out: &mut String, s: &str) {
    out.push('"');
    let bytes = s.as_bytes();
    if !bytes.iter().any(|&b| b == b'"' || b == b'\\' || b < 0x20) {
        out.push_str(s);
        out.push('"');
        return;
    }
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let esc = match b {
            b'"' => "\\\"",
            b'\\' => "\\\\",
            b'\x08' => "\\b",
            b'\x0c' => "\\f",
            b'\n' => "\\n",
            b'\r' => "\\r",
            b'\t' => "\\t",
            0x00..=0x1f => {
                if start < i {
                    out.push_str(&s[start..i]);
                }
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{b:04x}");
                start = i + 1;
                continue;
            }
            _ => continue,
        };
        if start < i {
            out.push_str(&s[start..i]);
        }
        out.push_str(esc);
        start = i + 1;
    }
    if start < s.len() {
        out.push_str(&s[start..]);
    }
    out.push('"');
}

impl Blame {
    /// The bytes it takes in memory, about.
    /// (Paths and metadata are shared: counted once, by their owner.)
    pub fn weight(&self) -> usize {
        64 + self.lines.len() * 8 + self.origins.len() * 64
    }

    /// About the bytes its stored form takes (for spacing checkpoints).
    pub fn stored_estimate(&self) -> usize {
        let mut ranges = 0usize;
        let mut i = 0;
        let len = self.lines.len();
        while i < len {
            let (o, l0) = self.lines[i];
            let mut count = 1u32;
            while i + (count as usize) < len {
                let (no, nl) = self.lines[i + (count as usize)];
                if no == o && nl == l0 + count {
                    count += 1;
                } else {
                    break;
                }
            }
            ranges += 1;
            i += count as usize;
        }
        let mut origins_bytes = 0usize;
        let mut changes_bytes = 0usize;
        for (_, _, m) in &self.origins {
            origins_bytes += 104;
            changes_bytes += 126 + m.change_id.len() + m.author.len() + m.summary.len();
        }
        40 + 18 * ranges + origins_bytes + changes_bytes
    }

    /// The origin of line `i` (from 0): snapshot, path, line there.
    pub fn origin(&self, i: usize) -> (&ObjectId, &str, u32) {
        let (o, l) = self.lines[i];
        let (id, p, _) = &self.origins[o as usize];
        (id, p, l)
    }

    /// What an answer shows of line `i`'s change.
    pub fn meta(&self, i: usize) -> &Arc<Meta> {
        &self.origins[self.lines[i].0 as usize].2
    }

    /// The stored bytes, origins' paths named by `key`.
    pub fn encode(&self, key: impl Fn(&str) -> String) -> Vec<u8> {
        let mut ranges: Vec<[u32; 3]> = Vec::new();
        let mut i = 0;
        let len = self.lines.len();
        while i < len {
            let (o, l0) = self.lines[i];
            let mut count = 1u32;
            while i + (count as usize) < len {
                let (no, nl) = self.lines[i + (count as usize)];
                if no == o && nl == l0 + count {
                    count += 1;
                } else {
                    break;
                }
            }
            ranges.push([count, o, l0]);
            i += count as usize;
        }
        let mut changes: Vec<(ObjectId, &Meta)> = self.origins.iter().map(|(id, _, m)| (*id, &**m)).collect();
        changes.sort_unstable_by_key(|a| a.0);
        changes.dedup_by(|a, b| a.0 == b.0);
        let mut out = String::with_capacity(BASE_BYTES + 24 * ranges.len() + 264 * self.origins.len());
        out.push_str(std::str::from_utf8(MAGIC).unwrap());
        out.push_str("{\"vd\":");
        write_u64(&mut out, self.vd);
        out.push_str(",\"coarse\":");
        out.push_str(if self.coarse { "true" } else { "false" });
        out.push_str(",\"origins\":[");
        for (idx, (id, p, _)) in self.origins.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push_str("[\"");
            write_hex(&mut out, &id.0);
            out.push_str("\",\"");
            out.push_str(&key(p));
            out.push_str("\"]");
        }
        out.push_str("],\"ranges\":[");
        for (idx, &[c, o, l0]) in ranges.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push('[');
            write_u64(&mut out, c as u64);
            out.push(',');
            write_u64(&mut out, o as u64);
            out.push(',');
            write_u64(&mut out, l0 as u64);
            out.push(']');
        }
        out.push_str("],\"changes\":[");
        for (idx, (id, m)) in changes.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push_str("[\"");
            write_hex(&mut out, &id.0);
            out.push_str("\",{\"c\":");
            write_json_str(&mut out, &m.change_id);
            out.push_str(",\"a\":");
            write_json_str(&mut out, &m.author);
            out.push_str(",\"t\":");
            write_i64(&mut out, m.timestamp);
            out.push_str(",\"s\":");
            write_json_str(&mut out, &m.summary);
            out.push_str(",\"g\":");
            write_i64(&mut out, m.generation);
            out.push_str("}]");
        }
        out.push_str("]}");
        out.into_bytes()
    }

    /// The path keys a stored blame names.
    pub fn keys(raw: &[u8]) -> Result<Vec<String>> {
        let body = raw.strip_prefix(MAGIC).ok_or_else(|| Error::Other(anyhow::anyhow!("blame object: not a blame object")))?;
        let s: Stored = serde_json::from_slice(body).map_err(|e| Error::Other(anyhow::anyhow!("blame object: {e}")))?;
        Ok(s.origins.into_iter().map(|(_, k)| k).collect())
    }

    /// Decode a stored blame, its path keys resolved by `path`;
    /// `max_lines` bounds what it may expand to.
    pub fn decode(raw: &[u8], max_lines: usize, path: impl Fn(&str) -> Option<Arc<str>>) -> Result<Blame> {
        let bad = |m: &str| Error::Other(anyhow::anyhow!("blame object: {m}"));
        let body = raw.strip_prefix(MAGIC).ok_or_else(|| bad("not a blame object"))?;
        let s: Stored = serde_json::from_slice(body).map_err(|e| bad(&e.to_string()))?;
        let mut lines = Vec::new();
        for [count, o, first] in s.ranges {
            if o as usize >= s.origins.len() || lines.len() + count as usize > max_lines {
                return Err(bad("out of bounds"));
            }
            lines.extend((0..count).map(|k| (o, first + k)));
        }
        let metas: HashMap<ObjectId, Arc<Meta>> = s.changes.into_iter().map(|(id, m)| (id, Arc::new(m))).collect();
        let mut origins = Vec::with_capacity(s.origins.len());
        for (id, k) in s.origins {
            let p = path(&k).ok_or_else(|| bad("a path it names is not stored"))?;
            let m = metas.get(&id).cloned().ok_or_else(|| bad("a change it names has no record"))?;
            origins.push((id, p, m));
        }
        Ok(Blame {
            vd: s.vd,
            coarse: s.coarse,
            origins,
            lines,
        })
    }
}

/// A version's plain text, split in lines.
#[derive(Debug)]
pub struct Text {
    pub id: ObjectId,
    pub data: bytes::Bytes,
    pub lines: Vec<(usize, usize)>,
}

impl Text {
    pub fn new(id: ObjectId, data: impl Into<bytes::Bytes>) -> Arc<Text> {
        let data = data.into();
        let lines = line_ranges(&data);
        Arc::new(Text { id, data, lines })
    }

    /// Construct [`Text`] if `data` contains no NUL byte and is valid UTF-8,
    /// scanning for NUL, UTF-8, and line boundaries in a single pass.
    pub fn try_plain(id: ObjectId, data: impl Into<bytes::Bytes>) -> Option<Arc<Text>> {
        let data = data.into();
        let lines = veil_core::blame::plain_text_line_ranges(&data)?;
        Some(Arc::new(Text { id, data, lines }))
    }

    /// Construct [`Text`] reusing unchanged prefix and suffix line ranges from `parent`.
    pub fn try_plain_from_parent(id: ObjectId, data: impl Into<bytes::Bytes>, parent: &Text) -> Option<Arc<Text>> {
        let data = data.into();
        let lines = veil_core::blame::plain_text_line_ranges_from_parent(&data, &parent.data, &parent.lines)?;
        Some(Arc::new(Text { id, data, lines }))
    }

    pub fn line(&self, i: usize) -> &[u8] {
        let (a, b) = self.lines[i];
        &self.data[a..b]
    }

    pub fn weight(&self) -> usize {
        64 + self.data.len() + self.lines.len() * 16
    }
}

/// Precomputed line mapping between a parent version's text `pt` and `text`.
#[derive(Clone, Debug)]
pub enum ParentMap {
    /// Both versions have identical bytes.
    Same,
    /// Same line count `len`, differing only at a few isolated line indices `diffs`.
    Replaced {
        len: usize,
        diffs: Vec<usize>,
        cost: u64,
    },
    /// `p` shared lines at the start, `mid` for the differing middle, `s` shared
    /// lines at the end (referencing the end of `pt`, which has `old_len` lines),
    /// plus `(coarse, cost)`.
    Trimmed {
        old_len: usize,
        p: usize,
        mid: Vec<Option<u32>>,
        s: usize,
        coarse: bool,
        cost: u64,
    },
}

impl ParentMap {
    pub fn coarse(&self) -> bool {
        match self {
            ParentMap::Same | ParentMap::Replaced { .. } => false,
            ParentMap::Trimmed { coarse, .. } => *coarse,
        }
    }

    pub fn cost(&self) -> u64 {
        match self {
            ParentMap::Same => 0,
            ParentMap::Replaced { cost, .. } | ParentMap::Trimmed { cost, .. } => *cost,
        }
    }
}

/// Compute the line mapping from parent `pt` to `text`.
pub fn diff_parent(pt: &Text, text: &Text) -> ParentMap {
    let same = pt.id == text.id || pt.data == text.data;
    if same {
        return ParentMap::Same;
    }
    let m = pt.lines.len();
    let n = text.lines.len();
    if m == n {
        if let Some(diffs) = veil_core::blame::isolated_replacements(&pt.data, &pt.lines, &text.data, &text.lines) {
            if diffs.is_empty() {
                return ParentMap::Same;
            }
            let lines = (m + n) as u64;
            let d = (2 * diffs.len()) as u64;
            let cost = lines.saturating_add(d.saturating_mul(d));
            return ParentMap::Replaced { len: n, diffs, cost };
        }
    }
    let (p, mid, s, coarse) = veil_core::blame::map_lines_trimmed(&pt.data, &pt.lines, &text.data, &text.lines);
    let lines = (m + n) as u64;
    let search = if coarse {
        veil_core::textmerge::work_limit(lines as usize)
    } else {
        let kept = (p + s + mid.iter().filter(|x| x.is_some()).count()) as u64;
        let d = lines.saturating_sub(2 * kept);
        d.saturating_mul(d)
    };
    let cost = lines.saturating_add(search);
    ParentMap::Trimmed {
        old_len: m,
        p,
        mid,
        s,
        coarse,
        cost,
    }
}

/// The blame of version `me` (introduced by snapshot `me.0` at path
/// `me.1`), whose text is `text`, from its parent versions in parent
/// order (`None`: that parent holds no plain-text version); and what the
/// diffs cost ([`veil_core::blame::map_cost`]).
pub fn step(me: &Origin, text: &Text, parents: &[Option<(&Text, &Blame)>]) -> (Blame, u64) {
    let mapped: Vec<Option<(&Blame, ParentMap)>> = parents
        .iter()
        .map(|p| p.map(|(pt, pb)| (pb, diff_parent(pt, text))))
        .collect();
    step_mapped(me, text.lines.len(), &mapped)
}

/// Compact `out.origins` if any of the origins in `candidates` (which lost at
/// least one line) are no longer referenced by `out.lines`.
fn compact_origins_if_needed(out: &mut Blame, candidates: &[u32]) {
    if candidates.is_empty() || out.origins.len() <= 1 {
        return;
    }
    let any_dead = candidates.iter().any(|&cand| !out.lines.iter().any(|&(o, _)| o == cand));
    if !any_dead {
        return;
    }
    let mut used = vec![false; out.origins.len()];
    for &(o, _) in &out.lines {
        used[o as usize] = true;
    }
    let mut remap = vec![0u32; out.origins.len()];
    let mut new_origins = Vec::with_capacity(out.origins.len());
    for (old_o, orig) in std::mem::take(&mut out.origins).into_iter().enumerate() {
        if used[old_o] {
            remap[old_o] = new_origins.len() as u32;
            new_origins.push(orig);
        }
    }
    for (o, _) in &mut out.lines {
        *o = remap[*o as usize];
    }
    out.origins = new_origins;
}

/// [`step`] when each parent's [`ParentMap`] has already been computed.
pub fn step_mapped(me: &Origin, n: usize, parents: &[Option<(&Blame, ParentMap)>]) -> (Blame, u64) {
    let mut counts = Vec::new();
    step_mapped_with_counts(me, n, parents, &mut counts)
}

/// [`step_mapped_with_counts`], mutating `cur` in place when stepping from a
/// single parent (`cur` itself) via `Same` or `Replaced` so neither `lines`
/// nor `origins` is cloned unless a checkpoint needs an `Arc<Blame>`.
pub fn step_mapped_in_place(
    cur: &mut Blame,
    me: &Origin,
    n: usize,
    pm: &ParentMap,
    counts: &mut Vec<u32>,
) -> u64 {
    if counts.len() != cur.origins.len() {
        counts.clear();
        counts.resize(cur.origins.len(), 0);
        for &(o, _) in &cur.lines {
            counts[o as usize] += 1;
        }
        if cur.origins.len() > 1 && counts.contains(&0) {
            let mut remap = vec![0u32; cur.origins.len()];
            let mut new_origins = Vec::with_capacity(cur.origins.len());
            let mut new_counts = Vec::with_capacity(cur.origins.len());
            for (old_o, orig) in std::mem::take(&mut cur.origins).into_iter().enumerate() {
                if counts[old_o] > 0 {
                    remap[old_o] = new_origins.len() as u32;
                    new_origins.push(orig);
                    new_counts.push(counts[old_o]);
                }
            }
            for (lo, _) in &mut cur.lines {
                *lo = remap[*lo as usize];
            }
            cur.origins = new_origins;
            *counts = new_counts;
        }
    }
    match pm {
        ParentMap::Same if cur.lines.len() == n => {
            cur.vd += 1;
            return 0;
        }
        ParentMap::Replaced { len, diffs, cost } if *len == cur.lines.len() && *len == n => {
            cur.vd += 1;
            let o = if let Some(pos) = cur.origins.iter().position(|x| x.0 == me.0 && Arc::ptr_eq(&x.1, &me.1)) {
                pos as u32
            } else {
                let idx = cur.origins.len() as u32;
                cur.origins.push(me.clone());
                counts.push(0);
                idx
            };
            let mut any_dead = false;
            for &d in diffs {
                let old_o = cur.lines[d].0;
                counts[old_o as usize] -= 1;
                if counts[old_o as usize] == 0 {
                    any_dead = true;
                }
                counts[o as usize] += 1;
                cur.lines[d] = (o, d as u32 + 1);
            }
            if any_dead && cur.origins.len() > 1 {
                let mut remap = vec![0u32; cur.origins.len()];
                let mut new_origins = Vec::with_capacity(cur.origins.len());
                let mut new_counts = Vec::with_capacity(cur.origins.len());
                for (old_o, orig) in std::mem::take(&mut cur.origins).into_iter().enumerate() {
                    if counts[old_o] > 0 {
                        remap[old_o] = new_origins.len() as u32;
                        new_origins.push(orig);
                        new_counts.push(counts[old_o]);
                    }
                }
                for (lo, _) in &mut cur.lines {
                    *lo = remap[*lo as usize];
                }
                cur.origins = new_origins;
                *counts = new_counts;
            }
            return *cost;
        }
        _ => {}
    }
    let inputs = [Some((&*cur, pm.clone()))];
    let (next, cost) = step_mapped_with_counts(me, n, &inputs, counts);
    *cur = next;
    cost
}

/// [`step_mapped`], maintaining `counts[o]` (how many lines of the current
/// single-parent chain reference `origins[o]`) across sequential single-parent
/// steps so dead origins are detected in `O(1)` without scanning `out.lines`.
pub fn step_mapped_with_counts(
    me: &Origin,
    n: usize,
    parents: &[Option<(&Blame, ParentMap)>],
    counts: &mut Vec<u32>,
) -> (Blame, u64) {
    if parents.len() == 1 {
        if let Some((pb, pm)) = &parents[0] {
            if counts.len() != pb.origins.len() {
                counts.clear();
                counts.resize(pb.origins.len(), 0);
                for &(o, _) in &pb.lines {
                    counts[o as usize] += 1;
                }
            }
            match pm {
                ParentMap::Same if pb.lines.len() == n => {
                    let mut out = (*pb).clone();
                    out.vd = pb.vd + 1;
                    return (out, 0);
                }
                ParentMap::Replaced { len, diffs, cost } if *len == pb.lines.len() && *len == n => {
                    let mut out = Blame {
                        vd: pb.vd + 1,
                        coarse: pb.coarse,
                        origins: pb.origins.clone(),
                        lines: pb.lines.clone(),
                    };
                    let o = if let Some(pos) = out.origins.iter().position(|x| x.0 == me.0 && Arc::ptr_eq(&x.1, &me.1)) {
                        pos as u32
                    } else {
                        let idx = out.origins.len() as u32;
                        out.origins.push(me.clone());
                        counts.push(0);
                        idx
                    };
                    let mut any_dead = false;
                    for &d in diffs {
                        let old_o = out.lines[d].0;
                        counts[old_o as usize] -= 1;
                        if counts[old_o as usize] == 0 {
                            any_dead = true;
                        }
                        counts[o as usize] += 1;
                        out.lines[d] = (o, d as u32 + 1);
                    }
                    if any_dead && out.origins.len() > 1 {
                        let mut remap = vec![0u32; out.origins.len()];
                        let mut new_origins = Vec::with_capacity(out.origins.len());
                        let mut new_counts = Vec::with_capacity(out.origins.len());
                        for (old_o, orig) in std::mem::take(&mut out.origins).into_iter().enumerate() {
                            if counts[old_o] > 0 {
                                remap[old_o] = new_origins.len() as u32;
                                new_origins.push(orig);
                                new_counts.push(counts[old_o]);
                            }
                        }
                        for (lo, _) in &mut out.lines {
                            *lo = remap[*lo as usize];
                        }
                        out.origins = new_origins;
                        *counts = new_counts;
                    }
                    return (out, *cost);
                }
                ParentMap::Trimmed { old_len, p, mid, s, coarse, cost } if *old_len == pb.lines.len() => {
                    counts.clear();
                    let mut out = Blame {
                        vd: pb.vd + 1,
                        coarse: pb.coarse || *coarse,
                        origins: pb.origins.clone(),
                        lines: Vec::with_capacity(n),
                    };
                    // 1. Prefix `0..p` comes straight from `pb.lines[0..p]`.
                    out.lines.extend_from_slice(&pb.lines[..*p]);
                    // 2. Middle `p..n - s`:
                    let mut me_idx: Option<u32> = None;
                    for (i, &mapped_j) in mid.iter().enumerate() {
                        match mapped_j {
                            Some(j) if (j as usize) < pb.lines.len() => {
                                out.lines.push(pb.lines[j as usize]);
                            }
                            _ => {
                                let o = *me_idx.get_or_insert_with(|| {
                                    if let Some(pos) = out.origins.iter().position(|x| x.0 == me.0 && Arc::ptr_eq(&x.1, &me.1)) {
                                        pos as u32
                                    } else {
                                        let idx = out.origins.len() as u32;
                                        out.origins.push(me.clone());
                                        idx
                                    }
                                });
                                out.lines.push((o, (*p + i) as u32 + 1));
                            }
                        }
                    }
                    // 3. Suffix `n - s..n` comes straight from `pb.lines[old_len - s..old_len]`.
                    out.lines.extend_from_slice(&pb.lines[*old_len - *s..]);
                    // Check if any origin present in the old middle `pb.lines[p..old_len - s]` became unused.
                    if *old_len - *p - *s > 0 && out.origins.len() > 1 {
                        let mut candidates: Vec<u32> = Vec::new();
                        for &(old_o, _) in &pb.lines[*p..*old_len - *s] {
                            if !candidates.contains(&old_o) {
                                candidates.push(old_o);
                            }
                        }
                        compact_origins_if_needed(&mut out, &candidates);
                    }
                    return (out, *cost);
                }
                _ => {}
            }
        }
    }
    counts.clear();
    let mut out = Blame {
        vd: 1 + parents.iter().flatten().map(|(b, _)| b.vd).max().unwrap_or(0),
        coarse: parents.iter().flatten().any(|(b, pm)| b.coarse || pm.coarse()),
        origins: Vec::new(),
        lines: vec![(u32::MAX, 0); n],
    };
    let mut index: HashMap<(ObjectId, usize), u32> = HashMap::new();
    let mut intern = |out: &mut Blame, o: &Origin| -> u32 {
        let key = (o.0, Arc::as_ptr(&o.1) as *const u8 as usize);
        if let Some(i) = index.get(&key) {
            return *i;
        }
        let i = out.origins.len() as u32;
        out.origins.push(o.clone());
        index.insert(key, i);
        i
    };
    let mut cost = 0u64;
    let mut open: Vec<usize> = (0..n).collect();
    for (pb, pm) in parents.iter().flatten() {
        if open.is_empty() {
            break;
        }
        cost = cost.saturating_add(pm.cost());
        out.coarse |= pm.coarse();
        let mut mine: Vec<Option<u32>> = vec![None; pb.origins.len()];
        open.retain(|&i| {
            let j = match pm {
                ParentMap::Same => Some(i as u32),
                ParentMap::Replaced { diffs, .. } => {
                    if diffs.contains(&i) {
                        None
                    } else {
                        Some(i as u32)
                    }
                }
                ParentMap::Trimmed { old_len, p, mid, s, .. } => {
                    if i < *p {
                        Some(i as u32)
                    } else if i >= n - *s {
                        Some((*old_len - (n - i)) as u32)
                    } else {
                        mid[i - *p]
                    }
                }
            };
            match j {
                Some(j) if (j as usize) < pb.lines.len() => {
                    let (o, l) = pb.lines[j as usize];
                    let o = *mine[o as usize].get_or_insert_with(|| intern(&mut out, &pb.origins[o as usize]));
                    out.lines[i] = (o, l);
                    false
                }
                _ => true,
            }
        });
    }
    if !open.is_empty() {
        let o = intern(&mut out, me);
        for i in open {
            out.lines[i] = (o, i as u32 + 1);
        }
    }
    (out, cost)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> ObjectId {
        ObjectId([n; 32])
    }

    fn text(s: &str) -> Arc<Text> {
        Text::new(ObjectId::hash(s.as_bytes()), s.as_bytes().to_vec())
    }

    fn meta(n: u8) -> Arc<Meta> {
        Arc::new(Meta { change_id: format!("change {n}"), author: "a".into(), timestamp: n as i64, summary: format!("did {n}"), generation: n as i64 })
    }

    /// A job's interner, as `query::files` keeps one.
    struct Paths(HashMap<String, Arc<str>>);

    impl Paths {
        fn get(&mut self, p: &str) -> Arc<str> {
            self.0.entry(p.to_string()).or_insert_with(|| Arc::from(p)).clone()
        }
    }

    fn who(b: &Blame) -> Vec<(u8, String, u32)> {
        (0..b.lines.len())
            .map(|i| {
                let (s, p, l) = b.origin(i);
                (s.0[0], p.to_string(), l)
            })
            .collect()
    }

    #[test]
    fn lines_come_from_the_first_parent_that_holds_them() {
        let mut paths = Paths(HashMap::new());
        let mut o = |n: u8, p: &str| (id(n), paths.get(p), meta(n));
        let v1 = text("a\nb\nc\n");
        let (b1, _) = step(&o(1, "f"), &v1, &[]);
        assert_eq!(who(&b1), [(1, "f".into(), 1), (1, "f".into(), 2), (1, "f".into(), 3)]);
        assert_eq!(b1.vd, 1);
        // A rename with an edit: line 2 is new, the others keep their origin.
        let v2 = text("a\nX\nc\nd\n");
        let (b2, cost) = step(&o(2, "g"), &v2, &[Some((&v1, &b1))]);
        assert!(cost > 0);
        assert_eq!(who(&b2), [(1, "f".into(), 1), (2, "g".into(), 2), (1, "f".into(), 3), (2, "g".into(), 4)]);
        assert_eq!(b2.vd, 2);
        // A merge: the first parent first, then the second; a parent with
        // no version holds nothing.
        let v3 = text("a\nb\nX\nd\nnew\n");
        let (b3, _) = step(&o(3, "g"), &v3, &[Some((&v2, &b2)), None, Some((&v1, &b1))]);
        assert_eq!(who(&b3), [(1, "f".into(), 1), (1, "f".into(), 2), (2, "g".into(), 2), (2, "g".into(), 4), (3, "g".into(), 5)]);
        assert_eq!(b3.vd, 3);
        assert_eq!(b3.meta(4).summary, "did 3");
        assert_eq!(b3.meta(0).summary, "did 1");
        // The same version passes every line without a diff.
        let (b4, cost) = step(&o(4, "g"), &v3, &[Some((&v3, &b3))]);
        assert_eq!((who(&b4), cost), (who(&b3), 0));
    }

    #[test]
    fn stored_blames_round_trip_and_stay_bounded() {
        let mut paths = Paths(HashMap::new());
        let f = paths.get("f");
        let v1 = text("a\nb\nc\nd\n");
        let (b1, _) = step(&(id(1), f.clone(), meta(1)), &v1, &[]);
        let v2 = text("a\nz\nc\nd\n");
        let (b2, _) = step(&(id(2), f.clone(), meta(2)), &v2, &[Some((&v1, &b1))]);
        let key = |p: &str| format!("k-{p}");
        let path = |k: &str| k.strip_prefix("k-").map(Arc::from);
        let raw = b2.encode(key);
        assert_eq!(Blame::decode(&raw, 4, path).unwrap(), b2);
        assert_eq!(Blame::keys(&raw).unwrap(), ["k-f", "k-f"]);
        assert!(Blame::decode(&raw, 3, path).is_err(), "more lines than allowed");
        assert!(Blame::decode(&raw, 4, |_| None).is_err(), "a path not stored");
        assert!(Blame::decode(b"veil-derived changed-paths 1\n{}", 10, path).is_err());
        // Bounded by its lines and changes: 400 lines from 400 changes at a
        // 4 KB path, each with the longest author and summary kept, all of
        // characters JSON escapes.
        let long: Arc<str> = Arc::from("d/".repeat(2000).as_str());
        let quoted = "\"".repeat(400);
        let m = |i: u32| {
            Arc::new(Meta {
                change_id: "k".repeat(32),
                author: first_line(&quoted, MAX_AUTHOR),
                timestamp: i64::MAX,
                summary: first_line(&quoted, MAX_SUMMARY),
                generation: i64::MAX - i as i64,
            })
        };
        let many = Blame {
            vd: 1,
            coarse: false,
            origins: (0..400u32).map(|i| (ObjectId::hash(&i.to_le_bytes()), long.clone(), m(i))).collect(),
            lines: (0..400).map(|i| (i, 1)).collect(),
        };
        let raw = many.encode(crate::derive::changes::path_key);
        assert!(raw.len() <= BASE_BYTES + (MAX_BYTES_PER_LINE + MAX_BYTES_PER_CHANGE) * 400, "{}", raw.len());
        // An empty blame at the largest depth: the base alone (BUG-1219).
        let empty = Blame { vd: u64::MAX, coarse: false, origins: Vec::new(), lines: Vec::new() };
        let raw = empty.encode(crate::derive::changes::path_key);
        assert!(raw.len() <= BASE_BYTES, "{}", raw.len());
        assert_eq!(first_line("one\u{7}two\nthree", 100), "one two");
        assert_eq!(first_line(&"é".repeat(100), 9), "éééé");
    }
}
