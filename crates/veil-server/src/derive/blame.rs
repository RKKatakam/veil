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
use veil_core::{
    blame::{line_ranges, map_cost, map_lines},
    ObjectId,
};

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
/// doubling them), past [`BASE_BYTES`].
pub const MAX_BYTES_PER_LINE: usize = 128;
pub const MAX_BYTES_PER_CHANGE: usize = 768;
pub const BASE_BYTES: usize = 64;

impl Blame {
    /// The bytes it takes in memory, about.
    /// (Paths and metadata are shared: counted once, by their owner.)
    pub fn weight(&self) -> usize {
        64 + self.lines.len() * 8 + self.origins.len() * 64
    }

    /// About the bytes its stored form takes (for spacing checkpoints).
    pub fn stored_estimate(&self) -> usize {
        let runs = 1 + self.lines.windows(2).filter(|w| w[1].0 != w[0].0 || w[1].1 != w[0].1 + 1).count();
        let changes: std::collections::HashSet<&ObjectId> = self.origins.iter().map(|o| &o.0).collect();
        BASE_BYTES + 16 * runs + 104 * self.origins.len() + 160 * changes.len()
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
        for &(o, l) in &self.lines {
            match ranges.last_mut() {
                Some(r) if r[1] == o && r[2] + r[0] == l => r[0] += 1,
                _ => ranges.push([1, o, l]),
            }
        }
        let s = Stored {
            vd: self.vd,
            coarse: self.coarse,
            origins: self.origins.iter().map(|(id, p, _)| (*id, key(p))).collect(),
            ranges,
            changes: {
                let mut c: Vec<(ObjectId, Meta)> = self.origins.iter().map(|(id, _, m)| (*id, (**m).clone())).collect();
                c.sort_by_key(|a| a.0);
                c.dedup_by(|a, b| a.0 == b.0);
                c
            },
        };
        let mut out = MAGIC.to_vec();
        out.extend(serde_json::to_vec(&s).expect("a blame serialises"));
        out
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
pub struct Text {
    pub id: ObjectId,
    pub data: Vec<u8>,
    pub lines: Vec<(usize, usize)>,
}

impl Text {
    pub fn new(id: ObjectId, data: Vec<u8>) -> Arc<Text> {
        let lines = line_ranges(&data);
        Arc::new(Text { id, data, lines })
    }

    pub fn line(&self, i: usize) -> &[u8] {
        let (a, b) = self.lines[i];
        &self.data[a..b]
    }

    pub fn weight(&self) -> usize {
        64 + self.data.len() + self.lines.len() * 16
    }
}

/// The blame of version `me` (introduced by snapshot `me.0` at path
/// `me.1`), whose text is `text`, from its parent versions in parent
/// order (`None`: that parent holds no plain-text version); and what the
/// diffs cost ([`map_cost`]).
pub fn step(me: &Origin, text: &Text, parents: &[Option<(&Text, &Blame)>]) -> (Blame, u64) {
    let n = text.lines.len();
    let mut out = Blame {
        vd: 1 + parents.iter().flatten().map(|(_, b)| b.vd).max().unwrap_or(0),
        coarse: parents.iter().flatten().any(|(_, b)| b.coarse),
        origins: Vec::new(),
        lines: vec![(u32::MAX, 0); n],
    };
    // By snapshot and the path's pointer: paths are interned once per job,
    // so nothing is cloned or hashed but a pointer (S14 cycle 3).
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
    for (pt, pb) in parents.iter().flatten() {
        if open.is_empty() {
            break;
        }
        let same = pt.id == text.id || pt.data == text.data;
        let map = if same {
            None
        } else {
            let (map, coarse) = map_lines(&pt.data, &text.data, n);
            cost = cost.saturating_add(map_cost(pt.lines.len(), &map, coarse));
            out.coarse |= coarse;
            Some(map)
        };
        // The parent's origins as this blame's, interned once each.
        let mut mine: Vec<Option<u32>> = vec![None; pb.origins.len()];
        open.retain(|&i| {
            let j = match &map {
                None => Some(i as u32),
                Some(m) => m[i],
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
        assert_eq!(first_line("one\u{7}two\nthree", 100), "one two");
        assert_eq!(first_line(&"é".repeat(100), 9), "éééé");
    }
}
