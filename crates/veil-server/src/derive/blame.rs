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

const MAGIC: &[u8] = b"veil-derived blame 1\n";

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
    /// Distinct origins: the snapshot that introduced a line and the
    /// file's path there.
    pub origins: Vec<(ObjectId, String)>,
    pub lines: Vec<(u32, u32)>,
}

/// The stored form: runs of lines with one origin and consecutive lines
/// there, `[count, origin, first line]`.
#[derive(Serialize, Deserialize)]
struct Stored {
    vd: u64,
    coarse: bool,
    origins: Vec<(ObjectId, String)>,
    ranges: Vec<[u32; 3]>,
}

impl Blame {
    /// The bytes it takes in memory, about.
    pub fn weight(&self) -> usize {
        64 + self.lines.len() * 8 + self.origins.iter().map(|(_, p)| 48 + p.len()).sum::<usize>()
    }

    /// The origin of line `i` (from 0): snapshot, path, line there.
    pub fn origin(&self, i: usize) -> (&ObjectId, &str, u32) {
        let (o, l) = self.lines[i];
        let (id, p) = &self.origins[o as usize];
        (id, p, l)
    }

    pub fn encode(&self) -> Vec<u8> {
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
            origins: self.origins.clone(),
            ranges,
        };
        let mut out = MAGIC.to_vec();
        out.extend(serde_json::to_vec(&s).expect("a blame serialises"));
        out
    }

    /// Decode a stored blame; `max_lines` bounds what it may expand to.
    pub fn decode(raw: &[u8], max_lines: usize) -> Result<Blame> {
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
        Ok(Blame {
            vd: s.vd,
            coarse: s.coarse,
            origins: s.origins,
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
pub fn step(me: (ObjectId, &str), text: &Text, parents: &[Option<(&Text, &Blame)>]) -> (Blame, u64) {
    let n = text.lines.len();
    let mut out = Blame {
        vd: 1 + parents.iter().flatten().map(|(_, b)| b.vd).max().unwrap_or(0),
        coarse: parents.iter().flatten().any(|(_, b)| b.coarse),
        origins: Vec::new(),
        lines: vec![(u32::MAX, 0); n],
    };
    let mut index: HashMap<(ObjectId, String), u32> = HashMap::new();
    let mut intern = |out: &mut Blame, id: &ObjectId, p: &str| -> u32 {
        let key = (*id, p.to_string());
        if let Some(i) = index.get(&key) {
            return *i;
        }
        let i = out.origins.len() as u32;
        out.origins.push(key.clone());
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
                    let o = *mine[o as usize].get_or_insert_with(|| {
                        let (id, p) = &pb.origins[o as usize];
                        intern(&mut out, id, p)
                    });
                    out.lines[i] = (o, l);
                    false
                }
                _ => true,
            }
        });
    }
    if !open.is_empty() {
        let o = intern(&mut out, &me.0, me.1);
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
        let v1 = text("a\nb\nc\n");
        let (b1, _) = step((id(1), "f"), &v1, &[]);
        assert_eq!(who(&b1), [(1, "f".into(), 1), (1, "f".into(), 2), (1, "f".into(), 3)]);
        assert_eq!(b1.vd, 1);
        // A rename with an edit: line 2 is new, the others keep their origin.
        let v2 = text("a\nX\nc\nd\n");
        let (b2, cost) = step((id(2), "g"), &v2, &[Some((&v1, &b1))]);
        assert!(cost > 0);
        assert_eq!(who(&b2), [(1, "f".into(), 1), (2, "g".into(), 2), (1, "f".into(), 3), (2, "g".into(), 4)]);
        assert_eq!(b2.vd, 2);
        // A merge: the first parent first, then the second; a parent with
        // no version holds nothing.
        let v3 = text("a\nb\nX\nd\nnew\n");
        let (b3, _) = step((id(3), "g"), &v3, &[Some((&v2, &b2)), None, Some((&v1, &b1))]);
        assert_eq!(who(&b3), [(1, "f".into(), 1), (1, "f".into(), 2), (2, "g".into(), 2), (2, "g".into(), 4), (3, "g".into(), 5)]);
        assert_eq!(b3.vd, 3);
        // The same version passes every line without a diff.
        let (b4, cost) = step((id(4), "g"), &v3, &[Some((&v3, &b3))]);
        assert_eq!((who(&b4), cost), (who(&b3), 0));
    }

    #[test]
    fn stored_blames_round_trip_and_stay_bounded() {
        let v1 = text("a\nb\nc\nd\n");
        let (b1, _) = step((id(1), "f"), &v1, &[]);
        let v2 = text("a\nz\nc\nd\n");
        let (b2, _) = step((id(2), "f"), &v2, &[Some((&v1, &b1))]);
        let raw = b2.encode();
        assert_eq!(Blame::decode(&raw, 4).unwrap(), b2);
        assert!(Blame::decode(&raw, 3).is_err(), "more lines than allowed");
        assert!(Blame::decode(b"veil-derived changed-paths 1\n{}", 10).is_err());
    }
}
