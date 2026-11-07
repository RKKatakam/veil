//! Search segments (milestone S15): immutable pieces of one shard's index.
//!
//! A segment holds **documents** (a path, its entry id, size and flags),
//! **tombstones** (paths it deletes from older segments of its shard) and a
//! **trigram index**: for each trigram of the documents' text (content for
//! code segments, the path for name segments), ASCII case folded, the
//! sorted ordinals of the documents holding it. Documents are sorted in
//! tree order ([`tree_cmp`]), so ordinals are in path order.
//!
//! A shard is a list of segments, oldest first. A document of segment `i`
//! is **live** unless a newer segment of the same shard holds a document or
//! a tombstone at its path ([`Segment::shadows`]). Answers count, rank and
//! page live documents only; dead ones are only a cost, bounded by
//! compaction (`index`).
//!
//! The encoding is not an object encoding (it starts with
//! [`MAGIC`]), so no push can name one, and nothing serves it to a client.

use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    sync::{Arc, OnceLock},
};

use veil_core::{cache::LruCache, ObjectId};

use crate::error::{Error, Result};

pub const MAGIC: &[u8] = b"veil-derived search-segment 1\n";

/// Document flags: the entry's kind (two bits), then what was indexed.
pub const KIND_FILE: u8 = 0;
pub const KIND_DIR: u8 = 1;
pub const KIND_LINK: u8 = 2;
pub const KIND_CONFLICT: u8 = 3;
pub const KIND_MASK: u8 = 3;
/// A secret (sealed entry): its path only, never its content.
pub const SEALED: u8 = 4;
/// A plain file of at most [`MAX_TEXT_BYTES`]: its content is searched
/// (unless [`BINARY`]). Decided by the entry alone, so the shard's counts
/// follow from its tree.
pub const TEXT: u8 = 8;
/// A [`TEXT`] file whose content holds a NUL byte (or is not a blob): not
/// searched.
pub const BINARY: u8 = 16;

/// Most bytes of a file whose content is indexed (as a diff shows lines).
pub const MAX_TEXT_BYTES: u64 = 1 << 20;

/// One document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Doc {
    pub path: String,
    /// The entry's id (a blob, a secret's sealed object, a sealed folder…);
    /// zero in name segments.
    pub id: ObjectId,
    pub size: u64,
    pub flags: u8,
}

impl Doc {
    /// Is its content searched?
    pub fn searchable(&self) -> bool {
        self.flags & TEXT != 0 && self.flags & BINARY == 0
    }
}

/// Compare paths in tree order: component by component, as a walk of the
/// trees (sorted by name) meets them.
pub fn tree_cmp(a: &str, b: &str) -> Ordering {
    a.split('/').cmp(b.split('/'))
}

/// The trigram of three bytes, ASCII case folded.
fn gram(a: u8, b: u8, c: u8) -> u32 {
    (a.to_ascii_lowercase() as u32) << 16 | (b.to_ascii_lowercase() as u32) << 8 | c.to_ascii_lowercase() as u32
}

/// The distinct trigrams of `text`, sorted.
pub fn grams(text: &[u8]) -> Vec<u32> {
    let mut out: Vec<u32> = text.windows(3).map(|w| gram(w[0], w[1], w[2])).collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// A segment being built: documents in tree order.
#[derive(Default)]
pub struct Builder {
    docs: Vec<Doc>,
    dead: Vec<String>,
    grams: HashMap<u32, Vec<u32>>,
    /// Postings held (each a doc ordinal), and content bytes read.
    pub postings: usize,
    pub bytes: u64,
}

impl Builder {
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty() && self.dead.is_empty()
    }

    /// Documents added.
    pub fn len(&self) -> usize {
        self.docs.len()
    }

    /// Add `doc` with the trigrams of its text (sorted, distinct). Docs
    /// come in tree order.
    pub fn add(&mut self, doc: Doc, grams: &[u32]) {
        debug_assert!(self.docs.last().is_none_or(|d| tree_cmp(&d.path, &doc.path) == Ordering::Less));
        let n = self.docs.len() as u32;
        for g in grams {
            self.grams.entry(*g).or_default().push(n);
        }
        self.postings += grams.len();
        self.docs.push(doc);
    }

    /// A tombstone: `path` is gone from the shard.
    pub fn delete(&mut self, path: String) {
        self.dead.push(path);
    }

    pub fn encode(mut self) -> Vec<u8> {
        self.dead.sort_by(|a, b| tree_cmp(a, b));
        self.dead.dedup();
        let mut grams: Vec<(u32, Vec<u32>)> = self.grams.into_iter().collect();
        grams.sort_unstable_by_key(|g| g.0);
        encode(&self.docs, &self.dead, &grams)
    }
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend(v.to_le_bytes());
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_u32(out, s.len() as u32);
    out.extend(s.as_bytes());
}

fn put_varint(out: &mut Vec<u8>, mut v: u32) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn encode(docs: &[Doc], dead: &[String], grams: &[(u32, Vec<u32>)]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    put_u32(&mut out, docs.len() as u32);
    for d in docs {
        put_str(&mut out, &d.path);
        out.extend(d.id.0);
        out.extend(d.size.to_le_bytes());
        out.push(d.flags);
    }
    put_u32(&mut out, dead.len() as u32);
    for p in dead {
        put_str(&mut out, p);
    }
    let mut postings = Vec::new();
    let mut table = Vec::with_capacity(grams.len() * 16);
    for (g, list) in grams {
        let start = postings.len() as u32;
        let mut last = 0u32;
        for (i, d) in list.iter().enumerate() {
            put_varint(&mut postings, if i == 0 { *d } else { d - last });
            last = *d;
        }
        put_u32(&mut table, *g);
        put_u32(&mut table, start);
        put_u32(&mut table, postings.len() as u32 - start);
        put_u32(&mut table, list.len() as u32);
    }
    put_u32(&mut out, grams.len() as u32);
    out.extend(table);
    out.extend(postings);
    out
}

/// A decoded segment.
pub struct Segment {
    pub docs: Vec<Doc>,
    by_path: HashMap<String, u32>,
    pub dead: HashSet<String>,
    /// `(trigram, offset, length, count)`, sorted by trigram.
    grams: Vec<(u32, u32, u32, u32)>,
    postings: Vec<u8>,
    /// About the memory it holds.
    pub weight: usize,
}

fn corrupt() -> Error {
    Error::Other(anyhow::anyhow!("search segment: corrupt"))
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(corrupt());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn str(&mut self) -> Result<String> {
        let n = self.u32()? as usize;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| corrupt())
    }
}

impl Segment {
    pub fn decode(raw: &[u8]) -> Result<Segment> {
        let mut r = Reader(raw.strip_prefix(MAGIC).ok_or_else(corrupt)?);
        let n = r.u32()? as usize;
        let mut docs = Vec::with_capacity(n.min(raw.len() / 45));
        let mut weight = 0usize;
        for _ in 0..n {
            let path = r.str()?;
            let id = ObjectId(r.take(32)?.try_into().unwrap());
            let size = u64::from_le_bytes(r.take(8)?.try_into().unwrap());
            let flags = r.take(1)?[0];
            weight += 2 * path.len() + 120;
            docs.push(Doc { path, id, size, flags });
        }
        let nd = r.u32()? as usize;
        let mut dead = HashSet::with_capacity(nd.min(raw.len() / 4));
        for _ in 0..nd {
            let p = r.str()?;
            weight += p.len() + 48;
            dead.insert(p);
        }
        let ng = r.u32()? as usize;
        let mut grams = Vec::with_capacity(ng.min(raw.len() / 16));
        for _ in 0..ng {
            grams.push((r.u32()?, r.u32()?, r.u32()?, r.u32()?));
        }
        let postings = r.0.to_vec();
        for &(_, off, len, _) in &grams {
            if off as usize + len as usize > postings.len() {
                return Err(corrupt());
            }
        }
        let by_path = docs.iter().enumerate().map(|(i, d)| (d.path.clone(), i as u32)).collect();
        weight += grams.len() * 16 + postings.len() + 256;
        Ok(Segment {
            docs,
            by_path,
            dead,
            grams,
            postings,
            weight,
        })
    }

    /// Does this segment hold a document or a tombstone at `path` (so that
    /// every older segment's document there is dead)?
    pub fn shadows(&self, path: &str) -> bool {
        self.by_path.contains_key(path) || self.dead.contains(path)
    }

    /// The ordinal of the document at `path`.
    pub fn find(&self, path: &str) -> Option<u32> {
        self.by_path.get(path).copied()
    }

    /// How many documents hold trigram `g` (a cost estimate).
    pub fn count(&self, g: u32) -> usize {
        match self.grams.binary_search_by_key(&g, |e| e.0) {
            Ok(i) => self.grams[i].3 as usize,
            Err(_) => 0,
        }
    }

    /// The ordinals of the documents holding trigram `g`, sorted.
    pub fn postings(&self, g: u32) -> Vec<u32> {
        let Ok(i) = self.grams.binary_search_by_key(&g, |e| e.0) else { return Vec::new() };
        let (_, off, len, count) = self.grams[i];
        let mut out = Vec::with_capacity(count as usize);
        let bytes = &self.postings[off as usize..(off + len) as usize];
        let (mut v, mut shift, mut last) = (0u32, 0u32, 0u32);
        for &b in bytes {
            v |= ((b & 0x7f) as u32) << shift;
            if b & 0x80 == 0 {
                last = if out.is_empty() { v } else { last + v };
                out.push(last);
                v = 0;
                shift = 0;
            } else {
                shift += 7;
            }
        }
        out
    }

    /// Ordinals of the documents holding every trigram of `want` (sorted,
    /// distinct): `None` when `want` is empty (no narrowing).
    pub fn holding(&self, want: &[u32]) -> Option<Vec<u32>> {
        if want.is_empty() {
            return None;
        }
        // The rarest trigram first.
        let mut order: Vec<u32> = want.to_vec();
        order.sort_by_key(|g| self.count(*g));
        let mut set = self.postings(order[0]);
        for g in &order[1..] {
            if set.is_empty() {
                break;
            }
            let other = self.postings(*g);
            let mut j = 0;
            set.retain(|d| {
                while j < other.len() && other[j] < *d {
                    j += 1;
                }
                j < other.len() && other[j] == *d
            });
        }
        Some(set)
    }
}

/// Work a query does on postings and documents, checked against its
/// deadline every 4,096 steps (BUG-1232): not part of an answer's `work`
/// (its amount depends on how segments are laid out), only bounded by time.
pub struct Budget {
    pub deadline: std::time::Instant,
    steps: std::cell::Cell<u64>,
}

impl Budget {
    pub fn new(deadline: std::time::Instant) -> Budget {
        Budget {
            deadline,
            steps: std::cell::Cell::new(0),
        }
    }

    /// Count `n` steps; past the deadline, the query fails.
    pub fn step(&self, n: u64) -> Result<()> {
        let before = self.steps.get();
        self.steps.set(before + n);
        if (before >> 12) != ((before + n) >> 12) {
            self.check()?;
        }
        Ok(())
    }

    /// Fail if the deadline passed.
    pub fn check(&self) -> Result<()> {
        if std::time::Instant::now() > self.deadline {
            return Err(crate::query::graph::too_slow());
        }
        Ok(())
    }
}

/// The postings of one trigram, decoded as they are read.
pub struct Posts<'a> {
    bytes: &'a [u8],
    pos: usize,
    last: u32,
    first: bool,
}

impl Iterator for Posts<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        let (mut v, mut shift) = (0u32, 0u32);
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            self.pos += 1;
            v |= ((b & 0x7f) as u32) << shift;
            if b & 0x80 == 0 {
                self.last = if self.first { v } else { self.last + v };
                self.first = false;
                return Some(self.last);
            }
            shift += 7;
        }
        None
    }
}

impl Segment {
    /// The postings of trigram `g`, if any document holds it.
    pub fn posts(&self, g: u32) -> Option<Posts<'_>> {
        let i = self.grams.binary_search_by_key(&g, |e| e.0).ok()?;
        let (_, off, len, _) = self.grams[i];
        Some(Posts {
            bytes: &self.postings[off as usize..(off + len) as usize],
            pos: 0,
            last: 0,
            first: true,
        })
    }

    /// The ordinals of the documents at or under `dir` (`""`: all) whose
    /// path is after `after` in tree order (`""`: from the first): one
    /// range, since documents are in tree order and a folder's paths are
    /// next to each other in it.
    pub fn range(&self, dir: &str, after: &str) -> (u32, u32) {
        let (mut lo, mut hi) = (0usize, self.docs.len());
        if !dir.is_empty() {
            lo = self.docs.partition_point(|d| tree_cmp(&d.path, dir) == Ordering::Less);
            let under = |p: &str| p == dir || (p.len() > dir.len() && p.starts_with(dir) && p.as_bytes()[dir.len()] == b'/');
            hi = lo + self.docs[lo..].partition_point(|d| under(&d.path));
        }
        if !after.is_empty() {
            lo = lo.max(self.docs.partition_point(|d| tree_cmp(&d.path, after) != Ordering::Greater));
        }
        (lo as u32, hi.max(lo) as u32)
    }
}

/// The ordinals in `[lo, hi)` of the documents holding every trigram of a
/// set, in increasing order: the postings are intersected as they are
/// decoded (each list advanced to the largest head), so taking the first
/// `k` costs what reaching them costs, not every posting (BUG-1232).
pub struct Holding<'a> {
    lists: Vec<Posts<'a>>,
    heads: Vec<u32>,
    next: u32,
    lo: u32,
    hi: u32,
    started: bool,
    done: bool,
}

impl<'a> Holding<'a> {
    pub fn new(seg: &'a Segment, want: &[u32], lo: u32, hi: u32) -> Holding<'a> {
        let mut lists = Vec::with_capacity(want.len());
        let mut done = lo >= hi;
        for g in want {
            match seg.posts(*g) {
                Some(p) => lists.push(p),
                None => done = true,
            }
        }
        Holding {
            heads: vec![0; lists.len()],
            lists,
            next: lo,
            lo,
            hi,
            started: false,
            done,
        }
    }

    /// Advance list `i` to its first ordinal at or after `to`.
    fn advance(&mut self, i: usize, to: u32, b: &Budget) -> Result<Option<u32>> {
        let mut n = 0;
        while self.heads[i] < to {
            match self.lists[i].next() {
                Some(v) => self.heads[i] = v,
                None => {
                    b.step(n)?;
                    return Ok(None);
                }
            }
            n += 1;
        }
        b.step(n)?;
        Ok(Some(self.heads[i]))
    }

    pub fn next(&mut self, b: &Budget) -> Result<Option<u32>> {
        if self.done {
            return Ok(None);
        }
        if self.lists.is_empty() {
            // No trigram to narrow by: every document of the range.
            if self.next >= self.hi {
                self.done = true;
                return Ok(None);
            }
            self.next += 1;
            b.step(1)?;
            return Ok(Some(self.next - 1));
        }
        if !self.started {
            self.started = true;
            for i in 0..self.lists.len() {
                match self.lists[i].next() {
                    Some(v) => self.heads[i] = v,
                    None => {
                        self.done = true;
                        return Ok(None);
                    }
                }
                if self.advance(i, self.lo, b)?.is_none() {
                    self.done = true;
                    return Ok(None);
                }
            }
        } else {
            // Past the ordinal last returned.
            let past = self.heads[0] + 1;
            if self.advance(0, past, b)?.is_none() {
                self.done = true;
                return Ok(None);
            }
        }
        loop {
            let target = *self.heads.iter().max().expect("lists");
            if target >= self.hi {
                self.done = true;
                return Ok(None);
            }
            let mut all = true;
            for i in 0..self.lists.len() {
                match self.advance(i, target, b)? {
                    None => {
                        self.done = true;
                        return Ok(None);
                    }
                    Some(v) if v > target => {
                        all = false;
                        break;
                    }
                    Some(_) => {}
                }
            }
            if all {
                return Ok(Some(target));
            }
        }
    }
}

/// Merge consecutive segments `inputs` (oldest first) of one shard into
/// one: live documents only (a document is dropped when a newer input, or
/// `newer` — the segments after the inputs — shadows its path; in name
/// segments also when an equal path is kept already), and tombstones
/// unless `oldest` (the inputs include the shard's oldest segment, so
/// nothing older is left to shadow). Returns the encoding and how many
/// documents were dropped.
pub fn merge(inputs: &[Arc<Segment>], newer: &dyn Fn(&str) -> bool, oldest: bool) -> (Vec<u8>, u64) {
    let mut kept: Vec<(usize, u32)> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut dropped = 0u64;
    for (i, s) in inputs.iter().enumerate().rev() {
        for (o, d) in s.docs.iter().enumerate() {
            let shadowed = newer(&d.path) || inputs[i + 1..].iter().any(|n| n.shadows(&d.path)) || seen.contains(d.path.as_str());
            if shadowed {
                dropped += 1;
            } else {
                seen.insert(&d.path);
                kept.push((i, o as u32));
            }
        }
    }
    kept.sort_by(|a, b| tree_cmp(&inputs[a.0].docs[a.1 as usize].path, &inputs[b.0].docs[b.1 as usize].path));
    let mut map: Vec<Vec<Option<u32>>> = inputs.iter().map(|s| vec![None; s.docs.len()]).collect();
    let mut docs = Vec::with_capacity(kept.len());
    for (n, (i, o)) in kept.iter().enumerate() {
        map[*i][*o as usize] = Some(n as u32);
        docs.push(inputs[*i].docs[*o as usize].clone());
    }
    let mut grams: HashMap<u32, Vec<u32>> = HashMap::new();
    for (i, s) in inputs.iter().enumerate() {
        for &(g, _, _, _) in &s.grams {
            let list: Vec<u32> = s.postings(g).into_iter().filter_map(|o| map[i][o as usize]).collect();
            if !list.is_empty() {
                grams.entry(g).or_default().extend(list);
            }
        }
    }
    let mut grams: Vec<(u32, Vec<u32>)> = grams.into_iter().collect();
    for (_, l) in &mut grams {
        l.sort_unstable();
    }
    grams.sort_unstable_by_key(|g| g.0);
    let mut dead: Vec<String> = if oldest {
        Vec::new()
    } else {
        inputs.iter().flat_map(|s| s.dead.iter()).filter(|p| !seen.contains(p.as_str())).cloned().collect()
    };
    dead.sort_by(|a, b| tree_cmp(a, b));
    dead.dedup();
    (encode(&docs, &dead, &grams), dropped)
}

/// Decoded segments, by project and id, process-wide (they never change).
fn cache() -> &'static LruCache<Arc<Segment>> {
    static CACHE: OnceLock<LruCache<Arc<Segment>>> = OnceLock::new();
    CACHE.get_or_init(|| LruCache::new(256 << 20))
}

fn cache_key(project: i64, id: &ObjectId) -> ObjectId {
    let mut h = blake3::Hasher::new();
    h.update(b"search-segment");
    h.update(&project.to_le_bytes());
    h.update(&id.0);
    ObjectId(*h.finalize().as_bytes())
}

/// Segment `id` of `project`, from the cache or the store.
pub fn load(src: &crate::sync::Source, id: &ObjectId) -> Result<Arc<Segment>> {
    let k = cache_key(src.project, id);
    if let Some(s) = cache().get(&k) {
        return Ok(s);
    }
    let raw = src.raw(id)?;
    let s = Arc::new(Segment::decode(&raw)?);
    cache().insert(k, s.clone(), s.weight);
    Ok(s)
}

/// Forget decoded segments (the tests' restart).
pub fn clear_cache() {
    cache().clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(p: &str) -> Doc {
        Doc {
            path: p.into(),
            id: ObjectId([1; 32]),
            size: 3,
            flags: TEXT,
        }
    }

    #[test]
    fn tree_order_is_the_walk_order() {
        let mut v = vec!["a-c", "a/b", "a", "b", "a/b/c", "a.d"];
        v.sort_by(|a, b| tree_cmp(a, b));
        assert_eq!(v, vec!["a", "a/b", "a/b/c", "a-c", "a.d", "b"]);
    }

    #[test]
    fn segments_round_trip_and_merge() {
        let mut b = Builder::default();
        b.add(doc("a/x"), &grams(b"hello world"));
        b.add(doc("a/y"), &grams(b"Hello there"));
        b.delete("gone".into());
        let s1 = Arc::new(Segment::decode(&b.encode()).unwrap());
        assert_eq!(s1.holding(&grams(b"hel")).unwrap(), vec![0, 1]);
        assert_eq!(s1.holding(&grams(b"world")).unwrap(), vec![0]);
        assert!(s1.holding(&[]).is_none());
        assert!(s1.shadows("gone") && s1.shadows("a/x") && !s1.shadows("a/z"));
        let mut b = Builder::default();
        b.add(doc("a/x"), &grams(b"bye"));
        b.delete("a/y".into());
        let s2 = Arc::new(Segment::decode(&b.encode()).unwrap());
        let (raw, dropped) = merge(&[s1.clone(), s2.clone()], &|_| false, false);
        assert_eq!(dropped, 2);
        let m = Segment::decode(&raw).unwrap();
        assert_eq!(m.docs.len(), 1);
        assert_eq!(m.holding(&grams(b"bye")).unwrap(), vec![0]);
        assert!(m.holding(&grams(b"hello")).unwrap().is_empty());
        assert!(m.dead.contains("gone") && m.dead.contains("a/y"));
        let (raw, _) = merge(&[s1, s2], &|p| p == "a/x", true);
        let m = Segment::decode(&raw).unwrap();
        assert!(m.docs.is_empty() && m.dead.is_empty());
    }

    #[test]
    fn holding_streams_the_intersection() {
        let mut b = Builder::default();
        let texts = ["abcdef", "xyz", "abcxyz", "zzabc", "abc", "nothing"];
        let paths = ["a", "a/b", "a/b/c", "a-c", "b", "c"];
        for (p, t) in paths.iter().zip(texts) {
            b.add(doc(p), &grams(t.as_bytes()));
        }
        let s = Segment::decode(&b.encode()).unwrap();
        let budget = Budget::new(std::time::Instant::now() + std::time::Duration::from_secs(60));
        let all = |want: &[u32], lo: u32, hi: u32| {
            let mut h = Holding::new(&s, want, lo, hi);
            let mut out = Vec::new();
            while let Some(o) = h.next(&budget).unwrap() {
                out.push(o);
            }
            out
        };
        let n = s.docs.len() as u32;
        assert_eq!(all(&grams(b"abc"), 0, n), s.holding(&grams(b"abc")).unwrap());
        assert_eq!(all(&grams(b"abcxyz"), 0, n), vec![2]);
        assert_eq!(all(&grams(b"abc"), 1, 3), vec![2]);
        assert_eq!(all(&[], 2, 4), vec![2, 3]);
        assert!(all(&grams(b"qqq"), 0, n).is_empty());
        assert_eq!(s.range("a", ""), (0, 3));
        assert_eq!(s.range("a/b", ""), (1, 3));
        assert_eq!(s.range("", "a/b"), (2, n));
        assert_eq!(s.range("a", "a/b/c"), (3, 3));
        assert_eq!(s.range("missing", ""), (6, 6));
    }

    #[test]
    fn corrupt_segments_are_refused() {
        let mut b = Builder::default();
        b.add(doc("a"), &grams(b"abcdef"));
        let raw = b.encode();
        for n in [0, MAGIC.len(), MAGIC.len() + 3, raw.len() - 1] {
            assert!(Segment::decode(&raw[..n]).is_err(), "{n}");
        }
        assert!(Segment::decode(b"veil-derived search-segment 1\n\xff\xff\xff\xff").is_err());
    }
}
