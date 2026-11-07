//! Search (milestone S15; `docs/design/server/phase-3-server-history.md`
//! §3.5): code and names, answered per viewer.
//!
//! | Route (`/v1/projects/{p}/q/…`) | Answers |
//! |---|---|
//! | `GET search?q=&rev=&kind=&path=&lang=&n=&after=` | ranked files: by content (`kind=code`, the default) at a branch tip, or by name over every path the project's history held (`kind=path`) |
//! | `GET grep?pattern=&rev=&i=&path=&n=&after=` | the lines matching a regular expression, file by file in tree order: through the index at a branch tip, by a scan of the viewer's tree at any other revision |
//!
//! **Per viewer, by construction.** The index ([`index`]) is sharded by
//! access line; a query opens only the shards of the lines the viewer
//! reads. Every number in an answer is computed from those shards' live
//! documents alone: the hits, `files` (how many matched), `complete`
//! (whether every candidate was read), the ranking's statistics (how many
//! documents there are, their average length, how many hold each word),
//! the order, the pages and `work` (the files and trees read). A copy of
//! the project holding only the viewer's projected history gives the same
//! answer, byte for byte (`search_projection_equivalence`): nothing hidden
//! is found, counted, ranked or paid for in a way the answer shows.
//!
//! **What the work does not show** (the stated bound): the postings read,
//! which include documents dead in the viewer's shards (old versions of
//! readable files, bounded by compaction to half the live ones) and
//! depend on how the shards' segments happen to be laid out (by landing
//! batches); the number of shards the viewer reads; and the segments'
//! loading. None of them depends on hidden content: a hidden file is in a
//! shard the viewer never opens.
//!
//! **Secrets** are found by path, never by content (their documents have
//! none). **Embargo lines** are never indexed, and a withheld revision is
//! no revision. Every query has a deadline (2 s), past which it fails
//! (never answers less), and bounds on what it reads, a function of the
//! viewer's data, so the copy cuts at the same place.

pub mod index;
pub mod pattern;
pub mod segment;

use std::{
    cell::Cell,
    cmp::Reverse,
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use veil_core::{object::EntryKind, ObjectId};

use self::{
    index::{flags_of, identity, read_state, text_of, Shard, CODE, NAMES},
    pattern::{extensions, has_extension, Pattern, Terms},
    segment::{tree_cmp, Segment, TEXT},
};
use crate::{
    auth::Caller,
    derive::lines::Lines,
    error::{Error, Result},
    query::{
        self,
        graph::{self, blocking, too_slow, G},
        trees::{clean_path, Trees},
        Ask,
    },
    sync::Source,
    Hub, HubState,
};

/// The bounds of one query.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Most results of a ranked page.
    pub results: usize,
    /// Most candidate files a ranked code search reads, and bytes.
    pub confirm_files: usize,
    pub confirm_bytes: u64,
    /// Most candidate paths a name search checks.
    pub names: usize,
    /// Lines shown per ranked result.
    pub lines: usize,
    /// Most files a grep page reads, and bytes.
    pub grep_files: usize,
    pub grep_bytes: u64,
    /// Matching lines shown per file of a grep.
    pub grep_lines: usize,
    /// About the most bytes of lines a page shows.
    pub page_bytes: usize,
    /// Most bytes of one line shown.
    pub line_bytes: usize,
    pub deadline: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            results: 100,
            confirm_files: 4_000,
            confirm_bytes: 32 << 20,
            names: 100_000,
            lines: 5,
            grep_files: 20_000,
            grep_bytes: 256 << 20,
            grep_lines: 1_000,
            page_bytes: 8 << 20,
            line_bytes: 512,
            deadline: Duration::from_secs(2),
        }
    }
}

/// The branch's index is not built yet under the accepted policy (a new
/// branch, a new policy): it is being built; the caller tries again.
pub fn indexing() -> Error {
    Error::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "indexing",
        "this branch is being indexed for search; try again in a few seconds",
    )
}

fn parse_id(s: &str) -> Option<ObjectId> {
    (s.len() == 64).then(|| ObjectId::from_hex(s).ok()).flatten()
}

/// Reads counted as work, with the deadline.
struct Work {
    n: Cell<u64>,
    deadline: Instant,
}

impl Work {
    fn tick(&self) -> Result<()> {
        self.n.set(self.n.get() + 1);
        if Instant::now() > self.deadline {
            return Err(too_slow());
        }
        Ok(())
    }
}

fn under(path: &str, dir: &str) -> bool {
    dir.is_empty() || path == dir || (path.len() > dir.len() && path.starts_with(dir) && path.as_bytes()[dir.len()] == b'/')
}

/// A line as answers show it: lossy UTF-8, at most `max` bytes.
fn shown(line: &[u8], max: usize) -> String {
    let s = String::from_utf8_lossy(line);
    if s.len() <= max {
        return s.into_owned();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// The shards of one viewer, opened: each with its segments, oldest first.
struct Opened(Vec<(Shard, Vec<Arc<Segment>>)>);

impl Opened {
    fn open(src: &Source, shards: BTreeMap<String, Shard>) -> Result<Opened> {
        let mut out = Vec::new();
        for (_, s) in shards {
            let segs = s
                .segments
                .iter()
                .map(|r| segment::load(src, &ObjectId::from_hex(&r.id).map_err(|e| Error::Other(anyhow::anyhow!("{e}")))?))
                .collect::<Result<Vec<_>>>()?;
            out.push((s, segs));
        }
        Ok(Opened(out))
    }

    /// Is the code document at `path` live in one of the shards?
    fn holds(&self, path: &str) -> bool {
        self.0.iter().any(|(_, segs)| {
            for s in segs.iter().rev() {
                if s.find(path).is_some() {
                    return true;
                }
                if s.dead.contains(path) {
                    return false;
                }
            }
            false
        })
    }

    /// The live documents of each segment holding every trigram of each
    /// of `want` (one set per entry; all documents for an empty one) that
    /// `keep` accepts: `(segment, per entry the ordinals)`, walked shard by
    /// shard.
    fn each(&self, want: &[Vec<u32>], keep: &dyn Fn(&segment::Doc) -> bool, mut f: impl FnMut(&Segment, Vec<Vec<u32>>) -> Result<()>) -> Result<()> {
        for (_, segs) in &self.0 {
            for (i, seg) in segs.iter().enumerate() {
                let newer = &segs[i + 1..];
                let mut live: HashMap<u32, bool> = HashMap::new();
                let mut alive = |o: u32| -> bool {
                    *live.entry(o).or_insert_with(|| {
                        let d = &seg.docs[o as usize];
                        keep(d) && !newer.iter().any(|n| n.shadows(&d.path))
                    })
                };
                let sets: Vec<Vec<u32>> = want
                    .iter()
                    .map(|g| {
                        let base = seg.holding(g).unwrap_or_else(|| (0..seg.docs.len() as u32).collect());
                        base.into_iter().filter(|o| alive(*o)).collect()
                    })
                    .collect();
                f(seg, sets)?;
            }
        }
        Ok(())
    }
}

/// The intersection of sorted sets.
fn intersect(sets: &[Vec<u32>]) -> Vec<u32> {
    let Some(first) = sets.first() else { return Vec::new() };
    let mut out = first.clone();
    for s in &sets[1..] {
        let have: HashSet<u32> = s.iter().copied().collect();
        out.retain(|o| have.contains(o));
    }
    out
}

/// The branch a search is for: a branch name (the default one if none);
/// a snapshot id is refused (search covers branch tips; `grep -r` scans).
fn branch_of(ask: &Ask, rev: Option<&str>) -> Result<String> {
    let b = rev.unwrap_or(&ask.project.default_branch).to_string();
    if parse_id(&b).is_some() {
        return Err(Error::bad_request("search covers branch tips: name a branch (grep scans other revisions)"));
    }
    Ok(b)
}

/// The viewer's readable shards of an index, if it is built under the
/// accepted policy; otherwise it is (re)built in the background and the
/// answer is `None`.
async fn shards(hub: &Arc<Hub>, ask: &Ask, kind: &'static str, branch: &str) -> Result<Option<(String, BTreeMap<String, Shard>)>> {
    let lines = Lines::new(&ask.project.policy);
    let ident = identity(&lines);
    let keys = lines.readable(&ask.project.view(&ask.viewer));
    let b = branch.to_string();
    let (head, shards) = blocking(hub, ask.project.id, move |cx| read_state(cx, &cx.hub().db, kind, &b, Some(&keys))).await?;
    match head {
        Some(h) if h.lines == ident => Ok(Some((h.snapshot, shards))),
        _ => {
            index::landed(hub, ask.project.id, vec![branch.to_string()]);
            Ok(None)
        }
    }
}

// ---- search ----------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize)]
pub struct SearchParams {
    pub q: Option<String>,
    pub rev: Option<String>,
    pub kind: Option<String>,
    pub path: Option<String>,
    pub lang: Option<String>,
    pub n: Option<usize>,
    pub after: Option<String>,
}

/// BM25's constants, and the weight of a word in the file's name.
const K1: f64 = 1.2;
const B: f64 = 0.75;
const NAME_BOOST: f64 = 1.5;

fn parse_cursor(s: &str) -> Result<(i64, String)> {
    let bad = || Error::bad_request("invalid cursor");
    let (score, path) = s.split_once(':').ok_or_else(bad)?;
    Ok((score.parse().map_err(|_| bad())?, path.to_string()))
}

/// One ranked hit.
struct Hit {
    path: String,
    score: i64,
    v: Value,
}

/// Order hits by score, then path; the page after `after`.
fn page(mut hits: Vec<Hit>, after: Option<(i64, String)>, n: usize) -> (Vec<Value>, Option<String>) {
    hits.sort_by(|a, b| Reverse(a.score).cmp(&Reverse(b.score)).then_with(|| tree_cmp(&a.path, &b.path)));
    // The first hit ordered after the cursor's (score, path).
    let start = match &after {
        Some((score, path)) => hits
            .iter()
            .position(|h| Reverse(h.score).cmp(&Reverse(*score)).then_with(|| tree_cmp(&h.path, path)) == std::cmp::Ordering::Greater)
            .unwrap_or(hits.len()),
        None => 0,
    };
    let rest = &hits[start..];
    let next = (rest.len() > n).then(|| format!("{}:{}", rest[n - 1].score, rest[n - 1].path));
    (rest.iter().take(n).map(|h| h.v.clone()).collect(), next)
}

/// A ranked search.
pub async fn search(hub: &Arc<Hub>, ask: &Ask, q: SearchParams, limits: Limits) -> Result<Value> {
    let deadline = Instant::now() + limits.deadline;
    let text = q.q.clone().unwrap_or_default();
    let terms = Terms::parse(&text)?;
    let dir = clean_path(q.path.as_deref().unwrap_or(""))?;
    let exts = q.lang.as_deref().map(extensions).transpose()?;
    let names = match q.kind.as_deref().unwrap_or("code") {
        "code" => false,
        "path" => true,
        _ => return Err(Error::bad_request("kind is `code` or `path`")),
    };
    let n = q.n.unwrap_or(20).clamp(1, limits.results);
    let after = q.after.as_deref().map(parse_cursor).transpose()?;
    let branch = branch_of(ask, q.rev.as_deref())?;
    query::resolve(hub, ask, &branch, deadline).await?;
    let Some((covered, code)) = shards(hub, ask, CODE, &branch).await? else { return Err(indexing()) };
    let name_shards = if names {
        match shards(hub, ask, NAMES, "").await? {
            Some((_, s)) => Some(s),
            None => return Err(indexing()),
        }
    } else {
        None
    };
    let covered = ObjectId::from_hex(&covered).map_err(|e| Error::Other(anyhow::anyhow!("{e}")))?;
    let snapshot = graph::ensure(hub, &ask.project, &ask.viewer, &[covered], Some(deadline)).await?[0];
    let version = ask.policy_version;
    blocking(hub, ask.project.id, move |cx| {
        let src = &cx.src;
        let work = Work { n: Cell::new(0), deadline };
        let keep_path = |p: &str| under(p, &dir) && exts.is_none_or(|e| has_extension(p, e));
        let code = Opened::open(src, code)?;
        let (hits, files, complete) = match name_shards {
            None => code_hits(src, &code, &terms, &keep_path, &work, &limits)?,
            Some(ns) => name_hits(&Opened::open(src, ns)?, &code, &terms, &keep_path, &work, &limits)?,
        };
        let (results, next) = page(hits, after, n);
        Ok(json!({
            "schema": "veil.search/1",
            "kind": if names { "path" } else { "code" },
            "rev": branch,
            "snapshot_id": snapshot.hex(),
            "query": text,
            "files": files,
            "complete": complete,
            "results": results,
            "truncated": next.is_some(),
            "next": next,
            "policy_version": version,
            "work": work.n.get(),
        }))
    })
    .await
}

/// Code hits: candidates (live documents holding every word's trigrams) in
/// tree order, read until the bounds, scored by BM25 over the viewer's
/// shards.
fn code_hits(src: &Source, code: &Opened, terms: &Terms, keep_path: &dyn Fn(&str) -> bool, work: &Work, limits: &Limits) -> Result<(Vec<Hit>, usize, bool)> {
    let docs: i64 = code.0.iter().map(|(s, _)| s.text_docs).sum();
    let bytes: i64 = code.0.iter().map(|(s, _)| s.text_bytes).sum();
    let mut df = vec![0u64; terms.words.len()];
    let mut cands: Vec<(String, ObjectId, u64)> = Vec::new();
    code.each(&terms.grams, &|d| d.searchable(), |seg, sets| {
        for (t, s) in sets.iter().enumerate() {
            df[t] += s.len() as u64;
        }
        for o in intersect(&sets) {
            let d = &seg.docs[o as usize];
            if keep_path(&d.path) {
                cands.push((d.path.clone(), d.id, d.size));
            }
        }
        Ok(())
    })?;
    cands.sort_by(|a, b| tree_cmp(&a.0, &b.0));
    let n = docs.max(0) as f64;
    let avg = if docs > 0 { (bytes as f64 / docs as f64).max(1.0) } else { 1.0 };
    let idf: Vec<f64> = df.iter().map(|d| (1.0 + (n - *d as f64 + 0.5) / (*d as f64 + 0.5)).ln()).collect();
    let (mut read, mut read_bytes, mut complete) = (0usize, 0u64, true);
    let mut hits = Vec::new();
    for (path, id, size) in cands {
        if read == limits.confirm_files || read_bytes + size > limits.confirm_bytes {
            complete = false;
            break;
        }
        work.tick()?;
        read += 1;
        read_bytes += size;
        let Some(content) = text_of(src, &id)? else { continue };
        let lower = content.to_ascii_lowercase();
        let tf: Vec<u64> = (0..terms.words.len()).map(|t| terms.count(t, &lower)).collect();
        if tf.contains(&0) {
            continue;
        }
        let name = path.rsplit('/').next().unwrap_or(&path).to_ascii_lowercase();
        let len = content.len() as f64;
        let mut score = 0.0;
        for t in 0..terms.words.len() {
            let f = tf[t] as f64;
            score += idf[t] * f * (K1 + 1.0) / (f + K1 * (1.0 - B + B * len / avg));
            if terms.count(t, name.as_bytes()) > 0 {
                score += idf[t] * NAME_BOOST;
            }
        }
        let (mut matches, mut lines) = (0u64, Vec::new());
        for (no, (line, low)) in content.split(|b| *b == b'\n').zip(lower.split(|b| *b == b'\n')).enumerate() {
            if terms.any(low) {
                matches += 1;
                if lines.len() < limits.lines {
                    lines.push(json!({ "line": no + 1, "text": shown(line, limits.line_bytes) }));
                }
            }
        }
        let micro = (score * 1e6).round() as i64;
        hits.push(Hit {
            v: json!({ "path": path, "score": micro as f64 / 1e6, "size": size, "matches": matches, "lines": lines }),
            path,
            score: micro,
        });
    }
    let files = hits.len();
    Ok((hits, files, complete))
}

/// Name hits: every path ever held (deduplicated) whose trigrams hold every
/// word's, checked until the bound; a word in the file's name weighs more,
/// a path at the revision more still, a long path less.
fn name_hits(names: &Opened, code: &Opened, terms: &Terms, keep_path: &dyn Fn(&str) -> bool, work: &Work, limits: &Limits) -> Result<(Vec<Hit>, usize, bool)> {
    let mut cands: HashSet<String> = HashSet::new();
    names.each(&terms.grams, &|_| true, |seg, sets| {
        for o in intersect(&sets) {
            let p = &seg.docs[o as usize].path;
            if keep_path(p) {
                cands.insert(p.clone());
            }
        }
        Ok(())
    })?;
    let mut cands: Vec<String> = cands.into_iter().collect();
    cands.sort_by(|a, b| tree_cmp(a, b));
    let mut complete = true;
    let mut hits = Vec::new();
    for (i, path) in cands.into_iter().enumerate() {
        if i == limits.names {
            complete = false;
            break;
        }
        work.tick()?;
        let lower = path.to_ascii_lowercase();
        if (0..terms.words.len()).any(|t| terms.count(t, lower.as_bytes()) == 0) {
            continue;
        }
        let name = lower.rsplit('/').next().unwrap_or(&lower);
        let at_rev = code.holds(&path);
        let mut score: i64 = (0..terms.words.len()).map(|t| if terms.count(t, name.as_bytes()) > 0 { 3_000_000 } else { 1_000_000 }).sum();
        if at_rev {
            score += 2_000_000;
        }
        score -= path.len().min(999) as i64 * 1_000;
        hits.push(Hit {
            v: json!({ "path": path, "score": score as f64 / 1e6, "at_rev": at_rev }),
            path,
            score,
        });
    }
    let files = hits.len();
    Ok((hits, files, complete))
}

// ---- grep --------------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize)]
pub struct GrepParams {
    pub pattern: String,
    pub rev: Option<String>,
    pub i: Option<bool>,
    pub path: Option<String>,
    pub n: Option<usize>,
    pub after: Option<String>,
}

/// One grep page being filled.
struct GrepPage<'l> {
    limits: &'l Limits,
    files: Vec<Value>,
    want: usize,
    read: usize,
    read_bytes: u64,
    bytes: usize,
    last: Option<String>,
    full: bool,
}

impl GrepPage<'_> {
    /// Would reading a file of `size` bytes pass a bound? Then the page is
    /// full, and ends after the last file examined.
    fn stop(&mut self, size: u64) -> bool {
        if self.files.len() == self.want || self.bytes >= self.limits.page_bytes || self.read == self.limits.grep_files || self.read_bytes + size > self.limits.grep_bytes {
            self.full = true;
        }
        self.full
    }

    fn examine(&mut self, path: &str, content: Option<Vec<u8>>, size: u64, re: &regex::bytes::Regex) {
        self.read += 1;
        self.read_bytes += size;
        self.last = Some(path.to_string());
        let Some(content) = content else { return };
        let (mut matches, mut lines) = (0u64, Vec::new());
        for (no, line) in content.split(|b| *b == b'\n').enumerate() {
            if re.is_match(line) {
                matches += 1;
                if lines.len() < self.limits.grep_lines {
                    let t = shown(line, self.limits.line_bytes);
                    self.bytes += t.len();
                    lines.push(json!({ "line": no + 1, "text": t }));
                }
            }
        }
        if matches > 0 {
            let mut f = json!({ "path": path, "matches": matches, "lines": lines });
            if matches as usize > self.limits.grep_lines {
                f["lines_truncated"] = json!(true);
            }
            self.files.push(f);
        }
    }
}

/// Lines matching a regular expression in a revision.
pub async fn grep(hub: &Arc<Hub>, ask: &Ask, q: GrepParams, limits: Limits) -> Result<Value> {
    let deadline = Instant::now() + limits.deadline;
    let pat = Pattern::parse(&q.pattern, q.i.unwrap_or(false))?;
    let dir = clean_path(q.path.as_deref().unwrap_or(""))?;
    let after = clean_path(q.after.as_deref().unwrap_or(""))?;
    let want = q.n.unwrap_or(100).clamp(1, 1_000);
    let rev = q.rev.clone().unwrap_or_else(|| ask.project.default_branch.clone());
    let resolved = query::resolve(hub, ask, &rev, deadline).await?;
    // At a branch tip whose index is built, the index narrows the files
    // read; anywhere else, the viewer's tree is scanned.
    let indexed = if parse_id(&rev).is_none() {
        match shards(hub, ask, CODE, &rev).await? {
            Some((covered, s)) => {
                let covered = ObjectId::from_hex(&covered).map_err(|e| Error::Other(anyhow::anyhow!("{e}")))?;
                Some((graph::ensure(hub, &ask.project, &ask.viewer, &[covered], Some(deadline)).await?[0], s))
            }
            None => None,
        }
    } else {
        None
    };
    let (vk, project, viewer, version) = (ask.project.view(&ask.viewer).key(), ask.project.clone(), ask.viewer.clone(), ask.policy_version);
    let pattern_text = q.pattern.clone();
    blocking(hub, project.id, move |cx| {
        let mut page = GrepPage {
            limits: &limits,
            files: Vec::new(),
            want,
            read: 0,
            read_bytes: 0,
            bytes: 0,
            last: None,
            full: false,
        };
        let (snapshot, work) = match indexed {
            Some((snapshot, shards)) => {
                let work = Work { n: Cell::new(0), deadline };
                let code = Opened::open(&cx.src, shards)?;
                let mut cands: Vec<(String, ObjectId, u64)> = Vec::new();
                let keep = |d: &segment::Doc| d.searchable() && under(&d.path, &dir) && (after.is_empty() || tree_cmp(&d.path, &after) == std::cmp::Ordering::Greater);
                code.each(std::slice::from_ref(&pat.grams), &keep, |seg, sets| {
                    cands.extend(sets[0].iter().map(|o| {
                        let d = &seg.docs[*o as usize];
                        (d.path.clone(), d.id, d.size)
                    }));
                    Ok(())
                })?;
                cands.sort_by(|a, b| tree_cmp(&a.0, &b.0));
                for (path, id, size) in cands {
                    if page.stop(size) {
                        break;
                    }
                    work.tick()?;
                    page.examine(&path, text_of(&cx.src, &id)?, size, &pat.regex);
                }
                (snapshot, work.n.get())
            }
            None => {
                let view = project.view(&viewer);
                let g = G::new(cx, &vk, Some(deadline));
                let t = Trees::new(&g, &view);
                let root = t.root_of(&*g.get(&resolved)?)?;
                let start = if dir.is_empty() {
                    Some((root, None))
                } else {
                    t.entry_at(root, &dir)?.map(|e| (e.id, Some(e)))
                };
                if let Some((id, entry)) = start {
                    match entry {
                        Some(e) if e.kind != EntryKind::Dir => {
                            if after.is_empty() || tree_cmp(&dir, &after) == std::cmp::Ordering::Greater {
                                scan_leaf(&t, &dir, &e, &mut page, &pat.regex)?;
                            }
                        }
                        _ => scan(&t, &dir, id, &after, &mut page, &pat.regex, 0)?,
                    }
                }
                let w = g.work();
                (resolved, w)
            }
        };
        let next = if page.full { page.last.clone() } else { None };
        Ok(json!({
            "schema": "veil.hub-grep/1",
            "rev": rev,
            "snapshot_id": snapshot.hex(),
            "pattern": pattern_text,
            "files": page.files,
            "truncated": next.is_some(),
            "next": next,
            "policy_version": version,
            "work": work,
        }))
    })
    .await
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

fn scan_leaf(t: &Trees, path: &str, e: &veil_core::TreeEntry, page: &mut GrepPage, re: &regex::bytes::Regex) -> Result<()> {
    if flags_of(e) & TEXT == 0 || page.stop(e.size) {
        return Ok(());
    }
    let (blob, bytes) = t.content(&e.id)?;
    let text = (blob && !bytes.contains(&0) && bytes.len() as u64 <= segment::MAX_TEXT_BYTES).then_some(bytes);
    page.examine(path, text, e.size, re);
    Ok(())
}

/// Walk folder `id` at `dir` of the viewer's tree in tree order, after
/// `after`, examining its text files until the page is full.
fn scan(t: &Trees, dir: &str, id: ObjectId, after: &str, page: &mut GrepPage, re: &regex::bytes::Regex, depth: usize) -> Result<()> {
    if depth > veil_core::tree::MAX_TREE_DEPTH {
        return Ok(());
    }
    let Some(tree) = t.tree(&id)? else { return Ok(()) };
    let mut entries: Vec<&veil_core::TreeEntry> = tree.entries.iter().collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    for e in entries {
        if page.full {
            return Ok(());
        }
        let p = join(dir, &e.name);
        let later = after.is_empty() || tree_cmp(&p, after) == std::cmp::Ordering::Greater;
        if e.kind == EntryKind::Dir {
            // A folder before the cursor is skipped, unless the cursor is
            // inside it.
            if later || after.starts_with(&format!("{p}/")) {
                scan(t, &p, e.id, after, page, re, depth + 1)?;
            }
        } else if later {
            scan_leaf(t, &p, e, page, re)?;
        }
    }
    Ok(())
}

// ---- routes --------------------------------------------------------------------------------

pub async fn search_route(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Query(q): Query<SearchParams>) -> Result<Json<Value>> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    Ok(Json(search(&hub, &ask, q, Limits::default()).await?))
}

pub async fn grep_route(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Query(q): Query<GrepParams>) -> Result<Json<Value>> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    Ok(Json(grep(&hub, &ask, q, Limits::default()).await?))
}
