//! Building the search index (milestone S15): derived data, computed on
//! real history (the server is trusted with code), read per viewer.
//!
//! **Two indexes, sharded by access line** (S12's line keys,
//! `derive::lines`): a file's document is in the shard of the line that
//! decides its path, so a viewer opens exactly the shards of the lines
//! they read.
//! * **code** (per branch): every file at the branch tip, with the
//!   trigrams of its content when it is plain text of at most 1 MiB. A
//!   secret's (sealed entry's) document holds its path only: the server
//!   holds ciphertext and never decodes it.
//! * **names** (per project): every path any snapshot of any branch ever
//!   held, with the trigrams of the path.
//!
//! **Incremental.** A branch's code index moves from the snapshot it
//! covers to the new tip by the diff of their trees: one new segment per
//! shard the diff touched (more, if it is large), holding the new
//! documents and tombstones for deleted paths. A new branch starts from
//! the default branch's segments (shared objects). The names index walks
//! the snapshots the new tip brought (`rev_list`: those not below the
//! branch's last walked tip, nor the default branch's) and adds the paths
//! each one introduced (its S12 changed-paths object).
//!
//! **Embargo lines are never indexed:** a withheld tip is skipped (the
//! index stays where it was), and nothing walked is on an embargo line.
//!
//! **Policy changes.** A shard is named by its line key, which names the
//! set of paths the line decides: a new policy keeps every shard whose key
//! it keeps, builds the others from the tip tree (code) or from every old
//! name (names), and drops the rest. Until a branch's index is built
//! under the accepted policy, queries answer `indexing` (never a result
//! outside the new access).
//!
//! **Bounded.** A segment is written once it holds 32 MiB of content, 4
//! million postings or 100,000 documents; segments are merged when the
//! newest two are of similar size (sizes stay geometric), when a shard
//! has more than 64, and a shard is rewritten when more of its documents
//! are dead than half its live ones; a merge's inputs stay under 64 MiB,
//! and a rewrite holds one group of them and the shard's paths.
//!
//! **Consistent.** Segments are immutable objects (content-addressed,
//! written before their rows); a head row and its shards' rows change in
//! one transaction, which compares and swaps the head's version: two
//! servers updating at once never mix states (the loser starts again), and
//! readers read the head, the shards, then the head again.

use std::{
    collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet},
    sync::{Arc, Mutex, OnceLock},
};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use veil_core::{
    hub::project::empty_tree_id,
    object::{EntryKind, Object, TreeEntry},
    ObjectId,
};

use super::segment::{self, grams, tree_cmp, Builder, Doc, Segment, BINARY, KIND_CONFLICT, KIND_DIR, KIND_FILE, KIND_LINK, MAX_TEXT_BYTES, SEALED, TEXT};
use crate::{
    derive::{
        changes::{self, Changed, MANY, NONE, WITHHELD},
        graph::{Graph, FLAG_EMBARGO_LINE},
        lines::Lines,
        Cx,
    },
    error::{Error, Result},
    sync::{root_snapshot_id, Source},
    Hub,
};

pub const CODE: &str = "code";
pub const NAMES: &str = "names";
/// How far each branch's history was walked for names.
pub const WALK: &str = "walk";

/// A segment is written once it holds this much content, postings or
/// documents.
pub const FLUSH_BYTES: u64 = 32 << 20;
pub const FLUSH_POSTINGS: usize = 4 << 20;
pub const FLUSH_DOCS: usize = 100_000;
/// Most encoded bytes a merge writes (and so its inputs hold).
pub const MERGE_CAP: u64 = 64 << 20;
/// Most segments a shard keeps before its smallest neighbours merge.
pub const MAX_SEGMENTS: usize = 64;
/// Names gathered by a walk before they are written as segments.
const NAMES_HELD: usize = 500_000;
/// Index updates at once in a server process.
const UPDATERS: usize = 2;

/// One segment of a shard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegRef {
    pub id: String,
    pub bytes: u64,
}

/// A shard's row: its segments (oldest first) and its live counts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shard {
    pub segments: Vec<SegRef>,
    /// Live documents (code; names count duplicates).
    pub docs: i64,
    /// Live documents whose entry makes them text ([`TEXT`]), and their bytes.
    pub text_docs: i64,
    pub text_bytes: i64,
    /// Documents replaced or deleted and still in a segment.
    pub dead: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub snapshot: String,
    pub lines: String,
    pub version: i64,
}

/// What one update did (the tests and the benchmark read it).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub branches: Vec<String>,
    pub segments: usize,
    pub segment_bytes: u64,
    pub docs: usize,
    pub content_bytes: u64,
    pub merges: usize,
    pub walked: usize,
}

/// The identity of an accepted policy's lines: an index built under
/// another answers nothing.
pub fn identity(lines: &Lines) -> String {
    let mut h = blake3::Hasher::new_derive_key("veil 2026 hub search lines v1");
    for k in lines.all() {
        h.update(k.as_bytes());
        h.update(b"\n");
    }
    hex::encode(&h.finalize().as_bytes()[..16])
}

fn bad(e: impl std::fmt::Display) -> Error {
    Error::Other(anyhow::anyhow!("search index: {e}"))
}

fn oid(s: &str) -> Result<ObjectId> {
    ObjectId::from_hex(s).map_err(bad)
}

// ---- rows -------------------------------------------------------------------------

pub fn read_head(cx: &Cx, pool: &PgPool, kind: &str, branch: &str) -> Result<Option<Head>> {
    let row: Option<(String, String, i64)> = cx.db(|| {
        sqlx::query_as("SELECT snapshot, lines, version FROM search_heads WHERE project_id = $1 AND kind = $2 AND branch = $3")
            .bind(cx.project())
            .bind(kind)
            .bind(branch)
            .fetch_optional(pool)
    })?;
    Ok(row.map(|(snapshot, lines, version)| Head { snapshot, lines, version }))
}

/// The shards of `(kind, branch)`: those of `keys`, or all.
fn read_shards(cx: &Cx, pool: &PgPool, kind: &str, branch: &str, keys: Option<&[String]>) -> Result<BTreeMap<String, Shard>> {
    let all = keys.is_none();
    let keys: Vec<String> = keys.map(|k| k.to_vec()).unwrap_or_default();
    let rows = cx.db(|| {
        sqlx::query(
            "SELECT line_key, segments, docs, text_docs, text_bytes, dead FROM search_shards \
             WHERE project_id = $1 AND kind = $2 AND branch = $3 AND ($4 OR line_key = ANY($5))",
        )
        .bind(cx.project())
        .bind(kind)
        .bind(branch)
        .bind(all)
        .bind(&keys)
        .fetch_all(pool)
    })?;
    let mut out = BTreeMap::new();
    for r in rows {
        let segs: String = r.get(1);
        out.insert(
            r.get::<String, _>(0),
            Shard {
                segments: serde_json::from_str(&segs).map_err(bad)?,
                docs: r.get(2),
                text_docs: r.get(3),
                text_bytes: r.get(4),
                dead: r.get(5),
            },
        );
    }
    Ok(out)
}

/// A head and its shards as of one committed write: the head is read
/// before and after the shards, and again until both agree.
pub fn read_state(cx: &Cx, pool: &PgPool, kind: &str, branch: &str, keys: Option<&[String]>) -> Result<(Option<Head>, BTreeMap<String, Shard>)> {
    for _ in 0..100 {
        let before = read_head(cx, pool, kind, branch)?;
        let shards = read_shards(cx, pool, kind, branch, keys)?;
        let after = read_head(cx, pool, kind, branch)?;
        if before == after {
            return Ok((after, shards));
        }
    }
    Err(Error::busy())
}

pub(crate) struct PreparedWrite {
    pub kind: &'static str,
    pub branch: String,
    pub expect: Option<i64>,
    pub snapshot: String,
    pub lines: String,
    pub shard_branch: String,
    pub rows: Vec<(String, String, i64, i64, i64, i64)>,
    pub removed: Vec<String>,
    /// The branches' walks this write takes to their tips: `(branch, tip)`.
    pub walks: Vec<(String, String)>,
    pub gc_epoch: i64,
}

impl PreparedWrite {
    #[allow(clippy::too_many_arguments)]
    fn new(
        kind: &'static str,
        branch: &str,
        expect: Option<i64>,
        snapshot: &str,
        lines: &str,
        shard_branch: &str,
        shards: &BTreeMap<String, Shard>,
        removed: Vec<String>,
        walks: Vec<(String, String)>,
        gc_epoch: i64,
    ) -> Self {
        let rows = shards
            .iter()
            .map(|(k, s)| (k.clone(), serde_json::to_string(&s.segments).unwrap(), s.docs, s.text_docs, s.text_bytes, s.dead))
            .collect();
        PreparedWrite {
            kind,
            branch: branch.to_string(),
            expect,
            snapshot: snapshot.to_string(),
            lines: lines.to_string(),
            shard_branch: shard_branch.to_string(),
            rows,
            removed,
            walks,
            gc_epoch,
        }
    }
}

fn read_gc_epoch_cx(cx: &Cx, pool: &PgPool) -> Result<i64> {
    let project = cx.project();
    let epoch: i64 = cx.db(|| async {
        let cur: Option<i64> = sqlx::query_scalar(
            "SELECT epoch FROM access_epochs WHERE project_id = $1 AND person_id = -1",
        )
        .bind(project)
        .fetch_optional(pool)
        .await?;
        match cur {
            Some(e) => Ok(e),
            None => {
                sqlx::query(
                    "INSERT INTO access_epochs (project_id, person_id, epoch, changed_at) \
                     VALUES ($1, -1, 0, 0) ON CONFLICT (project_id, person_id) DO NOTHING",
                )
                .bind(project)
                .execute(pool)
                .await?;
                sqlx::query_scalar(
                    "SELECT epoch FROM access_epochs WHERE project_id = $1 AND person_id = -1",
                )
                .bind(project)
                .fetch_one(pool)
                .await
            }
        }
    })?;
    cx.hub().observe_gc_epoch(project, epoch);
    Ok(epoch)
}

pub(crate) async fn apply_write(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    project: i64,
    w: &PreparedWrite,
) -> std::result::Result<bool, sqlx::Error> {
    let cur_gc_epoch: Option<i64> = sqlx::query_scalar(crate::pack_gc::GUARD_SQL)
        .bind(project)
        .bind(crate::pack_gc::gate_key(project))
        .fetch_optional(&mut **tx)
        .await?;
    if cur_gc_epoch != Some(w.gc_epoch) {
        return Ok(false);
    }
    let moved = match w.expect {
        Some(v) => sqlx::query(
            "UPDATE search_heads SET snapshot = $4, lines = $5, version = version + 1 \
             WHERE project_id = $1 AND kind = $2 AND branch = $3 AND version = $6",
        )
        .bind(project)
        .bind(w.kind)
        .bind(&w.branch)
        .bind(&w.snapshot)
        .bind(&w.lines)
        .bind(v)
        .execute(&mut **tx)
        .await?
        .rows_affected(),
        None => sqlx::query(
            "INSERT INTO search_heads (project_id, kind, branch, snapshot, lines, version) VALUES ($1, $2, $3, $4, $5, 1) \
             ON CONFLICT DO NOTHING",
        )
        .bind(project)
        .bind(w.kind)
        .bind(&w.branch)
        .bind(&w.snapshot)
        .bind(&w.lines)
        .execute(&mut **tx)
        .await?
        .rows_affected(),
    };
    if moved != 1 {
        return Ok(false);
    }
    for (k, segs, docs, text_docs, text_bytes, dead) in &w.rows {
        sqlx::query(
            "INSERT INTO search_shards (project_id, kind, branch, line_key, segments, docs, text_docs, text_bytes, dead) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (project_id, kind, branch, line_key) DO UPDATE SET segments = EXCLUDED.segments, docs = EXCLUDED.docs, \
             text_docs = EXCLUDED.text_docs, text_bytes = EXCLUDED.text_bytes, dead = EXCLUDED.dead",
        )
        .bind(project)
        .bind(w.kind)
        .bind(&w.shard_branch)
        .bind(k)
        .bind(segs)
        .bind(docs)
        .bind(text_docs)
        .bind(text_bytes)
        .bind(dead)
        .execute(&mut **tx)
        .await?;
    }
    if !w.removed.is_empty() {
        sqlx::query("DELETE FROM search_shards WHERE project_id = $1 AND kind = $2 AND branch = $3 AND line_key = ANY($4)")
            .bind(project)
            .bind(w.kind)
            .bind(&w.shard_branch)
            .bind(&w.removed)
            .execute(&mut **tx)
            .await?;
    }
    if !w.walks.is_empty() {
        let (branches, tips): (Vec<&str>, Vec<&str>) = w.walks.iter().map(|(b, s)| (b.as_str(), s.as_str())).unzip();
        sqlx::query(
            "INSERT INTO search_heads (project_id, kind, branch, snapshot, lines, version) \
             SELECT $1, $2, b, s, $5, 1 FROM UNNEST($3::text[], $4::text[]) AS t(b, s) \
             ON CONFLICT (project_id, kind, branch) DO UPDATE SET snapshot = EXCLUDED.snapshot, lines = EXCLUDED.lines, \
             version = search_heads.version + 1",
        )
        .bind(project)
        .bind(WALK)
        .bind(&branches)
        .bind(&tips)
        .bind(&w.lines)
        .execute(&mut **tx)
        .await?;
    }
    Ok(true)
}

// ---- segments ----------------------------------------------------------------------

/// The flags of entry `e` ([`segment`]).
pub fn flags_of(e: &TreeEntry) -> u8 {
    let kind = match e.kind {
        EntryKind::File => KIND_FILE,
        EntryKind::Dir => KIND_DIR,
        EntryKind::Symlink => KIND_LINK,
        EntryKind::Conflict => KIND_CONFLICT,
    };
    let sealed = !e.visibility.is_public();
    let mut f = kind;
    if sealed {
        f |= SEALED;
    }
    if e.kind == EntryKind::File && !sealed && e.size <= MAX_TEXT_BYTES {
        f |= TEXT;
    }
    f
}

/// The content of a [`TEXT`] entry, if it is searchable: a blob with no
/// NUL byte (the same test a grep's scan makes).
pub fn text_of(src: &Source, id: &ObjectId) -> Result<Option<Vec<u8>>> {
    let raw = src.raw(id)?;
    if !Object::is_blob_raw(&raw) {
        return Ok(None);
    }
    match Object::decode(&raw)? {
        Object::Blob(b) if !b.contains(&0) && b.len() as u64 <= MAX_TEXT_BYTES => Ok(Some(b)),
        _ => Ok(None),
    }
}

/// Writes segments for one shard, flushing at the caps.
struct Writer<'a> {
    src: &'a Source,
    b: Builder,
    out: Vec<SegRef>,
    stats: &'a mut Stats,
}

impl Writer<'_> {
    fn flush(&mut self) -> Result<()> {
        if self.b.is_empty() {
            return Ok(());
        }
        let raw = std::mem::take(&mut self.b).encode();
        self.out.push(put(self.src, raw, self.stats)?);
        Ok(())
    }

    fn add(&mut self, doc: Doc, grams: &[u32]) -> Result<()> {
        self.stats.docs += 1;
        self.b.add(doc, grams);
        if self.b.bytes >= FLUSH_BYTES || self.b.postings >= FLUSH_POSTINGS || self.b.len() >= FLUSH_DOCS {
            self.flush()?;
        }
        Ok(())
    }
}

fn put(src: &Source, raw: Vec<u8>, stats: &mut Stats) -> Result<SegRef> {
    let id = ObjectId::hash(&raw);
    let bytes = raw.len() as u64;
    stats.segments += 1;
    stats.segment_bytes += bytes;
    src.rt
        .block_on(src.hub.objects.put(src.project, &id, Bytes::from(raw)))
        .map_err(|e| Error::Other(e.context("storing a search segment")))?;
    Ok(SegRef { id: id.hex(), bytes })
}

/// Code documents of `adds` (sorted in tree order) and tombstones `dead`:
/// new segments.
fn code_segments(src: &Source, adds: &[(String, TreeEntry)], dead: Vec<String>, stats: &mut Stats) -> Result<Vec<SegRef>> {
    let mut w = Writer {
        src,
        b: Builder::default(),
        out: Vec::new(),
        stats,
    };
    for (path, e) in adds {
        let mut flags = flags_of(e);
        let mut g = Vec::new();
        if flags & TEXT != 0 {
            match text_of(src, &e.id)? {
                Some(t) => {
                    w.stats.content_bytes += t.len() as u64;
                    w.b.bytes += t.len() as u64;
                    g = grams(&t);
                }
                None => flags |= BINARY,
            }
        }
        w.add(
            Doc {
                path: path.clone(),
                id: e.id,
                size: e.size,
                flags,
            },
            &g,
        )?;
    }
    for p in dead {
        w.b.delete(p);
    }
    w.flush()?;
    Ok(w.out)
}

/// Name documents (sorted, distinct).
fn name_segments(src: &Source, names: &BTreeMap<String, u8>, stats: &mut Stats) -> Result<Vec<SegRef>> {
    let mut sorted: Vec<(&String, &u8)> = names.iter().collect();
    sorted.sort_by(|a, b| tree_cmp(a.0, b.0));
    let mut w = Writer {
        src,
        b: Builder::default(),
        out: Vec::new(),
        stats,
    };
    for (p, f) in sorted {
        w.add(
            Doc {
                path: p.clone(),
                id: ObjectId([0; 32]),
                size: 0,
                flags: *f,
            },
            &grams(p.as_bytes()),
        )?;
    }
    w.flush()?;
    Ok(w.out)
}

fn load_all(src: &Source, segs: &[SegRef]) -> Result<Vec<Arc<Segment>>> {
    segs.iter().map(|s| segment::load(src, &oid(&s.id)?)).collect()
}

/// Merge `shard.segments[a..b]` into one segment.
fn merge_range(src: &Source, shard: &mut Shard, a: usize, b: usize, newer: &dyn Fn(&str) -> bool, stats: &mut Stats) -> Result<()> {
    let inputs = load_all(src, &shard.segments[a..b])?;
    let (raw, dropped) = segment::merge(&inputs, newer, a == 0);
    stats.merges += 1;
    let empty = Segment::decode(&raw).map(|s| s.docs.is_empty() && s.dead.is_empty()).unwrap_or(false);
    let replacement = if empty { Vec::new() } else { vec![put(src, raw, stats)?] };
    shard.segments.splice(a..b, replacement);
    shard.dead = (shard.dead - dropped as i64).max(0);
    Ok(())
}

/// Keep a shard's segments few and its dead documents bounded.
fn compact(src: &Source, shard: &mut Shard, code: bool, stats: &mut Stats) -> Result<()> {
    if code && shard.dead >= 64 && shard.dead * 2 > shard.docs {
        rewrite(src, shard, stats)?;
    }
    let newer_of = |src: &Source, segs: &[SegRef]| -> Result<Vec<Arc<Segment>>> { load_all(src, segs) };
    loop {
        let n = shard.segments.len();
        if n < 2 {
            break;
        }
        let (x, y) = (shard.segments[n - 2].bytes, shard.segments[n - 1].bytes);
        if x > 2 * y || x + y > MERGE_CAP {
            break;
        }
        merge_range(src, shard, n - 2, n, &|_| false, stats)?;
    }
    while shard.segments.len() > MAX_SEGMENTS {
        let i = (0..shard.segments.len() - 1)
            .min_by_key(|&i| shard.segments[i].bytes + shard.segments[i + 1].bytes)
            .expect("more than one segment");
        let newer = newer_of(src, &shard.segments[i + 2..])?;
        merge_range(src, shard, i, i + 2, &|p| newer.iter().any(|s| s.shadows(p)), stats)?;
    }
    Ok(())
}

/// Rewrite every segment of a code shard without its dead documents:
/// groups of consecutive segments under [`MERGE_CAP`], newest first,
/// each shadowed by the paths of those after it.
fn rewrite(src: &Source, shard: &mut Shard, stats: &mut Stats) -> Result<()> {
    let mut groups: Vec<(usize, usize)> = Vec::new();
    let mut end = shard.segments.len();
    while end > 0 {
        let mut start = end - 1;
        let mut size = shard.segments[start].bytes;
        while start > 0 && size + shard.segments[start - 1].bytes <= MERGE_CAP {
            start -= 1;
            size += shard.segments[start].bytes;
        }
        groups.push((start, end));
        end = start;
    }
    // The paths (documents and tombstones) of the segments after the
    // group being merged. Newest group first: each is replaced by at most
    // one segment, and only lower groups remain to do, so their indexes
    // stay valid.
    let mut shadow: HashSet<String> = HashSet::new();
    for (a, b) in groups {
        let paths: Vec<String> = load_all(src, &shard.segments[a..b])?
            .iter()
            .flat_map(|s| s.docs.iter().map(|d| d.path.clone()).chain(s.dead.iter().cloned()).collect::<Vec<_>>())
            .collect();
        merge_range(src, shard, a, b, &|p| shadow.contains(p), stats)?;
        shadow.extend(paths);
    }
    Ok(())
}

// ---- updating -----------------------------------------------------------------------

/// Index updates running in this process, per (hub, project), with the
/// branches landed on meanwhile.
type Active = Mutex<HashMap<(usize, i64), BTreeSet<String>>>;

fn active() -> &'static Active {
    static A: OnceLock<Active> = OnceLock::new();
    A.get_or_init(Default::default)
}

fn permits() -> &'static tokio::sync::Semaphore {
    static P: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    P.get_or_init(|| tokio::sync::Semaphore::new(UPDATERS))
}

/// A landing moved `branches` of `project` (derived already): update their
/// indexes in the background. One update per project at a time here;
/// landings meanwhile make it run again for their branches.
pub fn landed(hub: &Arc<Hub>, project: i64, branches: Vec<String>) {
    if branches.is_empty() {
        return;
    }
    let key = (Arc::as_ptr(hub) as usize, project);
    {
        let mut a = active().lock().unwrap();
        if let Some(waiting) = a.get_mut(&key) {
            waiting.extend(branches);
            return;
        }
        a.insert(key, BTreeSet::new());
    }
    let hub = hub.clone();
    tokio::spawn(async move {
        let mut branches = branches;
        loop {
            if let Err(e) = update(&hub, project, Some(branches)).await {
                eprintln!("veil-server: indexing project {project} for search: {e:?}");
            }
            let next = {
                let mut a = active().lock().unwrap();
                let next = a.get_mut(&key).map(std::mem::take).unwrap_or_default();
                if next.is_empty() {
                    a.remove(&key);
                }
                next
            };
            if next.is_empty() {
                break;
            }
            branches = next.into_iter().collect();
        }
    });
}

/// Update every public branch's search index for `project`.
pub async fn catch_up_project(hub: &Arc<Hub>, project: i64) -> Result<Stats> {
    update(hub, project, None).await
}

/// Update the indexes of `branches` (every branch when `None`) of
/// `project` to their tips, deriving them first if needed.
pub async fn update(hub: &Arc<Hub>, project: i64, branches: Option<Vec<String>>) -> Result<Stats> {
    let _permit = permits().acquire().await.map_err(|e| Error::Other(e.into()))?;
    let targets: Vec<(String, String)> =
        sqlx::query_as("SELECT name, target FROM branches WHERE project_id = $1 AND hidden_for_embargo IS NULL ORDER BY name")
            .bind(project)
            .fetch_all(&hub.derive.db)
            .await?;
    let row: Option<(String, String)> = sqlx::query_as("SELECT default_branch, policy_text FROM projects WHERE id = $1")
        .bind(project)
        .fetch_optional(&hub.derive.db)
        .await?;
    let (default, policy) = row.unwrap_or_else(|| ("main".into(), String::new()));
    let ident = identity(&Lines::new(&veil_core::hub::access::AccessPolicy::parse(&policy)));
    // Every branch whose index is behind its tip, missing, or built under
    // another policy is taken too, whatever was asked (BUG-1231, as S12's
    // BUG-982): an update that failed or was cut is done by the next one,
    // and a branch that never landed since the index began is walked.
    let lagging: Vec<String> = sqlx::query_scalar(
        "SELECT b.name FROM branches b \
         LEFT JOIN search_heads c ON c.project_id = b.project_id AND c.kind = 'code' AND c.branch = b.name \
         LEFT JOIN search_heads w ON w.project_id = b.project_id AND w.kind = 'walk' AND w.branch = b.name \
         WHERE b.project_id = $1 AND b.hidden_for_embargo IS NULL \
         AND (c.snapshot IS DISTINCT FROM b.target OR c.lines IS DISTINCT FROM $2 OR w.snapshot IS DISTINCT FROM b.target)",
    )
    .bind(project)
    .bind(&ident)
    .fetch_all(&hub.derive.db)
    .await?;
    let wanted: Vec<(String, ObjectId)> = targets
        .into_iter()
        .filter(|(n, _)| branches.as_ref().is_none_or(|b| b.contains(n)) || lagging.contains(n) || *n == default)
        .filter_map(|(n, t)| ObjectId::from_hex(&t).ok().map(|t| (n, t)))
        .collect();
    // The default branch first: other new branches start from it.
    let mut wanted = wanted;
    wanted.sort_by_key(|(n, _)| *n != default);
    for (_, tip) in &wanted {
        let derived: Option<i32> = sqlx::query_scalar("SELECT 1 FROM graph WHERE project_id = $1 AND snapshot = $2")
            .bind(project)
            .bind(tip.hex())
            .fetch_optional(&hub.derive.db)
            .await?;
        if derived.is_none() && *tip != root_snapshot_id() {
            crate::derive::ensure(hub, project, *tip).await?;
        }
    }
    let cx = Cx {
        src: Source {
            hub: hub.clone(),
            project,
            rt: tokio::runtime::Handle::current(),
            pending: Default::default(),
            staged: None,
        },
    };
    tokio::task::spawn_blocking(move || {
        let lines = cx.lines()?;
        // Every branch in one transaction (BUG-2350: an update of the
        // branches many pushes moved cost two commits a branch); when a
        // compare-and-swap is lost to another update, or anything fails,
        // they are taken one at a time, as before.
        let mut stats = Stats::default();
        if let Ok(true) = all_at_once(&cx, &lines, &wanted, &default, &mut stats) {
            stats.branches = wanted.iter().map(|(n, _)| n.clone()).collect();
            return Ok(stats);
        }
        let mut stats = Stats::default();
        // One branch's failure does not stop the others; the first error
        // is returned once all were tried (the next update tries again).
        let mut first_error = None;
        for (name, tip) in &wanted {
            match code(&cx, &lines, name, *tip, &default, &mut stats).and_then(|()| names(&cx, &lines, name, *tip, &default, &mut stats)) {
                Ok(()) => stats.branches.push(name.clone()),
                Err(e) => {
                    first_error.get_or_insert(e);
                }
            }
        }
        match first_error {
            Some(e) => Err(e),
            None => Ok(stats),
        }
    })
    .await
    .map_err(|e| Error::Other(e.into()))?
}

/// At start-up: bring up to date every project (or only `project`) with a
/// branch whose index is behind its tip or missing (an update cut by a
/// restart, or a project from before the index), one project at a time,
/// in the background (BUG-1231). A project whose policy changed since is
/// taken at its next landing or query.
pub async fn resume(hub: Arc<Hub>, project: Option<i64>) {
    let projects: Result<Vec<i64>> = sqlx::query_scalar(
        "SELECT DISTINCT b.project_id FROM branches b \
         LEFT JOIN search_heads c ON c.project_id = b.project_id AND c.kind = 'code' AND c.branch = b.name \
         LEFT JOIN search_heads w ON w.project_id = b.project_id AND w.kind = 'walk' AND w.branch = b.name \
         WHERE b.hidden_for_embargo IS NULL AND (c.snapshot IS DISTINCT FROM b.target OR w.snapshot IS DISTINCT FROM b.target) AND ($1::bigint IS NULL OR b.project_id = $1)",
    )
    .bind(project)
    .fetch_all(&hub.derive.db)
    .await
    .map_err(Error::from);
    match projects {
        Ok(projects) => {
            for p in projects {
                if let Err(e) = update(&hub, p, Some(Vec::new())).await {
                    eprintln!("veil-server: resuming the search index of project {p}: {e:?}");
                }
            }
        }
        Err(e) => eprintln!("veil-server: finding search indexes behind their branches: {e:?}"),
    }
}

fn withheld(g: &Graph, tip: &ObjectId) -> Result<bool> {
    Ok(g.get(tip)?.flags & FLAG_EMBARGO_LINE != 0)
}

fn tree_of(src: &Source, s: &ObjectId) -> Result<ObjectId> {
    Ok(src.snapshot(s)?.tree)
}

/// Per shard: what a diff adds and deletes, and how its counts move.
#[derive(Default)]
struct Plan {
    adds: Vec<(String, TreeEntry)>,
    dead: Vec<String>,
    docs: i64,
    text_docs: i64,
    text_bytes: i64,
    replaced: i64,
}

fn textlike(e: &TreeEntry) -> (i64, i64) {
    if flags_of(e) & TEXT != 0 {
        (1, e.size as i64)
    } else {
        (0, 0)
    }
}

/// Move the code index of each of `wanted` (`(branch, tip)`) and the names
/// index to their tips in one transaction: `false` (nothing written) if a
/// head moved meanwhile.
fn all_at_once(cx: &Cx, lines: &Lines, wanted: &[(String, ObjectId)], default: &str, stats: &mut Stats) -> Result<bool> {
    let pool = &cx.hub().derive.db;
    let g = Graph::new(cx);
    let mut writes = Vec::new();
    for (branch, tip) in wanted {
        writes.extend(prepare_code(cx, &g, lines, branch, *tip, default, stats)?);
    }
    writes.extend(prepare_names_of(cx, &g, lines, wanted, default, stats)?);
    if writes.is_empty() {
        return Ok(true);
    }
    cx.db(|| async {
        let mut tx = pool.begin().await?;
        for w in &writes {
            if !apply_write(&mut tx, cx.project(), w).await? {
                tx.rollback().await?;
                return Ok(false);
            }
        }
        tx.commit().await?;
        cx.hub().commits.count(crate::db::Commit::Search);
        Ok(true)
    })
}

/// Move `branch`'s code index to `tip`.
fn code(cx: &Cx, lines: &Lines, branch: &str, tip: ObjectId, default: &str, stats: &mut Stats) -> Result<()> {
    let pool = &cx.hub().derive.db;
    let g = Graph::new(cx);
    for _ in 0..8 {
        let Some(w) = prepare_code(cx, &g, lines, branch, tip, default, stats)? else {
            return Ok(());
        };
        let ok = cx.db(|| async {
            let mut tx = pool.begin().await?;
            if !apply_write(&mut tx, cx.project(), &w).await? {
                tx.rollback().await?;
                return Ok(false);
            }
            tx.commit().await?;
            cx.hub().commits.count(crate::db::Commit::Search);
            Ok(true)
        })?;
        if ok {
            return Ok(());
        }
    }
    Err(Error::busy())
}

fn prepare_code(cx: &Cx, g: &Graph, lines: &Lines, branch: &str, tip: ObjectId, default: &str, stats: &mut Stats) -> Result<Option<PreparedWrite>> {
    let src = &cx.src;
    let pool = &cx.hub().derive.db;
    if withheld(g, &tip)? {
        return Ok(None);
    }
    let ident = identity(lines);
    let all: BTreeSet<String> = lines.all().into_iter().collect();
    let gc_epoch = read_gc_epoch_cx(cx, pool)?;
    let (head, old) = read_state(cx, pool, CODE, branch, None)?;
    if head.as_ref().is_some_and(|h| h.snapshot == tip.hex() && h.lines == ident) {
        return Ok(None);
    }
    // Where to start: this branch's index under the same lines, else
    // the default branch's, else nothing; under other lines, the
    // shards whose keys are kept (the rest are built from the tip).
    let (mut shards, base, fresh, removed): (BTreeMap<String, Shard>, Option<ObjectId>, BTreeSet<String>, Vec<String>) = match &head {
        Some(h) if h.lines == ident => (old, Some(oid(&h.snapshot)?), BTreeSet::new(), Vec::new()),
        Some(h) => {
            let removed: Vec<String> = old.keys().filter(|k| !all.contains(*k)).cloned().collect();
            let kept: BTreeMap<String, Shard> = old.into_iter().filter(|(k, _)| all.contains(k)).collect();
            let fresh = all.iter().filter(|k| !kept.contains_key(*k)).cloned().collect();
            (kept, Some(oid(&h.snapshot)?), fresh, removed)
        }
        None => {
            let from_default = if branch != default {
                let (dh, ds) = read_state(cx, pool, CODE, default, None)?;
                dh.filter(|h| h.lines == ident).map(|h| (h, ds))
            } else {
                None
            };
            match from_default {
                Some((dh, ds)) => (ds, Some(oid(&dh.snapshot)?), BTreeSet::new(), Vec::new()),
                None => (BTreeMap::new(), None, all.clone(), Vec::new()),
            }
        }
    };
    let tip_tree = tree_of(src, &tip)?;
    let mut plans: BTreeMap<String, Plan> = BTreeMap::new();
    if let Some(b) = base {
        let base_tree = tree_of(src, &b)?;
        for c in changes::diff(src, base_tree, tip_tree)?.0 {
            let ko = c.old.as_ref().map(|e| lines.key_of(&c.path, e).to_string()).filter(|k| !fresh.contains(k));
            let kn = c.new.as_ref().map(|e| lines.key_of(&c.path, e).to_string()).filter(|k| !fresh.contains(k));
            if let (Some(k), Some(e)) = (&ko, &c.old) {
                let p = plans.entry(k.clone()).or_default();
                let (t, b) = textlike(e);
                p.docs -= 1;
                p.text_docs -= t;
                p.text_bytes -= b;
                p.replaced += 1;
                if kn.as_ref() != Some(k) {
                    p.dead.push(c.path.clone());
                }
            }
            if let (Some(k), Some(e)) = (&kn, &c.new) {
                let p = plans.entry(k.clone()).or_default();
                let (t, b) = textlike(e);
                p.docs += 1;
                p.text_docs += t;
                p.text_bytes += b;
                p.adds.push((c.path.clone(), e.clone()));
            }
        }
    }
    if !fresh.is_empty() {
        for k in &fresh {
            shards.remove(k);
        }
        for c in changes::diff(src, empty_tree_id(), tip_tree)?.0 {
            let Some(e) = &c.new else { continue };
            let k = lines.key_of(&c.path, e);
            if fresh.contains(k) {
                let p = plans.entry(k.to_string()).or_default();
                let (t, b) = textlike(e);
                p.docs += 1;
                p.text_docs += t;
                p.text_bytes += b;
                p.adds.push((c.path.clone(), e.clone()));
            }
        }
    }
    // A new branch takes the default branch's shards as its own.
    let mut touched: BTreeSet<String> = if head.is_none() { shards.keys().cloned().collect() } else { BTreeSet::new() };
    for (k, mut p) in plans {
        p.adds.sort_by(|a, b| tree_cmp(&a.0, &b.0));
        let segs = code_segments(src, &p.adds, p.dead, stats)?;
        let s = shards.entry(k.clone()).or_default();
        s.segments.extend(segs);
        s.docs += p.docs;
        s.text_docs += p.text_docs;
        s.text_bytes += p.text_bytes;
        s.dead += p.replaced;
        compact(src, s, true, stats)?;
        touched.insert(k);
    }
    let mut removed = removed;
    let write: BTreeMap<String, Shard> = touched
        .into_iter()
        .filter_map(|k| match shards.get(&k) {
            Some(s) if !s.segments.is_empty() => Some((k, s.clone())),
            _ => {
                removed.push(k);
                None
            }
        })
        .collect();
    Ok(Some(PreparedWrite::new(
        CODE,
        branch,
        head.as_ref().map(|h| h.version),
        &tip.hex(),
        &ident,
        branch,
        &write,
        removed,
        Vec::new(),
        gc_epoch,
    )))
}

/// The snapshots below `tip` (itself included) that are not below any of
/// `stops`: newest first by generation, so that every child is taken before
/// its parents and flags are final when a snapshot is taken (`rev-list
/// TIP ^STOP…`). One pass, whatever the shape of the history.
fn rev_list(g: &Graph, tip: ObjectId, stops: &[ObjectId]) -> Result<Vec<ObjectId>> {
    const NEW: u8 = 1;
    const STOP: u8 = 2;
    let mut flags: HashMap<ObjectId, u8> = HashMap::new();
    let mut heap: BinaryHeap<(i64, ObjectId)> = BinaryHeap::new();
    // Snapshots in the heap marked NEW only.
    let mut open = 0usize;
    let push = |id: ObjectId, f: u8, flags: &mut HashMap<ObjectId, u8>, heap: &mut BinaryHeap<(i64, ObjectId)>, open: &mut usize| -> Result<()> {
        match flags.get_mut(&id) {
            Some(old) => {
                let was_new_only = *old == NEW;
                *old |= f;
                if was_new_only && *old != NEW {
                    *open -= 1;
                }
            }
            None => {
                flags.insert(id, f);
                heap.push((g.get(&id)?.generation, id));
                if f == NEW {
                    *open += 1;
                }
            }
        }
        Ok(())
    };
    for s in stops {
        push(*s, STOP, &mut flags, &mut heap, &mut open)?;
    }
    push(tip, NEW, &mut flags, &mut heap, &mut open)?;
    let mut out = Vec::new();
    while open > 0 {
        let Some((_, id)) = heap.pop() else { break };
        let f = flags[&id];
        if f == NEW {
            open -= 1;
            out.push(id);
        }
        for p in g.get(&id)?.parents.clone() {
            push(p, f, &mut flags, &mut heap, &mut open)?;
        }
    }
    Ok(out)
}

/// The leaves snapshot `s` introduced against its first parent: from its
/// changed-paths object, or its trees when it has none (`many`).
fn introduced(cx: &Cx, g: &Graph, s: &ObjectId) -> Result<Vec<(String, TreeEntry)>> {
    let row = g.get(s)?;
    let changed = row.changed.as_deref().unwrap_or(MANY);
    if changed == WITHHELD || changed == NONE {
        return Ok(Vec::new());
    }
    if changed != MANY {
        if let Some(Changed { paths, .. }) = cx.changed(changed)? {
            return Ok(paths.into_iter().filter_map(|p| p.new.map(|e| (p.path, e))).collect());
        }
    }
    let snap = cx.src.snapshot(s)?;
    let before = match snap.parents.first() {
        Some(p) => tree_of(&cx.src, p)?,
        None => empty_tree_id(),
    };
    Ok(changes::diff(&cx.src, before, snap.tree)?.0.into_iter().filter_map(|c| c.new.map(|e| (c.path, e))).collect())
}

/// Add to the names index every path the snapshots `tip` brought hold.
fn names(cx: &Cx, lines: &Lines, branch: &str, tip: ObjectId, default: &str, stats: &mut Stats) -> Result<()> {
    let pool = &cx.hub().derive.db;
    let g = Graph::new(cx);
    for _ in 0..8 {
        let Some(w) = prepare_names(cx, &g, lines, branch, tip, default, stats)? else {
            return Ok(());
        };
        let ok = cx.db(|| async {
            let mut tx = pool.begin().await?;
            if !apply_write(&mut tx, cx.project(), &w).await? {
                tx.rollback().await?;
                return Ok(false);
            }
            tx.commit().await?;
            cx.hub().commits.count(crate::db::Commit::Search);
            Ok(true)
        })?;
        if ok {
            return Ok(());
        }
    }
    Err(Error::busy())
}

fn prepare_names(cx: &Cx, g: &Graph, lines: &Lines, branch: &str, tip: ObjectId, default: &str, stats: &mut Stats) -> Result<Option<PreparedWrite>> {
    prepare_names_of(cx, g, lines, &[(branch.to_string(), tip)], default, stats)
}

/// [`prepare_names`] for several branches at once: the names index is the
/// project's one (its head a compare-and-swap), so an update of many
/// branches moves it once, each snapshot walked once, and moves every
/// branch's walk with it (BUG-2350).
fn prepare_names_of(cx: &Cx, g: &Graph, lines: &Lines, tips: &[(String, ObjectId)], default: &str, stats: &mut Stats) -> Result<Option<PreparedWrite>> {
    let src = &cx.src;
    let pool = &cx.hub().derive.db;
    let ident = identity(lines);
    let all: BTreeSet<String> = lines.all().into_iter().collect();
    let gc_epoch = read_gc_epoch_cx(cx, pool)?;
    let (head, old) = read_state(cx, pool, NAMES, "", None)?;
    // The branches whose walk is behind their tip (a withheld tip waits).
    let mut todo = Vec::new();
    for (branch, tip) in tips {
        if withheld(g, tip)? {
            continue;
        }
        let walked = read_head(cx, pool, WALK, branch)?;
        if head.as_ref().is_some_and(|h| h.lines == ident) && walked.as_ref().is_some_and(|w| w.snapshot == tip.hex()) {
            continue;
        }
        todo.push((branch.as_str(), *tip, walked));
    }
    if todo.is_empty() {
        return Ok(None);
    }
    let mut shards = old.clone();
    let mut touched: BTreeSet<String> = BTreeSet::new();
    let mut removed: Vec<String> = Vec::new();
    if head.as_ref().is_some_and(|h| h.lines != ident) {
        // A new policy: shards of kept keys stay; new keys are built
        // from every old name.
        removed = old.keys().filter(|k| !all.contains(*k)).cloned().collect();
        shards.retain(|k, _| all.contains(k));
        let fresh: BTreeSet<String> = all.iter().filter(|k| !shards.contains_key(*k)).cloned().collect();
        // Written every NAMES_HELD names, as the walk is, and one old
        // segment loaded at a time.
        let mut moved: BTreeMap<String, BTreeMap<String, u8>> = BTreeMap::new();
        let mut held = 0usize;
        let write = |moved: &mut BTreeMap<String, BTreeMap<String, u8>>, shards: &mut BTreeMap<String, Shard>, touched: &mut BTreeSet<String>, stats: &mut Stats| -> Result<()> {
            for (k, m) in std::mem::take(moved) {
                let segs = name_segments(src, &m, stats)?;
                let s = shards.entry(k.clone()).or_default();
                s.docs += m.len() as i64;
                s.segments.extend(segs);
                compact(src, s, false, stats)?;
                touched.insert(k);
            }
            Ok(())
        };
        for s in old.values() {
            for r in &s.segments {
                let seg = segment::load(src, &oid(&r.id)?)?;
                for d in &seg.docs {
                    let k = lines.key_of(&d.path, &entry_of(d)).to_string();
                    if fresh.contains(&k) && moved.entry(k).or_default().insert(d.path.clone(), d.flags).is_none() {
                        held += 1;
                    }
                }
                if held >= NAMES_HELD {
                    write(&mut moved, &mut shards, &mut touched, stats)?;
                    held = 0;
                }
            }
        }
        write(&mut moved, &mut shards, &mut touched, stats)?;
    }
    let default_walk = match head.is_some() && todo.iter().any(|(b, ..)| *b != default) {
        true => read_head(cx, pool, WALK, default)?,
        false => None,
    };
    let mut new = Vec::new();
    let mut seen: HashSet<ObjectId> = HashSet::new();
    for (branch, tip, walked) in &todo {
        let mut stops: Vec<ObjectId> = Vec::new();
        if head.is_some() {
            if let Some(w) = walked {
                stops.push(oid(&w.snapshot)?);
            }
            if *branch != default {
                if let Some(w) = &default_walk {
                    stops.push(oid(&w.snapshot)?);
                }
            }
        }
        new.extend(rev_list(g, *tip, &stops)?.into_iter().filter(|s| seen.insert(*s)));
    }
    stats.walked += new.len();
    let mut gathered: BTreeMap<String, BTreeMap<String, u8>> = BTreeMap::new();
    let mut held = 0usize;
    let flush = |gathered: &mut BTreeMap<String, BTreeMap<String, u8>>, shards: &mut BTreeMap<String, Shard>, touched: &mut BTreeSet<String>, stats: &mut Stats| -> Result<()> {
        for (k, m) in std::mem::take(gathered) {
            let segs = name_segments(src, &m, stats)?;
            let s = shards.entry(k.clone()).or_default();
            s.docs += m.len() as i64;
            s.segments.extend(segs);
            compact(src, s, false, stats)?;
            touched.insert(k);
        }
        Ok(())
    };
    for s in &new {
        if *s == root_snapshot_id() || g.get(s)?.flags & FLAG_EMBARGO_LINE != 0 {
            continue;
        }
        for (path, e) in introduced(cx, g, s)? {
            let k = lines.key_of(&path, &e).to_string();
            if gathered.entry(k).or_default().insert(path, flags_of(&e)).is_none() {
                held += 1;
            }
        }
        if held >= NAMES_HELD {
            flush(&mut gathered, &mut shards, &mut touched, stats)?;
            held = 0;
        }
    }
    flush(&mut gathered, &mut shards, &mut touched, stats)?;
    let write: BTreeMap<String, Shard> = touched.iter().filter_map(|k| shards.get(k).map(|s| (k.clone(), s.clone()))).collect();
    let walks = todo.iter().map(|(b, t, _)| (b.to_string(), t.hex())).collect();
    Ok(Some(PreparedWrite::new(
        NAMES,
        "",
        head.as_ref().map(|h| h.version),
        "",
        &ident,
        "",
        &write,
        removed,
        walks,
        gc_epoch,
    )))
}

/// Prepare search index updates for a single-branch landing so they can commit
/// in the deriver's single database transaction (BUG-1593). Returns `Ok(None)`
/// if another branch is lagging or if multiple branches were moved, falling back
/// to [`landed`].
pub(crate) fn prepare_for_landing(
    cx: &Cx,
    g: &Graph,
    lines: &Lines,
    tips: &[(String, ObjectId)],
) -> Result<Option<Vec<PreparedWrite>>> {
    if tips.len() != 1 {
        return Ok(None);
    }
    let (branch, tip) = &tips[0];
    let pool = &cx.hub().derive.db;
    let project = cx.project();
    let ident = identity(lines);
    let default: String = cx
        .db(|| sqlx::query_scalar::<_, String>("SELECT default_branch FROM projects WHERE id = $1").bind(project).fetch_optional(pool))?
        .unwrap_or_else(|| "main".into());
    // If any OTHER branch is lagging or if the default branch is not yet indexed
    // and we are landing on a non-default branch, fall back to `landed`.
    let other_lagging: Option<String> = cx.db(|| {
        sqlx::query_scalar(
            "SELECT b.name FROM branches b \
             LEFT JOIN search_heads c ON c.project_id = b.project_id AND c.kind = 'code' AND c.branch = b.name \
             LEFT JOIN search_heads w ON w.project_id = b.project_id AND w.kind = 'walk' AND w.branch = b.name \
             WHERE b.project_id = $1 AND b.name <> $2 AND b.hidden_for_embargo IS NULL \
             AND (c.snapshot IS DISTINCT FROM b.target OR c.lines IS DISTINCT FROM $3 OR w.snapshot IS DISTINCT FROM b.target) \
             LIMIT 1",
        )
        .bind(project)
        .bind(branch)
        .bind(&ident)
        .fetch_optional(pool)
    })?;
    if other_lagging.is_some() {
        return Ok(None);
    }
    let mut stats = Stats::default();
    let mut out = Vec::with_capacity(2);
    if let Some(w) = prepare_code(cx, g, lines, branch, *tip, &default, &mut stats)? {
        out.push(w);
    }
    if let Some(w) = prepare_names(cx, g, lines, branch, *tip, &default, &mut stats)? {
        out.push(w);
    }
    Ok(Some(out))
}

/// A tree entry standing for document `d` (its kind and whether it is
/// sealed: all a line key needs).
pub fn entry_of(d: &Doc) -> TreeEntry {
    TreeEntry {
        name: String::new(),
        kind: match d.flags & segment::KIND_MASK {
            KIND_DIR => EntryKind::Dir,
            KIND_LINK => EntryKind::Symlink,
            KIND_CONFLICT => EntryKind::Conflict,
            _ => EntryKind::File,
        },
        id: d.id,
        size: d.size,
        executable: false,
        visibility: Default::default(),
    }
}
