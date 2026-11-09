//! Object storage (`docs/HUB.md` §2.1): immutable objects, per project,
//! each under its BLAKE3 id or in a pack (S28, [`crate::pack`]). An object nothing references is
//! invisible: the server only ever serves objects it reached from a
//! committed snapshot, through the viewer's projection.
//!
//! [`BlobStore`] is the trait; [`FsStore`] keeps objects in a local
//! directory (development and unit tests), [`S3Store`] in an S3 bucket
//! (tested against MinIO).

use std::{
    borrow::Cow,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use veil_core::{cache::LruCache, hub::encoding, ObjectId};

use crate::pack::{Found, Index, Slot};

#[async_trait]
pub trait BlobStore: Send + Sync {
    /// The object at `key`, `None` if there is none.
    async fn get(&self, key: &str) -> Result<Option<Bytes>>;
    /// Store `data` at `key`. Keys name immutable content: writing the
    /// same key twice writes the same bytes.
    async fn put(&self, key: &str, data: Bytes) -> Result<()>;
    async fn exists(&self, key: &str) -> Result<bool>;
    /// The length of the object at `key` without reading it where the
    /// store can (a file's size, an S3 `HEAD`); `None` if there is none.
    async fn len(&self, key: &str) -> Result<Option<u64>> {
        Ok(self.get(key).await?.map(|b| b.len() as u64))
    }
    /// Bytes `start..=end` of the object at `key` (`end` clamped to its
    /// last byte, `u64::MAX` for "to the end"; empty when `start` is past
    /// it) and the object's length;
    /// `None` if there is none. Reads only those bytes where the store can
    /// (a `Range` request of the object routes); this default reads all.
    async fn get_range(&self, key: &str, start: u64, end: u64) -> Result<Option<(Bytes, u64)>> {
        Ok(self.get(key).await?.map(|b| (slice(&b, start, end), b.len() as u64)))
    }
    /// A read that needs no async runtime (a local file), for code already
    /// on a blocking thread; `None`: use [`BlobStore::get`].
    fn get_blocking(&self, _key: &str) -> Option<Result<Option<Bytes>>> {
        None
    }
    /// [`BlobStore::get_range`] without an async runtime, where the store
    /// can; `None`: use [`BlobStore::get_range`].
    fn get_range_blocking(&self, _key: &str, _start: u64, _end: u64) -> Option<Result<Option<(Bytes, u64)>>> {
        None
    }
    /// Remove the object at `key` (no error if there is none): only packs
    /// that were discarded (`pack::Packs::discard`) are ever removed.
    async fn delete(&self, key: &str) -> Result<()>;
    /// Every key that starts with `prefix` (a folder of keys, `…/`): what
    /// the store holds, to compare with the database's rows (the tests;
    /// S29's job).
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

/// Bytes `start..=end` of `b`, clamped.
pub(crate) fn slice(b: &Bytes, start: u64, end: u64) -> Bytes {
    let len = b.len() as u64;
    if start >= len {
        return Bytes::new();
    }
    b.slice(start as usize..=end.min(len - 1) as usize)
}

/// Object key of `id` in `project`.
pub fn object_key(project: i64, id: &ObjectId) -> String {
    let h = id.hex();
    format!("p/{project}/{}/{}", &h[..2], &h[2..])
}

/// Objects in a local directory: `<root>/p/<project>/ab/cdef…`, written to
/// a temporary file, synced, then renamed into place.
pub struct FsStore {
    root: PathBuf,
}

impl FsStore {
    pub fn new(root: impl Into<PathBuf>) -> FsStore {
        FsStore { root: root.into() }
    }

    fn path(&self, key: &str) -> Result<PathBuf> {
        if key.split('/').any(|p| p.is_empty() || p == "." || p == "..") {
            bail!("invalid object key");
        }
        Ok(self.root.join(key))
    }
}

#[async_trait]
impl BlobStore for FsStore {
    async fn get(&self, key: &str) -> Result<Option<Bytes>> {
        match tokio::fs::read(self.path(key)?).await {
            Ok(b) => Ok(Some(Bytes::from(b))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn put(&self, key: &str, data: Bytes) -> Result<()> {
        let path = self.path(key)?;
        if tokio::fs::try_exists(&path).await? {
            return Ok(());
        }
        let dir = path.parent().expect("keys have a directory").to_path_buf();
        tokio::task::spawn_blocking(move || -> Result<()> {
            use std::io::Write;
            std::fs::create_dir_all(&dir)?;
            let mut tmp = tempfile::NamedTempFile::new_in(&dir)?;
            tmp.write_all(&data)?;
            tmp.as_file().sync_all()?;
            tmp.persist(&path).map_err(|e| e.error)?;
            std::fs::File::open(&dir)?.sync_all()?;
            Ok(())
        })
        .await?
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        Ok(tokio::fs::try_exists(self.path(key)?).await?)
    }

    async fn len(&self, key: &str) -> Result<Option<u64>> {
        match tokio::fs::metadata(self.path(key)?).await {
            Ok(m) => Ok(Some(m.len())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_range(&self, key: &str, start: u64, end: u64) -> Result<Option<(Bytes, u64)>> {
        let path = self.path(key)?;
        tokio::task::spawn_blocking(move || file_range(&path, start, end)).await?
    }

    fn get_blocking(&self, key: &str) -> Option<Result<Option<Bytes>>> {
        Some((|| match std::fs::read(self.path(key)?) {
            Ok(b) => Ok(Some(Bytes::from(b))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        })())
    }

    fn get_range_blocking(&self, key: &str, start: u64, end: u64) -> Option<Result<Option<(Bytes, u64)>>> {
        Some(self.path(key).and_then(|p| file_range(&p, start, end)))
    }

    async fn delete(&self, key: &str) -> Result<()> {
        match tokio::fs::remove_file(self.path(key)?).await {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let dir = self.path(prefix.trim_end_matches('/'))?;
        let prefix = prefix.trim_end_matches('/').to_string();
        tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let mut out = Vec::new();
            let mut stack = vec![(dir, prefix)];
            while let Some((d, k)) = stack.pop() {
                let rd = match std::fs::read_dir(&d) {
                    Ok(rd) => rd,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e.into()),
                };
                for e in rd {
                    let e = e?;
                    let name = e.file_name().to_string_lossy().into_owned();
                    if e.file_type()?.is_dir() {
                        stack.push((e.path(), format!("{k}/{name}")));
                    } else if !name.starts_with(".tmp") {
                        out.push(format!("{k}/{name}"));
                    }
                }
            }
            out.sort();
            Ok(out)
        })
        .await?
    }
}

/// Bytes `start..=end` of the file at `path` (clamped) and its length.
fn file_range(path: &std::path::Path, start: u64, end: u64) -> Result<Option<(Bytes, u64)>> {
    use std::io::{Read, Seek};
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let len = f.metadata()?.len();
    if start >= len {
        return Ok(Some((Bytes::new(), len)));
    }
    f.seek(std::io::SeekFrom::Start(start))?;
    let mut buf = vec![0; (end.min(len - 1) - start + 1) as usize];
    f.read_exact(&mut buf)?;
    Ok(Some((Bytes::from(buf), len)))
}

/// Objects in an S3 bucket (path-style URLs, as MinIO serves them).
pub struct S3Store {
    bucket: rusty_s3::Bucket,
    credentials: rusty_s3::Credentials,
    http: reqwest::Client,
}

/// How long a signed request stays valid.
const S3_SIGN_FOR: Duration = Duration::from_secs(300);
/// How long an S3 request is tried again for, the wait before the second
/// try (doubling, jittered) and the longest wait: well inside a request's
/// deadline (`db::TRANSACTION_DEADLINE`, 45 s). An S3 service or a local
/// MinIO that resets connections under load stays unreachable for seconds
/// at a time (BUG-861).
const S3_RETRY_FOR: Duration = Duration::from_secs(10);
const S3_FIRST_WAIT: Duration = Duration::from_millis(25);
const S3_MOST_WAIT: Duration = Duration::from_secs(1);

/// Send an S3 request (`make` builds it afresh for each try) and read its
/// answer, again while the answer is a server error (5xx) or 429, or the
/// request fails, for at most [`S3_RETRY_FOR`] (BUG-861). A connection the
/// store closed, reset or timed out, before or during the answer, and the
/// store's own transient errors (500, 503 "slow down", 429 "too many
/// requests": MinIO under load, BUG-1005), are tried again:
/// every request the store sends is idempotent (GET, HEAD, DELETE, and PUT
/// of a key that names its content or a pack's fresh random name).
async fn s3_send(make: impl Fn() -> reqwest::RequestBuilder) -> Result<(u16, Bytes)> {
    s3_send_with_headers(make).await.map(|(status, _, body)| (status, body))
}

/// [`s3_send`], with the answer's headers.
async fn s3_send_with_headers(make: impl Fn() -> reqwest::RequestBuilder) -> Result<(u16, reqwest::header::HeaderMap, Bytes)> {
    let deadline = tokio::time::Instant::now() + S3_RETRY_FOR;
    let mut wait = S3_FIRST_WAIT;
    for tries in 1.. {
        let answer = match make().send().await {
            Ok(resp) => {
                let (status, headers) = (resp.status(), resp.headers().clone());
                resp.bytes().await.map(|body| (status, headers, body))
            }
            Err(e) => Err(e),
        };
        let jitter = Duration::from_millis(u64::from(u16::from_le_bytes(veil_core::crypto::random_bytes::<2>())) % (wait.as_millis() as u64 + 1));
        let last = tokio::time::Instant::now() + wait + jitter >= deadline;
        match answer {
            // 429: the store asks for fewer requests (BUG-1005, BUG-1053).
            Ok((status, headers, body)) if !(status.is_server_error() || status.as_u16() == 429) || last => return Ok((status.as_u16(), headers, body)),
            Err(e) if last || e.is_builder() => return Err(anyhow::Error::new(e).context(format!("S3 request failed {tries} times"))),
            _ => {}
        }
        tokio::time::sleep(wait + jitter).await;
        wait = (wait * 2).min(S3_MOST_WAIT);
    }
    unreachable!()
}

impl S3Store {
    /// `endpoint` e.g. `http://127.0.0.1:9000`.
    pub fn new(endpoint: &str, bucket: &str, region: &str, key: &str, secret: &str) -> Result<S3Store> {
        let url = endpoint.parse().context("S3 endpoint")?;
        let bucket = rusty_s3::Bucket::new(url, rusty_s3::UrlStyle::Path, bucket.to_string(), region.to_string())
            .map_err(|e| anyhow!("S3 bucket: {e}"))?;
        Ok(S3Store {
            bucket,
            credentials: rusty_s3::Credentials::new(key, secret),
            // Idle connections are dropped before the store drops them (AWS
            // after about 20 s), so few requests meet a closed one.
            http: reqwest::Client::builder().pool_max_idle_per_host(64).pool_idle_timeout(Duration::from_secs(15)).build()?,
        })
    }

    /// Create the bucket if it does not exist (development and tests).
    pub async fn ensure_bucket(&self) -> Result<()> {
        use rusty_s3::S3Action;
        let url = self.bucket.create_bucket(&self.credentials).sign(S3_SIGN_FOR);
        let (status, _) = s3_send(|| self.http.put(url.clone())).await?;
        if (200..300).contains(&status) || status == 409 {
            return Ok(());
        }
        bail!("creating the S3 bucket: HTTP {status}")
    }
}

#[async_trait]
impl BlobStore for S3Store {
    async fn get(&self, key: &str) -> Result<Option<Bytes>> {
        use rusty_s3::S3Action;
        let url = self.bucket.get_object(Some(&self.credentials), key).sign(S3_SIGN_FOR);
        match s3_send(|| self.http.get(url.clone())).await? {
            (200, body) => Ok(Some(body)),
            (404, _) => Ok(None),
            (s, _) => bail!("S3 GET: HTTP {s}"),
        }
    }

    async fn get_range(&self, key: &str, start: u64, end: u64) -> Result<Option<(Bytes, u64)>> {
        use rusty_s3::S3Action;
        let url = self.bucket.get_object(Some(&self.credentials), key).sign(S3_SIGN_FOR);
        // An open range is sent open: a store that does not parse a huge
        // end ignores the range and sends the whole object (BUG-1086).
        let range = if end == u64::MAX { format!("bytes={start}-") } else { format!("bytes={start}-{end}") };
        let (status, headers, body) = s3_send_with_headers(|| self.http.get(url.clone()).header("range", &range)).await?;
        // `Content-Range: bytes a-b/len` (206).
        let len = || -> Result<u64> {
            let v = headers.get("content-range").and_then(|v| v.to_str().ok()).unwrap_or_default();
            v.rsplit_once('/').and_then(|(_, l)| l.parse().ok()).ok_or_else(|| anyhow!("S3 GET with a range: no length in {v:?}"))
        };
        match status {
            206 => Ok(Some((body, len()?))),
            // Past the end. MinIO's 416 names no length (BUG-1086): a HEAD
            // gives it.
            416 => Ok(self.len(key).await?.map(|l| (Bytes::new(), l))),
            // A store that ignores the range sends the whole object.
            200 => Ok(Some((slice(&body, start, end), body.len() as u64))),
            404 => Ok(None),
            s => bail!("S3 GET with a range: HTTP {s}"),
        }
    }

    async fn put(&self, key: &str, data: Bytes) -> Result<()> {
        use rusty_s3::S3Action;
        let url = self.bucket.put_object(Some(&self.credentials), key).sign(S3_SIGN_FOR);
        let (status, _) = s3_send(|| self.http.put(url.clone()).body(data.clone())).await?;
        if !(200..300).contains(&status) {
            bail!("S3 PUT: HTTP {status}");
        }
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        use rusty_s3::S3Action;
        let url = self.bucket.delete_object(Some(&self.credentials), key).sign(S3_SIGN_FOR);
        match s3_send(|| self.http.delete(url.clone())).await?.0 {
            200..=299 | 404 => Ok(()),
            s => bail!("S3 DELETE: HTTP {s}"),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        use rusty_s3::S3Action;
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut action = self.bucket.list_objects_v2(Some(&self.credentials));
            action.with_prefix(prefix);
            if let Some(t) = &token {
                action.with_continuation_token(t.clone());
            }
            let url = action.sign(S3_SIGN_FOR);
            let (status, body) = s3_send(|| self.http.get(url.clone())).await?;
            if status != 200 {
                bail!("S3 LIST: HTTP {status}");
            }
            let page = rusty_s3::actions::ListObjectsV2::parse_response(&body).map_err(|e| anyhow!("S3 LIST: {e}"))?;
            out.extend(page.contents.into_iter().map(|c| c.key));
            match page.next_continuation_token {
                Some(t) => token = Some(t),
                None => break,
            }
        }
        out.sort();
        Ok(out)
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        use rusty_s3::S3Action;
        let url = self.bucket.head_object(Some(&self.credentials), key).sign(S3_SIGN_FOR);
        match s3_send(|| self.http.head(url.clone())).await?.0 {
            200 => Ok(true),
            404 => Ok(false),
            s => bail!("S3 HEAD: HTTP {s}"),
        }
    }

    async fn len(&self, key: &str) -> Result<Option<u64>> {
        use rusty_s3::S3Action;
        let url = self.bucket.head_object(Some(&self.credentials), key).sign(S3_SIGN_FOR);
        let (status, headers, _) = s3_send_with_headers(|| self.http.head(url.clone())).await?;
        match status {
            200 => {
                let v = headers.get("content-length").and_then(|v| v.to_str().ok()).unwrap_or_default();
                Ok(Some(v.parse().map_err(|_| anyhow!("S3 HEAD: no length in {v:?}"))?))
            }
            404 => Ok(None),
            s => bail!("S3 HEAD: HTTP {s}"),
        }
    }
}

/// Decoded bytes the server holds at once, across every request: those an
/// upload decodes (S27, BUG-1009), those the object routes and `fetch`
/// have read and not sent yet (BUG-1087), and those a `Range` decodes. Each
/// takes its share before it reads or decodes, and gives it back when it is
/// done; an object larger than this takes all of it.
pub const DECODED_IN_FLIGHT: u32 = 256 << 20;
pub(crate) static DECODED: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(DECODED_IN_FLIGHT as usize);

/// How much more than the size its entry records an object may hold: the
/// blob's header, or a sealed envelope's nonce, tag and label. A push whose
/// entry records less is refused (`sync::check_changes`), so a recorded
/// size bounds what reading its object holds.
pub const SIZE_SLACK: u64 = 4096;

/// A share of [`DECODED_IN_FLIGHT`] taken by one read or decoding.
pub struct ReadAhead(#[allow(dead_code)] tokio::sync::SemaphorePermit<'static>);

fn permits(cost: u64) -> u32 {
    cost.min(u64::from(DECODED_IN_FLIGHT)) as u32
}

impl ReadAhead {
    /// Wait for `cost` bytes: only for a request that holds none, so
    /// requests never wait on one another in a cycle.
    pub async fn wait(cost: u64) -> ReadAhead {
        ReadAhead(DECODED.acquire_many(permits(cost)).await.expect("never closed"))
    }

    /// `cost` bytes if they are free now.
    pub fn try_take(cost: u64) -> Option<ReadAhead> {
        DECODED.try_acquire_many(permits(cost)).ok().map(ReadAhead)
    }
}

/// The objects of every project, through an in-memory cache of recently
/// read objects (objects are immutable, so the cache never goes stale).
///
/// Objects are stored, cached and sent in their encoding
/// ([`veil_core::hub::encoding`], S27): compressed with zstd when that is
/// smaller. An object is in one of a project's listed packs (S28,
/// [`crate::pack`]: what pushes store) or loose under its own key (the id
/// of the uncompressed object: objects stored before S28, and what grants,
/// API commits and the deriver store). Every object read from the store is
/// decoded (bounded by the object size limit) and checked against its id
/// before it is cached or served, whichever way it was stored.
///
/// A **staged** pack (what an upload wrote) is no project's: its objects
/// are read only through [`Objects::get_staged`], by the request whose
/// receipts name it, and cached under keys of their own, so nothing staged
/// is ever answered as the project's.
pub struct Objects {
    store: Arc<dyn BlobStore>,
    /// Encodings, checked against their ids.
    cache: LruCache<Bytes>,
    /// The listed packs of every project, as this server knows them.
    packs: crate::pack::Packs,
    /// Requests to the store, for the benchmarks' cost gates
    /// (`storage-and-cost.md` §9): writes, bytes written, reads; of the
    /// writes, a push's and an upload's own (`own_writes`: those made in
    /// their scope, [`own`], counted where they are made: BUG-1398).
    pub writes: AtomicU64,
    pub written_bytes: AtomicU64,
    pub reads: AtomicU64,
    pub own_writes: AtomicU64,
    /// Database commits that record a pack before it is written (an
    /// upload's, a push's own: S28), apart from a push's transaction.
    pub pack_rows: AtomicU64,
}

/// The largest object the store holds, decoded: the largest a frame
/// carries.
const MAX_OBJECT: u64 = veil_core::hub::wire::MAX_FRAME_OBJECT as u64;

/// The object `id` decoded from its encoding `enc`, checked.
fn decoded(id: &ObjectId, enc: &Bytes) -> Result<Bytes> {
    match encoding::decode(id, enc, MAX_OBJECT).map_err(|_| anyhow!("stored object {} does not match its id", id.short()))? {
        Cow::Borrowed(_) => Ok(enc.clone()),
        Cow::Owned(raw) => Ok(Bytes::from(raw)),
    }
}

/// `b` in an allocation of its own, for the object cache (BUG-1089). What
/// the store answers can be a slice of a larger buffer (an S3 answer is a
/// part of the HTTP client's read buffer): cached as it is, a small object
/// kept the whole buffer alive while the cache weighed only its bytes, so
/// the cache held several times its budget. S27's smaller encodings made
/// that about 2.5 times worse (more cached objects, each pinning a buffer).
fn owned(b: &Bytes) -> Bytes {
    Bytes::copy_from_slice(b)
}

/// The server's own encoding of canonical encoding `raw` (S27).
pub fn encode(raw: Bytes) -> Bytes {
    match encoding::encode(&raw) {
        Cow::Borrowed(_) => raw,
        Cow::Owned(z) => Bytes::from(z),
    }
}

tokio::task_local! {
    /// Set while a push or an upload runs (not in what it spawns: the
    /// deriver, the search index, viewer graphs).
    static OWN: ();
}

/// Run `f` as a push's or an upload's own work: the storage writes made in
/// it count in [`Objects::own_writes`] (BUG-1398: attributed where they are
/// made, not by subtracting known kinds of other work).
pub async fn own<F: std::future::Future>(f: F) -> F::Output {
    OWN.scope((), f).await
}

fn count_write(o: &Objects, bytes: usize) {
    bump(&o.writes);
    o.written_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    if OWN.try_with(|_| ()).is_ok() {
        bump(&o.own_writes);
    }
}

/// Objects of one pack read together, by offset.
type Run = Vec<(ObjectId, Slot)>;

/// [`Objects::prefetch`]: the most bytes between two neighbours read in
/// one request, the most bytes one request reads, and requests at once.
pub const PREFETCH_GAP: u64 = 64 << 10;
pub const PREFETCH_SPAN: u64 = 2 << 20;
const PREFETCH_AT_ONCE: usize = 8;

/// Where a project's object is stored.
enum Place {
    Pack(Arc<str>, Slot),
    /// Its stored length.
    Loose(u64),
}

fn bump(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

impl Objects {
    /// Objects in `store`, without a database: packs this process lists
    /// are its only listed packs (unit tests).
    pub fn new(store: Arc<dyn BlobStore>, cache_bytes: usize) -> Objects {
        Objects::with_db(store, cache_bytes, None)
    }

    /// Objects in `store`, with the packs listed in `db`.
    pub fn with_db(store: Arc<dyn BlobStore>, cache_bytes: usize, db: Option<sqlx::PgPool>) -> Objects {
        Objects {
            store,
            cache: LruCache::new(cache_bytes),
            packs: crate::pack::Packs::new(db),
            writes: Default::default(),
            written_bytes: Default::default(),
            reads: Default::default(),
            own_writes: Default::default(),
            pack_rows: Default::default(),
        }
    }

    /// Key of decoded tree `id` of `project` in [`crate::Hub::trees`].
    pub fn tree_key(project: i64, id: &ObjectId) -> ObjectId {
        let mut h = blake3::Hasher::new();
        h.update(b"tree");
        h.update(&project.to_le_bytes());
        h.update(&id.0);
        ObjectId(*h.finalize().as_bytes())
    }

    fn cache_key(project: i64, id: &ObjectId) -> ObjectId {
        let mut h = blake3::Hasher::new();
        h.update(&project.to_le_bytes());
        h.update(&id.0);
        ObjectId(*h.finalize().as_bytes())
    }

    /// Key of object `id` of staged pack `name` of `project`, in the object
    /// cache and (`tree`) in [`crate::Hub::trees`]: never a project's key.
    pub fn staged_key(project: i64, name: &str, id: &ObjectId, tree: bool) -> ObjectId {
        let mut h = blake3::Hasher::new();
        h.update(if tree { b"staged tree" } else { b"staged" });
        h.update(&project.to_le_bytes());
        h.update(name.as_bytes());
        h.update(&id.0);
        ObjectId(*h.finalize().as_bytes())
    }

    /// Where object `id` of `project` is: a listed pack whose index this
    /// server holds; or (`again`, after a miss everywhere since `since`) one
    /// listed since, or one whose index it unloaded past its budget (read
    /// again from storage: BUG-1395), whatever other lookups page in or out
    /// meanwhile (BUG-1495).
    async fn in_pack(&self, project: i64, id: &ObjectId, again: bool, since: Instant) -> Result<Option<(Arc<str>, Slot)>> {
        self.packs.locate(&self.store, project, id, again, since, &self.reads).await
    }

    /// Bytes `start..=end` of the encoding of object `id` at slot `s` of
    /// pack `name` (clamped), read with a range request, **after the head
    /// the entry starts with is checked against the slot** (its id and its
    /// length: BUG-1154, BUG-1497): with the bytes asked for when they start
    /// near the entry's start (one request), else apart.
    async fn pack_range(&self, project: i64, name: &str, id: &ObjectId, s: Slot, start: u64, end: u64) -> Result<Bytes> {
        const ONE_READ: u64 = 1 << 20;
        const HEAD: u64 = crate::pack::ENTRY_HEAD;
        let len = s.encoding_len();
        let last = end.min(len.saturating_sub(1));
        let key = crate::pack::key(project, name);
        let key = &key;
        let read = |from: u64, to: u64| async move {
            bump(&self.reads);
            let (b, _) = self.store.get_range(key, from, to).await?.ok_or_else(|| anyhow!("listed pack {name} is not in the store"))?;
            if b.len() as u64 != to - from + 1 {
                bail!("pack {name} is shorter than its index");
            }
            Ok::<Bytes, anyhow::Error>(b)
        };
        if start > last || len == 0 {
            crate::pack::entry(id, s, &read(s.offset, s.offset + HEAD - 1).await?)?;
            return Ok(Bytes::new());
        }
        if start <= ONE_READ {
            let b = read(s.offset, s.offset + HEAD + last).await?;
            crate::pack::entry(id, s, &b)?;
            return Ok(b.slice((HEAD + start) as usize..));
        }
        crate::pack::entry(id, s, &read(s.offset, s.offset + HEAD - 1).await?)?;
        read(s.offset + HEAD + start, s.offset + HEAD + last).await
    }

    /// The encoding of `id` of `project` from the store, unchecked: from a
    /// listed pack, or loose; after a miss in both, from a pack listed since
    /// (by another server).
    async fn load_encoding(&self, project: i64, id: &ObjectId) -> Result<Option<Bytes>> {
        let since = Instant::now();
        if let Some((n, s)) = self.in_pack(project, id, false, since).await? {
            return self.pack_range(project, &n, id, s, 0, u64::MAX).await.map(Some);
        }
        bump(&self.reads);
        if let Some(enc) = self.store.get(&object_key(project, id)).await? {
            return Ok(Some(enc));
        }
        match self.in_pack(project, id, true, since).await? {
            Some((n, s)) => self.pack_range(project, &n, id, s, 0, u64::MAX).await.map(Some),
            None => Ok(None),
        }
    }

    /// Is `id` of `project` stored (in a listed pack, or loose)?
    async fn stored(&self, project: i64, id: &ObjectId) -> Result<bool> {
        let since = Instant::now();
        if self.in_pack(project, id, false, since).await?.is_some() {
            return Ok(true);
        }
        bump(&self.reads);
        if self.store.exists(&object_key(project, id)).await? {
            return Ok(true);
        }
        Ok(self.in_pack(project, id, true, since).await?.is_some())
    }

    /// The object `id` of `project` (its canonical encoding), checked
    /// against its id.
    pub async fn get(&self, project: i64, id: &ObjectId) -> Result<Option<Bytes>> {
        match self.cache.get(&Self::cache_key(project, id)) {
            Some(enc) => decoded(id, &enc).map(Some),
            None => {
                let enc = self.load_encoding(project, id).await?;
                self.load(project, id, enc)
            }
        }
    }

    /// The encoding of object `id` of `project`, as stored (and sent to a
    /// client that reads encoded frames), checked against its id.
    pub async fn get_encoded(&self, project: i64, id: &ObjectId) -> Result<Option<Bytes>> {
        let ck = Self::cache_key(project, id);
        if let Some(enc) = self.cache.get(&ck) {
            return Ok(Some(enc));
        }
        let Some(enc) = self.load_encoding(project, id).await? else {
            return Ok(None);
        };
        let enc = owned(&enc);
        decoded(id, &enc)?;
        self.cache.insert(ck, enc.clone(), enc.len());
        Ok(Some(enc))
    }

    /// Check and cache the encoding the store answered; the object decoded.
    fn load(&self, project: i64, id: &ObjectId, enc: Option<Bytes>) -> Result<Option<Bytes>> {
        let Some(enc) = enc else { return Ok(None) };
        let enc = owned(&enc);
        let raw = decoded(id, &enc)?;
        self.cache.insert(Self::cache_key(project, id), enc.clone(), enc.len());
        Ok(Some(raw))
    }

    /// [`Objects::get`] from a blocking thread: a local store is read
    /// directly where this server knows where the object is; any other
    /// through `rt`.
    pub fn get_blocking(&self, rt: &tokio::runtime::Handle, project: i64, id: &ObjectId) -> Result<Option<Bytes>> {
        if let Some(enc) = self.cache.get(&Self::cache_key(project, id)) {
            return decoded(id, &enc).map(Some);
        }
        let direct = match self.packs.find(project, id) {
            Found::At(n, s) => self.store.get_range_blocking(&crate::pack::key(project, &n), s.offset, s.last()).map(|r| {
                r.and_then(|got| match got {
                    Some((b, _)) if b.len() == s.len as usize => {
                        crate::pack::entry(id, s, &b)?;
                        Ok(Some(b.slice(crate::pack::ENTRY_HEAD as usize..)))
                    }
                    _ => Err(anyhow!("pack {n} is shorter than its index")),
                })
            }),
            Found::Absent => self.store.get_blocking(&object_key(project, id)).and_then(|r| match r {
                // A miss may be a pack listed since: the async path.
                Ok(None) => None,
                r => Some(r),
            }),
            Found::Paged | Found::Unloaded => None,
        };
        let Some(r) = direct else {
            return rt.block_on(self.get(project, id));
        };
        bump(&self.reads);
        self.load(project, id, r?)
    }

    /// Store object `id` (its canonical encoding `raw`) loose, compressed
    /// when that is smaller.
    pub async fn put(&self, project: i64, id: &ObjectId, raw: Bytes) -> Result<()> {
        self.put_encoded(project, id, encode(raw)).await
    }

    /// Store `enc`, an encoding of object `id` the caller has checked, loose.
    pub async fn put_encoded(&self, project: i64, id: &ObjectId, enc: Bytes) -> Result<()> {
        count_write(self, enc.len());
        self.store.put(&object_key(project, id), enc.clone()).await?;
        self.cache.insert(Self::cache_key(project, id), enc.clone(), enc.len());
        Ok(())
    }

    /// Write `objects` (encodings the caller has checked or made) as one
    /// pack of `project` in one storage write: its name, index and length.
    /// Nobody reads it until a transaction lists it, and
    /// [`Objects::listed_here`] is told.
    /// Its objects are cached under the pack's staged keys (the project's
    /// once listed: [`Objects::listed_here`]).
    /// It is recorded staged for `person` (a row) before it is written, so
    /// the database names every pack in storage, whatever stops the request
    /// after (BUG-1399). Its index is held under a share of the server's
    /// bound on indexes (BUG-1496), taken before it is built.
    pub async fn put_pack(&self, project: i64, person: i64, objects: Vec<(ObjectId, Bytes)>) -> Result<(Arc<str>, Held)> {
        self.write_pack(project, objects, Some(person)).await
    }

    /// [`Objects::put_pack`]; with `staged_by`, the pack is recorded staged
    /// for that person before it is written (without, only in tests).
    async fn write_pack(&self, project: i64, objects: Vec<(ObjectId, Bytes)>, staged_by: Option<i64>) -> Result<(Arc<str>, Held)> {
        let share = self.packs.bound().take(Index::weight_of(objects.len()) as u64).await?;
        let name: Arc<str> = crate::pack::new_name().into();
        for (id, enc) in &objects {
            self.cache.insert(Self::staged_key(project, &name, id, false), enc.clone(), enc.len());
        }
        let (bytes, index) = crate::pack::build(objects)?;
        let size = bytes.len() as u64;
        if let Some(person) = staged_by {
            self.packs.record_staged(project, person, &name, size, index.len()).await?;
            bump(&self.pack_rows);
        }
        count_write(self, size as usize);
        self.store.put(&crate::pack::key(project, &name), bytes).await?;
        Ok((name, Held::new(Arc::new(index), size, share)))
    }

    /// Stage `objects` (checked encodings `person` uploaded) as one pack,
    /// recorded before it is written: its name. Its objects are cached
    /// under staged keys only. Objects all held by a pack the person staged
    /// here recently (and not discarded) get that pack again: a push that
    /// lost a race uploads the same objects again (BUG-1157).
    pub async fn stage(&self, project: i64, person: i64, objects: Vec<(ObjectId, Bytes)>) -> Result<Arc<str>> {
        let ids: Vec<ObjectId> = objects.iter().map(|(id, _)| *id).collect();
        if let Some(name) = self.packs.staged_holding(project, person, &ids).await? {
            return Ok(name);
        }
        let (name, held) = self.write_pack(project, objects, Some(person)).await?;
        self.packs.staged_here(project, person, &name, held);
        Ok(name)
    }

    /// Of staged packs `names`, those `person` uploaded and nobody
    /// discarded ([`crate::pack::Packs::usable`]).
    pub async fn usable(&self, project: i64, person: i64, names: &[Arc<str>]) -> Result<std::collections::HashSet<Arc<str>>> {
        self.packs.usable(project, person, names).await
    }

    /// The index and length of staged pack `name` of `project`, held under
    /// its share of the bound on indexes; `None` if it is not in the store
    /// (discarded).
    pub async fn staged_index(&self, project: i64, name: &str) -> Result<Option<Arc<Held>>> {
        self.packs.staged_index(&*self.store, project, name).await
    }

    /// What a push or API commit keeps of staged pack `name` of `project`:
    /// its object count, length and the slots of `ids`
    /// ([`crate::pack::Packs::staged_slots`]); `None` if it is not in the
    /// store (discarded).
    pub async fn staged_slots(&self, project: i64, name: &str, ids: &[ObjectId]) -> Result<Option<StagedSlots>> {
        self.packs.staged_slots(&*self.store, project, name, ids).await
    }

    /// Object `id` at slot `s` of staged pack `name` of `project`: its
    /// encoding and the object, checked against its id; `None` if the pack
    /// is gone (discarded).
    pub async fn get_staged(&self, project: i64, name: &str, s: Slot, id: &ObjectId) -> Result<Option<(Bytes, Bytes)>> {
        let ck = Self::staged_key(project, name, id, false);
        if let Some(enc) = self.cache.get(&ck) {
            let raw = decoded(id, &enc)?;
            return Ok(Some((enc, raw)));
        }
        bump(&self.reads);
        let Some((b, _)) = self.store.get_range(&crate::pack::key(project, name), s.offset, s.last()).await? else {
            return Ok(None);
        };
        if b.len() != s.len as usize {
            return Ok(None);
        }
        let enc = Bytes::copy_from_slice(crate::pack::entry(id, s, &b)?);
        let raw = decoded(id, &enc)?;
        self.cache.insert(ck, enc.clone(), enc.len());
        Ok(Some((enc, raw)))
    }

    /// Read the objects of `ids` (of `project`) that are in listed packs
    /// and not cached, **neighbours in one ranged request**: per pack, by
    /// offset, slots at most [`PREFETCH_GAP`] apart, at most
    /// [`PREFETCH_SPAN`] per request; each entry's id checked and each
    /// object checked against its id before it is cached (BUG-1152: a
    /// clone's fetch asked one request per object). A read that fails here
    /// is only not cached: the object's own read reports it. What a request
    /// reads and what each object decodes to are held under
    /// [`DECODED_IN_FLIGHT`] (shares taken without waiting: without one,
    /// nothing is read ahead).
    pub async fn prefetch(&self, project: i64, ids: &[ObjectId]) {
        let mut by_pack: std::collections::HashMap<Arc<str>, Run> = Default::default();
        let mut seen = std::collections::HashSet::new();
        for id in ids {
            if !seen.insert(*id) || self.cache.get(&Self::cache_key(project, id)).is_some() {
                continue;
            }
            if let Found::At(n, s) = self.packs.find(project, id) {
                by_pack.entry(n).or_default().push((*id, s));
            }
        }
        let mut runs: Vec<(Arc<str>, Run)> = Vec::new();
        for (name, mut slots) in by_pack {
            slots.sort_by_key(|(_, s)| s.offset);
            let mut run: Run = Vec::new();
            for (id, s) in slots {
                if let (Some(first), Some(last)) = (run.first(), run.last()) {
                    let near = s.offset <= last.1.last() + 1 + PREFETCH_GAP;
                    if !(near && s.last() + 1 - first.1.offset <= PREFETCH_SPAN) {
                        runs.push((name.clone(), std::mem::take(&mut run)));
                    }
                }
                run.push((id, s));
            }
            if !run.is_empty() {
                runs.push((name, run));
            }
        }
        // Only what a single read would not do as well.
        runs.retain(|(_, r)| r.len() > 1);
        let mut it = runs.into_iter();
        let mut set = tokio::task::JoinSet::new();
        loop {
            while set.len() < PREFETCH_AT_ONCE {
                let Some((name, run)) = it.next() else { break };
                let (start, end) = (run[0].1.offset, run.last().expect("a run").1.last());
                // Within the server-wide bound on bytes read ahead: without
                // a share free now, the objects are read one at a time.
                let Some(held) = ReadAhead::try_take(end - start + 1) else { break };
                bump(&self.reads);
                let key = crate::pack::key(project, &name);
                let store = self.store.clone();
                set.spawn(async move { (run, start, store.get_range(&key, start, end).await, held) });
            }
            let Some(done) = set.join_next().await else { break };
            let Ok((run, start, Ok(Some((bytes, _))), _held)) = done else { continue };
            for (id, s) in run {
                let (from, to) = ((s.offset - start) as usize, (s.last() - start) as usize);
                if to >= bytes.len() {
                    break;
                }
                let Ok(enc) = crate::pack::entry(&id, s, &bytes[from..=to]) else { continue };
                // Its check decodes it: within a share of the bound on
                // decoded bytes for what it declares (BUG-1159), or not
                // read ahead (its own read takes the share and checks it).
                let declared = encoding::declared_len(&enc[..enc.len().min(encoding::HEADER)], enc.len() as u64).unwrap_or(MAX_OBJECT);
                let Some(_decoding) = ReadAhead::try_take(declared) else { continue };
                let enc = Bytes::copy_from_slice(enc);
                if decoded(&id, &enc).is_ok() {
                    self.cache.insert(Self::cache_key(project, &id), enc.clone(), enc.len());
                }
            }
        }
    }

    /// What object `id` at slot `s` of staged pack `name` of `project`
    /// decodes to, as its encoding declares (S27), from its first bytes
    /// only (or the cache), its entry's head checked; `None` if the pack is
    /// gone.
    pub async fn staged_declared(&self, project: i64, name: &str, s: Slot, id: &ObjectId) -> Result<Option<u64>> {
        if let Some(enc) = self.cache.get(&Self::staged_key(project, name, id, false)) {
            return Ok(encoding::declared_len(&enc[..enc.len().min(encoding::HEADER)], enc.len() as u64));
        }
        bump(&self.reads);
        let last = s.last().min(s.offset + crate::pack::ENTRY_HEAD + encoding::HEADER as u64 - 1);
        let Some((b, _)) = self.store.get_range(&crate::pack::key(project, name), s.offset, last).await? else {
            return Ok(None);
        };
        Ok(encoding::declared_len(crate::pack::entry(id, s, &b)?, s.encoding_len()))
    }

    /// The encoding of object `id` at slot `s` of staged pack `name` of
    /// `project`, its entry's head checked but not decoded (the caller
    /// decodes it, checked against the id, within its share of the bound on
    /// decoded bytes); `None` if the pack is gone.
    pub async fn staged_encoding(&self, project: i64, name: &str, s: Slot, id: &ObjectId) -> Result<Option<Bytes>> {
        if let Some(enc) = self.cache.get(&Self::staged_key(project, name, id, false)) {
            return Ok(Some(enc));
        }
        bump(&self.reads);
        let Some((b, _)) = self.store.get_range(&crate::pack::key(project, name), s.offset, s.last()).await? else {
            return Ok(None);
        };
        if b.len() != s.len as usize {
            return Ok(None);
        }
        Ok(Some(Bytes::copy_from_slice(crate::pack::entry(id, s, &b)?)))
    }

    /// Packs of `project` a transaction listed and committed: their objects
    /// are the project's from now on (cached ones under the project's keys).
    pub fn listed_here(&self, project: i64, packs: Vec<(Arc<str>, Arc<Index>)>) {
        self.listed(project, packs.into_iter().map(|(n, i)| (n, Some(i))).collect());
    }

    /// [`Objects::listed_here`], where a pack's index may not be in hand (a
    /// push keeps only the slots its receipts name, BUG-1496): it is the
    /// staged-index cache's if that holds it, else read when a lookup needs
    /// it.
    pub fn listed(&self, project: i64, packs: Vec<(Arc<str>, Option<Arc<Index>>)>) {
        let packs: Vec<(Arc<str>, Option<Arc<Index>>)> = packs
            .into_iter()
            .map(|(name, index)| {
                let index = index.or_else(|| self.packs.staged_cached(project, &name));
                (name, index)
            })
            .collect();
        for (name, index) in &packs {
            for (id, _) in index.iter().flat_map(|i| i.iter()) {
                if let Some(enc) = self.cache.get(&Self::staged_key(project, name, id, false)) {
                    self.cache.insert(Self::cache_key(project, id), enc.clone(), enc.len());
                }
            }
        }
        self.packs.listed(project, packs);
    }

    /// Discard packs `names` of `project` that no transaction listed
    /// ([`crate::pack::Packs::discard`]).
    pub async fn discard(&self, project: i64, names: &[Arc<str>]) -> Result<()> {
        self.packs.discard(&*self.store, project, names).await
    }

    /// Bytes `start..=end` of object `id` of `project` (its canonical
    /// encoding, never of what is stored) and its length, `end` clamped
    /// (`u64::MAX`: to the end). An object stored as it is (S27's plain
    /// encoding), loose or in a pack, is read for those bytes only. A
    /// compressed one is decoded whole, as every read is (checked against
    /// its id, its decoded bytes counted in [`DECODED_IN_FLIGHT`] while
    /// held), then sliced. A part of a plain object cannot be checked
    /// against the id: the client checks the object it puts together.
    pub async fn get_range(&self, project: i64, id: &ObjectId, start: u64, end: u64) -> Result<Option<(Bytes, u64)>> {
        if let Some(enc) = self.cache.get(&Self::cache_key(project, id)) {
            if !encoding::is_compressed(&enc) {
                return Ok(Some((slice(&enc, start, end), enc.len() as u64)));
            }
        } else {
            match self.head(project, id).await? {
                None => return Ok(None),
                Some((head, Place::Pack(n, s))) if !encoding::is_compressed(&head) => {
                    return Ok(Some((self.pack_range(project, &n, id, s, start, end).await?, s.encoding_len())));
                }
                Some((head, Place::Loose(_))) if !encoding::is_compressed(&head) => {
                    bump(&self.reads);
                    return self.store.get_range(&object_key(project, id), start, end).await;
                }
                Some(_) => {}
            }
        }
        let cost = self.read_cost(project, id, 0).await?;
        let _held = ReadAhead::wait(cost).await;
        Ok(self.get(project, id).await?.map(|raw| (slice(&raw, start, end), raw.len() as u64)))
    }

    /// The first bytes of the encoding of `id` of `project` (at most
    /// [`encoding::HEADER`]), with where it is stored: a listed pack, else
    /// loose, else a pack listed since.
    async fn head(&self, project: i64, id: &ObjectId) -> Result<Option<(Bytes, Place)>> {
        let since = Instant::now();
        let h = encoding::HEADER as u64 - 1;
        if let Some((n, s)) = self.in_pack(project, id, false, since).await? {
            return Ok(Some((self.pack_range(project, &n, id, s, 0, h).await?, Place::Pack(n, s))));
        }
        bump(&self.reads);
        if let Some((head, len)) = self.store.get_range(&object_key(project, id), 0, h).await? {
            return Ok(Some((head, Place::Loose(len))));
        }
        match self.in_pack(project, id, true, since).await? {
            Some((n, s)) => Ok(Some((self.pack_range(project, &n, id, s, 0, h).await?, Place::Pack(n, s)))),
            None => Ok(None),
        }
    }

    /// What reading object `id` may hold, decoded: by the size its entry
    /// records (`recorded`, checked at push against the object:
    /// [`SIZE_SLACK`]), or, for an entry that records none (a tree, a
    /// conflict, an empty file), by what its encoding declares (in the
    /// cache, or its first bytes in the store: S27's frames declare their
    /// size).
    pub async fn read_cost(&self, project: i64, id: &ObjectId, recorded: u64) -> Result<u64> {
        if recorded > 0 {
            return Ok(recorded.saturating_add(SIZE_SLACK));
        }
        let declared = match self.cache.get(&Self::cache_key(project, id)) {
            Some(enc) => encoding::declared_len(&enc[..enc.len().min(encoding::HEADER)], enc.len() as u64),
            None => match self.head(project, id).await? {
                Some((head, Place::Pack(_, s))) => encoding::declared_len(&head, s.encoding_len()),
                Some((head, Place::Loose(len))) => encoding::declared_len(&head, len),
                None => Some(0),
            },
        };
        // An encoding that declares nothing is refused when it is read.
        Ok(declared.unwrap_or(0).min(MAX_OBJECT).saturating_add(SIZE_SLACK))
    }

    pub async fn exists(&self, project: i64, id: &ObjectId) -> Result<bool> {
        if self.cache.get(&Self::cache_key(project, id)).is_some() {
            return Ok(true);
        }
        self.stored(project, id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fs_store_round_trip_and_keys() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStore::new(dir.path());
        let raw = Bytes::from_static(b"veil:blob\nhi");
        let id = ObjectId::hash(&raw);
        let objects = Objects::new(Arc::new(FsStore::new(dir.path())), 1 << 20);
        assert!(objects.get(1, &id).await.unwrap().is_none());
        objects.put(1, &id, raw.clone()).await.unwrap();
        objects.put(1, &id, raw.clone()).await.unwrap();
        assert_eq!(s.get(&object_key(1, &id)).await.unwrap().unwrap(), raw);
        // Projects are separate.
        assert!(!s.exists(&object_key(2, &id)).await.unwrap());
        assert!(s.get("p/../../etc/passwd").await.is_err());
        // A corrupted file is refused, not served.
        std::fs::write(dir.path().join(object_key(3, &id)).parent().unwrap().join("x"), b"").ok();
        let path = dir.path().join(object_key(3, &id));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"veil:blob\nbad").unwrap();
        assert!(objects.get(3, &id).await.is_err());
    }

    #[tokio::test]
    async fn ranges_read_only_the_bytes_asked_for() {
        let dir = tempfile::tempdir().unwrap();
        let raw = Bytes::from_static(b"veil:blob\n0123456789");
        let id = ObjectId::hash(&raw);
        let fs = FsStore::new(dir.path());
        fs.put(&object_key(1, &id), raw.clone()).await.unwrap();
        // A store with only the default (reads the whole object).
        struct Whole(FsStore);
        #[async_trait]
        impl BlobStore for Whole {
            async fn get(&self, key: &str) -> Result<Option<Bytes>> {
                self.0.get(key).await
            }
            async fn put(&self, key: &str, data: Bytes) -> Result<()> {
                self.0.put(key, data).await
            }
            async fn exists(&self, key: &str) -> Result<bool> {
                self.0.exists(key).await
            }
            async fn delete(&self, key: &str) -> Result<()> {
                self.0.delete(key).await
            }
            async fn list(&self, prefix: &str) -> Result<Vec<String>> {
                self.0.list(prefix).await
            }
        }
        let whole = Whole(FsStore::new(dir.path()));
        let key = object_key(1, &id);
        for store in [&fs as &dyn BlobStore, &whole] {
            let len = raw.len() as u64;
            assert_eq!(store.get_range(&key, 2, 5).await.unwrap(), Some((raw.slice(2..6), len)));
            assert_eq!(store.get_range(&key, 3, u64::MAX).await.unwrap(), Some((raw.slice(3..), len)));
            assert_eq!(store.get_range(&key, len, u64::MAX).await.unwrap(), Some((Bytes::new(), len)));
            assert_eq!(store.get_range(&object_key(2, &id), 0, 1).await.unwrap(), None);
        }
        // Through the cache, or the store: the same part.
        let objects = Objects::new(Arc::new(FsStore::new(dir.path())), 1 << 20);
        assert_eq!(objects.get_range(1, &id, 0, 3).await.unwrap(), Some((raw.slice(0..4), raw.len() as u64)));
        objects.get(1, &id).await.unwrap();
        assert_eq!(objects.get_range(1, &id, 0, 3).await.unwrap(), Some((raw.slice(0..4), raw.len() as u64)));
    }

    /// S27: objects are stored compressed when that is smaller, under the
    /// id of the uncompressed object; objects stored before (as they are)
    /// stay readable; whatever the store answers is checked, bounded,
    /// against the id.
    #[tokio::test]
    async fn objects_are_stored_compressed_and_old_ones_stay_readable() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStore::new(dir.path());
        let objects = Objects::new(Arc::new(FsStore::new(dir.path())), 1 << 20);
        let raw = Bytes::from([&b"veil:blob\n"[..], &b"let x = 1;\n".repeat(500)].concat());
        let id = ObjectId::hash(&raw);
        objects.put(1, &id, raw.clone()).await.unwrap();
        let stored = s.get(&object_key(1, &id)).await.unwrap().unwrap();
        assert!(encoding::is_compressed(&stored) && stored.len() < raw.len() / 10, "{} bytes stored", stored.len());
        let fresh = Objects::new(Arc::new(FsStore::new(dir.path())), 1 << 20);
        assert_eq!(fresh.get(1, &id).await.unwrap().unwrap(), raw);
        assert_eq!(fresh.get_encoded(1, &id).await.unwrap().unwrap(), stored);
        let rt = tokio::runtime::Handle::current();
        let fresh2 = Arc::new(Objects::new(Arc::new(FsStore::new(dir.path())), 1 << 20));
        let f = fresh2.clone();
        let got = tokio::task::spawn_blocking(move || f.get_blocking(&rt, 1, &id)).await.unwrap().unwrap().unwrap();
        assert_eq!(got, raw);
        // An object stored before S27, as it is.
        let old = Bytes::from_static(b"veil:blob\nan object from before compression, stored as it is");
        let old_id = ObjectId::hash(&old);
        s.put(&object_key(2, &old_id), old.clone()).await.unwrap();
        assert_eq!(fresh.get(2, &old_id).await.unwrap().unwrap(), old);
        assert_eq!(fresh.get_encoded(2, &old_id).await.unwrap().unwrap(), old);
        // Incompressible content (a secret's ciphertext) is stored as it is.
        let noise = Bytes::from([&b"veil:sea2\n"[..], &veil_core::crypto::random_bytes::<2048>()].concat());
        let nid = ObjectId::hash(&noise);
        objects.put(1, &nid, noise.clone()).await.unwrap();
        assert_eq!(s.get(&object_key(1, &nid)).await.unwrap().unwrap(), noise);
        // A store answering another object's frame, an unknown marker, or a
        // bomb past the object size limit: refused, never served.
        let other = encoding::encode(b"veil:blob\nsomething else entirely, something else entirely").into_owned();
        let mut bomb = vec![encoding::ZSTD];
        bomb.extend(zstd_frame_declaring(MAX_OBJECT + 1));
        for bad in [other, b"\x01veil:blob\n".to_vec(), bomb] {
            let bid = ObjectId::hash(b"veil:blob\nwanted");
            s.put(&object_key(4, &bid), Bytes::from(bad)).await.unwrap();
            assert!(fresh.get(4, &bid).await.is_err());
            assert!(fresh.get_encoded(4, &bid).await.is_err());
            std::fs::remove_file(dir.path().join(object_key(4, &bid))).unwrap();
        }
    }

    /// S28: a staged pack is no project's (nothing reads its objects as the
    /// project's), a listed one is read by range, entry by entry, checked
    /// against the ids; a `Range` of a packed object is of the object; a
    /// discarded pack is gone and can never be listed after.
    #[tokio::test]
    async fn packs_are_read_by_range_and_staged_ones_are_nobodys() {
        let dir = tempfile::tempdir().unwrap();
        let objects = Objects::new(Arc::new(FsStore::new(dir.path())), 1 << 20);
        let plain = Bytes::from_static(b"veil:blob\nplain bytes stored as they are");
        let big = Bytes::from([&b"veil:blob\n"[..], &b"compress me ".repeat(400)].concat());
        let (pid, bid) = (ObjectId::hash(&plain), ObjectId::hash(&big));
        let encs = vec![(pid, encode(plain.clone())), (bid, encode(big.clone()))];
        assert!(encoding::is_compressed(&encs[1].1));
        let name = objects.stage(1, 7, encs).await.unwrap();
        assert_eq!(objects.writes.load(Ordering::Relaxed), 1, "one storage write for the upload");
        // Staged: not the project's, whatever the cache holds.
        assert!(objects.get(1, &pid).await.unwrap().is_none());
        assert!(!objects.exists(1, &bid).await.unwrap());
        let (index, _) = objects.staged_index(1, &name).await.unwrap().unwrap();
        let (_, raw) = objects.get_staged(1, &name, index.get(&bid).unwrap(), &bid).await.unwrap().unwrap();
        assert_eq!(raw, big);
        // A slot that names another object's bytes is refused (read from
        // the store: nothing cached).
        let cold = Objects::new(Arc::new(FsStore::new(dir.path())), 1 << 20);
        assert!(cold.get_staged(1, &name, index.get(&pid).unwrap(), &bid).await.is_err());
        // Listed: read by range from a fresh server (nothing cached).
        objects.listed_here(1, vec![(name.clone(), index.clone())]);
        let fresh = Objects::new(Arc::new(FsStore::new(dir.path())), 1 << 20);
        fresh.listed_here(1, vec![(name.clone(), index.clone())]);
        assert_eq!(fresh.get(1, &pid).await.unwrap().unwrap(), plain);
        assert_eq!(fresh.get(1, &bid).await.unwrap().unwrap(), big);
        assert!(fresh.exists(1, &bid).await.unwrap());
        assert!(fresh.get(2, &pid).await.unwrap().is_none(), "another project's pack");
        let rt = tokio::runtime::Handle::current();
        let f2 = Arc::new(Objects::new(Arc::new(FsStore::new(dir.path())), 1 << 20));
        f2.listed_here(1, vec![(name.clone(), index.clone())]);
        let f = f2.clone();
        assert_eq!(tokio::task::spawn_blocking(move || f.get_blocking(&rt, 1, &bid)).await.unwrap().unwrap().unwrap(), big);
        // Ranges are of the object, plain or compressed.
        let f3 = Objects::new(Arc::new(FsStore::new(dir.path())), 1 << 20);
        f3.listed_here(1, vec![(name.clone(), index.clone())]);
        assert_eq!(f3.get_range(1, &pid, 5, 8).await.unwrap(), Some((plain.slice(5..9), plain.len() as u64)));
        assert_eq!(f3.get_range(1, &pid, plain.len() as u64, u64::MAX).await.unwrap(), Some((Bytes::new(), plain.len() as u64)));
        assert_eq!(f3.get_range(1, &bid, 10, 13).await.unwrap(), Some((big.slice(10..14), big.len() as u64)));
        assert_eq!(f3.read_cost(1, &bid, 0).await.unwrap(), big.len() as u64 + SIZE_SLACK);
        // Discarded: deleted (a staged pack that nobody listed).
        let other = objects.stage(1, 7, vec![(ObjectId::hash(b"veil:blob\nx"), encode(Bytes::from_static(b"veil:blob\nx")))]).await.unwrap();
        assert!(objects.staged_index(1, &other).await.unwrap().is_some());
        objects.discard(1, std::slice::from_ref(&other)).await.unwrap();
        assert!(objects.staged_index(1, &other).await.unwrap().is_none(), "discarded");
        assert!(!dir.path().join(crate::pack::key(1, &other)).exists(), "the discarded pack is deleted");
        let fresh = Objects::new(Arc::new(FsStore::new(dir.path())), 1 << 20);
        assert!(fresh.staged_index(1, &other).await.unwrap().is_none(), "and gone from the store");
    }

    /// BUG-1154 (S28 cycle 1): a listed pack whose index gives one object
    /// the slot of another (a damaged index, or a wrong one a later pack
    /// merger writes) must never serve the other object's bytes. Whole
    /// reads are checked against the id; a `Range` of a plain packed object
    /// (S5's `GET /v1/objects/…` with `Range: bytes=0-`) is not, and hands
    /// out the bytes of whatever object the slot points at: from the same
    /// pack, so possibly of a folder the reader cannot see.
    #[tokio::test]
    async fn bug_1154_a_wrong_slot_never_serves_another_objects_range() {
        let dir = tempfile::tempdir().unwrap();
        let objects = Objects::new(Arc::new(FsStore::new(dir.path())), 1 << 20);
        // Two plain objects of one push: one anyone may read, one hidden.
        let open = Bytes::from_static(b"veil:blob\nan open file, readable by its grant: 0123");
        let hidden = Bytes::from_static(b"veil:blob\nMARKER-HIDDEN-PACKED-OBJECT-5c1e90d7aa");
        let (oid, hid) = (ObjectId::hash(&open), ObjectId::hash(&hidden));
        let encs = vec![(oid, encode(open.clone())), (hid, encode(hidden.clone()))];
        assert!(!encoding::is_compressed(&encs[0].1) && !encoding::is_compressed(&encs[1].1), "both stored plain");
        let (name, index, _) = objects.put_pack(1, 7, encs).await.unwrap();
        // The index damaged: the open object's entry names the hidden one's
        // slot (the rest of the pack intact).
        let path = dir.path().join(crate::pack::key(1, &name));
        let mut bytes = std::fs::read(&path).unwrap();
        let (os, hs) = (index.get(&oid).unwrap(), index.get(&hid).unwrap());
        let at = bytes.windows(32).position(|w| w == oid.0).expect("the open object's index entry");
        bytes[at + 32..at + 40].copy_from_slice(&hs.offset.to_be_bytes());
        bytes[at + 40..at + 44].copy_from_slice(&hs.len.to_be_bytes());
        assert_ne!(os, hs);
        std::fs::write(&path, &bytes).unwrap();
        let damaged = match crate::pack::parse_index(&bytes, Some(bytes.len() as u64)) {
            // Refused (the slots no longer tile the pack, BUG-1394): nothing
            // to read, which closes the class.
            Err(_) => return,
            Ok(i) => Arc::new(i),
        };
        // A server that reads the damaged index (nothing cached).
        let fresh = Objects::new(Arc::new(FsStore::new(dir.path())), 1 << 20);
        fresh.listed_here(1, vec![(name.clone(), damaged)]);
        // A whole read is checked against the id: refused.
        assert!(fresh.get(1, &oid).await.is_err(), "a whole read checks the id");
        // A range of the open object: its own bytes or an error, never the
        // hidden object's.
        match fresh.get_range(1, &oid, 0, u64::MAX).await {
            // Refused, as the whole read is.
            Err(_) => {}
            Ok(Some((part, _))) => {
                assert!(
                    !part.windows(b"MARKER-HIDDEN-PACKED-OBJECT".len()).any(|w| w == b"MARKER-HIDDEN-PACKED-OBJECT"),
                    "a range of one object served another object's bytes: {:?}",
                    String::from_utf8_lossy(&part)
                );
                assert_eq!(part, open, "a range read served other bytes than the object's");
            }
            Ok(None) => panic!("a listed object read as absent"),
        }
    }

    /// BUG-1394 (S28 cycle 2; BUG-1154's class): every read checks the id
    /// an entry **starts** with, but nothing checks where a slot **ends**.
    /// A slot whose length is too long (a damaged index, a merger's
    /// mistake: what BUG-1154 is about) starts at its own entry, passes the
    /// id check, and runs on into the next entry: a ranged read of a plain
    /// object serves the neighbour's id and bytes after its own. Whole reads
    /// are decoded and checked against the id, so only ranges (and
    /// `head`'s length) are wrong. `parse_index` accepts it: slots are
    /// checked to be inside the pack, not to tile it.
    #[tokio::test]
    async fn bug_1394_a_slot_too_long_never_serves_its_neighbours_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let objects = Objects::new(Arc::new(FsStore::new(dir.path())), 1 << 20);
        let open = Bytes::from_static(b"veil:blob\nan open file, readable by its grant: 0123");
        let hidden = Bytes::from_static(b"veil:blob\nMARKER-HIDDEN-NEIGHBOUR-OBJECT-8f3a61c2d0");
        let (oid, hid) = (ObjectId::hash(&open), ObjectId::hash(&hidden));
        let encs = vec![(oid, encode(open.clone())), (hid, encode(hidden.clone()))];
        assert!(!encoding::is_compressed(&encs[0].1) && !encoding::is_compressed(&encs[1].1), "both stored plain");
        let (name, index, _) = objects.put_pack(1, 7, encs).await.unwrap();
        let (os, hs) = (index.get(&oid).unwrap(), index.get(&hid).unwrap());
        assert_eq!(os.offset + u64::from(os.len), hs.offset, "the hidden entry follows the open one");
        // The index damaged: the open object's slot as long as both entries.
        let path = dir.path().join(crate::pack::key(1, &name));
        let mut bytes = std::fs::read(&path).unwrap();
        let at = bytes.windows(32).position(|w| w == oid.0).expect("the open object's index entry");
        bytes[at + 40..at + 44].copy_from_slice(&(os.len + hs.len).to_be_bytes());
        std::fs::write(&path, &bytes).unwrap();
        let damaged = match crate::pack::parse_index(&bytes, Some(bytes.len() as u64)) {
            // Refusing the index closes the class: nothing to read.
            Err(_) => return,
            Ok(i) => Arc::new(i),
        };
        let fresh = Objects::new(Arc::new(FsStore::new(dir.path())), 1 << 20);
        fresh.listed_here(1, vec![(name.clone(), damaged)]);
        assert!(fresh.get(1, &oid).await.is_err(), "a whole read checks the object against its id");
        let marker = b"MARKER-HIDDEN-NEIGHBOUR-OBJECT";
        // Ranges from the start, the middle and the end: the object's own
        // bytes or an error.
        for (start, end) in [(0, u64::MAX), (20, u64::MAX), (open.len() as u64 - 4, open.len() as u64 + 200)] {
            match fresh.get_range(1, &oid, start, end).await {
                Err(_) => {}
                Ok(Some((part, len))) => {
                    assert!(
                        !part.windows(marker.len()).any(|w| w == marker),
                        "a range {start}..={end} of one object served its neighbour's bytes: {:?}",
                        String::from_utf8_lossy(&part)
                    );
                    assert_eq!(&part[..], &open[(start as usize).min(open.len())..], "a range served other bytes than the object's");
                    assert_eq!(len, open.len() as u64, "the object's length");
                }
                Ok(None) => panic!("a listed object read as absent"),
            }
        }
    }

    /// Property 2 (S28 cycle 2): neighbours read in one ranged request,
    /// one entry of them damaged in the pack (its id's bytes): the others
    /// are read and cached, the damaged one is not, and its own read is an
    /// error, never another object's bytes.
    #[tokio::test]
    async fn neighbour_reads_check_every_entry_of_a_batch() {
        let dir = tempfile::tempdir().unwrap();
        let objects = Objects::new(Arc::new(FsStore::new(dir.path())), 1 << 20);
        let raws: Vec<Bytes> = (0..3).map(|i| Bytes::from(format!("veil:blob\nneighbour {i}: MARKER-NEIGHBOUR-{i}-ab37"))).collect();
        let encs: Vec<(ObjectId, Bytes)> = raws.iter().map(|r| (ObjectId::hash(r), encode(r.clone()))).collect();
        let ids: Vec<ObjectId> = encs.iter().map(|(id, _)| *id).collect();
        let (name, index, _) = objects.put_pack(1, 7, encs).await.unwrap();
        let path = dir.path().join(crate::pack::key(1, &name));
        let mut bytes = std::fs::read(&path).unwrap();
        let mid = index.get(&ids[1]).unwrap();
        bytes[mid.offset as usize] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();
        let fresh = Objects::new(Arc::new(FsStore::new(dir.path())), 1 << 20);
        fresh.listed_here(1, vec![(name, index)]);
        fresh.prefetch(1, &ids).await;
        assert_eq!(fresh.reads.load(Ordering::Relaxed), 1, "one ranged request for the three");
        let cached = |id: &ObjectId| fresh.cache.get(&Objects::cache_key(1, id)).is_some();
        assert!(cached(&ids[0]) && cached(&ids[2]) && !cached(&ids[1]), "the intact neighbours are cached, the damaged one is not");
        assert_eq!(fresh.get(1, &ids[0]).await.unwrap(), Some(raws[0].clone()));
        assert_eq!(fresh.get(1, &ids[2]).await.unwrap(), Some(raws[2].clone()));
        assert!(fresh.get(1, &ids[1]).await.is_err(), "the damaged entry is an error");
        assert!(fresh.get_range(1, &ids[1], 0, u64::MAX).await.is_err(), "a range of it too");
    }

    /// BUG-1159 (S28 cycle 2; BUG-1087's class): the neighbour reads of a
    /// fetch (`Objects::prefetch`) take a share of the server-wide bound
    /// for the bytes they **read** (`ReadAhead::try_take(end - start + 1)`,
    /// at most `PREFETCH_SPAN`), then check each object by decoding it
    /// whole (`decoded`) outside any share: a compressed object decodes to
    /// up to 64 times its encoding (`encoding::MAX_RATIO`). Before cycle 2 a
    /// fetch read each object under a share of its decoded size (BUG-1087).
    /// Fetches of the same objects, not yet cached, right after a push (a
    /// fleet of clones) each decode them. Measured in a child process: 32
    /// prefetches at once of two neighbouring objects of 48 MiB that compress
    /// about 52 times hold far more than `DECODED_IN_FLIGHT` decoded.
    #[test]
    fn bug_1159_neighbour_reads_decode_within_the_servers_bound() {
        const CHILD: &str = "VEIL_TEST_PREFETCH_CHILD";
        const NAME: &str = "store::tests::bug_1159_neighbour_reads_decode_within_the_servers_bound";
        if std::env::var_os(CHILD).is_some() {
            let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(16).enable_all().build().unwrap();
            rt.block_on(async {
                let dir = tempfile::tempdir().unwrap();
                let objects = Objects::new(Arc::new(FsStore::new(dir.path())), 64 << 20);
                let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
                let mut encs = Vec::new();
                for side in *b"ab" {
                    let mut raw = b"veil:blob\n".to_vec();
                    raw.resize(48 << 20, 0);
                    for i in (16..raw.len()).step_by(80) {
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        raw[i] = x as u8;
                    }
                    raw[12] = side;
                    let raw = Bytes::from(raw);
                    let enc = encode(raw.clone());
                    assert!(encoding::is_compressed(&enc) && encoding::within_ratio(&enc), "compressed within the ratio: {}", enc.len());
                    encs.push((ObjectId::hash(&raw), enc));
                }
                let ids: Vec<ObjectId> = encs.iter().map(|(id, _)| *id).collect();
                let (name, index, _) = objects.put_pack(1, 7, encs).await.unwrap();
                drop(objects);
                // A server that has not read them.
                let fresh = Arc::new(Objects::new(Arc::new(FsStore::new(dir.path())), 64 << 20));
                fresh.listed_here(1, vec![(name, index)]);
                let vm = |field: &str| -> u64 {
                    let s = std::fs::read_to_string("/proc/self/status").unwrap();
                    let l = s.lines().find(|l| l.starts_with(field)).unwrap();
                    l.split_whitespace().nth(1).unwrap().parse::<u64>().unwrap() << 10
                };
                std::fs::write("/proc/self/clear_refs", "5").unwrap();
                let before = vm("VmRSS:");
                let mut set = tokio::task::JoinSet::new();
                for _ in 0..32 {
                    let (f, ids) = (fresh.clone(), ids.clone());
                    set.spawn(async move { f.prefetch(1, &ids).await });
                }
                while let Some(r) = set.join_next().await {
                    r.unwrap();
                }
                let grew = vm("VmHWM:").saturating_sub(before);
                let reads = fresh.reads.load(Ordering::Relaxed);
                assert!(fresh.cache.get(&Objects::cache_key(1, &ids[0])).is_some(), "the prefetches read the objects");
                println!("PREFETCH grew={grew} reads={reads}");
            });
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([NAME, "--exact", "--nocapture", "--include-ignored", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(out.status.success(), "the child failed: {text}{}", String::from_utf8_lossy(&out.stderr));
        let line = text.lines().find_map(|l| l.find("PREFETCH").map(|at| &l[at..])).unwrap_or_else(|| panic!("no measurement in {text}"));
        let grew: u64 = line.split_whitespace().find_map(|w| w.strip_prefix("grew=")).unwrap().parse().unwrap();
        assert!(
            grew <= u64::from(DECODED_IN_FLIGHT) + (64 << 20),
            "32 neighbour reads at once held {} MiB, past the {} MiB bound on decoded bytes ({line})",
            grew >> 20,
            DECODED_IN_FLIGHT >> 20
        );
    }

    /// The header of a zstd frame declaring `size` bytes of content (and
    /// one empty raw block): enough for a decoder to refuse it from its
    /// header.
    fn zstd_frame_declaring(size: u64) -> Vec<u8> {
        // Magic, descriptor (8-byte content size, single segment off),
        // window descriptor, the size, then a last raw block of 0 bytes.
        let mut f = vec![0x28, 0xb5, 0x2f, 0xfd, 0b1100_0000, 0x50];
        f.extend_from_slice(&size.to_le_bytes());
        f.extend_from_slice(&[0x01, 0x00, 0x00]);
        f
    }

    /// A small fixed-seed generator for the damage tests.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n.max(1)
        }
    }

    /// The pack's head: the magic and the count; one index entry.
    const PACK_HEAD: usize = 14;
    const PACK_ENTRY: usize = 44;

    /// The objects of the damage tests (id, object, encoding): plain ones
    /// of one length (so slots can be swapped), compressed ones, and a large
    /// plain one (ranges past `pack_range`'s single read), each with a
    /// marker of its own.
    fn damage_objects() -> Vec<(ObjectId, Bytes, Bytes)> {
        let mut raws: Vec<Bytes> = (0..6).map(|i| Bytes::from(format!("veil:blob\nMARKER-DAMAGE-PLAIN-{i:02}-7d3e0b5a19c4f2"))).collect();
        raws.extend((0..2).map(|i| Bytes::from([&b"veil:blob\n"[..], format!("MARKER-DAMAGE-COMPRESSED-{i}-").repeat(300).as_bytes()].concat())));
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut large = b"veil:blob\n".to_vec();
        large.extend((0..(1_500_000 / 8)).flat_map(|_| rng.next().to_le_bytes()));
        raws.push(Bytes::from(large));
        let objs: Vec<(ObjectId, Bytes, Bytes)> = raws.into_iter().map(|raw| (ObjectId::hash(&raw), raw.clone(), encode(raw))).collect();
        assert!(objs[..6].iter().all(|o| !encoding::is_compressed(&o.2)) && objs[6..8].iter().all(|o| encoding::is_compressed(&o.2)));
        assert!(!encoding::is_compressed(&objs[8].2), "the large object is stored plain");
        objs
    }

    /// Every kind of read of every object of the pack `name` of project 1
    /// in `dir`, listed with `index` (parsed from the pack as it was when
    /// its index was read): each answers its own object exactly, or refuses
    /// (an error, or nothing). The number of reads answered.
    async fn reads_answer_their_own_objects(dir: &std::path::Path, name: &Arc<str>, index: &Arc<Index>, objs: &[(ObjectId, Bytes, Bytes)], case: &str) -> usize {
        let fresh = || {
            let o = Objects::new(Arc::new(FsStore::new(dir)), 64 << 20);
            o.listed_here(1, vec![(name.clone(), index.clone())]);
            o
        };
        let mut answered = 0;
        let whole = fresh();
        let encoded = fresh();
        for (id, raw, enc) in objs {
            if let Ok(Some(got)) = whole.get(1, id).await {
                assert!(got == *raw, "{case}: a whole read of {} answered other bytes", id.short());
                answered += 1;
            }
            if let Ok(Some(got)) = encoded.get_encoded(1, id).await {
                assert!(got == *enc, "{case}: an encoded read of {} answered other bytes", id.short());
                answered += 1;
            }
            let len = raw.len() as u64;
            for (start, end) in [(0, u64::MAX), (5, 40), (len.saturating_sub(3), len + 100), (len / 2, u64::MAX), (1_200_000, 1_200_100)] {
                let ranges = fresh();
                if let Ok(Some((part, l))) = ranges.get_range(1, id, start, end).await {
                    let want = slice(raw, start, end);
                    assert!(
                        l == len && part == want,
                        "{case}: a range {start}..={end} of {} answered {} bytes of length {l}, not its own {} bytes of length {len}: {:?}",
                        id.short(),
                        part.len(),
                        want.len(),
                        String::from_utf8_lossy(&part[..part.len().min(120)])
                    );
                    answered += 1;
                }
            }
        }
        // Neighbours read together, then each read from the cache.
        let ahead = fresh();
        let ids: Vec<ObjectId> = objs.iter().map(|o| o.0).collect();
        ahead.prefetch(1, &ids).await;
        for (id, raw, _) in objs {
            if let Ok(Some(got)) = ahead.get(1, id).await {
                assert!(got == *raw, "{case}: a read after a neighbour read of {} answered other bytes", id.short());
                answered += 1;
            }
        }
        // From a blocking thread (a local store read directly).
        let blocking = Arc::new(fresh());
        let rt = tokio::runtime::Handle::current();
        let objs2 = objs.to_vec();
        let (b, c) = (blocking.clone(), case.to_string());
        answered += tokio::task::spawn_blocking(move || {
            let mut n = 0;
            for (id, raw, _) in &objs2 {
                if let Ok(Some(got)) = b.get_blocking(&rt, 1, id) {
                    assert!(got == *raw, "{c}: a blocking read of {} answered other bytes", id.short());
                    n += 1;
                }
            }
            n
        })
        .await
        .unwrap();
        answered
    }

    /// A pack of the damage tests in `dir`: its name, bytes and index.
    async fn damage_pack(dir: &std::path::Path, objs: &[(ObjectId, Bytes, Bytes)]) -> (Arc<str>, Vec<u8>, Arc<Index>) {
        let objects = Objects::new(Arc::new(FsStore::new(dir)), 1 << 20);
        let (name, index, _) = objects.put_pack(1, 7, objs.iter().map(|(id, _, enc)| (*id, enc.clone())).collect()).await.unwrap();
        let bytes = std::fs::read(dir.join(crate::pack::key(1, &name))).unwrap();
        (name, bytes, index)
    }

    /// Guarantee 1 of S28 (cycle 3 review): a read of one packed object
    /// answers exactly that object, or refuses, however the pack or its
    /// index is damaged: any byte of the index, slots of other entries,
    /// ids of other entries, the pack truncated before or after its index
    /// was read, entries swapped in the pack. Whole, encoded, ranged,
    /// neighbour and blocking reads. (A boundary moved between two
    /// neighbouring slots is BUG-1497, below.)
    #[tokio::test]
    async fn packed_reads_answer_their_own_object_or_refuse_whatever_the_damage() {
        let dir = tempfile::tempdir().unwrap();
        let objs = damage_objects();
        let (name, intact, index) = damage_pack(dir.path(), &objs).await;
        let path = dir.path().join(crate::pack::key(1, &name));
        // Undamaged: every read answers.
        let all = reads_answer_their_own_objects(dir.path(), &name, &index, &objs, "intact").await;
        assert_eq!(all, objs.len() * 9, "every read of an intact pack answers");
        let hl = PACK_HEAD + objs.len() * PACK_ENTRY;
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        let (mut parsed, mut refused) = (0, 0);
        for case in 0..240 {
            let mut bytes = intact.clone();
            let mut stale: Option<Vec<u8>> = None;
            let kind = case % 6;
            let e = |i: u64| PACK_HEAD + i as usize * PACK_ENTRY;
            let n = objs.len() as u64;
            match kind {
                // Any byte of the head or the index.
                0 => {
                    let at = 10 + rng.below((hl - 10) as u64) as usize;
                    bytes[at] = rng.next() as u8;
                }
                // An entry's offset or length taken from another entry.
                1 => {
                    let (a, b) = (e(rng.below(n)), e(rng.below(n)));
                    let f = if rng.below(2) == 0 { 32..40 } else { 40..44 };
                    let v = bytes[b + f.start..b + f.end].to_vec();
                    bytes[a + f.start..a + f.end].copy_from_slice(&v);
                }
                // An entry's id: another's, or a fresh one.
                2 => {
                    let a = e(rng.below(n));
                    let id: [u8; 32] = if rng.below(2) == 0 {
                        let b = e(rng.below(n));
                        bytes[b..b + 32].try_into().unwrap()
                    } else {
                        ObjectId::hash(&rng.next().to_le_bytes()).0
                    };
                    bytes[a..a + 32].copy_from_slice(&id);
                }
                // Truncated before its index is read.
                3 => bytes.truncate(rng.below(intact.len() as u64) as usize),
                // Truncated after its index was read.
                4 => {
                    stale = Some(bytes.clone());
                    bytes.truncate(hl + rng.below((intact.len() - hl) as u64) as usize);
                }
                // Two slots of the same length swapped in the index (the
                // plain objects, all of one length), or their entries swapped
                // in the pack.
                _ => {
                    let plain: Vec<u64> = (0..n).filter(|i| u32::from_be_bytes(bytes[e(*i) + 40..e(*i) + 44].try_into().unwrap()) as usize == 32 + objs[0].2.len()).collect();
                    assert!(plain.len() >= 2, "plain objects of one length");
                    let (a, b) = (plain[rng.below(plain.len() as u64) as usize], plain[rng.below(plain.len() as u64) as usize]);
                    let (oa, ob) = (e(a), e(b));
                    if rng.below(2) == 0 {
                        let (sa, sb) = (bytes[oa + 32..oa + 40].to_vec(), bytes[ob + 32..ob + 40].to_vec());
                        bytes[oa + 32..oa + 40].copy_from_slice(&sb);
                        bytes[ob + 32..ob + 40].copy_from_slice(&sa);
                    } else {
                        let off = |o: usize| u64::from_be_bytes(intact[o + 32..o + 40].try_into().unwrap()) as usize;
                        let l = 32 + objs[0].2.len();
                        let (pa, pb) = (off(oa), off(ob));
                        let (ea, eb) = (intact[pa..pa + l].to_vec(), intact[pb..pb + l].to_vec());
                        bytes[pa..pa + l].copy_from_slice(&eb);
                        bytes[pb..pb + l].copy_from_slice(&ea);
                    }
                }
            }
            std::fs::write(&path, &bytes).unwrap();
            let seen = stale.as_deref().unwrap_or(&bytes);
            let damaged = match crate::pack::parse_index(seen, Some(seen.len() as u64)) {
                Ok(i) => Arc::new(i),
                Err(_) => {
                    refused += 1;
                    continue;
                }
            };
            parsed += 1;
            reads_answer_their_own_objects(dir.path(), &name, &damaged, &objs, &format!("case {case} (kind {kind})")).await;
        }
        println!("damage cases: {parsed} indexes accepted and read, {refused} refused");
        assert!(parsed >= 40 && refused >= 40, "both kinds of outcome are exercised: {parsed} read, {refused} refused");
    }

    /// BUG-1497 (S28 cycle 3 review; BUG-1394's class, a route the fix did
    /// not close): `pack::parse_index` checks that the slots tile the pack,
    /// so each slot ends where the next one starts, but not **where** that
    /// boundary lies. Move the boundary between two neighbouring slots (the
    /// first one longer by `d`, the next one starting `d` later and shorter
    /// by `d`: a merger's off-by-`d`, BUG-1154's model) and the slots still
    /// tile: the first passes its id check, and a ranged read of a plain
    /// object serves its own bytes and then the next entry's id and bytes
    /// (or, moved the other way, a length that is not the object's).
    #[tokio::test]
    #[ignore = "BUG-1497: a boundary moved between two neighbouring slots passes the tiling check, and a range serves the neighbour's bytes"]
    async fn bug_1497_a_boundary_moved_between_neighbours_never_serves_the_neighbours_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let objs = damage_objects();
        let (name, intact, _) = damage_pack(dir.path(), &objs).await;
        let path = dir.path().join(crate::pack::key(1, &name));
        let n = objs.len();
        let slot = |b: &[u8], i: usize| {
            let at = PACK_HEAD + i * PACK_ENTRY;
            (u64::from_be_bytes(b[at + 32..at + 40].try_into().unwrap()), u32::from_be_bytes(b[at + 40..at + 44].try_into().unwrap()))
        };
        let set = |b: &mut [u8], i: usize, off: u64, len: u32| {
            let at = PACK_HEAD + i * PACK_ENTRY;
            b[at + 32..at + 40].copy_from_slice(&off.to_be_bytes());
            b[at + 40..at + 44].copy_from_slice(&len.to_be_bytes());
        };
        // Neighbours by offset: (index entry of the first, of the next).
        let mut by_offset: Vec<usize> = (0..n).collect();
        by_offset.sort_by_key(|&i| slot(&intact, i).0);
        let mut moved = 0;
        for w in by_offset.windows(2) {
            let (a, b) = (w[0], w[1]);
            for d in [48i64, 33, 32, 31, 1, -1, -8] {
                let ((oa, la), (ob, lb)) = (slot(&intact, a), slot(&intact, b));
                let (la2, lb2) = (i64::from(la) + d, i64::from(lb) - d);
                if la2 <= 32 || lb2 <= 32 {
                    continue;
                }
                let mut bytes = intact.clone();
                set(&mut bytes, a, oa, la2 as u32);
                set(&mut bytes, b, (ob as i64 + d) as u64, lb2 as u32);
                std::fs::write(&path, &bytes).unwrap();
                let index = Arc::new(crate::pack::parse_index(&bytes, Some(bytes.len() as u64)).expect("the moved boundary still tiles the pack"));
                moved += 1;
                reads_answer_their_own_objects(dir.path(), &name, &index, &objs, &format!("the boundary after entry {a} moved by {d}")).await;
            }
        }
        assert!(moved >= 40, "boundaries moved: {moved}");
    }
}
