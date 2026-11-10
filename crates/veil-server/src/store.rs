//! Object storage (`docs/HUB.md` §2.1): immutable objects, each stored once
//! under its BLAKE3 id, per project. An object nothing references is
//! invisible: the server only ever serves objects it reached from a
//! committed snapshot, through the viewer's projection.
//!
//! [`BlobStore`] is the trait; [`FsStore`] keeps objects in a local
//! directory (development and unit tests), [`S3Store`] in an S3 bucket
//! (tested against MinIO).

use std::{borrow::Cow, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use veil_core::{cache::LruCache, hub::encoding, ObjectId};

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
        tokio::task::spawn_blocking(move || -> Result<Option<(Bytes, u64)>> {
            use std::io::{Read, Seek};
            let mut f = match std::fs::File::open(&path) {
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
        })
        .await?
    }

    fn get_blocking(&self, key: &str) -> Option<Result<Option<Bytes>>> {
        Some((|| match std::fs::read(self.path(key)?) {
            Ok(b) => Ok(Some(Bytes::from(b))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        })())
    }
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
/// every request the store sends is idempotent (GET, HEAD, and PUT of a
/// key that names its content).
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
/// smaller, under the same key (the id of the uncompressed object). Old
/// objects, stored as they are, stay readable. Every object read from the
/// store is decoded (bounded by the object size limit) and checked against
/// its id before it is cached or served.
pub struct Objects {
    store: Arc<dyn BlobStore>,
    /// Encodings, checked against their ids.
    cache: LruCache<Bytes>,
    /// Decoded canonical bytes for objects up to [`RAW_CACHE_MAX_OBJECT`],
    /// checked against their ids.
    raw_cache: LruCache<Bytes>,
    /// Requests to the store, for the benchmarks' cost gates
    /// (`storage-and-cost.md` §9): writes, bytes written, reads.
    pub writes: std::sync::atomic::AtomicU64,
    pub written_bytes: std::sync::atomic::AtomicU64,
    pub reads: std::sync::atomic::AtomicU64,
}

/// The largest object the store holds, decoded: the largest a frame
/// carries.
const MAX_OBJECT: u64 = veil_core::hub::wire::MAX_FRAME_OBJECT as u64;
/// Largest decoded object cached in [`Objects::raw_cache`].
const RAW_CACHE_MAX_OBJECT: usize = 1 << 20;

/// The object `id` decoded from its encoding `enc`, checked.
fn decoded(id: &ObjectId, enc: &Bytes) -> Result<Bytes> {
    match encoding::decode(id, enc, MAX_OBJECT).map_err(|_| anyhow!("stored object {} does not match its id", id.short()))? {
        Cow::Borrowed(_) => Ok(enc.clone()),
        Cow::Owned(raw) => Ok(Bytes::from(raw)),
    }
}

/// [`decoded`] for an entry in [`Objects::cache`], which was already checked
/// against `id` before insertion.
fn decoded_cached(id: &ObjectId, enc: &Bytes) -> Result<Bytes> {
    match encoding::decode_trusted(id, enc, MAX_OBJECT).map_err(|_| anyhow!("stored object {} does not match its id", id.short()))? {
        Cow::Borrowed(_) => Ok(enc.clone()),
        Cow::Owned(raw) => Ok(Bytes::from(raw)),
    }
}

impl Objects {
    pub fn new(store: Arc<dyn BlobStore>, cache_bytes: usize) -> Objects {
        let raw_bytes = (cache_bytes / 4).max(1);
        let enc_bytes = cache_bytes.saturating_sub(raw_bytes).max(1);
        Objects {
            store,
            cache: LruCache::new(enc_bytes),
            raw_cache: LruCache::new(raw_bytes),
            writes: Default::default(),
            written_bytes: Default::default(),
            reads: Default::default(),
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
        let mut out = id.0;
        let p = project.to_le_bytes();
        for i in 0..8 {
            out[i] ^= p[i];
        }
        ObjectId(out)
    }

    /// The object `id` of `project` (its canonical encoding), checked
    /// against its id.
    pub async fn get(&self, project: i64, id: &ObjectId) -> Result<Option<Bytes>> {
        let ck = Self::cache_key(project, id);
        if let Some(raw) = self.raw_cache.get(&ck) {
            return Ok(Some(raw));
        }
        match self.cache.get(&ck) {
            Some(enc) => {
                let raw = decoded_cached(id, &enc)?;
                if raw.len() <= RAW_CACHE_MAX_OBJECT {
                    self.raw_cache.insert(ck, raw.clone(), raw.len());
                }
                Ok(Some(raw))
            }
            None => {
                self.reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.load(project, id, self.store.get(&object_key(project, id)).await?)
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
        self.reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Some(enc) = self.store.get(&object_key(project, id)).await? else {
            return Ok(None);
        };
        let raw = decoded(id, &enc)?;
        self.cache.insert(ck, enc.clone(), enc.len());
        if raw.len() <= RAW_CACHE_MAX_OBJECT {
            self.raw_cache.insert(ck, raw.clone(), raw.len());
        }
        Ok(Some(enc))
    }

    /// Check and cache the encoding the store answered; the object decoded.
    fn load(&self, project: i64, id: &ObjectId, enc: Option<Bytes>) -> Result<Option<Bytes>> {
        let Some(enc) = enc else { return Ok(None) };
        let raw = decoded(id, &enc)?;
        let ck = Self::cache_key(project, id);
        self.cache.insert(ck, enc.clone(), enc.len());
        if raw.len() <= RAW_CACHE_MAX_OBJECT {
            self.raw_cache.insert(ck, raw.clone(), raw.len());
        }
        Ok(Some(raw))
    }

    /// [`Objects::get`] from a blocking thread: a local store is read
    /// directly; any other through `rt`.
    pub fn get_blocking(&self, rt: &tokio::runtime::Handle, project: i64, id: &ObjectId) -> Result<Option<Bytes>> {
        let ck = Self::cache_key(project, id);
        if let Some(raw) = self.raw_cache.get(&ck) {
            return Ok(Some(raw));
        }
        if let Some(enc) = self.cache.get(&ck) {
            let raw = decoded_cached(id, &enc)?;
            if raw.len() <= RAW_CACHE_MAX_OBJECT {
                self.raw_cache.insert(ck, raw.clone(), raw.len());
            }
            return Ok(Some(raw));
        }
        let Some(r) = self.store.get_blocking(&object_key(project, id)) else {
            return rt.block_on(self.get(project, id));
        };
        self.reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.load(project, id, r?)
    }

    /// Store object `id` (its canonical encoding `raw`), compressed when
    /// that is smaller.
    pub async fn put(&self, project: i64, id: &ObjectId, raw: Bytes) -> Result<()> {
        if raw.len() <= RAW_CACHE_MAX_OBJECT {
            self.raw_cache.insert(Self::cache_key(project, id), raw.clone(), raw.len());
        }
        let enc = match encoding::encode(&raw) {
            Cow::Borrowed(_) => raw,
            Cow::Owned(z) => Bytes::from(z),
        };
        self.put_encoded(project, id, enc).await
    }

    /// Store `enc`, an encoding of object `id` the caller has checked.
    pub async fn put_encoded(&self, project: i64, id: &ObjectId, enc: Bytes) -> Result<()> {
        self.writes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.written_bytes.fetch_add(enc.len() as u64, std::sync::atomic::Ordering::Relaxed);
        self.store.put(&object_key(project, id), enc.clone()).await?;
        self.cache.insert(Self::cache_key(project, id), enc.clone(), enc.len());
        Ok(())
    }

    /// Bytes `start..=end` of object `id` of `project` (its canonical
    /// encoding, never of what is stored) and its length, `end` clamped
    /// (`u64::MAX`: to the end). An object stored as it is (S27's plain
    /// encoding) is read for those bytes only. A compressed one is decoded
    /// whole, as every read is (checked against its id, its decoded bytes
    /// counted in [`DECODED_IN_FLIGHT`] while held), then sliced. A part of
    /// a plain object cannot be checked against the id: the client checks
    /// the object it puts together.
    pub async fn get_range(&self, project: i64, id: &ObjectId, start: u64, end: u64) -> Result<Option<(Bytes, u64)>> {
        let key = object_key(project, id);
        let cached = self.cache.get(&Self::cache_key(project, id));
        let plain = match &cached {
            Some(enc) => !encoding::is_compressed(enc),
            None => {
                let Some((head, _)) = self.store.get_range(&key, 0, encoding::HEADER as u64 - 1).await? else { return Ok(None) };
                !encoding::is_compressed(&head)
            }
        };
        if plain {
            return match cached {
                Some(enc) => Ok(Some((slice(&enc, start, end), enc.len() as u64))),
                None => self.store.get_range(&key, start, end).await,
            };
        }
        let cost = self.read_cost(project, id, 0).await?;
        let _held = ReadAhead::wait(cost).await;
        Ok(self.get(project, id).await?.map(|raw| (slice(&raw, start, end), raw.len() as u64)))
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
            None => match self.store.get_range(&object_key(project, id), 0, encoding::HEADER as u64 - 1).await? {
                Some((head, len)) => encoding::declared_len(&head, len),
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
        self.store.exists(&object_key(project, id)).await
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
}
