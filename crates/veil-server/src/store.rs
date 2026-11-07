//! Object storage (`docs/HUB.md` §2.1): immutable objects, each stored once
//! under its BLAKE3 id, per project. An object nothing references is
//! invisible: the server only ever serves objects it reached from a
//! committed snapshot, through the viewer's projection.
//!
//! [`BlobStore`] is the trait; [`FsStore`] keeps objects in a local
//! directory (development and unit tests), [`S3Store`] in an S3 bucket
//! (tested against MinIO).

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use veil_core::{cache::LruCache, ObjectId};

#[async_trait]
pub trait BlobStore: Send + Sync {
    /// The object at `key`, `None` if there is none.
    async fn get(&self, key: &str) -> Result<Option<Bytes>>;
    /// Store `data` at `key`. Keys name immutable content: writing the
    /// same key twice writes the same bytes.
    async fn put(&self, key: &str, data: Bytes) -> Result<()>;
    async fn exists(&self, key: &str) -> Result<bool>;
    /// Bytes `start..=end` of the object at `key` (`end` clamped to its
    /// last byte; empty when `start` is past it) and the object's length;
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
/// answer, again while the answer is a server error (5xx) or the request
/// fails, for at most [`S3_RETRY_FOR`] (BUG-861). A connection the store
/// closed, reset or timed out, before or during the answer, and the
/// store's own transient errors (500, 503 "slow down"), are tried again:
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
            Ok((status, headers, body)) if !status.is_server_error() || last => return Ok((status.as_u16(), headers, body)),
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
        let range = format!("bytes={start}-{end}");
        let (status, headers, body) = s3_send_with_headers(|| self.http.get(url.clone()).header("range", &range)).await?;
        // `Content-Range: bytes a-b/len` (206) or `bytes */len` (416).
        let len = || -> Result<u64> {
            let v = headers.get("content-range").and_then(|v| v.to_str().ok()).unwrap_or_default();
            v.rsplit_once('/').and_then(|(_, l)| l.parse().ok()).ok_or_else(|| anyhow!("S3 GET with a range: no length in {v:?}"))
        };
        match status {
            206 => Ok(Some((body, len()?))),
            416 => Ok(Some((Bytes::new(), len()?))),
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
}

/// The objects of every project, through an in-memory cache of recently
/// read objects (objects are immutable, so the cache never goes stale).
pub struct Objects {
    store: Arc<dyn BlobStore>,
    cache: LruCache<Bytes>,
}

impl Objects {
    pub fn new(store: Arc<dyn BlobStore>, cache_bytes: usize) -> Objects {
        Objects {
            store,
            cache: LruCache::new(cache_bytes),
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

    /// The raw object `id` of `project`, checked against its id.
    pub async fn get(&self, project: i64, id: &ObjectId) -> Result<Option<Bytes>> {
        let ck = Self::cache_key(project, id);
        if let Some(b) = self.cache.get(&ck) {
            return Ok(Some(b));
        }
        let Some(b) = self.store.get(&object_key(project, id)).await? else {
            return Ok(None);
        };
        if ObjectId::hash(&b) != *id {
            bail!("stored object {} does not match its id", id.short());
        }
        self.cache.insert(ck, b.clone(), b.len());
        Ok(Some(b))
    }

    /// [`Objects::get`] from a blocking thread: a local store is read
    /// directly; any other through `rt`.
    pub fn get_blocking(&self, rt: &tokio::runtime::Handle, project: i64, id: &ObjectId) -> Result<Option<Bytes>> {
        let ck = Self::cache_key(project, id);
        if let Some(b) = self.cache.get(&ck) {
            return Ok(Some(b));
        }
        let Some(r) = self.store.get_blocking(&object_key(project, id)) else {
            return rt.block_on(self.get(project, id));
        };
        let Some(b) = r? else { return Ok(None) };
        if ObjectId::hash(&b) != *id {
            bail!("stored object {} does not match its id", id.short());
        }
        self.cache.insert(ck, b.clone(), b.len());
        Ok(Some(b))
    }

    pub async fn put(&self, project: i64, id: &ObjectId, raw: Bytes) -> Result<()> {
        self.store.put(&object_key(project, id), raw.clone()).await?;
        self.cache.insert(Self::cache_key(project, id), raw.clone(), raw.len());
        Ok(())
    }

    /// Bytes `start..=end` of object `id` of `project` and its length (see
    /// [`BlobStore::get_range`]): from the cache if it holds the object,
    /// else only those bytes from the store. A part cannot be checked
    /// against the id: the client checks the object it puts together.
    pub async fn get_range(&self, project: i64, id: &ObjectId, start: u64, end: u64) -> Result<Option<(Bytes, u64)>> {
        if let Some(b) = self.cache.get(&Self::cache_key(project, id)) {
            return Ok(Some((slice(&b, start, end), b.len() as u64)));
        }
        self.store.get_range(&object_key(project, id), start, end).await
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
}