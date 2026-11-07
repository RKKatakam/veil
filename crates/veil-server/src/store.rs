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
    /// A read that needs no async runtime (a local file), for code already
    /// on a blocking thread; `None`: use [`BlobStore::get`].
    fn get_blocking(&self, _key: &str) -> Option<Result<Option<Bytes>>> {
        None
    }
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
    let deadline = tokio::time::Instant::now() + S3_RETRY_FOR;
    let mut wait = S3_FIRST_WAIT;
    for tries in 1.. {
        let answer = match make().send().await {
            Ok(resp) => {
                let status = resp.status();
                resp.bytes().await.map(|body| (status, body))
            }
            Err(e) => Err(e),
        };
        let jitter = Duration::from_millis(u64::from(u16::from_le_bytes(veil_core::crypto::random_bytes::<2>())) % (wait.as_millis() as u64 + 1));
        let last = tokio::time::Instant::now() + wait + jitter >= deadline;
        match answer {
            // 429: the store asks for fewer requests (BUG-1005, BUG-1053).
            Ok((status, body)) if !(status.is_server_error() || status.as_u16() == 429) || last => return Ok((status.as_u16(), body)),
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
    /// Requests to the store, for the benchmarks' cost gates
    /// (`storage-and-cost.md` §9): writes, bytes written, reads.
    pub writes: std::sync::atomic::AtomicU64,
    pub written_bytes: std::sync::atomic::AtomicU64,
    pub reads: std::sync::atomic::AtomicU64,
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

impl Objects {
    pub fn new(store: Arc<dyn BlobStore>, cache_bytes: usize) -> Objects {
        Objects {
            store,
            cache: LruCache::new(cache_bytes),
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
        let mut h = blake3::Hasher::new();
        h.update(&project.to_le_bytes());
        h.update(&id.0);
        ObjectId(*h.finalize().as_bytes())
    }

    /// The object `id` of `project` (its canonical encoding), checked
    /// against its id.
    pub async fn get(&self, project: i64, id: &ObjectId) -> Result<Option<Bytes>> {
        match self.cache.get(&Self::cache_key(project, id)) {
            Some(enc) => decoded(id, &enc).map(Some),
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
        decoded(id, &enc)?;
        self.cache.insert(ck, enc.clone(), enc.len());
        Ok(Some(enc))
    }

    /// Check and cache the encoding the store answered; the object decoded.
    fn load(&self, project: i64, id: &ObjectId, enc: Option<Bytes>) -> Result<Option<Bytes>> {
        let Some(enc) = enc else { return Ok(None) };
        let raw = decoded(id, &enc)?;
        self.cache.insert(Self::cache_key(project, id), enc.clone(), enc.len());
        Ok(Some(raw))
    }

    /// [`Objects::get`] from a blocking thread: a local store is read
    /// directly; any other through `rt`.
    pub fn get_blocking(&self, rt: &tokio::runtime::Handle, project: i64, id: &ObjectId) -> Result<Option<Bytes>> {
        if let Some(enc) = self.cache.get(&Self::cache_key(project, id)) {
            return decoded(id, &enc).map(Some);
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
