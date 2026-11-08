//! Request bodies read under a memory budget (BUG-1187, `docs/HUB.md`
//! §13.25). Every body the server holds is counted, in KiB, against one of
//! two pools: the signed-in pool (a session this server knows) and the
//! anonymous pool (everyone else, an eighth of the budget), so no number
//! of clients holds more than the budget, and anonymous ones cannot take
//! the signed-in share.
//!
//! * A body of declared length takes its whole share in one step before
//!   any of it is read (waiting at most [`SHARE_WAIT`], else `busy`), so
//!   bodies never hold part of the pool while waiting for the rest. A body
//!   larger than its pool takes the whole pool.
//! * A body of unknown length (chunked) takes twice what it has received
//!   as it grows (its buffer doubles), and is refused `busy` the moment
//!   its pool has no more.
//! * A body arrives at [`MIN_RATE`] on average after [`GRACE`] or is
//!   refused `408` (the cache's rule, BUG-1183), so a body of `n` bytes
//!   holds its share and its connection for at most `GRACE + n / MIN_RATE`.
//!
//! * One client (a device, or an address) holds at most a quarter of its
//!   pool at once, so one cannot refuse the others: an anonymous body is at
//!   most a quarter of the anonymous pool (16 MiB by default), and a
//!   signed-in one larger than that (a large file's upload, up to the
//!   route's 2 GiB) only while its device holds nothing else, taking at
//!   most the whole pool.
//!
//! The share is held until the request's answer is made.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::body::{Body, Bytes};
use bytes::BytesMut;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::bucket::Key;

/// The slowest body served after the grace, in bytes a second: 128 kbit/s,
/// a slow mobile link (as the regional cache, `cache::MIN_RATE`).
pub const MIN_RATE: u64 = 16 << 10;
/// How long a body may take before [`MIN_RATE`] counts.
pub const GRACE: Duration = Duration::from_secs(20);
/// The longest a body waits for its share before it is refused `busy`.
pub const SHARE_WAIT: Duration = Duration::from_secs(10);
/// The share a body of unknown length starts with.
const FIRST: u64 = 64 << 10;

#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// Past the route's limit (`413`).
    TooLarge,
    /// Below the minimum rate (`408`).
    Late,
    /// Broken off, or not a body (`400`).
    Unreadable,
    /// Its share is not free (`503 busy`).
    Busy,
}

/// The two pools of the budget, and what each client holds of them.
pub struct Pools {
    signed: Arc<Semaphore>,
    anonymous: Arc<Semaphore>,
    signed_kib: u32,
    anonymous_kib: u32,
    /// KiB held per device or address.
    held: Arc<Mutex<HashMap<Key, u32>>>,
}

/// A body's share: of its pool, and of its client's quarter. Given back
/// when dropped.
#[derive(Debug)]
pub struct Share {
    permit: OwnedSemaphorePermit,
    key: Key,
    held: Arc<Mutex<HashMap<Key, u32>>>,
}

impl Share {
    fn kib(&self) -> u32 {
        self.permit.num_permits() as u32
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        let mut h = self.held.lock().unwrap();
        if let Some(n) = h.get_mut(&self.key) {
            *n = n.saturating_sub(self.kib());
            if *n == 0 {
                h.remove(&self.key);
            }
        }
    }
}

/// KiB, rounded up, within `u32`.
fn kib(n: u64) -> u32 {
    n.div_ceil(1024).min(u64::from(u32::MAX >> 4)) as u32
}

impl Pools {
    /// `budget` bytes: an eighth for anonymous bodies (at least 4 MiB), the
    /// rest for signed-in ones.
    pub fn new(budget: u64) -> Pools {
        let anonymous_kib = kib((budget / 8).max(4 << 20));
        let signed_kib = kib(budget).saturating_sub(anonymous_kib).max(kib(4 << 20));
        Pools {
            signed: Arc::new(Semaphore::new(signed_kib as usize)),
            anonymous: Arc::new(Semaphore::new(anonymous_kib as usize)),
            signed_kib,
            anonymous_kib,
            held: Default::default(),
        }
    }

    fn pool(&self, signed: bool) -> (&Arc<Semaphore>, u32) {
        if signed {
            (&self.signed, self.signed_kib)
        } else {
            (&self.anonymous, self.anonymous_kib)
        }
    }

    /// KiB held now, signed-in and anonymous.
    pub fn held_kib(&self) -> (u32, u32) {
        (self.signed_kib - self.signed.available_permits() as u32, self.anonymous_kib - self.anonymous.available_permits() as u32)
    }

    /// The most bytes of one anonymous body: a quarter of its pool.
    pub fn anonymous_limit(&self) -> u64 {
        u64::from(self.anonymous_kib / 4) << 10
    }

    /// Count `n` more KiB against `key`'s quarter of its pool: a client
    /// holds at most a quarter, except one signed-in body larger than that
    /// (an upload of a large file) while it holds nothing else.
    fn claim(&self, key: Key, signed: bool, n: u32, first: bool) -> bool {
        let quarter = self.pool(signed).1 / 4;
        let mut h = self.held.lock().unwrap();
        let cur = h.get(&key).copied().unwrap_or(0);
        if cur + n > quarter && !(signed && first && cur == 0) {
            return false;
        }
        h.insert(key, cur + n);
        true
    }

    fn unclaim(&self, key: Key, n: u32) {
        let mut h = self.held.lock().unwrap();
        if let Some(c) = h.get_mut(&key) {
            *c = c.saturating_sub(n);
            if *c == 0 {
                h.remove(&key);
            }
        }
    }

    /// Read `body` (`declared` bytes, if its head said; at most `limit`,
    /// and a quarter of the anonymous pool if not `signed`) for `key`,
    /// under a share of the signed-in or the anonymous pool.
    pub async fn read(&self, key: Key, signed: bool, mut body: Body, declared: Option<u64>, limit: u64) -> Result<(Bytes, Option<Share>), Refused> {
        if declared == Some(0) {
            return Ok((Bytes::new(), None));
        }
        let limit = if signed { limit } else { limit.min(self.anonymous_limit()) };
        if declared.is_some_and(|n| n > limit) {
            return Err(Refused::TooLarge);
        }
        let (pool, total) = self.pool(signed);
        let want = |n: u64| kib(n).min(total);
        let first = want(declared.unwrap_or(FIRST));
        if !self.claim(key, signed, first, true) {
            return Err(Refused::Busy);
        }
        let permit = match tokio::time::timeout(SHARE_WAIT, pool.clone().acquire_many_owned(first)).await {
            Ok(Ok(p)) => p,
            _ => {
                self.unclaim(key, first);
                return Err(Refused::Busy);
            }
        };
        let mut share = Share { permit, key, held: self.held.clone() };
        let mut buf = BytesMut::with_capacity(declared.unwrap_or(0) as usize);
        let start = tokio::time::Instant::now();
        loop {
            let due = start + GRACE + Duration::from_secs_f64(buf.len() as f64 / MIN_RATE as f64);
            let chunk = match tokio::time::timeout_at(due, next_chunk(&mut body)).await {
                Err(_) => return Err(Refused::Late),
                Ok(Some(Err(_))) => return Err(Refused::Unreadable),
                Ok(None) => break,
                Ok(Some(Ok(c))) => c,
            };
            let len = (buf.len() + chunk.len()) as u64;
            if len > limit || declared.is_some_and(|n| len > n) {
                return Err(if len > limit { Refused::TooLarge } else { Refused::Unreadable });
            }
            if declared.is_none() {
                // The buffer may double: count twice what it holds.
                let more = want(2 * len).saturating_sub(share.kib());
                if more > 0 {
                    if !self.claim(key, signed, more, false) {
                        return Err(Refused::Busy);
                    }
                    match pool.clone().try_acquire_many_owned(more) {
                        Ok(m) => share.permit.merge(m),
                        Err(_) => {
                            self.unclaim(key, more);
                            return Err(Refused::Busy);
                        }
                    }
                }
            }
            buf.extend_from_slice(&chunk);
        }
        if declared.is_some_and(|n| buf.len() as u64 != n) {
            return Err(Refused::Unreadable);
        }
        Ok((buf.freeze(), Some(share)))
    }
}

/// The next bytes of a body; `None` at its end.
async fn next_chunk(body: &mut Body) -> Option<Result<Bytes, axum::Error>> {
    use hyper::body::Body as _;
    loop {
        match std::future::poll_fn(|cx| std::pin::Pin::new(&mut *body).poll_frame(cx)).await? {
            Ok(f) => match f.into_data() {
                Ok(d) if !d.is_empty() => return Some(Ok(d)),
                _ => continue,
            },
            Err(e) => return Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        pin::Pin,
        task::{Context, Poll},
    };

    /// A body that sends `chunks`, then ends or stalls for ever.
    struct Chunks {
        chunks: VecDeque<Bytes>,
        end: bool,
    }

    impl hyper::body::Body for Chunks {
        type Data = Bytes;
        type Error = std::io::Error;
        fn poll_frame(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<hyper::body::Frame<Bytes>, std::io::Error>>> {
            match self.chunks.pop_front() {
                Some(c) => Poll::Ready(Some(Ok(hyper::body::Frame::data(c)))),
                None if self.end => Poll::Ready(None),
                None => Poll::Pending,
            }
        }
    }

    fn body(chunks: &[usize], end: bool) -> Body {
        Body::new(Chunks { chunks: chunks.iter().map(|n| Bytes::from(vec![b'x'; *n])).collect(), end })
    }

    const A: Key = Key::Ip(1);
    const B: Key = Key::Ip(2);
    const D: Key = Key::Device([1; 32]);
    const E: Key = Key::Device([2; 32]);

    /// Declared bodies take their whole share before reading and hold it
    /// until dropped; a share that is not free is `busy` after a short
    /// wait, never a wait while holding part of the pool.
    #[tokio::test(start_paused = true)]
    async fn bodies_are_read_only_under_a_share_of_the_budget() {
        let pools = Pools::new(32 << 20);
        assert_eq!((pools.signed_kib, pools.anonymous_kib), (28 << 10, 4 << 10), "an eighth, at least 4 MiB, for anonymous bodies");
        let (b, share) = pools.read(D, true, body(&[1 << 20, 1 << 20], true), Some(2 << 20), 64 << 20).await.unwrap();
        assert_eq!(b.len(), 2 << 20);
        assert_eq!(pools.held_kib(), (2048, 0));
        // Four addresses take the anonymous pool, a quarter each; a fifth waits, then is busy.
        let mut held = Vec::new();
        for k in 1..=4 {
            held.push(pools.read(Key::Ip(10 + k), false, body(&[1 << 20], true), Some(1 << 20), 64 << 20).await.unwrap().1);
        }
        assert_eq!(pools.held_kib(), (2048, 4096));
        assert_eq!(pools.read(A, false, body(&[10], true), Some(10), 64 << 20).await.unwrap_err(), Refused::Busy);
        // The signed-in pool is apart.
        assert!(pools.read(E, true, body(&[10], true), Some(10), 64 << 20).await.is_ok());
        drop((share, held));
        assert_eq!(pools.held_kib(), (0, 0));
        assert!(pools.held.lock().unwrap().is_empty(), "nothing is kept for clients holding nothing");
    }

    /// One client holds at most a quarter of its pool: an anonymous body
    /// past it is too large, a second one is busy; a signed-in device may
    /// send one body larger than that (a large file) while it holds nothing
    /// else, taking at most the whole pool.
    #[tokio::test(start_paused = true)]
    async fn one_client_holds_at_most_a_quarter_of_its_pool() {
        let pools = Pools::new(32 << 20);
        assert_eq!(pools.anonymous_limit(), 1 << 20);
        assert_eq!(pools.read(A, false, body(&[], true), Some(2 << 20), 64 << 20).await.unwrap_err(), Refused::TooLarge);
        let (_, a1) = pools.read(A, false, body(&[600 << 10], true), Some(600 << 10), 64 << 20).await.unwrap();
        assert_eq!(pools.read(A, false, body(&[600 << 10], true), Some(600 << 10), 64 << 20).await.unwrap_err(), Refused::Busy);
        assert!(pools.read(B, false, body(&[600 << 10], true), Some(600 << 10), 64 << 20).await.is_ok(), "another address is not refused");
        drop(a1);
        // A large upload: more than the signed-in pool, alone.
        let (big, all) = pools.read(D, true, body(&[20 << 20, 20 << 20], true), Some(40 << 20), 2 << 30).await.unwrap();
        assert_eq!(big.len(), 40 << 20);
        assert_eq!(pools.held_kib().0, 28 << 10, "the whole pool, no more");
        assert_eq!(pools.read(D, true, body(&[10], true), Some(10), 64 << 20).await.unwrap_err(), Refused::Busy);
        drop(all);
        assert_eq!(pools.held_kib(), (0, 0));
    }

    /// A body of unknown length grows its share as it arrives, and is
    /// refused the moment its pool or its client's quarter has no more;
    /// past the route's limit it is too large.
    #[tokio::test(start_paused = true)]
    async fn chunked_bodies_grow_their_share_or_are_refused() {
        let pools = Pools::new(32 << 20);
        let (b, share) = pools.read(A, false, body(&[100 << 10, 100 << 10], true), None, 64 << 20).await.unwrap();
        assert_eq!(b.len(), 200 << 10);
        assert_eq!(pools.held_kib().1, 400, "twice what it holds");
        drop(share);
        // Past the client's quarter.
        assert_eq!(pools.read(A, false, body(&[400 << 10, 400 << 10], true), None, 64 << 20).await.unwrap_err(), Refused::Busy);
        // Past the anonymous limit (a quarter of the pool).
        assert_eq!(pools.read(A, false, body(&[2 << 20], true), None, 64 << 20).await.unwrap_err(), Refused::TooLarge);
        assert_eq!(pools.held_kib(), (0, 0), "a refused body gives its share back");
        assert_eq!(pools.read(D, true, body(&[1 << 20, 1 << 20], true), None, 1 << 20).await.unwrap_err(), Refused::TooLarge);
        assert_eq!(pools.read(D, true, body(&[], true), Some(2 << 20), 1 << 20).await.unwrap_err(), Refused::TooLarge);
        // A declared length the body does not keep to.
        assert_eq!(pools.read(D, true, body(&[10], true), Some(20), 1 << 20).await.unwrap_err(), Refused::Unreadable);
        assert_eq!(pools.held_kib(), (0, 0));
        assert!(pools.held.lock().unwrap().is_empty());
    }

    /// BUG-1187's class: a body that stops is refused after the grace plus
    /// a second per 16 KiB received, and its share comes back.
    #[tokio::test(start_paused = true)]
    async fn a_body_that_stops_is_refused_in_bounded_time() {
        let pools = Pools::new(32 << 20);
        let t = tokio::time::Instant::now();
        let r = pools.read(A, false, body(&[160 << 10], false), Some(1 << 20), 64 << 20).await;
        assert_eq!(r.unwrap_err(), Refused::Late);
        let took = t.elapsed();
        assert!(took >= GRACE + Duration::from_secs(10) && took < GRACE + Duration::from_secs(11), "{took:?}");
        assert_eq!(pools.held_kib(), (0, 0));
    }
}
