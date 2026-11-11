//! Request bodies read under a memory budget (BUG-1187, BUG-1333;
//! `docs/HUB.md` §13.25). Every byte of a body the server holds is counted,
//! in KiB, against one of three pools of the budget:
//!
//! * **the reserve** (an eighth, at least 4 MiB), for small bodies (a
//!   declared length of at most [`SMALL`]: sign-in, most pushes, fetches,
//!   queries), which no large body can take;
//! * **the anonymous pool** (a quarter, at least 4 MiB), for everyone without
//!   a session this server knows;
//! * **the signed-in pool**, the rest.
//!
//! A small body grows in the reserve first, then in its own pool.
//!
//! * **A body holds what has arrived, no more**: its share grows as its
//!   bytes come (a body of unknown length twice that: its buffer may
//!   double), so a client that sends a head and nothing holds nothing.
//!   Growth is refused `busy` the moment its pool, or its client's part of
//!   it, has no more.
//! * **One client** (a person, or an address) holds at most a quarter of
//!   each pool, so one cannot refuse the others. An anonymous body is at
//!   most a quarter of the anonymous pool (32 MiB by default). A signed-in
//!   body larger than that (a large file's upload, up to the route's 2 GiB)
//!   may grow past its quarter while it is all its person holds, up to the
//!   whole signed-in pool; past the pool its bytes are not counted (one
//!   such body at a time).
//! * **A body must keep arriving** (`Arrival`): after a grace of 20 s,
//!   16 KiB/s on average (the cache's rule, BUG-1183), at least 8 KiB/s in
//!   every 20 s window, and it may hold at most what it sends in 10 minutes
//!   at its last window's rate. A slow client therefore holds in proportion
//!   to its rate, and a client that stops is cut off within 20 s.
//!
//! The share is held until the request's answer is made.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::body::{Body, Bytes};
use bytes::BytesMut;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

use super::bucket::Key;

/// The slowest body served after the grace, on average, in bytes a second:
/// 128 kbit/s, a slow mobile link (as the regional cache, `cache::MIN_RATE`).
pub const MIN_RATE: u64 = 16 << 10;
/// How long a body may take before the rate counts.
pub const GRACE: Duration = Duration::from_secs(20);
/// After the grace, every window of this length must bring [`WINDOW_BYTES`].
pub const WINDOW: Duration = Duration::from_secs(20);
/// Half of [`MIN_RATE`] over a [`WINDOW`].
pub const WINDOW_BYTES: u64 = MIN_RATE * 20 / 2;
/// A body holds at most this long's worth of its last window's rate.
pub const HOLD: Duration = Duration::from_secs(600);
/// What a body may hold whatever its rate.
const FREE_HOLD: u64 = 1 << 20;
/// The largest declared body that grows in the reserve first.
pub const SMALL: u64 = 1 << 20;
/// How long a large upload waits for room in the signed-in pool while it
/// is all its device holds.
pub const SHARE_WAIT: Duration = Duration::from_secs(10);

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

const RESERVE: usize = 0;
const SIGNED: usize = 1;
const ANONYMOUS: usize = 2;

struct Pool {
    sem: Arc<Semaphore>,
    kib: u32,
}

type Held = Arc<Mutex<HashMap<(Key, usize), u32>>>;

/// The pools of the budget, and what each client holds of each.
pub struct Pools {
    pools: [Pool; 3],
    held: Held,
}

/// A body's share: of its pools, and of its client's part of each. Given
/// back when dropped.
#[derive(Debug)]
pub struct Share {
    permits: Vec<(usize, OwnedSemaphorePermit)>,
    key: Key,
    held: Held,
}

impl Share {
    fn kib(&self) -> u32 {
        self.permits.iter().map(|(_, p)| p.num_permits() as u32).sum()
    }

    fn kib_in(&self, pool: usize) -> u32 {
        self.permits.iter().filter(|(i, _)| *i == pool).map(|(_, p)| p.num_permits() as u32).sum()
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        let mut h = self.held.lock().unwrap();
        for (i, p) in &self.permits {
            let k = (self.key, *i);
            if let Some(n) = h.get_mut(&k) {
                *n = n.saturating_sub(p.num_permits() as u32);
                if *n == 0 {
                    h.remove(&k);
                }
            }
        }
    }
}

/// KiB, rounded up, within `u32`.
fn kib(n: u64) -> u32 {
    n.div_ceil(1024).min(u64::from(u32::MAX >> 4)) as u32
}

impl Pools {
    /// `budget` bytes: an eighth for the reserve and a quarter for
    /// anonymous bodies (each at least 4 MiB), the rest signed-in.
    pub fn new(budget: u64) -> Pools {
        let reserve = kib((budget / 8).max(4 << 20));
        let anonymous = kib((budget / 4).max(4 << 20));
        let signed = kib(budget).saturating_sub(reserve + anonymous).max(kib(4 << 20));
        let pool = |kib: u32| Pool { sem: Arc::new(Semaphore::new(kib as usize)), kib };
        Pools { pools: [pool(reserve), pool(signed), pool(anonymous)], held: Default::default() }
    }

    fn held_in(&self, i: usize) -> u32 {
        self.pools[i].kib - self.pools[i].sem.available_permits() as u32
    }

    /// KiB held now in the signed-in and anonymous pools.
    pub fn held_kib(&self) -> (u32, u32) {
        (self.held_in(SIGNED), self.held_in(ANONYMOUS))
    }

    /// KiB held now in the reserve.
    pub fn reserve_kib(&self) -> u32 {
        self.held_in(RESERVE)
    }

    /// The most bytes of one anonymous body: a quarter of its pool.
    pub fn anonymous_limit(&self) -> u64 {
        u64::from(self.pools[ANONYMOUS].kib / 4) << 10
    }

    /// Grow `share` to `need` KiB in `order`'s pools, within what each pool
    /// has free and the client's quarter of it (`large`: the signed-in
    /// pool's whole, while this body is all the client holds there).
    /// `false` if it cannot.
    fn grow(&self, share: &mut Share, order: &[usize], large: bool, need: u32) -> bool {
        let mut more = need.saturating_sub(share.kib());
        for &i in order {
            if more == 0 {
                break;
            }
            let pool = &self.pools[i];
            let mut h = self.held.lock().unwrap();
            let cur = h.get(&(share.key, i)).copied().unwrap_or(0);
            let room = if large && i == SIGNED && cur == share.kib_in(i) { pool.kib } else { pool.kib / 4 }.saturating_sub(cur);
            let n = more.min(room).min(pool.sem.available_permits() as u32);
            if n == 0 {
                continue;
            }
            if let Ok(p) = pool.sem.clone().try_acquire_many_owned(n) {
                *h.entry((share.key, i)).or_default() += n;
                share.permits.push((i, p));
                more -= n;
            }
        }
        more == 0
    }

    /// Read `body` (`declared` bytes, if its head said; at most `limit`,
    /// and a quarter of the anonymous pool if not `signed`) for `key`,
    /// under a share that grows as it arrives.
    pub async fn read(&self, key: Key, signed: bool, body: &mut Body, declared: Option<u64>, limit: u64) -> Result<(Bytes, Option<Share>), Refused> {
        if declared == Some(0) {
            return Ok((Bytes::new(), None));
        }
        let main = if signed { SIGNED } else { ANONYMOUS };
        let limit = if signed { limit } else { limit.min(self.anonymous_limit()) };
        if declared.is_some_and(|n| n > limit) {
            return Err(Refused::TooLarge);
        }
        let small = declared.is_some_and(|n| n <= SMALL);
        let order: &[usize] = if small { &[RESERVE, main] } else { &[main] };
        // A signed-in body of declared length larger than its quarter: a
        // large file's upload, which may take the pool alone.
        let large = signed && declared.is_some_and(|n| kib(n) > self.pools[SIGNED].kib / 4);
        let reachable = if large { self.pools[SIGNED].kib } else { order.iter().map(|&i| self.pools[i].kib / 4).sum() };
        let mut share = Share { permits: Vec::new(), key, held: self.held.clone() };
        // The buffer: a declared length's whole, made once its first bytes
        // come (memory is used as it is written); else as it grows.
        let mut buf = BytesMut::new();
        let mut arrival = Arrival::new();
        loop {
            let chunk = match tokio::time::timeout_at(arrival.due(), next_chunk(body)).await {
                Err(_) => return Err(Refused::Late),
                Ok(Some(Err(_))) => return Err(Refused::Unreadable),
                Ok(None) => break,
                Ok(Some(Ok(c))) => c,
            };
            let len = (buf.len() + chunk.len()) as u64;
            if len > limit || declared.is_some_and(|n| len > n) {
                return Err(if len > limit { Refused::TooLarge } else { Refused::Unreadable });
            }
            if !arrival.arrived(chunk.len() as u64) {
                return Err(Refused::Late);
            }
            let mut need = kib(if declared.is_some() { len } else { 2 * len });
            if need > reachable {
                // Past its client's part of its pools; a large upload holds at
                // most the whole signed-in pool.
                if !large {
                    return Err(Refused::Busy);
                }
                need = reachable;
            }
            if !self.grow(&mut share, order, large, need) {
                // A large upload alone waits a little for room in its pool.
                let more = need.saturating_sub(share.kib());
                let waited = large
                    && match tokio::time::timeout(SHARE_WAIT, self.pools[SIGNED].sem.clone().acquire_many_owned(more)).await {
                        Ok(Ok(p)) => {
                            *self.held.lock().unwrap().entry((key, SIGNED)).or_default() += more;
                            share.permits.push((SIGNED, p));
                            true
                        }
                        _ => false,
                    };
                if !waited {
                    return Err(Refused::Busy);
                }
            }
            if buf.capacity() == 0 {
                if let Some(n) = declared {
                    buf.reserve(n as usize);
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

/// A body arriving: the rules of the module's documentation. Windows are
/// counted from the start; the first is the grace.
struct Arrival {
    start: Instant,
    got: u64,
    /// The window now, the bytes in it, and in the one before.
    window: u32,
    in_window: u64,
    last_window: u64,
}

impl Arrival {
    fn new() -> Arrival {
        Arrival { start: Instant::now(), got: 0, window: 0, in_window: 0, last_window: 0 }
    }

    /// Close the windows that ended: `false` if one after the grace brought
    /// too little.
    fn roll(&mut self) -> bool {
        let now = (Instant::now() - self.start).as_secs_f64();
        let w = (now / WINDOW.as_secs_f64()) as u32;
        while self.window < w {
            if self.window >= 1 && self.in_window < WINDOW_BYTES {
                return false;
            }
            self.last_window = self.in_window;
            self.in_window = 0;
            self.window += 1;
        }
        true
    }

    /// By when the next bytes must come.
    fn due(&self) -> Instant {
        let average = self.start + GRACE + Duration::from_secs_f64(self.got as f64 / MIN_RATE as f64);
        let end = self.start + WINDOW * (self.window + 1);
        // A window that brought enough already: the next one must too.
        let window = if self.window >= 1 && self.in_window < WINDOW_BYTES { end } else { end + WINDOW };
        average.min(window)
    }

    /// `n` more bytes: `false` if the body is too slow, or holds more than
    /// its rate allows.
    fn arrived(&mut self, n: u64) -> bool {
        if !self.roll() {
            return false;
        }
        self.got += n;
        self.in_window += n;
        let rate = self.last_window as f64 / WINDOW.as_secs_f64();
        self.window == 0 || self.got <= FREE_HOLD.max((rate * HOLD.as_secs_f64()) as u64)
    }
}

/// Read and drop what is left of a refused body, at most `most` bytes, as
/// long as it keeps the rules of `Arrival`: the client then reads its
/// refusal instead of a broken connection, and nothing is held.
pub async fn drain(body: &mut Body, most: u64) {
    let mut arrival = Arrival::new();
    while arrival.got <= most {
        match tokio::time::timeout_at(arrival.due(), next_chunk(body)).await {
            Ok(Some(Ok(c))) => {
                if !arrival.arrived(c.len() as u64) {
                    return;
                }
            }
            _ => return,
        }
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
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };

    /// A body that sends its chunks, each after its delay, then ends or
    /// stalls for ever.
    struct Chunks {
        chunks: VecDeque<(Duration, Bytes)>,
        sleep: Option<Pin<Box<tokio::time::Sleep>>>,
        end: bool,
    }

    impl hyper::body::Body for Chunks {
        type Data = Bytes;
        type Error = std::io::Error;
        fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<hyper::body::Frame<Bytes>, std::io::Error>>> {
            let Some((delay, _)) = self.chunks.front() else {
                return if self.end { Poll::Ready(None) } else { Poll::Pending };
            };
            let delay = *delay;
            let s = self.sleep.get_or_insert_with(|| Box::pin(tokio::time::sleep(delay)));
            if s.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.sleep = None;
            let (_, c) = self.chunks.pop_front().unwrap();
            Poll::Ready(Some(Ok(hyper::body::Frame::data(c))))
        }
    }

    fn timed(chunks: &[(u64, usize)], end: bool) -> Body {
        Body::new(Chunks { chunks: chunks.iter().map(|(ms, n)| (Duration::from_millis(*ms), Bytes::from(vec![b'x'; *n]))).collect(), sleep: None, end })
    }

    fn body(chunks: &[usize], end: bool) -> Body {
        timed(&chunks.iter().map(|n| (0, *n)).collect::<Vec<_>>(), end)
    }

    const A: Key = Key::Ip(1);
    const B: Key = Key::Ip(2);
    const D: Key = Key::Device([1; 32]);
    const E: Key = Key::Device([2; 32]);

    /// The pools: an eighth for the reserve, a quarter anonymous, the rest
    /// signed-in; a body holds what has arrived, and gives it back.
    #[tokio::test(start_paused = true)]
    async fn bodies_are_read_only_under_a_share_of_the_budget() {
        let pools = Pools::new(64 << 20);
        assert_eq!(pools.pools.iter().map(|p| p.kib).collect::<Vec<_>>(), vec![8 << 10, 40 << 10, 16 << 10]);
        let (b, share) = pools.read(D, true, &mut body(&[1 << 20, 1 << 20], true), Some(2 << 20), 64 << 20).await.unwrap();
        assert_eq!(b.len(), 2 << 20);
        assert_eq!(pools.held_kib(), (2048, 0));
        // Four addresses take the anonymous pool, a quarter each; a fifth is busy.
        let mut held = Vec::new();
        for k in 1..=4 {
            held.push(pools.read(Key::Ip(10 + k), false, &mut body(&[4 << 20], true), Some(4 << 20), 64 << 20).await.unwrap().1);
        }
        assert_eq!(pools.held_kib(), (2048, 16 << 10));
        assert_eq!(pools.read(A, false, &mut body(&[2 << 20], true), Some(2 << 20), 64 << 20).await.unwrap_err(), Refused::Busy);
        // A small body still goes, in the reserve; the signed-in pool is apart.
        assert!(pools.read(A, false, &mut body(&[600], true), Some(600), 64 << 20).await.is_ok());
        assert!(pools.read(E, true, &mut body(&[10], true), Some(10), 64 << 20).await.is_ok());
        drop((share, held));
        assert_eq!((pools.held_kib(), pools.reserve_kib()), ((0, 0), 0));
        assert!(pools.held.lock().unwrap().is_empty(), "nothing is kept for clients holding nothing");
    }

    /// BUG-1333: a body holds only what has arrived, so heads that declare a
    /// length and send nothing hold nothing, and are cut off after 20 s.
    #[tokio::test(start_paused = true)]
    async fn a_head_without_its_body_holds_nothing() {
        let pools = Arc::new(Pools::new(64 << 20));
        let mut waiting = Vec::new();
        for k in 0..16u128 {
            let pools = pools.clone();
            waiting.push(tokio::spawn(async move { pools.read(Key::Ip(k), false, &mut body(&[], false), Some(4 << 20), 64 << 20).await.map(|_| ()) }));
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!((pools.held_kib(), pools.reserve_kib()), ((0, 0), 0));
        assert!(pools.read(A, false, &mut body(&[200], true), Some(200), 64 << 20).await.is_ok(), "a sign-in beside them");
        for w in waiting {
            assert_eq!(w.await.unwrap(), Err(Refused::Late));
        }
    }

    /// BUG-1333: small bodies grow in the reserve, which no large body
    /// takes: with every anonymous and signed-in byte held, a sign-in and a
    /// small push still go.
    #[tokio::test(start_paused = true)]
    async fn small_bodies_have_a_reserve() {
        let pools = Pools::new(64 << 20);
        let mut held = Vec::new();
        for k in 0..4u128 {
            held.push(pools.read(Key::Ip(100 + k), false, &mut body(&[4 << 20], true), Some(4 << 20), 64 << 20).await.unwrap().1);
        }
        // One device's large upload takes the whole signed-in pool.
        held.push(pools.read(D, true, &mut body(&[20 << 20, 20 << 20], true), Some(40 << 20), 2 << 30).await.unwrap().1);
        assert_eq!(pools.held_kib(), (40 << 10, 16 << 10));
        assert!(pools.read(A, false, &mut body(&[300], true), Some(300), 64 << 20).await.is_ok(), "a sign-in");
        assert!(pools.read(E, true, &mut body(&[100 << 10], true), Some(100 << 10), 64 << 20).await.is_ok(), "a small push");
        assert_eq!(pools.read(E, true, &mut body(&[2 << 20], true), Some(2 << 20), 64 << 20).await.unwrap_err(), Refused::Busy);
        drop(held);
        assert_eq!((pools.held_kib(), pools.reserve_kib()), ((0, 0), 0));
    }

    /// One client holds at most a quarter of a pool: an anonymous body past
    /// it is too large, a second one is busy; a signed-in device may send
    /// one body larger than that (a large file) while it holds nothing
    /// else, holding at most the whole pool.
    #[tokio::test(start_paused = true)]
    async fn one_client_holds_at_most_a_quarter_of_its_pool() {
        let pools = Pools::new(64 << 20);
        assert_eq!(pools.anonymous_limit(), 4 << 20);
        assert_eq!(pools.read(A, false, &mut body(&[], true), Some(5 << 20), 64 << 20).await.unwrap_err(), Refused::TooLarge);
        let (_, a1) = pools.read(A, false, &mut body(&[3 << 20], true), Some(3 << 20), 64 << 20).await.unwrap();
        assert_eq!(pools.read(A, false, &mut body(&[3 << 20], true), Some(3 << 20), 64 << 20).await.unwrap_err(), Refused::Busy);
        assert!(pools.read(B, false, &mut body(&[3 << 20], true), Some(3 << 20), 64 << 20).await.is_ok(), "another address is not refused");
        drop(a1);
        // A large upload: more than the signed-in pool, alone.
        let (big, all) = pools.read(D, true, &mut body(&[30 << 20, 30 << 20], true), Some(60 << 20), 2 << 30).await.unwrap();
        assert_eq!(big.len(), 60 << 20);
        assert_eq!(pools.held_kib().0, 40 << 10, "the whole pool, no more");
        drop(all);
        assert_eq!(pools.held_kib(), (0, 0));
    }

    /// A body of unknown length counts twice what it holds, and is refused
    /// the moment its client's quarter has no more; past the route's limit
    /// it is too large.
    #[tokio::test(start_paused = true)]
    async fn chunked_bodies_grow_their_share_or_are_refused() {
        let pools = Pools::new(64 << 20);
        let (b, share) = pools.read(A, false, &mut body(&[100 << 10, 100 << 10], true), None, 64 << 20).await.unwrap();
        assert_eq!(b.len(), 200 << 10);
        assert_eq!(pools.held_kib().1, 400, "twice what it holds");
        drop(share);
        assert_eq!(pools.read(A, false, &mut body(&[1500 << 10, 1500 << 10], true), None, 64 << 20).await.unwrap_err(), Refused::Busy);
        assert_eq!(pools.read(A, false, &mut body(&[5 << 20], true), None, 64 << 20).await.unwrap_err(), Refused::TooLarge);
        assert_eq!(pools.read(D, true, &mut body(&[1 << 20, 1 << 20], true), None, 1 << 20).await.unwrap_err(), Refused::TooLarge);
        assert_eq!(pools.read(D, true, &mut body(&[10], true), Some(20), 1 << 20).await.unwrap_err(), Refused::Unreadable);
        assert_eq!((pools.held_kib(), pools.reserve_kib()), ((0, 0), 0));
        assert!(pools.held.lock().unwrap().is_empty());
    }

    /// BUG-1187 and BUG-1333's class: a body that stops after the grace is
    /// cut off within a window; one that trickles holds no more than its
    /// rate allows; one at the minimum rate is served.
    #[tokio::test(start_paused = true)]
    async fn slow_bodies_are_cut_off_in_proportion_to_their_rate() {
        let pools = Pools::new(64 << 20);
        // Sends 160 KiB, then nothing: cut off once the average falls below 16 KiB/s (20 s + 10 s).
        let t = Instant::now();
        assert_eq!(pools.read(A, false, &mut body(&[160 << 10], false), Some(1 << 20), 64 << 20).await.unwrap_err(), Refused::Late);
        let took = t.elapsed();
        assert!(took >= Duration::from_secs(29) && took <= Duration::from_secs(31), "{took:?}");
        // Sends 3 MiB at once, then nothing: cut off at the end of the first window after the grace (40 s), not the average's 212 s.
        let t = Instant::now();
        assert_eq!(pools.read(Key::Ip(9), false, &mut body(&[3 << 20], false), Some((3 << 20) + 1), 64 << 20).await.unwrap_err(), Refused::Late);
        let took = t.elapsed();
        assert!(took >= Duration::from_secs(39) && took <= Duration::from_secs(41), "{took:?}");
        // Sends 3 MiB at once, then 4 KiB/s: holds more than ten minutes of its rate, cut off.
        let mut trickle = vec![(0, 3 << 20)];
        trickle.extend((0..60).map(|_| (1000, 4 << 10)));
        let t = Instant::now();
        assert_eq!(pools.read(B, false, &mut timed(&trickle, true), Some((3 << 20) + 60 * (4 << 10)), 64 << 20).await.unwrap_err(), Refused::Late);
        assert!(t.elapsed() <= Duration::from_secs(45), "{:?}", t.elapsed());
        // 1 MiB at 16 KiB/s (a second a chunk): served.
        let slow: Vec<(u64, usize)> = (0..64).map(|_| (1000, 16 << 10)).collect();
        let (b, _) = pools.read(Key::Ip(3), false, &mut timed(&slow, true), Some(1 << 20), 64 << 20).await.unwrap();
        assert_eq!(b.len(), 1 << 20);
        assert_eq!((pools.held_kib(), pools.reserve_kib()), ((0, 0), 0));
    }
}
