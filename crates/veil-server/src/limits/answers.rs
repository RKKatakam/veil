//! Answers being written, under a memory budget (BUG-1330; `docs/HUB.md`
//! §13.25): the regional cache's rule (BUG-1181, BUG-1186) on the server.
//!
//! * Every answer of [`SMALL`] bytes or more holds a share of the answers'
//!   budget (`--request-memory`) for its bytes from the moment the route
//!   made them until the connection has taken them: the share travels inside
//!   the bytes handed to the connection (`Bytes::from_owner`) and comes back
//!   when they are written, or dropped with the connection.
//! * An answer whose length is known (a whole object, a JSON answer) takes
//!   its share before its head is sent, waiting at most [`WAIT`]; past it,
//!   it is answered `503 busy` instead, and its bytes are let go at once. An
//!   answer that streams (frames read as they go) takes a share for each
//!   piece before it is handed on, holding nothing while it waits.
//! * One client (a person, or an address) holds at most a quarter of the
//!   budget, except one answer larger than that while it holds nothing else
//!   (up to the whole budget): a client that does not read holds what its
//!   connection was handed, nothing more, until the write deadline closes it.
//!
//! Answers below [`SMALL`] take no share: a connection holds one at a time
//! (HTTP/2: one a stream), within its per-connection bound.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use axum::{body::Body, response::Response};
use bytes::Bytes;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::bucket::Key;

/// Answers smaller than this take no share.
pub const SMALL: usize = 64 << 10;
/// How long an answer of known length waits for its share.
pub const WAIT: Duration = Duration::from_secs(2);

type Held = Arc<Mutex<HashMap<Key, u32>>>;

/// The answers' budget.
pub struct Answers {
    sem: Arc<Semaphore>,
    kib: u32,
    held: Held,
}

/// A share of the budget for some bytes of one client's answer.
pub struct Hold {
    _permit: OwnedSemaphorePermit,
    kib: u32,
    key: Key,
    held: Held,
}

impl Drop for Hold {
    fn drop(&mut self) {
        let mut h = self.held.lock().unwrap();
        if let Some(n) = h.get_mut(&self.key) {
            *n = n.saturating_sub(self.kib);
            if *n == 0 {
                h.remove(&self.key);
            }
        }
    }
}

/// Bytes with their share: given back when the connection drops them.
struct Owned {
    bytes: Bytes,
    _hold: Hold,
}

impl AsRef<[u8]> for Owned {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

fn kib(n: usize) -> u32 {
    (n as u64).div_ceil(1024).min(u64::from(u32::MAX >> 4)) as u32
}

impl Answers {
    pub fn new(budget: u64) -> Arc<Answers> {
        let kib = (budget >> 10).clamp(4 << 10, u64::from(u32::MAX >> 4)) as u32;
        Arc::new(Answers { sem: Arc::new(Semaphore::new(kib as usize)), kib, held: Default::default() })
    }

    /// KiB held now.
    pub fn held_kib(&self) -> u32 {
        self.kib - self.sem.available_permits() as u32
    }

    /// A share for `n` bytes of `key`'s answer, waiting until `deadline`
    /// (`None`: as long as it takes).
    async fn take(self: Arc<Self>, key: Key, n: usize, deadline: Option<tokio::time::Instant>) -> Option<Hold> {
        let want = kib(n).min(self.kib);
        loop {
            {
                let mut h = self.held.lock().unwrap();
                let cur = h.get(&key).copied().unwrap_or(0);
                // A client's quarter; one larger answer alone.
                if cur + want <= self.kib / 4 || cur == 0 {
                    if let Ok(p) = self.sem.clone().try_acquire_many_owned(want) {
                        *h.entry(key).or_default() += want;
                        return Some(Hold { _permit: p, kib: want, key, held: self.held.clone() });
                    }
                }
            }
            if deadline.is_some_and(|d| tokio::time::Instant::now() >= d) {
                return None;
            }
            // Shares come back as connections write their bytes.
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// `resp` under the budget for `key`: its body's bytes hold shares
    /// while they are written. A read's answer (`refusable`) of known length
    /// whose share is not free within [`WAIT`] is `None` (the caller answers
    /// `busy`, and the client may ask again); a change's answer is never
    /// refused once the change is made: it goes without a share then.
    pub async fn budget(self: &Arc<Self>, key: Key, resp: Response, refusable: bool) -> Option<Response> {
        let known = hyper::body::Body::size_hint(resp.body()).exact().map(|n| n as usize);
        let prepaid = resp.extensions().get::<Prepaid>().map(|p| p.0.lock().unwrap().take());
        let first = match (prepaid, known) {
            (Some(paid), _) => paid,
            (None, known) => match known {
            Some(n) if n >= SMALL => match self.clone().take(key, n, Some(tokio::time::Instant::now() + WAIT)).await {
                Some(h) => Some(h),
                None if refusable => return None,
                None => return Some(resp),
            },
            _ => None,
            },
        };
        let (parts, body) = resp.into_parts();
        let body = Budgeted { inner: body, answers: self.clone(), key, first, waiting: None };
        Some(Response::from_parts(parts, Body::new(body)))
    }
}

/// Whose answer a route makes ([`super::admit`] sets it on the request),
/// for a route that takes its answer's share itself ([`prepay`]).
#[derive(Clone, Copy, Debug)]
pub struct For(pub Key);

/// A share a route took before making its answer, which [`Answers::budget`]
/// then uses.
#[derive(Clone)]
pub struct Prepaid(Arc<Mutex<Option<Hold>>>);

/// A share for an answer of `n` bytes, taken before the route reads them,
/// so a refused request reads nothing (an object of known size: BUG-1330):
/// `busy` if it is not free within [`WAIT`].
pub async fn prepay(hub: &crate::Hub, asker: Option<For>, n: u64) -> crate::error::Result<Prepaid> {
    let n = n as usize;
    let hold = match asker {
        Some(For(key)) if n >= SMALL => match hub.limits.answers.clone().take(key, n, Some(tokio::time::Instant::now() + WAIT)).await {
            Some(h) => Some(h),
            None => return Err(crate::error::Error::new(axum::http::StatusCode::SERVICE_UNAVAILABLE, "busy", "the server is busy; try again")),
        },
        _ => None,
    };
    Ok(Prepaid(Arc::new(Mutex::new(hold))))
}

type Taking = Pin<Box<dyn Future<Output = Option<Hold>> + Send>>;

/// An answer's body whose pieces carry their shares.
struct Budgeted {
    inner: Body,
    answers: Arc<Answers>,
    key: Key,
    /// The share taken for a body of known length.
    first: Option<Hold>,
    /// A piece waiting for its share.
    waiting: Option<(Taking, Bytes)>,
}

impl hyper::body::Body for Budgeted {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<hyper::body::Frame<Bytes>, axum::Error>>> {
        let this = self.get_mut();
        loop {
            if let Some((taking, _)) = &mut this.waiting {
                let hold = match taking.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(h) => h,
                };
                let (_, bytes) = this.waiting.take().expect("a piece waits");
                let b = match hold {
                    Some(h) => Bytes::from_owner(Owned { bytes, _hold: h }),
                    None => bytes,
                };
                return Poll::Ready(Some(Ok(hyper::body::Frame::data(b))));
            }
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(f))) => match f.into_data() {
                    Ok(d) => {
                        if let Some(h) = this.first.take() {
                            return Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from_owner(Owned { bytes: d, _hold: h })))));
                        }
                        if d.len() < SMALL {
                            return Poll::Ready(Some(Ok(hyper::body::Frame::data(d))));
                        }
                        let taking: Taking = Box::pin(this.answers.clone().take(this.key, d.len(), None));
                        this.waiting = Some((taking, d));
                    }
                    Err(f) => return Poll::Ready(Some(Ok(f))),
                },
                other => return other,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.waiting.is_none() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        let mut h = self.inner.size_hint();
        if let Some((_, b)) = &self.waiting {
            h.set_lower(h.lower() + b.len() as u64);
            if let Some(u) = h.upper() {
                h.set_upper(u + b.len() as u64);
            }
        }
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Key = Key::Ip(1);
    const B: Key = Key::Ip(2);

    async fn answer(answers: &Arc<Answers>, key: Key, n: usize) -> Option<Body> {
        let r = answers.budget(key, Response::new(Body::from(vec![b'a'; n])), true).await?;
        Some(r.into_body())
    }

    /// Read a body as a connection writes it: each piece dropped once read.
    async fn read_all(mut b: Body) -> usize {
        use hyper::body::Body as _;
        let mut n = 0;
        while let Some(f) = std::future::poll_fn(|cx| Pin::new(&mut b).poll_frame(cx)).await {
            n += f.unwrap().into_data().map_or(0, |d| d.len());
        }
        n
    }

    /// An answer holds its share until its bytes are taken, then gives it
    /// back; past a client's quarter, or the budget, an answer of known
    /// length is refused, and its bytes let go.
    #[tokio::test(start_paused = true)]
    async fn answers_hold_their_share_until_written() {
        let answers = Answers::new(16 << 20);
        let a1 = answer(&answers, A, 3 << 20).await.unwrap();
        assert_eq!(answers.held_kib(), 3 << 10);
        assert!(answer(&answers, A, 3 << 20).await.is_none(), "past A's quarter (4 MiB)");
        let b1 = answer(&answers, B, 4 << 20).await.unwrap();
        let small = answer(&answers, A, 1000).await.unwrap();
        assert_eq!(answers.held_kib(), 7 << 10, "small answers take nothing");
        assert_eq!(read_all(a1).await, 3 << 20);
        assert_eq!(answers.held_kib(), 4 << 10, "A's bytes written: its share is back");
        drop((b1, small));
        assert_eq!(answers.held_kib(), 0);
        // One answer larger than a quarter, alone: up to the whole budget.
        let big = answer(&answers, A, 12 << 20).await.unwrap();
        assert_eq!(answers.held_kib(), 12 << 10);
        assert!(answer(&answers, B, 8 << 20).await.is_none(), "the budget is taken");
        let change = answers.budget(B, Response::new(Body::from(vec![b'c'; 8 << 20])), false).await;
        assert!(change.is_some(), "a change's answer is never refused once the change is made");
        drop(big);
        assert!(answers.held.lock().unwrap().is_empty());
    }

    /// A body of `n` pieces of 1 MiB, of unknown length.
    struct Pieces(usize);

    impl hyper::body::Body for Pieces {
        type Data = Bytes;
        type Error = std::io::Error;
        fn poll_frame(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<hyper::body::Frame<Bytes>, std::io::Error>>> {
            if self.0 == 0 {
                return Poll::Ready(None);
            }
            self.0 -= 1;
            Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from(vec![b's'; 1 << 20])))))
        }
    }

    /// A streaming answer takes a share per piece, waiting for it while it
    /// holds nothing: two of them through a budget smaller than both
    /// complete, one piece after another.
    #[tokio::test(start_paused = true)]
    async fn streamed_answers_wait_for_their_pieces_shares() {
        let answers = Answers::new(4 << 20);
        let x = answers.budget(A, Response::new(Body::new(Pieces(6))), true).await.unwrap();
        let y = answers.budget(B, Response::new(Body::new(Pieces(6))), true).await.unwrap();
        let (x, y) = tokio::join!(read_all(x.into_body()), read_all(y.into_body()));
        assert_eq!((x, y), (6 << 20, 6 << 20));
        assert_eq!(answers.held_kib(), 0);
    }
}
