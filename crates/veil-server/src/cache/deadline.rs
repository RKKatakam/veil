//! A connection whose writes must make progress (BUG-1181, BUG-1183): a
//! write that stays pending for longer than the stall limit (a client that
//! stopped reading) fails, and so does one that would bring the time the
//! connection's writes have waited past the grace plus one second per
//! `min_rate` bytes written (a client that reads a little now and then).
//! The connection is then closed and what its answer held (memory, its
//! share of the cache's budget, its marks, its connection slot) is let go.
//! A client that reads at `min_rate` or faster is never cut off; one that
//! is idle between requests waits for nothing here (the HTTP layer's head
//! timeout bounds that).

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// What a connection's writes must keep up with.
#[derive(Clone, Copy, Debug)]
pub struct Pace {
    /// The longest one write may stay pending.
    pub stall: Duration,
    /// The time writes may wait in all, before `min_rate` counts.
    pub grace: Duration,
    /// Bytes a second: each byte written allows writes to wait that much
    /// longer.
    pub min_rate: u64,
}

pub struct WriteDeadline<S> {
    inner: S,
    pace: Option<Pace>,
    /// Since when the current write has been pending, and its deadline.
    timer: Option<(Instant, Pin<Box<tokio::time::Sleep>>)>,
    /// Bytes written, and the time writes waited, over the connection.
    written: u64,
    waited: Duration,
}

impl<S> WriteDeadline<S> {
    /// `inner`, with writes bounded by `pace` (`None`: unbounded).
    pub fn new(inner: S, pace: Option<Pace>) -> WriteDeadline<S> {
        WriteDeadline { inner, pace, timer: None, written: 0, waited: Duration::ZERO }
    }

    fn progress<T>(&mut self, cx: &mut Context<'_>, p: Poll<io::Result<T>>, wrote: impl FnOnce(&T) -> usize) -> Poll<io::Result<T>> {
        if let Poll::Ready(r) = &p {
            if let Some((since, _)) = self.timer.take() {
                self.waited += since.elapsed();
            }
            if let Ok(t) = r {
                self.written += wrote(t) as u64;
            }
            return p;
        }
        let Some(pace) = self.pace else { return p };
        let (written, waited) = (self.written, self.waited);
        let (_, t) = self.timer.get_or_insert_with(|| {
            let earned = pace.grace + Duration::from_secs_f64(written as f64 / pace.min_rate.max(1) as f64);
            (Instant::now(), Box::pin(tokio::time::sleep(pace.stall.min(earned.saturating_sub(waited)))))
        });
        if t.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "the client stopped reading, or reads too slowly")));
        }
        Poll::Pending
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WriteDeadline<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WriteDeadline<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let p = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.progress(cx, p, |n| *n)
    }

    fn poll_write_vectored(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let p = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        self.progress(cx, p, |n| *n)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let p = Pin::new(&mut self.inner).poll_flush(cx);
        self.progress(cx, p, |_| 0)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer that takes `n` bytes every `every`, and is pending between.
    struct Trickle {
        n: usize,
        every: Duration,
        next: Option<Pin<Box<tokio::time::Sleep>>>,
    }

    impl AsyncWrite for Trickle {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let every = self.every;
            let t = self.next.get_or_insert_with(|| Box::pin(tokio::time::sleep(every)));
            if t.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.next = None;
            Poll::Ready(Ok(buf.len().min(self.n)))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for Trickle {
        fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Write 64 KiB to a client taking `n` bytes every 10 ms, under a
    /// grace of 300 ms and a minimum of 16 KiB/s: the time until the write
    /// fails, or `None` if it all went.
    async fn write_to(n: usize) -> Option<Duration> {
        use tokio::io::AsyncWriteExt;
        let pace = Pace { stall: Duration::from_secs(1), grace: Duration::from_millis(300), min_rate: 16 << 10 };
        let mut w = WriteDeadline::new(Trickle { n, every: Duration::from_millis(10), next: None }, Some(pace));
        let t = Instant::now();
        w.write_all(&vec![0u8; 64 << 10]).await.err().map(|_| t.elapsed())
    }

    /// BUG-1183's class: a client reading a little at a time (each write
    /// well under the stall limit) is cut off once its writes waited past
    /// the grace plus a second per 16 KiB written; one reading faster than
    /// 16 KiB/s never is.
    #[tokio::test]
    async fn a_client_reading_below_the_minimum_rate_is_cut_off() {
        // 1.6 KB/s: about 0.3 s / (1 - 0.1).
        let cut = write_to(16).await.expect("1.6 KB/s is cut off");
        assert!(cut >= Duration::from_millis(300) && cut < Duration::from_secs(1), "{cut:?}");
        // 51 KB/s: 64 KiB in about 1.3 s, past the grace and the stall limit.
        assert_eq!(write_to(512).await, None, "a client faster than the minimum is served");
    }
}
