//! A connection whose writes must make progress (BUG-1181): a write that
//! stays pending for longer than the limit (a client that stopped reading)
//! fails, so the connection is closed and what its answer held (memory, its
//! share of the cache's budget, its marks) is let go.

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct WriteDeadline<S> {
    inner: S,
    limit: Option<Duration>,
    /// Since when the current write has been pending.
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> WriteDeadline<S> {
    /// `inner`, with writes bounded by `limit` (`None`: unbounded).
    pub fn new(inner: S, limit: Option<Duration>) -> WriteDeadline<S> {
        WriteDeadline { inner, limit, timer: None }
    }

    fn progress<T>(&mut self, cx: &mut Context<'_>, p: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        if p.is_ready() {
            self.timer = None;
            return p;
        }
        let Some(limit) = self.limit else { return p };
        let t = self.timer.get_or_insert_with(|| Box::pin(tokio::time::sleep(limit)));
        if t.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "the client stopped reading")));
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
        self.progress(cx, p)
    }

    fn poll_write_vectored(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let p = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        self.progress(cx, p)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let p = Pin::new(&mut self.inner).poll_flush(cx);
        self.progress(cx, p)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
