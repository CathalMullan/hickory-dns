use core::{
    pin::Pin,
    task::{Context, Poll},
};
use std::io;

/// Adapter from `tokio::io` to `futures_io`.
#[cfg(feature = "tokio")]
pub struct TokioIoAdapter<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(pub T);

#[cfg(feature = "tokio")]
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> Unpin for TokioIoAdapter<T> {}

#[cfg(feature = "tokio")]
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> futures_io::AsyncRead
    for TokioIoAdapter<T>
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut read_buf = tokio::io::ReadBuf::new(buf);
        match Pin::new(&mut self.0).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(feature = "tokio")]
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> futures_io::AsyncWrite
    for TokioIoAdapter<T>
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(feature = "tokio")]
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static>
    crate::tcp::DnsTcpStream for TokioIoAdapter<T>
{
    type Time = super::tokio_runtime::TokioTime;
}

/// Bridge from `futures_io` to runtime-specific IO traits.
pub struct FuturesIoAdapter<S: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin>(pub S);

impl<S: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin> Unpin for FuturesIoAdapter<S> {}

impl<S: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin> tokio::io::AsyncRead
    for FuturesIoAdapter<S>
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let unfilled = buf.initialize_unfilled();
        match Pin::new(&mut self.0).poll_read(cx, unfilled) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin> tokio::io::AsyncWrite
    for FuturesIoAdapter<S>
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}
