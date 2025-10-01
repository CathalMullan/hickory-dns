use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;

use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite, ReadBuf};

use crate::runtime::TokioTime;
use crate::tcp::DnsTcpStream;

/// Adapter from `DnsTcpStream` to alternative IO traits.
pub struct DnsStreamAdapter<S: DnsTcpStream>(pub S);

impl<S: DnsTcpStream> Unpin for DnsStreamAdapter<S> {}

impl<S: DnsTcpStream> TokioAsyncRead for DnsStreamAdapter<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let unfilled = buf.initialize_unfilled();
        match self.0.poll_read(cx, unfilled) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: DnsTcpStream> TokioAsyncWrite for DnsStreamAdapter<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.0.poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.0.poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.0.poll_shutdown(cx)
    }
}

/// Adapter from `tokio::io` to `DnsTcpStream`.
pub struct TokioIoAdapter<T: TokioAsyncRead + TokioAsyncWrite + Unpin>(pub T);

impl<T: TokioAsyncRead + TokioAsyncWrite + Unpin> Unpin for TokioIoAdapter<T> {}

impl<T: TokioAsyncRead + TokioAsyncWrite + Unpin + Send + Sync + 'static> DnsTcpStream
    for TokioIoAdapter<T>
{
    type Time = TokioTime;

    fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut buf = ReadBuf::new(buf);
        match Pin::new(&mut self.0).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
