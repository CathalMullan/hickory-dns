//! Abstractions to deal with different async runtimes.

use core::future::Future;
use core::marker::Send;
use core::net::SocketAddr;
use core::pin::Pin;
use core::time::Duration;
#[cfg(feature = "__quic")]
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    future::poll_fn,
    io,
    task::{Context, Poll},
};

use async_trait::async_trait;
use futures_io::{AsyncRead, AsyncWrite};
#[cfg(any(test, feature = "tokio"))]
use tokio::runtime::Runtime;
#[cfg(any(test, feature = "tokio"))]
use tokio::task::JoinHandle;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Spawn a background task, if it was present
#[cfg(any(test, feature = "tokio"))]
pub fn spawn_bg<F: Future<Output = R> + Send + 'static, R: Send + 'static>(
    runtime: &Runtime,
    background: F,
) -> JoinHandle<R> {
    runtime.spawn(background)
}

#[cfg(feature = "tokio")]
#[doc(hidden)]
pub mod iocompat {
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use std::io::{self, IoSlice};

    use futures_io::{AsyncRead, AsyncWrite};
    use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite, ReadBuf};

    /// Conversion from `tokio::io::{AsyncRead, AsyncWrite}` to `std::io::{AsyncRead, AsyncWrite}`
    pub struct AsyncIoTokioAsStd<T: TokioAsyncRead + TokioAsyncWrite>(pub T);

    impl<T: TokioAsyncRead + TokioAsyncWrite + Unpin> Unpin for AsyncIoTokioAsStd<T> {}
    impl<R: TokioAsyncRead + TokioAsyncWrite + Unpin> AsyncRead for AsyncIoTokioAsStd<R> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut buf = ReadBuf::new(buf);
            let polled = Pin::new(&mut self.0).poll_read(cx, &mut buf);

            polled.map_ok(|_| buf.filled().len())
        }
    }

    impl<W: TokioAsyncRead + TokioAsyncWrite + Unpin> AsyncWrite for AsyncIoTokioAsStd<W> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    /// Conversion from `std::io::{AsyncRead, AsyncWrite}` to `tokio::io::{AsyncRead, AsyncWrite}`
    pub struct AsyncIoStdAsTokio<T: AsyncRead + AsyncWrite>(pub T);

    impl<T: AsyncRead + AsyncWrite + Unpin> Unpin for AsyncIoStdAsTokio<T> {}
    impl<R: AsyncRead + AsyncWrite + Unpin> TokioAsyncRead for AsyncIoStdAsTokio<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0)
                .poll_read(cx, buf.initialized_mut())
                .map_ok(|len| buf.advance(len))
        }
    }

    impl<W: AsyncRead + AsyncWrite + Unpin> TokioAsyncWrite for AsyncIoStdAsTokio<W> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Pin::new(&mut self.get_mut().0).poll_close(cx)
        }
    }
}

#[cfg(feature = "tokio")]
#[allow(unreachable_pub)]
mod tokio_runtime {
    use std::sync::Arc;
    use std::sync::Mutex;

    #[cfg(feature = "__quic")]
    use quinn::Runtime;
    use tokio::net::{TcpSocket, TcpStream};
    use tokio::task::JoinSet;
    use tokio::time::timeout;
    use tracing::debug;

    use core::net::{Ipv4Addr, Ipv6Addr};

    use super::iocompat::AsyncIoTokioAsStd;
    use super::*;

    /// A handle to the Tokio runtime
    #[derive(Clone, Default)]
    pub struct TokioHandle {
        join_set: Arc<Mutex<JoinSet<()>>>,
    }

    impl Spawn for TokioHandle {
        fn spawn_bg(&mut self, future: impl Future<Output = ()> + Send + 'static) {
            let mut join_set = self.join_set.lock().unwrap();
            join_set.spawn(future);
            reap_tasks(&mut join_set);
        }
    }

    /// The Tokio Runtime for async execution
    #[derive(Clone, Default)]
    pub struct TokioRuntimeProvider(TokioHandle);

    impl TokioRuntimeProvider {
        /// Create a Tokio runtime
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl RuntimeProvider for TokioRuntimeProvider {
        type Handle = TokioHandle;
        type Timer = TokioTime;
        type Udp = TokioUdpSocket;
        type Tcp = AsyncIoTokioAsStd<TcpStream>;

        fn create_handle(&self) -> Self::Handle {
            self.0.clone()
        }

        fn connect_tcp(
            &self,
            server_addr: SocketAddr,
            bind_addr: Option<SocketAddr>,
            wait_for: Option<Duration>,
        ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Tcp, io::Error>>>> {
            Box::pin(async move {
                let socket = match server_addr {
                    SocketAddr::V4(_) => TcpSocket::new_v4(),
                    SocketAddr::V6(_) => TcpSocket::new_v6(),
                }?;

                if let Some(bind_addr) = bind_addr {
                    socket.bind(bind_addr)?;
                }

                socket.set_nodelay(true)?;
                let future = socket.connect(server_addr);
                let wait_for = wait_for.unwrap_or(CONNECT_TIMEOUT);
                match timeout(wait_for, future).await {
                    Ok(Ok(socket)) => Ok(AsyncIoTokioAsStd(socket)),
                    Ok(Err(e)) => Err(e),
                    Err(_) => {
                        debug!(%server_addr, "TCP connect timeout");
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "TCP connect timed out",
                        ))
                    }
                }
            })
        }

        fn bind_udp(
            &self,
            local_addr: SocketAddr,
            _server_addr: SocketAddr,
        ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Udp, io::Error>>>> {
            Box::pin(async move {
                tokio::net::UdpSocket::bind(local_addr)
                    .await
                    .map(Into::into)
            })
        }

        #[cfg(feature = "__quic")]
        fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
            Some(&TokioQuicSocketBinder)
        }
    }

    /// Reap finished tasks from a `JoinSet`, without awaiting or blocking.
    fn reap_tasks(join_set: &mut JoinSet<()>) {
        while join_set.try_join_next().is_some() {}
    }

    #[cfg(feature = "__quic")]
    struct TokioQuicSocketBinder;

    #[cfg(feature = "__quic")]
    impl QuicSocketBinder for TokioQuicSocketBinder {
        fn bind_quic(
            &self,
            local_addr: SocketAddr,
            _server_addr: SocketAddr,
        ) -> Result<Arc<dyn quinn::AsyncUdpSocket>, io::Error> {
            let socket = std::net::UdpSocket::bind(local_addr)?;
            quinn::TokioRuntime.wrap_udp_socket(socket)
        }
    }

    #[derive(Debug)]
    pub struct TokioUdpSocket(tokio::net::UdpSocket);

    impl core::ops::Deref for TokioUdpSocket {
        type Target = tokio::net::UdpSocket;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl TokioUdpSocket {
        pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
            tokio::net::UdpSocket::bind(addr).await.map(Self)
        }

        pub fn from_std(socket: std::net::UdpSocket) -> io::Result<Self> {
            tokio::net::UdpSocket::from_std(socket).map(Self)
        }

        pub fn into_std(self) -> io::Result<std::net::UdpSocket> {
            self.0.into_std()
        }
    }

    impl From<tokio::net::UdpSocket> for TokioUdpSocket {
        fn from(socket: tokio::net::UdpSocket) -> Self {
            Self(socket)
        }
    }

    #[async_trait]
    impl DnsUdpSocket for TokioUdpSocket {
        type Time = TokioTime;

        fn poll_recv_from(
            &self,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<(usize, SocketAddr)>> {
            let mut buf = tokio::io::ReadBuf::new(buf);
            let addr = core::task::ready!(self.0.poll_recv_from(cx, &mut buf))?;
            let len = buf.filled().len();

            Poll::Ready(Ok((len, addr)))
        }

        fn poll_send_to(
            &self,
            cx: &mut Context<'_>,
            buf: &[u8],
            target: SocketAddr,
        ) -> Poll<io::Result<usize>> {
            self.0.poll_send_to(cx, buf, target)
        }
    }

    #[async_trait]
    impl UdpSocket for TokioUdpSocket {
        /// sets up up a "client" udp connection that will only receive packets from the associated address
        ///
        /// if the addr is ipv4 then it will bind local addr to 0.0.0.0:0, ipv6 \[::\]0
        async fn connect(addr: SocketAddr) -> io::Result<Self> {
            let bind_addr: SocketAddr = match addr {
                SocketAddr::V4(_addr) => (Ipv4Addr::UNSPECIFIED, 0).into(),
                SocketAddr::V6(_addr) => (Ipv6Addr::UNSPECIFIED, 0).into(),
            };

            Self::connect_with_bind(addr, bind_addr).await
        }

        /// same as connect, but binds to the specified local address for sending address
        async fn connect_with_bind(_addr: SocketAddr, bind_addr: SocketAddr) -> io::Result<Self> {
            let socket = Self::bind(bind_addr).await?;

            // TODO: research connect more, it appears to break UDP receiving tests, etc...
            // socket.connect(addr).await?;

            Ok(socket)
        }

        async fn bind(addr: SocketAddr) -> io::Result<Self> {
            Self::bind(addr).await
        }
    }

    impl<T> DnsTcpStream for AsyncIoTokioAsStd<T>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + Sized + 'static,
    {
        type Time = TokioTime;
    }
}

#[cfg(feature = "tokio")]
pub use tokio_runtime::*;

/// RuntimeProvider defines which async runtime that handles IO and timers.
pub trait RuntimeProvider: Clone + Send + Sync + Unpin + 'static {
    /// Handle to the executor;
    type Handle: Clone + Send + Spawn + Sync + Unpin;

    /// Timer
    type Timer: Time;

    /// UdpSocket
    type Udp: DnsUdpSocket;

    /// TcpStream
    type Tcp: DnsTcpStream;

    /// Create a runtime handle
    fn create_handle(&self) -> Self::Handle;

    /// Create a TCP connection with custom configuration.
    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Tcp, io::Error>>>>;

    /// Create a UDP socket bound to `local_addr`. The returned value should **not** be connected to `server_addr`.
    /// *Notice: the future should be ready once returned at best effort. Otherwise UDP DNS may need much more retries.*
    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Udp, io::Error>>>>;

    /// Yields an object that knows how to bind a QUIC socket.
    //
    // Use some indirection here to avoid exposing the `quinn` crate in the public API
    // even for runtimes that might not (want to) provide QUIC support.
    fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
        None
    }
}

/// Trait for DnsUdpSocket
#[async_trait]
pub trait DnsUdpSocket
where
    Self: Send + Sync + Sized + Unpin,
{
    /// Time implementation used for this type
    type Time: Time;

    /// Poll once Receive data from the socket and returns the number of bytes read and the address from
    /// where the data came on success.
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>>;

    /// Receive data from the socket and returns the number of bytes read and the address from
    /// where the data came on success.
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| self.poll_recv_from(cx, buf)).await
    }

    /// Poll once to send data to the given address.
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>>;

    /// Send data to the given address.
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        poll_fn(|cx| self.poll_send_to(cx, buf, target)).await
    }
}

/// Trait for UdpSocket
#[async_trait]
pub trait UdpSocket: DnsUdpSocket {
    /// setups up a "client" udp connection that will only receive packets from the associated address
    async fn connect(addr: SocketAddr) -> io::Result<Self>;

    /// same as connect, but binds to the specified local address for sending address
    async fn connect_with_bind(addr: SocketAddr, bind_addr: SocketAddr) -> io::Result<Self>;

    /// a "server" UDP socket, that bind to the local listening address, and unbound remote address (can receive from anything)
    async fn bind(addr: SocketAddr) -> io::Result<Self>;
}

/// Noop trait for when the `quinn` dependency is not available.
#[cfg(not(feature = "__quic"))]
pub trait QuicSocketBinder {}

/// Create a UDP socket for QUIC usage.
/// This trait is designed for customization.
#[cfg(feature = "__quic")]
pub trait QuicSocketBinder {
    /// Create a UDP socket for QUIC usage.
    fn bind_quic(
        &self,
        _local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Result<Arc<dyn quinn::AsyncUdpSocket>, io::Error>;
}

/// Trait for TCP connection
pub trait DnsTcpStream: AsyncRead + AsyncWrite + Unpin + Send + Sync + Sized + 'static {
    /// Timer type to use with this TCP stream type
    type Time: Time;
}

/// A type defines the Handle which can spawn future.
pub trait Spawn {
    /// Spawn a future in the background
    fn spawn_bg(&mut self, future: impl Future<Output = ()> + Send + 'static);
}

/// Generic Time for Delay and Timeout.
// This trait is created to allow to use different types of time systems. It's used in Fuchsia OS, please be mindful when update it.
#[async_trait]
pub trait Time: Send + Sync + Unpin {
    /// Return a type that implements `Future` that will wait until the specified duration has
    /// elapsed.
    async fn delay_for(duration: Duration);

    /// Return a type that implement `Future` to complete before the specified duration has elapsed.
    async fn timeout<F: 'static + Future + Send>(
        duration: Duration,
        future: F,
    ) -> Result<F::Output, io::Error>;

    /// Get the current time as a Unix timestamp.
    ///
    /// This returns the number of seconds since the Unix epoch.
    fn current_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

/// New type which is implemented using tokio::time::{Delay, Timeout}
#[cfg(any(test, feature = "tokio"))]
#[derive(Clone, Copy, Debug)]
pub struct TokioTime;

#[cfg(any(test, feature = "tokio"))]
#[async_trait]
impl Time for TokioTime {
    async fn delay_for(duration: Duration) {
        tokio::time::sleep(duration).await
    }

    async fn timeout<F: 'static + Future + Send>(
        duration: Duration,
        future: F,
    ) -> Result<F::Output, io::Error> {
        tokio::time::timeout(duration, future)
            .await
            .map_err(move |_| io::Error::new(io::ErrorKind::TimedOut, "future timed out"))
    }
}
