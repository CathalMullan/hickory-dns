//! Abstractions to deal with different async runtimes.

use alloc::boxed::Box;
use core::future::Future;
use core::marker::Send;
use core::net::SocketAddr;
use core::pin::Pin;
use core::time::Duration;
use std::io;
use std::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use crate::error::ProtoError;
use crate::tcp::DnsTcpStream;
use crate::udp::DnsUdpSocket;

#[cfg(feature = "__quic")]
mod quinn_adapter;
#[cfg(feature = "__quic")]
pub use quinn_adapter::QuinnAdapter;

#[doc(hidden)]
#[cfg(feature = "std")]
pub mod iocompat;

#[cfg(feature = "tokio")]
mod tokio_runtime;
#[cfg(feature = "tokio")]
pub use tokio_runtime::{TokioHandle, TokioRuntimeProvider};

/// RuntimeProvider defines which async runtime that handles IO and timers.
pub trait RuntimeProvider: Clone + Send + Sync + Unpin + 'static {
    /// Handle to the executor;
    type Handle: Clone + Send + Spawn + Sync + Unpin;

    /// Timer
    type Timer: Time + Send + Unpin;

    /// UdpSocket
    type Udp: DnsUdpSocket + Send;

    /// TcpStream
    type Tcp: DnsTcpStream;

    /// TlsStream
    #[cfg(feature = "__tls")]
    type Tls: DnsTcpStream;

    /// Create a runtime handle
    fn create_handle(&self) -> Self::Handle;

    /// Create a TCP connection with custom configuration.
    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>>;

    /// Create a TLS connection with custom configuration.
    #[cfg(feature = "__tls")]
    #[allow(clippy::type_complexity)]
    fn connect_tls(
        &self,
        stream: Self::Tcp,
        server_name: rustls_pki_types::ServerName<'static>,
        client_config: alloc::sync::Arc<rustls::ClientConfig>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Tls>> + Send>>;

    /// Create a UDP socket bound to `local_addr`. The returned value should **not** be connected to `server_addr`.
    /// *Notice: the future should be ready once returned at best effort. Otherwise UDP DNS may need much more retries.*
    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>>;

    /// Wrap a UdpSocket into an async UDP socket.
    fn wrap_udp_socket(&self, socket: UdpSocket) -> io::Result<Self::Udp>;

    /// Yields an object that knows how to bind a QUIC socket.
    //
    // Use some indirection here to avoid exposing the `quinn` crate in the public API
    // even for runtimes that might not (want to) provide QUIC support.
    fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
        None
    }
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
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Result<alloc::sync::Arc<dyn quinn::AsyncUdpSocket>, io::Error>;
}

/// A type defines the Handle which can spawn future.
pub trait Spawn {
    /// Spawn a tracked future.
    fn spawn_tracked<F>(&mut self, future: F)
    where
        F: Future<Output = Result<(), ProtoError>> + Send + 'static;

    /// Spawn a detached future.
    fn spawn_detached<F, R>(&mut self, future: F)
    where
        F: Future<Output = R> + Send + 'static,
        R: Send + 'static;
}

/// Generic executor.
// This trait is created to facilitate running the tests defined in the tests mod using different types of
// executors. It's used in Fuchsia OS, please be mindful when update it.
pub trait Executor {
    /// Create the implementor itself.
    fn new() -> Self;

    /// Spawns a future object to run synchronously or asynchronously depending on the specific
    /// executor.
    fn block_on<F: Future>(&mut self, future: F) -> F::Output;
}

/// Generic Time for Delay and Timeout.
// This trait is created to allow to use different types of time systems. It's used in Fuchsia OS, please be mindful when update it.
#[async_trait]
pub trait Time {
    /// Return a type that implements `Future` that will wait until the specified duration has
    /// elapsed.
    async fn delay_for(duration: Duration);

    /// Return a type that implement `Future` to complete before the specified duration has elapsed.
    async fn timeout<F: 'static + Future + Send>(
        duration: Duration,
        future: F,
    ) -> Result<F::Output, std::io::Error>;

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
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug)]
pub struct TokioTime;

#[cfg(feature = "std")]
#[async_trait]
impl Time for TokioTime {
    async fn delay_for(duration: Duration) {
        tokio::time::sleep(duration).await
    }

    async fn timeout<F: 'static + Future + Send>(
        duration: Duration,
        future: F,
    ) -> Result<F::Output, std::io::Error> {
        tokio::time::timeout(duration, future)
            .await
            .map_err(move |_| std::io::Error::new(std::io::ErrorKind::TimedOut, "future timed out"))
    }
}
