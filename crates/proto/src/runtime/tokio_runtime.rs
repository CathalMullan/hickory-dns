use alloc::boxed::Box;
use alloc::sync::Arc;
use async_trait::async_trait;
use core::future::Future;
use core::net::SocketAddr;
use core::pin::Pin;
use core::time::Duration;
use std::io;
use std::sync::Mutex;

use tokio::task::JoinSet;
#[cfg(feature = "__tls")]
use tokio_rustls::TlsStream;

#[cfg(feature = "__quic")]
use quinn::Runtime as QuinnRuntime;
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::runtime::Runtime;
use tokio::time::timeout;

use super::iocompat::TokioIoAdapter;
use crate::ProtoError;
#[cfg(feature = "__quic")]
use crate::runtime::QuicSocketBinder;
use crate::runtime::{Executor, RuntimeProvider, Spawn, Time};
use crate::xfer::CONNECT_TIMEOUT;

impl Executor for Runtime {
    fn new() -> Self {
        Self::new().expect("failed to create tokio runtime")
    }

    fn block_on<F: Future>(&mut self, future: F) -> F::Output {
        Self::block_on(self, future)
    }
}

/// A handle to the Tokio runtime
#[derive(Clone, Default)]
pub struct TokioHandle {
    tasks: Arc<Mutex<JoinSet<Result<(), ProtoError>>>>,
}

impl Spawn for TokioHandle {
    fn spawn<F, R>(&mut self, future: F)
    where
        F: Future<Output = R> + Send + 'static,
        R: Send + 'static,
    {
        tokio::spawn(future);
    }

    fn spawn_bg<F>(&mut self, future: F)
    where
        F: Future<Output = Result<(), ProtoError>> + Send + 'static,
    {
        let mut join_set = self.tasks.lock().unwrap();
        join_set.spawn(future);
        reap_tasks(&mut join_set);
    }
}

/// Reap finished tasks from a `JoinSet`, without awaiting or blocking.
fn reap_tasks(join_set: &mut JoinSet<Result<(), ProtoError>>) {
    while join_set.try_join_next().is_some() {}
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
    type Udp = UdpSocket;
    type Tcp = TokioIoAdapter<TcpStream>;
    type TcpListener = TcpListener;
    #[cfg(feature = "__tls")]
    type Tls = TokioIoAdapter<TlsStream<TcpStream>>;

    fn create_handle(&self) -> Self::Handle {
        self.0.clone()
    }

    fn bind_tcp(
        &self,
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::TcpListener>> + Send>> {
        Box::pin(TcpListener::bind(addr))
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
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
                Ok(Ok(stream)) => Ok(TokioIoAdapter(stream)),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connection to {server_addr:?} timed out after {wait_for:?}"),
                )),
            }
        })
    }

    fn accept_tcp<'a>(
        &'a self,
        listener: &'a mut Self::TcpListener,
    ) -> Pin<Box<dyn Future<Output = io::Result<(Self::Tcp, SocketAddr)>> + Send + 'a>> {
        Box::pin(async move {
            listener
                .accept()
                .await
                .map(|(stream, addr)| (TokioIoAdapter(stream), addr))
        })
    }

    #[cfg(feature = "__tls")]
    fn connect_tls(
        &self,
        stream: Self::Tcp,
        server_name: rustls_pki_types::ServerName<'static>,
        client_config: Arc<rustls::ClientConfig>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Tls>> + Send>> {
        use tokio_rustls::TlsConnector;

        let early_data_enabled = client_config.enable_early_data;
        let tls_connector = TlsConnector::from(client_config).early_data(early_data_enabled);

        Box::pin(async move {
            let s = match timeout(
                CONNECT_TIMEOUT,
                tls_connector.connect(server_name, stream.0),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("tls error: {e}"),
                    ));
                }
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("TLS handshake timed out after {CONNECT_TIMEOUT:?}"),
                    ));
                }
            };

            Ok(TokioIoAdapter(TlsStream::Client(s)))
        })
    }

    #[cfg(feature = "__tls")]
    fn accept_tls<'a>(
        &'a self,
        stream: Self::Tcp,
        server_config: Arc<rustls::ServerConfig>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Tls>> + Send + 'a>> {
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);

        Box::pin(async move {
            let s = tls_acceptor.accept(stream.0).await.map_err(|e| {
                io::Error::new(io::ErrorKind::ConnectionRefused, format!("tls error: {e}"))
            })?;

            Ok(TokioIoAdapter(TlsStream::Server(s)))
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        Box::pin(UdpSocket::bind(local_addr))
    }

    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Self::Udp> {
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket)
    }

    #[cfg(feature = "__quic")]
    fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
        Some(&TokioQuicSocketBinder)
    }
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

/// New type which is implemented using tokio::time::{Delay, Timeout}
#[derive(Clone, Copy, Debug)]
pub struct TokioTime;

#[async_trait]
impl Time for TokioTime {
    async fn delay_for(duration: Duration) {
        tokio::time::sleep(duration).await;
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
