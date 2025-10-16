use alloc::{boxed::Box, sync::Arc};
use core::{
    fmt,
    future::{Future, poll_fn},
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use std::{io, time::Instant};

use futures_util::ready;
use quinn::{
    AsyncTimer, AsyncUdpSocket, Runtime, UdpPoller,
    udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState},
};

use crate::{
    runtime::{RuntimeProvider, Spawn, Time},
    udp::DnsUdpSocket,
};

/// Adapter that implements Quinn's `Runtime` trait for our `RuntimeProvider`.
#[derive(Clone)]
pub(crate) struct QuinnRuntimeAdapter<P: RuntimeProvider> {
    provider: P,
}

impl<P: RuntimeProvider> QuinnRuntimeAdapter<P> {
    /// Wrap a runtime provider.
    pub(crate) fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P: RuntimeProvider> Runtime for QuinnRuntimeAdapter<P> {
    fn new_timer(&self, t: Instant) -> Pin<Box<dyn AsyncTimer>> {
        Box::pin(QuinnTimerAdapter::<P>::new(t))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let mut handle = self.provider.create_handle();
        handle.spawn(future);
    }

    fn wrap_udp_socket(&self, sock: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let inner = UdpSocketState::new(UdpSockRef::from(&sock))?;
        let io = self.provider.wrap_udp_socket(sock)?;
        Ok(Arc::new(QuinnSocketAdapter { io, inner }))
    }
}

impl<P: RuntimeProvider> fmt::Debug for QuinnRuntimeAdapter<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuinnRuntimeAdapter")
            .field("provider", &core::any::type_name::<P>())
            .finish()
    }
}

/// Adapter that implements Quinn's `AsyncTimer` trait for our `RuntimeProvider`.
struct QuinnTimerAdapter<P: RuntimeProvider> {
    sleep: Pin<Box<dyn Future<Output = ()> + Send>>,
    _marker: PhantomData<P>,
}

impl<P: RuntimeProvider> QuinnTimerAdapter<P> {
    fn new(i: Instant) -> Self {
        Self {
            sleep: P::Timer::delay_for(i.duration_since(Instant::now())),
            _marker: PhantomData,
        }
    }
}

impl<P: RuntimeProvider> AsyncTimer for QuinnTimerAdapter<P> {
    fn reset(mut self: Pin<&mut Self>, i: Instant) {
        self.sleep = P::Timer::delay_for(i.duration_since(Instant::now()));
    }

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.sleep.as_mut().poll(cx)
    }
}

impl<P: RuntimeProvider> fmt::Debug for QuinnTimerAdapter<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuinnTimerAdapter").finish_non_exhaustive()
    }
}

/// Adapter that implements Quinn's `AsyncUdpSocket` trait for our `DnsUdpSocket`.
pub(crate) struct QuinnSocketAdapter<S: DnsUdpSocket> {
    io: S,
    inner: UdpSocketState,
}

impl<S: DnsUdpSocket> QuinnSocketAdapter<S> {
    /// Create a new Quinn socket adapter.
    pub(crate) fn new(io: S) -> io::Result<Self> {
        let inner = UdpSocketState::new(UdpSockRef::from(&io))?;
        Ok(Self { io, inner })
    }
}

impl<S: DnsUdpSocket + 'static> AsyncUdpSocket for QuinnSocketAdapter<S> {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(UdpPollHelper::new(move || {
            let socket = self.clone();
            async move { poll_fn(|cx| socket.io.poll_send_ready(cx)).await }
        }))
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let sock = UdpSockRef::from(&self.io);
        self.inner.send(sock, transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;

            let sock = UdpSockRef::from(&self.io);
            match self.inner.recv(sock, bufs, meta) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}

impl<S: DnsUdpSocket> fmt::Debug for QuinnSocketAdapter<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuinnSocketAdapter")
            .field("io", &core::any::type_name::<S>())
            .field("inner", &self.inner)
            .finish()
    }
}

// Copied from Quinn v0.11 (MIT OR Apache-2.0):
// https://github.com/quinn-rs/quinn/blob/0.11.x/quinn/src/runtime.rs
pin_project_lite::pin_project! {
    /// Helper adapting a function `MakeFut` that constructs a single-use future `Fut` into a
    /// [`UdpPoller`] that may be reused indefinitely
    struct UdpPollHelper<MakeFut, Fut> {
        make_fut: MakeFut,
        #[pin]
        fut: Option<Fut>,
    }
}

impl<MakeFut, Fut> UdpPollHelper<MakeFut, Fut> {
    /// Construct a [`UdpPoller`] that calls `make_fut` to get the future to poll, storing it until
    /// it yields [`Poll::Ready`], then creating a new one on the next
    /// [`poll_writable`](UdpPoller::poll_writable)
    fn new(make_fut: MakeFut) -> Self {
        Self {
            make_fut,
            fut: None,
        }
    }
}

impl<MakeFut, Fut> UdpPoller for UdpPollHelper<MakeFut, Fut>
where
    MakeFut: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = io::Result<()>> + Send + Sync + 'static,
{
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();
        if this.fut.is_none() {
            this.fut.set(Some((this.make_fut)()));
        }

        // We're forced to `unwrap` here because `Fut` may be `!Unpin`, which means we can't safely
        // obtain an `&mut Fut` after storing it in `self.fut` when `self` is already behind `Pin`,
        // and if we didn't store it then we wouldn't be able to keep it alive between
        // `poll_writable` calls.
        let result = this.fut.as_mut().as_pin_mut().unwrap().poll(cx);
        if result.is_ready() {
            // Polling an arbitrary `Future` after it becomes ready is a logic error, so arrange for
            // a new `Future` to be created on the next call.
            this.fut.set(None);
        }

        result
    }
}

impl<MakeFut, Fut> fmt::Debug for UdpPollHelper<MakeFut, Fut> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpPollHelper").finish_non_exhaustive()
    }
}
