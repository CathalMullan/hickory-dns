use alloc::boxed::Box;
use alloc::sync::Arc;
use core::fmt;
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::task::{Context, Poll};
use quinn::{AsyncTimer, Runtime};
use std::io;
use std::time::Instant;

use crate::runtime::{RuntimeProvider, Spawn, Time};

/// Adapter from `RuntimeProvider` to Quinn's runtime trait.
pub struct QuinnAdapter<P: RuntimeProvider> {
    provider: P,
}

impl<P: RuntimeProvider> QuinnAdapter<P> {
    /// Wrap a runtime to support Quinn.
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P: RuntimeProvider> Runtime for QuinnAdapter<P> {
    fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        Box::pin(QuinnTimer::<P>::new(deadline))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.provider.create_handle().spawn_detached(future);
    }

    fn wrap_udp_socket(
        &self,
        sock: std::net::UdpSocket,
    ) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        let Some(quic_binder) = self.provider.quic_binder() else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "QUIC not supported by this runtime provider",
            ));
        };

        let local_addr = sock.local_addr()?;
        let server_addr = sock.peer_addr().unwrap_or_else(|_| {
            if local_addr.is_ipv4() {
                core::net::SocketAddr::from(([0, 0, 0, 0], 0))
            } else {
                core::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
            }
        });

        quic_binder.bind_quic(local_addr, server_addr)
    }
}

impl<P: RuntimeProvider> fmt::Debug for QuinnAdapter<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuinnAdapter")
            .field("provider", &core::any::type_name::<P>())
            .finish()
    }
}

/// Adapter from `RuntimeProvider` timer to Quinn's `AsyncTimer`.
struct QuinnTimer<P: RuntimeProvider> {
    deadline: Instant,
    sleep: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    _marker: PhantomData<P>,
}

impl<P: RuntimeProvider> QuinnTimer<P> {
    fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            sleep: None,
            _marker: PhantomData,
        }
    }
}

impl<P: RuntimeProvider> AsyncTimer for QuinnTimer<P> {
    fn reset(mut self: Pin<&mut Self>, deadline: Instant) {
        self.deadline = deadline;
        self.sleep = None;
    }

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let now = Instant::now();

        if now >= self.deadline {
            return Poll::Ready(());
        }

        if self.sleep.is_none() {
            if let Some(duration) = self.deadline.checked_duration_since(now) {
                self.sleep = Some(Box::pin(P::Timer::delay_for(duration)));
            }
        }

        if let Some(sleep) = &mut self.sleep {
            sleep.as_mut().poll(cx)
        } else {
            Poll::Ready(())
        }
    }
}

impl<P: RuntimeProvider> fmt::Debug for QuinnTimer<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuinnTimer")
            .field("deadline", &self.deadline)
            .field("sleep", &self.sleep.as_ref().map(|_| "Some(Future)"))
            .field("_marker", &self._marker)
            .finish()
    }
}
