// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNS over TLS I/O stream implementation for Rustls

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::net::SocketAddr;
use std::io;

use futures_util::future::BoxFuture;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;

use crate::runtime::RuntimeProvider;
use crate::tcp::{DnsTcpStream, TcpStream};
use crate::xfer::BufDnsStreamHandle;

/// Initializes a TlsStream with an existing stream.
///
/// This is intended for use with a TlsListener and Incoming connections
pub fn tls_from_stream<S: DnsTcpStream>(
    stream: S,
    peer_addr: SocketAddr,
) -> (TcpStream<S>, BufDnsStreamHandle) {
    let (message_sender, outbound_messages) = BufDnsStreamHandle::new(peer_addr);
    let stream = TcpStream::from_stream_with_receiver(stream, peer_addr, outbound_messages);
    (stream, message_sender)
}

/// Creates a new TlsStream to the specified name_server
///
/// [RFC 7858](https://tools.ietf.org/html/rfc7858), DNS over TLS, May 2016
///
/// ```text
/// 3.2.  TLS Handshake and Authentication
///
///   Once the DNS client succeeds in connecting via TCP on the well-known
///   port for DNS over TLS, it proceeds with the TLS handshake [RFC5246],
///   following the best practices specified in [BCP195].
///
///   The client will then authenticate the server, if required.  This
///   document does not propose new ideas for authentication.  Depending on
///   the privacy profile in use (Section 4), the DNS client may choose not
///   to require authentication of the server, or it may make use of a
///   trusted Subject Public Key Info (SPKI) Fingerprint pin set.
///
///   After TLS negotiation completes, the connection will be encrypted and
///   is now protected from eavesdropping.
/// ```
///
/// # Arguments
///
/// * `name_server` - IP and Port for the remote DNS resolver
/// * `bind_addr` - IP and port to connect from
/// * `dns_name` - The DNS name associated with a certificate
#[allow(clippy::type_complexity)]
pub fn tls_connect<P: RuntimeProvider>(
    name_server: SocketAddr,
    server_name: ServerName<'static>,
    client_config: Arc<ClientConfig>,
    provider: P,
) -> (
    BoxFuture<'static, Result<TcpStream<P::Tls>, io::Error>>,
    BufDnsStreamHandle,
) {
    tls_connect_with_bind_addr(name_server, None, server_name, client_config, provider)
}

/// Creates a new TlsStream to the specified name_server connecting from a specific address.
///
/// # Arguments
///
/// * `name_server` - IP and Port for the remote DNS resolver
/// * `bind_addr` - IP and port to connect from
/// * `dns_name` - The DNS name associated with a certificate
#[allow(clippy::type_complexity)]
pub fn tls_connect_with_bind_addr<P: RuntimeProvider>(
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    server_name: ServerName<'static>,
    client_config: Arc<ClientConfig>,
    provider: P,
) -> (
    BoxFuture<'static, Result<TcpStream<P::Tls>, io::Error>>,
    BufDnsStreamHandle,
) {
    let (message_sender, outbound_messages) = BufDnsStreamHandle::new(name_server);

    // This set of futures collapses the next tcp socket into a stream which can be used for
    //  sending and receiving tcp packets.
    let stream = Box::pin(async move {
        let tcp_stream = provider.connect_tcp(name_server, bind_addr, None).await?;
        let tls_stream = provider
            .connect_tls(tcp_stream, server_name, client_config)
            .await?;

        Ok(TcpStream::from_stream_with_receiver(
            tls_stream,
            name_server,
            outbound_messages,
        ))
    });

    (stream, message_sender)
}

/// Creates a new TlsStream to the specified name_server connecting from a specific address.
///
/// # Arguments
///
/// * `name_server` - IP and Port for the remote DNS resolver
/// * `bind_addr` - IP and port to connect from
/// * `dns_name` - The DNS name associated with a certificate
#[allow(clippy::type_complexity)]
pub fn tls_connect_with_future<P: RuntimeProvider, F>(
    future: F,
    name_server: SocketAddr,
    server_name: ServerName<'static>,
    client_config: Arc<ClientConfig>,
    provider: P,
) -> (
    BoxFuture<'static, Result<TcpStream<P::Tls>, io::Error>>,
    BufDnsStreamHandle,
)
where
    F: Future<Output = io::Result<P::Tcp>> + Send + 'static,
{
    let (message_sender, outbound_messages) = BufDnsStreamHandle::new(name_server);

    let stream = Box::pin(async move {
        let tcp_stream = future.await?;
        let tls_stream = provider
            .connect_tls(tcp_stream, server_name, client_config)
            .await?;

        Ok(TcpStream::from_stream_with_receiver(
            tls_stream,
            name_server,
            outbound_messages,
        ))
    });

    (stream, message_sender)
}
