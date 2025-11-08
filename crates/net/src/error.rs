// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Error types for the net crate

#![deny(missing_docs)]

use alloc::boxed::Box;
use alloc::fmt;
use alloc::string::String;
#[cfg(feature = "wasm-bindgen")]
use alloc::string::ToString;
#[cfg(feature = "std")]
use alloc::sync::Arc;
use core::cmp::Ordering;
#[cfg(feature = "std")]
use std::io;

use enum_as_inner::EnumAsInner;
#[cfg(feature = "backtrace")]
use hickory_proto::ExtBacktrace;
use hickory_proto::{
    DnsError, ProtoError, ProtoErrorKind,
    rr::{Record, rdata::SOA},
};
use thiserror::Error;

/// An alias for results returned by functions of this crate
pub type NetResult<T> = ::core::result::Result<T, NetError>;

/// The error type for errors that get returned in the crate
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub struct NetError {
    /// Kind of error that occurred
    pub kind: NetErrorKind,
    /// Backtrace to the source of the error
    #[cfg(feature = "backtrace")]
    pub backtrack: Option<ExtBacktrace>,
}

impl NetError {
    /// Get the kind of the error
    #[inline]
    pub fn kind(&self) -> &NetErrorKind {
        &self.kind
    }

    /// Returns true if the domain does not exist
    #[inline]
    pub fn is_nx_domain(&self) -> bool {
        match &self.kind {
            NetErrorKind::Proto(proto) => proto.is_nx_domain(),
            _ => false,
        }
    }

    /// Returns true if the error represents NoRecordsFound
    #[inline]
    pub fn is_no_records_found(&self) -> bool {
        match &self.kind {
            NetErrorKind::Proto(proto) => proto.is_no_records_found(),
            _ => false,
        }
    }

    /// Returns the SOA record, if the error contains one
    #[inline]
    pub fn into_soa(self) -> Option<Box<Record<SOA>>> {
        match self.kind {
            NetErrorKind::Proto(proto) => proto.into_soa(),
            _ => None,
        }
    }

    /// Compare two errors to see if one contains a server response.
    pub fn cmp_specificity(&self, other: &Self) -> Ordering {
        let kind = self.kind();
        let other = other.kind();

        // First check for Proto-wrapped errors with NoRecordsFound
        match (kind, other) {
            (
                NetErrorKind::Proto(ProtoError {
                    kind: ProtoErrorKind::Dns(DnsError::NoRecordsFound { .. }),
                    ..
                }),
                NetErrorKind::Proto(ProtoError {
                    kind: ProtoErrorKind::Dns(DnsError::NoRecordsFound { .. }),
                    ..
                }),
            ) => return Ordering::Equal,
            (
                NetErrorKind::Proto(ProtoError {
                    kind: ProtoErrorKind::Dns(DnsError::NoRecordsFound { .. }),
                    ..
                }),
                _,
            ) => return Ordering::Greater,
            (
                _,
                NetErrorKind::Proto(ProtoError {
                    kind: ProtoErrorKind::Dns(DnsError::NoRecordsFound { .. }),
                    ..
                }),
            ) => return Ordering::Less,
            _ => (),
        }

        // Check IO errors
        #[cfg(feature = "std")]
        match (kind, other) {
            (NetErrorKind::Io { .. }, NetErrorKind::Io { .. }) => return Ordering::Equal,
            (NetErrorKind::Io { .. }, _) => return Ordering::Greater,
            (_, NetErrorKind::Io { .. }) => return Ordering::Less,
            _ => (),
        }

        // Check Timeout errors
        match (kind, other) {
            (NetErrorKind::Timeout, NetErrorKind::Timeout) => return Ordering::Equal,
            (NetErrorKind::Timeout, _) => return Ordering::Greater,
            (_, NetErrorKind::Timeout) => return Ordering::Less,
            _ => (),
        }

        Ordering::Equal
    }
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        cfg_if::cfg_if! {
            if #[cfg(feature = "backtrace")] {
                if let Some(backtrace) = &self.backtrack {
                    fmt::Display::fmt(&self.kind, f)?;
                    fmt::Debug::fmt(backtrace, f)
                } else {
                    fmt::Display::fmt(&self.kind, f)
                }
            } else {
                fmt::Display::fmt(&self.kind, f)
            }
        }
    }
}

impl<E: Into<NetErrorKind>> From<E> for NetError {
    fn from(error: E) -> Self {
        Self {
            kind: error.into(),
            #[cfg(feature = "backtrace")]
            backtrack: hickory_proto::trace!(),
        }
    }
}

impl From<ProtoErrorKind> for NetError {
    fn from(kind: ProtoErrorKind) -> Self {
        NetErrorKind::Proto(ProtoError::from(kind)).into()
    }
}

impl From<DnsError> for NetError {
    fn from(err: DnsError) -> Self {
        NetErrorKind::Proto(ProtoError::from(err)).into()
    }
}

impl From<&'static str> for NetError {
    fn from(msg: &'static str) -> Self {
        NetErrorKind::Message(msg).into()
    }
}

impl From<String> for NetError {
    fn from(msg: String) -> Self {
        NetErrorKind::Msg(msg).into()
    }
}

#[cfg(target_os = "android")]
impl From<jni::errors::Error> for NetError {
    fn from(e: jni::errors::Error) -> Self {
        NetErrorKind::Jni(Arc::new(e)).into()
    }
}

#[cfg(feature = "std")]
impl From<NetError> for io::Error {
    fn from(e: NetError) -> Self {
        match e.kind() {
            NetErrorKind::Timeout => Self::new(io::ErrorKind::TimedOut, e),
            _ => Self::other(e),
        }
    }
}

#[cfg(feature = "wasm-bindgen")]
impl From<NetError> for wasm_bindgen_crate::JsValue {
    fn from(e: NetError) -> Self {
        js_sys::Error::new(&e.to_string()).into()
    }
}

/// The error kind for errors that get returned in the crate
#[derive(Clone, Debug, EnumAsInner, Error)]
#[non_exhaustive]
pub enum NetErrorKind {
    /// An error from the protocol layer
    #[error("proto error: {0}")]
    Proto(#[from] ProtoError),

    /// A UDP response was received with an incorrect transaction id, likely indicating a
    /// cache-poisoning attempt.
    #[error("bad transaction id received")]
    BadTransactionId,

    /// The underlying resource is too busy
    ///
    /// This is a signal that an internal resource is too busy. The intended action should be tried
    /// again, ideally after waiting for a little while for the situation to improve. Alternatively,
    /// the action could be tried on another resource (for example, in a name server pool).
    #[error("resource too busy")]
    Busy,

    /// An error with an arbitrary message, referenced as &'static str
    #[error("{0}")]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[error("{0}")]
    Msg(String),

    /// No resolvers available
    #[error("no connections available")]
    NoConnections,

    // foreign
    /// An error got returned from IO
    #[cfg(feature = "std")]
    #[error("io error: {0}")]
    Io(Arc<io::Error>),

    /// A request timed out
    #[error("request timed out")]
    Timeout,

    /// A Quinn (Quic) connection error occurred
    #[cfg(feature = "__quic")]
    #[error("error creating quic connection: {0}")]
    QuinnConnect(#[from] quinn::ConnectError),

    /// A Quinn (QUIC) connection error occurred
    #[cfg(feature = "__quic")]
    #[error("error with quic connection: {0}")]
    QuinnConnection(#[from] quinn::ConnectionError),

    /// A Quinn (QUIC) write error occurred
    #[cfg(feature = "__quic")]
    #[error("error writing to quic connection: {0}")]
    QuinnWriteError(#[from] quinn::WriteError),

    /// A Quinn (QUIC) read error occurred
    #[cfg(feature = "__quic")]
    #[error("error writing to quic read: {0}")]
    QuinnReadError(#[from] quinn::ReadExactError),

    /// A Quinn (QUIC) stream error occurred
    #[cfg(feature = "__quic")]
    #[error("referenced a closed QUIC stream: {0}")]
    QuinnStreamError(#[from] quinn::ClosedStream),

    /// A Quinn (QUIC) configuration error occurred
    #[cfg(feature = "__quic")]
    #[error("error constructing quic configuration: {0}")]
    QuinnConfigError(#[from] quinn::ConfigError),

    /// QUIC TLS config must include an AES-128-GCM cipher suite
    #[cfg(feature = "__quic")]
    #[error("QUIC TLS config must include an AES-128-GCM cipher suite")]
    QuinnTlsConfigError(#[from] quinn::crypto::rustls::NoInitialCipherSuite),

    /// Unknown QUIC stream used
    #[cfg(feature = "__quic")]
    #[error("an unknown quic stream was used")]
    QuinnUnknownStreamError,

    /// A quic message id should always be 0
    #[cfg(feature = "__quic")]
    #[error("quic messages should always be 0, got: {0}")]
    QuicMessageIdNot0(u16),

    /// A Rustls error occurred
    #[cfg(feature = "__tls")]
    #[error("rustls construction error: {0}")]
    RustlsError(#[from] rustls::Error),

    /// Case randomization is enabled, and a server did not echo a query name back with the same
    /// case.
    #[error("case of query name in response did not match")]
    QueryCaseMismatch,

    /// A JNI call error
    #[cfg(target_os = "android")]
    #[error("JNI call error: {0}")]
    Jni(Arc<jni::errors::Error>),
}

#[cfg(feature = "std")]
impl From<io::Error> for NetErrorKind {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::TimedOut => Self::Timeout,
            _ => Self::Io(e.into()),
        }
    }
}
