//! Strict, trust-aware extraction of HTTP request metadata.
//!
//! This crate operates primarily on [`http`] types and does not require a web
//! framework, Tower, tracing, or OpenTelemetry. An opt-in `axum` feature adds
//! only transport-peer extraction from Axum request extensions. Forwarding
//! fields are never trusted implicitly.
//!
//! Public modules expose small synchronous extractors for one coherent field
//! responsibility. Applications compose only the modules they need at their
//! framework boundary; this crate does not impose a request-context aggregate
//! or an asynchronous adapter. Cargo features gate field-specific modules;
//! disabling default features leaves the shared [`header`] helpers and [`Error`]
//! available, and enabling a feature exposes only its documented module and
//! dependencies.

#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

#[cfg(feature = "api-key")]
pub mod api_key;

#[cfg(feature = "authority")]
pub mod authority;
#[cfg(feature = "authorization")]
pub mod authorization;
#[cfg(feature = "client-ip")]
pub mod client_ip;
#[cfg(feature = "client-ip-headers")]
pub mod client_ip_headers;
#[cfg(feature = "content-type")]
pub mod content_type;
#[cfg(feature = "forwarded")]
pub mod forwarded;

// extract header module
pub mod header;

#[cfg(feature = "request-id")]
pub mod request_id;
#[cfg(feature = "x-forwarded")]
pub mod x_forwarded;

mod error;

pub use error::Error;

pub use http::{HeaderMap, HeaderName, HeaderValue, Request};
