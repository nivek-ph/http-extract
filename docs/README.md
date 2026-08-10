# http-extract

`http-extract` is a synchronous, framework-independent Rust library for strict
HTTP request metadata extraction. Its public functions accept `http` crate
types and return ordinary Rust values such as `&str`, `u64`, `Mime`,
`Authority`, `IpAddr`, and `Vec<IpAddr>`.

The API separates two categories:

1. request and transport facts, such as URI authority and the socket peer;
2. raw, untrusted proxy assertions from `Forwarded`, `X-Forwarded-*`, or
   provider-specific fields.

Forwarding fields are never trusted merely because they are present. Errors
contain field names, never parser details or raw field values.
Authorization credentials, API keys, cookies, bodies, complete query strings,
and raw forwarding fields must not be logged.

Start with [Getting started](getting-started.md), then read the
[standards and compatibility](standards.md) boundary and the
[client IP trust boundary](trusted-proxies.md) before using a Header-derived IP
for access control, rate limiting, or audit decisions. The declared Rust baseline is
Rust 1.96.0.

The [API documentation](https://docs.rs/http-extract) is the complete type-level
reference. The repository includes a runnable production-oriented
[Axum example](axum-example.md). Axum is an optional, non-default dependency for
the transport-peer extension adapter and is not part of the default library
core.
