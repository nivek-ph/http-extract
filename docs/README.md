# http-extract

> **Extract the signal. Keep trust explicit.**

`http-extract` is a synchronous, framework-independent Rust library for strict
HTTP request metadata extraction. Its public functions accept `http` crate
types and return ordinary Rust values such as `&str`, `u64`, `Mime`,
`Authority`, `IpAddr`, and `Vec<IpAddr>`.

## One small API, one hard boundary

The library deliberately separates two kinds of information:

| Request and transport facts | Raw Header assertions |
| --- | --- |
| URI authority, Content-Type, request ID, socket peer | `Forwarded`, `X-Forwarded-*`, provider client-IP fields |
| Read through small, direct functions | Parsed without silently granting trust |

Forwarding fields are never trusted merely because they are present. Errors
contain field names, never parser details or raw field values. Authorization
credentials, API keys, cookies, bodies, complete query strings, and raw
forwarding fields must not be logged.

## Start here

1. [Install the crate and run a first extraction](getting-started.md).
2. [Understand the client IP trust boundary](trusted-proxies.md).
3. [Find the feature and API family you need](features.md).
4. [Run the production-oriented Axum example](axum-example.md).

The [API documentation](https://docs.rs/http-extract) is the complete type-level
reference. The exact protocol boundary is documented in
[Standards and compatibility](standards.md).

## Framework boundary

The default library core is synchronous and framework-independent. Axum is an
optional, non-default dependency used only for the transport-peer extension
adapter and the runnable example. The declared compiler baseline is Rust
1.96.0.
