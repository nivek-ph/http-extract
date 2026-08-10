# http-extract

Strict, synchronous extraction of HTTP request metadata using `http` types.
The default API is framework-independent; an optional `axum` feature adds
socket-peer extraction from `ConnectInfo` request extensions.

The crate keeps transport facts separate from Header assertions. Values from
`Forwarded`, `X-Forwarded-*`, and provider-specific client-IP fields are raw and
untrusted until the deployment establishes an explicit proxy trust boundary.

## Install

Default features provide all common extractors:

```toml
[dependencies]
http-extract = "0.1"
```

Select only the API families an application uses:

```toml
[dependencies]
http-extract = { version = "0.1", default-features = false, features = [
  "authority",
  "content-type",
] }
```



## API

Header functions contain the parsing logic. Matching Request functions are
convenience wrappers that delegate through `request.headers()`.


| Feature/API family  | Purpose                                                          |
| ------------------- | ---------------------------------------------------------------- |
| `api_key`           | `X-API-Key`, then `Api-Key` fallback                             |
| `authority`         | URI authority and strict `Host` extraction                       |
| `authorization`     | Raw Authorization plus lightweight Bearer/Basic scheme routing   |
| `client_ip`         | Socket-peer helpers and default/custom Header selection          |
| `client_ip_headers` | Common provider and proxy client-IP fields                       |
| `content_type`      | Strict `Content-Type` parsing into `mime::Mime`                  |
| `forwarded`         | RFC 7239 `Forwarded` `for=` IP chains                            |
| `request_id`        | `X-Request-Id`, then `Request-Id` fallback                       |
| `x_forwarded`       | `X-Forwarded-For` and `X-Forwarded-Proto` parsing                |
| `header`            | Strict singular-field helpers and append-without-replace utility |


See the [feature and API map](https://github.com/nivek-ph/http-extract/blob/main/docs/api-map.md)
for exact function names and return types.

## Client IP boundary

`extract_client_ip` checks these Header sources in order:

1. RFC 7239 `Forwarded`;
2. `X-Forwarded-For`;
3. `X-Real-IP`;
4. `CF-Connecting-IP`.

This standard-first order is a library convention, not an RFC-defined
precedence or trust policy. `extract_client_ip_with_headers` accepts an
explicit ordered slice of `ClientIpHeader` values for deployment-specific
selection. A malformed first-present source fails instead of falling through.

`extract_socket_ip` reads Axum `ConnectInfo<SocketAddr>` when available, then a
direct `SocketAddr` request extension; it never reads Headers.
`extract_proxy_client_ip` checks the Header order above and falls back to that
peer only when all supported Headers are absent. Header-derived values remain
untrusted unless the deployment enforces a trusted-proxy boundary.

Read the [client IP trust boundary](https://github.com/nivek-ph/http-extract/blob/main/docs/trusted-proxies.md)
before using a Header-derived IP for authorization, rate limiting, or auditing.

## Features

Default features are `api-key`, `authority`, `authorization`, `client-ip`,
`client-ip-headers`, `content-type`, `forwarded`, `request-id`, and
`x-forwarded`.

- `client-ip` enables its Header parsing dependencies;
- `content-type` enables the optional `mime` dependency;
- non-default `axum` enables `client-ip` and the optional Axum dependency;
- `--no-default-features` leaves only `Error` and the generic Header helpers.

The default normal dependency tree does not include Axum, Tower, Tokio,
tracing, or OpenTelemetry. See the [feature guide](https://github.com/nivek-ph/http-extract/blob/main/docs/features.md)
for copyable configurations.

## Errors and sensitive values

Missing optional metadata returns `Ok(None)`. Duplicate, non-text, and invalid
fields return the crate-wide `Error`; errors identify only the field name and
category, never its value.

Authorization credentials and API keys are returned only by their explicit
extractors. Do not log or echo those values, cookies, request bodies, complete
query strings, or raw forwarding fields.

## Standards

The crate implements narrow extraction behavior, not complete protocol or
authentication implementations:

- [HTTP Semantics, RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html),
including [field semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-5),
[authority](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2), and
[Content-Type](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3);
- [Forwarded, RFC 7239](https://www.rfc-editor.org/rfc/rfc7239.html), limited to
continuous `for=` IP chains and subject to its
[security considerations](https://www.rfc-editor.org/rfc/rfc7239.html#section-8);
- [Bearer, RFC 6750 Section 2.1](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1)
and [Basic, RFC 7617 Section 2](https://www.rfc-editor.org/rfc/rfc7617.html#section-2),
used only for lightweight scheme recognition without authentication or
Basic decoding.

`X-Forwarded-*` and provider-specific client-IP fields are de facto or vendor
conventions, not IETF standards. See
[standards and compatibility](https://github.com/nivek-ph/http-extract/blob/main/docs/standards.md)
for the supported boundary.

## Axum example

The runnable [Axum example](examples/axum/README.md) demonstrates peer
extraction, request metadata, client-IP selection, error handling, and safe
observable output:

```sh
cargo run --example axum-demo --features axum
```

The full guide is available in the [docs](https://github.com/nivek-ph/http-extract/blob/main/docs/README.md)
mdBook sources.
The crate declares Rust 1.96.0 and is licensed under MIT or Apache-2.0.
