# Cargo features

The crate declares Rust 1.96.0 as its compiler compatibility baseline. Default
features enable the complete common API: `api-key`, `authority`,
`authorization`, `client-ip`, `client-ip-headers`, `content-type`, `forwarded`,
`request-id`, and `x-forwarded`.

| Feature | Adds |
| --- | --- |
| `api-key` | Fixed `X-API-Key` / `Api-Key` extraction |
| `authority` | URI authority and strict `Host` extraction |
| `authorization` | Raw Authorization and lightweight Bearer/Basic routing |
| `axum` | Optional Axum `ConnectInfo<SocketAddr>` peer address/IP adapters; also enables `client-ip` |
| `client-ip` | Peer helpers and default/custom Header-based IP selection |
| `client-ip-headers` | Common single-value provider/proxy IP fields |
| `content-type` | Content-Type parsing and optional `mime` dependency |
| `forwarded` | Strict RFC 7239 `for=` IP-chain extraction |
| `request-id` | Fixed X-Request-Id then Request-Id precedence |
| `x-forwarded` | Raw X-Forwarded-For and X-Forwarded-Proto parsing |

`client-ip` enables `client-ip-headers`, `forwarded`, and `x-forwarded` because
its selectors use those parsing APIs. The crate-wide `Error` and generic
`header` utilities remain available with no default features.

Useful checks for consumers and contributors:

```sh
cargo check --no-default-features
cargo test --no-default-features --features authority,content-type,request-id
cargo test --no-default-features --features client-ip
cargo test --no-default-features --features client-ip-headers
```

Axum is an optional, non-default library dependency used only by the small
transport-peer adapter and the runnable example. Enable it explicitly:

```sh
cargo run --example axum-demo --features axum
```

Tower, Tokio, and tracing are not required by the default library API. The
example uses them as development dependencies.

This feature layout does not imply additional runtime compatibility. See
[Standards and compatibility](standards.md) for the protocol support boundary.
