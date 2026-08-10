# Getting started

The crate declares Rust 1.96.0 as its compiler compatibility baseline. Default
features provide the complete documented extraction API.

With all common API families enabled:

```toml
[dependencies]
http-extract = "0.1"
```

For a smaller dependency surface, disable defaults and enable only the features
you use:

```toml
[dependencies]
http-extract = { version = "0.1", default-features = false, features = [
  "authority",
  "content-type",
] }
```

Header functions contain the parsing logic. Request functions are convenience
wrappers that only delegate through `request.headers()`:

```rust
use http::Request;
use http_extract::{extract_request_authority, extract_request_content_type};

let request = Request::builder()
    .uri("https://example.com/items")
    .header("content-type", "application/json")
    .body(())?;

assert_eq!(
    extract_request_authority(&request)?.unwrap().as_str(),
    "example.com"
);
assert_eq!(
    extract_request_content_type(&request)?.unwrap().essence_str(),
    "application/json",
);
# Ok::<(), Box<dyn std::error::Error>>(())
```

A socket peer is not an HTTP field. Obtain it from the server adapter before
calling `extract_peer_ip`. With the non-default `axum` feature,
`extract_axum_peer_address` reads an existing `ConnectInfo<SocketAddr>` request
extension, while `extract_axum_peer_ip` returns its IP component; neither
fabricates that fact. The
Header-based `extract_client_ip` convenience does not use or authenticate the
transport peer, so its result remains untrusted.

Before deployment, review [Standards and compatibility](standards.md),
[Cargo features](features.md), and the [client IP trust boundary](trusted-proxies.md).
