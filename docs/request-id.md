# Request IDs

The request ID extractor uses a fixed practical precedence:

1. `X-Request-Id`;
2. `Request-Id`, only when the preferred field is absent.

The selected value is returned unchanged. An empty `X-Request-Id` therefore
returns `Some("")` and does not fall back. Duplicate selected fields and
non-text values fail without including the value in the error.

```rust
use http::Request;
use http_extract::request_id::extract_request_request_id;

let request = Request::builder()
    .header("request-id", "fallback")
    .header("x-request-id", "preferred")
    .body(())?;
assert_eq!(
    extract_request_request_id(&request)?,
    Some("preferred")
);
# Ok::<(), Box<dyn std::error::Error>>(())
```

These are crate-configured common field names, not a claim that either is a
universal IETF-standard request ID field. The crate does not generate, validate,
or propagate identifiers. The distinction from standardized fields is summarized
in [Standards and compatibility](standards.md).
