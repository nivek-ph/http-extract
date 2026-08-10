# http-extract

`http-extract` provides strict extraction of HTTP request
metadata. Its narrow `Forwarded` support extracts RFC 7239 `for=` IP chains.
The default core API uses types from the `http` crate and does not depend on
Axum, Tower, tracing, or OpenTelemetry. A non-default `axum` feature adds only
the request-extension peer adapter.

The crate separates two things that are easy to conflate:

- facts carried directly by a request URI or transport adapter;
- untrusted assertions parsed from forwarding, proxy, or provider fields.

Forwarding fields are never trusted by default. Authorization, API keys,
cookies, request bodies, and complete query strings are never extracted
implicitly.

The mdBook guide source is in [`docs`](docs/README.md); build it locally with
`mdbook build`.

## Standards and compatibility

The crate follows the stable RFC versions below only for the extraction
behavior its APIs document. It is not a complete HTTP or authentication
implementation.

- [HTTP Semantics, RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html):
  [Section 5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5) informs
  strict field handling,
  [Section 7.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2) covers
  request authority and `Host`, and
  [Section 8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3) covers
  `Content-Type`. The Authorization extractors use the
  [Section 11](https://www.rfc-editor.org/rfc/rfc9110.html#section-11)
  authentication framework only as context; they do not authenticate.
- [Forwarded, RFC 7239](https://www.rfc-editor.org/rfc/rfc7239.html): the crate
  implements a deliberately narrow profile of
  [Section 4](https://www.rfc-editor.org/rfc/rfc7239.html#section-4),
  [`for=` in Section 5.2](https://www.rfc-editor.org/rfc/rfc7239.html#section-5.2),
  and IP identifiers from
  [Section 6.1](https://www.rfc-editor.org/rfc/rfc7239.html#section-6.1). It
  extracts only a continuous IP chain and rejects missing, unknown,
  obfuscated, or non-IP nodes. It does not expose the full Forwarded object
  model. Trust still follows the
  [Section 8](https://www.rfc-editor.org/rfc/rfc7239.html#section-8) security
  boundary. Parsing or selecting a value does not establish trust.
- [Bearer Token Usage, RFC 6750 Section 2.1](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1):
  helpers recognize the Bearer scheme and return the raw credential substring;
  they do not validate tokens or authenticate requests.
- [Basic Authentication, RFC 7617 Section 2](https://www.rfc-editor.org/rfc/rfc7617.html#section-2):
  helpers recognize the Basic scheme and return the raw credential substring;
  they do not validate credentials, decode Base64, or authenticate requests.

`X-Forwarded-For`, `X-Forwarded-Proto`, `CF-Connecting-IP`,
`CloudFront-Viewer-Address`, `Fly-Client-IP`, `True-Client-IP`,
`X-Envoy-External-Address`, and `X-Real-IP` are common de facto or vendor
fields, not IETF standards. Their extractors only parse raw assertions; a
deployment must establish trust independently.

The declared Rust compatibility baseline is Rust 1.96.0, matching
`package.rust-version` and `rust-toolchain.toml`. Default features enable every
documented extraction module. With `default-features = false`, consumers opt
into the modules they need; see [Cargo features](#cargo-features) and the
[mdBook compatibility chapter](docs/standards.md).

## Request, headers, and Parts

Extraction functions accept the smallest input that carries the required
fact. This supports Tower's borrowed `Request<B>` and Axum-style
`FromRequestParts` code without a framework trait:

```rust
# #[cfg(feature = "authority")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use http::Request;
use http_extract::authority::{extract_header_authority, extract_request_authority};

let request = Request::builder()
    .uri("https://example.com/items")
    .header("host", "fallback.example")
    .body(())?;

let authority = extract_request_authority(&request)?;
assert_eq!(authority.unwrap().as_str(), "example.com");

let (parts, _) = request.into_parts();
let host = extract_header_authority(&parts.headers)?;
assert_eq!(host.unwrap().as_str(), "fallback.example");
# Ok(())
# }
# #[cfg(not(feature = "authority"))]
# fn main() {}
```

## Module and API map

Each public module owns one coherent extraction responsibility:

- `authority::extract_request_authority` returns a complete request's URI
  authority, consulting `Host` only when the URI has no authority;
- `authority::extract_header_authority` strictly extracts only the `Host`
  authority;
- `content_type::extract_header_content_type` parses the singular `Content-Type`
  field, with `extract_request_content_type` as a request convenience;
- `request_id::extract_header_request_id` prefers `X-Request-Id` and falls back
  to `Request-Id`; `extract_request_request_id` delegates from a request;
- `forwarded::extract_header_forwarded_for` extracts the standardized,
  untrusted `Forwarded` `for=` IP chain;
- `x_forwarded` separately parses the de facto `X-Forwarded-For` and
  `X-Forwarded-Proto` conventions as untrusted assertions;
- `client_ip::extract_peer_ip` returns an out-of-band transport peer IP;
  `extract_client_ip` uses the documented default Header order, while
  `extract_client_ip_with_headers` accepts caller-defined `ClientIpHeader`
  sources in order;
- `client_ip_headers` contains direct raw extraction for common single-value
  provider/proxy IP fields; these values are never trusted automatically;
- `authorization::extract_header_authorization` returns the raw singular field,
  while `extract_request_authorization` provides the same behavior for a
  complete request; the module's Bearer and Basic helpers only route matching
  schemes to raw credential strings;
- `api_key::extract_header_api_key` reads the fixed API-key fields, while
  `extract_request_api_key` provides the same policy for a complete request;
- `header::extract_single_header_value`, `extract_single_header_text`, and
  `append_header_value` contain shared strict field utilities.

All APIs are synchronous and operate on the smallest relevant `http` input.
Applications select and compose only the extractors they need at their own
framework boundary:

```rust
# #[cfg(all(feature = "authority", feature = "client-ip", feature = "content-type", feature = "request-id"))]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use http::Request;
use http_extract::{
    authority::extract_request_authority,
    client_ip::extract_client_ip,
    content_type::extract_header_content_type,
    request_id::extract_header_request_id,
};

let request = Request::builder()
    .uri("https://example.com/items?token=not-collected")
    .header("cf-connecting-ip", "198.51.100.9")
    .header("x-request-id", "request-123")
    .header("content-type", "application/json")
    .body(())?;
let client = extract_client_ip(request.headers())?.unwrap();
assert_eq!(client.to_string(), "198.51.100.9");
assert_eq!(
    extract_request_authority(&request)?.unwrap().as_str(),
    "example.com",
);
assert_eq!(
    extract_header_request_id(request.headers())?,
    Some("request-123")
);
assert_eq!(
    extract_header_content_type(request.headers())?.unwrap(),
    mime::APPLICATION_JSON,
);
# Ok(())
# }
# #[cfg(not(all(feature = "authority", feature = "client-ip", feature = "content-type", feature = "request-id")))]
# fn main() {}
```

The example policy treats `X-Request-Id` as preferred and `Request-Id` as its
fallback. They are application-configured field names, not a claim that both
are universal IETF-standard request-ID fields.

## Client IP selection

```rust
# #[cfg(feature = "client-ip")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use http::HeaderMap;
use http_extract::{
    client_ip::{ClientIpHeader, extract_client_ip, extract_client_ip_with_headers},
};

let mut headers = HeaderMap::new();
headers.insert("cf-connecting-ip", "198.51.100.1".parse()?);
headers.insert("x-real-ip", "198.51.100.2".parse()?);

assert_eq!(extract_client_ip(&headers)?.unwrap().to_string(), "198.51.100.2");
assert_eq!(
    extract_client_ip_with_headers(
        &headers,
        &[ClientIpHeader::CfConnectingIp, ClientIpHeader::XRealIp],
    )?
    .unwrap()
    .to_string(),
    "198.51.100.1",
);
# Ok(())
# }
# #[cfg(not(feature = "client-ip"))]
# fn main() {}
```

The default order is RFC 7239 `Forwarded`, `X-Forwarded-For`, `X-Real-IP`, then
`CF-Connecting-IP`. This standard-first precedence is a library convention,
not an RFC-defined precedence or trust policy.
`extract_client_ip_with_headers` accepts the same supported sources in any order
as `ClientIpHeader` values.
Runtime configuration strings can be converted once with `FromStr` or
`ClientIpHeader::try_from`; invalid and unsupported names return
`Error::UnsupportedHeaderName`.
Only an absent source falls through: a malformed first-present source returns
an error. For the two chain fields, selection returns the rightmost address.

Both functions inspect Headers only. Their result is a raw, untrusted assertion
and must not be used for authorization or rate limiting unless the deployment
separately guarantees that the relevant proxy overwrites the selected field.
Use `extract_peer_ip` when the transport peer itself is the desired network
fact.

## Common single-value client IP fields

`client_ip_headers` provides direct Header and Request functions for:

- `CF-Connecting-IP`;
- `CloudFront-Viewer-Address`, including IPv4 and IPv6 `IP:port` forms;
- `Fly-Client-IP`;
- `True-Client-IP`;
- `X-Envoy-External-Address`;
- `X-Real-IP`.

For example, `extract_header_cf_connecting_ip` and
`extract_request_cf_connecting_ip` return `Option<IpAddr>`. The other field
names follow the same `extract_header_*` / `extract_request_*` convention.
Every field is strict and singular: duplicates, non-text values, and malformed
addresses fail without including the value in the error.

These are provider or proxy conventions, not independently trustworthy facts.
The default selector includes `CF-Connecting-IP` and `X-Real-IP`; other fields
can be selected explicitly with `extract_client_ip_with_headers`. Selection does
not authenticate the sender or establish a trust boundary.

## Header utility

`header::append_header_value` is a thin wrapper around `HeaderMap::append`. It
accepts already validated `HeaderName` and `HeaderValue` values, never replaces
existing field lines, and returns whether the map already contained the name.
Because the typed inputs are validated before the call, appending is infallible
and does not create a diagnostic path that could echo a value.

## Authorization

`authorization::extract_header_authorization` returns the singular
`Authorization` field unchanged, including an empty value.
`authorization::extract_request_authorization` delegates the same extraction
for a complete `Request<B>`. The `extract_header_bearer_token` and
`extract_header_basic_credentials` helpers perform only ASCII
case-insensitive scheme routing and require one or more ASCII spaces before the
credentials. They consume only the first required space and return the rest
unchanged, preserving any additional leading spaces. Their `extract_request_*`
counterparts delegate from a complete request. A missing separator or another
scheme returns `None`, while `Bearer ` and `Basic ` return `Some("")`. Returned
values are sensitive and must not be logged or echoed; duplicate and non-text
fields return errors without containing the field value.

For standards context, see the HTTP authentication framework in
[RFC 9110 Section 11](https://www.rfc-editor.org/rfc/rfc9110.html#section-11),
Bearer usage in
[RFC 6750 Section 2.1](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1),
and Basic in
[RFC 7617 Section 2](https://www.rfc-editor.org/rfc/rfc7617.html#section-2).
The crate only recognizes the scheme and extracts the raw credential string;
it does not implement authentication, complete RFC syntax validation, or Basic
decoding.

## API keys

`api_key::extract_header_api_key` reads `X-API-Key` first and falls back to
`Api-Key` only when the preferred field is absent. It returns the selected
value unchanged, including `Some("")` for an empty field.
`api_key::extract_request_api_key` applies exactly the same behavior to a
complete `Request<B>`. These functions select and decode a field; they do not
authenticate the key. Returned values are sensitive and must not be logged or
echoed. Duplicate selected fields and non-text values return errors that do not
contain the field value.

## Request IDs

`request_id::extract_header_request_id` uses the fixed common precedence
`X-Request-Id` first, then `Request-Id` only when the preferred field is absent.
An empty preferred value is preserved and stops fallback. The Request function
only delegates to the Header function. The crate does not generate or validate
request IDs, and these configured names are not presented as universal IETF
standard fields.

## Cargo features

Default features enable the complete common API. Applications can disable them
and opt into only the modules they use:

```toml
[dependencies]
http-extract = { version = "0.1.0-alpha.0", default-features = false, features = [
  "authority",
  "content-type",
] }
```

Available module features are `api-key`, `authority`, `authorization`, `axum`,
`client-ip`, `client-ip-headers`, `content-type`, `forwarded`, `request-id`, and
`x-forwarded`. `client-ip` enables `client-ip-headers`, `forwarded`, and
`x-forwarded` because its selectors use those parsing modules.
The non-default `axum` feature enables `client-ip` and the optional Axum
dependency so `client_ip::extract_axum_peer_address` and
`client_ip::extract_axum_peer_ip` can read a socket peer from a request
extension.
`content-type` enables the optional `mime` dependency. The crate-wide `Error`
and generic `header` utilities remain available with `--no-default-features`.

## Errors and sensitive values

Every fallible public operation uses the crate-wide `http_extract::Error`.
Missing optional metadata is `Ok(None)`. Callers only need to handle the small
top-level categories `InvalidHeader` and `DuplicateHeader`. Errors identify the
affected Header without exposing parser details or field values.

Errors never contain Header values. Raw Authorization and API-key values are
returned only through their explicit extractors and must not be logged or
echoed.

## example

[`examples/axum`](examples/axum/README.md) shows an Axum request
boundary. With `--features axum`, the handler obtains the transport peer using
`client_ip::extract_axum_peer_address` and `extract_axum_peer_ip`, calls only
the independent extractors it needs, and returns a safe JSON summary.
