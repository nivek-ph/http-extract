# Axum request metadata example

This example shows how an Axum handler can call the framework-independent
`http-extract` functions directly. The handler extracts:

- the transport peer address and IP from Axum's request extensions using
  `client_ip::extract_axum_peer_address` and `extract_axum_peer_ip`;
- a best-effort client IP using `client_ip::extract_client_ip`;
- request authority, request ID, and Content-Type;
- masked Authorization, API-key, and cookie values plus cookie counts.

`extract_client_ip` uses this default Header order:

1. RFC 7239 `Forwarded`;
2. `X-Forwarded-For`;
3. `X-Real-IP`;
4. `CF-Connecting-IP`.

This standard-first order is a library convention, not an RFC-defined
precedence or trust policy. The result is a raw, untrusted Header assertion.
Before using it for authorization, rate
limiting, or auditing, the deployment must restrict access to controlled
proxies and ensure that the selected field is overwritten. Callers needing a
different order can use `extract_client_ip_with_headers` with an ordered
`ClientIpHeader` slice.

## Run locally

```sh
LISTEN_ADDR=127.0.0.1:3000 cargo run --example axum-demo --features axum
```

In another terminal:

```sh
curl -i 'http://127.0.0.1:3000/request-context?private=not-logged' \
  -H 'Host: api.example.test' \
  -H 'X-Real-IP: 198.51.100.9' \
  -H 'X-Request-Id: demo-123' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer not-logged' \
  -H 'Cookie: session=not-logged' \
  -H 'X-Api-Key: not-logged'
```

The response is `200 OK` with a JSON object containing the transport peer,
selected Header IP/source, authority, request ID, Content-Type, and masked
sensitive fields. Values longer than four characters retain only their first
and last two characters (`aa***bb`); shorter values are fully replaced by `*`.
The same JSON is logged in the `request_context` field. Missing optional values
are JSON `null`.

The event never includes complete Authorization credentials, API-key values,
or cookie content. It also omits raw forwarding fields, the complete query
string, and the body.
Rejections contain only the field name and return a generic HTTP 400 response.

## One-step in-process demo

```sh
cargo test --example axum-demo --features axum \
  one_step_axum_request_demo_returns_complete_safe_json -- --nocapture
```

The test injects a synthetic `ConnectInfo` extension, sends one request through
the real Router, and prints the complete JSON response. It also proves that raw
forwarding, query, body, Authorization, cookie, and API-key values are absent;
only the documented masked forms remain.

RFC 7239 defines `Forwarded` and its security limitations; see
[Section 4](https://www.rfc-editor.org/rfc/rfc7239.html#section-4) and
[Section 8](https://www.rfc-editor.org/rfc/rfc7239.html#section-8).
`X-Forwarded-For`, `X-Real-IP`, and provider-specific fields are de facto or
vendor conventions rather than IETF standards.
