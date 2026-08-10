# Axum integration example

The repository's `axum-demo` example demonstrates the library at an Axum request
boundary while keeping the core framework-independent. Axum supplies the TCP
peer through `ConnectInfo<SocketAddr>`;
`extract_axum_socket_address` and `extract_axum_socket_ip` read that
request extension, while Header-derived client IP values remain separate raw
assertions.

Run the listener:

```sh
LISTEN_ADDR=127.0.0.1:3000 cargo run --example axum-demo --features axum
```

Or run the one-step in-process request demonstration:

```sh
cargo test --example axum-demo --features axum \
  one_step_axum_request_demo_returns_complete_safe_json -- --nocapture
```

The handler passes `request.headers()` to `extract_client_ip`. That convenience
uses the library's default Header order and returns a raw, untrusted assertion;
it does not authenticate a proxy. A successful request returns and logs one
JSON object containing the peer address/IP, selected Header IP/source,
authority, request ID, Content-Type, and masked Authorization, API-key, and
cookie values. Sensitive strings retain only their first and last two
characters (`aa***bb`); values of four characters or fewer are fully masked.
Missing optional values are JSON `null`.

The event never includes complete Authorization credentials, API-key values,
or cookie content. It also omits raw forwarding fields, the complete query
string, and body. Malformed selected metadata produces a generic HTTP 400
response.

Review the [client IP trust boundary](trusted-proxies.md) and
[Standards and compatibility](standards.md) before using a Header-derived IP
for a security decision. Complete commands and the output contract are in the
example README at `examples/axum/README.md`.
