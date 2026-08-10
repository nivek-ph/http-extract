# Feature and API map

Every extraction feature owns one field family. Header functions are the single
parsing implementation; Request functions delegate. All public APIs are exposed
from the crate root, so applications import
`http_extract::extract_request_x_forwarded_proto` directly.

| Feature/API family | Main Header API | Request convenience | Result |
| --- | --- | --- | --- |
| `api_key` | `extract_header_api_key` | `extract_request_api_key` | `Option<&str>` |
| `authority` | `extract_header_authority` | `extract_request_authority` | `Option<Authority>` |
| `authorization` | `extract_header_authorization` plus Bearer/Basic helpers | matching `extract_request_*` functions | `Option<&str>` |
| `content_type` | `extract_header_content_type` | `extract_request_content_type` | `Option<Mime>` |
| `request_id` | `extract_header_request_id` | `extract_request_request_id` | `Option<&str>` |
| `forwarded` | `extract_header_forwarded_for` | `extract_request_forwarded_for` | `Option<Vec<IpAddr>>` |
| `x_forwarded` | `extract_header_x_forwarded_for`, `extract_header_x_forwarded_proto` | matching Request functions | IP or scheme vectors |
| `client_ip_headers` | one `extract_header_*` function per common provider/proxy field | matching Request functions | `Option<IpAddr>` |

`extract_request_socket_address` and
`extract_request_socket_ip` read a `SocketAddr` stored directly in request
extensions. `extract_socket_ip` prefers Axum `ConnectInfo<SocketAddr>` when the
`axum` feature is enabled, then falls back to the direct extension.
`extract_client_ip` uses the library's documented
default Header order; `extract_client_ip_with_headers` accepts an explicit
ordered slice of `ClientIpHeader` values. Both Header selectors return raw,
untrusted assertions. `extract_proxy_client_ip` applies the default Header
order and uses `extract_socket_ip` only when every supported Header is absent.

With the non-default `axum` feature,
`extract_axum_socket_address(&Request<B>)` and
`extract_axum_socket_ip(&Request<B>)` read only the `ConnectInfo<SocketAddr>`
request extension and return `None` when it is absent. They do not inspect
forwarding Headers.

`header` contains the strict singular-field helpers and
`append_header_value`, which appends without replacing existing field lines.

The exact RFC versions, supported sections, and non-standard field boundary are
collected in [Standards and compatibility](standards.md).
