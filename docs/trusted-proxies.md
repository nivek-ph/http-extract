# Client IP trust boundary

The transport peer is the only network fact available independently of HTTP
Headers. `Forwarded`, `X-Forwarded-For`, and provider-specific client IP fields
are caller-controlled assertions until a deployment establishes trust.

`extract_client_ip(headers)` checks these fields in order:

1. RFC 7239 `Forwarded`;
2. `X-Forwarded-For`;
3. `X-Real-IP`;
4. `CF-Connecting-IP`.

This standard-first precedence is a library convention, not an order or trust
policy defined by an RFC. Only an absent source falls through. A malformed
first-present source returns an error instead of consulting a lower-priority
field. `Forwarded` and
`X-Forwarded-For` contribute the rightmost address, representing the assertion
nearest the server.

Use `extract_client_ip_with_headers(headers, order)` with an ordered
`ClientIpHeader` slice to choose different sources or precedence. The selector
also supports the other single-value fields documented in
[Common client IP fields](client-ip-headers.md).
Configuration strings can be parsed into `ClientIpHeader` values with
`FromStr`; unsupported names fail before request extraction.

Neither selector receives the transport peer or trusted CIDRs. The returned IP
is therefore raw and untrusted. Before using it for authorization, rate
limiting, or audit decisions, restrict the application listener to controlled
proxies and ensure that the selected field is overwritten according to the
deployment's policy. Use the server adapter's peer directly, or
`extract_request_socket_ip` when it stores a `SocketAddr` request extension,
when the actual socket peer is the desired fact.

`extract_header_forwarded_for` remains deliberately strict: the field must be
singular and every element must contain a usable IP `for=` value. Missing,
unknown, obfuscated, and non-IP nodes fail rather than being skipped. See
[RFC 7239 Section 5.2](https://www.rfc-editor.org/rfc/rfc7239.html#section-5.2)
and its
[Section 8 security considerations](https://www.rfc-editor.org/rfc/rfc7239.html#section-8).

`X-Forwarded-For`, `X-Real-IP`, and the provider-specific fields are de facto
or vendor conventions, not IETF standards.
