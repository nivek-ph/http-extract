# Common client IP fields

The `client-ip-headers` feature provides one direct function per field:

- `extract_header_cf_connecting_ip` / `extract_request_cf_connecting_ip`;
- `extract_header_cloudfront_viewer_address` / matching Request function;
- `extract_header_fly_client_ip` / matching Request function;
- `extract_header_true_client_ip` / matching Request function;
- `extract_header_x_envoy_external_address` / matching Request function;
- `extract_header_x_real_ip` / matching Request function.

All return `Result<Option<IpAddr>, Error>`. Missing fields return `None`.
Fields are singular; duplicates, non-text values, and malformed addresses fail.
`CloudFront-Viewer-Address` accepts IPv4 and IPv6 `IP:port` forms, including
CloudFront's unbracketed IPv6 representation.

These are vendor or de facto field names, not IETF standards. Extraction does
not authenticate the sender or make the value safe for access control,
logging, or rate limiting. The default `extract_client_ip` order includes
`CF-Connecting-IP` and `X-Real-IP`; the other sources can be selected through
`extract_client_ip_with_headers`. Selection does not authenticate the sender,
so applications must apply a deployment-specific trust policy before using a
result. See [Standards and compatibility](standards.md) for the complete field
classification.
