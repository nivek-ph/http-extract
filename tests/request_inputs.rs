#![cfg(all(feature = "authority", feature = "request-id"))]

use http::Request;
use http_extract::{
    authority::{extract_header_authority, extract_request_authority},
    request_id::extract_header_request_id,
};

#[test]
fn independent_extractors_support_request_and_parts() {
    let request = Request::builder()
        .uri("https://example.com/items")
        .header("host", "fallback.example")
        .header("x-request-id", "request-123")
        .body(())
        .unwrap();
    assert_eq!(
        extract_request_authority(&request)
            .unwrap()
            .unwrap()
            .as_str(),
        "example.com"
    );

    let (parts, _) = request.into_parts();
    assert_eq!(
        extract_header_authority(&parts.headers)
            .unwrap()
            .unwrap()
            .as_str(),
        "fallback.example"
    );
    assert_eq!(
        extract_header_request_id(&parts.headers).unwrap(),
        Some("request-123")
    );
}
