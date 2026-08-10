//! Request ID extraction with fixed common field precedence.
//!
//! `X-Request-Id` is preferred and `Request-Id` is used only as a fallback.
//! These are configured field names used by this crate, not universal
//! IETF-standard request ID fields. This module does not generate or validate
//! identifiers.

use http::{HeaderMap, HeaderName, Request};

use crate::{Error, header::extract_single_header_text};

/// The preferred `X-Request-Id` field name.
pub const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// The fallback `Request-Id` field name.
pub const REQUEST_ID: HeaderName = HeaderName::from_static("request-id");

/// Extract a request ID from request fields.
///
/// `X-Request-Id` takes precedence over `Request-Id`; the fallback is inspected
/// only when `X-Request-Id` is absent. If both are absent, this function returns
/// `None`. The selected value is returned unchanged, so an empty field produces
/// `Some("")`. A selected field that occurs more than once or is not text
/// produces an error that does not contain the field value. This function does
/// not generate, validate, authenticate, or log an identifier.
pub fn extract_header_request_id(headers: &HeaderMap) -> Result<Option<&str>, Error> {
    if let Some(value) = extract_single_header_text(headers, &X_REQUEST_ID)? {
        return Ok(Some(value));
    }
    if let Some(value) = extract_single_header_text(headers, &REQUEST_ID)? {
        return Ok(Some(value));
    }
    Ok(None)
}

/// Extract a request ID from a complete request.
///
/// This reads `request.headers()` and delegates to
/// [`extract_header_request_id`]. It therefore uses the same fixed precedence,
/// missing and error behavior, preserves empty selected values, and performs no
/// generation or validation.
pub fn extract_request_request_id<B>(request: &Request<B>) -> Result<Option<&str>, Error> {
    extract_header_request_id(request.headers())
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, Request};

    use super::*;

    #[test]
    fn missing_fallback_and_preferred_values_are_distinguished() {
        let mut headers = HeaderMap::new();
        assert_eq!(extract_header_request_id(&headers), Ok(None));

        headers.insert("request-id", "fallback".parse().unwrap());
        assert_eq!(extract_header_request_id(&headers), Ok(Some("fallback")));

        headers.insert("x-request-id", "preferred".parse().unwrap());
        assert_eq!(extract_header_request_id(&headers), Ok(Some("preferred")));
    }

    #[test]
    fn preserves_empty_x_request_id_value_without_falling_back() {
        let mut headers = HeaderMap::new();
        headers.insert("request-id", "fallback".parse().unwrap());
        headers.insert("x-request-id", "".parse().unwrap());
        assert_eq!(extract_header_request_id(&headers), Ok(Some("")));
    }

    #[test]
    fn rejects_duplicate_and_non_text_selected_fields_without_echoing_values() {
        let mut headers = HeaderMap::new();
        headers.append("x-request-id", "first-secret".parse().unwrap());
        headers.append("x-request-id", "second-secret".parse().unwrap());
        let error = extract_header_request_id(&headers).unwrap_err();
        assert!(matches!(error, Error::DuplicateHeader { .. }));
        assert!(!error.to_string().contains("secret"));

        headers.clear();
        headers.insert("x-request-id", HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(matches!(
            extract_header_request_id(&headers),
            Err(Error::InvalidHeader { .. })
        ));
    }

    #[test]
    fn request_entry_point_delegates_to_headers() {
        let request = Request::builder()
            .header("request-id", "fallback")
            .body(())
            .unwrap();
        assert_eq!(extract_request_request_id(&request), Ok(Some("fallback")));
    }
}
