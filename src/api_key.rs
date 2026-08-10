//! API-key extraction from the fixed `X-API-Key` and `Api-Key` fields.
//!
//! `X-API-Key` takes precedence; `Api-Key` is consulted only when it is absent.
//! The selected value is returned unchanged, including an empty value. This
//! module selects a text field but does not validate or authenticate it. API keys
//! are sensitive: callers must not log or otherwise disclose returned values,
//! and extraction errors never include them.

use http::{HeaderMap, HeaderName, Request};

use crate::{Error, header::extract_single_header_text};

const X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");
const API_KEY: HeaderName = HeaderName::from_static("api-key");

/// Extract an API key from request fields.
///
/// `X-API-Key` takes precedence over `Api-Key`; the fallback is inspected only
/// when `X-API-Key` is absent. If both are absent, this function returns `None`.
/// The selected value is returned unchanged, so an empty field produces
/// `Some("")`. A selected field that occurs more than once or is not text
/// produces an error that does not contain its sensitive value. This function
/// does not validate or authenticate the key, and callers must not log or echo
/// it.
pub fn extract_header_api_key(headers: &HeaderMap) -> Result<Option<&str>, Error> {
    for name in [&X_API_KEY, &API_KEY] {
        if let Some(value) = extract_single_header_text(headers, name)? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

/// Extract an API key from a complete request.
///
/// This reads `request.headers()` and delegates to
/// [`extract_header_api_key`]. It therefore uses the same fixed precedence,
/// missing and error behavior, preserves empty selected values, and performs no
/// validation or authentication. The returned value is sensitive and must not
/// be logged or echoed.
pub fn extract_request_api_key<B>(request: &Request<B>) -> Result<Option<&str>, Error> {
    extract_header_api_key(request.headers())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_x_api_key_before_api_key_fallback() {
        let mut headers = HeaderMap::new();
        assert_eq!(extract_header_api_key(&headers).unwrap(), None);

        headers.insert("api-key", "fallback".parse().unwrap());
        assert_eq!(extract_header_api_key(&headers).unwrap(), Some("fallback"));

        headers.insert("x-api-key", "preferred".parse().unwrap());
        assert_eq!(extract_header_api_key(&headers).unwrap(), Some("preferred"));
    }

    #[test]
    fn preserves_empty_selected_values_without_falling_back() {
        let mut headers = HeaderMap::new();
        headers.insert("api-key", "fallback".parse().unwrap());
        headers.insert("x-api-key", "".parse().unwrap());
        assert_eq!(extract_header_api_key(&headers).unwrap(), Some(""));

        headers.remove("x-api-key");
        headers.insert("api-key", "".parse().unwrap());
        assert_eq!(extract_header_api_key(&headers).unwrap(), Some(""));
    }

    #[test]
    fn rejects_duplicate_and_non_text_values_without_echoing_them() {
        let mut duplicate = HeaderMap::new();
        duplicate.append("x-api-key", "first-secret".parse().unwrap());
        duplicate.append("x-api-key", "second-secret".parse().unwrap());
        let error = extract_header_api_key(&duplicate).unwrap_err();
        assert!(matches!(error, Error::DuplicateHeader { .. }));
        assert!(!format!("{error:?}").contains("secret"));

        let mut duplicate_fallback = HeaderMap::new();
        duplicate_fallback.append("api-key", "first-secret".parse().unwrap());
        duplicate_fallback.append("api-key", "second-secret".parse().unwrap());
        assert!(matches!(
            extract_header_api_key(&duplicate_fallback),
            Err(Error::DuplicateHeader { .. })
        ));

        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", http::HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(matches!(
            extract_header_api_key(&headers),
            Err(Error::InvalidHeader { .. })
        ));
    }

    #[test]
    fn request_entry_point_delegates_to_headers() {
        let request = Request::builder()
            .header("api-key", "fallback")
            .body(())
            .unwrap();

        assert_eq!(extract_request_api_key(&request).unwrap(), Some("fallback"));
    }
}
