//! Raw extraction of the sensitive `Authorization` field.
//!
//! In addition to raw field extraction, this module can route the common Bearer
//! and Basic schemes to borrowed credential strings. It does not validate
//! tokens, decode Basic credentials, fully validate the Authorization grammar,
//! or authenticate requests. Returned values are sensitive and must not be
//! logged or echoed; extraction errors never contain them.
//!
//! Standards context: the HTTP authentication framework is defined by
//! [RFC 9110 Section 11](https://www.rfc-editor.org/rfc/rfc9110.html#section-11),
//! Bearer usage by
//! [RFC 6750 Section 2.1](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1),
//! and Basic by
//! [RFC 7617 Section 2](https://www.rfc-editor.org/rfc/rfc7617.html#section-2).
//! The helpers here only recognize a scheme and return its raw credential
//! string; they do not implement authentication, complete RFC syntax
//! validation, or Basic decoding.

use http::{HeaderMap, Request, header::AUTHORIZATION};

use crate::{Error, header::extract_single_header_text};

/// The Bearer scheme.
pub const BEARER_SCHEME: &str = "Bearer";

/// The Basic scheme.
pub const BASIC_SCHEME: &str = "Basic";

/// The space character that separates the scheme from the credentials.
pub const SCHEME_SEPARATOR: char = ' ';

/// Extract the singular `Authorization` field as text.
///
/// A missing field returns `None`. The value is returned unchanged, including
/// an empty value. Duplicate field lines or a non-text value return an error
/// that does not contain the sensitive value. This function does not parse,
/// validate, decode, or authenticate the field, and callers must not log or
/// echo it. See the HTTP authentication framework in
/// [RFC 9110, Section 11].
///
/// [RFC 9110, Section 11]: https://www.rfc-editor.org/rfc/rfc9110.html#section-11
pub fn extract_header_authorization(headers: &HeaderMap) -> Result<Option<&str>, Error> {
    extract_single_header_text(headers, &AUTHORIZATION)
}

/// Extract the raw `Authorization` field from a complete request.
///
/// This reads `request.headers()` and delegates to
/// [`extract_header_authorization`], preserving its missing, empty, duplicate,
/// and non-text behavior. The returned value is sensitive and must not be
/// logged or echoed; no validation, decoding, or authentication is performed.
pub fn extract_request_authorization<B>(request: &Request<B>) -> Result<Option<&str>, Error> {
    extract_header_authorization(request.headers())
}

/// Extract raw Bearer credentials from the `Authorization` field.
///
/// Scheme matching is ASCII case-insensitive and requires at least one ASCII
/// space. Only the first required space is consumed; any additional spaces are
/// preserved in the returned credentials. `Bearer ` therefore produces
/// `Some("")`. A missing field, another scheme, or a scheme without the
/// required space returns `None`. Duplicate or non-text `Authorization` fields
/// return an error before scheme matching. This function does not validate the
/// token syntax or authenticate it, and the returned credential is sensitive.
/// See Bearer usage in [RFC 6750, Section 2.1].
///
/// [RFC 6750, Section 2.1]: https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1
pub fn extract_header_bearer_token(headers: &HeaderMap) -> Result<Option<&str>, Error> {
    Ok(extract_header_authorization(headers)?
        .and_then(|value| extract_scheme_credentials(value, BEARER_SCHEME)))
}

/// Extract raw Bearer credentials from a complete request.
///
/// This reads `request.headers()` and delegates to
/// [`extract_header_bearer_token`], preserving its missing, scheme-mismatch,
/// empty-credential, and field-error behavior. No token validation or
/// authentication is performed.
pub fn extract_request_bearer_token<B>(request: &Request<B>) -> Result<Option<&str>, Error> {
    extract_header_bearer_token(request.headers())
}

/// Extract raw Basic credentials from the `Authorization` field.
///
/// Scheme matching is ASCII case-insensitive and requires at least one ASCII
/// space. Only the first required space is consumed; any additional spaces are
/// preserved in the returned credentials. `Basic ` therefore produces
/// `Some("")`. A missing field, another scheme, or a scheme without the
/// required space returns `None`. Duplicate or non-text `Authorization` fields
/// return an error before scheme matching. This function does not validate or
/// Base64-decode the credential, split a user name and password, or authenticate
/// it. The returned credential is sensitive. See [RFC 7617, Section 2].
///
/// [RFC 7617, Section 2]: https://www.rfc-editor.org/rfc/rfc7617.html#section-2
pub fn extract_header_basic_credentials(headers: &HeaderMap) -> Result<Option<&str>, Error> {
    Ok(extract_header_authorization(headers)?
        .and_then(|value| extract_scheme_credentials(value, BASIC_SCHEME)))
}

/// Extract raw Basic credentials from a complete request.
///
/// This reads `request.headers()` and delegates to
/// [`extract_header_basic_credentials`], preserving its missing,
/// scheme-mismatch, empty-credential, and field-error behavior. No validation,
/// decoding, or authentication is performed.
pub fn extract_request_basic_credentials<B>(request: &Request<B>) -> Result<Option<&str>, Error> {
    extract_header_basic_credentials(request.headers())
}

fn extract_scheme_credentials<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
    let candidate = value.get(..scheme.len())?;
    if !candidate.eq_ignore_ascii_case(scheme) {
        return None;
    }

    value.get(scheme.len()..)?.strip_prefix(SCHEME_SEPARATOR)
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, Request, header::AUTHORIZATION};

    use super::*;

    #[test]
    fn extracts_raw_and_empty_authorization_values() {
        let mut headers = HeaderMap::new();
        assert_eq!(extract_header_authorization(&headers).unwrap(), None);

        headers.insert(AUTHORIZATION, "Bearer opaque-secret".parse().unwrap());
        assert_eq!(
            extract_header_authorization(&headers).unwrap(),
            Some("Bearer opaque-secret")
        );

        headers.insert(AUTHORIZATION, "".parse().unwrap());
        assert_eq!(extract_header_authorization(&headers).unwrap(), Some(""));
    }

    #[test]
    fn rejects_duplicate_and_non_text_values_without_echoing_them() {
        let mut duplicate = HeaderMap::new();
        duplicate.append(AUTHORIZATION, "Bearer first-secret".parse().unwrap());
        duplicate.append(AUTHORIZATION, "Basic second-secret".parse().unwrap());
        let error = extract_header_authorization(&duplicate).unwrap_err();
        assert!(matches!(error, Error::DuplicateHeader { .. }));
        assert!(!format!("{error:?}").contains("secret"));

        let mut non_text = HeaderMap::new();
        non_text.insert(AUTHORIZATION, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(matches!(
            extract_header_authorization(&non_text),
            Err(Error::InvalidHeader { .. })
        ));
    }

    #[test]
    fn routes_bearer_without_validating_or_normalizing_credentials() {
        assert_eq!(extract_scheme_credentials("Bearer🦀", BEARER_SCHEME), None);
        let mut headers = HeaderMap::new();
        assert_eq!(extract_header_bearer_token(&headers).unwrap(), None);

        headers.insert(AUTHORIZATION, "Basic encoded".parse().unwrap());
        assert_eq!(extract_header_bearer_token(&headers).unwrap(), None);

        headers.insert(AUTHORIZATION, "bEaReR opaque==".parse().unwrap());
        assert_eq!(
            extract_header_bearer_token(&headers).unwrap(),
            Some("opaque==")
        );

        headers.insert(AUTHORIZATION, "Bearer  keep-space".parse().unwrap());
        assert_eq!(
            extract_header_bearer_token(&headers).unwrap(),
            Some(" keep-space")
        );

        headers.insert(AUTHORIZATION, "Bearer ".parse().unwrap());
        assert_eq!(extract_header_bearer_token(&headers).unwrap(), Some(""));

        headers.insert(AUTHORIZATION, "Bearer".parse().unwrap());
        assert_eq!(extract_header_bearer_token(&headers).unwrap(), None);

        assert_eq!(
            extract_scheme_credentials("Béarer token", BEARER_SCHEME),
            None
        );
        assert_eq!(extract_scheme_credentials("🦀", BEARER_SCHEME), None);
    }

    #[test]
    fn routes_basic_without_decoding_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer token".parse().unwrap());
        assert_eq!(extract_header_basic_credentials(&headers).unwrap(), None);

        headers.insert(AUTHORIZATION, "bAsIc plain-credentials".parse().unwrap());
        assert_eq!(
            extract_header_basic_credentials(&headers).unwrap(),
            Some("plain-credentials")
        );

        headers.insert(AUTHORIZATION, "Basic ".parse().unwrap());
        assert_eq!(
            extract_header_basic_credentials(&headers).unwrap(),
            Some("")
        );

        headers.insert(AUTHORIZATION, "Basic  keep-space".parse().unwrap());
        assert_eq!(
            extract_header_basic_credentials(&headers).unwrap(),
            Some(" keep-space")
        );

        headers.insert(AUTHORIZATION, "Basic".parse().unwrap());
        assert_eq!(extract_header_basic_credentials(&headers).unwrap(), None);
    }

    #[test]
    fn requires_a_space_between_scheme_and_credentials() {
        let mut headers = HeaderMap::new();

        headers.insert(AUTHORIZATION, "BearerAA".parse().unwrap());
        assert_eq!(extract_header_bearer_token(&headers).unwrap(), None);

        headers.insert(AUTHORIZATION, "Bearer AA".parse().unwrap());
        assert_eq!(extract_header_bearer_token(&headers).unwrap(), Some("AA"));

        headers.insert(AUTHORIZATION, "BasicAA".parse().unwrap());
        assert_eq!(extract_header_basic_credentials(&headers).unwrap(), None);

        headers.insert(AUTHORIZATION, "Basic AA".parse().unwrap());
        assert_eq!(
            extract_header_basic_credentials(&headers).unwrap(),
            Some("AA")
        );
    }

    #[test]
    fn request_entry_points_delegate_to_headers() {
        let request = Request::builder()
            .header(AUTHORIZATION, "Bearer unparsed credentials")
            .body(())
            .unwrap();

        assert_eq!(
            extract_request_authorization(&request).unwrap(),
            Some("Bearer unparsed credentials")
        );
        assert_eq!(
            extract_request_bearer_token(&request).unwrap(),
            Some("unparsed credentials")
        );
        assert_eq!(extract_request_basic_credentials(&request).unwrap(), None);

        let basic = Request::builder()
            .header(AUTHORIZATION, "Basic encoded")
            .body(())
            .unwrap();
        assert_eq!(
            extract_request_basic_credentials(&basic).unwrap(),
            Some("encoded")
        );
    }
}
