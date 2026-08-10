//! `Content-Type` extraction.
//!
//! This module parses the representation media type described by
//! [RFC 9110, Section 8.3]. It does not inspect a message body or infer a media
//! type when the field is absent.
//!
//! [RFC 9110, Section 8.3]: https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3

use http::{HeaderMap, Request, header::CONTENT_TYPE};

use crate::{Error, header::extract_single_header_text};

/// Extract and parse a singular `Content-Type` field as a media type.
///
/// A missing field returns `None`. Duplicate field lines, non-text values, and
/// invalid or empty media types return an error. The result is parsed as
/// [`mime::Mime`]; this function does not inspect the body, sniff content, or
/// determine whether the declared type is truthful.
pub fn extract_header_content_type(headers: &HeaderMap) -> Result<Option<mime::Mime>, Error> {
    extract_single_header_text(headers, &CONTENT_TYPE)?
        .map(|value| {
            value
                .parse()
                .map_err(|_| Error::invalid_header(CONTENT_TYPE))
        })
        .transpose()
}

/// Extract and parse `Content-Type` from a complete request.
///
/// This reads `request.headers()` and delegates to
/// [`extract_header_content_type`], preserving its missing, duplicate,
/// encoding, and media-type validation behavior.
pub fn extract_request_content_type<B>(request: &Request<B>) -> Result<Option<mime::Mime>, Error> {
    extract_header_content_type(request.headers())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_a_singular_media_type() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            "application/json; charset=utf-8".parse().unwrap(),
        );

        let value = extract_header_content_type(&headers).unwrap().unwrap();
        assert_eq!(value.type_(), "application");
        assert_eq!(value.subtype(), "json");
    }

    #[test]
    fn rejects_duplicate_content_type() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_TYPE, "application/json".parse().unwrap());
        headers.append(CONTENT_TYPE, "text/plain".parse().unwrap());

        assert!(matches!(
            extract_header_content_type(&headers),
            Err(Error::DuplicateHeader { .. })
        ));
    }

    #[test]
    fn request_entry_point_delegates_to_headers() {
        let request = Request::builder()
            .header(CONTENT_TYPE, "application/json")
            .body(())
            .unwrap();
        assert_eq!(
            extract_request_content_type(&request).unwrap(),
            Some(mime::APPLICATION_JSON)
        );
    }
}
