//! Direct extraction of common single-value client IP fields.
//!
//! Each function parses exactly one provider or proxy field and returns its raw
//! asserted [`IpAddr`]. `CF-Connecting-IP`, `CloudFront-Viewer-Address`,
//! `Fly-Client-IP`, `True-Client-IP`, `X-Envoy-External-Address`, and
//! `X-Real-IP` are vendor or de facto conventions, not IETF standards.
//!
//! These values are untrusted: this module does not authenticate a proxy or
//! apply a trust policy. The feature-gated [`crate::extract_client_ip`]
//! convenience includes selected fields, but its output remains untrusted.
//! Applications must decide whether a specific field is trustworthy for their
//! deployment. Every extractor treats
//! the field as singular: absence returns `None`, while duplicate, non-text,
//! empty, or malformed values return a value-redacting error.

use std::net::{IpAddr, SocketAddr};

use http::{HeaderMap, HeaderName, Request};

use crate::{Error, header::extract_single_header_text};

/// The `CF-Connecting-IP` field name.
pub const CF_CONNECTING_IP: HeaderName = HeaderName::from_static("cf-connecting-ip");

/// The `CloudFront-Viewer-Address` field name.
pub const CLOUDFRONT_VIEWER_ADDRESS: HeaderName =
    HeaderName::from_static("cloudfront-viewer-address");

/// The `Fly-Client-IP` field name.
pub const FLY_CLIENT_IP: HeaderName = HeaderName::from_static("fly-client-ip");

/// The `True-Client-IP` field name.
pub const TRUE_CLIENT_IP: HeaderName = HeaderName::from_static("true-client-ip");

/// The `X-Envoy-External-Address` field name.
pub const X_ENVOY_EXTERNAL_ADDRESS: HeaderName =
    HeaderName::from_static("x-envoy-external-address");

/// The `X-Real-IP` field name.
pub const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");

/// Extract the raw, untrusted IP asserted by `CF-Connecting-IP`.
///
/// This reads only the [`HeaderMap`]. A missing field returns `None`; duplicate,
/// non-text, empty, or non-IP values return an error without including the
/// value. Surrounding whitespace is ignored. This vendor field is not an IETF
/// standard, and the function does not authenticate Cloudflare or the sender.
pub fn extract_header_cf_connecting_ip(headers: &HeaderMap) -> Result<Option<IpAddr>, Error> {
    extract_single_ip(headers, &CF_CONNECTING_IP)
}

/// Extract `CF-Connecting-IP` from a complete request.
///
/// This reads `request.headers()` and delegates to
/// [`extract_header_cf_connecting_ip`], preserving its missing and strict error
/// behavior. The returned assertion remains raw and untrusted.
pub fn extract_request_cf_connecting_ip<B>(request: &Request<B>) -> Result<Option<IpAddr>, Error> {
    extract_header_cf_connecting_ip(request.headers())
}

/// Extract an untrusted client IP from AWS CloudFront's
/// `CloudFront-Viewer-Address` `IP:port` value.
///
/// Both IPv4 and CloudFront's unbracketed IPv6-with-port form are supported;
/// bracketed IPv6 socket-address syntax is accepted as well. A missing field
/// returns `None`; duplicate, non-text, empty, missing-port, invalid-port, or
/// invalid-IP values return an error without including the value. Surrounding
/// whitespace is ignored. This vendor field is not an IETF standard, and the
/// result remains raw and untrusted; no sender authentication is performed.
pub fn extract_header_cloudfront_viewer_address(
    headers: &HeaderMap,
) -> Result<Option<IpAddr>, Error> {
    extract_single_header_text(headers, &CLOUDFRONT_VIEWER_ADDRESS)?
        .map(parse_cloudfront_viewer_address)
        .transpose()
}

/// Extract `CloudFront-Viewer-Address` from a complete request.
///
/// This reads `request.headers()` and delegates to
/// [`extract_header_cloudfront_viewer_address`], preserving its missing and
/// strict `IP:port` error behavior. The returned assertion remains raw and
/// untrusted.
pub fn extract_request_cloudfront_viewer_address<B>(
    request: &Request<B>,
) -> Result<Option<IpAddr>, Error> {
    extract_header_cloudfront_viewer_address(request.headers())
}

/// Extract the raw, untrusted IP asserted by `Fly-Client-IP`.
///
/// This reads only the [`HeaderMap`]. A missing field returns `None`; duplicate,
/// non-text, empty, or non-IP values return an error without including the
/// value. Surrounding whitespace is ignored. This vendor field is not an IETF
/// standard, and the function does not authenticate Fly.io or the sender.
pub fn extract_header_fly_client_ip(headers: &HeaderMap) -> Result<Option<IpAddr>, Error> {
    extract_single_ip(headers, &FLY_CLIENT_IP)
}

/// Extract `Fly-Client-IP` from a complete request.
///
/// This reads `request.headers()` and delegates to
/// [`extract_header_fly_client_ip`], preserving its missing and strict error
/// behavior. The returned assertion remains raw and untrusted.
pub fn extract_request_fly_client_ip<B>(request: &Request<B>) -> Result<Option<IpAddr>, Error> {
    extract_header_fly_client_ip(request.headers())
}

/// Extract an untrusted client IP asserted by `True-Client-IP`.
///
/// This reads only the [`HeaderMap`]. A missing field returns `None`; duplicate,
/// non-text, empty, or non-IP values return an error without including the
/// value. Surrounding whitespace is ignored. This de facto, non-IETF field is
/// commonly emitted by configured CDN or proxy products; its presence alone
/// does not authenticate the sender or establish trust.
pub fn extract_header_true_client_ip(headers: &HeaderMap) -> Result<Option<IpAddr>, Error> {
    extract_single_ip(headers, &TRUE_CLIENT_IP)
}

/// Extract `True-Client-IP` from a complete request.
///
/// This reads `request.headers()` and delegates to
/// [`extract_header_true_client_ip`], preserving its missing and strict error
/// behavior. The returned assertion remains raw and untrusted.
pub fn extract_request_true_client_ip<B>(request: &Request<B>) -> Result<Option<IpAddr>, Error> {
    extract_header_true_client_ip(request.headers())
}

/// Extract an untrusted client IP asserted by Envoy's
/// `X-Envoy-External-Address`.
///
/// This reads only the [`HeaderMap`]. A missing field returns `None`; duplicate,
/// non-text, empty, or non-IP values return an error without including the
/// value. Surrounding whitespace is ignored. This de facto, non-IETF field does
/// not authenticate Envoy or the sender, so its result remains raw and
/// untrusted.
pub fn extract_header_x_envoy_external_address(
    headers: &HeaderMap,
) -> Result<Option<IpAddr>, Error> {
    extract_single_ip(headers, &X_ENVOY_EXTERNAL_ADDRESS)
}

/// Extract `X-Envoy-External-Address` from a complete request.
///
/// This reads `request.headers()` and delegates to
/// [`extract_header_x_envoy_external_address`], preserving its missing and
/// strict error behavior. The returned assertion remains raw and untrusted.
pub fn extract_request_x_envoy_external_address<B>(
    request: &Request<B>,
) -> Result<Option<IpAddr>, Error> {
    extract_header_x_envoy_external_address(request.headers())
}

/// Extract the raw, untrusted IP asserted by `X-Real-IP`.
///
/// This reads only the [`HeaderMap`]. A missing field returns `None`; duplicate,
/// non-text, empty, or non-IP values return an error without including the
/// value. Surrounding whitespace is ignored. This de facto field is not an
/// IETF standard and does not authenticate the sender.
pub fn extract_header_x_real_ip(headers: &HeaderMap) -> Result<Option<IpAddr>, Error> {
    extract_single_ip(headers, &X_REAL_IP)
}

/// Extract `X-Real-IP` from a complete request.
///
/// This reads `request.headers()` and delegates to
/// [`extract_header_x_real_ip`], preserving its missing and strict error
/// behavior. The returned assertion remains raw and untrusted.
pub fn extract_request_x_real_ip<B>(request: &Request<B>) -> Result<Option<IpAddr>, Error> {
    extract_header_x_real_ip(request.headers())
}

fn extract_single_ip(headers: &HeaderMap, name: &HeaderName) -> Result<Option<IpAddr>, Error> {
    extract_single_header_text(headers, name)?
        .map(|value| parse_ip(value, name))
        .transpose()
}

fn parse_ip(value: &str, name: &HeaderName) -> Result<IpAddr, Error> {
    value
        .trim()
        .parse()
        .map_err(|_| Error::invalid_header(name.clone()))
}

fn parse_cloudfront_viewer_address(value: &str) -> Result<IpAddr, Error> {
    let value = value.trim();
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(address.ip());
    }

    let (address, port) = value
        .rsplit_once(':')
        .ok_or_else(|| Error::invalid_header(CLOUDFRONT_VIEWER_ADDRESS))?;
    port.parse::<u16>()
        .map_err(|_| Error::invalid_header(CLOUDFRONT_VIEWER_ADDRESS))?;
    address
        .parse()
        .map_err(|_| Error::invalid_header(CLOUDFRONT_VIEWER_ADDRESS))
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue};

    use super::*;

    type Extractor = fn(&HeaderMap) -> Result<Option<IpAddr>, Error>;

    fn ordinary_extractors() -> [(HeaderName, Extractor); 5] {
        [
            (CF_CONNECTING_IP, extract_header_cf_connecting_ip),
            (FLY_CLIENT_IP, extract_header_fly_client_ip),
            (TRUE_CLIENT_IP, extract_header_true_client_ip),
            (
                X_ENVOY_EXTERNAL_ADDRESS,
                extract_header_x_envoy_external_address,
            ),
            (X_REAL_IP, extract_header_x_real_ip),
        ]
    }

    #[test]
    fn single_ip_fields_handle_missing_valid_and_invalid_values() {
        for (name, extract) in ordinary_extractors() {
            let mut headers = HeaderMap::new();
            assert_eq!(extract(&headers).unwrap(), None);

            headers.insert(&name, " 2001:db8::1 ".parse().unwrap());
            assert_eq!(
                extract(&headers).unwrap(),
                Some("2001:db8::1".parse().unwrap())
            );

            headers.insert(&name, "not-an-ip".parse().unwrap());
            let error = extract(&headers).unwrap_err();
            assert!(matches!(error, Error::InvalidHeader { .. }));
            assert!(!error.to_string().contains("not-an-ip"));
        }
    }

    #[test]
    fn every_single_ip_field_rejects_duplicates() {
        for (name, extract) in ordinary_extractors() {
            let mut headers = HeaderMap::new();
            headers.append(&name, "192.0.2.1".parse().unwrap());
            headers.append(&name, "198.51.100.2".parse().unwrap());
            assert!(matches!(
                extract(&headers),
                Err(Error::DuplicateHeader { .. })
            ));
        }
    }

    #[test]
    fn cloudfront_viewer_address_handles_ipv4_and_ipv6_with_ports() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            extract_header_cloudfront_viewer_address(&headers).unwrap(),
            None
        );

        for (value, expected) in [
            ("198.51.100.10:46532", "198.51.100.10"),
            ("2001:db8::abcd:1234", "2001:db8::abcd"),
            ("[2001:db8::17]:4711", "2001:db8::17"),
        ] {
            headers.insert(&CLOUDFRONT_VIEWER_ADDRESS, value.parse().unwrap());
            assert_eq!(
                extract_header_cloudfront_viewer_address(&headers).unwrap(),
                Some(expected.parse().unwrap())
            );
        }

        for value in ["198.51.100.10", "198.51.100.10:not-a-port", "not-an-ip:80"] {
            headers.insert(&CLOUDFRONT_VIEWER_ADDRESS, value.parse().unwrap());
            let error = extract_header_cloudfront_viewer_address(&headers).unwrap_err();
            assert!(matches!(error, Error::InvalidHeader { .. }));
            assert!(!error.to_string().contains(value));
        }

        headers.clear();
        headers.append(
            &CLOUDFRONT_VIEWER_ADDRESS,
            "198.51.100.10:443".parse().unwrap(),
        );
        headers.append(
            &CLOUDFRONT_VIEWER_ADDRESS,
            "198.51.100.11:443".parse().unwrap(),
        );
        assert!(matches!(
            extract_header_cloudfront_viewer_address(&headers),
            Err(Error::DuplicateHeader { .. })
        ));
    }

    #[test]
    fn all_fields_reject_non_text_without_echoing_values() {
        let mut cases = ordinary_extractors().to_vec();
        cases.push((
            CLOUDFRONT_VIEWER_ADDRESS,
            extract_header_cloudfront_viewer_address,
        ));

        for (name, extract) in cases {
            let mut headers = HeaderMap::new();
            headers.insert(&name, HeaderValue::from_bytes(&[0xff]).unwrap());
            let error = extract(&headers).unwrap_err();
            assert!(matches!(error, Error::InvalidHeader { .. }));
            assert!(!error.to_string().contains("255"));
        }
    }

    #[test]
    fn request_entry_points_delegate_to_header_extractors() {
        let request = Request::builder()
            .header(&CF_CONNECTING_IP, "192.0.2.1")
            .header(&CLOUDFRONT_VIEWER_ADDRESS, "198.51.100.2:443")
            .header(&FLY_CLIENT_IP, "203.0.113.3")
            .header(&TRUE_CLIENT_IP, "192.0.2.4")
            .header(&X_ENVOY_EXTERNAL_ADDRESS, "198.51.100.5")
            .header(&X_REAL_IP, "203.0.113.6")
            .body(())
            .unwrap();

        assert_eq!(
            extract_request_cf_connecting_ip(&request).unwrap(),
            Some("192.0.2.1".parse().unwrap())
        );
        assert_eq!(
            extract_request_cloudfront_viewer_address(&request).unwrap(),
            Some("198.51.100.2".parse().unwrap())
        );
        assert_eq!(
            extract_request_fly_client_ip(&request).unwrap(),
            Some("203.0.113.3".parse().unwrap())
        );
        assert_eq!(
            extract_request_true_client_ip(&request).unwrap(),
            Some("192.0.2.4".parse().unwrap())
        );
        assert_eq!(
            extract_request_x_envoy_external_address(&request).unwrap(),
            Some("198.51.100.5".parse().unwrap())
        );
        assert_eq!(
            extract_request_x_real_ip(&request).unwrap(),
            Some("203.0.113.6".parse().unwrap())
        );
    }
}
