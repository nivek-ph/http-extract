//! Best-effort extraction of raw client IP assertions.
//!
//! [`extract_client_ip`] uses [`CLIENT_IP_HEADERS`], while
//! [`extract_client_ip_with_headers`] lets callers choose the fields and their
//! order explicitly using [`ClientIpHeader`] values.
//! Both functions only inspect HTTP fields. They cannot authenticate the
//! sender, so their results remain raw and untrusted. Applications must
//! establish the relevant proxy or CDN trust boundary before using a result
//! for authorization, abuse prevention, or rate limiting.
//!
//! RFC 7239 standardizes `Forwarded`; `X-Forwarded-For` and the single-value
//! provider/proxy fields are de facto conventions rather than IETF standards.
//! No standard defines precedence between these different field names.
//!
//! [RFC 7239]: https://www.rfc-editor.org/rfc/rfc7239.html

use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use http::{HeaderMap, HeaderName};

use crate::Error;

macro_rules! client_ip_headers {
    (
        $(
            $(#[$docs:meta])*
            ($variant:ident, $name:literal, $extractor:path);
        )+
    ) => {
        /// A supported client IP Header and its parsing rule.
        ///
        /// Choosing a variant does not authenticate the sender or make the
        /// extracted value trustworthy.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum ClientIpHeader {
            $(
                $(#[$docs])*
                $variant,
            )+
        }

        impl FromStr for ClientIpHeader {
            type Err = Error;

            fn from_str(source: &str) -> Result<Self, Self::Err> {
                let name = HeaderName::from_bytes(source.as_bytes())
                    .map_err(|_| Error::unsupported_header_name(source))?;

                match name.as_str() {
                    $(
                        $name => Ok(Self::$variant),
                    )+
                    _ => Err(Error::unsupported_header_name(source)),
                }
            }
        }

        impl ClientIpHeader {
            fn extract(self, headers: &HeaderMap) -> Result<Option<IpAddr>, Error> {
                match self {
                    $(
                        Self::$variant => ($extractor)(headers),
                    )+
                }
            }
        }
    };
}

client_ip_headers! {
    /// `CF-Connecting-IP`.
    (
        CfConnectingIp,
        "cf-connecting-ip",
        crate::client_ip_headers::extract_header_cf_connecting_ip
    );
    /// `X-Real-IP`.
    (XRealIp, "x-real-ip", crate::client_ip_headers::extract_header_x_real_ip);
    /// RFC 7239 `Forwarded`.
    (Forwarded, "forwarded", crate::forwarded::extract_rightmost_forwarded);
    /// `X-Forwarded-For`.
    (
        XForwardedFor,
        "x-forwarded-for",
        crate::x_forwarded::extract_rightmost_x_forwarded_for
    );
    /// `CloudFront-Viewer-Address`.
    (
        CloudFrontViewerAddress,
        "cloudfront-viewer-address",
        crate::client_ip_headers::extract_header_cloudfront_viewer_address
    );
    /// `Fly-Client-IP`.
    (
        FlyClientIp,
        "fly-client-ip",
        crate::client_ip_headers::extract_header_fly_client_ip
    );
    /// `True-Client-IP`.
    (
        TrueClientIp,
        "true-client-ip",
        crate::client_ip_headers::extract_header_true_client_ip
    );
    /// `X-Envoy-External-Address`.
    (
        XEnvoyExternalAddress,
        "x-envoy-external-address",
        crate::client_ip_headers::extract_header_x_envoy_external_address
    );
}

impl TryFrom<&str> for ClientIpHeader {
    type Error = Error;

    fn try_from(source: &str) -> Result<Self, Self::Error> {
        source.parse()
    }
}

/// The default Header lookup order used by [`extract_client_ip`].
///
/// The standardized `Forwarded` field is checked first, followed by the de
/// facto `X-Forwarded-For`, `X-Real-IP`, and `CF-Connecting-IP` fields. The
/// first present source wins. This standard-first order is a library
/// convention, not an RFC-defined precedence or trust policy.
pub const CLIENT_IP_HEADERS: &[ClientIpHeader] = &[
    ClientIpHeader::Forwarded,
    ClientIpHeader::XForwardedFor,
    ClientIpHeader::XRealIp,
    ClientIpHeader::CfConnectingIp,
];

/// Return the IP address of a transport peer supplied out-of-band by an adapter.
///
/// This is a direct conversion from [`SocketAddr`] to [`IpAddr`]. It does not
/// read HTTP fields or apply a proxy policy. The caller is responsible for
/// supplying the actual connection peer rather than a header-derived address.
pub const fn extract_peer_ip(peer: SocketAddr) -> IpAddr {
    extract_peer_address(peer).ip()
}

/// Return a transport peer address supplied out-of-band by an adapter.
///
/// An HTTP request does not inherently contain this network fact, so no
/// request-based convenience function is provided. The value is returned
/// unchanged; this function does not read headers or apply a proxy policy.
pub const fn extract_peer_address(peer: SocketAddr) -> SocketAddr {
    peer
}

/// Extract the Axum transport peer stored in a request extension.
///
/// This reads `axum::extract::ConnectInfo<SocketAddr>` inserted by
/// `Router::into_make_service_with_connect_info` or explicitly by a test. It
/// returns `None` when that extension is absent. The returned address is the
/// socket peer; this function neither parses nor trusts forwarding Headers.
#[cfg(feature = "axum")]
pub fn extract_axum_peer_address<B>(request: &http::Request<B>) -> Option<SocketAddr> {
    request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|info| info.0)
}

/// Extract the Axum socket peer IP stored in a request extension.
///
/// This returns the [`IpAddr`] from the
/// `axum::extract::ConnectInfo<SocketAddr>` request extension, or `None` when
/// that extension is absent. It does not parse `Forwarded`,
/// `X-Forwarded-For`, or vendor Headers, so it is not a Header-derived or
/// effective client IP.
#[cfg(feature = "axum")]
pub fn extract_axum_peer_ip<B>(request: &http::Request<B>) -> Option<IpAddr> {
    extract_axum_peer_address(request).map(|peer| peer.ip())
}

/// Extract a raw client IP assertion using the default field order.
///
/// This delegates to [`extract_client_ip_with_headers`] with
/// [`CLIENT_IP_HEADERS`]. A missing value in every source returns
/// `None`. A malformed, duplicate, or non-text value in the first present
/// source returns an error without consulting lower-priority sources.
///
/// For `Forwarded` and `X-Forwarded-For`, this returns the rightmost address,
/// which is the assertion nearest the server. The result is still untrusted;
/// this function has no transport-peer or trusted-proxy configuration.
pub fn extract_client_ip(headers: &HeaderMap) -> Result<Option<IpAddr>, Error> {
    extract_client_ip_with_headers(headers, CLIENT_IP_HEADERS)
}

/// Extract a raw client IP assertion using caller-defined fields and order.
///
/// Sources are checked from left to right and the first present value wins. An
/// empty order, or no value in any configured source, returns `None`. If a
/// source is present but malformed, duplicate, or non-text, its error is
/// returned immediately instead of falling through to another source.
///
/// `Forwarded` and `X-Forwarded-For` contribute their rightmost address. All
/// results remain raw and untrusted regardless of the chosen order.
pub fn extract_client_ip_with_headers(
    headers: &HeaderMap,
    sources: &[ClientIpHeader],
) -> Result<Option<IpAddr>, Error> {
    for source in sources {
        if let Some(ip) = source.extract(headers)? {
            return Ok(Some(ip));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use http::HeaderMap;

    use crate::{forwarded::FORWARDED, x_forwarded::X_FORWARDED_FOR};

    use super::*;
    #[test]
    fn peer_functions_preserve_the_transport_address() {
        let peer: SocketAddr = "203.0.113.8:443".parse().unwrap();
        assert_eq!(extract_peer_address(peer), peer);
        assert_eq!(
            extract_peer_ip(peer),
            "203.0.113.8".parse::<IpAddr>().unwrap()
        );
    }

    #[cfg(feature = "axum")]
    #[test]
    fn axum_peer_address_reads_connect_info_extension() {
        let peer: SocketAddr = "203.0.113.8:443".parse().unwrap();
        let mut request = http::Request::new(());
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));

        assert_eq!(extract_axum_peer_address(&request), Some(peer));
    }

    #[cfg(feature = "axum")]
    #[test]
    fn axum_peer_address_returns_none_without_connect_info() {
        let request = http::Request::new(());

        assert_eq!(extract_axum_peer_address(&request), None);
    }

    #[cfg(feature = "axum")]
    #[test]
    fn axum_peer_ip_reads_connect_info_extension() {
        let peer: SocketAddr = "203.0.113.8:443".parse().unwrap();
        let mut request = http::Request::new(());
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));

        assert_eq!(extract_axum_peer_ip(&request), Some(peer.ip()));
    }

    #[cfg(feature = "axum")]
    #[test]
    fn axum_peer_ip_returns_none_without_connect_info() {
        let request = http::Request::new(());

        assert_eq!(extract_axum_peer_ip(&request), None);
    }

    #[test]
    fn default_order_is_stable_and_first_present_header_wins() {
        assert_eq!(
            CLIENT_IP_HEADERS,
            &[
                ClientIpHeader::Forwarded,
                ClientIpHeader::XForwardedFor,
                ClientIpHeader::XRealIp,
                ClientIpHeader::CfConnectingIp,
            ]
        );

        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "192.0.2.1".parse().unwrap());
        headers.insert("x-real-ip", "192.0.2.2".parse().unwrap());
        headers.insert(&FORWARDED, "for=192.0.2.3".parse().unwrap());
        headers.insert(&X_FORWARDED_FOR, "192.0.2.4".parse().unwrap());

        assert_eq!(
            extract_client_ip(&headers).unwrap(),
            Some("192.0.2.3".parse().unwrap())
        );
    }

    #[test]
    fn default_order_falls_through_only_when_a_header_is_absent() {
        let mut headers = HeaderMap::new();
        headers.insert(&FORWARDED, "for=192.0.2.3".parse().unwrap());
        headers.insert(&X_FORWARDED_FOR, "192.0.2.4".parse().unwrap());

        assert_eq!(
            extract_client_ip(&headers).unwrap(),
            Some("192.0.2.3".parse().unwrap())
        );

        headers.insert("x-real-ip", "not-an-ip".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers).unwrap(),
            Some("192.0.2.3".parse().unwrap())
        );

        headers.insert(&FORWARDED, "for=unknown".parse().unwrap());
        assert!(matches!(
            extract_client_ip(&headers),
            Err(Error::InvalidHeader { .. })
        ));
    }

    #[test]
    fn chain_headers_return_the_rightmost_address() {
        let mut headers = HeaderMap::new();
        headers.insert(
            &FORWARDED,
            "for=192.0.2.1, for=198.51.100.2".parse().unwrap(),
        );
        assert_eq!(
            extract_client_ip_with_headers(&headers, &[ClientIpHeader::Forwarded]).unwrap(),
            Some("198.51.100.2".parse().unwrap())
        );

        headers.remove(&FORWARDED);
        headers.insert(&X_FORWARDED_FOR, "192.0.2.1, 198.51.100.3".parse().unwrap());
        assert_eq!(
            extract_client_ip_with_headers(&headers, &[ClientIpHeader::XForwardedFor]).unwrap(),
            Some("198.51.100.3".parse().unwrap())
        );
    }

    #[test]
    fn custom_order_changes_precedence() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "192.0.2.1".parse().unwrap());
        headers.insert("x-real-ip", "192.0.2.2".parse().unwrap());
        let custom_headers = [ClientIpHeader::XRealIp, ClientIpHeader::CfConnectingIp];

        assert_eq!(
            extract_client_ip_with_headers(&headers, &custom_headers).unwrap(),
            Some("192.0.2.2".parse().unwrap())
        );
        assert_eq!(extract_client_ip_with_headers(&headers, &[]).unwrap(), None);
    }

    #[test]
    fn custom_order_supports_every_documented_single_value_header() {
        for (source, header) in [
            (ClientIpHeader::CfConnectingIp, "cf-connecting-ip"),
            (ClientIpHeader::XRealIp, "x-real-ip"),
            (ClientIpHeader::FlyClientIp, "fly-client-ip"),
            (ClientIpHeader::TrueClientIp, "true-client-ip"),
            (
                ClientIpHeader::XEnvoyExternalAddress,
                "x-envoy-external-address",
            ),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header, "192.0.2.10".parse().unwrap());

            assert_eq!(
                extract_client_ip_with_headers(&headers, &[source]).unwrap(),
                Some("192.0.2.10".parse().unwrap()),
                "source {header}",
            );
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            "cloudfront-viewer-address",
            "192.0.2.10:443".parse().unwrap(),
        );
        assert_eq!(
            extract_client_ip_with_headers(&headers, &[ClientIpHeader::CloudFrontViewerAddress],)
                .unwrap(),
            Some("192.0.2.10".parse().unwrap())
        );
    }

    #[test]
    fn parses_supported_header_names() {
        for (name, expected) in [
            ("cf-connecting-ip", ClientIpHeader::CfConnectingIp),
            ("X-Real-IP", ClientIpHeader::XRealIp),
            ("forwarded", ClientIpHeader::Forwarded),
            ("x-forwarded-for", ClientIpHeader::XForwardedFor),
            (
                "cloudfront-viewer-address",
                ClientIpHeader::CloudFrontViewerAddress,
            ),
            ("fly-client-ip", ClientIpHeader::FlyClientIp),
            ("true-client-ip", ClientIpHeader::TrueClientIp),
            (
                "x-envoy-external-address",
                ClientIpHeader::XEnvoyExternalAddress,
            ),
        ] {
            assert_eq!(ClientIpHeader::try_from(name).unwrap(), expected);
            assert_eq!(name.parse::<ClientIpHeader>().unwrap(), expected);
        }

        for header in ["forwarded-for", "not a header"] {
            let error = header.parse::<ClientIpHeader>().unwrap_err();
            assert!(matches!(error, Error::UnsupportedHeaderName { .. }));
            assert!(error.to_string().contains(header));
        }
    }

    #[test]
    fn malformed_selected_source_does_not_fall_through() {
        let mut headers = HeaderMap::new();
        headers.insert(&FORWARDED, "for=unknown".parse().unwrap());
        headers.insert(&X_FORWARDED_FOR, "192.0.2.4".parse().unwrap());

        assert!(matches!(
            extract_client_ip_with_headers(
                &headers,
                &[ClientIpHeader::Forwarded, ClientIpHeader::XForwardedFor,],
            ),
            Err(Error::InvalidHeader { .. })
        ));
    }
}
