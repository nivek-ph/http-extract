//! Crate-wide, value-redacting extraction errors.
//!
//! Errors identify the HTTP field when possible while deliberately excluding
//! field values and parser details. This keeps formatting safe for operational
//! logs, including when the failed field contains credentials.

use http::HeaderName;

/// An error produced while extracting request metadata.
///
/// The public taxonomy is intentionally small. Parser details, header values,
/// and credentials are absent from every variant, so formatting an error cannot
/// disclose request secrets.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A field is malformed or cannot be decoded; its value is omitted.
    #[error("invalid header {name}")]
    InvalidHeader {
        /// The malformed field name.
        name: HeaderName,
    },
    /// A field defined by an extractor as singular occurred more than once.
    #[error("header {name} occurs more than once")]
    DuplicateHeader {
        /// The duplicated field name.
        name: HeaderName,
    },
    /// A configured Header name is unsupported by the selected operation.
    #[error("unsupported header {name}")]
    UnsupportedHeaderName {
        /// The unsupported field name.
        name: String,
    },
}

impl Error {
    #[cfg(feature = "client-ip")]
    pub(crate) fn unsupported_header_name(name: &str) -> Self {
        Self::UnsupportedHeaderName {
            name: name.to_string(),
        }
    }

    pub(crate) const fn invalid_header(name: HeaderName) -> Self {
        Self::InvalidHeader { name }
    }

    pub(crate) const fn duplicate_header(name: HeaderName) -> Self {
        Self::DuplicateHeader { name }
    }
}
