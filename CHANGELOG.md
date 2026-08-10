# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add request-extension helpers for directly stored `SocketAddr` values and their IP components.

### Removed

- Remove `extract_peer_address` and `extract_peer_ip`; callers with an out-of-band `SocketAddr`
  can use the value directly or call its `ip()` method.

## [0.1.1](https://github.com/nivek-ph/http-extract/releases/tag/v0.1.1) - 2026-08-10

### Changed

- Expose all public extraction APIs directly from the crate root.

### Removed

- Remove the former public field-family module paths in favor of the flat crate-root API.

## [0.1.0](https://github.com/nivek-ph/http-extract/releases/tag/v0.1.0) - 2026-08-10

### Added

- First stable release of the framework-independent HTTP request metadata extractors.
- Runnable Axum integration example.

### Changed

- Use absolute GitHub links for the extended documentation.
- Keep runnable examples while excluding repository integration tests from the published crate.

### Fixed

- Reject bracketed IPv6 values without a port and out-of-range socket ports in `X-Forwarded-For`.
