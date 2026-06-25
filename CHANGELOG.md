# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.3] - 2026-06-25

### Security
- Enabled TLS certificate verification by default; accepting invalid certificates now requires explicit opt-in with `danger_accept_invalid_certs(true)`.

### Changed
- Reduced the default dependency footprint by moving demo/test-only dependencies out of normal dependencies, feature-gating SOCKS support, and replacing token regex parsing with standard string parsing.
- Cleaned up formatting and strict Clippy warnings so CI checks pass.

### Removed
- Removed stale domain-listing references and the unused `DomainParse` error variant.

### Fixed
- Sent the configured user agent during bootstrap and return request errors for non-2xx bootstrap responses.
- Fixed README quick-start iteration so the message list remains usable after printing summaries.
- Made demo excerpt truncation Unicode-safe.
- Validated empty `mail_id` values before attempting attachment fetches.

[unreleased]: https://github.com/11philip22/guerrillamail-client-rs/compare/v0.7.3...HEAD
[0.7.3]: https://github.com/11philip22/guerrillamail-client-rs/compare/v0.7.2...v0.7.3
