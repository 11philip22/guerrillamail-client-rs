//! Error types for the GuerrillaMail client.
//!
//! This module defines all errors that can occur while interacting with the
//! GuerrillaMail service, including network failures, parsing issues during
//! client bootstrap, and malformed API responses.

use thiserror::Error;

/// Errors that can occur during GuerrillaMail operations.
///
/// Most errors originate either from HTTP failures (`reqwest`),
/// malformed or unexpected responses from GuerrillaMail,
/// or missing data required to continue an operation.
#[derive(Error, Debug)]
pub enum Error {
    /// An HTTP request failed.
    ///
    /// This includes network connectivity issues, TLS errors,
    /// timeouts, and non-success HTTP status codes returned
    /// by the GuerrillaMail service.
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    /// Response was received but did not match the expected shape/content.
    ///
    /// Use this for “missing field”, “unexpected type”, or “schema changed” cases.
    #[error("Unexpected GuerrillaMail response: {0}")]
    ResponseParse(&'static str),

    /// Failed to parse the API token from the GuerrillaMail homepage.
    ///
    /// This error typically occurs during client construction when
    /// the expected `api_token` JavaScript variable cannot be found
    /// or does not match the expected format.
    #[error("Failed to parse API token from GuerrillaMail page")]
    TokenParse,

    /// Failed to construct an HTTP header value.
    #[error("Invalid header value: {0}")]
    HeaderValue(#[from] reqwest::header::InvalidHeaderValue),

    /// Failed to deserialize JSON returned by the GuerrillaMail API.
    ///
    /// This usually indicates an unexpected response schema or a
    /// partially returned / malformed payload.
    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),
}
