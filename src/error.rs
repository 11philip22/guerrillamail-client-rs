//! Error types for GuerrillaMail client.

use thiserror::Error;

/// Errors that can occur during GuerrillaMail operations.
#[derive(Error, Debug)]
pub enum Error {
    /// HTTP request failed.
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    /// Failed to parse API token from page.
    #[error("Failed to parse API token from GuerrillaMail page")]
    TokenParse,

    /// Failed to parse domain list from page.
    #[error("Failed to parse domain list from GuerrillaMail page")]
    DomainParse,

    /// JSON parsing error.
    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    /// No domains available.
    #[error("No domains available")]
    NoDomains,
}
