//! Message model for GuerrillaMail.

use serde::Deserialize;

/// An email message from GuerrillaMail.
#[derive(Debug, Clone, Deserialize)]
pub struct Message {
    /// Unique message ID.
    pub mail_id: String,
    /// Sender email address.
    pub mail_from: String,
    /// Email subject line.
    pub mail_subject: String,
    /// Short excerpt of the email body.
    pub mail_excerpt: String,
    /// Unix timestamp of when the email was received.
    pub mail_timestamp: String,
}

/// Full email details including body content.
#[derive(Debug, Clone, Deserialize)]
pub struct EmailDetails {
    /// Unique message ID.
    pub mail_id: String,
    /// Sender email address.
    pub mail_from: String,
    /// Email subject line.
    pub mail_subject: String,
    /// Full HTML body of the email.
    pub mail_body: String,
    /// Unix timestamp of when the email was received.
    pub mail_timestamp: String,
}
