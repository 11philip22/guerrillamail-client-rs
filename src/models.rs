//! Message model for GuerrillaMail.

use serde::Deserialize;
use serde::Deserializer;
use std::fmt;

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
    /// Unix timestamp (as a string) of when the email was received.
    pub mail_timestamp: String,
}

/// Attachment metadata returned by GuerrillaMail.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Attachment {
    /// Original filename.
    #[serde(default, rename = "f")]
    pub filename: String,
    /// Content type or hint (meaning may vary).
    #[serde(default, rename = "t")]
    pub content_type_or_hint: Option<String>,
    /// Attachment part ID used for download.
    #[serde(default, rename = "p")]
    pub part_id: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StrOrNumU32 {
    Str(String),
    Num(u64),
}

fn de_u32_str_or_num_opt<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<StrOrNumU32>::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(StrOrNumU32::Str(raw)) => raw
            .trim()
            .parse::<u32>()
            .map(Some)
            .map_err(serde::de::Error::custom),
        Some(StrOrNumU32::Num(num)) => u32::try_from(num)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

/// Full email details including body content.
#[derive(Clone, Deserialize)]
pub struct EmailDetails {
    /// Unique message ID.
    pub mail_id: String,
    /// Sender email address.
    pub mail_from: String,
    /// Email subject line.
    pub mail_subject: String,
    /// Full HTML body of the email.
    pub mail_body: String,
    /// Unix timestamp (as a string) of when the email was received.
    pub mail_timestamp: String,
    /// Attachment metadata entries (if any).
    #[serde(default, rename = "att_info")]
    pub attachments: Vec<Attachment>,
    /// Attachment count (if provided by API).
    #[serde(default, rename = "att", deserialize_with = "de_u32_str_or_num_opt")]
    pub attachment_count: Option<u32>,
    /// Session token sometimes returned by the API.
    #[serde(default)]
    pub sid_token: Option<String>,
}

impl fmt::Debug for EmailDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmailDetails")
            .field("mail_id", &self.mail_id)
            .field("mail_from", &self.mail_from)
            .field("mail_subject", &self.mail_subject)
            .field("mail_body", &self.mail_body)
            .field("mail_timestamp", &self.mail_timestamp)
            .field("attachments", &self.attachments)
            .field("attachment_count", &self.attachment_count)
            .field("sid_token", &self.sid_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn email_details_deserialize_without_attachments() {
        let value = json!({
            "mail_id": "123",
            "mail_from": "sender@example.com",
            "mail_subject": "Hello",
            "mail_body": "<p>Body</p>",
            "mail_timestamp": "1700000000"
        });

        let details: EmailDetails = serde_json::from_value(value).unwrap();
        assert_eq!(details.mail_id, "123");
        assert!(details.attachments.is_empty());
        assert!(details.attachment_count.is_none());
        assert!(details.sid_token.is_none());
    }

    #[test]
    fn email_details_deserialize_with_attachments() {
        let value = json!({
            "mail_id": "123",
            "mail_from": "sender@example.com",
            "mail_subject": "Hello",
            "mail_body": "<p>Body</p>",
            "mail_timestamp": "1700000000",
            "att": 1,
            "att_info": [
                { "f": "file.txt", "t": "text/plain", "p": "99" }
            ],
            "sid_token": "sid123"
        });

        let details: EmailDetails = serde_json::from_value(value).unwrap();
        assert_eq!(details.attachment_count, Some(1));
        assert_eq!(
            details.attachments,
            vec![Attachment {
                filename: "file.txt".to_string(),
                content_type_or_hint: Some("text/plain".to_string()),
                part_id: "99".to_string(),
            }]
        );
        assert_eq!(details.sid_token.as_deref(), Some("sid123"));
    }

    #[test]
    fn email_details_deserialize_attachment_count_string() {
        let value = json!({
            "mail_id": "123",
            "mail_from": "sender@example.com",
            "mail_subject": "Hello",
            "mail_body": "<p>Body</p>",
            "mail_timestamp": "1700000000",
            "att": "1"
        });

        let details: EmailDetails = serde_json::from_value(value).unwrap();
        assert_eq!(details.attachment_count, Some(1));
    }

    #[test]
    fn email_details_deserialize_attachment_count_missing() {
        let value = json!({
            "mail_id": "123",
            "mail_from": "sender@example.com",
            "mail_subject": "Hello",
            "mail_body": "<p>Body</p>",
            "mail_timestamp": "1700000000"
        });

        let details: EmailDetails = serde_json::from_value(value).unwrap();
        assert!(details.attachment_count.is_none());
    }
}
