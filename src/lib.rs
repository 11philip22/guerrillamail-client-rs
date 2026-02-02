//! GuerrillaMail Rust Client
//!
//! An async Rust client for the GuerrillaMail temporary email service.
//!
//! # Example
//! ```no_run
//! use guerrillamail_client::Client;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), guerrillamail_client::Error> {
//!     let client = Client::new().await?;
//!     let email = client.create_email("myalias").await?;
//!     println!("Created: {}", email);
//!     
//!     let messages = client.get_messages(&email).await?;
//!     for msg in messages {
//!         println!("From: {}, Subject: {}", msg.mail_from, msg.mail_subject);
//!     }
//!     
//!     client.delete_email(&email).await?;
//!     Ok(())
//! }
//! ```

mod client;
mod error;
mod models;

pub use client::{Client, ClientBuilder};
pub use error::Error;
pub use models::{Attachment, EmailDetails, Message};

/// Result type alias for GuerrillaMail operations.
///
/// This is equivalent to `std::result::Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;
