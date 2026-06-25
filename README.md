<h1 align="center">guerrillamail-client</h1>

<p align="center">
  <strong>Async Rust client for disposable GuerrillaMail inboxes.</strong>
</p>

<p align="center">
  <a href="https://crates.io/crates/guerrillamail-client"><img src="https://img.shields.io/crates/v/guerrillamail-client?style=for-the-badge&logo=rust&logoColor=white&color=F59E0B" alt="Crates.io"></a>
  <a href="https://docs.rs/guerrillamail-client"><img src="https://img.shields.io/docsrs/guerrillamail-client?style=for-the-badge&logo=docs.rs&logoColor=white&color=3B82F6" alt="docs.rs"></a>
  <a href="https://github.com/11philip22/guerrillamail-client-rs"><img src="https://img.shields.io/badge/source-GitHub-181717?style=for-the-badge&logo=github&logoColor=white" alt="Source on GitHub"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-8B5CF6?style=for-the-badge" alt="MIT license"></a>
</p>

<p align="center">
  <a href="#overview">Overview</a>
  &middot; <a href="#features">Features</a>
  &middot; <a href="#installation">Installation</a>
  &middot; <a href="#quick-start">Quick start</a>
  &middot; <a href="#attachments">Attachments</a>
  &middot; <a href="#configuration">Configuration</a>
  &middot; <a href="#examples">Examples</a>
</p>

---

## Overview

`guerrillamail-client` is an async Rust API client for the
[GuerrillaMail](https://www.guerrillamail.com/) temporary email service. It is
designed for tests, demos, automation, and tooling that need disposable inboxes
without running mail infrastructure.

The client bootstraps a GuerrillaMail session, creates throwaway addresses,
polls message summaries, fetches full email bodies, downloads attachments, and
forgets addresses when the workflow is done.

> [!NOTE]
> This crate wraps the public GuerrillaMail service. It inherits that service's
> availability, retention behavior, filtering, and API changes.

## Features

- Async-first API built on `tokio` and `reqwest`.
- Create disposable email addresses from aliases.
- Poll inboxes and fetch full message contents.
- List and download message attachments.
- Forget addresses for the current GuerrillaMail session.
- Configure proxy, TLS behavior, user agent, endpoints, and request timeout.
- Typed response models and a crate-wide `Result<T>` alias.

## Installation

Add the crate and a Tokio runtime to your `Cargo.toml`:

```toml
[dependencies]
guerrillamail-client = "0.7.2"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Quick start

```rust
use guerrillamail_client::Client;

#[tokio::main]
async fn main() -> Result<(), guerrillamail_client::Error> {
    let client = Client::new().await?;
    let email = client.create_email("myalias").await?;

    println!("Temporary inbox: {email}");

    let messages = client.get_messages(&email).await?;
    for message in &messages {
        println!("{}: {}", message.mail_from, message.mail_subject);
    }

    if let Some(message) = messages.first() {
        let details = client.fetch_email(&email, &message.mail_id).await?;
        println!("{}", details.mail_body);
    }

    client.delete_email(&email).await?;

    Ok(())
}
```

## Attachments

Use `list_attachments` when you only need attachment metadata, or pass an
attachment from `EmailDetails::attachments` directly to `fetch_attachment`.

```rust
use guerrillamail_client::Client;

#[tokio::main]
async fn main() -> Result<(), guerrillamail_client::Error> {
    let client = Client::new().await?;
    let email = client.create_email("files-demo").await?;
    let messages = client.get_messages(&email).await?;

    if let Some(message) = messages.first() {
        let attachments = client.list_attachments(&email, &message.mail_id).await?;

        for attachment in attachments {
            let bytes = client
                .fetch_attachment(&email, &message.mail_id, &attachment)
                .await?;

            println!("Downloaded {} bytes from {}", bytes.len(), attachment.filename);
        }
    }

    client.delete_email(&email).await?;
    Ok(())
}
```

## Configuration

Use the builder when you need traffic inspection, stricter TLS verification, a
custom user agent, test endpoints, or a different timeout.

For SOCKS proxies, enable the crate's `socks` feature.

```rust
use guerrillamail_client::Client;
use std::time::Duration;

let client = Client::builder()
    .proxy("http://127.0.0.1:8080")
    .user_agent("my-app/1.0")
    .timeout(std::time::Duration::from_secs(30)) // default is 30s; customize as needed
    .build()
    .await?;
```

## Examples

Run the bundled demo to create an inbox, poll it, fetch received mail, download
attachments, and clean up the address:

```sh
cargo run --example demo
```

Full API documentation is available on
[docs.rs/guerrillamail-client](https://docs.rs/guerrillamail-client).
