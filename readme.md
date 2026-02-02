# guerrillamail-client

[![Crates.io](https://img.shields.io/crates/v/guerrillamail-client.svg)](https://crates.io/crates/guerrillamail-client)
[![Documentation](https://docs.rs/guerrillamail-client/badge.svg)](https://docs.rs/guerrillamail-client)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/woldp001/guerrillamail-client-rs/pulls)

![GuerrillaMail](https://img.guerrillamail.com/4/6/f/46f9fd8911b3a915c1fec119e9062d00.png)

An **async Rust client** for the [GuerrillaMail](https://www.guerrillamail.com) temporary email service.

This crate lets you programmatically create disposable email addresses, poll inboxes, and fetch message contents using an idiomatic async Rust API built on `tokio` and `reqwest`.

> ⚠️ **Unofficial API**  
> GuerrillaMail does not provide a documented public API. This client reverse-engineers
> the web interface and may break if GuerrillaMail changes their frontend behavior.

## When to use this

- Email-based testing (signups, verification emails, password resets)
- Automation and scraping workflows
- CI / integration tests that need a disposable inbox
- Security research and tooling

**Not recommended** for long-lived accounts or reliability-critical workflows.

## Features

- 🚀 **Async/await first** — built on `tokio` and `reqwest`
- 📧 **Create temporary email addresses**
- 📬 **Poll inbox messages**
- 📄 **Fetch full email contents**
- 🗑️ **Forget/delete addresses**
- 🌐 **Proxy support** (e.g. Burp, mitmproxy)
- 🛠️ **Configurable TLS + User-Agent**
- 📚 **Well-typed errors with proper chaining**

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
guerrillamail-client = "0.5.0"
tokio = { version = "1", features = ["full"] }
```

## Quick start

```rust
use guerrillamail_client::Client;

#[tokio::main]
async fn main() -> Result<(), guerrillamail_client::Error> {
    // Create a client (performs a bootstrap request)
    let client = Client::new().await?;

    // Create a temporary email address
    let email = client.create_email("myalias").await?;
    println!("Temporary email: {email}");

    // Poll inbox
    let messages = client.get_messages(&email).await?;
    for msg in messages {
        println!("From: {}", msg.mail_from);
        println!("Subject: {}", msg.mail_subject);
    }

    // Fetch full email body
    if let Some(msg) = messages.first() {
        let details = client.fetch_email(&email, &msg.mail_id).await?;
        println!("Body:\n{}", details.mail_body);
    }

    // Forget the email address
    client.delete_email(&email).await?;

    Ok(())
}
```

## Downloading attachments

```rust
use guerrillamail_client::Client;

#[tokio::main]
async fn main() -> Result<(), guerrillamail_client::Error> {
    let client = Client::new().await?;
    let email = client.create_email("myalias").await?;
    let messages = client.get_messages(&email).await?;

    if let Some(msg) = messages.first() {
        let attachments = client.list_attachments(&email, &msg.mail_id).await?;
        if let Some(attachment) = attachments.first() {
            let bytes = client
                .fetch_attachment(&email, &msg.mail_id, attachment)
                .await?;
            println!("Downloaded {} bytes", bytes.len());
        }
    }

    Ok(())
}
```

## Configuration via builder

For proxies, stricter TLS, or custom user agents, use the builder API:

```rust
use guerrillamail_client::Client;

let client = Client::builder()
    .proxy("http://127.0.0.1:8080")
    .danger_accept_invalid_certs(false)
    .user_agent("my-app/1.0")
    .build()
    .await?;
```

## Error handling

All public APIs return a crate-level `Error` enum.

- Transport / HTTP issues → `Error::Request`
- Invalid or unexpected JSON → `Error::Json`
- Response shape changes (missing fields, schema drift) → `Error::ResponseParse`
- Bootstrap token failures → `Error::TokenParse`

Underlying errors are **preserved as sources**, so tools like `anyhow` or `eyre`
can display full error chains.

## Limitations & caveats

- GuerrillaMail inboxes are **not permanent**
- Messages may disappear at any time
- Address reuse is not guaranteed
- Rate limits and blocking are controlled by GuerrillaMail, not this crate
- API behavior may change without warning

## Acknowledgements

This project was inspired by and partially based on  
[GuerrillaMail-Python](https://github.com/rino-snow/GuerrillaMail-Python).

## Contributing

PRs are welcome!  
Please run `cargo fmt` and `cargo clippy` before submitting.

If you’re changing behavior (e.g. stricter parsing), document it in the PR.

## Support

If this crate saves you time or helps your work, support is appreciated:

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/11philip22)

## License

This project is licensed under the MIT License; see [license](license) for details.
