//! Comprehensive example showcasing all GuerrillaMail client functionality.
//!
//! Features demonstrated:
//! - Creating a client (with optional proxy support)
//! - Creating a temporary email address
//! - Polling for incoming messages
//! - Fetching full email content
//! - Deleting/cleaning up the email address

use guerrillamail_client::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("GuerrillaMail Rust Client - Full Demo");
    println!("{}", "=".repeat(50));

    // =========================================
    // 1. Create client (optionally with proxy)
    // =========================================
    println!("\nCreating client...");

    // Without proxy:
    let client = Client::new().await?;

    // With proxy (uncomment to use):
    // let client = Client::builder().proxy("http://127.0.0.1:8080").build().await?;

    // Custom configuration example (uncomment to use):
    // let client = Client::builder()
    //     .proxy("http://127.0.0.1:8080")
    //     .danger_accept_invalid_certs(false)
    //     .user_agent("guerrillamail-demo/1.0")
    //     .ajax_url("https://www.guerrillamail.com/ajax.php")
    //     .build()
    //     .await?;

    println!("   Connected to GuerrillaMail API");

    // =========================================
    // 2. Create temporary email address
    // =========================================
    println!("\nCreating temporary email...");
    let alias = format!("demo{}", rand::random::<u16>());
    let email = client.create_email(&alias).await?;
    println!("   Created: {}", email);

    // =========================================
    // 3. Poll for messages (get_messages)
    // =========================================
    println!("\nWaiting for messages...");
    println!("   Send an email to: {}", email);
    println!("   (Polling for up to 2 minutes)");

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(120);
    let poll_interval = std::time::Duration::from_secs(5);

    loop {
        // get_messages returns basic info: id, from, subject, excerpt
        let messages = client.get_messages(&email).await?;

        if !messages.is_empty() {
            println!("\n\nReceived {} message(s)!", messages.len());

            for msg in &messages {
                println!("\n{}", "-".repeat(50));
                println!("Message ID:  {}", msg.mail_id);
                println!("From:        {}", msg.mail_from);
                println!("Subject:     {}", msg.mail_subject);
                println!(
                    "Excerpt:     {}",
                    msg.mail_excerpt.chars().take(80).collect::<String>()
                );
                println!("Timestamp:   {}", msg.mail_timestamp);

                // =========================================
                // 4. Fetch full email content (fetch_email)
                // =========================================
                println!("\nFetching full email body...");
                match client.fetch_email(&email, &msg.mail_id).await {
                    Ok(details) => {
                        println!("   Body length: {} characters", details.mail_body.len());
                        println!("   Preview (first 500 chars):");
                        println!("   {}", "-".repeat(40));
                        let preview: String = details.mail_body.chars().take(500).collect();
                        for line in preview.lines().take(10) {
                            println!("   {}", line);
                        }
                        if details.mail_body.len() > 500 {
                            println!("   ... (truncated)");
                        }

                        // =========================================
                        // 4b. Download attachments (if any)
                        // =========================================
                        if !details.attachments.is_empty() {
                            println!("\nFound {} attachment(s)", details.attachments.len());
                            for attachment in &details.attachments {
                                println!("   - {}", attachment.filename);
                                match client
                                    .fetch_attachment(&email, &msg.mail_id, attachment)
                                    .await
                                {
                                    Ok(bytes) => {
                                        println!("     Downloaded {} bytes", bytes.len());
                                    }
                                    Err(e) => {
                                        eprintln!("     Download failed: {}", e);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("   Failed to fetch: {}", e);
                    }
                }
            }
            break;
        }

        if start.elapsed() >= timeout {
            println!("\n\nTimeout: No messages received");
            break;
        }

        let remaining = (timeout - start.elapsed()).as_secs();
        print!("\r   Checking... {} seconds remaining   ", remaining);
        use std::io::Write;
        std::io::stdout().flush()?;

        tokio::time::sleep(poll_interval).await;
    }

    // =========================================
    // 5. Delete/forget email address
    // =========================================
    println!("\nCleaning up email address...");
    match client.delete_email(&email).await {
        Ok(true) => println!("   Email address deleted"),
        Ok(false) => println!("   Deletion may have failed"),
        Err(e) => eprintln!("   Error: {}", e),
    }

    println!("\n{}", "=".repeat(50));
    println!("Demo complete!");

    Ok(())
}
