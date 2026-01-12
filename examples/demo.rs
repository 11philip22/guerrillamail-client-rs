//! Comprehensive example showcasing all GuerrillaMail client functionality.
//!
//! Features demonstrated:
//! - Creating a client (with optional proxy support)
//! - Viewing available email domains
//! - Creating a temporary email address
//! - Polling for incoming messages
//! - Fetching full email content
//! - Deleting/cleaning up the email address

use guerrillamail_client::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("📧 GuerrillaMail Rust Client - Full Demo");
    println!("{}", "=".repeat(50));

    // =========================================
    // 1. Create client (optionally with proxy)
    // =========================================
    println!("\n🔌 Creating client...");

    // Without proxy:
    let client = Client::new().await?;

    // With proxy (uncomment to use):
    // let client = Client::with_proxy(Some("http://127.0.0.1:8080")).await?;

    println!("   ✅ Connected to GuerrillaMail API");

    // =========================================
    // 2. View available domains
    // =========================================
    println!("\n🌐 Available email domains:");
    for domain in client.domains() {
        println!("   - {}", domain);
    }

    // =========================================
    // 3. Create temporary email address
    // =========================================
    println!("\n📬 Creating temporary email...");
    let alias = format!("demo{}", rand::random::<u16>());
    let email = client.create_email(&alias, None).await?;
    println!("   ✅ Created: {}", email);

    // =========================================
    // 4. Poll for messages (get_messages)
    // =========================================
    println!("\n⏳ Waiting for messages...");
    println!("   Send an email to: {}", email);
    println!("   (Polling for up to 2 minutes)");

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(120);
    let poll_interval = std::time::Duration::from_secs(5);

    loop {
        // get_messages returns basic info: id, from, subject, excerpt
        let messages = client.get_messages(&email).await?;

        if !messages.is_empty() {
            println!("\n\n📥 Received {} message(s)!", messages.len());

            for msg in &messages {
                println!("\n{}", "-".repeat(50));
                println!("Message ID:  {}", msg.mail_id);
                println!("From:        {}", msg.mail_from);
                println!("Subject:     {}", msg.mail_subject);
                println!(
                    "Excerpt:     {}",
                    &msg.mail_excerpt[..msg.mail_excerpt.len().min(80)]
                );
                println!("Timestamp:   {}", msg.mail_timestamp);

                // =========================================
                // 5. Fetch full email content (fetch_email)
                // =========================================
                println!("\n📄 Fetching full email body...");
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
                    }
                    Err(e) => {
                        eprintln!("   ❌ Failed to fetch: {}", e);
                    }
                }
            }
            break;
        }

        if start.elapsed() >= timeout {
            println!("\n\n⚠️  Timeout: No messages received");
            break;
        }

        let remaining = (timeout - start.elapsed()).as_secs();
        print!("\r   Checking... {} seconds remaining   ", remaining);
        use std::io::Write;
        std::io::stdout().flush().ok();

        tokio::time::sleep(poll_interval).await;
    }

    // =========================================
    // 6. Delete/forget email address
    // =========================================
    println!("\n🗑️  Cleaning up email address...");
    match client.delete_email(&email).await {
        Ok(true) => println!("   ✅ Email address deleted"),
        Ok(false) => println!("   ⚠️  Deletion may have failed"),
        Err(e) => eprintln!("   ❌ Error: {}", e),
    }

    println!("\n{}", "=".repeat(50));
    println!("✨ Demo complete!");

    Ok(())
}
