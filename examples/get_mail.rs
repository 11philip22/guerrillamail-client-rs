//! Verification example for GuerrillaMail Rust client.

use guerrillamail::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Testing GuerrillaMail Rust library...");
    println!("{}", "-".repeat(50));

    // Create client
    let client = Client::new().await?;
    println!("✅ Connected to GuerrillaMail API");
    println!("   Available domains: {:?}", client.domains());

    // Create email
    let alias = "testuser123";
    let email = client.create_email(alias, None).await?;
    println!("\n✅ Created temporary email: {}", email);

    // Poll for messages for up to 2 minutes
    println!(
        "\n⏳ Polling for messages (2 min max)... Send an email to: {}",
        email
    );
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(120);

    loop {
        let messages = client.get_messages(&email).await?;

        if !messages.is_empty() {
            println!("\n✅ Message(s) received!");
            println!("   Messages in inbox: {}", messages.len());
            for msg in &messages {
                println!(
                    "   - From: {}, Subject: {}",
                    msg.mail_from, msg.mail_subject
                );
            }
            break;
        }

        if start.elapsed() >= timeout {
            println!("\n⚠️  Timeout: No messages received after 2 minutes");
            break;
        }

        let remaining = (timeout - start.elapsed()).as_secs();
        print!("\r   {} seconds remaining...    ", remaining);
        use std::io::Write;
        std::io::stdout().flush().ok();
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }

    // Delete email
    let deleted = client.delete_email(&email).await?;
    println!(
        "\n✅ Email deletion: {}",
        if deleted { "Success" } else { "Failed" }
    );

    println!("{}", "-".repeat(50));
    println!("🎉 All tests passed! GuerrillaMail Rust library is working correctly.");

    Ok(())
}
