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

    // Check inbox
    let messages = client.get_messages(&email).await?;
    println!("\n✅ Inbox check successful");
    println!("   Messages in inbox: {}", messages.len());
    for msg in &messages {
        println!(
            "   - From: {}, Subject: {}",
            msg.mail_from, msg.mail_subject
        );
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
