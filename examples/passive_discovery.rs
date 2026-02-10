//! Simple example of passive discovery
//!
//! Listens for mDNS announcements and prints discovered devices

use nexus_core::scanner::PassiveScanner;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("🎧 Starting Passive Network Discovery...");
    println!("Listening for mDNS/DNS-SD announcements on 224.0.0.251:5353");
    println!("Press Ctrl+C to stop\n");

    // Create passive scanner
    let scanner = PassiveScanner::new()?;

    // Channel for receiving discovered devices
    let (tx, mut rx) = mpsc::channel(100);

    // Spawn listener task
    let listener = tokio::spawn(async move {
        if let Err(e) = scanner.start_listening(tx).await {
            eprintln!("Listener error: {}", e);
        }
    });

    // Print discovered devices
    loop {
        tokio::select! {
            Some(device) = rx.recv() => {
                println!("┌─────────────────────────────────────────");
                println!("│ 🎧 Device Discovered (Passive)");
                println!("├─────────────────────────────────────────");
                println!("│ Hostname: {}", device.hostname);
                println!("│ IP:       {}", device.ip);
                println!("│ Services: {:?}", device.services);
                if let Some(hint) = &device.device_type_hint {
                    println!("│ Type:     {}", hint);
                }
                println!("│ Time:     {}", device.discovered_at.format("%H:%M:%S"));
                println!("└─────────────────────────────────────────\n");
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\n👋 Shutting down...");
                break;
            }
        }
    }

    listener.abort();
    Ok(())
}
