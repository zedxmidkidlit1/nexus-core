//! ARP passive monitoring example
//!
//! Listens for ARP traffic and prints MAC/IP mappings

use nexus_core::scanner::ArpMonitor;
use pnet::datalink;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("🎧 Starting ARP Passive Monitoring...");
    println!("Capturing ARP broadcasts for MAC/IP discovery");
    println!("Press Ctrl+C to stop\n");

    // Get the first active network interface
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| !iface.is_loopback() && iface.is_up() && !iface.ips.is_empty())
        .ok_or("No active network interface found")?;

    println!("📡 Monitoring interface: {}", interface.name);
    println!("   IP addresses: {:?}\n", interface.ips);

    // Create ARP monitor
    let monitor = ArpMonitor::new(interface);

    // Channel for receiving ARP events
    let (tx, mut rx) = mpsc::channel(100);

    // Spawn monitoring task
    let listener = tokio::spawn(async move {
        if let Err(e) = monitor.start_monitoring(tx).await {
            eprintln!("Monitor error: {}", e);
        }
    });

    println!("Listening for ARP packets...\n");

    // Print captured ARP events
    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                let arrow = if event.is_request { "→" } else { "←" };
                println!(
                    "🎧 {} {} ({}) {} {}",
                    event.timestamp.format("%H:%M:%S"),
                    event.sender_ip,
                    event.sender_mac,
                    arrow,
                    event.target_ip
                );
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
